'use strict';
//
// File: persistence/persistence_postgres.js
//
// ---------------------------------------------------------------------------
// THE SHARED STORE, AND THE FIRST HALF OF THE SCALABILITY WORK.
//
// `persistence.mode=postgres`. Three tables, one connection pool, and a
// transaction per flush. What it is FOR is two things at once, and it is worth
// keeping them apart because only the first of them is finished:
//
//   1. PERSISTENCE. This process's directory, realms and runtime appconfig
//      overrides survive a restart. Done, and it is the whole of what was
//      asked for.
//   2. COORDINATION. Several processes sharing one directory. NOT done, and
//      deliberately: see THE SEAM below. Pointing two copies of this service at
//      one database today gives you two copies that each write to it and
//      neither of which sees the other's writes until it restarts.
//
// **WHY POSTGRES AND NOT A DIRECTORY.** The obvious answer to "make LDAP
// persistent" is slapd, and `persistence.js`'s header argues at length why that
// would end this service rather than extend it. The second obvious answer is a
// key-value store, and JSONB is what makes Postgres the better one here: an
// entry is `{attributename: [values]}` with no schema, which is a document, and
// Postgres will index into a document (`attrs -> 'uid'`) while still giving a
// primary key, a transaction, and a `DELETE` that means it. Redis would be
// faster and would make every search a client-side scan; Mongo would match the
// shape exactly and is a heavier thing to put in a mock's compose file.
//
// ---------------------------------------------------------------------------
// THE SCHEMA, AND THE TWO COLUMN DECISIONS THAT ARE NOT OBVIOUS.
//
//   sts_ldap_entries(realm, dn_key, dn, attrs, origin, created_at, modified_at)
//   sts_realms(id, name, description, created_at, overrides)
//   sts_appconfig(key, value)
//
// **THE PRIMARY KEY IS (realm, dn_key) AND dn_key IS THE NORMALISED DN.** Not
// the DN as written. Two clients may spell one DN four ways — `UID=Alice, OU=Users`
// and `uid=alice,ou=users` name one entry — and `ldap_server.js`'s
// `normalizeDn()` is the single function in this service that decides that. The
// written spelling is kept beside it in `dn`, because it is what a client sees
// in a search result and losing it would mean every restored entry came back
// lower-cased.
//
// **created_at AND modified_at ARE text, NOT timestamptz.** They hold an RFC
// 4517 generalized time — `20260827192200Z` — which is what LDAP puts in
// `createTimestamp`, and a round trip through `timestamptz` would re-render it
// in whatever format the driver felt like and in whatever timezone the session
// had. The values are also already IN `attrs` as the two operational
// attributes; these columns exist so that a human or a report can `ORDER BY`
// them without digging into JSONB, and their being redundant is the reason they
// must be byte-identical rather than merely equivalent.
//
// ---------------------------------------------------------------------------
// A FLUSH IS ONE TRANSACTION, AND THAT IS THE WHOLE DURABILITY STORY.
//
// `persistence.js` hands this driver a diff — the upserts and deletes that take
// the last written state to the current one. They go in one `BEGIN … COMMIT`,
// so another reader of this database sees the whole of one change or none of
// it, and a failure rolls back to a state this process still has an accurate
// shadow of. There is no partial write to recover from, which is why the retry
// on the other side can be as simple as "leave the dirty bit on".
//
// ---------------------------------------------------------------------------
// THE SEAM: pg_notify, WHICH NOTHING LISTENS TO YET.
//
// After each committed transaction this driver emits
// `NOTIFY sts_ldap_change, '<json>'` naming the realm and the DNs that moved.
// Nothing in this service subscribes to it. It is here rather than in the later
// change for one reason: the notification has to be inside the transaction that
// made the change, so adding it later means editing this function anyway, and
// an emitter with no listener costs a few bytes per commit where a listener
// added to an emitter that is not there costs a debugging session.
//
// What the coordination phase still needs, written down so that it is a
// checklist rather than a rediscovery:
//   * A `LISTEN sts_ldap_change` on a connection of its own — a pooled client
//     cannot hold a LISTEN, because the pool will hand it to somebody else.
//   * Applying the change to the in-memory Map rather than reloading the realm,
//     and doing it inside `realms.run()` so the ambient realm is right.
//   * Ignoring this process's OWN notifications, which means a process id in
//     the payload; there is one in there already for exactly that reason.
//   * A decision about `ldap.maxEntries`, which is a ceiling on what this
//     PROCESS holds and stops meaning that when the store is shared.
//   * Nothing about tokens, sessions or codes, which are not in this database
//     and are not going to be: a token minted by one process is signed by that
//     process's key, and the key is regenerated per start.
// ---------------------------------------------------------------------------

// A CHANNEL NAME AND A SCHEMA VERSION, both spelt once here.
const CHANNEL = 'sts_ldap_change';
const SCHEMA_VERSION = 1;

// The schema, created if it is not there. `IF NOT EXISTS` throughout rather
// than a migration table, and that is a decision rather than laziness: this is
// a mock identity service, the schema is three tables, and a migration
// framework would be a larger dependency than the feature. If a column ever has
// to change, the honest answer for a service like this one is to say so in the
// release note and let an operator drop the tables.
const SCHEMA = [
  'CREATE TABLE IF NOT EXISTS sts_ldap_entries (' +
  '  realm       text        NOT NULL,' +
  '  dn_key      text        NOT NULL,' +
  '  dn          text        NOT NULL,' +
  '  attrs       jsonb       NOT NULL,' +
  '  origin      text,' +
  '  created_at  text,' +
  '  modified_at text,' +
  '  PRIMARY KEY (realm, dn_key))',
  // The one index worth having beyond the primary key: every enumerator in
  // this service walks one realm.
  'CREATE INDEX IF NOT EXISTS sts_ldap_entries_realm ON sts_ldap_entries (realm)',
  'CREATE TABLE IF NOT EXISTS sts_realms (' +
  '  id          text PRIMARY KEY,' +
  '  name        text,' +
  '  description text,' +
  '  created_at  bigint,' +
  '  overrides   jsonb NOT NULL DEFAULT \'{}\'::jsonb)',
  'CREATE TABLE IF NOT EXISTS sts_appconfig (' +
  '  key   text PRIMARY KEY,' +
  '  value jsonb NOT NULL)',
  // What version of the above is on disk. One row, and nothing reads it yet —
  // it is here so that a future change has something to look at other than the
  // shape of the tables.
  'CREATE TABLE IF NOT EXISTS sts_schema (' +
  '  version int PRIMARY KEY,' +
  '  applied_at timestamptz NOT NULL DEFAULT now())'
];

function create(options) {
  const url = options.url;
  const log = options.log;

  if (!url) {
    // ---------------------------------------------------------------------
    // ONLY REACHABLE BY SETTING IT EMPTY ON PURPOSE, since 2026-08-27.
    //
    // `persistence.databaseUrl` has a default now — the local development
    // string that matches this repository's docker-compose.yml — so the
    // ordinary "I turned postgres on and configured nothing" run no longer
    // arrives here; it attempts a connection to localhost and reports what
    // that says, with persistence.js naming this setting on the way past.
    // See the block above that row in common/config.js for why the empty
    // default was the wrong call and what replacing it cost.
    //
    // The check is KEPT because an operator can still write `databaseUrl: ''`
    // or `STS_DATABASE_URL=`, and "postgres mode with no connection string" is
    // a clearer thing to be told than whatever `pg` makes of an empty one.
    // Thrown from create() rather than open(), so persistence.js's one catch
    // reports it before anything has been restored.
    // ---------------------------------------------------------------------
    throw new Error('persistence.mode is "postgres" but ' +
                    'persistence.databaseUrl is empty — it has been set to ' +
                    'nothing explicitly, since it has a default. Set it, or ' +
                    'STS_DATABASE_URL, to a connection string ' +
                    '(postgres://user:password@host:5432/database), or unset ' +
                    'it to fall back to the local development default.');
  }

  let Pool;
  try {
    // REQUIRED LAZILY, and that is the point: `pg` is a dependency only this
    // mode needs, and a person running `persistence.mode=ldif` — or the default
    // memory mode, which is everybody who has not asked for any of this —
    // must not be stopped by its absence. The message names the package,
    // because "Cannot find module 'pg'" arriving out of a mock identity
    // service is a sentence with no obvious cause.
    Pool = require('pg').Pool;
  } catch (err) {
    throw new Error('persistence.mode is "postgres" but the "pg" package is ' +
                    'not installed (' + err.message + '). Run `npm install` ' +
                    'in this package, or use persistence.mode=ldif, which ' +
                    'needs nothing but a directory to write in.');
  }

  // ---------------------------------------------------------------------
  // TLS, AND THE TWO HALVES OF IT THAT LIVE IN DIFFERENT PLACES.
  //
  // ENCRYPTION is `sslmode` in the connection string, which is postgres's own
  // spelling and which `pg` parses for itself — `?sslmode=require` is in the
  // compose default, and the database refuses a plaintext connection anyway
  // because every `host` rule in its pg_hba.conf is `hostssl`. Nothing here
  // has to do anything for that to work.
  //
  // TRUST is not expressible in a connection string as far as `pg` is
  // concerned: `rejectUnauthorized` is a TLS option. So it is a setting, and
  // it is applied HERE rather than pushed into the URL, where it would be
  // silently ignored.
  //
  // THE OPTION IS ONLY SET WHEN sslmode ASKED FOR TLS. Passing `ssl` to `pg`
  // turns TLS on regardless of the URL, so setting it unconditionally would
  // make `sslmode=disable` mean its opposite — a connection string saying one
  // thing and the client doing another, which is the shape of bug this whole
  // change exists to remove.
  const wantsTls = /[?&]sslmode=(require|verify-ca|verify-full|prefer)/i
    .test(url);
  const verify = !!options.verifyTls;
  if (wantsTls) {
    log.info('persistence: the database connection is TLS (sslmode in the ' +
             'connection string), and the server certificate is ' +
             (verify ? 'VERIFIED against this process\'s trust anchors.'
                     : 'NOT verified — persistence.databaseTlsRejectUnauthorized ' +
                       'is off, which is the honest setting for the ' +
                       'self-signed pair the compose stack generates. The ' +
                       'connection is encrypted either way.'));
  } else {
    log.warn('persistence: the database connection string does not ask for ' +
             'TLS (no sslmode=require). The compose stack\'s database ' +
             'REFUSES a plaintext connection, so this will fail to connect ' +
             'there; against another database it will connect in the clear.');
  }

  // ONE DECIDER, AND A FAILED CONNECTION IS WHY.
  //
  // `pg` parses `sslmode` out of the connection string ITSELF and builds an
  // `ssl` config from it — so a string carrying `sslmode=require` and an
  // explicit `ssl: { rejectUnauthorized: false }` beside it are two answers to
  // one question, and the string's won: the first run of this against the
  // compose stack died with `self-signed certificate` despite the option
  // saying not to verify.
  //
  // So the `sslmode` parameter is STRIPPED before the string reaches `pg`, and
  // this driver configures the TLS. The parameter is still what the connection
  // string SAYS — it is read above to decide whether TLS is wanted at all, and
  // it is what an operator writes — but there is exactly one place that turns
  // it into a socket option, which is what stops the two disagreeing again.
  const dialled = (function () {
    if (!wantsTls) {
      return url;
    }
    try {
      const parsed = new URL(url);
      parsed.searchParams.delete('sslmode');
      return parsed.toString();
    } catch (e) {
      // A libpq keyword/value string rather than a URL. `pg` accepts those and
      // this cannot edit one safely, so it is passed through untouched and
      // whatever it says about ssl is what happens.
      log.debug('persistence: the connection string is not a URL, so its ' +
                'sslmode was left as it is.');
      return url;
    }
  })();

  const pool = new Pool({
    connectionString: dialled,
    ssl: wantsTls ? { rejectUnauthorized: verify } : undefined,
    // Small on purpose. Every query this driver makes is on the flush path,
    // there is one flush at a time by construction (persistence.js serialises
    // them), and a mock does not need a connection per core.
    max: 4,
    // A mock must not hang waiting for a database that is not there: the
    // failure has to arrive as a logged error and a service that keeps
    // answering, which needs the connection attempt to give up.
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000
  });

  pool.on('error', function (err) {
    // A pooled client that died while idle. Logged rather than thrown — an
    // unhandled 'error' on a Pool is a process exit, and a mock identity
    // service must not exit because a database restarted.
    log.error('persistence: an idle postgres client errored: ' + err.message +
              '. The pool will make a new one on the next write.');
  });

  // WHO THIS PROCESS IS, for the notification payload. `process.pid` alone is
  // not enough — two containers can hold the same pid — so it is joined to the
  // start time, which is what makes it unique enough for the one job it has:
  // letting a future listener ignore its own writes.
  const processId = String(process.pid) + '-' + String(Date.now());

  function withTransaction(fn) {
    log.debug('Entering withTransaction().');
    return pool.connect().then(function (client) {
      return client.query('BEGIN').then(function () {
        return fn(client);
      }).then(function (result) {
        return client.query('COMMIT').then(function () {
          client.release();
          log.debug('Leaving withTransaction(). Committed.');
          return result;
        });
      }).catch(function (err) {
        return client.query('ROLLBACK').catch(function (rollbackErr) {
          // The rollback itself failed, which means the connection is gone.
          // Logged and swallowed: the original error is the one worth
          // reporting, and releasing the client with an error tells the pool
          // to discard rather than reuse it.
          log.warn('persistence: a rollback failed (' + rollbackErr.message +
                   '); the connection is being discarded.');
        }).then(function () {
          client.release(err);
          log.debug('Leaving withTransaction(). Rolled back.');
          throw err;
        });
      });
    });
  }

  return {
    name: 'postgres',

    open: function () {
      log.debug('Entering the postgres driver open().');
      return withTransaction(function (client) {
        let chain = Promise.resolve();
        SCHEMA.forEach(function (statement) {
          chain = chain.then(function () { return client.query(statement); });
        });
        return chain.then(function () {
          return client.query(
            'INSERT INTO sts_schema (version) VALUES ($1) ' +
            'ON CONFLICT (version) DO NOTHING', [SCHEMA_VERSION]);
        });
      }).then(function () {
        log.info('persistence: the postgres store is open; schema version ' +
                 SCHEMA_VERSION + ' is present. NOTE that this is ' +
                 'PERSISTENCE and not COORDINATION — a second process ' +
                 'pointed at this database will not see this one\'s writes ' +
                 'until it restarts.');
        log.debug('Leaving the postgres driver open().');
      });
    },

    close: function () {
      log.debug('Entering the postgres driver close().');
      return pool.end().then(function () {
        log.debug('Leaving the postgres driver close().');
      });
    },

    loadDirectory: function () {
      log.debug('Entering the postgres driver loadDirectory().');
      return pool.query(
        'SELECT realm, dn, attrs, origin, created_at, modified_at ' +
        'FROM sts_ldap_entries ORDER BY realm, dn_key'
      ).then(function (result) {
        if (!result.rows.length) {
          log.debug('Leaving loadDirectory(). The table is empty.');
          return null;
        }
        const out = {};
        result.rows.forEach(function (row) {
          if (!out[row.realm]) {
            out[row.realm] = [];
          }
          out[row.realm].push({
            dn: row.dn,
            attributes: row.attrs || {},
            origin: row.origin || undefined,
            createdAt: row.created_at || null,
            modifiedAt: row.modified_at || row.created_at || null
          });
        });
        Object.keys(out).forEach(function (realmId) {
          log.info('persistence: read ' + out[realmId].length + ' entry/ies ' +
                   'for the realm "' + realmId + '" from postgres.');
        });
        log.debug('Leaving loadDirectory(). ' + result.rows.length + ' row(s).');
        return out;
      });
    },

    loadRealms: function () {
      log.debug('Entering the postgres driver loadRealms().');
      return pool.query(
        'SELECT id, name, description, created_at, overrides FROM sts_realms ' +
        'ORDER BY created_at NULLS FIRST, id'
      ).then(function (result) {
        if (!result.rows.length) {
          log.debug('Leaving loadRealms(). The table is empty.');
          return null;
        }
        log.debug('Leaving loadRealms(). ' + result.rows.length + ' realm(s).');
        return result.rows.map(function (row) {
          return {
            id: row.id,
            name: row.name,
            description: row.description,
            // bigint comes back as a STRING from node-postgres, because a
            // 64-bit integer does not fit a JS number. It is an epoch
            // millisecond count, which does, so it is converted here rather
            // than left as a string for realms.js to be surprised by.
            createdAt: row.created_at === null ? null : Number(row.created_at),
            overrides: row.overrides || {}
          };
        });
      });
    },

    loadOverrides: function () {
      log.debug('Entering the postgres driver loadOverrides().');
      return pool.query('SELECT key, value FROM sts_appconfig')
        .then(function (result) {
          if (!result.rows.length) {
            log.debug('Leaving loadOverrides(). The table is empty.');
            return null;
          }
          const out = {};
          result.rows.forEach(function (row) {
            // The value is stored WRAPPED — `{"raw": …}` — rather than as a
            // bare JSONB scalar, and the reason is that config.js keeps an
            // override RAW: a boolean set from a form is the string "true" and
            // the same setting from a file is `true`, and both must come back
            // as what they were. A bare jsonb column would round-trip that
            // correctly too; the wrapper is what makes it possible to add a
            // second field later (who set it, when) without a migration.
            out[row.key] = row.value && typeof row.value === 'object' &&
                           'raw' in row.value ? row.value.raw : row.value;
          });
          log.debug('Leaving loadOverrides(). ' + result.rows.length +
                    ' override(s).');
          return out;
        });
    },

    // ONE TRANSACTION for the whole diff, and a NOTIFY at the end of it. See
    // the header for both.
    saveDirectory: function (change) {
      log.debug('Entering the postgres driver saveDirectory().');
      return withTransaction(function (client) {
        let chain = Promise.resolve();
        const moved = [];

        change.upserts.forEach(function (row) {
          chain = chain.then(function () {
            moved.push({ realm: row.realm, dn: row.entry.dn, op: 'put' });
            return client.query(
              'INSERT INTO sts_ldap_entries ' +
              '  (realm, dn_key, dn, attrs, origin, created_at, modified_at) ' +
              'VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7) ' +
              'ON CONFLICT (realm, dn_key) DO UPDATE SET ' +
              '  dn = EXCLUDED.dn, attrs = EXCLUDED.attrs, ' +
              '  origin = EXCLUDED.origin, created_at = EXCLUDED.created_at, ' +
              '  modified_at = EXCLUDED.modified_at',
              [row.realm, row.key, row.entry.dn,
               JSON.stringify(row.entry.attributes || {}),
               row.entry.origin || null,
               row.entry.createdAt || null,
               row.entry.modifiedAt || null]);
          });
        });

        change.deletes.forEach(function (row) {
          chain = chain.then(function () {
            moved.push({ realm: row.realm, dn: row.key, op: 'delete' });
            return client.query(
              'DELETE FROM sts_ldap_entries WHERE realm = $1 AND dn_key = $2',
              [row.realm, row.key]);
          });
        });

        // A REALM THAT WENT AWAY takes its rows with it. The per-row deletes
        // above already cover every row this process knew about; this catches
        // rows written by an earlier run of this process that the current
        // shadow never saw, which is the difference between "the realm is
        // gone" and "the realm is gone as far as I remember".
        change.removedRealms.forEach(function (realmId) {
          chain = chain.then(function () {
            return client.query('DELETE FROM sts_ldap_entries WHERE realm = $1',
                                [realmId]);
          });
          chain = chain.then(function () {
            return client.query('DELETE FROM sts_realms WHERE id = $1',
                                [realmId]);
          });
        });

        return chain.then(function () {
          // THE SEAM. Nothing listens yet; the header says what the listener
          // will need. The payload is capped because Postgres refuses a
          // notification over 8000 bytes and a bulk import would sail past
          // that — a truncated list is marked so that a listener knows to
          // reload rather than to apply what it was sent.
          const capped = moved.length > 50;
          return client.query('SELECT pg_notify($1, $2)', [CHANNEL,
            JSON.stringify({
              from: processId,
              at: new Date().toISOString(),
              truncated: capped,
              changes: capped ? [] : moved
            })]);
        });
      }).then(function () {
        log.debug('Leaving the postgres driver saveDirectory(). ' +
                  change.upserts.length + ' upsert(s), ' +
                  change.deletes.length + ' delete(s).');
      });
    },

    // The realm registry, replaced wholesale inside one transaction. Wholesale
    // rather than diffed because there are never more than a handful of realms
    // and a diff would be more code than the thing it optimises — and because
    // a DELETE of what is not in the list is the only way a removed realm's
    // row goes away when persistence.realms is on and the directory is not.
    saveRealms: function (rows) {
      log.debug('Entering the postgres driver saveRealms().');
      return withTransaction(function (client) {
        const ids = rows.map(function (row) { return row.id; });
        // `= ANY($1)` with an empty array is valid and matches nothing, which
        // is exactly right when the last realm has just been removed.
        return client.query(
          'DELETE FROM sts_realms WHERE NOT (id = ANY($1::text[]))', [ids]
        ).then(function () {
          let chain = Promise.resolve();
          rows.forEach(function (row) {
            chain = chain.then(function () {
              return client.query(
                'INSERT INTO sts_realms (id, name, description, created_at, overrides) ' +
                'VALUES ($1, $2, $3, $4, $5::jsonb) ' +
                'ON CONFLICT (id) DO UPDATE SET ' +
                '  name = EXCLUDED.name, description = EXCLUDED.description, ' +
                '  created_at = EXCLUDED.created_at, ' +
                '  overrides = EXCLUDED.overrides',
                [row.id, row.name, row.description, row.createdAt,
                 JSON.stringify(row.overrides || {})]);
            });
          });
          return chain;
        });
      }).then(function () {
        log.debug('Leaving the postgres driver saveRealms(). ' + rows.length +
                  ' realm(s).');
      });
    },

    saveOverrides: function (map) {
      log.debug('Entering the postgres driver saveOverrides().');
      return withTransaction(function (client) {
        const keys = Object.keys(map);
        return client.query(
          'DELETE FROM sts_appconfig WHERE NOT (key = ANY($1::text[]))', [keys]
        ).then(function () {
          let chain = Promise.resolve();
          keys.forEach(function (key) {
            chain = chain.then(function () {
              return client.query(
                'INSERT INTO sts_appconfig (key, value) VALUES ($1, $2::jsonb) ' +
                'ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value',
                [key, JSON.stringify({ raw: map[key] })]);
            });
          });
          return chain;
        });
      }).then(function () {
        log.debug('Leaving the postgres driver saveOverrides(). ' +
                  Object.keys(map).length + ' override(s).');
      });
    }
  };
}

module.exports = {
  create: create,
  CHANNEL: CHANNEL,
  SCHEMA: SCHEMA,
  SCHEMA_VERSION: SCHEMA_VERSION
};
