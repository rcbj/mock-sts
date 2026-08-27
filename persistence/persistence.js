'use strict';
//
// File: persistence/persistence.js
//
// ---------------------------------------------------------------------------
// THE ONE PLACE THIS SERVICE WRITES ANYTHING DOWN, AND THE FIRST TIME IT EVER
// HAS.
//
// Every other document in this repository said, in one wording or another,
// that this service "persists nothing at all" and that everything is gone on
// restart. That was true until 2026-08-27 and it is not true any more. What
// changed is bounded and worth stating exactly, because a half-remembered
// version of this sentence is worse than either version of it:
//
//   * THE EMBEDDED DIRECTORY persists — every entry under every realm's base,
//     which is to say people, groups, applications, federation relationships
//     and the SPIFFE registry, because in this service those four registries
//     ARE directory entries and nothing else.
//   * THE TRUST REALM REGISTRY persists — the rows, their names and their
//     per-realm overrides.
//   * THE RUNTIME APPCONFIG OVERRIDES persist — the top of `config.js`'s five
//     layers, the one a console Save or `POST /admin-api/config/set` writes.
//
// AND NOTHING ELSE DOES. Sessions, access tokens, authorization codes,
// pre-authorized codes, SAML artifacts, Kerberos tickets, replay caches,
// statistics and the audit log are all still in memory and still gone on
// restart, and that is deliberate rather than unfinished: a mock whose issued
// credentials outlived the process would hand a client a token signed by a key
// that no longer exists, because THE SIGNING KEY IS STILL REGENERATED ON EVERY
// START. See README.md. What persists here is the CONFIGURATION and the
// DIRECTORY — the things somebody typed — and never the things this service
// minted.
//
// ---------------------------------------------------------------------------
// WHY THIS IS NOT A node-ldapjs FEATURE, WHICH IS THE FIRST QUESTION ANYBODY
// ASKS.
//
// It cannot be. `ldapjs` is a PROTOCOL library: a BER codec, a client, and a
// `Server` that parses an operation and routes it to a handler you wrote. It
// ships no storage of any kind and never has. (`node-ldapjs/lib/persistent_search.js`
// is the LDAP *persistent search* change-notification control — the name is a
// trap, and it is about telling a connected client that something changed, not
// about a disk.) The store in this service is ours and always was:
// `ldap/ldap_server.js`'s `const entries = realms.map()`, a Map of normalised
// DN to `{dn, attributes, createdAt, modifiedAt, origin}`.
//
// THE ALTERNATIVE WAS A REAL DIRECTORY, AND IT WAS REFUSED. Standing up
// OpenLDAP beside this service and proxying to it would give persistence for
// nothing — and would end the service. This directory is schemaless on
// purpose, accepts any bind, creates a person on first sight of any name in any
// protocol, and is written into DIRECTLY by six other modules
// (`admin_stats.js`, `applications.js`, `federation.js`, `spiffe_registry.js`,
// `scim.js`, `group_claims.js`) as ordinary function calls. Against slapd every
// one of those becomes a network round trip against a schema that would refuse
// half of what they write. So: the store stays ours, and it learns to write
// itself down.
//
// ---------------------------------------------------------------------------
// THREE MODES, AND THE MIDDLE ONE IS THE ONE MOST PEOPLE WILL USE.
//
//   memory    What this service has always done. Nothing is written, nothing
//             is read, and this whole directory is inert. THE DEFAULT, so a
//             run that says nothing about persistence behaves exactly as every
//             run before 2026-08-27 did — including every job in the parent
//             project's test suite, which is why none of them had to be told
//             about this.
//   ldif      LOCAL DEVELOPMENT, where there is no database and nobody wants
//             one. Each realm's directory is an RFC 2849 LDIF file in the data
//             directory, the realm registry and the appconfig overrides are
//             JSON beside them. LDIF rather than a JSON dump of our own
//             invention because the file is then something else can read:
//             `ldapadd -f`, `slapadd`, a diff in a review, an eyeball.
//   postgres  THE SHARED STORE. One row per entry, keyed by (realm, normalised
//             DN), attributes as JSONB. This is the mode that is also the first
//             half of the scalability work — see THE SEAM below.
//
// ---------------------------------------------------------------------------
// THE WRITE PATH GOES THROUGH ONE FUNCTION, AND THAT IS THE WHOLE REASON THIS
// IS SAFE TO ADD TO A FILE OF 6,500 LINES.
//
// `ldap/ldap_server.js` already required every writer to call
// `touchDirectory()` — the rule is stated at length above that function and
// exists because a reverse index of group membership goes stale otherwise. So
// there is already ONE choke point that every add, modify, delete, modifyDN,
// attribute append and typed delete in this service passes through, already
// documented, already enforced by prose, and already the thing a new writer is
// told to call. This module hangs off it.
//
// The alternative was to instrument the fifteen-odd writers individually with a
// "this DN changed" call. It would be more precise and it would be forgotten:
// a new writer that forgets `touchDirectory()` produces a stale groups claim,
// which is bad; a new writer that forgets `persist(dn)` produces an entry that
// is in the directory until the process restarts and then is not, which is
// worse and takes a day to find. One rule, already written down, already being
// followed, is worth more than a more precise one nobody remembers.
//
// WHAT THE CHOKE POINT COSTS IS THAT IT DOES NOT SAY WHICH ENTRY CHANGED, and
// the answer is a DIFF. This module keeps a shadow of what it last wrote — one
// string per entry — and on each flush compares the live stores against it.
// That produces exactly the upserts and deletes a database wants, catches an
// entry a writer changed in place, and catches a realm going away (its whole
// store is dropped by `realms.map()`'s purge, so there is nothing left to walk;
// the shadow is where the rows-to-delete come from).
//
// ---------------------------------------------------------------------------
// WHEN THE FLUSH HAPPENS, AND WHY THE TWO MODES ANSWER DIFFERENTLY.
//
// Both modes schedule; they differ only in the delay.
//
//   postgres  Delay 0 — a `setTimeout(…, 0)`, so every change made while
//             handling one request coalesces into ONE transaction that runs
//             the moment that request's synchronous work is done. That is
//             write-through at the granularity anybody actually cares about,
//             and it is what stops a bulk SCIM import or a realm build from
//             becoming one transaction per entry.
//   ldif      Delay `persistence.writeDelay`, 1500ms by default, because the
//             unit of writing there is a whole FILE. A realm build writes
//             thirteen entries; three of those in one file rewrite is the
//             point of the delay.
//
// And both flush on the way out: SIGTERM and SIGINT are trapped in
// `server.js`, which calls stop(). A `docker kill -9` is not, and cannot be —
// what that costs in postgres mode is nothing, and in ldif mode it is up to
// `writeDelay` milliseconds of writes.
//
// A FAILED WRITE IS LOGGED AND REPORTED AND NEVER THROWN. The service keeps
// answering out of memory, `GET /ldap` and `/admin/persistence` both carry the
// error, and the next flush tries again with the same diff (the shadow is only
// advanced on success, so nothing is lost by a failure). The alternative —
// refusing the LDAP operation whose write failed — was considered and rejected:
// it would make a database outage take down sixteen protocol families that do
// not need a database, and no other refusal in this service is that expensive.
//
// ---------------------------------------------------------------------------
// TWO INVERTED HOOKS, AND EACH PASSES RULE 3e's TEST INDEPENDENTLY.
//
// Rule 3e says a slot is what you reach for when a require would close a cycle
// or move a route, and that a sixth must not be added by analogy. There are two
// here and neither is an analogy:
//
//   * `config.setOverrideStore()`, filled below. This module READS
//     `persistence.mode` and four other settings through `config.value()`, so
//     it requires `config.js`. A require back — so that `setOverride()` could
//     write the override down — closes that cycle, and node answers a cycle
//     with a half-initialised module whose exports are `undefined`. The symptom
//     would arrive later as "persist is not a function" from inside a console
//     Save.
//   * `persistence.setDirectory()`, offered below and filled by
//     `ldap/ldap_server.js`. This one is about ROUTE ORDER rather than a cycle:
//     `ldap_server.js` registers `/ldap` and `/ldap/directory` at its require
//     time, and this module is required at #4a — far above `admin.js`. A
//     require from here would drag both of those routes to the front of the
//     express router, which is the exact failure rule 1 exists to prevent.
//
// `realms.js` is a PLAIN REQUIRE in the ordinary direction, and it is worth
// saying why it is not a third slot: that module requires only `config.js` and
// `async_hooks`, it registers no route at all, and it does not require this one
// — so a require of it here closes nothing and moves nothing. It fails rule
// 3e's test in both directions, which is what makes it a require. What it needs
// FROM here — "a realm changed, write it down" — arrives through
// `realms.onChange()`, which is an event this module subscribes to rather than
// a slot that module offers.
//
// ---------------------------------------------------------------------------
// THE SEAM: WHAT THIS IS DELIBERATELY NOT YET.
//
// The ask was persistence, and persistence is what this is. It is NOT
// coordination: two processes pointed at one database will each hold their own
// copy of the directory in memory, each write their own changes down, and
// neither will see the other's until it restarts. That is not a bug to be found
// later — it is written here so it is found now, it is stated on
// `/admin/persistence`, and it is what the next phase closes.
//
// What that phase needs is already marked. `persistence_postgres.js` emits a
// `pg_notify('sts_ldap_change', …)` after each transaction, carrying the realm
// and the DNs that moved; nothing LISTENs to it yet. The listener, the
// invalidation of the in-memory Map, and the question of what a per-process
// cache means for `/oauth2/token` (nothing — no token is in the database) are
// the phase, not this file.
// ---------------------------------------------------------------------------

const path = require('path');
const bunyan = require('bunyan');
const config = require('../common/config');
// The ordinary direction, and the header above argues why it is a require
// rather than a third slot: realms.js requires config.js and async_hooks and
// nothing else, registers no route, and does not require this module.
const realms = require('../common/realms');

const log = bunyan.createLogger({ name: 'sts-persistence' });
config.registerLogger(log);

// The three modes, spelt once. `config.js`'s row for `persistence.mode` carries
// the same list in its `enumValues`, which is the copy a caller is validated
// against; this one is what the code branches on, and the two are checked
// against each other at start() rather than trusted.
const MODES = ['memory', 'ldif', 'postgres'];

// ---------------------------------------------------------------------------
// THE DIRECTORY SLOT. See the header — it is a slot rather than a require
// because a require would move two routes.
//
// `ldap/ldap_server.js` fills it at its own require time with three functions,
// and it is validated WHOLE when it is installed rather than member by member
// at each call. A partial one would leave this module able to READ the
// directory and unable to restore it, which is the shape of failure that looks
// like an empty database rather than like a missing function.
// ---------------------------------------------------------------------------
let directory = null;

function setDirectory(hooks) {
  log.debug('Entering setDirectory().');
  const needed = ['realmEntries', 'replaceRealm'];
  const missing = needed.filter(function (name) {
    return !hooks || typeof hooks[name] !== 'function';
  });
  if (missing.length) {
    // Thrown rather than logged, and this is the one throw in this file. It can
    // only be reached by a maintainer changing ldap_server.js's call, it is
    // reached at require time so the process has not started serving anything,
    // and the alternative is a service that silently persists nothing.
    throw new Error('persistence: setDirectory() needs ' + needed.join(', ') +
                    '; missing ' + missing.join(', ') + '.');
  }
  directory = hooks;
  log.debug('Leaving setDirectory(). The directory hooks are installed.');
}

// ---------------------------------------------------------------------------
// State. All of it process-wide rather than per realm, and deliberately: this
// module is about the PROCESS's relationship with a disk or a database, and a
// realm does not have one of those. Every per-realm thing here is keyed by
// realm id inside these structures instead.
// ---------------------------------------------------------------------------

// The chosen driver, or null in memory mode and before start().
let driver = null;
// Which mode start() actually ran in. Read rather than re-derived, so that
// "what is this process doing" and "what is the setting set to" cannot
// disagree after a start that fell back.
let activeMode = 'memory';

// WHAT WAS LAST WRITTEN: realm id -> Map(normalised DN -> a string). The string
// is `JSON.stringify(entry)`, which is a cheap and sufficient equality test —
// two entries whose attributes were built in a different order compare unequal
// and produce one redundant UPSERT, which costs nothing and is the only way
// this can be wrong.
const shadow = new Map();

// The three dirty bits. Separate rather than one flag because the three things
// are written to different places and a change to one must not rewrite the
// other two — in ldif mode that would mean rewriting every realm's file
// because somebody changed a log level.
let directoryDirty = false;
let realmsDirty = false;
let configDirty = false;

// The pending flush, and the promise anybody waiting on it holds.
let timer = null;
let flushing = null;

// True while start() is loading. Every changed() call is a no-op then: restore
// writes into the live stores through the same functions an operator does, and
// without this the first act of a restored process would be to write back
// exactly what it just read.
let restoring = false;

// True once stop() has run. A flush scheduled by a late timer after the pool is
// closed would log an error about a closed client on every shutdown.
let stopped = false;

// What /admin/persistence, GET /ldap and GET /admin-api/persistence report.
let lastWriteAt = null;
let lastError = '';
let writes = 0;
let failures = 0;
let restoredAt = null;
let restoredCounts = { realms: 0, entries: 0, overrides: 0 };

// ---------------------------------------------------------------------------
// Reading the settings. Every one of them per call, like the rest of this
// service — except that all but `writeDelay` are restart-only, so the per-call
// read is a consistency habit rather than something that can change under us.
// ---------------------------------------------------------------------------

function mode() {
  return config.value('persistence.mode');
}

function dataDir() {
  // Resolved against the PACKAGE ROOT rather than the working directory, for
  // config_file.js's reason: a relative path resolves against the directory of
  // whoever is doing the resolving, and this module is two levels from where
  // `./data` means what somebody typing it meant. An absolute path is left
  // alone, which is what a container's volume mount always is.
  const configured = String(config.value('persistence.dataDir') || './data');
  if (path.isAbsolute(configured)) {
    return configured;
  }
  return path.resolve(path.join(__dirname, '..'), configured);
}

function databaseUrl() {
  return String(config.value('persistence.databaseUrl') || '');
}

function writeDelay() {
  // Postgres does not use it: a transaction per request is the point, so the
  // delay there is 0 whatever this says. See the header.
  return config.value('persistence.writeDelay');
}

function persistsAppconfig() {
  return config.value('persistence.appconfig');
}

function persistsRealms() {
  return config.value('persistence.realms');
}

// Is anything being written down at all? Every caller in this file asks this
// rather than comparing the mode to 'memory', so that a mode added later is one
// edit here instead of a search for string comparisons.
function enabled() {
  return activeMode !== 'memory' && driver !== null && !stopped;
}

// ---------------------------------------------------------------------------
// THE THREE "SOMETHING CHANGED" DOORS.
//
// Each marks its own bit and schedules. They are separate functions rather than
// one with an argument because the three call sites are in three different
// modules and each should say what it is reporting at the call site — a reader
// in ldap_server.js seeing `persistence.directoryChanged()` does not have to go
// and look up what a string argument meant.
// ---------------------------------------------------------------------------

function directoryChanged() {
  if (!enabled() || restoring) {
    return;
  }
  directoryDirty = true;
  schedule();
}

function realmsChanged() {
  if (!enabled() || restoring || !persistsRealms()) {
    return;
  }
  realmsDirty = true;
  schedule();
}

// `realmId` is the realm the override landed in, or null for a process-wide
// one. config.js's setOverride() already decides which, so this function is
// told rather than asked: a realm's overrides live on the realm row and a
// process-wide one lives in the appconfig store, and those are two different
// files and two different tables.
function configChanged(realmId) {
  if (!enabled() || restoring) {
    return;
  }
  if (realmId) {
    realmsChanged();
    return;
  }
  if (!persistsAppconfig()) {
    return;
  }
  configDirty = true;
  schedule();
}

function schedule() {
  if (timer || stopped) {
    return;
  }
  // 0 for a database, `writeDelay` for a file. The header argues both.
  const delay = activeMode === 'postgres' ? 0 : writeDelay();
  timer = setTimeout(function () {
    timer = null;
    flush().catch(function (err) {
      // flush() records its own failure; this catch exists so that an
      // unhandled rejection from a timer cannot take the process down. A mock
      // that exits because a database blinked would be worse than one that
      // stopped persisting.
      log.error('persistence: a scheduled flush failed: ' + err.message);
    });
  }, delay);
  // The timer must not hold the process open on its own — a service with
  // nothing else to do should still be able to exit.
  if (timer.unref) {
    timer.unref();
  }
}

// ---------------------------------------------------------------------------
// THE DIFF.
//
// What the live stores hold, keyed the way the shadow is, so the two can be
// compared. `directory.realmEntries()` is ldap_server.js's — it hands back
// `[{key, entry}]` for one realm, with `key` the normalised DN, because
// normalising a DN is that module's job and doing it here would be a second
// implementation of the one function whose disagreement would be invisible.
// ---------------------------------------------------------------------------
function liveDirectory() {
  log.debug('Entering liveDirectory().');
  const live = new Map();
  realms.list().forEach(function (realm) {
    const rows = new Map();
    directory.realmEntries(realm.id).forEach(function (row) {
      rows.set(row.key, row.entry);
    });
    live.set(realm.id, rows);
  });
  log.debug('Leaving liveDirectory(). ' + live.size + ' realm(s).');
  return live;
}

// The upserts and deletes that would take the shadow to `live`. Also reports
// which realms were touched at all, which is what a snapshot driver needs (it
// rewrites a file per realm and must not rewrite the ones nothing happened in)
// and which realms disappeared entirely.
function diff(live) {
  log.debug('Entering diff().');
  const upserts = [];
  const deletes = [];
  const touched = {};
  const removedRealms = [];

  live.forEach(function (rows, realmId) {
    const was = shadow.get(realmId) || new Map();
    rows.forEach(function (entry, key) {
      const json = JSON.stringify(entry);
      if (was.get(key) !== json) {
        upserts.push({ realm: realmId, key: key, entry: entry, json: json });
        touched[realmId] = true;
      }
    });
    was.forEach(function (json, key) {
      if (!rows.has(key)) {
        deletes.push({ realm: realmId, key: key });
        touched[realmId] = true;
      }
    });
  });

  // A REALM THAT IS GONE. `realms.map()` drops the realm's whole Map when the
  // realm is removed, so there is nothing left to walk and the loop above never
  // sees it — the shadow is the only remaining record that its rows were ever
  // written, which is exactly what makes it the right place to look.
  shadow.forEach(function (was, realmId) {
    if (live.has(realmId)) {
      return;
    }
    was.forEach(function (json, key) {
      deletes.push({ realm: realmId, key: key });
    });
    removedRealms.push(realmId);
  });

  log.debug('Leaving diff(). ' + upserts.length + ' upsert(s), ' +
            deletes.length + ' delete(s), ' + removedRealms.length +
            ' realm(s) gone.');
  return { upserts: upserts, deletes: deletes, touched: Object.keys(touched),
           removedRealms: removedRealms };
}

// The shadow advanced to what was just written. Called ONLY after a successful
// write, which is what makes a failed flush retry the same work rather than
// lose it.
function advanceShadow(live, removedRealms) {
  log.debug('Entering advanceShadow().');
  removedRealms.forEach(function (realmId) { shadow.delete(realmId); });
  live.forEach(function (rows, realmId) {
    const next = new Map();
    rows.forEach(function (entry, key) { next.set(key, JSON.stringify(entry)); });
    shadow.set(realmId, next);
  });
  log.debug('Leaving advanceShadow().');
}

// ---------------------------------------------------------------------------
// The realm rows and the appconfig overrides, as they are written down.
//
// A realm row is NOT the object realms.js holds: `builtin` is never written
// (the default realm is a constant in that module and is not a row anywhere),
// and `createdAt` is carried so that a restored realm reports when it was
// really defined rather than when the process last started.
// ---------------------------------------------------------------------------
function realmRows() {
  return realms.list().filter(function (realm) {
    return !realm.builtin;
  }).map(function (realm) {
    return {
      id: realm.id,
      name: realm.name,
      description: realm.description,
      createdAt: realm.createdAt,
      overrides: realm.overrides || {}
    };
  });
}

// ---------------------------------------------------------------------------
// THE FLUSH. One at a time, and a second caller waits for the first rather than
// starting a competing write — two transactions computing their diff against
// the same shadow would each think they had to write everything.
// ---------------------------------------------------------------------------
function flush() {
  log.debug('Entering flush().');
  if (!enabled()) {
    log.debug('Leaving flush(). Nothing is being persisted.');
    return Promise.resolve({ written: false });
  }
  if (flushing) {
    log.debug('Leaving flush(). One is already running; waiting for it.');
    return flushing.then(function () { return flush(); });
  }
  if (!directoryDirty && !realmsDirty && !configDirty) {
    log.debug('Leaving flush(). Nothing is dirty.');
    return Promise.resolve({ written: false });
  }

  const wantDirectory = directoryDirty;
  const wantRealms = realmsDirty;
  const wantConfig = configDirty;
  // Cleared BEFORE the write rather than after it, so that a change made while
  // the write is in flight sets the bit again and gets its own flush. Clearing
  // afterwards would drop it.
  directoryDirty = false;
  realmsDirty = false;
  configDirty = false;

  const live = wantDirectory ? liveDirectory() : null;
  const changes = live ? diff(live) : null;

  flushing = Promise.resolve().then(function () {
    if (!changes) {
      return null;
    }
    if (!changes.upserts.length && !changes.deletes.length &&
        !changes.removedRealms.length) {
      return null;
    }
    return driver.saveDirectory({
      upserts: changes.upserts,
      deletes: changes.deletes,
      touched: changes.touched,
      removedRealms: changes.removedRealms,
      all: live
    }).then(function () {
      advanceShadow(live, changes.removedRealms);
    });
  }).then(function () {
    if (!wantRealms) {
      return null;
    }
    return driver.saveRealms(realmRows());
  }).then(function () {
    if (!wantConfig) {
      return null;
    }
    return driver.saveOverrides(config.persistableOverrides());
  }).then(function () {
    writes++;
    lastWriteAt = new Date().toISOString();
    lastError = '';
    log.debug('Leaving flush(). Wrote ' +
              (changes ? changes.upserts.length + ' upsert(s), ' +
                         changes.deletes.length + ' delete(s)' : 'no entries') +
              (wantRealms ? ', the realm registry' : '') +
              (wantConfig ? ', the appconfig overrides' : '') + '.');
    return { written: true };
  }).catch(function (err) {
    // NOT rethrown, and the header argues why at length: the service keeps
    // answering out of memory. The dirty bits go back on so the next flush
    // retries, and the shadow was not advanced, so the same diff is recomputed
    // and nothing is lost.
    failures++;
    lastError = err.message;
    directoryDirty = directoryDirty || wantDirectory;
    realmsDirty = realmsDirty || wantRealms;
    configDirty = configDirty || wantConfig;
    log.error('persistence: could not write to the ' + activeMode +
              ' store: ' + err.message + '. The service is unaffected and is ' +
              'still answering from memory; the next change will try again.');
    log.debug('Leaving flush(). It failed.');
    return { written: false, error: err.message };
  }).then(function (result) {
    flushing = null;
    return result;
  });

  return flushing;
}

// ---------------------------------------------------------------------------
// STARTING, WHICH IS ALSO RESTORING.
//
// **IT IS CALLED FROM server.js BEFORE THE HTTP LISTENER BINDS, AND THAT IS THE
// WHOLE OF ITS POSITION ARGUMENT.** Every other module in this service does its
// work at require time; this one cannot, for one reason that is not
// negotiable: opening a Postgres pool is asynchronous, and a `require` cannot
// wait. So this joins the four modules that start something from `listen()`
// rather than from `require` — and it goes FIRST among them, because what it
// restores is what they are about to serve.
//
// The order inside is the dependency order and each step is argued:
//
//   1. THE APPCONFIG OVERRIDES, first, because everything below reads
//      settings. It is safe to apply them this late — after every module has
//      been required — because only a `runtime: true` setting can be
//      overridden at all (`checkOverride()` refuses the rest by name), and a
//      runtime setting is BY DEFINITION one that is read per call rather than
//      cached at require time. A restart-only setting can therefore never be
//      in this file, so `global.https`, `ldap.port` and the rest are exactly
//      what the environment and the appconfig file said.
//   2. THE REALM ROWS, because a realm has to EXIST before its directory can
//      be loaded into it. They are restored through `realms.create()`, the
//      same function `/admin/realms` calls, so that every builder registered
//      by every module fires exactly as it would for a realm somebody typed —
//      including ldap_server.js's, which seeds the realm's subtree. Anything
//      else would be a second way to make a realm, and the second way is the
//      one that is missing a step.
//   3. THE DIRECTORY, last, replacing what was seeded. A realm with rows in
//      the store gets exactly those rows; a realm with none keeps its seed,
//      which is what a first run looks like.
// ---------------------------------------------------------------------------
function start() {
  log.debug('Entering start().');
  const chosen = mode();
  if (MODES.indexOf(chosen) < 0) {
    // Unreachable through config.value(), whose enum type refuses anything
    // else. Checked anyway because the two lists — MODES here and enumValues
    // in config.js — are two copies of one fact, and this is the line that
    // notices they have drifted.
    log.error('persistence: "' + chosen + '" is not a mode this module knows ' +
              '(' + MODES.join(', ') + '). Nothing will be persisted.');
    activeMode = 'memory';
    log.debug('Leaving start(). The mode was not recognised.');
    return Promise.resolve({ mode: 'memory' });
  }
  if (chosen === 'memory') {
    activeMode = 'memory';
    log.info('persistence: off (persistence.mode=memory). Everything this ' +
             'service holds is in memory and goes when the process does, ' +
             'which is what it did before persistence existed.');
    log.debug('Leaving start(). Memory mode.');
    return Promise.resolve({ mode: 'memory' });
  }
  if (!directory) {
    // ldap_server.js was never required, which happens in a test that loads
    // this module alone. Reported rather than thrown for that reason.
    log.error('persistence: no directory is installed — ldap/ldap_server.js ' +
              'has not been required, so there is nothing to persist. ' +
              'Falling back to memory mode.');
    activeMode = 'memory';
    log.debug('Leaving start(). No directory.');
    return Promise.resolve({ mode: 'memory' });
  }

  try {
    driver = chosen === 'postgres'
      ? require('./persistence_postgres').create({ url: databaseUrl(), log: log })
      : require('./persistence_ldif').create({ dir: dataDir(), log: log });
  } catch (err) {
    // The postgres driver's `require('pg')` is the realistic way to get here —
    // an image built without the dependency. Named, because "cannot find
    // module pg" arriving from inside a mock identity service is a sentence
    // nobody expects.
    log.error('persistence: the "' + chosen + '" store could not be opened: ' +
              err.message + '. Falling back to memory mode; nothing will be ' +
              'written down.');
    driver = null;
    activeMode = 'memory';
    lastError = err.message;
    log.debug('Leaving start(). The driver would not load.');
    return Promise.resolve({ mode: 'memory', error: err.message });
  }

  activeMode = chosen;
  restoring = true;
  return driver.open().then(function () {
    return persistsAppconfig() ? driver.loadOverrides() : null;
  }).then(function (saved) {
    if (saved && Object.keys(saved).length) {
      const applied = config.applyPersistedOverrides(saved);
      restoredCounts.overrides = applied.length;
      log.info('persistence: restored ' + applied.length +
               ' runtime appconfig override(s) from the ' + activeMode +
               ' store: ' + applied.join(', ') + '.');
    }
    return persistsRealms() ? driver.loadRealms() : null;
  }).then(function (rows) {
    if (rows && rows.length) {
      restoredCounts.realms = restoreRealms(rows);
    }
    return driver.loadDirectory();
  }).then(function (byRealm) {
    let loaded = [];
    if (byRealm) {
      const restored = restoreDirectory(byRealm);
      restoredCounts.entries = restored.total;
      loaded = restored.loaded;
    }
    // Primed ONLY for the realms whose entries came out of the store — see
    // primeShadow(), which carries the argument and the bug it fixes. A first
    // run primes nothing, so the seeded directory is written exactly once.
    primeShadow(loaded);
    restoring = false;
    restoredAt = new Date().toISOString();
    log.info('persistence: ' + activeMode + ' store open; restored ' +
             restoredCounts.entries + ' directory entry/entries across ' +
             (restoredCounts.realms + 1) + ' realm(s), ' +
             restoredCounts.realms + ' defined realm(s) and ' +
             restoredCounts.overrides + ' appconfig override(s). ' +
             'What is NOT restored, and never will be: sessions, tokens, ' +
             'codes, artifacts, tickets and the signing key, all of which ' +
             'are minted rather than typed.');
    // A first run has an empty store and a seeded directory, so everything is
    // new and has to be written. A restored run's diff is empty and this
    // costs one no-op flush.
    directoryDirty = true;
    realmsDirty = persistsRealms();
    configDirty = false;
    schedule();
    log.debug('Leaving start(). Restored.');
    return { mode: activeMode, restored: restoredCounts };
  }).catch(function (err) {
    restoring = false;
    activeMode = 'memory';
    lastError = err.message;
    log.error('persistence: the ' + chosen + ' store could not be read: ' +
              err.message + '. Falling back to memory mode — this service is ' +
              'running with its seeded directory and will not write anything ' +
              'down. Nothing in the store was changed.' +
              // -------------------------------------------------------------
              // AND IF THE CONNECTION STRING IS THE BUILT-IN ONE, SAY SO.
              //
              // `persistence.databaseUrl` had no default until 2026-08-27, so
              // "postgres mode, nothing configured" used to be refused by name
              // before any connection was attempted. It has one now — the
              // local development string — which means that run reaches a
              // socket instead and reports whatever the socket says. "connect
              // ECONNREFUSED 127.0.0.1:5432" is a true answer and a poor one
              // for somebody who never chose localhost, so the guidance the
              // old refusal carried is put back HERE, on the only path that
              // lost it, and only when the value really did come from the
              // defaults layer. `sourceOf()` is what makes that a fact rather
              // than a guess about what the operator typed.
              // -------------------------------------------------------------
              (chosen === 'postgres' &&
               config.sourceOf('persistence.databaseUrl') === 'defaults'
                ? ' NOTE that persistence.databaseUrl was not configured, so ' +
                  'this was the built-in local development default (' +
                  describeDefaultTarget() + '). Set STS_DATABASE_URL, or ' +
                  'persistence.databaseUrl in your appconfig file, to point ' +
                  'at the database you meant.'
                : ''));
    // Deliberately not rethrown: a database that is not there must not stop a
    // mock identity service from starting. The whole point of this service is
    // that a client has something to talk to.
    log.debug('Leaving start(). The store could not be read.');
    return { mode: 'memory', error: err.message };
  });
}

// The realm rows, put back through the door an operator uses. See start()'s
// step 2 — this is the reason `realms.create()` is called rather than the
// registry being written into directly.
function restoreRealms(rows) {
  log.debug('Entering restoreRealms(). ' + rows.length + ' row(s).');
  let made = 0;
  rows.forEach(function (row) {
    if (realms.get(row.id)) {
      // Already defined, which means an appconfig file or an environment
      // variable defined it before this ran. The stored row does not overwrite
      // it: something a person wrote down for THIS run beats something this
      // module wrote down during the last one.
      log.warn('persistence: the realm "' + row.id + '" is already defined; ' +
               'the stored row was left alone.');
      return;
    }
    const result = realms.create({
      id: row.id,
      name: row.name,
      description: row.description,
      overrides: row.overrides || {}
    });
    if (!result.ok) {
      // Reported and skipped rather than fatal: one unrestorable realm must
      // not cost the others. The realistic cause is an id that was valid when
      // it was written and is not now — a reserved word added since.
      log.error('persistence: the stored realm "' + row.id + '" could not be ' +
                'restored: ' + result.errors.join(' '));
      return;
    }
    // create() stamps `createdAt` with now, which for a restore is a lie: the
    // realm was defined whenever somebody defined it. Put it back.
    if (row.createdAt) {
      result.realm.createdAt = row.createdAt;
    }
    made++;
  });
  log.debug('Leaving restoreRealms(). ' + made + ' restored.');
  return made;
}

// The entries, per realm, replacing what was seeded. A realm the store has
// nothing for keeps its seed — that is a realm created since the last write,
// or a first run.
function restoreDirectory(byRealm) {
  log.debug('Entering restoreDirectory().');
  let total = 0;
  const loaded = [];
  Object.keys(byRealm).forEach(function (realmId) {
    const list = byRealm[realmId] || [];
    if (!list.length) {
      return;
    }
    if (realmId !== realms.DEFAULT_ID && !realms.get(realmId)) {
      // Rows for a realm nobody defined. It happens when persistence.realms is
      // off while the directory is on, and it is reported rather than silently
      // dropped because the entries are still IN the store and will be deleted
      // by the first flush's diff — which is a real data loss and somebody
      // should get to see it coming.
      log.warn('persistence: the store holds ' + list.length + ' entry/ies ' +
               'for the realm "' + realmId + '", which is not defined. They ' +
               'are not loaded, and the next write will remove them. Turn ' +
               'persistence.realms on to restore realm definitions too.');
      return;
    }
    directory.replaceRealm(realmId, list);
    loaded.push(realmId);
    total += list.length;
  });
  log.debug('Leaving restoreDirectory(). ' + total + ' entry/entries into ' +
            loaded.length + ' realm(s).');
  return { total: total, loaded: loaded };
}

// ---------------------------------------------------------------------------
// THE SHADOW AT STARTUP, AND THIS FUNCTION HAD THE ONE BUG THIS FEATURE HAS HAD
// SO FAR. IT IS WORTH THE PARAGRAPH.
//
// The shadow is "what the store already holds", and the first flush writes the
// difference between it and the live directory. The obvious way to prime it is
// from the live directory — and that is exactly wrong, because it declares that
// the store already holds everything. On a FIRST RUN, where the store is empty
// and the live directory is the seeded tree, the first diff then comes out
// empty and the seed is never written down. The service reports a healthy
// store, `lastError` is null, and the tables have nothing in them.
//
// It hid for as long as it did because the two drivers make it look different.
// The ldif driver rewrites a WHOLE FILE for any realm the diff touched at all,
// so the handful of entries that do change just after startup dragged all
// nineteen into the file and the result looked correct. Postgres writes exactly
// the rows in the diff, so the same run put three rows in the table and it was
// obvious.
//
// So the shadow is primed ONLY for the realms whose contents actually CAME OUT
// of the store. A realm that was seeded rather than loaded gets an empty
// shadow, which means every one of its entries is new and is written.
//
// The primed realms are read back from `liveDirectory()` rather than from the
// rows the driver returned, and that is deliberate too: `replaceRealm()` just
// built those live objects out of those rows, so the two are equal by
// construction, and going through the live store is what guarantees the strings
// here are byte-identical to the ones the next diff will compute. Serialising
// the driver's rows separately would compare a JSON of one object shape against
// a JSON of another, and every entry would look changed on every start.
// ---------------------------------------------------------------------------
function primeShadow(loadedRealmIds) {
  log.debug('Entering primeShadow().');
  shadow.clear();
  const fromStore = loadedRealmIds || [];
  const live = liveDirectory();
  live.forEach(function (rows, realmId) {
    if (fromStore.indexOf(realmId) < 0) {
      // Seeded, not loaded. An empty shadow, so every entry is an upsert on
      // the first flush and the seed reaches the store.
      shadow.set(realmId, new Map());
      return;
    }
    const next = new Map();
    rows.forEach(function (entry, key) { next.set(key, JSON.stringify(entry)); });
    shadow.set(realmId, next);
  });
  log.debug('Leaving primeShadow(). ' + shadow.size + ' realm(s), ' +
            fromStore.length + ' of them read back from the store.');
}

// ---------------------------------------------------------------------------
// STOPPING. One last flush, then close. Called from the SIGTERM and SIGINT
// handlers in server.js — the two signals a container stop and a Ctrl-C send —
// and from nowhere else. `kill -9` cannot be trapped and is what `writeDelay`
// is measured against in ldif mode.
// ---------------------------------------------------------------------------
function stop() {
  log.debug('Entering stop().');
  if (!enabled()) {
    stopped = true;
    log.debug('Leaving stop(). Nothing was open.');
    return Promise.resolve();
  }
  if (timer) {
    clearTimeout(timer);
    timer = null;
  }
  return flush().then(function () {
    stopped = true;
    return driver.close();
  }).then(function () {
    log.info('persistence: the ' + activeMode + ' store was flushed and closed.');
    log.debug('Leaving stop().');
  }).catch(function (err) {
    stopped = true;
    log.error('persistence: the final flush or close failed: ' + err.message +
              '. Anything changed since the last successful write is lost.');
    log.debug('Leaving stop(). It failed.');
  });
}

// ---------------------------------------------------------------------------
// WHAT THIS MODULE SAYS ABOUT ITSELF. One shape, read by GET /ldap, by
// /admin/persistence and by GET /admin-api/persistence — for the reason
// config.js's describe() is one shape: a console and an API that compute the
// same answer twice are a console and an API that will disagree about it.
// ---------------------------------------------------------------------------
function status() {
  log.debug('Entering status().');
  const out = {
    mode: activeMode,
    configuredMode: mode(),
    enabled: enabled(),
    healthy: enabled() ? !lastError : null,
    dataDir: activeMode === 'ldif' ? dataDir() : null,
    // NEVER the URL itself: it carries a password, and this answer is rendered
    // on a console page and returned by an ungated management API.
    database: activeMode === 'postgres' ? describeDatabase() : null,
    writeDelayMs: activeMode === 'postgres' ? 0 : writeDelay(),
    persistsDirectory: activeMode !== 'memory',
    persistsRealms: activeMode !== 'memory' && persistsRealms(),
    persistsAppconfig: activeMode !== 'memory' && persistsAppconfig(),
    pending: directoryDirty || realmsDirty || configDirty,
    writes: writes,
    failures: failures,
    lastWriteAt: lastWriteAt,
    lastError: lastError || null,
    restoredAt: restoredAt,
    restored: restoredCounts,
    entriesTracked: 0,
    realmsTracked: shadow.size,
    // Said here rather than only in a CLAUDE.md, because this is what an
    // operator reads and the sentence is the difference between a correct
    // deployment and a puzzling one.
    coordinates: false,
    note: 'Persistence is not coordination. Two processes pointed at one ' +
          'store each hold their own copy of the directory in memory and ' +
          'will not see each other\'s writes until they restart. Sessions, ' +
          'tokens, codes, artifacts, Kerberos tickets and the signing key ' +
          'are never persisted in any mode.'
  };
  shadow.forEach(function (rows) { out.entriesTracked += rows.size; });
  log.debug('Leaving status().');
  return out;
}

// Where the DEFAULT connection string points, for the one log line that has to
// say "you did not configure this". It goes through describeDatabase() rather
// than printing the string, for that function's reason: the value carries a
// password even when nobody chose it.
function describeDefaultTarget() {
  const target = describeDatabase();
  if (!target || !target.host) {
    return 'the built-in connection string';
  }
  return target.host + ':' + target.port + '/' + target.database;
}

// The database, named without naming the credential. A URL is parsed rather
// than regexed so that a password containing an '@' cannot fool it into
// reporting half of itself.
function describeDatabase() {
  const raw = databaseUrl();
  if (!raw) {
    return null;
  }
  try {
    const parsed = new URL(raw);
    return {
      host: parsed.hostname,
      port: parsed.port || '5432',
      database: String(parsed.pathname || '').replace(/^\//, ''),
      user: parsed.username || null
    };
  } catch (err) {
    // Not a URL this runtime can parse — a libpq keyword/value string, which
    // `pg` also accepts. There is nothing safe to show of it, because the
    // password is in there somewhere and we do not know where.
    return { host: null, port: null, database: null, user: null,
             note: 'the connection string is not a URL; nothing about it is ' +
                   'shown, because it carries a password.' };
  }
}

// ---------------------------------------------------------------------------
// THE TWO WIRINGS THIS MODULE DOES TO ITSELF AT REQUIRE TIME.
//
// Both are subscriptions rather than requires-in-anger, and both are here
// rather than in the other module for the reasons the header gives.
// ---------------------------------------------------------------------------

// config.js's slot. It calls this after every successful setOverride(),
// clearOverride() and clearAllOverrides(), with the realm the write landed in
// or null. See rule 3e in CLAUDE.md and the header above.
config.setOverrideStore(function (realmId) {
  configChanged(realmId);
});

// realms.js's event. Fired by create(), update(), remove(), setOverride() and
// clearOverride() — every door through which a realm row can change.
realms.onChange(function () {
  realmsChanged();
});

module.exports = {
  MODES: MODES,
  mode: mode,
  activeMode: function () { return activeMode; },
  enabled: enabled,
  dataDir: dataDir,
  setDirectory: setDirectory,
  start: start,
  stop: stop,
  flush: flush,
  directoryChanged: directoryChanged,
  realmsChanged: realmsChanged,
  configChanged: configChanged,
  status: status
};
