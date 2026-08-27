'use strict';
//
// File: persistence/persistence_ldif.js
//
// ---------------------------------------------------------------------------
// LOCAL DEVELOPMENT'S STORE: A DIRECTORY OF FILES, AND THE DIRECTORY ONE IS
// LDIF.
//
// `persistence.mode=ldif` is for the run where there is no database and nobody
// is going to start one — a `node server.js` on a laptop, a single container
// with a volume, a demonstration. It writes:
//
//   <dataDir>/realm-default.ldif   the default realm's directory
//   <dataDir>/realm-<id>.ldif      one per defined trust realm
//   <dataDir>/realms.json          the realm registry: names and overrides
//   <dataDir>/appconfig.json       the runtime appconfig overrides
//
// **WHY LDIF FOR THE FIRST OF THOSE AND JSON FOR THE OTHER TWO.** They are
// different kinds of thing. A directory has an interchange format that predates
// this service by thirty years and that every other tool in the ecosystem
// speaks: RFC 2849. Writing the entries as LDIF means the file is something
// `ldapadd -f`, `slapadd`, `ldifde` and a human reviewer can all read, and it
// means the answer to "how do I get this data into a real directory" is "you
// already have it" rather than "write a converter". A realm registry and a map
// of overrides have no such format — inventing an LDIF spelling for them would
// be a private format wearing a public one's syntax, which is worse than plain
// JSON that says what it is.
//
// **WHAT LDIF COSTS, AND WHAT IS DONE ABOUT IT.** The stored entry carries one
// thing LDIF has no home for: `origin`, this service's marker for how an entry
// came to exist (`seed`, or absent). It is written as an RFC 2849 COMMENT
// immediately above the record — `# sts-origin: seed` — which every other LDIF
// reader ignores and this one reads back. The alternative was an invented
// attribute, and that is worse in a way that is easy to miss: an attribute
// would be REAL on reload, would appear in search results, would match filters,
// and would turn a private marker into part of the directory's content.
//
// Everything else round-trips exactly. `dn` is written as it was typed and
// re-normalised on load by ldap_server.js, which is the only module allowed to
// normalise a DN here; `createdAt`/`modifiedAt` are not written separately
// because they are already the `createTimestamp` and `modifyTimestamp`
// attributes, and writing them twice is how two copies of one fact come to
// disagree.
//
// ---------------------------------------------------------------------------
// EVERY WRITE IS ATOMIC, AND ON THIS PATH THAT IS NOT PEDANTRY.
//
// A file is written to `<name>.tmp` and renamed over the target. `rename(2)` is
// atomic within a filesystem, so a reader — including the next start of this
// service — sees either the whole previous file or the whole new one and never
// a half-written directory. Without it, a `docker kill` timed a millisecond
// into a write produces an LDIF file that is truncated mid-record, and the next
// start restores most of a directory and reports success, which is the worst
// available outcome: silent partial data loss that looks like nothing happened.
//
// ---------------------------------------------------------------------------
// IT WRITES WHOLE FILES, AND THE DIFF IT IS HANDED IS USED ONLY TO CHOOSE
// WHICH.
//
// `saveDirectory()` receives both a per-entry diff and the whole live picture.
// A database driver uses the first; this one uses the second, and reads the
// diff for exactly one thing — `touched`, the list of realms something actually
// happened in. Rewriting only those is what stops a change in `acme` from
// rewriting the default realm's file, which matters because these files are
// meant to be diffable and a rewrite with no change is still a new mtime and a
// new line in a `git status` somebody is watching.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

// RFC 2849 says lines SHOULD be wrapped, and does not say where. 76 is what
// OpenLDAP's tools emit and is therefore what a diff of our file against one
// they wrote will line up with.
const WRAP_AT = 76;

// The marker that carries `origin` through a format that has no field for it.
// A comment, deliberately — see the header.
const ORIGIN_COMMENT = '# sts-origin: ';

// ---------------------------------------------------------------------------
// RFC 2849 section 2, the value-encoding rules, spelt out because getting one
// of them wrong is a silent corruption rather than an error.
//
// A value may be written as plain text only if it is a SAFE-STRING:
//   SAFE-INIT-CHAR  any octet except NUL, LF, CR, SPACE, ':' and '<'
//   SAFE-CHAR       any octet except NUL, LF and CR
// and — this one is not in the grammar but is in section 2's prose and in every
// implementation — it must not END with a space, because a trailing space is
// indistinguishable from the line wrapping that section 2 also defines.
//
// Anything else is base64 after a double colon. We also base64 anything
// non-ASCII: the grammar permits UTF-8 octets in a SAFE-STRING, but a file
// whose encoding is guessed by whoever opens it is a file that will come back
// wrong, and base64 removes the guess.
// ---------------------------------------------------------------------------
function needsBase64(value) {
  const s = String(value);
  if (s === '') {
    return false;
  }
  const first = s.charCodeAt(0);
  if (first === 0x20 || first === 0x3a || first === 0x3c) {
    return true;
  }
  if (s.charCodeAt(s.length - 1) === 0x20) {
    return true;
  }
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x00 || c === 0x0a || c === 0x0d || c > 0x7f) {
      return true;
    }
  }
  return false;
}

// One `name: value` line, encoded and folded. Folding is a newline followed by
// a single SPACE, and the continuation is what that space introduces — so a
// value that itself begins with a space would be ambiguous, which is exactly
// why such a value is base64 above.
function ldifLine(name, value) {
  let line;
  if (needsBase64(value)) {
    line = name + ':: ' + Buffer.from(String(value), 'utf8').toString('base64');
  } else {
    line = name + ': ' + String(value);
  }
  if (line.length <= WRAP_AT) {
    return line;
  }
  const parts = [line.slice(0, WRAP_AT)];
  let rest = line.slice(WRAP_AT);
  while (rest.length) {
    // WRAP_AT - 1 because the leading space of a continuation counts toward
    // the line's width. Off by one here produces a file that is still valid
    // and no longer lines up with anybody else's, which is the kind of thing
    // that is noticed a year later in a diff.
    parts.push(' ' + rest.slice(0, WRAP_AT - 1));
    rest = rest.slice(WRAP_AT - 1);
  }
  return parts.join('\n');
}

// One stored entry as an LDIF record. `dn` first, as the specification
// requires; then the attributes in the order the entry holds them, which is the
// order they were written and is therefore stable across runs.
function entryToLdif(entry) {
  const lines = [];
  if (entry.origin) {
    lines.push(ORIGIN_COMMENT + entry.origin);
  }
  lines.push(ldifLine('dn', entry.dn));
  const attributes = entry.attributes || {};
  Object.keys(attributes).forEach(function (name) {
    const values = attributes[name] || [];
    values.forEach(function (value) {
      lines.push(ldifLine(name, value));
    });
  });
  return lines.join('\n');
}

function toLdif(rows, header) {
  const out = [];
  // Comments before `version:` are legal and are where this file explains
  // itself to whoever opens it without having read any of this.
  header.forEach(function (line) { out.push('# ' + line); });
  out.push('version: 1');
  out.push('');
  rows.forEach(function (entry) {
    out.push(entryToLdif(entry));
    out.push('');
  });
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// READING IT BACK. Unfolding first, because every other rule operates on
// logical lines: a continuation is a line beginning with exactly one space, and
// what it continues is the line before it with no separator at all.
// ---------------------------------------------------------------------------
function unfold(text) {
  const raw = String(text).split(/\r?\n/);
  const out = [];
  raw.forEach(function (line) {
    if (line.length && line.charAt(0) === ' ' && out.length) {
      out[out.length - 1] += line.slice(1);
      return;
    }
    out.push(line);
  });
  return out;
}

// `name: value`, `name:: base64` or `name:< url`. The third is a URL reference,
// which this service does not write and will not follow: dereferencing a file:
// or http: URL out of a data file is a way to read something somebody else
// chose, and there is no reason for it here.
function parseLine(line) {
  const colon = line.indexOf(':');
  if (colon < 0) {
    return null;
  }
  const name = line.slice(0, colon);
  const rest = line.slice(colon + 1);
  if (rest.charAt(0) === '<') {
    return { name: name, value: null, url: true };
  }
  if (rest.charAt(0) === ':') {
    return { name: name,
             value: Buffer.from(rest.slice(1).trim(), 'base64').toString('utf8') };
  }
  // Exactly ONE leading space is the separator and is dropped; a second is part
  // of the value. `.trim()` here would be a data-losing convenience.
  return { name: name,
           value: rest.charAt(0) === ' ' ? rest.slice(1) : rest };
}

function fromLdif(text, log) {
  log.debug('Entering fromLdif().');
  const lines = unfold(text);
  const entries = [];
  let current = null;
  let pendingOrigin = '';
  let skipped = 0;

  function finish() {
    if (current) {
      entries.push(current);
    }
    current = null;
  }

  lines.forEach(function (line) {
    if (line === '') {
      finish();
      pendingOrigin = '';
      return;
    }
    if (line.charAt(0) === '#') {
      if (line.indexOf(ORIGIN_COMMENT) === 0) {
        pendingOrigin = line.slice(ORIGIN_COMMENT.length).trim();
      }
      return;
    }
    const parsed = parseLine(line);
    if (!parsed) {
      return;
    }
    if (parsed.url) {
      // Reported rather than silently dropped: the value is genuinely absent
      // from the entry that gets loaded, and an attribute quietly missing from
      // a restored directory is the hardest kind of difference to notice.
      skipped++;
      return;
    }
    const name = parsed.name.toLowerCase();
    if (name === 'version') {
      return;
    }
    if (name === 'dn') {
      finish();
      current = { dn: parsed.value, attributes: {},
                  origin: pendingOrigin || undefined };
      pendingOrigin = '';
      return;
    }
    if (!current) {
      // An attribute before any `dn:`. A truncated or hand-edited file.
      skipped++;
      return;
    }
    if (!current.attributes[name]) {
      current.attributes[name] = [];
    }
    current.attributes[name].push(parsed.value);
  });
  finish();

  // The two operational timestamps are already attributes, so the stored
  // object's own copies are rebuilt from them rather than written twice. An
  // entry whose file predates them — or that somebody added by hand with
  // ldapadd — gets nulls, and ldap_server.js fills those the way it fills them
  // for any entry that arrives without them.
  entries.forEach(function (entry) {
    const created = (entry.attributes.createtimestamp || [])[0];
    const modified = (entry.attributes.modifytimestamp || [])[0];
    entry.createdAt = created || null;
    entry.modifiedAt = modified || created || null;
  });

  if (skipped) {
    log.warn('persistence: ' + skipped + ' LDIF line(s) were not loaded — a ' +
             'URL-valued attribute (which this service will not dereference) ' +
             'or a line before the first dn:.');
  }
  log.debug('Leaving fromLdif(). ' + entries.length + ' entry/entries.');
  return entries;
}

// ---------------------------------------------------------------------------
// The driver.
// ---------------------------------------------------------------------------
function create(options) {
  const dir = options.dir;
  const log = options.log;

  // `realm-<id>.ldif`. The id is validated by realms.js against a pattern that
  // admits only lower-case letters, digits and hyphens, so it cannot contain a
  // separator — but this is a filename built from data, so the check is made
  // HERE too rather than assumed from over there. A path that escaped the data
  // directory would be a write anywhere the process can reach.
  function realmFile(realmId) {
    const id = String(realmId || '');
    if (!/^[a-z0-9][a-z0-9-]*$/.test(id)) {
      throw new Error('persistence: "' + id + '" is not a realm id this ' +
                      'driver will build a filename from.');
    }
    return path.join(dir, 'realm-' + id + '.ldif');
  }

  function writeAtomic(file, text) {
    log.debug('Entering writeAtomic(). file=' + file);
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, text, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmp, file);
    log.debug('Leaving writeAtomic().');
  }

  function readIfPresent(file) {
    try {
      return fs.readFileSync(file, 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') {
        // The ordinary first run. Not an error, and the caller's null means
        // "nothing has ever been written" rather than "it was empty".
        return null;
      }
      throw err;
    }
  }

  return {
    name: 'ldif',

    open: function () {
      log.debug('Entering the ldif driver open().');
      return Promise.resolve().then(function () {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
        // Written and removed rather than assumed, because a volume mounted
        // read-only is a real deployment mistake and the failure it produces
        // otherwise arrives 1500ms later from inside a timer, detached from
        // the thing that caused it.
        const probe = path.join(dir, '.writable');
        fs.writeFileSync(probe, 'sts', { encoding: 'utf8', mode: 0o600 });
        fs.unlinkSync(probe);
        log.info('persistence: the ldif store is ' + dir + '.');
        log.debug('Leaving the ldif driver open().');
      });
    },

    close: function () {
      // Nothing to close: every write is its own open/write/rename. The
      // function exists because the driver contract has it and a driver that
      // omitted it would make every caller test for it.
      return Promise.resolve();
    },

    loadDirectory: function () {
      log.debug('Entering the ldif driver loadDirectory().');
      return Promise.resolve().then(function () {
        let names;
        try {
          names = fs.readdirSync(dir);
        } catch (err) {
          if (err.code === 'ENOENT') {
            log.debug('Leaving loadDirectory(). No data directory yet.');
            return null;
          }
          throw err;
        }
        const files = names.filter(function (name) {
          return /^realm-[a-z0-9][a-z0-9-]*\.ldif$/.test(name);
        });
        if (!files.length) {
          log.debug('Leaving loadDirectory(). Nothing has been written yet.');
          return null;
        }
        const out = {};
        files.forEach(function (name) {
          const realmId = name.replace(/^realm-/, '').replace(/\.ldif$/, '');
          const text = readIfPresent(path.join(dir, name));
          if (text === null) {
            return;
          }
          out[realmId] = fromLdif(text, log);
          log.info('persistence: read ' + out[realmId].length + ' entry/ies ' +
                   'for the realm "' + realmId + '" from ' + name + '.');
        });
        log.debug('Leaving loadDirectory(). ' + files.length + ' file(s).');
        return out;
      });
    },

    loadRealms: function () {
      log.debug('Entering the ldif driver loadRealms().');
      return Promise.resolve().then(function () {
        const text = readIfPresent(path.join(dir, 'realms.json'));
        if (text === null) {
          log.debug('Leaving loadRealms(). No file.');
          return null;
        }
        const parsed = JSON.parse(text);
        log.debug('Leaving loadRealms(). ' +
                  (parsed.realms || []).length + ' realm(s).');
        return parsed.realms || [];
      });
    },

    loadOverrides: function () {
      log.debug('Entering the ldif driver loadOverrides().');
      return Promise.resolve().then(function () {
        const text = readIfPresent(path.join(dir, 'appconfig.json'));
        if (text === null) {
          log.debug('Leaving loadOverrides(). No file.');
          return null;
        }
        const parsed = JSON.parse(text);
        log.debug('Leaving loadOverrides().');
        return parsed.overrides || {};
      });
    },

    // Whole files, one per realm that something happened in. See the header:
    // the per-entry diff is read only for `touched`.
    saveDirectory: function (change) {
      log.debug('Entering the ldif driver saveDirectory().');
      return Promise.resolve().then(function () {
        change.removedRealms.forEach(function (realmId) {
          try {
            fs.unlinkSync(realmFile(realmId));
            log.info('persistence: the realm "' + realmId + '" is gone; its ' +
                     'LDIF file was removed with it.');
          } catch (err) {
            if (err.code !== 'ENOENT') {
              throw err;
            }
            // Already absent, which is the state this was trying to reach.
          }
        });
        change.touched.forEach(function (realmId) {
          const rows = change.all.get(realmId);
          if (!rows) {
            return;
          }
          const list = [];
          rows.forEach(function (entry) { list.push(entry); });
          writeAtomic(realmFile(realmId), toLdif(list, [
            'The "' + realmId + '" realm\'s directory, written by mock-sts.',
            'RFC 2849 LDIF. It is read back at startup when ' +
              'persistence.mode=ldif, and it is ordinary LDIF otherwise: ' +
              'ldapadd -f will load it into any directory.',
            'A "# sts-origin:" comment above a record is this service\'s own ' +
              'marker for how the entry came to exist. Every other reader ' +
              'ignores it.',
            'Editing this file by hand is fine while the service is STOPPED. ' +
              'While it is running, the service rewrites the whole file on ' +
              'the next change and your edit is gone.'
          ]));
          log.info('persistence: wrote ' + list.length + ' entry/ies for the ' +
                   'realm "' + realmId + '".');
        });
        log.debug('Leaving the ldif driver saveDirectory().');
      });
    },

    saveRealms: function (rows) {
      log.debug('Entering the ldif driver saveRealms().');
      return Promise.resolve().then(function () {
        writeAtomic(path.join(dir, 'realms.json'), JSON.stringify({
          version: 1,
          note: 'The trust realms mock-sts had defined when this was written. ' +
                'The DEFAULT realm is not here and never will be: it is a ' +
                'constant in common/realms.js, not a row.',
          realms: rows
        }, null, 2) + '\n');
        log.debug('Leaving the ldif driver saveRealms(). ' + rows.length +
                  ' realm(s).');
      });
    },

    saveOverrides: function (map) {
      log.debug('Entering the ldif driver saveOverrides().');
      return Promise.resolve().then(function () {
        writeAtomic(path.join(dir, 'appconfig.json'), JSON.stringify({
          version: 1,
          note: 'Runtime appconfig overrides — the TOP of config.js\'s five ' +
                'layers, which is what a console Save and POST ' +
                '/admin-api/config/set write. They are re-applied at startup ' +
                'through the same setOverride() a caller uses, so this file ' +
                'adds no layer. Only a runtime-changeable setting can be ' +
                'here; a restart-only one is refused at the writing end.',
          overrides: map
        }, null, 2) + '\n');
        log.debug('Leaving the ldif driver saveOverrides(). ' +
                  Object.keys(map).length + ' override(s).');
      });
    }
  };
}

module.exports = {
  create: create,
  // Exported for tests/ and for nothing else in this service: the codec is the
  // half of this file that can be wrong in a way that is invisible until a
  // restart, so it is the half that has to be assertable without a filesystem.
  toLdif: toLdif,
  fromLdif: fromLdif,
  needsBase64: needsBase64,
  ldifLine: ldifLine
};
