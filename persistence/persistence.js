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
// ships no storage of any kind and never has.
// (`node-ldapjs/lib/persistent_search.js` is the LDAP *persistent search*
// change-notification control — the name is a trap, and it is about telling a
// connected client that something changed, not about a disk.) The store in this
// service is ours and always was: `ldap/ldap_server.js`'s `const entries =
// realms.map()`, a Map of normalised DN to `{dn, attributes, createdAt,
// modifiedAt, origin}`.
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
// answering out of memory, `GET /admin/ldap/service` and `/admin/persistence`
// both carry the error, and the next flush tries again with the same diff (the
// shadow is only advanced on success, so nothing is lost by a failure). The
// alternative — refusing the LDAP operation whose write failed — was considered
// and rejected: it would make a database outage take down sixteen protocol
// families that do not need a database, and no other refusal in this service is
// that expensive.
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
//     `ldap_server.js` registers `/ldap` and `/admin/ldap/directory` at its
//     require time, and this module is required at #4a — far above `admin.js`.
//     A require from here would drag both of those routes to the front of the
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
// The keystore, so this module can hand it the driver the moment one is open.
// A LEAF (rule 3) that registers no route; it requires `config`, `crypto`,
// `mode` and `secrets` and none of them requires this module back.
const keystore = require('../common/keystore');
// WHERE A SECRET COMES FROM (2026-09-12). A LEAF (rule 3) requiring only
// `config` and its own logger, and this module reaches it for ONE thing: the
// database password, when a deployment keeps it in the same place it keeps the
// key-encryption key rather than in the connection string. `keystore.js`
// already requires it for the key itself, so this is a second reader of one
// mechanism rather than a second mechanism.
const secrets = require('../common/secrets');
// WHAT THIS PROCESS MINTED, in product mode. A LIBRARY (rule 3) that registers
// no route and requires this module for nothing — it is HANDED the driver
// below, the way `keystore.setStore()` is, so the two can be tested apart.
const minted = require('./persistence_minted');
// THE USED-ASSERTION HISTORY (2026-09-13): every RFC 7523 and RFC 7522
// assertion this service has accepted, persisted in EVERY store and both modes
// rather than as minted state — see that module's header for why. A LIBRARY in
// `common/` that requires `config`, `realms` and `error_codes` and nothing that
// requires this file, so the require closes no cycle.
const usedAssertions = require('../common/used_assertions');
// SEVERAL PROCESSES AGAINST ONE STORE. A LIBRARY (rule 3), handed the driver
// and the appliers below — it requires this module for nothing, which is what
// lets `tests/replication.js` drive it against a stub with no database.
const replication = require('./persistence_replication');
// The ordinary direction, and the header above argues why it is a require
// rather than a third slot: realms.js requires config.js and async_hooks and
// nothing else, registers no route, and does not require this module.
const realms = require('../common/realms');
// A LEAF with no requires: the failure codes on the log lines and the fatal
// refusals below. See common/error_codes.js.
const errorCodes = require('../common/error_codes');
// THE CLUSTER GATE (2026-09-14, #46). A LIBRARY that is handed the open driver;
// it requires config, the capability table and the error codes, and nothing
// that requires this module back. See cluster/cluster.js.
const cluster = require('../cluster/cluster');
// A LEAF with no requires: the three-way merge of one directory entry, which
// the postgres driver applies inside its transaction and this module applies
// again to a local write that raced a flush or a replicated row (#46 sec. 3).
const directoryMerge = require('./directory_merge');

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
  // `applyEntry` and `removeEntry` are NOT on this list, deliberately: they
  // are what cross-process coordination needs, and a build without them is a
  // build that persists correctly and does not coordinate — which is what this
  // service was until 2026-09-06 and is a smaller service rather than a broken
  // one. `persistence_replication.js` checks for them by name and reports the
  // absence instead of failing.
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

// ---------------------------------------------------------------------------
// AND THE SAME FOR THE REALM REGISTRY AND THE SETTINGS (2026-09-14, #46).
//
// Both were written WHOLESALE — every realm this process held, every override
// it held, and a DELETE of every row that was not in the list. That was exact
// for one process and it is data loss for two: a realm created on node B, then
// any realm change saved on node A before B's row had replicated, deleted B's
// realm across the cluster; a setting written on B was deleted by A's next
// save of any setting. **A SAVE MUST NEVER DELETE A ROW MERELY BECAUSE THIS
// PROCESS'S COPY DOES NOT HOLD IT.**
//
// So each has a shadow — what this process knows the store holds, primed from
// the restore and advanced by every write it makes and every change it applies
// — and a flush writes the DIFFERENCE between the live copy and it: the realms
// whose name, description or overrides moved (each override set or cleared by
// key, merged into the stored row in SQL), the settings set and the settings
// cleared. A DELETE is written only for what this process removed:
// `removedHere` names the realms `realms.remove()` was called for here, and a
// cleared setting is one the shadow says is stored and the live map no longer
// has. A reset-all still clears every stored setting in one process, because
// there the shadow IS the table.
//
// The `ldif` driver ignores the delta and writes its whole files, which is
// right for it: a file store is one process's and cannot be shared.
// ---------------------------------------------------------------------------
// realm id -> JSON of { name, description, overrides }
const realmShadow = new Map();
// key -> raw value, or null before a restore primed it
let appconfigShadow = null;
// The realms removed in THIS process and not yet written down.
const removedHere = new Set();

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
// The ONE flush queued behind `flushing`, shared by every caller that arrives
// while it runs. See flush().
let flushQueued = null;

// True while start() is loading. Every changed() call is a no-op then: restore
// writes into the live stores through the same functions an operator does, and
// without this the first act of a restored process would be to write back
// exactly what it just read.
let restoring = false;

// True once stop() has run. A flush scheduled by a late timer after the pool is
// closed would log an error about a closed client on every shutdown.
let stopped = false;

// What /admin/persistence, GET /admin/ldap/service and GET
// /admin-api/persistence report.
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
  log.debug("Entering mode().");
  log.debug("Leaving mode().");
  return config.value('persistence.mode');
}

function dataDir() {
  log.debug("Entering dataDir().");
  // Resolved against the PACKAGE ROOT rather than the working directory, for
  // config_file.js's reason: a relative path resolves against the directory of
  // whoever is doing the resolving, and this module is two levels from where
  // `./data` means what somebody typing it meant. An absolute path is left
  // alone, which is what a container's volume mount always is.
  const configured = String(config.value('persistence.dataDir') || './data');
  if (path.isAbsolute(configured)) {
    log.debug("Leaving dataDir().");
    return configured;
  }
  log.debug("Leaving dataDir().");
  return path.resolve(path.join(__dirname, '..'), configured);
}

function databaseUrl() {
  log.debug("Entering databaseUrl().");
  log.debug("Leaving databaseUrl().");
  return String(config.value('persistence.databaseUrl') || '');
}

function writeDelay() {
  log.debug("Entering writeDelay().");
  log.debug("Leaving writeDelay().");
  // Postgres does not use it: a transaction per request is the point, so the
  // delay there is 0 whatever this says. See the header.
  return config.value('persistence.writeDelay');
}

function persistsAppconfig() {
  log.debug("Entering persistsAppconfig().");
  log.debug("Leaving persistsAppconfig().");
  return config.value('persistence.appconfig');
}

function persistsRealms() {
  log.debug("Entering persistsRealms().");
  log.debug("Leaving persistsRealms().");
  return config.value('persistence.realms');
}

// Is anything being written down at all? Every caller in this file asks this
// rather than comparing the mode to 'memory', so that a mode added later is one
// edit here instead of a search for string comparisons.
function enabled() {
  log.debug("Entering enabled().");
  log.debug("Leaving enabled().");
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

// ---------------------------------------------------------------------------
// A JOURNAL OF WHAT MOVED, SO A FLUSH NEED NOT WALK THE WHOLE DIRECTORY
// (2026-09-07).
//
// `diff()` compares every entry in every realm against the shadow. That is
// affordable DEBOUNCED — a burst of writes coalesces into one walk — and it
// became the dominant cost the moment a flush started happening per request,
// which is what read-your-write across request workers needs: the worker
// announces its commit after each response, and a reader waits for it.
//
// Measured with the whole-directory diff on that path: a 5,000-user SCIM load
// took 18.2 MINUTES in the dispatch mode against 17 seconds in one process,
// 219ms per create and rising, because every create walked a directory that
// every create made longer.
//
// So a writer that knows where it wrote says so, and only those entries are
// compared. **A writer that says nothing still gets the full walk**, which is
// the old behaviour and is correct — `dirtyEverything` is the safe default and
// the realm-removal path, which cannot name one DN, deliberately takes it.
// ---------------------------------------------------------------------------
let dirtyDns = new Set();
let dirtyEverything = false;

// ---------------------------------------------------------------------------
// WRITE GENERATIONS FOR THE DIRECTORY, THE REALMS AND THE SETTINGS
// (2026-09-14, #46) — the same three numbers `persistence_minted.js` keeps for
// its journal, and for the same caller. `dirGeneration` goes up whenever a
// dirty bit is set; a flush records the generation its take covered; and
// `dirCommittedAt` is the highest such generation whose write succeeded. So the
// cluster barrier can hold a response for the writes made while IT was being
// handled — `commitThrough()` below — instead of for any flush the process
// happens to have pending, which held every request behind the previous
// request's audit row.
// ---------------------------------------------------------------------------
let dirGeneration = 0;
let dirCommittedAt = 0;
let flushingTakenAt = 0;
// { gen, resolve } for each caller of directoryThrough() still waiting.
let dirWaiters = [];

function settleDirWaiters(error) {
  log.debug("Entering settleDirWaiters().");
  const still = [];
  dirWaiters.forEach(function (one) {
    if (dirCommittedAt >= one.gen) {
      one.resolve({ written: true });
    } else if (error) {
      one.resolve({ written: false, error: error });
    } else {
      still.push(one);
    }
  });
  dirWaiters = still;
  log.debug("Leaving settleDirWaiters().");
}

// Resolves once everything dirtied up to generation `target` has committed,
// or with `error` when the flush that took it failed.
function directoryThrough(target) {
  log.debug("Entering directoryThrough().");
  if (dirCommittedAt >= target || !enabled()) {
    log.debug("Leaving directoryThrough(). Already committed.");
    return Promise.resolve({ written: false });
  }
  const waiting = new Promise(function (resolve) {
    dirWaiters.push({ gen: target, resolve: resolve });
  });
  if (!(flushing && flushingTakenAt >= target)) {
    // A flush that takes the dirty bits AFTER the target: the queued one when
    // a flush is running, which serves every caller that arrived before it
    // starts. Its answer is the waiter's to report.
    flush().then(function (result) {
      if (result && result.error) {
        settleDirWaiters(result.error);
      } else {
        settleDirWaiters(null);
      }
    });
  }
  log.debug("Leaving directoryThrough().");
  return waiting;
}

function directoryChanged(dn) {
  log.debug("Entering directoryChanged().");
  if (!enabled() || restoring) {
    log.debug("Leaving directoryChanged().");
    return;
  }
  directoryDirty = true;
  dirGeneration += 1;
  if (dn === undefined || dn === null || dn === '') {
    dirtyEverything = true;
  } else if (!dirtyEverything) {
    dirtyDns.add(String(dn));
  }
  schedule();
  log.debug("Leaving directoryChanged().");
}

// ---------------------------------------------------------------------------
// A FOURTH DOOR, AND IT IS NOT A FOURTH DIRTY BIT.
//
// `persistence_minted.js` keeps its own journal — it has to, because what it
// records is a KEY and the three bits above record only that something in a
// category moved. What it needs from here is the SCHEDULE, so that a minted
// write and a directory write made while handling one request cost one wake
// between them. So this is the one "something changed" door that marks nothing
// and only schedules.
// ---------------------------------------------------------------------------
//
// **AND UNTIL 2026-09-14 NOTHING CALLED IT**, so a minted write was flushed
// only when something else was — a sign-out's tombstone sat in the journal
// and the ended session stayed live in the store. `persistence_minted.js`'s
// `note()` calls it now, once per flush, through `setScheduler()` below; that
// file's block above `scheduler` has the measurement. It answers whether it
// scheduled, so a write made while this answers no asks again.
function mintedChanged() {
  log.debug("Entering mintedChanged().");
  if (!enabled() || restoring) {
    log.debug("Leaving mintedChanged().");
    return false;
  }
  schedule();
  log.debug("Leaving mintedChanged().");
  return true;
}

function realmsChanged() {
  log.debug("Entering realmsChanged().");
  if (!enabled() || restoring || !persistsRealms()) {
    log.debug("Leaving realmsChanged().");
    return;
  }
  realmsDirty = true;
  dirGeneration += 1;
  schedule();
  log.debug("Leaving realmsChanged().");
}

// `realmId` is the realm the override landed in, or null for a process-wide
// one. config.js's setOverride() already decides which, so this function is
// told rather than asked: a realm's overrides live on the realm row and a
// process-wide one lives in the appconfig store, and those are two different
// files and two different tables.
function configChanged(realmId) {
  log.debug("Entering configChanged().");
  if (!enabled() || restoring) {
    log.debug("Leaving configChanged().");
    return;
  }
  if (realmId) {
    realmsChanged();
    log.debug("Leaving configChanged().");
    return;
  }
  if (!persistsAppconfig()) {
    log.debug("Leaving configChanged().");
    return;
  }
  configDirty = true;
  dirGeneration += 1;
  schedule();
  log.debug("Leaving configChanged().");
}

function schedule() {
  log.debug("Entering schedule().");
  if (timer || stopped) {
    log.debug("Leaving schedule().");
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
      log.error(errorCodes.tag('STS-STORE-0001') +
                'persistence: a scheduled flush failed: ' + err.message);
    });
  }, delay);
  // The timer must not hold the process open on its own — a service with
  // nothing else to do should still be able to exit.
  if (timer.unref) {
    timer.unref();
  }
  log.debug("Leaving schedule().");
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
// ---------------------------------------------------------------------------
// ONE ENTRY OUT OF A REALM, WITHOUT WALKING IT (2026-09-08).
//
// `directory.entryAt()` is `ldap_server.js`'s keyed read. It is OPTIONAL — the
// slot's `needed` list above is unchanged, so a filler written before this
// exists (the in-process `appconfig_persistence.js` stub is one) still
// installs — and the fallback is the walk this replaced, which is correct and
// merely slow.
//
// It matters because both callers ran per WRITE rather than per burst once the
// request-worker pool arrived: the flush below diffed against a snapshot of
// everything, and `applyDirectoryChange()` searched a whole realm to record one
// applied row. Each was O(entries) per create, on the writing side and on every
// receiving side, which is quadratic over a bulk load and showed up exactly
// like that — 65ms per SCIM create at 500 entries, 109ms at 4,000.
// ---------------------------------------------------------------------------
function entryAt(realmId, key) {
  log.debug("Entering entryAt().");
  if (typeof directory.entryAt === 'function') {
    log.debug("Leaving entryAt().");
    return directory.entryAt(realmId, key);
  }
  const found = (directory.realmEntries(realmId) || []).find(function (one) {
    return one.key === key;
  });
  log.debug("Leaving entryAt().");
  return found ? found.entry : null;
}

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
function diff(live, wanted, removals) {
  log.debug('Entering diff().');
  const upserts = [];
  const deletes = [];
  const touched = {};
  const removedRealms = [];

  // ONLY WHAT THE JOURNAL NAMES, WHERE THERE IS ONE. `wanted` is null for a
  // full walk — a writer that did not say where, a restore, the first flush —
  // and a Set of normalised keys otherwise. The DELETE half still walks the
  // shadow for a journaled realm, because a key that is GONE from `rows` is
  // exactly the one the journal cannot name by looking at the live store.
  // THE REALMS TO CONSIDER, and where their rows come from. With a journal
  // there is no snapshot: each realm is visited and each journalled key looked
  // up directly, which is the same comparison the snapshot path makes and none
  // of the work of building one.
  const walk = live || new Map(realms.list().map(function (realm) {
    return [realm.id, null];
  }));
  walk.forEach(function (rows, realmId) {
    const at = function (key) {
      log.debug("Entering at().");
      log.debug("Leaving at().");
      return rows ? rows.get(key) : entryAt(realmId, key);
    };
    const was = shadow.get(realmId) || new Map();
    if (wanted) {
      wanted.forEach(function (key) {
        const entry = at(key);
        if (!entry) {
          // GONE FROM THE LIVE STORE. Reported as a delete only if the shadow
          // says this process had written it — a key journalled in one realm
          // is looked for in every realm, and "absent here and never written
          // here" is the ordinary case rather than a deletion.
          if (was.has(key)) {
            deletes.push({ realm: realmId, key: key });
            touched[realmId] = true;
          }
          return;
        }
        const json = JSON.stringify(entry);
        if (was.get(key) !== json) {
          // `base` IS WHAT THIS PROCESS BASED THE WRITE ON — the shadow's
          // copy, or null when it believed the DN held nothing. The postgres
          // driver merges the live entry with the row as it is now against
          // it, so an attribute another node changed since is kept rather
          // than overwritten. See `persistence/directory_merge.js`.
          upserts.push({ realm: realmId, key: key, entry: entry, json: json,
                         base: was.has(key) ? was.get(key) : null });
          touched[realmId] = true;
        }
      });
      return;
    }
    rows.forEach(function (entry, key) {
      const json = JSON.stringify(entry);
      if (was.get(key) !== json) {
        upserts.push({ realm: realmId, key: key, entry: entry, json: json,
                       base: was.has(key) ? was.get(key) : null });
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
    // ONLY A FULL WALK CAN SEE A REALM THAT IS GONE. Without a snapshot there
    // is nothing to compare the shadow against — so `realms.onChange()` below
    // marks the whole directory dirty, which forces the very next flush to
    // build one. The removal is reported by that walk rather than missed
    // here.
    if (!live || live.has(realmId)) {
      return;
    }
    // **ONLY A REALM THIS PROCESS REMOVED (2026-09-14, #46).** A realm in the
    // shadow and not in the registry was, until this, always one this process
    // had removed. With several nodes it is also a realm ANOTHER node created,
    // whose entries replicated here before its registry row did — and the
    // deletes below then removed that realm's directory, its registry row and
    // everything it had minted from the store, on every node. `removedHere` is
    // filled by `realms.onChange()` below for a removal made here and nowhere
    // else; a realm that is merely not here yet is left alone.
    if (!removals || removals.indexOf(realmId) < 0) {
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
// ---------------------------------------------------------------------------
// THE SHADOW RECORDS WHAT WAS WRITTEN, NOT WHAT IS LIVE NOW (2026-09-07).
//
// This used to re-read `live` and stringify it — and `live` holds REFERENCES to
// the stored entries, which the service mutates in place. The database write
// between `diff()` and this call is asynchronous, so anything written during it
// was already visible here: the shadow recorded the NEWER value as persisted
// while only the older one had actually been sent. The next diff then found no
// difference and never wrote it. Lost, silently, with nothing failing.
//
// **IT WAS ALWAYS A RACE AND PER-REQUEST FLUSHING MADE IT ROUTINE.** Measured:
// `POST /oauth2/register` saves twice — once for the record, once with the
// registration document attached — and in a dispatched run some client rows
// reached `sts_ldap_entries` with no `appregistrationjson` at all. Reading such
// a registration back gave `userinfo_signed_response_alg: undefined` on two
// workers of three and the right answer on the one holding it in memory, which
// is what `sts_userinfo_protected` measured as a signed response arriving as
// `application/json`.
//
// So the shadow is advanced from the CHANGES — the exact `json` that was
// diffed and sent — and from nothing else. A key not in this batch keeps
// whatever the shadow already said about it, which is the truth: nothing was
// written for it. That makes the full and partial paths identical here, so
// `wanted` is no longer needed.
// ---------------------------------------------------------------------------
function advanceShadow(changes, removedRealms) {
  log.debug('Entering advanceShadow().');
  removedRealms.forEach(function (realmId) { shadow.delete(realmId); });
  changes.upserts.forEach(function (row) {
    let held = shadow.get(row.realm);
    if (!held) {
      held = new Map();
      shadow.set(row.realm, held);
    }
    held.set(row.key, row.json);
  });
  changes.deletes.forEach(function (row) {
    const held = shadow.get(row.realm);
    if (held) {
      held.delete(row.key);
    }
  });
  log.debug('Leaving advanceShadow(). ' + changes.upserts.length +
            ' upsert(s), ' + changes.deletes.length + ' delete(s).');
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
  log.debug("Entering realmRows().");
  log.debug("Leaving realmRows().");
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
// THE REALM REGISTRY AND THE SETTINGS AS DELTAS AGAINST THEIR SHADOWS
// (2026-09-14, #46). See `realmShadow` above for why. Computed SYNCHRONOUSLY
// when a flush takes its dirty bits, and the shadows advanced from exactly
// what was computed once the write succeeded — `advanceShadow()`'s rule for
// the directory: record what was SENT, never what is live by then.
// ---------------------------------------------------------------------------
function sameValue(a, b) {
  log.debug("Entering sameValue().");
  log.debug("Leaving sameValue().");
  return JSON.stringify(a === undefined ? null : a) ===
         JSON.stringify(b === undefined ? null : b);
}

// What one realm row changed against what the store is known to hold, or null
// for nothing. `was` is the parsed shadow, or null for a realm never stored.
function realmChangeOf(row, was) {
  log.debug("Entering realmChangeOf().");
  const overrides = row.overrides || {};
  if (!was) {
    log.debug("Leaving realmChangeOf(). A realm the store does not hold.");
    return { row: row, name: true, description: true,
             set: Object.assign({}, overrides), cleared: [] };
  }
  const held = was.overrides || {};
  const set = {};
  const cleared = [];
  Object.keys(overrides).forEach(function (key) {
    if (!Object.prototype.hasOwnProperty.call(held, key) ||
        !sameValue(held[key], overrides[key])) {
      set[key] = overrides[key];
    }
  });
  Object.keys(held).forEach(function (key) {
    if (!Object.prototype.hasOwnProperty.call(overrides, key)) {
      cleared.push(key);
    }
  });
  const name = row.name !== was.name;
  const description = row.description !== was.description;
  if (!name && !description && !cleared.length && !Object.keys(set).length) {
    log.debug("Leaving realmChangeOf(). Unchanged.");
    return null;
  }
  log.debug("Leaving realmChangeOf().");
  return { row: row, name: name, description: description, set: set,
           cleared: cleared };
}

function realmsDelta(removals) {
  log.debug("Entering realmsDelta().");
  const upserts = [];
  const liveIds = new Set();
  realmRows().forEach(function (row) {
    liveIds.add(row.id);
    const was = realmShadow.has(row.id)
      ? JSON.parse(realmShadow.get(row.id)) : null;
    const change = realmChangeOf(row, was);
    if (change) {
      upserts.push(change);
    }
  });
  const removed = (removals || []).filter(function (id) {
    return !liveIds.has(id);
  });
  log.debug("Leaving realmsDelta(). " + upserts.length + " changed, " +
            removed.length + " removed.");
  return { upserts: upserts, removed: removed };
}

function advanceRealmShadow(delta) {
  log.debug("Entering advanceRealmShadow().");
  delta.removed.forEach(function (id) {
    realmShadow.delete(id);
  });
  delta.upserts.forEach(function (change) {
    const was = realmShadow.has(change.row.id)
      ? JSON.parse(realmShadow.get(change.row.id))
      : { name: change.row.name, description: change.row.description,
          overrides: {} };
    if (change.name) {
      was.name = change.row.name;
    }
    if (change.description) {
      was.description = change.row.description;
    }
    was.overrides = was.overrides || {};
    change.cleared.forEach(function (key) {
      delete was.overrides[key];
    });
    Object.keys(change.set).forEach(function (key) {
      was.overrides[key] = change.set[key];
    });
    realmShadow.set(change.row.id, JSON.stringify(was));
  });
  log.debug("Leaving advanceRealmShadow().");
}

function appconfigDelta() {
  log.debug("Entering appconfigDelta().");
  const live = config.persistableOverrides();
  const held = appconfigShadow || {};
  const set = {};
  const cleared = [];
  Object.keys(live).forEach(function (key) {
    if (!Object.prototype.hasOwnProperty.call(held, key) ||
        !sameValue(held[key], live[key])) {
      set[key] = live[key];
    }
  });
  Object.keys(held).forEach(function (key) {
    if (!Object.prototype.hasOwnProperty.call(live, key)) {
      cleared.push(key);
    }
  });
  log.debug("Leaving appconfigDelta(). " + Object.keys(set).length +
            " set, " + cleared.length + " cleared.");
  return { set: set, cleared: cleared, live: live };
}

function advanceAppconfigShadow(delta) {
  log.debug("Entering advanceAppconfigShadow().");
  const next = Object.assign({}, appconfigShadow || {});
  delta.cleared.forEach(function (key) {
    delete next[key];
  });
  Object.keys(delta.set).forEach(function (key) {
    next[key] = delta.set[key];
  });
  appconfigShadow = next;
  log.debug("Leaving advanceAppconfigShadow().");
}

// ---------------------------------------------------------------------------
// WHAT THE STORE DECIDED, APPLIED HERE (2026-09-14, #46 section 3).
//
// The postgres driver answers a directory flush with the rows another node's
// write decided: `merged` (both kept, and the stored entry is not this
// process's copy), `theirs` (a different entry at that DN committed first) and
// `deleted` (another node deleted it). Each is put into the live directory
// with the journal suppressed, and the shadow is set to what the STORE holds —
// so the next diff compares against the truth.
//
// **A WRITE MADE WHILE THE FLUSH WAS OUT IS NOT OVERWRITTEN.** The live entry
// is compared with the JSON that was sent; if it moved, it is merged once more
// — base: what was sent, mine: live, theirs: what was stored — and the key is
// journalled again, so the newer local change is written by the next flush
// against the right base.
// ---------------------------------------------------------------------------
function applyDirectoryOutcomes(changes, outcomes) {
  log.debug("Entering applyDirectoryOutcomes().");
  if (!outcomes || !outcomes.length || !directory ||
      typeof directory.applyEntry !== 'function') {
    log.debug("Leaving applyDirectoryOutcomes(). Nothing to apply.");
    return;
  }
  const sentJson = new Map();
  changes.upserts.forEach(function (row) {
    sentJson.set(row.realm + '\n' + row.key, row.json);
  });
  outcomes.forEach(function (one) {
    const sent = sentJson.get(one.realm + '\n' + one.key);
    const live = entryAt(one.realm, one.key);
    const moved = !!live && JSON.stringify(live) !== sent;
    const rows = shadow.get(one.realm) || new Map();
    shadow.set(one.realm, rows);
    const was = restoring;
    restoring = true;
    try {
      if (one.outcome === 'deleted') {
        log.warn(errorCodes.tag('STS-STORE-0053') + 'persistence: ' +
                 one.key + ' in the "' + one.realm + '" realm was changed ' +
                 'here after another node deleted it; the delete wins, and ' +
                 'it has been removed here too.');
        directory.removeEntry(one.realm, one.key);
        rows.delete(one.key);
        return;
      }
      if (one.outcome === 'theirs') {
        log.warn(errorCodes.tag('STS-STORE-0052') + 'persistence: ' +
                 one.key + ' in the "' + one.realm + '" realm was added ' +
                 'here while another node added a different entry at the ' +
                 'same DN, which committed first. That entry is kept and ' +
                 'replaces this process\'s copy.');
      }
      let applied = one.entry;
      if (moved && one.outcome === 'merged') {
        applied = directoryMerge.mergeEntry(sent ? JSON.parse(sent) : null,
                                            live, one.entry).entry ||
                  one.entry;
      }
      directory.applyEntry(one.realm, one.key, applied);
      rows.set(one.key, directoryMerge.canonicalJson(one.entry));
    } finally {
      restoring = was;
    }
    if (moved && one.outcome === 'merged') {
      // The newer local change goes out with the next flush.
      directoryDirty = true;
      dirGeneration += 1;
      dirtyDns.add(one.key);
      schedule();
    }
  });
  log.debug("Leaving applyDirectoryOutcomes(). " + outcomes.length +
            " row(s).");
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
    // -----------------------------------------------------------------------
    // ONE FLUSH QUEUED BEHIND THE RUNNING ONE, SHARED BY EVERY CALLER
    // (2026-09-13).
    //
    // This was `return flushing.then(flush)` per caller, and in postgres mode
    // there is a caller per WRITE: `schedule()` arms a zero-delay timer, the
    // timer calls this, and a write that lands while a transaction is open
    // arms the next one. So every write made during a flush added a waiter;
    // when it settled ALL of them ran, one started the next flush, and every
    // other one chained itself again. The waiters therefore never drained
    // while the writes went on — fifty thousand LDAP adds were fifty thousand
    // waiters re-chained on every commit, a promise, a closure and two debug
    // calls each.
    //
    // **MEASURED, AND IT IS WHAT FAILED THE 50k JOB IN `postgres` MODE.** A
    // sampling heap profile of a single-process postgres service during that
    // load put over 3 GB of 6.6 GB allocated in fifteen seconds in this one
    // line and the promise machinery under it. RSS went from 1 GB to 4.2 GB,
    // GC stalls of 2.6s and 5.3s stopped the process — the one group create
    // after the load took 3.3s — and at the END of a whole suite, on a heap
    // already carrying every job before it, the same stalls outlast undici's
    // ten-second connect timeout: `fetch failed` on the read-back, 41s after
    // the last add.
    //
    // A caller that arrives while a flush is running needs a flush that starts
    // AFTER it, and one such flush serves every caller that arrived before it
    // starts — it takes the whole journal at that moment. So there is one
    // queued flush, created by the first caller to need it and returned to the
    // rest.
    // -----------------------------------------------------------------------
    if (!flushQueued) {
      const queued = flushing.then(function () {
        if (flushQueued === queued) {
          flushQueued = null;
        }
        return flush();
      });
      flushQueued = queued;
    }
    log.debug('Leaving flush(). One is already running; waiting for it.');
    return flushQueued;
  }
  if (!directoryDirty && !realmsDirty && !configDirty && !minted.dirty()) {
    // Nothing in flight and nothing dirty: every generation has committed, or
    // its failure put a dirty bit back.
    dirCommittedAt = dirGeneration;
    settleDirWaiters(null);
    log.debug('Leaving flush(). Nothing is dirty.');
    return Promise.resolve({ written: false });
  }

  const wantDirectory = directoryDirty;
  const wantRealms = realmsDirty;
  const wantConfig = configDirty;
  const takenAt = dirGeneration;
  // Cleared BEFORE the write rather than after it, so that a change made while
  // the write is in flight sets the bit again and gets its own flush. Clearing
  // afterwards would drop it.
  directoryDirty = false;
  realmsDirty = false;
  configDirty = false;

  // THE JOURNAL, TAKEN AND CLEARED BEFORE THE WRITE for the same reason the
  // dirty bits above are: a change made while this flush is in flight has to
  // start a new journal and get its own flush, not be swallowed by this one.
  const wanted = (wantDirectory && !dirtyEverything && dirtyDns.size)
    ? dirtyDns : null;
  if (wantDirectory) {
    dirtyDns = new Set();
    dirtyEverything = false;
  }
  // THE SNAPSHOT IS ONLY BUILT WHEN THERE IS NOTHING BETTER, and `wanted` is
  // that better thing: a journal naming exactly the keys that moved. Walking
  // every entry in every realm to find them is what made a create cost more
  // the more entries there already were — see entryAt() above. A full walk is
  // still right for a writer that did not say where (`dirtyEverything`), for
  // the first flush, and for a restore.
  let live = (wantDirectory && !wanted) ? liveDirectory() : null;
  // THE REMOVALS MADE HERE, taken now and forgotten only once written — see
  // `removedHere` above.
  const removals = Array.from(removedHere);
  const changes = wantDirectory ? diff(live, wanted, removals) : null;
  // THE REGISTRY AND THE SETTINGS AS DELTAS, computed now for `changes`'
  // reason: what is sent is what the shadows are advanced by.
  const realmChanges = wantRealms ? realmsDelta(removals) : null;
  const configChanges = wantConfig ? appconfigDelta() : null;

  flushing = Promise.resolve().then(function () {
    if (!changes) {
      return null;
    }
    if (!changes.upserts.length && !changes.deletes.length &&
        !changes.removedRealms.length) {
      return null;
    }
    // ---------------------------------------------------------------------
    // A SNAPSHOT DRIVER STILL GETS ITS SNAPSHOT (2026-09-12).
    //
    // The journalled flush above skips `liveDirectory()` and hands the driver
    // `all: null`, which is right for `postgres` — it writes the rows that
    // moved and nothing else. The `ldif` driver writes a WHOLE FILE per
    // touched realm and reads `change.all.get(realmId)` to do it, so from the
    // day the journal arrived every ldif flush that named its DNs failed with
    // "Cannot read properties of null (reading 'get')" — logged, retried on
    // the next change, and failing again, so the file on disk stopped moving
    // while the service answered correctly out of memory. Nothing showed it:
    // `tests/appconfig_persistence.js` fills the directory slot with a stub
    // that never names a DN, so every flush it drove took the full-walk path.
    // `tests/truststore_persistence.js` found it, writing a real entry through
    // the real directory and reading it back from a second process.
    //
    // Only the TOUCHED realms are walked, which is what that driver writes:
    // the journal's saving is kept for every realm nothing happened in.
    // ---------------------------------------------------------------------
    if (!live && driver.name === 'ldif') {
      live = new Map();
      changes.touched.forEach(function (realmId) {
        const rows = new Map();
        directory.realmEntries(realmId).forEach(function (row) {
          rows.set(row.key, row.entry);
        });
        live.set(realmId, rows);
      });
    }
    return driver.saveDirectory({
      upserts: changes.upserts,
      deletes: changes.deletes,
      touched: changes.touched,
      removedRealms: changes.removedRealms,
      all: live
    }).then(function (result) {
      advanceShadow(changes, changes.removedRealms);
      applyDirectoryOutcomes(changes, result && result.outcomes);
    });
  }).then(function () {
    if (!wantRealms) {
      return null;
    }
    // The whole list AND the delta: a snapshot driver writes the first, a
    // database the second. See `realmShadow` above.
    return driver.saveRealms(realmRows(), realmChanges).then(function () {
      advanceRealmShadow(realmChanges);
    });
  }).then(function () {
    if (!wantConfig) {
      return null;
    }
    return driver.saveOverrides(configChanges.live, configChanges)
      .then(function () {
        advanceAppconfigShadow(configChanges);
      });
  }).then(function () {
    // THE DIRECTORY, THE REALMS AND THE SETTINGS HAVE COMMITTED; the minted
    // write below is a separate transaction with generations of its own.
    dirCommittedAt = Math.max(dirCommittedAt, takenAt);
    settleDirWaiters(null);
    removals.forEach(function (id) {
      if (!realms.get(id)) {
        removedHere.delete(id);
      }
    });
    // ---------------------------------------------------------------------
    // THE MINTED ROWS RIDE THE SAME SCHEDULE AND NOT THE SAME TRANSACTION.
    //
    // The same schedule because there is no reason for two timers: a request
    // that changed a directory entry and minted a token should cost one wake
    // rather than two, and `schedule()`'s delay is already right for both (0
    // for a database).
    //
    // NOT the same transaction, and that is the part worth arguing. The
    // directory write is all-or-nothing over a diff computed against a
    // shadow; a minted write is a batch of independent rows read from live
    // stores. Joining them would mean a failed session write rolling back a
    // directory change that succeeded — and it would put the audit log,
    // which is written on every request, inside the transaction that holds
    // the directory. They fail independently, they are reported separately,
    // and neither can lose the other's work.
    // ---------------------------------------------------------------------
    if (!minted.dirty()) {
      return null;
    }
    return minted.flush();
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
    settleDirWaiters(err.message);
    log.error(errorCodes.tag('STS-STORE-0002') +
              'persistence: could not write to the ' + activeMode +
              ' store: ' + err.message + '. The service is unaffected and is ' +
              'still answering from memory; the next change will try again.');
    log.debug('Leaving flush(). It failed.');
    return { written: false, error: err.message };
  }).then(function (result) {
    flushing = null;
    return result;
  });

  flushingTakenAt = takenAt;
  log.debug("Leaving flush().");
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
// ===========================================================================
// THE CONNECTION STRING, WITH THE PASSWORD PUT BACK INTO IT (2026-09-12).
//
// `persistence.databaseUrl` carries a password in plain text, which is right
// for a throwaway database of mock identities and is not a deployment. When
// `persistence.databasePasswordProvider` names a secret store, the password is
// read from there — the SAME five providers and the same mechanism the
// key-encryption key uses, by default out of the SAME file or secret — and
// injected here.
//
// **IT IS INJECTED INTO THE STRING RATHER THAN PASSED BESIDE IT, AND THAT IS
// `pg`'s DOING RATHER THAN A PREFERENCE.** `ConnectionParameters` does
// `Object.assign({}, config, parse(config.connectionString))`, so everything
// parsed out of the string WINS over an explicit field — and `parse()` returns
// `password: ''` as an own property even for a string that carries none, so a
// `password` passed beside a `connectionString` is silently overwritten with
// the empty one. There is no arrangement of those two options that works.
//
// **`encodeURIComponent` AND NOT THE RAW VALUE**, which is the part that looks
// like fussiness and is not. `URL.password = value` percent-encodes the
// userinfo set and leaves `%`, `&` and `+` alone, and `pg` then runs
// `decodeURIComponent()` over what it finds — so a password containing a `%`
// arrives mangled, or throws `URI malformed` inside the driver. Encoding first
// and letting the setter pass the escapes through round-trips every byte:
// `tests/database_password.js` asserts it through `pg`'s own parser for a
// password made of every character that has ever caused this.
//
// **A PASSWORD ALREADY IN THE STRING IS REPLACED**, and the log says so
// without saying what with. Two passwords for one connection is a question
// with no good answer, and the configured provider is the one somebody chose
// deliberately — a leftover in the URL is what they are moving away from.
//
// A string that is not a URL (libpq's keyword/value form, which `pg` also
// accepts) cannot be edited safely, so it is REFUSED rather than dialled
// without the password somebody configured — the same direction every other
// refusal in this file takes.
// ===========================================================================
function resolveDatabaseUrl() {
  log.debug('Entering resolveDatabaseUrl().');
  const raw = databaseUrl();
  if (!secrets.configuredFor(secrets.DATABASE_PASSWORD)) {
    log.debug('Leaving resolveDatabaseUrl(). No provider is configured.');
    return Promise.resolve(raw);
  }
  log.debug("Leaving resolveDatabaseUrl().");
  return secrets.readDatabasePassword().then(function (password) {
    if (!password) {
      log.debug('Leaving resolveDatabaseUrl(). Nothing was read.');
      return raw;
    }
    let parsed = null;
    try {
      parsed = new URL(raw);
    } catch (e) {
      log.debug("Caught in a callback in resolveDatabaseUrl(): " +
                ((e && e.message) || e));
      throw new Error(errorCodes.tag('STS-STORE-0005') +
                      'persistence.databasePasswordProvider is set, so the ' +
                      'password has to be put into persistence.databaseUrl — ' +
                      'and that value is not a URL this service can edit (it ' +
                      'looks like libpq\'s keyword/value form). Write it as ' +
                      'postgres://user@host:5432/database and leave the ' +
                      'password out; the store is what supplies it.');
    }
    const had = !!parsed.password;
    // See the header: encode FIRST, because the setter does not encode the
    // three characters `pg`'s own decode will then choke on.
    parsed.password = encodeURIComponent(password);
    log.info('persistence: the database password was read from ' +
             secrets.describeDatabasePassword().label + ' and put into the ' +
             'connection string' +
             (had ? ', replacing the one persistence.databaseUrl carried.'
                  : '. The connection string carries none, which is the ' +
                    'arrangement to want.'));
    log.debug('Leaving resolveDatabaseUrl(). Injected.');
    return parsed.toString();
  });
}

function start() {
  log.debug('Entering start().');
  const chosen = mode();
  if (MODES.indexOf(chosen) < 0) {
    // Unreachable through config.value(), whose enum type refuses anything
    // else. Checked anyway because the two lists — MODES here and enumValues
    // in config.js — are two copies of one fact, and this is the line that
    // notices they have drifted.
    log.error(errorCodes.tag('STS-STORE-0003') +
              'persistence: "' + chosen + '" is not a mode this module knows ' +
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
    activeMode = 'memory';
    lastError = 'no directory is installed';
    log.debug('Leaving start(). No directory.');
    return Promise.reject(new Error(errorCodes.tag('STS-STORE-0004') +
      'persistence.mode is "' + chosen + '" and no directory is installed: ' +
      'ldap/ldap_server.js has not been required, so there is nothing to ' +
      'persist. This is a module-assembly problem rather than a store ' +
      'problem — server.js requires that module long before this runs — and ' +
      'it is fatal for the same reason an unreachable store is: a process ' +
      'configured to persist and persisting nothing is the state this ' +
      'refusal exists to prevent.'));
  }

  log.debug("Leaving start().");
  // -------------------------------------------------------------------------
  // THE PASSWORD COMES BEFORE THE POOL (2026-09-12), AND THAT IS WHY THIS
  // FUNCTION SPLITS HERE.
  //
  // `persistence.databasePasswordProvider` can put the database password in
  // the same secret store as the key-encryption key, and reading one is a
  // network call to somebody else's service. The pool is built SYNCHRONOUSLY
  // out of a connection string, so the string has to be finished first —
  // which is the same ordering `keystore.start()` has with its own secret,
  // and the same reason: a `require` and a constructor cannot await.
  //
  // **THE SPLIT IS A FUNCTION AND NOT AN `await` IN THIS ONE** so that the
  // driver-load `try` below keeps answering with the driver's own message. A
  // rejection raised inside the chain would be caught at the foot of this
  // file and wrapped in *the store could not be read*, which for a missing
  // `pg` package is the sentence twice — the exact thing the comment on that
  // catch says not to do.
  //
  // Only postgres has a password to resolve; ldif has a directory.
  // -------------------------------------------------------------------------
  return chosen === 'postgres'
    ? resolveDatabaseUrl().then(function (url) {
      return openStore(chosen, url);
    })
    : openStore(chosen, '');
}

// The half of `start()` that runs once the connection string is final. Split
// out above; `resolvedUrl` is what postgres dials and is ignored by ldif.
function openStore(chosen, resolvedUrl) {
  log.debug('Entering openStore(). mode=' + chosen);
  try {
    driver = chosen === 'postgres'
      // `verifyTls` is READ HERE AND PASSED IN, rather than read in the
      // driver: that module takes its url and its logger as options and
      // reaches for nothing, which is what lets a test construct one against
      // any database without this file's settings existing at all.
      ? require('./persistence_postgres').create({
          url: resolvedUrl, log: log,
          verifyTls: !!config.value('persistence.databaseTlsRejectUnauthorized')
        })
      : require('./persistence_ldif').create({ dir: dataDir(), log: log });
  } catch (err) {
    // The postgres driver's `require('pg')` is the realistic way to get here —
    // an image built without the dependency. Named, because "cannot find
    // module pg" arriving from inside a mock identity service is a sentence
    // nobody expects.
    driver = null;
    activeMode = 'memory';
    lastError = err.message;
    log.debug('Leaving openStore(). The driver would not load.');
    // The driver's own message already names the mode and says what to do —
    // it is written for exactly this moment — so it is passed through rather
    // than wrapped. A wrapper here produced "persistence.mode is postgres and
    // its driver could not be loaded: persistence.mode is postgres but the pg
    // package is not installed", which is the sentence twice.
    return Promise.reject(err);
  }

  activeMode = chosen;
  restoring = true;
  log.debug("Leaving openStore().");
  return driver.open().then(function () {
    // ---------------------------------------------------------------------
    // THE CLUSTER GATE, BEFORE ANYTHING IS ARMED OR RESTORED (2026-09-14, #46).
    //
    // A node joins here, and in active-passive mode a standby WAITS here for
    // the service lease — before the keystore has a store, before the minted
    // journal is armed, before a single row is read back. `restoring` is
    // already true, so every "something changed" door above is closed for the
    // whole wait and a standby writes nothing to a store another node owns.
    // A refusal (a mode the store cannot hold, a node configured differently,
    // active-active with capabilities missing) rejects into the fatal catch
    // below, which is where every other startup refusal of this module goes.
    // ---------------------------------------------------------------------
    return cluster.gate(driver);
  }).then(function () {
    // ---------------------------------------------------------------------
    // HAND THE KEYSTORE ITS STORE, THE MOMENT THERE IS ONE (2026-09-06).
    //
    // It is installed HERE rather than at require time because `driver` does
    // not exist until this function chooses one — and it is installed BEFORE
    // anything else is loaded so that `keystore.start()`, which `server.js`
    // calls next, has somewhere to read from.
    //
    // A driver from an older build without the three key functions is
    // reported rather than fatal: `keystore.setStore()` refuses the whole
    // object and says what is lost, and a development-mode service does not
    // care because it persists no keys.
    // ---------------------------------------------------------------------
    keystore.setStore({
      loadKeys: function () {
        log.debug("Entering loadKeys().");
        log.debug("Leaving loadKeys().");
        return driver.loadKeys();
      },
      saveKeys: function (realmId, ciphertext) {
        log.debug("Entering saveKeys().");
        log.debug("Leaving saveKeys().");
        return driver.saveKeys(realmId, ciphertext);
      },
      deleteKeys: function (realmId) {
        log.debug("Entering deleteKeys().");
        log.debug("Leaving deleteKeys().");
        return driver.deleteKeys(realmId);
      },
      // THE TWO THAT MAKE THE STORE THE ARBITER BETWEEN NODES (2026-09-14,
      // #46), offered only by a driver that has them — postgres. A store
      // without them is one process's (`ldif`), where the upsert above was
      // always right; `keystore.arbitrates()` reads their absence.
      loadKey: typeof driver.loadKey === 'function'
        ? function (realmId) {
          log.debug("Entering loadKey().");
          log.debug("Leaving loadKey().");
          return driver.loadKey(realmId);
        }
        : undefined,
      mergeKeys: typeof driver.mergeKeys === 'function'
        ? function (realmId, ciphertext, merge) {
          log.debug("Entering mergeKeys().");
          log.debug("Leaving mergeKeys().");
          return driver.mergeKeys(realmId, ciphertext, merge);
        }
        : undefined,
      // A CERTIFICATE AUTHORITY ANOTHER PROCESS WROTE HAS BEEN ADOPTED, AND
      // THE LISTENER THIS PROCESS HOLDS MAY NO LONGER CHAIN TO IT. The same
      // `reconcileTheListener()` the in-container PKI broadcast triggers —
      // the socket is not a row, so replicating the row does not move it
      // (`tls/CLAUDE.md`). Reached through `request_pool.js` lazily, which is
      // rule 1 rather than taste: this runs long after the protocol stack is
      // loaded, and a require at the top of this file would drag `/tls`'s
      // routes ahead of every protocol module. A request worker holds no
      // listener and does nothing.
      hierarchyAdopted: function (scopeId) {
        log.debug("Entering hierarchyAdopted().");
        if (process.env.STS_REQUEST_WORKER) {
          log.debug("Leaving hierarchyAdopted(). A worker holds no listener.");
          return;
        }
        try {
          require('../common/request_pool').hierarchyArrived(scopeId);
        } catch (e) {
          log.warn(errorCodes.tag('STS-STORE-0051') + 'persistence: the "' +
                   scopeId + '" certificate authority another node wrote ' +
                   'was adopted and the listener could not be reconciled ' +
                   'with it: ' + ((e && e.message) || e));
        }
        log.debug("Leaving hierarchyAdopted().");
      }
    });
    // ---------------------------------------------------------------------
    // AND THE MINTED STORE ITS DRIVER, AT THE SAME MOMENT AND FOR THE SAME
    // REASON (2026-09-06). Installing it is also what ARMS every declared
    // store: `realms.setPersistObserver()` is filled from in there, so from
    // this line on a `sessions.set()` journals its key. Before it, and in
    // every mode and build that does not reach this line, the observer is
    // null and every store behaves exactly as it always has.
    //
    // It is installed even when the mode makes it inert, because the module
    // has to be able to SAY why — `/admin/persistence` reports "the ldif
    // store cannot hold minted state" rather than reporting nothing, and a
    // driver that was never handed over could not tell that from "no store
    // is open".
    // ---------------------------------------------------------------------
    minted.setDriver(driver, activeMode);
    // And the schedule: a minted write alone is a reason to flush. See
    // mintedChanged().
    minted.setScheduler(mintedChanged);
    // -------------------------------------------------------------------
    // AND THE USED-ASSERTION HISTORY ITS STORE, BEFORE ANYTHING IS SERVED.
    // A file store is READ here: a token request answered from an empty copy
    // of a history that exists on disk would accept every assertion spent
    // before the restart, which is the replay this history exists to close.
    // Unlike the minted journal it is NOT gated by the mode — the keys that
    // verify an assertion are the client's, on its directory entry, and they
    // persist in every store.
    // -------------------------------------------------------------------
    return usedAssertions.setStore(driver, activeMode);
  }).then(function () {
    return persistsAppconfig() ? driver.loadOverrides() : null;
  }).then(function (saved) {
    // WHAT THE SETTINGS TABLE HOLDS, which is what a flush diffs against. The
    // whole table, a refused key included, so a reset-all in one process
    // still clears every stored setting exactly as the wholesale write did.
    appconfigShadow = Object.assign({}, saved || {});
    if (saved && Object.keys(saved).length) {
      const applied = config.applyPersistedOverrides(saved);
      restoredCounts.overrides = applied.length;
      log.info('persistence: restored ' + applied.length +
               ' runtime appconfig override(s) from the ' + activeMode +
               ' store: ' + applied.join(', ') + '.');
    }
    return persistsRealms() ? driver.loadRealms() : null;
  }).then(function (rows) {
    realmShadow.clear();
    if (rows && rows.length) {
      restoredCounts.realms = restoreRealms(rows);
      // THE REALMS THE STORE HOLDS AND THIS PROCESS RESTORED. A stored row
      // that could not be restored (STS-STORE-0007) is left out, so it is
      // neither written over nor deleted by a process that cannot read it;
      // the wholesale write used to delete it at the first flush.
      rows.forEach(function (row) {
        if (realms.get(row.id)) {
          realmShadow.set(row.id, shadowRowOf(row));
        }
      });
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
             (minted.enabled()
               ? 'What this process MINTS is restored separately, once the ' +
                 'keystore is open — see the line that follows this one.'
               : 'What is NOT restored: sessions, tokens, codes, artifacts, ' +
                 'tickets and the signing key, all of which are minted ' +
                 'rather than typed. That is unconditional in DEVELOPMENT ' +
                 'mode, where the signing key is regenerated on every start ' +
                 'and a restored token would verify against nothing; product ' +
                 'mode on a postgres store restores all of it.'));
    // A first run has an empty store and a seeded directory, so everything is
    // new and has to be written. A restored run's diff is empty and this
    // costs one no-op flush.
    directoryDirty = true;
    dirGeneration += 1;
    realmsDirty = persistsRealms();
    configDirty = false;
    schedule();
    log.debug('Leaving openStore(). Restored.');
    return { mode: activeMode, restored: restoredCounts };
  }).catch(function (err) {
    restoring = false;
    activeMode = 'memory';
    lastError = err.message;
    // A CLUSTER REFUSAL IS NOT A STORE THAT COULD NOT BE READ. The store was
    // opened and read perfectly well; what refused was the membership, and
    // wrapping its sentence in "the store could not be read" would send an
    // operator to look at the database. Passed through with its own code.
    if (/STS-CLUSTER-\d{4}/.test(String(err && err.message))) {
      log.debug('Leaving openStore(). The cluster gate refused.');
      throw err;
    }
    // ---------------------------------------------------------------------
    // FATAL SINCE 2026-08-28, AND THIS REVERSES WHAT THIS BLOCK USED TO DO.
    //
    // It caught, logged, fell back to memory and RESOLVED, on the argument
    // that a database outage must not take down sixteen protocol families and
    // that the whole point of this service is that a client has something to
    // talk to. That argument is still true of a store that breaks WHILE
    // RUNNING — see flush(), which still records a failure and carries on —
    // and it is the wrong answer at STARTUP, for a reason the old behaviour
    // made worse rather than better:
    //
    //   **A PROCESS THAT WAS TOLD TO PERSIST AND IS NOT PERSISTING LOOKS
    //   EXACTLY LIKE ONE THAT IS.** Every endpoint answers. The console draws.
    //   A person creates realms, registers applications and configures a
    //   federation partner, and all of it is thrown away on the next restart —
    //   which is the restart they will do precisely because they expected the
    //   work to survive it. The fallback was reported on /admin/persistence
    //   and in the log, and neither is where somebody is looking while the
    //   service appears to be working.
    //
    // So a store that was CONFIGURED and cannot be opened or read now stops
    // the process. `persistence.mode=memory` — the default — reaches none of
    // this and is unaffected, so a service nobody asked to persist behaves
    // exactly as it always has.
    //
    // The message is built rather than thrown bare because it is the last
    // thing the operator will see, and "connect ECONNREFUSED" on its own does
    // not say which of the six settings to look at.
    // ---------------------------------------------------------------------
    const explanation = errorCodes.tag('STS-STORE-0006') +
              'persistence.mode is "' + chosen + '" and the store ' +
              'could not be read: ' + err.message + '. Nothing in the store ' +
              'was changed.' +
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
                : '');
    log.debug('Leaving openStore(). The store could not be read.');
    throw new Error(explanation);
  });
}

// The realm rows, put back through the door an operator uses. See start()'s
// step 2 — this is the reason `realms.create()` is called rather than the
// registry being written into directly.
// `replicated` SEPARATES TWO CALLERS THAT WANT OPPOSITE THINGS FROM AN EXISTING
// REALM (2026-09-07). At STARTUP a realm already present was defined by an
// appconfig file or an environment variable, and something a person wrote down
// for this run beats a row this module wrote during the last one — so it is
// left alone. Applying a change ANOTHER PROCESS just made is the reverse: the
// realm exists here precisely because it replicated, and skipping it threw away
// the only thing that changed.
//
// **WHAT THAT COST IS EVERY REALM-SCOPED SETTING.** A realm's runtime overrides
// live on its row, so `POST /realm/<id>/admin-api/config/set` on one worker was
// written, replicated, and then discarded by every other worker because the
// realm was already there. A dispatched run measured it as
// `xacml.enforceAccess` turned off and still refusing, `oauth2.consentRequired`
// set and the consent screen still drawn — settings that reported success and
// did nothing anywhere but the process that took the call.
function restoreRealms(rows, replicated) {
  log.debug('Entering restoreRealms(). ' + rows.length + ' row(s).');
  let made = 0;
  rows.forEach(function (row) {
    const existing = realms.get(row.id);
    if (existing && !replicated) {
      // Already defined, which means an appconfig file or an environment
      // variable defined it before this ran. The stored row does not overwrite
      // it: something a person wrote down for THIS run beats something this
      // module wrote down during the last one.
      log.warn('persistence: the realm "' + row.id + '" is already defined; ' +
               'the stored row was left alone.');
      return;
    }
    if (existing) {
      // The realm is here because it replicated. Take what another process
      // changed — its overrides above all, which is what a realm-scoped
      // setting IS.
      // `replicated`, so the realm registry does not re-judge a change the
      // process that made it already judged (realms.js,
      // kerberosOverrideProblem()).
      realms.update(row.id, { name: row.name, description: row.description,
                              overrides: row.overrides || {},
                              replicated: true });
      return;
    }
    const result = realms.create({
      id: row.id,
      name: row.name,
      description: row.description,
      overrides: row.overrides || {},
      // Told so, for the watchers that must not treat a realm another process
      // made — or the last run made — as one made here. `pki.js` is why.
      restored: true
    });
    if (!result.ok) {
      // Reported and skipped rather than fatal: one unrestorable realm must
      // not cost the others. The realistic cause is an id that was valid when
      // it was written and is not now — a reserved word added since.
      log.error(errorCodes.tag('STS-STORE-0007') +
                'persistence: the stored realm "' + row.id + '" could not be ' +
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

// One stored realm row as the realm shadow holds it.
function shadowRowOf(row) {
  log.debug("Entering shadowRowOf().");
  log.debug("Leaving shadowRowOf().");
  return JSON.stringify({ name: row.name, description: row.description,
                          overrides: row.overrides || {} });
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
      log.warn(errorCodes.tag('STS-STORE-0009') +
               'persistence: the store holds ' + list.length + ' entry/ies ' +
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
    rows.forEach(function (entry, key) {
      next.set(key, JSON.stringify(entry));
    });
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
  log.debug("Leaving stop().");
  return replication.stop().then(function () {
    return flush();
  }).then(function () {
    // AFTER the flush above rather than inside it, because that one returns
    // early when nothing of ITS three kinds is dirty — and a shutdown whose
    // only unwritten work is a session must still write the session.
    return minted.stop();
  }).then(function () {
    // Writes whatever confirmation a file store still owes, and puts the
    // history back in this process's memory before the driver it was using
    // is closed underneath it.
    return usedAssertions.clearStore();
  }).then(function () {
    // LEAVING THE CLUSTER LAST, after every write this process owed has been
    // made under its membership — and before the pool closes, since leaving
    // is a statement. A standby that never held the lease leaves the same way.
    return cluster.leave();
  }).then(function () {
    stopped = true;
    return driver.close();
  }).then(function () {
    log.info('persistence: the ' + activeMode +
             ' store was flushed and closed.');
    log.debug('Leaving stop().');
  }).catch(function (err) {
    stopped = true;
    log.error(errorCodes.tag('STS-STORE-0008') +
              'persistence: the final flush or close failed: ' + err.message +
              '. Anything changed since the last successful write is lost.');
    log.debug('Leaving stop(). It failed.');
  });
}

// ---------------------------------------------------------------------------
// THE APPLIERS: HOW ANOTHER PROCESS'S WRITE BECOMES THIS PROCESS'S MEMORY.
//
// One per kind of change. Each is handed a POINTER — a kind, a realm and a
// key — reads the row it names out of the store, and puts it where a local
// write would have put it. Nothing is sent in the notification, which is what
// lets the notification be lossy.
//
// **EVERY ONE OF THEM SUPPRESSES THE JOURNAL AROUND ITS WRITE**, and that is
// not tidiness: without it, applying another process's write would make this
// process report the write as its own and flush it straight back, which wakes
// the other process, which applies it and writes it back. Two processes would
// exchange one row for ever. `restoring` is the same flag the startup restore
// uses and it is set for the same reason.
// ---------------------------------------------------------------------------
function applyDirectoryChange(change) {
  log.debug("Entering applyDirectoryChange().");
  if (!directory || typeof directory.applyEntry !== 'function' ||
      typeof driver.readEntry !== 'function') {
    log.debug("Leaving applyDirectoryChange().");
    return Promise.resolve(false);
  }
  log.debug("Leaving applyDirectoryChange().");
  // The stored key is the NORMALISED DN, which is what `sts_ldap_entries` is
  // keyed by and what `realmEntries()` hands back — so the change row carries
  // the DN as written and this has to normalise nothing itself. Normalising a
  // DN is ldap_server.js's job and a second implementation here would be one
  // whose disagreement is invisible.
  return driver.readEntry(change.realm, change.key).then(function (row) {
    const rows = shadow.get(change.realm) || new Map();
    // -----------------------------------------------------------------------
    // A CHANGE THIS PROCESS HAS NOT WRITTEN YET IS NOT THROWN AWAY
    // (2026-09-14, #46 section 3).
    //
    // This put the stored row over the live entry unconditionally and then
    // set the shadow to it — so a member added here a moment earlier, not yet
    // flushed, was gone from memory AND from the diff (live now equalled the
    // shadow), and was never written anywhere. The same three-way merge the
    // driver makes is made here: base is the shadow, mine is live, theirs is
    // the row. What it keeps of mine is journalled again, so the next flush
    // writes it against the row it has now seen.
    // -----------------------------------------------------------------------
    const key = row ? row.key : change.key;
    const live = entryAt(change.realm, key);
    const base = rows.has(key) ? rows.get(key) : null;
    const pending = live ? JSON.stringify(live) !== base : base !== null;
    let keep = null;
    if (pending) {
      const verdict = directoryMerge.mergeEntry(
        base ? JSON.parse(base) : null, live, row ? row.entry : null);
      keep = verdict.outcome === 'mine' || verdict.outcome === 'merged'
        ? verdict.entry : null;
      if (!live) {
        // A delete made here meets a change made there: the delete wins, and
        // is written by the next flush against the row it has now seen.
        keep = 'deleted';
      }
    }
    const was = restoring;
    restoring = true;
    try {
      if (keep === 'deleted') {
        // Nothing to apply: the entry stays gone here.
        log.debug('applyDirectoryChange(): a delete made here wins over ' +
                  'another node\'s change to ' + key + '.');
      } else if (keep) {
        directory.applyEntry(change.realm, key, keep);
      } else if (!row) {
        directory.removeEntry(change.realm, change.key);
      } else {
        directory.applyEntry(change.realm, row.key, row.entry);
      }
    } finally {
      restoring = was;
    }
    // AND THE SHADOW IS ADVANCED FOR THAT ROW, which is the subtle half. The
    // shadow is what the DIFF compares against; leaving it stale would make
    // the next local flush see another process's entry as one this process
    // had changed, and write it back as its own — harmlessly, but as an
    // endless stream of redundant UPSERTs between two idle processes.
    //
    // It is the STORE's row now and not the live entry, because the two
    // differ exactly when a pending change was kept above — and the shadow
    // must say what the store holds for that change to be written.
    if (!row) {
      rows.delete(change.key);
    } else if (keep) {
      rows.set(row.key, directoryMerge.canonicalJson(row.entry));
    } else {
      const stored = entryAt(change.realm, row.key);
      if (stored) {
        rows.set(row.key, JSON.stringify(stored));
      }
    }
    shadow.set(change.realm, rows);
    if (keep) {
      directoryDirty = true;
      dirGeneration += 1;
      dirtyDns.add(key);
      schedule();
    }
    return true;
  });
}

function applyRealmsChange() {
  log.debug("Entering applyRealmsChange().");
  if (!persistsRealms()) {
    log.debug("Leaving applyRealmsChange().");
    return Promise.resolve(false);
  }
  log.debug("Leaving applyRealmsChange().");
  return driver.loadRealms().then(function (rows) {
    const stored = rows || [];
    // -----------------------------------------------------------------------
    // WHAT THIS PROCESS HAS CHANGED AND NOT WRITTEN YET RIDES ON TOP
    // (2026-09-14, #46). `restoreRealms(…, true)` replaces a realm's
    // overrides with the stored ones, which threw away a setting made here a
    // moment earlier and not yet flushed — and then the diff saw nothing to
    // write. So each stored row is merged with this process's delta against
    // the shadow (name and description if changed here, overrides set and
    // cleared here), and the shadow becomes the stored row.
    // -----------------------------------------------------------------------
    const pending = realmsDelta(Array.from(removedHere));
    const pendingById = new Map();
    pending.upserts.forEach(function (one) {
      pendingById.set(one.row.id, one);
    });
    const merged = stored.filter(function (row) {
      return !removedHere.has(row.id);
    }).map(function (row) {
      const mine = pendingById.get(row.id);
      if (!mine || !realmShadow.has(row.id)) {
        return row;
      }
      const overrides = Object.assign({}, row.overrides || {});
      mine.cleared.forEach(function (key) {
        delete overrides[key];
      });
      Object.assign(overrides, mine.set);
      return Object.assign({}, row, {
        name: mine.name ? mine.row.name : row.name,
        description: mine.description ? mine.row.description
                                      : row.description,
        overrides: overrides
      });
    });
    // -----------------------------------------------------------------------
    // AND A REALM ANOTHER NODE REMOVED IS REMOVED HERE. It never was: this
    // applier only created and updated, and the wholesale save then wrote the
    // removed realm straight back from this process's copy. A realm leaves
    // this process only when the shadow says the store HAD it and the store
    // no longer does — a realm created here and not yet written is in
    // neither, and is left alone.
    // -----------------------------------------------------------------------
    const storedIds = new Set(stored.map(function (row) { return row.id; }));
    const gone = Array.from(realmShadow.keys()).filter(function (id) {
      return !storedIds.has(id) && !!realms.get(id);
    });
    const was = restoring;
    restoring = true;
    try {
      // THROUGH `restoreRealms()`, the same function the startup restore uses,
      // so that every builder every module registered fires for a realm
      // another process created — including ldap_server.js's, which seeds the
      // subtree. A second way to make a realm is the one that is missing a
      // step, and this service already learnt that once.
      restoreRealms(merged, true);
      gone.forEach(function (id) {
        log.info('persistence: the "' + id + '" realm was removed by another ' +
                 'node; removing it here.');
        realms.remove(id);
        // Its directory is gone from the store with it, so its shadow goes
        // too — and without this the next full walk would find the realm's
        // rows remembered and the realm absent.
        shadow.delete(id);
      });
    } finally {
      restoring = was;
    }
    stored.forEach(function (row) {
      realmShadow.set(row.id, shadowRowOf(row));
    });
    gone.forEach(function (id) {
      realmShadow.delete(id);
    });
    if (pending.upserts.length) {
      realmsDirty = persistsRealms();
      dirGeneration += 1;
      schedule();
    }
    return true;
  });
}

function applyAppconfigChange() {
  log.debug("Entering applyAppconfigChange().");
  if (!persistsAppconfig()) {
    log.debug("Leaving applyAppconfigChange().");
    return Promise.resolve(false);
  }
  log.debug("Leaving applyAppconfigChange().");
  return driver.loadOverrides().then(function (saved) {
    // ----------------------------------------------------------------------
    // AN EMPTY TABLE IS A FACT HERE, NOT AN ABSENCE (2026-09-08).
    //
    // The driver answers `null` when `sts_appconfig` holds no rows, and this
    // used to return early on it. That is the right reading at STARTUP —
    // nothing was ever stored, so keep what the appconfig file said — and the
    // exact opposite reading of a REPLICATED change: a change row only exists
    // because another process wrote one, and "the table is now empty" is
    // precisely what `POST /admin-api/config/reset-all` means.
    //
    // So clearing the LAST override never propagated. Measured on three
    // request workers: set `oid4vci.batchSize` to 7, reset it, and the issuer
    // metadata answered 7, 4, 7, 4, 7, 7 depending on which worker replied —
    // only the one that HANDLED the reset had cleared it. `admin_api` reported
    // it as "this test has changed what every later job sees", which is
    // exactly what it had done.
    // ----------------------------------------------------------------------
    // WHAT THIS PROCESS HAS SET OR CLEARED AND NOT WRITTEN YET RIDES ON TOP
    // (2026-09-14, #46), for `applyRealmsChange()`'s reason: applying the
    // table whole erased a setting made here a moment earlier.
    const pending = appconfigDelta();
    const wanted = Object.assign({}, saved || {});
    pending.cleared.forEach(function (key) {
      delete wanted[key];
    });
    Object.assign(wanted, pending.set);
    const was = restoring;
    restoring = true;
    appconfigShadow = Object.assign({}, saved || {});
    try {
      // THE SAME `applyPersistedOverrides()` the startup restore calls, so a
      // setting changed in another process's console goes through the same
      // validation — including the refusal of a restart-only setting, which
      // matters more here than at startup: another process may be a different
      // build with a different idea of which settings are runtime.
      config.applyPersistedOverrides(wanted);
    } finally {
      restoring = was;
    }
    if (pending.cleared.length || Object.keys(pending.set).length) {
      configDirty = persistsAppconfig();
      dirGeneration += 1;
      schedule();
    }
    return true;
  });
}

function applyKeysChange(change) {
  log.debug("Entering applyKeysChange().");
  // -------------------------------------------------------------------------
  // **ADOPTED, SINCE 2026-09-14 (#46 section 1), WHERE THIS DID NOTHING.**
  //
  // It logged "THEY ARE NOT ADOPTED HERE: … taking new ones would strand
  // everything it has already signed. Restart this process to pick them up."
  // That was a sound argument for ONE container, where the request pool's key
  // channel had already made every process agree before anything signed, and
  // it was the worst defect in the issue for several: a realm created on node
  // A and first used on node B got two key sets and the later upsert won the
  // row; `keystore.rotate()` reached one node; and a rebuilt Root reached one
  // node while the others served the old leaf on 8443, 9443 and 636.
  //
  // What changed is that the STORE now arbitrates (`mergeKeys()`, first
  // writer wins for a key set, a merge for a certificate authority), so the
  // row another node wrote is by construction the one every node must use,
  // and "strand what this process signed" is the choice between stranding a
  // window and disagreeing for ever. `common/keystore.js`'s
  // `applyStoredChange()` carries the argument and reads the CURRENT row,
  // which is what makes a late or out-of-order change safe to apply.
  //
  // **A CERTIFICATE AUTHORITY THAT ARRIVED IS ALSO A SOCKET TO RECONCILE** —
  // `hierarchyAdopted` on the keystore's store hooks, below in `openStore()`,
  // which the keystore calls however the row arrived: from this applier, or
  // from its own write finding another node's row under the lock.
  // -------------------------------------------------------------------------
  if (typeof keystore.applyStoredChange !== 'function') {
    log.debug("Leaving applyKeysChange(). No applier.");
    return Promise.resolve(false);
  }
  log.debug("Leaving applyKeysChange().");
  return keystore.applyStoredChange(change.realm).then(function (answer) {
    return !!(answer && answer.adopted);
  });
}

// ---------------------------------------------------------------------------
// STARTING COORDINATION. `server.js` calls this LAST — after the directory,
// the realms, the settings, the keys and the minted rows are all restored —
// because the change log's high-water mark only means "I am up to date" if
// this process actually is.
// ---------------------------------------------------------------------------
function coordinate() {
  log.debug('Entering coordinate().');
  if (!enabled()) {
    log.debug('Leaving coordinate(). Nothing is being persisted.');
    return Promise.resolve({ coordinating: false });
  }
  log.debug("Leaving coordinate().");
  return replication.start(driver, {
    directory: applyDirectoryChange,
    realms: applyRealmsChange,
    appconfig: applyAppconfigChange,
    keys: applyKeysChange,
    // A FUNCTION WITH A `prepare` ON IT. The applier contract is a function —
    // `replication.js` checks `typeof applier === 'function'` — and `prepare`
    // is an optional property it looks for beside it, so this stays one
    // applier rather than becoming a second shape every kind has to adopt. It
    // is what turns a page of minted changes into ONE read; see
    // persistence_minted.js's prefetch().
    // BOTH KINDS THROUGH ONE APPLIER. `minted-own` differs only in whether a
    // reader waits for it (see the driver's latestBlockingChangeSeq); applying
    // it is identical, and a second applier would be a second place to keep
    // that in step.
    'minted-own': Object.assign(
      function (change) { return minted.applyChange(change); },
      { prepare: function (rows) {
        log.debug("Entering prepare().");
        log.debug("Leaving prepare().");
        return minted.prefetch(rows);
      },
        done: function () {
          log.debug("Entering done().");
          log.debug("Leaving done().");
          return minted.endPrefetch();
        } }),
    minted: Object.assign(
      function (change) { return minted.applyChange(change); },
      { prepare: function (rows) {
        log.debug("Entering prepare().");
        log.debug("Leaving prepare().");
        return minted.prefetch(rows);
      },
        done: function () {
          log.debug("Entering done().");
          log.debug("Leaving done().");
          return minted.endPrefetch();
        } })
  });
}

// ---------------------------------------------------------------------------
// WHAT THIS MODULE SAYS ABOUT ITSELF. One shape, read by GET
// /admin/ldap/service, by /admin/persistence and by GET /admin-api/persistence
// — for the reason config.js's describe() is one shape: a console and an API
// that compute the same answer twice are a console and an API that will
// disagree about it.
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
    coordinates: replication.status().coordinating,
    // ONE REPORT, from the module that does the work. The page and the API
    // both draw this, so they cannot disagree about what is being written
    // down — rule 7's shape applied to a report rather than to an action.
    minted: minted.status(),
    // The RFC 7523 / RFC 7522 used-assertion history, which is NOT minted
    // state: it persists in both modes wherever a driver can hold it, so the
    // page answering "what survives a restart" has to say so separately.
    usedAssertions: usedAssertions.summary(),
    // AND WHAT IT SHARES WITH OTHER PROCESSES. One report from the module that
    // does the work, for the same reason as the line above.
    replication: replication.status(),
    note: (replication.status().coordinating
            ? 'Processes against this store COORDINATE: every change is ' +
              'written to a monotonic log inside the transaction that made ' +
              'it, and each process applies what the others committed. The ' +
              'LISTEN/NOTIFY nudge only makes that prompt — the log is the ' +
              'contract, so a missed notification costs latency and never a ' +
              'change. What is NOT shared is sockets: the KDC, the LDAP ' +
              'listeners, the TLS ports and SPIFFE\'s four are per process, ' +
              'and the replay caches converge rather than synchronise. '
            : 'Persistence is not coordination in this configuration. Two ' +
              'processes pointed at one store each hold their own copy in ' +
              'memory and will not see each other\'s writes until they ' +
              'restart. Set persistence.coordinate on a postgres store to ' +
              'change that. ') +
          'What this service MINTS — sessions, tokens, codes, artifacts, ' +
          'Kerberos tickets, the counters and the audit log — is persisted ' +
          'in PRODUCT mode on a postgres store, encrypted under the same ' +
          'key-encryption key as the signing keys, and in no other ' +
          'configuration: development mode regenerates the signing key on ' +
          'every start, so a restored token would verify against nothing.'
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
  log.debug("Entering describeDefaultTarget().");
  const target = describeDatabase();
  if (!target || !target.host) {
    log.debug("Leaving describeDefaultTarget().");
    return 'the built-in connection string';
  }
  log.debug("Leaving describeDefaultTarget().");
  return target.host + ':' + target.port + '/' + target.database;
}

// The database, named without naming the credential. A URL is parsed rather
// than regexed so that a password containing an '@' cannot fool it into
// reporting half of itself.
function describeDatabase() {
  log.debug("Entering describeDatabase().");
  const raw = databaseUrl();
  if (!raw) {
    log.debug("Leaving describeDatabase().");
    return null;
  }
  try {
    const parsed = new URL(raw);
    // THE TLS STATE, out of the two places it actually lives. `sslmode` is
    // postgres's own spelling and rides in the connection string; whether the
    // certificate is BELIEVED is a setting, because `pg` takes that as a TLS
    // option and not as a URL parameter. Both are reported, because "encrypted"
    // and "authenticated" are two different answers and a page that gave one
    // number for them would be the misleading half of a true sentence.
    const sslmode = String(parsed.searchParams.get('sslmode') || '')
      .toLowerCase();
    const encrypted = ['require', 'verify-ca', 'verify-full', 'prefer']
      .indexOf(sslmode) >= 0;
    // WHERE THE PASSWORD COMES FROM (2026-09-12) — never what it is. A
    // deployment that moved the password into a secret store has no other way
    // to see that this process agreed: the connection string on the page
    // looks the same either way, because the page never printed the password
    // in the first place.
    const password = secrets.describeDatabasePassword();
    log.debug("Leaving describeDatabase().");
    return {
      host: parsed.hostname,
      port: parsed.port || '5432',
      database: String(parsed.pathname || '').replace(/^\//, ''),
      user: parsed.username || null,
      passwordFrom: password.configured
        ? (password.label +
           (password.where && password.where.from
             ? ' (' + password.where.from + ')' : '') +
           (password.shared ? ', shared with the key-encryption key' : ''))
        : 'the connection string',
      passwordProvider: password.provider,
      passwordSecret: password.configured ? password : undefined,
      sslmode: sslmode || 'not set',
      encrypted: encrypted,
      verifyCertificate:
        !!config.value('persistence.databaseTlsRejectUnauthorized'),
      tls: encrypted
        ? ('TLS, sslmode=' + sslmode + '; the server certificate is ' +
           (config.value('persistence.databaseTlsRejectUnauthorized')
             ? 'verified against this process\'s trust anchors.'
             : 'NOT verified (persistence.databaseTlsRejectUnauthorized is ' +
               'off), which is the honest setting for the self-signed pair ' +
               'the compose stack generates. The connection is encrypted ' +
               'either way.'))
        : ('NOT TLS — the connection string does not ask for it. The compose ' +
           'stack\'s database REFUSES a plaintext connection, because every ' +
           'host rule in its pg_hba.conf is hostssl, so this configuration ' +
           'will not connect there.')
    };
  } catch (err) {
    log.debug("Caught in describeDatabase(): " + ((err && err.message) || err));
    log.debug("Leaving describeDatabase().");
    // Not a URL this runtime can parse — a libpq keyword/value string, which
    // `pg` also accepts. There is nothing safe to show of it, because the
    // password is in there somewhere and we do not know where.
    return { host: null, port: null, database: null, user: null,
             sslmode: 'unknown', encrypted: false, verifyCertificate: false,
             tls: 'unknown — the connection string is not a URL, so the ' +
                  'sslmode cannot be read out of it.',
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
realms.onChange(function (id, what) {
  // A REMOVAL MADE HERE, remembered until it is written — the only kind of
  // realm this module will ever delete from the store (#46; see `removedHere`
  // above). Not while restoring: a removal applied from another node's write
  // is that node's to record, and it already has.
  if (what === 'remove' && enabled() && !restoring) {
    removedHere.add(String(id));
  } else if (what === 'create') {
    removedHere.delete(String(id));
  }
  realmsChanged();
  // ---------------------------------------------------------------------
  // AND THE DIRECTORY NEEDS A FULL WALK AFTER A REALM IS REMOVED (2026-09-08).
  //
  // `diff()` finds a removed realm's rows by comparing the shadow against a
  // SNAPSHOT of what is live — and since this same day it only builds that
  // snapshot when there is no journal to work from, because building one per
  // write is what made a create cost more the more entries there already were.
  // A removal writes no journal entry (there is nothing left to name), so
  // without this the deletes would simply never be emitted and the realm's
  // rows would outlive it in the store.
  //
  // Marked for ANY realm change rather than only a removal: `changed()` is the
  // one door every path goes through, the events are rare (a realm is created,
  // updated or removed by hand), and one full walk after one of them is a cost
  // nobody can measure. Getting this narrow would be optimising the rarest
  // event in the service at the risk of the only one that loses data.
  // ---------------------------------------------------------------------
  directoryChanged();
});

module.exports = {
  // FOR `tests/database_password.js` ONLY, and it is worth saying why a
  // private function is exported at all. The claim this feature makes is that
  // a password read from a secret store REACHES THE CONNECTION STRING — and
  // the only other way to see that is to dial a real database, which an
  // in-process test has none of. What the test asserts is the string this
  // returns, put through `pg`'s own parser: two implementations meeting, which
  // is the arrangement `tests/webauthn_cross_impl.js` describes.
  resolveDatabaseUrl: resolveDatabaseUrl,
  MODES: MODES,
  mode: mode,
  activeMode: function () {
    log.debug("Entering activeMode().");
    log.debug("Leaving activeMode().");
    return activeMode;
  },
  enabled: enabled,
  dataDir: dataDir,
  setDirectory: setDirectory,
  start: start,
  stop: stop,
  flush: flush,
  directoryChanged: directoryChanged,
  realmsChanged: realmsChanged,
  configChanged: configChanged,
  mintedChanged: mintedChanged,
  // The minted half, for `server.js`'s third startup step. It is re-exported
  // rather than required over there directly so that `server.js` has ONE
  // persistence module to talk to, which is what it has always had.
  restoreMinted: function () {
    log.debug("Entering restoreMinted().");
    log.debug("Leaving restoreMinted().");
    return minted.restore();
  },
  // THE MINTED FLUSH, for `common/request_worker.js`'s commit-before-answer.
  // The store's flush and this one are two schedulers, and a caller that
  // awaited only the first would leave everything this service MINTS exactly
  // as racy as it was — which is most of what a browser flow writes.
  flushMinted: function () {
    log.debug("Entering flushMinted().");
    log.debug("Leaving flushMinted().");
    // AND THE KEYSTORE'S QUEUED ROWS (2026-09-14, #46). A signing key set or
    // a certificate authority written by a request is a write another node
    // must see before the response reaches it — a SCEP RA certificate issued
    // by GetCACert on A and used by PKIOperation on B is exactly that — so
    // commit-before-answer waits for them too. `minted.flush()`'s answer is
    // the one returned; the keystore reports its own failures.
    return Promise.all([
      minted.flush(),
      typeof keystore.settleAll === 'function' ? keystore.settleAll() : null
    ]).then(function (both) {
      return both[0];
    });
  },
  // THE STORE `cluster/cluster_claims.js` AND `cluster/cluster_secrets.js`
  // WORK AGAINST (2026-09-14, #46): the open driver when it can hold an atomic
  // claim and a shared secret — postgres — and null otherwise, which those
  // modules answer from this process's memory. Handed over rather than
  // reached for, so that neither module needs to know which drivers exist.
  clusterStore: function () {
    log.debug("Entering clusterStore().");
    if (!enabled() || !driver || typeof driver.claimOnce !== 'function') {
      log.debug("Leaving clusterStore(). None.");
      return null;
    }
    log.debug("Leaving clusterStore().");
    return driver;
  },
  // ---------------------------------------------------------------------
  // WHAT THIS PROCESS HAS WRITTEN, AS A POSITION, AND A WAIT FOR ITS COMMIT
  // (2026-09-14, #46), for cluster/cluster_barrier.js's rule 2. A request
  // reads the position when it arrives and again when it answers; if it moved,
  // `commitThrough()` resolves once everything up to the second reading is in
  // the store — the one flush in flight that covers it where there is one, a
  // new one otherwise — with an array of the answers, any of which may carry
  // `error`. The keystore's queued rows have no generation, so a request that
  // answers while any are queued waits for all of them, as it always did.
  // ---------------------------------------------------------------------
  writeGeneration: function () {
    log.debug("Entering writeGeneration().");
    log.debug("Leaving writeGeneration().");
    // `observed` is the part of `minted` that was a tally rather than a write
    // (`persistence_minted.js`, `observedGeneration`); the barrier subtracts
    // it.
    return { directory: dirGeneration, minted: minted.generation(),
             observed: typeof minted.observedGeneration === 'function'
               ? minted.observedGeneration() : 0 };
  },
  keysPending: function () {
    log.debug("Entering keysPending().");
    log.debug("Leaving keysPending().");
    return enabled() && typeof keystore.pendingWrites === 'function' &&
      !!keystore.pendingWrites();
  },
  commitThrough: function (target) {
    log.debug("Entering commitThrough().");
    const wanted = target || { directory: dirGeneration,
                               minted: minted.generation() };
    const waits = [
      directoryThrough(Number(wanted.directory) || 0),
      minted.flushThrough(Number(wanted.minted) || 0)
    ];
    if (typeof keystore.pendingWrites === 'function' &&
        keystore.pendingWrites() && typeof keystore.settleAll === 'function') {
      waits.push(Promise.resolve(keystore.settleAll()).then(function () {
        return null;
      }));
    }
    log.debug("Leaving commitThrough().");
    return Promise.all(waits);
  },
  // Whether anything this process has changed is not yet committed, for the
  // cluster barrier's commit-before-respond. See cluster/cluster_barrier.js.
  pendingWrites: function () {
    log.debug("Entering pendingWrites().");
    log.debug("Leaving pendingWrites().");
    return enabled() && !restoring &&
      (directoryDirty || realmsDirty || configDirty || !!timer ||
       !!flushing || minted.dirty() ||
       (typeof keystore.pendingWrites === 'function' &&
        keystore.pendingWrites()));
  },
  // THE SEQUENCE THIS PROCESS'S LAST COMMIT REACHED, for
  // `common/request_worker.js`'s commit announcement. It is the STORE's answer
  // and not this process's `applied`: what a reader has to wait for is the
  // sequence the write actually landed at, which only the store knows.
  // Whether this process has written any change rows — read either side of a
  // flush to tell "I wrote" from "I had nothing to write", with no query.
  // ---------------------------------------------------------------------
  // THE DATABASE METRICS, for `/admin/database` (2026-09-11).
  //
  // **A ROUTER AND NOT A COLLECTOR.** Every statement, every catch and every
  // number is `persistence_postgres.js`'s, because that module owns the pool
  // and the console must not: a connection string is a credential and `pg` is
  // a dependency only one mode needs. What this adds is the answer for the
  // modes that have no database — which is most of them, and which has to be
  // a SENTENCE rather than an empty object.
  //
  // **THE THREE "NO" ANSWERS ARE KEPT APART ON PURPOSE.** A page that showed
  // one blank table for all of them would be useless in exactly the moment
  // somebody opens it: *this service is not configured for a database*,
  // *it is, and the driver never opened one* and *it opened one and this
  // build of the driver has no metrics* are three different things to do
  // something about, and only the second is a fault.
  // ---------------------------------------------------------------------
  databaseMetrics: function (options) {
    log.debug('Entering databaseMetrics().');
    const configured = mode();
    if (configured !== 'postgres') {
      log.debug('Leaving databaseMetrics(). Not a database mode.');
      return Promise.resolve({
        ok: false, available: false, mode: configured,
        why: 'persistence.mode is "' + configured + '", so this service has ' +
             'no database to report on. `memory` writes nothing at all and ' +
             '`ldif` writes RFC 2849 files — neither has a connection, a ' +
             'pool or a catalog. Set persistence.mode to `postgres` (it is ' +
             'restart-only: the store is opened before the listener binds).'
      });
    }
    if (!driver || !enabled()) {
      log.debug('Leaving databaseMetrics(). No open driver.');
      return Promise.resolve({
        ok: false, available: false, mode: configured,
        why: 'persistence.mode is "postgres" and this process has NO OPEN ' +
             'STORE. That is a fault rather than a configuration: the store ' +
             'is opened from persistence.start() before the listener binds, ' +
             'and a failure there is fatal — so a running service in this ' +
             'state has had its store stopped underneath it. The startup log ' +
             'names what happened.'
      });
    }
    if (typeof driver.metrics !== 'function') {
      log.debug('Leaving databaseMetrics(). The driver has none.');
      return Promise.resolve({
        ok: false, available: false, mode: configured,
        why: 'the open driver reports no metrics function, which means a ' +
             'build of persistence_postgres.js older than 2026-09-11.'
      });
    }
    log.debug("Leaving databaseMetrics().");
    return driver.metrics({
      timeoutMs: Number(config.value('persistence.metricsTimeoutMs'))
    }).then(function (report) {
      report.available = true;
      report.mode = configured;
      // The target, from the ONE function that already parses a connection
      // string without printing the password in it. A second reading here
      // would be a second chance to get that wrong.
      report.target = describeDatabase();
      // **THE SCHEMA IS NOT REPORTED HERE AND THERE IS NO SETTING FOR IT.**
      // The first version of this read `persistence.databaseSchema`, which
      // does not exist — `config.value()` THROWS for a key it does not know,
      // so that line would have failed every call on the one mode this
      // function is for. The schema is chosen by the `search_path` in the
      // connection string (or by the database's own default), which means the
      // only honest answer is the SERVER's: the `server` probe asks
      // `current_schema()`, and that is what every schema probe below it
      // actually scoped to.
      // **REQUIRED LAZILY, LIKE THE DRIVER ITSELF.** That module pulls in
      // `pg` at create() time, and this file is required by every process
      // that loads the protocol stack — including the ones running in
      // `memory` mode, which must not be stopped by a missing optional
      // dependency. By the time this line runs the driver is open, so it is
      // a cache hit.
      //
      // What crosses is the DECLARED schema: the version the driver expects
      // and the objects it would create. The page reads them against what is
      // actually in the database, which is the one drift check on that page
      // that nothing else in this service makes — `tests/postgres_schema.js`
      // compares the driver against `postgres/schema.sql`, and neither of
      // them compares either against a running server.
      const declared = require('./persistence_postgres');
      report.schemaVersion = declared.SCHEMA_VERSION;
      report.declaredObjects = declared.SCHEMA_OBJECTS.map(function (one) {
        return one.name;
      });
      log.debug('Leaving databaseMetrics(). ok=' + report.ok);
      return report;
    });
  },

  changeRowsWritten: function () {
    log.debug("Entering changeRowsWritten().");
    if (!driver || typeof driver.changeRowsWritten !== 'function') {
      log.debug("Leaving changeRowsWritten().");
      return 0;
    }
    log.debug("Leaving changeRowsWritten().");
    return driver.changeRowsWritten();
  },

  latestChangeSeq: function () {
    log.debug("Entering latestChangeSeq().");
    if (!enabled() || !driver || typeof driver.latestChangeSeq !== 'function') {
      log.debug("Leaving latestChangeSeq().");
      return Promise.resolve(0);
    }
    log.debug("Leaving latestChangeSeq().");
    return Promise.resolve(driver.latestChangeSeq()).then(function (seq) {
      return Number(seq) || 0;
    });
  },
  mintedStatus: function () {
    log.debug("Entering mintedStatus().");
    log.debug("Leaving mintedStatus().");
    return minted.status();
  },
  coordinate: coordinate,
  replicationStatus: function () {
    log.debug("Entering replicationStatus().");
    log.debug("Leaving replicationStatus().");
    return replication.status();
  },
  // THE READ BARRIER, for `common/request_pool.js`. Re-exported here rather
  // than reached for directly so that a caller has ONE persistence module to
  // talk to — the same reason restoreMinted() is re-exported above.
  syncNow: function () {
    log.debug("Entering syncNow().");
    log.debug("Leaving syncNow().");
    return replication.syncNow();
  },
  status: status
};
