'use strict';
//
// File: appconfig_persistence.js
//
// ===========================================================================
// WHAT A SETTING CHANGE ACTUALLY WRITES TO DISK, AND WHAT COMES BACK.
//
// The console and the management API both answer "did that setting change?"
// out of memory, so a value that round-trips through either of them proves that
// something is holding it and nothing more. The parent project's
// `tests/vendored/sts_admin_console.js` and `tests/vendored/sts_admin_api_operations.js` go as far
// as an HTTP client can — they watch `/admin-api/persistence`'s write counter
// move, its dirty flag clear and its failure counter stay put — and that is
// still an assertion about a number the service computed about itself.
//
// WHAT NEITHER OF THEM CAN ASK IS WHAT IS IN THE FILE.
//
// That is this file's whole claim to being here, and it passes the rule at the
// top of tests/CLAUDE.md on the same clause `ldif_codec.js` does, one step
// further along: **the failure is invisible until a restart, and it happens in
// a different process.** An override that is held in memory and written wrongly
// — or not written at all — is correct on every endpoint for the whole life of
// the process that made it. Nothing an HTTP client can ask shows it. The damage
// appears on the NEXT start, as a setting that has quietly gone back to its
// default, in a store that is perfectly valid.
//
// So this drives the real modules in process, against a temporary directory,
// and then reads the files:
//
//   * a PROCESS-WIDE override lands in `appconfig.json`, with the value and the
//     type it was set with;
//   * a REALM's override lands on that realm's row in `realms.json` and NOT in
//     `appconfig.json` — they are two different files, and `configChanged()` is
//     one function with a branch in it that no reader of either file can see;
//   * `applyPersistedOverrides()` puts a saved file back, which is the half
//     that happens on the next start and is the only reason the writing half
//     matters;
//   * a saved RESTART-ONLY setting is REFUSED on the way back in and reported
//     rather than smuggled past the validation every other caller goes
//     through — a file written by an older build is the ordinary case, not a
//     hypothetical one;
//   * and `clearOverride()` really takes the row OUT of the file, rather than
//     writing the old value back over it. That is the distinction
//     tests/CLAUDE.md already warns about from the other end: a `set` that
//     restores a value leaves `source: override` behind for ever.
//
// IT DRIVES `ldif` AND NOT `postgres`, AND THAT IS THE DIRECTORY'S RULE RATHER
// THAN AN OMISSION. Both modes are real and both are behind ONE driver
// interface — `persistence.js` chooses between `persistence_ldif.js` and
// `persistence_postgres.js` in three lines and does nothing differently
// afterwards — so what is asserted below is the same code path in either case:
// which of the three things is dirty, which file or table it belongs in, and
// what `applyPersistedOverrides()` does with what comes back. What differs is
// the driver's own SQL, and reaching that needs a database, which is the one
// thing tests/CLAUDE.md says a test here may not need ("no port, no container,
// no browser, no network"). The postgres driver is exercised by the parent
// suite's two admin jobs whenever the service under test is configured that
// way — they read `status.mode` off the service and assert against whatever
// they meet rather than assuming ldif — and, since 2026-08-28, by
// `tests/sts_persistence_postgres.js` over there, which stands up a Postgres
// and a mock of its own, RESTARTS the mock, and asserts what came back out of
// `sts_appconfig`, `sts_realms` and `sts_ldap_entries`. That job is the only
// one in this ecosystem that owns the service it drives, which is what a
// restart needs and what this directory's no-port rule forbids.
//
// THIS IS THE FIRST TEST IN THIS DIRECTORY THAT TURNS A STORE ON, which
// tests/CLAUDE.md anticipated and set one condition for: it must clean up a
// DIRECTORY rather than a Map. It writes into a directory of its own under the
// system temporary directory, made per run, and removes it in a `finally` —
// including when an assertion has failed, since a failing run is exactly the
// one that would otherwise leave the litter behind.
//
// It also restores `process.env` and every override it sets, because the realm
// table and the environment are shared by every test in the run.
// ===========================================================================

// CONFIG_FILE is DELETED before anything here is required, for
// config_realm_layer.js's reason: what this asserts must be true of the service
// as it ships, and a developer with CONFIG_FILE exported in their shell would
// otherwise be running it against their own appconfig.
delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');

const config = require('../common/config');
const realms = require('../common/realms');
const persistence = require('../persistence/persistence');

// The one key this file drives process-wide. It is chosen rather than invented:
// an INTEGER cannot be satisfied by an echo the way a string can, it is
// `runtime: true` so it may be overridden at all, and it belongs to a family
// nothing else in this directory touches.
const PROCESS_KEY = 'krb5.clockSkew';

// And the one it drives on a realm. `saml.issuer` is seeded onto every realm at
// creation — every realm gets its own so that two realms cannot mint assertions
// their audiences could not tell apart — so what is asserted is that a CHANGE
// to it is written, which is a different claim from the seed being written.
const REALM_KEY = 'saml.issuer';

function run(t) {
  t.log.info('Entering run().');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-appconfig-test-'));
  const saved = saveEnvironment();
  const realmId = 'persist' + Math.random().toString(36).slice(2, 8);

  return Promise.resolve()
    .then(function () { return drive(t, dir, realmId); })
    .finally(function () {
      // Order matters: the store is stopped before the realm is removed, so a
      // scheduled flush cannot fire against a table this file has already
      // taken its realm out of.
      try {
        persistence.stop();
      } catch (e) {
        // stop() on a store that never opened is not an error, and a throw
        // here would replace the failure that matters.
        t.log.debug('persistence.stop() said: ' + e.message);
      }
      try {
        config.clearOverride(PROCESS_KEY);
      } catch (e) {
        t.log.debug('clearing ' + PROCESS_KEY + ' said: ' + e.message);
      }
      try {
        realms.remove(realmId);
      } catch (e) {
        t.log.debug('removing the realm said: ' + e.message);
      }
      restoreEnvironment(saved);
      try {
        fs.rmSync(dir, { recursive: true, force: true });
        t.log.info('Removed the temporary store at ' + dir + '.');
      } catch (e) {
        t.log.warn('Could not remove ' + dir + ': ' + e.message);
      }
      t.log.info('Leaving run().');
    });
}

async function drive(t, dir, realmId) {
  t.log.info('the store, in ldif mode, writing into ' + dir);
  process.env.STS_PERSISTENCE_MODE = 'ldif';
  process.env.STS_PERSISTENCE_DATA_DIR = dir;
  process.env.STS_PERSISTENCE_APPCONFIG = 'true';
  process.env.STS_PERSISTENCE_REALMS = 'true';
  // Zero, so a flush is not waited for: the delay exists to coalesce a burst of
  // directory writes, and this file makes one change at a time on purpose.
  process.env.STS_PERSISTENCE_WRITE_DELAY = '0';

  // THE STORE WILL NOT OPEN WITHOUT A DIRECTORY, and installing a real one
  // here would mean requiring ldap/ldap_server.js — which requires the console,
  // which requires the authorization server, which is most of the service. So
  // this fills the slot with the two functions the module actually needs, and
  // that is not a shortcut: what is under test is the APPCONFIG and REALM
  // halves of the store, and a directory that answers "no entries" exercises
  // them exactly as a full one would while keeping this a unit test. The
  // directory half has its own coverage in ldif_codec.js, which tests the codec
  // rather than the driver for the same reason.
  persistence.setDirectory({
    realmEntries: function () { return []; },
    replaceRealm: function () { return undefined; }
  });
  await persistence.start();
  t.check(persistence.enabled(), 'the store opened',
          'mode=' + persistence.activeMode() + ', dir=' + persistence.dataDir());
  if (!persistence.enabled()) {
    // Everything below asserts about files this would have written. Saying so
    // once is better than eleven failures that all mean this.
    t.bad('nothing below can be asserted with the store closed',
          persistence.status().lastError);
    return;
  }

  await aProcessWideOverrideIsWritten(t, dir);
  await aRealmsOverrideIsWrittenSomewhereElse(t, dir, realmId);
  await theRealmRuntimeMarkerIsHonoured(t, realmId);
  await aSavedFileIsPutBack(t, dir);
  await aSavedRestartOnlySettingIsRefused(t);
  await clearingTakesTheRowOut(t, dir);
}

// ---------------------------------------------------------------------------
// A PROCESS-WIDE OVERRIDE LANDS IN appconfig.json, WITH ITS TYPE.
//
// The type is worth asserting and is the half that a round trip through HTTP
// cannot see at all: `krb5.clockSkew` is an integer, the console posts it as
// the STRING "123" out of a text box, and what has to be in the file is what
// `applyPersistedOverrides()` will hand back to `checkOverride()` on the next
// start. A file holding `"123"` where the table expects an integer is a file
// that either fails validation on the way back in or quietly re-types the
// setting — and both of those happen in a different process, days later.
// ---------------------------------------------------------------------------
async function aProcessWideOverrideIsWritten(t, dir) {
  t.log.info('a process-wide override lands in appconfig.json');
  const before = Number(config.value(PROCESS_KEY));
  const wanted = before + 7;

  const result = config.setOverride(PROCESS_KEY, wanted);
  t.check(result.ok, 'the override was accepted',
          JSON.stringify(result.errors || []));
  t.equal(result.realm, null,
          'and it landed process-wide rather than on a realm');

  await persistence.flush();
  const file = readJson(path.join(dir, 'appconfig.json'));
  t.check(!!file, 'appconfig.json exists after the flush',
          'in ' + dir + ': ' + fs.readdirSync(dir).join(', '));
  t.equal((file.overrides || {})[PROCESS_KEY], wanted,
          'AND IT HOLDS THE VALUE, AS A NUMBER — the console posts "' +
          wanted + '" out of a text box, and what has to be on disk is what ' +
          'checkOverride() will be handed on the next start');
  t.check(typeof (file.overrides || {})[PROCESS_KEY] === 'number',
          'and its TYPE survived the write',
          'it is a ' + typeof (file.overrides || {})[PROCESS_KEY]);
  t.check(!!file.note && /override/i.test(file.note),
          'and the file says what it is, for whoever finds it',
          String(file.note).slice(0, 60) + '…');
}

// ---------------------------------------------------------------------------
// A REALM'S OVERRIDE LANDS SOMEWHERE ELSE ENTIRELY.
//
// `configChanged(realmId)` is one function with a branch in it: a realm's
// overrides live on the realm row in realms.json and a process-wide one lives
// in the appconfig store. Those are two files and, in postgres mode, two
// tables. From either file alone the branch is invisible, which is why both are
// read here and why the NEGATIVE half — the realm's value is NOT in
// appconfig.json — is the assertion that would catch them collapsing into one.
// ---------------------------------------------------------------------------
async function aRealmsOverrideIsWrittenSomewhereElse(t, dir, realmId) {
  t.log.info("a realm's override lands on its row in realms.json");
  const made = realms.create({ id: realmId, name: 'Persistence test' });
  t.check(made.ok !== false, 'the realm was created',
          JSON.stringify(made.errors || []));

  // FLUSHED HERE, BEFORE THE OVERRIDE, AND THAT IS NOT TIDINESS. Creating a
  // realm makes the registry dirty on its own, so without this the create's
  // write and the override's write coalesce into one — and the assertion below
  // then passes whether or not the OVERRIDE scheduled a write at all. It was
  // written without this line first, and a mutant with the whole realm branch
  // of `configChanged()` switched off survived it.
  await persistence.flush();
  const seeded = readJson(path.join(dir, 'realms.json'));
  t.check(!!seeded, 'the realm registry was written when the realm was made',
          'in ' + dir + ': ' + fs.readdirSync(dir).join(', '));

  // THE WRITE IS MADE THROUGH config.setOverride() WITH THE REALM AMBIENT,
  // which is what every door a person uses actually does — the console's Save,
  // the token-lifetimes form, POST /admin-api/config/set — and it is the ONLY
  // way this file reaches the branch under test. `realms.setOverride()` next
  // door writes the realm row directly and fires the realm change event, so it
  // never goes through `configChanged()` at all: a version of this assertion
  // written against it passed against a mutant with the whole realm branch
  // switched off.
  const wanted = 'urn:test:' + realmId + ':issuer';
  const set = realms.run(realms.get(realmId), function () {
    return config.setOverride(REALM_KEY, wanted);
  });
  t.check(set.ok !== false, 'the realm setting was accepted',
          JSON.stringify(set.errors || []));
  t.equal(set.realm, realmId,
          'AND config.setOverride() ROUTED IT TO THE AMBIENT REALM — a write ' +
          'lands wherever it was made, which is the whole of what makes ' +
          '/admin/config realm-aware without any of its callers knowing');

  await persistence.flush();
  const rows = readJson(path.join(dir, 'realms.json'));
  const row = ((rows && rows.realms) || []).filter(function (one) {
    return one.id === realmId;
  })[0];
  t.check(!!row, 'the realm is in realms.json',
          'it holds ' + JSON.stringify(((rows && rows.realms) || [])
            .map(function (one) { return one.id; })));
  t.equal(row && (row.overrides || {})[REALM_KEY], wanted,
          'and the row carries the override that was set on it');
  t.check(!!(row && row.overrides && Object.keys(row.overrides).length > 1),
          'beside the settings seeded onto every realm at creation, which are ' +
          'what stop two realms minting assertions their audiences could not ' +
          'tell apart',
          JSON.stringify(Object.keys((row && row.overrides) || {})));

  const appconfig = readJson(path.join(dir, 'appconfig.json')) || {};
  t.check(!Object.prototype.hasOwnProperty.call(appconfig.overrides || {},
                                                REALM_KEY),
          "AND THE REALM'S VALUE IS NOT IN appconfig.json — a realm's " +
          'overrides and the process\'s are two different files, and a ' +
          'realm whose settings leaked into the process-wide store would ' +
          'come back on the next start as everybody\'s',
          JSON.stringify(Object.keys(appconfig.overrides || {})));

  t.check(!(rows && rows.realms || []).some(function (one) {
    return one.id === 'default';
  }), 'and the DEFAULT realm is not a row in that file — it is a constant ' +
      'in realms.js, so a file that carried one would be describing a realm ' +
      'nobody can remove');
}

// ---------------------------------------------------------------------------
// AND THE ONE SETTING A REALM MAY CARRY THAT THE PROCESS MAY NOT.
//
// `oauth2.rfc9700` decides whether the main port is bound as HTTPS, so it is
// restart-only for the process; a realm binds no socket, so a realm may carry
// it. config.js marks that with `realmRuntime` and `checkOverride()` has taken
// a third argument for it all along — and every caller inside this service
// omitted that argument, so the marker was unreachable through
// `config.setOverride()`, which is the function all four doors go through.
//
// It is asserted here as well as from the console because the two halves fail
// differently: over there the symptom is a whole settings section that cannot
// be saved, and here it is the rule itself.
// ---------------------------------------------------------------------------
async function theRealmRuntimeMarkerIsHonoured(t, realmId) {
  t.log.info('the one setting a realm may carry and the process may not');
  const KEY = 'oauth2.rfc9700';
  const setting = config.SETTINGS.filter(function (one) {
    return one.key === KEY;
  })[0];
  t.check(!!setting && setting.realmRuntime === true && !setting.runtime,
          KEY + ' is the realmRuntime row: restart-only for the process, ' +
          'settable on a realm',
          JSON.stringify({ runtime: setting && setting.runtime,
                           realmRuntime: setting && setting.realmRuntime }));

  const processWide = config.setOverride(KEY, true);
  t.check(processWide.ok === false,
          'setting it PROCESS-WIDE is refused — global.https derives from it ' +
          'and a listener is bound when the process starts',
          JSON.stringify(processWide.errors || []));

  const inRealm = realms.run(realms.get(realmId), function () {
    return config.setOverride(KEY, true);
  });
  t.check(inRealm.ok !== false,
          'AND SETTING IT ON A REALM IS ACCEPTED, through the same function — ' +
          'which it was not, because setOverride() computed the realm and ' +
          'then asked checkOverride() without telling it',
          JSON.stringify(inRealm.errors || []));
  t.equal(inRealm.realm, realmId, 'and it landed on that realm');

  const there = realms.run(realms.get(realmId), function () {
    return config.value(KEY);
  });
  t.equal(there, true, 'the realm reads it as set');
  t.equal(config.value(KEY), false,
          'AND THE PROCESS DOES NOT — one process answering permissively at ' +
          '/oauth2/authorize and enforcing the BCP under a realm prefix is ' +
          'the whole point of the marker');

  realms.run(realms.get(realmId), function () {
    config.clearOverride(KEY);
  });
}

// ---------------------------------------------------------------------------
// AND THE HALF THAT HAPPENS ON THE NEXT START.
//
// Writing correctly is only worth anything if reading puts it back, and the
// reading half runs in a process that has already required every module. That
// is safe for one reason and only one: `checkOverride()` refuses anything that
// is not `runtime: true`, and a runtime setting is BY DEFINITION read per call
// rather than captured at require time — so there is nothing in a saved file
// that any module could already have cached.
// ---------------------------------------------------------------------------
async function aSavedFileIsPutBack(t, dir) {
  t.log.info('a saved file is applied the way the next start applies it');
  const file = readJson(path.join(dir, 'appconfig.json')) || {};
  const savedValue = (file.overrides || {})[PROCESS_KEY];

  // Take the override away in memory, the way a fresh process has none, and
  // then hand the file back exactly as start() does.
  config.clearOverride(PROCESS_KEY);
  const withoutIt = Number(config.value(PROCESS_KEY));
  t.check(withoutIt !== savedValue,
          'with the override cleared the setting is back to its default',
          withoutIt + ' against the saved ' + savedValue);

  const applied = config.applyPersistedOverrides(file.overrides);
  t.check(applied.indexOf(PROCESS_KEY) >= 0,
          'applyPersistedOverrides() reports having applied it',
          JSON.stringify(applied));
  t.equal(Number(config.value(PROCESS_KEY)), savedValue,
          'AND THE VALUE IS IN FORCE AGAIN — which is the whole point of the ' +
          'file, and the half that happens in a different process from the ' +
          'one that wrote it');
  t.equal(config.sourceOf(PROCESS_KEY), 'override',
          'and it is an override again rather than an appconfig value, so ' +
          '/admin/config says where it came from');
}

// ---------------------------------------------------------------------------
// A SAVED VALUE IS RE-CHECKED RATHER THAN TRUSTED, and this is not a
// hypothetical: the file was written by this service, but by a POSSIBLY OLDER
// BUILD of it — a setting may have been renamed, retyped, had its enum narrowed
// or been made restart-only since. Smuggling such a value past the validation
// every other caller goes through is how a saved file comes to configure a
// service in a state no caller could have put it in.
// ---------------------------------------------------------------------------
async function aSavedRestartOnlySettingIsRefused(t) {
  t.log.info('a saved value that is no longer allowed is reported, not applied');
  const pinned = restartOnlySetting();
  t.check(!!pinned, 'the table has a restart-only setting to try',
          pinned && pinned.key);
  if (!pinned) {
    return;
  }
  const before = config.value(pinned.key);
  const applied = config.applyPersistedOverrides({
    [pinned.key]: before,
    'no.such.setting.was.ever.here': 1
  });
  t.check(applied.indexOf(pinned.key) < 0,
          'a saved RESTART-ONLY setting (' + pinned.key + ') is NOT applied — ' +
          'the file was written by this service but by a possibly older ' +
          'build of it, and a value that is no longer allowed must go ' +
          'through the same validation as every other caller',
          'applied ' + JSON.stringify(applied));
  t.check(applied.indexOf('no.such.setting.was.ever.here') < 0,
          'and neither is a key this build has never heard of — a renamed ' +
          'setting is the ordinary way a saved file grows one',
          'applied ' + JSON.stringify(applied));
  t.check(config.sourceOf(pinned.key) !== 'override',
          'and the refused setting is not an override afterwards',
          'source=' + config.sourceOf(pinned.key));
  // The refusal is REPORTED to the log rather than returned — see
  // applyPersistedOverrides(), which warns per key and names the reason. What
  // is asserted here is the half that matters to the running service: the
  // value is not in force, and the row is LEFT in the store, because nothing
  // is deleted on the strength of one start refusing it.
}

// ---------------------------------------------------------------------------
// CLEARING TAKES THE ROW OUT OF THE FILE.
//
// This is the disk half of a rule tests/CLAUDE.md already states from the other
// end: restore a setting with `reset`, never with a second `set`, because a set
// leaves `source: override` on the row for ever. On disk it is sharper — a
// clear that wrote the old value back would leave the row in the file, and the
// next start would re-apply an override nobody asked for, on a setting whose
// default may have changed in between.
// ---------------------------------------------------------------------------
async function clearingTakesTheRowOut(t, dir) {
  t.log.info('clearing an override takes its row out of the file');
  config.clearOverride(PROCESS_KEY);
  await persistence.flush();
  const file = readJson(path.join(dir, 'appconfig.json')) || {};
  t.check(!Object.prototype.hasOwnProperty.call(file.overrides || {},
                                                PROCESS_KEY),
          'the row is GONE from appconfig.json rather than holding the old ' +
          'value — a clear that wrote the default back would be re-applied ' +
          'as an override on the next start, on a setting whose default may ' +
          'have moved in between',
          JSON.stringify(file.overrides || {}));
  const status = persistence.status();
  t.equal(status.failures, 0, 'and no write failed along the way');
  t.equal(status.pending, false, 'and nothing is left waiting to be written');
}

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------
function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    // Absent or unparseable. The caller asserts on the null, which says more
    // than a thrown parse error would.
    return null;
  }
}

function restartOnlySetting() {
  return config.SETTINGS.filter(function (setting) {
    return !setting.runtime && !setting.realmRuntime;
  })[0];
}

const PERSISTENCE_VARS = ['STS_PERSISTENCE_MODE', 'STS_PERSISTENCE_DATA_DIR',
                          'STS_PERSISTENCE_APPCONFIG', 'STS_PERSISTENCE_REALMS',
                          'STS_PERSISTENCE_WRITE_DELAY'];

function saveEnvironment() {
  const saved = {};
  PERSISTENCE_VARS.forEach(function (key) {
    saved[key] = Object.prototype.hasOwnProperty.call(process.env, key)
      ? process.env[key] : undefined;
  });
  return saved;
}

function restoreEnvironment(saved) {
  Object.keys(saved).forEach(function (key) {
    if (saved[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = saved[key];
    }
  });
}

module.exports = {
  name: 'appconfig_persistence',
  describe: 'that a setting change reaches the store on DISK, comes back on ' +
            'the next start, and that a realm\'s settings and the process\'s ' +
            'are two different files',
  run: run
};
