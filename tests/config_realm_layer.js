'use strict';
//
// File: config_realm_layer.js
//
// ===========================================================================
// WHAT A TRUST REALM MAY AND MAY NOT CARRY, ASSERTED AT BOTH ENDS.
//
// Three locks live in `common/config.js` and `common/realms.js`, all three were
// wrong at some point on 2026-08-25, and NONE of the three failures produced an
// error anywhere:
//
//   1. `POST /admin-api/realms/create` documented an `overrides` field and
//      dropped it on the floor. It answered 200 and built a realm configured
//      differently from the one that was asked for.
//   2. `realms.*` was documented as refused on a realm and was accepted. The
//      value was inert — the reading end ignores it — but `GET
//      /admin-api/realms` then published a realm as carrying a setting no
//      reader would ever consult.
//   3. `global.https` DERIVES its default from `oauth2.rfc9700`, and a realm
//      may carry that flag. Resolved through the ordinary reader, the derived
//      default followed the realm — so a realm inherited a claim about a
//      SOCKET IT DID NOT BIND: `oauth2_bcp.js` reported RFC 9700 sections 2.1
//      and 2.6 as met over a plain HTTP connection, and `issuerOf()` published
//      an `https://` issuer on an `http://` port.
//
// Every one of those is a silent disagreement rather than a fault, which is
// what makes them worth a test rather than a comment. The third is also the
// reason this directory exists: it cannot be observed from the parent
// project's suite, because that suite always starts this service with
// `STS_HTTPS=true`, and with the scheme pinned the broken and the fixed code
// give the same answer. See tests/CLAUDE.md.
//
// THERE IS NO NETWORK HERE. Everything below drives the two modules in
// process, which is why it can flip `process.env` between assertions —
// `resolve()` reads the environment per call — and why it takes about a
// second.
// ===========================================================================

// CONFIG_FILE is DELETED rather than set, before config.js is required.
// Anything this suite asserts must be true of the service as it ships, and a
// developer with CONFIG_FILE exported in their shell would otherwise be
// running these assertions against their own appconfig. With it unset the
// resolution stops at env/defaults.js, which is generated from the `dflt`
// column and is therefore the shipped answer by construction.
delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const bcp = require('../oauth-oidc/oauth2_bcp');

// The phrase config.js uses to refuse a restart-only setting. Matched rather
// than the whole message so a reworded reason does not fail this, but matched
// at all so that a refusal for some OTHER reason — a type check, say — cannot
// stand in for the one being asserted.
const RESTART_REFUSAL = 'cannot be changed while this service is running';

// ---------------------------------------------------------------------------
// Run `fn` with some environment variables set, then put the environment back
// exactly as it was. A key given as `undefined` is DELETED for the duration,
// which is a distinct case from empty and is the one that matters here:
// `global.https` is only derived when nothing above the default layer answers.
// ---------------------------------------------------------------------------
function withEnv(vars, fn) {
  const saved = {};
  Object.keys(vars).forEach(function (key) {
    saved[key] = Object.prototype.hasOwnProperty.call(process.env, key)
      ? process.env[key]
      : undefined;
    if (vars[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = vars[key];
    }
  });
  try {
    return fn();
  } finally {
    Object.keys(saved).forEach(function (key) {
      if (saved[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = saved[key];
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Create a realm, hand it to `fn`, and remove it however that goes. The realm
// table is process-wide, so a test that left
// one behind would change what a later test in the same run resolves.
// ---------------------------------------------------------------------------
function withRealm(t, id, overrides, fn) {
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename,
                               overrides: overrides || {} });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    return undefined;
  }
  try {
    return fn(made.realm);
  } finally {
    realms.remove(id);
  }
}

// ---------------------------------------------------------------------------
// 1. THE MARKER ITSELF.
//
// config.js says in as many words: "DO NOT ADD A SECOND ONE BY ANALOGY", and
// gives the test — the restart reason has to be something a realm demonstrably
// does not have. A comment cannot enforce that. This can, and what it enforces
// is not that a second one is wrong but that adding one is a DECISION: the row
// below has to be edited in the same commit, which is where somebody reads the
// paragraph.
// ---------------------------------------------------------------------------
function checkMarker(t) {
  t.log.info('the realmRuntime marker');
  const marked = config.SETTINGS.filter(function (s) {
    return s.realmRuntime;
  });
  t.equal(marked.length, 1,
          'exactly one setting is marked realmRuntime');
  t.equal(marked.length === 1 ? marked[0].key : null, 'oauth2.rfc9700',
          'and it is oauth2.rfc9700');
  marked.forEach(function (s) {
    // The marker only means anything on a row that is restart-only for the
    // process. On a runtime row it would be noise, and a reader would take it
    // for a rule that had been relaxed.
    t.equal(s.runtime, false,
            s.key + ' is still restart-only for the PROCESS');
    t.check(typeof s.restartReason === 'string' && s.restartReason.length > 0,
            s.key + ' says why it is restart-only',
            JSON.stringify(s.restartReason));
  });
}

// ---------------------------------------------------------------------------
// 2. THE WRITING END: who may set what, on a realm and on the process.
// ---------------------------------------------------------------------------
function checkWritingEnd(t) {
  t.log.info('the writing end — config.checkOverride()');

  const processWide = config.checkOverride('oauth2.rfc9700', true);
  t.check(typeof processWide === 'string' &&
          processWide.indexOf(RESTART_REFUSAL) >= 0,
          'the PROCESS still refuses oauth2.rfc9700 at runtime',
          JSON.stringify(processWide));

  t.equal(config.checkOverride('oauth2.rfc9700', true, true), null,
          'a REALM may carry oauth2.rfc9700');

  // The exemption is the marker and nothing else. Every other restart-only row
  // has to stay refused in both directions — this is the assertion that would
  // catch `forRealm` being widened into "restart-only settings are fine on a
  // realm", which is the shape the next mistake would take.
  const restartOnly = config.SETTINGS.filter(function (s) {
    return !s.runtime && !s.realmRuntime;
  });
  const leaked = restartOnly.filter(function (s) {
    // The setting's OWN current value, so it is type-valid by construction and
    // the only ground left to refuse it on is the restart rule.
    const problem = config.checkOverride(s.key, config.text(s.key), true);
    return !(typeof problem === 'string' &&
             problem.indexOf(RESTART_REFUSAL) >= 0);
  });
  t.equal(leaked.length, 0,
          'every OTHER restart-only setting is still refused on a realm (' +
          restartOnly.length + ' checked)');
  leaked.forEach(function (s) {
    t.bad('  ' + s.key + ' was accepted on a realm and carries no ' +
          'realmRuntime marker',
          'either mark it deliberately or fix checkRealmOverride()');
  });

  // `global.https` is the specific one worth naming, because it is the row the
  // marker's whole argument is ABOUT: a realm may carry the mode precisely
  // because it binds no socket, so it must not be able to carry the scheme.
  const scheme = config.checkOverride('global.https', true, true);
  t.check(typeof scheme === 'string',
          'a realm may NOT carry global.https — it binds no socket',
          JSON.stringify(scheme));
}

// ---------------------------------------------------------------------------
// 3. THE WRITING END, THROUGH realms.js — where two of the three defects were.
// ---------------------------------------------------------------------------
function checkRealmWrites(t) {
  t.log.info('the writing end — realms.create() / realms.setOverride()');

  // Defect 1: create() documented `overrides` and ignored it. Asserting the
  // realm CARRIES what it was created with is the whole of that fix, and it is
  // the one thing a 200 could never have told anybody.
  const made = realms.create({ id: 'trl-create', name: 'trl-create',
                               overrides: { 'oauth2.rfc9700': true } });
  t.check(made.ok, 'create() accepts an overrides object',
          (made.errors || []).join(' '));
  if (made.ok) {
    t.equal(made.realm.overrides['oauth2.rfc9700'], true,
            'and the realm actually CARRIES it (it was dropped until ' +
            '2026-08-25)');
    realms.remove('trl-create');
  }

  // Defect 2, at every writing path: set, and create/update's whole-object
  // validation. Both go through checkRealmOverride() so that they cannot
  // disagree, which is the property being pinned here rather than the refusal
  // itself.
  const badCreate = realms.create({
    id: 'trl-bad', name: 'trl-bad',
    overrides: { 'realms.pathSegment': 'zone' }
  });
  t.check(!badCreate.ok, 'create() REFUSES a realms.* override',
          JSON.stringify(badCreate.errors));
  if (badCreate.ok) {
    realms.remove('trl-bad');
  }

  withRealm(t, 'trl-set', {}, function (realm) {
    const good = realms.setOverride(realm.id, 'oauth2.rfc9700', true);
    t.check(good.ok, 'setOverride() accepts oauth2.rfc9700 on a realm',
            JSON.stringify(good.errors));

    ['realms.pathSegment', 'realms.enabled'].forEach(function (key) {
      const bad = key === 'realms.enabled' ? false : 'zone';
      const refused = realms.setOverride(realm.id, key, bad);
      t.check(!refused.ok, 'setOverride() REFUSES ' + key + ' on a realm',
              JSON.stringify(refused.errors));
    });
  });
}

// ---------------------------------------------------------------------------
// 4. THE READING END: the derived default that leaked, and the general rule.
// ---------------------------------------------------------------------------
function checkReadingEnd(t) {
  t.log.info('the reading end — a derived default is about the PROCESS');

  withRealm(t, 'trl-derived', { 'oauth2.rfc9700': true }, function (realm) {
    // All three states of the scheme, because the bug was only visible in one
    // of them: with STS_HTTPS set either way the env layer answers above the
    // default and the broken code looked correct. UNSET is the shipped case —
    // `derived: true` keeps the row out of env/*.js — so it is also the case
    // every ordinary start of this service is in.
    [undefined, 'true', 'false'].forEach(function (scheme) {
      const env = { STS_HTTPS: scheme, STS_OAUTH2_RFC9700: undefined };
      withEnv(env, function () {
        const outside = config.value('global.https');
        const inside = realms.run(realm, function () {
          return config.value('global.https');
        });
        t.equal(inside, outside,
                'global.https inside the realm follows the PROCESS ' +
                '(STS_HTTPS=' + String(scheme) + ')');
        const mode = realms.run(realm, function () {
          return config.value('oauth2.rfc9700');
        });
        t.equal(mode, true,
                'and the realm still carries the mode itself ' +
                '(STS_HTTPS=' + String(scheme) + ')');
      });
    });
  });

  // The other direction, and it is not a formality: the fix must not cost the
  // row its actual purpose, which is that turning the mode on for the PROCESS
  // brings HTTPS with it (RFC 9700 section 2.1).
  withEnv({ STS_OAUTH2_RFC9700: 'true', STS_HTTPS: undefined }, function () {
    t.equal(config.value('global.https'), true,
            'RFC 9700 mode on the PROCESS still derives global.https');
  });
  withEnv({ STS_OAUTH2_RFC9700: 'false', STS_HTTPS: undefined }, function () {
    t.equal(config.value('global.https'), false,
            'and with the mode off the process is still plain http');
  });

  // ---------------------------------------------------------------------
  // THE GENERAL RULE, so that the next derived row is covered on the day it
  // is added rather than the day somebody remembers this file. A realm may
  // carry a realmRuntime setting; nothing DERIVED from one may follow it,
  // because every realmRuntime row is by definition restart-only for a
  // reason the derived row still has.
  //
  // If a derived setting is ever meant to vary per realm, this assertion is
  // where that decision gets written down — do not simply delete it.
  // ---------------------------------------------------------------------
  const derived = config.SETTINGS.filter(function (s) { return s.derived; });
  const flipped = {};
  config.SETTINGS.filter(function (s) { return s.realmRuntime; })
    .forEach(function (s) {
      flipped[s.key] = !config.value(s.key);
    });
  withRealm(t, 'trl-flip', flipped, function (realm) {
    derived.forEach(function (s) {
      const outside = JSON.stringify(config.value(s.key));
      const inside = JSON.stringify(realms.run(realm, function () {
        return config.value(s.key);
      }));
      t.equal(inside, outside,
              'derived ' + s.key + ' ignores a realm-only realmRuntime ' +
              'override');
    });
  });
  t.check(derived.length > 0, 'there are derived settings to check at all',
          derived.length + ' found');
}

// ---------------------------------------------------------------------------
// 5. THE READING END'S OWN LOCK ON `realms.*`.
//
// config.js calls this "the second of two locks on one door" and says it is the
// end that cannot be got around. That claim is only worth anything if it holds
// with the FIRST lock bypassed, so this bypasses it: the override is written
// straight onto the realm object, the way a realm stored by a build older than
// the writing lock would carry it.
// ---------------------------------------------------------------------------
function checkReadingLock(t) {
  t.log.info('the reading end — realms.* is ignored on a realm');
  withRealm(t, 'trl-legacy', {}, function (realm) {
    realm.overrides['realms.pathSegment'] = 'zone';
    realm.overrides['realms.enabled'] = false;
    const segment = realms.run(realm, function () {
      return config.value('realms.pathSegment');
    });
    t.equal(segment, config.value('realms.pathSegment'),
            'a realms.pathSegment written onto a realm is ignored when read');
    const on = realms.run(realm, function () {
      return config.value('realms.enabled');
    });
    t.equal(on, config.value('realms.enabled'),
            'and so is realms.enabled — a realm cannot switch realms off');
  });
}

// ---------------------------------------------------------------------------
// 6. WHAT IT ALL MEANT, which is the assertion a person would actually make.
//
// The three above are about layers. This one is about the answer a client
// gets: with the process on plain http and a realm in RFC 9700 mode, the mode
// is ON and the two TLS requirements are reported NOT ENFORCED. Before the fix
// both came back `deployment` — a compliance report claiming TLS over a
// connection that had none.
// ---------------------------------------------------------------------------
function checkComplianceReport(t) {
  t.log.info('the consequence — oauth2_bcp.js over a plain socket');
  withEnv({ STS_HTTPS: undefined, STS_OAUTH2_RFC9700: undefined },
          function () {
    withRealm(t, 'trl-bcp', { 'oauth2.rfc9700': true }, function (realm) {
      t.equal(bcp.enabled(), false,
              'the DEFAULT realm is still permissive');
      realms.run(realm, function () {
        t.equal(bcp.enabled(), true, 'the realm enforces the BCP');
        ['response-over-tls', 'tls-everywhere'].forEach(function (id) {
          const row = bcp.REQUIREMENTS.filter(function (r) {
            return r.id === id;
          })[0];
          if (!row) {
            t.bad('requirement "' + id + '" is missing from REQUIREMENTS',
                  'it was renamed or removed; this check needs updating');
            return;
          }
          const state = typeof row.enforced === 'function'
            ? row.enforced()
            : row.enforced;
          t.equal(state, 'no',
                  id + ' is reported NOT enforced — this process bound a ' +
                  'plain socket');
        });
      });
    });
  });
}

function run(t) {
  checkMarker(t);
  checkWritingEnd(t);
  checkRealmWrites(t);
  checkReadingEnd(t);
  checkReadingLock(t);
  checkComplianceReport(t);
}

module.exports = {
  name: 'config_realm_layer',
  describe: 'what a trust realm may and may not carry, at both ends',
  run: run
};
