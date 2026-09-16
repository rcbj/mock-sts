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

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'config_realm_layer',
  level: process.env.LOG_LEVEL || 'info' });

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
  log.debug("Entering withEnv().");
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
    log.debug("Leaving withEnv().");
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
  log.debug("Entering withRealm().");
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename,
                               overrides: overrides || {} });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving withRealm().");
    return undefined;
  }
  try {
    log.debug("Leaving withRealm().");
    return fn(made.realm);
  } finally {
    realms.remove(id);
  }
}

// A VALID value for a setting that is not the one it currently has. It was
// `!config.value(key)` while every realmRuntime row was a boolean, and a
// negated port is `false` — which the realm refuses on type grounds, so the
// realm was never created and the derived-settings check below silently
// checked nothing. The point of the flip is only that the realm carries
// SOMETHING different, so each type gets the cheapest other legal value.
function differentValue(setting) {
  log.debug("Entering differentValue().");
  if (setting.type === 'bool') {
    log.debug("Leaving differentValue().");
    return !config.value(setting.key);
  }
  if (setting.type === 'enum') {
    const now = config.text(setting.key);
    const other = (setting.enumValues || []).filter(function (v) {
      return v !== now;
    })[0];
    log.debug("Leaving differentValue().");
    return other === undefined ? now : other;
  }
  if (setting.type === 'port' || setting.type === 'int') {
    const now = Number(config.value(setting.key)) || 0;
    const max = setting.max === undefined ? 65535 : setting.max;
    log.debug("Leaving differentValue().");
    return now + 1 <= max ? now + 1 : Math.max(setting.min || 0, now - 1);
  }
  log.debug("Leaving differentValue().");
  // A string. Suffixed rather than replaced so that a row with a grammar —
  // `spiffe.trustDomain` takes letters, digits, dots, dashes and underscores —
  // is still given something it accepts.
  return String(config.text(setting.key) || 'x') + '-other';
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
  log.debug("Entering checkMarker().");
  t.log.info('the realmRuntime marker');
  // **THE LIST AND NOT THE COUNT, SINCE 2026-09-12.** It was `length === 1`
  // and `oauth2.rfc9700` while there was one holder, and the point of the
  // assertion was never the number: it is that adding one is a DECISION taken
  // in the same commit, at the line somebody has to edit. Naming them keeps
  // that exactly as strict — an eighth still fails here — and says what the
  // seven are.
  //
  // SPIFFE's six arrived together and are one argument, made at the head of
  // that group in config.js: this process binds four SPIFFE listeners and
  // builds one trust domain's authorities WHEN IT STARTS, and a realm's SPIFFE
  // is not started then — it is created OFF, its authorities are built on
  // first use and its listeners are bound when it is turned on. So for a realm
  // none of the six was consumed at any startup.
  //
  // KERBEROS'S TEN ARRIVED TOGETHER on 2026-09-15 and are one argument too,
  // made at the head of the Kerberos group in config.js: this process builds
  // ONE principal database when it starts, from these settings, and that is
  // what made them restart-only — but a TRUST REALM's Kerberos is not started
  // then. A realm is created with `krb5.enabled` off, builds its own principal
  // database when it is turned on, and rebuilds it when one of these changes on
  // that realm. So for a realm none of the ten was consumed at any startup. The
  // sockets (`krb5.kdcPort`, `krb5.servicePort`) and the development trust
  // (`krb5.trustedRealm` and its three) are NOT here, and must not be: those
  // are bound and built for the process.
  const EXPECTED_REALM_RUNTIME = [
    'oauth2.rfc9700',
    'krb5.realm',
    'krb5.domainSid',
    'krb5.krbtgtPassword',
    'krb5.servicePrincipal',
    'krb5.servicePassword',
    'krb5.serviceSalt',
    'krb5.kvno',
    'krb5.enctypes',
    'krb5.userPassword',
    'krb5.autoServicePassword',
    // OAuth 2.1 mode (2026-09-13). It implies RFC 9700 mode and moves the
    // socket for the same one reason, argued at its row in config.js.
    'oauth2.oauth21',
    'spiffe.trustDomain',
    'spiffe.x509KeyType',
    'spiffe.jwtKeyType',
    'spiffe.workloadSocketEnabled',
    'spiffe.workloadSocket',
    'spiffe.workloadPort',
    'spiffe.serverSocketEnabled',
    'spiffe.serverSocket',
    'spiffe.serverPort',
    'spiffe.grpcHost'
  ];
  const marked = config.SETTINGS.filter(function (s) {
    return s.realmRuntime;
  }).map(function (s) { return s.key; });
  t.equal(marked.slice(0).sort().join(','),
          EXPECTED_REALM_RUNTIME.slice(0).sort().join(','),
          'the realmRuntime rows are exactly the ones this file names — add ' +
          'one and this is the line that makes it a decision',
          marked.join(','));
  config.SETTINGS.filter(function (s) { return s.realmRuntime; })
    .forEach(function (s) {
    // The marker only means anything on a row that is restart-only for the
    // process. On a runtime row it would be noise, and a reader would take it
    // for a rule that had been relaxed.
    t.equal(s.runtime, false,
            s.key + ' is still restart-only for the PROCESS');
    t.check(typeof s.restartReason === 'string' && s.restartReason.length > 0,
            s.key + ' says why it is restart-only',
            JSON.stringify(s.restartReason));
  });
  log.debug("Leaving checkMarker().");
}

// ---------------------------------------------------------------------------
// 2. THE WRITING END: who may set what, on a realm and on the process.
// ---------------------------------------------------------------------------
function checkWritingEnd(t) {
  log.debug("Entering checkWritingEnd().");
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
  log.debug("Leaving checkWritingEnd().");
}

// ---------------------------------------------------------------------------
// 3. THE WRITING END, THROUGH realms.js — where two of the three defects were.
// ---------------------------------------------------------------------------
function checkRealmWrites(t) {
  log.debug("Entering checkRealmWrites().");
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
  log.debug("Leaving checkRealmWrites().");
}

// ---------------------------------------------------------------------------
// 4. THE READING END: the derived default that leaked, and the general rule.
// ---------------------------------------------------------------------------
function checkReadingEnd(t) {
  log.debug("Entering checkReadingEnd().");
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
  // ---------------------------------------------------------------------
  // THE ONE EXEMPTION, AND IT IS THE DECISION THIS BLOCK ASKS FOR
  // (2026-09-15). `krb5.serviceDomains` derives its default from
  // `krb5.realm` — the hosts a KDC will invent a service principal for are
  // the hosts in its own domain — and `krb5.realm` became a setting a trust
  // realm carries when each realm got a KDC of its own. A realm named
  // ACME.EXAMPLE.COM that went on being willing to be
  // `HTTP/web.example.com`, the DEFAULT realm's domain, would invent service
  // principals for another realm's hosts. So this derived row follows the
  // realm deliberately, and `krb5_principals.js` reads it inside the realm
  // whose database it is building.
  // ---------------------------------------------------------------------
  const FOLLOWS_THE_REALM = ['krb5.serviceDomains'];
  const derived = config.SETTINGS.filter(function (s) {
    return s.derived && FOLLOWS_THE_REALM.indexOf(s.key) === -1;
  });
  const flipped = {};
  config.SETTINGS.filter(function (s) { return s.realmRuntime; })
    .forEach(function (s) {
      flipped[s.key] = differentValue(s);
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
  log.debug("Leaving checkReadingEnd().");
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
  log.debug("Entering checkReadingLock().");
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
  log.debug("Leaving checkReadingLock().");
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
  log.debug("Entering checkComplianceReport().");
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
  log.debug("Leaving checkComplianceReport().");
}

function run(t) {
  log.debug("Entering run().");
  checkMarker(t);
  checkWritingEnd(t);
  checkRealmWrites(t);
  checkReadingEnd(t);
  checkReadingLock(t);
  checkComplianceReport(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'config_realm_layer',
  describe: 'what a trust realm may and may not carry, at both ends',
  run: run
};
