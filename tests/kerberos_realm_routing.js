'use strict';
//
// File: kerberos_realm_routing.js
//
// ===========================================================================
// A KDC PER TRUST REALM, ON THE SHARED PORT 88 (2026-09-15, issue #33).
//
// Kerberos was one of the two socket families a trust realm did not get: one
// KDC, one principal database and one `krb5.realm` for the whole process,
// pinned to the default realm. It is now told apart by the Kerberos realm NAME
// inside each request — the discriminator the protocol already carries — and
// this file is the guard for every part of that.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, which is the question tests/CLAUDE.md asks first.
//
// Two of the three sections cannot be asked of a running service at all:
//
//   * **THE SETTING RULES** are refusals the realm REGISTRY makes before
//     anything is built (realms.js, kerberosOverrideProblem()). They are
//     reachable over `/admin-api/realms/set`, but what is asserted here is the
//     rule itself and its error code, one door below that.
//   * **THE ROUTING** is a decision `handleMessage()` makes about which realm
//     answers, and the honest way to drive it is to hand that function the
//     bytes a client would send — which is what a socket does, with a socket in
//     the way. Over HTTP only `/KdcProxy` reaches it, and the pinned case needs
//     a request that arrived under a realm prefix, which is an argument rather
//     than a URL here.
//
// The third — that a realm's database is its OWN — is asserted against the real
// databases this process builds, which is also the cheapest place to see that
// the DEFAULT realm's is unchanged.
//
// Every realm this file makes is removed again, and the default realm is left
// exactly as it was found.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
// The code a refusal carries rides under a Symbol rather than on a field — see
// errorCodes.mark() — so it is read with codeOf() and never as `.errorCode`.
const errorCodes = require('../common/error_codes');
const principals = require('../kerberos/krb5_principals.js');
const kdc = require('../kerberos/krb5_kdc.js');
const msgs = require('../kerberos/krb5_messages.js');
const kcrypto = require('../kerberos/krb5_crypto.js');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'kerberos_realm_routing',
  level: process.env.LOG_LEVEL || 'info' });

const ACME = 'ACME.EXAMPLE.COM';
const BETA = 'BETA.EXAMPLE.COM';

function kerberosTime(atMs) {
  log.debug("Entering kerberosTime().");
  log.debug("Leaving kerberosTime().");
  return new Date(atMs);
}

// An AS-REQ for `username` in `realm`, with no pre-authentication — which is
// all this file needs: what is asserted is WHICH KDC answers, and the answer to
// a bare AS-REQ (KDC_ERR_PREAUTH_REQUIRED, or KDC_ERR_WRONG_REALM) names the
// realm that produced it.
function asReq(realm, username) {
  log.debug("Entering asReq().");
  const now = Date.now();
  log.debug("Leaving asReq().");
  return msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: [],
    reqBody: {
      kdcOptions: [msgs.KDC_OPTION.FORWARDABLE],
      cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: [username] },
      realm: realm,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: ['krbtgt', realm] },
      till: kerberosTime(now + 8 * 3600 * 1000),
      nonce: 1234567,
      etypes: [kcrypto.etypeByName('aes256-cts-hmac-sha1-96').id]
    }
  });
}

// A TGS-REQ with no PA-TGS-REQ. The realm check is the FIRST thing that
// function does — before it looks for the ticket — so a request this shape
// distinguishes "wrong realm" (68) from "no ticket in it" (25), which is
// exactly the two answers this file tells apart.
function tgsReq(realm, service) {
  log.debug("Entering tgsReq().");
  const now = Date.now();
  log.debug("Leaving tgsReq().");
  return msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.TGS_REQ,
    padata: [],
    reqBody: {
      kdcOptions: [],
      realm: realm,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: service },
      till: kerberosTime(now + 3600 * 1000),
      nonce: 7654321,
      etypes: [kcrypto.etypeByName('aes256-cts-hmac-sha1-96').id]
    }
  });
}

// What the KDC answered, as `{ error, realm, text }` for a KRB-ERROR and
// `{ asRep: true, realm }` for an AS-REP. The `realm` of either is the realm
// that ANSWERED, which is the whole assertion in section C.
async function ask(bytes, options) {
  log.debug("Entering ask().");
  const reply = await kdc.handleMessage(bytes, options);
  const identified = msgs.identify(reply);
  if (identified && identified.applicationNumber === msgs.APPLICATION.AS_REP) {
    const rep = msgs.readAsRep(reply);
    log.debug("Leaving ask(). An AS-REP.");
    return { asRep: true, realm: rep.crealm || '' };
  }
  const err = msgs.readKrbError(reply);
  log.debug("Leaving ask(). A KRB-ERROR.");
  return { error: err.errorCode, realm: err.realm || '',
           text: String(err.eText || '') };
}

// A realm with Kerberos ON, removed again afterwards however the body ends —
// including when the body is ASYNC, which is why this awaits it rather than
// returning it: a `finally` around a promise that has only been RETURNED runs
// before the body has done anything, and the realm would be gone by the time
// the first assertion looked for it.
async function withKerberosRealm(t, id, name, fn) {
  log.debug("Entering withKerberosRealm(). id=" + id);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename,
                               overrides: { 'krb5.realm': name,
                                            'krb5.enabled': 'true' } });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving withKerberosRealm(). Not created.");
    return undefined;
  }
  try {
    log.debug("Leaving withKerberosRealm().");
    return await fn(made.realm);
  } finally {
    realms.remove(id);
  }
}

// ---------------------------------------------------------------------------
// A. THE SETTING RULES, which are what stop two realms answering to one name.
// ---------------------------------------------------------------------------
async function theSettingRules(t) {
  log.debug("Entering theSettingRules().");
  t.log.info('=== A. a realm may not be given a name nothing can route ===');

  // 1. A NEW REALM IS CREATED WITH KERBEROS OFF, and that is seeded rather
  //    than inherited: `krb5.enabled` is true for the service.
  const plain = realms.create({ id: 'krr-off', name: 'krr-off',
                                description: 'Created by ' + __filename });
  t.check(plain.ok, 'a realm with no Kerberos settings is created',
          (plain.errors || []).join(' '));
  if (plain.ok) {
    t.equal(String(plain.realm.overrides['krb5.enabled']), 'false',
            'and it is created with krb5.enabled OFF, seeded on the realm — ' +
            'a realm does not get a KDC merely by existing');
    t.equal(principals.enabledIn('krr-off'), false,
            'so that realm has no KDC');
    t.equal(JSON.stringify(principals.servedIn('krr-off')), '[]',
            'and serves no Kerberos realm at all');
    t.equal(principals.trustRealmFor(''), null,
            'an empty name routes nowhere');
    realms.remove('krr-off');
  }

  // 2. TURNING IT ON WITHOUT A NAME OF ITS OWN IS REFUSED (STS-KRB-0123).
  const noName = realms.create({ id: 'krr-noname', name: 'krr-noname',
                                 overrides: { 'krb5.enabled': 'true' } });
  t.check(!noName.ok, 'Kerberos cannot be turned on for a realm with no ' +
          'krb5.realm of its own — it would inherit the service\'s name and ' +
          'be a second realm answering to it');
  t.equal(errorCodes.codeOf(noName), 'STS-KRB-0123',
          'and the refusal carries its code',
          JSON.stringify(noName.errors || []));
  t.check(!realms.get('krr-noname'),
          'and the realm was not created at all — the refusal is whole');

  // 3. A NAME ANOTHER REALM ANSWERS TO IS REFUSED (STS-KRB-0124), including
  //    the DEFAULT realm's own name and, in development, the trusted realm.
  await withKerberosRealm(t, 'krr-a', ACME, function () {
    const twin = realms.create({ id: 'krr-b', name: 'krr-b',
                                 overrides: { 'krb5.realm': ACME } });
    t.check(!twin.ok, 'a second realm may not claim a name the first answers ' +
            'to');
    t.equal(errorCodes.codeOf(twin), 'STS-KRB-0124',
            'and that refusal has its own code',
            JSON.stringify(twin.errors || []));
    const cased = realms.create({ id: 'krr-c', name: 'krr-c',
                                  overrides: { 'krb5.realm':
                                               ACME.toLowerCase() } });
    t.check(!cased.ok,
            'nor one that differs only in case — two realms a person could ' +
            'not tell apart in a krb5.conf');
    const asDefault = realms.create({ id: 'krr-d', name: 'krr-d',
                                      overrides: { 'krb5.realm':
                                                   principals.REALM } });
    t.check(!asDefault.ok && errorCodes.codeOf(asDefault) === 'STS-KRB-0124',
            'nor the DEFAULT realm\'s own Kerberos realm');
    const trusted = principals.TRUSTED_REALM;
    const asTrusted = realms.create({ id: 'krr-e', name: 'krr-e',
                                      overrides: { 'krb5.realm': trusted } });
    t.check(!asTrusted.ok && errorCodes.codeOf(asTrusted) === 'STS-KRB-0124',
            'nor krb5.trustedRealm, which the default realm answers for in ' +
            'development mode');

    // 4. A RENAME WHILE IT IS ON IS REFUSED (STS-KRB-0125) — every key in the
    //    realm's database is salted with the name.
    const renamed = realms.setOverride('krr-a', 'krb5.realm', BETA);
    t.check(!renamed.ok && errorCodes.codeOf(renamed) === 'STS-KRB-0125',
            'a realm\'s Kerberos realm cannot be renamed while its Kerberos ' +
            'is on: its keys are salted with the name',
            JSON.stringify(renamed.errors || []));
    const cleared = realms.clearOverride('krr-a', 'krb5.realm');
    t.check(!cleared.ok && errorCodes.codeOf(cleared) === 'STS-KRB-0125',
            'and it cannot be cleared either, which is the same change said ' +
            'another way');

    // 5. OFF, RENAME, ON is the way round it, and it works.
    const off = realms.setOverride('krr-a', 'krb5.enabled', 'false');
    t.check(off.ok, 'turning Kerberos off on the realm is allowed',
            (off.errors || []).join(' '));
    const now = realms.setOverride('krr-a', 'krb5.realm', BETA);
    t.check(now.ok, 'and then the name may be changed',
            (now.errors || []).join(' '));
    const on = realms.setOverride('krr-a', 'krb5.enabled', 'true');
    t.check(on.ok && principals.servedIn('krr-a')[0] === BETA,
            'and turned on again under the new name',
            JSON.stringify(principals.servedIn('krr-a')));
  });
  log.debug("Leaving theSettingRules().");
}

// ---------------------------------------------------------------------------
// B. THE DATABASE: a realm's own, built from its own settings.
// ---------------------------------------------------------------------------
async function theDatabase(t) {
  log.debug("Entering theDatabase().");
  t.log.info('=== B. each realm builds a principal database of its own ===');
  const defaultRealm = principals.REALM;
  const defaultCount = principals.all().length;
  const defaultAlice = principals.find(['alice']);

  await withKerberosRealm(t, 'krr-db', ACME, function (realm) {
    realms.run(realm, function () {
      t.equal(principals.REALM, ACME,
              'inside the realm, the Kerberos realm is the realm\'s own');
      const alice = principals.find(['alice']);
      t.check(!!alice, 'the realm has its own fixture accounts (development ' +
              'mode seeds them per realm)');
      t.equal(alice && alice.salt, ACME + 'alice',
              'salted with THIS realm\'s name, so its keys are not the ' +
              'default realm\'s');
      t.check(!!alice && !!defaultAlice && alice !== defaultAlice,
              'and it is a different record from the default realm\'s alice');
      t.check(!!principals.find(['krbtgt', ACME]),
              'it has a krbtgt of its own, whose key seals its TGTs');
      t.equal(principals.find(['krbtgt', principals.TRUSTED_REALM]), null,
              'and NO trust with the development second realm: trust realms ' +
              'do not trust each other\'s Kerberos');
      t.equal(JSON.stringify(principals.realmsServed()), '["' + ACME + '"]',
              'so it serves exactly one Kerberos realm');
      t.check(principals.SERVICE_DOMAINS.indexOf('acme.example.com') >= 0,
              'the hosts it will invent a service principal for are its own ' +
              'domain\'s, derived from its name',
              JSON.stringify(principals.SERVICE_DOMAINS));
    });

    // THE DEFAULT REALM IS UNTOUCHED, which is the claim a process with no
    // realms defined rests on.
    t.equal(principals.REALM, defaultRealm,
            'outside the realm the default realm still answers as itself');
    t.equal(principals.all().length, defaultCount,
            'with exactly the principals it had before the realm existed');
    t.equal(principals.find(['alice']) === defaultAlice, true,
            'and the same alice record, salted its own way');

    // A REBUILD keeps what is runtime state. `krb5.kvno` is one of the
    // settings a realm's database is built from.
    realms.run(realm, function () {
      principals.signOut(['alice'], ACME, new Date('2026-03-04T05:06:07Z'));
    });
    const changed = realms.setOverride('krr-db', 'krb5.kvno', '9');
    t.check(changed.ok, 'a setting the database is built from may be changed ' +
            'on the realm', (changed.errors || []).join(' '));
    realms.run(realm, function () {
      t.equal(principals.KVNO, 9,
              'the realm\'s database is rebuilt with the new value');
      t.equal(principals.find(['alice']) &&
              principals.find(['alice']).kvno, 9,
              'so its accounts carry it');
      const stamp = principals.signedOutAt(['alice'], ACME);
      t.equal(stamp && stamp.toISOString(), '2026-03-04T05:06:07.000Z',
              'AND THE SIGN-OUT SURVIVED THE REBUILD — runtime state is ' +
              'carried onto the record the new settings built');
    });

    // TURNING IT OFF takes the principals away rather than leaving a database
    // nothing routes to.
    realms.setOverride('krr-db', 'krb5.enabled', 'false');
    realms.run(realm, function () {
      t.equal(principals.find(['alice']), null,
              'with Kerberos off the realm holds no principal');
      t.equal(JSON.stringify(principals.realmsServed()), '[]',
              'and serves no name');
    });
    t.equal(principals.trustRealmFor(ACME), null,
            'so nothing on port 88 routes that name any more');
  });
  log.debug("Leaving theDatabase().");
}

// ---------------------------------------------------------------------------
// C. THE ROUTING, through the one function every door calls.
// ---------------------------------------------------------------------------
async function theRouting(t) {
  log.debug("Entering theRouting().");
  t.log.info('=== C. which realm answers a request on the shared port ===');
  const home = principals.REALM;

  await withKerberosRealm(t, 'krr-route', ACME, async function (realm) {
    // 1. THE DEFAULT REALM still answers its own name exactly as it did.
    const mine = await ask(asReq(home, 'alice'));
    t.equal(mine.error, 25,
            'an AS-REQ naming the service\'s own realm is answered ' +
            'KDC_ERR_PREAUTH_REQUIRED, as it always was', JSON.stringify(mine));
    t.equal(mine.realm, home, 'by the default realm');

    // 2. ANOTHER REALM'S NAME REACHES THAT REALM, on the same socket, with no
    //    path and no port of its own.
    const theirs = await ask(asReq(ACME, 'alice'));
    t.equal(theirs.error, 25,
            'an AS-REQ naming another trust realm\'s Kerberos realm is ' +
            'answered by a KDC too', JSON.stringify(theirs));
    t.equal(theirs.realm, ACME,
            'AND IT IS THAT REALM\'S KDC THAT ANSWERED — the realm name in ' +
            'the request is the discriminator');

    // 3. A NAME NOBODY SERVES is KDC_ERR_WRONG_REALM from the default realm,
    //    which is the sentence that was there before realms had KDCs.
    const nowhere = await ask(asReq('NOSUCH.EXAMPLE.COM', 'alice'));
    t.equal(nowhere.error, 68,
            'a realm no trust realm answers to is KDC_ERR_WRONG_REALM',
            JSON.stringify(nowhere));
    t.equal(nowhere.realm, home,
            'answered as the default realm, since no realm was entered');
    t.check(nowhere.text.indexOf(ACME) === -1,
            'and the refusal does NOT list the other realms\' Kerberos ' +
            'names: port 88 is unauthenticated, and this service\'s realms ' +
            'are otherwise told apart by a path somebody has to know',
            nowhere.text);

    // 4. A REALM'S OWN /realm/<id>/KdcProxy IS PINNED to that realm.
    const pinnedOk = await ask(asReq(ACME, 'alice'), { realm: realm });
    t.equal(pinnedOk.error, 25,
            'a request on the realm\'s own KdcProxy naming that realm is ' +
            'answered by it', JSON.stringify(pinnedOk));
    t.equal(pinnedOk.realm, ACME, 'as that realm');
    const pinnedWrong = await ask(asReq(home, 'alice'), { realm: realm });
    t.equal(pinnedWrong.error, 68,
            'and one naming a DIFFERENT realm is refused rather than ' +
            'answered from another database', JSON.stringify(pinnedWrong));
    t.equal(pinnedWrong.realm, ACME,
            'the refusal comes from the realm the address named');

    // 5. THE TGS EXCHANGE REFUSES AN UNSERVED REALM (STS-KRB-0121) where it
    //    used to fall back to this KDC's own and answer as that.
    const tgsWrong = await ask(tgsReq('NOSUCH.EXAMPLE.COM',
                                      ['HTTP', 'web.example.com']));
    t.equal(tgsWrong.error, 68,
            'a TGS-REQ naming a realm nobody serves is KDC_ERR_WRONG_REALM — ' +
            'it was silently answered as the default realm until 2026-09-15',
            JSON.stringify(tgsWrong));
    const tgsMine = await ask(tgsReq(home, ['HTTP', 'web.example.com']));
    t.equal(tgsMine.error, 25,
            'while one naming a realm this KDC does serve gets as far as ' +
            '"there is no ticket in it", which is the answer that proves the ' +
            'realm check is not refusing everything', JSON.stringify(tgsMine));
  });

  // 6. A REALM WHOSE KERBEROS IS OFF is not routed to, and its name is not
  //    served — the realm exists, and on this socket it does not.
  const off = realms.create({ id: 'krr-dark', name: 'krr-dark',
                              overrides: { 'krb5.realm': BETA } });
  if (off.ok) {
    const dark = await ask(asReq(BETA, 'alice'));
    t.equal(dark.error, 68,
            'a realm with a name but krb5.enabled off answers nothing on ' +
            'port 88', JSON.stringify(dark));
    t.equal(dark.realm, home, 'the default realm refuses it');
    realms.remove('krr-dark');
  }
  log.debug("Leaving theRouting().");
}

// ---------------------------------------------------------------------------
// D. WHAT A REALM WITH NO KDC MUST REFUSE, and what a rename must not leave
// behind. Every one of these was a defect a review found on the day this was
// built (2026-09-15): the acts below SUCCEEDED emptily in a realm with no
// Kerberos realm, storing a key under `…@` and handing back a keytab with no
// entries, and a rename left every runtime-made principal in the partition
// under the old name.
// ---------------------------------------------------------------------------
async function theRealmWithNoKdc(t) {
  log.debug("Entering theRealmWithNoKdc().");
  t.log.info('=== D. a realm with no KDC refuses, and a rename cleans up ===');
  const keys = require('../kerberos/krb5_person_keys.js');
  const made = realms.create({ id: 'krr-nokdc', name: 'krr-nokdc',
                               description: 'Created by ' + __filename });
  if (!t.check(made.ok, 'a realm with Kerberos off is created',
               (made.errors || []).join(' '))) {
    log.debug("Leaving theRealmWithNoKdc(). Not created.");
    return;
  }
  try {
    realms.run(made.realm, function () {
      const acts = [
        ['create-service', function () {
          return keys.createServicePrincipal('HTTP/web.krr.test', {});
        }],
        ['rotate-service', function () {
          return keys.rotateServicePrincipal('HTTP/web.krr.test', {});
        }],
        ['delete-service', function () {
          return keys.deleteServicePrincipal('HTTP/web.krr.test', {});
        }],
        ['clear-person-keys', function () {
          return keys.clearPersonKeys('alice', {});
        }],
        ['drop-previous-person-keys', function () {
          return keys.dropPreviousPersonKeys('alice', {});
        }],
        ['drop-previous-service-keys', function () {
          return keys.dropPreviousServiceKeys('HTTP/web.krr.test', {});
        }]
      ];
      acts.forEach(function (pair) {
        const result = pair[1]();
        t.check(result && result.ok === false &&
                errorCodes.codeOf(result) === 'STS-KRB-0128',
                pair[0] + ' is REFUSED in a realm with no KDC — it used to ' +
                'succeed emptily, storing a key under a principal whose ' +
                'realm name is the empty string',
                JSON.stringify({ ok: result && result.ok,
                                 code: errorCodes.codeOf(result) }));
      });
      t.equal(principals.REALM, '',
              'and the realm has no Kerberos realm name at all, which is ' +
              'what those acts would have built a principal from');
    });
  } finally {
    realms.remove('krr-nokdc');
  }

  // A RENAME THROUGH THE SUPPORTED PATH leaves nothing behind.
  await withKerberosRealm(t, 'krr-rename', ACME, function (realm) {
    realms.run(realm, function () {
      // A runtime-made principal: somebody authenticates as a name nobody
      // configured, which is what findOrCreateUser() is for.
      const made = principals.findOrCreateUser(['someone-new'], ACME);
      t.check(!!made && made.autoCreated,
              'a principal made at runtime is in the realm\'s partition');
    });
    realms.setOverride('krr-rename', 'krb5.enabled', 'false');
    realms.setOverride('krr-rename', 'krb5.realm', BETA);
    realms.setOverride('krr-rename', 'krb5.enabled', 'true');
    realms.run(realm, function () {
      t.equal(principals.REALM, BETA, 'the realm answers under its new name');
      const left = principals.all().filter(function (one) {
        return String(one.realm) !== BETA;
      });
      t.equal(left.length, 0,
              'AND NOTHING IS LEFT UNDER THE OLD ONE — a runtime-made ' +
              'principal keyed `name@OLD.REALM` can never be reached again ' +
              'and would sit in the partition for ever',
              JSON.stringify(left.map(function (one) {
                return one.name.join('/') + '@' + one.realm;
              })));
    });
  });
  log.debug("Leaving theRealmWithNoKdc().");
}

// ---------------------------------------------------------------------------
// E. A RESTORED ROW FOR A REALM WHOSE DATABASE IS NOT BUILT YET. The
// reconciler is handed what the partition held when the row arrived, which for
// such a realm is nothing — and then it BUILDS the database, registering the
// very principal the row is for. Reading the argument rather than the partition
// again therefore dropped the row's runtime state on the FIRST restored row of
// every non-default realm: a sign-out stamped on that realm's krbtgt did not
// survive a restart. `kerberos_principal_store.js` covers the rule itself; this
// is the ordering only a second realm can show.
// ---------------------------------------------------------------------------
function theRestoreOrdering(t) {
  log.debug("Entering theRestoreOrdering().");
  t.log.info('=== E. a restore that has to build the realm first ===');
  const handle = realms.handleFor('krb5.principals');
  if (!t.check(!!handle && typeof handle.restore === 'function',
               'krb5.principals has a restore accessor')) {
    log.debug("Leaving theRestoreOrdering().");
    return;
  }
  const NAME = 'RESTORE.EXAMPLE.COM';
  const key = 'krbtgt/' + NAME + '@' + NAME;
  const spec = { id: 'krr-restore', name: 'krr-restore',
                 description: 'Created by ' + __filename,
                 overrides: { 'krb5.realm': NAME, 'krb5.enabled': 'true' } };
  const first = realms.create(spec);
  if (!t.check(first.ok, 'a realm with Kerberos on is created',
               (first.errors || []).join(' '))) {
    log.debug("Leaving theRestoreOrdering().");
    return;
  }
  // The row a previous run would have written down: that realm's krbtgt,
  // signed out, through JSON exactly as a stored row has been.
  const stored = realms.run(first.realm, function () {
    return JSON.parse(JSON.stringify(Object.assign(
      {}, principals.find(['krbtgt', NAME], NAME),
      { signedOutAt: '2026-02-03T04:05:06.000Z' })));
  });
  t.check(stored && stored.realm === NAME,
          'and its krbtgt is a configured principal of that realm');
  // Forget everything this process built for it, which is the state a RESTART
  // is in when the store hands that row back.
  realms.remove('krr-restore');
  const again = realms.create(spec);
  if (!again.ok) {
    t.bad('the realm could not be defined again',
          (again.errors || []).join(' '));
    log.debug("Leaving theRestoreOrdering().");
    return;
  }
  try {
    handle.restore('krr-restore', key, stored);
    const back = realms.run(again.realm, function () {
      return principals.signedOutAt(['krbtgt', NAME], NAME);
    });
    t.equal(back && back.toISOString(), '2026-02-03T04:05:06.000Z',
            'THE SIGN-OUT SURVIVED — the reconciler read the record again ' +
            'after building the realm\'s database, rather than the empty ' +
            'partition it was handed on the way in');
  } finally {
    realms.remove('krr-restore');
  }
  log.debug("Leaving theRestoreOrdering().");
}

module.exports = {
  name: 'kerberos_realm_routing',
  describe: 'a KDC per trust realm on the shared port 88: the setting rules, ' +
            'each realm\'s own principal database, and which realm answers',
  run: async function (t) {
    log.debug("Entering run().");
    await theSettingRules(t);
    await theDatabase(t);
    await theRouting(t);
    await theRealmWithNoKdc(t);
    theRestoreOrdering(t);
    log.debug("Leaving run().");
  }
};
