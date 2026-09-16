'use strict';
//
// File: realm_isolation.js
//
// ===========================================================================
// A REALM'S IDENTITY REGISTER AND ITS REVOCATION SET ARE ITS OWN.
//
// Both were process-wide until 2026-08-25, both were process-wide ON PURPOSE,
// and the purpose stopped being true the day the embedded directory became a
// SUBTREE PER REALM (`ldap/CLAUDE.md`). The argument, in `admin_stats.js`'s own
// words, was that "the identity register mirrors the embedded directory, which
// is shared by every realm" — correct when it was written, and a leak the
// moment the second half of it stopped holding.
//
// What it produced was not an error anywhere. `/admin/users` under
// `/realm/acme` listed everybody who had ever signed in to the DEFAULT realm,
// and the realm's own directory reader then reported each of those people's
// entries as missing — because in that realm they genuinely were. Two pages of
// one console disagreeing, each of them sure. And on the metrics page one
// realm's `tokens.revoked` appeared under every realm, beside a `tokens.held`
// that was correctly partitioned.
//
// The revocation set had a second edge that is a REFUSAL rather than a
// disagreement: `POST /realm/acme/oauth2/revoke` could kill a jti issued by the
// default realm, which is a cross-realm write in the one protocol family whose
// realm support is published as `full`.
//
// WHY THIS IS HERE AND NOT IN THE PARENT PROJECT'S SUITE. The rule in
// tests/CLAUDE.md is "can it be asserted by driving the running service over
// HTTP?", and the leak itself can — two sign-ins and two `?format=json` reads
// show it. Three things put this file here anyway:
//
//   * The parent project's `sts/` gitlink is pinned at a commit from before
//     this repository was reorganised, so a guard written over there today
//     does not run against this code at all. See the root CLAUDE.md.
//   * What is actually being guarded is a MODULE CONTRACT — "a store that
//     holds per-realm state is declared `realms.map()` and not `new Map()`" —
//     and the assertions below are about that declaration rather than about
//     any endpoint. The two stores are reached directly; no route, no port.
//   * The purge case at the end is invisible over HTTP: it asserts that
//     removing a realm takes its register with it, and an HTTP caller cannot
//     tell "purged" from "a realm that never had anything".
//
// If a THIRD store is ever found to have been left process-wide for the same
// retired reason, it belongs in this file rather than in one of its own.
//
// ---------------------------------------------------------------------------
// THE THIRD ONE TURNED UP ON 2026-09-06 AND IS THE SCIM COUNTERS.
//
// `admin_stats.js`'s `scimCounts` was a plain object beside a file in which
// every other store — the endpoint calls, the token registry, the artifact
// list, the identity register, the revocation set, the claim sets — is
// `realms.map()`, `realms.arr()` or `realms.obj()`. Same shape of leak and the
// same retired reason: `/scim/v2` is realm-prefixed like every other endpoint
// here and writes into a directory that has been a SUBTREE PER REALM since
// 2026-08-25, so a provisioning client working in `/realm/acme` created
// entries in acme and was counted in the default realm's totals. One page
// reporting traffic that happened somewhere else, beside a directory count
// that was correctly partitioned — which is exactly what the register did.
//
// It surfaced when `/admin/scim/monitor` was written, because that page draws
// the counters and the directory side by side and the disagreement stops being
// something a reader has to notice across two tabs.
//
// What is asserted here is the DECLARATION, as it is for the other two: a
// store that holds per-realm state is `realms.obj()` and not `{}`. The
// counters' own contract — a refused caller is not a client, an absent
// measurement is null, a counter cannot throw — is `tests/scim_monitor.js`.
//
// ---------------------------------------------------------------------------
// AND SEVEN MORE ON 2026-09-12, FROM A SWEEP RATHER THAN A PAGE.
//
// The CAEP and RISC registers, `vc_offers.js`'s deferred access tokens,
// `spiffe_auth.js`'s recorded connections, `scim_auth.js`'s Digest nonces and
// HOBA stores, and `federation.js`'s release index — `common/CLAUDE.md` has the
// table of what each leaked. Sections 5b and 5c below. Two of them are asserted
// in a CHILD PROCESS, because their modules register routes (or require one
// that does) and this file shares one process with every other; and the CAEP
// and RISC registers' in-place edits are asserted against a real persistence
// observer there too, because that observer cannot be put back in this one.
// The OpenID4VCI request-encryption key, which became per realm the same day,
// has a file of its own — `tests/vci_request_encryption_key.js` — because what
// it asserts is the KEY SET's machinery and not a store's declaration.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: a
// developer with CONFIG_FILE exported would otherwise be asserting against
// their own appconfig rather than against the service as it ships.
delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const stats = require('../common/admin_stats');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'realm_isolation',
  level: process.env.LOG_LEVEL || 'info' });

// ---------------------------------------------------------------------------
// Create a realm, hand it to `fn`, and remove it however that goes. The realm
// table is process-wide, so a realm left
// behind changes what a later test in the same run resolves. Same shape as
// config_realm_layer.js's, deliberately — two spellings of "clean up after
// yourself" is how one of them comes to be the one nobody follows.
// ---------------------------------------------------------------------------
function withRealm(t, id, fn) {
  log.debug("Entering withRealm().");
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
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

// Every identity the register lists in whatever realm is ambient when this is
// called. `userRows()` is what `/admin/users` and `/admin/metrics` are both
// built from, so asserting on it is asserting on both pages at once.
function keysHere() {
  log.debug("Entering keysHere().");
  log.debug("Leaving keysHere().");
  return stats.userRows().map(function (row) { return row.key; });
}

function has(list, key) {
  log.debug("Entering has().");
  log.debug("Leaving has().");
  return list.indexOf(key) >= 0;
}

// ---------------------------------------------------------------------------
// 1. THE IDENTITY REGISTER.
//
// Recorded in a realm, invisible outside it; recorded outside, invisible in it.
// Both directions are asserted because the store is one Map per realm and a
// half-done conversion — say, writing through the facade and reading a stale
// module-level binding — would pass one of them.
// ---------------------------------------------------------------------------
function checkRegister(t) {
  log.debug("Entering checkRegister().");
  t.log.info('the identity register — who a realm has SEEN');

  const before = keysHere();
  t.check(!has(before, 'iso-inside') && !has(before, 'iso-outside'),
          'the default realm starts without either of this test\'s names',
          before.join(', ') || '(nobody)');

  withRealm(t, 'iso-register', function (realm) {
    realms.run(realm, function () {
      stats.recordAuthentication({ protocol: 'Test', method: 'in process',
                                   presented: 'iso-inside' });
    });
    stats.recordAuthentication({ protocol: 'Test', method: 'in process',
                                 presented: 'iso-outside' });

    const inside = realms.run(realm, keysHere);
    const outside = keysHere();

    t.check(has(inside, 'iso-inside'),
            'the realm lists the person who authenticated in it',
            inside.join(', ') || '(nobody)');
    t.check(!has(inside, 'iso-outside'),
            'and does NOT list the person who authenticated in the default ' +
            'realm',
            inside.join(', ') || '(nobody)');
    t.check(has(outside, 'iso-outside'),
            'the default realm lists its own person',
            outside.join(', ') || '(nobody)');
    t.check(!has(outside, 'iso-inside'),
            'and does NOT list the realm\'s',
            outside.join(', ') || '(nobody)');

    // The number the metrics page prints, from the same rows. Asserted
    // separately because it is read from `snapshot()` rather than from
    // `userRows()`, and a partition that reached one and not the other is
    // exactly the kind of half-fix that reads as working.
    const insideKnown = realms.run(realm, function () {
      return stats.snapshot().users.known;
    });
    t.equal(insideKnown, inside.length,
            'the realm\'s metrics count agrees with the realm\'s list');
  });
  log.debug("Leaving checkRegister().");
}

// ---------------------------------------------------------------------------
// 2. ONE NAME, TWO REALMS, TWO PEOPLE.
//
// The register is keyed on the local name and this service checks no password,
// so `alice` in two realms is two entries in two directory subtrees. The
// counts have to be separate as well as the rows: a shared record found by key
// would pass the row assertions above and still show one realm the other's
// authentication count.
// ---------------------------------------------------------------------------
function checkSameName(t) {
  log.debug("Entering checkSameName().");
  t.log.info('one name in two realms');

  withRealm(t, 'iso-samename', function (realm) {
    stats.recordAuthentication({ protocol: 'Test', method: 'in process',
                                 presented: 'iso-shared' });
    stats.recordAuthentication({ protocol: 'Test', method: 'in process',
                                 presented: 'iso-shared' });
    realms.run(realm, function () {
      stats.recordAuthentication({ protocol: 'Test', method: 'in process',
                                   presented: 'iso-shared' });
    });

    // `userDetail()` answers { user, tokens, artifacts } — the row is inside
    // it, and reading `.authentications` off the wrapper gives `undefined`,
    // which `equal()` reports honestly and which is how this line came to be
    // written twice.
    const outside = stats.userDetail('iso-shared');
    const inside = realms.run(realm, function () {
      return stats.userDetail('iso-shared');
    });

    t.check(!!outside && !!inside,
            'both realms know somebody by that name',
            'default=' + !!outside + ', realm=' + !!inside);
    if (outside && inside) {
      t.equal(outside.user.authentications, 2,
              'the default realm counted its own two authentications');
      t.equal(inside.user.authentications, 1,
              'and the realm counted its own one');
    }
  });
  log.debug("Leaving checkSameName().");
}

// ---------------------------------------------------------------------------
// 3. THE REVOCATION SET.
//
// A jti is unique across realms, so nothing legitimate ever crossed this line
// and every assertion below was true before the partition EXCEPT the negative
// one — which is the whole point, and the reason the negative is written
// first.
// ---------------------------------------------------------------------------
function checkRevocation(t) {
  log.debug("Entering checkRevocation().");
  t.log.info('the revocation set');

  withRealm(t, 'iso-revoke', function (realm) {
    const jti = 'iso-jti-' + Date.now();
    realms.run(realm, function () { stats.revoke(jti, 'this test'); });

    t.check(!stats.isRevoked(jti),
            'a jti revoked inside a realm is NOT revoked in the default realm',
            jti);
    t.check(realms.run(realm, function () { return stats.isRevoked(jti); }),
            'and IS revoked inside the realm that revoked it',
            jti);

    // The count beside `tokens.held` on the metrics page.
    const outsideCount = stats.revokedCount();
    const insideCount = realms.run(realm, function () {
      return stats.revokedCount();
    });
    t.check(insideCount > outsideCount,
            'the realm\'s revocation count is its own',
            'realm=' + insideCount + ', default=' + outsideCount);

    // Restoring is per realm too, and it is worth its own line: `restore()`
    // deletes from the set and clears a flag on the token record, and a
    // partition that reached the set and not the lookup would leave a jti
    // reported revoked after it had been restored.
    realms.run(realm, function () { stats.restore(jti); });
    t.check(!realms.run(realm, function () { return stats.isRevoked(jti); }),
            'restoring inside the realm un-revokes it there', jti);
  });
  log.debug("Leaving checkRevocation().");
}

// ---------------------------------------------------------------------------
// 4. REMOVING A REALM TAKES ITS REGISTER WITH IT.
//
// `realms.map()` registers a purge; a plain Map cannot. This is the assertion
// no HTTP caller could make — after the realm is gone its pages are gone too,
// so "purged" and "never existed" look identical from outside. In process the
// id can be created a second time and asked what it remembers, which must be
// nothing.
// ---------------------------------------------------------------------------
function checkPurge(t) {
  log.debug("Entering checkPurge().");
  t.log.info('removing a realm');

  withRealm(t, 'iso-purge', function (realm) {
    realms.run(realm, function () {
      stats.recordAuthentication({ protocol: 'Test', method: 'in process',
                                   presented: 'iso-ghost' });
      stats.revoke('iso-ghost-jti', 'this test');
    });
    const seen = realms.run(realm, keysHere);
    t.check(has(seen, 'iso-ghost'), 'the realm has somebody to forget',
            seen.join(', ') || '(nobody)');
  });

  // Same id, second life. `withRealm` above removed the first one.
  withRealm(t, 'iso-purge', function (realm) {
    const seen = realms.run(realm, keysHere);
    t.check(!has(seen, 'iso-ghost'),
            'a realm created again with the same id remembers none of the ' +
            'first one\'s people',
            seen.join(', ') || '(nobody)');
    t.check(!realms.run(realm, function () {
              return stats.isRevoked('iso-ghost-jti');
            }),
            'and none of its revocations', 'iso-ghost-jti');
  });
  log.debug("Leaving checkPurge().");
}

// ---------------------------------------------------------------------------
// 5. THE SCIM COUNTERS. The third store, added 2026-09-06.
//
// Two directions, because a store that is per realm in one direction only is
// the leak with extra steps: what happens inside a realm must not be visible
// outside it, and what happened outside must not appear inside. The register
// above is asserted both ways for the same reason.
// ---------------------------------------------------------------------------
function checkScimCounters(t) {
  log.debug("Entering checkScimCounters().");
  t.log.info('the SCIM traffic counters');

  // A known state to measure from. This is the counters' own reset — there is
  // deliberately no console control that calls it — and it clears THIS
  // REALM'S, which is the whole property under test.
  stats.resetScimForTests();
  stats.recordScim({ operation: 'create', resourceType: 'User', status: 201,
                     ok: true, authScheme: 'basic', principal: 'iso-outside',
                     ms: 1, bytes: 1 });
  const outsideBefore = stats.scimMonitorSnapshot();
  t.equal(outsideBefore.calls, 1,
          'the default realm has taken one SCIM call');

  withRealm(t, 'iso-scim', function (realm) {
    const inside = realms.run(realm, function () {
      stats.recordScim({ operation: 'delete', resourceType: 'Group',
                         status: 204, ok: true, authScheme: 'bearer',
                         principal: 'iso-inside', isClient: true,
                         ms: 2, bytes: 2 });
      return stats.scimMonitorSnapshot();
    });

    t.equal(inside.calls, 1,
            'THE REALM COUNTS ITS OWN CALL AND NOT THE ONE OUTSIDE IT. This ' +
            'was 2 until the counters were declared realms.obj(), which is ' +
            'the whole of the leak: a client provisioning under /realm/acme ' +
            'was counted in the default realm\'s totals, beside a directory ' +
            'count that was correctly partitioned');
    t.equal(inside.realm.id, 'iso-scim',
            'and the snapshot says which realm it is for, so a reader cannot ' +
            'mistake one for the other');
    t.check(inside.clients.length === 1 &&
            inside.clients[0].principal === 'iso-inside',
            'the client list is the realm\'s own too — the register above ' +
            'leaked in exactly this way, and a client table is the same kind ' +
            'of claim about who has been here',
            'clients: ' + inside.clients.map(function (row) {
              return row.principal;
            }).join(', '));

    const outsideAfter = stats.scimMonitorSnapshot();
    t.equal(outsideAfter.calls, 1,
            'AND THE OTHER DIRECTION: the realm\'s call did not appear in ' +
            'the default realm either. A store that partitions one way only ' +
            'is the leak with extra steps');
    t.check(!outsideAfter.clients.some(function (row) {
              return row.principal === 'iso-inside';
            }),
            'nor did its client', 'iso-inside');
  });

  // A removed realm takes its counters with it, which is what `realms.obj()`
  // means and is the case an HTTP caller cannot see: "purged" and "a realm
  // that never had any traffic" answer identically from outside.
  const ghost = realms.create({ id: 'iso-scim-ghost', name: 'iso-scim-ghost',
                                description: 'Created by ' + __filename });
  if (ghost.ok) {
    realms.run(ghost.realm, function () {
      stats.recordScim({ operation: 'list', resourceType: 'User', status: 200,
                         ok: true, authScheme: 'basic', principal: 'iso-ghost',
                         ms: 1, bytes: 1 });
    });
    realms.remove('iso-scim-ghost');
    const remade = realms.create({ id: 'iso-scim-ghost',
                                   name: 'iso-scim-ghost',
                                   description: 'Created by ' + __filename });
    if (remade.ok) {
      const back = realms.run(remade.realm, function () {
        return stats.scimMonitorSnapshot();
      });
      t.equal(back.calls, 0,
              'a realm removed and remade has none of the old one\'s ' +
              'traffic — the counters went with it');
      realms.remove('iso-scim-ghost');
    } else {
      t.bad('the throwaway realm could not be remade',
            (remade.errors || []).join(' '));
    }
  } else {
    t.bad('the throwaway realm could not be created',
          (ghost.errors || []).join(' '));
  }

  // Left as it was found, so that a later file in the same run is not looking
  // at this one's traffic.
  stats.resetScimForTests();
  log.debug("Leaving checkScimCounters().");
}

// ---------------------------------------------------------------------------
// 5b. THE CAEP AND RISC REGISTERS (2026-09-12).
//
// Both were `new Map()` beside `ssf_streams.js`'s streams, which have been per
// realm since the day SSF arrived — so a stream agreed in `acme` counted its
// events against a session row every realm's console listed, and deleting
// `alice` in `acme` put a `purged` row on the DEFAULT realm's
// /admin/risc-accounts beside a directory that still held its own `alice`.
// Same retired reason as the three above: the directory and the session store
// are per realm, and a register ABOUT them was not.
//
// Both ways round and across a purge, for the header's reason, plus the
// DECLARATION: each is a persisted store with a realm in it, because product
// mode writes down the sessions and accounts these rows describe.
// ---------------------------------------------------------------------------
function checkSignalRegisters(t) {
  log.debug("Entering checkSignalRegisters().");
  t.log.info('the CAEP and RISC registers');
  const caep = require('../ssf/caep');
  const risc = require('../ssf/risc');

  [['caep', caep, 'iso-session', 'caep.register'],
   ['risc', risc, 'iso-account', 'risc.register']].forEach(function (spec) {
    const label = spec[0];
    const register = spec[1];
    const key = spec[2];
    const handle = realms.handleFor(spec[3]);
    t.check(!!handle && handle.scope === 'realm' && handle.merge === 'replace',
            label + '\'s register is DECLARED as a persisted store with a ' +
            'realm in it, merged by replacement — a row is whole-valued',
            handle ? handle.scope + '/' + handle.merge : '(not declared)');

    withRealm(t, 'iso-' + label, function (realm) {
      realms.run(realm, function () {
        register.rowFor(key, { iss: 'https://iso.example' });
      });
      t.check(!!realms.run(realm, function () { return register.get(key); }),
              label + ': a row made in a realm is there in that realm');
      t.equal(register.get(key), null,
              label.toUpperCase() + ': AND IS NOT IN THE DEFAULT REALM. It ' +
              'was, while the register was one Map for the process');
      register.rowFor(key + '-outside', {});
      t.equal(realms.run(realm,
                         function () {
                           return register.get(key + '-outside');
                         }),
              null,
              label + ': and a row made outside the realm is not inside it');

      // The edit-in-place half — that `touch()` REPORTS a row mutated where it
      // stands — is asserted in the child process below, because it needs a
      // persistence observer and `realms.setPersistObserver()` has no way to
      // put back the one another file in this run may have installed.
      register.clear();
    });

    // Same id, second life.
    withRealm(t, 'iso-' + label, function (realm) {
      t.equal(realms.run(realm, function () { return register.get(key); }),
              null,
              label + ': a realm removed and created again has none of the ' +
              'old one\'s rows');
    });
  });
  log.debug("Leaving checkSignalRegisters().");
}

// ---------------------------------------------------------------------------
// 5c. THE STORES WHOSE MODULES CANNOT BE LOADED IN THIS PROCESS (2026-09-12).
//
// `oid4vc/vc_offers.js` registers the offer pages and `spiffe/spiffe_auth.js`
// requires `tls/tls_server.js`, which registers `/tls*` — and `run.js` runs
// every file in ONE process, where a route registered here moves what a later
// file sees of the router. So they are asserted in a CHILD PROCESS, which is
// `tests/oauth_oid4vc_hardcoded.js`'s arrangement for the same reason.
//
//   * `vc_offers.deferredAccessTokens` was a `new Set()` beside four
//     `realms.map()`s: a deferred token minted in one realm was deferred in
//     every realm, and on one worker only.
//   * `spiffe_auth.js`'s recorded connections were `sharedMap()` while SPIFFE
//     had one pair of sockets. It has a pair PER REALM, and the realm a gRPC
//     connection is in is the realm of the LISTENER it arrived on, which
//     `spiffe_server.js` makes ambient around every handler — so the child
//     enters a realm the way that wrapper does and records a caller there.
//
// Three more are asserted as DECLARATIONS, because their modules export no
// reader and a behavioural probe would need a directory, a Digest client or a
// federation relationship to reach them: `scim_auth.js`'s Digest nonces and
// HOBA challenge and replay sets, and `federation.js`'s release index.
// ---------------------------------------------------------------------------
function childStores() {
  const OUT = process.env.ISO_CHILD_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  try {
    delete process.env.CONFIG_FILE;
    const ROOT = process.env.ISO_CHILD_ROOT;
    const realms = require(ROOT + '/common/realms');
    const offers = require(ROOT + '/oid4vc/vc_offers');
    const auth = require(ROOT + '/spiffe/spiffe_auth');

    const a = realms.create({ id: 'iso-child-a', name: 'a' }).realm;
    const b = realms.create({ id: 'iso-child-b', name: 'b' }).realm;

    // THE DEFERRED ACCESS TOKENS.
    const tokens = offers.deferredAccessTokens;
    realms.run(a, function () { tokens.add('iso-deferred-token'); });
    note(realms.run(a,
                    function () { return tokens.has('iso-deferred-token'); }),
         'vc_offers: a deferred access token recorded in a realm is deferred ' +
         'there');
    note(!tokens.has('iso-deferred-token') &&
         !realms.run(b,
                     function () { return tokens.has('iso-deferred-token'); }),
         'VC_OFFERS: AND IS AN ORDINARY TOKEN IN THE DEFAULT REALM AND IN ' +
         'ANOTHER — it was deferred everywhere while the store was one Set');
    const tokenHandle = realms.handleFor('vc_offers.deferredAccessTokens');
    note(tokenHandle && tokenHandle.scope === 'realm',
         'vc_offers: the store is declared persisted, with a realm in it',
         tokenHandle ? tokenHandle.scope : '(not declared)');
    const dumped = tokenHandle ? tokenHandle.dump(a.id) : [];
    note(dumped.length === 1 && dumped[0].key.indexOf('iso-deferred-token') < 0,
         'vc_offers: and what it holds is a DIGEST of the token, never the ' +
         'bearer credential ' +
         'itself',
         JSON.stringify(dumped.map(function (row) { return row.key; })));
    realms.remove('iso-child-a');
    const again = realms.create({ id: 'iso-child-a', name: 'a' }).realm;
    note(!realms.run(again,
                     function () { return tokens.has('iso-deferred-token'); }),
         'vc_offers: a realm removed and remade has none of the old one\'s ' +
         'tokens');

    // THE SPIRE SERVER API'S RECORDED CONNECTIONS.
    const caller = { authenticated: true,
                     spiffeId: 'spiffe://iso.example/agent',
                     peer: '10.9.8.7:40001', transport: 'tcp',
                     certificate: { fingerprintSha256: 'AA:BB:CC' },
                     entities: {} };
    const connKey = 'AA:BB:CC|10.9.8.7:40001';
    const connHandle = realms.handleFor('spiffe.recordedConnections');
    note(connHandle && connHandle.scope === 'realm',
         'spiffe_auth: the recorded-connection store is declared per realm ' +
         'and not `shared` any ' +
         'more', connHandle ? connHandle.scope : '(not ' +
             'declared)');
    realms.run(b, function () { auth.recordCaller(caller); });
    note(connHandle && connHandle.read(b.id, connKey).present,
         'spiffe_auth: a connection accepted on a realm\'s listener is ' +
         'recorded in THAT realm — the ambient realm spiffe_server.js enters ' +
         'around the handler');
    note(connHandle && !connHandle.read('', connKey).present &&
         !connHandle.read(again.id, connKey).present,
         'SPIFFE_AUTH: AND NOT IN THE DEFAULT REALM OR ANOTHER ONE, so one ' +
         'realm\'s connections neither count against nor evict another\'s');
    realms.remove('iso-child-b');
    const remadeB = realms.create({ id: 'iso-child-b', name: 'b' }).realm;
    note(connHandle && !connHandle.read(remadeB.id, connKey).present,
         'spiffe_auth: and removing the realm takes its connections with it');

    // AN EDIT IN PLACE REACHES THE JOURNAL, in the realm it was made in. The
    // CAEP and RISC state machines mutate a row object already in the map, and
    // `realms.map()` journals only a `set()` — so without `touch()` product
    // mode would write a row as it was CREATED and a restart would put back a
    // session that was never revoked. A child process because this needs an
    // observer, and the one in the parent run cannot be put back.
    const journal = [];
    realms.setPersistObserver(function (handle, realmId, key) {
      journal.push([handle, realmId, key]);
    });
    const caep = require(ROOT + '/ssf/caep');
    const risc = require(ROOT + '/ssf/risc');
    [['caep.register', caep, 'iso-journal-session',
      'https://schemas.openid.net/secevent/caep/event-type/session-revoked'],
     ['risc.register', risc, 'iso-journal-account',
      'https://schemas.openid.net/secevent/risc/event-type/account-disabled']
    ].forEach(function (spec) {
      realms.run(remadeB, function () { spec[1].rowFor(spec[2], {}); });
      journal.length = 0;
      realms.run(remadeB, function () {
        spec[1].applyToState(spec[1].get(spec[2]), spec[3], {});
      });
      note(journal.some(function (row) {
             return row[0] === spec[0] && row[1] === remadeB.id &&
                    row[2] === spec[2];
           }),
           spec[0] + ': a row edited IN PLACE by the state machine is ' +
           'reported to the journal, in the realm it was edited ' +
           'in', JSON.stringify(journal));
    });
  } catch (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function checkChildStores(t) {
  log.debug("Entering checkChildStores().");
  t.log.info('the stores asserted in a child process');
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const childProcess = require('child_process');
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-realm-iso-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, {
    ISO_CHILD_OUT: out, ISO_CHILD_ROOT: root, LOG_LEVEL: 'fatal' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childStores.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 120000,
      maxBuffer: 64 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in checkChildStores(): " + ((e && e.message) || e));
    // The child died before writing a report; said below with its status.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    t.log.debug('could not remove ' + out + ': ' + e.message);
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) { t.check(one.ok, one.what, one.detail); });
  }

  // THE THREE DECLARATIONS.
  const read = function (rel) {
    log.debug("Entering read().");
    log.debug("Leaving read().");
    return fs.readFileSync(path.join(root, rel), 'utf8');
  };
  const scim = read('scim/scim_auth.js');
  ['digestNonces', 'hobaChallenges', 'hobaSeen'].forEach(function (name) {
    t.check(new RegExp('^const ' + name + ' = realms\\.map\\(', 'm').test(
        scim) &&
            !new RegExp('^const ' + name + ' = new Map\\(', 'm').test(scim),
            'scim_auth: `' + name + '` is declared realms.map() — one ' +
            'realm\'s unauthenticated challenges no longer evict another ' +
            'realm\'s from a shared cap');
  });
  const federation = read('federation/federation.js');
  t.check(/^const releaseIndexes = realms\.keyed\(/m.test(federation) &&
          !/^let releaseIndex = /m.test(federation),
          'federation: the release index is realms.keyed() — it was built ' +
          'out of whichever realm issued the first token in its window and ' +
          'applied to every realm\'s tokens for the rest of it');
  log.debug("Leaving checkChildStores().");
}

// ---------------------------------------------------------------------------
// 5b-ii. KERBEROS'S THREE STORES (2026-09-15).
//
// They were `realms.sharedMap({ scope: 'shared' })` — declared shared ON
// PURPOSE, and this file's own rule was satisfied by the word: the KDC answered
// in no realm, so its principal database, the acceptor's replay cache and the
// SPNEGO negotiations it held were the process's. Each trust realm now has a
// KDC of its own, told apart by the Kerberos realm name, so all three are
// `realms.map()` and the DECLARATION is what says so.
//
// The declaration is what is checked, for the reason this file checks scim's
// and federation's that way: `handleFor()` reports the scope a store was
// declared with, and a store declared shared cannot be made per realm by any
// amount of care at its call sites. The BEHAVIOUR — a realm's principals are
// its own, a realm removed takes them with it — is
// `tests/kerberos_realm_routing.js`, which drives the KDC.
// ---------------------------------------------------------------------------
function checkKerberosStores(t) {
  log.debug("Entering checkKerberosStores().");
  t.log.info('the Kerberos stores');
  // Required for their declarations rather than their behaviour, which is why
  // the two socket owners are loaded here and never started.
  require('../kerberos/krb5_principals.js');
  require('../kerberos/krb5_service.js');
  require('../kerberos/spnego_exchange.js');
  [['krb5.principals', 'the principal database'],
   ['krb5.replayCache', 'the acceptor\'s replay cache'],
   ['spnego.pending', 'the unfinished SPNEGO negotiations']].forEach(
      function (pair) {
    const handle = realms.handleFor(pair[0]);
    t.check(!!handle, pair[0] + ' is a declared store');
    if (handle) {
      t.equal(handle.scope, 'realm',
              pair[1] + ' (' + pair[0] + ') is declared PER REALM — it was ' +
              'scope: \'shared\' until each trust realm had a KDC of its own',
              String(handle.scope));
    }
  });
  log.debug("Leaving checkKerberosStores().");
}

// ---------------------------------------------------------------------------
// 5c. GNAP (2026-09-12): twelve stores in `gnap/gnap_store.js`, the approver
// index in `gnap/gnap_signals.js` and the counters in `gnap/gnap_monitor.js`.
//
// `tests/vendored/sts_gnap_core.js` asserts the over-HTTP half — a token from
// one realm refused by another realm's resource server, a continuation token
// that finds nothing in the default realm. What is here is the half that
// cannot be asked over HTTP: that a realm removed and created again under the
// same id remembers NONE of the first one's grants, tokens, resource sets,
// approvers or counts, and that no module in `gnap/` declares a process-wide
// Map or Set at module scope for the next store to be added as.
// ---------------------------------------------------------------------------
function checkGnapStores(t) {
  log.debug("Entering checkGnapStores().");
  t.log.info('the GNAP stores');
  const fs = require('fs');
  const path = require('path');
  const store = require('../gnap/gnap_store');
  const monitor = require('../gnap/gnap_monitor');
  const signals = require('../gnap/gnap_signals');
  const ids = {};

  withRealm(t, 'iso-gnap', function (realm) {
    realms.run(realm, function () {
      ids.grant =
          store.newGrant({ client: { identifier: 'iso-gnap-client' } }).id;
      store.putToken({ jti: 'iso-gnap-jti', grant: ids.grant },
                     'iso-gnap-token-value');
      store.putResource('iso-gnap-resource', { access: ['read'] });
      signals.noteApprover('iso-gnap-client', 'iso-gnap-person');
      monitor.record('iso-gnap-client', 'grant.requested', {});
    });
    t.check(!store.getGrant(ids.grant),
            'a GNAP grant made inside a realm is not in the default realm',
            ids.grant);
    t.check(!store.tokenByValue('iso-gnap-token-value'),
            'nor is its access token, looked up by value');
    t.check(!store.resourceByReference('iso-gnap-resource'),
            'nor a resource set registered there');
    t.check(!signals.approvedBy('iso-gnap-client', 'iso-gnap-person'),
            'nor who approved a grant to which application — the index a ' +
            'GNAP application\'s scoped stream is decided by');
    t.check(!monitor.snapshot().rows['iso-gnap-client'],
            'nor the monitor\'s counters');
    t.check(realms.run(realm, function () {
      return !!store.getGrant(ids.grant) &&
             !!store.tokenByValue('iso-gnap-token-value') &&
             !!store.resourceByReference('iso-gnap-resource') &&
             !!monitor.snapshot().rows['iso-gnap-client'];
    }), 'and every one of them IS there inside the realm that made it');
  });

  withRealm(t, 'iso-gnap', function (realm) {
    t.check(realms.run(realm, function () {
      return !store.getGrant(ids.grant) && !store.tokenByJti('iso-gnap-jti') &&
             !store.resourceByReference('iso-gnap-resource') &&
             !signals.approvedBy('iso-gnap-client', 'iso-gnap-person') &&
             !monitor.snapshot().rows['iso-gnap-client'];
    }), 'a realm created again under the same id remembers none of the first ' +
        'one\'s GNAP grants, tokens, resource sets, approvers or counts');
  });

  const dir = path.join(__dirname, '..', 'gnap');
  fs.readdirSync(dir)
    .filter(function (f) { return /\.js$/.test(f); })
    .forEach(function (file) {
    const src = fs.readFileSync(path.join(dir, file), 'utf8');
    t.check(!/^(const|let|var)\s+\w+\s*=\s*new (Map|Set)\(/m.test(src),
            'gnap/' + file + ' declares no module-scope Map or Set — a store ' +
            'there is realms.map(), or it is one realm\'s state in every ' +
            'realm');
  });
  log.debug("Leaving checkGnapStores().");
}

// ---------------------------------------------------------------------------
// 6. WITH NO REALM DEFINED, NOTHING ABOVE IS OBSERVABLE.
//
// The property the whole realm design rests on, asserted here for the two
// stores this file is about: in a service with no realms defined there is
// exactly one partition, so the register and the revocation set behave as the
// plain Map and Set they replaced. Every realm this file creates is removed by
// `withRealm`, which is what makes the assertion meaningful at this point in
// the run rather than merely true.
// ---------------------------------------------------------------------------
function checkDefaultUnchanged(t) {
  log.debug("Entering checkDefaultUnchanged().");
  t.log.info('a service with no realms defined');

  t.equal(realms.count(), 1,
          'this test cleaned up after itself — only the default realm is left');
  t.check(!realms.active(),
          'and with none defined the realm layer reports itself inactive');

  const jti = 'iso-plain-' + Date.now();
  stats.revoke(jti, 'this test');
  t.check(stats.isRevoked(jti),
          'a revocation in the default realm reads back in the default realm',
          jti);
  stats.restore(jti);

  stats.recordAuthentication({ protocol: 'Test', method: 'in process',
                               presented: 'iso-plain' });
  t.check(has(keysHere(), 'iso-plain'),
          'and an authentication in the default realm reads back there',
          'iso-plain');
  log.debug("Leaving checkDefaultUnchanged().");
}

function run(t) {
  log.debug("Entering run().");
  checkRegister(t);
  checkSameName(t);
  checkRevocation(t);
  checkPurge(t);
  checkScimCounters(t);
  checkSignalRegisters(t);
  checkKerberosStores(t);
  checkGnapStores(t);
  checkChildStores(t);
  checkDefaultUnchanged(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'realm_isolation',
  describe: 'a realm\'s identity register and revocation set are its own',
  run: run
};
