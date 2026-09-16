'use strict';
//
// File: cluster_limits_challenges_retention.js
//
// ===========================================================================
// ISSUE #46 SECTIONS 2, 5 AND 8, THE OPERATIONS HALF (2026-09-14): ONE RATE
// LIMIT BUDGET, SCIM AND SPNEGO STATE ANY NODE CAN ANSWER, WHO A REQUEST CAME
// FROM, AND A CHANGE LOG THAT IS TRIMMED.
//
//   A. RATE LIMITS. `websecurity.attemptShared()` against a stub store with
//      postgres's `countWindow` semantics (one row, one atomic increment)
//      refuses a burst of concurrent guesses at EXACTLY the limit however the
//      burst is split — and the CONTROL, a store that reads, waits and writes
//      back (what a replicated bucket row was), lets more than the limit
//      through, so the probe discriminates. No store: `attemptShared()` is
//      `attempt()`. A store that throws: this process's own buckets decide.
//   B. WHO A REQUEST CAME FROM. `common/client_address.js`: the old rule with
//      `global.trustedProxies` empty, a direct caller's header ignored and the
//      right-most untrusted hop taken with it set, and a request worker
//      believing what the front process wrote.
//   C. SCIM. The Digest nonces and HOBA challenges are persisted stores; a
//      nonce ANOTHER PROCESS issued (restored the way replication restores a
//      row) is answered here; a nonce count another node already spent is
//      refused (`STS-SCIM-0076`) where a fresh count is accepted; and a claim
//      store that cannot be asked refuses (`STS-SCIM-0078`).
//   D. SPNEGO. Two negotiations pending from ONE address — every client behind
//      a load balancer — coexist; a continuation with no cookie is matched by
//      the MIC to its own negotiation and leaves the other alone; one naming
//      its negotiation by cookie is matched by it and clears the cookie; a
//      guessed MIC deletes nothing; and a continuation another node already
//      completed is refused (`STS-KRB-0119`).
//   E. RETENTION. `persistence_replication.js` reports its low-water mark at
//      start, trims with the retention and reader lifetime it was configured
//      with, trims nothing when retention is off, says so when it finds
//      itself declared gone, and leaves at a clean stop. The driver's trim is
//      one statement holding both halves of the bound; its SEMANTICS were run
//      against a real postgres (cluster/CLAUDE.md records it), and what is
//      held here is that the statement still says both.
//   F. THE LDAP BIND, in product mode: synchronous with no shared store, as
//      `performOperation()`'s callers rely on; with one, the operation answers
//      a promise and the bind after the limit's failures is refused before its
//      password is read.
//
// IN A CHILD PROCESS: a persist observer and a stubbed `clusterStore()` are
// process-wide, and SCIM loads the directory, the session store and a CA.
//
// WHY IN PROCESS, tests/CLAUDE.md's first question: two nodes racing one row,
// or a replicated row that arrived before its own process issued it, cannot be
// arranged over HTTP against one service. The live two-node run is recorded in
// cluster/CLAUDE.md.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'cluster_limits_challenges_retention',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in the child. Stringified, so it may use nothing from this file.
function childMain() {
  const ROOT = process.env.CLCR_ROOT;
  const OUT = process.env.CLCR_OUT;
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function later(fn, failing) {
    return new Promise(function (resolve, reject) {
      setImmediate(function () {
        if (failing && failing()) {
          reject(new Error('connection refused'));
          return;
        }
        try {
          resolve(fn());
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  // A store with postgres's semantics for claims and windows: one row per
  // key, each statement atomic, every answer one macrotask later.
  function atomicStore() {
    const claims = new Map();
    const windows = new Map();
    const store = {
      failing: false,
      claimOnce: function (scope, realm, key, opts) {
        return later(function () {
          const k = scope + ' ' + realm + ' ' + key;
          const row = claims.get(k);
          if (row && row.expiresAt > Date.now()) {
            return { claimed: false, existing: { origin: 'node-b' } };
          }
          claims.set(k, { reservation: opts.reservation,
                          expiresAt: Date.now() + opts.ttlMs });
          return { claimed: true };
        }, function () { return store.failing; });
      },
      releaseClaim: function (scope, realm, key, reservation) {
        return later(function () {
          const k = scope + ' ' + realm + ' ' + key;
          const row = claims.get(k);
          if (row && row.reservation === reservation) {
            claims.delete(k);
            return true;
          }
          return false;
        }, function () { return store.failing; });
      },
      claimHeld: function (scope, realm, key) {
        return later(function () {
          const row = claims.get(scope + ' ' + realm + ' ' + key);
          return !!row && row.expiresAt > Date.now();
        }, function () { return store.failing; });
      },
      purgeClaims: function () {
        return later(function () { return 0; });
      },
      countWindow: function (scope, realm, key, windowMs) {
        return later(function () {
          const k = scope + ' ' + realm + ' ' + key;
          const now = Date.now();
          const row = windows.get(k);
          if (!row || row.endsAt <= now) {
            windows.set(k, { count: 1, endsAt: now + windowMs });
            return { count: 1, remainingMs: windowMs };
          }
          row.count += 1;
          return { count: row.count, remainingMs: row.endsAt - now };
        }, function () { return store.failing; });
      },
      peekWindow: function (scope, realm, key) {
        return later(function () {
          const row = windows.get(scope + ' ' + realm + ' ' + key);
          return row && row.endsAt > Date.now()
            ? { count: row.count, remainingMs: row.endsAt - Date.now() }
            : { count: 0, remainingMs: 0 };
        }, function () { return store.failing; });
      },
      clearWindow: function (scope, realm, key) {
        return later(function () {
          return windows.delete(scope + ' ' + realm + ' ' + key);
        }, function () { return store.failing; });
      },
      purgeWindows: function () {
        return later(function () { return 0; });
      }
    };
    return store;
  }

  // THE CONTROL: a window counted the way a replicated bucket row was —
  // read, a macrotask, write back what was read plus one.
  function lostUpdateStore() {
    const store = atomicStore();
    const windows = new Map();
    store.countWindow = function (scope, realm, key, windowMs) {
      const k = scope + ' ' + realm + ' ' + key;
      const read = windows.get(k) ||
        { count: 0, endsAt: Date.now() + windowMs };
      return later(function () {
        const written = { count: read.count + 1, endsAt: read.endsAt };
        windows.set(k, written);
        return { count: written.count, remainingMs: windowMs };
      });
    };
    return store;
  }

  function fromAddress(address, extra) {
    return Object.assign({ headers: {}, socket: { remoteAddress: address } },
                         extra || {});
  }

  (async function () {
    try {
      const realms = require(ROOT + '/common/realms');
      // THE JOURNAL, so the persisted stores are journalling views.
      const journal = [];
      realms.setPersistObserver(function (handle, realmId, key) {
        journal.push({ handle: handle, realm: realmId, key: key });
      });
      const config = require(ROOT + '/common/config');
      const persistence = require(ROOT + '/persistence/persistence');
      const claims = require(ROOT + '/cluster/cluster_claims');
      const counters = require(ROOT + '/cluster/cluster_counters');
      const websecurity = require(ROOT + '/common/websecurity');
      const clientAddress = require(ROOT + '/common/client_address');
      const realStore = persistence.clusterStore;

      // ================= A. RATE LIMITS =====================================
      websecurity.reset();
      const plain = [1, 2, 3, 4].map(function () {
        return websecurity.attempt('clcr-plain', fromAddress('192.0.2.1'),
                                   'pat', 3).ok;
      }).join(',');
      websecurity.reset();
      const viaShared = [];
      for (let i = 0; i < 4; i++) {
        viaShared.push((await websecurity.attemptShared('clcr-plain',
          fromAddress('192.0.2.1'), 'pat', 3)).ok);
      }
      note(viaShared.join(',') === plain && plain === 'true,true,true,false',
           'A1. with no shared store attemptShared() answers exactly what ' +
           'attempt() does', plain + ' / ' + viaShared.join(','));

      const atomic = atomicStore();
      persistence.clusterStore = function () { return atomic; };
      const LIMIT = 5;
      const burst = await Promise.all(Array.from({ length: 40 },
        function (_, i) {
          // Twenty "addresses" on two "nodes": the IDENTITY bucket is what a
          // guesser spreading over nodes and addresses has to get past.
          return websecurity.attemptShared('clcr-burst',
            fromAddress('198.51.100.' + (i % 20)), 'target-person',
            { identity: LIMIT, address: 1000 });
        }));
      const allowed = burst.filter(function (one) { return one.ok; }).length;
      note(allowed === LIMIT,
           'A2. FORTY CONCURRENT GUESSES AT ONE PERSON, SPREAD OVER TWENTY ' +
           'ADDRESSES, ARE ALLOWED EXACTLY THE LIMIT (' + LIMIT + ') — every ' +
           'count landed in one row', allowed + ' allowed');
      const refusedOne = burst.filter(function (one) { return !one.ok; })[0];
      const errorCodes = require(ROOT + '/common/error_codes');
      note(refusedOne && refusedOne.kind === 'identity' &&
           errorCodes.codeOf(refusedOne) === 'STS-HTTP-0017' &&
           refusedOne.retryAfterS >= 1,
           'and a refusal is the limiter\'s own, with its code and a wait',
           JSON.stringify(refusedOne));

      const lossy = lostUpdateStore();
      persistence.clusterStore = function () { return lossy; };
      const lossyBurst = await Promise.all(Array.from({ length: 40 },
        function (_, i) {
          return websecurity.attemptShared('clcr-burst-control',
            fromAddress('198.51.100.' + (i % 20)), 'target-person',
            { identity: LIMIT, address: 1000 });
        }));
      const lossyAllowed = lossyBurst.filter(function (one) {
        return one.ok;
      }).length;
      note(lossyAllowed > LIMIT,
           'A3. CONTROL: the same burst against a count that is read and ' +
           'written back — a replicated bucket row — lets more than the ' +
           'limit through, so A2 measures the store and not the burst',
           lossyAllowed + ' allowed');

      persistence.clusterStore = function () { return atomic; };
      const who = fromAddress('203.0.113.50');
      for (let i = 0; i < 3; i++) {
        await websecurity.attemptShared('clcr-bind', who, 'uid=x', 3);
      }
      const blockedNow = await websecurity.blockedShared('clcr-bind', who,
                                                         'uid=x', 3);
      note(blockedNow && blockedNow.ok === false,
           'A4. blockedShared() refuses at the limit without counting',
           JSON.stringify(blockedNow));
      await websecurity.succeededShared('clcr-bind', who, 'uid=x',
                                        { keepAddress: true });
      const afterSuccess = await websecurity.blockedShared('clcr-bind', who,
                                                           'uid=x', 3);
      const addressStill = await websecurity.blockedShared('clcr-bind', who,
                                                           'uid=other', 3);
      note(afterSuccess && afterSuccess.kind === 'address' &&
           addressStill && addressStill.kind === 'address',
           'and succeededShared() with keepAddress clears the identity ' +
           'bucket and leaves the address bucket counting',
           JSON.stringify([afterSuccess, addressStill]));

      atomic.failing = true;
      websecurity.reset();
      const fallback = [];
      for (let i = 0; i < 3; i++) {
        fallback.push((await websecurity.attemptShared('clcr-down',
          fromAddress('192.0.2.77'), 'fallen', 2)).ok);
      }
      atomic.failing = false;
      note(fallback.join(',') === 'true,true,false',
           'A5. A STORE THAT CANNOT BE ASKED LEAVES THIS PROCESS\'S OWN ' +
           'BUCKETS DECIDING — still a limit, per node for that window',
           fallback.join(','));

      // ================= B. WHO A REQUEST CAME FROM =========================
      const forwarded = function (peer, chain) {
        return fromAddress(peer, { headers: { 'x-forwarded-for': chain } });
      };
      config.setOverride('global.trustProxy', false);
      note(clientAddress.clientAddressOf(forwarded('10.0.0.5',
                                                   '1.2.3.4')) === '10.0.0.5',
           'B1. trustProxy off: the socket, whatever the header says');
      config.setOverride('global.trustProxy', true);
      note(clientAddress.clientAddressOf(forwarded('10.0.0.5',
             '6.6.6.6, 1.2.3.4')) === '6.6.6.6',
           'B2. trustProxy on, no ranges: the OLD rule exactly — the ' +
           'left-most entry');
      config.setOverride('global.trustedProxies', '10.0.0.0/8, fd00::/8');
      note(clientAddress.clientAddressOf(forwarded('192.0.2.9',
             '6.6.6.6')) === '192.0.2.9' &&
           !clientAddress.forwardedBelieved(forwarded('192.0.2.9', '6.6.6.6')),
           'B3. WITH RANGES, A CALLER THAT REACHED THE NODE DIRECTLY CANNOT ' +
           'CHOOSE ITS ADDRESS: its header is ignored, and not believed for ' +
           'the base URL either');
      note(clientAddress.clientAddressOf(forwarded('::ffff:10.1.1.1',
             '6.6.6.6, 203.0.113.7, 10.2.2.2')) === '203.0.113.7' &&
           clientAddress.forwardedBelieved(forwarded('10.1.1.1', 'x')),
           'B4. from a trusted proxy, the right-most hop that is not one — ' +
           'the client-written left end is ignored, and an IPv4-mapped peer ' +
           'matches its IPv4 range');
      config.setOverride('global.trustedProxies', 'not-a-range');
      note(clientAddress.clientAddressOf(forwarded('192.0.2.9',
             '6.6.6.6')) === '192.0.2.9',
           'B5. a value that is not a range is ignored, never widened into ' +
           '"trust everybody"');
      config.clearOverride('global.trustedProxies');
      config.clearOverride('global.trustProxy');

      // ================= C. SCIM ============================================
      const scimAuth = require(ROOT + '/scim/scim_auth');
      note(!!realms.handleFor('scim.digestNonces') &&
           !!realms.handleFor('scim.hobaChallenges'),
           'C1. the Digest nonces and HOBA challenges are declared persisted');
      persistence.clusterStore = function () { return atomic; };
      claims.reset();
      const realmName = String(config.value('scim.authRealm') || 'SCIM');
      const password = String(config.value('scim.digestPassword'));
      const sha = function (text) {
        return nodeCrypto.createHash('sha256').update(text).digest('hex');
      };
      const digestRequest = function (nonce, nc) {
        const uri = '/scim/v2/Users';
        const ha1 = sha('clcr-digest:' + realmName + ':' + password);
        const ha2 = sha('GET:' + uri);
        const response = sha(ha1 + ':' + nonce + ':' + nc + ':cn0nce:auth:' +
                             ha2);
        return { method: 'GET', originalUrl: uri, url: uri,
                 socket: { remoteAddress: '192.0.2.40' },
                 headers: { authorization: 'Digest username="clcr-digest", ' +
                   'realm="' + realmName + '", nonce="' + nonce + '", uri="' +
                   uri + '", algorithm=SHA-256, qop=auth, nc=' + nc +
                   ', cnonce="cn0nce", response="' + response + '"' } };
      };
      // A NONCE ANOTHER PROCESS ISSUED: never through this process's
      // issueDigestNonce(), put in the store the way replication restores a
      // row.
      const foreignNonce = nodeCrypto.randomBytes(18).toString('base64');
      realms.handleFor('scim.digestNonces').restore('', foreignNonce,
                                                    { at: Date.now() });
      const first = await scimAuth.authenticateSpent(
        digestRequest(foreignNonce, '00000001'), 'read');
      note(first.ok && first.scheme === 'digest',
           'C2. A DIGEST NONCE ANOTHER PROCESS ISSUED IS ANSWERED HERE — it ' +
           'was "not one this server issued", stale=true, before',
           JSON.stringify({ ok: first.ok, detail: first.detail }));
      // The count another node already accepted: its claim is in the store,
      // and this process's own memory has never seen it.
      await claims.claim({ scope: 'scim.digest-nonce-count',
                           value: foreignNonce + '\n00000002',
                           ttlMs: 60000 });
      const replayed = await scimAuth.authenticateSpent(
        digestRequest(foreignNonce, '00000002'), 'read');
      note(!replayed.ok && errorCodes.codeOf(replayed) === 'STS-SCIM-0076' &&
           replayed.status === 401,
           'C3. A NONCE COUNT ANOTHER NODE ALREADY ACCEPTED IS REFUSED AS A ' +
           'REPLAY (STS-SCIM-0076)', JSON.stringify(replayed));
      const fresh = await scimAuth.authenticateSpent(
        digestRequest(foreignNonce, '00000003'), 'read');
      note(fresh.ok,
           'and its control: the next count on the same nonce is accepted',
           JSON.stringify({ ok: fresh.ok, detail: fresh.detail }));
      atomic.failing = true;
      const blind = await scimAuth.authenticateSpent(
        digestRequest(foreignNonce, '00000004'), 'read');
      atomic.failing = false;
      note(!blind.ok && errorCodes.codeOf(blind) === 'STS-SCIM-0078',
           'C4. a claim store that cannot be asked refuses (fail closed)',
           JSON.stringify(blind));
      const challenges = scimAuth.challenges({ headers: {}, method: 'GET',
                                               originalUrl: '/scim/v2/Users' });
      note(journal.some(function (row) {
        return row.handle === 'scim.digestNonces';
      }) && journal.some(function (row) {
        return row.handle === 'scim.hobaChallenges';
      }),
           'C5. issuing a challenge JOURNALS the nonce and the HOBA ' +
           'challenge, so the read barrier carries them to whichever process ' +
           'the answer reaches', challenges.length + ' challenge(s)');

      // ================= D. SPNEGO ==========================================
      const exchange = require(ROOT + '/kerberos/spnego_exchange.js');
      const spnego = require(ROOT + '/kerberos/krb5_spnego.js');
      const prim = require(ROOT + '/kerberos/krb5_primitives.js');
      const pendingHandle = realms.handleFor('spnego.pending');
      const DOOR = '/spnego/protected';
      const BALANCER = '10.9.9.9';
      const negotiation = function (client) {
        return { id: nodeCrypto.randomBytes(18).toString('base64url'),
                 key: new Uint8Array(nodeCrypto.randomBytes(32)),
                 mechListDer: new Uint8Array(nodeCrypto.randomBytes(24)),
                 client: client };
      };
      const pend = function (n) {
        pendingHandle.restore('', DOOR + '|' + n.id, {
          at: Date.now(), id: n.id, door: DOOR, address: BALANCER,
          mechListDer: prim.toHex(n.mechListDer),
          selected: spnego.KRB5_MECH_OID,
          initiatorKey: { etype: 18, key: prim.toHex(n.key) },
          acceptorSubkey: null, client: n.client, ticketFlags: [] });
      };
      const continuationFor = async function (n, cookie, garbage) {
        const mic = garbage ? new Uint8Array(nodeCrypto.randomBytes(28))
          : await spnego.computeMechListMic({ key: n.key, etype: 18,
              role: 'initiator', mechListDer: n.mechListDer,
              sequenceNumber: 0 });
        const headers = { authorization: 'Negotiate ' + Buffer.from(
          spnego.encodeNegTokenResp({ mechListMic: mic })).toString('base64') };
        if (cookie) {
          headers.cookie = 'other=1; sts_spnego_negotiation=' + cookie;
        }
        return { headers: headers, ip: BALANCER,
                 connection: { remoteAddress: BALANCER },
                 get: function (name) {
                   return headers[String(name).toLowerCase()];
                 } };
      };
      const alice = negotiation('alice@EXAMPLE.COM');
      const bob = negotiation('bob@EXAMPLE.COM');
      pend(alice);
      pend(bob);
      const present = function (n) {
        return pendingHandle.read('', DOOR + '|' + n.id).present;
      };
      note(present(alice) && present(bob),
           'D1. TWO NEGOTIATIONS PENDING FROM ONE ADDRESS COEXIST — behind a ' +
           'load balancer that address is everybody\'s, and they were one key');
      const guessed = await exchange.negotiate(
        await continuationFor(alice, null, true), { door: DOOR });
      note(guessed.code === 'bad-mech-list-mic' && present(alice) &&
           present(bob),
           'D2. a continuation whose MIC fits no negotiation is refused and ' +
           'DELETES NONE — the address key let one bad token spend somebody ' +
           'else\'s', guessed.code);
      const bobDone = await exchange.negotiate(
        await continuationFor(bob, null, false), { door: DOOR });
      note(bobDone.ok && bobDone.client === 'bob@EXAMPLE.COM' &&
           !present(bob) && present(alice),
           'D3. WITH NO COOKIE THE MIC MATCHES ITS OWN NEGOTIATION: bob is ' +
           'accepted as bob, and alice\'s is untouched',
           JSON.stringify({ code: bobDone.code, client: bobDone.client }));
      const aliceDone = await exchange.negotiate(
        await continuationFor(alice, alice.id, false), { door: DOOR });
      const cookies = [];
      const fakeRes = { req: { secure: true },
        set: function () {}, status: function () {},
        append: function (name, value) { cookies.push(value); } };
      exchange.applyVerdict(fakeRes, aliceDone);
      note(aliceDone.ok && aliceDone.client === 'alice@EXAMPLE.COM' &&
           !present(alice) &&
           /^sts_spnego_negotiation=; .*Max-Age=0/.test(cookies[0] || ''),
           'D4. a continuation naming its negotiation by cookie is matched ' +
           'by it, and the answer clears the cookie',
           JSON.stringify({ code: aliceDone.code, cookies: cookies }));
      const carol = negotiation('carol@EXAMPLE.COM');
      pend(carol);
      // No `realm`, so the claim lands in the AMBIENT realm — which is what
      // the real continuation does since SPNEGO became per trust realm
      // (2026-09-15). It read `realm: ''` while the store was shared, and a
      // claim in a realm nothing claims in would no longer collide with it.
      await claims.claim({ scope: 'spnego.continuation', value: carol.id,
                           ttlMs: 60000 });
      const carolAgain = await exchange.negotiate(
        await continuationFor(carol, carol.id, false), { door: DOOR });
      note(!carolAgain.ok && carolAgain.code === 'no-pending-continuation' &&
           carolAgain.errorCode === 'STS-KRB-0119',
           'D5. A CONTINUATION ANOTHER NODE ALREADY COMPLETED IS REFUSED ' +
           '(STS-KRB-0119), though this node still held the row',
           JSON.stringify({ code: carolAgain.code,
                            errorCode: carolAgain.errorCode }));
      persistence.clusterStore = realStore;

      // ================= E. RETENTION =======================================
      const replication = require(ROOT +
        '/persistence/persistence_replication');
      replication.reset();
      const calls = { reports: [], purges: [], leaves: 0 };
      let insertNext = false;
      const stub = {
        origin: function () { return 'stub-origin'; },
        latestChangeSeq: function () { return Promise.resolve(42); },
        changesSince: function () { return Promise.resolve([]); },
        reportChangeReader: function (applied, nodeId) {
          calls.reports.push({ applied: applied, nodeId: nodeId });
          const inserted = calls.reports.length === 1 || insertNext;
          return Promise.resolve({ inserted: inserted });
        },
        leaveChangeReader: function () {
          calls.leaves += 1;
          return Promise.resolve(true);
        },
        purgeChangeLog: function (opts) {
          calls.purges.push(opts);
          return Promise.resolve({ readersGone: 0, readers: 1, bound: 42,
                                   trimmed: 3 });
        }
      };
      config.setOverride('persistence.changeLogRetentionS', 3600);
      const started = await replication.start(stub, {});
      await new Promise(function (r) { setImmediate(r); });
      note(started.coordinating && calls.reports.length === 1 &&
           calls.reports[0].applied === 42 && calls.reports[0].nodeId === '',
           'E1. a process that starts reading the log reports where it ' +
           'starts, with no node id outside a cluster',
           JSON.stringify(calls.reports));
      note(replication.status().retention.trimming === true,
           'E2. outside a cluster a front process leads the trim itself ' +
           '(cluster.lead() answers onGain at once)',
           JSON.stringify(replication.status().retention));
      const trimmed = await replication.purgeOnce();
      note(trimmed && trimmed.trimmed === 3 &&
           calls.purges[0].retentionMs === 3600000 &&
           calls.purges[0].readerTtlMs === 3600000,
           'E3. the trim is asked with the retention and a reader lifetime ' +
           'no shorter than it', JSON.stringify(calls.purges));
      config.setOverride('persistence.changeLogRetentionS', 0);
      const off = await replication.purgeOnce();
      note(off === null && calls.purges.length === 1,
           'E4. retention 0 trims nothing, which is what the log did before');
      config.setOverride('persistence.changeLogRetentionS', 3600);
      insertNext = true;
      await replication.reportPosition(true);
      note(!!replication.status().retention.declaredGoneAt,
           'E5. A PROCESS THAT FINDS ITS PLACE REMOVED SINCE IT LAST ' +
           'REPORTED SAYS SO (STS-STORE-0057) — it may have missed trimmed ' +
           'changes', JSON.stringify(replication.status().retention));
      await replication.stop();
      note(calls.leaves === 1 && replication.status().retention.trimming ===
           false,
           'E6. a clean stop leaves the readers and stops trimming');
      config.clearOverride('persistence.changeLogRetentionS');
      replication.reset();

      // THE STATEMENT holds both halves of the bound.
      const pgPath = require.resolve(ROOT + '/node_modules/pg');
      const previous = require.cache[pgPath];
      const statements = [];
      const FakeClient = function () {};
      FakeClient.prototype.query = function (sql, params) {
        statements.push({ sql: String(sql), params: params || [] });
        return Promise.resolve({ rows: [{}], rowCount: 0 });
      };
      FakeClient.prototype.release = function () {};
      FakeClient.prototype.on = function () {};
      FakeClient.prototype.connect = function () { return Promise.resolve(); };
      FakeClient.prototype.end = function () { return Promise.resolve(); };
      const FakePool = function () {};
      FakePool.prototype.on = function () {};
      FakePool.prototype.query = FakeClient.prototype.query;
      FakePool.prototype.connect = function () {
        return Promise.resolve(new FakeClient());
      };
      FakePool.prototype.end = function () { return Promise.resolve(); };
      require.cache[pgPath] = { id: pgPath, filename: pgPath, loaded: true,
                                exports: { Pool: FakePool,
                                           Client: FakeClient } };
      delete require.cache[require.resolve(ROOT +
        '/persistence/persistence_postgres')];
      const pgDriver = require(ROOT + '/persistence/persistence_postgres')
        .create({ url: 'postgres://sts_app@localhost:5432/sts',
                  log: { debug: function () {}, info: function () {},
                         warn: function () {}, error: function () {} } });
      if (previous) {
        require.cache[pgPath] = previous;
      }
      await pgDriver.purgeChangeLog({ retentionMs: 3600000,
                                     readerTtlMs: 3600000 });
      await pgDriver.countWindow('s', '', 'k', 1000);
      const trim = statements.filter(function (one) {
        return /DELETE FROM sts_changes/.test(one.sql);
      })[0];
      note(trim && /c\.seq < \(SELECT low FROM live\)/.test(trim.sql) &&
           /c\.at < now\(\) - \(\$2::bigint/.test(trim.sql) &&
           /\(SELECT readers FROM live\) > 0/.test(trim.sql) &&
           /sts_cluster_nodes/.test(trim.sql),
           'E7. the trim statement removes a change only below the lowest ' +
           'live reader AND older than the retention, nothing with no ' +
           'reader, and declares a reader of a dead node gone',
           trim ? trim.sql : 'no statement');
      const count = statements.filter(function (one) {
        return /INSERT INTO sts_cluster_windows/.test(one.sql);
      })[0];
      note(count && /CASE WHEN sts_cluster_windows\.window_ends_at <= /.test(
             count.sql) && /count \+ 1/.test(count.sql),
           'E8. a window is counted in one upsert that resets a passed ' +
           'window and increments a live one', count ? count.sql : '');
      counters.reset();
    } catch (e) {
      note(false, 'the child ran to the end', e && e.stack);
    }
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })();
}

// F. THE LDAP BIND, in product mode (the only mode that limits binds), in a
// child of its own because the mode is read at start. Stringified.
function bindChild() {
  const ROOT = process.env.CLCR_ROOT;
  const OUT = process.env.CLCR_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  (async function () {
    try {
      const d = require(ROOT + '/ldap/ldap_server.js');
      const credentials = require(ROOT + '/common/credentials.js');
      const persistence = require(ROOT + '/persistence/persistence');
      const made = d.createUser('bind-limited', { origin: 'test' });
      const pw = credentials.setPassword('bind-limited',
                                         'Correct-Horse-9-Battery');
      note(made && made.ok && pw && pw.ok, 'F0. a product-mode person to ' +
           'bind as', JSON.stringify([made && made.ok, pw && pw.errors]));
      const DN = 'uid=bind-limited,ou=users,dc=example,dc=com';
      const bind = function (password) {
        return d.performOperation('bind', { dn: DN, channel: 'ldaps',
                                            credentials: password });
      };
      const local = bind('wrong-1');
      note(local && typeof local.then !== 'function' && local.ok === false,
           'F1. with no shared store a bind is answered in the same tick, as ' +
           'it always was', JSON.stringify(local));
      const windows = new Map();
      const later = function (fn) {
        return new Promise(function (resolve) {
          setImmediate(function () { resolve(fn()); });
        });
      };
      const store = {
        claimOnce: function () { return later(function () {
          return { claimed: true }; }); },
        countWindow: function (scope, realm, key, windowMs) {
          return later(function () {
            const row = windows.get(key) || { count: 0,
                                              endsAt: Date.now() + windowMs };
            row.count += 1;
            windows.set(key, row);
            return { count: row.count, remainingMs: row.endsAt - Date.now() };
          });
        },
        peekWindow: function (scope, realm, key) {
          return later(function () {
            const row = windows.get(key);
            return row ? { count: row.count,
                           remainingMs: row.endsAt - Date.now() }
              : { count: 0, remainingMs: 0 };
          });
        },
        clearWindow: function (scope, realm, key) {
          return later(function () { return windows.delete(key); });
        }
      };
      persistence.clusterStore = function () { return store; };
      const answers = [];
      for (let i = 0; i < 7; i++) {
        const pending = bind('wrong-again');
        answers.push({ promise: !!(pending && typeof pending.then ===
                                   'function'),
                       answer: await pending });
        await new Promise(function (r) { setTimeout(r, 5); });
      }
      const limit = Number(require(ROOT + '/common/config')
        .value('security.rateLimitPerIdentity'));
      const refusedAt = answers.findIndex(function (one) {
        return one.answer && one.answer.errorName === 'UnwillingToPerformError';
      });
      note(answers.every(function (one) { return one.promise; }) &&
           refusedAt === limit,
           'F2. WITH A SHARED STORE THE BIND ASKS IT: the operation answers a ' +
           'promise, and the bind after ' + limit + ' failures counted in the ' +
           'shared window is refused before its password is read',
           JSON.stringify(answers.map(function (one) {
             return one.answer && (one.answer.errorName || 'ok');
           })));
      note(windows.size >= 1,
           'and the failures were counted in the store, not in the process',
           windows.size + ' window(s)');
    } catch (e) {
      note(false, 'the bind child ran to the end', e && e.stack);
    }
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })();
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'sts-clcr-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, {
    CLCR_OUT: out, CLCR_ROOT: ROOT, LOG_LEVEL: 'fatal',
    STS_LOG_LEVEL: 'fatal' });
  delete env.CONFIG_FILE;
  delete env.STS_REQUEST_WORKER;
  const program = 'const fs = require("fs");\n(' + childMain.toString() +
                  ')()';
  const result = childProcess.spawnSync(process.execPath, ['-e', program], {
    cwd: ROOT, env: env, encoding: 'utf8', timeout: 240000,
    maxBuffer: 64 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // The child died before writing a report; said below with its status.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-3000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  const bindOut = out + '.bind';
  const bindEnv = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      bindEnv[key] = process.env[key];
    }
  });
  const bound = childProcess.spawnSync(process.execPath, ['-e',
    '(' + bindChild.toString() + ')()'], {
    cwd: ROOT, encoding: 'utf8', timeout: 180000,
    env: Object.assign(bindEnv, { CLCR_OUT: bindOut, CLCR_ROOT: ROOT,
                                  STS_MODE: 'product', LOG_LEVEL: 'fatal',
                                  STS_LOG_LEVEL: 'fatal' }) });
  let bindFindings = null;
  try {
    bindFindings = JSON.parse(fs.readFileSync(bindOut, 'utf8'));
    fs.rmSync(bindOut, { force: true });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // Reported below with the child's status.
    bindFindings = null;
  }
  if (t.check(Array.isArray(bindFindings),
              'the bind child reported its findings',
              'status=' + bound.status + ' ' +
              String(bound.stderr || '').slice(-3000))) {
    bindFindings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  // A REQUEST WORKER believes what its front process wrote: a second, small
  // child, because `client_address.js` reads the worker flag at require time.
  const worker = childProcess.spawnSync(process.execPath, ['-e',
    'const c = require(' + JSON.stringify(path.join(ROOT,
      'common/client_address')) + ');' +
    'process.stdout.write("\\nRESULT=" + c.clientAddressOf({ headers: { ' +
    '"x-forwarded-for": "203.0.113.9" }, socket: {} }) + "\\n")'], {
    cwd: ROOT, encoding: 'utf8', timeout: 60000,
    env: Object.assign({}, process.env, { STS_REQUEST_WORKER: '1',
                                          LOG_LEVEL: 'fatal',
                                          STS_LOG_LEVEL: 'fatal' }) });
  const said = /\nRESULT=([^\n]*)\n/.exec(String(worker.stdout || ''));
  t.equal(said ? said[1] : String(worker.stderr || '').slice(-500),
          '203.0.113.9',
          'B6. IN A REQUEST WORKER THE ADDRESS IS THE ONE THE FRONT PROCESS ' +
          'WROTE — a unix socket has no peer, and the limiter answered ' +
          '"unknown" for everybody');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cluster_limits_challenges_retention',
  describe: 'one rate-limit budget across nodes, SCIM and SPNEGO state any ' +
            'node can answer, trusted proxies, and change-log retention',
  run: run
};
