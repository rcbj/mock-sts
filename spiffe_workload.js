'use strict';
//
// File: spiffe_workload.js
//
// ---------------------------------------------------------------------------
// THE SPIFFE WORKLOAD API — the second of the three server-side surfaces, and
// the one a workload actually talks to.
//
// Seven methods on one gRPC service, `SpiffeWorkloadAPI`, reached over a Unix
// domain socket (what `SPIFFE_ENDPOINT_SOCKET` means to every real client) or
// over TCP. It is a LIBRARY: it registers no HTTP route and starts no listener
// — `spiffe_server.js` mounts these handlers — and it requires `helpers.js`,
// `config.js`, `audit.js`, `admin_stats.js`, `spiffe_id.js`, `spiffe_ca.js`,
// `spiffe_registry.js` and `spiffe_grpc.js`, none of which requires it back.
//
// ---------------------------------------------------------------------------
// THE CENTRAL FACT ABOUT THIS FILE: NOTHING HERE ATTESTS THE CALLER
//
// In a real deployment the agent looks at the peer of the Unix socket — its
// pid, and from that its uid, gid, executable path, container, Kubernetes pod —
// turns that into SELECTORS, and answers with the SVIDs of the registration
// entries whose selectors are a subset of those. That is workload attestation,
// and it is the whole of how a Workload API decides who is asking.
//
// This service does none of it. Node has no portable way to read a Unix
// socket's peer credentials, and more to the point THIS SERVICE AUTHENTICATES
// NOBODY — the LDAP directory accepts every bind, the KDC gives anyone a TGT,
// and no password is checked anywhere. So the Workload API here answers with
// **every registration entry that is not expired**, and a caller matching
// nothing gets one invented for it when `spiffe.autoCreateEntries` is on.
//
// Three consequences, all of them deliberate and all of them stated on
// `GET /spiffe` rather than left to be discovered:
//
//   * **Any caller can obtain any identity in this trust domain.** That is the
//     same statement as "any bind succeeds" one directory over, and it is what
//     makes the service useful for exercising a client rather than dangerous to
//     run on a laptop. It also means the socket's filesystem permissions are
//     the only thing standing between a process and every SVID here.
//
//   * **Selector matching is implemented and is not what decides this
//     answer.** `spiffe_registry.selectorsMatch()` computes exactly what SPIRE
//     would, and the SPIRE Server API's `GetAuthorizedEntries` and the
//     console's "what would match" view use it. It is not used HERE because
//     there is nothing to match against.
//
//   * **`spiffe.autoCreateEntries` off is the interesting setting.** With it
//     off, a caller matching no entry is answered with an EMPTY SVID list —
//     which is what a real agent does for an unregistered workload, and is the
//     only way to exercise a client's "I have no identity" path. That path is
//     the one most client libraries have and almost nobody runs.
//
// ---------------------------------------------------------------------------
// THE STREAMS ARE STREAMS, AND THAT IS THE SECOND THING TO GET RIGHT
//
// Four of the seven methods are server streams, and a real client opens
// `FetchX509SVID` once and keeps it open for the life of the process. It
// expects a new `X509SVIDResponse` whenever anything changes — an SVID
// approaching expiry, an authority rotating, a federated bundle arriving.
//
// So these do not write once and end. `pushOnRotation()` below re-mints and
// re-writes at half the SVID lifetime, for as long as the client is there,
// which means a client's rotation handling is exercised BY DEFAULT rather than
// only if somebody waits an hour. A Workload API that answers once and ends the
// stream looks completely correct on the first fetch and puts `go-spiffe` into
// a reconnect loop.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');
const config = require('./config');
const audit = require('./audit');
const stats = require('./admin_stats');
const spiffeId = require('./spiffe_id');
const ca = require('./spiffe_ca');
const registry = require('./spiffe_registry');
const rpc = require('./spiffe_grpc');

function trustDomain() { return ca.trustDomain(); }

// ---------------------------------------------------------------------------
// WHICH IDENTITIES THE CALLER GETS.
//
// The one decision the header is about, made in one place so that all four
// issuing methods answer consistently — a FetchX509SVID that returned three
// identities and a FetchJWTSVID that returned one would be a mock that
// contradicts itself.
// ---------------------------------------------------------------------------
function entitledEntries() {
  log.debug('Entering entitledEntries().');
  const rows = registry.allEntries().filter(function (entry) {
    return !entry.expired;
  });
  if (rows.length) {
    log.debug('Leaving entitledEntries(). ' + rows.length + ' entry/entries.');
    return rows;
  }
  if (!config.value('spiffe.autoCreateEntries')) {
    // The interesting answer. A real agent says exactly this to an
    // unregistered workload, and a client that has never seen it has never run
    // its own "I have no identity" path.
    log.info('spiffe: a workload asked for an SVID, no registration entry ' +
             'exists, and spiffe.autoCreateEntries is off — so it is being ' +
             'answered with an empty SVID list, which is what a real agent ' +
             'does for an unregistered workload.');
    log.debug('Leaving entitledEntries(). None, and none will be invented.');
    return [];
  }
  // Nothing registered and we are permitted to invent. ONE entry, named for
  // what it is, so that a person looking at /admin/spiffe/entries can see that
  // this service made it up rather than wondering who configured it.
  const id = spiffeId.make(trustDomain(), '/workload');
  const created = registry.createEntry({
    spiffeId: id,
    parentId: spiffeId.serverId(trustDomain()),
    selectors: [],
    description: 'Invented for a workload that matched no registration entry ' +
                 '(spiffe.autoCreateEntries).'
  }, 'auto', trustDomain(), '');
  if (!created.ok) {
    log.warn('spiffe: an entry could not be invented for an unmatched ' +
             'workload: ' + created.errors.join('; '));
    log.debug('Leaving entitledEntries(). None could be invented.');
    return [];
  }
  log.debug('Leaving entitledEntries(). One was invented.');
  return [created.entry];
}

// The federated bundles a holder of these entries should be given: the union of
// every `federatesWith` on them, as a map keyed by the trust domain's SPIFFE ID
// (not its bare name — the map key in both response messages is a SPIFFE ID,
// and a bare name there is a map a client silently finds nothing in).
async function federatedBundlesFor(entries) {
  log.debug('Entering federatedBundlesFor().');
  const wanted = {};
  (entries || []).forEach(function (entry) {
    (entry.federatesWith || []).forEach(function (name) { wanted[name] = true; });
  });
  const out = {};
  Object.keys(wanted).forEach(function (name) {
    const der = ca.federatedX509BundleDer(name);
    if (der && der.length) {
      out[spiffeId.trustDomainId(name)] = der;
    } else {
      // A federation relationship configured before the bundle arrived. Not an
      // error and not silent: it is the ordinary order of events, and a
      // workload that gets no bundle for a trust domain its entry names has no
      // other way to find out why.
      log.debug('federatedBundlesFor(): ' + name + ' is named by an entry and ' +
                'no bundle for it is held here, so nothing is sent for it.');
    }
  });
  log.debug('Leaving federatedBundlesFor(). ' + Object.keys(out).length + ' bundle(s).');
  return out;
}

// ---------------------------------------------------------------------------
// FetchX509SVID — the method everything else is built around.
//
// One `X509SVID` per entitled entry, each carrying the leaf chain, the private
// key, and the trust domain's own X.509 bundle. All three are ASN.1 DER, NOT
// PEM, which is the single most common thing to get wrong here: a PEM in these
// fields is a string a client will decode as DER and reject as malformed, and
// the error names neither field.
// ---------------------------------------------------------------------------
async function buildX509Response() {
  log.debug('Entering buildX509Response().');
  const entries = entitledEntries();
  const bundleDer = await ca.x509BundleDer();
  const svids = [];
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const svid = await ca.mintX509Svid(entry.spiffeId, {
      ttl: entry.x509SvidTtl,
      dnsNames: entry.dnsNames,
      hint: entry.hint
    });
    registry.noteSvidIssued(entry.id);
    stats.recordSvid('X.509', {
      subject: entry.spiffeId, entryId: entry.id, serial: svid.serialHex,
      hint: entry.hint, expiresAt: svid.expiresAt
    });
    svids.push({
      spiffe_id: entry.spiffeId,
      x509_svid: svid.chainDer,
      x509_svid_key: svid.privateKeyDer,
      bundle: bundleDer,
      hint: entry.hint || ''
    });
  }
  audit.audit({
    action: 'spiffe.svid.issue', actor: '', protocol: 'SPIFFE Workload API',
    channel: 'grpc', target: svids.length === 1 ? svids[0].spiffe_id : '',
    summary: svids.length + ' X509-SVID(s) were issued over the Workload API',
    // The SVIDs themselves are never recorded — an X509-SVID is delivered WITH
    // ITS PRIVATE KEY, which makes this the sharpest case in the service of
    // audit.js's no-credential rule.
    detail: { count: svids.length,
              ids: svids.map(function (s) { return s.spiffe_id; }).join(' ') }
  });
  log.debug('Leaving buildX509Response(). ' + svids.length + ' SVID(s).');
  return {
    svids: svids,
    // No CRLs. SPIFFE has no revocation — the answer is a short lifetime and
    // rotation — and an empty list is the correct and conforming value rather
    // than a gap. Said here because a reader looking for revocation support
    // will look at this field first.
    crl: [],
    federated_bundles: await federatedBundlesFor(entries)
  };
}

// The rotation timer. Half the SVID lifetime, which is what SPIRE uses, and it
// is what makes a client's rotation path run without anybody waiting an hour.
//
// `push` returns false once the client has gone, which is what stops the timer:
// a timer that outlived its stream would re-mint SVIDs for a workload that is
// not there, and grpc-js reports a write to a dead stream as an unhandled
// server error.
function pushOnRotation(push, buildResponse, label) {
  const period = Math.max(30, Math.floor(config.value('spiffe.svidTtl') / 2));
  log.debug('pushOnRotation(): ' + label + ' will be re-sent every ' + period +
            ' second(s) while the client is there.');
  const timer = setInterval(function () {
    Promise.resolve()
      .then(buildResponse)
      .then(function (message) {
        if (!push(message)) {
          clearInterval(timer);
          log.debug('spiffe: the ' + label + ' rotation timer stopped; the ' +
                    'client has gone.');
        }
      })
      .catch(function (err) {
        // A failure to re-mint must not take the stream down: the client is
        // holding a valid SVID until it expires, and an error here is better
        // reported than fatal.
        log.error('spiffe: could not re-send ' + label + ': ' + err.message);
      });
  }, period * 1000);
  // `unref` so a held-open stream cannot keep the process alive on its own.
  // Everything else in this service dies with the process and so should this.
  if (timer.unref) timer.unref();
  return timer;
}

const fetchX509Svid = rpc.serverStream('workload', 'FetchX509SVID',
  async function (call, push) {
    await ca.ready();
    pushOnRotation(push, buildX509Response, 'FetchX509SVID');
    return await buildX509Response();
  });

// ---------------------------------------------------------------------------
// FetchX509Bundles — the trust bundles alone, with no SVID and no private key.
//
// A separate method because a workload that only VERIFIES peers needs the
// bundles and has no business being handed an identity. A client that fetches
// SVIDs it never uses is a client holding private keys it does not need.
// ---------------------------------------------------------------------------
async function buildX509BundlesResponse() {
  log.debug('Entering buildX509BundlesResponse().');
  const bundles = {};
  bundles[ca.trustDomainId()] = await ca.x509BundleDer();
  ca.federatedBundles().forEach(function (entry) {
    const der = ca.federatedX509BundleDer(entry.trustDomain);
    if (der && der.length) bundles[spiffeId.trustDomainId(entry.trustDomain)] = der;
  });
  log.debug('Leaving buildX509BundlesResponse(). ' +
            Object.keys(bundles).length + ' bundle(s).');
  return { crl: [], bundles: bundles };
}

const fetchX509Bundles = rpc.serverStream('workload', 'FetchX509Bundles',
  async function (call, push) {
    await ca.ready();
    pushOnRotation(push, buildX509BundlesResponse, 'FetchX509Bundles');
    return await buildX509BundlesResponse();
  });

// ---------------------------------------------------------------------------
// FetchJWTSVID — unary, and the one method that takes a parameter that matters.
//
// `audience` is REQUIRED and at least one. A JWT-SVID with no audience is a
// bearer token good against anything that accepts one, which is why the
// specification puts the audience in the request rather than in configuration
// — and why this refuses an empty list rather than defaulting one. That refusal
// is a conformance check of the same kind as the security header: a client that
// omits the audience has a bug every real implementation will report.
//
// `spiffe_id` is optional. Given, it narrows to that identity — and if the
// caller is not entitled to it, the answer is an empty list rather than an
// error, which is what SPIRE does: "you may not have that" and "there is no
// such entry" are not distinguishable to a workload and should not be.
// ---------------------------------------------------------------------------
const fetchJwtSvid = rpc.unary('workload', 'FetchJWTSVID', async function (call) {
  await ca.ready();
  const request = call.request || {};
  const audiences = (request.audience || []).map(function (a) {
    return String(a || '').trim();
  }).filter(Boolean);
  if (!audiences.length) {
    throw rpc.invalidArgument('FetchJWTSVID requires at least one audience. ' +
                              'A JWT-SVID is a bearer credential — whoever ' +
                              'holds it can present it — so the audience is ' +
                              'what stops one issued for service A being ' +
                              'replayed against service B. Every conforming ' +
                              'Workload API refuses this call without one.');
  }
  const wanted = String(request.spiffe_id || '').trim();
  let entries = entitledEntries();
  if (wanted) {
    const parsed = spiffeId.parse(wanted);
    if (!parsed.ok) {
      throw rpc.invalidArgument('spiffe_id: ' + parsed.reason);
    }
    entries = entries.filter(function (entry) { return entry.spiffeId === parsed.id; });
  }
  const svids = [];
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const minted = await ca.mintJwtSvid(entry.spiffeId, audiences,
                                        { ttl: entry.jwtSvidTtl, hint: entry.hint });
    registry.noteSvidIssued(entry.id);
    stats.recordSvid('JWT', {
      subject: entry.spiffeId, entryId: entry.id, audiences: audiences,
      hint: entry.hint, expiresAt: minted.expiresAt
    });
    svids.push({ spiffe_id: entry.spiffeId, svid: minted.token,
                 hint: entry.hint || '' });
  }
  audit.audit({
    action: 'spiffe.svid.issue', actor: '', protocol: 'SPIFFE Workload API',
    channel: 'grpc', target: svids.length === 1 ? svids[0].spiffe_id : '',
    summary: svids.length + ' JWT-SVID(s) were issued over the Workload API',
    // The audiences are recorded and the TOKENS are not. A JWT-SVID is a bearer
    // credential; a row holding one would be a credential on a web page.
    detail: { count: svids.length, audience: audiences.join(' ') }
  });
  return { svids: svids };
});

// ---------------------------------------------------------------------------
// FetchJWTBundles — the JWT verification keys, as JWK Sets.
//
// The map value is `bytes` holding a JWK Set document, which is the structural
// difference from the X.509 bundles one method up: those are concatenated DER,
// these are JSON. A client that treats them alike fails on whichever it meets
// second.
//
// Only the `jwt-svid` keys go in. The bundle document this service publishes at
// its bundle endpoint carries both kinds, and sending the X.509 half here would
// be sending certificates to something that is going to parse them as JWKs.
// ---------------------------------------------------------------------------
async function jwtBundleFor(document) {
  const jwtKeys = (document.keys || []).filter(function (key) {
    return key.use === 'jwt-svid';
  });
  return Buffer.from(JSON.stringify({ keys: jwtKeys }), 'utf8');
}

async function buildJwtBundlesResponse() {
  log.debug('Entering buildJwtBundlesResponse().');
  const bundles = {};
  bundles[ca.trustDomainId()] = await jwtBundleFor(await ca.bundle());
  const federated = ca.federatedBundles();
  for (let i = 0; i < federated.length; i++) {
    bundles[spiffeId.trustDomainId(federated[i].trustDomain)] =
      await jwtBundleFor(federated[i].document);
  }
  log.debug('Leaving buildJwtBundlesResponse(). ' +
            Object.keys(bundles).length + ' bundle(s).');
  return { bundles: bundles };
}

const fetchJwtBundles = rpc.serverStream('workload', 'FetchJWTBundles',
  async function (call, push) {
    await ca.ready();
    pushOnRotation(push, buildJwtBundlesResponse, 'FetchJWTBundles');
    return await buildJwtBundlesResponse();
  });

// ---------------------------------------------------------------------------
// ValidateJWTSVID — the one method in this whole family that says no.
//
// See the note in `spiffe_ca.validateJwtSvid()`: the point of this call is to
// be told no, so a mock that said yes to everything would be useless to the
// only person who would ever call it. It is the same exception `/oauth2/userinfo`
// is among the token-reading endpoints.
//
// The `claims` field is a `google.protobuf.Struct`, which grpc-js builds from a
// plain object — but only from JSON-shaped values. `aud` may be a string or an
// array and both are fine; a `Buffer` or an `undefined` in there produces a
// serialisation error naming the field and not the value.
// ---------------------------------------------------------------------------
const validateJwtSvid = rpc.unary('workload', 'ValidateJWTSVID', async function (call) {
  await ca.ready();
  const request = call.request || {};
  const result = await ca.validateJwtSvid(request.svid, request.audience);
  audit.audit({
    action: 'spiffe.svid.validate', actor: '', protocol: 'SPIFFE Workload API',
    channel: 'grpc', target: result.ok ? result.spiffeId : '',
    summary: 'A JWT-SVID was ' + (result.ok ? 'validated' : 'refused') +
             ' at the Workload API',
    // The reason is recorded and the SVID is not.
    detail: result.ok ? { audience: String(request.audience || '') }
                      : { refused: result.reason }
  });
  if (!result.ok) {
    throw rpc.invalidArgument(result.reason);
  }
  return { spiffe_id: result.spiffeId, claims: structFrom(result.claims) };
});

// ---------------------------------------------------------------------------
// A CLAIM SET AS A `google.protobuf.Struct`, BUILT BY HAND.
//
// This looks like something a library should do and no library here does it.
// `@grpc/proto-loader` and protobufjs beneath it wrap exactly ONE well-known
// type — `google.protobuf.Any` — so a plain JavaScript object assigned to a
// Struct field serialises as a Struct with NO FIELDS. It does not throw and it
// does not warn: `ValidateJWTSVID` answers 200 with the right `spiffe_id` and
// `claims: {}`, which reads as a token that carried no claims rather than as a
// server that dropped them. That was this file's first version, and the only
// reason it was caught is that a real client asked for the claims and got none.
//
// So the shape is built explicitly. A Struct is `{ fields: { name: Value } }`
// and a Value is a `oneof` of six — which is why each branch below sets exactly
// ONE member: setting two leaves protobuf keeping whichever came last, and a
// number silently becoming a string is the kind of thing a client only notices
// when it compares `exp` against a clock.
//
// **AND THE MEMBER NAMES HERE ARE camelCase WHILE EVERY OTHER FIELD IN THIS
// FAMILY IS snake_case.** That is not a slip and it cost an hour. `keepCase:
// true` in `spiffe_grpc.js` tells the loader not to camel-case the fields of
// the files it PARSES — which is why the handlers say `spiffe_id` and
// `x509_svid_key`. `google/protobuf/struct.proto` is not one of those files:
// protobufjs carries the well-known types as pre-built descriptors whose JS
// names are already camelCase, and `keepCase` never reaches them. So
// `string_value` here serialises to NOTHING — no throw, no warning, a Struct
// with the right field names and every value empty — and `stringValue` works.
// The same is true of any other well-known type with fields; `Empty` and the
// `BoolValue`/`StringValue` wrappers happen not to be affected, the first
// because it has no fields and the second because its one field is called
// `value` in both spellings.
// ---------------------------------------------------------------------------
function structFrom(value) {
  const fields = {};
  Object.keys(value || {}).forEach(function (key) {
    fields[key] = valueFrom(value[key]);
  });
  return { fields: fields };
}

function valueFrom(value) {
  if (value === null || value === undefined) {
    // NULL_VALUE is the zero of its enum, written by name because the loader
    // is configured with `enums: String`.
    return { nullValue: 'NULL_VALUE' };
  }
  if (typeof value === 'boolean') return { boolValue: value };
  if (typeof value === 'number') {
    // A non-finite number has no protobuf representation. It cannot arrive from
    // a verified JWT payload — JSON has no NaN — but a Struct that will not
    // serialise fails the whole call with a message about a field, so the
    // impossible case is answered rather than left to be discovered.
    return Number.isFinite(value) ? { numberValue: value }
                                  : { stringValue: String(value) };
  }
  if (typeof value === 'string') return { stringValue: value };
  if (Array.isArray(value)) {
    return { listValue: { values: value.map(valueFrom) } };
  }
  return { structValue: structFrom(value) };
}

// ---------------------------------------------------------------------------
// FetchWITSVID and FetchWITBundles — DELIBERATELY UNIMPLEMENTED, and this is
// the one place in this family where that is the honest answer.
//
// WIT — the Workload Identity Token — is in the current `workloadapi.proto` and
// `wit-svid` is a `use` value the bundle specification names, so the methods
// are on the service and a client may call them. What is NOT settled anywhere
// this service could read is the TOKEN ITSELF: its header, its claim set, and
// how a `wit_svid_key` relates to it.
//
// Minting something JWS-shaped and calling it a WIT-SVID would be inventing a
// credential format. That is worse than not implementing it, and it is worse in
// the specific way this whole service is built to avoid: a client author would
// write code against this mock's invention, it would work here, and it would
// interoperate with nothing. The same reasoning that makes `wauth` a refusal in
// `wsfed.js` rather than a fabricated second factor.
//
// So: `Unimplemented`, with a message that says what it is and what it would
// take, rather than a silent empty response — which a client would read as "I
// am entitled to no WIT-SVIDs" and never ask about again.
// ---------------------------------------------------------------------------
const WIT_MESSAGE =
  'This service does not issue WIT-SVIDs. The methods are on the service ' +
  'because they are in the SPIFFE project\'s own workloadapi.proto, and ' +
  '`wit-svid` is a `use` value the bundle specification names — but the ' +
  'Workload Identity Token\'s own format is not settled in a specification ' +
  'this service could implement against. Minting something JWS-shaped and ' +
  'calling it a WIT-SVID would be inventing a credential format, which is ' +
  'the one thing a mock must not do: code written against the invention ' +
  'would work here and interoperate with nothing. X509-SVIDs and JWT-SVIDs ' +
  'are fully implemented.';

const fetchWitSvid = rpc.serverStream('workload', 'FetchWITSVID',
  async function () {
    throw rpc.statusError(rpc.grpc.status.UNIMPLEMENTED, WIT_MESSAGE);
  });

const fetchWitBundles = rpc.serverStream('workload', 'FetchWITBundles',
  async function () {
    throw rpc.statusError(rpc.grpc.status.UNIMPLEMENTED, WIT_MESSAGE);
  });

// The handler map, keyed by the method names `@grpc/proto-loader` produced.
// They are camelCase with the leading letter lowered — `fetchX509Svid`, not
// `FetchX509SVID` — which is the loader's convention and is NOT what the
// `.proto` says. Getting it wrong produces a server that starts, advertises the
// service, and answers `Unimplemented` to everything, with nothing in the logs.
const HANDLERS = {
  FetchX509SVID: fetchX509Svid,
  FetchX509Bundles: fetchX509Bundles,
  FetchJWTSVID: fetchJwtSvid,
  FetchJWTBundles: fetchJwtBundles,
  ValidateJWTSVID: validateJwtSvid,
  FetchWITSVID: fetchWitSvid,
  FetchWITBundles: fetchWitBundles
};

// What this surface implements, for the pages that describe it. `implemented`
// is a claim rather than a count, and the two WIT methods say why they are not
// — a table that reported seven of seven would be the most misleading thing on
// the page.
const METHOD_NOTES = {
  FetchX509SVID: { implemented: true,
    what: 'One X509-SVID per registration entry, each with its private key ' +
          'and the trust domain bundle, all DER. The stream stays open and ' +
          're-sends at half the SVID lifetime, so a client\'s rotation ' +
          'handling runs without anybody waiting an hour.' },
  FetchX509Bundles: { implemented: true,
    what: 'The X.509 trust bundles alone — this trust domain\'s and every ' +
          'federated one\'s — with no identity and no private key.' },
  FetchJWTSVID: { implemented: true,
    what: 'A JWT-SVID per entitled identity for the audience(s) asked for. ' +
          'Refuses a call with no audience, which every conforming ' +
          'implementation does.' },
  FetchJWTBundles: { implemented: true,
    what: 'The JWT verification keys as JWK Sets — JSON, where the X.509 ' +
          'bundles are concatenated DER.' },
  ValidateJWTSVID: { implemented: true,
    what: 'Really verifies: signature against the trust domain\'s JWT ' +
          'authorities, exp with no leeway, the audience, and that the sub ' +
          'belongs to the trust domain whose key verified it. The one method ' +
          'here that says no.' },
  FetchWITSVID: { implemented: false, what: WIT_MESSAGE },
  FetchWITBundles: { implemented: false, what: WIT_MESSAGE }
};

module.exports = {
  HANDLERS: HANDLERS,
  METHOD_NOTES: METHOD_NOTES,
  WIT_MESSAGE: WIT_MESSAGE,
  // Exported for the console's "what would this workload get" view, which asks
  // the same question the Workload API answers and must not compute it a second
  // way.
  entitledEntries: entitledEntries
};
