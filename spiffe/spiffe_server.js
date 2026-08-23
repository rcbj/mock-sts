'use strict';
//
// File: spiffe_server.js
//
// ---------------------------------------------------------------------------
// THE FIRST OF THE THREE SERVER-SIDE SPIFFE SURFACES — the BUNDLE ENDPOINT,
// which is plain HTTPS and needs no gRPC at all — plus the page that explains
// all three, plus the `listen()` that starts the two gRPC listeners the other
// two surfaces live on.
//
// It is the module `server.js` requires, and it is the SPIFFE analogue of
// `ldap_server.js` and `tls_server.js`: requiring it registers its HTTP views
// (rule 1), and its **own listeners are started from `listen()` in `server.js`,
// not at require time**. That is the rule those two modules already carry and
// the reason is the same — binding a port can fail, and a `require` that throws
// takes the whole service down where a route cannot. A failure to bind is
// RECORDED rather than thrown, and published on `GET /spiffe`, because the HTTP
// view answers 200 either way and there is otherwise no way to tell a running
// listener from one whose port was already taken.
//
// ---------------------------------------------------------------------------
// THE BUNDLE ENDPOINT IS THE SURFACE WITH NO MOVING PARTS
//
// It is one GET returning a JWK Set with two extra members. That is the whole
// of the SPIFFE federation protocol's server side: a foreign trust domain is
// configured with this URL, polls it, and trusts what it finds according to one
// of two profiles —
//
//   `https_web`     the URL is verified with the WEB PKI, the way a browser
//                   would. Which means it is only as good as the certificate
//                   this service is reached over, and this service's
//                   certificate is self-signed and regenerated every start.
//   `https_spiffe`  the URL is verified with a SPIFFE ID and an already-known
//                   bundle. The chicken-and-egg is solved by the first bundle
//                   being configured out of band.
//
// **This service publishes its bundle over whichever scheme the main port is
// on**, which is http by default and https when `global.https` is set. A real
// federation partner will refuse a plain-http bundle endpoint, and that is
// correct of it: the bundle is the root of trust for a whole trust domain, and
// fetching it over a channel anybody can rewrite means trusting whoever is in
// the middle. Said on the page rather than left to be met as a refusal.
// ---------------------------------------------------------------------------

const app = require('../common/app');
const { log, xmlEscape, baseUrlOf } = require('../common/helpers');
const config = require('../common/config');
const audit = require('../common/audit');
const spiffeId = require('./spiffe_id');
const ca = require('./spiffe_ca');
const registry = require('./spiffe_registry');
const rpc = require('./spiffe_grpc');
const workload = require('./spiffe_workload');
const serverApi = require('./spiffe_api');
// What is enforced, for the page and for the decision above about which
// socket gets TLS. A library that registers nothing.
const auth = require('./spiffe_auth');
// The console, for one slot and nothing else. `admin.js` cannot require THIS
// module — server.js requires it first, so the require would pull the bundle
// endpoint and /spiffe into the express router ahead of every /admin route, and
// GET /sts-metadata is built by walking that router. So it offers a slot and
// this module fills it at require time, the same shape setDirectoryReader(),
// setGroupReader() and setScimReader() already have.
//
// What crosses is two facts about SOCKETS — which of the four bound, and where
// the bundle is — because a page cannot see a socket any other way. Requiring
// admin.js from here is safe in the direction that matters: it registers its
// routes at ITS require time, which has already happened.
const admin = require('../admin-ui/admin');

// Read once: the route is registered with it at require time, which is what
// makes `spiffe.bundlePath` restart-only in config.js. `sts_metadata.js` reads
// the same setting for its row, so the description cannot name a path the
// router does not have.
const BUNDLE_PATH = config.value('spiffe.bundlePath') || '/spiffe/bundle';

// Listener state. Declared HERE, beside the other module state rather than
// beside `listen()` where it is written, because the HTTP views read it and
// they are registered above `listen()` — the same arrangement `ldap_server.js`
// and `tls_server.js` both use, and for the same reason.
let workloadServer = null;
let apiServer = null;
let workloadBindings = [];
let apiBindings = [];
let started = false;

function enabled() { return !!config.value('spiffe.enabled'); }

// ---------------------------------------------------------------------------
// THE BUNDLE ENDPOINT.
//
// `Cache-Control: no-store`, and that is not boilerplate here. The bundle
// carries this trust domain's authority certificates and JWT verification keys,
// they are regenerated on every start, and a cached copy outlives the keys it
// describes. The resulting failure is "nothing from that trust domain
// verifies", which reads as a broken bundle rather than a stale one — the same
// reasoning that puts the header on every document that carries the STS signing
// key.
// ---------------------------------------------------------------------------
app.get(BUNDLE_PATH, async function (req, res) {
  log.debug('Entering the SPIFFE bundle endpoint.');
  if (!enabled()) {
    // 404 rather than 503, because with SPIFFE off there is no bundle
    // endpoint here at all — a federation partner should see the same thing it
    // would see against a service that never had one.
    res.status(404).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify({ error: 'SPIFFE is turned off on this service ' +
                                     '(spiffe.enabled).' }));
    log.debug('Leaving the SPIFFE bundle endpoint. SPIFFE is off.');
    return;
  }
  try {
    const document = await ca.bundle();
    audit.audit({
      action: 'spiffe.bundle.read', actor: '', protocol: 'SPIFFE',
      channel: 'http', target: ca.trustDomainId(),
      summary: 'The trust bundle was fetched',
      detail: { sequence: document.spiffe_sequence,
                keys: (document.keys || []).length }
    });
    // `application/json`. The federation specification does not mint a media
    // type of its own — a bundle is a JWK Set — and `application/jwk-set+json`
    // would be defensible and is NOT what SPIRE sends. Matching SPIRE is worth
    // more here than being clever, because the client on the other end was
    // probably written against it.
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(document, null, 2));
    log.debug('Leaving the SPIFFE bundle endpoint. sequence=' +
              document.spiffe_sequence);
  } catch (e) {
    // The authorities failed to build at startup. 503 rather than 500: it is a
    // state this service can recover from with a restart, and the message says
    // which setting to look at.
    res.status(503).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify({ error: 'This service has no trust bundle: ' +
                                     e.message }));
    log.debug('Leaving the SPIFFE bundle endpoint. There is no bundle.');
  }
});

// A federated trust domain's bundle, exactly as it was given to this service.
// Published because a person debugging a federation needs to see what this
// service actually holds, and because "the bundle I pushed" and "the bundle you
// are serving to workloads" are two things worth being able to compare.
app.get('/spiffe/federated/:trustDomain', function (req, res) {
  log.debug('Entering the federated bundle view.');
  const name = String(req.params.trustDomain || '').trim().toLowerCase();
  const entry = ca.federatedBundle(name);
  if (!entry) {
    res.status(404).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify({ error: 'This service holds no bundle for the ' +
                                     'trust domain ' + name + '.',
                              held: ca.federatedBundles().map(function (e) {
                                return e.trustDomain;
                              }) }));
    log.debug('Leaving the federated bundle view. Not held.');
    return;
  }
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(entry.document, null, 2));
  log.debug('Leaving the federated bundle view. trustDomain=' + name);
});

// ---------------------------------------------------------------------------
// WHAT THIS IS, FOR A PERSON — and, with ?format=json, for a program.
//
// The same shape `GET /ldap` and `GET /tls` have, and it carries the same kind
// of thing: what the surfaces are, where they are, whether the sockets actually
// bound, and — at length — what is NOT checked. That last part is most of the
// page on purpose. A mock that quietly issued identities to anybody would teach
// a client author something false about every SPIFFE deployment they will ever
// meet.
// ---------------------------------------------------------------------------
function description(req) {
  log.debug('Entering description().');
  const base = baseUrlOf(req);
  const state = ca.state();
  const document = {
    what: 'A SPIFFE issuing authority: the bundle endpoint, the Workload API ' +
          'and the SPIRE Server API. The SPIRE Server API authenticates its ' +
          'caller with mutual TLS and an X509-SVID and authorizes every ' +
          'method against SPIRE\'s own table; the Workload API authenticates ' +
          'nobody, because its specification says it MUST NOT, and identifies ' +
          'a caller only by what this service can see of the connection. ' +
          'Nothing attests a workload or a node.',
    enabled: enabled(),
    trustDomain: state.trustDomain,
    trustDomainId: state.trustDomainId,
    serverId: state.serverId,
    ready: state.ready,
    error: state.error,
    bundle: {
      url: base + BUNDLE_PATH,
      sequence: state.sequence,
      refreshHint: state.refreshHint,
      profiles: {
        https_web: 'The partner verifies this URL with the Web PKI. This ' +
                   'service\'s certificate is self-signed and regenerated on ' +
                   'every start, so a partner using this profile has to trust ' +
                   'it explicitly — fetch it from /tls/server-certificate.',
        https_spiffe: 'The partner verifies this URL with a SPIFFE ID and a ' +
                      'bundle it already has. Supported in the sense that the ' +
                      'endpoint serves the right document; the SPIFFE ID this ' +
                      'service would present on that connection is the TLS ' +
                      'certificate\'s, which is not an SVID.'
      },
      scheme: config.value('global.https') ? 'https' : 'http',
      schemeNote: config.value('global.https')
        ? 'The main port is HTTPS (global.https), so the bundle endpoint is ' +
          'too.'
        : 'THE MAIN PORT IS PLAIN HTTP, so this bundle endpoint is http. A ' +
          'real federation partner will refuse it, and is right to: the ' +
          'bundle is the root of trust for a whole trust domain, and fetching ' +
          'it over a channel anybody can rewrite means trusting whoever is in ' +
          'the middle. Set global.https to serve it over TLS.'
    },
    authorities: {
      x509: state.x509Authorities.map(function (authority) {
        return { id: authority.id, active: authority.active,
                 keyType: authority.keyType, subject: authority.subject,
                 notAfter: authority.notAfter };
      }),
      jwt: state.jwtAuthorities.map(function (authority) {
        return { kid: authority.id, active: authority.active,
                 keyType: authority.keyType, alg: authority.alg };
      }),
      note: 'Generated per start and held in memory, exactly like the STS ' +
            'signing key and the TLS certificate. A workload holding a bundle ' +
            'from before a restart will fail to verify every SVID minted ' +
            'after it.'
    },
    workloadApi: {
      service: 'SpiffeWorkloadAPI',
      listeners: workloadBindings,
      securityHeader: rpc.SECURITY_HEADER + ': true',
      securityHeaderRequired: !!config.value('spiffe.requireSecurityHeader'),
      methods: rpc.methodsOf('workload').map(function (method) {
        const note = workload.METHOD_NOTES[protoNameOf(method.path)] || {};
        return { name: protoNameOf(method.path), path: method.path,
                 streaming: method.responseStream,
                 implemented: note.implemented !== false,
                 what: note.what || '' };
      })
    },
    serverApi: {
      listeners: apiBindings,
      services: serverApi.SERVICE_HANDLERS.map(function (entry) {
        return {
          name: entry.label,
          what: entry.what,
          methods: rpc.methodsOf(entry.name).map(function (method) {
            const full = entry.label + '.' + protoNameOf(method.path);
            return { name: protoNameOf(method.path), path: method.path,
                     implemented: !serverApi.NOT_IMPLEMENTED[full],
                     what: serverApi.NOT_IMPLEMENTED[full] || '' };
          })
        };
      })
    },
    registry: {
      entries: registry.entryCount(),
      agents: registry.agentCount(),
      maxEntries: registry.maxEntries(),
      maxAgents: registry.maxAgents(),
      note: 'The store is the embedded LDAP directory. An ldapmodify under ' +
            'ou=spiffe changes what the next SVID looks like, because nothing ' +
            'caches these.'
    },
    federated: state.federated,
    // The list every reader of this page needs most, and it is deliberately
    // longer than the rest of the document.
    notChecked: [
      'NO WORKLOAD ATTESTATION. A real agent reads the peer credentials of ' +
      'the Unix socket — pid, and from that uid, gid, executable path, ' +
      'container, pod — and turns them into selectors. Node has no portable ' +
      'way to read SO_PEERCRED, so this service identifies a caller only by ' +
      'the transport it arrived on, the endpoint it reached and its peer ' +
      'address, and the selectors it produces are spelt `transport:`, ' +
      '`endpoint:` and `peer:` rather than `unix:` so that they cannot be ' +
      'mistaken for an attestor\'s. Those DO decide which entries answer ' +
      '(spiffe.attestWorkloads), but nothing proves who the caller is: any ' +
      'caller that can reach the socket can still obtain an identity here.',
      'NO CREDENTIAL AT ALL ON THE WORKLOAD API, and that is the ' +
      'specification rather than this service being permissive. The SPIFFE ' +
      'Workload Endpoint specification says the endpoint "MUST NOT require ' +
      'any direct authentication of its clients" and that "Transport Layer ' +
      'Security MUST NOT be required" — a workload has no root of trust until ' +
      'this call gives it one. So spiffe.authRequired deliberately does not ' +
      'reach this surface.',
      'NOTHING VERIFIES AN ASSERTED SELECTOR. With ' +
      'spiffe.acceptAssertedSelectors on, a Workload API caller may send its ' +
      'own selectors in a metadata header and they are matched as though ' +
      'something had checked them. It is off by default and it exists ' +
      'because selector matching is the interesting behaviour of a Workload ' +
      'API and there is otherwise no way to exercise a client\'s "these ' +
      'matched and those did not" path here.',
      'NO NODE ATTESTATION. Whatever attestor an agent names and whatever ' +
      'payload it sends are written down as claimed and never verified. The ' +
      'agent selectors on /admin/spiffe/agents carry an `unverified:true` ' +
      'value for exactly this reason. The ONE exception is a join token, ' +
      'which this server minted and therefore checks: see `refused` below.',
      'A CSR SIGNATURE IS NOT VERIFIED. Only the public key is read out of a ' +
      'CSR — which is what stops a caller naming itself something it is not — ' +
      'but proof of possession is not checked.',
      'NO REVOCATION, ANYWHERE. SPIFFE has none: the answer is a short ' +
      'lifetime and rotation. The CRL fields in the Workload API responses ' +
      'are empty because that is the conforming value, not because they are ' +
      'unimplemented. An SVID presented to the SPIRE Server API is checked ' +
      'against its validity window and the trust bundle and against no ' +
      'revocation list, because there is none to check.'
    ].concat(auth.authRequired() ? [] : [
      'AND, RIGHT NOW, NOTHING ON THE SPIRE SERVER API EITHER. ' +
      'spiffe.authRequired is OFF, so that port is plain gRPC, no caller is ' +
      'identified, the per-method table below is not applied, and anybody who ' +
      'can reach it can create a registration entry granting any identity in ' +
      'this trust domain and then collect an SVID for it. The `admin` and ' +
      '`downstream` flags on an entry are recorded and read by nothing while ' +
      'it is off.'
    ]),
    // WHO IS ASKING, on the surface that asks. The whole table comes from
    // spiffe_auth.js so that this page, /admin/spiffe and the management API
    // cannot disagree about what is enforced — the same reason the two
    // discovery documents are built from one object.
    authentication: auth.state(),
    // And the short list of what IS refused, because a page that only said
    // "nothing is checked" would be wrong.
    refused: [
      'A Workload API call with no `' + rpc.SECURITY_HEADER + ': true` ' +
      'metadata header, unless spiffe.requireSecurityHeader is off. Every ' +
      'conforming implementation refuses this, so a client that omits it has ' +
      'a bug nothing else will tell them about.',
      'FetchJWTSVID and MintJWTSVID with no audience.',
      'ValidateJWTSVID on anything that does not really verify: signature, ' +
      'expiry with no leeway, audience, and that the sub belongs to the trust ' +
      'domain whose key verified it.',
      'A registration entry whose SPIFFE ID is invalid, belongs to another ' +
      'trust domain, or sits under the reserved /spire path.',
      'AttestAgent for a banned agent, and — with spiffe.authRequired on — a ' +
      'join token this server did not mint, one that has expired, one ' +
      'presented twice, and one minted for a named agent and presented by ' +
      'another. A join token is the one attestation payload here this ' +
      'service ISSUED and can therefore verify.',
      'Every method on the SPIRE Server API that the caller\'s entity is not ' +
      'allowed, with UNAUTHENTICATED when nothing was presented and ' +
      'PERMISSION_DENIED when something was and it was not enough. The two ' +
      'are different instructions to a client and SPIRE distinguishes them. ' +
      'Note that Debug.GetInfo is LOCAL-ONLY, so even an admin SVID is ' +
      'refused it over TCP — that is SPIRE\'s row and the surprise is the ' +
      'point.',
      'An X509-SVID that no authority in this trust domain or a federated ' +
      'one signed, one outside its validity window (spiffe.clockSkew), one ' +
      'with no URI subjectAltName, one with several, and one whose SPIFFE ID ' +
      'names a different trust domain from the authority that signed it.',
      'RenewAgent for a caller that is not the agent it would renew — which ' +
      'with spiffe.authRequired off is every caller, so the method answers ' +
      'Unimplemented in that mode with the reason it used to give always.',
      'Appending an authority to this trust domain\'s own bundle, which would ' +
      'publish a signing key nothing here holds.',
      'RefreshBundle, which would have this service fetch a URL somebody ' +
      'registered — the same refusal it gives WS-Federation\'s wreqptr and a ' +
      'client\'s jwks_uri.'
    ],
    links: {
      bundle: base + BUNDLE_PATH,
      console: base + '/admin/spiffe',
      entries: base + '/admin/spiffe/entries',
      agents: base + '/admin/spiffe/agents',
      api: base + '/admin-api/spiffe',
      directory: base + '/ldap/spiffe',
      metadata: base + '/sts-metadata'
    }
  };
  log.debug('Leaving description().');
  return document;
}

// `/SpiffeWorkloadAPI/FetchX509SVID` -> `FetchX509SVID`. The loader gives
// handlers camelCase names and the wire path carries the real one, so the path
// is what these pages report: a reader comparing this page with the `.proto`
// should see the same spelling.
function protoNameOf(methodPath) {
  const parts = String(methodPath || '').split('/');
  return parts[parts.length - 1] || '';
}

app.get('/spiffe', function (req, res) {
  log.debug('Entering the /spiffe view.');
  const document = description(req);
  if (String(req.query.format || '') === 'json') {
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(document, null, 2));
    log.debug('Leaving the /spiffe view. JSON.');
    return;
  }
  res.status(200).type('text/html').set('Cache-Control', 'no-store')
     .send(page(document));
  log.debug('Leaving the /spiffe view. HTML.');
});

function esc(value) { return xmlEscape(value == null ? '' : String(value)); }

// A listener, and WHAT A CALLER HAS TO PRESENT ON IT. The third column is not
// decoration: the four sockets have three different postures — plain, plain and
// trusted as `local`, and mutual TLS — and a reader who cannot see which is
// which meets the difference as a handshake failure. Same reason
// `tls_server.js` says on the page which port needs verification turned off.
function listenerRows(bindings) {
  if (!bindings.length) {
    return '<tr><td colspan="3">Nothing bound. Either this listener is ' +
           'turned off in configuration, or <code>listen()</code> has not ' +
           'run yet.</td></tr>';
  }
  return bindings.map(function (binding) {
    return '<tr><td><code>' + esc(binding.address) + '</code>' +
      (binding.tls ? ' <span class="note">(mutual TLS)</span>' : '') +
      '</td><td>' +
      (binding.listening
        ? 'listening'
        : '<strong>did not bind</strong>: ' + esc(binding.error)) +
      '</td><td>' + esc(binding.authentication || '') + '</td></tr>';
  }).join('');
}

function methodRows(methods) {
  return methods.map(function (method) {
    return '<tr><td><code>' + esc(method.name) + '</code>' +
      (method.streaming ? ' <span class="note">(stream)</span>' : '') +
      '</td><td>' + (method.implemented ? 'yes' : '<strong>no</strong>') +
      '</td><td>' + esc(method.what) + '</td></tr>';
  }).join('');
}

function page(document) {
  const state = ca.state();
  return '<!doctype html><html><head><meta charset="utf-8">' +
    '<title>SPIFFE — mock STS</title><style>' +
    'body{font-family:system-ui,sans-serif;margin:2rem;max-width:60rem;line-height:1.5}' +
    'table{border-collapse:collapse;margin:1rem 0;width:100%}' +
    'th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;vertical-align:top}' +
    'th{background:#f4f4f4}code{background:#f4f4f4;padding:.1rem .3rem}' +
    '.note{color:#666}.warn{background:#fff6e5;border-left:4px solid #e69500;padding:.6rem 1rem}' +
    '</style></head><body>' +
    '<h1>SPIFFE</h1>' +
    '<p>This service is the issuing authority for the trust domain <code>' +
    esc(document.trustDomainId) + '</code>. Three server-side surfaces: the ' +
    'bundle endpoint below (plain HTTPS), the <strong>Workload API</strong> ' +
    'and the <strong>SPIRE Server API</strong> (both gRPC, on their own ' +
    'sockets — this page cannot see a socket, so it reports whether each one ' +
    'actually bound).</p>' +
    (document.enabled ? '' :
      '<p class="warn">SPIFFE is turned OFF on this service ' +
      '(<code>spiffe.enabled</code>). The bundle endpoint answers 404 and ' +
      'every gRPC call is refused with <code>Unavailable</code>. Turning it ' +
      'back on needs no restart.</p>') +
    (state.ready ? '' :
      '<p class="warn">' + (state.error
        ? 'The issuing authority could not be built, so nothing here will ' +
          'issue an SVID: ' + esc(state.error)
        : 'The issuing authority is still being generated. An RSA-4096 key ' +
          'takes a few seconds; reload.') + '</p>') +
    '<p class="warn"><strong>NOTHING HERE IS ATTESTED.</strong> No workload ' +
    'and no node: any caller that can reach the Workload API socket can ' +
    'obtain an identity in this trust domain, and an agent\'s attestation ' +
    'payload is written down as claimed. That is this service\'s posture ' +
    'everywhere — it checks no password and accepts every LDAP bind — and it ' +
    'matters more here than anywhere else, because what comes out is a ' +
    'credential another service will believe.</p>' +
    '<p class="' + (document.authentication.enforced ? 'note' : 'warn') + '">' +
    (document.authentication.enforced
      ? '<strong>The SPIRE Server API is the exception, and it is on.</strong> ' +
        'Its TCP port is mutual TLS, a caller presents an X509-SVID from this ' +
        'trust domain, and every method is authorized against SPIRE\'s own ' +
        'table — the whole of which is below. Its Unix socket is the ' +
        '<code>local</code> entity and needs no credential. The Workload API ' +
        'is deliberately untouched by this: its specification says a client ' +
        'MUST NOT be required to authenticate.'
      : '<strong>And the SPIRE Server API is not authenticating anybody ' +
        'either, because <code>spiffe.authRequired</code> is off.</strong> ' +
        'That port is plain gRPC and anybody who can reach it can create a ' +
        'registration entry granting any identity here and then collect an ' +
        'SVID for it. Turn the setting on — it needs a restart, because it ' +
        'decides how the socket is bound — to get the behaviour of a real ' +
        'spire-server.') +
    '</p>' +

    '<h2>The bundle endpoint</h2>' +
    '<p><a href="' + esc(document.bundle.url) + '"><code>' +
    esc(document.bundle.url) + '</code></a> — a JWK Set with ' +
    '<code>spiffe_sequence</code> (' + esc(document.bundle.sequence) + ') and ' +
    '<code>spiffe_refresh_hint</code> (' + esc(document.bundle.refreshHint) +
    ' seconds). Each key carries <code>use</code> of <code>x509-svid</code> or ' +
    '<code>jwt-svid</code>; a consumer MUST IGNORE a key whose <code>use</code> ' +
    'it does not recognise, which is why a bundle with the member missing ' +
    'verifies nothing and reports no error.</p>' +
    '<p class="' + (config.value('global.https') ? 'note' : 'warn') + '">' +
    esc(document.bundle.schemeNote) + '</p>' +

    '<h2>The trust domain\'s authorities</h2>' +
    '<table><tr><th>Kind</th><th>Id</th><th>Key</th><th>State</th></tr>' +
    document.authorities.x509.map(function (a) {
      return '<tr><td>X.509</td><td><code>' + esc(a.id) + '</code></td><td>' +
        esc(a.keyType) + '</td><td>' + (a.active ? 'active' : 'retired, still ' +
        'published') + ', until ' + esc(a.notAfter) + '</td></tr>';
    }).join('') +
    document.authorities.jwt.map(function (a) {
      return '<tr><td>JWT</td><td><code>' + esc(a.kid) + '</code></td><td>' +
        esc(a.keyType) + ' / ' + esc(a.alg) + '</td><td>' +
        (a.active ? 'active' : 'retired, still published') + '</td></tr>';
    }).join('') +
    '</table>' +
    '<p class="note">' + esc(document.authorities.note) + '</p>' +

    '<h2>The Workload API</h2>' +
    '<table><tr><th>Address</th><th>State</th><th>What a caller presents</th></tr>' +
    listenerRows(document.workloadApi.listeners) + '</table>' +
    '<p>Every call must carry the metadata header <code>' +
    esc(document.workloadApi.securityHeader) + '</code>' +
    (document.workloadApi.securityHeaderRequired
      ? '. This service enforces that, which is the one conformance check it ' +
        'makes: a client that omits it has a bug that nothing else will ever ' +
        'report.'
      : ', and this service is NOT enforcing it at the moment ' +
        '(<code>spiffe.requireSecurityHeader</code> is off).') + '</p>' +
    '<table><tr><th>Method</th><th>Implemented</th><th>What</th></tr>' +
    methodRows(document.workloadApi.methods) + '</table>' +

    '<h2>The SPIRE Server API</h2>' +
    '<table><tr><th>Address</th><th>State</th><th>What a caller presents</th></tr>' +
    listenerRows(document.serverApi.listeners) + '</table>' +
    document.serverApi.services.map(function (service) {
      return '<h3>' + esc(service.name) + '</h3><p>' + esc(service.what) + '</p>' +
        '<table><tr><th>Method</th><th>Implemented</th><th>What</th></tr>' +
        methodRows(service.methods) + '</table>';
    }).join('') +

    '<h2>Who may call the SPIRE Server API</h2>' +
    '<p>' + esc(document.authentication.what) + '</p>' +
    '<p class="note">' + esc(document.authentication.bootstrapping) + '</p>' +
    '<p class="note">' + esc(document.authentication.identityNote) + '</p>' +
    (document.authentication.adminIds.length
      ? '<p>Administrators by configuration (<code>spiffe.adminIds</code>): ' +
        document.authentication.adminIds.map(function (id) {
          return '<code>' + esc(id) + '</code>';
        }).join(', ') + '. A registration entry marked <code>admin</code> is ' +
        'the other way, and both are read on every call.</p>'
      : '<p>No SPIFFE ID is an administrator by configuration ' +
        '(<code>spiffe.adminIds</code> is empty). The other way in is a ' +
        'registration entry marked <code>admin</code>, which the form on ' +
        '<a href="/admin/spiffe/entries">/admin/spiffe/entries</a> sets, and ' +
        'the <code>local</code> Unix socket, which needs no credential at ' +
        'all.</p>') +
    '<table><tr><th>Entity</th><th>What it means</th></tr>' +
    document.authentication.entities.map(function (entity) {
      return '<tr><td><code>' + esc(entity.id) + '</code></td><td>' +
        esc(entity.what) + '</td></tr>';
    }).join('') + '</table>' +
    '<h3>The per-method table</h3>' +
    '<p>Copied from SPIRE\'s own <code>policy_data.json</code> rather than ' +
    'reasoned out, because a table somebody derived from what each method ' +
    '"obviously" needs is one that disagrees with SPIRE in two or three ' +
    'places — and the client author who meets the disagreement has no way to ' +
    'tell which end is wrong. <code>any</code> means the method is open here ' +
    'and in a real server too.</p>' +
    '<table><tr><th>Method</th><th>Allowed to</th></tr>' +
    document.authentication.policy.map(function (row) {
      return '<tr><td><code>' + esc(row.method) + '</code></td><td>' +
        esc(row.allow.join(', ')) + '</td></tr>';
    }).join('') + '</table>' +

    '<h2>What is not checked</h2><ul>' +
    document.notChecked.map(function (line) {
      return '<li>' + esc(line) + '</li>';
    }).join('') + '</ul>' +

    '<h2>What is refused</h2>' +
    '<p>A short list, and it is here because a page that only said "nothing is ' +
    'checked" would be wrong.</p><ul>' +
    document.refused.map(function (line) {
      return '<li>' + esc(line) + '</li>';
    }).join('') + '</ul>' +

    '<h2>The registry</h2>' +
    '<p>' + esc(document.registry.entries) + ' registration entry/entries and ' +
    esc(document.registry.agents) + ' agent(s). ' +
    esc(document.registry.note) + '</p>' +

    '<h2>Elsewhere</h2><ul>' +
    Object.keys(document.links).map(function (key) {
      return '<li><a href="' + esc(document.links[key]) + '">' + esc(key) +
        '</a> — <code>' + esc(document.links[key]) + '</code></li>';
    }).join('') + '</ul>' +
    '<p class="note">Add <code>?format=json</code> to this page for the ' +
    'machine-readable form.</p>' +
    '</body></html>';
}

// ---------------------------------------------------------------------------
// STARTING THE TWO gRPC LISTENERS.
//
// Called from `listen()` in `server.js`, for the reason at the top of this
// file. Four addresses at most — a Unix socket and a TCP port for each surface
// — and each is reported separately, because "the Workload API socket is up and
// the SPIRE Server API port is not" is an ordinary outcome and one flag could
// only report one of them. That is the lesson `ldap_server.js` records about
// 389 and 636, applied before it had to be learnt again.
// ---------------------------------------------------------------------------
function addressesFor(surface) {
  const out = [];
  if (surface === 'workload') {
    if (config.value('spiffe.workloadSocketEnabled')) {
      out.push({ address: 'unix://' + config.value('spiffe.workloadSocket'),
                 socketPath: config.value('spiffe.workloadSocket') });
    }
    const port = config.value('spiffe.workloadPort');
    if (port) {
      out.push({ address: config.value('spiffe.grpcHost') + ':' + port });
    }
  } else {
    if (config.value('spiffe.serverSocketEnabled')) {
      out.push({ address: 'unix://' + config.value('spiffe.serverSocket'),
                 socketPath: config.value('spiffe.serverSocket') });
    }
    const port = config.value('spiffe.serverPort');
    if (port) {
      out.push({ address: config.value('spiffe.grpcHost') + ':' + port });
    }
  }
  return out;
}

async function bindAll(server, surface) {
  log.debug('Entering bindAll(). surface=' + surface);
  const results = [];
  const addresses = addressesFor(surface);
  // ---------------------------------------------------------------------
  // WHICH SOCKET GETS TLS, AND WHY IT IS EXACTLY ONE OF THE FOUR.
  //
  // The two specifications ask for opposite things and this is where that
  // becomes four sockets with three different postures. See
  // `spiffe_auth.js`'s header for the argument; the shape of it here:
  //
  //   Workload API, socket AND TCP   PLAIN, always. The Workload Endpoint
  //                                  specification says "Transport Layer
  //                                  Security MUST NOT be required", because a
  //                                  workload has no root of trust until this
  //                                  call gives it one. TLS here would refuse
  //                                  every conforming client.
  //   SPIRE Server API, socket       PLAIN, always. It is the `local` entity —
  //                                  the private socket a real `spire-server`
  //                                  CLI uses, whose access control is the
  //                                  filesystem.
  //   SPIRE Server API, TCP          MUTUAL TLS when `spiffe.authRequired` is
  //                                  on, which is the default, and plain when
  //                                  it is not.
  //
  // That last line is the one that changes what an existing caller sees, which
  // is why the setting is RESTART-ONLY: a flag that was runtime for its checks
  // and restart-only for its socket is the silent disagreement config.js's
  // header warns about — /admin/config would report mutual TLS while a plain
  // listener went on answering. The same reasoning `oauth2.rfc9700` carries
  // about `global.https`.
  // ---------------------------------------------------------------------
  let secure = null;
  if (surface === 'server' && auth.authRequired()) {
    try {
      secure = await rpc.serverApiCredentials();
    } catch (e) {
      // REPORTED, never thrown, and the port still comes up — plain. A
      // listener that refused to bind because its certificate could not be
      // minted would take the surface away for a reason nothing could show,
      // and `GET /spiffe` reports which of the two each address got.
      log.error('spiffe: the SPIRE Server API could not be given a TLS ' +
                'identity (' + e.message + '), so its TCP port is binding ' +
                'PLAIN and nothing on it is authenticated. GET /spiffe says ' +
                'so; this is a fault here rather than a configuration ' +
                'problem.');
      secure = null;
    }
  }
  for (let i = 0; i < addresses.length; i++) {
    const entry = addresses[i];
    if (entry.socketPath) rpc.prepareSocketPath(entry.socketPath);
    // The socket is the `local` entity and is never TLS; see above. `secure`
    // is null for every address but one.
    const tls = !entry.socketPath && secure;
    const bound = await rpc.bindOne(server, entry.address,
      tls ? secure : rpc.grpc.ServerCredentials.createInsecure());
    bound.tls = !!tls;
    bound.socket = !!entry.socketPath;
    // What a caller has to do to use this address, said on the page rather
    // than left to be met as a handshake failure — the rule `tls_server.js`
    // follows about the main port.
    bound.authentication = entry.socketPath
      ? (surface === 'server'
          ? (auth.trustLocalSocket()
              ? 'No credential. This socket is the `local` entity and is ' +
                'trusted outright, which is how the spire-server CLI works.'
              : 'An X509-SVID is required even here ' +
                '(spiffe.trustLocalSocket is off).')
          : 'None, and there must be none: the Workload Endpoint ' +
            'specification forbids requiring one.')
      : (tls
          ? 'Mutual TLS. Verify this server against the trust bundle, present ' +
            'your own X509-SVID, and expect to be authorized per method.'
          : (surface === 'server'
              ? 'None — spiffe.authRequired is off, so this port is plain ' +
                'gRPC and every method is open to everybody.'
              : 'None, and there must be none: the Workload Endpoint ' +
                'specification forbids requiring one. The deployment secures ' +
                'this port by other means or does not expose it.'));
    results.push(bound);
  }
  log.debug('Leaving bindAll(). ' + results.length + ' address(es).');
  return results;
}

function listen() {
  log.debug('Entering listen().');
  if (started) {
    log.debug('Leaving listen(). Already started.');
    return { whenReady: Promise.resolve({ workload: workloadBindings,
                                          api: apiBindings }) };
  }
  started = true;
  workloadServer = rpc.buildServer([
    { name: 'workload', handlers: workload.HANDLERS }
  ]);
  apiServer = rpc.buildServer(serverApi.SERVICE_HANDLERS.map(function (entry) {
    return { name: entry.name, handlers: entry.handlers };
  }));
  const whenReady = (async function () {
    // The authorities first: a listener that answered before the CA existed
    // would refuse every call for a reason that has nothing to do with the
    // call. Awaited rather than raced, and a failure here is REPORTED — the
    // listeners still come up, and every call then fails with the real reason
    // rather than with a connection refused.
    try {
      await ca.ready();
    } catch (e) {
      log.error('spiffe: the issuing authority failed, so the listeners will ' +
                'answer and every call will be refused with the reason: ' +
                e.message);
    }
    // The registry's seed entries, once the store exists. Here rather than at
    // require time because `ldap_server.js` fills the directory slot at ITS
    // require time, and `server.js` requires this module after it — but
    // `listen()` is the first moment BOTH are certainly true.
    try {
      registry.seed(ca.trustDomain());
    } catch (e) {
      // A directory that would not hold the seed entries. Reported, never
      // fatal: the surfaces work, they simply have nothing in them.
      log.error('spiffe: the seed registration entries could not be created: ' +
                e.message);
    }
    workloadBindings = await bindAll(workloadServer, 'workload');
    apiBindings = await bindAll(apiServer, 'server');
    return { workload: workloadBindings, api: apiBindings };
  })();
  log.debug('Leaving listen().');
  return { whenReady: whenReady };
}

function close() {
  log.debug('Entering close().');
  [workloadServer, apiServer].forEach(function (server) {
    if (!server) return;
    try {
      server.forceShutdown();
    } catch (e) {
      // Already down, or never came up. Nothing to do about it and nothing
      // depends on it having worked.
      log.debug('close(): a gRPC server would not shut down: ' + e.message);
    }
  });
  workloadServer = null;
  apiServer = null;
  started = false;
  log.debug('Leaving close().');
}

admin.setSpiffeReader(function () {
  return { workload: workloadBindings.slice(0), api: apiBindings.slice(0),
           bundlePath: BUNDLE_PATH };
});

module.exports = {
  listen: listen,
  close: close,
  description: description,
  BUNDLE_PATH: BUNDLE_PATH,
  bindings: function () {
    return { workload: workloadBindings.slice(0), api: apiBindings.slice(0) };
  }
};
