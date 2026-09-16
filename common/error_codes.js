'use strict';
//
// File: error_codes.js
//
// ===========================================================================
// THE ERROR CODES: ONE NAME FOR EVERY WAY THIS SERVICE CAN FAIL OR REFUSE.
//
// A failure here used to be identified by its SENTENCE — the
// `error_description` a client was sent, the line a handler logged, the summary
// on an audit row. A sentence is the right thing to put in front of a person
// and the wrong thing to search for: it is reworded, it carries a value that
// differs per request, and the same condition is described in three places in
// three wordings. So an operator asking "how often does federation refuse a
// signature" had a grep and a guess, and a maintainer asking "where is the
// thing that produced this row" had the same.
//
// Every failure condition this service can produce now has a CODE in the table
// below, `STS-<SUBSYSTEM>-<NNNN>`, and the code is recorded in two places:
//
//   * **on the audit row** — `errorCode`, filterable at `/admin/audit` and
//     `GET /admin-api/audit?code=`, and at the front of the row's summary so a
//     free-text search finds it too;
//   * **in the log line** `audit.js` writes for every row that carries one, and
//     at the front of the message wherever a failure is logged without a row
//     (`tag()`), which is the case for anything that stops the process before
//     an audit ring exists to hold it.
//
// ---------------------------------------------------------------------------
// FOUR RULES, AND EACH IS WHY SOMETHING BELOW IS SHAPED THE WAY IT IS.
//
// 1. **A CODE IS NEVER SENT TO A CLIENT.** Not in a body, not in a header, not
//    in a redirect. Every protocol this service speaks already defines how it
//    reports an error — `invalid_grant`, `KDC_ERR_PREAUTH_FAILED`, an LDAP
//    result code, a SOAP fault, a gRPC status, a SAML `StatusCode` — and a
//    client under test is exactly the thing that must see those and nothing
//    else. A code is an OPERATOR's name for the condition; putting one on the
//    wire would be this service inventing a member no specification has, in
//    front of the client whose error handling it exists to exercise. So
//    `mark()` writes to the RESPONSE OBJECT, which the call-log funnel reads
//    after the bytes have gone, and never to anything that is serialised.
//
// 2. **THE SPEC ERROR IS UNCHANGED AND IS DOCUMENTED BESIDE THE CODE.** Where a
//    condition is reported to the client in a specification's vocabulary, the
//    `spec` member says which — so the documentation page can answer "what did
//    the client actually see" without anybody reading the handler. It is a
//    description of what the handler already sends, never an instruction to
//    send it.
//
// 3. **ONE CODE PER CONDITION, NOT PER CALL SITE.** Two handlers that refuse
//    for the same reason share a code; one handler that can refuse for four
//    reasons has four. The test is whether an operator would want to count them
//    separately. A code that meant two conditions would make its count a sum
//    nobody can read back apart.
//
// 4. **A CODE IS NEVER RENUMBERED OR REUSED.** It is a name that ends up in
//    somebody's alert rule and in somebody's saved log search. A condition that
//    stops existing keeps its row with `retired` set — the documentation page
//    says so — and its number is not handed to anything else.
//
// ---------------------------------------------------------------------------
// IT IS A LEAF, AND THAT IS WHAT LETS EVERY FILE USE IT.
//
// It requires NOTHING from this repository — not `helpers.js`, not `config.js`,
// not even a logger — so it can be required from `config.js` and `crypto.js`,
// which are themselves leaves, and from `audit.js`, which may require
// `helpers.js` and `config.js` and nothing else. A registry of failures that
// could close a require cycle would be a registry that caused one. `fs` and
// `path` are required only inside the command-line half at the foot.
//
// The Entering/Leaving convention is met the way `version.js` meets it: a
// console-backed `log` whose debug output is off unless DEBUG below is flipped.
//
// ---------------------------------------------------------------------------
// ADDING A FAILURE — the whole of what it costs:
//
//   1. a row in CODES, under its subsystem, with the next free number;
//   2. `errorCodes.mark(res, 'STS-…')` before an HTTP response that refuses or
//      fails, or `errorCode: 'STS-…'` on the `audit()` call for anything that
//      is not an HTTP response, or `errorCodes.tag('STS-…')` at the front of a
//      log message for a failure no audit row can hold;
//   3. `node common/error_codes.js --docs`, which regenerates
//      `docs/error-codes.md`.
//
// `tests/error_codes.js` fails on a code used and not registered, a code
// registered and used nowhere, a documentation page that is stale, and a
// failure-shaped call site (the patterns are listed there) with no code beside
// it. That last check is what makes "every future failure has a code" a
// property of the build rather than of anybody remembering.
//
// Run directly:
//   node common/error_codes.js --docs     regenerate docs/error-codes.md
//   node common/error_codes.js --check    non-zero if the page is stale
//   node common/error_codes.js --json     the table
// ===========================================================================

const DEBUG = false;

const log = {
  debug: function (message) {
    if (DEBUG) console.log('[error_codes] ' + message);
  },
  warn: function (message) {
    console.warn('[error_codes] ' + message);
  }
};

// `STS-` so a code can never be mistaken for a specification's own error name
// in a log line, a subsystem of two to ten capitals and digits, and four digits
// so no subsystem runs out.
const CODE_PATTERN = /^STS-[A-Z][A-Z0-9]{1,9}-[0-9]{4}$/;

// Anywhere in a string — what the test scans source files with.
const CODE_IN_TEXT = /STS-[A-Z][A-Z0-9]{1,9}-[0-9]{4}/g;

// ---------------------------------------------------------------------------
// THE SUBSYSTEMS.
//
// Organised by protocol family where there is one and by major component where
// there is not, and in the order a reader meets them on the documentation page.
// `where` names the files a subsystem's codes are raised from, so somebody
// holding a code knows which directory's CLAUDE.md to read first. It is prose
// for a person rather than a rule the test enforces: a code is raised where the
// condition is detected, and one module occasionally detects another family's.
// ---------------------------------------------------------------------------
const SUBSYSTEMS = [
  { id: 'HTTP', label: 'HTTP front door',
    where: 'common/app.js, common/cors.js, common/validation.js, ' +
           'common/websecurity.js',
    what: 'Every HTTP request passes through here before it reaches a ' +
          'protocol: the security headers, the CORS allowlist, the body ' +
          'parsers, the validation guard, the rate limiter, and the call-log ' +
          'funnel that records the ' +
          'answer. The three generic codes below are what that funnel ' +
          'records for a failed response nothing more specific claimed.' },
  // THE PROXY PROTOCOL (2026-09-14, #46): below HTTP and below TLS, so a
  // subsystem of its own rather than HTTP's — a refusal here happens before
  // any listener's protocol has read a byte, on every TCP listener at once.
  { id: 'PROXY', label: 'PROXY protocol',
    where: 'common/proxy_protocol.js, server.js',
    what: 'The HAProxy PROXY protocol v2 header read at the front of every ' +
          'TCP connection when global.proxyProtocol is v2: who may send one ' +
          '(global.trustedProxies), the header itself, and the startup ' +
          'refusal when nobody is trusted.' },
  { id: 'CORE', label: 'Service core',
    where: 'server.js, common/protocol_stack.js, common/config.js, ' +
           'common/config_file.js, common/realms.js, common/helpers.js, ' +
           'common/mode.js, common/version.js, sts_metadata.js, home/',
    what: 'Starting the service, the settings table, trust realms, and the ' +
          'helpers every protocol shares.' },
  { id: 'WORKER', label: 'Worker pools',
    where: 'common/worker_pool.js, common/worker.js, common/request_pool.js, ' +
           'common/request_worker.js, common/service_state.js',
    what: 'The child processes post-quantum signing runs in, and the request ' +
          'workers the whole protocol stack can be dispatched to.' },
  { id: 'STORE', label: 'Persistence and coordination',
    where: 'persistence/',
    what: 'The memory, LDIF and PostgreSQL stores, the minted-row flush, and ' +
          'the change log several processes coordinate through.' },
  { id: 'CLUSTER', label: 'Cluster membership and agreement',
    where: 'cluster/',
    what: 'Several containers against one store: membership and its ' +
          'heartbeat, leases and the fence every write checks, the gate in ' +
          'front of active-passive and active-active mode, atomic claims, ' +
          'the secrets every node shares, and the barrier that makes a ' +
          'request see what other nodes committed before it arrived.' },
  { id: 'KEYS', label: 'Cryptography, keys and secrets',
    where: 'common/crypto.js, common/pq_jose.js, common/keystore.js, ' +
           'common/secrets.js',
    what: 'Signing, verification, encryption and decryption; the signing ' +
          'keys that survive a restart; the key-encryption key and the ' +
          'database password read from a secret store.' },
  { id: 'PKI', label: 'Certificate authority',
    where: 'common/pki.js, common/pki_authoring.js, ' +
           'common/pki_revocation.js, common/revocation_status.js, pki/, ' +
           'admin-ui/pki_admin.js',
    what: 'The Root, Intermediate and Issuing CAs, certificate authoring, ' +
          'the CRL and OCSP responders, and the revocation check a presented ' +
          'certificate is held to.' },
  // CERTIFICATE ENROLLMENT (2026-09-13): the shared core the three enrollment
  // protocols issue through, and the three protocols. Four subsystems rather
  // than one because an operator reading `STS-SCEP-0012` on an audit row wants
  // the protocol a failing client spoke, and `STS-ENROLL-*` is the half none of
  // them owns — who may have a certificate for whom, and what goes in it.
  { id: 'ENROLL', label: 'Certificate enrollment core',
    where: 'common/cert_enrollment.js, common/enrollment_monitor.js',
    what: 'Who may be issued a certificate for which directory entry, what ' +
          'a certificate issued over ACME, EST or SCEP contains, the PKCS#10 ' +
          'proof of possession, the enrolled certificates and credentials ' +
          'kept on a person or application entry, and their revocation.' },
  { id: 'ACME', label: 'ACME (RFC 8555)',
    where: 'acme/',
    what: 'The ACME server: the directory, nonces, JWS request ' +
          'authentication, accounts bound by External Account Binding, ' +
          'orders, pre-validated authorizations, finalize, certificate ' +
          'download, revocation, key change, renewal information, and its ' +
          'console pages.' },
  { id: 'EST', label: 'EST (RFC 7030)',
    where: 'est/',
    what: 'Enrollment over Secure Transport: cacerts, simpleenroll, ' +
          'simplereenroll, serverkeygen and csrattrs, HTTP Basic and TLS ' +
          'client certificate authentication, and its console pages.' },
  { id: 'SCEP', label: 'SCEP (RFC 8894)',
    where: 'scep/',
    what: 'The Simple Certificate Enrolment Protocol: GetCACaps, GetCACert, ' +
          'GetNextCACert and PKIOperation, the CMS envelope, the RA ' +
          'certificate, challenge passwords, and its console pages.' },
  { id: 'AUTHN', label: 'Sign-in, second factors and sessions',
    where: 'authn/, common/credentials.js, common/totp.js, ' +
           'common/backup_codes.js, common/password_policy.js, ' +
           'common/oidc_rp.js',
    what: 'The sign-in screen, WebAuthn, TOTP and recovery codes, password ' +
          'verification, the sign-on session, and the OpenID Connect relying ' +
          'party the console and the portal sign in through.' },
  { id: 'OAUTH', label: 'OAuth 2.0 and OpenID Connect',
    where: 'oauth-oidc/, common/person_assertions.js',
    what: 'The authorization server: every endpoint, client authentication, ' +
          'DPoP, mTLS, RFC 9700 mode, consent, and the RFC 7521/7522/7523 ' +
          'assertion grants.' },
  { id: 'SAML', label: 'SAML 2.0 and SAML 1.1',
    where: 'saml/',
    what: 'Both browser SSO profiles, Single Logout, the SAML 1.1 SOAP ' +
          'responder, and service-provider metadata.' },
  { id: 'WSTRUST', label: 'WS-Trust',
    where: 'ws-trust/',
    what: 'The security token service, WS-Trust 1.0 through 1.4.' },
  { id: 'WSFED', label: 'WS-Federation',
    where: 'ws-federation/',
    what: 'The passive requestor profile and the mock relying party.' },
  { id: 'FED', label: 'Federation',
    where: 'federation/',
    what: 'Relationships with foreign identity providers and service ' +
          'providers, in either direction, including the outbound requests ' +
          'made to a partner.' },
  { id: 'KRB', label: 'Kerberos and SPNEGO',
    where: 'kerberos/',
    what: 'The KDC on TCP/UDP 88 and MS-KKDCP, the Kerberos service, SPNEGO ' +
          'and the SPNEGO sign-in.' },
  { id: 'LDAP', label: 'LDAP directory',
    where: 'ldap/',
    what: 'The embedded directory on 389 and 636 and the console pages that ' +
          'show it.' },
  { id: 'SCIM', label: 'SCIM 2.0',
    where: 'scim/',
    what: 'Provisioning at /scim/v2 and its six authentication schemes.' },
  { id: 'SPIFFE', label: 'SPIFFE',
    where: 'spiffe/',
    what: 'The bundle endpoint, the Workload API and the SPIRE Server API.' },
  { id: 'TLS', label: 'TLS listeners',
    where: 'tls/',
    what: 'The 8443 and 9443 listeners, the trust store, and the server ' +
          'certificate three other sockets share.' },
  { id: 'VC', label: 'OpenID4VCI, OpenID4VP and DID',
    where: 'oid4vc/',
    what: 'The credential issuer, the verifier, credential offers and DID ' +
          'documents.' },
  { id: 'SSF', label: 'Shared Signals, CAEP and RISC',
    where: 'ssf/',
    what: 'Streams, subjects, delivery by push and poll, the receivers this ' +
          'service registers for itself, and the outbound push.' },
  { id: 'GNAP', label: 'GNAP (RFC 9635 / RFC 9767)',
    where: 'gnap/',
    what: 'The grant request and continuation endpoints; interaction ' +
          '(redirect, app, user code); key proofing (HTTP message ' +
          'signatures, mutual TLS, detached and attached JWS); the five ' +
          'access token formats (jwt-signed, jwt-encrypted, macaroon, ' +
          'biscuit, zcap); token management; the RS-facing introspection, ' +
          'resource registration and token derivation of RFC 9767; the ' +
          'push finish outbound request; the console pages; and CAEP ' +
          'emission for grants.' },
  { id: 'XACML', label: 'XACML and access policy',
    where: 'xacml/, common/access_gate.js, common/issuance_gate.js, ' +
           'common/roles.js',
    what: 'The PDP, the policy repository, the embedded PEPs that decide ' +
          'this service\'s own access and issuance, the PIP over HTTP, and ' +
          'the remote-PEP endpoints.' },
  // THE ONE SUBSYSTEM THAT IS NOT THIS PROCESS. The remote PEP is a second
  // container with no audit log of its own, so its codes are recorded in its
  // log lines (tag()) — which is where an operator of that container reads. It
  // is here rather than in a table of its own because a code is a name an
  // operator searches for across both containers' logs, and two tables would
  // be two places a number could be handed out twice. The Dockerfile copies
  // this file to the image root, beside version.js and for its reason.
  { id: 'XPEP', label: 'Remote XACML PEP (container)',
    where: 'xacml-pep/',
    what: 'The second container: the remote Policy Enforcement Point that ' +
          'pulls the policy repository from this service, registers and ' +
          'heartbeats, asks the PIP over HTTP and decides in its own ' +
          'process. It has no audit log, so these codes appear at the front ' +
          'of its log lines rather than on an audit row.' },
  { id: 'ADMIN', label: 'Admin console',
    where: 'admin-ui/ (except pki_admin.js), admin-core/',
    what: 'The console at /admin, its gate, and the actions behind its ' +
          'controls.' },
  { id: 'API', label: 'Management API',
    where: 'mgmt-api/',
    what: '/admin-api, its access token, its request validation and the ' +
          'explorer.' },
  { id: 'PORTAL', label: 'User portal',
    where: 'portal/',
    what: 'The pages that belong to the person looking at them, and account ' +
          'activation.' },
  { id: 'LOGOUT', label: 'Sign-out',
    where: 'logout/',
    what: 'The protocol-independent sign-out and the session inventory.' },
  { id: 'REG', label: 'Registries',
    where: 'common/applications.js, common/consent.js, ' +
           'common/app_permissions.js, common/delegation.js, ' +
           'common/admin_stats.js, common/audit.js, ' +
           'common/claim_attributes.js, common/group_claims.js, ' +
           'common/user_graph.js, common/credential_graph.js, ' +
           'common/inetorgperson.js',
    what: 'The application registry, consent, delegated permissions, the ' +
          'delegation register, the statistics and the claim configuration.' },
  { id: 'DBG', label: 'Protocol debugger',
    where: 'debugger/, and the debugger scope rule in ' +
           'oauth-oidc/oauth2.js',
    what: 'The embedded identity protocol debugger: its listener, its ' +
          'sign-in, the access token its api requires, the permission that ' +
          'token carries, and the api process it forwards to.' }
];

// ---------------------------------------------------------------------------
// THE TABLE.
//
// One row per failure condition:
//
//   code       STS-<SUBSYSTEM>-<NNNN>; never renumbered, never reused
//   summary    what failed, as a sentence an operator reads in a log line
//   spec       what the CLIENT is told, in its protocol's own vocabulary,
//              where the condition reaches a client at all — '' where it does
//              not (a background failure, a startup refusal)
//   retired    set on a condition that no longer exists; the row stays
//
// The sections are in SUBSYSTEMS order and the numbers within a section are
// ascending. The test checks both, so a merge that interleaves two branches'
// additions is noticed rather than published out of order.
// ---------------------------------------------------------------------------
const CODES = [
  // ===== HTTP ==============================================================
  { code: 'STS-HTTP-0001',
    summary: 'No route matched the request path, and Express answered with ' +
      'its own 404 (`Cannot GET /path`).',
    spec: 'HTTP 404' },
  { code: 'STS-HTTP-0002',
    summary: 'A request was refused with a 4xx status that no handler ' +
      'classified. This is the call-log funnel\'s fallback, and a row ' +
      'carrying it names a failure that is missing its own code.',
    spec: 'HTTP 4xx, as the handler sent it' },
  { code: 'STS-HTTP-0003',
    summary: 'A request failed with a 5xx status that no handler classified ' +
      '— usually an exception Express caught. A row carrying it names ' +
      'a failure that is missing its own code.',
    spec: 'HTTP 5xx, as the handler sent it' },
  { code: 'STS-HTTP-0004',
    summary: 'The request body exceeded the 5 MB limit the body parsers ' +
      'enforce.',
    spec: 'HTTP 413' },
  { code: 'STS-HTTP-0010',
    summary: 'A query string carried a parameter named constructor, ' +
      'prototype or __proto__, which the validation guard refuses ' +
      'before any endpoint sees the request.',
    spec: 'HTTP 400 text/plain' },
  { code: 'STS-HTTP-0011',
    summary: 'A query-string value contained a control character (a CR, LF, ' +
      'NUL or similar), which the validation guard refuses before any ' +
      'endpoint sees the request.',
    spec: 'HTTP 400 text/plain' },
  { code: 'STS-HTTP-0012',
    summary: 'The request body was in a charset or content encoding the body ' +
      'parsers do not read, so it was refused before any endpoint ' +
      'saw it.',
    spec: 'HTTP 415' },
  { code: 'STS-HTTP-0013',
    summary: 'The request body was cut off before it was complete, or did ' +
      'not match its Content-Length, so it was refused before any ' +
      'endpoint saw it.',
    spec: 'HTTP 400' },
  { code: 'STS-HTTP-0014',
    summary: 'A middleware ahead of the router raised an error the body ' +
      'parsers do not classify (a body stream that could not be read, ' +
      'most often), so the request failed before any endpoint saw ' +
      'it.',
    spec: 'HTTP status as Express\'s final handler sends it' },
  { code: 'STS-HTTP-0015',
    summary: 'A state-changing form post from a signed-in session carried no ' +
      'CSRF token.',
    spec: 'the refusal the calling surface renders (a console, portal or ' +
      'sign-in page)' },
  { code: 'STS-HTTP-0016',
    summary: 'A state-changing form post carried a CSRF token that belongs ' +
      'to a different session, or to one that has ended.',
    spec: 'the refusal the calling surface renders (a console, portal or ' +
      'sign-in page)' },
  { code: 'STS-HTTP-0017',
    summary: 'Too many attempts at one operation for one identity inside the ' +
      'rate-limit window; further attempts are refused until the ' +
      'window passes.',
    spec: 'the refusal the calling surface renders, in its own protocol\'s ' +
      'words' },
  { code: 'STS-HTTP-0018',
    summary: 'Too many attempts at one operation from one address inside the ' +
      'rate-limit window; further attempts are refused until the ' +
      'window passes.',
    spec: 'the refusal the calling surface renders, in its own protocol\'s ' +
      'words' },
  // CORS (2026-09-13): the allowlist common/cors.js holds every response to.
  // The preflight is the one of the four that is a RESPONSE refused; the
  // other three are recorded in a log line, because the request they belong
  // to is answered and a browser simply may not read the answer.
  { code: 'STS-HTTP-0019',
    summary: 'A CORS preflight came from an origin that is not this ' +
      'service\'s own and that no application in the realm lists in ' +
      'appCorsOrigin, so it was answered with no CORS headers.',
    spec: 'HTTP 204 with no Access-Control-Allow-Origin; the browser does ' +
      'not send the request' },
  { code: 'STS-HTTP-0020',
    summary: 'A cross-origin request named no client, and its origin is not ' +
      'this service\'s own and is listed by no application in the realm, ' +
      'so its answer carried no Access-Control-Allow-Origin.',
    spec: 'none — the endpoint answers; the browser withholds the answer ' +
      'from the page' },
  { code: 'STS-HTTP-0021',
    summary: 'A cross-origin request named a client this realm has no ' +
      'application for (a client_id, Basic user name, client assertion or ' +
      'access token client_id), so its answer carried no ' +
      'Access-Control-Allow-Origin.',
    spec: 'none — the endpoint answers; the browser withholds the answer ' +
      'from the page (a CORS error in place of the protocol\'s own error)' },
  { code: 'STS-HTTP-0022',
    summary: 'A cross-origin request named a client whose appCorsOrigin does ' +
      'not list the request\'s origin, so its answer carried no ' +
      'Access-Control-Allow-Origin.',
    spec: 'none — the endpoint answers; the browser withholds the answer ' +
      'from the page' },
  { code: 'STS-HTTP-0023',
    summary: 'A value of global.corsOrigins is not an origin, and was ' +
      'ignored rather than widened.',
    spec: '' },
  // ===== PROXY =============================================================
  { code: 'STS-PROXY-0001',
    summary: 'A connection from an address outside global.trustedProxies ' +
      '(and not this host) was closed, because with global.proxyProtocol on ' +
      'every connection must come through a trusted proxy. One audit row ' +
      'per address per minute; the rest are counted.',
    spec: 'the TCP connection is closed before any protocol byte is read' },
  { code: 'STS-PROXY-0002',
    summary: 'A connection from a trusted proxy did not begin with the ' +
      'PROXY protocol v2 signature — a balancer without proxy protocol ' +
      'enabled, or a plain client on the proxy\'s address — and was closed.',
    spec: 'the TCP connection is closed' },
  { code: 'STS-PROXY-0003',
    summary: 'A connection from a trusted proxy began with a PROXY protocol ' +
      'version 1 (text) header; only version 2 is accepted, and it was ' +
      'closed.',
    spec: 'the TCP connection is closed' },
  { code: 'STS-PROXY-0004',
    summary: 'A PROXY protocol v2 header was malformed — a version other ' +
      'than 2, an unknown command, family or transport, an address block ' +
      'shorter than its family needs, or a TLV running past the declared ' +
      'length — and the connection was closed.',
    spec: 'the TCP connection is closed' },
  { code: 'STS-PROXY-0005',
    summary: 'A PROXY protocol v2 header declared more address and TLV ' +
      'bytes than this service reads (4096), and the connection was closed ' +
      'before they were buffered.',
    spec: 'the TCP connection is closed' },
  { code: 'STS-PROXY-0006',
    summary: 'A PROXY protocol v2 header carried a CRC32C TLV that does not ' +
      'match the header, and the connection was closed.',
    spec: 'the TCP connection is closed' },
  { code: 'STS-PROXY-0007',
    summary: 'A connection from a trusted proxy did not complete its PROXY ' +
      'protocol header within global.proxyProtocolTimeoutMs, and was closed.',
    spec: 'the TCP connection is closed' },
  { code: 'STS-PROXY-0008',
    summary: 'A connection from a trusted proxy closed part-way through its ' +
      'PROXY protocol header.',
    spec: '' },
  { code: 'STS-PROXY-0009',
    summary: 'The service refused to start: global.proxyProtocol is v2 and ' +
      'global.trustedProxies holds no usable address or range, so no ' +
      'header could be believed.',
    spec: '' },
  // ===== CORE ==============================================================
  { code: 'STS-CORE-0001',
    summary: 'The appconfig file CONFIG_FILE names could not be loaded, so ' +
      'the service refused to start.',
    spec: '' },
  { code: 'STS-CORE-0002',
    summary: 'One or more settings have no value in the appconfig layer or ' +
      'the environment (env/defaults.js has not been regenerated), so ' +
      'the service refused to start.',
    spec: '' },
  { code: 'STS-CORE-0003',
    summary: 'A runtime setting change could not be handed to persistence. ' +
      'The setting is in force and may not survive a restart.',
    spec: '' },
  { code: 'STS-CORE-0004',
    summary: 'A setting was named that does not exist in the settings table.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-CORE-0005',
    summary: 'A restart-only setting was changed while the service is ' +
      'running; it must be set in the appconfig file or the ' +
      'environment instead.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-CORE-0006',
    summary: 'A setting\'s value failed its type or bounds check — from a ' +
      'console form, /admin-api, or a per-application attribute that ' +
      'overrides it.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-CORE-0007',
    summary: 'A setting was reset where nothing had overridden it.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-CORE-0008',
    summary: 'A runtime setting saved in the persistence store was not ' +
      'applied, because it no longer passes validation (renamed, ' +
      'retyped or made restart-only since).',
    spec: '' },
  { code: 'STS-CORE-0009',
    summary: 'A trust realm id was not lower-case letters, digits and ' +
      'hyphens of at most 31 characters.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-CORE-0010',
    summary: 'A trust realm was defined with the id of the built-in default ' +
      'realm.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-CORE-0011',
    summary: 'A trust realm id is the first segment of a path this service ' +
      'already serves, so the realm would shadow the endpoint.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-CORE-0012',
    summary: 'A trust realm was defined with an id that is already in use.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-CORE-0013',
    summary: 'A trust realm was named that is not defined.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-CORE-0014',
    summary: 'A realms.* setting was set on one trust realm; those settings ' +
      'decide how a realm is reached and may only be set ' +
      'service-wide.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-CORE-0015',
    summary: 'A per-process setting (such as workers.count) was set on one ' +
      'trust realm, where it would change every realm at once.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-CORE-0016',
    summary: 'A setting was cleared on a trust realm that does not set it.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-CORE-0017',
    summary: 'The router could not be read to reserve realm ids, so a realm ' +
      'id may shadow an endpoint without being refused.',
    spec: '' },
  { code: 'STS-CORE-0018',
    summary: 'A trust realm change watcher threw; the change stands but what ' +
      'watches it (persistence, most often) may not have recorded ' +
      'it.',
    spec: '' },
  { code: 'STS-CORE-0019',
    summary: 'A store could not build itself for a newly created trust ' +
      'realm; the realm exists without that store\'s state.',
    spec: '' },
  { code: 'STS-CORE-0020',
    summary: 'A store could not purge a removed trust realm\'s state, which ' +
      'is left behind for an id nobody can reach.',
    spec: '' },
  { code: 'STS-CORE-0021',
    summary: 'The persistence observer offered to the realm stores was not a ' +
      'function, so nothing this process mints will be written down.',
    spec: '' },
  { code: 'STS-CORE-0022',
    summary: 'Two persisted stores were declared under one handle; the ' +
      'second is not persisted.',
    spec: '' },
  { code: 'STS-CORE-0023',
    summary: 'A persisted store could not report a write to persistence; the ' +
      'write stands in memory and may not be written down.',
    spec: '' },
  { code: 'STS-CORE-0024',
    summary: 'A trust realm\'s signing keys could not be certified under its ' +
      'Issuing CAs; they still sign, with a self-signed certificate.',
    spec: '' },
  { code: 'STS-CORE-0025',
    summary: 'The BBS key pair handed down from the front process could not ' +
      'be read, so this process generated its own.',
    spec: '' },
  { code: 'STS-CORE-0026',
    summary: 'A request declared a JSON body that does not parse; it is read ' +
      'as empty.',
    spec: 'whatever the endpoint answers for an empty body' },
  { code: 'STS-CORE-0027',
    summary: 'The token recorder behind the statistics threw while a JWT was ' +
      'being signed; the token is unaffected and is missing from ' +
      '/admin/tokens.',
    spec: '' },
  { code: 'STS-CORE-0028',
    summary: 'A trust realm\'s post-quantum keys could not be generated ' +
      'ahead of time; the first JWKS fetch in that realm makes them instead.',
    spec: '' },
  { code: 'STS-CORE-0029',
    summary: 'The Kerberos KDC\'s TCP/UDP listeners could not start (often ' +
      'port 88 is privileged or taken); the rest of the service runs.',
    spec: '' },
  { code: 'STS-CORE-0030',
    summary: 'The embedded LDAP directory\'s listener could not start; the ' +
      'rest of the service runs.',
    spec: '' },
  { code: 'STS-CORE-0031',
    summary: 'The SPIFFE gRPC listeners could not start; the rest of the ' +
      'service runs.',
    spec: '' },
  { code: 'STS-CORE-0032',
    summary: 'The 8443/9443 TLS endpoints could not start; the rest of the ' +
      'service runs.',
    spec: '' },
  { code: 'STS-CORE-0033',
    summary: 'The last flush at shutdown failed, so the process exited ' +
      'non-zero and a change made just before it may not have been ' +
      'written down.',
    spec: '' },
  { code: 'STS-CORE-0034',
    summary: 'The BBS key pair could not be shared with the request workers; ' +
      'each generates its own and a did:web document may name a key ' +
      'its siblings did not sign with.',
    spec: '' },
  { code: 'STS-CORE-0035',
    summary: 'The service refused to start because its signing key material ' +
      '(or the key-encryption key that opens it) could not be read.',
    spec: '' },
  { code: 'STS-CORE-0036',
    summary: 'The service refused to start because the configured ' +
      'persistence store could not be opened or read.',
    spec: '' },
  { code: 'STS-CORE-0037',
    summary: 'The front page\'s logo could not be read from disk at startup; ' +
      'the page is drawn without it.',
    spec: '' },
  { code: 'STS-CORE-0038',
    summary: 'The logo was requested and none was read at startup.',
    spec: 'HTTP 404 text/plain' },
  { code: 'STS-CORE-0039',
    summary: 'The VERSION file is not M.N and was ignored.',
    spec: '' },
  { code: 'STS-CORE-0040',
    summary: 'No readable VERSION file was found, so the version is reported ' +
      'as 0.0.',
    spec: '' },
  { code: 'STS-CORE-0041',
    summary: 'The build stamp version.json could not be written at image ' +
      'build time.',
    spec: '' },
  { code: 'STS-CORE-0042',
    summary: 'A shared store\'s reconciler threw while deciding whether a ' +
      'restored or replicated row (or its removal) may be applied, so it was ' +
      'not applied and what the process held is unchanged.',
    spec: '' },
  { code: 'STS-CORE-0043',
    summary: 'The plain-HTTP revocation listener (pki.httpPort) could not ' +
      'bind, so every http:// CRL, OCSP and caIssuers address in this ' +
      'service\'s certificates answers nothing.',
    spec: '' },
  { code: 'STS-CORE-0090',
    summary: 'setSubjectResolver() was given an object without both ' +
      'subjectFor() and nameFor(), so no person in this process is issued ' +
      'a subject.',
    spec: 'none — logged' },
  { code: 'STS-CORE-0091',
    summary: 'The subject resolver threw, and the person was given no ' +
      'subject (or a subject was treated as naming nobody).',
    spec: 'none — logged' },
  { code: 'STS-CORE-0092',
    summary: 'A realm\'s key set could not be generated off the event loop; ' +
      'the first read of it generates it on the loop instead.',
    spec: 'none — logged' },
  // ===== WORKER ============================================================
  { code: 'STS-WORKER-0001',
    summary: 'The IPC channel to a post-quantum worker process failed, so a ' +
      'job sent to it may not arrive or its answer may not come back.',
    spec: '' },
  { code: 'STS-WORKER-0002',
    summary: 'A post-quantum worker process exited or was killed with jobs ' +
      'in flight; every one of those jobs was failed and its caller ' +
      'told it can be retried.',
    spec: '' },
  { code: 'STS-WORKER-0003',
    summary: 'Post-quantum worker processes kept exiting immediately without ' +
      'finishing a job, so the pool stopped forking them and ' +
      'computes in the front process (blocking) — usually an ' +
      'unreadable CONFIG_FILE or a machine out of memory.',
    spec: '' },
  { code: 'STS-WORKER-0004',
    summary: 'A post-quantum worker stayed alive and did not answer a job ' +
      'within workers.jobTimeoutS, so the request waiting on it was ' +
      'failed rather than left to hang.',
    spec: '' },
  { code: 'STS-WORKER-0005',
    summary: 'During shutdown a post-quantum worker did not finish within ' +
      'the drain bound and was killed.',
    spec: '' },
  { code: 'STS-WORKER-0006',
    summary: 'A job (post-quantum sign, verify or generate, or a scrypt ' +
      'derivation) threw inside a worker process and was answered as ' +
      'a failure.',
    spec: '' },
  { code: 'STS-WORKER-0007',
    summary: 'A dispatched read waited the full 2000ms barrier bound for an ' +
      'earlier write to be reported committed and was served without ' +
      'it, so it may be stale.',
    spec: '' },
  { code: 'STS-WORKER-0008',
    summary: 'Read-barrier tickets that had been answered for longer than ' +
      'the reap threshold without any worker reporting them committed ' +
      'were dropped — a lost commit announcement, or a flush running ' +
      'that long.',
    spec: '' },
  { code: 'STS-WORKER-0009',
    summary: 'A TLS client certificate was too large to forward to a request ' +
      'worker in a header, so the worker saw the request as having ' +
      'presented no certificate.',
    spec: '' },
  { code: 'STS-WORKER-0010',
    summary: 'The request-worker socket directory or socket file could not ' +
      'be narrowed to owner-only permissions and keeps the process ' +
      'umask.',
    spec: '' },
  { code: 'STS-WORKER-0011',
    summary: 'A request worker asked the front process for a directory ' +
      'sign-out with a connection key the front process could not ' +
      'decode, so nothing was closed for it.',
    spec: '' },
  { code: 'STS-WORKER-0012',
    summary: 'The front process could not close the LDAP connections a ' +
      'request worker asked it to end during a sign-out, so those ' +
      'connections may still be bound.',
    spec: '' },
  { code: 'STS-WORKER-0013',
    summary: 'A realm\'s signing keys or certificate authority could not be ' +
      'handed to a request worker over IPC, so that worker may hold ' +
      'different key material from the rest of the service.',
    spec: '' },
  { code: 'STS-WORKER-0014',
    summary: 'A re-issued TLS listener certificate could not be handed to a ' +
      'request worker, so that worker keeps pinning the previous one ' +
      'and its OpenID Connect back channel fails until it is ' +
      'replaced.',
    spec: '' },
  { code: 'STS-WORKER-0015',
    summary: 'After the certificate hierarchy was rebuilt, the front process ' +
      'could not re-issue its TLS listener certificate under it.',
    spec: '' },
  { code: 'STS-WORKER-0016',
    summary: 'The front process could not send a newly forked request worker ' +
      'its start message.',
    spec: '' },
  { code: 'STS-WORKER-0017',
    summary: 'A request worker reported that it could not start (its socket ' +
      'failed, its state could not be brought up, or it did not ' +
      'finish starting in time).',
    spec: '' },
  { code: 'STS-WORKER-0018',
    summary: 'A request worker\'s unix socket failed to bind or errored, so ' +
      'that worker cannot serve.',
    spec: '' },
  { code: 'STS-WORKER-0019',
    summary: 'A request worker could not bring up its state (the store, the ' +
      'signing keys, the minted rows or coordination) and will not ' +
      'serve.',
    spec: '' },
  { code: 'STS-WORKER-0020',
    summary: 'The IPC channel to a request worker failed.',
    spec: '' },
  { code: 'STS-WORKER-0021',
    summary: 'A request worker died holding answered write requests whose ' +
      'flush it had not reported, so those writes may not have ' +
      'reached the store.',
    spec: '' },
  { code: 'STS-WORKER-0022',
    summary: 'A request worker exited or was killed with requests in flight; ' +
      'each was answered 502.',
    spec: '' },
  { code: 'STS-WORKER-0023',
    summary: 'Request workers kept exiting immediately without serving ' +
      'anything, so the pool stopped forking them and every request ' +
      'is handled in the front process.',
    spec: '' },
  { code: 'STS-WORKER-0024',
    summary: 'The service refused to start: workers.dispatch names paths to ' +
      'hand to request workers but the process is not coordinating ' +
      'through a store, which would make workers answer from ' +
      'divergent private copies.',
    spec: '' },
  { code: 'STS-WORKER-0025',
    summary: 'Not one request worker started, so every request is being ' +
      'handled in the front process.',
    spec: '' },
  { code: 'STS-WORKER-0026',
    summary: 'Only some of the configured request workers started.',
    spec: '' },
  { code: 'STS-WORKER-0027',
    summary: 'A request worker did not answer a read barrier in time, so the ' +
      'request was served from whatever that worker holds, possibly ' +
      'stale.',
    spec: '' },
  { code: 'STS-WORKER-0028',
    summary: 'A request matched workers.dispatch while a pool is configured ' +
      'but no request worker was serving, so it was refused rather ' +
      'than answered from the front process.',
    spec: 'HTTP 503 (Retry-After: 5), plain text' },
  { code: 'STS-WORKER-0029',
    summary: 'A request worker\'s answer failed mid-stream, so the client\'s ' +
      'connection was destroyed with a truncated response.',
    spec: 'connection reset (truncated response)' },
  { code: 'STS-WORKER-0030',
    summary: 'A request worker could not answer a dispatched request (it ' +
      'went away or the proxy connection failed).',
    spec: 'HTTP 502, plain text (or a destroyed connection if headers ' +
      'were already sent)' },
  { code: 'STS-WORKER-0031',
    summary: 'During shutdown a request worker did not finish within the ' +
      'drain bound and was killed.',
    spec: '' },
  { code: 'STS-WORKER-0032',
    summary: 'A request worker could not announce to the front process that ' +
      'its flush committed, so a reader may be told it is current ' +
      'before that write is visible.',
    spec: '' },
  { code: 'STS-WORKER-0033',
    summary: 'A client certificate forwarded by the front process could not ' +
      'be decoded in the request worker and was treated as absent.',
    spec: '' },
  { code: 'STS-WORKER-0034',
    summary: 'A request worker could not send a message to the front process ' +
      'over IPC.',
    spec: '' },
  { code: 'STS-WORKER-0035',
    summary: 'A request worker could not announce that a dispatched protocol ' +
      'operation finished, so a reader may wait the full barrier ' +
      'bound for it.',
    spec: '' },
  { code: 'STS-WORKER-0036',
    summary: 'A request worker\'s read barrier (catching up with the change ' +
      'log) threw unexpectedly; the front process was told it could ' +
      'not catch up.',
    spec: '' },
  { code: 'STS-WORKER-0037',
    summary: 'A client certificate\'s issuer chain was too large to forward ' +
      'to a request worker beside the leaf, so the worker saw the leaf alone ' +
      'and could not verify a foreign CRL about it.',
    spec: '' },
  { code: 'STS-WORKER-0038',
    summary: 'The service refused to start: workers.surfaceCount gives the ' +
      'admin console and the user portal request workers of their own and ' +
      'workers.readYourWrite is off, so a sign-in crossing the two pools ' +
      'would intermittently read a session that had not yet arrived.',
    spec: '' },
  { code: 'STS-WORKER-0039',
    summary: 'workers.surfaceCount is set and workers.dispatch names none of ' +
      'workers.surfaces, so the hosted-surface workers were not started.',
    spec: '' },
  { code: 'STS-WORKER-0040',
    summary: 'A batch request (workers.batch) was refused because ' +
      'workers.batchQueueLimit batch requests were already waiting for the ' +
      'pool\'s batch lane.',
    spec: 'HTTP 503 with Retry-After' },
  { code: 'STS-WORKER-0041',
    summary: 'A batch request (workers.batch) waited ' +
      'workers.batchQueueTimeoutS for the pool\'s batch lane and was refused.',
    spec: 'HTTP 503 with Retry-After' },
  // ===== STORE =============================================================
  { code: 'STS-STORE-0001',
    summary: 'A scheduled persistence flush threw past its own handler.',
    spec: '' },
  { code: 'STS-STORE-0002',
    summary: 'Writing the directory, the realm registry or the settings ' +
      'overrides to the persistence store failed; the service keeps ' +
      'answering from memory and retries on the next change.',
    spec: '' },
  { code: 'STS-STORE-0003',
    summary: 'persistence.mode names a mode the persistence module does not ' +
      'know, so nothing is persisted.',
    spec: '' },
  { code: 'STS-STORE-0004',
    summary: 'The service refused to start: a persisting mode is configured ' +
      'and no directory module is installed to persist.',
    spec: '' },
  { code: 'STS-STORE-0005',
    summary: 'The service refused to start: the database password comes from ' +
      'a secret store but persistence.databaseUrl is not a URL it ' +
      'can be injected into.',
    spec: '' },
  { code: 'STS-STORE-0006',
    summary: 'The service refused to start: the configured persistence store ' +
      'could not be opened or read.',
    spec: '' },
  { code: 'STS-STORE-0007',
    summary: 'A realm stored in the persistence store could not be recreated ' +
      'at startup and was skipped.',
    spec: '' },
  { code: 'STS-STORE-0008',
    summary: 'The final flush or close of the persistence store at shutdown ' +
      'failed; changes since the last successful write are lost.',
    spec: '' },
  { code: 'STS-STORE-0009',
    summary: 'The store holds directory entries for a realm that is not ' +
      'defined; they are not loaded and the next write removes them.',
    spec: '' },
  { code: 'STS-STORE-0010',
    summary: 'Lines of an LDIF store file were not loaded (a URL-valued ' +
      'attribute or a line before the first dn:).',
    spec: '' },
  { code: 'STS-STORE-0011',
    summary: 'The LDIF store\'s keys.json could not be parsed.',
    spec: '' },
  { code: 'STS-STORE-0012',
    summary: 'Product mode asked for minted state to persist on a store that ' +
      'cannot hold it (ldif); sessions, tokens and the audit log ' +
      'stay in memory.',
    spec: '' },
  { code: 'STS-STORE-0013',
    summary: 'A batched read of minted rows during replication failed; the ' +
      'page falls back to one query per row.',
    spec: '' },
  { code: 'STS-STORE-0014',
    summary: 'A replicated minted-row change carried a key that is not the ' +
      'shape this service writes, and was skipped.',
    spec: '' },
  { code: 'STS-STORE-0015',
    summary: 'Another process\'s minted row could not be opened because this ' +
      'process has no key-encryption key; this process is behind.',
    spec: '' },
  { code: 'STS-STORE-0016',
    summary: 'Another process\'s minted row would not open under this ' +
      'process\'s key-encryption key, and was skipped.',
    spec: '' },
  { code: 'STS-STORE-0017',
    summary: 'Another process\'s minted row opened and is not JSON, and was ' +
      'skipped.',
    spec: '' },
  { code: 'STS-STORE-0018',
    summary: 'Minted state could not be written because no key-encryption ' +
      'key is available to seal it.',
    spec: '' },
  { code: 'STS-STORE-0019',
    summary: 'A handle that is not a declared store reported a minted write; ' +
      'its rows cannot be written.',
    spec: '' },
  { code: 'STS-STORE-0020',
    summary: 'A minted store holds a value that will not serialise, so that ' +
      'row cannot be written.',
    spec: '' },
  { code: 'STS-STORE-0021',
    summary: 'Writing minted state (sessions, tokens, codes, the audit log) ' +
      'to the store failed; the keys stay journalled and the next ' +
      'flush retries.',
    spec: '' },
  { code: 'STS-STORE-0022',
    summary: 'The service refused to start: minted state is persisted but no ' +
      'key-encryption key is available to open it.',
    spec: '' },
  { code: 'STS-STORE-0023',
    summary: 'An earlier run\'s unreadable minted rows could not be cleared ' +
      'from the store.',
    spec: '' },
  { code: 'STS-STORE-0024',
    summary: 'A store refused a minted row restored at startup; the row was ' +
      'dropped.',
    spec: '' },
  { code: 'STS-STORE-0025',
    summary: 'Minted rows older than persistence.mintedRetention could not ' +
      'be purged from the store.',
    spec: '' },
  { code: 'STS-STORE-0026',
    summary: 'The service refused to start: the minted state in the store ' +
      'could not be read.',
    spec: '' },
  { code: 'STS-STORE-0027',
    summary: 'The service refused to start: persistence.mode is postgres and ' +
      'persistence.databaseUrl was set to empty.',
    spec: '' },
  { code: 'STS-STORE-0028',
    summary: 'The service refused to start: persistence.mode is postgres and ' +
      'the pg package is not installed.',
    spec: '' },
  { code: 'STS-STORE-0029',
    summary: 'The postgres store could not be opened because the schema is ' +
      'missing or the connecting role lacks permission on it (build ' +
      'it with postgres/schema.sql).',
    spec: '' },
  { code: 'STS-STORE-0030',
    summary: 'An idle pooled postgres client errored (typically a database ' +
      'restart); the pool makes a new one.',
    spec: '' },
  { code: 'STS-STORE-0031',
    summary: 'A checked-out postgres connection errored while in use; it is ' +
      'discarded.',
    spec: '' },
  { code: 'STS-STORE-0032',
    summary: 'A postgres transaction\'s ROLLBACK failed; the connection is ' +
      'discarded.',
    spec: '' },
  { code: 'STS-STORE-0033',
    summary: 'A postgres metrics connection could not be RESET and is ' +
      'discarded rather than returned to the pool.',
    spec: '' },
  { code: 'STS-STORE-0034',
    summary: 'The database metrics could not be collected (no connection).',
    spec: '' },
  { code: 'STS-STORE-0035',
    summary: 'The postgres LISTEN connection for change notifications ' +
      'dropped; it reconnects and the poll covers the gap.',
    spec: '' },
  { code: 'STS-STORE-0036',
    summary: 'The postgres LISTEN connection for change notifications could ' +
      'not connect; the poll still converges.',
    spec: '' },
  { code: 'STS-STORE-0037',
    summary: 'The change log could not be read at startup, so this process ' +
      'runs uncoordinated and keeps retrying.',
    spec: '' },
  { code: 'STS-STORE-0038',
    summary: 'A pull of other processes\' changes from the change log ' +
      'failed; this process is behind until a retry succeeds.',
    spec: '' },
  { code: 'STS-STORE-0039',
    summary: 'A read barrier gave up before catching up with the change log; ' +
      'the request is answered from this process\'s copy.',
    spec: '' },
  { code: 'STS-STORE-0040',
    summary: 'A read barrier could not read the change log; the request is ' +
      'answered from this process\'s copy.',
    spec: '' },
  { code: 'STS-STORE-0041',
    summary: 'Preparing a page of replicated rows of one kind failed; they ' +
      'are applied one at a time.',
    spec: '' },
  { code: 'STS-STORE-0042',
    summary: 'One replicated change could not be applied in this process; ' +
      'the rest of the page is unaffected.',
    spec: '' },
  { code: 'STS-STORE-0043',
    summary: 'Clearing an applier\'s per-page replication state failed.',
    spec: '' },
  { code: 'STS-STORE-0044',
    summary: 'The open persistence driver has no used-assertion functions, ' +
      'so the used-assertion history is held in this process and forgotten ' +
      'at a restart.',
    spec: '' },
  { code: 'STS-STORE-0045',
    summary: 'Writing the used-assertion history to a file store failed; a ' +
      'claim that could not be written is refused, a confirmation is lost.',
    spec: '' },
  { code: 'STS-STORE-0046',
    summary: 'The database store could not be asked whether an assertion ' +
      'has been used; the assertion is refused.',
    spec: '' },
  { code: 'STS-STORE-0047',
    summary: 'Sweeping expired used-assertion rows, or removing a removed ' +
      'realm\'s, failed; the rows are ignored by every read and expire.',
    spec: '' },
  { code: 'STS-STORE-0048',
    summary: 'Confirming or releasing a used-assertion claim when its ' +
      'response finished failed; the row stays reserved until the assertion ' +
      'expires.',
    spec: '' },
  { code: 'STS-STORE-0049',
    summary: 'A change-log sequence number this process stepped past never ' +
      'became visible within the hole lifetime, and is no longer asked for; ' +
      'it was a transaction that rolled back.',
    spec: '' },
  { code: 'STS-STORE-0050',
    summary: 'A conditional write of a signing-key or certificate-authority ' +
      'row found the row inserted and removed by other writers twice while ' +
      'it waited, and wrote nothing.',
    spec: '' },
  { code: 'STS-STORE-0051',
    summary: 'A certificate authority another node wrote was adopted and the ' +
      'TLS listener could not be reconciled with it.',
    spec: '' },
  { code: 'STS-STORE-0052',
    summary: 'A directory entry this process added was already in the store ' +
      'as a DIFFERENT entry another node created first; the stored entry ' +
      'was kept and this process\'s copy replaced by it.',
    spec: 'none — logged' },
  { code: 'STS-STORE-0053',
    summary: 'A change to a directory entry was not written because another ' +
      'node deleted the entry after this process last saw it; the entry ' +
      'was removed here too.',
    spec: 'none — logged' },
  { code: 'STS-STORE-0054',
    summary: 'A minted row (a session, a code, a token) was not written back ' +
      'because another node had already ended it and the store holds its ' +
      'tombstone; this process\'s copy was dropped.',
    spec: 'none — logged' },
  { code: 'STS-STORE-0055',
    summary: 'Expired tombstones of ended minted rows could not be swept from ' +
      'the store.',
    spec: 'none — logged' },
  { code: 'STS-STORE-0056',
    summary: 'A minted row another node had changed could not be merged with ' +
      'this process\'s copy (it would not open or the merge threw), so this ' +
      'process\'s copy was written as it was.',
    spec: 'none — logged' },
  // #46 section 8 (2026-09-14): change-log retention,
  // persistence/persistence_replication.js.
  { code: 'STS-STORE-0057',
    summary: 'A process found its place among the change log\'s readers ' +
      'removed since it last reported: it had been declared gone, so changes ' +
      'it had not applied may have been trimmed. It should be restarted.',
    spec: '' },
  { code: 'STS-STORE-0058',
    summary: 'A process could not report its position in the change log; ' +
      'the log is not trimmed past where it last said it was, and the ' +
      'report is retried after the next pull.',
    spec: '' },
  { code: 'STS-STORE-0059',
    summary: 'Trimming the change log below every reader\'s position failed; ' +
      'it is retried on the next interval.',
    spec: '' },
  // ===== CLUSTER ===========================================================
  { code: 'STS-CLUSTER-0001',
    summary: 'A write transaction was refused by the fence: this node\'s ' +
      'membership row had expired, or a lease the write needed was no longer ' +
      'held at the token it was acquired with.',
    spec: '' },
  { code: 'STS-CLUSTER-0002',
    summary: 'This node was refused membership because a live node is ' +
      'running a different cluster mode or a different fingerprint of the ' +
      'settings every node must share; it does not start.',
    spec: '' },
  { code: 'STS-CLUSTER-0003',
    summary: 'A heartbeat could not be written; the node keeps serving until ' +
      'its membership would expire.',
    spec: '' },
  { code: 'STS-CLUSTER-0004',
    summary: 'This node could not renew its membership within its lifetime ' +
      'and exits, because the others may already treat it as dead.',
    spec: '' },
  { code: 'STS-CLUSTER-0005',
    summary: 'This node\'s membership row had already expired when it tried ' +
      'to renew it, so it exits rather than come back.',
    spec: '' },
  { code: 'STS-CLUSTER-0006',
    summary: 'This node lost a lease that its role depends on (the service ' +
      'lease in active-passive mode) and exits.',
    spec: '' },
  { code: 'STS-CLUSTER-0007',
    summary: 'A cluster mode other than off was configured without a ' +
      'postgres persistence store; the service does not start.',
    spec: '' },
  { code: 'STS-CLUSTER-0008',
    summary: 'Active-active mode was configured without persisted keys under ' +
      'an operator key-encryption key, which every node must share; the ' +
      'service does not start.',
    spec: '' },
  { code: 'STS-CLUSTER-0009',
    summary: 'Active-active mode was refused because capabilities it depends ' +
      'on are not provided by this build and were not accepted as missing; ' +
      'the service does not start.',
    spec: '' },
  { code: 'STS-CLUSTER-0010',
    summary: 'Leaving the cluster on shutdown failed; this node\'s row and ' +
      'leases expire on their own.',
    spec: '' },
  { code: 'STS-CLUSTER-0011',
    summary: 'A write was fenced and this process exits, because a process ' +
      'that has lost its right to write would try again on the next change.',
    spec: '' },
  { code: 'STS-CLUSTER-0012',
    summary: 'Asking the store for a lease failed; the role is not taken and ' +
      'is asked for again on the next heartbeat.',
    spec: '' },
  { code: 'STS-CLUSTER-0013',
    summary: 'The claim store could not be asked; the single-use value is ' +
      'refused rather than accepted unrecorded.',
    spec: '' },
  { code: 'STS-CLUSTER-0014',
    summary: 'Releasing a claim failed; it stays held until it expires.',
    spec: '' },
  { code: 'STS-CLUSTER-0015',
    summary: 'Sweeping expired claims failed; they are ignored by every read ' +
      'and swept on the next attempt.',
    spec: '' },
  { code: 'STS-CLUSTER-0016',
    summary: 'A secret every node must share could not be written to or read ' +
      'from the store; the service does not start.',
    spec: '' },
  { code: 'STS-CLUSTER-0017',
    summary: 'A shared secret could not be sealed or opened with the ' +
      'key-encryption key; the service does not start.',
    spec: '' },
  { code: 'STS-CLUSTER-0018',
    summary: 'A request could not catch up with the other nodes\' committed ' +
      'writes before it was served; it is answered from this process\'s ' +
      'copy.',
    spec: '' },
  { code: 'STS-CLUSTER-0019',
    summary: 'A response held until its writes committed could not commit ' +
      'them; it is sent anyway and the writes are retried.',
    spec: '' },
  { code: 'STS-CLUSTER-0020',
    summary: 'Active-active mode is running with capabilities an operator ' +
      'accepted as missing; each named one is a known way nodes disagree.',
    spec: '' },
  { code: 'STS-CLUSTER-0021',
    summary: 'A request worker could not attach to its node\'s cluster ' +
      'membership; the worker does not start.',
    spec: '' },
  { code: 'STS-CLUSTER-0022',
    summary: 'A counter that may only go up (a WebAuthn signature counter, ' +
      'a one-time code step) could not be advanced because the store could ' +
      'not be asked; the credential is refused.',
    spec: '' },
  { code: 'STS-CLUSTER-0023',
    summary: 'A rate-limit window every node counts in could not be counted, ' +
      'read or cleared because the store could not be asked; the limiter ' +
      'decided on this process\'s own buckets for that attempt.',
    spec: '' },
  { code: 'STS-CLUSTER-0024',
    summary: 'Sweeping the rate-limit windows whose time has passed failed; ' +
      'they are swept on a later count.',
    spec: '' },
  { code: 'STS-CLUSTER-0025',
    summary: 'A node\'s heartbeat ran late by a heartbeat or more because ' +
      'its event loop was busy; a stall past the membership lifetime costs the ' +
      'node its membership.',
    spec: '' },
  { code: 'STS-CLUSTER-0026',
    summary: 'Active-active mode was refused because global.publicBaseUrl is ' +
      'empty, so each node would name itself by the address it was reached ' +
      'on.',
    spec: '' },
  { code: 'STS-CLUSTER-0040',
    summary: 'A cluster mode was configured with persistence.minted off, so ' +
      'nodes would not share sessions, pending sign-ins, codes or tokens; ' +
      'the service does not start.',
    spec: '' },
  // ===== KEYS ==============================================================
  { code: 'STS-KEYS-0001',
    summary: 'The artifact logger handed to an XML encryption threw and was ' +
      'ignored.',
    spec: '' },
  { code: 'STS-KEYS-0002',
    summary: 'The key-encryption key is empty or shorter than 32 bytes and ' +
      'was refused rather than stretched.',
    spec: '' },
  { code: 'STS-KEYS-0003',
    summary: 'This runtime cannot generate ML-DSA keys (it needs OpenSSL 3.5 ' +
      '/ node 24); ML-DSA certificates are unavailable.',
    spec: '' },
  { code: 'STS-KEYS-0004',
    summary: 'A stored password or secret hash is not decodable and was ' +
      'treated as no match.',
    spec: '' },
  { code: 'STS-KEYS-0005',
    summary: 'A stored password or secret hash names scrypt parameters this ' +
      'process cannot compute and was treated as no match.',
    spec: '' },
  { code: 'STS-KEYS-0006',
    summary: 'The worker pool could not run a scrypt derivation, so it was ' +
      'computed in the front process instead.',
    spec: '' },
  { code: 'STS-KEYS-0007',
    summary: 'An XML signature was not verified: the document is not ' +
      'well-formed XML.',
    spec: 'refusal by the calling protocol (e.g. SAML Responder status, ' +
      'SOAP fault)' },
  { code: 'STS-KEYS-0008',
    summary: 'An XML signature was not verified: the named element is absent ' +
      'or carries no ds:Signature of its own.',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0009',
    summary: 'An XML signature was refused because its Reference names a ' +
      'different element than the one it is attached to (signature ' +
      'wrapping).',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0010',
    summary: 'An XML signature on a nested element uses inclusive ' +
      'canonicalization, which this service cannot reproduce, and was ' +
      'refused.',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0011',
    summary: 'The XML signature engine threw on a malformed signature ' +
      'element or an unknown algorithm.',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0012',
    summary: 'An XML signature value does not verify against the expected ' +
      'certificate or key.',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0013',
    summary: 'An XML signature is genuine but the digest does not match: the ' +
      'signed element was altered.',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0014',
    summary: 'An XML signature did not verify for a reason other than the ' +
      'signature value or the digest.',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0015',
    summary: 'An XML-encrypted element could not be decrypted: it is not ' +
      'well-formed XML.',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0016',
    summary: 'An XML-encrypted element could not be decrypted: it contains ' +
      'no xenc:EncryptedData.',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0017',
    summary: 'An XML-encrypted element uses a block cipher this service does ' +
      'not read.',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0018',
    summary: 'An XML-encrypted element carries no xenc:EncryptedKey in its ' +
      'KeyInfo (RetrievalMethod is not implemented).',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0019',
    summary: 'An XML-encrypted element wraps its key with a key transport ' +
      'this service does not unwrap.',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0020',
    summary: 'An XML-encrypted element is missing one of its two ' +
      'xenc:CipherValue elements.',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0021',
    summary: 'An XML-encrypted element\'s wrapped key unwrapped to the wrong ' +
      'length: it was encrypted to a different certificate.',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0022',
    summary: 'An XML-encrypted element failed its AES-GCM authentication tag ' +
      'or AES-CBC padding check.',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0023',
    summary: 'An XML-encrypted element decrypted to something that is not ' +
      'well-formed XML.',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0024',
    summary: 'An XML-encrypted element\'s key could not be unwrapped with ' +
      'this service\'s private key.',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0025',
    summary: 'An XML-encrypted element could not be read for a reason other ' +
      'than the key.',
    spec: 'refusal by the calling protocol' },
  { code: 'STS-KEYS-0026',
    summary: 'The keystore was handed a store without both loadKeys and ' +
      'saveKeys, and refused it whole.',
    spec: '' },
  { code: 'STS-KEYS-0027',
    summary: 'The service refused to start: signing keys are configured to ' +
      'persist and no persistence store is open.',
    spec: '' },
  { code: 'STS-KEYS-0028',
    summary: 'The service refused to start: the stored signing key material ' +
      'could not be loaded from the store.',
    spec: '' },
  { code: 'STS-KEYS-0029',
    summary: 'The service refused to start: stored signing key material ' +
      'could not be decrypted, almost certainly because the ' +
      'key-encryption key is not the one it was sealed with.',
    spec: '' },
  { code: 'STS-KEYS-0030',
    summary: 'Signing keys adopted from another process could not be held, ' +
      'or this process\'s cached set could not be dropped, so it keeps ' +
      'signing with its own and disagrees with the rest of the ' +
      'service.',
    spec: '' },
  { code: 'STS-KEYS-0031',
    summary: 'A realm\'s signing keys could not be serialised for sharing ' +
      'with other processes, so another process may hold different ' +
      'keys.',
    spec: '' },
  { code: 'STS-KEYS-0032',
    summary: 'A realm\'s stored key material is held encrypted and there is ' +
      'no key-encryption key to open it, so a new signing key is ' +
      'generated.',
    spec: '' },
  { code: 'STS-KEYS-0033',
    summary: 'A realm\'s key material decrypted at startup and no longer ' +
      'decrypts (corruption or a bug).',
    spec: '' },
  { code: 'STS-KEYS-0034',
    summary: 'A realm\'s generated signing keys cannot be written (no store ' +
      'open or no key-encryption key), so they will differ after the ' +
      'next restart.',
    spec: '' },
  { code: 'STS-KEYS-0035',
    summary: 'Writing a realm\'s signing keys to the store failed, so they ' +
      'will differ after the next restart.',
    spec: '' },
  { code: 'STS-KEYS-0036',
    summary: 'Rotation could not remove a realm\'s stored signing keys.',
    spec: '' },
  { code: 'STS-KEYS-0037',
    summary: 'A realm was removed and its stored signing keys could not be ' +
      'removed with it.',
    spec: '' },
  { code: 'STS-KEYS-0038',
    summary: 'An ephemeral key-encryption key was offered while the keystore ' +
      'persists, and was refused.',
    spec: '' },
  { code: 'STS-KEYS-0039',
    summary: 'The ephemeral key-encryption key handed to this process was ' +
      'not usable.',
    spec: '' },
  { code: 'STS-KEYS-0040',
    summary: 'A value could not be sealed under the key-encryption key.',
    spec: '' },
  { code: 'STS-KEYS-0041',
    summary: 'A realm\'s certificate authority cannot be written (no store ' +
      'open or no key-encryption key), so it will be gone after the ' +
      'next restart.',
    spec: '' },
  { code: 'STS-KEYS-0042',
    summary: 'Writing a realm\'s certificate authority to the store failed.',
    spec: '' },
  { code: 'STS-KEYS-0043',
    summary: 'The key-encryption key could not be read from its configured ' +
      'secret provider.',
    spec: '' },
  { code: 'STS-KEYS-0044',
    summary: 'The database password could not be read from its configured ' +
      'secret provider.',
    spec: '' },
  { code: 'STS-KEYS-0045',
    summary: 'A secret provider\'s SDK package is not installed (it is an ' +
      'optional peer dependency).',
    spec: '' },
  { code: 'STS-KEYS-0046',
    summary: 'A secret provider is selected but its location (file path, ' +
      'secret id, resource name, vault URL or read path) is not ' +
      'configured.',
    spec: '' },
  { code: 'STS-KEYS-0047',
    summary: 'The file holding a secret could not be read.',
    spec: '' },
  { code: 'STS-KEYS-0048',
    summary: 'A secret store answered with no value, or without the named ' +
      'field.',
    spec: '' },
  { code: 'STS-KEYS-0049',
    summary: 'The database password\'s location is shared with the ' +
      'key-encryption key and holds something that is not a JSON ' +
      'object, so it was refused rather than handing the key to a ' +
      'database.',
    spec: '' },
  { code: 'STS-KEYS-0050',
    summary: 'A secret\'s provider setting names a provider that does not ' +
      'exist.',
    spec: '' },
  { code: 'STS-KEYS-0051',
    summary: 'The secret store accepted the client certificate at the cert ' +
      'auth method and returned no token.',
    spec: '' },
  { code: 'STS-KEYS-0052',
    summary: 'keys.vaultCertAuthMount is not a mount path this service will ' +
      'put into a request.',
    spec: '' },
  { code: 'STS-KEYS-0053',
    summary: 'The database password read from its secret provider is empty ' +
      'and was refused.',
    spec: '' },
  { code: 'STS-KEYS-0054',
    summary: 'The file holding a secret is readable by group or other.',
    spec: '' },
  { code: 'STS-KEYS-0055',
    summary: 'keys.kidFormat asks for an RFC 9278 JWK Thumbprint URI and ' +
      'none could be computed for a signing key, so its tokens carry the ' +
      'internal kid. Logged once per key.',
    spec: 'none — the token is signed under its internal kid' },
  { code: 'STS-KEYS-0056',
    summary: 'A queued write of a signing-key or certificate-authority row ' +
      'failed in a way its own handler did not report.',
    spec: '' },
  { code: 'STS-KEYS-0057',
    summary: 'A certificate authority row was changed by another node at the ' +
      'same moment, and that node\'s CA tier or certificate slot was kept ' +
      'over this one\'s (first writer wins).',
    spec: '' },
  { code: 'STS-KEYS-0058',
    summary: 'A signing-key or certificate-authority row another process ' +
      'wrote could not be decrypted or parsed, so it was not adopted.',
    spec: '' },
  // ===== PKI ===============================================================
  { code: 'STS-PKI-0001',
    summary: 'A certificate-authority use case prefers a key algorithm this ' +
      'service cannot use, so its Issuing CA was built with the ' +
      'branch\'s algorithm instead.',
    spec: '' },
  { code: 'STS-PKI-0002',
    summary: 'A build, issue, key generation or export named a key algorithm ' +
      'this service cannot generate.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0003',
    summary: 'A build or issue named a signature algorithm this service ' +
      'cannot produce.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0004',
    summary: 'The signing key cannot produce the signature algorithm asked ' +
      'for (the key and signature families disagree).',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0005',
    summary: 'The Root CA could not be issued by the certificate encoder; ' +
      'nothing was stored.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0006',
    summary: 'A scope\'s Intermediate CA could not be issued by the ' +
      'certificate encoder; nothing was stored.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0007',
    summary: 'One of a scope\'s Issuing CAs could not be issued while ' +
      'building its branch; nothing was stored.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0008',
    summary: 'The realm has no certificate authority (no hierarchy or ' +
      'branch), so nothing can be issued from, cleared or certified ' +
      'under it.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0009',
    summary: 'The scope has no Issuing CA for the use case a certificate was ' +
      'asked for.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0010',
    summary: 'A signing key pair was asked for without naming what it is ' +
      'issued to.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0011',
    summary: 'A signing key pair was asked for with a purpose (profile) this ' +
      'service does not issue.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0012',
    summary: 'A signing key pair was asked for with a subject kind (target) ' +
      'this service does not issue to.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0013',
    summary: 'The certificate for an application or person signing key pair ' +
      'could not be issued by the encoder.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0014',
    summary: 'A certificate path was checked in a realm that has no ' +
      'certificate authority, so there is no anchor.',
    spec: 'invalid_client or invalid_grant (HTTP 400/401), where an ' +
      'assertion x5c path is being checked' },
  { code: 'STS-PKI-0015',
    summary: 'A presented certificate path could not be parsed.',
    spec: 'invalid_client or invalid_grant (HTTP 400/401), where an ' +
      'assertion x5c path is being checked' },
  { code: 'STS-PKI-0016',
    summary: 'A link in a presented certificate path is not signed by the ' +
      'certificate above it.',
    spec: 'invalid_client or invalid_grant (HTTP 400/401), where an ' +
      'assertion x5c path is being checked' },
  { code: 'STS-PKI-0017',
    summary: 'A certificate in a presented path names an issuer that is not ' +
      'the next certificate\'s subject.',
    spec: 'invalid_client or invalid_grant (HTTP 400/401), where an ' +
      'assertion x5c path is being checked' },
  { code: 'STS-PKI-0018',
    summary: 'A certificate in a presented path has expired.',
    spec: 'invalid_client or invalid_grant (HTTP 400/401), where an ' +
      'assertion x5c path is being checked' },
  { code: 'STS-PKI-0019',
    summary: 'A certificate in a presented path is not valid yet.',
    spec: 'invalid_client or invalid_grant (HTTP 400/401), where an ' +
      'assertion x5c path is being checked' },
  { code: 'STS-PKI-0020',
    summary: 'A presented certificate path is internally consistent and does ' +
      'not end at this service\'s Root CA (a foreign anchor).',
    spec: 'invalid_client or invalid_grant (HTTP 400/401), where an ' +
      'assertion x5c path is being checked' },
  { code: 'STS-PKI-0021',
    summary: 'A presented certificate path ends at this service\'s Root and ' +
      'does not pass through this realm\'s own Intermediate CA (issued ' +
      'in another realm).',
    spec: 'invalid_client or invalid_grant (HTTP 400/401), where an ' +
      'assertion x5c path is being checked' },
  { code: 'STS-PKI-0022',
    summary: 'A certificate-authority operation named a use case that does ' +
      'not exist.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0023',
    summary: 'A branch that no longer chains to the current Root could not ' +
      'be rebuilt before issuing, so nothing was certified.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0024',
    summary: 'A leaf certificate under a use case\'s Issuing CA could not be ' +
      'issued by the encoder.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0025',
    summary: 'A certificate was to be forgotten from a slot that holds none.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0026',
    summary: 'A certificate was to be issued under an Issuing CA with no ' +
      'subject public key given.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0027',
    summary: 'The realm\'s PKI object store is full (pki.maxStoredObjects), ' +
      'so a new object was refused rather than evicting one.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0028',
    summary: 'An object-store removal or clear was asked for on a realm ' +
      'whose store is empty.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0029',
    summary: 'An object named in the PKI object store does not exist.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0030',
    summary: 'A realm\'s signing key could not be read in order to certify ' +
      'it.',
    spec: '' },
  { code: 'STS-PKI-0031',
    summary: 'Some of a realm\'s signing keys could not be certified under ' +
      'its Intermediate; they still sign, self-signed.',
    spec: '' },
  { code: 'STS-PKI-0032',
    summary: 'Some certificates under an Issuing CA could not be re-minted ' +
      'during a renewal or reissue.',
    spec: '' },
  { code: 'STS-PKI-0033',
    summary: 'A replaced certificate could not be put on its issuer\'s ' +
      'revocation list as superseded.',
    spec: '' },
  { code: 'STS-PKI-0034',
    summary: 'A scope has no Intermediate CA (no branch), so an Issuing CA ' +
      'cannot be reissued or imported into it.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0035',
    summary: 'A use case belongs to another scope kind (realm or process) ' +
      'than the one named.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0036',
    summary: 'An Issuing CA could not be re-issued with a new key pair by ' +
      'the encoder.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0037',
    summary: 'A CA import was missing the certificate or its private key.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0038',
    summary: 'A certificate supplied for import or pinning could not be ' +
      'read.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0039',
    summary: 'A private key supplied for import or pinning could not be ' +
      'read.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0040',
    summary: 'A supplied private key does not belong to the supplied ' +
      'certificate.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0041',
    summary: 'A certificate supplied as a CA is not a CA (basicConstraints ' +
      'cA:FALSE).',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0042',
    summary: 'A key pair was pinned without naming the slot it is for.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0043',
    summary: 'A key pair was pinned without a private key.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0044',
    summary: 'A module registered key material for certification without a ' +
      'known use case, slot or publicKeyPem function; the ' +
      'registration was refused.',
    spec: '' },
  { code: 'STS-PKI-0045',
    summary: 'A registered module\'s public key could not be read to certify ' +
      'it at startup.',
    spec: '' },
  { code: 'STS-PKI-0046',
    summary: 'A registered module\'s key could not be certified at startup; ' +
      'it still works, self-signed.',
    spec: '' },
  { code: 'STS-PKI-0047',
    summary: 'A registered key was certified and the module that owns it ' +
      'threw when told.',
    spec: '' },
  { code: 'STS-PKI-0048',
    summary: 'At startup the service could not obtain a Root CA; every key ' +
      'is self-signed.',
    spec: '' },
  { code: 'STS-PKI-0049',
    summary: 'At startup the process certificate-authority branch (TLS, ' +
      'SPIFFE) could not be built.',
    spec: '' },
  { code: 'STS-PKI-0050',
    summary: 'At startup a realm\'s certificate-authority branch could not ' +
      'be built.',
    spec: '' },
  { code: 'STS-PKI-0051',
    summary: 'At startup the default realm\'s signing keys could not be ' +
      'certified; they still sign, self-signed.',
    spec: '' },
  { code: 'STS-PKI-0052',
    summary: 'At startup the certificate revocation lists could not be ' +
      'published into the directory; the LDAP distribution points do ' +
      'not answer.',
    spec: '' },
  { code: 'STS-PKI-0053',
    summary: 'A realm created at runtime could not get a ' +
      'certificate-authority branch; its keys stay self-signed.',
    spec: '' },
  { code: 'STS-PKI-0054',
    summary: 'Setting up the certificate authority for a realm created at ' +
      'runtime threw.',
    spec: '' },
  { code: 'STS-PKI-0055',
    summary: 'A revocation, release or CRL named a certificate authority the ' +
      'scope does not hold.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0056',
    summary: 'A revocation named no serial number.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0057',
    summary: 'A revocation named a reason that is not an RFC 5280 section ' +
      '5.3.1 reason.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0058',
    summary: 'A hold was to be released on a serial that is not on the ' +
      'authority\'s revocation list.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0059',
    summary: 'A release was asked for on a certificate revoked for a ' +
      'permanent reason (only certificateHold can be released).',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0060',
    summary: 'The directory hook for publishing CRLs was offered without ' +
      'both publishCrl() and baseDnFor(), and was refused whole.',
    spec: '' },
  { code: 'STS-PKI-0061',
    summary: 'The directory could not say where a scope lives; the CRL DN ' +
      'falls back to one built from ldap.baseDn.',
    spec: '' },
  { code: 'STS-PKI-0062',
    summary: 'The Web Crypto engine pkijs needs could not be installed; CRLs ' +
      'and OCSP responses cannot be signed.',
    spec: '' },
  { code: 'STS-PKI-0063',
    summary: 'A certificate revocation list could not be signed with its ' +
      'authority\'s key.',
    spec: 'HTTP 500 text at /pki/crl; console refusal' },
  { code: 'STS-PKI-0064',
    summary: 'A certificate revocation list could not be published into the ' +
      'directory (write-behind after a revocation, or at startup).',
    spec: '' },
  { code: 'STS-PKI-0065',
    summary: 'An OCSP request was sent to an address with no certificate ' +
      'authority behind it.',
    spec: 'OCSP responseStatus unauthorized (6), HTTP 200' },
  { code: 'STS-PKI-0066',
    summary: 'An OCSP request could not be parsed.',
    spec: 'OCSP responseStatus malformedRequest (1), HTTP 200' },
  { code: 'STS-PKI-0067',
    summary: 'An OCSP response could not be signed with its authority\'s key.',
    spec: 'OCSP responseStatus internalError (2), HTTP 200' },
  { code: 'STS-PKI-0068',
    summary: 'A CRL was requested for a certificate authority this service ' +
      'does not hold.',
    spec: 'HTTP 404 text/plain' },
  { code: 'STS-PKI-0069',
    summary: 'The CRL endpoint failed while building a CRL.',
    spec: 'HTTP 500 text/plain' },
  { code: 'STS-PKI-0070',
    summary: 'An authority\'s CA certificate (caIssuers) was requested for ' +
      'an authority this service does not hold.',
    spec: 'HTTP 404 text/plain' },
  { code: 'STS-PKI-0071',
    summary: 'An OCSP GET request path segment was not a base64 DER request. ' +
      'Retired 2026-09-13: such a request does not conform to the OCSP ' +
      'syntax and is answered malformedRequest inside the protocol ' +
      '(STS-PKI-0066), as RFC 6960 section 2.3 asks.',
    spec: 'HTTP 400 text/plain', retired: true },
  { code: 'STS-PKI-0072',
    summary: 'An OCSP request arrived with no body. Retired 2026-09-13, for ' +
      'STS-PKI-0071\'s reason: it is answered malformedRequest ' +
      '(STS-PKI-0066).',
    spec: 'HTTP 400 text/plain', retired: true },
  { code: 'STS-PKI-0073',
    summary: 'An OCSP POST body was larger than the 64KB this responder ' +
      'accepts.',
    spec: 'HTTP 413 text/plain' },
  { code: 'STS-PKI-0074',
    summary: 'The OCSP endpoint threw while answering a request.',
    spec: 'HTTP 500 text/plain' },
  { code: 'STS-PKI-0075',
    summary: 'A key pair could not be generated for the certificate ' +
      'authoring pane.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0076',
    summary: 'A generated key pair could not be rendered as JWK and is shown ' +
      'as PEM instead.',
    spec: '' },
  { code: 'STS-PKI-0077',
    summary: 'The certificate authoring pane named a certificate profile ' +
      'this service does not know.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0078',
    summary: 'A subjectAltName or name-constraint general-name line on the ' +
      'authoring pane could not be read (no type, unknown type, or ' +
      'malformed othername).',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0079',
    summary: 'An authority/subject information access line on the authoring ' +
      'pane has no method.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0080',
    summary: 'A policy mapping line on the authoring pane is not <issuer ' +
      'oid>=<subject oid>.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0081',
    summary: 'A name constraint line on the authoring pane is not "permit ' +
      '<name>" or "exclude <name>".',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0082',
    summary: 'A custom extension line on the authoring pane is not ' +
      '<oid>|<critical>|<base64 DER>.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0083',
    summary: 'An extra subject attribute line on the authoring pane is not ' +
      'NAME=value or OID=value.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0084',
    summary: 'A field on the authoring pane would not parse, for a reason no ' +
      'grammar code classifies.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0085',
    summary: 'A certificate was to be issued from the authoring pane with no ' +
      'subject.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0086',
    summary: '"Reuse the key pair below" was ticked on the authoring pane ' +
      'and the two key boxes are not both filled in.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0087',
    summary: 'The key pair pasted into the authoring pane could not be read ' +
      'as the chosen key algorithm.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0088',
    summary: 'No issuing certificate authority was chosen or found for a ' +
      'certificate from the authoring pane.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0089',
    summary: 'The issuer chosen on the authoring pane holds no private key ' +
      'in this service.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0090',
    summary: 'A Not Before or Not After date on the authoring pane could not ' +
      'be read.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0091',
    summary: 'Not After is not later than Not Before on the authoring pane.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0092',
    summary: 'The certificate encoder could not issue the certificate the ' +
      'authoring pane described.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0093',
    summary: 'A certificate was issued from the authoring pane and its ' +
      'certification request (CSR) could not be built.',
    spec: '' },
  { code: 'STS-PKI-0094',
    summary: 'A certificate built on the authoring pane could not be stored, ' +
      'for a reason the store did not classify.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0095',
    summary: 'The hybrid certificate\'s alternative key pair is half filled ' +
      'in on the authoring pane.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0096',
    summary: 'A stored object whose key pair was to be reused has no private ' +
      'key.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0097',
    summary: 'The issuer chain above a stored PKI object loops back on ' +
      'itself; the walk stopped.',
    spec: '' },
  { code: 'STS-PKI-0098',
    summary: 'A key pair export named a keystore format that does not exist.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0099',
    summary: 'A key pair export found no key pair to export.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0100',
    summary: 'The keystore export of a key pair failed (for example a ' +
      'password PKCS#12 needs, or a format the key cannot take).',
    spec: 'Console refusal page; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0101',
    summary: 'A PKI console action or export was attempted by a session ' +
      'without Admin Write.',
    spec: 'HTTP 403 text/plain (export) or console refusal banner' },
  { code: 'STS-PKI-0102',
    summary: 'A PKI console action threw an unexpected exception.',
    spec: 'Console refusal banner or page' },
  { code: 'STS-PKI-0103',
    summary: 'The PKI console key-pair export threw an unexpected exception.',
    spec: 'Console refusal page' },
  { code: 'STS-PKI-0104',
    summary: 'After the Root CA was replaced, a branch could not be rebuilt ' +
      'under it.',
    spec: '' },
  { code: 'STS-PKI-0105',
    summary: 'A PKI console or API action was refused by the module behind ' +
      'it without a more specific code (a missing code at that ' +
      'module).',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0106',
    summary: 'A person key-pair issue or removal named no person.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0107',
    summary: 'A person key-pair action was asked of a process with no ' +
      'directory to hold it.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0108',
    summary: 'An RFC 7522 (SAML) signing key pair was asked for a person; ' +
      'only applications may hold one. Retired 2026-09-13: a person may ' +
      'hold an RFC 7522 key pair, and the SAML bearer grant reads it.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}', retired: true },
  { code: 'STS-PKI-0109',
    summary: 'A person key-pair action named nobody in this realm.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0110',
    summary: 'A person\'s signing key pair was issued and could not be ' +
      'written onto their entry.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0111',
    summary: 'A person key-pair removal found nothing to take off.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0112',
    summary: 'A scoped PKI action named a realm\'s branch that this realm\'s ' +
      'console does not draw.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0113',
    summary: 'An application key-pair issue or removal named no application.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0114',
    summary: 'An application key-pair issue named an application that is not ' +
      'in this realm.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0115',
    summary: 'An application\'s signing key pair was issued and one of its ' +
      'attributes could not be written; the private key is lost.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0116',
    summary: 'An application key-pair removal found nothing to take off for ' +
      'that profile.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0117',
    summary: 'A PKI console or API action named an action that does not ' +
      'exist.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0118',
    summary: 'A presented certificate chain was refused because a ' +
      'certificate in it is REVOKED — on this service\'s own register, or ' +
      'on the verified CRL of a foreign issuer (common/revocation_status.js).',
    spec: 'Per door: HTTP 403 on 9443; no session and no recorded ' +
      'authentication on 8443; invalid_client at the token endpoint ' +
      '(tls_client_auth, and an x5c assertion as invalid_client or ' +
      'invalid_grant); HTTP 403 access_denied at /xacml; the SCIM ' +
      'client-certificate scheme not accepted (401 if nothing else ' +
      'authenticates); gRPC UNAUTHENTICATED at the SPIRE Server API' },
  { code: 'STS-PKI-0119',
    summary: 'A presented certificate chain was refused under ' +
      'pki.revocationCheck=hard-fail because its revocation status could not ' +
      'be established — a foreign CRL could not be fetched, did not verify, ' +
      'was stale, or no issuer certificate was available to verify one.',
    spec: 'The same refusals as STS-PKI-0118, per door' },
  { code: 'STS-PKI-0120',
    summary: 'The CRL named by a presented certificate\'s ' +
      'cRLDistributionPoints could not be fetched: a network failure, a ' +
      'timeout, a non-2xx status, a redirect or a body over ' +
      'pki.revocationMaxCrlBytes.',
    spec: '' },
  { code: 'STS-PKI-0121',
    summary: 'A fetched CRL could not be used: it did not parse, named ' +
      'another issuer, failed its signature, carried an unsupported critical ' +
      'extension or was past its nextUpdate — or a presented chain could not ' +
      'be walked at all.',
    spec: '' },
  { code: 'STS-PKI-0122',
    summary: 'The OCSP responder named by a presented certificate\'s ' +
      'Authority Information Access could not be asked: a network failure, a ' +
      'timeout, a non-2xx status, a redirect, a body over ' +
      'pki.revocationMaxCrlBytes, or a responseStatus other than successful ' +
      '(common/revocation_status.js).',
    spec: '' },
  { code: 'STS-PKI-0123',
    summary: 'An OCSP response could not be used: it did not parse, carried ' +
      'no answer for the certificate asked about, was signed by neither the ' +
      'issuer nor a delegated responder the issuer certified with ' +
      'id-kp-OCSPSigning, failed its signature, echoed a different nonce (or ' +
      'none, under pki.revocationOcspRequireNonce) or was not fresh.',
    spec: '' },
  { code: 'STS-PKI-0124',
    summary: 'A delta CRL named by freshestCRL could not be applied: it did ' +
      'not parse or verify, carried no deltaCRLIndicator, named a different ' +
      'issuer or scope from its base, or its BaseCRLNumber and cRLNumber do ' +
      'not fit the base CRL it would be merged into.',
    spec: '' },
  { code: 'STS-PKI-0125',
    summary: 'An indirect CRL could not be trusted: the cRLIssuer a ' +
      'certificate names has no certificate in the presented chain, among ' +
      'this service\'s authorities or in pki.revocationCrlIssuersFile that ' +
      'may sign CRLs and chains to the presented path — or the list at that ' +
      'point was not signed by it or does not declare itself indirect.',
    spec: '' },
  { code: 'STS-PKI-0126',
    summary: 'The certificate of a CRL\'s signer could not be fetched from ' +
      'the caIssuers address in the CRL\'s own Authority Information Access ' +
      '(RFC 5280 section 5.2.7), or none fetched there may sign that list: a ' +
      'fetch failure, a document that is not a certificate, or a certificate ' +
      'without cRLSign that does not chain to the presented path.',
    spec: '' },
  { code: 'STS-PKI-0127',
    summary: 'A delegated OCSP responder\'s answers were not used because ' +
      'its own certificate is REVOKED on the CRL it names, or because its ' +
      'status could not be established under pki.revocationCheck=hard-fail ' +
      '(RFC 6960 section 4.2.2.2.1).',
    spec: '' },
  { code: 'STS-PKI-0128',
    summary: 'An ldap: or ldaps: revocation address was not dialled or not ' +
      'answered usably: plain ldap is not permitted by pki.revocationLdap, ' +
      'the URL names no host or a critical extension, a name relative to the ' +
      'CRL issuer has no pki.revocationLdapDirectory to be looked up in, or ' +
      'the directory answered with a referral, several entries or no such ' +
      'attribute.',
    spec: '' },
  { code: 'STS-PKI-0129',
    summary: 'A certificate REGISTERED on an application entry (an RFC 7523 ' +
      'key\'s x5c, an RFC 7522 certificate), on a federation relationship ' +
      '(fedSigningCertificate, or a key in its JWKS) or in ' +
      'oid4vp.trustedIssuerCertificates verified a signature and was then ' +
      'refused because it is revoked, or its status could not be established ' +
      'under pki.revocationCheck=hard-fail.',
    spec: 'Per door: invalid_client or invalid_grant at the token endpoint; ' +
      'the federated sign-in refused with the reason on the error page; ' +
      'invalid_request at the OID4VP response endpoint' },
  { code: 'STS-PKI-0130',
    summary: 'The OCSP responder address of a certificate authority this ' +
      'service holds was fetched with a GET carrying no request — the URL ' +
      'exactly as it is written in a certificate\'s Authority Information ' +
      'Access, which RFC 6960 appendix A.1.1 makes the base of both ' +
      'transports rather than a document.',
    spec: 'HTTP 400 text/plain naming the POST and GET transports' },
  { code: 'STS-PKI-0131',
    summary: 'The OCSP responder address of a certificate authority this ' +
      'service does not hold was fetched with a GET carrying no request.',
    spec: 'HTTP 404 text/plain' },
  { code: 'STS-PKI-0132',
    summary: 'An OCSP request carried a nonce of 0 octets or more than 32, ' +
      'which RFC 8954 section 2.1 requires a responder to reject.',
    spec: 'OCSPResponse malformedRequest(1), HTTP 200' },
  { code: 'STS-PKI-0133',
    summary: 'An OCSP request named no certificate the responder\'s ' +
      'authority issued — every CertID\'s issuer name and key hashes belong ' +
      'to somebody else — so the responder is not authoritative for any of ' +
      'it (RFC 6960 section 2.3, RFC 5019 section 2.2.3).',
    spec: 'OCSPResponse unauthorized(6), HTTP 200' },
  { code: 'STS-PKI-0134',
    summary: 'A request reached the plain-HTTP revocation listener for a ' +
      'path outside /pki/. That socket serves the revocation endpoints and ' +
      'nothing else.',
    spec: 'HTTP 404 text/plain' },
  { code: 'STS-PKI-0140',
    summary: 'A certificate upload named no application, or the registration ' +
      'it produced could not be written.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0141',
    summary: 'A certificate upload carried a PRIVATE KEY block. Nothing was ' +
      'stored; the application keeps its own key.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0142',
    summary: 'A certificate upload carried no PEM certificate, or a PEM ' +
      'block that is not a certificate.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0143',
    summary: 'A certificate in an upload, or the chain it forms, could not ' +
      'be parsed.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0144',
    summary: 'The first certificate of an upload is a certificate authority ' +
      'rather than the signing leaf.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0145',
    summary: 'An uploaded certificate is expired or not yet valid.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0146',
    summary: 'An uploaded certificate carries a key the profile\'s verifier ' +
      'cannot use, or a KeyUsage that forbids digitalSignature.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0147',
    summary: 'An uploaded certificate\'s chain is incomplete: it does not ' +
      'reach a self-signed root, or the certificate is itself self-signed.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0148',
    summary: 'A certificate upload carried a certificate that is not on the ' +
      'path from the leaf to its root.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0149',
    summary: 'An uploaded certificate chains to this service\'s own Root and ' +
      'was refused by the realm path check (another realm\'s branch, a ' +
      'failed link, or revocation).',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0150',
    summary: 'An external chain uploaded with a certificate does not verify: ' +
      'a signature, an issuer name or a validity window failed.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0151',
    summary: 'An issuer in an uploaded external chain is not a CA, may not ' +
      'sign certificates, or has its path length constraint exceeded.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0152',
    summary: 'An uploaded certificate\'s chain verifies and the certificate ' +
      'was refused on revocation.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0153',
    summary: 'A certificate upload targeted a person. Only an application\'s ' +
      'key pair is replaced by an uploaded certificate. Retired 2026-09-13: ' +
      'a person\'s key pair may be replaced by an uploaded certificate too.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}', retired: true },
  { code: 'STS-PKI-0154',
    summary: 'An uploaded certificate verified and one of the attributes it ' +
      'replaces could not be written to the application entry.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0155',
    summary: 'An uploaded certificate this realm issued would widen its ' +
      'holder: for a person, its subjectAltName names somebody else ' +
      '(another urn:sts:person: or an urn:sts:application:); for an ' +
      'application, it names a urn:sts:person:.',
    spec: 'Console refusal banner; /admin-api HTTP 400 with {ok:false, ' +
      'errors}' },
  { code: 'STS-PKI-0156',
    summary: 'The certificate behind a key that verified an RFC 7523 or RFC ' +
      '7522 assertion has an INCOMPLETE chain: it is not this realm\'s, and ' +
      'nothing registered with it reaches a self-signed root ' +
      '(pki.verifySignerChain).',
    spec: 'invalid_grant at the grant, invalid_client at client ' +
      'authentication' },
  { code: 'STS-PKI-0157',
    summary: 'The chain of the certificate behind a key that verified an RFC ' +
      '7523 or RFC 7522 assertion does not verify: a signature, an issuer ' +
      'name or a validity window failed — the leaf expired, an intermediate ' +
      'expired, or a pinned self-signed certificate no longer holds.',
    spec: 'invalid_grant at the grant, invalid_client at client ' +
      'authentication' },
  { code: 'STS-PKI-0158',
    summary: 'A certificate that signs another on a signer\'s path is not ' +
      'permitted to: no basicConstraints cA=TRUE, a KeyUsage without ' +
      'keyCertSign, or a pathLenConstraint exceeded. Raised for a presented ' +
      'x5c (pki.verifyLeaf) and for a registered chain at use.',
    spec: 'invalid_grant at the grant, invalid_client at client ' +
      'authentication' },
  { code: 'STS-PKI-0159',
    summary: 'The certificate whose key verified an assertion may not sign ' +
      'one: it is a certificate authority, or its KeyUsage does not permit ' +
      'digitalSignature.',
    spec: 'invalid_grant at the grant, invalid_client at client ' +
      'authentication' },
  { code: 'STS-PKI-0160',
    summary: 'A registered JWK\'s x5c certificate does not hold the key the ' +
      'JWK represents (RFC 7517 section 4.7), so its chain says nothing ' +
      'about the key that verified the assertion.',
    spec: 'invalid_grant at the grant, invalid_client at client ' +
      'authentication' },
  { code: 'STS-PKI-0161',
    summary: 'A certificate behind a key that verified an assertion, or one ' +
      'in its registered chain, could not be read.',
    spec: 'invalid_grant at the grant, invalid_client at client ' +
      'authentication' },
  { code: 'STS-PKI-0162',
    summary: 'The certificate chain an x5u header names was requested for a ' +
      'SHA-256 that is not a JOSE signing certificate in that scope — a ' +
      'mistyped address, or a certificate replaced since the token was ' +
      'signed.',
    spec: 'HTTP 404 text/plain' },
  { code: 'STS-PKI-0163',
    summary: 'The certificate the register holds for a signing key\'s slot ' +
      'is over a different key, so tokens signed with that key carry no ' +
      'x5c or x5u until it is certified again. Logged once per certificate.',
    spec: 'none — the token is issued without the header' },
  { code: 'STS-PKI-0164',
    summary: 'The x5c or x5u header for a signed token could not be built; ' +
      'the token was signed without it.',
    spec: 'none — the token is issued without the header' },
  { code: 'STS-PKI-0165',
    summary: 'A TLS listener certificate was asked for without naming what ' +
      'it is for (no slot).',
    spec: 'the caller\'s refusal: console page or /admin-api HTTP 400 ' +
      '{ ok: false, errors }' },
  { code: 'STS-PKI-0166',
    summary: 'A TLS listener certificate was refused its subjectAltName: a ' +
      'name that is not a DNS name or IP address, or no name at all.',
    spec: 'the caller\'s refusal: console page or /admin-api HTTP 400 ' +
      '{ ok: false, errors }' },
  { code: 'STS-PKI-0167',
    summary: 'A TLS listener certificate was asked for with a key algorithm ' +
      'a TLS stack does not serve (only RSA and NIST-curve ECDSA are ' +
      'issued).',
    spec: 'the caller\'s refusal: console page or /admin-api HTTP 400 ' +
      '{ ok: false, errors }' },
  { code: 'STS-PKI-0168',
    summary: 'A TLS client certificate was asked for with no holder named.',
    spec: 'the caller\'s refusal: /portal/signing-key HTTP 400 page' },
  { code: 'STS-PKI-0169',
    summary: 'A TLS client certificate was asked for with a key algorithm a ' +
      'browser does not present (RSA 2048/3072, ECDSA P-256/P-384 only), or ' +
      'with a name that is not a short label.',
    spec: 'the caller\'s refusal: /portal/signing-key HTTP 400 page' },
  { code: 'STS-PKI-0170',
    summary: 'A person already holds pki.personTlsClientCertificateMax valid ' +
      'TLS client certificates, so another was not issued.',
    spec: 'the caller\'s refusal: /portal/signing-key HTTP 400 page' },
  { code: 'STS-PKI-0171',
    summary: 'A TLS client certificate revocation named a serial the signed-in ' +
      'person holds no certificate under.',
    spec: 'the caller\'s refusal: /portal/signing-key HTTP 400 page' },
  { code: 'STS-PKI-0180',
    summary: 'An application already holds ' +
      'pki.applicationTlsClientCertificateMax valid TLS client certificates, ' +
      'so another was not issued.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-PKI-0181',
    summary: 'A TLS client certificate revocation named a serial the ' +
      'application holds no certificate under.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-PKI-0182',
    summary: 'A certificate authority tier was built on this node and on ' +
      'another at the same moment; the other committed first and was kept.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply) ' +
      'for a deliberate build; none for a startup build, which adopts it' },
  { code: 'STS-PKI-0183',
    summary: 'A certificate authority was not built because the store could ' +
      'not be asked whether another node is building it.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-PKI-0184',
    summary: 'Another node held the build of a certificate authority for ' +
      'longer than this node waits, and nothing appeared in the store.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-PKI-0185',
    summary: 'A CRL was not signed because its CRL number could not be ' +
      'advanced in the store shared by this service\'s nodes.',
    spec: 'HTTP 500 from the CRL distribution point' },
  { code: 'STS-PKI-0186',
    summary: 'A certificate was not recorded because the Issuing CA that ' +
      'signed it was replaced, repeatedly, while it was being signed.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  // ===== ENROLL ============================================================
  { code: 'STS-ENROLL-0001',
    summary: 'A certificate request named a profile that is not one of the nine issued over an enrollment protocol.',
    spec: 'the protocol\'s refusal: ACME malformed / badCSR, EST HTTP 400, SCEP failInfo badRequest' },
  { code: 'STS-ENROLL-0002',
    summary: 'A certificate request named a CA, OCSP Responder or Kerberos KDC profile, which is never issued over an enrollment protocol.',
    spec: 'the protocol\'s refusal: ACME unauthorized, EST HTTP 403, SCEP failInfo badRequest' },
  { code: 'STS-ENROLL-0003',
    summary: 'A certificate request named a profile that is not in the family\'s allowedProfiles setting in this realm.',
    spec: 'the protocol\'s refusal: ACME unauthorized, EST HTTP 403, SCEP failInfo badRequest' },
  { code: 'STS-ENROLL-0004',
    summary: 'A certificate was asked of the enrollment core for a family that is not ACME, EST or SCEP.',
    spec: 'HTTP 500 (a defect in the caller)' },
  { code: 'STS-ENROLL-0010',
    summary: 'A person or application was named by a malformed identifier.',
    spec: 'the protocol\'s refusal (HTTP 400)' },
  { code: 'STS-ENROLL-0011',
    summary: 'No directory is loaded in this process, so there is no entry a certificate could be issued for or kept on.',
    spec: 'HTTP 503' },
  { code: 'STS-ENROLL-0012',
    summary: 'The person or application a certificate was asked for has no entry in this realm.',
    spec: 'the protocol\'s refusal (HTTP 404 / ACME unauthorized / SCEP badRequest)' },
  { code: 'STS-ENROLL-0013',
    summary: 'An enrollment authentication named no username or client_id.',
    spec: 'HTTP 401' },
  { code: 'STS-ENROLL-0014',
    summary: 'An enrollment password was not accepted for a person who has an entry in this realm.',
    spec: 'HTTP 401' },
  { code: 'STS-ENROLL-0015',
    summary: 'An enrollment password was offered for a name with no entry in this realm and no administrator standing.',
    spec: 'HTTP 401' },
  { code: 'STS-ENROLL-0016',
    summary: 'Enrollment client credentials were not accepted: an unknown client_id, or (in product mode) a missing or wrong client secret.',
    spec: 'HTTP 401' },
  { code: 'STS-ENROLL-0017',
    summary: 'Enrollment certificate authentication was attempted with no TLS client certificate on the connection.',
    spec: 'HTTP 401' },
  { code: 'STS-ENROLL-0018',
    summary: 'An enrollment client certificate did not verify to this realm\'s certificate authority (another realm, another authority, expired or revoked).',
    spec: 'HTTP 401' },
  { code: 'STS-ENROLL-0019',
    summary: 'An enrollment client certificate verified but does not certify clientAuth, names no single entry, or is not an unrevoked certificate that entry holds.',
    spec: 'HTTP 401' },
  { code: 'STS-ENROLL-0020',
    summary: 'An enrollment authorization was asked about with no authenticated principal or no target entry.',
    spec: 'HTTP 403' },
  { code: 'STS-ENROLL-0021',
    summary: 'A certificate was asked for an entry other than the one that authenticated, by a principal that does not hold Admin Write.',
    spec: 'the protocol\'s refusal: ACME unauthorized, EST HTTP 403, SCEP badRequest' },
  { code: 'STS-ENROLL-0022',
    summary: 'A certificate request named more than one person or application in its subjectAltName.',
    spec: 'HTTP 400' },
  { code: 'STS-ENROLL-0023',
    summary: 'An administrator with no entry of their own in this realm sent a request that named no entry.',
    spec: 'HTTP 400' },
  { code: 'STS-ENROLL-0030',
    summary: 'A certificate request was empty or is not a readable PKCS#10 CertificationRequest.',
    spec: 'ACME badCSR, EST HTTP 400, SCEP badRequest' },
  { code: 'STS-ENROLL-0031',
    summary: 'A certificate request carries a public key this certificate authority cannot certify.',
    spec: 'ACME badCSR / badPublicKey, EST HTTP 400' },
  { code: 'STS-ENROLL-0032',
    summary: 'A certificate request carries a key-encapsulation key, which cannot prove possession by signing.',
    spec: 'ACME badCSR, EST HTTP 400' },
  { code: 'STS-ENROLL-0033',
    summary: 'A certificate request\'s signature does not verify with the key it carries (no proof of possession).',
    spec: 'ACME badCSR, EST HTTP 400, SCEP badMessageCheck' },
  { code: 'STS-ENROLL-0034',
    summary: 'A certificate request\'s subject or requested extensions could not be read.',
    spec: 'ACME badCSR, EST HTTP 400' },
  { code: 'STS-ENROLL-0035',
    summary: 'A server-generated key pair was asked for an unknown key algorithm, or could not be generated.',
    spec: 'HTTP 400' },
  { code: 'STS-ENROLL-0040',
    summary: 'A certificate was refused because the entry already holds pki.enrollmentMaxCertificatesPerEntry unexpired enrolled certificates.',
    spec: 'HTTP 409 / ACME rejectedIdentifier' },
  { code: 'STS-ENROLL-0041',
    summary: 'An enrolled certificate, private key or credential could not be written onto its directory entry.',
    spec: 'HTTP 503' },
  { code: 'STS-ENROLL-0042',
    summary: 'The family\'s Issuing CA could not issue an enrolled certificate.',
    spec: 'HTTP 503 / ACME serverInternal' },
  { code: 'STS-ENROLL-0043',
    summary: 'A server-generated private key or an EAB key could not be sealed for storage.',
    spec: 'HTTP 503' },
  { code: 'STS-ENROLL-0044',
    summary: 'An entry already holds the most unused EAB keys or SCEP challenges it may.',
    spec: 'HTTP 409 on the console or /admin-api' },
  { code: 'STS-ENROLL-0050',
    summary: 'A certificate request asked for a URI (or another name form) the entry does not own.',
    spec: 'ACME rejectedIdentifier, EST HTTP 403, SCEP badRequest' },
  { code: 'STS-ENROLL-0051',
    summary: 'A certificate request asked for a DNS name or IP address not registered on the entry.',
    spec: 'ACME rejectedIdentifier, EST HTTP 403, SCEP badRequest' },
  { code: 'STS-ENROLL-0052',
    summary: 'A certificate request asked for an email address that is not the entry\'s mail attribute.',
    spec: 'ACME rejectedIdentifier, EST HTTP 403, SCEP badRequest' },
  { code: 'STS-ENROLL-0053',
    summary: 'A certificate request asked for a user principal name that is neither the entry\'s userPrincipalName nor its mail.',
    spec: 'ACME rejectedIdentifier, EST HTTP 403, SCEP badRequest' },
  { code: 'STS-ENROLL-0054',
    summary: 'A TLS server certificate was asked for with no host name in the request.',
    spec: 'ACME malformed, EST HTTP 400, SCEP badRequest' },
  { code: 'STS-ENROLL-0055',
    summary: 'An S/MIME certificate was asked for an entry with no mail attribute.',
    spec: 'HTTP 400' },
  { code: 'STS-ENROLL-0056',
    summary: 'A smartcard logon certificate was asked for an entry with neither userPrincipalName nor mail.',
    spec: 'HTTP 400' },
  { code: 'STS-ENROLL-0057',
    summary: 'An administrator tried to register something that is not a DNS name or an IP address as a certificate host name.',
    spec: 'HTTP 400 on the console or /admin-api' },
  { code: 'STS-ENROLL-0058',
    summary: 'An administrator tried to remove a certificate host name the entry does not have.',
    spec: 'HTTP 404 on the console or /admin-api' },
  { code: 'STS-ENROLL-0060',
    summary: 'An ACME or EST request arrived over plain HTTP in product mode.',
    spec: 'HTTP 403 (ACME: an RFC 7807 unauthorized problem)' },
  { code: 'STS-ENROLL-0061',
    summary: 'A client was throttled after too many refused enrollment requests in one web-security window.',
    spec: 'HTTP 429 with Retry-After (ACME rateLimited)' },
  { code: 'STS-ENROLL-0070',
    summary: 'A revocation named a serial no enrollment protocol issued in this realm.',
    spec: 'HTTP 404 (ACME malformed)' },
  { code: 'STS-ENROLL-0071',
    summary: 'A revocation named a certificate that does not belong to the entry asking.',
    spec: 'HTTP 403 (ACME unauthorized)' },
  { code: 'STS-ENROLL-0072',
    summary: 'The certificate authority refused an enrolled certificate\'s revocation.',
    spec: 'HTTP 400' },
  { code: 'STS-ENROLL-0080',
    summary: 'An External Account Binding key id is not known in this realm.',
    spec: 'ACME unauthorized / externalAccountRequired' },
  { code: 'STS-ENROLL-0081',
    summary: 'An External Account Binding key that already bound one account was presented for another.',
    spec: 'ACME unauthorized' },
  { code: 'STS-ENROLL-0082',
    summary: 'An External Account Binding key was presented after it expired.',
    spec: 'ACME unauthorized' },
  { code: 'STS-ENROLL-0083',
    summary: 'A SCEP challenge password was not accepted (unknown id or wrong secret).',
    spec: 'SCEP CertRep FAILURE badRequest' },
  { code: 'STS-ENROLL-0084',
    summary: 'A SCEP challenge password that had already been redeemed was presented again.',
    spec: 'SCEP CertRep FAILURE badRequest' },
  { code: 'STS-ENROLL-0085',
    summary: 'A SCEP challenge password was presented after it expired.',
    spec: 'SCEP CertRep FAILURE badRequest' },
  { code: 'STS-ENROLL-0090',
    summary: 'An enrollment monitor counter could not be recorded (the request it counted is unaffected).',
    spec: 'none (log only)' },
  { code: 'STS-ENROLL-0091',
    summary: 'An ACME External Account Binding key or a SCEP challenge ' +
      'password could not be proved unspent because the cluster store ' +
      'could not be asked, so it was refused.',
    spec: 'ACME unauthorized / SCEP CertRep FAILURE badRequest' },
  // ===== ACME ==============================================================
  { code: 'STS-ACME-0001',
    summary: 'ACME is turned off in this realm (acme.enabled is false).',
    spec: 'HTTP 503, ACME serverInternal problem' },
  { code: 'STS-ACME-0002',
    summary: 'An ACME request was refused by the transport rule and the core gave no code of its own (fallback for STS-ENROLL-0060).',
    spec: 'HTTP 403, ACME unauthorized problem' },
  { code: 'STS-ACME-0003',
    summary: 'An ACME request was throttled and the core gave no code of its own (fallback for STS-ENROLL-0061).',
    spec: 'HTTP 429 with Retry-After, ACME rateLimited problem' },
  { code: 'STS-ACME-0010',
    summary: 'An ACME POST did not carry Content-Type application/jose+json (RFC 8555 section 6.2).',
    spec: 'HTTP 415, ACME malformed problem' },
  { code: 'STS-ACME-0011',
    summary: 'An ACME request body was larger than acme.maxRequestBytes.',
    spec: 'HTTP 413, ACME malformed problem' },
  { code: 'STS-ACME-0012',
    summary: 'An ACME request body (or an external account binding) is not a flattened JWS JSON object with exactly protected, payload and signature.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0013',
    summary: 'A member of an ACME flattened JWS is not strict base64url.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0014',
    summary: 'An ACME JWS protected header is unreadable, fails its schema, or carries crit, b64, jku, x5u or x5c.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0015',
    summary: 'An ACME JWS is signed with an algorithm this server does not accept for an account key.',
    spec: 'HTTP 400, ACME badSignatureAlgorithm problem with algorithms' },
  { code: 'STS-ACME-0016',
    summary: 'An ACME request carried no Replay-Nonce, or one this server did not issue in this realm.',
    spec: 'HTTP 400, ACME badNonce problem with a fresh Replay-Nonce' },
  { code: 'STS-ACME-0017',
    summary: 'An ACME request carried an expired Replay-Nonce.',
    spec: 'HTTP 400, ACME badNonce problem with a fresh Replay-Nonce' },
  { code: 'STS-ACME-0018',
    summary: 'An ACME request carried a Replay-Nonce that had already been used.',
    spec: 'HTTP 400, ACME badNonce problem with a fresh Replay-Nonce' },
  { code: 'STS-ACME-0019',
    summary: 'An ACME JWS protected header url is not the URL the request was sent to (RFC 8555 section 6.4).',
    spec: 'HTTP 403, ACME unauthorized problem' },
  { code: 'STS-ACME-0020',
    summary: 'An ACME JWS carried both jwk and kid, neither, or the one the resource does not take.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0021',
    summary: 'An ACME account key (jwk) is malformed, carries a private member, does not fit alg, is an RSA key under 2048 bits, or does not load.',
    spec: 'HTTP 400, ACME badPublicKey or malformed problem' },
  { code: 'STS-ACME-0022',
    summary: 'An ACME kid is not the URL of an account on this server in this realm.',
    spec: 'HTTP 400, ACME accountDoesNotExist problem' },
  { code: 'STS-ACME-0023',
    summary: 'An ACME request was signed by a deactivated account.',
    spec: 'HTTP 403, ACME unauthorized problem' },
  { code: 'STS-ACME-0024',
    summary: 'An ACME JWS signature does not verify with the account key.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0025',
    summary: 'An ACME JWS payload is unreadable, missing where one is required, present where POST-as-GET is required, or fails the resource schema.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0026',
    summary: 'An ACME resource was requested with a method it does not answer (a GET on a POST-as-GET resource, a POST on the directory or renewal information).',
    spec: 'HTTP 405 with Allow, ACME malformed problem' },
  { code: 'STS-ACME-0027',
    summary: 'An ACME resource (account, order, authorization, certificate) belongs to a different account from the one that signed the request.',
    spec: 'HTTP 403, ACME unauthorized problem' },
  { code: 'STS-ACME-0028',
    summary: 'An ACME order, authorization or certificate id names nothing in this realm.',
    spec: 'HTTP 404, ACME malformed problem' },
  { code: 'STS-ACME-0030',
    summary: 'An ACME newAccount with onlyReturnExisting found no account for the key.',
    spec: 'HTTP 400, ACME accountDoesNotExist problem' },
  { code: 'STS-ACME-0031',
    summary: 'An ACME newAccount carried no externalAccountBinding, which this server requires.',
    spec: 'HTTP 403, ACME externalAccountRequired problem' },
  { code: 'STS-ACME-0032',
    summary: 'An ACME externalAccountBinding is malformed: its header is not exactly alg, kid and url, its alg is not a MAC, its url is not the newAccount URL, or its payload is not the account key.',
    spec: 'HTTP 400, ACME malformed or badSignatureAlgorithm problem' },
  { code: 'STS-ACME-0033',
    summary: 'An ACME externalAccountBinding names a key id that is not known in this realm.',
    spec: 'HTTP 403, ACME unauthorized problem' },
  { code: 'STS-ACME-0034',
    summary: 'An ACME externalAccountBinding MAC does not verify with the key issued under its key id.',
    spec: 'HTTP 403, ACME unauthorized problem' },
  { code: 'STS-ACME-0035',
    summary: 'An ACME externalAccountBinding key has expired before binding an account.',
    spec: 'HTTP 403, ACME unauthorized problem' },
  { code: 'STS-ACME-0036',
    summary: 'An ACME externalAccountBinding key could not bind the account and the core gave no code of its own.',
    spec: 'HTTP 403, ACME unauthorized problem' },
  { code: 'STS-ACME-0037',
    summary: 'An ACME account contact is not a single mailto: address.',
    spec: 'HTTP 400, ACME invalidContact or unsupportedContact problem' },
  { code: 'STS-ACME-0038',
    summary: 'An ACME account update asked for a status other than deactivated.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0040',
    summary: 'An ACME newOrder named an identifier type this server does not issue for.',
    spec: 'HTTP 400, ACME unsupportedIdentifier problem with subproblems' },
  { code: 'STS-ACME-0041',
    summary: 'An ACME newOrder identifier value is not well formed for its type.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0042',
    summary: 'An ACME newOrder named an identifier the account\'s bound entry does not own (an unregistered host name, somebody else\'s mail, another entry).',
    spec: 'HTTP 400, ACME rejectedIdentifier problem with subproblems' },
  { code: 'STS-ACME-0043',
    summary: 'An ACME newOrder carried notBefore or notAfter, which this server does not accept.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0044',
    summary: 'An ACME newOrder named a profile that is unknown, never issued over an enrollment protocol, or not in acme.allowedProfiles.',
    spec: 'HTTP 400, ACME invalidProfile problem' },
  { code: 'STS-ACME-0045',
    summary: 'An ACME newOrder profile needs an identifier or attribute the order or entry lacks (a server profile with no host, email with no email identifier, smartcard logon with no UPN).',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0046',
    summary: 'An ACME newOrder named one identifier twice.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0047',
    summary: 'An ACME newOrder replaces member names no certificate this account\'s entry was issued over ACME in this realm (RFC 9773 section 5).',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0048',
    summary: 'The directory entry an ACME account or EAB key is bound to no longer exists in this realm.',
    spec: 'HTTP 403, ACME unauthorized problem' },
  { code: 'STS-ACME-0049',
    summary: 'An ACME newOrder replaces a certificate that another order already replaced (RFC 9773 section 5).',
    spec: 'HTTP 409, ACME alreadyReplaced problem' },
  { code: 'STS-ACME-0050',
    summary: 'An ACME finalize was sent for an order that is not ready (already valid, processing or invalid).',
    spec: 'HTTP 403, ACME orderNotReady problem' },
  { code: 'STS-ACME-0051',
    summary: 'An ACME finalize csr is not strict base64url.',
    spec: 'HTTP 400, ACME badCSR problem' },
  { code: 'STS-ACME-0052',
    summary: 'An ACME finalize CSR could not be read and the core gave no code of its own.',
    spec: 'HTTP 400, ACME badCSR problem' },
  { code: 'STS-ACME-0053',
    summary: 'An ACME finalize CSR does not name exactly the order\'s identifiers (RFC 8555 section 7.4).',
    spec: 'HTTP 400, ACME badCSR problem' },
  { code: 'STS-ACME-0054',
    summary: 'An ACME finalize issuance failed and the core gave no code of its own.',
    spec: 'HTTP 500, ACME serverInternal problem' },
  { code: 'STS-ACME-0055',
    summary: 'An ACME authorization update was not {"status": "deactivated"}.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0056',
    summary: 'An ACME challenge response was not the empty object.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0060',
    summary: 'An ACME revokeCert certificate is not base64url DER of one certificate.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0061',
    summary: 'An ACME revokeCert certificate was not issued over ACME in this realm.',
    spec: 'HTTP 404, ACME malformed problem' },
  { code: 'STS-ACME-0062',
    summary: 'An ACME revokeCert reason is not one this server accepts from a subscriber (0, 1, 3, 4, 5 or 9).',
    spec: 'HTTP 400, ACME badRevocationReason problem' },
  { code: 'STS-ACME-0063',
    summary: 'An ACME revokeCert was signed neither by an account bound to the certificate\'s entry nor by the certificate\'s own key.',
    spec: 'HTTP 403, ACME unauthorized problem' },
  { code: 'STS-ACME-0064',
    summary: 'An ACME revokeCert named a certificate that is already revoked.',
    spec: 'HTTP 400, ACME alreadyRevoked problem' },
  { code: 'STS-ACME-0065',
    summary: 'Revoking a certificate issued over ACME failed and the core gave no code of its own.',
    spec: 'HTTP 500, ACME serverInternal problem; console error notice' },
  { code: 'STS-ACME-0070',
    summary: 'An ACME keyChange inner JWS is malformed, unverifiable or carries an unreadable payload.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0071',
    summary: 'An ACME keyChange inner JWS breaks section 7.3.5: no jwk, a kid or nonce, a different url, or an account that is not the signer.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0072',
    summary: 'An ACME keyChange oldKey is not the account\'s current key.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0073',
    summary: 'An ACME keyChange new key is already the key of another account.',
    spec: 'HTTP 409 with Location, ACME malformed problem' },
  { code: 'STS-ACME-0074',
    summary: 'An ACME keyChange new key is the account\'s current key.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0080',
    summary: 'An ACME renewalInfo certificate identifier is malformed (RFC 9773 section 4.1).',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0081',
    summary: 'An ACME renewalInfo certificate identifier names no certificate issued over ACME in this realm.',
    spec: 'HTTP 404, ACME malformed problem' },
  { code: 'STS-ACME-0082',
    summary: 'The query string of an ACME orders list failed validation.',
    spec: 'HTTP 400, ACME malformed problem' },
  { code: 'STS-ACME-0090',
    summary: 'An ACME console or management API action is not one of the six.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from /admin-api' },
  { code: 'STS-ACME-0091',
    summary: 'An ACME console or management API action body failed validation.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from /admin-api' },
  { code: 'STS-ACME-0092',
    summary: 'An ACME console or management API deactivate-account named no account in this realm.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from /admin-api' },
  { code: 'STS-ACME-0093',
    summary: 'An ACME console or management API revoke-certificate named no certificate issued over ACME in this realm.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from /admin-api' },
  { code: 'STS-ACME-0094',
    summary: 'An ACME console or management API EAB or host name action was refused by the core with no code of its own.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from /admin-api' },
  { code: 'STS-ACME-0095',
    summary: 'An ACME endpoint, console action or management API action threw unexpectedly.',
    spec: 'HTTP 500, ACME serverInternal problem; console error notice' },
  { code: 'STS-ACME-0096',
    summary: 'An ACME console or management API revoke-certificate named a certificate that is already revoked.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from /admin-api' },
  { code: 'STS-ACME-0097',
    summary: 'The query string of an ACME console page failed validation.',
    spec: 'HTTP 400 text/plain' },
  { code: 'STS-ACME-0098',
    summary: 'An ACME finalize was refused because the order is already ' +
      'being finalized by another request, on this node or another.',
    spec: 'HTTP 403, ACME orderNotReady problem' },
  { code: 'STS-ACME-0099',
    summary: 'An ACME Replay-Nonce or an order\'s finalize could not be ' +
      'claimed because the cluster store could not be asked, so the request ' +
      'was refused.',
    spec: 'HTTP 500, ACME serverInternal problem' },
  // ===== EST ===============================================================
  { code: 'STS-EST-0001',
    summary: 'An EST request reached a realm whose est.enabled is off.',
    spec: 'HTTP 503 with a text/plain sentence' },
  { code: 'STS-EST-0002',
    summary: 'An EST path named a label that is not a certificate profile (RFC 7030 section 3.2.2).',
    spec: 'HTTP 404 with a text/plain sentence' },
  { code: 'STS-EST-0003',
    summary: 'An EST operation was asked with a method it does not answer.',
    spec: 'HTTP 405 with an Allow header' },
  { code: 'STS-EST-0004',
    summary: 'A client asked /fullcmc, which this server does not implement (RFC 7030 section 4.3 is optional).',
    spec: 'HTTP 501' },
  { code: 'STS-EST-0005',
    summary: 'A client asked /serverkeygen in a realm whose est.serverKeyGeneration is off.',
    spec: 'HTTP 501' },
  { code: 'STS-EST-0006',
    summary: 'An EST enrollment body was not sent as application/pkcs10.',
    spec: 'HTTP 415' },
  { code: 'STS-EST-0007',
    summary: 'An EST enrollment body was larger than est.maxRequestBytes.',
    spec: 'HTTP 413' },
  { code: 'STS-EST-0008',
    summary: 'An EST enrollment body was empty, or was not base64 (RFC 8951: only the base64 alphabet, padding and whitespace).',
    spec: 'HTTP 400' },
  { code: 'STS-EST-0009',
    summary: 'An EST request that must be authenticated carried no credential.',
    spec: 'HTTP 401 with WWW-Authenticate: Basic realm="EST"' },
  { code: 'STS-EST-0010',
    summary: 'An EST request carried HTTP Basic in a realm whose est.basicAuthentication is off.',
    spec: 'HTTP 401' },
  { code: 'STS-EST-0011',
    summary: 'An EST request carried a malformed HTTP Basic credential (not base64, no colon, or an unusable username).',
    spec: 'HTTP 401' },
  { code: 'STS-EST-0012',
    summary: 'An EST request authenticated only by a TLS client certificate in a realm whose est.certificateAuthentication is off.',
    spec: 'HTTP 401' },
  { code: 'STS-EST-0013',
    summary: 'An EST request carried an Authorization scheme other than Basic.',
    spec: 'HTTP 401 with WWW-Authenticate: Basic realm="EST"' },
  { code: 'STS-EST-0014',
    summary: 'EST /cacerts was asked in a realm with no certificate hierarchy, so there is no CA certificate to return.',
    spec: 'HTTP 503' },
  { code: 'STS-EST-0015',
    summary: 'A /simplereenroll named no certificate this entry holds whose subject and subjectAltName the request repeats (RFC 7030 section 4.2.2).',
    spec: 'HTTP 400' },
  { code: 'STS-EST-0016',
    summary: 'A /simplereenroll request\'s subject or subjectAltName differs from the TLS client certificate being renewed (RFC 7030 section 4.2.2).',
    spec: 'HTTP 400' },
  { code: 'STS-EST-0017',
    summary: 'A /serverkeygen template asked for a key this service cannot generate for that profile (a KEM key outside key-encipherment).',
    spec: 'HTTP 400' },
  { code: 'STS-EST-0018',
    summary: 'A /serverkeygen template asked for the private key to be encrypted (DecryptKeyIdentifier or AsymmetricDecryptKeyIdentifier), which this server does not implement.',
    spec: 'HTTP 501' },
  { code: 'STS-EST-0019',
    summary: 'An EST request carried a query string; no EST operation takes one.',
    spec: 'HTTP 400' },
  { code: 'STS-EST-0020',
    summary: 'An EST handler failed unexpectedly; the client is told nothing about why.',
    spec: 'HTTP 500 with a generic sentence' },
  { code: 'STS-EST-0021',
    summary: 'A /simplereenroll named a certificate that has expired or been revoked.',
    spec: 'HTTP 400' },
  { code: 'STS-EST-0030',
    summary: 'A query string on /admin/est or /admin/est/monitor failed validation.',
    spec: 'HTTP 400 on the console' },
  { code: 'STS-EST-0031',
    summary: 'An EST console or /admin-api action body failed validation.',
    spec: 'HTTP 400 on the console or /admin-api' },
  { code: 'STS-EST-0032',
    summary: 'An EST console or /admin-api action named an action that does not exist.',
    spec: 'HTTP 400 on the console or /admin-api' },
  { code: 'STS-EST-0033',
    summary: 'An EST /admin-api action was refused and carried no more specific code.',
    spec: 'HTTP 400 on /admin-api' },
  // ===== SCEP ==============================================================
  { code: 'STS-SCEP-0001',
    summary: 'A SCEP request reached a realm where scep.enabled is off.',
    spec: 'HTTP 503 text/plain' },
  { code: 'STS-SCEP-0002',
    summary: 'A SCEP request named no operation, an operation RFC 8894 does not define, or a malformed or repeated query parameter.',
    spec: 'HTTP 400 text/plain' },
  { code: 'STS-SCEP-0003',
    summary: 'A SCEP operation other than PKIOperation was sent as a POST.',
    spec: 'HTTP 405 text/plain' },
  { code: 'STS-SCEP-0004',
    summary: 'GetNextCACert was asked for; this server does not pre-announce a CA rollover.',
    spec: 'HTTP 501 text/plain' },
  { code: 'STS-SCEP-0005',
    summary: 'GetCACert or PKIOperation was asked of a realm with no certificate authority, so there is no SCEP Issuing CA or RA certificate.',
    spec: 'HTTP 503 text/plain' },
  { code: 'STS-SCEP-0006',
    summary: 'The SCEP RA certificate could not be issued or its replacement could not be recorded.',
    spec: 'HTTP 503 text/plain, or the console/API refusal' },
  { code: 'STS-SCEP-0007',
    summary: 'A PKIOperation POST did not carry Content-Type application/x-pki-message.',
    spec: 'HTTP 415 text/plain' },
  { code: 'STS-SCEP-0008',
    summary: 'A pkiMessage was larger than scep.maxRequestBytes.',
    spec: 'HTTP 413 text/plain' },
  { code: 'STS-SCEP-0009',
    summary: 'A GET PKIOperation carried no message parameter, or one that is not strict base64.',
    spec: 'HTTP 400 text/plain' },
  { code: 'STS-SCEP-0010',
    summary: 'A pkiMessage is not one complete CMS ContentInfo carrying a well-formed SignedData.',
    spec: 'HTTP 400 text/plain (no CertRep can be built)' },
  { code: 'STS-SCEP-0011',
    summary: 'A pkiMessage does not have exactly one signer whose certificate is in the SignedData.',
    spec: 'HTTP 400, or CertRep FAILURE badMessageCheck' },
  { code: 'STS-SCEP-0012',
    summary: 'A pkiMessage lacks signed attributes, or its transactionID or senderNonce is missing or malformed.',
    spec: 'HTTP 400 text/plain (no CertRep can be built)' },
  { code: 'STS-SCEP-0013',
    summary: 'The profile segment of a /enroll/scep URL is not a profile identifier.',
    spec: 'HTTP 400 text/plain' },
  { code: 'STS-SCEP-0020',
    summary: 'A pkiMessage is signed over a digest this server does not accept (SHA-1, MD5 or unknown).',
    spec: 'CertRep FAILURE badAlg' },
  { code: 'STS-SCEP-0021',
    summary: 'A pkiMessage names a signature algorithm this server does not verify, or one that disagrees with its digest or the signer key.',
    spec: 'CertRep FAILURE badAlg' },
  { code: 'STS-SCEP-0022',
    summary: 'The messageDigest signed attribute is not the digest of the encapsulated content.',
    spec: 'CertRep FAILURE badMessageCheck' },
  { code: 'STS-SCEP-0023',
    summary: 'The signature over a pkiMessage\'s signed attributes does not verify with its signer certificate.',
    spec: 'CertRep FAILURE badMessageCheck' },
  { code: 'STS-SCEP-0024',
    summary: 'The contentType signed attribute is missing or does not agree with the encapsulated content.',
    spec: 'CertRep FAILURE badMessageCheck' },
  { code: 'STS-SCEP-0025',
    summary: 'A pkiMessage signer certificate carries a key that is not RSA, so no reply can be encrypted to it.',
    spec: 'CertRep FAILURE badAlg (unencrypted)' },
  { code: 'STS-SCEP-0026',
    summary: 'The pkcsPKIEnvelope is not a readable CMS EnvelopedData.',
    spec: 'CertRep FAILURE badMessageCheck' },
  { code: 'STS-SCEP-0027',
    summary: 'The pkcsPKIEnvelope is not encrypted to this realm\'s current RA certificate.',
    spec: 'CertRep FAILURE badMessageCheck' },
  { code: 'STS-SCEP-0028',
    summary: 'The pkcsPKIEnvelope transports its content key with an algorithm other than RSAES-PKCS1-v1_5 or RSAES-OAEP.',
    spec: 'CertRep FAILURE badAlg' },
  { code: 'STS-SCEP-0029',
    summary: 'The pkcsPKIEnvelope content is encrypted with a cipher other than AES-CBC (DES-EDE3-CBC is refused).',
    spec: 'CertRep FAILURE badAlg' },
  { code: 'STS-SCEP-0030',
    summary: 'The pkcsPKIEnvelope content did not decrypt with the RA key (a wrong key or bad padding, deliberately not told apart).',
    spec: 'CertRep FAILURE badMessageCheck' },
  { code: 'STS-SCEP-0031',
    summary: 'A pkiMessage carried a messageType this server does not answer.',
    spec: 'CertRep FAILURE badRequest' },
  { code: 'STS-SCEP-0032',
    summary: 'A PKCSReq or RenewalReq envelope did not hold a PKCS#10 request, or a CertPoll, GetCert or GetCRL envelope did not hold its structure.',
    spec: 'CertRep FAILURE badRequest' },
  { code: 'STS-SCEP-0033',
    summary: 'A SCEP certificate request carries a key that is not RSA; SCEP encrypts its reply with RSA key transport.',
    spec: 'CertRep FAILURE badAlg' },
  { code: 'STS-SCEP-0034',
    summary: 'A PKCSReq was signed by a certificate whose key is not the key in the PKCS#10 request (RFC 8894 section 2.3).',
    spec: 'CertRep FAILURE badMessageCheck' },
  { code: 'STS-SCEP-0035',
    summary: 'A PKCSReq carried no challengePassword attribute.',
    spec: 'CertRep FAILURE badRequest' },
  { code: 'STS-SCEP-0036',
    summary: 'The profile named in the /enroll/scep URL is not the profile the challenge or the renewed certificate is for.',
    spec: 'CertRep FAILURE badRequest' },
  { code: 'STS-SCEP-0037',
    summary: 'A transactionID that already completed was sent again with a different request.',
    spec: 'CertRep FAILURE badRequest' },
  { code: 'STS-SCEP-0038',
    summary: 'A CertPoll (GetCertInitial) named a transactionID this realm holds no result for.',
    spec: 'CertRep FAILURE badCertId' },
  { code: 'STS-SCEP-0039',
    summary: 'A CertPoll or a retried request for a completed transaction was signed with a different key from the request that completed it.',
    spec: 'CertRep FAILURE badCertId' },
  { code: 'STS-SCEP-0040',
    summary: 'A RenewalReq, GetCert or GetCRL was not signed by a certificate this realm issued to an entry that still holds it.',
    spec: 'CertRep FAILURE badMessageCheck' },
  { code: 'STS-SCEP-0041',
    summary: 'A GetCert named a certificate that is not one the signer\'s entry holds.',
    spec: 'CertRep FAILURE badCertId' },
  { code: 'STS-SCEP-0042',
    summary: 'A GetCRL named an issuer that is not this realm\'s SCEP Issuing CA.',
    spec: 'CertRep FAILURE badCertId' },
  { code: 'STS-SCEP-0043',
    summary: 'The SCEP Issuing CA\'s CRL could not be built for a GetCRL.',
    spec: 'CertRep FAILURE badRequest' },
  { code: 'STS-SCEP-0044',
    summary: 'A CertRep could not be built or signed (an internal failure).',
    spec: 'HTTP 500 text/plain' },
  { code: 'STS-SCEP-0045',
    summary: 'The certificate authority refused a SCEP certificate for a reason the enrollment core did not code.',
    spec: 'CertRep FAILURE badRequest' },
  { code: 'STS-SCEP-0046',
    summary: 'A pkiMessage signer certificate is outside its validity period.',
    spec: 'CertRep FAILURE badTime' },
  { code: 'STS-SCEP-0060',
    summary: 'A /admin/scep or /admin-api/scep query string failed input validation.',
    spec: 'HTTP 400 text/plain or { ok: false, errors }' },
  { code: 'STS-SCEP-0061',
    summary: 'A /admin/scep or /admin-api/scep action body failed input validation.',
    spec: 'the console redirect with error=, or HTTP 400 { ok: false, errors }' },
  { code: 'STS-SCEP-0062',
    summary: 'A /admin/scep or /admin-api/scep action named no action, or one that does not exist.',
    spec: 'the console redirect with error=, or HTTP 400 { ok: false, errors }' },
  { code: 'STS-SCEP-0063',
    summary: 'A SCEP certificate revocation from the console or /admin-api named an unknown RFC 5280 reason.',
    spec: 'the console redirect with error=, or HTTP 400 { ok: false, errors }' },
  { code: 'STS-SCEP-0064',
    summary: 'A SCEP message was refused because another request with the ' +
      'same transactionID was still being answered, on this node or ' +
      'another, when the wait ran out.',
    spec: 'SCEP CertRep FAILURE badRequest' },
  { code: 'STS-SCEP-0065',
    summary: 'A SCEP message was refused because its transaction could not ' +
      'be claimed: the cluster store could not be asked.',
    spec: 'SCEP CertRep FAILURE badRequest' },
  // ===== AUTHN =============================================================
  { code: 'STS-AUTHN-0001',
    summary: 'A request to the sign-in screen or the federation chooser ' +
      'carried a pending sign-in id that failed input validation.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-AUTHN-0002',
    summary: 'The sign-in form POST failed input validation (an unknown ' +
      'action, an oversized field, a malformed id).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-AUTHN-0003',
    summary: 'No sign-in is pending under the id the sign-in screen, the ' +
      'federation chooser or the form POST named: it expired, was ' +
      'already spent, or never existed.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-AUTHN-0004',
    summary: 'The person pressed Cancel at the sign-in screen; the calling ' +
      'protocol is told the user declined.',
    spec: 'HTTP 303 back to the calling protocol with ' +
      'authn_error=access_denied' },
  { code: 'STS-AUTHN-0005',
    summary: 'The issuance policy refused an unauthenticated (\'continue ' +
      'without signing in\') session for the application at the ' +
      'sign-in screen.',
    spec: 'HTTP 200 sign-in page, redrawn with the reason' },
  { code: 'STS-AUTHN-0006',
    summary: 'The sign-in form was submitted with no username.',
    spec: 'HTTP 200 sign-in page, redrawn with the reason' },
  { code: 'STS-AUTHN-0007',
    summary: 'A passwordless security-key sign-in was asked for where the ' +
      'calling protocol demanded a second factor.',
    spec: 'HTTP 200 sign-in page, redrawn with the reason' },
  { code: 'STS-AUTHN-0008',
    summary: 'Too many sign-in attempts for this identity or address; the ' +
      'password check was not attempted (rate limiter lockout).',
    spec: 'HTTP 200 sign-in page, redrawn with the reason' },
  { code: 'STS-AUTHN-0009',
    summary: 'The issuance policy refused a session for the application to ' +
      'the person who just authenticated at the sign-in screen (a ' +
      'required role is not held).',
    spec: 'HTTP 200 sign-in page, redrawn with the reason' },
  { code: 'STS-AUTHN-0010',
    summary: 'The issuance policy refused to start a sign-on session at the ' +
      'session funnel, for a door other than the sign-in screen ' +
      '(federation, SPNEGO, client certificate, WS-Trust, a ' +
      'second-factor screen).',
    spec: '' },
  { code: 'STS-AUTHN-0011',
    summary: 'A sign-out was asked for and there was no session to end: it ' +
      'had already expired or been signed out.',
    spec: '' },
  { code: 'STS-AUTHN-0012',
    summary: 'An arrival session could not be started for a browser reaching ' +
      'a protocol front door; the request continued without one.',
    spec: '' },
  { code: 'STS-AUTHN-0013',
    summary: 'setSessionObserver() was given something that is not a ' +
      'function and was ignored; no Shared Signals transmitter will ' +
      'hear about sessions.',
    spec: '' },
  { code: 'STS-AUTHN-0014',
    summary: 'The installed session observer (the CAEP transmitter) threw ' +
      'while being told about a session event; the event was dropped ' +
      'and the sign-in or sign-out went ahead.',
    spec: '' },
  { code: 'STS-AUTHN-0015',
    summary: 'A session cookie could not be written because the response ' +
      'object has neither set() nor setHeader(); the session exists ' +
      'and the browser was not told.',
    spec: '' },
  { code: 'STS-AUTHN-0016',
    summary: 'The application registry threw while resolving an ' +
      'application\'s federation relationships or declared ' +
      'authentication mechanism on the way to the sign-in screen; the ' +
      'shortcut was skipped.',
    spec: '' },
  { code: 'STS-AUTHN-0017',
    summary: 'The federation register threw while resolving a brokering ' +
      'relationship or building the sign-in screen\'s partner buttons; ' +
      'they were omitted.',
    spec: '' },
  { code: 'STS-AUTHN-0018',
    summary: 'A request to a second-factor screen (security key, one-time ' +
      'code, recovery code) carried a step id that failed input ' +
      'validation.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-AUTHN-0019',
    summary: 'The second-factor step named by the request has expired or ' +
      'does not exist.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-AUTHN-0020',
    summary: 'The WebAuthn ceremony POST failed input validation.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-AUTHN-0021',
    summary: 'The WebAuthn ceremony result posted by the browser was not ' +
      'JSON.',
    spec: 'HTTP 200 security-key page, redrawn with the reason' },
  { code: 'STS-AUTHN-0022',
    summary: 'The browser reported that the WebAuthn ceremony failed ' +
      '(declined, timed out, no authenticator), or sent no credential ' +
      'at all.',
    spec: 'HTTP 200 security-key page, redrawn with the reason; on the ' +
      'portal, its own refusal' },
  { code: 'STS-AUTHN-0023',
    summary: 'In product mode the configured webauthn.rpId does not fit the ' +
      'host the request arrived on, so the ceremony is refused.',
    spec: 'HTTP 200 security-key page with the reason' },
  { code: 'STS-AUTHN-0024',
    summary: 'Product mode refused to enrol a credential (security key or ' +
      'authenticator app) for a person who has no directory entry, ' +
      'because enrolling would create them.',
    spec: 'HTTP 200 page / action result with the reason' },
  { code: 'STS-AUTHN-0025',
    summary: 'No security key is enrolled for this person in the role the ' +
      'step needs (second factor or passwordless).',
    spec: 'invalid_request (HTTP 400), or HTTP 200 security-key page with ' +
      'the reason' },
  { code: 'STS-AUTHN-0026',
    summary: 'A WebAuthn assertion named a credential that is not one of the ' +
      'security keys enrolled for this person in this role.',
    spec: 'HTTP 200 security-key page with the reason' },
  { code: 'STS-AUTHN-0027',
    summary: 'The WebAuthn registration or assertion could not be parsed or ' +
      'checked (malformed CBOR, authenticator data or ' +
      'clientDataJSON).',
    spec: 'HTTP 200 security-key page with the reason; on the portal, its ' +
      'own refusal' },
  { code: 'STS-AUTHN-0028',
    summary: 'WebAuthn verification failed: clientDataJSON\'s type is not ' +
      'the ceremony\'s (webauthn.create / webauthn.get).',
    spec: 'HTTP 200 page naming the failed check' },
  { code: 'STS-AUTHN-0029',
    summary: 'WebAuthn verification failed: the challenge in clientDataJSON ' +
      'is not the one this service issued for the step.',
    spec: 'HTTP 200 page naming the failed check' },
  { code: 'STS-AUTHN-0030',
    summary: 'WebAuthn verification failed: the origin in clientDataJSON is ' +
      'not this service\'s origin or on webauthn.allowedOrigins.',
    spec: 'HTTP 200 page naming the failed check' },
  { code: 'STS-AUTHN-0031',
    summary: 'WebAuthn verification failed: the RP ID hash in the ' +
      'authenticator data is not SHA-256 of the expected RP ID.',
    spec: 'HTTP 200 page naming the failed check' },
  { code: 'STS-AUTHN-0032',
    summary: 'WebAuthn verification failed: the authenticator data does not ' +
      'have the user-present (UP) flag set.',
    spec: 'HTTP 200 page naming the failed check' },
  { code: 'STS-AUTHN-0033',
    summary: 'WebAuthn verification failed: webauthn.userVerification is ' +
      'required and the authenticator did not set the user-verified ' +
      '(UV) flag.',
    spec: 'HTTP 200 page naming the failed check' },
  { code: 'STS-AUTHN-0034',
    summary: 'WebAuthn registration failed: the authenticator data carries ' +
      'no attested credential data (AT flag clear).',
    spec: 'HTTP 200 page naming the failed check' },
  { code: 'STS-AUTHN-0035',
    summary: 'WebAuthn assertion failed: the signature counter did not ' +
      'advance past the stored value, which is the signature of a ' +
      'cloned authenticator.',
    spec: 'HTTP 200 page naming the failed check' },
  { code: 'STS-AUTHN-0036',
    summary: 'WebAuthn assertion failed: the signature over ' +
      'authenticatorData and the clientDataJSON hash does not verify ' +
      'against the enrolled public key.',
    spec: 'HTTP 200 page naming the failed check' },
  { code: 'STS-AUTHN-0037',
    summary: 'A WebAuthn ceremony failed a check this service has no ' +
      'specific code for; the check-name table in ' +
      'authn/webauthn_policy.js is behind the verifier.',
    spec: 'HTTP 200 page naming the failed check' },
  { code: 'STS-AUTHN-0038',
    summary: 'A security key\'s signature counter could not be recorded ' +
      'after a successful assertion; the sign-in stands and the replay ' +
      'defence has nothing new to check next time.',
    spec: '' },
  { code: 'STS-AUTHN-0039',
    summary: 'The one-time code form POST failed input validation.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-AUTHN-0040',
    summary: 'Too many one-time code attempts for this identity or address; ' +
      'the code was not checked (rate limiter lockout).',
    spec: 'HTTP 200 one-time code page, redrawn with the reason' },
  { code: 'STS-AUTHN-0041',
    summary: 'The recovery code form POST failed input validation.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-AUTHN-0042',
    summary: 'Too many recovery code attempts for this identity or address; ' +
      'the code was not checked (rate limiter lockout).',
    spec: 'HTTP 200 recovery code page, redrawn with the reason' },
  { code: 'STS-AUTHN-0043',
    summary: 'Checking a recovery code threw (the worker pool or the store ' +
      'failed part way).',
    spec: 'HTTP 200 recovery code page asking to try again' },
  { code: 'STS-AUTHN-0044',
    summary: 'Security keys are switched off in this realm ' +
      '(webauthn.enabled), so no new key may be enrolled.',
    spec: 'HTTP 200 page / action result with the reason' },
  { code: 'STS-AUTHN-0045',
    summary: 'A passwordless (primary) security key may not be enrolled in ' +
      'this realm (webauthn.primaryAllowed).',
    spec: 'HTTP 200 page / action result with the reason' },
  { code: 'STS-AUTHN-0046',
    summary: 'A second-factor security key may not be enrolled in this realm ' +
      '(webauthn.mfaAllowed).',
    spec: 'HTTP 200 page / action result with the reason' },
  { code: 'STS-AUTHN-0047',
    summary: 'The credential store\'s setDirectory() hooks were refused ' +
      'whole because readPassword or writePassword was missing.',
    spec: '' },
  { code: 'STS-AUTHN-0048',
    summary: 'A password was refused because it is the reserved refusal ' +
      'password \'invalid\', refused in every mode.',
    spec: 'the calling protocol\'s own authentication failure (sign-in ' +
      'page, LDAP invalidCredentials (49), SOAP fault, HTTP 401)' },
  { code: 'STS-AUTHN-0049',
    summary: 'A password verification was asked for with no username, in ' +
      'product mode.',
    spec: 'the calling protocol\'s own authentication failure' },
  { code: 'STS-AUTHN-0050',
    summary: 'Product mode is in force and no credential store is installed, ' +
      'so every password verification is refused (fail closed).',
    spec: 'the calling protocol\'s own authentication failure' },
  { code: 'STS-AUTHN-0051',
    summary: 'The stored password could not be read because the credential ' +
      'store threw; the verification was refused.',
    spec: 'the calling protocol\'s own authentication failure' },
  { code: 'STS-AUTHN-0052',
    summary: 'The person holds no stored password (userPassword), so product ' +
      'mode cannot verify one.',
    spec: 'the calling protocol\'s own authentication failure' },
  { code: 'STS-AUTHN-0053',
    summary: 'The stored userPassword is not in the hashed form this service ' +
      'writes, so it was refused rather than compared as plaintext.',
    spec: 'the calling protocol\'s own authentication failure' },
  { code: 'STS-AUTHN-0054',
    summary: 'The presented password does not match the stored hash.',
    spec: 'the calling protocol\'s own authentication failure' },
  { code: 'STS-AUTHN-0055',
    summary: 'Setting a password was asked for with no password given.',
    spec: 'action result with the reason (HTTP 200 page / JSON / LDAP ' +
      'result)' },
  { code: 'STS-AUTHN-0056',
    summary: 'A new password was refused by the realm\'s password policy ' +
      '(length, symbols, uppercase, digit).',
    spec: 'action result with the reason; LDAP constraintViolation where ' +
      'written over the socket' },
  { code: 'STS-AUTHN-0057',
    summary: 'A new password was refused because it is the current password ' +
      'or one of the remembered previous ones (pwdInHistory).',
    spec: 'action result with the reason; LDAP constraintViolation where ' +
      'written over the socket' },
  { code: 'STS-AUTHN-0058',
    summary: 'A credential operation (set a password, enrol an ' +
      'authenticator, generate recovery codes, issue an activation ' +
      'link) named no person.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0059',
    summary: 'A credential operation was refused because no credential store ' +
      'is installed in this process (or it lacks the functions for ' +
      'that credential).',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0060',
    summary: 'Writing a password to the credential store threw.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0061',
    summary: 'A credential write named a person who has no entry in this ' +
      'realm\'s directory.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0062',
    summary: 'The product-mode bootstrap could not ask the store whether ' +
      'anybody holds a credential, so no bootstrap account was ' +
      'attempted.',
    spec: '' },
  { code: 'STS-AUTHN-0063',
    summary: 'The product-mode bootstrap account could not be created in the ' +
      'directory.',
    spec: '' },
  { code: 'STS-AUTHN-0064',
    summary: 'The product-mode bootstrap could not set a password: this ' +
      'service is in product mode and nobody can sign in.',
    spec: '' },
  { code: 'STS-AUTHN-0065',
    summary: 'Reading a person\'s security keys from the credential store ' +
      'threw; they were reported as holding none.',
    spec: '' },
  { code: 'STS-AUTHN-0066',
    summary: 'A security key was to be recorded or enrolled in a role that ' +
      'is neither \'primary\' nor \'mfa\'.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0067',
    summary: 'A security key was not enrolled because the person already ' +
      'holds webauthn.maxKeysPerPerson keys.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0068',
    summary: 'Writing a security key to the credential store threw, or the ' +
      'store refused to record a verified key.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0069',
    summary: 'Removing a security key named a credential id that is not ' +
      'enrolled for that person.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0070',
    summary: 'Removing a security key was refused because it is the ' +
      'person\'s last way in (no password and no other primary key).',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0071',
    summary: 'Reading a person\'s authenticator-app enrolment from the ' +
      'credential store threw; it was reported as none.',
    spec: '' },
  { code: 'STS-AUTHN-0072',
    summary: 'An authenticator-app shared secret could not be sealed under ' +
      'the key-encryption key, so it was not stored.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0073',
    summary: 'Writing or clearing an authenticator-app enrolment in the ' +
      'credential store threw.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0074',
    summary: 'An authenticator-app enrolment was refused because ' +
      'authenticator apps are switched off (totp.enabled).',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0075',
    summary: 'A pending authenticator-app or security-key enrolment was not ' +
      'found to confirm: it expired or was never begun.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0076',
    summary: 'No authenticator app is enrolled for the person a one-time ' +
      'code step, verification or removal named.',
    spec: 'invalid_request (HTTP 400) at the sign-in screen; action ' +
      'result elsewhere' },
  { code: 'STS-AUTHN-0077',
    summary: 'The person\'s authenticator-app enrolment cannot be read (not ' +
      'JSON, or sealed under a different key-encryption key), so the ' +
      'second factor is refused rather than skipped.',
    spec: 'HTTP 200 one-time code page with the reason' },
  { code: 'STS-AUTHN-0078',
    summary: 'A one-time code verified but the accepted step could not be ' +
      'written back, so that code could be replayed inside its ' +
      'window.',
    spec: '' },
  { code: 'STS-AUTHN-0079',
    summary: 'Listing this realm\'s people for the second-factor roster ' +
      'threw; the roster lists only people otherwise known.',
    spec: '' },
  { code: 'STS-AUTHN-0080',
    summary: 'Reading a person\'s recovery codes from the credential store ' +
      'threw; they were reported as none.',
    spec: '' },
  { code: 'STS-AUTHN-0081',
    summary: 'Writing or clearing a person\'s recovery codes in the ' +
      'credential store threw.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0082',
    summary: 'Generating recovery codes was refused because they are ' +
      'switched off (backupCodes.enabled).',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0083',
    summary: 'A set of distinct recovery codes could not be generated at the ' +
      'configured count and length.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0084',
    summary: 'No pending set of recovery codes was found to confirm: it ' +
      'expired, or the handle is not this person\'s.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0085',
    summary: 'A confirmed set of recovery codes could not be stored; the set ' +
      'is still pending and confirming again retries.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0086',
    summary: 'A request to show a person\'s recovery codes again was ' +
      'refused: only hashes are stored.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0087',
    summary: 'No recovery codes have been issued for the person a ' +
      'recovery-code screen, verification or removal named.',
    spec: 'invalid_request (HTTP 400) at the sign-in screen; action ' +
      'result elsewhere' },
  { code: 'STS-AUTHN-0088',
    summary: 'Every recovery code in the person\'s set has already been ' +
      'used, so the recovery-code screen was refused.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-AUTHN-0089',
    summary: 'The person\'s stored recovery codes cannot be read, so a ' +
      'presented code was refused rather than let through.',
    spec: 'HTTP 200 recovery code page with the reason' },
  { code: 'STS-AUTHN-0090',
    summary: 'A presented recovery code is not the shape of one (letters and ' +
      'digits of the code alphabet); no comparison was made.',
    spec: 'HTTP 200 recovery code page with the reason' },
  { code: 'STS-AUTHN-0091',
    summary: 'A presented recovery code has already been spent.',
    spec: 'HTTP 200 recovery code page with the reason' },
  { code: 'STS-AUTHN-0092',
    summary: 'A presented recovery code is not one of the person\'s codes.',
    spec: 'HTTP 200 recovery code page with the reason' },
  { code: 'STS-AUTHN-0093',
    summary: 'A recovery code verified but could not be marked spent, so it ' +
      'was refused: a code that cannot be spent works for ever.',
    spec: 'HTTP 200 recovery code page with the reason' },
  { code: 'STS-AUTHN-0094',
    summary: 'A security-key enrolment was confirmed with an enrolment id ' +
      'that is not the one in progress (another tab).',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0095',
    summary: 'A security-key enrolment was refused because that ' +
      'authenticator is already enrolled for the person.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0096',
    summary: 'An activation link was checked with no username or no token.',
    spec: 'the portal\'s activation refusal page' },
  { code: 'STS-AUTHN-0097',
    summary: 'Reading an activation token from the credential store threw; ' +
      'the link was refused.',
    spec: 'the portal\'s activation refusal page' },
  { code: 'STS-AUTHN-0098',
    summary: 'An activation link was presented for a person with no ' +
      'outstanding activation token.',
    spec: 'the portal\'s activation refusal page' },
  { code: 'STS-AUTHN-0099',
    summary: 'An activation link was presented after its token expired ' +
      '(security.activationTtlMinutes).',
    spec: 'the portal\'s activation refusal page' },
  { code: 'STS-AUTHN-0100',
    summary: 'An activation link\'s token does not match the one issued for ' +
      'that person.',
    spec: 'the portal\'s activation refusal page' },
  { code: 'STS-AUTHN-0101',
    summary: 'Writing an activation token to the credential store threw; no ' +
      'link was issued.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0102',
    summary: 'A spent activation token could not be cleared from the ' +
      'credential store, so the link may still work.',
    spec: '' },
  { code: 'STS-AUTHN-0103',
    summary: 'A presented one-time code is not the configured number of ' +
      'digits; no comparison was made.',
    spec: 'HTTP 200 one-time code page with the reason; action result at ' +
      'enrolment' },
  { code: 'STS-AUTHN-0104',
    summary: 'A stored TOTP shared secret could not be decoded from base32, ' +
      'so the code could not be checked.',
    spec: 'HTTP 200 one-time code page with the reason' },
  { code: 'STS-AUTHN-0105',
    summary: 'A presented one-time code matched no time step in the allowed ' +
      'window: wrong, or expired.',
    spec: 'HTTP 200 one-time code page with the reason; action result at ' +
      'enrolment' },
  { code: 'STS-AUTHN-0106',
    summary: 'A presented one-time code was already used (RFC 6238 section ' +
      '5.2): its time step is at or below the last one accepted.',
    spec: 'HTTP 200 one-time code page with the reason' },
  { code: 'STS-AUTHN-0107',
    summary: 'A password policy save or reset named a profile other than ' +
      '\'default\'.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0108',
    summary: 'A password policy save was refused because a field is missing, ' +
      'out of range, unreadable, or inconsistent with another.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0109',
    summary: 'A password policy save was refused because this process has no ' +
      'embedded directory to keep ou=passwordPolicies in.',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0110',
    summary: 'The directory refused to store the password policy profile (it ' +
      'is at its maximum number of entries).',
    spec: 'action result with the reason' },
  { code: 'STS-AUTHN-0111',
    summary: 'No generated password satisfied the password policy within the ' +
      'draw limit, so none was generated.',
    spec: 'the caller\'s own failure (usually HTTP 500 or an action ' +
      'refusal)' },
  { code: 'STS-AUTHN-0112',
    summary: 'A hosted surface (console or portal) cannot sign anybody in: ' +
      'its seeded OIDC client is not in this realm\'s registry.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0113',
    summary: 'A hosted surface\'s seeded OIDC client carries no client ' +
      'secret, so it cannot authenticate at the token endpoint.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0114',
    summary: 'Product mode refused a hosted-surface sign-in because this ' +
      'service was reached at an address that is not a registered ' +
      'redirect URI of its client.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0115',
    summary: 'In development a hosted surface\'s client could not learn the ' +
      'redirect URI for the address it was reached at; the sign-in ' +
      'went ahead.',
    spec: '' },
  { code: 'STS-AUTHN-0116',
    summary: 'The OIDC back channel could not read this service\'s own TLS ' +
      'certificate to verify the loopback connection against.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0117',
    summary: 'The OIDC back channel\'s token or JWKS request was answered ' +
      'with a redirect, which is not followed.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0118',
    summary: 'The OIDC back channel\'s answer was larger than the limit and ' +
      'was abandoned.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0119',
    summary: 'The OIDC back channel did not get an answer from this service ' +
      'within oidcRp.backChannelTimeoutS.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0120',
    summary: 'The OIDC back channel\'s loopback request to this service ' +
      'failed (connection refused, reset, TLS error).',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0121',
    summary: 'A hosted surface\'s callback carried an error from the ' +
      'authorization endpoint (for example the person declined).',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0122',
    summary: 'A hosted surface\'s callback carried no code or no state.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0123',
    summary: 'A hosted surface\'s callback named a state this service did ' +
      'not start, already completed, or has forgotten.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0124',
    summary: 'A hosted surface\'s callback presented a state that belongs to ' +
      'the other surface.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0125',
    summary: 'A hosted surface\'s sign-in flow took longer than ' +
      'authn.pendingTtlS and expired before the callback.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0126',
    summary: 'The token endpoint refused a hosted surface\'s authorization ' +
      'code redemption (a non-200 answer).',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0127',
    summary: 'The token response to a hosted surface carried no id_token.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0128',
    summary: 'A hosted surface could not read this service\'s own JWKS to ' +
      'verify the ID Token.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0129',
    summary: 'The ID Token issued to a hosted surface has a header that is ' +
      'not base64url JSON.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0130',
    summary: 'The ID Token issued to a hosted surface has no alg in its ' +
      'header.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0131',
    summary: 'The ID Token issued to a hosted surface says alg=none.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0132',
    summary: 'The ID Token issued to a hosted surface names a kid the JWKS ' +
      'does not publish, or the JWKS publishes no keys.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0133',
    summary: 'The ID Token issued to a hosted surface did not verify against ' +
      'any published key (signature, issuer, audience or lifetime).',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0134',
    summary: 'The ID Token issued to a hosted surface carries a nonce that ' +
      'is not the one the sign-in sent.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0135',
    summary: 'The ID Token issued to a hosted surface names nobody: no ' +
      'preferred_username and no sub.',
    spec: 'the console\'s or portal\'s sign-in refusal page' },
  { code: 'STS-AUTHN-0136',
    summary: 'A console or portal session\'s ID Token and access token ran ' +
      'out and its sign-in was issued no refresh token to renew them with; ' +
      'the session was ended.',
    spec: 'none — the next page runs the authorization code flow again' },
  { code: 'STS-AUTHN-0137',
    summary: 'The token endpoint refused the refresh token grant a console ' +
      'or portal session made to renew its tokens (a revoked, replayed or ' +
      'expired refresh token); the session was ended.',
    spec: 'none — the next page runs the authorization code flow again' },
  { code: 'STS-AUTHN-0138',
    summary: 'The ID Token a console or portal renewal was issued names a ' +
      'different issuer, subject or authentication time from the sign-in ' +
      '(OpenID Connect Core section 12.2); the session was ended.',
    spec: 'none — the next page runs the authorization code flow again' },
  { code: 'STS-AUTHN-0139',
    summary: 'A console or portal session could not renew its tokens because ' +
      'the trust realm its sign-in ran in no longer exists; the session was ' +
      'ended.',
    spec: 'none — the next page runs the authorization code flow again' },
  { code: 'STS-AUTHN-0140',
    summary: 'Renewing a console or portal session\'s tokens threw; the ' +
      'request went on and the renewal is tried again on the next one.',
    spec: 'none' },
  { code: 'STS-AUTHN-0141',
    summary: 'A console or portal session\'s tokens ran out after the window ' +
      'it could renew them in (the refresh token\'s lifetime from the ' +
      'sign-in) had closed; the session was ended.',
    spec: 'none — the next page runs the authorization code flow again' },
  { code: 'STS-AUTHN-0142',
    summary: 'A correct password was refused at a door that cannot ask for ' +
      'a new one (an LDAP bind, the password grant, WS-Trust, SCIM or EST ' +
      'Basic) because pwdReset is TRUE on the entry; in product mode only.',
    spec: 'that protocol\'s own authentication failure' },
  { code: 'STS-AUTHN-0143',
    summary: 'pwdReset could not be written on a person\'s entry.',
    spec: 'none — logged' },
  { code: 'STS-AUTHN-0144',
    summary: 'A forced password change named a step that does not exist or ' +
      'has expired.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-AUTHN-0145',
    summary: 'A forced password change request was refused by the input ' +
      'validator.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-AUTHN-0146',
    summary: 'A forced password change was refused: no new password, two ' +
      'that differ, the reserved refusal password, or one the password ' +
      'policy refused; the page is drawn again with the reason.',
    spec: 'the change page again with the reason' },
  // WHAT AN ADMINISTRATOR DOES TO SOMEBODY'S CREDENTIALS, AND THE SIGN-IN
  // ENROLMENT A REQUIRED SECOND FACTOR ASKS FOR (2026-09-13).
  { code: 'STS-AUTHN-0160',
    summary: 'Disabling somebody\'s passwordless sign-in was refused: they ' +
      'hold no security key in the primary role.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-AUTHN-0161',
    summary: 'Disabling somebody\'s passwordless sign-in was refused: they ' +
      'have no password, so their primary security keys are their only way ' +
      'in.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-AUTHN-0162',
    summary: 'Disabling somebody\'s second factors was refused: they hold no ' +
      'authenticator app, no mfa-role security key and no recovery codes.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-AUTHN-0163',
    summary: 'The credential store refused a write while security keys or ' +
      'second factors were being removed; what went before it is reported.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-AUTHN-0164',
    summary: 'A password reset link could not be written onto, or cleared ' +
      'from, the person\'s entry.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-AUTHN-0165',
    summary: 'A password reset link was presented for somebody with none ' +
      'outstanding (never issued, or already spent).',
    spec: 'the reset page\'s one refusal sentence, HTTP 400' },
  { code: 'STS-AUTHN-0166',
    summary: 'A password reset link was presented after it expired ' +
      '(security.passwordResetTtlMinutes).',
    spec: 'the reset page\'s one refusal sentence, HTTP 400' },
  { code: 'STS-AUTHN-0167',
    summary: 'A password reset link was presented whose token does not match ' +
      'the hash on the entry.',
    spec: 'the reset page\'s one refusal sentence, HTTP 400' },
  { code: 'STS-AUTHN-0168',
    summary: 'A password reset link was presented with no username or no ' +
      'token.',
    spec: 'the reset page\'s one refusal sentence, HTTP 400' },
  { code: 'STS-AUTHN-0169',
    summary: 'The password could not be removed from somebody\'s entry while ' +
      'a password reset link was being issued, so the link was withdrawn.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-AUTHN-0170',
    summary: 'The per-account second-factor requirement (stsMfaRequired) ' +
      'could not be written.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-AUTHN-0171',
    summary: 'A passwordless security-key sign-in was refused because a ' +
      'second factor is required of the person (their account or the ' +
      'realm\'s authn.mfaRequired).',
    spec: 'the sign-in screen again with the reason' },
  { code: 'STS-AUTHN-0172',
    summary: 'A sign-in was refused: a second factor is required of the ' +
      'person, they hold none, and neither an authenticator app nor a ' +
      'security key can be enrolled in the realm.',
    spec: 'the sign-in screen again with the reason' },
  { code: 'STS-AUTHN-0173',
    summary: 'The second-factor set-up step named by the request is expired, ' +
      'unknown, or not a set-up step.',
    spec: 'OAuth-style invalid_request page, HTTP 400' },
  { code: 'STS-AUTHN-0174',
    summary: 'A request to the second-factor set-up step was malformed, or ' +
      'asked to confirm a code before an authenticator app was chosen.',
    spec: 'HTTP 400 page' },
  { code: 'STS-AUTHN-0175',
    summary: 'A second-factor set-up choice was refused: the mechanism is ' +
      'switched off in the realm, or the person holds a second factor ' +
      'already.',
    spec: 'HTTP 400 page' },
  { code: 'STS-AUTHN-0176',
    summary: 'An authenticator app enrolment at sign-in could not be started.',
    spec: 'HTTP 400 page' },
  { code: 'STS-AUTHN-0177',
    summary: 'The code confirming an authenticator app enrolled at sign-in ' +
      'was refused; the same secret is drawn again.',
    spec: 'HTTP 400 page' },
  { code: 'STS-AUTHN-0180',
    summary: 'A signed-in session was refused because the directory holds ' +
      'no entry for the person, so there is no subject to give it ' +
      '(ldap.autocreateUsers off, or a federation relationship with ' +
      'dynamic provisioning off and nobody provisioned).',
    spec: 'the calling door\'s own refusal' },
  // ----- #46: the hosted surfaces renew once across the cluster -------------
  { code: 'STS-AUTHN-0181',
    summary: 'A security-key assertion verified and was refused because its ' +
      'ceremony challenge had already been answered, by another node or a ' +
      'request racing this one (#46).',
    spec: 'HTTP 200 security-key page with the reason' },
  { code: 'STS-AUTHN-0182',
    summary: 'A single-use credential (a one-time code step, a recovery ' +
      'code, a security-key assertion, an activation or password reset link) ' +
      'could not be proved unspent because the cluster store could not be ' +
      'asked, so it was refused.',
    spec: 'the calling door\'s own refusal page' },
  { code: 'STS-AUTHN-0183',
    summary: 'An activation or password reset link was refused because ' +
      'another request, on this node or another, is spending it or has ' +
      'spent it.',
    spec: 'HTTP 400 portal page (one sentence for every link failure)' },
  { code: 'STS-AUTHN-0184',
    summary: 'Recovery codes another node spent could not be written as ' +
      'spent on the person\'s entry; their claims still refuse them.',
    spec: 'none (log only)' },
  { code: 'STS-AUTHN-0185',
    summary: 'The product-mode bootstrap was not attempted on this node: the ' +
      'store could not be asked whether another node is running it.',
    spec: 'none (log only)' },
  { code: 'STS-AUTHN-0189',
    summary: 'A hosted surface\'s token renewal was in flight on another ' +
      'node (its claim was held) and its renewed tokens had not reached ' +
      'this node within the wait; this request went on without renewing.',
    spec: 'none — logged only' },
  { code: 'STS-AUTHN-0190',
    summary: 'A hosted surface could not renew a session\'s tokens because ' +
      'the claim store could not be asked; the request went on without ' +
      'renewing, rather than risk a second redemption of the refresh token.',
    spec: 'none — logged only' },
  { code: 'STS-AUTHN-0191',
    summary: 'A sign-out ended a session whose end another process had ' +
      'already reported, so no second event or success row was written.',
    spec: 'none — audit row only; the sign-out is answered as usual' },
  { code: 'STS-AUTHN-0192',
    summary: 'Whether another process had already reported a session\'s end ' +
      'could not be asked, so it was reported here and a receiver may be ' +
      'told twice.',
    spec: 'none — logged' },
  { code: 'STS-AUTHN-0193',
    summary: 'A security key registration was refused because the same ' +
      'credential id was being (or had just been) registered by another ' +
      'request or node.',
    spec: 'WebAuthn Level 3 section 7.1 step 26 (a credential id already ' +
      'registered is refused)' },
  { code: 'STS-AUTHN-0194',
    summary: 'A security key registration was refused because the store that ' +
      'decides whether its credential id is already registered elsewhere ' +
      'could not be asked.',
    spec: 'none — fail closed' },
  // ===== OAUTH =============================================================
  { code: 'STS-OAUTH-0001',
    summary: 'A JWT client assertion could not be read as a JWT (its header ' +
      'is not base64url JSON).',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0002',
    summary: 'A client_secret_jwt client assertion was signed with an ' +
      'algorithm other than HS256, HS384 or HS512.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0003',
    summary: 'A client_secret_jwt client assertion arrived for a client ' +
      'whose registry entry holds no client_secret to verify it with.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0004',
    summary: 'A private_key_jwt client assertion named a symmetric algorithm ' +
      'or none — the alg-confusion forgery — and was refused.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0005',
    summary: 'A private_key_jwt client registered only a jwks_uri, which ' +
      'this service will not fetch, so there was no key to verify its ' +
      'assertion with.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0006',
    summary: 'A private_key_jwt client has no keys registered or issued, so ' +
      'its client assertion could not be verified.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0007',
    summary: 'A JWT client assertion did not verify: wrong key, wrong ' +
      'issuer, wrong audience or expired.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0008',
    summary: 'A JWT client assertion\'s sub is not the client it ' +
      'authenticates (RFC 7523 section 3).',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0009',
    summary: 'A JWT client assertion carried no exp, which product mode ' +
      'refuses (RFC 7523 section 3 claim 4).',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0010',
    summary: 'A JWT client assertion is valid for longer than ' +
      'oauth2.jwtBearerMaxLifetimeS allows.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0011',
    summary: 'A JWT client assertion carried no jti, so a replay of it could ' +
      'not be refused.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0012',
    summary: 'A JWT client assertion was replayed: its issuer and jti are ' +
      'already in the used-assertion history, spent or held by a request in ' +
      'flight, as a client assertion or as a grant.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0013',
    summary: 'The used-assertion history for the realm holds ' +
      'oauth2.assertionReplayCacheSize unexpired rows, so a new client ' +
      'assertion was refused rather than a live row forgotten.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0014',
    summary: 'A client registered for RFC 8705 certificate authentication ' +
      'connected with no TLS client certificate.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0015',
    summary: 'A self_signed_tls_client_auth client has no certificate ' +
      'thumbprint registered to compare against.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0016',
    summary: 'A self_signed_tls_client_auth client presented a certificate ' +
      'whose thumbprint is not the registered one (RFC 8705 section ' +
      '2.2).',
    spec: 'invalid_client (HTTP 401)' },
  // RETIRED 2026-09-13: a tls_client_auth client needs no subject DN (a
  // certificate this realm issued to it authenticates it) — STS-OAUTH-0486 is
  // the refusal for an external certificate with nothing registered — and a
  // DN is compared as a name alongside four other subject parameters, which
  // is STS-OAUTH-0485.
  { code: 'STS-OAUTH-0017',
    summary: 'A tls_client_auth client has no subject DN registered to ' +
      'compare against.',
    spec: 'invalid_client (HTTP 401)', retired: true },
  { code: 'STS-OAUTH-0018',
    summary: 'A tls_client_auth client presented a certificate whose subject ' +
      'DN is not the registered one (RFC 8705 section 2.1.2).',
    spec: 'invalid_client (HTTP 401)', retired: true },
  { code: 'STS-OAUTH-0019',
    summary: 'A client_secret_basic or client_secret_post client presented ' +
      'no client_secret.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0020',
    summary: 'The client_secret presented does not match the one on the ' +
      'client\'s registry entry.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0021',
    summary: 'A client_secret_jwt or private_key_jwt client sent no ' +
      'client_assertion.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0022',
    summary: 'A JWT client assertion arrived under a client_assertion_type ' +
      'other than RFC 7523\'s.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0023',
    summary: 'A saml2_bearer client sent no client_assertion (RFC 7522 ' +
      'section 2.2).',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0024',
    summary: 'A SAML client assertion arrived under a client_assertion_type ' +
      'other than RFC 7522\'s.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0025',
    summary: 'The client\'s registry entry names a ' +
      'token_endpoint_auth_method this service cannot verify.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0026',
    summary: 'A JWKS registered for an RFC 7523 party (client or assertion ' +
      'issuer) is not valid JSON.',
    spec: 'invalid_client (HTTP 401) or invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0027',
    summary: 'A JWKS registered for an RFC 7523 party contains no keys.',
    spec: 'invalid_client (HTTP 401) or invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0028',
    summary: 'None of the keys in a JWKS registered for an RFC 7523 party ' +
      'could be read.',
    spec: 'invalid_client (HTTP 401) or invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0029',
    summary: 'An encrypted (five-part) JWT assertion has a protected header ' +
      'that is not base64url JSON.',
    spec: 'invalid_client (HTTP 401) or invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0030',
    summary: 'An encrypted JWT assertion names an algorithm, curve or kid ' +
      'for which this authorization server holds no decryption key.',
    spec: 'invalid_client (HTTP 401) or invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0031',
    summary: 'An encrypted JWT assertion could not be decrypted with any ' +
      'candidate key.',
    spec: 'invalid_client (HTTP 401) or invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0032',
    summary: 'An encrypted JWT assertion\'s protected header carries a cty ' +
      'other than JWT.',
    spec: 'invalid_client (HTTP 401) or invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0033',
    summary: 'An encrypted JWT assertion decrypted to something that is not ' +
      'a signed JWT (RFC 7523 section 3 claim 9).',
    spec: 'invalid_client (HTTP 401) or invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0034',
    summary: 'The x5c certificate chain in a JWT assertion\'s header could ' +
      'not be path-checked at all.',
    spec: 'invalid_client (HTTP 401) or invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0035',
    summary: 'The x5c certificate in a JWT assertion does not chain to this ' +
      'realm\'s own certificate authority.',
    spec: 'invalid_client (HTTP 401) or invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0036',
    summary: 'The x5c leaf certificate in a JWT assertion chains here but ' +
      'could not be read for its public key.',
    spec: 'invalid_client (HTTP 401) or invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0037',
    summary: 'An RFC 7523 JWT bearer grant was requested while ' +
      'oauth2.jwtBearerGrant is off.',
    spec: 'unsupported_grant_type (HTTP 400)' },
  { code: 'STS-OAUTH-0038',
    summary: 'An RFC 7523 JWT bearer grant request carried no assertion ' +
      'parameter.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0039',
    summary: 'An RFC 7523 authorization-grant assertion is not a JWT.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0040',
    summary: 'An RFC 7523 authorization-grant assertion says alg=none.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0041',
    summary: 'An RFC 7523 authorization-grant assertion is signed with an ' +
      'algorithm this service does not verify.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0042',
    summary: 'An RFC 7523 authorization-grant assertion carries no iss ' +
      '(section 3 claim 1).',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0043',
    summary: 'An RFC 7523 authorization-grant assertion names an issuer ' +
      'nobody in the realm has declared, and no x5c chain vouches for ' +
      'it.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0044',
    summary: 'The application declared as an RFC 7523 assertion issuer ' +
      'registered only a jwks_uri, which this service will not fetch.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0045',
    summary: 'The keys registered for an RFC 7523 assertion issuer could not ' +
      'be read.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0046',
    summary: 'No key is registered or issued for an RFC 7523 assertion ' +
      'issuer, so its assertion could not be verified.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0047',
    summary: 'An RFC 7523 authorization-grant assertion did not verify: ' +
      'wrong key, wrong audience or expired.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0048',
    summary: 'An RFC 7523 authorization-grant assertion carries no sub ' +
      '(section 3 claim 2).',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0049',
    summary: 'A person\'s RFC 7523 assertion named somebody other than that ' +
      'person as its subject.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0050',
    summary: 'An RFC 7523 authorization-grant assertion carries no exp ' +
      '(section 3 claim 4).',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0051',
    summary: 'An RFC 7523 authorization-grant assertion\'s iat is in the ' +
      'future beyond the allowed clock skew.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0052',
    summary: 'An RFC 7523 authorization-grant assertion is valid for longer ' +
      'than oauth2.jwtBearerMaxLifetimeS allows.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0053',
    summary: 'An RFC 7523 authorization-grant assertion carries no jti, so ' +
      'it could not be spent.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0054',
    summary: 'An RFC 7523 authorization-grant assertion was replayed: its ' +
      'issuer and jti are already in the used-assertion history, spent or ' +
      'held by a request in flight, as a grant or as a client assertion.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0055',
    summary: 'The used-assertion history for the realm holds ' +
      'oauth2.assertionReplayCacheSize unexpired rows, so a new RFC 7523 ' +
      'grant was refused rather than a live row forgotten.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0056',
    summary: 'An RFC 7522 SAML 2.0 bearer grant was requested while ' +
      'oauth2.saml2BearerGrant is off.',
    spec: 'unsupported_grant_type (HTTP 400)' },
  { code: 'STS-OAUTH-0057',
    summary: 'An RFC 7522 SAML assertion was missing or would not decode ' +
      'from base64url XML.',
    spec: 'invalid_request (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0058',
    summary: 'An encrypted RFC 7522 SAML assertion would not decrypt.',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0059',
    summary: 'An RFC 7522 SAML document would not parse as a SAML 2.0 ' +
      'Assertion.',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0060',
    summary: 'An RFC 7522 SAML assertion carries a Version other than 2.0.',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0061',
    summary: 'An RFC 7522 SAML assertion carries no Issuer (section 3 item ' +
      '1).',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0062',
    summary: 'An RFC 7522 SAML assertion names an Issuer no application in ' +
      'the realm has declared as oauthSamlAssertionIssuer.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0063',
    summary: 'The certificates registered for an RFC 7522 assertion issuer ' +
      'or client could not be read.',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0064',
    summary: 'No RFC 7522 certificate is registered for the assertion issuer ' +
      'or client, so its SAML assertion could not be verified.',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0065',
    summary: 'An RFC 7522 SAML assertion carries no signature of its own ' +
      '(section 3 item 9).',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0066',
    summary: 'An RFC 7522 SAML assertion\'s KeyInfo certificate is not one ' +
      'registered for RFC 7522 against its issuer or client.',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0067',
    summary: 'An RFC 7522 SAML assertion\'s signature did not verify against ' +
      'any registered certificate.',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0068',
    summary: 'An RFC 7522 SAML assertion carries a Condition this ' +
      'authorization server cannot evaluate.',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0069',
    summary: 'A timestamp in an RFC 7522 SAML assertion (NotBefore, ' +
      'NotOnOrAfter or IssueInstant) is not an xsd:dateTime.',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0070',
    summary: 'An RFC 7522 SAML assertion is not yet valid (Conditions ' +
      'NotBefore).',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0071',
    summary: 'An RFC 7522 SAML assertion has expired (Conditions ' +
      'NotOnOrAfter).',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0072',
    summary: 'An RFC 7522 SAML assertion carries no AudienceRestriction ' +
      '(section 3 item 2).',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0073',
    summary: 'An RFC 7522 SAML assertion is addressed to an audience that is ' +
      'not this token endpoint.',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0074',
    summary: 'An RFC 7522 SAML assertion has no usable Subject NameID ' +
      '(section 3 item 3).',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0075',
    summary: 'An RFC 7522 SAML client assertion\'s Subject is not the ' +
      'client_id (section 3 item 3B).',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0076',
    summary: 'An RFC 7522 SAML assertion carries no bearer ' +
      'SubjectConfirmation (section 3 item 5).',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0077',
    summary: 'None of an RFC 7522 SAML assertion\'s bearer ' +
      'SubjectConfirmations is usable (expired, or no matching ' +
      'Recipient).',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0078',
    summary: 'An RFC 7522 SAML assertion has no expiry at all (section 3 ' +
      'item 4).',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0079',
    summary: 'An RFC 7522 SAML assertion\'s IssueInstant is in the future ' +
      'beyond the allowed clock skew.',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0080',
    summary: 'An RFC 7522 SAML assertion is valid for longer than ' +
      'oauth2.saml2BearerMaxLifetimeS allows.',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0081',
    summary: 'An RFC 7522 SAML assertion carries no ID, so it could not be ' +
      'spent.',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0082',
    summary: 'An RFC 7522 SAML assertion was replayed: its Issuer and ID ' +
      'are already in the used-assertion history, spent or held by a request ' +
      'in flight, under either section.',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0083',
    summary: 'The used-assertion history for the realm holds ' +
      'oauth2.assertionReplayCacheSize unexpired rows, so a new SAML ' +
      'assertion was refused rather than a live row forgotten.',
    spec: 'invalid_grant (HTTP 400) or invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0084',
    summary: 'The person-assertion register was handed an incomplete ' +
      'directory slot at startup and refused it whole, so no person ' +
      'can hold an RFC 7523 key pair in this process.',
    spec: '' },
  { code: 'STS-OAUTH-0085',
    summary: 'A person\'s RFC 7523 key pair could not be stored because this ' +
      'process has no directory.',
    spec: '' },
  { code: 'STS-OAUTH-0086',
    summary: 'A person\'s RFC 7523 private key could not be sealed under the ' +
      'key-encryption key; nothing was written and the issued key ' +
      'pair is lost.',
    spec: '' },
  { code: 'STS-OAUTH-0087',
    summary: 'An attribute of a person\'s RFC 7523 key pair could not be ' +
      'written to their directory entry; the issued key pair is lost.',
    spec: '' },
  { code: 'STS-OAUTH-0088',
    summary: 'A person\'s sealed RFC 7523 private key will not open under ' +
      'this process\'s key-encryption key (it was sealed under a ' +
      'different one).',
    spec: '' },
  { code: 'STS-OAUTH-0089',
    summary: 'Taking a person\'s RFC 7523 key pair off was refused: this ' +
      'process has no directory, or no person was named.',
    spec: '' },
  { code: 'STS-OAUTH-0090',
    summary: 'Taking a person\'s RFC 7523 key pair off was refused: nobody ' +
      'by that name holds one.',
    spec: '' },
  { code: 'STS-OAUTH-0091',
    summary: 'A certificate-bound token (cnf x5t#S256) was presented on a ' +
      'connection carrying no client certificate (RFC 8705 section ' +
      '3.1).',
    spec: 'invalid_token (HTTP 401 at a protected endpoint; HTTP 400 ' +
      'invalid_grant at the refresh grant)' },
  { code: 'STS-OAUTH-0092',
    summary: 'A certificate-bound token was presented on a connection made ' +
      'with a different client certificate (RFC 8705 section 3.1).',
    spec: 'invalid_token (HTTP 401 at a protected endpoint; HTTP 400 ' +
      'invalid_grant at the refresh grant)' },
  { code: 'STS-OAUTH-0093',
    summary: 'A DPoP proof was required and none was presented.',
    spec: 'invalid_dpop_proof (HTTP 400 at the token endpoint, HTTP 401 ' +
      'at a protected endpoint)' },
  { code: 'STS-OAUTH-0094',
    summary: 'More than one DPoP header field was sent (RFC 9449 permits ' +
      'exactly one).',
    spec: 'invalid_dpop_proof (HTTP 400 / 401)' },
  { code: 'STS-OAUTH-0095',
    summary: 'The DPoP proof is not a compact JWS with three parts.',
    spec: 'invalid_dpop_proof (HTTP 400 / 401)' },
  { code: 'STS-OAUTH-0096',
    summary: 'The DPoP proof could not be base64url-decoded.',
    spec: 'invalid_dpop_proof (HTTP 400 / 401)' },
  { code: 'STS-OAUTH-0097',
    summary: 'The DPoP proof\'s header or payload is not a JSON object.',
    spec: 'invalid_dpop_proof (HTTP 400 / 401)' },
  { code: 'STS-OAUTH-0098',
    summary: 'The DPoP proof\'s typ is not dpop+jwt.',
    spec: 'invalid_dpop_proof (HTTP 400 / 401)' },
  { code: 'STS-OAUTH-0099',
    summary: 'The DPoP proof is signed with an algorithm this server does ' +
      'not accept (none, a MAC, or unregistered).',
    spec: 'invalid_dpop_proof (HTTP 400 / 401)' },
  { code: 'STS-OAUTH-0100',
    summary: 'The DPoP proof header carries no jwk public key.',
    spec: 'invalid_dpop_proof (HTTP 400 / 401)' },
  { code: 'STS-OAUTH-0101',
    summary: 'The DPoP proof header\'s jwk carries private key material.',
    spec: 'invalid_dpop_proof (HTTP 400 / 401)' },
  { code: 'STS-OAUTH-0102',
    summary: 'The DPoP proof header\'s jwk key type or curve does not match ' +
      'its alg.',
    spec: 'invalid_dpop_proof (HTTP 400 / 401)' },
  { code: 'STS-OAUTH-0103',
    summary: 'The DPoP proof is missing one of jti, htm, htu or iat.',
    spec: 'invalid_dpop_proof (HTTP 400 / 401)' },
  { code: 'STS-OAUTH-0104',
    summary: 'The DPoP proof\'s signature does not verify with the key in ' +
      'its own header.',
    spec: 'invalid_dpop_proof (HTTP 400 / 401)' },
  { code: 'STS-OAUTH-0105',
    summary: 'The DPoP proof\'s htm does not match the request method.',
    spec: 'invalid_dpop_proof (HTTP 400 / 401)' },
  { code: 'STS-OAUTH-0106',
    summary: 'The DPoP proof\'s htu does not match the request URI (commonly ' +
      'a TLS-terminating proxy with global.trustProxy off).',
    spec: 'invalid_dpop_proof (HTTP 400 / 401)' },
  { code: 'STS-OAUTH-0107',
    summary: 'The DPoP proof\'s iat is outside the accepted clock window ' +
      '(oauth2.dpopIatSkewS).',
    spec: 'invalid_dpop_proof (HTTP 400 / 401)' },
  { code: 'STS-OAUTH-0108',
    summary: 'Nonce mode is on and the DPoP proof carried no nonce; the ' +
      'client is sent one to retry with.',
    spec: 'use_dpop_nonce (HTTP 400 at the token endpoint, HTTP 401 at a ' +
      'protected endpoint)' },
  { code: 'STS-OAUTH-0109',
    summary: 'The DPoP proof\'s nonce is not one this server issued, or it ' +
      'has expired.',
    spec: 'use_dpop_nonce (HTTP 400 / 401)' },
  { code: 'STS-OAUTH-0110',
    summary: 'The DPoP proof was replayed: its jti has already been used.',
    spec: 'invalid_dpop_proof (HTTP 400 / 401)' },
  { code: 'STS-OAUTH-0111',
    summary: 'A DPoP proof accompanying an access token carries no ath.',
    spec: 'invalid_dpop_proof (HTTP 401)' },
  { code: 'STS-OAUTH-0112',
    summary: 'A DPoP proof\'s ath does not match the access token presented ' +
      'with it.',
    spec: 'invalid_dpop_proof (HTTP 401)' },
  { code: 'STS-OAUTH-0113',
    summary: 'A DPoP-bound token was presented with a proof signed by a key ' +
      'other than the one in its cnf.jkt.',
    spec: 'invalid_dpop_proof (HTTP 401)' },
  { code: 'STS-OAUTH-0114',
    summary: 'An access token this service issued does not name this ' +
      'resource server as its audience — compared whole against the address ' +
      'the request arrived on since 2026-09-13 (RFC 9068 section 4, RFC 9700 ' +
      'section 2.3).',
    spec: 'invalid_token (HTTP 401)' },
  { code: 'STS-OAUTH-0115',
    summary: 'In RFC 9700 mode, an access token was sent in the URI query ' +
      'string (section 4.3.2).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0116',
    summary: 'A protected endpoint was called with no Bearer or DPoP access ' +
      'token.',
    spec: 'invalid_token (HTTP 401, WWW-Authenticate challenge)' },
  { code: 'STS-OAUTH-0117',
    summary: 'A DPoP-bound access token was presented with the Bearer ' +
      'scheme.',
    spec: 'invalid_token (HTTP 401)' },
  { code: 'STS-OAUTH-0118',
    summary: 'A DPoP proof was refused for a reason the verifier did not ' +
      'name (fallback; the verifier normally names one of ' +
      'STS-OAUTH-0093 to -0113).',
    spec: 'invalid_dpop_proof (HTTP 400 at the token endpoint, HTTP 401 ' +
      'at a protected endpoint)' },
  { code: 'STS-OAUTH-0119',
    summary: 'In RFC 9700 mode, the authorization request\'s redirect_uri ' +
      'does not parse as an absolute URI; nothing is redirected.',
    spec: 'invalid_request (HTTP 400, not redirected)' },
  { code: 'STS-OAUTH-0120',
    summary: 'In RFC 9700 mode, the redirect_uri uses http on a host that is ' +
      'not a loopback address (section 2.6).',
    spec: 'invalid_request (HTTP 400, not redirected)' },
  { code: 'STS-OAUTH-0121',
    summary: 'In RFC 9700 mode, no redirect URIs are registered for the ' +
      'client, so the redirect_uri cannot be exact-matched.',
    spec: 'invalid_request (HTTP 400, not redirected)' },
  { code: 'STS-OAUTH-0122',
    summary: 'In RFC 9700 mode, the redirect_uri matches none of the URIs ' +
      'registered for the client (section 2.1).',
    spec: 'invalid_request (HTTP 400, not redirected)' },
  { code: 'STS-OAUTH-0123',
    summary: 'In RFC 9700 mode, an RP-Initiated Logout ' +
      'post_logout_redirect_uri is not registered (no open ' +
      'redirector).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0124',
    summary: 'In RFC 9700 mode, a state, code_challenge or nonce value ' +
      'already used by another client was presented (section 2.1.1).',
    spec: 'invalid_request (redirected error)' },
  { code: 'STS-OAUTH-0125',
    summary: 'In RFC 9700 mode, a state, code_challenge or nonce value was ' +
      'reused after its authorization code was redeemed.',
    spec: 'invalid_request (redirected error)' },
  { code: 'STS-OAUTH-0126',
    summary: 'In RFC 9700 mode, the authorization request asked for a ' +
      'response type that issues an access token from the ' +
      'authorization endpoint (section 2.1.2).',
    spec: 'unsupported_response_type (redirected error)' },
  { code: 'STS-OAUTH-0127',
    summary: 'In RFC 9700 mode, a public client sent an authorization-code ' +
      'request with no PKCE code_challenge.',
    spec: 'invalid_request (redirected error)' },
  { code: 'STS-OAUTH-0128',
    summary: 'In RFC 9700 mode, the code_challenge_method is not S256.',
    spec: 'invalid_request (redirected error)' },
  { code: 'STS-OAUTH-0129',
    summary: 'In RFC 9700 mode, an S256 code_challenge is not 43 base64url ' +
      'characters.',
    spec: 'invalid_request (redirected error)' },
  { code: 'STS-OAUTH-0130',
    summary: 'In RFC 9700 mode, a response type naming id_token was ' +
      'requested with no nonce.',
    spec: 'invalid_request (redirected error)' },
  { code: 'STS-OAUTH-0131',
    summary: 'In RFC 9700 mode, the resource owner password credentials ' +
      'grant was requested (section 2.4).',
    spec: 'unsupported_grant_type (HTTP 400)' },
  { code: 'STS-OAUTH-0132',
    summary: 'In RFC 9700 mode, a dynamic client registration asked for the ' +
      'password grant.',
    spec: 'invalid_client_metadata (HTTP 400)' },
  { code: 'STS-OAUTH-0133',
    summary: 'In RFC 9700 mode, a dynamic client registration asked for the ' +
      'implicit grant.',
    spec: 'invalid_client_metadata (HTTP 400)' },
  { code: 'STS-OAUTH-0134',
    summary: 'In RFC 9700 mode, a dynamic client registration asked for a ' +
      'response type that issues an access token.',
    spec: 'invalid_client_metadata (HTTP 400)' },
  { code: 'STS-OAUTH-0135',
    summary: 'In RFC 9700 mode, a dynamic client registration carried a ' +
      'redirect URI that is not absolute.',
    spec: 'invalid_redirect_uri (HTTP 400)' },
  { code: 'STS-OAUTH-0136',
    summary: 'In RFC 9700 mode, a dynamic client registration carried an ' +
      'http redirect URI off the loopback address.',
    spec: 'invalid_redirect_uri (HTTP 400)' },
  { code: 'STS-OAUTH-0137',
    summary: 'A confidential client failed client authentication at the ' +
      'token endpoint and the verifier did not name a more specific ' +
      'cause (fallback; normally one of STS-OAUTH-0001 to -0083).',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0138',
    summary: 'In RFC 9700 mode, an already-redeemed refresh token was ' +
      'presented again; its whole family was revoked (section 2.2.2).',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0139',
    summary: 'In RFC 9700 mode, a refresh token\'s grant had been idle ' +
      'longer than oauth2.refreshIdleSeconds.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0140',
    summary: 'In RFC 9700 mode, a refresh request carried no client_id.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0141',
    summary: 'In RFC 9700 mode, a refresh token was presented by a client ' +
      'other than the one it was issued to.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0142',
    summary: 'In RFC 9700 mode, a refresh request asked for scope the ' +
      'original grant did not carry.',
    spec: 'invalid_scope (HTTP 400)' },
  { code: 'STS-OAUTH-0143',
    summary: 'In RFC 9700 mode, an authorization code was presented a second ' +
      'time; the tokens it bought were revoked (section 4.5).',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0144',
    summary: 'In RFC 9700 mode, an authorization request named no client_id; ' +
      'it is answered rather than redirected (section 4.11.2).',
    spec: 'invalid_request (HTTP 400, not redirected)' },
  { code: 'STS-OAUTH-0145',
    summary: 'In RFC 9700 mode, a code_verifier arrived for an authorization ' +
      'code issued without a code_challenge (PKCE downgrade, section ' +
      '4.8.2).',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0146',
    summary: 'In RFC 9700 mode, an authorization code was redeemed by a ' +
      'client other than the one it was issued to.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0147',
    summary: 'In RFC 9700 mode, the Token Request omitted the redirect_uri ' +
      'the authorization request carried.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0148',
    summary: 'The consent screen was reached with a malformed query or form ' +
      '(the input validator refused it).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0149',
    summary: 'The consent screen was reached with a consent id that is not ' +
      'pending: expired, already answered, or never issued.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0150',
    summary: 'A consent was answered from a browser with no sign-on session ' +
      'any more, so there is nobody to record it for.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0151',
    summary: 'A consent was answered from a browser signed in as somebody ' +
      'other than the person it was asked of.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0152',
    summary: 'The person declined consent on the consent screen; nothing was ' +
      'issued and the client is told access_denied.',
    spec: 'access_denied (HTTP 303 back to the authorization endpoint, ' +
      'then redirected to the client)' },
  { code: 'STS-OAUTH-0153',
    summary: 'The authorization_details parameter is not readable JSON, not ' +
      'an array, names an unsupported type, or names a credential ' +
      'configuration this issuer does not offer.',
    spec: 'invalid_authorization_details (redirected error, or HTTP 400 ' +
      'at the token endpoint)' },
  { code: 'STS-OAUTH-0154',
    summary: 'An RFC 8707 resource parameter is not an absolute URI or ' +
      'carries a fragment.',
    spec: 'invalid_target (redirected error, or HTTP 400 at the token ' +
      'endpoint)' },
  { code: 'STS-OAUTH-0155',
    summary: 'A scope named a delegated permission the client has not been ' +
      'granted, and oauth2.delegatedPermissionsEnforced is on.',
    spec: 'invalid_scope (redirected error, or HTTP 400 at the token ' +
      'endpoint)' },
  { code: 'STS-OAUTH-0156',
    summary: 'The issuance policy (the role gate) refused to issue an ' +
      'authorization code to this person for this application.',
    spec: 'access_denied (redirected error)' },
  { code: 'STS-OAUTH-0157',
    summary: 'The OpenID Connect Core 5.5 claims request on an authorization ' +
      'request is malformed.',
    spec: 'invalid_request (redirected error)' },
  { code: 'STS-OAUTH-0158',
    summary: 'RFC 9700 mode refused a request for a reason the policy did ' +
      'not name (fallback; the policy normally names one of ' +
      'STS-OAUTH-0119 to -0147).',
    spec: 'the error the RFC 9700 check named (HTTP 400 or redirected)' },
  { code: 'STS-OAUTH-0159',
    summary: 'The authorization request is malformed (the input validator ' +
      'refused it); answered here rather than redirected.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0160',
    summary: 'The authorization request has no redirect_uri, so the error ' +
      'cannot be redirected. (What is usable is the schema\'s question since ' +
      '2026-09-13; a value it refuses is STS-OAUTH-0159.)',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0161',
    summary: 'The authorization request named no client_id.',
    spec: 'invalid_request (redirected error, or HTTP 400 page before ' +
      'sign-in)' },
  { code: 'STS-OAUTH-0162',
    summary: 'The authorization request asked for a response_type this ' +
      'service does not implement.',
    spec: 'unsupported_response_type (redirected error, or HTTP 400 page)' },
  { code: 'STS-OAUTH-0163',
    summary: 'The authorization request asked for a response_type this ' +
      'authorization server profile does not advertise.',
    spec: 'unsupported_response_type (redirected error, or HTTP 400 page)' },
  { code: 'STS-OAUTH-0164',
    summary: 'The authorization request asked for a response_mode this ' +
      'authorization server profile does not advertise.',
    spec: 'invalid_request (redirected error, or HTTP 400 page)' },
  { code: 'STS-OAUTH-0165',
    summary: 'The authorization request asked for a code_challenge_method ' +
      'this authorization server profile does not advertise.',
    spec: 'invalid_request (redirected error, or HTTP 400 page)' },
  { code: 'STS-OAUTH-0166',
    summary: 'The sign-in screen reported that authentication did not ' +
      'complete, and the authorization endpoint relayed that to the ' +
      'client.',
    spec: 'the error the sign-in screen named, e.g. access_denied ' +
      '(redirected error)' },
  { code: 'STS-OAUTH-0167',
    summary: 'The consent screen reported a refusal, and the authorization ' +
      'endpoint relayed it to the client.',
    spec: 'the error the consent screen named, e.g. access_denied ' +
      '(redirected error)' },
  { code: 'STS-OAUTH-0168',
    summary: 'Consent is outstanding and the request carried prompt=none, ' +
      'which forbids showing the consent screen.',
    spec: 'consent_required (redirected error)' },
  { code: 'STS-OAUTH-0169',
    summary: 'The authorization response could not be issued because of an ' +
      'unexpected failure while minting it.',
    spec: 'server_error (redirected error, or HTTP 400 page)' },
  { code: 'STS-OAUTH-0170',
    summary: 'The request carried prompt=none and there is no sign-on ' +
      'session.',
    spec: 'login_required (redirected error, or HTTP 400 page)' },
  { code: 'STS-OAUTH-0171',
    summary: 'An RP-Initiated Logout request is malformed (the input ' +
      'validator refused it).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0172',
    summary: 'An access token presented at UserInfo did not verify: expired, ' +
      'not yet valid, or not issued by this service.',
    spec: 'invalid_token (HTTP 401, WWW-Authenticate challenge)' },
  { code: 'STS-OAUTH-0173',
    summary: 'The token presented at UserInfo is not an access token (its ' +
      'typ is not Bearer).',
    spec: 'invalid_token (HTTP 401, WWW-Authenticate challenge)' },
  { code: 'STS-OAUTH-0174',
    summary: 'The access token presented at UserInfo has been revoked.',
    spec: 'invalid_token (HTTP 401, WWW-Authenticate challenge)' },
  { code: 'STS-OAUTH-0175',
    summary: 'The access token presented at UserInfo was not issued with the ' +
      'openid scope.',
    spec: 'insufficient_scope (HTTP 403, WWW-Authenticate challenge)' },
  { code: 'STS-OAUTH-0176',
    summary: 'A claims request sent directly to UserInfo is malformed.',
    spec: 'invalid_request (HTTP 400, WWW-Authenticate challenge)' },
  { code: 'STS-OAUTH-0177',
    summary: 'The client\'s registered UserInfo signing or encryption could ' +
      'not be applied (unusable algorithm, or no usable recipient ' +
      'key).',
    spec: 'server_error (HTTP 500)' },
  { code: 'STS-OAUTH-0178',
    summary: 'POST /dpop/nonce-mode was refused because the realm is in ' +
      'product mode, where test controls are closed.',
    spec: 'access_denied (HTTP 403)' },
  { code: 'STS-OAUTH-0179',
    summary: 'POST /dpop/nonce-mode carried something other than ' +
      'required=true or required=false.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0180',
    summary: 'The DPoP nonce setting could not be written.',
    spec: 'server_error (HTTP 500)' },
  { code: 'STS-OAUTH-0181',
    summary: 'The directory threw while a person\'s profile claims were ' +
      'being read; the claims were omitted from what was issued.',
    spec: '' },
  { code: 'STS-OAUTH-0182',
    summary: 'A token this service had just issued could not be re-read for ' +
      'its jti, so the delegation register records no identifier for ' +
      'it.',
    spec: '' },
  { code: 'STS-OAUTH-0183',
    summary: 'The RFC 8414 signed_metadata document could not be signed; the ' +
      'metadata was published without it.',
    spec: '' },
  { code: 'STS-OAUTH-0184',
    summary: 'The JWKS could not be published (a signing key could not be ' +
      'made or exported).',
    spec: 'HTTP 500' },
  { code: 'STS-OAUTH-0185',
    summary: 'An Authorization: Basic header on a Token Request could not be ' +
      'decoded; the form parameters are read instead.',
    spec: '' },
  { code: 'STS-OAUTH-0186',
    summary: 'A path naming an authorization server profile is malformed.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0187',
    summary: 'A Token Request presented an authorization code this service ' +
      'holds no record of: never issued, issued before a restart, or ' +
      'issued by another authorization server.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0188',
    summary: 'An already-redeemed authorization code was presented again in ' +
      'a request that differs from the one it was redeemed with.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0189',
    summary: 'An already-redeemed authorization code was presented again ' +
      'after its own lifetime had run out.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0190',
    summary: 'The jti of a token issued for an authorization code could not ' +
      'be read, so it could not be revoked on a replay.',
    spec: '' },
  { code: 'STS-OAUTH-0191',
    summary: 'The issuance policy (the role gate) refused a token the token ' +
      'endpoint was about to issue.',
    spec: 'access_denied (HTTP 400)' },
  { code: 'STS-OAUTH-0192',
    summary: 'In product mode, a Token Request came from a client that did ' +
      'not authenticate, and no more specific cause was named ' +
      '(fallback).',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0193',
    summary: 'In product mode, a Token Request named a client this service ' +
      'has no entry for, so it could not authenticate.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0194',
    summary: 'In product mode, a Token Request came from a public client ' +
      '(token_endpoint_auth_method none); product mode has no public ' +
      'clients.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0195',
    summary: 'In product mode, a confidential client has nothing on its ' +
      'entry to authenticate it against.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0196',
    summary: 'A Token Request is malformed (the input validator refused it).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0197',
    summary: 'A Token Request asked for a grant type this authorization ' +
      'server profile does not advertise.',
    spec: 'unsupported_grant_type (HTTP 400)' },
  { code: 'STS-OAUTH-0198',
    summary: 'A client is configured for a token endpoint authentication ' +
      'method this authorization server profile does not advertise.',
    spec: 'invalid_client (HTTP 400)' },
  { code: 'STS-OAUTH-0199',
    summary: 'A Token Request presented an authorization code that has ' +
      'expired.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0200',
    summary: 'An authorization code was redeemed at a different ' +
      'authorization server profile from the one that issued it.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0201',
    summary: 'A Token Request\'s redirect_uri does not match the one on the ' +
      'authorization request.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0202',
    summary: 'An authorization code issued with PKCE was redeemed without a ' +
      'code_verifier.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0203',
    summary: 'A code_verifier does not match the authorization code\'s ' +
      'code_challenge.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0204',
    summary: 'An authorization code bound to a DPoP key (dpop_jkt) was ' +
      'redeemed without a DPoP proof.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0205',
    summary: 'An authorization code bound to a DPoP key was redeemed with a ' +
      'proof from a different key.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0206',
    summary: 'A Token Request asked for an RFC 8707 resource the ' +
      'authorization code does not carry.',
    spec: 'invalid_target (HTTP 400)' },
  { code: 'STS-OAUTH-0207',
    summary: 'An OpenID4VCI pre-authorized code is unknown or already used.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0208',
    summary: 'An OpenID4VCI pre-authorized code has expired.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0209',
    summary: 'An OpenID4VCI pre-authorized code requires a Transaction Code ' +
      'and none was sent.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0210',
    summary: 'An OpenID4VCI Transaction Code was wrong on the last allowed ' +
      'attempt, so the pre-authorized code was spent.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0211',
    summary: 'An OpenID4VCI Transaction Code was wrong.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0212',
    summary: 'A pre-authorized code Token Request\'s authorization_details ' +
      'names a credential configuration the offer did not.',
    spec: 'invalid_authorization_details (HTTP 400)' },
  { code: 'STS-OAUTH-0213',
    summary: 'A refresh token did not verify (bad signature, expired, or not ' +
      'issued here).',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0214',
    summary: 'A refresh token has been revoked.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0215',
    summary: 'A DPoP-bound refresh token was presented without a DPoP proof.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0216',
    summary: 'A DPoP-bound refresh token was presented with a proof from a ' +
      'different key.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0217',
    summary: 'A refresh request asked for an RFC 8707 resource the original ' +
      'grant does not carry.',
    spec: 'invalid_target (HTTP 400)' },
  { code: 'STS-OAUTH-0218',
    summary: 'A password grant request is missing its username or password.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0219',
    summary: 'A password grant was rate limited: too many attempts for the ' +
      'account or the address.',
    spec: 'invalid_grant (HTTP 400, Retry-After)' },
  { code: 'STS-OAUTH-0220',
    summary: 'A password grant\'s credentials did not verify.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0221',
    summary: 'A password grant was refused because the person holds a second ' +
      'factor, which the grant cannot carry.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0222',
    summary: 'An RFC 7523 JWT bearer grant was refused for a reason the ' +
      'verifier did not name (fallback; normally one of ' +
      'STS-OAUTH-0026 to -0055).',
    spec: 'the error the verifier named (HTTP 400)' },
  { code: 'STS-OAUTH-0223',
    summary: 'An RFC 7522 SAML 2.0 bearer grant was refused for a reason the ' +
      'verifier did not name (fallback; normally one of ' +
      'STS-OAUTH-0056 to -0083).',
    spec: 'the error the verifier named (HTTP 400)' },
  { code: 'STS-OAUTH-0224',
    summary: 'An RFC 8693 token exchange request carried no subject_token.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0225',
    summary: 'An RFC 8693 subject_token could not be read at all; the ' +
      'exchange continues with an empty subject.',
    spec: '' },
  { code: 'STS-OAUTH-0226',
    summary: 'An RFC 8693 actor_token could not be read; the exchange ' +
      'continues without an actor.',
    spec: '' },
  { code: 'STS-OAUTH-0227',
    summary: 'A Token Request named a grant_type this service does not ' +
      'implement.',
    spec: 'unsupported_grant_type (HTTP 400)' },
  { code: 'STS-OAUTH-0228',
    summary: 'The token endpoint failed with an unexpected exception.',
    spec: 'server_error (HTTP 500)' },
  { code: 'STS-OAUTH-0229',
    summary: 'An RFC 7662 introspection request is malformed (the input ' +
      'validator refused it).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0230',
    summary: 'An RFC 7009 revocation request is malformed (the input ' +
      'validator refused it).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0231',
    summary: 'Dynamic client registration was refused: the realm is in ' +
      'product mode and oauth2.openRegistration is off.',
    spec: 'access_denied (HTTP 403)' },
  { code: 'STS-OAUTH-0232',
    summary: 'A dynamic client registration document was refused by the ' +
      'input validator.',
    spec: 'invalid_client_metadata (HTTP 400)' },
  { code: 'STS-OAUTH-0233',
    summary: 'A dynamic client registration\'s redirect_uris is not an array.',
    spec: 'invalid_redirect_uri (HTTP 400)' },
  { code: 'STS-OAUTH-0234',
    summary: 'A client configuration endpoint path names a malformed ' +
      'client_id.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0235',
    summary: 'The client configuration endpoint was asked about a client ' +
      'that was never dynamically registered.',
    spec: 'invalid_client (HTTP 404)' },
  { code: 'STS-OAUTH-0236',
    summary: 'The registration access token presented at the client ' +
      'configuration endpoint does not match.',
    spec: 'invalid_token (HTTP 401, WWW-Authenticate challenge)' },
  { code: 'STS-OAUTH-0237',
    summary: 'A refresh token was presented unencrypted. Every refresh token ' +
      'this service issues is a signed JWT encrypted to its realm, so a ' +
      'plain signed one is refused (or reported inactive at introspection).',
    spec: 'invalid_grant (HTTP 400); active: false at introspection' },
  { code: 'STS-OAUTH-0238',
    summary: 'A refresh token could not be decrypted: it is not a compact ' +
      'JWE, names a key this realm does not hold (another realm, or keys ' +
      'since rotated), or its authentication tag did not verify.',
    spec: 'invalid_grant (HTTP 400); active: false at introspection' },
  { code: 'STS-OAUTH-0239',
    summary: 'A refresh token decrypted to something that is not a signed ' +
      'JWT (its JWE did not carry cty JWT around a JWS).',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0240',
    summary: 'A refresh token could not be encrypted at issuance, or the ' +
      'realm\'s refresh-token encryption keys could not be read; no refresh ' +
      'token was issued.',
    spec: 'server_error (HTTP 500)' },
  { code: 'STS-OAUTH-0241',
    summary: 'oauth2.refreshTokenEncryptionAlg or …Enc names an algorithm ' +
      'common/crypto.js does not implement; refresh tokens were encrypted ' +
      'with the default instead.',
    spec: '' },
  { code: 'STS-OAUTH-0242',
    summary: 'An RFC 7522 SAML 2.0 bearer grant was signed by a PERSON\'s ' +
      'registered RFC 7522 key pair and its <Subject> names somebody other ' +
      'than that person; a person\'s key may only assert about themselves.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0243',
    summary: 'An RFC 7523 or RFC 7522 assertion verified and the ' +
      'used-assertion history could not be consulted or written, so it was ' +
      'refused: an assertion this service cannot prove unused is not one it ' +
      'accepts.',
    spec: 'invalid_client (HTTP 401) or invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0244',
    summary: 'RFC 9068 section 3: the scope named more than one resource (two ' +
      'applications, or delegated permissions of two APIs), so a JWT access ' +
      'token would carry scopes whose resource is ambiguous; no token or ' +
      'code was issued.',
    spec: 'invalid_scope (redirected error, or HTTP 400 at the token ' +
      'endpoint)' },
  { code: 'STS-OAUTH-0245',
    summary: 'RFC 9068 section 2.2.3: the request addressed one set of ' +
      'resources (resource, audience, or what a refresh token remembers) ' +
      'while its scope named a different application or API.',
    spec: 'invalid_scope (redirected error, or HTTP 400 at the token ' +
      'endpoint)' },
  { code: 'STS-OAUTH-0246',
    summary: 'RFC 9068 section 3: the request addressed several resources and ' +
      'carried a scope that cannot be tied to exactly one of them (neither a ' +
      'delegated permission of one, nor an OpenID Connect scope with this ' +
      'service among them).',
    spec: 'invalid_target (redirected error, or HTTP 400 at the token ' +
      'endpoint)' },
  { code: 'STS-OAUTH-0247',
    summary: 'RFC 9068 section 4: a token this service signed was presented ' +
      'to one of its resource servers (UserInfo, the OID4VCI credential ' +
      'endpoints, SCIM, SSF) with a typ header that is not at+jwt — an ID ' +
      'Token, another JWT, or an access token minted before at+jwt.',
    spec: 'invalid_token (HTTP 401), or the surface\'s own 401' },
  { code: 'STS-OAUTH-0248',
    summary: 'RFC 9068 section 4: a token this service signed names an iss ' +
      'that is not an issuer this service publishes at the address the ' +
      'request arrived on (the default authorization server or a named one).',
    spec: 'invalid_token (HTTP 401), or the surface\'s own 401' },
  // ----- OAuth 2.1 mode, private-use redirects, the secret limit (2026-09-13)
  // Reserved block STS-OAUTH-0270..0299 — see oauth-oidc/oauth21.js.
  { code: 'STS-OAUTH-0270',
    summary: 'An authorization request asked for response_mode=form_post at ' +
      'a native application\'s private-use redirect URI, which a protocol ' +
      'handler can never receive a POST body at, so it was answered here ' +
      'rather than redirected (every mode).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0271',
    summary: 'OAuth 2.1 mode: the authorization request names a client with ' +
      'no redirect URI of its own (section 2.3.1); oauth2.redirectUris is ' +
      'not read in that mode.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0272',
    summary: 'OAuth 2.1 mode: the client\'s only redirect URIs are addresses ' +
      'development observed and nobody confirmed, which product mode ' +
      'withholds.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0273',
    summary: 'OAuth 2.1 mode: the authorization request named no ' +
      'redirect_uri and the client has registered more than one, so the ' +
      'parameter is required (section 4.1.1).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0274',
    summary: 'OAuth 2.1 mode: the authorization request named no ' +
      'redirect_uri and the one URI registered for the client is not a ' +
      'usable redirect URI (it was put on the entry without passing any ' +
      'check).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0275',
    summary: 'OAuth 2.1 mode: an authorization request issuing a code ' +
      'carried no code_challenge and does not meet the OpenID Connect nonce ' +
      'exemption (a confidential client with a credential on file, openid, a ' +
      'nonce) — section 7.5.1.1.',
    spec: 'invalid_request (HTTP 400, redirected once the redirect_uri is ' +
      'validated)' },
  { code: 'STS-OAUTH-0276',
    summary: 'OAuth 2.1 mode: code_challenge was sent with no ' +
      'code_challenge_method, which that specification makes REQUIRED.',
    spec: 'invalid_request (HTTP 400, redirected)' },
  { code: 'STS-OAUTH-0277',
    summary: 'OAuth 2.1 mode: an authorization code with no code_challenge ' +
      'was presented — either not issued under the nonce exemption, or ' +
      'issued under it and redeemed without client authentication (section ' +
      '4.1.3).',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0278',
    summary: 'OAuth 2.1 mode: a token request names a client whose entry ' +
      'declares nothing — never registered, or only ever sighted.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0279',
    summary: 'OAuth 2.1 mode: the client credentials grant was asked for by ' +
      'a client that did not authenticate (section 4.2).',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0280',
    summary: 'OAuth 2.1 mode: the token request included client ' +
      'authentication that did not verify against anything on file — a ' +
      'public or unknown client sending a secret, or a credential that ' +
      'failed (section 3.2.2).',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0281',
    summary: 'OAuth 2.1 mode: a token or introspection request carried more ' +
      'than one client authentication method (section 2.4).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0282',
    summary: 'OAuth 2.1 mode: SAML bearer client authentication, which ' +
      'draft-ietf-oauth-rfc7523bis-11 says must not be used for client ' +
      'authentication.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0283',
    summary: 'OAuth 2.1 mode: a JWT client assertion does not name the ' +
      'issuer identifier as its sole audience ' +
      '(draft-ietf-oauth-rfc7523bis-11).',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0284',
    summary: 'Too many failed client-secret authentications for one client ' +
      'from one address in this realm, so the token request was refused ' +
      'before the secret was checked (wherever secrets are checked).',
    spec: 'invalid_client (HTTP 429, Retry-After)' },
  { code: 'STS-OAUTH-0285',
    summary: 'OAuth 2.1 mode: a request parameter was repeated at the ' +
      'authorization or token endpoint (sections 3.1 and 3.2).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0286',
    summary: 'OAuth 2.1 mode: a post_logout_redirect_uri was given for a ' +
      'client that registered none of its own; oauth2.redirectUris is not ' +
      'read in that mode.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0287',
    summary: 'OAuth 2.1 mode: a client registration asked for ' +
      'token_endpoint_auth_method=saml2_bearer.',
    spec: 'invalid_client_metadata (HTTP 400)' },
  { code: 'STS-OAUTH-0288',
    summary: 'A stored frontchannel_logout_uri is not an http or https URL, ' +
      'so the client was not notified and the value was not framed.',
    spec: 'none — the client is listed as not notified' },
  { code: 'STS-OAUTH-0289',
    summary: 'OAuth 2.1 mode: a client registration asked for the client ' +
      'credentials grant with token_endpoint_auth_method=none.',
    spec: 'invalid_client_metadata (HTTP 400)' },
  { code: 'STS-OAUTH-0290',
    summary: 'RFC 9700 or OAuth 2.1 mode: a private-use ' +
      'post_logout_redirect_uri was given and the client the request names ' +
      'has not registered it.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0291',
    summary: 'An RFC 9701 JWT introspection request (Accept: ' +
      'application/token-introspection+jwt) did not authenticate the ' +
      'resource server: no credential, an unknown or public client, nothing ' +
      'on file to verify, or a credential that did not verify. Refused in ' +
      'every mode, because the response is addressed to the caller.',
    spec: 'invalid_client (HTTP 400, RFC 9701 section 5)' },
  { code: 'STS-OAUTH-0292',
    summary: 'Product mode: an RFC 7662 introspection request did not ' +
      'authenticate the caller as a client with a credential that verified.',
    spec: 'invalid_client (HTTP 401, RFC 7662 section 2.3)' },
  { code: 'STS-OAUTH-0293',
    summary: 'The JWT introspection response a client registered could not ' +
      'be produced: an algorithm this service does not have (set by ' +
      'ldapmodify), an enc with no alg, no usable key in its jwks, or the ' +
      'signature failed.',
    spec: 'server_error (HTTP 500)' },
  { code: 'STS-OAUTH-0294',
    summary: 'The introspection endpoint failed with an unexpected error ' +
      'outside every refusal it makes.',
    spec: 'server_error (HTTP 500)' },
  { code: 'STS-OAUTH-0295',
    summary: 'A client authenticating at the introspection endpoint declares ' +
      'a token_endpoint_auth_method the selected authorization server does ' +
      'not list in introspection_endpoint_auth_methods_supported.',
    spec: 'invalid_client (HTTP 400 for a JWT request, 401 for JSON)' },
  { code: 'STS-OAUTH-0296',
    summary: 'A resource server\'s registered (or default) RFC 9701 ' +
      'introspection response algorithm is not one the selected ' +
      'authorization server advertises in its introspection_*_values_' +
      'supported members.',
    spec: 'invalid_client (HTTP 400)' },
  // SOFTWARE STATEMENTS (RFC 7591 section 2.3), 2026-09-13. After the OAuth 2.1
  // block reserved at 0270..0299.
  { code: 'STS-OAUTH-0300',
    summary: 'A software statement (RFC 7591 section 2.3) presented at ' +
      'registration is not a string holding a compact JWS — it is missing ' +
      'its three segments, or it is a JWE.',
    spec: 'invalid_software_statement (HTTP 400)' },
  { code: 'STS-OAUTH-0301',
    summary: 'A software statement\'s JOSE header or claims are not JSON ' +
      'objects.',
    spec: 'invalid_software_statement (HTTP 400)' },
  { code: 'STS-OAUTH-0302',
    summary: 'A software statement says alg "none" (RFC 7591 section 2.3 ' +
      'requires it to be signed or MACed).',
    spec: 'invalid_software_statement (HTTP 400)' },
  { code: 'STS-OAUTH-0303',
    summary: 'A software statement is signed with an algorithm this service ' +
      'does not verify statements with — an HMAC, for which no shared key ' +
      'exists, or an unknown one.',
    spec: 'invalid_software_statement (HTTP 400)' },
  { code: 'STS-OAUTH-0304',
    summary: 'A software statement carries no `iss` claim (RFC 7591 section ' +
      '2.3).',
    spec: 'invalid_software_statement (HTTP 400)' },
  { code: 'STS-OAUTH-0305',
    summary: 'A software statement names an issuer this authorization server ' +
      'publishes and is not typed software-statement+jwt, so it is one of ' +
      'this service\'s other tokens.',
    spec: 'invalid_software_statement (HTTP 400)' },
  { code: 'STS-OAUTH-0306',
    summary: 'A software statement from a declared publisher carries an x5c ' +
      'certificate that chains to this realm and was issued to somebody ' +
      'other than that publisher.',
    spec: 'unapproved_software_statement (HTTP 400)' },
  { code: 'STS-OAUTH-0307',
    summary: 'A software statement\'s issuer is declared by an application ' +
      'that holds no key a statement can be verified with (no usable jwks, ' +
      'no key pair from /admin/pki).',
    spec: 'unapproved_software_statement (HTTP 400)' },
  { code: 'STS-OAUTH-0308',
    summary: 'A software statement\'s issuer is not declared in any ' +
      'application\'s oauthSoftwareStatementIssuer, and ' +
      'oauth2.softwareStatementRequireTrustedIssuer is on.',
    spec: 'unapproved_software_statement (HTTP 400)' },
  { code: 'STS-OAUTH-0309',
    summary: 'A software statement\'s signature did not verify under any of ' +
      'its issuer\'s keys, or it has expired or is not yet valid.',
    spec: 'invalid_software_statement (HTTP 400)' },
  { code: 'STS-OAUTH-0310',
    summary: 'The registered certificate of the key that verified a software ' +
      'statement has a trust chain that does not hold.',
    spec: 'invalid_software_statement (HTTP 400)' },
  { code: 'STS-OAUTH-0311',
    summary: 'A software statement\'s `iat` is in the future beyond ' +
      'oauth2.clientAssertionSkewS.',
    spec: 'invalid_software_statement (HTTP 400)' },
  { code: 'STS-OAUTH-0312',
    summary: 'A software statement carries an `aud` that names neither this ' +
      'authorization server\'s issuer nor its registration endpoint.',
    spec: 'invalid_software_statement (HTTP 400)' },
  { code: 'STS-OAUTH-0313',
    summary: 'A verified software statement\'s claims were refused by the ' +
      'input validator.',
    spec: 'invalid_software_statement (HTTP 400)' },
  { code: 'STS-OAUTH-0314',
    summary: 'A registration carried no software statement while ' +
      'oauth2.softwareStatementRequired is on.',
    spec: 'invalid_software_statement (HTTP 400)' },
  { code: 'STS-OAUTH-0315',
    summary: 'An RFC 7592 update of a client that registered on the strength ' +
      'of a trusted software statement, at an endpoint otherwise closed, did ' +
      'not carry a trusted statement from the same issuer.',
    spec: 'unapproved_software_statement (HTTP 400)' },
  { code: 'STS-OAUTH-0340',
    summary: 'An authorization request carried no request object where a ' +
      'signed one is required (oauth2.requireSignedRequestObject, ' +
      'the client\'s require_signed_request_object, or the ' +
      'authorization server\'s profile; RFC 9101 section 10.5).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0341',
    summary: 'An authorization request carried both request and ' +
      'request_uri, or repeated one of them (RFC 9101 section 5).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0342',
    summary: 'A request object was sent by value to an authorization ' +
      'server whose metadata says request_parameter_supported ' +
      'false.',
    spec: 'request_not_supported (HTTP 400)' },
  { code: 'STS-OAUTH-0343',
    summary: 'A request object was sent by reference to an authorization ' +
      'server whose metadata says request_uri_parameter_supported ' +
      'false.',
    spec: 'request_uri_not_supported (HTTP 400)' },
  { code: 'STS-OAUTH-0344',
    summary: 'An authorization request carried a request object and no ' +
      'client_id query parameter (RFC 9101 section 5).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0345',
    summary: 'A request_uri is not one the client registered in ' +
      'request_uris, so it was refused and never fetched (RFC 9101 ' +
      'section 10.4).',
    spec: 'invalid_request_uri (HTTP 400)' },
  { code: 'STS-OAUTH-0346',
    summary: 'A registered request_uri may not be fetched in this mode: ' +
      'plain http in product mode, or otherwise unusable.',
    spec: 'invalid_request_uri (HTTP 400)' },
  { code: 'STS-OAUTH-0347',
    summary: 'A registered request_uri could not be fetched: a non-200 ' +
      'answer (a redirect included, which is not followed), a ' +
      'timeout, a network error, or more than ' +
      'oauth2.requestUriMaxBytes.',
    spec: 'invalid_request_uri (HTTP 400)' },
  { code: 'STS-OAUTH-0348',
    summary: 'A registered request_uri answered with a media type other ' +
      'than application/oauth-authz-req+jwt or application/jwt, in ' +
      'product mode.',
    spec: 'invalid_request_uri (HTTP 400)' },
  { code: 'STS-OAUTH-0349',
    summary: 'A request_uri\'s fragment is a SHA-256 of different content ' +
      'from what it answered with (OpenID Connect Core section ' +
      '6.2).',
    spec: 'invalid_request_uri (HTTP 400)' },
  { code: 'STS-OAUTH-0350',
    summary: 'A request object\'s encryption is not what the client ' +
      'registered: unencrypted where request_object_encryption_alg ' +
      'is registered, or a different alg or enc.',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0351',
    summary: 'A request object is encrypted with an algorithm or content ' +
      'encryption the selected authorization server does not ' +
      'decrypt.',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0352',
    summary: 'An encrypted request object has no key here to open it: a ' +
      'symmetric algorithm for a client with no secret, or a kid ' +
      'that is not this realm\'s request object encryption key.',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0353',
    summary: 'An encrypted request object could not be decrypted, or its ' +
      'JWE header is unreadable.',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0354',
    summary: 'An encrypted request object decrypted to something that is ' +
      'not a JWS (RFC 9101 section 4: signed, then encrypted).',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0355',
    summary: 'A request object is not a compact JWT, or its header is ' +
      'unreadable.',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0356',
    summary: 'A request object is typed as another kind of JWT (RFC 9101 ' +
      'section 10.8).',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0357',
    summary: 'An unsigned request object (alg none) was refused: product ' +
      'mode, or a signed request object is required.',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0358',
    summary: 'A request object is signed with an algorithm other than the ' +
      'client\'s registered request_object_signing_alg.',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0359',
    summary: 'A request object is signed with an algorithm the selected ' +
      'authorization server does not list in ' +
      'request_object_signing_alg_values_supported.',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0360',
    summary: 'A request object names a signing algorithm this service does ' +
      'not verify.',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0361',
    summary: 'A request object cannot be verified: the client holds no key ' +
      'for it (no jwks, only a jwks_uri, or no client secret for ' +
      'HMAC).',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0362',
    summary: 'A request object\'s signature did not verify with any of the ' +
      'client\'s keys, or it is expired or not yet valid.',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0363',
    summary: 'The certificate of the key that verified a request object ' +
      'does not have a valid trust chain.',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0364',
    summary: 'An unsigned request object\'s claims are refused: not a JSON ' +
      'object, expired or not yet valid.',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0365',
    summary: 'A request object\'s iss is not the client that sent it.',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0366',
    summary: 'A request object\'s aud does not name this authorization ' +
      'server (its issuer or its authorization endpoint).',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0367',
    summary: 'A request object\'s client_id claim differs from the ' +
      'client_id query parameter (RFC 9101 section 6.3).',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0368',
    summary: 'A request object is not explicitly typed oauth-authz-req+jwt ' +
      'and oauth2.requireRequestObjectType requires it.',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0369',
    summary: 'A request object lacks iss or aud and ' +
      'oauth2.requireRequestObjectIssuerAudience requires both.',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0370',
    summary: 'A request object\'s kid names none of the client\'s keys (RFC ' +
      '9101 section 6.2).',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0371',
    summary: 'A response_type duplicated in the query differs from the ' +
      'request object\'s (OpenID Connect Core section 6.1).',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0372',
    summary: 'A request_uri is a pushed authorization request URN and ' +
      'there is no pushed authorization request here to resolve it, ' +
      'or it resolved to nothing.',
    spec: 'request_uri_not_supported or invalid_request_uri (HTTP 400)' },
  { code: 'STS-OAUTH-0373',
    summary: 'The authorization endpoint failed with an unexpected error ' +
      'while resolving a request object.',
    spec: 'server_error (HTTP 500)' },
  // PUSHED AUTHORIZATION REQUESTS (RFC 9126), 2026-09-13. Block 0400..0449;
  // oauth-oidc/par.js and the PAR endpoint in oauth-oidc/oauth2.js.
  { code: 'STS-OAUTH-0400',
    summary: 'A pushed authorization request arrived while ' +
      'oauth2.pushedAuthorizationRequests is off.',
    spec: 'invalid_request (HTTP 404)' },
  { code: 'STS-OAUTH-0401',
    summary: 'The pushed authorization request endpoint was called with a ' +
      'method other than POST.',
    spec: 'HTTP 405 with Allow: POST (RFC 9126 section 2.3)' },
  { code: 'STS-OAUTH-0402',
    summary: 'A pushed authorization request was larger than ' +
      'oauth2.parMaxBodyBytes.',
    spec: 'HTTP 413 (RFC 9126 section 2.3)' },
  { code: 'STS-OAUTH-0403',
    summary: 'A pushed authorization request was not a form body, was ' +
      'malformed, or repeated a parameter that may not repeat.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0404',
    summary: 'A pushed authorization request carried request_uri, which ' +
      'RFC 9126 section 2.1 says MUST NOT be provided.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0405',
    summary: 'A pushed authorization request named no client — no ' +
      'client_id, no Basic header and no client assertion.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0406',
    summary: 'A pushed authorization request named one client_id in its ' +
      'body and authenticated as another.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0407',
    summary: 'A client pushed more authorization requests from one address ' +
      'in one window than oauth2.parRequestsPerMinute allows.',
    spec: 'HTTP 429 with Retry-After (RFC 9126 section 2.3)' },
  { code: 'STS-OAUTH-0408',
    summary: 'A push was refused because the realm already holds ' +
      'oauth2.parMaxRequests live pushed requests.',
    spec: 'temporarily_unavailable (HTTP 503)' },
  { code: 'STS-OAUTH-0409',
    summary: 'A push carrying a request object also carried authorization ' +
      'request parameters in the form body (RFC 9126 section 3).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0410',
    summary: 'A request_uri at the authorization endpoint is not one this ' +
      'authorization server issued at /oauth2/par, or it was swept.',
    spec: 'invalid_request_uri (HTTP 400 on this server)' },
  { code: 'STS-OAUTH-0411',
    summary: 'A pushed request_uri was used after it expired ' +
      '(oauth2.parRequestUriLifetimeS).',
    spec: 'invalid_request_uri (HTTP 400 on this server)' },
  { code: 'STS-OAUTH-0412',
    summary: 'A pushed request_uri was used again after an authorization ' +
      'response had been issued on it.',
    spec: 'invalid_request_uri (HTTP 400 on this server)' },
  { code: 'STS-OAUTH-0413',
    summary: 'A pushed request_uri was used with a client_id other than the ' +
      'client that pushed it.',
    spec: 'invalid_request_uri (HTTP 400 on this server)' },
  { code: 'STS-OAUTH-0414',
    summary: 'A pushed request_uri was used at a different authorization ' +
      'server from the one it was pushed at.',
    spec: 'invalid_request_uri (HTTP 400 on this server)' },
  { code: 'STS-OAUTH-0415',
    summary: 'A push carried plain parameters where a signed request object ' +
      'is required (RFC 9126 section 2.3, RFC 9101 section 10.5).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0416',
    summary: 'The DPoP proof sent with a pushed authorization request was ' +
      'refused, or a nonce was required.',
    spec: 'invalid_dpop_proof or use_dpop_nonce (HTTP 400)' },
  { code: 'STS-OAUTH-0417',
    summary: 'A push carried a DPoP proof and a dpop_jkt naming a different ' +
      'key (RFC 9449 section 10.1).',
    spec: 'invalid_dpop_proof (HTTP 400)' },
  { code: 'STS-OAUTH-0419',
    summary: 'An authorization request was not pushed, and the setting, the ' +
      'client or the authorization server requires pushed authorization ' +
      'requests (RFC 9126 section 4).',
    spec: 'invalid_request (HTTP 400 on this server)' },
  { code: 'STS-OAUTH-0420',
    summary: 'The pushed authorization request endpoint failed with an ' +
      'unexpected error.',
    spec: 'server_error (HTTP 500)' },
  { code: 'STS-OAUTH-0421',
    summary: 'A client pushed an authorization request while configured for ' +
      'an authentication method the selected authorization server does not ' +
      'list in token_endpoint_auth_methods_supported.',
    spec: 'invalid_client (HTTP 400)' },
  { code: 'STS-OAUTH-0422',
    summary: 'RFC 9700 mode refused a client\'s authentication at the pushed ' +
      'authorization request endpoint and named no more specific code.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0423',
    summary: 'Product mode refused an unauthenticated client at the pushed ' +
      'authorization request endpoint.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0424',
    summary: 'An authenticated client pushed a request object that carries ' +
      'no client_id claim (RFC 9126 section 3).',
    spec: 'invalid_request_object (HTTP 400)' },
  { code: 'STS-OAUTH-0426',
    summary: 'A request_uri pushed as plain parameters was used after a ' +
      'signed request object became required (RFC 9126 section 7.4).',
    spec: 'invalid_request (HTTP 400 on this server)' },
  { code: 'STS-OAUTH-0427',
    summary: 'An OAuth monitoring counter (/admin/oauth2/monitor) threw or ' +
      'was asked for an event outside its vocabulary; nothing else was ' +
      'affected.',
    spec: 'none — logged only' },
  // RICH AUTHORIZATION REQUESTS (RFC 9396)
  { code: 'STS-OAUTH-0450',
    summary: 'authorization_details is not readable JSON, not an array, or ' +
      'carries more entries than oauth2.authorizationDetailsMaxEntries.',
    spec: 'invalid_authorization_details (HTTP 400, or redirected)' },
  { code: 'STS-OAUTH-0451',
    summary: 'An authorization_details entry is not a JSON object, or has ' +
      'no string type (RFC 9396 section 2).',
    spec: 'invalid_authorization_details (HTTP 400, or redirected)' },
  { code: 'STS-OAUTH-0452',
    summary: 'An authorization_details entry\'s common data field ' +
      '(locations, actions, datatypes, identifier, privileges) has the ' +
      'wrong shape (RFC 9396 section 2.2).',
    spec: 'invalid_authorization_details (HTTP 400, or redirected)' },
  { code: 'STS-OAUTH-0453',
    summary: 'An authorization_details entry is of a type no application in ' +
      'the realm declares and this service does not understand (RFC 9396 ' +
      'section 5).',
    spec: 'invalid_authorization_details (HTTP 400, or redirected)' },
  { code: 'STS-OAUTH-0454',
    summary: 'An authorization_details entry is of a type outside the ' +
      'client\'s registered authorization_details_types (RFC 9396 section ' +
      '10).',
    spec: 'invalid_authorization_details (HTTP 400, or redirected)' },
  { code: 'STS-OAUTH-0455',
    summary: 'An authorization_details entry is of a type the named ' +
      'authorization server does not publish in ' +
      'authorization_details_types_supported.',
    spec: 'invalid_authorization_details (HTTP 400, or redirected)' },
  { code: 'STS-OAUTH-0456',
    summary: 'An authorization_details entry does not conform to the JSON ' +
      'Schema its type\'s definition declares (RFC 9396 section 5).',
    spec: 'invalid_authorization_details (HTTP 400, or redirected)' },
  { code: 'STS-OAUTH-0457',
    summary: 'An authorization_details entry names a location the resource ' +
      'declaring its type does not answer to.',
    spec: 'invalid_authorization_details (HTTP 400, or redirected)' },
  { code: 'STS-OAUTH-0458',
    summary: 'A token request\'s authorization_details asks for more than ' +
      'the grant authorized (RFC 9396 section 6).',
    spec: 'invalid_authorization_details (HTTP 400)' },
  { code: 'STS-OAUTH-0459',
    summary: 'A request\'s authorization_details address more than one ' +
      'resource server, which one JWT access token cannot carry ' +
      'unambiguously (RFC 9068 section 3).',
    spec: 'invalid_authorization_details (HTTP 400, or redirected)' },
  { code: 'STS-OAUTH-0460',
    summary: 'A request names a resource or a scope for a different API ' +
      'from the one its authorization_details address.',
    spec: 'invalid_target or invalid_scope (HTTP 400, or redirected)' },
  { code: 'STS-OAUTH-0461',
    summary: 'An application declares an oauthAuthorizationDetailsType value ' +
      'that cannot be read as a definition; it is ignored.',
    spec: 'none — logged only' },
  { code: 'STS-OAUTH-0462',
    summary: 'Two applications declare the same authorization_details type; ' +
      'the first in identifier order answers for it.',
    spec: 'none — logged only' },
  // RFC 8705 (2026-09-13): mutual-TLS client authentication and certificate-
  // bound access tokens. Block reserved at 0480..0499.
  { code: 'STS-OAUTH-0480',
    summary: 'A tls_client_auth client presented a TLS client certificate ' +
      'whose chain did not verify against the client truststore (RFC 8705 ' +
      'section 2.1).',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0481',
    summary: 'A tls_client_auth client presented a certificate that chains to ' +
      'this service\'s own Root and is not a TLS client identity in this ' +
      'realm (another realm\'s, or a key pair issued for another purpose).',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0482',
    summary: 'A tls_client_auth client\'s entry registers more than one of ' +
      'RFC 8705 section 2.1.2\'s five certificate subject parameters.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0483',
    summary: 'A tls_client_auth client presented a certificate this realm ' +
      'issued to it that its record no longer lists (taken off or replaced).',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0484',
    summary: 'A tls_client_auth client presented a certificate this realm ' +
      'issued as the identity of another application or of a person.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0485',
    summary: 'A tls_client_auth client presented a verified certificate that ' +
      'does not carry the subject DN or subjectAltName it registered (RFC ' +
      '8705 section 2.1.2).',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0486',
    summary: 'A tls_client_auth client presented a verified certificate this ' +
      'realm did not issue to it, and registers no certificate subject to ' +
      'match it against.',
    spec: 'invalid_client (HTTP 401)' },
  { code: 'STS-OAUTH-0487',
    summary: 'A client that registered tls_client_certificate_bound_access_' +
      'tokens made a token request on a connection with no client ' +
      'certificate (RFC 8705 section 3.4), refused in every mode.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-OAUTH-0488',
    summary: 'A client declaring an RFC 8705 certificate authentication ' +
      'method did not authenticate by certificate and no more specific ' +
      'reason was recorded; refused in every mode.',
    spec: 'invalid_client (HTTP 401)' },
  // RFC 9470 (2026-09-13): step-up authentication. `oauth-oidc/step_up.js`
  // decides; the authorization endpoint, `dpop.presentedAccessToken()` and the
  // stand-in resource answer. Block reserved at 0500..0529.
  { code: 'STS-OAUTH-0500',
    summary: 'An authorization request\'s acr_values were not met by the ' +
      'authentication performed after the person was sent to sign in again ' +
      '(RFC 9470 section 5); refused in every mode.',
    spec: 'unmet_authentication_requirements (redirected error)' },
  { code: 'STS-OAUTH-0501',
    summary: 'An authorization request\'s max_age was still not met on the ' +
      'return from the sign-in it was sent to — the sign-in did not start a ' +
      'new authentication.',
    spec: 'unmet_authentication_requirements (redirected error)' },
  { code: 'STS-OAUTH-0502',
    summary: 'The session did not meet an authorization request\'s ' +
      'acr_values or max_age, and prompt=none forbids sending the person to ' +
      'sign in again.',
    spec: 'login_required (redirected error)' },
  { code: 'STS-OAUTH-0503',
    summary: 'A resource server here challenged an access token whose acr ' +
      'meets none of the acr values the resource requires (RFC 9470 section ' +
      '3).',
    spec: 'insufficient_user_authentication (HTTP 401, WWW-Authenticate ' +
      'challenge with acr_values)' },
  { code: 'STS-OAUTH-0504',
    summary: 'A resource server here challenged an access token whose ' +
      'auth_time is older than the max_age the resource requires, or absent ' +
      '(RFC 9470 section 3).',
    spec: 'insufficient_user_authentication (HTTP 401, WWW-Authenticate ' +
      'challenge with max_age)' },
  { code: 'STS-OAUTH-0505',
    summary: 'The step-up stand-in resource was asked for an application ' +
      'this realm has no entry for.',
    spec: 'invalid_request (HTTP 404)' },
  { code: 'STS-OAUTH-0506',
    summary: 'An access token presented at the step-up stand-in resource ' +
      'does not name that application in its aud (RFC 9068 section 4 step ' +
      '4).',
    spec: 'invalid_token (HTTP 401, WWW-Authenticate challenge)' },
  { code: 'STS-OAUTH-0507',
    summary: 'An access token presented at the step-up stand-in resource ' +
      'did not verify against this realm\'s signing key.',
    spec: 'invalid_token (HTTP 401, WWW-Authenticate challenge)' },
  { code: 'STS-OAUTH-0508',
    summary: 'A configured step-up requirement (oauth2.stepUpAcrValues, or ' +
      'an application\'s oauthStepUpAcrValues or oauthStepUpMaxAge written ' +
      'by hand) holds a value that cannot be one, and it was ignored.',
    spec: 'none — logged only' },
  { code: 'STS-OAUTH-0509',
    summary: 'An authorization request\'s acr_values carries a value that ' +
      'cannot be an acr value (a double quote, a backslash or a control ' +
      'character).',
    spec: 'invalid_request (redirected error)' },
  { code: 'STS-OAUTH-0510',
    summary: 'A password or assertion grant was refused because the ' +
      'directory holds no entry for the person, so there is no subject to ' +
      'issue a token about.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0511',
    summary: 'A refresh was refused because the subject of the refresh ' +
      'token names nobody in the directory any more (the person was ' +
      'deleted, or deleted and re-created).',
    spec: 'invalid_grant (HTTP 400)' },
  // ----- #46: single-use OAuth values spent through a cluster claim ---------
  { code: 'STS-OAUTH-0512',
    summary: 'An authorization code was being redeemed by another Token ' +
      'Request at the same moment (its claim was held), and that ' +
      'redemption\'s record did not appear within the wait, so this one ' +
      'was refused.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0513',
    summary: 'An authorization code could not be spent because the claim ' +
      'store could not be asked; the Token Request was refused and the code ' +
      'left unspent (fail closed).',
    spec: 'server_error (HTTP 500)' },
  { code: 'STS-OAUTH-0514',
    summary: 'An authorization response on a pushed request_uri was refused ' +
      'because another response was issued on it at the same moment (its ' +
      'claim was held) (RFC 9126 section 4).',
    spec: 'invalid_request_uri (HTTP 400)' },
  { code: 'STS-OAUTH-0515',
    summary: 'A pushed request_uri could not be spent because the claim ' +
      'store could not be asked, so nothing was issued on it (fail closed).',
    spec: 'server_error (HTTP 500)' },
  { code: 'STS-OAUTH-0516',
    summary: 'In RFC 9700 mode, a refresh token was redeemed by another ' +
      'request, on this node or another, at the same moment or before this ' +
      'node heard of it (its claim was held); treated as a replay and its ' +
      'family revoked (section 2.2.2).',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0517',
    summary: 'In RFC 9700 mode, a refresh token was presented whose family ' +
      'had already been revoked by a replay — possibly a token minted on ' +
      'another node that the revoking node never saw.',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-OAUTH-0518',
    summary: 'In RFC 9700 mode, a refresh token could not be redeemed because ' +
      'the claim store could not be asked; refused, and left unspent (fail ' +
      'closed).',
    spec: 'server_error (HTTP 500)' },
  { code: 'STS-OAUTH-0519',
    summary: 'A DPoP proof was refused because another request carrying the ' +
      'same jti claimed it first, on this node or another (RFC 9449 section ' +
      '11.1).',
    spec: 'invalid_dpop_proof (HTTP 400 / 401)' },
  { code: 'STS-OAUTH-0520',
    summary: 'A DPoP proof was refused because the claim store could not be ' +
      'asked whether its jti had been used (fail closed).',
    spec: 'invalid_dpop_proof (HTTP 400 / 401)' },
  // ===== SAML ==============================================================
  { code: 'STS-SAML-0001',
    summary: 'A SAML 2.0 sign-in resumed with a held-request id that is ' +
      'unknown or has expired (saml2.requestTtlMin), so there is no ' +
      'AuthnRequest to answer.',
    spec: 'HTTP 400 page' },
  { code: 'STS-SAML-0002',
    summary: 'The SAMLRequest at the SAML 2.0 Single Sign-On service is not ' +
      'a readable <samlp:AuthnRequest>: malformed XML, or another ' +
      'message.',
    spec: 'HTTP 400 page' },
  { code: 'STS-SAML-0003',
    summary: 'A SAML 2.0 AuthnRequest names no <saml:Issuer> and the path ' +
      'names no service provider, so there is no audience to issue ' +
      'for.',
    spec: 'HTTP 400 page' },
  { code: 'STS-SAML-0004',
    summary: 'saml2.entityId is empty in a product-mode realm, so the SAML ' +
      '2.0 identity provider has no name to issue or publish metadata ' +
      'under.',
    spec: 'HTTP 503 (a page at the SSO service, text/plain at the ' +
      'metadata endpoint)' },
  { code: 'STS-SAML-0005',
    summary: 'In product mode, a SAML 2.0 AuthnRequest\'s ' +
      'AssertionConsumerServiceURL is not a ' +
      'samlAssertionConsumerService registered on the service ' +
      'provider\'s entry, or none is registered.',
    spec: 'HTTP 400 page' },
  { code: 'STS-SAML-0006',
    summary: 'The SAML 2.0 assertion consumer service URL is not an absolute ' +
      'http(s) URL.',
    spec: 'HTTP 400 page' },
  { code: 'STS-SAML-0007',
    summary: 'A SAML 2.0 AuthnRequest asked for a ProtocolBinding this ' +
      'identity provider does not implement (for example PAOS).',
    spec: 'HTTP 400 page' },
  { code: 'STS-SAML-0008',
    summary: 'A SAML 2.0 AuthnRequest set IsPassive and there is no usable ' +
      'session, so the identity provider may not show the sign-in ' +
      'screen.',
    spec: 'samlp:Response with status Responder / NoPassive' },
  { code: 'STS-SAML-0009',
    summary: 'The sign-in screen reported that a SAML 2.0 sign-in was ' +
      'cancelled or failed.',
    spec: 'samlp:Response with status Responder / AuthnFailed' },
  { code: 'STS-SAML-0010',
    summary: 'The issuance policy refused a SAML 2.0 assertion for this ' +
      'person to this service provider.',
    spec: 'samlp:Response with status Responder / RequestDenied' },
  { code: 'STS-SAML-0011',
    summary: 'In product mode, a SAML 2.0 assertion configured to be ' +
      'encrypted could not be encrypted (no usable certificate), so ' +
      'none was sent.',
    spec: 'samlp:Response with status Responder and no assertion' },
  { code: 'STS-SAML-0012',
    summary: 'A SAML 2.0 assertion or logout NameID could not be encrypted ' +
      'to the service provider\'s certificate (usually a non-RSA key) ' +
      'and went out in clear.',
    spec: '' },
  { code: 'STS-SAML-0013',
    summary: 'A SAML 2.0 protocol message (Response, LogoutResponse or ' +
      'LogoutRequest) could not be signed and was sent unsigned.',
    spec: '' },
  { code: 'STS-SAML-0014',
    summary: 'The SAML 2.0 identity provider metadata could not be signed ' +
      'and was served unsigned.',
    spec: '' },
  { code: 'STS-SAML-0015',
    summary: 'The body posted to the SAML 2.0 Artifact Resolution Service is ' +
      'not XML.',
    spec: 'SOAP samlp:ArtifactResponse with status Requester (HTTP 200)' },
  { code: 'STS-SAML-0016',
    summary: 'The SOAP body posted to the SAML 2.0 Artifact Resolution ' +
      'Service carries no <samlp:ArtifactResolve>.',
    spec: 'SOAP samlp:ArtifactResponse with status Requester (HTTP 200)' },
  { code: 'STS-SAML-0017',
    summary: 'A SAML 2.0 ArtifactResolve carries no <samlp:Artifact>.',
    spec: 'SOAP samlp:ArtifactResponse with status Requester (HTTP 200)' },
  { code: 'STS-SAML-0018',
    summary: 'A SAML 2.0 artifact does not resolve: never issued here, ' +
      'expired (saml2.artifactTtlS), or already resolved once.',
    spec: 'SOAP samlp:ArtifactResponse with status Requester (HTTP 200)' },
  { code: 'STS-SAML-0019',
    summary: 'The SAMLRequest at the SAML 2.0 Single Logout service is not a ' +
      'readable <samlp:LogoutRequest>.',
    spec: 'HTTP 400 page' },
  { code: 'STS-SAML-0020',
    summary: 'A SAML 2.0 LogoutRequest carried an <saml:EncryptedID> this ' +
      'service could not decrypt, so the session was not ended.',
    spec: 'HTTP 400 page' },
  { code: 'STS-SAML-0021',
    summary: 'The mock SAML 2.0 service provider was handed an artifact that ' +
      'does not resolve (already resolved, expired or never issued).',
    spec: 'HTTP 200 error page' },
  { code: 'STS-SAML-0022',
    summary: 'A response delivered to the mock SAML 2.0 service provider ' +
      'failed at least one of its verification checks.',
    spec: 'HTTP 200 page listing the failed checks' },
  { code: 'STS-SAML-0023',
    summary: 'A SAML 2.0 assertion could not be signed and was returned ' +
      'unsigned.',
    spec: '' },
  { code: 'STS-SAML-0024',
    summary: 'A SAML 1.1 assertion could not be signed and was returned ' +
      'unsigned.',
    spec: '' },
  { code: 'STS-SAML-0025',
    summary: 'A SAML 1.1 browser flow resumed with a held-flow id that is ' +
      'unknown or has expired (saml11.requestTtlMin).',
    spec: 'HTTP 400 page' },
  { code: 'STS-SAML-0026',
    summary: 'A SAML 1.1 flow named a profile other than post or artifact in ' +
      'the non-spec profile parameter.',
    spec: 'HTTP 400 page' },
  { code: 'STS-SAML-0027',
    summary: 'saml11.providerId is empty in a product-mode realm, so the ' +
      'SAML 1.1 identity provider has no name to issue or publish ' +
      'metadata under.',
    spec: 'HTTP 503 page or text/plain at the inter-site transfer service ' +
      'and metadata; samlp:Response status Responder at the SAML ' +
      'responder' },
  { code: 'STS-SAML-0028',
    summary: 'In product mode, a SAML 1.1 flow\'s shire is not a ' +
      'samlAssertionConsumerService registered on the relying party\'s ' +
      'entry, or none is registered.',
    spec: 'HTTP 400 page' },
  { code: 'STS-SAML-0029',
    summary: 'The SAML 1.1 assertion consumer URL is not an absolute http(s) ' +
      'URL.',
    spec: 'HTTP 400 page' },
  { code: 'STS-SAML-0030',
    summary: 'A SAML 1.1 flow names no relying party: no providerId, no path ' +
      'segment and no TARGET origin to take one from.',
    spec: 'HTTP 400 page' },
  { code: 'STS-SAML-0031',
    summary: 'The sign-in screen reported that a SAML 1.1 sign-in was ' +
      'cancelled or failed.',
    spec: 'HTTP 400 page' },
  { code: 'STS-SAML-0032',
    summary: 'The issuance policy refused a SAML 1.1 assertion for this ' +
      'person to this relying party.',
    spec: 'HTTP 403 page' },
  { code: 'STS-SAML-0033',
    summary: 'A SAML 1.1 <samlp:Response> could not be signed and was sent ' +
      'unsigned.',
    spec: '' },
  { code: 'STS-SAML-0034',
    summary: 'The SAML 1.1 identity provider metadata could not be signed ' +
      'and was served unsigned.',
    spec: '' },
  { code: 'STS-SAML-0035',
    summary: 'The body posted to the SAML 1.1 SAML responder is not XML.',
    spec: 'SOAP samlp:Response with status samlp:Requester (HTTP 200)' },
  { code: 'STS-SAML-0036',
    summary: 'The SOAP body posted to the SAML 1.1 SAML responder carries no ' +
      '<samlp:Request>.',
    spec: 'SOAP samlp:Response with status samlp:Requester (HTTP 200)' },
  { code: 'STS-SAML-0037',
    summary: 'A SAML 1.1 artifact does not resolve: never issued here, ' +
      'expired (saml11.artifactTtlS), or already resolved once.',
    spec: 'SOAP samlp:Response with status samlp:Requester (HTTP 200)' },
  { code: 'STS-SAML-0038',
    summary: 'A SAML 1.1 AssertionIDReference names an assertion this ' +
      'service does not hold.',
    spec: 'SOAP samlp:Response with status samlp:Requester (HTTP 200)' },
  { code: 'STS-SAML-0039',
    summary: 'A SAML 1.1 AttributeQuery or AuthenticationQuery was refused ' +
      'because the realm is in product mode and nothing authenticates ' +
      'the caller.',
    spec: 'SOAP samlp:Response with status samlp:Requester (HTTP 200)' },
  { code: 'STS-SAML-0040',
    summary: 'A SAML 1.1 query carries no <saml:Subject> with a ' +
      'NameIdentifier.',
    spec: 'SOAP samlp:Response with status samlp:Requester (HTTP 200)' },
  { code: 'STS-SAML-0041',
    summary: 'A SAML 1.1 <samlp:Request> carries none of the four request ' +
      'types the responder answers (an AuthorizationDecisionQuery ' +
      'included).',
    spec: 'SOAP samlp:Response with status samlp:Requester (HTTP 200)' },
  { code: 'STS-SAML-0042',
    summary: 'The mock SAML 1.1 relying party was handed an artifact that ' +
      'does not resolve (already resolved, expired or never issued).',
    spec: 'HTTP 400 page' },
  { code: 'STS-SAML-0043',
    summary: 'A response delivered to the mock SAML 1.1 relying party failed ' +
      'at least one of its verification checks.',
    spec: 'HTTP 200 page listing the failed checks' },
  { code: 'STS-SAML-0044',
    summary: 'A service provider metadata refresh named an application that ' +
      'is not in the registry.',
    spec: '' },
  { code: 'STS-SAML-0045',
    summary: 'Service provider metadata was not fetched because ' +
      'federation.outbound is off.',
    spec: '' },
  { code: 'STS-SAML-0046',
    summary: 'Service provider metadata was not fetched because ' +
      'samlSpMetadataUrl is empty, not a URL, or not a scheme the ' +
      'outbound policy dials.',
    spec: '' },
  { code: 'STS-SAML-0047',
    summary: 'The service provider metadata URL answered with a redirect, ' +
      'which is not followed.',
    spec: '' },
  { code: 'STS-SAML-0048',
    summary: 'The service provider metadata URL answered with a status other ' +
      'than 200.',
    spec: '' },
  { code: 'STS-SAML-0049',
    summary: 'The service provider metadata document exceeded ' +
      'saml2.spMetadataMaxBytes and the fetch was abandoned.',
    spec: '' },
  { code: 'STS-SAML-0050',
    summary: 'The service provider metadata URL did not answer within ' +
      'federation.outboundTimeoutMs.',
    spec: '' },
  { code: 'STS-SAML-0051',
    summary: 'The service provider metadata request failed at the network or ' +
      'TLS layer (DNS, connection refused, untrusted certificate).',
    spec: '' },
  { code: 'STS-SAML-0052',
    summary: 'Fetched service provider metadata is unusable: not ' +
      'well-formed, an EntitiesDescriptor, or no KeyDescriptor usable ' +
      'for encryption.',
    spec: '' },
  { code: 'STS-SAML-0053',
    summary: 'Fetched service provider metadata carries a certificate this ' +
      'service cannot use (unreadable, or not an RSA key).',
    spec: '' },
  { code: 'STS-SAML-0054',
    summary: 'The application entry refused the metadata and encryption ' +
      'certificate a refresh fetched.',
    spec: '' },
  { code: 'STS-SAML-0055',
    summary: 'A SAML 2.0 sign-in came back from its one trip to the sign-in ' +
      'screen without a fresh authentication (ForceAuthn) or without a ' +
      'session, and was answered AuthnFailed rather than sent again.',
    spec: 'Response status AuthnFailed' },
  { code: 'STS-SAML-0056',
    summary: 'A SAML 2.0 sign-in came back from its one trip to the sign-in ' +
      'screen with a session that still does not meet the ' +
      'RequestedAuthnContext, and was answered NoAuthnContext.',
    spec: 'Response status NoAuthnContext' },
  { code: 'STS-SAML-0057',
    summary: 'A SAML 2.0 artifact this process still held was already ' +
      'resolved by another process against the same store (the cluster ' +
      'claim, #46); section 3.6.4.1 allows one resolution.',
    spec: 'ArtifactResponse with StatusCode Requester (HTTP 200)' },
  { code: 'STS-SAML-0058',
    summary: 'A SAML 1.1 artifact this process still held was already ' +
      'resolved by another process against the same store (the cluster ' +
      'claim, #46); saml-bindings-1.1 section 3.2.3 allows one resolution.',
    spec: 'samlp:Response with StatusCode samlp:Requester (HTTP 200)' },
  { code: 'STS-SAML-0059',
    summary: 'The cluster claim store could not be asked whether a SAML ' +
      'artifact (2.0 or 1.1) was already resolved, so it was refused rather ' +
      'than resolved unproven.',
    spec: 'StatusCode Responder (HTTP 200)' },
  { code: 'STS-SAML-0060',
    summary: 'An artifact resolution (2.0 or 1.1) failed while its answer ' +
      'was being built or sent, after the artifact had been spent.',
    spec: 'StatusCode Responder (HTTP 200) when nothing was sent yet' },
  // ===== WSTRUST ===========================================================
  { code: 'STS-WSTRUST-0001',
    summary: 'The RequestSecurityToken body is not well-formed XML (or is ' +
      'empty), so no operation could be read from it.',
    spec: 'SOAP Fault soap:Sender / soap:Client (HTTP 400)' },
  { code: 'STS-WSTRUST-0002',
    summary: 'A WS-Security UsernameToken was presented without a username ' +
      'or without a password.',
    spec: 'SOAP Fault soap:Sender / soap:Client (HTTP 500)' },
  { code: 'STS-WSTRUST-0003',
    summary: 'A WS-Security UsernameToken\'s password was refused by the ' +
      'credential verifier (the reserved string in development, the ' +
      'stored userPassword in product). The fault does not say ' +
      'whether the user or the password was wrong.',
    spec: 'SOAP Fault soap:Sender / soap:Client (HTTP 500)' },
  { code: 'STS-WSTRUST-0004',
    summary: 'Product mode: a SAML assertion presented as the requester\'s ' +
      'credential or inside OnBehalfOf/ActAs does not verify against ' +
      'this STS\'s own signing certificate.',
    spec: 'SOAP Fault soap:Sender / soap:Client (HTTP 500)' },
  { code: 'STS-WSTRUST-0005',
    summary: 'Product mode: a SAML assertion presented to the STS is not yet ' +
      'valid (its Conditions NotBefore is in the future beyond the ' +
      'clock skew).',
    spec: 'SOAP Fault soap:Sender / soap:Client (HTTP 500)' },
  { code: 'STS-WSTRUST-0006',
    summary: 'Product mode: a SAML assertion presented to the STS has ' +
      'expired (its Conditions NotOnOrAfter has passed beyond the ' +
      'clock skew).',
    spec: 'SOAP Fault soap:Sender / soap:Client (HTTP 500)' },
  { code: 'STS-WSTRUST-0007',
    summary: 'Product mode: a SAML assertion presented to the STS carries no ' +
      'NameID, so it names nobody.',
    spec: 'SOAP Fault soap:Sender / soap:Client (HTTP 500)' },
  { code: 'STS-WSTRUST-0008',
    summary: 'Product mode: a wst:OnBehalfOf or wst14:ActAs element carries ' +
      'no SAML assertion, so the delegated subject is only a name.',
    spec: 'SOAP Fault soap:Sender / soap:Client (HTTP 500)' },
  { code: 'STS-WSTRUST-0009',
    summary: 'Product mode: a request delegates (OnBehalfOf/ActAs) but ' +
      'presents no credential of its own for the requester.',
    spec: 'SOAP Fault soap:Sender / soap:Client (HTTP 500)' },
  { code: 'STS-WSTRUST-0010',
    summary: 'Product mode: a WS-Trust request presented no credential at ' +
      'all in its security header.',
    spec: 'SOAP Fault soap:Sender / soap:Client (HTTP 500)' },
  { code: 'STS-WSTRUST-0011',
    summary: 'The issuance policy (the role gate) refused a token for this ' +
      'subject to this AppliesTo.',
    spec: 'SOAP Fault soap:Sender / soap:Client (HTTP 403)' },
  { code: 'STS-WSTRUST-0012',
    summary: '?encrypt=1 was requested but the request carries no recipient ' +
      'X509Certificate to encrypt the assertion to. Product mode ' +
      'refuses; development returns the assertion in clear and logs ' +
      'this.',
    spec: 'SOAP Fault soap:Sender / soap:Client (HTTP 500) in product; ' +
      'none in development' },
  { code: 'STS-WSTRUST-0013',
    summary: '?encrypt=1 was requested and encrypting the assertion to the ' +
      'request\'s certificate failed. Product mode refuses; ' +
      'development returns the assertion in clear and logs this.',
    spec: 'SOAP Fault soap:Sender / soap:Client (HTTP 500) in product; ' +
      'none in development' },
  { code: 'STS-WSTRUST-0014',
    summary: 'A Validate request carried no token in its ValidateTarget, so ' +
      'it was answered with a status of invalid.',
    spec: 'wst:Status wst:Code .../status/invalid (HTTP 200)' },
  { code: 'STS-WSTRUST-0015',
    summary: 'The STS endpoint threw an unexpected exception while handling ' +
      'a RequestSecurityToken.',
    spec: 'SOAP 1.2 Fault soap:Sender (HTTP 500)' },
  { code: 'STS-WSTRUST-0016',
    summary: 'A token was issued but starting the browser sign-on session ' +
      'the exchange also starts threw; the RSTR is unaffected.',
    spec: '' },
  { code: 'STS-WSTRUST-0017',
    summary: 'A JWT was refused because the directory holds no entry for the ' +
      'person, so there is no subject to issue it about.',
    spec: 'SOAP Fault (HTTP 400)' },
  // ===== WSFED =============================================================
  { code: 'STS-WSFED-0001',
    summary: 'A wsignin1.0 request carried wreqptr, which this service ' +
      'refuses to dereference (fetching a URL from a query parameter ' +
      'would be a server-side request forgery).',
    spec: 'HTTP 400 error page (the profile defines no error response)' },
  { code: 'STS-WSFED-0002',
    summary: 'A wsignin1.0 request named no wtrealm, so there is no relying ' +
      'party to issue a token for.',
    spec: 'HTTP 400 error page (the profile defines no error response)' },
  { code: 'STS-WSFED-0003',
    summary: 'Product mode: the wreply is not one of the wsfedReplyUrl ' +
      'values registered on the wtrealm\'s application entry (or none ' +
      'is registered).',
    spec: 'HTTP 400 error page (the profile defines no error response)' },
  { code: 'STS-WSFED-0004',
    summary: 'The resolved wreply is not an absolute http(s) URL, so the ' +
      'sign-in response form would post back to this service.',
    spec: 'HTTP 400 error page (the profile defines no error response)' },
  { code: 'STS-WSFED-0005',
    summary: 'The request (wreq TokenType or the non-spec tokenType ' +
      'parameter) asked for a token type other than SAML 1.1 or SAML ' +
      '2.0.',
    spec: 'HTTP 400 error page (the profile defines no error response)' },
  { code: 'STS-WSFED-0006',
    summary: 'wauth demanded an authentication method this identity provider ' +
      'cannot perform or report.',
    spec: 'HTTP 400 error page (the profile defines no error response)' },
  { code: 'STS-WSFED-0007',
    summary: 'The sign-in at the authentication service was cancelled or ' +
      'failed, so nothing is posted to the relying party.',
    spec: 'HTTP 200 error page; the relying party is never posted to' },
  { code: 'STS-WSFED-0008',
    summary: 'wfresh is not a non-negative number of minutes.',
    spec: 'HTTP 400 error page (the profile defines no error response)' },
  { code: 'STS-WSFED-0009',
    summary: 'wauth demanded a hardware token and the existing browser ' +
      'session used no security key.',
    spec: 'HTTP 400 error page (the profile defines no error response)' },
  { code: 'STS-WSFED-0010',
    summary: 'wauth demanded multi-factor authentication and the existing ' +
      'browser session had only one factor.',
    spec: 'HTTP 400 error page (the profile defines no error response)' },
  { code: 'STS-WSFED-0011',
    summary: 'The issuance policy (the role gate) refused a token for the ' +
      'signed-in person to this wtrealm.',
    spec: 'HTTP 403 error page' },
  { code: 'STS-WSFED-0012',
    summary: 'The request asked for wattr1.0 (attribute service) or ' +
      'wpseudo1.0 (pseudonym service), neither of which is ' +
      'implemented.',
    spec: 'HTTP 501 error page' },
  { code: 'STS-WSFED-0013',
    summary: 'The passive requestor endpoint was sent a wa value it does not ' +
      'understand.',
    spec: 'HTTP 400 error page (the profile defines no error response)' },
  { code: 'STS-WSFED-0014',
    summary: 'The wreq parameter is not readable XML; it is ignored and the ' +
      'default token type is used.',
    spec: '' },
  { code: 'STS-WSFED-0015',
    summary: 'The WS-Federation metadata document could not be signed and ' +
      'was served unsigned.',
    spec: '' },
  { code: 'STS-WSFED-0016',
    summary: 'The mock relying party at /wsfed/rp received a sign-in ' +
      'response that failed one or more of its verification checks.',
    spec: 'HTTP 200 page listing the failed checks' },
  // ===== FED ===============================================================
  { code: 'STS-FED-0001',
    summary: 'A federation endpoint (login or assertion consumer service) ' +
      'was reached while federation.enabled is off.',
    spec: 'HTTP 404 page' },
  { code: 'STS-FED-0002',
    summary: 'A federation login or assertion consumer service request named ' +
      'a relationship that does not exist (or, at the ACS, is not ' +
      'service-provider side).',
    spec: 'HTTP 404 page' },
  { code: 'STS-FED-0003',
    summary: 'Federation service provider metadata was asked for a ' +
      'relationship that is not a SAML service-provider-side ' +
      'relationship.',
    spec: 'HTTP 404 page' },
  { code: 'STS-FED-0004',
    summary: 'A federated sign-in was started through an ' +
      'identity-provider-side relationship, which has nothing to sign ' +
      'in to.',
    spec: 'HTTP 400 page' },
  { code: 'STS-FED-0005',
    summary: 'A federated sign-in or partner response arrived for a ' +
      'relationship that is disabled.',
    spec: 'HTTP 403 page' },
  { code: 'STS-FED-0006',
    summary: 'A federated sign-in or partner response arrived for a ' +
      'relationship that is enabled but missing a field its protocol ' +
      'needs.',
    spec: 'HTTP 409 page at login, HTTP 403 page at the assertion ' +
      'consumer service' },
  { code: 'STS-FED-0007',
    summary: 'The federation assertion consumer service received no ' +
      'SAMLResponse or no wresult.',
    spec: 'HTTP 400 page' },
  { code: 'STS-FED-0008',
    summary: 'A partner\'s SAMLResponse could not be base64-decoded.',
    spec: 'HTTP 400 page' },
  { code: 'STS-FED-0009',
    summary: 'A partner\'s SAMLResponse or WS-Federation wresult is not ' +
      'well-formed XML, or has no document element.',
    spec: 'HTTP 400 page' },
  { code: 'STS-FED-0010',
    summary: 'A federation partner answered with a SAML status other than ' +
      'Success: it declined to authenticate the person.',
    spec: 'HTTP 400 page' },
  { code: 'STS-FED-0011',
    summary: 'A partner\'s SAML Response or WS-Federation token carried no ' +
      '<Assertion> (an encrypted assertion looks like this; it is not ' +
      'decrypted).',
    spec: 'HTTP 400 page' },
  { code: 'STS-FED-0012',
    summary: 'A partner\'s SAML assertion or response carries no XML ' +
      'signature at all, so it is refused as unauthenticated.',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0013',
    summary: 'A partner\'s XML signature did not verify against the ' +
      'fedSigningCertificate configured on the relationship (a ' +
      'certificate inside the document is never used).',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0014',
    summary: 'A partner\'s assertion arrived for a relationship with no ' +
      'fedSigningCertificate, so nothing can be verified and nothing ' +
      'is accepted.',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0015',
    summary: 'A partner\'s verified assertion names an issuer other than the ' +
      'relationship\'s fedPeer.',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0016',
    summary: 'A partner\'s assertion arrived for a relationship with no ' +
      'fedPeer, so its issuer cannot be checked and it is refused.',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0017',
    summary: 'A partner\'s assertion is not yet valid (NotBefore is in the ' +
      'future beyond oauth2.clockSkewS).',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0018',
    summary: 'A partner\'s assertion has expired (NotOnOrAfter has passed ' +
      'beyond oauth2.clockSkewS); a replay or clock disagreement.',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0019',
    summary: 'A partner\'s SAML 2.0 assertion carries no ' +
      'AudienceRestriction, which the Web Browser SSO profile requires.',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0020',
    summary: 'A partner\'s assertion is addressed to an audience other than ' +
      'this service\'s entityID or fedClientId for the relationship.',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0021',
    summary: 'A partner\'s response came back with no RelayState, wctx or ' +
      'state, so it cannot be matched to a sign-in this service ' +
      'started (unsolicited).',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0022',
    summary: 'A partner\'s response carried a RelayState, wctx or state this ' +
      'service did not mint, or whose sign-in expired or was already ' +
      'spent (a replay or forgery).',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0023',
    summary: 'A partner\'s SAML 2.0 assertion InResponseTo names a different ' +
      'AuthnRequest from the one this sign-in sent.',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0024',
    summary: 'A WS-Federation message at the federation assertion consumer ' +
      'service is not wa=wsignin1.0 (a federated sign-out is not ' +
      'consumed).',
    spec: 'HTTP 400 page' },
  { code: 'STS-FED-0025',
    summary: 'An OAuth 2.0 / OpenID Connect partner redirected back with an ' +
      'error instead of a code.',
    spec: 'HTTP 400 page' },
  { code: 'STS-FED-0026',
    summary: 'An OpenID Connect partner configured for a front-channel ID ' +
      'Token posted back no id_token.',
    spec: 'HTTP 400 page' },
  { code: 'STS-FED-0027',
    summary: 'An OAuth 2.0 / OpenID Connect partner redirected back with ' +
      'neither a code nor an error.',
    spec: 'HTTP 400 page' },
  { code: 'STS-FED-0028',
    summary: 'An OpenID Connect partner\'s token response carried no ' +
      'id_token.',
    spec: 'HTTP 502 page' },
  { code: 'STS-FED-0029',
    summary: 'An OAuth 2.0 partner\'s token response carried no access_token.',
    spec: 'HTTP 502 page' },
  { code: 'STS-FED-0030',
    summary: 'fedJwks on the relationship is not valid JSON, so there is no ' +
      'key to verify a partner\'s JWT with.',
    spec: 'HTTP 500 page' },
  { code: 'STS-FED-0031',
    summary: 'Neither fedJwks nor fedJwksUri is configured on the ' +
      'relationship, so there is no key to verify a partner\'s JWT ' +
      'with.',
    spec: 'HTTP 500 page' },
  { code: 'STS-FED-0032',
    summary: 'A partner\'s ID Token or access token has a header that is not ' +
      'base64url JSON, or names no alg.',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0033',
    summary: 'A partner\'s ID Token or access token declares alg=none — an ' +
      'unsigned token presented as signed.',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0034',
    summary: 'A partner\'s JWT names a kid the partner\'s key set does not ' +
      'contain (a key rotation, or a forgery).',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0035',
    summary: 'The partner\'s key set is empty, so no JWT from it can be ' +
      'verified.',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0036',
    summary: 'A partner\'s JWT signature did not verify against any key in ' +
      'its set with the key\'s algorithm family, or a key could not be ' +
      'read.',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0037',
    summary: 'A partner\'s JWT is expired or not yet valid beyond ' +
      'oauth2.clockSkewS.',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0038',
    summary: 'A partner\'s JWT audience is not fedClientId or its issuer is ' +
      'not fedPeer.',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0039',
    summary: 'A partner\'s ID Token nonce does not match the nonce this ' +
      'sign-in sent (a replayed ID Token).',
    spec: 'HTTP 401 page' },
  { code: 'STS-FED-0040',
    summary: 'The optional UserInfo request to an OpenID Connect partner ' +
      'failed; the sign-in continued on the verified ID Token without ' +
      'those attributes.',
    spec: '' },
  { code: 'STS-FED-0041',
    summary: 'A plain OAuth 2.0 partner returned an access token this ' +
      'service cannot read and no fedUserinfoUrl is configured, so ' +
      'nobody can be named.',
    spec: 'HTTP 500 page' },
  { code: 'STS-FED-0042',
    summary: 'This service threw while consuming a partner\'s response or ' +
      'finishing a federated sign-in.',
    spec: 'HTTP 500 page' },
  { code: 'STS-FED-0043',
    summary: 'A partner\'s assertion verified but yielded no username: no ' +
      'subject, and no fedUsernameSource attribute.',
    spec: 'HTTP 400 page' },
  { code: 'STS-FED-0044',
    summary: 'The issuance policy refused a session for a person arriving ' +
      'through a federation relationship.',
    spec: 'HTTP 403 page' },
  { code: 'STS-FED-0045',
    summary: 'The application registry threw while recording the foreign ' +
      'identity provider after a federated sign-in; the sign-in ' +
      'stood.',
    spec: '' },
  { code: 'STS-FED-0046',
    summary: 'A caller asked federation_http.js to dial an attribute outside ' +
      'DIALLABLE — a bug in the caller, refused.',
    spec: 'HTTP 502 or 500 page for the federated sign-in it was part of' },
  { code: 'STS-FED-0047',
    summary: 'A back-channel request to a federation partner was not made ' +
      'because federation.outbound is off.',
    spec: 'HTTP 502 or 500 page for the federated sign-in it was part of' },
  { code: 'STS-FED-0048',
    summary: 'A back-channel URL on a federation relationship cannot be ' +
      'dialled: empty, not a URL, plain http with ' +
      'federation.outboundAllowInsecure off, or another scheme.',
    spec: 'HTTP 502 or 500 page for the federated sign-in it was part of' },
  { code: 'STS-FED-0049',
    summary: 'A federation partner answered a back-channel request with a ' +
      'redirect, which is not followed.',
    spec: 'HTTP 502 or 500 page for the federated sign-in it was part of' },
  { code: 'STS-FED-0050',
    summary: 'A federation partner\'s back-channel response exceeded ' +
      'federation.maxResponseBytes and was abandoned.',
    spec: 'HTTP 502 or 500 page for the federated sign-in it was part of' },
  { code: 'STS-FED-0051',
    summary: 'A federation partner answered a back-channel request with a ' +
      'non-2xx status.',
    spec: 'HTTP 502 or 500 page for the federated sign-in it was part of' },
  { code: 'STS-FED-0052',
    summary: 'A federation partner\'s back-channel response stream failed ' +
      'part way through.',
    spec: 'HTTP 502 or 500 page for the federated sign-in it was part of' },
  { code: 'STS-FED-0053',
    summary: 'A back-channel request to a federation partner could not be ' +
      'built from its options.',
    spec: 'HTTP 502 or 500 page for the federated sign-in it was part of' },
  { code: 'STS-FED-0054',
    summary: 'A federation partner did not answer a back-channel request ' +
      'within federation.outboundTimeoutMs.',
    spec: 'HTTP 502 or 500 page for the federated sign-in it was part of' },
  { code: 'STS-FED-0055',
    summary: 'A back-channel request to a federation partner failed at the ' +
      'network or TLS layer (DNS, connection refused, untrusted ' +
      'certificate).',
    spec: 'HTTP 502 or 500 page for the federated sign-in it was part of' },
  { code: 'STS-FED-0056',
    summary: 'A federation partner answered a back-channel request with a ' +
      '2xx status whose body is not JSON.',
    spec: 'HTTP 502 or 500 page for the federated sign-in it was part of' },
  { code: 'STS-FED-0057',
    summary: 'The application registry threw while checking whether an ' +
      'application is configured for a federation relationship; the ' +
      'per-application count was skipped.',
    spec: '' },
  { code: 'STS-FED-0058',
    summary: 'The application registry threw while listing the applications ' +
      'using a federation relationship; the map is drawn without that ' +
      'half.',
    spec: '' },
  { code: 'STS-FED-0059',
    summary: 'The federation register threw while recording a successful use ' +
      'of a relationship; the sign-in stood.',
    spec: '' },
  { code: 'STS-FED-0060',
    summary: 'The federation register threw while recording a refused ' +
      'sign-in on a relationship (fedLastError).',
    spec: '' },
  { code: 'STS-FED-0061',
    summary: 'Creating a federation relationship was refused: the id, role ' +
      'or protocol is not valid.',
    spec: 'action result ok:false (console redirect or /admin-api HTTP ' +
      '400)' },
  { code: 'STS-FED-0062',
    summary: 'Creating a federation relationship was refused: no embedded ' +
      'directory is loaded to hold it.',
    spec: 'action result ok:false (console redirect or /admin-api HTTP ' +
      '400)' },
  { code: 'STS-FED-0063',
    summary: 'Creating a federation relationship was refused: one with that ' +
      'id already exists.',
    spec: 'action result ok:false (console redirect or /admin-api HTTP ' +
      '400)' },
  { code: 'STS-FED-0064',
    summary: 'Creating a federation relationship was refused: ou=federations ' +
      'is at federation.max or the directory is full.',
    spec: 'action result ok:false (console redirect or /admin-api HTTP ' +
      '400)' },
  { code: 'STS-FED-0065',
    summary: 'An update or deletion named a federation relationship that ' +
      'does not exist.',
    spec: 'action result ok:false (console redirect or /admin-api HTTP ' +
      '400)' },
  { code: 'STS-FED-0066',
    summary: 'An update named a field that is not an attribute of a ' +
      'federation relationship.',
    spec: 'action result ok:false (console redirect or /admin-api HTTP ' +
      '400)' },
  { code: 'STS-FED-0067',
    summary: 'An update named a federation relationship field that is not ' +
      'editable (identity, or a recorded counter).',
    spec: 'action result ok:false (console redirect or /admin-api HTTP ' +
      '400)' },
  { code: 'STS-FED-0068',
    summary: 'An update named a field belonging to the other direction of ' +
      'relationship.',
    spec: 'action result ok:false (console redirect or /admin-api HTTP ' +
      '400)' },
  { code: 'STS-FED-0069',
    summary: 'An update asked to remove a value a multi-valued relationship ' +
      'field does not carry.',
    spec: 'action result ok:false (console redirect or /admin-api HTTP ' +
      '400)' },
  { code: 'STS-FED-0070',
    summary: 'An update asked to add an empty value to a multi-valued ' +
      'relationship field.',
    spec: 'action result ok:false (console redirect or /admin-api HTTP ' +
      '400)' },
  { code: 'STS-FED-0071',
    summary: 'An update asked to add a value a multi-valued relationship ' +
      'field already carries.',
    spec: 'action result ok:false (console redirect or /admin-api HTTP ' +
      '400)' },
  { code: 'STS-FED-0072',
    summary: 'The directory refused the write for an update to a federation ' +
      'relationship.',
    spec: 'action result ok:false (console redirect or /admin-api HTTP ' +
      '400)' },
  { code: 'STS-FED-0073',
    summary: 'The directory would not delete a federation relationship.',
    spec: 'action result ok:false (console redirect or /admin-api HTTP ' +
      '400)' },
  { code: 'STS-FED-0090',
    summary: 'A federated sign-in verified, but the directory holds no entry ' +
      'for the person and none was created (dynamic provisioning off on the ' +
      'relationship, or the directory declined), so no session was started.',
    spec: 'HTTP 403 page' },
  // ===== KRB ===============================================================
  { code: 'STS-KRB-0001',
    summary: 'A cross-realm referral could not be issued because the trust ' +
      'account and the client share no encryption type.',
    spec: 'KDC_ERR_ETYPE_NOSUPP (14)' },
  { code: 'STS-KRB-0002',
    summary: 'An S4U request sent both PA-FOR-USER and cname-in-addl-tkt, ' +
      'which are separate S4U2Self and S4U2Proxy requests.',
    spec: 'KDC_ERR_BADOPTION (13)' },
  { code: 'STS-KRB-0003',
    summary: 'An S4U2Self request carried a PA-FOR-USER that does not ' +
      'decode.',
    spec: 'KDC_ERR_BADOPTION (13)' },
  { code: 'STS-KRB-0004',
    summary: 'An S4U2Self request\'s PA-FOR-USER checksum did not verify ' +
      'under the requester\'s TGT session key.',
    spec: 'KDC_ERR_BADOPTION (13)' },
  { code: 'STS-KRB-0005',
    summary: 'An S4U2Self request named a user this KDC does not know and ' +
      'will not create (reserved, service-shaped or in a realm it ' +
      'does not serve).',
    spec: 'KDC_ERR_C_PRINCIPAL_UNKNOWN (6)' },
  { code: 'STS-KRB-0006',
    summary: 'An S4U2Self request asked for a ticket to a service other than ' +
      'the requester itself.',
    spec: 'KDC_ERR_BADOPTION (13)' },
  { code: 'STS-KRB-0007',
    summary: 'An S4U2Proxy request set cname-in-addl-tkt but carried no ' +
      'additional ticket.',
    spec: 'KDC_ERR_BADOPTION (13)' },
  { code: 'STS-KRB-0008',
    summary: 'An S4U2Proxy evidence ticket was addressed to a service other ' +
      'than the requester.',
    spec: 'KDC_ERR_BADOPTION (13)' },
  { code: 'STS-KRB-0009',
    summary: 'An S4U2Proxy evidence ticket did not decrypt with the ' +
      'requester\'s long-term key.',
    spec: 'KDC_ERR_BADOPTION (13)' },
  { code: 'STS-KRB-0010',
    summary: 'S4U2Proxy was refused: neither msDS-AllowedToDelegateTo on the ' +
      'requester nor msDS-AllowedToActOnBehalfOfOtherIdentity on the ' +
      'target permits the delegation.',
    spec: 'KDC_ERR_BADOPTION (13)' },
  { code: 'STS-KRB-0011',
    summary: 'S4U2Proxy permitted only by resource-based delegation was ' +
      'refused because PA-PAC-OPTIONS with the resource-based bit was ' +
      'missing.',
    spec: 'KDC_ERR_BADOPTION (13)' },
  { code: 'STS-KRB-0012',
    summary: 'Classic constrained delegation was refused because the ' +
      'evidence ticket is not forwardable.',
    spec: 'KDC_ERR_BADOPTION (13)' },
  { code: 'STS-KRB-0013',
    summary: 'An AS-REQ for an account that requires pre-authentication ' +
      'carried no PA-ENC-TIMESTAMP; the KDC answered with the ' +
      'pre-authentication methods it accepts.',
    spec: 'KDC_ERR_PREAUTH_REQUIRED (25)' },
  { code: 'STS-KRB-0014',
    summary: 'The PA-ENC-TIMESTAMP, or the PA-ENC-TS-ENC inside it, was not ' +
      'well formed.',
    spec: 'KDC_ERR_PREAUTH_FAILED (24)' },
  { code: 'STS-KRB-0015',
    summary: 'The PA-ENC-TIMESTAMP was encrypted with a different encryption ' +
      'type from the one the request negotiated.',
    spec: 'KDC_ERR_PREAUTH_FAILED (24)' },
  { code: 'STS-KRB-0016',
    summary: 'The PA-ENC-TIMESTAMP did not decrypt under the client\'s ' +
      'long-term key: a wrong password, salt or key usage.',
    spec: 'KDC_ERR_PREAUTH_FAILED (24)' },
  { code: 'STS-KRB-0017',
    summary: 'The pre-authentication timestamp was outside the KDC\'s ' +
      'clock-skew tolerance.',
    spec: 'KRB_AP_ERR_SKEW (37)' },
  { code: 'STS-KRB-0018',
    summary: 'An AS-REQ named a realm this KDC does not serve.',
    spec: 'KDC_ERR_WRONG_REALM (68)' },
  { code: 'STS-KRB-0019',
    summary: 'An AS-REQ carried no client name.',
    spec: 'KDC_ERR_C_PRINCIPAL_UNKNOWN (6)' },
  { code: 'STS-KRB-0020',
    summary: 'An AS-REQ named a client this KDC does not know and will not ' +
      'create (a reserved or service-shaped name).',
    spec: 'KDC_ERR_C_PRINCIPAL_UNKNOWN (6)' },
  { code: 'STS-KRB-0021',
    summary: 'An AS-REQ named a service principal this KDC does not know.',
    spec: 'KDC_ERR_S_PRINCIPAL_UNKNOWN (7)' },
  { code: 'STS-KRB-0022',
    summary: 'The KDC has no krbtgt principal for the realm it is answering, ' +
      'so no ticket can be signed (in product mode, usually the ' +
      'published krbtgt password was refused).',
    spec: 'KDC_ERR_S_PRINCIPAL_UNKNOWN (7)' },
  { code: 'STS-KRB-0023',
    summary: 'An AS-REQ was refused because the client account is disabled ' +
      'or locked out.',
    spec: 'KDC_ERR_CLIENT_REVOKED (18)' },
  { code: 'STS-KRB-0024',
    summary: 'An AS-REQ was refused because the client\'s password has ' +
      'expired.',
    spec: 'KDC_ERR_KEY_EXPIRED (23)' },
  { code: 'STS-KRB-0025',
    summary: 'An AS-REQ was refused because the client and the KDC share no ' +
      'encryption type.',
    spec: 'KDC_ERR_ETYPE_NOSUPP (14)' },
  { code: 'STS-KRB-0026',
    summary: 'A TGS-REQ carried no PA-TGS-REQ, so there was no ' +
      'ticket-granting ticket to verify.',
    spec: 'KDC_ERR_PREAUTH_REQUIRED (25)' },
  { code: 'STS-KRB-0027',
    summary: 'A TGS-REQ\'s PA-TGS-REQ did not contain a readable AP-REQ.',
    spec: 'KRB_ERR_GENERIC (60)' },
  { code: 'STS-KRB-0028',
    summary: 'A TGS-REQ presented a ticket for a service principal this KDC ' +
      'does not know.',
    spec: 'KDC_ERR_S_PRINCIPAL_UNKNOWN (7)' },
  { code: 'STS-KRB-0029',
    summary: 'A TGS-REQ\'s ticket did not decrypt with this KDC\'s key for ' +
      'the service it names.',
    spec: 'KRB_AP_ERR_BAD_INTEGRITY (31)' },
  { code: 'STS-KRB-0030',
    summary: 'A TGS-REQ\'s Authenticator did not decrypt with the ticket\'s ' +
      'session key.',
    spec: 'KRB_AP_ERR_BAD_INTEGRITY (31)' },
  { code: 'STS-KRB-0031',
    summary: 'A TGS-REQ\'s Authenticator and ticket name different clients.',
    spec: 'KRB_AP_ERR_BADMATCH (36)' },
  { code: 'STS-KRB-0032',
    summary: 'A TGS-REQ presented an expired ticket.',
    spec: 'KRB_AP_ERR_TKT_EXPIRED (32)' },
  { code: 'STS-KRB-0033',
    summary: 'A TGS-REQ presented a ticket that is not yet valid.',
    spec: 'KRB_AP_ERR_TKT_NYV (33)' },
  { code: 'STS-KRB-0034',
    summary: 'A TGS-REQ was refused because the ticket was authenticated ' +
      'before its client signed out (logout.kerberosSignOut).',
    spec: 'KDC_ERR_TGT_REVOKED (20)' },
  { code: 'STS-KRB-0035',
    summary: 'A TGS-REQ\'s Authenticator clock was outside the KDC\'s ' +
      'clock-skew tolerance.',
    spec: 'KRB_AP_ERR_SKEW (37)' },
  { code: 'STS-KRB-0036',
    summary: 'A TGS-REQ\'s Authenticator carried no checksum over the ' +
      'request body.',
    spec: 'KRB_AP_ERR_INAPP_CKSUM (50)' },
  { code: 'STS-KRB-0037',
    summary: 'A TGS-REQ\'s Authenticator checksum did not match the request ' +
      'body.',
    spec: 'KRB_AP_ERR_INAPP_CKSUM (50)' },
  { code: 'STS-KRB-0038',
    summary: 'A TGS-REQ named a service principal this KDC neither knows nor ' +
      'registers on demand, and no trust refers it elsewhere.',
    spec: 'KDC_ERR_S_PRINCIPAL_UNKNOWN (7)' },
  { code: 'STS-KRB-0039',
    summary: 'The issuance policy refused a service ticket because the ' +
      'client does not hold a role the service requires.',
    spec: 'KDC_ERR_POLICY (12)' },
  { code: 'STS-KRB-0040',
    summary: 'A TGS-REQ was refused because the service and the request ' +
      'share no encryption type.',
    spec: 'KDC_ERR_ETYPE_NOSUPP (14)' },
  { code: 'STS-KRB-0041',
    summary: 'A FORWARDED request was refused because the presented ticket ' +
      'is not forwardable.',
    spec: 'KDC_ERR_BADOPTION (13)' },
  { code: 'STS-KRB-0042',
    summary: 'A FORWARDED request was refused because the client account is ' +
      'flagged NOT_DELEGATED.',
    spec: 'KDC_ERR_BADOPTION (13)' },
  { code: 'STS-KRB-0043',
    summary: 'A RENEW request was refused because the ticket is not ' +
      'renewable.',
    spec: 'KDC_ERR_BADOPTION (13)' },
  { code: 'STS-KRB-0044',
    summary: 'A RENEW request was refused because the renewable ticket ' +
      'carries no renew-till.',
    spec: 'KDC_ERR_BADOPTION (13)' },
  { code: 'STS-KRB-0045',
    summary: 'A RENEW request was refused because the ticket\'s renew-till ' +
      'has passed.',
    spec: 'KRB_AP_ERR_TKT_EXPIRED (32)' },
  { code: 'STS-KRB-0046',
    summary: 'A RENEW request named a different service from the ticket ' +
      'being renewed.',
    spec: 'KDC_ERR_BADOPTION (13)' },
  { code: 'STS-KRB-0047',
    summary: 'The KDC received a Kerberos message that is not a request a ' +
      'KDC answers.',
    spec: 'KRB_AP_ERR_MSG_TYPE (40)' },
  { code: 'STS-KRB-0048',
    summary: 'The KDC could not decode or handle a request.',
    spec: 'KRB_ERR_GENERIC (60)' },
  { code: 'STS-KRB-0049',
    summary: 'A TCP request to the KDC exceeded krb5.maxRequestBytes and the ' +
      'connection was closed.',
    spec: 'connection closed' },
  { code: 'STS-KRB-0050',
    summary: 'A TCP request to the KDC carried a length prefix with the ' +
      'reserved top bit set and the connection was closed.',
    spec: 'connection closed' },
  { code: 'STS-KRB-0051',
    summary: 'The KDC failed to build any reply at all, not even a KRB-ERROR ' +
      '(TCP, UDP or MS-KKDCP).',
    spec: 'TCP connection closed; no UDP datagram; HTTP 500 over ' +
      '/KdcProxy' },
  { code: 'STS-KRB-0052',
    summary: 'The KDC\'s TCP listener failed, usually because its port could ' +
      'not be bound.',
    spec: '' },
  { code: 'STS-KRB-0053',
    summary: 'The KDC\'s UDP listener failed, usually because its port could ' +
      'not be bound.',
    spec: '' },
  { code: 'STS-KRB-0054',
    summary: 'A KDC reply was too large for a UDP datagram, so the client ' +
      'was told to retry over TCP.',
    spec: 'KRB_ERR_RESPONSE_TOO_BIG (52)' },
  { code: 'STS-KRB-0055',
    summary: 'A POST to /KdcProxy carried an empty body.',
    spec: 'HTTP 400' },
  { code: 'STS-KRB-0056',
    summary: 'A POST to /KdcProxy carried a body that does not decode as a ' +
      'KDC-PROXY-MESSAGE.',
    spec: 'HTTP 400' },
  { code: 'STS-KRB-0057',
    summary: 'A POST to /KdcProxy carried a kerb-message too short to be ' +
      'framed.',
    spec: 'HTTP 400' },
  { code: 'STS-KRB-0058',
    summary: 'The service did not start: krb5.enctypes names an encryption ' +
      'type the Kerberos codec does not implement.',
    spec: '' },
  { code: 'STS-KRB-0059',
    summary: 'krb5.servicePrincipal is not a service/host name, so no ' +
      'account was created for the Kerberos acceptor.',
    spec: '' },
  { code: 'STS-KRB-0060',
    summary: 'krb5.servicePassword is empty, so no account was created for ' +
      'the Kerberos acceptor.',
    spec: '' },
  { code: 'STS-KRB-0061',
    summary: 'Product mode refused the published default ' +
      'krb5.servicePassword, so no account was created for the ' +
      'Kerberos acceptor.',
    spec: '' },
  { code: 'STS-KRB-0062',
    summary: 'Product mode refused the published default ' +
      'krb5.krbtgtPassword, so no krbtgt was created and the KDC ' +
      'issues no ticket.',
    spec: '' },
  { code: 'STS-KRB-0063',
    summary: 'The Kerberos acceptor refused a token larger than ' +
      'krb5.serviceMaxTokenBytes.',
    spec: 'KRB_ERR_GENERIC (60)' },
  { code: 'STS-KRB-0064',
    summary: 'The Kerberos acceptor could not decode the GSS ' +
      'InitialContextToken wrapper.',
    spec: 'KRB_ERR_GENERIC (60)' },
  { code: 'STS-KRB-0065',
    summary: 'The Kerberos acceptor was sent a GSS token that is not an ' +
      'AP-REQ.',
    spec: 'KRB_AP_ERR_MSG_TYPE (40)' },
  { code: 'STS-KRB-0066',
    summary: 'The Kerberos acceptor could not decode the AP-REQ.',
    spec: 'KRB_ERR_GENERIC (60)' },
  { code: 'STS-KRB-0067',
    summary: 'The Kerberos acceptor refused a ticket for a service principal ' +
      'it holds no key for.',
    spec: 'KRB_AP_ERR_NOT_US (35)' },
  { code: 'STS-KRB-0068',
    summary: 'The Kerberos acceptor refused a ticket encrypted with a key ' +
      'version it does not hold (a stale keytab).',
    spec: 'KRB_AP_ERR_BADKEYVER (44)' },
  { code: 'STS-KRB-0069',
    summary: 'The ticket presented to the Kerberos acceptor did not decrypt ' +
      'with the service\'s key.',
    spec: 'KRB_AP_ERR_BAD_INTEGRITY (31)' },
  { code: 'STS-KRB-0070',
    summary: 'The Authenticator presented to the Kerberos acceptor did not ' +
      'decrypt with the ticket\'s session key.',
    spec: 'KRB_AP_ERR_BAD_INTEGRITY (31)' },
  { code: 'STS-KRB-0071',
    summary: 'The Authenticator and the ticket presented to the Kerberos ' +
      'acceptor name different clients.',
    spec: 'KRB_AP_ERR_BADMATCH (36)' },
  { code: 'STS-KRB-0072',
    summary: 'The Authenticator presented to the Kerberos acceptor was ' +
      'outside the clock-skew tolerance.',
    spec: 'KRB_AP_ERR_SKEW (37)' },
  { code: 'STS-KRB-0073',
    summary: 'The Kerberos acceptor refused an expired ticket.',
    spec: 'KRB_AP_ERR_TKT_EXPIRED (32)' },
  { code: 'STS-KRB-0074',
    summary: 'The Kerberos acceptor refused a replayed Authenticator.',
    spec: 'KRB_AP_ERR_REPEAT (34)' },
  { code: 'STS-KRB-0075',
    summary: 'The Kerberos acceptor refused a new Authenticator because its ' +
      'replay cache is full of entries still inside the replay ' +
      'window.',
    spec: 'KRB_ERR_GENERIC (60)' },
  { code: 'STS-KRB-0076',
    summary: 'The Authenticator\'s 0x8003 GSS checksum presented to the ' +
      'Kerberos acceptor is malformed.',
    spec: 'KRB_AP_ERR_INAPP_CKSUM (50)' },
  { code: 'STS-KRB-0077',
    summary: 'The Authenticator presented to the Kerberos acceptor carried a ' +
      'checksum type other than 0x8003.',
    spec: 'KRB_AP_ERR_INAPP_CKSUM (50)' },
  { code: 'STS-KRB-0078',
    summary: 'A request to the Kerberos service\'s TCP listener exceeded ' +
      'krb5.serviceMaxTokenBytes and the connection was closed.',
    spec: 'connection closed' },
  { code: 'STS-KRB-0079',
    summary: 'A request to the Kerberos service\'s TCP listener carried a ' +
      'length prefix with the reserved top bit set and the connection ' +
      'was closed.',
    spec: 'connection closed' },
  { code: 'STS-KRB-0080',
    summary: 'The Kerberos service failed to build a reply and closed the ' +
      'connection.',
    spec: 'connection closed' },
  { code: 'STS-KRB-0081',
    summary: 'The Kerberos service\'s TCP listener failed, usually because ' +
      'its port could not be bound.',
    spec: '' },
  { code: 'STS-KRB-0082',
    summary: 'A SPNEGO request carried no Authorization header and was ' +
      'answered with the bare Negotiate challenge.',
    spec: 'HTTP 401 WWW-Authenticate: Negotiate' },
  { code: 'STS-KRB-0083',
    summary: 'A SPNEGO request carried an Authorization header naming a ' +
      'scheme other than Negotiate.',
    spec: 'HTTP 401 WWW-Authenticate: Negotiate' },
  { code: 'STS-KRB-0084',
    summary: 'A SPNEGO request carried Negotiate with an empty token.',
    spec: 'HTTP 401 WWW-Authenticate: Negotiate' },
  { code: 'STS-KRB-0085',
    summary: 'A SPNEGO token was neither a NegToken nor a bare Kerberos ' +
      'token.',
    spec: 'HTTP 401, NegTokenResp negState reject' },
  { code: 'STS-KRB-0086',
    summary: 'A SPNEGO NegTokenInit offered no mechanism this service ' +
      'performs.',
    spec: 'HTTP 401, NegTokenResp negState reject' },
  { code: 'STS-KRB-0087',
    summary: 'A SPNEGO NegTokenInit carried no optimistic mechanism token, ' +
      'so the acceptor asked for one.',
    spec: 'HTTP 401, NegTokenResp negState accept-incomplete' },
  { code: 'STS-KRB-0088',
    summary: 'The SPNEGO mechanism selected is not one this service ' +
      'performs.',
    spec: 'HTTP 401, NegTokenResp negState reject' },
  { code: 'STS-KRB-0089',
    summary: 'The Kerberos acceptor threw while a SPNEGO token was being ' +
      'checked.',
    spec: 'HTTP 401, NegTokenResp negState reject' },
  { code: 'STS-KRB-0090',
    summary: 'A SPNEGO Kerberos AP-REQ was refused without the acceptor ' +
      'naming a more specific condition.',
    spec: 'HTTP 401, NegTokenResp negState reject with a KRB-ERROR' },
  { code: 'STS-KRB-0091',
    summary: 'A SPNEGO mechListMIC did not verify (RFC 4178 section 5).',
    spec: 'HTTP 401, NegTokenResp negState reject' },
  { code: 'STS-KRB-0092',
    summary: 'A SPNEGO exchange required a mechListMIC and none was sent ' +
      '(RFC 4178 section 5).',
    spec: 'HTTP 401, NegTokenResp negState reject' },
  { code: 'STS-KRB-0093',
    summary: 'The SPNEGO acceptor sent request-mic and is waiting for the ' +
      'client\'s mechListMIC.',
    spec: 'HTTP 401, NegTokenResp negState request-mic' },
  { code: 'STS-KRB-0094',
    summary: 'A bare SPNEGO NegTokenResp arrived with no negotiation in ' +
      'progress to continue.',
    spec: 'HTTP 401, NegTokenResp negState reject' },
  { code: 'STS-KRB-0095',
    summary: 'A SPNEGO continuation carried no mechListMIC.',
    spec: 'HTTP 401, NegTokenResp negState reject' },
  { code: 'STS-KRB-0096',
    summary: 'An unhandled failure on /spnego/protected.',
    spec: 'HTTP 500 page' },
  { code: 'STS-KRB-0097',
    summary: 'A SPNEGO sign-in at /authn/spnego was refused because ' +
      'krb5.spnegoAuthentication is off.',
    spec: 'HTTP 403 page' },
  { code: 'STS-KRB-0098',
    summary: 'A valid Kerberos ticket was accepted at /authn/spnego and the ' +
      'issuance policy refused to start a session.',
    spec: 'HTTP 403 page' },
  { code: 'STS-KRB-0099',
    summary: 'An unhandled failure on the SPNEGO sign-in at /authn/spnego.',
    spec: 'HTTP 500 page' },
  // --- stored Kerberos keys: directory people and service principals (2026-09-12)
  { code: 'STS-KRB-0100',
    summary: 'The principal database\'s key source slot was offered ' +
      'something incomplete and refused it whole; no person and no stored ' +
      'service key will be used.',
    spec: '' },
  { code: 'STS-KRB-0101',
    summary: 'A product-mode AS-REQ named a person and this process has no ' +
      'key source (no directory) to read Kerberos keys from.',
    spec: 'KRB-ERROR KDC_ERR_C_PRINCIPAL_UNKNOWN (6)' },
  { code: 'STS-KRB-0102',
    summary: 'A product-mode AS-REQ named a person while krb5.personKeys is ' +
             'off.',
    spec: 'KRB-ERROR KDC_ERR_C_PRINCIPAL_UNKNOWN (6)' },
  { code: 'STS-KRB-0103',
    summary: 'A product-mode AS-REQ named a person who is not in the default ' +
      'trust realm\'s directory.',
    spec: 'KRB-ERROR KDC_ERR_C_PRINCIPAL_UNKNOWN (6)' },
  { code: 'STS-KRB-0104',
    summary: 'A product-mode AS-REQ named a person who has no Kerberos keys, ' +
      'or whose keys were derived from a password they no longer have; they ' +
      'are told to sign in once with the password.',
    spec:
      'KRB-ERROR KDC_ERR_C_PRINCIPAL_UNKNOWN (6) with an e-text saying so' },
  { code: 'STS-KRB-0105',
    summary: 'A person\'s stored Kerberos keys could not be opened (sealed ' +
      'under another key-encryption key, not this service\'s shape, or bound ' +
      'to another name).',
    spec: 'KRB-ERROR KDC_ERR_C_PRINCIPAL_UNKNOWN (6)' },
  { code: 'STS-KRB-0106',
    summary: 'Reading a stored service principal key threw; the configured ' +
      'account, if any, answered instead.',
    spec: '' },
  { code: 'STS-KRB-0107',
    summary: 'Deriving a person\'s Kerberos keys from a password that was ' +
      'just set or verified failed; the sign-in or password change was ' +
      'unaffected.',
    spec: '' },
  { code: 'STS-KRB-0108',
    summary: 'Kerberos key material could not be sealed under the ' +
      'key-encryption key, so it was not stored.',
    spec: '' },
  { code: 'STS-KRB-0109',
    summary: 'Kerberos key material could not be written to the directory ' +
      'entry it belongs on.',
    spec: '' },
  { code: 'STS-KRB-0110',
    summary: 'The Kerberos key register was offered an incomplete directory ' +
      'slot and refused it whole.',
    spec: '' },
  // --- the principal store across a restart and across processes (2026-09-12)
  { code: 'STS-KRB-0111',
    summary: 'A restored or replicated row for a CONFIGURED principal ' +
      'carried configuration (password, salt, etypes, kvno, PAC identity, ' +
      'delegation, description or type) that differs from what the current ' +
      'settings build; the settings were kept and only the runtime state was ' +
      'taken.',
    spec: '' },
  { code: 'STS-KRB-0112',
    summary: 'A restored or replicated principal row was neither configured ' +
      'by this process\'s settings nor made at runtime (auto-created or ' +
      'directory-keyed), so it was not restored: the settings that made it ' +
      'no longer do.',
    spec: '' },
  { code: 'STS-KRB-0113',
    summary: 'A replicated removal named a CONFIGURED principal and was ' +
      'refused; a configured account exists because the settings build it.',
    spec: '' },
  { code: 'STS-KRB-0114',
    summary: 'A restored or replicated runtime-made principal carries a RID ' +
      'another principal in this database already holds; neither was ' +
      'renumbered, and a service authorizing on the PAC cannot tell them ' +
      'apart.',
    spec: '' },
  // --- previous key versions (2026-09-12)
  { code: 'STS-KRB-0115',
    summary: 'A ticket presented in a TGS-REQ (the ticket-granting ticket or ' +
      'an S4U2Proxy evidence ticket) names a key version of a stored-key ' +
      'principal that is neither its current kvno nor a previous version ' +
      'still retained (krb5.retainedKeyVersions, krb5.retainedKeyTtlS), or ' +
      'one retained without that enctype.',
    spec: 'KRB-ERROR KRB_AP_ERR_BADKEYVER (44)' },
  { code: 'STS-KRB-0116',
    summary: 'An Authenticator this process had not seen was already ' +
      'accepted by another process against the same store (the cluster ' +
      'claim, #46) — a replay delivered to a different node.',
    spec: 'KRB-ERROR KRB_AP_ERR_REPEAT (34)' },
  { code: 'STS-KRB-0117',
    summary: 'The cluster claim store could not be asked whether an ' +
      'Authenticator was already accepted, so it was refused rather than ' +
      'accepted unproven.',
    spec: 'KRB-ERROR KRB_ERR_GENERIC (60)' },
  { code: 'STS-KRB-0118',
    summary: 'A KDC request was answered before this node caught up with the ' +
      'other nodes\' committed changes, so a sign-out committed elsewhere in ' +
      'the last moment may not be honoured by it.',
    spec: 'none — logged; the request is answered' },
  // #46 section 5 (2026-09-14): a request-mic continuation spent through a
  // cluster claim in kerberos/spnego_exchange.js.
  { code: 'STS-KRB-0119',
    summary: 'A SPNEGO request-mic continuation was refused because another ' +
      'process of this service had already completed that negotiation.',
    spec: 'RFC 4178 section 4.2.2, a reject NegTokenResp; HTTP 401' },
  { code: 'STS-KRB-0120',
    summary: 'A SPNEGO request-mic continuation could not be proved unspent ' +
      'because the store that records completed negotiations could not be ' +
      'asked; it was refused (fail closed).',
    spec: 'RFC 4178 section 4.2.2, a reject NegTokenResp; HTTP 401' },
  { code: 'STS-KRB-0121',
    summary: 'A TGS-REQ named a realm this KDC does not serve. Until ' +
      '2026-09-15 such a request was answered as the default realm.',
    spec: 'KDC_ERR_WRONG_REALM (68)' },
  { code: 'STS-KRB-0122',
    summary: 'A KDC request sent to a trust realm\'s own ' +
      '/realm/<id>/KdcProxy named a Kerberos realm that realm does not ' +
      'serve (another ' +
      'realm\'s name, or one whose Kerberos is off).',
    spec: 'KDC_ERR_WRONG_REALM (68)' },
  { code: 'STS-KRB-0123',
    summary: 'Kerberos was turned on for a trust realm that has no ' +
      'krb5.realm of its own.',
    spec: 'none (a refused administrative change)' },
  { code: 'STS-KRB-0124',
    summary: 'A trust realm was given a krb5.realm another realm already ' +
      'answers to (another realm\'s, the default realm\'s, or ' +
      'krb5.trustedRealm), compared without regard to case.',
    spec: 'none (a refused administrative change)' },
  { code: 'STS-KRB-0125',
    summary: 'A trust realm\'s krb5.realm was changed or cleared while its ' +
      'Kerberos was on.',
    spec: 'none (a refused administrative change)' },
  { code: 'STS-KRB-0126',
    summary: 'The acceptor was presented a ticket for a Kerberos realm the ' +
      'trust realm it was reached in does not serve.',
    spec: 'KRB_AP_ERR_NOT_US (35); over SPNEGO, HTTP 401' },
  { code: 'STS-KRB-0127',
    summary: 'Two trust realms answer to one Kerberos realm name (a restored ' +
      'or replicated realm the registry did not re-judge), so the KDC routes ' +
      'that name to the first and not the second.',
    spec: 'none (logged when the router finds it)' },
  { code: 'STS-KRB-0128',
    summary: 'A Kerberos key act — creating, rotating, deleting or clearing a ' +
      'stored key — was asked of a trust realm that has no KDC, so there is ' +
      'no principal for the key to belong to.',
    spec: 'HTTP 400 { ok: false, errors } / 303 with error=' },
  // ===== LDAP ==============================================================
  { code: 'STS-LDAP-0001',
    summary: 'An LDAP simple bind presented the reserved password this ' +
      'service refuses in every protocol.',
    spec: 'LDAP invalidCredentials (49)' },
  { code: 'STS-LDAP-0002',
    summary: 'An LDAP simple bind was refused by the password verifier ' +
      '(product mode). The verifier\'s own STS-AUTHN code is recorded ' +
      'instead where it gave one.',
    spec: 'LDAP invalidCredentials (49)' },
  { code: 'STS-LDAP-0003',
    summary: 'An LDAP add, rename or search named a DN outside this ' +
      'directory\'s naming context.',
    spec: 'LDAP noSuchObject (32)' },
  { code: 'STS-LDAP-0004',
    summary: 'An entry could not be created because one already exists at ' +
      'that DN (LDAP add or rename, or a group create).',
    spec: 'LDAP entryAlreadyExists (68); a console/SCIM refusal elsewhere' },
  { code: 'STS-LDAP-0005',
    summary: 'A person could not be created because another entry in ' +
      'ou=users already holds that username (one entry per person).',
    spec: 'LDAP entryAlreadyExists (68); a console/SCIM refusal elsewhere' },
  { code: 'STS-LDAP-0006',
    summary: 'An entry could not be written because its parent container ' +
      'does not exist in this realm.',
    spec: 'LDAP noSuchObject (32); a console/SCIM refusal elsewhere' },
  { code: 'STS-LDAP-0007',
    summary: 'The directory holds its maximum number of entries ' +
      '(ldap.maxEntries), so an entry was not created.',
    spec: 'LDAP adminLimitExceeded (11) on an add; a console/SCIM ' +
      'refusal, or nothing, elsewhere' },
  { code: 'STS-LDAP-0008',
    summary: 'An LDAP add or modify carried an attribute value containing a ' +
      'NUL byte.',
    spec: 'LDAP invalidAttributeSyntax (21)' },
  { code: 'STS-LDAP-0009',
    summary: 'An LDAP write tried to set pwdHistory or pwdChangedTime, which ' +
      'the password policy maintains (product mode).',
    spec: 'LDAP constraintViolation (19)' },
  { code: 'STS-LDAP-0010',
    summary: 'An LDAP write would have left an entry holding more than one ' +
      'userPassword value.',
    spec: 'LDAP constraintViolation (19)' },
  { code: 'STS-LDAP-0011',
    summary: 'An LDAP write supplied a pre-hashed userPassword in product ' +
      'mode, which cannot be checked against the password policy.',
    spec: 'LDAP constraintViolation (19)' },
  { code: 'STS-LDAP-0012',
    summary: 'A userPassword written over LDAP was refused by the password ' +
      'policy. The policy\'s own STS-AUTHN code is recorded instead ' +
      'where it gave one.',
    spec: 'LDAP constraintViolation (19)' },
  { code: 'STS-LDAP-0013',
    summary: 'An operation named an entry that does not exist (LDAP delete, ' +
      'modify, rename, compare or search base; or a SCIM/console ' +
      'delete).',
    spec: 'LDAP noSuchObject (32); a SCIM 404 elsewhere' },
  { code: 'STS-LDAP-0014',
    summary: 'An entry could not be deleted or renamed because other entries ' +
      'sit beneath it.',
    spec: 'LDAP notAllowedOnNonLeaf (66); a SCIM 400 elsewhere' },
  { code: 'STS-LDAP-0015',
    summary: 'An LDAP modify carried no changes.',
    spec: 'LDAP protocolError (2)' },
  { code: 'STS-LDAP-0016',
    summary: 'An LDAP modify named a change operation other than add, delete ' +
      'or replace.',
    spec: 'LDAP protocolError (2)' },
  { code: 'STS-LDAP-0017',
    summary: 'An LDAP modify deleted an attribute the entry does not hold.',
    spec: 'LDAP noSuchAttribute (16)' },
  { code: 'STS-LDAP-0018',
    summary: 'An LDAP modifyDN would have moved an entry into another trust ' +
      'realm\'s directory.',
    spec: 'LDAP affectsMultipleDSAs (71)' },
  { code: 'STS-LDAP-0019',
    summary: 'An LDAP compare named an attribute the entry does not hold.',
    spec: 'LDAP noSuchAttribute (16)' },
  { code: 'STS-LDAP-0020',
    summary: 'A one-level or subtree search was based at the root DSE, which ' +
      'only a base search may read.',
    spec: 'LDAP noSuchObject (32)' },
  { code: 'STS-LDAP-0021',
    summary: 'An LDAP search reached its size limit and the answer is ' +
      'incomplete.',
    spec: 'LDAP sizeLimitExceeded (4)' },
  { code: 'STS-LDAP-0022',
    summary: 'A request worker failed an LDAP operation (it died or did not ' +
      'answer), so the operation was not retried in the front ' +
      'process.',
    spec: 'LDAP unavailable (52)' },
  { code: 'STS-LDAP-0023',
    summary: 'A request worker refused an LDAP operation with an error name ' +
      'the front process could not rebuild into an LDAP result.',
    spec: 'LDAP operationsError (1)' },
  { code: 'STS-LDAP-0024',
    summary: 'An LDAP handler run in a request worker finished without ' +
      'sending a result or failing, which would have hung the client.',
    spec: 'LDAP operationsError (1)' },
  { code: 'STS-LDAP-0025',
    summary: 'The plain LDAP listener reported a socket error.',
    spec: '' },
  { code: 'STS-LDAP-0026',
    summary: 'The LDAPS listener reported a socket error.',
    spec: '' },
  { code: 'STS-LDAP-0027',
    summary: 'The plain LDAP listener could not bind its port at startup; ' +
      'the directory does not answer on it.',
    spec: '' },
  { code: 'STS-LDAP-0028',
    summary: 'The LDAPS listener could not bind its port at startup; LDAPS ' +
      'is not offered.',
    spec: '' },
  { code: 'STS-LDAP-0029',
    summary: 'No server certificate was available when the directory loaded, ' +
      'so LDAPS is not offered.',
    spec: '' },
  { code: 'STS-LDAP-0030',
    summary: 'LDAPS could not be re-keyed with the certificate the service ' +
      'ended up with, so it serves the one built at require time.',
    spec: '' },
  { code: 'STS-LDAP-0031',
    summary: 'A certificate authority\'s CRL could not be published into the ' +
      'directory; its ldap:// distribution point fetches nothing.',
    spec: '' },
  { code: 'STS-LDAP-0032',
    summary: 'The account-change observer threw after a directory write; the ' +
      'write stands and the observer\'s event was lost.',
    spec: '' },
  { code: 'STS-LDAP-0033',
    summary: 'The LDAP connection watcher failed, so request workers may ' +
      'hold a stale list of bound connections.',
    spec: '' },
  { code: 'STS-LDAP-0034',
    summary: 'A search filter could not be evaluated against an entry (for ' +
      'example an extensible match), so the entry was treated as not ' +
      'matching.',
    spec: 'none; the entry is simply not returned' },
  { code: 'STS-LDAP-0035',
    summary: 'ou=applications holds its maximum (applications.max), so an ' +
      'application sighting was not recorded.',
    spec: '' },
  { code: 'STS-LDAP-0036',
    summary: 'ou=federations holds its maximum (federation.max), so a ' +
      'federation relationship was not created.',
    spec: '' },
  { code: 'STS-LDAP-0037',
    summary: 'ou=policies holds its maximum (xacml.maxPolicies), so an XACML ' +
      'policy was not created.',
    spec: '' },
  { code: 'STS-LDAP-0038',
    summary: 'ou=roles holds its maximum (roles.maxRoles), so a role was not ' +
      'created.',
    spec: '' },
  { code: 'STS-LDAP-0039',
    summary: 'ou=peps holds its maximum (xacml.maxPeps), so a remote PEP ' +
      'registration was not created.',
    spec: '' },
  { code: 'STS-LDAP-0040',
    summary: 'A credential or consent could not be written because the named ' +
      'identity has no entry in this realm.',
    spec: '' },
  { code: 'STS-LDAP-0041',
    summary: 'roles.remotePepGroup or roles.xacmlUserGroup carries DN ' +
      'syntax, so its group was not seeded.',
    spec: '' },
  { code: 'STS-LDAP-0042',
    summary: 'A user create, group create or membership change named no user ' +
      'or group.',
    spec: 'a console/API or SCIM refusal' },
  { code: 'STS-LDAP-0043',
    summary: 'A user or group create was given a DN where a name was ' +
      'expected.',
    spec: 'a console/API or SCIM refusal' },
  { code: 'STS-LDAP-0044',
    summary: 'A user create was given a decentralized identifier (DID) where ' +
      'a username was expected.',
    spec: 'a console/API or SCIM refusal' },
  { code: 'STS-LDAP-0045',
    summary: 'A user create was given a SPIFFE ID where a username was ' +
      'expected.',
    spec: 'a console/API or SCIM refusal' },
  { code: 'STS-LDAP-0046',
    summary: 'A user or group name carries a character RFC 4514 reserves in ' +
      'a DN, so it cannot name an entry.',
    spec: 'a console/API or SCIM refusal' },
  { code: 'STS-LDAP-0047',
    summary: 'A user create named an attribute that is not in the person ' +
      'catalogue.',
    spec: 'a console/API refusal' },
  { code: 'STS-LDAP-0048',
    summary: 'A write of a person or group named a DN that holds an entry of ' +
      'another kind.',
    spec: 'a SCIM or console/API refusal' },
  { code: 'STS-LDAP-0049',
    summary: 'A group membership change named no member.',
    spec: 'a console/API refusal' },
  { code: 'STS-LDAP-0050',
    summary: 'A group membership change named a group that does not exist, ' +
      'or an entry that is not a group.',
    spec: 'a console/API refusal' },
  { code: 'STS-LDAP-0051',
    summary: 'A replicated change to ou=trustAnchors could not be applied to ' +
      'the TLS truststore; the next change or a restart reads it again.',
    spec: '' },
  { code: 'STS-LDAP-0052',
    summary: 'In product mode, an anonymous LDAP connection asked to add, ' +
      'modify, rename or delete an entry.',
    spec: 'LDAP result code 50, insufficientAccessRights' },
  { code: 'STS-LDAP-0053',
    summary: 'In product mode, a bound LDAP connection that does not hold ' +
      'Admin Write asked to add, rename or delete an entry, or to modify ' +
      'an entry other than its own.',
    spec: 'LDAP result code 50, insufficientAccessRights' },
  { code: 'STS-LDAP-0054',
    summary: 'In product mode, a person asked to change an attribute on ' +
      'their own entry that ldap.selfWritableAttributes does not name.',
    spec: 'LDAP result code 50, insufficientAccessRights' },
  { code: 'STS-LDAP-0070',
    summary: 'In product mode, an anonymous LDAP bind (no DN) was refused; a ' +
      'bind as somebody is required.',
    spec: 'LDAP result code 48, inappropriateAuthentication' },
  { code: 'STS-LDAP-0071',
    summary: 'In product mode, a bind was made on the plain LDAP listener ' +
      'and refused before its password was read; binds require LDAPS.',
    spec: 'LDAP result code 13, confidentialityRequired' },
  { code: 'STS-LDAP-0072',
    summary: 'In product mode, an unauthenticated bind (a DN with an empty ' +
      'password, RFC 4513 section 5.1.2) was refused.',
    spec: 'LDAP result code 53, unwillingToPerform' },
  { code: 'STS-LDAP-0073',
    summary: 'In product mode, a bind was refused without checking its ' +
      'password because the bind DN or the address has had too many failed ' +
      'binds within the rate-limit window.',
    spec: 'LDAP result code 53, unwillingToPerform' },
  { code: 'STS-LDAP-0074',
    summary: 'In product mode, a search or compare arrived on a connection ' +
      'that has not bound as anybody; the root DSE is the only read allowed ' +
      'before a bind.',
    spec: 'LDAP result code 50, insufficientAccessRights' },
  { code: 'STS-LDAP-0075',
    summary: 'In product mode, a compare named a credential attribute ' +
      '(userPassword, a client secret, a private key, a TOTP or recovery ' +
      'code, an activation token or a Kerberos key), which no reader of ' +
      'the socket may test.',
    spec: 'LDAP result code 50, insufficientAccessRights' },
  { code: 'STS-LDAP-0076',
    summary: 'In product mode, an add or modify named createTimestamp, ' +
      'modifyTimestamp or entryDN, which the directory maintains itself.',
    spec: 'LDAP result code 19, constraintViolation' },
  { code: 'STS-LDAP-0077',
    summary: 'A delete or rename of the default realm\'s bootstrap ' +
      'administrator (admin.bootstrapUsername) was refused — over LDAP or ' +
      'SCIM — because that account cannot be removed.',
    spec: 'LDAP result code 53, unwillingToPerform; SCIM 403' },
  { code: 'STS-LDAP-0078',
    summary: 'A flag of the bootstrap administrator (pwdReset, ' +
      'stsBootstrapAdministrator or stsConsoleClaimedAt) could not be ' +
      'written because the account has no entry in this realm.',
    spec: 'none — logged' },
  { code: 'STS-LDAP-0090',
    summary: 'A person was refused creation under a username that is a ' +
      'subject identifier (urn:uuid: or a bare UUID).',
    spec: 'action result ok:false (console, /admin-api HTTP 400, SCIM 400)' },
  { code: 'STS-LDAP-0091',
    summary: 'No entry was created for an authentication whose identity is ' +
      'a urn:uuid: subject naming nobody in this realm\'s directory.',
    spec: 'none — logged' },
  { code: 'STS-LDAP-0092',
    summary: 'A create was refused because the same DN or username was still ' +
      'being created by another request, on this node or another one, when ' +
      'the create had waited for it as long as it waits.',
    spec: 'LDAP_ENTRY_ALREADY_EXISTS (68); HTTP 409 on SCIM and ' +
      '/admin-api' },
  { code: 'STS-LDAP-0093',
    summary: 'A create was refused because the store that decides whether a ' +
      'DN or username is already being created elsewhere could not be ' +
      'asked (fail closed).',
    spec: 'LDAP_UNAVAILABLE (52); HTTP 503 on /admin-api, 500 on SCIM' },
  { code: 'STS-LDAP-0094',
    summary: 'A bind could not be completed after the shared rate limiter ' +
      'was asked; the bind is answered operationsError.',
    spec: 'RFC 4511 section 4.1.9, operationsError (1)' },
  { code: 'STS-LDAP-0095',
    summary: 'This node\'s bound directory connections could not be read ' +
      'for, or committed to, the cluster connection table; other nodes list ' +
      'what it published last (a sign-out still reaches them by identity).',
    spec: 'none — logged' },
  { code: 'STS-LDAP-0096',
    summary: 'Another node signed an identity out and this node could not ' +
      'close the directory connections bound as it; they may still be open.',
    spec: 'none — logged' },
  // ===== SCIM ==============================================================
  { code: 'STS-SCIM-0001',
    summary: 'A SCIM endpoint (or HOBA key registration) was called while ' +
      'SCIM is turned off (scim.enabled).',
    spec: 'HTTP 501 (SCIM Error; plain JSON on ' +
      '/.well-known/hoba/register)' },
  { code: 'STS-SCIM-0002',
    summary: 'A SCIM request body was not JSON.',
    spec: 'SCIM invalidSyntax (HTTP 400)' },
  { code: 'STS-SCIM-0003',
    summary: 'A SCIM request body was refused by the document safety check ' +
      '(a polluting key, too deep or too many members) before scimmy ' +
      'coerced it.',
    spec: 'SCIM invalidSyntax (HTTP 400)' },
  { code: 'STS-SCIM-0004',
    summary: 'A SCIM filter, attributes, excludedAttributes, sortBy or ' +
      'sortOrder parameter was longer than the limit.',
    spec: 'SCIM invalidFilter (HTTP 400)' },
  { code: 'STS-SCIM-0005',
    summary: 'A SCIM startIndex or count was not an integer.',
    spec: 'SCIM invalidValue (HTTP 400)' },
  { code: 'STS-SCIM-0006',
    summary: 'A SCIM filter could not be evaluated against the resources ' +
      'here.',
    spec: 'SCIM invalidFilter (HTTP 400)' },
  { code: 'STS-SCIM-0007',
    summary: 'A SCIM User request named an id with no person entry under ' +
      'ou=users.',
    spec: 'HTTP 404 (SCIM Error)' },
  { code: 'STS-SCIM-0008',
    summary: 'A SCIM User create or replace used the reserved userName this ' +
      'service refuses on purpose.',
    spec: 'SCIM invalidValue (HTTP 400)' },
  { code: 'STS-SCIM-0009',
    summary: 'The directory refused a SCIM User create for a reason it did ' +
      'not name with a code of its own.',
    spec: 'SCIM uniqueness (HTTP 409) or invalidValue (HTTP 400)' },
  { code: 'STS-SCIM-0010',
    summary: 'A SCIM User could not be mapped to a directory entry (userName ' +
      'is required).',
    spec: 'SCIM invalidValue (HTTP 400)' },
  { code: 'STS-SCIM-0011',
    summary: 'The directory refused a SCIM User or Group write for a reason ' +
      'it did not name with a code of its own.',
    spec: 'HTTP 500, or SCIM invalidValue (HTTP 400)' },
  { code: 'STS-SCIM-0012',
    summary: 'The directory refused a SCIM User or Group delete for a reason ' +
      'it did not name with a code of its own.',
    spec: 'HTTP 404, or SCIM invalidValue (HTTP 400)' },
  { code: 'STS-SCIM-0013',
    summary: 'A SCIM Group request named an id that is not a group here.',
    spec: 'HTTP 404 (SCIM Error)' },
  { code: 'STS-SCIM-0014',
    summary: 'A SCIM Group could not be mapped to a directory entry ' +
      '(displayName is required).',
    spec: 'SCIM invalidValue (HTTP 400)' },
  { code: 'STS-SCIM-0015',
    summary: '/Me was used by a request that authenticated as nobody, so ' +
      'there is no subject to alias.',
    spec: 'HTTP 501 (SCIM Error)' },
  { code: 'STS-SCIM-0016',
    summary: '/Me was used by a request whose authenticated subject has no ' +
      'entry under ou=users.',
    spec: 'HTTP 404 (SCIM Error)' },
  { code: 'STS-SCIM-0017',
    summary: 'POST /Me was called; the authenticated subject already exists.',
    spec: 'HTTP 501 (SCIM Error)' },
  { code: 'STS-SCIM-0018',
    summary: 'A SCIM .search body did not carry the SearchRequest schema ' +
      'URN.',
    spec: 'SCIM invalidSyntax (HTTP 400)' },
  { code: 'STS-SCIM-0019',
    summary: 'A SCIM BulkRequest was larger than the advertised maximum ' +
      'payload size (scim.bulkMaxPayloadSize).',
    spec: 'HTTP 413 (SCIM Error)' },
  { code: 'STS-SCIM-0020',
    summary: 'A SCIM handler threw something that is not a SCIM error — a ' +
      'defect in this service.',
    spec: 'HTTP 500 (SCIM Error)' },
  { code: 'STS-SCIM-0021',
    summary: 'A SCIM request was refused inside the scimmy library itself ' +
      '(schema coercion, filter parsing, Bulk limits, or a handler ' +
      'error scimmy flattened to 404).',
    spec: 'SCIM Error (HTTP 4xx) as scimmy chose it' },
  { code: 'STS-SCIM-0022',
    summary: 'A SCIM request failed inside the scimmy library itself with a ' +
      'server error.',
    spec: 'SCIM Error (HTTP 5xx)' },
  { code: 'STS-SCIM-0023',
    summary: 'A HOBA key registration was refused for a reason scim_auth.js ' +
      'did not name with a code.',
    spec: 'HTTP 4xx/5xx JSON on /.well-known/hoba/register' },
  { code: 'STS-SCIM-0029',
    summary: 'The SCIM authentication gate refused a request for a reason it ' +
      'did not name with a code.',
    spec: 'HTTP 401 or 403 (SCIM Error)' },
  { code: 'STS-SCIM-0030',
    summary: 'A SCIM Bearer or DPoP access token was refused by the shared ' +
      'access-token check for a reason it did not name with a code.',
    spec: 'HTTP 401 (SCIM Error) with the check\'s ' +
      'WWW-Authenticate/DPoP-Nonce headers' },
  { code: 'STS-SCIM-0031',
    summary: 'A SCIM access token was not issued by this service, or its ' +
      'signature did not verify.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0032',
    summary: 'A token presented to SCIM is not an access token (its typ is ' +
      'not Bearer).',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0033',
    summary: 'A SCIM access token has been revoked.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0034',
    summary: 'A SCIM HTTP Basic credential was not base64.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0035',
    summary: 'A SCIM HTTP Basic credential carried no colon between user-id ' +
      'and password.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0036',
    summary: 'A SCIM HTTP Basic credential named an empty username.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0037',
    summary: 'A SCIM HTTP Basic password was refused by the verifier for a ' +
      'reason it did not name with a code of its own.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0038',
    summary: 'A SCIM Digest credential set userhash=true, which this server ' +
      'does not support.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0039',
    summary: 'A SCIM Digest credential named an algorithm this server does ' +
      'not offer (or MD5 while scim.digestMd5 is off).',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0040',
    summary: 'A SCIM Digest credential asked for a qop other than auth.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0041',
    summary: 'A SCIM Digest credential was missing username, nonce or ' +
      'response.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0042',
    summary: 'A SCIM Digest credential named a nonce this server did not ' +
      'issue or has forgotten.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate stale=true)' },
  { code: 'STS-SCIM-0043',
    summary: 'A SCIM Digest credential named a nonce older than ' +
      'scim.digestNonceSeconds.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate stale=true)' },
  { code: 'STS-SCIM-0044',
    summary: 'A SCIM Digest credential with qop=auth carried no nc or no ' +
      'cnonce.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0045',
    summary: 'A SCIM Digest nonce count was replayed.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0046',
    summary: 'The uri in a SCIM Digest credential did not match the ' +
      'request-target.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0047',
    summary: 'A SCIM Digest response hash did not match (wrong password).',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0048',
    summary: 'A SCIM HOBA credential\'s result was not four fields.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0049',
    summary: 'A SCIM HOBA credential\'s signature field was not base64url.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0050',
    summary: 'A SCIM HOBA credential named a challenge this server did not ' +
      'issue or has forgotten.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0051',
    summary: 'A SCIM HOBA credential named a challenge older than ' +
      'scim.hobaMaxAgeSeconds.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0052',
    summary: 'A SCIM HOBA credential (key id, challenge and nonce) was ' +
      'replayed.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0053',
    summary: 'A SCIM HOBA credential named a key id with no registered ' +
      'public key.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0054',
    summary: 'The HOBA public key stored for a key id could not be read back ' +
      '— a broken registration in the directory.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0055',
    summary: 'A SCIM HOBA signature did not verify against the registered ' +
      'key.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0056',
    summary: 'A SCIM request presented HTTP Digest in product mode, where ' +
      'Digest is not offered.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0057',
    summary: 'A SCIM request presented a credential in a scheme this service ' +
      'does not offer (or has turned off).',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0058',
    summary: 'A SCIM request that requires authentication presented no ' +
      'credential.',
    spec: 'HTTP 401 (SCIM Error, WWW-Authenticate)' },
  { code: 'STS-SCIM-0059',
    summary: 'A SCIM access token lacked the scim:read or scim:write scope ' +
      'the operation needs.',
    spec: 'HTTP 403 (SCIM Error), WWW-Authenticate ' +
      'error=insufficient_scope' },
  { code: 'STS-SCIM-0060',
    summary: 'The access policy refused an authenticated SCIM request, for a ' +
      'reason it did not name with a code of its own.',
    spec: 'HTTP 403 (SCIM Error)' },
  { code: 'STS-SCIM-0061',
    summary: 'A session could not be recorded for an accepted SCIM ' +
      'credential; the request went ahead.',
    spec: '' },
  { code: 'STS-SCIM-0062',
    summary: 'An accepted SCIM credential could not be recorded at the ' +
      'authentication funnel; the request went ahead.',
    spec: '' },
  { code: 'STS-SCIM-0063',
    summary: 'A HOBA key registration arrived while HOBA is turned off ' +
      '(scim.authHoba).',
    spec: 'HTTP 501 JSON' },
  { code: 'STS-SCIM-0064',
    summary: 'A HOBA key registration carried no pub parameter.',
    spec: 'HTTP 400 JSON' },
  { code: 'STS-SCIM-0065',
    summary: 'A HOBA key registration\'s public key could not be read.',
    spec: 'HTTP 400 JSON' },
  { code: 'STS-SCIM-0066',
    summary: 'A HOBA key registration offered a key that is not RSA.',
    spec: 'HTTP 400 JSON' },
  { code: 'STS-SCIM-0067',
    summary: 'A HOBA key registration\'s kid contained a full stop or ' +
      'whitespace.',
    spec: 'HTTP 400 JSON' },
  { code: 'STS-SCIM-0068',
    summary: 'A HOBA key registration named nobody and came from no ' +
      'signed-in session.',
    spec: 'HTTP 400 JSON' },
  { code: 'STS-SCIM-0069',
    summary: 'Outside development mode, a HOBA key registration for an ' +
      'existing account came from somebody not signed in as that ' +
      'account.',
    spec: 'HTTP 403 JSON' },
  { code: 'STS-SCIM-0070',
    summary: 'Outside development mode, a HOBA key registration named an ' +
      'account that does not exist, and none is created.',
    spec: 'HTTP 404 JSON' },
  { code: 'STS-SCIM-0071',
    summary: 'A HOBA key registration\'s kid is already registered to ' +
      'another account.',
    spec: 'HTTP 409 JSON' },
  { code: 'STS-SCIM-0072',
    summary: 'The directory refused to create the account a HOBA key ' +
      'registration named, for a reason it did not name with a code ' +
      'of its own.',
    spec: 'HTTP 409 or 400 JSON' },
  { code: 'STS-SCIM-0073',
    summary: 'The account a HOBA key registration created could not be read ' +
      'back.',
    spec: 'HTTP 500 JSON' },
  { code: 'STS-SCIM-0074',
    summary: 'A HOBA public key could not be written onto the account\'s ' +
      'entry, for a reason the directory did not name with a code of ' +
      'its own.',
    spec: 'HTTP 507 or 400 JSON' },
  { code: 'STS-SCIM-0075',
    summary: 'A SCIM error carried an HTTP status or scimType RFC 7644 ' +
      'section 3.12 does not allow, which is a defect in this service; it ' +
      'was sent as 500 rather than ending the process.',
    spec: 'HTTP 500 (SCIM Error)' },
  // #46 section 5 (2026-09-14): a Digest nonce count and a HOBA signature
  // spent through a cluster claim in `authenticateSpent()`.
  { code: 'STS-SCIM-0076',
    summary: 'An HTTP Digest credential was refused because its nonce count ' +
      'had already been accepted with that nonce by another process of ' +
      'this service (a replay).',
    spec: 'RFC 7616 section 3.4; HTTP 401 with a fresh challenge' },
  { code: 'STS-SCIM-0077',
    summary: 'A HOBA credential was refused because the same key id, ' +
      'challenge and nonce had already been accepted by another process of ' +
      'this service (a replay).',
    spec: 'RFC 7486 section 6; HTTP 401 with a fresh challenge' },
  { code: 'STS-SCIM-0078',
    summary: 'A Digest or HOBA credential could not be proved unspent because ' +
      'the store that records spent credentials could not be asked; it was ' +
      'refused (fail closed).',
    spec: 'HTTP 500 (SCIM Error)' },
  // ===== SPIFFE ============================================================
  { code: 'STS-SPIFFE-0001',
    summary: 'A SPIFFE gRPC handler failed with something that was not a ' +
      'gRPC status, which is a defect in this service (or the request ' +
      'worker running the method failed) rather than a problem with ' +
      'the call.',
    spec: 'gRPC UNKNOWN' },
  { code: 'STS-SPIFFE-0002',
    summary: 'SPIFFE is turned off in this realm (spiffe.enabled), so the ' +
      'call or the bundle fetch was refused.',
    spec: 'gRPC UNAVAILABLE; HTTP 404 at the bundle endpoint' },
  { code: 'STS-SPIFFE-0003',
    summary: 'A Workload API call did not carry the workload.spiffe.io: true ' +
      'metadata header the Workload Endpoint specification requires.',
    spec: 'gRPC INVALID_ARGUMENT' },
  { code: 'STS-SPIFFE-0004',
    summary: 'spiffe_auth.js named a gRPC status grpc-js does not have; the ' +
      'call was refused with PERMISSION_DENIED instead. A defect in ' +
      'this service.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0005',
    summary: 'The XACML access policy refused a SPIRE Server API call that ' +
      'SPIRE\'s own per-method table allowed.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0006',
    summary: 'A session for an authenticated SPIRE Server API caller could ' +
      'not be recorded; the call itself was unaffected.',
    spec: '' },
  { code: 'STS-SPIFFE-0007',
    summary: 'The verified caller could not be attached to a gRPC call ' +
      'object, so its handler saw no caller detail.',
    spec: '' },
  { code: 'STS-SPIFFE-0008',
    summary: 'Recording a gRPC call in the metrics counters threw and was ' +
      'ignored.',
    spec: '' },
  { code: 'STS-SPIFFE-0009',
    summary: 'A configured SPIFFE socket path exists and is not a socket, so ' +
      'it was left alone and will not bind.',
    spec: '' },
  { code: 'STS-SPIFFE-0010',
    summary: 'The SPIRE Server API Unix socket could not be made mode 0600, ' +
      'so other local users may reach the trusted local entity.',
    spec: '' },
  { code: 'STS-SPIFFE-0011',
    summary: 'A SPIFFE gRPC listener could not bind its address or socket.',
    spec: '' },
  { code: 'STS-SPIFFE-0012',
    summary: 'The SPIRE Server API TLS listener could not be set to ' +
      'request-but-not-require a client certificate, so a caller with ' +
      'no SVID cannot reach AttestAgent over TCP.',
    spec: '' },
  { code: 'STS-SPIFFE-0013',
    summary: 'A SPIRE Server API method has no row in the authorization ' +
      'policy table, so it was refused. A defect in this service.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0014',
    summary: 'A SPIRE Server API method that requires an entity was called ' +
      'by a caller that presented no credential at all.',
    spec: 'gRPC UNAUTHENTICATED' },
  { code: 'STS-SPIFFE-0015',
    summary: 'A SPIRE Server API caller does not hold any entity (local, ' +
      'agent, admin, downstream) the method is allowed to.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0016',
    summary: 'The client certificate presented to the SPIRE Server API ' +
      'carries no URI subjectAltName, so it is not an X509-SVID.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0017',
    summary: 'The client certificate presented to the SPIRE Server API ' +
      'carries more than one URI subjectAltName.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0018',
    summary: 'The URI subjectAltName on the presented client certificate is ' +
      'not a valid SPIFFE ID.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0019',
    summary: 'The client certificate presented to the SPIRE Server API would ' +
      'not parse.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0020',
    summary: 'The presented X509-SVID is not yet valid, allowing for the ' +
      'configured clock skew.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0021',
    summary: 'The presented X509-SVID has expired, allowing for the ' +
      'configured clock skew.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0022',
    summary: 'This service holds no X.509 authority to verify a presented ' +
      'X509-SVID against, which is a fault here.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0023',
    summary: 'A presented X509-SVID was signed by an authority belonging to ' +
      'a different trust domain from the one its SPIFFE ID names.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0024',
    summary: 'No X.509 authority this service holds, its own or federated, ' +
      'signed the presented X509-SVID.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0025',
    summary: 'One of this trust domain\'s own X.509 authority certificates ' +
      'would not parse and cannot verify anything.',
    spec: '' },
  { code: 'STS-SPIFFE-0026',
    summary: 'Recording an accepted SPIFFE credential as an authentication ' +
      'threw and was ignored.',
    spec: '' },
  { code: 'STS-SPIFFE-0027',
    summary: 'A JWT-SVID was requested with no audience (FetchJWTSVID, ' +
      'MintJWTSVID or NewJWTSVID).',
    spec: 'gRPC INVALID_ARGUMENT' },
  { code: 'STS-SPIFFE-0028',
    summary: 'FetchJWTSVID named a spiffe_id that is not a valid SPIFFE ID.',
    spec: 'gRPC INVALID_ARGUMENT' },
  { code: 'STS-SPIFFE-0029',
    summary: 'A WIT-SVID method was called; this service issues no WIT-SVIDs ' +
      'and holds no WIT authority.',
    spec: 'gRPC UNIMPLEMENTED' },
  { code: 'STS-SPIFFE-0030',
    summary: 'A held-open Workload API stream could not be re-sent its ' +
      'rotated SVIDs or bundles; the next rotation is still tried.',
    spec: '' },
  { code: 'STS-SPIFFE-0031',
    summary: 'ValidateJWTSVID was given no JWT-SVID.',
    spec: 'gRPC INVALID_ARGUMENT' },
  { code: 'STS-SPIFFE-0032',
    summary: 'ValidateJWTSVID was given no audience to validate against.',
    spec: 'gRPC INVALID_ARGUMENT' },
  { code: 'STS-SPIFFE-0033',
    summary: 'The JWT-SVID given to ValidateJWTSVID is not a JWT.',
    spec: 'gRPC INVALID_ARGUMENT' },
  { code: 'STS-SPIFFE-0034',
    summary: 'The sub claim of the JWT-SVID given to ValidateJWTSVID is not ' +
      'a valid SPIFFE ID.',
    spec: 'gRPC INVALID_ARGUMENT' },
  { code: 'STS-SPIFFE-0035',
    summary: 'This service holds no JWT bundle for the trust domain a ' +
      'JWT-SVID names, so it cannot be validated.',
    spec: 'gRPC INVALID_ARGUMENT' },
  { code: 'STS-SPIFFE-0036',
    summary: 'No key in the trust domain\'s JWT bundle has the kid a ' +
      'JWT-SVID names.',
    spec: 'gRPC INVALID_ARGUMENT' },
  { code: 'STS-SPIFFE-0037',
    summary: 'A JWT-SVID did not verify: its signature, expiry or audience ' +
      'was wrong.',
    spec: 'gRPC INVALID_ARGUMENT' },
  { code: 'STS-SPIFFE-0038',
    summary: 'A verified JWT-SVID\'s subject differs from the one presented; ' +
      'this should be unreachable.',
    spec: 'gRPC INVALID_ARGUMENT' },
  { code: 'STS-SPIFFE-0039',
    summary: 'A federated bundle or federation relationship named a trust ' +
      'domain that is not a valid trust domain name.',
    spec: 'gRPC INVALID_ARGUMENT (per batch item)' },
  { code: 'STS-SPIFFE-0040',
    summary: 'A federated bundle was submitted under a trust domain this ' +
      'service itself serves, in this realm or another.',
    spec: 'gRPC INVALID_ARGUMENT (per batch item)' },
  { code: 'STS-SPIFFE-0041',
    summary: 'A submitted federated bundle is not a well-formed SPIFFE ' +
      'bundle document.',
    spec: 'gRPC INVALID_ARGUMENT (per batch item)' },
  { code: 'STS-SPIFFE-0042',
    summary: 'The realm already holds its maximum number of federated ' +
      'bundles (spiffe.maxFederatedBundles).',
    spec: 'gRPC INVALID_ARGUMENT (per batch item)' },
  { code: 'STS-SPIFFE-0043',
    summary: 'The SPIFFE issuing authority could not be built at startup, so ' +
      'nothing will issue an SVID.',
    spec: '' },
  { code: 'STS-SPIFFE-0044',
    summary: 'An X509-SVID this service had just issued could not be read ' +
      'back for the directory; the SVID itself was unaffected.',
    spec: '' },
  { code: 'STS-SPIFFE-0045',
    summary: 'A certificate in the SPIFFE authority\'s own chain would not ' +
      'parse while its state was being reported.',
    spec: '' },
  { code: 'STS-SPIFFE-0046',
    summary: 'No SPIFFE registration entry has the id the call named.',
    spec: 'gRPC NOT_FOUND (or per batch item)' },
  { code: 'STS-SPIFFE-0047',
    summary: 'The registry refused to create a registration entry in a ' +
      'BatchCreateEntry call (invalid, duplicate, full, or not ' +
      'stored).',
    spec: 'gRPC INVALID_ARGUMENT (per batch item)' },
  { code: 'STS-SPIFFE-0048',
    summary: 'An item of BatchUpdateEntry named no entry id.',
    spec: 'gRPC INVALID_ARGUMENT (per batch item)' },
  { code: 'STS-SPIFFE-0049',
    summary: 'The registry refused a registration entry update in a ' +
      'BatchUpdateEntry call.',
    spec: 'gRPC INVALID_ARGUMENT (per batch item)' },
  { code: 'STS-SPIFFE-0050',
    summary: 'No agent is recorded on this server under the id the call ' +
      'named or the connection carries.',
    spec: 'gRPC NOT_FOUND' },
  { code: 'STS-SPIFFE-0051',
    summary: 'AttestAgent received a challenge_response when this server ' +
      'issues no attestation challenge.',
    spec: 'gRPC INVALID_ARGUMENT' },
  { code: 'STS-SPIFFE-0052',
    summary: 'The agent attesting or renewing is banned on this server.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0053',
    summary: 'A call that signs a certificate signing request carried none ' +
      '(AttestAgent, RenewAgent, MintX509SVID, a BatchNewX509SVID ' +
      'item).',
    spec: 'gRPC INVALID_ARGUMENT (or per batch item)' },
  { code: 'STS-SPIFFE-0054',
    summary: 'A join_token attestation carried an empty token.',
    spec: 'gRPC INVALID_ARGUMENT' },
  { code: 'STS-SPIFFE-0055',
    summary: 'A join token presented at AttestAgent was never issued by this ' +
      'realm, or has already been spent.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0056',
    summary: 'A join token presented at AttestAgent has expired.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0057',
    summary: 'A join token created for a named agent was presented by an ' +
      'attestation producing a different agent.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0058',
    summary: 'RenewAgent was called on a connection that carries no attested ' +
      'agent\'s X509-SVID.',
    spec: 'gRPC UNIMPLEMENTED' },
  { code: 'STS-SPIFFE-0059',
    summary: 'CreateJoinToken was refused because the realm holds ' +
      'spiffe.maxJoinTokens unexpired tokens.',
    spec: 'gRPC RESOURCE_EXHAUSTED' },
  { code: 'STS-SPIFFE-0060',
    summary: 'AppendBundle or PublishJWTAuthority asked this service to add ' +
      'an authority to its own bundle, which it refuses.',
    spec: 'gRPC PERMISSION_DENIED' },
  { code: 'STS-SPIFFE-0061',
    summary: 'No federated bundle or federation relationship is held for the ' +
      'trust domain named.',
    spec: 'gRPC NOT_FOUND (or per batch item); HTTP 404 at ' +
      '/spiffe/federated/{trustDomain}' },
  { code: 'STS-SPIFFE-0062',
    summary: 'A federated bundle or federation relationship for that trust ' +
      'domain already exists.',
    spec: 'gRPC ALREADY_EXISTS (per batch item)' },
  { code: 'STS-SPIFFE-0063',
    summary: 'A federated bundle delete in RESTRICT mode was refused because ' +
      'registration entries still federate with that trust domain.',
    spec: 'gRPC FAILED_PRECONDITION (per batch item)' },
  { code: 'STS-SPIFFE-0064',
    summary: 'The certificate signing request given to MintX509SVID carries ' +
      'no SPIFFE ID in a URI subjectAltName.',
    spec: 'gRPC INVALID_ARGUMENT' },
  { code: 'STS-SPIFFE-0065',
    summary: 'MintJWTSVID was not given the SPIFFE ID to mint for.',
    spec: 'gRPC INVALID_ARGUMENT' },
  { code: 'STS-SPIFFE-0066',
    summary: 'Signing one item\'s certificate signing request in ' +
      'BatchNewX509SVID failed.',
    spec: 'gRPC INVALID_ARGUMENT (per batch item)' },
  { code: 'STS-SPIFFE-0067',
    summary: 'RefreshBundle asked this service to fetch a federated bundle ' +
      'from its recorded endpoint URL, which it never does.',
    spec: 'gRPC UNIMPLEMENTED' },
  { code: 'STS-SPIFFE-0068',
    summary: 'A JWT authority could not be exported as DER for a Bundle ' +
      'message and was sent with empty key material.',
    spec: '' },
  { code: 'STS-SPIFFE-0069',
    summary: 'The SPIFFE bundle endpoint has no trust bundle to serve ' +
      'because the authorities failed to build.',
    spec: 'HTTP 503' },
  { code: 'STS-SPIFFE-0070',
    summary: 'The SPIRE Server API could not be given a TLS identity, so its ' +
      'TCP port bound plain and authenticates nobody.',
    spec: '' },
  { code: 'STS-SPIFFE-0071',
    summary: 'A realm\'s SPIFFE listener was not bound because another realm ' +
      'in this process already answers on that address.',
    spec: '' },
  { code: 'STS-SPIFFE-0072',
    summary: 'A realm\'s SPIFFE issuing authority failed while its listeners ' +
      'were starting; every call there will be refused with the ' +
      'reason.',
    spec: '' },
  { code: 'STS-SPIFFE-0073',
    summary: 'A realm\'s seed SPIFFE registration entries could not be ' +
      'created.',
    spec: '' },
  { code: 'STS-SPIFFE-0074',
    summary: 'The SPIFFE listeners could not be reconciled after a trust ' +
      'realm changed.',
    spec: '' },
  { code: 'STS-SPIFFE-0075',
    summary: 'A join token at AttestAgent could not be proved unspent ' +
      'because the cluster store could not be asked, so the attestation was ' +
      'refused.',
    spec: 'gRPC UNAVAILABLE' },
  { code: 'STS-SPIFFE-0076',
    summary: 'A realm\'s SPIFFE JWT authority or self-signed X.509 authority ' +
      'could not be established once for the cluster, so none was made.',
    spec: 'the SPIFFE call fails as when no authority could be built' },
  // ===== TLS ===============================================================
  { code: 'STS-TLS-0001',
    summary: 'The service did not start: tls.minVersion or tls.ciphers ' +
      'cannot build a TLS context.',
    spec: '' },
  { code: 'STS-TLS-0002',
    summary: 'The service did not start: tls.certificateFile and tls.keyFile ' +
      'must be set together and only one was.',
    spec: '' },
  { code: 'STS-TLS-0003',
    summary: 'The service did not start: the certificate or key named by ' +
      'tls.certificateFile / tls.keyFile could not be read.',
    spec: '' },
  { code: 'STS-TLS-0004',
    summary: 'The service did not start: tls.certificateFile is not a PEM ' +
      'certificate.',
    spec: '' },
  { code: 'STS-TLS-0005',
    summary: 'The service did not start: tls.keyFile is not a readable ' +
      'private key.',
    spec: '' },
  { code: 'STS-TLS-0006',
    summary: 'The service did not start: the key in tls.keyFile does not ' +
      'match the certificate in tls.certificateFile.',
    spec: '' },
  { code: 'STS-TLS-0007',
    summary: 'The trust anchor a request worker was handed does not sign the ' +
      'certificate handed in with it, so no anchor is published.',
    spec: '' },
  { code: 'STS-TLS-0008',
    summary: 'This service\'s Root CA does not sign the chain the TLS ' +
      'listener presents, so no anchor is published.',
    spec: '' },
  { code: 'STS-TLS-0009',
    summary: 'The TLS listener certificate could not be re-issued under the ' +
      'certificate authority this service now holds.',
    spec: '' },
  { code: 'STS-TLS-0010',
    summary: 'The client truststore could not be extended to a listener ' +
      'because it was given something that is not a TLS server.',
    spec: '' },
  { code: 'STS-TLS-0011',
    summary: 'The client truststore could not be applied to a TLS listener, ' +
      'which keeps its previous context.',
    spec: '' },
  { code: 'STS-TLS-0012',
    summary: 'A truststore add found no PEM certificate in what it was sent.',
    spec: 'HTTP 400 (POST /tls/trust)' },
  { code: 'STS-TLS-0013',
    summary: 'A strict truststore add was refused whole because a ' +
      'certificate in it could not be read by OpenSSL.',
    spec: '' },
  { code: 'STS-TLS-0014',
    summary: 'A truststore add stopped because the truststore holds its ' +
      'maximum number of anchors.',
    spec: 'HTTP 400 (POST /tls/trust) when nothing was added' },
  { code: 'STS-TLS-0015',
    summary: 'A truststore remove named something that is not a SHA-256 ' +
      'fingerprint.',
    spec: '' },
  { code: 'STS-TLS-0016',
    summary: 'A truststore remove named an anchor the truststore does not ' +
      'hold.',
    spec: '' },
  { code: 'STS-TLS-0017',
    summary: 'Starting a sign-on session for a verified client certificate ' +
      'threw; the connection was unaffected.',
    spec: '' },
  { code: 'STS-TLS-0018',
    summary: 'Recording a verified client certificate as an authentication ' +
      'threw; the connection was unaffected.',
    spec: '' },
  { code: 'STS-TLS-0019',
    summary: 'The service did not start: tls.trustAnchorsFile could not be ' +
      'read.',
    spec: '' },
  { code: 'STS-TLS-0020',
    summary: 'The service did not start: tls.trustAnchorsFile holds no PEM ' +
      'certificate.',
    spec: '' },
  { code: 'STS-TLS-0021',
    summary: 'The required-client-certificate listener refused a handshake, ' +
      'usually a client certificate missing or not verifying against ' +
      'the truststore.',
    spec: 'TLS handshake failure' },
  { code: 'STS-TLS-0022',
    summary: 'A TLS handshake failed on the optional-client-certificate ' +
      'listener (a version, cipher or non-TLS mismatch).',
    spec: 'TLS handshake failure' },
  { code: 'STS-TLS-0023',
    summary: 'A /tls or /tls/forwarded request carried a format parameter ' +
      'other than json or html.',
    spec: 'HTTP 400' },
  { code: 'STS-TLS-0024',
    summary: 'POST /tls/trust or /tls/trust/clear was refused because ' +
      'product mode does not open the truststore to anybody who can ' +
      'reach the port.',
    spec: 'HTTP 403' },
  { code: 'STS-TLS-0025',
    summary: 'A TLS listener could not bind its port.',
    spec: '' },
  { code: 'STS-TLS-0026',
    summary: 'The TLS listener certificate does not chain to this service\'s ' +
      'Root and re-issuing it produced the same certificate.',
    spec: '' },
  { code: 'STS-TLS-0027',
    summary: 'The runtime trust anchor store was installed without one of ' +
      'its list, write and remove functions, and was refused whole; runtime ' +
      'anchors are not persisted.',
    spec: '' },
  { code: 'STS-TLS-0028',
    summary: 'A runtime trust anchor is in force but could not be written to ' +
      'ou=trustAnchors, so it will not survive a restart.',
    spec: '' },
  { code: 'STS-TLS-0029',
    summary: 'A runtime trust anchor was removed from every listener but ' +
      'could not be removed from ou=trustAnchors, so it will come back on a ' +
      'restart.',
    spec: '' },
  { code: 'STS-TLS-0030',
    summary: 'The stored trust anchors could not be read; the truststore was ' +
      'left as it was.',
    spec: '' },
  { code: 'STS-TLS-0031',
    summary: 'The required-client-certificate listener refused a verified ' +
      'certificate this service issued that is not a TLS client identity ' +
      '(not from a TLS client or enrollment Issuing CA, no clientAuth, or no ' +
      'single urn:sts:person:/application: name).',
    spec: 'HTTP 403 with the connection report' },
  // ===== VC ================================================================
  { code: 'STS-VC-0001',
    summary: 'An oid4vci encryption setting names no content encryption ' +
      '(enc) this issuer implements, so the implemented list is ' +
      'advertised and accepted instead.',
    spec: '' },
  { code: 'STS-VC-0002',
    summary: 'A DID-named credential configuration names a sibling ' +
      'configuration the issuer metadata does not offer, so it is not ' +
      'advertised.',
    spec: '' },
  { code: 'STS-VC-0003',
    summary: 'The Credential Issuer metadata could not be signed, so it was ' +
      'served without signed_metadata.',
    spec: '' },
  { code: 'STS-VC-0004',
    summary: 'The identity JSON-LD context could not be read, so no ' +
      'configured claim is put in the ldp_vc credential being issued.',
    spec: '' },
  { code: 'STS-VC-0005',
    summary: 'A configured claim maps to a JSON-LD term the vendored ' +
      'identity context does not define, so it was left out of an ' +
      'ldp_vc credential.',
    spec: '' },
  { code: 'STS-VC-0006',
    summary: 'A Credential or Deferred Credential Request arrived ' +
      'unencrypted while the issuer requires request encryption.',
    spec: 'invalid_encryption_parameters (HTTP 400)' },
  { code: 'STS-VC-0007',
    summary: 'A plain Credential or Deferred Credential Request body is not ' +
      'JSON.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-VC-0008',
    summary: 'An encrypted (application/jwt) Credential or Deferred ' +
      'Credential Request could not be decrypted or its plaintext is ' +
      'not JSON.',
    spec: 'invalid_encryption_parameters (HTTP 400)' },
  { code: 'STS-VC-0009',
    summary: 'A Credential Request sent both credential_identifier and ' +
      'credential_configuration_id.',
    spec: 'invalid_credential_request (HTTP 400)' },
  { code: 'STS-VC-0010',
    summary: 'A Credential Request used credential_identifier although the ' +
      'token response granted no credential_identifiers.',
    spec: 'invalid_credential_request (HTTP 400)' },
  { code: 'STS-VC-0011',
    summary: 'A Credential Request named a credential_identifier the token ' +
      'response did not grant.',
    spec: 'invalid_credential_request (HTTP 400)' },
  { code: 'STS-VC-0012',
    summary: 'A Credential Request used credential_configuration_id although ' +
      'the token response granted credential_identifiers.',
    spec: 'invalid_credential_request (HTTP 400)' },
  { code: 'STS-VC-0013',
    summary: 'A Credential Request named a credential_configuration_id this ' +
      'issuer does not offer.',
    spec: 'unsupported_credential_type (HTTP 400)' },
  { code: 'STS-VC-0014',
    summary: 'A Credential Request named no credential at all (neither ' +
      'credential_identifier nor credential_configuration_id).',
    spec: 'invalid_credential_request (HTTP 400)' },
  { code: 'STS-VC-0015',
    summary: 'A Credential Request carried no credential_response_encryption ' +
      'while the issuer requires an encrypted response.',
    spec: 'invalid_encryption_parameters (HTTP 400)' },
  { code: 'STS-VC-0016',
    summary: 'A Credential Request\'s credential_response_encryption ' +
      'parameters are unusable (key, alg, enc or zip).',
    spec: 'invalid_encryption_parameters (HTTP 400)' },
  { code: 'STS-VC-0017',
    summary: 'A Credential Request carried no JWT proof of possession.',
    spec: 'invalid_proof (HTTP 400)' },
  { code: 'STS-VC-0018',
    summary: 'A Credential Request carried more proofs than the issuer\'s ' +
      'batch size allows.',
    spec: 'invalid_credential_request (HTTP 400)' },
  { code: 'STS-VC-0019',
    summary: 'A proof of possession in a Credential Request was refused ' +
      '(malformed, wrong typ, alg, audience, iat, nonce, or ' +
      'signature).',
    spec: 'invalid_proof (HTTP 400)' },
  { code: 'STS-VC-0020',
    summary: 'A Deferred Credential Request named a transaction_id this ' +
      'issuer never issued, has expired, or was already redeemed.',
    spec: 'invalid_transaction_id (HTTP 400)' },
  { code: 'STS-VC-0021',
    summary: 'A Notification Request body is not JSON.',
    spec: 'invalid_notification_request (HTTP 400)' },
  { code: 'STS-VC-0022',
    summary: 'A Notification Request named a notification_id this issuer ' +
      'never issued or that has expired.',
    spec: 'invalid_notification_id (HTTP 400)' },
  { code: 'STS-VC-0023',
    summary: 'A Notification Request\'s event is not one of ' +
      'credential_accepted, credential_failure or credential_deleted.',
    spec: 'invalid_notification_request (HTTP 400)' },
  { code: 'STS-VC-0024',
    summary: 'The non-spec notification inspection endpoint was asked for a ' +
      'notification_id that does not exist.',
    spec: 'invalid_notification_id (HTTP 404)' },
  { code: 'STS-VC-0025',
    summary: 'The Credential Offer page\'s query parameters failed input ' +
      'validation.',
    spec: 'HTTP 400 plain text' },
  { code: 'STS-VC-0026',
    summary: 'Where only registered addresses are accepted, the Credential ' +
      'Offer\'s wallet parameter named a URL that is neither ' +
      'oid4vci.walletUrl nor listed in oid4vci.allowedWalletUrls.',
    spec: 'HTTP 400 plain text' },
  { code: 'STS-VC-0027',
    summary: 'A pre-authorized (cross-device or deferred) Credential Offer ' +
      'was requested from a session that continued without signing ' +
      'in, where test controls are closed.',
    spec: 'HTTP 403 plain text' },
  { code: 'STS-VC-0028',
    summary: 'The QR code for a cross-device Credential Offer could not be ' +
      'rendered.',
    spec: 'HTTP 500 plain text' },
  { code: 'STS-VC-0029',
    summary: 'A Credential Offer fetched by reference (credential_offer_uri) ' +
      'does not exist or has expired.',
    spec: 'invalid_request (HTTP 404)' },
  { code: 'STS-VC-0030',
    summary: 'Product mode: a pre-authorized code was spent after reaching ' +
      'oid4vci.txCodeMaxAttempts wrong Transaction Codes.',
    spec: '' },
  { code: 'STS-VC-0031',
    summary: 'A certificate in oid4vp.trustedIssuerCertificates could not be ' +
      'read and is ignored by the Verifier.',
    spec: '' },
  { code: 'STS-VC-0032',
    summary: 'The OID4VP Verifier page\'s or presentation start endpoint\'s ' +
      'query parameters failed input validation.',
    spec: 'HTTP 400 plain text' },
  { code: 'STS-VC-0033',
    summary: 'Where only registered addresses are accepted, the presentation ' +
      'start\'s wallet parameter named a URL that is neither ' +
      'oid4vp.walletUrl nor listed in oid4vp.allowedWalletUrls.',
    spec: 'HTTP 400 plain text' },
  { code: 'STS-VC-0034',
    summary: 'The QR code for a cross-device OID4VP Authorization Request ' +
      'could not be rendered.',
    spec: 'HTTP 500 plain text' },
  { code: 'STS-VC-0035',
    summary: 'An OID4VP Request Object fetched by request_uri does not ' +
      'exist.',
    spec: 'invalid_request (HTTP 404)' },
  { code: 'STS-VC-0036',
    summary: 'An OID4VP Authorization Response was posted with a state for ' +
      'which no Authorization Request is outstanding.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-VC-0037',
    summary: 'The wallet answered an OID4VP Authorization Request with an ' +
      'error response (it declined or could not present).',
    spec: 'HTTP 200 with redirect_uri; the verdict records the wallet\'s ' +
      'error' },
  { code: 'STS-VC-0038',
    summary: 'An OID4VP Authorization Response\'s vp_token is not a JSON ' +
      'object keyed by the DCQL credential query id, or holds no ' +
      'presentation.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-VC-0039',
    summary: 'A presented SD-JWT Disclosure is not base64url-encoded JSON.',
    spec: 'invalid_request (HTTP 400), as part of a refused presentation' },
  { code: 'STS-VC-0040',
    summary: 'A presented SD-JWT Disclosure hashes to a digest the issuer ' +
      'never signed.',
    spec: 'invalid_request (HTTP 400), as part of a refused presentation' },
  { code: 'STS-VC-0041',
    summary: 'A presentation failed one or more of the OID4VP Verifier\'s ' +
      'checks (issuer signature, disclosures, key binding, nonce, ' +
      'audience, validity or requested claims).',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-VC-0042',
    summary: 'The non-spec presentation result endpoint was asked for a ' +
      'state it has no record of.',
    spec: 'invalid_request (HTTP 404)' },
  { code: 'STS-VC-0043',
    summary: 'The key credentials are signed with is not in this realm\'s ' +
      'key set, so the DID document cannot publish it.',
    spec: '' },
  { code: 'STS-VC-0044',
    summary: 'The BBS public key could not be published in the DID document.',
    spec: '' },
  { code: 'STS-VC-0045',
    summary: 'The path-form /did.json was requested for a DID that has no ' +
      'path; did:web resolves it at the well-known location.',
    spec: 'not_found (HTTP 404)' },
  { code: 'STS-VC-0046',
    summary: 'The DID generator was asked for a method other than jwk or ' +
      'web.',
    spec: 'invalid_request (HTTP 400)' },
  { code: 'STS-VC-0047',
    summary: 'The embedded directory threw while being read for a person\'s ' +
      'credential claims; the credential is built without directory ' +
      'values.',
    spec: '' },
  { code: 'STS-VC-0048',
    summary: 'Populating the embedded directory for the current credential ' +
      'claim set threw.',
    spec: '' },
  { code: 'STS-VC-0049',
    summary: 'A pre-authorized code this process still held was already ' +
      'redeemed by another process against the same store (the cluster ' +
      'claim, #46).',
    spec: 'invalid_grant (HTTP 400)' },
  { code: 'STS-VC-0050',
    summary: 'A c_nonce every proof verified against was already spent by ' +
      'another process against the same store (the cluster claim, #46).',
    spec: 'invalid_proof (HTTP 400)' },
  { code: 'STS-VC-0051',
    summary: 'The cluster claim store could not be asked about an OpenID4VCI ' +
      'single-use value — a pre-authorized code, a c_nonce or a Transaction ' +
      'Code attempt — so the request was refused rather than accepted ' +
      'unproven.',
    spec: 'invalid_grant or invalid_proof (HTTP 400)' },
  // ===== SSF ===============================================================
  { code: 'STS-SSF-0001',
    summary: 'A Shared Signals endpoint was called while the family is ' +
      'turned off (ssf.enabled).',
    spec: 'HTTP 501 {err: invalid_request}' },
  { code: 'STS-SSF-0002',
    summary: 'An SSF endpoint was presented an access token that the shared ' +
      'access-token check refused (a DPoP proof, binding, audience or ' +
      'transport rule), and that check named no more specific ' +
      'condition.',
    spec: 'HTTP 401 {err: authentication_failed}, or the shared check\'s ' +
      'own status and headers' },
  { code: 'STS-SSF-0003',
    summary: 'An SSF endpoint was presented an access token this service did ' +
      'not issue, or whose signature does not verify.',
    spec: 'HTTP 401 {err: authentication_failed} with WWW-Authenticate' },
  { code: 'STS-SSF-0004',
    summary: 'An SSF endpoint was presented a token that is not an access ' +
      'token (its typ claim names a refresh token, an ID Token or ' +
      'something else).',
    spec: 'HTTP 401 {err: authentication_failed} with WWW-Authenticate' },
  { code: 'STS-SSF-0005',
    summary: 'An SSF access token lacked the scope the operation needs ' +
      '(ssf:read to read, ssf:write to change a stream).',
    spec: 'HTTP 403 {err: access_denied} with WWW-Authenticate' },
  { code: 'STS-SSF-0006',
    summary: 'HTTP Basic was presented to an SSF endpoint while the scheme ' +
      'is turned off (ssf.authBasic).',
    spec: 'HTTP 401 {err: authentication_failed} with WWW-Authenticate' },
  { code: 'STS-SSF-0007',
    summary: 'An SSF HTTP Basic credential did not decode to user:password.',
    spec: 'HTTP 401 {err: authentication_failed} with WWW-Authenticate' },
  { code: 'STS-SSF-0008',
    summary: 'An SSF HTTP Basic credential carried the reserved password ' +
      'that is always refused, so that a wrong-credential path ' +
      'exists.',
    spec: 'HTTP 401 {err: authentication_failed} with WWW-Authenticate' },
  { code: 'STS-SSF-0009',
    summary: 'An SSF HTTP Basic credential failed password verification ' +
      '(product mode: no such person, a wrong password, or a person ' +
      'with no password).',
    spec: 'HTTP 401 {err: authentication_failed} with WWW-Authenticate' },
  { code: 'STS-SSF-0010',
    summary: 'A protected SSF endpoint was called with no credential at all.',
    spec: 'HTTP 401 {err: authentication_failed} with WWW-Authenticate' },
  { code: 'STS-SSF-0011',
    summary: 'The body of an SSF management, subject, verification or poll ' +
      'request is not JSON.',
    spec: 'HTTP 400 {err: invalid_request}' },
  { code: 'STS-SSF-0012',
    summary: 'A push stream was refused at creation because its delivery ' +
      'endpoint cannot be dialled by this transmitter (not a URL, ' +
      'wrong scheme, plain http with ssf.pushAllowInsecure off, or a ' +
      'host outside ssf.pushAllowedHosts).',
    spec: 'HTTP 400 {err: invalid_request}' },
  { code: 'STS-SSF-0013',
    summary: 'A Stream Configuration was refused at creation (a missing aud, ' +
      'an unsupported delivery method, a malformed member).',
    spec: 'HTTP 400 {err: invalid_request}' },
  { code: 'STS-SSF-0014',
    summary: 'An SSF request named a stream_id this transmitter does not ' +
      'hold.',
    spec: 'HTTP 404 {err: invalid_request}' },
  { code: 'STS-SSF-0015',
    summary: 'A stream update (PUT or PATCH) was refused because the ' +
      'configuration it would produce is invalid.',
    spec: 'HTTP 400 {err: invalid_request}' },
  { code: 'STS-SSF-0016',
    summary: 'A stream status change was refused (an unknown status value or ' +
      'a malformed request).',
    spec: 'HTTP 400 {err: invalid_request}' },
  { code: 'STS-SSF-0017',
    summary: 'An Add Subject request was refused because the subject ' +
      'identifier is invalid (RFC 9493 format or member rules, or a ' +
      'missing critical member).',
    spec: 'HTTP 400 {err: invalid_request}' },
  { code: 'STS-SSF-0018',
    summary: 'A Remove Subject request was refused because the subject ' +
      'identifier is invalid.',
    spec: 'HTTP 400 {err: invalid_request}' },
  { code: 'STS-SSF-0019',
    summary: 'A verification request came sooner than the stream\'s ' +
      'min_verification_interval while ssf.verificationRateLimit is ' +
      'on.',
    spec: 'HTTP 429 {err: invalid_request} with Retry-After' },
  { code: 'STS-SSF-0020',
    summary: 'A verification request was answered with a refusal because the ' +
      'verification event could not be transmitted or delivered; the ' +
      'transmission\'s own audit row names the cause.',
    spec: 'HTTP 400 {err: invalid_request}' },
  { code: 'STS-SSF-0021',
    summary: 'A poll request named a stream that delivers by push, so there ' +
      'is nothing to collect.',
    spec: 'HTTP 400 {err: invalid_request}' },
  { code: 'STS-SSF-0022',
    summary: 'A Security Event Token was pushed at /ssf/receive while this ' +
      'service is not accepting pushed events (ssf.receiveEnabled).',
    spec: 'HTTP 501 {err: invalid_request}' },
  { code: 'STS-SSF-0023',
    summary: 'A push at /ssf/receive carried an empty body.',
    spec: 'HTTP 400 {err: invalid_request}' },
  { code: 'STS-SSF-0024',
    summary: 'A Security Event Token pushed at /ssf/receive did not verify ' +
      'while ssf.receiveRequireSignature is on.',
    spec: 'HTTP 400 {err: invalid_key}' },
  { code: 'STS-SSF-0025',
    summary: 'A Security Event Token pushed at /ssf/receive could not be ' +
      'read as a SET; it was recorded anyway.',
    spec: 'HTTP 400 {err: invalid_request}' },
  { code: 'STS-SSF-0026',
    summary: 'An event was not transmitted on a stream because the stream ' +
      'does not deliver that event type.',
    spec: '' },
  { code: 'STS-SSF-0027',
    summary: 'An event was not transmitted because its payload fails the ' +
      'event type\'s member rules.',
    spec: '' },
  { code: 'STS-SSF-0028',
    summary: 'An event whose type requires a subject was not transmitted ' +
      'because it carried none.',
    spec: '' },
  { code: 'STS-SSF-0029',
    summary: 'An event was not transmitted on a stream because its subject ' +
      'is not one the stream covers.',
    spec: '' },
  { code: 'STS-SSF-0030',
    summary: 'A built and signed Security Event Token was not queued on its ' +
      'stream (usually because the stream is disabled).',
    spec: '' },
  { code: 'STS-SSF-0031',
    summary: 'A Security Event Token could not be signed, or its delivery ' +
      'failed with an exception, so the event was not transmitted. ' +
      'Check ssf.signingAlgorithm.',
    spec: '' },
  { code: 'STS-SSF-0032',
    summary: 'An RFC 8935 push of a Security Event Token failed for a reason ' +
      'the push did not classify.',
    spec: '' },
  { code: 'STS-SSF-0033',
    summary: 'A push was not made because push delivery is turned off ' +
      '(ssf.pushDelivery); the event stays on the queue.',
    spec: '' },
  { code: 'STS-SSF-0034',
    summary: 'A push was not made because the stream\'s delivery endpoint ' +
      'may not be dialled (not a URL, wrong scheme, plain http, or a host ' +
      'outside ssf.pushAllowedHosts).',
    spec: '' },
  { code: 'STS-SSF-0035',
    summary: 'A push to one of this service\'s own receivers was not made ' +
      'because this service\'s TLS certificate could not be read to ' +
      'pin the connection.',
    spec: '' },
  { code: 'STS-SSF-0036',
    summary: 'A receiver answered a push with a redirect, which is not ' +
      'followed.',
    spec: '' },
  { code: 'STS-SSF-0037',
    summary: 'A receiver answered a push with a body larger than ' +
      'ssf.pushMaxResponseBytes.',
    spec: '' },
  { code: 'STS-SSF-0038',
    summary: 'A receiver refused a pushed Security Event Token with an RFC ' +
      '8935 error (400 with err and description).',
    spec: '' },
  { code: 'STS-SSF-0039',
    summary: 'A receiver answered a push with a status that is neither ' +
      'success nor an RFC 8935 refusal (a 5xx, a 429, or another ' +
      'failure status).',
    spec: '' },
  { code: 'STS-SSF-0040',
    summary: 'The response to a push failed while it was being read.',
    spec: '' },
  { code: 'STS-SSF-0041',
    summary: 'A push request could not be built (a malformed request ' +
      'option).',
    spec: '' },
  { code: 'STS-SSF-0042',
    summary: 'A receiver did not answer a push within ssf.pushTimeoutMs.',
    spec: '' },
  { code: 'STS-SSF-0043',
    summary: 'A push could not connect to the receiver (DNS, connection ' +
      'refused, reset).',
    spec: '' },
  { code: 'STS-SSF-0044',
    summary: 'A push was refused at TLS because nothing here trusts the ' +
      'receiver\'s certificate.',
    spec: '' },
  { code: 'STS-SSF-0045',
    summary: 'A Shared Signals console or management API action named a ' +
      'stream this transmitter does not hold.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from ' +
      '/admin-api' },
  { code: 'STS-SSF-0046',
    summary: 'A stream status change from the console or management API was ' +
      'refused (an unknown status value).',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from ' +
      '/admin-api' },
  { code: 'STS-SSF-0047',
    summary: 'An event emitted by hand from the SSF, CAEP or RISC console or ' +
      'management API carried a payload that is not JSON.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from ' +
      '/admin-api' },
  { code: 'STS-SSF-0048',
    summary: 'An event transmitted by hand from the SSF console or ' +
      'management API carried a subject that is not JSON.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from ' +
      '/admin-api' },
  { code: 'STS-SSF-0049',
    summary: 'The Shared Signals console or management API was asked for an ' +
      'action it does not have.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors: [Unknown ' +
      'action ...]} from /admin-api' },
  { code: 'STS-SSF-0050',
    summary: 'A CAEP event emitted by hand named a type that is not one of ' +
      'CAEP\'s eight.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from ' +
      '/admin-api' },
  { code: 'STS-SSF-0051',
    summary: 'A CAEP event emitted by hand named a session the CAEP register ' +
      'does not track.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from ' +
      '/admin-api' },
  { code: 'STS-SSF-0052',
    summary: 'A CAEP or RISC event emitted by hand has a payload that fails ' +
      'the event type\'s member rules.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from ' +
      '/admin-api' },
  { code: 'STS-SSF-0053',
    summary: 'A CAEP event emitted by hand was refused by the session ' +
      'register\'s state machine (a session-presented about a revoked ' +
      'session).',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from ' +
      '/admin-api' },
  { code: 'STS-SSF-0054',
    summary: 'A CAEP session reset named a session the register does not ' +
      'track.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from ' +
      '/admin-api' },
  { code: 'STS-SSF-0055',
    summary: 'The CAEP console or management API was asked for an action it ' +
      'does not have.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors: [Unknown ' +
      'action ...]} from /admin-api' },
  { code: 'STS-SSF-0056',
    summary: 'An automatic CAEP emission (a session starting, being ' +
      'presented or ending) failed with an exception.',
    spec: '' },
  { code: 'STS-SSF-0057',
    summary: 'A RISC event emitted by hand named a type that is not one of ' +
      'RISC\'s fourteen.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from ' +
      '/admin-api' },
  { code: 'STS-SSF-0058',
    summary: 'A RISC event emitted by hand named no account.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from ' +
      '/admin-api' },
  { code: 'STS-SSF-0059',
    summary: 'A RISC event emitted by hand was refused by the account ' +
      'register\'s state machine (something other than account-purged ' +
      'about a purged account).',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from ' +
      '/admin-api' },
  { code: 'STS-SSF-0060',
    summary: 'A RISC event emitted by hand was suppressed because the ' +
      'account has opted out (risc.honourOptOut).',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from ' +
      '/admin-api' },
  { code: 'STS-SSF-0061',
    summary: 'A RISC account reset named an account the register does not ' +
      'track.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from ' +
      '/admin-api' },
  { code: 'STS-SSF-0062',
    summary: 'The RISC console or management API was asked for an action it ' +
      'does not have.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors: [Unknown ' +
      'action ...]} from /admin-api' },
  { code: 'STS-SSF-0063',
    summary: 'An automatic RISC emission (a directory write this service ' +
      'observed) failed with an exception.',
    spec: '' },
  { code: 'STS-SSF-0064',
    summary: 'An internal receive endpoint asked for a receiver surface this ' +
      'service does not have — a programming error in the surface\'s ' +
      'route.',
    spec: 'HTTP 500 {err: invalid_request}' },
  { code: 'STS-SSF-0065',
    summary: 'A push reached the admin console\'s or user portal\'s receive ' +
      'endpoint while this service is not running its own receivers ' +
      '(ssf.enabled or ssf.internalReceivers off).',
    spec: 'HTTP 501 {err: invalid_request}' },
  { code: 'STS-SSF-0066',
    summary: 'A push reached an internal receive endpoint whose surface has ' +
      'no stream in this realm (it was deleted, or never seeded).',
    spec: 'HTTP 404 {err: invalid_request}' },
  { code: 'STS-SSF-0067',
    summary: 'A push at an internal receive endpoint presented no ' +
      'authorization header, or not the one minted for that surface\'s ' +
      'stream.',
    spec: 'HTTP 401 {err: access_denied}' },
  { code: 'STS-SSF-0068',
    summary: 'A push at an internal receive endpoint carried an empty body.',
    spec: 'HTTP 400 {err: invalid_request}' },
  { code: 'STS-SSF-0069',
    summary: 'A Security Event Token delivered to an internal receiver could ' +
      'not be read as a SET; it was recorded anyway.',
    spec: 'HTTP 400 {err: invalid_request}' },
  { code: 'STS-SSF-0070',
    summary: 'A Security Event Token delivered to an internal receiver is ' +
      'not addressed to that receiver\'s audience; it was recorded and ' +
      'refused.',
    spec: 'HTTP 400 {err: invalid_audience}' },
  { code: 'STS-SSF-0071',
    summary: 'A Security Event Token delivered to an internal receiver did ' +
      'not verify while ssf.receiveRequireSignature is on.',
    spec: 'HTTP 400 {err: invalid_key}' },
  { code: 'STS-SSF-0072',
    summary: 'The admin console or the user portal could not be registered ' +
      'as a Shared Signals receiver in a realm, because its seeded ' +
      'stream configuration was refused; that surface\'s inbox stays ' +
      'empty.',
    spec: '' },
  { code: 'STS-SSF-0073',
    summary: 'A protocol family (GNAP) asked ssf.emitProtocolEvent() for ' +
      'an event type that is not one of CAEP\'s; nothing was sent.',
    spec: '' },
  { code: 'STS-SSF-0074',
    summary: 'A CAEP event a protocol family asked to emit failed ' +
      'ssf_events validation and was not sent.',
    spec: '' },
  { code: 'STS-SSF-0075',
    summary: 'A CAEP event a protocol family asked to emit could not be ' +
      'built or delivered (the promise rejected).',
    spec: '' },
  { code: 'STS-SSF-0076',
    summary: 'A family\'s subject scope installed with ' +
      'ssf_streams.setSubjectScope() threw while a stream\'s coverage was ' +
      'being decided; it was ignored (narrows nothing).',
    spec: '' },
  { code: 'STS-SSF-0077',
    summary: 'A GNAP access token was presented to an SSF endpoint while ' +
      'GNAP is switched off in the realm (gnap.enabled), or the GNAP family ' +
      'is not loaded in this process.',
    spec: 'HTTP 401 authentication_failed' },
  { code: 'STS-SSF-0078',
    summary: 'A GNAP access token presented to an SSF endpoint was refused ' +
      'and the GNAP resource-server check named no code of its own.',
    spec: 'HTTP 401 invalid_token' },
  { code: 'STS-SSF-0079',
    summary: 'A GNAP access token presented to an SSF endpoint was issued ' +
      'for a named resource server, which this transmitter is not.',
    spec: 'HTTP 401 invalid_token' },
  { code: 'STS-SSF-0080',
    summary: 'A GNAP access token presented to an SSF endpoint does not ' +
      'carry the ssf:read or ssf:write access the operation needs.',
    spec: 'HTTP 403 access_denied' },
  { code: 'STS-SSF-0081',
    summary: 'A Security Event Token was not transmitted because the ' +
      'application that owns the stream is not allowed that event type ' +
      '(ssfAllowedEvents on its entry).',
    spec: '' },
  // WHAT AN ADMINISTRATOR DID TO SOMEBODY'S CREDENTIALS (2026-09-13).
  { code: 'STS-SSF-0090',
    summary: 'A RISC event about an administrator\'s act on an account ' +
      '(account-credential-change-required, recovery-information-changed) ' +
      'could not be built or delivered.',
    spec: '' },
  { code: 'STS-SSF-0091',
    summary: 'A CAEP credential-change about a person could not be built, ' +
      'was not a valid event, or could not be delivered.',
    spec: '' },
  { code: 'STS-SSF-0092',
    summary: 'A push was not made because ssf.pushBacklog pushes were already ' +
      'waiting for one of ssf.pushConcurrency slots; the SET was put on the ' +
      'stream\'s dead-letter queue.',
    spec: '' },
  { code: 'STS-SSF-0093',
    summary: 'A push stream was declared dead: its pushes all failed for ' +
      'ssf.deadStreamTimeoutS. Nothing more is pushed to it until a probe ' +
      'or an operator revives it.',
    spec: '' },
  { code: 'STS-SSF-0094',
    summary: 'Security Event Tokens could not be delivered since the last ' +
      'dead-letter sweep and are on dead-letter queues (one summary line per ' +
      'realm per sweep, never one per SET).',
    spec: '' },
  { code: 'STS-SSF-0095',
    summary: 'A stream was asked to be revived and is not dead.',
    spec: 'HTTP 400 on /admin-api/ssf/revive' },
  { code: 'STS-SSF-0096',
    summary: 'A SET for a dead push stream was put on its dead-letter queue ' +
      'unsigned instead of being pushed.',
    spec: '' },
  { code: 'STS-SSF-0097',
    summary: 'The dead-letter sweep failed in a realm; it is tried again at ' +
      'the next interval.',
    spec: '' },
  { code: 'STS-SSF-0098',
    summary: 'Whether another process had already reported a stream as dead ' +
      'or revived could not be asked, so it was reported here and may be ' +
      'reported twice.',
    spec: 'none — logged' },
  { code: 'STS-SSF-0099',
    summary: 'A GNAP key proof on a Shared Signals endpoint could not be ' +
      'confirmed unused across the cluster, so the token was refused.',
    spec: 'HTTP 401 {err: invalid_token}' },
  // ===== GNAP ==============================================================
  { code: 'STS-GNAP-0001',
    summary: 'A GNAP key names a proofing method this authorization server ' +
      'does not implement, in string or object form.',
    spec: 'HTTP 401 GNAP invalid_client' },
  { code: 'STS-GNAP-0002',
    summary: 'A GNAP key\'s "proof" member is neither a method name nor an ' +
      'object.',
    spec: 'HTTP 401 GNAP invalid_request' },
  { code: 'STS-GNAP-0003',
    summary: 'A GNAP key uses the object form of "proof" for a method that ' +
      'is defined in string form only (every method but httpsig).',
    spec: 'HTTP 401 GNAP invalid_request' },
  { code: 'STS-GNAP-0004',
    summary: 'An httpsig proof in object form lacks "alg" or ' +
      '"content-digest-alg" (RFC 9635 section 7.3.1).',
    spec: 'HTTP 401 GNAP invalid_request' },
  { code: 'STS-GNAP-0005',
    summary: 'A GNAP key is neither a key object nor a non-empty reference ' +
      'string.',
    spec: 'HTTP 401 GNAP invalid_request' },
  { code: 'STS-GNAP-0006',
    summary: 'A GNAP key reference names no key registered with this ' +
      'authorization server (no application entry carries it, or its ' +
      'shared key is unopenable or shorter than 32 bytes).',
    spec: 'HTTP 401 GNAP invalid_client' },
  { code: 'STS-GNAP-0007',
    summary: 'A GNAP key by value is presented in no format, or in more ' +
      'than one of jwk, cert and cert#S256 (RFC 9635 section 11.35).',
    spec: 'HTTP 401 GNAP invalid_client' },
  { code: 'STS-GNAP-0008',
    summary: 'A GNAP key\'s "cert" member is not a PEM X.509 certificate.',
    spec: 'HTTP 401 GNAP invalid_client' },
  { code: 'STS-GNAP-0009',
    summary: 'A GNAP key\'s "cert#S256" member is not a base64url SHA-256 ' +
      'thumbprint.',
    spec: 'HTTP 401 GNAP invalid_client' },
  { code: 'STS-GNAP-0010',
    summary: 'A GNAP key\'s "jwk" member is not a JSON Web Key object.',
    spec: 'HTTP 401 GNAP invalid_client' },
  { code: 'STS-GNAP-0011',
    summary: 'A GNAP key by value carries private or symmetric JWK ' +
      'material; only a public key may be sent.',
    spec: 'HTTP 401 GNAP invalid_client' },
  { code: 'STS-GNAP-0012',
    summary: 'A JWK presented in GNAP lacks "alg" or "kid", or names alg ' +
      '"none".',
    spec: 'HTTP 401 GNAP invalid_client' },
  { code: 'STS-GNAP-0013',
    summary: 'A JWK presented in GNAP names an alg that is not an ' +
      'asymmetric JWS algorithm for its key type.',
    spec: 'HTTP 401 GNAP invalid_client' },
  { code: 'STS-GNAP-0014',
    summary: 'A JWK presented in GNAP does not import as a public key.',
    spec: 'HTTP 401 GNAP invalid_client' },
  { code: 'STS-GNAP-0020',
    summary: 'A GNAP document\'s "access" member is not an array of access ' +
      'rights.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0021',
    summary: 'A GNAP access right is an empty reference string.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0022',
    summary: 'A GNAP access right is neither a reference string nor an ' +
      'object with a string "type".',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0023',
    summary: 'A GNAP access right\'s actions, locations, datatypes, ' +
      'privileges or identifier is not of the type RFC 9635 section 8 ' +
      'requires.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0024',
    summary: 'A requested GNAP access token (an access_token element) is ' +
      'not an object.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0025',
    summary: 'A requested GNAP access token carries a label that is not a ' +
      'non-empty string.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0026',
    summary: 'A request for multiple GNAP access tokens leaves one without ' +
      'a label (RFC 9635 section 2.1.2).',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0027',
    summary: 'A requested GNAP access token\'s "flags" member is not an ' +
      'array of strings.',
    spec: 'HTTP 400 GNAP invalid_flag' },
  { code: 'STS-GNAP-0028',
    summary: 'A requested GNAP access token names the same flag more than ' +
      'once.',
    spec: 'HTTP 400 GNAP invalid_flag' },
  { code: 'STS-GNAP-0029',
    summary: 'A GNAP client requested a response-only flag (durable).',
    spec: 'HTTP 400 GNAP invalid_flag' },
  { code: 'STS-GNAP-0030',
    summary: 'A GNAP client requested a flag this authorization server ' +
      'does not understand.',
    spec: 'HTTP 400 GNAP invalid_flag' },
  { code: 'STS-GNAP-0031',
    summary: 'A GNAP grant request\'s "access_token" member is an empty ' +
      'array.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0032',
    summary: 'Two access tokens in one GNAP grant request share a label.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0033',
    summary: 'A GNAP subject identifier is not an object with a "format".',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0034',
    summary: 'A GNAP subject identifier uses a format that is not in RFC ' +
      '9493.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0035',
    summary: 'A GNAP "aliases" subject identifier contains another ' +
      '"aliases" identifier.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0036',
    summary: 'A GNAP subject identifier lacks a member its format requires ' +
      'or carries a malformed one (aliases with no identifiers, an account ' +
      'URI without acct:, a phone number not in E.164).',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0037',
    summary: 'A GNAP "sub_ids" member is not an array of subject ' +
      'identifiers.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0038',
    summary: 'A GNAP "subject" request member, or its sub_id_formats or ' +
      'assertion_formats, is malformed.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0039',
    summary: 'A GNAP grant request\'s "client" member is absent, empty, or ' +
      'neither an object nor an instance identifier.',
    spec: 'HTTP 401 GNAP invalid_client' },
  { code: 'STS-GNAP-0040',
    summary: 'A GNAP grant request\'s "client" object carries no key.',
    spec: 'HTTP 401 GNAP invalid_client' },
  { code: 'STS-GNAP-0041',
    summary: 'A GNAP client\'s class_id or display member (name, uri, ' +
      'logo_uri) is malformed, or a display URI is not absolute.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0042',
    summary: 'A GNAP grant request\'s "user" member is an empty reference, ' +
      'or neither a string nor an object.',
    spec: 'HTTP 403 GNAP unknown_user (400 invalid_request when it is ' +
      'neither a string nor an object)' },
  { code: 'STS-GNAP-0043',
    summary: 'A GNAP "user.assertions" member is not an array of objects ' +
      'with string "format" and "value".',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0044',
    summary: 'A GNAP "interact" member is not an object.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0045',
    summary: 'A GNAP "interact.start" member is absent or not an array.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0046',
    summary: 'A GNAP interaction start mode has no name.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0047',
    summary: 'A GNAP "interact.finish" member has no method.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0048',
    summary: 'A GNAP interaction finish nonce is absent or not printable ' +
      'ASCII.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0049',
    summary: 'A GNAP interaction finish URI (redirect or push) is not an ' +
      'absolute URI without a fragment.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0050',
    summary: 'A GNAP interaction finish names a hash_method this ' +
      'authorization server cannot compute.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0051',
    summary: 'A GNAP "interact.hints" member is malformed.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0052',
    summary: 'A GNAP request document (a grant, continuation, ' +
      'modification, rotation, introspection or registration request) is ' +
      'not a JSON object.',
    spec: 'HTTP 400 GNAP invalid_request (invalid_rotation for a rotation)' },
  { code: 'STS-GNAP-0053',
    summary: 'A GNAP request document exceeds the shared bounds on nesting ' +
      'depth, key count or member names (validation.checkDocument()).',
    spec: 'HTTP 400 GNAP invalid_request (invalid_rotation for a rotation)' },
  { code: 'STS-GNAP-0054',
    summary: 'A new GNAP grant request carries "interact_ref", which is ' +
      'only ever sent to a continuation URI.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0055',
    summary: 'A GNAP grant request asks for neither an access token nor ' +
      'subject information.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0056',
    summary: 'A GNAP grant request\'s "existing_access_token" (RFC 9767 ' +
      'token derivation) is not a non-empty string.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0057',
    summary: 'A GNAP continuation POST carries members other than ' +
      '"interact_ref", which belong to a PATCH.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0058',
    summary: 'A GNAP continuation\'s "interact_ref" is not a string of ' +
      'unreserved characters.',
    spec: 'HTTP 400 GNAP invalid_interaction' },
  { code: 'STS-GNAP-0059',
    summary: 'A GNAP grant modification (PATCH) includes "client" or ' +
      '"interact_ref".',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0060',
    summary: 'A GNAP token rotation request carries content other than a ' +
      'single "key" member.',
    spec: 'HTTP 400 GNAP invalid_rotation' },
  { code: 'STS-GNAP-0061',
    summary: 'A GNAP request document does not match its JSON schema ' +
      '(gnap_schemas.js: types, lengths, caps, URI formats, control ' +
      'characters).',
    spec: 'HTTP 400 GNAP invalid_request (invalid_rotation for a rotation)' },
  { code: 'STS-GNAP-0070',
    summary: 'A GNAP user reference is not one this authorization server ' +
      'issued.',
    spec: 'HTTP 403 GNAP unknown_user' },
  { code: 'STS-GNAP-0071',
    summary: 'None of the user assertions in a GNAP grant request is one ' +
      'this authorization server issued and can verify.',
    spec: 'HTTP 403 GNAP unknown_user' },
  { code: 'STS-GNAP-0072',
    summary: 'The user identifiers and assertions in a GNAP grant request ' +
      'name more than one person.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0080',
    summary: 'A GNAP client instance or resource server presented an ' +
      'instance identifier this authorization server does not know.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0081',
    summary: 'A GNAP instance identifier resolves to an application entry ' +
      'with no key registered to verify its requests.',
    spec: 'HTTP 401 GNAP invalid_client' },
  { code: 'STS-GNAP-0082',
    summary: 'In product mode, a GNAP client instance or resource server ' +
      'proved a key no application entry registers (development mode would ' +
      'have created one).',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0083',
    summary: 'The application entry for a GNAP key seen for the first time ' +
      '(development mode) could not be created.',
    spec: 'HTTP 401 GNAP invalid_client' },
  { code: 'STS-GNAP-0090',
    summary: 'The issuance policy refused one GNAP access token for a ' +
      'grant; the token was left out of the response (RFC 9635 section ' +
      '3.2.2).',
    spec: '' },
  { code: 'STS-GNAP-0091',
    summary: 'No enabled access token format satisfies every resource set ' +
      'a requested GNAP token names; the token was left out of the ' +
      'response.',
    spec: '' },
  { code: 'STS-GNAP-0092',
    summary: 'A GNAP access token could not be minted in its chosen ' +
      'format; the token was left out of the response.',
    spec: '' },
  { code: 'STS-GNAP-0100',
    summary: 'None of the interaction start modes a GNAP client offered is ' +
      'supported for it, and no push finish can reach the resource owner ' +
      'another way.',
    spec: 'HTTP 400 GNAP invalid_interaction' },
  { code: 'STS-GNAP-0101',
    summary: 'In product mode, a GNAP interaction finish URI is not ' +
      'registered for the client instance (gnapFinishUri).',
    spec: 'HTTP 400 GNAP invalid_interaction' },
  { code: 'STS-GNAP-0102',
    summary: 'A GNAP push finish URI is not one this service will dial ' +
      '(not an absolute http(s) URL, plain http with ' +
      'gnap.pushAllowInsecure off, or a host outside ' +
      'gnap.pushAllowedHosts).',
    spec: 'HTTP 400 GNAP invalid_interaction' },
  { code: 'STS-GNAP-0103',
    summary: 'In product mode, a GNAP finish URI uses plain http to a host ' +
      'other than localhost.',
    spec: 'HTTP 400 GNAP invalid_interaction' },
  { code: 'STS-GNAP-0110',
    summary: 'A GNAP client proved its key with a proofing method this ' +
      'authorization server\'s key_proofs_supported does not list.',
    spec: 'HTTP 401 GNAP invalid_client' },
  { code: 'STS-GNAP-0111',
    summary: 'A GNAP client asked for a bearer token while bearer tokens ' +
      'are off (gnap.bearerTokens) or its entry forbids them ' +
      '(gnapBearerTokens).',
    spec: 'HTTP 400 GNAP invalid_flag' },
  { code: 'STS-GNAP-0112',
    summary: 'A GNAP grant request or modification asks for an access ' +
      'right the client may not request (gnapAllowedAccess), or names an ' +
      'unregistered reference while gnap.unknownAccessReferences is ' +
      'refuse.',
    spec: 'HTTP 403 GNAP request_denied' },
  { code: 'STS-GNAP-0113',
    summary: 'A GNAP grant needs the resource owner\'s approval and the ' +
      'client offered no way to interact; the grant was finalized.',
    spec: 'HTTP 400 GNAP invalid_interaction' },
  { code: 'STS-GNAP-0120',
    summary: 'A resource owner did not approve a GNAP grant — recorded ' +
      'when they answer, and again when the client continues and is told.',
    spec: 'HTTP 403 GNAP user_denied, at the next continuation' },
  { code: 'STS-GNAP-0121',
    summary: 'The person who approved a GNAP grant is not the user the ' +
      'request named, and gnap.allowCrossUser is off.',
    spec: 'HTTP 403 GNAP unknown_user, at the next continuation' },
  { code: 'STS-GNAP-0130',
    summary: 'A GNAP continuation URI and access token do not together ' +
      'identify an active grant request.',
    spec: 'HTTP 401 GNAP invalid_continuation' },
  { code: 'STS-GNAP-0131',
    summary: 'A GNAP continuation named a grant request that is finalized.',
    spec: 'HTTP 400 GNAP invalid_continuation' },
  { code: 'STS-GNAP-0132',
    summary: 'A pending GNAP grant request expired before it was approved; ' +
      'the continuation finalized it.',
    spec: 'HTTP 400 GNAP invalid_continuation' },
  { code: 'STS-GNAP-0133',
    summary: 'A GNAP client continued before the wait period ended.',
    spec: 'HTTP 400 GNAP too_fast, with a new continue member' },
  { code: 'STS-GNAP-0134',
    summary: 'A GNAP interaction reference was presented for a grant ' +
      'request that is not pending; the grant was finalized (RFC 9635 ' +
      'section 5.1).',
    spec: 'HTTP 400 GNAP too_many_attempts' },
  { code: 'STS-GNAP-0135',
    summary: 'A GNAP continuation presented an interaction reference that ' +
      'is not the one issued for the grant request.',
    spec: 'HTTP 400 GNAP invalid_interaction, with a new continue member' },
  { code: 'STS-GNAP-0136',
    summary: 'A GNAP client polled more than gnap.maxPolls times before ' +
      'the resource owner decided; the grant was finalized.',
    spec: 'HTTP 400 GNAP too_many_attempts' },
  { code: 'STS-GNAP-0137',
    summary: 'A GNAP client polled a grant whose finish method delivers an ' +
      'interaction reference, instead of presenting that reference (RFC ' +
      '9635 section 3.3.5).',
    spec: 'HTTP 400 GNAP invalid_continuation, with a new continue member' },
  { code: 'STS-GNAP-0140',
    summary: 'A GNAP grant modification (PATCH) named a grant request that ' +
      'is neither pending nor approved.',
    spec: 'HTTP 400 GNAP invalid_continuation' },
  { code: 'STS-GNAP-0141',
    summary: 'A GNAP grant modification asks for more than was approved ' +
      'and offers no way to interact with the resource owner.',
    spec: 'HTTP 403 GNAP request_denied, with a new continue member' },
  { code: 'STS-GNAP-0150',
    summary: 'A GNAP token management URI and access token do not identify ' +
      'a token.',
    spec: 'HTTP 401 GNAP invalid_rotation (invalid_request for a DELETE)' },
  { code: 'STS-GNAP-0151',
    summary: 'A GNAP token rotation asked for a new key while key rotation ' +
      'is off (gnap.keyRotation, or the authorization server\'s ' +
      'key_rotation_supported).',
    spec: 'HTTP 400 GNAP key_rotation_not_supported' },
  { code: 'STS-GNAP-0152',
    summary: 'A GNAP key rotation was asked for a bearer token, which has ' +
      'no key to rotate.',
    spec: 'HTTP 400 GNAP invalid_rotation' },
  { code: 'STS-GNAP-0153',
    summary: 'A revoked GNAP access token was presented for rotation.',
    spec: 'HTTP 400 GNAP invalid_rotation' },
  { code: 'STS-GNAP-0154',
    summary: 'A GNAP access token whose grant is finalized was presented ' +
      'for rotation.',
    spec: 'HTTP 400 GNAP invalid_rotation' },
  { code: 'STS-GNAP-0155',
    summary: 'A rotated GNAP access token could not be minted.',
    spec: 'HTTP 400 GNAP invalid_rotation' },
  { code: 'STS-GNAP-0160',
    summary: 'A GNAP endpoint threw an unexpected error.',
    spec: 'HTTP 500 GNAP request_denied' },
  { code: 'STS-GNAP-0161',
    summary: 'A GNAP endpoint was reached while GNAP is turned off in this ' +
      'trust realm (gnap.enabled).',
    spec: 'HTTP 404 GNAP request_denied' },
  { code: 'STS-GNAP-0162',
    summary: 'The authorization server segment of a /:as/gnap path is not ' +
      'a valid identifier.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0163',
    summary: 'The GNAP grant endpoint refused a request whose refusal ' +
      'carried no more specific code.',
    spec: 'HTTP 400 GNAP, with the refusal\'s own error code' },
  { code: 'STS-GNAP-0164',
    summary: 'A GNAP continuation URI does not name a grant request in the ' +
      'shape this authorization server issues.',
    spec: 'HTTP 401 GNAP invalid_continuation' },
  { code: 'STS-GNAP-0165',
    summary: 'The GNAP continuation endpoint refused a request whose ' +
      'refusal carried no more specific code.',
    spec: 'HTTP 400 GNAP, with the refusal\'s own error code' },
  { code: 'STS-GNAP-0166',
    summary: 'A GNAP token management URI does not name a token in the ' +
      'shape this authorization server issues.',
    spec: 'HTTP 401 GNAP invalid_rotation (invalid_request for a DELETE)' },
  { code: 'STS-GNAP-0167',
    summary: 'The GNAP token management endpoint refused a request whose ' +
      'refusal carried no more specific code.',
    spec: 'HTTP 400 GNAP, with the refusal\'s own error code' },
  { code: 'STS-GNAP-0168',
    summary: 'The GNAP introspection endpoint refused a request whose ' +
      'refusal carried no more specific code.',
    spec: 'HTTP 400 GNAP, with the refusal\'s own error code' },
  { code: 'STS-GNAP-0169',
    summary: 'The GNAP resource registration endpoint refused a request ' +
      'whose refusal carried no more specific code.',
    spec: 'HTTP 400 GNAP, with the refusal\'s own error code' },
  { code: 'STS-GNAP-0200',
    summary: 'A Content-Digest algorithm this service was asked to compute ' +
      'or accept is not sha-256 or sha-512 (for example a key\'s ' +
      'content-digest-alg).',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0201',
    summary: 'A GNAP request with content carries no Content-Digest field.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0202',
    summary: 'A Content-Digest field is not a Structured Field Dictionary.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0203',
    summary: 'A Content-Digest member is not a Byte Sequence.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0204',
    summary: 'A Content-Digest does not match the request content.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0205',
    summary: 'A Content-Digest field carries no digest in an accepted ' +
      'algorithm.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0206',
    summary: 'An HTTP message signature\'s covered component identifier is ' +
      'malformed, or the covered components are not an Inner List.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0207',
    summary: 'A covered component carries a parameter that is not ' +
      'understood or is of the wrong type.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0208',
    summary: 'A covered component carries ;req, which a request verifier ' +
      'has no related request to resolve.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0209',
    summary: 'An HTTP message signature covers a derived component this ' +
      'verifier does not understand.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0210',
    summary: 'An HTTP message signature covers @status (or another ' +
      'response-only component) on a request, or a response status is ' +
      'malformed.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0211',
    summary: 'A request has no method or no absolute target URI to derive ' +
      'a covered component from.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0212',
    summary: 'A covered @query-param has no name parameter, or names a ' +
      'parameter the target URI does not have.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0213',
    summary: 'A covered @query-param names a parameter that occurs more ' +
      'than once.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0214',
    summary: 'A covered component carries ;tr, and trailers are not part ' +
      'of the message this verifier is given.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0215',
    summary: 'A covered component combines ;bs with ;sf or ;key.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0216',
    summary: 'A covered HTTP field is not present in the message.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0217',
    summary: 'A covered component asks for ;sf or ;key on a field whose ' +
      'Structured Field type is unknown or is not a Dictionary.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0218',
    summary: 'A covered ;key names a Dictionary member the field does not ' +
      'have.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0219',
    summary: 'A covered field does not parse as its Structured Field type.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0220',
    summary: 'An HTTP message signature lists @signature-params among its ' +
      'covered components.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0221',
    summary: 'A covered component\'s value contains a newline or a ' +
      'character outside ASCII.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0222',
    summary: 'A signature parameter is of the wrong type or is a negative ' +
      'timestamp, or the signature parameters cannot be serialized.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0223',
    summary: 'An HTTP message signature covers the same component more ' +
      'than once.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0224',
    summary: 'The key for a signature algorithm is the wrong kind or too ' +
      'weak (a shared secret shorter than its hash, an asymmetric key of ' +
      'the wrong type, an RSA key under 2048 bits).',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0225',
    summary: 'A signature label handed to the HTTP message signer is not a ' +
      'valid Dictionary key.',
    spec: '' },
  { code: 'STS-GNAP-0226',
    summary: 'No signature algorithm could be determined: neither the key ' +
      'nor an alg parameter names one.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0227',
    summary: 'A signature algorithm, or a signature\'s alg parameter, is ' +
      'not one this verifier supports.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0228',
    summary: 'A JWS algorithm was signalled with the alg parameter, or an ' +
      'alg parameter disagrees with the key\'s algorithm.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0229',
    summary: 'Signing or verifying an HTTP message signature failed inside ' +
      'the cryptographic library.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0230',
    summary: 'An HTTP message signature could not be appended to a ' +
      'message: it is not a successful sign() result, or its label is ' +
      'already used.',
    spec: '' },
  { code: 'STS-GNAP-0231',
    summary: 'A Signature or Signature-Input field is not a Structured ' +
      'Field Dictionary.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0232',
    summary: 'A Signature or Signature-Input field uses one label more ' +
      'than once.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0233',
    summary: 'A GNAP request proved by httpsig carries no HTTP message ' +
      'signature (no Signature-Input and no Signature field).',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0234',
    summary: 'A signature label is present in only one of the Signature ' +
      'and Signature-Input fields.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0235',
    summary: 'A Signature-Input member is not an Inner List of string ' +
      'component identifiers, or a Signature member is not a Byte ' +
      'Sequence.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0236',
    summary: 'The message carries no HTTP message signature with the label ' +
      'the verifier asked for.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0237',
    summary: 'No HTTP message signature carries the required tag ' +
      '(tag="gnap").',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0238',
    summary: 'An HTTP message signature carries the alg parameter, which ' +
      'RFC 9635 section 7.3.1 forbids.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0239',
    summary: 'An HTTP message signature has no created parameter.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0240',
    summary: 'An HTTP message signature is older than the allowed age ' +
      '(gnap.signatureMaxAgeS).',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0241',
    summary: 'An HTTP message signature claims a created time further in ' +
      'the future than the allowed clock skew.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0242',
    summary: 'An HTTP message signature has passed its expires parameter.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0243',
    summary: 'An HTTP message signature does not cover a required ' +
      'component (@method, @target-uri, content-digest, authorization).',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0244',
    summary: 'No verification key is known for an HTTP message signature ' +
      '(its tag or keyid does not name the presented key).',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0245',
    summary: 'An HTTP message signature uses an algorithm the verifier ' +
      'does not allow.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0246',
    summary: 'An HTTP message signature does not verify over the signature ' +
      'base rebuilt from the message.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0260',
    summary: 'A GNAP request\'s content is a JWS whose payload is not a ' +
      'JSON object.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0261',
    summary: 'A GNAP request\'s content is not JSON.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0262',
    summary: 'A GNAP JWS key proof is not a compact JWS, or its JOSE ' +
      'header is not JSON.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0263',
    summary: 'A GNAP JWS key proof\'s typ is not the one its proofing ' +
      'method requires.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0264',
    summary: 'A GNAP JWS key proof\'s alg is not the key\'s own, or is ' +
      '"none".',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0265',
    summary: 'A GNAP JWS key proof\'s kid does not name the presented JWK.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0266',
    summary: 'A GNAP JWS key proof\'s htm is not the request method.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0267',
    summary: 'A GNAP JWS key proof\'s uri is not the URI the request was ' +
      'sent to.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0268',
    summary: 'A GNAP JWS key proof\'s created time is missing or outside ' +
      'the allowed age.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0269',
    summary: 'A GNAP JWS key proof does not carry the hash of the ' +
      'presented access token in "ath".',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0270',
    summary: 'A GNAP JWS key proof\'s signature does not verify against ' +
      'the presented key.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0271',
    summary: 'A GNAP JWS key proof has already been used.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0272',
    summary: 'A GNAP detached JWS proof for a request with no content is ' +
      'not signed over an empty payload.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0273',
    summary: 'A GNAP detached JWS proof does not carry the SHA-256 digest ' +
      'of the request content.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0274',
    summary: 'A GNAP request\'s Content-Digest was refused and the digest ' +
      'check named no more specific code.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0275',
    summary: 'A GNAP HTTP message signature did not verify and the ' +
      'verifier named no more specific code.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0276',
    summary: 'A GNAP HTTP message signature\'s nonce has already been ' +
      'used.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0277',
    summary: 'A GNAP key proved by mutual TLS was presented on a ' +
      'connection with no client certificate.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0278',
    summary: 'The TLS client certificate is not the certificate the GNAP ' +
      'key names, or does not carry the presented key.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0279',
    summary: 'A GNAP request had no usable key to verify it with.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0280',
    summary: 'A cert#S256 GNAP key, which carries no public key, was used ' +
      'with a signature proofing method rather than mutual TLS.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0281',
    summary: 'A GNAP key rotation changes the proofing method or its ' +
      'parameters.',
    spec: 'HTTP 401 GNAP invalid_rotation' },
  { code: 'STS-GNAP-0282',
    summary: 'A GNAP key rotation was attempted for a key proved by mutual ' +
      'TLS, for which rotation is not defined.',
    spec: 'HTTP 400 GNAP key_rotation_not_supported' },
  { code: 'STS-GNAP-0283',
    summary: 'A GNAP key names a proofing method that has no verifier ' +
      'implemented.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0284',
    summary: 'A GNAP request that must carry a Detached-JWS header (a ' +
      'detached JWS proof, a content-less jws request, or a detached JWS ' +
      'key rotation) has none.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0285',
    summary: 'A GNAP request proved by an attached JWS (or an attached-JWS ' +
      'key rotation) does not send a JWS as its content.',
    spec: 'HTTP 401 GNAP invalid_client (400 invalid_resource_server at ' +
      'the RS-facing endpoints)' },
  { code: 'STS-GNAP-0286',
    summary: 'In a GNAP httpsig key rotation, the new key\'s signature ' +
      'does not cover the old key\'s Signature and Signature-Input.',
    spec: 'HTTP 401 GNAP invalid_rotation' },
  { code: 'STS-GNAP-0300',
    summary: 'A GNAP token model\'s access is not a non-empty array of ' +
      'access rights.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0301',
    summary: 'A GNAP token model\'s access element is an empty reference, ' +
      'or neither a reference string nor a typed object.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0302',
    summary: 'A GNAP token model\'s access element has an array dimension ' +
      'or an identifier of the wrong type.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0303',
    summary: 'A GNAP token model is not valid under RFC 9767 section 2.1 ' +
      '(a missing or malformed member, or a bearer flag and cnf that ' +
      'disagree), when minted or read back.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0304',
    summary: 'A presented GNAP access token has expired.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0305',
    summary: 'A presented GNAP access token is not yet valid (nbf).',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0306',
    summary: 'A presented GNAP access token is not intended for the ' +
      'audience it was presented to.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0307',
    summary: 'A key-bound GNAP access token was presented without that ' +
      'key.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0308',
    summary: 'A presented GNAP access token does not grant the access the ' +
      'request needs, possibly because an attenuation narrowed it.',
    spec: 'HTTP 403 insufficient_scope at a resource server ' +
      '(WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0310',
    summary: 'A GNAP macaroon could not be minted or checked: the model ' +
      'does not round-trip as caveats, the root key is too short, or the ' +
      'macaroon library refused.',
    spec: '' },
  { code: 'STS-GNAP-0311',
    summary: 'A presented macaroon is not unpadded base64url, or not a ' +
      'libmacaroons v2 binary macaroon.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0312',
    summary: 'A presented macaroon\'s identifier is not this service\'s ' +
      'GNAP prefix and a jti, so this service did not mint it.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0313',
    summary: 'A presented macaroon carries a third-party caveat, which ' +
      'needs a discharge macaroon this format does not carry.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0314',
    summary: 'A presented macaroon\'s HMAC chain does not verify under the ' +
      'resource server\'s root key.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0315',
    summary: 'A presented macaroon carries a caveat outside this ' +
      'service\'s caveat grammar.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0316',
    summary: 'A presented macaroon\'s authority section is malformed: a ' +
      'caveat out of place or repeated, a required one missing, or not a ' +
      'valid token model.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0317',
    summary: 'A macaroon attenuation was refused: empty, outside the ' +
      'exp/nbf/aud/access grammar, or refused by the library.',
    spec: '' },
  { code: 'STS-GNAP-0320',
    summary: 'A biscuit could not be minted or verified with the keys ' +
      'given (not Ed25519), or the biscuit library refused to mint or ' +
      'emitted a value that is not token68.',
    spec: '' },
  { code: 'STS-GNAP-0321',
    summary: 'The biscuit WASM library could not be loaded.',
    spec: 'HTTP 401 invalid_token at a resource server; at issuance the ' +
      'token is left out' },
  { code: 'STS-GNAP-0322',
    summary: 'A presented biscuit is not URL-safe base64, does not parse, ' +
      'or its signature chain does not verify under this authorization ' +
      'server\'s public key.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0323',
    summary: 'A presented biscuit\'s authority block is not a GNAP token ' +
      'model (misnumbered or non-JSON access facts, a singular fact ' +
      'repeated, or not exactly one key binding).',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0324',
    summary: 'A biscuit authorization check failed, or the authorizer ' +
      'could not be built for the presentation.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0325',
    summary: 'Biscuit authorization exceeded its run limits (facts, ' +
      'iterations or time), which is a refusal and never a pass.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0326',
    summary: 'A biscuit attenuation block was refused: empty, a parameter ' +
      'of an unsupported type, or rejected by the library.',
    spec: '' },
  { code: 'STS-GNAP-0330',
    summary: 'ZCAP keys are unusable (no absolute controller URL, a keyId ' +
      'not under it, or not an Ed25519 KeyObject), or a capability\'s ' +
      'invocationTarget is not an absolute URI.',
    spec: '' },
  { code: 'STS-GNAP-0331',
    summary: 'The ZCAP libraries could not be loaded.',
    spec: 'HTTP 401 invalid_token at a resource server; at issuance the ' +
      'token is left out' },
  { code: 'STS-GNAP-0332',
    summary: 'A presented ZCAP is not base64url JSON with exactly the ' +
      'members and @context this format writes.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0333',
    summary: 'A presented ZCAP\'s delegation proof does not verify under ' +
      'this authorization server\'s key.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0334',
    summary: 'A presented ZCAP\'s GNAP terms are inconsistent, or it names ' +
      'no invocationTarget.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0335',
    summary: 'The ZCAP libraries refused to sign a capability.',
    spec: '' },
  { code: 'STS-GNAP-0340',
    summary: 'A presented jwt-encrypted GNAP access token is encrypted to ' +
      'a resource server\'s key, which this authorization server does not ' +
      'hold.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0341',
    summary: 'A presented jwt-encrypted GNAP access token does not ' +
      'decrypt.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0342',
    summary: 'A presented JWT GNAP access token\'s signature does not ' +
      'verify.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0343',
    summary: 'A presented JWT is not a GNAP access token (its typ is ' +
      'wrong).',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0344',
    summary: 'A GNAP token names an access token format that does not ' +
      'exist.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0400',
    summary: 'A GNAP interaction start link (redirect or app) names no ' +
      'request still waiting for approval.',
    spec: 'HTTP 400 page' },
  { code: 'STS-GNAP-0401',
    summary: 'A GNAP interaction start link had already been used.',
    spec: 'HTTP 400 page' },
  { code: 'STS-GNAP-0402',
    summary: 'The GNAP user code page was opened while GNAP is turned off ' +
      '(gnap.enabled).',
    spec: 'HTTP 400 page' },
  { code: 'STS-GNAP-0403',
    summary: 'A GNAP user code form post was malformed.',
    spec: 'HTTP 400 page' },
  { code: 'STS-GNAP-0404',
    summary: 'Too many GNAP user codes were tried from one address.',
    spec: 'HTTP 429 page' },
  { code: 'STS-GNAP-0405',
    summary: 'A GNAP user code is not recognised, or has expired.',
    spec: 'HTTP 400 page' },
  { code: 'STS-GNAP-0406',
    summary: 'A GNAP approval page or answer names no request waiting for ' +
      'the person, or one whose interaction was never started.',
    spec: 'HTTP 400 page' },
  { code: 'STS-GNAP-0407',
    summary: 'A GNAP approval answer failed its anti-forgery check.',
    spec: 'HTTP 400 page' },
  { code: 'STS-GNAP-0408',
    summary: 'A GNAP approval answer was malformed.',
    spec: 'HTTP 400 page' },
  { code: 'STS-GNAP-0409',
    summary: 'A GNAP approval could not be completed because of an ' +
      'unexpected error.',
    spec: 'HTTP 400 page' },
  { code: 'STS-GNAP-0500',
    summary: 'A GNAP RS-facing request\'s "resource_server" member is ' +
      'absent, or has neither a key nor an instance identifier.',
    spec: 'HTTP 400 GNAP invalid_resource_server' },
  { code: 'STS-GNAP-0501',
    summary: 'A GNAP introspection request has no "access_token", or its ' +
      '"proof" is not a method name.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0502',
    summary: 'A GNAP resource registration request is malformed (no access ' +
      'rights, token_formats_supported not strings, ' +
      'token_introspection_required not a boolean).',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0510',
    summary: 'A resource server asked for a derived token while token ' +
      'derivation is off (gnap.tokenDerivation).',
    spec: 'HTTP 403 GNAP request_denied' },
  { code: 'STS-GNAP-0511',
    summary: 'A GNAP token derivation names an existing access token that ' +
      'is not active.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0512',
    summary: 'A GNAP token derivation names an existing access token that ' +
      'was not issued for the requesting resource server.',
    spec: 'HTTP 403 GNAP request_denied' },
  { code: 'STS-GNAP-0513',
    summary: 'A GNAP derived token asks for more access than the token it ' +
      'is derived from, beyond rights registered for a downstream resource ' +
      'server.',
    spec: 'HTTP 403 GNAP request_denied' },
  { code: 'STS-GNAP-0520',
    summary: 'GNAP token introspection was asked for while it is off ' +
      '(gnap.introspection).',
    spec: 'HTTP 404 GNAP invalid_request' },
  { code: 'STS-GNAP-0530',
    summary: 'GNAP resource registration was asked for while it is off ' +
      '(gnap.resourceRegistration).',
    spec: 'HTTP 404 GNAP invalid_request' },
  { code: 'STS-GNAP-0531',
    summary: 'A GNAP resource registration names only token formats this ' +
      'authorization server does not issue.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0532',
    summary: 'A GNAP resource registration requires introspection while ' +
      'introspection is off.',
    spec: 'HTTP 400 GNAP invalid_request' },
  { code: 'STS-GNAP-0533',
    summary: 'A resource server tried to register access it may not ' +
      '(gnapAllowedAccess).',
    spec: 'HTTP 400 GNAP invalid_access' },
  { code: 'STS-GNAP-0540',
    summary: 'No GNAP access token was presented to a resource server (no ' +
      'Authorization header in the GNAP or Bearer scheme).',
    spec: 'HTTP 401 invalid_token (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0541',
    summary: 'A GNAP access token presented to a resource server is ' +
      'unknown, revoked or expired, or its grant is finalized.',
    spec: 'HTTP 401 invalid_token (WWW-Authenticate: GNAP) at a ' +
      'resource server; HTTP 401 with WWW-Authenticate at the SSF ' +
      'transmitter' },
  { code: 'STS-GNAP-0542',
    summary: 'A bearer GNAP access token was presented under the GNAP ' +
      'scheme rather than Bearer.',
    spec: 'HTTP 401 invalid_request (WWW-Authenticate: GNAP) at a ' +
      'resource server; HTTP 401 with WWW-Authenticate at the SSF ' +
      'transmitter' },
  { code: 'STS-GNAP-0543',
    summary: 'A key-bound GNAP access token was presented under the Bearer ' +
      'scheme rather than GNAP with a key proof.',
    spec: 'HTTP 401 invalid_request (WWW-Authenticate: GNAP) at a ' +
      'resource server; HTTP 401 with WWW-Authenticate at the SSF ' +
      'transmitter' },
  { code: 'STS-GNAP-0544',
    summary: 'The key of a presented key-bound GNAP access token, or the ' +
      'request content, could not be read.',
    spec: 'HTTP 401 invalid_request (WWW-Authenticate: GNAP) at a ' +
      'resource server; HTTP 401 with WWW-Authenticate at the SSF ' +
      'transmitter' },
  { code: 'STS-GNAP-0545',
    summary: 'The key proof with a presented GNAP access token did not ' +
      'verify and the verifier named no more specific code.',
    spec: 'HTTP 401 invalid_token (WWW-Authenticate: GNAP) at a ' +
      'resource server; HTTP 401 with WWW-Authenticate at the SSF ' +
      'transmitter' },
  { code: 'STS-GNAP-0546',
    summary: 'A presented GNAP access token failed its format\'s ' +
      'verification and the format named no more specific code.',
    spec: 'HTTP 401 invalid_token or 403 insufficient_scope at the ' +
      'demonstration resource server (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0550',
    summary: 'The GNAP demonstration resource server was reached while it ' +
      'is turned off (gnap.demoResourceServer).',
    spec: 'HTTP 404 GNAP invalid_request' },
  { code: 'STS-GNAP-0551',
    summary: 'The GNAP demonstration resource server was called with no ' +
      'access token; it answered with the RS-first challenge of RFC 9635 ' +
      'section 9.1.',
    spec: 'HTTP 401 invalid_token with WWW-Authenticate: GNAP as_uri, ' +
      'access, referrer' },
  { code: 'STS-GNAP-0552',
    summary: 'The GNAP demonstration resource server refused a presented ' +
      'token whose refusal carried no more specific code.',
    spec: 'HTTP 401 invalid_token (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0553',
    summary: 'A GNAP access token presented at the demonstration resource ' +
      'server does not grant the action (read or write) on its resource ' +
      'type.',
    spec: 'HTTP 403 insufficient_scope (WWW-Authenticate: GNAP)' },
  { code: 'STS-GNAP-0600',
    summary: 'A GNAP push interaction finish was not sent because ' +
      'gnap.pushFinish is off; the client learns the outcome when it ' +
      'continues.',
    spec: '' },
  { code: 'STS-GNAP-0601',
    summary: 'A GNAP push interaction finish URI is not one this service ' +
      'will dial; nothing was sent.',
    spec: '' },
  { code: 'STS-GNAP-0602',
    summary: 'A client answered a GNAP push interaction finish with a ' +
      'redirect, which is not followed.',
    spec: '' },
  { code: 'STS-GNAP-0603',
    summary: 'A client answered a GNAP push interaction finish with a ' +
      'status other than 2xx.',
    spec: '' },
  { code: 'STS-GNAP-0604',
    summary: 'A GNAP push interaction finish could not be started or ' +
      'delivered, or its response could not be read.',
    spec: '' },
  { code: 'STS-GNAP-0605',
    summary: 'A GNAP push interaction finish timed out.',
    spec: '' },
  { code: 'STS-GNAP-0650',
    summary: 'A GNAP monitor event is not in gnap_monitor.js\'s vocabulary ' +
      'and was not counted — a programming error.',
    spec: '' },
  { code: 'STS-GNAP-0651',
    summary: 'A GNAP monitor counter threw and was ignored; the grant ' +
      'itself was unaffected.',
    spec: '' },
  { code: 'STS-GNAP-0652',
    summary: 'An application entry carries a gnapKey that is not a JSON ' +
      'key object; it identifies nobody.',
    spec: '' },
  { code: 'STS-GNAP-0653',
    summary: 'A GNAP shared key on an application entry could not be ' +
      'opened with this process\'s key-encryption key, so the key ' +
      'reference was not resolved.',
    spec: '' },
  { code: 'STS-GNAP-0654',
    summary: 'A resource server\'s entry carries a gnapJweKey that is not ' +
      'JSON; jwt-encrypted tokens for it are encrypted to this ' +
      'authorization server instead.',
    spec: '' },
  { code: 'STS-GNAP-0655',
    summary: 'The macaroon root key could not be written onto a resource ' +
      'server\'s application entry.',
    spec: '' },
  { code: 'STS-GNAP-0660',
    summary: 'A GNAP console or management API revoke-grant names a grant ' +
      'that is not in this realm.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from ' +
      '/admin-api' },
  { code: 'STS-GNAP-0661',
    summary: 'A GNAP console or management API delete-resource-set names a ' +
      'resource set not registered in this realm.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from ' +
      '/admin-api' },
  { code: 'STS-GNAP-0662',
    summary: 'A GNAP console or management API action is not one of ' +
      'revoke-grant and delete-resource-set.',
    spec: 'Console error notice; HTTP 400 {ok: false, errors} from ' +
      '/admin-api' },
  { code: 'STS-GNAP-0663',
    summary: 'The query string of a GNAP console page failed validation.',
    spec: 'HTTP 400 text/plain' },
  { code: 'STS-GNAP-0664',
    summary: 'A GNAP console action form post failed validation.',
    spec: 'Console error notice' },
  { code: 'STS-GNAP-0665',
    summary: 'A GNAP management API action was refused and the refusal ' +
      'carried no more specific code.',
    spec: 'HTTP 400 {ok: false, errors}' },
  { code: 'STS-GNAP-0700',
    summary: 'The approver of a GNAP grant could not be recorded for the ' +
      'Shared Signals subject scope; the approval went ahead.',
    spec: '' },
  { code: 'STS-GNAP-0701',
    summary: 'A CAEP event about a GNAP grant or token could not be ' +
      'delivered.',
    spec: '' },
  { code: 'STS-GNAP-0710',
    summary: 'A continuation access token this process still held was ' +
      'already used by another process against the same store (the cluster ' +
      'claim, #46).',
    spec: 'invalid_continuation (HTTP 401)' },
  { code: 'STS-GNAP-0711',
    summary: 'An interaction reference this process still held was already ' +
      'presented to another process against the same store (the cluster ' +
      'claim, #46).',
    spec: 'invalid_interaction (HTTP 400)' },
  { code: 'STS-GNAP-0712',
    summary: 'An interaction start link (redirect or app) this process still ' +
      'held was already followed at another process against the same store ' +
      '(the cluster claim, #46).',
    spec: 'HTML page (HTTP 400)' },
  { code: 'STS-GNAP-0713',
    summary: 'A user code this process still held was already entered at ' +
      'another process against the same store (the cluster claim, #46).',
    spec: 'HTML page (HTTP 400)' },
  { code: 'STS-GNAP-0714',
    summary: 'A token management access token this process still held was ' +
      'already used by another process against the same store (the cluster ' +
      'claim, #46).',
    spec: 'invalid_rotation or invalid_request (HTTP 401)' },
  { code: 'STS-GNAP-0715',
    summary: 'A key proof (an HTTP message signature nonce or a JWS) this ' +
      'process had not seen was already accepted by another process against ' +
      'the same store (the cluster claim, #46).',
    spec: 'invalid_client, invalid_resource_server or invalid_token ' +
          '(HTTP 401)' },
  { code: 'STS-GNAP-0716',
    summary: 'The cluster claim store could not be asked about a GNAP ' +
      'single-use value, so the request was refused rather than accepted ' +
      'unproven.',
    spec: 'the refusal of the value it guarded' },
  { code: 'STS-GNAP-0717',
    summary: 'A resource owner\'s decision on a GNAP grant was refused ' +
      'because a decision on the same interaction had already been recorded, by ' +
      'another request or another node against the same store (the cluster ' +
      'claim, #46).',
    spec: 'RFC 9635 section 4 (an interaction is answered once)' },
  // ===== XACML =============================================================
  { code: 'STS-XACML-0001',
    summary: 'A request reached an XACML endpoint while the family is ' +
      'switched off (xacml.enabled).',
    spec: 'HTTP 501 not_implemented' },
  { code: 'STS-XACML-0002',
    summary: 'A request reached a remote-PEP endpoint or POST /xacml/pip ' +
      'while remote enforcement points are switched off ' +
      '(xacml.remotePeps).',
    spec: 'HTTP 501 not_implemented' },
  { code: 'STS-XACML-0003',
    summary: 'The XACML surface (GET /xacml, /xacml/pdp, /xacml/policies, ' +
      '/xacml/protected) was refused to a caller that presented no ' +
      'client certificate.',
    spec: 'HTTP 403 access_denied' },
  { code: 'STS-XACML-0004',
    summary: 'The XACML surface was refused to a caller whose client ' +
      'certificate did not verify against this service\'s truststore.',
    spec: 'HTTP 403 access_denied' },
  { code: 'STS-XACML-0005',
    summary: 'The XACML surface was refused to a verified certificate whose ' +
      'subject resolves to no directory entry holding XACML_USER (not ' +
      'in roles.xacmlUserGroup).',
    spec: 'HTTP 403 access_denied' },
  { code: 'STS-XACML-0006',
    summary: 'The XACML surface was refused by the access policy to a ' +
      'verified caller that does hold XACML_USER — an operator-edited ' +
      'access-control document denied it.',
    spec: 'HTTP 403 access_denied' },
  { code: 'STS-XACML-0007',
    summary: 'A remote-PEP endpoint (/xacml/pep/*, POST /xacml/pip) was ' +
      'refused to a caller that presented no client certificate.',
    spec: 'HTTP 403 access_denied (PIPError XML on /xacml/pip)' },
  { code: 'STS-XACML-0008',
    summary: 'A remote-PEP endpoint was refused to a caller whose client ' +
      'certificate did not verify against this service\'s truststore.',
    spec: 'HTTP 403 access_denied' },
  { code: 'STS-XACML-0009',
    summary: 'A remote-PEP endpoint was refused to a verified certificate ' +
      'whose subject resolves to no directory entry holding ' +
      'REMOTE_PEPS (not in roles.remotePepGroup).',
    spec: 'HTTP 403 access_denied' },
  { code: 'STS-XACML-0010',
    summary: 'A remote-PEP endpoint was refused by the access policy to a ' +
      'verified caller that does hold REMOTE_PEPS — an ' +
      'operator-edited access-control document denied it.',
    spec: 'HTTP 403 access_denied' },
  { code: 'STS-XACML-0011',
    summary: 'A decision request to POST /xacml/pdp was not a well-formed ' +
      'JSON Profile request.',
    spec: 'HTTP 400 invalid_request' },
  { code: 'STS-XACML-0012',
    summary: 'A decision could not be made because the repository\'s root ' +
      'policy does not load; the PDP answered Indeterminate.',
    spec: 'HTTP 200 with decision Indeterminate (XACML status ' +
      'syntax-error); GET /xacml/protected may then refuse with 403' },
  { code: 'STS-XACML-0013',
    summary: 'The engine reached Indeterminate through a processing or ' +
      'syntax error while evaluating a policy (not a missing ' +
      'attribute).',
    spec: 'HTTP 200 with decision Indeterminate (XACML status ' +
      'processing-error or syntax-error); GET /xacml/protected may ' +
      'then refuse with 403' },
  { code: 'STS-XACML-0014',
    summary: 'The embedded demonstration PEP at GET /xacml/protected refused ' +
      'the subject because the decision was not one its bias allows.',
    spec: 'HTTP 403 with the PEP\'s JSON enforcement answer' },
  { code: 'STS-XACML-0015',
    summary: 'The embedded demonstration PEP refused a Permit because the ' +
      'decision carried an obligation it cannot discharge (XACML 3.0 ' +
      'section 7.2).',
    spec: 'HTTP 403 with the PEP\'s JSON enforcement answer' },
  { code: 'STS-XACML-0016',
    summary: 'GET /xacml was asked with a format or bias query parameter ' +
      'outside its allowed values.',
    spec: 'HTTP 400 text/plain' },
  { code: 'STS-XACML-0017',
    summary: 'A remote PEP registration arrived on a plain HTTP listener, ' +
      'which cannot carry the client certificate ' +
      'xacml.pepRequireCertificate demands.',
    spec: 'HTTP 401 invalid_client' },
  { code: 'STS-XACML-0018',
    summary: 'A remote PEP registration arrived over TLS with no client ' +
      'certificate while xacml.pepRequireCertificate is on.',
    spec: 'HTTP 401 invalid_client' },
  { code: 'STS-XACML-0019',
    summary: 'A remote PEP registration produced no usable name from the ' +
      'certificate\'s common name or the body\'s name.',
    spec: 'HTTP 400 invalid_request' },
  { code: 'STS-XACML-0020',
    summary: 'A remote PEP heartbeat named no PEP, neither by certificate ' +
      'nor by body.',
    spec: 'HTTP 400 invalid_request' },
  { code: 'STS-XACML-0021',
    summary: 'A remote PEP heartbeat named a PEP that is not registered in ' +
      'ou=peps.',
    spec: 'HTTP 404 invalid_request' },
  { code: 'STS-XACML-0022',
    summary: 'POST /xacml/pip was rate-limited (xacml.pipMaxPerWindow over ' +
      'security.rateLimitWindowS).',
    spec: 'HTTP 429 too_many_requests (PIPError XML) with Retry-After' },
  { code: 'STS-XACML-0023',
    summary: 'A PIP query was not a well-formed <PIPRequest> carrying a ' +
      '<Request> and at least one <AttributeDesignator>.',
    spec: 'HTTP 400 invalid_request (PIPError XML)' },
  { code: 'STS-XACML-0024',
    summary: 'A PIP query named more designators than ' +
      'xacml.pipMaxDesignators allows.',
    spec: 'HTTP 400 invalid_request (PIPError XML)' },
  { code: 'STS-XACML-0025',
    summary: 'A PIP query carried a designator field or subject-id that is ' +
      'over its length cap or contains a control character.',
    spec: 'HTTP 400 invalid_request (PIPError XML)' },
  { code: 'STS-XACML-0026',
    summary: 'A write to ou=policies, ou=peps or ou=roles was refused ' +
      'because no embedded directory is loaded in this process.',
    spec: 'console: 303 back to the page with error=…; /admin-api: HTTP ' +
      '400 { ok: false, errors }; remote PEP register/heartbeat: HTTP ' +
      '400/404 invalid_request' },
  { code: 'STS-XACML-0027',
    summary: 'The embedded directory refused a write or removal in ' +
      'ou=policies, ou=peps or ou=roles — usually a container at its ' +
      'maximum.',
    spec: 'console: 303 back to the page with error=…; /admin-api: HTTP ' +
      '400 { ok: false, errors }; remote PEP register/heartbeat: HTTP ' +
      '400/404 invalid_request' },
  { code: 'STS-XACML-0028',
    summary: 'A policy document was refused at write: it does not parse or ' +
      'fails XACML static type checking.',
    spec: 'console: 303 back to the page with error=…; /admin-api: HTTP ' +
      '400 { ok: false, errors }' },
  { code: 'STS-XACML-0029',
    summary: 'A policy write named an entry that is not 1 to 128 letters, ' +
      'digits, dot, dash or underscore.',
    spec: 'console: 303 back to the page with error=…; /admin-api: HTTP ' +
      '400 { ok: false, errors }' },
  { code: 'STS-XACML-0030',
    summary: 'A policy write asked to be the root while another policy ' +
      'already is.',
    spec: 'console: 303 back to the page with error=…; /admin-api: HTTP ' +
      '400 { ok: false, errors }' },
  { code: 'STS-XACML-0031',
    summary: 'An XACML console action was refused because the console ' +
      'session holds Admin Read and not Admin Write.',
    spec: '303 back to the page with error=…, or HTTP 400 { ok: false, ' +
      'why } for a JSON post' },
  { code: 'STS-XACML-0032',
    summary: 'An XACML console or management API action named an action that ' +
      'does not exist.',
    spec: 'console: 303 back to the page with error=…; /admin-api: HTTP ' +
      '400 { ok: false, errors }' },
  { code: 'STS-XACML-0033',
    summary: 'An XACML repository or editor action named a policy that is ' +
      'not in the repository.',
    spec: 'console: 303 back to the page with error=…; /admin-api: HTTP ' +
      '400 { ok: false, errors }' },
  { code: 'STS-XACML-0034',
    summary: 'The editor was asked to edit a stored policy that does not ' +
      'load.',
    spec: 'console: 303 back to the page with error=…; /admin-api: HTTP ' +
      '400 { ok: false, errors }' },
  { code: 'STS-XACML-0035',
    summary: 'The guided policy editor refused an edit (a path, node kind or ' +
      'argument that the grammar does not allow).',
    spec: 'console: 303 back to the page with error=…; /admin-api: HTTP ' +
      '400 { ok: false, errors }' },
  { code: 'STS-XACML-0036',
    summary: 'A policy could not be created because the named template ' +
      'refused to build (unknown template or bad parameter).',
    spec: 'console: 303 back to the page with error=…; /admin-api: HTTP ' +
      '400 { ok: false, errors }' },
  { code: 'STS-XACML-0037',
    summary: 'An ALFA import did not parse.',
    spec: 'console: 303 back to the page with error=…; /admin-api: HTTP ' +
      '400 { ok: false, errors }' },
  { code: 'STS-XACML-0038',
    summary: 'A remote PEP console action named no PEP, or one that is not ' +
      'registered.',
    spec: 'console: 303 back to the page with error=…; /admin-api: HTTP ' +
      '400 { ok: false, errors }' },
  { code: 'STS-XACML-0039',
    summary: 'An issuance was refused because the issuance policy answered ' +
      'Deny.',
    spec: 'the issuance site\'s own protocol refusal (for example OAuth ' +
      'access_denied)' },
  { code: 'STS-XACML-0040',
    summary: 'An issuance was refused because the issuance policy answered ' +
      'NotApplicable.',
    spec: 'the issuance site\'s own protocol refusal (for example OAuth ' +
      'access_denied)' },
  { code: 'STS-XACML-0041',
    summary: 'An issuance was refused because the issuance policy could not ' +
      'be evaluated (Indeterminate).',
    spec: 'the issuance site\'s own protocol refusal (for example OAuth ' +
      'access_denied)' },
  { code: 'STS-XACML-0042',
    summary: 'An issuance for an application that requires a role was ' +
      'refused FAIL-CLOSED because no issuance policy is loaded ' +
      '(disabled, not loading, or the built-in template failed).',
    spec: 'the issuance site\'s own protocol refusal (for example OAuth ' +
      'access_denied)' },
  { code: 'STS-XACML-0043',
    summary: 'No issuance policy is loaded; issuance to applications ' +
      'requiring only EVERYBODY is not being gated (logged once per ' +
      'process).',
    spec: '' },
  { code: 'STS-XACML-0044',
    summary: 'Access to a gated surface was refused because the access ' +
      'policy answered Deny.',
    spec: 'the gated surface\'s own refusal (for example HTTP 403)' },
  { code: 'STS-XACML-0045',
    summary: 'Access to a gated surface was refused because the access ' +
      'policy could not be evaluated (Indeterminate).',
    spec: 'the gated surface\'s own refusal (for example HTTP 403)' },
  { code: 'STS-XACML-0046',
    summary: 'Access to a gated surface was refused because the access ' +
      'policy answered NotApplicable under deny-unless-permit.',
    spec: 'the gated surface\'s own refusal (for example HTTP 403)' },
  { code: 'STS-XACML-0047',
    summary: 'The access policy named by xacml.accessPolicy is disabled, so ' +
      'access to every gated surface is ALLOWED without a policy ' +
      'decision.',
    spec: '' },
  { code: 'STS-XACML-0048',
    summary: 'The access policy named by xacml.accessPolicy does not load, ' +
      'so access to every gated surface is ALLOWED without a policy ' +
      'decision.',
    spec: '' },
  { code: 'STS-XACML-0049',
    summary: 'The built-in access-control policy could not be built from its ' +
      'template (a defect), so access to every gated surface is ' +
      'ALLOWED without a policy decision.',
    spec: '' },
  { code: 'STS-XACML-0050',
    summary: 'common/access_gate.js was given a decider that is not a ' +
      'function; every access decision is allowed.',
    spec: '' },
  { code: 'STS-XACML-0051',
    summary: 'The access gate\'s decider threw; access was ALLOWED because a ' +
      'throw is a defect rather than a decision.',
    spec: '' },
  { code: 'STS-XACML-0052',
    summary: 'The issuance gate\'s decider threw; issuance was ALLOWED ' +
      'because a throw is a defect rather than a decision.',
    spec: '' },
  { code: 'STS-XACML-0053',
    summary: 'The role register threw while resolving a party\'s roles; only ' +
      'the built-in roles were used.',
    spec: '' },
  { code: 'STS-XACML-0054',
    summary: 'The role register threw while building the roles claim; the ' +
      'token or assertion was issued without it.',
    spec: '' },
  { code: 'STS-XACML-0055',
    summary: 'A role write named an invalid role name, or the name of a ' +
      'built-in role.',
    spec: 'console: 303 back to the page with error=…; /admin-api: HTTP ' +
      '400 { ok: false, errors }' },
  { code: 'STS-XACML-0056',
    summary: 'A role removal named a built-in role, which is computed and ' +
      'cannot be deleted.',
    spec: 'console: 303 back to the page with error=…; /admin-api: HTTP ' +
      '400 { ok: false, errors }' },
  { code: 'STS-XACML-0057',
    summary: 'A role removal named a role that does not exist.',
    spec: 'console: 303 back to the page with error=…; /admin-api: HTTP ' +
      '400 { ok: false, errors }' },
  { code: 'STS-XACML-0058',
    summary: 'A stored, enabled policy does not parse, so it was left out of ' +
      'the repository a decision resolves references against.',
    spec: '' },
  { code: 'STS-XACML-0059',
    summary: 'The seeded policy was refused when ou=policies was created.',
    spec: '' },
  { code: 'STS-XACML-0060',
    summary: 'The policy repository\'s change observer threw after a ' +
      'successful write; the write stands.',
    spec: '' },
  { code: 'STS-XACML-0061',
    summary: 'A directory value the PIP read does not parse at the datatype ' +
      'the policy designates, so it was dropped from the bag.',
    spec: '' },
  { code: 'STS-XACML-0062',
    summary: 'A decision counter behind /admin/xacml/monitor threw; nothing ' +
      'was counted and the decision is unaffected.',
    spec: '' },
  { code: 'STS-XACML-0063',
    summary: 'A decision was recorded against an asker the monitor\'s ' +
      'catalogue does not know, so it was not counted.',
    spec: '' },
  { code: 'STS-XACML-0064',
    summary: 'A realm\'s remote PEP register could not be read (for the ' +
      'monitor or the other-realms hint); that part was reported as ' +
      'empty.',
    spec: '' },
  { code: 'STS-XACML-0065',
    summary: 'The change-nudge dispatcher threw, which is a defect rather ' +
      'than an unreachable PEP; no policy change is lost.',
    spec: '' },
  { code: 'STS-XACML-0066',
    summary: 'A change nudge was not sent because the PEP\'s notify URL is ' +
      'outside the outbound bounds (not a URL, wrong scheme, plain ' +
      'http without xacml.pepNotifyAllowInsecure, or a host not in ' +
      'xacml.pepNotifyAllowedHosts).',
    spec: '' },
  { code: 'STS-XACML-0067',
    summary: 'A PEP\'s notify endpoint answered a change nudge with a ' +
      'redirect, which is not followed.',
    spec: '' },
  { code: 'STS-XACML-0068',
    summary: 'A PEP\'s notify endpoint answered a change nudge with a ' +
      'non-2xx status.',
    spec: '' },
  { code: 'STS-XACML-0069',
    summary: 'A PEP\'s notify endpoint did not answer a change nudge within ' +
      'xacml.pepNotifyTimeoutMs.',
    spec: '' },
  { code: 'STS-XACML-0070',
    summary: 'A change nudge could not be delivered because the connection ' +
      'to the PEP\'s notify endpoint failed.',
    spec: '' },
  { code: 'STS-XACML-0071',
    summary: 'An HTTPS listener certificate was asked for a PEP that is not ' +
      'registered in this realm, so there is no realm to issue it from.',
    spec: 'console: a page saying so; /admin-api: HTTP 400 ' +
      '{ ok: false, errors }' },
  { code: 'STS-XACML-0072',
    summary: 'A remote PEP\'s HTTPS listener certificate could not be ' +
      'issued: the certificate authority refused it, or issuing threw.',
    spec: 'console: a page saying so; /admin-api: HTTP 400 ' +
      '{ ok: false, errors }, or 500 when issuing threw' },
  // ===== XPEP ==============================================================
  { code: 'STS-XPEP-0001',
    summary: 'The error-code registry could not be loaded from ./error_codes ' +
      'or ../common/error_codes; the container starts anyway and ' +
      'tags its lines with a local fallback. In the image, the ' +
      'Dockerfile stopped copying common/error_codes.js.',
    spec: '' },
  { code: 'STS-XPEP-0002',
    summary: 'The version module could not be loaded from ./version or ' +
      '../common/version, so the PEP registers and reports its ' +
      'version as \'unknown\'. In the image, the Dockerfile stopped ' +
      'copying common/version.js and VERSION.',
    spec: '' },
  { code: 'STS-XPEP-0003',
    summary: 'PEP_TLS_CERT, PEP_TLS_KEY or PEP_TLS_CA names a file that ' +
      'could not be read; the PEP carries on without it, so it ' +
      'registers unauthenticated or is refused.',
    spec: '' },
  { code: 'STS-XPEP-0004',
    summary: 'The policy permitted the request but the decision carries an ' +
      'obligation this PEP cannot discharge, so section 7.2 turned ' +
      'the Permit into a refusal.',
    spec: 'HTTP 403 from GET /protected' },
  { code: 'STS-XPEP-0005',
    summary: 'A decision was asked for while the PEP holds no root policy ' +
      '(it has never pulled one, or what it pulled had no root); the ' +
      'decision is NotApplicable and the bias settles it.',
    spec: 'HTTP 403 from GET /protected when deny-biased, 200 when ' +
      'permit-biased' },
  { code: 'STS-XPEP-0006',
    summary: 'The engine answered Indeterminate for a request against the ' +
      'policy this PEP holds (a processing or missing-attribute ' +
      'error); the bias settles it.',
    spec: 'HTTP 403 from GET /protected when deny-biased, 200 when ' +
      'permit-biased' },
  { code: 'STS-XPEP-0007',
    summary: 'A request arrived whose URL would not parse, so it could name ' +
      'none of the PEP\'s endpoints.',
    spec: 'HTTP 400' },
  { code: 'STS-XPEP-0008',
    summary: 'Deciding a GET /protected request threw inside the PEP (the ' +
      'PIP, the engine or enforcement), so no decision was reached. A ' +
      'defect in the PEP, not a Deny.',
    spec: 'HTTP 500 decision_failed' },
  { code: 'STS-XPEP-0009',
    summary: 'A request named a method and path the PEP does not answer (it ' +
      'answers GET /, GET /protected, POST /notify and GET ' +
      '/healthcheck).',
    spec: 'HTTP 404 not_found' },
  { code: 'STS-XPEP-0010',
    summary: 'A policy pull threw unexpectedly, from the nudge or from the ' +
      'poll timer. The policy already held is kept and the next poll ' +
      'tries again.',
    spec: '' },
  { code: 'STS-XPEP-0011',
    summary: 'Retrying the registration on the poll timer threw ' +
      'unexpectedly; the pull still runs and the registration is ' +
      'tried again next interval.',
    spec: '' },
  { code: 'STS-XPEP-0012',
    summary: 'The heartbeat, or the pull it triggers when the PDP says this ' +
      'copy is behind, threw unexpectedly. Reporting only; ' +
      'enforcement is unaffected.',
    spec: '' },
  { code: 'STS-XPEP-0013',
    summary: 'The PEP could not start (registration, first pull, timers or ' +
      'listener setup threw) and the process exits.',
    spec: '' },
  { code: 'STS-XPEP-0014',
    summary: 'The seven XACML engine modules were found neither beside ' +
      'engine.js nor one directory up, so the PEP cannot load and the ' +
      'process dies at require.',
    spec: '' },
  { code: 'STS-XPEP-0015',
    summary: 'The PEP could not reach the PDP to register (network, TLS, ' +
      'timeout or a PEP_PDP_URL that is not a URL). It still enforces ' +
      'and retries on every poll.',
    spec: '' },
  { code: 'STS-XPEP-0016',
    summary: 'The PDP refused the PEP\'s registration (a missing or ' +
      'unrecognised client certificate, a full register, a taken ' +
      'name, or remote PEPs turned off). It still enforces with what ' +
      'it can pull and retries on every poll.',
    spec: '' },
  { code: 'STS-XPEP-0017',
    summary: 'A policy pull could not reach the PDP. The last good policy ' +
      'set is kept and enforced, and the PEP reports itself stale.',
    spec: '' },
  { code: 'STS-XPEP-0018',
    summary: 'The PDP refused a policy pull or answered it with an ' +
      'unexpected status (commonly 403: no verified certificate ' +
      'holding REMOTE_PEPS; 501: remote PEPs off in that realm). The ' +
      'last good policy set is kept.',
    spec: '' },
  { code: 'STS-XPEP-0019',
    summary: 'The PDP answered a policy pull with 200 and a body that is not ' +
      'a policy set. The last good policy set is kept.',
    spec: '' },
  { code: 'STS-XPEP-0020',
    summary: 'One or more pulled policies would not parse or validate in ' +
      'this PEP and were left out, so its policy count disagrees with ' +
      'the PDP\'s.',
    spec: '' },
  { code: 'STS-XPEP-0021',
    summary: 'A policy pull succeeded but no pulled policy is the root, so ' +
      'there is nothing to evaluate and every decision is ' +
      'NotApplicable until one is.',
    spec: '' },
  { code: 'STS-XPEP-0022',
    summary: 'The heartbeat could not reach the PDP. Reporting only; ' +
      'enforcement is unaffected.',
    spec: '' },
  { code: 'STS-XPEP-0023',
    summary: 'The PDP refused the heartbeat or answered it with a status ' +
      'other than 200 (for example an unregistered PEP). Reporting ' +
      'only; enforcement is unaffected.',
    spec: '' },
  { code: 'STS-XPEP-0024',
    summary: 'The policy designates more access-subject attributes than one ' +
      'PIP query may carry, so none was fetched and every designator ' +
      'resolves to an empty bag.',
    spec: '' },
  { code: 'STS-XPEP-0025',
    summary: 'The PIP query to POST /xacml/pip could not be made (network, ' +
      'TLS, timeout or an unparsable PDP URL); the PEP decides on the ' +
      'request\'s own attributes alone.',
    spec: '' },
  { code: 'STS-XPEP-0026',
    summary: 'The PDP refused the PIP query or answered it with a status ' +
      'other than 200 (403 when the client certificate does not hold ' +
      'REMOTE_PEPS); the PEP decides on the request\'s own attributes ' +
      'alone.',
    spec: '' },
  { code: 'STS-XPEP-0027',
    summary: 'The PDP\'s answer to the PIP query would not parse as a ' +
      'PIPResponse, so every designator resolves to an empty bag.',
    spec: '' },
  { code: 'STS-XPEP-0028',
    summary: 'The PIP returned a value that is not valid at the datatype the ' +
      'policy\'s designator declares; the value is dropped rather ' +
      'than making the decision Indeterminate.',
    spec: '' },
  { code: 'STS-XPEP-0029',
    summary: 'Only one of PEP_HTTPS_CERT and PEP_HTTPS_KEY is set, so the ' +
      'PEP has no HTTPS listener. Plain HTTP is unaffected.',
    spec: '' },
  { code: 'STS-XPEP-0030',
    summary: 'The HTTPS certificate and key files could not be read, are not ' +
      'PEM, or do not belong together. A listener already serving keeps ' +
      'the pair it has; one not yet started waits for a usable pair.',
    spec: '' },
  { code: 'STS-XPEP-0031',
    summary: 'The HTTPS listener could not bind its port (commonly the port ' +
      'is taken). Plain HTTP and enforcement are unaffected.',
    spec: '' },
  { code: 'STS-XPEP-0032',
    summary: 'The certificate the HTTPS listener is serving is expired or ' +
      'not yet valid, so clients that check will refuse the handshake.',
    spec: '' },
  // ===== ADMIN =============================================================
  { code: 'STS-ADMIN-0001',
    summary: 'The admin console could not start a sign-in: its OIDC client ' +
      'entry (sts-admin-console) is missing or has no secret.',
    spec: 'HTTP 503 temporarily_unavailable (JSON) or a 503 page' },
  { code: 'STS-ADMIN-0002',
    summary: 'The admin console could not start a sign-in in product mode ' +
      'because the address it was reached at is not a registered ' +
      'redirect URI of sts-admin-console.',
    spec: 'HTTP 503 temporarily_unavailable (JSON) or a 503 page' },
  { code: 'STS-ADMIN-0003',
    summary: 'A console request that cannot be redirected to sign in (a JSON ' +
      'caller, or a form POST) carried no console session.',
    spec: 'HTTP 401 login_required' },
  { code: 'STS-ADMIN-0004',
    summary: 'A console sign-out was refused because the form did not carry ' +
      'this session\'s CSRF token.',
    spec: 'HTTP 403 csrf' },
  { code: 'STS-ADMIN-0005',
    summary: 'A console write (a non-GET request) was refused because it did ' +
      'not carry this session\'s CSRF token.',
    spec: 'HTTP 403 csrf' },
  { code: 'STS-ADMIN-0006',
    summary: 'The access policy (the XACML access-control document) refused ' +
      'a console request for a person who holds the console role it ' +
      'needs.',
    spec: 'HTTP 403 policy_denied' },
  { code: 'STS-ADMIN-0007',
    summary: 'A signed-in person without the Admin Read role tried to read a ' +
      'console page.',
    spec: 'HTTP 403 insufficient_role' },
  { code: 'STS-ADMIN-0008',
    summary: 'A signed-in person without the Admin Write role tried to post ' +
      'a console form.',
    spec: 'HTTP 403 insufficient_role' },
  { code: 'STS-ADMIN-0009',
    summary: 'A console request\'s query string failed validation (an ' +
      'over-long, repeated or malformed parameter).',
    spec: 'HTTP 400 page' },
  { code: 'STS-ADMIN-0010',
    summary: 'The admin console\'s OIDC callback refused the authorization ' +
      'response (state, code redemption, ID Token verification or ' +
      'session establishment failed).',
    spec: 'HTTP 400 page' },
  { code: 'STS-ADMIN-0011',
    summary: 'The admin console\'s OIDC callback threw rather than ' +
      'resolving; this is a defect in the relying-party code, not something ' +
      'a request can cause.',
    spec: 'HTTP 500 page' },
  { code: 'STS-ADMIN-0012',
    summary: 'A console action was refused (its result was not ok) and the ' +
      'action named no more specific code.',
    spec: 'HTTP 303 back to the page with error=, or HTTP 400 JSON' },
  { code: 'STS-ADMIN-0013',
    summary: 'An asynchronous console action (Shared Signals, CAEP, RISC or ' +
      'SPIFFE) rejected instead of resolving a refusal; it is ' +
      'answered as a refused action.',
    spec: 'HTTP 303 back to the page with error=, or HTTP 400 JSON' },
  { code: 'STS-ADMIN-0014',
    summary: 'A console inverted-hook slot was offered an incomplete filler ' +
      'at startup and refused it whole; the pages and operations ' +
      'behind it report the reader as not installed.',
    spec: '' },
  { code: 'STS-ADMIN-0015',
    summary: 'The startup check of SETTING_HOMES found a settings group ' +
      'drawn on no page, drawn twice, unknown to config.js, or sent ' +
      'to a path that is not a console page.',
    spec: '' },
  { code: 'STS-ADMIN-0016',
    summary: 'The new-user form\'s Fill with example data was refused ' +
      'because the service is running in product mode.',
    spec: 'HTTP 200 form page with a warning, or HTTP 400 JSON' },
  { code: 'STS-ADMIN-0017',
    summary: 'The new-user form\'s Fill with example data was pressed with ' +
      'no username to seed the example person from.',
    spec: 'HTTP 200 form page with a warning' },
  { code: 'STS-ADMIN-0018',
    summary: 'The new-user form was posted with an action other than create ' +
      'or fill.',
    spec: 'HTTP 200 form page with a warning, or HTTP 400 JSON' },
  { code: 'STS-ADMIN-0019',
    summary: 'The admin console\'s Shared Signals receive endpoint refused a ' +
      'pushed Security Event Token and the receiver named no more ' +
      'specific code.',
    spec: 'HTTP 4xx/5xx per RFC 8935, as the receiver decided' },
  { code: 'STS-ADMIN-0020',
    summary: 'The realm switcher named a trust realm that is not defined; ' +
      'the browser was sent back to the current realm.',
    spec: 'HTTP 303 to the current realm' },
  { code: 'STS-ADMIN-0021',
    summary: 'A console drill-down named a record that does not exist: an ' +
      'application, an authorization server profile, a trust realm or ' +
      'a federation relationship.',
    spec: 'HTTP 200 page saying there is no such record' },
  { code: 'STS-ADMIN-0022',
    summary: 'The realm switcher was given a return path that is not a ' +
      'single-slash-rooted path (a possible open redirect); /admin ' +
      'was used instead.',
    spec: 'HTTP 303 to /admin in the chosen realm' },
  { code: 'STS-ADMIN-0500',
    summary: 'An admin console control or management API action named an ' +
      'operation its resource does not have.',
    spec: 'HTTP 400 (API JSON errors) or a 303 back to the console page ' +
      'with error=' },
  { code: 'STS-ADMIN-0501',
    summary: 'An admin action needs a module that is not loaded in this ' +
      'process (the logout reader, the directory or group writer, the ' +
      'Shared Signals reporters, the XACML pages, or the ' +
      'client-certificate truststore), so there is nothing to act on.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0502',
    summary: 'A token revoke or restore named no jti and no token to read ' +
      'one from.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0503',
    summary: 'An artifact revoke or restore named no credential handle.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0504',
    summary: 'An artifact revoke or restore named a handle this service no ' +
      'longer holds (never issued, or forgotten to the cap).',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0505',
    summary: 'A token-set revoke or restore named no set.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0506',
    summary: 'A token-set revoke or restore named a set this service no ' +
      'longer holds.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0507',
    summary: 'A token-set revoke was refused because nothing in the set ' +
      'carries an identifier to revoke.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0508',
    summary: 'A revoke-by-kind named a credential kind that cannot be ' +
      'revoked.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0509',
    summary: 'A bulk token revocation by subject or by user named nobody.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0510',
    summary: 'A session revoke on /admin/sessions did not carry both the ' +
      'identity key and the session id.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0511',
    summary: 'A session revoke ended nothing: the session had already ended, ' +
      'or the logout module skipped it.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0512',
    summary: 'An /admin/logout action named no identity to act on.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0513',
    summary: 'An /admin/logout end action was posted with nothing selected.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0514',
    summary: 'A delegated-permission action that edits the exposing ' +
      'application named no resource application.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0515',
    summary: 'A delegated-permission grant or revoke named no client ' +
      'application.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0516',
    summary: 'The delegated-permission register refused a change made from ' +
      'the console or the management API.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0517',
    summary: 'The XACML administration pages refused an action reached ' +
      'through the management API.',
    spec: 'HTTP 400 (API)' },
  { code: 'STS-ADMIN-0518',
    summary: 'A users action that acts on one person (activation link, ' +
      'password, second-factor clear) named nobody.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0519',
    summary: 'An activation link could not be issued for the named person.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0520',
    summary: 'An operator\'s clear of a person\'s authenticator app was ' +
      'refused.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0521',
    summary: 'An operator\'s clear of a person\'s recovery codes was refused.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0522',
    summary: 'An operator\'s removal of a person\'s security key was refused ' +
      '(no such key, or it is their last way in).',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0523',
    summary: 'A set-password action sent neither a password nor a request to ' +
      'generate one.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0524',
    summary: 'A set-password action\'s password and confirmation did not ' +
      'match.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0525',
    summary: 'A password set by an operator was refused by the password ' +
      'policy or could not be written.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0526',
    summary: 'Creating a person from the console or the management API was ' +
      'refused by the directory (a bad or taken username, or a ' +
      'refused attribute).',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0527',
    summary: 'Creating a group from the console or the management API was ' +
      'refused by the directory.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0528',
    summary: 'Adding a member to a group from the console or the management ' +
      'API was refused by the directory.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0529',
    summary: 'An applications action that edits one entry named no ' +
      'application.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0530',
    summary: 'The application registry refused to create an entry (including ' +
      'a SAML 2.0 service provider or SAML 1.1 relying party ' +
      'registered by hand).',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0531',
    summary: 'The application registry refused to change an attribute on an ' +
      'entry (including the SAML 2.0 logout service and signing ' +
      'certificate).',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0532',
    summary: 'Refreshing a service provider\'s SAML metadata from its ' +
      'configured URL failed.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0533',
    summary: 'A revoke-registration named an application the registry does ' +
      'not hold.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0534',
    summary: 'A revoke-registration named an application that has no RFC ' +
      '7591 registration to revoke.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0535',
    summary: 'The application registry refused to forget an entry.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0536',
    summary: 'The authorization server profile register refused a create, ' +
      'member change, reset or delete.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0537',
    summary: 'A SAML 2.0 service provider action named no entityID.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0538',
    summary: 'A SAML 1.1 relying party action named no identifier.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0539',
    summary: 'A console role grant or revoke was refused and carried no more ' +
      'specific code.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0540',
    summary: 'The consent register refused a global consent change, a ' +
      'revocation or a forget.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0541',
    summary: 'Creating a role was refused because a role of that name ' +
      'already exists.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0542',
    summary: 'The role register refused a role write or delete (the name ' +
      'grammar, a built-in name, or the cap).',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0543',
    summary: 'A role action named a role that does not exist.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0544',
    summary: 'A role membership action named a member kind that is not user, ' +
      'group or application.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0545',
    summary: 'A role membership action named no member.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0546',
    summary: 'A role membership action named a built-in role, which is ' +
      'computed and has no membership to edit.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0547',
    summary: 'Adding a role member was refused because they already hold the ' +
      'role.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0548',
    summary: 'Removing a role member was refused because they do not hold ' +
      'the role.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0549',
    summary: 'Saving a password policy profile was refused (a missing or ' +
      'invalid field, or fields that contradict each other).',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0550',
    summary: 'Resetting a password policy profile to the built-in defaults ' +
      'was refused.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0551',
    summary: 'A claims action named a claim set this page or resource does ' +
      'not carry.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0552',
    summary: 'A claim set or its directory-attribute selection refused a ' +
      'change (a reserved or duplicate claim name, or an unknown ' +
      'attribute).',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0553',
    summary: 'Removing a claim was refused because the claim set has no ' +
      'claim of that name.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0554',
    summary: 'Replacing a claim set was refused because the claims posted ' +
      'are not valid JSON.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0555',
    summary: 'Replacing a claim set was refused because the claims posted ' +
      'are not a JSON array.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0556',
    summary: 'The verifiable credential claim selection refused a change.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0557',
    summary: 'A verifiable credential claim add or remove named no ' +
      'attribute.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0558',
    summary: 'Adding a verifiable credential claim was refused because it is ' +
      'already selected.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0559',
    summary: 'Removing a verifiable credential claim was refused because it ' +
      'is not selected.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0560',
    summary: 'Populating the directory for the verifiable credential claim ' +
      'set failed.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0561',
    summary: 'The OpenID4VP verifier configuration refused a change to the ' +
      'requested claims or the default format.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0562',
    summary: 'The trust realm registry refused a create, update, override ' +
      'change or removal.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0563',
    summary: 'A request tried to remove the trust realm it arrived in.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0564',
    summary: 'The settings table refused a change: an unknown or ' +
      'restart-only key, or a value that failed the setting\'s check.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0565',
    summary: 'A settings action was posted with no setting it recognises.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0566',
    summary: 'A token lifetime or SAML assertion settings action was given a ' +
      'field that page does not own.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0567',
    summary: 'A Shared Signals, CAEP or RISC console action was refused and ' +
      'carried no more specific code.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0568',
    summary: 'Adding client-certificate trust anchors was refused (nothing ' +
      'readable as a certificate, all already held, or the truststore ' +
      'full).',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0569',
    summary: 'Removing a client-certificate trust anchor was refused (no ' +
      'anchor with that fingerprint).',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0570',
    summary: 'The SPIFFE registry refused a registration entry create, ' +
      'update or delete.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0571',
    summary: 'A SPIFFE registration entry update or delete named no entry.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0572',
    summary: 'A SPIFFE registration entry update named a field that may not ' +
      'be changed.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0573',
    summary: 'A SPIFFE agent action named no agent.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0574',
    summary: 'The SPIFFE registry refused an agent ban, unban or delete.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0575',
    summary: 'The federation register refused a relationship create, change, ' +
      'enable, disable or delete.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0576',
    summary: 'A federation action named no relationship.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0577',
    summary: 'Rotating a SPIFFE X.509 or JWT authority from the console ' +
      'failed.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0578',
    summary: 'A SPIFFE authority rotation named neither x509, jwt nor both.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0579',
    summary: 'Setting a federated SPIFFE bundle named no trust domain.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0580',
    summary: 'A federated SPIFFE bundle was refused (not a readable bundle ' +
      'for that trust domain).',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0581',
    summary: 'Removing a federated SPIFFE bundle was refused because none is ' +
      'held for that trust domain.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0582',
    summary: 'A console role grant or revoke named a role that is neither ' +
      'Admin Read nor Admin Write.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0583',
    summary: 'A console role grant named somebody whose name cannot be a ' +
      'directory entry under ou=users.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0584',
    summary: 'A console role revoke named nobody.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0585',
    summary: 'The directory refused the group write behind a console role ' +
      'grant or revoke.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0586',
    summary: 'A console role revoke was refused because the person holds the ' +
      'role through a memberOf value on their own entry, which this ' +
      'console does not write.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0587',
    summary: 'The console roles\' directory slot was offered a filler ' +
      'missing required functions and was not installed; the roles read as ' +
      'having no directory.',
    spec: '' },
  { code: 'STS-ADMIN-0588',
    summary: 'A key pair export was refused because the caller does not hold ' +
      'Admin Write.',
    spec: 'HTTP 403' },
  { code: 'STS-ADMIN-0589',
    summary: 'A key pair export named a key this realm does not hold.',
    spec: 'HTTP 400 (JSON or API) or a 303 with error=' },
  { code: 'STS-ADMIN-0590',
    summary: 'A key pair export was refused because the key has not been ' +
      'generated yet, or has no exportable encoding.',
    spec: 'HTTP 400 (JSON or API) or a 303 with error=' },
  { code: 'STS-ADMIN-0591',
    summary: 'A key pair export asked for a format that key does not offer.',
    spec: 'HTTP 400 (JSON or API) or a 303 with error=' },
  { code: 'STS-ADMIN-0592',
    summary: 'A key pair export found no PEM key pair for the key in this ' +
      'realm.',
    spec: 'HTTP 400 (JSON or API) or a 303 with error=' },
  { code: 'STS-ADMIN-0593',
    summary: 'The key exporter refused an export (for example a PKCS#12 with ' +
      'no password, or a key it cannot read).',
    spec: 'HTTP 400 (JSON or API) or a 303 with error=' },
  { code: 'STS-ADMIN-0594',
    summary: 'A key pair export threw unexpectedly.',
    spec: 'HTTP 400 (JSON) or a 303 with error=' },
  { code: 'STS-ADMIN-0595',
    summary: 'The crypto report was handed a malformed protocol family list ' +
      'and ignored it; its drift check does not run.',
    spec: '' },
  { code: 'STS-ADMIN-0596',
    summary: 'This build of the admin console offers no crypto reporter ' +
      'slot, so the management API cannot mirror the crypto and key ' +
      'pages.',
    spec: '' },
  { code: 'STS-ADMIN-0597',
    summary: 'The API explorer could not mint an access token for the ' +
      'reader; the page draws and Try it will be refused.',
    spec: '' },
  { code: 'STS-ADMIN-0598',
    summary: 'The /admin/database page threw while being drawn.',
    spec: 'HTTP 200 page saying it could not be drawn' },
  { code: 'STS-ADMIN-0599',
    summary: 'The /admin/secrets page threw while being drawn.',
    spec: 'HTTP 200 page saying it could not be drawn' },
  { code: 'STS-ADMIN-0600',
    summary: 'The delegation map picture could not be laid out; the page ' +
      'drew without it.',
    spec: '' },
  { code: 'STS-ADMIN-0601',
    summary: 'The federation map picture could not be laid out; the page ' +
      'drew without it.',
    spec: '' },
  // --- /admin/kerberos/principals (2026-09-12)
  { code: 'STS-ADMIN-0602',
    summary: 'A Kerberos principals action named an action the page does not ' +
      'have.',
    spec: 'HTTP 400 { ok: false, errors } / 303 with error=' },
  { code: 'STS-ADMIN-0603',
    summary: 'A Kerberos service principal action named something that is ' +
      'not a usable service principal name (fewer than two components, a ' +
      'foreign realm, krbtgt, or characters a principal may not carry).',
    spec: 'HTTP 400 { ok: false, errors } / 303 with error=' },
  { code: 'STS-ADMIN-0604',
    summary: 'A service principal was created for an SPN that already holds ' +
      'a stored key; rotate it instead.',
    spec: 'HTTP 400 { ok: false, errors } / 303 with error=' },
  { code: 'STS-ADMIN-0605',
    summary: 'A service principal was rotated or deleted and holds no stored ' +
      'key.',
    spec: 'HTTP 400 { ok: false, errors } / 303 with error=' },
  { code: 'STS-ADMIN-0606',
    summary: 'The application entry a service principal\'s key is stored on ' +
      'could not be found or created.',
    spec: 'HTTP 400 { ok: false, errors } / 303 with error=' },
  { code: 'STS-ADMIN-0607',
    summary: 'A Kerberos key could not be sealed or written, so nothing was ' +
      'stored and no keytab was handed out.',
    spec: 'HTTP 400 { ok: false, errors } / 303 with error=' },
  { code: 'STS-ADMIN-0608',
    summary: 'A clear-person-keys action named nobody, or somebody not in ' +
      'the default trust realm\'s directory.',
    spec: 'HTTP 400 { ok: false, errors } / 303 with error=' },
  { code: 'STS-ADMIN-0609',
    summary: 'The Kerberos key register has no directory in this process, so ' +
      'a principal could be neither listed nor changed.',
    spec: 'HTTP 400 { ok: false, errors } / 303 with error=' },
  { code: 'STS-ADMIN-0620',
    summary: 'Regenerating an application\'s client secret was refused: the ' +
      'application is not in the registry.',
    spec: 'HTTP 400 { ok: false, errors } / 303 with error=' },
  { code: 'STS-ADMIN-0640',
    summary: 'A certificate details view was asked for with a value that is ' +
      'not a SHA-256 certificate fingerprint (64 hexadecimal digits).',
    spec: 'the page with a dialog saying so / HTTP 400 { ok: false, errors }' },
  { code: 'STS-ADMIN-0641',
    summary: 'A certificate details view named a fingerprint this service ' +
      'does not hold in the trust realm the request was reached in.',
    spec: 'the page with a dialog saying so / HTTP 404 { ok: false, errors }' },
  { code: 'STS-ADMIN-0642',
    summary: 'A certificate this service holds could not be described or its ' +
      'chain could not be built.',
    spec: 'the page with a dialog saying so / HTTP 500 { ok: false, errors }' },
  { code: 'STS-ADMIN-0643',
    summary: 'The used-assertion history page could not be drawn, because ' +
      'the store holding the history could not be read.',
    spec: 'the page with a warning saying so' },
  { code: 'STS-ADMIN-0644',
    summary: 'An RFC 9728 protected resource metadata import was refused ' +
      '(load-resource-metadata), where the library named no code of its own.',
    spec: 'HTTP 400 (API), or /admin/applications/new redrawn with the reason' },
  { code: 'STS-ADMIN-0645',
    summary: 'A create from an imported RFC 9728 document was refused on ' +
      '/admin/applications/new, where the create named no code of its own, ' +
      'and the page was redrawn with the reason.',
    spec: '/admin/applications/new redrawn with the reason' },
  { code: 'STS-ADMIN-0646',
    summary: 'A software statement was asked to be issued for an application ' +
      'that is not in the registry.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-ADMIN-0647',
    summary: 'The client metadata given for a software statement to issue is ' +
      'not a JSON object, or the input validator refused it.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-ADMIN-0648',
    summary: 'The client metadata given for a software statement to issue ' +
      'names a JWT claim or a member only registration assigns.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-ADMIN-0649',
    summary: 'A software statement for an application could not be signed or ' +
      'written onto its entry.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-ADMIN-0650',
    summary: 'A software statement could not be issued because there was no ' +
      'issuer to name: no request address reached the action and ' +
      'oauth2.issuer is not set.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  // ----- the OAuth 2.0 / OIDC monitoring page (2026-09-13) -----------------
  { code: 'STS-ADMIN-0700',
    summary: 'The query string of /admin/oauth2/monitor did not match the ' +
      'shape the page accepts (state, client_id, page, per, clientsPage, ' +
      'offset, limit, format) and was refused before anything was read.',
    spec: 'HTTP 400 text/plain' },
  { code: 'STS-ADMIN-0701',
    summary: 'An OAuth 2.0 monitoring action named an action the page does ' +
      'not have; the refusal names the one it does.',
    spec: 'the caller\'s refusal (a 303 with error= on the console, HTTP 400 ' +
      '{ ok: false, errors } on /admin-api)' },
  { code: 'STS-ADMIN-0702',
    summary: 'A withdrawal of a pushed authorization request carried no ' +
      'request_uri, or one longer than the store could ever hold.',
    spec: 'the caller\'s refusal (a 303 with error= on the console, HTTP 400 ' +
      '{ ok: false, errors } on /admin-api)' },
  { code: 'STS-ADMIN-0703',
    summary: 'A withdrawal of a pushed authorization request named a value ' +
      'that is not in the urn:ietf:params:oauth:request_uri: namespace this ' +
      'service issues pushed request_uris from (RFC 9126 section 2.2).',
    spec: 'the caller\'s refusal (a 303 with error= on the console, HTTP 400 ' +
      '{ ok: false, errors } on /admin-api)' },
  { code: 'STS-ADMIN-0704',
    summary: 'A withdrawal named a request_uri this realm does not hold: it ' +
      'was never pushed here, it expired and was swept, or it was already ' +
      'withdrawn.',
    spec: 'the caller\'s refusal (a 303 with error= on the console, HTTP 400 ' +
      '{ ok: false, errors } on /admin-api)' },
  { code: 'STS-ADMIN-0705',
    summary: 'An OAuth 2.0 monitoring console action threw; nothing is known ' +
      'to have changed and the log line carries the stack.',
    spec: 'a 303 back to /admin/oauth2/monitor with error=' },
  { code: 'STS-ADMIN-0706',
    summary: 'The bootstrap administrator could not be created in the ' +
      'default realm, or could not be given both console roles, at startup.',
    spec: 'none — logged' },
  { code: 'STS-ADMIN-0720',
    summary: 'Issuing an application a TLS client certificate was refused ' +
      'with no more specific code (the key algorithm, the label or the ' +
      'realm\'s certificate authority).',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-ADMIN-0721',
    summary: 'An application TLS client certificate\'s file password was ' +
      'too short, too long, or not the same twice.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-ADMIN-0722',
    summary: 'An application TLS client certificate action named an ' +
      'application the registry does not hold.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-ADMIN-0723',
    summary: 'Revoking an application\'s TLS client certificate was refused ' +
      'with no more specific code.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-ADMIN-0724',
    summary: 'An asynchronous applications action on the console threw; ' +
      'nothing is known to have changed and the log line carries the stack.',
    spec: 'the console\'s refusal (a redirect with the error)' },
  // THE PASSWORD AND SECOND-FACTOR CONTROLS ON A PERSON'S PAGE (2026-09-13).
  { code: 'STS-ADMIN-0780',
    summary: 'Resetting somebody\'s password was refused by the password ' +
      'policy or the store.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0781',
    summary: 'Issuing somebody a password reset link was refused (nobody by ' +
      'that name, or no store).',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0782',
    summary: 'A password reset link was issued and the person\'s password ' +
      'could not be removed, so the link was withdrawn.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0783',
    summary: 'Disabling somebody\'s primary security keys was refused.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0784',
    summary: 'Disabling somebody\'s second factors was refused.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  { code: 'STS-ADMIN-0785',
    summary: 'Requiring, or no longer requiring, a second factor of somebody ' +
      'was refused.',
    spec: 'HTTP 400 (API) or a 303 with error=' },
  // PER-REALM ADMINISTRATORS (2026-09-14, #32).
  { code: 'STS-ADMIN-0786',
    summary: 'A realm administrator reached the console in a realm other than ' +
      'the one they signed in through, where they hold no role.',
    spec: 'HTTP 403 on /admin' },
  { code: 'STS-ADMIN-0787',
    summary: 'A realm administrator was refused a service-wide console page ' +
      'or action (the store, the listeners, the service Root, the realm ' +
      'registry, another realm).',
    spec: 'HTTP 403 on /admin' },
  { code: 'STS-ADMIN-0788',
    summary: 'A realm administrator posted a setting that names the whole ' +
      'service rather than their realm.',
    spec: 'HTTP 403 on /admin' },
  { code: 'STS-ADMIN-0789',
    summary: 'A new trust realm\'s bootstrap administrator could not be given ' +
      'its generated password in product mode.',
    spec: 'none — logged' },
  { code: 'STS-ADMIN-0790',
    summary: 'The realm chooser in front of /admin was asked for a realm ' +
      'that is not defined.',
    spec: 'HTTP 400 on /admin' },
  // ===== API ===============================================================
  { code: 'STS-API-0001',
    summary: 'A management API request carried no Bearer access token while ' +
      'adminApi.authRequired is on.',
    spec: 'HTTP 401 unauthorized, WWW-Authenticate: Bearer' },
  { code: 'STS-API-0002',
    summary: 'A management API access token was not signed by this service ' +
      '(the default realm\'s key), or its signature did not verify.',
    spec: 'HTTP 401 invalid_token, WWW-Authenticate: Bearer ' +
      'error="invalid_token"' },
  { code: 'STS-API-0003',
    summary: 'A management API access token had expired.',
    spec: 'HTTP 401 invalid_token, WWW-Authenticate: Bearer ' +
      'error="invalid_token"' },
  { code: 'STS-API-0004',
    summary: 'A management API access token was audienced to a different ' +
      'resource server than /admin-api.',
    spec: 'HTTP 403 forbidden' },
  { code: 'STS-API-0005',
    summary: 'The XACML access policy refused a management API request made ' +
      'with a valid token, usually because the token lacks the ' +
      'admin:read or admin:write scope the method needs.',
    spec: 'HTTP 403 forbidden' },
  { code: 'STS-API-0006',
    summary: 'In product mode with the token gate off, the XACML access ' +
      'policy refused a management API caller who does hold a console ' +
      'role.',
    spec: 'HTTP 403 forbidden' },
  { code: 'STS-API-0007',
    summary: 'In product mode with the token gate off, a management API ' +
      'request arrived with nobody signed in.',
    spec: 'HTTP 401 JSON (HTTP 403 page for a browser)' },
  { code: 'STS-API-0008',
    summary: 'In product mode with the token gate off, a signed-in ' +
      'management API caller did not hold the console role the method ' +
      'needs.',
    spec: 'HTTP 403 forbidden (HTTP 403 page for a browser)' },
  { code: 'STS-API-0009',
    summary: 'A management API request body did not match the operation\'s ' +
      'JSON Schema (an unknown member or a wrong type).',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0010',
    summary: 'A management API request schema would not compile at startup, ' +
      'so that operation runs unvalidated.',
    spec: '' },
  { code: 'STS-API-0011',
    summary: 'The crypto reporter slot that admin-ui/crypto_metadata.js ' +
      'fills was not installed, so the crypto report, the key list or ' +
      'a key export could not be answered.',
    spec: 'HTTP 503 { ok: false, errors }' },
  { code: 'STS-API-0012',
    summary: 'The database report could not be built (the probe run ' +
      'rejected).',
    spec: 'HTTP 500 { ok: false, errors }' },
  { code: 'STS-API-0013',
    summary: 'The secret-store report could not be built (the probe run ' +
      'rejected).',
    spec: 'HTTP 500 { ok: false, errors }' },
  { code: 'STS-API-0014',
    summary: 'A key export request named an action other than export.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0015',
    summary: 'A key export was refused (an unknown key, an unsupported ' +
      'format, or a missing PKCS#12 password) and the refusal carried ' +
      'no more specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0016',
    summary: 'A key export threw while the keystore file was being built.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0017',
    summary: 'The TLS truststore reader is not installed in this process, so ' +
      'the truststore could not be reported.',
    spec: 'HTTP 503' },
  { code: 'STS-API-0018',
    summary: 'The Shared Signals action rejected instead of resolving a ' +
      'refusal, which is a defect in ssf/ssf.js.',
    spec: 'HTTP 500 { ok: false, errors }' },
  { code: 'STS-API-0019',
    summary: 'The CAEP action rejected instead of resolving a refusal.',
    spec: 'HTTP 500 { ok: false, errors }' },
  { code: 'STS-API-0020',
    summary: 'The RISC action rejected instead of resolving a refusal.',
    spec: 'HTTP 500 { ok: false, errors }' },
  { code: 'STS-API-0021',
    summary: 'The PKI action rejected (certificate authority or key ' +
      'generation threw).',
    spec: 'HTTP 500 { ok: false, errors }' },
  { code: 'STS-API-0022',
    summary: 'The SPIFFE action rejected (an authority rotation or key ' +
      'generation threw).',
    spec: 'HTTP 500 { ok: false, errors }' },
  { code: 'STS-API-0030',
    summary: 'A management API users action was refused (including an ' +
      'unknown action) and the action layer attached no more specific ' +
      'code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0031',
    summary: 'A management API sessions action was refused (including an ' +
      'unknown action) and the action layer attached no more specific ' +
      'code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0032',
    summary: 'A management API sign-out (logout) action was refused ' +
      '(including an unknown action) and the action layer attached no ' +
      'more specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0033',
    summary: 'A management API groups action was refused (including an ' +
      'unknown action) and the action layer attached no more specific ' +
      'code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0034',
    summary: 'A management API admin roles (rbac) action was refused ' +
      '(including an unknown action) and the action layer attached no ' +
      'more specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0035',
    summary: 'A management API multi-factor (mfa) action was refused ' +
      '(including an unknown action) and the action layer attached no ' +
      'more specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0036',
    summary: 'A management API tokens action was refused (including an ' +
      'unknown action) and the action layer attached no more specific ' +
      'code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0037',
    summary: 'A management API trust realms action was refused (including an ' +
      'unknown action) and the action layer attached no more ' +
      'specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0038',
    summary: 'A management API configuration action was refused (including ' +
      'an unknown action) and the action layer attached no more ' +
      'specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0039',
    summary: 'A management API token lifetimes action was refused (including ' +
      'an unknown action) and the action layer attached no more ' +
      'specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0040',
    summary: 'A management API SAML assertions action was refused (including ' +
      'an unknown action) and the action layer attached no more ' +
      'specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0041',
    summary: 'A management API claims action was refused (including an ' +
      'unknown action) and the action layer attached no more specific ' +
      'code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0042',
    summary: 'A management API UserInfo claims action was refused (including ' +
      'an unknown action) and the action layer attached no more ' +
      'specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0043',
    summary: 'A management API custom SAML attributes action was refused ' +
      '(including an unknown action) and the action layer attached no ' +
      'more specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0044',
    summary: 'A management API credential claims action was refused ' +
      '(including an unknown action) and the action layer attached no ' +
      'more specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0045',
    summary: 'A management API verifier request action was refused ' +
      '(including an unknown action) and the action layer attached no ' +
      'more specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0046',
    summary: 'A management API federation action was refused (including an ' +
      'unknown action) and the action layer attached no more specific ' +
      'code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0047',
    summary: 'A management API SAML 2.0 action was refused (including an ' +
      'unknown action) and the action layer attached no more specific ' +
      'code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0048',
    summary: 'A management API SAML 1.1 action was refused (including an ' +
      'unknown action) and the action layer attached no more specific ' +
      'code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0049',
    summary: 'A management API authorization servers action was refused ' +
      '(including an unknown action) and the action layer attached no ' +
      'more specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0050',
    summary: 'A management API applications action was refused (including an ' +
      'unknown action) and the action layer attached no more ' +
      'specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0051',
    summary: 'A management API XACML action was refused (including an ' +
      'unknown action) and the action layer attached no more specific ' +
      'code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0052',
    summary: 'A management API Shared Signals (ssf) action was refused ' +
      '(including an unknown action) and the action layer attached no ' +
      'more specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0053',
    summary: 'A management API CAEP action was refused (including an unknown ' +
      'action) and the action layer attached no more specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0054',
    summary: 'A management API RISC action was refused (including an unknown ' +
      'action) and the action layer attached no more specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0055',
    summary: 'A management API PKI action was refused (including an unknown ' +
      'action) and the action layer attached no more specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0056',
    summary: 'A management API signals receiver action was refused ' +
      '(including an unknown action) and the action layer attached no ' +
      'more specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0057',
    summary: 'A management API TLS truststore action was refused (including ' +
      'an unknown action) and the action layer attached no more ' +
      'specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0058',
    summary: 'A management API delegated permissions action was refused ' +
      '(including an unknown action) and the action layer attached no ' +
      'more specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0059',
    summary: 'A management API roles action was refused (including an ' +
      'unknown action) and the action layer attached no more specific ' +
      'code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0060',
    summary: 'A management API policies action was refused (including an ' +
      'unknown action) and the action layer attached no more specific ' +
      'code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0061',
    summary: 'A management API consent action was refused (including an ' +
      'unknown action) and the action layer attached no more specific ' +
      'code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0062',
    summary: 'A management API SPIFFE action was refused (including an ' +
      'unknown action) and the action layer attached no more specific ' +
      'code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0063',
    summary: 'A management API SPIFFE registration entries action was ' +
      'refused (including an unknown action) and the action layer ' +
      'attached no more specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0064',
    summary: 'A management API SPIFFE agents action was refused (including ' +
      'an unknown action) and the action layer attached no more ' +
      'specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0065',
    summary: 'A management API Kerberos principals action was refused ' +
      '(including an unknown action) and the action layer attached no more ' +
      'specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0080',
    summary: 'A management API certificate details request was refused and ' +
      'the view attached no more specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0081',
    summary: 'The used-assertion history could not be read for ' +
      'GET /admin-api/used-assertions, because the store holding it could ' +
      'not be queried.',
    spec: 'HTTP 500 { ok: false, errors }' },
  { code: 'STS-API-0082',
    summary: 'A management API access token verified and its JOSE typ header ' +
      'is not at+jwt (RFC 9068 section 4): an ID Token, another JWT, or an ' +
      'access token minted before at+jwt.',
    spec: 'HTTP 401 invalid_token, WWW-Authenticate: Bearer ' +
      'error="invalid_token"' },
  { code: 'STS-API-0083',
    summary: 'A management API access token names an iss that is not an ' +
      'issuer this service publishes at any address this API answers under ' +
      '(RFC 9068 section 4).',
    spec: 'HTTP 401 invalid_token, WWW-Authenticate: Bearer ' +
      'error="invalid_token"' },
  // ----- GET/POST /admin-api/oauth2/monitor (2026-09-13) --------------------
  { code: 'STS-API-0100',
    summary: 'The query string of GET /admin-api/oauth2/monitor did not ' +
      'match the shape the operation accepts (offset, limit, state, client_id, ' +
      'page, per, clientsPage) and was refused before anything was read.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0101',
    summary: 'An /admin-api/oauth2/monitor action was refused and the action ' +
      'layer attached no more specific code.',
    spec: 'HTTP 400 { ok: false, errors }' },
  { code: 'STS-API-0102',
    summary: 'An /admin-api/oauth2/monitor action threw; nothing is known to ' +
      'have changed and the log line carries the stack.',
    spec: 'HTTP 500 { ok: false, errors }' },
  { code: 'STS-API-0110',
    summary: 'An /admin-api access token bound to a client certificate (RFC ' +
      '8705 cnf x5t#S256) was presented on a connection without that ' +
      'certificate.',
    spec: 'invalid_token (HTTP 401)' },
  // ===== PORTAL ============================================================
  // PER-REALM ADMINISTRATORS (2026-09-14, #32).
  { code: 'STS-API-0111',
    summary: 'A trust realm\'s own access token was presented at /admin-api by ' +
      'a client other than that realm\'s sts-management-api.',
    spec: 'HTTP 403 forbidden' },
  { code: 'STS-API-0112',
    summary: 'A trust realm\'s own token or administrator reached a ' +
      'service-wide /admin-api operation, or another realm\'s.',
    spec: 'HTTP 403 forbidden' },
  { code: 'STS-API-0113',
    summary: 'A users or groups create that had claimed its name across ' +
      'nodes threw before it could answer; the claim was given back.',
    spec: 'HTTP 500' },
  { code: 'STS-PORTAL-0001',
    summary: 'A user portal request\'s query string or form body did not ' +
      'match the shape its route accepts, and was refused before ' +
      'anything was read or changed.',
    spec: 'HTTP 400 page (Bad request)' },
  { code: 'STS-PORTAL-0002',
    summary: 'An activation link was tried too often from one address or for ' +
      'one account, and the rate limiter refused the attempt.',
    spec: 'HTTP 429 page' },
  { code: 'STS-PORTAL-0003',
    summary: 'An activation link was refused: the token is wrong, expired, ' +
      'already spent, or was never issued for that person. The four ' +
      'causes deliberately answer the same sentence.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0004',
    summary: 'The authenticator app setup started during an activation ' +
      'expired before its code was confirmed.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0005',
    summary: 'The one-time code typed to confirm an authenticator app during ' +
      'an activation did not verify.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0006',
    summary: 'An activation set a password whose confirmation did not match.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0007',
    summary: 'An activation chose no way to sign in: no password, and no ' +
      'security key used instead of one.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0008',
    summary: 'A new password set from the portal (at activation or on the ' +
      'password page) was refused by the password policy or could not ' +
      'be written.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0009',
    summary: 'An authenticator app was asked for during an activation and ' +
      'its enrolment could not be started; the activation finished ' +
      'without it.',
    spec: '' },
  { code: 'STS-PORTAL-0010',
    summary: 'The access policy refused a signed-in person a portal page or ' +
      'action.',
    spec: 'HTTP 403 page' },
  { code: 'STS-PORTAL-0011',
    summary: 'The portal could not start its OpenID Connect sign-in: the ' +
      'sts-user-portal client entry is missing or has no secret, or ' +
      'in product mode the portal was reached at an address not ' +
      'registered as a redirect URI.',
    spec: 'HTTP 503 page' },
  { code: 'STS-PORTAL-0012',
    summary: 'The portal\'s OpenID Connect callback could not complete a ' +
      'sign-in (a state, code, token or ID Token step failed).',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0013',
    summary: 'The portal\'s OpenID Connect callback threw unexpectedly.',
    spec: 'HTTP 500 page' },
  { code: 'STS-PORTAL-0014',
    summary: 'The portal\'s directory slot was offered a filler without ' +
      'personEntry() and was not installed; the Overview falls back ' +
      'to what the session carries.',
    spec: '' },
  { code: 'STS-PORTAL-0015',
    summary: 'Reading the signed-in person\'s directory entry for the ' +
      'Overview threw; the page fell back to what the session ' +
      'carries.',
    spec: '' },
  { code: 'STS-PORTAL-0016',
    summary: 'The QR code for an authenticator app enrolment could not be ' +
      'rendered; the secret is offered for typing only.',
    spec: '' },
  { code: 'STS-PORTAL-0017',
    summary: 'A portal form post was refused because its CSRF token was ' +
      'missing or did not match the session.',
    spec: 'HTTP 403 page' },
  { code: 'STS-PORTAL-0018',
    summary: 'Confirming an authenticator app code was tried too often and ' +
      'the rate limiter refused the attempt.',
    spec: 'HTTP 429 page' },
  { code: 'STS-PORTAL-0019',
    summary: 'A password change was tried too often and the rate limiter ' +
      'refused the attempt.',
    spec: 'HTTP 429 page' },
  { code: 'STS-PORTAL-0020',
    summary: 'Self-service signing key generation was tried too often and ' +
      'the rate limiter refused it.',
    spec: 'HTTP 429 page' },
  { code: 'STS-PORTAL-0021',
    summary: 'Removing the person\'s own authenticator app was refused ' +
      '(there was none, or the store refused the write).',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0022',
    summary: 'An authenticator app enrolment could not be started (the ' +
      'mechanism is off, or product mode will not enrol this person).',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0023',
    summary: 'The code typed to confirm an authenticator app enrolment on ' +
      '/portal/mfa did not verify.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0024',
    summary: 'A set of recovery codes could not be generated for the ' +
      'signed-in person.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0025',
    summary: 'A confirmed set of recovery codes could not be stored (the ' +
      'pending set was gone or the write failed).',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0026',
    summary: 'A portal form post named no action, or one its handler does ' +
      'not have.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0027',
    summary: 'Taking a signing key off was refused because the person holds ' +
      'none.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0028',
    summary: 'A person tried to issue themselves a signing key while ' +
      'pki.personSelfService is off.',
    spec: 'HTTP 403 page' },
  { code: 'STS-PORTAL-0029',
    summary: 'The certificate authority could not issue a self-service ' +
      'signing key pair.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0030',
    summary: 'A self-service signing key pair was issued but could not be ' +
      'written to the person\'s entry; the key pair is discarded.',
    spec: 'HTTP 500 page' },
  { code: 'STS-PORTAL-0031',
    summary: 'A password change was refused because the current password did ' +
      'not verify.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0032',
    summary: 'A password change gave no new password, or a confirmation that ' +
      'did not match.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0033',
    summary: 'A security key enrolment could not be started (policy refused ' +
      'the role, the key limit was reached, or the mechanism is off).',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0034',
    summary: 'A security key enrolment was finished with no WebAuthn ' +
      'ceremony result, usually because the browser ran no script.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0035',
    summary: 'A security key enrolment was refused because the configured ' +
      'WebAuthn RP ID does not fit the host the portal was reached ' +
      'at.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0036',
    summary: 'A security key enrolment\'s registration response did not ' +
      'verify, or the key was refused on the write.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0037',
    summary: 'Removing one of the person\'s own security keys was refused ' +
      '(no such key on their entry, or removing it would leave no way in).',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0038',
    summary: 'The portal\'s Shared Signals receive endpoint refused a push ' +
      'that carried no more specific code of its own (receivers off, ' +
      'no stream, wrong bearer token, empty or malformed token, wrong ' +
      'audience, or an unverified signature).',
    spec: 'SSF error JSON (HTTP 400, 401, 404, 500 or 501)' },
  { code: 'STS-PORTAL-0039',
    summary: 'A person\'s revocation of their own TLS client certificate ' +
      'was refused (a serial they hold no certificate under, or the ' +
      'revocation register refused it).',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0040',
    summary: 'A TLS client certificate was asked for with a file password ' +
      'that is too short, too long, or not the same twice.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0041',
    summary: 'A self-service TLS client certificate could not be issued ' +
      '(no certificate authority, a refused key algorithm or label, or the ' +
      'cap reached).',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0042',
    summary: 'A TLS client certificate was issued and its PKCS#12 and PEM ' +
      'files could not be built; the certificate was revoked at once.',
    spec: 'HTTP 500 page' },
  { code: 'STS-PORTAL-0047',
    summary: 'A person\'s own ACME account binding key or SCEP challenge password was not made on /portal/certificates (the enrollment core refused it; its own code is on the monitor row).',
    spec: 'HTTP 4xx page' },
  { code: 'STS-PORTAL-0048',
    summary: 'A person asked /portal/certificates to delete an account binding key or challenge password they do not hold.',
    spec: 'HTTP 404 page' },
  { code: 'STS-PORTAL-0049',
    summary: 'A person asked /portal/certificates to revoke a certificate they do not hold, or the revocation was refused.',
    spec: 'HTTP 404 or 400 page' },
  { code: 'STS-PORTAL-0050',
    summary: 'A person asked /portal/certificates for an ACME or SCEP credential while that protocol is turned off in the realm.',
    spec: 'HTTP 403 page' },
  { code: 'STS-PORTAL-0051',
    summary: 'A POST to /portal/certificates named no action the page performs.',
    spec: 'HTTP 400 page' },
  // /portal/reset-password (2026-09-13).
  { code: 'STS-PORTAL-0070',
    summary: 'A password reset link was refused by the rate limit.',
    spec: 'HTTP 429 page' },
  { code: 'STS-PORTAL-0071',
    summary: 'A password reset link did not verify; the page answers one ' +
      'sentence for every reason.',
    spec: 'HTTP 400 page' },
  { code: 'STS-PORTAL-0072',
    summary: 'A new password from a reset link was refused before it was ' +
      'tried: missing, not typed twice alike, or the reserved password.',
    spec: 'the reset form again, HTTP 400' },
  { code: 'STS-PORTAL-0073',
    summary: 'A new password from a reset link was refused by the password ' +
      'policy or the store.',
    spec: 'the reset form again, HTTP 400' },
  // ===== LOGOUT ============================================================
  { code: 'STS-PORTAL-0074',
    summary: 'The realm chooser in front of /portal was asked for a realm ' +
      'that is not defined.',
    spec: 'HTTP 400 on /portal' },
  { code: 'STS-LOGOUT-0001',
    summary: 'A sign-out named somebody other than the caller while naming ' +
      'another person is closed (logout.anyUser off, or product ' +
      'mode).',
    spec: 'HTTP 403 {error: forbidden} or a 403 page' },
  { code: 'STS-LOGOUT-0002',
    summary: 'A sign-out request carried no session cookie and named nobody, ' +
      'so there is nobody to act on. (A browser GET is sent to sign ' +
      'in instead, which is not a failure.)',
    spec: 'HTTP 401 {error: no_subject} or a 401 page' },
  { code: 'STS-LOGOUT-0003',
    summary: 'A sign-out form failed validation (an unrecognised scope ' +
      'value, or an over-long selection).',
    spec: 'HTTP 400 page' },
  { code: 'STS-LOGOUT-0004',
    summary: 'One family\'s live items could not be read for a sign-out ' +
      'inventory; the page reports that family as unreadable.',
    spec: '' },
  { code: 'STS-LOGOUT-0005',
    summary: 'One family\'s live items could not be read while a sign-out ' +
      'was ending them, so nothing in that family was ended.',
    spec: '' },
  { code: 'STS-LOGOUT-0006',
    summary: 'Ending one live item during a sign-out failed with an ' +
      'exception; it is reported as not ended.',
    spec: '' },
  { code: 'STS-LOGOUT-0007',
    summary: 'A sign-out ended nothing: nothing live was found for the ' +
      'identity, or nothing that was selected could be ended.',
    spec: '' },
  // ===== REG ===============================================================
  { code: 'STS-REG-0001',
    summary: 'An application identifier was empty, longer than 512 ' +
      'characters, or contained a line break or NUL.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0002',
    summary: 'The application registry has no store: no directory is loaded ' +
      'in this process, so nothing can be created, deleted, ' +
      'registered or seeded.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api ' +
      'reply), where there is a caller' },
  { code: 'STS-REG-0003',
    summary: 'An application was created with an identifier that is already ' +
      'in the registry.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0004',
    summary: 'An application was created with a kind the registry does not ' +
      'know.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0005',
    summary: 'An application was declared for a protocol family the registry ' +
      'does not know.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0006',
    summary: 'An attribute not in the published application schema was ' +
      'written.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0007',
    summary: 'A DERIVED application attribute (a counter or a sighting) was ' +
      'written by hand.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0008',
    summary: 'An application attribute was written against its cardinality: ' +
      'several values for a single-valued one, or set where ' +
      'add/remove applies (or the reverse).',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0009',
    summary: 'An add or remove on an application attribute carried no value.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0010',
    summary: 'An attribute scoped to certain protocol families was written ' +
      'onto an application not declared for any of them.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0011',
    summary: 'An application home page was not an absolute http or https ' +
      'URL.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0012',
    summary: 'A permission base URI was not absolute.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0013',
    summary: 'A delegated permission name was not usable.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0014',
    summary: 'A delegated permission was defined that the application ' +
      'already defines.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0015',
    summary: 'A delegated permission was defined on an application with no ' +
      'permission base URI.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0016',
    summary: 'A delegated permission was granted that no application ' +
      'defines.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0017',
    summary: 'An application was granted a delegated permission it defines ' +
      'itself.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0018',
    summary: 'A global consent value was not an RFC 6749 scope token.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0019',
    summary: 'An application\'s private key could not be sealed under the ' +
      'key-encryption key, so it was not stored.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0020',
    summary: 'The directory would not take an application entry: ' +
      'ou=applications is full (applications.max) or the directory ' +
      'refused the write.',
    spec: 'the caller\'s refusal where there is one; a protocol exchange ' +
      'carries on' },
  { code: 'STS-REG-0021',
    summary: 'An application was named that is not in the registry.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0022',
    summary: 'The directory would not delete an application entry.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0023',
    summary: 'An application\'s sealed private key will not open under this ' +
      'process\'s key-encryption key; it was written under a different ' +
      'one.',
    spec: '' },
  { code: 'STS-REG-0024',
    summary: 'An application\'s stored RFC 7591 registration document is not ' +
      'valid JSON; the registration is rebuilt from its attributes.',
    spec: '' },
  { code: 'STS-REG-0025',
    summary: 'An application carries a per-application setting override that ' +
      'does not parse; the service-wide setting is used instead.',
    spec: '' },
  { code: 'STS-REG-0026',
    summary: 'Two or more applications claim one identifier (an audience, a ' +
      'client_id, a permission base URI or an AppliesTo); the first ' +
      'found is used.',
    spec: '' },
  { code: 'STS-REG-0027',
    summary: 'A delegated permission was removed that the application does ' +
      'not define.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0028',
    summary: 'The consent register was offered a directory missing one of ' +
      'its four functions, so no consent can be recorded.',
    spec: '' },
  { code: 'STS-REG-0029',
    summary: 'A consent could not be recorded, revoked or forgotten because ' +
      'no directory is installed.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api ' +
      'reply); the consent screen asks again' },
  { code: 'STS-REG-0030',
    summary: 'A consent was agreed and the directory did not write it down ' +
      '(no entry for the person, most often); the person is asked ' +
      'again next time.',
    spec: '' },
  { code: 'STS-REG-0031',
    summary: 'A consent revoke or forget did not name the person, ' +
      'application and scope it needs.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0032',
    summary: 'A consent was revoked or forgotten that is not on the ' +
      'person\'s entry.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0033',
    summary: 'A delegation act could not be recorded; the protocol exchange ' +
      'carried on and the act is missing from /admin/delegation.',
    spec: '' },
  { code: 'STS-REG-0034',
    summary: 'A claim set was named that does not exist.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0035',
    summary: 'A claim-attribute selection named an attribute that is not in ' +
      'the catalogue.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0036',
    summary: 'A typed custom claim was given with no name.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0037',
    summary: 'A typed custom claim was given a name this service sets ' +
      'itself.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0038',
    summary: 'A typed custom claim name was configured twice in one set.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0039',
    summary: 'The directory\'s user observer threw while being told about an ' +
      'authentication, an enrolment, an issuance or a credential ' +
      'status change; the event stands and the directory entry may ' +
      'not reflect it.',
    spec: '' },
  { code: 'STS-REG-0040',
    summary: 'A SCIM request could not be counted; /admin/scim/monitor ' +
      'under-reports it.',
    spec: '' },
  { code: 'STS-REG-0041',
    summary: 'The application registry threw while recording an ' +
      'authentication; the authentication stands and the application ' +
      'entry does not show it.',
    spec: '' },
  { code: 'STS-REG-0042',
    summary: 'The claim-attribute resolver threw during issuance; the token ' +
      'or assertion is issued without its configured attribute ' +
      'claims.',
    spec: '' },
  { code: 'STS-REG-0043',
    summary: 'The group-claim resolver threw during issuance; the token or ' +
      'assertion is issued without its groups claim.',
    spec: '' },
  { code: 'STS-REG-0044',
    summary: 'The role register threw during issuance; the token or ' +
      'assertion is issued without its roles claim.',
    spec: '' },
  { code: 'STS-REG-0045',
    summary: 'The directory could not be read for the groups claim; the ' +
      'token or assertion is issued without it.',
    spec: '' },
  { code: 'STS-REG-0046',
    summary: 'groups.claimName is empty or names a claim this service sets ' +
      'itself, so tokens and assertions are issued without the groups ' +
      'claim that is switched on.',
    spec: '' },
  { code: 'STS-REG-0047',
    summary: 'The audit log\'s actor resolver threw while naming the ' +
      'signed-in user for an HTTP row; the row is recorded with no ' +
      'actor.',
    spec: '' },
  { code: 'STS-REG-0048',
    summary: 'An audit event could not be recorded and was dropped; the ' +
      'operation it describes went ahead regardless.',
    spec: '' },
  // --- return-address provenance (2026-09-12)
  { code: 'STS-REG-0049',
    summary: 'In product mode, a return address (a SAML ACS URL or shire, a ' +
      'WS-Federation wreply, or the console\'s or portal\'s own callback) ' +
      'is on the application\'s entry but still marked as OBSERVED — a ' +
      'development-mode request put it there and nobody confirmed it — so ' +
      'it was refused as unregistered.',
    spec: 'the family\'s own refusal for an unregistered address: an HTTP ' +
      '400 page for SAML 2.0, SAML 1.1 and WS-Federation; the console\'s ' +
      'or portal\'s sign-in refusal page' },
  { code: 'STS-REG-0050',
    summary: 'A confirm-address or discard-address named an address that is ' +
      'not marked as observed on that attribute of the entry.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0051',
    summary: 'A confirm-address or discard-address named an attribute that ' +
      'is not a return-address attribute.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0052',
    summary: 'A confirm-address or discard-address carried no address.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0053',
    summary: 'An ssfAllowedEvents value was neither caep, risc nor an event ' +
      'type URI this transmitter knows.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0060',
    summary: 'A write of oauthAssertionKeySource or ' +
      'oauthSamlAssertionKeySource named a value outside issued, ' +
      'uploaded-realm-ca and uploaded-external-ca.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0061',
    summary: 'Regenerating the client secret of sts-management-api was ' +
      'refused because adminApi.clientSecret pins it.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  // Reserved block STS-REG-0070..0079 (2026-09-13).
  { code: 'STS-REG-0070',
    summary: 'A client registration (RFC 7591 or 7592) named a redirect_uri, ' +
      'post_logout_redirect_uri or frontchannel_logout_uri that is not a ' +
      'usable address — not http(s) with a host, not a private-use scheme ' +
      'named for a domain, or (for the front-channel URI) not http(s).',
    spec: 'invalid_redirect_uri or invalid_client_metadata (HTTP 400)' },
  { code: 'STS-REG-0071',
    summary: 'A console or /admin-api write put an unusable address on ' +
      'oauthRedirectUri, oauthPostLogoutRedirectUri or ' +
      'oauthFrontchannelLogoutUri.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0072',
    summary: 'An RFC 7591 registration or RFC 7592 update named an RFC 9701 ' +
      'introspection_signed_response_alg, ' +
      'introspection_encrypted_response_alg or ' +
      'introspection_encrypted_response_enc this service cannot honour, ' +
      'or an enc with no alg.',
    spec: 'invalid_client_metadata (HTTP 400)' },
  { code: 'STS-REG-0073',
    summary: 'A console or /admin-api write put an unusable RFC 9701 ' +
      'algorithm on oauthIntrospectionSignedResponseAlg, ' +
      'oauthIntrospectionEncryptedResponseAlg or ' +
      'oauthIntrospectionEncryptedResponseEnc, or an enc on an entry with no ' +
      'alg.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0074',
    summary: 'An RFC 9728 protected resource metadata import named no ' +
      'document: nothing pasted, nothing uploaded and no URL.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0075',
    summary: 'An RFC 9728 import gave the document more than one way ' +
      '(pasted, uploaded and a URL are exclusive).',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0076',
    summary: 'An RFC 9728 document was empty, too large ' +
      '(federation.maxResponseBytes), not JSON, not a JSON object, or refused ' +
      'by the JSON document walk.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0077',
    summary: 'An RFC 9728 document is malformed: `resource` missing, not a ' +
      'URL or carrying a fragment, or a member of the wrong JSON type.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0078',
    summary: 'An RFC 9728 document was to be fetched by URL and ' +
      'federation.outbound is off.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0079',
    summary: 'The URL an RFC 9728 document was to be fetched from is not a ' +
      'URL, or not https while federation.outboundAllowInsecure is off.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0080',
    summary: 'In product mode, the host of an RFC 9728 document URL resolves ' +
      'to a loopback, private, link-local or reserved address.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0081',
    summary: 'The host of an RFC 9728 document URL could not be resolved.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0082',
    summary: 'The RFC 9728 document URL answered with a redirect, which is ' +
      'not followed.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0083',
    summary: 'The RFC 9728 document URL answered a status other than 200.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0084',
    summary: 'The RFC 9728 document fetched by URL was larger than ' +
      'federation.maxResponseBytes.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0085',
    summary: 'The RFC 9728 document URL did not answer within ' +
      'federation.outboundTimeoutMs.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0086',
    summary: 'The request for an RFC 9728 document failed at the connection ' +
      '(refused, reset, a certificate this service does not trust).',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0087',
    summary: 'In product mode, a fetched RFC 9728 document\'s `resource` is ' +
      'not the identifier its well-known URL was built from (section 3.3).',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0088',
    summary: 'In product mode, an RFC 9728 document\'s `resource` is not an ' +
      'https URL (section 2).',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0089',
    summary: 'A console or /admin-api write put an unusable value on ' +
      'oauthResourceMetadata (not a JSON object with a `resource`) or ' +
      'oauthResourceMetadataUrl (not an http or https URL).',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0100',
    summary: 'An RFC 7591 registration or RFC 7592 update named ' +
      'request_uris, request_object_signing_alg, ' +
      'request_object_encryption_alg, request_object_encryption_enc ' +
      'or require_signed_request_object this service cannot honour.',
    spec: 'invalid_client_metadata (HTTP 400)' },
  { code: 'STS-REG-0101',
    summary: 'A console or /admin-api write put an unusable value on ' +
      'oauthRequestUri, oauthRequestObjectSigningAlg, ' +
      'oauthRequestObjectEncryptionAlg, ' +
      'oauthRequestObjectEncryptionEnc or ' +
      'oauthRequireSignedRequestObject.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0110',
    summary: 'An RFC 7591 registration or RFC 7592 update gave ' +
      'authorization_details_types a value that is not an array of type ' +
      'names (RFC 9396 section 10).',
    spec: 'invalid_client_metadata (HTTP 400)' },
  { code: 'STS-REG-0111',
    summary: 'A console or /admin-api write put a value on ' +
      'oauthAuthorizationDetailsTypes that is not a type name.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0112',
    summary: 'A console or /admin-api write put an unusable ' +
      'authorization_details type definition on ' +
      'oauthAuthorizationDetailsType: not a name or a JSON object, a stray ' +
      'member, a location that is not an absolute URI, a schema that does ' +
      'not compile, or the built-in openid_credential.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0120',
    summary: 'An RFC 7591 registration or RFC 7592 update gave ' +
      'require_pushed_authorization_requests a value that is not a boolean.',
    spec: 'invalid_client_metadata (HTTP 400)' },
  { code: 'STS-REG-0121',
    summary: 'A console or /admin-api write put a value other than TRUE or ' +
      'FALSE on oauthRequirePushedAuthorizationRequests.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0130',
    summary: 'A registration gave an RFC 8705 certificate subject parameter a ' +
      'value that is not what it names (a DN, host name, URI, IP address or ' +
      'mailbox).',
    spec: 'invalid_client_metadata (HTTP 400)' },
  { code: 'STS-REG-0131',
    summary: 'A registration gave more than one of RFC 8705 section 2.1.2\'s ' +
      'five certificate subject parameters.',
    spec: 'invalid_client_metadata (HTTP 400)' },
  { code: 'STS-REG-0132',
    summary: 'A registration gave tls_client_certificate_bound_access_tokens ' +
      'a value that is not a boolean.',
    spec: 'invalid_client_metadata (HTTP 400)' },
  { code: 'STS-REG-0133',
    summary: 'A registration asked for certificate-bound access tokens while ' +
      'the main port is not TLS, so no token could be bound.',
    spec: 'invalid_client_metadata (HTTP 400)' },
  { code: 'STS-REG-0134',
    summary: 'A console or /admin-api write gave an RFC 8705 certificate ' +
      'subject attribute a value that is not what it names.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0135',
    summary: 'A console or /admin-api write set a second RFC 8705 ' +
      'certificate subject attribute beside the one the entry holds.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0136',
    summary: 'A console or /admin-api write put a value other than TRUE or ' +
      'FALSE on oauthTlsClientCertificateBoundAccessTokens.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  // RFC 9470 (2026-09-13): what a resource application requires.
  { code: 'STS-REG-0140',
    summary: 'A console or /admin-api write put a value on ' +
      'oauthStepUpAcrValues that cannot be an acr value.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-REG-0141',
    summary: 'A console or /admin-api write put a value on oauthStepUpMaxAge ' +
      'that is not a whole number of seconds.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  // CORS (2026-09-13): what an application's allowlist may hold.
  { code: 'STS-REG-0150',
    summary: 'A console or /admin-api write put a value on appCorsOrigin ' +
      'that is not an exact origin — a path, a wildcard, null, a user name, ' +
      'or no host.',
    spec: 'the caller\'s refusal (errors on a console or /admin-api reply)' },
  { code: 'STS-DBG-0001',
    summary: 'The debugger permission was asked for by somebody who may ' +
      'not hold it — not a person, not signed in, not in the ' +
      'default realm, or not a console administrator — and was left ' +
      'off the token.',
    spec: 'none — the token is issued without that scope (RFC 6749 ' +
      'section 3.3)' },
  { code: 'STS-DBG-0002',
    summary: 'A request to the debugger carried no debugger session and no ' +
      'bearer token, and was not a page a browser could be sent to ' +
      'sign in from.',
    spec: 'HTTP 401 with WWW-Authenticate: Bearer' },
  { code: 'STS-DBG-0003',
    summary: 'A debugger access token did not verify against the default ' +
      'realm\'s signing key, or could not be read.',
    spec: 'HTTP 401 invalid_token' },
  { code: 'STS-DBG-0004',
    summary: 'A debugger access token had expired.',
    spec: 'HTTP 401 invalid_token' },
  { code: 'STS-DBG-0005',
    summary: 'A token presented to the debugger was not a JWT access token ' +
      '(typ at+jwt).',
    spec: 'HTTP 401 invalid_token' },
  { code: 'STS-DBG-0006',
    summary: 'A debugger access token was issued by somebody other than ' +
      'this service\'s default authorization server.',
    spec: 'HTTP 401 invalid_token' },
  { code: 'STS-DBG-0007',
    summary: 'A debugger access token was addressed to a different ' +
      'audience.',
    spec: 'HTTP 403 insufficient_scope' },
  { code: 'STS-DBG-0008',
    summary: 'A debugger access token did not carry the debugger ' +
      'permission.',
    spec: 'HTTP 403 insufficient_scope' },
  { code: 'STS-DBG-0009',
    summary: 'The access policy refused the debugger to the token\'s ' +
      'subject — ordinarily because they no longer hold a console ' +
      'role.',
    spec: 'HTTP 403 page or JSON' },
  { code: 'STS-DBG-0010',
    summary: 'The debugger\'s api process is not running, so an /api call ' +
      'could not be forwarded.',
    spec: 'HTTP 502' },
  { code: 'STS-DBG-0011',
    summary: 'Forwarding an /api call to the debugger\'s api process ' +
      'failed or timed out.',
    spec: 'HTTP 502 or 504' },
  { code: 'STS-DBG-0012',
    summary: 'An /api request body was larger than ' +
      'debugger.maxRequestBytes.',
    spec: 'HTTP 413' },
  { code: 'STS-DBG-0013',
    summary: 'The debugger\'s api process exited or did not report that it ' +
      'was listening in time.',
    spec: 'none — logged; it is forked again' },
  { code: 'STS-DBG-0014',
    summary: 'The debugger\'s api process failed to start ' +
      'debugger.restartLimit times in a row and was given up on.',
    spec: 'none — logged; /api answers 502' },
  { code: 'STS-DBG-0015',
    summary: 'The debugger was enabled and its built UI or api was not ' +
      'where debugger.uiDirectory or debugger.apiDirectory says, so ' +
      'it was not started.',
    spec: 'none — logged and shown on /admin/debugger' },
  { code: 'STS-DBG-0016',
    summary: 'The debugger listener could not bind its port.',
    spec: 'none — logged and shown on /admin/debugger' },
  { code: 'STS-DBG-0017',
    summary: 'The debugger could not start a sign-in: its client is ' +
      'missing from the registry, or the address it was reached at ' +
      'is not a registered redirect URI in product mode.',
    spec: 'HTTP page (500 or 403)' },
  { code: 'STS-DBG-0018',
    summary: 'The debugger\'s sign-in callback refused what the ' +
      'authorization server sent back.',
    spec: 'HTTP 400 page' },
  { code: 'STS-DBG-0019',
    summary: 'A signed-in administrator asked the debugger for a path it ' +
      'does not serve.',
    spec: 'HTTP 404' },
  { code: 'STS-DBG-0020',
    summary: 'An entry in debugger.allowedDestinations is not a CIDR range ' +
      'and was left out of the allow-list.',
    spec: 'none — logged at startup' },
  { code: 'STS-DBG-0021',
    summary: 'A sign-out from the debugger did not carry the session\'s ' +
      'CSRF token.',
    spec: 'HTTP 403 page' },
  { code: 'STS-DBG-0022',
    summary: 'A method other than GET or HEAD was sent to the debugger\'s ' +
      'static pages.',
    spec: 'HTTP 405' },
  { code: 'STS-DBG-0023',
    summary: 'The /admin/debugger page or GET /admin-api/debugger could not ' +
      'build its report.',
    spec: 'HTTP 500 page or JSON' },
  { code: 'STS-DBG-0024',
    summary: 'The debugger permission was refused because neither console ' +
      'role group has a member: the empty-roster rule that opens the ' +
      'console to everybody does not open the debugger.',
    spec: 'none at issuance (the scope is left off); HTTP 403 at the ' +
      'debugger' },
  { code: 'STS-DBG-0030',
    summary: 'A certificate-bound access token (RFC 8705 cnf x5t#S256) was ' +
      'presented to the debugger on a connection without that certificate.',
    spec: 'invalid_token (HTTP 401)' }
  // ===== END ===============================================================
];

// ---------------------------------------------------------------------------
// The index, built once. A duplicate is REPORTED rather than silently resolved
// to the later row, because a duplicate code is two conditions sharing a name,
// which is the one thing this table exists to prevent. The test fails on it;
// this warning is for a process started from a tree the test was not run on.
// ---------------------------------------------------------------------------
const BY_CODE = {};

const SUBSYSTEM_IDS = {};

SUBSYSTEMS.forEach(function (s) {
  SUBSYSTEM_IDS[s.id] = s;
});

CODES.forEach(function (row) {
  if (BY_CODE[row.code]) {
    log.warn('the error code ' + row.code + ' is registered twice; the first ' +
             'row is the one used.');
    return;
  }
  BY_CODE[row.code] = row;
});

function subsystemOf(code) {
  log.debug("Entering subsystemOf().");
  const parts = String(code || '').split('-');
  log.debug("Leaving subsystemOf().");
  return parts.length === 3 ? parts[1] : '';
}

function isWellFormed(code) {
  log.debug("Entering isWellFormed().");
  log.debug("Leaving isWellFormed().");
  return CODE_PATTERN.test(String(code || ''));
}

function isKnown(code) {
  log.debug("Entering isKnown().");
  log.debug("Leaving isKnown().");
  return Object.prototype.hasOwnProperty.call(BY_CODE, String(code || ''));
}

function describe(code) {
  log.debug("Entering describe().");
  log.debug("Leaving describe().");
  return BY_CODE[String(code || '')] || null;
}

// ---------------------------------------------------------------------------
// mark(res, code) — THE HTTP HALF.
//
// Records which condition a response is about to report, ON THE RESPONSE
// OBJECT, and returns `res` so it can be written inline:
//
//   return oauthError(errorCodes.mark(res, 'STS-OAUTH-nnnn'), 400, …);
//
// or as a statement of its own on the line before. Nothing about the response
// changes — no header, no body — which is rule 1. `common/app.js`'s call log
// reads it back from `finish`, after the bytes have gone, and puts it on the
// audit row.
//
// **A SYMBOL AND NOT `res.locals`.** Three listeners here write responses that
// are not Express's (`tls/tls_server.js` has a handler of its own), and a
// property under a Symbol cannot be serialised by `res.json(res.locals)` or
// collide with a template variable. It is not enumerable for the same reason.
//
// **THE LAST MARK WINS.** A shared helper that marks a general condition can
// be overridden by a caller that knows the specific one, simply by marking
// after it; the reverse order would need a second function.
//
// It cannot throw. A registry lookup that failed a token request would be the
// tail wagging the dog, which is `audit()`'s rule and for its reason. An
// UNREGISTERED code is still recorded — dropping it would hide the one row
// that says the table is incomplete — and is warned about.
// ---------------------------------------------------------------------------
const MARK = Symbol.for('mock-sts.errorCode');

function mark(res, code) {
  log.debug("Entering mark().");
  if (!res || (typeof res !== 'object' && typeof res !== 'function')) {
    log.debug("Leaving mark().");
    return res;
  }
  try {
    if (!isKnown(code)) {
      log.warn('an unregistered error code was marked on a response: ' +
               String(code) + '. Add it to common/error_codes.js.');
    }
    Object.defineProperty(res, MARK, { value: String(code), writable: true,
                                       configurable: true, enumerable: false });
  } catch (e) {
    // Swallowed with a reason: a frozen or proxied response object is not a
    // reason to fail the request it belongs to. The row falls back to the
    // generic code for its status, which is weaker and not wrong.
    log.warn('an error code could not be marked on a response: ' + e.message);
  }
  log.debug("Leaving mark().");
  return res;
}

function codeOf(res) {
  log.debug("Entering codeOf().");
  if (!res || (typeof res !== 'object' && typeof res !== 'function')) {
    log.debug("Leaving codeOf().");
    return '';
  }
  log.debug("Leaving codeOf().");
  return res[MARK] || '';
}

// ---------------------------------------------------------------------------
// The generic code for a failed HTTP response nothing marked.
//
// It exists so that EVERY failed response has a code on its row, which is what
// makes a filter on "rows with a code" mean "failures". But it is a fallback
// and says so: STS-HTTP-0002 and -0003 in a log are a failure site that is
// missing its own code, and the documentation page tells a reader to report
// one. A status below 400 on an unmarked response is not a failure and gets
// nothing.
// ---------------------------------------------------------------------------
function fallbackFor(status, matched) {
  log.debug("Entering fallbackFor().");
  const code = parseInt(status, 10) || 0;
  if (code === 404 && !matched) {
    log.debug("Leaving fallbackFor().");
    return 'STS-HTTP-0001';
  }
  if (code === 413) {
    log.debug("Leaving fallbackFor().");
    return 'STS-HTTP-0004';
  }
  if (code >= 500) {
    log.debug("Leaving fallbackFor().");
    return 'STS-HTTP-0003';
  }
  if (code >= 400) {
    log.debug("Leaving fallbackFor().");
    return 'STS-HTTP-0002';
  }
  log.debug("Leaving fallbackFor().");
  return '';
}

// ---------------------------------------------------------------------------
// tag(code) — THE LOG-LINE HALF.
//
//   log.error(errorCodes.tag('STS-STORE-nnnn') + 'the store could not be opened: ' + …)
//
// For a failure that has no audit row to carry the code: one that stops the
// process (the ring dies with it), one in a module that cannot require
// `audit.js` without closing a cycle, and one detected before any realm or
// request exists. Brackets and a trailing space, so the code leads the message
// and a grep for `[STS-` finds every tagged line.
// ---------------------------------------------------------------------------
function tag(code) {
  log.debug("Entering tag().");
  log.debug("Leaving tag().");
  return '[' + String(code || '') + '] ';
}

// ---------------------------------------------------------------------------
// THE DOCUMENTATION PAGE, generated from the table so the two cannot disagree.
//
// `docs/CLAUDE.md` says nothing in that directory is generated, and this is the
// one exception it now names: a list of several hundred codes written by hand
// beside a table of the same codes is a second copy that is wrong within a
// week, and unlike every other list that rule is about, this one is published
// by no endpoint a reader could be sent to instead. The page is committed, so
// it reads in the repository and on the site with no build step; the test is
// what keeps it current.
// ---------------------------------------------------------------------------
function escapeCell(text) {
  log.debug("Entering escapeCell().");
  log.debug("Leaving escapeCell().");
  return String(text || '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function markdown() {
  log.debug("Entering markdown().");
  const lines = [];
  lines.push('---');
  lines.push('title: Error codes');
  lines.push('nav_order: 18');
  lines.push('---');
  lines.push('');
  lines.push('<!-- GENERATED by `node common/error_codes.js --docs` from the ' +
             'table in');
  lines.push('     common/error_codes.js. Do not edit this file by hand: ' +
             'tests/error_codes.js');
  lines.push('     fails when it differs from what the table generates. -->');
  lines.push('');
  lines.push('# Error codes');
  lines.push('');
  lines.push('Every way this service can fail or refuse has a code of the ' +
             'form');
  lines.push('`STS-<SUBSYSTEM>-<NNNN>`. There are **' +
             CODES.filter(function (r) {
    return !r.retired;
  }).length + '** of them, in **' + SUBSYSTEMS.length + '** subsystems.');
  lines.push('');
  lines.push('## Where a code appears');
  lines.push('');
  lines.push('* **On the audit row** for the event, as `errorCode`, and at ' +
             'the front of');
  lines.push('  its summary. Filter for one at `/admin/audit?code=STS-…` or');
  lines.push('  `GET /admin-api/audit?code=STS-…`; a prefix such as ' +
             '`STS-OAUTH` matches a');
  lines.push('  whole subsystem.');
  lines.push('* **On the admin console** at `/admin/error-codes` ' +
             '(Monitoring), which');
  lines.push('  lists this table with how many rows in the audit log carry ' +
             'each code');
  lines.push('  right now, and at `GET /admin-api/error-codes`.');
  lines.push('* **In the service log**, at the front of the line `[STS-…]`, ' +
             'for every');
  lines.push('  audit row that carries one and for failures that have no row ' +
             '— chiefly');
  lines.push('  the ones that stop the service starting, which happen before ' +
             'there is an');
  lines.push('  audit log to hold them.');
  lines.push('');
  lines.push('## Where a code never appears');
  lines.push('');
  lines.push('**A code is never sent to a client** — not in a response body, ' +
             'a header or');
  lines.push('a redirect. Each protocol this service speaks already defines ' +
             'how it reports');
  lines.push('an error (`invalid_grant`, `KDC_ERR_PREAUTH_FAILED`, an LDAP ' +
             'result code, a');
  lines.push('SOAP fault, a gRPC status, a SAML `StatusCode`), and a client ' +
             'under test must');
  lines.push('see exactly that. The **Client sees** column below says what ' +
             'the client is');
  lines.push('sent for each condition; it describes the response, and the ' +
             'code changes');
  lines.push('nothing about it.');
  lines.push('');
  lines.push('A code is an operator\'s name for a condition. It is never ' +
             'renumbered or');
  lines.push('reused, so it is safe to put in an alert rule or a saved ' +
             'search.');
  lines.push('');
  lines.push('## The three generic codes');
  lines.push('');
  lines.push('`STS-HTTP-0002` and `STS-HTTP-0003` are what the HTTP call log ' +
             'records for a');
  lines.push('4xx or 5xx response that no handler gave a more specific code. ' +
             '**Seeing one');
  lines.push('means a failure site is missing its code** — please report it ' +
             'with the');
  lines.push('request path from the audit row. `STS-HTTP-0001` is an ' +
             'unrouted path, which');
  lines.push('is an ordinary outcome.');
  lines.push('');
  lines.push('## Contents');
  lines.push('');
  SUBSYSTEMS.forEach(function (s) {
    const count = CODES.filter(function (r) {
      return subsystemOf(r.code) === s.id;
    }).length;
    lines.push('* [' + s.label + ' (`STS-' + s.id + '`)](#sts-' +
               s.id.toLowerCase() +
               ') — ' + count);
  });
  lines.push('');
  SUBSYSTEMS.forEach(function (s) {
    const rows = CODES.filter(function (r) {
      return subsystemOf(r.code) === s.id;
    });
    lines.push('## STS-' + s.id);
    lines.push('');
    lines.push('**' + s.label + '.** ' + s.what);
    lines.push('');
    lines.push('Raised from: ' + s.where + '.');
    lines.push('');
    if (!rows.length) {
      lines.push('No codes are registered in this subsystem.');
      lines.push('');
      return;
    }
    lines.push('| Code | What failed | Client sees |');
    lines.push('|---|---|---|');
    rows.forEach(function (r) {
      lines.push('| `' + r.code + '`' + (r.retired ? ' *(retired)*' : '') +
          ' ' +
          '| ' +
                 escapeCell(r.summary) + ' | ' +
                 (r.spec ? escapeCell(r.spec) : '—') + ' |');
    });
    lines.push('');
  });
  lines.push('## Adding a code');
  lines.push('');
  lines.push('This page is generated. A new failure is a row in the `CODES` ' +
             'table in');
  lines.push('`common/error_codes.js`, a `mark()`, `errorCode` or `tag()` ' +
             'where the');
  lines.push('failure is detected, and `node common/error_codes.js --docs`. ' +
             'The test suite');
  lines.push('fails until all three are done.');
  lines.push('');
  log.debug("Leaving markdown(). " + lines.length + " line(s).");
  return lines.join('\n');
}

function docsPath() {
  log.debug("Entering docsPath().");
  const path = require('path');
  log.debug("Leaving docsPath().");
  return path.join(__dirname, '..', 'docs', 'error-codes.md');
}

module.exports = {
  CODE_PATTERN: CODE_PATTERN,
  CODE_IN_TEXT: CODE_IN_TEXT,
  SUBSYSTEMS: SUBSYSTEMS,
  CODES: CODES,
  isWellFormed: isWellFormed,
  isKnown: isKnown,
  describe: describe,
  subsystemOf: subsystemOf,
  mark: mark,
  codeOf: codeOf,
  fallbackFor: fallbackFor,
  tag: tag,
  markdown: markdown,
  docsPath: docsPath
};

if (require.main === module) {
  const fs = require('fs');
  const args = process.argv.slice(2);
  if (args.indexOf('--docs') >= 0) {
    fs.writeFileSync(docsPath(), markdown());
    console.log('wrote ' + docsPath() + ' (' + CODES.length + ' codes)');
  } else if (args.indexOf('--check') >= 0) {
    let current = '';
    try {
      current = fs.readFileSync(docsPath(), 'utf8');
    } catch (e) {
      log.debug("Caught in the load of common/error_codes.js: " +
                ((e && e.message) || e));
      // A missing page is a stale page; the message below says how to make it.
      current = '';
    }
    if (current !== markdown()) {
      console.error('[error_codes] docs/error-codes.md is stale. Run: ' +
                    'node common/error_codes.js --docs');
      process.exit(1);
    }
    console.log('docs/error-codes.md matches the table (' + CODES.length + ' ' +
        'codes)');
  } else {
    console.log(JSON.stringify({ subsystems: SUBSYSTEMS, codes: CODES }, null,
                               2));
  }
}
