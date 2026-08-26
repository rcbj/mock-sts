'use strict';
//
// File: sts_metadata.js
//
// ---------------------------------------------------------------------------
// GET /admin/sts-metadata — what this mock is, protocol by protocol, endpoint
// by endpoint and spec by spec.
//
// ---------------------------------------------------------------------------
// IT WAS /sts-metadata AND IT IS A CONSOLE PAGE NOW. THREE THINGS FOLLOW
// FROM THAT AND ALL THREE ARE THE POINT OF THE MOVE.
//
//   * **IT WEARS THE CONSOLE'S CHROME.** This file no longer emits a document:
//     `renderInner()` below builds the BODY of a page and `admin.respond()`
//     wraps it in the console's shell — the same two columns, the same
//     stylesheet, the same breadcrumb, the same gate banner. The sidebar is the
//     reason a reader wanted this: the page used to be a cul-de-sac with no way
//     back to anything, reachable only from a link somebody remembered.
//   * **IT IS BEHIND THE CONSOLE'S GATE.** `admin.js` registers one
//     `app.use('/admin', ...)` above its own routes, express applies middleware
//     only to routes added after it, and this module is required LAST by
//     server.js — so this route is guarded by construction. With
//     `admin.authRequired` on (the default) a browser with no session is sent
//     to the sign-in screen and a caller asking for `?format=json` is refused
//     401 rather than redirected. That is a change of behaviour for anything
//     that fetched the old path unauthenticated, and the parent project's
//     `tests/sts_metadata.js` now signs in the way `tests/admin_api.js` does.
//   * **REQUIRING `admin.js` FROM HERE MOVES NOTHING.** That is the question to
//     ask of any require in this service, because require order is route order
//     — and this one is safe in both directions: server.js requires the console
//     long before it requires this file, so the require below is a cache hit
//     that registers nothing; and in a process that somehow loaded this file
//     first, the console's routes and its gate would register AHEAD of this
//     page's route, which is the order this page needs anyway. There is no
//     cycle: `admin.js` does not require this module and must not — it would
//     drag the console's own routes behind the last module in server.js.
//
// A DOWNLOAD BUTTON is on the page because the JSON form is now behind the
// gate too: `?format=json` in a browser is a session-carrying GET, and an
// `<a download>` is the whole mechanism — this service serves no script
// anywhere (`script-src 'none'`), so a "download" that needed one would be a
// button that did nothing.
//
// It exists because this service now speaks eight protocol families across ten
// modules, and there was no way to find out what it offers short of reading
// server.js. It answers three questions: what can I call, what may I call it
// with, and what specification is it pretending to implement.
//
// **The endpoint list is read from Express's own router, not written down here.**
// That is the whole design. A hand-kept list of endpoints in a file next to the
// endpoints is a list that goes stale the first time somebody adds a route, and
// the failure is silent in the worst direction — the page still looks complete.
// So `app._router.stack` is walked on every request and the table below only
// supplies the NAME and the description for a path it finds. Two consequences,
// both shown on the page rather than hidden:
//
//   * a route that is registered and undescribed is listed as UNDOCUMENTED. It
//     still appears, with its methods, because the page's first duty is to be a
//     true list of what is callable.
//   * a description for a path that is NOT registered is listed as a stale entry.
//     That is the direction that catches a route being renamed or removed.
//
// `tests/sts_metadata.js` fails on either, which is what makes the page's claim to
// completeness worth something. It is also why the route walk happens per request
// instead of at require time: at require time the answer would depend on module
// load order, and a module loaded after this one would be missing.
//
// The specs are necessarily hand-written — no server can introspect which
// document it is implementing — so they are written CONSERVATIVELY. Each says
// what this mock actually does against it, including where it does less than the
// specification requires, because a list of specs that overstates is worse than
// no list at all in a tool people use to learn those specs.
// ---------------------------------------------------------------------------

const app = require('./common/app');
const { log, xmlEscape, baseUrlOf, PORT } = require('./common/helpers');
// The admin console, for its SHELL and nothing else: `page()` through
// `respond()`, which is what puts this page in the same two columns, under the
// same sidebar and behind the same banner as every other console page. See the
// header for why requiring it here moves no route and makes no cycle. Nothing
// about what this page SAYS comes from that module — it renders, and this file
// still decides everything it renders.
const admin = require('./admin-ui/admin');
const config = require('./common/config');
// The named authorization servers this process has served. They cannot be read
// off the router — one route serves all of them — so they are listed by hand,
// the same way the Kerberos and LDAP listeners are.
const authorizationServers = require('./oauth-oidc/authorization_servers');

// ---------------------------------------------------------------------------
// The specifications this service implements, and how far.
//
// `coverage` is the honest part: "full" means a client conforming to that
// document works against this mock; "partial" says what is missing; "mock" means
// the shape is right and the enforcement is deliberately absent, which is what a
// test double is for.
// ---------------------------------------------------------------------------
const SPECS = [
  // The one specification on this page that is not a protocol this service
  // speaks: it is the shape of the DOCUMENT that describes the management API.
  // It is listed because the drift check requires every referenced id to exist,
  // and because a reader who follows the /admin-api rows deserves to know which
  // version of OpenAPI they will be handed — 3.0 and 3.1 differ enough that a
  // generator pointed at the wrong one fails in the schemas rather than at the
  // top.
  { id: 'openapi', name: 'OpenAPI Specification 3.1.0',
    where: 'OpenAPI Initiative',
    url: 'https://spec.openapis.org/oas/v3.1.0.html',
    coverage: 'full for what the management API needs, which is most of a ' +
              'document and none of the hard parts: paths, operations, query ' +
              'parameters, JSON request bodies with examples, component ' +
              'schemas, tags and an empty security requirement — that last ' +
              'being how OpenAPI states "this needs no credential", which is ' +
              'true of every operation here. NO securitySchemes, no callbacks, ' +
              'no webhooks, no links, no discriminated unions. The document is ' +
              'GENERATED from the route table that registers the routes, so ' +
              'this row describes a serializer rather than a hand-written ' +
              'file.' },
  // The five SPIFFE documents. They are not RFCs — SPIFFE is a CNCF project with
  // its own numbered standards in one repository — so `where` says so rather
  // than leaving a reader to look for an RFC number that does not exist.
  { id: 'spiffe-id', name: 'SPIFFE-ID',
    where: 'SPIFFE (CNCF)',
    url: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md',
    coverage: 'full: the whole grammar, checked on the RAW TEXT rather than ' +
              'through a URL parser — the trust domain lower-case and ' +
              'restricted to letters, digits, dots, dashes and underscores; no ' +
              'port, userinfo, query or fragment; no empty, relative or ' +
              'percent-encoded path segment; the 2048- and 255-byte limits; ' +
              'and the reserved /spire path. An upper-case trust domain is ' +
              'REFUSED rather than normalised, because `new URL()` would ' +
              'lower-case it silently and a client that sent the wrong form ' +
              'would never learn it.' },
  { id: 'spiffe-x509-svid', name: 'X509-SVID',
    where: 'SPIFFE (CNCF)',
    url: 'https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md',
    coverage: 'full for issuing: exactly one URI subjectAltName holding the ' +
              'SPIFFE ID, CA:FALSE, keyUsage digitalSignature with no ' +
              'keyCertSign, extKeyUsage serverAuth AND clientAuth (an SVID is ' +
              'used at both ends of an mTLS connection), and EC P-256 by ' +
              'default with RSA and Ed25519 available. NOT verified on the way ' +
              'IN: nothing here validates a presented SVID, because nothing ' +
              'here authenticates anybody.' },
  { id: 'spiffe-jwt-svid', name: 'JWT-SVID',
    where: 'SPIFFE (CNCF)',
    url: 'https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md',
    coverage: 'full in both directions, and this is the one SPIFFE surface ' +
              'here that REFUSES: minting requires an audience, and ' +
              'ValidateJWTSVID really checks — signature against the trust ' +
              'domain\'s JWT authorities, exp with no leeway, the audience, ' +
              'and that the sub belongs to the trust domain whose key ' +
              'verified it. There is deliberately no `iss` claim: a JWT-SVID ' +
              'is verified against the bundle of the trust domain in its ' +
              '`sub`, and an issuer claim would teach a client to check the ' +
              'wrong thing.' },
  { id: 'spiffe-bundle', name: 'SPIFFE Trust Domain and Bundle',
    where: 'SPIFFE (CNCF)',
    url: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md',
    coverage: 'full for the document: a JWK Set with `spiffe_sequence` and ' +
              '`spiffe_refresh_hint`, every key carrying `use` of x509-svid or ' +
              'jwt-svid, and x5c holding base64 DER. A submitted federated ' +
              'bundle is CHECKED against those rules — one of the few ' +
              'refusals here — because a consumer MUST IGNORE a JWK with no ' +
              '`use`, so a bundle missing it verifies nothing and reports no ' +
              'error. PARTIAL for federation: the bundle endpoint URL of a ' +
              'relationship is recorded and NEVER FETCHED, so bundles are ' +
              'pushed in rather than polled.' },
  { id: 'spiffe-workload-api', name: 'SPIFFE Workload API and Workload Endpoint',
    where: 'SPIFFE (CNCF)',
    url: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md',
    coverage: 'partial, and the gap is the whole of workload attestation. Five ' +
              'of the seven methods are implemented — FetchX509SVID, ' +
              'FetchX509Bundles, FetchJWTSVID, FetchJWTBundles, ' +
              'ValidateJWTSVID — over a Unix socket and over TCP, with the ' +
              'streams held open and re-sent at half the SVID lifetime so a ' +
              'client\'s rotation path runs. The mandatory ' +
              '`workload.spiffe.io: true` header IS enforced. FetchWITSVID and ' +
              'FetchWITBundles answer Unimplemented, because the Workload ' +
              'Identity Token\'s format is not settled in a document this ' +
              'service could implement against and inventing one would be ' +
              'inventing a credential format. NO CREDENTIAL IS ASKED FOR ' +
              'AND THERE MUST NOT BE ONE — the Workload Endpoint ' +
              'specification says the endpoint MUST NOT require direct ' +
              'authentication of its clients and that TLS MUST NOT be ' +
              'required — so what is missing is ATTESTATION rather than ' +
              'authentication. A caller is identified only by the transport ' +
              'it arrived on, the endpoint it reached and its peer address, ' +
              'because node cannot read a Unix socket\'s peer credentials; ' +
              'those selectors DO decide which registration entries answer ' +
              '(spiffe.attestWorkloads), and they prove nothing about who is ' +
              'calling, so any caller that reaches the socket still gets an ' +
              'identity. The selectors are spelt `transport:`, `endpoint:` ' +
              'and `peer:` rather than `unix:` so that they cannot be ' +
              'mistaken for an attestor\'s.' },
  { id: 'spire-server-api', name: 'SPIRE Server API',
    where: 'SPIRE (CNCF) — spire-api-sdk',
    url: 'https://github.com/spiffe/spire-api-sdk',
    coverage: 'partial: six services and 42 methods are served from the ' +
              'vendored protos, of which 36 are implemented. The six that ' +
              'are not each answer with a reason — AppendBundle and ' +
              'PublishJWTAuthority (they would publish an authority this ' +
              'server holds no key for), RefreshBundle (it would fetch a URL ' +
              'somebody registered), and the three WIT methods. THE CALLER IS ' +
              'AUTHENTICATED AND AUTHORIZED: the TCP port is mutual TLS, the ' +
              'caller\'s SPIFFE ID is taken from its X509-SVID\'s URI SAN ' +
              'and verified against the trust bundle, and every method is ' +
              'checked against SPIRE\'s own policy_data.json — local, agent, ' +
              'admin, downstream — with the Unix socket trusted as `local` ' +
              'the way a real spire-server trusts its private one. RenewAgent ' +
              'stopped being unimplemented because of it: it renews the agent ' +
              'on the connection. spiffe.authRequired off restores the old ' +
              'posture, where the port is plain and anybody who reaches it ' +
              'can create a registration entry granting any identity.' },
  { id: 'rfc4120', name: 'Kerberos v5 (RFC 4120)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc4120',
    coverage: 'partial: the AS and TGS exchanges over TCP, UDP and MS-KKDCP, with ' +
              'pre-authentication (PA-ENC-TIMESTAMP), PA-ETYPE-INFO2 carrying the salt, ticket ' +
              'flags, clock-skew enforcement and the error catalogue. Two realms with a trust ' +
              'between them, so cross-realm referrals work. No FAST, no request signatures, no ' +
              'S4U, no kpasswd. The AP exchange belongs to the protected service, not here. ' +
              // The rule for these notes is that they say what would mislead somebody who
              // believed the row. "Pre-authentication is implemented" is true and, on its own,
              // implies an account database with per-account secrets in it.
              'ANY username authenticates and every user account shares ONE password, which ' +
              'GET /krb5/principals publishes: pre-authentication is verified for real (the ' +
              'password is the key, so it has to be), but it is the same password for ' +
              'everybody and an unknown username is created on the spot rather than refused.' },
  { id: 'rfc3961', name: 'Kerberos encryption framework (RFC 3961/3962/8009, RFC 4757)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc3961',
    coverage: 'full for the etypes offered: aes128/256-cts-hmac-sha1-96 (17, 18), ' +
              'aes128/256-cts-hmac-sha256/384 (19, 20) and arcfour-hmac-md5 (23). DES is ' +
              'decode-only and not offered. The same codec runs in the browser.' },
  { id: 'ms-sfu', name: '[MS-SFU] Kerberos Protocol Extensions: ' +
                       'Service for User and Constrained Delegation',
    where: 'Microsoft Open Specifications',
    url: 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/',
    coverage: 'partial: S4U2Self (PA-FOR-USER with the section 2.2.1 ' +
              'S4UByteArray checksum, HMAC-MD5 at key usage 17) and S4U2Proxy ' +
              '(cname-in-addl-tkt with the evidence ticket), authorized BOTH ' +
              'ways — msDS-AllowedToDelegateTo on the front end and ' +
              'msDS-AllowedToActOnBehalfOfOtherIdentity on the back end, with ' +
              'the asymmetries between them enforced: classic needs ' +
              'forwardable evidence and resource-based needs PA-PAC-OPTIONS ' +
              'with the resource-based bit, refused with KDC_ERR_BADOPTION ' +
              'without it. S4U_DELEGATION_INFO is written into the PAC. NOT ' +
              'implemented: the U2U variants, and no attempt is made to model ' +
              'a real domain\'s ACL on either attribute — the two lists are ' +
              'configuration in krb5_principals.js and are published at ' +
              '/admin/delegation.' },
  { id: 'ms-pac', name: '[MS-PAC] Privilege Attribute Certificate',
    where: 'Microsoft Open Specifications',
    url: 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/',
    coverage: 'partial: every ticket carries a signed PAC — logon information ' +
              '(KERB_VALIDATION_INFO, NDR), client info, UPN/DNS info, attributes and the ' +
              'requestor SID. A TGT gets two signatures and a service ticket four, per sections ' +
              '2.8.2/2.8.3. Claims and device info are not produced, and SID FILTERING across a ' +
              'trust is NOT implemented — a re-signed PAC keeps every SID it arrived with.' },
  { id: 'rfc4178', name: 'SPNEGO (RFC 4178)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc4178',
    coverage: 'full for one mechanism: NegTokenInit (with the optimistic mechToken) and ' +
              'NegTokenResp in all four negStates, the mechListMIC in both directions with ' +
              'section 5\'s rule for when it is mandatory, and [MS-SPNG]\'s NegTokenInit2 ' +
              'decoded. Only Kerberos is actually offered — NTLM is recognised in a client\'s ' +
              'mechTypes list and never selected, because offering a mechanism this service ' +
              'cannot perform would be a lie a client would act on. A mechListMIC that does ' +
              'not verify is a REJECT, not a warning: it is the whole of the downgrade defence.' },
  { id: 'rfc4559', name: 'SPNEGO-based HTTP authentication (RFC 4559)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc4559',
    coverage: 'full: the bare "WWW-Authenticate: Negotiate" challenge, the token in ' +
              'Authorization, and the mutual-authentication token returned in ' +
              'WWW-Authenticate on the 200. One difference from a real server is stated ' +
              'rather than hidden: a half-finished negotiation is held against the client ' +
              'address rather than the CONNECTION, because Express offers no stable ' +
              'connection identity — which is also why real SPNEGO breaks behind ' +
              'connection-pooling proxies.' },
  { id: 'ms-kkdcp', name: '[MS-KKDCP] Kerberos KDC Proxy Protocol',
    where: 'Microsoft Open Specifications',
    url: 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/',
    coverage: 'mock: POST /KdcProxy accepts a KDC-PROXY-MESSAGE and relays it to the KDC in ' +
              'this process. Exists because a browser cannot open a raw socket to port 88.' },
  // --- SCIM 2.0 ------------------------------------------------------------
  //
  // Three documents rather than one, and the split is worth knowing: 7642 is the
  // requirements and use cases (no wire format at all), 7643 is the schema, and 7644 is
  // the protocol. A client author who has read only one of them has usually read 7644
  // and is looking for the attribute characteristics, which are in 7643.
  { id: 'rfc7642', name: 'SCIM: Definitions, Overview, Concepts, and Requirements (RFC 7642)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc7642',
    coverage: 'mock: this is the requirements-and-use-cases document and defines no wire ' +
              'format, so there is nothing in it to implement. It is listed because it is ' +
              'what says what SCIM is FOR, and because the use case this service serves — ' +
              'an identity provider pushing accounts into a service provider\'s directory — ' +
              'is section 3.1 of it.' },
  { id: 'rfc7643', name: 'SCIM: Core Schema (RFC 7643)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc7643',
    coverage: 'partial: the User and Group resources with their common attributes (id, ' +
              'externalId, meta), and the enterprise User extension in part — ' +
              'employeeNumber, department, organization, division and manager. The schema ' +
              'definitions themselves are published at /scim/v2/Schemas with every ' +
              'attribute\'s characteristics, and they come from the scimmy library rather ' +
              'than being retyped here. NOT covered: the entire attribute set of the ' +
              'enterprise extension (costCenter and manager.$ref are absent), and any ' +
              'schema extension of this service\'s own. Every value that comes back is ' +
              'read off an LDAP entry and none of it is verified by anything — where the ' +
              'entry is silent, the value was INVENTED from the username by the same ' +
              'deterministic persona a Verifiable Credential is filled from.' },
  { id: 'rfc7644', name: 'SCIM: Protocol (RFC 7644)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc7644',
    coverage: 'partial: create, read, list, replace, PATCH (section 3.5.2 in full, ' +
              'value-filter paths included), delete, both shapes of .search, bulk, and ' +
              'the three discovery endpoints — with filtering (3.4.2.2), sorting, ' +
              'pagination, attribute projection and the section 3.12 error shape. ' +
              'Section 2 is covered in full and is the only place in this service where ' +
              'a credential is REQUIRED: all six schemes it names are offered (OAuth 2.0 ' +
              'bearer and DPoP tokens, HTTP Basic, HTTP Digest, HOBA, the session cookie ' +
              'and a TLS client certificate), its SHALL about WWW-Authenticate is on ' +
              'every 401, and its MUST about an access control policy is two OAuth ' +
              'scopes — scim:read and scim:write — with every other scheme granting ' +
              'both. Section 3.11 (/Me) is covered too, as an alias onto the same User ' +
              'handlers, and still answers 501 where there is genuinely no subject. NOT ' +
              'covered, each on purpose and each said on /scim: NOTHING IS REALLY ' +
              'CHECKED ABOUT A CREDENTIAL — anybody can get a token with either scope, ' +
              'any password but "invalid" passes Basic, anybody can register a HOBA key ' +
              '— so it is a turnstile rather than a lock, and what it buys is that a ' +
              'client\'s 401, 403 and challenge-response paths can be run at all; no ' +
              'ETag or If-Match (section 3.14), advertised as unsupported because a ' +
              'version built over a one-second timestamp would be a concurrency control ' +
              'a client trusts and that is wrong; and no changePassword, there being no ' +
              'password here that is checked. active:false is stored and DEACTIVATES ' +
              'NOBODY.' },

  // The four authentication schemes SCIM delegates to that are not already
  // described elsewhere in this list. RFC 6750 and RFC 9449 are further down
  // with the rest of OAuth, because the token a SCIM caller presents is the
  // same token this service's own authorization server issues — which is the
  // whole reason the scope requirement is worth anything.
  { id: 'rfc7235', name: 'HTTP/1.1 Authentication (RFC 7235)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc7235',
    coverage: 'partial: the framework RFC 7644 section 2 delegates to — the 401 status, ' +
              'the WWW-Authenticate challenge with one header per offered scheme, and the ' +
              'Authorization credential. Used by the SCIM endpoints only; no other ' +
              'surface in this service refuses a caller who presents nothing.' },
  { id: 'rfc7617', name: 'The Basic HTTP Authentication Scheme (RFC 7617)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc7617',
    coverage: 'full as a scheme, and it verifies nothing: any username with any password ' +
              'is accepted except the reserved "invalid", which keeps a 401 reachable. ' +
              'charset="UTF-8" is in the challenge. RFC 7644 section 2 DISCOURAGES this ' +
              'scheme in those words; it is offered because it is what a provisioning ' +
              'client most often meets.' },
  { id: 'rfc7616', name: 'HTTP Digest Access Authentication (RFC 7616)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc7616',
    coverage: 'partial, and it is the ONE scheme here that really checks a password — it ' +
              'cannot not, since the response is a hash over it, so every username shares ' +
              'one password exactly as they do in Kerberos. SHA-256, SHA-512-256 and MD5 ' +
              'with their -sess variants, qop=auth, stale=true on an expired nonce, nonce ' +
              'count replay refused, and the section 3.5 Authentication-Info response so ' +
              'a client can authenticate this server back. NOT covered: qop=auth-int (the ' +
              'body has been through this service\'s own parser, so an integrity check ' +
              'computed over it could disagree with what was sent) and userhash (there is ' +
              'no user list to search by hash — every name here is created on sight).' },
  { id: 'rfc7486', name: 'HOBA: HTTP Origin-Bound Authentication (RFC 7486)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc7486',
    coverage: 'partial: client public key registration at /.well-known/hoba/register, the ' +
              'challenge with max-age and realm, and signature verification over the ' +
              'section 5 length-prefixed to-be-signed blob — RSA with SHA-256, algorithm ' +
              '0. THE SIGNATURE IS REALLY VERIFIED; what is permissive is that anybody ' +
              'may register any key for any name. NOT covered: algorithm 1 (RSA-SHA1), ' +
              'the javascript client conventions of section 8, and any binding to a ' +
              'device identifier — the did/didtype registration parameters are accepted ' +
              'and ignored.' },

  { id: 'rfc4511', name: 'LDAP v3: the protocol (RFC 4511)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc4511',
    coverage: 'partial: bind (simple), unbind, add, delete, modify, modifyDN, compare and ' +
              'search, on TWO listeners carrying the same handlers and the same store — ' +
              'plain TCP 389 and LDAPS (TLS from the first byte) on 636 — with the root DSE ' +
              'and result codes 0 (success), 2 ' +
              '(protocolError), 4 (sizeLimitExceeded), 11 (adminLimitExceeded), 16 ' +
              '(noSuchAttribute), 32 (noSuchObject), 49 (invalidCredentials), 66 ' +
              '(notAllowedOnNonLeaf) and 68 (entryAlreadyExists) all reachable on both. ' +
              'No SASL, no StartTLS, no controls ' +
              '(so no paged results and no sorting), no extended operations and no ' +
              'referrals. StartTLS is named twice there on purpose: it IS an extended ' +
              'operation (section 4.14), so "no extended operations" and "no StartTLS" are ' +
              'one fact rather than two, and the way to TLS here is the other port. ' +
              // The rule these notes follow: say what would mislead somebody who believed
              // the row. "Bind is implemented" is true and, alone, implies credentials.
              'EVERY BIND SUCCEEDS — any DN, any password, anonymous included — with the ' +
              'single exception of the literal password "invalid", which is refused with ' +
              'LDAP_INVALID_CREDENTIALS so a negative test has something to fail on. It is ' +
              'the ldapjs 3.0.7 library, pinned as a submodule and used unmodified; what is ' +
              'written here is the handlers.' },
  { id: 'rfc4512', name: 'LDAP v3: directory information models (RFC 4512)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc4512',
    coverage: 'mock: the tree, the root DSE and namingContexts are real; THE SCHEMA IS NOT ' +
              'THERE AT ALL. No objectClass is enforced, no attribute is checked against a ' +
              'syntax or a matching rule, and there is no subschema subentry — so an entry ' +
              'may carry any attribute a client cares to send, which a real directory would ' +
              'refuse. Three structural rules are still enforced, because their absence ' +
              'would teach a client something false: an add needs its parent, a delete needs ' +
              'a leaf, and an attribute with no values does not exist.' },
  { id: 'rfc4513', name: 'LDAP v3: authentication methods and security mechanisms (RFC 4513)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc4513',
    coverage: 'partial, and the part that is here is the TRANSPORT rather than the ' +
              'authentication: simple bind (section 5.1) is the only method offered — no ' +
              'SASL, so no EXTERNAL and no DIGEST-MD5 — and it authenticates nobody, since ' +
              'every bind succeeds except the literal password "invalid". What TLS on 636 ' +
              'adds is confidentiality for a password that was never going to be checked, ' +
              'which is worth having for a client that has to prove it can do LDAPS and ' +
              'worth saying out loud so nobody reads the TLS as authentication. StartTLS ' +
              '(section 3) is NOT implemented: it is an extended operation and the ldapjs ' +
              'submodule this service is built on implements none, and this repository does ' +
              'not patch that submodule. Worth knowing which of the two this document ' +
              'actually standardised — StartTLS is in here; ldaps:// is the de-facto scheme ' +
              'it left alone, which is why no RFC defines the thing every client speaks. ' +
              'The certificate is self-signed, regenerated on every start and shared with ' +
              'the two HTTPS listeners, so a client verifies it per run: fetch it from ' +
              'GET /tls/server-certificate rather than reaching for LDAPTLS_REQCERT=never, ' +
              'which would also hide the one thing worth checking here.' },
  { id: 'rfc4514', name: 'LDAP v3: string representation of distinguished names (RFC 4514)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc4514',
    coverage: 'partial: DNs are parsed and rendered by @ldapjs/dn, which implements this ' +
              'document. What this service adds — comparing two DNs for equality — is a ' +
              'simplification and says so: it case-folds and strips the whitespace around ' +
              'each comma, and does NOT do RFC 4518 string preparation, so a DN carrying an ' +
              'escaped comma inside a value is compared byte-wise.' },
  { id: 'rfc4515', name: 'LDAP v3: string representation of search filters (RFC 4515)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc4515',
    coverage: 'full for what @ldapjs/filter implements: presence, equality, substrings, ' +
              'greater-or-equal, less-or-equal, approximate, and the and/or/not composites. ' +
              'Matching is case-insensitive on both the attribute description and the value, ' +
              'because there is no schema to choose a matching rule from. An extensible ' +
              'match is not evaluated; the attempt is logged rather than silently treated as ' +
              'no match, since an unsupported filter and an empty directory look identical ' +
              'from the client.' },
  { id: 'rfc4519', name: 'LDAP v3: schema for user applications (RFC 4519)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc4519',
    coverage: 'mock: this document is where the NAMES this directory uses come from — cn, sn, ' +
              'uid, mail, givenName, member, uniqueMember, and the groupOfNames and ' +
              'organizationalUnit classes the seeded tree is built out of. NOTHING IN IT IS ' +
              'ENFORCED, which is the same absence RFC 4512 records: member is MUST on a ' +
              'groupOfNames here and an empty group is accepted, an entry may carry any of ' +
              'these attributes without the objectClass that defines them, and none of the ' +
              'syntaxes or matching rules is checked. memberOf is NOT from this document or any ' +
              'other — it is Microsoft\'s and OpenLDAP\'s, maintained by the server in the ' +
              'directories that have it and maintained by nothing here, so a client can write it ' +
              'onto an entry and disagree with the group. /admin/groups reports that ' +
              'disagreement rather than hiding it. Its applicationProcess class is the one ' +
              'REGISTERED class an application entry under ou=applications carries: it brings ' +
              'cn and description, and there is nothing standard anywhere for a client_id, a ' +
              'set of redirect URIs or a service principal name, so the rest of that schema is ' +
              'invented here and published at /ldap/applications rather than implied.' },
  { id: 'rfc8446', name: 'TLS 1.3 (RFC 8446), and TLS 1.2 (RFC 5246)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc8446',
    coverage: 'full, and none of it is this service\'s code — the two HTTPS listeners and ' +
              'the directory\'s LDAPS listener on 636 are ' +
              'node\'s own TLS stack over OpenSSL, with whatever versions and ciphers that ' +
              'build offers. What is written here is the POLICY and the REPORT: one listener ' +
              'asks for a client certificate and accepts whatever arrives, the other requires ' +
              'one, and both hand back what the server saw. Two things about client ' +
              'authentication are worth knowing before reading that report. Under TLS 1.3 the ' +
              'client sends its Certificate and Finished LAST, so the handshake is complete ' +
              'from its point of view before the server has said anything about the ' +
              'certificate — a client that reports success on secureConnect will report a ' +
              'happy mutual-TLS connection to a server that rejected it a millisecond later. ' +
              'And node refuses an unverified client certificate by CLOSING THE SOCKET WITH NO ' +
              'ALERT, which is why the permissive listener exists at all: it is the only one ' +
              'that can tell you why.' },
  { id: 'rfc5280', name: 'X.509 certificates and CRLs (RFC 5280)',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc5280',
    coverage: 'partial, and the path validation is OpenSSL\'s rather than this service\'s: ' +
              'client certificates are verified against anchors POSTed to /tls/trust at ' +
              'runtime, and the server certificate is self-signed here per start with a ' +
              'subjectAltName carrying every name this stack is reached by. NO REVOCATION IS ' +
              'CHECKED — no CRL is fetched and no OCSP responder is consulted — so a revoked ' +
              'certificate verifies here and would not verify anywhere that matters. Name ' +
              'constraints, policies and path length are enforced only to the extent OpenSSL ' +
              'enforces them, which is to say properly, and by nothing written here.' },
  { id: 'ws-trust', name: 'WS-Trust 1.4 (and 1.0-1.3)',
    where: 'OASIS ws-sx',
    url: 'https://docs.oasis-open.org/ws-sx/ws-trust/v1.4/ws-trust.html',
    coverage: 'partial: Issue, Renew, Validate and Cancel over SOAP 1.1 and 1.2. ' +
              'Request signatures are not verified and no policy is enforced — this is a test STS.' },
  { id: 'wss-username', name: 'WS-Security UsernameToken Profile 1.1',
    where: 'OASIS wss',
    url: 'https://docs.oasis-open.org/wss/v1.1/wss-v1.1-spec-os-UsernameTokenProfile.pdf',
    coverage: 'mock: a UsernameToken is accepted when both members are present. No password is ever ' +
              'checked, except that the literal "invalid" is refused so a negative test can force a failure.' },
  { id: 'saml2', name: 'SAML 2.0 Core',
    where: 'OASIS saml-core-2.0-os',
    url: 'https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
    coverage: 'partial: issues signed Assertions (AuthnStatement, AttributeStatement, ' +
              'SubjectConfirmation with the bearer SubjectConfirmationData the Web SSO profile ' +
              'requires, Conditions), carried by WS-Trust, by WS-Federation, and since 2026-08-24 ' +
              'in a <samlp:Response> of its own — THERE IS A WEB BROWSER SSO PROFILE NOW, at ' +
              '/saml2, and the three rows below cover its bindings, profiles and metadata. What ' +
              'is still absent: no assertion is encrypted, no AuthnRequest signature is verified, ' +
              'and no <samlp:AttributeQuery> is answered. The WS-FEDERATION metadata still ' +
              'publishes no IDPSSODescriptor, which is now a fact about that document rather than ' +
              'about this service — the SAML 2.0 metadata at /saml2/metadata is where the ' +
              'IDPSSODescriptor is.' },
  { id: 'saml2-bindings', name: 'SAML 2.0 Bindings',
    where: 'OASIS saml-bindings-2.0-os',
    url: 'https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf',
    coverage: 'partial: HTTP Redirect (section 3.4) with the DEFLATE encoding and the detached ' +
              'query-string signature of 3.4.4.1, HTTP POST (3.5), HTTP Artifact (3.6) with the ' +
              'type 0x0004 artifact and the one-shot rule of 3.6.4.1, and SOAP over HTTP (3.2.3) ' +
              'for the artifact resolution back channel. NOT here: PAOS (3.3), which is refused ' +
              'by name rather than quietly answered over POST, and the URI binding (3.7). A ' +
              'request signature is recorded and never verified.' },
  { id: 'saml2-profiles', name: 'SAML 2.0 Profiles',
    where: 'OASIS saml-profiles-2.0-os',
    url: 'https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf',
    coverage: 'partial: the Web Browser SSO profile (section 4.1) service-provider-initiated, over ' +
              'all three bindings, with the bearer SubjectConfirmationData 4.1.4.2 requires; and ' +
              'Single Logout (4.4), both directions, WITHOUT front-channel fan-out — an ' +
              'identity-provider-initiated logout NAMES the other service providers and builds a ' +
              'LogoutRequest for each rather than firing them into frames it cannot observe. NOT ' +
              'here: identity-provider-initiated SSO with an unsolicited Response, the ECP ' +
              'profile (4.2), Name Identifier Management (4.5), and the Assertion Query and ' +
              'Request profile (6). No assertion is encrypted.' },
  { id: 'saml2-metadata', name: 'SAML 2.0 Metadata',
    where: 'OASIS saml-metadata-2.0-os',
    url: 'https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf',
    coverage: 'partial: a signed EntityDescriptor holding one IDPSSODescriptor, and ONE PER ' +
              'SERVICE PROVIDER — a distinct entityID and its own endpoints, which is what Okta ' +
              'and Ping publish. It is minted for any entityID asked for. This service PUBLISHES ' +
              'metadata and does not CONSUME it: there is no SPSSODescriptor ingest, which is why ' +
              'a service provider\'s logout return address has to be declared and why an ' +
              'assertion consumer service URL is taken from the request rather than looked up.' },
  { id: 'saml11', name: 'SAML 1.1 Core',
    where: 'OASIS oasis-sstc-saml-core-1.1',
    url: 'https://www.oasis-open.org/committees/download.php/3406/oasis-sstc-saml-core-1.1.pdf',
    coverage: 'partial: issues signed Assertions with an AuthenticationStatement and an ' +
              'AttributeStatement, which is the DEFAULT token of the WS-Federation profile here ' +
              'because it is what AD FS issues. THIS NOTE USED TO SAY there was no SAML 1.1 ' +
              'request/response protocol and no browser artifact profile, and that the assertion ' +
              'only ever travelled in a wresult; since 2026-08-24 /saml11 is a browser-facing ' +
              'identity provider and /saml11/responder answers a <samlp:Request> in all four of ' +
              'its shapes. What is still absent: the fifth request type, ' +
              'AuthorizationDecisionQuery, which is refused by name because this service makes no ' +
              'authorization decisions; and there is no SAML 1.1 Single Logout to implement, ' +
              'because the protocol has none.' },
  { id: 'saml11-bindings', name: 'SAML 1.1 Bindings and Profiles',
    where: 'OASIS oasis-sstc-saml-bindings-1.1',
    url: 'https://www.oasis-open.org/committees/download.php/3405/oasis-sstc-saml-bindings-1.1.pdf',
    coverage: 'partial: the SOAP binding (section 3.1) for the SAML responder, and the type ' +
              '0x0001 artifact of 3.2.2 — FORTY-TWO bytes, where a SAML 2.0 artifact is 44: 2.0 ' +
              'added a two-byte EndpointIndex that 1.1 has no field for, so a relying party ' +
              'assuming the newer layout reads the SourceID two bytes late. An artifact resolves ' +
              'EXACTLY ONCE (3.2.3): resolving destroys it, and the second attempt is refused ' +
              'with a status naming the reason.' },
  { id: 'saml11-profiles', name: 'SAML 1.1 Profiles',
    where: 'OASIS oasis-sstc-saml-profile-1.1',
    url: 'https://www.oasis-open.org/committees/download.php/3404/oasis-sstc-saml-profile-1.1.pdf',
    coverage: 'partial: BOTH browser profiles — Browser/Artifact (section 4.1) and Browser/POST ' +
              '(4.2) — each with the confirmation method its section requires, which are ' +
              'different values and are not interchangeable. THERE IS NO REQUEST MESSAGE IN SAML ' +
              '1.1, so both are identity-provider-initiated: a flow starts when a browser arrives ' +
              'carrying a TARGET, the relying party never identifies itself in the protocol, and ' +
              'a failure is a PAGE rather than a Response because there is nothing to answer. ' +
              'Shibboleth\'s non-standard AuthnRequest profile ' +
              '(urn:mace:shibboleth:1.0:profiles:AuthnRequest) is accepted and advertised, ' +
              'because it is what every real SAML 1.1 service provider sends.' },
  { id: 'ws-federation', name: 'WS-Federation 1.2',
    where: 'OASIS wsfed',
    url: 'https://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html',
    coverage: 'partial: the Web (Passive) Requestor Profile of section 13 — wsignin1.0 with wtrealm, ' +
              'wreply, wctx, wct, wfresh, wauth, whr and wreq, the sign-in response as a form POST, ' +
              'and wsignout1.0/wsignoutcleanup1.0 with front-channel cleanup requests. Signed ' +
              'federation metadata (section 3.1) at the AD FS path. NOT implemented, and each is ' +
              'named rather than left silent: the active (SOAP) requestor profile beyond what /sts ' +
              'already answers, wresultptr, the attribute service (wattr1.0) and the pseudonym ' +
              'service (wpseudo1.0) which both answer 501, wreqptr (refused — dereferencing a URL ' +
              'from a query parameter is a server-side request forgery), token encryption in this ' +
              'profile (a passive request carries no recipient certificate), and any authorization ' +
              'or policy enforcement.' },
  { id: 'xmldsig', name: 'XML Signature and XML Encryption',
    where: 'W3C',
    url: 'https://www.w3.org/TR/xmldsig-core1/',
    coverage: 'full for what it emits: enveloped signature, exclusive canonicalization, ' +
              'RSA-SHA256; AES-256-CBC content encryption with an RSA-OAEP wrapped key.' },
  { id: 'rfc6749', name: 'RFC 6749 — OAuth 2.0',
    where: 'IETF',
    url: 'https://www.rfc-editor.org/rfc/rfc6749',
    coverage: 'partial: authorization_code, implicit, password, client_credentials and ' +
              'refresh_token. Client authentication is accepted, not verified — EXCEPT in RFC ' +
              '9700 mode, where a client registered here as confidential must present the ' +
              'client_secret this service issued it (section 2.5, the one credential checked ' +
              'anywhere in this service). That mode also refuses the password and implicit ' +
              'grants outright and rotates refresh tokens.' },
  { id: 'rfc6750', name: 'RFC 6750 — Bearer Token Usage',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc6750',
    coverage: 'partial: bearer tokens are read from the Authorization header. Credential endpoints ' +
              'check that a token is PRESENT but cannot validate one issued by a separate ' +
              'authorization server.' },
  { id: 'rfc7009', name: 'RFC 7009 — Token Revocation',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc7009',
    coverage: 'full: revocation takes effect — a revoked token is reported inactive by introspection.' },
  { id: 'rfc7515', name: 'RFC 7515/7516/7517/7518 — JWS, JWE, JWK, JWA',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc7515',
    coverage: 'partial: RS256 signatures throughout; RSA-OAEP-256 with A128GCM/A256GCM for the ' +
              'encrypted Credential Request and Response.' },
  { id: 'rfc7519', name: 'RFC 7519 — JSON Web Token',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc7519',
    coverage: 'full: every token this service issues is an RS256 JWT that verifies against the ' +
              'published JWKS.' },
  { id: 'rfc7591', name: 'RFC 7591 — Dynamic Client Registration',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc7591',
    coverage: 'full: registers a client, returns its credentials and a registration access token.' },
  { id: 'rfc7592', name: 'RFC 7592 — Dynamic Client Registration Management',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc7592',
    coverage: 'full for the three operations: read, update and delete a registered client, each ' +
              'guarded by the registration access token issued with it.' },
  { id: 'rfc7636', name: 'RFC 7636 — PKCE',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc7636',
    coverage: 'partial: S256 and plain are advertised and the challenge is carried through the ' +
              'authorization code.' },
  { id: 'rfc7662', name: 'RFC 7662 — Token Introspection',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc7662',
    coverage: 'full: honest active/inactive, with the claims of the token presented.' },
  { id: 'rfc7800', name: 'RFC 7800 — Proof-of-Possession Key Semantics',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc7800',
    coverage: 'full for the use made of it: cnf.jwk binds an issued credential to the holder key ' +
              'whose possession was proved.' },
  { id: 'rfc9449', name: 'RFC 9449 — DPoP (Demonstrating Proof of Possession)',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc9449',
    coverage: 'full for a mock: all twelve section 4.3 proof checks, cnf.jkt on access AND refresh ' +
              'tokens, token_type DPoP, the dpop_jkt authorization request parameter (section 10), ' +
              'jti replay detection, and the server-supplied nonce handshake in both shapes — 400 ' +
              'use_dpop_nonce at the token endpoint, 401 with WWW-Authenticate at a protected one. ' +
              'Nonces are off until /dpop/nonce-mode turns them on. Not implemented: the ' +
              'authorization-code binding via PAR, and mTLS-bound tokens (RFC 8705), which are the ' +
              "other way to sender-constrain. Note a foreign access token's cnf cannot be trusted " +
              'here, since this issuer does not verify a token the separate authorization server ' +
              'signed — the check is real only for tokens this service issued.' },
  { id: 'rfc8414', name: 'RFC 8414 — Authorization Server Metadata',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc8414',
    coverage: 'full: every member section 2 defines, plus a genuinely signed signed_metadata. ' +
              'Served at the well-known path and with an issuer path component appended.' },
  { id: 'rfc8693', name: 'RFC 8693 — Token Exchange',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc8693',
    coverage: 'partial: the grant is accepted at the token endpoint and the subject token becomes ' +
              'the identity in the issued token.' },
  { id: 'rfc9396', name: 'RFC 9396 — Rich Authorization Requests',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc9396',
    coverage: 'partial: authorization_details of type openid_credential, which is how OID4VCI asks ' +
              'for a credential without a scope, with its optional claims member (a subset of the ' +
              'claims the metadata advertises) honoured by the credential endpoint. Accepted at the ' +
              'token endpoint too, which is the only place the pre-authorized code flow can ask. ' +
              'Granted details come back on the token response.' },
  { id: 'rfc9207', name: 'RFC 9207 — Authorization Server Issuer Identification',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc9207',
    coverage: 'full: every authorization response carries iss, errors included, and both discovery ' +
              'documents advertise authorization_response_iss_parameter_supported so a client knows ' +
              'it may require it.' },
  { id: 'rfc8705', name: 'RFC 8705 — Mutual-TLS Client Authentication and Certificate-Bound Access Tokens',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc8705',
    coverage: 'partial, and the split is the point: SECTION 3 — certificate-bound access ' +
              'tokens — is implemented and section 2 — mutual-TLS client authentication, where ' +
              'the certificate replaces the client_secret — is not. A Token Request made over ' +
              'a connection carrying a client certificate is answered with cnf["x5t#S256"] on ' +
              'the access AND refresh tokens, the base64url SHA-256 of the certificate\'s DER, ' +
              'and the four protected endpoints thumbprint the connection\'s certificate and ' +
              'compare. An UNVERIFIED certificate still binds, which section 3 permits ' +
              'explicitly — the proof is that the same key completed the handshake, not that a ' +
              'CA vouched for it. Only available where the main port is TLS (global.https), ' +
              'since that is where the token endpoint is, and advertised as ' +
              'tls_client_certificate_bound_access_tokens only there.' },
  { id: 'rfc8707', name: 'RFC 8707 — Resource Indicators for OAuth 2.0',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc8707',
    coverage: 'full for the authorization code flow: `resource` is read at the authorization ' +
              'endpoint and again at the token endpoint and becomes the access token\'s aud. ' +
              'It must be an absolute URI with no fragment, it may be repeated for the small ' +
              'set of resource servers RFC 9700 section 2.3 allows, and the token endpoint may ' +
              'NARROW what the authorization request asked for and never widen it. The ' +
              'resource server here then refuses a token issued for another audience. Not ' +
              'implemented: the parameter on the other grants, and there is no metadata member ' +
              'for it to advertise — the RFC defines none.' },
  { id: 'oauth-form-post', name: 'OAuth 2.0 Form Post Response Mode',
    where: 'OpenID Foundation',
    url: 'https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html',
    coverage: 'full: response_mode=form_post is answered with a self-submitting form POSTing ' +
              'every response parameter — code or token, state, and the RFC 9207 iss — to the ' +
              'redirect_uri, so the response is in no URL, no browser history entry and no ' +
              'Referer header (RFC 9700 section 4.3). ERROR responses honour it too, which is ' +
              'the half that is easy to miss: a failure delivered in a query string is a ' +
              'failure in browser history. The page carries a real submit button as well as ' +
              'the script, because script-src is \'none\' here and with the script blocked the ' +
              'button is the whole mechanism. It was ADVERTISED AND MISSING for a long time — ' +
              'every request got a 302 whatever it asked for — which is why the member was ' +
              'removed from the metadata until this existed.' },
  { id: 'rfc7523', name: 'RFC 7523 — JWT Profile for OAuth 2.0 Client Authentication',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc7523',
    coverage: 'full for section 2.2 and section 3, which is CLIENT AUTHENTICATION by assertion: ' +
              'private_key_jwt is verified against the JWKS the client registered and ' +
              'client_secret_jwt against its secret, with iss and sub both required to be the ' +
              'client, the audience allowed to be the token endpoint or the issuer (RFC 7523 ' +
              'and OpenID Connect Core section 9 name different ones and deployments differ), ' +
              'expiry with a configurable skew, and a jti remembered until the assertion ' +
              'expires so a replay is refused. An assertion nominating an HMAC alg for ' +
              'private_key_jwt is REFUSED rather than verified with the public key as a ' +
              'secret — the classic forgery, and one anybody can perform because the key is ' +
              'public. NOT implemented: section 2.1, the JWT authorization GRANT, which is a ' +
              'way of getting a token rather than of authenticating a client.' },
  { id: 'rfc9700', name: 'RFC 9700 — OAuth 2.0 Security Best Current Practice',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc9700',
    coverage: 'partial, AND OFF BY DEFAULT — it is a MODE (oauth2.rfc9700) rather than how this ' +
              'service behaves, because a client is exercised by both answers and every existing ' +
              'caller of this mock uses an unregistered redirect_uri, no PKCE, the implicit grant ' +
              'or the password grant. Turned on it covers the whole of section 2. ' +
              '2.1: exact-string redirect URI matching with RFC 8252\'s loopback port exception, ' +
              'no open redirector at the authorization endpoint OR at end_session_endpoint, no ' +
              'http redirect URI off the loopback, and the main port bound as HTTPS so an ' +
              'authorization response is not sent over an unencrypted connection. ' +
              '2.1.1: PKCE required of every client not registered as confidential, S256 only, ' +
              'the section 4.8.2 downgrade refusal, a nonce with any id_token, and the RFC 6749 ' +
              'section 4.1.3 client and redirect_uri checks at the token endpoint. ' +
              '2.1.2: no response type that issues an access token from the authorization ' +
              'endpoint. 2.2.2: refresh token ROTATION, replay detection that revokes the whole ' +
              'chain, and the client binding this grant never checked. 2.3: a refresh may narrow ' +
              'a scope and never widen it; access tokens were already audience-restricted to one ' +
              'resource server. 2.4: the password grant refused. 2.5: a client registered here ' +
              'as confidential must authenticate, by any of the six token-endpoint methods — ' +
              'client_secret_basic and _post, client_secret_jwt, private_key_jwt against a ' +
              'registered JWKS, and RFC 8705 section 2\'s tls_client_auth and ' +
              'self_signed_tls_client_auth — all verified, which is the one credential this ' +
              'service checks anywhere. 2.6: CORS withheld from the authorization endpoint. ' +
              'Both discovery documents stop advertising whatever the mode would refuse. Three ' +
              'things are DETECTED rather than enforced, because they are the client\'s to keep: ' +
              'reuse of a code_challenge or nonce across transactions (which a real server ' +
              'generally cannot see and a mock that remembers can), an unbound access token ' +
              '(section 2.2 is a SHOULD and there is deliberately no "DPoP required" mode), and ' +
              'symmetric client authentication where 2.5 recommends asymmetric — the ' +
              'preference is detected, but all SIX methods are now genuinely verified, the ' +
              'three asymmetric ones included. Section 4.5 ' +
              'Sections 2.2 and 2.3 are covered as far as an authorization server can cover ' +
              'them: BOTH sender-constraining mechanisms are implemented (DPoP, and RFC 8705 ' +
              'certificate binding wherever the main port is TLS), the resource server ' +
              'validates the proof and prevents its replay, RFC 8707 resource indicators make ' +
              'the audience restrictable to one resource server or a small set, and a token ' +
              'issued for another audience is refused at the protected endpoints. Section 4.5 ' +
              'is covered too: the code is single use with the replay relaxation turned off, a ' +
              'second presentation REVOKES the access, refresh and ID Tokens it bought, and the ' +
              'code is bound to the client that redeems it. TWO REQUIREMENTS ARE STATED AS ' +
              'UNENFORCEABLE rather than omitted — the client must validate the ID Token nonce ' +
              'and must not use a token before that succeeds, neither of which this server can ' +
              'observe; oauth2.breakIdTokenNonce spoils the nonce on purpose so a client author ' +
              'can find out whether their own code checks it. NOT covered: ' +
              'Pushed Authorization Requests (RFC 9126) and Resource Indicators (RFC 8707), ' +
              'which are features this service does not have rather than constraints it declines ' +
              'to enforce. GET /oauth2/rfc9700 lists every requirement with which of those it ' +
              'is.' },
  { id: 'webauthn', name: 'Web Authentication (WebAuthn) Level 3',
    where: 'W3C',
    url: 'https://www.w3.org/TR/webauthn-3/',
    coverage: 'partial, relying-party side: registration (section 7.1) and assertion (section 7.2) ' +
              'are verified — challenge, origin, RP ID hash, user presence and verification flags, ' +
              'the signature counter, and the signature over authenticatorData || ' +
              'SHA-256(clientDataJSON), for ES256, RS256 and EdDSA keys. Attestation statements are ' +
              'decoded but NOT validated and no metadata service is consulted: this is a mock, and ' +
              'attesting to an authenticator\'s provenance is the one thing it must not pretend to ' +
              'do. Written independently of the debugger\'s own decoder so the two can be checked ' +
              'against each other (tests/webauthn_cross_impl.js).' },
  { id: 'oidc', name: 'OpenID Connect Core 1.0',
    where: 'OpenID Foundation', url: 'https://openid.net/specs/openid-connect-core-1_0.html',
    coverage: 'partial: id_token with nonce, at_hash and c_hash, the three authentication flows, and ' +
              'the section 5.3 UserInfo endpoint — which is the one place a scope changes what comes ' +
              'back, since the id_token carries every claim whatever was asked for. No request object.' },
  { id: 'oidc-fclogout', name: 'OpenID Connect Front-Channel Logout 1.0',
    where: 'OpenID Foundation',
    url: 'https://openid.net/specs/openid-connect-frontchannel-1_0.html',
    coverage: 'full for the provider\'s side of a specification that is mostly ' +
              'the relying party\'s: the two discovery members, the two ' +
              'per-client registration members, the `sid` claim on an ID Token ' +
              'issued on a browser session, and the sign-out page loading each ' +
              'registered frontchannel_logout_uri in a hidden iframe with iss ' +
              'and sid where the client asked for them. Three sign-outs render ' +
              'it — /oauth2/logout, /logout and the OIDC half of a global ' +
              'logout — through one function, so they cannot notify different ' +
              'sets. What the specification says CANNOT be known is not ' +
              'pretended to here either: section 5 states the provider cannot ' +
              'tell whether a notification succeeded, so every URL is printed ' +
              'as a link beside its iframe rather than reported as sent. ' +
              'oauth2.frontchannelLogout turns all of it off, including the ' +
              'claim and the advertisement, which is the only honest way to ' +
              'switch it — a document advertising a capability whose claim is ' +
              'off would be a document that lies. BACK-CHANNEL logout is a ' +
              'different specification and is NOT implemented; the metadata ' +
              'says so.' },
  { id: 'oidc-discovery', name: 'OpenID Connect Discovery 1.0',
    where: 'OpenID Foundation', url: 'https://openid.net/specs/openid-connect-discovery-1_0.html',
    coverage: 'partial: the provider configuration document with every REQUIRED member of section 3, ' +
              'built by extending the RFC 8414 document so the two cannot disagree about the twenty ' +
              'members they share. Served at the well-known path, at the section 4 issuer-with-path ' +
              'form, and at the RFC 8414 inserted-path form. The acr, display and encryption members ' +
              'are ABSENT because none of them is implemented, and an invented value would be worse ' +
              'than the silence. WebFinger issuer discovery (section 2) is not implemented.' },
  { id: 'oidc-logout', name: 'OpenID Connect RP-Initiated Logout 1.0',
    where: 'OpenID Foundation',
    url: 'https://openid.net/specs/openid-connect-rpinitiated-1_0.html',
    coverage: 'mock: end_session_endpoint really does end the session, but id_token_hint is neither ' +
              'required nor checked and post_logout_redirect_uri is not validated against any ' +
              'registration. Front-channel and back-channel logout are not implemented and the ' +
              'discovery document says so rather than staying silent.' },
  { id: 'oid4vci', name: 'OpenID for Verifiable Credential Issuance 1.0',
    where: 'OpenID Foundation',
    url: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html',
    coverage: 'partial but broad: issuer metadata, nonce, proof of possession, batch issuance, ' +
              'deferred issuance, Credential Offers (Appendix H.1/H.2/H.3), the pre-authorized code ' +
              'grant with tx_code, credential_identifiers, request and response encryption ' +
              '(section 10), and the Notification Endpoint (section 11).' },
  { id: 'oid4vp', name: 'OpenID for Verifiable Presentations 1.0',
    where: 'OpenID Foundation',
    url: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html',
    coverage: 'partial: Authorization Requests by value and as a signed Request Object by reference, ' +
              'response_mode=direct_post, a DCQL query, and full verification of what comes back. ' +
              'No presentation_definition (DIF PE) — DCQL only.' },
  { id: 'sd-jwt', name: 'RFC 9901 — Selective Disclosure for JWTs (SD-JWT)',
    where: 'IETF', url: 'https://www.rfc-editor.org/rfc/rfc9901',
    coverage: 'full for issuance and verification: _sd digests with a decoy, salted Disclosures, the ' +
              'Combined Serialization, and a Key Binding JWT checked including sd_hash over the exact ' +
              'bytes presented.' },
  { id: 'sd-jwt-vc', name: 'SD-JWT-based Verifiable Credentials (draft-ietf-oauth-sd-jwt-vc)',
    where: 'IETF', url: 'https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/',
    coverage: 'partial: vct, cnf holder binding, and the /.well-known/jwt-vc-issuer key resolution ' +
              'document. Naming the issuer by DID is an EXTENSION — this document defines no ' +
              'DID-based issuer signature mechanism.' },
  { id: 'vcdm', name: 'W3C Verifiable Credentials Data Model 1.1 and 2.0',
    where: 'W3C', url: 'https://www.w3.org/TR/vc-data-model-2.0/',
    coverage: 'partial: the VC-JWT encoding of VCDM 1.1 (jwt_vc_json) and VCDM 2.0 credentials with ' +
              'an embedded proof (ldp_vc).' },
  { id: 'di-bbs', name: 'W3C Data Integrity — bbs-2023 cryptosuite',
    where: 'W3C', url: 'https://www.w3.org/TR/vc-di-bbs/',
    coverage: 'full for base proofs and derived proofs over BLS12-381, including the mandatory ' +
              'pointers and the unlinkable selective disclosure a derived proof provides.' },
  { id: 'rdf-c14n', name: 'RDF Dataset Canonicalization (URDNA2015) and JSON-LD 1.1',
    where: 'W3C', url: 'https://www.w3.org/TR/rdf-canon/',
    coverage: 'full for what Data Integrity needs. JSON-LD contexts are VENDORED, never fetched: ' +
              'canonicalization that depended on a network fetch would be neither reproducible nor safe.' },
  { id: 'did-core', name: 'W3C DID Core 1.0 (did:web, did:key, did:jwk)',
    where: 'W3C', url: 'https://www.w3.org/TR/did-1.0/',
    coverage: 'partial: this service PUBLISHES a did:web document with two verification methods. ' +
              'The wallet side resolves all three methods.' },
  { id: 'did-config', name: 'DIF Well Known DID Configuration',
    where: 'DIF',
    url: 'https://identity.foundation/well-known-did-configuration/resources/did-configuration/',
    coverage: 'full in the JWT form: a Domain Linkage Credential proving this origin and this DID ' +
              'are the same entity. The Linked Data Proof form is not served.' }
];

// ---------------------------------------------------------------------------
// What each endpoint IS. Keyed by the Express path so it can be joined to the
// router's own list; the HTTP methods are never written here, because the router
// knows them and this file would only get them wrong.
//
// `group` orders the page. `specs` are ids from SPECS above; a typo there is
// reported on the page rather than silently dropping the link.
// ---------------------------------------------------------------------------
const ENDPOINTS = [
  // --- Kerberos ---
  //
  // Note what is NOT on this page and cannot be: the KDC's own listeners are RAW SOCKETS
  // on TCP and UDP port 88, and the protected service is a raw TCP socket of its own.
  // This page is built by walking the live Express router, which is exactly why it cannot
  // go stale — and a protocol that registers no route is the one blind spot that design
  // has. The three HTTP endpoints below are the only Kerberos surfaces the walk can see;
  // the sockets are described in their rows' text so a reader is not left thinking port
  // 88 does not exist.
  { path: '/KdcProxy', group: 'Kerberos', name: 'KDC Proxy (MS-KKDCP)',
    // rfc3961 belongs here because every message this relays has enc-parts encrypted under
    // that framework by the KDC behind it — and because a specification nothing links to is
    // an IDLE CLAIM, which tests/sts_metadata.js fails the page for. It was listed and
    // unlinked when the Kerberos rows were first added.
    specs: ['ms-kkdcp', 'rfc4120', 'rfc3961'],
    what: 'Relays a KDC-PROXY-MESSAGE to the KDC listening on TCP and UDP port 88 in this ' +
          'process. A browser cannot open a raw socket, so this is how the in-browser client ' +
          'reaches a KDC without the api relay.' },
  { path: '/krb5/principals', group: 'Kerberos', name: 'What the KDC knows',
    // The salts and the offered etypes ARE the RFC 3961/3962 surface: string-to-key takes
    // the salt, and etype negotiation is what the list decides.
    specs: ['rfc4120', 'ms-pac', 'rfc3961'],
    what: 'The principal database of both realms: names, salts (which are NOT derivable from ' +
          'the principal name, which is why PA-ETYPE-INFO2 exists), offered etypes, the ' +
          'deliberate misconfigurations, and the PAC identity each account carries. Also the ' +
          'account policy — any username authenticates, every user shares one password, and ' +
          'this is where that password is written down. Not a real ' +
          'Kerberos endpoint — a KDC publishes none of this.' },
  { path: '/krb5/service', group: 'Kerberos', name: 'The protected service',
    specs: ['rfc4120'],
    what: 'What the AP-REQ acceptor is, where its raw TCP socket is listening, and the ordered ' +
          'checks it applies to a ticket. Not a real Kerberos endpoint either.' },
  { path: '/spnego', group: 'Kerberos', name: 'A SPNEGO-protected page is advertised here',
    specs: ['rfc4559', 'rfc4178', 'rfc4120'],
    what: 'Says that /spnego/protected exists, which service principal name is behind it, ' +
          'which mechanisms are accepted, and which query knobs make the negotiation fail in ' +
          'one specific way. None of that is in the protocol exchange itself — a client has to ' +
          'derive the SPN from the URL and find the KDC from its own configuration, which is ' +
          'why so many SPNEGO failures leave no evidence on the wire. Add ?format=json.' },
  { path: '/spnego/protected', group: 'Kerberos', name: 'The protected resource',
    // rfc3961 is linked because the AP-REQ inside the mechToken, its Authenticator and the
    // AP-REP returned for mutual authentication are all encrypted under that framework.
    specs: ['rfc4559', 'rfc4178', 'rfc4120', 'rfc3961', 'ms-pac'],
    what: 'Answers 401 with a bare "WWW-Authenticate: Negotiate" to an unauthenticated ' +
          'request, and 200 with an AP-REP in that header to a valid one. The Kerberos checks ' +
          'are krb5_service.js\'s, unchanged — this endpoint adds the negotiation and the ' +
          'HTTP that carries it and no protocol code of its own.' },

  // --- LDAP ---
  //
  // The same blind spot the Kerberos rows above describe, and for the same reason: the
  // directory is a RAW TCP SOCKET on port 389 — and, since LDAPS, a SECOND raw socket on
  // 636 — while this page is built by walking the Express router, and the walk cannot see
  // either of them. Two sockets rather than one is the part that is easy to miss when
  // reading this page for what LDAP surface exists: neither appears below, and a reader
  // who counts rows would conclude the directory is HTTP. The two rows below are the only
  // LDAP surfaces that ARE HTTP, and NEITHER OF THEM IS LDAP — they are this service
  // describing its own directory, which is what lets a reader tell an empty directory
  // from a search filter that matched nothing. Both listeners are described in their text.
  { path: '/ldap', group: 'LDAP', name: 'What the directory is',
    specs: ['rfc4511', 'rfc4512', 'rfc4513', 'rfc4514', 'rfc4515'],
    what: 'The embedded LDAPv3 directory: its URLs and ports (TCP 389 for plain LDAP and ' +
          'TCP 636 for LDAPS by default — RAW SOCKETS this page cannot see, so it reports ' +
          'whether each one actually bound), its base DN, the bind policy — every bind ' +
          'succeeds, any DN and any password, except the literal "invalid" — and the fact ' +
          'that it has NO SCHEMA (which is why the application entries under ou=applications ' +
          'come with a published vocabulary of their own; see /ldap/applications). The two listeners are one directory: the same handlers ' +
          'and the same store, so TLS changes what is on the wire and nothing about the ' +
          'answers, and a certificate presented to 636 is not asked for and would not be a ' +
          'login if it were. Also the structural rules it does still enforce and the ' +
          'one it deliberately does not (referential integrity: deleting a user leaves its ' +
          'DN in every group that lists it). Not an LDAP operation; the root DSE carries ' +
          'the machine-readable half of it. Add ?format=json.' },
  { path: '/ldap/spiffe', group: 'LDAP', name: 'The SPIFFE registry, and its schema',
    specs: ['rfc4511', 'rfc4519', 'spiffe-id'],
    what: 'THE TWO SPIFFE CONTAINERS AS THE DIRECTORY HOLDS THEM. ' +
          '`ou=entries,ou=spiffe` holds the registration entries — which SPIFFE ID a ' +
          'workload gets, under which parent, matching which selectors — and ' +
          '`ou=agents,ou=spiffe` holds what has attested. They are different KINDS of ' +
          'thing, which is why they are two containers: an entry is CONFIGURATION that ' +
          'decides what gets issued, and an agent is a RECORD of something that ' +
          'happened, so nothing about an agent is editable from the console. THE ' +
          'ENTRIES ARE THE REGISTRY rather than a copy of one: nothing caches them, so ' +
          'an ldapmodify of spiffeX509SvidTtl changes the lifetime of the next SVID the ' +
          'Workload API hands out. The page also publishes the SCHEMA — every object ' +
          'class and attribute, with which are editable — because this directory is ' +
          'schemaless and these ~30 attribute names are this service\'s own inventions: ' +
          'no registered LDAP schema has a SPIFFE ID or a selector on it. Add ' +
          '?format=json.' },
  { path: '/ldap/federations', group: 'LDAP',
    name: 'The federation register, and its schema',
    specs: ['rfc4511', 'rfc4512', 'rfc4519'],
    what: 'THE APPLICATION REGISTRY\'S TWIN, and the one container in this ' +
          'directory where AN LDAPMODIFY IS A SECURITY CHANGE. Every other ' +
          'edit here changes what this service HANDS OUT; ' +
          'fedSigningCertificate decides whose assertions it will BELIEVE and ' +
          'fedEnabled turns a partner on. It is a container of its own rather ' +
          'than a corner of ou=applications because half its entries are ' +
          'foreign identity providers, which ask this service for nothing at ' +
          'all — filing a party that authenticates people TO this service ' +
          'among the parties that consume what it issues would make the one ' +
          'question that container answers unanswerable. It publishes the ' +
          'schema for the same reason /ldap/applications does, plus a column ' +
          'that page has no need of: which DIRECTION each attribute is for. ' +
          'fedClientSecret is in the clear here, and it is this service\'s ' +
          'own credential at somebody else\'s — a stronger statement than ' +
          'anything else in this directory, made for the reason ' +
          '/krb5/principals prints the Kerberos passwords.' },
  { path: '/ldap/applications', group: 'LDAP', name: 'The application registry, and its schema',
    specs: ['rfc4511', 'rfc4512', 'rfc4519', 'rfc7591'],
    what: 'EVERY APPLICATION THIS SERVICE HAS BEEN ASKED ABOUT — an OAuth client, an OpenID ' +
          'Connect relying party, a SAML 2.0 or 1.1 service provider, a WS-Federation ' +
          'application, a WS-Trust relying party, the OpenID4VP verifier, a Kerberos service ' +
          '— one entry per unique identifier under ou=applications, so an application that ' +
          'speaks two protocols under one name is one row with two kinds. THE ENTRIES ARE ' +
          'THE REGISTRY rather than a copy of one: the RFC 7591 registrations live there, ' +
          'nothing caches them, and an ldapmodify of oauthRedirectUri changes which redirect ' +
          'URI RFC 9700 mode accepts on the next request. The page also publishes the SCHEMA ' +
          '— the object classes, the attributes and which protocol sets each — because ' +
          'node-ldapjs has no schema subsystem and this directory is schemaless: it is a ' +
          'vocabulary, not a constraint, and one nothing would enforce is worth reading ' +
          'rather than inferring. Two attributes hold credentials in the clear, for the ' +
          'reason /krb5/principals prints the Kerberos passwords. Add ?format=json.' },
  { path: '/ldap/directory', group: 'LDAP', name: 'Every entry in the directory',
    specs: ['rfc4511', 'rfc4514'],
    what: 'The whole store, DN by DN, with where each entry came from — seeded, added over ' +
          'LDAP, or created because somebody authenticated. That last column is the point: ' +
          'LDAP_AUTOCREATE_USERS (ON by default) grows an entry under ou=users for anybody ' +
          'who authenticates through ANY of the twelve protocol families here, through one ' +
          'hook on the funnel they all already pass. THAT HOOK NOW CARRIES THREE KINDS OF ' +
          'EVENT: an authentication, an ISSUANCE (every identity this trust domain mints ' +
          'an X509-SVID for gets the same entry, carrying the certificate as the same six ' +
          'x509* attributes a verified TLS client certificate writes — assigned rather ' +
          'than appended, because an SVID rotates every half-lifetime), and a CREDENTIAL ' +
          'STATUS, which is not a revocation and is explained on GET /spiffe. Not an ' +
          'LDAP operation. Add ?format=json.' },

  // --- SCIM ---
  //
  // The fifteenth family, and the only one whose purpose is to WRITE. Every row below
  // provisions into the embedded LDAP directory above — the same entries, the same cap,
  // no store of its own — so what SCIM created is reported by /ldap/directory,
  // /admin/users and /admin/groups rather than by anything here.
  //
  // Unlike Kerberos, LDAP and TLS, this group has NO blind spot: SCIM is HTTP all the
  // way down, so every one of its endpoints is a route on the plain listener and this
  // walk can see all of them. That is why the routes are registered against the shared
  // app one by one rather than behind a mounted express Router, which this walk skips.
  { path: '/scim', group: 'SCIM', name: 'What the SCIM surface is',
    specs: ['rfc7642', 'rfc7643', 'rfc7644', 'rfc7235', 'rfc7617', 'rfc7616',
            'rfc7486', 'rfc4511', 'rfc4519'],
    what: 'NOT a SCIM endpoint — a real server publishes none of this. What the ' +
          'provisioning surface is, what it writes into (the embedded directory, entry ' +
          'for entry), what a SCIM id is here (the entry\'s DN, and what that costs on a ' +
          'rename), every authentication scheme it offers with the access control policy ' +
          'behind them, the things it deliberately does not do, and the dozen things you ' +
          'can do to make it fail. Two are worth reading before pointing anything at it: ' +
          'THESE ENDPOINTS CREATE AND DELETE ACCOUNTS AND ARE THE ONE SURFACE HERE THAT ' +
          'REQUIRES A CREDENTIAL — while checking almost nothing about it, since anybody ' +
          'can get a token with either scope, any password but "invalid" passes Basic and ' +
          'anybody can register a HOBA key; and active:false DEACTIVATES NOBODY — it is ' +
          'stored as scimActive and read by nothing here. Add ?format=json.' },
  { path: '/scim/v2/ServiceProviderConfig', group: 'SCIM',
    name: 'What this SCIM server supports',
    specs: ['rfc7643', 'rfc7644', 'rfc7235', 'rfc7617', 'rfc7616', 'rfc7486'],
    what: 'RFC 7643 section 5. Filtering, sorting, PATCH and bulk are supported; ETag and ' +
          'changePassword are NOT, and are advertised as unsupported rather than ' +
          'half-implemented — a version built over a one-second timestamp would be a ' +
          'concurrency control a client trusts and that is wrong, and no password here is ' +
          'checked so there is none to change. THE DOCUMENT IS THE SERVER: the same object ' +
          'the endpoints read their limits from builds it, so it cannot advertise a page ' +
          'size or a bulk limit that is not the one enforced — and the same table that ' +
          'builds every WWW-Authenticate challenge builds authenticationSchemes, so a ' +
          'scheme that is turned off disappears from both together. THREE of the seven ' +
          'schemes published have no canonical `type` in RFC 7643 section 5 (a client ' +
          'certificate, a cookie and HOBA, all three named by RFC 7644 section 2) and ' +
          'carry an honest type of their own rather than being left out. READABLE ' +
          'WITHOUT A CREDENTIAL, unless scim.authDiscovery says otherwise: it is where a ' +
          'client learns which schemes exist.' },
  { path: '/scim/v2/ResourceTypes', group: 'SCIM', name: 'The resource types',
    specs: ['rfc7643'],
    what: 'User and Group, with the schema and the endpoint of each (RFC 7643 section 6) — ' +
          'and, on User, the enterprise extension as a schemaExtension, because the ' +
          'extension is DECLARED here rather than only mapped.' },
  { path: '/scim/v2/ResourceTypes/:id', group: 'SCIM', name: 'One resource type',
    specs: ['rfc7643'],
    what: 'One of the two above, by name.' },
  { path: '/scim/v2/Schemas', group: 'SCIM', name: 'The schemas',
    specs: ['rfc7643'],
    what: 'The core User and Group schemas with every attribute\'s characteristics — ' +
          'required, multi-valued, mutability, returned, uniqueness, canonical values. ' +
          'This is the half of SCIM that is genuinely hard to hand-roll and is why this ' +
          'service took a dependency rather than writing it.' },
  { path: '/scim/v2/Schemas/:id', group: 'SCIM', name: 'One schema',
    specs: ['rfc7643'],
    what: 'One schema by its URN.' },
  { path: '/scim/v2/Users', group: 'SCIM', name: 'Users: list and create',
    specs: ['rfc7644', 'rfc7643', 'rfc4511', 'rfc4519'],
    effect: 'POST creates an entry under ou=users in the embedded directory',
    what: 'GET is the list, with ?filter (section 3.4.2.2), ?sortBy, ?sortOrder, ' +
          '?startIndex, ?count, ?attributes and ?excludedAttributes. POST creates — and ' +
          'what it creates is an ORDINARY DIRECTORY ENTRY at uid=<userName>,ou=users, the ' +
          'same DN a person who signed in would have got, so provisioning somebody and ' +
          'authenticating as them produce one entry rather than two. userName is unique ' +
          '(409 uniqueness); the userName "invalid" is refused on purpose (400 ' +
          'invalidValue), the same reserved value every other protocol here refuses.' },
  { path: '/scim/v2/Users/.search', group: 'SCIM', name: 'Users: search by POST',
    specs: ['rfc7644'],
    what: 'Section 3.4.3 — the same query as a POST body, for a filter too long to put in ' +
          'a URL. The body must carry the SearchRequest schema URN and is refused with ' +
          '400 invalidSyntax if it does not: a POST to .search carrying a resource is a ' +
          'client that meant to create something, and answering it as an empty search ' +
          'would be the most confusing possible reply.' },
  { path: '/scim/v2/Users/:id', group: 'SCIM', name: 'One user: read, replace, modify, delete',
    specs: ['rfc7644', 'rfc7643', 'rfc4511'],
    effect: 'PUT and PATCH rewrite an entry under ou=users; DELETE removes it',
    what: 'THE id IS THE ENTRY\'S DN, percent-encoded — RFC 7643 section 3.1 wants an ' +
          'opaque server-assigned identifier and the DN already is one. PUT replaces ONLY ' +
          'THE MAPPED ATTRIBUTES and leaves the rest of the entry alone: read strictly, a ' +
          'SCIM PUT would delete schacDateOfBirth, authnMethod and every x509 attribute ' +
          'the moment a client updated a phone number, and those are facts SCIM never knew ' +
          'about and cannot restore. PATCH is section 3.5.2 in full, value-filter paths ' +
          'included. DELETE leaves the DN behind in every group that lists it, because ' +
          'this directory does no referential integrity on purpose.' },
  { path: '/scim/v2/Groups', group: 'SCIM', name: 'Groups: list and create',
    specs: ['rfc7644', 'rfc7643', 'rfc4519'],
    effect: 'POST creates an entry under ou=groups',
    what: 'The list is every group by BOTH of this directory\'s rules — under ou=groups, ' +
          'or carrying a group objectClass wherever it sits — because SCIM here is a view ' +
          'of that directory and a third opinion about what a group is would be the one ' +
          'that eventually disagrees. A created group gets placement AND a groupOfNames ' +
          'objectClass, so it stays a group if a client moves it.' },
  { path: '/scim/v2/Groups/.search', group: 'SCIM', name: 'Groups: search by POST',
    specs: ['rfc7644'],
    what: 'Section 3.4.3, for groups.' },
  { path: '/scim/v2/Groups/:id', group: 'SCIM', name: 'One group: read, replace, modify, delete',
    specs: ['rfc7644', 'rfc7643', 'rfc4519'],
    effect: 'PUT and PATCH rewrite a group entry; DELETE removes it',
    what: 'READ resolves member, uniqueMember and memberUid alike and returns each ' +
          'member as the DN — treating the three differently is how every posixGroup ' +
          'membership silently disappears. WRITE puts new values in member, since a SCIM ' +
          'member id is a DN, and clears the other two so that a client which removed ' +
          'everybody does not find the group still populated. A member naming nothing is ' +
          'ACCEPTED and logged: a dangling member is a state worth being able to produce.' },
  { path: '/scim/v2/.search', group: 'SCIM', name: 'Search across both resource types',
    specs: ['rfc7644'],
    what: 'Section 3.4.3 at the root, which is the one thing the per-type .search cannot ' +
          'do: one filter answered by Users AND Groups, merged into one ListResponse.' },
  { path: '/scim/v2/Bulk', group: 'SCIM', name: 'Bulk',
    specs: ['rfc7644'],
    effect: 'applies up to the advertised number of creates, updates and deletes in one request',
    what: 'Section 3.7. Each operation carries its own status, so a bulk in which one ' +
          'operation failed is still a 200 — the failure is inside it. The payload limit ' +
          'is checked against the number the ServiceProviderConfig ADVERTISES rather than ' +
          'against the express body parser\'s service-wide one, because a client reads a ' +
          'published limit as a promise.' },
  { path: '/scim/v2/Me', group: 'SCIM', name: '/Me, the authenticated subject',
    specs: ['rfc7644', 'rfc7235'],
    what: 'Section 3.11\'s alias for the subject the request authenticated as. GET, PUT, ' +
          'PATCH and DELETE resolve the credential to a directory entry and delegate to ' +
          'the SAME User handlers /Users/{id} uses, so there is no second read or write ' +
          'path to keep in step. It used to answer 501 on every method because nothing ' +
          'here authenticated, and TWO OF THOSE 501s ARE STILL RIGHT and are kept: an ' +
          'ANONYMOUS caller has no subject to alias (the alias is unavailable, which is ' +
          'not the same as the resource being missing), and POST would create a subject ' +
          'that by definition already exists. A credential naming somebody with no entry ' +
          '— a client_credentials token, a client certificate — gets 404 instead.' },
  { path: '/.well-known/hoba/register', group: 'SCIM',
    name: 'Register a HOBA public key',
    specs: ['rfc7486'],
    what: 'RFC 7486 section 7. A form-encoded POST carrying pub=<PEM public key> and (this ' +
          'service\'s own parameter) username=<who it is for>, answered with 201 and the ' +
          'Hobareg: regok header. UNAUTHENTICATED on purpose, for the reason POST ' +
          '/tls/trust is: it is how a caller GETS a credential, so requiring one to reach ' +
          'it would make the scheme unusable by anybody who did not already have another. ' +
          'Anybody may register any key for any name — the SIGNATURE is then really ' +
          'verified, which is the half that makes the scheme worth implementing. The key ' +
          'lands on the person\'s own entry under ou=users as hobaPublicKey, so an ' +
          'ldapsearch and /admin/users show it. GET describes the endpoint, because a ' +
          'well-known path that 404s to a browser is indistinguishable from one nobody ' +
          'implemented.' },

  // --- TLS ---
  //
  // The third instance of the blind spot the Kerberos and LDAP rows describe, and the
  // one where it is easiest to forget it applies: these listeners speak HTTP, so they
  // LOOK like they should already be on this page — but they are HTTPS on their own
  // sockets (8443 and 9443), and this page is built by walking the Express router of
  // the PLAIN listener. It cannot see them. The four rows below are the plain-HTTP
  // views; the listeners themselves are described in their text.
  //
  // There is a FOURTH TLS socket in this process and it is not in this group: the
  // directory's LDAPS listener on 636, which serves the certificate below. It is under
  // LDAP because that is the protocol it speaks, and the only reason to know it is here
  // is the certificate — one anchor covers all three.
  { path: '/tls', group: 'TLS', name: 'What the TLS endpoint is',
    specs: ['rfc8446', 'rfc5280'],
    what: 'Two HTTPS listeners on their own sockets — 8443 asks for a client certificate and ' +
          'never refuses one, 9443 REQUIRES one and refuses it during the handshake — whose ' +
          'entire content is what the SERVER saw: the request as it arrived, what TLS ' +
          'negotiated underneath it, and the client certificate exactly as presented. Neither ' +
          'is visible to this page, which walks the plain listener\'s router. This row is the ' +
          'description; GET /tls/whoami over either listener is the report itself. Add ' +
          '?format=json.' },
  { path: '/tls/forwarded', group: 'TLS', name: 'What a proxy told this service',
    specs: ['rfc9700', 'rfc8446'],
    what: 'NON-SPEC. The request as it ARRIVED and what was believed of it: every forwarding ' +
          'header, every client-certificate header a proxy might inject, whether ' +
          'global.trustProxy made this service believe any of it, and what the effective base ' +
          'URL came out as — which every issuer and every endpoint in both discovery documents ' +
          'is built from, so if that is wrong everything a client reads is wrong with it. RFC ' +
          '9700 section 2.6 has two halves here: a proxy MUST strip inbound security-sensitive ' +
          'headers before setting its own, which this service cannot do for it, and an ' +
          'application must not BELIEVE them unless a proxy is really there, which is what the ' +
          'setting is. NO CLIENT CERTIFICATE IS EVER READ FROM A HEADER in either mode — a ' +
          'certificate in a header is one anybody can forge — and the ones a request carried ' +
          'are listed so that ignoring them is visible rather than silent. Add ?format=json.' },
  { path: '/tls/server-certificate', group: 'TLS', name: 'The server certificate (PEM)',
    specs: ['rfc5280'],
    what: 'The self-signed certificate every TLS socket in this process presents, as PEM — ' +
          'both HTTPS listeners and the directory\'s LDAPS listener on 636, which serves this ' +
          'same certificate and key rather than a second pair. That is a decision about what ' +
          'a CALLER has to do rather than a saved keypair: one anchor covering 8443, 9443 and ' +
          '636 is ONE fetch, where two would make an ldapsearch fail with "unable to get local ' +
          'issuer certificate" against a truststore built for the HTTPS ports — an error that ' +
          'names nothing and reads as a broken directory. It is REGENERATED ' +
          'ON EVERY START, like the signing key, so it is an anchor nobody can have baked in ' +
          'and no cached copy of it stays valid — hence Cache-Control: no-store. Fetch it into ' +
          'your own truststore rather than switching verification off.' },
  { path: '/tls/trust', group: 'TLS', name: 'Trust a client certificate issuer',
    specs: ['rfc5280'],
    what: 'POST one or more PEM certificates — raw, or as the `certificates` field of a form or ' +
          'JSON body — and client certificates chaining to them verify from the next handshake ' +
          'onward (tls.Server.setSecureContext; existing connections keep the truststore they ' +
          'were made under). It starts EMPTY and has to: the CA it verifies is usually ' +
          'generated in a browser minutes before the connection and exists nowhere else, so no ' +
          'file could hold it. It is on the PLAIN port because that is the one reachable before ' +
          'anything is trusted. POST only.' },
  { path: '/tls/trust/clear', group: 'TLS', name: 'Empty the client truststore',
    specs: ['rfc5280'],
    what: 'Removes every anchor, returning the service to its starting state: no client ' +
          'certificate verifies, and nothing can connect to the listener that requires one. ' +
          'POST only.' },

  // --- service ---
  { path: '/', group: 'Service', name: 'The front page',
    specs: [],
    what: 'What this service is, in one card: the project on GitHub, its ' +
          'issues, the documentation site, and the admin console on this ' +
          'instance. It lists NO endpoints on purpose — this page is the ' +
          'list, it is generated, and a hand-written set of highlights on ' +
          'the front door would be a second copy of it that nothing checks. ' +
          'It was an unrouted path until 2026-08-24, so the answer to the ' +
          'one URL a person types first was Express\'s "Cannot GET /".' },
  { path: '/logo.png', group: 'Service', name: 'The logo on the front page',
    specs: [],
    what: 'The only image this service serves: the parent project\'s logo, ' +
          'resized and reduced to 31 kB, read from disk once at startup. If ' +
          'it could not be read this answers 404 in its own words rather ' +
          'than Express\'s, and the front page is drawn without it.' },
  { path: '/realms', group: 'Service', name: 'The trust realm directory',
    specs: [],
    what: 'NON-SPEC, and deliberately UNGATED. Every trust realm this process ' +
          'is running — a trust realm being a whole logical copy of this ' +
          'service, reached under a segment at the front of the path and ' +
          'holding its own configuration, signing key, sessions and tokens. ' +
          'It carries each realm\'s id, name, base URL and path prefix, the ' +
          'prefix SEGMENT itself (which is a setting, so a client cannot ' +
          'guess it), and which protocol families a realm actually ' +
          'separates. The last of those is the part nothing else answers: a ' +
          'realm separates what this service ISSUES and not the embedded ' +
          'DIRECTORY, and four families answer on sockets with nowhere to ' +
          'put a path segment at all — so somebody who assumed a realm was a ' +
          'boundary everywhere would find out from an ldapsearch. A client being pointed at a realm cannot construct a ' +
          'single URL without this, which is why it is not behind the ' +
          'console\'s gate — the same argument every discovery document ' +
          'here rests on.' },

  { path: '/healthcheck', group: 'Service', name: 'Health check',
    specs: [], what: 'Liveness only. Answers 200 with a JSON message; used by the compose healthcheck.' },
  { path: '/docs', group: 'Service', name: 'Service documentation',
    specs: ['rfc8414'], what: 'What the RFC 8414 service_documentation member points at.' },
  { path: '/policy', group: 'Service', name: 'Operator policy',
    specs: ['rfc8414'], what: 'What op_policy_uri points at.' },
  { path: '/tos', group: 'Service', name: 'Terms of service',
    specs: ['rfc8414'], what: 'What op_tos_uri points at.' },
  // Registered by app.options('*', cors(...)) rather than by a protocol module,
  // and listed because it IS callable and the page's first duty is to be a true
  // list of what is. It was the first thing the drift check caught: a route that
  // exists and is described nowhere.
  { path: '*', group: 'Service', name: 'CORS preflight',
    specs: [], what: 'Answers the preflight for every path, and sets ' +
                     'Access-Control-Allow-Private-Network so a page on an https origin can call ' +
                     'this service on loopback (Chrome Private Network Access).' },

  // --- Admin ---
  //
  // NON-SPEC, all of it: no specification describes an operator console, and none of
  // these paths is something a client should ever be pointed at. They are listed
  // because this page's first duty is to be a true list of what is callable, and
  // because two of them CHANGE WHAT THE PROTOCOL ENDPOINTS DO — which is the single
  // most surprising thing about this service and the last thing that should be
  // discoverable only by reading server.js.
  // --- SPIFFE ---
  //
  // The same blind spot the Kerberos, LDAP and TLS groups have, and it is wider
  // here than anywhere else: TWO of the three server-side SPIFFE surfaces
  // register no Express route at all. The Workload API and the SPIRE Server API
  // are gRPC on their own sockets — a Unix socket and a TCP port each, four in
  // all — so the walk that builds this page cannot see them, and everything
  // this document says about them is said in the text of the row below. GET
  // /spiffe reports whether each one actually bound, which is the only place
  // that can.
  { path: '/spiffe', group: 'SPIFFE', name: 'What the SPIFFE surfaces are',
    specs: ['spiffe-id', 'spiffe-bundle', 'spiffe-x509-svid', 'spiffe-jwt-svid',
            'spiffe-workload-api', 'spire-server-api'],
    what: 'THE ONE PAGE THAT DESCRIBES ALL THREE SERVER-SIDE SPIFFE SURFACES, and the ' +
          'only one that can report the two invisible ones. This service is the issuing ' +
          'authority for one trust domain (spiffe.trustDomain, `example.org` by ' +
          'default): the BUNDLE ENDPOINT below is plain HTTPS; the SPIFFE WORKLOAD API ' +
          '(the gRPC service SpiffeWorkloadAPI, five of seven methods) is on a UNIX ' +
          'SOCKET at spiffe.workloadSocket — `/tmp/spire-agent/public/api.sock`, which ' +
          'is SPIRE\'s own path and what SPIFFE_ENDPOINT_SOCKET means to every real ' +
          'client — and on TCP spiffe.workloadPort (8092); the SPIRE SERVER API (Entry, ' +
          'Agent, Bundle, SVID, TrustDomain and Debug, 36 of 42 methods) is on TCP ' +
          'spiffe.serverPort (8181, because SPIRE\'s own 8081 is this service\'s HTTP ' +
          'port) and optionally on a socket of its own. RAW SOCKETS, all four: this page ' +
          'is built by walking the Express router and cannot see one, so their state is ' +
          'reported by GET /spiffe and on /admin/spiffe rather than here. MOST OF THAT ' +
          'PAGE IS WHAT IS AND IS NOT CHECKED — no workload attestation and no node ' +
          'attestation (a Workload API caller is identified by its transport, endpoint ' +
          'and peer address and nothing else, because node cannot read a socket\'s peer ' +
          'credentials), no revocation anywhere — the directory does record a ' +
          '`spiffeCredentialStatus` on an identity whose last registration entry was ' +
          'deleted or whose agent was banned or deleted, and that is not one: nothing ' +
          'reads it back and no certificate is refused because of it — and, on the ' +
          'other side, the WHOLE ' +
          'per-method authorization table for the SPIRE Server API, whose TCP port is ' +
          'MUTUAL TLS with an X509-SVID (spiffe.authRequired) — because what comes out of ' +
          'these surfaces is a credential another service will believe. Add ' +
          '?format=json.' },
  { path: '/spiffe/bundle', group: 'SPIFFE', name: 'The trust bundle',
    specs: ['spiffe-bundle'],
    what: 'THE FEDERATION SURFACE, and the whole of it: one GET returning a JWK Set with ' +
          'two extra members — `spiffe_sequence`, which changes when the bundle changes ' +
          'and never otherwise, and `spiffe_refresh_hint`. Every key carries `use` of ' +
          '`x509-svid` (with the certificate in `x5c`, base64 DER) or `jwt-svid`; a ' +
          'consumer MUST IGNORE a key whose `use` it does not recognise, which is why a ' +
          'bundle missing that member verifies nothing and reports no error. The path is ' +
          'spiffe.bundlePath and is restart-only, because the require order is the route ' +
          'order. Served no-store: the authorities are regenerated on every start, so a ' +
          'cached copy outlives the keys it describes. NOTE THE SCHEME — this is http ' +
          'unless global.https is set, and a real federation partner will refuse a ' +
          'plain-http bundle endpoint, correctly: the bundle is the root of trust for a ' +
          'whole trust domain.' },
  { path: '/spiffe/federated/:trustDomain', group: 'SPIFFE',
    name: 'A federated trust domain\'s bundle, as held',
    specs: ['spiffe-bundle'],
    what: 'What this service actually holds for a foreign trust domain, exactly as it ' +
          'was given. Published so that "the bundle I pushed" and "the bundle you are ' +
          'serving to workloads" can be compared, which is most of debugging a ' +
          'federation. A FOREIGN BUNDLE IS ALWAYS GIVEN AND NEVER FETCHED: the ' +
          'relationship\'s bundle endpoint URL is recorded, RefreshBundle on the SPIRE ' +
          'Server API refuses to follow it, and the reason is the one this service gives ' +
          'for wreqptr and jwks_uri — fetching a URL somebody registered, to obtain a ' +
          'key that will verify credentials, is a server-side request forgery with a ' +
          'citation attached. Push one in with POST /admin-api/spiffe/federation-set or ' +
          'BatchSetFederatedBundle.' },
  { path: '/admin/sts-metadata', group: 'Admin', name: 'This page',
    specs: [],
    what: 'NON-SPEC. Every protocol this service speaks, every endpoint it ' +
          'registers with the methods each accepts, and every specification ' +
          'it implements with an honest coverage note. The endpoint list is ' +
          'read from the running Express router on each request, so it ' +
          'cannot claim a route that is not there or miss one that is. Add ' +
          '?format=json for the machine-readable form, which is also what ' +
          'the Download button on the page hands you. It moved here from ' +
          '/sts-metadata on 2026-08-24: it is a console page now, so it ' +
          'wears the console\'s chrome and is behind the console\'s gate.' },
  { path: '/admin', group: 'Admin', name: 'Admin console',
    specs: [],
    what: 'NON-SPEC. What the console is, what it can change about this service, and what it ' +
          'deliberately cannot (it does not revoke assertions, tickets or credentials, because ' +
          'nothing consults this service about those). It DOES end a sign-on session since ' +
          '2026-08-24, at /admin/logout, and this row used to say the opposite: the old ' +
          'argument was that wsignout1.0 has a cleanup to fan out and a third way to end a ' +
          'session would be a third way to get that wrong, which stopped being true when the ' +
          'fan-outs became functions owned by their own protocol modules. PROTECTED, and it is ' +
          'the only HTML surface here that is: with ' +
          'admin.authRequired on (the default) every page needs a sign-on session from ' +
          '/authn/login and one of two roles held as directory groups — see /admin/rbac. That ' +
          'is a turnstile and not a lock, exactly as SCIM\'s is: no password is checked ' +
          'anywhere in this service, so the username typed at that screen is the whole of the ' +
          'claim, and /admin-api is NOT gated at all. Turning the setting off restores the ' +
          'completely open console this used to be.' },
  { path: '/admin/logout', group: 'Admin', name: 'Sign-out',
    specs: [],
    what: 'NON-SPEC. The operator\'s view of /logout: the same live-session lists for a person ' +
          'NAMED rather than for whoever is holding the cookie, filtered by family and paged, ' +
          'with a global logout button and per-row controls. It also carries the two UNDOs ' +
          '/logout has not — restoring a revoked token and clearing a Kerberos sign-out ' +
          'instant, both labelled NON-SPEC because no real deployment could offer either. What ' +
          'it cannot do is deliver the front-channel notifications: those are iframes in the ' +
          'signed-out person\'s own browser. Add ?format=json.' },
  { path: '/admin/metrics', group: 'Admin', name: 'Metrics',
    specs: [],
    what: 'NON-SPEC. Every endpoint call by matched route and status class, every token by typ ' +
          'with how many are valid, expired, revoked and DPoP-bound, every assertion, ticket and ' +
          'credential the same way, and sessions counted BOTH ways: the browser sign-on sessions ' +
          'this service really holds, and the sessions implied by what it has issued. The two ' +
          'disagree on purpose and the page says why. Add ?format=json.' },
  { path: '/admin/users', group: 'Admin', name: 'Users',
    specs: [],
    what: 'NON-SPEC. Every userid presented to this service as part of an interaction that ' +
          'SUCCEEDED, across every protocol family here: either sign-in screen, the password grant, ' +
          'a WS-Security UsernameToken, a Kerberos AS-REQ or an accepted AP-REQ, a token exchange. ' +
          'A refused request records nothing. ?user=<name> drills into one: the names they were ' +
          'seen under, how they authenticated each time, every sign-on session they hold and the ' +
          'tokens issued ON each of those sessions, and the assertions, tickets and credentials ' +
          'issued to them. One row is one local name across all protocols — alice, ' +
          'urn:sts-mock:user:alice and alice@REALM are one identity — and subjects that never ' +
          'authenticated at all (an exchanged foreign token, OnBehalfOf, S4U) are listed and ' +
          'marked as such. Add ?format=json. IT HAS ONE CONTROL, and it writes somewhere else: ' +
          'POST creates a person in the embedded LDAP directory, refusing a username that is ' +
          'already there. The new entry does not appear in this page\'s own table until they ' +
          'authenticate — that list is who this service has SEEN, and the entry is what the ' +
          'directory HOLDS.' },
  { path: '/admin/applications', group: 'Admin', name: 'Applications',
    // rfc7591 because the client registrations this page shows ARE the entries under
    // ou=applications, and rfc4519 because applicationProcess — the one registered
    // object class that fits an application — is its. NOT rfc4512, for the reason the
    // groups row gives: this directory has no schema, and the vocabulary these entries
    // use is invented and published rather than registered.
    specs: ['rfc4511', 'rfc4519', 'rfc7591'],
    what: 'NON-SPEC page over the embedded LDAP directory, and the other side of ' +
          '/admin/users: that page lists every identity that has authenticated here, this ' +
          'one lists what they authenticated TO — every OAuth client, OpenID Connect relying ' +
          'party, SAML 2.0 or 1.1 service provider, WS-Federation application, WS-Trust ' +
          'relying party, OpenID4VP verifier and Kerberos service. One entry per unique ' +
          'identifier whatever protocol brought it, so an application appearing under one ' +
          'name in two protocols is one row with two kinds. Filtered by identifier or name ' +
          'and by kind, and paged with ?page= and ?per=; ?application=<id> drills into one ' +
          'and pages its attributes under ?attributesPage=. THE ENTRIES ARE THE REGISTRY ' +
          'rather than a display of one — the RFC 7591 registrations live in them, nothing ' +
          'caches them, and an ldapmodify of oauthRedirectUri changes which redirect URI RFC ' +
          '9700 mode accepts on the next request. IT WRITES AS WELL: create an application ' +
          'before it has ever connected, and add, remove or set the attributes that say what ' +
          'it is ALLOWED to do — but never the counters or the sightings, which are what ' +
          'HAPPENED and which only ldapmodify reaches, because a form that could rewrite them ' +
          'would make the page lie about this service\'s own behaviour. The forms call the ' +
          'same functions a protocol path and an LDAP modify call, so they are not a third ' +
          'store. Two attributes hold credentials in the clear, marked as such, for the reason ' +
          '/krb5/principals prints the Kerberos passwords. Add ?format=json.' },
  { path: '/admin/applications/new', group: 'Admin', name: 'New application',
    // The same three as the page above it, for the same three reasons: rfc4511
    // because what it writes is a directory entry, rfc4519 because
    // applicationProcess is that specification's, rfc7591 because the entry it
    // creates is the shape a dynamic client registration lands in.
    specs: ['rfc4511', 'rfc4519', 'rfc7591'],
    what: 'NON-SPEC console page. THE CREATE FORM for /admin/applications, on a page of its ' +
          'own: name a client_id, wtrealm, AppliesTo, entityID or service principal name that ' +
          'has never connected, optionally a kind, and TICK THE PROTOCOL FAMILIES the ' +
          'application is DECLARED for from a closed list of fourteen. The entry lands in the ' +
          'ou=applications container OF THE TRUST REALM THIS PAGE WAS REACHED IN — the ' +
          'directory is per realm — and it is an ordinary directory entry, so an ldapsearch ' +
          'under that realm\'s base DN sees exactly what this created. IT IS NOT A SECOND ' +
          'DOOR: the form posts action=create to /admin/applications, which is the same ' +
          'action the list page\'s own inline row posts and the same function a protocol ' +
          'endpoint reaches, so there is one store behind all three. THE DECLARATION GRANTS ' +
          'AND REFUSES NOTHING — nothing in this service reads appAllowedProtocol, and an ' +
          'application declared for SAML 2.0 alone is still issued an access token, because a ' +
          'mock that refused a protocol would remove a test case rather than add one; it is ' +
          'kept apart from appProtocol, which is what HAPPENED, so the two can be read against ' +
          'each other on the drill-down. What DOES take effect is the configuration underneath ' +
          '— the redirect URIs, the grant types and the secret, which RFC 9700 mode reads and ' +
          'which are set from the Applications page. Add ?format=json for the two vocabularies ' +
          'and the container DN.' },
  { path: '/admin/spiffe', group: 'Admin', name: 'SPIFFE',
    specs: ['spiffe-id', 'spiffe-bundle', 'spiffe-x509-svid', 'spiffe-jwt-svid'],
    what: 'THE TRUST DOMAIN this service is the issuing authority for: its X.509 and ' +
          'JWT authorities (the active one and the retired ones still published in the ' +
          'bundle), where the bundle is and what its sequence is, every federated trust ' +
          'domain, and WHETHER EACH OF THE FOUR gRPC LISTENERS ACTUALLY BOUND — which ' +
          'nothing else can report, because this page cannot see a socket any more than ' +
          'this metadata document can. Its two forms rotate an authority and set or ' +
          'remove a federated bundle; a foreign bundle is PUSHED IN and never fetched, ' +
          'which is the refusal this service also gives wreqptr and jwks_uri. It says on ' +
          'every screen that nothing here is ATTESTED, and reports separately whether the ' +
          'SPIRE Server API is AUTHENTICATING its callers — the two are different claims ' +
          'and the second is a setting. The reply carries the per-method authorization ' +
          'table. Add ?format=json.' },
  { path: '/admin/spiffe/entries', group: 'Admin', name: 'SPIFFE registration entries',
    specs: ['spiffe-id', 'spire-server-api'],
    what: 'Every registration entry, filtered and paged, with a drill-down per entry ' +
          '(?entry=) that shows its whole directory entry and the forms that change and ' +
          'delete it. WHAT MAY BE CHANGED IS DECLARED AND NOT DERIVED: what the entry ' +
          'may DO is editable; the revision number and the SVID counter are what ' +
          'HAPPENED and are refused, because a form that could rewrite them would make ' +
          'the page lie about this service\'s own behaviour. ldapmodify still reaches ' +
          'everything. THE SELECTORS RESTRICT NOTHING — they are recorded, reported and ' +
          'used by GetAuthorizedEntries, and the Workload API hands every caller every ' +
          'identity. Add ?format=json.' },
  { path: '/admin/spiffe/agents', group: 'Admin', name: 'SPIFFE agents',
    specs: ['spiffe-id', 'spire-server-api'],
    what: 'Every agent that has called AttestAgent, filtered and paged, with a ' +
          'drill-down per agent (?agent=). These entries are a RECORD rather than ' +
          'configuration, so the only writes are ban, unban and delete. NODE ' +
          'ATTESTATION IS NEVER VERIFIED: whatever attestor an agent names and whatever ' +
          'payload it sends are written down as claimed, which is why every agent ' +
          'carries a selector valued `unverified:true`. The BAN is enforced — one of ' +
          'the few refusals in this service, and what keeps the button from being a lie ' +
          '— while DELETE is forgetting rather than revoking: the agent reappears the ' +
          'moment it attests again. Add ?format=json.' },
  { path: '/admin/authorization-servers', group: 'Admin', name: 'Authorization servers',
    specs: ['rfc8414', 'oidc-discovery', 'rfc9700'],
    what: 'NON-SPEC page over the two discovery documents. ONE PROCESS, SEVERAL AUTHORIZATION ' +
          'SERVERS: the path component both shapes already carry — RFC 8414 section 3.1 ' +
          'INSERTS it, OpenID Connect Discovery section 4 APPENDS the well-known segment to it ' +
          '— now selects a CONFIGURATION as well as an issuer identifier, so each can publish ' +
          'its own endpoints, capabilities and issuer. Any member is settable, including one ' +
          'this service has never heard of: publishing something a client did not expect is ' +
          'half the point, which is why this has a CATALOGUE rather than a schema. A path ' +
          'nobody configured publishes the document this service always published, so nothing ' +
          'that worked before behaves differently. It changes what the document SAYS and not ' +
          'what the endpoints DO — advertise plain PKCE and the token endpoint still verifies ' +
          'S256 — so every view computes the DRIFT and names the members that do not describe ' +
          'this service. Add ?format=json; ?profile=<id> drills into one.' },
  { path: '/admin/groups', group: 'Admin', name: 'Directory groups',
    // rfc4519 is linked because member, uniqueMember and the groupOfNames class are its,
    // and rfc4511 because what this page reports is the state that protocol's operations
    // leave behind. NOT rfc4512: this directory has no schema and the page says so.
    specs: ['rfc4511', 'rfc4514', 'rfc4519'],
    what: 'NON-SPEC page over the embedded LDAP directory. Lists every group with how many of its ' +
          'membership values name an entry that is actually there; ?group=<dn> drills into one ' +
          'and shows every attribute it holds, operational ones included, and every member ' +
          'resolved — each linked to their row on /admin/users where this console knows them by ' +
          'name. A group is an entry under ou=groups OR one carrying a group objectClass wherever ' +
          'it sits, because the directory is SCHEMALESS and either alone would miss what a client ' +
          'can write; the page says which rule caught each. Three states are reported rather than ' +
          'smoothed over, and they are the point of the page: a DANGLING member (this directory ' +
          'does not enforce referential integrity, so deleting a user leaves its DN in every ' +
          'group), a member that is itself a GROUP (nesting is shown and never expanded — nothing ' +
          'here walks it), and an entry whose own memberOf claims a group that does not list it ' +
          'back (nothing here maintains memberOf). A GROUP HERE GRANTS NOTHING, WITH TWO NAMED ' +
          'EXCEPTIONS: no token, assertion, ticket or PAC this service issues carries a group ' +
          'from this directory as an authorization and no endpoint reads one — except that ' +
          'admin.readGroup and admin.writeGroup (cn=admin-read, cn=admin-write) decide who may ' +
          'use /admin, and they are ordinary entries listed here like any other. Even those two ' +
          'grant nothing outside that console. See /admin/rbac. Add ?format=json.' },
  { path: '/admin/rbac', group: 'Admin', name: 'Admin roles',
    // rfc4511/rfc4514/rfc4519 because the two roles ARE two ordinary groups in the
    // embedded directory — the same member/groupOfNames machinery /admin/groups
    // reports — and NOT because any of those specifications says anything about
    // authorizing a web console. Nothing does: this is a role model of this
    // service's own.
    specs: ['rfc4511', 'rfc4514', 'rfc4519'],
    effect: 'decides who may read and who may change this console',
    what: 'NON-SPEC. WHO MAY USE /admin. Two roles — Admin Read and Admin Write, and WRITE ' +
          'IMPLIES READ — held as two ORDINARY GROUPS in the embedded LDAP directory ' +
          '(admin.readGroup, admin.writeGroup; cn=admin-read and cn=admin-write by default), ' +
          'so this page, POST /admin-api/rbac/grant, an ldapmodify on 389 or 636 and a SCIM ' +
          'PATCH are FOUR DOORS onto one membership rather than four stores. Grants and ' +
          'revokes here, filtered and paged. THESE TWO GROUPS ARE THE ONLY GROUPS IN THIS ' +
          'SERVICE THAT GRANT ANYTHING, and what they grant is this console and nothing else — ' +
          'no token, assertion, ticket, PAC or credential is changed by holding one, and no ' +
          'protocol endpoint reads them. While NEITHER group has a member, anybody who signs ' +
          'in holds both roles and every page says so: this service has no password anywhere ' +
          'to bootstrap an administrator with, so an empty roster OPENS (admin.openWhenEmpty, ' +
          'which can be turned off — and /admin-api, which is NOT gated, is then the only way ' +
          'back in). None of it is in force while admin.authRequired is off. Add ?format=json.' },
  { path: '/admin/scim', group: 'Admin', name: 'SCIM',
    // rfc7643 and rfc7644 because the page reports that surface; rfc4511 and rfc4519
    // because what it reports having done is entries in the embedded directory, and the
    // mapping table names their attribute types.
    specs: ['rfc7643', 'rfc7644', 'rfc4511', 'rfc4519'],
    what: 'NON-SPEC page over the SCIM 2.0 endpoints. Which operation was performed how ' +
          'many times, on which resource type, and what was refused with which scimType — ' +
          'every operation and resource type listed INCLUDING the ones at zero, because ' +
          '"does this server do PATCH" is otherwise answered by omission. Then the surface ' +
          'itself, read from the module that implements it rather than described a second ' +
          'time here: the endpoints, the four things SCIM here deliberately does not do, ' +
          'the five things you can do to make it fail, and which LDAP attribute each SCIM ' +
          'member is. IT HAS NO CONTROLS, which is the console parity rule holding rather ' +
          'than a gap: everything about SCIM that can be changed is a configuration row. ' +
          'The bulk count deliberately does not tally with the rest — one Bulk of five ' +
          'creates is one bulk AND five creates. Add ?format=json.' },
  { path: '/admin/tokens', group: 'Admin', name: 'Issued tokens, assertions and tickets',
    // rfc7009 is linked because this IS that revocation: one set of revoked jtis serves
    // both this page and /oauth2/revoke. rfc7662 and oidc-core because they are what then
    // reports the token dead. saml2 and saml11 because the page now lists those assertions
    // too, and rfc4120 because it lists the KDC's tickets.
    specs: ['rfc7009', 'rfc7662', 'oidc', 'saml2', 'saml11', 'rfc4120'],
    effect: 'lists every JWT, SAML assertion and Kerberos ticket issued; POST revokes one token, a ' +
            'whole kind, or everything for a subject',
    what: 'NON-SPEC page over an RFC 7009 operation. GET lists what was issued in ONE table, newest ' +
          'first: every JWT, every SAML 2.0 and SAML 1.1 assertion (WS-Trust\'s and WS-Federation\'s ' +
          'alike) and every Kerberos TGT and service ticket. Claims and facts only — never the ' +
          'signed token, the assertion XML or the ticket, which would make the page a credential ' +
          'dump. Filtered by family, kind and state and paged with ?page= and ?per=; both work with ' +
          '?format=json, whose reply carries page, pages, matched and the rows in `issued`, each ' +
          'naming its family. POST revokes by jti or by pasted token, by kind, by subject, or ' +
          'everything. It is the SAME revocation set /oauth2/revoke writes to, so introspection, ' +
          'UserInfo and the refresh grant all honour it immediately. ONLY THE JWTs CAN BE REVOKED: ' +
          'nothing consults this service about an assertion or a ticket, so those rows are listed ' +
          'with the reason there is no button rather than with a button that would change a number ' +
          'here and nothing out there. Restore is offered and is NON-SPEC: no authorization server ' +
          'can undo a revocation, and it is here so that getting back to a working token does not ' +
          'mean restarting the service. OID4VCI credentials are counted on /admin/metrics and are ' +
          'not in this table.' },
  { path: '/admin/tokens/credential', group: 'Admin',
    name: 'One credential, and every generation behind it',
    // rfc8693 is what a generation IS — every row above the last one is an
    // exchange — and rfc6749 and oidc are what the last one is labelled with,
    // because the bottom of every line is an ordinary grant rather than an
    // act. rfc4120 and ws-trust are cited for the WALLS rather than for
    // anything drawn: they are the two families that consume or produce a
    // credential this register cannot name, and the page says which it hit.
    specs: ['rfc8693', 'rfc6749', 'oidc', 'rfc4120', 'ws-trust'],
    what: 'NON-SPEC PAGE OVER FIVE SPECIFICATIONS, and the FIRST drill-down ' +
          '/admin/tokens has had: every identifier in that table links here. ' +
          'It answers where ONE credential came from, keyed on the ' +
          'identifier the protocol itself gave it (a jti, an AssertionID), ' +
          'which is the only thing the issued register and the delegation ' +
          'register both hold about the same object — and is why a Kerberos ' +
          'ticket has no link from that table: that protocol has no ' +
          'identifier to quote. THE ANSWER IS USUALLY "NOTHING WAS ' +
          'EXCHANGED", which is not an empty page: most credentials were ' +
          'issued directly, and the page leads with that and names the grant ' +
          'or flow that produced them. The other case is the one worth ' +
          'opening — an RFC 8693 exchange whose subject token came out of ' +
          'another, back to a browser sign-in three tiers away — and it is ' +
          'ONE generations table, newest first, with the origin as the last ' +
          'row, plus the acts, the parties and every line in words. THE ' +
          'PICTURE IS THE DELEGATION MAP ASKED A DIFFERENT QUESTION: ' +
          'common/credential_graph.js returns a graph in ' +
          'delegation.graph()\'s shape, so the same code draws it and a ' +
          'party here is the same party, drawn the same way, as on the four ' +
          'pages that had it first. A CREDENTIAL THIS SERVICE NO LONGER ' +
          'HOLDS IS NOT A 404: both registers are capped and drop the oldest ' +
          'SEPARATELY, so a lineage can know an identifier existed and ' +
          'nothing else about it, and the page says which of the two states ' +
          'it is in. A line longer than the walk limit is truncated and says ' +
          'so, because a lineage that stops quietly reads as an issuance ' +
          'that never happened. No credential is ever shown, only its kind ' +
          'and identifier. Naming nothing gets the chooser rather than a ' +
          '404, and there is no form, so nothing on /admin-api answers for ' +
          'it. ?format=json is the lineage and the graph; ?format=svg is the ' +
          'drawing alone.' },
  { path: '/admin/delegation', group: 'Admin', name: 'Delegation',
    // Four specifications because this page is the one place all four are read
    // against each other: [MS-SFU] for the three Kerberos S4U mechanisms,
    // rfc4120 for the forwarded ticket-granting ticket, ws-trust for
    // OnBehalfOf and ActAs, and rfc8693 for token exchange in both its shapes.
    // Nothing else here cites all four, which is the point of the page.
    specs: ['ms-sfu', 'rfc4120', 'ws-trust', 'rfc8693'],
    what: 'NON-SPEC PAGE OVER FOUR SPECIFICATIONS. Who acted on whose behalf, ' +
          'through what, to reach what — every delegation this service has ' +
          'performed or REFUSED, in ONE model across three protocol families. ' +
          'Eight mechanisms: Kerberos S4U2Self, S4U2Proxy classic and ' +
          'resource-based, and a forwarded TGT; WS-Trust OnBehalfOf and ' +
          'ActAs; RFC 8693 token exchange as impersonation and as delegation. ' +
          'Each act names the three LAYERS — the initial identity, the ' +
          'intermediary acting on their behalf, and the target being reached ' +
          '— and a layer can be a person, an application (ou=applications), ' +
          'or both, which the Kerberos front end always is. THE AXIS THAT ' +
          'MATTERS IS IMPERSONATION VERSUS DELEGATION: a delegation carries ' +
          'the chain in the credential (an `act` claim, a composite ActAs, ' +
          'S4U_DELEGATION_INFO in the PAC) and an impersonation carries ' +
          'nothing, so for those acts THIS PAGE IS THE ONLY PLACE THE FACT ' +
          'EXISTS — no reading of the token at the resource server can ' +
          'recover it. REFUSALS ARE RECORDED and are most of the value: they ' +
          'carry the KDC\'s own e-text naming both accounts, both attributes ' +
          'and which was missing, and they appear in NO other list here, ' +
          'because nothing was accepted so no authentication was recorded. A ' +
          'SECOND TABLE is CONFIGURATION rather than history — who MAY ' +
          'delegate to whom, out of msDS-AllowedToDelegateTo on the front end ' +
          'and msDS-AllowedToActOnBehalfOfOtherIdentity on the back end, with ' +
          'the flags that stop delegation (NOT_DELEGATED) or enable protocol ' +
          'transition (TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) beside them. ' +
          'It is KERBEROS ONLY because Kerberos is the only family here that ' +
          'polices delegation at all: WS-Trust puts no authorization on ' +
          'either element and this service adds none, and RFC 8693 leaves the ' +
          'policy to the authorization server, which this one has not got — ' +
          'so any client may exchange any token for a token about anybody. ' +
          'Every act says which of the two it was. NO CREDENTIAL IS EVER ON A ' +
          'ROW, only its kind and identifier; a Kerberos ticket genuinely has ' +
          'none. In memory, capped by delegation.maxRecords, gone on restart, ' +
          'with no clear control and no way to add a row by hand. Filtered by ' +
          'mechanism, kind, outcome, protocol and free text; paged; ' +
          '?format=json carries the acts, the distinct CHAINS among them (one ' +
          'per edge of the picture) and the policy.' },
  { path: '/admin/delegation/map', group: 'Admin', name: 'Delegation — the picture',
    // The same four specifications as the page above it, and for the same
    // reason: this is that page's acts drawn rather than a different subject.
    // A shorter list here would say that the diagram covers less than the table
    // it is drawn from, which is exactly backwards — the picture is what makes
    // the four readable against each other.
    specs: ['ms-sfu', 'rfc4120', 'ws-trust', 'rfc8693'],
    what: 'NON-SPEC PAGE OVER FOUR SPECIFICATIONS, and a DRILL-DOWN of ' +
          '/admin/delegation rather than a section of its own. The same acts as ' +
          'a DIAGRAM, generated on the server as SVG: a STICK FIGURE for every ' +
          'party with an entry under ou=users, a RECTANGLE for every one with an ' +
          'entry under ou=applications, a rectangle WITH A FIGURE IN IT for the ' +
          'middle tier that is routinely both, and a HEXAGON for this service ' +
          'carrying the TRUST REALM the picture is of. Two kinds of line and ' +
          'they are different claims: `acts for` is the DELEGATION relationship, ' +
          'coloured by mode (amber for an impersonation, green for a delegation, ' +
          'the pairing the table uses), and `reaches` is the TRUST relationship ' +
          '— what the credential was FOR, which is `what is this token\'s ' +
          'audience` asked as a picture. A dashed grey line from the hexagon is ' +
          'this service having ISSUED to whoever asked. A BROKEN line jumps a ' +
          'party nobody named, which is what a forwarded ticket-granting ticket ' +
          'is: no intermediary, and none possible. RED is a chain nothing was ' +
          'ever issued on, and a party the directory has never heard of is ' +
          'drawn DASHED in the shape its role implies rather than as a ' +
          'registered one. A party that reached ITSELF (S4U2Self) is marked on ' +
          'the box rather than drawn as a loop. Beneath the picture, the same ' +
          'thing in words: every party with both of its links, every ' +
          'relationship as a row, and EVERY CREDENTIAL THAT CAME OUT — kind and ' +
          'identifier only, never the credential, and a Kerberos ticket has no ' +
          'identifier to quote. It takes the delegation page\'s five filters ' +
          'and is drawn from EVERYTHING THAT MATCHED rather than from one page ' +
          'of it, because paging a diagram draws the pagination. NO SCRIPT — ' +
          'the layout is computed on the server with @dagrejs/dagre and the ' +
          'shapes are this repository\'s own, so script-src \'none\' is ' +
          'untouched and the picture does not pan or zoom. ?format=json is the ' +
          'whole graph (also in the `graph` member of GET /admin-api/delegation) ' +
          'and ?format=svg is the document alone, with no links in it.' },
  { path: '/admin/delegation/chain', group: 'Admin',
    name: 'Delegation — one relationship',
    // The same four specifications as the two pages above, and for the reason
    // the map's entry gives: this is those acts drawn, narrowed to one chain,
    // rather than a different subject. A shorter list would claim the
    // drill-down covers less than the table it came from.
    specs: ['ms-sfu', 'rfc4120', 'ws-trust', 'rfc8693'],
    what: 'NON-SPEC PAGE OVER FOUR SPECIFICATIONS, and a DRILL-DOWN of ' +
          '/admin/delegation. ONE delegation relationship — one chain, which is ' +
          'one (mechanism, initial identity, intermediary, target) — drawn on ' +
          'its own with everything else in the service left out, which is the ' +
          'answer to `what is this row, exactly` on a service whose whole ' +
          'picture is forty boxes. Reached from a link on EVERY ROW of both ' +
          'tables on /admin/delegation. ?chain= carries the chain key rather ' +
          'than an index, because an index into a capped list moves when the ' +
          'cap bites and a stale link would then describe a DIFFERENT ' +
          'relationship instead of nothing. A chain whose acts have all been ' +
          'dropped is NOT a 404: it says which of the two happened and offers ' +
          'the way back. Beneath the picture: the parties, the up-to-two lines ' +
          'a chain has, every credential issued on it (kind and identifier ' +
          'only, never the credential), and every act with its time — the ' +
          'picture has the times taken out, because four acts a second apart ' +
          'between the same parties are one line. Same renderer, same shapes ' +
          'and same server-side layout as the map: NO SCRIPT. ?format=json is ' +
          'the chain, its acts and the graph; ?format=svg is the document ' +
          'alone, with no links in it.' },
  { path: '/admin/delegation/application', group: 'Admin',
    name: 'Delegation — one application',
    specs: ['ms-sfu', 'rfc4120', 'ws-trust', 'rfc8693'],
    what: 'NON-SPEC PAGE OVER FOUR SPECIFICATIONS, and a DRILL-DOWN of ' +
          '/admin/delegation that asks the other question: not `what talks to ' +
          'what` but WHAT HAS BEEN ISSUED BECAUSE OF THIS APPLICATION. Choose ' +
          'one from the list every act has named — the chooser is on ' +
          '/admin/delegation as well as here — and get every act it took part ' +
          'in REGARDLESS OF THE ROLE IT PLAYED, the picture of every ' +
          'relationship it is in, and every delegated credential that came out, ' +
          'each with the role this application had in the act that produced it. ' +
          'That is the point of the page: a middle tier is the INTERMEDIARY of ' +
          'the chains it acts on and the TARGET of the ones that reach it, and ' +
          'offering only the second — the easy half — would hide what was ' +
          'issued THROUGH it, which is the interesting half of a delegation. ' +
          'The list is built from the ACTS and not from ou=applications, so an ' +
          'entry can be marked `not in the registry`: an RFC 8693 audience ' +
          'nobody has otherwise mentioned is a real target this console would ' +
          'otherwise have no name for. An application is keyed on its ' +
          'IDENTIFIER, normalised, so two spellings are one application — and ' +
          'not on a box in the picture, because an RFC 8693 intermediary\'s box ' +
          'is the ACTOR while the application it acted through is the ' +
          'client_id beside it. A bare page is the chooser rather than a 404. ' +
          'No credential is ever shown, only its kind and identifier. ' +
          '?format=json carries the application, its acts, the graph and the ' +
          'role played per act; ?format=svg is the picture alone.' },
  { path: '/admin/delegation/user', group: 'Admin',
    name: 'Delegation — one person',
    // The four the picture's DELEGATION half is drawn from, plus the two that
    // define what its ISSUANCE half labels every line with. rfc6749 and
    // openid-connect are here and on no other delegation row, which is the
    // whole difference between this page and the three beside it: it is the one
    // that leaves the delegation register.
    specs: ['ms-sfu', 'rfc4120', 'ws-trust', 'rfc8693', 'rfc6749', 'oidc'],
    what: 'NON-SPEC PAGE OVER SIX SPECIFICATIONS, the FOURTH drill-down of ' +
          '/admin/delegation and THE ONLY PICTURE IN THIS CONSOLE DRAWN FROM ' +
          'MORE THAN THE DELEGATION REGISTER. It answers what has this service ' +
          'done in one identity\'s name, END TO END — which the other three ' +
          'cannot, because most of what happens in somebody\'s name is not a ' +
          'delegation: an authorization code grant is not an act, nor is an ' +
          'AS-REQ, nor a SAML assertion, so a person who signed in nine times ' +
          'and holds twenty tokens is an empty picture drawn from acts alone. ' +
          'Choose somebody from the list — the chooser is on /admin/delegation ' +
          'and /admin/delegation/map as well — and get every credential ever ' +
          'issued naming them (JWT, assertion, ticket, SVID, verifiable ' +
          'credential) as a line to the application holding it, LABELLED WITH ' +
          'THE EXACT OAUTH 2.0 GRANT OR OPENID CONNECT FLOW that produced it ' +
          'and the section that defines it; their authentications as dotted ' +
          'lines into this service, per protocol family, with the method on ' +
          'each; and every delegation act naming them in any of the three ' +
          'roles, drawn by the same code /admin/delegation/map uses. Neither ' +
          'new line takes a mode colour, because impersonation and delegation ' +
          'are properties of a delegation mechanism and a grant claims ' +
          'neither. An RFC 8693 exchange writes a row in BOTH registers and is ' +
          'drawn ONCE, on its delegation line, with the number left off ' +
          'printed; a Kerberos S4U ticket is the overlap that survives, since a ' +
          'ticket has no identifier either register could collapse on. The ' +
          'chooser\'s list is the identity register UNIONED with the delegation ' +
          'register, so it offers people nothing was ever issued to — an ' +
          'S4U2Self subject who has never been here is the row worth opening. ' +
          'A bare page is the chooser rather than a 404. No credential is ever ' +
          'shown, only its kind and identifier. ?format=json carries the ' +
          'person, the credentials with the grant on each, the acts and the ' +
          'graph; ?format=svg is the picture alone.' },
  { path: '/admin/audit', group: 'Admin', name: 'Audit log',
    // rfc4511 is linked because the directory operations are its and they are the
    // largest source of rows here. Nothing else: an audit log is not a protocol,
    // and citing one would be claiming an interoperability this page does not have.
    specs: ['rfc4511'],
    what: 'NON-SPEC. What this service has been asked to do, in the order it was asked, as ROWS ' +
          'rather than as counters — which is the difference from /admin/metrics: that page can ' +
          'say the directory holds eleven entries, and only this one can say a twelfth was created ' +
          'at 14:02 and deleted at 14:03 by somebody bound as uid=carol, over LDAPS. Six ' +
          'categories: a credential ACCEPTED in any of the sixteen families here; a sign-on ' +
          'session created or ended; every LDAP operation over 389 and 636 alike (an entry ' +
          'created, deleted, updated, renamed, searched, compared, bound to), with a user, a group ' +
          'and an entry told apart by PLACEMENT because this directory is schemaless; every ' +
          '/admin page viewed and form posted; every /admin-api call; and every other endpoint ' +
          'call. NO CREDENTIAL IS EVER RECORDED — no password, bearer token, assertion, request or ' +
          'response body; a modify names the attributes it changed and never their values, a ' +
          'compare says whether it matched and not what was tried, and an authorization code in a ' +
          'query string is redacted. ONE ACT USUALLY PRODUCES SEVERAL ROWS and they are not ' +
          'duplicates: a sign-in writes the HTTP call, the credential being accepted and the ' +
          'session that came out of it, which are three facts at three layers. It also OBSERVES ' +
          'ITSELF — fetching this page records an admin.view event — which is stated rather than ' +
          'suppressed, because the alternative is a blind spot exactly where the reader stands. ' +
          'Filtered by category, action, outcome, actor and free text, and paged with ?page= and ' +
          '?per=; both work with ?format=json, whose reply carries page, pages, matched and the ' +
          'rows in `events`. Walk it by `seq` rather than by page: that number is monotonic and ' +
          'never reused, so a gap between the last one seen and oldestSeq is exactly how many ' +
          'events the cap discarded. In memory and dies with the process, and there is NO CLEAR ' +
          'BUTTON — an erase control on an unprotected console would make the page unable to ' +
          'answer the one question an audit log exists for. audit.maxEvents and ' +
          'audit.protocolCalls on /admin/config change the cap and whether the noisiest category ' +
          'is recorded at all.' },
  { path: '/admin/claims', group: 'Admin', name: 'Custom claims',
    specs: ['rfc7519', 'oidc'],
    effect: 'changes what every FUTURE access token and ID Token contains',
    what: 'NON-SPEC. Two claim sets — OAuth 2.0 access token, OIDC ID Token — added to every ' +
          'token of that kind issued from then on. ADDITIVE only: a claim this service sets ' +
          'itself is refused rather than overridden, because every one of those is load-bearing ' +
          '(a settable exp would produce tokens that fail to verify with nothing pointing back at ' +
          'the page). Values may carry ${username}-style placeholders. Add ?format=json; POST the ' +
          'same JSON to set a set. The two SAML sets moved to /admin/saml-attributes on ' +
          '2026-08-24; the store behind both pages is one store.' },
  { path: '/admin/saml2', group: 'Admin', name: 'SAML 2.0 identity provider',
    specs: ['saml2', 'saml2-metadata', 'saml2-profiles'],
    effect: 'writes to the LDAP directory, and answers the one question nothing else here can',
    what: 'NON-SPEC. WHICH METADATA DOCUMENT DO I CONFIGURE THIS SERVICE ' +
          'PROVIDER FROM — which is not one URL, because the metadata is per ' +
          'application, and the slug in its path is a digest nobody derives by ' +
          'hand. It holds nothing: every row is an entry in ou=applications, ' +
          'and both its writes go through the same updateApplication() ' +
          '/admin/applications posts to. The saml2.* settings are READINGS ' +
          'here with a link to /admin/config, not a second form onto them.' },
  { path: '/admin/federation', group: 'Admin', name: 'Federation relationships',
    specs: ['saml2-profiles', 'saml11-profiles', 'ws-federation', 'oidc', 'rfc6749'],
    effect: 'writes to the LDAP directory, and CONFIGURES A REFUSAL — the only ' +
            'page in this console that does',
    what: 'NON-SPEC. WHICH FOREIGN IDENTITY SERVICES THIS ONE WILL BELIEVE, ' +
          'and what it releases to the ones it asserts to. Every other page in ' +
          'this console reports what happened or widens what this service will ' +
          'accept; this one is the opposite in both directions, because an ' +
          'assertion consumer service cannot be permissive without being an ' +
          'authentication bypass for every protocol in this process. A ' +
          'relationship is created DISABLED, and one that is enabled and ' +
          'half-configured refuses rather than half-working. It holds nothing: ' +
          'every row is an entry under ou=federations, and every form is one ' +
          'ldapmodify of it. The one field it will not show is ' +
          'fedClientSecret — this service\'s own credential AT the partner, ' +
          'which an ldapsearch still prints, deliberately and loudly.' },
  { path: '/admin/saml11', group: 'Admin', name: 'SAML 1.1 identity provider',
    specs: ['saml11', 'saml11-profiles', 'saml2-metadata'],
    effect: 'writes to the LDAP directory, and answers a question the SAML 2.0 page never has to',
    what: 'NON-SPEC. The same "which metadata document do I configure this ' +
          'from" the SAML 2.0 page answers, plus one that is peculiar to this ' +
          'protocol: WHAT IS THIS RELYING PARTY CALLED. SAML 1.1 has no ' +
          'request message, so nothing makes a relying party identify itself, ' +
          'and an identifier here may be one this service GUESSED from the ' +
          'origin of a TARGET — which the page says out loud, because a ' +
          'guessed audience fails inside a signature check with nothing ' +
          'explaining why. It holds nothing: every row is an entry in ' +
          'ou=applications. It has ONE action where /admin/saml2 has four, and ' +
          'the three it lacks are three things SAML 1.1 has no protocol for.' },
  { path: '/admin/saml-attributes', group: 'Admin', name: 'Custom SAML attributes',
    specs: ['saml2', 'saml11'],
    effect: 'changes what every FUTURE SAML assertion contains',
    what: 'NON-SPEC. The other two sets of the same store — SAML 2.0 Attribute (Name, optional ' +
          'NameFormat) and SAML 1.1 Attribute (AttributeName, AttributeNamespace, defaulted to ' +
          'the WS-Federation claim namespace) — added to every assertion of that kind issued from ' +
          'then on. The 2.0 set reaches what WS-Trust issues with a 2.0 token type and the 1.1 ' +
          'set what WS-Federation\'s passive requestor profile carries. ADDITIVE only, and the ' +
          'reserved JWT claim names do NOT apply here: they are load-bearing in a token and ' +
          'collide with nothing in an assertion. Each set also carries a selection of LDAP ' +
          'attribute types whose values are read off the person\'s own directory entry. Add ' +
          '?format=json; POST the same JSON to set a set.' },
  { path: '/admin/vc', group: 'Admin', name: 'Credential claims',
    specs: ['oid4vci', 'sd-jwt-vc', 'vcdm', 'rfc4519'],
    effect: 'changes what every FUTURE Verifiable Credential contains, AND writes to the LDAP ' +
            'directory',
    what: 'NON-SPEC. Which claims an issued credential carries, chosen from a catalogue of LDAP ' +
          'attribute types rather than of claim names — the value of a claim is the value on that ' +
          'person\'s entry under ou=users, so an LDAP client and a wallet see one person. Ten are ' +
          'selected on a fresh start, which is exactly the six claims this issuer carried before ' +
          'the page existed. It applies to all five credential configurations, and the issuer ' +
          'metadata is built from the same list, so what is advertised cannot drift from what is ' +
          'minted. THE ldp_vc FORMAT CARRIES A SUBSET: it is signed over canonicalized JSON-LD, so ' +
          'only terms the vendored context defines can appear, and the page names the ones left ' +
          'out. Saving a selection SWEEPS the directory: every person under ou=users gains the ' +
          'selected attributes they are missing, invented from their username — deterministically, ' +
          'so one username is one invented person across restarts — and an attribute already there ' +
          'is never overwritten. Add ?format=json; POST {"action":"select","attributes":[...]} for ' +
          'the same thing without a browser.' },

  { path: '/admin/realms', group: 'Admin', name: 'Trust realms',
    specs: [],
    effect: 'defines and removes whole logical copies of this service, each ' +
            'with its own signing key — and removing one destroys everything ' +
            'it held',
    what: 'NON-SPEC. Several logical copies of this service in one process, ' +
          'each reached under a path prefix and each with its own ' +
          'configuration, signing key, sessions, authorization codes, ' +
          'tokens, offers, service providers, statistics and audit log. The ' +
          'DEFAULT realm has no prefix and cannot be removed or renamed: ' +
          'every URL this service published before realms existed is a URL ' +
          'in it, which is what makes a service with no realms defined ' +
          'behave exactly as it did. Two things here are answered nowhere ' +
          'else — what a realm\'s endpoints actually are (the prefix segment ' +
          'is a setting and the ids are whatever somebody typed) and WHICH ' +
          'FAMILIES ARE SEPARATED BY IT. The embedded directory is SHARED — ' +
          'one set of people, groups and applications for every realm, since ' +
          'LDAP answers on a socket with no path in it — so OAuth client ' +
          'registrations, SAML service provider entries and the two admin ' +
          'roles are shared, as are Kerberos, the two TLS listeners and ' +
          'SPIFFE\'s four sockets. What a realm separates is what this ' +
          'service ISSUES about them, and everything it holds while doing it. ' +
          'It keeps no store of its own: the registry is common/realms.js\'s ' +
          'and a realm\'s settings go through the same config.setOverride() ' +
          '/admin/config calls. Add ?format=json; POST {"action":"create", ' +
          '"id":"acme"} for the same thing without a browser.' },

  { path: '/admin/realm-switch', group: 'Admin', name: 'Realm chooser target',
    specs: [],
    what: 'NON-SPEC. Where the realm chooser in the console header submits, ' +
          'and the whole of what it does is turn a realm id and a path into ' +
          'one redirect. It exists because a `<select>` cannot navigate ' +
          'without script and this console runs none (`script-src ' +
          '\'none\'`), so the chooser is a GET form rather than an onchange ' +
          'handler. Two things about it are worth knowing. Its `to` ' +
          'parameter arrives in a query string and leaves in a Location ' +
          'header, which is the shape of every open redirect there has ever ' +
          'been — so it is accepted only as a single-slash-rooted path of at ' +
          'most 2000 characters, and anything else is REFUSED rather than ' +
          'corrected, with /admin as the answer to that and to an unknown ' +
          'realm alike. And the redirect is ABSOLUTE, which is the opposite ' +
          'of what the rest of this console does: res.location() here ' +
          'prefixes a rooted target with the CURRENT realm, and that is ' +
          'exactly wrong for the one endpoint whose purpose is to land you ' +
          'in a different one. 303, so the reload after it is a GET.' },

  { path: '/admin/config', group: 'Admin', name: 'Configuration',
    specs: [],
    effect: 'changes what every FUTURE token, assertion, ticket and search is ' +
            'built with, for the settings that are changeable at all',
    what: 'NON-SPEC. Every setting this service has, grouped by the protocol ' +
          'they belong to, with the effective value ' +
          'of each and, which is the part that was not answerable before, ' +
          'WHERE THAT VALUE CAME FROM: a runtime override set here, an ' +
          'environment variable, the appconfig file this process was started ' +
          'with, or env/defaults.js under it — and there is no fifth, since a ' +
          'setting with a value in none of them stops this service from ' +
          'starting. The page itself says how many there ' +
          'are and how many can be changed while the service runs, counted ' +
          'off config.js\'s table — this sentence used to carry the two ' +
          'numbers and had drifted by half. The rest were consumed at ' +
          'startup (a bound ' +
          'socket, the TLS certificate\'s names, the Kerberos principal ' +
          'database and its long-term keys, the directory\'s base DN) and are ' +
          'shown with the reason rather than hidden. Changes are IN MEMORY and ' +
          'are gone on restart — nothing writes to the appconfig file.' },
  { path: '/admin/token-lifetimes', group: 'Admin', name: 'Token lifetimes',
    specs: ['rfc6749', 'rfc7519', 'oidc'],
    effect: 'changes how long every FUTURE access token, ID Token and refresh ' +
            'token is good for, and what this service believes when it reads ' +
            'one back',
    what: 'NON-SPEC. Four of the settings on /admin/config, on a page of ' +
          'their own because they are the ones somebody sets to a specific ' +
          'number to watch something happen: the access token, ID Token and ' +
          'refresh token lifetimes, and the clock skew applied wherever this ' +
          'service reads back a token it signed. Every lifetime is a whole ' +
          'number of thirty-second units and the skew is capped at 300. It ' +
          'writes through the same function /admin/config does — there is no ' +
          'second store — and a change reaches the NEXT token, since a ' +
          'lifetime is stamped into one as its exp claim when it is signed. ' +
          'The page also counts what has already expired, against the same ' +
          'clock /oauth2/introspect uses. Add ?format=json; ' +
          'POST {"action":"set","oauth2.accessTokenTtlS":60} for the same ' +
          'thing without a browser.' },
  { path: '/admin/vc-verifier-config', group: 'Admin', name: 'Verifier request (the bar door)',
    specs: ['oid4vp', 'sd-jwt-vc', 'vcdm', 'rfc4519'],
    effect: 'changes the dcql_query of every FUTURE OID4VP Authorization Request',
    what: 'NON-SPEC. What the mock Verifier at /oid4vp/verifier asks a wallet for — which claims, ' +
          'and in which of the three credential formats — reaching the wire as the dcql_query of ' +
          'the next Authorization Request and, after it, as what the presentation is checked ' +
          'against. The claims are the /admin/vc catalogue grouped into CLAIMS rather than ' +
          'attribute types, because a credential carries one Disclosure per top-level claim and ' +
          'address is therefore one unit of disclosure however many LDAP attributes feed it. A ' +
          'claim NOT in the catalogue can be asked for too, and is the point rather than a loose ' +
          'end: nothing here issues it, so it is the only way to exercise what a wallet does with ' +
          'a request it cannot satisfy. Requesting NOTHING is also a setting — DCQL reads an ' +
          'absent claims member as the whole credential. The DCQL PATH DIFFERS BY FORMAT and the ' +
          'page shows which: top level for dc+sd-jwt, under credentialSubject for jwt_vc_json, ' +
          'and under the vendored JSON-LD context\'s own term for ldp_vc, which cannot carry ' +
          'every claim at all. This page ASKS and admits nobody: a presentation that verifies ' +
          'starts no session and issues no token. Add ?format=json; POST ' +
          '{"action":"select","claims":[...]} for the same thing without a browser.' },

  // --- Management API ---
  //
  // NON-SPEC, all of it, and it is the /admin console's own surface over JSON:
  // every page's `?format=json` view and every one of its forms, at a path a
  // script can use. The rows are short on purpose — the OpenAPI document at
  // /admin-api/openapi.json carries the detail, is built from the same table
  // that registers these routes, and cannot go stale in the way a hand-written
  // description can.
  //
  // The four POST rows are ONE express pattern each, behind every action in
  // them: `/admin-api/tokens/:action` serves six real URLs. That is why they are
  // listed with the parameter rather than as twenty-four rows, and why they are
  // not linkable here.
  { path: '/admin-api', group: 'Management API', name: 'Management API index',
    specs: ['openapi'],
    what: 'NON-SPEC. What the API is and every operation in it, each naming the ' +
          '/admin control it mirrors. Nothing here changes anything. NOT ' +
          'PROTECTED — nothing in this service checks a credential.' },
  { path: '/admin-api/logout', group: 'Management API', name: 'Live sessions, and ending them',
    specs: ['openapi'],
    what: 'What this service is still holding for one identity across every protocol family, ' +
          'and the four operations that act on it — global, end, restore-token and ' +
          'restore-kerberos. It mirrors /admin/logout and calls the same two functions, so the ' +
          'console and this API cannot come to disagree about what a live session is. The rows ' +
          'that CANNOT be ended are in the reply with a `why`, which is the member most likely ' +
          'to be mistaken for a defect and is the honest half of the answer.' },
  { path: '/admin-api/logout/:action', group: 'Management API',
    name: 'Live sessions: end them',
    specs: ['openapi'],
    what: 'The four actions above, each named in the path the way every other action resource ' +
          'here names its own.' },
  { path: '/admin-api/openapi.json', group: 'Management API',
    name: 'OpenAPI document', specs: ['openapi'],
    what: 'NON-SPEC. The OpenAPI 3.1 document for the management API, BUILT ' +
          'FROM THE ROUTE TABLE that registers those routes rather than kept ' +
          'beside it, so an operation cannot exist and be undocumented. ' +
          'servers[0].url is this service as the request reached it, so a ' +
          'document fetched through a published port names an address the ' +
          'caller can use.' },
  { path: '/admin-api/docs', group: 'Management API', name: 'API explorer',
    specs: ['openapi'],
    what: 'NON-SPEC. A page that reads the document above and renders one form ' +
          'per operation, with the equivalent curl line beside each. It is this ' +
          'repository\'s own rather than Swagger UI — 11.7 MB with an ' +
          'install-time telemetry dependency, in a service that is deliberately ' +
          'dependency-light and must build offline. THE ONE PAGE IN THIS SERVICE ' +
          'WITH A SCRIPT: it is served under a policy that relaxes script-src to ' +
          "'self' and adds connect-src, and nothing else." },
  { path: '/admin-api/docs/explorer.js', group: 'Management API',
    name: 'API explorer script', specs: [],
    what: 'NON-SPEC. The explorer\'s script, and the only script this service ' +
          'serves. A separate resource rather than an inline block precisely so ' +
          "that script-src 'self' suffices and 'unsafe-inline' is never needed." },
  { path: '/admin-api/status', group: 'Management API', name: 'Service status',
    specs: [],
    what: 'NON-SPEC. The issuer, when this process started, and the running ' +
          'totals — calls, tokens held and revoked, other artifacts, users, ' +
          'sign-on sessions. The cheapest call here and the one to poll. Mirrors ' +
          'GET /admin.' },
  { path: '/admin-api/metrics', group: 'Management API', name: 'Metrics',
    specs: [],
    what: 'NON-SPEC. Everything /admin/metrics counts, as JSON: calls by matched ' +
          'route and status class, tokens and artifacts by kind with the state ' +
          'of each, and sessions counted both ways. Mirrors GET /admin/metrics.' },
  { path: '/admin-api/users', group: 'Management API', name: 'Users',
    specs: [],
    what: 'NON-SPEC. Every identity this service has authenticated, filtered and ' +
          'paged; ?user= is the drill-down, with the sessions each holds and the ' +
          'tokens issued on them. A name never seen answers 200 with ' +
          'known:false rather than 404 — it is an answer about the identity, not ' +
          'about the route. Mirrors GET /admin/users.' },
  { path: '/admin-api/users/:action', group: 'Management API',
    name: 'User actions',
    specs: ['rfc4511', 'rfc4519'],
    effect: 'creates an entry under ou=users in the embedded LDAP directory',
    what: 'NON-SPEC path over the embedded directory. One URL behind the pattern: create, ' +
          'which puts a person there BEFORE they authenticate — otherwise an entry appears ' +
          'only when somebody presents a credential somewhere in this service. The entry ' +
          'carries the invented person behind that name, so an issued credential and an ' +
          'ldapsearch agree from the start. ONE ENTRY PER PERSON: a username already here is ' +
          'refused, whatever protocol brought them and whichever attribute their entry is ' +
          'named by, and an ldapadd under ou=users gets the same refusal as ' +
          'LDAP_ENTRY_ALREADY_EXISTS (68) — all three doors call one function. NO PASSWORD IS ' +
          'SET, because none is ever checked. Creating the entry does not put the name in GET ' +
          '/admin-api/users: that lists identities this service has SEEN authenticate, and ' +
          'this writes what the directory HOLDS. Mirrors POST /admin/users.' },
  { path: '/admin-api/groups', group: 'Management API', name: 'Directory groups',
    specs: ['rfc4511', 'rfc4514', 'rfc4519'],
    what: 'NON-SPEC. Every group in the embedded LDAP directory; ?group=<dn> is ' +
          'the drill-down. A process with no directory answers 200 with ' +
          'directory:false and a group that is not there with found:false, ' +
          'because both are answers rather than errors. A GROUP HERE GRANTS ' +
          'NOTHING. Mirrors GET /admin/groups.' },
  { path: '/admin-api/rbac', group: 'Management API', name: 'Admin console roles',
    specs: ['rfc4511', 'rfc4514', 'rfc4519'],
    what: 'NON-SPEC. The two console roles with every grant, the four settings behind the ' +
          'gate, and who the CALLER is. The roles are two ordinary directory groups, so this ' +
          'and an ldapsearch answer about the same entries. Mirrors GET /admin/rbac.' },
  { path: '/admin-api/rbac/:action', group: 'Management API', name: 'Admin role actions',
    specs: ['rfc4511', 'rfc4514', 'rfc4519'],
    effect: 'grants or revokes access to the admin console',
    what: 'NON-SPEC. Two URLs behind one pattern: grant and revoke. THIS RESOURCE IS NOT ' +
          'GATED BY admin.authRequired and neither is anything else under /admin-api, which ' +
          'is deliberate and has a consequence worth stating: with the console protected and ' +
          'this open, anybody who can reach this port can grant themselves both roles. It is ' +
          'the same decision the whole service rests on — /oauth2/token will mint a token for ' +
          'any username asked of it — and it is what makes this the way back in when the ' +
          'roster is empty and admin.openWhenEmpty is off, a state from which no browser can ' +
          'reach the console at all. Granting a role somebody already holds, or revoking one ' +
          'they do not, answers 200 with changed:false. A person who does not exist CAN be ' +
          'granted a role: the membership dangles until they first sign in. Mirrors ' +
          'POST /admin/rbac.' },
  { path: '/admin-api/tokens', group: 'Management API',
    name: 'Issued tokens, assertions and tickets',
    specs: ['rfc7009', 'rfc7662', 'oidc', 'saml2', 'saml11', 'rfc4120'],
    what: 'NON-SPEC. Everything issued and still remembered — every JWT, every ' +
          'SAML assertion and every Kerberos ticket — in one list, newest first, ' +
          'filtered by family, kind and state and paged with ?page= and ?per=. ' +
          'Claims and facts only, never the signed artifact. OID4VCI credentials ' +
          'are counted on /admin-api/metrics and are not in this list. Mirrors ' +
          'GET /admin/tokens.' },
  { path: '/admin-api/tokens/:action', group: 'Management API',
    name: 'Token actions',
    specs: ['rfc7009', 'rfc7662', 'oidc'],
    effect: 'revokes one token, a whole kind, everything for a subject or an ' +
            'identity, or everything',
    what: 'NON-SPEC path over an RFC 7009 operation. Six URLs behind one ' +
          'pattern: revoke, restore, revoke-kind, revoke-subject, revoke-user, ' +
          'revoke-all. It is the SAME revocation set /oauth2/revoke writes to, ' +
          'so introspection, UserInfo and the refresh grant honour it ' +
          'immediately. ONLY THE THREE JWT KINDS CAN BE REVOKED — nothing ' +
          'consults this service about an assertion or a ticket. restore is ' +
          'NON-SPEC even here: no real authorization server can undo a ' +
          'revocation. Mirrors POST /admin/tokens.' },
  { path: '/admin-api/applications/:action', group: 'Management API',
    name: 'Application actions',
    specs: ['rfc4511', 'rfc7591', 'rfc7592', 'rfc9700'],
    effect: 'creates, edits or deletes an entry under ou=applications, which is what RFC 9700 ' +
            'mode then enforces',
    what: 'NON-SPEC path over the embedded directory. Six URLs behind one pattern: create, ' +
          'set, add, remove, revoke-registration, forget. NOT A THIRD STORE — each calls the ' +
          'same function in applications.js that a protocol path and an LDAP modify reach, ' +
          'against the same entries, so a POST here and an ldapmodify are one act arriving by ' +
          'two routes. WHAT MAY BE CHANGED IS DECLARED AND NOT DERIVED: the redirect URIs, ' +
          'grant types, scopes, secret and auth method say what an application is ALLOWED to ' +
          'do and are editable; the counters, the sightings, the kinds and the protocols are ' +
          'what HAPPENED and are refused with a list of what is not, because a call that could ' +
          'rewrite them would make this registry lie about the service\'s own behaviour. ' +
          'ldapmodify still reaches everything, which is deliberate. `create` is how a relying ' +
          'party is configured BEFORE it connects — otherwise an entry only appears when an ' +
          'identifier is accepted — and `forget` is the one operation that loses a fact, which ' +
          'is why it is separate from revoke-registration. Mirrors POST /admin/applications.' },
  { path: '/admin-api/applications', group: 'Management API', name: 'Applications',
    specs: ['rfc4511', 'rfc7591'],
    what: 'NON-SPEC. Every application this service has been asked about, as JSON: OAuth ' +
          'clients, OpenID Connect relying parties, SAML 2.0 and 1.1 service providers, ' +
          'WS-Federation applications, WS-Trust relying parties, the OpenID4VP verifier and ' +
          'Kerberos services, one per unique identifier. Filtered by ?q= and ?kind= and paged ' +
          'with ?page= and ?per=; ?application=<id> answers with one of them, every attribute ' +
          'of its directory entry and what the published schema says each attribute is, its ' +
          'own list paged under ?attributesPage=. The entries ARE the registry — they live ' +
          'under ou=applications and nothing caches them — so this reply reflects an ' +
          'ldapmodify made a second earlier. POST /admin-api/applications/{action} writes: ' +
          'create, set, add, remove, revoke-registration and forget, each calling the same ' +
          'function a protocol path or an LDAP modify reaches, so they are not a third store. ' +
          'What they will not change is the derived half — the counters and the sightings — ' +
          'which is refused with a list of what is editable. Note that ?kind= does not ' +
          'partition the list, since a record commonly carries two. Mirrors ' +
          'GET and POST /admin/applications.' },
  { path: '/admin-api/applications/new', group: 'Management API',
    name: 'New application form', specs: ['rfc4511', 'rfc7591'],
    what: 'NON-SPEC. THE TWO CLOSED VOCABULARIES A CREATE TAKES, as JSON: the eight kinds and ' +
          'the fourteen protocol families an application may be DECLARED for, each with what ' +
          'it means, plus the ou=applications container a new entry would land in — THIS ' +
          'REALM\'S, because the directory is per realm — how many it will hold, and the ' +
          'attributes a create cannot take but set/add/remove can. IT CREATES NOTHING: the ' +
          'create is POST /admin-api/applications/create, and this is the list that call ' +
          'validates against, published so a caller learns what it may send from the service ' +
          'rather than from a copy in a document. Declaring a family grants and refuses ' +
          'nothing — no endpoint reads appAllowedProtocol. Mirrors GET ' +
          '/admin/applications/new.' },
  { path: '/admin-api/authorization-servers', group: 'Management API',
    name: 'Authorization servers', specs: ['rfc8414', 'oidc-discovery', 'rfc9700'],
    what: 'NON-SPEC. Every authorization server profile as JSON, paged, each with its ' +
          'overrides, its removals, the two URLs it is published at and its DRIFT — the ' +
          'members whose published value does not describe this service. ?profile=<id> returns ' +
          'one. Mirrors GET /admin/authorization-servers.' },
  { path: '/admin-api/authorization-servers/:action', group: 'Management API',
    name: 'Authorization server actions', specs: ['rfc8414', 'rfc9700'],
    effect: 'changes what a discovery document publishes, on the next fetch',
    what: 'NON-SPEC. Five URLs behind one pattern: create, set, remove, reset, delete. ANY ' +
          'MEMBER NAME IS ACCEPTED, including one this service has never heard of — the ' +
          'difference between this and the applications registry, which refuses an attribute ' +
          'outside its schema, and it is deliberate: that schema is a contract about what an ' +
          'entry carries and this is a way to publish something a client did not expect. ' +
          '`remove` and `reset` are not the same operation: reset undoes an override, remove ' +
          'publishes an ABSENCE, and a client that cannot find a member learns nothing rather ' +
          'than learning the capability is missing. Mirrors POST /admin/authorization-servers.' },
  { path: '/admin-api/scim', group: 'Management API', name: 'SCIM',
    specs: ['rfc7643', 'rfc7644', 'openapi'],
    what: 'Everything /admin/scim shows, over JSON: the counters, the endpoint list, what ' +
          'SCIM here will not do, the reachable negatives and the whole attribute ' +
          'mapping. READ-ONLY, and the second of the two operations here with no POST ' +
          'beside it — the other is the audit log. In both cases that is the parity rule ' +
          'holding: the console page carries no control either, because everything about ' +
          'SCIM that can be changed is a configuration row and POST /admin-api/config/set ' +
          'is already the operation for it.' },
  { path: '/admin-api/spiffe', group: 'Management API', name: 'The SPIFFE trust domain',
    specs: ['openapi', 'spiffe-bundle'],
    what: 'GET /admin/spiffe over JSON: the authorities, the bundle and its sequence, ' +
          'the federated trust domains, and which of the four gRPC listeners bound. No ' +
          'private key is in the reply — the authority CERTIFICATE is published, the way ' +
          'GET /tls/server-certificate publishes that one.' },
  { path: '/admin-api/spiffe/:action', group: 'Management API',
    name: 'Rotate an authority, or set a federated bundle',
    specs: ['openapi', 'spiffe-bundle'],
    what: 'rotate, federation-set and federation-remove — the same three the console\'s ' +
          'forms post, through the same action function, with the action taken from the ' +
          'URL instead of a hidden input. Rotating PREPENDS an authority and keeps the ' +
          'old one published, so SVIDs already issued go on verifying; it is also the ' +
          'only way to add one, since AppendBundle on the SPIRE Server API is refused.' },
  { path: '/admin-api/spiffe/entries', group: 'Management API',
    name: 'The registration entries',
    specs: ['openapi', 'spiffe-id'],
    what: 'GET /admin/spiffe/entries over JSON, filtered and paged, with ?entry= for ' +
          'one of them and its directory entry. The entries ARE the registry: they live ' +
          'under ou=entries,ou=spiffe and nothing caches them, so an ldapmodify is ' +
          'visible here on the next call.' },
  { path: '/admin-api/spiffe/entries/:action', group: 'Management API',
    name: 'Create, change or delete a registration entry',
    specs: ['openapi', 'spiffe-id'],
    what: 'create, update and delete, calling the same functions the console\'s forms ' +
          'and the SPIRE Server API\'s BatchCreateEntry do — three doors onto one ' +
          'store. Three refusals and no others: a SPIFFE ID that is not one, one in ' +
          'another trust domain, and one under the reserved /spire path.' },
  { path: '/admin-api/spiffe/agents', group: 'Management API', name: 'The attested agents',
    specs: ['openapi', 'spire-server-api'],
    what: 'GET /admin/spiffe/agents over JSON, filtered and paged, with ?agent= for one ' +
          'of them. A RECORD rather than configuration — everything on these entries was ' +
          'written by this service when an agent attested, and none of it was verified.' },
  { path: '/admin-api/spiffe/agents/:action', group: 'Management API',
    name: 'Ban, unban or forget an agent',
    specs: ['openapi', 'spire-server-api'],
    what: 'ban, unban and delete. The ban is ENFORCED at AttestAgent, which is what ' +
          'keeps it from being a lie; delete is forgetting rather than revoking, since ' +
          'the agent reappears the moment it attests again.' },
  { path: '/admin-api/delegation', group: 'Management API',
    name: 'Delegation',
    specs: ['ms-sfu', 'rfc4120', 'ws-trust', 'rfc8693'],
    what: 'NON-SPEC. Every delegation this service has performed or REFUSED, ' +
          'as JSON: eight mechanisms across Kerberos, WS-Trust and OAuth 2.0 ' +
          'Token Exchange in one model, each naming the initial identity, the ' +
          'intermediary acting for them and the target reached. Filtered by ' +
          'type, mode, outcome, protocol and free text and paged with ?page= ' +
          'and ?per=. Read `mode` first: an `impersonation` leaves nothing in ' +
          'the credential to say a middle tier was involved, so this is the ' +
          'only place that fact will ever be. A refused act carries the ' +
          'KDC\'s own reason and appears in no other resource here. Besides ' +
          'the paged acts the reply carries `chains` — the distinct ' +
          '(mechanism, initial, intermediary, target) tuples among what ' +
          'matched, one per edge — and `policy`, who may delegate to whom ' +
          'before anybody has tried. WALK IT BY `seq`. READ ONLY, one of the ' +
          'two resources here that is: everything on it is an observation or ' +
          'somebody else\'s configuration, so there is nothing to change. ' +
          'Mirrors GET /admin/delegation.' },
  { path: '/admin-api/audit', group: 'Management API', name: 'Audit log',
    specs: ['rfc4511'],
    what: 'NON-SPEC. What happened here, in order, as JSON: every ' +
          'authentication, sign-on session, LDAP directory operation, console ' +
          'interaction, management API call and protocol endpoint call, ' +
          'newest first, filtered by category, action, outcome, actor and ' +
          'free text and paged with ?page= and ?per=. NO CREDENTIAL IS EVER ' +
          'IN A ROW — no password, bearer token, assertion or body; a modify ' +
          'names the attributes it changed and never their values. WALK IT BY ' +
          '`seq` rather than by page: it is monotonic and never reused, so ' +
          '"everything after 4102" is exact where page 2 taken a second after ' +
          'page 1 can repeat a row that shifted onto it. READ ONLY — one of ' +
          'the two resources here that is, the other being ' +
          '/admin-api/delegation. There is no clear operation, because ' +
          'an erase control on an unprotected API would make an audit log ' +
          'unable to answer the one question it exists for. Mirrors GET ' +
          '/admin/audit.' },
  { path: '/admin-api/realms', group: 'Management API', name: 'Trust realms',
    specs: [],
    what: 'NON-SPEC. Every trust realm this process is running, each with its ' +
          'path prefix, its base URL, the kid of its own signing key, what it ' +
          'sets and the four discovery documents a client asks for first — ' +
          'plus which protocol families a realm actually separates and ' +
          'which are shared with every other realm. Mirrors ' +
          'GET /admin/realms. NOTE that this whole API is itself realm-scoped ' +
          'by the same prefix: /realm/acme/admin-api/config is that realm\'s ' +
          'configuration, so these two operations are only the ones that ' +
          'manage the REGISTRY.' },
  { path: '/admin-api/realms/:action', group: 'Management API',
    name: 'Trust realm actions',
    effect: 'defines and removes whole logical copies of this service, each ' +
            'with its own signing key — and removing one destroys its ' +
            'sessions, tokens, statistics and audit log',
    specs: [],
    what: 'NON-SPEC. Five URLs behind one pattern: create, update, set, ' +
          'unset, remove. Mirrors POST /admin/realms. A realm cannot remove ' +
          'ITSELF — the caller would be left on a prefix that had stopped ' +
          'existing — and the default realm cannot be removed at all, since ' +
          'every URL this service published before realms existed is a URL ' +
          'in it.' },
  { path: '/admin-api/config', group: 'Management API', name: 'Configuration',
    specs: [],
    what: 'NON-SPEC. Every setting, its effective value, and the source of ' +
          'that value — override, environment variable, the appconfig file ' +
          'or env/defaults.js under it. Mirrors GET /admin/config.' },
  { path: '/admin-api/config/:action', group: 'Management API',
    name: 'Configuration actions',
    specs: [],
    effect: 'changes what every FUTURE token, assertion, ticket and search is ' +
            'built with',
    what: 'NON-SPEC. Four URLs behind one pattern: set, set-many, reset, ' +
          'reset-all. set-many is ALL-OR-NOTHING, so a body with one bad ' +
          'field changes nothing and names it; a setting consumed at startup ' +
          'is refused with the reason rather than accepted, because an ' +
          'accepted change that does nothing reads as having worked. Every ' +
          'change is in memory and gone on restart, and reset-all is what a ' +
          'test should call to put the service back. Mirrors POST ' +
          '/admin/config.' },
  { path: '/admin-api/token-lifetimes', group: 'Management API',
    name: 'Token lifetimes',
    specs: ['rfc6749', 'rfc7519', 'oidc'],
    what: 'NON-SPEC. The three lifetimes and the clock skew, as full ' +
          'configuration rows (bounds, source, default) and as four plain ' +
          'numbers, with a count of what has already been issued under them ' +
          'and how much of it has expired. Mirrors GET ' +
          '/admin/token-lifetimes.' },
  { path: '/admin-api/token-lifetimes/:action', group: 'Management API',
    name: 'Token lifetime actions',
    specs: ['rfc6749', 'rfc7519', 'oidc'],
    effect: 'changes how long every FUTURE token issued here is good for',
    what: 'NON-SPEC. Two URLs behind one pattern: set and defaults. set is ' +
          'ALL-OR-NOTHING and, unlike POST /admin-api/config/set-many, ' +
          'REFUSES a property that is not one of the four rather than ' +
          'ignoring it — that door is for a form posting a whole section, ' +
          'this one is for a caller that means to set a lifetime, where a ' +
          'misspelt key that succeeded and changed nothing is the worst ' +
          'possible answer. defaults clears the override on these four only, ' +
          'leaving any other setting alone. Nothing already issued changes. ' +
          'Mirrors POST /admin/token-lifetimes.' },
  { path: '/admin-api/claims', group: 'Management API', name: 'Custom claims',
    specs: ['rfc7519', 'oidc'],
    what: 'NON-SPEC. The two JWT claim sets and the rules that govern them: ' +
          'the claim names this service sets itself and will not let you ' +
          'override, and the placeholders a value may use. Mirrors GET ' +
          '/admin/claims.' },
  { path: '/admin-api/claims/:action', group: 'Management API',
    name: 'Custom claim actions',
    specs: ['rfc7519', 'oidc'],
    effect: 'changes what every FUTURE access token and ID Token contains',
    what: 'NON-SPEC. Seven URLs behind one pattern: add, remove, clear, ' +
          'replace, and the three that set the DIRECTORY ATTRIBUTE half — ' +
          'attributes, attributes-all, attributes-clear. ADDITIVE only — a ' +
          'claim this service sets itself is refused rather than overridden, ' +
          'because every one of those is load-bearing. A `set` of saml2 or ' +
          'saml11 is refused here and named: that door is ' +
          '/admin-api/saml-attributes. Nothing already issued changes. Mirrors ' +
          'POST /admin/claims.' },
  { path: '/admin-api/federation', group: 'Management API',
    name: 'Federation relationships',
    specs: ['saml2-profiles', 'saml11-profiles', 'ws-federation', 'oidc', 'rfc6749'],
    what: 'NON-SPEC. Every federation relationship in both directions, with ' +
          'the fields each still needs before it can work — read off the same ' +
          'per-protocol rule the endpoint applies, so a caller can check its ' +
          'own configuration without reimplementing it. Mirrors GET ' +
          '/admin/federation. fedClientSecret is never returned; that is not a ' +
          'security boundary and is not claimed as one, since an ldapsearch ' +
          'shows it — it is this API not being a second way to read a ' +
          'credential belonging to somebody else\'s service out of this ' +
          'process.' },
  { path: '/admin-api/federation/:action', group: 'Management API',
    name: 'Configure a federation relationship',
    specs: ['saml2-profiles', 'saml11-profiles', 'ws-federation', 'oidc', 'rfc6749'],
    effect: 'the same seven writes the console\'s forms make, and this API is ' +
            'NOT GATED',
    what: 'NON-SPEC. create, set, add-value, remove-value, enable, disable, ' +
          'delete — calling admin.js\'s federationAction(), which is the same ' +
          'function the console posts to. **It is how a test configures a ' +
          'federation partner with no browser at all**, which is the only way ' +
          'this feature can be exercised automatically. The honest ' +
          'consequence, stated rather than buried: anybody who can reach this ' +
          'port can configure a signing certificate this service will then ' +
          'believe. That is not a new hole — the same caller can already grant ' +
          'itself both admin roles and mint a token for any username — but it ' +
          'is the sharpest form of it.' },
  { path: '/admin-api/saml2', group: 'Management API',
    name: 'SAML 2.0 identity provider',
    specs: ['saml2', 'saml2-metadata', 'saml2-profiles'],
    what: 'NON-SPEC. Every SAML 2.0 service provider and the FOUR ENDPOINT ' +
          'URLS each one is configured from — which is a per-row fact rather ' +
          'than a constant, because the metadata is per application. A caller ' +
          'that guessed the slug rule would be a second implementation of it. ' +
          'Also the nine saml2.* settings as read, and two numbers about the ' +
          'profile that are invisible until they are wrong: artifacts awaiting ' +
          'resolution and requests held for sign-in. Mirrors GET /admin/saml2.' },
  { path: '/admin-api/saml2/:action', group: 'Management API',
    name: 'SAML 2.0 service provider actions',
    specs: ['saml2', 'saml2-profiles'],
    effect: 'writes to the LDAP directory — the application entry, through the same ' +
            'function an ldapmodify reaches',
    what: 'NON-SPEC. Four URLs behind one pattern: register, ' +
          'set-logout-service, remove-logout-service, set-signing-certificate. ' +
          'None of them decides whether a request is ACCEPTED — any entityID ' +
          'is — they decide where a LogoutResponse goes and what is recorded. ' +
          'Mirrors POST /admin/saml2.' },
  { path: '/admin-api/saml11', group: 'Management API',
    name: 'SAML 1.1 identity provider',
    specs: ['saml11', 'saml11-profiles', 'saml2-metadata'],
    what: 'NON-SPEC. Every SAML 1.1 relying party and the THREE ENDPOINT URLS ' +
          'each one is configured from, per row for the same reason the SAML ' +
          '2.0 resource\'s are. Also the nine saml11.* settings as read, and ' +
          'THREE numbers about the profile: artifacts awaiting resolution and ' +
          'flows held for sign-in, which behave like the 2.0 ones, and ' +
          'assertions held by reference, which does NOT — it is capped rather ' +
          'than swept, so sitting at its ceiling is the healthy state. Mirrors ' +
          'GET /admin/saml11.' },
  { path: '/admin-api/saml11/:action', group: 'Management API',
    name: 'SAML 1.1 relying party actions',
    specs: ['saml11', 'saml11-profiles'],
    effect: 'writes to the LDAP directory — the application entry, through the same ' +
            'function an ldapadd reaches',
    what: 'NON-SPEC. ONE action, `register`, where the SAML 2.0 resource has ' +
          'four: there is no logout service to declare and no signing ' +
          'certificate to record, because SAML 1.1 has neither a Single Logout ' +
          'nor a request for a relying party to sign. Registering is optional ' +
          'and buys two things — a metadata document to hand somebody, and a ' +
          'NAME to put in providerId so the audience is not guessed. Mirrors ' +
          'POST /admin/saml11.' },
  { path: '/admin-api/saml-attributes', group: 'Management API',
    name: 'Custom SAML attributes',
    specs: ['saml2', 'saml11'],
    what: 'NON-SPEC. The two SAML attribute sets of the same store, the ' +
          'catalogue of LDAP attribute types they choose from, and the one ' +
          'rule that is theirs: the AttributeNamespace a SAML 1.1 attribute ' +
          'gets when the call does not name one. There is no reserved-name ' +
          'list here and the absence is the answer — that list is a JWT rule. ' +
          'Mirrors GET /admin/saml-attributes.' },
  { path: '/admin-api/saml-attributes/:action', group: 'Management API',
    name: 'Custom SAML attribute actions',
    specs: ['saml2', 'saml11'],
    effect: 'changes what every FUTURE SAML assertion contains',
    what: 'NON-SPEC. The same seven URLs behind one pattern, on the two SAML ' +
          'sets: add, remove, clear, replace, attributes, attributes-all, ' +
          'attributes-clear. One action function and one store behind this and ' +
          '/admin-api/claims/:action alike; what differs is which sets each ' +
          'accepts. Mirrors POST /admin/saml-attributes.' },
  { path: '/admin-api/credential-claims', group: 'Management API',
    name: 'Credential claims',
    specs: ['oid4vci', 'sd-jwt-vc', 'vcdm', 'rfc4519'],
    what: 'NON-SPEC. Which claims an issued Verifiable Credential carries — the ' +
          'catalogue of LDAP attribute types, what is selected from it, which ' +
          'terms ldp_vc cannot carry, and a preview of what one person\'s ' +
          'credential would contain if it were issued now. Mirrors GET ' +
          '/admin/vc.' },
  { path: '/admin-api/credential-claims/:action', group: 'Management API',
    name: 'Credential claim actions',
    specs: ['oid4vci', 'sd-jwt-vc', 'vcdm', 'rfc4519'],
    effect: 'changes what every FUTURE Verifiable Credential contains, AND ' +
            'writes to the LDAP directory',
    what: 'NON-SPEC. Five URLs behind one pattern: select, add, remove, ' +
          'defaults, populate. Changing the selection SWEEPS the directory — ' +
          'every person under ou=users gains the selected attributes they are ' +
          'missing, invented deterministically from their username, and an ' +
          'attribute already there is never overwritten. The issuer metadata is ' +
          'built from the same selection, so what is advertised cannot drift ' +
          'from what is minted. Mirrors POST /admin/vc.' },
  { path: '/admin-api/verifier-request', group: 'Management API',
    name: 'Verifier request (the bar door)',
    specs: ['oid4vp', 'sd-jwt-vc', 'vcdm', 'rfc4519'],
    what: 'NON-SPEC. What the mock Verifier at /oid4vp/verifier asks a wallet ' +
          'for, in which credential format, and the dcql_query they build — ' +
          'from the function that builds the real one, so it is the next ' +
          'Authorization Request rather than a description of it. Each ' +
          'catalogue row also says whether the ISSUER currently mints that ' +
          'claim. Mirrors GET /admin/vc-verifier-config.' },
  { path: '/admin-api/verifier-request/:action', group: 'Management API',
    name: 'Verifier request actions',
    specs: ['oid4vp', 'sd-jwt-vc', 'vcdm'],
    effect: 'changes the dcql_query of every FUTURE OID4VP Authorization Request',
    what: 'NON-SPEC. Five URLs behind one pattern: select, add, remove, ' +
          'defaults, format. A claim NOT in the catalogue can be asked for and ' +
          'that is the point — nothing here issues it, so it is the only way to ' +
          'exercise what a wallet does with a request it cannot satisfy. ' +
          'Requesting NOTHING is also a setting: DCQL reads an absent claims ' +
          'member as the whole credential. A request already in flight keeps the ' +
          'claims it was built with. Mirrors POST /admin/vc-verifier-config.' },

  // --- WS-Trust ---
  { path: '/sts', group: 'WS-Trust', name: 'Security Token Service',
    specs: ['ws-trust', 'wss-username', 'saml2', 'xmldsig'],
    what: 'POST a SOAP RequestSecurityToken; dispatches on wst:RequestType (Issue, Renew, Validate, ' +
          'Cancel) and returns an RSTR. GET describes the endpoint. Add ?encrypt=1 to have the issued ' +
          'assertion returned as an EncryptedAssertion.' },
  { path: '/sts/cert', group: 'WS-Trust', name: 'STS certificate',
    specs: ['ws-trust'], what: 'The PEM certificate whose key signs the assertions, so a relying ' +
                               'party can verify them.' },

  // --- WS-Federation ---
  { path: '/wsfed', group: 'WS-Federation', name: 'Passive requestor endpoint',
    specs: ['ws-federation', 'saml11', 'saml2', 'xmldsig', 'ws-trust'],
    effect: 'with no wa it describes itself; wa=wsignin1.0 shows the sign-in screen, or POSTs a token ' +
            'to wreply when a session already exists',
    what: 'GET or POST, dispatching on wa: wsignin1.0 signs in and POSTs an RSTR to wreply (section ' +
          '13.2.2 — a form POST, never a redirect, so the token is not length-limited and never ' +
          'reaches a URL or a Referer header); wsignout1.0 ends the session and sends a cleanup ' +
          'request to every relying party it signed into; wsignoutcleanup1.0 ends it without fanning ' +
          'out. Reads wtrealm (required, and the audience), wreply (optional — defaults to /wsfed/rp), ' +
          'wctx (echoed byte for byte), wct, wfresh (MINUTES), wauth, whr and a wreq RST by value. ' +
          'The token is a SAML 1.1 assertion by default because that is what AD FS issues; ' +
          '?tokenType=saml2 and ?trust=1.3 are NON-SPEC switches for the other token type and the ' +
          'ws-sx RSTR Collection wrapper. wattr1.0 and wpseudo1.0 answer 501; wreqptr is refused.' },
  { path: '/wsfed/login', group: 'WS-Federation', name: 'Sign-in form target',
    specs: ['ws-federation'],
    what: 'Where the WS-Federation sign-in screen posts. No password is checked — the username typed ' +
          'becomes the subject of the assertion — except that the literal "invalid" fails, as it does ' +
          'in every other protocol here. It creates the SAME session the OAuth 2.0 / OIDC login ' +
          'screen creates, which is what makes single sign-on work across the two: sign in there with ' +
          'a security key and the assertion issued here says a hardware key was used.' },
  { path: '/wsfed/autopost.js', group: 'WS-Federation', name: 'Sign-in response auto-post script',
    specs: ['ws-federation'],
    what: 'Submits the section 13.2.2 form. A separate resource rather than an inline script for the ' +
          'reason the WebAuthn one is: this service sets script-src \'none\' on every response and ' +
          'that page relaxes it to \'self\'. With scripting off the page\'s submit button is the ' +
          'whole mechanism, which is why it is labelled for a person rather than hidden.' },
  { path: '/FederationMetadata/2007-06/FederationMetadata.xml', group: 'WS-Federation',
    name: 'Federation metadata', specs: ['ws-federation', 'xmldsig', 'saml11', 'saml2'],
    what: 'A SIGNED EntityDescriptor with a fed:SecurityTokenServiceType role: the signing ' +
          'certificate, fed:TokenTypesOffered (SAML 1.1 and 2.0), fed:ClaimTypesOffered, and both the ' +
          'PassiveRequestorEndpoint and the SecurityTokenServiceEndpoint. At AD FS\'s path because ' +
          'WS-Federation names none and that is where relying parties look. The signature is the ' +
          'FIRST child of EntityDescriptor, where the SAML metadata schema requires it. There is ' +
          'deliberately no IDPSSODescriptor: this service has no SAML 2.0 Web SSO profile, and ' +
          'advertising one would be a relying party\'s first configuration attempt and its first 404.' },
  { path: '/wsfed/rp', group: 'WS-Federation', name: 'Mock relying party (not a spec endpoint)',
    specs: ['ws-federation', 'saml11', 'saml2', 'xmldsig'],
    effect: 'mints a wctx and offers a complete sign-in request for each shape the endpoint can issue',
    what: 'NON-SPEC — a relying party is not part of an identity provider. It is here because it is ' +
          'the default wreply, and because it VERIFIES the sign-in response check by check: the ' +
          'assertion signature against /sts/cert, the issuer, the audience against its own realm, the ' +
          'validity window, and the wctx round trip (an identity provider that re-encoded it produces ' +
          'the same symptom as a lost session). Also answers wa=wsignoutcleanup1.0, which is the ' +
          'direction that message is really defined for.' },

  // --- SAML 2.0 ---
  // The profile whose absence this file documented at length until 2026-08-24.
  // The `saml2` coverage note above was rewritten in the same change; if one of
  // them says there is no Web SSO profile here, it is that note that is wrong.
  { path: '/saml2', group: 'SAML 2.0', name: 'What the profile is',
    specs: ['saml2', 'saml2-bindings', 'saml2-profiles', 'saml2-metadata'],
    what: 'A description page: the endpoints, the three bindings, and how the ' +
          'per-service-provider metadata works. GET /sts and GET /wsfed answer ' +
          'the same way for the same reason — an endpoint that 400s at ' +
          'somebody who wanted to know what it was is a bad first impression.' },
  { path: '/saml2/metadata', group: 'SAML 2.0', name: 'Identity provider metadata',
    specs: ['saml2-metadata', 'xmldsig'],
    what: 'The SIGNED IDPSSODescriptor: both SSO bindings, both SLO bindings, ' +
          'the artifact resolution service, the NameID formats and the signing ' +
          'certificate. ds:Signature goes FIRST inside EntityDescriptor, where ' +
          'the metadata schema puts it — a protocol message puts it after ' +
          'Issuer, so the two are not interchangeable. no-store, because the ' +
          'signing key is regenerated on every start.' },
  { path: '/saml2/metadata/:sp', group: 'SAML 2.0',
    name: 'Identity provider metadata for ONE service provider',
    specs: ['saml2-metadata', 'xmldsig'],
    what: 'THE SAME DOCUMENT, PER APPLICATION: a distinct identity provider ' +
          'entityID and endpoints scoped to that service provider, which is ' +
          'what Okta and Ping publish. IT 404s FOR NOTHING — an entityID ' +
          'nobody registered is registered BY THE ASK, so a service provider ' +
          'can be pointed here before anything is provisioned. The segment is ' +
          'the percent-encoded entityID, or a slug (app-<12 hex>) where the ' +
          'entityID is not safe in a path. saml2.perApplicationEntityId turns ' +
          'the separate entityID off; the endpoints stay per-application.' },
  { path: '/saml2/sso', group: 'SAML 2.0', name: 'Single Sign-On service',
    specs: ['saml2', 'saml2-bindings', 'saml2-profiles', 'xmldsig'],
    effect: 'starts a browser sign-on session — the SAME session OAuth 2.0 / OIDC and ' +
            'WS-Federation use',
    what: 'GET is the HTTP Redirect binding and POST is the HTTP POST binding; ' +
          'the RESPONSE goes back on whichever the AuthnRequest\'s ' +
          'ProtocolBinding asked for, HTTP POST by default. It has NO SIGN-IN ' +
          'SCREEN OF ITS OWN: a POST-binding request is held and turned into a ' +
          'GET so the SameSite=Lax session cookie is visible, and the screen is ' +
          '/authn/login. ANY entityID is accepted, and the first valid request ' +
          'from one creates its application entry. A request signature is ' +
          'RECORDED AND NOT CHECKED, like every credential here.' },
  { path: '/saml2/sso/:sp', group: 'SAML 2.0',
    name: 'Single Sign-On service for ONE service provider',
    specs: ['saml2', 'saml2-bindings', 'saml2-profiles', 'xmldsig'],
    effect: 'the same, and it is the same endpoint',
    what: 'The address the per-application metadata publishes. The scope in ' +
          'the path decides which identity provider names itself in the ' +
          'answer; the AuthnRequest\'s own Issuer decides who the assertion is ' +
          'for either way, so a request that disagrees with the path is ' +
          'answered for its Issuer.' },
  { path: '/saml2/ars', group: 'SAML 2.0', name: 'Artifact Resolution Service',
    specs: ['saml2', 'saml2-bindings', 'saml2-profiles'],
    what: 'POST a SOAP 1.1 envelope carrying an ArtifactResolve and get one ' +
          'back carrying the message. A BACK CHANNEL: the browser never ' +
          'touches it, which is the whole point of the artifact profile — the ' +
          'assertion never passes through the user agent. AN ARTIFACT ' +
          'RESOLVES EXACTLY ONCE (section 3.6.4.1): resolving destroys it, and ' +
          'the second attempt is refused with a status naming the reason. GET ' +
          'describes the endpoint and shows the curl.' },
  { path: '/saml2/ars/:sp', group: 'SAML 2.0',
    name: 'Artifact Resolution Service for ONE service provider',
    specs: ['saml2', 'saml2-bindings'],
    what: 'The address the per-application metadata publishes, and the same ' +
          'service: an artifact is found by its own value rather than by the ' +
          'path it is resolved at.' },
  { path: '/saml2/slo', group: 'SAML 2.0', name: 'Single Logout service',
    specs: ['saml2', 'saml2-bindings', 'saml2-profiles', 'xmldsig'],
    effect: 'ENDS the browser sign-on session, which signs the OAuth 2.0 / OIDC and ' +
            'WS-Federation sides out too',
    what: 'Both directions. A LogoutRequest from a service provider ends the ' +
          'session and is answered with a LogoutResponse on the binding it ' +
          'arrived on; a bare GET ends the session and NAMES every service ' +
          'provider it signed into, with a LogoutRequest built for each. WHERE ' +
          'THE LogoutResponse GOES IS A GUESS unless it was declared — a ' +
          'LogoutRequest carries no return address, only SP metadata does, and ' +
          'this service does not consume SP metadata. Declare it on ' +
          '/admin/saml2 or with saml2.defaultSingleLogoutService.' },
  { path: '/saml2/slo/:sp', group: 'SAML 2.0',
    name: 'Single Logout service for ONE service provider',
    specs: ['saml2', 'saml2-bindings', 'saml2-profiles'],
    effect: 'the same, and it is the same endpoint',
    what: 'The address the per-application metadata publishes.' },
  { path: '/saml2/autopost.js', group: 'SAML 2.0', name: 'HTTP POST binding auto-post script',
    specs: ['saml2-bindings'],
    what: 'The FIFTH scripted page in this service, and the argument is made ' +
          'again in saml2_sso.js rather than by analogy: the HTTP POST binding ' +
          'IS a self-submitting form, so there is no version of it without a ' +
          'script. script-src is relaxed to \'self\' naming this one resource, ' +
          'never \'unsafe-inline\', and the page carries a REAL SUBMIT BUTTON ' +
          '— with scripting off the button is the whole mechanism.' },
  { path: '/saml2/sp', group: 'SAML 2.0', name: 'Mock service provider (not a spec endpoint)',
    specs: ['saml2', 'saml2-bindings', 'saml2-profiles', 'xmldsig'],
    effect: 'mints a RelayState and offers a complete AuthnRequest for each of the three bindings',
    what: 'NON-SPEC — a service provider is not part of an identity provider. ' +
          'It is here because it is the default AssertionConsumerServiceURL, ' +
          'and because it VERIFIES the response check by check: both ' +
          'signatures, the issuer, the audience, the validity window, the ' +
          'bearer SubjectConfirmationData that section 4.1.4.2 requires, and ' +
          'the RelayState round trip. It also resolves an artifact, in ' +
          'process rather than by this service making a SOAP call to itself.' },

  // --- SAML 1.1 ---
  { path: '/saml11', group: 'SAML 1.1', name: 'What the profile is',
    specs: ['saml11', 'saml11-bindings', 'saml11-profiles'],
    what: 'A description page: the endpoints, the two browser profiles, and ' +
          'the list of what SAML 1.1 spells differently from 2.0 — which is ' +
          'most of what makes this a separate implementation rather than a ' +
          'flag. GET /saml2, GET /sts and GET /wsfed answer the same way.' },
  { path: '/saml11/metadata', group: 'SAML 1.1', name: 'Identity provider metadata',
    specs: ['saml11', 'saml2-metadata', 'xmldsig'],
    what: 'SIGNED, and it is a SAML 2.0 METADATA DOCUMENT describing a SAML ' +
          '1.1 identity provider — which is correct rather than a compromise: ' +
          'SAML 1.1 has no metadata specification of its own, and what every ' +
          'relying party consumes is an EntityDescriptor whose ' +
          'protocolSupportEnumeration is urn:oasis:names:tc:SAML:1.1:protocol. ' +
          'TWO descriptors: an IDPSSODescriptor for the browser profiles and ' +
          'an AttributeAuthorityDescriptor for the responder\'s query half, ' +
          'because a Shibboleth service provider looks for its attribute ' +
          'authority in the second and will not find it in the first. THERE IS ' +
          'NO SingleLogoutService — SAML 1.1 has no Single Logout. no-store, ' +
          'because the signing key is regenerated on every start.' },
  { path: '/saml11/metadata/:rp', group: 'SAML 1.1',
    name: 'Identity provider metadata for ONE relying party',
    specs: ['saml11', 'saml2-metadata', 'xmldsig'],
    what: 'THE SAME DOCUMENT, PER APPLICATION, and the same rule the SAML 2.0 ' +
          'one follows: it 404s for nothing, because an identifier nobody ' +
          'registered is registered BY THE ASK. The segment is the ' +
          'percent-encoded identifier or a slug, and the slug is THE SAME ONE ' +
          '/saml2 uses — one application has one handle across both profiles, ' +
          'or the console would show one entry as two. ' +
          'saml11.perApplicationProviderId turns the separate providerID off; ' +
          'the endpoints stay per-application.' },
  { path: '/saml11/sso', group: 'SAML 1.1', name: 'Inter-site transfer service',
    specs: ['saml11', 'saml11-bindings', 'saml11-profiles', 'xmldsig'],
    effect: 'starts a browser sign-on session — the SAME session OAuth 2.0 / OIDC, ' +
            'WS-Federation and SAML 2.0 use',
    what: 'SAML 1.1\'s name for what SAML 2.0 calls the Single Sign-On ' +
          'service, and the difference is not only vocabulary: THERE IS NO ' +
          'REQUEST MESSAGE. A flow starts with a TARGET and nothing else, so ' +
          'the relying party is named by Shibboleth\'s providerId parameter, ' +
          'by the path segment, or — failing both — GUESSED FROM THE ORIGIN of ' +
          'the TARGET, which is logged as a guess. It has no sign-in screen of ' +
          'its own and needs no POST-to-GET dance: the flow arrives as a ' +
          'top-level GET, which a SameSite=Lax cookie is carried on. ' +
          'ForceAuthn, IsPassive and RequestedAuthnContext have no spelling in ' +
          'this protocol, so they are absent rather than unimplemented.' },
  { path: '/saml11/sso/:rp', group: 'SAML 1.1',
    name: 'Inter-site transfer service for ONE relying party',
    specs: ['saml11', 'saml11-profiles'],
    effect: 'the same, and it is the same endpoint',
    what: 'The address the per-application metadata publishes. With no ' +
          'providerId parameter the path segment is what names the relying ' +
          'party — which in SAML 1.1 matters more than it does in 2.0, where ' +
          'the request\'s own Issuer always could.' },
  { path: '/saml11/responder', group: 'SAML 1.1', name: 'SAML responder (SOAP)',
    specs: ['saml11', 'saml11-bindings', 'xmldsig'],
    what: 'POST a SOAP envelope carrying a <samlp:Request>. FOUR shapes are ' +
          'answered where the SAML 2.0 artifact service answers one, because ' +
          'this endpoint has to exist for the artifact profile anyway and an ' +
          'AttributeQuery is then the same builder behind the same envelope: ' +
          'AssertionArtifact (ONE-SHOT — resolving destroys it), ' +
          'AssertionIDReference (NOT one-shot; a reference is not a ' +
          'credential), AttributeQuery and AuthenticationQuery. The last two ' +
          'are SAML 1.1\'s ATTRIBUTE AUTHORITY, which is the half Shibboleth ' +
          'deployments leaned on. NOTHING AUTHENTICATES A CALLER: anybody who ' +
          'can reach this port can ask it about anybody, by name, and every ' +
          'query is logged saying so. GET describes the endpoint.' },
  { path: '/saml11/responder/:rp', group: 'SAML 1.1',
    name: 'SAML responder for ONE relying party',
    specs: ['saml11', 'saml11-bindings'],
    what: 'The address the per-application metadata publishes, and the same ' +
          'service: an artifact is found by its own value rather than by the ' +
          'path it is resolved at. The scope decides the Recipient on the ' +
          'answer and the audience of a query\'s assertion when the query ' +
          'named no Resource.' },
  { path: '/saml11/autopost.js', group: 'SAML 1.1',
    name: 'Browser/POST profile auto-post script',
    specs: ['saml11-bindings', 'saml11-profiles'],
    what: 'The SIXTH scripted page in this service, and the argument is made ' +
          'again in saml11_sso.js rather than by analogy — which matters here ' +
          'precisely because the fifth was /saml2/autopost.js and "the same as ' +
          'next door" is the least useful thing that could be said. The ' +
          'Browser/POST profile IS a self-submitting form in its own older ' +
          'specification, arrived at independently. script-src is relaxed to ' +
          '\'self\' naming this one resource, never \'unsafe-inline\', and the ' +
          'page carries a REAL SUBMIT BUTTON — with scripting off the button ' +
          'is the whole mechanism.' },
  { path: '/saml11/rp', group: 'SAML 1.1', name: 'Mock relying party (not a spec endpoint)',
    specs: ['saml11', 'saml11-bindings', 'saml11-profiles', 'xmldsig'],
    effect: 'starts a complete flow on either browser profile and verifies what comes back',
    what: 'NON-SPEC — a relying party is not part of an identity provider. It ' +
          'is here because it is the default assertion consumer, and because ' +
          'it VERIFIES check by check: both signatures through the id ' +
          'attributes SAML 1.1 actually uses, the status QName, the Recipient, ' +
          'the ABSENCE of InResponseTo on a profile with no request, the ' +
          'confirmation method matching the profile, and the ' +
          'DoNotCacheCondition that Browser/POST carries and the artifact ' +
          'profile does not. It resolves an artifact IN PROCESS rather than by ' +
          'this service making a SOAP call to itself, and reloading the result ' +
          'page demonstrates the one-shot rule rather than erroring.' },

  // --- Federation ---
  //
  // THE ONLY GROUP ON THIS PAGE WHERE THIS SERVICE IS THE CLIENT. Every other
  // endpoint listed here is something a caller asks OF this service; these are
  // where it consumes what somebody else issued, and where it will refuse.
  { path: '/federation', group: 'Federation', name: 'What federation is here',
    specs: ['saml2-profiles', 'saml11-profiles', 'ws-federation', 'oidc', 'rfc6749'],
    what: 'A description page listing every configured relationship in both ' +
          'directions and the URL to configure at each partner. GET /saml2, ' +
          'GET /saml11 and GET /wsfed answer the same way and for the same ' +
          'reason. It is also the one page in this service that says out loud ' +
          'that a feature here REFUSES by default.' },
  { path: '/federation/login/:id', group: 'Federation',
    name: 'Start a federated sign-in',
    specs: ['saml2-profiles', 'saml11-profiles', 'ws-federation', 'oidc', 'rfc6749'],
    effect: 'sends the browser to a FOREIGN identity provider — an ' +
            '<AuthnRequest>, an inter-site transfer URL, wa=wsignin1.0 or an ' +
            'OAuth 2.0 authorization request, whichever the relationship says',
    what: 'Takes ?returnTo=, a path on this service to land on afterwards, ' +
          'which is how a partner button on /authn/login satisfies whatever ' +
          'flow was already in progress. It REFUSES a relationship that is ' +
          'disabled (403) or enabled-and-half-configured (409) rather than ' +
          'starting something that cannot finish — the only endpoints in this ' +
          'service that refuse for a configuration reason. PKCE is always sent ' +
          'on the two OAuth-shaped protocols and there is no setting to stop ' +
          'it.' },
  { path: '/federation/acs/:id', group: 'Federation',
    name: 'Assertion consumer service / wreply / redirect_uri',
    specs: ['saml2', 'saml2-bindings', 'saml2-profiles', 'saml11',
            'saml11-bindings', 'ws-federation', 'oidc', 'rfc6749', 'xmldsig'],
    effect: 'STARTS A BROWSER SIGN-ON SESSION for somebody this service has ' +
            'never authenticated — the same session OAuth 2.0 / OIDC, ' +
            'WS-Federation, SAML and the admin console all read — and creates ' +
            'their directory entry',
    what: 'ONE PATH RECEIVES ALL FIVE PROTOCOLS: five would mean five URLs to ' +
          'configure at a partner and four ways to configure the wrong one, ' +
          'whose failure is a 404 in a browser AFTER a successful sign-in ' +
          'somewhere else. **THIS IS THE ONE ENDPOINT IN THIS SERVICE THAT IS ' +
          'NOT PERMISSIVE, AND CANNOT BE.** What arrives is an ' +
          'unauthenticated HTTP request claiming to be a person; the only ' +
          'thing between that and a session is the signature check against ' +
          'the certificate configured on the relationship. So: the signature ' +
          'must verify against THAT key and not against one the document ' +
          'brought, the issuer must be the configured partner, the assertion ' +
          'must be inside its validity window, and the response must answer a ' +
          'request this service sent unless fedAllowUnsolicited says ' +
          'otherwise. Every refusal draws a page naming the check and writes ' +
          'fedLastError on the relationship — it never redirects, because the ' +
          'person\'s sign-in already succeeded at the partner and the only ' +
          'interesting question is what this service disliked about the ' +
          'answer.' },
  { path: '/federation/metadata/:id', group: 'Federation',
    name: 'This service\'s OWN SAML metadata, per partner',
    specs: ['saml2-metadata', 'saml2', 'saml11'],
    what: 'An SPSSODescriptor rather than an IDPSSODescriptor — this is the ' +
          'half of this service that is a service provider. Per relationship, ' +
          'because this service calls itself something different to every ' +
          'partner. UNSIGNED, deliberately, and it is the one metadata ' +
          'document here that is: /saml2/metadata is signed because a service ' +
          'provider configuring its trust in this service gains from checking ' +
          'who wrote the document, and here the partner is being told where ' +
          'to send things by the very key a signature would be made with. It ' +
          '404s for a relationship that is not SAML, where /saml2/metadata ' +
          '404s for nothing — because that one mints a document for any ' +
          'entityID asked for and this one describes an arrangement that ' +
          'either exists or does not.' },

  // --- OAuth 2.0 / OIDC ---
  { path: '/.well-known/oauth-authorization-server', group: 'OAuth 2.0 / OIDC',
    name: 'Authorization Server Metadata', specs: ['rfc8414'],
    what: 'Every member RFC 8414 section 2 defines, plus a genuinely signed signed_metadata.' },
  { path: '/.well-known/oauth-authorization-server/*', group: 'OAuth 2.0 / OIDC',
    name: 'Authorization Server Metadata (issuer with a path)', specs: ['rfc8414'],
    what: 'The same document at the section 3.1 shape, where the issuer identifier carries a path.' },
  { path: '/.well-known/openid-configuration', group: 'OAuth 2.0 / OIDC',
    name: 'OpenID Provider Configuration', specs: ['oidc-discovery', 'oidc', 'oidc-logout', 'rfc8414',
                                                   'rfc9207', 'rfc9449'],
    what: 'What an OIDC client looks for first. The RFC 8414 document extended with what OpenID ' +
          'Connect Discovery adds — subject_types_supported, id_token_signing_alg_values_supported, ' +
          'claims_supported, the request/claims parameter booleans and end_session_endpoint. Built ' +
          'from the same source as the RFC 8414 document so the two cannot drift. No ' +
          'userinfo_endpoint: there is no userinfo endpoint, and the claims are in the id_token.' },
  { path: '/.well-known/openid-configuration/*', group: 'OAuth 2.0 / OIDC',
    name: 'OpenID Provider Configuration (RFC 8414 inserted-path form)',
    specs: ['oidc-discovery', 'rfc8414'],
    what: 'The same document where the well-known segment is INSERTED before the issuer\'s path, ' +
          'which is RFC 8414 section 3.1\'s shape rather than OIDC\'s. Answered like the ' +
          'oauth-authorization-server route: the issuer is the base URL the request arrived on.' },
  { path: '/*/.well-known/openid-configuration', group: 'OAuth 2.0 / OIDC',
    name: 'OpenID Provider Configuration (issuer with a path)', specs: ['oidc-discovery'],
    what: 'Discovery 1.0 section 4 APPENDS the well-known path to an issuer that carries one, which ' +
          'is the other URL from the row above and the usual reason a discovery fetch 404s. Here the ' +
          'issuer in the document is rebuilt from the path, since a document a client fetched at ' +
          '/tenant1/... and that claims a different issuer is one it must reject.' },
  { path: '/oauth2/jwks', group: 'OAuth 2.0 / OIDC', name: 'JWKS',
    specs: ['rfc7515', 'rfc7519'],
    what: 'The signing key as a single RS256 JWK with its x5c. Regenerated on every start, so it is ' +
          'served no-store.' },
  { path: '/oauth2/authorize', group: 'OAuth 2.0 / OIDC', name: 'Authorization endpoint',
    specs: ['rfc6749', 'oidc', 'rfc7636', 'rfc9396', 'rfc9207', 'rfc9700'], effect: 'needs client_id and redirect_uri — answers 400 when followed bare, then redirects to the sign-in screen once they are supplied',
    what: 'Redirects to the authentication service when there is no session, and is entered a ' +
          'second time when the person comes back signed in — the same request over again, which ' +
          'is why this endpoint keeps no state between the two. Then issues a code, token and/or ' +
          'id_token per response_type. Carries PKCE, nonce, authorization_details and OID4VCI ' +
          'issuer_state, response_mode (query, fragment and form_post — the last answers with ' +
          'a self-submitting form so the response is in no URL, no history entry and no ' +
          'Referer, errors included; a mode this authorization server does not advertise is ' +
          'REFUSED rather than answered with a redirect, because `web_message` silently ' +
          'answered with a 302 leaves a client waiting for a postMessage that never comes), ' +
          'and RFC 8707 `resource` — which becomes the access token\'s audience, ' +
          'may be repeated for a small set of resource servers, and must be an absolute URI ' +
          'with no fragment. In RFC 9700 mode (oauth2.rfc9700, off by default) it also refuses ' +
          'what ' +
          'that BCP says to refuse: a redirect_uri that is not registered — answered HERE as a ' +
          '400 rather than redirected, since redirecting an error to an unvalidated URI is the ' +
          'open redirector section 2.1 forbids — an http redirect URI off the loopback, a public ' +
          'client with no PKCE, code_challenge_method=plain, an id_token with no nonce, and any ' +
          'response type that would issue an access token from here. Section 4.11.2 closes the ' +
          'rest of the open-redirector question: a request naming NO client_id is answered here ' +
          'rather than redirected (RFC 6749 section 4.1.2.1), and an error is only AUTOMATICALLY ' +
          'redirected when somebody is signed in — otherwise the person is shown the client, ' +
          'the destination and the error and follows a link if they choose, because an ' +
          'authorization server that bounces an unauthenticated browser to a legitimate ' +
          'client\'s registered URI is a hop an attacker can send a victim through with no ' +
          'interaction. prompt=none and a refusal coming back from the sign-in screen are the ' +
          'two exceptions, both from the specification.' },
  // ---------------------------------------------------------------------
  // THE PROTOCOL-INDEPENDENT SIGN-OUT. In the Authentication group and not in
  // a group of its own, because it is the other end of what that group does —
  // and deliberately not under any protocol, which is the whole point of it.
  // ---------------------------------------------------------------------
  { path: '/logout', group: 'Authentication', name: 'Sign out of everything',
    specs: ['oidc-fclogout', 'rfc7009', 'ws-federation', 'saml2', 'rfc4120', 'rfc4511'],
    what: 'THE PROTOCOL-INDEPENDENT SIGN-OUT, and the only endpoint here that is about all ' +
          'sixteen families at once. GET lists everything this service is still holding for ' +
          'one identity — every browser sign-on session, every OIDC relying party, ' +
          'WS-Federation realm and SAML 2.0 service provider signed into on one, every token ' +
          'it can still revoke, every outstanding authorization and pre-authorized code, every ' +
          'directory connection bound as them, and the Kerberos ticket position — with a ' +
          'checkbox against each. POST ends what was ticked, and a POST that ticks NOTHING is a ' +
          'GLOBAL logout, which is the default and the point. It also sends what only a browser ' +
          'can send: the Front-Channel Logout iframes, the wsignoutcleanup1.0 images, and the ' +
          'SAML LogoutRequests as links. WHAT IT CANNOT END IS LISTED WITH THE REASON — an ' +
          'assertion, a service ticket or an SVID already issued is beyond recall because ' +
          'nothing consults this service when one is presented, and hiding those would make a ' +
          'global logout look complete when it is not. No console role is needed; with no ' +
          'session it sends the browser to /authn/login and back. logout.anyUser decides ' +
          'whether ?username= may name somebody else, which grants nothing that signing in as ' +
          'them would not. Add ?format=json.' },
  { path: '/authn/login', group: 'Authentication', name: 'Sign-in screen',
    specs: ['oidc'],
    effect: 'shows the sign-in screen for a request another endpoint sent here; needs an ?authn= id, ' +
            'so following it bare answers 400',
    what: 'THE AUTHENTICATION SERVICE. The POST that carries a username and a password is ' +
          'answered with a 303 and never a 307 (RFC 9700 section 4.12): a 307 preserves the ' +
          'method and the body, so the browser would repeat those credentials to whatever the ' +
          'redirect points at — which after a sign-in is a URL the calling protocol composed. ' +
          'Every protocol here that needs a person identified sends ' +
          'them to this one screen with a return URL carrying its own request whole, and gets them ' +
          'back with a session cookie established — GET renders the screen, POST takes what was ' +
          'typed. No password is checked; the username typed becomes the identity in every token, ' +
          'assertion and credential that follows. It knows nothing about the protocol that sent ' +
          'anybody here: what the screen SHOWS about the request it interrupted is supplied by the ' +
          'caller, and a refusal comes back as authn_error=access_denied for the CALLER to turn ' +
          'into whatever its own specification says a refusal looks like. The return URL is checked ' +
          'to be a path on this service — an authentication service that will redirect anywhere ' +
          'after signing somebody in is a phishing tool with a login screen in front of it.' },
  { path: '/authn/webauthn', group: 'Authentication', name: 'WebAuthn security-key step',
    specs: ['oidc', 'webauthn'],
    effect: 'enrols or asserts a security key, then completes the sign-in',
    what: 'The security-key step of the login flow, in EITHER of its two roles — as a SECOND ' +
          'FACTOR after the password step (reached when the authorization request named mfa in ' +
          'acr_values or the user ticked that box), or as the PRIMARY credential with no password ' +
          'at all (the passwordless box, which the caller can forbid by demanding a second ' +
          'factor). First use ENROLS a key for that username; later sign-ins ASSERT with it. The ' +
          'ceremony is verified here — challenge, origin, RP ID hash, flags and the signature over ' +
          'authenticatorData || SHA-256(clientDataJSON) — by an implementation written ' +
          'independently of the debugger\'s own, so the two can be checked against each other. The ' +
          'roles differ in what the session then claims and in nothing else: a second factor ' +
          'records amr ["pwd","hwk"] and acr "mfa", a passwordless sign-in records amr ["hwk"] and ' +
          'acr "1" — ONE factor, since this ceremony asks for user verification as preferred ' +
          'rather than required — and a password-only sign-in records amr ["pwd"] and acr "1". ' +
          'Both key paths are authentications in their own right, so both appear on /admin/users ' +
          'and seed a directory entry; the second factor additionally flags that entry ' +
          'mfaAuthenticated TRUE. The RP ID is this origin\'s host and is not configurable: ' +
          'WebAuthn binds a ceremony to the calling origin, and that is the whole of its phishing ' +
          'resistance.' },
  { path: '/authn/webauthn.js', group: 'Authentication', name: 'WebAuthn ceremony script',
    specs: ['webauthn'],
    what: 'The script the security-key page runs, in both of its roles — the ceremony a second ' +
          'factor performs and the one a passwordless sign-in performs are the same bytes. It is a ' +
          'separate resource rather than an inline script because this service sets script-src \'none\' on every response by default; that ' +
          'one page relaxes it to \'self\', which is the smallest exception that works. An inline ' +
          'script there would simply not run, with the button doing nothing and no error anywhere.' },
  { path: '/oauth2/logout', group: 'OAuth 2.0 / OIDC', name: 'Session end (end_session_endpoint)',
    specs: ['oidc', 'oidc-logout', 'rfc9700'],
    effect: 'drops the mock session cookie, and in RFC 9700 mode revokes the refresh tokens ' +
            'issued on that session',
    what: 'What end_session_endpoint in the OIDC discovery document points at. Drops the session ' +
          'cookie and returns to post_logout_redirect_uri. id_token_hint is neither required nor ' +
          'checked. The redirect target is not validated either — this is an OPEN REDIRECTOR, and ' +
          'the plainest one in this service — UNLESS RFC 9700 mode is on, which matches it against ' +
          'the client\'s registered post_logout_redirect_uris (or the oauth2.redirectUris setting) ' +
          'exactly as an authorization request\'s redirect_uri, and answers a miss with a 400 ' +
          'rather than following it. That mode also makes signing out mean something to the ' +
          'BACK channel: every refresh token issued on the session is revoked (RFC 9700 ' +
          'section 2.2.2\'s security-event MAY), since otherwise a sign-out drops a cookie and ' +
          'leaves a thirty-day credential in the client\'s hands. Access tokens are left alone ' +
          '— they expire in an hour, and revoking them would remove the evidence of what the ' +
          'session did.' },
  { path: '/oauth2/token', group: 'OAuth 2.0 / OIDC', name: 'Token endpoint',
    specs: ['rfc6749', 'oidc', 'rfc8693', 'rfc9396', 'oid4vci', 'rfc9449', 'rfc7800', 'rfc9700',
            'rfc8705', 'rfc8707', 'rfc7523'],
    what: 'authorization_code, refresh_token, client_credentials, password, token-exchange, and ' +
          "OID4VCI's pre-authorized_code with tx_code enforcement. A DPoP proof on the request " +
          'binds the issued access and refresh tokens to its key (cnf.jkt) and makes token_type ' +
          'DPoP; without one the response is an ordinary Bearer token. A Token Request made ' +
          'over a connection carrying a CLIENT CERTIFICATE binds the access and refresh tokens ' +
          'to it as well (RFC 8705 cnf["x5t#S256"]), which needs the main port to be TLS. RFC ' +
          '8707 `resource` narrows the audience, and may only narrow what the authorization ' +
          'request asked for. In RFC 9700 mode a client whose entry says it is CONFIDENTIAL ' +
          'must authenticate here, by any of the six methods — the two secret ones, the two ' +
          'assertion ones (RFC 7523, verified against a registered JWKS or the secret, with a ' +
          'jti replay refused) and RFC 8705 section 2\'s two certificate ones. In RFC 9700 mode the ' +
          'authorization_code grant additionally refuses a code_verifier for a code that was ' +
          'issued without a challenge (the section 4.8.2 downgrade), a code redeemed by a client ' +
          'it was not issued to, and a Token Request with no redirect_uri on it. That mode also ' +
          'refuses the PASSWORD grant outright (section 2.4), ROTATES refresh tokens and revokes ' +
          'the whole chain when a retired one is presented again (section 2.2.2), refuses a ' +
          'refresh from another client, for a wider scope than was granted or for a RESOURCE ' +
          'SERVER the grant was not authorized for — a refresh token carries the RFC 8707 ' +
          'resources its grant had, so a renewal cannot widen its own audience — expires a ' +
          'refresh CHAIN that has been idle (oauth2.refreshIdleSeconds, measured from the last ' +
          'redemption rather than from issuance), and requires a client whose entry says it is ' +
          'confidential to authenticate by any of the six methods (section 2.5). ' +
          'And it turns off the REPLAY RELAXATION above: a code presented a second time is ' +
          'refused rather than answered with the tokens it already bought, and those tokens ' +
          'are revoked (section 4.5, and RFC 6749 section 10.5 for the revocation).' },
  { path: '/dpop/nonce-mode', group: 'OAuth 2.0 / OIDC',
    name: 'DPoP nonce switch (not a spec endpoint)', specs: [],
    what: 'NON-SPEC, for tests and for trying the handshake by hand: turns the RFC 9449 section ' +
          '8/9 server-supplied nonce requirement on and off at runtime, so the 401/retry exchange ' +
          'can be exercised without restarting the service. GET reports the current state; POST ' +
          '{"required": true|false} sets it.' },
  { path: '/oauth2/autopost.js', group: 'OAuth 2.0 / OIDC',
    name: 'The form-post response script', specs: ['oauth-form-post', 'rfc9700'],
    what: 'The script that submits the form on a response_mode=form_post authorization ' +
          'response. A SEPARATE RESOURCE because this service sets script-src \'none\' on ' +
          'every response and that one page relaxes it to \'self\' — an inline script would ' +
          'simply not run, and the button would be the only thing that worked. With scripting ' +
          'off the button IS the mechanism, which is why it is a real button with a label ' +
          'rather than a hidden fallback. The same arrangement /wsfed/autopost.js has, for the ' +
          'same reason.' },
  { path: '/:as/oauth2/authorize', group: 'OAuth 2.0 / OIDC',
    name: 'Authorization endpoint (a named authorization server)',
    specs: ['rfc6749', 'oidc', 'rfc7636', 'rfc9396', 'rfc9207', 'rfc9700', 'rfc8414'],
    effect: 'needs client_id and redirect_uri, like the unprefixed one',
    what: 'ONE ROUTE, AS MANY AUTHORIZATION SERVERS AS HAVE BEEN NAMED. The path component ' +
          'selects one and CREATES it on first sight with the same capabilities the default ' +
          'server has, so an arbitrary name works immediately and can then be configured at ' +
          '/admin/authorization-servers. What that configuration publishes is what this ' +
          'endpoint enforces — a server advertising code_challenge_methods_supported ["S256"] ' +
          'refuses `plain` HERE and nowhere else — so the document is the authorization server ' +
          'rather than a description of one. A code issued by one is not redeemable at ' +
          'another\'s token endpoint. The section above lists the ones this process has ' +
          'actually served.' },
  { path: '/:as/oauth2/token', group: 'OAuth 2.0 / OIDC',
    name: 'Token endpoint (a named authorization server)',
    specs: ['rfc6749', 'oidc', 'rfc8693', 'rfc9396', 'rfc9449', 'rfc9700', 'rfc8414'],
    what: 'The same grants the unprefixed token endpoint performs, restricted to the ones THIS ' +
          'authorization server advertises in grant_types_supported — and to the client ' +
          'authentication methods it advertises. Its tokens carry its own issuer and audience, ' +
          'so a conforming client that read its metadata finds them agreeing.' },
  { path: '/:as/oauth2/userinfo', group: 'OAuth 2.0 / OIDC',
    name: 'UserInfo endpoint (a named authorization server)', specs: ['oidc', 'rfc6750'],
    what: 'The same endpoint under a named authorization server\'s own path, which is what its ' +
          'OpenID Provider Configuration advertises.' },
  { path: '/:as/oauth2/introspect', group: 'OAuth 2.0 / OIDC',
    name: 'Introspection (a named authorization server)', specs: ['rfc7662'],
    what: 'The same honest active/inactive the unprefixed endpoint gives, under a named ' +
          'authorization server\'s own path. The REVOCATION SET is one set across every ' +
          'authorization server in this process, because a revoked token is revoked — so this ' +
          'reports inactive for a token revoked at any of them. That is deliberately unlike a ' +
          'credential, which does not cross between them: a code issued by one is refused at ' +
          'another\'s token endpoint.' },
  { path: '/:as/oauth2/revoke', group: 'OAuth 2.0 / OIDC',
    name: 'Revocation (a named authorization server)', specs: ['rfc7009'],
    what: 'Revocation that takes effect, under a named authorization server\'s own path: ' +
          'introspection then reports inactive, at every authorization server here and not ' +
          'only this one, for the reason given one row above. The console\'s revoke control ' +
          'writes to that same set — two sets would each look correct alone and never see ' +
          'each other.' },
  { path: '/:as/oauth2/register', group: 'OAuth 2.0 / OIDC',
    name: 'Registration (a named authorization server)', specs: ['rfc7591', 'rfc9700'],
    what: 'Registers a client, which may then use ANY authorization server here — nothing ' +
          'restricts a client to the one it registered at, and /admin/applications records ' +
          'which ones it has actually used.' },
  { path: '/:as/oauth2/logout', group: 'OAuth 2.0 / OIDC',
    name: 'Session end (a named authorization server)', specs: ['oidc', 'oidc-logout'],
    what: 'The session is ONE session across every authorization server in this process, ' +
          'because it is one browser and one cookie.' },
  { path: '/:as/oauth2/jwks', group: 'OAuth 2.0 / OIDC',
    name: 'JWKS (a named authorization server)', specs: ['rfc7515', 'rfc7519'],
    what: 'The same signing key. Every authorization server in this process signs with it, ' +
          'which is a property of the mock rather than of the model — they are separate ' +
          'issuers sharing one key, and a real deployment would not do that.' },
  { path: '/oauth2/rfc9700', group: 'OAuth 2.0 / OIDC',
    name: 'RFC 9700 mode report (not a spec endpoint)', specs: ['rfc9700'],
    what: 'NON-SPEC, because RFC 9700 defines no discovery member and no endpoint: a client has ' +
          'no way to learn from the protocol whether the server it is talking to enforces the ' +
          'Security BCP. So this says so, and says the uncomfortable half too — every requirement ' +
          'the mode has an opinion about, and whether it is ENFORCED, only DETECTED (the ones ' +
          'that are the client\'s to keep, which this server can see broken but cannot fix), ' +
          'ALWAYS true here, or NOT enforced with the reason attached. Read-only: the mode is ' +
          'the oauth2.rfc9700 setting, so it is turned on at /admin/config or through ' +
          'POST /admin-api/config like everything else configurable.' },
  { path: '/oauth2/userinfo', group: 'OAuth 2.0 / OIDC', name: 'UserInfo endpoint',
    specs: ['oidc', 'rfc6750', 'rfc9449', 'rfc7591', 'rfc8705', 'rfc8707'],
    effect: 'answers 401 with a WWW-Authenticate challenge when followed bare — it is a protected ' +
            'resource and needs the access token from an OIDC flow',
    what: 'THE SENDER CONSTRAINT AND THE AUDIENCE ARE CHECKED HERE and at the three credential ' +
          'endpoints, through the one function all four share: a DPoP-bound token gets its ' +
          'proof verified and replay-checked, a certificate-bound one gets the connection\'s ' +
          'certificate thumbprinted and compared, and a token issued for a DIFFERENT audience ' +
          '(RFC 8707 `resource`) is refused. OIDC Core section 5.3, on GET and POST. The ' +
          'claims about whoever the access token was ' +
          'issued for, gated by its scope (section 5.4) — which is the only place in this mock a ' +
          'scope changes the answer. THE ONE PROTECTED ENDPOINT HERE THAT REFUSES A TOKEN IT DID NOT ' +
          'ISSUE: it verifies the signature, the typ (so a refresh token or an id_token is refused), ' +
          'revocation and the openid scope, each with its own error. Bearer or DPoP-bound, through ' +
          'the same check the credential endpoints use. Returns application/jwt instead of JSON to a ' +
          'client that registered userinfo_signed_response_alg=RS256.' },
  { path: '/oauth2/introspect', group: 'OAuth 2.0 / OIDC', name: 'Introspection endpoint',
    specs: ['rfc7662'], what: 'Honest active/inactive with the presented token\'s claims.' },
  { path: '/oauth2/revoke', group: 'OAuth 2.0 / OIDC', name: 'Revocation endpoint',
    specs: ['rfc7009'], what: 'Revocation that takes effect: introspection then reports inactive.' },
  { path: '/oauth2/register', group: 'OAuth 2.0 / OIDC', name: 'Dynamic client registration',
    specs: ['rfc7591', 'rfc9700'],
    what: 'Registers a client and returns its credentials plus a registration access token. The ' +
          'registration IS the application entry under ou=applications — there is no second ' +
          'store — so /admin/applications and an ldapsearch see the same client. In RFC 9700 ' +
          'mode it REFUSES metadata the other endpoints would refuse in use: the password grant ' +
          '(section 2.4), the implicit grant and any response type naming token (2.1.2), and an ' +
          'http redirect URI off the loopback (2.6), each with invalid_client_metadata and the ' +
          'section. Recording a permission the token endpoint will always refuse is the ' +
          'discovery document\'s promise broken in the other direction.' },
  { path: '/oauth2/register/:client_id', group: 'OAuth 2.0 / OIDC',
    name: 'Registered client management', specs: ['rfc7592', 'rfc6750'],
    what: 'Read, update or delete a registered client, guarded by its registration access token.' },

  // --- OID4VCI ---
  { path: '/.well-known/openid-credential-issuer', group: 'VC Issuance (OID4VCI)',
    name: 'Credential Issuer Metadata', specs: ['oid4vci'],
    what: 'The credential configurations on offer, the endpoints, batch and encryption support, and ' +
          'this issuer\'s DID (issuer_did, an extension).' },
  { path: '/.well-known/openid-credential-issuer/*', group: 'VC Issuance (OID4VCI)',
    name: 'Credential Issuer Metadata (issuer with a path)', specs: ['oid4vci'],
    what: 'The same document where the Credential Issuer Identifier carries a path, which is what ' +
          'forces well-known path insertion.' },
  { path: '/.well-known/jwt-vc-issuer', group: 'VC Issuance (OID4VCI)',
    name: 'JWT VC Issuer Metadata', specs: ['sd-jwt-vc'],
    what: 'SD-JWT VC key resolution: the issuer identifier and its jwks_uri, plus issuer_did beside ' +
          'them as an extension.' },
  { path: '/.well-known/jwt-vc-issuer/*', group: 'VC Issuance (OID4VCI)',
    name: 'JWT VC Issuer Metadata (issuer with a path)', specs: ['sd-jwt-vc'],
    what: 'The same document, well-known path inserted before the issuer\'s path.' },
  { path: '/oid4vci/nonce', group: 'VC Issuance (OID4VCI)', name: 'Nonce endpoint',
    specs: ['oid4vci'], what: 'A fresh c_nonce for a proof of possession. Single use.' },
  { path: '/oid4vci/credential', group: 'VC Issuance (OID4VCI)', name: 'Credential endpoint',
    specs: ['oid4vci', 'sd-jwt', 'sd-jwt-vc', 'vcdm', 'di-bbs', 'rdf-c14n', 'rfc7800', 'rfc7515',
             'rfc6750'],
    what: 'Mints dc+sd-jwt, jwt_vc_json or ldp_vc per the configuration asked for. Verifies the ' +
          'wallet\'s proof, supports batch issuance, and accepts an encrypted request and/or returns ' +
          'an encrypted response.' },
  { path: '/oid4vci/deferred_credential', group: 'VC Issuance (OID4VCI)',
    name: 'Deferred credential endpoint', specs: ['oid4vci', 'rfc6750'],
    what: 'Collects a credential the issuer answered 202 for, against its transaction_id.' },
  { path: '/oid4vci/notification', group: 'VC Issuance (OID4VCI)', name: 'Notification endpoint',
    specs: ['oid4vci', 'rfc6750'], what: 'Section 11: the wallet reports what it did with the credential. ' +
                              'Validated and recorded.' },
  { path: '/oid4vci/notification/:id', group: 'VC Issuance (OID4VCI)',
    name: 'Notification readback (not a spec endpoint)', specs: [],
    what: 'NON-SPEC, for tests: what the wallet reported against a notification_id.' },
  { path: '/oid4vci/last_request', group: 'VC Issuance (OID4VCI)',
    name: 'Last Credential Request (not a spec endpoint)', specs: [],
    what: 'NON-SPEC, for tests: whether the last Credential Request arrived encrypted, and how.' },
  { path: '/oid4vci/credential-offer/:id', group: 'VC Issuance (OID4VCI)',
    name: 'Credential Offer by reference', specs: ['oid4vci'],
    what: 'Serves an offer fetched via credential_offer_uri.' },
  { path: '/issuer', group: 'VC Issuance (OID4VCI)', name: 'Issuer web page',
    specs: ['oid4vci'], what: 'Appendix H.1: where an End-User starts an issuer-initiated flow.' },
  { path: '/issuer/offer', group: 'VC Issuance (OID4VCI)', name: 'Build a Credential Offer',
    specs: ['oid4vci'], effect: 'mints an offer and redirects the browser to the wallet',
    what: 'Builds an offer and either sends the browser to the wallet or renders a QR code. ' +
          '?mode=cross-device (H.2) and ?mode=deferred (H.3) select the pre-authorized code grant ' +
          'with a Transaction Code.' },
  { path: '/bbs/keys/1', group: 'VC Issuance (OID4VCI)', name: 'BBS public key',
    specs: ['di-bbs'],
    what: 'The BLS12-381 key an ldp_vc proof is verified with, as a Multikey. This is what a plain ' +
          'ldp_vc credential\'s verificationMethod dereferences to.' },

  // --- DIDs ---
  { path: '/.well-known/did.json', group: 'Decentralized Identifiers',
    name: 'DID document (did:web)', specs: ['did-core'],
    what: 'This issuer as a did:web, with the RS256 key as a JsonWebKey2020 and the BBS key as a ' +
          'Multikey. The DID is derived from the request Host, so one container works at any address.' },
  { path: '/did/generate', group: 'Decentralized Identifiers',
    name: 'Generate a verifiable DID (not a spec endpoint)', specs: [],
    what: 'NON-SPEC, for tests and for trying the DID Tools page: ?method=jwk mints a fresh P-256 ' +
          'key and returns a did:jwk with a credential signed by it; ?method=web returns this ' +
          "service's own did:web with one signed by the RS256 key its document publishes. A DID " +
          'with nothing signed by it could only be parsed, not verified.' },
  { path: '/.well-known/did-configuration.json', group: 'Decentralized Identifiers',
    name: 'Domain Linkage Credential', specs: ['did-config', 'vcdm', 'rfc7519'],
    what: 'Proves this origin and this DID are the same entity. For did:web it is the only ' +
          'non-circular proof: resolving did:web:host means fetching host.' },

  // --- OID4VP ---
  { path: '/oid4vp/verifier', group: 'VC Presentation (OID4VP)', name: 'Verifier web page',
    specs: ['oid4vp'], what: 'Where a presentation starts: the verifier asks, the wallet answers.' },
  { path: '/oid4vp/start', group: 'VC Presentation (OID4VP)', name: 'Build an Authorization Request',
    specs: ['oid4vp'], effect: 'builds a request and redirects the browser to the wallet',
    what: 'response_type=vp_token with a DCQL query, a fresh nonce and response_mode=direct_post, ' +
          'passed by value or by reference, with a QR screen for cross-device.' },
  { path: '/oid4vp/request/:id', group: 'VC Presentation (OID4VP)', name: 'Request Object',
    specs: ['oid4vp', 'rfc7519'],
    what: 'The signed Request Object fetched via request_uri.' },
  { path: '/oid4vp/response', group: 'VC Presentation (OID4VP)', name: 'Response URI',
    specs: ['oid4vp', 'sd-jwt', 'sd-jwt-vc', 'di-bbs', 'rdf-c14n', 'vcdm'],
    what: 'Where the wallet POSTs the vp_token, and where it is really verified: issuer signature, ' +
          'every Disclosure digest against _sd, the Key Binding JWT including sd_hash, the validity ' +
          'window, and whether the claims asked for arrived.' },
  { path: '/oid4vp/result/:state', group: 'VC Presentation (OID4VP)',
    name: 'Verification verdict (not a spec endpoint)', specs: [],
    what: 'NON-SPEC, for the wallet\'s step 3 and for tests: the per-check verdict for a presentation.' },
  { path: '/oid4vp/done', group: 'VC Presentation (OID4VP)', name: 'Presentation complete page',
    specs: ['oid4vp'], what: 'Where the End-User lands after a cross-device presentation.' }
];

const SPEC_BY_ID = {};
SPECS.forEach(function (s) { SPEC_BY_ID[s.id] = s; });

// ---------------------------------------------------------------------------
// THE THIRTEEN PROTOCOL FAMILIES, AND WHY THIS LIST EXISTS AT ALL ON A PAGE
// WHOSE WHOLE DESIGN IS THAT IT DERIVES EVERYTHING.
//
// The tables below are the truth and they are unreadable as an ANSWER to the
// first question anybody brings here: what does this thing speak? Four hundred
// endpoint rows in fifteen groups, ordered by what the express router happened
// to be handed, do not add up to "Kerberos, and here is where it is" — and
// three of the families cannot be derived at all, because a family is only on
// the router if it is HTTP:
//
//   * SAML 2.0 and SAML 1.1 register NO ROUTE. The assertions are built by
//     saml/saml2.js and saml/saml11.js and travel inside somebody else's
//     envelope — a WS-Trust RSTR, a WS-Federation wresult — so a page built by
//     walking the router lists neither, and a reader would conclude this
//     service has no SAML in it.
//   * Kerberos, LDAP, PKI and SPIFFE each have their real surface on a RAW
//     SOCKET (port 88, 389 and 636, 8443 and 9443, and four gRPC listeners),
//     which the walk cannot see either. What it sees are the explanatory HTTP
//     views beside them.
//
// So this list is hand-written, and the three drift checks below are what keep
// a hand-written list on a derived page honest: a `groups` entry naming a group
// with no rows is reported, a `specs` entry naming a specification that does
// not exist is reported, and a group of rows that NO protocol claims is
// reported — which is the direction that catches the seventeenth family being
// added without a row here. `NON_PROTOCOL_GROUPS` is the whole of the excuse
// list, and it is four entries long on purpose.
//
// `sockets` is the sentence the table cannot say for itself: where the protocol
// actually lives when it does not live on the router.
// ---------------------------------------------------------------------------
const PROTOCOLS = [
  { name: 'OAuth2 / OIDC', groups: ['OAuth 2.0 / OIDC'],
    specs: ['rfc6749', 'oidc', 'rfc8414', 'rfc9700'],
    what: 'A mock authorization server and OpenID Provider: all five grants, ' +
          'PKCE, DPoP, introspection, revocation, dynamic registration, ' +
          'UserInfo and RP-initiated logout, with as many named ' +
          'authorization servers as have been asked for. RFC 9700 mode ' +
          'turns the BCP\'s refusals on.' },
  { name: 'Federation', groups: ['Federation'],
    specs: ['saml2-profiles', 'saml11-profiles', 'ws-federation', 'oidc', 'rfc6749'],
    what: 'BOTH ENDS OF A FEDERATION RELATIONSHIP, in five protocols: SAML ' +
          '2.0, SAML 1.1, WS-Federation 1.2, OpenID Connect and OAuth 2.0. As ' +
          'a SERVICE PROVIDER it consumes what a foreign identity provider ' +
          'issued, verifies it against a configured key, maps the attributes ' +
          'onto a directory entry and starts a session — the same session ' +
          'every other protocol here reads, which is what lets a federated ' +
          'identity satisfy an OAuth 2.0 authorization request or a SAML ' +
          'AuthnRequest without either of those knowing federation exists. As ' +
          'an IDENTITY PROVIDER it marks a partner as a federation partner ' +
          'rather than a test client and decides which attributes are ' +
          'released to it.\n\n**IT IS THE ONE FEATURE HERE THAT REFUSES BY ' +
          'DEFAULT AND HAS TO BE CONFIGURED BEFORE IT WILL DO ANYTHING**, and ' +
          'that is not an omission to fix: "accept any assertion" would not ' +
          'be a permissive mock of federation, it would be an authentication ' +
          'bypass for every protocol in this process. A relationship is ' +
          'created disabled, at /admin/federation or POST ' +
          '/admin-api/federation/create.' },
  { name: 'SAML 2.0', groups: ['SAML 2.0'],
    specs: ['saml2', 'saml2-bindings', 'saml2-profiles', 'saml2-metadata', 'xmldsig'],
    what: 'A full identity provider since 2026-08-24: the Web Browser SSO ' +
          'profile over all three bindings — HTTP Redirect and HTTP POST for ' +
          'the AuthnRequest, and HTTP POST, HTTP Redirect or HTTP Artifact for ' +
          'the Response, with a SOAP artifact resolution service behind the ' +
          'third — plus Single Logout and SIGNED METADATA PER SERVICE ' +
          'PROVIDER, minted for any entityID asked for. **This card used to ' +
          'say NO ROUTE OF ITS OWN**, and it was true for years: the ' +
          'assertions were built by saml/saml2.js and travelled inside ' +
          'somebody else\'s envelope. They still do — a WS-Trust RSTR and a ' +
          'WS-Federation wresult carry the same builder\'s output — and now ' +
          'there is a browser profile of their own beside it.',
    sockets: 'Also carried in a WS-Trust RSTR and in a WS-Federation wresult, ' +
             'which is where every SAML 2.0 assertion here went before this ' +
             'profile existed.' },
  { name: 'SAML 1.1', groups: ['SAML 1.1'],
    specs: ['saml11', 'saml11-bindings', 'saml11-profiles', 'xmldsig'],
    what: 'The same again in the older grammar (saml/saml11.js), because a ' +
          'WS-Federation relying party is as likely to want SAML 1.1 as 2.0 ' +
          'and an implementation that only ever tested the newer one has ' +
          'tested half of what it claims. **This card used to say it had no ' +
          'groups**, and it was true: the assertions travelled only inside ' +
          'somebody else\'s envelope. Since 2026-08-24 /saml11 is a ' +
          'browser-facing identity provider of its own — BOTH browser ' +
          'profiles, the SOAP responder behind the artifact one, and an ' +
          'attribute authority answering AttributeQuery and ' +
          'AuthenticationQuery. It is a SEPARATE implementation from the SAML ' +
          '2.0 profile rather than a mode of it, because SAML 1.1 has no ' +
          'request message, no Single Logout, and a different spelling for ' +
          'almost every element the two have in common.',
    sockets: 'Also carried in a WS-Federation wresult and in a WS-Trust RSTR, ' +
             'which is where every SAML 1.1 assertion here went before this ' +
             'profile existed.' },
  { name: 'WS-Federation', groups: ['WS-Federation'],
    specs: ['ws-federation', 'saml11', 'saml2'],
    what: 'The 1.2 Web (Passive) Requestor Profile: /wsfed dispatching on ' +
          'wa, the sign-in screen, signed federation metadata at the AD FS ' +
          'path, wsignout1.0, and a mock relying party that shows what was ' +
          'sent to it.' },
  { name: 'WS-Trust', groups: ['WS-Trust'],
    specs: ['ws-trust', 'wss-username', 'xmldsig'],
    what: 'RST / RSTR over SOAP at /sts, in all four versions (1.0 through ' +
          '1.4), issuing either SAML dialect with the assertion signed and ' +
          'optionally encrypted to the requestor\'s certificate.' },
  { name: 'Kerberos', groups: ['Kerberos'],
    specs: ['rfc4120', 'rfc3961', 'ms-pac', 'ms-kkdcp'],
    what: 'A mock KDC: AS-REQ / TGS-REQ, pre-authentication, four encryption ' +
          'types, a Microsoft PAC in the ticket, cross-realm referrals and ' +
          'constrained delegation. The rows on this page are its HTTP views ' +
          'and its MS-KKDCP proxy, which exists because a browser cannot ' +
          'open a socket.',
    sockets: 'The KDC itself is TCP and UDP port 88, which this page cannot ' +
             'see.' },
  { name: 'SPNEGO', groups: ['Kerberos'], specs: ['rfc4178', 'rfc4559'],
    what: 'Kerberos over HTTP: /spnego/protected answers 401 ' +
          'WWW-Authenticate: Negotiate, reads the NegTokenInit a browser or ' +
          'a client sends back, and accepts the AP-REQ inside it against the ' +
          'service principal\'s key.',
    sockets: 'The ticket it accepts comes from the KDC on port 88.' },
  { name: 'SPIFFE', groups: ['SPIFFE'],
    specs: ['spiffe-id', 'spiffe-bundle', 'spiffe-x509-svid',
            'spiffe-jwt-svid', 'spiffe-workload-api', 'spire-server-api'],
    what: 'One trust domain, its bundle endpoint, the SPIFFE Workload API ' +
          'and 36 of the 42 SPIRE Server API methods. The Workload API ' +
          'authenticates NOBODY — a workload has no root of trust until ' +
          'that call gives it one — and the SPIRE Server API\'s TCP port is ' +
          'mutual TLS with an X509-SVID.',
    sockets: 'Both gRPC surfaces are raw sockets: a Unix socket and a TCP ' +
             'port each. Only the bundle endpoint is on the router.' },
  { name: 'SCIM', groups: ['SCIM'],
    specs: ['rfc7642', 'rfc7643', 'rfc7644'],
    what: 'Provisioning, with no store of its own: a POST /scim/v2/Users and ' +
          'an ldapadd write the same directory entry, so a person created ' +
          'here signs in over every protocol above.' },
  { name: 'LDAP', groups: ['LDAP'],
    specs: ['rfc4511', 'rfc4512', 'rfc4513', 'rfc4514', 'rfc4515', 'rfc4519'],
    what: 'The embedded directory every other family reads: bind, search, ' +
          'add, modify, modifyDN, delete and compare, over the real ' +
          'protocol. The two rows on this page are this service describing ' +
          'its own store and are not LDAP at all.',
    sockets: 'BER over TCP 389, and TLS on 636. Neither is on the router.' },
  { name: 'PKI / X.509', groups: ['TLS'],
    specs: ['rfc5280', 'rfc8446'],
    what: 'The other end of a TLS and a MUTUAL-TLS connection, whose whole ' +
          'content is what the server saw of the handshake — which is the ' +
          'only way a client can find out what its certificate actually ' +
          'proved. The truststore is loaded over the plain port.',
    sockets: 'The listeners are HTTPS on 8443 and 9443 (and LDAPS 636), so ' +
             'this page sees only their plain-HTTP views.' },
  { name: 'WebAuthn / CTAP', groups: ['Authentication'], specs: ['webauthn'],
    what: 'A second factor on the sign-in screen every protocol here sends a ' +
          'person to: registration and assertion ceremonies against a real ' +
          'security key, with the attestation and the authenticator data ' +
          'checked rather than merely parsed.' },
  { name: 'Verifiable Credentials (OID4VCI / OID4VP)',
    groups: ['VC Issuance (OID4VCI)', 'VC Presentation (OID4VP)',
             'Decentralized Identifiers'],
    specs: ['oid4vci', 'oid4vp', 'sd-jwt-vc', 'vcdm', 'did-core'],
    what: 'Both sides of it: an issuer (three credential formats, Credential ' +
          'Offers, pre-authorized codes, deferred and batch issuance, ' +
          'notifications) and a verifier that checks a presentation properly ' +
          '— every disclosure digest, the key binding, and whether what was ' +
          'asked for arrived.' }
];

// Groups of endpoints that are NOT a protocol family, and so are not expected
// to be claimed by a row above. Four, and each is the service talking about
// itself rather than speaking to somebody: liveness and the RFC 8414 documents
// (Service), the operator console (Admin), the console over JSON (Management
// API), and whatever the router has that nobody has described yet
// (Undocumented) — that last one is already reported on its own.
const NON_PROTOCOL_GROUPS = ['Service', 'Admin', 'Management API',
                             'Undocumented'];

// A stable html id for a group heading, so the protocol list above can link
// into the table below it. Derived from the group name rather than typed
// beside it: a hand-kept id is one more thing to get out of step with the
// heading it names.
//
// No entering/leaving pair, like `esc()`, `groupsOf()` and `specLinks()` beside
// it: it is called once per group heading and once per protocol card while a
// page is being built, and a trace of the page is what the callers already log.
function groupAnchor(group) {
  return 'group-' + String(group).toLowerCase().replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

// The protocol list, joined to what is actually on the page: how many endpoint
// rows each family has here, and the three kinds of drift a hand-written list
// on a derived page can carry.
function protocolReport(rows) {
  log.debug("Entering protocolReport().");
  const countBy = {};
  rows.forEach(function (r) {
    countBy[r.group] = (countBy[r.group] || 0) + 1;
  });
  const claimed = {};
  const missingGroups = [];
  const missingSpecs = [];
  const list = PROTOCOLS.map(function (p) {
    let endpoints = 0;
    p.groups.forEach(function (group) {
      claimed[group] = true;
      if (!Object.prototype.hasOwnProperty.call(countBy, group)) {
        missingGroups.push(p.name + ' -> ' + group);
        return;
      }
      endpoints += countBy[group];
    });
    (p.specs || []).forEach(function (id) {
      if (!SPEC_BY_ID[id]) {
        missingSpecs.push(p.name + ' -> ' + id);
      }
    });
    return { name: p.name, what: p.what, sockets: p.sockets || '',
             groups: p.groups.slice(0), specs: (p.specs || []).slice(0),
             endpoints: endpoints };
  });
  // The direction that catches a new protocol family arriving with no row in
  // PROTOCOLS: a group of endpoints nobody claims and nothing excuses.
  const unclaimed = Object.keys(countBy).filter(function (group) {
    return !claimed[group] && NON_PROTOCOL_GROUPS.indexOf(group) === -1;
  });
  log.debug("Leaving protocolReport(). " + list.length + " protocol(s), " +
            missingGroups.length + " missing group(s), " + unclaimed.length +
            " unclaimed group(s).");
  return { protocols: list, missingGroups: missingGroups,
           missingSpecs: missingSpecs, unclaimedGroups: unclaimed };
}

// ---------------------------------------------------------------------------
// The router's own list of what is registered, grouped by path so the three
// methods on /oauth2/register/:client_id read as one endpoint.
//
// Express 4 keeps the routes on app._router.stack. It is a private member, which
// is worth a word: the alternative is a list maintained by hand, and this page
// exists precisely because that list cannot be trusted. If a future Express moves
// it, the tests fail loudly (the page reports every described path as stale)
// rather than quietly reporting nothing.
// ---------------------------------------------------------------------------
function registeredRoutes() {
  log.debug("Entering registeredRoutes().");
  const router = app._router || app.router;
  const stack = (router && router.stack) || [];
  const byPath = new Map();
  stack.forEach(function (layer) {
    if (!layer.route || !layer.route.path) return;
    const path = String(layer.route.path);
    const methods = Object.keys(layer.route.methods || {})
      .filter(function (m) { return m !== '_all'; })
      .map(function (m) { return m.toUpperCase(); });
    if (!byPath.has(path)) byPath.set(path, new Set());
    methods.forEach(function (m) { byPath.get(path).add(m); });
  });
  const out = [];
  byPath.forEach(function (methods, path) {
    out.push({ path: path, methods: Array.from(methods).sort() });
  });
  log.debug("Leaving registeredRoutes(). " + out.length + " path(s).");
  return out;
}

// Join the router's paths to their descriptions, and report both kinds of drift.
function describeEndpoints() {
  log.debug("Entering describeEndpoints().");
  const described = new Map();
  ENDPOINTS.forEach(function (e) { described.set(e.path, e); });

  const rows = [];
  const undocumented = [];
  registeredRoutes().forEach(function (route) {
    const entry = described.get(route.path);
    if (entry) {
      rows.push(Object.assign({}, entry, { methods: route.methods, documented: true }));
      described.delete(route.path);
      return;
    }
    undocumented.push(route.path);
    rows.push({ path: route.path, methods: route.methods, group: 'Undocumented',
                name: '(undocumented)', specs: [],
                what: 'This route is registered but sts_metadata.js does not describe it.',
                documented: false });
  });
  // Whatever is left was described and is not registered.
  const stale = Array.from(described.keys());
  // Any spec id that no entry references, and any reference to a spec that does
  // not exist. Both are drift in the same table.
  const referenced = new Set();
  rows.forEach(function (r) { (r.specs || []).forEach(function (id) { referenced.add(id); }); });
  const unknownSpecs = Array.from(referenced).filter(function (id) { return !SPEC_BY_ID[id]; });
  // The hand-written half of the page, checked against the derived half. See
  // the header above PROTOCOLS for the three kinds of drift this reports and
  // why a list that cannot be derived still has to be checked.
  const protocols = protocolReport(rows);
  log.debug("Leaving describeEndpoints(). " + rows.length + " row(s), " + undocumented.length +
            " undocumented, " + stale.length + " stale, " +
            protocols.protocols.length + " protocol(s).");
  return { rows: rows, undocumented: undocumented, stale: stale,
           unknownSpecs: unknownSpecs,
           protocols: protocols.protocols,
           unknownProtocolGroups: protocols.missingGroups,
           unknownProtocolSpecs: protocols.missingSpecs,
           unclaimedGroups: protocols.unclaimedGroups };
}

// 'Admin' sits last of the real groups, before 'Undocumented': it is the only group
// that is not a protocol, and a reader looking for what this service SPEAKS should
// not have to scroll past an operator console to find it.
// 'Authentication' sits directly after 'Service' and before every protocol: it is
// not one of them, it is the thing they all send a person to, and a reader who
// finds it under OAuth would reasonably conclude WS-Federation has a second one.
const GROUP_ORDER = ['Service', 'Authentication', 'WS-Trust', 'WS-Federation', 'OAuth 2.0 / OIDC',
                     'VC Issuance (OID4VCI)', 'Decentralized Identifiers', 'VC Presentation (OID4VP)',
                     'Admin', 'Management API', 'Undocumented'];

function groupsOf(rows) {
  const seen = [];
  GROUP_ORDER.forEach(function (g) {
    if (rows.some(function (r) { return r.group === g; })) seen.push(g);
  });
  rows.forEach(function (r) {
    if (seen.indexOf(r.group) === -1) seen.push(r.group);
  });
  return seen;
}

function esc(v) { return xmlEscape(v == null ? '' : String(v)); }

// ---------------------------------------------------------------------------
// Whether a path can be turned into a link a reader can actually follow.
//
// The temptation is to link all of them, and it produces a page with 22 dead
// links out of 41. A path is followable from a browser only if it answers a GET
// and is a concrete URL:
//
//   * no GET — a link on POST /oauth2/token issues a GET, and the router has no
//     GET for it, so the reader lands on Express's "Cannot GET /oauth2/token".
//     That reads as a broken service rather than as a wrong link.
//   * a parameter — "/oauth2/register/:client_id" is a route pattern. The literal
//     string with the colon in it is not an address of anything.
//   * a wildcard — same, and the concrete form of each of these is already listed
//     as its own row (the well-known documents), so nothing is lost.
//
// So the ones that work become links and the rest say why not. The reason is worth
// showing rather than hiding: "POST only" is the single most useful thing to know
// about an endpoint you were about to click.
function linkabilityOf(row) {
  log.debug("Entering linkabilityOf().");
  var methods = row.methods || [];
  if (methods.indexOf('GET') === -1) {
    log.debug("Leaving linkabilityOf().");
    return { linkable: false, reason: methods.length === 1 ? methods[0] + ' only'
                                                           : 'no GET (' + methods.join(', ') + ')' };
  }
  if (row.path.indexOf(':') !== -1) {
    var name = (/:([A-Za-z0-9_]+)/.exec(row.path) || [])[0] || 'a parameter';
    log.debug("Leaving linkabilityOf().");
    return { linkable: false, reason: 'takes ' + name };
  }
  if (row.path.indexOf('*') !== -1) {
    log.debug("Leaving linkabilityOf().");
    return { linkable: false, reason: 'wildcard' };
  }
  log.debug("Leaving linkabilityOf().");
  return { linkable: true, reason: '' };
}

// The path column: a link where that is honest, the bare path where it is not.
//
// Links are root-relative, so they follow the host this page was reached at —
// localhost:8081, sts:8081 on the compose network, or a published port — without
// this document having to know which. They open in a new tab so the index survives
// the click, which matters because most of these return a document to read and
// compare against the row it came from.
function pathCell(row) {
  var link = linkabilityOf(row);
  if (!link.linkable) {
    return '<code>' + esc(row.path) + '</code> <span class="why" title="' +
           'This path is listed because it is registered, but it cannot be followed from a browser.">' +
           esc(link.reason) + '</span>';
  }
  var title = 'GET ' + row.path + ' in a new tab' + (row.effect ? ' — ' + row.effect : '');
  return '<a href="' + esc(row.path) + '" target="_blank" rel="noopener noreferrer" title="' +
         esc(title) + '"><code>' + esc(row.path) + '</code></a>' +
         (row.effect ? ' <span class="eff" title="' + esc(row.effect) + '">&#8599;</span>' : '');
}

function specLinks(ids) {
  if (!ids || !ids.length) return '<span class="none">&mdash;</span>';
  return ids.map(function (id) {
    const spec = SPEC_BY_ID[id];
    if (!spec) return '<span class="bad">unknown spec id "' + esc(id) + '"</span>';
    return '<a href="#spec-' + esc(id) + '">' + esc(spec.name.split(' — ')[0].split(' (')[0]) + '</a>';
  }).join(', ');
}

// WHERE THIS PAGE'S DOCUMENT COMES FROM, SINCE IT IS NO LONGER FROM HERE.
//
// This function builds the BODY of a console page and nothing else — no
// doctype, no head, no <style>. `admin.respond()` wraps what comes back in
// `admin.page()`, which is the console's two columns, its sidebar, its
// breadcrumb, its gate banner and the ONE stylesheet it has. Two consequences
// worth stating because both were the temptation while writing this:
//
//   * **The classes used below live in admin.js.** `.lead`, `.m`, `.why`,
//     `.eff`, `.bad`, `.none`, `.protos` and `a.btn` are that file's, marked
//     there as this page's. A <style> block of this file's own would be markup
//     inside <body>, which browsers accept and no validator does — and there
//     would then be two stylesheets to keep in step.
//   * **Still no script, and that is not this page's choice.** The
//     Content-Security-Policy this service sets is `script-src 'none'`, so the
//     download control below is an `<a download>` rather than anything that
//     builds a blob.
function renderInner(base, report) {
  log.debug("Entering renderInner().");
  const rows = report.rows;

  let html = '<p class="lead">Every protocol this service speaks, every ' +
    'endpoint it registers and every specification it implements. The ' +
    'endpoint list is read from the running Express router on each request, ' +
    'not from a list kept by hand, so it cannot claim an endpoint that is ' +
    'not there or miss one that is. Issuer identifier <code>' + esc(base) +
    '</code>; WS-Trust issuer <code>' + esc(config.value('wstrust.issuer')) +
    '</code>; listening on port ' + esc(PORT) +
    // The scheme, said out loud, because the issuer above and every endpoint
    // below are built from the URL this request arrived on — so they follow the
    // socket by themselves, and a reader comparing this page against a
    // configuration file needs to know which socket that was. It is also the
    // one requirement RFC 9700 mode cannot settle with a check.
    (config.value('global.https')
      ? ' over <strong>HTTPS</strong> (global.https' +
        (config.value('oauth2.rfc9700')
          ? ', which RFC 9700 mode turns on — section 2.1 says an authorization ' +
            'response must not be sent over an unencrypted connection'
          : '') +
        '), with the same self-signed certificate ports 8443, 9443 and LDAPS ' +
        '636 serve. It is regenerated on every start, so fetch it from ' +
        '<code>/tls/server-certificate</code> and trust it — without ' +
        'verification the first time, since there is no plain port left to ' +
        'fetch it from.'
      : ' over plain HTTP.') + '</p>';

  // ---------------------------------------------------------------------
  // THE DOWNLOAD CONTROL, AT THE TOP BECAUSE IT IS ABOUT THE WHOLE PAGE.
  //
  // `download` on an anchor is the entire mechanism: the same URL the page
  // documents, asked for as an attachment. It is not a form and not a button,
  // for the reason in the header — nothing on this service may run a script,
  // so anything cleverer would be a control that did nothing. It carries the
  // session cookie because it is an ordinary same-origin GET, which is what
  // makes it work now that this page is behind the console's gate.
  // ---------------------------------------------------------------------
  html += '<p><a class="btn" href="/admin/sts-metadata?format=json" ' +
    'download="sts-metadata.json" title="The whole of this page as JSON: ' +
    'every protocol, every endpoint, every specification, and the drift ' +
    'report">Download all of this as JSON</a> <span class="why">' +
    esc(rows.length) + ' endpoints, ' + esc(report.protocols.length) +
    ' protocol families, ' + esc(SPECS.length) +
    ' specifications</span></p>';

  html += '<h2 id="protocols">Protocols this service speaks</h2>' +
    '<p class="lead">Thirteen families. The count on each card is how many ' +
    'rows that family has in the tables below, and it is not a measure of ' +
    'how much of the protocol is here: <strong>four of these live mostly ' +
    'on a raw socket and two register no route at all</strong>, and this ' +
    'page is built by walking the Express router. Where that is the case ' +
    'the card says where the protocol really is.</p>' +
    '<div class="protos">' +
    report.protocols.map(function (p) {
      const target = p.groups.length ? '#' + groupAnchor(p.groups[0]) : '';
      const title = target
        ? '<a href="' + esc(target) + '">' + esc(p.name) + '</a>'
        : '<span class="n">' + esc(p.name) + '</span>';
      const specs = specLinks(p.specs);
      return '<div class="proto">' + title +
        '<div class="d">' + esc(p.what) + '</div>' +
        (p.sockets ? '<div class="d"><em>' + esc(p.sockets) + '</em></div>'
                   : '') +
        '<div class="c">' +
        (p.endpoints
          ? esc(p.endpoints) + ' endpoint(s) below'
          : 'no endpoint of its own') +
        ' &middot; ' + specs + '</div></div>';
    }).join('') + '</div>';

  html += '<p class="lead"><strong>This is a test double.</strong> It signs ' +
    'everything with a key generated fresh at each start, it never checks a ' +
    'password, and it does not validate access tokens issued by a separate ' +
    'authorization server. The <em>coverage</em> column below says where ' +
    'each specification is implemented in full and where the shape is right ' +
    'but the enforcement is deliberately absent.</p>';

  // ---------------------------------------------------------------------
  // THE NAMED AUTHORIZATION SERVERS, which this page cannot read off the router.
  //
  // The same blind spot the Kerberos and LDAP listeners have, arrived at from
  // the other direction: those are sockets the walk cannot see, and these are
  // ONE route — `/:as/oauth2/…` — serving as many authorization servers as have
  // been asked for. A reader counting rows would conclude there is one
  // authorization server here, and there are as many as somebody has named.
  //
  // Only the ones that have actually been ACCESSED are listed, because the set
  // is unbounded by construction: a name becomes an authorization server by
  // being asked for, so listing "all of them" would mean listing every string.
  // What is here is what this process has actually served.
  // ---------------------------------------------------------------------
  const namedServers = authorizationServers.list().filter(function (one) {
    return one.id !== authorizationServers.DEFAULT_ID;
  });
  if (namedServers.length) {
    html += '<h2>Authorization servers</h2>' +
      '<p class="lead">This process publishes <strong>' + (namedServers.length + 1) +
      '</strong> authorization servers, and only the endpoint PATTERN is on the list below — ' +
      'the walk that builds this page sees <code>/:as/oauth2/…</code> as one route however ' +
      'many names have been served through it. Each has its own metadata, its own capabilities ' +
      'and its own issuer, and <strong>what its document advertises is what its endpoints ' +
      'do</strong>. A name that has never been asked for is not here: a name becomes an ' +
      'authorization server BY being asked for, with the same capabilities the default one ' +
      'has, so the set of possible ones is every string and the set of real ones is this.</p>' +
      '<table><thead><tr><th class="p">Authorization server</th><th>Metadata</th>' +
      '<th>Endpoints</th><th class="s">Asked for</th></tr></thead><tbody>' +
      '<tr><td><code>' + esc(authorizationServers.DEFAULT_ID) + '</code>' +
      '<div class="why">the unprefixed endpoints</div></td>' +
      '<td><a href="/.well-known/oauth-authorization-server" target="_blank" ' +
      'rel="noopener noreferrer"><code>/.well-known/oauth-authorization-server</code></a><br>' +
      '<a href="/.well-known/openid-configuration" target="_blank" rel="noopener noreferrer">' +
      '<code>/.well-known/openid-configuration</code></a></td>' +
      '<td><code>/oauth2/authorize</code><br><code>/oauth2/token</code></td>' +
      '<td>always</td></tr>' +
      namedServers.map(function (one) {
        return '<tr><td><code>' + esc(one.id) + '</code>' +
          (one.autoCreated
            ? '<div class="why">created by being asked for</div>'
            : '<div class="why">configured here</div>') + '</td>' +
          '<td><a href="' + esc(one.urls.oauth) + '" target="_blank" rel="noopener noreferrer">' +
          '<code>' + esc(one.urls.oauth) + '</code></a><br>' +
          '<a href="' + esc(one.urls.oidc) + '" target="_blank" rel="noopener noreferrer">' +
          '<code>' + esc(one.urls.oidc) + '</code></a></td>' +
          '<td><code>' + esc(one.urls.authorize) + '</code><br><code>' +
          esc(one.urls.token) + '</code></td>' +
          '<td>' + esc(one.seen) + ' time(s)</td></tr>';
      }).join('') +
      '</tbody></table>' +
      '<p class="lead"><a href="/admin/authorization-servers">Configure them</a> — what a ' +
      'profile publishes is what that authorization server enforces, so narrowing ' +
      '<code>code_challenge_methods_supported</code> there refuses the other method at that ' +
      'server\'s own authorization endpoint and nowhere else.</p>';
  }

  // Drift, if any. Shown at the top because it is the thing a reader most needs
  // to know about the rest of the page. Five kinds now rather than three: the
  // protocol list above is hand-written on a page that derives everything else,
  // so the checks that keep it honest report here beside the others.
  if (report.undocumented.length || report.stale.length ||
      report.unknownSpecs.length || report.unknownProtocolGroups.length ||
      report.unknownProtocolSpecs.length || report.unclaimedGroups.length) {
    // NOT FOLDED, AND IT IS THE ONE BLOCK ON THIS PAGE THAT IS NOT. Every
    // other paragraph here is prose a reader may skip; this one appears only
    // when the page disagrees with the router, which is the whole reason this
    // page exists (see the drift checks above). A report that has to be
    // clicked open to be read is a report somebody can close and forget. It
    // is also built across several statements rather than as one expression,
    // so it could not go through admin.warn() as it stands.
    html += '<div class="warn"><strong>This page is out of step with the router.</strong><ul>';
    if (report.undocumented.length) {
      html += '<li>Registered but not described here: ' +
        report.undocumented.map(function (p) { return '<code>' + esc(p) + '</code>'; }).join(', ') +
        '. They are listed below under <em>Undocumented</em>.</li>';
    }
    if (report.stale.length) {
      html += '<li>Described here but NOT registered: ' +
        report.stale.map(function (p) { return '<code>' + esc(p) + '</code>'; }).join(', ') +
        '. Either the route was renamed or the description is stale.</li>';
    }
    if (report.unknownSpecs.length) {
      html += '<li>Endpoints reference specification ids that do not exist: ' +
        report.unknownSpecs.map(function (i) { return '<code>' + esc(i) + '</code>'; }).join(', ') +
        '.</li>';
    }
    if (report.unknownProtocolGroups.length) {
      html += '<li>The protocol list names endpoint groups that have no ' +
        'rows: ' +
        report.unknownProtocolGroups.map(function (i) {
          return '<code>' + esc(i) + '</code>';
        }).join(', ') + '. Either the group was renamed or the family is ' +
        'gone.</li>';
    }
    if (report.unknownProtocolSpecs.length) {
      html += '<li>The protocol list references specification ids that do ' +
        'not exist: ' +
        report.unknownProtocolSpecs.map(function (i) {
          return '<code>' + esc(i) + '</code>';
        }).join(', ') + '.</li>';
    }
    if (report.unclaimedGroups.length) {
      html += '<li>These endpoint groups are on the page and no protocol ' +
        'above claims them: ' +
        report.unclaimedGroups.map(function (i) {
          return '<code>' + esc(i) + '</code>';
        }).join(', ') + '. A family was added to this service and not to the ' +
        'list at the top of this page.</li>';
    }
    html += '</ul></div>';
  } else {
    html += '<div class="ok">Every registered route is described, every ' +
      'description matches a registered route (' + rows.length +
      ' endpoints), and every one of the ' + report.protocols.length +
      ' protocol families above names a group that is here and a ' +
      'specification that exists.</div>';
  }

  groupsOf(rows).forEach(function (group) {
    html += '<h2 id="' + esc(groupAnchor(group)) + '">' + esc(group) +
      '</h2><table><thead><tr><th class="p">Path</th>' +
      '<th>Methods</th><th class="n">Name</th><th>What it is</th><th class="s">Specifications</th>' +
      '</tr></thead><tbody>';
    rows.filter(function (r) { return r.group === group; })
      .sort(function (a, b) { return a.path < b.path ? -1 : (a.path > b.path ? 1 : 0); })
      .forEach(function (r) {
        html += '<tr><td class="p">' + pathCell(r) + '</td>' +
          '<td class="m">' + esc(r.methods.join(', ')) + '</td>' +
          '<td class="n">' + (r.documented === false ? '<span class="bad">' + esc(r.name) + '</span>'
                                                     : esc(r.name)) + '</td>' +
          // WHAT AN ENDPOINT IS, FOLDED. This table is every route the router
          // has — around 250 of them — and this column is a paragraph on most
          // rows, which made the one page in this console that lists
          // everything the one page nobody could skim. admin.note() leaves a
          // short description alone and folds a long one behind its first
          // sentence; see the block above it in ../admin-ui/admin.js.
          '<td>' + admin.note(esc(r.what)) + '</td>' +
          '<td class="s">' + specLinks(r.specs) + '</td></tr>';
      });
    html += '</tbody></table>';
  });

  html += '<h2 id="specifications">Specifications implemented</h2>' +
    '<table><thead><tr><th class="n">Specification</th>' +
    '<th>Published by</th><th>Coverage in this mock</th></tr></thead><tbody>';
  SPECS.forEach(function (s) {
    html += '<tr id="spec-' + esc(s.id) + '"><td class="n"><a href="' + esc(s.url) +
      '" target="_blank" rel="noopener noreferrer">' + esc(s.name) + '</a></td>' +
      '<td>' + esc(s.where) + '</td><td>' + admin.note(esc(s.coverage)) +
      '</td></tr>';
  });
  html += '</tbody></table>';

  html += admin.note('Machine-readable: <code>' + esc(base) +
    '/admin/sts-metadata?format=json</code>, which is what the button at ' +
    'the top hands you as a file. It is behind the console gate like the ' +
    'page, so a program fetching it signs in at <code>/authn/login</code> ' +
    'first, or ' +
    'reads the same service through <code>/admin-api</code>, which is not ' +
    'gated. This document is not a specification-defined discovery ' +
    'document &mdash; for those, see <code>/.well-known/openid-configuration</code>, ' +
    '<code>/.well-known/oauth-authorization-server</code>, ' +
    '<code>/.well-known/openid-credential-issuer</code>, <code>/.well-known/jwt-vc-issuer</code>, ' +
    '<code>/.well-known/did.json</code> and ' +
    '<code>/.well-known/did-configuration.json</code>.');
  log.debug("Leaving renderInner(). " + html.length + " characters.");
  return html;
}

function metadataJson(base, report) {
  log.debug("Entering metadataJson().");
  log.debug("Leaving metadataJson().");
  return {
    service: 'idptools mock Security Token Service',
    issuer: base,
    wsTrustIssuer: config.value('wstrust.issuer'),
    port: PORT,
    testDouble: true,
    endpoints: report.rows.map(function (r) {
      var link = linkabilityOf(r);
      return { path: r.path, methods: r.methods, name: r.name, group: r.group,
               description: r.what, specs: r.specs, documented: r.documented !== false,
               // Whether the path can be followed from a browser, and the absolute
               // URL when it can. Reported rather than left for a client to work
               // out, because getting it wrong is what produces a dead link.
               linkable: link.linkable,
               notLinkableBecause: link.linkable ? undefined : link.reason,
               url: link.linkable ? base + r.path : undefined,
               effect: r.effect };
    }),
    specifications: SPECS,
    // The protocol list, with the endpoint count each family actually has on
    // this page. It is in the document rather than only on the page for the
    // reason everything else here is: a test can then assert that this service
    // still speaks the thirteen it claims to, which is not a question the
    // endpoint list answers — two of the thirteen register no route at all.
    protocols: report.protocols,
    // The drift report is part of the document, not just the page: a test asserts
    // these are empty, which is the only thing that keeps the descriptions honest.
    undocumentedPaths: report.undocumented,
    stalePaths: report.stale,
    unknownSpecIds: report.unknownSpecs,
    // The same, for the hand-written half. `unclaimedGroups` is the one that
    // catches the direction nothing else can: a protocol family added to this
    // service and not to the list at the top of the page.
    unknownProtocolGroups: report.unknownProtocolGroups,
    unknownProtocolSpecIds: report.unknownProtocolSpecs,
    unclaimedGroups: report.unclaimedGroups
  };
}

// ---------------------------------------------------------------------------
// THE PAGE. It is `/admin/sts-metadata` and it is REGISTERED HERE rather than
// in admin.js, which is the arrangement two rules of this service leave
// standing: this module is required LAST by server.js so that it is never the
// reason a route is missing from its own list, and admin.js must not require it
// back (that would drag every console route behind the last module in the
// file). What it borrows is the shell — see the header.
//
// The gate above it is admin.js's one `app.use('/admin', ...)`, which express
// applies to routes registered after it. Nothing here repeats that check: a
// second opinion about who may read this page is a second thing to get wrong.
//
// `admin.respond()` answers `?format=json` itself, which keeps the machine
// -readable form byte-for-byte the shape every other console page's is —
// 200, `Cache-Control: no-store`, and the JSON this file builds.
// ---------------------------------------------------------------------------
app.get('/admin/sts-metadata', function (req, res) {
  log.debug("Entering the STS metadata endpoint.");
  const base = baseUrlOf(req);
  const report = describeEndpoints();
  admin.respond(req, res, metadataJson(base, report), 'Service metadata',
                '/admin/sts-metadata', renderInner(base, report));
  log.debug("Leaving the STS metadata endpoint. " + report.rows.length +
            " endpoints, " + report.protocols.length + " protocol families.");
});

module.exports = {
  SPECS: SPECS,
  PROTOCOLS: PROTOCOLS,
  ENDPOINTS: ENDPOINTS,
  registeredRoutes: registeredRoutes,
  describeEndpoints: describeEndpoints
};
