'use strict';
//
// File: server.js
//
//
// WS-Trust 1.4 STS mock.
//
// A deliberately small, dependency-light Security Token Service that speaks
// enough WS-Trust to exercise the OAuth2/OIDC Debugger's WS-Trust workflow end
// to end in the test suite. It accepts a SOAP RequestSecurityToken (RST) and
// dispatches on wst:RequestType:
//
//   Issue    -> RSTR Collection with a freshly minted, STS-signed SAML 2.0
//               assertion (or a JWT / plain UsernameToken echo, per TokenType),
//               a Lifetime, and an attached reference.
//   Renew    -> RSTR with a fresh token for the supplied RenewTarget.
//   Validate -> RSTR with wst:Status/wst:Code valid|invalid.
//   Cancel   -> RSTR with wst:RequestedTokenCancelled.
//
// Authentication: a WS-Security UsernameToken is accepted when username and
// password are both present (and the password is not the literal "invalid",
// which lets a negative test force an auth failure). A request carrying an
// OnBehalfOf/ActAs token (delegation) is also accepted. This is a TEST STS —
// it does not verify request signatures or enforce real policy.
//
// The project's real intent is to run against Apache CXF's WS-Trust STS; this
// mock is the CI fallback (see the plan / README) and the app can target either.
//
// Config via env:
//   CONFIG_FILE  the configuration module to load, chosen the same way as for the
//                api and client services (e.g. ./env/local.js). It supplies
//                EVERY setting this service has — env/docker-tests.js is what
//                the containerized test stack uses.
//
// The sixty-five settings themselves are not listed here any more, because a
// list in a comment is a list that goes stale: `config.js` is the table, and it
// carries each setting's name, its environment variable, its default, what it
// does, and whether changing it while the service runs does anything.
// /admin/config renders that table with the effective value of each and where
// it came from, and `GET /admin-api/config` answers the same thing over JSON.
//
// An ENVIRONMENT VARIABLE STILL BEATS THE FILE, which is what keeps every
// container and test that set one working unchanged: STS_PORT, STS_ISSUER,
// KRB5_REALM and the rest all still do exactly what they did. STS_ISSUER is the
// one that grew: it was a single value serving as the SAML assertion issuer,
// the WS-Trust token issuer and the WS-Federation entityID, which are three
// different things that shared a default. They are now saml.issuer,
// wstrust.issuer and wsfed.entityId, all three still fed by STS_ISSUER when it
// is set.
//
// Logging: everything this mock does is written to the log at DEBUG level — every
// endpoint call (path, request headers and body, response headers and body,
// status code and elapsed time), and every SAML assertion, JWT and SD-JWT VC both
// BEFORE and AFTER it was signed or encrypted. Drop the level to info (see
// env/test.js) for a quiet run.
//
// ---------------------------------------------------------------------------
// This file is now the SHELL only: it loads the modules and listens. It used to be
// all 4,489 lines of the service, which is why the split happened — eight protocol
// families in one file meant no way to see what was in it short of reading it.
//
//   helpers.js       the log, the keys, and the helpers more than one protocol needs
//   app.js           the express app and every middleware, which must be installed
//                    before any route module loads
//   saml2.js         SAML 2.0 assertions: build, sign, encrypt
//   saml11.js        SAML 1.1 assertions, which is what WS-Federation RPs expect
//   wstrust.js       WS-Trust 1.4 RST/RSTR and the /sts endpoints
//   oauth2.js        RFC 8414 metadata, JWKS, and the mock authorization server
//   wsfed.js         WS-Federation 1.2 passive requestor: /wsfed, its metadata,
//                    and a mock relying party to verify what it sends
//   vc_configs.js    the credential configurations this issuer offers
//   vc_offers.js     Credential Offers, pre-authorized codes, deferred state
//   vc_did.js        the did:web document and the DIF domain linkage credential
//   vc_issuer.js     OID4VCI: metadata, proofs, the three credential formats
//   vc_verifier.js   OID4VP: the request, and verifying what comes back
//   sts_metadata.js  GET /admin/sts-metadata — every endpoint and spec, listed
//
// **Requiring a module registers its endpoints.** Each one does `app.get(...)` at
// its top level against the shared app from app.js, rather than exporting a
// register() function — which kept every handler exactly where it was written
// instead of re-indented inside a wrapper. So the order below is the route
// order. Nothing here has overlapping paths, so it does not currently matter, but
// a module registering a wildcard would care a great deal. sts_metadata.js is last
// on purpose: it reads the router to list what everything else registered, and
// while it re-reads it per request, being last means it is never the reason a
// route is missing.
// ---------------------------------------------------------------------------

// FIRST, and before any module that reads the appconfig file. Every module now
// lives in a subdirectory, so a relative CONFIG_FILE — `./env/local.js`, which
// is what the documented invocation and the Dockerfile's ENV both say — no
// longer resolves against the package root from where those modules sit. This
// makes it absolute once, in place, so all fourteen direct readers agree. See
// common/config_file.js.
require('./common/config_file').resolveConfigFile();

const https = require('https');
const app = require('./common/app');
const { log, PORT, HOST } = require('./common/helpers');
const config = require('./common/config');

// Which LDAP attributes the four claim sets carry. A LIBRARY — it registers no
// route, so this line adds nothing to /admin/sts-metadata and its position in
// the route order is not a position at all. It is required HERE, ahead of the
// modules that issue, because requiring it is what fills admin_stats.js's
// attribute-resolver slot, and an empty slot means tokens issued without their
// configured attributes. admin.js requires it too, which would be enough today
// by accident; this line is what makes it true on purpose, and what keeps it
// true for a process that loads the protocol modules without the console.
require('./common/claim_attributes');

// The groups claim: for anybody who is a member of a group in the embedded
// directory, a claim naming those groups in every access token, ID Token and
// both SAML assertions. A LIBRARY too, required HERE for exactly the reason the
// line above is: requiring it is what fills admin_stats.js's group-resolver
// slot, and an empty slot means tokens issued without the claim with nothing
// looking wrong. It must come before the modules that issue; the directory it
// reads arrives later, through its own slot, and until then it simply reports
// that no directory is loaded.
require('./common/group_claims');

require('./ws-trust/wstrust');
// The authentication service: the sign-in screen every protocol here sends a
// person to, and the session store it fills. FIRST of the modules that use it,
// because require order is route order on the /admin/sts-metadata page and the
// thing that authenticates should be listed before the protocols that lean on
// it.
require('./authn/authn');
require('./oauth-oidc/oauth2');
// WS-Federation's passive requestor profile. It must come AFTER authn.js and the
// order is a dependency and not a preference: it signs users in to the session
// that service owns (startSession/sessionOf), so that single sign-on works across
// the two protocols. The dependency is one-way — authn.js knows nothing about
// this module — which is what keeps it out of the cycles the split exists to
// avoid.
require('./ws-federation/wsfed');
require('./oid4vc/vc_offers');
require('./oid4vc/vc_did');
require('./oid4vc/vc_issuer');
require('./oid4vc/vc_verifier');
// The Kerberos KDC. Requiring it registers /KdcProxy and /krb5/principals like
// every other module here — but NOT the raw TCP/UDP listeners on port 88, which
// are started by krb5.listen() below. Binding a privileged port can fail, and a
// require that throws takes the whole service down; a route cannot.
const krb5 = require('./kerberos/krb5_kdc');
// The Kerberos-protected service. Like the KDC it registers its HTTP view at
// require time and starts its socket from listen(), for the same reason.
const krb5Service = require('./kerberos/krb5_service');
// The same acceptor over HTTP: SPNEGO. It must come AFTER krb5_service.js and
// the order is a dependency rather than a preference — it calls that module's
// accept() for every Kerberos check and adds none of its own. Unlike the two
// above it starts nothing: it is HTTP all the way down, so requiring it is the
// whole of its installation.
require('./kerberos/spnego');
// The admin console. It must come AFTER oauth2.js and, like wsfed.js, the order is a
// dependency rather than a preference: its metrics page reports the browser sign-on
// sessions oauth2.js owns, read through the `sessions` map that module exports. The
// dependency is one way — oauth2.js knows nothing about the console — so it is not a
// cycle. What holds the STATE it renders is admin_stats.js, which registers no route
// and is required by app.js, so the counting is already running by the time this
// line is reached.
require('./admin-ui/admin');
// The management API: everything that console shows and everything it can
// change, at /admin-api, over JSON. It must come AFTER admin.js and the order is
// a dependency rather than a preference — it requires that module for the four
// action functions and the per-page JSON views, and calls nothing else, which is
// what makes it incapable of holding a second opinion about what a revocation
// means. Its OpenAPI document is built from its own route table (admin_api.js ->
// admin_api_spec.js), so an operation cannot be undocumented; the explorer that
// calls it is at /admin-api/docs and is the ONE page in this service with a
// script on it, served under a policy that relaxes exactly that clause.
require('./mgmt-api/admin_api');
// The TLS / mutual-TLS endpoint. Third in the family of modules whose real
// surface is a SOCKET rather than a route: it registers its plain-HTTP views
// (/tls, /tls/server-certificate, /tls/trust) at require time and starts two
// HTTPS listeners from listen() below, for the same reason the KDC and the
// directory do — a bind can fail, and a require that throws takes the whole
// service down where a route cannot.
//
// Its position used to be free. It is not any more: ldap_server.js below serves
// this module's server certificate on 636, so it requires this file — and node
// would load it here whatever this line said. Saying it explicitly is what
// keeps "the order in this file is the route order" true.
const tlsServer = require('./tls/tls_server');
// The embedded LDAPv3 directory (RFC 4511), built on the node-ldapjs submodule.
// Like the two Kerberos modules it registers its HTTP views at require time
// (/ldap, /ldap/directory) and starts its TCP listener from listen() below, for
// the same reason: binding port 389 is privileged and can fail, and a require
// that throws takes the whole service down where a route cannot.
//
// It must come AFTER admin.js, and that is a dependency rather than a
// preference: it installs itself as admin_stats.js's user observer, which is how
// an entry appears under ou=users for anybody who authenticates through ANY
// protocol here. Requiring it earlier would work too — nothing authenticates
// during require — but keeping it beside the console is what makes the pairing
// visible to the next reader.
//
// It must also come after ./tls_server below, and THAT one is not optional: its
// LDAPS listener on 636 serves the certificate and key that module generates,
// so requiring it first is what makes the route order in this file the real one
// rather than a fiction node quietly corrects.
const ldapServer = require('./ldap/ldap_server');
// SCIM 2.0 (RFC 7642, 7643, 7644) — the fifteenth family, and the one whose
// whole purpose is to WRITE. It provisions into the directory above, entry for
// entry, with no store of its own: a POST /scim/v2/Users and an ldapadd write
// the same entry, so a person provisioned over SCIM appears on /admin/users,
// carries the credential-claim attributes /admin/vc selects, and lands in
// whatever group a client puts them in.
//
// It must come AFTER ./ldap_server, and that is a dependency rather than a
// preference: it requires that module for the twelve functions that make
// ou=users and ou=groups a store, and requiring it any earlier would pull every
// /ldap route into the express router at that point. It is NOT one of that
// file's five inverted hooks — there is no cycle and no route moves, which is
// rule 3e's test, and this proposal fails it both ways round, so it is a plain
// require.
//
// Unlike the four modules above it, it starts nothing: it is HTTP all the way
// down, so requiring it is the whole of its installation.
require('./scim/scim');
// SPIFFE — the sixteenth family, and the third module here whose own listeners
// are started from listen() below rather than at require time.
//
// Three server-side surfaces: the BUNDLE ENDPOINT (plain HTTPS, registered by
// requiring this), the WORKLOAD API and the SPIRE SERVER API (both gRPC, on a
// Unix socket and a TCP port each). The gRPC listeners are invisible to
// /admin/sts-metadata for the same reason the KDC's, the directory's and the
// TLS endpoint's sockets are, so they are described by hand there.
//
// It must come AFTER ./ldap_server, and it is a dependency rather than a
// preference: the SPIFFE registry's store is the directory under ou=spiffe, and
// that module fills spiffe_registry.js's setDirectory() slot at ITS require
// time. Requiring this any earlier would leave the registry with no store at
// the moment the seed entries are written.
//
// The 8443/9443/636/8081 certificate is NOT shared with this. A SPIFFE trust
// domain is its own PKI — the CA here signs identities in one trust domain and
// the TLS certificate identifies a host — and one process holding two of them
// is correct rather than wasteful. See spiffe_ca.js.
const spiffeServer = require('./spiffe/spiffe_server');
require('./sts_metadata');

// ---------------------------------------------------------------------------
// THE MAIN LISTENER, and the one decision made about it before it binds.
//
// `global.https` — whose default is `oauth2.rfc9700`, so RFC 9700 mode brings
// it with it — makes this an HTTPS listener instead of a plain one. It is not a
// fourth certificate: `tls_server.js` generates ONE self-signed pair per start
// and 8443, 9443 and the directory's LDAPS 636 already serve it, so a caller
// trusts this service once rather than four times. That module has been
// required above by the time this runs, which is what makes the key available
// here without moving anything in the require order.
//
// Two things follow and neither is hidden.
//
// **There is then no plain listener in this process at all.** `POST /tls/trust`
// and `GET /tls/server-certificate` are on this port on purpose — they are what
// a caller reaches BEFORE it trusts anything — so with HTTPS on, the first
// fetch of the certificate has to be made without verifying it (`curl -k`).
// That is the ordinary bootstrap for a service whose certificate is regenerated
// every start, and it is said here, on /tls, and in the startup line below
// rather than left to be discovered as a handshake failure.
//
// **The scheme every document here advertises follows the socket by itself.**
// `baseUrlOf()` builds every issuer, endpoint and metadata URL from
// `req.protocol` and the Host header, which is what already makes one process
// answer correctly as localhost, as sts on a compose network and through a
// published port. An https.Server sets `req.protocol` to https, so the RFC 8414
// document, the OpenID Provider Configuration, the OID4VCI and OID4VP metadata,
// the federation metadata and the DID document all move together and none of
// them had to be told. Do not "fix" this by pinning a scheme anywhere: a
// hardcoded https is wrong on the default plain listener, and a document whose
// endpoints disagree with the port they were fetched from is the failure this
// derivation exists to prevent.
// ---------------------------------------------------------------------------
const useHttps = config.value('global.https');

function announce() {
  log.info('WS-Trust STS mock listening on ' + (useHttps ? 'https' : 'http') +
           '://' + HOST + ':' + PORT +
           ' (WS-Trust issuer ' + config.value('wstrust.issuer') +
           '); POST SOAP RST to /sts');
  if (useHttps) {
    log.info('This port is HTTPS (global.https' +
             (config.value('oauth2.rfc9700') ? ', which RFC 9700 mode turned on' : '') +
             '), served with the same self-signed certificate 8443, 9443 and ' +
             'LDAPS 636 use. It is regenerated on every start, so fetch it ' +
             'from /tls/server-certificate and trust it — and fetch it WITHOUT ' +
             'verification the first time (curl -k), because with this on ' +
             'there is no plain port left to fetch it from.');
    log.info('It also ASKS for a client certificate and never requires one ' +
             '(RFC 8705): a Token Request made with one gets an access token ' +
             'bound to it — cnf["x5t#S256"] — which the protected endpoints ' +
             'then check. A request with none is unaffected.');
  }
  log.info('RFC 8414 metadata at /.well-known/oauth-authorization-server; ' +
           'OpenID Provider Configuration at /.well-known/openid-configuration; JWKS at /oauth2/jwks');
  log.info('OID4VCI issuer metadata at /.well-known/openid-credential-issuer; ' +
           'credential endpoint at /oid4vci/credential');
  log.info('Issuer-initiated (OID4VCI H.1): the issuer web page is at /issuer; ' +
           'it builds a Credential Offer and sends the browser to the wallet.');
  log.info('Authentication service at /authn/login (the sign-in screen every protocol here sends ' +
           'a person to) and /authn/webauthn (its second factor).');
  log.info('Mock authorization server endpoints: /oauth2/authorize (redirects to /authn/login when ' +
           'there is no session), /oauth2/token, /oauth2/userinfo, /oauth2/introspect, ' +
           '/oauth2/revoke, /oauth2/register, /oauth2/logout');
  log.info('WS-Federation passive requestor at /wsfed (wsignin1.0 / wsignout1.0); metadata at ' +
           '/FederationMetadata/2007-06/FederationMetadata.xml; a mock relying party that verifies ' +
           'the sign-in response is at /wsfed/rp.');
  log.info('Every endpoint call, and every token or assertion before and after it was signed, ' +
           'is written to this log at debug level.');
  log.info('A SPNEGO-protected page (RFC 4559 over RFC 4178) is advertised at /spnego and ' +
           'lives at /spnego/protected; ?mic=require, ?mech=none and ?mutual=off make the ' +
           'negotiation fail in one specific way each.');
  log.info('Every protocol, every endpoint and every specification this ' +
           'service implements is listed at /admin/sts-metadata (add ' +
           '?format=json for the machine-readable form, or use the Download ' +
           'button on the page). It is a console page, so it is behind ' +
           'admin.authRequired like the rest of /admin; it was at ' +
           '/sts-metadata until 2026-08-24.');
  log.info('The management API is at /admin-api — every /admin control over JSON, with ' +
           'its OpenAPI 3.1 document at /admin-api/openapi.json and an explorer that ' +
           'calls it at /admin-api/docs. It is NOT protected either.');
  log.info('The admin console is at /admin: /admin/metrics counts every call, token, assertion, ' +
           'ticket and session; /admin/tokens lists every JWT, SAML assertion and Kerberos ticket ' +
           'issued and invalidates access tokens, ID Tokens and refresh tokens (only those three ' +
           'can be); /admin/claims adds custom claims to future tokens and /admin/saml-attributes ' +
           'to future assertions. It is NOT ' +
           'protected — nothing in this service is — so do not put this port on a public address.');
  // The KDC's sockets are started here rather than at require time so that a
  // failure to bind (port 88 is privileged) is reported by a running service
  // instead of preventing it from starting at all. GET /krb5/principals says what
  // this KDC knows; GET /admin/sts-metadata cannot see a raw socket, so the
  // listener has its own entry there.
  const kdcListeners = krb5.listen();
  kdcListeners.whenReady.then(function (ready) {
    log.info('krb5: the KDC is reachable on TCP and UDP ' + ready.port + '; MS-KKDCP at /KdcProxy; ' +
             'GET /krb5/principals lists what it knows.');
  }).catch(function (err) {
    // Reported rather than thrown: the rest of this service is still useful, and a
    // silent failure to bind would surface later as a KDC that never answers.
    log.error('krb5: the KDC could not start: ' + err.message);
  });
  krb5Service.listen();
  // The LDAP directory's socket, started here for the same reason the KDC's is.
  // GET /ldap says what it is and GET /ldap/directory shows every entry in it;
  // GET /admin/sts-metadata cannot see a raw socket, so the listener has its
  // own entry there beside the KDC's.
  const ldapListener = ldapServer.listen();
  ldapListener.whenReady.then(function (ready) {
    log.info('ldap: the directory is reachable on TCP ' + ready.port +
             ' with base DN ' + ready.baseDn + (ready.ldapsListening
               ? ', and over LDAPS on ' + ready.ldapsPort + ' with the same ' +
                 'certificate the HTTPS listeners serve (fetch it from ' +
                 '/tls/server-certificate and trust it; it is regenerated on ' +
                 'every start)'
               : ', and NOT over LDAPS — ' + (ready.ldapsError ||
                 'it never bound') + ', which leaves the plain listener and ' +
                 'the rest of this service untouched') +
             '. Every bind succeeds except the password "invalid"; GET /ldap ' +
             'describes it and GET /ldap/directory lists every entry.');
  }).catch(function (err) {
    // Reported rather than thrown, exactly as the KDC's failure is: the rest of
    // this service is still useful, and a silent failure to bind would surface
    // later as a directory that never answers.
    log.error('ldap: the directory could not start: ' + err.message);
  });
  // The two HTTPS listeners, started here for the same reason the other two
  // sockets are. GET /tls describes them and hands out the server certificate;
  // GET /admin/sts-metadata cannot see a socket, so they are described by hand
  // there beside the KDC's and the directory's.
  // The two gRPC listeners, started here for the reason the other four sockets
  // are. GET /spiffe describes all three surfaces and reports whether each
  // socket bound; GET /admin/sts-metadata cannot see one, so they are described
  // by hand there beside the KDC's, the directory's and the TLS endpoint's.
  const spiffeListeners = spiffeServer.listen();
  spiffeListeners.whenReady.then(function (ready) {
    const up = ready.workload.concat(ready.api)
      .filter(function (b) { return b.listening; });
    const down = ready.workload.concat(ready.api)
      .filter(function (b) { return !b.listening; });
    log.info('spiffe: the trust domain ' + config.value('spiffe.trustDomain') +
             ' is served by ' + up.length + ' gRPC listener(s)' +
             (up.length ? ' — ' + up.map(function (b) { return b.address; })
               .join(', ') : '') +
             (down.length ? ', and ' + down.length + ' did NOT bind (' +
               down.map(function (b) { return b.address + ': ' + b.error; })
               .join('; ') + '), which leaves the rest of this service ' +
               'untouched' : '') +
             '. The trust bundle is at ' + spiffeServer.BUNDLE_PATH +
             ' and GET /spiffe says what is and is not checked — which is ' +
             'most of that page, because NOTHING HERE IS ATTESTED: any ' +
             'caller that reaches the Workload API gets any identity in the ' +
             'trust domain.');
  }).catch(function (err) {
    // Reported rather than thrown, exactly as the other three are.
    log.error('spiffe: the SPIFFE listeners could not start: ' + err.message);
  });
  const tlsListeners = tlsServer.listen();
  tlsListeners.whenReady.then(function (ready) {
    log.info('tls: an HTTPS endpoint that reports the connection back to ' +
             'whoever made it is on ' + ready.tlsPort + ' (a client ' +
             'certificate is asked for, never required, and always ' +
             'explained) and on ' + ready.mtlsPort + ' (one is REQUIRED, and ' +
             'refused during the handshake if it does not verify). GET ' +
             '/tls/whoami over either. The client truststore starts EMPTY — ' +
             'POST the issuing CA to /tls/trust on this port — because the CA ' +
             'it has to verify is usually generated in a browser minutes ' +
             'before the connection.');
  }).catch(function (err) {
    // Reported rather than thrown, as the other two are: the rest of this
    // service is still useful, and a silent failure to bind would surface
    // later as a TLS endpoint that never answers.
    log.error('tls: the TLS endpoint could not start: ' + err.message);
  });
}

// Built rather than started above, because the two shapes differ only in this
// one expression and writing the whole announcement twice is how the two
// versions of it come to say different things.
if (useHttps) {
  const serverCert = tlsServer.serverCertificate();
  https.createServer({
    cert: serverCert.certPem,
    key: serverCert.privateKeyPem,
    // RFC 8705 — certificate-bound access tokens. The token endpoint is on this
    // listener, so a certificate has to be ASKED FOR here or there is never one
    // to bind to. The posture is 8443's exactly: asked for, never required.
    //
    // `rejectUnauthorized: false` looks like a hole and is not. A certificate
    // that built no chain to a trusted anchor is still thumbprinted and still
    // binds the token, because RFC 8705 section 3 binds to the CERTIFICATE and
    // explicitly permits a self-signed one — the proof is that the same key
    // completed this handshake, not that a CA vouched for it. Requiring
    // verification would also make the feature unreachable, since the
    // truststore at /tls/trust starts empty by design.
    requestCert: true,
    rejectUnauthorized: false
  }, app).listen(PORT, HOST, announce);
} else {
  app.listen(PORT, HOST, announce);
}
