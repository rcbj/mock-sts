'use strict';
//
// File: mode.js
//
// ---------------------------------------------------------------------------
// WHAT THIS SERVICE IS: A MOCK, OR AN IDENTITY PROVIDER.
//
// **THE ONE PLACE EITHER ANSWER IS GIVEN.** Every surface that used to decide
// for itself whether a credential was required asks here instead, and the three
// settings that used to decide separately — `admin.authRequired`,
// `scim.authRequired`, `spiffe.authRequired` — are gone. They were not "partial
// security"; they were one question with four answers, and a deployment that
// required a credential at SCIM and not at the console was unsecured with a
// longer configuration file.
//
// ---------------------------------------------------------------------------
// THE TWO MODES, AND WHAT ACTUALLY DIFFERS.
//
// **`development` IS EVERY RELEASE OF THIS SERVICE BEFORE 2026-09-06** and is
// the default, so an unedited process behaves exactly as it always did. That is
// not a legacy compatibility shim — it is the mode that makes this thing
// USEFUL: a client is exercised by a server that says yes, and a test suite
// that had to provision a credential for every one of seventeen protocol
// families before it could assert anything about a protocol would spend its
// life on setup.
//
// **`product` runs THE SAME PROTOCOL IMPLEMENTATIONS with the permissiveness
// taken out.** Not a different code path per protocol, and that distinction is
// the whole architecture: what changes is the answer to a handful of policy
// questions, all of them asked here. If a future change adds a behaviour that
// exists in one mode and not the other, it belongs behind a predicate in this
// file rather than behind an `if` at the call site — otherwise "what does
// product mode do" becomes a question you answer by reading the whole service.
//
// ---------------------------------------------------------------------------
// THE FOUR THINGS PRODUCT MODE REQUIRES, which are the four rcbj named.
//
//   1. REAL AUTHENTICATION. A presented password is verified against the hashed
//      `userPassword` on the person's directory entry, at every door that takes
//      one: the sign-in screen, an LDAP bind, a WS-Security UsernameToken, SCIM
//      Basic. `common/credentials.js` performs it; this file decides whether it
//      is asked.
//   2. EVERY REFERENCED OBJECT EXISTS ALREADY. Nothing is created because it
//      was named — not a user, not an application, not a service principal, not
//      an authorization server. An unknown name is a refusal, which is what
//      makes the register a statement about the deployment rather than a log of
//      what has been tried.
//   3. EVERY OAUTH 2.0 / OIDC APPLICATION HOLDS A SECRET, and authenticates
//      with it. There are no public clients in product mode.
//   4. `/admin-api` IS GATED. It is ungated in development on purpose — it is
//      what the tests drive and the way back in when nobody holds a role — and
//      that is a total authentication bypass which cannot survive into a
//      product.
//
// ---------------------------------------------------------------------------
// IT IS PER TRUST REALM, and that is worth stating because it is unusual.
//
// `global.mode` is `realmRuntime`, following `oauth2.rfc9700` exactly: a realm
// binds no socket, so nothing about the mode is a property of a listener, and
// one process can serve a development realm and a product realm at once. A
// client can then be exercised against both without a second service — which is
// the same argument that made RFC 9700 mode a realm rather than a second
// instance.
//
// **WHAT IS NOT PER REALM IS ISOLATION**, and the two must not be confused. A
// trust realm is fully isolated from every other in BOTH modes; the mode says
// how hard the doors are, not whose doors they are.
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3). It registers no route, so its position in the require
// order is not a position. It requires only `config`, which requires nothing
// here, so it is a LEAF and must stay one: everything above it may require it
// and it may never require any of them back. Every predicate takes no argument
// and reads the AMBIENT realm, exactly as `config.value()` does.
// ---------------------------------------------------------------------------

const config = require('./config');

// This module's own logger rather than the shared one in helpers.js, which
// requires this module: a require back would close a cycle. So the level is
// read the way the vendored modules read theirs: STS_LOG_LEVEL, then
// CONFIG_FILE's logLevel, then info.
let logLevelProblem = null;
const log = require('bunyan').createLogger({
  name: 'sts-mode',
  level: (function () {
    if (process.env.STS_LOG_LEVEL) {
      return process.env.STS_LOG_LEVEL;
    }
    try {
      return require(process.env.CONFIG_FILE).logLevel || 'info';
    } catch (e) {
      logLevelProblem = e;
      return 'info';
    }
  })()
});
if (logLevelProblem) {
  log.debug('No log level from CONFIG_FILE, so info: ' +
            logLevelProblem.message);
}

const DEVELOPMENT = 'development';
const PRODUCT = 'product';

// The mode of the realm this request is in. Read through `config.value()` and
// never cached, because it is runtime-settable and per realm — a cached answer
// would be the mode of whichever realm happened to ask first.
function current() {
  log.debug("Entering current().");
  const value = String(config.value('global.mode') || DEVELOPMENT);
  log.debug("Leaving current().");
  return value === PRODUCT ? PRODUCT : DEVELOPMENT;
}

function isProduct() {
  log.debug("Entering isProduct().");
  log.debug("Leaving isProduct().");
  return current() === PRODUCT;
}

function isDevelopment() {
  log.debug("Entering isDevelopment().");
  log.debug("Leaving isDevelopment().");
  return current() === DEVELOPMENT;
}

// ---------------------------------------------------------------------------
// THE PREDICATES. One per policy question, named for the QUESTION and not for
// the mode, so that a call site reads as what it is checking rather than as
// which mode it is in — `if (mode.verifiesCredentials())` says why the branch
// exists where `if (mode.isProduct())` says only when.
//
// They are all `isProduct()` today and that is not a reason to collapse them.
// The moment one of them wants a setting of its own, or a third mode arrives,
// the call sites do not move.
// ---------------------------------------------------------------------------

// Is a presented password actually checked? Development checks none, in any
// protocol — the one exception being Kerberos, which cannot be permissive that
// way because the password IS the key, and whose permissiveness therefore lives
// in the KDC's account policy instead. See kerberos/CLAUDE.md.
function verifiesCredentials() {
  log.debug("Entering verifiesCredentials().");
  log.debug("Leaving verifiesCredentials().");
  return isProduct();
}

// May a user, application, service principal or authorization server be created
// because something NAMED it? Development says yes and that is most of what
// makes it a mock: a client can point at this service with any client_id and
// get a working exchange.
function autoCreates() {
  log.debug("Entering autoCreates().");
  log.debug("Leaving autoCreates().");
  return !isProduct();
}

// Must an OAuth 2.0 / OpenID Connect application hold a client secret and
// authenticate with it? There are no public clients in product mode — which
// also means no PKCE-only public client, and a deployment that wants one wants
// development mode or a different product.
function requiresClientSecret() {
  log.debug("Entering requiresClientSecret().");
  log.debug("Leaving requiresClientSecret().");
  return isProduct();
}

// ---------------------------------------------------------------------------
// FIVE MORE QUESTIONS, ADDED 2026-09-12 BY AN AUDIT FOR WHAT WAS HARD-CODED.
//
// Every one of them was a development-mode behaviour written as a LITERAL at a
// call site — a fixture password, a persona surname, an ungated switch — with
// no mode check, so product mode shipped it unchanged. The rule at the top of
// this file is that a behaviour existing in one mode and not the other belongs
// behind a predicate here; these are the ones that had not been put here.
// ---------------------------------------------------------------------------

// Is a service created with DEMONSTRATION DATA in it? The directory's three
// people and their groups, the Kerberos fixture accounts and their literal
// long-term keys, the SPIFFE registry's sample entries, and the credential
// attributes generated onto every person. A product deployment starts empty
// apart from what it was configured with, because a fixture account with a
// password printed in this repository is an account anybody can use.
function seedsDemoData() {
  log.debug("Entering seedsDemoData().");
  log.debug("Leaving seedsDemoData().");
  return !isProduct();
}

// Does the realm chooser in front of `/admin` and `/portal` LIST the realms?
// (2026-09-14, #32.) A person arriving at either surface with no session, on a
// service with realms defined, chooses which realm to sign in through.
// Development draws every realm in a list, because the list is what somebody
// exercising the service wants; product asks for the realm's id in a text box,
// because a list drawn to anybody who can reach the page publishes every
// tenant this deployment serves.
function listsRealmsBeforeSignIn() {
  log.debug("Entering listsRealmsBeforeSignIn().");
  log.debug("Leaving listsRealmsBeforeSignIn().");
  return !isProduct();
}

// May a claim VALUE be invented where the store holds none? A persona surname,
// an address at a domain nobody owns with `email_verified: true`, a generated
// birthdate in a signed credential, an `@example.com` subject in a security
// event sent to a real receiver. Development invents them so a client has
// something to parse; product OMITS what it does not know, because an invented
// fact a relying party believes is worse than an absent one it can handle.
function inventsClaimValues() {
  log.debug("Entering inventsClaimValues().");
  log.debug("Leaving inventsClaimValues().");
  return !isProduct();
}

// May a response be delivered to an address the REQUEST named and no
// registration did? A SAML AssertionConsumerServiceURL, a SAML 1.1 `shire`, a
// WS-Federation `wreply`, a wallet URL on a query string. Development accepts
// any absolute URL on purpose — it is how a client under test is pointed at
// this service without registering first. Product delivers only to an address
// on the application's own entry, which is the difference between an identity
// provider and a signed-assertion forwarding service.
function acceptsUnregisteredAddresses() {
  log.debug("Entering acceptsUnregisteredAddresses().");
  log.debug("Leaving acceptsUnregisteredAddresses().");
  return !isProduct();
}

// Are the TEST CONTROLS open to anybody who can reach the port? Adding a trust
// anchor at POST /tls/trust, switching DPoP nonces, reading the Kerberos
// fixture passwords off /krb5/principals, signing somebody ELSE out with
// ?username=, registering an OAuth client with no initial credential, asking a
// SAML 1.1 attribute authority about any named person. Each exists so a test
// can drive a state; in product each is either refused or behind the credential
// the equivalent administrative operation already requires.
function opensTestControls() {
  log.debug("Entering opensTestControls().");
  log.debug("Leaving opensTestControls().");
  return !isProduct();
}

// Is a write over the DIRECTORY'S OWN SOCKET authorized against the identity
// that bound? Product mode: an anonymous connection writes nothing, an
// administrator (Admin Write, in the default realm) writes anything, and a
// person may modify only the attributes `ldap.selfWritableAttributes` names on
// their own entry. Development binds any DN with any password, so the bound DN
// proves nothing and a check keyed on it would refuse the suite while
// protecting nothing. `ldap/ldap_server.js`'s `directoryWriteRefusal()` argues
// the rule.
function authorizesDirectoryWrites() {
  log.debug("Entering authorizesDirectoryWrites().");
  log.debug("Leaving authorizesDirectoryWrites().");
  return isProduct();
}

// ---------------------------------------------------------------------------
// THE DIRECTORY'S OWN SOCKET, READ SIDE AND BIND SIDE (2026-09-12).
//
// node-ldapjs is a protocol library and decides nothing: it records the DN a
// bind named on the connection and leaves every question about what that
// connection may then do to the handlers. `authorizesDirectoryWrites()` above
// answers the write half. These five answer the rest, and they are five rather
// than one because each is a different question an operator reading
// /admin/mode asks, and each is refused with a different LDAP result code.
// `ldap/ldap_server.js`'s *THE DIRECTORY'S READ AND BIND SECURITY* block argues
// all of them. Development answers no to every one: every bind succeeds there,
// so a bound DN proves nothing and a check keyed on it protects nothing.
// ---------------------------------------------------------------------------

// Must a connection BIND AS SOMEBODY before it may read? Product: an anonymous
// or unauthenticated simple bind is refused (RFC 4513 sections 5.1.1 and 5.1.2
// both permit a server to), and a search or compare on a connection that never
// bound is refused — the root DSE excepted, because a client reads it to find
// out where to bind.
function requiresDirectoryBind() {
  log.debug("Entering requiresDirectoryBind().");
  log.debug("Leaving requiresDirectoryBind().");
  return isProduct();
}

// Are CREDENTIAL ATTRIBUTES withheld from every reader of the socket? Product:
// a password hash, a client secret, a private key, a TOTP secret, a recovery
// code, an activation token and a Kerberos key never leave in a search, a
// filter cannot see them (or it would be an oracle, one character at a time),
// and a compare against one is refused. An administrator is not excepted: the
// console and the management API read them through this module's functions,
// and nothing needs them on the wire.
function withholdsDirectorySecrets() {
  log.debug("Entering withholdsDirectorySecrets().");
  log.debug("Leaving withholdsDirectorySecrets().");
  return isProduct();
}

// May a client WRITE an attribute the directory maintains itself —
// createTimestamp, modifyTimestamp, entryDN? Product: no, not even an
// administrator, because a timestamp anybody can set is not evidence of when
// anything happened.
function protectsOperationalAttributes() {
  log.debug("Entering protectsOperationalAttributes().");
  log.debug("Leaving protectsOperationalAttributes().");
  return isProduct();
}

// Must a bind that carries a password arrive over TLS? Product: a simple bind
// on the plain listener is answered confidentialityRequired before the password
// is looked at, since by then it has already crossed the network in the clear.
function requiresConfidentialDirectoryBinds() {
  log.debug("Entering requiresConfidentialDirectoryBinds().");
  log.debug("Leaving requiresConfidentialDirectoryBinds().");
  return isProduct();
}

// Are FAILED binds rate limited? Product: failures are counted per bind DN and
// per address in `common/websecurity.js`'s buckets, and a caller over either
// limit is refused before its password is checked — so a correct guess during a
// lockout is refused like a wrong one and teaches nothing. A SUCCESSFUL bind is
// never counted, because a connection pool binds on every connection it opens.
function limitsDirectoryBindFailures() {
  log.debug("Entering limitsDirectoryBindFailures().");
  log.debug("Leaving limitsDirectoryBindFailures().");
  return isProduct();
}

// May a response go out WEAKER than the caller or the registration asked for?
// An assertion an application is configured to have encrypted, or a WS-Trust
// token requested with an encryption certificate, that cannot be encrypted —
// development sends it in the clear and says so loudly, because refusing to
// issue would hide the defect a client author is trying to see. Product
// refuses: a document the deployment said must be confidential and was not is a
// leak, however loudly it is logged. Not `opensTestControls()`, which the first
// version used for want of this: that one is about who may DRIVE a switch, and
// this one is about what a response is allowed to lose on the way out.
function sendsWeakerThanAsked() {
  log.debug("Entering sendsWeakerThanAsked().");
  log.debug("Leaving sendsWeakerThanAsked().");
  return !isProduct();
}

// When a presented certificate's REVOCATION STATUS cannot be established — a
// foreign CRL that cannot be fetched, does not verify or is stale — is the
// certificate refused? This is what `pki.revocationCheck=auto` resolves to:
// product answers yes (hard-fail), development answers no (soft-fail).
//
// **SOFT-FAIL IS THE WEAKNESS AN ATTACKER USES**: somebody holding a revoked
// certificate who can block the fetch turns "revoked" into "unknown", and
// soft-fail waves "unknown" through. A product closes that. Development keeps
// soft-fail because what it refuses is then exactly what somebody REVOKED —
// both modes consult this service's own register, which has no network in it
// and cannot make a good certificate fail. `common/revocation_status.js`
// argues all of it.
function refusesUnknownRevocationStatus() {
  log.debug("Entering refusesUnknownRevocationStatus().");
  log.debug("Leaving refusesUnknownRevocationStatus().");
  return isProduct();
}

// Must an ACME or EST request arrive over TLS (2026-09-13)? RFC 8555 section
// 6.1 says ACME MUST be HTTPS and RFC 7030 section 3.2 puts EST on TLS by
// definition, so product answers yes and refuses a request that reached the
// main port as plain HTTP. Development answers, logs that it did, and is how a
// client under test reaches a service started with STS_HTTPS=false. SCEP is
// not asked: its messages are signed and encrypted CMS and RFC 8894 section
// 2.1 runs it over plain HTTP on purpose.
function requiresEnrollmentTls() {
  log.debug("Entering requiresEnrollmentTls().");
  log.debug("Leaving requiresEnrollmentTls().");
  return isProduct();
}

// May a caller that does not authenticate introspect a token at
// /oauth2/introspect (2026-09-13)? RFC 7662 section 2.1 says the endpoint MUST
// require some form of authorization, and development answers yes anyway: the
// suites and every client under test introspect with nothing but the token,
// and a refusal there removes the case they run. Product answers no — an open
// introspection endpoint tells anybody holding a token string who it belongs
// to and what it may do.
//
// **AN RFC 9701 JWT RESPONSE IS NOT ASKED THIS**, and must not be: that
// response names the resource server that asked in its `aud`, so it needs an
// authenticated caller in every mode, and section 5 says to refuse one that is
// not. `oauth-oidc/oauth2.js`'s `introspectEndpoint()` makes both decisions.
function opensIntrospection() {
  log.debug("Entering opensIntrospection().");
  log.debug("Leaving opensIntrospection().");
  return !isProduct();
}

// May a request object be UNSIGNED — `alg: none` — at the authorization
// endpoint (2026-09-13)? RFC 9101 section 4 says a request object is signed, or
// signed and then encrypted, and nothing else; OpenID Connect Core section 6.1
// still allows `none`, and a great many clients send one. Development accepts
// it — unless `oauth2.requireSignedRequestObject`, the client's
// `oauthRequireSignedRequestObject` or the authorization server's profile says a
// signed one is required, which RFC 9101 section 10.5 says turns `none` away —
// because a client under test that has only met a strict server has never run
// the code it is trying to debug. Product refuses it: an unsigned request
// object is query parameters with extra steps, and anybody can write one.
function acceptsUnsignedRequestObjects() {
  log.debug("Entering acceptsUnsignedRequestObjects().");
  log.debug("Leaving acceptsUnsignedRequestObjects().");
  return !isProduct();
}

// May a registered `request_uri` be dialled over plain HTTP, or answer with a
// media type other than `application/oauth-authz-req+jwt` or `application/jwt`
// (2026-09-13)? RFC 9101 section 5.2 makes a request_uri HTTPS and section 10.4
// asks the server to check what comes back. Development allows both, logged,
// because a client under test commonly serves its request object from a local
// listener with no certificate; product refuses both. What is fetched is ONLY
// ever a URI the client REGISTERED — `oauth-oidc/request_object.js` argues that
// half, and no mode changes it.
function acceptsLooseRequestUris() {
  log.debug("Entering acceptsLooseRequestUris().");
  log.debug("Leaving acceptsLooseRequestUris().");
  return !isProduct();
}

// Does this process embed the identity protocol debugger (2026-09-13)?
// `debugger.enabled` decides where it says `on` or `off`; its default, `auto`,
// is this predicate's own answer: yes in development, where the debugger is
// the other half of what this service is for, and no in product, where an
// operator should turn on a network relay deliberately rather than find one.
// Read against the DEFAULT realm's mode, because the listener and the child
// process belong to the process and not to a realm. See debugger/CLAUDE.md.
function embedsProtocolDebugger() {
  log.debug("Entering embedsProtocolDebugger().");
  const asked = String(config.value('debugger.enabled') || 'auto');
  if (asked === 'on' || asked === 'off') {
    log.debug("Leaving embedsProtocolDebugger(). debugger.enabled=" + asked);
    return asked === 'on';
  }
  log.debug("Leaving embedsProtocolDebugger(). auto.");
  return isDevelopment();
}

// May the embedded debugger's api dial anything other than this service
// (2026-09-13)? Development answers yes — the debugger's own address guard
// still applies, with private networks allowed, which is how it reaches a
// Keycloak or a KDC beside this stack. Product answers no: the api child is
// handed an ALLOW-LIST of this service's own addresses plus
// `debugger.allowedDestinations`, because a relay that dials a caller's URL
// from inside an identity provider's network is the thing to not ship.
function limitsDebuggerDestinations() {
  log.debug("Entering limitsDebuggerDestinations().");
  log.debug("Leaving limitsDebuggerDestinations().");
  return isProduct();
}

// May a URL an ADMINISTRATOR names reach an address inside this service's own
// network (2026-09-13)? The one caller is the RFC 9728 import on
// /admin/applications/new, which fetches a protected resource's metadata
// document. Development answers yes: a resource on localhost is the ordinary
// thing to import there. Product answers no — the name is resolved once, every
// address is checked against loopback, the private ranges, link-local and the
// reserved blocks, and the connection is pinned to the address that was
// checked. `oauth-oidc/protected_resource_metadata.js` argues it.
function dialsInternalAddresses() {
  log.debug("Entering dialsInternalAddresses().");
  log.debug("Leaving dialsInternalAddresses().");
  return !isProduct();
}

// Is an RFC 9728 protected resource metadata document that fails a MUST a
// client applies accepted with a warning (2026-09-13)? Two of them: section
// 3.3's `resource` matching the well-known URL the document was fetched from,
// and section 2's https scheme for a resource identifier. Development warns
// and imports; product refuses. A document that is MALFORMED — the wrong JSON
// types, no `resource` — is refused in both, because shape is not a mode.
function acceptsNonconformingResourceMetadata() {
  log.debug("Entering acceptsNonconformingResourceMetadata().");
  log.debug("Leaving acceptsNonconformingResourceMetadata().");
  return !isProduct();
}

// Is the management API gated? See the note above on why it is not, in
// development. **THIS IS THE ONLY GATE THE MODE TURNS ON**, because it is the
// only one that was ever off.
function gatesManagementApi() {
  log.debug("Entering gatesManagementApi().");
  log.debug("Leaving gatesManagementApi().");
  return isProduct();
}

// ---------------------------------------------------------------------------
// THE FOUR GATES THAT WERE ALREADY ON, AND WHY THE MODE DOES NOT MOVE THEM.
//
// **`admin.authRequired`, `scim.authRequired`, `spiffe.authRequired` and
// `ssf.authRequired` ALL DEFAULTED TO `true`.** They existed so that an
// operator could turn a gate OFF, which is a thing a mock wants and a product
// must not offer — so what "moving them to the mode" means is that the gate is
// now UNCONDITIONAL and the setting that could disable it is gone.
//
// **THEY RETURN `true` IN BOTH MODES, AND THAT IS THE POINT RATHER THAN AN
// OVERSIGHT.** A first draft had them answer `isProduct()`, which turned four
// gates OFF in development and was caught within the hour by the console suite
// — a reader's form POST answered 303 where it must answer 403, because with
// the gate off everybody may do everything. Development mode is what this
// service always did, and what it always did was require a sign-in at all four.
//
// **WHAT THE MODE ACTUALLY CHANGES AT THESE DOORS IS `verifiesCredentials()`.**
// The gate asks who you are in both modes; only in product mode is the answer
// checked. That is the distinction the whole file exists to keep: a turnstile
// and a lock are different, and this service has always had the turnstile.
// ---------------------------------------------------------------------------

// Is a sign-on session and a role required at the console? Was
// `admin.authRequired`, which defaulted to on.
function gatesConsole() {
  log.debug("Entering gatesConsole().");
  log.debug("Leaving gatesConsole().");
  return true;
}

// Is a credential required at /scim/v2? Was `scim.authRequired`, on by default,
// because those endpoints create and DELETE accounts.
function gatesScim() {
  log.debug("Entering gatesScim().");
  log.debug("Leaving gatesScim().");
  return true;
}

// Is a credential required at the Shared Signals endpoints? Was
// `ssf.authRequired`, on by default. A stream is an agreement to be SENT
// security events about people, so an ungated one is a subscription anybody can
// take out.
function gatesSharedSignals() {
  log.debug("Entering gatesSharedSignals().");
  log.debug("Leaving gatesSharedSignals().");
  return true;
}

// Is an X509-SVID over mutual TLS required at the SPIRE Server API? Was
// `spiffe.authRequired`, on by default, because what comes out of that surface
// is a credential another service will believe.
//
// **The Workload API is deliberately NOT on this list and must never be**: its
// specification says it MUST NOT authenticate a caller, because a workload has
// no root of trust until that call gives it one. What it lacks there is
// ATTESTATION, not authentication, and no mode changes that.
function gatesSpireServerApi() {
  log.debug("Entering gatesSpireServerApi().");
  log.debug("Leaving gatesSpireServerApi().");
  return true;
}

// ---------------------------------------------------------------------------
// WHAT THE MODE CHANGES, as data rather than as prose — so that /admin/mode,
// GET /admin-api/mode and this file cannot come to disagree about what product
// mode does. The page renders this; nothing writes the list twice.
// ---------------------------------------------------------------------------
const REQUIREMENTS = [
  { id: 'credentials',
    what: 'A presented password is verified',
    development: 'No password is checked in any protocol. The sign-in screen ' +
                 'accepts anything, an LDAP bind accepts any DN with any ' +
                 'password, a WS-Security UsernameToken is read for its name ' +
                 'and not its secret, SCIM Basic passes on any pair, and ' +
                 'WS-Trust issues to a caller that presented nothing or an ' +
                 'unsigned SAML assertion.',
    product: 'Verified against the hashed `userPassword` on the person\'s ' +
             'directory entry, at every one of those doors. A person with no ' +
             '`userPassword` set cannot sign in at all. The OAuth 2.0 ' +
             'password grant is one of those doors, and refuses a person ' +
             'holding a second factor, which that grant cannot carry. ' +
             'WS-Trust requires a credential, and accepts an assertion only ' +
             'when this realm signed it and it is inside its Conditions.',
    where: 'common/credentials.js, ws-trust/wstrust.js, oauth-oidc/oauth2.js' },
  { id: 'resource-metadata-import',
    what: 'An RFC 9728 protected resource metadata import is held to the ' +
          'rules a client of the document follows',
    development: 'A document fetched from a URL is imported with a warning ' +
                 'when its `resource` does not match the well-known URL it ' +
                 'came from (section 3.3) or is not https, and the URL may ' +
                 'resolve to loopback or a private address.',
    product: 'Both are refused, and a URL resolving to a loopback, private, ' +
             'link-local or reserved address is not dialled — the name is ' +
             'resolved once and the connection pinned to the address that ' +
             'was checked. A malformed document is refused in both modes.',
    where: 'oauth-oidc/protected_resource_metadata.js' },
  { id: 'realm-chooser',
    what: 'The realm chooser before sign-in lists every realm',
    development: 'A browser with no session at /admin or /portal, on a ' +
                 'service with trust realms defined, is shown a list of every ' +
                 'realm to sign in through.',
    product: 'The same page asks for the realm\'s id in a text box, so the ' +
             'deployment\'s realms are not published to anybody who can ' +
             'reach it.',
    where: 'common/realm_chooser.js' },
  { id: 'weaker-responses',
    what: 'A response may go out weaker than asked',
    development: 'An assertion or token that should have been encrypted and ' +
                 'could not be is sent in the clear, with a warning.',
    product: 'Refused.',
    where: 'saml/saml2_sso.js, ws-trust/wstrust.js' },
  { id: 'objects',
    what: 'A referenced object must already exist',
    development: 'A user, application, service principal or authorization ' +
                 'server is created the first time something names it, which ' +
                 'is what lets a client point at this service with any ' +
                 'identifier and get a working exchange.',
    product: 'An unknown name is REFUSED. Everything must be created ahead ' +
             'of time, through the console, /admin-api, SCIM or an LDAP add.',
    where: 'ldap/ldap_server.js, kerberos/krb5_principals.js, ' +
           'common/applications.js, oauth-oidc/authorization_servers.js, ' +
           'spiffe/spiffe_workload.js, scim/scim_auth.js' },
  { id: 'key-material',
    what: 'Signing keys survive a restart',
    development: 'A new signing key is generated on every start and held in ' +
                 'memory. A token does not survive a restart — which is what ' +
                 'makes this service disposable, and the `kid` is derived ' +
                 'from the key material so two instances can never publish ' +
                 'one name over two keys.',
    product: 'Generated ONCE and read back from the persistence store — ' +
             'which product mode therefore requires — encrypted with ' +
             'AES-256-GCM under a key this service never generates and never ' +
             'stores, read from a mounted file, AWS Secrets Manager, GCP ' +
             'Secret Manager, Azure Key Vault or HashiCorp Vault.',
    where: 'common/keystore.js, common/secrets.js' },
  { id: 'client-secret',
    what: 'An OAuth 2.0 / OIDC application holds a secret',
    development: 'A client may be public and send nothing but a client_id.',
    product: 'Every application must hold a client secret and authenticate ' +
             'with it. There are no public clients.',
    where: 'oauth-oidc/client_auth.js' },
  { id: 'introspection',
    what: 'A caller of /oauth2/introspect authenticates',
    development: 'An RFC 7662 JSON introspection answers anybody who holds ' +
                 'the token string, with no client credential. An RFC 9701 ' +
                 'JWT response (Accept: application/token-introspection+jwt) ' +
                 'is the exception in both modes: its aud names the resource ' +
                 'server that asked, so that caller must authenticate as a ' +
                 'client with a credential on file, and is refused 400 ' +
                 'invalid_client otherwise.',
    product: 'Every introspection request must authenticate as a client ' +
             'with a credential that verifies — client_secret_basic or post, ' +
             'a client assertion, or an RFC 8705 certificate — and is ' +
             'refused ' +
             '401 invalid_client otherwise (400 for a JWT request, RFC 9701 ' +
             'section 5).',
    where: 'oauth-oidc/oauth2.js, oauth-oidc/introspection_jwt.js' },
  { id: 'request-objects',
    what: 'A JWT-secured authorization request is signed, and a request_uri ' +
          'is HTTPS',
    development: 'A request object signed with `none` (OpenID Connect Core ' +
                 '6.1) is accepted unless a signed one is required — by ' +
                 'oauth2.requireSignedRequestObject, the client\'s entry or ' +
                 'the authorization server\'s profile. A registered ' +
                 'request_uri may be plain http and may answer with any ' +
                 'media type; both are logged.',
    product: 'A request object must be signed (RFC 9101 section 4) and is ' +
             'refused invalid_request_object otherwise. A registered ' +
             'request_uri must be https and must answer ' +
             'application/oauth-authz-req+jwt or application/jwt, or the ' +
             'request is refused invalid_request_uri. In both modes a ' +
             'request_uri is fetched only when the client registered it.',
    where: 'oauth-oidc/request_object.js' },
  { id: 'management-api',
    what: '/admin-api requires a sign-in and a role',
    development: 'Open. It is what the tests drive and the way back in when ' +
                 'nobody holds a role — which also means anybody who can ' +
                 'reach this port can grant themselves both roles through it.',
    product: 'Gated exactly as /admin is: the same session, the same two ' +
             'roles.',
    where: 'mgmt-api/admin_api.js' },
  { id: 'console',
    what: '/admin requires a sign-in and a role',
    development: 'Required — and it always was; the setting that could turn ' +
                 'it off is gone. The sign-in behind it checks no password, ' +
                 'so what the gate proves is that somebody typed a name that ' +
                 'holds a role.',
    product: 'Required, and the sign-in behind it verifies the credential.',
    where: 'admin-ui/admin.js' },
  { id: 'certificate-enrollment',
    what: 'ACME and EST require TLS; an enrollment credential is verified',
    development: 'ACME (/enroll/acme) and EST (/.well-known/est) answer over ' +
                 'plain HTTP as well and log that they did. An EST password ' +
                 'is not checked (the credentials row) and an application\'s ' +
                 'client secret is not required. An ACME External Account ' +
                 'Binding MAC and a SCEP challenge password ARE verified, and ' +
                 'who a certificate may be issued for is enforced exactly as ' +
                 'in product: yourself, or anybody in the realm if you hold ' +
                 'Admin Write.',
    product: 'A request that did not arrive over TLS is refused ' +
             '(STS-ENROLL-0060). EST verifies the directory password and ' +
             'requires the client secret. Everything else is as in ' +
             'development.',
    where: 'common/cert_enrollment.js, acme/, est/, scep/' },
  { id: 'scim',
    what: '/scim/v2 requires a credential',
    development: 'Required in one of RFC 7644 section 2\'s six schemes — and ' +
                 'it always was — with none of them verified beyond its shape.',
    product: 'Required and verified. HTTP Digest is not offered, because RFC ' +
             '7616 needs the password or its hash and a scrypt hash can ' +
             'check neither; a HOBA key may be registered only by the ' +
             'signed-in owner of an existing account, and registering one ' +
             'never creates an account.',
    where: 'scim/scim_auth.js' },
  { id: 'shared-signals',
    what: '/ssf requires a credential',
    development: 'Required in one of the schemes the endpoints accept — and ' +
                 'it always was — none verified beyond its shape.',
    product: 'Required and verified: a Basic credential is checked against ' +
             'the person\'s userPassword, and ssf.authBasic removes the ' +
             'scheme.',
    where: 'ssf/ssf_auth.js' },
  { id: 'demo-data',
    what: 'A new service contains demonstration data',
    development: 'The directory is seeded with three people, two groups, a ' +
                 'bind account, and the remote-pep-1 and xacml-user-1 ' +
                 'identities in the two XACML role groups; the KDC with ' +
                 'fixture accounts, delegation rules and a trusted realm ' +
                 'whose passwords are written in its source; the SPIFFE ' +
                 'registry with sample entries; and every person is given ' +
                 'generated credential attributes.',
    product: 'None of it. The directory, the principal database and the ' +
             'registry hold what was configured or provisioned, and nothing ' +
             'else — the two XACML role groups exist and are empty, and the ' +
             'KDC refuses to build krbtgt or its service account on the ' +
             'passwords published in this repository.',
    where: 'ldap/ldap_server.js, kerberos/krb5_principals.js, ' +
           'spiffe/spiffe_registry.js' },
  { id: 'claim-values',
    what: 'A claim value may be invented',
    development: 'A token names a persona — family name `Mock`, an address ' +
                 'at sts.example with email_verified true — a credential ' +
                 'fills an absent attribute with a generated value, and a ' +
                 'security event names an @example.com subject.',
    product: 'A value comes from the person\'s directory entry or is omitted.',
    where: 'common/helpers.js, oauth-oidc/oauth2.js, oid4vc/vc_claims.js, ' +
           'ssf/ssf_subjects.js, ssf/risc.js' },
  { id: 'return-addresses',
    what: 'A response goes where the request says',
    development: 'Any absolute URL a SAML AuthnRequest, a SAML 1.1 shire, a ' +
                 'WS-Federation wreply or a wallet link names is used, ' +
                 'registered or not — and an address a sighting writes onto ' +
                 'an application entry (or a callback the console or portal ' +
                 'learns from a Host header) is MARKED as observed on ' +
                 'appReturnAddressObserved.',
    product: 'Only an address registered on the application\'s own entry — ' +
             'and a sighting never adds one. An address still marked as ' +
             'observed is NOT registered: development put it there and it is ' +
             'refused until an operator confirms it on the application\'s ' +
             'page or with POST /admin-api/applications/confirm-address ' +
             '(STS-REG-0049). Addresses recorded before sightings were ' +
             'marked carry no mark and still need reviewing before a realm ' +
             'is switched. The console\'s and the portal\'s own callbacks ' +
             'are not learnt from a request\'s Host header (set ' +
             'global.publicBaseUrl), and a WebAuthn RP ID that does not fit ' +
             'the host refuses the ceremony instead of falling back to it.',
    where: 'saml/saml2_sso.js, saml/saml11_sso.js, ws-federation/wsfed.js, ' +
           'oid4vc/vc_offers.js, oid4vc/vc_verifier.js, ' +
           'common/applications.js, common/oidc_rp.js, authn/authn.js' },
  { id: 'test-controls',
    what: 'Test controls are open',
    development: 'POST /tls/trust and /tls/trust/clear, POST ' +
                 '/dpop/nonce-mode, the passwords on ' +
                 '/krb5/principals, signing another person out with ' +
                 '?username=, open dynamic client registration, the SAML ' +
                 '1.1 attribute authority and HOBA key registration all ' +
                 'answer anybody, and a refused SCIM Digest challenge prints ' +
                 'the shared password.',
    product: 'Each is refused, or requires the credential its administrative ' +
             'equivalent already requires. A sign-out naming anybody but the ' +
             'signed-in caller is refused whatever logout.anyUser says. ' +
             'Dynamic client registration is refused unless ' +
             'oauth2.openRegistration is on — or the registration carries a ' +
             'software statement this realm trusts (it issued it, or an ' +
             'application declares its issuer) and ' +
             'oauth2.softwareStatementOpensRegistration is on, which is the ' +
             'operator deciding who may register by deciding whose ' +
             'statements to trust.',
    where: 'tls/tls_server.js, oauth-oidc/oauth2.js, kerberos/krb5_kdc.js, ' +
           'logout/logout.js, saml/saml11_sso.js, scim/scim_auth.js' },
  { id: 'directory-writes',
    what: 'A write to the directory over LDAP is authorized',
    development: 'Any connection may add, modify, rename or delete any entry ' +
                 'in any realm, anonymous ones included — which is what lets ' +
                 'a test drive the raw socket with no setup.',
    product: 'An anonymous connection writes nothing. A connection bound as ' +
             'somebody holding Admin Write — in the default realm\'s ' +
             'directory, and not merely because no role has a member yet — ' +
             'writes anything. Anybody else may modify only their OWN entry, ' +
             'and only the attributes ldap.selfWritableAttributes names; a ' +
             'userPassword among them still meets the password policy. The ' +
             'refusal is LDAP result code 50, insufficientAccessRights. What ' +
             'this does not cover is READING: see directory-reads.',
    where: 'ldap/ldap_server.js' },
  { id: 'directory-reads',
    what: 'A read of the directory over LDAP requires a bind, and never ' +
          'returns a credential',
    development: 'Any connection, anonymous or never bound, may search and ' +
                 'compare every entry and read every attribute but a ' +
                 'Kerberos key, and may write createTimestamp, ' +
                 'modifyTimestamp and entryDN like any other attribute.',
    product: 'A search or compare on a connection that has not bound as ' +
             'somebody is refused with result code 50, ' +
             'insufficientAccessRights — the root DSE excepted, which a ' +
             'client reads to find out where to bind. Credential attributes ' +
             '(userPassword, pwdHistory, client secrets, registration access ' +
             'tokens, private keys, TOTP secrets, recovery codes, activation ' +
             'tokens and Kerberos keys) are never returned by a search, are ' +
             'invisible to a search FILTER so that it cannot be used as an ' +
             'oracle, and cannot be compared against; an administrator is ' +
             'not excepted. createTimestamp, modifyTimestamp and entryDN ' +
             'cannot be written by anybody, with result code 19, ' +
             'constraintViolation.',
    where: 'ldap/ldap_server.js' },
  { id: 'directory-binds',
    what: 'An LDAP bind is confidential, authenticated and rate limited',
    development: 'Every bind succeeds but one with the password "invalid", ' +
                 'on 389 and 636 alike, anonymous and unauthenticated ones ' +
                 'included, with no limit on how many fail.',
    product: 'An anonymous bind is refused with result code 48, ' +
             'inappropriateAuthentication, and a DN with an empty password ' +
             'with 53, unwillingToPerform (RFC 4513 sections 5.1.1 and ' +
             '5.1.2). A bind carrying a password on the plain listener is ' +
             'refused with 13, confidentialityRequired, before the password ' +
             'is read — use LDAPS, or turn ldap.plainListener off. FAILED ' +
             'binds are counted per bind DN and per address against ' +
             'security.rateLimitPerIdentity and security.rateLimitPerAddress ' +
             'within security.rateLimitWindowS, and a caller over either is ' +
             'refused with 53 before its password is checked; a successful ' +
             'bind clears its own DN\'s counter, never its address\'s, and ' +
             'is never counted.',
    where: 'ldap/ldap_server.js, common/websecurity.js' },
  { id: 'spire',
    what: 'The SPIRE Server API requires an X509-SVID',
    development: 'Required over mutual TLS and authorized against SPIRE\'s ' +
                 'own per-method table; anybody may ask the local socket to ' +
                 'mint the SVID that gets them in.',
    product: 'The same, over a registry that no longer mints an entry for ' +
             'whoever asks.',
    where: 'spiffe/spiffe_auth.js' },
  // 2026-09-12. The one row here whose two columns differ in what is REFUSED
  // for a reason that is not "development checks nothing": both modes consult
  // the register, and the difference is what an UNREACHABLE foreign CRL costs.
  { id: 'revocation-check',
    what: 'A presented certificate is checked for revocation',
    development: 'SOFT-FAIL (pki.revocationCheck=auto). A certificate this ' +
                 'service issued is looked up in its own register, the whole ' +
                 'chain, and a revoked one is refused; one from another ' +
                 'authority is checked with the OCSP responder and the CRL ' +
                 'it names, and a status that cannot be fetched or verified ' +
                 'is accepted and reported.',
    product: 'HARD-FAIL (pki.revocationCheck=auto). The same lookups, and a ' +
             'foreign certificate whose status cannot be fetched, verified ' +
             'or trusted as fresh — or that its issuer\'s responder does not ' +
             'know — is REFUSED too: an attacker who can block a fetch ' +
             'cannot turn "revoked" into "accepted". One whose issuer names ' +
             'no list and no responder at all is accepted unless ' +
             'pki.revocationRequireDistributionPoint is on.',
    where: 'common/revocation_status.js, tls/tls_server.js, ' +
           'oauth-oidc/mtls.js, oauth-oidc/client_auth.js, ' +
           'scim/scim_auth.js, spiffe/spiffe_auth.js, common/pki.js' },
  // 2026-09-13. The embedded protocol debugger. Its GATE is not on this page
  // because it does not move: an access token carrying the debugger
  // permission, issued only to a console administrator, in both modes.
  { id: 'protocol-debugger',
    what: 'The identity protocol debugger is embedded, and what its api may ' +
          'dial',
    development: 'ON (debugger.enabled=auto): its own listener ' +
                 '(debugger.port) serves the debugger UI and forwards /api to ' +
                 'a child process. The api dials whatever a signed-in ' +
                 'administrator asks it to, including private networks.',
    product: 'OFF unless debugger.enabled=on. When on, the api child is ' +
             'handed an ALLOW-LIST — this service\'s own addresses and ' +
             'debugger.allowedDestinations — and refuses every other ' +
             'destination, raw sockets included.',
    where: 'debugger/debugger_server.js, debugger/debugger_api_process.js' }
];

// WHAT PRODUCT MODE STILL DOES NOT DO. Named here rather than left to be
// discovered, because a mode called `product` invites the assumption that
// everything in it is production-grade, and three things are not:
//
//   * ~~NO REVOCATION IS CHECKED ON A CLIENT CERTIFICATE~~ — **PAID ON
//     2026-09-12.** It read "there is no OCSP responder and no CRL fetch, in
//     either mode". The responder arrived on 2026-09-11 and the check on
//     2026-09-12 (`common/revocation_status.js`), with OCSP for a FOREIGN
//     certificate and delta and indirect CRLs the same day; what remains is
//     in NOT_YET below.
//   * ~~NOTHING THIS SERVICE MINTS SURVIVES A RESTART~~ — **PAID ON
//     2026-09-06 and left here as the record of it.** It read "in either
//     mode, because the signing key is regenerated on every start; a product
//     deployment needs key persistence and rotation, and that is a feature
//     rather than a mode". Both halves arrived that day: `keystore.js`
//     persists the keys in product mode, and with the premise gone
//     `persistence_minted.js` persists the sessions, tokens, codes,
//     artifacts, tickets, counters and audit log beside them. DEVELOPMENT
//     MODE IS UNCHANGED and the sentence is still true of it, which is why
//     it is qualified here rather than deleted.
//   * A KERBEROS ACCOUNT POLICY IS STILL PERMISSIVE in the sense that every
//     seeded principal shares one password. Product mode stops the KDC creating
//     principals on demand; it does not give the existing ones distinct
//     long-term keys.
const NOT_YET = [
  // **THIS ROW NARROWED ON 2026-09-11 AND DID NOT GO AWAY.** It read *there
  // is no OCSP responder and no CRL fetch*; the first half stopped being true
  // that day — every authority in `/admin/pki` signs a CRL and answers OCSP —
  // and the SECOND half is what this row was always about and is unchanged.
  // Publishing revocation and consulting it are different pieces of work, and
  // a row deleted because half of it was done would have quietly removed the
  // half that is still outstanding.
  // **AND IT NARROWED AGAIN ON 2026-09-12, AND AGAIN DID NOT GO AWAY.** It
  // read *revocation is PUBLISHED and never CONSULTED*: a certificate revoked
  // on /admin/pki still authenticated here. `common/revocation_status.js`
  // consults it now at every door that accepts a presented certificate, and
  // the REQUIREMENTS row above says what each mode refuses. What is left is
  // the three things that file does not do, which are what this row is about.
  // **AND A THIRD TIME THE SAME DAY.** It named three things outstanding: OCSP
  // for a foreign certificate, indirect and delta CRLs, and a registered key.
  // The first two are consulted now — the responder a certificate names, with
  // delegated-responder validation, and delta and indirect lists with their
  // issuing distribution point — and what is left is narrower than either.
  { id: 'certificate-revocation',
    what: 'Revocation is CONSULTED for a presented certificate (see the ' +
          'requirement above) and for a REGISTERED one when it verifies ' +
          'something — the register, the OCSP responder (a delegated ' +
          'responder\'s own status included) and the CRL a foreign ' +
          'certificate names, over http, https and ldaps, delta CRLs merged, ' +
          'indirect CRLs read per issuer with their signer fetched from the ' +
          'list\'s caIssuers address where nothing here holds it. What ' +
          'remains is limits rather than work: a BARE key registered with no ' +
          'certificate (a JWK without x5c) names no issuer and no list, so ' +
          'only taking it off the entry stops it verifying; plain ldap: is ' +
          'dialled only when pki.revocationLdap allows it; a distribution ' +
          'point named relative to its CRL issuer is used only with ' +
          'pki.revocationLdapDirectory set and every RDN single-valued; and ' +
          'LDAPS 636 asks for no client certificate, so nothing there is ' +
          'consulted.' },
  { id: 'key-overlap',
    what: 'A rotation has NO OVERLAP. This service publishes one key per ' +
          'realm per algorithm, so everything signed with the old key stops ' +
          'verifying the moment the new one is in use. A product deployment ' +
          'wants both keys in JWKS for a window, which needs the old private ' +
          'key kept — the thing rotation is for getting rid of — so it is a ' +
          'design rather than a setting.' },
  // **THE SPIFFE HALF OF THIS ROW NARROWED ON 2026-09-11.** It said "the TLS
  // server certificate and the SPIFFE authorities, which belong to their own
  // modules and are shared across realms" — and the SPIFFE X.509 authority is
  // `common/pki.js`'s SPIFFE Issuing CA now, per realm, in the same sealed
  // `pki:` row family as the rest of the hierarchy, so in product mode it
  // survives a restart. The JWT authority does not: it has no certificate and
  // no hierarchy to hang from, so there is nothing for the keystore to keep it
  // beside.
  { id: 'post-quantum-keys',
    what: 'The eleven post-quantum keys per realm are NOT persisted, in ' +
          'either mode: they are generated on the worker pool because ' +
          'generating them is expensive, and cached by pq_jose.js. Nor are ' +
          'the TLS server certificate and the SPIFFE JWT authority, which ' +
          'belong to their own modules. The SPIFFE X.509 authority came off ' +
          'this row on 2026-09-11: it is this realm\'s SPIFFE Issuing CA ' +
          'under the service Root, so it persists in product mode exactly as ' +
          'the rest of the certificate authority does. Only the RSA signing ' +
          'key and the eight EC/Ed keys beside it survive a restart ' +
          'otherwise.' },
  { id: 'key-never-in-memory',
    what: 'A private key is DECRYPTED IN THIS PROCESS while it signs. Since ' +
          '2026-09-06 what is resident between signatures is the ciphertext, ' +
          'and `keys.plaintextRetention` decides how long the plaintext ' +
          'lives — but the key-encryption key is resident too, so this ' +
          'narrows the value of a SNAPSHOT (a core dump, a swapped page, a ' +
          'debugger attached for a moment) and defends against nothing that ' +
          'can read this memory at a moment of its choosing and wait for the ' +
          'next signature. A key that this process genuinely cannot read is ' +
          'an HSM, or a KMS that signs on your behalf, and is a different ' +
          'design rather than a setting. A JavaScript string also cannot be ' +
          'wiped: the decrypt buffer is zeroed and everything made out of it ' +
          'is released rather than erased.' },
  // **REWRITTEN 2026-09-12.** It read *product mode stops the KDC creating
  // principals on demand; it does not give the seeded ones distinct long-term
  // keys — they still share `krb5.userPassword`*. Product mode now seeds no
  // fixture principals at all, so there are no shared keys left to describe —
  // and what that exposed is the larger gap, which is this row now.
  { id: 'kerberos-keys',
    what: 'Product mode creates no fixture principals, no trusted realm and ' +
          'nothing on demand, and refuses the published krbtgt and service ' +
          'passwords. Directory people authenticate to the product KDC with ' +
          'keys derived from their own password when it is set or verified, ' +
          'sealed on their entry (`stsKrb5Keys`); service principals get ' +
          'random keys and a keytab shown once at ' +
          '/admin/kerberos/principals. A password change or a rotation keeps ' +
          'the version it replaced — at most krb5.retainedKeyVersions, each ' +
          'for krb5.retainedKeyTtlS — so a ticket issued under it is still ' +
          'accepted until it could have expired, while pre-authentication ' +
          'and issuance use the current key only; "Drop previous versions" ' +
          'ends that window. Not yet: the krbtgt key has no rotation and so ' +
          'no previous version (a TGT under an older krb5.krbtgtPassword is ' +
          'refused). Since 2026-09-15 each trust realm whose krb5.enabled ' +
          'is on has a KDC, a Kerberos realm and keys of its own, on the ' +
          'shared port.' },
  // `vci-request-encryption-key` WAS HERE AND WAS PAID ON 2026-09-12. The
  // OpenID4VCI request-encryption key is a member of each realm's key set now
  // (`helpers.js`'s `makeStsKeys()`), so it is per realm, travels to request
  // workers over the key channel with the rest of the set, and persists
  // wherever the signing keys do. What is left is the race every key-set
  // enrichment already has: two separate service instances on one store adding
  // a key to an OLD stored set at the same moment.
  // `truststore-door` WAS HERE AND WAS PAID IN TWO STEPS ON 2026-09-12: first
  // the gated door (/admin/tls/trust, POST /admin-api/tls/trust/{add,remove}),
  // then persistence — a runtime anchor is written to ou=trustAnchors in the
  // default realm's directory, restored before the TLS listeners bind, and
  // re-applied when another process changes the container. What is left is
  // narrower and is the directory's: any LDAP client allowed to write
  // ou=trustAnchors can add an anchor, which the directory authorization gap
  // below covers.
  // `directory-authorization` WAS HERE AND ITS WRITE HALF WAS PAID ON
  // 2026-09-12 — see the `directory-writes` requirement above. It read *a bound
  // LDAP client may add, modify or delete any entry*. What it did not say, and
  // what is left, is that the same client may READ any entry.
  // NARROWED 2026-09-12, when `directory-reads` landed. It read *any
  // connection — anonymous included — may search and compare every entry in
  // every realm and read every attribute, including oauthClientSecret and
  // fedClientSecret in the clear*. An anonymous connection now reads nothing
  // and no connection reads a credential; what is left is the part that is a
  // design question rather than a hole.
  { id: 'directory-read-authorization',
    what: 'The embedded directory has no PER-IDENTITY read authorization. In ' +
          'product mode a read requires a bind and credential attributes are ' +
          'withheld from everybody, but any connection that has bound as ' +
          'somebody may search and compare every entry in the realm its base ' +
          'names and read every other attribute on it — every person\'s ' +
          'mail, telephone number and group memberships, every ' +
          'application\'s redirect URIs. Deciding what a person, an ' +
          'administrator and an application may each read is the outstanding ' +
          'design.' },
];

// The whole answer, for the console page, the management API and the metadata
// report. One function so the three cannot disagree.
function report() {
  log.debug("Entering report().");
  log.debug("Leaving report().");
  return {
    mode: current(),
    isProduct: isProduct(),
    requirements: REQUIREMENTS.map(function (row) {
      return Object.assign({ inForce: isProduct() ? row.product :
                                      row.development },
                           row);
    }),
    notYet: NOT_YET
  };
}

module.exports = {
  DEVELOPMENT: DEVELOPMENT,
  PRODUCT: PRODUCT,
  current: current,
  isProduct: isProduct,
  isDevelopment: isDevelopment,
  verifiesCredentials: verifiesCredentials,
  autoCreates: autoCreates,
  requiresClientSecret: requiresClientSecret,
  gatesManagementApi: gatesManagementApi,
  seedsDemoData: seedsDemoData,
  listsRealmsBeforeSignIn: listsRealmsBeforeSignIn,
  inventsClaimValues: inventsClaimValues,
  acceptsUnregisteredAddresses: acceptsUnregisteredAddresses,
  opensTestControls: opensTestControls,
  authorizesDirectoryWrites: authorizesDirectoryWrites,
  requiresDirectoryBind: requiresDirectoryBind,
  withholdsDirectorySecrets: withholdsDirectorySecrets,
  protectsOperationalAttributes: protectsOperationalAttributes,
  requiresConfidentialDirectoryBinds: requiresConfidentialDirectoryBinds,
  limitsDirectoryBindFailures: limitsDirectoryBindFailures,
  sendsWeakerThanAsked: sendsWeakerThanAsked,
  refusesUnknownRevocationStatus: refusesUnknownRevocationStatus,
  requiresEnrollmentTls: requiresEnrollmentTls,
  opensIntrospection: opensIntrospection,
  acceptsUnsignedRequestObjects: acceptsUnsignedRequestObjects,
  acceptsLooseRequestUris: acceptsLooseRequestUris,
  embedsProtocolDebugger: embedsProtocolDebugger,
  limitsDebuggerDestinations: limitsDebuggerDestinations,
  dialsInternalAddresses: dialsInternalAddresses,
  acceptsNonconformingResourceMetadata: acceptsNonconformingResourceMetadata,
  gatesConsole: gatesConsole,
  gatesScim: gatesScim,
  gatesSharedSignals: gatesSharedSignals,
  gatesSpireServerApi: gatesSpireServerApi,
  REQUIREMENTS: REQUIREMENTS,
  NOT_YET: NOT_YET,
  report: report
};
