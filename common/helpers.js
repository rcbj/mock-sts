'use strict';
//
// File: helpers.js
//
// ---------------------------------------------------------------------------
// The things every other module of this mock needs, and nothing that belongs to
// one protocol.
//
// Three kinds of thing live here, and the reason each is shared rather than
// owned is worth knowing before moving anything out:
//
//   * the LOG and the artifact log. This mock exists to show what it did, so
//     every module writes to one logger at one level.
//   * the KEYS. One RSA key pair signs everything (SAML assertions, every JWT,
//     the RFC 8414 and OID4VCI metadata, the DID documents) and one BBS key pair
//     signs every ldp_vc credential. They are generated once per start, so they
//     cannot be per-module: two modules generating their own would publish two
//     keys under one issuer and the symptom is "the signature does not verify".
//   * the small helpers that more than one protocol needs — base64url, the
//     request's own base URL, a body parser that copes with form or JSON, the two
//     error-response shapes, and the mock's one user.
//
// The last group is why this file exists at all rather than each protocol
// keeping its own: `userFor`, `parseBody`, `oauthError`, `signJwt` and `vciError`
// were used across the OAuth2, OID4VCI and OID4VP sections, and leaving them in
// any one of those made the modules require each other in a CYCLE (the offer
// pages need the mock user; the authorization server needs the offer state).
// A cycle in node does not fail loudly — it hands back a half-initialised module
// whose exports are undefined, and the failure surfaces later as a function that
// is not a function. Keeping the shared leaves here is what makes the dependency
// graph a tree.
// ---------------------------------------------------------------------------

// CONFIG_FILE is made ABSOLUTE before it is read. This module lives in a
// subdirectory now, and a relative `./env/local.js` resolves against THIS
// directory rather than the package root — see common/config_file.js, which is
// required first for that reason and requires nothing itself.
require('./config_file').resolveConfigFile();
// NOTE that this module no longer requires CONFIG_FILE itself. It did — for the
// log level, before config.js existed — and the binding was dead by the time
// this was written, which mattered once CONFIG_FILE became optional: an unset
// variable made `require(undefined)` throw a TypeError naming an "id" argument
// nobody typed, out of a module that had no use for what it was loading.
// resolveConfigFile() above is still called, because eleven OTHER modules read
// the variable directly and this is one of the three places that runs early
// enough to make it absolute for them.
//
// Every setting this service has, resolved from the runtime overrides, the
// environment, and the two appconfig files in that order.
// It is BELOW this module in the dependency graph and requires nothing from
// here, which is what keeps the graph a tree (rule 3).
const config = require('./config');
const crypto = require('crypto');
const forge = require('node-forge');
const jwt = require('jsonwebtoken');
const bunyan = require("bunyan");
const bbs2023 = require('./vendored/bbs2023.js');
// TRUST REALMS. Two things in this file are per realm and both are here rather
// than in twenty modules for the same reason: this is where every one of them
// already looks. `baseUrlOf()` is how eighty call sites build a URL, and `STS`
// is how eight of them reach a signing key. realms.js requires config.js and
// nothing else here, so this cannot be a cycle.
const realms = require('./realms');
const log = bunyan.createLogger({ name: 'sts',
                                level: config.value('global.logLevel') });
// Registering it is what makes global.logLevel a setting rather than a claim:
// bunyan takes a level when the logger is created, so without this /admin/config
// could change the setting and every line after it would still be written at the
// level the process started with. This is the logger every protocol module
// destructures, so it is nearly all of them; see the note in config.js for the
// eight vendored krb5_* modules that cannot be registered.
config.registerLogger(log);
log.info("Log initialized. logLevel=" + log.level());

// ---------------------------------------------------------------------------
// Logging helpers.
//
// This is a mock whose whole purpose is to show what it did, so everything it
// produces is written down at debug level: the artifact BEFORE it was signed or
// encrypted, the artifact AFTER, and — for every endpoint — the request that
// came in, the response that went back, the status code and how long it took.
// ---------------------------------------------------------------------------

// A security artifact, recorded before and after it was protected.
//
//   what   'SAML assertion' / 'JWT' / 'SD-JWT VC' ...
//   stage  'before signing' / 'after signing' / 'before encryption' / ...
//   value  the object or string itself, recorded in full
function logArtifact(what, stage, value) {
  log.debug({ artifact: what,
              stage: stage,
              value: (typeof value === 'string') ? value : JSON.stringify(value) },
            what + ' ' + stage + '.');
}

// Headers with nothing removed: this mock issues test credentials only, and the
// point of the log is to be able to see exactly what was exchanged.
function headersOf(source) {
  const out = {};
  Object.keys(source || {}).forEach(function (k) { out[k] = source[k]; });
  return out;
}

// Bodies arrive (and leave) as strings or objects; either way they go in whole.
function bodyOf(value) {
  if (value === undefined || value === null) return '';
  return (typeof value === 'string') ? value : JSON.stringify(value);
}

// ---------------------------------------------------------------------------
// The one hook admin_stats.js needs, and the reason it is a hook rather than a
// require.
//
// The admin console has to know about every JWT this service issues, and
// signJwt() below is the single place all of them are minted — so counting them
// anywhere else would mean counting them at five call sites and forgetting the
// sixth. But `admin_stats.js` requires THIS file (it needs the log), so this file
// cannot require it back: a cycle in node hands back a half-initialised module
// whose exports are undefined, and the symptom arrives later as something that is
// not a function.
//
// So the direction is inverted. This file, the leaf, offers a slot; admin_stats.js
// installs itself in it at ITS require time. app.js requires admin_stats.js — which
// is not a trick to make the ordering work but a genuine dependency, since the call
// log in app.js is where the per-endpoint statistics are collected — and every
// protocol module requires app.js, so the recorder is installed before any route
// exists and therefore before any token can be minted.
//
// The recorder is called for its side effect only and its return value is ignored:
// statistics must never be able to stop a token being issued.
let jwtRecorder = null;

function setJwtRecorder(fn) {
  jwtRecorder = fn;
  log.debug("A JWT recorder was installed; every token this service signs will now be counted.");
}

// Read once, because the listener is bound with it before anything can ask
// for it again; config.js marks it restart-only for that reason and refuses
// to change it while this process runs.
const PORT = config.value('global.port');

// The bind address, likewise fixed once. 0.0.0.0 is every interface, which is
// what a container needs.
const HOST = config.value('global.host');

// ---------------------------------------------------------------------------
// ISSUER USED TO LIVE HERE, and it was ONE value doing three jobs: the SAML
// <Issuer>, the `iss` of the WS-Trust JWT, and the WS-Federation entityID.
// They shared a default and nothing else — an entityID names the identity
// provider, an Issuer names whoever signed an assertion — so a deployment
// that needed one of them to be its own real name had to change all three.
//
// They are now `saml.issuer`, `wstrust.issuer` and `wsfed.entityId` in
// config.js, all three still defaulting to `urn:wstrust:mock:sts` and all
// three still fed by STS_ISSUER when it is set, so nothing that worked before
// changed. Callers read them from config.js directly rather than through a
// re-export here: they are runtime-settable, so a constant captured at
// require time would be the one thing the console could not change.
// ---------------------------------------------------------------------------

// --- STS signing key/cert (generated once at startup) ----------------------
function makeStsKeys() {
  log.debug("Entering makeStsKeys().");
  const kp = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = kp.publicKey;
  cert.serialNumber = '02';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 5);
  const attrs = [{ name: 'commonName', value: 'ws-trust-mock-sts' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(kp.privateKey, forge.md.sha256.create());
  const certB64 = forge.pki.certificateToPem(cert)
    .replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  log.debug("Leaving makeStsKeys().");
  return {
    privateKeyPem: forge.pki.privateKeyToPem(kp.privateKey),
    certPem: forge.pki.certificateToPem(cert),
    certB64: certB64,
    // A `kid` names a KEY, so it is derived from the key material rather than
    // hard-coded. This key is regenerated on every start, and the kid was
    // previously a constant — so two instances of this mock (a stale container
    // beside a fresh one, or two ports during development) published the SAME kid
    // over DIFFERENT keys. A verifier matches the kid exactly, tries that one key,
    // fails, and reports "the signature does not verify", which reads like a
    // corrupt document instead of what it is: keys fetched from the wrong
    // instance. A per-key kid cannot collide, so the mismatch names itself.
    kid: 'sts-mock-' + forge.md.sha256.create().update(certB64).digest().toHex().slice(0, 12)
  };
}

// ---------------------------------------------------------------------------
// ONE SIGNING KEY PER TRUST REALM, AND `STS` IS A VIEW ONTO THE CURRENT ONE.
//
// A realm that shared the process's key would not be a trust realm. The whole
// claim a realm makes is that a token it issued is ITS token — so a verifier
// that fetched realm `acme`'s JWKS and is handed a token minted in the default
// realm must find that the signature does not verify. Two realms on one key
// would make every realm's tokens interchangeable, which is the one property
// somebody defining a second realm is trying not to have.
//
// LAZY, per realm: `makeStsKeys()` generates a 2048-bit RSA key, which is a
// tenth of a second, and a realm that has issued nothing has not paid for one.
// The default realm's is made on the first read, which is during module load
// here — so a service with no realms does exactly what it did before, at
// exactly the same moment.
//
// A PROXY rather than a function, and the reason is the call sites again: eight
// modules destructure `const { STS } = require('./helpers')` and then read
// `STS.kid`, `STS.certPem`, `STS.privateKey`. A function would have been
// `stsKeys().kid` at every one of them; the proxy leaves all eight untouched
// and correct. What it forwards is a property READ — there is nothing here that
// writes to STS after this file has finished, and the one thing that used to
// (`STS.privateKey = …` below) is now part of what the factory returns.
// ---------------------------------------------------------------------------
const stsKeysFor = realms.keyed(function (realm) {
  const keys = makeStsKeys();
  // ---------------------------------------------------------------------
  // THE SAME PRIVATE KEY AS AN ALREADY-PARSED `KeyObject`, and it is here for
  // speed rather than for tidiness.
  //
  // `jwt.sign(payload, pem, ...)` hands node a PEM STRING, and node has to turn
  // that string into a key before it can sign with it — every single time. That
  // parse is not a rounding error: under load it measured 21% of this service's
  // non-idle CPU, against 48% for the RSA signature it was preparing for, so
  // roughly a third of the cost of issuing a token was re-reading a key that had
  // not changed since startup. Parsing it once here took one signature from
  // 1.08ms to 0.48ms and rather more than doubled the token endpoint's
  // throughput.
  //
  // It lives ON the key set rather than beside it because every module that
  // signs already destructures `STS` from this file, so the eight call sites
  // needed nothing new imported. `privateKeyPem` is KEPT and is still what the
  // three XML signers use — xml-crypto takes the PEM — so nothing that read it
  // before had to change.
  //
  // It is derived rather than stored: there is exactly one private key per
  // realm and this is the same one, so the two cannot drift apart.
  // ---------------------------------------------------------------------
  keys.privateKey = crypto.createPrivateKey(keys.privateKeyPem);
  keys.realm = realm.id;
  log.info('A signing key was generated for the "' + realm.id + '" realm: kid=' +
           keys.kid + '.');
  return keys;
});

const STS = new Proxy({}, {
  get: function (target, prop) { return stsKeysFor()[prop]; },
  has: function (target, prop) { return prop in stsKeysFor(); },
  ownKeys: function () { return Reflect.ownKeys(stsKeysFor()); },
  getOwnPropertyDescriptor: function (target, prop) {
    const d = Object.getOwnPropertyDescriptor(stsKeysFor(), prop);
    // A proxy may not report a property as non-configurable when its target has
    // no such property, and this target is permanently empty. Marking every
    // descriptor configurable is what keeps Object.keys() and a spread legal
    // over this — the JWKS builder spreads it.
    return d ? Object.assign({}, d, { configurable: true }) : undefined;
  }
});


// Every document that carries or describes this key is served `Cache-Control:
// no-store` (the RFC 8414 metadata, the OID4VCI credential issuer metadata, the
// jwt-vc-issuer document and the JWKS). The key is regenerated on every start, so
// a cached copy of any of them outlives the key it describes — and the resulting
// failure is a signature that does not verify, which looks like a broken document
// rather than a stale one. Nothing about a mock is worth caching.

// --- helpers ---------------------------------------------------------------
function xmlEscape(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function genId() {
  return '_' + forge.util.bytesToHex(forge.random.getBytesSync(16));
}

// --- reading XML somebody else wrote ---------------------------------------
// An element, or its text, found by LOCAL NAME with the namespace ignored.
//
// Shared rather than owned because three readers need exactly this: WS-Trust
// parses an RST, WS-Federation parses the `wreq` RST that may ride on a sign-in
// request, and the mock relying party parses the `wresult` it is POSTed. All
// three are given XML written by somebody else, so the prefix is not knowable in
// advance and neither is the namespace: the trust namespace alone has four
// versions in use (2004/04, 2005/02, ws-sx 200512 and whatever a client invents),
// and WS-Federation's own responses are usually written with `t:` where this
// service writes `wst:`. Matching the local name is what lets one parser answer
// WS-Trust 1.0 through 1.4 instead of four, and it is the reason these are here
// and not in wstrust.js where they were written.
//
// getElementsByTagNameNS('*', name) searches DESCENDANTS ONLY, which is what
// every caller wants (find the UsernameToken anywhere in the SOAP envelope) but
// is worth stating: firstByLocal(el, 'Assertion') will not return `el` itself
// even when `el` IS the Assertion.
function firstByLocal(root, name) {
  const els = root.getElementsByTagNameNS('*', name);
  return els && els.length ? els[0] : null;
}

function textByLocal(root, name) {
  const e = firstByLocal(root, name);
  return e ? (e.textContent || '').trim() : '';
}

function iso(offsetMin) {
  return new Date(Date.now() + (offsetMin || 0) * 60000).toISOString();
}

// base64url, in both directions. Deliberately without entering/leaving logs:
// these are called several times per token and would drown the log.
function b64u(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64uDecode(s) {
  return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function jsonFromB64u(s) { return JSON.parse(b64uDecode(s).toString('utf8')); }

// Small and called constantly: no entering/leaving logs, they would drown the log.
function nowSec() { return Math.floor(Date.now() / 1000); }

function randomId(bytes) { return b64u(crypto.randomBytes(bytes || 24)); }

// One BBS key pair per start, like the RSA one. Generated lazily because key
// generation is async and the module loads synchronously.
let bbsKeys = null;

async function bbsKeyPair() {
  if (!bbsKeys) bbsKeys = await bbs2023.generateKeyPair();
  return bbsKeys;
}

// Request bodies arrive as raw text (the SOAP parser takes every content type),
// so form-encoded and JSON are both decoded here.
// ---------------------------------------------------------------------------
// DOES THIS SCOPE STRING CARRY THAT SCOPE.
//
// Here rather than in oauth2.js, where it was written, for the reason
// everything else in this file is here: more than one protocol needs it now.
// `scim_auth.js` reads it to decide whether an access token may write to the
// directory, and a second copy over there would be a second answer to "is
// `scim:write ` with a trailing space the write scope" — which is the kind of
// disagreement that shows up as one endpoint accepting a token another refuses.
//
// RFC 6749 section 3.3: a scope is a space-delimited, case-SENSITIVE list.
// Split on any run of whitespace rather than a single space, because a client
// that joined its scopes with a tab or sent one across a folded header is
// asking for exactly what it looks like it is asking for.
// ---------------------------------------------------------------------------
function hasScope(scope, name) {
  return String(scope || '').split(/\s+/).indexOf(name) >= 0;
}

function parseBody(req) {
  log.debug("Entering parseBody(). content-type=" + (req.headers['content-type'] || '(none)'));
  const raw = typeof req.body === 'string' ? req.body : '';
  const type = String(req.headers['content-type'] || '');
  if (/json/i.test(type)) {
    try {
      const parsed = JSON.parse(raw || '{}');
      log.debug("Leaving parseBody(). Parsed a JSON body.");
      return parsed;
    } catch (e) {
      log.error('the request body is not JSON: ' + e.message);
      log.debug("Leaving parseBody(). Nothing could be parsed.");
      return {};
    }
  }
  const out = {};
  new URLSearchParams(raw).forEach(function (v, k) { out[k] = v; });
  log.debug("Leaving parseBody(). Parsed a form-encoded body with " +
            Object.keys(out).length + " parameter(s).");
  return out;
}

function oauthError(res, status, error, description) {
  log.debug("Entering oauthError(). status=" + status + ", error=" + error);
  res.status(status).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify({ error: error, error_description: description }));
  log.debug("Leaving oauthError().");
}

// --- token minting ----------------------------------------------------------
// Every OAuth token this server issues goes through here, so this is where each
// one is recorded: the claim set before it is signed, and the JWT after.
//
// `context` is optional and is NOT part of the token: nothing in it is signed, read
// back or sent anywhere. It is how a caller states what the payload cannot say — at
// present the browser sign-on session the token was issued under and the grant that
// issued it, neither of which appears in any claim, because OIDC's `sid` is for
// front-channel logout and adding claims to every token to make an admin page easier
// to draw would change what every client receives. A caller that passes nothing is
// unaffected, which is why the parameter is at the end and optional.
function signJwt(payload, context) {
  log.debug("Entering signJwt(). typ=" + (payload.typ || '(none)'));
  logArtifact('OAuth token (' + (payload.typ || 'unknown') + ')', 'before signing',
              { header: { alg: 'RS256', kid: STS.kid }, payload: payload });
  const signed = jwt.sign(payload, STS.privateKey, { algorithm: 'RS256', keyid: STS.kid });
  logArtifact('OAuth token (' + (payload.typ || 'unknown') + ')', 'after signing', signed);
  // Every token this service issues passes through here, which is what makes the
  // admin console's count a count and not an estimate. Wrapped because a throw in
  // the statistics would otherwise fail the request that was issuing the token —
  // the tail wagging the dog.
  if (jwtRecorder) {
    try {
      jwtRecorder(payload, signed, context || null);
    } catch (e) {
      log.error('the JWT recorder threw and was ignored; the token itself is unaffected: ' + e.message);
    }
  }
  log.debug("Leaving signJwt().");
  return signed;
}

function vciError(res, status, error, description) {
  log.debug("Entering vciError(). status=" + status + ", error=" + error);
  res.status(status).type('application/json').send(JSON.stringify({
    error: error, error_description: description
  }));
  log.debug("Leaving vciError().");
}

// ---------------------------------------------------------------------------
// THE URL THIS SERVICE IS BEING REACHED AT, which is the thing every issuer,
// every endpoint in both discovery documents and every DID here is built from.
//
// It comes off the REQUEST rather than out of configuration, which is what
// makes one process answer correctly as http://localhost:8081 from a host run,
// as http://sts:8081 on a compose network and through a published port without
// being told which. That has been true since the beginning and none of it
// changes here.
//
// What is new is the reverse-proxy case RFC 9700 section 2.6 is about. When
// something terminates TLS in front of this service, the socket sees http and
// the last hop's host, while the CLIENT used https and a different name — so a
// document built from the socket publishes URLs no client can use, and an
// `iss` no client will accept. `X-Forwarded-Proto` and `X-Forwarded-Host` are
// how a proxy says what the client used.
//
// **They are believed only when `global.trustProxy` says a proxy is there.**
// With nothing in front, those are ordinary request headers and any caller can
// set them — so believing them would let a client choose what this service
// thinks its own issuer and endpoints are. The setting is the whole of the
// difference and it is read per request, so it can be turned on without a
// restart when somebody puts a proxy in.
//
// `forwardedFrom()` is shared with dpop.js's htu derivation, which used to make
// this decision differently — it honoured the headers unconditionally — so that
// two functions in one service disagreed about whether a forwarded header was
// believable. One function now, and one setting.
// ---------------------------------------------------------------------------
function trustProxy() {
  return !!config.value('global.trustProxy');
}

// The scheme and host a request should be understood as having arrived at:
// the forwarded ones where a proxy is trusted, the socket's otherwise. A
// comma-separated list takes its FIRST value, which is the client-facing hop —
// each proxy appends, so the left-hand end is the one furthest from here.
function forwardedFrom(req) {
  const socketProto = (req && req.protocol) || 'http';
  const socketHost = (req && req.get && req.get('host')) || ('localhost:' + PORT);
  if (!trustProxy()) {
    return { proto: socketProto, host: socketHost, forwarded: false };
  }
  const headers = (req && req.headers) || {};
  const proto = String(headers['x-forwarded-proto'] || socketProto)
    .split(',')[0].trim().toLowerCase() || socketProto;
  const host = String(headers['x-forwarded-host'] || socketHost)
    .split(',')[0].trim() || socketHost;
  return {
    proto: proto, host: host,
    forwarded: !!(headers['x-forwarded-proto'] || headers['x-forwarded-host'])
  };
}

// ---------------------------------------------------------------------------
// IT INCLUDES THE TRUST REALM'S PATH PREFIX, AND THAT ONE LINE IS WHY EIGHTY
// CALL SITES ARE REALM-AWARE WITHOUT HAVING BEEN EDITED.
//
// Every issuer identifier, every RFC 8414 and OpenID Provider metadata
// document, every SAML entityID and metadata URL, every credential issuer
// identifier, every did:web, every DPoP `htu` and every redirect this service
// builds is `baseUrlOf(req)` with a path glued to it. Returning
// `http://host:8081/realm/acme` here rather than `http://host:8081` makes all
// of them name the realm the request arrived in — which is exactly what makes
// two realms two authorization servers rather than one served twice.
//
// It is EMPTY in the default realm, so this is the same string it always was.
// ---------------------------------------------------------------------------
function baseUrlOf(req) {
  log.debug("Entering baseUrlOf().");
  const from = forwardedFrom(req);
  const base = from.proto + '://' + from.host + realms.currentPrefix();
  log.debug("Leaving baseUrlOf(). base=" + base +
            (from.forwarded ? " (from forwarded headers; global.trustProxy is on)" : ""));
  return base;
}


// Where the wallet lives, as a URL the BROWSER can use. Shared because the
// Credential Offer pages and the OID4VP request pages both hand the End-User back
// to it (oid4vp.walletUrl falls back to this one).
//
// A FUNCTION rather than the constant it used to be, and that is the shape
// every runtime-settable value takes here: a constant is read once at require
// time, so /admin/config could change the setting and every caller would go
// on using what it captured at startup.
function walletBaseUrl() {
  return config.value('oid4vci.walletUrl');
}

// Whoever signs in at the login screen. No password is ever checked; the
// username they type is the identity every token then describes.
function userFor(username) {
  log.debug("Entering userFor(). username=" + username);
  const name = String(username || 'mock-user');
  const user = {
    sub: 'urn:sts-mock:user:' + name,
    username: name,
    preferred_username: name,
    name: name + ' (mock)',
    given_name: name,
    family_name: 'Mock',
    email: name + '@sts-mock.example',
    email_verified: true
  };
  log.debug("Leaving userFor(). sub=" + user.sub);
  return user;
}

// ---------------------------------------------------------------------------
// THE ONE SPELLING OF A CERTIFICATE SUBJECT.
//
// Here rather than in `tls/tls_server.js`, where it was written, because FOUR
// callers now need the same string and two of them cannot reach that module.
// `scim_auth.js` and `spiffe_auth.js` require it directly and always could;
// `spiffe_ca.js` cannot, and the reason is rule 3e's test rather than a
// preference — `admin-ui/admin.js` requires `spiffe_ca.js`, and `server.js`
// requires `admin.js` at 18 and `tls_server.js` at 20, so a require from that
// module would pull every `/tls*` route into the express router ahead of the
// console's and `GET /admin/sts-metadata` walks that router. A leaf in
// `helpers.js` moves no route and closes no cycle, which is what a shared
// spelling has to be.
//
// WHY THIS FORM AT ALL, and why it is not what a report shows. Node hands a
// subject back most-significant-first (`C=US, O=Example, CN=alice`) and
// `openssl x509 -subject` prints it that way too. A DN as LDAP and every RFC
// 4514 document writes it is the REVERSE — leaf first, `CN=alice,O=Example,C=US`
// — with no spaces after the commas, and THAT is the form this service files an
// identity under and the directory builds an entry from. One form used for both
// would be wrong in whichever direction it was wrong: a report that disagreed
// with openssl, or a DN nothing in LDAP would accept.
//
// TWO SPELLINGS OF ONE DN IS TWO PEOPLE ON /admin/users, which is the whole
// reason this is one function. A verified TLS client certificate, a client
// certificate at the SCIM endpoints, an X509-SVID at the SPIRE Server API and
// an X509-SVID this service has just MINTED all produce a subject, and any two
// of them that render it differently put two objects in the directory for one
// identity.
//
// IT TAKES BOTH SHAPES NODE PRODUCES, because node has two and this service
// meets both. `tls.TLSSocket#getPeerCertificate()` gives an OBJECT keyed by
// attribute type, with repeated types collapsed into an array (`OU=A,OU=B`
// arrives as `OU: ['A','B']`, and those are separate RDNs rather than one
// multi-valued RDN, so each becomes its own component here).
// `crypto.X509Certificate#subject` gives a STRING with one `type=value` per
// LINE, in the same most-significant-first order — which is what
// `spiffe_ca.js` has, because it reads back the certificate it just issued
// rather than one that arrived on a socket. Anything else is returned as it
// stands.
//
// Values are ESCAPED. A comma inside `O=Example\, Ltd` that went through
// unescaped would turn one RDN into two and name an object that does not exist.
// ---------------------------------------------------------------------------
function escapeRdnValue(value) {
  const text = String(value == null ? '' : value);
  // RFC 4514 section 2.4: these are escaped anywhere, '#' only leading, and a
  // space only when it leads or trails.
  let out = text.replace(/([\\,+"<>;=])/g, '\\$1');
  if (out.indexOf('#') === 0) out = '\\' + out;
  out = out.replace(/^ /, '\\ ').replace(/ $/, '\\ ');
  return out;
}

function dnRfc4514(dn) {
  if (!dn) {
    return '';
  }
  // crypto.X509Certificate's shape: one `type=value` per line. Split rather
  // than parsed, because node has already done the parsing — a value that
  // itself contains a newline is not representable in that output and so
  // cannot arrive here.
  if (typeof dn === 'string') {
    if (dn.indexOf('\n') < 0) {
      // A single-component subject, or something already in one line. Returned
      // as it stands rather than guessed at: a caller that already holds an
      // RFC 4514 string must get it back unchanged.
      return dn.trim();
    }
    return dn.split('\n').map(function (line) {
      const text = String(line).trim();
      const eq = text.indexOf('=');
      if (eq < 0) {
        return '';
      }
      return text.slice(0, eq) + '=' + escapeRdnValue(text.slice(eq + 1));
    }).filter(function (part) {
      return part !== '';
    }).reverse().join(',');
  }
  if (typeof dn !== 'object') {
    return String(dn);
  }
  const parts = [];
  Object.keys(dn).forEach(function (key) {
    const value = dn[key];
    (Array.isArray(value) ? value : [value]).forEach(function (one) {
      parts.push(key + '=' + escapeRdnValue(one));
    });
  });
  return parts.reverse().join(',');
}

module.exports = {
  log: log,
  logArtifact: logArtifact,
  headersOf: headersOf,
  bodyOf: bodyOf,
  PORT: PORT,
  HOST: HOST,
  STS: STS,
  xmlEscape: xmlEscape,
  genId: genId,
  firstByLocal: firstByLocal,
  textByLocal: textByLocal,
  iso: iso,
  baseUrlOf: baseUrlOf,
  forwardedFrom: forwardedFrom,
  trustProxy: trustProxy,
  b64u: b64u,
  b64uDecode: b64uDecode,
  jsonFromB64u: jsonFromB64u,
  nowSec: nowSec,
  randomId: randomId,
  bbsKeyPair: bbsKeyPair,
  walletBaseUrl: walletBaseUrl,
  parseBody: parseBody,
  oauthError: oauthError,
  vciError: vciError,
  signJwt: signJwt,
  setJwtRecorder: setJwtRecorder,
  userFor: userFor,
  hasScope: hasScope,
  escapeRdnValue: escapeRdnValue,
  dnRfc4514: dnRfc4514,
  // The whole key set of ONE named realm, for the two callers that need a
  // realm's key while not in that realm: the console's realm list, which shows
  // each realm's kid, and the logout that has to know whose token it is looking
  // at. Everything else reads `STS` and gets the ambient realm's, which is what
  // it wanted.
  stsKeysFor: stsKeysFor
};
