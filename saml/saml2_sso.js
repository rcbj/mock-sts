'use strict';
//
// File: saml2_sso.js
//
// ===========================================================================
// SAML 2.0 — the Web Browser SSO profile, all three bindings, and Single Logout.
//
// **THIS FILE REVERSES A DOCUMENTED NON-GOAL.** Until 2026-08-24 the sentence
// "there is no SAML 2.0 Web SSO profile" appeared in README.md, in the root
// `CLAUDE.md`, in `saml/CLAUDE.md`, in `ws-federation/wsfed.js` (which is why
// its federation metadata publishes no IDPSSODescriptor), and in
// `sts_metadata.js` twice — once in the `saml2` coverage note and once on the
// SAML 2.0 protocol card, which said NO ROUTE OF ITS OWN. Every one of those had
// to be qualified rather than deleted, because the reason each of them EXISTED
// is still worth a reader's attention: this service was an assertion issuer with
// no browser-facing profile for a long time, deliberately, and the absence was
// documented so that nobody would take it for an oversight. What follows is the
// profile.
//
//   GET|POST /saml2/sso[/{sp}]      the Single Sign-On service. HTTP Redirect
//                                   (section 3.4) and HTTP POST (3.5) alike —
//                                   the binding is how the request ARRIVED, and
//                                   the AuthnRequest's own ProtocolBinding says
//                                   how the response goes back.
//   POST     /saml2/ars[/{sp}]      the Artifact Resolution Service, SOAP over
//                                   HTTP (3.2.3). This is the back channel the
//                                   Browser/Artifact profile rests on.
//   GET|POST /saml2/slo[/{sp}]      Single Logout (saml-profiles §4.4), both
//                                   directions: a LogoutRequest arriving from a
//                                   service provider, and this identity
//                                   provider starting one itself.
//   GET      /saml2/metadata[/{sp}] the SIGNED IdP metadata, and the interesting
//                                   half of this feature — see below.
//   GET      /saml2/autopost.js     the one script an HTTP POST response runs.
//   GET|POST /saml2/sp              a mock SERVICE PROVIDER. NON-SPEC, the
//                                   default assertion consumer service, and
//                                   where a response can be verified check by
//                                   check without a second service.
//   GET      /saml2                 what all of that is, for somebody who
//                                   clicked the link.
//
// ---------------------------------------------------------------------------
// SIX DECISIONS HERE ARE NOT OBVIOUS FROM THE SPECIFICATIONS.
//
// 1. **THE METADATA IS UNIQUE PER SERVICE PROVIDER, and it is minted for any
//    entityID that is asked for.** `/saml2/metadata/{sp}` names an identity
//    provider of its own — `urn:sts-mock:idp:{sp}` — with its own SSO, SLO and
//    artifact endpoints under that same `{sp}` segment, which is what Okta and
//    Ping do and what a service provider integrating with one of them expects.
//    It 404s for nothing: an entityID nobody has registered is registered BY
//    THE ASK, so a service provider can be pointed at this service before
//    anything at all has been provisioned. `saml2.perApplicationEntityId` turns
//    the per-application entityID off for a service provider library that keys
//    its trust store off the entityID and is surprised to find a new one per
//    application; the ENDPOINTS stay per-application either way, because that is
//    what makes the documents worth having separately.
//
// 2. **THERE IS NO SIGN-IN SCREEN IN THIS FILE, and that is the deliberate
//    difference from `ws-federation/wsfed.js`.** That module has one because
//    section 13.2.1 lets a WS-Federation sign-in request arrive as a cross-site
//    form POST, which `SameSite=Lax` keeps the session cookie off, so it cannot
//    read the session it would need to skip the screen. The HTTP POST binding
//    has exactly the same problem — and the answer here is to STASH the request
//    and 303 the browser to a GET on this same endpoint, which is a top-level
//    GET navigation and therefore DOES carry a Lax cookie. So this profile
//    reaches `authn.js`'s screen through `beginAuthentication()` like the
//    authorization endpoint does, and three things follow that WS-Federation
//    does not get: single sign-on with OAuth and WS-Federation in one session, a
//    WebAuthn ceremony available at the screen, and one fewer place asking for a
//    username. A screen of this profile's own would have been a second
//    authentication service for no reason at all.
//
// 3. **EVERY ENTITYID IS ACCEPTED AND NOTHING IS VERIFIED — including a
//    signature the service provider went to the trouble of making.** A signed
//    AuthnRequest's certificate is RECORDED on the application entry
//    (`samlSigningCertificate`) and the fact that it was signed is recorded
//    beside it, and neither is checked. That is the same posture as everywhere
//    else here — this service checks no password, validates no access token and
//    attests no workload — and it is stated rather than left to be discovered,
//    because a mock that silently ignored a signature would let a service
//    provider believe its signing was being exercised. What the recording buys
//    is that the check has somewhere to READ FROM the day it is wanted.
//
// 4. **THE ASSERTION IS BUILT BY `saml2.js` AND NOT BY THIS FILE.** That module
//    gained five options for this profile (a NameID format, a
//    SubjectConfirmationData, a session index, an authentication instant and an
//    issuer) rather than a second builder, for the reason its own header gives:
//    one assertion writer means one place where the element order, the namespace
//    and the signature location are decided, and those are exactly what a
//    service provider's parser is strict about. It also means the custom SAML
//    2.0 attributes configured on `/admin/saml-attributes` reach an assertion
//    issued HERE with no wiring at all — the same line that puts them in a
//    WS-Trust or WS-Federation assertion puts them in this one, which is the
//    property that would have been lost by writing a second builder.
//
// 5. **THE RESPONSE IS SIGNED AS WELL AS THE ASSERTION, and both are settings.**
//    `saml2.signAssertion` and `saml2.signResponse` are ON by default because
//    that is what AD FS and Keycloak do and it is what a strict service provider
//    checks. Turning either off is a test case rather than a mistake: a service
//    provider that accepts an unsigned assertion has a hole in it, and this is
//    how somebody finds that out. On the HTTP Redirect binding `signResponse`
//    means the QUERY STRING signature of section 3.4.4.1, which is what a
//    redirect response is really verified by — an XML signature is there too and
//    is not what that binding's verifier reads.
//
// 6. **THE ARTIFACT IS ONE-SHOT AND SAYS SO.** Section 3.6.4.1 requires that an
//    artifact be resolvable exactly once, and no lifetime setting can express
//    that — so resolving one DESTROYS it, and a second ArtifactResolve for the
//    same artifact is refused with a status naming the reason rather than
//    answering with the message again. It is the single easiest thing to get
//    wrong in this profile and the hardest to notice, because the happy path
//    passes either way.
// ===========================================================================

const zlib = require('zlib');
// TRUST REALMS: the stores below are partitioned by realm. It requires
// config.js and nothing else here, so it cannot join a cycle and it registers
// no route, so its position is not a position at all.
const realms = require('../common/realms');
const crypto = require('crypto');
const { DOMParser } = require('@xmldom/xmldom');
const { SignedXml } = require('xml-crypto');
const app = require('../common/app');
const { log, logArtifact, STS, xmlEscape, genId, iso, baseUrlOf, randomId,
        parseBody, firstByLocal, textByLocal } = require('../common/helpers');
// Read per request rather than captured at require time, so that /admin/config
// and /admin-api can change what the next response says and how it is signed.
const config = require('../common/config');
// The one assertion writer. See decision 4.
const { buildSamlAssertion } = require('./saml2');
// The session, from the service that owns it. This profile starts none of its
// own: `beginAuthentication()` sends the browser to authn.js's screen and back.
const { sessionOf, endSession, beginAuthentication } = require('../authn/authn');
// The application registry, which lives under ou=applications in the embedded
// directory. A library that registers no route, so requiring it here changes
// nothing about the route order this module's position in server.js fixes.
const applications = require('../common/applications');

// --- the vocabulary --------------------------------------------------------
const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';

const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';

const NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata';

const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

const NS_SOAP = 'http://schemas.xmlsoap.org/soap/envelope/';

const BINDING_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

const BINDING_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

const BINDING_ARTIFACT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact';

const BINDING_SOAP = 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP';

const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

const STATUS_REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester';

const STATUS_RESPONDER = 'urn:oasis:names:tc:SAML:2.0:status:Responder';

const STATUS_NO_PASSIVE = 'urn:oasis:names:tc:SAML:2.0:status:NoPassive';

const STATUS_PARTIAL_LOGOUT = 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout';

const SIG_RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

const DIGEST_SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

const C14N_EXCLUSIVE = 'http://www.w3.org/2001/10/xml-exc-c14n#';

const TRANSFORM_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

// The NameID formats this identity provider ADVERTISES. It is not a list of
// what it will accept: a NameIDPolicy naming something outside this list is
// answered with the format it asked for (see nameIdFormatFor), because a
// service provider being handed back its own format is the behaviour worth
// exercising and InvalidNameIDPolicy would remove the test case. The list is
// what goes in the metadata, and a service provider's configuration UI is
// usually built from exactly this.
const NAMEID_FORMATS = [
  'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName',
  'urn:oasis:names:tc:SAML:2.0:nameid-format:entity'
];

// How the End-User authenticated, in SAML 2.0's vocabulary. This answers the
// same question `wsfed.js`'s authnMethodsFor() answers and is deliberately NOT
// shared with it, for two reasons worth stating rather than leaving as an
// apparent duplication: a require from here to `ws-federation/` would make the
// newer and more widely spoken profile depend on the older and more niche one,
// and half of that function is the SAML 1.1 AuthenticationMethod vocabulary,
// which has no meaning in this file at all. The three outcomes and the reasoning
// behind each URI ARE that function's, and if one of them changes both should.
const AC_PASSWORD = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';

const AC_UNSPECIFIED = 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified';

// Microsoft's, and used here for the reason wsfed.js records: SAML 2.0's own
// authentication context classes have no member that describes a WebAuthn
// hardware key without overstating what happened.
const AC_MULTIFACTOR = 'http://schemas.microsoft.com/claims/multipleauthn';

// A RequestedAuthnContext naming one of these is read as "a second factor is
// required", and the sign-in screen is asked for one rather than the request
// being refused. That is the opposite of what WS-Federation's `wauth` does with
// the same demand, and the difference is real rather than an inconsistency: the
// screen this profile uses CAN run a WebAuthn ceremony, so the demand can be
// MET here, where over there it could only have been faked.
const AC_MFA_DEMANDS = [
  AC_MULTIFACTOR,
  'urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract',
  'urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken',
  'urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI',
  'http://schemas.microsoft.com/claims/multipleauthn'
];

const BASE_PATH = '/saml2';

const SSO_PATH = BASE_PATH + '/sso';

const SLO_PATH = BASE_PATH + '/slo';

const ARS_PATH = BASE_PATH + '/ars';

const METADATA_PATH = BASE_PATH + '/metadata';

const SP_PATH = BASE_PATH + '/sp';

// The AuthnRequest interrupted by the sign-in screen, and the AuthnRequest that
// arrived by POST and has to become a GET before the session cookie is visible.
// One map for both, because they are the same thing: a request this service is
// holding while the browser goes somewhere and comes back.
const REQUEST_TTL_MS = 10 * 60 * 1000;

// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const pendingRequests = realms.map();

// Artifact -> the message it stands for. See decision 6: resolving one deletes
// it, so this map is also the record of what has NOT been resolved yet.
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const artifacts = realms.map();

// The RelayState values the mock service provider below has minted, so it can
// check the round trip. Its own state and nobody else's, exactly as
// /wsfed/rp's rpContexts is.
const SP_CONTEXT_TTL_MS = 30 * 60 * 1000;

// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const spContexts = realms.map();

// ---------------------------------------------------------------------------
// WHICH SERVICE PROVIDER A PATH NAMES.
//
// `{sp}` is a URL PATH SEGMENT, and an entityID is usually a URL — so it cannot
// simply be the entityID. Two spellings are accepted and they cover between them
// everything anybody types:
//
//   * the entityID itself, percent-encoded, which is what a machine generates
//     and what `/admin/saml2` links to;
//   * a SLUG, which is the entityID when it is already safe in a path segment
//     and `app-<12 hex of its sha256>` when it is not — the same device
//     `applications.js`'s shortName() uses on an RDN, and for the same reason:
//     the short form is not the identity, it is a handle for it.
//
// The consequence to keep in mind is that a slug is NOT reversible, so resolving
// one means asking the registry which of the applications it holds has that
// slug. That is a scan, and it is a scan of a mock's in-memory directory rather
// than of anything expensive.
// ---------------------------------------------------------------------------
const SAFE_SEGMENT = /^[A-Za-z0-9._~-]{1,64}$/;

function slugOf(identifier) {
  const text = String(identifier == null ? '' : identifier);
  if (SAFE_SEGMENT.test(text)) {
    return text;
  }
  return 'app-' + crypto.createHash('sha256').update(text, 'utf8')
    .digest('hex').slice(0, 12);
}

// The entityID a path segment names, and whether this service had heard of it.
// It NEVER answers "no such service provider" — see decision 1. A segment that
// matches nothing is taken to BE an entityID, which is what makes the metadata
// endpoint answer for anything asked of it.
function entityIdFromSegment(segment) {
  log.debug("Entering entityIdFromSegment(). segment=" + (segment || '(none)'));
  const text = String(segment == null ? '' : segment).trim();
  if (!text) {
    log.debug("Leaving entityIdFromSegment(). The unscoped endpoint.");
    return { entityId: '', known: false, unscoped: true };
  }
  // Express has already percent-decoded the parameter, so an entityID that was
  // encoded into the path arrives whole here.
  const direct = applications.get(text);
  if (direct) {
    log.debug("Leaving entityIdFromSegment(). It is a known identifier.");
    return { entityId: text, known: true, unscoped: false };
  }
  // A slug, then — which has to be looked for, because it cannot be reversed.
  const match = applications.list().filter(function (row) {
    return slugOf(row.identifier) === text;
  })[0];
  if (match) {
    log.debug("Leaving entityIdFromSegment(). A slug for " + match.identifier + ".");
    return { entityId: match.identifier, known: true, unscoped: false };
  }
  log.debug("Leaving entityIdFromSegment(). Nothing here knows it; it IS the entityID.");
  return { entityId: text, known: false, unscoped: false };
}

// This identity provider's own entityID, for a given service provider. See
// decision 1 for why there is more than one of them, and
// `saml2.perApplicationEntityId` for turning that off.
function idpEntityIdFor(spEntityId) {
  const base = String(config.value('saml2.entityId') || 'urn:sts-mock:idp');
  if (!spEntityId || !config.value('saml2.perApplicationEntityId')) {
    return base;
  }
  return base + ':' + slugOf(spEntityId);
}

// Where this service provider's endpoints live. One function so that the
// metadata document and the handlers cannot disagree about a URL — the failure
// that produces is a service provider configured from a document, posting to a
// path nothing serves, and a 404 that looks like the identity provider is down.
function endpointsFor(base, spEntityId) {
  const suffix = spEntityId ? '/' + encodeURIComponent(slugOf(spEntityId)) : '';
  return {
    sso: base + SSO_PATH + suffix,
    slo: base + SLO_PATH + suffix,
    ars: base + ARS_PATH + suffix,
    metadata: base + METADATA_PATH + suffix
  };
}

// ---------------------------------------------------------------------------
// THE REGISTRY.
//
// Every entityID this profile answers for gets an application entry, and this
// is the one place that happens. `counts` is the argument that matters:
// `applications.seen()` counts an AUTHENTICATION unless told otherwise, and an
// AuthnRequest arriving is not one — the person may never sign in. So the
// request records the sighting with `counts: false` and the RESPONSE, which is
// the moment this service has decided to tell that service provider who
// somebody is, records the authentication.
// ---------------------------------------------------------------------------
function recordServiceProvider(detail) {
  log.debug("Entering recordServiceProvider(). identifier=" + (detail.identifier || '(none)'));
  if (!config.value('saml2.autocreateApplications')) {
    log.debug("Leaving recordServiceProvider(). saml2.autocreateApplications is off.");
    return null;
  }
  const record = applications.seen(detail);
  log.debug("Leaving recordServiceProvider().");
  return record;
}

// What the registry already knows about this service provider, as plain fields.
// Absent everywhere the directory is (see applications.js's header — without
// ldap_server.js there is no registry at all), so every caller has to cope with
// an empty object rather than with null.
function fieldsOf(spEntityId) {
  const row = spEntityId ? applications.get(spEntityId) : null;
  return (row && row.fields) || {};
}

// --- reading a message off the wire ----------------------------------------
// Both bindings, one function. The difference between them is entirely in the
// ENCODING and in where the signature lives:
//
//   HTTP Redirect (3.4)  SAMLRequest is DEFLATE (raw, no zlib header) then
//                        base64 then URL-encoded, and the signature is a
//                        DETACHED one over the query string in `Signature`,
//                        with `SigAlg` naming the algorithm.
//   HTTP POST (3.5)      SAMLRequest is base64 of the XML with no compression,
//                        and the signature is an enveloped ds:Signature INSIDE
//                        the document.
//
// The decode accepts either shape whichever binding it arrived on, and that is
// deliberate: a service provider that DEFLATEs a POST-binding message is out of
// profile and is also common, and refusing it would produce "invalid request"
// where the useful answer is the assertion it was asking for. What is NOT
// guessed at is which binding it was — that comes from the HTTP method.
function decodeMessage(encoded) {
  log.debug("Entering decodeMessage().");
  const buf = Buffer.from(String(encoded || ''), 'base64');
  if (buf.length && buf[0] === 0x3c) {
    log.debug("Leaving decodeMessage(). Plain base64 XML.");
    return buf.toString('utf8');
  }
  try {
    const inflated = zlib.inflateRawSync(buf).toString('utf8');
    log.debug("Leaving decodeMessage(). DEFLATEd.");
    return inflated;
  } catch (e) {
    // Not DEFLATEd after all — a POST-binding message with leading whitespace,
    // most often. Read as plain XML, which is what it then is.
    log.debug("Leaving decodeMessage(). Not DEFLATEd: " + e.message);
    return buf.toString('utf8');
  }
}

function encodeRedirect(xml) {
  return zlib.deflateRawSync(Buffer.from(xml, 'utf8')).toString('base64');
}

function encodePost(xml) {
  return Buffer.from(xml, 'utf8').toString('base64');
}

// The parameters of a SAML message, from a GET query or a form POST. The body
// wins on a collision for the reason `wsfed.js`'s paramsOf() gives: a POST that
// also carried query parameters said the same thing twice and the body is the
// half it meant.
function paramsOf(req) {
  log.debug("Entering paramsOf(). method=" + req.method);
  const out = {};
  Object.keys(req.query || {}).forEach(function (k) { out[k] = req.query[k]; });
  if (req.method === 'POST') {
    const body = parseBody(req);
    Object.keys(body).forEach(function (k) { out[k] = body[k]; });
  }
  log.debug("Leaving paramsOf(). " + Object.keys(out).length + " parameter(s).");
  return out;
}

// --- the pages -------------------------------------------------------------
// One shell, and it is `wsfed.js`'s: the CSS is inline because app.js sets
// `default-src 'none'` with `style-src 'unsafe-inline'`, so a stylesheet as a
// separate resource would need its own exception to buy nothing.
function page(title, inner) {
  return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + xmlEscape(title) + '</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'padding:2rem;color:#222;line-height:1.45}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:24px 28px;' +
    'max-width:56rem;margin:0 auto;box-shadow:0 6px 24px rgba(0,0,0,.08)}' +
    'h1{font-size:1.3em;margin:0 0 4px;color:#12107c}h2{font-size:1em;margin:1.4em 0 .4em}' +
    'p.sub{color:#666;font-size:.85em;margin:0 0 18px}' +
    '.row{display:flex;gap:10px;margin-top:20px}' +
    'button{padding:9px 14px;border-radius:5px;border:1px solid #12107c;background:#12107c;color:#fff;' +
    'font-size:.95em;cursor:pointer}button.secondary{background:#fff;color:#12107c}' +
    '.err{background:#fdecea;border:1px solid #f5c6c2;color:#b00020;padding:8px 10px;border-radius:5px;' +
    'font-size:.9em;margin-bottom:12px}' +
    '.ok{background:#e8f5e9;border:1px solid #a5d6a7;padding:8px 10px;border-radius:5px;' +
    'font-size:.9em;margin-bottom:12px}' +
    'table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;font-size:.85em}' +
    'th,td{border:1px solid #ddd;padding:.35rem .55rem;text-align:left;vertical-align:top}' +
    'th{background:#f0f0f5}.pass{color:#0b6b4f;font-weight:600;white-space:nowrap}' +
    '.fail{color:#b00020;font-weight:600;white-space:nowrap}' +
    '.meta{margin-top:18px;padding-top:12px;border-top:1px solid #eee;font-size:.78em;color:#666;' +
    'word-break:break-all}.meta div{margin:3px 0}' +
    'pre{background:#f4f4f8;border:1px solid #e2e2ea;border-radius:5px;padding:.6rem;font-size:.75rem;' +
    'overflow-x:auto;white-space:pre-wrap;word-break:break-all}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em;background:#f4f4f8;' +
    'padding:.1rem .25rem;border-radius:3px;word-break:break-all}a{color:#12107c}' +
    'ul{margin:.3em 0;padding-left:1.2em}li{margin:.2em 0}' +
    '</style></head><body><div class="card">' + inner + '</div></body></html>\n';
}

function sendPage(res, status, title, inner) {
  res.status(status).type('text/html').set('Cache-Control', 'no-store').send(page(title, inner));
}

// A sentence naming what was wrong, and a status. It is a PAGE and not a SAML
// error response, and which of the two a failure gets is a real distinction
// this profile makes: once the assertion consumer service URL is known, an
// error goes BACK TO THE SERVICE PROVIDER as a <samlp:Response> with a status
// code, because that is what section 3.2.2 says and because a service provider's
// error handling is the half of it least likely to have been tested. Before that
// point there is nowhere to send anything, and the page is the only honest
// answer — the same position `wsfed.js` is in for its whole profile.
function samlError(res, status, title, detail, extra) {
  log.debug("Entering samlError(). status=" + status + ", title=" + title);
  const inner = '<h1>' + xmlEscape(title) + '</h1>' +
    '<p class="sub">SAML 2.0 Web Browser SSO at <code>' + SSO_PATH + '</code></p>' +
    '<div class="err">' + xmlEscape(detail) + '</div>' + (extra || '') +
    '<div class="meta"><div>This is a page rather than a <code>&lt;samlp:Response&gt;</code> ' +
    'because the request never got as far as naming somewhere to send one. Once an assertion ' +
    'consumer service URL is known, a failure is delivered there as a Response carrying a status ' +
    'code — which is what section 3.2.2 requires and is the error path a service provider is ' +
    'least likely to have exercised. The request is logged in full at debug level.</div></div>';
  res.status(status).type('text/html').set('Cache-Control', 'no-store').send(page(title, inner));
  log.debug("Leaving samlError().");
}

// --- signing ---------------------------------------------------------------
// The enveloped XML signature this service puts on a Response, an
// ArtifactResponse and its own metadata. The DIFFERENCE between the three is the
// reference and where the signature goes, and both are schema-mandated rather
// than a matter of taste: a protocol message puts ds:Signature after Issuer, and
// a metadata EntityDescriptor puts it FIRST. Getting either wrong produces a
// document that verifies and that a strict parser rejects, which is the worst of
// both.
function signDocument(xml, rootLocalName, id, placement) {
  log.debug("Entering signDocument(). root=" + rootLocalName + ", placement=" + placement);
  const sig = new SignedXml({ privateKey: STS.privateKeyPem, publicCert: STS.certPem });
  sig.signatureAlgorithm = SIG_RSA_SHA256;
  sig.canonicalizationAlgorithm = C14N_EXCLUSIVE;
  sig.addReference({
    xpath: "/*[local-name(.)='" + rootLocalName + "']",
    transforms: [TRANSFORM_ENVELOPED, C14N_EXCLUSIVE],
    digestAlgorithm: DIGEST_SHA256,
    uri: id ? ('#' + id) : ''
  });
  // `after-issuer` for a protocol message, `prepend` for metadata. Written as
  // two locations rather than two functions because everything else about the
  // signature is identical, and a second function is where the two drift.
  const location = placement === 'prepend'
    ? { reference: "/*[local-name(.)='" + rootLocalName + "']", action: 'prepend' }
    : { reference: "/*[local-name(.)='" + rootLocalName + "']/*[local-name(.)='Issuer']",
        action: 'after' };
  sig.computeSignature(xml, { location: location });
  const signed = sig.getSignedXml();
  log.debug("Leaving signDocument(). " + signed.length + " characters.");
  return signed;
}

// The HTTP Redirect binding's DETACHED signature (section 3.4.4.1). It is a
// signature over the QUERY STRING and not over the document, and the order of
// the parameters in the signed octet string is part of the specification:
// SAMLRequest or SAMLResponse, then RelayState if there is one, then SigAlg.
// A verifier rebuilds that string from the parameters as they arrived, so a
// signer that used a different order produces a signature that verifies nowhere
// and whose only symptom at the far end is "invalid signature".
function signQueryString(queryString) {
  log.debug("Entering signQueryString().");
  const signature = crypto.createSign('RSA-SHA256')
    .update(queryString, 'utf8').sign(STS.privateKeyPem).toString('base64');
  log.debug("Leaving signQueryString().");
  return signature;
}

// --- what a session says ---------------------------------------------------
// THREE outcomes, because /authn/login can use a security key in either of two
// roles: after a password (two factors) or instead of one (one factor, and a
// key). See the note on AC_PASSWORD above for why the passwordless case is
// `unspecified` rather than one of SAML's named classes.
function authnContextFor(session) {
  log.debug("Entering authnContextFor().");
  const amr = (session && session.amr) || [];
  const hardwareKey = amr.indexOf('hwk') >= 0;
  const password = amr.indexOf('pwd') >= 0;
  if ((hardwareKey && password) || (session && session.acr === 'mfa')) {
    log.debug("Leaving authnContextFor(). Multi-factor.");
    return { classRef: AC_MULTIFACTOR, multiFactor: true, hardwareKey: hardwareKey };
  }
  if (hardwareKey) {
    log.debug("Leaving authnContextFor(). A security key, and one factor.");
    return { classRef: AC_UNSPECIFIED, multiFactor: false, hardwareKey: true };
  }
  log.debug("Leaving authnContextFor(). A password.");
  return { classRef: AC_PASSWORD, multiFactor: false, hardwareKey: false };
}

// --- reading an AuthnRequest ------------------------------------------------
// Everything section 3.4.1 of saml-core puts on one, plus the two things the
// bindings put beside it. Nothing here REFUSES anything: an attribute this
// service does not act on is recorded so that the log and the console can show
// what the service provider actually sent, which for a debugging service is the
// whole point.
function readAuthnRequest(xml) {
  log.debug("Entering readAuthnRequest().");
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const root = doc.documentElement;
  if (!root || root.localName !== 'AuthnRequest') {
    log.debug("Leaving readAuthnRequest(). It is not an AuthnRequest.");
    return { ok: false, why: 'the message is <' + (root ? root.localName : 'nothing') +
                             '> and this endpoint reads <samlp:AuthnRequest>' };
  }
  const policy = firstByLocal(root, 'NameIDPolicy');
  const requested = firstByLocal(root, 'RequestedAuthnContext');
  const out = {
    ok: true,
    xml: xml,
    id: root.getAttribute('ID') || '',
    version: root.getAttribute('Version') || '',
    issueInstant: root.getAttribute('IssueInstant') || '',
    destination: root.getAttribute('Destination') || '',
    protocolBinding: root.getAttribute('ProtocolBinding') || '',
    acsUrl: root.getAttribute('AssertionConsumerServiceURL') || '',
    acsIndex: root.getAttribute('AssertionConsumerServiceIndex') || '',
    forceAuthn: String(root.getAttribute('ForceAuthn') || '') === 'true',
    isPassive: String(root.getAttribute('IsPassive') || '') === 'true',
    issuer: textByLocal(root, 'Issuer'),
    nameIdFormat: policy ? (policy.getAttribute('Format') || '') : '',
    allowCreate: policy ? String(policy.getAttribute('AllowCreate') || '') === 'true' : false,
    subjectHint: '',
    requestedAuthnContexts: [],
    signed: !!firstByLocal(root, 'Signature'),
    signingCertificate: ''
  };
  // A <saml:Subject> on an AuthnRequest is the service provider saying WHO it
  // expects — section 3.4.1 allows it and most identity providers ignore it.
  // This one reads it as a hint to pre-fill the sign-in screen with, which is
  // exactly what OIDC's `login_hint` gets, and never as an assertion about who
  // is at the browser.
  const subject = firstByLocal(root, 'Subject');
  if (subject) {
    const nameId = firstByLocal(subject, 'NameID');
    out.subjectHint = nameId ? (nameId.textContent || '').trim() : '';
  }
  if (requested) {
    const refs = requested.getElementsByTagNameNS('*', 'AuthnContextClassRef');
    for (let i = 0; i < refs.length; i++) {
      out.requestedAuthnContexts.push((refs[i].textContent || '').trim());
    }
  }
  // The certificate off a signed request's KeyInfo. RECORDED AND NOT CHECKED —
  // decision 3 — so this is the material a verification would read the day one
  // is wanted, and nothing today depends on it.
  const certEl = firstByLocal(root, 'X509Certificate');
  if (certEl) {
    out.signingCertificate = (certEl.textContent || '').replace(/\s+/g, '');
  }
  log.debug("Leaving readAuthnRequest(). id=" + out.id + ", issuer=" + out.issuer +
            ", binding=" + (out.protocolBinding || '(unstated)'));
  return out;
}

// Which binding the RESPONSE goes back on. The request's ProtocolBinding says,
// and HTTP POST is the default when it says nothing — which is section 4.1.2's
// own default and is what every service provider that omits it expects. A
// binding this service does not implement is named in the refusal rather than
// silently downgraded to POST: a service provider that asked for PAOS and
// received a form post would conclude that PAOS worked.
function responseBindingFor(request) {
  log.debug("Entering responseBindingFor(). asked=" + (request.protocolBinding || '(none)'));
  const asked = String(request.protocolBinding || '');
  if (!asked) {
    log.debug("Leaving responseBindingFor(). HTTP POST, the default.");
    return { binding: BINDING_POST, stated: false };
  }
  if (asked === BINDING_POST || asked === BINDING_REDIRECT || asked === BINDING_ARTIFACT) {
    log.debug("Leaving responseBindingFor(). " + asked);
    return { binding: asked, stated: true };
  }
  log.debug("Leaving responseBindingFor(). It is not one this service has.");
  return { error: asked };
}

// The NameID Format to answer with. See `saml2.nameIdFormat`: a request naming a
// format gets that format back, whatever it is.
function nameIdFormatFor(request) {
  const asked = String(request.nameIdFormat || '');
  if (asked) {
    return asked;
  }
  return String(config.value('saml2.nameIdFormat') ||
                'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');
}

// The NameID VALUE. Every format but one is answered with the username, because
// this service invents no second identifier for somebody and a `persistent`
// value that was really the username is at least honest about being the
// username. `transient` is the exception and has to be: the format's whole
// meaning is that the value is per-session and opaque, so answering it with a
// stable username would be a lie a service provider cannot detect.
function nameIdValueFor(format, session) {
  log.debug("Entering nameIdValueFor(). format=" + format);
  const username = (session.user && session.user.username) || '';
  if (format === 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient') {
    // Derived from the session so that two requests inside one browser session
    // get the SAME transient id, which is what a service provider correlating
    // two logins in one session expects, and a new one after signing out.
    const handle = crypto.createHash('sha256')
      .update(String(session.id || '') + '|' + username, 'utf8').digest('hex').slice(0, 32);
    log.debug("Leaving nameIdValueFor(). A transient identifier.");
    return '_' + handle;
  }
  if (format === 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress') {
    log.debug("Leaving nameIdValueFor(). The mail address.");
    return (session.user && session.user.email) || username;
  }
  log.debug("Leaving nameIdValueFor(). The username.");
  return username;
}

// The attributes. Written from the one user object, in the shape a SAML 2.0
// service provider reads: a full URI in `Name` with the NameFormat that says so,
// plus the short unqualified spellings that a great many service providers
// (Keycloak's own default mappers among them) are configured with instead.
//
// **The custom SAML 2.0 attributes from /admin/saml-attributes are NOT added
// here**, and that is the point: `buildSamlAssertion()` appends them to whatever
// this returns, filtered by name so that a configured attribute cannot displace
// one of these — see decision 4 and the note in saml2.js. Adding them here as
// well would put every one of them in twice.
const CLAIM_NS = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims';

const ATTRNAME_FORMAT_URI = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';

const ATTRNAME_FORMAT_BASIC = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';

function attributesFor(user) {
  log.debug("Entering attributesFor(). user=" + user.username);
  const attributes = [
    { name: CLAIM_NS + '/name', nameFormat: ATTRNAME_FORMAT_URI, value: user.username },
    { name: CLAIM_NS + '/givenname', nameFormat: ATTRNAME_FORMAT_URI, value: user.given_name },
    { name: CLAIM_NS + '/surname', nameFormat: ATTRNAME_FORMAT_URI, value: user.family_name },
    { name: CLAIM_NS + '/emailaddress', nameFormat: ATTRNAME_FORMAT_URI, value: user.email },
    { name: CLAIM_NS + '/nameidentifier', nameFormat: ATTRNAME_FORMAT_URI, value: user.sub },
    // The unqualified four. A service provider configured against Keycloak or
    // Shibboleth keys off these, and one configured against AD FS keys off the
    // URIs above; sending both is what makes this mock usable against either
    // without a mapper being written first. They are distinct Name values, so
    // this is not one attribute said twice — it is the same fact under the two
    // names the ecosystem actually uses.
    { name: 'uid', nameFormat: ATTRNAME_FORMAT_BASIC, value: user.username },
    { name: 'mail', nameFormat: ATTRNAME_FORMAT_BASIC, value: user.email },
    { name: 'givenName', nameFormat: ATTRNAME_FORMAT_BASIC, value: user.given_name },
    { name: 'sn', nameFormat: ATTRNAME_FORMAT_BASIC, value: user.family_name },
    { name: 'displayName', nameFormat: ATTRNAME_FORMAT_BASIC, value: user.name }
  ];
  log.debug("Leaving attributesFor(). " + attributes.length + " attribute(s).");
  return attributes;
}

// --- building the response --------------------------------------------------
function statusElement(code, subCode, message) {
  return '<samlp:Status><samlp:StatusCode Value="' + xmlEscape(code) + '">' +
    (subCode ? '<samlp:StatusCode Value="' + xmlEscape(subCode) + '"/>' : '') +
    '</samlp:StatusCode>' +
    (message ? '<samlp:StatusMessage>' + xmlEscape(message) + '</samlp:StatusMessage>' : '') +
    '</samlp:Status>';
}

// A <samlp:Response>, with or without an assertion in it. One builder for the
// success and the failure alike, because the two differ by exactly one child
// element and a status code — and because an error response that took a
// different code path is an error response nobody ever looks at.
function buildResponse(opts) {
  log.debug("Entering buildResponse(). status=" + opts.status);
  const id = genId();
  const xml =
    '<samlp:Response xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' + NS_SAML + '"' +
      ' ID="' + id + '" Version="2.0" IssueInstant="' + iso(0) + '"' +
      (opts.destination ? ' Destination="' + xmlEscape(opts.destination) + '"' : '') +
      (opts.inResponseTo ? ' InResponseTo="' + xmlEscape(opts.inResponseTo) + '"' : '') + '>' +
      '<saml:Issuer>' + xmlEscape(opts.issuer) + '</saml:Issuer>' +
      statusElement(opts.status, opts.subStatus, opts.statusMessage) +
      (opts.assertion || '') +
    '</samlp:Response>';
  logArtifact('SAML 2.0 Response', 'before signing', xml);
  if (!config.value('saml2.signResponse')) {
    log.debug("Leaving buildResponse(). Unsigned: saml2.signResponse is off.");
    return { xml: xml, id: id, signed: false };
  }
  try {
    const signed = signDocument(xml, 'Response', id, 'after-issuer');
    logArtifact('SAML 2.0 Response', 'after signing', signed);
    log.debug("Leaving buildResponse(). Signed.");
    return { xml: signed, id: id, signed: true };
  } catch (e) {
    // Reported and returned unsigned rather than thrown, exactly as
    // buildSamlAssertion() does: an unsigned response that a service provider
    // rejects is a diagnosable failure, and an exception here is a 500 that
    // says nothing about SAML at all.
    log.error('the SAML 2.0 Response could not be signed, sending it unsigned: ' + e.message);
    log.debug("Leaving buildResponse(). Unsigned after a signing failure.");
    return { xml: xml, id: id, signed: false };
  }
}

// The assertion, from the one builder. Everything the Web Browser SSO profile
// requires of it and nothing this file decided for itself — see decision 4.
function buildAssertionFor(request, session, spEntityId, idpEntityId, acsUrl) {
  log.debug("Entering buildAssertionFor(). sp=" + spEntityId);
  const user = session.user;
  const context = authnContextFor(session);
  const lifetimeMin = Number(config.value('saml2.assertionLifetimeMin')) || 60;
  const format = nameIdFormatFor(request);
  const assertion = buildSamlAssertion(user.username, spEntityId, lifetimeMin, {
    issuer: idpEntityId,
    authnContextClassRef: context.classRef,
    nameIdFormat: format,
    nameIdValue: nameIdValueFor(format, session),
    // saml-profiles-2.0-os section 4.1.4.2: the bearer assertion MUST carry a
    // Recipient that matches the assertion consumer service URL it was
    // delivered to, and an InResponseTo that matches the request. A service
    // provider that checks either — and most do — refuses an assertion without
    // them, with a message that reads like a signature problem.
    subjectConfirmation: {
      recipient: acsUrl,
      inResponseTo: request.id,
      notOnOrAfter: iso(lifetimeMin)
    },
    // The SESSION, not the assertion, is what a LogoutRequest names later. This
    // is the line that makes Single Logout able to find anything.
    sessionIndex: session.id,
    authnInstant: new Date((session.authTime || 0) * 1000).toISOString(),
    attributes: attributesFor(user),
    sign: config.value('saml2.signAssertion')
  });
  log.debug("Leaving buildAssertionFor(). " + assertion.length + " characters.");
  return assertion;
}

// --- delivering it ----------------------------------------------------------
// Written with no regular expressions and nothing to escape, for the reason
// oauth2.js's ceremony script records: a backslash in a script that passes
// through a JavaScript string literal on its way out does not survive the trip.
const AUTOPOST_SCRIPT = [
  '(function () {',
  '  var f = document.getElementById("saml2-form");',
  '  if (f) { f.submit(); }',
  '})();',
  ''
].join('\n');

// **THIS IS THE FIFTH SCRIPTED PAGE IN THIS SERVICE AND THE ARGUMENT IS MADE
// AGAIN RATHER THAN BY ANALOGY**, which is what the root CLAUDE.md asks for.
// `app.js` sets `script-src 'none'` on every response, and the reason is in its
// own comment: it makes the family of reflected-content problems moot rather
// than merely unlikely. The HTTP POST binding (section 3.5) IS a self-submitting
// form — the message travels in the body of a form POST, which is what keeps a
// response that can be several kilobytes of signed XML out of a URL, a log and a
// Referer header — so there is no version of this binding without one. The
// exception is the same shape as the other four and no wider: `script-src
// 'self'` naming ONE resource, never `'unsafe-inline'`. And the submit button is
// not a fallback nobody sees — with scripting off the button IS the mechanism,
// so it is labelled for a person rather than hidden.
//
// `form-action` is deliberately absent from the policy, here as everywhere: the
// form posts to the assertion consumer service, which is by definition another
// origin, and `form-action 'self'` would block the response from ever reaching
// the service provider. The symptom is a sign-in that appears to succeed while
// the service provider never hears anything.
app.get(BASE_PATH + '/autopost.js', function (req, res) {
  log.debug("Serving the SAML 2.0 HTTP POST binding auto-post script.");
  res.set('Content-Security-Policy', app.contentSecurityPolicy({ 'style-src': null,
                                                                 'img-src': null }));
  res.type('application/javascript').set('Cache-Control', 'no-store').send(AUTOPOST_SCRIPT);
});

function postBindingPage(destination, field, message, relayState, note) {
  log.debug("Entering postBindingPage(). destination=" + destination);
  const inner = '<h1>' + xmlEscape(note.title) + '</h1>' +
    '<p class="sub">' + note.sub + '</p>' +
    '<form method="post" action="' + xmlEscape(destination) + '" id="saml2-form">' +
      '<input type="hidden" name="' + field + '" value="' + xmlEscape(message) + '">' +
      (relayState !== undefined && relayState !== null && relayState !== ''
        ? '<input type="hidden" name="RelayState" value="' + xmlEscape(relayState) + '">' : '') +
      '<div class="row"><button type="submit">Continue to ' + xmlEscape(note.who) +
      '</button></div>' +
    '</form>' +
    '<div class="meta">' +
    '<div>posting to: <code>' + xmlEscape(destination) + '</code></div>' +
    '<div>field: <code>' + field + '</code>, ' + message.length + ' base64 characters</div>' +
    '<div>RelayState: ' + (relayState ? '<code>' + xmlEscape(relayState) +
      '</code>, echoed byte for byte' : 'the request carried none, so none is returned') + '</div>' +
    '<div>The form submits itself from <code>' + BASE_PATH + '/autopost.js</code>. It is a ' +
    'separate resource because this service sets <code>script-src \'none\'</code> on every ' +
    'response and this page relaxes it to <code>\'self\'</code> — an inline script would not run, ' +
    'and the button would be the only thing that worked. With scripting off, the button IS the ' +
    'mechanism.</div>' +
    '</div>' +
    '<script src="' + BASE_PATH + '/autopost.js"></script>';
  log.debug("Leaving postBindingPage().");
  return inner;
}

function sendPostBinding(res, title, inner) {
  res.set('Content-Security-Policy', app.contentSecurityPolicy({ 'script-src': "'self'" }));
  res.status(200).type('text/html').set('Cache-Control', 'no-store').send(page(title, inner));
}

// A message on the HTTP Redirect binding: DEFLATE, base64, URL-encode, and — when
// this service signs its responses — the detached signature of section 3.4.4.1
// over the octet string in the order that section fixes.
function redirectUrlFor(destination, field, xml, relayState) {
  log.debug("Entering redirectUrlFor(). field=" + field);
  let qs = field + '=' + encodeURIComponent(encodeRedirect(xml));
  if (relayState) {
    qs += '&RelayState=' + encodeURIComponent(relayState);
  }
  if (config.value('saml2.signResponse')) {
    qs += '&SigAlg=' + encodeURIComponent(SIG_RSA_SHA256);
    qs += '&Signature=' + encodeURIComponent(signQueryString(qs));
  }
  const url = destination + (destination.indexOf('?') >= 0 ? '&' : '?') + qs;
  log.debug("Leaving redirectUrlFor(). " + url.length + " characters.");
  return url;
}

// The artifact of section 3.6.4: a four-byte header and two twenty-byte halves.
//
//   TypeCode        0x0004, which is the only artifact type SAML 2.0 defines
//   EndpointIndex   which ArtifactResolutionService to come back to; this
//                   service publishes one, at index 0
//   SourceID        SHA-1 of the ISSUER's entityID — not a hash for security,
//                   an INDEX, so that a service provider talking to several
//                   identity providers can tell whose artifact it is holding
//                   without asking anybody
//   MessageHandle   twenty random bytes, and the only part that is a secret
//
// The whole 44 bytes are base64, which is what travels in `SAMLart`.
function mintArtifact(idpEntityId, endpointIndex) {
  log.debug("Entering mintArtifact(). idp=" + idpEntityId);
  const header = Buffer.alloc(4);
  header.writeUInt16BE(0x0004, 0);
  header.writeUInt16BE(endpointIndex || 0, 2);
  const sourceId = crypto.createHash('sha1').update(String(idpEntityId), 'utf8').digest();
  const handle = crypto.randomBytes(20);
  const artifact = Buffer.concat([header, sourceId, handle]).toString('base64');
  log.debug("Leaving mintArtifact(). " + artifact.length + " base64 characters.");
  return artifact;
}

function stashArtifact(artifact, detail) {
  const ttlS = Number(config.value('saml2.artifactTtlS')) || 300;
  artifacts.set(artifact, Object.assign({ expires: Date.now() + ttlS * 1000 }, detail));
  artifacts.forEach(function (v, k) { if (v.expires < Date.now()) artifacts.delete(k); });
}

// Deliver a built message to a service provider, on whichever binding was asked
// for. One function for the sign-in response and the logout response alike,
// because the three bindings are a property of SAML and not of the message.
function deliver(res, opts) {
  log.debug("Entering deliver(). binding=" + opts.binding);
  if (opts.binding === BINDING_ARTIFACT) {
    const artifact = mintArtifact(opts.issuer, 0);
    stashArtifact(artifact, {
      xml: opts.xml, spEntityId: opts.spEntityId, issuer: opts.issuer,
      inResponseTo: opts.inResponseTo, createdAt: Date.now()
    });
    let url = opts.destination + (opts.destination.indexOf('?') >= 0 ? '&' : '?') +
      'SAMLart=' + encodeURIComponent(artifact);
    if (opts.relayState) {
      url += '&RelayState=' + encodeURIComponent(opts.relayState);
    }
    log.info('saml2: artifact ' + artifact.slice(0, 12) + '… stands for a ' + opts.field +
             ' for ' + (opts.spEntityId || '(unnamed)') + '; it is resolvable once, at ' +
             ARS_PATH + '.');
    // 303, not 302: this may follow the POST that carried the AuthnRequest, and
    // a 307 would repeat that body at the service provider. The same reasoning
    // authn.js's returnToCaller() writes down at length.
    res.set('Cache-Control', 'no-store').redirect(303, url);
    log.debug("Leaving deliver(). By artifact.");
    return;
  }
  if (opts.binding === BINDING_REDIRECT) {
    const url = redirectUrlFor(opts.destination, opts.field, opts.xml, opts.relayState);
    if (url.length > 8000) {
      // Not refused — reported. Section 4.1.2 says the Redirect binding MUST
      // NOT be used for a response because it will typically exceed what a user
      // agent permits, and this service lets it happen anyway because a service
      // provider with no server behind its ACS has no other way to receive one.
      // What it will not do is let the truncation be discovered as a mystery.
      log.warn('saml2: this redirect-binding response is ' + url.length + ' characters, which is ' +
               'past what several browsers and most CDNs carry. Section 4.1.2 says the Redirect ' +
               'binding MUST NOT be used for a response for exactly this reason. It is being sent ' +
               'anyway; ask for ProtocolBinding=HTTP-POST or HTTP-Artifact instead.');
    }
    res.set('Cache-Control', 'no-store').redirect(303, url);
    log.debug("Leaving deliver(). By redirect.");
    return;
  }
  sendPostBinding(res, opts.note.title,
                  postBindingPage(opts.destination, opts.field, encodePost(opts.xml),
                                  opts.relayState, opts.note));
  log.debug("Leaving deliver(). By form POST.");
}

// ---------------------------------------------------------------------------
// THE SINGLE SIGN-ON SERVICE.
//
// The whole of the profile's front half is here, and it runs in five steps that
// are worth naming because each one can end the request:
//
//   1. read the message off whichever binding it arrived on
//   2. hold it and become a GET, if it arrived by POST — see decision 2
//   3. work out where the response goes, because after this point a failure can
//      be REPORTED to the service provider instead of shown on a page
//   4. get a session, which may mean going to the sign-in screen and back
//   5. build the response and deliver it on the binding that was asked for
// ---------------------------------------------------------------------------
function singleSignOn(req, res) {
  log.debug("Entering singleSignOn(). method=" + req.method);
  const base = baseUrlOf(req);
  const params = paramsOf(req);
  const scoped = entityIdFromSegment(req.params.sp);

  // --- step 2, first, because it decides whether there is anything to read ---
  // A held request being resumed: either the browser has come back from the
  // sign-in screen, or a POST-binding request has just been turned into a GET.
  const held = params.rid ? pendingRequests.get(String(params.rid)) : null;
  if (params.rid && !held) {
    log.debug("Leaving singleSignOn(). The held request had expired.");
    return samlError(res, 400, 'This sign-in request has expired',
      'A request is held for ten minutes while the browser is at the sign-in screen. Start the ' +
      'AuthnRequest again from the service provider.');
  }

  const encoded = held ? held.samlRequest : params.SAMLRequest;
  if (!encoded) {
    log.debug("Leaving singleSignOn(). No SAMLRequest, so it describes itself.");
    return sendPage(res, 200, 'SAML 2.0 Single Sign-On service',
                    describeSsoPage(base, scoped));
  }

  const relayState = held ? held.relayState : (params.RelayState || '');
  const arrivedBy = held ? held.arrivedBy : (req.method === 'POST' ? BINDING_POST : BINDING_REDIRECT);
  const xml = decodeMessage(encoded);
  logArtifact('SAML 2.0 AuthnRequest', 'as received on the ' +
              (arrivedBy === BINDING_POST ? 'HTTP POST' : 'HTTP Redirect') + ' binding', xml);
  const request = readAuthnRequest(xml);
  if (!request.ok) {
    log.debug("Leaving singleSignOn(). The message could not be read.");
    return samlError(res, 400, 'That is not an AuthnRequest',
      request.why + '. The Single Sign-On service reads <samlp:AuthnRequest> ' +
      '(saml-core-2.0-os section 3.4.1); a <samlp:LogoutRequest> goes to ' + SLO_PATH + '.');
  }
  // The redirect binding's signature travels beside the message rather than in
  // it, so `signed` has to take both into account. Neither is verified — see
  // decision 3 — and BOTH are recorded, because "was it signed at all" is a
  // question a service provider integrator asks constantly.
  const querySigned = !!(held ? held.signature : params.Signature);
  request.signed = request.signed || querySigned;
  request.sigAlg = String((held ? held.sigAlg : params.SigAlg) || '');

  // --- step 2 proper -------------------------------------------------------
  // A POST-binding request has to become a GET before this service can see its
  // own session cookie: the cookie is SameSite=Lax, the POST is cross-site, and
  // the cookie is therefore NOT sent — so a signed-in person would be shown the
  // sign-in screen every time. Holding the request and 303ing to a GET on this
  // same endpoint is a top-level GET navigation, which Lax does carry. This is
  // the difference from ws-federation/wsfed.js, which answers the same problem
  // with a sign-in screen of its own; see decision 2.
  if (!held && arrivedBy === BINDING_POST) {
    const record = {
      id: randomId(18), samlRequest: String(encoded), relayState: String(relayState || ''),
      arrivedBy: arrivedBy, signature: String(params.Signature || ''),
      sigAlg: String(params.SigAlg || ''), expires: Date.now() + REQUEST_TTL_MS
    };
    pendingRequests.set(record.id, record);
    pendingRequests.forEach(function (v, k) { if (v.expires < Date.now()) pendingRequests.delete(k); });
    log.debug("Leaving singleSignOn(). Held and redirected so the session cookie is visible.");
    return res.set('Cache-Control', 'no-store')
              .redirect(303, req.path + '?rid=' + encodeURIComponent(record.id));
  }

  // --- step 3: where does the answer go ------------------------------------
  const spEntityId = request.issuer || scoped.entityId;
  if (!spEntityId) {
    log.debug("Leaving singleSignOn(). The request names no issuer.");
    return samlError(res, 400, 'The AuthnRequest names no issuer',
      'A <saml:Issuer> is what says which service provider this request is from, and it becomes ' +
      'the assertion\'s audience restriction. An assertion with no audience is one any service ' +
      'provider would be entitled to accept.',
      '<p>There is a mock service provider here that sends a complete request: ' +
      '<a href="' + SP_PATH + '">' + SP_PATH + '</a>.</p>');
  }
  const idpEntityId = idpEntityIdFor(spEntityId);
  const known = fieldsOf(spEntityId);
  // The assertion consumer service URL, in the order a real identity provider
  // would take it — except that the middle step, SP metadata, is one this
  // service does not have. It is NOT validated against a registration, exactly
  // as WS-Federation's wreply is not and for the same stated reason: this mock
  // accepts arbitrary return URLs on purpose. It must be an absolute http(s)
  // URL, because a form action that is not one posts back to this origin and
  // the failure reads as a service provider that ignored the response.
  const acsUrl = String(request.acsUrl ||
    (Array.isArray(known.samlAssertionConsumerService)
      ? known.samlAssertionConsumerService[known.samlAssertionConsumerService.length - 1]
      : known.samlAssertionConsumerService || '') ||
    (base + SP_PATH));
  if (!/^https?:\/\//i.test(acsUrl)) {
    log.debug("Leaving singleSignOn(). The ACS URL is not absolute.");
    return samlError(res, 400, 'The assertion consumer service URL must be absolute',
      'It is "' + acsUrl + '". The response is delivered to that address by form POST, by ' +
      'redirect or as an artifact, and a relative value addresses this service instead — which ' +
      'looks exactly like a service provider that ignored the response.');
  }
  const wanted = responseBindingFor(request);
  if (wanted.error) {
    log.debug("Leaving singleSignOn(). An unimplemented ProtocolBinding was asked for.");
    return samlError(res, 400, 'That response binding is not implemented',
      'This request asked for ProtocolBinding="' + wanted.error + '". This identity provider ' +
      'delivers a response over HTTP POST, HTTP Redirect and HTTP Artifact, which are the three ' +
      'its metadata advertises.',
      '<p>It is refused rather than quietly answered over HTTP POST, because a service provider ' +
      'that asked for PAOS and received a form post would conclude that PAOS worked.</p>');
  }

  // THE SERVICE PROVIDER, recorded now that the request has been understood and
  // before anything can go wrong at the sign-in screen. `counts: false` because
  // an AuthnRequest is not an authentication — the person may never sign in —
  // and counting one here would double every successful flow.
  recordServiceProvider({
    identifier: spEntityId,
    kind: 'saml2-service-provider',
    protocol: 'SAML 2.0',
    note: 'sent an AuthnRequest to the Web Browser SSO profile',
    counts: false,
    fields: {
      samlEntityId: spEntityId,
      samlAssertionConsumerService: acsUrl,
      samlNameIdFormat: request.nameIdFormat || '',
      samlResponseBinding: wanted.binding,
      samlAuthnRequestSigned: request.signed ? 'TRUE' : 'FALSE',
      samlSigningCertificate: request.signingCertificate || ''
    }
  });

  // --- step 4: a session ----------------------------------------------------
  const session = sessionOf(req);
  const wantsMfa = request.requestedAuthnContexts.some(function (ref) {
    return AC_MFA_DEMANDS.indexOf(ref) >= 0;
  });
  const stale = session && wantsMfa && !authnContextFor(session).multiFactor;
  if (!session || request.forceAuthn || stale) {
    if (request.isPassive) {
      // IsPassive says the identity provider MUST NOT take control of the user
      // interface — so the answer is a Response carrying NoPassive, delivered to
      // the service provider, and not a sign-in screen. It is one of the two
      // status codes a service provider is most likely never to have handled,
      // which is exactly why it is implemented rather than ignored.
      log.debug("IsPassive is set and there is no usable session, so NoPassive goes back.");
      const refusal = buildResponse({
        issuer: idpEntityId, destination: acsUrl, inResponseTo: request.id,
        status: STATUS_RESPONDER, subStatus: STATUS_NO_PASSIVE,
        statusMessage: session
          ? 'The session here has one factor and this request asked for more, and IsPassive ' +
            'forbids asking for it.'
          : 'There is no browser session here, and IsPassive forbids asking for one.'
      });
      deliver(res, {
        binding: wanted.binding, destination: acsUrl, field: 'SAMLResponse', xml: refusal.xml,
        relayState: relayState, issuer: idpEntityId, spEntityId: spEntityId,
        inResponseTo: request.id,
        note: { title: 'Refused — SAML 2.0', who: 'the service provider',
                sub: 'A <samlp:Response> carrying NoPassive. IsPassive="true" forbids this ' +
                     'identity provider from taking control of the user interface, so it ' +
                     'reports rather than asks.' }
      });
      log.debug("Leaving singleSignOn(). NoPassive.");
      return;
    }
    // Hold the request and go to authn.js's screen. The return address is a GET
    // on this endpoint carrying the held id, so coming back runs this function
    // again from the top with a session in place.
    const record = held || {
      id: randomId(18), samlRequest: String(encoded), relayState: String(relayState || ''),
      arrivedBy: arrivedBy, signature: String(params.Signature || ''),
      sigAlg: String(params.SigAlg || '')
    };
    record.expires = Date.now() + REQUEST_TTL_MS;
    pendingRequests.set(record.id, record);
    pendingRequests.forEach(function (v, k) { if (v.expires < Date.now()) pendingRequests.delete(k); });
    const returnTo = req.path + '?rid=' + encodeURIComponent(record.id);
    const where = beginAuthentication({
      returnTo: returnTo,
      hint: request.subjectHint,
      // The service provider's entityID is its identifier in the application
      // registry, so an entry naming a federation relationship federates a
      // SAML 2.0 sign-in exactly as it federates an OAuth one. Nothing in this
      // module knows that happened: what comes back is a session.
      application: spEntityId,
      // A RequestedAuthnContext demanding more than one factor takes the
      // opt-out away rather than being refused — the opposite of what
      // WS-Federation's wauth does with the same demand, because THIS screen
      // can run the ceremony. See the note on AC_MFA_DEMANDS.
      forceMfa: wantsMfa,
      protocol: 'SAML 2.0',
      details: [
        { label: 'Service provider', value: spEntityId,
          note: 'the <saml:Issuer> of the AuthnRequest, and the audience of the assertion.' },
        { label: 'Assertion consumer service', value: acsUrl,
          note: 'where the response is delivered. Not checked against any registration.' },
        { label: 'Response binding', value: wanted.binding,
          note: wanted.stated ? 'asked for by ProtocolBinding.'
                              : 'the default, because the request named none.' },
        { label: 'NameID format', value: nameIdFormatFor(request),
          note: request.nameIdFormat ? 'asked for by NameIDPolicy.'
                                     : 'this service\'s default: the request asked for none.' }
      ].concat(request.forceAuthn
        ? [{ label: 'ForceAuthn', value: 'true',
             note: 'why this screen appeared even though a session already existed.' }]
        : []).concat(stale
        ? [{ label: 'RequestedAuthnContext', value: request.requestedAuthnContexts.join(' '),
             note: 'more than one factor was asked for and this session has one.' }]
        : [])
    });
    log.debug("Leaving singleSignOn(). To the sign-in screen, returning to " + returnTo + ".");
    return res.set('Cache-Control', 'no-store').redirect(303, where);
  }

  // The person cancelled at the screen, or it failed. authn.js reports back on
  // the query string and leaves it to the CALLER to decide what its protocol
  // does — and what this one does is send a Response carrying a status, because
  // section 3.2.2 has one for exactly this and a service provider's handling of
  // it is worth exercising.
  if (params.authn_error) {
    log.debug("The sign-in did not complete: " + params.authn_error);
    pendingRequests.delete(String(params.rid || ''));
    const refusal = buildResponse({
      issuer: idpEntityId, destination: acsUrl, inResponseTo: request.id,
      status: STATUS_RESPONDER,
      subStatus: 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed',
      statusMessage: String(params.authn_error_description || params.authn_error)
    });
    deliver(res, {
      binding: wanted.binding, destination: acsUrl, field: 'SAMLResponse', xml: refusal.xml,
      relayState: relayState, issuer: idpEntityId, spEntityId: spEntityId,
      inResponseTo: request.id,
      note: { title: 'Sign-in failed — SAML 2.0', who: 'the service provider',
              sub: 'A <samlp:Response> carrying AuthnFailed. Unlike WS-Federation\'s passive ' +
                   'profile, this one has somewhere to report a cancellation to.' }
    });
    log.debug("Leaving singleSignOn(). AuthnFailed.");
    return;
  }

  // --- step 5: the answer ---------------------------------------------------
  pendingRequests.delete(String(params.rid || ''));
  issueSignInResponse(res, {
    request: request, session: session, spEntityId: spEntityId, idpEntityId: idpEntityId,
    acsUrl: acsUrl, binding: wanted.binding, relayState: relayState
  });
  log.debug("Leaving singleSignOn(). A response went to " + spEntityId + ".");
}

function issueSignInResponse(res, ctx) {
  log.debug("Entering issueSignInResponse(). sp=" + ctx.spEntityId);
  const session = ctx.session;
  const assertion = buildAssertionFor(ctx.request, session, ctx.spEntityId,
                                      ctx.idpEntityId, ctx.acsUrl);
  const response = buildResponse({
    issuer: ctx.idpEntityId, destination: ctx.acsUrl, inResponseTo: ctx.request.id,
    status: STATUS_SUCCESS, assertion: assertion
  });

  // THE AUTHENTICATION, recorded here rather than when the request arrived: this
  // is the moment this service has decided to tell that service provider who
  // somebody is. The sighting was recorded at step 3 with `counts: false` for
  // exactly this reason.
  recordServiceProvider({
    identifier: ctx.spEntityId,
    kind: 'saml2-service-provider',
    protocol: 'SAML 2.0',
    sessionId: session.id || '',
    user: (session.user && session.user.username) || '',
    note: 'was issued a Web Browser SSO assertion',
    fields: {
      samlEntityId: ctx.spEntityId,
      samlAssertionConsumerService: ctx.acsUrl,
      samlResponseBinding: ctx.binding
    }
  });

  // Which service providers this session has signed into, so that Single Logout
  // has somewhere to fan out to. It lives ON the session rather than in a map of
  // its own because that is exactly the lifetime it should have: when the
  // session goes, so does the list, and nothing has to be swept. The same
  // decision `wsfed.js` makes about `session.wsfedRealms`.
  session.saml2ServiceProviders = session.saml2ServiceProviders || {};
  session.saml2ServiceProviders[ctx.spEntityId] = {
    acs: ctx.acsUrl, idpEntityId: ctx.idpEntityId, at: Date.now()
  };

  deliver(res, {
    binding: ctx.binding, destination: ctx.acsUrl, field: 'SAMLResponse', xml: response.xml,
    relayState: ctx.relayState, issuer: ctx.idpEntityId, spEntityId: ctx.spEntityId,
    inResponseTo: ctx.request.id,
    note: { title: 'Signing in — SAML 2.0', who: 'the service provider',
            sub: 'saml-profiles-2.0-os section 4.1.4 — the response travels in the body of a ' +
                 'form POST, so it is not length-limited and never appears in a URL, a log or a ' +
                 'Referer header.' }
  });
  log.debug("Leaving issueSignInResponse(). " +
            ((session.user && session.user.username) || '?') + " signed in to " + ctx.spEntityId + ".");
}

// ---------------------------------------------------------------------------
// THE ARTIFACT RESOLUTION SERVICE (section 3.6.3, over the SOAP binding 3.2.3).
//
// This is the back channel the Browser/Artifact profile rests on, and it is the
// one endpoint in this profile a BROWSER never touches: the service provider
// calls it directly, server to server, with the artifact its user agent carried.
// That is the whole reason the profile exists — the assertion never passes
// through the browser at all.
//
// It is not authenticated, and on a service that authenticates nobody that is
// the ordinary state of affairs rather than a decision about this endpoint. What
// stands in for authentication is the MessageHandle, which is twenty random
// bytes, and the one-shot rule of decision 6.
// ---------------------------------------------------------------------------
function soapEnvelope(inner) {
  return '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="' + NS_SOAP + '"><soap:Body>' + inner +
    '</soap:Body></soap:Envelope>';
}

function buildArtifactResponse(idpEntityId, inResponseTo, status, statusMessage, payload) {
  log.debug("Entering buildArtifactResponse(). status=" + status);
  const xml =
    '<samlp:ArtifactResponse xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' + NS_SAML + '"' +
      ' ID="' + genId() + '" Version="2.0" IssueInstant="' + iso(0) + '"' +
      (inResponseTo ? ' InResponseTo="' + xmlEscape(inResponseTo) + '"' : '') + '>' +
      '<saml:Issuer>' + xmlEscape(idpEntityId) + '</saml:Issuer>' +
      statusElement(status, '', statusMessage) +
      (payload || '') +
    '</samlp:ArtifactResponse>';
  log.debug("Leaving buildArtifactResponse().");
  return xml;
}

// The ArtifactResponse is DELIBERATELY NOT SIGNED, and it is worth saying why
// rather than leaving it to look like an omission: what a service provider
// verifies is the <samlp:Response> INSIDE it, which carries its own signature
// and its own assertion signature, and which is the document its whole security
// model is written about. A signature on the envelope would be a second thing to
// check that no service provider library checks. The back channel's own
// integrity is TLS's job, which is what the SOAP binding says.
function resolveArtifact(req, res) {
  log.debug("Entering resolveArtifact().");
  const scoped = entityIdFromSegment(req.params.sp);
  const raw = typeof req.body === 'string' ? req.body : '';
  logArtifact('SAML 2.0 ArtifactResolve', 'as received over SOAP', raw);
  const answer = function (status, message, payload, inResponseTo) {
    const envelope = soapEnvelope(buildArtifactResponse(
      idpEntityIdFor(scoped.entityId), inResponseTo, status, message, payload));
    logArtifact('SAML 2.0 ArtifactResponse', 'as returned over SOAP', envelope);
    // 200 whatever the status: a SOAP fault is an HTTP-layer failure and this is
    // a SAML-layer refusal, and collapsing the two makes a service provider's
    // client throw a transport error where it should be reading a status code.
    res.status(200).type('text/xml; charset=utf-8').set('Cache-Control', 'no-store')
       .send(envelope);
  };

  let doc = null;
  try {
    doc = new DOMParser().parseFromString(raw, 'text/xml');
  } catch (e) {
    // Kept as a SAML status rather than thrown, for the reason above.
    log.error('saml2: the ArtifactResolve body is not XML: ' + e.message);
    log.debug("Leaving resolveArtifact(). Unparseable.");
    return answer(STATUS_REQUESTER, 'the request body is not XML: ' + e.message, '', '');
  }
  const resolve = firstByLocal(doc, 'ArtifactResolve');
  if (!resolve) {
    log.debug("Leaving resolveArtifact(). No ArtifactResolve.");
    return answer(STATUS_REQUESTER, 'there is no <samlp:ArtifactResolve> in the SOAP body. ' +
                  'This endpoint speaks the SOAP binding (saml-bindings-2.0-os section 3.2.3) ' +
                  'and nothing else.', '', '');
  }
  const inResponseTo = resolve.getAttribute('ID') || '';
  const spEntityId = textByLocal(resolve, 'Issuer');
  const artifact = textByLocal(resolve, 'Artifact');
  if (!artifact) {
    log.debug("Leaving resolveArtifact(). No artifact in the request.");
    return answer(STATUS_REQUESTER, 'the ArtifactResolve carries no <samlp:Artifact>.',
                  '', inResponseTo);
  }
  const held = artifacts.get(artifact);
  if (!held) {
    // The one refusal in this file that is worth making loudly, because it is
    // the same answer for three different mistakes and a service provider
    // cannot tell them apart from the status code alone: an artifact that was
    // never minted here, one that has expired, and — the interesting one — one
    // that has ALREADY BEEN RESOLVED. Decision 6.
    log.warn('saml2: artifact ' + String(artifact).slice(0, 12) + '… does not resolve. It was ' +
             'never minted here, or it has expired (saml2.artifactTtlS), or it has already been ' +
             'resolved once — which destroys it, because section 3.6.4.1 says an artifact is ' +
             'resolvable exactly once.');
    log.debug("Leaving resolveArtifact(). Unknown artifact.");
    return answer(STATUS_REQUESTER,
                  'that artifact does not resolve: it was never issued here, it has expired, or ' +
                  'it has already been resolved — an artifact is one-shot (section 3.6.4.1).',
                  '', inResponseTo);
  }
  // ONE-SHOT. Deleted BEFORE the answer is built rather than after it is sent,
  // so that two ArtifactResolve calls arriving together cannot both find it.
  artifacts.delete(artifact);
  if (spEntityId && held.spEntityId && spEntityId !== held.spEntityId) {
    // Recorded rather than refused, which is this service's posture everywhere:
    // the artifact was minted for one service provider and another is resolving
    // it. A real identity provider refuses this. The log says so, the artifact
    // is spent either way, and the message is returned — because what a mock is
    // for is letting somebody SEE that their service provider did this.
    log.warn('saml2: artifact ' + String(artifact).slice(0, 12) + '… was minted for "' +
             held.spEntityId + '" and is being resolved by "' + spEntityId + '". A real identity ' +
             'provider refuses that; this one records it and answers, which is what a mock is ' +
             'for. The artifact is spent either way.');
  }
  log.debug("Leaving resolveArtifact(). Resolved and destroyed.");
  return answer(STATUS_SUCCESS, '', held.xml, inResponseTo);
}

// ---------------------------------------------------------------------------
// SINGLE LOGOUT (saml-profiles-2.0-os section 4.4).
//
// Both directions arrive here, and they are told apart by which message the
// binding carried: a <samlp:LogoutRequest> is a service provider asking this
// identity provider to end the session, and a bare GET is somebody asking this
// identity provider to start one.
//
// **WHERE THE LogoutResponse GOES IS A GUESS, AND IT IS MADE OUT LOUD.** A
// LogoutRequest carries no return address — only SP METADATA has one, in a
// SingleLogoutService element, and this service does not consume SP metadata. So
// the address is looked for in three places in order: the application entry's
// `samlSingleLogoutService`, which is what an operator sets and what an
// `ldapmodify` reaches; `saml2.defaultSingleLogoutService`; and finally the
// assertion consumer service URL that service provider last used, which is a
// guess and is logged as one. It is a guess that works — a service provider's
// ACS and its SLO endpoint are commonly the same handler — and it is the
// difference between Single Logout being testable here and not.
// ---------------------------------------------------------------------------
function logoutReturnAddressFor(spEntityId) {
  log.debug("Entering logoutReturnAddressFor(). sp=" + spEntityId);
  const known = fieldsOf(spEntityId);
  const declared = known.samlSingleLogoutService;
  const first = Array.isArray(declared) ? declared[0] : declared;
  if (first) {
    log.debug("Leaving logoutReturnAddressFor(). From the application entry.");
    return { url: String(first), from: 'the samlSingleLogoutService on its application entry' };
  }
  const configured = String(config.value('saml2.defaultSingleLogoutService') || '');
  if (configured) {
    log.debug("Leaving logoutReturnAddressFor(). From the configuration.");
    return { url: configured, from: 'saml2.defaultSingleLogoutService' };
  }
  const acs = Array.isArray(known.samlAssertionConsumerService)
    ? known.samlAssertionConsumerService[known.samlAssertionConsumerService.length - 1]
    : known.samlAssertionConsumerService;
  if (acs) {
    log.warn('saml2: "' + spEntityId + '" has no SingleLogoutService recorded, so its ' +
             'LogoutResponse is going to the assertion consumer service URL it last used (' +
             acs + '). That is a GUESS — a LogoutRequest carries no return address and this ' +
             'service does not consume SP metadata. Set samlSingleLogoutService on its ' +
             'application entry, or saml2.defaultSingleLogoutService, to remove it.');
    log.debug("Leaving logoutReturnAddressFor(). Guessed from the ACS URL.");
    return { url: String(acs), from: 'the assertion consumer service URL it last used — A GUESS' };
  }
  log.debug("Leaving logoutReturnAddressFor(). There is nowhere to send it.");
  return { url: '', from: '' };
}

function buildLogoutResponse(idpEntityId, destination, inResponseTo, status, message) {
  log.debug("Entering buildLogoutResponse(). status=" + status);
  const id = genId();
  const xml =
    '<samlp:LogoutResponse xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' + NS_SAML + '"' +
      ' ID="' + id + '" Version="2.0" IssueInstant="' + iso(0) + '"' +
      (destination ? ' Destination="' + xmlEscape(destination) + '"' : '') +
      (inResponseTo ? ' InResponseTo="' + xmlEscape(inResponseTo) + '"' : '') + '>' +
      '<saml:Issuer>' + xmlEscape(idpEntityId) + '</saml:Issuer>' +
      statusElement(status, '', message) +
    '</samlp:LogoutResponse>';
  logArtifact('SAML 2.0 LogoutResponse', 'before signing', xml);
  if (!config.value('saml2.signResponse')) {
    log.debug("Leaving buildLogoutResponse(). Unsigned.");
    return xml;
  }
  try {
    const signed = signDocument(xml, 'LogoutResponse', id, 'after-issuer');
    logArtifact('SAML 2.0 LogoutResponse', 'after signing', signed);
    log.debug("Leaving buildLogoutResponse(). Signed.");
    return signed;
  } catch (e) {
    log.error('the LogoutResponse could not be signed, sending it unsigned: ' + e.message);
    log.debug("Leaving buildLogoutResponse(). Unsigned after a signing failure.");
    return xml;
  }
}

function buildLogoutRequest(idpEntityId, destination, nameId, nameIdFormat, sessionIndex) {
  log.debug("Entering buildLogoutRequest(). to=" + destination);
  const id = genId();
  const xml =
    '<samlp:LogoutRequest xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' + NS_SAML + '"' +
      ' ID="' + id + '" Version="2.0" IssueInstant="' + iso(0) + '"' +
      (destination ? ' Destination="' + xmlEscape(destination) + '"' : '') + '>' +
      '<saml:Issuer>' + xmlEscape(idpEntityId) + '</saml:Issuer>' +
      '<saml:NameID' + (nameIdFormat ? ' Format="' + xmlEscape(nameIdFormat) + '"' : '') + '>' +
        xmlEscape(nameId) + '</saml:NameID>' +
      (sessionIndex ? '<samlp:SessionIndex>' + xmlEscape(sessionIndex) + '</samlp:SessionIndex>' : '') +
    '</samlp:LogoutRequest>';
  logArtifact('SAML 2.0 LogoutRequest', 'before signing', xml);
  if (!config.value('saml2.signResponse')) {
    log.debug("Leaving buildLogoutRequest(). Unsigned.");
    return xml;
  }
  try {
    const signed = signDocument(xml, 'LogoutRequest', id, 'after-issuer');
    log.debug("Leaving buildLogoutRequest(). Signed.");
    return signed;
  } catch (e) {
    log.error('the LogoutRequest could not be signed, sending it unsigned: ' + e.message);
    log.debug("Leaving buildLogoutRequest(). Unsigned after a signing failure.");
    return xml;
  }
}

function singleLogout(req, res) {
  log.debug("Entering singleLogout(). method=" + req.method);
  const base = baseUrlOf(req);
  const params = paramsOf(req);
  const scoped = entityIdFromSegment(req.params.sp);

  // A LogoutResponse arriving HERE is another identity provider's answer to a
  // LogoutRequest this one sent, and this service is not a federation gateway —
  // it is reported and dropped rather than acted on, which is the same decision
  // wsfed.js makes about a cleanup request arriving at the identity provider.
  if (params.SAMLResponse) {
    const answered = decodeMessage(params.SAMLResponse);
    logArtifact('SAML 2.0 LogoutResponse', 'as received at the identity provider', answered);
    log.debug("Leaving singleLogout(). A LogoutResponse was received and dropped.");
    return sendPage(res, 200, 'Logout response received — SAML 2.0',
      '<h1>A LogoutResponse arrived here</h1>' +
      '<div class="ok">It has been logged and dropped.</div>' +
      '<p>A LogoutResponse is an answer to a LogoutRequest, and this identity provider does not ' +
      'wait for one: its logout page fans out and reports, rather than driving a chain of ' +
      'redirects through every service provider in turn. Acting on this would make this service ' +
      'a federation gateway, which it is not.</p>' +
      '<pre>' + xmlEscape(answered) + '</pre>');
  }

  if (!params.SAMLRequest) {
    // IdP-initiated: somebody asked this identity provider to end the session.
    log.debug("Leaving singleLogout(). Identity-provider-initiated.");
    return identityProviderInitiatedLogout(req, res, base, params);
  }

  const xml = decodeMessage(params.SAMLRequest);
  logArtifact('SAML 2.0 LogoutRequest', 'as received from a service provider', xml);
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const root = doc.documentElement;
  if (!root || root.localName !== 'LogoutRequest') {
    log.debug("Leaving singleLogout(). It is not a LogoutRequest.");
    return samlError(res, 400, 'That is not a LogoutRequest',
      'This endpoint reads <samlp:LogoutRequest> (saml-core-2.0-os section 3.7.1). An ' +
      '<samlp:AuthnRequest> goes to ' + SSO_PATH + '.');
  }
  const requestId = root.getAttribute('ID') || '';
  const spEntityId = textByLocal(root, 'Issuer') || scoped.entityId;
  const nameIdEl = firstByLocal(root, 'NameID');
  const nameId = nameIdEl ? (nameIdEl.textContent || '').trim() : '';
  const nameIdFormat = nameIdEl ? (nameIdEl.getAttribute('Format') || '') : '';
  const sessionIndex = textByLocal(root, 'SessionIndex');
  const idpEntityId = idpEntityIdFor(spEntityId);
  const arrivedBy = req.method === 'POST' ? BINDING_POST : BINDING_REDIRECT;

  // The session ends here. `endSession()` returns what it dropped, which is how
  // the page below can name the other service providers that were signed in —
  // and which is why the list has to be read BEFORE the answer is built.
  const session = endSession(req, res);
  const others = (session && session.saml2ServiceProviders) || {};
  const otherNames = Object.keys(others).filter(function (name) { return name !== spEntityId; });

  recordServiceProvider({
    identifier: spEntityId,
    kind: 'saml2-service-provider',
    protocol: 'SAML 2.0',
    counts: false,
    note: 'sent a LogoutRequest',
    fields: { samlEntityId: spEntityId }
  });

  const back = logoutReturnAddressFor(spEntityId);
  // PartialLogout rather than Success when this session had OTHER service
  // providers in it, because that is what happened: section 3.7.3.2 has a status
  // code for exactly this, and reporting Success would tell the service provider
  // that a federation-wide logout it never got was complete. Every real identity
  // provider that does not implement front-channel fan-out gets this wrong.
  const partial = otherNames.length > 0;
  const status = partial ? STATUS_SUCCESS : STATUS_SUCCESS;
  const subStatus = partial ? STATUS_PARTIAL_LOGOUT : '';
  const message = partial
    ? 'The browser session ended. ' + otherNames.length + ' other service provider(s) were ' +
      'signed in on it and were NOT sent a LogoutRequest from here — see ' + base + SLO_PATH + '.'
    : '';
  if (!back.url) {
    log.debug("Leaving singleLogout(). Nowhere to send the LogoutResponse.");
    return sendPage(res, 200, 'Signed out — SAML 2.0',
      '<h1>Signed out</h1>' +
      '<div class="ok">' + (session
        ? 'The session for ' + xmlEscape((session.user && session.user.username) || '') +
          ' has ended. It is the session the OAuth 2.0 / OIDC and WS-Federation sides share, so ' +
          'they are signed out too.'
        : 'There was no session to end. The cookie has been cleared anyway.') + '</div>' +
      '<p>There is nowhere to send the <code>&lt;samlp:LogoutResponse&gt;</code>: <code>' +
      xmlEscape(spEntityId) + '</code> has no <code>samlSingleLogoutService</code> on its ' +
      'application entry, <code>saml2.defaultSingleLogoutService</code> is empty, and this ' +
      'service has never seen an assertion consumer service URL for it either. A LogoutRequest ' +
      'carries no return address of its own — only SP metadata does, and this service does not ' +
      'consume SP metadata.</p>' +
      '<p>Set one on <a href="/admin/saml2">the SAML 2.0 console page</a>, through ' +
      '<code>POST /admin-api/saml2/set-logout-service</code>, or with an ' +
      '<code>ldapmodify</code>.</p>');
  }

  const response = buildLogoutResponse(idpEntityId, back.url, requestId,
                                       status, message);
  log.info('saml2: ' + spEntityId + ' logged out' + (nameId ? ' ' + nameId : '') +
           (sessionIndex ? ' (session index ' + sessionIndex + ')' : '') +
           '; the LogoutResponse goes to ' + back.url + ', from ' + back.from + '.');
  deliver(res, {
    binding: arrivedBy, destination: back.url, field: 'SAMLResponse', xml: response,
    relayState: params.RelayState || '', issuer: idpEntityId, spEntityId: spEntityId,
    inResponseTo: requestId,
    note: { title: 'Signed out — SAML 2.0', who: 'the service provider',
            sub: 'A <samlp:LogoutResponse> on the binding the LogoutRequest arrived on, going ' +
                 'to ' + xmlEscape(back.from) + '.' }
  });
  log.debug("Leaving singleLogout(). A LogoutResponse went to " + spEntityId + ".");
  return undefined;
}

// ---------------------------------------------------------------------------
// THE LOGOUT REQUESTS ONE SESSION IS OWED, as data rather than as HTML.
//
// `session.saml2ServiceProviders` is written when a sign-in response goes out.
// This turns it into the list Single Logout has to address, with the
// LogoutRequest already built and encoded for the HTTP Redirect binding.
//
// It is a function of its own for ONE reason: the protocol-independent
// `/logout` at the root of this service has to name exactly these, and a second
// builder over there would be a second answer to what a LogoutRequest for this
// session looks like — a message this service SIGNS, so two builders would be
// two signed documents that could differ.
//
// A service provider with no logout return address is REPORTED with an empty
// url rather than dropped, for the same reason the table below prints "nowhere
// to send one": that is the interesting row.
// ---------------------------------------------------------------------------
function logoutTargetsFor(session) {
  log.debug("Entering logoutTargetsFor().");
  const signedInto = (session && session.saml2ServiceProviders) || {};
  const username = (session && session.user && session.user.username) || '';
  const out = Object.keys(signedInto).map(function (name) {
    const back = logoutReturnAddressFor(name);
    const idpEntityId = signedInto[name].idpEntityId || idpEntityIdFor(name);
    const request = buildLogoutRequest(idpEntityId, back.url, username,
                                       String(config.value('saml2.nameIdFormat')),
                                       (session && session.id) || '');
    return {
      entityId: name,
      from: back.from,
      destination: back.url,
      url: back.url
        ? back.url + (back.url.indexOf('?') >= 0 ? '&' : '?') +
          'SAMLRequest=' + encodeURIComponent(encodeRedirect(request))
        : ''
    };
  });
  log.debug("Leaving logoutTargetsFor(). " + out.length + " service provider(s).");
  return out;
}

// Identity-provider-initiated logout. The session ends and every service
// provider it signed into is NAMED, with a LogoutRequest built for each.
//
// It is a page of links and not an automatic fan-out, and that is the same
// decision wsfed.js makes about its cleanup pings for a different reason: a
// WS-Federation cleanup is an idempotent GET that works as a one-pixel image,
// and a SAML LogoutRequest is a signed message that most service providers
// expect over POST and that they ANSWER. Firing those into hidden frames would
// produce a page that claims a federation-wide logout it cannot observe. Naming
// them, with the message ready to send, is what this service can honestly do.
function identityProviderInitiatedLogout(req, res, base, params) {
  log.debug("Entering identityProviderInitiatedLogout().");
  const session = endSession(req, res);
  const targets = logoutTargetsFor(session);
  const names = targets.map(function (t) { return t.entityId; });
  const username = (session && session.user && session.user.username) || '';
  const rows = targets.map(function (target) {
    return '<tr><td><code>' + xmlEscape(target.entityId) + '</code></td>' +
      '<td>' + (target.url
        ? '<a href="' + xmlEscape(target.url) + '">send a LogoutRequest</a><br>' +
          '<span class="sub">' + xmlEscape(target.from) + '</span>'
        : '<span class="fail">nowhere to send one</span>') + '</td></tr>';
  }).join('');
  const inner = '<h1>Signed out</h1>' +
    '<p class="sub">SAML 2.0 Single Logout, identity-provider-initiated ' +
    '(saml-profiles-2.0-os section 4.4)</p>' +
    '<div class="ok">' + (session
      ? 'The session for ' + xmlEscape(username) + ' has ended. It is the session the OAuth 2.0 ' +
        '/ OIDC and WS-Federation sides share, so they are signed out too.'
      : 'There was no session to end. The cookie has been cleared anyway.') + '</div>' +
    (names.length
      ? '<h2>' + names.length + ' service provider' + (names.length === 1 ? '' : 's') +
        ' was signed in on it</h2>' +
        '<table><thead><tr><th>Service provider</th><th>LogoutRequest</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table>' +
        '<p class="sub">These are LINKS rather than an automatic fan-out, and that is deliberate. ' +
        'WS-Federation\'s <code>wsignoutcleanup1.0</code> is an idempotent GET that works as a ' +
        'one-pixel image; a SAML LogoutRequest is a signed message that a service provider ' +
        'ANSWERS, and firing those into hidden frames would produce a page claiming a ' +
        'federation-wide logout it cannot observe.</p>'
      : '<p>This session had signed into no service provider through this profile, so there is ' +
        'nothing to log out of.</p>') +
    (params.RelayState ? '<div class="meta"><div>RelayState: <code>' +
      xmlEscape(String(params.RelayState)) + '</code></div></div>' : '');
  sendPage(res, 200, 'Signed out — SAML 2.0', inner);
  log.debug("Leaving identityProviderInitiatedLogout(). " + names.length + " named.");
}

// ---------------------------------------------------------------------------
// THE METADATA (saml-metadata-2.0-os).
//
// SIGNED, with ds:Signature FIRST inside EntityDescriptor — the metadata schema
// puts it at the head of the sequence, where a protocol message puts it after
// Issuer and a SAML 1.1 assertion puts it last. Four documents in this service,
// three positions, all schema-mandated; see wsfed.js's federation metadata,
// which is the same argument for the same reason.
//
// It answers for ANY {sp}. See decision 1 — the ask is what registers it.
// ---------------------------------------------------------------------------
function metadataFor(base, spEntityId) {
  log.debug("Entering metadataFor(). sp=" + (spEntityId || '(unscoped)'));
  const id = genId();
  const idpEntityId = idpEntityIdFor(spEntityId);
  const where = endpointsFor(base, spEntityId);
  const keyDescriptor = function (use) {
    return '<md:KeyDescriptor use="' + use + '"><ds:KeyInfo xmlns:ds="' + NS_DS + '">' +
      '<ds:X509Data><ds:X509Certificate>' + STS.certB64 +
      '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>';
  };
  const service = function (element, binding, location, extra) {
    return '<md:' + element + ' Binding="' + binding + '" Location="' + xmlEscape(location) + '"' +
      (extra || '') + '/>';
  };
  const xml =
    '<?xml version="1.0" encoding="UTF-8"?>' +
    '<md:EntityDescriptor xmlns:md="' + NS_MD + '" ID="' + id + '"' +
      ' entityID="' + xmlEscape(idpEntityId) + '">' +
      '<md:IDPSSODescriptor' +
        // WantAuthnRequestsSigned is FALSE and that is the honest value: this
        // service records a request signature and does not check it (decision
        // 3). Advertising `true` would be asking service providers to sign
        // something nothing verifies, which is worse than not asking.
        ' WantAuthnRequestsSigned="false"' +
        ' protocolSupportEnumeration="' + NS_SAMLP + '">' +
        keyDescriptor('signing') +
        // The artifact resolution service comes FIRST inside the descriptor,
        // because the metadata schema's sequence puts ArtifactResolutionService
        // before SingleLogoutService before NameIDFormat before
        // SingleSignOnService. A document in any other order is one a generated
        // parser rejects, and hand-written parsers were written against this.
        service('ArtifactResolutionService', BINDING_SOAP, where.ars, ' index="0" isDefault="true"') +
        service('SingleLogoutService', BINDING_REDIRECT, where.slo) +
        service('SingleLogoutService', BINDING_POST, where.slo) +
        NAMEID_FORMATS.map(function (format) {
          return '<md:NameIDFormat>' + format + '</md:NameIDFormat>';
        }).join('') +
        service('SingleSignOnService', BINDING_REDIRECT, where.sso) +
        service('SingleSignOnService', BINDING_POST, where.sso) +
        // The artifact SSO endpoint. It is the same URL as the other two, which
        // is correct and looks wrong: HTTP-Artifact as a REQUEST binding means
        // the AuthnRequest arrives as an artifact this service would resolve at
        // the service provider — which this service does not do — while the
        // ARTIFACT PROFILE that everybody means is a request over Redirect or
        // POST with ProtocolBinding=HTTP-Artifact on it. It is advertised so a
        // service provider that populates its binding menu from the metadata
        // (the debugger does) offers the artifact choice at all.
        service('SingleSignOnService', BINDING_ARTIFACT, where.sso) +
      '</md:IDPSSODescriptor>' +
      '<md:Organization>' +
        '<md:OrganizationName xml:lang="en">mock-sts</md:OrganizationName>' +
        '<md:OrganizationDisplayName xml:lang="en">Mock security token service' +
        '</md:OrganizationDisplayName>' +
        '<md:OrganizationURL xml:lang="en">' + xmlEscape(base) + '/</md:OrganizationURL>' +
      '</md:Organization>' +
    '</md:EntityDescriptor>';
  logArtifact('SAML 2.0 IdP metadata', 'before signing', xml);
  try {
    const signed = signDocument(xml, 'EntityDescriptor', id, 'prepend');
    logArtifact('SAML 2.0 IdP metadata', 'after signing', signed);
    log.debug("Leaving metadataFor(). Signed.");
    return signed;
  } catch (e) {
    log.error('the SAML 2.0 metadata could not be signed, serving it unsigned: ' + e.message);
    log.debug("Leaving metadataFor(). Unsigned.");
    return xml;
  }
}

function serveMetadata(req, res) {
  log.debug("Entering the SAML 2.0 metadata endpoint.");
  const base = baseUrlOf(req);
  const scoped = entityIdFromSegment(req.params.sp);
  if (scoped.entityId) {
    // THE ASK IS WHAT REGISTERS IT. `counts: false` because fetching a metadata
    // document is not an authentication and is not even a request from that
    // service provider — it is somebody configuring one.
    recordServiceProvider({
      identifier: scoped.entityId,
      kind: 'saml2-service-provider',
      protocol: 'SAML 2.0',
      counts: false,
      note: scoped.known
        ? 'its identity provider metadata was fetched'
        : 'first seen when its identity provider metadata was asked for',
      fields: { samlEntityId: scoped.entityId }
    });
  }
  // no-store like every other document here that carries the signing key: the
  // key is regenerated on every start, so a cached copy describes a key that is
  // gone and the failure looks like a broken signature rather than a stale
  // document.
  res.status(200).type('application/samlmetadata+xml').set('Cache-Control', 'no-store')
     .send(metadataFor(base, scoped.entityId));
  log.debug("Leaving the SAML 2.0 metadata endpoint. sp=" + (scoped.entityId || '(unscoped)'));
}

// ---------------------------------------------------------------------------
// THE PAGES A PERSON REACHES BY CLICKING.
// ---------------------------------------------------------------------------
function describeSsoPage(base, scoped) {
  log.debug("Entering describeSsoPage().");
  const where = endpointsFor(base, scoped.entityId);
  return '<h1>SAML 2.0 — Single Sign-On service</h1>' +
    '<p class="sub">Identity provider <code>' + xmlEscape(idpEntityIdFor(scoped.entityId)) +
    '</code> at <code>' + xmlEscape(where.sso) + '</code></p>' +
    '<p>This endpoint takes a <code>SAMLRequest</code> carrying a ' +
    '<code>&lt;samlp:AuthnRequest&gt;</code>, on the HTTP Redirect binding (a GET) or the HTTP ' +
    'POST binding (a form POST), and answers with a <code>&lt;samlp:Response&gt;</code> on ' +
    'whichever binding the request\'s <code>ProtocolBinding</code> asked for. It authenticates ' +
    'nobody: the username typed at the sign-in screen becomes the subject of the assertion.</p>' +
    '<h2>Try it</h2><ul>' +
    '<li><a href="' + SP_PATH + '">' + SP_PATH + '</a> — a mock service provider here that sends ' +
    'a complete AuthnRequest over each of the three bindings and then verifies the response check ' +
    'by check.</li>' +
    '<li><a href="' + xmlEscape(where.metadata) + '">' + xmlEscape(where.metadata) + '</a> — the ' +
    'signed identity provider metadata, which is what a service provider should be configured ' +
    'from.</li></ul>' +
    '<h2>What it reads</h2><table><thead><tr><th>Where</th><th>What this service does with it</th>' +
    '</tr></thead><tbody>' +
    [['SAMLRequest', 'Required. DEFLATE + base64 on the Redirect binding, plain base64 on POST — ' +
                     'and either is accepted on either, because a service provider that ' +
                     'compresses a POST message is out of profile and common.'],
     ['RelayState', 'Echoed back byte for byte and never interpreted. It is the service ' +
                    'provider\'s own state, and an identity provider that decoded and re-encoded ' +
                    'it produces the same symptom as a lost session.'],
     ['SigAlg, Signature', 'The Redirect binding\'s detached signature (section 3.4.4.1). ' +
                           'RECORDED AND NOT CHECKED, like every credential here.'],
     ['ProtocolBinding', 'Which binding the RESPONSE comes back on: HTTP-POST (the default), ' +
                         'HTTP-Redirect or HTTP-Artifact. Anything else is refused by name.'],
     ['AssertionConsumerServiceURL', 'Where the response goes. Not validated against any ' +
                                     'registration, like every other return URL here. With none, ' +
                                     'the response goes to this service\'s own mock service ' +
                                     'provider at ' + SP_PATH + '.'],
     ['NameIDPolicy/@Format', 'Answered with the format it asks for, whatever it is. With none, ' +
                              'the saml2.nameIdFormat setting.'],
     ['ForceAuthn', 'Shows the sign-in screen even when a session already exists.'],
     ['IsPassive', 'Never shows it: with no usable session the answer is a Response carrying ' +
                   'NoPassive, which is the status code a service provider is least likely to ' +
                   'have handled.'],
     ['RequestedAuthnContext', 'A class asking for more than one factor takes the opt-out away at ' +
                               'the sign-in screen — the OPPOSITE of what WS-Federation\'s wauth ' +
                               'does, because this screen can actually run the ceremony.'],
     ['Subject/NameID', 'Read as a hint to pre-fill the sign-in screen, exactly as OIDC\'s ' +
                        'login_hint is, and never as a claim about who is at the browser.'],
     ['Destination, IssueInstant', 'Recorded in the log. Neither is enforced: there is no clock ' +
                                   'skew setting for this profile to reject a request under.']
    ].map(function (r) {
      return '<tr><td><code>' + r[0] + '</code></td><td>' + r[1] + '</td></tr>';
    }).join('') + '</tbody></table>' +
    '<div class="meta"><div>Not implemented, and stated rather than left to be discovered: ' +
    'encrypted assertions and encrypted NameIDs (the assertion is signed and in the clear), ' +
    'the ECP profile and its PAOS binding, identity-provider-initiated SSO with an unsolicited ' +
    'Response, Name Identifier Management, and the Assertion Query and Request profile. ' +
    'AuthnRequest signatures are recorded and not verified.</div></div>';
}

app.get(BASE_PATH, function (req, res) {
  log.debug("Entering the SAML 2.0 description page.");
  const base = baseUrlOf(req);
  const where = endpointsFor(base, '');
  sendPage(res, 200, 'SAML 2.0 — Web Browser SSO',
    '<h1>SAML 2.0 — Web Browser SSO, all three bindings</h1>' +
    '<p class="sub">Identity provider <code>' + xmlEscape(idpEntityIdFor('')) + '</code> at ' +
    '<code>' + xmlEscape(base) + '</code></p>' +
    '<p>A full SAML 2.0 identity provider: HTTP Redirect and HTTP POST for the request, and ' +
    'HTTP POST, HTTP Redirect or HTTP Artifact for the response, with a SOAP artifact resolution ' +
    'service behind the third. It accepts ANY entityID — a service provider does not have to be ' +
    'provisioned here before it can be pointed at this service, and the first valid AuthnRequest ' +
    'from an entityID creates its application entry in the embedded directory.</p>' +
    '<h2>The endpoints</h2><table><thead><tr><th>Endpoint</th><th>What it is</th></tr></thead>' +
    '<tbody>' +
    '<tr><td><a href="' + SSO_PATH + '">' + SSO_PATH + '</a></td><td>Single Sign-On. ' +
      '<code>' + SSO_PATH + '/{sp}</code> is the same service scoped to one service provider.' +
      '</td></tr>' +
    '<tr><td><code>' + ARS_PATH + '</code></td><td>Artifact Resolution, SOAP over HTTP. A ' +
      'browser never touches it — the service provider calls it directly, which is the whole ' +
      'point of the artifact profile.</td></tr>' +
    '<tr><td><a href="' + SLO_PATH + '">' + SLO_PATH + '</a></td><td>Single Logout, both ' +
      'directions.</td></tr>' +
    '<tr><td><a href="' + METADATA_PATH + '">' + METADATA_PATH + '</a></td><td>The signed ' +
      'identity provider metadata. <code>' + METADATA_PATH + '/{sp}</code> is a document of its ' +
      'OWN for that service provider — a different entityID and different endpoints — and it is ' +
      'minted for any {sp} asked for.</td></tr>' +
    '<tr><td><a href="' + SP_PATH + '">' + SP_PATH + '</a></td><td>A mock service provider. ' +
      'NON-SPEC, the default assertion consumer service, and where a response can be verified ' +
      'check by check without a second service.</td></tr>' +
    '</tbody></table>' +
    '<h2>Per-service-provider metadata</h2>' +
    '<p>Every service provider gets its own identity provider, the way Okta and Ping do it. Ask ' +
    'for <code>' + METADATA_PATH + '/{anything}</code> and it is minted — the entityID may be a ' +
    'percent-encoded URL or a plain name:</p>' +
    '<ul><li><a href="' + METADATA_PATH + '/example-sp">' + METADATA_PATH + '/example-sp</a></li>' +
    '<li><code>' + METADATA_PATH + '/' + encodeURIComponent('https://sp.example.com/saml') +
    '</code></li></ul>' +
    '<p><code>saml2.perApplicationEntityId</code> turns the per-application entityID off; the ' +
    'endpoints stay per-application either way, which is what makes the documents worth having ' +
    'separately.</p>' +
    '<div class="meta"><div>The generic endpoints are <code>' + xmlEscape(where.sso) +
    '</code>, <code>' + xmlEscape(where.slo) + '</code> and <code>' + xmlEscape(where.ars) +
    '</code>. They behave identically — the scope in the path decides which identity provider ' +
    'names itself in the answer, and the AuthnRequest\'s own Issuer decides who the assertion is ' +
    'for either way.</div></div>');
  log.debug("Leaving the SAML 2.0 description page.");
});

app.get(METADATA_PATH, serveMetadata);
app.get(METADATA_PATH + '/:sp', serveMetadata);

app.get(SSO_PATH, singleSignOn);
app.get(SSO_PATH + '/:sp', singleSignOn);
// The HTTP POST binding (section 3.5). The one thing to know about it is
// decision 2: this handler holds the request and turns it into a GET, because
// the session cookie is SameSite=Lax and does not arrive on a cross-site POST.
app.post(SSO_PATH, singleSignOn);
app.post(SSO_PATH + '/:sp', singleSignOn);

app.post(ARS_PATH, resolveArtifact);
app.post(ARS_PATH + '/:sp', resolveArtifact);
// A GET on the artifact resolution service is a person who clicked it, and
// answering "Cannot POST" would send them looking for a typo.
app.get(ARS_PATH, function (req, res) {
  log.debug("Entering the artifact resolution service description page.");
  sendPage(res, 200, 'Artifact Resolution Service — SAML 2.0',
    '<h1>Artifact Resolution Service</h1>' +
    '<p class="sub">SOAP over HTTP (saml-bindings-2.0-os section 3.2.3), at <code>' +
    ARS_PATH + '</code></p>' +
    '<p>This endpoint takes a POST whose body is a SOAP 1.1 envelope carrying a ' +
    '<code>&lt;samlp:ArtifactResolve&gt;</code>, and answers with one carrying a ' +
    '<code>&lt;samlp:ArtifactResponse&gt;</code> with the message inside it. It is a BACK ' +
    'CHANNEL: the browser never touches it, which is the whole point of the artifact profile — ' +
    'the assertion never passes through the user agent at all.</p>' +
    '<h2>By hand</h2><pre>' + xmlEscape(
      'curl -s -X POST http://localhost:8081' + ARS_PATH + " \\\n" +
      "  -H 'Content-Type: text/xml; charset=utf-8' -H 'SOAPAction: \"\"' \\\n" +
      "  -d '<soap:Envelope xmlns:soap=\"" + NS_SOAP + "\"><soap:Body>" +
      '<samlp:ArtifactResolve xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' + NS_SAML + '" ' +
      'ID="_1" Version="2.0" IssueInstant="' + iso(0) + '">' +
      '<saml:Issuer>https://sp.example.com/saml</saml:Issuer>' +
      '<samlp:Artifact>THE-SAMLart-VALUE</samlp:Artifact>' +
      "</samlp:ArtifactResolve></soap:Body></soap:Envelope>'") + '</pre>' +
    '<div class="meta"><div>An artifact resolves EXACTLY ONCE — section 3.6.4.1 — so running ' +
    'that command twice with the same artifact is refused the second time, by design. It also ' +
    'expires: <code>saml2.artifactTtlS</code>.</div></div>');
  log.debug("Leaving the artifact resolution service description page.");
});

app.get(SLO_PATH, singleLogout);
app.get(SLO_PATH + '/:sp', singleLogout);
app.post(SLO_PATH, singleLogout);
app.post(SLO_PATH + '/:sp', singleLogout);

// ===========================================================================
// THE MOCK SERVICE PROVIDER. NON-SPEC, and it earns its place the same two ways
// /wsfed/rp does:
//
//   * it is the default AssertionConsumerServiceURL, so an AuthnRequest that
//     names no return address has somewhere real to go instead of nowhere;
//   * it makes the profile testable from one service. Everything else here is
//     verified by the client under test; a Response POSTed into the void could
//     not be checked at all without standing up a second service, and the checks
//     below are the ones that catch the mistakes this profile makes — an
//     unresolvable signature reference, a mangled RelayState, an audience naming
//     the wrong service provider, a SubjectConfirmationData whose InResponseTo
//     does not match the request.
// ===========================================================================
function verifyResponseSignature(xml, wanted) {
  log.debug("Entering verifyResponseSignature(). wanted=" + wanted);
  try {
    const doc = new DOMParser().parseFromString(xml, 'text/xml');
    // The Response's own signature is a DIRECT child of the Response; the
    // assertion's is a direct child of the Assertion. `firstByLocal` would find
    // whichever came first in the document, which is not the same question — and
    // getting it wrong reports the assertion's signature twice and the
    // response's never.
    const root = wanted === 'Response'
      ? doc.documentElement
      : firstByLocal(doc.documentElement, 'Assertion');
    if (!root) {
      log.debug("Leaving verifyResponseSignature(). There is no " + wanted + ".");
      return { ok: false, present: false, why: 'there is no <' + wanted + '> to check' };
    }
    let sigEl = null;
    for (let i = 0; i < root.childNodes.length; i++) {
      const child = root.childNodes[i];
      if (child.nodeType === 1 && child.localName === 'Signature') { sigEl = child; break; }
    }
    if (!sigEl) {
      log.debug("Leaving verifyResponseSignature(). It is not signed.");
      return { ok: false, present: false, why: 'the ' + wanted + ' carries no ds:Signature' };
    }
    const sig = new SignedXml({ publicCert: STS.certPem });
    sig.loadSignature(sigEl);
    // No `idAttribute` — SAML 2.0's is `ID`, which is already one of the
    // defaults, and naming it again UNSHIFTS A DUPLICATE onto that list and
    // trips xml-crypto's signature-wrapping guard with a security error about a
    // document that has nothing wrong with it. wsfed.js's
    // verifyAssertionSignature() cost a debugging session over exactly this.
    const ok = sig.checkSignature(xml);
    log.debug("Leaving verifyResponseSignature(). ok=" + ok);
    return { ok: !!ok, present: true, why: ok ? '' : 'the signature did not verify' };
  } catch (e) {
    // xml-crypto throws rather than returning false for most failures, and the
    // message names which of them it was — an unresolvable reference reads quite
    // differently from a digest mismatch, and that distinction is the diagnosis.
    log.debug("Leaving verifyResponseSignature(). It threw: " + e.message);
    return { ok: false, present: true, why: e.message };
  }
}

// Every check, in the order a service provider would apply them, each with its
// own verdict. One boolean for the whole response would say "it failed" and
// nothing anybody could act on — the same argument /wsfed/rp and the OID4VP
// verifier both make.
function verifyResponse(xml, spEntityId, acsUrl, relayState) {
  log.debug("Entering verifyResponse().");
  const checks = [];
  const add = function (name, ok, detail) { checks.push({ name: name, ok: !!ok, detail: detail }); };
  const result = { checks: checks, subject: '', attributes: [], sessionIndex: '', status: '' };

  let doc = null;
  try {
    doc = new DOMParser().parseFromString(xml, 'text/xml');
  } catch (e) {
    add('the response parses as XML', false, e.message);
    log.debug("Leaving verifyResponse(). Not XML.");
    return result;
  }
  const root = doc.documentElement;
  add('it is a samlp:Response', !!root && root.localName === 'Response',
      root ? '<' + root.localName + '> in ' + (root.namespaceURI || '(no namespace)')
           : 'nothing parsed');
  if (!root || root.localName !== 'Response') {
    log.debug("Leaving verifyResponse(). Not a Response.");
    return result;
  }

  const statusEl = firstByLocal(root, 'StatusCode');
  const status = statusEl ? (statusEl.getAttribute('Value') || '') : '';
  result.status = status;
  const statusMessage = textByLocal(root, 'StatusMessage');
  add('the status is Success', status === STATUS_SUCCESS,
      (status || '(no StatusCode)') + (statusMessage ? ' — ' + statusMessage : ''));

  const issuer = textByLocal(root, 'Issuer');
  add('the issuer is this identity provider', issuer === idpEntityIdFor(spEntityId),
      issuer + (issuer === idpEntityIdFor(spEntityId) ? ''
        : ', expected ' + idpEntityIdFor(spEntityId)));

  const destination = root.getAttribute('Destination') || '';
  add('Destination names this assertion consumer service', destination === acsUrl,
      destination || '(none)');

  const responseSig = verifyResponseSignature(xml, 'Response');
  add('the Response signature verifies', responseSig.ok,
      responseSig.present ? (responseSig.ok ? 'RSA-SHA256 over an exclusive canonicalization'
                                            : responseSig.why)
        : 'unsigned — saml2.signResponse is off, which is a supported state and not a failure ' +
          'of the service provider');

  const assertion = firstByLocal(root, 'Assertion');
  add('it contains an assertion', !!assertion,
      assertion ? 'in ' + assertion.namespaceURI : 'no saml:Assertion — see the status above');
  if (!assertion) {
    result.ok = checks.every(function (c) { return c.ok; });
    log.debug("Leaving verifyResponse(). No assertion.");
    return result;
  }

  const assertionSig = verifyResponseSignature(xml, 'Assertion');
  add('the assertion signature verifies', assertionSig.ok,
      assertionSig.present ? (assertionSig.ok ? 'resolved through the ID attribute'
                                              : assertionSig.why)
        : 'unsigned — saml2.signAssertion is off');

  const conditions = firstByLocal(assertion, 'Conditions');
  const audience = conditions ? textByLocal(conditions, 'Audience') : '';
  add('the audience is this service provider', audience === spEntityId,
      'audience ' + (audience || '(none)') + ', expected ' + spEntityId);

  const notBefore = conditions ? conditions.getAttribute('NotBefore') : '';
  const notOnOrAfter = conditions ? conditions.getAttribute('NotOnOrAfter') : '';
  const now = Date.now();
  add('it is inside its validity window',
      !!notBefore && !!notOnOrAfter && Date.parse(notBefore) <= now && now < Date.parse(notOnOrAfter),
      (notBefore || '(no NotBefore)') + ' to ' + (notOnOrAfter || '(no NotOnOrAfter)'));

  // The four things saml-profiles section 4.1.4.2 requires of a BEARER
  // assertion, which is the half of the profile a service provider most often
  // skips and an identity provider most often omits.
  const scd = firstByLocal(assertion, 'SubjectConfirmationData');
  add('the bearer SubjectConfirmationData is there', !!scd,
      scd ? 'Recipient, NotOnOrAfter and InResponseTo' : 'missing — section 4.1.4.2 requires it');
  if (scd) {
    add('its Recipient is this assertion consumer service',
        (scd.getAttribute('Recipient') || '') === acsUrl,
        scd.getAttribute('Recipient') || '(none)');
    const known = spContexts.get(String(relayState || ''));
    add('its InResponseTo is the request this service provider sent',
        !!known && (scd.getAttribute('InResponseTo') || '') === known.requestId,
        known ? (scd.getAttribute('InResponseTo') || '(none)') + ', expected ' + known.requestId
              : 'this service provider has no record of the request — the RelayState was altered, ' +
                'or this response was not started from ' + SP_PATH);
  }

  // The RelayState round trip. Its own state, so this service provider is the
  // only thing that can check it — and an identity provider that decoded and
  // re-encoded it, or dropped it for being long, produces exactly the same
  // symptom as a lost session.
  const known = spContexts.get(String(relayState || ''));
  add('RelayState came back unaltered', !!known,
      known ? 'the same value this service provider minted, byte for byte'
            : (relayState ? 'this service provider did not mint "' + relayState + '"'
                          : 'no RelayState came back'));

  const nameEl = firstByLocal(assertion, 'NameID');
  result.subject = nameEl ? (nameEl.textContent || '').trim() : '';
  result.nameIdFormat = nameEl ? (nameEl.getAttribute('Format') || '') : '';
  add('the assertion names a subject', !!result.subject, result.subject || '(none)');

  const authnStatement = firstByLocal(assertion, 'AuthnStatement');
  result.sessionIndex = authnStatement ? (authnStatement.getAttribute('SessionIndex') || '') : '';
  result.authnContext = textByLocal(assertion, 'AuthnContextClassRef');
  add('it carries an AuthnStatement with a SessionIndex', !!result.sessionIndex,
      result.sessionIndex ? result.sessionIndex + ' (' + (result.authnContext || 'no class ref') + ')'
                          : 'missing — Single Logout has nothing to name the session by');

  const attributes = assertion.getElementsByTagNameNS('*', 'Attribute');
  for (let i = 0; i < attributes.length; i++) {
    const a = attributes[i];
    const values = a.getElementsByTagNameNS('*', 'AttributeValue');
    const list = [];
    for (let j = 0; j < values.length; j++) {
      list.push((values[j].textContent || '').trim());
    }
    result.attributes.push({ name: a.getAttribute('Name') || '',
                             nameFormat: a.getAttribute('NameFormat') || '',
                             values: list });
  }
  add('the attributes arrived', result.attributes.length > 0,
      result.attributes.length + ' attribute(s)');

  result.ok = checks.every(function (c) { return c.ok; });
  log.debug("Leaving verifyResponse(). ok=" + result.ok + ", " + checks.length + " check(s).");
  return result;
}

// The mock service provider's own AuthnRequest. Unsigned, and that is not
// laziness: this identity provider records a request signature and does not
// check it (decision 3), so a signature here would be ceremony that proved
// nothing — and the one thing worth demonstrating, that an unsigned request is
// accepted, is exactly what the debugger's signed one cannot show.
function spAuthnRequest(base, spEntityId, acsUrl, protocolBinding, destination) {
  log.debug("Entering spAuthnRequest(). binding=" + protocolBinding);
  const id = genId();
  const xml =
    '<samlp:AuthnRequest xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' + NS_SAML + '"' +
      ' ID="' + id + '" Version="2.0" IssueInstant="' + iso(0) + '"' +
      ' Destination="' + xmlEscape(destination) + '"' +
      ' ProtocolBinding="' + protocolBinding + '"' +
      ' AssertionConsumerServiceURL="' + xmlEscape(acsUrl) + '">' +
      '<saml:Issuer>' + xmlEscape(spEntityId) + '</saml:Issuer>' +
      '<samlp:NameIDPolicy AllowCreate="true"/>' +
    '</samlp:AuthnRequest>';
  log.debug("Leaving spAuthnRequest(). id=" + id);
  return { id: id, xml: xml };
}

app.get(SP_PATH, function (req, res) {
  log.debug("Entering the mock service provider (GET).");
  const base = baseUrlOf(req);
  const spEntityId = base + SP_PATH;
  const acsUrl = base + SP_PATH;
  const destination = base + SSO_PATH;

  // A response can also arrive HERE by GET — the HTTP Redirect binding for a
  // response, and the artifact binding's SAMLart. Both are answered by the same
  // verification the POST below runs, because what arrived is the same document.
  const params = paramsOf(req);
  if (params.SAMLResponse || params.SAMLart) {
    log.debug("Leaving the mock service provider (GET). A response arrived on a GET binding.");
    return receiveAtMockSp(req, res, params, base, spEntityId, acsUrl);
  }

  const links = [BINDING_POST, BINDING_REDIRECT, BINDING_ARTIFACT].map(function (binding) {
    const built = spAuthnRequest(base, spEntityId, acsUrl, binding, destination);
    const relayState = 'sp-' + randomId(12);
    spContexts.set(relayState, { requestId: built.id, binding: binding,
                                 expires: Date.now() + SP_CONTEXT_TTL_MS });
    spContexts.forEach(function (v, k) { if (v.expires < Date.now()) spContexts.delete(k); });
    const url = destination + '?SAMLRequest=' + encodeURIComponent(encodeRedirect(built.xml)) +
      '&RelayState=' + encodeURIComponent(relayState);
    const label = binding === BINDING_POST ? 'HTTP POST' :
      (binding === BINDING_REDIRECT ? 'HTTP Redirect' : 'HTTP Artifact');
    return '<li><a href="' + xmlEscape(url) + '">Response over ' + label + '</a> — the request ' +
      'goes on the Redirect binding, and <code>ProtocolBinding</code> asks for the answer on ' +
      label + '.' + (binding === BINDING_ARTIFACT
        ? ' The browser will carry a <code>SAMLart</code> back here and this page resolves it.' : '') +
      '</li>';
  }).join('');

  const inner = '<h1>Mock service provider</h1>' +
    '<p class="sub">NON-SPEC. A service provider is not part of an identity provider — this one ' +
    'exists so the Web Browser SSO profile can be exercised, and verified, without a second ' +
    'service.</p>' +
    '<p>Its entityID is <code>' + xmlEscape(spEntityId) + '</code>, and it is also the default ' +
    '<code>AssertionConsumerServiceURL</code>: an AuthnRequest that names none is answered ' +
    'here.</p>' +
    '<h2>Start a sign-in</h2><ul>' + links + '</ul>' +
    '<h2>Then</h2><ul>' +
    '<li><a href="' + SLO_PATH + '">Single Logout</a> — ends the session and names every service ' +
    'provider it signed into.</li>' +
    '<li><a href="' + METADATA_PATH + '/' + encodeURIComponent(slugOf(spEntityId)) + '">This ' +
    'service provider\'s own identity provider metadata</a> — a distinct entityID and its own ' +
    'endpoints, which is what makes the metadata unique per application.</li></ul>' +
    '<div class="meta"><div>The AuthnRequests above are UNSIGNED, deliberately: this identity ' +
    'provider records a request signature and does not check it, so signing here would be ' +
    'ceremony that proved nothing — and an unsigned request being accepted is itself the ' +
    'behaviour worth showing.</div></div>';
  sendPage(res, 200, 'Mock service provider — SAML 2.0', inner);
  log.debug("Leaving the mock service provider (GET).");
});

// Resolving an artifact for the mock service provider. It calls the resolution
// function IN PROCESS rather than making a SOAP call to this same service over
// HTTP, and that is a deliberate refusal rather than a shortcut: an outbound
// HTTP request this service makes to a URL it computed is the shape of thing
// every other module here declines to do (wsfed's `wreqptr`, the registry's
// `jwks_uri`), and there is nothing to learn from this process talking to
// itself over a socket. What the page does instead is SHOW the SOAP exchange
// that a real service provider would have made.
function resolveForMockSp(artifact) {
  log.debug("Entering resolveForMockSp().");
  const held = artifacts.get(artifact);
  if (!held) {
    log.debug("Leaving resolveForMockSp(). It does not resolve.");
    return { ok: false, why: 'that artifact does not resolve: it was never issued here, it has ' +
                             'expired, or it has already been resolved — an artifact is one-shot.' };
  }
  artifacts.delete(artifact);
  log.debug("Leaving resolveForMockSp(). Resolved and destroyed.");
  return { ok: true, xml: held.xml };
}

function receiveAtMockSp(req, res, params, base, spEntityId, acsUrl) {
  log.debug("Entering receiveAtMockSp().");
  const relayState = String(params.RelayState || '');
  let xml = '';
  let howItArrived = '';
  if (params.SAMLart) {
    const resolved = resolveForMockSp(String(params.SAMLart));
    if (!resolved.ok) {
      log.debug("Leaving receiveAtMockSp(). The artifact did not resolve.");
      return sendPage(res, 200, 'Artifact did not resolve — mock service provider',
        '<h1>The artifact did not resolve</h1>' +
        '<div class="err">' + xmlEscape(resolved.why) + '</div>' +
        '<p>The commonest cause is the most interesting one: an artifact is resolvable EXACTLY ' +
        'ONCE (section 3.6.4.1), so reloading this page after a successful resolution lands ' +
        'here. That is the behaviour rather than a fault.</p>' +
        '<p><a href="' + SP_PATH + '">Start another sign-in</a></p>');
    }
    xml = resolved.xml;
    howItArrived = 'as a SAMLart the browser carried, resolved over the back channel';
  } else {
    xml = decodeMessage(String(params.SAMLResponse || ''));
    howItArrived = req.method === 'POST'
      ? 'in the body of a form POST (the HTTP POST binding)'
      : 'on the query string (the HTTP Redirect binding)';
  }
  logArtifact('SAML 2.0 Response', 'as received by the mock service provider', xml);
  const verdict = verifyResponse(xml, spEntityId, acsUrl, relayState);
  if (relayState) spContexts.delete(relayState);

  const rows = verdict.checks.map(function (c) {
    return '<tr><td>' + xmlEscape(c.name) + '</td><td class="' + (c.ok ? 'pass">PASS' : 'fail">FAIL') +
      '</td><td>' + xmlEscape(c.detail) + '</td></tr>';
  }).join('');
  const attributeRows = verdict.attributes.map(function (a) {
    return '<tr><td><code>' + xmlEscape(a.name) + '</code></td><td>' +
      xmlEscape(a.values.join(', ')) + '</td><td>' + xmlEscape(a.nameFormat || '') + '</td></tr>';
  }).join('');
  const inner = '<h1>Response received</h1>' +
    '<p class="sub">Mock service provider at <code>' + xmlEscape(spEntityId) + '</code> — ' +
    xmlEscape(howItArrived) + '.</p>' +
    (verdict.ok
      ? '<div class="ok">Every check passed. An assertion for <code>' +
        xmlEscape(verdict.subject) + '</code>.</div>'
      : '<div class="err">Not every check passed. Each one below says which, and why — a single ' +
        'verdict for the whole response would say "it failed" and nothing anybody could act ' +
        'on.</div>') +
    '<h2>Checks</h2><table><thead><tr><th>Check</th><th>Verdict</th><th>Detail</th></tr></thead>' +
    '<tbody>' + rows + '</tbody></table>' +
    (attributeRows
      ? '<h2>Attributes</h2><table><thead><tr><th>Name</th><th>Value</th><th>NameFormat</th></tr>' +
        '</thead><tbody>' + attributeRows + '</tbody></table>' +
        '<p class="sub">Anything configured on <a href="/admin/saml-attributes">Custom SAML ' +
        'attributes</a> is in this table too: the SAML 2.0 set is appended by the same assertion ' +
        'builder that serves WS-Trust and WS-Federation, so it reaches this profile with no ' +
        'wiring of its own.</p>'
      : '') +
    '<h2>The response, as it arrived</h2><pre>' + xmlEscape(xml || '(nothing)') + '</pre>' +
    '<p><a href="' + SP_PATH + '">Start another sign-in</a> &middot; ' +
    '<a href="' + SLO_PATH + '">Sign out</a></p>' +
    '<div class="meta"><div>This service provider keeps no session. It verifies what it was sent ' +
    'and shows it, which is all a mock service provider can honestly claim to do.</div>' +
    (params.SAMLart
      ? '<div>The artifact was resolved IN PROCESS rather than by this service making a SOAP call ' +
        'to itself over HTTP — there is nothing to learn from that, and an outbound request to a ' +
        'URL this service computed is the shape of thing every other module here declines to ' +
        'make. A real service provider POSTs a signed ArtifactResolve to <code>' + ARS_PATH +
        '</code>; the curl for it is on <a href="' + ARS_PATH + '">that endpoint\'s own ' +
        'page</a>.</div>'
      : '') + '</div>';
  // 200 whatever the verdict: the request was answered, and the verdict is the
  // document. A 400 here would be this service provider reporting on the
  // identity provider's behaviour with a status code the browser attributes to
  // itself.
  sendPage(res, 200, 'Response — mock service provider', inner);
  log.debug("Leaving receiveAtMockSp(). ok=" + verdict.ok);
  return undefined;
}

app.post(SP_PATH, function (req, res) {
  log.debug("Entering the mock service provider (POST).");
  const base = baseUrlOf(req);
  receiveAtMockSp(req, res, paramsOf(req), base, base + SP_PATH, base + SP_PATH);
  log.debug("Leaving the mock service provider (POST).");
});

module.exports = {
  BINDING_REDIRECT: BINDING_REDIRECT,
  BINDING_POST: BINDING_POST,
  BINDING_ARTIFACT: BINDING_ARTIFACT,
  BINDING_SOAP: BINDING_SOAP,
  NAMEID_FORMATS: NAMEID_FORMATS,
  // Read by admin-ui/admin.js, which draws the console page for this profile
  // and must not reimplement any of it — the same division /admin/groups keeps
  // with ldap_server.js.
  slugOf: slugOf,
  idpEntityIdFor: idpEntityIdFor,
  endpointsFor: endpointsFor,
  artifactCount: function () { return artifacts.size; },
  pendingRequestCount: function () { return pendingRequests.size; },
  metadataFor: metadataFor,
  verifyResponse: verifyResponse,
  // The LogoutRequests one session is owed. Read by ../logout/logout.js so that
  // a global sign-out names exactly what Single Logout names — see the block
  // above logoutTargetsFor().
  logoutTargetsFor: logoutTargetsFor
};
