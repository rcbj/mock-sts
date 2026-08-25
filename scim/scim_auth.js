'use strict';
//
// File: scim_auth.js
//
// ---------------------------------------------------------------------------
// WHO IS ASKING AT THE SCIM ENDPOINTS, AND WHAT THEY MAY DO.
//
// This is the FIRST surface in this service that refuses a caller who presents
// nothing, and the reason it is this one is the reason SCIM was worth having at
// all: /scim/v2 is the only family here whose purpose is to WRITE. Every other
// endpoint answers a question about somebody — issue this person a token, seal
// this ticket, tell me who signed in. These create and DELETE accounts, in a
// directory that fifteen other things then read. A surface that does that and
// asks nobody's name is the one place in a permissive mock where "permissive"
// stops being a teaching device and starts being a hole somebody copies.
//
// **IT IS STILL PERMISSIVE, AND THAT IS THE WHOLE DESIGN.** Nothing here is a
// lock; it is a turnstile. Anybody may get an access token from this service's
// own token endpoint with any grant, asking for whatever scope they like.
// Anybody may present Basic with any username and any password but one. Anybody
// may register a HOBA public key and then authenticate with it. What changed is
// that a caller must now SAY who they are through one of the schemes RFC 7644
// section 2 names, and — for the OAuth ones — hold the scope for what they are
// about to do. That is exactly the shape a real deployment has, which is what
// makes a client's authentication and authorization paths runnable here; it is
// not a claim that this service checks anybody.
//
// ---------------------------------------------------------------------------
// WHAT THE SPECIFICATION ACTUALLY SAYS, BECAUSE IT IS SHORTER THAN PEOPLE
// EXPECT.
//
// RFC 7644 section 2: "The SCIM protocol is based upon HTTP and does not itself
// define a SCIM-specific scheme for authentication and authorization. SCIM
// depends on the use of Transport Layer Security (TLS) and/or standard HTTP
// authentication and authorization schemes as per [RFC7235]." So there is no
// SCIM credential to implement and no SCIM login to get wrong. What that
// section does is NAME six ways of doing it — TLS client authentication, HOBA,
// bearer tokens, proof-of-possession tokens, cookies, and HTTP Basic (which it
// discourages, in those words) — and then state the only two normative
// sentences in it:
//
//   * "a SCIM service provider SHALL indicate supported HTTP authentication
//     schemes via the 'WWW-Authenticate' header".  That is `challenges()` below
//     and the 401 every refusal here carries. It is a SHALL, so a 401 with no
//     challenge would be non-conforming — and, more to the point, useless: a
//     client that is told it failed and not what to send next cannot proceed.
//
//   * the provider "MUST be able to map the authenticated client to an access
//     control policy in order to determine the client's authorization to
//     retrieve and update SCIM resources".  This service HAS such a policy and
//     it is two lines long, which is the honest amount for a mock: an OAuth
//     credential may do what its scopes say, and every other scheme may do
//     everything. Both halves are published on GET /scim and on /admin/scim
//     rather than left to be discovered by a client that expected the second
//     half to be narrower.
//
// RFC 7643 section 5 is the other half: `authenticationSchemes` in the
// ServiceProviderConfig, whose `type` has five canonical values — `oauth`,
// `oauth2`, `oauthbearertoken`, `httpbasic`, `httpdigest`. Note what that list
// is NOT: it is not the same list as section 2's six, and three of the schemes
// section 2 names have no canonical value at all. How that is squared is in
// `schemesForConfig()` below and it is the one place where the two documents
// disagree with each other rather than with this service.
//
// ---------------------------------------------------------------------------
// THE TABLE IS THE WHOLE MODULE.
//
// `SCHEMES` is the single source for four surfaces that would otherwise drift:
//
//   * the WWW-Authenticate challenge on every 401 (the SHALL above),
//   * `authenticationSchemes` in the ServiceProviderConfig,
//   * what GET /scim tells a person,
//   * what /admin/scim and GET /admin-api/scim report, including the per-scheme
//     counters.
//
// A scheme is a row. Turning one off is a `config.js` row, so it disappears
// from the challenge and from the published document together — which is the
// property that matters, because a client reads a published scheme as a promise
// and a challenge as an instruction, and a server that advertised Digest while
// refusing every Digest request would be lying in both places at once.
//
// **DO NOT ADD A SCHEME THAT IS NOT IN RFC 7644 SECTION 2.** Every row here is
// something that section names. The temptation is API keys and a shared header,
// which is what most provisioning integrations actually use in the field; it is
// not in the specification, a client built against it here would interoperate
// with nothing, and this service already has six ways in.
//
// ---------------------------------------------------------------------------
// FOUR DECISIONS ARE LOAD-BEARING.
//
// **THE BEARER CHECK IS `dpop.presentedAccessToken()` AND NOT A SECOND ONE.**
// That function is the single check /oauth2/userinfo and the three OID4VCI
// credential endpoints already share, and it carries a great deal that is easy
// to leave out of a fresh implementation: the RFC 9449 proof and its nonce
// handshake, the RFC 8705 certificate binding, the RFC 9700 refusal of a token
// in a query string, and the audience check. Writing a fifth one here would be
// a fifth thing nobody updates. What it does NOT do is speak SCIM: it answers
// the request itself, with an OAuth-shaped `{error, error_description}` body,
// and a SCIM client is entitled to an RFC 7644 section 3.12 Error object. So it
// is called with a CAPTURING response object and what it would have said is
// translated. See `attemptBearer()`, where that shim is written out; it is a
// workaround and is commented as one rather than left to look like a design.
//
// **ONLY THE OAUTH SCHEMES CARRY SCOPES.** A Basic credential has none, a
// client certificate has none, a HOBA signature has none. The access control
// policy therefore reads: an OAuth credential may do what `scim:read` and
// `scim:write` say it may, and every other accepted credential may do both.
// That is a real policy rather than an absence of one, and it has a consequence
// worth stating where somebody will read it: a caller who cannot get the scope
// can simply use Basic instead. Which is why every scheme has its own switch —
// a deployment exercising a client's scope handling turns the other five off,
// and then the only way in is the one being tested.
//
// **WHICH SCHEMES COUNT AS AN AUTHENTICATION, AND WHICH DO NOT.** `recorded` on
// the row decides, and the rule is the one this service already applies
// everywhere: `stats.recordAuthentication()` is called at the moment a
// credential is ACCEPTED, and not again while that same act continues.
//
//   * Basic, Digest and HOBA are RECORDED. Each presents a credential on every
//     request, and accepting it is an act of authentication exactly as a
//     WS-Trust UsernameToken is. So SCIM became the fifteenth family to reach
//     that funnel — SPIFFE is the sixteenth and arrived after it — its callers
//     appear on /admin/users, and the directory seeds an entry for them like
//     any other.
//   * A BEARER OR DPoP token is NOT recorded. The credential behind it was
//     accepted when the token was issued — at the authorization endpoint, or at
//     the token endpoint for a grant with no user — and recording it again here
//     would count one sign-in once per provisioning request. Same reasoning that
//     keeps the token endpoint from counting an application sighting the
//     authorization endpoint already counted.
//   * A SESSION COOKIE is NOT recorded, for the same reason: `authn.js` already
//     recorded that sign-in, and the cookie is that session continuing.
//   * A CLIENT CERTIFICATE is NOT recorded here either, and this one is the
//     interesting one. `tls_server.js` records a certificate on
//     `secureConnection` and explicitly not per request, because one connection
//     carrying six requests is one authentication and not six. A per-request
//     record here would undo that decision from the other end.
//
// **NOTHING IN THIS FILE TOUCHES `res`.** It decides; `scim.js` answers, in
// SCIM's own error shape and with the headers this module hands back. Same
// split `oauth2_bcp.js` has with `oauth2.js`, and it is what makes the whole of
// this testable without a socket. The one exception proves it: `attemptBearer()`
// gives `presentedAccessToken()` a FAKE response to write into, precisely so
// that the real one is untouched.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3) AND IT REGISTERS NOTHING.
//
// It requires `helpers.js`, `config.js`, `dpop.js`, `mtls.js`, `admin_stats.js`,
// `authn.js`, `tls_server.js` and `ldap_server.js`, and none of those requires
// it back, so it cannot join a cycle. The last three are the only ones worth a
// sentence: they register routes, so requiring them from a module read EARLIER
// than they are would move those routes in the express router — but `scim.js`,
// the only thing that requires this file, already sits after all three in
// server.js's require order, so nothing moves. That is rule 3e's test applied
// rather than a slot added by analogy: there is no cycle and no route moves, so
// these are plain requires.
// ---------------------------------------------------------------------------

const crypto = require('crypto');

const { log, baseUrlOf, parseBody, hasScope } = require('../common/helpers');
const config = require('../common/config');
const dpop = require('../oauth-oidc/dpop');
const mtls = require('../oauth-oidc/mtls');
const stats = require('../common/admin_stats');
const authn = require('../authn/authn');
const tlsServer = require('../tls/tls_server');
const directory = require('../ldap/ldap_server');

// ---------------------------------------------------------------------------
// THE SETTINGS, READ WHERE THEY ARE USED.
//
// Every one of them is `runtime: true` in config.js, which is only true because
// each is read through a function called per request rather than captured in a
// `const` at require time. That is the rule that file's header states and the
// one that is easiest to break by accident — a captured value is the single
// thing /admin/config cannot reach, and it fails in the direction that looks
// like the console is broken.
// ---------------------------------------------------------------------------
function authRequired() {
  return config.value('scim.authRequired') !== false;
}

function authDiscovery() {
  return config.value('scim.authDiscovery') === true;
}

function realm() {
  // It goes into a header value, so quotes and anything outside printable ASCII
  // are taken out rather than trusted. node's setHeader THROWS on a non-ASCII
  // value and a quote would close the quoted-string early — either way a typo
  // in a configuration field would turn the one response that explains what to
  // send into a 500, which is the worst place in this module to have one.
  return String(config.value('scim.authRealm') || 'SCIM')
    .replace(/[^\x20-\x7E]/g, '').replace(/"/g, '').trim() || 'SCIM';
}

function scopeRead() {
  return String(config.value('scim.scopeRead') || 'scim:read');
}

function scopeWrite() {
  return String(config.value('scim.scopeWrite') || 'scim:write');
}

function digestPassword() {
  return String(config.value('scim.digestPassword') || '');
}

function digestNonceSeconds() {
  return Number(config.value('scim.digestNonceSeconds')) || 300;
}

function hobaMaxAgeSeconds() {
  return Number(config.value('scim.hobaMaxAgeSeconds')) || 600;
}

function schemeOn(key) {
  return config.value(key) !== false;
}

// The one refused password, exactly as the password grant, WS-Trust, the
// WS-Federation sign-in screen and every LDAP bind refuse it. It is what keeps
// a 401 reachable on a scheme that otherwise accepts anything — and note that
// Digest needs no such exception, because there the password is really checked.
const REFUSED_PASSWORD = 'invalid';

// ---------------------------------------------------------------------------
// THE SCHEMES.
//
// `type` is the RFC 7643 section 5 canonical value, or '' where the scheme has
// none — see `schemesForConfig()` for what happens to those. `attempt` returns
// null when the request is not using this scheme at all, and otherwise a
// decision. `challenge` is what goes in WWW-Authenticate, and a row with none
// is a scheme a client cannot be INVITED to use (a cookie is not something a
// server can ask for in a challenge, and a certificate is asked for by the TLS
// handshake or not at all).
//
// The ORDER is the order they are tried and the order they are advertised, and
// it is deliberate: the two token schemes first because they are the ones with
// an access control policy behind them, then the two password schemes, then the
// two that need no Authorization header at all.
// ---------------------------------------------------------------------------
const SCHEMES = [
  {
    id: 'bearer',
    type: 'oauthbearertoken',
    canonical: true,
    name: 'OAuth 2.0 Bearer Token',
    setting: 'scim.authBearer',
    primary: true,
    scoped: true,
    recorded: false,
    spec: 'RFC 6750',
    specUri: 'https://www.rfc-editor.org/rfc/rfc6750',
    description:
      'An access token issued by this service\'s own authorization server, ' +
      'presented as "Authorization: Bearer <token>". Any grant will do — ' +
      'authorization code, client credentials, password, refresh, device, ' +
      'token exchange — and the scope is whatever was asked for, because this ' +
      'authorization server grants what it is asked. The token must carry the ' +
      'read scope to read and the write scope to write, must be one THIS ' +
      'service signed, must not have been revoked, and must not have been ' +
      'narrowed by RFC 8707 to a different resource.',
    attempt: attemptBearer,
    challenge: bearerChallenge
  },
  {
    id: 'dpop',
    type: 'oauth2',
    canonical: true,
    name: 'OAuth 2.0 DPoP (proof-of-possession) token',
    setting: 'scim.authBearer',
    scoped: true,
    recorded: false,
    spec: 'RFC 9449',
    specUri: 'https://www.rfc-editor.org/rfc/rfc9449',
    description:
      'The proof-of-possession token RFC 7644 section 2 names, in the shape ' +
      'this service already issues: an access token bound to a key (cnf.jkt), ' +
      'presented as "Authorization: DPoP <token>" with a fresh DPoP proof over ' +
      'the method and URL. An RFC 8705 certificate-bound token is the other ' +
      'proof-of-possession form and is honoured on the same path. Handled by ' +
      'the same check as the Bearer row — they are one credential with two ' +
      'ways of being held — and listed separately because a client reading ' +
      'this document is entitled to know the bound form is understood.',
    attempt: null,
    challenge: null
  },
  {
    id: 'basic',
    type: 'httpbasic',
    canonical: true,
    name: 'HTTP Basic',
    setting: 'scim.authBasic',
    scoped: false,
    recorded: true,
    spec: 'RFC 7617',
    specUri: 'https://www.rfc-editor.org/rfc/rfc7617',
    description:
      'Any username and any password, exactly as every LDAP bind here ' +
      'succeeds — with the single exception of the password "invalid", which ' +
      'is refused so that a 401 stays reachable. RFC 7644 section 2 ' +
      'DISCOURAGES this scheme, in those words, because it rests on a ' +
      'relatively static symmetric secret; it is implemented anyway because ' +
      'it is what a provisioning client most often meets and its 401 handling ' +
      'is worth being able to run. No password is checked, so what this ' +
      'authenticates is a NAME, and that name is what the audit log records.',
    attempt: attemptBasic,
    challenge: basicChallenge
  },
  {
    id: 'digest',
    type: 'httpdigest',
    canonical: true,
    name: 'HTTP Digest',
    setting: 'scim.authDigest',
    scoped: false,
    recorded: true,
    spec: 'RFC 7616',
    specUri: 'https://www.rfc-editor.org/rfc/rfc7616',
    description:
      'The one scheme here where the password really is checked, and it ' +
      'cannot not be: the response is a hash over the password, so a server ' +
      'that accepted anything would not be performing the exchange at all. ' +
      'So it does what Kerberos does for the same reason — ANY username ' +
      'authenticates and every one of them shares one password ' +
      '(scim.digestPassword). SHA-256, SHA-512-256 and MD5 are all offered, ' +
      'in that order, with the -sess variants; qop is auth. A wrong password ' +
      'is a 401, a stale nonce is a 401 with stale=true, and a replayed nonce ' +
      'count is a 401 — three negatives that are otherwise hard to provoke.',
    attempt: attemptDigest,
    challenge: digestChallenge
  },
  {
    id: 'hoba',
    type: 'hoba',
    canonical: false,
    name: 'HOBA (HTTP Origin-Bound Authentication)',
    setting: 'scim.authHoba',
    scoped: false,
    recorded: true,
    spec: 'RFC 7486',
    specUri: 'https://www.rfc-editor.org/rfc/rfc7486',
    description:
      'The signature-based scheme RFC 7644 section 2 names, and the only one ' +
      'of the six with no password anywhere in it. A client registers a public ' +
      'key at /.well-known/hoba/register — anybody may, this service ' +
      'registers everybody — and then signs the server\'s challenge together ' +
      'with the origin, the realm and its own key id and nonce. THE SIGNATURE ' +
      'IS REALLY VERIFIED, for the reason the Digest password really is ' +
      'checked: a signature check that passes anything is not the scheme. RSA ' +
      'with SHA-256 (algorithm 0) only.',
    attempt: attemptHoba,
    challenge: hobaChallenge
  },
  {
    id: 'cookie',
    type: 'httpcookie',
    canonical: false,
    name: 'Session cookie',
    setting: 'scim.authCookie',
    scoped: false,
    recorded: false,
    spec: 'RFC 7644 section 2 ("Cookies")',
    specUri: 'https://www.rfc-editor.org/rfc/rfc7644#section-2',
    description:
      'The browser sign-on session this service already has — the one ' +
      '/authn/login establishes and WS-Federation shares — offered here ' +
      'because section 2 names it: "clients may assert HTTP cookies over TLS ' +
      'that contain an authentication state understood by the SCIM service ' +
      'provider". It is what makes a SCIM call from a page on this service ' +
      'work with no second credential. There is no challenge for it: a server ' +
      'cannot ask for a cookie in WWW-Authenticate, so it is used when it is ' +
      'there and never demanded.',
    attempt: attemptCookie,
    challenge: null
  },
  {
    id: 'clientcert',
    type: 'tlsclientauth',
    canonical: false,
    name: 'TLS client certificate',
    setting: 'scim.authClientCert',
    scoped: false,
    recorded: false,
    spec: 'RFC 8446 / RFC 5280',
    specUri: 'https://www.rfc-editor.org/rfc/rfc8446',
    description:
      'Mutual TLS, the first scheme RFC 7644 section 2 names. Available only ' +
      'where this request arrived over TLS with a certificate that VERIFIED ' +
      'against an anchor somebody POSTed to /tls/trust — so on the main port ' +
      'only when it is bound as HTTPS (global.https, which oauth2.rfc9700 ' +
      'turns on). The identity is the subject in RFC 4514 form, which is the ' +
      'same string /admin/users and the directory already file a certificate ' +
      'under. It is not recorded again here: tls_server.js records a ' +
      'certificate once per CONNECTION on purpose, and counting it per ' +
      'request would undo that from the other end.',
    attempt: attemptClientCertificate,
    challenge: null
  }
];

function schemeById(id) {
  return SCHEMES.filter(function (row) { return row.id === id; })[0] || null;
}

function enabledSchemes() {
  return SCHEMES.filter(function (row) { return schemeOn(row.setting); });
}

// ---------------------------------------------------------------------------
// THE CHALLENGES.
//
// RFC 7644 section 2's one SHALL. Every refusal from this module carries them,
// and they are built from the same table the ServiceProviderConfig is, so a
// scheme that is offered is one a client can actually use and a scheme that is
// turned off vanishes from both at once.
//
// Two schemes have no challenge and that is not an omission: a server cannot
// ask for a cookie in WWW-Authenticate, and a client certificate is asked for
// by the TLS handshake or not at all. Both are still published in the
// ServiceProviderConfig, which is where a client is meant to read them.
// ---------------------------------------------------------------------------
function bearerChallenge() {
  return 'Bearer realm="' + realm() + '", scope="' + scopeRead() + ' ' + scopeWrite() + '"';
}

function basicChallenge() {
  // charset="UTF-8" is RFC 7617 section 2.1: without it a client has no way to
  // know how to encode a non-ASCII password, and the two obvious guesses
  // disagree.
  return 'Basic realm="' + realm() + '", charset="UTF-8"';
}

function hobaChallenge(req) {
  return 'HOBA challenge="' + issueHobaChallenge() + '", max-age="' +
         hobaMaxAgeSeconds() + '", realm="' + realm() + '"';
}

// One challenge per algorithm, strongest first — RFC 7616 section 3.7 says a
// server MAY send several and SHOULD order them that way, and a client takes
// the first it understands. MD5 is last and is offered at all because the
// installed base of Digest clients that speak nothing else is most of it.
function digestChallenge(req, opts) {
  log.debug("Entering digestChallenge().");
  const stale = !!(opts && opts.stale);
  const nonce = issueDigestNonce();
  const opaque = crypto.randomBytes(8).toString('hex');
  const out = DIGEST_ALGORITHMS.map(function (row) {
    return 'Digest realm="' + realm() + '", qop="auth", algorithm=' + row.token +
      ', nonce="' + nonce + '", opaque="' + opaque + '", charset=UTF-8' +
      (stale ? ', stale=true' : '');
  });
  log.debug("Leaving digestChallenge(). " + out.length + " challenge(s).");
  return out;
}

// Every challenge a caller could act on, in table order. Returned as an ARRAY
// because express sets one header per element and RFC 7235 allows either that
// or one comma-joined value — and the array form is the one that survives a
// Digest challenge, whose value contains commas of its own.
function challenges(req, opts) {
  log.debug("Entering challenges().");
  const out = [];
  enabledSchemes().forEach(function (row) {
    if (!row.challenge) {
      return;
    }
    const built = row.challenge(req, opts);
    if (Array.isArray(built)) {
      built.forEach(function (one) { out.push(one); });
      return;
    }
    if (built) {
      out.push(built);
    }
  });
  log.debug("Leaving challenges(). " + out.length + " challenge(s).");
  return out;
}

// ---------------------------------------------------------------------------
// A REFUSAL, IN THE SHAPE `scim.js` NEEDS.
//
// This module never touches `res` — see the header — so a refusal is a value:
// the status, the RFC 7644 section 3.12 `scimType` where one applies (for these
// two statuses none does, which is why it is null and not invented), the prose,
// and the headers the answer must carry. `scim.js` turns it into a SCIM Error
// object, because what a refusal LOOKS like is protocol knowledge and stays in
// the protocol module.
// ---------------------------------------------------------------------------
function refusal(status, detail, headers) {
  return { ok: false, status: status, scimType: null, detail: detail,
           headers: headers || {} };
}

function unauthenticated(req, detail, extra) {
  const headers = Object.assign({ 'WWW-Authenticate': challenges(req, extra) },
                                (extra && extra.headers) || {});
  return refusal(401, detail, headers);
}

// ---------------------------------------------------------------------------
// THE SCHEME OF AN Authorization HEADER, WITHOUT PARSING THE REST OF IT.
//
// Read once, at the top of authenticate(), so that a request carrying a
// credential this service does not offer is told THAT rather than being told a
// credential is required — "you sent Negotiate and I speak Bearer, Basic,
// Digest and HOBA" is an answer somebody can act on in one step.
// ---------------------------------------------------------------------------
function authorizationScheme(req) {
  const header = String((req.headers && req.headers['authorization']) || '').trim();
  if (!header) {
    return '';
  }
  return header.split(/\s+/)[0].toLowerCase();
}

// ---------------------------------------------------------------------------
// OAUTH 2.0 — BEARER AND DPoP.
//
// THE CAPTURING RESPONSE, WHICH IS A WORKAROUND AND IS WRITTEN OUT AS ONE.
//
// `dpop.presentedAccessToken()` is the single access-token check the four
// protected endpoints in this service share, and it is worth every line of what
// follows to reuse it rather than write a fifth: it carries the RFC 9449 proof
// and the 401/DPoP-Nonce handshake, the RFC 8705 certificate binding, the RFC
// 9700 refusal of a token in the query string, and the RFC 8707 audience check.
// A second implementation would be a second thing to update and would be a
// version behind within a release.
//
// What it will not do is speak SCIM. It ANSWERS the request itself, with an
// OAuth `{error, error_description}` body — and a SCIM client is owed an RFC
// 7644 section 3.12 Error object with the status as a string. So it is handed a
// response object that records instead of writing, and what it would have said
// is translated into a refusal here. The HEADERS it set are kept verbatim,
// which is the part that matters most: DPoP-Nonce and the `use_dpop_nonce`
// challenge are how a wallet learns to retry, and dropping them would leave a
// conforming client unable to proceed with no error to point at.
// ---------------------------------------------------------------------------
function capturingResponse() {
  log.debug("Entering capturingResponse().");
  const captured = { status: 0, headers: {}, body: '' };
  const res = {
    set: function (name, value) { captured.headers[name] = value; return res; },
    setHeader: function (name, value) { captured.headers[name] = value; return res; },
    status: function (code) { captured.status = code; return res; },
    type: function () { return res; },
    send: function (body) { captured.body = String(body === undefined ? '' : body); return res; },
    json: function (body) { captured.body = JSON.stringify(body); return res; },
    end: function (body) { captured.body = String(body === undefined ? '' : body); return res; }
  };
  log.debug("Leaving capturingResponse().");
  return { res: res, captured: captured };
}

function capturedDescription(captured) {
  try {
    const parsed = JSON.parse(captured.body || '{}');
    return String(parsed.error_description || parsed.error || '').trim();
  } catch (e) {
    // Not JSON. presentedAccessToken() always writes JSON today, and a change
    // there must not turn a 401 into an exception here — the raw text is a
    // better answer than nothing.
    return String(captured.body || '').trim();
  }
}

function attemptBearer(req, ctx) {
  log.debug("Entering attemptBearer().");
  const scheme = authorizationScheme(req);
  if (scheme !== 'bearer' && scheme !== 'dpop') {
    log.debug("Leaving attemptBearer(). This request carries no OAuth credential.");
    return null;
  }

  const shim = capturingResponse();
  const presented = dpop.presentedAccessToken(req, shim.res, 'the SCIM endpoints');
  if (!presented) {
    log.debug("Leaving attemptBearer(). The shared access token check refused it.");
    return refusal(shim.captured.status || 401,
      capturedDescription(shim.captured) ||
      'This access token could not be accepted.', shim.captured.headers);
  }

  // The row it counts as. One credential, two ways of holding it: the DPoP row
  // exists so that a client reading the ServiceProviderConfig can see the bound
  // form is understood, and this is where the two rejoin.
  const row = presented.scheme === 'dpop' ? 'dpop' : 'bearer';
  const claims = presented.claims || {};

  // The same four checks /oauth2/userinfo makes, and for the same reason it
  // makes them rather than accepting a foreign token the way the OID4VCI
  // credential endpoints do: this is not a resource somebody else's
  // authorization server can speak for. A scope is a permission, and a
  // permission read off a token nobody verified is a permission its holder
  // wrote for themselves.
  if (!presented.verified) {
    log.debug("Leaving attemptBearer(). The token is not one this service signed.");
    return refusal(401,
      'This access token was not issued by this service, or its signature does not verify ' +
      'against the key at /oauth2/jwks. Unlike the OID4VCI credential endpoints, which accept ' +
      'a token from a separate authorization server, these endpoints cannot: the scope on a ' +
      'token nobody verified is a permission its holder wrote for themselves. Get a token from ' +
      'this service\'s token endpoint with any grant.',
      { 'WWW-Authenticate': challenges(req) });
  }
  if (claims.typ !== 'Bearer') {
    log.debug("Leaving attemptBearer(). That is a " + claims.typ + " token.");
    return refusal(401,
      'This is a "' + (claims.typ || 'unknown') + '" token, not an access token. Every token ' +
      'this service issues is signed with the same key, so the typ claim is the only thing that ' +
      'tells a refresh token or an ID Token apart from the access token these endpoints need.',
      { 'WWW-Authenticate': challenges(req) });
  }
  if (stats.isRevoked(claims.jti)) {
    log.debug("Leaving attemptBearer(). The token was revoked.");
    return refusal(401,
      'This access token was revoked — at /oauth2/revoke, from the admin console, or by being ' +
      'rotated. Introspection reports it inactive and these endpoints answer the same way; a ' +
      'revocation only some endpoints honoured would be worse than none.',
      { 'WWW-Authenticate': challenges(req) });
  }

  // WHOSE token it is. A client_credentials token has no user behind it, which
  // is not a problem for provisioning — it is the ordinary shape for it — so
  // the client_id is the principal and `isClient` says why the name looks like
  // an application. `username` is what every user-bearing grant here carries
  // alongside `sub`, and it is the form the audit log and /admin/users file
  // people under.
  const isClient = !claims.username && !claims.sub;
  const principal = String(claims.username || claims.sub || claims.client_id || '').trim();

  log.debug("Leaving attemptBearer(). " + row + " for " + (principal || '(unnamed)') + ".");
  return {
    ok: true,
    scheme: row,
    principal: principal,
    isClient: isClient,
    scopes: String(claims.scope || ''),
    clientId: String(claims.client_id || ''),
    sub: String(claims.sub || ''),
    jti: String(claims.jti || ''),
    note: 'access token' + (row === 'dpop' ? ', DPoP-bound' : '') +
          (presented.jkt ? ' (jkt ' + presented.jkt.slice(0, 12) + '...)' : '')
  };
}

// ---------------------------------------------------------------------------
// HTTP BASIC (RFC 7617).
//
// Any username, any password but one. That is the LDAP bind rule stated again,
// and the exception is the same reserved value: `invalid` is refused so that a
// 401 is reachable on a scheme which otherwise cannot produce one. Note what is
// NOT checked — the password — which is why what this authenticates is a name
// and why the row says so in the ServiceProviderConfig rather than leaving a
// reader to assume a check happened.
// ---------------------------------------------------------------------------
function attemptBasic(req, ctx) {
  log.debug("Entering attemptBasic().");
  if (authorizationScheme(req) !== 'basic') {
    log.debug("Leaving attemptBasic(). Not a Basic credential.");
    return null;
  }
  const header = String(req.headers['authorization'] || '');
  const encoded = header.replace(/^\s*Basic\s+/i, '').trim();
  let decoded = '';
  try {
    decoded = Buffer.from(encoded, 'base64').toString('utf8');
  } catch (e) {
    // Not base64. Reported as a refusal rather than as a missing credential,
    // because the client did present one and the difference is what it has to
    // fix.
    log.debug("Leaving attemptBasic(). The credential is not base64.");
    return unauthenticated(req,
      'The Basic credential is not base64 (RFC 7617 section 2): ' + e.message);
  }
  const cut = decoded.indexOf(':');
  if (cut < 0) {
    log.debug("Leaving attemptBasic(). There is no colon in it.");
    return unauthenticated(req,
      'A Basic credential is base64(user-id ":" password) — RFC 7617 section 2. What arrived ' +
      'carries no colon, so there is no way to tell where the username ends.');
  }
  const username = decoded.slice(0, cut).trim();
  const password = decoded.slice(cut + 1);
  if (!username) {
    log.debug("Leaving attemptBasic(). The username is empty.");
    return unauthenticated(req,
      'The Basic credential names nobody. This service checks no password, so the username is ' +
      'the whole of what it authenticates and an empty one authenticates nothing.');
  }
  if (password === REFUSED_PASSWORD) {
    log.debug("Leaving attemptBasic(). The reserved password was used.");
    return unauthenticated(req,
      'The password "' + REFUSED_PASSWORD + '" is refused on purpose — the same reserved value ' +
      'the OAuth password grant, WS-Trust, the WS-Federation sign-in screen and every LDAP bind ' +
      'here refuse. Every other password is accepted, including no password at all, because ' +
      'nothing in this service checks one. Nothing else about this request was wrong.');
  }
  log.debug("Leaving attemptBasic(). " + username + " is accepted.");
  return {
    ok: true, scheme: 'basic', principal: username, isClient: false,
    scopes: '', note: 'HTTP Basic (no password was checked)'
  };
}

// ---------------------------------------------------------------------------
// HTTP DIGEST (RFC 7616), WHICH IS THE ONE SCHEME HERE THAT CHECKS A PASSWORD —
// AND CANNOT NOT.
//
// This is the Kerberos argument, made again for the same reason. The digest
// response is a hash OVER the password, so a server that accepted any response
// would not be performing the exchange at all: nothing would be exercised at
// the client end either, since a client's digest code is exactly the part that
// computes that hash. So this does what the KDC does — ANY username
// authenticates, and every one of them shares one password
// (`scim.digestPassword`, `password!` by default, which is the same value
// KRB5_USER_PASSWORD defaults to so that a tester has one fact to remember).
//
// That makes three negatives reachable that no other scheme here can produce: a
// wrong password (401), an expired nonce (401 with `stale=true`, which a
// conforming client retries silently and a hand-written one usually does not),
// and a REPLAYED nonce count (401, no stale — the credential was valid and has
// been seen before, which is a different sentence and deserves a different
// answer).
//
// The algorithms are offered strongest first because RFC 7616 section 3.7 says
// so and because a client takes the first it understands. MD5 is last and is
// offered at all because most of the installed base of Digest clients speaks
// nothing else; it is not a recommendation, and the page says so.
// ---------------------------------------------------------------------------
const DIGEST_ALGORITHMS = [
  { token: 'SHA-256', hash: 'sha256' },
  { token: 'SHA-512-256', hash: 'sha512-256' },
  { token: 'MD5', hash: 'md5' }
].filter(function (row) {
  // Checked against the openssl this process actually has rather than assumed.
  // `sha512-256` is missing from some builds and `md5` from a FIPS one, and a
  // challenge naming an algorithm this process cannot compute would be an
  // instruction a client follows into a 500.
  const available = crypto.getHashes().indexOf(row.hash) >= 0;
  if (!available) {
    log.warn('scim: this node build cannot compute ' + row.hash + ', so HTTP Digest will ' +
             'not offer ' + row.token + '. The remaining algorithms are unaffected.');
  }
  return available;
});

// The nonces this server has issued. In memory and dying with the process like
// every other store here; bounded, because the value comes off a challenge
// anybody can ask for by making an unauthenticated request.
const digestNonces = new Map();
const MAX_DIGEST_NONCES = 2000;

function issueDigestNonce() {
  log.debug("Entering issueDigestNonce().");
  const now = Date.now();
  const ttl = digestNonceSeconds() * 1000;
  digestNonces.forEach(function (record, key) {
    if (now - record.at > ttl) {
      digestNonces.delete(key);
    }
  });
  while (digestNonces.size >= MAX_DIGEST_NONCES) {
    // The oldest first. A Map iterates in insertion order, so the first key is
    // the least recently issued.
    digestNonces.delete(digestNonces.keys().next().value);
  }
  const nonce = crypto.randomBytes(18).toString('base64');
  digestNonces.set(nonce, { at: now, counts: new Set() });
  log.debug("Leaving issueDigestNonce(). " + digestNonces.size + " nonce(s) outstanding.");
  return nonce;
}

// The auth-params of a credential, for the two schemes here that have any:
// Digest and HOBA. RFC 7235 section 2.1 gives them one grammar, so this reads
// both — RFC 7616 section 3.4 allows each value to be a quoted string or a bare
// token, and which of the two a given parameter uses differs between
// implementations (`algorithm` and `nc` are conventionally bare and `qop` is
// sent both ways), so both forms are read for every parameter rather than per
// parameter. Getting that wrong reads `qop` as `"auth"` with the quotes
// included, which then matches nothing.
function authParams(header) {
  log.debug("Entering authParams().");
  const out = {};
  const text = String(header || '').replace(/^\s*[A-Za-z][A-Za-z0-9_-]*\s+/, '');
  const pattern = /([a-zA-Z0-9_-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))/g;
  let match = pattern.exec(text);
  while (match) {
    out[match[1].toLowerCase()] = match[2] !== undefined
      ? match[2].replace(/\\(.)/g, '$1')
      : match[3];
    match = pattern.exec(text);
  }
  log.debug("Leaving authParams(). " + Object.keys(out).length + " parameter(s).");
  return out;
}

function digestHash(algorithmToken, text) {
  const base = String(algorithmToken || 'MD5').replace(/-sess$/i, '').toUpperCase();
  const row = DIGEST_ALGORITHMS.filter(function (candidate) {
    return candidate.token === base;
  })[0];
  if (!row) {
    return null;
  }
  return crypto.createHash(row.hash).update(text, 'utf8').digest('hex');
}

function attemptDigest(req, ctx) {
  log.debug("Entering attemptDigest().");
  if (authorizationScheme(req) !== 'digest') {
    log.debug("Leaving attemptDigest(). Not a Digest credential.");
    return null;
  }
  const params = authParams(req.headers['authorization']);
  const algorithm = String(params.algorithm || 'MD5');
  const session = /-sess$/i.test(algorithm);

  // Refused rather than ignored. RFC 7616 section 3.4.4 makes `userhash` the
  // client saying "the username above is H(user:realm)", and a server that read
  // it as a plain username would authenticate somebody called
  // `3d78...` — a name nobody has, silently. This service never sends
  // `userhash=true` in a challenge, which is how it declares it cannot do this;
  // a client that sends it anyway is told so.
  if (String(params.userhash || '').toLowerCase() === 'true') {
    log.debug("Leaving attemptDigest(). userhash was asked for.");
    return unauthenticated(req,
      'This credential sets userhash=true (RFC 7616 section 3.4.4), and this server does not ' +
      'support it — which is why its challenges never carry userhash=true. It would have to ' +
      'find the user by the hash of their name, and a directory that creates every name it is ' +
      'shown has nothing to search. Send the username in the clear.');
  }
  if (digestHash(algorithm, '') === null) {
    log.debug("Leaving attemptDigest(). Unknown algorithm " + algorithm + ".");
    return unauthenticated(req,
      'This credential names algorithm=' + algorithm + ' and this server offers ' +
      DIGEST_ALGORITHMS.map(function (row) { return row.token; }).join(', ') +
      ' (each also with the -sess variant). The challenge lists what it will accept.');
  }
  const qop = String(params.qop || '').toLowerCase();
  if (qop && qop !== 'auth') {
    // auth-int is the other RFC 7616 quality of protection and is deliberately
    // not offered: it hashes the entity body, and the body this service sees has
    // been through the express text parser and re-encoded, so an integrity check
    // computed here could disagree with what was actually sent for reasons that
    // have nothing to do with the credential. A check that is wrong occasionally
    // and silently is worse than one that is absent and says so.
    log.debug("Leaving attemptDigest(). qop=" + qop + " is not offered.");
    return unauthenticated(req,
      'This credential asks for qop=' + qop + ' and this server offers qop="auth" only. ' +
      'auth-int hashes the entity body, and the body this service sees has already been ' +
      'decoded and re-encoded by its own parser — an integrity check computed over that could ' +
      'disagree with what was sent, which is a worse answer than not offering it.');
  }
  const username = String(params.username || '').trim();
  if (!username || !params.nonce || !params.response) {
    log.debug("Leaving attemptDigest(). It is missing a required parameter.");
    return unauthenticated(req,
      'A Digest credential needs at least username, realm, nonce, uri and response (RFC 7616 ' +
      'section 3.4), and with qop=auth it needs cnonce and nc as well. What arrived is missing ' +
      'one of them.');
  }

  const record = digestNonces.get(String(params.nonce));
  if (!record) {
    log.debug("Leaving attemptDigest(). The nonce is not one this server issued.");
    return unauthenticated(req,
      'This nonce is not one this server issued, or it has already been forgotten. A fresh ' +
      'challenge is on this response with stale=true, which RFC 7616 section 3.3 says a client ' +
      'should retry with the same credentials rather than asking a person again.',
      { stale: true });
  }
  if (Date.now() - record.at > digestNonceSeconds() * 1000) {
    digestNonces.delete(String(params.nonce));
    log.debug("Leaving attemptDigest(). The nonce is stale.");
    return unauthenticated(req,
      'This nonce is older than ' + digestNonceSeconds() + ' seconds (scim.digestNonceSeconds). ' +
      'The challenge on this response carries stale=true, so retry it with the same credentials.',
      { stale: true });
  }

  // qop=auth requires a nonce count, and the count is what makes a Digest
  // credential single-use. A repeat is refused WITHOUT stale=true, deliberately:
  // stale means "your credential was fine, ask me again", and a replay is the
  // opposite claim.
  if (qop === 'auth') {
    const nc = String(params.nc || '');
    const cnonce = String(params.cnonce || '');
    if (!nc || !cnonce) {
      log.debug("Leaving attemptDigest(). qop=auth with no nc or cnonce.");
      return unauthenticated(req,
        'With qop=auth a credential must carry both cnonce and nc (RFC 7616 section 3.4). ' +
        'Without the nonce count there is nothing to stop the same credential being replayed, ' +
        'which is most of what the nonce is for.');
    }
    if (record.counts.has(nc)) {
      log.debug("Leaving attemptDigest(). nc=" + nc + " has been used already.");
      return unauthenticated(req,
        'This nonce count (nc=' + nc + ') has been used with this nonce already. That is a ' +
        'replay, and it is refused WITHOUT stale=true — stale would mean the credential was ' +
        'fine and should be retried, and this one has been seen before. Increment nc.');
    }
  }

  // RFC 7616 section 3.4.6: A2 is method ":" uri, where uri is the
  // request-target the CLIENT put in the credential. It is compared with what
  // actually arrived, because a credential computed over a different URI is one
  // that was minted for a different request — which is exactly what a replay
  // across endpoints looks like.
  const uri = String(params.uri || '');
  const target = String(req.originalUrl || req.url || '');
  if (uri && uri !== target) {
    log.debug("Leaving attemptDigest(). The uri does not match the request.");
    return unauthenticated(req,
      'The uri in this credential is "' + uri + '" and this request was for "' + target +
      '". RFC 7616 section 3.4.6 hashes the request-target into the response, so the two have ' +
      'to be the same string — a credential computed over a different URI was minted for a ' +
      'different request.');
  }

  const password = digestPassword();
  let ha1 = digestHash(algorithm, username + ':' + realm() + ':' + password);
  if (session) {
    // RFC 7616 section 3.4.2: the -sess variants fold the nonces into A1, so
    // that the long-term secret is hashed once per session rather than once per
    // request.
    ha1 = digestHash(algorithm, ha1 + ':' + params.nonce + ':' + (params.cnonce || ''));
  }
  const ha2 = digestHash(algorithm, String(req.method || 'GET').toUpperCase() + ':' + uri);
  const expected = qop === 'auth'
    ? digestHash(algorithm, ha1 + ':' + params.nonce + ':' + params.nc + ':' +
                            params.cnonce + ':auth:' + ha2)
    : digestHash(algorithm, ha1 + ':' + params.nonce + ':' + ha2);

  const given = String(params.response || '').toLowerCase();
  const same = given.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(given, 'utf8'), Buffer.from(expected, 'utf8'));
  if (!same) {
    log.debug("Leaving attemptDigest(). The response hash does not match.");
    return unauthenticated(req,
      'The digest response does not match. This is the one scheme here where the password is ' +
      'really checked — it has to be, since the response IS a hash over it — so every user ' +
      'shares one password, which is "' + (password ? password : '(empty)') + '" unless ' +
      'scim.digestPassword has been changed. Any username works with it.');
  }
  if (qop === 'auth') {
    record.counts.add(String(params.nc));
  }

  // RFC 7616 section 3.5, the Authentication-Info response header. It is what
  // lets a client authenticate the SERVER, and leaving it out is the commonest
  // way to implement Digest and give a client nothing to verify.
  const rspauth = qop === 'auth'
    ? digestHash(algorithm, ha1 + ':' + params.nonce + ':' + params.nc + ':' +
                            params.cnonce + ':auth:' + digestHash(algorithm, ':' + uri))
    : '';

  log.debug("Leaving attemptDigest(). " + username + " is accepted.");
  return {
    ok: true, scheme: 'digest', principal: username, isClient: false, scopes: '',
    headers: rspauth
      ? { 'Authentication-Info': 'qop=auth, rspauth="' + rspauth + '", cnonce="' +
                                 params.cnonce + '", nc=' + params.nc }
      : {},
    note: 'HTTP Digest (' + algorithm + '), and the password really was checked'
  };
}

// ---------------------------------------------------------------------------
// HOBA — HTTP ORIGIN-BOUND AUTHENTICATION (RFC 7486).
//
// The third scheme RFC 7644 section 2 names, and the only one of the six with
// no password anywhere in it: the client holds a key pair, registers the public
// half once, and thereafter signs a challenge this server issued together with
// the origin, the realm, its key id and a nonce of its own. Nothing shared, so
// nothing to leak.
//
// **THE SIGNATURE IS REALLY VERIFIED**, which is the same decision the Digest
// password really being checked is, and for the same reason: a signature check
// that passes anything is not the scheme, and the part of a client this
// exercises IS the signing. What is permissive is the REGISTRATION — anybody
// may register a key for any name, exactly as any name authenticates
// everywhere else here. The turnstile, not the lock.
//
// Two details of RFC 7486 are easy to get wrong and both are written out below:
// the TBS blob is length-prefixed with a COLON and the fields are concatenated
// with nothing between them (so `3:abc` and not `3:abc.`), and the origin
// carries an explicit PORT even when it is the scheme's default, because the
// specification says there is no default. Get either wrong and every signature
// fails with nothing to look at — both ends are computing over different bytes.
//
// The registered algorithms are 0 (RSA-SHA256) and 1 (RSA-SHA1). Only 0 is
// accepted, and that is a refusal with a reason rather than a gap: SHA-1
// signatures are the thing nobody should be building a client around in 2026,
// and this service publishes what it will not do rather than letting it be
// discovered.
// ---------------------------------------------------------------------------
const HOBA_ALG_RSA_SHA256 = '0';

// The challenges this server has issued, and the (kid, challenge, nonce)
// triples it has already seen. Both bounded and both in memory: a challenge is
// something anybody can ask for by making an unauthenticated request.
const hobaChallenges = new Map();
const hobaSeen = new Set();
const MAX_HOBA_CHALLENGES = 2000;
const MAX_HOBA_SEEN = 5000;

function issueHobaChallenge() {
  log.debug("Entering issueHobaChallenge().");
  const now = Date.now();
  const ttl = hobaMaxAgeSeconds() * 1000;
  hobaChallenges.forEach(function (at, key) {
    if (now - at > ttl) {
      hobaChallenges.delete(key);
    }
  });
  while (hobaChallenges.size >= MAX_HOBA_CHALLENGES) {
    hobaChallenges.delete(hobaChallenges.keys().next().value);
  }
  const challenge = crypto.randomBytes(16).toString('base64url');
  hobaChallenges.set(challenge, now);
  log.debug("Leaving issueHobaChallenge(). " + hobaChallenges.size + " outstanding.");
  return challenge;
}

// The web origin, RFC 7486 section 4: scheme, authority and port, with the port
// ALWAYS present because that specification gives it no default. Built from
// baseUrlOf() so that it agrees with every other URL this service publishes —
// including behind a proxy, where `global.trustProxy` decides whether the
// forwarded headers are believed. A client computing the origin from the URL it
// dialled and a server computing it from the socket are the commonest reason a
// HOBA signature does not verify, so this is one decision and not two.
function hobaOrigin(req) {
  log.debug("Entering hobaOrigin().");
  const base = String(baseUrlOf(req) || '');
  const match = /^([a-z]+):\/\/([^/:]+)(?::(\d+))?/i.exec(base);
  if (!match) {
    log.debug("Leaving hobaOrigin(). The base URL could not be read.");
    return base;
  }
  const port = match[3] || (match[1].toLowerCase() === 'https' ? '443' : '80');
  log.debug("Leaving hobaOrigin(). " + match[1] + "://" + match[2] + ":" + port);
  return match[1].toLowerCase() + '://' + match[2] + ':' + port;
}

// RFC 7486 section 5's to-be-signed blob. Each field is preceded by the number
// of octets in it and a colon, and the six are concatenated with nothing
// between them. The realm may be empty and is still present as `0:`, which is
// the case a hand-written client most often drops.
function hobaTbs(fields) {
  return fields.map(function (value) {
    const text = String(value === undefined || value === null ? '' : value);
    return Buffer.byteLength(text, 'utf8') + ':' + text;
  }).join('');
}

// ---------------------------------------------------------------------------
// WHERE A REGISTERED KEY LIVES, WHICH IS THE DIRECTORY AND NOT A MAP.
//
// The same decision applications.js and the SPIFFE registry made: the store is
// `ou=users`, so a registered key is visible in an `ldapsearch`, on
// /admin/users and in the entry every other family here already writes to. A
// Map beside the directory would have been fifteen lines shorter and would have
// been the one credential in this service that nothing else could see.
//
// The value is `<kid> <base64 DER>` in a multi-valued `hobaPublicKey` — this
// service's own attribute name, like `scimActive` and the `x509*` ones, because
// nothing standard carries a HOBA client public key.
//
// **THE MERGE DROPS THE THREE OPERATIONAL ATTRIBUTES**, for the reason
// scim_map.js's NOT_STORED does: writePerson() REPLACES the attribute set, and
// `entryDN` is synthesised on every read rather than stored — carrying it
// through would write a stored copy of the DN, which is a second definition of
// one fact and the one that goes stale on a rename.
// ---------------------------------------------------------------------------
const HOBA_ATTRIBUTE = 'hobaPublicKey';
const NOT_STORED = ['entrydn', 'createtimestamp', 'modifytimestamp'];

function mergeableAttributes(entry) {
  const out = {};
  Object.keys((entry && entry.attributes) || {}).forEach(function (name) {
    if (NOT_STORED.indexOf(String(name).toLowerCase()) >= 0) {
      return;
    }
    const value = entry.attributes[name];
    out[name] = Array.isArray(value) ? value.slice(0) : [String(value)];
  });
  return out;
}

// The username an entry answers to. `uid` first and the naming value second,
// which is the pair existingUserEntry() matches on — an entry named by a
// certificate's `cn` has no `uid` until somebody signs in with that name.
function usernameOfEntry(entry) {
  const attributes = (entry && entry.attributes) || {};
  const uid = Object.keys(attributes).filter(function (name) {
    return name.toLowerCase() === 'uid';
  })[0];
  if (uid && attributes[uid] && attributes[uid].length) {
    return String(attributes[uid][0]);
  }
  const rdn = String((entry && entry.dn) || '').split(',')[0];
  return rdn.indexOf('=') >= 0 ? rdn.slice(rdn.indexOf('=') + 1) : rdn;
}

function hobaKeysOf(entry) {
  const attributes = (entry && entry.attributes) || {};
  const name = Object.keys(attributes).filter(function (key) {
    return key.toLowerCase() === HOBA_ATTRIBUTE.toLowerCase();
  })[0];
  return name ? (attributes[name] || []).map(String) : [];
}

// Find the entry that registered this key id. A scan, because a key id is
// chosen by the client and there is nothing to index it by — the directory is
// schemaless and this service does not maintain indexes on invented attributes.
// Bounded by ldap.maxEntries like every other sweep here.
function entryForHobaKid(kid) {
  log.debug("Entering entryForHobaKid(). kid=" + kid);
  const wanted = String(kid) + ' ';
  let found = null;
  directory.allPersons().forEach(function (entry) {
    if (found) {
      return;
    }
    const hit = hobaKeysOf(entry).filter(function (value) {
      return value.indexOf(wanted) === 0;
    })[0];
    if (hit) {
      found = { entry: entry, der: hit.slice(wanted.length) };
    }
  });
  log.debug("Leaving entryForHobaKid(). " + (found ? 'Found ' + found.entry.dn : 'No such key.'));
  return found;
}

function attemptHoba(req, ctx) {
  log.debug("Entering attemptHoba().");
  if (authorizationScheme(req) !== 'hoba') {
    log.debug("Leaving attemptHoba(). Not a HOBA credential.");
    return null;
  }
  const params = authParams(req.headers['authorization']);
  const parts = String(params.result || '').split('.');
  if (parts.length !== 4) {
    log.debug("Leaving attemptHoba(). The result is not four fields.");
    return unauthenticated(req,
      'A HOBA credential is result="kid.challenge.nonce.sig", four base64url fields separated ' +
      'by full stops (RFC 7486 section 6). What arrived has ' + parts.length + '.');
  }
  const kid = parts[0];
  const challenge = parts[1];
  const nonce = parts[2];
  let signature = null;
  try {
    signature = Buffer.from(parts[3], 'base64url');
  } catch (e) {
    // Not base64url. Named as such rather than reported as a bad signature,
    // which would send somebody looking at their key.
    log.debug("Leaving attemptHoba(). The signature is not base64url.");
    return unauthenticated(req, 'The signature field is not base64url: ' + e.message);
  }

  const issuedAt = hobaChallenges.get(challenge);
  if (issuedAt === undefined) {
    log.debug("Leaving attemptHoba(). The challenge is not one this server issued.");
    return unauthenticated(req,
      'This challenge is not one this server issued, or it has been forgotten. A fresh one is ' +
      'in the WWW-Authenticate header on this response; RFC 7486 section 5 lets a client reuse ' +
      'a challenge until its max-age runs out, which here is ' + hobaMaxAgeSeconds() + ' seconds.');
  }
  if (Date.now() - issuedAt > hobaMaxAgeSeconds() * 1000) {
    hobaChallenges.delete(challenge);
    log.debug("Leaving attemptHoba(). The challenge has expired.");
    return unauthenticated(req,
      'This challenge is older than its max-age of ' + hobaMaxAgeSeconds() +
      ' seconds (scim.hobaMaxAgeSeconds). A fresh one is on this response.');
  }

  // The replay check, and it is on the CLIENT's nonce rather than on the
  // challenge: the specification means a challenge to be reused until it
  // expires, so refusing a repeated challenge would refuse conforming clients.
  // A repeated (kid, challenge, nonce) is a copied credential, which is a
  // different thing and is what a nonce is for.
  const triple = kid + '.' + challenge + '.' + nonce;
  if (hobaSeen.has(triple)) {
    log.debug("Leaving attemptHoba(). That signature has been seen before.");
    return unauthenticated(req,
      'This exact credential has been presented before (same key id, challenge and nonce). ' +
      'The challenge may be reused until its max-age runs out, but the nonce is what makes ' +
      'each signature single-use — generate a fresh one per request.');
  }

  const registered = entryForHobaKid(kid);
  if (!registered) {
    log.debug("Leaving attemptHoba(). No key is registered under that kid.");
    return unauthenticated(req,
      'No public key is registered here under the key id "' + kid + '". Register one with a ' +
      'form-encoded POST to /.well-known/hoba/register carrying pub=<PEM public key> and ' +
      'username=<who it is for> (RFC 7486 section 7). Anybody may register any key for any ' +
      'name, exactly as any name authenticates everywhere else in this service.');
  }

  let key = null;
  try {
    key = crypto.createPublicKey({
      key: Buffer.from(registered.der, 'base64'), format: 'der', type: 'spki'
    });
  } catch (e) {
    // The stored key cannot be read. That is this service's fault rather than
    // the caller's, and saying so is what stops somebody debugging their client
    // over a broken registration.
    log.error('scim: the HOBA key stored on ' + registered.entry.dn + ' under kid ' + kid +
              ' could not be read back: ' + e.message);
    log.debug("Leaving attemptHoba(). The stored key is unreadable.");
    return unauthenticated(req,
      'The key registered under that id cannot be read back by this server (' + e.message +
      '). Register it again.');
  }

  const tbs = hobaTbs([nonce, HOBA_ALG_RSA_SHA256, hobaOrigin(req), realm(), kid, challenge]);
  let verified = false;
  try {
    verified = crypto.verify('sha256', Buffer.from(tbs, 'utf8'), key, signature);
  } catch (e) {
    // A malformed signature makes verify() throw rather than return false.
    // Treated as a refusal, because from the caller's side the two are one
    // answer: this did not verify.
    log.debug("Leaving attemptHoba(). The signature could not be checked: " + e.message);
    verified = false;
  }
  if (!verified) {
    log.debug("Leaving attemptHoba(). The signature does not verify.");
    return unauthenticated(req,
      'This HOBA signature does not verify against the key registered under "' + kid + '". ' +
      'The to-be-signed blob is RFC 7486 section 5\'s: each field prefixed with its length in ' +
      'octets and a colon, concatenated with nothing between them, in the order nonce, ' +
      'algorithm, origin, realm, kid, challenge. This server computed it over origin "' +
      hobaOrigin(req) + '" and realm "' + realm() + '" — note that the origin carries an ' +
      'explicit port even when it is the default, because RFC 7486 gives it none.');
  }

  while (hobaSeen.size >= MAX_HOBA_SEEN) {
    hobaSeen.delete(hobaSeen.values().next().value);
  }
  hobaSeen.add(triple);

  const username = usernameOfEntry(registered.entry);
  log.debug("Leaving attemptHoba(). " + username + " is accepted.");
  return {
    ok: true, scheme: 'hoba', principal: username, isClient: false, scopes: '',
    note: 'HOBA, RSA-SHA256 over the RFC 7486 blob (kid ' + kid + ')'
  };
}

// ---------------------------------------------------------------------------
// THE SESSION COOKIE.
//
// RFC 7644 section 2's "Cookies": a client may assert an HTTP cookie carrying
// an authentication state the service provider understands. This service has
// exactly one such state — the browser sign-on session /authn/login creates and
// WS-Federation shares — so this is that session, read through the same
// `sessionOf()` every other reader uses. It is what makes a fetch() from a page
// on this service work with no second credential.
//
// It is tried only when there is no Authorization header, which is not an
// optimisation: a request that carries a credential is asking to be judged on
// that credential, and quietly falling back to a cookie when it fails would
// mean a client testing its bearer token error path getting a 200.
// ---------------------------------------------------------------------------
function attemptCookie(req, ctx) {
  log.debug("Entering attemptCookie().");
  if (authorizationScheme(req)) {
    log.debug("Leaving attemptCookie(). This request carries an Authorization header.");
    return null;
  }
  const session = authn.sessionOf(req);
  if (!session) {
    log.debug("Leaving attemptCookie(). There is no session.");
    return null;
  }
  const username = String((session.user && session.user.username) || '').trim();
  if (!username) {
    log.debug("Leaving attemptCookie(). The session names nobody.");
    return null;
  }
  log.debug("Leaving attemptCookie(). The session belongs to " + username + ".");
  return {
    ok: true, scheme: 'cookie', principal: username, isClient: false, scopes: '',
    sessionId: String(session.id || ''),
    note: 'the browser sign-on session (' + (session.acr || 'no acr') + ')'
  };
}

// ---------------------------------------------------------------------------
// THE TLS CLIENT CERTIFICATE.
//
// The first scheme RFC 7644 section 2 names. Available only where this request
// arrived over TLS and the certificate VERIFIED — which on the main port means
// `global.https` is on and somebody has POSTed an anchor to /tls/trust, and on
// 8443/9443 is what those listeners are for.
//
// **VERIFIED IS THE WHOLE OF WHAT IS CHECKED, and that is the same sentence
// /tls says.** No revocation is consulted and no directory entry has to exist.
// What is different HERE is that it now leads somewhere: on the TLS listeners a
// verified certificate is reported and grants nothing, and at these endpoints
// it authenticates a caller who may then write to the directory. That is the
// first place in this service where a certificate is a credential rather than
// an observation, which is worth knowing before turning `scim.authClientCert`
// on in a deployment that had assumed otherwise.
//
// The identity is the subject in RFC 4514 form — the same string tls_server.js
// records and the directory files a certificate under, through the same
// function, because two spellings of one DN is two people.
// ---------------------------------------------------------------------------
function attemptClientCertificate(req, ctx) {
  log.debug("Entering attemptClientCertificate().");
  if (authorizationScheme(req)) {
    log.debug("Leaving attemptClientCertificate(). This request carries an Authorization header.");
    return null;
  }
  const socket = req.socket || req.connection;
  if (!socket || typeof socket.getPeerCertificate !== 'function') {
    log.debug("Leaving attemptClientCertificate(). This is not a TLS connection.");
    return null;
  }
  if (socket.authorized !== true) {
    // A certificate that did not verify is not a refusal here: the request may
    // be perfectly good under another scheme, and the main port asks for a
    // certificate without requiring one. It is simply not this credential.
    log.debug("Leaving attemptClientCertificate(). No certificate verified on this connection.");
    return null;
  }
  const certificate = socket.getPeerCertificate();
  if (!certificate || !certificate.subject) {
    log.debug("Leaving attemptClientCertificate(). There is no peer certificate.");
    return null;
  }
  const subject = tlsServer.dnRfc4514(certificate.subject);
  if (!subject) {
    log.debug("Leaving attemptClientCertificate(). The subject is empty.");
    return null;
  }
  log.debug("Leaving attemptClientCertificate(). " + subject + " is accepted.");
  return {
    ok: true, scheme: 'clientcert', principal: subject, isClient: false, scopes: '',
    note: 'a client certificate that verified against an anchor from /tls/trust' +
          (certificate.fingerprint256 ? ' (' + certificate.fingerprint256 + ')' : '')
  };
}

// ---------------------------------------------------------------------------
// REGISTERING A HOBA PUBLIC KEY (RFC 7486 section 7).
//
// The specification puts this at /.well-known/hoba/register and makes it a
// form-encoded POST carrying `pub`, and it answers with `Hobareg: regok`. Two
// things about it are this service's own and are marked as such on GET /scim:
//
//   * WHO the key is for. In RFC 7486 the registration happens inside an
//     already-authenticated context — the person is signed in and is adding a
//     credential to the account they are signed in to. Here there is usually no
//     such context, so `username` is a parameter, with the browser session used
//     when there is one and no username given. Anybody may register any key for
//     any name, which is the same statement as "every LDAP bind succeeds".
//   * The key is stored ON THE PERSON'S DIRECTORY ENTRY, so it is visible in an
//     ldapsearch and on /admin/users like everything else about them. If the
//     name is new the entry is created through `createUser()` — the same door
//     the console's form, the management API and SCIM itself use — because
//     there must not be a fifth way to put somebody in ou=users.
//
// `registerHobaKey()` returns a value rather than answering: `scim.js` owns the
// response, here as everywhere else in this module.
// ---------------------------------------------------------------------------
function registerHobaKey(req) {
  log.debug("Entering registerHobaKey().");
  if (!schemeOn('scim.authHoba')) {
    log.debug("Leaving registerHobaKey(). HOBA is turned off.");
    return { ok: false, status: 501,
      detail: 'HOBA is turned off on this service (scim.authHoba). The route is registered, ' +
              'which is why this is a 501 and not a 404.' };
  }
  const body = parseBody(req) || {};
  const pem = String(body.pub || '').trim();
  if (!pem) {
    log.debug("Leaving registerHobaKey(). There was no key.");
    return { ok: false, status: 400,
      detail: 'A registration carries pub=<PEM public key> (RFC 7486 section 7), ' +
              'form-encoded. Nothing else in the body is required by this service.' };
  }
  let key = null;
  try {
    key = crypto.createPublicKey(pem);
  } catch (e) {
    // Not a key. The message from openssl is passed through, because it is
    // usually specific enough to fix the request in one go.
    log.debug("Leaving registerHobaKey(). The key could not be read.");
    return { ok: false, status: 400,
      detail: 'That public key could not be read: ' + e.message + '. It should be a PEM ' +
              'SubjectPublicKeyInfo block — the "-----BEGIN PUBLIC KEY-----" one, not a ' +
              'certificate and not a private key.' };
  }
  if (key.asymmetricKeyType !== 'rsa') {
    log.debug("Leaving registerHobaKey(). It is a " + key.asymmetricKeyType + " key.");
    return { ok: false, status: 400,
      detail: 'That is a ' + key.asymmetricKeyType + ' key, and RFC 7486 registers two ' +
              'signature algorithms — 0 (RSA-SHA256) and 1 (RSA-SHA1) — so there is no ' +
              'algorithm number for anything else. This service accepts 0 only: SHA-1 is not ' +
              'something to be building a client around, and publishing that refusal is ' +
              'better than leaving it to be discovered.' };
  }

  const der = key.export({ format: 'der', type: 'spki' });
  // The key id. RFC 7486 lets the client choose one and gives `kidtype` for
  // saying what it is; a hash of the key itself is the default here for the
  // reason the signing key's `kid` is derived from its material in helpers.js —
  // two keys cannot then claim one id.
  const kid = String(body.kid || '').trim() ||
    crypto.createHash('sha256').update(der).digest('base64url').slice(0, 22);
  if (/[.\s]/.test(kid)) {
    log.debug("Leaving registerHobaKey(). The kid carries a separator.");
    return { ok: false, status: 400,
      detail: 'A key id cannot contain a full stop or whitespace: the credential is ' +
              '"kid.challenge.nonce.sig" and a kid carrying a full stop could not be read ' +
              'back out of it.' };
  }

  const session = authn.sessionOf(req);
  const username = String(body.username ||
    (session && session.user && session.user.username) || '').trim();
  if (!username) {
    log.debug("Leaving registerHobaKey(). Nobody was named.");
    return { ok: false, status: 400,
      detail: 'This registration names nobody. RFC 7486 registers a key against an ' +
              'already-authenticated account; there is rarely one here, so send ' +
              'username=<who this key is for>, or register from a browser that has signed ' +
              'in at /authn/login.' };
  }

  let entry = directory.existingUserEntry(username);
  if (!entry) {
    const made = directory.createUser(username, {
      origin: 'hoba', channel: 'http', protocol: 'SCIM',
      note: 'created by a HOBA key registration'
    });
    if (!made.ok) {
      log.debug("Leaving registerHobaKey(). The entry could not be created.");
      return { ok: false, status: made.existing ? 409 : 400,
        detail: (made.errors || []).join(' ') };
    }
    entry = directory.readPerson(made.dn);
  }
  if (!entry) {
    log.debug("Leaving registerHobaKey(). The entry vanished between two reads.");
    return { ok: false, status: 500,
      detail: 'The directory entry for ' + username + ' could not be read back.' };
  }

  const attributes = mergeableAttributes(entry);
  const existingName = Object.keys(attributes).filter(function (name) {
    return name.toLowerCase() === HOBA_ATTRIBUTE.toLowerCase();
  })[0] || HOBA_ATTRIBUTE;
  const values = (attributes[existingName] || []).filter(function (value) {
    // A second registration under one key id REPLACES rather than accumulating.
    // The alternative is an entry that grows a value per registration and a
    // lookup that finds whichever came first, which is the trap
    // applyVcAttributes()'s second rule is about.
    return String(value).indexOf(kid + ' ') !== 0;
  });
  values.push(kid + ' ' + der.toString('base64'));
  attributes[existingName] = values;

  const written = directory.writePerson(entry.dn, attributes);
  if (!written.ok) {
    log.debug("Leaving registerHobaKey(). The write failed: " + written.reason);
    return { ok: false, status: written.reason === 'full' ? 507 : 400,
      detail: 'The key could not be written to ' + entry.dn + ' (' + written.reason + ').' };
  }

  log.info('scim: a HOBA public key was registered for ' + username + ' at ' + entry.dn +
           ' under kid ' + kid + '. Nothing was checked about who registered it — see ' +
           'GET /scim.');
  log.debug("Leaving registerHobaKey(). kid=" + kid);
  return {
    ok: true, status: 201,
    // RFC 7486 section 7's own signal that the registration completed. The body
    // is this service's: the specification defines none, and a client that has
    // just registered a key wants to be told the id it will have to send.
    headers: { 'Hobareg': 'regok' },
    body: {
      kid: kid, username: username, dn: entry.dn, algorithm: HOBA_ALG_RSA_SHA256,
      attribute: HOBA_ATTRIBUTE,
      note: 'Registered. Nothing about this registration was authenticated, and the key is ' +
            'on the directory entry — an ldapsearch and /admin/users show it. Authenticate ' +
            'with Authorization: HOBA result="kid.challenge.nonce.sig".'
    }
  };
}

// ---------------------------------------------------------------------------
// THE DECISION.
//
// `need` is 'read', 'write' or 'none' — the last being the discovery endpoints,
// which are open unless `scim.authDiscovery` says otherwise. That default is
// the bootstrapping argument /tls/trust already makes: the ServiceProviderConfig
// is where a client READS which schemes exist, so requiring a credential to
// fetch it means a client must already know the answer to the question it is
// asking. A deployment that wants everything shut can have that, and it is one
// setting away.
//
// The order of what follows is load-bearing:
//
//   1. A CREDENTIAL THAT WAS PRESENTED AND FAILED IS ALWAYS A REFUSAL, even
//      when authentication is not required. A client testing its expired-token
//      path must not get a 200 because the endpoint would also have accepted
//      nobody.
//   2. A credential that was presented and worked is used, even when
//      authentication is not required — so the audit log and /Me have somebody
//      to name.
//   3. Only then does "is authentication required" decide what happens to a
//      request carrying nothing.
// ---------------------------------------------------------------------------
function authenticate(req, need) {
  log.debug("Entering authenticate(). need=" + need);
  const wanted = String(need || 'none');
  let decision = null;
  const rows = enabledSchemes();
  for (let i = 0; i < rows.length && !decision; i++) {
    if (!rows[i].attempt) {
      continue;
    }
    decision = rows[i].attempt(req, { need: wanted });
  }

  if (decision && !decision.ok) {
    log.debug("Leaving authenticate(). A credential was presented and refused.");
    return decision;
  }

  if (!decision) {
    const scheme = authorizationScheme(req);
    const mustAuthenticate = authRequired() && (wanted !== 'none' || authDiscovery());
    if (!mustAuthenticate) {
      log.debug("Leaving authenticate(). Nothing was presented and nothing is required.");
      return { ok: true, scheme: 'anonymous', principal: '', anonymous: true,
               scopes: '', isClient: false,
               note: authRequired()
                 ? 'a discovery endpoint, which is open (scim.authDiscovery)'
                 : 'authentication is turned off (scim.authRequired)' };
    }
    if (scheme) {
      log.debug("Leaving authenticate(). The scheme " + scheme + " is not offered here.");
      return unauthenticated(req,
        'This request carries an "' + scheme + '" credential and this service offers ' +
        enabledSchemes().map(function (row) { return row.name; }).join(', ') +
        '. The WWW-Authenticate headers on this response say what to send.');
    }
    log.debug("Leaving authenticate(). Nothing was presented.");
    return unauthenticated(req,
      'These endpoints create, change and delete accounts, and they now require a credential. ' +
      'Any of the schemes in the WWW-Authenticate headers will do, and every one of them is ' +
      'permissive: an access token from this service\'s own token endpoint with the "' +
      scopeRead() + '" or "' + scopeWrite() + '" scope, any username with any password but ' +
      'one over Basic, any username over Digest with the shared password, or a HOBA key ' +
      'anybody may register. The ServiceProviderConfig at /scim/v2/ServiceProviderConfig ' +
      'lists them, and it is readable without a credential for that reason.');
  }

  // Accepted. The access control policy, which is two lines and is published in
  // both of them: an OAuth credential may do what its scopes say, and anything
  // else may do both. RFC 7644 section 2's MUST is that a provider be ABLE to
  // map an authenticated client to such a policy — not that the policy be
  // elaborate.
  const row = schemeById(decision.scheme);
  if (row && row.scoped && wanted !== 'none') {
    const required = wanted === 'write' ? scopeWrite() : scopeRead();
    if (!hasScope(decision.scopes, required)) {
      log.debug("Leaving authenticate(). The token lacks " + required + ".");
      const challenge = (decision.scheme === 'dpop' ? 'DPoP' : 'Bearer') +
        ' realm="' + realm() + '", error="insufficient_scope", error_description="' +
        'this operation needs the ' + required + ' scope", scope="' + required + '"';
      return {
        ok: false, status: 403, scimType: null,
        detail: 'This operation needs the "' + required + '" scope and the access token was ' +
                'issued with ' + (decision.scopes ? '"' + decision.scopes + '"' : 'no scope ' +
                'at all') + '. Ask for it at the authorization or token endpoint — this ' +
                'authorization server grants what it is asked, so any grant will do. Reads ' +
                'need "' + scopeRead() + '" and writes need "' + scopeWrite() + '"; one does ' +
                'not imply the other, deliberately, so that a client\'s handling of a ' +
                'read-only credential is something you can actually produce here.',
        headers: { 'WWW-Authenticate': [challenge] }
      };
    }
  }

  // The authentication funnel, for the schemes that present a credential per
  // request. See the header for why a bearer token, a session cookie and a
  // client certificate are NOT recorded here — each was already recorded where
  // it was accepted, and counting it again would report one act as many.
  if (row && row.recorded && decision.principal) {
    recordAuthentication(decision, row);
  }

  log.debug("Leaving authenticate(). " + decision.scheme + " for " +
            (decision.principal || '(nobody)') + ".");
  return decision;
}

// One accepted credential, at the single funnel every other family here passes.
// Wrapped, because nothing about recording an authentication may be able to
// fail one — the same guarantee the directory observer inside that function
// already gives.
function recordAuthentication(decision, row) {
  log.debug("Entering recordAuthentication() for SCIM.");
  try {
    stats.recordAuthentication({
      presented: decision.principal,
      protocol: 'SCIM',
      method: row.name,
      // RFC 8176. Stated only where something really was checked: Digest hashes
      // the password so `pwd` is honest, HOBA verifies a signature so `sig` is,
      // and Basic checked nothing at all — where nothing was stated, nothing is
      // written onto the entry, which is applyAuthenticationFactors()'s rule.
      amr: row.id === 'digest' ? ['pwd'] : (row.id === 'hoba' ? ['sig'] : []),
      note: decision.note || ''
    });
  } catch (e) {
    log.warn('scim: an accepted credential could not be recorded: ' + e.message);
  }
  log.debug("Leaving recordAuthentication() for SCIM.");
}

// ---------------------------------------------------------------------------
// THE ServiceProviderConfig'S `authenticationSchemes`, IN TWO HALVES — AND THE
// REASON IT IS TWO IS THAT THE TWO SPECIFICATIONS DISAGREE WITH EACH OTHER.
//
// RFC 7644 section 2 names six ways to authenticate. RFC 7643 section 5 gives
// `authenticationSchemes.type` five CANONICAL VALUES — oauth, oauth2,
// oauthbearertoken, httpbasic, httpdigest — and three of section 2's six have
// no value in that list at all: there is nothing to call a client certificate,
// a cookie or HOBA. That is not this service's problem to solve and it will not
// pretend it does not exist:
//
//   * The four rows with a canonical value go through SCIMMY.Config, which
//     ENFORCES that list (its ServiceProviderConfig definition carries the five
//     as canonicalValues and its coercion throws on anything else). So the
//     library validates them, which is what it is here for.
//   * The three without one are appended to the SERIALISED document by
//     `scim.js`, carrying an honest type of their own. RFC 7643 section 7 calls
//     canonical values "suggested" and a service provider may publish others; a
//     client matching on the canonical five finds the ones it knows, and one
//     reading the whole array finds a name, a description and a specUri for the
//     rest.
//
// Both halves are built from the SAME table by the two functions below, so the
// document cannot advertise a scheme that is turned off nor omit one that is
// on. Do not "simplify" this by dropping the three: a ServiceProviderConfig
// that listed four of the seven ways in would be the most misleading document
// this service publishes, and it is the first thing a SCIM client reads.
//
// `primary` is set on the bearer row and NOT passed through SCIMMY.Config:
// scimmy's definition of the sub-attributes does not include it (RFC 7643's
// example in section 8.5 carries it, its schema definition does not) and an
// unknown sub-attribute throws. It is added during serialisation with the rest.
// ---------------------------------------------------------------------------
function schemeDocument(row, base) {
  log.debug("Entering schemeDocument().");
  const out = {
    type: row.type,
    name: row.name,
    description: row.description,
    specUri: row.specUri
  };
  // ONLY WHEN THERE IS A BASE URL, and this is not tidiness. `documentationUri`
  // is a `reference` attribute with referenceTypes ["external"] in RFC 7643's
  // schema, so scimmy's coercion requires an absolute URL and THROWS on a path
  // — and this function is called at require time as well, when there is no
  // request to build a URL from and therefore no honest value to give it. A
  // throw there takes the whole service down over an optional member.
  if (base) {
    out.documentationUri = base + '/scim';
  }
  log.debug("Leaving schemeDocument().");
  return out;
}

function schemesForConfig(base) {
  log.debug("Entering schemesForConfig().");
  const out = enabledSchemes().filter(function (row) { return row.canonical; })
    .map(function (row) { return schemeDocument(row, base); });
  log.debug("Leaving schemesForConfig(). " + out.length + " canonical scheme(s).");
  return out;
}

function schemesBeyondTheCanonicalList(base) {
  log.debug("Entering schemesBeyondTheCanonicalList().");
  const out = enabledSchemes().filter(function (row) { return !row.canonical; })
    .map(function (row) { return schemeDocument(row, base); });
  log.debug("Leaving schemesBeyondTheCanonicalList(). " + out.length + " scheme(s).");
  return out;
}

// Which published scheme is `primary`, by id, so that serialisation can mark it
// without a second opinion about which one it is.
function primarySchemeId() {
  const row = enabledSchemes().filter(function (candidate) { return candidate.primary; })[0];
  return row ? row.id : '';
}

// ---------------------------------------------------------------------------
// WHAT THIS SURFACE IS, AS DATA.
//
// Read by GET /scim, by /admin/scim and by GET /admin-api/scim, all three
// through scim.js's description() — so the console page and the JSON cannot
// disagree with the challenge a client actually gets, because all of it is this
// one table.
// ---------------------------------------------------------------------------
function describe(req) {
  log.debug("Entering describe() for SCIM authentication.");
  const out = {
    required: authRequired(),
    discoveryOpen: !authDiscovery(),
    realm: realm(),
    scopes: { read: scopeRead(), write: scopeWrite() },
    hobaRegistration: '/.well-known/hoba/register',
    digestAlgorithms: DIGEST_ALGORITHMS.map(function (row) { return row.token; }),
    schemes: SCHEMES.map(function (row) {
      return {
        id: row.id,
        type: row.type,
        canonical: !!row.canonical,
        name: row.name,
        enabled: schemeOn(row.setting),
        setting: row.setting,
        primary: !!row.primary,
        scoped: !!row.scoped,
        recorded: !!row.recorded,
        challenged: !!row.challenge,
        spec: row.spec,
        specUri: row.specUri,
        description: row.description
      };
    }),
    policy: [
      'An OAuth credential — a Bearer or DPoP access token — may do what its scopes say: "' +
      scopeRead() + '" to read and "' + scopeWrite() + '" to write. Neither implies the ' +
      'other, so that a client\'s handling of a read-only credential is something this ' +
      'service can actually produce.',

      'EVERY OTHER SCHEME MAY DO BOTH. Basic, Digest, HOBA, a session cookie and a client ' +
      'certificate carry no scopes, so the policy for them is the whole surface. That is ' +
      'worth reading twice: a caller who cannot get a scope can use Basic instead, which is ' +
      'why each scheme has a switch of its own — a deployment exercising scope handling turns ' +
      'the other five off.',

      'RFC 7644 section 2 requires a provider to be ABLE to map an authenticated client to an ' +
      'access control policy. This is that policy. It is two lines because this service ' +
      'authenticates nobody in the sense that matters — it is a turnstile, not a lock.',

      'AUTHORIZATION IS NOT AUTHENTICATION HERE EITHER. Any caller can get any scope: this ' +
      'authorization server grants what it is asked, from any grant, to any client_id. What ' +
      'the scope requirement exercises is the CLIENT\'s handling of one, which is the thing ' +
      'a permissive server otherwise makes untestable.'
    ]
  };
  log.debug("Leaving describe(). " + out.schemes.length + " scheme(s).");
  return out;
}

// The counters' vocabulary, so that /admin/scim can draw a row per scheme
// including the zeroes — the same rule the operations table follows, and for
// the same reason: "does this server do Digest" is answered by a row saying 0
// and not by an absence.
function schemeIds() {
  return SCHEMES.map(function (row) { return row.id; }).concat(['anonymous']);
}

log.info('scim: the SCIM endpoints authenticate through ' +
         enabledSchemes().map(function (row) { return row.name; }).join(', ') +
         (authRequired() ? '. A credential is REQUIRED' : '. A credential is OPTIONAL ' +
          '(scim.authRequired is off)') + '; every one of them is permissive, and the ' +
         'access control policy is on GET /scim.');

module.exports = {
  SCHEMES: SCHEMES,
  REFUSED_PASSWORD: REFUSED_PASSWORD,
  authRequired: authRequired,
  authDiscovery: authDiscovery,
  realm: realm,
  scopeRead: scopeRead,
  scopeWrite: scopeWrite,
  challenges: challenges,
  authenticate: authenticate,
  registerHobaKey: registerHobaKey,
  schemesForConfig: schemesForConfig,
  schemesBeyondTheCanonicalList: schemesBeyondTheCanonicalList,
  primarySchemeId: primarySchemeId,
  describe: describe,
  schemeIds: schemeIds
};
