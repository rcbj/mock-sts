'use strict';
//
// File: wsfed.js
//
// ===========================================================================
// WS-Federation 1.2 — the Web (Passive) Requestor Profile, section 13.
//
// This is the profile that joins the pieces that were already here. Until it
// existed, this service could mint a SAML assertion and sign it, and it had a
// login screen, and it had no way to hand an assertion to a relying party through
// a browser — it was an assertion ISSUER with no browser-facing SSO profile, and
// README.md said so at some length rather than let the gap beside WS-Trust and
// SAML 2.0 be read as an oversight. What follows is that profile:
//
//   GET|POST /wsfed          the passive requestor endpoint. Dispatches on `wa`:
//                              wsignin1.0          sign in (13.2.1 / 13.2.2)
//                              wsignout1.0         sign out (13.2.4)
//                              wsignoutcleanup1.0  clean up (13.2.4)
//                              wattr1.0/wpseudo1.0 refused, and says why
//                            With no `wa` at all it describes itself, like GET /sts.
//   POST /wsfed/login        where the sign-in screen posts
//   GET  /wsfed/autopost.js  the one script the sign-in response page runs
//   GET  /FederationMetadata/2007-06/FederationMetadata.xml
//                            the signed federation metadata, at the path AD FS
//                            publishes it at, because that is where every client
//                            looks first
//   GET|POST /wsfed/rp       a mock RELYING PARTY: non-spec, the default `wreply`,
//                            and where the sign-in response can be verified check
//                            by check without a second service
//
// **The response is a form POST, not a redirect** (13.2.2), and that single fact is
// what makes this profile different from everything else in this service: the token
// travels in the body of a self-submitting form, so it is not length-limited and
// never lands in a URL, a log or a Referer header. The three things that follow
// from it are all recorded below — the CSP exception the auto-submit needs, why
// `form-action` must stay out of that policy, and the SameSite consequence of a
// sign-in request that arrives by POST.
//
// **It authenticates nobody, like the rest of this service.** The username typed at
// the sign-in screen is the subject of the assertion, and the only password refused
// is the literal "invalid", so a negative test has something to fail on.
//
// ---------------------------------------------------------------------------
// Four decisions here are not obvious from the specification, and each is the
// record of what a relying party actually expects:
//
// 1. **SAML 1.1 is the default token, not SAML 2.0.** WS-Federation is token-type
//    agnostic and this service has issued SAML 2.0 for years, so 2.0 looks like the
//    obvious default — but AD FS issues a SAML **1.1** assertion to a WS-Federation
//    relying party unless told otherwise, and the RP libraries written against it
//    read 1.1 first. A mock whose default was the rarer of the two would exercise
//    the wrong half of those clients. Both are offered (see `tokenType` below and
//    `fed:TokenTypesOffered` in the metadata), and saml11.js exists for this.
//
// 2. **The RSTR wrapper uses the WS-Trust 2005/02 namespace by default**, as a
//    single RequestSecurityTokenResponse rather than a Collection. That is what AD
//    FS emits for this profile and what WIF-era relying parties parse; ws-sx
//    200512 with an RSTRC is what /sts emits for WS-Trust proper. `?trust=1.3`
//    switches this endpoint over, so a client can be driven through both shapes —
//    which matters because an RP that only ever saw one of them usually turns out
//    to have hard-coded it.
//
// 3. **The session is the one oauth2.js owns**, through its startSession/sessionOf
//    (this module is required after it in server.js, so the dependency is one-way
//    and no cycle exists). Single sign-on across the two protocols is the point:
//    sign in at the OIDC screen with a security key and arrive at `wsignin1.0`, and
//    the assertion's AuthenticationMethod says a hardware key was used because the
//    session recorded `amr: ["pwd","hwk"]`. Two session stores would have made that
//    invisible and each would have looked correct on its own.
//
// 4. **`wctx` is echoed byte for byte and never interpreted.** It is the relying
//    party's own state and the commonest thing for an IdP to mangle (by decoding
//    it, re-encoding it, or dropping it when it is long), and an RP whose `wctx`
//    comes back altered cannot tell that from a lost session. The mock RP below
//    checks the round trip explicitly for that reason.
// ===========================================================================

const { DOMParser } = require('@xmldom/xmldom');
const { SignedXml } = require('xml-crypto');
const app = require('./app');
const { log, logArtifact, ISSUER, STS, xmlEscape, genId, iso, baseUrlOf, randomId,
        parseBody, firstByLocal, textByLocal } = require('./helpers');
const { buildSamlAssertion } = require('./saml2');
const { buildSaml11Assertion } = require('./saml11');
const { sessionOf, startSession, endSession } = require('./oauth2');

// --- the vocabulary --------------------------------------------------------
const WSFED_NS = 'http://docs.oasis-open.org/wsfed/federation/200706';

const WSFED_AUTH_NS = 'http://docs.oasis-open.org/wsfed/authorization/200706';

const SAML_METADATA_NS = 'urn:oasis:names:tc:SAML:2.0:metadata';

// WS-Trust February 2005 — the namespace this profile's RSTR is written in by
// default. Not a typo for the ws-sx one /sts uses: see decision 2 above.
const TRUST_2005_02 = 'http://schemas.xmlsoap.org/ws/2005/02/trust';

const TRUST_1_3 = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';

const SAML11_TOKEN_TYPE = 'urn:oasis:names:tc:SAML:1.0:assertion';

const SAML2_TOKEN_TYPE = 'urn:oasis:names:tc:SAML:2.0:assertion';

// The claim URIs a WS-Federation relying party keys off. They are the Microsoft
// namespaces rather than anything OASIS published, because that is what exists:
// WS-Federation defines a claim dialect and no claim vocabulary, and every RP in
// this ecosystem was written against these.
const CLAIM_NS = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims';

const MS_CLAIM_NS = 'http://schemas.microsoft.com/ws/2008/06/identity/claims';

const ATTRNAME_FORMAT_URI = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';

// How the End-User authenticated, said twice because the two token types have
// separate vocabularies for it: SAML 1.1 has AuthenticationMethod URIs, SAML 2.0
// has AuthnContextClassRef.
//
// The multi-factor value is Microsoft's `.../claims/multipleauthn` in BOTH, and
// that is deliberate rather than lazy: SAML 2.0's authentication context classes
// have no member that describes a WebAuthn hardware key without overstating what
// happened (SmartcardPKI, TimeSyncToken and X509 each claim a specific mechanism
// this service did not perform), while `multipleauthn` is exactly the claim being
// made — more than one factor — and is the value AD FS emits for it, so a relying
// party in this ecosystem already knows it.
const AM_PASSWORD_SAML11 = 'urn:oasis:names:tc:SAML:1.0:am:password';

const AC_PASSWORD_SAML2 = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';

const AM_MULTIFACTOR = 'http://schemas.microsoft.com/claims/multipleauthn';

// What `wauth` may ask for (13.2.1). A request for anything else is refused rather
// than quietly answered with a password assertion: `wauth` is how a relying party
// DEMANDS an authentication type, and an IdP that ignores it lets the demand appear
// to have been met.
const WAUTH_PASSWORD = [
  AM_PASSWORD_SAML11,
  'urn:oasis:names:tc:SAML:1.0:am:unspecified',
  AC_PASSWORD_SAML2,
  'urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/authenticationmethod/password',
  'http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password'
];

const WAUTH_MULTIFACTOR = [
  AM_MULTIFACTOR,
  'urn:oasis:names:tc:SAML:1.0:am:HardwareToken'
];

const PASSIVE_PATH = '/wsfed';

const RP_PATH = '/wsfed/rp';

const SIGNIN_TTL_MS = 10 * 60 * 1000;

const RP_CONTEXT_TTL_MS = 30 * 60 * 1000;

// The sign-in request being interrupted by the screen, exactly as pendingLogins
// does for the authorization endpoint: sign-in id -> the parameters it arrived with.
const pendingSignIns = new Map();

// The `wctx` values the mock relying party has minted, so it can check the round
// trip. Its own state and nobody else's — which is the whole point of wctx.
const rpContexts = new Map();

// --- reading the request ---------------------------------------------------
// 13.2.1 allows the sign-in request as a GET with a query string or as a form
// POST. Both are read here, with the body winning over the query on a collision:
// a POST that also carried query parameters is the caller having said the same
// thing twice, and the body is the half they meant.
function paramsOf(req) {
  log.debug("Entering paramsOf(). method=" + req.method);
  const out = {};
  Object.keys(req.query || {}).forEach(function (k) { out[k] = req.query[k]; });
  if (req.method === 'POST') {
    const body = parseBody(req);
    Object.keys(body).forEach(function (k) { out[k] = body[k]; });
  }
  log.debug("Leaving paramsOf(). wa=" + (out.wa || '(none)') + ", " +
            Object.keys(out).length + " parameter(s).");
  return out;
}

// The parameters, minus the ones that must not survive a round trip through the
// sign-in screen. `wfresh` is the one that matters: wfresh=0 demands a fresh
// authentication, and carrying it back after the user has just authenticated would
// demand another one, forever. It is the same trap `prompt=login` sets at the
// authorization endpoint, and it is dropped in the same place for the same reason.
function requeryString(params, omit) {
  log.debug("Entering requeryString().");
  const usp = new URLSearchParams();
  Object.keys(params).forEach(function (k) {
    if (omit && omit.indexOf(k) >= 0) return;
    usp.set(k, params[k]);
  });
  log.debug("Leaving requeryString().");
  return usp.toString();
}

// --- the pages -------------------------------------------------------------
// One shell for all of them. The CSS is inline because app.js sets
// `default-src 'none'` with `style-src 'unsafe-inline'`, so a stylesheet as a
// separate resource would need its own exception to buy nothing.
function page(title, inner) {
  return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + xmlEscape(title) + '</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'padding:2rem;color:#222;line-height:1.45}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:24px 28px;' +
    'max-width:52rem;margin:0 auto;box-shadow:0 6px 24px rgba(0,0,0,.08)}' +
    'h1{font-size:1.3em;margin:0 0 4px;color:#12107c}h2{font-size:1em;margin:1.4em 0 .4em}' +
    'p.sub{color:#666;font-size:.85em;margin:0 0 18px}' +
    'label{display:block;font-size:.85em;font-weight:600;margin:12px 0 4px}' +
    'input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:8px 10px;' +
    'border:1px solid #bbb;border-radius:5px;font-size:1em}.row{display:flex;gap:10px;margin-top:20px}' +
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

// A sentence naming the parameter that was wrong, and a 400. WS-Federation defines
// no error response for this profile — the sign-in request is a browser navigation
// and there is nowhere to report to except the screen — so the error IS a page, and
// it says what to change rather than "invalid request".
function wsfedError(res, status, title, detail, extra) {
  log.debug("Entering wsfedError(). status=" + status + ", title=" + title);
  const inner = '<h1>' + xmlEscape(title) + '</h1>' +
    '<p class="sub">WS-Federation passive requestor endpoint at <code>' + PASSIVE_PATH + '</code></p>' +
    '<div class="err">' + xmlEscape(detail) + '</div>' + (extra || '') +
    '<div class="meta"><div>This profile has no error response of its own: a sign-in request is a ' +
    'browser navigation, so there is nothing to redirect an error to and this page is the answer. ' +
    'The request is logged in full at debug level.</div></div>';
  res.status(status).type('text/html').set('Cache-Control', 'no-store').send(page(title, inner));
  log.debug("Leaving wsfedError().");
}

// --- what goes in the token ------------------------------------------------
// The claims, once, in the shape each token type wants. Written from the one user
// object so the two assertions cannot describe different people — which they did
// while this was two lists.
function claimsFor(user, authnMethod, authnInstant) {
  log.debug("Entering claimsFor(). user=" + user.username);
  const claims = [
    { namespace: CLAIM_NS, name: 'nameidentifier', value: user.sub },
    { namespace: CLAIM_NS, name: 'name', value: user.username },
    { namespace: CLAIM_NS, name: 'givenname', value: user.given_name },
    { namespace: CLAIM_NS, name: 'surname', value: user.family_name },
    { namespace: CLAIM_NS, name: 'emailaddress', value: user.email },
    // The UPN and the mail address are the same string here because userFor()
    // mints one address, and inventing a second identifier that differed would be
    // a distinction with nothing behind it. A relying party matching on `upn`
    // still gets the shape it expects.
    { namespace: CLAIM_NS, name: 'upn', value: user.email },
    { namespace: MS_CLAIM_NS, name: 'authenticationmethod', value: authnMethod },
    { namespace: MS_CLAIM_NS, name: 'authenticationinstant', value: authnInstant }
  ];
  log.debug("Leaving claimsFor(). " + claims.length + " claim(s).");
  return claims;
}

// What the session says actually happened, in each token type's vocabulary. A
// session that recorded `hwk` produces the multi-factor value; a password-only one
// produces the password value. Nothing here is configurable by the request, which
// is the point: `wauth` asks, the session answers.
function authnMethodsFor(session) {
  const mfa = (session.amr || []).indexOf('hwk') >= 0 || session.acr === 'mfa';
  return {
    saml11: mfa ? AM_MULTIFACTOR : AM_PASSWORD_SAML11,
    saml2: mfa ? AM_MULTIFACTOR : AC_PASSWORD_SAML2,
    multiFactor: mfa
  };
}

// The token type asked for. Three ways, in precedence order, and the first two are
// the specification's:
//
//   * `wreq`, which carries a whole RST — the spec-blessed way to say anything
//     WS-Trust can express, and TokenType is what a passive client puts in it
//   * `tokenType`, a NON-SPEC query parameter in the manner of /sts's ?encrypt=1,
//     because typing a whole RST into a URL to see the other token type is not
//     something anybody should have to do to try this by hand
//   * the default, SAML 1.1
//
// `wreqptr` is refused rather than dereferenced. It names a URL the IdP is meant to
// fetch the request from, and a mock that fetched an arbitrary URL handed to it in
// a query parameter would be a server-side request forgery with a specification
// citation attached.
function tokenTypeFor(params) {
  log.debug("Entering tokenTypeFor().");
  let asked = '';
  let from = 'the default';
  if (params.wreq) {
    try {
      const doc = new DOMParser().parseFromString(String(params.wreq), 'text/xml');
      asked = textByLocal(doc, 'TokenType');
      if (asked) from = 'the wreq RST';
      // AppliesTo in a wreq is read only to be reported: wtrealm is the realm this
      // profile names, and two answers to "who is this token for" must not both be
      // authoritative. A disagreement is logged because it is a client bug worth
      // seeing, not silently resolved.
      const appliesTo = firstByLocal(doc, 'AppliesTo');
      const address = appliesTo ? textByLocal(appliesTo, 'Address') : '';
      if (address && params.wtrealm && address !== String(params.wtrealm)) {
        log.debug('wsfed: the wreq RST names AppliesTo "' + address + '" while wtrealm is "' +
                  params.wtrealm + '"; wtrealm wins in this profile.');
      }
    } catch (e) {
      // Not XML. Reported and ignored rather than fatal — the request can still be
      // answered with the default token, and the log says the wreq was unreadable.
      log.error('wsfed: the wreq parameter is not readable XML: ' + e.message);
    }
  }
  if (!asked && params.tokenType) {
    asked = String(params.tokenType);
    from = 'the non-spec tokenType parameter';
  }
  // The short forms, because nobody types the URN by hand twice.
  if (asked === 'saml11' || asked === 'saml1' || asked === '1.1') asked = SAML11_TOKEN_TYPE;
  if (asked === 'saml2' || asked === 'saml20' || asked === '2.0') asked = SAML2_TOKEN_TYPE;
  if (!asked) {
    log.debug("Leaving tokenTypeFor(). SAML 1.1, from " + from + ".");
    return { tokenType: SAML11_TOKEN_TYPE, from: from };
  }
  if (asked !== SAML11_TOKEN_TYPE && asked !== SAML2_TOKEN_TYPE) {
    log.debug("Leaving tokenTypeFor(). An unsupported token type was asked for: " + asked);
    return { error: asked, from: from };
  }
  log.debug("Leaving tokenTypeFor(). " + asked + ", from " + from + ".");
  return { tokenType: asked, from: from };
}

// --- the sign-in response (13.2.2) -----------------------------------------
// The RSTR that goes in `wresult`. Not signed itself — the assertion inside it is,
// which is what a relying party checks; a signature over the wrapper would be
// something no RP in this profile looks at.
function buildRstr(tokenType, assertionXml, realm, lifetimeMin, trustVersion) {
  log.debug("Entering buildRstr(). tokenType=" + tokenType + ", trust=" + trustVersion);
  const trustNs = trustVersion === '1.3' ? TRUST_1_3 : TRUST_2005_02;
  const wsu = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
  const keyType = trustVersion === '1.3'
    ? trustNs + '/Bearer'
    // 2005/02 has no /Bearer: the value that says "no proof key, this is a bearer
    // token" in that vintage is NoProofKey out of the identity namespace, and it is
    // what AD FS puts here.
    : 'http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey';
  const appliesTo = realm
    ? '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">' +
      '<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">' +
      '<wsa:Address>' + xmlEscape(realm) + '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>'
    : '';
  // The element order is AD FS's and is worth keeping: Lifetime, AppliesTo,
  // RequestedSecurityToken, TokenType, RequestType, KeyType. The WS-Trust schema
  // is a sequence, so a relying party built on a generated parser rejects any
  // other order, and the ones that hand-parse were written against this one.
  const inner =
    '<t:Lifetime>' +
      '<wsu:Created xmlns:wsu="' + wsu + '">' + iso(0) + '</wsu:Created>' +
      '<wsu:Expires xmlns:wsu="' + wsu + '">' + iso(lifetimeMin) + '</wsu:Expires>' +
    '</t:Lifetime>' +
    appliesTo +
    '<t:RequestedSecurityToken>' + assertionXml + '</t:RequestedSecurityToken>' +
    '<t:TokenType>' + tokenType + '</t:TokenType>' +
    '<t:RequestType>' + trustNs + '/Issue</t:RequestType>' +
    '<t:KeyType>' + keyType + '</t:KeyType>';
  const rstr = '<t:RequestSecurityTokenResponse xmlns:t="' + trustNs + '">' + inner +
               '</t:RequestSecurityTokenResponse>';
  const wresult = trustVersion === '1.3'
    ? '<t:RequestSecurityTokenResponseCollection xmlns:t="' + trustNs + '">' + rstr +
      '</t:RequestSecurityTokenResponseCollection>'
    : rstr;
  logArtifact('WS-Federation wresult (RSTR)', 'as posted to the relying party', wresult);
  log.debug("Leaving buildRstr(). " + wresult.length + " characters.");
  return wresult;
}

// The auto-submitting form of 13.2.2, and the two policy notes that go with it.
//
// **This page runs a script, and it is the second response in this service that
// relaxes `script-src`** — to `'self'`, naming `/wsfed/autopost.js`, exactly as the
// WebAuthn page does. An inline script would not run at all under the default
// policy, silently, leaving a page that looks like it is working and never posts.
// The submit button is not a fallback nobody sees: with scripting off it is the
// whole mechanism, so it is labelled for a person rather than hidden.
//
// **`form-action` is deliberately absent from the policy, here as everywhere.**
// app.js records why for the OAuth redirect; this profile is the other half of the
// same reason and a stronger one: the form posts to `wreply`, which is by
// definition another origin. `form-action 'self'` would block the sign-in response
// from ever reaching the relying party, and the symptom is a sign-in that appears
// to succeed while the RP simply never hears anything.
function signInResponsePage(wreply, wresult, wctx, realm, tokenType) {
  log.debug("Entering signInResponsePage(). wreply=" + wreply);
  const inner = '<h1>Signing in to the relying party</h1>' +
    '<p class="sub">WS-Federation 1.2 section 13.2.2 — the token travels in a form POST, not in a ' +
    'redirect, so it is not length-limited and never appears in a URL, a log or a Referer header.</p>' +
    '<form method="post" action="' + xmlEscape(wreply) + '" id="wsfed-form">' +
      '<input type="hidden" name="wa" value="wsignin1.0">' +
      '<input type="hidden" name="wresult" value="' + xmlEscape(wresult) + '">' +
      (wctx !== undefined && wctx !== null && wctx !== ''
        ? '<input type="hidden" name="wctx" value="' + xmlEscape(wctx) + '">' : '') +
      '<div class="row"><button type="submit">Continue to the relying party</button></div>' +
    '</form>' +
    '<div class="meta">' +
    '<div>wa: <code>wsignin1.0</code></div>' +
    '<div>posting to (wreply): <code>' + xmlEscape(wreply) + '</code></div>' +
    '<div>realm (wtrealm): <code>' + xmlEscape(realm) + '</code></div>' +
    '<div>token type: <code>' + xmlEscape(tokenType) + '</code></div>' +
    '<div>wctx: ' + (wctx ? '<code>' + xmlEscape(wctx) + '</code>, echoed byte for byte'
                          : 'the request carried none, so none is returned') + '</div>' +
    '<div>The form submits itself from <code>/wsfed/autopost.js</code>. It is a separate resource ' +
    'because this service sets <code>script-src \'none\'</code> on every response and this page ' +
    'relaxes it to <code>\'self\'</code> — an inline script would not run, and the button would be ' +
    'the only thing that worked. With scripting off, the button IS the mechanism.</div>' +
    '</div>' +
    '<script src="/wsfed/autopost.js"></script>';
  log.debug("Leaving signInResponsePage().");
  return inner;
}

// Written with no regular expressions and nothing to escape, for the reason
// oauth2.js's ceremony script records: a backslash in a script that passes through
// a JavaScript string literal on its way out does not survive the trip.
const AUTOPOST_SCRIPT = [
  '(function () {',
  '  var f = document.getElementById("wsfed-form");',
  '  if (f) { f.submit(); }',
  '})();',
  ''
].join('\n');

app.get('/wsfed/autopost.js', function (req, res) {
  log.debug("Serving the WS-Federation sign-in response auto-post script.");
  res.set('Content-Security-Policy', "default-src 'none'");
  res.type('application/javascript').set('Cache-Control', 'no-store').send(AUTOPOST_SCRIPT);
});

function sendSignInResponse(res, inner) {
  // The same shape of exception the WebAuthn page takes, and no wider: a named
  // resource, not 'unsafe-inline'.
  res.set('Content-Security-Policy',
          "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; " +
          "base-uri 'none'; frame-ancestors 'none'");
  res.status(200).type('text/html').set('Cache-Control', 'no-store')
     .send(page('Signing in — WS-Federation', inner));
}

// --- the sign-in screen ----------------------------------------------------
// Its own screen rather than the authorization endpoint's, because the parameters a
// person needs to see are different ones — wtrealm, wreply, wctx, wauth, whr — and
// a screen that showed `client_id: (none)` for a WS-Federation sign-in would be
// describing a request that does not exist.
//
// It has no security-key checkbox, and that is a real limitation rather than an
// omission: the WebAuthn step lives in oauth2.js because it needs that module's
// pendingMfa and returns to the authorization endpoint, and reaching into it from
// here is the import cycle this service's split exists to prevent. What replaces it
// is the shared session — sign in once through the OIDC screen with a key and the
// session carries `hwk` here — which is also what `wauth` asking for multi-factor
// is answered from.
function signInPage(base, signIn, error) {
  log.debug("Entering signInPage(). wtrealm=" + (signIn.params.wtrealm || '(none)'));
  const p = signIn.params;
  const inner = '<h1>Sign in</h1>' +
    '<p class="sub">Mock WS-Federation identity provider at <code>' + xmlEscape(base) + '</code></p>' +
    (error ? '<div class="err">' + xmlEscape(error) + '</div>' : '') +
    '<form method="post" action="/wsfed/login">' +
    '<input type="hidden" name="signin_id" value="' + xmlEscape(signIn.id) + '">' +
    '<label for="username">Username</label>' +
    '<input type="text" id="username" name="username" autocomplete="username" autofocus value="">' +
    '<label for="password">Password</label>' +
    '<input type="password" id="password" name="password" autocomplete="current-password">' +
    '<div class="row"><button type="submit" id="wsfed-login" name="action" value="login">Sign In</button>' +
    '<button type="submit" id="wsfed-cancel" name="action" value="cancel" class="secondary">Cancel' +
    '</button></div></form>' +
    '<div class="meta">' +
    '<div>No password is checked. The username you enter is the subject of the assertion, and the ' +
    'claims are built from it.</div>' +
    '<div>wtrealm: <code>' + xmlEscape(p.wtrealm || '') + '</code></div>' +
    '<div>wreply: <code>' + xmlEscape(p.wreply || '(none — the response goes to this service\'s own ' +
      'mock relying party at ' + RP_PATH + ')') + '</code></div>' +
    '<div>wctx: <code>' + xmlEscape(p.wctx || '(none)') + '</code></div>' +
    (p.wauth ? '<div>wauth: <code>' + xmlEscape(p.wauth) + '</code> — the authentication method this ' +
               'relying party asked for.</div>' : '') +
    (p.wfresh !== undefined ? '<div>wfresh: <code>' + xmlEscape(p.wfresh) + '</code> — why this screen ' +
               'appeared even if you were already signed in.</div>' : '') +
    (p.whr ? '<div>whr: <code>' + xmlEscape(p.whr) + '</code> — a home realm was named. This service ' +
             'is the only identity provider here, so the request is answered locally rather than ' +
             'forwarded, and the parameter is recorded rather than honoured.</div>' : '') +
    '<div>The session this creates is the SAME one the OAuth 2.0 / OIDC login screen creates, so ' +
    'signing in here signs you in there and the other way round. To get an assertion that says a ' +
    'hardware key was used, sign in at <code>/oauth2/authorize</code> with a security key first.</div>' +
    '</div>';
  log.debug("Leaving signInPage().");
  return inner;
}

function sendPage(res, status, title, inner) {
  res.status(status).type('text/html').set('Cache-Control', 'no-store').send(page(title, inner));
}

// --- wfresh (13.2.1) -------------------------------------------------------
// "wfresh=0" means authenticate now whatever the session says; "wfresh=N" means the
// authentication must be no older than N MINUTES (not seconds — this is the one
// place WS-Federation and OIDC's max_age differ in unit, and reading it as seconds
// makes every request look fresh).
function freshEnough(session, wfresh) {
  log.debug("Entering freshEnough(). wfresh=" + wfresh);
  if (wfresh === undefined || wfresh === null || wfresh === '') {
    log.debug("Leaving freshEnough(). None was asked for.");
    return { ok: true };
  }
  const minutes = parseInt(String(wfresh), 10);
  if (isNaN(minutes) || minutes < 0) {
    log.debug("Leaving freshEnough(). wfresh is not a number of minutes.");
    return { ok: false, invalid: true };
  }
  if (minutes === 0) {
    log.debug("Leaving freshEnough(). wfresh=0 demands a fresh authentication.");
    return { ok: false, why: 'wfresh=0: this relying party asked for a fresh authentication.' };
  }
  const ageMin = (Date.now() / 1000 - (session.authTime || 0)) / 60;
  if (ageMin > minutes) {
    log.debug("Leaving freshEnough(). The session is " + Math.round(ageMin) + " minutes old.");
    return { ok: false, why: 'wfresh=' + minutes + ': the existing session authenticated ' +
                             Math.round(ageMin) + ' minutes ago.' };
  }
  log.debug("Leaving freshEnough(). The session is fresh enough.");
  return { ok: true };
}

// --- sign-in (13.2.1 -> 13.2.2) -------------------------------------------
function signIn(req, res, params) {
  log.debug("Entering signIn(). wtrealm=" + (params.wtrealm || '(none)'));
  const base = baseUrlOf(req);

  if (params.wreqptr) {
    log.debug("Leaving signIn(). wreqptr was used.");
    return wsfedError(res, 400, 'wreqptr is not dereferenced',
      'This request carries wreqptr, which names a URL the identity provider is meant to fetch the ' +
      'request from. This service will not fetch an arbitrary URL handed to it in a query parameter — ' +
      'that is a server-side request forgery with a specification citation attached. Send the request ' +
      'in wreq by value instead.');
  }

  const realm = String(params.wtrealm || '');
  if (!realm) {
    log.debug("Leaving signIn(). No wtrealm.");
    return wsfedError(res, 400, 'wtrealm is required',
      'A wsignin1.0 request must name the relying party it is for (section 13.2.1). The realm becomes ' +
      'the assertion\'s audience restriction, and an assertion with no audience is one any relying ' +
      'party would be entitled to accept.',
      '<p>There is a mock relying party here that sends a complete request: ' +
      '<a href="' + RP_PATH + '">' + RP_PATH + '</a>.</p>');
  }

  // wreply is optional (13.2.1). With none, the response goes to this service's own
  // mock relying party rather than nowhere: a real IdP would post to the endpoint
  // registered for wtrealm, and there is no registration here to consult.
  //
  // It is NOT validated against anything, exactly as post_logout_redirect_uri is
  // not at /oauth2/logout, and for the same stated reason — this mock accepts
  // arbitrary return URLs on purpose. It must at least be an absolute http(s) URL,
  // because a form action that is not one posts back to this origin and the failure
  // reads as the relying party having ignored the response.
  const wreply = params.wreply ? String(params.wreply) : (base + RP_PATH);
  if (!/^https?:\/\//i.test(wreply)) {
    log.debug("Leaving signIn(). wreply is not an absolute http(s) URL.");
    return wsfedError(res, 400, 'wreply must be an absolute URL',
      'wreply is "' + wreply + '". The sign-in response is a form POST to that address, and a ' +
      'relative or non-http(s) value posts back to this service instead — which looks exactly like a ' +
      'relying party that ignored the response.');
  }

  const asked = tokenTypeFor(params);
  if (asked.error) {
    log.debug("Leaving signIn(). An unsupported token type was asked for.");
    return wsfedError(res, 400, 'That token type is not offered',
      'This request asked for "' + asked.error + '" (from ' + asked.from + '). This identity provider ' +
      'issues SAML 1.1 (' + SAML11_TOKEN_TYPE + ') and SAML 2.0 (' + SAML2_TOKEN_TYPE + ') assertions, ' +
      'which are the two token types its federation metadata advertises in fed:TokenTypesOffered.');
  }

  // wauth: what authentication method the relying party is demanding.
  const wauth = params.wauth ? String(params.wauth) : '';
  if (wauth && WAUTH_PASSWORD.indexOf(wauth) < 0 && WAUTH_MULTIFACTOR.indexOf(wauth) < 0) {
    log.debug("Leaving signIn(). wauth named a method this service cannot perform.");
    return wsfedError(res, 400, 'That authentication method is not available',
      'wauth asked for "' + wauth + '". This identity provider can perform a password sign-in, and it ' +
      'can report a multi-factor one when the browser session was established with a security key.',
      '<h2>What it accepts</h2><ul>' +
      WAUTH_PASSWORD.concat(WAUTH_MULTIFACTOR).map(function (v) {
        return '<li><code>' + xmlEscape(v) + '</code></li>';
      }).join('') + '</ul>' +
      '<p>It is refused rather than answered with a password assertion on purpose: <code>wauth</code> ' +
      'is how a relying party <em>demands</em> a method, and an identity provider that ignored it ' +
      'would let the demand appear to have been met.</p>');
  }

  // Already signed in, and fresh enough? Then this is the second pass — after the
  // screen, or a later request on a session that already exists — and the response
  // goes out now. This is where single sign-on happens.
  const session = sessionOf(req);
  const fresh = session ? freshEnough(session, params.wfresh) : { ok: true };
  if (fresh.invalid) {
    log.debug("Leaving signIn(). wfresh was not a number.");
    return wsfedError(res, 400, 'wfresh must be a number of minutes',
      'wfresh is "' + params.wfresh + '". Section 13.2.1 makes it the maximum age of the ' +
      'authentication in MINUTES, with 0 meaning "authenticate now" — it is not a number of seconds ' +
      'and it is not a boolean.');
  }
  if (session && fresh.ok) {
    if (WAUTH_MULTIFACTOR.indexOf(wauth) >= 0 && !authnMethodsFor(session).multiFactor) {
      // The one place this profile has to refuse something it could have faked. The
      // screen below cannot run a WebAuthn ceremony (see signInPage), so answering
      // a multi-factor demand from a password session would mean writing a claim
      // that did not happen — and a relying party reading it would have learned
      // something false about how the person signed in.
      log.debug("Leaving signIn(). wauth asked for multi-factor and the session has one factor.");
      return wsfedError(res, 400, 'This session has one factor',
        'wauth asked for "' + wauth + '", and the browser session here was established with a ' +
        'password alone. This service will not claim a second factor that did not happen.',
        '<h2>Two ways forward</h2><ul>' +
        '<li>Get a multi-factor session first: sign in at <code>/oauth2/authorize</code> with the ' +
        'security-key box ticked (or with <code>acr_values=mfa</code>, which ticks it and disables ' +
        'the opt-out). The session is shared, so coming back here then produces an assertion whose ' +
        'AuthenticationMethod is <code>' + xmlEscape(AM_MULTIFACTOR) + '</code>.</li>' +
        '<li>Or ask for what this session has: ' +
        '<a href="' + PASSIVE_PATH + '?' + xmlEscape(requeryString(params, ['wauth'])) + '">the same ' +
        'request without wauth</a>.</li></ul>');
    }
    log.debug("The session stands, so the sign-in response goes out now.");
    return issueSignInResponse(req, res, params, session, realm, wreply, asked.tokenType);
  }

  // Otherwise: authenticate first. The request is stashed whole so the login POST
  // can send the browser back to it unchanged.
  const signInState = {
    id: randomId(18),
    params: JSON.parse(JSON.stringify(params)),
    expires: Date.now() + SIGNIN_TTL_MS
  };
  pendingSignIns.set(signInState.id, signInState);
  pendingSignIns.forEach(function (v, k) { if (v.expires < Date.now()) pendingSignIns.delete(k); });
  sendPage(res, 200, 'Sign in — WS-Federation',
           signInPage(base, signInState, fresh.ok ? '' : fresh.why));
  log.debug("Leaving signIn(). Showing the sign-in screen first.");
}

function issueSignInResponse(req, res, params, session, realm, wreply, tokenType) {
  log.debug("Entering issueSignInResponse(). tokenType=" + tokenType);
  const user = session.user;
  const methods = authnMethodsFor(session);
  const authnInstant = new Date((session.authTime || 0) * 1000).toISOString();
  const lifetimeMin = 60;
  let assertion;
  if (tokenType === SAML2_TOKEN_TYPE) {
    assertion = buildSamlAssertion(user.username, realm, lifetimeMin, {
      authnContextClassRef: methods.saml2,
      // The full claim URI in one Name, which is SAML 2.0's shape, with the
      // NameFormat that says so. SAML 1.1 splits the same URI in two.
      attributes: claimsFor(user, methods.saml2, authnInstant).map(function (c) {
        return { name: c.namespace + '/' + c.name, nameFormat: ATTRNAME_FORMAT_URI, value: c.value };
      })
    });
  } else {
    assertion = buildSaml11Assertion({
      subject: user.username,
      audience: realm,
      lifetimeMin: lifetimeMin,
      authnMethod: methods.saml11,
      authnInstant: authnInstant,
      attributes: claimsFor(user, methods.saml11, authnInstant)
    });
  }
  const trustVersion = String(params.trust || '') === '1.3' ? '1.3' : '2005/02';
  const wresult = buildRstr(tokenType, assertion, realm, lifetimeMin, trustVersion);

  // Remember which relying parties this session has signed into, so wsignout1.0 has
  // somewhere to send its cleanup requests. It lives ON the session rather than in a
  // map of its own because that is exactly the lifetime it should have: when the
  // session goes, so does the list, and nothing has to be swept.
  session.wsfedRealms = session.wsfedRealms || {};
  session.wsfedRealms[realm] = wreply;

  sendSignInResponse(res, signInResponsePage(wreply, wresult, params.wctx, realm, tokenType));
  log.debug("Leaving issueSignInResponse(). " + user.username + " signed in to " + realm + ".");
}

app.post('/wsfed/login', function (req, res) {
  log.debug("Entering the WS-Federation sign-in form target.");
  const base = baseUrlOf(req);
  const body = parseBody(req);
  const signInState = pendingSignIns.get(String(body.signin_id || ''));
  if (!signInState || signInState.expires < Date.now()) {
    pendingSignIns.delete(String(body.signin_id || ''));
    log.debug("Leaving the sign-in form target. The form had expired.");
    return wsfedError(res, 400, 'This sign-in form has expired',
      'The form is held for ten minutes with the sign-in request it interrupted. Start the ' +
      'wsignin1.0 request again from the relying party.');
  }

  if (String(body.action || '') === 'cancel') {
    pendingSignIns.delete(signInState.id);
    log.debug("Leaving the sign-in form target. The user cancelled.");
    // There is nowhere to report this TO. The OAuth flow answers a cancellation
    // with error=access_denied at the redirect_uri, and WS-Federation's passive
    // profile has no such response: an RP learns nothing except that the browser
    // never came back. Saying so on the page is the honest version.
    return wsfedError(res, 200, 'Sign-in cancelled',
      'You cancelled at the sign-in screen. This profile has no error response to send a relying ' +
      'party — unlike an OAuth authorization request, which would be answered with ' +
      'error=access_denied at its redirect_uri — so ' + xmlEscape(String(signInState.params.wtrealm ||
      'the relying party')) + ' is simply never posted to.');
  }

  const username = String(body.username || '').trim();
  if (!username) {
    log.debug("Leaving the sign-in form target. No username, so the form is shown again.");
    return sendPage(res, 200, 'Sign in — WS-Federation',
      signInPage(base, signInState, 'Enter a username. It does not have to exist — it is the subject ' +
                                    'of the assertion this identity provider will issue.'));
  }
  if (String(body.password || '') === 'invalid') {
    // The same reserved password WS-Trust and the password grant refuse, so a
    // negative test has one thing to fail on in every protocol here.
    log.debug("Leaving the sign-in form target. The reserved password was used.");
    return sendPage(res, 200, 'Sign in — WS-Federation',
      signInPage(base, signInState, 'Authentication failed for ' + username + '.'));
  }

  pendingSignIns.delete(signInState.id);
  startSession(res, username, ['pwd'], '1');
  // Back to the passive endpoint with the request as it arrived — minus wfresh,
  // which has now been honoured and would otherwise demand a fresh authentication
  // on every pass, forever.
  res.redirect(302, base + PASSIVE_PATH + '?' + requeryString(signInState.params, ['wfresh']));
  log.debug("Leaving the sign-in form target. " + username + " is signed in; back to " + PASSIVE_PATH + ".");
});

// --- sign-out (13.2.4) -----------------------------------------------------
// The session ends here, and every relying party it signed into is sent a cleanup
// request. Those are `<img>` loads, which is how front-channel logout is done
// front-channel logout, and they are the reason this one response relaxes
// `img-src`: app.js sets `img-src 'self' data:`, and a cleanup ping to a relying
// party is by definition a third-party origin. It is the feature, not a leak — the
// URLs are ones the relying parties themselves supplied as wreply.
//
// The pings are also listed visibly on the page. A silent `<img>` that failed would
// leave a person with no way to see that the cleanup did not happen.
function signOut(req, res, params, cleanupOnly) {
  log.debug("Entering signOut(). cleanupOnly=" + !!cleanupOnly);
  const session = endSession(req, res);
  const realms = (session && session.wsfedRealms) || {};
  const names = Object.keys(realms);
  const wreply = params.wreply ? String(params.wreply) : '';
  const cleanupUrl = function (url) {
    return url + (url.indexOf('?') >= 0 ? '&' : '?') + 'wa=wsignoutcleanup1.0';
  };
  let inner = '<h1>' + (cleanupOnly ? 'Signed out (cleanup)' : 'Signed out') + '</h1>' +
    '<p class="sub">WS-Federation 1.2 section 13.2.4</p>' +
    '<div class="ok">' + (session
      ? 'The session for ' + xmlEscape(session.user.username) + ' has ended. It was the session the ' +
        'OAuth 2.0 / OIDC side shares, so that side is signed out too.'
      : 'There was no session to end. The cookie has been cleared anyway.') + '</div>';
  if (cleanupOnly) {
    // A cleanup request arriving HERE (rather than at a relying party) ends the
    // session and stops. It deliberately does not fan out further cleanups: a
    // federation of two identity providers each cleaning the other up on receipt is
    // a loop, and this service is not a federation gateway.
    inner += '<p>This was a <code>wsignoutcleanup1.0</code> request, so the session was dropped and ' +
      'no further cleanup requests were sent — an identity provider that fanned out on receipt of a ' +
      'cleanup would loop with whatever sent it.</p>';
  } else if (names.length) {
    inner += '<h2>Cleanup requests sent to ' + names.length + ' relying part' +
      (names.length === 1 ? 'y' : 'ies') + '</h2><ul>' +
      names.map(function (r) {
        return '<li><code>' + xmlEscape(r) + '</code><br>' +
          '<a href="' + xmlEscape(cleanupUrl(realms[r])) + '" target="_blank" rel="noopener noreferrer">' +
          xmlEscape(cleanupUrl(realms[r])) + '</a></li>';
      }).join('') + '</ul>' +
      names.map(function (r) {
        return '<img src="' + xmlEscape(cleanupUrl(realms[r])) + '" alt="" width="1" height="1">';
      }).join('') +
      '<p class="sub">Each was fetched as a one-pixel image as this page loaded — front-channel ' +
      'logout, and the links above are the same URLs so a failed ping can be seen rather than ' +
      'guessed at.</p>';
  } else {
    inner += '<p>This session had signed into no relying party through this profile, so there was ' +
      'nothing to clean up.</p>';
  }
  if (wreply) {
    // Not an automatic redirect: the cleanup pings have to load first, and a 302
    // would abandon them. WS-Federation says the IdP MAY return the browser to
    // wreply, and a link is the version that does not defeat the cleanup.
    inner += '<h2>Return to the relying party</h2><p><a href="' + xmlEscape(wreply) + '">' +
      xmlEscape(wreply) + '</a></p><p class="sub">A link and not a redirect: the cleanup requests ' +
      'above load with this page, and a 302 would abandon them before they were sent.</p>';
  }
  // The one response in this service that widens img-src, and only that clause.
  res.set('Content-Security-Policy',
          "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src *; " +
          "base-uri 'none'; frame-ancestors 'none'");
  res.status(200).type('text/html').set('Cache-Control', 'no-store')
     .send(page('Signed out — WS-Federation', inner));
  log.debug("Leaving signOut(). " + names.length + " cleanup request(s) on the page.");
}

// --- the passive requestor endpoint ---------------------------------------
function passiveRequestor(req, res) {
  log.debug("Entering the WS-Federation passive requestor endpoint. method=" + req.method);
  const params = paramsOf(req);
  const wa = String(params.wa || '');

  // wct is the request's own timestamp (13.2.1). Recorded, not enforced: this
  // service has a KRB5_CLOCK_OFFSET to make a clock lie deliberately and nothing
  // equivalent here, so rejecting on skew would fail requests for a reason a
  // caller could not investigate.
  if (params.wct) {
    const skewSec = Math.round((Date.now() - Date.parse(String(params.wct))) / 1000);
    log.debug('wsfed: wct=' + params.wct + (isNaN(skewSec) ? ' (unparseable)'
                                                           : ' (' + skewSec + 's from this clock)'));
  }
  if (params.wp) {
    log.debug('wsfed: wp=' + params.wp + ' — a policy was named. Recorded; no policy is enforced here.');
  }
  if (params.wencoding) {
    log.debug('wsfed: wencoding=' + params.wencoding + ' — recorded. The parameters are read as ' +
              'ordinary form/query values whatever this says.');
  }

  if (!wa) {
    log.debug("Leaving the passive requestor endpoint. Describing itself.");
    return sendPage(res, 200, 'WS-Federation passive requestor endpoint', descriptionPage(baseUrlOf(req)));
  }
  if (wa === 'wsignin1.0') {
    signIn(req, res, params);
    log.debug("Leaving the passive requestor endpoint. wsignin1.0.");
    return;
  }
  if (wa === 'wsignout1.0') {
    signOut(req, res, params, false);
    log.debug("Leaving the passive requestor endpoint. wsignout1.0.");
    return;
  }
  if (wa === 'wsignoutcleanup1.0') {
    signOut(req, res, params, true);
    log.debug("Leaving the passive requestor endpoint. wsignoutcleanup1.0.");
    return;
  }
  if (wa === 'wattr1.0' || wa === 'wpseudo1.0') {
    log.debug("Leaving the passive requestor endpoint. " + wa + " is not implemented.");
    return wsfedError(res, 501, 'That service is not implemented',
      wa === 'wattr1.0'
        ? 'wattr1.0 is the attribute service (section 3.2/13.3): a relying party asking the identity ' +
          'provider for more claims about a subject it already has a token for. It is not implemented ' +
          'here, and it is named rather than silently rejected because "unknown wa" would send someone ' +
          'looking for a typo. Every claim this service has about a subject is already in the token: ' +
          'the name identifier, name, given name, surname, mail address, UPN, and how and when they ' +
          'authenticated.'
        : 'wpseudo1.0 is the pseudonym service (section 3.3/13.4), which issues a per-relying-party ' +
          'pseudonym for a subject. It is not implemented here. There would be nothing behind it: this ' +
          'service authenticates nobody and holds no per-relying-party state to map a pseudonym to.');
  }
  log.debug("Leaving the passive requestor endpoint. An unknown wa: " + wa);
  return wsfedError(res, 400, 'Unknown wa', 'This endpoint does not understand wa="' + wa + '".',
    '<h2>What it understands</h2><ul>' +
    '<li><code>wsignin1.0</code> — sign in, and get a token posted to wreply</li>' +
    '<li><code>wsignout1.0</code> — sign out, and send a cleanup request to each relying party</li>' +
    '<li><code>wsignoutcleanup1.0</code> — end the session without fanning out</li>' +
    '<li><code>wattr1.0</code>, <code>wpseudo1.0</code> — answered with 501 and an explanation</li>' +
    '</ul>');
}

// What GET /wsfed says when it is followed bare, which is what a reader clicking it
// from /sts-metadata does. GET /sts answers the same way for the same reason: an
// endpoint that 400s at a person who wanted to know what it was is a bad first
// impression of a service whose entire purpose is to be looked at.
function descriptionPage(base) {
  log.debug("Entering descriptionPage().");
  const inner = '<h1>WS-Federation 1.2 — passive requestor endpoint</h1>' +
    '<p class="sub">Issuer <code>' + xmlEscape(ISSUER) + '</code> at <code>' + xmlEscape(base) +
    PASSIVE_PATH + '</code></p>' +
    '<p>This endpoint takes a <code>wa</code> parameter, by GET or by form POST, and signs a browser ' +
    'in to a relying party by POSTing it a token (section 13.2.2). It authenticates nobody: the ' +
    'username typed at the screen becomes the subject of the assertion.</p>' +
    '<h2>Try it</h2><ul>' +
    '<li><a href="' + RP_PATH + '">' + RP_PATH + '</a> — a mock relying party here that sends a ' +
    'complete sign-in request and then verifies the response check by check.</li>' +
    '<li><a href="/FederationMetadata/2007-06/FederationMetadata.xml">' +
    '/FederationMetadata/2007-06/FederationMetadata.xml</a> — the signed federation metadata, ' +
    'which is what a relying party should be configured from.</li></ul>' +
    '<h2>Sign-in request parameters (section 13.2.1)</h2><table><thead><tr><th>Parameter</th>' +
    '<th>What this service does with it</th></tr></thead><tbody>' +
    [['wa', 'Required. <code>wsignin1.0</code>, <code>wsignout1.0</code> or ' +
            '<code>wsignoutcleanup1.0</code>.'],
     ['wtrealm', 'Required for sign-in. The relying party\'s identifier, and the assertion\'s ' +
                 'audience restriction.'],
     ['wreply', 'Where the response is POSTed. Optional — with none it goes to <code>' + RP_PATH +
                '</code>. Not validated against any registration, like every other return URL here.'],
     ['wctx', 'Echoed back byte for byte and never interpreted. It is the relying party\'s state.'],
     ['wct', 'The request timestamp. Recorded with its skew from this clock; not enforced.'],
     ['wfresh', 'The maximum age of the authentication, in MINUTES. 0 forces the screen; N re-shows ' +
                'it when the session authenticated longer than N minutes ago.'],
     ['wauth', 'The authentication method demanded. A password method is honoured; a multi-factor ' +
               'one is honoured only when the session really was established with a security key, ' +
               'and refused otherwise rather than answered with a claim that did not happen.'],
     ['whr', 'The home realm. Recorded and shown on the screen; this service is the only identity ' +
             'provider here, so nothing is forwarded.'],
     ['wreq', 'An RST by value. Its <code>TokenType</code> selects the token; an <code>AppliesTo</code> ' +
              'that disagrees with wtrealm is logged, and wtrealm wins.'],
     ['wreqptr', 'Refused. It names a URL for the identity provider to fetch, and fetching an ' +
                 'arbitrary URL from a query parameter is a server-side request forgery.'],
     ['wp, wencoding', 'Recorded in the log. No policy is enforced.'],
     ['tokenType, trust', 'NON-SPEC, in the manner of <code>/sts?encrypt=1</code>: ' +
      '<code>tokenType=saml2</code> asks for a SAML 2.0 assertion instead of the SAML 1.1 default, ' +
      'and <code>trust=1.3</code> wraps it in a ws-sx 200512 RSTR Collection instead of a 2005/02 ' +
      'RequestSecurityTokenResponse.']
    ].map(function (r) {
      return '<tr><td><code>' + r[0] + '</code></td><td>' + r[1] + '</td></tr>';
    }).join('') + '</tbody></table>' +
    '<div class="meta"><div>Not implemented, and stated rather than left to be discovered: ' +
    '<code>wresultptr</code> (the response is always by value), the attribute and pseudonym services ' +
    '(<code>wattr1.0</code>, <code>wpseudo1.0</code>, both answered 501), token encryption in this ' +
    'profile (there is no recipient certificate in a passive request to encrypt to — ' +
    '<code>/sts?encrypt=1</code> has one because a WS-Security signature carries it), and the ' +
    'WS-Federation metadata exchange over SOAP.</div></div>';
  log.debug("Leaving descriptionPage().");
  return inner;
}

app.get(PASSIVE_PATH, passiveRequestor);

// 13.2.1 allows the sign-in request as a form POST as well as a GET, and there is
// one thing to know about it: the session cookie is SameSite=Lax, so a POST from
// another origin does not carry it and this endpoint shows the screen even though a
// session exists. The alternative is SameSite=None, which requires Secure, which
// this service cannot be over http://localhost. See oauth2.js's startSession.
app.post(PASSIVE_PATH, passiveRequestor);

// --- federation metadata (section 3.1) -------------------------------------
// At AD FS's path, because that is where every relying party in this ecosystem
// looks and the specification names no path at all.
//
// It is SIGNED, and the signature goes FIRST inside EntityDescriptor — the SAML
// metadata schema puts ds:Signature at the head of the sequence, where an
// assertion puts it after the Issuer and a SAML 1.1 assertion puts it last. Three
// documents in this service, three positions, all schema-mandated.
//
// What is deliberately NOT in it: an IDPSSODescriptor. This service has no SAML 2.0
// Web SSO profile — no SingleSignOnService endpoint — and a role descriptor
// advertising one would be a relying party's first configuration attempt and its
// first 404.
function federationMetadata(base) {
  log.debug("Entering federationMetadata().");
  const id = genId();
  const claim = function (name, namespace, display, description) {
    return '<auth:ClaimType Uri="' + namespace + '/' + name + '" Optional="true">' +
      '<auth:DisplayName>' + xmlEscape(display) + '</auth:DisplayName>' +
      '<auth:Description>' + xmlEscape(description) + '</auth:Description></auth:ClaimType>';
  };
  const keyDescriptor = function (use) {
    return '<KeyDescriptor use="' + use + '"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
      '<ds:X509Data><ds:X509Certificate>' + STS.certB64 +
      '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>';
  };
  const endpoint = function (element, address) {
    return '<fed:' + element + '><wsa:EndpointReference><wsa:Address>' + xmlEscape(address) +
      '</wsa:Address></wsa:EndpointReference></fed:' + element + '>';
  };
  const xml =
    '<?xml version="1.0" encoding="UTF-8"?>' +
    '<EntityDescriptor xmlns="' + SAML_METADATA_NS + '" ID="' + id + '"' +
      ' entityID="' + xmlEscape(ISSUER) + '">' +
      '<RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' +
        ' xmlns:fed="' + WSFED_NS + '"' +
        ' xmlns:auth="' + WSFED_AUTH_NS + '"' +
        ' xmlns:wsa="http://www.w3.org/2005/08/addressing"' +
        ' xsi:type="fed:SecurityTokenServiceType"' +
        ' protocolSupportEnumeration="' + WSFED_NS + ' http://schemas.xmlsoap.org/ws/2005/02/trust">' +
        keyDescriptor('signing') +
        '<fed:TokenTypesOffered>' +
          '<fed:TokenType Uri="' + SAML11_TOKEN_TYPE + '"/>' +
          '<fed:TokenType Uri="' + SAML2_TOKEN_TYPE + '"/>' +
        '</fed:TokenTypesOffered>' +
        '<fed:ClaimTypesOffered>' +
          claim('nameidentifier', CLAIM_NS, 'Name ID', 'The subject identifier this service minted.') +
          claim('name', CLAIM_NS, 'Name', 'The username typed at the sign-in screen.') +
          claim('givenname', CLAIM_NS, 'Given name', 'Made up from the username.') +
          claim('surname', CLAIM_NS, 'Surname', 'Always "Mock".') +
          claim('emailaddress', CLAIM_NS, 'E-mail address', 'username@sts-mock.example.') +
          claim('upn', CLAIM_NS, 'UPN', 'The same string as the mail address.') +
          claim('authenticationmethod', MS_CLAIM_NS, 'Authentication method',
                'What the browser session actually did: a password, or multiple factors when a ' +
                'security key was used.') +
          claim('authenticationinstant', MS_CLAIM_NS, 'Authentication instant',
                'When that session authenticated.') +
        '</fed:ClaimTypesOffered>' +
        endpoint('SecurityTokenServiceEndpoint', base + '/sts') +
        endpoint('PassiveRequestorEndpoint', base + PASSIVE_PATH) +
      '</RoleDescriptor>' +
    '</EntityDescriptor>';
  logArtifact('WS-Federation metadata', 'before signing', xml);
  try {
    const sig = new SignedXml({ privateKey: STS.privateKeyPem, publicCert: STS.certPem });
    sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    sig.addReference({
      xpath: "/*[local-name(.)='EntityDescriptor']",
      transforms: [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#'
      ],
      digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
      uri: '#' + id
    });
    sig.computeSignature(xml, {
      location: { reference: "/*[local-name(.)='EntityDescriptor']", action: 'prepend' }
    });
    const signed = sig.getSignedXml();
    logArtifact('WS-Federation metadata', 'after signing', signed);
    log.debug("Leaving federationMetadata(). Signed.");
    return signed;
  } catch (e) {
    log.error('the federation metadata could not be signed, serving it unsigned: ' + e.message);
    log.debug("Leaving federationMetadata(). Unsigned.");
    return xml;
  }
}

app.get('/FederationMetadata/2007-06/FederationMetadata.xml', function (req, res) {
  log.debug("Entering the WS-Federation metadata endpoint.");
  const base = baseUrlOf(req);
  // no-store like every other document here that carries the signing key: the key
  // is regenerated on every start, so a cached copy describes a key that is gone
  // and the failure looks like a broken signature rather than a stale document.
  res.status(200).type('application/xml').set('Cache-Control', 'no-store')
     .send(federationMetadata(base));
  log.debug("Leaving the WS-Federation metadata endpoint.");
});

// ===========================================================================
// The mock relying party. NON-SPEC — a relying party is not part of an identity
// provider, and this one is here for two reasons that earn it:
//
//   * it is the default `wreply`, so a sign-in request that names no return
//     address has somewhere real to go instead of nowhere;
//   * it makes the profile testable from one service. Everything else here is
//     verified by the client under test; a sign-in response POSTed into the void
//     could not be checked at all without standing up a second service, and the
//     checks below are the ones that catch the mistakes this profile makes
//     (an unresolvable signature reference, a mangled wctx, an audience naming the
//     wrong realm).
//
// It is also the only thing in this service that VERIFIES a WS-Federation response,
// which makes it the counterpart of what /oid4vp/response is for presentations.
// ===========================================================================

// Whether the assertion's signature is this service's, resolved against the
// document it arrived in.
//
// The `idAttribute` argument is the whole reason this is a function and not three
// lines at the call site, and it has to be passed EXACTLY when it is needed and
// never otherwise. Both halves of that cost a debugging session:
//
//   * xml-crypto resolves a reference URI of "#x" by looking for an attribute named
//     Id, ID or id, and a SAML 1.1 assertion's is **AssertionID**. Without being
//     told, the reference resolves to nothing and a perfectly good signature reports
//     as broken — the shape of failure that makes people distrust a signature
//     library and hand-roll a worse check.
//   * but passing `idAttribute: 'ID'` for SAML 2.0, where it is already a default,
//     **unshifts a DUPLICATE onto that list**. xml-crypto then counts the one
//     matching element once per name and refuses the document with "multiple
//     elements with the same value for the ID / Id / Id attributes, in order to
//     prevent signature wrapping attack" — a security error, about a genuine attack,
//     naming a document that has nothing wrong with it. Symmetry between the two
//     call sites is what produced it: SAML 1.1 needs the argument, so SAML 2.0
//     looked like it needed the equivalent one, and it must have none.
function verifyAssertionSignature(xml, idAttribute) {
  log.debug("Entering verifyAssertionSignature(). idAttribute=" + (idAttribute || '(the defaults)'));
  try {
    const doc = new DOMParser().parseFromString(xml, 'text/xml');
    const sigEl = firstByLocal(doc, 'Signature');
    if (!sigEl) {
      log.debug("Leaving verifyAssertionSignature(). There is no ds:Signature.");
      return { ok: false, why: 'the assertion carries no ds:Signature at all' };
    }
    const options = { publicCert: STS.certPem };
    if (idAttribute) options.idAttribute = idAttribute;
    const sig = new SignedXml(options);
    sig.loadSignature(sigEl);
    const ok = sig.checkSignature(xml);
    log.debug("Leaving verifyAssertionSignature(). ok=" + ok);
    return { ok: !!ok, why: ok ? '' : 'the signature did not verify' };
  } catch (e) {
    // xml-crypto throws rather than returning false for most failures, and the
    // message names which of them it was — an unresolvable reference reads quite
    // differently from a digest mismatch, and that distinction is the diagnosis.
    log.debug("Leaving verifyAssertionSignature(). It threw: " + e.message);
    return { ok: false, why: e.message };
  }
}

// Every check, in the order a relying party would apply them, each with its own
// verdict. One boolean for the whole response would say "it failed" and nothing a
// person could act on, which is the same argument the OID4VP verifier makes.
function verifySignInResponse(params, realm) {
  log.debug("Entering verifySignInResponse().");
  const checks = [];
  const add = function (name, ok, detail) { checks.push({ name: name, ok: !!ok, detail: detail }); };
  const result = { checks: checks, subject: '', claims: [], tokenType: '', assertionVersion: '' };

  add('wa is wsignin1.0', String(params.wa || '') === 'wsignin1.0',
      'wa=' + (params.wa || '(none)'));
  const wresult = params.wresult ? String(params.wresult) : '';
  add('wresult is present', !!wresult,
      wresult ? wresult.length + ' characters' : 'nothing to verify');
  if (!wresult) {
    log.debug("Leaving verifySignInResponse(). There was no wresult.");
    return result;
  }

  let doc = null;
  try {
    doc = new DOMParser().parseFromString(wresult, 'text/xml');
  } catch (e) {
    // Kept as a failed check rather than thrown: the page's job is to report every
    // check, and "it is not XML" is a verdict like any other.
    add('wresult parses as XML', false, e.message);
    log.debug("Leaving verifySignInResponse(). wresult is not XML.");
    return result;
  }
  const rstr = firstByLocal(doc, 'RequestSecurityTokenResponse') ||
    (doc.documentElement && doc.documentElement.localName === 'RequestSecurityTokenResponse'
      ? doc.documentElement : null);
  add('wresult carries an RSTR', !!rstr,
      rstr ? 'in the ' + (rstr.namespaceURI || '(no)') + ' namespace' : 'no RequestSecurityTokenResponse');
  const tokenType = textByLocal(doc, 'TokenType');
  result.tokenType = tokenType;
  add('the RSTR names a token type', !!tokenType, tokenType || 'no t:TokenType');

  const assertion = firstByLocal(doc, 'Assertion');
  add('it contains an assertion', !!assertion,
      assertion ? 'in ' + assertion.namespaceURI : 'no saml:Assertion');
  if (!assertion) {
    log.debug("Leaving verifySignInResponse(). There is no assertion.");
    return result;
  }
  // SAML 1.1 and 2.0 are told apart by namespace, not by the TokenType the sender
  // claimed: the assertion is the thing that was signed, so it is the thing whose
  // own statement about itself counts.
  const isSaml11 = assertion.namespaceURI === 'urn:oasis:names:tc:SAML:1.0:assertion';
  result.assertionVersion = isSaml11 ? 'SAML 1.1' : 'SAML 2.0';

  // SAML 1.1's id attribute has to be named; SAML 2.0's must NOT be, because ID is
  // already one of the defaults and naming it again trips the wrapping-attack guard.
  const verdict = verifyAssertionSignature(wresult, isSaml11 ? 'AssertionID' : null);
  add('the assertion signature verifies against /sts/cert', verdict.ok,
      verdict.ok ? 'RSA-SHA256 over an exclusive canonicalization, resolved through ' +
                   (isSaml11 ? 'AssertionID' : 'ID')
                 : verdict.why);

  const issuer = isSaml11 ? (assertion.getAttribute('Issuer') || '') : textByLocal(assertion, 'Issuer');
  add('the issuer is this service', issuer === ISSUER, issuer || '(none)');

  const conditions = firstByLocal(assertion, 'Conditions');
  const audience = conditions ? textByLocal(conditions, 'Audience') : '';
  add('the audience is this relying party', audience === realm,
      'audience ' + (audience || '(none)') + ', expected ' + realm);

  const notBefore = conditions ? conditions.getAttribute('NotBefore') : '';
  const notOnOrAfter = conditions ? conditions.getAttribute('NotOnOrAfter') : '';
  const now = Date.now();
  const inWindow = !!notBefore && !!notOnOrAfter &&
    Date.parse(notBefore) <= now && now < Date.parse(notOnOrAfter);
  add('it is inside its validity window', inWindow,
      (notBefore || '(no NotBefore)') + ' to ' + (notOnOrAfter || '(no NotOnOrAfter)'));

  // The wctx round trip. Its own state, so this relying party is the only thing
  // that can check it — and an IdP that decoded and re-encoded it, or dropped it
  // for being long, produces exactly the same symptom as a lost session.
  const wctx = params.wctx ? String(params.wctx) : '';
  const known = rpContexts.get(wctx);
  add('wctx came back unaltered', !!known,
      known ? 'the same value this relying party minted, byte for byte'
            : (wctx ? 'this relying party did not mint "' + wctx + '" — it was altered, or this ' +
                      'response was not started from ' + RP_PATH
                    : 'no wctx came back'));
  if (known) rpContexts.delete(wctx);

  const nameEl = firstByLocal(assertion, 'NameIdentifier') || firstByLocal(assertion, 'NameID');
  result.subject = nameEl ? (nameEl.textContent || '').trim() : '';
  add('the assertion names a subject', !!result.subject, result.subject || '(none)');

  const attributes = assertion.getElementsByTagNameNS('*', 'Attribute');
  for (let i = 0; i < attributes.length; i++) {
    const a = attributes[i];
    // Two shapes, one list: SAML 1.1 splits the claim URI into a namespace and a
    // name, SAML 2.0 has it whole in Name.
    const uri = isSaml11
      ? (a.getAttribute('AttributeNamespace') || '') + '/' + (a.getAttribute('AttributeName') || '')
      : (a.getAttribute('Name') || '');
    const valueEl = firstByLocal(a, 'AttributeValue');
    result.claims.push({ uri: uri, value: valueEl ? (valueEl.textContent || '').trim() : '' });
  }
  add('the claims arrived', result.claims.length > 0, result.claims.length + ' claim(s)');

  result.ok = checks.every(function (c) { return c.ok; });
  log.debug("Leaving verifySignInResponse(). ok=" + result.ok + ", " + checks.length + " check(s).");
  return result;
}

app.get(RP_PATH, function (req, res) {
  log.debug("Entering the mock relying party (GET).");
  const base = baseUrlOf(req);
  const realm = base + RP_PATH;

  // A cleanup request arriving at the relying party, which is the direction
  // wsignoutcleanup1.0 is actually defined for. A real RP drops its own session
  // here; this one has none and says so rather than pretending.
  if (String(req.query.wa || '') === 'wsignoutcleanup1.0') {
    log.debug("Leaving the mock relying party. A cleanup request was received.");
    return sendPage(res, 200, 'Cleanup received — mock relying party',
      '<h1>Cleanup received</h1><div class="ok">This relying party was sent ' +
      '<code>wa=wsignoutcleanup1.0</code> and would drop its own session here.</div>' +
      '<p>It holds none: it verifies a sign-in response and shows it, and keeps nothing afterwards. ' +
      'The identity provider fetched this URL as a one-pixel image from its sign-out page, which is ' +
      'front-channel logout.</p><p><a href="' + RP_PATH + '">Start another sign-in</a></p>');
  }

  // A fresh wctx per attempt, held for half an hour so the round-trip check can be
  // made on the way back. This is the only state this relying party keeps.
  const wctx = 'rp-' + randomId(12);
  rpContexts.set(wctx, { realm: realm, expires: Date.now() + RP_CONTEXT_TTL_MS });
  rpContexts.forEach(function (v, k) { if (v.expires < Date.now()) rpContexts.delete(k); });

  const request = function (extra) {
    const usp = new URLSearchParams();
    usp.set('wa', 'wsignin1.0');
    usp.set('wtrealm', realm);
    usp.set('wreply', base + RP_PATH);
    usp.set('wctx', wctx);
    usp.set('wct', iso(0));
    Object.keys(extra || {}).forEach(function (k) { usp.set(k, extra[k]); });
    return PASSIVE_PATH + '?' + usp.toString();
  };
  const inner = '<h1>Mock relying party</h1>' +
    '<p class="sub">NON-SPEC. A relying party is not part of an identity provider — this one exists ' +
    'so the passive requestor profile can be exercised, and verified, without a second service.</p>' +
    '<p>Its realm is <code>' + xmlEscape(realm) + '</code>, and it is also the default ' +
    '<code>wreply</code>: a sign-in request that names no return address is POSTed here.</p>' +
    '<h2>Start a sign-in</h2><ul>' +
    '<li><a href="' + xmlEscape(request({})) + '">SAML 1.1 assertion in a 2005/02 RSTR</a> — the ' +
    'default, and what AD FS issues.</li>' +
    '<li><a href="' + xmlEscape(request({ tokenType: 'saml2' })) + '">SAML 2.0 assertion</a></li>' +
    '<li><a href="' + xmlEscape(request({ trust: '1.3' })) + '">SAML 1.1 in a ws-sx 200512 RSTR ' +
    'Collection</a> — the other wrapper a relying party may be given.</li>' +
    '<li><a href="' + xmlEscape(request({ wfresh: '0' })) + '">wfresh=0</a> — forces the sign-in ' +
    'screen even when a session already exists.</li>' +
    '<li><a href="' + xmlEscape(request({ wauth: AM_MULTIFACTOR })) + '">wauth=multipleauthn</a> — ' +
    'refused unless the browser session was established with a security key.</li>' +
    '</ul>' +
    '<h2>Then</h2><ul>' +
    '<li><a href="' + PASSIVE_PATH + '?wa=wsignout1.0&amp;wreply=' + encodeURIComponent(base + RP_PATH) +
    '">Sign out</a> — ends the session and sends a cleanup request to every relying party it signed ' +
    'into.</li>' +
    '<li><a href="/FederationMetadata/2007-06/FederationMetadata.xml">The federation metadata</a> ' +
    'this relying party would be configured from.</li></ul>' +
    '<div class="meta"><div>wctx for this attempt: <code>' + xmlEscape(wctx) + '</code>. It is ' +
    'checked on the way back, because an identity provider that decoded and re-encoded it produces ' +
    'the same symptom as a lost session.</div></div>';
  sendPage(res, 200, 'Mock relying party — WS-Federation', inner);
  log.debug("Leaving the mock relying party (GET).");
});

app.post(RP_PATH, function (req, res) {
  log.debug("Entering the mock relying party (POST).");
  const base = baseUrlOf(req);
  const realm = base + RP_PATH;
  const params = parseBody(req);
  logArtifact('WS-Federation sign-in response', 'as received by the mock relying party', params);
  const verdict = verifySignInResponse(params, realm);

  const rows = verdict.checks.map(function (c) {
    return '<tr><td>' + xmlEscape(c.name) + '</td><td class="' + (c.ok ? 'pass">PASS' : 'fail">FAIL') +
      '</td><td>' + xmlEscape(c.detail) + '</td></tr>';
  }).join('');
  const claimRows = verdict.claims.map(function (c) {
    return '<tr><td><code>' + xmlEscape(c.uri) + '</code></td><td>' + xmlEscape(c.value) + '</td></tr>';
  }).join('');
  const inner = '<h1>Sign-in response received</h1>' +
    '<p class="sub">Mock relying party at <code>' + xmlEscape(realm) + '</code> — POSTed to, not ' +
    'redirected to, which is the whole shape of this profile.</p>' +
    (verdict.ok
      ? '<div class="ok">Every check passed. ' + xmlEscape(verdict.assertionVersion) +
        ' assertion for <code>' + xmlEscape(verdict.subject) + '</code>.</div>'
      : '<div class="err">Not every check passed. Each one below says which, and why — a single ' +
        'verdict for the whole response would say "it failed" and nothing anybody could act on.</div>') +
    '<h2>Checks</h2><table><thead><tr><th>Check</th><th>Verdict</th><th>Detail</th></tr></thead>' +
    '<tbody>' + rows + '</tbody></table>' +
    (claimRows
      ? '<h2>Claims</h2><table><thead><tr><th>Claim URI</th><th>Value</th></tr></thead><tbody>' +
        claimRows + '</tbody></table>'
      : '') +
    '<h2>wresult, as it arrived</h2><pre>' + xmlEscape(params.wresult || '(none)') + '</pre>' +
    '<p><a href="' + RP_PATH + '">Start another sign-in</a> &middot; ' +
    '<a href="' + PASSIVE_PATH + '?wa=wsignout1.0&amp;wreply=' + encodeURIComponent(base + RP_PATH) +
    '">Sign out</a></p>' +
    '<div class="meta"><div>This relying party keeps no session. It verifies what it was sent and ' +
    'shows it, which is all a mock relying party can honestly claim to do.</div></div>';
  // 200 whatever the verdict: the POST was answered, and the verdict is the
  // document. A 400 here would be this relying party reporting on the identity
  // provider's behaviour with a status code the browser attributes to itself.
  sendPage(res, 200, 'Sign-in response — mock relying party', inner);
  log.debug("Leaving the mock relying party (POST). ok=" + verdict.ok);
});

module.exports = {
  SAML11_TOKEN_TYPE: SAML11_TOKEN_TYPE,
  SAML2_TOKEN_TYPE: SAML2_TOKEN_TYPE,
  federationMetadata: federationMetadata,
  verifySignInResponse: verifySignInResponse,
  verifyAssertionSignature: verifyAssertionSignature
};
