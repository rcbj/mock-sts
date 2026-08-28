'use strict';
//
// File: federation_sp.js
//
// ===========================================================================
// THIS SERVICE AS A SERVICE PROVIDER: CONSUMING WHAT SOMEBODY ELSE ISSUED.
//
//   GET  /federation                 what all of this is, and every configured
//                                    relationship, for somebody who clicked the
//                                    link.
//   GET  /federation/login/{id}      START. Sends the browser to the partner —
//                                    an <AuthnRequest> on a binding, an
//                                    inter-site transfer URL, wa=wsignin1.0, or
//                                    an OAuth 2.0 authorization request.
//   GET|POST /federation/acs/{id}    FINISH. The assertion consumer service,
//                                    the WS-Federation wreply and the OAuth 2.0
//                                    redirect_uri, all on one path — see
//                                    decision 2.
//   GET  /federation/metadata/{id}   THIS SERVICE'S OWN SAML metadata for that
//                                    partner, so the partner can be configured
//                                    without anybody typing five URLs.
//
// ---------------------------------------------------------------------------
// THIS IS THE MODULE WHERE THE SERVICE'S USUAL POSTURE IS INVERTED, AND EVERY
// REFUSAL IN IT IS DELIBERATE.
//
// Everywhere else here, a check that fails is a check this service chose to
// make and could have skipped: `/oauth2/token` mints a token for any username,
// `/saml2/sso` answers any entityID, every LDAP bind succeeds. Read this file
// expecting that and every refusal below looks like something to relax.
//
// It is the opposite. **What arrives at `/federation/acs/{id}` is an
// unauthenticated HTTP request that claims to be a person.** The only thing
// separating "alice signed in at the partner" from "somebody POSTed some XML"
// is the signature check against `fedSigningCertificate`, and the session that
// comes out of it is the SAME session `/oauth2/authorize`, `/wsfed`, `/saml2`
// and `/admin` all read. A permissive version of this endpoint is not a
// permissive mock — it is an authentication bypass for every protocol in the
// process.
//
// So: **nothing here is skipped, and nothing here is configurable to be
// skipped.** Where a check CAN be relaxed it is a per-relationship attribute
// with its own name and its own sentence on the page (`fedAllowUnsolicited` is
// the only one), never a global setting and never a default.
//
// ---------------------------------------------------------------------------
// SIX DECISIONS THAT ARE NOT OBVIOUS FROM THE SPECIFICATIONS.
//
// 1. **THE PERSON IS AUTHENTICATED THROUGH `authn.js`, NOT HERE.** This module
//    never writes a session cookie. It ends by calling `authn.startSession()`,
//    the same function the sign-in screen calls, which is what makes a
//    federated identity work in every protocol this service speaks without any
//    of them being told federation exists. A session store of this module's own
//    would have been the second store this repository refuses everywhere else,
//    and it would have been the one `/admin/users` could not see.
//
//    The consequence worth stating: a federated sign-in produces a session with
//    `amr` naming what the PARTNER said it did, not what this service did —
//    this service did nothing. Where the partner said nothing, the amr is
//    `["federated"]`, which is not an RFC 8176 value and deliberately is not
//    one: inventing `pwd` because a partner probably used a password would put
//    a factor in a token that nobody performed.
//
// 2. **ONE PATH RECEIVES ALL FIVE PROTOCOLS, and it is `/federation/acs/{id}`.**
//    A SAML assertion consumer service, a WS-Federation `wreply` and an OAuth
//    2.0 `redirect_uri` are three names for "where the answer comes back", and
//    the relationship id in the path already says which protocol is expected.
//    Five paths would mean five URLs to configure at the partner and four ways
//    to configure the wrong one — and the failure of configuring the wrong one
//    is a 404 in a browser after a successful sign-in somewhere else, which is
//    the least diagnosable failure this feature could have.
//
// 3. **THE REQUEST CONTEXT IS SERVER-SIDE AND THE PARTNER CARRIES ONLY A
//    HANDLE.** `RelayState`, `wctx` and `state` all carry one opaque id, and
//    everything about the flow — the `<AuthnRequest>` ID an assertion must
//    answer, the OAuth `nonce`, the PKCE verifier, and WHERE THE PERSON WAS
//    GOING — lives in a Map here. Putting the return URL in the parameter
//    instead would be an open redirect operated by whoever can forge a
//    RelayState, which is everybody.
//
// 4. **THE RETURN IS ALWAYS A PATH ON THIS SERVICE.** `returnTo` is validated
//    the way `authn.beginAuthentication()` validates its own — it must start
//    with a single `/` — and it is stored server-side besides. Both, because
//    they fail differently: the check catches a caller's bug and the storage
//    catches an attacker.
//
// 5. **THE ID TOKEN IS VERIFIED WITH THE RELATIONSHIP'S KEYS AND NOTHING
//    ELSE.** No `alg: none`, no HMAC where an RSA key was configured, no
//    unverified decode used for anything but choosing WHICH key. That last one
//    is `client_auth.js`'s rule about an unverified `sub` and it is the same
//    rule: an unverified value may SELECT, it may never ESTABLISH.
//
// 6. **A FAILURE IS SHOWN, RECORDED AND NOT REDIRECTED.** Every refusal draws a
//    page naming the check that failed and writes `fedLastError` on the
//    relationship. It does NOT bounce the browser back to wherever it came from
//    with an error parameter — the person's sign-in has already succeeded at
//    the partner, so the interesting question is entirely "what did this
//    service dislike about the answer", and that question is unanswerable from
//    a redirect that has thrown the detail away.
//
// ---------------------------------------------------------------------------
// WHERE IT SITS IN THE REQUIRE ORDER (rule 1).
//
// **AFTER `authn/authn.js`**, and it is the same dependency `saml2_sso.js` has
// and stronger than WS-Federation's: it has no sign-in screen of its own and it
// calls `startSession()` directly. It must also be after `common/applications.js`
// is loadable, which it is everywhere, and it requires `federation.js`,
// `federation_map.js` and `federation_http.js` — all three libraries that
// register nothing.
//
// It does NOT require `ldap_server.js` and must never: that module is near the
// end of the order because requiring it pulls every `/ldap` route into the
// router, and this module's routes would then sit behind them. The directory
// is reached the way every other module reaches it — through the identity
// funnel, which this module gets to by way of `authn.startSession()` rather
// than by calling `stats.recordAuthentication()` itself. That is not merely
// tidiness: calling both produced TWO authentication records for one federated
// sign-in, which is what `startSession()`'s sixth argument exists to prevent.
// ===========================================================================

const crypto = require('crypto');
const zlib = require('zlib');
const jwt = require('jsonwebtoken');
const { DOMParser } = require('@xmldom/xmldom');
// One signer and one verifier for the whole service since 2026-08-27.
const stsCrypto = require('../common/crypto');

const app = require('./../common/app');
const config = require('./../common/config');
const applications = require('./../common/applications');
const authn = require('./../authn/authn');
const federation = require('./federation');
const fedMap = require('./federation_map');
const fedHttp = require('./federation_http');
// For the context store below only. `realms.js` requires config.js and nothing
// else here, so it registers no route and cannot join a cycle — rule 3m.
const realms = require('./../common/realms');
const {
  log, logArtifact, STS, xmlEscape, firstByLocal, textByLocal, iso, baseUrlOf,
  jsonFromB64u, randomId, parseBody
} = require('./../common/helpers');

// READ FROM THE REGISTER rather than written here, and the header of PATHS over
// there says why: the console has to print these URLs and may not require this
// module, so one copy in the library both sides reach is the only arrangement
// in which the page and the router cannot disagree.
const BASE_PATH = federation.PATHS.base;
const LOGIN_PATH = federation.PATHS.login;
const ACS_PATH = federation.PATHS.acs;
const METADATA_PATH = federation.PATHS.metadata;

const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
const NS_SAMLP11 = 'urn:oasis:names:tc:SAML:1.0:protocol';
const BINDING_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
const BINDING_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

// ---------------------------------------------------------------------------
// THE REQUEST CONTEXTS. See decision 3.
//
// Keyed by the handle that rides on RelayState / wctx / state. Capped and swept
// on every write, because the key is minted here but the MAP is written to by
// anybody who can reach `/federation/login/{id}` — which, unlike the rest of
// this module, needs no configuration at all to reach.
// ---------------------------------------------------------------------------
//
// PER TRUST REALM since 2026-08-25. A relationship is an entry in the realm's
// own `ou=federations` and `/federation/acs/{id}` verifies against the
// certificate configured on it, so a context minted while `acme` was ambient
// being spendable at the DEFAULT realm's assertion consumer service would let a
// flow that began in one realm finish in another — on the one surface here
// where a missing check is an authentication bypass rather than a fidelity bug.
// Nothing legitimate crossed: a handle is minted and spent inside one flow, and
// a flow carries its realm in every URL it uses.
//
// THE CAP IS NOW PER REALM, which is the one thing to weigh rather than assume:
// MAX_CONTEXTS in flight in each realm rather than 500 for the process. That is
// deliberate — the cap is here so that anybody who can reach
// `/federation/login/{id}` cannot grow this map without limit, and a shared cap
// would have let one realm's flood evict another realm's in-flight sign-ins,
// which is the denial of service the cap exists to bound arriving through the
// door it was meant to close.
const contexts = realms.map();
const MAX_CONTEXTS = 500;

// The longest `application` a context will carry. A client_id has no length
// limit in any specification this service implements, and this value is written
// into a directory attribute at the far end — so it is bounded where it is
// accepted rather than where it is spent. It is generous: the longest identifier
// anything here files an application under is a SAML entityID, which is a URL.
const MAX_APPLICATION_LEN = 256;

function contextTtlMs() {
  return config.value('federation.requestTtlMin') * 60 * 1000;
}

function putContext(record) {
  log.debug('Entering putContext().');
  const handle = 'fed-' + randomId(18);
  const now = Date.now();
  contexts.forEach(function (value, key) {
    if (value.expires < now) contexts.delete(key);
  });
  if (contexts.size >= MAX_CONTEXTS) {
    // The OLDEST goes, and it is a sweep rather than a refusal because the
    // alternative is a login endpoint anybody can reach that stops working for
    // everybody once it is hit enough times. What is lost is one person's
    // in-flight sign-in, which fails as an unsolicited response and says so.
    let oldestKey = null;
    let oldestAt = Infinity;
    contexts.forEach(function (value, key) {
      if (value.startedAt < oldestAt) { oldestAt = value.startedAt; oldestKey = key; }
    });
    if (oldestKey) {
      contexts.delete(oldestKey);
      log.warn('federation: ' + MAX_CONTEXTS + ' sign-ins are in flight, so the oldest ' +
               'was dropped. Whoever it belonged to will be told their response was ' +
               'unsolicited, which is the truth as far as this service can tell.');
    }
  }
  contexts.set(handle, Object.assign({ handle: handle, startedAt: now,
                                       expires: now + contextTtlMs() }, record));
  log.debug('Leaving putContext(). handle=' + handle + ', ' + contexts.size + ' in flight.');
  return handle;
}

// ---------------------------------------------------------------------------
// WHAT A COMPLETED SIGN-IN NEEDS OFF THE REQUEST CONTEXT, in one place.
//
// FIVE call sites build the result `completeSignIn()` is handed — one per
// protocol, plus OAuth 2.0's two ways of learning who somebody is — and each of
// them reads these fields off the context it holds. They were five copies of
// `returnTo: (context && context.returnTo) || ''` until `application` joined it,
// at which point the shape of the mistake became obvious: a sixth field, or a
// sixth protocol, is five places to remember and one to forget. A federated
// sign-in that succeeds and lands somebody on a page nobody asked for is what a
// dropped `returnTo` looks like; a dropped `application` is a count on
// /admin/federation/map that is quietly short.
//
// A MISSING CONTEXT IS NOT AN ERROR HERE. The SAML 1.1 unsolicited case has no
// context at all (`fedAllowUnsolicited`), so both fields are empty and both
// callers already behave correctly for that: the person lands on this service's
// own "signed in" page, and no pair is counted because nothing said what the
// sign-in was for.
// ---------------------------------------------------------------------------
function fromContext(context) {
  return {
    returnTo: (context && context.returnTo) || '',
    application: (context && context.application) || ''
  };
}

// Read AND SPEND. A context is good for one response, which is what makes a
// replayed assertion fail the second time even where the partner's own replay
// window has not closed. The SAML 1.1 case is the one that has no context at
// all — see `fedAllowUnsolicited` — and it is handled by the caller rather than
// by pretending there was one.
function takeContext(handle) {
  log.debug('Entering takeContext(). handle=' + (handle || '(none)'));
  const record = contexts.get(String(handle || ''));
  if (!record) {
    log.debug('Leaving takeContext(). No such context.');
    return null;
  }
  contexts.delete(record.handle);
  if (record.expires < Date.now()) {
    log.debug('Leaving takeContext(). It had expired.');
    return null;
  }
  log.debug('Leaving takeContext(). Found it.');
  return record;
}

function enabled() {
  return !!config.value('federation.enabled');
}

// ---------------------------------------------------------------------------
// PAGES. This module draws two: a refusal and an index. Both are plain HTML
// with no script — `app.js` sets `script-src 'none'` for the whole service and
// nothing here is the exception that needs relaxing, because the one page that
// posts a form (the outbound HTTP-POST binding) is a REAL form with a real
// submit button and no script at all.
//
// THAT IS THE DIFFERENCE FROM THE FIVE SCRIPTED PAGES elsewhere here, and it is
// worth the sentence so nobody adds a sixth by analogy: those five auto-submit
// because the person has already decided and a click would be ceremony. This
// one is a person LEAVING THIS SERVICE for a foreign identity provider, which
// is exactly the moment a deliberate click is worth having — and it means the
// federation feature adds no CSP relaxation anywhere.
// ---------------------------------------------------------------------------
const STYLE = 'body{font-family:system-ui,Segoe UI,Helvetica,Arial,sans-serif;margin:2rem auto;' +
  'max-width:52rem;line-height:1.5;color:#111}h1{font-size:1.4rem}h2{font-size:1.05rem;' +
  'margin-top:1.6rem}code{background:#f4f4f5;padding:.1rem .3rem;border-radius:3px;' +
  'word-break:break-all}table{border-collapse:collapse;width:100%;margin:.6rem 0}' +
  'th,td{border:1px solid #ddd;padding:.35rem .5rem;text-align:left;font-size:.9rem;' +
  'vertical-align:top}th{background:#fafafa}.bad{color:#a00;font-weight:600}' +
  '.ok{color:#060}.note{color:#555;font-size:.9rem}button{font:inherit;padding:.5rem 1rem;' +
  'border:1px solid #333;background:#111;color:#fff;border-radius:4px;cursor:pointer}' +
  'ul{padding-left:1.2rem}';

function page(title, body) {
  return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>' + xmlEscape(title) + '</title><style>' + STYLE + '</style></head><body>' +
    body + '</body></html>';
}

// A refusal, and it does three things every time: it draws the reason, it
// writes `fedLastError` on the relationship, and it answers a status code a
// test can assert on. See decision 6 — it never redirects.
function refuse(res, record, status, what, why, extra) {
  log.debug('Entering refuse(). what=' + what);
  const id = (record && record.fedId) || '';
  if (id) federation.recordFailure(id, what + ': ' + why);
  const body = '<h1>The federated sign-in was refused</h1>' +
    '<p class="bad">' + xmlEscape(what) + '</p>' +
    '<p>' + xmlEscape(why) + '</p>' +
    (extra || '') +
    (id ? '<p class="note">This is recorded on the relationship as ' +
          '<code>fedLastError</code>. The whole record is at ' +
          '<a href="/admin/federation?relationship=' + encodeURIComponent(id) + '">' +
          '/admin/federation</a>, and every refusal is also a row in the audit log.</p>'
        : '') +
    '<p class="note"><strong>This service refuses rather than accepting here, which is the ' +
    'opposite of what it does everywhere else.</strong> What arrives at this endpoint is an ' +
    'unauthenticated request claiming to be a person, and the session it would produce is the ' +
    'one every other protocol in this process reads. See federation/CLAUDE.md.</p>' +
    '<p><a href="' + BASE_PATH + '">Back to the federation index</a></p>';
  res.status(status).type('html').set('Cache-Control', 'no-store').send(page('Refused', body));
  log.debug('Leaving refuse(). ' + status + '.');
}

// ---------------------------------------------------------------------------
// WHAT THIS SERVICE CALLS ITSELF TO A PARTNER.
//
// One function, because the same string is the SAML `<Issuer>` of an outbound
// AuthnRequest, the `Audience` an inbound assertion must name, the
// WS-Federation `wtrealm` and the OAuth `client_id` fallback — and four
// spellings of it would be four things a partner had to be configured with.
//
// It is PER RELATIONSHIP rather than one constant, which is the same decision
// `saml2.perApplicationEntityId` makes in the other direction and for the same
// reason: a partner keying its trust store off an entityID must be able to be
// given one that is only ours-with-them.
// ---------------------------------------------------------------------------
function ourEntityId(base, record) {
  return base + ACS_PATH + '/' + encodeURIComponent(record.fedId);
}

function acsUrl(base, record) {
  return base + ACS_PATH + '/' + encodeURIComponent(record.fedId);
}

// ---------------------------------------------------------------------------
// THE PARTNER'S CERTIFICATE AS A PEM.
//
// `fedSigningCertificate` holds base64 DER, which is what a
// `<ds:X509Certificate>` carries and what `samlSigningCertificate` on an
// application entry holds — one spelling across this service. xml-crypto wants
// a PEM, so this is the one conversion, in one place: two call sites doing it
// inline is two chances to wrap at 63 characters instead of 64, which produces
// a key that parses and verifies nothing.
// ---------------------------------------------------------------------------
function certPemOf(record) {
  log.debug('Entering certPemOf().');
  const der = String(record.fedSigningCertificate || '').replace(/\s+/g, '');
  if (!der) {
    log.debug('Leaving certPemOf(). There is none configured.');
    return '';
  }
  const wrapped = der.replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  log.debug('Leaving certPemOf(). ' + der.length + ' base64 characters.');
  return '-----BEGIN CERTIFICATE-----\n' + wrapped + '\n-----END CERTIFICATE-----\n';
}

// ---------------------------------------------------------------------------
// VERIFYING AN XML SIGNATURE MADE BY SOMEBODY ELSE.
//
// **THIS IS A POLICY WRAPPER OVER `common/crypto.js`, AND THE POLICY IS THE
// PART THAT MATTERS.** The mechanics — which id spellings resolve, which
// canonicalization, which signature belongs to which element — are the shared
// verifier's and are the same everywhere. What is decided HERE is what makes
// this door different from every other one in the service: no configured
// certificate means nothing is accepted, and the certificate is always the
// relationship's rather than the document's.
//
// This comment used to explain an `idAttribute` argument that had to be passed
// for SAML 1.1 and withheld for SAML 2.0, because symmetry between the two call
// sites produced a signature-wrapping error on a perfectly good document. That
// argument no longer exists; `saml/CLAUDE.md` keeps the story.
//
// **THE KEY IS THE CONFIGURED ONE AND ONLY THE CONFIGURED ONE.** `publicCert`
// is passed explicitly, so a signature carrying its own `<ds:KeyInfo>` with a
// certificate inside it is verified against OUR copy and not against the one
// it brought — which is the difference between a signature check and a
// decoration. That is the single most important line in this module.
// ---------------------------------------------------------------------------
function verifyXmlSignature(xml, record, wanted) {
  log.debug('Entering verifyXmlSignature(). wanted=' + wanted);
  const pem = certPemOf(record);
  if (!pem) {
    // **THE ONE REFUSAL IN THIS SERVICE THAT IS NOT A MODE**, and it stays here
    // rather than moving into the shared verifier: `common/crypto.js` answers
    // "does this signature verify against this key", and "there is no key
    // configured, so nothing is accepted" is a FEDERATION policy about a
    // relationship. See `federation/CLAUDE.md` — the gate is on the SIGNER, and
    // a permissive answer here would be an authentication bypass for every
    // protocol in the process.
    log.debug('Leaving verifyXmlSignature(). No certificate is configured.');
    return { ok: false, present: false,
             why: 'no fedSigningCertificate is configured on this relationship, so there ' +
                  'is nothing to verify the signature against. Nothing is accepted until ' +
                  'there is' };
  }
  // **THE PARTNER'S OWN <ds:KeyInfo> CERTIFICATE IS NEVER USED, AND PASSING
  // `certPem` IS WHAT ENSURES IT.** The shared verifier falls back to the
  // certificate inside the document when it is given no other — which is
  // correct for a general-purpose tool and would be the whole hole here, since
  // anybody can sign an assertion and attach the key that verifies it. This
  // call always passes the certificate configured on the RELATIONSHIP, so the
  // fallback is unreachable from this door.
  //
  // The `idAttribute` argument that used to be threaded through three call
  // sites is gone: SAML 1.1's `AssertionID` and SAML 2.0's `ID` are both
  // resolved from the document by the verifier, so a partner's version is no
  // longer something this file has to work out in advance and pass down.
  const result = stsCrypto.verifyXmlSignature(xml, {
    element: wanted,
    certPem: pem
  });
  log.debug('Leaving verifyXmlSignature(). ok=' + result.ok);
  return {
    ok: result.ok,
    present: result.present,
    why: result.ok ? ''
      : (result.why || 'the signature did not verify against fedSigningCertificate')
  };
}

// ---------------------------------------------------------------------------
// ONE SAML ASSERTION'S CONTENTS, 2.0 and 1.1 alike.
//
// The two versions differ in three places and nowhere else that matters here:
// the subject is `<NameID>` or `<NameIdentifier>`, an attribute's name is
// `Name` or `AttributeName`, and 1.1 splits the name into a namespace and a
// local part. All three are handled here rather than in two extractors,
// because the shape that comes OUT is the same bag either way and two
// extractors would be two chances to spell a bag member differently.
// ---------------------------------------------------------------------------
function assertionContents(assertion) {
  log.debug('Entering assertionContents().');
  const out = { subject: '', nameFormat: '', bag: {}, authnInstant: '', context: '' };
  const nameEl = firstByLocal(assertion, 'NameID') || firstByLocal(assertion, 'NameIdentifier');
  if (nameEl) {
    out.subject = (nameEl.textContent || '').trim();
    out.nameFormat = nameEl.getAttribute('Format') || nameEl.getAttribute('Format') || '';
  }
  const authn = firstByLocal(assertion, 'AuthnStatement') ||
    firstByLocal(assertion, 'AuthenticationStatement');
  if (authn) {
    out.authnInstant = authn.getAttribute('AuthnInstant') ||
      authn.getAttribute('AuthenticationInstant') || '';
    out.context = textByLocal(authn, 'AuthnContextClassRef') ||
      authn.getAttribute('AuthenticationMethod') || '';
  }
  const attributes = assertion.getElementsByTagName('*');
  for (let i = 0; i < attributes.length; i++) {
    const el = attributes[i];
    if (el.localName !== 'Attribute') continue;
    // SAML 1.1 splits the name. The two halves are joined with a `/` where the
    // namespace does not already end in one, which is how AD FS spells its own
    // claim URIs and therefore how the default map's WS-Federation rows are
    // written — a namespace and a name kept apart would match nothing.
    const namespace = el.getAttribute('AttributeNamespace') || '';
    const local = el.getAttribute('Name') || el.getAttribute('AttributeName') || '';
    if (!local) continue;
    const name = namespace
      ? (namespace.charAt(namespace.length - 1) === '/' ? namespace + local
                                                        : namespace + '/' + local)
      : local;
    const values = [];
    const children = el.getElementsByTagName('*');
    for (let j = 0; j < children.length; j++) {
      if (children[j].localName !== 'AttributeValue') continue;
      const text = (children[j].textContent || '').trim();
      if (text) values.push(text);
    }
    if (!values.length) continue;
    out.bag[name] = (out.bag[name] || []).concat(values);
  }
  log.debug('Leaving assertionContents(). subject=' + out.subject + ', ' +
            Object.keys(out.bag).length + ' attribute(s).');
  return out;
}

// The validity window, as a check with a sentence. `Conditions` is optional in
// both versions and an assertion with none is ACCEPTED — refusing it would
// refuse a perfectly ordinary AD FS assertion — but the fact is reported rather
// than hidden, because "this assertion can never expire" is worth knowing.
function conditionsCheck(assertion) {
  log.debug('Entering conditionsCheck().');
  const conditions = firstByLocal(assertion, 'Conditions');
  if (!conditions) {
    log.debug('Leaving conditionsCheck(). There are none.');
    return { ok: true, why: 'the assertion carries no <Conditions>, so it states no ' +
                            'validity window at all and nothing here can expire it' };
  }
  const notBefore = conditions.getAttribute('NotBefore') || '';
  const notOnOrAfter = conditions.getAttribute('NotOnOrAfter') || '';
  const now = Date.now();
  // The same allowance this service applies to its own tokens, for the reason
  // oauth-oidc/CLAUDE.md gives about clockSkewS: an assertion refused thirty
  // seconds early because two machines disagree reads as a broken federation
  // from both ends. It is the SAME setting rather than a second one, because a
  // deployment that has decided how far out its clock may be has decided it
  // once.
  const skew = config.value('oauth2.clockSkewS') * 1000;
  if (notBefore && Date.parse(notBefore) - skew > now) {
    log.debug('Leaving conditionsCheck(). Not yet valid.');
    return { ok: false, why: 'the assertion is not valid until ' + notBefore +
                             ', which is in the future even allowing ' +
                             config.value('oauth2.clockSkewS') + 's of clock skew' };
  }
  if (notOnOrAfter && Date.parse(notOnOrAfter) + skew <= now) {
    log.debug('Leaving conditionsCheck(). Expired.');
    return { ok: false, why: 'the assertion expired at ' + notOnOrAfter +
                             ' (allowing ' + config.value('oauth2.clockSkewS') +
                             's of clock skew). A partner and this service disagreeing ' +
                             'about the time is the usual cause; the other is a replay' };
  }
  log.debug('Leaving conditionsCheck(). Inside its window.');
  return { ok: true, why: (notBefore || '(no NotBefore)') + ' to ' +
                          (notOnOrAfter || '(no NotOnOrAfter)') };
}

// ---------------------------------------------------------------------------
// THE END OF EVERY SUCCESSFUL FLOW, whichever protocol got here.
//
// ONE function, and that is the whole reason the five protocol branches above
// it are as thin as they are: the mapping, the directory entry, the counters,
// the audit trail and the session are the same five acts in every protocol, and
// five copies of them would be five subtly different federated sign-ins.
//
// THE ORDER MATTERS AND IS NOT ARBITRARY:
//
//   1. map, so the username exists before anything is filed under it;
//   2. `recordAuthentication()`, which is the funnel that seeds the directory
//      entry AND carries the mapped attributes to it — a credential has been
//      ACCEPTED by the time this line runs, which is the rule that funnel
//      documents;
//   3. the relationship's counters;
//   4. the application record for the partner, so `/admin/applications` knows
//      the foreign identity provider exists;
//   5. the session, LAST, because it is the thing that has an effect outside
//      this process and everything above it is a record of why.
// ---------------------------------------------------------------------------
// ONE KIND FOR ALL FIVE PROTOCOLS, and it is a ROW ADDED TO `applications.js`'s
// KINDS rather than a reuse of one that was already there.
//
// The first version of this mapped each protocol onto the nearest existing
// kind — a SAML 2.0 partner became a `saml2-service-provider`, an OIDC one an
// `oauth2-client` — which was wrong in the way that is hardest to notice: every
// page drew it correctly, and every one of them said the foreign identity
// provider was a CLIENT of this service. It is the opposite. That list is
// closed on purpose, and its header says a kind outside it is recorded with a
// warning; the sanctioned way to say something new is a row, so there is one.
//
// The PROTOCOL is not lost by collapsing the five: it goes on the same record
// as `appProtocol`, which is where every other party's protocol goes.
const PARTNER_KIND = 'federation-identity-provider';

function completeSignIn(req, res, record, result) {
  log.debug('Entering completeSignIn(). id=' + record.fedId);
  const mapped = fedMap.mapIncoming(record, result.bag, result.subject);
  if (!mapped.username) {
    log.debug('Leaving completeSignIn(). There is no username.');
    return refuse(res, record, 400, 'The partner named nobody',
                  'The assertion verified, but nothing in it could be read as a username: ' +
                  (record.fedUsernameSource
                    ? 'this relationship takes the username from "' + record.fedUsernameSource +
                      '", which was not sent, and there was no subject either'
                    : 'it carried no subject, and no fedUsernameSource is configured to ' +
                      'take one from an attribute instead'),
                  bagTable(result.bag));
  }
  const protocolLabel = (federation.protocolRow(record.fedProtocol) || {}).label ||
    record.fedProtocol;
  const via = 'Federation (' + protocolLabel + ')';
  // What the PARTNER said it did. See decision 1: `federated` is not an RFC
  // 8176 value and deliberately is not one.
  const amr = result.amr && result.amr.length ? result.amr : ['federated'];

  // WHAT THE FUNNEL IS TOLD, and it goes through `startSession()` rather than
  // through a `stats.recordAuthentication()` call of its own. That was written
  // the other way round first and produced TWO authentication records for one
  // federated sign-in — /admin/users counted every arrival twice and the audit
  // log carried a duplicate of each — because `startSession()` has always
  // recorded the authentication itself. See its sixth argument, where the
  // reasoning is written down.
  const detail = {
    // No indefinite article: "a OpenID Connect" and "an SAML 2.0" are both
    // wrong, and picking between them by first letter gets both of those wrong
    // too — the article follows the SOUND, and three of the five labels are
    // initialisms. federation.js's create() note is phrased around the same
    // problem.
    method: protocolLabel + ' assertion from ' + (record.fedPeer || record.fedId) +
            ', verified against this relationship\'s configured key',
    sub: result.subject,
    // NO `client_id`. It was here first and was a real bug: the identity funnel
    // passes `client_id` to `applications.recordAuthentication()`, which filed
    // the foreign identity provider as an `oauth2-client` — so the partner's
    // registry entry carried a kind saying it was a client OF this service,
    // which is precisely backwards. The partner is recorded below, once,
    // through `applications.seen()`, under a kind that says what it is.
    summary: mapped.username + ' was signed in through the federation relationship "' +
             record.fedId + '"; this service checked no credential of theirs and verified ' +
             (record.fedPeer || 'the partner') + '\'s signature',
    note: 'No credential was checked HERE — the partner authenticated this person and ' +
          'this service verified the partner\'s signature. That is the one thing this ' +
          'service does check.',
    // The mapped attributes, riding on the funnel to the directory. It is a
    // field on the existing observer payload rather than a sixth slot, which is
    // exactly what `certificate` and `linkedTo` already are — see rule 3e's
    // test, which this passes because nothing new points anywhere new.
    federation: {
      id: record.fedId,
      peer: record.fedPeer || '',
      protocol: record.fedProtocol,
      protocolLabel: protocolLabel,
      subject: result.subject,
      autocreate: federation.boolOf(record.fedAutocreateUsers, true),
      attributes: mapped.attributes,
      mapped: mapped.mapped.length,
      unmapped: mapped.unmapped.map(function (one) { return one.incoming; })
    }
  };

  // The relationship's own counts, and — where this sign-in began at an
  // application configured to authenticate through it — that pair's counts
  // beside them. `result.application` is the hint the login endpoint put on the
  // request context; recordUse() decides whether it means anything.
  federation.recordUse(record.fedId,
                       { user: mapped.username, application: result.application || '' });

  // The foreign identity provider as an APPLICATION, so that the one question
  // `ou=applications` exists to answer — what parties has this service dealt
  // with? — is not missing the ones on the other side of a federation. It is
  // filed under the partner's own identifier, which is the same key rule that
  // makes an OAuth client and a WS-Federation realm with one string one record.
  try {
    applications.seen({
      identifier: record.fedPeer || record.fedId,
      kind: PARTNER_KIND,
      protocol: protocolLabel,
      note: 'a FOREIGN IDENTITY PROVIDER this service federates with as a service ' +
            'provider, through the relationship "' + record.fedId + '". It is not a ' +
            'client of this service: it authenticates people TO it.',
      fields: samlFieldsFor(record)
    });
  } catch (e) {
    log.error('federation: the application registry threw and was ignored; the ' +
              'sign-in itself stands: ' + e.message);
  }

  // LAST, because it is the thing that has an effect outside this process and
  // everything above it is a record of why. It carries `detail`, so the one
  // authentication this sign-in produces is recorded with the partner's own
  // facts on it — including the mapped attributes, which reach the directory
  // through the identity funnel and by no other route.
  const session = authn.startSession(res, mapped.username, amr, result.acr || '', via, detail);
  log.info('federation: ' + mapped.username + ' signed in through ' + record.fedId +
           ' (' + protocolLabel + ' from ' + (record.fedPeer || 'an unnamed partner') +
           '). ' + mapped.mapped.length + ' attribute(s) mapped, ' +
           mapped.unmapped.length + ' unmapped. Session ' + session.id + '.');

  const returnTo = result.returnTo || '';
  if (returnTo) {
    // 303, for the reason `authn.js`'s returnToCaller() gives at length: this
    // may follow a POST carrying an assertion, and 302's behaviour after a POST
    // is historically ambiguous where 303's is defined.
    res.redirect(303, returnTo);
    log.debug('Leaving completeSignIn(). Sent them on to ' + returnTo + '.');
    return;
  }
  res.type('html').set('Cache-Control', 'no-store').send(
    page('Signed in', signedInPage(record, mapped, result, session)));
  log.debug('Leaving completeSignIn(). Drew the result page.');
}

function samlFieldsFor(record) {
  log.debug('Entering samlFieldsFor().');
  const fields = {};
  if (record.fedProtocol === 'saml2' || record.fedProtocol === 'saml11') {
    if (record.fedPeer) fields.samlEntityId = record.fedPeer;
    if (record.fedSigningCertificate) {
      fields.samlSigningCertificate = record.fedSigningCertificate;
    }
  }
  if (record.fedProtocol === 'wsfed' && record.fedPeer) fields.wsfedRealm = record.fedPeer;
  if (record.fedProtocol === 'oidc' || record.fedProtocol === 'oauth2') {
    if (record.fedClientId) fields.oauthClientId = record.fedClientId;
  }
  log.debug('Leaving samlFieldsFor().');
  return fields;
}

function bagTable(bag) {
  const names = Object.keys(bag || {});
  if (!names.length) return '<p class="note">The assertion carried no attributes at all.</p>';
  return '<h2>What the partner sent</h2><table><tr><th>Name</th><th>Value(s)</th></tr>' +
    names.map(function (name) {
      const values = Array.isArray(bag[name]) ? bag[name] : [bag[name]];
      return '<tr><td><code>' + xmlEscape(name) + '</code></td><td>' +
        values.map(function (v) { return xmlEscape(String(v)); }).join('<br>') + '</td></tr>';
    }).join('') + '</table>';
}

function signedInPage(record, mapped, result, session) {
  log.debug('Entering signedInPage().');
  const rows = mapped.mapped.map(function (one) {
    return '<tr><td><code>' + xmlEscape(one.incoming) + '</code></td><td><code>' +
      xmlEscape(one.ldap) + '</code></td><td>' +
      one.values.map(function (v) { return xmlEscape(v); }).join('<br>') +
      '</td><td class="note">' + xmlEscape(one.where) + '</td></tr>';
  }).join('');
  const unmapped = mapped.unmapped.map(function (one) {
    return '<tr><td><code>' + xmlEscape(one.incoming) + '</code></td><td colspan="2">' +
      one.values.map(function (v) { return xmlEscape(v); }).join('<br>') +
      '</td><td class="note">nothing maps this name, so it was NOT written</td></tr>';
  }).join('');
  log.debug('Leaving signedInPage().');
  return '<h1>Signed in through ' + xmlEscape(record.fedName || record.fedId) + '</h1>' +
    '<p>This service is now signing you in as <code>' + xmlEscape(mapped.username) +
    '</code>. The session is <code>' + xmlEscape(session.id) + '</code>, and it is the ' +
    'SAME session every other protocol here reads — so an OAuth 2.0 authorization ' +
    'request, a WS-Federation sign-in or the admin console will now find you signed in.</p>' +
    '<table><tr><th>What</th><th>Value</th></tr>' +
    '<tr><td>Partner</td><td><code>' + xmlEscape(record.fedPeer || '(unnamed)') + '</code></td></tr>' +
    '<tr><td>Protocol</td><td>' +
      xmlEscape((federation.protocolRow(record.fedProtocol) || {}).label || record.fedProtocol) +
      '</td></tr>' +
    '<tr><td>Subject the partner sent</td><td><code>' + xmlEscape(result.subject || '(none)') +
      '</code></td></tr>' +
    '<tr><td>Username here</td><td><code>' + xmlEscape(mapped.username) + '</code>' +
      (mapped.usernamePrefixed
        ? ' <span class="note">(federation.usernamePrefix was applied)</span>' : '') +
      ' <span class="note">from ' + xmlEscape(mapped.usernameFrom) + '</span></td></tr>' +
    '<tr><td>Directory entry</td><td>' +
      (federation.boolOf(record.fedAutocreateUsers, true)
        ? 'created or updated under <code>ou=users</code> — see ' +
          '<a href="/admin/users">/admin/users</a>'
        : '<span class="note">NOT created: fedAutocreateUsers is off on this ' +
          'relationship, so this sign-in leaves no entry behind</span>') +
      '</td></tr></table>' +
    (rows ? '<h2>Attributes mapped onto the directory entry</h2><table>' +
      '<tr><th>The partner sent</th><th>Became</th><th>Value(s)</th><th>Decided by</th></tr>' +
      rows + unmapped + '</table>'
      : '<h2>Attributes</h2><p class="note">The partner sent no attributes at all, so the ' +
        'entry carries only the username.</p>' + (unmapped ? '<table>' + unmapped + '</table>' : '')) +
    (mapped.unmapped.length
      ? '<p class="note"><strong>' + mapped.unmapped.length + ' attribute(s) were thrown ' +
        'away</strong> because nothing maps their names. That is deliberate — this directory ' +
        'has no schema, so an attribute written under an unrecognised name would be accepted ' +
        'silently and nothing would ever report that the name was wrong. Add a mapping on ' +
        '<a href="/admin/federation?relationship=' + encodeURIComponent(record.fedId) +
        '">the relationship</a> to keep one.</p>'
      : '') +
    '<p><a href="' + BASE_PATH + '">Back to the federation index</a> · ' +
    '<a href="/admin/federation?relationship=' + encodeURIComponent(record.fedId) +
    '">This relationship in the console</a></p>';
}

// ===========================================================================
// STARTING A FLOW.
// ===========================================================================

// Where to come back to, validated. See decision 4 — the check catches a
// caller's bug and the server-side storage catches an attacker, and both are
// wanted because they fail differently.
function returnToOf(raw) {
  const text = String(raw || '');
  if (!text) return '';
  if (text.charAt(0) !== '/' || text.charAt(1) === '/') {
    log.warn('federation: refused a returnTo of "' + text + '" — it must be a path on ' +
             'this service. The sign-in continues and ends on the result page instead.');
    return '';
  }
  return text;
}

// ---------------------------------------------------------------------------
// SAML 2.0: the <AuthnRequest>.
//
// It names `AssertionConsumerServiceURL` explicitly rather than relying on the
// partner having our metadata, because a partner that HAS our metadata ignores
// the parameter and one that does not would otherwise have nowhere to send the
// answer. `ProtocolBinding` asks for HTTP-POST always: a Response on the
// Redirect binding is DEFLATEd into a URL, and a signed assertion of a few
// kilobytes does not reliably fit in one.
// ---------------------------------------------------------------------------
function authnRequestXml(base, record) {
  log.debug('Entering authnRequestXml().');
  const id = '_' + crypto.randomBytes(16).toString('hex');
  const xml =
    '<samlp:AuthnRequest xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' + NS_SAML + '"' +
      ' ID="' + id + '" Version="2.0" IssueInstant="' + iso(0) + '"' +
      ' Destination="' + xmlEscape(record.fedSsoUrl) + '"' +
      ' ProtocolBinding="' + BINDING_POST + '"' +
      ' AssertionConsumerServiceURL="' + xmlEscape(acsUrl(base, record)) + '">' +
      '<saml:Issuer>' + xmlEscape(ourEntityId(base, record)) + '</saml:Issuer>' +
      '<samlp:NameIDPolicy AllowCreate="true"/>' +
    '</samlp:AuthnRequest>';
  logArtifact('federated SAML 2.0 AuthnRequest', 'before signing', xml);
  if (!federation.boolOf(record.fedSignRequest, false)) {
    log.debug('Leaving authnRequestXml(). Unsigned. id=' + id);
    return { id: id, xml: xml };
  }
  // AFTER the Issuer, which is where the schema puts a signature on a request
  // and where a partner will look for it. A signer with no placement appends it
  // to the document element instead, which is schema-invalid and which several
  // identity providers refuse without saying why.
  const signed = stsCrypto.signXml(xml, {
    privateKeyPem: STS.privateKeyPem,
    certPem: STS.certPem,
    placement: stsCrypto.PLACEMENT.AFTER_ISSUER,
    refUri: '#' + id,
    what: 'federated SAML 2.0 AuthnRequest'
  });
  logArtifact('federated SAML 2.0 AuthnRequest', 'after signing', signed);
  log.debug('Leaving authnRequestXml(). Signed. id=' + id);
  return { id: id, xml: signed };
}

// The HTTP POST binding as a REAL FORM WITH A REAL BUTTON. See the note above
// STYLE: this is the one place in this service where a self-posting form would
// have been the obvious thing and is deliberately not done, because the person
// is leaving this service for somebody else's and a deliberate click is worth
// having there. It also means this feature adds no CSP relaxation at all.
function postBindingPage(action, fields, record) {
  log.debug('Entering postBindingPage().');
  const inputs = Object.keys(fields).map(function (name) {
    return '<input type="hidden" name="' + xmlEscape(name) + '" value="' +
      xmlEscape(String(fields[name])) + '">';
  }).join('');
  log.debug('Leaving postBindingPage().');
  return page('Continue to ' + (record.fedName || record.fedId),
    '<h1>Continue to ' + xmlEscape(record.fedName || record.fedId) + '</h1>' +
    '<p>This service is about to send you to <code>' + xmlEscape(record.fedSsoUrl) +
    '</code> to sign in. It will post ' +
    Object.keys(fields).map(function (n) { return '<code>' + xmlEscape(n) + '</code>'; })
      .join(' and ') + ' there.</p>' +
    '<p class="note">There is no script on this page and it does not submit itself. Five ' +
    'pages in this service DO auto-post, and each one argues for itself; this one does not, ' +
    'because you are leaving this service for a foreign identity provider and that is exactly ' +
    'the moment a deliberate click is worth having.</p>' +
    '<form method="post" action="' + xmlEscape(action) + '">' + inputs +
    '<button type="submit">Continue to the identity provider</button></form>');
}

// ---------------------------------------------------------------------------
// THE OAUTH 2.0 / OIDC AUTHORIZATION REQUEST.
//
// PKCE is ALWAYS sent, in both protocols and whatever the partner advertises.
// RFC 9700 section 2.1.1 requires it of a public client and recommends it of
// every client, a partner that does not understand `code_challenge` ignores an
// unknown parameter as RFC 6749 section 3.1 requires, and this service is
// exactly the kind of client the requirement is about — the code comes back on
// a redirect a browser followed. There is no setting to turn it off, and that
// is the point: the one thing worse than not sending PKCE is a flag that stops.
// ---------------------------------------------------------------------------
function authorizationRequestUrl(base, record, context) {
  log.debug('Entering authorizationRequestUrl().');
  const responseType = String(record.fedResponseType || 'code');
  const params = new URLSearchParams();
  params.set('response_type', responseType);
  params.set('client_id', String(record.fedClientId || ''));
  params.set('redirect_uri', acsUrl(base, record));
  params.set('state', context.handle);
  if (record.fedScope) params.set('scope', String(record.fedScope));
  if (record.fedProtocol === 'oidc') {
    params.set('nonce', context.nonce);
    if (responseType !== 'code') {
      // An ID Token cannot come back on a query string — it would be in the
      // browser's history, in the Referer of everything that page loads, and in
      // every proxy log between here and there. form_post is OIDC's own answer
      // and is the same argument RFC 9700 section 4.3 makes for the
      // authorization response this service ISSUES.
      params.set('response_mode', 'form_post');
    }
  }
  if (responseType === 'code') {
    params.set('code_challenge', context.pkceChallenge);
    params.set('code_challenge_method', 'S256');
  }
  const joiner = String(record.fedSsoUrl).indexOf('?') === -1 ? '?' : '&';
  const url = String(record.fedSsoUrl) + joiner + params.toString();
  log.debug('Leaving authorizationRequestUrl(). response_type=' + responseType);
  return url;
}

function pkcePair() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier: verifier, challenge: challenge };
}

// ---------------------------------------------------------------------------
// GET /federation/login/{id}
// ---------------------------------------------------------------------------
app.get(LOGIN_PATH + '/:id', function (req, res) {
  log.debug('Entering the federation login endpoint. id=' + req.params.id);
  if (!enabled()) {
    res.status(404).type('html').send(page('Not here',
      '<h1>Federation is off</h1><p><code>federation.enabled</code> is off, so no ' +
      'federation endpoint answers. No relationship was changed.</p>'));
    log.debug('Leaving the federation login endpoint. Federation is off.');
    return;
  }
  const id = String(req.params.id || '');
  const record = federation.get(id);
  if (!record) {
    res.status(404).type('html').send(page('No such relationship',
      '<h1>No such federation relationship</h1><p>There is no relationship called <code>' +
      xmlEscape(id) + '</code>. The configured ones are at <a href="' + BASE_PATH + '">' +
      BASE_PATH + '</a>.</p>'));
    log.debug('Leaving the federation login endpoint. No such relationship.');
    return;
  }
  if (record.fedRole !== 'service-provider') {
    return refuse(res, null, 400, 'That relationship goes the other way',
      '"' + id + '" is an identity-provider-side relationship: this service ASSERTS to ' +
      'that partner rather than consuming from it. There is nothing to sign in to here. ' +
      'A partner this service both consumes from and asserts to is two relationships — ' +
      'see federation/CLAUDE.md.');
  }
  if (!federation.isEnabled(record)) {
    return refuse(res, record, 403, 'That relationship is disabled',
      'It exists and is configured, and <code>fedEnabled</code> is FALSE. Every ' +
      'relationship is created disabled deliberately: a partner that half-exists and ' +
      'silently accepts assertions is the failure this whole register is arranged to ' +
      'prevent. Enable it on /admin/federation.');
  }
  const readiness = federation.readinessOf(record);
  if (!readiness.ready) {
    return refuse(res, record, 409, 'That relationship is not fully configured',
      'It is enabled, but ' + readiness.missing.join(', ') + ' ' +
      (readiness.missing.length === 1 ? 'is' : 'are') + ' still empty. It refuses rather ' +
      'than half-working — a federated sign-in that got half way and produced a session ' +
      'would be the worst possible outcome.');
  }

  const base = baseUrlOf(req);
  const returnTo = returnToOf(req.query.returnTo || req.query.return_to);
  const pkce = pkcePair();
  const contextRecord = {
    id: record.fedId, protocol: record.fedProtocol, returnTo: returnTo,
    // WHAT THE PERSON WAS SIGNING IN TO, carried across the round trip so that
    // completeSignIn() can move the relationship's per-application counts.
    //
    // IT IS HERE BECAUSE THERE IS NOWHERE ELSE IT COULD BE. What comes back to
    // `/federation/acs/{id}` is a signed document about a PERSON: it names the
    // partner, the subject and the attributes, and it says nothing whatever
    // about the application at this end — there is no field in any of the five
    // protocols for one. `authn.js` knows the pair at the moment it sends the
    // browser away and never again, so either it rides on the context or the
    // number cannot be had at all.
    //
    // TRUNCATED, AND NOT TRUSTED. It is a query parameter on an endpoint that —
    // alone in this module — needs no configuration at all to reach, so it is
    // bounded here against a context whose size somebody else chose, and
    // `federation.recordUse()` checks the pair against the live register before
    // writing anything anywhere. Neither check is sufficient alone: this one
    // bounds the MAP, that one bounds the DIRECTORY.
    application: String(req.query.application || '').slice(0, MAX_APPLICATION_LEN),
    nonce: 'n-' + randomId(16),
    pkceVerifier: pkce.verifier, pkceChallenge: pkce.challenge
  };

  if (record.fedProtocol === 'saml2') {
    const built = authnRequestXml(base, record);
    contextRecord.requestId = built.id;
    const handle = putContext(contextRecord);
    if (String(record.fedBinding || 'HTTP-Redirect') === 'HTTP-POST') {
      res.type('html').set('Cache-Control', 'no-store').send(
        postBindingPage(record.fedSsoUrl,
                        { SAMLRequest: Buffer.from(built.xml, 'utf8').toString('base64'),
                          RelayState: handle },
                        record));
      log.debug('Leaving the federation login endpoint. SAML 2.0 over HTTP POST.');
      return;
    }
    // HTTP Redirect: DEFLATE with no zlib header (saml-bindings section 3.4.4.1),
    // then base64, then URL-encode. The request is NOT signed on this binding
    // even when fedSignRequest is on, and that is stated rather than silently
    // dropped: the Redirect binding signs the QUERY STRING with a `Signature`
    // parameter rather than carrying an enveloped ds:Signature, which is a
    // different construction — a partner wanting a signed request should be
    // sent one on the POST binding.
    if (federation.boolOf(record.fedSignRequest, false)) {
      log.warn('federation: ' + record.fedId + ' asks for a signed AuthnRequest and uses ' +
               'the HTTP Redirect binding, whose signature is over the QUERY STRING rather ' +
               'than enveloped in the XML. This service does not build that construction, ' +
               'so the request goes UNSIGNED. Use HTTP-POST for a signed request.');
    }
    const deflated = zlib.deflateRawSync(Buffer.from(built.xml, 'utf8')).toString('base64');
    const joiner = String(record.fedSsoUrl).indexOf('?') === -1 ? '?' : '&';
    const url = record.fedSsoUrl + joiner + 'SAMLRequest=' + encodeURIComponent(deflated) +
      '&RelayState=' + encodeURIComponent(handle);
    res.redirect(302, url);
    log.debug('Leaving the federation login endpoint. SAML 2.0 over HTTP Redirect.');
    return;
  }

  if (record.fedProtocol === 'saml11') {
    // NO REQUEST MESSAGE. SAML 1.1's browser profiles are
    // identity-provider-initiated: what the browser is sent to is the partner's
    // inter-site transfer service carrying a TARGET, which is where the partner
    // sends them AFTERWARDS. So the handle rides on TARGET rather than on a
    // RelayState, and the response comes back with no InResponseTo to match —
    // which is why fedAllowUnsolicited is forced on for this protocol.
    //
    // AND `shire` BESIDE IT, WHICH IS NOT DECORATION. Shibboleth's parameter
    // for the assertion consumer service — where the <Response> is POSTed, as
    // distinct from where the person goes afterwards. Without it a partner
    // decides the destination for itself, and one that has this service
    // REGISTERED posts to the registered address: the same path with the
    // `fedctx` query STRIPPED, because a registration holds a URL and not a
    // per-flow handle. The assertion then verifies, the sign-in completes, and
    // the person lands on this service's "signed in" page instead of going back
    // to the application that started the flow — a federation that works
    // perfectly and never returns. Sending both is what a real SAML 1.1 service
    // provider does, and it makes the flow independent of what is registered at
    // the far end.
    const handle = putContext(contextRecord);
    const target = acsUrl(base, record) + '?fedctx=' + encodeURIComponent(handle);
    const joiner = String(record.fedSsoUrl).indexOf('?') === -1 ? '?' : '&';
    const url = record.fedSsoUrl + joiner + 'TARGET=' + encodeURIComponent(target) +
      '&shire=' + encodeURIComponent(target);
    res.redirect(302, url);
    log.debug('Leaving the federation login endpoint. SAML 1.1 inter-site transfer.');
    return;
  }

  if (record.fedProtocol === 'wsfed') {
    const handle = putContext(contextRecord);
    const params = new URLSearchParams();
    params.set('wa', 'wsignin1.0');
    params.set('wtrealm', ourEntityId(base, record));
    params.set('wreply', acsUrl(base, record));
    params.set('wctx', handle);
    // section 13.2.1's wct — the current time — which several identity
    // providers use to decide whether the request is fresh.
    params.set('wct', new Date().toISOString());
    const joiner = String(record.fedSsoUrl).indexOf('?') === -1 ? '?' : '&';
    res.redirect(302, record.fedSsoUrl + joiner + params.toString());
    log.debug('Leaving the federation login endpoint. WS-Federation wsignin1.0.');
    return;
  }

  // OIDC and OAuth 2.0.
  const handle = putContext(contextRecord);
  const stored = contexts.get(handle);
  res.redirect(302, authorizationRequestUrl(base, record, stored));
  log.debug('Leaving the federation login endpoint. ' + record.fedProtocol +
            ' authorization request.');
});

// ===========================================================================
// FINISHING A FLOW: the one path that receives all five protocols.
// ===========================================================================

function paramsOf(req) {
  log.debug('Entering paramsOf(). method=' + req.method);
  const out = {};
  Object.keys(req.query || {}).forEach(function (k) { out[k] = req.query[k]; });
  if (req.method === 'POST') {
    const body = parseBody(req);
    Object.keys(body).forEach(function (k) { out[k] = body[k]; });
  }
  log.debug('Leaving paramsOf(). ' + Object.keys(out).length + ' parameter(s).');
  return out;
}

// ---------------------------------------------------------------------------
// A SAML RESPONSE, 2.0 or 1.1, verified check by check.
//
// Every check is made and the FIRST failure refuses. That is deliberately not
// the shape `/wsfed/rp` and `/saml2/sp` use — those are mock relying parties
// whose whole job is to report every check to a person reading the page, so
// they collect verdicts and show them all. THIS endpoint issues a session, so
// it stops at the first thing that is wrong: continuing past a failed signature
// in order to report the audience as well would mean parsing an unverified
// document to build a nicer error page.
// ---------------------------------------------------------------------------
function consumeSamlResponse(req, res, record, params, version) {
  log.debug('Entering consumeSamlResponse(). version=' + version);
  const encoded = String(params.SAMLResponse || '');
  if (!encoded) {
    log.debug('Leaving consumeSamlResponse(). No SAMLResponse.');
    return refuse(res, record, 400, 'Nothing arrived',
      'This is the assertion consumer service for "' + record.fedId + '" and the request ' +
      'carried no SAMLResponse. A browser that reached it by hand will see this; so will a ' +
      'partner configured to send its answer somewhere else.');
  }
  let xml = '';
  try {
    xml = Buffer.from(encoded, 'base64').toString('utf8');
  } catch (e) {
    log.debug('Leaving consumeSamlResponse(). Not base64.');
    return refuse(res, record, 400, 'The SAMLResponse is not base64',
                  'It could not be decoded: ' + e.message);
  }
  logArtifact('federated SAML ' + version + ' Response', 'as received', xml);

  let doc = null;
  try {
    doc = new DOMParser().parseFromString(xml, 'text/xml');
  } catch (e) {
    log.debug('Leaving consumeSamlResponse(). Not XML.');
    return refuse(res, record, 400, 'The SAMLResponse is not XML', e.message);
  }
  const root = doc && doc.documentElement;
  if (!root) {
    return refuse(res, record, 400, 'The SAMLResponse is empty',
                  'It decoded to something with no document element.');
  }

  // The status FIRST, because a partner that refused to authenticate somebody
  // sends a perfectly well-formed Response with no assertion in it, and
  // reporting that as "no assertion" would send somebody looking for a bug in
  // this service.
  const statusEl = firstByLocal(root, 'StatusCode');
  const status = statusEl ? (statusEl.getAttribute('Value') || '') : '';
  const statusMessage = textByLocal(root, 'StatusMessage') || '';
  const succeeded = version === '2.0'
    ? status === STATUS_SUCCESS
    : /Success$/.test(status);
  if (!succeeded) {
    log.debug('Leaving consumeSamlResponse(). The partner refused.');
    return refuse(res, record, 400, 'The partner refused to authenticate them',
      'It answered ' + (status || '(no StatusCode)') +
      (statusMessage ? ' — "' + statusMessage + '"' : '') +
      '. That is the partner\'s answer, not this service\'s: nothing here was asked to ' +
      'accept or refuse anything.');
  }

  const assertion = firstByLocal(root, 'Assertion');
  if (!assertion) {
    return refuse(res, record, 400, 'There is no assertion in it',
      'The Response reported success and carried no <Assertion>. If the partner is ' +
      'configured to ENCRYPT the assertion, that is the cause: this service does not ' +
      'decrypt one — see federation/CLAUDE.md, where that is listed as a deliberate gap ' +
      'rather than left to be discovered here.');
  }

  // THE SIGNATURE. Either the Response or the Assertion may carry it and either
  // is enough — which is what every real service provider accepts, because
  // AD FS signs the assertion, Keycloak signs both and Shibboleth signs the
  // response. What is NOT enough is neither.
  const assertionSig = verifyXmlSignature(xml, record, 'Assertion');
  const responseSig = verifyXmlSignature(xml, record, 'Response');
  if (!assertionSig.ok && !responseSig.ok) {
    log.debug('Leaving consumeSamlResponse(). The signature did not verify.');
    return refuse(res, record, 401, 'The signature did not verify',
      (!assertionSig.present && !responseSig.present)
        ? 'Neither the <Response> nor the <Assertion> carries a ds:Signature at all. An ' +
          'unsigned assertion is an unauthenticated HTTP request with XML in it, and this ' +
          'is the one endpoint in this service where that cannot be accepted.'
        : 'The Assertion: ' + (assertionSig.present ? assertionSig.why : 'unsigned') +
          '. The Response: ' + (responseSig.present ? responseSig.why : 'unsigned') +
          '. Both are checked against fedSigningCertificate on this relationship, and ' +
          'against nothing else — a certificate carried inside the document\'s own ' +
          'ds:KeyInfo is deliberately ignored.',
      '<p class="note">The certificate configured here is ' +
      (record.fedSigningCertificate
        ? '<code>' + xmlEscape(String(record.fedSigningCertificate).slice(0, 60)) + '…</code> (' +
          String(record.fedSigningCertificate).length + ' base64 characters)'
        : '<strong>empty</strong>') + '.</p>');
  }

  // THE ISSUER. It has to be the partner this relationship names — otherwise
  // any partner whose certificate is configured anywhere could assert for any
  // other, which is the flaw that has broken more than one real federation.
  const issuer = textByLocal(root, 'Issuer') || (assertion.getAttribute('Issuer') || '');
  const expectedIssuer = String(record.fedPeer || '').trim();
  if (expectedIssuer && issuer !== expectedIssuer) {
    log.debug('Leaving consumeSamlResponse(). Wrong issuer.');
    return refuse(res, record, 401, 'It was issued by somebody else',
      'The assertion names <code>' + issuer + '</code> as its issuer and this relationship ' +
      'expects <code>' + expectedIssuer + '</code>. The signature verified, which means ' +
      'the key configured here signed an assertion claiming to be from a different party.');
  }
  if (!expectedIssuer) {
    log.warn('federation: ' + record.fedId + ' has no fedPeer configured, so the ' +
             'assertion\'s issuer ("' + issuer + '") was not checked. Set fedPeer: without ' +
             'it, any assertion the configured key signed is accepted whoever it claims to ' +
             'be from.');
  }

  const validity = conditionsCheck(assertion);
  if (!validity.ok) {
    log.debug('Leaving consumeSamlResponse(). Outside its validity window.');
    return refuse(res, record, 401, 'The assertion is not valid now', validity.why);
  }

  // THE AUDIENCE. Optional in practice — plenty of identity providers omit it
  // — so an absent one is accepted with a warning and a PRESENT one that names
  // somebody else is refused. Those two are different facts and collapsing them
  // would mean either refusing half the partners in the world or accepting an
  // assertion minted for a different service provider.
  const conditions = firstByLocal(assertion, 'Conditions');
  const audience = conditions ? textByLocal(conditions, 'Audience') : '';
  const base = baseUrlOf(req);
  const ours = ourEntityId(base, record);
  if (audience && audience !== ours && audience !== record.fedClientId) {
    log.warn('federation: the assertion from ' + record.fedId + ' names <Audience>' +
             audience + '</Audience> and this service calls itself ' + ours + ' to that ' +
             'partner. It is ACCEPTED, because a partner that was configured with a ' +
             'different name for us is the ordinary case and refusing it would make this ' +
             'feature unusable — but an assertion minted for somebody ELSE looks exactly ' +
             'like this, so it is worth checking what the partner was configured with.');
  }

  const contents = assertionContents(assertion);

  // InResponseTo. SAML 2.0 only — 1.1 has no request for anything to be in
  // response to — and only where the relationship has not opted out.
  let context = null;
  const handle = String(params.RelayState || params.fedctx || '');
  if (handle) context = takeContext(handle);
  if (version === '2.0' && !federation.boolOf(record.fedAllowUnsolicited, false)) {
    const scd = firstByLocal(assertion, 'SubjectConfirmationData');
    const inResponseTo = (scd && scd.getAttribute('InResponseTo')) ||
      root.getAttribute('InResponseTo') || '';
    if (!context) {
      log.debug('Leaving consumeSamlResponse(). Unsolicited.');
      return refuse(res, record, 401, 'This service did not ask for that assertion',
        handle
          ? 'The RelayState "' + handle + '" is not one this service minted, or the ' +
            'sign-in it belonged to expired (federation.requestTtlMin is ' +
            config.value('federation.requestTtlMin') + ' minutes).'
          : 'No RelayState came back at all, so there is nothing to match the assertion ' +
            'against. Set fedAllowUnsolicited on the relationship to accept a response ' +
            'this service did not start — which is what identity-provider-initiated ' +
            'sign-on is, and it removes this check.');
    }
    if (inResponseTo && inResponseTo !== context.requestId) {
      log.debug('Leaving consumeSamlResponse(). InResponseTo does not match.');
      return refuse(res, record, 401, 'It answers a different request',
        'The assertion says InResponseTo="' + inResponseTo + '" and the sign-in this ' +
        'RelayState belongs to sent "' + context.requestId + '".');
    }
  }

  const amr = [];
  if (contents.context) amr.push(contents.context);
  log.debug('Leaving consumeSamlResponse(). Verified; completing the sign-in.');
  return completeSignIn(req, res, record, {
    subject: contents.subject,
    bag: contents.bag,
    amr: amr.length ? ['federated'] : ['federated'],
    acr: contents.context || '',
    returnTo: fromContext(context).returnTo,
    application: fromContext(context).application
  });
}

// ---------------------------------------------------------------------------
// A WS-FEDERATION SIGN-IN RESPONSE.
//
// `wresult` is an RSTR — a `<RequestSecurityTokenResponse>` wrapping a
// `<RequestedSecurityToken>` wrapping an assertion which may be SAML 1.1 or
// SAML 2.0. Which one it is decides the id attribute the signature reference
// resolves through, and getting that wrong is the bug `wsfed.js`'s
// `verifyAssertionSignature()` header describes.
// ---------------------------------------------------------------------------
function consumeWsFedResponse(req, res, record, params) {
  log.debug('Entering consumeWsFedResponse().');
  const wa = String(params.wa || '');
  if (wa && wa !== 'wsignin1.0') {
    log.debug('Leaving consumeWsFedResponse(). Not a sign-in response.');
    return refuse(res, record, 400, 'That is not a sign-in response',
      'wa=' + wa + '. This endpoint consumes wa=wsignin1.0. A wsignout1.0 arriving here ' +
      'is a partner configured to send its sign-out where its sign-in goes — this service ' +
      'does not consume a federated sign-out, which is listed as a gap in ' +
      'federation/CLAUDE.md rather than left to be discovered.');
  }
  const wresult = String(params.wresult || '');
  if (!wresult) {
    return refuse(res, record, 400, 'Nothing arrived',
      'The request carried no wresult. That is what a wsignin1.0 response puts the token in.');
  }
  logArtifact('federated WS-Federation wresult', 'as received', wresult);
  let doc = null;
  try {
    doc = new DOMParser().parseFromString(wresult, 'text/xml');
  } catch (e) {
    return refuse(res, record, 400, 'The wresult is not XML', e.message);
  }
  const root = doc && doc.documentElement;
  const assertion = root ? firstByLocal(root, 'Assertion') : null;
  if (!assertion) {
    return refuse(res, record, 400, 'There is no assertion in the wresult',
      'The RequestSecurityTokenResponse carried no <Assertion>. An ENCRYPTED token looks ' +
      'exactly like this from here; this service does not decrypt one.');
  }
  const version = assertion.namespaceURI === NS_SAML ? '2.0' : '1.1';
  log.debug('consumeWsFedResponse(): the token is a SAML ' + version + ' assertion.');

  const sig = verifyXmlSignature(wresult, record, 'Assertion');
  if (!sig.ok) {
    log.debug('Leaving consumeWsFedResponse(). The signature did not verify.');
    return refuse(res, record, 401, 'The signature did not verify',
      sig.present
        ? sig.why + '. It is checked against fedSigningCertificate on this relationship ' +
          'and against nothing else.'
        : 'The assertion carries no ds:Signature at all, which makes it an ' +
          'unauthenticated HTTP request with XML in it.');
  }
  const issuer = textByLocal(assertion, 'Issuer') || assertion.getAttribute('Issuer') || '';
  const expectedIssuer = String(record.fedPeer || '').trim();
  if (expectedIssuer && issuer && issuer !== expectedIssuer) {
    return refuse(res, record, 401, 'It was issued by somebody else',
      'The assertion names <code>' + issuer + '</code> and this relationship expects ' +
      '<code>' + expectedIssuer + '</code>.');
  }
  const validity = conditionsCheck(assertion);
  if (!validity.ok) {
    return refuse(res, record, 401, 'The assertion is not valid now', validity.why);
  }
  const contents = assertionContents(assertion);
  const context = takeContext(String(params.wctx || ''));
  if (!context && !federation.boolOf(record.fedAllowUnsolicited, false)) {
    log.debug('Leaving consumeWsFedResponse(). Unsolicited.');
    return refuse(res, record, 401, 'This service did not ask for that token',
      params.wctx
        ? 'The wctx "' + params.wctx + '" is not one this service minted, or the sign-in ' +
          'it belonged to expired.'
        : 'No wctx came back. Section 13.2.1 makes it optional, so a partner that drops it ' +
          'is not misbehaving — set fedAllowUnsolicited on the relationship to accept its ' +
          'responses anyway, and note that doing so removes this check for every response.');
  }
  log.debug('Leaving consumeWsFedResponse(). Verified; completing the sign-in.');
  return completeSignIn(req, res, record, {
    subject: contents.subject, bag: contents.bag,
    amr: ['federated'], acr: contents.context || '',
    returnTo: fromContext(context).returnTo,
    application: fromContext(context).application
  });
}

// ---------------------------------------------------------------------------
// THE PARTNER'S KEYS, AND THE ONE PLACE A JWT FROM SOMEBODY ELSE IS VERIFIED.
//
// `fedJwks` is read first and is never refreshed; `fedJwksUri` is fetched. The
// order is the one the schema rows state and it matters: a relationship
// carrying pasted keys makes NO outbound request at all, which is what a
// deployment with no egress needs.
//
// The `kid` selects and does not establish — `client_auth.js`'s rule again. A
// token whose header names a `kid` nothing has is refused rather than being
// tried against every key: a partner that rotated a key wants to hear that,
// and trying them all turns a rotation into a silent success against a key the
// partner has retired.
// ---------------------------------------------------------------------------
function keysFor(record) {
  log.debug('Entering keysFor(). id=' + record.fedId);
  const pasted = String(record.fedJwks || '').trim();
  if (pasted) {
    try {
      const parsed = JSON.parse(pasted);
      const keys = Array.isArray(parsed.keys) ? parsed.keys : (parsed.kty ? [parsed] : []);
      log.debug('Leaving keysFor(). ' + keys.length + ' pasted key(s).');
      return Promise.resolve({ ok: true, keys: keys, from: 'fedJwks' });
    } catch (e) {
      log.debug('Leaving keysFor(). fedJwks will not parse.');
      return Promise.resolve({ ok: false, keys: [],
                               why: 'fedJwks on this relationship is not JSON: ' + e.message });
    }
  }
  if (!String(record.fedJwksUri || '').trim()) {
    log.debug('Leaving keysFor(). Neither is configured.');
    return Promise.resolve({ ok: false, keys: [],
                             why: 'neither fedJwks nor fedJwksUri is configured, so there ' +
                                  'is no key to verify the token with' });
  }
  return fedHttp.fetchJson(record, 'fedJwksUri', { method: 'GET' }).then(function (answer) {
    if (!answer.ok || !answer.json) {
      log.debug('Leaving keysFor(). The JWKS could not be fetched.');
      return { ok: false, keys: [],
               why: 'the JWKS at ' + answer.url + ' could not be fetched: ' + answer.why };
    }
    const keys = Array.isArray(answer.json.keys) ? answer.json.keys : [];
    log.debug('Leaving keysFor(). ' + keys.length + ' fetched key(s).');
    return { ok: true, keys: keys, from: 'fedJwksUri' };
  });
}

function verifyForeignJwt(token, record, keys, options) {
  log.debug('Entering verifyForeignJwt().');
  let header = null;
  try {
    header = jsonFromB64u(String(token).split('.')[0]);
  } catch (e) {
    log.debug('Leaving verifyForeignJwt(). The header will not decode.');
    return { ok: false, why: 'its header is not base64url JSON: ' + e.message };
  }
  if (!header || !header.alg) {
    return { ok: false, why: 'it has no alg in its header' };
  }
  if (String(header.alg).toLowerCase() === 'none') {
    // Named rather than lumped in with "no key matched", because `alg: none` is
    // an attack with a name and somebody seeing it should know which one.
    return { ok: false,
             why: 'its header says alg=none, which is an unsigned token presented as a ' +
                  'signed one. It is refused by name rather than by failing to find a key' };
  }
  const kid = header.kid || '';
  const candidates = keys.filter(function (key) {
    if (kid && key.kid) return key.kid === kid;
    return true;
  });
  if (!candidates.length) {
    return { ok: false,
             why: kid
               ? 'its header names kid "' + kid + '" and the partner\'s key set has no such ' +
                 'key. That is what a key rotation looks like — refetch or repaste ' +
                 'the keys'
               : 'the partner\'s key set is empty' };
  }
  let lastWhy = '';
  for (let i = 0; i < candidates.length; i++) {
    let pem = null;
    try {
      pem = crypto.createPublicKey({ key: candidates[i], format: 'jwk' });
    } catch (e) {
      lastWhy = 'a key in the set could not be read: ' + e.message;
      continue;
    }
    try {
      const payload = stsCrypto.verifyJws(String(token), pem, Object.assign({
        // THE ALGORITHM FAMILY COMES FROM THE KEY, NOT FROM THE TOKEN. This is
        // `client_auth.js`'s rule and it is the classic JWT forgery: without
        // it, a token nominating HS256 would be verified using the partner's
        // PUBLIC key as an HMAC secret, which anybody can do.
        algorithms: candidates[i].kty === 'EC'
          ? ['ES256', 'ES384', 'ES512']
          : ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'],
        clockTolerance: config.value('oauth2.clockSkewS')
      }, options || {}));
      log.debug('Leaving verifyForeignJwt(). Verified.');
      return { ok: true, payload: payload, kid: candidates[i].kid || '' };
    } catch (e) {
      lastWhy = e.message;
    }
  }
  log.debug('Leaving verifyForeignJwt(). Nothing verified it: ' + lastWhy);
  return { ok: false, why: lastWhy || 'no key in the partner\'s set verified it' };
}

// ---------------------------------------------------------------------------
// THE OAUTH 2.0 / OIDC CALLBACK.
//
// This is the branch with the back channel in it, and every outbound request
// goes through `federation_http.js` — see that file's header for why a
// configured URL is a different thing from a registered one.
// ---------------------------------------------------------------------------
function consumeOauthResponse(req, res, record, params) {
  log.debug('Entering consumeOauthResponse(). protocol=' + record.fedProtocol);
  if (params.error) {
    log.debug('Leaving consumeOauthResponse(). The partner returned an error.');
    return refuse(res, record, 400, 'The partner refused',
      'It answered <code>' + xmlEscape(String(params.error)) + '</code>' +
      (params.error_description ? ' — "' + xmlEscape(String(params.error_description)) + '"' : '') +
      '. That is the partner\'s answer about this service as a CLIENT of it: the usual ' +
      'causes are a redirect_uri it does not have registered (this one is ' +
      '<code>' + xmlEscape(acsUrl(baseUrlOf(req), record)) + '</code>) or a client_id it ' +
      'does not know.');
  }
  const context = takeContext(String(params.state || ''));
  if (!context) {
    log.debug('Leaving consumeOauthResponse(). No state.');
    return refuse(res, record, 401, 'This service did not start that sign-in',
      params.state
        ? 'The state "' + xmlEscape(String(params.state)) + '" is not one this service ' +
          'minted, or the sign-in it belonged to expired (federation.requestTtlMin is ' +
          config.value('federation.requestTtlMin') + ' minutes). A state that does not ' +
          'match is what a cross-site request forgery on this callback looks like, so it ' +
          'is refused rather than accepted with a warning.'
        : 'No state came back at all. This service always sends one, so a response ' +
          'without one did not come from a flow it started.');
  }

  const responseType = String(record.fedResponseType || 'code');

  // The front-channel shape: an ID Token straight back, no back channel at all.
  if (responseType !== 'code') {
    const idToken = String(params.id_token || '');
    if (!idToken) {
      return refuse(res, record, 400, 'No ID Token arrived',
        'This relationship asks for response_type=' + responseType + ' with ' +
        'response_mode=form_post, so the answer should have POSTed an id_token here.');
    }
    return finishOidc(req, res, record, context, idToken, '');
  }

  const code = String(params.code || '');
  if (!code) {
    return refuse(res, record, 400, 'No authorization code arrived',
      'The partner redirected here with neither a code nor an error, which is not a ' +
      'response RFC 6749 section 4.1.2 describes.');
  }

  // THE TOKEN REQUEST. `client_secret_basic` where there is a secret, because
  // RFC 6749 section 2.3.1 says a server MUST support it and MAY support the
  // body form — so the one that is always available is the one used. A partner
  // that wants the secret in the body will refuse this and say so, which is a
  // better failure than guessing.
  const form = {
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: acsUrl(baseUrlOf(req), record),
    code_verifier: context.pkceVerifier
  };
  const options = { method: 'POST', form: form };
  if (record.fedClientSecret) {
    options.basic = { user: record.fedClientId, pass: record.fedClientSecret };
  } else {
    // A public client. The client_id goes in the body, which is what RFC 6749
    // section 4.1.3 requires when the client does not authenticate.
    form.client_id = String(record.fedClientId || '');
  }
  log.debug('consumeOauthResponse(): redeeming the code at the partner.');
  return fedHttp.fetchJson(record, 'fedTokenUrl', options).then(function (answer) {
    if (!answer.ok || !answer.json) {
      log.debug('Leaving consumeOauthResponse(). The token request failed.');
      return refuse(res, record, 502, 'The code could not be redeemed',
        'The token request to ' + (answer.url || 'the partner') + ' failed: ' + answer.why +
        (answer.text && !answer.json
          ? '. It answered with something that is not JSON, which usually means a proxy ' +
            'in front of the partner rather than the partner itself.'
          : ''),
        answer.json && answer.json.error_description
          ? '<p class="note">The partner said: <code>' +
            xmlEscape(String(answer.json.error_description)) + '</code></p>'
          : '');
    }
    const tokens = answer.json;
    if (record.fedProtocol === 'oidc') {
      if (!tokens.id_token) {
        return refuse(res, record, 502, 'The partner returned no ID Token',
          'The code was redeemed and the response carried ' +
          Object.keys(tokens).join(', ') + ' but no <code>id_token</code>. That is an ' +
          'OAuth 2.0 token response rather than an OpenID Connect one — either the ' +
          '`openid` scope was not asked for (this relationship asks for "' +
          xmlEscape(String(record.fedScope || '')) + '") or the partner is not an OpenID ' +
          'Provider, in which case this relationship should be protocol oauth2.');
      }
      return finishOidc(req, res, record, context, String(tokens.id_token),
                        String(tokens.access_token || ''));
    }
    return finishOauth2(req, res, record, context, tokens);
  }).catch(function (e) {
    // fetchJson() never rejects, so this can only be a throw in the code above
    // — and it has to be caught, because an unhandled rejection in the middle
    // of a browser redirect leaves the person on a blank page with the failure
    // only in this process's log.
    log.error('federation: the ' + record.fedProtocol + ' callback threw: ' + e.stack);
    return refuse(res, record, 500, 'This service failed while finishing the sign-in',
                  e.message);
  });
}

function finishOidc(req, res, record, context, idToken, accessToken) {
  log.debug('Entering finishOidc().');
  return keysFor(record).then(function (keySet) {
    if (!keySet.ok) {
      log.debug('Leaving finishOidc(). No keys.');
      return refuse(res, record, 500, 'There is no key to verify the ID Token with',
                    keySet.why);
    }
    const verified = verifyForeignJwt(idToken, record, keySet.keys, {
      // The audience is this service's client_id at the partner, and the issuer
      // is what the relationship names. Both are checked BY jwt.verify() rather
      // than after it, so a token that fails either is never parsed into
      // anything this service acts on.
      audience: String(record.fedClientId || '') || undefined,
      issuer: String(record.fedPeer || '') || undefined
    });
    if (!verified.ok) {
      log.debug('Leaving finishOidc(). The ID Token did not verify.');
      return refuse(res, record, 401, 'The ID Token did not verify', verified.why +
        '. It is checked against the keys in ' + keySet.from + ' on this relationship, ' +
        'with aud=' + (record.fedClientId || '(unset)') + ' and iss=' +
        (record.fedPeer || '(unset)') + '.');
    }
    const payload = verified.payload;
    if (context.nonce && payload.nonce && payload.nonce !== context.nonce) {
      // The nonce check. OpenID Connect Core section 3.1.3.7 step 11, and it is
      // the check `oauth2_bcp.js` records as `enforced: 'no'` on the ISSUING
      // side because nothing there can observe a client doing it. Here this
      // service IS the client, so it does it.
      log.debug('Leaving finishOidc(). The nonce does not match.');
      return refuse(res, record, 401, 'The ID Token answers a different request',
        'Its nonce is "' + xmlEscape(String(payload.nonce)) + '" and this sign-in sent "' +
        xmlEscape(context.nonce) + '". A replayed ID Token looks exactly like this.');
    }
    if (context.nonce && !payload.nonce) {
      log.warn('federation: the ID Token from ' + record.fedId + ' carries no nonce and ' +
               'this service sent one. It is ACCEPTED — the code flow is protected by the ' +
               'state and the PKCE verifier as well — but a partner that drops the nonce ' +
               'cannot be used with response_type=id_token, where it is the only replay ' +
               'protection there is.');
    }
    const bag = {};
    Object.keys(payload).forEach(function (name) {
      // The protocol's own members are not attributes about a person and must
      // not become directory attributes. `sub` is handled separately as the
      // subject; the rest are about the token.
      if (['iss', 'aud', 'exp', 'iat', 'nbf', 'jti', 'nonce', 'at_hash', 'c_hash',
           'azp', 'auth_time', 'sid', 'sub', 'acr', 'amr'].indexOf(name) !== -1) return;
      bag[name] = payload[name];
    });
    const amr = Array.isArray(payload.amr) && payload.amr.length ? payload.amr : ['federated'];
    const finish = function (extra) {
      Object.keys(extra || {}).forEach(function (name) {
        if (bag[name] === undefined) bag[name] = extra[name];
      });
      return completeSignIn(req, res, record, {
        subject: String(payload.sub || ''), bag: bag, amr: amr,
        acr: String(payload.acr || ''),
        returnTo: fromContext(context).returnTo,
        application: fromContext(context).application
      });
    };
    if (!accessToken || !String(record.fedUserinfoUrl || '').trim()) {
      log.debug('Leaving finishOidc(). No UserInfo call.');
      return finish(null);
    }
    log.debug('finishOidc(): asking the partner\'s UserInfo endpoint as well.');
    return fedHttp.fetchJson(record, 'fedUserinfoUrl',
                             { method: 'GET', bearer: accessToken }).then(function (answer) {
      if (!answer.ok || !answer.json) {
        // NOT a failure of the sign-in. The ID Token has already verified and
        // named the person; UserInfo adds attributes. Failing the whole sign-in
        // because an optional second call did not answer would be the wrong
        // trade, and the warning is what says the attributes are missing.
        log.warn('federation: UserInfo at ' + answer.url + ' did not answer for ' +
                 record.fedId + ' (' + answer.why + '). The sign-in STANDS on the ID ' +
                 'Token, which has already verified — what is lost is whatever ' +
                 'attributes that endpoint would have added.');
        return finish(null);
      }
      log.debug('Leaving finishOidc(). UserInfo added ' +
                Object.keys(answer.json).length + ' member(s).');
      const extra = {};
      Object.keys(answer.json).forEach(function (name) {
        if (name === 'sub') return;
        extra[name] = answer.json[name];
      });
      return finish(extra);
    });
  });
}

// ---------------------------------------------------------------------------
// PLAIN OAUTH 2.0, WHICH IS A DIFFERENT PROTOCOL AND NOT OIDC WITH A FLAG.
//
// There is no ID Token, so there is no artifact that says who signed in. Two
// shapes are supported and the difference between them is the whole reason this
// protocol is listed separately:
//
//   * A JWT ACCESS TOKEN. Verified exactly as an ID Token is — and this is the
//     ONLY place in this service where an access token from somebody else is
//     verified. Its claims become the bag.
//   * AN OPAQUE ACCESS TOKEN plus a userinfo-shaped endpoint. The token is a
//     bearer credential this service presents; whatever the endpoint answers is
//     the bag.
//
// **NEITHER IS AUTHENTICATION IN THE SENSE OIDC MEANS**, and this service says
// so on the page rather than pretending otherwise. An access token says a
// client was authorized, not that a person signed in just now, and the whole
// of "why you should not use OAuth 2.0 for authentication" lives in that gap.
// Supporting it anyway is right for a mock — plenty of real deployments do it,
// and being able to exercise one is the point — but doing it silently would be
// this repository teaching the mistake.
// ---------------------------------------------------------------------------
function finishOauth2(req, res, record, context, tokens) {
  log.debug('Entering finishOauth2().');
  const accessToken = String(tokens.access_token || '');
  if (!accessToken) {
    log.debug('Leaving finishOauth2(). No access token.');
    return refuse(res, record, 502, 'The partner returned no access token',
      'The token response carried ' + Object.keys(tokens).join(', ') + '.');
  }
  log.warn('federation: ' + record.fedId + ' is a plain OAuth 2.0 relationship, so this ' +
           'sign-in rests on an ACCESS TOKEN rather than on an ID Token. An access token ' +
           'says a client was authorized, not that this person signed in just now — see ' +
           'federation/CLAUDE.md. It is supported because real deployments do it.');
  const looksLikeJwt = accessToken.split('.').length === 3;
  const useUserinfo = !looksLikeJwt || !String(record.fedJwks || record.fedJwksUri || '').trim();

  if (!useUserinfo) {
    return keysFor(record).then(function (keySet) {
      if (!keySet.ok) {
        return refuse(res, record, 500, 'There is no key to verify the access token with',
                      keySet.why);
      }
      const verified = verifyForeignJwt(accessToken, record, keySet.keys, {
        issuer: String(record.fedPeer || '') || undefined
      });
      if (!verified.ok) {
        return refuse(res, record, 401, 'The access token did not verify', verified.why);
      }
      const payload = verified.payload;
      const bag = {};
      Object.keys(payload).forEach(function (name) {
        if (['iss', 'aud', 'exp', 'iat', 'nbf', 'jti', 'client_id', 'scope', 'sub',
             'token_type', 'cnf'].indexOf(name) !== -1) return;
        bag[name] = payload[name];
      });
      log.debug('Leaving finishOauth2(). A verified JWT access token.');
      return completeSignIn(req, res, record, {
        subject: String(payload.sub || ''), bag: bag, amr: ['federated'],
        acr: '',
        returnTo: fromContext(context).returnTo,
        application: fromContext(context).application
      });
    });
  }

  if (!String(record.fedUserinfoUrl || '').trim()) {
    log.debug('Leaving finishOauth2(). Opaque token and no userinfo endpoint.');
    return refuse(res, record, 500, 'There is no way to learn who this is',
      'The partner returned an ' + (looksLikeJwt ? 'access token this relationship has no ' +
      'keys to verify' : 'OPAQUE access token') + ', and no fedUserinfoUrl is configured. ' +
      'A plain OAuth 2.0 relationship needs one or the other: an access token that cannot ' +
      'be read and cannot be exchanged for a profile names nobody.');
  }
  return fedHttp.fetchJson(record, 'fedUserinfoUrl',
                           { method: 'GET', bearer: accessToken }).then(function (answer) {
    if (!answer.ok || !answer.json) {
      log.debug('Leaving finishOauth2(). The userinfo call failed.');
      return refuse(res, record, 502, 'The partner would not say who this is',
        'The request to ' + answer.url + ' failed: ' + answer.why + '. Unlike the OIDC ' +
        'case, this call is NOT optional here — it is the only thing that names the ' +
        'person, because a plain OAuth 2.0 flow issues no ID Token.');
    }
    const profile = answer.json;
    const bag = {};
    Object.keys(profile).forEach(function (name) {
      if (name === 'sub') return;
      bag[name] = profile[name];
    });
    log.debug('Leaving finishOauth2(). The profile endpoint answered.');
    return completeSignIn(req, res, record, {
      subject: String(profile.sub || profile.id || profile.user_id || ''),
      bag: bag, amr: ['federated'], acr: '',
      returnTo: fromContext(context).returnTo,
      application: fromContext(context).application
    });
  });
}

// ---------------------------------------------------------------------------
// The endpoint itself. GET and POST, because a SAML Response arrives by POST, a
// WS-Federation one by POST, an OAuth redirect by GET and an OIDC form_post by
// POST — and which one it is depends on the relationship rather than on the
// method.
// ---------------------------------------------------------------------------
function consume(req, res) {
  log.debug('Entering the federation assertion consumer service. id=' + req.params.id);
  if (!enabled()) {
    res.status(404).type('html').send(page('Not here',
      '<h1>Federation is off</h1><p><code>federation.enabled</code> is off.</p>'));
    log.debug('Leaving the assertion consumer service. Federation is off.');
    return;
  }
  const id = String(req.params.id || '');
  const record = federation.get(id);
  if (!record || record.fedRole !== 'service-provider') {
    res.status(404).type('html').send(page('No such relationship',
      '<h1>No such assertion consumer service</h1><p>There is no service-provider-side ' +
      'relationship called <code>' + xmlEscape(id) + '</code>.</p>'));
    log.debug('Leaving the assertion consumer service. No such relationship.');
    return;
  }
  if (!federation.isUsable(record)) {
    return refuse(res, record, 403, 'That relationship is not usable',
      federation.isEnabled(record)
        ? 'It is enabled but not fully configured: ' +
          federation.readinessOf(record).missing.join(', ') + ' still to set.'
        : 'It is disabled. A response arriving for a disabled relationship is refused ' +
          'without being looked at — which is what disabling is for.');
  }
  const params = paramsOf(req);
  try {
    if (record.fedProtocol === 'saml2') return consumeSamlResponse(req, res, record, params, '2.0');
    if (record.fedProtocol === 'saml11') return consumeSamlResponse(req, res, record, params, '1.1');
    if (record.fedProtocol === 'wsfed') return consumeWsFedResponse(req, res, record, params);
    return consumeOauthResponse(req, res, record, params);
  } catch (e) {
    // Every branch above can throw on a malformed document, and a throw here
    // reaches express's error handler as a 500 with a stack trace in it. This
    // catches it into the same refusal page every other failure draws, so that
    // the relationship records what happened and the person sees a sentence.
    log.error('federation: ' + id + ' threw while consuming a response: ' + e.stack);
    return refuse(res, record, 500, 'This service failed while reading the response',
                  e.message);
  }
}

app.get(ACS_PATH + '/:id', consume);
app.post(ACS_PATH + '/:id', consume);

// ---------------------------------------------------------------------------
// GET /federation/metadata/{id} — THIS SERVICE'S OWN SAML metadata for one
// partner.
//
// It is per relationship for the reason `ourEntityId()` is: this service calls
// itself something different to every partner, so one document naming one
// entityID would be wrong for all but the first.
//
// It is UNSIGNED, and that is worth saying rather than leaving to be noticed.
// `/saml2/metadata/{sp}` — the identity-provider side — IS signed, because a
// service provider configuring its trust in this service has something to gain
// from checking who wrote the document. Here the situation is reversed: the
// partner is being told where to send things and which certificate we sign
// requests with, and a signature over that made by the very key in question
// proves nothing they did not already have to trust.
// ---------------------------------------------------------------------------
app.get(METADATA_PATH + '/:id', function (req, res) {
  log.debug('Entering the federation metadata endpoint. id=' + req.params.id);
  const id = String(req.params.id || '');
  const record = federation.get(id);
  if (!record || record.fedRole !== 'service-provider' ||
      (record.fedProtocol !== 'saml2' && record.fedProtocol !== 'saml11')) {
    res.status(404).type('html').send(page('No such metadata',
      '<h1>No metadata here</h1><p>There is no SAML service-provider-side relationship ' +
      'called <code>' + xmlEscape(id) + '</code>. Metadata is a SAML thing, so an OIDC, ' +
      'OAuth 2.0 or WS-Federation relationship has none — what a partner needs for those ' +
      'is on <a href="' + BASE_PATH + '">' + BASE_PATH + '</a>.</p>'));
    log.debug('Leaving the federation metadata endpoint. Not a SAML relationship.');
    return;
  }
  const base = baseUrlOf(req);
  const der = STS.certPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const xml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<md:EntityDescriptor xmlns:md="' + NS_MD + '" ' +
      'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ' +
      'entityID="' + xmlEscape(ourEntityId(base, record)) + '">' +
    '<md:SPSSODescriptor AuthnRequestsSigned="' +
      (federation.boolOf(record.fedSignRequest, false) ? 'true' : 'false') + '" ' +
      'WantAssertionsSigned="true" ' +
      'protocolSupportEnumeration="' +
      (record.fedProtocol === 'saml11' ? NS_SAMLP11 : NS_SAMLP) + '">' +
    '<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
      der + '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>' +
    '<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified</md:NameIDFormat>' +
    '<md:AssertionConsumerService Binding="' + BINDING_POST + '" ' +
      'Location="' + xmlEscape(acsUrl(base, record)) + '" index="0" isDefault="true"/>' +
    '</md:SPSSODescriptor></md:EntityDescriptor>';
  logArtifact('federation service provider metadata', 'as served', xml);
  // no-store for the reason every document carrying this service's key gets it:
  // the signing key is regenerated on every start, so a cached copy describes a
  // key that no longer exists.
  res.type('application/samlmetadata+xml').set('Cache-Control', 'no-store').send(xml);
  log.debug('Leaving the federation metadata endpoint.');
});

// ---------------------------------------------------------------------------
// GET /federation — what all of this is.
// ---------------------------------------------------------------------------
app.get(BASE_PATH, function (req, res) {
  log.debug('Entering the federation index.');
  const base = baseUrlOf(req);
  const all = federation.list();
  const consuming = all.filter(function (one) { return one.fedRole === 'service-provider'; });
  const asserting = all.filter(function (one) { return one.fedRole === 'identity-provider'; });

  const consumeRows = consuming.map(function (record) {
    const readiness = federation.readinessOf(record);
    const usable = federation.isUsable(record);
    return '<tr><td><code>' + xmlEscape(record.fedId) + '</code></td>' +
      '<td>' + xmlEscape((federation.protocolRow(record.fedProtocol) || {}).label ||
                         record.fedProtocol) + '</td>' +
      '<td><code>' + xmlEscape(record.fedPeer || '(none set)') + '</code></td>' +
      '<td class="' + (usable ? 'ok' : 'bad') + '">' +
        (usable ? 'ready'
                : (federation.isEnabled(record)
                     ? 'enabled, not configured: ' + xmlEscape(readiness.missing.join(', '))
                     : 'disabled')) + '</td>' +
      '<td>' + (usable
        ? '<a href="' + LOGIN_PATH + '/' + encodeURIComponent(record.fedId) + '">Sign in</a>'
        : '<span class="note">—</span>') +
        ((record.fedProtocol === 'saml2' || record.fedProtocol === 'saml11')
          ? ' · <a href="' + METADATA_PATH + '/' + encodeURIComponent(record.fedId) +
            '">metadata</a>'
          : '') + '</td></tr>';
  }).join('');

  const assertRows = asserting.map(function (record) {
    return '<tr><td><code>' + xmlEscape(record.fedId) + '</code></td>' +
      '<td>' + xmlEscape((federation.protocolRow(record.fedProtocol) || {}).label ||
                         record.fedProtocol) + '</td>' +
      '<td><code>' + xmlEscape(record.fedApplication || '(no application named)') + '</code></td>' +
      '<td>' + (record.fedRelease && record.fedRelease.length
        ? xmlEscape(record.fedRelease.join(', '))
        : '<span class="note">no release policy — this partner gets whatever /admin/claims ' +
          'and /admin/saml-attributes would give anybody</span>') + '</td></tr>';
  }).join('');

  const body = '<h1>Federation</h1>' +
    '<p>This service can be <strong>either end</strong> of a federation relationship, in ' +
    'five protocols: SAML 2.0, SAML 1.1, WS-Federation 1.2, OpenID Connect and OAuth 2.0.</p>' +
    '<p class="note"><strong>This is the one feature here that has to be configured before ' +
    'it will do anything.</strong> Everywhere else this service accepts what it is given — ' +
    'any username, any client_id, any entityID, any LDAP bind. It cannot do that here: what ' +
    'arrives at an assertion consumer service is an unauthenticated request claiming to be a ' +
    'person, and the session it produces is the one every other protocol in this process ' +
    'reads. So a relationship is created DISABLED, and an assertion is refused unless it ' +
    'verifies against the key configured on it.</p>' +
    '<h2>Consuming: a foreign identity provider signs people in here</h2>' +
    (consumeRows
      ? '<table><tr><th>Relationship</th><th>Protocol</th><th>Partner</th><th>State</th>' +
        '<th></th></tr>' + consumeRows + '</table>'
      : '<p class="note">None configured. Add one on ' +
        '<a href="/admin/federation">/admin/federation</a>, or through ' +
        '<code>POST /admin-api/federation/create</code>.</p>') +
    '<h2>Asserting: this service signs people in to a foreign service provider</h2>' +
    (assertRows
      ? '<table><tr><th>Relationship</th><th>Protocol</th><th>Application</th>' +
        '<th>Attributes released</th></tr>' + assertRows + '</table>'
      : '<p class="note">None configured. Every protocol endpoint here already issues to ' +
        'anybody that asks — what an identity-provider-side relationship adds is the ' +
        'partner being marked as a federation partner rather than a test client, and a ' +
        'list of which attributes are released to it.</p>') +
    '<h2>Endpoints</h2><table><tr><th>Path</th><th>What</th></tr>' +
    '<tr><td><code>' + LOGIN_PATH + '/{id}</code></td><td>Start a federated sign-in. Takes ' +
      '<code>?returnTo=</code>, a path on this service to land on afterwards.</td></tr>' +
    '<tr><td><code>' + ACS_PATH + '/{id}</code></td><td>Where the answer comes back: the ' +
      'assertion consumer service, the WS-Federation <code>wreply</code> and the OAuth 2.0 ' +
      '<code>redirect_uri</code>, all one path. <strong>This is the URL to configure at the ' +
      'partner.</strong></td></tr>' +
    '<tr><td><code>' + METADATA_PATH + '/{id}</code></td><td>This service\'s own SAML ' +
      'metadata for that partner. Unsigned, deliberately.</td></tr></table>' +
    '<p class="note">The base URL this service sees itself at is <code>' + xmlEscape(base) +
    '</code>, so the URLs above are absolute from there.</p>' +
    '<p><a href="/admin/federation">Configure relationships in the console</a> · ' +
    '<a href="/authn/login">The sign-in screen</a>' +
    (config.value('federation.loginButtons')
      ? ', which offers every usable partner as a button'
      : ' (federation.loginButtons is off, so no partner is offered there)') + '</p>';
  res.type('html').set('Cache-Control', 'no-store').send(page('Federation', body));
  log.debug('Leaving the federation index.');
});

module.exports = {
  BASE_PATH: BASE_PATH,
  LOGIN_PATH: LOGIN_PATH,
  ACS_PATH: ACS_PATH,
  METADATA_PATH: METADATA_PATH,
  ourEntityId: ourEntityId,
  acsUrl: acsUrl,
  certPemOf: certPemOf
};
