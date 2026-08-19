'use strict';
//
// File: oauth2.js
//
// ===========================================================================
// The endpoints the RFC 8414 metadata advertises.
//
// A dummy authorization server: every endpoint in the metadata document answers,
// and every token it issues is a real RS256 JWT signed with the STS key, so it
// verifies against the JWKS the same document points at (/oauth2/jwks).
//
//   GET  /oauth2/authorize   authorization endpoint (code / implicit / hybrid)
//   POST /oauth2/token       authorization_code, refresh_token, password,
//                            client_credentials, token-exchange
//   *    /oauth2/userinfo    OIDC Core 5.3, on GET and POST — the one protected
//                            endpoint here that verifies the token first
//   POST /oauth2/introspect  RFC 7662
//   POST /oauth2/revoke      RFC 7009
//   *    /oauth2/register    RFC 7591 registration + RFC 7592 management
//   GET  /oauth2/logout      end_session_endpoint (RP-Initiated Logout)
//   GET  /oauth2/jwks        the signing key (above, with the metadata)
//   GET  /docs /policy /tos  the documents the metadata links to
//
// It authenticates NOBODY: the authorization endpoint issues a code for whoever
// asks (the "user" is the login_hint, or a fixed mock subject), and any client
// secret is accepted. That is the point — it exists so the debugger's panes have
// something complete to talk to, not to enforce anything. What it does do
// properly is the mechanics a client can check: PKCE verification, single-use
// authorization codes, real signatures, honest introspection, and revocation
// that actually takes effect.
// ===========================================================================
//
// It also serves BOTH discovery documents — the RFC 8414 metadata and the OpenID
// Provider Configuration an OIDC client looks for — and the JWKS they advertise,
// because those describe THIS server: the endpoints below are the ones the
// metadata promises, and keeping the promise beside the thing that keeps it is
// what stops the two drifting. The OIDC document is the RFC 8414 one extended, for
// the same reason at one remove: two documents describing one server must not be
// two hand-kept copies of the members they share.
//
// The one place it reaches outside itself is the OID4VCI pre-authorized code
// grant: the codes and the issuer_states are minted by the Credential Offer
// (vc_offers.js) and redeemed here, because redeeming a code is a token endpoint's
// job whatever minted it. That is a one-way dependency — the offer module knows
// nothing about this one.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const forge = require('node-forge');
const jwt = require('jsonwebtoken');
const app = require('./app');
const { log, logArtifact, STS, baseUrlOf, b64u, jsonFromB64u, nowSec, randomId,
        xmlEscape, parseBody, oauthError, signJwt, userFor } = require('./helpers');
const dpop = require('./dpop');
// The service's statistics and its ONE set of revoked jtis. It is a library like
// dpop.js — it registers nothing and requires only helpers.js — so requiring it
// here cannot create a cycle. The revocation set used to be a Set in this file;
// see the comment where it was, below.
const stats = require('./admin_stats');
const { VCI_CONFIGS, VCI_CONFIG_ID, VCI_SCOPE, vciFormatOf } = require('./vc_configs');
// For one thing: checking a wallet's requested claim paths against the ones this
// issuer's metadata advertises for that credential's format. A library that
// registers no route, so this adds nothing to the require order.
const vcClaims = require('./vc_claims');
const { deferredAccessTokens, issuerStates, preAuthorizedCodes } = require('./vc_offers');
// The authentication service. It requires nothing from this module, which is
// what makes this a one-way dependency: a protocol asks it to authenticate
// somebody and is handed them back with a session.
const authn = require('./authn');
const { sessionOf, endSession } = authn;
// ---------------------------------------------------------------------------
// RFC 8414 — OAuth 2.0 Authorization Server Metadata
//
// A dummy metadata document with EVERY member RFC 8414 section 2 defines
// populated, so the debugger's Configuration Parameters pane can be filled from
// a real endpoint. Served at the well-known path from section 3, and also with
// an issuer path component appended (section 3.1) so both shapes resolve.
//
// The issuer and every endpoint are derived from the URL the request arrived
// on, so the document is self-consistent whether it is reached as
// http://localhost:8081 (host) or http://sts:8081 (compose network).
// ---------------------------------------------------------------------------
function asMetadata(req) {
  log.debug("Entering asMetadata().");
  const base = baseUrlOf(req);
  const metadata = {
    // --- REQUIRED ---
    issuer: base,
    authorization_endpoint: base + '/oauth2/authorize',
    token_endpoint: base + '/oauth2/token',
    // Every combination the authorization endpoint actually issues: it splits
    // response_type on whitespace and accepts any mixture of code, token and
    // id_token, so `id_token token` belongs here too — OpenID Connect Dynamic
    // Registration names it as one an OP should support, and leaving it out of
    // the list while honouring it is the same drift as the reverse.
    response_types_supported: ['code', 'token', 'id_token', 'code token', 'code id_token',
                               'id_token token', 'code id_token token'],
    // --- RECOMMENDED / OPTIONAL ---
    jwks_uri: base + '/oauth2/jwks',
    registration_endpoint: base + '/oauth2/register',
    // `address` and `phone` were listed here and are gone: OIDC Core section 5.4
    // makes each of these scopes a request for a NAMED set of claims, and userFor()
    // mints no address and no phone_number, so the two were a promise of claims
    // that could never arrive. It reads as an omission next to the
    // claims_supported list in the OIDC document, which is the whole reason the
    // two documents are built from this one object.
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    // query and fragment only. `form_post` was advertised here and is NOT
    // implemented: redirectBack() answers every authorization request with a 302
    // to the redirect_uri, so a client that asked for form_post would be sent a
    // redirect anyway and would sit waiting for a POST that never arrives. A
    // metadata member is a promise the endpoint has to keep, and the failure of
    // this particular one is silent at the client end, which is the worst kind.
    response_modes_supported: ['query', 'fragment'],
    // Only what the token endpoint below actually implements — the metadata
    // should not promise a grant this server would refuse. (No device_code:
    // there is no device authorization endpoint to start that flow.)
    grant_types_supported: ['authorization_code', 'implicit', 'refresh_token', 'client_credentials',
                            'password', 'urn:ietf:params:oauth:grant-type:token-exchange',
                            // OID4VCI's pre-authorized code grant, which the
                            // cross-device Credential Offers use.
                            'urn:ietf:params:oauth:grant-type:pre-authorized_code'],
    // RFC 9396. OID4VCI's other way of saying which credential is wanted:
    // authorization_details of type openid_credential, instead of a scope.
    authorization_details_types_supported: ['openid_credential'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post',
                                            'client_secret_jwt', 'private_key_jwt', 'none'],
    token_endpoint_auth_signing_alg_values_supported: ['RS256', 'RS384', 'RS512', 'ES256', 'PS256', 'HS256'],
    service_documentation: base + '/docs',
    // One locale, because there is one: the login screen is the only UI this
    // server renders and it is written in English, and nothing here reads the
    // ui_locales request parameter. The list used to name four, which a client
    // is entitled to read as "ask for fr-CA and you will get it".
    ui_locales_supported: ['en-US'],
    op_policy_uri: base + '/policy',
    op_tos_uri: base + '/tos',
    revocation_endpoint: base + '/oauth2/revoke',
    revocation_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'private_key_jwt'],
    revocation_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256', 'PS256'],
    introspection_endpoint: base + '/oauth2/introspect',
    introspection_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'private_key_jwt'],
    introspection_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256', 'PS256'],
    code_challenge_methods_supported: ['S256', 'plain'],
    // RFC 9207. redirectBack() puts `iss` on every authorization response this
    // server sends, success and error alike, so this is simply true — and it was
    // true and unadvertised, which is the half that buys a client nothing: a
    // client only knows it may REQUIRE the parameter (and so refuse a mix-up
    // attacker's response that lacks it) if the metadata says the server sends it.
    authorization_response_iss_parameter_supported: true,
    // RFC 9449 section 5.1. Its presence is how a wallet learns DPoP is on offer
    // at all — there is no other signal, so an authorization server that supports
    // DPoP and does not advertise it will simply never be asked for it.
    dpop_signing_alg_values_supported: dpop.SIGNING_ALGS
    // signed_metadata is added below — it is a JWT OF this object, so it cannot
    // be one of the claims it signs.
  };
  log.debug("Leaving asMetadata().");
  return metadata;
}

// RFC 8414 section 2.1: signed_metadata is a JWT whose claims are the metadata
// members, signed by the issuer, and carrying iss and sub. Genuinely signed
// with the STS key so it can be verified (public key at /sts/cert, JWKS below).
function signedMetadata(meta) {
  log.debug("Entering signedMetadata().");
  const claims = Object.assign({}, meta, { sub: meta.issuer });
  logArtifact('RFC 8414 signed_metadata', 'before signing', claims);
  try {
    const signed = jwt.sign(claims, STS.privateKeyPem,
      { algorithm: 'RS256', issuer: meta.issuer, expiresIn: 3600, keyid: STS.kid });
    logArtifact('RFC 8414 signed_metadata', 'after signing', signed);
    log.debug("Leaving signedMetadata().");
    return signed;
  } catch (e) {
    log.error('signed_metadata: ' + e.message);
    log.debug("Leaving signedMetadata(). Nothing was signed.");
    return undefined;
  }
}

function sendAsMetadata(req, res) {
  log.debug("Entering sendAsMetadata().");
  const meta = asMetadata(req);
  const signed = signedMetadata(meta);
  if (signed) meta.signed_metadata = signed;
  res.status(200).type('application/json').set('Cache-Control', 'no-store').send(JSON.stringify(meta, null, 2));
  log.debug("Leaving sendAsMetadata().");
}

app.get('/.well-known/oauth-authorization-server', sendAsMetadata);

// Issuer-with-path form, e.g. /.well-known/oauth-authorization-server/tenant1.
app.get('/.well-known/oauth-authorization-server/*', sendAsMetadata);

// ---------------------------------------------------------------------------
// OpenID Connect Discovery 1.0 — GET /.well-known/openid-configuration
//
// The OTHER discovery document, and the one most OIDC clients look for first:
// a relying party given nothing but an issuer identifier finds this path and
// expects everything it needs to be in what comes back. Without it this server
// spoke OIDC — id_token, nonce, at_hash, c_hash, three flows — and could not be
// CONFIGURED by an OIDC client, which is a strange thing for a mock whose whole
// job is to be pointed at by clients.
//
// **It is built by extending the RFC 8414 document rather than beside it.** The
// two documents describe one server, they overlap in about twenty members, and
// two hand-kept copies of twenty members disagree the first time somebody edits
// one of them — a client configured from openid-configuration would then behave
// differently from one configured from oauth-authorization-server against the
// same endpoints, and nothing would report it. So asMetadata() is the single
// source and this function adds only what OpenID Connect Discovery defines on
// top of it. RFC 8414 was written from this document and the member names are
// the same registry, so the overlap is genuine and not a coincidence worth
// preserving by hand.
//
// What is DELIBERATELY ABSENT, since a discovery document is read as a promise:
//
//   * `acr_values_supported`, `display_values_supported`, the id_token and
//     userinfo ENCRYPTION members, `check_session_iframe`: none are implemented,
//     and an empty or invented value for any of them is worse than the member's
//     absence, which says exactly the right thing.
//   * WebFinger (section 2). Issuer discovery from an e-mail address is a
//     separate endpoint (/.well-known/webfinger) and this service does not have
//     one; the issuer is expected to be known already.
//
// One honesty note that has no metadata member to live in, so it lives here:
// claims_supported below is the exact set idToken() emits, not a menu, and the
// id_token carries all of it whatever scope was asked for. The UserInfo endpoint
// is the one place a scope changes the answer (section 5.4), so the two can
// return different subsets of the same list — which is what that section
// describes rather than a disagreement between them.
// ---------------------------------------------------------------------------
function oidcMetadata(req, issuer) {
  log.debug("Entering oidcMetadata(). issuer=" + (issuer || '(the request base URL)'));
  const base = baseUrlOf(req);
  const metadata = Object.assign(asMetadata(req), {
    // --- REQUIRED by OpenID Connect Discovery 1.0 section 3 -----------------
    // issuer, authorization_endpoint, token_endpoint, jwks_uri and
    // response_types_supported come from the RFC 8414 document above.
    //
    // RECOMMENDED, and here: the section 5.3 UserInfo Endpoint. It is a
    // protected resource, it accepts a Bearer or a DPoP-bound token through the
    // same check as every other protected endpoint in this service, and — unlike
    // them — it verifies the token before answering, because a profile is a
    // statement about somebody this server authenticated.
    userinfo_endpoint: base + '/oauth2/userinfo',
    // Section 5.3.2's signed response, offered because RFC 7591 registration is
    // offered: a client that registers `userinfo_signed_response_alg: "RS256"`
    // gets `application/jwt` back, signed with the same key as everything else.
    // `none` is the default and means the plain JSON of section 5.3.2.
    userinfo_signing_alg_values_supported: ['RS256', 'none'],
    //
    // `public`: the `sub` userFor() mints is urn:sts-mock:user:<username> and is
    // the same value for every client that asks, which is what public MEANS.
    // Claiming `pairwise` would be a claim about a calculation this server does
    // not perform.
    subject_types_supported: ['public'],
    // Every JWT this service signs goes through signJwt(), which is RS256 and
    // only RS256. The id_token is not encrypted, so there is no *_enc member.
    id_token_signing_alg_values_supported: ['RS256'],

    // --- RECOMMENDED / OPTIONAL, and true of this server --------------------
    // Exactly what idToken() puts in the token, in the order it puts it there.
    // A client can read this list and know that asking for anything else — an
    // address, a phone number, an acr — gets it nothing.
    claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'auth_time', 'nonce', 'azp',
                       'jti', 'at_hash', 'c_hash', 'name', 'given_name', 'family_name',
                       'preferred_username', 'email', 'email_verified'],
    claim_types_supported: ['normal'],
    // Three parameters this server reads and three it does not, stated as the
    // booleans the specification defines rather than left to a client to
    // discover by sending one and watching it be ignored. The authorization
    // endpoint honours prompt=none and prompt=login (and nothing else), and it
    // does not accept a `claims` parameter, a `request` object or a `request_uri`
    // — which is the same "no request object here" the /sts-metadata coverage
    // note already says in prose.
    prompt_values_supported: ['none', 'login'],
    claims_parameter_supported: false,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
    // Moot while request_uri_parameter_supported is false, and stated anyway:
    // the member's default is true, so leaving it out would have this server
    // promising to enforce a registration requirement it has no code for.
    require_request_uri_registration: false,
    // OpenID Connect RP-Initiated Logout 1.0. /oauth2/logout drops the session
    // cookie and returns to post_logout_redirect_uri — but it neither requires
    // nor checks id_token_hint, and it does not validate the redirect target
    // against anything, so this is the shape of RP-initiated logout rather than
    // its security. It is advertised because the alternative is a client with no
    // way to end a session that this server really does end.
    end_session_endpoint: base + '/oauth2/logout',
    // Neither logout notification specification is implemented: no front-channel
    // iframe is rendered and no back-channel POST is sent. Both members default
    // to false, and both are stated because "the OP did not mention it" and "the
    // OP said no" read identically to a client and only one of them is a fact
    // this server is prepared to stand behind.
    frontchannel_logout_supported: false,
    backchannel_logout_supported: false
  });
  // The path-appended form's issuer (see below). Assigned after the merge so it
  // replaces the base URL asMetadata() derived, and assigned rather than merged
  // so the member keeps its position at the top of the document.
  if (issuer) metadata.issuer = issuer;
  log.debug("Leaving oidcMetadata(). " + Object.keys(metadata).length + " member(s).");
  return metadata;
}

// signed_metadata is an RFC 8414 member and OpenID Connect Discovery does not
// define it. It is included anyway: the two documents share one member registry,
// an OIDC client ignores members it does not know, and a signed copy of THIS
// document — the OIDC members included — is the only way to check that what
// arrived is what the issuer published.
function sendOidcMetadata(req, res, issuer) {
  log.debug("Entering sendOidcMetadata().");
  const meta = oidcMetadata(req, issuer);
  const signed = signedMetadata(meta);
  if (signed) meta.signed_metadata = signed;
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(meta, null, 2));
  log.debug("Leaving sendOidcMetadata().");
}

app.get('/.well-known/openid-configuration', function (req, res) {
  log.debug("Entering the OpenID Connect Discovery endpoint.");
  sendOidcMetadata(req, res);
  log.debug("Leaving the OpenID Connect Discovery endpoint.");
});

// ---------------------------------------------------------------------------
// An issuer identifier with a path component, which the two specifications
// resolve to two DIFFERENT URLs — the single most common reason a discovery
// fetch 404s, so both are served.
//
//   OpenID Connect Discovery 1.0 section 4  APPENDS:  https://host/tenant1/.well-known/openid-configuration
//   RFC 8414 section 3.1                    INSERTS:  https://host/.well-known/openid-configuration/tenant1
//
// The appended form gets the issuer it was asked for, built back up from the path
// the request arrived on: that shape exists precisely so a multi-tenant server can
// answer for one tenant, and a document at /tenant1/... claiming to be issued by
// https://host is one a conforming client MUST reject (the issuer has to match the
// one the URL was built from). The endpoints inside it stay where they really are,
// since nothing requires them to live under the issuer.
//
// The inserted form is the RFC 8414 shape and is answered the way the
// oauth-authorization-server route above answers it — with the request's base URL
// as the issuer — so the two behave alike.
// ---------------------------------------------------------------------------
app.get('/.well-known/openid-configuration/*', function (req, res) {
  log.debug("Entering the OpenID Connect Discovery endpoint (RFC 8414 inserted-path form).");
  sendOidcMetadata(req, res);
  log.debug("Leaving the OpenID Connect Discovery endpoint (RFC 8414 inserted-path form).");
});

app.get('/*/.well-known/openid-configuration', function (req, res) {
  log.debug("Entering the OpenID Connect Discovery endpoint (issuer-path form).");
  // req.params[0] is everything before /.well-known — the issuer's path
  // component, one segment or several.
  const path = String(req.params[0] || '').replace(/^\/+|\/+$/g, '');
  sendOidcMetadata(req, res, baseUrlOf(req) + (path ? '/' + path : ''));
  log.debug("Leaving the OpenID Connect Discovery endpoint (issuer-path form). path=" + path);
});

// The JWKS the metadata advertises, so jwks_uri actually resolves: the STS
// signing key as a single RS256 JWK.
app.get('/oauth2/jwks', function (req, res) {
  log.debug("Entering the JWKS endpoint.");
  try {
    const pub = forge.pki.certificateFromPem(STS.certPem).publicKey;
    const b64u = function (hex) {
      return Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    res.status(200).type('application/json').set('Cache-Control', 'no-store').send(JSON.stringify({
      keys: [{
        kty: 'RSA', use: 'sig', alg: 'RS256', kid: STS.kid,
        n: b64u(pub.n.toString(16)), e: b64u(pub.e.toString(16)),
        x5c: [STS.certB64]
      }]
    }, null, 2));
    log.debug("Leaving the JWKS endpoint.");
  } catch (e) {
    log.error('could not publish the JWKS: ' + e.message);
    res.status(500).type('application/json').send(JSON.stringify({ error: e.message }));
    log.debug("Leaving the JWKS endpoint. It failed.");
  }
});

const ACCESS_TOKEN_TTL = 3600;

const REFRESH_TOKEN_TTL = 30 * 24 * 3600;

const AUTH_CODE_TTL_MS = 5 * 60 * 1000;

const authzCodes = new Map();       // code -> the authorization request it came from

// ---------------------------------------------------------------------------
// NON-SPEC: what happens when the SAME authorization code arrives twice.
//
// RFC 6749 section 4.1.2 says a code is single use, and section 10.5 says a
// second presentation SHOULD invalidate what the first one issued. A real
// authorization server does exactly that, and so did this one: the record was
// deleted the moment it was looked up, so EVERY second Token Request carrying
// that code — a reloaded debugger2.html, a double-submitted form, a retry
// after a PKCE or redirect_uri check refused the first attempt — was answered
// with "Unknown or already-used authorization code". That sentence is equally
// true of a stolen code and of a browser that asked twice, and it says nothing
// about which one happened, which is the wrong trade for a service whose whole
// job is to show what occurred.
//
// So redemption here is IDEMPOTENT for as long as the code would have been
// valid anyway: the token set a code was redeemed for is kept for the rest of
// that code's own five-minute lifetime, and a repeat of the SAME request —
// same client, same redirect_uri, same PKCE verifier, same DPoP key — is
// answered with the tokens it already got. Nothing new is minted, so the
// second answer IS the first answer, down to the jti.
//
// It is not a way to redeem somebody else's code. Anything about the request
// that differs is refused and the difference is named; once the code's own
// lifetime is over, so is the replay; and both refusals now say when the code
// was redeemed and by which client, which is the fact the old message was
// missing. What is remembered is kept a further five minutes past the code's
// expiry PURELY so that those sentences can still be written.
//
// The pre-authorized code grant further down is deliberately NOT relaxed: its
// single use is a property of the Credential Offer under test, and
// tests/sd_jwt_vc_issuance.js asserts that a replayed offer is refused.
// ---------------------------------------------------------------------------
const redeemedCodes = new Map();    // code -> the token set it was redeemed for

// The browser session, the login screen it comes out of and the WebAuthn step
// beside it all used to be declared here. They are `authn.js` now — see its
// header for why, and note that this module reads the session and never writes
// one: authenticating is somebody else's endpoint.

// Which tokens are no longer valid. This was a `new Set()` here, and it moved into
// admin_stats.js when the admin console gained a page that revokes tokens too:
// there must be exactly ONE set, because two would each look correct alone and
// never see each other — a token revoked from the console would keep introspecting
// as active, and there would be no error anywhere to point at. It is the same
// reasoning that keeps WS-Federation out of a session store of its own.
//
// Read in four places (UserInfo, introspection, the refresh grant, and the console)
// and written in two (RFC 7009's /oauth2/revoke below, and the console).

const registeredClients = new Map();// client_id -> { metadata, registrationAccessToken }

// Client credentials from either client_secret_basic or client_secret_post. No
// secret is ever checked; what matters is which client is being claimed.
function clientFrom(req, body) {
  log.debug("Entering clientFrom().");
  const auth = req.headers['authorization'] || '';
  if (/^Basic\s+/i.test(auth)) {
    try {
      const decoded = Buffer.from(auth.replace(/^Basic\s+/i, ''), 'base64').toString('utf8');
      const i = decoded.indexOf(':');
      const client = { client_id: decodeURIComponent(i < 0 ? decoded : decoded.slice(0, i)) };
      log.debug("Leaving clientFrom(). client_secret_basic named " + client.client_id + ".");
      return client;
    } catch (e) {
      log.error('could not read the Basic credential: ' + e.message);
      // Fall through to the form parameter.
    }
  }
  log.debug("Leaving clientFrom(). client_id from the body: " + (body.client_id || '(none)'));
  return { client_id: body.client_id || '' };
}

// What a custom claim's ${placeholders} may refer to. Built from the payload that
// is about to be signed rather than from the request, so a claim reading
// "${sub}" says what the token itself says — including under token exchange,
// where the subject is not the person who signed in.
//
// Refresh tokens get no custom claims and that is deliberate: a refresh token is
// presented back to this server and to nothing else, so a claim in one reaches no
// relying party and would only make the two halves of a grant disagree.
function customClaimContext(base, payload, user) {
  return {
    username: (user && user.username) || payload.username || '',
    sub: payload.sub || '',
    email: (user && user.email) || '',
    name: (user && user.name) || '',
    given_name: (user && user.given_name) || '',
    family_name: (user && user.family_name) || '',
    client_id: payload.client_id || payload.azp || '',
    audience: Array.isArray(payload.aud) ? payload.aud.join(' ') : (payload.aud || base || '')
  };
}

// What the token registry is told that the token itself does not say: which browser
// sign-on session this issuance ran on, and which grant produced it. Neither is a
// claim — see the note on signJwt() — and both are what let the admin console's user
// drill-down put a token under the session it belongs to. A call site that leaves
// `session_id` out is stating that there was no session, which is true of every
// direct grant, and the console prints that rather than "unknown".
function issuanceContext(opts) {
  return { sessionId: (opts && opts.session_id) || '', grant: (opts && opts.grant) || '' };
}

function accessToken(base, opts) {
  log.debug("Entering accessToken().");
  const iat = nowSec();
  const user = opts.user || userFor(opts.username);
  const payload = {
    iss: base, sub: opts.sub || user.sub, aud: opts.audience || base + '/resource',
    client_id: opts.client_id, scope: opts.scope || '', typ: 'Bearer',
    jti: randomId(16), iat: iat, nbf: iat, exp: iat + ACCESS_TOKEN_TTL,
    username: user.username
  };
  if (opts.act) payload.act = opts.act;
  // RFC 9449 section 6.1: a DPoP-bound access token names the key it is bound to
  // in the `cnf.jkt` confirmation claim (RFC 7800's `cnf`, with RFC 9449's `jkt`
  // member). The claim travels INSIDE the signed token, which is what lets a
  // resource server check the binding without asking the authorization server
  // anything — and what stops the wallet nominating its own key.
  if (opts.jkt) payload.cnf = { jkt: opts.jkt };
  // OID4VCI section 6.2: when the authorization was expressed as
  // authorization_details, the token response grants credential_identifiers and
  // the Credential Request must use one of them. They ride in the access token
  // so the credential endpoint can verify one without consulting any state — the
  // token is signed, so the wallet cannot award itself an identifier.
  if (opts.authorization_details) payload.authorization_details = opts.authorization_details;
  // Whatever the admin console was told to add — see admin_stats.js. The merge is
  // this way round, custom claims UNDER the protocol's own, so that a claim the
  // console somehow accepted which collides with one of these loses. The console
  // refuses the reserved names outright, so this is the second of two defences
  // rather than the only one; a token whose `exp` came from a web form would fail
  // to verify with nothing anywhere pointing back at the form.
  const payloadWithCustom = Object.assign(
    stats.jwtClaims('access_token', customClaimContext(base, payload, user)), payload);
  const token = signJwt(payloadWithCustom, issuanceContext(opts));
  log.debug("Leaving accessToken().");
  return token;
}

function refreshToken(base, opts) {
  log.debug("Entering refreshToken().");
  const iat = nowSec();
  const user = opts.user || userFor(opts.username);
  const token = signJwt({
    // username travels with the refresh token, so refreshing keeps describing
    // the person who actually signed in.
    iss: base, sub: opts.sub || user.sub, aud: base, client_id: opts.client_id,
    scope: opts.scope || '', typ: 'Refresh', jti: randomId(16), username: user.username,
    iat: iat, nbf: iat, exp: iat + REFRESH_TOKEN_TTL,
    // RFC 9449 section 5: a refresh token issued to a PUBLIC client alongside a
    // DPoP-bound access token is itself bound to the same key. A wallet is a
    // public client and cannot authenticate, so without this the long-lived half
    // of the grant would stay a bearer credential and binding the short-lived
    // half would buy very little. The refresh grant enforces it, which is what
    // makes the OID4VCI section 14.5 refresh on step 4 carry a proof of its own.
    cnf: opts.jkt ? { jkt: opts.jkt } : undefined,
    // What this grant authorized in OID4VCI terms — the Credential Dataset
    // identifiers and, where the wallet asked for one, its claims selection.
    // Carried here because the refresh grant reads it back off this token: the
    // access token it mints has to authorize the same credential, or a section
    // 14.5 refresh would be refused by the credential endpoint for naming an
    // identifier "that was not granted".
    authorization_details: opts.authorization_details || undefined
  }, issuanceContext(opts));
  log.debug("Leaving refreshToken().");
  return token;
}

// OIDC section 3.1.3.6: at_hash / c_hash are the base64url of the left half of
// the SHA-256 of the ASCII of the token.
function halfHash(value) {
  log.debug("Entering halfHash().");
  const h = crypto.createHash('sha256').update(String(value), 'ascii').digest();
  log.debug("Leaving halfHash().");
  return b64u(h.subarray(0, h.length / 2));
}

function idToken(base, opts) {
  log.debug("Entering idToken().");
  const iat = nowSec();
  const user = opts.user || userFor(opts.username);
  const payload = {
    iss: base, sub: opts.sub || user.sub, aud: opts.client_id, typ: 'ID',
    iat: iat, nbf: iat, exp: iat + ACCESS_TOKEN_TTL, auth_time: opts.auth_time || iat,
    azp: opts.client_id, jti: randomId(16),
    name: user.name, given_name: user.given_name, family_name: user.family_name,
    preferred_username: user.preferred_username, email: user.email,
    email_verified: user.email_verified
  };
  // How the End-User authenticated, and to what level. RFC 8176 for amr; `hwk`
  // is proof of possession of a hardware key, which is what a WebAuthn
  // assertion demonstrates. A relying party that asked for a second factor
  // through acr_values checks these — so they are emitted whenever the session
  // recorded them, and their absence is then meaningful rather than ambiguous.
  if (opts.amr) payload.amr = opts.amr;
  if (opts.acr) payload.acr = opts.acr;
  if (opts.nonce) payload.nonce = opts.nonce;
  if (opts.access_token) payload.at_hash = halfHash(opts.access_token);
  if (opts.code) payload.c_hash = halfHash(opts.code);
  // The ID Token's own custom claim set, separate from the access token's: the two
  // go to different readers (a client reads the ID Token, a resource server reads
  // the access token) and configuring them together would mean never being able to
  // test that a claim reached one and not the other.
  const payloadWithCustom = Object.assign(
    stats.jwtClaims('id_token', customClaimContext(base, payload, user)), payload);
  const token = signJwt(payloadWithCustom, issuanceContext(opts));
  log.debug("Leaving idToken().");
  return token;
}

function hasScope(scope, name) {
  return String(scope || '').split(/\s+/).indexOf(name) >= 0;
}

function tokenSet(base, opts) {
  log.debug("Entering tokenSet(). scope=" + (opts.scope || '(none)'));
  const access = accessToken(base, opts);
  const body = {
    access_token: access,
    // RFC 9449 section 5: `DPoP`, not `Bearer`, when the token is bound. This is
    // how the wallet learns it must send a proof on every subsequent call — a
    // bound token announced as Bearer would be presented as one and refused.
    token_type: opts.jkt ? 'DPoP' : 'Bearer',
    expires_in: ACCESS_TOKEN_TTL,
    scope: opts.scope || ''
  };
  if (opts.authorization_details) body.authorization_details = opts.authorization_details;
  if (opts.withRefresh !== false) body.refresh_token = refreshToken(base, opts);
  if (hasScope(opts.scope, 'openid')) {
    body.id_token = idToken(base, Object.assign({}, opts, { access_token: access }));
  }
  log.debug("Leaving tokenSet(). Issued: " + Object.keys(body).join(', '));
  return body;
}

// --- the authorization endpoint ----------------------------------------------
// A browser flow, so it behaves like one: an unauthenticated request is sent to
// the AUTHENTICATION SERVICE (authn.js), and only once the person comes back
// signed in does this endpoint issue the authorization code (or the
// implicit/hybrid tokens) and redirect back to the client.
//
//   GET /oauth2/authorize   no session  -> 302 to /authn/login, with a return
//                                          URL carrying this request whole
//                           session     -> issue and redirect to redirect_uri
//
// So the endpoint is entered TWICE for a sign-in and once afterwards, and the
// second entry is the first request over again — which is exactly what makes it
// safe to keep no state here: everything the response is built from is on the
// query string both times.
//
// No password is checked over there — the username typed in is simply who the
// tokens then describe. A session cookie means the next authorization request
// does not prompt again; prompt=login forces it to, and is dropped from the
// return URL so that it forces it exactly once.
// the redirect back after login is the same request over again.
function queryString(query, omit) {
  log.debug("Entering queryString().");
  const usp = new URLSearchParams();
  Object.keys(query).forEach(function (k) {
    if (omit && omit.indexOf(k) >= 0) return;
    usp.set(k, query[k]);
  });
  log.debug("Leaving queryString().");
  return usp.toString();
}

// Build the authorization response for a signed-in user and redirect back to
// the client. Everything after authentication — which is "as normal".
// authorization_details (RFC 9396) as OID4VCI uses it: an array of objects of
// type openid_credential, each naming a credential_configuration_id. Unreadable
// JSON is not silently dropped — a wallet that sent nonsense should be told.
// The OPTIONAL `claims` member of an openid_credential authorization detail
// (OID4VCI section 5.1.1): which claims the Wallet wants the issued Credential
// to carry, as claims description objects (Appendix A.1) holding claims path
// pointers (Appendix B).
//
// Three kinds of refusal, and each is a refusal rather than a silent drop for
// the same reason the type check above is: a wallet whose selection was quietly
// ignored gets a credential carrying claims it did not ask for and no way to
// discover why.
//
//   * a shape Appendix A.1 does not allow — a path that is not a non-empty array
//     of strings, nulls and integers;
//   * a repeated claim, which Appendix A.3 says MUST abort the processing;
//   * a path this issuer does not advertise for that credential's format, which
//     is the one check that is this issuer's own. Its metadata says what it can
//     put in a credential; honouring a request for anything else would mean
//     issuing a credential the wallet was told was impossible, or (more likely)
//     issuing one silently missing the claim.
//
// Absent is not empty: `{ claims: null }` means the wallet expressed no
// preference and gets everything, which is what every authorization made before
// this member existed did.
function parseClaimsDescriptions(raw, configId) {
  log.debug("Entering parseClaimsDescriptions(). configId=" + configId);
  if (raw === undefined || raw === null) {
    log.debug("Leaving parseClaimsDescriptions(). No claims member.");
    return { claims: null };
  }
  if (!Array.isArray(raw) || !raw.length) {
    log.debug("Leaving parseClaimsDescriptions(). Not a non-empty array.");
    return { error: 'the claims member of an authorization detail must be a non-empty array of ' +
                    'claims description objects (OID4VCI Appendix A.1).' };
  }
  const out = [];
  const seen = new Set();
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (!c || typeof c !== 'object' || Array.isArray(c)) {
      log.debug("Leaving parseClaimsDescriptions(). Entry " + i + " is not an object.");
      return { error: 'claims[' + i + '] is not a claims description object.' };
    }
    const path = c.path;
    if (!Array.isArray(path) || !path.length) {
      log.debug("Leaving parseClaimsDescriptions(). Entry " + i + " has no usable path.");
      return { error: 'claims[' + i + '].path must be a non-empty claims path pointer array ' +
                      '(OID4VCI Appendix B).' };
    }
    const badPart = path.findIndex(function (part) {
      return !(typeof part === 'string' || part === null || Number.isInteger(part));
    });
    if (badPart >= 0) {
      log.debug("Leaving parseClaimsDescriptions(). Entry " + i + " has a bad path component.");
      return { error: 'claims[' + i + '].path[' + badPart + '] must be a string, null or an ' +
                      'integer (OID4VCI Appendix B).' };
    }
    const key = vcClaims.pathKey(path);
    if (seen.has(key)) {
      log.debug("Leaving parseClaimsDescriptions(). Entry " + i + " repeats a claim.");
      return { error: 'the claim ' + key + ' is described twice; OID4VCI Appendix A.3 says a ' +
                      'repeated claims description MUST abort the processing.' };
    }
    seen.add(key);
    const entry = { path: path.slice() };
    if (c.mandatory !== undefined) {
      if (typeof c.mandatory !== 'boolean') {
        log.debug("Leaving parseClaimsDescriptions(). Entry " + i + " has a non-boolean mandatory.");
        return { error: 'claims[' + i + '].mandatory must be a boolean.' };
      }
      entry.mandatory = c.mandatory;
    }
    out.push(entry);
  }
  const unknown = vcClaims.unknownPaths(out.map(function (c) { return c.path; }),
                                        vciFormatOf(configId));
  if (unknown.length) {
    log.debug("Leaving parseClaimsDescriptions(). " + unknown.length + " unadvertised path(s).");
    return { error: 'this issuer does not advertise ' +
                    unknown.map(vcClaims.pathKey).join(', ') + ' for credential_configuration_id "' +
                    configId + '". Its metadata lists the claims it can carry in ' +
                    'credential_configurations_supported.' };
  }
  log.debug("Leaving parseClaimsDescriptions(). " + out.length + " claim(s) requested.");
  return { claims: out };
}

function parseAuthorizationDetails(raw) {
  log.debug("Entering parseAuthorizationDetails().");
  if (!raw) {
    log.debug("Leaving parseAuthorizationDetails(). None were sent.");
    return { details: null };
  }
  let parsed;
  try {
    parsed = JSON.parse(String(raw));
  } catch (e) {
    log.debug("Leaving parseAuthorizationDetails(). Not JSON: " + e.message);
    return { error: 'authorization_details is not readable JSON: ' + e.message };
  }
  if (!Array.isArray(parsed)) {
    log.debug("Leaving parseAuthorizationDetails(). Not an array.");
    return { error: 'authorization_details must be a JSON array.' };
  }
  const wanted = [];
  for (let i = 0; i < parsed.length; i++) {
    const d = parsed[i] || {};
    if (d.type !== 'openid_credential') {
      log.debug("Leaving parseAuthorizationDetails(). Unsupported type: " + d.type);
      return { error: 'authorization_details type "' + d.type + '" is not supported; ' +
                      'this issuer understands openid_credential.' };
    }
    const configId = d.credential_configuration_id;
    if (configId && !VCI_CONFIGS[configId]) {
      log.debug("Leaving parseAuthorizationDetails(). Unknown configuration: " + configId);
      return { error: 'credential_configuration_id "' + configId + '" is not one this issuer offers.' };
    }
    const entry = { type: 'openid_credential', credential_configuration_id: configId || VCI_CONFIG_ID };
    const claims = parseClaimsDescriptions(d.claims, entry.credential_configuration_id);
    if (claims.error) {
      log.debug("Leaving parseAuthorizationDetails(). " + claims.error);
      return { error: claims.error };
    }
    if (claims.claims) entry.claims = claims.claims;
    wanted.push(entry);
  }
  log.debug("Leaving parseAuthorizationDetails(). " + wanted.length + " detail(s).");
  return { details: wanted.length ? wanted : null };
}

function issueAuthorizationResponse(req, res, query, user, authTime, authInfo) {
  const amr = (authInfo && authInfo.amr) || null;
  const acr = (authInfo && authInfo.acr) || null;
  // The session this response is being issued ON. Every path into this function has
  // one — an unauthenticated request is shown the login screen instead — so an empty
  // id here would mean a session object arrived from somewhere that did not make it,
  // which is worth seeing on the console rather than defaulting quietly.
  const sessionId = (authInfo && authInfo.id) || '';
  log.debug("Entering issueAuthorizationResponse(). response_type=" + (query.response_type || '(none)') +
            ", user=" + user.username);
  const base = baseUrlOf(req);
  const redirectUri = String(query.redirect_uri);
  const types = String(query.response_type || '').split(/\s+/).filter(Boolean);
  const scope = String(query.scope || 'openid');
  const out = {};
  const parsedDetails = parseAuthorizationDetails(query.authorization_details);
  if (parsedDetails.error) {
    log.debug("Leaving issueAuthorizationResponse(). " + parsedDetails.error);
    return redirectBack(res, base, redirectUri, query.state,
      { error: 'invalid_authorization_details', error_description: parsedDetails.error },
      types.length > 1 || types.indexOf('code') < 0);
  }
  const authorizationDetails = parsedDetails.details;
  if (authorizationDetails) {
    logArtifact('authorization_details', 'as requested', authorizationDetails);
  }

  if (types.indexOf('code') >= 0) {
    const code = randomId(24);
    authzCodes.set(code, {
      client_id: String(query.client_id), redirect_uri: redirectUri, scope: scope,
      nonce: query.nonce, user: user, auth_time: authTime, amr: amr, acr: acr,
      // Carried on the code so that the tokens the code is redeemed for can name the
      // session it was issued on. It is the only route between the two: the code
      // arrives at the token endpoint with no cookie behind it, and a browser session
      // cannot be inferred from a back-channel request.
      session_id: sessionId,
      code_challenge: query.code_challenge, code_challenge_method: query.code_challenge_method || 'plain',
      // RFC 9449 section 10: the JWK Thumbprint of the DPoP key the client
      // intends to use, taken at the authorization request so the code itself is
      // bound. Stored verbatim and never derived — the whole value of the
      // parameter is that it was fixed BEFORE the code existed.
      dpop_jkt: query.dpop_jkt ? String(query.dpop_jkt) : '',
      // What the wallet asked to be authorized for, if it used
      // authorization_details rather than a scope. The token response has to
      // echo it back with the credential_identifiers it grants.
      authorization_details: authorizationDetails,
      expires: Date.now() + AUTH_CODE_TTL_MS
    });
    out.code = code;
  }
  // Which grant the console will say issued these. A response carrying a code AND a
  // token is the hybrid flow rather than the implicit one, and the distinction is
  // worth keeping: it is the difference between a token that came back through the
  // browser and one that will come back through the token endpoint.
  const flow = types.indexOf('code') >= 0 ? 'hybrid (authorization endpoint)' : 'implicit';
  if (types.indexOf('token') >= 0) {
    out.access_token = accessToken(base, { user: user, client_id: String(query.client_id), scope: scope,
                                           session_id: sessionId, grant: flow });
    out.token_type = 'Bearer';
    out.expires_in = ACCESS_TOKEN_TTL;
    out.scope = scope;
  }
  if (types.indexOf('id_token') >= 0) {
    out.id_token = idToken(base, {
      user: user, client_id: String(query.client_id), nonce: query.nonce, auth_time: authTime,
      amr: amr, acr: acr, session_id: sessionId, grant: flow,
      access_token: out.access_token, code: out.code
    });
  }
  // Only a bare code goes in the query; anything carrying a token uses the
  // fragment, per OAuth 2.0 / OIDC.
  logArtifact('Authorization response', 'as returned to the client', out);
  redirectBack(res, base, redirectUri, query.state, out,
    types.length > 1 || types.indexOf('code') < 0);
  log.debug("Leaving issueAuthorizationResponse().");
}

function redirectBack(res, base, redirectUri, state, params, fragment) {
  log.debug("Entering redirectBack(). fragment=" + !!fragment);
  const usp = new URLSearchParams();
  Object.keys(params).forEach(function (k) { if (params[k] !== undefined) usp.set(k, params[k]); });
  if (state !== undefined) usp.set('state', state);
  usp.set('iss', base);
  const sep = fragment ? '#' : (redirectUri.indexOf('?') >= 0 ? '&' : '?');
  res.redirect(302, redirectUri + sep + usp.toString());
  log.debug("Leaving redirectBack().");
}

app.get('/oauth2/authorize', function (req, res) {
  log.debug("Entering the authorization endpoint.");
  const base = baseUrlOf(req);
  const q = req.query || {};
  const redirectUri = String(q.redirect_uri || '');

  // Without a usable redirect_uri there is nowhere to report an error TO, so it
  // is reported here instead (OAuth 2.0 section 4.1.2.1).
  if (!redirectUri || !/^https?:\/\//i.test(redirectUri)) {
    log.debug("Leaving the authorization endpoint. There is no usable redirect_uri to report to.");
    return oauthError(res, 400, 'invalid_request', 'A valid absolute redirect_uri is required.');
  }
  const fail = function (error, description) {
    log.debug("Leaving the authorization endpoint. Reporting " + error + " to the client.");
    redirectBack(res, base, redirectUri, q.state, { error: error, error_description: description }, false);
  };
  if (!q.client_id) return fail('invalid_request', 'client_id is required.');
  const types = String(q.response_type || '').split(/\s+/).filter(Boolean);
  const known = ['code', 'token', 'id_token'];
  if (!types.length || types.some(function (t) { return known.indexOf(t) < 0; })) {
    return fail('unsupported_response_type', 'response_type "' + (q.response_type || '') + '" is not supported.');
  }

  // issuer_state (OID4VCI section 4.1.1): if this request came from a Credential
  // Offer this server issued, say so — it is what ties the authorization request
  // back to the offer, and seeing it arrive is most of its debugging value.
  if (q.issuer_state) {
    const known = issuerStates.get(String(q.issuer_state));
    if (known && known.expires >= Date.now()) {
      log.debug("The authorization request carries an issuer_state from a Credential Offer this issuer made" +
                " (credential_configuration_ids=" + (known.configurationIds || []).join(', ') + ").");
    } else {
      log.debug("The authorization request carries an issuer_state this issuer does not recognise: " +
                q.issuer_state);
    }
  }

  // Did the person come back from the authentication service having refused?
  // Checked BEFORE the session, because there is no session in that case and
  // the next thing this endpoint would otherwise do is send them straight back
  // to the screen they just declined — a redirect loop with a login form in it.
  //
  // The service names the outcome and this endpoint decides what OAuth does
  // about it, which is what keeps protocol knowledge here: `redirectBack()`
  // knows about response_mode, and in form_post the answer is not a redirect at
  // all but a self-submitting form.
  if (q.authn_error) {
    log.debug("Leaving the authorization endpoint. The authentication service reported " +
              q.authn_error + ".");
    return fail(String(q.authn_error),
                String(q.authn_error_description || 'Authentication did not complete.'));
  }

  // Already signed in? Then this is the second pass — back from the
  // authentication service, or a later request on the same session — and the
  // response goes out now.
  const session = sessionOf(req);
  const forcePrompt = String(q.prompt || '').split(/\s+/).indexOf('login') >= 0;
  if (session && !forcePrompt) {
    log.debug("Leaving the authorization endpoint. The session stands, so the response goes out now.");
    return issueAuthorizationResponse(req, res, q, session.user, session.authTime, session);
  }
  if (String(q.prompt || '').split(/\s+/).indexOf('none') >= 0) {
    // OIDC: prompt=none must not show any UI.
    return fail('login_required', 'No session, and prompt=none forbids showing the login screen.');
  }

  // Otherwise: hand the person to the authentication service, and say where to
  // bring them back to — this same endpoint, with this same request.
  //
  // `prompt` is dropped from the return URL and only from it: it has been
  // honoured by the time they come back, and leaving it on would send them
  // round again for ever. Everything else goes back untouched, because what
  // runs on the return leg has to be the request the client actually made —
  // the PKCE challenge, the nonce, authorization_details and the rest are all
  // read on that second pass.
  const returnTo = '/oauth2/authorize?' + queryString(q, ['prompt']);
  // acr_values is how a relying party demands a second factor. Anything naming
  // mfa or a hardware key forces the WebAuthn step and disables the opt-out, so
  // the checkbox cannot be used to answer a request for step-up with a password.
  const forceMfa = /\b(mfa|hwk|phr|phrh)\b/i.test(String(q.acr_values || ''));
  // What the screen tells the person they are signing in FOR. Written here
  // because these are OAuth's parameters and only this module knows what they
  // mean — the issuer_state note in particular, which says whether the request
  // came from a Credential Offer this issuer actually made.
  const details = [
    { label: 'client_id', value: q.client_id || '' },
    { label: 'scope', value: q.scope || '(none requested)' },
    { label: 'redirect_uri', value: q.redirect_uri || '' }
  ];
  if (q.issuer_state) {
    details.push({ label: 'issuer_state', value: q.issuer_state,
                   note: issuerStates.has(String(q.issuer_state))
                     ? 'from a Credential Offer this issuer made' : '' });
  }
  res.redirect(302, authn.beginAuthentication({
    returnTo: returnTo, details: details, hint: q.login_hint || '',
    forceMfa: forceMfa, protocol: 'OAuth 2.0 / OIDC'
  }));
  log.debug("Leaving the authorization endpoint. Sent to the authentication service first.");
});



// Ends the session, so the next authorization request prompts again.
app.get('/oauth2/logout', function (req, res) {
  log.debug("Entering the logout endpoint.");
  // The same session WS-Federation's wsignout1.0 ends, through the same function —
  // one browser session shared by both protocols means signing out of either signs
  // out of both, which is what a person testing them together expects.
  endSession(req, res);
  const target = req.query.post_logout_redirect_uri;
  if (target && /^https?:\/\//i.test(String(target))) {
    log.debug("Leaving the logout endpoint. Redirecting to " + target + ".");
    return res.redirect(302, String(target));
  }
  res.status(200).type('text/plain').send('Signed out of the mock authorization server.\n');
  log.debug("Leaving the logout endpoint.");
});

// ---------------------------------------------------------------------------
// OpenID Connect Core 1.0 section 5.3 — the UserInfo Endpoint.
//
// A protected resource: present the access token from an OIDC flow and get back
// the claims about the person it was issued for. GET and POST both, because
// section 5.3.1 requires both, and the token comes from the Authorization header
// only — RFC 6750 section 2.3's query-parameter form is NOT RECOMMENDED by its
// own specification, leaks the token into logs and referrers, and could not carry
// a DPoP-bound token in any case.
//
// **This is the one protected endpoint here that refuses a token it did not
// issue, and the exception is the point rather than an inconsistency.** The
// Credential, Deferred Credential and Notification endpoints accept a foreign
// token because OID4VCI lets the authorization server be somebody else, so
// refusing one would break the flow this mock exists to exercise. UserInfo is
// defined the other way round: it answers "who did YOU authenticate", and about
// the subject of a signature it cannot check this server knows nothing at all. A
// mock that made up a profile for an unverifiable token would be teaching the
// wrong lesson to the client reading its output — and it is also what makes
// `cnf.jkt` mean something here, since the binding is only real on a token whose
// signature was checked first.
//
// So four things are checked, and each has a distinct answer so a client can tell
// them apart:
//
//   * the signature, issuer and expiry (401 invalid_token, with the reason — an
//     expired token and a forged one are different problems and "invalid_token"
//     alone sends people looking in the wrong place)
//   * `typ`, so a refresh token or an id_token presented here is refused rather
//     than quietly answered. They are all RS256 JWTs from the same key, so
//     nothing but this claim distinguishes them
//   * revocation, because /oauth2/revoke has to mean the same thing at every
//     endpoint that reads a token — introspection reporting `active: false`
//     while UserInfo still answers would make revocation decorative
//   * the `openid` scope (403 insufficient_scope), which is what a token from the
//     client_credentials or token-exchange grant lacks: those have no end-user,
//     and there is no profile to return for a token that never described one
//
// Scope gating, and why the id_token does NOT do the same. Section 5.4 makes
// `profile` and `email` requests for a named set of claims AT THIS ENDPOINT, so
// this is one place in this mock where a scope genuinely changes the answer, and
// that is worth being able to watch. The id_token still carries everything
// whatever was asked for, which the same section permits — the claims go in the
// id_token when there is no access token to fetch them with — and it is also the
// only behaviour that can serve the implicit flow this server offers.
// ---------------------------------------------------------------------------

// Which claims each scope asks for (section 5.4), restricted to the ones
// userFor() actually mints — `address` and `phone` are not in scopes_supported
// for exactly that reason, so they are not here either.
const USERINFO_SCOPE_CLAIMS = {
  profile: ['name', 'given_name', 'family_name', 'preferred_username'],
  email: ['email', 'email_verified']
};

// The reason a token failed to verify, in the words a person debugging it needs.
// jwt.verify() throws one of a small set of named errors and the distinction
// between them is the whole diagnosis, so it is not collapsed into "invalid".
function tokenFailure(token) {
  log.debug("Entering tokenFailure().");
  try {
    jwt.verify(token, STS.certPem, { algorithms: ['RS256'] });
    log.debug("Leaving tokenFailure(). It verifies after all.");
    return '';
  } catch (e) {
    let why;
    if (e.name === 'TokenExpiredError') {
      why = 'This access token expired at ' + new Date(e.expiredAt).toISOString() + '.';
    } else if (e.name === 'NotBeforeError') {
      why = 'This access token is not valid yet (nbf is in the future).';
    } else {
      // Everything else — a bad signature, a token from another issuer, an
      // opaque string that is not a JWT at all. They are one answer because the
      // server genuinely cannot tell them apart, and saying so is honest.
      why = 'This access token was not issued by this server, or its signature does not verify ' +
            'against the key at /oauth2/jwks (' + e.message + '). Unlike the OID4VCI credential ' +
            'endpoints, UserInfo cannot accept a token from a separate authorization server: it ' +
            'has nothing to say about a subject it did not authenticate.';
    }
    log.debug("Leaving tokenFailure(). " + e.name);
    return why;
  }
}

function userinfoResponse(req, res) {
  log.debug("Entering userinfoResponse(). method=" + req.method);
  const base = baseUrlOf(req);

  // The Bearer/DPoP check every protected endpoint in this service shares. It
  // answers the request itself and returns null when the token is missing, is
  // bound and presented as Bearer, or comes with a proof that does not hold up.
  const presented = dpop.presentedAccessToken(req, res, 'the userinfo endpoint');
  if (!presented) {
    log.debug("Leaving userinfoResponse(). No usable access token was presented.");
    return;
  }

  // RFC 6750 section 3: a 401 from a protected resource carries a challenge
  // naming the scheme, and 403 insufficient_scope names the scope that was
  // missing. Without them a client is told it failed but not what to change.
  //
  // The description goes out twice — in the header and in the JSON body — and
  // the header copy has to be cut down to ASCII first. An HTTP field value is
  // ASCII (RFC 9110 section 5.5), node's setHeader THROWS on anything else
  // rather than mangling it, and the descriptions in this file are prose written
  // with em dashes and curly quotes like every other comment here. The first one
  // that reached the header turned a 401 into a 500 — which is the worst place
  // in the service to have one, because the exception replaces the very message
  // that was explaining what went wrong. Quotes go too: they would close the
  // quoted-string early. The body keeps the real text; JSON is UTF-8.
  const headerSafe = function (text) {
    return String(text)
      .replace(/[‘’]/g, "'").replace(/[“”]/g, "'")
      .replace(/[–—]/g, '-').replace(/…/g, '...')
      .replace(/"/g, "'")
      .replace(/[^\x20-\x7E]/g, '');
  };
  const challenge = function (status, error, description, extra) {
    const scheme = presented.scheme === 'dpop' ? 'DPoP' : 'Bearer';
    res.set('WWW-Authenticate', scheme + ' error="' + error + '", error_description="' +
            headerSafe(description) + '"' + (extra || ''));
    log.debug("Leaving userinfoResponse(). " + error + ".");
    return oauthError(res, status, error, description);
  };

  if (!presented.verified) {
    return challenge(401, 'invalid_token', tokenFailure(presented.accessToken));
  }
  const claims = presented.claims || {};
  if (claims.typ !== 'Bearer') {
    return challenge(401, 'invalid_token',
      'This is a "' + (claims.typ || 'unknown') + '" token, not an access token. Every token this ' +
      'server issues is an RS256 JWT signed with the same key, so the typ claim is the only thing ' +
      'that tells a refresh token or an id_token apart from the access token UserInfo needs.');
  }
  if (stats.isRevoked(claims.jti)) {
    return challenge(401, 'invalid_token',
      'This access token was revoked at /oauth2/revoke. Introspection reports it inactive, and ' +
      'UserInfo answers the same way — a revocation that only some endpoints honoured would be ' +
      'worse than none.');
  }
  if (!hasScope(claims.scope, 'openid')) {
    return challenge(403, 'insufficient_scope',
      'UserInfo needs an access token issued with the "openid" scope; this one was issued with ' +
      (claims.scope ? '"' + claims.scope + '"' : 'no scope at all') + '. A client_credentials or ' +
      'token-exchange token has no end-user behind it, so there is no profile to return.',
      ', scope="openid"');
  }

  // Who the token was issued for. `sub` comes from the token rather than from
  // userFor(), because section 5.3.2 requires the sub here to be the one the
  // client saw in the id_token and the token is the record of what that was; the
  // rest is rebuilt from the username that travels with it.
  const user = userFor(claims.username);
  const body = { sub: claims.sub || user.sub };
  Object.keys(USERINFO_SCOPE_CLAIMS).forEach(function (scope) {
    if (!hasScope(claims.scope, scope)) return;
    USERINFO_SCOPE_CLAIMS[scope].forEach(function (name) { body[name] = user[name]; });
  });
  logArtifact('UserInfo response', 'as returned', body);

  // Section 5.3.2: the response is JSON unless the client registered a
  // `userinfo_signed_response_alg`, in which case it is a JWT of the same claims
  // with `iss` and `aud` added — the two members that make a signed response
  // worth having, since without them it could be replayed to another client.
  // This is read from the RFC 7591 registration the client already did here, so
  // the two features meet where they should: register asking for a signed
  // response and this endpoint starts signing for that client.
  const registered = registeredClients.get(String(claims.client_id || '')) || {};
  const alg = String(registered.userinfo_signed_response_alg || 'none');
  if (alg !== 'none') {
    if (alg !== 'RS256') {
      // Refused rather than downgraded to JSON: silently ignoring the algorithm
      // a client registered would leave it verifying a signature that is not
      // there, and this key signs RS256 only.
      log.debug("Leaving userinfoResponse(). The client registered an alg this server cannot sign.");
      return oauthError(res, 500, 'server_error',
        'This client registered userinfo_signed_response_alg="' + alg + '", and this server signs ' +
        'RS256 only (see userinfo_signing_alg_values_supported).');
    }
    const signed = signJwt(Object.assign({ iss: base, aud: claims.client_id, typ: 'UserInfo' }, body));
    res.status(200).type('application/jwt').set('Cache-Control', 'no-store').send(signed);
    log.debug("Leaving userinfoResponse(). A signed UserInfo response for " + body.sub + ".");
    return;
  }
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(body, null, 2));
  log.debug("Leaving userinfoResponse(). " + Object.keys(body).length + " claim(s) for " + body.sub + ".");
}

app.get('/oauth2/userinfo', userinfoResponse);

app.post('/oauth2/userinfo', userinfoResponse);

// --- token endpoint ---------------------------------------------------------
// ---------------------------------------------------------------------------
// NON-SPEC: the DPoP nonce switch.
//
// RFC 9449 sections 8 and 9 let a server demand a server-supplied nonce in every
// proof, which turns the first request of a session into a 401/retry handshake.
// Whether to do that is a deployment's choice, and both answers are worth being
// able to try — a wallet that handles the happy path but not the handshake is a
// wallet that works until it meets a server that asks.
//
// So it is a runtime switch rather than configuration: a test, or somebody
// reading the page, can turn it on, watch the retry, and turn it off again
// without restarting the service. GET reports; POST {"required": true|false}
// sets. Listed on /sts-metadata as non-spec, because it is.
// ---------------------------------------------------------------------------
app.get('/dpop/nonce-mode', function (req, res) {
  log.debug("Entering the DPoP nonce-mode endpoint (read).");
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
    .send(JSON.stringify(dpop.state(), null, 2));
  log.debug("Leaving the DPoP nonce-mode endpoint (read).");
});

app.post('/dpop/nonce-mode', function (req, res) {
  log.debug("Entering the DPoP nonce-mode endpoint (write).");
  const body = parseBody(req);
  // Only an explicit boolean, so a typo cannot silently leave the switch in a
  // state nobody chose: a test that means to turn nonces OFF and leaves them on
  // makes every later section in the run fail for an invisible reason.
  const wanted = body.required;
  if (wanted !== true && wanted !== false && wanted !== 'true' && wanted !== 'false') {
    log.debug("Leaving the DPoP nonce-mode endpoint. Refused.");
    return oauthError(res, 400, 'invalid_request',
      'Send {"required": true} or {"required": false}.');
  }
  dpop.setNonceMode(wanted === true || wanted === 'true');
  // A change of policy invalidates nothing already issued, but the replay cache
  // is process-wide and a test that has just been refusing proofs on purpose
  // wants a clean slate for the next section.
  dpop.forgetProofs();
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
    .send(JSON.stringify(dpop.state(), null, 2));
  log.debug("Leaving the DPoP nonce-mode endpoint (write). required=" + dpop.nonceModeOn());
});

// --- what became of an authorization code -----------------------------------
// The functions behind the relaxation described where `redeemedCodes` is
// declared. They are here rather than beside it because everything they exist
// for happens in the token endpoint immediately below.

function forgetStaleRedemptions() {
  log.debug("Entering forgetStaleRedemptions().");
  const now = Date.now();
  redeemedCodes.forEach(function (v, k) {
    if (v.forget < now) redeemedCodes.delete(k);
  });
  log.debug("Leaving forgetStaleRedemptions(). " + redeemedCodes.size +
            " redemption(s) remembered.");
}

// What makes two Token Requests for one code the SAME request. The client id
// is the resolved one rather than the body parameter, so a client using
// client_secret_basic is compared on what it authenticated as.
function redemptionFingerprint(client, body, dpopJkt) {
  log.debug("Entering redemptionFingerprint().");
  const parts = {
    client_id: String((client && client.client_id) || ''),
    redirect_uri: String(body.redirect_uri || ''),
    code_verifier: String(body.code_verifier || ''),
    dpop_jkt: String(dpopJkt || '')
  };
  log.debug("Leaving redemptionFingerprint(). client_id=" +
            (parts.client_id || '(none)'));
  return parts;
}

// The FIRST field that differs, by name, or "" when the two are the same
// request. The name is the whole point: it is what the refusal says.
function redemptionDifference(was, now) {
  log.debug("Entering redemptionDifference().");
  const names = ['client_id', 'redirect_uri', 'code_verifier', 'dpop_jkt'];
  for (let i = 0; i < names.length; i++) {
    const name = names[i];
    if (String(was[name] || '') !== String(now[name] || '')) {
      log.debug("Leaving redemptionDifference(). " + name + " differs.");
      return name;
    }
  }
  log.debug("Leaving redemptionDifference(). It is the same request.");
  return '';
}

function rememberRedemption(code, record, fingerprint, issued) {
  log.debug("Entering rememberRedemption().");
  forgetStaleRedemptions();
  redeemedCodes.set(code, {
    when: Date.now(),
    // The code's OWN expiry, not a fresh one: the replay window is the rest of
    // the life the code already had, so this relaxation cannot outlive the
    // rule it relaxes.
    expires: record.expires,
    forget: record.expires + AUTH_CODE_TTL_MS,
    client_id: fingerprint.client_id,
    fingerprint: fingerprint,
    response: issued
  });
  log.debug("Leaving rememberRedemption(). The tokens for this code are " +
            "replayable until " + new Date(record.expires).toISOString() + ".");
}

// How long this process has been up, in words, for the one refusal that needs
// to say it: a code minted before a restart is not "already used", it is gone
// with the Map that held it, and those two look identical from the client.
function describeUptime() {
  log.debug("Entering describeUptime().");
  const seconds = Math.max(0,
    Math.round((Date.now() - stats.STARTED_AT) / 1000));
  if (seconds < 120) {
    log.debug("Leaving describeUptime().");
    return seconds + ' second(s)';
  }
  if (seconds < 7200) {
    log.debug("Leaving describeUptime().");
    return Math.round(seconds / 60) + ' minute(s)';
  }
  log.debug("Leaving describeUptime().");
  return Math.round(seconds / 3600) + ' hour(s)';
}

// A code the live map does not hold. Either it was redeemed here — in which
// case the same request gets the same tokens back and a different one is
// refused with the difference named — or this server never issued it, which is
// its own sentence and not "already used".
function replayOrRefuseRedemption(res, code, fingerprint, respond) {
  log.debug("Entering replayOrRefuseRedemption().");
  forgetStaleRedemptions();
  const done = redeemedCodes.get(code);
  if (!done) {
    log.debug("Leaving replayOrRefuseRedemption(). This server has no record " +
              "of that code at all.");
    return oauthError(res, 400, 'invalid_grant',
      'Unknown or already-used authorization code. Nothing is held here ' +
      'under that value and nothing was redeemed under it recently: this ' +
      'service keeps authorization codes in memory only, so a code issued ' +
      'before it was last restarted (it has been up ' + describeUptime() +
      ') went with them, as did one issued by a different authorization ' +
      'server.');
  }
  const ago = Math.max(0, Math.round((Date.now() - done.when) / 1000));
  const differs = redemptionDifference(done.fingerprint, fingerprint);
  if (differs) {
    log.debug("Leaving replayOrRefuseRedemption(). The " + differs +
              " differs from the request this code was redeemed with.");
    return oauthError(res, 400, 'invalid_grant',
      'This authorization code was redeemed ' + ago + ' second(s) ago by ' +
      'client "' + (done.client_id || '(none)') + '". A repeat of that same ' +
      'request would be answered with the same tokens, but this one differs ' +
      'in ' + differs + ', so it is refused (RFC 6749 section 4.1.2: an ' +
      'authorization code is single use).');
  }
  if (done.expires < Date.now()) {
    log.debug("Leaving replayOrRefuseRedemption(). The code was redeemed and " +
              "its own lifetime has since run out.");
    return oauthError(res, 400, 'invalid_grant',
      'This authorization code was redeemed ' + ago + ' second(s) ago by ' +
      'client "' + (done.client_id || '(none)') + '", and the ' +
      Math.round(AUTH_CODE_TTL_MS / 60000) + ' minute lifetime it was issued ' +
      'with has since run out, so the tokens it bought are no longer ' +
      'replayed here. Start a new authorization request; the refresh token ' +
      'from the first redemption is still good.');
  }
  // Loud, because a client that redeems a code twice is doing something a real
  // authorization server would refuse, and reading this log is how somebody
  // finds that out from a server that did not.
  log.warn('An authorization code was presented a second time by client "' +
           (done.client_id || '(none)') + '" ' + ago + ' second(s) after it ' +
           'was redeemed. The request is identical and the code is still ' +
           'within its lifetime, so the SAME token set is being returned ' +
           'rather than an error. RFC 6749 section 4.1.2 permits a real ' +
           'authorization server to refuse this and section 10.5 to revoke ' +
           'what it issued.');
  log.debug("Leaving replayOrRefuseRedemption(). Replaying the token set.");
  return respond(done.response);
}

app.post('/oauth2/token', function (req, res) {
  log.debug("Entering the token endpoint.");
  const base = baseUrlOf(req);
  const body = parseBody(req);
  const client = clientFrom(req, body);
  const grant = String(body.grant_type || '');
  res.set('Cache-Control', 'no-store');

  // --- DPoP (RFC 9449 section 5) -------------------------------------------
  // Optional, and checked before any grant is considered so that every grant
  // gets the same treatment: a wallet that sends a proof gets a bound token
  // whether it arrived by authorization code, by pre-authorized code or by
  // refresh. A wallet that sends none gets a Bearer token exactly as before,
  // which is what keeps this switch invisible to the workflows that do not use
  // it.
  let dpopJkt = '';
  if (req.headers['dpop'] !== undefined) {
    const checked = dpop.verifyProof(req.headers['dpop'], {
      htm: req.method, htu: dpop.htuOf(req)
    });
    if (!checked.ok) {
      // Section 8: when the server wants a nonce it does not refuse outright —
      // it ASKS, with a fresh nonce in the header and `use_dpop_nonce` as the
      // error, and the wallet retries once. Answering a plain invalid_dpop_proof
      // here would leave a conforming client with no way forward.
      if (checked.needNonce) {
        res.set('DPoP-Nonce', dpop.issueNonce());
        log.debug("Leaving the token endpoint. Asking the client for a DPoP nonce.");
        return oauthError(res, 400, 'use_dpop_nonce',
          'Authorization server requires nonce in DPoP proof');
      }
      log.debug("Leaving the token endpoint. The DPoP proof was refused.");
      return oauthError(res, 400, 'invalid_dpop_proof', checked.description);
    }
    dpopJkt = checked.jkt;
    log.debug("This Token Request carries a valid DPoP proof. jkt=" + dpopJkt);
  }
  // Note there is no "DPoP required" mode here. Nonce mode makes proofs FRESHER;
  // it does not make them mandatory. A request with no DPoP header is a Bearer
  // request and is answered as one, so turning nonce mode on cannot break the
  // Bearer clients this server also exists to exercise.

  const respond = function (payload) {
    res.status(200).type('application/json').send(JSON.stringify(payload));
    log.debug("Leaving the token endpoint. Issued: " + Object.keys(payload).join(', '));
  };

  // Turn what was authorized into what may be requested: OID4VCI calls these
  // Credential Dataset identifiers, and they are the issuer's own names for
  // "this credential, for this End-User".
  const grantIdentifiers = function (details, user) {
    log.debug("Entering grantIdentifiers().");
    if (!details) return null;
    log.debug("Leaving grantIdentifiers().");
    return details.map(function (d) {
      const granted = {
        type: 'openid_credential',
        credential_configuration_id: d.credential_configuration_id,
        credential_identifiers: [
          d.credential_configuration_id + ':' +
          b64u(crypto.createHash('sha256')
            .update(String((user && user.sub) || 'anonymous') + ':' + d.credential_configuration_id)
            .digest()).slice(0, 16)
        ]
      };
      // Echoed back, and it has to be: this is what the credential endpoint
      // reads the selection off (it rides inside the access token), and it is
      // also the only way the wallet learns that the claims it asked for are the
      // claims that were authorized. RFC 9396 section 7 enriches the details it
      // returns rather than replacing them.
      if (d.claims) granted.claims = d.claims;
      return granted;
    });
  };

  if (grant === 'authorization_code') {
    const code = String(body.code || '');
    const fingerprint = redemptionFingerprint(client, body, dpopJkt);
    const record = authzCodes.get(code);
    if (!record) {
      // Not necessarily an error: this is also where a second, identical Token
      // Request for a code already redeemed is answered with the tokens it got
      // the first time. See `redeemedCodes` above.
      log.debug("Leaving the token endpoint. No live code by that value; " +
                "what became of it decides the answer.");
      return replayOrRefuseRedemption(res, code, fingerprint, respond);
    }
    if (record.expires < Date.now()) {
      authzCodes.delete(code);
      log.debug("Leaving the token endpoint. The code had expired.");
      return oauthError(res, 400, 'invalid_grant',
        'The authorization code has expired.');
    }
    // NOTHING below consumes the code: every check refuses and leaves it
    // redeemable, so a client that gets one of them can fix what the message
    // names and try the same code again. Burning it here is what used to turn
    // "your code_verifier does not match" into "already-used authorization
    // code" on the very next attempt — the wrong answer at exactly the moment
    // somebody was acting on the right one. The code is consumed at the bottom,
    // where it is actually redeemed.
    if (body.redirect_uri && body.redirect_uri !== record.redirect_uri) {
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'redirect_uri does not match the authorization request.');
    }
    if (record.code_challenge) {
      const verifier = String(body.code_verifier || '');
      if (!verifier) {
        log.debug("Leaving the token endpoint. PKCE was used and no " +
                  "code_verifier came with the code.");
        return oauthError(res, 400, 'invalid_grant',
          'PKCE was used, so code_verifier is required.');
      }
      const computed = record.code_challenge_method === 'S256'
        ? b64u(crypto.createHash('sha256').update(verifier, 'ascii').digest())
        : verifier;
      if (computed !== record.code_challenge) {
        log.debug("Leaving the token endpoint. The grant was refused.");
        return oauthError(res, 400, 'invalid_grant', 'The code_verifier does not match the code_challenge.');
      }
    }
    // RFC 9449 section 10: when the authorization request named a key with
    // `dpop_jkt`, the code is bound to it and only that key may redeem it. This
    // closes the window PKCE does not: an attacker who steals the code AND the
    // code_verifier still cannot use them, because they cannot sign for the key.
    if (record.dpop_jkt) {
      if (!dpopJkt) {
        log.debug("Leaving the token endpoint. The code is DPoP-bound and no proof came with it.");
        return oauthError(res, 400, 'invalid_grant',
          'The authorization request bound this code to a DPoP key (dpop_jkt), so the Token ' +
          'Request must carry a DPoP proof from that key.');
      }
      if (record.dpop_jkt !== dpopJkt) {
        log.debug("Leaving the token endpoint. The code's dpop_jkt does not match the proof.");
        return oauthError(res, 400, 'invalid_grant',
          'This authorization code is bound to DPoP key ' + record.dpop_jkt +
          ', but the proof was signed by ' + dpopJkt + '.');
      }
      log.debug("The authorization code's dpop_jkt matches the proof. jkt=" + dpopJkt);
    }
    const issued = tokenSet(base, {
      jkt: dpopJkt,
      user: record.user, client_id: record.client_id, scope: record.scope,
      nonce: record.nonce, auth_time: record.auth_time, amr: record.amr, acr: record.acr,
      // Off the code, which carried it from the authorization endpoint. This is the
      // ordinary case: most tokens this service issues belong to a sign-on session
      // and only arrive at the console as belonging to one because of this line.
      session_id: record.session_id || '', grant: 'authorization_code',
      authorization_details: grantIdentifiers(record.authorization_details, record.user)
    });
    // Single use — and remembered as used, with what it bought, so that the
    // same request arriving again gets that answer back instead of a sentence
    // about a code nobody can look up any more.
    authzCodes.delete(code);
    rememberRedemption(code, record, fingerprint, issued);
    return respond(issued);
  }

  // OID4VCI's pre-authorized code grant (Appendix H.2 / H.3, RFC-registered as
  // urn:ietf:params:oauth:grant-type:pre-authorized_code). No authorization
  // request happened: the End-User was identified out of band and the code in
  // the Credential Offer is the authorization. When the offer said a
  // Transaction Code is required, the wallet must present the one the End-User
  // read off the issuer's screen.
  if (grant === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
    const code = String(body['pre-authorized_code'] || '');
    const record = preAuthorizedCodes.get(code);
    if (!record) {
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'Unknown or already-used pre-authorized code.');
    }
    if (record.expires < Date.now()) {
      preAuthorizedCodes.delete(code);
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'The pre-authorized code has expired.');
    }
    const presented = String(body.tx_code || '');
    if (record.txCode) {
      if (!presented) {
        log.debug("Leaving the token endpoint. The grant was refused: no tx_code.");
        return oauthError(res, 400, 'invalid_grant',
          'This pre-authorized code requires the Transaction Code shown by the issuer (tx_code).');
      }
      if (presented !== record.txCode) {
        log.debug("Leaving the token endpoint. The grant was refused: the tx_code is wrong.");
        return oauthError(res, 400, 'invalid_grant', 'The Transaction Code is not correct.');
      }
    }
    // Single use, like an authorization code.
    preAuthorizedCodes.delete(code);
    // The End-User was identified out of band, so there is a subject and no sign-on
    // session — and the users page has to be able to say that difference rather than
    // report a missing session as an unknown one.
    stats.recordAuthentication({
      presented: (record.user && record.user.username) || '',
      protocol: 'OpenID4VCI', method: 'pre-authorized code' + (record.txCode ? ' with a Transaction Code' : ''),
      sub: (record.user && record.user.sub) || '', client_id: client.client_id,
      note: 'Identified out of band when the Credential Offer was made; no browser session exists.'
    });
    // OID4VCI section 6.1.1: the Wallet MAY send authorization_details in the
    // Token Request, in the Pre-Authorized Code Flow as well as the
    // Authorization Code one — and here it is the ONLY place it can, because
    // this flow has no authorization request to have sent them in. That is what
    // lets a cross-device or deferred issuance ask for a subset of the claims.
    const askedFor = parseAuthorizationDetails(body.authorization_details);
    if (askedFor.error) {
      log.debug("Leaving the token endpoint. " + askedFor.error);
      return oauthError(res, 400, 'invalid_authorization_details', askedFor.error);
    }
    // What the OFFER was for bounds what the Token Request may ask for: the
    // pre-authorized code authorizes those credentials and no others, so a
    // request naming a different configuration is asking for something nobody
    // ever offered.
    const offered = record.configurationIds || [];
    const notOffered = (askedFor.details || []).filter(function (d) {
      return offered.indexOf(d.credential_configuration_id) === -1;
    });
    if (notOffered.length) {
      log.debug("Leaving the token endpoint. The details name a configuration the offer did not.");
      return oauthError(res, 400, 'invalid_authorization_details',
        'this Credential Offer is for ' + offered.join(', ') + ', so ' +
        notOffered.map(function (d) { return '"' + d.credential_configuration_id + '"'; }).join(', ') +
        ' cannot be authorized by it.');
    }
    const issued = tokenSet(base, {
      jkt: dpopJkt,
      user: record.user, client_id: client.client_id, scope: VCI_SCOPE, withRefresh: false,
      grant: 'pre-authorized code',
      authorization_details: grantIdentifiers(askedFor.details, record.user)
    });
    // Remember which access token belongs to a deferred issuance, so the
    // credential endpoint knows to answer 202 rather than a credential.
    if (record.deferred) {
      deferredAccessTokens.add(issued.access_token);
      log.debug("This access token belongs to a DEFERRED issuance.");
    }
    return respond(issued);
  }

  if (grant === 'refresh_token') {
    let claims;
    try {
      claims = jwt.verify(String(body.refresh_token || ''), STS.certPem, { algorithms: ['RS256'] });
    } catch (e) {
      log.error('the refresh token is not valid: ' + e.message);
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'The refresh token is not valid: ' + e.message);
    }
    if (stats.isRevoked(claims.jti)) return oauthError(res, 400, 'invalid_grant', 'The refresh token was revoked.');
    // RFC 9449 section 5: a bound refresh token may only be redeemed by its own
    // key. Without this the refresh token would be a bearer credential that
    // mints bound access tokens for whoever holds it — which is worse than not
    // binding at all, because the token_type would say `DPoP` and imply a
    // guarantee that was never checked.
    const boundTo = dpop.jktOf(claims);
    if (boundTo) {
      if (!dpopJkt) {
        log.debug("Leaving the token endpoint. The refresh token is bound and no proof came.");
        return oauthError(res, 400, 'invalid_grant',
          'This refresh token is bound to a DPoP key, so the Token Request must carry a DPoP ' +
          'proof from that key.');
      }
      if (boundTo !== dpopJkt) {
        log.debug("Leaving the token endpoint. The refresh token's cnf.jkt does not match.");
        return oauthError(res, 400, 'invalid_grant',
          'This refresh token is bound to DPoP key ' + boundTo + ', but the proof was signed ' +
          'by ' + dpopJkt + '.');
      }
    }
    return respond(tokenSet(base, {
      // The same reasoning applies to the OID4VCI half of the grant: the
      // credential_identifiers and the claims selection were authorized by the
      // authorization request this refresh token descends from, so an access
      // token that dropped them would refuse the very Credential Request the
      // section 14.5 refresh on step 4 exists to make — naming a
      // credential_identifier "that was not granted".
      authorization_details: claims.authorization_details,
      // A refresh keeps whatever binding it had: re-binding to the key that
      // happens to have signed this request would let a stolen bound token be
      // laundered into one bound to the thief's key.
      jkt: boundTo || dpopJkt,
      user: userFor(claims.username), client_id: claims.client_id,
      scope: body.scope ? String(body.scope) : claims.scope,
      // The session the REFRESHED token came from, looked up by the refresh token's
      // own jti. Nothing on the wire carries it — a refresh token names no session —
      // so without this every second-generation token would show as sessionless and a
      // session's token list would stop growing the moment a client refreshed.
      session_id: stats.sessionIdOfJti(claims.jti), grant: 'refresh_token'
    }));
  }

  if (grant === 'client_credentials') {
    // No user is involved, so no refresh token and no ID token.
    //
    // It is recorded on the users page all the same, flagged as a CLIENT rather than
    // a person. Leaving it out would be tidier and wrong: these tokens have a subject
    // and appear in the tokens table, so a users page that did not know the name
    // would be a second page of one console contradicting the first.
    stats.recordAuthentication({
      presented: client.client_id || 'unknown-client',
      protocol: 'OAuth 2.0', method: 'client_credentials', isClient: true,
      sub: client.client_id || 'unknown-client', client_id: client.client_id,
      note: 'A client authenticating as itself. No human and no browser is behind this token, ' +
            'and no secret was checked.'
    });
    return respond(tokenSet(base, {
      jkt: dpopJkt,
      sub: client.client_id || 'unknown-client', username: client.client_id,
      client_id: client.client_id, scope: String(body.scope || ''), withRefresh: false,
      grant: 'client_credentials',
      user: Object.assign(userFor(client.client_id), { sub: client.client_id || 'unknown-client' })
    }));
  }

  if (grant === 'password') {
    const username = String(body.username || '');
    if (!username || !body.password) {
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_request', 'username and password are required.');
    }
    // The one credential this mock rejects, so a negative test has something to
    // fail on (the WS-Trust side of this service does the same).
    if (body.password === 'invalid') {
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'Authentication failed for user ' + username + '.');
    }
    // A password grant is an authentication: the credential was presented here, to
    // this endpoint, and this is where it succeeded. No session is created — the
    // grant exists for clients that cannot open a browser — so the tokens below
    // belong to a person and to no session, which is a shape the users page shows.
    stats.recordAuthentication({
      presented: username, protocol: 'OAuth 2.0', method: 'password grant (RFC 6749 section 4.3)',
      sub: userFor(username).sub, client_id: client.client_id,
      note: 'No password is checked here either, except the reserved string "invalid". ' +
            'A password grant creates no browser session.'
    });
    return respond(tokenSet(base, {
      jkt: dpopJkt,
      user: userFor(username), client_id: client.client_id, scope: String(body.scope || 'openid'),
      grant: 'password'
    }));
  }

  if (grant === 'urn:ietf:params:oauth:grant-type:token-exchange') {
    const subjectToken = String(body.subject_token || '');
    if (!subjectToken) return oauthError(res, 400, 'invalid_request', 'subject_token is required.');
    let subject = {};
    // Whether this service is the one that authenticated the subject, or is merely
    // reading a name off somebody else's token. The users page has to say which: a
    // subject that arrived on an unverified token was never authenticated HERE, and
    // a console that listed the two the same way would be claiming an authentication
    // that never happened.
    let subjectVerified = true;
    try {
      subject = jwt.verify(subjectToken, STS.certPem, { algorithms: ['RS256'] });
    } catch (e) {
      // A token from somewhere else: exchange it anyway, but say who it was for
      // as best it can be read.
      subjectVerified = false;
      log.debug("The subject_token was not signed by this server; reading it without verifying.");
      try {
        subject = jsonFromB64u(subjectToken.split('.')[1]) || {};
      } catch (e2) {
        log.error('the subject_token could not be read at all: ' + e2.message);
        subject = {};
      }
    }
    let act;
    if (body.actor_token) {
      try {
        act = { sub: (jsonFromB64u(String(body.actor_token).split('.')[1]) || {}).sub };
      } catch (e) {
        log.error('the actor_token could not be read: ' + e.message);
        act = undefined;
      }
    }
    stats.recordAuthentication({
      presented: subject.username || subject.sub || 'urn:sts-mock:exchanged',
      protocol: 'OAuth 2.0', method: 'token exchange (RFC 8693)',
      sub: subject.sub || '', client_id: client.client_id,
      note: subjectVerified
        ? 'The subject_token was signed by this service and verified, so this subject was ' +
          'authenticated here — earlier, by whatever grant produced that token.'
        : 'The subject_token was NOT signed by this service. The name was read out of it without ' +
          'verifying anything, so this is a subject this service has been TOLD about rather than ' +
          'one it authenticated.'
    });
    const exchanged = tokenSet(base, {
      jkt: dpopJkt,
      sub: subject.sub || 'urn:sts-mock:exchanged',
      user: Object.assign(userFor(subject.username), subject.sub ? { sub: subject.sub } : {}),
      client_id: client.client_id, scope: String(body.scope || subject.scope || ''),
      audience: body.audience || body.resource, act: act, withRefresh: false,
      grant: 'token exchange'
    });
    exchanged.issued_token_type = 'urn:ietf:params:oauth:token-type:access_token';
    return respond(exchanged);
  }

  log.debug("Leaving the token endpoint.");
  log.debug("Leaving the token endpoint. The grant type is not supported.");
  return oauthError(res, 400, 'unsupported_grant_type', 'grant_type "' + grant + '" is not supported.');
});

// --- introspection (RFC 7662) ------------------------------------------------
app.post('/oauth2/introspect', function (req, res) {
  log.debug("Entering the introspection endpoint.");
  const body = parseBody(req);
  res.set('Cache-Control', 'no-store');
  const inactive = function () {
    res.status(200).type('application/json').send(JSON.stringify({ active: false }));
    log.debug("Leaving the introspection endpoint. The token is not active.");
  };
  const token = String(body.token || '');
  if (!token) return inactive();
  let claims;
  try {
    claims = jwt.verify(token, STS.certPem, { algorithms: ['RS256'] });
  } catch (e) {
    // Expired, forged, or simply not one of ours.
    log.debug("Introspection: the token does not verify (" + e.message + "), so it is inactive.");
    return inactive();
  }
  if (stats.isRevoked(claims.jti)) return inactive();
  res.status(200).type('application/json').send(JSON.stringify({
    active: true,
    scope: claims.scope || '',
    client_id: claims.client_id,
    username: claims.username,
    // A bound token is not a Bearer token, and an introspection response that
    // says otherwise invites the caller to accept it as one.
    token_type: claims.typ === 'Refresh' ? 'refresh_token'
                                        : (dpop.jktOf(claims) ? 'DPoP' : 'Bearer'),
    // RFC 9449 section 6.1 / RFC 7662: the confirmation travels to the resource
    // server so it can check the binding itself.
    cnf: claims.cnf,
    exp: claims.exp, iat: claims.iat, nbf: claims.nbf,
    sub: claims.sub, aud: claims.aud, iss: claims.iss, jti: claims.jti
  }));
  log.debug("Leaving the introspection endpoint. The token is active.");
});

// --- revocation (RFC 7009) ---------------------------------------------------
// "The authorization server responds with HTTP 200 for both a successful
// revocation and an invalid token" — so this always succeeds. A revoked jti
// stops introspecting as active and stops refreshing.
app.post('/oauth2/revoke', function (req, res) {
  log.debug("Entering the revocation endpoint.");
  const body = parseBody(req);
  const token = String(body.token || '');
  if (token) {
    try {
      const claims = jwt.verify(token, STS.certPem, { algorithms: ['RS256'] });
      if (claims.jti) stats.revoke(claims.jti, 'the RFC 7009 revocation endpoint');
    } catch (e) {
      // RFC 7009: an invalid token is still a successful revocation.
      log.debug("Revocation: the token does not verify (" + e.message + "), so there is nothing to revoke.");
    }
  }
  res.status(200).set('Cache-Control', 'no-store').end();
  log.debug("Leaving the revocation endpoint. " + stats.revokedCount() + " token(s) revoked so far.");
});

// --- dynamic client registration (RFC 7591) + management (RFC 7592) ----------
function clientRecord(base, metadata, clientId, secret, token) {
  log.debug("Entering clientRecord(). client_id=" + clientId);
  const record = Object.assign({}, metadata, {
    client_id: clientId,
    client_id_issued_at: nowSec(),
    client_secret: secret,
    client_secret_expires_at: 0,               // 0 = never
    registration_access_token: token,
    registration_client_uri: base + '/oauth2/register/' + clientId
  });
  log.debug("Leaving clientRecord().");
  return record;
}

app.post('/oauth2/register', function (req, res) {
  log.debug("Entering the client registration endpoint.");
  const base = baseUrlOf(req);
  const metadata = parseBody(req);
  if (metadata.redirect_uris && !Array.isArray(metadata.redirect_uris)) {
    return oauthError(res, 400, 'invalid_redirect_uri', 'redirect_uris must be an array.');
  }
  const clientId = 'sts-mock-client-' + randomId(8);
  const record = clientRecord(base, metadata, clientId, randomId(24), randomId(24));
  registeredClients.set(clientId, record);
  res.status(201).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(record, null, 2));
  log.debug("Leaving the client registration endpoint. Registered " + clientId + ".");
});

// The management calls all authenticate with the registration access token the
// registration handed out.
function withRegisteredClient(req, res, handler) {
  log.debug("Entering withRegisteredClient(). client_id=" + req.params.client_id);
  const record = registeredClients.get(req.params.client_id);
  if (!record) {
    log.debug("Leaving withRegisteredClient(). No such client.");
    return oauthError(res, 404, 'invalid_client', 'No such registered client.');
  }
  const auth = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
  if (auth !== record.registration_access_token) {
    res.set('WWW-Authenticate', 'Bearer');
    log.debug("Leaving withRegisteredClient(). The registration access token did not match.");
    return oauthError(res, 401, 'invalid_token', 'The registration access token does not match.');
  }
  const result = handler(record);
  log.debug("Leaving withRegisteredClient().");
  return result;
}

app.get('/oauth2/register/:client_id', function (req, res) {
  log.debug("Entering the client read endpoint.");
  withRegisteredClient(req, res, function (record) {
    res.status(200).type('application/json').send(JSON.stringify(record, null, 2));
  });
  log.debug("Leaving the client read endpoint.");
});

app.put('/oauth2/register/:client_id', function (req, res) {
  log.debug("Entering the client update endpoint.");
  withRegisteredClient(req, res, function (record) {
    const updated = Object.assign({}, parseBody(req), {
      client_id: record.client_id,
      client_id_issued_at: record.client_id_issued_at,
      client_secret: record.client_secret,
      client_secret_expires_at: record.client_secret_expires_at,
      registration_access_token: record.registration_access_token,
      registration_client_uri: record.registration_client_uri
    });
    registeredClients.set(record.client_id, updated);
    res.status(200).type('application/json').send(JSON.stringify(updated, null, 2));
  });
  log.debug("Leaving the client update endpoint.");
});

app.delete('/oauth2/register/:client_id', function (req, res) {
  log.debug("Entering the client delete endpoint.");
  withRegisteredClient(req, res, function (record) {
    registeredClients.delete(record.client_id);
    res.status(204).end();
  });
  log.debug("Leaving the client delete endpoint.");
});

// --- the documents the metadata links to ------------------------------------
app.get('/docs', function (req, res) {
  log.debug("Entering the service documentation endpoint.");
  res.type('text/plain').send(
    'Mock authorization server (service_documentation).\n\n' +
    'Every endpoint in ' + baseUrlOf(req) + '/.well-known/oauth-authorization-server answers.\n' +
    'Tokens are RS256 JWTs signed with the key at ' + baseUrlOf(req) + '/oauth2/jwks.\n' +
    'No credential is ever verified: this server exists to exercise a client.\n');
  log.debug("Leaving the service documentation endpoint.");
});

app.get('/policy', function (req, res) {
  log.debug("Entering the policy document endpoint.");
  res.type('text/plain').send('Mock authorization server policy (op_policy_uri). Test data only.\n');
  log.debug("Leaving the policy document endpoint.");
});

app.get('/tos', function (req, res) {
  log.debug("Entering the terms of service endpoint.");
  res.type('text/plain').send('Mock authorization server terms of service (op_tos_uri). Test data only.\n');
  log.debug("Leaving the terms of service endpoint.");
});

module.exports = {
  asMetadata: asMetadata,
  accessToken: accessToken,
  tokenSet: tokenSet,
  registeredClients: registeredClients
  // The browser session used to be exported from here, because this module owned
  // the login flow it came out of. It does not any more: `authn.js` does, and
  // wsfed.js and admin.js take it from there. Re-exporting it would leave two
  // names for one store and a reader no way to tell which is the real one.
};
