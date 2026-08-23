// File: dpop.js
//
// ---------------------------------------------------------------------------
// The server's half of DPoP — RFC 9449, OAuth 2.0 Demonstrating Proof of
// Possession. This module is the checker; oauth2.js binds the tokens it issues
// and vc_issuer.js's protected endpoints demand a proof for them.
//
// Requiring this module registers nothing. It is a library, unlike the protocol
// modules beside it — there is no `app.get` here — so its position in
// server.js's require order does not matter. It requires helpers.js and nothing
// else, so it cannot be part of a cycle.
//
// What it is defending against. A Bearer access token (RFC 6750) is a password:
// anything that can read it can spend it, so a token leaked from a log, a proxy,
// a crash dump or an open redirect is a working credential until it expires. A
// DPoP-bound token carries `cnf.jkt`, the RFC 7638 thumbprint of a public key,
// and every request presenting it must also carry a fresh signature from the
// matching private key over that request's method and URI. The stolen bytes are
// then worthless without the key.
//
// RFC 9449 section 4.3 lists twelve checks a receiver MUST make. They are
// implemented here in that order and each is labelled with its number, because
// the ones that are easiest to leave out are the ones that quietly convert this
// from a proof of possession into a decoration:
//
//   * omit the SIGNATURE check (6) and any client can claim any key.
//   * omit `htm`/`htu` (8, 9) and one captured proof works at every endpoint —
//     including the token endpoint proof being replayed at the credential
//     endpoint.
//   * omit `ath` (12) and a proof captured with one token can be presented
//     with another, which is exactly the theft this is supposed to stop.
//   * omit the `cnf.jkt` comparison (12) and the token is not bound to
//     anything: the client simply presents its own key and is believed.
//   * omit `typ` (4) and some other JWT the client signed with the same key —
//     an OID4VCI credential proof of possession, say, which this very workflow
//     also signs — is accepted as a DPoP proof.
//
// Which is why tests/sts_dpop.js removes each of those checks in turn and
// requires that the suite notices.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
// jsonwebtoken and the STS key arrived with presentedAccessToken() below: it
// verifies an access token this service issued before believing its cnf. Still a
// leaf — jsonwebtoken is an npm package and helpers.js is this module's only
// project dependency, so the no-cycle property is unchanged.
const jwt = require('jsonwebtoken');
const helpers = require('../common/helpers');
// RFC 8705 — the other sender constraint. A library like this one: it registers
// nothing and requires only helpers.js and config.js, so requiring it here
// cannot create a cycle. It is required HERE rather than at the four protected
// endpoints because presentedAccessToken() below is the single check they share.
const mtls = require('./mtls');
// For one decision: whether to REFUSE an access token in a query string rather
// than merely ignore it (RFC 9700 section 4.3.2). A library that registers no
// route and requires only helpers.js, config.js and client_auth.js, so
// requiring it here cannot create a cycle.
const bcp = require('./oauth2_bcp');
const log = helpers.log;
const b64u = helpers.b64u;
const jsonFromB64u = helpers.jsonFromB64u;
const nowSec = helpers.nowSec;
const randomId = helpers.randomId;
const STS = helpers.STS;
const vciError = helpers.vciError;
// The one decision about whether a forwarded header is believable, shared with
// baseUrlOf() so that two functions in this service cannot answer it two ways.
const forwardedFrom = helpers.forwardedFrom;

const PROOF_TYP = 'dpop+jwt';

// The algorithms this server will check a proof with. RFC 9449 check 5: a
// registered ASYMMETRIC signature algorithm, never `none` and never a MAC. The
// list is deliberately explicit rather than "whatever the JWT library accepts":
// an allow-list is the only thing that stops an `alg` the client chose from
// selecting a verification path the server did not intend.
const ALGS = {
  ES256: { hash: 'sha256', kty: 'EC', crv: 'P-256', dsaEncoding: 'ieee-p1363' },
  ES384: { hash: 'sha384', kty: 'EC', crv: 'P-384', dsaEncoding: 'ieee-p1363' },
  ES512: { hash: 'sha512', kty: 'EC', crv: 'P-521', dsaEncoding: 'ieee-p1363' },
  RS256: { hash: 'sha256', kty: 'RSA' },
  RS384: { hash: 'sha384', kty: 'RSA' },
  RS512: { hash: 'sha512', kty: 'RSA' },
  PS256: { hash: 'sha256', kty: 'RSA', padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
           saltLength: 32 },
  PS384: { hash: 'sha384', kty: 'RSA', padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
           saltLength: 48 },
  PS512: { hash: 'sha512', kty: 'RSA', padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
           saltLength: 64 }
};
const SIGNING_ALGS = Object.keys(ALGS);

// RFC 9449 section 11.1: the acceptable window for a proof's `iat`. Short,
// because the window is how long a captured proof stays useful for the same
// method and URI; the nonce mechanism below is what shortens it further when a
// deployment cares.
const IAT_SKEW_SECONDS = 300;

// Replay detection (section 11.1). A `jti` seen once is refused thereafter. In a
// real deployment this is a shared cache with an eviction policy; here it is a
// Map of jti -> the second it was seen, pruned on use, which is all a mock needs
// and is honest about being bounded by the same window as `iat`.
const seenJtis = new Map();

// Server-supplied nonces (sections 8 and 9). OFF by default: the mechanism is a
// second round trip on the first request of every session, so a deployment opts
// in. `requireNonces()` is read per request rather than captured at require
// time, so a test can turn it on and off without restarting the service.
let nonceMode = false;
const issuedNonces = new Map();
const NONCE_TTL_SECONDS = 300;

function setNonceMode(on) {
  log.debug('Entering setNonceMode(). on=' + on);
  nonceMode = on === true;
  log.debug('Leaving setNonceMode(). DPoP nonces are ' + (nonceMode ? 'REQUIRED' : 'not required'));
  return nonceMode;
}

function nonceModeOn() {
  return nonceMode === true;
}

function issueNonce() {
  log.debug('Entering issueNonce().');
  pruneNonces();
  const nonce = randomId(16);
  issuedNonces.set(nonce, nowSec());
  log.debug('Leaving issueNonce().');
  return nonce;
}

function pruneNonces() {
  const cutoff = nowSec() - NONCE_TTL_SECONDS;
  issuedNonces.forEach(function (issued, nonce) {
    if (issued < cutoff) issuedNonces.delete(nonce);
  });
}

function nonceIsCurrent(nonce) {
  log.debug('Entering nonceIsCurrent().');
  pruneNonces();
  const ok = !!nonce && issuedNonces.has(String(nonce));
  log.debug('Leaving nonceIsCurrent(). ok=' + ok);
  return ok;
}

// ---------------------------------------------------------------------------
// The JWK Thumbprint, RFC 7638 — the value that becomes `cnf.jkt`.
//
// Built member by member in the specification's own order rather than by sorting
// the key's members, so a key carrying a `kid` or Web Crypto's `key_ops`/`ext`
// hashes to the same value as the same key without them. That is not tidiness:
// the wallet sends its key in every proof header, and if a stray member changed
// the digest the token would stop matching its own key.
// ---------------------------------------------------------------------------
const THUMBPRINT_MEMBERS = {
  EC: ['crv', 'kty', 'x', 'y'],
  RSA: ['e', 'kty', 'n'],
  OKP: ['crv', 'kty', 'x'],
  oct: ['k', 'kty']
};

function canonicalJwk(jwk) {
  log.debug('Entering canonicalJwk().');
  if (!jwk || !jwk.kty) throw new Error('a JWK Thumbprint needs a key with a kty.');
  const members = THUMBPRINT_MEMBERS[jwk.kty];
  if (!members) throw new Error('no RFC 7638 member list for kty ' + jwk.kty + '.');
  const missing = members.filter(function (m) {
    return jwk[m] === undefined || jwk[m] === null || jwk[m] === '';
  });
  if (missing.length) {
    throw new Error('this ' + jwk.kty + ' key is missing ' + missing.join(', ') + '.');
  }
  log.debug('Leaving canonicalJwk().');
  return '{' + members.map(function (m) {
    return JSON.stringify(m) + ':' + JSON.stringify(jwk[m]);
  }).join(',') + '}';
}

function thumbprint(jwk) {
  log.debug('Entering thumbprint().');
  const jkt = b64u(crypto.createHash('sha256').update(canonicalJwk(jwk), 'utf8').digest());
  log.debug('Leaving thumbprint(). jkt=' + jkt);
  return jkt;
}

// `ath`, RFC 9449 section 4.2: base64url(SHA-256(ASCII(access token))).
function athOf(accessToken) {
  return b64u(crypto.createHash('sha256').update(String(accessToken), 'ascii').digest());
}

// ---------------------------------------------------------------------------
// `htu` — the request's own target URI, without query or fragment, normalized
// the way section 4.3 asks (RFC 3986 syntax- and scheme-based normalization).
//
// Behind a proxy this has to be the URI the CLIENT used, not the one the socket
// saw: with the api or a CORS proxy in front of this service, `req.protocol`
// and `req.get('host')` describe the last hop and every proof would be refused
// for naming the real endpoint.
//
// **THE FORWARDED HEADERS ARE HONOURED ONLY WHERE A PROXY IS TRUSTED**, and
// that is a change — this function used to believe them unconditionally, while
// `baseUrlOf()` in helpers.js ignored them, so two functions in one service
// disagreed about whether a forwarded header was believable. They share
// `forwardedFrom()` now and one setting decides.
//
// It is the htu check that makes the setting matter rather than the metadata.
// `htu` binds a proof to the endpoint it was made for, which is what stops a
// proof captured at one endpoint being replayed at another — and if a CLIENT
// can set the expected value with a header, it can name the endpoint it stole
// the proof from and the binding stops meaning anything. So with
// `global.trustProxy` off, what the socket saw is what a proof must name; the
// refusal in check 9 says so, and names the setting, because a proof refused
// for a reason nobody can see is an afternoon.
// ---------------------------------------------------------------------------
function htuOf(req) {
  log.debug('Entering htuOf().');
  const from = forwardedFrom(req);
  const proto = String(from.proto || 'http').toLowerCase();
  const host = String(from.host || '').trim().toLowerCase();
  // req.originalUrl carries the query; the path alone is what belongs here.
  const path = String(req.originalUrl || req.url || '/').split('?')[0].split('#')[0];
  let hostname = host;
  let port = '';
  const colon = host.lastIndexOf(':');
  if (colon > -1 && host.indexOf(']') < colon) {
    hostname = host.slice(0, colon);
    port = host.slice(colon + 1);
  }
  if ((proto === 'https' && port === '443') || (proto === 'http' && port === '80')) port = '';
  const htu = proto + '://' + hostname + (port ? ':' + port : '') + path;
  log.debug('Leaving htuOf(). htu=' + htu);
  return htu;
}

function normalizeHtu(value) {
  log.debug('Entering normalizeHtu(). value=' + value);
  let parsed;
  try {
    parsed = new URL(String(value));
  } catch (e) {
    // Unparseable, so it cannot match anything. Returned as-is so the caller's
    // comparison fails and says what arrived, rather than throwing.
    log.debug('Leaving normalizeHtu(). Not a URL.');
    return String(value || '');
  }
  const scheme = parsed.protocol.toLowerCase();
  let port = parsed.port;
  if ((scheme === 'https:' && port === '443') || (scheme === 'http:' && port === '80')) port = '';
  const out = scheme + '//' + parsed.hostname.toLowerCase() + (port ? ':' + port : '') +
              parsed.pathname;
  log.debug('Leaving normalizeHtu(). out=' + out);
  return out;
}

// ---------------------------------------------------------------------------
// The twelve checks.
//
// Returns { ok: true, jkt, jwk, claims } or { ok: false, error, description,
// needNonce }. It never sends a response: the caller decides the status code and
// the header shape, because an authorization server says `use_dpop_nonce` in a
// 400 JSON body while a resource server says it in a 401 WWW-Authenticate, and
// this module has no business knowing which of the two it is serving.
// ---------------------------------------------------------------------------
function verifyProof(rawHeader, opts) {
  log.debug('Entering verifyProof(). htm=' + (opts && opts.htm) + ', htu=' + (opts && opts.htu));
  const options = opts || {};
  const fail = function (description, extra) {
    log.debug('Leaving verifyProof(). REFUSED: ' + description);
    return Object.assign({ ok: false, error: 'invalid_dpop_proof', description: description },
                         extra || {});
  };

  // Check 1: not more than one DPoP header field. Express joins repeated header
  // fields with ", " — and a compact JWS contains no comma — so a comma here
  // means two headers arrived, and accepting either of them would let an
  // attacker append their own proof to a captured request.
  if (rawHeader === undefined || rawHeader === null || String(rawHeader).trim() === '') {
    return fail('No DPoP proof was presented.', { missing: true });
  }
  const raw = String(rawHeader).trim();
  if (raw.indexOf(',') >= 0) {
    return fail('More than one DPoP header field was sent; RFC 9449 permits exactly one.');
  }

  // Check 2: a single well-formed JWT.
  const parts = raw.split('.');
  if (parts.length !== 3) {
    return fail('The DPoP proof is not a compact JWS with three parts.');
  }
  let header;
  let claims;
  try {
    header = jsonFromB64u(parts[0]);
    claims = jsonFromB64u(parts[1]);
  } catch (e) {
    return fail('The DPoP proof could not be decoded: ' + e.message);
  }
  if (!header || typeof header !== 'object' || !claims || typeof claims !== 'object') {
    return fail('The DPoP proof header or payload is not a JSON object.');
  }

  // Check 4: typ. Before the signature, because it costs nothing and it is the
  // check that stops a JWT signed for another purpose being accepted here.
  if (header.typ !== PROOF_TYP) {
    return fail('The DPoP proof must have typ "' + PROOF_TYP + '"; this one has ' +
                JSON.stringify(header.typ) + '. Without this check some other JWT the client ' +
                'signed with the same key would be accepted as a proof.');
  }

  // Check 5: a supported asymmetric algorithm, not none and not a MAC.
  const spec = ALGS[header.alg];
  if (!spec) {
    return fail('The DPoP proof is signed with ' + JSON.stringify(header.alg) +
                ', which this server does not accept. RFC 9449 requires a registered ' +
                'asymmetric algorithm, never none and never a MAC: ' + SIGNING_ALGS.join(', ') + '.');
  }

  // Check 7: the jwk header must carry a public key and no private key. Checked
  // before the signature, because importing a key object that carries private
  // material would let a client hand over a whole key pair and be believed.
  const jwk = header.jwk;
  if (!jwk || typeof jwk !== 'object' || !jwk.kty) {
    return fail('The DPoP proof header must carry the public key as a jwk.');
  }
  const privateMembers = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'].filter(function (m) {
    return jwk[m] !== undefined;
  });
  if (privateMembers.length) {
    return fail('The DPoP proof header carries private key material (' +
                privateMembers.join(', ') + '), which RFC 9449 forbids.');
  }
  if (jwk.kty !== spec.kty || (spec.crv && jwk.crv !== spec.crv)) {
    return fail('The DPoP proof header key (' + jwk.kty + (jwk.crv ? '/' + jwk.crv : '') +
                ') does not match its alg ' + header.alg + '.');
  }

  // Check 3: all required claims. Named individually so the client is told which.
  const required = ['jti', 'htm', 'htu', 'iat'];
  const absent = required.filter(function (c) {
    return claims[c] === undefined || claims[c] === null || claims[c] === '';
  });
  if (absent.length) {
    return fail('The DPoP proof is missing ' + absent.join(', ') + '.');
  }

  // Check 6: the signature verifies with the key in the header.
  let publicKey;
  try {
    publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  } catch (e) {
    return fail('The DPoP proof header key could not be read: ' + e.message);
  }
  const signingInput = Buffer.from(parts[0] + '.' + parts[1], 'ascii');
  let signature;
  try {
    signature = Buffer.from(parts[2].replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  } catch (e) {
    return fail('The DPoP proof signature is not base64url.');
  }
  const verifyKey = { key: publicKey };
  if (spec.dsaEncoding) verifyKey.dsaEncoding = spec.dsaEncoding;
  if (spec.padding) verifyKey.padding = spec.padding;
  if (spec.saltLength !== undefined) verifyKey.saltLength = spec.saltLength;
  let signatureOk = false;
  try {
    signatureOk = crypto.verify(spec.hash, signingInput, verifyKey, signature);
  } catch (e) {
    // A malformed signature makes node throw rather than return false. Same
    // outcome for the client, but say so rather than letting it become a 500.
    log.debug('the DPoP proof signature could not be checked: ' + e.message);
    signatureOk = false;
  }
  if (!signatureOk) {
    return fail('The DPoP proof signature does not verify with the key in its own header.');
  }

  // Check 8: htm matches this request's method.
  if (String(claims.htm).toUpperCase() !== String(options.htm || '').toUpperCase()) {
    return fail('The DPoP proof was made for HTTP ' + claims.htm + ', but this is a ' +
                options.htm + ' request.');
  }

  // Check 9: htu matches this request's URI, ignoring query and fragment.
  const presented = normalizeHtu(claims.htu);
  const expected = normalizeHtu(options.htu);
  if (presented !== expected) {
    // The commonest cause of this on a deployment that works everywhere else is
    // a reverse proxy: the client made the request to the proxy's URL, the
    // socket here saw the last hop's, and the two differ in scheme, host or
    // both. So the setting is named rather than left to be discovered — a proof
    // refused for a reason nobody can see is an afternoon, and this refusal
    // would otherwise read as the client's bug.
    return fail('The DPoP proof was made for ' + claims.htu + ', but this request went to ' +
                options.htu + '.' +
                (helpers.trustProxy()
                  ? ''
                  : ' If something is terminating TLS in front of this service, that is why: ' +
                    'global.trustProxy is OFF, so X-Forwarded-Proto and X-Forwarded-Host are ' +
                    'ignored and this server describes the LAST HOP rather than the URL the ' +
                    'client used. Turn it on where a proxy really is in front — and leave it ' +
                    'off where one is not, because those are headers any client can set, and ' +
                    'a client that chooses its own htu has unbound its own proof.'));
  }

  // Check 11: iat within an acceptable window.
  const age = nowSec() - Number(claims.iat);
  if (!isFinite(age) || Math.abs(age) > IAT_SKEW_SECONDS) {
    return fail('The DPoP proof iat is ' + (isFinite(age) ? age + ' seconds away' : 'not a number') +
                '; this server accepts ' + IAT_SKEW_SECONDS + ' seconds either way.');
  }

  // Check 10: the nonce, when this server is asking for one. The order matters:
  // a missing nonce is not a refusal but a REQUEST, answered with a fresh nonce
  // for the client to retry with, so it is reported separately from a wrong one.
  if (nonceModeOn()) {
    if (claims.nonce === undefined) {
      return fail('This server requires a DPoP nonce.', { needNonce: true });
    }
    if (!nonceIsCurrent(claims.nonce)) {
      return fail('The DPoP proof nonce is not one this server issued, or it has expired.',
                  { needNonce: true });
    }
  }

  // Section 11.1: replay. A proof is good for one request.
  pruneJtis();
  if (seenJtis.has(String(claims.jti))) {
    return fail('This DPoP proof has already been used (jti ' + claims.jti + '). A proof is ' +
                'good for one request.');
  }

  // Check 12, first half: ath, when an access token came with the proof.
  const jkt = thumbprint(jwk);
  if (options.accessToken) {
    if (claims.ath === undefined) {
      return fail('The DPoP proof must carry ath when it accompanies an access token; without ' +
                  'it a proof captured with one token could be presented with another.');
    }
    if (claims.ath !== athOf(options.accessToken)) {
      return fail('The DPoP proof ath does not match the access token presented with it.');
    }
  }

  // Check 12, second half: the token's own binding. This is the comparison that
  // makes the token sender-constrained — without it the client simply presents
  // whichever key it likes and is believed.
  if (options.expectedJkt && options.expectedJkt !== jkt) {
    return fail('The access token is bound to a different key than the one that signed this ' +
                'DPoP proof (cnf.jkt ' + options.expectedJkt + ', proof key ' + jkt + ').');
  }

  seenJtis.set(String(claims.jti), nowSec());
  log.debug('Leaving verifyProof(). Accepted. jkt=' + jkt);
  return { ok: true, jkt: jkt, jwk: jwk, claims: claims, header: header };
}

function pruneJtis() {
  const cutoff = nowSec() - (IAT_SKEW_SECONDS * 2);
  seenJtis.forEach(function (seen, jti) {
    if (seen < cutoff) seenJtis.delete(jti);
  });
}

// The confirmation a token carries, if any. RFC 9449 section 6.1 puts it in
// `cnf.jkt`; a token without one is a Bearer token and must be presented as one.
function jktOf(claims) {
  return (claims && claims.cnf && typeof claims.cnf.jkt === 'string') ? claims.cnf.jkt : '';
}

// For tests and for /sts-metadata: what this server will accept.
function state() {
  return {
    signing_alg_values_supported: SIGNING_ALGS,
    nonces_required: nonceModeOn(),
    iat_skew_seconds: IAT_SKEW_SECONDS,
    proofs_remembered: seenJtis.size,
    nonces_outstanding: issuedNonces.size
  };
}

// Only for tests that need a clean slate: the replay cache is deliberately
// process-wide, so a test asserting "a fresh proof is accepted" after asserting
// "a replayed one is refused" needs a way to forget.
function forgetProofs() {
  log.debug('Entering forgetProofs(). ' + seenJtis.size + ' remembered proof(s) discarded.');
  seenJtis.clear();
  log.debug('Leaving forgetProofs().');
}

// ---------------------------------------------------------------------------
// The access token on a protected endpoint — Bearer (RFC 6750) or DPoP (RFC
// 9449 section 7).
//
// Three of this service's protected endpoints — Credential, Deferred Credential
// and Notification — used to carry their own copy of a Bearer-only check. They
// share this one, because a per-endpoint copy is how one of three ends up not
// demanding the proof, and the endpoint that forgot is the one an attacker would
// use.
//
// **It lives here rather than in vc_issuer.js, where it was written, because
// there are now four.** /oauth2/userinfo is the fourth, and it is in oauth2.js —
// a module vc_issuer.js cannot be required from without either building a cycle
// or moving OID4VCI ahead of OAuth2 in the route order. Copying the check into
// the OAuth2 module instead is precisely the mistake the paragraph above records
// having already been made once. dpop.js registers no routes and requires only
// helpers.js, so it is the one place both callers can reach.
//
// It answers the request itself on failure and returns null, so a caller reads:
//
//   const presented = dpop.presentedAccessToken(req, res, 'the credential endpoint');
//   if (!presented) return;
//
// What it will and will not vouch for. OID4VCI lets the authorization server be
// somebody else (this suite points the metadata at Keycloak), so a token this
// issuer cannot verify is still accepted — that is stated at the top of
// vc_issuer.js and has not changed. The consequence for DPoP is worth being
// explicit about: `cnf.jkt` is read from a token whose signature may be
// unverifiable here, so for a foreign token the binding is checked between the
// proof and a claim anyone could have written. When the token IS one of ours the
// signature is checked first and the binding is real. A production resource
// server has no such excuse and must verify the token before trusting its cnf.
//
// `verified` in the returned object is how a caller that CANNOT live with that
// tells the difference: the userinfo endpoint refuses a token it did not issue,
// because a profile is a statement about somebody this server authenticated, and
// there is nothing it can honestly say about the subject of a signature it
// cannot check.
// ---------------------------------------------------------------------------
// The audiences a token issued here carries, as this service's own resource
// server. `<base>/resource` is what accessToken() mints when nothing narrows
// it; anything else on the token came from an RFC 8707 `resource` parameter and
// names a resource server that is not this one.
//
// The path ENDS WITH `/resource` rather than equalling it, because this process
// publishes several authorization servers and a named one issues for
// `<base>/{id}/resource` — its own resource server, under its own name. Testing
// for equality refused every token any named authorization server had ever
// issued, at every protected endpoint, with a message about audience
// restriction that was true and completely misleading.
//
// What it still refuses is what it was written for: an audience from a
// `resource` parameter, which names somebody else's server and does not end
// there.
function isOwnResourceAudience(value) {
  const text = String(value || '');
  if (!text) {
    return false;
  }
  try {
    const path = new URL(text).pathname;
    return path === '/resource' || path.endsWith('/resource');
  } catch (e) {
    // Not a URL. RFC 8707 requires an absolute URI, and the default audience is
    // one — so an audience that does not parse was not minted by this service's
    // own default and is not this resource server.
    return false;
  }
}

function audienceRefusal(claims, verified) {
  log.debug("Entering audienceRefusal().");
  if (!verified || !claims || claims.aud === undefined) {
    log.debug("Leaving audienceRefusal(). Not ours, or it names no audience.");
    return null;
  }
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (audiences.some(isOwnResourceAudience)) {
    log.debug("Leaving audienceRefusal(). This token is for this resource server.");
    return null;
  }
  log.debug("Leaving audienceRefusal(). It names " + audiences.join(', ') + ".");
  return {
    error: 'invalid_token',
    description: 'RFC 9700 section 2.3: an access token is audience-restricted and a resource ' +
                 'server must refuse one issued for a different audience. This token names ' +
                 audiences.map(function (one) { return '"' + one + '"'; }).join(', ') +
                 ', and the endpoints here are the resource server this service issues for. A ' +
                 'token narrowed with the RFC 8707 `resource` parameter is usable at THAT ' +
                 'resource server and nowhere else, which is the whole of what the restriction ' +
                 'buys.'
  };
}

function presentedAccessToken(req, res, where) {
  log.debug("Entering presentedAccessToken(). where=" + where);
  // RFC 9700 section 4.3.2 — an access token MUST NOT travel in a URI query
  // parameter. RFC 6750 section 2.3 defines a form that does, and this service
  // has never read it: the token comes from the Authorization header and
  // nowhere else, so one in the query has always been simply ignored.
  //
  // IGNORED IS NOT THE SAME AS REFUSED, and the difference is what this adds.
  // A client that sends `?access_token=...` gets a 401 saying a token is
  // required — which is true, unhelpful, and sends somebody looking at their
  // credential rather than at where they put it. In RFC 9700 mode the query is
  // looked at ONLY to say so, and the refusal names the reason: a URL goes into
  // browser history, into the address bar, into server logs and into the
  // Referer of anything the page then fetches, and a token in one is a token in
  // all of those.
  //
  // The token itself is never echoed back. It has already been somewhere it
  // should not be; putting it in a response body would be one more place.
  const inQuery = req.query && (req.query.access_token !== undefined ||
                                req.query.token !== undefined);
  if (inQuery && bcp.enabled()) {
    res.set('WWW-Authenticate', 'Bearer error="invalid_request"');
    log.warn('RFC 9700 section 4.3.2: a request to ' + (where || 'a protected endpoint') +
             ' carried an access token in the QUERY STRING. Refused. That URL is now in this ' +
             'client\'s browser history and in whatever logged the request.');
    log.debug("Leaving presentedAccessToken(). A token was in the query string.");
    vciError(res, 400, 'invalid_request',
      'RFC 9700 section 4.3.2: an access token must not be sent in a URI query parameter. ' +
      'RFC 6750 section 2.3 defines that form and its own specification does not recommend it, ' +
      'because a URL ends up in browser history, in the address bar, in server logs and in the ' +
      'Referer header of anything the page goes on to fetch — so the token is in all of those ' +
      'too. This endpoint reads the Authorization header only, and treat the token you just ' +
      'sent as disclosed.');
    return null;
  }
  const auth = String(req.headers['authorization'] || '');
  const match = /^(Bearer|DPoP)\s+(\S+)\s*$/i.exec(auth);
  if (!match) {
    // Both schemes are offered in the challenge, since either is acceptable
    // here; RFC 9449 section 7.1 requires DPoP to appear when the server
    // supports it, or a client has no way to discover that it may use it.
    res.set('WWW-Authenticate', 'DPoP algs="' + SIGNING_ALGS.join(' ') + '", Bearer');
    log.debug("Leaving presentedAccessToken(). No access token.");
    vciError(res, 401, 'invalid_token',
      'An access token is required, presented as "Bearer <token>" or, when it is DPoP-bound, ' +
      'as "DPoP <token>" with a DPoP proof.');
    return null;
  }
  const scheme = match[1].toLowerCase();
  const accessToken = match[2];

  // What the token says about its own binding. Verified where possible: an
  // unverified token could have a cnf its holder wrote.
  let claims = null;
  let verified = false;
  try {
    claims = jwt.verify(accessToken, STS.certPem, { algorithms: ['RS256'] });
    verified = true;
  } catch (e) {
    log.debug("This access token is not one of ours, so its claims are read unverified: " +
              e.message);
    try {
      claims = jsonFromB64u(String(accessToken).split('.')[1]) || {};
    } catch (e2) {
      // Not a JWT at all. Opaque tokens are legal, and this issuer accepts them
      // as it always has — there is simply no binding to find in one.
      log.debug("...and it is not a JWT either, so there is no cnf to read: " + e2.message);
      claims = {};
    }
  }
  const boundTo = jktOf(claims);

  // RFC 8705 section 3.1 — the OTHER sender constraint, checked here for the
  // same reason the DPoP one is: this function is the single check the four
  // protected endpoints share, and a second one beside it would be a fourth
  // caller nobody updated. It refuses nothing on a token that carries no
  // certificate confirmation, so a Bearer or DPoP request is untouched.
  const certificateProblem = mtls.checkBinding(claims, req, verified);
  if (certificateProblem) {
    res.set('WWW-Authenticate', 'Bearer error="invalid_token"');
    log.debug("Leaving presentedAccessToken(). The certificate binding did not hold.");
    vciError(res, 401, certificateProblem.error, certificateProblem.description);
    return null;
  }

  // RFC 9700 section 2.3 — an access token is audience-restricted, and a
  // resource server MUST refuse one that names a different audience. Only for a
  // token this service ISSUED, which is the same judgement made about cnf above:
  // the `aud` of a token signed by somebody else is a string this service cannot
  // check and was never the audience of anyway.
  //
  // What counts as "this resource server" is deliberately the PATH and not the
  // whole URL. Every token issued here carries `<base>/resource`, and the base
  // is whatever URL the request that minted it arrived on — so a token minted at
  // localhost:8081 and presented at 127.0.0.1:8081 would fail a whole-URL
  // comparison while being, in every sense that matters, a token for this
  // service. What the check is FOR is a token narrowed to somebody else by an
  // RFC 8707 `resource` parameter, and that always has a different path.
  const audienceProblem = audienceRefusal(claims, verified);
  if (audienceProblem) {
    res.set('WWW-Authenticate', 'Bearer error="invalid_token"');
    log.debug("Leaving presentedAccessToken(). The audience is somebody else's.");
    vciError(res, 401, audienceProblem.error, audienceProblem.description);
    return null;
  }

  // A bound token presented as Bearer is a protocol error even though the bytes
  // are the same. Accepting it would throw the binding away silently, which is
  // the single most likely way to implement DPoP and gain nothing.
  if (boundTo && scheme !== 'dpop') {
    res.set('WWW-Authenticate', 'DPoP error="invalid_token", error_description="the token is ' +
                                'DPoP-bound and must be presented with the DPoP scheme"');
    log.debug("Leaving presentedAccessToken(). A bound token was presented as Bearer.");
    vciError(res, 401, 'invalid_token',
      'This access token is DPoP-bound (it carries cnf.jkt), so it must be presented as ' +
      '"Authorization: DPoP <token>" with a DPoP proof — not as a Bearer token.');
    return null;
  }

  // No binding and no proof: a plain Bearer request, exactly as before.
  if (!boundTo && req.headers['dpop'] === undefined) {
    log.debug("Leaving presentedAccessToken(). A Bearer request. verified=" + verified);
    return { accessToken: accessToken, claims: claims, scheme: scheme, jkt: '', verified: verified };
  }

  const checked = verifyProof(req.headers['dpop'], {
    htm: req.method,
    htu: htuOf(req),
    accessToken: accessToken,
    expectedJkt: boundTo
  });
  if (!checked.ok) {
    // RFC 9449 section 9: a RESOURCE server asks for a nonce with a 401 and
    // `use_dpop_nonce` in WWW-Authenticate — not with the 400 JSON body an
    // authorization server uses. Getting this shape wrong leaves a conforming
    // wallet unable to proceed, so the two are deliberately not shared.
    if (checked.needNonce) {
      res.set('DPoP-Nonce', issueNonce());
      res.set('WWW-Authenticate', 'DPoP error="use_dpop_nonce", error_description="Resource ' +
                                  'server requires nonce in DPoP proof"');
      log.debug("Leaving presentedAccessToken(). Asking the wallet for a DPoP nonce.");
      vciError(res, 401, 'use_dpop_nonce', 'Resource server requires nonce in DPoP proof');
      return null;
    }
    res.set('WWW-Authenticate', 'DPoP error="invalid_dpop_proof"');
    log.debug("Leaving presentedAccessToken(). The DPoP proof was refused.");
    vciError(res, 401, 'invalid_dpop_proof', checked.description);
    return null;
  }
  log.debug("Leaving presentedAccessToken(). A valid DPoP request. jkt=" + checked.jkt +
            ", token verified=" + verified);
  return {
    accessToken: accessToken, claims: claims, scheme: scheme, jkt: checked.jkt,
    verified: verified, dpop: checked
  };
}

module.exports = {
  PROOF_TYP: PROOF_TYP,
  SIGNING_ALGS: SIGNING_ALGS,
  IAT_SKEW_SECONDS: IAT_SKEW_SECONDS,
  canonicalJwk: canonicalJwk,
  thumbprint: thumbprint,
  athOf: athOf,
  htuOf: htuOf,
  normalizeHtu: normalizeHtu,
  verifyProof: verifyProof,
  jktOf: jktOf,
  setNonceMode: setNonceMode,
  nonceModeOn: nonceModeOn,
  issueNonce: issueNonce,
  nonceIsCurrent: nonceIsCurrent,
  state: state,
  forgetProofs: forgetProofs,
  presentedAccessToken: presentedAccessToken
};
