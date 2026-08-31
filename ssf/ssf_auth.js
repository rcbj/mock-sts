'use strict';
//
// File: ssf_auth.js
//
// ---------------------------------------------------------------------------
// WHO MAY DRIVE A STREAM.
//
// SSF 1.0 section 8 says the management, status, subject, verification and
// poll endpoints MUST be protected, and — unlike RFC 7644, which names six
// schemes and leaves it there — it says the transmitter PUBLISHES what it
// accepts, in `authorization_schemes` on its configuration metadata. So a
// receiver discovers how to authenticate rather than guessing, and this
// module's list and that member are one table.
//
// **TWO SCHEMES, NOT SIX, AND THAT IS A DECISION.** SCIM offers all six of RFC
// 7644's because RFC 7644 names all six and a provisioning client meets them
// in the wild. SSF names none: `authorization_schemes` is an open list of
// `spec_urn` values and the only one the specification's own examples use is
// OAuth 2.0. So this offers the one the specification points at and HTTP Basic
// beside it, which exists for the reason the SCIM one exists — a client under
// test that has not implemented a token flow yet can still reach every
// endpoint, and its 401 path stays reachable when the credential is wrong.
//
// **IT IS A TURNSTILE AND NOT A LOCK**, exactly as `scim/CLAUDE.md` says of
// its own: anybody can get a token with either SSF scope from this service's
// token endpoint with any grant, and any username with any password but
// `invalid` passes Basic. What the gate buys is that a client's 401, 403 and
// scope-handling paths can be run at all — none of which an unauthenticated
// endpoint can exercise.
//
// **TWO SCOPES, AND THE DIFFERENCE IS REAL.** `ssf:read` reads a stream, its
// status and the poll queue; `ssf:write` creates, changes and deletes one,
// adds and removes subjects, sets a status and asks for a verification event.
// A read token is refused for every one of those with a 403 naming the scope,
// which is the second place in this service where two scopes differ in what
// they permit.
//
// ---------------------------------------------------------------------------
// THE METADATA IS OPEN EITHER WAY AND MUST STAY SO.
//
// `/.well-known/ssf-configuration` is never gated. A receiver has to be able to
// read what the endpoints are and which schemes they take BEFORE it can
// authenticate to one, and a transmitter whose discovery document needs a
// credential is one nothing can bootstrap against. It is the same rule
// `scim.authDiscovery` expresses for the ServiceProviderConfig, with the
// setting left out because there is no version of this that is useful closed.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). It registers no route. It requires `helpers.js`,
// `config.js` and `oauth-oidc/dpop.js` — the last for
// `presentedAccessToken()`, which is the ONE access-token check the protected
// endpoints in this service share and must not be written a second time here.
// `dpop.js` is itself a library requiring only `helpers.js` and leaves, so
// this cannot join a cycle.
// ---------------------------------------------------------------------------

const { log, hasScope, capturingResponse, capturedDescription } =
  require('../common/helpers');
const config = require('../common/config');
const dpop = require('../oauth-oidc/dpop');

// The `authorization_schemes` this transmitter publishes. `spec_urn` is the
// member SSF 1.0 section 7.1 defines; the rest is prose for `GET /ssf` and for
// the console, and no receiver reads it.
const SCHEMES = [
  { id: 'oauth', spec_urn: 'urn:ietf:rfc:6749',
    name: 'OAuth 2.0 access token',
    what: 'A Bearer or DPoP-bound access token this service issued, ' +
          'carrying ssf:read or ssf:write. It is the scheme SSF 1.0\'s own ' +
          'examples use, and the only one of the two that can express a ' +
          'DIFFERENCE between reading a stream and changing one.' },
  { id: 'basic', spec_urn: 'urn:ietf:rfc:7617',
    name: 'HTTP Basic',
    what: 'Any username with any password except the reserved "invalid", ' +
          'which is refused so that a 401 stays reachable. It grants BOTH ' +
          'scopes — a scheme with no scope in it cannot express the ' +
          'distinction, and pretending otherwise would be a refusal a ' +
          'client could not act on.' }
];

// The one password Basic refuses, so that a wrong-credential path exists at
// all. The same value and the same reasoning as SCIM's.
const REFUSED_PASSWORD = 'invalid';

function authRequired() {
  log.debug('Entering authRequired().');
  const on = !!config.value('ssf.authRequired');
  log.debug('Leaving authRequired(). ' + on);
  return on;
}

function scopeRead() {
  log.debug('Entering scopeRead().');
  const value = String(config.value('ssf.authScopeRead') || 'ssf:read');
  log.debug('Leaving scopeRead(). ' + value);
  return value;
}

function scopeWrite() {
  log.debug('Entering scopeWrite().');
  const value = String(config.value('ssf.authScopeWrite') || 'ssf:write');
  log.debug('Leaving scopeWrite(). ' + value);
  return value;
}

// The realm named in every challenge. One string, so a client that caches a
// credential per realm caches it once.
function realm() {
  log.debug('Entering realm().');
  log.debug('Leaving realm().');
  return 'ssf';
}

// What a 401 offers, in the order this service prefers them.
function challenges() {
  log.debug('Entering challenges().');
  const list = ['Bearer realm="' + realm() + '", scope="' + scopeRead() +
    ' ' + scopeWrite() + '"',
    'Basic realm="' + realm() + '", charset="UTF-8"'];
  log.debug('Leaving challenges(). ' + list.length + '.');
  return list;
}

function authorizationScheme(req) {
  log.debug('Entering authorizationScheme().');
  const header = String((req.headers || {}).authorization || '');
  const scheme = header.split(' ')[0].toLowerCase();
  log.debug('Leaving authorizationScheme(). ' + (scheme || '(none)'));
  return scheme;
}

function refusal(status, description, headers, err) {
  log.debug('Entering refusal(). ' + status);
  log.debug('Leaving refusal().');
  return { ok: false, status: status, err: err || 'authentication_failed',
    description: description, headers: headers || {}, principal: '',
    scheme: '', scopes: '' };
}

// ---------------------------------------------------------------------------
// THE OAUTH ATTEMPT.
//
// It goes through `dpop.presentedAccessToken()` and NOT through a check of its
// own, for the reason `scim/scim_auth.js` gives at length about the same call:
// that function carries the RFC 9449 proof and the 401/DPoP-Nonce handshake,
// the RFC 8705 certificate binding, the RFC 9700 refusal of a token in the
// query string and the RFC 8707 audience check, and a second implementation
// would be a version behind within a release.
//
// What it will not do is speak SSF, so it is handed a recording response
// (`helpers.capturingResponse()`) and what it would have said is translated
// into the `{err, description}` shape RFC 8935 and this family use. THE
// HEADERS IT SET ARE KEPT VERBATIM — DPoP-Nonce and the `use_dpop_nonce`
// challenge are how a client learns to retry.
// ---------------------------------------------------------------------------
function attemptOAuth(req, need) {
  log.debug('Entering attemptOAuth().');
  const scheme = authorizationScheme(req);
  if (scheme !== 'bearer' && scheme !== 'dpop') {
    log.debug('Leaving attemptOAuth(). No OAuth credential.');
    return null;
  }
  const shim = capturingResponse();
  const presented = dpop.presentedAccessToken(req, shim.res,
                                              'the SSF endpoints');
  if (!presented) {
    log.debug('Leaving attemptOAuth(). The shared check refused it.');
    return refusal(shim.captured.status || 401,
      capturedDescription(shim.captured) ||
      'This access token could not be accepted.', shim.captured.headers);
  }
  const claims = presented.claims || {};
  if (!presented.verified) {
    log.debug('Leaving attemptOAuth(). Not a token this service signed.');
    return refusal(401,
      'This access token was not issued by this service, or its signature ' +
      'does not verify against the key at /oauth2/jwks. A scope on a token ' +
      'nobody verified is a permission its holder wrote for themselves, and ' +
      'these endpoints decide what this transmitter delivers to whom. Get a ' +
      'token from this service\'s token endpoint with any grant.',
      { 'WWW-Authenticate': challenges() });
  }
  if (claims.typ !== 'Bearer') {
    log.debug('Leaving attemptOAuth(). Wrong token type.');
    return refusal(401,
      'This is a "' + (claims.typ || 'unknown') + '" token, not an access ' +
      'token. Every token this service issues is signed with the same key, ' +
      'so the typ claim is the only thing that tells a refresh token or an ' +
      'ID Token apart from the access token these endpoints need.',
      { 'WWW-Authenticate': challenges() });
  }
  const scopes = String(claims.scope || '');
  const required = need === 'write' ? scopeWrite() : scopeRead();
  if (need !== 'none' && !hasScope(scopes, required)) {
    log.debug('Leaving attemptOAuth(). Missing the "' + required + '" scope.');
    return refusal(403,
      'This access token carries ' + (scopes
        ? 'the scope(s) "' + scopes + '"' : 'no scope at all') + ' and this ' +
      'operation needs "' + required + '". The two scopes are not the same ' +
      'permission: "' + scopeRead() + '" reads a stream, its status and its ' +
      'poll queue, and "' + scopeWrite() + '" changes what this transmitter ' +
      'delivers and to whom. Ask for the one you need — this service grants ' +
      'either to anybody.',
      { 'WWW-Authenticate': challenges() }, 'access_denied');
  }
  log.debug('Leaving attemptOAuth(). Accepted.');
  return { ok: true, status: 200, scheme: presented.scheme === 'dpop'
    ? 'dpop' : 'bearer',
    principal: String(claims.sub || claims.client_id || ''),
    scopes: scopes, err: '', description: '', headers: {} };
}

// ---------------------------------------------------------------------------
// THE BASIC ATTEMPT.
//
// No password is checked but one, exactly as everywhere else here. It grants
// BOTH scopes and says so: a scheme with no scope in it cannot express the
// difference between reading and writing, and returning a read-only decision
// would be a refusal a client could not act on — there would be nothing it
// could send to get past it.
// ---------------------------------------------------------------------------
function attemptBasic(req) {
  log.debug('Entering attemptBasic().');
  const scheme = authorizationScheme(req);
  if (scheme !== 'basic') {
    log.debug('Leaving attemptBasic(). No Basic credential.');
    return null;
  }
  const header = String((req.headers || {}).authorization || '');
  const encoded = header.slice(header.indexOf(' ') + 1).trim();
  let decoded = '';
  try {
    decoded = Buffer.from(encoded, 'base64').toString('utf8');
  } catch (e) {
    // Not base64. There is nothing to recover — the credential is malformed
    // rather than wrong, and saying which is the useful half.
    decoded = '';
  }
  const cut = decoded.indexOf(':');
  const user = cut < 0 ? decoded : decoded.slice(0, cut);
  const password = cut < 0 ? '' : decoded.slice(cut + 1);
  if (!user) {
    log.debug('Leaving attemptBasic(). No username.');
    return refusal(401,
      'The Basic credential did not decode to "user:password". It is ' +
      'base64 of those two joined by a colon, and this service accepts any ' +
      'username with any password except "' + REFUSED_PASSWORD + '".',
      { 'WWW-Authenticate': challenges() });
  }
  if (password === REFUSED_PASSWORD) {
    log.debug('Leaving attemptBasic(). The reserved password.');
    return refusal(401,
      'The password "' + REFUSED_PASSWORD + '" is reserved and always ' +
      'refused, so that a wrong-credential path exists at all. Every other ' +
      'password for every username is accepted.',
      { 'WWW-Authenticate': challenges() });
  }
  log.debug('Leaving attemptBasic(). Accepted ' + user + '.');
  return { ok: true, status: 200, scheme: 'basic', principal: user,
    scopes: scopeRead() + ' ' + scopeWrite(), err: '', description: '',
    headers: {} };
}

// ---------------------------------------------------------------------------
// THE ONE CALL EVERY PROTECTED ENDPOINT MAKES.
//
//   need   'read', 'write' or 'none'
//
// Returns `{ ok, status, err, description, headers, principal, scheme,
// scopes, anonymous }` and answers nothing itself — the route decides the
// body, because a stream management refusal and a poll refusal are different
// documents.
// ---------------------------------------------------------------------------
function authenticate(req, need) {
  log.debug('Entering authenticate(). need=' + need);
  const wanted = String(need || 'none');
  let decision = attemptOAuth(req, wanted);
  if (!decision) {
    decision = attemptBasic(req);
  }
  if (decision) {
    log.debug('Leaving authenticate(). A credential was presented.');
    return decision;
  }
  if (!authRequired()) {
    log.debug('Leaving authenticate(). Nothing required.');
    return { ok: true, status: 200, scheme: 'anonymous', principal: '',
      scopes: scopeRead() + ' ' + scopeWrite(), anonymous: true, err: '',
      description: '', headers: {},
      note: 'authentication is turned off (ssf.authRequired)' };
  }
  if (wanted === 'none') {
    log.debug('Leaving authenticate(). Open endpoint.');
    return { ok: true, status: 200, scheme: 'anonymous', principal: '',
      scopes: '', anonymous: true, err: '', description: '', headers: {},
      note: 'this endpoint is open — a receiver has to be able to read what ' +
            'the endpoints are before it can authenticate to one' };
  }
  log.debug('Leaving authenticate(). Nothing was presented.');
  return refusal(401,
    'These endpoints decide what this transmitter delivers and to whom, so ' +
    'they require a credential. Either scheme in the WWW-Authenticate ' +
    'headers will do and both are permissive: an access token from this ' +
    'service\'s own token endpoint with the "' + scopeRead() + '" or "' +
    scopeWrite() + '" scope, or any username with any password but "' +
    REFUSED_PASSWORD + '" over Basic. The transmitter configuration at ' +
    '/.well-known/ssf-configuration lists the schemes and is readable ' +
    'without a credential for exactly that reason.',
    { 'WWW-Authenticate': challenges() });
}

// The `authorization_schemes` member of the transmitter metadata. SSF 1.0
// defines only `spec_urn` on each entry, so that is the only member emitted —
// a document carrying this service's own prose would be inviting a receiver
// to depend on a member no specification defines.
function schemesForMetadata() {
  log.debug('Entering schemesForMetadata().');
  const list = SCHEMES.map(function (row) {
    return { spec_urn: row.spec_urn };
  });
  log.debug('Leaving schemesForMetadata(). ' + list.length + '.');
  return list;
}

// What this gate is, as data, for `GET /ssf` and `/admin/ssf`.
function describe() {
  log.debug('Entering describe().');
  const out = {
    required: authRequired(),
    realm: realm(),
    scopes: { read: scopeRead(), write: scopeWrite() },
    refusedPassword: REFUSED_PASSWORD,
    metadataIsOpen: true,
    schemes: SCHEMES.map(function (row) {
      return { id: row.id, name: row.name, spec_urn: row.spec_urn,
        what: row.what };
    }),
    note: 'A turnstile rather than a lock. Anybody can get a token with ' +
          'either scope from this service\'s own token endpoint with any ' +
          'grant, and any username with any password but "' +
          REFUSED_PASSWORD + '" passes Basic. What it buys is that a ' +
          'client\'s 401, 403 and scope-handling paths can be run at all.'
  };
  log.debug('Leaving describe().');
  return out;
}

module.exports = {
  SCHEMES: SCHEMES,
  REFUSED_PASSWORD: REFUSED_PASSWORD,
  authRequired: authRequired,
  scopeRead: scopeRead,
  scopeWrite: scopeWrite,
  realm: realm,
  challenges: challenges,
  authenticate: authenticate,
  schemesForMetadata: schemesForMetadata,
  describe: describe
};
