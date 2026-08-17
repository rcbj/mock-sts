'use strict';
//
// File: admin_stats.js
//
// ---------------------------------------------------------------------------
// What this service has done since it started, and the two things an operator of
// it can change: which tokens are invalid, and what custom claims every new token
// carries.
//
// It is a LIBRARY, not a protocol module — like dpop.js it registers no route, so
// its position in the require order does not matter and it cannot be the reason a
// route is missing. `admin.js` is the console that renders what is in here; this
// file holds the state and none of the HTML, which is the split that lets the
// counters be read by a test over JSON without going near a page.
//
// It requires helpers.js and nothing else in this repository, deliberately: it is
// called from app.js's call log, from helpers.js's signJwt(), from both assertion
// builders, from the KDC and from the credential issuer, which between them are
// most of the service. Anything it required, all of those would then require
// transitively, and the cycles rule 2 of the architecture exists to avoid would be
// one careless import away.
//
// Three things are worth knowing before reading further.
//
// **Everything here is in memory and dies with the process.** That is the same
// choice the signing key makes (regenerated on every start) and for the same
// reason: nothing about a mock is worth persisting, and a statistics file that
// outlived the key that signed the tokens it describes would be actively
// misleading. The console says so on every page rather than leaving a reader to
// wonder why the numbers reset.
//
// **The registries are bounded.** A long-running instance issuing tokens in a loop
// must not become a memory leak, so the token, assertion, ticket and credential
// registries have caps and drop their oldest entries. What was dropped is COUNTED
// and shown on the page: a silent truncation would turn "12 tokens issued" into a
// number that quietly means something else.
//
// **Revocation lives here rather than in oauth2.js, where it was written.** The
// admin console revokes tokens and so does RFC 7009's /oauth2/revoke, and two sets
// of revoked jtis would each look correct alone and never see each other — the same
// failure the single session store exists to prevent. There is one set, and
// introspection, UserInfo, the refresh grant and this console all consult it.
// ---------------------------------------------------------------------------

const { log, setJwtRecorder } = require('./helpers');

// When this process started answering. Everything on the metrics page is "since"
// this instant, and the page prints it, because a rate with no window is a number
// with no meaning.
const STARTED_AT = Date.now();

// ---------------------------------------------------------------------------
// The caps.
//
// Chosen to be far above any interactive or test use of this service and far below
// anything that would trouble a node heap. Each registry counts what it dropped so
// the page can say "5,000 shown, 812 forgotten" instead of implying 5,000 is all
// there ever were.
// ---------------------------------------------------------------------------
const MAX_TOKENS = 5000;
const MAX_ARTIFACTS = 5000;
const MAX_CALL_PATHS = 500;

// ---------------------------------------------------------------------------
// Endpoint call statistics.
//
// Keyed by METHOD and the ROUTE PATTERN Express matched ("/oauth2/register/:client_id"),
// not by the URL that was requested — otherwise every registered client id would
// get a row of its own and the table would be unbounded and unreadable. A request
// that matched no route has no pattern, so its path is used as-is; that IS
// unbounded (anyone can request any path), which is what MAX_CALL_PATHS bounds.
// ---------------------------------------------------------------------------
const calls = new Map();       // "GET /path" -> the row below

let callTotal = 0;

let callPathsDropped = 0;

const UNMATCHED_BUCKET = '(other unmatched paths)';

function callRow(method, path) {
  const key = method + ' ' + path;
  let row = calls.get(key);
  if (row) return row;
  row = { method: method, path: path, count: 0, totalMs: 0, maxMs: 0,
          statuses: {}, lastAt: 0, lastStatus: 0, matched: true };
  calls.set(key, row);
  return row;
}

// Called from app.js's call log, once per answered request. `matched` says whether
// Express found a route: an unmatched path is a 404 and is interesting exactly
// once, which is why it is the one that gets collapsed when the table is full.
function recordCall(call) {
  log.debug("Entering recordCall(). " + call.method + " " + call.path + " -> " + call.status);
  let path = call.path;
  let matched = !!call.matched;
  if (!matched && calls.size >= MAX_CALL_PATHS) {
    // Collapse rather than grow without limit. Counted, and named on the page, so
    // the collapse is visible rather than a table that mysteriously stops growing.
    callPathsDropped++;
    path = UNMATCHED_BUCKET;
  }
  const row = callRow(call.method, path);
  row.matched = row.matched && matched;
  row.count++;
  row.totalMs += call.durationMs || 0;
  if ((call.durationMs || 0) > row.maxMs) row.maxMs = call.durationMs || 0;
  const bucket = String(Math.floor((call.status || 0) / 100)) + 'xx';
  row.statuses[bucket] = (row.statuses[bucket] || 0) + 1;
  row.lastAt = Date.now();
  row.lastStatus = call.status || 0;
  callTotal++;
  log.debug("Leaving recordCall(). " + callTotal + " call(s) recorded in total.");
}

// ---------------------------------------------------------------------------
// The tokens.
//
// Every JWT this service signs through helpers.signJwt() lands here — access
// tokens, id_tokens, refresh tokens, the signed UserInfo response and the OID4VP
// Request Object — because that function is the single place they are minted.
// The credential formats sign directly with jsonwebtoken and are recorded
// separately (recordCredential below); WS-Trust's JWT does the same.
//
// The record deliberately keeps the CLAIMS and not the token: the console lists
// what was issued to whom and until when, and a page holding thousands of signed
// bearer credentials in a form a browser will render is a page that leaks them.
// The jti is what the console acts on, and the jti is enough.
// ---------------------------------------------------------------------------
const tokens = new Map();      // jti (or a synthetic key) -> the record below

let tokensForgotten = 0;

let tokensWithoutJti = 0;

// What `typ` means, in the vocabulary the console and RFC 7009 use. Every token
// this server issues is an RS256 JWT signed with the same key, so `typ` is the only
// thing that tells them apart — the same fact UserInfo relies on.
const KIND_BY_TYP = {
  'Bearer': 'access_token',
  'ID': 'id_token',
  'Refresh': 'refresh_token',
  'UserInfo': 'userinfo_response',
  'oauth-authz-req+jwt': 'request_object'
};

// The three the console offers to invalidate, which are the three the user of this
// service can actually present again. A signed UserInfo response is a reply, not a
// credential, and revoking one would mean nothing.
const REVOCABLE_KINDS = ['access_token', 'id_token', 'refresh_token'];

function kindOfTyp(typ) {
  return KIND_BY_TYP[String(typ || '')] || ('other (typ=' + (typ || 'none') + ')');
}

// Installed into helpers.js at require time — see the comment on setJwtRecorder
// there for why the direction is inverted. The signed token is passed in and
// deliberately not kept.
function recordJwt(payload, signed) {
  log.debug("Entering recordJwt(). typ=" + (payload.typ || '(none)'));
  const kind = kindOfTyp(payload.typ);
  // A token with no jti cannot be revoked and cannot be looked up, so it gets a
  // synthetic key that sorts with the others and is marked unrevocable on the page.
  // The signed UserInfo response is the one that arrives this way.
  let key = payload.jti;
  if (!key) {
    tokensWithoutJti++;
    key = 'no-jti-' + tokensWithoutJti;
  }
  const record = {
    key: key,
    jti: payload.jti || '',
    kind: kind,
    typ: payload.typ || '',
    revocable: !!payload.jti && REVOCABLE_KINDS.indexOf(kind) >= 0,
    sub: payload.sub || '',
    // `username` on an access or refresh token, `preferred_username` on an ID
    // Token: the two carry the same person under different names because that is
    // what their respective specifications call the claim, and a console column
    // that read only one of them would show a dash for every ID Token.
    username: payload.username || payload.preferred_username || '',
    client_id: payload.client_id || payload.azp || payload.aud || '',
    scope: payload.scope || '',
    // jkt rather than the whole cnf: the thumbprint is the binding, and it is what
    // makes a row on the page say "DPoP" honestly rather than by guessing.
    jkt: (payload.cnf && payload.cnf.jkt) || '',
    iat: payload.iat || 0,
    nbf: payload.nbf || 0,
    exp: payload.exp || 0,
    issuedAt: Date.now(),
    revoked: false,
    revokedAt: 0,
    revokedVia: '',
    // Recorded because it decides what the "sessions" figure means; see
    // sessionsFromArtifacts().
    length: String(signed || '').length
  };
  if (tokens.size >= MAX_TOKENS) {
    // Map iterates in insertion order, so the first key is the oldest.
    const oldest = tokens.keys().next().value;
    tokens.delete(oldest);
    tokensForgotten++;
  }
  tokens.set(key, record);
  log.debug("Leaving recordJwt(). " + tokens.size + " token(s) held, " + tokensForgotten + " forgotten.");
}

setJwtRecorder(recordJwt);

// ---------------------------------------------------------------------------
// Revocation, for the whole service.
//
// The set holds jtis rather than token records because a jti can be revoked whose
// record has already been forgotten to the cap, and because RFC 7009 lets a caller
// revoke a token this registry never saw (one issued before a restart, say). It is
// the set that is authoritative; the record's `revoked` flag is a convenience for
// the page and is kept in step here.
// ---------------------------------------------------------------------------
const revokedJtis = new Set();

function revoke(jti, via) {
  log.debug("Entering revoke(). jti=" + jti);
  if (!jti) {
    log.debug("Leaving revoke(). There was no jti to revoke.");
    return false;
  }
  const first = !revokedJtis.has(jti);
  revokedJtis.add(jti);
  const record = tokens.get(jti);
  if (record) {
    record.revoked = true;
    record.revokedAt = record.revokedAt || Date.now();
    record.revokedVia = record.revokedVia || (via || 'unstated');
  }
  log.info('admin: the token with jti ' + jti + ' is revoked (' + (via || 'unstated') + '). ' +
           revokedJtis.size + ' revoked in total.');
  log.debug("Leaving revoke(). " + (first ? "It is newly revoked." : "It was already revoked."));
  return first;
}

// Un-revoking is NOT something an authorization server can do — RFC 7009 has no
// such operation and a real deployment could not offer one, because a resource
// server may already have cached the refusal. It is here because this service
// exists to be experimented with, and having to restart it to get back to a
// working token turns a two-second test into a two-minute one. The console labels
// it NON-SPEC for exactly that reason.
function restore(jti) {
  log.debug("Entering restore(). jti=" + jti);
  const was = revokedJtis.delete(jti);
  const record = tokens.get(jti);
  if (record) {
    record.revoked = false;
    record.revokedAt = 0;
    record.revokedVia = '';
  }
  log.info('admin: the token with jti ' + jti + ' is no longer revoked (NON-SPEC).');
  log.debug("Leaving restore(). " + (was ? "It had been revoked." : "It had not been revoked."));
  return was;
}

function isRevoked(jti) {
  return !!jti && revokedJtis.has(jti);
}

function revokedCount() {
  return revokedJtis.size;
}

// ---------------------------------------------------------------------------
// The artifacts that are not JWTs: assertions, tickets and credentials.
//
// One shape for all three, because the metrics page asks the same three questions
// of each — how many, how many still valid, and whose. `expiresAt` is a
// millisecond epoch or 0 for "no expiry was stated", which is the honest answer
// for a couple of them rather than pretending to an expiry of now.
// ---------------------------------------------------------------------------
const artifacts = [];

let artifactsForgotten = 0;

function recordArtifact(kind, detail) {
  const record = Object.assign({ kind: kind, issuedAt: Date.now(), expiresAt: 0, subject: '' }, detail);
  artifacts.push(record);
  if (artifacts.length > MAX_ARTIFACTS) {
    artifacts.shift();
    artifactsForgotten++;
  }
  return record;
}

// A SAML assertion, 2.0 or 1.1. Called from the two builders rather than from
// their callers: WS-Trust, WS-Federation and anything added later all go through
// them, so this counts every assertion instead of every assertion somebody
// remembered to count.
function recordAssertion(version, detail) {
  log.debug("Entering recordAssertion(). version=" + version + ", subject=" + (detail.subject || '?'));
  const record = recordArtifact('SAML ' + version, {
    id: detail.id || '',
    subject: detail.subject || '',
    audience: detail.audience || '',
    expiresAt: detail.expiresAt || 0,
    signed: detail.signed !== false
  });
  log.debug("Leaving recordAssertion(). " + artifacts.length + " artifact(s) held.");
  return record;
}

// A Kerberos ticket. `kind` is 'TGT' or 'service ticket' — the distinction the
// metrics page makes, because a TGT IS the Kerberos session and a service ticket
// is one use of it, so counting them together would report the wrong thing twice.
function recordTicket(kind, detail) {
  log.debug("Entering recordTicket(). kind=" + kind + ", client=" + (detail.client || '?'));
  const record = recordArtifact('Kerberos ' + kind, {
    subject: detail.client || '',
    realm: detail.realm || '',
    service: detail.service || '',
    etype: detail.etype || '',
    expiresAt: detail.expiresAt || 0
  });
  log.debug("Leaving recordTicket(). " + artifacts.length + " artifact(s) held.");
  return record;
}

// A verifiable credential, in whichever of the three formats was asked for.
function recordCredential(format, detail) {
  log.debug("Entering recordCredential(). format=" + format);
  const record = recordArtifact('Credential (' + format + ')', {
    subject: detail.subject || '',
    configId: detail.configId || '',
    expiresAt: detail.expiresAt || 0
  });
  log.debug("Leaving recordCredential(). " + artifacts.length + " artifact(s) held.");
  return record;
}

// ---------------------------------------------------------------------------
// Custom claims.
//
// Four sets, one per place a claim can be put, because the four are genuinely
// different vocabularies and a single list would have to guess:
//
//   access_token   members of the OAuth 2.0 access token's claim set
//   id_token       members of the OIDC ID Token's claim set
//   saml2          <saml:Attribute Name="..." NameFormat="...">
//   saml11         <saml:Attribute AttributeName="..." AttributeNamespace="...">
//
// They are ADDITIVE. A configured claim is added to what the protocol already
// puts in the token; it never replaces one, and the reserved list below is what
// enforces that. The reason is that every reserved name is load-bearing somewhere
// in this service — an `exp` a person could set from a web form would produce
// tokens that fail to verify with no error message pointing back here, and a
// settable `scope` would silently change what UserInfo answers.
// ---------------------------------------------------------------------------
const RESERVED_JWT_CLAIMS = [
  'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti', 'typ', 'cnf',
  'scope', 'client_id', 'azp', 'nonce', 'at_hash', 'c_hash', 'auth_time',
  'amr', 'acr', 'username', 'authorization_details', 'act'
];

const CLAIM_SETS = {
  access_token: { label: 'OAuth 2.0 access token', kind: 'jwt', claims: [] },
  id_token: { label: 'OIDC ID Token', kind: 'jwt', claims: [] },
  saml2: { label: 'SAML 2.0 Attribute', kind: 'saml2', claims: [] },
  saml11: { label: 'SAML 1.1 Attribute (WS-Federation)', kind: 'saml11', claims: [] }
};

const CLAIM_SET_IDS = Object.keys(CLAIM_SETS);

// The default namespace a SAML 1.1 attribute gets when the admin does not name
// one. It is the claim namespace every WS-Federation relying party already reads,
// which makes an attribute configured with just a name arrive somewhere useful
// instead of in a namespace nothing looks in.
const DEFAULT_SAML11_NAMESPACE = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims';

// ---------------------------------------------------------------------------
// The placeholders a value may contain.
//
// Without them every configured claim would be a constant, and a constant claim
// cannot exercise the thing people actually want to test: that a claim carrying
// the signed-in user's identity reaches the relying party. The syntax is ${name}
// and an unknown name is left ALONE rather than replaced with the empty string —
// a claim that was meant to say "${dept}" and silently became "" is a bug that
// looks like a configuration mistake, and one that still says "${dept}" names
// itself.
// ---------------------------------------------------------------------------
const PLACEHOLDERS = ['username', 'sub', 'email', 'name', 'given_name', 'family_name',
                      'client_id', 'audience', 'now', 'iso'];

// Without entering/leaving logs, like b64u() in helpers.js: this runs once per
// custom claim per token and would drown the log it is supposed to be readable in.
function expandValue(value, context) {
  const ctx = context || {};
  return String(value == null ? '' : value).replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, function (whole, name) {
    if (Object.prototype.hasOwnProperty.call(ctx, name) && ctx[name] != null) return String(ctx[name]);
    if (name === 'now') return String(Math.floor(Date.now() / 1000));
    if (name === 'iso') return new Date().toISOString();
    // Deliberately unchanged: see the comment above.
    return whole;
  });
}

// ---------------------------------------------------------------------------
// A JWT claim value is not always a string, and a web form only produces strings.
//
// So a value is read as JSON when it unambiguously looks like JSON — an object, an
// array, a bare true/false/null, or a number — and as a string otherwise. That
// rule has one consequence worth stating rather than discovering: a claim whose
// value is genuinely the four characters `true` cannot be configured, because
// there is no way to tell the two apart from a text field. Wrapping it in quotes
// (`"true"`) is the escape, since that parses as the JSON string.
//
// SAML attribute values are never typed: the XML content model is text.
// ---------------------------------------------------------------------------
function typedValue(text) {
  const trimmed = String(text == null ? '' : text).trim();
  if (!/^[{\[]|^(true|false|null)$|^-?\d+(\.\d+)?([eE][-+]?\d+)?$/.test(trimmed)) return text;
  try {
    return JSON.parse(trimmed);
  } catch (e) {
    // It looked like JSON and is not — a half-typed array, most likely. The raw
    // text is what the admin typed and is what the claim gets, rather than an
    // error at issuance time in a place nobody is watching.
    log.debug("A claim value looked like JSON and did not parse; it is used as text: " + trimmed);
    return text;
  }
}

// Validate and install a whole set at once. Returns the errors rather than
// throwing, because the caller is a form handler that has to redisplay them.
function setClaimSet(id, entries) {
  log.debug("Entering setClaimSet(). id=" + id + ", " + (entries || []).length + " entry/entries.");
  const set = CLAIM_SETS[id];
  if (!set) {
    log.debug("Leaving setClaimSet(). No such claim set.");
    return { ok: false, errors: ['There is no claim set called "' + id + '". The four are: ' +
                                 CLAIM_SET_IDS.join(', ') + '.'] };
  }
  const errors = [];
  const cleaned = [];
  const seen = new Set();
  (entries || []).forEach(function (entry, index) {
    const name = String((entry && entry.name) || '').trim();
    if (!name) {
      errors.push('Entry ' + (index + 1) + ' has no name.');
      return;
    }
    if (set.kind === 'jwt' && RESERVED_JWT_CLAIMS.indexOf(name) >= 0) {
      errors.push('"' + name + '" is a claim this service sets itself and cannot be overridden. ' +
                  'Custom claims are added to a token, never substituted into it.');
      return;
    }
    if (seen.has(name)) {
      errors.push('"' + name + '" is configured twice; the later one would win silently, so both ' +
                  'are refused.');
      return;
    }
    seen.add(name);
    const claim = { name: name, value: String((entry && entry.value) != null ? entry.value : '') };
    if (set.kind === 'saml2' && entry.nameFormat) claim.nameFormat = String(entry.nameFormat);
    if (set.kind === 'saml11') claim.namespace = String(entry.namespace || DEFAULT_SAML11_NAMESPACE);
    cleaned.push(claim);
  });
  if (errors.length) {
    log.debug("Leaving setClaimSet(). Refused with " + errors.length + " error(s); nothing changed.");
    return { ok: false, errors: errors };
  }
  set.claims = cleaned;
  log.info('admin: the ' + set.label + ' claim set now has ' + cleaned.length + ' custom claim(s): ' +
           (cleaned.map(function (c) { return c.name; }).join(', ') || '(none)'));
  log.debug("Leaving setClaimSet(). Installed " + cleaned.length + " claim(s).");
  return { ok: true, errors: [], claims: cleaned };
}

function claimSet(id) {
  const set = CLAIM_SETS[id];
  return set ? set.claims.slice() : [];
}

// The custom claims for a JWT, expanded against this token's context and typed.
// Returns a plain object ready to be merged into a payload — and the merge at the
// call site is written so the protocol's own claims win, which is belt as well as
// the braces of the reserved list.
function jwtClaims(id, context) {
  log.debug("Entering jwtClaims(). id=" + id);
  const out = {};
  claimSet(id).forEach(function (claim) {
    out[claim.name] = typedValue(expandValue(claim.value, context));
  });
  const names = Object.keys(out);
  if (names.length) {
    log.debug("jwtClaims(): adding " + names.length + " custom claim(s) to a " + id + ": " + names.join(', '));
  }
  log.debug("Leaving jwtClaims(). " + names.length + " claim(s).");
  return out;
}

// The custom attributes for a SAML assertion, in the shape each builder wants:
// saml2.js takes { name, nameFormat, value } and saml11.js takes
// { name, namespace, value }. Two shapes because the two specifications genuinely
// differ — SAML 1.1 splits the claim URI into a namespace and a name — and a
// single shape here would only push that difference into both builders.
function samlAttributes(id, context) {
  log.debug("Entering samlAttributes(). id=" + id);
  const out = claimSet(id).map(function (claim) {
    const attribute = { name: claim.name, value: expandValue(claim.value, context) };
    if (id === 'saml2' && claim.nameFormat) attribute.nameFormat = claim.nameFormat;
    if (id === 'saml11') attribute.namespace = claim.namespace || DEFAULT_SAML11_NAMESPACE;
    return attribute;
  });
  log.debug("Leaving samlAttributes(). " + out.length + " attribute(s).");
  return out;
}

// ---------------------------------------------------------------------------
// Reading the state back.
// ---------------------------------------------------------------------------
function tokenStateOf(record, nowMs) {
  if (record.revoked || (record.jti && revokedJtis.has(record.jti))) return 'revoked';
  if (record.exp && record.exp * 1000 <= nowMs) return 'expired';
  if (record.nbf && record.nbf * 1000 > nowMs) return 'not yet valid';
  if (!record.exp) return 'no expiry stated';
  return 'valid';
}

function tokenList() {
  log.debug("Entering tokenList().");
  const nowMs = Date.now();
  const out = [];
  tokens.forEach(function (record) {
    out.push(Object.assign({ state: tokenStateOf(record, nowMs) }, record));
  });
  // Newest first: the token somebody is debugging is the one they just got.
  out.sort(function (a, b) { return b.issuedAt - a.issuedAt; });
  log.debug("Leaving tokenList(). " + out.length + " token(s).");
  return out;
}

function artifactList() {
  log.debug("Entering artifactList().");
  const nowMs = Date.now();
  const out = artifacts.map(function (record) {
    return Object.assign({
      state: (record.expiresAt && record.expiresAt <= nowMs) ? 'expired'
           : (record.expiresAt ? 'valid' : 'no expiry stated')
    }, record);
  }).sort(function (a, b) { return b.issuedAt - a.issuedAt; });
  log.debug("Leaving artifactList(). " + out.length + " artifact(s).");
  return out;
}

// Revoke every token matching a predicate, and say how many. Used by the console's
// "revoke every access token" and "revoke everything for this subject" buttons,
// which exist because revoking one jti at a time is not how anybody tests a
// resource server's behaviour when its tokens go bad.
function revokeWhere(predicate, via) {
  log.debug("Entering revokeWhere().");
  let count = 0;
  tokens.forEach(function (record) {
    if (!record.revocable || record.revoked) return;
    if (!predicate(record)) return;
    if (revoke(record.jti, via)) count++;
  });
  log.debug("Leaving revokeWhere(). Revoked " + count + " token(s).");
  return count;
}

// ---------------------------------------------------------------------------
// Sessions derived from what was issued.
//
// This is a DEFINITION, not a measurement, so it is written down: a subject has an
// artifact-derived session in a protocol family when that family has issued it at
// least one artifact that is still valid — unexpired, and unrevoked where
// revocation exists. It is not the same thing as the browser sign-on session the
// console reports beside it, and the two disagree in both directions on purpose:
//
//   * a client_credentials access token has no human and no browser behind it, so
//     it is a session here and nothing at all there;
//   * a signed-in browser that has been issued nothing yet is a session there and
//     nothing here;
//   * a Kerberos client never touches the browser session at all.
//
// A TGT is counted as the Kerberos session and a service ticket is not, because
// that is what they are: the TGT is the credential the session consists of.
// ---------------------------------------------------------------------------
const OAUTH_SESSION_KINDS = ['access_token', 'id_token', 'refresh_token'];

function sessionsFromArtifacts() {
  log.debug("Entering sessionsFromArtifacts().");
  const nowMs = Date.now();
  const families = new Map();
  const add = function (family, subject) {
    if (!subject) return;
    if (!families.has(family)) families.set(family, new Set());
    families.get(family).add(subject);
  };
  tokens.forEach(function (record) {
    if (OAUTH_SESSION_KINDS.indexOf(record.kind) < 0) return;
    if (tokenStateOf(record, nowMs) !== 'valid') return;
    add('OAuth 2.0 / OIDC', record.sub || record.username);
  });
  artifacts.forEach(function (record) {
    if (record.expiresAt && record.expiresAt <= nowMs) return;
    if (record.kind === 'SAML 2.0') add('SAML 2.0 (WS-Trust, WS-Federation)', record.subject);
    else if (record.kind === 'SAML 1.1') add('SAML 1.1 (WS-Federation)', record.subject);
    else if (record.kind === 'Kerberos TGT') add('Kerberos (a TGT is the session)', record.subject);
    else if (record.kind.indexOf('Credential (') === 0) add('OID4VCI credentials', record.subject);
  });
  const everyone = new Set();
  const rows = [];
  families.forEach(function (subjects, family) {
    subjects.forEach(function (s) { everyone.add(s); });
    rows.push({ family: family, subjects: subjects.size, who: Array.from(subjects).sort() });
  });
  rows.sort(function (a, b) { return b.subjects - a.subjects; });
  log.debug("Leaving sessionsFromArtifacts(). " + rows.length + " family/families, " +
            everyone.size + " distinct subject(s).");
  return { families: rows, distinctSubjects: everyone.size };
}

// ---------------------------------------------------------------------------
// The whole picture, computed on demand.
//
// On demand rather than kept up to date incrementally, and that is the important
// choice: "valid" and "expired" are functions of the clock, so a counter
// incremented at issuance would be wrong a second later and would need a sweeper
// to stay right. Counting 5,000 records per page view costs nothing.
// ---------------------------------------------------------------------------
function snapshot() {
  log.debug("Entering snapshot().");
  const nowMs = Date.now();

  const byKind = new Map();
  tokens.forEach(function (record) {
    if (!byKind.has(record.kind)) {
      byKind.set(record.kind, { kind: record.kind, issued: 0, valid: 0, expired: 0,
                                revoked: 0, notYetValid: 0, noExpiry: 0, bound: 0 });
    }
    const row = byKind.get(record.kind);
    row.issued++;
    if (record.jkt) row.bound++;
    const state = tokenStateOf(record, nowMs);
    if (state === 'valid') row.valid++;
    else if (state === 'expired') row.expired++;
    else if (state === 'revoked') row.revoked++;
    else if (state === 'not yet valid') row.notYetValid++;
    else row.noExpiry++;
  });

  const artifactKinds = new Map();
  artifacts.forEach(function (record) {
    if (!artifactKinds.has(record.kind)) {
      artifactKinds.set(record.kind, { kind: record.kind, issued: 0, valid: 0, expired: 0, noExpiry: 0 });
    }
    const row = artifactKinds.get(record.kind);
    row.issued++;
    if (!record.expiresAt) row.noExpiry++;
    else if (record.expiresAt > nowMs) row.valid++;
    else row.expired++;
  });

  const callRows = Array.from(calls.values()).sort(function (a, b) { return b.count - a.count; });
  const statusTotals = {};
  callRows.forEach(function (row) {
    Object.keys(row.statuses).forEach(function (bucket) {
      statusTotals[bucket] = (statusTotals[bucket] || 0) + row.statuses[bucket];
    });
  });

  const result = {
    startedAt: STARTED_AT,
    uptimeMs: nowMs - STARTED_AT,
    now: nowMs,
    calls: { total: callTotal, paths: callRows.length, byStatusClass: statusTotals,
             pathsCollapsed: callPathsDropped, rows: callRows },
    tokens: { held: tokens.size, forgotten: tokensForgotten, cap: MAX_TOKENS,
              revoked: revokedJtis.size, byKind: Array.from(byKind.values()) },
    artifacts: { held: artifacts.length, forgotten: artifactsForgotten, cap: MAX_ARTIFACTS,
                 byKind: Array.from(artifactKinds.values()) },
    sessions: sessionsFromArtifacts(),
    claims: CLAIM_SET_IDS.map(function (id) {
      return { id: id, label: CLAIM_SETS[id].label, count: CLAIM_SETS[id].claims.length,
               claims: CLAIM_SETS[id].claims.slice() };
    })
  };
  log.debug("Leaving snapshot(). " + result.calls.total + " call(s), " + result.tokens.held +
            " token(s), " + result.artifacts.held + " artifact(s).");
  return result;
}

module.exports = {
  STARTED_AT: STARTED_AT,
  MAX_TOKENS: MAX_TOKENS,
  MAX_ARTIFACTS: MAX_ARTIFACTS,
  CLAIM_SET_IDS: CLAIM_SET_IDS,
  CLAIM_SETS: CLAIM_SETS,
  RESERVED_JWT_CLAIMS: RESERVED_JWT_CLAIMS,
  PLACEHOLDERS: PLACEHOLDERS,
  DEFAULT_SAML11_NAMESPACE: DEFAULT_SAML11_NAMESPACE,
  REVOCABLE_KINDS: REVOCABLE_KINDS,
  recordCall: recordCall,
  recordAssertion: recordAssertion,
  recordTicket: recordTicket,
  recordCredential: recordCredential,
  revoke: revoke,
  restore: restore,
  revokeWhere: revokeWhere,
  isRevoked: isRevoked,
  revokedCount: revokedCount,
  claimSet: claimSet,
  setClaimSet: setClaimSet,
  jwtClaims: jwtClaims,
  samlAttributes: samlAttributes,
  expandValue: expandValue,
  tokenList: tokenList,
  artifactList: artifactList,
  snapshot: snapshot
};
