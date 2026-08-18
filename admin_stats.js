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

const { log, setJwtRecorder, userFor } = require('./helpers');

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
const MAX_USERS = 2000;

// How many authentication events one user keeps. The users page shows a person's
// history and a person signing in repeatedly is the normal case here — a test loop
// can sign the same name in a thousand times — so the events are capped per user
// rather than in total, and what was dropped is counted on the record so the page
// can say "the most recent 50 of 1,204" instead of implying there were 50.
const MAX_EVENTS_PER_USER = 50;

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

// Every kind a JWT can be recorded under, read off the table above rather than
// written out again — the tokens page's filter offers exactly these, and a filter
// listing a kind that can no longer be issued (or missing one that can) is a filter
// that quietly returns nothing.
const TOKEN_KINDS = Object.keys(KIND_BY_TYP).map(function (typ) { return KIND_BY_TYP[typ]; });

function kindOfTyp(typ) {
  return KIND_BY_TYP[String(typ || '')] || ('other (typ=' + (typ || 'none') + ')');
}

// Installed into helpers.js at require time — see the comment on setJwtRecorder
// there for why the direction is inverted. The signed token is passed in and
// deliberately not kept.
//
// `context` is the third parameter signJwt() offers and is what ties a token to the
// browser session it was issued under. It cannot be read off the payload, and that
// is the whole reason it exists: no token this service issues carries a session
// identifier — OIDC's `sid` claim is for front-channel logout and inventing one here
// would change what every client receives to make a console page easier to write. So
// the issuer states it out of band instead. A caller that says nothing (the
// credential issuer, WS-Trust's JWT) leaves both fields empty, which the users page
// reports as "not through a browser session" rather than as unknown.
function recordJwt(payload, signed, context) {
  log.debug("Entering recordJwt(). typ=" + (payload.typ || '(none)'));
  const issuedUnder = context || {};
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
    // The browser sign-on session this token was issued under, and the grant that
    // issued it. Empty for everything that had no session behind it — the two
    // direct grants, the pre-authorized code, a token exchange — which is a fact
    // about the token rather than a gap in the recording.
    sessionId: issuedUnder.sessionId || '',
    grant: issuedUnder.grant || '',
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
// The people this service has authenticated.
//
// Every userid presented to it as part of a correct protocol interaction lands here:
// the name typed at either sign-in screen, the one on a password grant, the subject
// of a UsernameToken, the client principal in a Kerberos AS-REQ or an accepted
// AP-REQ, and the subject of an exchanged token. "Correct" is doing work in that
// sentence — a request that was refused records nothing, so this registry is a list
// of identities that got somewhere rather than of names that were tried. The one
// deliberate inclusion that is not a person is `client_credentials`, which is
// recorded and flagged as a CLIENT: it produces tokens with a subject and no human,
// and leaving it out would make the users page disagree with the tokens page.
//
// **Identity is keyed on the LOCAL NAME, and that is a decision with a visible
// consequence.** The same person reaches this service under four spellings —
// `alice` at the login screen, `urn:sts-mock:user:alice` as the `sub` of every token,
// `alice` as a SAML subject, `alice@STS.MOCK` as a Kerberos principal — and a page
// showing four rows for one name would be a worse answer than one row, since the
// whole premise of this mock is that the name you type is who you are in every
// protocol at once. So the prefix and the realm are stripped for the key and KEPT on
// the record, and every form seen is listed on the page. What that costs: two
// genuinely different people called `alice` in two Kerberos realms are one row here.
// The realms column is what makes that visible rather than silent, and no such
// collapse happens across case — `Alice` and `alice` stay two, because nothing in
// this service treats them as one.
//
// Kept in memory and dropped with the process, like everything else here.
// ---------------------------------------------------------------------------

// The prefix helpers.userFor() puts in front of a subject, derived rather than
// written down again: a change to that function must not leave this file stripping a
// prefix nothing produces any more, which would silently split every user into two
// rows (one seen through a token, one through a sign-in).
const SUBJECT_PREFIX = (function () {
  const probe = 'probe';
  const sample = userFor(probe).sub;
  return sample.slice(0, sample.length - probe.length);
})();

const users = new Map();       // local name -> the record below

let usersForgotten = 0;

// Does this identity begin `<attributetype>=`? That is the one shape identityOf()
// below must not split at an '@'. Deliberately strict — a type is a letter
// followed by letters, digits and hyphens, which is what RFC 4512 allows — so that
// it cannot match a name somebody typed at a sign-in screen.
const DN_SHAPED = /^[A-Za-z][A-Za-z0-9-]*=/;

// A presented identity, split into the part that identifies a person here and the
// parts that merely say where it was presented. Without entering/leaving logs: it is
// called for every token and artifact on every users page view, so a pair of lines
// here would be most of the log.
function identityOf(value) {
  const text = String(value == null ? '' : value).trim();
  if (!text) return { key: '', name: '', realm: '', form: '' };
  let rest = text;
  let realm = '';
  if (rest.indexOf(SUBJECT_PREFIX) === 0) rest = rest.slice(SUBJECT_PREFIX.length);
  // A Kerberos principal. The LAST '@' splits it, because a principal name may
  // itself contain one (a UPN-shaped account name is ordinary in a Windows realm)
  // and the realm never does.
  //
  // This applies to every identity and not only to Kerberos ones, which has one
  // consequence to know about rather than discover: a person who types an e-mail
  // address at the login screen is filed under the part before the '@', with the
  // domain shown in the Realms column. On this service that is usually what was
  // meant — the same person's Kerberos principal would land in the same row — and
  // where it is not, the column says which domains have been folded together.
  //
  // A DN is the exception, and it has to be: an X.509 subject or an LDAP bind DN
  // routinely carries `emailAddress=alice@example.com`, where the '@' is inside an
  // attribute VALUE and the text after it is a mail domain rather than a realm.
  // Splitting there produced a key ending `...,emailAddress=alice` — a DN that
  // names nothing, and one the directory would then build an entry from. So a
  // value that begins with an attribute type and an '=' is taken whole. Nothing
  // else here can look like that: a username, a `urn:` subject and a mail address
  // all fail the test, and a Kerberos principal cannot contain '=' before its
  // first character run ends.
  const at = DN_SHAPED.test(rest) ? -1 : rest.lastIndexOf('@');
  if (at > 0) {
    realm = rest.slice(at + 1);
    rest = rest.slice(0, at);
  }
  return { key: rest, name: rest, realm: realm, form: text };
}

// Just the key, for the many places that only need to ask "is this the same person".
function identityKeyOf(value) {
  return identityOf(value).key;
}

// ---------------------------------------------------------------------------
// The one hook ldap_server.js needs, and the reason it is a hook rather than a
// require.
//
// The embedded LDAP directory grows an entry for every person who authenticates
// to this service, through any of the twelve protocol families —
// recordAuthentication() below is the single funnel all of them already go
// through at the moment the credential is ACCEPTED, so one observer here is one
// place and not twelve.
//
// But ldap_server.js requires THIS file (it needs identityOf's normalisation, so
// that `alice`, `urn:sts-mock:user:alice` and `alice@REALM` seed one entry and
// not three), so this file cannot require it back: a cycle in node hands back a
// half-initialised module whose exports are undefined, and the symptom arrives
// later as something that is not a function. So the direction is inverted, the
// same way helpers.js's setJwtRecorder is — this file offers a slot, and
// ldap_server.js installs itself in it at ITS require time.
//
// The observer is called for its side effect only and its return value is
// ignored: a directory must never be able to stop an authentication being
// recorded, still less to fail the authentication itself.
// ---------------------------------------------------------------------------
let userObserver = null;

function setUserObserver(fn) {
  userObserver = fn;
  log.debug("A user observer was installed; every identity that authenticates " +
            "will now be offered to it.");
}

function userRecord(identity) {
  let record = users.get(identity.key);
  if (record) return record;
  if (users.size >= MAX_USERS) {
    // Map iterates in insertion order, so the first key is the least recently
    // FIRST SEEN — not the least recently active. Chosen because it needs no sweep
    // and because a registry of 2,000 distinct usernames on a mock is already a
    // load generator rather than a person, and the page says how many went.
    const oldest = users.keys().next().value;
    users.delete(oldest);
    usersForgotten++;
  }
  record = {
    key: identity.key, name: identity.name,
    forms: {}, realms: {}, protocols: {},
    events: [], eventsForgotten: 0,
    authentications: 0, firstAt: 0, lastAt: 0,
    // Set by the one call site that knows it is not a person; see the note above.
    isClient: false
  };
  users.set(identity.key, record);
  return record;
}

// One successful authentication. `detail` says what happened in the vocabulary the
// page prints:
//
//   presented   the identity exactly as it arrived (the key is derived from it)
//   protocol    the family, which is what the page groups by
//   method      how, within that family — "the sign-in screen (password + a
//               security key)", "AS-REQ with PA-ENC-TIMESTAMP", "UsernameToken"
//   sessionId   the browser sign-on session this created or ran on, when there is
//               one. It is what lets the drill-down put tokens under a session.
//   amr/acr, client_id, note, isClient — all optional, all shown where present.
//
// It returns the record so a caller can log what it now knows, and it NEVER throws
// on a missing field: a statistics call that could fail an authentication would be
// the tail wagging the dog, the same rule signJwt()'s recorder follows.
function recordAuthentication(detail) {
  const info = detail || {};
  log.debug("Entering recordAuthentication(). protocol=" + (info.protocol || '?') +
            ", presented=" + (info.presented || '?'));
  const identity = identityOf(info.presented);
  if (!identity.key) {
    log.debug("Leaving recordAuthentication(). There was no identity to record.");
    return null;
  }
  const now = Date.now();
  const record = userRecord(identity);
  record.forms[identity.form] = (record.forms[identity.form] || 0) + 1;
  if (identity.realm) record.realms[identity.realm] = (record.realms[identity.realm] || 0) + 1;
  if (info.isClient) record.isClient = true;
  const protocol = String(info.protocol || 'unstated');
  if (!record.protocols[protocol]) {
    record.protocols[protocol] = { protocol: protocol, count: 0, methods: {}, firstAt: now, lastAt: 0 };
  }
  const family = record.protocols[protocol];
  const method = String(info.method || 'unstated');
  family.count++;
  family.methods[method] = (family.methods[method] || 0) + 1;
  family.lastAt = now;
  record.authentications++;
  record.firstAt = record.firstAt || now;
  record.lastAt = now;
  record.events.push({
    at: now, protocol: protocol, method: method, presented: identity.form,
    realm: identity.realm || '', sub: info.sub || '', client_id: info.client_id || '',
    amr: (info.amr || []).join(', '), acr: info.acr || '',
    sessionId: info.sessionId || '', note: info.note || ''
  });
  if (record.events.length > MAX_EVENTS_PER_USER) {
    record.events.shift();
    record.eventsForgotten++;
  }
  log.info('admin: ' + identity.key + ' authenticated through ' + protocol + ' (' + method +
           '). ' + record.authentications + ' time(s) so far; ' + users.size + ' user(s) known.');
  // The embedded LDAP directory, if it is loaded. Wrapped for the same reason the
  // JWT recorder is: a throw out here would fail the request that was accepting a
  // credential, which is the tail wagging the dog. It is given the NORMALISED
  // identity rather than `presented`, so that the three spellings of one person
  // seed one entry.
  if (userObserver) {
    try {
      userObserver({
        key: identity.key, name: identity.name, realm: identity.realm,
        presented: identity.form, protocol: protocol, method: method,
        isClient: record.isClient, sub: info.sub || '',
        // Passed through untouched, and only the TLS listeners set it: a client
        // certificate's identity IS a DN, so the entry the directory seeds for it
        // is not `uid=<name>` and the facts that go in it — issuer, serial,
        // validity — are on the certificate rather than in anything this file
        // holds. It rides on the observer rather than on a second hook because
        // this is already the funnel, and a second call at the TLS listener would
        // be a second thing to keep right. Nothing here reads it.
        certificate: info.certificate || null
      });
    } catch (e) {
      log.error('the user observer threw and was ignored; the authentication ' +
                'itself is unaffected: ' + e.message);
    }
  }
  log.debug("Leaving recordAuthentication(). " + users.size + " user(s) known.");
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

// The same three answers for an artifact, and there are only three: nothing that is
// not a JWT can be revoked here, so 'revoked' is not among them. Written as a
// function beside tokenStateOf() because both are read by the merged list below and
// two definitions of "expired" in one table is the kind of disagreement nobody
// notices until the two rows are next to each other.
function artifactStateOf(record, nowMs) {
  if (!record.expiresAt) return 'no expiry stated';
  return record.expiresAt <= nowMs ? 'expired' : 'valid';
}

function artifactList() {
  log.debug("Entering artifactList().");
  const nowMs = Date.now();
  const out = artifacts.map(function (record) {
    return Object.assign({ state: artifactStateOf(record, nowMs) }, record);
  }).sort(function (a, b) { return b.issuedAt - a.issuedAt; });
  log.debug("Leaving artifactList(). " + out.length + " artifact(s).");
  return out;
}

// ---------------------------------------------------------------------------
// Everything issued, in one list.
//
// The tokens page draws JWTs, SAML assertions and Kerberos tickets in a single
// table, and the merge happens HERE rather than there: which artifact belongs
// beside a token, and what "still valid" means for each, are statements about the
// state this file holds. admin.js renders what it is handed.
//
// The families keep their own fields — a ticket has an enc-type and no scope, an
// assertion has an audience and no client_id — and gain four in common, which are
// the four every row of that table needs whatever it is:
//
//   family        'token', 'assertion' or 'ticket'
//   state         against the same clock, from the two functions above
//   expiresAtMs   MILLISECONDS. A JWT's `exp` is seconds and an artifact's
//                 `expiresAt` is already milliseconds, and a single table cannot
//                 sort or compare two units. Getting this wrong reads as every
//                 token having expired in 1970.
//   identifier    the jti or the AssertionID — and the empty string for a Kerberos
//                 ticket, which genuinely has none to quote; see the page.
//
// OID4VCI credentials are recorded here too and are deliberately NOT in this list:
// they are counted on the metrics page and listed nowhere. That is a gap rather
// than a principle — a credential is as much an issued artifact as an assertion is
// — and closing it means adding a fourth entry to ISSUED_FAMILIES below and a
// column mapping in admin.js, not anything harder.
// ---------------------------------------------------------------------------
const ISSUED_FAMILIES = [
  { family: 'token', label: 'JWTs', kinds: TOKEN_KINDS,
    what: 'every JWT this service signs: access tokens, ID Tokens, refresh tokens, ' +
          'the signed UserInfo response and the OID4VP Request Object' },
  { family: 'assertion', label: 'SAML assertions', kinds: ['SAML 2.0', 'SAML 1.1'],
    what: 'issued through WS-Trust (SAML 2.0 and SAML 1.1 token types) and through ' +
          'WS-Federation sign-in' },
  { family: 'ticket', label: 'Kerberos tickets', kinds: ['Kerberos TGT', 'Kerberos service ticket'],
    what: 'issued by the KDC over raw TCP and UDP 88 and over MS-KKDCP, and used by ' +
          'the Kerberos-protected service and by SPNEGO' }
];

// kind -> family, for the artifacts. One map built from the structure above rather
// than a prefix test on the kind string, so the filter's list of kinds and the list
// this function admits cannot drift apart: a kind the filter offers and this map
// does not know would be a dropdown entry that always matches nothing.
const FAMILY_BY_ARTIFACT_KIND = {};
ISSUED_FAMILIES.forEach(function (entry) {
  if (entry.family === 'token') return;
  entry.kinds.forEach(function (kind) { FAMILY_BY_ARTIFACT_KIND[kind] = entry.family; });
});

function issuedList() {
  log.debug("Entering issuedList().");
  const nowMs = Date.now();
  const out = [];
  tokens.forEach(function (record) {
    out.push(Object.assign({}, record, {
      family: 'token',
      state: tokenStateOf(record, nowMs),
      expiresAtMs: record.exp ? record.exp * 1000 : 0,
      identifier: record.jti || ''
    }));
  });
  artifacts.forEach(function (record) {
    const family = FAMILY_BY_ARTIFACT_KIND[record.kind];
    // A credential, or a kind added to the registry and not to the structure above.
    // Skipped rather than shown under a family nothing can filter by.
    if (!family) return;
    out.push(Object.assign({}, record, {
      family: family,
      state: artifactStateOf(record, nowMs),
      expiresAtMs: record.expiresAt || 0,
      identifier: record.id || '',
      // Carried explicitly rather than left undefined: the page's button column
      // reads this one field for all three families, so an assertion says why it
      // has no button in the same place a UserInfo response does.
      revocable: false
    }));
  });
  // Newest first, across all three families together — the point of one table is
  // that a sign-in which produced an ID Token and a SAML assertion shows both,
  // next to each other, in the order they happened.
  out.sort(function (a, b) { return b.issuedAt - a.issuedAt; });
  log.debug("Leaving issuedList(). " + out.length + " row(s) across " +
            ISSUED_FAMILIES.length + " family/families.");
  return out;
}

// ---------------------------------------------------------------------------
// Reading the users back.
//
// The list is built from THREE sources and not one, which is the part worth
// understanding before changing it:
//
//   1. the authentication registry above — everyone who presented a credential;
//   2. every token's `sub`/`username`;
//   3. every artifact's subject.
//
// Sources 2 and 3 exist because an identity can be issued something here without
// ever having authenticated here: a token exchange presents somebody else's token,
// WS-Trust's OnBehalfOf names a delegated subject, and a Kerberos S4U2Self ticket is
// for a user who has not been near this KDC. Building the page from source 1 alone
// would list a subject in the tokens table and deny they exist on the users page,
// which is the kind of disagreement between two pages of one console that costs an
// afternoon. Such a row is marked `authenticated: false` and the page says what that
// means rather than leaving the reader to assume the recording is broken.
// ---------------------------------------------------------------------------

// A {name: count} object as the sorted array the page wants, commonest first.
function countedRows(counts, nameKey) {
  return Object.keys(counts || {}).map(function (name) {
    const row = { count: counts[name] };
    row[nameKey] = name;
    return row;
  }).sort(function (a, b) { return b.count - a.count; });
}

// The empty shell every row starts as, whether it came from a real authentication or
// only from something issued. One function so that a row from source 2 has exactly
// the fields a row from source 1 has — a page that reads `row.protocols.length` must
// not have to ask where the row came from first.
function blankUserRow(identity) {
  return {
    key: identity.key, name: identity.name, forms: {}, realms: {}, protocols: {},
    authentications: 0, firstAt: 0, lastAt: 0, isClient: false,
    authenticated: false, events: [], eventsForgotten: 0,
    tokens: { issued: 0, valid: 0, expired: 0, revoked: 0, other: 0 },
    artifactKinds: {}, artifacts: 0, lastActivityAt: 0
  };
}

function userRows() {
  log.debug("Entering userRows().");
  const nowMs = Date.now();
  const rows = new Map();
  const rowFor = function (value) {
    const identity = identityOf(value);
    if (!identity.key) return null;
    if (!rows.has(identity.key)) rows.set(identity.key, blankUserRow(identity));
    const row = rows.get(identity.key);
    row.forms[identity.form] = (row.forms[identity.form] || 0) + 1;
    if (identity.realm) row.realms[identity.realm] = (row.realms[identity.realm] || 0) + 1;
    return row;
  };

  users.forEach(function (record) {
    const row = blankUserRow(record);
    // The registry's own counts win over anything reconstructed below: they count
    // authentications, and the forms map there was built one presentation at a time.
    row.forms = Object.assign({}, record.forms);
    row.realms = Object.assign({}, record.realms);
    row.protocols = record.protocols;
    row.authentications = record.authentications;
    row.firstAt = record.firstAt;
    row.lastAt = record.lastAt;
    row.isClient = record.isClient;
    row.authenticated = true;
    // A copy: the page and the JSON reply both read this, and handing out the live
    // array would let a caller's sort or splice edit the registry.
    row.events = record.events.slice();
    row.eventsForgotten = record.eventsForgotten;
    row.lastActivityAt = record.lastAt;
    rows.set(record.key, row);
  });

  tokens.forEach(function (record) {
    // `username` first: it is the local name, and falling back to `sub` costs
    // nothing because identityOf() strips the prefix off it anyway.
    const row = rowFor(record.username || record.sub);
    if (!row) return;
    // Both spellings are recorded as forms when they differ, so the page can show
    // that this row's `sub` is what the tokens say.
    if (record.sub && record.username) {
      row.forms[record.sub] = (row.forms[record.sub] || 0) + 1;
    }
    row.tokens.issued++;
    const state = tokenStateOf(record, nowMs);
    if (state === 'valid') row.tokens.valid++;
    else if (state === 'expired') row.tokens.expired++;
    else if (state === 'revoked') row.tokens.revoked++;
    else row.tokens.other++;
    if (record.issuedAt > row.lastActivityAt) row.lastActivityAt = record.issuedAt;
  });

  artifacts.forEach(function (record) {
    const row = rowFor(record.subject);
    if (!row) return;
    row.artifacts++;
    row.artifactKinds[record.kind] = (row.artifactKinds[record.kind] || 0) + 1;
    if (record.issuedAt > row.lastActivityAt) row.lastActivityAt = record.issuedAt;
  });

  const out = Array.from(rows.values()).map(function (row) {
    return Object.assign({}, row, {
      forms: countedRows(row.forms, 'form'),
      realms: countedRows(row.realms, 'realm'),
      artifactKinds: countedRows(row.artifactKinds, 'kind'),
      protocols: Object.keys(row.protocols).map(function (name) {
        const family = row.protocols[name];
        return { protocol: family.protocol, count: family.count, lastAt: family.lastAt,
                 methods: countedRows(family.methods, 'method') };
      }).sort(function (a, b) { return b.lastAt - a.lastAt; })
    });
  });
  // Most recently active first, which on a mock is nearly always the person being
  // debugged right now.
  out.sort(function (a, b) { return b.lastActivityAt - a.lastActivityAt; });
  log.debug("Leaving userRows(). " + out.length + " user(s), " +
            out.filter(function (r) { return r.authenticated; }).length + " authenticated here.");
  return out;
}

// One user, with everything issued to them. The tokens keep their session id, which
// is what the drill-down groups by; the artifacts keep their own fields, because a
// ticket has an enc-type and an assertion has an audience and flattening the two
// would lose the half of each that is worth reading.
function userDetail(key) {
  log.debug("Entering userDetail(). key=" + key);
  const wanted = String(key || '');
  const row = userRows().filter(function (r) { return r.key === wanted; })[0] || null;
  if (!row) {
    log.debug("Leaving userDetail(). No such user.");
    return null;
  }
  const nowMs = Date.now();
  const theirTokens = [];
  tokens.forEach(function (record) {
    if (identityKeyOf(record.username || record.sub) !== wanted) return;
    theirTokens.push(Object.assign({ state: tokenStateOf(record, nowMs) }, record));
  });
  theirTokens.sort(function (a, b) { return b.issuedAt - a.issuedAt; });
  const theirArtifacts = artifacts.filter(function (record) {
    return identityKeyOf(record.subject) === wanted;
  }).map(function (record) {
    return Object.assign({ state: artifactStateOf(record, nowMs) }, record);
  }).sort(function (a, b) { return b.issuedAt - a.issuedAt; });
  log.debug("Leaving userDetail(). " + theirTokens.length + " token(s), " +
            theirArtifacts.length + " artifact(s).");
  return { user: row, tokens: theirTokens, artifacts: theirArtifacts };
}

// The session a token was issued under, by jti. The refresh grant is what needs it:
// a refreshed token belongs to the same sign-on session as the refresh token that
// bought it, and that link exists nowhere on the wire — the refresh token carries no
// session identifier, so without this the second generation of every token would
// appear under "no session" and a session's token list would quietly stop growing.
function sessionIdOfJti(jti) {
  const record = jti ? tokens.get(jti) : null;
  return (record && record.sessionId) || '';
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

  const knownUsers = userRows();

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
    // Counted, not listed: the whole list is what /admin/users is for, and repeating
    // it inside every metrics reply would make the two disagree the first time one
    // of them changed.
    users: { known: knownUsers.length, cap: MAX_USERS, forgotten: usersForgotten,
             authenticatedHere: knownUsers.filter(function (r) { return r.authenticated; }).length,
             clients: knownUsers.filter(function (r) { return r.isClient; }).length,
             authentications: knownUsers.reduce(function (n, r) { return n + r.authentications; }, 0) },
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
  MAX_USERS: MAX_USERS,
  MAX_EVENTS_PER_USER: MAX_EVENTS_PER_USER,
  CLAIM_SET_IDS: CLAIM_SET_IDS,
  CLAIM_SETS: CLAIM_SETS,
  RESERVED_JWT_CLAIMS: RESERVED_JWT_CLAIMS,
  PLACEHOLDERS: PLACEHOLDERS,
  DEFAULT_SAML11_NAMESPACE: DEFAULT_SAML11_NAMESPACE,
  REVOCABLE_KINDS: REVOCABLE_KINDS,
  TOKEN_KINDS: TOKEN_KINDS,
  ISSUED_FAMILIES: ISSUED_FAMILIES,
  recordCall: recordCall,
  recordAuthentication: recordAuthentication,
  setUserObserver: setUserObserver,
  identityOf: identityOf,
  identityKeyOf: identityKeyOf,
  userRows: userRows,
  userDetail: userDetail,
  sessionIdOfJti: sessionIdOfJti,
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
  issuedList: issuedList,
  snapshot: snapshot
};
