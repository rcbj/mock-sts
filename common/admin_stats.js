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
// TRUST REALMS: the stores below are partitioned by realm. It requires
// config.js and nothing else here, so it cannot join a cycle and it registers
// no route, so its position is not a position at all.
const realms = require('./realms');
// The audit log. A one-way require and it must stay one: audit.js requires
// helpers.js and config.js and nothing else in this repository, precisely so
// that this file — which most of the service already requires — can call it
// without dragging a graph behind it.
//
// It is called from ONE place in here, recordAuthentication() below, and that
// is the point: that function is already the single funnel every one of the
// sixteen protocol families passes through at the moment a credential is
// accepted, so the audit log gets its authentication events from one line
// rather than from sixteen call sites, the seventeenth of which would be the
// one nobody adds. It is also the only place in this service that has already
// normalised the identity, which is what lets an audit row and a /admin/users
// row name the same person.
const audit = require('./audit');
// THE FEDERATION RELEASE FILTER, and it is a plain require in the ordinary
// direction rather than a hook. Rule 3e's test both ways round: that module
// registers no route, and it requires only helpers.js, config.js and audit.js —
// none of which requires this file — so nothing about requiring it from here
// closes a cycle or moves a route, and a slot would cost a reader an
// indirection for nothing. It is the same argument applications.js is required
// under, twenty lines above.
const federation = require('./../federation/federation');
// For one value: `oauth2.clockSkewS`, the allowance the OAuth endpoints apply
// when they read back a token this service signed. It is read HERE so that the
// state a console screen reports is the state the endpoints will act on — a
// page saying "valid" about a token /oauth2/introspect calls inactive (or the
// reverse) is worse than a page with no state column at all, because it is
// believed. config.js requires nothing from this repository, so this is a plain
// require in the ordinary direction and closes no cycle (rule 3b).
const config = require('./config');
// The application registry — what was on the OTHER side of an authentication.
// See the note where it is called, below, for why this is a plain require and
// not the fifth inverted hook on this module.
const applications = require('./applications');

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
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const calls = realms.map();       // "GET /path" -> the row below

// ---------------------------------------------------------------------
// THE COUNTERS THAT ARE NOT IN THE MAPS, PER TRUST REALM.
//
// The tables above are realm-partitioned; these five numbers describe them, and
// a counter left process-wide would count every realm's calls beside a list
// holding one realm's rows. The metrics page shows both, and the two would
// disagree by however many realms are running — which reads as a bug in the
// page rather than as what it is.
//
// `realms.obj(factory)` is a plain object per realm, so `nums.callTotal++`
// works exactly as the bindings it replaced did.
//
// **`usersForgotten` IS IN HERE AS OF 2026-08-25, AND IT DELIBERATELY WAS NOT
// UNTIL THEN.** The argument for leaving it out was that the identity register
// below mirrors the embedded directory, and the directory was shared by every
// realm — so a per-realm counter would have described a per-realm list that did
// not exist. **The directory became a SUBTREE PER REALM on 2026-08-25**
// (`ldap/CLAUDE.md`), which retired the premise rather than the reasoning: the
// register follows the directory, so both it and the counter describing it are
// partitioned now. This is the shape to look for anywhere else something was
// left process-wide "because the directory is shared" — that sentence was true
// for one day.
// ---------------------------------------------------------------------
const nums = realms.obj(function () {
  return { callTotal: 0, callPathsDropped: 0, tokensForgotten: 0,
           tokensWithoutJti: 0, artifactsForgotten: 0, usersForgotten: 0 };
});



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
    nums.callPathsDropped++;
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
  nums.callTotal++;
  log.debug("Leaving recordCall(). " + nums.callTotal + " call(s) recorded in total.");
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
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const tokens = realms.map();      // jti (or a synthetic key) -> the record below



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
    nums.tokensWithoutJti++;
    key = 'no-jti-' + nums.tokensWithoutJti;
  }
  const record = {
    key: key,
    jti: payload.jti || '',
    kind: kind,
    typ: payload.typ || '',
    revocable: !!payload.jti && REVOCABLE_KINDS.indexOf(kind) >= 0,
    sub: payload.sub || '',
    // WHO SAID IT, which is this service under whichever base URL the request
    // arrived on — `oauth2.issuer` is empty by default precisely so that one
    // process answers correctly as localhost, as `sts` on a compose network and
    // through a published port. It is kept because it is the only thing in this
    // record that can tell an audience naming a PARTY from one naming this
    // service itself: a refresh token is addressed to the token endpoint and an
    // access token nobody named a resource for carries `<base>/resource`, and
    // `user_graph.js` would otherwise draw a box for each of them. Nothing can
    // be derived here instead — the base is a property of the REQUEST, and by
    // the time a page reads this record there is no request to ask.
    iss: payload.iss || '',
    // `username` on an access or refresh token, `preferred_username` on an ID
    // Token: the two carry the same person under different names because that is
    // what their respective specifications call the claim, and a console column
    // that read only one of them would show a dash for every ID Token.
    username: payload.username || payload.preferred_username || '',
    client_id: payload.client_id || payload.azp || payload.aud || '',
    // WHAT THIS TOKEN IS ADDRESSED TO, as its own fact. `client_id` above falls
    // back to the `aud` when nothing better names the client, which is right for
    // the tokens page's one party column and loses the audience entirely on
    // every token that DOES name its client — which is every token an RFC 8693
    // exchange issues, where the audience is the whole point. `credential_graph.js`
    // draws the resource a credential was issued to reach, so it needs the
    // audience whether or not a client_id sits beside it. An array is joined
    // rather than kept: `aud` may be one or several (RFC 7519 section 4.1.3) and
    // one string is what every reader of this record already expects.
    audience: Array.isArray(payload.aud) ? payload.aud.join(' ')
                                         : String(payload.aud || ''),
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
    nums.tokensForgotten++;
  }
  tokens.set(key, record);
  log.debug("Leaving recordJwt(). " + tokens.size + " token(s) held, " + nums.tokensForgotten + " forgotten.");
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
//
// PER TRUST REALM since 2026-08-25, and it read "for the whole service" until
// then. Two things were wrong with one set. The metrics page prints
// `tokens.revoked` beside `tokens.held`, which comes from a per-realm map, so
// one realm's revocation count appeared under every realm — the exact
// disagreement the counters block near the top of this file exists to prevent.
// And `POST /oauth2/revoke` under one realm could kill a jti issued by another,
// which is a cross-realm WRITE in the one family whose realm support is
// documented as `full`. Nothing legitimate crossed: a jti only ever appears in
// the realm whose signing key minted it, so within a realm every read and write
// here answers exactly as it did.
//
// A Set has no facade in `realms.js` — `map()`, `arr()` and `obj()` are the
// three — so this is `keyed()`, the general case, and the reads below are
// spelled `revokedJtis()` because of it.
// ---------------------------------------------------------------------------
const revokedJtis = realms.keyed(function () { return new Set(); });

function revoke(jti, via) {
  log.debug("Entering revoke(). jti=" + jti);
  if (!jti) {
    log.debug("Leaving revoke(). There was no jti to revoke.");
    return false;
  }
  const first = !revokedJtis().has(jti);
  revokedJtis().add(jti);
  const record = tokens.get(jti);
  if (record) {
    record.revoked = true;
    record.revokedAt = record.revokedAt || Date.now();
    record.revokedVia = record.revokedVia || (via || 'unstated');
  }
  log.info('admin: the token with jti ' + jti + ' is revoked (' + (via || 'unstated') + '). ' +
           revokedJtis().size + ' revoked in total.');
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
  const was = revokedJtis().delete(jti);
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
  return !!jti && revokedJtis().has(jti);
}

function revokedCount() {
  return revokedJtis().size;
}

// ---------------------------------------------------------------------------
// The artifacts that are not JWTs: assertions, tickets and credentials.
//
// One shape for all three, because the metrics page asks the same three questions
// of each — how many, how many still valid, and whose. `expiresAt` is a
// millisecond epoch or 0 for "no expiry was stated", which is the honest answer
// for a couple of them rather than pretending to an expiry of now.
// ---------------------------------------------------------------------------
// PER TRUST REALM. `realms.arr()` is a array that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain array it replaced. See common/realms.js.
const artifacts = realms.arr();


function recordArtifact(kind, detail) {
  const record = Object.assign({ kind: kind, issuedAt: Date.now(), expiresAt: 0, subject: '' }, detail);
  artifacts.push(record);
  if (artifacts.length > MAX_ARTIFACTS) {
    artifacts.shift();
    nums.artifactsForgotten++;
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

// A SPIFFE SVID, X.509 or JWT.
//
// A FOURTH artifact family rather than rows under `token`, and the distinction
// is not cosmetic. A JWT-SVID is a JWS and would sit perfectly well among the
// JWTs — but an X509-SVID is a certificate, the two are issued by the same act
// against the same registration entry, and splitting them would put one half of
// SPIFFE on the tokens page and the other half nowhere. More to the point:
// **neither is revocable here**, where every kind under `token` is. `signJwt()`
// is not the funnel for a JWT-SVID either, and cannot be — it signs with the
// STS key, and a JWT-SVID is signed by the trust domain's JWT authority — so
// this is the funnel, called from spiffe_workload.js and spiffe_api.js at the
// moment each SVID is minted.
function recordSvid(kind, detail) {
  log.debug("Entering recordSvid(). kind=" + kind + ", subject=" + (detail.subject || '?'));
  const record = recordArtifact('SVID (' + kind + ')', {
    subject: detail.subject || '',
    entryId: detail.entryId || '',
    audience: (detail.audiences || []).join(' '),
    serial: detail.serial || '',
    hint: detail.hint || '',
    expiresAt: detail.expiresAt || 0
  });
  // -----------------------------------------------------------------------
  // AND THE DIRECTORY, FOR AN X509-SVID. See noteCertificateIssued() below for
  // why an ISSUANCE reaches the observer at all, given that being issued a
  // credential is not authenticating with one.
  // -----------------------------------------------------------------------
  if (kind === 'X.509' && detail.certificate) {
    noteCertificateIssued(detail.subject, detail.certificate, detail);
  }
  log.debug("Leaving recordSvid(). " + artifacts.length + " artifact(s) held.");
  return record;
}

// ---------------------------------------------------------------------------
// AN ISSUED CERTIFICATE IS AN IDENTITY IN THE DIRECTORY, WHICH IS A DIFFERENT
// CLAIM FROM "IT AUTHENTICATED" AND THE TWO MUST NOT MERGE.
//
// Until now the directory grew an entry for a SPIFFE identity at exactly three
// points, all of them an acceptance: an X509-SVID over mutual TLS at the SPIRE
// Server API, an agent attesting, and a JWT-SVID verified at ValidateJWTSVID.
// Being ISSUED an SVID was deliberately not one of them, and the argument was
// sound as far as it went — a workload that collects a certificate has proved
// nothing, and /admin/users answers "who has authenticated here".
//
// What it left out is that this trust domain's whole output is CERTIFICATES,
// and a directory that could not say which identities hold one — nor what the
// current one is, nor whether the identity has since been shut off — could not
// answer the question somebody points an LDAP client at a SPIFFE mock to ask.
// So an issuance now reaches the observer too, and it is told which of the two
// it is:
//
//   * `event: 'authentication'` — a credential was ACCEPTED. Counted on this
//     page, an audit row, the whole existing path, unchanged.
//   * `event: 'issuance'` — a certificate was MINTED for this identity. It
//     creates or updates the directory entry and writes the certificate onto
//     it, and it does NOTHING ELSE: no `authentications` count, no audit
//     `authentication` row, and no protocol row. An issuance that inflated the
//     authentication count would make /admin/users's central number mean two
//     things at once, and an agent holding a stream open re-mints every
//     half-lifetime — so a workload left running overnight would read as having
//     authenticated four hundred times. What the identity DOES get on that page
//     is the row `recordArtifact()` above already gives it: an SVID with no
//     authentication behind it, which the page counts under "seen only as a
//     subject" and which is the honest answer.
//
// THE FUNNEL IS recordSvid() ABOVE, which the five X509-SVID mints already
// call, and that is the same argument recordAuthentication() makes for itself:
// one place rather than five, and a sixth mint added later that forgets to call
// it is a mint with no artifact row either — so the omission shows on
// /admin/metrics rather than being silent in the directory alone.
//
// WHAT IS NOT COVERED, and each is a decision rather than a gap:
//
//   * A JWT-SVID. It is not a certificate; it has no subject, issuer, serial or
//     validity in the sense these attributes hold, and the identity behind one
//     reaches the directory anyway when it is VALIDATED at ValidateJWTSVID,
//     which is an acceptance.
//   * The SPIRE Server API's OWN server SVID, minted in spiffe_grpc.js to bind
//     the mutual-TLS port. It never reaches this function because that call
//     site records no artifact either, and it must not: filing this service's
//     own listener among the people is the mistake didPlan() already refuses
//     for `/did/generate?method=web`.
//   * A downstream CA from NewDownstreamX509CA. It is an intermediate belonging
//     to whoever asked for it, not an identity in this trust domain, and
//     spiffe_ca.js deliberately does not add it to this service's authorities
//     either.
// ---------------------------------------------------------------------------
function noteCertificateIssued(subject, certificate, detail) {
  log.debug("Entering noteCertificateIssued(). subject=" + (subject || '?'));
  const identity = identityOf(subject);
  if (!identity.key || !userObserver) {
    log.debug("Leaving noteCertificateIssued(). " +
              (identity.key ? "There is no directory." : "There is no identity."));
    return;
  }
  const info = detail || {};
  try {
    userObserver({
      event: 'issuance',
      key: identity.key, name: identity.name, realm: identity.realm,
      presented: identity.form,
      protocol: 'SPIFFE',
      method: 'X509-SVID issued',
      isClient: false, sub: '',
      amr: [], acr: '',
      // NOT `certificate`, which the observer already reads as "the identity IS
      // this DN" and routes to certificatePlan(). Every SVID this trust domain
      // mints carries the SAME subject — `spiffe.svidSubject`, `C=US,O=SPIRE` —
      // so that route would fold every workload in the domain onto one entry
      // named for `O=SPIRE`. The identity here is the SPIFFE ID; the
      // certificate is a FACT ABOUT it, which is what the different key says.
      issuedCertificate: certificate,
      entryId: info.entryId || '',
      hint: info.hint || '',
      linkedTo: ''
    });
  } catch (e) {
    // The same rule the observer call in recordAuthentication() follows, and
    // here it matters more: this runs inside a gRPC handler that has already
    // minted a certificate the caller is owed, and a throw would turn a
    // successful issuance into an Unknown status.
    log.error('the user observer threw on an issuance and was ignored; the ' +
              'SVID itself is unaffected: ' + e.message);
  }
  log.debug("Leaving noteCertificateIssued().");
}

// ---------------------------------------------------------------------------
// AND THE OTHER END OF IT: AN IDENTITY WHOSE CREDENTIALS HAVE BEEN SHUT OFF.
//
// SPIFFE HAS NO REVOCATION and this does not invent one — `GET /spiffe` says so
// outright and the Workload API's `crl` field stays empty because empty is the
// conforming value. What this records is the three things in the registry that
// DO end an identity's ability to hold a credential here, which is the honest
// nearest thing: a registration entry deleted, an agent banned, an agent
// deleted. `spiffe_registry.js` is what calls it, at the point each of those
// happens, and the directory writes a status onto the entry rather than
// removing it — the record of an identity that USED to be issued certificates
// is the whole reason somebody would look.
//
// It goes through the observer for the reason everything else here does: this
// file cannot require ldap_server.js (that module requires this one, and a
// cycle in node hands back exports that are undefined), and a second slot for
// three calls would cost a reader an indirection that rule 3e says to spend
// only where a require would close a cycle or move a route. This one is the
// SAME slot with a third `event`.
// ---------------------------------------------------------------------------
function recordCredentialStatus(subject, status, detail) {
  log.debug("Entering recordCredentialStatus(). subject=" + (subject || '?') +
            ", status=" + status);
  const identity = identityOf(subject);
  if (!identity.key || !userObserver) {
    log.debug("Leaving recordCredentialStatus(). " +
              (identity.key ? "There is no directory." : "There is no identity."));
    return;
  }
  const info = detail || {};
  try {
    userObserver({
      event: 'credential-status',
      key: identity.key, name: identity.name, realm: identity.realm,
      presented: identity.form,
      protocol: 'SPIFFE',
      method: String(status),
      credentialStatus: String(status),
      // Why, in the words the page prints. It is written as a sentence rather
      // than as a code because it is the only thing on the entry that explains
      // a status a reader did not expect, and "entry-deleted" would need a
      // table nobody has.
      credentialStatusReason: String(info.reason || ''),
      isClient: false, sub: '', amr: [], acr: '', linkedTo: ''
    });
  } catch (e) {
    // As above: a ban or a delete has already happened and must not be undone
    // by a directory that could not write it down.
    log.error('the user observer threw on a credential status change and was ' +
              'ignored; the change itself stands: ' + e.message);
  }
  log.debug("Leaving recordCredentialStatus().");
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
// SCIM, WHICH IS COUNTED HERE AND NOT ON /admin/metrics.
//
// Every other family in this service is counted twice on purpose and in two
// different senses: an endpoint CALL (app.js's log, by matched route) and an
// ARTIFACT (a token, an assertion, a ticket). SCIM produces no artifact — a
// provisioned person is an LDAP entry and the directory already reports those —
// so what is worth counting is the SHAPE of what a provisioning client did:
// which operation, on which resource type, and whether it was refused.
//
// **It is deliberately NOT folded into snapshot().** The /scim routes are
// already in that reply, counted by path like every other endpoint, and a second
// total beside them would be one act counted twice in one document — the same
// mistake rule 3c warns about for audit rows. So this is its own reply, read by
// /admin/scim and by GET /admin-api/scim, and /admin/metrics is untouched.
//
// **THE VOCABULARY IS A TABLE**, the way audit.js's CATEGORIES and ACTIONS are,
// and for the same reason: the console's breakdown and the management API's
// `operations` member are both built from it, so an operation cannot be
// performed and go unreported, nor be reported and never occur. A new operation
// is a row here and a `recordScim()` call, and nothing else.
// ---------------------------------------------------------------------------
const SCIM_OPERATIONS = [
  { operation: 'create', label: 'Create', method: 'POST',
    what: 'A resource was created (RFC 7644 section 3.3).' },
  { operation: 'list', label: 'List', method: 'GET',
    what: 'A collection was queried (section 3.4.2), with or without a filter.' },
  { operation: 'read', label: 'Read', method: 'GET',
    what: 'One resource was retrieved by id (section 3.4.1).' },
  { operation: 'search', label: 'Search', method: 'POST',
    what: 'A query sent as a POST to .search (section 3.4.3), which is what a ' +
          'client uses when its filter is too long for a URL.' },
  { operation: 'replace', label: 'Replace', method: 'PUT',
    what: 'A whole resource was replaced (section 3.5.1).' },
  { operation: 'modify', label: 'Modify', method: 'PATCH',
    what: 'A PATCH was applied (section 3.5.2). The operation a provisioning ' +
          'client uses most, and the one whose path grammar is hardest to get ' +
          'right — which is why this service does not implement it itself.' },
  { operation: 'delete', label: 'Delete', method: 'DELETE',
    what: 'A resource was deleted (section 3.6).' },
  { operation: 'bulk', label: 'Bulk', method: 'POST',
    what: 'A BulkRequest was applied (section 3.7). The operations INSIDE it ' +
          'are counted individually as well, so one bulk of five creates is ' +
          'one bulk row and five create rows — which is the honest reading and ' +
          'is said on the page, because a reader adding the column up will ' +
          'otherwise find it does not tally.' },
  { operation: 'discovery', label: 'Discovery', method: 'GET',
    what: 'ServiceProviderConfig, ResourceTypes or Schemas (section 4). What a ' +
          'client reads before it does anything else, and the one thing here ' +
          'that touches no directory entry.' }
];

const SCIM_RESOURCE_TYPES = ['User', 'Group', 'Bulk', 'ServiceProviderConfig',
                             'ResourceType', 'Schema', 'Self'];

const scimCounts = {
  total: 0,
  ok: 0,
  failed: 0,
  firstAt: 0,
  lastAt: 0,
  byOperation: {},
  byResourceType: {},
  byStatus: {},
  // Keyed by the `scimType` from RFC 7644 section 3.12, with '(none)' for a
  // refusal that carried no such code — a 404 has none, and a table that
  // silently dropped those would report far fewer failures than there were.
  byScimType: {},
  // WHICH AUTHENTICATION SCHEME GOT IN. Keyed by scim_auth.js's scheme ids,
  // plus `anonymous` for a request nothing authenticated (a discovery call, or
  // any call while scim.authRequired is off) and `refused` for one that never
  // got past the gate. The VOCABULARY is not here, deliberately: it belongs to
  // scim_auth.js, this module cannot require that one (it requires this), and
  // the console draws the full list of schemes from the surface description it
  // already reads. So this is a plain tally and the zeroes are supplied by the
  // page — which is the same division /admin/scim already has between the
  // counters and the surface.
  byAuthScheme: {}
};

function bump(table, key) {
  const name = String(key || '(none)');
  table[name] = (table[name] || 0) + 1;
}

// One SCIM request, recorded where it is ANSWERED rather than where it arrives —
// the same rule recordAuthentication() follows about a credential being
// accepted. A request that never reached a handler is an endpoint call and is
// counted as one by app.js; a request this module counts is one the SCIM
// implementation had an opinion about.
//
// It cannot throw. It is called from inside request handlers whose failure mode
// would otherwise be a provisioning client seeing a 500 because a counter was
// unhappy, which is the same guarantee audit() gives and for the same reason.
function recordScim(detail) {
  log.debug("Entering recordScim().");
  try {
    const info = detail || {};
    const now = Date.now();
    scimCounts.total++;
    if (info.ok) {
      scimCounts.ok++;
    } else {
      scimCounts.failed++;
    }
    if (!scimCounts.firstAt) {
      scimCounts.firstAt = now;
    }
    scimCounts.lastAt = now;
    bump(scimCounts.byOperation, info.operation);
    bump(scimCounts.byResourceType, info.resourceType);
    bump(scimCounts.byStatus, info.status);
    bump(scimCounts.byAuthScheme, info.authScheme);
    if (!info.ok) {
      bump(scimCounts.byScimType, info.scimType);
    }
  } catch (e) {
    // Swallowed on purpose: a counter must never be able to fail a provisioning
    // request. Logged rather than ignored, because a counter that stopped
    // counting silently would make this page quietly wrong.
    log.warn('scim: a request could not be counted: ' + e.message);
  }
  log.debug("Leaving recordScim().");
}

// The counters, with the two vocabularies beside them so that a caller can draw
// every row — including the ones at zero, which are the interesting ones for
// somebody asking "does this server support PATCH".
function scimSnapshot() {
  log.debug("Entering scimSnapshot().");
  const operations = SCIM_OPERATIONS.map(function (row) {
    return { operation: row.operation, label: row.label, method: row.method,
             what: row.what, count: scimCounts.byOperation[row.operation] || 0 };
  });
  const resourceTypes = SCIM_RESOURCE_TYPES.map(function (name) {
    return { resourceType: name, count: scimCounts.byResourceType[name] || 0 };
  });
  const out = {
    total: scimCounts.total,
    ok: scimCounts.ok,
    failed: scimCounts.failed,
    firstAt: scimCounts.firstAt,
    lastAt: scimCounts.lastAt,
    operations: operations,
    resourceTypes: resourceTypes,
    byStatus: Object.assign({}, scimCounts.byStatus),
    byScimType: Object.assign({}, scimCounts.byScimType),
    byAuthScheme: Object.assign({}, scimCounts.byAuthScheme)
  };
  log.debug("Leaving scimSnapshot(). " + out.total + " request(s) counted.");
  return out;
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

// PER TRUST REALM, since 2026-08-25 and for the reason the counters block above
// gives: this register is the list of people a realm has SEEN, and the people a
// realm HOLDS are its own subtree of the directory. While it was one Map every
// realm's console listed every other realm's users — `/admin/users` under
// `/realm/acme` showed somebody who had only ever signed in to the default
// realm — and that realm's own directory reader then reported their entry as
// missing, because in that realm it genuinely was. Two pages of one console
// disagreeing, which is the failure this file's comments warn about twice.
//
// **THE CAP IS NOW PER REALM**, in the same one line, the way `tokens` and
// `artifacts` already were: MAX_USERS identities in each. Deliberate, and the
// opposite of the choice `ldap_server.js` makes for `ldap.maxEntries`, which
// stays process-wide — there the cap protects ONE store every realm writes
// into, and here each realm has a store of its own, so a shared cap would let a
// busy realm evict a quiet realm's people.
const users = realms.map();    // local name -> the record below

// Does this identity begin `<attributetype>=`? That is the one shape identityOf()
// below must not split at an '@'. Deliberately strict — a type is a letter
// followed by letters, digits and hyphens, which is what RFC 4512 allows — so that
// it cannot match a name somebody typed at a sign-in screen.
const DN_SHAPED = /^[A-Za-z][A-Za-z0-9-]*=/;

// And is it a DECENTRALIZED IDENTIFIER? The same question as the one above, asked
// for the same reason and about a different shape: `did:web:sts.example.com%3A8443`
// and `did:jwk:eyJrdHkiOi…` are single opaque identifiers, and the ':' separators
// are part of the syntax rather than a name and a realm. Splitting one at an '@'
// would be splitting inside a method-specific id — a did:web whose domain carries
// a userinfo component, or a base64url payload that happens to decode with one —
// and the part before it names nothing.
//
// It matters here because the Decentralized Identity endpoints present identities
// of exactly this shape: an ldp_vc names its subject `did:jwk:…`, the OID4VP
// Verifier reports whatever DID presented to it, and /did/generate mints one. RFC
// 3986 says the method name is lowercase ALPHA and DIGIT; the `i` flag is here
// because this test is deciding how to file a person and not validating a DID.
const DID_SHAPED = /^did:[a-z0-9]+:/i;

// A presented identity, split into the part that identifies a person here and the
// parts that merely say where it was presented. Without entering/leaving logs: it is
// called for every token and artifact on every users page view, so a pair of lines
// here would be most of the log.
function identityOf(value) {
  log.debug("Entering identityOf().");
  const text = String(value == null ? '' : value).trim();
  if (!text) {
    log.debug("Leaving identityOf().");
    return { key: '', name: '', realm: '', form: '' };
  }
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
  //
  // A DID is the other exception and arrives from the Decentralized Identity
  // endpoints; see DID_SHAPED above for why it is taken whole.
  const at = (DN_SHAPED.test(rest) || DID_SHAPED.test(rest)) ? -1 : rest.lastIndexOf('@');
  if (at > 0) {
    realm = rest.slice(at + 1);
    rest = rest.slice(0, at);
  }
  log.debug("Leaving identityOf().");
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
  log.debug("Entering userRecord().");
  let record = users.get(identity.key);
  if (record) {
    log.debug("Leaving userRecord().");
    return record;
  }
  if (users.size >= MAX_USERS) {
    // Map iterates in insertion order, so the first key is the least recently
    // FIRST SEEN — not the least recently active. Chosen because it needs no sweep
    // and because a registry of 2,000 distinct usernames on a mock is already a
    // load generator rather than a person, and the page says how many went.
    const oldest = users.keys().next().value;
    users.delete(oldest);
    nums.usersForgotten++;
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
  log.debug("Leaving userRecord().");
  return record;
}

// ---------------------------------------------------------------------------
// SOMEBODY WHO EXISTS AND HAS NOT AUTHENTICATED HERE, ADDED 2026-08-27 FOR
// PERSISTENCE, AND THE DISTINCTION IT DRAWS IS THE WHOLE POINT OF IT.
//
// Until the directory could be written down, everybody in this register got
// here by authenticating, and `/admin/users` could say "these are the people
// this service knows" and "these are the people who signed in" with one list.
// A RESTORED DIRECTORY BREAKS THAT. Its people exist — they are entries, they
// are searchable over 389, SCIM will read them, a token issued to them carries
// their attributes — and not one of them has authenticated in THIS process.
//
// The bug this fixes was found by restarting: the directory came back with
// twenty entries and `/admin/users` reported `known: 0`, because that page has
// never read the directory. It reads THIS register. So a restore has to fill
// it, and the sentence it fills it with has to be the true one:
//
//   `authentications: 0`, `restored: true`, and `authenticated` FALSE on the
//   row — which is what keeps `authenticatedHere` counting sign-ins rather
//   than people.
//
// **THE COUNTS ARE DELIBERATELY NOT RESTORED**, and that is not an omission to
// be tidied up later. How many times somebody signed in, when they first did,
// which protocols they used and every event in their drill-down are STATISTICS
// about a process, and this service's statistics have always been per process —
// `/admin/metrics` starts at zero on every start and is documented as doing so.
// What persists is what somebody typed; what resets is what this process
// counted. Restoring the counts would make `/admin/metrics` disagree with
// `/admin/users` about how many authentications this process has seen.
// ---------------------------------------------------------------------------
function noteKnownIdentity(name, how) {
  log.debug("Entering noteKnownIdentity(). how=" + how);
  const identity = identityOf(name);
  if (!identity.key) {
    log.debug("Leaving noteKnownIdentity(). There was no identity in it.");
    return null;
  }
  if (users.has(identity.key)) {
    // Already here, which means they have authenticated — during this
    // process's startup, or just now. **THIS EARLY RETURN IS LOAD-BEARING ON
    // THE AUTHENTICATION PATH**: `recordAuthentication()` builds the record before
    // it calls the user observer, and that observer reaches `createUser()`,
    // which calls this. Without the check, somebody signing in for the first
    // time would be marked as not having signed in. The live record is always
    // the better one and must never be overwritten with a blank.
    log.debug("Leaving noteKnownIdentity(). Already known.");
    return users.get(identity.key);
  }
  const record = userRecord(identity);
  // WHY this record exists without a sign-in behind it: `restored` off a
  // persistent store, `created` because somebody made the person by hand.
  // userRows() reads it and nothing else does.
  record.knownBy = how === 'restored' ? 'restored' : 'created';
  log.debug("Leaving noteKnownIdentity().");
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
//               amr and acr are also handed to the user observer, which is how
//               the directory comes to know that a sign-in had two factors.
//
// It returns the record so a caller can log what it now knows, and it NEVER throws
// on a missing field: a statistics call that could fail an authentication would be
// the tail wagging the dog, the same rule signJwt()'s recorder follows.
function recordAuthentication(detail) {
  log.debug("Entering recordAuthentication().");
  const info = detail || {};
  log.debug("Entering recordAuthentication(). protocol=" + (info.protocol || '?') +
            ", presented=" + (info.presented || '?'));
  const identity = identityOf(info.presented);
  if (!identity.key) {
    log.debug("Leaving recordAuthentication(). There was no identity to record.");
    log.debug("Leaving recordAuthentication().");
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
  // The audit log's authentication event. Here rather than at the fourteen call
  // sites for the reason given at the require above, and here rather than at the
  // TOP of this function because the row must mean "a credential was accepted"
  // — an identity that could not be read is not an authentication and gets no
  // row, which is the early return above.
  //
  // audit.audit() cannot throw; see its header. Nothing about recording an
  // authentication may be able to fail one.
  audit.audit({
    action: 'authentication',
    actor: identity.key,
    actorForm: identity.form,
    protocol: protocol,
    channel: 'internal',
    target: info.sessionId || '',
    summary: identity.key + ' authenticated through ' + protocol + ' (' + method + ')',
    detail: {
      method: method,
      presented: identity.form,
      realm: identity.realm || '',
      sub: info.sub || '',
      client_id: info.client_id || '',
      amr: (info.amr || []).join(', '),
      acr: info.acr || '',
      sessionId: info.sessionId || '',
      isClient: !!record.isClient,
      authenticationsSoFar: record.authentications,
      note: info.note || ''
    }
  });
  // THE APPLICATION on the other side of this authentication, where the caller
  // named one. A plain require in the ordinary direction rather than a fifth
  // hook (rule 3e): applications.js registers no route and requires only
  // helpers.js, config.js and audit.js, so nothing about requiring it from here
  // closes a cycle or moves a route, and a slot would cost a reader an
  // indirection for nothing.
  //
  // This covers the grants where a client_id rides on the authentication —
  // client_credentials, the password grant, token exchange. It does NOT cover
  // the authorization code flow, and it cannot: the person is authenticated in
  // authn.js, which knows nothing about OAuth by design, so the client_id is
  // never in scope at this funnel. Those protocols call applications.seen()
  // where their own identifier is accepted; the header of that function says so.
  //
  // Wrapped like the observer below and for the same reason.
  try {
    applications.recordAuthentication({
      client_id: info.client_id || '',
      protocol: protocol,
      sessionId: info.sessionId || '',
      user: identity.key,
      applicationKind: info.applicationKind || '',
      note: info.isClient
        ? 'authenticated as itself (the client IS the identity)'
        : 'a credential was accepted for this application'
    });
  } catch (e) {
    log.error('the application registry threw and was ignored; the ' +
              'authentication itself stands: ' + e.message);
  }
  // The embedded LDAP directory, if it is loaded. Wrapped for the same reason the
  // JWT recorder is: a throw out here would fail the request that was accepting a
  // credential, which is the tail wagging the dog. It is given the NORMALISED
  // identity rather than `presented`, so that the three spellings of one person
  // seed one entry.
  if (userObserver) {
    try {
      userObserver({
        // WHICH OF THE THREE THINGS HAPPENED. The observer used to be offered
        // one kind of event and needed no discriminator; it is now offered
        // three (see noteCertificateIssued() above), and an absent `event` has
        // to keep meaning this one — an older copy of ldap_server.js that does
        // not read the field must go on behaving exactly as it did.
        event: 'authentication',
        key: identity.key, name: identity.name, realm: identity.realm,
        presented: identity.form, protocol: protocol, method: method,
        isClient: record.isClient, sub: info.sub || '',
        // HOW they authenticated, in RFC 8176's vocabulary, passed through
        // untouched for the same reason `certificate` is: this file counts and
        // the directory decides what to do about it. It is what lets an entry
        // record that a second factor was used — a WebAuthn ceremony after a
        // password arrives here as ["pwd","hwk"], and the same ceremony used as
        // the PRIMARY credential arrives as ["hwk"] alone, which is one factor
        // and must not be flagged as two. Most families set neither: a Kerberos
        // AS-REQ and a UsernameToken have no amr to state, and an entry with no
        // factors recorded is the honest answer for them rather than a default.
        amr: info.amr || [], acr: info.acr || '',
        // Passed through untouched, and only the TLS listeners set it: a client
        // certificate's identity IS a DN, so the entry the directory seeds for it
        // is not `uid=<name>` and the facts that go in it — issuer, serial,
        // validity — are on the certificate rather than in anything this file
        // holds. It rides on the observer rather than on a second hook because
        // this is already the funnel, and a second call at the TLS listener would
        // be a second thing to keep right. Nothing here reads it.
        certificate: info.certificate || null,
        // WHOSE identity this one belongs to, where the caller knows and only
        // where it does. It exists for one shape: a DECENTRALIZED IDENTIFIER,
        // which names nobody by itself, arriving from the Credential Endpoint
        // where the access token has already said who the credential is about.
        // The directory folds such a DID onto that person's entry instead of
        // creating a second one named by a digest of it.
        //
        // NORMALISED like `key` is, and through the same function: the caller
        // has whatever the token carried — `alice` or `urn:sts-mock:user:alice`
        // — and passing it through raw would link the DID to a person filed
        // under a name nothing else here uses, which is the split this whole
        // funnel exists to prevent.
        //
        // Empty for every other family, and that is not an omission to fill in
        // later: a name-shaped identity IS the person, so a link from it to
        // itself would say nothing.
        linkedTo: info.linkedTo ? identityKeyOf(info.linkedTo) : '',
        // WHAT A FOREIGN IDENTITY PROVIDER SAID ABOUT THEM, where a federated
        // sign-in is what brought us here. Only `federation/federation_sp.js`
        // sets it, and it is passed through UNTOUCHED for exactly the reason
        // `certificate` above is: this file counts, and the directory decides
        // what to do about it. Nothing here reads it.
        //
        // It is a FIELD ON THIS PAYLOAD rather than a fourth `event` or a sixth
        // slot, and that is rule 3e's test applied rather than skipped. A new
        // event would be wrong on its own terms — this IS an authentication,
        // and filing it as something else would take a federated sign-in off
        // /admin/users, which is precisely where somebody looks for one. A new
        // slot would be an indirection bought for nothing: `certificate` and
        // `linkedTo` already established that a family with an extra fact about
        // the identity puts it here, and this is the third.
        //
        // The attributes inside it are ALREADY MAPPED to this directory's own
        // names — federation_map.js owns that vocabulary — so nothing here or
        // in ldap_server.js has to know what a `urn:oid:` name is.
        federation: info.federation || null
      });
    } catch (e) {
      log.error('the user observer threw and was ignored; the authentication ' +
                'itself is unaffected: ' + e.message);
    }
  }
  log.debug("Leaving recordAuthentication(). " + users.size + " user(s) known.");
  log.debug("Leaving recordAuthentication().");
  return record;
}

// ---------------------------------------------------------------------------
// Custom claims.
//
// FIVE sets since 2026-08-26, one per place a claim can be put, because the
// five are genuinely different vocabularies and a single list would have to
// guess:
//
//   access_token   members of the OAuth 2.0 access token's claim set
//   id_token       members of the OIDC ID Token's claim set
//   userinfo       members of the OIDC UserInfo response (Core 5.3.2)
//   saml2          <saml:Attribute Name="..." NameFormat="...">
//   saml11         <saml:Attribute AttributeName="..." AttributeNamespace="...">
//
// ONE STORE, THREE PAGES. The first two are configured on /admin/claims, the
// third on /admin/userinfo-claims and the last two on /admin/saml-attributes,
// and that split is a fact about the CONSOLE rather than about this file:
// setClaimSet() is the one door onto all five, so a set is changed the same way
// and audited the same way whichever page or API operation reached it.
// JWT_CLAIM_SET_IDS, USERINFO_CLAIM_SET_IDS and SAML_CLAIM_SET_IDS below are
// what each page filters by, derived from `kind`.
//
// **THE THIRD IS THE ONE THAT IS NOT ISSUED.** An access token, an ID Token and
// both assertions are minted once and are then signed documents nothing here
// can reach inside. The UserInfo response is BUILT ON EVERY CALL, so a change
// to that set is visible to a client already holding a token — which is the one
// thing on this page that does not carry the "nothing already issued changes"
// warning, and is why it is worth having separately from the ID Token that
// carries the same person's claims.
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
  'amr', 'acr', 'username', 'authorization_details', 'act',
  // OIDC Core 5.5's claims request, as the authorization endpoint understood
  // it. It rides in the access token for the reason `authorization_details`
  // does — the UserInfo endpoint has to know what the client asked for, and a
  // signed token is the one thing that reaches it — so a settable `claims`
  // would let a web form decide what a request asked for. See oauth2.js.
  'claims'
];

// PER TRUST REALM, AND IT WAS NOT UNTIL 2026-08-28.
//
// `realms.obj(factory)` builds one of these per realm, so `CLAIM_SETS[id]` is
// the ambient realm's table and every one of the readers below is unchanged
// and now realm-correct — the shape CLAUDE.md's realm rule 2 asks for: *a
// store becomes per realm at its declaration and nowhere else*.
//
// **IT WAS A PLAIN OBJECT, AND THAT WAS A LEAK RATHER THAN A SIMPLIFICATION.**
// A custom claim added at `/realm/acme/admin/claims` was added to the ONE
// table, so it was carried by every access token this process minted — the
// DEFAULT realm's included, and every other realm's — while each realm's
// console showed it as though it were that realm's own configuration. The
// other half of the same claim set was already per realm
// (`common/claim_attributes.js` holds the DIRECTORY ATTRIBUTES a set carries),
// so one set disagreed with itself about whether it belonged to a realm.
//
// The LABEL and the KIND are constants and are duplicated into every
// partition, which costs five strings per realm and keeps the table one shape:
// splitting the metadata from the state would have been two tables to keep in
// step, and the thing that goes wrong with two tables is a set in one and not
// the other.
//
// `CLAIM_SET_IDS` below reads `Object.keys()` off this, which the proxy
// answers from the ambient realm's partition — every partition carries the
// same five ids, because they come from this one factory.
function freshClaimSets() {
  return {
    access_token: { label: 'OAuth 2.0 access token', kind: 'jwt', claims: [] },
    id_token: { label: 'OIDC ID Token', kind: 'jwt', claims: [] },
    userinfo: { label: 'OIDC UserInfo response', kind: 'userinfo', claims: [] },
    saml2: { label: 'SAML 2.0 Attribute', kind: 'saml2', claims: [] },
    saml11: { label: 'SAML 1.1 Attribute (WS-Federation)', kind: 'saml11',
              claims: [] }
  };
}

const CLAIM_SETS = realms.obj(freshClaimSets);

// The prose that used to sit on the members of the literal above, kept because
// it is the reasoning for what is in the table rather than for how it is held:
//
//   `userinfo` IS THE FIFTH SET AND IT IS NOT A JWT SET even though its
//   content is JSON and its signed form is a JWT. `kind` answers one question
//   only: WHICH CONSOLE PAGE AND WHICH /admin-api RESOURCE CARRIES THIS SET.
//   The UserInfo response has a page of its own — /admin/userinfo-claims —
//   because the thing it configures is a different artefact from either token:
//   it is fetched rather than issued, it is re-read on every call so a change
//   is visible without a new sign-in, and OIDC Core 5.4 makes a SCOPE decide
//   half of what is in it, which is true of nothing else on this list. Giving
//   it `kind: 'jwt'` would have put it on /admin/claims automatically, which
//   is exactly the accident JWT_CLAIM_SET_IDS being DERIVED is meant to make
//   impossible in the other direction.
//
//   What it DOES share with a JWT set is the RESERVED LIST — see
//   setClaimSet(), which checks `reservedNames()` rather than `kind === 'jwt'`.
//   A UserInfo response carries `sub` (5.3.2, and a client MUST check it), and
//   when the client registered a `userinfo_signed_response_alg` the whole
//   thing is a JWT carrying `iss` and `aud` as well. Every name on that list is
//   load-bearing in at least one of the two shapes, so the list applies whole.
const CLAIM_SET_IDS = Object.keys(CLAIM_SETS);

// THE FOUR SETS ARE ONE STORE AND TWO CONSOLE PAGES, and these two lists are
// what says which page a set is on: /admin/claims configures the two JWT sets
// and /admin/saml-attributes the two SAML ones (2026-08-24; before that, one
// page carried all four and a reader configuring an assertion had to read past
// two token sets to reach it).
//
// DERIVED FROM `kind` rather than typed out, for the reason NAV is derived from
// SECTIONS in admin-ui/admin.js: a set added to CLAIM_SETS and forgotten in a
// hand-written list would be a set with a store, an issuance path and no page
// to configure it on, and nothing would fail. `jwt` is the OAuth/OIDC half;
// everything else is an assertion. The STORE did not split and must not — one
// object, one setClaimSet(), one audit row per change, however many pages reach
// it.
const JWT_CLAIM_SET_IDS = CLAIM_SET_IDS.filter(function (id) {
  return CLAIM_SETS[id].kind === 'jwt';
});
// THE SAML LIST IS NOW A POSITIVE TEST AND IT HAD TO BECOME ONE. It was
// `kind !== 'jwt'` while there were exactly two kinds, and the day a third
// arrived that spelling would have swept the UserInfo set onto
// /admin/saml-attributes — a set with a page, a store and an issuance path,
// configured on a page about assertions, and nothing anywhere failing. A list
// derived by exclusion is only derived from what exists at the moment it is
// written; this one is derived from what the sets ARE.
const SAML_CLAIM_SET_IDS = CLAIM_SET_IDS.filter(function (id) {
  return CLAIM_SETS[id].kind === 'saml2' || CLAIM_SETS[id].kind === 'saml11';
});
const USERINFO_CLAIM_SET_IDS = CLAIM_SET_IDS.filter(function (id) {
  return CLAIM_SETS[id].kind === 'userinfo';
});

// The default namespace a SAML 1.1 attribute gets when the admin does not name
// one. It is the claim namespace every WS-Federation relying party already reads,
// which makes an attribute configured with just a name arrive somewhere useful
// instead of in a namespace nothing looks in.
const DEFAULT_SAML11_NAMESPACE = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims';

// ---------------------------------------------------------------------------
// THE OTHER HALF OF A CLAIM SET, AND WHY IT ARRIVES THROUGH A SLOT.
//
// The claim-set pages offer two things per set: the typed claims below, and a
// SELECTION of LDAP attribute types whose values are read off the person's entry
// under ou=users. The selection and the reading live in claim_attributes.js,
// which cannot be required from here — it requires vc_claims.js, vc_claims.js
// requires THIS file, and the loop would hand back a half-initialised module
// whose exports are undefined. That is the cycle rule 2 of the architecture
// exists for, and the symptom arrives later as something that is not a function.
//
// So the direction is inverted the same way setUserObserver() below and
// helpers.js's setJwtRecorder() are: this file offers the slot and
// claim_attributes.js fills it at ITS require time. What that buys is the whole
// point of doing it this way — NO ISSUANCE SITE CHANGED. oauth2.js's two calls
// to jwtClaims() and the two assertion builders' calls to samlAttributes() are
// the lines they always were, and the attribute claims arrive through them. Four
// edited call sites would have been four that drift and a fifth added later that
// nobody remembers.
//
// It stays null in a process that never loaded that module, and every set is
// then its typed claims alone — a smaller service, not a broken one.
// ---------------------------------------------------------------------------
let attributeResolver = null;

function setAttributeResolver(hooks) {
  attributeResolver = hooks || null;
  log.debug("A claim-attribute resolver was installed; the four claim sets can " +
            "now carry LDAP attributes read from the directory.");
}

// Both wrapped, and for the reason the user observer is wrapped: a directory
// this service consults must never be able to fail the issuance it was consulted
// during. A token missing a configured claim is a bug somebody can see and
// diagnose; a token endpoint returning 500 because an entry was mid-write is a
// bug that looks like the token endpoint.
//
// Neither has an entering/leaving pair, deliberately: each runs once per token
// inside jwtClaims() or samlAttributes(), whose own pair already brackets it,
// and claim_attributes.js logs what it did on the other side of the call. Three
// pairs around one call would be most of what the log said about issuing a
// token.
function resolvedJwtClaims(id, context) {
  if (!attributeResolver || typeof attributeResolver.jwtClaims !== 'function') {
    return {};
  }
  try {
    return attributeResolver.jwtClaims(id, context) || {};
  } catch (e) {
    log.error('the claim-attribute resolver threw and was ignored; the token is ' +
              'issued without its attribute claims: ' + e.message);
    return {};
  }
}

function resolvedSamlAttributes(id, context) {
  if (!attributeResolver || typeof attributeResolver.samlAttributes !== 'function') {
    return [];
  }
  try {
    return attributeResolver.samlAttributes(id, context) || [];
  } catch (e) {
    log.error('the claim-attribute resolver threw and was ignored; the assertion ' +
              'is issued without its attribute claims: ' + e.message);
    return [];
  }
}

// ---------------------------------------------------------------------------
// A SECOND SLOT, AND WHY IT IS NOT A FIFTH HOOK ADDED BY ANALOGY.
//
// CLAUDE.md rule 3e says the hooks on this file are four different problems
// rather than a pattern, and that a fifth must not be added because the fourth
// exists. The test it gives is the one that matters — a slot is what you reach
// for when a require would CLOSE A CYCLE or MOVE A ROUTE — and this one fails
// both ways round, which is why it is here:
//
//   * group_claims.js requires THIS file (for the four set ids, the reserved
//     names and identityKeyOf()), so a require in the other direction closes a
//     loop and hands back a half-initialised module.
//   * what it needs is the DIRECTORY's group membership, and only
//     ldap_server.js can answer that — the last module server.js requires, so
//     any require reaching it drags every /ldap route to the front of the
//     express router that /admin/sts-metadata is built by walking.
//
// What it buys is the same thing the attribute resolver above buys: NO
// ISSUANCE SITE CHANGED. oauth2.js's calls to jwtClaims() and the two assertion
// builders' calls to samlAttributes() are the lines they always were.
//
// It stays null in a process that never loaded that module, and every set is
// then its typed claims and its directory attributes alone — a smaller service,
// not a broken one.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE ROLES CLAIM, AND WHY IT IS A PLAIN REQUIRE WHERE THE GROUPS CLAIM NEEDED
// A SLOT.
//
// CLAUDE.md rule 3e says the hooks on this file are four different problems
// rather than a pattern, that a fifth must not be added because the fourth
// exists, and that the group resolver is the one to check a new proposal
// against — it was added only after showing a require failed BOTH ways round.
//
// THE ROLES CLAIM FAILS NEITHER, so it does not get a slot:
//
//   * `common/roles.js` is a LEAF. It requires `helpers` and `config` and
//     nothing else in this repository, so requiring it here cannot close a
//     cycle — which is the whole of why `group_claims.js` could not be
//     required this way round: that file requires THIS one.
//   * It registers no route, so requiring it moves nothing in the router.
//
// The DIRECTORY still arrives at that module through a slot of its own that
// `ldap_server.js` fills, for the reason it always does — only that module can
// answer what is in `ou=roles`, and it is the last thing `server.js` requires.
//
// So the rule is honoured by doing the ordinary thing where the ordinary thing
// works, which is what the rule actually asks for. `audit.js` is required here
// the same way and for the same reason.
const roles = require('./roles');

let groupResolver = null;

function setGroupResolver(hooks) {
  groupResolver = hooks || null;
  log.debug("A group-claim resolver was installed; tokens and assertions can " +
            "now carry the directory groups their subject is a member of.");
}

// Wrapped for the reason the two above are wrapped: a directory this service
// consults must never be able to fail the issuance it was consulted during.
function resolvedGroupClaims(id, context) {
  if (!groupResolver || typeof groupResolver.jwtClaims !== 'function') {
    return {};
  }
  try {
    return groupResolver.jwtClaims(id, context) || {};
  } catch (e) {
    log.error('the group-claim resolver threw and was ignored; the token is ' +
              'issued without its groups claim: ' + e.message);
    return {};
  }
}

// The roles claim, wrapped for the reason every other directory read during an
// issuance is wrapped: a register this service consults must never be able to
// fail the issuance it was consulted during. `roles.js` already swallows its
// own store errors; this is the second net, and it costs nothing.
//
// **WHO THE CLAIM IS ABOUT is the subject of the token**, and where there is no
// person — a client_credentials grant — that is the CLIENT, which is exactly
// the case the role register exists to be able to answer. `authenticated` is
// true here because a token is being minted: whatever door this came through
// let them through it.
function resolvedRoleClaims(context) {
  const ctx = context || {};
  const username = String(ctx.username || ctx.subject || '');
  try {
    return roles.claimFor(
      username
        ? { kind: 'user', name: username, authenticated: true }
        : { kind: 'application',
            name: String(ctx.client_id || ''), authenticated: true }) || {};
  } catch (e) {
    log.error('the role register threw and was ignored; the token is issued ' +
              'without its roles claim: ' + e.message);
    return {};
  }
}

// The SAML half. ONE <Attribute> with several <AttributeValue> children rather
// than one element per role — the same rule `group_claims.js` states beside its
// own emitter, and the same defect it prevents: several elements with one Name
// is a relying party reading the first and silently seeing one role where the
// person holds four.
function resolvedRoleAttributes(id, context) {
  const claim = resolvedRoleClaims(context);
  const names = Object.keys(claim);
  if (!names.length) {
    return [];
  }
  return names.map(function (name) {
    const attribute = { name: name, values: claim[name] };
    if (id === 'saml11') {
      attribute.namespace = DEFAULT_SAML11_NAMESPACE;
    }
    return attribute;
  });
}

function resolvedGroupAttributes(id, context) {
  if (!groupResolver || typeof groupResolver.samlAttributes !== 'function') {
    return [];
  }
  try {
    return groupResolver.samlAttributes(id, context) || [];
  } catch (e) {
    log.error('the group-claim resolver threw and was ignored; the assertion ' +
              'is issued without its groups claim: ' + e.message);
    return [];
  }
}

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
  log.debug("Entering typedValue().");
  const trimmed = String(text == null ? '' : text).trim();
  if (!/^[{\[]|^(true|false|null)$|^-?\d+(\.\d+)?([eE][-+]?\d+)?$/.test(trimmed)) {
    log.debug("Leaving typedValue().");
    return text;
  }
  try {
    log.debug("Leaving typedValue().");
    return JSON.parse(trimmed);
  } catch (e) {
    // It looked like JSON and is not — a half-typed array, most likely. The raw
    // text is what the admin typed and is what the claim gets, rather than an
    // error at issuance time in a place nobody is watching.
    log.debug("A claim value looked like JSON and did not parse; it is used as text: " + trimmed);
    log.debug("Leaving typedValue().");
    return text;
  }
  log.debug("Leaving typedValue().");
}

// ---------------------------------------------------------------------------
// The audit row for a typed-claim change, and why it is here rather than in
// admin.js's four action branches.
//
// setClaimSet() is the single funnel all four of them pass through — add,
// remove, clear and replace all end here — so one call is one place, and four
// calls at the branches would be four that drift and a fifth branch added later
// with none. The same rule the authentication funnel follows, for the same
// reason.
//
// It shares the `claims.change` action with the attribute half in
// claim_attributes.js, because they are the same fact about the same page: this
// set changed. What differs is the detail, and `how` is what says which half.
//
// NO CLAIM VALUE IS EVER RECORDED — only names. A value here is whatever
// somebody typed into a web form on a service where people paste JWTs into web
// forms, and audit.js's header states that the log carries no credential. That
// sentence stays true because every call site keeps it, not because something
// central strips it.
// ---------------------------------------------------------------------------
function recordClaimSetChange(id, set, added, removed, count, ok, errors) {
  log.debug("Entering recordClaimSetChange(). id=" + id + ", ok=" + ok);
  // No guard: audit.audit() is wrapped over there and cannot throw. A guard
  // would suggest to the next reader that this call is allowed to fail a
  // configuration change, and it is not.
  audit.audit({
    action: 'claims.change',
    outcome: ok ? 'success' : 'refused',
    actor: '',
    target: id,
    channel: 'http',
    summary: ok
      ? 'The ' + set.label + ' set now carries ' + count + ' typed claim(s)' +
        (added.length ? '; added ' + added.join(', ') : '') +
        (removed.length ? '; removed ' + removed.join(', ') : '') + '.'
      : 'A change to the ' + set.label + ' set was refused: ' + (errors || []).join(' '),
    detail: {
      set: id,
      how: 'claims',
      added: added.join(', '),
      removed: removed.join(', '),
      claimCount: count
    }
  });
  log.debug("Leaving recordClaimSetChange().");
}

// WHICH NAMES A SET REFUSES, asked of the SET rather than tested against one
// spelling of `kind`.
//
// It was `set.kind === 'jwt'` inline until the UserInfo set arrived, and that
// was a check no reader could add a fourth kind to correctly: the answer is not
// "is this a JWT" but "does this artefact have names this service sets itself".
// A UserInfo response does — `sub` is required by OIDC Core 5.3.2 and a client
// MUST verify it matches the ID Token's, and the signed form of the same
// response is a JWT carrying `iss`, `aud` and `exp` — so it refuses the same
// list. A SAML assertion does NOT: `exp` and `scope` collide with nothing in
// an <Attribute>, and refusing them there would tell a caller their call will
// fail when it will succeed.
function reservedNames(set) {
  return (set.kind === 'jwt' || set.kind === 'userinfo') ? RESERVED_JWT_CLAIMS : [];
}

// Validate and install a whole set at once. Returns the errors rather than
// throwing, because the caller is a form handler that has to redisplay them.
function setClaimSet(id, entries) {
  log.debug("Entering setClaimSet(). id=" + id + ", " + (entries || []).length + " entry/entries.");
  const set = CLAIM_SETS[id];
  if (!set) {
    log.debug("Leaving setClaimSet(). No such claim set.");
    return { ok: false, errors: ['There is no claim set called "' + id + '". The ' +
                                 CLAIM_SET_IDS.length + ' are: ' + CLAIM_SET_IDS.join(', ') + '.'] };
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
    if (reservedNames(set).indexOf(name) >= 0) {
      errors.push('"' + name + '" is a claim this service sets itself and cannot be overridden. ' +
                  'Custom claims are added to a ' + (set.kind === 'userinfo' ? 'UserInfo response' : 'token') +
                  ', never substituted into it.');
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
    recordClaimSetChange(id, set, [], [], set.claims.length, false, errors);
    log.debug("Leaving setClaimSet(). Refused with " + errors.length + " error(s); nothing changed.");
    return { ok: false, errors: errors };
  }
  const beforeNames = set.claims.map(function (claim) { return claim.name; });
  const afterNames = cleaned.map(function (claim) { return claim.name; });
  const added = afterNames.filter(function (name) { return beforeNames.indexOf(name) < 0; });
  const removed = beforeNames.filter(function (name) { return afterNames.indexOf(name) < 0; });
  set.claims = cleaned;
  log.info('admin: the ' + set.label + ' claim set now has ' + cleaned.length + ' custom claim(s): ' +
           (afterNames.join(', ') || '(none)'));
  recordClaimSetChange(id, set, added, removed, cleaned.length, true, []);
  log.debug("Leaving setClaimSet(). Installed " + cleaned.length + " claim(s).");
  return { ok: true, errors: [], claims: cleaned };
}

function claimSet(id) {
  const set = CLAIM_SETS[id];
  return set ? set.claims.slice() : [];
}

// ---------------------------------------------------------------------------
// THE FEDERATION RELEASE POLICY, APPLIED TO AN OBJECT OF CLAIMS.
//
// Lifted out of jwtClaims() on 2026-08-26 rather than written a second time,
// and the reason is the one that lifts anything out of anything here: it now
// has a SECOND caller that is not a claim set. OIDC Core section 5.5's claims
// request reaches the UserInfo endpoint without passing through jwtClaims() at
// all — it is layer 3 of that response and the configured set is layer 1 — so a
// partner with a release list naming `email` could otherwise have ASKED for
// `birthdate` and been given it, which is precisely the hole a release list
// exists to close. The filter belongs to the fact "this audience may see these
// names", not to the mechanism that produced them.
//
// It REMOVES ONLY, and it cannot reach anything not in the object it is handed:
// not `sub`, not `iss`, not `exp`, none of which is an attribute about a person
// and every one of which is what makes the artefact verifiable at all.
// `federation/CLAUDE.md` argues that boundary.
//
// NO POLICY IS NOT AN EMPTY POLICY. `releaseFilterFor()` answers null for a
// partner with no release list, and null changes nothing.
//
// It stays HERE rather than moving to a library of its own because this module
// already requires `federation.js` and three of the four modules allowed to do
// so are named in rule 3o; a fifth requirer for one filter would be a require
// added by analogy, which is exactly what that rule refuses.
// ---------------------------------------------------------------------------
function applyClaimRelease(out, context, what) {
  const release = federation.releaseFilterFor(context);
  if (!release) {
    return out;
  }
  const before = Object.keys(out);
  before.forEach(function (name) {
    if (!release.names.has(name)) delete out[name];
  });
  const kept = Object.keys(out);
  if (kept.length !== before.length) {
    log.info('admin: the federation relationship "' + release.id + '" releases ' +
             kept.length + ' of ' + before.length + ' ' + (what || 'claim(s)') +
             ' to this audience; ' +
             before.filter(function (n) { return !release.names.has(n); }).join(', ') +
             ' withheld. The protocol\'s own claims are untouched.');
  }
  return out;
}

// The custom claims for a JWT, expanded against this token's context and typed.
// Returns a plain object ready to be merged into a payload — and the merge at the
// call site is written so the protocol's own claims win, which is belt as well as
// the braces of the reserved list.
function jwtClaims(id, context) {
  log.debug("Entering jwtClaims(). id=" + id);
  // The directory attributes FIRST, so that a claim somebody typed by hand wins
  // over an attribute claim of the same name. Somebody who typed
  // `email = nobody@example.org` on the same page that has `mail` ticked has said
  // something specific, and the specific thing beats the general one. The rule is
  // stated on the page and in the API's reply rather than left to be discovered:
  // the two halves are one screen apart, and a silent precedence rule is the kind
  // of thing that gets diagnosed as a bug in the directory.
  //
  // Neither half can reach a reserved name. The typed ones are refused at
  // configuration time by setClaimSet() below, and the attribute ones cannot
  // collide by construction — no OIDC claim in that catalogue is a name this
  // service sets. The merge at the CALL SITE is the third defence: oauth2.js
  // assigns the protocol's own payload over this object, so a collision that
  // somehow got past both loses there.
  //
  // THREE LAYERS, and the groups claim is the bottom one. A name somebody typed
  // wins over an attribute they ticked, and both win over the groups claim,
  // which is the only one of the three nobody named on a page — it comes from a
  // setting and a directory. So somebody who typed `groups = none` or ticked an
  // attribute called `groups` has said something specific about THIS service,
  // and the specific thing beats the general one. Written as an assignment
  // ORDER here because a JWT payload is an object; samlAttributes() below has
  // to write the same rule as a filter, for the reason stated there.
  //
  // FOUR LAYERS NOW, and the roles claim is UNDER the groups claim rather than
  // beside it. Both come from a setting and a directory rather than from
  // anything somebody named on a page, so the precedence between the two only
  // matters when they are configured to the SAME name — which is a real
  // configuration (`groups.claimName` = `roles` is one of the spellings its own
  // row recommends trying) and therefore needs an answer rather than an
  // accident. The answer is that GROUPS WINS, because that claim has been here
  // longer and a client already parsing it must not have its meaning changed by
  // a feature arriving underneath it.
  const out = resolvedRoleClaims(context);
  Object.assign(out, resolvedGroupClaims(id, context));
  Object.assign(out, resolvedJwtClaims(id, context));
  claimSet(id).forEach(function (claim) {
    out[claim.name] = typedValue(expandValue(claim.value, context));
  });
  // ---------------------------------------------------------------------
  // AND THE FOURTH LAYER, WHICH ONLY EVER REMOVES: the federation release
  // policy for this audience, if there is one.
  //
  // It is LAST because it is a filter rather than a source — the three layers
  // above decide what this service would put in a token for anybody, and this
  // decides which of them a particular federation partner is allowed to see.
  // Applied before the three would mean the precedence rules ran over a list
  // that had already been cut, so a typed claim could lose to an attribute
  // claim purely because the typed one was filtered.
  //
  // WHAT IT CANNOT TOUCH is anything not in `out`: not `sub`, not `iss`, not
  // `exp`, none of which is an attribute about a person and every one of which
  // is what makes the token verifiable at all. `federation/CLAUDE.md` argues
  // that boundary rather than leaving it to be discovered here.
  //
  // NO POLICY IS NOT AN EMPTY POLICY. `releaseFilterFor()` answers null for a
  // partner with no release list, and null changes nothing — see its header,
  // where the difference is the whole point.
  // ---------------------------------------------------------------------
  applyClaimRelease(out, context, 'custom claim(s)');
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
  const typed = claimSet(id).map(function (claim) {
    const attribute = { name: claim.name, value: expandValue(claim.value, context) };
    if (id === 'saml2' && claim.nameFormat) attribute.nameFormat = claim.nameFormat;
    if (id === 'saml11') attribute.namespace = claim.namespace || DEFAULT_SAML11_NAMESPACE;
    return attribute;
  });
  // The same precedence jwtClaims() applies, but it has to be written as a FILTER
  // rather than as an assignment order: an assertion is a list of <Attribute>
  // elements and not an object, so a duplicate name would not overwrite anything
  // — it would produce two elements with one name, and a relying party reading
  // the first would silently see whichever the builder happened to emit first.
  const names = new Set(typed.map(function (attribute) { return attribute.name; }));
  const fromDirectory = resolvedSamlAttributes(id, context).filter(function (attribute) {
    return !names.has(attribute.name);
  });
  // The third layer, filtered against BOTH of the two above it — the same
  // precedence jwtClaims() writes as an assignment order, and it has to be a
  // filter here for the same reason the second layer does: two <Attribute>
  // elements with one Name is not an overwrite, it is a relying party reading
  // whichever the builder happened to emit first.
  fromDirectory.forEach(function (attribute) { names.add(attribute.name); });
  const fromGroups = resolvedGroupAttributes(id, context).filter(function (attribute) {
    return !names.has(attribute.name);
  });
  // The FIFTH layer and the lowest, filtered against all three above it, and
  // beneath the groups claim for the reason jwtClaims() gives: the two are the
  // only layers here nobody named on a page, they can be configured to the same
  // name, and the older of the two has to keep its meaning.
  fromGroups.forEach(function (attribute) { names.add(attribute.name); });
  const fromRoles = resolvedRoleAttributes(id, context).filter(function (attribute) {
    return !names.has(attribute.name);
  });
  let out = fromRoles.concat(fromGroups, fromDirectory, typed);
  // The same fourth layer jwtClaims() applies, and for the same reason it is
  // last: this decides which of the attributes this service would assert to
  // ANYBODY a particular federation partner is allowed to see. It removes only,
  // and it cannot reach the NameID, the Issuer, the Conditions or the
  // signature — none of which is in this list.
  const release = federation.releaseFilterFor(context);
  if (release) {
    const before = out.length;
    out = out.filter(function (attribute) { return release.names.has(attribute.name); });
    if (out.length !== before) {
      log.info('admin: the federation relationship "' + release.id + '" releases ' +
               out.length + ' of ' + before + ' custom attribute(s) to this audience. ' +
               'The assertion\'s own elements are untouched.');
    }
  }
  log.debug("Leaving samlAttributes(). " + out.length + " attribute(s), " +
            fromDirectory.length + " of them from the directory and " +
            fromGroups.length + " of them the groups claim.");
  return out;
}

// ---------------------------------------------------------------------------
// Reading the state back.
// ---------------------------------------------------------------------------
// WHAT A TOKEN'S STATE IS, AGAINST THE SAME CLOCK THE ENDPOINTS USE.
//
// `oauth2.clockSkewS` is passed to jwt.verify() as `clockTolerance` at every
// place this service reads back a token it signed — introspection, UserInfo,
// the refresh grant, token exchange, the DPoP-bound access token check — so it
// is applied here too, and for a reason worth stating rather than assuming.
// Without it, a token inside the allowance is REPORTED expired here and
// ACCEPTED there. That is not a cosmetic disagreement: this page is where
// somebody goes to find out why their client was refused, and a state column
// that contradicts the endpoint sends them to debug the wrong half. The
// console does not decide what expired means — `oauth2.js` does, and this
// reads the same setting.
//
// The skew widens the window in both directions, which is what a tolerance is:
// a token is expired only once it is past `exp` PLUS the allowance, and not yet
// valid only while it is before `nbf` MINUS it.
function tokenStateOf(record, nowMs) {
  if (record.revoked || (record.jti && revokedJtis().has(record.jti))) return 'revoked';
  const skewMs = config.value('oauth2.clockSkewS') * 1000;
  if (record.exp && record.exp * 1000 + skewMs <= nowMs) return 'expired';
  if (record.nbf && record.nbf * 1000 - skewMs > nowMs) return 'not yet valid';
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
//
// IT DELIBERATELY DOES NOT APPLY `oauth2.clockSkewS`, and that is not the
// disagreement the paragraph above warns about. That setting exists so this
// page agrees with the endpoint that will read the token back, and there is no
// such endpoint for a SAML assertion or a Kerberos ticket: nothing here reads
// one of those back at all, so there is nothing to agree with, and an OAuth
// allowance silently stretching a ticket's lifetime on a page would be this
// service inventing a tolerance that its KDC (which has `krb5.clockSkew`, a
// different setting with a different owner) never applied.
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
          'the Kerberos-protected service and by SPNEGO' },
  { family: 'svid', label: 'SPIFFE SVIDs', kinds: ['SVID (X.509)', 'SVID (JWT)'],
    what: 'issued over the SPIFFE Workload API and by the SPIRE Server API\'s ' +
          'SVID service. NONE OF THEM IS REVOCABLE from /admin/tokens, unlike ' +
          'every kind above it: SPIFFE has no revocation — the answer is a ' +
          'short lifetime and rotation — so a button there would be a lie of ' +
          'exactly the kind this console avoids' }
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
// ONE ROW OF THAT LIST, BY THE IDENTIFIER THE PROTOCOL GAVE IT.
//
// The lookup `credential_graph.js` needs, and the reason it is here rather than
// a `filter()` over there: `issuedList()`'s row shape is this file's — the
// merged `family`, `identifier` and `expiresAtMs` members exist because the
// tokens page needed one table over four registers — and a caller doing its own
// walk would be a second place that decides a token's identifier is its `jti`
// and an artifact's is its `id`.
//
// It walks rather than indexing, and that is a deliberate non-optimisation: both
// stores are capped (`MAX_TOKENS`, `MAX_ARTIFACTS`) and an index would be a
// second copy of a key that is already the only thing joining these records to
// the delegation register. Null for an identifier neither store holds, which is
// the ORDINARY answer for anything old enough to have been dropped to a cap —
// the caller says so rather than treating it as a mistake.
// ---------------------------------------------------------------------------
function issuedById(identifier) {
  log.debug("Entering issuedById(). identifier=" + identifier);
  const wanted = String(identifier == null ? '' : identifier).trim();
  if (!wanted) {
    log.debug("Leaving issuedById(). Nothing was asked for.");
    return null;
  }
  const found = issuedList().filter(function (row) {
    return String(row.identifier || '') === wanted;
  });
  log.debug("Leaving issuedById(). " + found.length + " row(s) hold it.");
  return found.length ? found[0] : null;
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
    // FALSE for a record that got here WITHOUT a sign-in — restored from a
    // persistent store, or created by hand — and true for every record that
    // got here the way records always got here. See noteKnownIdentity() above:
    // such a person EXISTS and has not signed in, and one flag saying both
    // would make `authenticatedHere` count people rather than sign-ins.
    row.authenticated = !record.knownBy;
    row.knownBy = record.knownBy || 'authentication';
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
        // `firstAt` as well as `lastAt` since 2026-08-26: `user_graph.js` puts
        // the families of one person in the order they STARTED, so that the
        // sign-in everything else rests on is read before the exchanges that
        // quote it, and `lastAt` orders them by whichever was busiest most
        // recently instead.
        return { protocol: family.protocol, count: family.count,
                 firstAt: family.firstAt, lastAt: family.lastAt,
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
    calls: { total: nums.callTotal, paths: callRows.length, byStatusClass: statusTotals,
             pathsCollapsed: nums.callPathsDropped, rows: callRows },
    tokens: { held: tokens.size, forgotten: nums.tokensForgotten, cap: MAX_TOKENS,
              revoked: revokedJtis().size, byKind: Array.from(byKind.values()) },
    artifacts: { held: artifacts.length, forgotten: nums.artifactsForgotten, cap: MAX_ARTIFACTS,
                 byKind: Array.from(artifactKinds.values()) },
    // Counted, not listed: the whole list is what /admin/users is for, and repeating
    // it inside every metrics reply would make the two disagree the first time one
    // of them changed.
    users: { known: knownUsers.length, cap: MAX_USERS, forgotten: nums.usersForgotten,
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
  JWT_CLAIM_SET_IDS: JWT_CLAIM_SET_IDS,
  SAML_CLAIM_SET_IDS: SAML_CLAIM_SET_IDS,
  USERINFO_CLAIM_SET_IDS: USERINFO_CLAIM_SET_IDS,
  reservedNames: reservedNames,
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
  noteKnownIdentity: noteKnownIdentity,
  identityOf: identityOf,
  identityKeyOf: identityKeyOf,
  userRows: userRows,
  userDetail: userDetail,
  sessionIdOfJti: sessionIdOfJti,
  recordAssertion: recordAssertion,
  recordTicket: recordTicket,
  recordCredential: recordCredential,
  recordSvid: recordSvid,
  recordCredentialStatus: recordCredentialStatus,
  SCIM_OPERATIONS: SCIM_OPERATIONS,
  SCIM_RESOURCE_TYPES: SCIM_RESOURCE_TYPES,
  recordScim: recordScim,
  scimSnapshot: scimSnapshot,
  revoke: revoke,
  restore: restore,
  revokeWhere: revokeWhere,
  isRevoked: isRevoked,
  revokedCount: revokedCount,
  claimSet: claimSet,
  setClaimSet: setClaimSet,
  // Filled by claim_attributes.js at its require time; see the note above it.
  // The inversion is what keeps the four issuance sites unchanged.
  setAttributeResolver: setAttributeResolver,
  setGroupResolver: setGroupResolver,
  jwtClaims: jwtClaims,
  samlAttributes: samlAttributes,
  // The release filter on its own, for the ONE caller that produces claims
  // without going through a claim set — the UserInfo endpoint's answer to a
  // section 5.5 claims request. See the header above it for why that caller
  // must not be exempt.
  applyClaimRelease: applyClaimRelease,
  expandValue: expandValue,
  tokenList: tokenList,
  artifactList: artifactList,
  issuedList: issuedList,
  issuedById: issuedById,
  snapshot: snapshot
};
