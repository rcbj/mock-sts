'use strict';
//
// File: audit.js
//
// ---------------------------------------------------------------------------
// THE AUDIT LOG: what happened here, in the order it happened, as a list of
// discrete events rather than as counters.
//
// admin_stats.js already answers "how much" — 412 calls, 63 tokens, 9 users.
// This answers "what, when, and to whom", which is a different question and the
// one nobody could ask before: the counters cannot tell you that somebody
// deleted `uid=bob,ou=users` at 14:02, that the delete came in over LDAPS, and
// that the same minute a token was revoked from the console. Those are three
// rows here and three numbers that each went up by one over there.
//
// It is a LIBRARY, like admin_stats.js and dpop.js — it registers no route, so
// its position in the require order does not matter and it cannot be the reason
// a route is missing. `admin.js` renders it at /admin/audit and `admin_api.js`
// serves it at /admin-api/audit; this file holds the events and none of the
// HTML.
//
// **It requires helpers.js and config.js and NOTHING ELSE in this repository,
// and that is load-bearing rather than tidy.** It is called from app.js's call
// log, from admin_stats.js's recordAuthentication(), from authn.js's session
// store and from every LDAP handler — which is most of the service. Anything
// this file required, all of those would require transitively, and the cycles
// rule 2 of the architecture exists to avoid would be one careless import away.
// In particular it must NOT require admin_stats.js: that module requires THIS
// one, so the identity normalisation this file would like is passed IN by the
// one caller that has already done it.
//
// ---------------------------------------------------------------------------
// FIVE THINGS ARE WORTH KNOWING BEFORE READING FURTHER.
//
// **It is in memory and dies with the process**, like the counters, the
// sessions and the signing key. An audit log that outlived the key that signed
// the tokens it describes would be worse than none, and there is no compliance
// story here to serve: this service authenticates nobody. The page says so
// rather than leaving a reader to discover it at the next restart.
//
// **No credential is ever recorded.** Not a password, not a bearer token, not
// an assertion, not a request or response body. An event carries the FACTS of
// what happened — who, what, where, the outcome — and the identifiers already
// safe to show (a `jti`, a DN, a session id prefix). The temptation to record
// the body of an admin POST so the page can say what changed is real and is
// refused here: those bodies carry pasted JWTs. The one thing read out of a
// body is the `action` field, by name, capped in length — see actionOf().
//
// **Recording never fails an operation.** Every entry point is wrapped, and a
// throw out of here is logged and swallowed. The same rule signJwt()'s recorder
// and the directory's user observer follow, and for the same reason: the tail
// must not wag the dog. An audit log that could refuse a bind would be a worse
// bug than a missing row.
//
// **ONE ACT PRODUCES SEVERAL EVENTS, on purpose.** Signing in at
// /authn/login writes three: the HTTP call (`protocol.call`), the credential
// being accepted (`authentication`), and the session that came out of it
// (`session.start`). They are not duplicates — they are three different facts
// at three different layers, and collapsing them would mean choosing which of
// the three questions this page can answer. The page says this where somebody
// reading a list of three rows for one sign-in will see it.
//
// **THIS LOG OBSERVES ITSELF.** Fetching /admin/audit is admin console access,
// so it records an `admin.view` event, so the list is one row longer than it
// was when you asked. That is not a defect to engineer around: suppressing it
// would mean an audit log with a blind spot exactly where somebody reading the
// audit log stands. It is stated on the page instead, and `?category=` is how
// you read past it.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');
const config = require('./config');

// ---------------------------------------------------------------------------
// The cap, read WHERE IT IS USED rather than captured at require time.
//
// `audit.maxEvents` is a runtime setting — /admin/config and POST
// /admin-api/config/set can change it while the service runs — and a
// module-level `const` is the one thing those two cannot reach. Reading it per
// call is what makes the console's own control work; a captured copy fails in
// the direction that looks like the console is broken.
// ---------------------------------------------------------------------------
function maxEvents() {
  return config.value('audit.maxEvents');
}

// Whether an ordinary protocol endpoint call is worth a row. On by default,
// because "all protocol endpoint interaction" is what this log was asked for —
// but it is far and away the noisiest source (every JWKS poll, every metadata
// fetch), and somebody watching the directory or the console wants to be able
// to turn the firehose off without losing the rest. Read here, per call, for
// the same reason the cap is.
function protocolCallsRecorded() {
  return config.value('audit.protocolCalls');
}

// ---------------------------------------------------------------------------
// THE VOCABULARY.
//
// Two tables rather than two hand-written lists in the console's <select>
// elements: the page and the API both build their filters from these, so a
// category or an action cannot exist in the log and be unfilterable, nor be
// offered as a filter and never occur.
//
// The categories are the six layers this service has anything to say about.
// They are deliberately not "protocols" — a sign-in over WS-Federation and one
// over OIDC are both `authentication`, because what an auditor asks is "who got
// in", not "through which endpoint" (that is on the row).
// ---------------------------------------------------------------------------
const CATEGORIES = [
  { category: 'authentication', label: 'Authentication',
    what: 'A credential was ACCEPTED, in any of the fourteen protocol ' +
          'families here. Recorded at the single funnel every one of them ' +
          'already passes through, so this is one place and not fourteen.' },
  { category: 'session', label: 'Sessions',
    what: 'A browser sign-on session was created or ended. Shared between ' +
          'OAuth 2.0 / OIDC and WS-Federation, so a WS-Federation sign-out ' +
          'and an /oauth2/logout produce the same row.' },
  { category: 'directory', label: 'Directory',
    what: 'The embedded LDAP directory: entries created, deleted, updated, ' +
          'renamed and queried, over plain 389 and over LDAPS 636 alike.' },
  { category: 'admin', label: 'Admin console',
    what: 'Every page of /admin that was viewed and every form that was ' +
          'posted. Includes the request that drew the page you are reading.' },
  { category: 'api', label: 'Management API',
    what: 'Every call into /admin-api, read and write alike.' },
  { category: 'application', label: 'Applications',
    what: 'An application — an OAuth client, an OIDC relying party, a SAML ' +
          'service provider, a WS-Federation application, a WS-Trust relying ' +
          'party, a Kerberos service — was seen for the first time, or ' +
          'recorded something new. The counterpart of the authentication row ' +
          'above: that one says WHO, this one says WHAT THEY WERE SIGNING IN ' +
          'TO. One act commonly writes both.' },
  { category: 'protocol', label: 'Protocol endpoints',
    what: 'Every other HTTP endpoint: the token endpoint, the KDC proxy, the ' +
          'credential endpoint, the metadata documents, all of it.' },
  // SPIFFE is its own category rather than rows under `application` or
  // `authentication`, and the reason is that a SPIFFE row answers a question
  // neither of those does. An SVID is not an authentication — nothing
  // authenticated to get one — and a registration entry is not an application
  // sighting, it is CONFIGURATION deciding what will be issued later. The two
  // gRPC surfaces also arrive on a channel nothing else here uses, so folding
  // them into `protocol` would put them in a filter that means "HTTP endpoint"
  // everywhere else.
  { category: 'spiffe', label: 'SPIFFE',
    what: 'The three server-side SPIFFE surfaces: an SVID minted, a ' +
          'registration entry created, changed or deleted, an agent attesting, ' +
          'and the trust bundle being fetched or federated. An SVID row is NOT ' +
          'an authentication row — nothing authenticates to be issued one here ' +
          '— which is why these are not counted among the fourteen families.' }
];

const ACTIONS = [
  { action: 'authentication', category: 'authentication',
    label: 'A credential was accepted' },

  { action: 'session.start', category: 'session',
    label: 'A sign-on session was created' },
  { action: 'session.end', category: 'session',
    label: 'A sign-on session was ended' },

  // The four the request that started this feature named, plus the two that
  // fall out of the same operations on something that is not a person. The
  // directory is SCHEMALESS, so what an entry IS cannot be read off an
  // objectClass — it is decided by placement, which is the same rule
  // /admin/groups uses and is why an add under ou=users is a user.create and
  // the identical add one level over is a group.create.
  { action: 'user.create', category: 'directory', label: 'A user was created' },
  { action: 'user.delete', category: 'directory', label: 'A user was deleted' },
  { action: 'user.update', category: 'directory', label: 'A user was updated' },
  { action: 'user.rename', category: 'directory', label: 'A user was renamed' },
  { action: 'user.query', category: 'directory',
    label: 'A search returned at least one user' },
  { action: 'group.create', category: 'directory', label: 'A group was created' },
  { action: 'group.delete', category: 'directory', label: 'A group was deleted' },
  { action: 'group.update', category: 'directory', label: 'A group was updated' },
  { action: 'group.rename', category: 'directory', label: 'A group was renamed' },
  { action: 'entry.create', category: 'directory',
    label: 'An entry elsewhere in the tree was created' },
  { action: 'entry.delete', category: 'directory',
    label: 'An entry elsewhere in the tree was deleted' },
  { action: 'entry.update', category: 'directory',
    label: 'An entry elsewhere in the tree was updated' },
  { action: 'entry.rename', category: 'directory',
    label: 'An entry elsewhere in the tree was renamed' },
  { action: 'directory.search', category: 'directory',
    label: 'A search that returned no user' },
  { action: 'directory.compare', category: 'directory',
    label: 'An attribute value was compared' },
  { action: 'directory.bind', category: 'directory', label: 'A bind' },

  // Two rather than one, because "this application exists" and "this
  // application did something again" are different facts and a reader filtering
  // for the first does not want the second. An unchanged repeat writes NEITHER:
  // every token request would otherwise produce a row saying nothing happened.
  { action: 'application.create', category: 'application',
    label: 'An application was seen for the first time' },
  { action: 'application.update', category: 'application',
    label: 'An application recorded something new' },
  // Only ever from the console or the management API: no protocol path deletes
  // an application, because a protocol only ever learns that one EXISTS.
  { action: 'application.delete', category: 'application',
    label: 'An application was deleted from the registry' },

  { action: 'admin.view', category: 'admin', label: 'A console page was viewed' },
  { action: 'admin.change', category: 'admin',
    label: 'A console form was posted' },
  // The SUBSTANCE of a claim-set change, as against the HTTP row that says a
  // form was posted to /admin/claims. Both are recorded and they answer
  // different questions: `admin.change` says somebody was at that page at that
  // moment, this says what the four claim sets now contain. The second matters
  // more than it looks — a custom claim reaches every access token, ID Token
  // and SAML assertion issued from then on, so "when did this token start
  // carrying that?" is a question the HTTP row cannot answer and this one can.
  { action: 'claims.change', category: 'admin',
    label: 'A token or assertion claim set was changed' },

  { action: 'api.read', category: 'api', label: 'A management API read' },
  { action: 'api.change', category: 'api', label: 'A management API write' },

  { action: 'protocol.call', category: 'protocol',
    label: 'A protocol endpoint was called' },

  // SPIFFE. Nine actions, and the split between them is the same one the
  // application rows draw: what was CONFIGURED, what HAPPENED, and what was
  // ISSUED. `spiffe.svid.issue` is by far the noisiest — a workload refetches
  // its SVID as often as it likes — which is why it is one action rather than
  // one per SVID format: a reader filtering for it wants "identities were
  // handed out", not a breakdown.
  //
  // NO SVID IS EVER RECORDED IN A ROW, only the SPIFFE ID it named. A JWT-SVID
  // is a bearer credential and an X509-SVID is delivered WITH ITS PRIVATE KEY,
  // so this is the sharpest case in the service of the no-credential rule at
  // the top of this file.
  { action: 'spiffe.svid.issue', category: 'spiffe',
    label: 'An SVID was issued' },
  { action: 'spiffe.svid.validate', category: 'spiffe',
    label: 'A JWT-SVID was validated' },
  { action: 'spiffe.entry.create', category: 'spiffe',
    label: 'A registration entry was created' },
  { action: 'spiffe.entry.update', category: 'spiffe',
    label: 'A registration entry was changed' },
  { action: 'spiffe.entry.delete', category: 'spiffe',
    label: 'A registration entry was deleted' },
  { action: 'spiffe.agent.create', category: 'spiffe',
    label: 'An agent attested for the first time' },
  { action: 'spiffe.agent.attest', category: 'spiffe',
    label: 'An agent attested again' },
  { action: 'spiffe.agent.ban', category: 'spiffe',
    label: 'An agent was banned' },
  { action: 'spiffe.agent.unban', category: 'spiffe',
    label: 'An agent was unbanned' },
  { action: 'spiffe.agent.delete', category: 'spiffe',
    label: 'An agent was deleted' },
  { action: 'spiffe.bundle.read', category: 'spiffe',
    label: 'The trust bundle was fetched' },
  { action: 'spiffe.bundle.change', category: 'spiffe',
    label: 'An authority was rotated, or a federated bundle was set or removed' }
];

const CATEGORY_OF_ACTION = {};
ACTIONS.forEach(function (entry) {
  CATEGORY_OF_ACTION[entry.action] = entry.category;
});

// The three outcomes, and they are three rather than two because "refused" and
// "broke" are different facts about this service: a 400 is this service working
// correctly and saying no, a 500 is this service failing. Collapsing them into
// !ok would make the one row worth paging somebody about look like the fifty
// rows that are a client getting its parameters wrong.
const OUTCOMES = ['success', 'refused', 'error'];

// ---------------------------------------------------------------------------
// The store.
//
// An array used as a ring: newest at the end, oldest shifted off when the cap
// is reached. `shift()` on a JS array is O(n), which on a 5,000-element array
// of small objects is a few microseconds and happens once per event past the
// cap — measurably nothing here, and the alternative (a real circular buffer
// with a head index) is more code to get the ordering wrong in.
//
// `seq` is monotonic and NEVER reused, including across a trim. That is what
// makes the number on a row a stable name for that event: a caller can say "I
// have read up to 4,102" and mean it, where a row index would silently mean a
// different event as soon as anything was dropped.
// ---------------------------------------------------------------------------
const events = [];

let seq = 0;

let recorded = 0;

let dropped = 0;

// ---------------------------------------------------------------------------
// WHO, for an HTTP event — and why it arrives through a slot.
//
// The interesting column on an admin row is the person who was signed in when
// they posted the form, and only authn.js knows that: it owns the session
// cookie and the session store. But authn.js requires app.js, app.js requires
// THIS file, and a require in the other direction would close the loop — node
// would hand back a half-initialised module whose exports are undefined, and
// the symptom would arrive later as something that is not a function.
//
// So the direction is inverted, the same way helpers.js's setJwtRecorder and
// admin_stats.js's setUserObserver are: this file offers a slot and authn.js
// fills it at ITS require time. It stays null in a process that never loaded
// that module, and every HTTP event then simply has no actor — which is a
// weaker log and not a broken one.
//
// The resolver must not have side effects and must not throw. A throw is caught
// anyway, because a session lookup must never be able to fail a request.
// ---------------------------------------------------------------------------
let actorResolver = null;

function setActorResolver(fn) {
  actorResolver = fn;
  log.debug("An audit actor resolver was installed; HTTP events will now name " +
            "the signed-in user where there is one.");
}

function actorOfRequest(req) {
  if (!actorResolver) return '';
  try {
    return String(actorResolver(req) || '');
  } catch (e) {
    // Swallowed with a reason: the actor is a nicety on an audit row and the
    // request it decorates is real work. A session store that throws must not
    // turn a working endpoint into a 500.
    log.error('the audit actor resolver threw and was ignored: ' + e.message);
    return '';
  }
}

// ---------------------------------------------------------------------------
// Recording one event.
//
// Everything is optional and nothing here throws, which is the whole contract:
// the callers are the KDC, the directory and the express call log, and none of
// them may fail because a statistics module did.
//
// `detail` is a flat object of small facts. It is capped in both directions —
// how many keys, and how long each value may be — because it is the one part of
// an event a caller fills freely, and an unbounded string on an unbounded
// number of events is the memory leak the cap above exists to prevent, arriving
// through the side door.
// ---------------------------------------------------------------------------
const MAX_DETAIL_KEYS = 12;

const MAX_DETAIL_LENGTH = 200;

const MAX_SUMMARY_LENGTH = 400;

function trimmed(value, limit) {
  const text = String(value == null ? '' : value);
  if (text.length <= limit) return text;
  // Named rather than silently cut: a value that ends mid-word reads as data
  // that was always like that, which is how a truncation becomes a bug report.
  return text.slice(0, limit) + '… (' + text.length + ' characters)';
}

function detailOf(source) {
  const out = {};
  const keys = Object.keys(source || {});
  keys.slice(0, MAX_DETAIL_KEYS).forEach(function (key) {
    const value = source[key];
    if (value === null || value === undefined || value === '') return;
    if (typeof value === 'number' || typeof value === 'boolean') {
      out[key] = value;
      return;
    }
    out[key] = trimmed(value, MAX_DETAIL_LENGTH);
  });
  if (keys.length > MAX_DETAIL_KEYS) {
    out['(more)'] = (keys.length - MAX_DETAIL_KEYS) + ' further field(s) not kept';
  }
  return out;
}

// Drop as many of the oldest events as the cap now requires. A LOOP rather than
// a single shift, because `audit.maxEvents` is a runtime setting: lowering it
// from 5,000 to 100 has to take effect on the next event rather than one row per
// event for the next 4,900.
function trimToCap() {
  const cap = Math.max(1, parseInt(maxEvents(), 10) || 1);
  while (events.length > cap) {
    events.shift();
    dropped++;
  }
}

function record(event) {
  const info = event || {};
  const action = String(info.action || 'protocol.call');
  const category = CATEGORY_OF_ACTION[action] || String(info.category || 'protocol');
  const now = Date.now();
  seq++;
  recorded++;
  const row = {
    seq: seq,
    at: now,
    category: category,
    action: action,
    // Defaulted to success rather than to '' because most events here are
    // things that happened; a refusal is the one that has to say so.
    outcome: OUTCOMES.indexOf(info.outcome) >= 0 ? info.outcome : 'success',
    // The normalised local name where a caller had one (`alice`), so that a row
    // here and a row on /admin/users name the same person. Never computed in
    // this file — see the header: admin_stats.js owns that normalisation and
    // this module cannot require it back.
    actor: trimmed(info.actor || '', MAX_DETAIL_LENGTH),
    // The identity exactly as it was presented, when that differs — a bind DN,
    // a Kerberos principal, an X.509 subject. Both are shown, because the
    // collapse from one to the other is a thing an auditor has to be able to
    // see rather than infer.
    actorForm: trimmed(info.actorForm || '', MAX_DETAIL_LENGTH),
    // What it was done to: a DN, a path, a session id, a jti.
    target: trimmed(info.target || '', MAX_DETAIL_LENGTH),
    // Which family, where one applies. Free text on purpose: the fourteen
    // families here already spell themselves differently in the places this is
    // read from, and forcing them into an enum would mean a lookup table that
    // silently drops the fifteenth.
    protocol: trimmed(info.protocol || '', 60),
    // Where it came from: 'http', 'ldap', 'ldaps', 'internal'. Not the client's
    // IP address — see the note on the console page. A mock behind a compose
    // bridge reports the bridge, which is a fact about docker and not about
    // whoever made the call.
    channel: trimmed(info.channel || '', 40),
    summary: trimmed(info.summary || '', MAX_SUMMARY_LENGTH),
    detail: detailOf(info.detail)
  };
  events.push(row);
  trimToCap();
  return row;
}

// The public entry point. Wrapped so that a caller cannot be broken by a defect
// in here — see the header. Every recording site in this service calls THIS and
// not record() above.
function audit(event) {
  try {
    return record(event);
  } catch (e) {
    // Swallowed with a reason: the alternative is an audit log that can fail a
    // bind, revoke or token issuance, which is strictly worse than a missing
    // row. Logged at error so it is not invisible.
    log.error('an audit event could not be recorded and was dropped: ' + e.message);
    return null;
  }
}

// ---------------------------------------------------------------------------
// THE HTTP FUNNEL.
//
// One call from app.js's call log covers three of the six categories — the
// console, the management API and every protocol endpoint — because that
// middleware is already the single place every answered request passes through.
// Three recording sites spread over forty route handlers would be three that
// drift and thirty-seven that were never added.
//
// The classification is HERE rather than in app.js so that the caller stays one
// line, and so that the rule about what counts as console access lives beside
// the vocabulary it uses.
// ---------------------------------------------------------------------------

// The action a form or a JSON body names, and NOTHING else out of that body.
//
// This is the one place an admin request body is read at all, and it is worth
// being explicit about why it is narrow: those bodies carry pasted JWTs (the
// tokens page revokes by pasted token), so anything more than the action name
// would put a live bearer credential on a page and in a JSON reply. The value
// is capped as well, because it is caller-supplied and reaches the console's
// markup.
const MAX_ACTION_LENGTH = 60;

function actionOf(req) {
  const raw = typeof req.body === 'string' ? req.body : '';
  if (!raw) return '';
  const type = String(req.headers['content-type'] || '');
  try {
    if (/json/i.test(type)) {
      const parsed = JSON.parse(raw);
      return trimmed(parsed && parsed.action, MAX_ACTION_LENGTH);
    }
    return trimmed(new URLSearchParams(raw).get('action') || '', MAX_ACTION_LENGTH);
  } catch (e) {
    // Not a body this can read; the row simply has no action name on it. Not an
    // error worth a line — an unparseable body is already a 400 the row records.
    return '';
  }
}

// What a status code means as an outcome. See OUTCOMES above for why 4xx and
// 5xx are not one thing.
function outcomeOfStatus(status) {
  const code = parseInt(status, 10) || 0;
  if (code >= 500) return 'error';
  if (code >= 400) return 'refused';
  return 'success';
}

// Which of the three HTTP categories a path belongs to.
//
// The order matters and is not alphabetical: `/admin-api` starts with `/admin`,
// so testing for the console first would file every management API call as
// console access and the API category would be permanently empty.
function httpActionFor(path, method) {
  const write = method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';
  if (path === '/admin-api' || path.indexOf('/admin-api/') === 0) {
    return write ? 'api.change' : 'api.read';
  }
  if (path === '/admin' || path.indexOf('/admin/') === 0) {
    return write ? 'admin.change' : 'admin.view';
  }
  return 'protocol.call';
}

// Called once per answered request, from app.js's call log, beside
// stats.recordCall(). `req` is still live at that point — the response has been
// flushed, but the request object has not gone anywhere — which is what lets
// the actor be resolved here rather than being threaded through.
function recordHttp(req, res, detail) {
  log.debug("Entering recordHttp(). " + req.method + " " + req.originalUrl);
  const info = detail || {};
  // The URL WITHOUT its query string. The query is on the row as a detail where
  // it is interesting, and a path that carried it would make every distinct
  // ?page= a different-looking row for the same page view.
  const path = String(req.originalUrl || '/').split('?')[0];
  const action = httpActionFor(path, req.method);
  if (action === 'protocol.call' && !protocolCallsRecorded()) {
    log.debug("Leaving recordHttp(). audit.protocolCalls is off; not recorded.");
    return null;
  }
  const actor = actorOfRequest(req);
  const posted = (action === 'admin.change' || action === 'api.change')
    ? actionOf(req) : '';
  const row = audit({
    action: action,
    outcome: outcomeOfStatus(res.statusCode),
    actor: actor,
    target: path,
    channel: 'http',
    // The route PATTERN express matched, which is what admin_stats.js keys its
    // call table on — carried here too so that a row on this page and a row on
    // /admin/metrics can be lined up without guessing.
    protocol: '',
    summary: req.method + ' ' + path + ' → ' + res.statusCode +
             (posted ? ' (' + posted + ')' : ''),
    detail: {
      method: req.method,
      status: res.statusCode,
      route: info.route || '',
      matched: !!info.matched,
      durationMs: info.durationMs || 0,
      query: queryText(req.query),
      postedAction: posted
    }
  });
  log.debug("Leaving recordHttp(). Recorded as " + action + ".");
  return row;
}

// The query string as one short line, for the detail column. Values are kept
// because on this service they are page numbers, filters and client ids rather
// than secrets — with the one exception below, which is not a rule that can be
// relaxed: an OAuth 2.0 authorization CODE and an id_token_hint travel in a
// query string, and both are credentials.
const REDACTED_QUERY_KEYS = ['code', 'id_token_hint', 'access_token', 'token',
                             'assertion', 'client_secret', 'password',
                             'credential', 'vp_token', 'response'];

function queryText(query) {
  const source = query || {};
  const parts = [];
  Object.keys(source).slice(0, MAX_DETAIL_KEYS).forEach(function (key) {
    const redact = REDACTED_QUERY_KEYS.indexOf(String(key).toLowerCase()) >= 0;
    parts.push(key + '=' + (redact ? '(redacted)'
                                   : trimmed(source[key], 60)));
  });
  return parts.join(' ');
}

// ---------------------------------------------------------------------------
// THE DIRECTORY FUNNEL.
//
// ldap_server.js calls recordDirectory() once per operation. The action is
// worked out HERE from the operation and the DN, so that the rule about what
// counts as a user — placement, because the directory is schemaless — is
// written once rather than at each of the six handlers.
//
// The containers are passed in rather than derived: this module knows nothing
// about the base DN and must not, since `ldap.baseDn` is a setting and the
// caller already has it resolved.
// ---------------------------------------------------------------------------
function objectKindOf(dn, containers) {
  const lower = String(dn || '').toLowerCase().replace(/\s*,\s*/g, ',');
  const users = String((containers && containers.users) || '').toLowerCase()
                  .replace(/\s*,\s*/g, ',');
  const groups = String((containers && containers.groups) || '').toLowerCase()
                   .replace(/\s*,\s*/g, ',');
  if (users && lower !== users && lower.slice(-(users.length + 1)) === ',' + users) {
    return 'user';
  }
  if (groups && lower !== groups && lower.slice(-(groups.length + 1)) === ',' + groups) {
    return 'group';
  }
  return 'entry';
}

// operation is 'create' | 'delete' | 'update' | 'rename'. A search or a compare
// does not come through here — those have one action each, since "a search of a
// group" is not a thing anybody filters for.
function directoryActionFor(operation, dn, containers) {
  return objectKindOf(dn, containers) + '.' + operation;
}

function recordDirectory(event) {
  const info = event || {};
  return audit({
    action: info.action,
    outcome: info.outcome,
    actor: info.actor || '',
    actorForm: info.actorForm || '',
    target: info.target || '',
    protocol: info.protocol || 'LDAP',
    channel: info.channel || 'ldap',
    summary: info.summary || '',
    detail: info.detail
  });
}

// ---------------------------------------------------------------------------
// Reading it back.
//
// Newest first, which is what every list in this console does and what somebody
// debugging wants: the thing that just happened is the thing being debugged.
// A COPY of the array rather than the array itself, so that a caller iterating
// it while an endpoint records cannot have the ground move — the row objects
// themselves are shared and are never mutated after they are pushed.
// ---------------------------------------------------------------------------
function list() {
  log.debug("Entering list(). " + events.length + " event(s) held.");
  const out = events.slice(0).reverse();
  log.debug("Leaving list(). " + out.length + " event(s) returned, newest first.");
  return out;
}

// The counts the page's tiles and the API's summary need, taken in one pass
// rather than by filtering the list six times.
function summary() {
  log.debug("Entering summary().");
  const byCategory = {};
  const byAction = {};
  const byOutcome = {};
  CATEGORIES.forEach(function (entry) { byCategory[entry.category] = 0; });
  OUTCOMES.forEach(function (name) { byOutcome[name] = 0; });
  events.forEach(function (row) {
    byCategory[row.category] = (byCategory[row.category] || 0) + 1;
    byAction[row.action] = (byAction[row.action] || 0) + 1;
    byOutcome[row.outcome] = (byOutcome[row.outcome] || 0) + 1;
  });
  const out = {
    held: events.length,
    // Everything ever recorded, which is the number that says whether the cap
    // has bitten. `held` alone would read as "this is all there was".
    recorded: recorded,
    dropped: dropped,
    maxEvents: maxEvents(),
    protocolCalls: protocolCallsRecorded(),
    oldestAt: events.length ? events[0].at : 0,
    newestAt: events.length ? events[events.length - 1].at : 0,
    oldestSeq: events.length ? events[0].seq : 0,
    newestSeq: events.length ? events[events.length - 1].seq : 0,
    byCategory: byCategory,
    byAction: byAction,
    byOutcome: byOutcome
  };
  log.debug("Leaving summary(). " + out.held + " held, " + out.dropped + " dropped.");
  return out;
}

log.info('The audit log is running: every authentication, session, directory ' +
         'operation, console interaction, management API call and protocol ' +
         'endpoint call is recorded as an event. It is at /admin/audit and ' +
         'GET /admin-api/audit, holds at most ' + maxEvents() + ' events in ' +
         'memory, and carries no credential of any kind.');

module.exports = {
  CATEGORIES: CATEGORIES,
  ACTIONS: ACTIONS,
  OUTCOMES: OUTCOMES,
  audit: audit,
  record: audit,
  recordHttp: recordHttp,
  recordDirectory: recordDirectory,
  directoryActionFor: directoryActionFor,
  objectKindOf: objectKindOf,
  setActorResolver: setActorResolver,
  list: list,
  summary: summary
};
