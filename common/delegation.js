'use strict';
//
// File: delegation.js
//
// ---------------------------------------------------------------------------
// DELEGATION: who acted on whose behalf, through what, to reach what.
//
// Three of the protocol families here can do it and each calls it something
// different — Kerberos has S4U2Self, two flavours of S4U2Proxy and a forwarded
// ticket-granting ticket; WS-Trust has OnBehalfOf and ActAs; OAuth 2.0 Token
// Exchange has impersonation and delegation. This file is the ONE model all six
// are recorded against, because the question a person brings to this page is
// protocol-independent: *alice never touched the back end, so why is there a
// ticket to it in her name, and who asked for it?*
//
// It is a LIBRARY, like admin_stats.js, audit.js and dpop.js — it registers no
// route, so its position in the require order does not matter and it cannot be
// the reason a route is missing. `admin.js` renders it at /admin/delegation and
// `admin_api.js` serves it at /admin-api/delegation; this file holds the acts
// and none of the HTML.
//
// It requires helpers.js, config.js and admin_stats.js — that last one for
// identityOf()'s normalisation only, which is what makes `alice`,
// `alice@STS.MOCK` and `urn:sts-mock:user:alice` one person on a chain rather
// than three. admin_stats.js requires nothing here, so there is no cycle and
// none of rule 3e's slots is needed. Keep it that way: this file is called from
// the KDC, from WS-Trust and from the token endpoint, and anything it required
// all three would require transitively.
//
// ---------------------------------------------------------------------------
// FIVE THINGS ARE WORTH KNOWING BEFORE READING FURTHER.
//
// **A ROW IS AN ACT, NOT A RELATIONSHIP.** Each one is a single exchange at a
// single moment. The same three parties appearing eleven times is eleven rows,
// and `chainKey` is what collapses them — it is the identity of the CHAIN
// (initial, intermediary, target and type) with the time and the credentials
// left out. The page groups on it and the visualisation that comes later will
// draw one edge per distinct value. Deduplicating at record time instead would
// throw away the one thing the acts have that a relationship does not: when,
// how often, and with which credential.
//
// **REFUSALS ARE RECORDED AND ARE MOST OF THE VALUE.** A delegation that
// succeeded tells you the plumbing works. A delegation that was REFUSED tells
// you which of two attributes on which of two accounts is missing, and that is
// the question people actually arrive with. The KDC already builds that
// sentence for its own error reply; this file keeps it beside the parties it
// was about, where the other two protocols — which check nothing at all — can
// be seen not to have one.
//
// **THERE IS NO FUNNEL AND THERE CANNOT BE ONE.** signJwt() is the single point
// every JWT passes; recordAuthentication() is the single point every accepted
// credential passes. Delegation has no such point: it happens in three modules
// that share no code path, and the moment it becomes visible is different in
// each (a padata in a TGS-REQ, an element in an RST, a form field on a token
// request). So this file is called from several places on purpose, and the
// header of each call site says which act it is recording. What the shape below
// buys is that all of them produce the SAME row.
//
// **NOTHING HERE WRITES AN AUDIT ROW, deliberately.** Every delegation that
// SUCCEEDED already writes an `authentication` row through the funnel it also
// passes, and a second row for one act is exactly the double-count rule 3c
// warns about. A delegation that was REFUSED writes none — nothing was accepted
// — which is a genuine gap in the audit log that this page closes rather than
// one the audit log should grow a seventh category for. Cite this paragraph
// before adding an audit call here.
//
// **IT IS IN MEMORY AND DIES WITH THE PROCESS**, like the counters, the audit
// log, the sessions and the signing key. `delegation.maxRecords` is the cap and
// what was dropped is COUNTED, so a truncated list says it was truncated rather
// than implying the cap is all there ever was.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');
// TRUST REALMS: the stores below are partitioned by realm. It requires
// config.js and nothing else here, so it cannot join a cycle and it registers
// no route, so its position is not a position at all.
const realms = require('./realms');
const config = require('./config');
const stats = require('./admin_stats');

// ---------------------------------------------------------------------------
// THE TWO AXES, AND WHY THE PROTOCOL-INDEPENDENT ONE IS `mode` RATHER THAN THE
// TYPE.
//
// `type` is what the protocol calls it, and there are eight because the three
// protocols between them define eight. `mode` is the thing they share, and it
// is the axis worth filtering on:
//
//   **impersonation** — the credential that comes out names the INITIAL identity
//   and says nothing about the intermediary. The service at the far end cannot
//   tell it is talking to a middle tier rather than to the person, and no
//   forensic reading of the token afterwards can either.
//
//   **delegation** — the credential CARRIES the chain. RFC 8693 puts the actor
//   in an `act` claim (and nests it, so a second hop is visible under the
//   first); WS-Trust 1.4's ActAs is composite by definition; and a Kerberos
//   S4U2Proxy ticket carries S4U_DELEGATION_INFO in its PAC, naming every
//   service the request transited.
//
// The distinction is the whole reason a person cares: an impersonation is
// invisible at the far end, so the only place it can ever be seen is a table
// like this one, on the issuer. Getting a row's mode wrong would therefore be
// worse than getting its type wrong.
//
// One consequence to state rather than leave to be discovered: `mode` is a
// property of the MECHANISM and not of what this service checked. Every row
// here, in all eight types, was allowed — this service polices exactly one of
// them (see `authorizedBy` below).
// ---------------------------------------------------------------------------
const MODES = [
  { mode: 'impersonation', label: 'Impersonation',
    what: 'What comes out names the initial identity and nothing else. The ' +
          'service at the far end cannot tell an intermediary was involved, ' +
          'and neither can anybody reading the credential afterwards — which ' +
          'is why the issuer is the only place this is ever visible.' },
  { mode: 'delegation', label: 'Delegation',
    what: 'What comes out CARRIES the chain: an `act` claim, a composite ' +
          'ActAs, or S4U_DELEGATION_INFO in the PAC. The far end can see who ' +
          'is really asking, and can decide differently because of it.' }
];

const MODE_IDS = MODES.map(function (one) { return one.mode; });

// The eight, as the specifications name them. `spec` is cited on the page for
// the same reason /admin/sts-metadata cites one per endpoint: a table of
// delegation mechanisms with no references is a table somebody has to take on
// trust.
//
// `policed` says whether THIS SERVICE decides who may perform the act. It is
// true for exactly the three Kerberos S4U rows and false for everything else,
// and that asymmetry is real rather than an omission — see the note on
// `authorizedBy`.
const TYPES = [
  { type: 'krb5-s4u2self', protocol: 'Kerberos v5', mode: 'impersonation',
    label: 'S4U2Self (protocol transition)', spec: '[MS-SFU] 3.2.5.1',
    policed: true,
    what: 'A service asked for a ticket TO ITSELF naming a user who was not ' +
          'involved at all — no password, no ticket of theirs, nothing they ' +
          'consented to. It is how a service that authenticated somebody by ' +
          'other means gets a Kerberos identity for them, and it is not a ' +
          'privilege: the ticket is to yourself.' },
  { type: 'krb5-s4u2proxy-classic', protocol: 'Kerberos v5', mode: 'delegation',
    label: 'S4U2Proxy — classic constrained delegation', spec: '[MS-SFU] 3.2.5.2',
    policed: true,
    what: 'The front end then reached ANOTHER service as that user. ' +
          'Authorized by msDS-AllowedToDelegateTo on the FRONT-END account, ' +
          'which only a domain admin can set, and requiring the evidence ' +
          'ticket to be forwardable.' },
  { type: 'krb5-s4u2proxy-rbcd', protocol: 'Kerberos v5', mode: 'delegation',
    label: 'S4U2Proxy — resource-based (RBCD)', spec: '[MS-SFU] 3.2.5.2',
    policed: true,
    what: 'The same messages, authorized from the opposite direction: ' +
          'msDS-AllowedToActOnBehalfOfOtherIdentity on the BACK-END account, ' +
          'which whoever controls that object can set themselves. That is the ' +
          'entire security story of RBCD, and it needs no forwardable ' +
          'evidence — but does need PA-PAC-OPTIONS.' },
  { type: 'krb5-forwarded', protocol: 'Kerberos v5', mode: 'impersonation',
    label: 'Forwarded TGT (unconstrained delegation)', spec: 'RFC 4120 5.8.1',
    policed: true,
    what: 'The client handed over its whole ticket-granting ticket. Whoever ' +
          'holds it can reach ANYTHING as that client until it expires, with ' +
          'no further reference to this KDC — so there is no list of ' +
          'permitted targets, because there is no constraint. The only ' +
          'control is at issue time, and it is on the ACCOUNT being ' +
          'protected (NOT_DELEGATED) rather than on any service.' },
  { type: 'wstrust-onbehalfof', protocol: 'WS-Trust', mode: 'impersonation',
    label: 'WS-Trust OnBehalfOf', spec: 'WS-Trust 1.3 §9.2',
    policed: false,
    what: 'The requester asked for a token ABOUT somebody else. The token ' +
          'names that somebody and does not name the requester, so the ' +
          'relying party sees an ordinary sign-in.' },
  { type: 'wstrust-actas', protocol: 'WS-Trust', mode: 'delegation',
    label: 'WS-Trust ActAs (composite)', spec: 'WS-Trust 1.4 §9.3',
    policed: false,
    what: 'The 1.4 addition, and composite by definition: the token is about ' +
          'the named subject AND says the requester is acting. It is the ' +
          'element to reach for when the far end must be able to tell.' },
  { type: 'oauth-impersonation', protocol: 'OAuth 2.0', mode: 'impersonation',
    label: 'Token exchange — impersonation', spec: 'RFC 8693 §1.1',
    policed: false,
    what: 'A subject_token and no actor_token. What comes back is a token ' +
          'for the subject with no record of who exchanged it.' },
  { type: 'oauth-delegation', protocol: 'OAuth 2.0', mode: 'delegation',
    label: 'Token exchange — delegation', spec: 'RFC 8693 §4.1',
    policed: false,
    what: 'A subject_token AND an actor_token. What comes back carries an ' +
          '`act` claim naming the actor — and `act` nests, so a second hop ' +
          'appears underneath the first rather than replacing it.' }
];

const TYPE_IDS = TYPES.map(function (one) { return one.type; });

const TYPE_BY_ID = {};
TYPES.forEach(function (one) { TYPE_BY_ID[one.type] = one; });

// Two rather than the audit log's three, and the reason is that the third one
// cannot happen: `error` there means this service failed, and a delegation is
// decided rather than performed — there is no third answer between issuing the
// credential and refusing to.
const OUTCOMES = ['issued', 'refused'];

// The three layers of the architecture, in the order a request moves through
// them. The names are this file's own and are deliberately not any protocol's:
// a Kerberos front end, a WS-Trust requester and an OAuth client doing an
// exchange are the same position in the same picture, and naming the position
// after one of them would make the other two look like special cases.
const ROLES = [
  { role: 'initial', label: 'Initial identity',
    what: 'Who the credential is ABOUT. The person who signed in somewhere ' +
          'else, or who never signed in at all — under S4U2Self and ' +
          'OnBehalfOf they were not present and proved nothing.' },
  { role: 'intermediary', label: 'Intermediary',
    what: 'Who is acting on their behalf: the front-end service, the ' +
          'requester, the client performing the exchange. This is the party ' +
          'that presented a credential of its own, and under an ' +
          'impersonation it is the party the far end will never see.' },
  { role: 'target', label: 'Target',
    what: 'What is being reached — the back-end service, the AppliesTo, the ' +
          'audience or resource. It is an application rather than a person, ' +
          'and it is the layer that decides whether any of this mattered.' }
];

const ROLE_IDS = ROLES.map(function (one) { return one.role; });

// ---------------------------------------------------------------------------
// The store. A list rather than a Map, because there is no key an act has that
// is stable and unique — two S4U2Proxy requests a second apart are two acts
// with everything in common — and `seq` is assigned here rather than derived
// from anything in the request.
// ---------------------------------------------------------------------------
// PER TRUST REALM. `realms.arr()` is a array that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain array it replaced. See common/realms.js.
const acts = realms.arr();

let seq = 0;

let recorded = 0;

let dropped = 0;

// Read per record rather than captured at require time, which is what the
// `runtime: true` on the setting claims. Lowering the cap trims on the very
// next act rather than one row per act thereafter.
function maxRecords() {
  const value = parseInt(config.value('delegation.maxRecords'), 10);
  return (isFinite(value) && value > 0) ? value : 1;
}

// ---------------------------------------------------------------------------
// A PARTY: an identity, an application, or both.
//
// All three roles use this one shape and each of them can be either or both,
// which is the fact that makes the model protocol-independent rather than a
// Kerberos model the other two are squeezed into:
//
//   * an initial identity is a PERSON and has no application of its own;
//   * a target is an APPLICATION and has no person behind it;
//   * an intermediary is routinely BOTH — `HTTP/frontend.sts.mock` is an entry
//     under ou=users (a service account authenticates, so the funnel files it
//     with the people) and an entry under ou=applications (a ticket was issued
//     FOR it, so applications.js recorded it). Two entries, one party, and a
//     model with only one slot would have had to choose which of them to lose.
//
// `key` is the normalised identity — identityOf()'s answer, so a row here and a
// row on /admin/users name the same person — and `presented` is the form it
// arrived in, kept for the reason the audit log keeps both: the collapse from
// `alice@STS.MOCK` to `alice` is something a reader has to be able to SEE
// rather than take on trust.
//
// `application` is an identifier and NOT a promise that an entry exists. What
// this service has been asked about is applications.js's business and it is
// recorded at that module's own call sites; a delegation act naming an
// application the registry has never seen is an ordinary and interesting
// outcome — an RFC 8693 `audience` nobody has otherwise mentioned is exactly
// that — so the page resolves the name against the registry and says which of
// the two it found, the same three-state rule /admin/groups uses for a member.
// Creating the entry from here would be a fifth door onto that registry and
// would make the page unable to report the difference.
// ---------------------------------------------------------------------------
function party(detail) {
  const info = detail || {};
  const presented = String(info.presented == null ? '' : info.presented).trim();
  const application = String(info.application == null ? '' : info.application).trim();
  return {
    key: presented ? stats.identityKeyOf(presented) : '',
    presented: presented,
    application: application,
    // What this party is here, in the protocol's own words — `the front-end
    // service`, `the client performing the exchange`. One phrase, because the
    // column is narrow and the ROLES table above already says what the position
    // means in general.
    what: String(info.what == null ? '' : info.what).trim()
  };
}

// The identity of the CHAIN rather than of the act: the three parties and the
// type, with the time, the credentials and the outcome left out.
//
// Two things are deliberately IN it and each was got wrong first. The TYPE is
// in it, because `alice -> frontend -> backend` reached by classic constrained
// delegation and the same three reached by RBCD are two different arrangements
// of the same boxes, and a graph that drew one edge for both would be hiding
// the only interesting difference. The OUTCOME is deliberately OUT of it, so
// that a chain which is refused nine times and then succeeds is ONE chain with
// ten acts on it rather than two — a reader following a fix wants to watch a
// single edge change colour.
//
// The normalised key is used where there is one and the presented form
// otherwise, so a chain does not fork the first time somebody's realm is
// spelled differently.
function chainKeyOf(record) {
  const at = function (p) { return p.key || p.presented || p.application || '(none)'; };
  return [record.type, at(record.initial), at(record.intermediary),
          at(record.target)].join(' | ');
}

// One credential in or out. `identifier` is a jti, an AssertionID or '' — a
// Kerberos ticket genuinely has none to quote, which the page says rather than
// leaving a blank column to be read as a bug.
//
// NO CREDENTIAL IS EVER KEPT, only its identifier and what kind it was. That is
// audit.js's rule and it applies here for the same reason and one more: a
// delegation act is precisely the request that carries two credentials at once,
// so it is the row most likely to put a pasted assertion on a web page.
function credential(detail) {
  const info = detail || {};
  return {
    kind: String(info.kind == null ? '' : info.kind).trim(),
    identifier: String(info.identifier == null ? '' : info.identifier).trim(),
    note: String(info.note == null ? '' : info.note).trim()
  };
}

function credentials(list) {
  if (!list) return [];
  return (Array.isArray(list) ? list : [list])
    .filter(Boolean)
    .map(credential)
    .filter(function (one) { return one.kind || one.identifier || one.note; });
}

// ---------------------------------------------------------------------------
// RECORD ONE ACT.
//
// Called from the KDC, from WS-Trust's RST handler and from the token endpoint.
// It CANNOT THROW — the whole body is wrapped, and a caller must never guard it
// — because a table on a console page must not be able to fail a delegation the
// protocol has already decided to allow. That is the rule audit()'s header
// states, the rule the directory's user observer follows, and the rule
// signJwt()'s recorder follows; this is the fourth place it applies and the
// first where the thing it protects is a Kerberos ticket already half built.
//
//   protocol      the family name, as /admin/users spells it
//   type          one of TYPE_IDS
//   outcome       'issued' or 'refused'
//   initial       { presented, application, what } — who it is about
//   intermediary  the same — who is acting
//   target        the same — what is being reached
//   authorizedBy  what PERMITTED it, where anything did. The attribute and the
//                 account it is on, in the KDC's own words.
//   reason        why it was REFUSED, in the words of the error the caller is
//                 about to send. Empty on an issued act.
//   consumed      the credentials presented: the evidence ticket, the
//                 subject_token, the UsernameToken
//   produced      what came out: the service ticket, the access token, the
//                 assertion
//   sessionId     the browser sign-on session, where there was one. Usually
//                 empty, and that is a fact about delegation rather than a gap
//                 in the recording — a service asking on somebody's behalf has
//                 no browser anywhere in it
//   note          one sentence of context for the row
// ---------------------------------------------------------------------------
function record(detail) {
  try {
    return recordUnguarded(detail || {});
  } catch (e) {
    // Swallowed on purpose, and loudly: see the header above. A malformed call
    // here must cost a row on a console page and nothing else.
    log.error('delegation: an act could not be recorded and the protocol was ' +
              'left alone: ' + e.message);
    return null;
  }
}

function recordUnguarded(info) {
  const type = String(info.type || '');
  log.debug("Entering recordUnguarded(). type=" + (type || '(none)') +
            ", outcome=" + (info.outcome || '(none)'));
  const known = TYPE_BY_ID[type];
  if (!known) {
    // Recorded as given rather than dropped, and warned about: a row nobody can
    // filter is still a row somebody can read, where a silently discarded act
    // is a delegation this service performed and cannot account for. The same
    // choice applications.js's seen() makes about an unknown kind.
    log.warn('delegation: "' + type + '" is not one of the types this store ' +
             'knows (' + TYPE_IDS.join(', ') + '). The act is recorded as ' +
             'given, which is how one mechanism comes to be listed under two ' +
             'spellings — fix the caller or add a row to TYPES.');
  }
  const outcome = OUTCOMES.indexOf(String(info.outcome || '')) >= 0
    ? String(info.outcome) : 'issued';
  seq++;
  recorded++;
  const record = {
    seq: seq,
    at: Date.now(),
    protocol: String(info.protocol || (known ? known.protocol : '')),
    type: type,
    // Carried on the row rather than looked up when it is drawn, so that a row
    // recorded under an unknown type still says something in both columns.
    typeLabel: known ? known.label : type,
    mode: known ? known.mode : '',
    spec: known ? known.spec : '',
    policed: known ? !!known.policed : false,
    outcome: outcome,
    initial: party(info.initial),
    intermediary: party(info.intermediary),
    target: party(info.target),
    authorizedBy: String(info.authorizedBy || ''),
    reason: String(info.reason || ''),
    consumed: credentials(info.consumed),
    produced: credentials(info.produced),
    sessionId: String(info.sessionId || ''),
    note: String(info.note || '')
  };
  record.chainKey = chainKeyOf(record);
  acts.push(record);
  const cap = maxRecords();
  while (acts.length > cap) {
    acts.shift();
    dropped++;
  }
  log.info('delegation: ' + record.protocol + ' ' + (record.typeLabel || record.type) +
    ' — ' + (record.intermediary.presented || record.intermediary.application || 'something') +
    ' ' + (outcome === 'issued' ? 'acted for ' : 'was REFUSED acting for ') +
    (record.initial.presented || '(nobody named)') +
    (record.target.application || record.target.presented
      ? ' at ' + (record.target.application || record.target.presented) : '') +
    (record.reason ? ' — ' + record.reason : ''));
  log.debug("Leaving recordUnguarded(). " + acts.length + " act(s) held, " +
            dropped + " dropped.");
  return record;
}

// Newest first, the way the audit log and the tokens page both answer. A copy,
// because the caller filters and pages it.
function list() {
  log.debug("Entering list(). " + acts.length + " act(s) held.");
  const out = acts.slice(0).reverse();
  log.debug("Leaving list(). " + out.length + " act(s) returned, newest first.");
  return out;
}

// The counts the page's tiles and the API's summary need, in one pass rather
// than by filtering the list six times.
//
// `chains` is the number of DISTINCT chainKeys and is the number the
// visualisation will draw. It is reported beside `held` deliberately: eleven
// acts over two chains and eleven acts over eleven chains are very different
// pictures, and a single count cannot tell them apart.
function summary() {
  log.debug("Entering summary().");
  const byType = {};
  const byMode = {};
  const byOutcome = {};
  const byProtocol = {};
  const chains = {};
  TYPE_IDS.forEach(function (id) { byType[id] = 0; });
  MODE_IDS.forEach(function (id) { byMode[id] = 0; });
  OUTCOMES.forEach(function (name) { byOutcome[name] = 0; });
  acts.forEach(function (row) {
    byType[row.type] = (byType[row.type] || 0) + 1;
    if (row.mode) byMode[row.mode] = (byMode[row.mode] || 0) + 1;
    byOutcome[row.outcome] = (byOutcome[row.outcome] || 0) + 1;
    if (row.protocol) byProtocol[row.protocol] = (byProtocol[row.protocol] || 0) + 1;
    chains[row.chainKey] = (chains[row.chainKey] || 0) + 1;
  });
  const out = {
    held: acts.length, recorded: recorded, dropped: dropped,
    maxRecords: maxRecords(),
    chains: Object.keys(chains).length,
    oldestSeq: acts.length ? acts[0].seq : 0,
    newestSeq: seq,
    byType: byType, byMode: byMode, byOutcome: byOutcome, byProtocol: byProtocol
  };
  log.debug("Leaving summary(). " + out.held + " act(s) over " + out.chains +
            " chain(s).");
  return out;
}

// Every DISTINCT chain, newest act first, with how many acts are on it and how
// they came out.
//
// This is the table the visualisation will be drawn from and it is built here
// rather than in admin.js for the reason every other view function moved into
// this layer: what counts as one chain is a statement about the store, and a
// second opinion about it in the renderer is the drift this codebase keeps
// warning about. admin.js renders what it is handed.
function chainList(rows) {
  log.debug("Entering chainList().");
  const source = rows || list();
  const byKey = new Map();
  source.forEach(function (row) {
    let chain = byKey.get(row.chainKey);
    if (!chain) {
      chain = {
        chainKey: row.chainKey,
        protocol: row.protocol, type: row.type, typeLabel: row.typeLabel,
        mode: row.mode,
        initial: row.initial, intermediary: row.intermediary, target: row.target,
        acts: 0, issued: 0, refused: 0,
        firstAt: row.at, lastAt: row.at,
        // The most recent explanation, whichever kind it was. A chain that was
        // refused four times and then worked should say how it was authorized,
        // not why it used to fail — `source` is newest first, so the first row
        // seen is the latest act and nothing below overwrites it.
        authorizedBy: row.authorizedBy, reason: row.reason
      };
      byKey.set(row.chainKey, chain);
    }
    chain.acts++;
    if (row.outcome === 'issued') chain.issued++; else chain.refused++;
    chain.firstAt = Math.min(chain.firstAt, row.at);
    chain.lastAt = Math.max(chain.lastAt, row.at);
  });
  const out = Array.from(byKey.values());
  log.debug("Leaving chainList(). " + out.length + " chain(s).");
  return out;
}

module.exports = {
  MODES: MODES,
  MODE_IDS: MODE_IDS,
  TYPES: TYPES,
  TYPE_IDS: TYPE_IDS,
  OUTCOMES: OUTCOMES,
  ROLES: ROLES,
  ROLE_IDS: ROLE_IDS,
  record: record,
  list: list,
  chainList: chainList,
  summary: summary,
  maxRecords: maxRecords
};
