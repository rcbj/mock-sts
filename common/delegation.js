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
  log.debug("Entering party().");
  const info = detail || {};
  const presented = String(info.presented == null ? '' : info.presented).trim();
  const application = String(info.application == null ? '' : info.application).trim();
  log.debug("Leaving party().");
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
  log.debug("Entering recordUnguarded().");
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
  log.debug("Leaving recordUnguarded().");
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

// ---------------------------------------------------------------------------
// THE PICTURE, AS A MODEL. Nodes, edges, and what came out of each edge.
//
// The header of chainList() above says a chain is "what the visualisation will
// be drawn from — one edge per row". That was half right and this function is
// the other half: a chain has THREE parties and therefore up to TWO edges, and
// the boxes are shared between chains — the whole reason to draw a picture at
// all is that `frontend` appearing as the intermediary of six chains is ONE box
// with six lines leaving it rather than six rows a reader has to notice begin
// with the same word.
//
// So this walks the ACTS rather than the chains, and it is deliberately NOT
// built on chainList()'s answer even though it groups by the same key. Two
// things it needs are the two things that function drops on purpose: the
// CREDENTIALS (the picture is asked to say what was issued, and a chain has the
// credentials taken out of it) and the spread of one identity across roles.
// Reading them back off a chain would mean putting them into a chain, which
// would make that shape a worse answer to the question it does answer.
//
// FOUR DECISIONS IN HERE ARE JUDGEMENTS RATHER THAN MECHANICS, and each is one
// somebody would otherwise have to reverse-engineer from the drawing:
//
// **A NODE IS AN IDENTITY, NOT A ROLE.** Two parties merge into one box when
// `key || presented || application` matches, which is the same expression
// chainKeyOf() collapses on — so a box in the picture and a column in the table
// cannot come to disagree about who is who. It means a party that is the target
// of one chain and the intermediary of the next is ONE box with a line in and a
// line out, which is exactly the middle tier a reader came here to find. It also
// means the node carries `roles`, because "this box was an initial identity 40
// times and a target once" is the sentence that says which box to look at first.
//
// **AN ABSENT PARTY IS NOT A BOX, AND THE EDGE JUMPS IT.** A forwarded
// ticket-granting ticket has NO intermediary and cannot have one — the client
// hands the ticket to whichever service it chooses and this KDC is never told
// which — so the chain is drawn as one edge from the initial identity straight
// to the target, carrying `skipped: ['intermediary']`. The alternative was a
// shared "(nobody named)" box, and that would be a lie of exactly the kind a
// picture makes easy: every unconstrained delegation in the process would
// converge on one node, which reads as a party they have in common when what
// they have in common is that there is nothing to name.
//
// **A SELF-EDGE IS A FACT ABOUT THE BOX, NOT A LOOP ON IT.** S4U2Self names the
// requester as the intermediary AND as the target, because the ticket is to
// itself. Drawn as an arrow leaving a box and re-entering it, that is a picture
// of nothing; it is recorded as `selfTarget` on the node instead and the drawing
// says so in words. The initial-to-intermediary edge still carries the whole
// act, which is where the interesting half of S4U2Self is anyway.
//
// **THE ISSUER IS IN THE PICTURE AND IT IS NOT A PARTY.** Every edge here exists
// because THIS service issued or refused a credential, and a picture that left
// it out would show a delegation happening between three strangers. It is one
// node — `kind: 'sts'`, carrying the TRUST REALM, because a realm is a whole
// logical copy of this service and two realms' pictures are two different
// services' pictures — with an edge to whoever ASKED. That is the intermediary
// where there is one and the initial identity where there is not, which is the
// forwarded-TGT case again: the client asking to have its own ticket forwarded
// is the party this service handed something to.
//
// `rows` is a list of acts newest first — list()'s answer, or the filtered
// subset a page is showing. Everything below is derived from it and nothing is
// read out of the store, so a caller can draw the picture of any subset it can
// filter.
// ---------------------------------------------------------------------------

// The identity of a party FOR THE PICTURE, and it is chainKeyOf()'s expression
// with TWO deliberate differences. Both were found by drawing an S4U2Self.
//
// **The '(none)' fallback is gone**, because here an unnamed party must yield
// nothing at all: a falsy answer is what tells the caller to draw no box rather
// than to draw an anonymous one, and one shared '(none)' box would make every
// unconstrained delegation in the process appear to converge on a party they
// have in common.
//
// **The APPLICATION identifier is normalised too**, which chainKeyOf() does not
// do and does not need to. A party carries `key` — identityKeyOf()'s answer —
// only when something was PRESENTED; a target names an application and presents
// nothing, so its identifier arrives exactly as the protocol spelled it. On an
// S4U2Self that is the same principal twice: `HTTP/frontend@EXAMPLE.COM` as the
// intermediary, normalised to `HTTP/frontend` because it presented a ticket, and
// `HTTP/frontend@EXAMPLE.COM` raw as the target, because a ticket was issued TO
// it. Unnormalised, the picture draws the requester and the service it asked for
// a ticket to ITSELF as two boxes with a line between them, which is a drawing
// of something that did not happen. **Two spellings of one identity is two
// people** is the rule the directory already follows at `dnRfc4514()` and at
// `userFor()`; this is the same rule one layer up.
//
// The table is deliberately left alone: it shows both spellings side by side in
// two columns, where seeing them is the point, and changing `chainKey` would
// change what `/admin-api/delegation` calls a chain.
function nodeIdOf(party) {
  if (party.key) {
    return party.key;
  }
  if (party.application) {
    return stats.identityKeyOf(party.application);
  }
  return party.presented || '';
}

// The three roles of one chain, in the order a request moves through them, with
// the ones nobody named left out. What comes back is what the edges are drawn
// between — consecutive survivors — and `skipped` on each edge names the roles
// that were jumped, so the drawing can say "through an intermediary this service
// was never told the name of" rather than silently connecting two boxes that
// never spoke.
function presentParties(row) {
  const out = [];
  ROLE_IDS.forEach(function (role) {
    const party = row[role];
    const id = party ? nodeIdOf(party) : '';
    if (id) {
      out.push({ role: role, id: id, party: party });
    }
  });
  return out;
}

// One credential kind, accumulated. The identifiers are kept up to a handful
// because the picture quotes one or two beside a line and the list beneath it
// quotes them all — and a jti is 22 characters, so an edge carrying forty of
// them would be a label wider than the diagram.
const MAX_IDENTIFIERS_PER_KIND = 6;

function foldCredentials(into, list) {
  log.debug("Entering foldCredentials().");
  (list || []).forEach(function (one) {
    const kind = one.kind || '(unnamed)';
    let held = into[kind];
    if (!held) {
      held = { kind: kind, count: 0, identifiers: [], moreIdentifiers: 0,
               notes: [] };
      into[kind] = held;
    }
    held.count++;
    if (one.identifier) {
      if (held.identifiers.indexOf(one.identifier) >= 0) {
        // Already quoted. Not counted as "more", because more means what the cap
        // hid and this is the same credential seen twice.
      } else if (held.identifiers.length < MAX_IDENTIFIERS_PER_KIND) {
        held.identifiers.push(one.identifier);
      } else {
        held.moreIdentifiers++;
      }
    }
    // ONE note per kind rather than one per act: every S4U2Proxy row carries the
    // same sentence about the evidence ticket, and a label repeating it eleven
    // times would be eleven copies of the thing that does not vary.
    if (one.note && held.notes.indexOf(one.note) < 0 && held.notes.length < 3) {
      held.notes.push(one.note);
    }
  });
  log.debug("Leaving foldCredentials().");
}

function credentialList(folded) {
  return Object.keys(folded).map(function (kind) {
    return folded[kind];
  }).sort(function (a, b) {
    return b.count - a.count || a.kind.localeCompare(b.kind);
  });
}

// How many token rows the list beneath the picture carries. It is a cap on the
// LIST and not on the graph — every act is still counted into its edge — so what
// a reader loses when it bites is the individual identifiers of the oldest
// credentials. What was left off is COUNTED, for the reason the store counts
// what it dropped: a truncated list must say it was truncated.
const MAX_TOKEN_ROWS = 250;

function graph(rows) {
  log.debug("Entering graph().");
  const source = rows || list();
  const nodes = new Map();
  const edges = new Map();
  const tokens = [];
  let tokensLeftOff = 0;
  const chains = {};

  // The issuer's own node. Always present, including on an empty graph, because
  // "this service, in this realm, has issued nothing yet" is a picture worth
  // drawing and an empty document is not.
  //
  // Its id opens with a space so that it cannot collide with a party's: every
  // identity this service has ever been given is trimmed by party() before it
  // becomes a key, so no party can be called ' sts'.
  const realm = realms.current();
  const sts = {
    id: ' sts',
    kind: 'sts',
    realm: { id: realm.id, name: realm.name, isDefault: realms.isDefault(realm) },
    issuer: String(config.value('wstrust.issuer') || ''),
    roles: { initial: 0, intermediary: 0, target: 0 },
    acts: 0, issued: 0, refused: 0
  };
  nodes.set(sts.id, sts);

  function nodeFor(id, party) {
    log.debug("Entering nodeFor().");
    let node = nodes.get(id);
    if (!node) {
      node = {
        id: id,
        kind: 'party',
        // Unioned across every appearance rather than taken from the first: a
        // party can arrive as a bare name on one act and with its application
        // identifier on the next, and the box should carry both.
        key: '', presented: '', application: '',
        // What the party IS, in the protocol's own words, from the act that said
        // it first. They are per-role sentences, and the box's role is whichever
        // it played most, which is settled below.
        what: '',
        roles: { initial: 0, intermediary: 0, target: 0 },
        protocols: [],
        acts: 0, issued: 0, refused: 0,
        firstAt: 0, lastAt: 0,
        // Set when some act named this party as BOTH the intermediary and the
        // target of one chain. S4U2Self is the whole of why: the ticket is to
        // yourself, and an arrow leaving a box and coming back is a drawing of
        // nothing.
        selfTarget: false
      };
      nodes.set(id, node);
    }
    if (party) {
      if (party.key && !node.key) node.key = party.key;
      if (party.presented && !node.presented) node.presented = party.presented;
      if (party.application && !node.application) node.application = party.application;
      if (party.what && !node.what) node.what = party.what;
    }
    log.debug("Leaving nodeFor().");
    return node;
  }

  function edgeFor(id, seed) {
    log.debug("Entering edgeFor().");
    let edge = edges.get(id);
    if (!edge) {
      edge = Object.assign({
        id: id,
        acts: 0, issued: 0, refused: 0,
        firstAt: 0, lastAt: 0,
        authorizedBy: '', reason: '',
        consumedFold: {}, producedFold: {}
      }, seed);
      edges.set(id, edge);
    }
    log.debug("Leaving edgeFor().");
    return edge;
  }

  source.forEach(function (row) {
    chains[row.chainKey] = true;
    const present = presentParties(row);
    // Every party of the act, whether or not an edge reaches it. A target that
    // is the same box as the intermediary draws no edge and must still be a box.
    present.forEach(function (at) {
      const node = nodeFor(at.id, at.party);
      node.roles[at.role]++;
      node.acts++;
      if (row.outcome === 'issued') node.issued++; else node.refused++;
      node.firstAt = node.firstAt ? Math.min(node.firstAt, row.at) : row.at;
      node.lastAt = Math.max(node.lastAt, row.at);
      if (row.protocol && node.protocols.indexOf(row.protocol) < 0) {
        node.protocols.push(row.protocol);
      }
    });

    for (let i = 0; i + 1 < present.length; i++) {
      const from = present[i];
      const to = present[i + 1];
      if (from.id === to.id) {
        // S4U2Self, and anything else that reaches itself. Recorded on the box
        // and drawn as a note rather than as a loop — see the header.
        nodeFor(to.id, to.party).selfTarget = true;
        continue;
      }
      // The roles jumped between these two. presentParties() has already dropped
      // them, so this is the only place the fact survives, and it is the
      // difference between "alice reached the back end" and "alice reached the
      // back end through something this KDC was never told the name of".
      const skipped = ROLE_IDS.slice(ROLE_IDS.indexOf(from.role) + 1,
                                    ROLE_IDS.indexOf(to.role));
      // The chain key is IN the edge id, so two chains that happen to share a
      // pair of boxes stay two lines. That is the same decision chainKeyOf()
      // makes about the mechanism: `alice -> frontend` by S4U2Proxy classic and
      // the same pair by RBCD are two arrangements of the same boxes, and one
      // line for both would hide the only difference.
      const edge = edgeFor(row.chainKey + ' | ' + from.role + ' > ' + to.role, {
        from: from.id, to: to.id,
        fromRole: from.role, toRole: to.role,
        // What this line MEANS, which is not the same on both halves of a chain.
        // The first is the DELEGATION relationship — who is acting for whom. The
        // second is the TRUST relationship — what the credential is for, which
        // is the question "what is this token's audience" asked as a picture.
        relation: to.role === 'target' ? 'reaches' : 'acts-for',
        skipped: skipped,
        chainKey: row.chainKey,
        protocol: row.protocol, type: row.type, typeLabel: row.typeLabel,
        mode: row.mode, spec: row.spec, policed: row.policed,
        // Carried so a line can be labelled with WHO it is about without the
        // renderer having to walk back to the chain: on a `reaches` edge the
        // interesting sentence is "as alice", and alice is not either end of it.
        subject: nodeIdOf(row.initial),
        actor: nodeIdOf(row.intermediary)
      });
      edge.acts++;
      if (row.outcome === 'issued') edge.issued++; else edge.refused++;
      edge.firstAt = edge.firstAt ? Math.min(edge.firstAt, row.at) : row.at;
      edge.lastAt = Math.max(edge.lastAt, row.at);
      // Newest first in `source`, so the FIRST explanation seen is the latest one
      // and nothing below overwrites it — the rule chainList() states.
      if (!edge.authorizedBy && row.authorizedBy) edge.authorizedBy = row.authorizedBy;
      if (!edge.reason && row.reason) edge.reason = row.reason;
      foldCredentials(edge.consumedFold, row.consumed);
      // What came OUT hangs on the edge that reaches the TARGET, because that is
      // what the credential is for. Hanging it on the acts-for edge as well would
      // count it twice in a picture whose whole claim is that each line says a
      // different thing — and where there is no target edge (nobody named the
      // target) the one edge there is carries it, or the drawing would show a
      // delegation that produced nothing.
      if (to.role === 'target' || present.length < 3) {
        foldCredentials(edge.producedFold, row.produced);
      }
    }

    // WHO ASKED, which is who this service handed something to. The intermediary
    // where the chain has one; the initial identity where it does not, which is
    // the forwarded-TGT case — the client asking for its own ticket to be made
    // forwardable.
    const asker = nodeIdOf(row.intermediary) || nodeIdOf(row.initial);
    if (asker) {
      const edge = edgeFor(' sts > ' + asker, {
        from: sts.id, to: asker,
        fromRole: 'issuer', toRole: 'asker',
        relation: 'issued',
        skipped: [],
        chainKey: '', protocols: [],
        protocol: '', type: '', typeLabel: '',
        mode: '', spec: '', policed: false,
        subject: '', actor: asker
      });
      edge.acts++;
      if (row.outcome === 'issued') edge.issued++; else edge.refused++;
      edge.firstAt = edge.firstAt ? Math.min(edge.firstAt, row.at) : row.at;
      edge.lastAt = Math.max(edge.lastAt, row.at);
      // Every family that asked, not the last one: this is the one line in the
      // picture that can carry three protocols at once, and it is worth seeing
      // that it does.
      if (row.protocol && edge.protocols.indexOf(row.protocol) < 0) {
        edge.protocols.push(row.protocol);
      }
      foldCredentials(edge.producedFold, row.produced);
      sts.acts++;
      if (row.outcome === 'issued') sts.issued++; else sts.refused++;
    }

    // WHAT WAS ISSUED, one row per credential, newest first because `source` is.
    // Refusals produce nothing by definition, so they are not here — which is why
    // the count under this list and the count of acts disagree, and why the page
    // says so rather than leaving the difference to be noticed.
    if (row.outcome === 'issued') {
      (row.produced || []).forEach(function (one) {
        if (tokens.length >= MAX_TOKEN_ROWS) {
          tokensLeftOff++;
          return;
        }
        tokens.push({
          seq: row.seq, at: row.at,
          kind: one.kind, identifier: one.identifier, note: one.note,
          protocol: row.protocol, type: row.type, typeLabel: row.typeLabel,
          mode: row.mode,
          chainKey: row.chainKey,
          subject: nodeIdOf(row.initial),
          actor: nodeIdOf(row.intermediary),
          target: nodeIdOf(row.target)
        });
      });
    }
  });

  const nodeList = Array.from(nodes.values()).map(function (node) {
    if (node.kind === 'sts') {
      return node;
    }
    // The role the box played MOST, which is what a drawing needs in order to
    // decide what to call it when the directory knows nothing about it. A tie
    // goes to the earlier role, which is the order a request moves through them
    // — a party that was an initial identity twice and a target twice is drawn
    // as the initial identity, because that is the end a reader starts from.
    let chief = '';
    let best = 0;
    ROLE_IDS.forEach(function (role) {
      if (node.roles[role] > best) {
        best = node.roles[role];
        chief = role;
      }
    });
    node.chiefRole = chief;
    return node;
  });

  const edgeList = Array.from(edges.values()).map(function (edge) {
    const out = Object.assign({}, edge);
    out.consumed = credentialList(edge.consumedFold);
    out.produced = credentialList(edge.producedFold);
    delete out.consumedFold;
    delete out.producedFold;
    return out;
  });

  const out = {
    realm: sts.realm,
    issuer: sts.issuer,
    nodes: nodeList,
    edges: edgeList,
    tokens: tokens,
    tokensLeftOff: tokensLeftOff,
    maxTokenRows: MAX_TOKEN_ROWS,
    acts: source.length,
    chains: Object.keys(chains).length
  };
  log.debug("Leaving graph(). " + out.nodes.length + " node(s), " +
            out.edges.length + " edge(s), " + out.tokens.length +
            " token(s) listed, " + tokensLeftOff + " left off.");
  return out;
}

// ---------------------------------------------------------------------------
// ONE CHAIN'S ACTS, for the page that draws a single relationship.
//
// `chainKey` is the identity of a chain and there is nothing else an act
// carries that could name one: a positional index into `chainList()` would move
// the moment the cap dropped an act, so a link somebody put in a ticket would
// come back describing a different relationship rather than nothing — which is
// the failure mode a stale link must never have.
//
// It is here rather than in the console for the reason `chainList()` gives:
// what counts as one chain is a statement about the store, and a `filter()` in
// a renderer would be a second opinion about it.
// ---------------------------------------------------------------------------
function actsOfChain(rows, chainKey) {
  const wanted = String(chainKey == null ? '' : chainKey);
  if (!wanted) {
    return [];
  }
  return (rows || list()).filter(function (row) {
    return row.chainKey === wanted;
  });
}

// ---------------------------------------------------------------------------
// THE IDENTITIES THAT APPEAR IN A DELEGATION, IN WHATEVER ROLE.
//
// The mirror of the three functions above, keyed on the PARTY rather than on
// the application it acted through, and it is here for the same reason they
// are: what counts as one party is a statement about this store, and a second
// opinion about it in a renderer is the drift this file's headers keep warning
// about.
//
// **THE KEY IS `nodeIdOf()`'s ANSWER AND DELIBERATELY NOT `applicationKeyOf()`'s**,
// which is the same distinction those three make read the other way round. An
// application is keyed on the identifier a protocol NAMED — the `client_id`, the
// `AppliesTo`, the SPN — because "everything delegated through this client" is a
// question about the client. A person is keyed on the identity they PRESENTED,
// normalised by `identityKeyOf()`, because `alice`, `alice@STS.MOCK` and
// `urn:sts-mock:user:alice` are one person and the console files them under one
// row on /admin/users. Using one key for both would lose exactly the case each
// is for: an RFC 8693 exchange's intermediary is an ACTOR (a party) beside a
// `client_id` (an application), and they are two different strings naming two
// different things in one column.
//
// So this key is the same one `/admin/users` uses, which is what lets a link
// from that page reach this store and get the acts naming that person — in any
// of the three roles, because the whole point is that somebody's name appears
// in a delegation they were never present for.
// ---------------------------------------------------------------------------

// Which roles this identity played in this ONE act, and it can genuinely be two
// — a forwarded ticket-granting ticket names the client as the initial identity
// and this service was never told who it was handed to, and an S4U2Self names
// its requester as the intermediary and as the target. An array for that reason
// and not for symmetry with applicationRolesIn().
function identityRolesIn(row, key) {
  log.debug("Entering identityRolesIn().");
  const wanted = String(key == null ? '' : key);
  const out = [];
  if (!wanted) {
    log.debug("Leaving identityRolesIn().");
    return out;
  }
  ROLE_IDS.forEach(function (role) {
    const party = row[role];
    if (party && nodeIdOf(party) === wanted) {
      out.push(role);
    }
  });
  log.debug("Leaving identityRolesIn().");
  return out;
}

// Every act this identity took part in, whatever role it played. The filter is
// `identityRolesIn()` rather than a comparison of its own, for the reason
// `actsForApplication()` gives: the page that says which role somebody played
// and the page that decides whether to show the act cannot come to disagree.
function actsForIdentity(rows, key) {
  const wanted = String(key == null ? '' : key);
  if (!wanted) {
    return [];
  }
  return (rows || list()).filter(function (row) {
    return identityRolesIn(row, wanted).length > 0;
  });
}

// Every distinct identity among these acts, with what it did. It is what the
// PERSON chooser is built from, the way `applicationList()` is what the
// application chooser is built from — and the counts are why it is a list
// rather than a set of names.
//
// **AN IDENTITY HERE IS NOT NECESSARILY ONE `/admin/users` HAS A ROW FOR, and
// that is the interesting half rather than an edge case.** A delegation names
// somebody who was not present and proved nothing — that is what S4U2Self and
// OnBehalfOf ARE — so a refused S4U2Self for a person who has never been near
// this service puts their name here and nowhere else. The console unions this
// list with the identity register for exactly that reason and marks which side
// each name came from.
function identityList(rows) {
  log.debug("Entering identityList().");
  const source = rows || list();
  const byKey = new Map();
  source.forEach(function (row) {
    ROLE_IDS.forEach(function (role) {
      const party = row[role];
      const key = party ? nodeIdOf(party) : '';
      if (!key) {
        return;
      }
      let entry = byKey.get(key);
      if (!entry) {
        entry = {
          key: key,
          // The first spelling seen, which — `source` being newest first — is
          // the most recent one. Every other spelling is beside it, for the
          // reason applicationList() keeps them: a collapse is something a
          // reader has to be able to SEE rather than take on trust.
          presented: party.presented || party.application || key,
          spellings: [],
          roles: { initial: 0, intermediary: 0, target: 0 },
          protocols: [],
          chainKeys: [],
          acts: 0, issued: 0, refused: 0, credentials: 0,
          firstAt: 0, lastAt: 0,
          // Set when this party ALSO named an application — the middle tier
          // that is a person and an application at once. It is what tells the
          // console to draw the second link.
          application: ''
        };
        byKey.set(key, entry);
      }
      const spelling = party.presented || party.application;
      if (spelling && entry.spellings.indexOf(spelling) < 0) {
        entry.spellings.push(spelling);
      }
      if (!entry.application && party.application) {
        entry.application = party.application;
      }
      entry.roles[role]++;
      if (entry.chainKeys.indexOf(row.chainKey) < 0) {
        entry.chainKeys.push(row.chainKey);
      }
      if (row.protocol && entry.protocols.indexOf(row.protocol) < 0) {
        entry.protocols.push(row.protocol);
      }
    });
    // The act's OWN counters once per identity rather than once per role, for
    // applicationList()'s reason: an S4U2Self names its requester twice, and
    // counting it twice would leave the total under the chooser disagreeing
    // with the number of acts on the page above it.
    const seen = {};
    ROLE_IDS.forEach(function (role) {
      const party = row[role];
      const key = party ? nodeIdOf(party) : '';
      if (!key || seen[key]) {
        return;
      }
      seen[key] = true;
      const entry = byKey.get(key);
      entry.acts++;
      if (row.outcome === 'issued') {
        entry.issued++;
        entry.credentials += (row.produced || []).length;
      } else {
        entry.refused++;
      }
      entry.firstAt = entry.firstAt ? Math.min(entry.firstAt, row.at) : row.at;
      entry.lastAt = Math.max(entry.lastAt, row.at);
    });
  });
  const out = Array.from(byKey.values()).map(function (entry) {
    entry.chains = entry.chainKeys.length;
    delete entry.chainKeys;
    return entry;
  }).sort(function (a, b) {
    return b.acts - a.acts || a.key.localeCompare(b.key);
  });
  log.debug("Leaving identityList(). " + out.length + " identity/identities.");
  return out;
}

// ---------------------------------------------------------------------------
// THE APPLICATIONS THAT APPEAR IN A DELEGATION, IN WHATEVER ROLE.
//
// **THE KEY IS THE APPLICATION IDENTIFIER AND DELIBERATELY NOT THE NODE ID.**
// That distinction is the whole of why these three functions are here rather
// than being a walk over `graph().nodes` in the console, and getting it wrong
// loses exactly the case the question is about.
//
// `nodeIdOf()` answers what a party IS — its normalised identity where it
// presented one, and its application identifier only where it presented
// nothing. For a Kerberos front end those are the same string. For an RFC 8693
// exchange they are not: the intermediary presented an actor whose `sub` is the
// node's id, and the APPLICATION it acted through is the `client_id` beside it.
// So a picker built on node ids would offer that client under the actor's name,
// or not at all — and "show me everything delegated through this client" is the
// question somebody actually arrives with.
//
// One identifier, normalised the way `nodeIdOf()` normalises an application, so
// that `HTTP/backend` and `HTTP/backend@EXAMPLE.COM` are ONE application and not
// two. **Two spellings of one identity is two people** is the rule the directory
// follows at `dnRfc4514()`; this is that rule applied to the other kind of
// party. Every spelling seen is kept beside the key, because the collapse is
// something a reader has to be able to SEE rather than take on trust — the same
// reason `party()` keeps `presented` next to `key`.
//
// An INITIAL identity is counted too, although no call site here names an
// application for one today. The model allows it, and a role that is counted
// only where it currently occurs is a page that would go quietly wrong the day
// a fourth mechanism was recorded.
// ---------------------------------------------------------------------------
function applicationKeyOf(identifier) {
  const raw = String(identifier == null ? '' : identifier).trim();
  return raw ? stats.identityKeyOf(raw) : '';
}

// Which roles this application played in this ONE act, and it can genuinely be
// two: an S4U2Self names the requester as the intermediary and as the target,
// which is the case that makes this an array rather than a string.
function applicationRolesIn(row, key) {
  log.debug("Entering applicationRolesIn().");
  const wanted = String(key == null ? '' : key);
  const out = [];
  if (!wanted) {
    log.debug("Leaving applicationRolesIn().");
    return out;
  }
  ROLE_IDS.forEach(function (role) {
    const party = row[role];
    if (party && applicationKeyOf(party.application) === wanted) {
      out.push(role);
    }
  });
  log.debug("Leaving applicationRolesIn().");
  return out;
}

// Every act this application took part in, whatever role it played. The filter
// is `applicationRolesIn()` rather than a comparison of its own, so the page
// that says which role it played and the page that decides whether to show the
// act cannot come to disagree.
function actsForApplication(rows, key) {
  const wanted = String(key == null ? '' : key);
  if (!wanted) {
    return [];
  }
  return (rows || list()).filter(function (row) {
    return applicationRolesIn(row, wanted).length > 0;
  });
}

// Every distinct application among these acts, with what it did. This is what
// the chooser on /admin/delegation is built from, and the counts are the reason
// it is a list rather than a bare set of names: "this client is in 40 acts as
// the intermediary and 1 as a target" is what tells somebody which of thirty
// applications to open first.
//
// `credentials` counts what was PRODUCED by the acts it took part in, not what
// was produced FOR it. The distinction matters and the page says it: a token
// produced by an act where this application was the intermediary was issued
// THROUGH it, and one produced where it was the target was issued FOR it. Both
// are "related to" it, which is the question being asked, and a count that
// silently meant one of them would be the wrong answer half the time.
function applicationList(rows) {
  log.debug("Entering applicationList().");
  const source = rows || list();
  const byKey = new Map();
  source.forEach(function (row) {
    ROLE_IDS.forEach(function (role) {
      const party = row[role];
      const key = party ? applicationKeyOf(party.application) : '';
      if (!key) {
        return;
      }
      let entry = byKey.get(key);
      if (!entry) {
        entry = {
          key: key,
          // The first spelling seen, which — `source` being newest first — is
          // the most recent one. It is what the chooser shows, and every other
          // spelling is beside it.
          identifier: party.application,
          spellings: [],
          roles: { initial: 0, intermediary: 0, target: 0 },
          protocols: [],
          chainKeys: [],
          acts: 0, issued: 0, refused: 0, credentials: 0,
          firstAt: 0, lastAt: 0,
          // Set when this application is ALSO a party that presented a
          // credential — the middle tier that is a person and an application at
          // once. The console draws two links for it and this is what tells it
          // to look.
          identityKey: ''
        };
        byKey.set(key, entry);
      }
      if (entry.spellings.indexOf(party.application) < 0) {
        entry.spellings.push(party.application);
      }
      if (!entry.identityKey && party.key) {
        entry.identityKey = party.key;
      }
      entry.roles[role]++;
      if (entry.chainKeys.indexOf(row.chainKey) < 0) {
        entry.chainKeys.push(row.chainKey);
      }
      if (row.protocol && entry.protocols.indexOf(row.protocol) < 0) {
        entry.protocols.push(row.protocol);
      }
    });
    // The act's OWN counters are added once per application rather than once per
    // role, or an S4U2Self — which names its requester twice — would report two
    // acts where there was one, and the total under the chooser would not add up
    // to the number of acts on the page above it.
    const seen = {};
    ROLE_IDS.forEach(function (role) {
      const party = row[role];
      const key = party ? applicationKeyOf(party.application) : '';
      if (!key || seen[key]) {
        return;
      }
      seen[key] = true;
      const entry = byKey.get(key);
      entry.acts++;
      if (row.outcome === 'issued') {
        entry.issued++;
        entry.credentials += (row.produced || []).length;
      } else {
        entry.refused++;
      }
      entry.firstAt = entry.firstAt ? Math.min(entry.firstAt, row.at) : row.at;
      entry.lastAt = Math.max(entry.lastAt, row.at);
    });
  });
  const out = Array.from(byKey.values()).map(function (entry) {
    entry.chains = entry.chainKeys.length;
    delete entry.chainKeys;
    return entry;
  }).sort(function (a, b) {
    // Busiest first, then by name, because the chooser is read top-down and the
    // application somebody is looking for is usually the one everything went
    // through.
    return b.acts - a.acts || a.key.localeCompare(b.key);
  });
  log.debug("Leaving applicationList(). " + out.length + " application(s).");
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
  actsOfChain: actsOfChain,
  // The three the application chooser and its page rest on. They are here
  // rather than in admin.js because "which application is this, and what role
  // did it play" is a statement about the store — see their header, and
  // chainList()'s, which makes the same argument about a chain.
  applicationKeyOf: applicationKeyOf,
  applicationRolesIn: applicationRolesIn,
  actsForApplication: actsForApplication,
  applicationList: applicationList,
  // And the three that mirror them for a PARTY rather than an application, plus
  // the function that decides what one IS. `nodeIdOf()` is exported because the
  // picture of one person (common/user_graph.js) draws boxes for parties this
  // store has never seen — an OAuth client a token names, a SAML audience — and
  // has to key them the same way this file does, or the two halves of one
  // diagram would put the same party in two boxes.
  nodeIdOf: nodeIdOf,
  identityRolesIn: identityRolesIn,
  actsForIdentity: actsForIdentity,
  identityList: identityList,
  graph: graph,
  summary: summary,
  maxRecords: maxRecords
};
