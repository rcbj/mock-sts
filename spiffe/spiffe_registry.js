'use strict';
//
// File: spiffe_registry.js
//
// ---------------------------------------------------------------------------
// REGISTRATION ENTRIES AND ATTESTED AGENTS, AND THE DIRECTORY IS THEIR STORE.
//
// A registration entry says "a workload matching these selectors, under this
// parent, gets this SPIFFE ID". It is the single most important object in a
// SPIFFE deployment: the Workload API answers out of it, the SPIRE Server API's
// Entry service is CRUD over it, and `/admin/spiffe/entries` is a third door
// onto the same store.
//
// It is a LIBRARY (rule 3): it registers no route and requires `helpers.js`,
// `config.js`, `audit.js` and `spiffe_id.js` — none of which requires it back.
// `ldap_server.js` fills its `setDirectory()` slot at ITS require time, which is
// the same inversion `applications.js` and `vc_claims.js` use and for the same
// reason: a require reaching that module from here would drag every `/ldap`
// route to the front of the express router, and `GET /sts-metadata` is built by
// walking that router.
//
// ---------------------------------------------------------------------------
// THE DIVISION IS EXACTLY `applications.js`'s, DELIBERATELY
//
// THIS module owns what an entry IS — the schema, both conversions, what may be
// changed — and `ldap_server.js` owns WHERE the containers are, how an entry is
// created, and what the cap is. Neither knows the other's half. That division
// is worth copying rather than inventing a new one, because it is what makes
// three doors onto one store possible:
//
//   * `ldapmodify` against `ou=spiffe`
//   * a form on `/admin/spiffe/entries`
//   * `POST /admin-api/spiffe/entries/{action}`, and the SPIRE Server API's
//     `BatchCreateEntry` / `BatchUpdateEntry` / `BatchDeleteEntry`
//
// **THERE IS NO MAP SHADOWING THE ENTRIES AND THERE MUST NOT BE ONE.** Every
// read is a directory read. That is what makes an `ldapmodify` of
// `spiffeX509SvidTtl` change the lifetime of the NEXT SVID the Workload API
// hands out, with nothing to invalidate and no cache to be stale. On a mock
// whose store is a Map in this process there is nothing to gain by a second
// one, and everything to lose: two stores each look correct alone and never see
// each other.
//
// ---------------------------------------------------------------------------
// TWO CONTAINERS, NOT ONE, AND THEY HOLD DIFFERENT KINDS OF THING
//
// `ou=entries,ou=spiffe` holds registration entries — configuration, written by
// an operator or an API, which decides what gets issued.
//
// `ou=agents,ou=spiffe` holds attested agents — a RECORD of something that
// happened, written by this service when an agent attests. The same split
// `applications.js` draws between what an application may DO and what it HAS
// DONE, and it is why `EDITABLE` below covers the first container and not the
// second: a form that could rewrite an agent's attestation type would make the
// page lie about this service's own behaviour, indistinguishably from the
// recording being broken.
//
// Both are OUTSIDE `ou=users`, and that matters for the same reason
// `ou=applications` is: `populateVcAttributes()` would give a registration entry
// a birthdate, and `/admin/groups` reports membership from there. Neither sweep
// touches this subtree.
//
// ---------------------------------------------------------------------------
// SELECTOR MATCHING, WHICH IS THE ONE PIECE OF REAL LOGIC IN HERE
//
// SPIRE's rule: an entry matches a workload when the ENTRY'S selectors are a
// SUBSET of the workload's. Not equality, and not intersection. A workload
// attested as `unix:uid:1000`, `unix:gid:1000`, `unix:path:/bin/app` matches an
// entry asking for `unix:uid:1000` alone — the entry states a minimum the
// workload must meet. Reading it as equality means almost nothing ever matches;
// reading it as intersection means an entry asking for two selectors is
// satisfied by a workload that has one of them, which hands out identities.
//
// **Nothing in this service actually attests a workload**, so on the Workload
// API that rule is not what decides an answer — see `spiffe_workload.js`. It is
// implemented and used by the SPIRE Server API's `GetAuthorizedEntries` and by
// the console's "which entries would this workload match" view, because a
// client author debugging their selectors needs a server that computes the same
// thing SPIRE would.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const { log } = require('../common/helpers');
const config = require('../common/config');
const audit = require('../common/audit');
const spiffeId = require('./spiffe_id');
// ---------------------------------------------------------------------------
// WHY THIS FILE KNOWS ABOUT THE PEOPLE CONTAINER AT ALL.
//
// It does not, and that is the point of reaching it through here.
// `ldap_server.js` grows an entry under `ou=users` for every identity this
// trust domain issues an X509-SVID to, and the three things below are the only
// three in this service that end — or restore — an identity's ability to obtain
// one. Somebody reading that entry has to be able to see it; nothing else can
// tell them.
//
// `admin_stats.js` is the funnel, exactly as it is for an authentication and an
// issuance, and this is a PLAIN REQUIRE in the ordinary direction rather than a
// slot. Rule 3e's test, applied both ways round: that module registers no route
// and does not require this one, so requiring it closes no cycle and moves no
// route. The `setDirectory()` slot this file already has would have been the
// other candidate and is the wrong one — it is the SPIFFE containers' store,
// and `ou=users` is not in them.
//
// **THIS IS NOT REVOCATION AND MUST NOT BE DESCRIBED AS ANY.** SPIFFE has none;
// see `applySpiffeCredentialStatus()` in `ldap_server.js`, which is where the
// whole argument is written down, and `GET /spiffe`, which states it as a thing
// this service deliberately does not do. Nothing here refuses a certificate,
// nothing publishes a serial, and an SVID already issued goes on verifying
// until it expires.
// ---------------------------------------------------------------------------
const stats = require('../common/admin_stats');

function maxEntries() { return config.value('spiffe.maxEntries'); }
function maxAgents() { return config.value('spiffe.maxAgents'); }

// ---------------------------------------------------------------------------
// THE SCHEMA.
//
// `node-ldapjs` has no schema subsystem and it is a submodule this repository
// does not modify, so — exactly as in `applications.js` — there is nothing to
// register this with. The table IS the definition: an entry is built by WALKING
// it, `GET /ldap/spiffe` publishes it, and an attribute not in it is REFUSED
// rather than written.
//
// `multi` accumulates and `single` is assigned. Getting that backwards on the
// SVID counter would grow one value per issuance, which is the trap
// `applyVcAttributes()`'s second rule is about.
//
// Where a registered object class fits it is used. Nothing standard has a
// SPIFFE ID or a selector on it, so `spiffeRegistrationEntry` and `spiffeAgent`
// are invented — this service's own names, in the way `x509subject`,
// `didSubject` and every `app*` attribute already are.
// ---------------------------------------------------------------------------
const SCHEMA = {
  objectClasses: [
    { name: 'top', where: 'RFC 4512', standard: true,
      what: 'The abstract class every entry carries.' },
    { name: 'applicationProcess', where: 'RFC 4519 section 3.3', standard: true,
      what: 'The one REGISTERED class that fits: it brings cn and description, ' +
            'so the NAME of a registration entry is a standard attribute even ' +
            'though nothing else about it can be. The same class ' +
            'ou=applications uses, for the same reason.' },
    { name: 'spiffeRegistrationEntry', where: 'this service', standard: false,
      what: 'INVENTED. No registered LDAP schema has a SPIFFE ID, a parent ID ' +
            'or a selector — SPIRE keeps its entries in SQL and nothing else ' +
            'keeps them anywhere — so there was nothing to borrow.' },
    { name: 'spiffeAgent', where: 'this service', standard: false,
      what: 'INVENTED, for the same reason, on the entries under ou=agents.' }
  ],
  attributes: [
    // --- identity ---------------------------------------------------------
    { name: 'spiffeEntryId', kind: 'single', from: 'this registry', editable: false,
      what: 'THE KEY: the entry id, which is what the SPIRE Server API calls ' +
            '`id` and what BatchUpdateEntry and BatchDeleteEntry name. ' +
            'Generated here as 32 hex characters and never reused. The ' +
            'entry\'s own cn is a shortened form of it, so this is the ' +
            'attribute to search on — the arrangement appIdentifier already ' +
            'has one container over.' },
    { name: 'cn', kind: 'single', from: 'this registry', standard: true,
      editable: false,
      what: 'The RDN value: the entry id.' },
    { name: 'spiffeId', kind: 'single', from: 'the caller', editable: true,
      what: 'THE IDENTITY THIS ENTRY GRANTS — the SPIFFE ID a matching ' +
            'workload is issued. Refused if it is not a valid SPIFFE ID, if ' +
            'it belongs to another trust domain, or if it is under the ' +
            'reserved /spire path.' },
    { name: 'spiffeParentId', kind: 'single', from: 'the caller', editable: true,
      what: 'WHO MAY ISSUE IT: the SPIFFE ID of the agent (or of this server) ' +
            'that this entry hangs beneath. A real deployment uses it to ' +
            'decide which agent may hand out which identity. Nothing here ' +
            'enforces it — no agent is authenticated — so it is recorded, ' +
            'reported and used for GetAuthorizedEntries, and nothing else.' },
    { name: 'spiffeSelector', kind: 'multi', from: 'the caller', editable: true,
      what: 'One value per selector, written `type:value` — `unix:uid:1000`, ' +
            '`k8s:ns:default`, `docker:label:app:web`. The type is everything ' +
            'before the FIRST colon and the value is the whole rest, colons ' +
            'included, which is why they are stored as one string rather ' +
            'than as a pair: splitting on every colon is how ' +
            '`docker:label:app:web` becomes a selector nobody wrote.' },

    // --- what gets issued -------------------------------------------------
    { name: 'spiffeX509SvidTtl', kind: 'single', from: 'the caller', editable: true,
      what: 'The lifetime in seconds of the X509-SVIDs this entry produces. ' +
            'Absent or 0 means spiffe.svidTtl.' },
    { name: 'spiffeJwtSvidTtl', kind: 'single', from: 'the caller', editable: true,
      what: 'The same for JWT-SVIDs. Absent or 0 means spiffe.jwtSvidTtl.' },
    { name: 'spiffeDnsName', kind: 'multi', from: 'the caller', editable: true,
      what: 'DNS subjectAltNames added to the SVID beside the SPIFFE ID. What ' +
            'makes an SVID usable by TLS software that checks a hostname and ' +
            'cannot read a SPIFFE ID.' },
    { name: 'spiffeFederatesWith', kind: 'multi', from: 'the caller', editable: true,
      what: 'Trust domain names whose bundles are handed to a workload holding ' +
            'this identity — X509SVIDResponse.federated_bundles. A name with ' +
            'no bundle here is recorded and simply contributes nothing, ' +
            'because a federation relationship configured before the bundle ' +
            'arrives is the ordinary order of events.' },
    { name: 'spiffeHint', kind: 'single', from: 'the caller', editable: true,
      what: 'The operator\'s guidance when a workload gets more than one SVID ' +
            '— `internal`, `external`. Passed through to the Workload API ' +
            'verbatim; nothing here reads it.' },
    { name: 'spiffeAdmin', kind: 'single', from: 'the caller', editable: true,
      what: 'TRUE where the holder may call the SPIRE Server API\'s ' +
            'administrative methods. RECORDED AND NOT ENFORCED, like every ' +
            'other authorization fact in this service: no call here is ' +
            'refused for want of it.' },
    { name: 'spiffeDownstream', kind: 'single', from: 'the caller', editable: true,
      what: 'TRUE where the holder is a downstream SPIRE server that may ask ' +
            'for an intermediate CA (NewDownstreamX509CA). Recorded, not ' +
            'enforced.' },
    { name: 'spiffeStoreSvid', kind: 'single', from: 'the caller', editable: true,
      what: 'TRUE where the SVID is to be written to an SVID store plugin ' +
            'rather than handed to the workload. Recorded and not acted on — ' +
            'this service has no store plugins.' },
    { name: 'spiffeEntryExpiresAt', kind: 'single', from: 'the caller', editable: true,
      what: 'When the ENTRY itself stops applying, as seconds since the epoch. ' +
            'Different from an SVID lifetime: this retires the registration. ' +
            'An expired entry is kept and reported as expired rather than ' +
            'deleted, because an entry that vanished is indistinguishable ' +
            'from one nobody created.' },

    // --- what has happened ------------------------------------------------
    { name: 'spiffeRevisionNumber', kind: 'single', from: 'this registry',
      editable: false,
      what: 'Incremented on every change. The SPIRE Server API publishes it ' +
            'and an agent uses it to tell "the entry I hold is current" from ' +
            '"I hold an entry".' },
    { name: 'spiffeOrigin', kind: 'single', from: 'this registry', editable: false,
      what: 'How this entry got here: `seed`, `console`, `api`, `grpc`, ' +
            '`auto` (invented for a workload that matched nothing) or ' +
            '`ldap`. What tells an invented entry from one somebody meant.' },
    { name: 'spiffeSvidsIssued', kind: 'single', from: 'this registry',
      editable: false,
      what: 'How many SVIDs have been issued against this entry. ASSIGNED on ' +
            'every change — a counter that accumulated values would be ' +
            'nonsense — and a live number in a directory entry, which a real ' +
            'directory would not hold.' },
    { name: 'spiffeLastSvidAt', kind: 'single', from: 'this registry',
      editable: false,
      what: 'GeneralizedTime, the most recent issuance against it.' },
    { name: 'spiffeCreatedAt', kind: 'single', from: 'this registry',
      editable: false,
      what: 'GeneralizedTime. Beside the entry\'s own createTimestamp because ' +
            'the SPIRE Server API publishes `created_at` as a number and a ' +
            'reader should be able to see both are the same moment.' },
    { name: 'description', kind: 'multi', from: 'this registry', standard: true,
      editable: false,
      what: 'One line saying where this entry came from.' },

    // --- agents (ou=agents) -----------------------------------------------
    { name: 'spiffeAgentId', kind: 'single', from: 'the agent', editable: false,
      what: 'THE KEY of an agent entry: the agent\'s own SPIFFE ID, always ' +
            'under the reserved /spire/agent path.' },
    { name: 'spiffeAttestationType', kind: 'single', from: 'the agent',
      editable: false,
      what: 'The node attestor the agent said it used — `join_token`, `k8s_psat`, ' +
            '`aws_iid`, anything. TAKEN ON TRUST AND NEVER VERIFIED, which is ' +
            'the whole of what this service does about node attestation.' },
    { name: 'spiffeAgentSelector', kind: 'multi', from: 'the agent',
      editable: false,
      what: 'The selectors the attestation produced. Invented from what the ' +
            'agent sent, for the same reason.' },
    { name: 'spiffeAgentBanned', kind: 'single', from: 'this registry',
      editable: false,
      what: 'TRUE where BanAgent was called. A banned agent is REFUSED at ' +
            'AttestAgent and RenewAgent — one of the few refusals in this ' +
            'service — because an unbannable agent makes the ban button a lie.' },
    { name: 'spiffeAgentCanReattest', kind: 'single', from: 'the agent',
      editable: false,
      what: 'Whether the attestor can be run again without an operator. ' +
            'Reported to the agent, which decides what to do about it.' },
    { name: 'spiffeAgentSvidHash', kind: 'single', from: 'this registry',
      editable: false,
      what: 'SHA-256 over the DER of the agent\'s current SVID, which is what ' +
            'spire.api.types.Agent carries and how an operator tells two ' +
            'agents with one identity apart.' },
    { name: 'spiffeAgentExpiresAt', kind: 'single', from: 'this registry',
      editable: false,
      what: 'When that SVID expires, as seconds since the epoch.' },
    { name: 'spiffeFirstSeen', kind: 'single', from: 'this registry',
      editable: false,
      what: 'GeneralizedTime, when this agent first attested.' },
    { name: 'spiffeLastSeen', kind: 'single', from: 'this registry',
      editable: false,
      what: 'GeneralizedTime, the most recent time.' },
    { name: 'spiffeAttestations', kind: 'single', from: 'this registry',
      editable: false,
      what: 'How many times it has attested or renewed. ASSIGNED, not ' +
            'accumulated.' }
  ]
};

// The editable set, DECLARED rather than derived — the same rule
// `applications.js`'s EDITABLE table follows, and drawn in the same place.
// Declared is what the entry may DO; derived is what HAPPENED. A form that
// could rewrite `spiffeSvidsIssued` would make the page lie about this
// service's own behaviour, indistinguishably from the recording being broken.
// `ldapmodify` still reaches everything: refusing it HERE is the difference
// between offering an operation and merely not preventing it.
const EDITABLE = SCHEMA.attributes.filter(function (a) { return a.editable === true; })
  .map(function (a) { return a.name; });

const BY_LOWER_NAME = {};
SCHEMA.attributes.forEach(function (a) { BY_LOWER_NAME[a.name.toLowerCase()] = a; });

// Every attribute lookup goes through here, because names arrive canonically
// spelled on the way OUT of the directory and lower-cased in the store. An
// index assuming either produces a record with an empty identifier rather than
// an error — the defect `applications.js` names in its own header.
function byLowerName(attributes, name) {
  if (!attributes) return [];
  const key = String(name).toLowerCase();
  const found = attributes[key] !== undefined ? attributes[key] : attributes[name];
  if (found === undefined) return [];
  return Array.isArray(found) ? found : [found];
}

function firstValue(attributes, name) {
  const values = byLowerName(attributes, name);
  return values.length ? String(values[0]) : '';
}

function boolValue(attributes, name) {
  return /^true$/i.test(firstValue(attributes, name));
}

function intValue(attributes, name) {
  const n = parseInt(firstValue(attributes, name), 10);
  return Number.isFinite(n) ? n : 0;
}

// ---------------------------------------------------------------------------
// THE DIRECTORY SLOT.
//
// Filled by `ldap_server.js` at its require time. Until it is, every read here
// answers empty and every write is refused — which is the correct behaviour
// during startup rather than a failure, since nothing can have asked for an
// SVID before the service is listening. It is LOGGED at warn if a write is
// attempted, because "the registry is empty and nothing says why" is the
// symptom of this slot never being filled, and it has happened before in this
// repository (see the note at the top of applications.js).
// ---------------------------------------------------------------------------
let directory = null;

function setDirectory(fns) {
  log.debug('Entering setDirectory().');
  directory = fns || null;
  log.debug('Leaving setDirectory(). The SPIFFE registry ' +
            (directory ? 'now has' : 'no longer has') + ' a store.');
}

function haveDirectory(what) {
  if (directory) return true;
  log.warn('spiffe: ' + what + ' was attempted before ldap_server.js filled ' +
           'the registry\'s directory slot; nothing was stored. This is a ' +
           'require-order problem, not a caller problem.');
  return false;
}

// ---------------------------------------------------------------------------
// SELECTORS.
//
// One string, `type:value`, split on the FIRST colon only. `docker:label:app:web`
// is type `docker` and value `label:app:web`; splitting on every colon gives a
// selector nobody wrote and an entry that never matches.
// ---------------------------------------------------------------------------
function parseSelector(text) {
  const value = String(text == null ? '' : text).trim();
  const colon = value.indexOf(':');
  if (colon <= 0 || colon === value.length - 1) return null;
  return { type: value.slice(0, colon), value: value.slice(colon + 1) };
}

function selectorText(selector) {
  if (!selector) return '';
  if (typeof selector === 'string') return selector.trim();
  const type = String(selector.type || '').trim();
  const value = String(selector.value || '').trim();
  if (!type || !value) return '';
  return type + ':' + value;
}

// SPIRE's matching rule, written once: the ENTRY'S selectors must all be
// present on the workload. See the header for why it is neither equality nor
// intersection.
function selectorsMatch(entrySelectors, workloadSelectors) {
  const have = {};
  (workloadSelectors || []).forEach(function (s) {
    const text = selectorText(s);
    if (text) have[text] = true;
  });
  const wanted = (entrySelectors || []).map(selectorText).filter(Boolean);
  // An entry with NO selectors matches everything, which is SPIRE's behaviour
  // and is worth stating: it is how a catch-all entry is written, and it is
  // also the shape of an entry somebody created and forgot to finish.
  if (!wanted.length) return true;
  for (let i = 0; i < wanted.length; i++) {
    if (!have[wanted[i]]) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// A RECORD, IN BOTH DIRECTIONS.
//
// `recordFromAttributes()` reads a directory entry into the object every caller
// works with; `attributesFromRecord()` writes one back. Two functions rather
// than a shared table walk, because they are not symmetrical: the read hands
// back the WHOLE ENTRY (dn, operational attributes, the lot — the shape
// `applications.js`'s `readApplication()` settled on, and for the same reason:
// THE DN IS NOT AN ATTRIBUTE, so a caller handed only attributes cannot learn
// where the entry lives) and the write speaks only in attributes.
// ---------------------------------------------------------------------------
function recordFromEntry(entry) {
  if (!entry) return null;
  const a = entry.attributes || {};
  const record = {
    id: firstValue(a, 'spiffeEntryId') || firstValue(a, 'cn'),
    dn: entry.dn,
    spiffeId: firstValue(a, 'spiffeId'),
    parentId: firstValue(a, 'spiffeParentId'),
    selectors: byLowerName(a, 'spiffeSelector').map(function (s) {
      return parseSelector(s);
    }).filter(Boolean),
    x509SvidTtl: intValue(a, 'spiffeX509SvidTtl'),
    jwtSvidTtl: intValue(a, 'spiffeJwtSvidTtl'),
    dnsNames: byLowerName(a, 'spiffeDnsName').map(String),
    federatesWith: byLowerName(a, 'spiffeFederatesWith').map(String),
    hint: firstValue(a, 'spiffeHint'),
    admin: boolValue(a, 'spiffeAdmin'),
    downstream: boolValue(a, 'spiffeDownstream'),
    storeSvid: boolValue(a, 'spiffeStoreSvid'),
    expiresAt: intValue(a, 'spiffeEntryExpiresAt'),
    revisionNumber: intValue(a, 'spiffeRevisionNumber'),
    origin: firstValue(a, 'spiffeOrigin') || 'unstated',
    svidsIssued: intValue(a, 'spiffeSvidsIssued'),
    lastSvidAt: firstValue(a, 'spiffeLastSvidAt'),
    createdAt: firstValue(a, 'spiffeCreatedAt') || entry.createdAt || '',
    modifiedAt: entry.modifiedAt || '',
    attributes: a
  };
  // Derived and never stored, for the reason a stored copy of a derived fact is
  // always the one that goes stale: an entry whose expiry passed is EXPIRED,
  // and computing it on read means it becomes true at the right moment with
  // nothing having to sweep.
  record.expired = record.expiresAt > 0 &&
                   record.expiresAt < Math.floor(Date.now() / 1000);
  return record;
}

function attributesFromRecord(record, existing) {
  const now = generalizedTime();
  const previous = existing || {};
  const attributes = {
    objectclass: ['top', 'applicationProcess', 'spiffeRegistrationEntry'],
    cn: [record.id],
    spiffeentryid: [record.id],
    spiffeid: [record.spiffeId],
    spiffeparentid: [record.parentId],
    spiffecreatedat: [firstValue(previous, 'spiffeCreatedAt') || now],
    spiffeorigin: [record.origin || firstValue(previous, 'spiffeOrigin') || 'unstated'],
    spifferevisionnumber: [String(record.revisionNumber || 0)],
    spiffesvidsissued: [String(record.svidsIssued || 0)],
    description: [record.description ||
                  firstValue(previous, 'description') ||
                  'A SPIFFE registration entry.']
  };
  const selectors = (record.selectors || []).map(selectorText).filter(Boolean);
  if (selectors.length) attributes.spiffeselector = selectors;
  const dnsNames = (record.dnsNames || []).map(function (n) {
    return String(n || '').trim();
  }).filter(Boolean);
  if (dnsNames.length) attributes.spiffednsname = dnsNames;
  const federates = (record.federatesWith || []).map(function (n) {
    return String(n || '').trim().toLowerCase();
  }).filter(Boolean);
  if (federates.length) attributes.spiffefederateswith = federates;
  if (record.x509SvidTtl) attributes.spiffex509svidttl = [String(record.x509SvidTtl)];
  if (record.jwtSvidTtl) attributes.spiffejwtsvidttl = [String(record.jwtSvidTtl)];
  if (record.hint) attributes.spiffehint = [String(record.hint)];
  if (record.admin) attributes.spiffeadmin = ['TRUE'];
  if (record.downstream) attributes.spiffedownstream = ['TRUE'];
  if (record.storeSvid) attributes.spiffestoresvid = ['TRUE'];
  if (record.expiresAt) attributes.spiffeentryexpiresat = [String(record.expiresAt)];
  if (record.lastSvidAt) attributes.spiffelastsvidat = [record.lastSvidAt];
  return attributes;
}

function generalizedTime(when) {
  const d = when ? new Date(when) : new Date();
  function two(n) { return (n < 10 ? '0' : '') + n; }
  return d.getUTCFullYear() + two(d.getUTCMonth() + 1) + two(d.getUTCDate()) +
         two(d.getUTCHours()) + two(d.getUTCMinutes()) + two(d.getUTCSeconds()) + 'Z';
}

function newEntryId() {
  return crypto.randomBytes(16).toString('hex');
}

// ---------------------------------------------------------------------------
// WHAT MAY BE ASKED FOR.
//
// The one place a proposed entry is checked, so that the console form, the
// management API, the SPIRE Server API and an auto-created entry are all held
// to the same rules — and so that the reasons are written once, in the words a
// caller should see.
//
// Three refusals, and each is about an identifier this service would otherwise
// mint for two different reasons:
//
//   * not a valid SPIFFE ID at all;
//   * a SPIFFE ID in ANOTHER trust domain, which this authority cannot sign
//     for. It is the specific error a federation misconfiguration produces and
//     it deserves its own sentence rather than a generic refusal;
//   * a SPIFFE ID under `/spire`, which is reserved for the server and its
//     agents.
//
// Everything else is permitted, including a duplicate SPIFFE ID: two entries
// granting one identity under different parents is a real and useful
// configuration, and SPIRE allows it.
// ---------------------------------------------------------------------------
function checkRecord(record, trustDomain) {
  log.debug('Entering checkRecord(). spiffeId=' + (record || {}).spiffeId);
  const errors = [];
  const parsed = spiffeId.parse((record || {}).spiffeId);
  if (!parsed.ok) {
    errors.push('spiffeId: ' + parsed.reason);
  } else if (parsed.trustDomain !== trustDomain) {
    errors.push('spiffeId: ' + parsed.id + ' is in the trust domain ' +
                parsed.trustDomain + ', and this service is the issuing ' +
                'authority for ' + trustDomain + ' only. It cannot sign an ' +
                'SVID naming somebody else\'s trust domain — that is what ' +
                'federation is for, and a federated bundle is somebody ELSE\'s ' +
                'authority, published here.');
  } else if (spiffeId.isReservedPath(parsed.id)) {
    errors.push('spiffeId: ' + parsed.id + ' is under the reserved /spire ' +
                'path, which belongs to this server and the agents it ' +
                'attests. An entry there would be an identifier issued for ' +
                'two unrelated reasons.');
  }
  const parent = (record || {}).parentId;
  if (parent) {
    const parsedParent = spiffeId.parse(parent);
    if (!parsedParent.ok) {
      errors.push('parentId: ' + parsedParent.reason);
    } else if (parsedParent.trustDomain !== trustDomain) {
      errors.push('parentId: a parent is an agent or a server in this trust ' +
                  'domain; ' + parsedParent.id + ' is in ' +
                  parsedParent.trustDomain + '.');
    }
  } else {
    errors.push('parentId: an entry hangs beneath a parent — this server ' +
                '(' + spiffeId.serverId(trustDomain) + ') or an agent under ' +
                'it. SPIRE requires one and so does this.');
  }
  const selectors = (record || {}).selectors || [];
  selectors.forEach(function (selector, index) {
    if (!selectorText(selector)) {
      errors.push('selector ' + (index + 1) + ': a selector is written ' +
                  'type:value, and both halves are required.');
    }
  });
  log.debug('Leaving checkRecord(). ' + errors.length + ' problem(s).');
  return { ok: !errors.length, errors: errors };
}

// ---------------------------------------------------------------------------
// READING.
// ---------------------------------------------------------------------------
function allEntries() {
  log.debug('Entering allEntries().');
  if (!directory) {
    log.debug('Leaving allEntries(). No store yet.');
    return [];
  }
  const rows = directory.allEntries().map(recordFromEntry).filter(Boolean);
  rows.sort(function (a, b) {
    return String(a.spiffeId).localeCompare(String(b.spiffeId)) ||
           String(a.id).localeCompare(String(b.id));
  });
  log.debug('Leaving allEntries(). ' + rows.length + ' entry/entries.');
  return rows;
}

function entryById(id) {
  if (!directory) return null;
  const key = String(id == null ? '' : id).trim();
  if (!key) return null;
  return recordFromEntry(directory.readEntry(key));
}

// Every entry granting a given SPIFFE ID. A list rather than one, because two
// entries may grant one identity under different parents.
function entriesForSpiffeId(id) {
  const wanted = String(id == null ? '' : id).trim();
  return allEntries().filter(function (entry) { return entry.spiffeId === wanted; });
}

// Every entry a workload with these selectors would match, under this parent.
// `parentId` is optional: omitted, the parent is not considered, which is what
// the console's "what would match" view wants and what this service's own
// Workload API — which attests nobody — needs.
function entriesForWorkload(selectors, parentId) {
  log.debug('Entering entriesForWorkload().');
  const parent = String(parentId == null ? '' : parentId).trim();
  const rows = allEntries().filter(function (entry) {
    if (entry.expired) return false;
    if (parent && entry.parentId !== parent) return false;
    return selectorsMatch(entry.selectors, selectors);
  });
  log.debug('Leaving entriesForWorkload(). ' + rows.length + ' match(es).');
  return rows;
}

function entryCount() {
  return directory ? directory.countEntries() : 0;
}

// ---------------------------------------------------------------------------
// WRITING.
//
// `origin` says how the entry got here and is what tells an invented entry from
// one somebody meant. Every writer passes its own, and there is no default: a
// caller that forgot is a caller whose entries are indistinguishable from
// auto-created ones on the page whose whole job is to tell them apart.
// ---------------------------------------------------------------------------
function createEntry(record, origin, trustDomain, actor) {
  log.debug('Entering createEntry(). spiffeId=' + (record || {}).spiffeId);
  if (!haveDirectory('creating a registration entry')) {
    log.debug('Leaving createEntry(). No store.');
    return { ok: false, errors: ['The registry has no store yet.'] };
  }
  const checked = checkRecord(record, trustDomain);
  if (!checked.ok) {
    log.debug('Leaving createEntry(). Refused.');
    return { ok: false, errors: checked.errors };
  }
  if (entryCount() >= maxEntries()) {
    log.debug('Leaving createEntry(). Full.');
    return { ok: false, errors: ['This registry holds its maximum of ' +
      maxEntries() + ' entry/entries (spiffe.maxEntries).'] };
  }
  const id = String(record.id || '').trim() || newEntryId();
  if (entryById(id)) {
    log.debug('Leaving createEntry(). Duplicate id.');
    return { ok: false, errors: ['A registration entry with the id ' + id +
      ' is already here.'] };
  }
  const full = Object.assign({}, record, {
    id: id, origin: origin, revisionNumber: 1, svidsIssued: 0,
    description: 'Created by ' + origin + '.'
  });
  const written = directory.writeEntry(id, attributesFromRecord(full, null));
  if (!written) {
    log.debug('Leaving createEntry(). The store refused it.');
    return { ok: false, errors: ['The directory would not hold it; see the ' +
      'service log.'] };
  }
  auditEntry('spiffe.entry.create', id, full, actor,
             'A SPIFFE registration entry for ' + full.spiffeId + ' was created');
  // The other direction, and it is needed because both of these are reversible:
  // an identity whose entries were all deleted and which is then registered
  // again can be issued SVIDs again, and a directory entry still saying
  // `revoked` would be the stalest thing on the page. It writes NOTHING where
  // this directory has no entry for the identity — which is the ordinary case
  // for a brand-new registration, since nothing has been issued to it yet.
  stats.recordCredentialStatus(full.spiffeId, 'active', {
    reason: 'a SPIFFE registration entry naming this identity (' + id +
            ') exists, so an SVID can be issued for it'
  });
  log.debug('Leaving createEntry(). id=' + id);
  return { ok: true, errors: [], id: id, entry: entryById(id) };
}

function updateEntry(id, changes, trustDomain, actor) {
  log.debug('Entering updateEntry(). id=' + id);
  if (!haveDirectory('updating a registration entry')) {
    log.debug('Leaving updateEntry(). No store.');
    return { ok: false, errors: ['The registry has no store yet.'] };
  }
  const existing = entryById(id);
  if (!existing) {
    log.debug('Leaving updateEntry(). Not here.');
    return { ok: false, errors: ['No registration entry has the id ' + id + '.'] };
  }
  const merged = Object.assign({}, existing, changes || {}, {
    id: existing.id,
    origin: existing.origin,
    svidsIssued: existing.svidsIssued,
    lastSvidAt: existing.lastSvidAt,
    revisionNumber: (existing.revisionNumber || 0) + 1
  });
  const checked = checkRecord(merged, trustDomain);
  if (!checked.ok) {
    log.debug('Leaving updateEntry(). Refused.');
    return { ok: false, errors: checked.errors };
  }
  directory.writeEntry(id, attributesFromRecord(merged, existing.attributes));
  auditEntry('spiffe.entry.update', id, merged, actor,
             'The SPIFFE registration entry for ' + merged.spiffeId + ' was updated');
  log.debug('Leaving updateEntry(). revision=' + merged.revisionNumber);
  return { ok: true, errors: [], id: id, entry: entryById(id) };
}

function deleteEntry(id, actor) {
  log.debug('Entering deleteEntry(). id=' + id);
  if (!haveDirectory('deleting a registration entry')) {
    log.debug('Leaving deleteEntry(). No store.');
    return { ok: false, errors: ['The registry has no store yet.'] };
  }
  const existing = entryById(id);
  if (!existing) {
    log.debug('Leaving deleteEntry(). Not here.');
    return { ok: false, errors: ['No registration entry has the id ' + id + '.'] };
  }
  directory.deleteEntry(id);
  auditEntry('spiffe.entry.delete', id, existing, actor,
             'The SPIFFE registration entry for ' + existing.spiffeId + ' was deleted');
  // AND THE HOLDER'S OWN ENTRY, IF THIS WAS THE LAST WAY IT COULD BE ISSUED
  // ONE. The qualifier is the whole of the check and getting it wrong would be
  // silent: SEVERAL registration entries may name one SPIFFE ID — different
  // parents, different selectors, that is an ordinary SPIRE arrangement — and
  // marking the identity revoked because one of them went would say a workload
  // is dead while it is still collecting an SVID every half hour.
  const remaining = entriesForSpiffeId(existing.spiffeId).length;
  if (!remaining) {
    stats.recordCredentialStatus(existing.spiffeId, 'revoked', {
      reason: 'the last SPIFFE registration entry naming this identity (' + id +
              ') was deleted, so no further SVID can be issued for it here. ' +
              'Nothing was revoked — SPIFFE has no revocation — and any SVID ' +
              'already issued verifies until it expires.'
    });
  } else {
    log.debug('deleteEntry(): ' + remaining + ' other registration entry/' +
              'entries still name ' + existing.spiffeId + ', so its directory ' +
              'entry is left active.');
  }
  log.debug('Leaving deleteEntry(). Removed.');
  return { ok: true, errors: [], id: id };
}

// The counter, touched at the moment an SVID is actually minted against an
// entry. A read-modify-write like every other change here, and it deliberately
// does NOT bump the revision number: a revision is a change to what the entry
// SAYS, and an agent that re-fetched every entry because one of them had been
// used would poll this service into the ground.
function noteSvidIssued(id) {
  log.debug('Entering noteSvidIssued(). id=' + id);
  if (!directory) {
    log.debug('Leaving noteSvidIssued(). No store.');
    return;
  }
  const existing = entryById(id);
  if (!existing) {
    log.debug('Leaving noteSvidIssued(). The entry is gone.');
    return;
  }
  const merged = Object.assign({}, existing, {
    svidsIssued: (existing.svidsIssued || 0) + 1,
    lastSvidAt: generalizedTime()
  });
  directory.writeEntry(id, attributesFromRecord(merged, existing.attributes));
  log.debug('Leaving noteSvidIssued(). ' + merged.svidsIssued + ' issued.');
}

// ---------------------------------------------------------------------------
// AGENTS.
//
// The other container, and a RECORD rather than configuration. Everything here
// is written by this service when an agent attests; nothing about an agent is
// editable, for the reason stated in the header.
//
// **ATTESTATION IS NOT CHECKED.** Whatever the agent says its attestor was and
// whatever selectors it claims are written down as claimed. That is this
// service's posture everywhere — it authenticates nobody — and it is stated on
// `/spiffe`, on `/admin/spiffe` and in the attribute descriptions above rather
// than left to be inferred from a mock that never says no.
//
// The ONE refusal is a BAN, and it exists so that the ban button is not a lie:
// a banned agent is refused at AttestAgent and at RenewAgent.
// ---------------------------------------------------------------------------
function allAgents() {
  log.debug('Entering allAgents().');
  if (!directory) {
    log.debug('Leaving allAgents(). No store yet.');
    return [];
  }
  const rows = directory.allAgents().map(agentFromEntry).filter(Boolean);
  rows.sort(function (a, b) { return String(a.id).localeCompare(String(b.id)); });
  log.debug('Leaving allAgents(). ' + rows.length + ' agent(s).');
  return rows;
}

function agentFromEntry(entry) {
  if (!entry) return null;
  const a = entry.attributes || {};
  return {
    id: firstValue(a, 'spiffeAgentId'),
    dn: entry.dn,
    attestationType: firstValue(a, 'spiffeAttestationType'),
    selectors: byLowerName(a, 'spiffeAgentSelector').map(parseSelector).filter(Boolean),
    banned: boolValue(a, 'spiffeAgentBanned'),
    canReattest: boolValue(a, 'spiffeAgentCanReattest'),
    svidHash: firstValue(a, 'spiffeAgentSvidHash'),
    expiresAt: intValue(a, 'spiffeAgentExpiresAt'),
    firstSeen: firstValue(a, 'spiffeFirstSeen'),
    lastSeen: firstValue(a, 'spiffeLastSeen'),
    attestations: intValue(a, 'spiffeAttestations'),
    attributes: a
  };
}

function agentById(id) {
  if (!directory) return null;
  const key = String(id == null ? '' : id).trim();
  if (!key) return null;
  return agentFromEntry(directory.readAgent(key));
}

function agentCount() {
  return directory ? directory.countAgents() : 0;
}

// Record an attestation. Creates the agent entry on first sight and updates it
// afterwards, which is the `seen()` shape `applications.js` uses — one function
// for both, because two would eventually disagree about what a first sighting
// records.
function recordAttestation(id, detail) {
  log.debug('Entering recordAttestation(). id=' + id);
  if (!haveDirectory('recording an agent attestation')) {
    log.debug('Leaving recordAttestation(). No store.');
    return null;
  }
  const info = detail || {};
  const existing = agentById(id);
  if (existing && existing.banned) {
    // The one refusal. Returned rather than thrown so the caller can answer
    // with the gRPC status its own service uses.
    log.debug('Leaving recordAttestation(). The agent is banned.');
    return { banned: true, agent: existing };
  }
  if (!existing && agentCount() >= maxAgents()) {
    // The OLDEST is dropped rather than this one refused. An agent that cannot
    // attest cannot do anything at all, and the id comes off whatever the
    // caller sent — so a load generator inventing agent names must not be able
    // to lock out the one that matters.
    const oldest = allAgents().sort(function (a, b) {
      return String(a.lastSeen).localeCompare(String(b.lastSeen));
    })[0];
    if (oldest) {
      log.warn('spiffe: ou=agents holds its maximum of ' + maxAgents() +
               ' (spiffe.maxAgents); dropping the least recently seen agent ' +
               oldest.id + ' to make room for ' + id + '.');
      directory.deleteAgent(oldest.id);
    }
  }
  const now = generalizedTime();
  const attributes = {
    objectclass: ['top', 'applicationProcess', 'spiffeAgent'],
    cn: [agentCnFor(id)],
    spiffeagentid: [id],
    spiffeattestationtype: [String(info.attestationType || 'unknown')],
    spiffefirstseen: [existing ? existing.firstSeen || now : now],
    spiffelastseen: [now],
    spiffeattestations: [String(((existing || {}).attestations || 0) + 1)],
    spiffeagentbanned: [existing && existing.banned ? 'TRUE' : 'FALSE'],
    spiffeagentcanreattest: [info.canReattest ? 'TRUE' : 'FALSE'],
    description: ['A SPIFFE agent, attested with ' +
                  String(info.attestationType || 'an unstated attestor') + '.']
  };
  const selectors = (info.selectors || []).map(selectorText).filter(Boolean);
  if (selectors.length) attributes.spiffeagentselector = selectors;
  if (info.svidHash) attributes.spiffeagentsvidhash = [String(info.svidHash)];
  if (info.expiresAt) attributes.spiffeagentexpiresat = [String(info.expiresAt)];
  directory.writeAgent(id, attributes);
  audit.audit({
    action: existing ? 'spiffe.agent.attest' : 'spiffe.agent.create',
    actor: '', protocol: 'SPIFFE', channel: 'grpc', target: id,
    summary: 'The SPIFFE agent ' + id + (existing ? ' attested again' : ' attested for the first time'),
    detail: { attestationType: String(info.attestationType || 'unknown'),
              selectors: selectors.length }
  });
  // It attested, so it is not banned and it is not unknown — the two things
  // that would have made it `revoked`. Written on EVERY attestation rather than
  // only on the first, and cheaply: the directory does nothing when the entry
  // already says this, which is how applySpiffeCredentialStatus() ends.
  stats.recordCredentialStatus(id, 'active', {
    reason: 'this agent attested successfully, so it may be issued an SVID'
  });
  log.debug('Leaving recordAttestation(). ' + (existing ? 'Updated.' : 'Created.'));
  return { banned: false, agent: agentById(id), created: !existing };
}

function setAgentBanned(id, banned, actor) {
  log.debug('Entering setAgentBanned(). id=' + id + ', banned=' + banned);
  if (!haveDirectory('banning an agent')) {
    log.debug('Leaving setAgentBanned(). No store.');
    return { ok: false, errors: ['The registry has no store yet.'] };
  }
  const existing = agentById(id);
  if (!existing) {
    log.debug('Leaving setAgentBanned(). Not here.');
    return { ok: false, errors: ['No agent has the id ' + id + '.'] };
  }
  const attributes = Object.assign({}, existing.attributes);
  attributes.spiffeagentbanned = [banned ? 'TRUE' : 'FALSE'];
  directory.writeAgent(id, attributes);
  audit.audit({
    action: banned ? 'spiffe.agent.ban' : 'spiffe.agent.unban',
    actor: actor || '', protocol: 'SPIFFE', channel: 'internal', target: id,
    summary: 'The SPIFFE agent ' + id + ' was ' + (banned ? 'banned' : 'unbanned'),
    detail: {}
  });
  // A ban is the ONE refusal this module makes, so it is the one place where
  // "this identity can no longer get a credential here" is exactly true rather
  // than nearly: a banned agent is refused at AttestAgent and at RenewAgent.
  // An agent's id IS its SPIFFE ID, so there is nothing to look up.
  stats.recordCredentialStatus(id, banned ? 'revoked' : 'active', {
    reason: banned
      ? 'this agent is banned on this server, so AttestAgent and RenewAgent ' +
        'refuse it and no further SVID can be issued for it. Nothing was ' +
        'revoked — SPIFFE has no revocation — and any SVID already issued ' +
        'verifies until it expires.'
      : 'this agent was unbanned, so it may attest and renew again'
  });
  log.debug('Leaving setAgentBanned().');
  return { ok: true, errors: [], id: id, agent: agentById(id) };
}

function deleteAgent(id, actor) {
  log.debug('Entering deleteAgent(). id=' + id);
  if (!haveDirectory('deleting an agent')) {
    log.debug('Leaving deleteAgent(). No store.');
    return { ok: false, errors: ['The registry has no store yet.'] };
  }
  const existing = agentById(id);
  if (!existing) {
    log.debug('Leaving deleteAgent(). Not here.');
    return { ok: false, errors: ['No agent has the id ' + id + '.'] };
  }
  directory.deleteAgent(id);
  audit.audit({
    action: 'spiffe.agent.delete', actor: actor || '', protocol: 'SPIFFE',
    channel: 'internal', target: id,
    summary: 'The SPIFFE agent ' + id + ' was deleted', detail: {}
  });
  // Weaker than a ban and recorded the same way, because the OUTCOME for the
  // holder is the same until it comes back: RenewAgent refuses an agent this
  // server has no record of, naming AttestAgent as the way back. A
  // re-attestation restores it, which is why recordAttestation() writes the
  // other value.
  stats.recordCredentialStatus(id, 'revoked', {
    reason: 'this agent was deleted from the server, so RenewAgent refuses it ' +
            'and it must call AttestAgent again before it can be issued ' +
            'another SVID. Nothing was revoked — SPIFFE has no revocation — ' +
            'and any SVID already issued verifies until it expires.'
  });
  log.debug('Leaving deleteAgent(). Removed.');
  return { ok: true, errors: [], id: id };
}

// An agent's RDN. A SPIFFE ID is far too long and holds characters a DN would
// have to escape, so the entry is named by a digest of it with the identifier
// whole on the entry as `spiffeAgentId` — the arrangement `didPlan()` settled
// on for a DID-named person, and for the same reason.
function agentCnFor(id) {
  return 'agent-' + crypto.createHash('sha256').update(String(id))
    .digest('hex').slice(0, 12);
}

function auditEntry(action, id, record, actor, summary) {
  audit.audit({
    action: action, actor: actor || '', protocol: 'SPIFFE',
    channel: 'internal', target: record.spiffeId || id,
    summary: summary,
    // NO SECRET IS EVER IN A REGISTRATION ENTRY — there is nothing here but
    // identifiers, selectors and lifetimes — so the detail can name what
    // changed. `audit.js`'s no-credential rule is untouched by this.
    detail: { entryId: id, parentId: record.parentId || '',
              selectors: (record.selectors || []).length }
  });
}

// ---------------------------------------------------------------------------
// SEEDING.
//
// Three entries at startup, the way `ldap_server.js` seeds three people, and
// for the same reason: a service whose Workload API answers with an empty list
// on a fresh start teaches a client author nothing, and the first thing they
// will do is assume they have misconfigured something.
//
// The three are chosen to exercise different client paths rather than to be
// realistic:
//
//   * `/workload`         one plain identity, no hint. The simple case.
//   * `/ns/default/sa/web`  a Kubernetes-shaped ID with a `hint` and DNS names,
//                           so a client that picks an SVID by hint has one to
//                           pick, and a TLS stack that checks a hostname works.
//   * `/ns/default/sa/db`   a second one with a different hint, because
//                           "more than one SVID came back" is a path most
//                           client libraries have and few callers ever run.
//
// Seeded ONCE, and only where the container is empty: a restart re-seeds
// because nothing here is persisted, but an operator who deleted all three
// meant it, and re-creating them on the next request would make the delete
// button appear not to work.
// ---------------------------------------------------------------------------
function seed(trustDomain) {
  log.debug('Entering seed().');
  if (!directory) {
    log.debug('Leaving seed(). No store.');
    return 0;
  }
  if (entryCount() > 0) {
    log.debug('Leaving seed(). The container already holds entries.');
    return 0;
  }
  const parent = spiffeId.serverId(trustDomain);
  const rows = [
    { spiffeId: spiffeId.make(trustDomain, '/workload'), parentId: parent,
      selectors: [{ type: 'unix', value: 'uid:1000' }],
      description: 'Seeded at startup.' },
    { spiffeId: spiffeId.make(trustDomain, '/ns/default/sa/web'), parentId: parent,
      selectors: [{ type: 'k8s', value: 'ns:default' },
                  { type: 'k8s', value: 'sa:web' }],
      dnsNames: ['web.default.svc', 'web.default.svc.cluster.local'],
      hint: 'external', description: 'Seeded at startup.' },
    { spiffeId: spiffeId.make(trustDomain, '/ns/default/sa/db'), parentId: parent,
      selectors: [{ type: 'k8s', value: 'ns:default' },
                  { type: 'k8s', value: 'sa:db' }],
      hint: 'internal', description: 'Seeded at startup.' }
  ];
  let made = 0;
  rows.forEach(function (row) {
    const result = createEntry(row, 'seed', trustDomain, '');
    if (result.ok) made++;
    else log.warn('spiffe: a seed entry could not be created: ' +
                  result.errors.join('; '));
  });
  log.info('spiffe: ' + made + ' registration entry/entries were seeded. They ' +
           'are ordinary entries — delete them and they stay deleted until a ' +
           'restart.');
  log.debug('Leaving seed(). ' + made + ' created.');
  return made;
}

module.exports = {
  SCHEMA: SCHEMA,
  EDITABLE: EDITABLE,
  setDirectory: setDirectory,
  parseSelector: parseSelector,
  selectorText: selectorText,
  selectorsMatch: selectorsMatch,
  checkRecord: checkRecord,
  newEntryId: newEntryId,
  generalizedTime: generalizedTime,
  agentCnFor: agentCnFor,
  allEntries: allEntries,
  entryById: entryById,
  entriesForSpiffeId: entriesForSpiffeId,
  entriesForWorkload: entriesForWorkload,
  entryCount: entryCount,
  createEntry: createEntry,
  updateEntry: updateEntry,
  deleteEntry: deleteEntry,
  noteSvidIssued: noteSvidIssued,
  allAgents: allAgents,
  agentById: agentById,
  agentCount: agentCount,
  recordAttestation: recordAttestation,
  setAgentBanned: setAgentBanned,
  deleteAgent: deleteAgent,
  seed: seed,
  maxEntries: maxEntries,
  maxAgents: maxAgents
};
