'use strict';
//
// File: claim_attributes.js
//
// ---------------------------------------------------------------------------
// WHICH LDAP ATTRIBUTES THE FIVE TOKEN, RESPONSE AND ASSERTION SETS CARRY.
//
// admin_stats.js already holds the five CUSTOM CLAIM sets — a name and a value
// somebody typed on /admin/claims, /admin/userinfo-claims or
// /admin/saml-attributes, with
// ${placeholders}. This holds the other half of those pages: a SELECTION out of
// the directory's user-object attribute catalogue, per set, whose value is not
// typed anywhere because it is read off that person's entry under ou=users.
//
// THREE PAGES SINCE 2026-08-26 AND STILL ONE SELECTION PER SET. The console
// shows the two JWT sets on /admin/claims, the UserInfo set on
// /admin/userinfo-claims and the two SAML ones on /admin/saml-attributes;
// nothing here knows that, and nothing here should — a per-page store would be
// the second store this whole arrangement exists to prevent, and the catalogue
// below is published by all three replies in full.
//
// The difference between the two halves is the whole reason this file exists.
// A typed claim is a constant (or a placeholder over the sign-in), and it says
// whatever the person at the keyboard said. An attribute claim says what the
// DIRECTORY says, so an `ldapmodify` on `uid=alice,ou=users` changes the next
// access token, and an LDAP client and an OIDC client pointed at this service
// are shown the same person. That is the thing worth exercising, and until now
// only a Verifiable Credential could do it.
//
// **The catalogue is vc_claims.js's and is not copied.** That module already
// holds every one of those attribute types, each spelled the way its schema
// document spells it, each with the OIDC claim it becomes and the conversion
// where the two differ (a generalized date is YYYYMMDD where a claim is
// YYYY-MM-DD). ldap_server.js already merges its spellings into the directory's
// canonical names. A second catalogue here would be a second list of spellings,
// which is one list that will eventually be wrong — and worse, the two pages
// would disagree about what `schacDateOfBirth` is called while both looked
// right on their own.
//
// So there are now THREE readers of that one catalogue and they choose from it
// independently, which is deliberate rather than accidental symmetry:
//
//   vc_claims.js's own selection   what an issued CREDENTIAL carries   /admin/vc
//   vc_verifier_config.js          what the mock Verifier ASKS FOR     /admin/vc-verifier-config
//   this file                      what a TOKEN carries                /admin/claims
//   this file (the same store)     what a USERINFO RESPONSE carries    /admin/userinfo-claims
//   this file (the same store)     what an ASSERTION carries           /admin/saml-attributes
//
// Keeping them separate is what makes "issue a credential carrying a claim the
// access token does not" and "ask for a claim nothing here issues" reachable.
// One page setting all three would make both impossible to produce, and those
// are the mismatches a client's error paths are built for.
//
// ---------------------------------------------------------------------------
// FOUR THINGS ARE LOAD-BEARING.
//
// **It is a LIBRARY (rule 3) and it registers no route**, so its position in the
// require order does not matter. It requires helpers.js, admin_stats.js,
// vc_claims.js and audit.js, and NONE of those requires it back — which is what
// keeps it out of the cycles rule 2 exists for. admin_stats.js in particular
// cannot require it: vc_claims.js requires admin_stats.js, so a require in that
// direction would close a loop and node would hand back a half-initialised
// module whose exports are undefined. The symptom would arrive later and
// somewhere else as something that is not a function.
//
// **So the merge into a token is INVERTED, the same way three other things in
// this service are.** admin_stats.js offers a slot — setAttributeResolver() —
// and this file fills it at ITS require time, exactly as helpers.js offers
// setJwtRecorder() and admin_stats.js offers setUserObserver(). The consequence
// is the one that matters: NO ISSUANCE SITE CHANGES. oauth2.js's two calls to
// stats.jwtClaims() and the two assertion builders' calls to
// stats.samlAttributes() are the same four lines they were, and the attribute
// claims arrive through them. Four call sites edited would have been four that
// drift, and a fifth added later that nobody remembers to edit.
//
// **NOTHING IS SELECTED ON A FRESH START, in any of the five sets.** That is not
// timidity, it is the only defensible default: this page changes what every
// client of this service receives, and a mock that started issuing a `birthdate`
// in every access token because a feature was added would break the tests of
// everyone who upgraded. /admin/vc's ten defaults are a different case — that
// page reproduces what its issuer already carried before it existed.
//
// **A hand-typed custom claim WINS over an attribute claim of the same name.**
// Somebody who typed `email = nobody@example.org` on the same page that has
// `mail` ticked has said something specific, and the specific thing wins over
// the general one. It is stated on the page and in the API's reply rather than
// left to be discovered, because the two halves are one screen apart and a
// silent precedence rule is the kind of thing that gets diagnosed as a bug in
// the directory.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');
// TRUST REALMS: the stores below are partitioned by realm. It requires
// config.js and nothing else here, so it cannot join a cycle and it registers
// no route, so its position is not a position at all.
const realms = require('./realms');
// The counters and the four claim sets. This is the module whose slot is filled
// at the bottom of this file, and the dependency runs in this direction only.
const stats = require('./admin_stats');
// The catalogue, the persona and the directory read. See the header: it is not
// copied, and the spellings live over there.
const vcClaims = require('../oid4vc/vc_claims');
// The event log. Every change here writes a row of its own, because the HTTP row
// app.js records for the same POST says that a claims page was posted to and not
// WHICH set gained WHICH attribute — see recordChange() below.
const audit = require('./audit');

// ---------------------------------------------------------------------------
// The catalogue, indexed.
//
// Built from the exported array rather than being a second table of names, for
// the reason in the header. Lower-cased keys because LDAP attribute
// descriptions are case-insensitive and the store lower-cases every name on the
// way in, so every lookup that could start from a stored entry has to start
// from the lower-cased form.
// ---------------------------------------------------------------------------
const CATALOGUE = vcClaims.VC_ATTRIBUTES;

const BY_LDAP = new Map();
CATALOGUE.forEach(function (row) {
  BY_LDAP.set(row.ldap.toLowerCase(), row);
});

// ---------------------------------------------------------------------------
// THE SAME CATALOGUE INDEXED THE OTHER WAY ROUND — by the OIDC CLAIM NAME.
//
// Everything above this line answers "somebody ticked an LDAP attribute type;
// what claim does it become". OIDC Core 5.5 asks the opposite question: a
// client sends `{"userinfo": {"birthdate": null}}` and names a CLAIM, and this
// service has to find the attribute on that person's entry that would produce
// it. Without this index the UserInfo endpoint would have to walk the catalogue
// per requested name, which is the second walk of one list that this whole file
// exists to prevent.
//
// TWO KINDS OF KEY, and the second is the one that is easy to leave out:
//
//   * the FLAT claim name, which is `row.claim.join('.')` — the same string
//     `report[].claim` carries and the same one a SAML attribute is named with.
//     So `address.locality` is a key, and a client may ask for exactly that.
//   * the TOP-LEVEL name of a nested claim — `address` — which maps to EVERY
//     row beneath it. That is the spelling OIDC Core 5.5.1 actually uses:
//     `{"address": null}` asks for the whole Address Claim (Core 5.1.1), one
//     JSON object with up to six members, and answering it with nothing because
//     no single catalogue row is called `address` would be the most confusing
//     possible reading of a request this service can satisfy in full.
//
// Lower-cased for lookup, because a claim name arrives from a client and
// `Birthdate` is a misspelling worth answering rather than a different claim.
// The catalogue's own spelling is what goes back on the wire.
// ---------------------------------------------------------------------------
const BY_CLAIM = new Map();
CATALOGUE.forEach(function (row) {
  const flat = row.claim.join('.');
  if (!BY_CLAIM.has(flat.toLowerCase())) {
    BY_CLAIM.set(flat.toLowerCase(), [row]);
  }
  if (row.claim.length > 1) {
    const top = row.claim[0].toLowerCase();
    if (!BY_CLAIM.has(top)) {
      BY_CLAIM.set(top, []);
    }
    BY_CLAIM.get(top).push(row);
  }
});

// The sets are admin_stats.js's, read from there rather than written out again:
// a set added over there has to appear here, and a copy of the list is how it
// would fail to. It was four until 2026-08-26 and is five now, and NOTHING IN
// THIS FILE WAS EDITED TO MAKE THAT TRUE — which is the whole reason the list
// is derived.
const SET_IDS = stats.CLAIM_SET_IDS;

// setId -> Set of lower-cased attribute names. Empty on a fresh start, in every
// one of them; see the header for why that is the only defensible default. Held in
// memory like every other piece of configuration in this service — the signing
// key is regenerated on every start, so a selection that outlived it would
// describe tokens nothing can verify.
// PER TRUST REALM. `realms.obj()` is a object that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain object it replaced. See common/realms.js.
// SEEDED BY THE FACTORY, ONCE PER REALM, AND THAT IS NOT A STYLE CHOICE.
// `realms.obj()` builds a partition the first time a realm asks for one, so
// seeding the five set ids AFTER the call seeds exactly one partition — the
// realm that happened to be ambient at require time, which is none, which is
// the default realm's. Every other realm then got an EMPTY object, and
// `isKnownSet()` answered false for every set id in it: the three `attributes`
// actions on all three claim-set doors refused every set in every trust realm,
// with a sentence that listed the set it was refusing, because the list is
// read from the process-wide table and the lookup is not.
const selections = realms.obj(function () {
  const fresh = {};
  SET_IDS.forEach(function (id) {
    fresh[id] = new Set();
  });
  return fresh;
});

function isKnownSet(setId) {
  return Object.prototype.hasOwnProperty.call(selections, String(setId || ''));
}

// ---------------------------------------------------------------------------
// Reading the selection.
// ---------------------------------------------------------------------------

// The selected rows, in CATALOGUE order rather than in the order they were
// ticked. The order reaches the token — it is the order of the members of a JWT
// payload and of the <Attribute> elements in an assertion — and a claim list
// that reordered itself because somebody unticked and reticked a box would look
// like a different token to anything diffing them.
function selectedRows(setId) {
  const chosen = selections[String(setId || '')];
  if (!chosen) {
    return [];
  }
  return CATALOGUE.filter(function (row) {
    return chosen.has(row.ldap.toLowerCase());
  });
}

// Canonically spelled, because this list is published: both claim-set pages
// answer it in their JSON and GET /admin-api/claims and GET
// /admin-api/saml-attributes serve the same object. A reply naming
// `schacdateofbirth` beside a catalogue naming `schacDateOfBirth` reads as two
// different attributes.
function selectedNames(setId) {
  return selectedRows(setId).map(function (row) { return row.ldap; });
}

function isSelected(setId, ldapName) {
  const chosen = selections[String(setId || '')];
  return !!chosen && chosen.has(String(ldapName || '').toLowerCase());
}

// Every name in the catalogue, for the "select all" button and for the API's
// equivalent operation.
function allNames() {
  return CATALOGUE.map(function (row) { return row.ldap; });
}

// ---------------------------------------------------------------------------
// THE AUDIT ROW, and why there is one when app.js already records the POST.
//
// app.js's call log writes an `admin.change` (or `api.change`) row for every
// console form post and every management API write, carrying the path, the
// action name and the signed-in user. What it cannot carry is the SUBSTANCE:
// nothing out of a request body is recorded there beyond the action name, on
// purpose, because those bodies carry pasted JWTs on this service.
//
// So the fact that a claims page was posted to and the fact that the ID Token
// set gained `mail` and lost `title` are two different facts at two layers, and
// this is the second one. audit.js's header states the rule they are both
// instances of — one act produces several events, and collapsing them would
// mean choosing which question the page can answer.
//
// NO VALUE IS EVER RECORDED. An attribute's NAME is a schema fact and is safe;
// a value is somebody's postal address. The whole log carries no credential and
// no personal data, and the way that sentence stays true is that every call
// site keeps it, not that one central place strips it.
//
// `actor` is deliberately left empty: this is reached from claimsAction(), which
// takes a body and no request, and threading a request through it just to name
// a person would be the tail wagging the dog. The HTTP row for the same POST is
// one row away and carries the signed-in username.
// ---------------------------------------------------------------------------
function recordChange(setId, how, added, removed, count, ok, errors) {
  log.debug("Entering recordChange(). setId=" + setId + ", how=" + how);
  // audit.audit() cannot throw — it is wrapped over there — so there is no guard
  // here and there must not be one: a guard would suggest to the next reader
  // that this call is allowed to fail an admin action, and it is not.
  audit.audit({
    action: 'claims.change',
    outcome: ok ? 'success' : 'refused',
    actor: '',
    target: setId,
    channel: 'http',
    summary: ok
      ? 'The ' + labelOf(setId) + ' set now carries ' + count + ' directory attribute(s)' +
        (added.length ? '; added ' + added.join(', ') : '') +
        (removed.length ? '; removed ' + removed.join(', ') : '') + '.'
      : 'A change to the ' + labelOf(setId) + ' set was refused: ' +
        (errors || []).join(' '),
    detail: {
      set: setId,
      how: how,
      // Comma-joined rather than nested, because detailOf() keeps scalars and
      // trims strings; an array would be stringified by something else's rules.
      added: added.join(', '),
      removed: removed.join(', '),
      attributeCount: count
    }
  });
  log.debug("Leaving recordChange().");
}

function labelOf(setId) {
  const set = stats.CLAIM_SETS[setId];
  return set ? set.label : String(setId);
}

// ---------------------------------------------------------------------------
// Changing the selection. ONE FUNNEL, which is what makes the audit row and the
// log line properties of the change rather than of the caller.
//
// Errors are returned rather than thrown, because every caller is a form
// handler or an API handler that has to redisplay them — the same contract
// admin_stats.setClaimSet() and vc_claims.setSelection() have.
//
// An unknown attribute is an ERROR and not a silent omission, and the whole call
// is refused rather than partially applied. The page offers a fixed list, so an
// unknown name means either a hand-written request — which deserves an answer —
// or a rename in the catalogue that left a caller behind. A partial application
// would leave the set in a state nobody asked for, which is the same rule
// `replace` follows for the typed claims.
// ---------------------------------------------------------------------------
function setSelection(setId, names, how) {
  log.debug("Entering setSelection(). setId=" + setId + ", " + (names || []).length + " name(s) offered.");
  const id = String(setId || '');
  if (!isKnownSet(id)) {
    log.debug("Leaving setSelection(). No such set.");
    return { ok: false, errors: ['There is no claim set called "' + id + '". The ' +
                                 SET_IDS.length + ' are: ' + SET_IDS.join(', ') + '.'] };
  }
  const errors = [];
  const wanted = new Set();
  (names || []).forEach(function (name) {
    const key = String(name == null ? '' : name).trim().toLowerCase();
    if (!key) {
      return;
    }
    if (!BY_LDAP.has(key)) {
      errors.push('There is no attribute called "' + name + '" in the catalogue. GET ' +
                  '/admin-api/claims lists every one of them.');
      return;
    }
    wanted.add(key);
  });
  if (errors.length) {
    recordChange(id, how || 'select', [], [], selections[id].size, false, errors);
    log.debug("Leaving setSelection(). " + errors.length + " error(s); nothing changed.");
    return { ok: false, errors: errors };
  }

  const before = selections[id];
  const added = [];
  const removed = [];
  wanted.forEach(function (key) {
    if (!before.has(key)) added.push(BY_LDAP.get(key).ldap);
  });
  before.forEach(function (key) {
    if (!wanted.has(key)) removed.push(BY_LDAP.get(key).ldap);
  });
  selections[id] = wanted;

  const now = selectedNames(id);
  log.info('admin: the ' + labelOf(id) + ' set now carries the directory attribute(s) ' +
           (now.join(', ') || '(none)') + '. Added: ' + (added.join(', ') || 'nothing') +
           '. Removed: ' + (removed.join(', ') || 'nothing') + '.');
  recordChange(id, how || 'select', added, removed, now.length, true, []);
  log.debug("Leaving setSelection(). " + now.length + " attribute(s) selected.");
  return { ok: true, set: id, attributes: now, added: added, removed: removed };
}

function selectAll(setId) {
  log.debug("Entering selectAll(). setId=" + setId);
  const result = setSelection(setId, allNames(), 'all');
  log.debug("Leaving selectAll(). ok=" + result.ok);
  return result;
}

function clearSelection(setId) {
  log.debug("Entering clearSelection(). setId=" + setId);
  // The empty array is the whole of it: setSelection() with nothing wanted is
  // exactly "remove everything", and a second code path for it would be a second
  // place to forget the audit row.
  const result = setSelection(setId, [], 'clear');
  log.debug("Leaving clearSelection(). ok=" + result.ok);
  return result;
}

// ---------------------------------------------------------------------------
// THE VALUES.
//
// Read through vc_claims.subjectClaimsFor(), which takes the rows to build as
// its third argument — it exists for a wallet asking for a subset, and a subset
// is exactly what a claim set's selection is. So the resolution order here is
// the same one a credential follows and is not a second implementation of it:
//
//   1. the directory entry under ou=users, which is where an `ldapmodify` lands
//   2. the generated persona, for a person with no entry, an entry without that
//      attribute, or a directory that is not running
//
// (Its first source, the access token, is not reachable from here: `tokenClaims`
// is passed empty, because the thing being built IS the token. A token whose
// `email` claim was sourced from its own `email` claim would be a circle.)
//
// Nothing is ever left absent because a source was missing: a selected claim
// that silently did not arrive would be indistinguishable, at the client, from a
// selection that never took effect.
// ---------------------------------------------------------------------------

// Who the token is about. The two kinds of caller spell it differently and
// neither spelling is wrong — oauth2.js's context calls it `username` because
// that is the claim it carries, and the assertion builders call it `subject`
// because that is what a SAML Subject is. Reading both here is one line; making
// them agree would have meant editing four issuance sites, which is exactly what
// the slot in admin_stats.js exists to avoid.
function subjectOf(context) {
  const ctx = context || {};
  return String(ctx.username || ctx.subject || '');
}

// The claims the selected attributes produce for one person, nested where the
// catalogue nests (`address.locality` becomes an `address` object with a
// `locality` member, which is what OIDC Core 5.1.1 defines and what a client
// reading `address` expects).
function claimsFor(setId, username) {
  log.debug("Entering claimsFor(). setId=" + setId + ", user=" + username);
  const rows = selectedRows(setId);
  if (!rows.length) {
    log.debug("Leaving claimsFor(). Nothing is selected for that set.");
    return { claims: {}, report: [], entryFound: false };
  }
  const built = vcClaims.subjectClaimsFor(username, {}, rows);
  log.debug("Leaving claimsFor(). " + built.report.length + " claim(s).");
  return built;
}

// The same, in the shape the two assertion builders want.
//
// A SAML Attribute is FLAT — the content model is a name and text values, with
// no way to spell a nested claim — so a nested one has to be named somehow, and
// the name used is the DOTTED PATH the JWT sets already use (`address.locality`).
// The alternative was to emit the leaf name alone, which would put `locality`,
// `region` and `country` in an assertion with nothing saying they are one
// address and no way to tell `country` from a nationality. Saying
// `address.locality` in both families means a person comparing an ID Token with
// an assertion is looking at one claim under one name.
//
// `nameFormat` is left absent for SAML 2.0 (the builder omits the attribute when
// there is none, and the specification's default is
// unspecified — which is the honest answer for a name this service invented) and
// SAML 1.1 gets the same default namespace a typed claim gets, for the reason
// admin_stats.js states beside it: it is the namespace every WS-Federation
// relying party already reads.
function samlAttributesFor(setId, username) {
  log.debug("Entering samlAttributesFor(). setId=" + setId + ", user=" + username);
  const built = claimsFor(setId, username);
  const out = built.report.map(function (item) {
    const attribute = { name: item.claim, value: item.value };
    if (setId === 'saml11') attribute.namespace = stats.DEFAULT_SAML11_NAMESPACE;
    return attribute;
  });
  log.debug("Leaving samlAttributesFor(). " + out.length + " attribute(s).");
  return out;
}

// What one person's selected attributes would put in this set right now, flat
// and annotated with where each value came from. It is the console's preview and
// the API's, and it is built by the function the ISSUANCE path calls rather than
// by a second walk of the catalogue — a preview that agreed with the page and
// disagreed with the token would be worse than no preview at all.
function previewFor(setId, username) {
  log.debug("Entering previewFor(). setId=" + setId + ", user=" + username);
  const built = claimsFor(setId, username);
  log.debug("Leaving previewFor(). " + built.report.length + " claim(s).");
  return { user: username, entryFound: built.entryFound,
           claims: built.claims, report: built.report };
}

// One person's value for every row in the catalogue, selected or not, so the
// console can show what ticking a box WOULD produce. Built in one pass rather
// than one call per row: subjectClaimsFor() reads the directory entry once, and
// one read per catalogue row per page render would be a read per row too many.
function catalogueValuesFor(username) {
  log.debug("Entering catalogueValuesFor(). user=" + username);
  const built = vcClaims.subjectClaimsFor(username, {}, CATALOGUE);
  const byLdap = {};
  built.report.forEach(function (item) {
    byLdap[item.ldap.toLowerCase()] = item;
  });
  log.debug("Leaving catalogueValuesFor(). " + built.report.length + " value(s).");
  return { byLdap: byLdap, entryFound: built.entryFound };
}

// ---------------------------------------------------------------------------
// OIDC CORE 5.5 — A CLAIM THE CLIENT ASKED FOR BY NAME.
//
// The whole of this file above answers "what did an ADMINISTRATOR tick"; this
// answers "what did the CLIENT ask for", which is the other half of what
// reaches a UserInfo response. The two are deliberately separate stores of
// intent and neither is derived from the other: a claims request naming
// `birthdate` is honoured whether or not `schacDateOfBirth` is ticked on the
// UserInfo set, because the set is what everybody gets and the request is what
// this client asked for this time. See oauth2.js's userinfoResponse(), which is
// where the precedence between the two is written down.
//
// THREE THINGS ARE WORTH KNOWING BEFORE READING THE CODE.
//
// **One directory read for the whole request, not one per name.** A client may
// name a dozen claims; subjectClaimsFor() reads the entry once and is handed
// the union of the rows they resolve to. A read per requested name would be a
// read per name too many, and — worse — two reads of one entry mid-`ldapmodify`
// could answer one request with two versions of one person.
//
// **A LANGUAGE TAG IS PART OF THE NAME AND IS NOT A DIFFERENT CLAIM.** Core 5.2
// lets a client ask for `family_name#ja-Kana-JP`, and this service holds one
// value per attribute — so the tag is stripped for the lookup and PUT BACK on
// the way out, which is what section 5.2 says a response does. The value is the
// same one `family_name` would have carried, and pretending otherwise (by
// refusing the name, or by answering under the untagged one) would be a client
// unable to match the request it sent to the response it got.
//
// **AN UNRESOLVABLE NAME IS REPORTED, NOT REFUSED.** Core 5.5.1 is explicit:
// a server MUST NOT return an error because a requested claim is not available,
// and `essential` does not change that — it is a hint about what the client
// will do without it. So the name comes back in `unknown` for the log, the
// console and the API to say so, and the response simply lacks it.
// ---------------------------------------------------------------------------

// The rows one requested claim name resolves to, and how it should be spelled
// back. Returns null for a name this service's catalogue cannot produce.
function rowsForClaim(name) {
  const raw = String(name == null ? '' : name).trim();
  if (!raw) {
    return null;
  }
  const hash = raw.indexOf('#');
  const base = hash >= 0 ? raw.slice(0, hash) : raw;
  const tag = hash >= 0 ? raw.slice(hash) : '';
  const rows = BY_CLAIM.get(base.toLowerCase());
  if (!rows || !rows.length) {
    return null;
  }
  // A GROUP request (`address`) is the top-level name of a nested claim and
  // resolves to every row beneath it; anything else is one row. `grouped` is
  // what tells the caller which of the two it has, because the answer is
  // shaped differently — an object with members, or one value.
  const grouped = rows.length > 1 || (rows[0].claim.length > 1 && base.indexOf('.') < 0);
  return { requested: raw, base: base, tag: tag, rows: rows, grouped: grouped };
}

// Put a value at a dotted path, creating the objects on the way down. Written
// here rather than reached for in vc_claims.js because that module's own
// setPath() is private to it, and exporting it would make a helper that exists
// for the credential builder into part of this file's contract.
function setPath(target, path, value) {
  let node = target;
  for (let i = 0; i < path.length - 1; i++) {
    if (!node[path[i]] || typeof node[path[i]] !== 'object') {
      node[path[i]] = {};
    }
    node = node[path[i]];
  }
  node[path[path.length - 1]] = value;
}

// What a list of requested claim names produces for one person, read off their
// entry under ou=users — or, where the entry has nothing, invented from the
// username, deterministically, exactly as every other reader of this catalogue
// does. `claims` is ready to merge into a response; `report` is one row per
// name for the log and the console; `unknown` is every name this catalogue
// cannot produce.
function requestedClaimsFor(username, names) {
  log.debug("Entering requestedClaimsFor(). user=" + username + ", " +
            (names || []).length + " name(s) requested.");
  const asked = [];
  const unknown = [];
  (names || []).forEach(function (name) {
    const resolved = rowsForClaim(name);
    if (!resolved) {
      unknown.push(String(name));
      return;
    }
    asked.push(resolved);
  });
  if (!asked.length) {
    log.debug("Leaving requestedClaimsFor(). Nothing in the catalogue answers this request.");
    return { claims: {}, report: [], unknown: unknown, entryFound: false };
  }

  // The union, in CATALOGUE order and without repeats — the same ordering rule
  // selectedRows() follows, and for the same reason: the order reaches the
  // response, and a claim list that reordered itself because a client listed
  // its names differently would look like a different document to anything
  // diffing them.
  const wanted = new Set();
  asked.forEach(function (entry) {
    entry.rows.forEach(function (row) { wanted.add(row.ldap.toLowerCase()); });
  });
  const rows = CATALOGUE.filter(function (row) {
    return wanted.has(row.ldap.toLowerCase());
  });
  const built = vcClaims.subjectClaimsFor(username, {}, rows);
  const byFlat = {};
  built.report.forEach(function (item) { byFlat[item.claim] = item; });

  const claims = {};
  const report = [];
  asked.forEach(function (entry) {
    if (entry.grouped) {
      // The whole Address Claim, as one object. Taken off `built.claims` rather
      // than reassembled from the report, because that object is what
      // setPath() already nested correctly and a second assembly here would be
      // a second answer to "what shape is an address".
      const value = built.claims[entry.rows[0].claim[0]];
      if (value === undefined) {
        unknown.push(entry.requested);
        return;
      }
      claims[entry.rows[0].claim[0]] = value;
      entry.rows.forEach(function (row) {
        const item = byFlat[row.claim.join('.')];
        if (item) {
          report.push({ requested: entry.requested, claim: item.claim, ldap: item.ldap,
                        value: item.value, source: item.source });
        }
      });
      return;
    }
    const row = entry.rows[0];
    const item = byFlat[row.claim.join('.')];
    if (!item) {
      unknown.push(entry.requested);
      return;
    }
    if (entry.tag) {
      // Core 5.2: the tag is part of the member name in the response, so a
      // tagged request is answered at the top level under the name it was
      // asked under — even where the untagged claim nests. A nested member
      // cannot carry a tag on its container, and inventing a spelling for that
      // would be this service making up a section of the specification.
      claims[entry.requested] = item.value;
    } else if (row.claim.length > 1) {
      setPath(claims, row.claim, item.value);
    } else {
      claims[row.claim[0]] = item.value;
    }
    report.push({ requested: entry.requested, claim: item.claim, ldap: item.ldap,
                  value: item.value, source: item.source });
  });

  log.debug("Leaving requestedClaimsFor(). " + report.length + " claim(s) resolved, " +
            unknown.length + " name(s) this catalogue cannot produce.");
  return { claims: claims, report: report, unknown: unknown, entryFound: built.entryFound };
}

// Every claim name a client may ask for, in the two spellings the index holds —
// the flat name of each row and the top-level name of each nested group. It is
// what the console lists under "what a client may request" and what the
// management API publishes, so that a client learns the vocabulary from this
// service rather than from a copy of the catalogue in a document.
function requestableClaims() {
  log.debug("Entering requestableClaims().");
  const seen = new Set();
  const out = [];
  CATALOGUE.forEach(function (row) {
    if (row.claim.length > 1) {
      const top = row.claim[0];
      if (!seen.has(top)) {
        seen.add(top);
        out.push({ claim: top, ldap: CATALOGUE.filter(function (r) {
          return r.claim[0] === top && r.claim.length > 1;
        }).map(function (r) { return r.ldap; }).join(', '),
          label: 'The whole ' + top + ' claim (OIDC Core 5.1.1)', grouped: true });
      }
    }
    const flat = row.claim.join('.');
    if (!seen.has(flat)) {
      seen.add(flat);
      out.push({ claim: flat, ldap: row.ldap, label: row.label, grouped: false });
    }
  });
  log.debug("Leaving requestableClaims(). " + out.length + " name(s).");
  return out;
}

// The catalogue as the console's table and the API's document want it: one row
// per attribute type, with which of the sets currently carries it. Built
// here rather than in admin.js because the API answers the same list and neither
// of them should be walking the catalogue itself.
function catalogueRows() {
  log.debug("Entering catalogueRows().");
  const out = CATALOGUE.map(function (row) {
    const sets = {};
    SET_IDS.forEach(function (id) {
      sets[id] = isSelected(id, row.ldap);
    });
    return { ldap: row.ldap, claim: row.claim.join('.'), label: row.label,
             schema: row.schema, sets: sets };
  });
  log.debug("Leaving catalogueRows(). " + out.length + " row(s).");
  return out;
}

// ---------------------------------------------------------------------------
// FILLING THE SLOT.
//
// This is the whole of the installation, and it is why no issuance site changed.
// admin_stats.js calls these two from inside jwtClaims() and samlAttributes(),
// wraps them, and merges what comes back UNDER the typed claims — see the note
// there about precedence.
//
// Done at require time, at module scope, like every other inverted dependency
// here. A process that never loads this module simply has no attribute claims,
// which is a smaller service and not a broken one.
// ---------------------------------------------------------------------------
stats.setAttributeResolver({
  jwtClaims: function (setId, context) {
    return claimsFor(setId, subjectOf(context)).claims;
  },
  samlAttributes: function (setId, context) {
    return samlAttributesFor(setId, subjectOf(context));
  }
});

log.info('The claim-attribute selection is loaded: /admin/claims can now put ' +
         'LDAP attributes from the directory into an access token and an ID ' +
         'Token, /admin/userinfo-claims into a UserInfo response, and ' +
         '/admin/saml-attributes into a SAML 2.0 assertion and a SAML 1.1 one. ' +
         'Nothing is selected on a fresh start, so this changes no token until ' +
         'somebody asks it to.');

module.exports = {
  CATALOGUE: CATALOGUE,
  SET_IDS: SET_IDS,
  selectedRows: selectedRows,
  selectedNames: selectedNames,
  isSelected: isSelected,
  allNames: allNames,
  setSelection: setSelection,
  selectAll: selectAll,
  clearSelection: clearSelection,
  claimsFor: claimsFor,
  samlAttributesFor: samlAttributesFor,
  previewFor: previewFor,
  catalogueValuesFor: catalogueValuesFor,
  catalogueRows: catalogueRows,
  // OIDC Core 5.5's half. Read by oauth-oidc/oauth2.js at the UserInfo endpoint
  // and by admin-ui/admin.js for the page that documents it — one resolver, so
  // the vocabulary the console publishes cannot drift from the one the endpoint
  // answers.
  requestedClaimsFor: requestedClaimsFor,
  requestableClaims: requestableClaims
};
