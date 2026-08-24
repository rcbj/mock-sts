'use strict';
//
// File: claim_attributes.js
//
// ---------------------------------------------------------------------------
// WHICH LDAP ATTRIBUTES THE FOUR TOKEN AND ASSERTION SETS CARRY.
//
// admin_stats.js already holds the four CUSTOM CLAIM sets — a name and a value
// somebody typed on /admin/claims or /admin/saml-attributes, with
// ${placeholders}. This holds the other half of those pages: a SELECTION out of
// the directory's user-object attribute catalogue, per set, whose value is not
// typed anywhere because it is read off that person's entry under ou=users.
//
// TWO PAGES SINCE 2026-08-24 AND STILL ONE SELECTION PER SET. The console shows
// the two JWT sets on /admin/claims and the two SAML ones on
// /admin/saml-attributes; nothing here knows that, and nothing here should — a
// per-page store would be the second store this whole arrangement exists to
// prevent, and the catalogue below is published by both replies in full.
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
// **NOTHING IS SELECTED ON A FRESH START, in any of the four sets.** That is not
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

// The four sets are admin_stats.js's four, read from there rather than written
// out again: a fifth set added over there has to appear here, and a copy of the
// list is how it would fail to.
const SET_IDS = stats.CLAIM_SET_IDS;

// setId -> Set of lower-cased attribute names. Empty on a fresh start, in all
// four; see the header for why that is the only defensible default. Held in
// memory like every other piece of configuration in this service — the signing
// key is regenerated on every start, so a selection that outlived it would
// describe tokens nothing can verify.
const selections = {};
SET_IDS.forEach(function (id) {
  selections[id] = new Set();
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
    return { ok: false, errors: ['There is no claim set called "' + id + '". The four are: ' +
                                 SET_IDS.join(', ') + '.'] };
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

// The catalogue as the console's table and the API's document want it: one row
// per attribute type, with which of the four sets currently carries it. Built
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
         'Token, and /admin/saml-attributes into a SAML 2.0 assertion and a ' +
         'SAML 1.1 one. Nothing is selected on a fresh start, so this changes ' +
         'no token until somebody asks it to.');

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
  catalogueRows: catalogueRows
};
