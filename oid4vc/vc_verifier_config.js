'use strict';
//
// File: vc_verifier_config.js
//
// ---------------------------------------------------------------------------
// WHAT THE BAR DOOR ASKS FOR.
//
// `vc_verifier.js` is the Verifier — the mock relying party the pages call "The
// Bar Door", which asks a wallet for part of a credential and then checks what
// comes back. Until this file existed, what it asked for was one line:
//
//   const VP_REQUESTED_CLAIMS = (process.env.OID4VP_CLAIMS || 'given_name,family_name')...
//
// which is enough to demonstrate selective disclosure and not enough to exercise
// a wallet. The questions worth asking a wallet are "what does its consent
// screen do with fourteen claims", "what does it do when the Verifier asks for a
// claim the credential does not carry", and "what does it do when the request
// names no claims at all" — and none of them can be asked without a restart while
// the list is an environment variable.
//
// So the request is CONFIGURATION, /admin/vc-verifier-config is the page that
// sets it, and this module is where it lives. It is a LIBRARY in the sense
// dpop.js, admin_stats.js and vc_claims.js are: it registers no route, so its
// position in the require order does not matter, and it requires only helpers.js
// and the two other libraries below (vc_claims.js and vc_configs.js, neither of
// which registers anything either) so it cannot join a cycle. That matters here
// because both ends of the exchange read it — vc_verifier.js early in the require
// order, admin.js late — and a require between those two in either direction
// would drag one module's routes into the router at the other's position, which
// is what `GET /admin/sts-metadata` is built by walking.
//
// ---------------------------------------------------------------------------
// THE CATALOGUE IS vc_claims.js's CATALOGUE, TURNED AROUND.
//
// That file's rows are LDAP attribute types — the issuer's side of this, where a
// claim's value is the value on the person's entry under `ou=users`. A Verifier
// cannot ask for an LDAP attribute; it asks for a CLAIM, and the two lists are
// not the same length. Six attribute rows (`street`, `l`, `st`, `postalCode`,
// `c`, `postalAddress`) are one claim, `address`, because of how the credential
// is built: `buildSdJwtVc()` makes one Disclosure per TOP-LEVEL claim, so
// `address` is one unit of disclosure and a holder cannot present the locality
// without the street. A page offering six address checkboxes would be offering a
// choice that does not exist on the wire.
//
// So the rows here are the top-level claims, each naming the attribute types
// behind it, and asking for one is asking for everything it is made of. That is
// stated on the page rather than left to be discovered from a presentation that
// disclosed more than the tester expected.
//
// ---------------------------------------------------------------------------
// A CLAIM THAT IS NOT IN THE CATALOGUE CAN STILL BE ASKED FOR, and that is the
// point rather than a loose end.
//
// The interesting negative here is a Verifier asking for something the credential
// does not carry: the wallet has to say so, and this service's own "Requested
// claims" check has to fail with the name in it. There is no other way to reach
// that state — every claim the issuer can mint is in the catalogue, so a
// selection drawn only from the catalogue can only ever produce requests that
// succeed. It is also what keeps `OID4VP_CLAIMS` honest: a name set there that
// this build does not issue is kept and marked rather than silently dropped,
// because a deployment whose configuration was quietly discarded at startup is
// worse than one whose request fails visibly.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
// TRUST REALMS: the verifier's request below is per realm.
const realms = require('../common/realms');
const config = require('../common/config');
const { VC_ATTRIBUTES, isSelected } = require('./vc_claims');
const { VCI_VCT, VCI_JWT_TYPES, VCI_CONFIG_ID, VCI_DID_CONFIG_ID, VCI_JWT_CONFIG_ID,
        VCI_LDP_CONFIG_ID, VCI_LDP_DID_CONFIG_ID } = require('./vc_configs');

// The most claims one request may name. A ceiling rather than a policy: the
// selection can be POSTed as JSON by anything, and a DCQL query with ten thousand
// paths in it is a request no wallet can display and nothing here would enjoy
// logging. Well above the catalogue's own size, so the page's own Save can never
// hit it.
const MAX_REQUESTED = 40;

// The DCQL credential query's id, which is also the key the vp_token is a member
// of when the presentation comes back (OID4VP section 8.1). It lives here rather
// than in vc_verifier.js because the query is built here and the two must be the
// same string: a response keyed by an id the request did not use is one this
// Verifier cannot find the presentation in.
const DCQL_ID = 'identity_credential';

// A claim name this service will put in a DCQL path. Deliberately narrow: a JSON
// member name may contain almost anything, but everything the three credential
// formats here can carry is an identifier, and the one character worth refusing
// on purpose is the dot — somebody typing `address.locality` means a nested path,
// which is not what this asks for (see the header: the unit of disclosure is the
// top-level claim), and accepting it would produce a request for a claim named
// "address.locality" that no credential will ever carry.
const CLAIM_NAME = /^[A-Za-z_][A-Za-z0-9_-]*$/;

// ---------------------------------------------------------------------------
// THE CATALOGUE, derived rather than written out.
//
// Written out, it would be a second list of claim names to keep in step with
// vc_claims.js's, and the failure when they drifted would be silent: the Verifier
// would ask for a claim the issuer stopped minting, or stop offering one it
// started minting, and either way the page would look right. So it is grouped out
// of that file's rows, and a claim added there appears here with no edit at all.
//
// Per row:
//   claim      the claim name, which is what a DCQL path names
//   label      what the page calls it — the attribute's own label where one
//              attribute makes the claim, and the claim name titled where several
//              do (`address`), because "Street address" would be a lie on a row
//              that also carries the locality and the country
//   members    the vc_claims.js rows behind it, in that file's order
//   attributes the LDAP attribute types, for the page's schema column
//   ldpTerms   the JSON-LD terms this claim becomes in an ldp_vc credential, which
//              is where the three formats stop agreeing — see FORMATS below
// ---------------------------------------------------------------------------
function titleFor(claimName) {
  const words = String(claimName).split('_');
  return words.map(function (word, i) {
    return i === 0 ? word.charAt(0).toUpperCase() + word.slice(1) : word;
  }).join(' ');
}

const REQUESTABLE = [];
const BY_CLAIM = new Map();
VC_ATTRIBUTES.forEach(function (attribute) {
  const name = attribute.claim[0];
  let row = BY_CLAIM.get(name);
  if (!row) {
    row = { claim: name, label: '', members: [], attributes: [], ldpTerms: [] };
    BY_CLAIM.set(name, row);
    REQUESTABLE.push(row);
  }
  row.members.push(attribute);
  row.attributes.push(attribute.ldap);
  if (attribute.ldpTerm) {
    row.ldpTerms.push(attribute.ldpTerm);
  }
});
REQUESTABLE.forEach(function (row) {
  row.label = row.members.length === 1 ? row.members[0].label : titleFor(row.claim);
  // Whether this claim is an object assembled from several attributes. The page
  // shows it, because "asking for `address` gets you all six of these" is the one
  // thing about this table that is not obvious from looking at it.
  row.nested = row.members.length > 1;
});

function rowFor(claimName) {
  return BY_CLAIM.get(String(claimName || '')) || null;
}

// Which of the attributes behind a claim the ISSUER is currently configured to
// put in a credential (/admin/vc, vc_claims.js's selection). Asked by the page and
// answered here rather than there, so that admin.js keeps rendering and deciding
// nothing: "you are asking for a claim this issuer is not currently minting" is a
// statement about two configurations, and both of them live on this side.
function carriedNow(claimName) {
  const row = rowFor(claimName);
  if (!row) {
    return { known: false, carried: [], missing: [] };
  }
  const carried = [];
  const missing = [];
  row.members.forEach(function (attribute) {
    if (isSelected(attribute.ldap)) {
      carried.push(attribute.ldap);
    } else {
      missing.push(attribute.ldap);
    }
  });
  return { known: true, carried: carried, missing: missing };
}

// ---------------------------------------------------------------------------
// THE CREDENTIAL TYPES A WALLET MAY SUBMIT.
//
// One request asks for ONE of these, because a presentation cannot convert
// between formats: a wallet holding a jwt_vc_json credential has nothing to
// answer a dc+sd-jwt query with, and the honest failure is that it says so. The
// three differ in the two ways DCQL cares about and in a third that decides what
// the whole exchange is worth:
//
//   how the credential is IDENTIFIED   an SD-JWT VC by its `vct` (meta.vct_values),
//                                      a W3C VC by its type array
//                                      (meta.type_values, an array OF ARRAYS —
//                                      each entry a complete set that satisfies
//                                      the query)
//   where the CLAIMS live              the top level of the payload for
//                                      dc+sd-jwt, under `credentialSubject` for
//                                      both W3C formats — and for ldp_vc under a
//                                      DIFFERENT SPELLING again, because the
//                                      credential is JSON-LD and only the terms
//                                      the vendored context defines may appear
//   whether anything can be WITHHELD   per-claim Disclosures for dc+sd-jwt, a
//                                      re-randomised BBS derived proof for
//                                      ldp_vc, and nothing at all for
//                                      jwt_vc_json, whose holder hands over the
//                                      whole credentialSubject or nothing
//
// The identifying VALUES are not configurable. They are what this service's own
// issuer mints (vc_configs.js), and a Verifier asking for a vct nobody here
// issues would be a request no wallet in this stack could ever satisfy — a
// negative worth having, but one that belongs to the issuer's configuration
// rather than to a text box on this page.
// ---------------------------------------------------------------------------
const FORMATS = [
  { id: 'dc+sd-jwt', label: 'SD-JWT VC', claimsAt: 'top',
    identifiedBy: 'meta.vct_values', identifier: VCI_VCT,
    identifierText: VCI_VCT,
    selectiveDisclosure: 'per claim, by withholding Disclosures',
    holderBinding: 'Key Binding JWT signed by the credential\'s cnf key',
    configs: [VCI_CONFIG_ID, VCI_DID_CONFIG_ID],
    what: 'The default, and the only one of the three whose selective disclosure is per claim: ' +
          'the holder sends the issuer-signed JWT plus one Disclosure per claim it chooses to ' +
          'reveal, and a Key Binding JWT over exactly those bytes.' },
  { id: 'jwt_vc_json', label: 'JWT VC (W3C, JOSE-secured)', claimsAt: 'credentialSubject',
    identifiedBy: 'meta.type_values', identifier: VCI_JWT_TYPES,
    identifierText: VCI_JWT_TYPES.join(', '),
    selectiveDisclosure: 'none — the whole credentialSubject is presented',
    holderBinding: 'a Verifiable Presentation JWT signed by the credential\'s cnf key',
    configs: [VCI_JWT_CONFIG_ID],
    what: 'The same facts with NO selective disclosure. Asking for two claims still gets every ' +
          'claim the credential carries, and this Verifier says so on the result rather than ' +
          'counting the extras as a failure — the holder had no way to send less.' },
  { id: 'ldp_vc', label: 'LDP VC (W3C, Data Integrity, bbs-2023)', claimsAt: 'ldp',
    identifiedBy: 'meta.type_values', identifier: VCI_JWT_TYPES,
    identifierText: VCI_JWT_TYPES.join(', '),
    selectiveDisclosure: 'per canonical statement, and unlinkable between presentations',
    holderBinding: 'the derived proof itself, bound to this request\'s nonce',
    configs: [VCI_LDP_CONFIG_ID, VCI_LDP_DID_CONFIG_ID],
    what: 'Signed over canonicalized JSON-LD, so a claim can only be asked for by a term the ' +
          'vendored context defines — several claims below have none and are dropped from an ' +
          'ldp_vc query rather than asked for under a name that would fail canonicalization.' }
];

const FORMAT_IDS = FORMATS.map(function (format) { return format.id; });

// One format by its id, with ONE piece of tolerance that is not cosmetic: a space
// is read as a plus. `dc+sd-jwt` is a format id containing the one character a
// query string spells a space with, so `?format=dc+sd-jwt` reaches a handler as
// "dc sd-jwt" — every link that names that format has to percent-encode it, and
// the ones on the bar door did not. That was invisible while an unrecognised
// format fell back to a constant that happened to be this one; it stopped being
// invisible the moment the fallback became configuration, since a button saying
// "present an SD-JWT VC" would have asked for whatever the default was. The links
// are fixed AND this accepts the un-encoded spelling, because a QR code somebody
// saved, or a wallet that built the link itself, is not something this service can
// go back and correct.
function formatById(id) {
  const wanted = String(id == null ? '' : id).trim().split(' ').join('+');
  return FORMATS.filter(function (format) { return format.id === wanted; })[0] || null;
}

// ---------------------------------------------------------------------------
// The state. In memory like every other piece of configuration here — the signing
// key is regenerated on every start, so a selection that outlived it would
// describe requests against credentials nothing can verify.
// ---------------------------------------------------------------------------
function parseNames(value) {
  if (Array.isArray(value)) {
    return value.map(function (name) { return String(name == null ? '' : name).trim(); });
  }
  return String(value == null ? '' : value).split(/[\s,]+/).map(function (name) { return name.trim(); });
}

// What the process started with: OID4VP_CLAIMS if it is set, and the two claims
// this Verifier asked for before this page existed if it is not. Kept as the
// target of Reset rather than the catalogue's defaults, so that a deployment that
// configured the variable gets ITS list back and not somebody else's.
// A FUNCTION, because oid4vp.claims is settable at runtime: Reset has to mean
// "back to what this deployment configured", and a constant captured at
// require time would mean "back to what it configured when the process
// started" — which stops being the same sentence the moment /admin/config is
// used. It returns a fresh array each call, so no caller can mutate it.
function defaultRequested() {
  return parseNames(config.value('oid4vp.claims'))
    .filter(function (name) { return name !== ''; });
}

// PER TRUST REALM, both of them. What a verifier asks a wallet to present, and
// in which credential format, is a decision a realm makes for itself — and the
// verifier client id is already realm-distinct (realms.js seeds it), so a
// shared request would be one verifier's question asked under several names.
// `realms.obj(factory)` is a plain object per realm, so the reads and the
// reassignments below work exactly as the two bindings they replaced did.
const state = realms.obj(function () {
  return { requested: defaultRequested(), format: 'dc+sd-jwt' };
});

// The default credential format: what /oid4vp/start asks for when the link it was
// reached by does not name one. The bar door's three format buttons DO name one,
// so they are unaffected by this — which is deliberate, since a page offering
// "present an SD-JWT VC" that asked for something else would be lying in the one
// place a reader is most likely to trust it.

function requestedClaims() {
  return state.requested.slice();
}

// The requested claims with what the page needs to describe each: the catalogue
// row where there is one, and the fact that there is not where there is not.
function requestedRows() {
  return state.requested.map(function (name) {
    const row = rowFor(name);
    return { claim: name, inCatalogue: !!row, label: row ? row.label : '', row: row };
  });
}

function isRequested(claimName) {
  return state.requested.indexOf(String(claimName || '')) >= 0;
}

// Install a whole selection at once. Returns the errors rather than throwing,
// because the caller is a form handler that has to redisplay them — the same
// contract vc_claims.setSelection() and admin_stats.setClaimSet() have.
//
// The ORDER of what comes back is the catalogue's, with anything not in the
// catalogue after it in the order it was given. The order reaches the DCQL query
// and therefore the wallet's consent screen, and a list that reordered itself
// because somebody unticked and reticked a box would look like a different
// request to anything diffing them.
function setRequested(names) {
  log.debug("Entering setRequested(). " + (names || []).length + " name(s) offered.");
  const errors = [];
  const wanted = [];
  const seen = new Set();
  parseNames(names).forEach(function (name) {
    if (name === '') {
      return;
    }
    if (!CLAIM_NAME.test(name)) {
      errors.push('"' + name + '" is not a claim name this service will put in a DCQL path. ' +
                  'Letters, digits, hyphen and underscore, starting with a letter or an ' +
                  'underscore — and no dots, because the unit of disclosure is the top-level ' +
                  'claim and a nested path would name a claim no credential here carries.');
      return;
    }
    if (seen.has(name)) {
      // Silently, because a duplicate is not a mistake worth an error message: two
      // identical DCQL paths would be one request asking for the same claim twice.
      return;
    }
    seen.add(name);
    wanted.push(name);
  });
  if (wanted.length > MAX_REQUESTED) {
    errors.push('That is ' + wanted.length + ' claims; at most ' + MAX_REQUESTED + ' may be ' +
                'requested at once.');
  }
  if (errors.length) {
    log.debug("Leaving setRequested(). " + errors.length + " error(s); nothing changed.");
    return { ok: false, errors: errors };
  }
  const inCatalogue = REQUESTABLE
    .filter(function (row) { return seen.has(row.claim); })
    .map(function (row) { return row.claim; });
  const extras = wanted.filter(function (name) { return !rowFor(name); });
  const before = state.requested;
  state.requested = inCatalogue.concat(extras);
  const added = state.requested.filter(function (name) { return before.indexOf(name) < 0; });
  const removed = before.filter(function (name) { return state.requested.indexOf(name) < 0; });
  log.info('oid4vp: the Verifier now asks for ' + (state.requested.join(', ') || '(no claims at all)') +
           '. Added: ' + (added.join(', ') || 'nothing') + '. Removed: ' +
           (removed.join(', ') || 'nothing') + '.');
  log.debug("Leaving setRequested(). " + state.requested.length + " claim(s) requested.");
  return { ok: true, requested: requestedClaims(), added: added, removed: removed };
}

function addRequested(name) {
  log.debug("Entering addRequested(). name=" + name);
  const wanted = String(name == null ? '' : name).trim();
  if (wanted === '') {
    log.debug("Leaving addRequested(). Nothing was typed.");
    return { ok: false, errors: ['Type the name of a claim to ask for.'] };
  }
  if (isRequested(wanted)) {
    log.debug("Leaving addRequested(). Already asked for.");
    return { ok: false, errors: ['This Verifier already asks for "' + wanted + '".'] };
  }
  const result = setRequested(state.requested.concat([wanted]));
  log.debug("Leaving addRequested(). ok=" + result.ok);
  return result;
}

function removeRequested(name) {
  log.debug("Entering removeRequested(). name=" + name);
  const wanted = String(name == null ? '' : name).trim();
  if (!isRequested(wanted)) {
    log.debug("Leaving removeRequested(). Not in the list.");
    return { ok: false, errors: ['This Verifier does not ask for "' + wanted + '".'] };
  }
  const result = setRequested(state.requested.filter(function (claim) { return claim !== wanted; }));
  log.debug("Leaving removeRequested(). ok=" + result.ok);
  return result;
}

function resetRequested() {
  log.debug("Entering resetRequested().");
  const result = setRequested(defaultRequested());
  log.debug("Leaving resetRequested(). ok=" + result.ok);
  return result;
}

function defaultFormatId() {
  return state.format;
}

function setDefaultFormat(id) {
  log.debug("Entering setDefaultFormat(). id=" + id);
  const format = formatById(id);
  if (!format) {
    log.debug("Leaving setDefaultFormat(). No such format.");
    return { ok: false, errors: ['There is no credential format called "' + id + '". The three ' +
                                 'are: ' + FORMAT_IDS.join(', ') + '.'] };
  }
  state.format = format.id;
  log.info('oid4vp: a request that does not name a format now asks for ' + format.id + '.');
  log.debug("Leaving setDefaultFormat(). format=" + format.id);
  return { ok: true, format: format.id };
}

// The format a request is for: what was asked for where that is one of the three,
// and the configured default otherwise. One function rather than the ternary
// chain this replaced, because "anything unrecognised falls back" was written out
// in three places and the fallback is now configuration rather than a constant.
function formatOf(wanted) {
  const format = formatById(wanted);
  return format ? format.id : state.format;
}

// ---------------------------------------------------------------------------
// The DCQL claims array, which is where the three formats stop agreeing.
//
// dc+sd-jwt      ["given_name"]                      claims are top-level
// jwt_vc_json    ["credentialSubject","given_name"]   claims are in the subject
// ldp_vc         ["credentialSubject","birthDate"]    ...under the term the
//                                                     vendored JSON-LD context
//                                                     defines, which is not the
//                                                     OIDC claim name
//
// That third line is the one that used to be wrong. Both W3C formats were given
// the OIDC claim name, which coincides for `given_name` and `family_name` — the
// only two claims this Verifier could ask for before this page existed — and does
// not for `birthdate` (`birthDate` in the context) or for `address`, which is not
// a term at all: an ldp_vc credential carries `streetAddress`, `locality`,
// `region` and `country` flat, because that is how the context defines them.
//
// A claim with no term in that context is DROPPED from an ldp_vc query rather
// than asked for under a name the credential cannot carry. Dropped and stated:
// ldpOmitted() is what the page and the Verifier's own text say it with, since a
// request that silently asked for less than the page showed would make selective
// disclosure look broken in the one format whose selective disclosure is the most
// interesting thing about it.
// ---------------------------------------------------------------------------
function pathsFor(format, claimName) {
  if (format.claimsAt === 'top') {
    return [[claimName]];
  }
  if (format.claimsAt !== 'ldp') {
    return [['credentialSubject', claimName]];
  }
  const row = rowFor(claimName);
  if (!row) {
    // Not in the catalogue, so there is nothing to translate it to. Asked for as
    // written, under credentialSubject: this is the "ask for a claim that is not
    // there" case, and the honest thing is to ask for exactly what was typed.
    return [['credentialSubject', claimName]];
  }
  return row.ldpTerms.map(function (term) { return ['credentialSubject', term]; });
}

// The whole DCQL query (OID4VP section 6), built HERE rather than in the Verifier
// so that the console's preview and the request a wallet receives cannot be two
// implementations that drift. vc_verifier.js's vpDcqlQuery() is now the caller
// that logs the artifact and nothing else.
function dcqlQuery(formatId) {
  log.debug("Entering dcqlQuery(). format=" + formatId);
  const wanted = formatOf(formatId);
  const format = formatById(wanted);
  const credential = {
    id: DCQL_ID,
    format: wanted,
    // An SD-JWT VC is identified by its vct, a W3C VC by its type array — and
    // type_values is an array OF ARRAYS, each entry a complete type set that
    // would satisfy the query. ldp_vc is named exactly as jwt_vc_json is: what
    // differs between those two is how the credential is SECURED, not how it is
    // named.
    meta: format.claimsAt === 'top'
      ? { vct_values: [format.identifier] }
      : { type_values: [format.identifier] }
  };
  const claims = dcqlClaims(wanted);
  // An EMPTY claims array is not the same request as no claims member at all, and
  // the difference is the reason this is an `if` rather than an assignment: DCQL
  // reads an absent `claims` as "the whole credential", which is the opposite of
  // what this Verifier is for — so a configuration naming no claims sends no
  // member, and every page that shows this says so in as many words rather than
  // printing an empty list.
  if (claims.length) {
    credential.claims = claims;
  }
  log.debug("Leaving dcqlQuery(). " + claims.length + " path(s) as " + wanted + ".");
  return { credentials: [credential] };
}

// The paths ONE claim takes in one format, by name rather than by row — what the
// console's table draws, and the reason it can draw a column headed "DCQL path"
// at all: a path is not a property of the claim, it is a property of the claim
// AND the format, and a column that quietly picked one format would be wrong
// two-thirds of the time.
function dcqlPathsFor(formatId, claimName) {
  const format = formatById(formatOf(formatId));
  return pathsFor(format, String(claimName || ''));
}

function dcqlClaims(formatId) {
  log.debug("Entering dcqlClaims(). format=" + formatId);
  const format = formatById(formatId) || formatById(state.format);
  const out = [];
  state.requested.forEach(function (claimName) {
    pathsFor(format, claimName).forEach(function (path) {
      out.push({ path: path });
    });
  });
  log.debug("Leaving dcqlClaims(). " + out.length + " path(s) for " + state.requested.length + " claim(s).");
  return out;
}

// The requested claims an ldp_vc query cannot carry: in the catalogue, and with no
// term in the vendored context. Not the same as "unknown" — an unknown claim is
// asked for as written (see pathsFor), because that is the negative somebody
// configured on purpose.
function ldpOmitted() {
  return state.requested.filter(function (claimName) {
    const row = rowFor(claimName);
    return !!row && row.ldpTerms.length === 0;
  });
}

module.exports = {
  DCQL_ID: DCQL_ID,
  REQUESTABLE: REQUESTABLE,
  FORMATS: FORMATS,
  FORMAT_IDS: FORMAT_IDS,
  MAX_REQUESTED: MAX_REQUESTED,
  defaultRequested: defaultRequested,
  rowFor: rowFor,
  carriedNow: carriedNow,
  formatById: formatById,
  formatOf: formatOf,
  defaultFormatId: defaultFormatId,
  setDefaultFormat: setDefaultFormat,
  requestedClaims: requestedClaims,
  requestedRows: requestedRows,
  isRequested: isRequested,
  setRequested: setRequested,
  addRequested: addRequested,
  removeRequested: removeRequested,
  resetRequested: resetRequested,
  dcqlClaims: dcqlClaims,
  dcqlPathsFor: dcqlPathsFor,
  dcqlQuery: dcqlQuery,
  ldpOmitted: ldpOmitted
};
