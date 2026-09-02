'use strict';
//
// File: scim_map.js
//
// ---------------------------------------------------------------------------
// WHAT A SCIM RESOURCE IS, IN TERMS OF LDAP ATTRIBUTES.
//
// `scim.js` speaks RFC 7644 and reaches the directory; this says which LDAP
// attribute each SCIM member is, in both directions. It is the FOURTH library
// over the same territory and the split is the one rule 3d already draws:
//
//   vc_claims.js            what an issued CREDENTIAL carries      /admin/vc
//   vc_verifier_config.js   what the mock Verifier ASKS FOR        /admin/vc-verifier-config
//   claim_attributes.js     what a TOKEN carries                   /admin/claims
//   claim_attributes.js     what an ASSERTION carries              /admin/saml-attributes
//   this file               what a SCIM RESOURCE is made of        /admin/scim
//
// The first three are SELECTIONS out of one catalogue and are deliberately
// independent of each other. This one is NOT a selection and there is nothing to
// tick: SCIM defines its own schema (RFC 7643), so what a User carries is
// decided by that document rather than by this service, and the only question
// left is which LDAP attribute each member is stored in. That is a mapping and a
// mapping is a table.
//
// **THE ATTRIBUTE SPELLINGS ARE NOT A FIFTH LIST.** Every row that names an
// attribute vc_claims.js already knows is checked against that catalogue at
// require time and DISAGREEMENTS ARE REPORTED — the same rule ldap_server.js's
// learnName() follows, and for the same reason: four independently maintained
// sets of spellings is how one of them comes to be quietly wrong about
// `schacDateOfBirth` while all four look right read alone. Reported and not
// thrown, because a table of how to capitalise a name must never be able to stop
// this service starting.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3) AND IT TOUCHES NO DIRECTORY.
//
// It registers no route, so its position in the require order is not a position.
// It requires `helpers.js` and `vc_claims.js` and nothing else here, and neither
// requires it back — which is what lets `admin.js` require it to draw the
// mapping table on /admin/scim even though admin.js is required BEFORE
// ldap_server.js. That is the whole reason the conversions live here rather than
// in `scim.js`: a require from the console into the SCIM module would drag the
// /scim routes into the express router ahead of /admin, and /admin/sts-metadata
// is built by walking that router.
//
// So there are two readers and they read different halves:
//
//   scim.js    the CONVERSIONS, on every request
//   admin.js   the CATALOGUE, to draw it on a page
//
// Nothing in this file reads or writes an entry. It is handed an entry object —
// the {dn, origin, createdAt, modifiedAt, attributes} shape ldap_server.js's
// entryObject() produces — and hands back a SCIM resource, or the reverse. That
// is what makes it testable without a directory and what keeps the placement
// rules (where a person's entry goes, what counts as a group) in the one module
// that already owns them.
//
// ---------------------------------------------------------------------------
// FIVE DECISIONS ARE LOAD-BEARING, and each is easy to undo by accident.
//
// **THE SCIM `id` IS THE ENTRY'S DN.** RFC 7643 section 3.1 wants an opaque,
// server-assigned, unique identifier that the client must not parse, and the DN
// is exactly that and is already the key the entry is stored under. Any other
// choice is a SECOND definition of one fact: a `uid` is not unique in this tree
// (nothing stops `uid=alice,ou=users` and `cn=alice,ou=people` existing side by
// side), a synthesised id would have to be stored on the entry and would go
// stale on a rename the way `applicationEntry()` shows a stored DN does, and a
// digest would be unusable in the place a reader most wants to read one. The
// cost is stated rather than hidden: a DN in a URL path segment is ugly
// (`/scim/v2/Users/uid%3Dalice%2Cou%3Dusers%2Cdc%3Dexample%2Cdc%3Dcom`), and an
// LDAP rename gives the same person a new SCIM id — which is a real deviation
// from "stable for the lifetime of the resource" and is on /admin/scim in those
// words. It is the honest one for a directory-backed server: after a rename it
// IS a different key.
//
// **SCIM SEES A WINDOW ONTO THE ENTRY AND A PUT REPLACES ONLY WHAT IS INSIDE
// IT.** RFC 7644 section 3.5.1 says a PUT replaces the resource, and read
// strictly against an LDAP entry that would mean a provisioning client
// deleting `schacDateOfBirth`, `authnMethod`, `mfaAuthenticated` and every
// x509 attribute the moment it updated somebody's phone number — facts SCIM
// never knew about, cannot send, and cannot restore. So `fromScimUser()` is
// given the attributes the entry already has and REPLACES ONLY THE MAPPED
// ONES. Everything outside the window is carried through untouched. A client
// that means to remove a mapped value still can, by omitting it, which is what
// the PUT semantics are actually for.
//
// **A TYPE ON A MULTI-VALUED MEMBER IS SCIM'S IDEA, NOT THE DIRECTORY'S.** LDAP
// has `telephoneNumber` and `mobile` as separate attribute types; SCIM has one
// `phoneNumbers` array whose entries carry a `type`. So the type on the way OUT
// says which attribute the value came from, and on the way IN it decides which
// attribute it goes to — with an untyped value going to the first row for that
// member. `primary` is emitted for the first value and is NOT stored: there is
// no attribute for it, and inventing one would mean this service quietly
// disagreeing with an `ldapmodify` about which of somebody's two mail values is
// the real one.
//
// **`active` AND `externalId` ARE THIS SERVICE'S OWN ATTRIBUTES AND NOTHING
// READS THEM.** There is no standard LDAP attribute for either — `nsAccountLock`
// and `pwdAccountLockedTime` are vendor inventions and mean something narrower —
// so they are stored as `scimActive` and `scimExternalId`, named the way every
// other invention here is. Setting `active` to false DEACTIVATES NOBODY: no
// endpoint in this service reads it, no bind is refused because of it and no
// token is withheld. That is the same distinction this service already draws
// about a group (carrying a fact is not acting on one), it is stated on
// /admin/scim and in the ServiceProviderConfig's own documentation link, and it
// matters more here than for a group because deprovisioning is the single most
// common thing a SCIM client is built to do. A mock that silently pretended to
// disable an account would teach a provisioning client that its deprovisioning
// path works.
//
// **EVERY PERSON UNDER `ou=users` MAPS, INCLUDING THE ONES WITH NO `uid`.**
// `userName` is RFC 7643's one required User attribute and scimmy enforces it
// on the way OUT, while a client certificate's entry is named `cn=<CN>` and
// carries no `uid` at all — so one such entry used to make `GET /Users` a 400
// for the WHOLE directory. `toScimUser()` therefore falls back to the RDN
// value (the directory's own `usernameOfEntry()`, passed in) and then to the
// DN, exactly as `toScimGroup()` does for `displayName`. The rule is that this
// mapping is TOTAL: it is handed whatever is in the tree and it must produce a
// resource, because the alternative is one entry making every other person
// unreadable. The whole argument is at the code.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const vcClaims = require('../oid4vc/vc_claims');

// The schema URNs, written once. RFC 7643 sections 4.1, 4.2 and 4.3.
const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const ENTERPRISE_SCHEMA = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';

// ---------------------------------------------------------------------------
// THE ATTRIBUTES THIS SERVICE INVENTED FOR SCIM.
//
// Merged into ldap_server.js's canonical-name table through learnName(), which
// is the ONE door into it, so that /admin/users and /admin/ldap/directory show
// `scimActive` rather than the `scimactive` the store lower-cases it to. Both
// are `stsApplication`-style inventions: nothing standard carries them, and
// saying so beside them is cheaper than leaving a reader to search RFC 4519 for
// an attribute that is not in it.
// ---------------------------------------------------------------------------
const OWN_NAMES = [
  'scimActive',
  'scimExternalId'
];

// ---------------------------------------------------------------------------
// THE USER MAPPING.
//
// `scim` is the SCIM attribute path as RFC 7643 spells it — dotted for a
// sub-attribute of a complex type. `ldap` is the attribute type in the
// directory. `kind` says how the two shapes differ, which is the only thing a
// converter has to branch on:
//
//   'single'   one SCIM value, one LDAP value
//   'bool'     as above, stored as the LDAP boolean strings TRUE / FALSE
//   'multi'    a SCIM array of complex values, one LDAP attribute per `type`
//   'complex'  a SCIM complex value whose sub-attributes are separate LDAP types
//   'derived'  read-only: computed rather than stored (`groups`, the meta block)
//
// `schema` names the document that defines the LDAP attribute, the way
// vc_claims.js's rows do, so that a reader can tell an RFC 4519 type from one of
// this service's own without leaving the page.
// ---------------------------------------------------------------------------
const USER_ATTRIBUTES = [
  { scim: 'userName', ldap: 'uid', kind: 'single', required: true,
    schema: 'RFC 4519 2.39',
    note: 'The SCIM uniqueness constraint. It is the RDN of an auto-created ' +
          'entry, so for anybody this service authenticated it is also their ' +
          'sign-in name — but it is NOT the SCIM id, which is the DN.' },
  { scim: 'externalId', ldap: 'scimExternalId', kind: 'single',
    schema: "this service's own (no standard type)",
    note: 'The provisioning client\'s own identifier for this person. Stored ' +
          'verbatim and read by nothing here.' },
  { scim: 'name.formatted', ldap: 'cn', kind: 'single', schema: 'RFC 4519 2.3' },
  { scim: 'name.familyName', ldap: 'sn', kind: 'single', schema: 'RFC 4519 2.32' },
  { scim: 'name.givenName', ldap: 'givenName', kind: 'single', schema: 'RFC 4519 2.6' },
  { scim: 'displayName', ldap: 'displayName', kind: 'single', schema: 'RFC 2798 2.3' },
  { scim: 'title', ldap: 'title', kind: 'single', schema: 'RFC 4519 2.38' },
  { scim: 'userType', ldap: 'employeeType', kind: 'single', schema: 'RFC 2798 2.7' },
  { scim: 'preferredLanguage', ldap: 'preferredLanguage', kind: 'single',
    schema: 'RFC 2798 2.10' },
  { scim: 'profileUrl', ldap: 'labeledURI', kind: 'single', schema: 'RFC 2079 2' },
  { scim: 'active', ldap: 'scimActive', kind: 'bool',
    schema: "this service's own (no standard type)",
    note: 'DEACTIVATES NOBODY. Nothing in this service reads it: no bind is ' +
          'refused, no token is withheld and no session ends. It is recorded ' +
          'and that is all.' },

  { scim: 'emails', ldap: 'mail', kind: 'multi', type: 'work',
    schema: 'RFC 4524 2.16' },
  { scim: 'phoneNumbers', ldap: 'telephoneNumber', kind: 'multi', type: 'work',
    schema: 'RFC 4519 2.35' },
  { scim: 'phoneNumbers', ldap: 'mobile', kind: 'multi', type: 'mobile',
    schema: 'RFC 4524 2.18' },

  { scim: 'addresses.streetAddress', ldap: 'street', kind: 'complex',
    parent: 'addresses', schema: 'RFC 4519 2.34' },
  { scim: 'addresses.locality', ldap: 'l', kind: 'complex',
    parent: 'addresses', schema: 'RFC 4519 2.16' },
  { scim: 'addresses.region', ldap: 'st', kind: 'complex',
    parent: 'addresses', schema: 'RFC 4519 2.33' },
  { scim: 'addresses.postalCode', ldap: 'postalCode', kind: 'complex',
    parent: 'addresses', schema: 'RFC 4519 2.24' },
  { scim: 'addresses.country', ldap: 'c', kind: 'complex',
    parent: 'addresses', schema: 'RFC 4519 2.2' },
  { scim: 'addresses.formatted', ldap: 'postalAddress', kind: 'complex',
    parent: 'addresses', schema: 'RFC 4519 2.23',
    // RFC 4517 3.3.28 separates the lines of a postal address with '$'; SCIM's
    // `formatted` is a display string with newlines. The same conversion
    // vc_claims.js does for the OIDC `formatted` member, for the same reason:
    // two documents spelling one address differently.
    toScim: function (value) { return String(value).split('$').join('\n'); },
    fromScim: function (value) { return String(value).split('\n').join('$'); } },

  { scim: ENTERPRISE_SCHEMA + ':employeeNumber', ldap: 'employeeNumber',
    kind: 'single', extension: true, schema: 'RFC 2798 2.6' },
  { scim: ENTERPRISE_SCHEMA + ':department', ldap: 'departmentNumber',
    kind: 'single', extension: true, schema: 'RFC 2798 2.4' },
  { scim: ENTERPRISE_SCHEMA + ':organization', ldap: 'o',
    kind: 'single', extension: true, schema: 'RFC 4519 2.19' },
  { scim: ENTERPRISE_SCHEMA + ':division', ldap: 'ou',
    kind: 'single', extension: true, schema: 'RFC 4519 2.20' },
  { scim: ENTERPRISE_SCHEMA + ':manager.value', ldap: 'manager',
    kind: 'single', extension: true, schema: 'RFC 2798 2.9',
    note: 'A DN in the directory and an id in SCIM. It is passed through ' +
          'UNCHANGED rather than resolved, because the SCIM id of a person IS ' +
          'their DN here — so the two spellings coincide, and a resolution ' +
          'step would only be a place for them to stop coinciding.' },

  { scim: 'groups', ldap: '(member, uniqueMember, memberUid on the group)',
    kind: 'derived', readOnly: true, schema: 'RFC 4519 2.17, 2.40; RFC 2307 2.3',
    note: 'READ-ONLY, as RFC 7643 section 4.1.2 requires. Membership is a fact ' +
          'about the GROUP\'s entry, so it is changed through a Group resource ' +
          'and never through a User one. Resolved by ldap_server.js\'s ' +
          'groupsOfUser(), which is the same function the groups claim reads — ' +
          'so a token and a SCIM resource cannot disagree about who is in what.' },
  { scim: 'meta.created', ldap: 'createTimestamp', kind: 'derived', readOnly: true,
    schema: 'RFC 4512 3.4' },
  { scim: 'meta.lastModified', ldap: 'modifyTimestamp', kind: 'derived', readOnly: true,
    schema: 'RFC 4512 3.4' }
];

// ---------------------------------------------------------------------------
// THE GROUP MAPPING, which is smaller and has one hard part.
//
// `members` is not a mapping of one attribute: ldap_server.js resolves THREE
// (`member` and `uniqueMember` hold a DN, `memberUid` holds a bare name) and
// treating them alike is how every posixGroup membership silently disappears.
// So the read side is handed the already-resolved list that module produces and
// this file only reshapes it; the WRITE side puts every value in `member`,
// because a SCIM client sends an id, an id here is a DN, and `member` is the
// attribute that holds one. A group that already used `memberUid` keeps it —
// see `fromScimGroup()`, which is the window rule again.
// ---------------------------------------------------------------------------
const GROUP_ATTRIBUTES = [
  { scim: 'displayName', ldap: 'cn', kind: 'single', required: true,
    schema: 'RFC 4519 2.3' },
  { scim: 'externalId', ldap: 'scimExternalId', kind: 'single',
    schema: "this service's own (no standard type)" },
  { scim: 'members', ldap: 'member', kind: 'members',
    schema: 'RFC 4519 2.17',
    note: 'READ resolves member, uniqueMember and memberUid alike; WRITE puts ' +
          'a new value in `member`, since a SCIM member id is a DN. A dangling ' +
          'member — a DN nothing is stored at — is returned as a member, ' +
          'because the group saying so is the fact, and this directory does no ' +
          'referential integrity on purpose.' },
  { scim: 'meta.created', ldap: 'createTimestamp', kind: 'derived', readOnly: true,
    schema: 'RFC 4512 3.4' },
  { scim: 'meta.lastModified', ldap: 'modifyTimestamp', kind: 'derived', readOnly: true,
    schema: 'RFC 4512 3.4' }
];

// ---------------------------------------------------------------------------
// THE SPELLING CHECK, run once at require time.
//
// Every row whose LDAP attribute is one vc_claims.js already knows is compared
// against that catalogue's spelling. This is learnName()'s rule applied one
// module earlier: that function will also see these names (ldap_server.js merges
// OWN_NAMES below), but it would compare them against the FIRST spelling learnt
// and could not say which list disagreed. Here the answer is specific.
// ---------------------------------------------------------------------------
function checkSpellings() {
  log.debug("Entering checkSpellings().");
  let checked = 0;
  USER_ATTRIBUTES.concat(GROUP_ATTRIBUTES).forEach(function (row) {
    if (row.kind === 'derived') {
      return;
    }
    const known = vcClaims.CANONICAL_NAMES[String(row.ldap).toLowerCase()];
    if (known === undefined) {
      return;
    }
    checked++;
    if (known !== row.ldap) {
      log.warn('scim: the SCIM mapping spells the attribute type "' +
               String(row.ldap).toLowerCase() + '" as "' + row.ldap +
               '" and the credential claim catalogue spells it "' + known +
               '". They match identically either way (RFC 4512 section 2.5 ' +
               'makes attribute descriptions case-insensitive) so nothing is ' +
               'found or missed differently; it is only the spelling shown on ' +
               'a page, and one of the two tables is wrong.');
    }
  });
  log.debug("Leaving checkSpellings(). " + checked + " row(s) had a spelling to check.");
}

checkSpellings();

// ---------------------------------------------------------------------------
// Reading an attribute off an entry object.
//
// ldap_server.js hands attributes back CANONICALLY SPELLED (`givenName`) while
// the store holds them lower-cased, and a caller may have either in hand. So
// every lookup here is case-insensitive, exactly as applications.js's
// byLowerName() is and for the same reason: an index that assumed either
// produces a resource with an empty userName rather than an error.
// ---------------------------------------------------------------------------
function valuesOf(attributes, name) {
  const wanted = String(name || '').toLowerCase();
  const keys = Object.keys(attributes || {});
  for (let i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() === wanted) {
      const value = attributes[keys[i]];
      return Array.isArray(value) ? value.slice(0) : [value];
    }
  }
  return [];
}

function firstOf(attributes, name) {
  const values = valuesOf(attributes, name);
  return values.length ? String(values[0]) : '';
}

// Put a value at a dotted path, creating the objects on the way. Written out
// rather than reached for from a dependency because the whole of it is this.
//
// A LIST of segments is accepted as well as a dotted string, for the one path
// here that cannot be spelt as one: an extension attribute's member name holds
// the schema URN, and that has dots of its own. See egressPath().
function setPath(target, path, value) {
  const parts = Array.isArray(path) ? path : String(path).split('.');
  let node = target;
  for (let i = 0; i < parts.length - 1; i++) {
    if (node[parts[i]] === undefined) {
      node[parts[i]] = {};
    }
    node = node[parts[i]];
  }
  node[parts[parts.length - 1]] = value;
}

function getPath(source, path) {
  const parts = Array.isArray(path) ? path : String(path).split('.');
  let node = source;
  for (let i = 0; i < parts.length; i++) {
    if (node === null || node === undefined || typeof node !== 'object') {
      return undefined;
    }
    node = node[parts[i]];
  }
  return node;
}

// The two halves of an extension row's path, separated at the LAST colon — the
// attribute half never contains one. RFC 7643 section 3.3 spells such a path as
// the schema URN, a colon, and then an ordinary (possibly dotted) attribute:
// `urn:...:extension:enterprise:2.0:User:manager.value`.
function extensionParts(scimPath) {
  const path = String(scimPath);
  const colon = path.lastIndexOf(':');
  return { urn: path.slice(0, colon), path: path.slice(colon + 1) };
}

// ---------------------------------------------------------------------------
// WHERE AN EXTENSION ROW'S VALUE SITS ON THE WAY OUT, AND WHY IT IS NOT WHERE
// IT SITS ON THE WAY IN.
//
// RFC 7643 section 3.3 lets a resource carry an extension attribute in either
// of two shapes: a member named by the schema URN holding an object, or a
// top-level member whose name is the URN, a colon and the attribute. scimmy
// hands the ingress handler the FIRST — its coercion normalises to it — and
// accepts either on the way out, so the two look interchangeable and are not.
// What decides it is the FILTER MATCHER: `SCIMMY.Types.Filter` parses
// `urn:...:User:manager.value eq "x"` into the key `urn:...:User:manager`
// carrying a nested `value`, which is the SECOND shape. A resource carrying
// only the object form therefore matches no filter naming an enterprise
// attribute — and a filter naming a sub-attribute of one throws, which is the
// same scimmy defect applyFilter() in scim.js documents.
//
// So egress writes the namespaced form and ingress reads the object form, each
// being the one the side of scimmy it faces actually looks at.
//
// Both come back as a LIST of segments rather than a dotted string, because the
// first segment cannot be spelt in one: the URN has dots of its own
// (`...:enterprise:2.0:User`), so splitting the whole path on '.' — which is
// what this file used to do — buries the value under a member named
// `...:enterprise:2` that no client asks for and scimmy's coercion drops. That
// is why the enterprise attributes went out of a POST and came back as nothing.
//
// Neither is entered and left out loud, and nor is extensionParts() above: they
// sit with setPath(), getPath() and valuesOf() — called once per attribute per
// resource, so a pair of log lines in them is a list of a thousand rows for one
// page of users, and the converters that call them already log the conversion.
// ---------------------------------------------------------------------------
function egressPath(row) {
  if (!row.extension) {
    return String(row.scim).split('.');
  }
  const parts = extensionParts(row.scim);
  const steps = String(parts.path).split('.');
  return [parts.urn + ':' + steps[0]].concat(steps.slice(1));
}

function ingressPath(row) {
  if (!row.extension) {
    return String(row.scim).split('.');
  }
  const parts = extensionParts(row.scim);
  return [parts.urn].concat(String(parts.path).split('.'));
}

// The LDAP boolean strings. RFC 4517 section 3.3.3 spells them in capitals and
// nothing else is a boolean, so `true` and `1` written by an ldapmodify are read
// generously on the way out and never written on the way in.
function boolFromLdap(text) {
  const value = String(text || '').trim().toLowerCase();
  return value === 'true' || value === '1' || value === 'yes';
}

// A generalized time (RFC 4517 3.3.13, `20260821T...Z` as this service writes
// it) as the ISO 8601 instant SCIM's `meta` wants. A value this service did not
// write is passed through rather than guessed at: `meta.created` showing the raw
// directory value is a reader's clue about where it came from, and a fabricated
// date is not.
function isoFromGeneralizedTime(text) {
  const digits = String(text || '').replace(/[^0-9]/g, '');
  if (digits.length < 14) {
    return String(text || '') || undefined;
  }
  const iso = digits.slice(0, 4) + '-' + digits.slice(4, 6) + '-' + digits.slice(6, 8) +
              'T' + digits.slice(8, 10) + ':' + digits.slice(10, 12) + ':' +
              digits.slice(12, 14) + 'Z';
  return Number.isNaN(new Date(iso).getTime()) ? String(text) : iso;
}

// ---------------------------------------------------------------------------
// EVERYTHING OUTSIDE THE MAPPING'S WINDOW, CARRIED THROUGH — EXCEPT THREE
// ATTRIBUTES THAT ARE NOT REALLY ON THE ENTRY.
//
// The entry object this is given comes from ldap_server.js's entryObject(),
// which adds `entryDN` SYNTHESISED from where the entry is stored and includes
// the two operational timestamps. None of the three is a stored attribute:
// `entryDN` is the key the entry lives under (RFC 5020), and createTimestamp and
// modifyTimestamp belong to the entry rather than to whatever wrote it.
//
// Carrying them through would WRITE them, because the write replaces the whole
// attribute set — and it did, until an audit row showed `entryDN` among the
// attributes a SCIM PUT had just written. What that produces is precisely the
// failure the synthesis exists to prevent: a stored copy of the DN, which is a
// second definition of one fact and the one that goes stale the moment somebody
// renames the entry with an LDAP modrdn. The timestamps are less dramatic and
// wrong the same way — writePerson() sets both itself, so a carried-through copy
// is overwritten a line later and only ever confused an audit row.
//
// Dropped HERE rather than in ldap_server.js's write, because that module is
// right to accept whatever attributes it is handed: what is operational is a
// property of the read that produced them, and this is the only place that read
// and that write meet.
// ---------------------------------------------------------------------------
const NOT_STORED = ['entrydn', 'createtimestamp', 'modifytimestamp'];

function carryThrough(existing) {
  const out = {};
  Object.keys(existing || {}).forEach(function (name) {
    if (NOT_STORED.indexOf(String(name).toLowerCase()) >= 0) {
      return;
    }
    const value = existing[name];
    out[name] = Array.isArray(value) ? value.slice(0) : [String(value)];
  });
  return out;
}

// ---------------------------------------------------------------------------
// AN ENTRY AS A SCIM USER.
//
// `context` carries what this file cannot work out on its own — the groups the
// person is in, which needs the directory — and the location prefix for `meta`.
// Everything else is read off the entry.
//
// THE RESULT IS PADDED and that is a route around a defect rather than a style.
// `SCIMMY.Types.Filter#match()` in scimmy 1.3.5 does `Object.entries(actual)` on
// the value of a nested attribute without checking it is there, so a filter
// naming `emails.value` throws — not "does not match", THROWS — for every
// resource that has no `emails` member at all. That is the ordinary case: a
// filter like `emails.value co "@example.com"` against a directory where one
// person has no mail. So every multi-valued and complex member is present, empty
// where there is nothing, and `prune()` below takes the empties back off before
// the resource is returned to a client. The two steps are separate on purpose —
// the padding is for the matcher and the pruning is for the wire, and folding
// them together is how one of them quietly stops happening.
// ---------------------------------------------------------------------------
function toScimUser(entry, context) {
  log.debug("Entering toScimUser(). dn=" + (entry && entry.dn));
  const ctx = context || {};
  const attributes = (entry && entry.attributes) || {};
  const resource = {
    schemas: [USER_SCHEMA],
    id: entry.dn,
    // Padded for the matcher; pruned before it goes out.
    name: {},
    emails: [],
    phoneNumbers: [],
    addresses: [],
    groups: [],
    meta: {
      resourceType: 'User',
      created: isoFromGeneralizedTime(firstOf(attributes, 'createTimestamp') || entry.createdAt),
      lastModified: isoFromGeneralizedTime(firstOf(attributes, 'modifyTimestamp') || entry.modifiedAt),
      location: (ctx.location || '') + encodeURIComponent(entry.dn)
    }
  };

  // The extension members this mapping writes into, padded like the members
  // above and for the same reason: `manager.value` is a sub-attribute, so a
  // filter naming it dives into a value that has to be there. Built from the
  // catalogue rather than written out, so an extension row cannot be added
  // without its padding, and every parent on the way is created because the
  // matcher walks the whole path and not just the leaf.
  USER_ATTRIBUTES.forEach(function (row) {
    if (!row.extension) {
      return;
    }
    const steps = egressPath(row);
    let node = resource;
    for (let i = 0; i < steps.length - 1; i++) {
      if (node[steps[i]] === undefined) {
        node[steps[i]] = {};
      }
      node = node[steps[i]];
    }
  });

  const address = {};
  USER_ATTRIBUTES.forEach(function (row) {
    if (row.kind === 'derived') {
      return;
    }
    const values = valuesOf(attributes, row.ldap);
    if (!values.length) {
      return;
    }
    // An extension row is written as its namespaced member rather than at a
    // dotted path off the resource. See egressPath().
    const path = egressPath(row);
    if (row.kind === 'single') {
      setPath(resource, path,
              row.toScim ? row.toScim(values[0]) : String(values[0]));
      return;
    }
    if (row.kind === 'bool') {
      setPath(resource, path, boolFromLdap(values[0]));
      return;
    }
    if (row.kind === 'complex') {
      address[row.scim.split('.').pop()] = row.toScim ? row.toScim(values[0]) : String(values[0]);
      return;
    }
    // 'multi'. One SCIM entry per LDAP value, carrying the type this row says —
    // which is what tells a client that `mobile` and `telephoneNumber` are two
    // kinds of one SCIM member rather than one attribute listed twice.
    values.forEach(function (value) {
      resource[row.scim].push({ value: String(value), type: row.type });
    });
  });

  // ONE MEMBER IS NOT OPTIONAL, AND AN ENTRY THAT COULD NOT SUPPLY IT USED TO
  // TAKE THE WHOLE LIST DOWN WITH IT.
  //
  // `userName` is the only REQUIRED attribute in RFC 7643's User schema, and
  // scimmy enforces it on the way OUT as well as on the way in: a resource
  // without one throws `Required attribute 'userName' is missing` out of its
  // coercion. The egress handler maps every person in `ou=users` in one pass,
  // so ONE entry that produced no `userName` answered a plain `GET /Users`
  // with a 400 naming an attribute and naming no entry — every other person in
  // the directory unreadable over SCIM because of one of them, and the message
  // pointing at the client's request, which had nothing wrong with it.
  //
  // An entry with no `uid` is ordinary here rather than corrupt, which is why
  // this is a mapping decision and not a repair. `certificatePlan()` names a
  // client certificate's entry `cn=<CN>,ou=users` and deliberately writes no
  // `uid` — the certificate is the identity, and `namePlan()`'s fold is what
  // later adds one if that person also signs in by name — so a single mutual
  // TLS connection to 9443 was enough to break every SCIM list until somebody
  // deleted the entry. An `ldapadd` can produce the same thing at will: this
  // directory enforces no schema, on purpose.
  //
  // The fallback is the RDN VALUE, and it is the DIRECTORY'S rule rather than
  // a second one invented here: `usernameOfEntry()` is what
  // `existingUserEntry()` matches a typed name against, so the `userName` SCIM
  // reports is the name a create of that person would collide with. `entry.dn`
  // is the last resort — exactly as `toScimGroup()` falls back to it for
  // `displayName`, and for the same reason: whatever is under `ou=users`, this
  // function has to produce a resource rather than an exception.
  if (!String(resource.userName || '').trim()) {
    resource.userName = String(ctx.rdnName || '').trim() || entry.dn;
    log.debug("toScimUser(). The entry carries no uid, so its userName is " +
              "the RDN value: " + resource.userName);
  }

  // `primary` marks the FIRST value of each multi-valued member and is not
  // stored anywhere — see the header. Set after the loop rather than inside it
  // because two rows feed `phoneNumbers` and the first value of the member is
  // not the first value of either row.
  ['emails', 'phoneNumbers'].forEach(function (member) {
    if (resource[member].length) {
      resource[member][0].primary = true;
    }
  });

  if (Object.keys(address).length) {
    address.type = 'work';
    resource.addresses.push(address);
  }

  // The groups this person is in, resolved by the caller. `type` is `direct`
  // for every one of them because nothing in this service expands a nested
  // group — the console says the same thing about the same data, and claiming
  // `indirect` membership we never computed would be a lie about a feature that
  // is not here.
  (ctx.groups || []).forEach(function (group) {
    resource.groups.push({
      value: group.dn,
      display: group.cn || group.dn,
      type: 'direct'
    });
  });

  log.debug("Leaving toScimUser(). " + Object.keys(resource).length + " member(s).");
  return resource;
}

// ---------------------------------------------------------------------------
// A SCIM USER AS ATTRIBUTES, over the attributes the entry already has.
//
// `existing` is the entry's current attribute object, or {} for a create. What
// comes back is the WHOLE attribute set to write, because ldap_server.js's write
// replaces rather than merges (the reason is written there): so everything
// outside the mapping's window has to be carried through here, or a SCIM update
// would silently delete the credential claims and the authentication history.
//
// Returns `{ attributes, errors }` rather than throwing, the same contract
// vc_claims.setSelection() has: the caller is a request handler that has to turn
// a refusal into a SCIM error with the right `scimType`, and an exception thrown
// through scimmy's ingress handler comes back as a 404 (see the note in scim.js).
// ---------------------------------------------------------------------------
function fromScimUser(resource, existing) {
  log.debug("Entering fromScimUser().");
  const errors = [];
  const out = carryThrough(existing);

  // Then take every mapped attribute back off, so that an omitted SCIM member
  // REMOVES the value rather than leaving the old one behind. That is what makes
  // this a PUT and not a PATCH, and doing it as a separate pass is what makes it
  // true for the rows the resource does not mention at all.
  USER_ATTRIBUTES.forEach(function (row) {
    if (row.kind === 'derived' || row.readOnly) {
      return;
    }
    Object.keys(out).forEach(function (name) {
      if (name.toLowerCase() === String(row.ldap).toLowerCase()) {
        delete out[name];
      }
    });
  });

  const address = (Array.isArray(resource.addresses) && resource.addresses.length)
    ? resource.addresses[0] : {};

  USER_ATTRIBUTES.forEach(function (row) {
    if (row.kind === 'derived' || row.readOnly) {
      return;
    }
    if (row.kind === 'single' || row.kind === 'bool') {
      // Read an extension row out of the object at its schema URN, which is
      // the shape scimmy's coercion hands this handler and NOT the one the
      // egress side writes. See egressPath().
      const value = getPath(resource, ingressPath(row));
      if (value === undefined || value === null || String(value) === '') {
        return;
      }
      out[row.ldap] = [row.kind === 'bool'
        ? (value === true || String(value).toLowerCase() === 'true' ? 'TRUE' : 'FALSE')
        : (row.fromScim ? row.fromScim(value) : String(value))];
      return;
    }
    if (row.kind === 'complex') {
      const value = address[row.scim.split('.').pop()];
      if (value === undefined || value === null || String(value) === '') {
        return;
      }
      out[row.ldap] = [row.fromScim ? row.fromScim(value) : String(value)];
      return;
    }
    // 'multi'. Every value whose `type` names this row, plus — for the row that
    // is the member's DEFAULT — every value carrying no type at all. Without
    // that second half a client sending `{"value": "a@b.example"}` with no type,
    // which is legal and common, would have its email accepted and stored
    // nowhere.
    const values = (Array.isArray(resource[row.scim]) ? resource[row.scim] : [])
      .filter(function (item) {
        const type = String((item && item.type) || '').toLowerCase();
        return type === String(row.type).toLowerCase() ||
               (type === '' && isDefaultRowFor(row.scim, row));
      })
      .map(function (item) { return String(item && item.value === undefined ? '' : item.value); })
      .filter(function (value) { return value !== ''; });
    if (values.length) {
      out[row.ldap] = values;
    }
  });

  const userName = String(getPath(resource, 'userName') || '').trim();
  if (!userName) {
    errors.push('userName is required (RFC 7643 section 4.1.1) and was not sent.');
  }

  log.debug("Leaving fromScimUser(). " + Object.keys(out).length +
            " attribute(s), " + errors.length + " error(s).");
  return { attributes: out, errors: errors };
}

// Which row of a multi-valued member takes the values that carry no type. The
// FIRST row for that member in the catalogue, which is why the catalogue's order
// is not arbitrary: an untyped phone number is a `telephoneNumber` because that
// row is listed before `mobile`.
function isDefaultRowFor(member, row) {
  const rows = USER_ATTRIBUTES.filter(function (candidate) {
    return candidate.kind === 'multi' && candidate.scim === member;
  });
  return rows.length > 0 && rows[0].ldap === row.ldap;
}

// ---------------------------------------------------------------------------
// A GROUP ENTRY AS A SCIM GROUP.
//
// `members` arrives already resolved — the array ldap_server.js's membersOf()
// builds, whose items carry `value`, `dn`, `present` and `kind`. This file
// reshapes it and decides nothing about it, for the reason group_claims.js
// gives about the same data: that module owns WHAT A GROUP IS and this owns what
// SCIM says about one.
// ---------------------------------------------------------------------------
function toScimGroup(entry, context) {
  log.debug("Entering toScimGroup(). dn=" + (entry && entry.dn));
  const ctx = context || {};
  const attributes = (entry && entry.attributes) || {};
  const resource = {
    schemas: [GROUP_SCHEMA],
    id: entry.dn,
    displayName: firstOf(attributes, 'cn') || entry.dn,
    members: [],
    meta: {
      resourceType: 'Group',
      created: isoFromGeneralizedTime(firstOf(attributes, 'createTimestamp') || entry.createdAt),
      lastModified: isoFromGeneralizedTime(firstOf(attributes, 'modifyTimestamp') || entry.modifiedAt),
      location: (ctx.location || '') + encodeURIComponent(entry.dn)
    }
  };
  const externalId = firstOf(attributes, 'scimExternalId');
  if (externalId) {
    resource.externalId = externalId;
  }

  (ctx.members || []).forEach(function (member) {
    resource.members.push({
      // The DN rather than the raw value, so that a `memberUid` holding `alice`
      // comes back as the same id the User resource has. Sending the bare name
      // would be SCIM saying two different things about one person depending on
      // which attribute their membership happened to be written in.
      value: member.dn,
      display: member.cn || member.displayName || member.value,
      // RFC 7643 section 4.2 defines `type` on a member as User or Group. A
      // dangling member is neither and is reported as a User rather than
      // omitted: the group listing it IS the fact, this directory does no
      // referential integrity on purpose, and dropping the row would hide the
      // one thing /admin/groups exists to show.
      type: member.kind === 'group' ? 'Group' : 'User'
    });
  });

  log.debug("Leaving toScimGroup(). " + resource.members.length + " member(s).");
  return resource;
}

// A SCIM group as attributes, over what the entry already has — the same window
// rule `fromScimUser()` follows, and here it does one extra thing worth knowing
// about: a group whose membership was written as `uniqueMember` or `memberUid`
// has THOSE attributes cleared as well, because SCIM's `members` is the whole
// membership and leaving half of it in a second attribute would make a client
// that removed everybody find the group still populated.
function fromScimGroup(resource, existing) {
  log.debug("Entering fromScimGroup().");
  const errors = [];
  const out = carryThrough(existing);

  ['cn', 'scimExternalId', 'member', 'uniqueMember', 'memberUid'].forEach(function (name) {
    Object.keys(out).forEach(function (key) {
      if (key.toLowerCase() === name.toLowerCase()) {
        delete out[key];
      }
    });
  });

  const displayName = String(resource.displayName || '').trim();
  if (!displayName) {
    errors.push('displayName is required (RFC 7643 section 4.2) and was not sent.');
  } else {
    out.cn = [displayName];
  }
  if (resource.externalId) {
    out.scimExternalId = [String(resource.externalId)];
  }
  const members = (Array.isArray(resource.members) ? resource.members : [])
    .map(function (item) { return String((item && item.value) || '').trim(); })
    .filter(function (value) { return value !== ''; });
  if (members.length) {
    out.member = members;
  }
  // An objectClass so that the entry is a group by BOTH of ldap_server.js's
  // rules rather than only by where it sits — a client that moves it out of
  // ou=groups should not stop it being one, and `groupOfNames` is what `member`
  // belongs to (RFC 4519 section 3.5).
  if (!Object.keys(out).some(function (key) { return key.toLowerCase() === 'objectclass'; })) {
    out.objectClass = ['top', 'groupOfNames'];
  }

  log.debug("Leaving fromScimGroup(). " + Object.keys(out).length +
            " attribute(s), " + errors.length + " error(s).");
  return { attributes: out, errors: errors };
}

// ---------------------------------------------------------------------------
// Take the padding back off.
//
// An empty array or an empty object in a SCIM response is not wrong, but it is
// noise a client has to read past — and `"name": {}` in particular reads as "we
// know their name and it is nothing". The padding exists for scimmy's filter
// matcher (see toScimUser()) and this is where it stops being useful.
// ---------------------------------------------------------------------------
function prune(resource) {
  log.debug("Entering prune().");
  const out = {};
  Object.keys(resource).forEach(function (key) {
    const value = resource[key];
    if (Array.isArray(value)) {
      if (value.length) {
        out[key] = value;
      }
      return;
    }
    if (value && typeof value === 'object') {
      const inner = prune(value);
      if (Object.keys(inner).length) {
        out[key] = inner;
      }
      return;
    }
    if (value !== undefined && value !== null && value !== '') {
      out[key] = value;
    }
  });
  log.debug("Leaving prune().");
  return out;
}

module.exports = {
  USER_SCHEMA: USER_SCHEMA,
  GROUP_SCHEMA: GROUP_SCHEMA,
  ENTERPRISE_SCHEMA: ENTERPRISE_SCHEMA,
  USER_ATTRIBUTES: USER_ATTRIBUTES,
  GROUP_ATTRIBUTES: GROUP_ATTRIBUTES,
  OWN_NAMES: OWN_NAMES,
  toScimUser: toScimUser,
  fromScimUser: fromScimUser,
  toScimGroup: toScimGroup,
  fromScimGroup: fromScimGroup,
  prune: prune,
  valuesOf: valuesOf,
  firstOf: firstOf
};
