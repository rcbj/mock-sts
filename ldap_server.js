'use strict';
//
// File: ldap_server.js
//
// ---------------------------------------------------------------------------
// An embedded LDAPv3 directory server (RFC 4511), built on the node-ldapjs
// SUBMODULE beside this file rather than on a copy of it.
//
// NOTE ON THE DEPENDENCY, because it is unlike every other one here. `ldapjs`
// resolves to `./node-ldapjs`, a git submodule pinned to rcbj/node-ldapjs — see
// the `file:node-ldapjs` entry in package.json. Two consequences follow and both
// have already been paid for once:
//
//   * `git clone` of this repository does not bring it. `git submodule update
//     --init --recursive` does, and the parent project's launchers pass
//     --recursive for exactly this reason. An uninitialised submodule is an
//     EMPTY DIRECTORY, so the failure is `Cannot find module 'ldapjs'` from this
//     file — which names a package rather than a submodule.
//   * `npm install` on a `file:` dependency installs that package's
//     devDependencies too (tap, eslint and their trees — 200 packages and a
//     dozen advisories that have nothing to do with this service). Install with
//     `--omit=dev`; the Dockerfile does, and .npmrc makes a bare `npm install`
//     do the same.
//
// This module does NOT modify node-ldapjs. Everything below is handlers
// registered against its public server API, so the submodule stays a usable,
// unpatched copy of the library — which is the whole point of pinning it rather
// than vendoring a fork of its internals.
//
// ---------------------------------------------------------------------------
// WHAT THIS DIRECTORY IS FOR, AND THE ONE THING IT DELIBERATELY DOES NOT DO.
//
// It exists to be the far end of the parent project's LDAP debugger: something
// a client can bind to, search, and write to, whose every answer is written to
// this service's log. Like everything else here it authenticates nobody —
// **every bind succeeds**, whatever DN and whatever password, including an
// anonymous one.
//
// The single exception is the literal password `invalid`, which is refused with
// LDAP_INVALID_CREDENTIALS (49). That is not a softening of "authenticates
// nobody": it is this service's standing convention, the same string the
// password grant, WS-Trust and the WS-Federation sign-in screen already reject,
// and it exists so that a negative test has something to fail on. A directory
// that could not produce a 49 would make "the bind failed" untestable, and 49 is
// the result code an LDAP client's error handling is built around.
//
// It is SCHEMALESS on purpose. No objectClass is enforced, no attribute is
// checked against a syntax, and `must`/`may` are not consulted — so a debugger
// can add an entry with whatever attributes it wants and see them come back.
// A real directory would refuse most of that, and where the difference matters
// (a missing objectClass, an unknown attribute type) it is a difference a reader
// should be told about rather than one this mock should hide by inventing a
// schema of its own. GET /ldap says so on the page.
//
// Three protocol behaviours ARE enforced, because each is a real rule whose
// absence would teach a client something false:
//
//   * an add whose PARENT does not exist is LDAP_NO_SUCH_OBJECT (32). A
//     directory is a tree, and a client that has never seen this refusal will
//     write its first entry into a real directory and not understand the error.
//   * a delete of an entry that HAS CHILDREN is LDAP_NOT_ALLOWED_ON_NONLEAF
//     (66), for the same reason.
//   * a modify naming an attribute that is not there is
//     LDAP_NO_SUCH_ATTRIBUTE (16) for `delete` and `replace`-with-values-absent,
//     and succeeds for `add`.
//
// And one that is NOT enforced, stated here rather than discovered: deleting a
// user does not remove it from the groups that list it as a `member`. Referential
// integrity is a feature of some directories and not of the protocol; OpenLDAP
// needs an overlay for it and Active Directory does it in the DSA. Leaving the
// dangling member is the honest default and is what a `member`-based group search
// will then show.
//
// ---------------------------------------------------------------------------
// AN LDAP OBJECT FOR EVERY USER WHO AUTHENTICATES.
//
// `LDAP_AUTOCREATE_USERS` (default ON) makes this directory grow a
// `uid=<name>,ou=users,<base>` entry the first time a person authenticates
// ANYWHERE in this service — the OAuth2 login screen, WS-Trust, WS-Federation,
// a Kerberos AS-REQ, a WebAuthn assertion. That is one hook and not twelve,
// because `admin_stats.recordAuthentication()` is already the single funnel every
// one of those call sites goes through at the moment the credential is ACCEPTED.
//
// The hook is INVERTED for the reason helpers.js's setJwtRecorder is: this module
// requires admin_stats.js (it needs the identity normalisation), so admin_stats.js
// cannot require this one back without a cycle, and a cycle in node hands back a
// half-initialised module whose exports are undefined. So admin_stats.js offers a
// slot and this file installs itself in it at require time.
//
// Two identities are skipped, and both are deliberate:
//
//   * an LDAP bind. The identity presented to a bind is a DN — it names an
//     object in this very directory — so creating `uid=cn=admin\,dc=example...`
//     from one would be nonsense. A bind is recorded in the admin console like
//     any other authentication; it just does not seed an entry.
//   * an OAuth CLIENT (client_credentials, client authentication at the token
//     endpoint). A client is not a person, and `ou=users` is for people. The
//     admin console makes the same distinction with its `isClient` flag, which is
//     what this reads.
//
// And ONE identity is not a name at all: a verified TLS CLIENT CERTIFICATE. Its
// subject is already a DN, so it does not become `uid=<name>` — see
// certificatePlan() for where it goes instead and what that costs. It arrives
// through the same observer as everything else, with the certificate's own facts
// riding along beside the identity.
// ---------------------------------------------------------------------------

const ldap = require('ldapjs');
const app = require('./app');
const { log, xmlEscape } = require('./helpers');
const stats = require('./admin_stats');
// The admin console, for ONE reason: to hand it the reader below so that a user's
// page can show that user's directory entry. It is required here rather than the
// other way round because server.js requires ./admin BEFORE this module (rule 6),
// so admin.js must not require this one back — see the note above objectFor().
const admin = require('./admin');

// The port. 389 is the assigned one and this process is root in the container,
// so it binds it directly; a host run is not root, which is why the variable
// exists. Changing it means the parent project's api has to allow the new port
// in `ldapAllowedPorts` or its LDAP client will refuse to reach it — the same
// coupling KRB5_KDC_PORT has with krb5AllowedPorts, and for the same reason.
const LDAP_PORT = parseInt(process.env.LDAP_PORT, 10) || 389;

// The naming context this directory serves. Everything below it is ours;
// anything outside it is answered LDAP_NO_SUCH_OBJECT, which is what a real
// server does for a base DN it holds no data for.
const BASE_DN = process.env.LDAP_BASE_DN || 'dc=example,dc=com';

// Where auto-created people and hand-made groups are expected to live. They are
// derived rather than configured: two variables that could disagree with
// BASE_DN would produce entries in a tree nobody is searching.
const USERS_DN = 'ou=users,' + BASE_DN;
const GROUPS_DN = 'ou=groups,' + BASE_DN;

// Only an explicit "0" or "false" turns the auto-creation off, so a missing or
// misspelled variable leaves it ON — the safe direction here, because the
// feature is what makes the directory non-empty for somebody who has just
// signed in and gone looking for themselves.
const AUTOCREATE_USERS = !/^(0|false|no|off)$/i
  .test(String(process.env.LDAP_AUTOCREATE_USERS || '').trim());

// The password that is refused. See the header: this is the service's standing
// convention rather than an authentication policy.
const REFUSED_PASSWORD = 'invalid';

// A ceiling on how large this directory may grow. It is in memory and it grows
// on its own (every authentication can add an entry), so an unbounded one is a
// memory leak with a protocol in front of it. When it is reached, new entries
// are refused with LDAP_ADMIN_LIMIT_EXCEEDED rather than silently dropped.
const MAX_ENTRIES = parseInt(process.env.LDAP_MAX_ENTRIES, 10) || 2000;

// How many entries one search may return. RFC 4511 section 4.5.1.4 lets a
// client ask for fewer with sizeLimit and lets the server impose its own; a
// search of a directory this small will never reach it, but a client that has
// never seen LDAP_SIZE_LIMIT_EXCEEDED has never handled a paged result either.
const MAX_SEARCH_RESULTS = parseInt(process.env.LDAP_SIZE_LIMIT, 10) || 500;

// Whether the socket is up, and on which port. Declared HERE, beside the other
// module state, rather than beside listen() where it is written: the HTTP views
// read it, they are registered above listen(), and a `let` further down the file
// is in the temporal dead zone until module evaluation reaches it. Nothing calls
// those views during evaluation, so it works either way — but a reader should
// not have to establish that. `boundPort` starts at the configured value so the
// page is not wrong before listen() has run; it is replaced with the port that
// was actually bound, which differs when LDAP_PORT is 0.
let listening = false;
let listenError = '';
let boundPort = LDAP_PORT;

// ---------------------------------------------------------------------------
// The store.
//
// One Map keyed by the NORMALISED DN, holding the DN exactly as it was written
// and the attributes. Attribute names are stored in lower case because that is
// what arrives — @ldapjs/attribute lower-cases a type on the way in, so an entry
// added as `objectClass` comes back as `objectclass` — and because LDAP
// attribute descriptions are case-insensitive anyway. What is lost by that is
// only how the name LOOKED, which is why CANONICAL_NAMES exists: a debugger
// showing `givenname` where every schema document says `givenName` reads as a
// bug in the debugger.
// ---------------------------------------------------------------------------
const entries = new Map();

const CANONICAL_NAMES = {
  objectclass: 'objectClass', dc: 'dc', o: 'o', ou: 'ou', cn: 'cn', sn: 'sn',
  uid: 'uid', mail: 'mail', givenname: 'givenName', displayname: 'displayName',
  telephonenumber: 'telephoneNumber', title: 'title', description: 'description',
  member: 'member', memberof: 'memberOf', uniquemember: 'uniqueMember',
  userpassword: 'userPassword', employeenumber: 'employeeNumber',
  employeetype: 'employeeType', departmentnumber: 'departmentNumber',
  postaladdress: 'postalAddress', l: 'l', st: 'st', c: 'c', gidnumber: 'gidNumber',
  uidnumber: 'uidNumber', homedirectory: 'homeDirectory',
  createtimestamp: 'createTimestamp', modifytimestamp: 'modifyTimestamp',
  // The root DSE's own attributes (RFC 4512 section 5.1). They are here for the
  // same reason as the rest: a client showing `namingcontexts` where every
  // document says `namingContexts` looks like the client is broken.
  namingcontexts: 'namingContexts', supportedldapversion: 'supportedLDAPVersion',
  supportedcontrol: 'supportedControl', supportedextension: 'supportedExtension',
  supportedsaslmechanisms: 'supportedSASLMechanisms', vendorname: 'vendorName',
  vendorversion: 'vendorVersion', subschemasubentry: 'subschemaSubentry',
  entrydn: 'entryDN',
  // This service's OWN names, on the entries a TLS client certificate seeds.
  // They are listed here for the display, not to suggest they are standard:
  // there is no standard attribute type for "the DN inside the certificate",
  // and certificatePlan() says why the standard one that does exist —
  // `userCertificate`, which is binary — is not what these are.
  x509subject: 'x509subject', x509issuer: 'x509issuer',
  x509serialnumber: 'x509serialNumber', x509notbefore: 'x509notBefore',
  x509notafter: 'x509notAfter', x509fingerprint256: 'x509fingerprint256'
};

// A DN as a comparison key. Case-folded, and the whitespace around each comma
// removed, because `cn=alice, ou=users` and `CN=Alice,OU=Users` name the same
// object and a Map keyed on the raw string would hold two of it. This is a
// simplification of RFC 4518 string preparation and says so: it does not
// normalise escaping or attribute-value syntax, so a DN written with `\,` in a
// value is compared byte-wise. That is enough for a directory whose DNs this
// service and its own debugger write.
function normalizeDn(value) {
  const text = String(value == null ? '' : value).trim();
  return text.split(',').map(function (part) {
    return part.trim().toLowerCase();
  }).join(',');
}

// The parent of a DN, or '' for a naming context with nothing above it.
function parentDn(value) {
  const parts = String(value == null ? '' : value).split(',');
  if (parts.length <= 1) return '';
  return parts.slice(1).join(',').trim();
}

// Is `dn` at or below `base`? Used by every scope decision and by the check that
// refuses to operate outside this server's naming context.
function isUnder(dn, base) {
  const a = normalizeDn(dn);
  const b = normalizeDn(base);
  if (!b) return true;
  if (a === b) return true;
  return a.endsWith(',' + b);
}

// How many commas separate a DN from a base — 0 for the base itself, 1 for its
// immediate children. This is what tells `one` from `sub`.
function depthUnder(dn, base) {
  const a = normalizeDn(dn);
  const b = normalizeDn(base);
  if (a === b) return 0;
  const rest = a.slice(0, a.length - b.length - 1);
  return rest.split(',').length;
}

function canonicalName(lower) {
  return CANONICAL_NAMES[lower] || lower;
}

// The scope, as one of 'base' | 'one' | 'sub'.
//
// Read from the NUMBER on the wire (RFC 4511 section 4.5.1.2: baseObject 0,
// singleLevel 1, wholeSubtree 2) and not from ldapjs's `scopeName`, which spells
// the middle two 'single' and 'subtree'. That difference cost a search: a
// handler comparing scopeName against 'one' and 'sub' matched neither, fell
// through to its default, and answered every one-level search as a subtree — so
// the results were a superset, every assertion about them still passed, and the
// only visible symptom was one extra entry. A wrong scope is invisible in
// exactly the direction that makes it hardest to notice.
function scopeOf(req) {
  const value = typeof req.scope === 'number' ? req.scope : 2;
  if (value === 0) return 'base';
  if (value === 1) return 'one';
  return 'sub';
}

// Attribute values are always an array of strings on the way in, whatever the
// caller handed us. LDAP has no scalars, and a store that sometimes held one is
// a store every reader has to test the type of.
function valuesOf(value) {
  if (value === undefined || value === null) return [];
  if (Array.isArray(value)) return value.map(function (v) { return String(v); });
  return [String(value)];
}

// A generalized time, which is what createTimestamp and modifyTimestamp are:
// YYYYMMDDHHMMSSZ. Written out rather than taken from a library because the one
// place it differs from an ISO 8601 string is the punctuation, and a debugger
// showing an ISO string where a directory shows a generalized time is showing
// the wrong thing.
function generalizedTime(when) {
  const d = when instanceof Date ? when : new Date();
  const pad = function (n, width) {
    return String(n).padStart(width || 2, '0');
  };
  return pad(d.getUTCFullYear(), 4) + pad(d.getUTCMonth() + 1) +
    pad(d.getUTCDate()) + pad(d.getUTCHours()) + pad(d.getUTCMinutes()) +
    pad(d.getUTCSeconds()) + 'Z';
}

// ---------------------------------------------------------------------------
// Reading and writing entries.
// ---------------------------------------------------------------------------

function getEntry(dn) {
  return entries.get(normalizeDn(dn)) || null;
}

function hasChildren(dn) {
  log.debug('Entering hasChildren(). dn=' + dn);
  const key = normalizeDn(dn);
  for (const other of entries.keys()) {
    if (other !== key && other.endsWith(',' + key)) {
      log.debug('Leaving hasChildren(). It has at least one child.');
      return true;
    }
  }
  log.debug('Leaving hasChildren(). It is a leaf.');
  return false;
}

// Put an entry in the store. `attributes` is a plain object whose values may be
// a string or an array; the operational attributes are added here so that every
// entry has them however it was created.
function putEntry(dn, attributes, options) {
  log.debug('Entering putEntry(). dn=' + dn);
  const opts = options || {};
  const now = generalizedTime();
  const stored = { dn: String(dn), attributes: {}, createdAt: now, modifiedAt: now };
  Object.keys(attributes || {}).forEach(function (name) {
    stored.attributes[String(name).toLowerCase()] = valuesOf(attributes[name]);
  });
  stored.attributes.createtimestamp = [now];
  stored.attributes.modifytimestamp = [now];
  if (opts.origin) stored.origin = String(opts.origin);
  entries.set(normalizeDn(dn), stored);
  log.debug('Leaving putEntry(). The directory now holds ' + entries.size +
            ' entry/entries.');
  return stored;
}

// The entry as a filter-matchable object: {attributename: [values]}. The DN is
// included as `entrydn`, which is not standard LDAP but is what lets a filter
// like `(entryDN=cn=alice,...)` work; a real directory offers `entryDN` as an
// operational attribute (RFC 5020) so the name is at least borrowed rather than
// invented.
function matchable(stored) {
  const out = {};
  Object.keys(stored.attributes).forEach(function (name) {
    out[name] = stored.attributes[name].slice(0);
  });
  out.entrydn = [stored.dn];
  return out;
}

// The entry as ldapjs wants it on the wire, honouring the requested attribute
// list. An empty list means "all user attributes", which per RFC 4511 section
// 4.5.1.8 does NOT include the operational ones — so createTimestamp and
// modifyTimestamp come back only when they were asked for by name. That
// distinction is one of the commonest surprises in LDAP and is worth
// reproducing rather than smoothing over.
const OPERATIONAL = ['createtimestamp', 'modifytimestamp', 'entrydn'];

// ---------------------------------------------------------------------------
// A BUG IN ldapjs 3.0.7 THAT THIS FILE ROUTES AROUND, recorded here because the
// workaround is one line and looks like a stylistic choice.
//
// `SearchResponse.prototype.send(entry)` runs a SECOND attribute filter of its
// own after the handler has already chosen what to send. That filter compares
// the entry's attribute name — LOWER-CASED, as `_a` — against the requested
// list held EXACTLY AS THE CLIENT SENT IT:
//
//     } else if (self.attributes.length &&
//                self.attributes.indexOf(_a) === -1) { delete ... }
//
// So a client asking for `telephoneNumber` gets back everything it asked for
// EXCEPT `telephoneNumber`, because `telephonenumber` is not in `['title',
// 'telephoneNumber', 'cn']`. Every attribute whose conventional spelling has a
// capital in it — telephoneNumber, givenName, displayName, objectClass,
// userPassword — is silently dropped from a SELECTIVE search and from nothing
// else, which is why a search asking for everything looks perfect and why this
// took a while to find. LDAP attribute descriptions are case-insensitive
// (RFC 4512 section 2.5), so it is a defect rather than a convention.
//
// `send()`'s `nofiltering` argument does NOT turn it off, which is the trap
// inside the trap: that flag guards the `_`-prefix and `notAttributes` branches
// above this one, and the requested-attributes branch has no guard at all. Its
// documentation says as much ("skip filtering notAttributes and '_'
// attributes") and reads like it covers everything.
//
// What does turn it off is passing a SearchResultEntry INSTANCE rather than a
// plain `{dn, attributes}` object: `send()` takes an early branch for one and
// writes it untouched. So this function builds the message itself. That is
// correct here rather than merely expedient — the selection has already been
// made below, case-insensitively and with RFC 4511 section 4.5.1.8's rule about
// operational attributes, so a second pass can only remove things it should
// not.
//
// The bug is deliberately NOT fixed in the submodule. node-ldapjs is pinned and
// used UNMODIFIED so that it stays a usable copy of the library rather than a
// fork nobody else can consume, and so that the api and this service are
// running the same code as anybody else's ldapjs. Patching its internals would
// make every future update a merge, and would hide a defect that a real client
// talking to a real ldapjs server still has. If it is ever fixed upstream this
// code is unaffected: it does not depend on the filter being absent, only on
// not being filtered twice.
// ---------------------------------------------------------------------------

function toSearchEntry(stored, requested, messageId) {
  log.debug('Entering toSearchEntry(). dn=' + stored.dn);
  const wanted = (requested || []).map(function (a) {
    return String(a).toLowerCase();
  });
  const all = wanted.length === 0 || wanted.indexOf('*') !== -1;
  const attributes = {};
  Object.keys(stored.attributes).forEach(function (name) {
    const isOperational = OPERATIONAL.indexOf(name) !== -1;
    const askedFor = wanted.indexOf(name) !== -1;
    if (askedFor || (all && !isOperational)) {
      attributes[canonicalName(name)] = stored.attributes[name].slice(0);
    }
  });
  if (wanted.indexOf('entrydn') !== -1) attributes.entryDN = [stored.dn];
  log.debug('Leaving toSearchEntry(). ' + Object.keys(attributes).length +
            ' attribute(s) will be sent.');
  // A MESSAGE INSTANCE, not a {dn, attributes} object. See the note above:
  // handing send() a plain object invites its own case-sensitive second filter,
  // and handing it an instance does not.
  //
  // THE messageId HAS TO BE THE RESPONSE'S, and passing it is not optional.
  // LdapMessage defaults the field to 1, so send()'s `if (!entry.messageId)`
  // never fires — 1 is truthy — and the very next line throws "SearchEntry
  // messageId mismatch" for every search after the first on a connection. The
  // symptom is an uncaught exception in the server's log and a search that
  // returns zero entries and then ends successfully, which reads as an empty
  // directory.
  return new ldap.SearchEntry({
    messageId: messageId,
    objectName: stored.dn,
    attributes: Object.keys(attributes).map(function (name) {
      return new ldap.Attribute({ type: name, values: attributes[name] });
    })
  });
}

// ---------------------------------------------------------------------------
// The seeded directory.
//
// It is seeded rather than empty because an LDAP debugger opened against an
// empty directory shows nothing and teaches nothing: the first search returns no
// entries and the reader cannot tell that from a filter they got wrong. What is
// here is the smallest tree that makes every operation the debugger offers
// demonstrable — two containers, three people, two groups, and one account that
// looks like the one a client would bind as.
// ---------------------------------------------------------------------------
function seed() {
  log.debug('Entering seed().');
  const dcValue = BASE_DN.split(',')[0].split('=')[1] || 'example';
  putEntry(BASE_DN, {
    objectClass: ['top', 'domain', 'dcObject'],
    dc: dcValue,
    description: 'The mock STS directory. Every bind succeeds; nothing here ' +
      'is a real account.'
  }, { origin: 'seed' });
  putEntry(USERS_DN, {
    objectClass: ['top', 'organizationalUnit'],
    ou: 'users',
    description: 'People. An entry appears here for anyone who authenticates ' +
      'to this service through any protocol.'
  }, { origin: 'seed' });
  putEntry(GROUPS_DN, {
    objectClass: ['top', 'organizationalUnit'],
    ou: 'groups',
    description: 'Groups, as groupOfNames — membership is the multi-valued ' +
      '`member` attribute holding the DN of each member.'
  }, { origin: 'seed' });
  putEntry('cn=admin,' + BASE_DN, {
    objectClass: ['top', 'person', 'organizationalRole'],
    cn: 'admin',
    sn: 'Administrator',
    description: 'A bind account. So is every other DN in the universe: this ' +
      'server accepts any bind except the password "invalid".'
  }, { origin: 'seed' });
  [
    { uid: 'alice', cn: 'Alice Anderson', sn: 'Anderson', given: 'Alice',
      title: 'Principal Engineer' },
    { uid: 'bob', cn: 'Bob Brown', sn: 'Brown', given: 'Bob',
      title: 'Support Analyst' },
    { uid: 'carol', cn: 'Carol Carter', sn: 'Carter', given: 'Carol',
      title: 'Directory Administrator' }
  ].forEach(function (person) {
    putEntry('uid=' + person.uid + ',' + USERS_DN, {
      objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
      uid: person.uid,
      cn: person.cn,
      sn: person.sn,
      givenName: person.given,
      displayName: person.cn,
      title: person.title,
      mail: person.uid + '@sts-mock.example',
      description: 'Seeded, not authenticated.'
    }, { origin: 'seed' });
  });
  putEntry('cn=developers,' + GROUPS_DN, {
    objectClass: ['top', 'groupOfNames'],
    cn: 'developers',
    description: 'A groupOfNames. Membership is the `member` attribute.',
    member: ['uid=alice,' + USERS_DN, 'uid=bob,' + USERS_DN]
  }, { origin: 'seed' });
  putEntry('cn=directory-admins,' + GROUPS_DN, {
    objectClass: ['top', 'groupOfNames'],
    cn: 'directory-admins',
    description: 'A second group, so a search for groups returns more than one.',
    member: ['uid=carol,' + USERS_DN]
  }, { origin: 'seed' });
  log.info('ldap: seeded ' + entries.size + ' entries under ' + BASE_DN + '.');
  log.debug('Leaving seed().');
}

seed();

// An RFC 4514 DN split into its RDNs, leaf first. The split is on commas that
// are NOT escaped, because a value may legitimately contain one — `O=Example\,
// Ltd` is one RDN and not two — and splitting there would produce components
// that name nothing. Like normalizeDn() this honours escaping and does not
// parse attribute-value syntax; that is enough for the DNs this service and the
// certificates it is shown are written with.
function splitRdns(dn) {
  return String(dn == null ? '' : dn).split(/(?<!\\),/)
    .map(function (part) { return part.trim(); })
    .filter(function (part) { return part.length > 0; });
}

// One RDN as {attribute, value} pairs. A multi-valued RDN (`cn=alice+uid=a1`)
// is several, and they are all returned, because every one of them has to end
// up IN the entry: an entry whose RDN names an attribute it does not carry is
// malformed in any real directory, and this one being schemaless is not a
// reason to write one. The type is split at the FIRST '=' because an attribute
// type cannot contain one.
function rdnPairs(rdn) {
  return String(rdn == null ? '' : rdn).split('+').map(function (part) {
    const at = part.indexOf('=');
    if (at < 1) {
      return null;
    }
    return { attribute: part.slice(0, at).trim().toLowerCase(),
             value: part.slice(at + 1).trim() };
  }).filter(Boolean);
}

// RFC 4514 section 2.4 escaping, and its inverse. A DN is a STRING made of
// values, so the two directions have to be kept apart: `O=Example\, Ltd` is one
// RDN whose value is `Example, Ltd`, and storing the backslash as part of the
// value — or writing the comma into the DN without one — each produce something
// that looks almost right and names the wrong object.
//
// tls_server.js has a sibling of the escape half. They are not shared on
// purpose: that one renders node's certificate object into a DN and belongs with
// the code that reads certificates, and this one is used wherever this directory
// builds a DN of its own. Sharing would mean one of the two modules requiring
// the other for a string function.
function escapeDnValue(value) {
  const text = String(value == null ? '' : value);
  let out = text.replace(/([\\,+"<>;=])/g, '\\$1');
  if (out.indexOf('#') === 0) {
    out = '\\' + out;
  }
  return out.replace(/^ /, '\\ ').replace(/ $/, '\\ ');
}

function unescapeDnValue(value) {
  return String(value == null ? '' : value).replace(/\\(.)/g, '$1');
}

// Append the values an attribute does not already have, and say whether
// anything changed. The caller uses the answer to decide whether
// modifyTimestamp moves: a timestamp that advanced on a reconnection that wrote
// nothing would make every handshake look like a write.
function addValues(stored, name, values) {
  const key = String(name).toLowerCase();
  const have = stored.attributes[key] || [];
  const added = valuesOf(values).filter(function (value) {
    return value !== '' && have.indexOf(value) === -1;
  });
  if (!added.length) {
    return false;
  }
  stored.attributes[key] = have.concat(added);
  return true;
}

// ---------------------------------------------------------------------------
// WHERE A CLIENT CERTIFICATE'S ENTRY GOES, which is the one placement decision
// in this module with no obviously right answer.
//
// A certificate subject IS a DN — X.509 and LDAP share the model — so unlike
// every other identity here it does not need a name turned into one. What it
// needs is a PLACE, and the honest observation is that it usually names an
// object in somebody ELSE's directory: `CN=alice,O=Example Corp,C=US` is not
// under `dc=example,dc=com` and never was.
//
// Two rules, in this order:
//
//   * if the subject already lies under this directory's base DN AND its parent
//     exists, the entry is created AT it, unchanged. It names an object here, so
//     putting it anywhere else would be inventing a second one.
//   * otherwise the subject's CN — or its leaf RDN where it has no CN — names
//     an entry under ou=users: `CN=alice,O=Example Corp,C=US` becomes
//     `cn=alice,ou=users,<base>`, and every other RDN of the subject goes on
//     that entry as an attribute rather than being dropped.
//     Grafting the whole subject under ou=users instead would need
//     `o=example corp,c=us,ou=users,<base>` to exist as entries, and a tree with
//     holes in it is worse than a shortened DN — this directory enforces "an add
//     needs its parent" and would be breaking its own rule to seed one.
//
// Nothing is lost either way: the full subject is written into the entry as
// `x509subject`. What the second rule COSTS is a collapse — two certificates
// whose leaf RDNs match, two `CN=alice` from different CAs, land on one entry.
// Both subjects are listed there so the collapse is visible rather than silent,
// and the admin console still files them as two identities because it keys on
// the whole DN.
//
// The x509* attributes are NOT standard schema. There is no standard attribute
// type for "the DN in the certificate" — RFC 4523 defines `userCertificate`,
// which holds the certificate itself and is a BINARY attribute transferred as
// `userCertificate;binary`. This store holds strings, so writing base64 into
// that name would put a value on the wire that no client can parse as a
// certificate and would read as a bug in the directory rather than as a choice
// here. So the facts go into names that are obviously this service's own, and
// the certificate itself stays where it is already published in full: the TLS
// listener's own report.
// ---------------------------------------------------------------------------
function certificatePlan(info) {
  log.debug('Entering certificatePlan().');
  const certificate = info.certificate || {};
  const subject = String(certificate.subject || info.key || '').trim();
  const rdns = splitRdns(subject);
  const leaf = rdns.length ? rdns[0] : '';
  const pairs = rdnPairs(leaf);
  const common = String(certificate.commonName || '').trim();

  // What the entry is NAMED, when it is not created at the subject itself. The
  // CN where the certificate has one, and the leaf RDN otherwise — not simply
  // the leaf, and the reason is the commonest shape a CA produces: openssl puts
  // emailAddress LAST in the subject, so the leaf RDN of
  // `C=US,O=Example,CN=alice,emailAddress=alice@example.com` is the address, and
  // `emailAddress=alice@example.com,ou=users` is not how a directory names a
  // person. Where there is no CN the leaf is the best name there is and is used
  // as it stands. Either way the value is ESCAPED in the DN and stored
  // UNESCAPED as the attribute, which is the distinction escapeDnValue() exists
  // for.
  const naming = common
    ? { attribute: 'cn', rdnValue: escapeDnValue(common), value: common }
    : (pairs.length
        ? { attribute: pairs[0].attribute, rdnValue: pairs[0].value,
            value: unescapeDnValue(pairs[0].value) }
        : null);

  let dn;
  if (subject && isUnder(subject, BASE_DN) && getEntry(parentDn(subject))) {
    dn = subject;
  } else if (naming) {
    dn = naming.attribute + '=' + naming.rdnValue + ',' + USERS_DN;
  } else {
    // A subject with no parsable RDN at all. It is still an identity that
    // authenticated, so it gets an entry rather than being dropped; `uid=` is
    // the shape every other auto-created entry here uses.
    dn = 'uid=' + escapeDnValue(subject || 'unknown') + ',' + USERS_DN;
  }

  const attributes = {
    objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
    sn: 'Mock',
    displayName: (common || subject || 'unknown') + ' (client certificate)'
  };
  // Every RDN of the subject becomes an attribute — `O`, `OU`, `C` and the rest
  // — because they describe this identity and a directory entry is where a
  // reader will look for them. Unescaped: the escaping belongs to the DN.
  pairs.forEach(function (pair) {
    attributes[pair.attribute] = [unescapeDnValue(pair.value)];
  });
  if (naming) {
    attributes[naming.attribute] = [naming.value];
  }
  // `cn` whatever the RDN was, because it is the attribute every reader and
  // every naive filter reaches for first.
  if (!attributes.cn) {
    attributes.cn = [common || (naming ? naming.value : subject)];
  }
  // No mail is invented here, unlike the entry a typed username seeds. The
  // certificate is the source of truth for this identity, so an address it does
  // not carry is one this service would be making up.
  if (certificate.email) {
    attributes.mail = [String(certificate.email)];
  }
  const facts = {
    x509subject: subject,
    x509issuer: certificate.issuer || '',
    x509serialNumber: certificate.serialNumber || '',
    x509notBefore: certificate.validFrom || '',
    x509notAfter: certificate.validTo || '',
    x509fingerprint256: certificate.fingerprint256 || ''
  };
  Object.keys(facts).forEach(function (name) {
    if (facts[name]) {
      attributes[name] = [String(facts[name])];
    }
  });
  log.debug('Leaving certificatePlan(). dn=' + dn);
  // `merge` is what a SECOND certificate for an entry that already exists adds
  // to it — the facts and not the names, since a renewed or reissued
  // certificate is a new serial and a new validity for the same person and
  // appending them is what makes both visible.
  return { dn: dn, attributes: attributes, merge: facts };
}

// ---------------------------------------------------------------------------
// An entry for whoever authenticated, anywhere in this service.
// ---------------------------------------------------------------------------
function autoCreateUser(detail) {
  log.debug('Entering autoCreateUser(). key=' + (detail && detail.key));
  if (!AUTOCREATE_USERS) {
    log.debug('Leaving autoCreateUser(). LDAP_AUTOCREATE_USERS is off.');
    return null;
  }
  const info = detail || {};
  const name = String(info.key || '').trim();
  if (!name) {
    log.debug('Leaving autoCreateUser(). There was no identity to create.');
    return null;
  }
  // See the header: a bind presents a DN, which already names an object here,
  // and a client is not a person.
  if (String(info.protocol || '').toLowerCase() === 'ldap') {
    log.debug('Leaving autoCreateUser(). An LDAP bind names a DN, not a user.');
    return null;
  }
  if (info.isClient) {
    log.debug('Leaving autoCreateUser(). That identity is a client, not a person.');
    return null;
  }
  // A client CERTIFICATE identity is a DN and is placed accordingly; everything
  // else is a name and becomes `uid=<name>,ou=users`. See certificatePlan().
  const plan = info.certificate
    ? certificatePlan(info)
    : {
        dn: 'uid=' + name + ',' + USERS_DN,
        attributes: {
          objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
          uid: name,
          cn: name,
          sn: 'Mock',
          givenName: name,
          displayName: name + ' (mock)',
          mail: name + '@sts-mock.example'
        },
        merge: {}
      };
  const dn = plan.dn;
  const existing = getEntry(dn);
  const note = 'authenticated through ' + String(info.protocol || 'an ' +
    'unstated protocol');
  if (existing) {
    // Already here. Record the protocol if it is one this entry has not seen —
    // which is what makes the entry say something a second sign-in did not
    // already say, without growing without bound — and, for a certificate, any
    // fact this one carries that the last one did not: a renewal is a new serial
    // and a new validity for the same person.
    let changed = addValues(existing, 'description', [note]);
    Object.keys(plan.merge).forEach(function (attribute) {
      if (plan.merge[attribute] && addValues(existing, attribute, [String(plan.merge[attribute])])) {
        changed = true;
      }
    });
    if (changed) {
      existing.attributes.modifytimestamp = [generalizedTime()];
      log.debug('Leaving autoCreateUser(). The entry existed and now records ' +
                'something it did not before.');
      return existing;
    }
    log.debug('Leaving autoCreateUser(). The entry already existed.');
    return existing;
  }
  if (entries.size >= MAX_ENTRIES) {
    // Reported rather than thrown: the authentication itself succeeded and must
    // not be failed by a directory that is full.
    log.warn('ldap: not creating ' + dn + '; the directory holds its maximum ' +
             'of ' + MAX_ENTRIES + ' entries.');
    log.debug('Leaving autoCreateUser(). The directory is full.');
    return null;
  }
  const created = putEntry(dn, Object.assign({}, plan.attributes,
                                             { description: [note] }),
                           { origin: 'authentication' });
  log.info('ldap: created ' + dn + ' because ' + name + ' ' + note + '.');
  log.debug('Leaving autoCreateUser(). The entry was created.');
  return created;
}

// ---------------------------------------------------------------------------
// ONE USER'S ENTRY, FOR THE ADMIN CONSOLE.
//
// /admin/users?user=<name> is the page that answers "what does this service hold
// about this person", and the directory entry autoCreateUser() seeded above is
// part of that answer — so the console shows it there rather than making a reader
// find the same object again on /ldap/directory.
//
// The direction of the dependency is inverted here for the same reason the
// observer above is, and it is worth stating because it is the OPPOSITE way round
// from what the call graph looks like. admin.js renders this; it would naturally
// require this module and read `entries`. It must not: server.js requires ./admin
// before ./ldap_server (rule 6 — this module needs admin_stats' identity
// normalisation), and a require from admin.js would drag this module's routes in
// ahead of the console's, which reorders the express router that /sts-metadata
// reads. So admin.js offers a slot and this module fills it, exactly as
// admin_stats.js does for the observer.
//
// It is given the IDENTITY KEY the console files a person under — the local name,
// with `urn:sts-mock:user:` and any realm already stripped — which is the same
// string autoCreateUser() built the DN from, so the two cannot drift.
//
// What comes back is deliberately more than the entry: the DN is reported whether
// or not anything is there, because "no entry at uid=bob,ou=users" and "the
// directory is not running" and "auto-creation is off" are three different answers
// and a null would be all three at once. The console phrases which one it is; this
// function states the facts it needs to do that.
// ---------------------------------------------------------------------------
function objectFor(name) {
  log.debug('Entering objectFor(). name=' + name);
  const key = String(name == null ? '' : name).trim();
  const dn = 'uid=' + key + ',' + USERS_DN;
  const stored = key ? getEntry(dn) : null;

  // Every OTHER entry in the tree whose uid names this same person. A client can
  // add `cn=alice,ou=people` through the protocol, and a page that reported only
  // the auto-created DN would say "no entry" while the directory held one. Only
  // the DNs are listed — the dump below is of the entry the console is about.
  const alsoNamed = [];
  if (key) {
    entries.forEach(function (entry) {
      if (normalizeDn(entry.dn) === normalizeDn(dn)) {
        return;
      }
      const uids = entry.attributes.uid || [];
      if (uids.indexOf(key) >= 0) {
        alsoNamed.push(entry.dn);
      }
    });
  }

  const out = {
    dn: dn,
    found: !!stored,
    entry: null,
    alsoNamed: alsoNamed.sort(),
    baseDn: BASE_DN,
    usersDn: USERS_DN,
    port: boundPort,
    listening: listening,
    listenError: listenError,
    autoCreateUsers: AUTOCREATE_USERS,
    entryCount: entries.size,
    maxEntries: MAX_ENTRIES,
    // Not `entryCount >= maxEntries` computed by the caller: the cap is this
    // module's and a second copy of the comparison is a second thing to keep
    // right.
    full: entries.size >= MAX_ENTRIES
  };
  if (stored) {
    // Canonically spelled, and OPERATIONAL ATTRIBUTES INCLUDED. A search would
    // return createTimestamp and modifyTimestamp only when they were asked for
    // by name (RFC 4511 section 4.5.1.8, and toSearchEntry() honours it) — but
    // this is not a search, it is this service showing its own store, and a dump
    // that silently dropped two of the entry's attributes would be the one thing
    // a dump must not do.
    const attributes = {};
    Object.keys(stored.attributes).sort().forEach(function (attribute) {
      attributes[canonicalName(attribute)] = stored.attributes[attribute].slice(0);
    });
    out.entry = {
      dn: stored.dn,
      origin: stored.origin || 'unstated',
      createdAt: stored.createdAt,
      modifiedAt: stored.modifiedAt,
      operational: OPERATIONAL.map(canonicalName),
      attributes: attributes
    };
  }
  log.debug('Leaving objectFor(). ' + (stored ? 'The entry is there.' : 'There ' +
            'is no entry at ' + dn + '.') + ' ' + alsoNamed.length +
            ' other entry/entries name it.');
  return out;
}

// The inverted hook. See the header for why the direction is this way round.
stats.setUserObserver(autoCreateUser);

// The second inverted hook, and the one that reads rather than writes. See
// objectFor() above for why the console does not simply require this module.
// Guarded so that a copy of admin.js WITHOUT the slot — an older one, or the
// parent project's — costs a warning rather than `admin.setDirectoryReader is not
// a function` thrown at require time, which would take the whole service down over
// one section of one page. A directory whose entries nobody renders is still a
// working directory.
if (typeof admin.setDirectoryReader === 'function') {
  admin.setDirectoryReader(objectFor);
} else {
  log.warn('ldap: the admin console offers no setDirectoryReader(), so a user ' +
           'page will not show that user\'s directory entry. The directory ' +
           'itself is unaffected.');
}

// ---------------------------------------------------------------------------
// The server, and its handlers.
//
// Every handler is registered against BASE_DN and against '' — the second is
// the ROOT DSE and anything outside the naming context. A client that binds
// before it knows the base DN reads the root DSE first, and a server that had no
// handler for it answers LDAP_UNAVAILABLE, which reads as the server being down.
// ---------------------------------------------------------------------------
const server = ldap.createServer({ log: log });

server.on('error', function (err) {
  // Reported rather than thrown: the rest of this service is still useful, and
  // a listener that dies silently surfaces later as a directory that never
  // answers.
  log.error('ldap: the server reported an error: ' + err.message);
});

// --- bind ------------------------------------------------------------------
server.bind('', function (req, res, next) {
  log.debug('Entering the LDAP bind handler.');
  const dn = req.dn ? req.dn.toString() : '';
  const credentials = req.credentials === undefined ? '' : String(req.credentials);
  log.info('ldap: BIND dn="' + dn + '" (' +
           (dn ? 'named' : 'anonymous') + '), ' + credentials.length +
           ' character password.');
  if (credentials === REFUSED_PASSWORD) {
    // The one refusal. See the header: it is the service's convention, not a
    // policy, and it is what makes result code 49 reachable.
    log.info('ldap: refusing the bind; the password is the literal string "' +
             REFUSED_PASSWORD + '", which this service rejects in every ' +
             'protocol so that a negative test has something to fail on.');
    log.debug('Leaving the LDAP bind handler. LDAP_INVALID_CREDENTIALS.');
    return next(new ldap.InvalidCredentialsError());
  }
  stats.recordAuthentication({
    presented: dn || '(anonymous)',
    protocol: 'ldap',
    method: dn ? 'simple bind' : 'anonymous simple bind',
    note: 'no password was checked'
  });
  res.end();
  log.debug('Leaving the LDAP bind handler. The bind succeeded.');
  return next();
});

// --- add -------------------------------------------------------------------
server.add('', function (req, res, next) {
  log.debug('Entering the LDAP add handler.');
  const dn = req.dn.toString();
  log.info('ldap: ADD ' + dn);
  if (!isUnder(dn, BASE_DN)) {
    log.debug('Leaving the LDAP add handler. Outside the naming context.');
    return next(new ldap.NoSuchObjectError(BASE_DN));
  }
  if (getEntry(dn)) {
    log.debug('Leaving the LDAP add handler. It is already there.');
    return next(new ldap.EntryAlreadyExistsError(dn));
  }
  const parent = parentDn(dn);
  if (parent && !getEntry(parent)) {
    // A directory is a tree. See the header: this refusal is one of the three
    // real rules this schemaless mock still enforces.
    log.info('ldap: refusing to add ' + dn + '; its parent ' + parent +
             ' does not exist.');
    log.debug('Leaving the LDAP add handler. The parent is missing.');
    return next(new ldap.NoSuchObjectError(parent));
  }
  if (entries.size >= MAX_ENTRIES) {
    log.debug('Leaving the LDAP add handler. The directory is full.');
    return next(new ldap.AdminLimitExceededError(
      'this directory holds its maximum of ' + MAX_ENTRIES + ' entries'));
  }
  const attributes = {};
  req.attributes.forEach(function (attr) {
    attributes[attr.type] = attr.values.slice(0);
  });
  putEntry(dn, attributes, { origin: 'ldap add' });
  log.info('ldap: added ' + dn + ' with ' + Object.keys(attributes).length +
           ' attribute(s).');
  res.end();
  log.debug('Leaving the LDAP add handler. The entry was added.');
  return next();
});

// --- delete ----------------------------------------------------------------
server.del('', function (req, res, next) {
  log.debug('Entering the LDAP delete handler.');
  const dn = req.dn.toString();
  log.info('ldap: DELETE ' + dn);
  const stored = getEntry(dn);
  if (!stored) {
    log.debug('Leaving the LDAP delete handler. There is no such entry.');
    return next(new ldap.NoSuchObjectError(dn));
  }
  if (hasChildren(dn)) {
    log.debug('Leaving the LDAP delete handler. It is not a leaf.');
    return next(new ldap.NotAllowedOnNonLeafError(dn));
  }
  entries.delete(normalizeDn(dn));
  // Note what is NOT done here: the DN is left in any group that lists it as a
  // member. See the header — referential integrity is a directory feature and
  // not a protocol rule, and hiding the dangling member would hide the thing a
  // reader should see.
  log.info('ldap: deleted ' + dn + '. Any group listing it as a member still ' +
           'does; this server does not do referential integrity.');
  res.end();
  log.debug('Leaving the LDAP delete handler. The entry was deleted.');
  return next();
});

// --- modify ----------------------------------------------------------------
server.modify('', function (req, res, next) {
  log.debug('Entering the LDAP modify handler.');
  const dn = req.dn.toString();
  log.info('ldap: MODIFY ' + dn + ' with ' + req.changes.length + ' change(s).');
  const stored = getEntry(dn);
  if (!stored) {
    log.debug('Leaving the LDAP modify handler. There is no such entry.');
    return next(new ldap.NoSuchObjectError(dn));
  }
  if (!req.changes.length) {
    log.debug('Leaving the LDAP modify handler. It asked for no changes.');
    return next(new ldap.ProtocolError('a modify must carry at least one change'));
  }
  // RFC 4511 section 4.6: the changes are applied in order and the whole
  // operation is atomic — either all of them or none. So they are applied to a
  // COPY, which replaces the stored attributes only once every change has been
  // accepted. Applying them in place and rolling back on failure is the same
  // thing written so that a bug leaves half a change behind.
  const working = {};
  Object.keys(stored.attributes).forEach(function (name) {
    working[name] = stored.attributes[name].slice(0);
  });
  for (let i = 0; i < req.changes.length; i++) {
    const change = req.changes[i];
    const operation = String(change.operation || '').toLowerCase();
    const type = String(change.modification.type || '').toLowerCase();
    const values = change.modification.values.map(function (v) {
      return String(v);
    });
    log.debug('ldap: change ' + (i + 1) + ' is ' + operation + ' ' + type +
              ' with ' + values.length + ' value(s).');
    if (operation === 'add') {
      const before = working[type] || [];
      const added = values.filter(function (v) {
        return before.indexOf(v) === -1;
      });
      working[type] = before.concat(added);
    } else if (operation === 'replace') {
      if (values.length === 0) {
        delete working[type];
      } else {
        working[type] = values;
      }
    } else if (operation === 'delete') {
      if (!working[type]) {
        log.debug('Leaving the LDAP modify handler. ' + type + ' is not there.');
        return next(new ldap.NoSuchAttributeError(type));
      }
      if (values.length === 0) {
        delete working[type];
      } else {
        working[type] = working[type].filter(function (v) {
          return values.indexOf(v) === -1;
        });
        // An attribute with no values does not exist. RFC 4511 section 4.1.7:
        // an attribute always has at least one value, so deleting the last one
        // deletes the attribute — which is why a subsequent delete of the same
        // attribute is a 16 rather than a no-op.
        if (working[type].length === 0) delete working[type];
      }
    } else {
      log.debug('Leaving the LDAP modify handler. Unknown operation.');
      return next(new ldap.ProtocolError(
        'unknown modify operation "' + operation + '"'));
    }
  }
  working.createtimestamp = stored.attributes.createtimestamp;
  working.modifytimestamp = [generalizedTime()];
  stored.attributes = working;
  stored.modifiedAt = working.modifytimestamp[0];
  log.info('ldap: modified ' + dn + '.');
  res.end();
  log.debug('Leaving the LDAP modify handler. The changes were applied.');
  return next();
});

// --- modifyDN (rename) -----------------------------------------------------
server.modifyDN('', function (req, res, next) {
  log.debug('Entering the LDAP modifyDN handler.');
  const dn = req.dn.toString();
  const newRdn = req.newRdn.toString();
  const newSuperior = req.newSuperior ? req.newSuperior.toString() : parentDn(dn);
  const target = newRdn + (newSuperior ? ',' + newSuperior : '');
  log.info('ldap: MODIFYDN ' + dn + ' -> ' + target);
  const stored = getEntry(dn);
  if (!stored) {
    log.debug('Leaving the LDAP modifyDN handler. There is no such entry.');
    return next(new ldap.NoSuchObjectError(dn));
  }
  if (hasChildren(dn)) {
    // Moving a subtree means rewriting every DN below it, which this mock does
    // not do — and doing half of it would leave orphans. Refusing is honest.
    log.debug('Leaving the LDAP modifyDN handler. It has children.');
    return next(new ldap.NotAllowedOnNonLeafError(dn));
  }
  if (getEntry(target)) {
    log.debug('Leaving the LDAP modifyDN handler. The target exists.');
    return next(new ldap.EntryAlreadyExistsError(target));
  }
  if (!isUnder(target, BASE_DN)) {
    log.debug('Leaving the LDAP modifyDN handler. Outside the naming context.');
    return next(new ldap.NoSuchObjectError(BASE_DN));
  }
  entries.delete(normalizeDn(dn));
  stored.dn = target;
  // The RDN's own attribute has to hold the new value, or the entry no longer
  // describes itself. deleteOldRdn says whether the OLD value goes; a client
  // that clears it and never sets the new one is the commonest way to end up
  // with an entry whose cn does not match its DN.
  const rdnParts = newRdn.split('=');
  if (rdnParts.length >= 2) {
    const rdnType = rdnParts[0].trim().toLowerCase();
    const rdnValue = rdnParts.slice(1).join('=').trim();
    const current = stored.attributes[rdnType] || [];
    if (current.indexOf(rdnValue) === -1) {
      stored.attributes[rdnType] = current.concat([rdnValue]);
    }
  }
  stored.attributes.modifytimestamp = [generalizedTime()];
  entries.set(normalizeDn(target), stored);
  res.end();
  log.debug('Leaving the LDAP modifyDN handler. The entry was renamed.');
  return next();
});

// --- compare ---------------------------------------------------------------
server.compare('', function (req, res, next) {
  log.debug('Entering the LDAP compare handler.');
  const dn = req.dn.toString();
  const type = String(req.attribute || '').toLowerCase();
  log.info('ldap: COMPARE ' + dn + ' ' + type + '=' + req.value);
  const stored = getEntry(dn);
  if (!stored) {
    log.debug('Leaving the LDAP compare handler. There is no such entry.');
    return next(new ldap.NoSuchObjectError(dn));
  }
  if (!stored.attributes[type]) {
    log.debug('Leaving the LDAP compare handler. The attribute is not there.');
    return next(new ldap.NoSuchAttributeError(type));
  }
  const matched = stored.attributes[type].some(function (v) {
    // Case-insensitive, which is what the caseIgnoreMatch rule most string
    // attributes use does. A schema-aware server would pick the rule per
    // attribute; this one has no schema and says so.
    return v.toLowerCase() === String(req.value).toLowerCase();
  });
  res.end(matched);
  log.debug('Leaving the LDAP compare handler. matched=' + matched);
  return next();
});

// --- search ----------------------------------------------------------------
server.search('', function (req, res, next) {
  log.debug('Entering the LDAP search handler.');
  const base = req.dn.toString();
  const scope = scopeOf(req);
  const filter = req.filter.toString();
  log.info('ldap: SEARCH base="' + base + '" scope=' + scope +
           ' filter=' + filter + ' attributes=[' +
           (req.attributes || []).join(', ') + ']');
  // The root DSE. A client that does not yet know the base DN asks for it here,
  // with a base of '' and scope base — and a server with no answer for that
  // looks like a server that is down.
  if (normalizeDn(base) === '') {
    if (scope === 'base') {
      res.send(toSearchEntry({
        dn: '',
        attributes: {
          objectclass: ['top', 'LDAProotDSE'],
          namingcontexts: [BASE_DN],
          supportedldapversion: ['3'],
          vendorname: ['mock STS (ldapjs, unmodified, pinned as a submodule)'],
          // supportedControl, supportedExtension and supportedSASLMechanisms
          // are absent rather than empty, and the difference is the point: an
          // LDAP attribute always has at least one value (RFC 4511 section
          // 4.1.7), so "this server supports no controls" is said by not
          // publishing the attribute. Sending it empty is not a weaker claim,
          // it is a malformed one.
          description: ['Every bind succeeds except the password "invalid". ' +
                        'This directory has no schema and answers no ' +
                        'controls, extended operations or SASL mechanisms.']
        }
      }, req.attributes, res.messageId));
      res.end();
      log.debug('Leaving the LDAP search handler. The root DSE was sent.');
      return next();
    }
    log.debug('Leaving the LDAP search handler. A non-base search of the ' +
              'root DSE is refused.');
    return next(new ldap.NoSuchObjectError(''));
  }
  if (!isUnder(base, BASE_DN)) {
    log.debug('Leaving the LDAP search handler. Outside the naming context.');
    return next(new ldap.NoSuchObjectError(base));
  }
  if (!getEntry(base)) {
    log.debug('Leaving the LDAP search handler. The base does not exist.');
    return next(new ldap.NoSuchObjectError(base));
  }
  const clientLimit = parseInt(req.sizeLimit, 10) || 0;
  const limit = clientLimit > 0
    ? Math.min(clientLimit, MAX_SEARCH_RESULTS)
    : MAX_SEARCH_RESULTS;
  let sent = 0;
  let considered = 0;
  for (const stored of entries.values()) {
    if (!isUnder(stored.dn, base)) continue;
    const depth = depthUnder(stored.dn, base);
    if (scope === 'base' && depth !== 0) continue;
    if (scope === 'one' && depth !== 1) continue;
    considered++;
    let matches = false;
    try {
      // The SECOND argument is `strictAttrCase`, and it must be false. LDAP
      // attribute descriptions are case-insensitive (RFC 4512 section 2.5), and
      // this store holds them lower-cased because that is how they arrive —
      // @ldapjs/attribute lower-cases a type on the way in. @ldapjs/filter
      // defaults the flag to TRUE, which is what made `(objectClass=*)` match
      // nothing here while `(cn=developers)` matched: a presence filter compares
      // the attribute name it was given, `objectClass`, against a key spelled
      // `objectclass`. The symptom is the worst kind — a search that succeeds
      // and returns zero entries, which reads as an empty directory rather than
      // as a filter that could not see it.
      matches = req.filter.matches(matchable(stored), false);
    } catch (e) {
      // A filter this store cannot evaluate is not a match, and it is worth a
      // line: an extensible-match filter or an unknown matching rule lands
      // here, and silently returning nothing would look like an empty
      // directory rather than an unsupported filter.
      log.warn('ldap: the filter could not be evaluated against ' + stored.dn +
               ': ' + e.message);
      matches = false;
    }
    if (!matches) continue;
    if (sent >= limit) {
      log.info('ldap: the search reached its size limit of ' + limit + '.');
      res.end(ldap.LDAP_SIZE_LIMIT_EXCEEDED);
      log.debug('Leaving the LDAP search handler. The size limit was reached.');
      return next();
    }
    res.send(toSearchEntry(stored, req.attributes, res.messageId));
    sent++;
  }
  log.info('ldap: the search considered ' + considered + ' entry/entries in ' +
           'scope and returned ' + sent + '.');
  res.end();
  log.debug('Leaving the LDAP search handler. ' + sent + ' entry/entries sent.');
  return next();
});

server.unbind(function (req, res, next) {
  log.debug('Entering the LDAP unbind handler.');
  log.info('ldap: UNBIND');
  res.end();
  log.debug('Leaving the LDAP unbind handler.');
  return next();
});

// ---------------------------------------------------------------------------
// The HTTP views.
//
// GET /sts-metadata is built by walking the express router, so a protocol that
// registers no route is invisible to it — which is exactly what a raw TCP
// listener is. These two routes are what make this directory visible from a
// browser AND what make it appear in that index; the listener itself is
// described by hand there, as the KDC's is.
// ---------------------------------------------------------------------------

function pageShell(title, inner) {
  return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + xmlEscape(title) + '</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;' +
    'background:#f4f4f7;margin:0;padding:2rem;color:#222;line-height:1.45}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;' +
    'padding:24px 28px;max-width:60rem;margin:0 auto;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}' +
    'h1{font-size:1.3em;margin:0 0 4px;color:#12107c}' +
    'h2{font-size:1em;margin:1.4em 0 .4em}' +
    'p.sub{color:#666;font-size:.85em;margin:0 0 18px}' +
    'table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;' +
    'font-size:.85em}' +
    'th,td{border:1px solid #ddd;padding:.35rem .55rem;text-align:left;' +
    'vertical-align:top}th{background:#f0f0f5}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;' +
    'font-size:.85em;background:#f4f4f8;padding:.1rem .25rem;border-radius:3px;' +
    'word-break:break-all}a{color:#12107c}' +
    'ul{margin:.3em 0;padding-left:1.2em}li{margin:.2em 0}' +
    '</style></head><body><div class="card">' + inner + '</div></body></html>\n';
}

// What this directory is, as data. Shared by the page and by ?format=json so
// the two cannot disagree — which is the same reason /sts-metadata reads the
// router rather than a written-down list.
function description(req) {
  log.debug('Entering description().');
  const host = String(req.get('host') || 'localhost').split(':')[0];
  const out = {
    url: 'ldap://' + host + ':' + boundPort,
    port: boundPort,
    // WHETHER THE SOCKET ACTUALLY BOUND, and it is published because this page
    // is HTTP and the directory is not: /ldap answers 200 whether or not port
    // 389 was available, so a reader — or a test — has no other way to tell a
    // running directory from one whose listener lost a race with the host's own
    // slapd. It is a privileged port and this service does not treat a failure
    // to bind as fatal (the rest of it is still useful), so the failure is
    // otherwise silent until somebody's connection is refused.
    listening: listening,
    listenError: listenError,
    baseDn: BASE_DN,
    usersDn: USERS_DN,
    groupsDn: GROUPS_DN,
    ldapVersion: 3,
    bindPolicy: 'every bind succeeds — any DN, any password, including an ' +
      'anonymous one — except the literal password "' + REFUSED_PASSWORD +
      '", which is answered LDAP_INVALID_CREDENTIALS (49) so that a negative ' +
      'test has something to fail on',
    refusedPassword: REFUSED_PASSWORD,
    schema: 'none. No objectClass is enforced and no attribute is checked ' +
      'against a syntax, so an entry may carry whatever attributes a client ' +
      'sends. A real directory would refuse most of that.',
    referentialIntegrity: false,
    tls: false,
    autoCreateUsers: AUTOCREATE_USERS,
    autoCreateRule: 'an entry uid=<name>,' + USERS_DN + ' appears the first ' +
      'time <name> authenticates to this service through ANY protocol. An ' +
      'LDAP bind does not seed one (it presents a DN, not a user name) and ' +
      'neither does an OAuth client. A verified TLS CLIENT CERTIFICATE is the ' +
      'one identity that is already a DN: its entry keeps the subject\'s own ' +
      'leaf RDN — cn=alice,' + USERS_DN + ' for CN=alice,O=Example — or the ' +
      'whole subject where that already lies under ' + BASE_DN + ', and the ' +
      'full subject, issuer, serial and validity are on the entry as x509* ' +
      'attributes, which are this service\'s own names and not schema.',
    enforcedRules: [
      'an add whose parent does not exist is LDAP_NO_SUCH_OBJECT (32)',
      'a delete of an entry with children is LDAP_NOT_ALLOWED_ON_NONLEAF (66)',
      'a modify delete of an attribute that is not present is ' +
        'LDAP_NO_SUCH_ATTRIBUTE (16)',
      'deleting the last value of an attribute deletes the attribute'
    ],
    limits: {
      maxEntries: MAX_ENTRIES,
      maxSearchResults: MAX_SEARCH_RESULTS,
      currentEntries: entries.size
    },
    operations: ['bind', 'unbind', 'add', 'delete', 'modify', 'modifyDN',
                 'compare', 'search'],
    specifications: ['RFC 4510 (LDAP technical specification road map)',
                     'RFC 4511 (the protocol)',
                     'RFC 4512 (directory information models)',
                     'RFC 4514 (DN string representation)',
                     'RFC 4515 (search filter string representation)'],
    implementation: 'ldapjs 3.0.7, pinned as the node-ldapjs submodule and ' +
      'used unmodified'
  };
  log.debug('Leaving description().');
  return out;
}

app.get('/ldap', function (req, res) {
  log.debug('Entering GET /ldap.');
  const info = description(req);
  if (String(req.query.format || '').toLowerCase() === 'json') {
    log.debug('Leaving GET /ldap. JSON.');
    return res.status(200).json(info);
  }
  const rows = [
    ['URL', info.url],
    ['Base DN', info.baseDn],
    ['People', info.usersDn],
    ['Groups', info.groupsDn],
    ['Protocol version', 'LDAPv3'],
    ['Transport', 'plain TCP. There is no LDAPS and no StartTLS here.'],
    ['Entries right now', String(info.limits.currentEntries)],
    ['Listener', info.listening
      ? 'up on TCP ' + info.port
      : 'DOWN — ' + (info.listenError || 'it never bound') +
        '. This page is HTTP and answers either way; the directory does not.'],
    ['An entry per authenticated user', info.autoCreateUsers ? 'on' : 'off']
  ].map(function (pair) {
    return '<tr><td>' + xmlEscape(pair[0]) + '</td><td><code>' +
      xmlEscape(pair[1]) + '</code></td></tr>';
  }).join('');
  const inner = '<h1>An LDAP directory lives here</h1>' +
    '<p class="sub">LDAPv3 over TCP ' + LDAP_PORT + ', RFC 4511. A browser ' +
    'cannot speak it &mdash; the debugger&rsquo;s api opens the socket.</p>' +
    '<table><tr><th>Thing</th><th>Value</th></tr>' + rows + '</table>' +
    '<h2>It authenticates nobody</h2>' +
    '<p>' + xmlEscape(info.bindPolicy) + '.</p>' +
    '<h2>It has no schema</h2>' +
    '<p>' + xmlEscape(info.schema) + '</p>' +
    '<h2>What it does still enforce</h2><ul>' +
    info.enforcedRules.map(function (rule) {
      return '<li>' + xmlEscape(rule) + '</li>';
    }).join('') +
    '</ul>' +
    '<p>And one thing it does <em>not</em>: deleting a user leaves its DN in ' +
    'every group that lists it as a <code>member</code>. Referential ' +
    'integrity is a directory feature, not a protocol rule.</p>' +
    '<p class="sub"><a href="/ldap?format=json">This page as JSON</a> ' +
    '&middot; <a href="/ldap/directory">every entry in the directory</a> ' +
    '&middot; <a href="/sts-metadata">everything this service speaks</a></p>';
  res.status(200).type('html').send(pageShell('LDAP directory', inner));
  log.debug('Leaving GET /ldap.');
});

app.get('/ldap/directory', function (req, res) {
  log.debug('Entering GET /ldap/directory.');
  const listed = [];
  entries.forEach(function (stored) {
    const attributes = {};
    Object.keys(stored.attributes).forEach(function (name) {
      attributes[canonicalName(name)] = stored.attributes[name].slice(0);
    });
    listed.push({
      dn: stored.dn,
      origin: stored.origin || 'unstated',
      attributes: attributes
    });
  });
  listed.sort(function (a, b) {
    return a.dn.localeCompare(b.dn);
  });
  if (String(req.query.format || '').toLowerCase() === 'json') {
    log.debug('Leaving GET /ldap/directory. JSON, ' + listed.length +
              ' entry/entries.');
    return res.status(200).json({ baseDn: BASE_DN, count: listed.length,
                                  entries: listed });
  }
  const rows = listed.map(function (entry) {
    const attrs = Object.keys(entry.attributes).map(function (name) {
      return '<code>' + xmlEscape(name) + '</code>: ' +
        xmlEscape(entry.attributes[name].join(' | '));
    }).join('<br>');
    return '<tr><td><code>' + xmlEscape(entry.dn) + '</code></td><td>' +
      xmlEscape(entry.origin) + '</td><td>' + attrs + '</td></tr>';
  }).join('');
  const inner = '<h1>Every entry in the directory</h1>' +
    '<p class="sub">' + listed.length + ' entry/entries under <code>' +
    xmlEscape(BASE_DN) + '</code>. This page is not LDAP &mdash; it is this ' +
    'service showing its own store, which is how you can tell an empty ' +
    'directory from a search filter that matched nothing.</p>' +
    '<table><tr><th>DN</th><th>Came from</th><th>Attributes</th></tr>' +
    rows + '</table>' +
    '<p class="sub"><a href="/ldap/directory?format=json">This page as ' +
    'JSON</a> &middot; <a href="/ldap">what this directory is</a></p>';
  res.status(200).type('html').send(pageShell('LDAP directory contents', inner));
  log.debug('Leaving GET /ldap/directory. ' + listed.length + ' entry/entries.');
});

// ---------------------------------------------------------------------------
// Starting the listener.
//
// Called from server.js rather than at require time, and the reason is the same
// one the KDC has: binding port 389 is privileged and can fail, and a require
// that throws takes the whole service down where a route cannot. Callers await
// `whenReady` rather than reading a port that is not bound yet.
// ---------------------------------------------------------------------------
function listen() {
  log.debug('Entering listen().');
  const whenReady = new Promise(function (resolve, reject) {
    server.listen(LDAP_PORT, '0.0.0.0', function () {
      const address = server.address();
      boundPort = address ? address.port : LDAP_PORT;
      listening = true;
      listenError = '';
      log.info('ldap: listening on TCP ' + boundPort + ' with base DN ' +
               BASE_DN + '; ' + entries.size +
               ' entry/entries; GET /ldap describes it.');
      resolve({ port: boundPort, baseDn: BASE_DN });
    });
    server.once('error', function (err) {
      // 389 is privileged and it is a well-known port, so the two ways this
      // fails are "not root" and "something else is already there" — a host's
      // own slapd, most often. Neither is fatal to the rest of the service, so
      // the failure is RECORDED rather than thrown, and published on /ldap so
      // that it is visible from outside instead of only in this log.
      listening = false;
      listenError = err.message + (err.code ? ' (' + err.code + ')' : '');
      log.error('ldap: could not bind TCP ' + LDAP_PORT + ': ' + listenError +
                '. The directory will not answer; everything else in this ' +
                'service is unaffected. Set LDAP_PORT to a free, ' +
                'unprivileged port if something else owns 389.');
      reject(err);
    });
  });
  log.debug('Leaving listen().');
  return { server: server, whenReady: whenReady };
}

function close() {
  log.debug('Entering close().');
  server.close();
  log.debug('Leaving close().');
}

module.exports = {
  listen: listen,
  close: close,
  LDAP_PORT: LDAP_PORT,
  BASE_DN: BASE_DN,
  USERS_DN: USERS_DN,
  GROUPS_DN: GROUPS_DN,
  AUTOCREATE_USERS: AUTOCREATE_USERS,
  REFUSED_PASSWORD: REFUSED_PASSWORD,
  MAX_ENTRIES: MAX_ENTRIES,
  MAX_SEARCH_RESULTS: MAX_SEARCH_RESULTS,
  entries: entries,
  autoCreateUser: autoCreateUser,
  objectFor: objectFor
};
