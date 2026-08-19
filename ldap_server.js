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
const config = require('./config');
const stats = require('./admin_stats');
// The admin console, for ONE reason: to hand it the reader below so that a user's
// page can show that user's directory entry. It is required here rather than the
// other way round because server.js requires ./admin BEFORE this module (rule 6),
// so admin.js must not require this one back — see the note above objectFor().
const admin = require('./admin');
// The TLS module, for ONE thing: the server certificate and key it generates at
// its own require time. The LDAPS listener below serves that same pair rather
// than making a second one — see the note above SERVER_CERTIFICATE over there
// for why one certificate for every TLS socket in this process is the property
// worth having, and this file's own LDAPS section for what it costs.
//
// This is a plain require rather than one of the two inverted hooks above,
// because neither of the things that force an inversion applies: tls_server.js
// requires app.js, helpers.js and admin_stats.js and knows nothing about this
// module, so there is no cycle to make; and its routes are /tls, which collide
// with nothing here. What the require DOES do is pull those routes into the
// express router at this point rather than after this module's, so server.js
// now requires ./tls_server BEFORE ./ldap_server to say so out loud. It changes
// no output — /sts-metadata sorts its rows by path within a group — and the
// line over there is for the next reader rather than for the page.
const tlsServer = require('./tls_server');
// WHICH attributes a person's entry should carry so that the credentials this
// service issues have something to say, and what to invent for them. Another
// plain require and not a third inversion, for the same reasons as tls_server.js
// above: vc_claims.js is a LIBRARY — it registers no route, so requiring it adds
// nothing to the express router and cannot reorder /sts-metadata — and it
// requires only helpers.js, so there is no cycle to make. The traffic in the
// other direction, this module's two functions that IT calls, does go through a
// slot: see the setDirectory() install further down.
const vcClaims = require('./vc_claims');

// The port. 389 is the assigned one and this process is root in the container,
// so it binds it directly; a host run is not root, which is why the variable
// exists. Changing it means the parent project's api has to allow the new port
// in `ldapAllowedPorts` or its LDAP client will refuse to reach it — the same
// coupling KRB5_KDC_PORT has with krb5AllowedPorts, and for the same reason.
const LDAP_PORT = config.value('ldap.port');

// The LDAPS port. 636 is the IANA-assigned one for LDAP over TLS and, like 389,
// it is privileged — so the container binds it and a host run usually cannot.
// A failure to bind is RECORDED and published on GET /ldap exactly as the plain
// listener's is, and it is not fatal to the plain listener: the two sockets are
// started independently and either can be up while the other is not, which is
// the commonest outcome of a host run and is why they have separate state
// below rather than one `listening` flag that would have to lie about one.
//
// Two ports rather than StartTLS, and that is not a preference: StartTLS is an
// EXTENDED OPERATION (RFC 4511 section 4.14) that upgrades a connection already
// in progress, and ldapjs implements no extended operations at all — so
// offering it would mean patching the submodule, which this repository does not
// do. It is also worth knowing that LDAPS is the one of the two that no RFC
// defines: RFC 4513 standardised StartTLS and left `ldaps://` as the de-facto
// scheme it already was. Every client speaks it anyway.
const LDAPS_PORT = config.value('ldap.tlsPort');

// The naming context this directory serves. Everything below it is ours;
// anything outside it is answered LDAP_NO_SUCH_OBJECT, which is what a real
// server does for a base DN it holds no data for.
const BASE_DN = config.value('ldap.baseDn');

// Where auto-created people and hand-made groups are expected to live. They are
// derived rather than configured: two variables that could disagree with
// BASE_DN would produce entries in a tree nobody is searching.
const USERS_DN = 'ou=users,' + BASE_DN;
const GROUPS_DN = 'ou=groups,' + BASE_DN;

// Only an explicit "0" or "false" turns the auto-creation off, so a missing or
// misspelled variable leaves it ON — the safe direction here, because the
// feature is what makes the directory non-empty for somebody who has just
// signed in and gone looking for themselves.
function autocreateUsers() {
  return config.value('ldap.autocreateUsers');
}

// The password that is refused. See the header: this is the service's standing
// convention rather than an authentication policy.
const REFUSED_PASSWORD = 'invalid';

// A ceiling on how large this directory may grow. It is in memory and it grows
// on its own (every authentication can add an entry), so an unbounded one is a
// memory leak with a protocol in front of it. When it is reached, new entries
// are refused with LDAP_ADMIN_LIMIT_EXCEEDED rather than silently dropped.
function maxEntries() {
  return config.value('ldap.maxEntries');
}

// How many entries one search may return. RFC 4511 section 4.5.1.4 lets a
// client ask for fewer with sizeLimit and lets the server impose its own; a
// search of a directory this small will never reach it, but a client that has
// never seen LDAP_SIZE_LIMIT_EXCEEDED has never handled a paged result either.
function maxSearchResults() {
  return config.value('ldap.sizeLimit');
}

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
// The LDAPS listener's own three. Separate rather than a flag on the ones above,
// for the reason LDAPS_PORT gives: "389 is up and 636 is not" is a state a host
// run reaches almost every time, and a single pair could only report one of them.
let tlsListening = false;
let tlsListenError = '';
let boundTlsPort = LDAPS_PORT;

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
  // RFC 2307's, and the one a posixGroup's membership is written in. It holds a
  // bare user name where the other three hold a DN, which is why /admin/groups
  // resolves it differently — see MEMBER_ATTRIBUTES.
  memberuid: 'memberUid',
  userpassword: 'userPassword', employeenumber: 'employeeNumber',
  employeetype: 'employeeType', departmentnumber: 'departmentNumber',
  postaladdress: 'postalAddress', l: 'l', st: 'st', c: 'c', gidnumber: 'gidNumber',
  uidnumber: 'uidNumber', homedirectory: 'homeDirectory',
  createtimestamp: 'createTimestamp', modifytimestamp: 'modifyTimestamp',
  // PKCS#9, and it arrives on this directory inside a certificate subject.
  emailaddress: 'emailAddress',
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

// The attribute types /admin/vc can put on a person so that a credential has
// something to carry. They are MERGED rather than typed out a second time: that
// catalogue already spells each one the way its schema document spells it
// (`schacDateOfBirth`, `labeledURI`, `departmentNumber`), and two lists of
// spellings is one list that will eventually be wrong. Anything already named
// above keeps its spelling — Object.assign's later argument wins, so the merge
// is written in the order that makes the table above authoritative.
Object.keys(vcClaims.CANONICAL_NAMES).forEach(function (lower) {
  if (!CANONICAL_NAMES[lower]) CANONICAL_NAMES[lower] = vcClaims.CANONICAL_NAMES[lower];
});

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

// Does this identity begin `<attributetype>=`, which is to say: is it a DN
// rather than a name? admin_stats.js asks the same question of the same values
// for a different reason (it must not split a DN at an '@'), and the two are
// deliberately separate one-line tests rather than a shared export: this one
// decides where an entry goes, that one decides what a person is called, and a
// single knob turning both would couple two decisions that only look alike.
const DN_SHAPED = /^[A-Za-z][A-Za-z0-9-]*=/;

// The CN out of a DN, unescaped, or '' where there is none. Used when the
// certificate's own commonName was not passed — the DN always carries it if the
// subject has one, so there is no second source to disagree with.
function commonNameOf(dn) {
  const pairs = splitRdns(dn).map(rdnPairs).reduce(function (a, b) {
    return a.concat(b);
  }, []);
  const cn = pairs.filter(function (pair) { return pair.attribute === 'cn'; })[0];
  return cn ? unescapeDnValue(cn.value) : '';
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
  // The LEAF's pairs name the entry; ALL of them become attributes. Two
  // different lists, and using one for both is the mistake to avoid in each
  // direction: naming the entry from the whole subject produces a DN with
  // somebody's country in it, and taking the attributes from the leaf alone
  // silently drops the O, OU and C the certificate went to the trouble of
  // carrying.
  const pairs = rdnPairs(leaf);
  const allPairs = rdns.map(rdnPairs).reduce(function (a, b) {
    return a.concat(b);
  }, []);
  const common = String(certificate.commonName || commonNameOf(subject) ||
                        '').trim();

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
  allPairs.forEach(function (pair) {
    const existing = attributes[pair.attribute] || [];
    const value = unescapeDnValue(pair.value);
    // Concatenated rather than assigned: a subject with two OUs has two RDNs of
    // the same type, and the second overwriting the first would lose half of
    // what the certificate said.
    if (existing.indexOf(value) < 0) {
      attributes[pair.attribute] = existing.concat([value]);
    }
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
  if (!autocreateUsers()) {
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
  // The invented person behind the name. Their given name, family name and
  // mailbox are what the entry gets — where it used to get `dave`, `Mock` and
  // `dave@sts-mock.example`, one string three times over.
  //
  // The change is deliberate and it is not cosmetic: those three are attributes a
  // credential asserts, so a directory that derived all of them from the login
  // name made every issued credential say the login name back. `given_name:
  // "dave"` is not a given name, and a wallet developer testing what their UI does
  // with a person's name learned nothing from it. What the entry keeps from the
  // login name is the two things that ARE the identity — the DN and the `uid` —
  // which is also how a real directory looks: somebody's uid rarely is their name.
  //
  // `(mock)` stays on the displayName. Every value here is invented, and the one
  // place a person reads before the others should say so.
  const persona = vcClaims.personaFor(name);
  const plan = info.certificate
    ? certificatePlan(info)
    : {
        dn: 'uid=' + name + ',' + USERS_DN,
        attributes: {
          objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
          uid: name,
          cn: persona.display,
          sn: persona.family,
          givenName: persona.given,
          displayName: persona.display + ' (mock)',
          mail: persona.email
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
    // And whatever the credential claim set now wants that this entry does not
    // carry. It runs on a RETURNING person and not only on a new one, because the
    // selection can change between two sign-ins: somebody who ticks `title` on
    // /admin/vc gets the whole directory populated then (that page runs the same
    // sweep), and this is what covers the person who authenticates for the first
    // time after that but whose entry was created before it.
    if (applyVcAttributes(existing, name)) {
      changed = true;
    }
    if (changed) {
      existing.attributes.modifytimestamp = [generalizedTime()];
      log.debug('Leaving autoCreateUser(). The entry existed and now records ' +
                'something it did not before.');
      return existing;
    }
    log.debug('Leaving autoCreateUser(). The entry already existed.');
    return existing;
  }
  if (entries.size >= maxEntries()) {
    // Reported rather than thrown: the authentication itself succeeded and must
    // not be failed by a directory that is full.
    log.warn('ldap: not creating ' + dn + '; the directory holds its maximum ' +
             'of ' + maxEntries() + ' entries.');
    log.debug('Leaving autoCreateUser(). The directory is full.');
    return null;
  }
  const created = putEntry(dn, Object.assign({}, plan.attributes,
                                             { description: [note] }),
                           { origin: 'authentication' });
  // The invented facts a credential will assert about this person, written HERE
  // rather than into the credential, so that the entry an LDAP client reads and
  // the credential a wallet is handed say the same thing about the same person.
  // It runs after putEntry() rather than being folded into the attributes above
  // because it fills only what is ABSENT, and the plan's own attributes — uid,
  // cn, sn, the certificate's RDNs — are the ones that must win.
  applyVcAttributes(created, name);
  log.info('ldap: created ' + dn + ' because ' + name + ' ' + note + '.');
  log.debug('Leaving autoCreateUser(). The entry was created.');
  return created;
}

// ---------------------------------------------------------------------------
// THE FACTS A CREDENTIAL NEEDS, INVENTED ONCE AND KEPT HERE.
//
// /admin/vc chooses which attributes an issued credential carries. Those
// attributes have to have VALUES, and this service authenticates nobody — there
// is no source of a real birthdate, and there had better not be. So vc_claims.js
// invents a consistent person per username and this function writes what is
// missing onto their entry.
//
// Three rules, and each of them is the answer to a way this could go wrong:
//
//   * ABSENT ONLY. An attribute the entry already carries is never touched. That
//     covers the seeded people (alice keeps `Alice Anderson`, and only gains the
//     attributes she had none of), a certificate's RDNs, and — the one that
//     matters most — anything an operator set through LDAP. A sweep that
//     overwrote `mail` after somebody had just ldapmodify'd it would be a
//     directory that argues with its own clients.
//   * ONE VALUE. These are single-valued facts; addValues() would happily append
//     a second `mail` on the next sweep if the first were ever edited, and an
//     entry that accumulated a birthdate per sign-in would be the visible symptom
//     of a bug nobody could locate.
//   * A NAME, NOT A DN, seeds the person. A TLS client certificate's identity is
//     a DN, and `uid` holding one would contradict the entry it sits on — so the
//     row that carries the username is skipped for those. Everything else is
//     invented from the DN string quite happily; it is only a seed.
// ---------------------------------------------------------------------------
function applyVcAttributes(stored, key) {
  log.debug('Entering applyVcAttributes(). dn=' + (stored && stored.dn));
  if (!stored) {
    log.debug('Leaving applyVcAttributes(). There is no entry.');
    return false;
  }
  const name = String(key == null ? '' : key).trim() || commonNameOf(stored.dn) ||
               (stored.attributes.uid || [])[0] || stored.dn;
  const isDn = DN_SHAPED.test(name);
  const generated = vcClaims.generatedFor(name);
  const added = [];
  Object.keys(generated).forEach(function (attribute) {
    const have = stored.attributes[attribute] || [];
    if (have.length) {
      return;
    }
    if (isDn && attribute === 'uid') {
      // See the third rule: this entry is named by a certificate subject, and a
      // uid holding that subject would name the person something the DN does not.
      return;
    }
    stored.attributes[attribute] = [generated[attribute]];
    added.push(canonicalName(attribute));
  });
  if (!added.length) {
    log.debug('Leaving applyVcAttributes(). It already had everything the ' +
              'credential claim set asks for.');
    return false;
  }
  stored.attributes.modifytimestamp = [generalizedTime()];
  log.info('ldap: ' + stored.dn + ' gained ' + added.join(', ') +
           ' so that an issued credential has something to assert.');
  log.debug('Leaving applyVcAttributes(). ' + added.length + ' attribute(s) added.');
  return true;
}

// The name to invent a person from, for an entry nobody handed us a key for —
// which is every entry the sweep below walks. The uid is what autoCreateUser()
// built the DN from and what /admin/users files the person under, so it is the
// one that keeps the sweep's values identical to the ones an authentication
// would have written; the CN is the fallback for a certificate-seeded entry,
// which has no uid; the DN is the last resort and is at least stable.
function personaKeyOf(stored) {
  const uid = (stored.attributes.uid || [])[0];
  if (uid) return String(uid);
  const cn = (stored.attributes.cn || [])[0];
  if (cn) return String(cn);
  return stored.dn;
}

// ---------------------------------------------------------------------------
// THE SWEEP, run when the claim set changes and once at startup.
//
// Changing the selection on /admin/vc has to reach the people who are already
// here, or the page would appear to do nothing for every user created before it
// was touched — and the way that failure presents is the expensive one: the
// credential still carries the claim (vc_claims.js falls back to the invented
// value), so it looks like it worked, and only an LDAP client shows that the
// directory disagrees.
//
// What counts as a person is ENTRIES UNDER ou=users, the container excepted.
// Deliberately not "everything with a person objectClass anywhere": this
// directory is schemaless, a client can add anything anywhere, and inventing a
// birthdate for `cn=developers,ou=groups` because somebody gave it an
// objectClass of person would be a sweep doing damage in a place nobody asked it
// to look. The container itself is excepted because it is an
// organizationalUnit — an `ou=users` carrying a nationality is not a person, it
// is a bug that reads as one.
// ---------------------------------------------------------------------------
function populateVcAttributes() {
  log.debug('Entering populateVcAttributes().');
  const wanted = vcClaims.selectedNames();
  let examined = 0;
  let changed = 0;
  const before = new Map();
  entries.forEach(function (stored) {
    if (!isUnder(stored.dn, USERS_DN) || normalizeDn(stored.dn) === normalizeDn(USERS_DN)) {
      return;
    }
    examined++;
    before.set(stored.dn, Object.keys(stored.attributes).length);
    if (applyVcAttributes(stored, personaKeyOf(stored))) {
      changed++;
    }
  });
  // The number of VALUES written, not just of entries touched, because "12
  // entries changed" says nothing about whether the attribute somebody just
  // ticked actually landed anywhere.
  let values = 0;
  entries.forEach(function (stored) {
    if (before.has(stored.dn)) {
      values += Object.keys(stored.attributes).length - before.get(stored.dn);
    }
  });
  log.info('ldap: swept ' + examined + ' entry/entries under ' + USERS_DN + ' for the ' +
           wanted.length + ' attribute(s) the credential claim set asks for; ' + changed +
           ' entry/entries gained ' + values + ' value(s).');
  log.debug('Leaving populateVcAttributes(). ' + changed + ' of ' + examined + ' changed.');
  return { examined: examined, changed: changed, values: values, attributes: wanted };
}

// What one person's entry holds, for vc_claims.js to read a claim value out of.
// The attribute names are the stored (lower-cased) ones, which is what that
// module compares against — see the note on its directoryAttributes().
//
// It is given the same identity key the console files a person under, so
// locateEntry() answers for both shapes of identity: a name is
// `uid=<name>,ou=users` and a certificate's DN is found by the subject the entry
// recorded. Nothing is invented here — a missing entry is null, and the caller's
// own fallback is what fills the claim.
function vcAttributesFor(key) {
  log.debug('Entering vcAttributesFor(). key=' + key);
  const name = String(key == null ? '' : key).trim();
  if (!name) {
    log.debug('Leaving vcAttributesFor(). There was no identity to look up.');
    return null;
  }
  const located = locateEntry(name);
  if (!located.stored) {
    log.debug('Leaving vcAttributesFor(). Nothing at ' + located.dn + '.');
    return null;
  }
  log.debug('Leaving vcAttributesFor(). ' +
            Object.keys(located.stored.attributes).length + ' attribute(s) at ' +
            located.stored.dn + '.');
  return located.stored.attributes;
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
//
// Finding it is two rules, because there are two shapes of identity here. A NAME
// is `uid=<name>,ou=users` and always was. A DN — which is what a TLS client
// certificate's identity is — is looked up by the subject the entry RECORDED,
// in `x509subject`, because that is exact and stays right if certificatePlan()'s
// naming rule ever changes; and where the subject lies inside this directory's
// own tree, the entry it names directly is the answer. Failing both, the DN
// certificatePlan() WOULD have built is reported, so the page can say where the
// entry would have gone rather than naming a place nothing was ever going to be.
function locateEntry(key) {
  log.debug('Entering locateEntry(). key=' + key);
  if (DN_SHAPED.test(key)) {
    const direct = getEntry(key);
    if (direct) {
      log.debug('Leaving locateEntry(). The DN names an entry here directly.');
      return { dn: direct.dn, stored: direct };
    }
    let found = null;
    entries.forEach(function (entry) {
      if (found) {
        return;
      }
      if ((entry.attributes.x509subject || []).indexOf(key) >= 0) {
        found = entry;
      }
    });
    if (found) {
      log.debug('Leaving locateEntry(). Found by x509subject: ' + found.dn);
      return { dn: found.dn, stored: found };
    }
    const plan = certificatePlan({ certificate: { subject: key } });
    log.debug('Leaving locateEntry(). Nothing yet; it would go at ' + plan.dn);
    return { dn: plan.dn, stored: null };
  }
  const dn = 'uid=' + key + ',' + USERS_DN;
  log.debug('Leaving locateEntry(). A name, so ' + dn);
  return { dn: dn, stored: getEntry(dn) };
}

function objectFor(name) {
  log.debug('Entering objectFor(). name=' + name);
  const key = String(name == null ? '' : name).trim();
  const located = key ? locateEntry(key) : { dn: '', stored: null };
  const dn = located.dn;
  const stored = located.stored;

  // Every OTHER entry in the tree whose uid names this same person. A client can
  // add `cn=alice,ou=people` through the protocol, and a page that reported only
  // the auto-created DN would say "no entry" while the directory held one. Only
  // the DNs are listed — the dump below is of the entry the console is about.
  //
  // Skipped for a DN identity: `uid` holds names, so matching a whole DN against
  // it can only ever find nothing, and the entry for that identity was found by
  // its subject above rather than by a name at all.
  const alsoNamed = [];
  if (key && !DN_SHAPED.test(key)) {
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
    // The second socket, because the console warns when a reader cannot reach
    // this entry over LDAP and that is now two questions. A page that said "no
    // client can connect" while LDAPS was up would be wrong in the direction
    // that costs somebody an afternoon.
    ldapsPort: secureServer ? boundTlsPort : null,
    ldapsListening: tlsListening,
    autoCreateUsers: autocreateUsers(),
    entryCount: entries.size,
    maxEntries: maxEntries(),
    // Not `entryCount >= maxEntries` computed by the caller: the cap is this
    // module's and a second copy of the comparison is a second thing to keep
    // right.
    full: entries.size >= maxEntries()
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

// ---------------------------------------------------------------------------
// WHAT THE CONSOLE'S GROUPS PAGE READS. The third inverted hook, and the same
// direction as objectFor() above for the same reason — see the note there.
//
// ---------------------------------------------------------------------------
// WHAT COUNTS AS A GROUP, which is the one decision here with two defensible
// answers and no third.
//
// A real directory would answer with a SCHEMA: an entry is a group when its
// objectClass says so. This one has no schema (that is deliberate, and GET
// /ldap says so), and a client can `add` anything anywhere through the
// protocol — a groupOfNames under ou=users, or an entry under ou=groups
// carrying no objectClass at all. So both rules are applied and neither is
// allowed to hide the other:
//
//   * PLACEMENT — it sits under ou=groups and is not that container itself.
//   * OBJECTCLASS — it carries one of the four group classes below, wherever
//     it sits.
//
// Which rule matched is reported per group, because a groupOfNames sitting
// outside ou=groups and an attribute-less entry inside it are both things
// somebody wrote on purpose to see what this service does with them, and a page
// that silently normalised them into one list would answer the question wrong.
// ---------------------------------------------------------------------------
const GROUP_CLASSES = ['groupofnames', 'groupofuniquenames', 'posixgroup',
                       'groupofurls'];

// The attributes that carry membership, and what each one's values ARE — which
// is the distinction that matters when they are resolved. `member` and
// `uniqueMember` hold a DN (RFC 4519); `memberUid` holds a bare user name, so a
// posixGroup's members are looked up as uid=<value>,ou=users rather than as
// DNs. Treating them alike is how a page ends up reporting every posixGroup
// member as dangling.
const MEMBER_ATTRIBUTES = [
  { name: 'member', holds: 'dn' },
  { name: 'uniquemember', holds: 'dn' },
  { name: 'memberuid', holds: 'uid' }
];

// Is this entry a group, and by which rule? Returns '' for "it is not one".
function groupRuleFor(stored) {
  const under = isUnder(stored.dn, GROUPS_DN) &&
                normalizeDn(stored.dn) !== normalizeDn(GROUPS_DN);
  const classes = (stored.attributes.objectclass || []).map(function (value) {
    return String(value).toLowerCase();
  });
  const classed = classes.some(function (value) {
    return GROUP_CLASSES.indexOf(value) >= 0;
  });
  if (under && classed) return 'both';
  if (under) return 'placement';
  if (classed) return 'objectClass';
  return '';
}

// The key the ADMIN CONSOLE files a person under, worked out from the DN of the
// entry that names them — the inverse of the `uid=<name>,ou=users` locateEntry()
// builds, and the reason a member row can link to /admin/users?user=... at all.
//
// Two sources, in this order, and the order is what keeps the link honest: the
// entry's own `uid` where it has one, because that is what autoCreateUser()
// wrote and is exactly what the console keyed on; failing that, the uid RDN of
// the DN itself, which is all there is for a member that names an entry this
// directory does not hold. An entry named some other way — `cn=alice,ou=users`
// added through the protocol, or the `cn=` entry a TLS client certificate
// seeds — yields '' and gets no link rather than a link to a user page that
// would say "nothing has authenticated as that".
function consoleKeyFor(dn, stored) {
  if (stored && (stored.attributes.uid || []).length) {
    return String(stored.attributes.uid[0]);
  }
  const leaf = splitRdns(dn)[0] || '';
  const pairs = rdnPairs(leaf).filter(function (pair) {
    return pair.attribute === 'uid';
  });
  return pairs.length ? unescapeDnValue(pairs[0].value) : '';
}

// One membership value, resolved. `holds` says how to read it — see
// MEMBER_ATTRIBUTES — and everything else is a fact about what is or is not at
// the far end.
//
// A member that names nothing is reported as DANGLING rather than dropped, and
// that is the whole reason this resolution exists: this directory does not
// enforce referential integrity (deleting a user leaves its DN in every group
// that listed it — see the header), so a dangling member is a state a client
// can reach in two operations and a page that quietly showed six members where
// the entry lists seven would be hiding the very thing it was built to show.
function resolveMember(value, attribute) {
  const raw = String(value == null ? '' : value);
  const holds = attribute.holds;
  const dn = holds === 'uid' ? 'uid=' + raw + ',' + USERS_DN : raw;
  const stored = getEntry(dn);
  const rule = stored ? groupRuleFor(stored) : '';
  return {
    value: raw,
    attribute: canonicalName(attribute.name),
    // What the attribute's value MEANT, so a reader can see why memberUid's
    // `alice` and member's `uid=alice,ou=users,...` end up at the same entry.
    holds: holds,
    dn: dn,
    present: !!stored,
    // A group that lists another group is NESTED membership, which this service
    // does not expand — nothing here walks it, and no protocol endpoint reads
    // these groups at all. Saying which members are groups is what lets a reader
    // see the nesting they wrote; claiming to have flattened it would be a lie
    // about a feature that is not here.
    kind: !stored ? 'dangling' : (rule ? 'group' : 'entry'),
    userKey: stored ? consoleKeyFor(dn, stored) : '',
    // Enough of the entry to draw a row without a second lookup. Empty for a
    // dangling member, which is the point.
    cn: stored ? (stored.attributes.cn || [])[0] || '' : '',
    mail: stored ? (stored.attributes.mail || [])[0] || '' : '',
    displayName: stored ? (stored.attributes.displayname || [])[0] || '' : ''
  };
}

// Every membership value on one entry, in the order MEMBER_ATTRIBUTES lists the
// attributes and, within an attribute, the order the values are stored in.
function membersOf(stored) {
  const out = [];
  MEMBER_ATTRIBUTES.forEach(function (attribute) {
    (stored.attributes[attribute.name] || []).forEach(function (value) {
      out.push(resolveMember(value, attribute));
    });
  });
  return out;
}

// The OTHER answer to "who is in this group": entries elsewhere in the tree
// whose own `memberOf` names it and which the group's member attributes do NOT
// list back.
//
// This is not a nicety. `memberOf` is maintained by the SERVER in every
// directory that has it (it is not even a standard attribute — it is Microsoft's
// and OpenLDAP's, through an overlay), and this one maintains nothing: a client
// that writes `memberOf: cn=developers,...` onto a user creates exactly this
// disagreement, and it is one of the two or three things a person would come to
// a mock directory to try. Listing them separately, under their own heading,
// says which side of the disagreement each name came from — merging them into
// the member list would manufacture a consistency this directory never claimed.
function claimedMembersOf(groupDn) {
  const listed = {};
  const stored = getEntry(groupDn);
  if (stored) {
    membersOf(stored).forEach(function (member) {
      listed[normalizeDn(member.dn)] = true;
    });
  }
  const out = [];
  const key = normalizeDn(groupDn);
  entries.forEach(function (entry) {
    const claims = (entry.attributes.memberof || []).some(function (value) {
      return normalizeDn(value) === key;
    });
    if (!claims || listed[normalizeDn(entry.dn)]) {
      return;
    }
    out.push({
      dn: entry.dn,
      userKey: consoleKeyFor(entry.dn, entry),
      cn: (entry.attributes.cn || [])[0] || '',
      mail: (entry.attributes.mail || [])[0] || ''
    });
  });
  return out.sort(function (a, b) {
    return normalizeDn(a.dn) < normalizeDn(b.dn) ? -1 : 1;
  });
}

// The directory-level facts every one of the console's LDAP sections needs. The
// same six objectFor() reports, out of one function so that the two pages cannot
// come to disagree about whether a socket is up.
function directoryState() {
  return {
    baseDn: BASE_DN,
    usersDn: USERS_DN,
    groupsDn: GROUPS_DN,
    port: boundPort,
    listening: listening,
    listenError: listenError,
    ldapsPort: secureServer ? boundTlsPort : null,
    ldapsListening: tlsListening,
    entryCount: entries.size,
    maxEntries: maxEntries()
  };
}

// The console's group reader. One function for both of its pages, because the
// list and the detail answer the same question at two depths and two functions
// would be two places for "what counts as a group" to drift apart.
//
// With no DN it is the list. With one it is the list AND that group in full —
// the list costs one pass over a store capped at maxEntries() and it is what lets
// the detail page carry its own way back to the siblings.
function groupsFor(dn) {
  log.debug('Entering groupsFor(). dn=' + (dn || '(the whole list)'));
  const wanted = String(dn == null ? '' : dn).trim();
  const out = directoryState();
  out.requested = wanted;
  out.found = false;
  out.notAGroup = false;
  out.group = null;

  const groups = [];
  entries.forEach(function (entry) {
    const rule = groupRuleFor(entry);
    if (!rule) {
      return;
    }
    const members = membersOf(entry);
    groups.push({
      dn: entry.dn,
      cn: (entry.attributes.cn || [])[0] || commonNameOf(entry.dn),
      rule: rule,
      description: (entry.attributes.description || [])[0] || '',
      objectClass: (entry.attributes.objectclass || []).slice(0),
      origin: entry.origin || 'unstated',
      createdAt: entry.createdAt,
      modifiedAt: entry.modifiedAt,
      memberCount: members.length,
      // Split out because the two numbers are the interesting pair: a group
      // whose seven members resolve to five entries is the referential-integrity
      // story, and a single count tells it as "seven members" with nothing wrong.
      presentCount: members.filter(function (m) { return m.present; }).length,
      danglingCount: members.filter(function (m) { return !m.present; }).length,
      claimedCount: claimedMembersOf(entry.dn).length,
      attributeCount: Object.keys(entry.attributes).length
    });
  });
  groups.sort(function (a, b) {
    return normalizeDn(a.dn) < normalizeDn(b.dn) ? -1 : 1;
  });
  out.groups = groups;
  out.groupCount = groups.length;

  if (!wanted) {
    log.debug('Leaving groupsFor(). ' + groups.length + ' group(s).');
    return out;
  }

  const stored = getEntry(wanted);
  if (!stored) {
    log.debug('Leaving groupsFor(). There is no entry at ' + wanted + '.');
    return out;
  }
  const rule = groupRuleFor(stored);
  if (!rule) {
    // The entry is real and is not a group. A separate state from "no such
    // entry" because the page has something useful to say about it — a client
    // can rename a group out of ou=groups or strip its objectClass, and "there
    // is nothing there" would send a reader looking for a deletion that did not
    // happen.
    out.notAGroup = true;
    out.entryDn = stored.dn;
    log.debug('Leaving groupsFor(). ' + stored.dn + ' is an entry but not a group.');
    return out;
  }

  // Canonically spelled and OPERATIONAL ATTRIBUTES INCLUDED, for the reason
  // objectFor() gives: this is not a search, it is the service showing its own
  // store, and a dump that dropped two attributes would be the one thing a dump
  // must not do.
  const attributes = {};
  Object.keys(stored.attributes).sort().forEach(function (attribute) {
    attributes[canonicalName(attribute)] = stored.attributes[attribute].slice(0);
  });
  const members = membersOf(stored);
  out.found = true;
  out.group = {
    dn: stored.dn,
    cn: (stored.attributes.cn || [])[0] || commonNameOf(stored.dn),
    rule: rule,
    origin: stored.origin || 'unstated',
    createdAt: stored.createdAt,
    modifiedAt: stored.modifiedAt,
    operational: OPERATIONAL.map(canonicalName),
    memberAttributes: MEMBER_ATTRIBUTES.map(function (a) {
      return canonicalName(a.name);
    }),
    attributes: attributes,
    members: members,
    memberCount: members.length,
    presentCount: members.filter(function (m) { return m.present; }).length,
    danglingCount: members.filter(function (m) { return !m.present; }).length,
    claimed: claimedMembersOf(stored.dn)
  };
  log.debug('Leaving groupsFor(). ' + stored.dn + ' has ' + members.length +
            ' member value(s), ' + out.group.danglingCount + ' of them dangling.');
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

// The third, and guarded for the same reason: an older admin.js without the slot
// costs a warning rather than a TypeError at require time, which would take the
// whole service down over one page.
if (typeof admin.setGroupReader === 'function') {
  admin.setGroupReader(groupsFor);
} else {
  log.warn('ldap: the admin console offers no setGroupReader(), so /admin/groups ' +
           'will report that no directory is loaded. The directory itself is ' +
           'unaffected.');
}

// The fourth, and the only one that goes to a module this file also requires
// outright. That is not a contradiction: vc_claims.js is required above for the
// catalogue and the invented people, and it calls back into these two functions
// through a slot because IT must not require THIS module — it is read by
// vc_issuer.js, which server.js requires fifty lines before ./admin, and a
// require from there would drag this directory's routes to the front of the
// express router that /sts-metadata is built by walking. Guarded like the two
// above: an older vc_claims.js without the slot costs a warning, not a service
// that will not start.
if (typeof vcClaims.setDirectory === 'function') {
  vcClaims.setDirectory({ attributesFor: vcAttributesFor, populate: populateVcAttributes });
} else {
  log.warn('ldap: vc_claims.js offers no setDirectory(), so issued credentials ' +
           'will carry invented values rather than what this directory holds. The ' +
           'directory itself is unaffected.');
}

// And once, now. The seeded people were written before any of this existed and
// the claim set already has ten attributes selected, so without this sweep alice
// would have no birthdate in the directory while her credential asserted one —
// the two disagreeing from the very first request, which is the exact confusion
// this whole arrangement exists to avoid.
populateVcAttributes();

// ---------------------------------------------------------------------------
// The server, and its handlers.
//
// Every handler is registered against BASE_DN and against '' — the second is
// the ROOT DSE and anything outside the naming context. A client that binds
// before it knows the base DN reads the root DSE first, and a server that had no
// handler for it answers LDAP_UNAVAILABLE, which reads as the server being down.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// TWO SERVERS, ONE SET OF HANDLERS.
//
// ldapjs decides between a net.Server and a tls.Server AT CONSTRUCTION, from
// whether it was given a certificate and a key (lib/server.js) — so LDAPS is a
// second server OBJECT here and not an option on the first, and handlers are
// registered per instance. Every `server.bind(...)`, `server.search(...)` and
// the rest below therefore has to reach both, and the failure to avoid is a
// handler that lands on one and not the other: a directory that answers a
// search on 389 and refuses it on 636 looks like a TLS fault and is not one.
//
// So `server` below is NOT a server. It is a fan-out carrying the nine method
// names ldapjs exposes for the operations, and every registration in this file
// goes through it unchanged — which is the whole point, since the alternatives
// are a second copy of three hundred lines of handlers or a reach into ldapjs's
// internal `routes` map, and this repository consumes that submodule through
// its public API only (see CLAUDE.md). Adding an operation costs one name in
// the list; adding a listener costs nothing.
//
// The secure one is built only if there IS certificate material. There always
// is — tls_server.js generates it at require time and would have thrown before
// this line if it could not — so this branch is for the case where that stops
// being true: an absence recorded and published on GET /ldap is worth more than
// a TypeError out of a constructor, which is the same trade every listen path
// here makes.
// ---------------------------------------------------------------------------
const plainServer = ldap.createServer({ log: log });

const serverCertificate = tlsServer.serverCertificate();

let secureServer = null;
if (serverCertificate && serverCertificate.certPem &&
    serverCertificate.privateKeyPem) {
  // `certificate` and `key` are the option names ldapjs checks for, and it
  // hands the whole options object to tls.createServer(). No client certificate
  // is asked for here: this listener proves the SERVER's identity and nothing
  // else, which GET /ldap says out loud rather than leaving somebody to work
  // out why the client certificate they offered was never requested. The
  // permissive and strict client-certificate listeners are the HTTPS ones next
  // door, where the whole content is the answer to that question.
  secureServer = ldap.createServer({
    log: log,
    certificate: serverCertificate.certPem,
    key: serverCertificate.privateKeyPem
  });
} else {
  tlsListenError = 'there was no server certificate at startup';
  log.warn('ldap: no server certificate is available, so LDAPS will not be ' +
           'offered on ' + LDAPS_PORT + '. The plain listener on ' + LDAP_PORT +
           ' is unaffected.');
}

const servers = secureServer ? [plainServer, secureServer] : [plainServer];

// The eight operations and unbind. Written out rather than read off ldapjs's
// prototype, because that would fan out `listen`, `close` and `address` too —
// and those three must stay per-server: each listener has its own port, its own
// bind failure and its own answer to "are you up".
const OPERATIONS = ['bind', 'unbind', 'add', 'del', 'modify', 'modifyDN',
                    'compare', 'search'];

const server = {};
OPERATIONS.forEach(function (operation) {
  server[operation] = function () {
    const args = Array.prototype.slice.call(arguments);
    servers.forEach(function (one) {
      one[operation].apply(one, args);
    });
    // ldapjs returns the server for chaining and nothing here chains, but a
    // fan-out that returned undefined would break the first caller that did.
    return server;
  };
});

// NOT fanned out: an error says which listener it came from. Two sockets and
// one message about "the server" would send a reader to the wrong port, and the
// two fail in different ways — 389 loses a race with the host's own slapd, 636
// is refused because the process is not root.
plainServer.on('error', function (err) {
  // Reported rather than thrown: the rest of this service is still useful, and
  // a listener that dies silently surfaces later as a directory that never
  // answers.
  log.error('ldap: the plain listener (' + boundPort + ') reported an error: ' +
            err.message);
});

if (secureServer) {
  secureServer.on('error', function (err) {
    log.error('ldap: the LDAPS listener (' + boundTlsPort + ') reported an ' +
              'error: ' + err.message + '. The plain listener on ' + boundPort +
              ' is a separate socket and is unaffected.');
  });
}

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
  if (entries.size >= maxEntries()) {
    log.debug('Leaving the LDAP add handler. The directory is full.');
    return next(new ldap.AdminLimitExceededError(
      'this directory holds its maximum of ' + maxEntries() + ' entries'));
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
    ? Math.min(clientLimit, maxSearchResults())
    : maxSearchResults();
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
  // Read rather than written down again: the HTTPS listeners' ports are that
  // module's to decide, and a second copy here would be a second thing to keep
  // right the day somebody sets STS_TLS_PORT.
  const tlsPorts = tlsServer.ports();
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
    // This was `false` and it is now the whole answer, because one boolean had
    // to stand for three different facts and got at least one of them wrong for
    // any reader: LDAPS is here, StartTLS is not, and no CLIENT certificate is
    // ever asked for on either transport.
    tls: {
      ldaps: !!secureServer,
      port: secureServer ? boundTlsPort : null,
      url: secureServer ? 'ldaps://' + host + ':' + boundTlsPort : '',
      // Published for the same reason the plain listener's is: this page is
      // HTTP and answers 200 whether or not 636 was available, so there is
      // otherwise no way to tell LDAPS being offered from LDAPS having lost the
      // port to something else.
      listening: tlsListening,
      error: tlsListenError,
      // Not a gap that was overlooked: StartTLS is an extended operation and
      // ldapjs implements none, and this repository does not patch that
      // submodule. LDAPS is also the one of the pair no RFC defines — RFC 4513
      // standardised StartTLS and left ldaps:// as the de-facto scheme.
      startTls: false,
      clientCertificates: 'never requested. This listener proves the SERVER ' +
        'to the client and nothing more; a client certificate offered to it ' +
        'is not asked for and would not be a login if it were. The HTTPS ' +
        'listeners on ' + tlsPorts.tls + ' and ' + tlsPorts.mtls + ' are ' +
        'where client certificates are the whole subject.',
      certificate: {
        subject: serverCertificate ? serverCertificate.subject : '',
        names: serverCertificate ? serverCertificate.names : [],
        fingerprint256: serverCertificate ? serverCertificate.fingerprint256 : '',
        notAfter: serverCertificate ? serverCertificate.notAfter : '',
        source: 'the same certificate and key the HTTPS listeners on ' +
          tlsPorts.tls + ' and ' + tlsPorts.mtls + ' serve. It is self-signed ' +
          'and regenerated on every start, so trust it per run rather than ' +
          'once: GET /tls/server-certificate hands it out in PEM. One anchor ' +
          'for all three sockets is why they share it.'
      }
    },
    autoCreateUsers: autocreateUsers(),
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
      maxEntries: maxEntries(),
      maxSearchResults: maxSearchResults(),
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
    ['LDAPS URL', info.tls.ldaps
      ? info.tls.url
      : 'not offered — ' + (info.tls.error || 'no reason was recorded')],
    ['Base DN', info.baseDn],
    ['People', info.usersDn],
    ['Groups', info.groupsDn],
    ['Protocol version', 'LDAPv3'],
    ['Transport', 'plain TCP on ' + info.port + ', and LDAPS — TLS from the ' +
      'first byte — on ' + (info.tls.port || LDAPS_PORT) + '. There is no ' +
      'StartTLS: it is an extended operation and this library implements none.'],
    ['Entries right now', String(info.limits.currentEntries)],
    ['Listener', info.listening
      ? 'up on TCP ' + info.port
      : 'DOWN — ' + (info.listenError || 'it never bound') +
        '. This page is HTTP and answers either way; the directory does not.'],
    ['LDAPS listener', info.tls.listening
      ? 'up on TCP ' + info.tls.port
      : 'DOWN — ' + (info.tls.error || 'it never bound') +
        '. The two sockets are independent, so this says nothing about the ' +
        'one above.'],
    ['An entry per authenticated user', info.autoCreateUsers ? 'on' : 'off']
  ].map(function (pair) {
    return '<tr><td>' + xmlEscape(pair[0]) + '</td><td><code>' +
      xmlEscape(pair[1]) + '</code></td></tr>';
  }).join('');
  const inner = '<h1>An LDAP directory lives here</h1>' +
    '<p class="sub">LDAPv3 over TCP ' + LDAP_PORT + ', and over TLS on ' +
    LDAPS_PORT + ', RFC 4511. A browser cannot speak it &mdash; the ' +
    'debugger&rsquo;s api opens the socket.</p>' +
    '<table><tr><th>Thing</th><th>Value</th></tr>' + rows + '</table>' +
    '<h2>It authenticates nobody</h2>' +
    '<p>' + xmlEscape(info.bindPolicy) + '.</p>' +
    '<h2>LDAPS, and what it does not change</h2>' +
    '<p>Port ' + (info.tls.port || LDAPS_PORT) + ' is the same directory over ' +
    'TLS &mdash; the same entries, the same handlers, the same every-bind-' +
    'succeeds. What TLS adds is that the password is not on the wire in the ' +
    'clear; it does not make it <em>checked</em>. The certificate is ' +
    '<strong>the one the HTTPS listeners serve</strong>: ' +
    '<code>' + xmlEscape(info.tls.certificate.subject) + '</code>, SHA-256 ' +
    '<code>' + xmlEscape(info.tls.certificate.fingerprint256) + '</code>, ' +
    'self-signed and regenerated on every start. Fetch it from ' +
    '<a href="/tls/server-certificate">/tls/server-certificate</a> and put it ' +
    'in your truststore &mdash; <code>LDAPTLS_REQCERT=never</code> is the ' +
    'habit this endpoint exists to avoid, and it would also hide the one ' +
    'thing worth checking here.</p>' +
    '<p>' + xmlEscape(info.tls.clientCertificates) + ' There is no StartTLS: ' +
    'it is an extended operation (RFC 4511 &sect;4.14) and ldapjs implements ' +
    'none, and this service does not patch that submodule. LDAPS is the one ' +
    'of the two no RFC defines &mdash; RFC 4513 standardised StartTLS and ' +
    'left <code>ldaps://</code> as the de-facto scheme every client speaks ' +
    'anyway.</p>' +
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
  const whenPlain = new Promise(function (resolve, reject) {
    plainServer.listen(LDAP_PORT, '0.0.0.0', function () {
      const address = plainServer.address();
      boundPort = address ? address.port : LDAP_PORT;
      listening = true;
      listenError = '';
      log.info('ldap: listening on TCP ' + boundPort + ' with base DN ' +
               BASE_DN + '; ' + entries.size +
               ' entry/entries; GET /ldap describes it.');
      resolve({ port: boundPort, baseDn: BASE_DN });
    });
    plainServer.once('error', function (err) {
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
  // The LDAPS socket. This promise NEVER REJECTS, and that asymmetry is the
  // point: LDAPS is the second way in to a directory that already answers on
  // 389, so a failure to bind 636 must not turn into a rejected whenReady and
  // an "ldap: the directory could not start" in server.js for a directory that
  // started. It is recorded, logged, and published on GET /ldap — the same
  // treatment a failure on 389 gets, minus the rejection.
  const whenSecure = new Promise(function (resolve) {
    if (!secureServer) {
      // No certificate material. Already logged and recorded where that was
      // discovered; this only has to answer.
      resolve({ ldapsPort: null, ldapsListening: false,
                ldapsError: tlsListenError });
      return;
    }
    secureServer.listen(LDAPS_PORT, '0.0.0.0', function () {
      const address = secureServer.address();
      boundTlsPort = address ? address.port : LDAPS_PORT;
      tlsListening = true;
      tlsListenError = '';
      log.info('ldap: LDAPS is listening on TCP ' + boundTlsPort +
               ', serving the same certificate as the HTTPS listeners (' +
               serverCertificate.subject + ', SHA-256 ' +
               serverCertificate.fingerprint256 + '). It is self-signed and ' +
               'regenerated on every start, so fetch it from ' +
               '/tls/server-certificate and trust it rather than turning ' +
               'verification off.');
      resolve({ ldapsPort: boundTlsPort, ldapsListening: true,
                ldapsError: '' });
    });
    secureServer.once('error', function (err) {
      // 636 is privileged for exactly the same reason 389 is, so the two ways
      // this fails are the same two: not root, or something else already owns
      // the port. Resolved rather than rejected — see above.
      tlsListening = false;
      tlsListenError = err.message + (err.code ? ' (' + err.code + ')' : '');
      log.error('ldap: could not bind TCP ' + LDAPS_PORT + ' for LDAPS: ' +
                tlsListenError + '. The plain listener and everything else in ' +
                'this service are unaffected; set LDAPS_PORT to a free, ' +
                'unprivileged port for a host run.');
      resolve({ ldapsPort: null, ldapsListening: false,
                ldapsError: tlsListenError });
    });
  });
  // Merged rather than returned as a pair, so that the caller in server.js
  // keeps reading `ready.port` and `ready.baseDn` as it always did and finds
  // the LDAPS fields beside them.
  const whenReady = Promise.all([whenPlain, whenSecure]).then(function (both) {
    return Object.assign({}, both[0], both[1]);
  });
  log.debug('Leaving listen().');
  return { server: plainServer, secureServer: secureServer,
           whenReady: whenReady };
}

function close() {
  log.debug('Entering close().');
  servers.forEach(function (one) {
    try {
      one.close();
    } catch (e) {
      // Closing a listener that never bound throws, and there is nothing useful
      // to do about it: this exists for tests and for an orderly shutdown. It
      // matters more with two listeners than it did with one — 636 is
      // privileged and often never bound at all, and an unguarded close there
      // would take the plain listener down with it.
      log.debug('close(): ' + e.message);
    }
  });
  listening = false;
  tlsListening = false;
  log.debug('Leaving close().');
}

module.exports = {
  listen: listen,
  close: close,
  LDAP_PORT: LDAP_PORT,
  LDAPS_PORT: LDAPS_PORT,
  BASE_DN: BASE_DN,
  USERS_DN: USERS_DN,
  GROUPS_DN: GROUPS_DN,
  autocreateUsers: autocreateUsers,
  REFUSED_PASSWORD: REFUSED_PASSWORD,
  maxEntries: maxEntries,
  maxSearchResults: maxSearchResults,
  entries: entries,
  autoCreateUser: autoCreateUser,
  objectFor: objectFor,
  groupsFor: groupsFor
};
