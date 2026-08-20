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

// For one thing only: the short, stable uid a DID-named entry is placed at.
// See didPlan().
const crypto = require('crypto');
const ldap = require('ldapjs');
const app = require('./app');
const { log, xmlEscape } = require('./helpers');
const config = require('./config');
const stats = require('./admin_stats');
// The application registry. This module is its STORE — see the applications
// section below — so the dependency runs both ways in the shape rule 6
// describes: a plain require here for the schema and the two conversions, and
// an inverted slot filled at the bottom of this file for the four functions
// that read and write the container.
const applications = require('./applications');
// The audit log. A plain require and it cannot become anything else: audit.js
// requires helpers.js and config.js only, so it can be reached from the deepest
// module here without dragging a graph behind it.
//
// This is the module with the MOST recording sites in the service — one per LDAP
// operation, seven of them — and unlike the HTTP call log there is no single
// funnel to put them behind: ldapjs dispatches straight into the handler for
// each operation, and what an audit row has to say differs per operation (a
// modify names its changed attributes, a search names how many entries came
// back). What IS written once is the rule that decides whether an add is a
// user, a group or something else, and that lives in audit.directoryActionFor()
// rather than being spelled out at four of the seven.
const audit = require('./audit');
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

// The groups claim: which directory groups reach an access token, an ID Token
// and both SAML assertions. A plain require for exactly the reasons above —
// it is a LIBRARY (it registers no route, so it cannot reorder /sts-metadata)
// and it requires helpers.js, config.js and admin_stats.js, none of which
// requires this file. The traffic in the other direction, groupsOfUser(), goes
// through its setDirectory() slot further down, because THAT module must not
// require this one: it is read from admin_stats.js's resolver, which every
// issuance site reaches long before the directory's routes should exist.
const groupClaims = require('./group_claims');

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
// The third container, and the one whose entries are a REGISTRY rather than a
// description of one. See the applications section further down.
const APPLICATIONS_DN = 'ou=applications,' + BASE_DN;

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
// How many entries may live under ou=applications. A directory limit, so it
// REFUSES rather than evicting: the applications container is the source of
// truth for what this service knows about a client, and a store that quietly
// dropped the oldest entry to make room would be the worst possible one. Read
// per call, like every other runtime setting.
function maxApplications() {
  return config.value('applications.max');
}

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

// ---------------------------------------------------------------------------
// TWO LISTS OF SPELLINGS, AND THE SPLIT IS WHO DEFINED THE NAME.
//
// `STANDARD_NAMES` are attribute types somebody else defined and published; the
// specification is named above each group. `OWN_NAMES` are this service's own
// inventions, here for the display and NOT to suggest they are standard — the
// comments on those groups say so individually, because that distinction is the
// one a reader of a mock most needs and the one a table like this most easily
// blurs.
//
// Both are written as THE CANONICAL SPELLING ALONE, with the lower-cased lookup
// key derived from it. This used to be a map of `lower: 'Mixed'` pairs, and the
// trouble with that shape is that a typo in the KEY is invisible: the entry
// simply never matches, the name renders lower-cased, and that is exactly the
// symptom this table exists to prevent — so it would be failing silently at the
// only job it has. `toLowerCase()` cannot disagree with itself. It is also the
// shape `vc_claims.js` already derives its own table in, which is why merging
// the two costs nothing.
//
// WHY THE STANDARD SET IS LONG, when this service writes perhaps thirty of
// them. The directory is SCHEMALESS on purpose: a client can `add` any attribute
// it likes to any entry, and two of the families here write entries nobody
// typed — a TLS client certificate's subject becomes attributes RDN by RDN, so
// whichever types are in that subject arrive whether or not this service has
// ever heard of them. A table holding only what this service happens to write
// would be right about its own entries and wrong about everybody else's, which
// is worse than having none: the reader who most needs the conventional spelling
// is the one looking at an attribute this service did not write. `seeAlso` is
// what made the point — a perfectly ordinary RFC 4519 type, rendering as
// `seealso` on the one page whose job is to show an entry faithfully.
//
// WHAT IS NOT HERE. No spelling is invented for a name nobody published. Where
// two specifications disagree about the capitalisation of one name the older
// registered one wins and the disagreement is noted, because picking silently is
// how a table like this becomes a third opinion.
// ---------------------------------------------------------------------------
const STANDARD_NAMES = [
  // RFC 4519 — the standard directory attribute types, in full. `name` is in
  // here because it is a real type (section 2.18): the supertype cn, sn, ou and
  // the rest derive from, which a client may perfectly well ask for by name.
  'businessCategory', 'c', 'cn', 'dc', 'description', 'destinationIndicator',
  'distinguishedName', 'dnQualifier', 'enhancedSearchGuide',
  'facsimileTelephoneNumber', 'generationQualifier', 'givenName',
  'houseIdentifier', 'initials', 'internationalISDNNumber', 'l', 'member',
  'name', 'o', 'ou', 'owner', 'physicalDeliveryOfficeName', 'postalAddress',
  'postalCode', 'postOfficeBox', 'preferredDeliveryMethod', 'registeredAddress',
  'roleOccupant', 'searchGuide', 'seeAlso', 'serialNumber', 'sn', 'st',
  'street', 'telephoneNumber', 'teletexTerminalIdentifier', 'telexNumber',
  'title', 'uid', 'uniqueMember', 'userPassword', 'x121Address',
  // RFC 4519 section 2.40 spells this with a lower-case x, and RFC 2798's
  // inetOrgPerson definition spells the same type `x500uniqueIdentifier`. The
  // registered directory-schema spelling wins here; the two differ only in a
  // letter LDAP does not distinguish anyway, so nothing matches differently —
  // one of them just has to be chosen for the display.
  'x500UniqueIdentifier',

  // RFC 4524 — COSINE. The types still in ordinary use; the specification also
  // carries a dozen marked obsolete or historic (janetMailbox, dITRedirect,
  // the three *Quality types) and those are deliberately left out rather than
  // listed, since publishing a spelling suggests the name is worth writing.
  'associatedDomain', 'associatedName', 'buildingName', 'co', 'documentAuthor',
  'documentIdentifier', 'documentLocation', 'documentPublisher',
  'documentTitle', 'documentVersion', 'drink', 'homePhone', 'homePostalAddress',
  'host', 'info', 'mail', 'manager', 'organizationalStatus', 'otherMailbox',
  'personalTitle', 'roomNumber', 'secretary', 'uniqueIdentifier', 'userClass',

  // RFC 2798 — inetOrgPerson, which is the class most of the people in this
  // directory would carry in a real one. `labeledURI` is RFC 2079's rather than
  // this one's; it is grouped here because inetOrgPerson is where it is met.
  'audio', 'carLicense', 'departmentNumber', 'displayName', 'employeeNumber',
  'employeeType', 'jpegPhoto', 'labeledURI', 'mobile', 'pager', 'photo',
  'preferredLanguage', 'userCertificate', 'userPKCS12', 'userSMIMECertificate',

  // RFC 2307 — NIS. `memberUid` is the one that earns its place beyond the
  // display: it holds a BARE USER NAME where member and uniqueMember hold a DN,
  // which is why /admin/groups resolves it differently — see MEMBER_ATTRIBUTES.
  'bootFile', 'bootParameter', 'gecos', 'gidNumber', 'homeDirectory',
  'ipHostNumber', 'ipNetmaskNumber', 'ipNetworkNumber', 'ipProtocolNumber',
  'ipServicePort', 'ipServiceProtocol', 'loginShell', 'macAddress',
  'memberNisNetgroup', 'memberUid', 'nisMapEntry', 'nisMapName',
  'nisNetgroupTriple', 'oncRpcNumber', 'shadowExpire', 'shadowFlag',
  'shadowInactive', 'shadowLastChange', 'shadowMax', 'shadowMin',
  'shadowWarning', 'uidNumber',

  // RFC 4512 — the object class attribute, the operational attributes every
  // entry has, and the subschema ones. A SEARCH withholds the operational ones
  // unless they are asked for by name (section 4.5.1.8) and toSearchEntry()
  // honours that; being withheld is no reason to be unable to spell them, since
  // asking for one by name is exactly when a client sees it.
  'aliasedObjectName', 'attributeTypes', 'createTimestamp', 'creatorsName',
  'dITContentRules', 'dITStructureRules', 'governingStructureRule',
  'ldapSyntaxes', 'matchingRules', 'matchingRuleUse', 'modifiersName',
  'modifyTimestamp', 'nameForms', 'objectClass', 'objectClasses',
  'structuralObjectClass', 'subschemaSubentry',

  // RFC 4512 again — the root DSE's own attributes (section 5.1), plus the two
  // vendor ones from RFC 3045. They are here for the same reason as the rest: a
  // client showing `namingcontexts` where every document says `namingContexts`
  // looks like the client is broken.
  'altServer', 'namingContexts', 'supportedControl', 'supportedExtension',
  'supportedFeatures', 'supportedLDAPVersion', 'supportedSASLMechanisms',
  'vendorName', 'vendorVersion',

  // RFC 5020 and RFC 4530 — the two operational attributes that name an entry
  // rather than describe it. `entryDN` is load-bearing beyond the display: it is
  // what matchable() calls the DN when a filter matches on it, and what
  // applicationObject() publishes the DN as, so those two and this table have to
  // agree or an ldapsearch filter and a console page name one fact two things.
  'entryDN', 'entryUUID',

  // PKCS#9, and it arrives on this directory inside a certificate subject —
  // certificatePlan() turns every RDN of a verified client certificate's subject
  // into an attribute, so which types turn up is decided by whoever issued the
  // certificate and not by anything here.
  'emailAddress',

  // NOT REGISTERED ANYWHERE, and here anyway. `memberOf` is the reverse of
  // group membership as Active Directory and most directories in the wild
  // implement it, and it has never been standardised — draft-ietf-ldapext-memberof
  // expired. It cannot go in this service's own list either, because this
  // service did not invent it: a client writes it, and /admin/groups reports the
  // disagreement when an entry's own memberOf names a group that does not list
  // it back. NOTHING HERE MAINTAINS IT — that page says so, and the spelling
  // being conventional must not be read as the attribute being managed.
  'memberOf'
];

// ---------------------------------------------------------------------------
// This service's own names. Not standard, and listed here for the display only.
// Each group says why nothing standard was used instead, because "we invented an
// attribute type" is a claim that needs one.
// ---------------------------------------------------------------------------
const OWN_NAMES = [
  // On the entries a TLS client certificate seeds. There is no standard
  // attribute type for "the DN inside the certificate", and the standard one
  // that does exist — `userCertificate`, which is binary — is not what these
  // are; certificatePlan() says the rest.
  'x509subject', 'x509issuer', 'x509serialNumber', 'x509notBefore',
  'x509notAfter', 'x509fingerprint256',

  // On the entries a DECENTRALIZED IDENTIFIER seeds, and load-bearing rather
  // than decorative: the entry is NAMED by a hash of the DID (didPlan() says
  // why), so `didSubject` is the only place the identifier itself survives and
  // the only thing locateEntry() can find the entry by. There is no standard
  // attribute type for "the DID this entry is", which is unsurprising — DID Core
  // postdates the LDAP schema documents by two decades and nobody registered
  // one.
  'didSubject', 'didMethod',

  // On any entry whose person authenticated somewhere that STATES how they did
  // it — which today is the sign-in screen and nothing else, because amr is an
  // OIDC vocabulary and a Kerberos AS-REQ has nothing to put in it. There is no
  // standard attribute type for "this account authenticated with more than one
  // factor": the nearest things in the wild are Active Directory's msDS-*
  // attributes, which are Microsoft's own names for something else entirely, and
  // pretending to be one of those would be worse than obviously not being one.
  'authnMethod', 'mfaAuthenticated', 'mfaLastAuthTime'
];

// The table itself, built from the two lists. `learnName()` is the ONE way in,
// so the disagreement check below cannot be bypassed by a later merge — and
// there are three of those.
const CANONICAL_NAMES = {};

// A name is learnt once. A SECOND spelling of the same name is a real defect and
// is reported rather than silently resolved: the two lists here, the credential
// claim catalogue and the applications schema are four independently maintained
// sets of spellings, and "whichever was merged first wins" is how one of them
// comes to be quietly wrong about `schacDateOfBirth` while all four look right
// read alone. Reported and not thrown, because a table of how to CAPITALISE a
// name must never be able to stop this service starting.
function learnName(spelling, source) {
  const canonical = String(spelling);
  const lower = canonical.toLowerCase();
  const known = CANONICAL_NAMES[lower];
  if (known === undefined) {
    CANONICAL_NAMES[lower] = canonical;
    return;
  }
  if (known !== canonical) {
    log.warn('ldap: two spellings of the attribute type "' + lower + '" — "' + known +
             '" is already known and ' + source + ' says "' + canonical + '". Keeping "' +
             known + '". They match identically either way (RFC 4512 section 2.5 makes ' +
             'attribute descriptions case-insensitive) so nothing is found or missed ' +
             'differently; it is only the spelling shown on a page, and one of the two ' +
             'lists is wrong.');
  }
}

STANDARD_NAMES.forEach(function (spelling) { learnName(spelling, 'the standard list'); });
OWN_NAMES.forEach(function (spelling) { learnName(spelling, "this service's own list"); });

// The attribute types /admin/vc can put on a person so that a credential has
// something to carry. They are MERGED rather than typed out a second time: that
// catalogue already spells each one the way its schema document spells it
// (`schacDateOfBirth`, `labeledURI`, `departmentNumber`), and two lists of
// spellings is one list that will eventually be wrong. Through learnName(), so
// that a catalogue disagreeing with the standard list above is REPORTED rather
// than resolved by merge order — several of its rows are RFC 4519 and RFC 2798
// types this file now spells itself, and those two lists agreeing is a thing to
// find out about rather than to assume.
Object.keys(vcClaims.CANONICAL_NAMES).forEach(function (lower) {
  learnName(vcClaims.CANONICAL_NAMES[lower], 'the credential claim catalogue');
});

// And the applications registry's, for the same reason and from the same kind of
// source: `applications.js` owns that schema and spells every attribute the way
// `/ldap/applications` publishes it — `oauthClientId`, `appRegistrationJson`,
// `samlEntityId`. Without this merge every applications page and every reply from
// the management API showed `oauthclientid` beside a published schema that says
// `oauthClientId`, which reads as a bug in the page rather than as what it is:
// the store lower-casing a name because @ldapjs/attribute does.
//
// FIRST SPELLING WINS, and that matters here more than above. That schema
// carries `cn` and `description`, which the standard list at the top of this
// file already spells; a merge that overwrote would let the registry's table
// decide how a standard attribute looks on a PERSON's entry too, since there is
// one map for the whole directory. Both spell those two the same way, so the
// check stays quiet — which is the point of having it rather than assuming.
applications.SCHEMA.attributes.forEach(function (row) {
  learnName(row.name, 'the applications schema');
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
  putEntry(APPLICATIONS_DN, {
    objectClass: ['top', 'organizationalUnit'],
    ou: 'applications',
    description: 'Applications: the OAuth clients, OpenID Connect relying ' +
      'parties, SAML service providers, WS-Federation applications, WS-Trust ' +
      'relying parties, OpenID4VP verifiers and Kerberos services this ' +
      'service has been asked about. THIS CONTAINER IS THE REGISTRY — it is ' +
      'not a copy of one kept elsewhere — so an ldapmodify here changes what ' +
      'the protocol endpoints do. applications.js holds the schema; GET ' +
      '/ldap/applications publishes it.'
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

// And is it a DECENTRALIZED IDENTIFIER? A third shape of identity, arriving from
// the Decentralized Identity endpoints — an ldp_vc's `did:jwk:…` subject, whatever
// DID the OID4VP Verifier was shown, the one /did/generate mints. Like DN_SHAPED
// this is deliberately not shared with admin_stats.js's identical-looking test:
// that one decides whether to split an identity at an '@', this one decides where
// an entry goes, and one knob turning both would couple two decisions that only
// look alike.
const DID_SHAPED = /^did:[a-z0-9]+:/i;

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
// WHERE A NAME'S ENTRY GOES, which is the easy one and the shape every other
// protocol here produces: `uid=<name>,ou=users`.
//
// The invented person behind the name is what the entry gets — where it used to
// get `dave`, `Mock` and `dave@sts-mock.example`, one string three times over.
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
// ---------------------------------------------------------------------------
function namePlan(name) {
  log.debug('Entering namePlan(). name=' + name);
  const persona = vcClaims.personaFor(name);
  log.debug('Leaving namePlan().');
  return {
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
}

// ---------------------------------------------------------------------------
// WHERE A DECENTRALIZED IDENTIFIER'S ENTRY GOES, which is the second placement
// decision in this module with no obviously right answer — and it is the
// OPPOSITE problem from a certificate's.
//
// A certificate subject is already a DN and needs a PLACE. A DID is neither a DN
// nor a name: it is one long opaque string, and the two obvious things to do
// with it are both wrong in a way worth writing down.
//
//   * `uid=<the did>,ou=users` verbatim. Correct, and unusable: a did:jwk
//     carries a base64url-encoded JWK, so the DN runs to several hundred
//     characters and every page, every log line and every ldapsearch output
//     naming this person is mostly key material.
//   * A container of its own, `ou=dids`. Tidy, and it would put these people
//     outside the two sweeps that matter: populateVcAttributes() walks ou=users,
//     and /admin/groups reports membership from there. A DID subject that no
//     credential claim reaches is a DID subject this service cannot issue a
//     credential about, which is the one thing it exists to do.
//
// So the entry goes under ou=users with everybody else and is NAMED by a short,
// stable digest of the DID — `uid=did-<12 hex>` — with the identifier itself
// kept whole on the entry as `didSubject`. Twelve hex characters is 48 bits; at
// the few thousand entries maxEntries() allows, a collision is not a risk worth
// a longer name for.
//
// What that costs is one thing and it is worth saying plainly: THE UID IS NOT
// THE IDENTITY. Everywhere else here `uid` is what the person typed and what
// /admin/users files them under; on these entries it is a name this service made
// up. `didSubject` is the identity — locateEntry() finds the entry by it, and
// personaKeyOf() invents the person FROM it, so the startup sweep and the
// authentication path seed one invented person rather than two.
// ---------------------------------------------------------------------------
function didUid(did) {
  return 'did-' + crypto.createHash('sha256').update(String(did), 'utf8')
    .digest('hex').slice(0, 12);
}

function didPlan(info) {
  log.debug('Entering didPlan().');
  const did = String(info.key || '').trim();
  // The method name — `jwk`, `web`, `key`. Kept because it is the one fact about
  // a DID that is readable without resolving it, so "which methods has this
  // service seen" becomes an ordinary filter on /ldap/directory rather than a
  // question nobody can ask.
  const method = (did.split(':')[1] || '').toLowerCase();
  const persona = vcClaims.personaFor(did);
  const uid = didUid(did);
  // The description says how this entry came to exist, and for a DID the default
  // — "authenticated through X" — would be the wrong sentence in both halves:
  // nobody typed a password, and at /did/generate nobody presented anything at
  // all. So this plan carries its own.
  const note = 'named by a decentralized identifier presented through ' +
    String(info.protocol || 'an unstated protocol') +
    (info.method ? ' (' + info.method + ')' : '');
  log.debug('Leaving didPlan(). uid=' + uid + ' for ' + did.slice(0, 48));
  // Nothing to merge onto an entry that already exists. Unlike a certificate,
  // which is reissued with a new serial and a new validity for the same person,
  // a DID presented a second time is byte-for-byte the DID that named this entry
  // in the first place.
  return {
    dn: 'uid=' + escapeDnValue(uid) + ',' + USERS_DN,
    attributes: {
      objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
      uid: uid,
      cn: persona.display,
      sn: persona.family,
      givenName: persona.given,
      // Marked (DID) rather than (mock). Every value on every entry here is
      // invented, and what this one needs to say first is the thing that is
      // different about it: the person is named by a decentralized identifier
      // and not by anything anybody typed.
      displayName: persona.display + ' (DID)',
      mail: persona.email,
      didSubject: did,
      didMethod: method
    },
    merge: {},
    note: note
  };
}

// ---------------------------------------------------------------------------
// HOW SOMEBODY AUTHENTICATED, WRITTEN ONTO THE ENTRY THEY ALREADY HAVE.
//
// The case this exists for is WebAuthn, which is TWO things on one screen and
// must not become one thing in the directory:
//
//   * used as a SECOND FACTOR, after a password, it authenticates nobody new.
//     The person is the one the password step named, their entry is the one
//     that already exists (or the one autoCreateUser() is creating on this same
//     pass), and what the key adds is the FACT that a second factor was used.
//     That fact is a flag here — `mfaAuthenticated: TRUE` — and not an entry.
//   * used as the PRIMARY credential, passwordless, it is an authentication in
//     its own right and the entry is created for it exactly as a password
//     sign-in's is. Nothing special is needed for that: it reaches
//     recordAuthentication() like every other accepted credential, so
//     autoCreateUser() runs and namePlan() puts `uid=<name>,ou=users` there.
//     What this function then records is that the single factor was a key —
//     `authnMethod: hwk` with no `pwd` beside it — which is the only place a
//     reader can tell a passwordless sign-in from a password one afterwards.
//
// Three attributes, and each answers a different question. They are separate
// because merging them loses one of the three:
//
//   authnMethod        every RFC 8176 method this person has EVER used here,
//                      accumulated. Appended, so `pwd` and `hwk` both survive.
//   mfaAuthenticated   TRUE or FALSE for the MOST RECENT authentication, so it
//                      is overwritten rather than appended. A person who used a
//                      key yesterday and a password today reads FALSE, which is
//                      the honest answer to "did they just use two factors".
//   mfaLastAuthTime    when multi-factor last happened, and it is never cleared
//                      — that is the history the flag above deliberately does
//                      not keep.
//
// Two rules hold it up:
//
//   * NOTHING IS WRITTEN WHERE NOTHING WAS STATED. Most families here set no
//     amr at all — a Kerberos AS-REQ, a WS-Trust UsernameToken and an LDAP bind
//     have nothing to say in that vocabulary — and an absent attribute is the
//     honest answer for them. Writing `mfaAuthenticated: FALSE` on everybody
//     would turn "this service has never been told" into "this service checked
//     and it was one factor", which are not the same claim.
//   * TWO FACTORS MEANS TWO. `amr` with a single member is one factor whatever
//     that member is, so a passwordless `["hwk"]` is FALSE. acr is honoured as
//     well because it is what a relying party actually reads, and the two are
//     set together by the one caller that sets either.
//
// A GROUP GRANTS NOTHING here and neither does this: no endpoint reads these
// attributes, no token carries them, and nothing decides anything on them. They
// are a record of what happened, on the page an LDAP client can see it from.
// ---------------------------------------------------------------------------
function applyAuthenticationFactors(stored, info) {
  log.debug('Entering applyAuthenticationFactors(). dn=' + (stored && stored.dn));
  if (!stored) {
    log.debug('Leaving applyAuthenticationFactors(). There is no entry.');
    return false;
  }
  const amr = (Array.isArray(info.amr) ? info.amr : []).map(function (value) {
    return String(value || '').trim();
  }).filter(function (value) {
    return value !== '';
  });
  const acr = String(info.acr || '').trim();
  if (!amr.length && !acr) {
    log.debug('Leaving applyAuthenticationFactors(). This protocol states no ' +
              'authentication method, so nothing is written.');
    return false;
  }
  let changed = addValues(stored, 'authnMethod', amr);
  // More than one factor, or a caller that said so outright. `mfa` is the acr
  // this service's own sign-in screen sets; the comparison is lower-cased
  // because acr is an opaque string to everybody except whoever minted it and
  // this is the one minter.
  const multiFactor = amr.length > 1 || acr.toLowerCase() === 'mfa';
  const flag = multiFactor ? 'TRUE' : 'FALSE';
  if ((stored.attributes.mfaauthenticated || [])[0] !== flag) {
    // Assigned rather than appended: an entry that accumulated one TRUE per
    // sign-in would be the visible symptom of a bug nobody could locate, which
    // is the same trap applyVcAttributes() writes its second rule about.
    stored.attributes.mfaauthenticated = [flag];
    changed = true;
  }
  if (multiFactor) {
    stored.attributes.mfalastauthtime = [generalizedTime()];
    changed = true;
  }
  if (!changed) {
    log.debug('Leaving applyAuthenticationFactors(). It already said this.');
    return false;
  }
  stored.attributes.modifytimestamp = [generalizedTime()];
  log.info('ldap: ' + stored.dn + ' records authentication with ' +
           (amr.length ? amr.join(', ') : acr) + '; mfaAuthenticated is ' + flag + '.');
  log.debug('Leaving applyAuthenticationFactors(). The entry was updated.');
  return true;
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
  // Three shapes of identity and one placement function each, chosen here and
  // decided there. A client CERTIFICATE identity is a DN (certificatePlan()); a
  // DECENTRALIZED IDENTIFIER is one long opaque string (didPlan()); everything
  // else is a name and becomes `uid=<name>,ou=users` (namePlan()).
  //
  // The order matters in one direction only: a certificate's identity is a
  // subject DN, so it is tested first and the DID test never sees it. Nothing
  // else here can be both — a DN begins `<attributetype>=` and a DID begins
  // `did:`.
  const plan = info.certificate
    ? certificatePlan(info)
    : (DID_SHAPED.test(name) ? didPlan(info) : namePlan(name));
  const dn = plan.dn;
  const existing = getEntry(dn);
  // What the entry's description says about why it exists. A plan may state its
  // own — didPlan() does, because "authenticated through W3C DID Core" would be
  // the wrong sentence for an identifier nobody signed in with.
  const note = plan.note || ('authenticated through ' + String(info.protocol || 'an ' +
    'unstated protocol'));
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
    // And how they authenticated this time, where the protocol says. This is
    // the whole of what a WebAuthn SECOND FACTOR adds to a directory: the
    // person already has this entry — the password step named them — so the
    // key writes a flag and creates nothing.
    if (applyAuthenticationFactors(existing, info)) {
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
  // Before the audit row below, so that the attributes it lists are the ones the
  // entry actually has. On a PASSWORDLESS WebAuthn sign-in this is what says the
  // single factor was a key rather than a password, on an entry that exists
  // because that sign-in was an authentication in its own right.
  applyAuthenticationFactors(created, info);
  log.info('ldap: created ' + dn + ' because ' + name + ' ' + note + '.');
  // A user created by the SERVICE rather than by a client, and the audit row
  // says so through `channel: 'internal'` — no LDAP client asked for this. It
  // is the one directory row with no connection behind it, which is why it does
  // not go through auditLdap(): there is no socket to read a bind DN off, and
  // the actor is the person who authenticated somewhere else entirely.
  //
  // It is recorded only on the branch that actually created something. The two
  // returns above are a directory that already had the entry and a directory
  // that is full, and neither created a user; a row on either would make
  // "when did uid=dave appear?" unanswerable, which is the whole question this
  // row exists for.
  audit.recordDirectory({
    action: 'user.create',
    actor: detail.key || '',
    actorForm: detail.presented || '',
    target: dn,
    protocol: detail.protocol || '',
    channel: 'internal',
    summary: 'created ' + dn + ' because ' + name + ' ' + note,
    detail: { reason: note,
              protocol: detail.protocol || '',
              method: detail.method || '',
              attributes: Object.keys(created.attributes).join(', '),
              entriesNow: entries.size,
              note: 'created by this service, not by an LDAP client; ' +
                    'ldap.autocreateUsers is on' }
  });
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
// which is every entry the sweep below walks. Four sources, in the order that
// keeps the sweep's values identical to the ones an authentication would have
// written: `didSubject` where there is one, because on those entries it is the
// identity and the uid is only a digest of it; then the uid, which is what
// namePlan() built the DN from and what /admin/users files the person under;
// then the CN, the fallback for a certificate-seeded entry, which has no uid;
// then the DN, which is the last resort and is at least stable.
function personaKeyOf(stored) {
  // The DID first, where there is one, and this line is load-bearing: on a
  // DID-named entry the uid is a DIGEST of the identity rather than the identity
  // (see didPlan()), so seeding from it would invent a SECOND person for
  // somebody the authentication path had already invented one for — and the two
  // would disagree on every attribute the sweep filled in.
  const did = (stored.attributes.didsubject || [])[0];
  if (did) return String(did);
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
// Finding it is three rules, because there are three shapes of identity here. A
// NAME is `uid=<name>,ou=users` and always was. A DN — which is what a TLS client
// certificate's identity is — is looked up by the subject the entry RECORDED,
// in `x509subject`, because that is exact and stays right if certificatePlan()'s
// naming rule ever changes; and where the subject lies inside this directory's
// own tree, the entry it names directly is the answer. A DECENTRALIZED
// IDENTIFIER is looked up the same way and for the same reason, by `didSubject`,
// which on those entries is the identity where the uid is only a digest of it.
// Failing all of that, the DN the matching plan WOULD have built is reported, so
// the page can say where the entry would have gone rather than naming a place
// nothing was ever going to be.
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
  // A DECENTRALIZED IDENTIFIER, which is the third shape and the one that CANNOT
  // be looked up by rebuilding its name and reading the store. It could — the
  // digest is deterministic — but doing it that way would make didPlan()'s naming
  // rule impossible to change without orphaning every entry already written under
  // the old one. So the entry is found by what it RECORDED, exactly as a
  // certificate's is, and didPlan() is consulted only to say where an entry
  // WOULD go when there is none.
  if (DID_SHAPED.test(key)) {
    let found = null;
    entries.forEach(function (entry) {
      if (found) {
        return;
      }
      if ((entry.attributes.didsubject || []).indexOf(key) >= 0) {
        found = entry;
      }
    });
    if (found) {
      log.debug('Leaving locateEntry(). Found by didSubject: ' + found.dn);
      return { dn: found.dn, stored: found };
    }
    const plan = didPlan({ key: key });
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
  // its subject above rather than by a name at all. Skipped for a DID for the
  // same reason and one more — the uid on a DID-named entry is a DIGEST of the
  // identity, so comparing the identity against it would find nothing even on
  // the entry that is this person's.
  const alsoNamed = [];
  if (key && !DN_SHAPED.test(key) && !DID_SHAPED.test(key)) {
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

// ---------------------------------------------------------------------------
// THE OTHER DIRECTION: WHICH GROUPS IS THIS PERSON IN?
//
// groupsFor() above answers "who is in this group", which is what a page asks.
// A CLAIM asks the inverse, once per token, about one person — so it is a
// different walk and not a filter over that one: groupsFor('') resolves every
// member of every group and builds the console's counts, which is most of a
// page's worth of work to answer one yes/no per group.
//
// It is here rather than in group_claims.js for the reason objectFor() and
// groupsFor() are here: WHAT COUNTS AS A GROUP is this module's decision (both
// rules — placement under ou=groups, or a group objectClass wherever it sits),
// and a second implementation over there would be the second definition that
// eventually disagrees. group_claims.js decides what to DO with the answer;
// this decides what the answer IS. Same split as oauth2_bcp.js and oauth2.js.
//
// THREE THINGS ARE LOAD-BEARING.
//
// **A member value is resolved exactly as resolveMember() resolves it**, which
// is why `holds` is read from MEMBER_ATTRIBUTES rather than assumed: `member`
// and `uniqueMember` hold a DN and `memberUid` holds a bare name. Treating
// them alike is how every posixGroup membership silently stops reaching a
// token, which is the same defect the console's member list was written to
// avoid.
//
// **AN ENTRY IS NOT REQUIRED.** The person is matched by the DN their identity
// resolves to, whether or not anything is stored there. A group that lists
// `uid=bob,ou=users` while bob has no entry is a DANGLING member from the
// group's side and is still the group SAYING bob is in it — and with
// ldap.autocreateUsers on, bob's entry appears at the moment he authenticates
// and a token is minted in the same breath. Requiring the entry would make the
// claim depend on the order of two things that happen together.
//
// **BOTH ANSWERS COME BACK AND NEITHER IS APPLIED HERE.** A group can name this
// person, or this person's own `memberOf` can name the group, and this
// directory maintains neither from the other — that disagreement is a thing
// /admin/groups exists to display and not a defect to paper over. So each row
// says HOW it was found, `via` for the group's own member attributes and
// `viaMemberOf` for the person's claim, and group_claims.js applies
// groups.claimFromMemberOf to decide which of them a token believes. A memberOf
// naming something that is not a group here is dropped: it would otherwise
// invent a group out of a string somebody typed.
// ---------------------------------------------------------------------------
function groupsOfUser(key) {
  log.debug('Entering groupsOfUser(). key=' + key);
  const wanted = String(key == null ? '' : key).trim();
  const out = { key: wanted, dn: '', entryFound: false, groups: [],
                baseDn: BASE_DN, groupsDn: GROUPS_DN };
  if (!wanted) {
    log.debug('Leaving groupsOfUser(). There was no identity to look up.');
    return out;
  }

  // The same three-shaped lookup every other reader here uses, so a name, a
  // certificate's subject DN and a decentralized identifier all land on the one
  // entry this service files that person under. Where nothing is stored, the DN
  // the matching plan WOULD have built comes back — which is exactly what the
  // dangling-member case above needs.
  const located = locateEntry(wanted);
  out.dn = located.dn;
  out.entryFound = !!located.stored;
  const personDn = normalizeDn(located.dn);

  // The person's own claim, normalised once rather than per group.
  const claimed = {};
  if (located.stored) {
    (located.stored.attributes.memberof || []).forEach(function (value) {
      claimed[normalizeDn(value)] = true;
    });
  }

  entries.forEach(function (entry) {
    const rule = groupRuleFor(entry);
    if (!rule) {
      return;
    }
    const via = [];
    MEMBER_ATTRIBUTES.forEach(function (attribute) {
      const listed = (entry.attributes[attribute.name] || []).some(function (value) {
        const raw = String(value == null ? '' : value);
        const dn = attribute.holds === 'uid' ? 'uid=' + raw + ',' + USERS_DN : raw;
        return normalizeDn(dn) === personDn;
      });
      if (listed) {
        via.push(canonicalName(attribute.name));
      }
    });
    const viaMemberOf = !!claimed[normalizeDn(entry.dn)];
    if (!via.length && !viaMemberOf) {
      return;
    }
    out.groups.push({
      dn: entry.dn,
      // The same two sources groupsFor() uses and in the same order, so the cn
      // in a token is the cn on the page. An entry under ou=groups with no cn
      // still has a name — its RDN — and a group with no name in a claim would
      // be an empty string in a list.
      cn: (entry.attributes.cn || [])[0] || commonNameOf(entry.dn),
      rule: rule,
      via: via,
      viaMemberOf: viaMemberOf
    });
  });

  out.groups.sort(function (a, b) {
    return normalizeDn(a.dn) < normalizeDn(b.dn) ? -1 : 1;
  });
  log.debug('Leaving groupsOfUser(). ' + located.dn + ' is in ' +
            out.groups.length + ' group(s).');
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

// The FIFTH, and it is the same shape as the fourth: a module this file also
// requires outright, calling back into one function here through a slot because
// IT must not require THIS module. group_claims.js is reached from
// admin_stats.js's resolver, which every token and both assertion builders go
// through — so a require from there would drag this directory's routes ahead of
// almost the whole router. Guarded like the four above: an older
// group_claims.js without the slot costs a warning, not a service that will not
// start.
//
// What crosses is deliberately ONE function and not the membership rules
// themselves. What counts as a group, and how a member value is resolved, are
// decisions of this module (see groupsOfUser()); which of its two answers a
// token believes, and what the claim is called, are that module's.
if (typeof groupClaims.setDirectory === 'function') {
  groupClaims.setDirectory({ groupsOfUser: groupsOfUser });
} else {
  log.warn('ldap: group_claims.js offers no setDirectory(), so no token or ' +
           'assertion will carry a groups claim. The directory itself is ' +
           'unaffected.');
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

// ---------------------------------------------------------------------------
// THE AUDIT ROW EVERY OPERATION BELOW WRITES.
//
// Two facts are worked out here rather than at each of the seven handlers,
// because both are about the CONNECTION rather than about the operation and
// getting either wrong at one handler out of seven is the kind of thing nobody
// notices:
//
// **Which socket it came in on.** The plain listener on 389 and LDAPS on 636
// share one set of handlers — that is the whole point of the fan-out this file
// registers against — so a handler cannot tell them apart, and a page that could
// not either would be unable to answer the question somebody turning on LDAPS
// actually has, which is whether anything is using it. `req.connection` is the
// raw socket and a TLS one carries `encrypted`.
//
// **Who is bound.** ldapjs holds the bound DN on the connection, which is what
// makes an operation attributable at all: the bind names somebody and the six
// operations after it do not. The DN is recorded whole in `actorForm`, and
// `actor` is the console's key for that person where the DN yields one, so a
// directory row and a /admin/users row name one person rather than two.
// consoleKeyFor() is the same derivation the groups page links with, reused
// rather than repeated — a second copy would be a second thing to keep in step
// with autoCreateUser().
//
// Note what is NOT here: the client's address. See the note on the console page
// — on a mock behind a compose bridge it reports the bridge, which is a fact
// about docker and not about whoever made the call.
// ---------------------------------------------------------------------------
function ldapChannelOf(req) {
  return (req.connection && req.connection.encrypted) ? 'ldaps' : 'ldap';
}

function boundDnOf(req) {
  const bound = req.connection && req.connection.ldap && req.connection.ldap.bindDN;
  if (!bound) return '';
  const text = String(bound);
  // ldapjs seeds an unbound connection with `cn=anonymous` rather than leaving
  // it empty, and reporting that as an identity would put a person called
  // "anonymous" on the users page. It is the absence of a bind, so it is
  // reported as one.
  return text.toLowerCase() === 'cn=anonymous' ? '' : text;
}

// How many entries still list this DN as a member, counted just before it is
// deleted. It is the single most useful fact on a delete row: this directory
// does not enforce referential integrity (see the header — that is a decision),
// so every one of those becomes a DANGLING member the moment the entry goes,
// and this is the only record of when that happened. /admin/groups shows the
// resulting state and can never say when it arrived.
//
// All three membership attributes are counted, resolved the way MEMBER_ATTRIBUTES
// says: `memberUid` holds a bare name where `member` and `uniqueMember` hold a
// DN, and counting the three alike is exactly how every posixGroup member gets
// missed.
function membershipsNaming(dn) {
  const key = normalizeDn(dn);
  const uid = (splitRdns(dn)[0] || '').toLowerCase().indexOf('uid=') === 0
    ? unescapeDnValue(rdnPairs(splitRdns(dn)[0])[0].value) : '';
  let count = 0;
  entries.forEach(function (entry) {
    const names = MEMBER_ATTRIBUTES.some(function (attribute) {
      return (entry.attributes[attribute.name] || []).some(function (value) {
        return attribute.holds === 'uid'
          ? (uid && String(value).toLowerCase() === uid.toLowerCase())
          : normalizeDn(value) === key;
      });
    });
    if (names) count++;
  });
  return count;
}

function auditLdap(req, fields) {
  const boundDn = boundDnOf(req);
  audit.recordDirectory(Object.assign({
    channel: ldapChannelOf(req),
    protocol: ldapChannelOf(req) === 'ldaps' ? 'LDAPS' : 'LDAP',
    actor: boundDn ? consoleKeyFor(boundDn, getEntry(boundDn)) : '',
    actorForm: boundDn
  }, fields));
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
    // The refusal is recorded, and it is the one audit row in this file with no
    // successful operation behind it. That is the point of recording it: a
    // client whose password is wrong and a client that cannot reach the port at
    // all look identical from every other page here, and result code 49 is the
    // one an LDAP client's error handling is built around.
    //
    // The bind DN is on the row and the PASSWORD IS NOT, not even its length as
    // a "harmless" fact — the whole log carries no credential and a length is a
    // credential's most useful property to an attacker who has the rest.
    auditLdap(req, {
      action: 'directory.bind', outcome: 'refused',
      // Not the connection's bound DN, which for a REFUSED bind is whatever the
      // connection was before: the DN this attempt named.
      actor: dn ? consoleKeyFor(dn, getEntry(dn)) : '', actorForm: dn,
      target: dn || '(anonymous)',
      summary: 'a bind as ' + (dn || '(anonymous)') + ' was refused with ' +
               'LDAP_INVALID_CREDENTIALS (49)',
      detail: { resultCode: 49,
                reason: 'the password is the literal string "' +
                        REFUSED_PASSWORD + '", the one this service refuses in ' +
                        'every protocol' }
    });
    log.debug('Leaving the LDAP bind handler. LDAP_INVALID_CREDENTIALS.');
    return next(new ldap.InvalidCredentialsError());
  }
  // A successful bind writes TWO audit rows and they are not duplicates: this
  // one says an LDAP bind happened on this socket, and the `authentication` row
  // recordAuthentication() writes below says a credential was accepted — the
  // same row a Kerberos AS-REQ and a WS-Trust UsernameToken produce, which is
  // what makes "everyone who got in today" one filter rather than fourteen.
  auditLdap(req, {
    action: 'directory.bind',
    actor: dn ? consoleKeyFor(dn, getEntry(dn)) : '', actorForm: dn,
    target: dn || '(anonymous)',
    summary: 'a ' + (dn ? 'simple' : 'anonymous simple') + ' bind as ' +
             (dn || '(anonymous)') + ' succeeded',
    detail: { anonymous: !dn,
              entryExists: dn ? !!getEntry(dn) : false,
              note: 'no password was checked; every bind here succeeds except ' +
                    'the password "' + REFUSED_PASSWORD + '"' }
  });
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
  // What KIND of thing was created is decided by PLACEMENT and not by the
  // objectClass the client sent, and that is not a shortcut. This directory is
  // schemaless: a client can add a `groupOfNames` under ou=users or an entry
  // with no objectClass at all under ou=groups, and believing the class would
  // file both wrongly. Placement is the same rule /admin/groups reports by, so
  // the two pages agree about what a user is. The classes are on the row as a
  // detail, which is where the disagreement shows up when there is one.
  auditLdap(req, {
    action: audit.directoryActionFor('create', dn,
                                     { users: USERS_DN, groups: GROUPS_DN }),
    target: dn,
    summary: 'added ' + dn + ' with ' + Object.keys(attributes).length +
             ' attribute(s)',
    detail: { attributes: Object.keys(attributes).join(', '),
              attributeCount: Object.keys(attributes).length,
              objectClass: (attributes.objectClass || attributes.objectclass ||
                            []).join(', '),
              entriesNow: entries.size }
  });
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
  // The kind is worked out from the DN and not from `stored`, so that a delete
  // and the add that preceded it produce the same word for the same entry.
  //
  // `danglingLeft` is on the row on purpose and is the most useful fact on it:
  // this directory does not enforce referential integrity, so a delete leaves
  // the DN in every group that listed it, and the audit row is the only place
  // the moment that happened is recorded. /admin/groups shows the resulting
  // state and cannot say when it arrived. Counted AFTER the delete, so it is
  // the number of memberships that are dangling now rather than the number that
  // were about to be.
  const dangling = membershipsNaming(dn);
  auditLdap(req, {
    action: audit.directoryActionFor('delete', dn,
                                     { users: USERS_DN, groups: GROUPS_DN }),
    target: dn,
    summary: 'deleted ' + dn,
    detail: { attributeCount: Object.keys(stored.attributes).length,
              danglingLeft: dangling,
              entriesNow: entries.size,
              note: 'any group listing this DN as a member still does; this ' +
                    'directory does not do referential integrity' }
  });
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
  // Recorded AFTER the working copy has replaced the stored one, and that is
  // not incidental: a modify is atomic (RFC 4511 section 4.6, which is why the
  // changes were applied to a copy above), so every early return in the loop
  // over the changes is an operation that did NOT happen and must not leave a
  // row saying it did.
  //
  // The changes are named as `operation attribute`, WITHOUT their values. That
  // is the same rule the rest of this log follows and it bites here: a modify
  // is where a `userPassword` gets set, and a row that helpfully showed what
  // changed would put it on a page. The attribute names alone answer "what was
  // touched", which is the audit question; the debug log has the values for
  // anybody who wants them.
  auditLdap(req, {
    action: audit.directoryActionFor('update', dn,
                                     { users: USERS_DN, groups: GROUPS_DN }),
    target: dn,
    summary: 'modified ' + dn + ' with ' + req.changes.length + ' change(s)',
    detail: { changes: req.changes.map(function (change) {
                return String(change.operation || '').toLowerCase() + ' ' +
                       String(change.modification.type || '').toLowerCase();
              }).join(', '),
              changeCount: req.changes.length,
              attributesNow: Object.keys(working).length,
              note: 'attribute names only; no value is ever recorded here' }
  });
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
  // The kind is taken from the NEW DN, because that is what the entry is now —
  // and a rename can move an entry between containers, which is exactly the
  // case where the two DNs would disagree. Both are on the row, so a rename out
  // of ou=users shows as a `user.rename` or an `entry.rename` with the other
  // name beside it rather than as a row that quietly picked one.
  auditLdap(req, {
    action: audit.directoryActionFor('rename', target,
                                     { users: USERS_DN, groups: GROUPS_DN }),
    target: target,
    summary: 'renamed ' + dn + ' to ' + target,
    detail: { from: dn, to: target, newRdn: newRdn,
              newSuperior: newSuperior,
              movedContainer: normalizeDn(parentDn(dn)) !== normalizeDn(newSuperior),
              note: 'any group listing the OLD DN as a member still does; this ' +
                    'directory does not do referential integrity' }
  });
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
  // The attribute is named and the VALUE is not, for the reason the modify row
  // gives: `compare` against `userPassword` is precisely how a client checks a
  // password without binding, and the value is the password. Whether it matched
  // is the outcome of the operation and is recorded; what was tried is not.
  auditLdap(req, {
    action: 'directory.compare',
    target: dn,
    summary: 'compared ' + type + ' on ' + dn + ' — ' +
             (matched ? 'it matched' : 'it did not match'),
    detail: { attribute: type, matched: matched,
              note: 'the value compared is not recorded; on userPassword it ' +
                    'would be a password' }
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
      // Recorded like any other search, and it earns its row: a client that
      // does not yet know the base DN asks for the root DSE FIRST, so this is
      // usually the very first thing any LDAP client does here and its absence
      // from the log would make a client that never got past discovery look
      // like a client that never connected.
      auditLdap(req, {
        action: 'directory.search',
        target: '(root DSE)',
        summary: 'read the root DSE',
        detail: { scope: scope, filter: filter, returned: 1,
                  attributes: (req.attributes || []).join(', ') }
      });
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
  // How many of the entries that went back were PEOPLE. It is what decides
  // whether this row reads as `user.query` or as `directory.search`, and the
  // decision is made on what was RETURNED rather than on the base the client
  // asked from: a subtree search of the whole directory is the ordinary way an
  // LDAP client looks somebody up, and filing that as "a search somewhere" and
  // a search based at ou=users as "a user query" would put the two commonest
  // spellings of one act in two different buckets.
  let usersSent = 0;
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
      // A truncated search is `refused` rather than `success`, and the two must
      // not be merged: the client has an INCOMPLETE answer and, unless it reads
      // result code 4, does not know it. That is the search whose absence from
      // this log would cost somebody an afternoon.
      auditLdap(req, {
        action: usersSent ? 'user.query' : 'directory.search',
        outcome: 'refused',
        target: base,
        summary: 'a search of ' + base + ' hit the size limit of ' + limit +
                 ' after ' + sent + ' entry/entries',
        detail: { scope: scope, filter: filter, returned: sent,
                  users: usersSent, sizeLimit: limit,
                  clientSizeLimit: clientLimit || 'none',
                  resultCode: 4,
                  note: 'LDAP_SIZE_LIMIT_EXCEEDED; the answer is incomplete' }
      });
      log.debug('Leaving the LDAP search handler. The size limit was reached.');
      return next();
    }
    res.send(toSearchEntry(stored, req.attributes, res.messageId));
    sent++;
    if (isUnder(stored.dn, USERS_DN) && normalizeDn(stored.dn) !== normalizeDn(USERS_DN)) {
      usersSent++;
    }
  }
  log.info('ldap: the search considered ' + considered + ' entry/entries in ' +
           'scope and returned ' + sent + '.');
  // A search that returned nothing is still a search and still gets a row. That
  // is not completeness for its own sake: a filter this store cannot evaluate,
  // and a presence filter defeated by attribute-name case, both look exactly
  // like an empty directory from the client's side (the comment above
  // req.filter.matches is the record of that having happened here), and the row
  // saying "considered 14, returned 0" is what tells the two apart.
  auditLdap(req, {
    action: usersSent ? 'user.query' : 'directory.search',
    target: base,
    summary: 'searched ' + base + ' (' + scope + ') and returned ' + sent +
             ' of ' + considered + ' entry/entries in scope' +
             (usersSent ? ', ' + usersSent + ' of them under ou=users' : ''),
    detail: { scope: scope, filter: filter, considered: considered,
              returned: sent, users: usersSent, sizeLimit: limit,
              attributes: (req.attributes || []).join(', ') || '(all)' }
  });
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
      'attributes, which are this service\'s own names and not schema. A ' +
      'DECENTRALIZED IDENTIFIER is the third shape and is neither a name nor a ' +
      'DN: an issued credential\'s did:jwk subject, whatever DID presents to ' +
      'the OID4VP Verifier, the one /did/generate mints. Its entry goes at ' +
      'uid=did-<12 hex of the SHA-256 of the DID>,' + USERS_DN + ' — a ' +
      'did:jwk written out in full is a DN of several hundred characters, ' +
      'most of it key material — with the identifier itself kept whole on the ' +
      'entry as didSubject, and its method as didMethod. Search for the ' +
      'person by didSubject, not by uid: on those entries the uid is a digest ' +
      'and the didSubject is the identity.',
    authenticationFacts: 'where the protocol that accepted the credential says ' +
      'HOW it was presented — which today is the sign-in screen and nothing ' +
      'else, since amr is an OIDC vocabulary — the entry also carries ' +
      'authnMethod (every RFC 8176 method this person has used here, ' +
      'accumulated), mfaAuthenticated (TRUE or FALSE for the MOST RECENT ' +
      'authentication, overwritten each time) and mfaLastAuthTime (when ' +
      'multi-factor last happened, never cleared). These are this service\'s ' +
      'own names and not schema. A WebAuthn ceremony after a password writes ' +
      'TRUE; the same ceremony used passwordless writes authnMethod hwk with ' +
      'no pwd beside it and mfaAuthenticated FALSE, because one factor is one ' +
      'factor however phishing-resistant it is. Nothing here READS them: no ' +
      'token carries them and no endpoint decides anything on them, exactly as ' +
      'a group here grants nothing.',
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
    '<h2>Where an identity&rsquo;s entry goes</h2>' +
    '<p>' + xmlEscape(info.autoCreateRule) + '</p>' +
    '<h2>And how they authenticated</h2>' +
    '<p>' + xmlEscape(info.authenticationFacts) + '</p>' +
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
    '<p>The tree has three containers. <code>ou=users</code> holds people, one ' +
    'per identity that has authenticated here through any protocol. ' +
    '<code>ou=groups</code> holds groups, which grant nothing. ' +
    '<code>ou=applications</code> holds the OTHER side of those ' +
    'authentications — every OAuth client, relying party, service provider and ' +
    'Kerberos service this service has been asked about — and it is different ' +
    'from the other two in one way worth knowing: <strong>it is a registry ' +
    'rather than a record</strong>. The RFC 7591 client registrations live ' +
    'there and nothing caches them, so an <code>ldapmodify</code> of an ' +
    'application entry changes what the protocol endpoints do. ' +
    '<a href="/ldap/applications">What is in it, and the schema it uses</a>.</p>' +
    '<p class="sub"><a href="/ldap?format=json">This page as JSON</a> ' +
    '&middot; <a href="/ldap/applications">the application registry</a> ' +
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
// ---------------------------------------------------------------------------
// THE APPLICATIONS CONTAINER, AND THE FOUR FUNCTIONS THAT MAKE IT A STORE.
//
// `applications.js` owns the SCHEMA — what an application entry carries and how
// a record converts to and from attributes. This file owns the DIRECTORY: where
// the container is, how an entry is created, what the cap is, and what an audit
// row for one says. Neither knows the other's half, and the boundary is these
// four functions plus the two conversions they call.
//
// The hook is INVERTED for the reason `vcClaims.setDirectory()` is: this module
// is LAST in the require order because requiring it pulls every `/ldap` route
// into the express router at that point, and `oauth2.js` — which reads the
// registry on every authorization request in RFC 9700 mode — cannot drag those
// routes to the front of it. So `applications.js` offers the slot and this file
// fills it below.
//
// **There is no cache on the other side of this.** Every read the registry does
// is a read of these entries, which is what makes an `ldapmodify` take effect on
// the next request rather than after a restart. That is the whole point of the
// directory being the source of truth, and a cache added for speed would quietly
// undo it — on a mock, where the whole store is a Map in this process, there is
// nothing to be gained by one anyway.
//
// **An application entry is not a person and must not be swept as one.**
// `populateVcAttributes()` walks `ou=users` and would otherwise give an OAuth
// client a birthdate; `/admin/groups` walks the same container and reports
// membership. Both are already limited to `ou=users`, which is why this
// container is a container of its own rather than a corner of that one — the
// opposite decision from `didPlan()`, where being outside those sweeps was the
// bug because a DID names a person.
// ---------------------------------------------------------------------------
function applicationDn(identifier) {
  return 'cn=' + escapeDnValue(applications.labelFor(identifier)) + ',' + APPLICATIONS_DN;
}

// Find an application by its IDENTIFIER rather than by its DN, because the DN
// may be a digest of it — an identifier longer than a readable RDN is named
// `cn=app-<12 hex>`, the same device didPlan() uses, with the same consequence
// that the cn is not the identity. `appIdentifier` is.
function applicationEntry(identifier) {
  log.debug('Entering applicationEntry(). identifier=' + identifier);
  const direct = getEntry(applicationDn(identifier));
  if (direct) {
    log.debug('Leaving applicationEntry(). Found at its DN.');
    return direct;
  }
  // The DN did not match, which happens when somebody renamed the entry. The
  // identifier is still on it, so a walk finds it — and a walk is affordable
  // here in a way it would not be in a real directory: the cap is a few hundred
  // entries in one process.
  const wanted = String(identifier);
  let found = null;
  entries.forEach(function (stored) {
    if (found || !isUnder(stored.dn, APPLICATIONS_DN)) {
      return;
    }
    if ((stored.attributes.appidentifier || [])[0] === wanted) {
      found = stored;
    }
  });
  log.debug('Leaving applicationEntry(). ' + (found ? 'Found by appIdentifier.' : 'Not here.'));
  return found;
}

// ---------------------------------------------------------------------------
// ONE APPLICATION ENTRY AS THE REGISTRY AND THE CONSOLE SEE IT.
//
// The same shape objectFor() hands the console for a person's entry, and it is
// the same shape deliberately: `/admin/users` and `/admin/groups` already draw
// an entry with attributeTable(), and an application entry that arrived in some
// other shape would have needed a second renderer that could then disagree with
// the first about what a dump of an entry looks like.
//
// Three things it carries that the raw attribute map did not, and each is a
// thing the applications pages were missing because of it:
//
//   * THE DN. It is not an attribute — it is the key the entry is stored under —
//     so a caller handed `stored.attributes` had no way to learn where the entry
//     lives, and every applications page could show the `cn` and nothing else.
//     It is published as `entryDN` (RFC 5020) because matchable() already uses
//     that name for the same fact, so an ldapsearch filter and this dump agree
//     about what the DN is called.
//   * THE OPERATIONAL ATTRIBUTES, createTimestamp and modifyTimestamp. A SEARCH
//     withholds those unless they are asked for by name (RFC 4511 section
//     4.5.1.8) and toSearchEntry() honours it — but this is not a search, it is
//     this service showing its own store, and `operational` names which ones a
//     search would have withheld so a page can say so rather than pretend the
//     distinction does not exist.
//   * THE CANONICAL SPELLING. The store lower-cases every attribute name because
//     that is how @ldapjs/attribute delivers it; a page showing `oauthclientid`
//     where the published schema says `oauthClientId` reads as a bug in the
//     page. canonicalName() now knows the applications schema's names too —
//     see the merge beside CANONICAL_NAMES.
// ---------------------------------------------------------------------------
function applicationObject(stored) {
  const attributes = {};
  Object.keys(stored.attributes).sort().forEach(function (attribute) {
    attributes[canonicalName(attribute)] = stored.attributes[attribute].slice(0);
  });
  // Synthesised rather than stored, exactly as matchable() does it: the DN is
  // where the entry IS, so holding a copy of it on the entry would be a second
  // definition of the same fact and the one that goes stale on a rename.
  attributes[canonicalName('entrydn')] = [stored.dn];
  return {
    dn: stored.dn,
    origin: stored.origin || 'unstated',
    createdAt: stored.createdAt,
    modifiedAt: stored.modifiedAt,
    operational: OPERATIONAL.map(canonicalName),
    attributes: attributes
  };
}

function readApplication(identifier) {
  const stored = applicationEntry(identifier);
  return stored ? applicationObject(stored) : null;
}

function applicationCount() {
  let n = 0;
  entries.forEach(function (stored) {
    if (isUnder(stored.dn, APPLICATIONS_DN) && normalizeDn(stored.dn) !== normalizeDn(APPLICATIONS_DN)) {
      n++;
    }
  });
  return n;
}

function allApplications() {
  log.debug('Entering allApplications().');
  const rows = [];
  entries.forEach(function (stored) {
    if (isUnder(stored.dn, APPLICATIONS_DN) &&
        normalizeDn(stored.dn) !== normalizeDn(APPLICATIONS_DN)) {
      rows.push(applicationObject(stored));
    }
  });
  log.debug('Leaving allApplications(). ' + rows.length + ' application(s).');
  return rows;
}

// Create or replace an application entry. REPLACE rather than merge, and that
// is the one place this differs from `applyVcAttributes()`'s "fill only what is
// absent" rule — deliberately, and for a reason particular to a registry: the
// record being written was READ FROM THIS ENTRY a moment ago and then changed,
// so it already contains whatever the entry had, an operator's own edits
// included. Merging on top of that would make it impossible ever to REMOVE a
// value — a redirect URI deleted with ldapmodify would come back on the next
// authorization request, which is the opposite of the directory being the
// source of truth.
//
// The operational attributes are the exception and are preserved: createTimestamp
// belongs to the entry rather than to the record, and an entry that reported
// being created afresh on every sign-in would make the audit log unreadable.
function writeApplication(identifier, attributes) {
  log.debug('Entering writeApplication(). identifier=' + identifier);
  const existing = applicationEntry(identifier);
  const dn = existing ? existing.dn : applicationDn(identifier);
  if (!existing && applicationCount() >= maxApplications()) {
    // Warned rather than thrown, exactly as a full directory is when somebody
    // authenticates: whatever this application was doing succeeded, and a
    // registry that could fail a token request would be the tail wagging the
    // dog.
    log.warn('ldap: not creating ' + dn + '; ou=applications holds its maximum of ' +
             maxApplications() + ' entry/entries (applications.max). The application ' +
             'itself is unaffected — it simply goes unrecorded.');
    log.debug('Leaving writeApplication(). The container is full.');
    return false;
  }
  if (entries.size >= maxEntries() && !existing) {
    log.warn('ldap: not creating ' + dn + '; the directory holds its maximum of ' +
             maxEntries() + ' entries.');
    log.debug('Leaving writeApplication(). The directory is full.');
    return false;
  }
  const created = existing ? existing.createdAt : generalizedTime();
  const stored = putEntry(dn, attributes, { origin: existing ? existing.origin : 'application' });
  stored.createdAt = created;
  stored.attributes.createtimestamp = [created];
  stored.attributes.modifytimestamp = [generalizedTime()];
  auditDirectory(existing ? 'entry.update' : 'entry.create', dn, attributes, !existing);
  log.debug('Leaving writeApplication(). The entry was ' +
            (existing ? 'updated.' : 'created.'));
  return true;
}

// Remove an application entry. The container itself is never a candidate —
// applicationEntry() only ever returns something under it — and a delete here
// does not touch anything else in the tree: an application entry has no
// children and nothing in this directory references one, so there is no
// dangling member to leave behind the way deleting a user does.
function deleteApplicationEntry(identifier) {
  log.debug('Entering deleteApplicationEntry(). identifier=' + identifier);
  const stored = applicationEntry(identifier);
  if (!stored) {
    log.debug('Leaving deleteApplicationEntry(). It was not here.');
    return false;
  }
  entries.delete(normalizeDn(stored.dn));
  auditDirectory('entry.delete', stored.dn, stored.attributes, false);
  log.debug('Leaving deleteApplicationEntry(). ' + entries.size + ' entry/entries left.');
  return true;
}

// The directory's own audit row for an application entry, which is a DIFFERENT
// fact from applications.js's `application.create`: that one says an application
// was seen, this one says an entry in the tree changed. Both are recorded
// because /admin/audit's directory filter would otherwise show every entry this
// service writes except these, and a blind spot in a directory log is worse than
// a row somebody has to read past.
//
// NO VALUES ARE NAMED, only attribute names — the same rule every other LDAP
// row here follows, and it matters more on these entries than on any other:
// oauthClientSecret and appRegistrationAccessToken are among the attributes.
function auditDirectory(action, dn, attributes, created) {
  audit.audit({
    action: action,
    actor: '',
    protocol: 'LDAP',
    channel: 'internal',
    target: dn,
    summary: 'The application entry ' + dn + ' was ' +
             (action === 'entry.delete' ? 'deleted' : (created ? 'created' : 'updated')),
    detail: { attributes: Object.keys(attributes || {}).sort().join(', ') }
  });
}

// The slot, filled at require time. Its four functions are all this file
// exposes of the container; everything else about an application — what it is,
// what it carries, how a record becomes attributes — is applications.js's.
applications.setDirectory({
  readApplication: readApplication,
  writeApplication: writeApplication,
  allApplications: allApplications,
  countApplications: applicationCount,
  deleteApplication: deleteApplicationEntry,
  // Two facts about the container itself, for the pages that report where these
  // entries live and how many will fit. They are here rather than in that module
  // because that module deliberately does not know where the container is.
  containerDn: function () { return APPLICATIONS_DN; },
  maxApplications: maxApplications
});

// ---------------------------------------------------------------------------
// GET /ldap/applications — the registry, and the schema that defines it.
//
// Two things on one page because they answer one question. The TABLE is what
// this service has been asked about; the SCHEMA below it is what an entry may
// carry and where each attribute comes from — published rather than left to be
// read out of the source, for the reason `GET /ldap` publishes the bind policy:
// a directory whose shape you have to infer is one every client infers
// differently.
//
// It is a view of the store rather than a store of its own: every row is read
// through applications.js, which reads these very entries. The page cannot
// disagree with the directory because it has nothing to disagree with.
// ---------------------------------------------------------------------------
app.get('/ldap/applications', function (req, res) {
  log.debug('Entering GET /ldap/applications.');
  const rows = applications.list();
  const payload = {
    baseDn: BASE_DN,
    container: APPLICATIONS_DN,
    count: rows.length,
    max: maxApplications(),
    sourceOfTruth: 'These entries ARE the registry. An ldapmodify here changes what the ' +
      'protocol endpoints do — adding a value to oauthRedirectUri adds a redirect URI ' +
      'that RFC 9700 mode will then accept by exact match.',
    kinds: applications.KINDS,
    schema: applications.SCHEMA,
    applications: rows
  };
  if (String(req.query.format || '').toLowerCase() === 'json') {
    log.debug('Leaving GET /ldap/applications. JSON, ' + rows.length + ' application(s).');
    return res.status(200).json(payload);
  }
  const appRows = rows.map(function (row) {
    // EVERY attribute, which now includes the operational ones and entryDN. A
    // search would withhold those unless they were asked for by name (RFC 4511
    // section 4.5.1.8); this is the service showing its own store, so it shows
    // them, and the column heading below says so.
    const attrs = Object.keys(row.attributes).sort().map(function (name) {
      const value = row.attributes[name];
      return '<code>' + xmlEscape(name) + '</code>: ' +
        xmlEscape(Array.isArray(value) ? value.join(' | ') : String(value));
    }).join('<br>');
    // The DN on every row. This is the page headed "the registry as the
    // directory sees it", and the directory sees an entry by its DN — a row that
    // named only the identifier left the one address an ldapsearch needs to be
    // reconstructed by the reader from a naming rule published nowhere.
    return '<tr><td><code>' + xmlEscape(row.identifier) + '</code>' +
      (row.dn ? '<br><span class="sub"><code>' + xmlEscape(row.dn) + '</code>' +
        (row.identifier === row.dnLabel ? '' :
          ' &mdash; the identifier is too long for a readable RDN, so the cn is a ' +
          'digest of it and <code>appIdentifier</code> is the identity') +
        '</span>' : '') +
      '</td><td>' + xmlEscape(row.name) + '</td><td>' +
      xmlEscape(row.kinds.join(', ') || '(unstated)') + '<br><span class="sub">' +
      xmlEscape(row.protocols.join(', ')) + '</span></td><td>' +
      (row.registered ? 'yes' : 'no') + '</td><td>' + row.authentications +
      ' auth<br>' + row.sessions + ' session(s)<br>' + row.users + ' user(s)</td><td>' +
      attrs + '</td></tr>';
  }).join('');
  const classRows = applications.SCHEMA.objectClasses.map(function (one) {
    return '<tr><td><code>' + xmlEscape(one.name) + '</code></td><td>' +
      xmlEscape(one.where) + (one.standard ? '' : ' <strong>(invented here)</strong>') +
      '</td><td>' + xmlEscape(one.what) + '</td></tr>';
  }).join('');
  const attrRows = applications.SCHEMA.attributes.map(function (row) {
    return '<tr><td><code>' + xmlEscape(row.name) + '</code>' +
      (row.sensitive ? ' <strong>(credential)</strong>' : '') +
      '</td><td>' + xmlEscape(row.kind) + '</td><td>' + xmlEscape(row.from) +
      '</td><td>' + xmlEscape(row.what) + '</td></tr>';
  }).join('');
  const kindRows = applications.KINDS.map(function (one) {
    return '<tr><td><code>' + xmlEscape(one.kind) + '</code></td><td>' +
      xmlEscape(one.label) + '</td><td>' + xmlEscape(one.what) + '</td></tr>';
  }).join('');
  const inner = '<h1>Applications</h1>' +
    '<p class="sub">' + rows.length + ' of a maximum ' + maxApplications() +
    ' under <code>' + xmlEscape(APPLICATIONS_DN) + '</code>: every OAuth client, ' +
    'OpenID Connect relying party, SAML service provider, WS-Federation application, ' +
    'WS-Trust relying party, OpenID4VP verifier and Kerberos service this instance has ' +
    'been asked about. One entry per unique identifier, so an application that speaks ' +
    'two protocols under one name is one row with two kinds rather than two rows.</p>' +
    '<p class="sub"><strong>These entries are the registry, not a copy of one.</strong> ' +
    'An <code>ldapmodify</code> here changes what the protocol endpoints do: add a value ' +
    'to <code>oauthRedirectUri</code> and RFC 9700 mode accepts that redirect URI by exact ' +
    'match on the next authorization request. Nothing caches them.</p>' +
    (rows.length
      ? '<table><tr><th>Identifier</th><th>Name</th><th>Kind</th><th>Registered</th>' +
        '<th>Seen</th><th>Every attribute</th></tr>' + appRows + '</table>'
      : '<p class="sub">Nothing yet. An entry appears the first time a client_id, ' +
        'wtrealm, AppliesTo, entityID or service principal name is accepted.</p>') +
    '<h2>What an application can be</h2>' +
    '<table><tr><th>Kind</th><th>Label</th><th>What it means</th></tr>' + kindRows +
    '</table>' +
    '<h2>The object classes</h2>' +
    '<p class="sub">node-ldapjs has no schema subsystem &mdash; it is protocol machinery, ' +
    'and it is a submodule this repository does not modify &mdash; and this directory is ' +
    'schemaless on purpose. So this is a VOCABULARY rather than a constraint: nothing ' +
    'rejects an entry for disobeying it. Where a registered class fits, it is used.</p>' +
    '<table><tr><th>Class</th><th>Where from</th><th>What it brings</th></tr>' +
    classRows + '</table>' +
    '<h2>The attributes</h2>' +
    '<p class="sub"><code>multi</code> accumulates a repeat, <code>single</code> is ' +
    'assigned &mdash; which is what stops a counter growing a value per sign-in. Two ' +
    'attributes hold CREDENTIALS in the clear, for the reason ' +
    '<code>/krb5/principals</code> prints the Kerberos passwords; they are never written ' +
    'to the audit log.</p>' +
    '<table><tr><th>Attribute</th><th>Values</th><th>Set by</th><th>What it is</th></tr>' +
    attrRows + '</table>' +
    '<p class="sub"><a href="/ldap/applications?format=json">This page as JSON</a> ' +
    '&middot; <a href="/ldap/directory">every entry in the directory</a> &middot; ' +
    '<a href="/ldap">what this directory is</a></p>';
  res.status(200).type('html').send(pageShell('Applications', inner));
  log.debug('Leaving GET /ldap/applications. ' + rows.length + ' application(s).');
});

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
  groupsFor: groupsFor,
  groupsOfUser: groupsOfUser,
  APPLICATIONS_DN: APPLICATIONS_DN,
  maxApplications: maxApplications
};
