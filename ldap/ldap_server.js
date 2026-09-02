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
// schema of its own. GET /admin/ldap/service says so on the page.
//
// Four behaviours ARE enforced. Three of them are protocol rules whose absence
// would teach a client something false, and the fourth is this service's own:
//
//   * an add whose PARENT does not exist is LDAP_NO_SUCH_OBJECT (32). A
//     directory is a tree, and a client that has never seen this refusal will
//     write its first entry into a real directory and not understand the error.
//   * a delete of an entry that HAS CHILDREN is LDAP_NOT_ALLOWED_ON_NONLEAF
//     (66), for the same reason.
//   * a modify naming an attribute that is not there is
//     LDAP_NO_SUCH_ATTRIBUTE (16) for `delete` and `replace`-with-values-absent,
//     and succeeds for `add`.
//   * ONE ENTRY PER PERSON: an add under `ou=users` whose username is already
//     here is LDAP_ENTRY_ALREADY_EXISTS (68), naming the entry that holds it.
//     This one is not a protocol rule — LDAP has no notion of a username, and a
//     real directory gets this from a uniqueness constraint in its schema, which
//     is exactly the subsystem this mock does not have. It is enforced because
//     every OTHER door onto this container now folds onto one entry per person
//     (see existingUserEntry()), and a directory that let an `ldapadd` undo that
//     in one operation would be keeping the rule nowhere.
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
//
// ONE ENTRY PER PERSON, HOWEVER MANY WAYS THEY GET IN. `rcbj` signing in at the
// login screen, `urn:sts-mock:user:rcbj` in a token, `rcbj@STS.MOCK` in a
// Kerberos AS-REQ and `rcbj` on a WS-Security UsernameToken have always been one
// entry — identityOf() in admin_stats.js normalises all four to one key before
// this hook ever sees them. What did NOT fold was the identity that is a DN
// rather than a name, and now does: a certificate saying `CN=rcbj` lands on the
// entry rcbj already has, and a password sign-in after a handshake lands on the
// one the certificate made. existingUserEntry() is the whole of it, and the same
// function answers at the other two doors — an `ldapadd` under `ou=users` and
// createUser(), which the console and the management API share. A DID is the one
// identity that names nobody by itself and so cannot generally fold; where this
// service KNOWS whose it is, it does. See didPlan().
// ---------------------------------------------------------------------------

// For one thing only: the short, stable uid a DID-named entry is placed at.
// See didPlan().
const crypto = require('crypto');
const ldap = require('ldapjs');
const app = require('../common/app');
const { log, xmlEscape } = require('../common/helpers');
const config = require('../common/config');
// THE TRUST REALM REGISTRY, and this module is the one place in this service
// that needs more of it than the ambient value. It reads `currentId()` to build
// a DN, `get()`/`run()` to seed a named realm's subtree the moment it is
// defined, and `DEFAULT_ID` to pin the two admin console roles to the default
// realm. It requires only config.js, so it closes no cycle and moves no route
// — the ordinary direction, no slot. See the naming-context block below.
const realms = require('../common/realms');
// ---------------------------------------------------------------------------
// WHERE THIS DIRECTORY IS WRITTEN DOWN, SINCE 2026-08-27.
//
// A PLAIN REQUIRE, in the ordinary direction, and rule 3e's test is why rather
// than habit: that module registers NO ROUTE at all — it is a library, rule 3's
// shape — and it does not require this file, so requiring it here moves nothing
// in the router and closes no cycle. It requires only `config.js` and
// `realms.js`, both of which are already loaded by the two lines above.
//
// THE DEPENDENCY IN THE OTHER DIRECTION IS A SLOT, filled a few lines below,
// and that one is not optional: that module has to READ this directory to write
// it down and to REPLACE it at startup, and a require from there to here would
// drag `/ldap` and `/ldap/directory` into the express router at position #4a —
// far ahead of `admin.js`, and exactly the failure rule 1 exists to prevent.
// ---------------------------------------------------------------------------
const persistence = require('../persistence/persistence');
const stats = require('../common/admin_stats');
// The application registry. This module is its STORE — see the applications
// section below — so the dependency runs both ways in the shape rule 6
// describes: a plain require here for the schema and the two conversions, and
// an inverted slot filled at the bottom of this file for the four functions
// that read and write the container.
const applications = require('../common/applications');
// The SPIFFE registry's schema and both conversions. The same division
// applications.js draws: THAT module owns what a registration entry IS, THIS
// one owns where the containers are, how an entry is created and what the cap
// is. Its setDirectory() slot is filled below at require time, for the reason
// every slot in this file exists — a require reaching this module from there
// would drag every /ldap route to the front of the express router.
// The federation register's schema and both conversions, on exactly the same
// terms: THAT module owns what a relationship IS and this one owns where the
// container is. Its setDirectory() slot is filled below at require time, and it
// is safe to require in the ordinary direction here for the same reason
// applications.js is — it registers no route, so nothing about requiring it can
// move one.
const federation = require('../federation/federation');
const spiffeRegistry = require('../spiffe/spiffe_registry');
const scimMap = require('../scim/scim_map');
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
const audit = require('../common/audit');
// The admin console, for ONE reason: to hand it the reader below so that a user's
// page can show that user's directory entry. It is required here rather than the
// other way round because server.js requires ./admin BEFORE this module (rule 6),
// so admin.js must not require this one back — see the note above objectFor().
const admin = require('../admin-ui/admin');
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
// no output — /admin/sts-metadata sorts its rows by path within a group — and
// the line over there is for the next reader rather than for the page.
const tlsServer = require('../tls/tls_server');
// WHICH attributes a person's entry should carry so that the credentials this
// service issues have something to say, and what to invent for them. Another
// plain require and not a third inversion, for the same reasons as tls_server.js
// above: vc_claims.js is a LIBRARY — it registers no route, so requiring it adds
// nothing to the express router and cannot reorder /admin/sts-metadata — and it
// requires only helpers.js, so there is no cycle to make. The traffic in the
// other direction, this module's two functions that IT calls, does go through a
// slot: see the setDirectory() install further down.
const vcClaims = require('../oid4vc/vc_claims');

// The groups claim: which directory groups reach an access token, an ID Token
// and both SAML assertions. A plain require for exactly the reasons above —
// it is a LIBRARY (it registers no route, so it cannot reorder
// /admin/sts-metadata) and it requires helpers.js, config.js and
// admin_stats.js, none of which requires this file. The traffic in the other
// direction, groupsOfUser(), goes through its setDirectory() slot further down,
// because THAT module must not require this one: it is read from
// admin_stats.js's resolver, which every issuance site reaches long before the
// directory's routes should exist.
const groupClaims = require('../common/group_claims');
// The admin console's two roles, which are two groups in THIS directory. Required
// outright rather than through a slot in the other direction because it registers
// no route (rule 3), so nothing about the require order changes by naming it here;
// the slot below is what carries this module's functions the other way.
const adminRbac = require('../admin-ui/admin_rbac');
// WHAT A PERSON AGREED AN APPLICATION MAY ASK FOR ON THEIR BEHALF. Required
// outright for `groupClaims`'s reason and with the same traffic in the other
// direction: `common/consent.js` registers no route (rule 3) and requires
// helpers.js, config.js, applications.js and admin_stats.js — none of which
// requires this file — so naming it here changes nothing about the require
// order. The four functions this module contributes go the other way through
// its setDirectory() slot further down, because THAT module is read from
// `oauth-oidc/consent_screen.js` and from the console, both of which server.js
// requires long before this directory's routes should exist.
const consent = require('../common/consent');

// The port. 389 is the assigned one and this process is root in the container,
// so it binds it directly; a host run is not root, which is why the variable
// exists. Changing it means the parent project's api has to allow the new port
// in `ldapAllowedPorts` or its LDAP client will refuse to reach it — the same
// coupling KRB5_KDC_PORT has with krb5AllowedPorts, and for the same reason.
const LDAP_PORT = config.value('ldap.port');

// The LDAPS port. 636 is the IANA-assigned one for LDAP over TLS and, like 389,
// it is privileged — so the container binds it and a host run usually cannot.
// A failure to bind is RECORDED and published on GET /admin/ldap/service exactly as the plain
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

// ---------------------------------------------------------------------------
// THE NAMING CONTEXT, AND THE SUBTREE EACH TRUST REALM OWNS INSIDE IT.
//
// `ROOT_DN` is what the SOCKET serves — `ldap.baseDn`, one naming context, one
// tree, published in the root DSE and answered for on 389 and 636. Everything
// below it is ours; anything outside it is LDAP_NO_SUCH_OBJECT, which is what a
// real server does for a base DN it holds no data for.
//
// `baseDn()` is what the AMBIENT REALM owns, and it is a SUBTREE of that:
//
//     the default realm    dc=example,dc=com                 (ROOT_DN itself)
//     the realm `acme`     dc=acme,dc=example,dc=com
//
// so `ou=users`, `ou=groups`, `ou=applications`, `ou=federations` and the two
// SPIFFE containers exist once per realm and share nothing. A person created
// under `/realm/acme` is `uid=…,ou=users,dc=acme,dc=example,dc=com` and is
// invisible to every search based at the default realm's `ou=users` — and,
// since 2026-08-25, to a subtree search based at the default realm's ROOT as
// well: the search handler scopes its answer to the realm the base names, and
// the root DSE publishes one naming context per realm so that a client can
// still find the others. `ldapsearch -b "dc=acme,dc=example,dc=com"` is how you
// read that realm, which is the same sentence as before and now the only way.
//
// **WHY A SUBTREE RATHER THAN A PARTITIONED STORE.** The realm is ambient in an
// AsyncLocalStorage that `app.js`'s first middleware enters, and that middleware
// runs on an HTTP request. **LDAP has no HTTP request.** An `ldapsearch` arrives
// on 389 carrying a bind DN and a base DN and nothing else — no path, no header,
// nowhere to put a realm segment — so if the partition were a Map per realm,
// selected by an ambient value, an LDAP client could never reach any realm but
// the default one. Putting the realm IN THE DN is what makes
// `ldapsearch -b "dc=acme,dc=example,dc=com"` mean what it says, and it is the
// only shape that does. One Map keyed by DN also leaves `groupIndexNow()`, the
// root DSE and every containment check exactly as they were.
//
// The alternative considered and rejected was a LISTENER per realm. It isolates
// just as well and it costs the thing this feature is for: a port is bound when
// the process starts, so realms would have stopped being creatable at runtime.
//
// **WHY THE REALM'S BASE IS DERIVED AND NOT CONFIGURED.** `ldap.baseDn` is
// restart-only because *the tree is built under it at startup* — the
// "material derived at startup" kind, which `common/CLAUDE.md` names as the
// case that must never be given the `realmRuntime` marker. So a realm cannot
// carry `ldap.baseDn`, and its base is computed from its id instead. That is
// not a limitation working around a rule; it is the rule being right. Two
// realms are told apart by their ids everywhere else in this service, and a
// configurable base would let two of them name one subtree.
//
// The RDN attribute type is taken from the root's own first RDN so the tree
// stays homogeneous: a `dc=example,dc=com` root gives `dc=acme,…`, and an
// `o=example` root gives `o=acme,…` rather than a dc grafted onto an o.
// ---------------------------------------------------------------------------
const ROOT_DN = config.value('ldap.baseDn');

// `dc` for the ordinary root, whatever the root uses otherwise. Computed once:
// ROOT_DN cannot change while the process runs.
const REALM_RDN_TYPE = (function () {
  const first = String(ROOT_DN).split(',')[0];
  const type = first.indexOf('=') > 0 ? first.split('=')[0].trim() : 'dc';
  return type || 'dc';
})();

// The base DN of a NAMED realm. Exported and used by the purge, by the
// default-realm pinning the admin console needs, and by every page that lists
// what a realm owns.
function realmBaseDn(id) {
  if (!id || id === realms.DEFAULT_ID) {
    return ROOT_DN;
  }
  return REALM_RDN_TYPE + '=' + id + ',' + ROOT_DN;
}

// The base DN of whatever realm is ambient. THE function every DN below is
// built from — the same shape `helpers.baseUrlOf()` has for URLs, and for the
// same reason: one place that knows about realms, and a hundred call sites that
// do not.
function baseDn() {
  return realmBaseDn(realms.currentId());
}

// Where auto-created people and hand-made groups live. Derived rather than
// configured: two values that could disagree with the base would produce
// entries in a tree nobody is searching.
function usersDn() {
  return 'ou=users,' + baseDn();
}

function groupsDn() {
  return 'ou=groups,' + baseDn();
}

// The third container, and the one whose entries are a REGISTRY rather than a
// description of one. See the applications section further down.
function applicationsDn() {
  return 'ou=applications,' + baseDn();
}

// The SIXTH container, and it is `federation/federation.js`'s store the way
// ou=applications is `applications.js`'s. It is a container of its own rather
// than a corner of ou=applications for a reason worth keeping: an application
// entry is something this service was ASKED ABOUT, and half the entries here
// are FOREIGN IDENTITY PROVIDERS, which ask this service for nothing at all.
// Filing a party that authenticates people TO this service among the parties
// that consume what it issues would make the one question ou=applications
// exists to answer unanswerable.
function federationsDn() {
  return 'ou=federations,' + baseDn();
}

// The fourth and fifth, and they are `spiffe_registry.js`'s store the way
// ou=applications is `applications.js`'s. TWO containers rather than one,
// because they hold different KINDS of thing: an entry under ou=entries is
// CONFIGURATION deciding what will be issued, and an entry under ou=agents is a
// RECORD of something that happened. The same split ou=applications draws
// internally between what an application may do and what it has done — made
// structural here, because a registration entry and an attested agent share no
// attributes at all.
function spiffeDn() {
  return 'ou=spiffe,' + baseDn();
}

function spiffeEntriesDn() {
  return 'ou=entries,' + spiffeDn();
}

function spiffeAgentsDn() {
  return 'ou=agents,' + spiffeDn();
}

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

// How many entries may live under ou=federations. The same directory-limit rule
// applications.max follows — it REFUSES rather than evicting — and it matters
// more here than there: an evicted application entry is a record that has been
// lost, and an evicted federation relationship is a partner that silently
// stopped being trusted.
function maxFederations() {
  return config.value('federation.max');
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
// A Map keyed by the NORMALISED DN, holding the DN exactly as it was written
// and the attributes.
//
// **ONE PER TRUST REALM, since 2026-08-25, and it was one Map for the whole
// process for the two days before that.** Each realm has an embedded directory
// of its own behind the one socket: `entries.get()` in `acme` cannot return
// the default realm's entry, because it is not in the Map it is reading.
//
// WHY THAT MATTERS MORE THAN IT SOUNDS. With one Map the isolation was a RULE —
// every reader had to remember to ask whether the DN it found belonged to the
// realm it was answering for — and a rule that must be remembered at fifty call
// sites is a rule that will be missed. It was missed twice in one day: the
// enumerators were scoped and every lookup BY DN was not, so
// `/realm/acme/admin/groups?group=<a default-realm DN>` rendered that group in
// full and `DELETE /realm/acme/scim/v2/Groups/<same DN>` removed it. Splitting
// the store turns the rule into an invariant that cannot be forgotten, because
// there is nothing to forget: the wrong entry is not reachable from here.
//
// WHAT PAYS FOR IT. The socket has no realm on it, so each handler resolves one
// from the DN in the request — `realmFor()` below — and runs its body inside
// `realms.run()`, after which every helper in this file is that realm's. The
// ceiling stays process-wide: `ldap.maxEntries` is checked against
// `totalEntries()`, which sums the stores, because the cap is about the memory
// this process occupies and n realms holding n times the ceiling was never the
// intention.
//
// The alternative shapes, and why not: a LISTENER per realm works (node binds a
// port whenever it likes — the claim that this would make realms restart-only
// was simply wrong) but it makes a realm reachable by PORT, which is a second
// discriminator beside the DN and one more thing every client has to be told.
// An ldapjs `Server` per realm behind one socket does not work at all: the
// discriminator lives inside the protocol, per operation, and a Server owns its
// net.Server. Attribute names are stored in lower case because that is
// what arrives — @ldapjs/attribute lower-cases a type on the way in, so an entry
// added as `objectClass` comes back as `objectclass` — and because LDAP
// attribute descriptions are case-insensitive anyway. What is lost by that is
// only how the name LOOKED, which is why CANONICAL_NAMES exists: a debugger
// showing `givenname` where every schema document says `givenName` reads as a
// bug in the debugger.
// ---------------------------------------------------------------------------
const entries = realms.map();

// EVERY REALM'S STORE, ADDED UP. The one number that is still about the process
// rather than about a realm, and it exists for exactly one purpose: the
// `ldap.maxEntries` ceiling. See the block above — the cap is on what this
// process holds in memory, so it has to see all of it.
function totalEntries() {
  let n = 0;
  realms.list().forEach(function (realm) {
    n += entries.realmMap(realm.id).size;
  });
  return n;
}

// WHICH REALM A DN BELONGS TO, decided by the DN alone. It is what lets the
// SOCKET pick a store: an LDAP request arrives with no realm on it, and the DN
// it carries — a base to search from, or the entry to add, modify, delete or
// compare — is the only thing in the protocol that can name one.
//
// The closest containing base wins. `dc=acme,dc=example,dc=com` and everything
// beneath it answer the realm `acme`; everything else, including a DN under a
// segment no realm claims, answers the default realm. A DN outside the naming
// context never reaches here — the handlers refuse it first.
function realmFor(dn) {
  let best = realms.DEFAULT_REALM;
  let bestLength = ROOT_DN.length;
  if (!realms.active()) {
    return best;
  }
  realms.list().forEach(function (realm) {
    const candidate = realmBaseDn(realm.id);
    // Longer is deeper, and length is a fair proxy here because every one of
    // these bases is built by the same function from the same root.
    if (isUnder(dn, candidate) && candidate.length > bestLength) {
      best = realm;
      bestLength = candidate.length;
    }
  });
  return best;
}

// Run `fn` in the realm the DN names, which is what every LDAP handler does
// with the DN it was given. One function so that "which store does this
// operation touch" has one answer and one place to read it.
function inRealmOf(dn, fn) {
  return realms.run(realmFor(dn), fn);
}

// ---------------------------------------------------------------------------
// A COUNTER THAT SAYS "SOMETHING IN HERE CHANGED", and the one rule that comes
// with it.
//
// It exists for groupIndexNow() below, which answers "which groups is this
// person in" from a reverse index instead of by walking every entry in the
// tree. The index is only correct while nothing has been written, so every
// write says so here.
//
// **A NEW WRITER MUST CALL touchDirectory().** That is not a style preference:
// a write that does not bump this leaves the index describing the directory as
// it was, and the symptom is a `groups` claim that is one ldapmodify out of
// date in a token that is otherwise perfect — which reads as a claim-mapping
// bug and would be looked for anywhere but here. The call sites today are
// putEntry(), addValues(), the vc-attribute sweep, the LDAP delete, modify and
// modifyDN handlers, and the four typed deletes (applications, SPIFFE, people,
// groups). Every one of them either replaces an entry in this Map or mutates a
// stored entry's attributes in place, and those are the only two things that
// can make the index wrong.
//
// The rebuild ALSO fires when `entries.size` disagrees with the size the index
// was built at. That is a net rather than a design: it catches an add or a
// delete that forgot to call this, and it cannot catch an in-place attribute
// change, which is why the rule above is the rule and this is a second line of
// defence.
// ---------------------------------------------------------------------------
let directoryVersion = 0;

function touchDirectory() {
  directoryVersion++;
  // ---------------------------------------------------------------------
  // AND SINCE 2026-08-27 IT IS ALSO WHAT MAKES THE DIRECTORY PERSIST.
  //
  // This function was already the one thing every writer in this service was
  // required to call — the rule is stated at length above, and it is enforced
  // by prose rather than by the compiler — so it is where persistence hangs
  // rather than at each of the fifteen writers. The argument is in
  // persistence/persistence.js's header and it is worth reading before
  // deciding this line belongs somewhere else: a new writer that forgets
  // touchDirectory() produces a stale groups claim, and a new writer that
  // forgot a separate persist() call would produce an entry that exists until
  // the process restarts and then does not.
  //
  // In memory mode — the default, and every run before this existed — the call
  // returns immediately on a boolean. It never writes anything synchronously
  // in any mode: what it does is set a dirty bit and schedule.
  // ---------------------------------------------------------------------
  persistence.directoryChanged();
}

// ---------------------------------------------------------------------------
// WALKING THIS REALM'S DIRECTORY.
//
// `entries` is the AMBIENT REALM'S store (see the block above it), so
// `entries.forEach()` already means "every entry in this realm" and this
// function is a one-line wrapper over it. It is kept, with its name, for two
// reasons rather than out of sentiment: twenty-four callers say what they mean
// by calling it, and the name is where the reader is told that a walk here is
// realm-scoped without having to go and look at the declaration.
//
// **IT USED TO BE THE WHOLE ISOLATION MECHANISM AND IT IS WORTH KNOWING WHY IT
// IS NOT ANY MORE.** With one Map for the process this function carried a
// containment test — "under my base, minus every realm's subtree inside it" —
// and every reader that did NOT go through it was a leak waiting to be found.
// Two were found: `allGroupEntries()` listing another realm's groups (fixed by
// scoping the walk) and every lookup BY DN answering about the whole tree
// (fixed by scoping each one, then made structural by splitting the store).
// The lesson is in the store's own comment: a scoped walk is not a scoped
// lookup, and only the split makes both true by construction.
// ---------------------------------------------------------------------------
function eachEntryInRealm(fn) {
  entries.forEach(fn);
}

// THE NAMING CONTEXTS THIS SOCKET SERVES: the root, and one per defined realm.
// A list rather than a single value since 2026-08-25 — each realm's directory
// is a separate store reached by naming its base, so publishing only the root
// would leave a client no way to discover that the others are there, and
// discovery is the one job the root DSE has. With no realms defined this is a
// single-valued attribute holding exactly what it always held.
function namingContexts() {
  const out = [ROOT_DN];
  if (!realms.active()) {
    return out;
  }
  realms.list().forEach(function (realm) {
    const base = realmBaseDn(realm.id);
    if (normalizeDn(base) !== normalizeDn(ROOT_DN)) {
      out.push(base);
    }
  });
  return out;
}

// How many entries THIS REALM holds, which is `entries.size` now that the store
// is per realm — a function because two dozen callers already ask this way, and
// because the sentence "this realm's directory" is worth saying at the call
// site. `totalEntries()` up beside the store is the process-wide one, and the
// `ldap.maxEntries` ceiling is checked against THAT: the cap is on the memory
// this process occupies, and a per-realm ceiling would let n realms hold n
// times the number somebody set.
function realmEntryCount() {
  return entries.size;
}

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
  // entryObject() publishes the DN as, so those two and this table have to
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

  // THE SAME SIX ARE NOW ALSO WRITTEN BY THE SPIFFE ISSUING AUTHORITY, onto the
  // entry of every identity it mints an X509-SVID for — the same names on
  // purpose, because a certificate is a certificate however it arrived and a
  // second set spelt `svid*` would mean a filter written for one path silently
  // misses the other. The three below go with them and exist only on that path:
  // an SVID is minted afresh every half-lifetime, so the six above are ASSIGNED
  // rather than appended there and these are what is left to say how many times
  // and since when. See applySpiffeCertificate().
  'x509svidsIssued', 'x509firstIssued', 'x509lastIssued',

  // On the entries a DECENTRALIZED IDENTIFIER seeds, and load-bearing rather
  // than decorative: the entry is NAMED by a hash of the DID (didPlan() says
  // why), so `didSubject` is the only place the identifier itself survives and
  // the only thing locateEntry() can find the entry by. There is no standard
  // attribute type for "the DID this entry is", which is unsurprising — DID Core
  // postdates the LDAP schema documents by two decades and nobody registered
  // one.
  'didSubject', 'didMethod',

  // On the entries a SPIFFE identity seeds, and load-bearing for exactly the
  // reason the two above it are: the entry is NAMED by a hash of the SPIFFE ID
  // (spiffePlan() says why), so `spiffeSubject` is the only place the
  // identifier itself survives and the only thing locateEntry() can find the
  // entry by. `spiffePath` and `spiffeTrustDomain` are the two halves of it a
  // reader actually wants to filter on. Note that these are DIFFERENT NAMES
  // from `spiffeId` and `spiffeAgentId` one container over: those are on
  // REGISTRATION entries under ou=spiffe and mean "the identity this entry
  // configures", where these are on a PERSON under ou=users and mean "an
  // identity that authenticated here". Merging the two spellings would file a
  // registration entry and its holder under one name.
  'spiffeSubject', 'spiffePath', 'spiffeTrustDomain',

  // WHETHER THIS IDENTITY MAY STILL BE ISSUED A CREDENTIAL HERE, and this is
  // the one group in this list whose name could be read as a claim the service
  // does not make. **SPIFFE HAS NO REVOCATION** — `GET /spiffe` says so, and
  // the Workload API's `crl` field is empty because empty is the conforming
  // value, not because it is unimplemented. `spiffeCredentialStatus` is NOT a
  // certificate status and nothing verifying an SVID consults it: it records
  // the three things in the registry that end an identity's ability to get a
  // NEW one — its registration entry deleted, its agent banned, its agent
  // deleted — and the certificates already in the world go on verifying until
  // they expire, exactly as SPIFFE intends. The reason is a sentence rather
  // than a code because it is the only thing that explains a status a reader
  // did not expect. `spiffeRevokedAt` is never cleared, which is
  // `mfaLastAuthTime`'s rule: it is the history the current-state flag beside
  // it deliberately does not keep.
  'spiffeCredentialStatus', 'spiffeCredentialStatusReason', 'spiffeRevokedAt',

  // On any entry whose person authenticated somewhere that STATES how they did
  // it — which today is the sign-in screen and nothing else, because amr is an
  // OIDC vocabulary and a Kerberos AS-REQ has nothing to put in it. There is no
  // standard attribute type for "this account authenticated with more than one
  // factor": the nearest things in the wild are Active Directory's msDS-*
  // attributes, which are Microsoft's own names for something else entirely, and
  // pretending to be one of those would be worse than obviously not being one.
  'authnMethod', 'mfaAuthenticated', 'mfaLastAuthTime',

  // The HOBA client public keys registered at /.well-known/hoba/register, one
  // value per key as `<kid> <base64 DER>`. Another invention for the same
  // reason as the two above: RFC 7486 postdates the LDAP schema documents and
  // registered no attribute type, and the nearest standard thing —
  // `userPKCS12`, or `userCertificate` again — is a different object entirely.
  // It is a CREDENTIAL, which the two lists above are not: anyone who can read
  // this directory can see which key authenticates somebody, though not sign
  // with it. That is the same honest position the Kerberos passwords and
  // `oauthClientSecret` are in, and it is on GET /scim rather than left to be
  // found.
  'hobaPublicKey',

  // WHERE THIS PERSON CAME FROM, on an entry a FEDERATED sign-in created. Five
  // names, and they exist because this is the one path in this service where an
  // entry is created out of somebody ELSE'S assertion — every other entry under
  // ou=users was made because a credential was presented HERE, and the
  // difference matters to whoever reads the directory afterwards. A person with
  // `federationIssuer` on their entry has never authenticated to this service
  // at all.
  //
  // `federationAttribute` is the useful one and the one with no analogue
  // anywhere else here: it lists which of this entry's OTHER attributes came
  // off a foreign assertion rather than out of the invented-persona sweep. Both
  // kinds are ordinary directory attributes and look identical, and applyVcAttributes()
  // fills in `mail`, `givenName` and the rest for everybody — so without this
  // there is no way to tell a real email address a partner sent from one this
  // service made up, which is exactly the question a federated directory entry
  // raises. Nothing reads it; it is there to be read.
  'federationRelationship', 'federationIssuer', 'federationSubject',
  'federationLastSeen', 'federationAttribute',

  // WHAT THIS PERSON AGREED AN APPLICATION MAY ASK FOR ON THEIR BEHALF, one
  // value per (application, scope) — `20260901143000Z openid webapp1`. Invented
  // for the same reason as everything above it: OAuth 2.0 postdates the LDAP
  // schema documents and registered no attribute type for consent, and the
  // nearest standard thing is nothing at all. The grammar is
  // `common/consent.js`'s and is argued there, including why the client_id is
  // LAST (it is the one field with no rule about what it may contain, so it
  // takes the remainder of the value).
  //
  // It is NOT a credential and it grants nothing: it is a record of an answer,
  // and the authorization endpoint reads it only to decide whether to draw the
  // consent screen. The OTHER half of the feature is `oauthGlobalConsent`,
  // which is on an APPLICATION's entry and is in the applications schema rather
  // than in this list.
  'oauthConsent'
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
  log.debug('Entering learnName().');
  const canonical = String(spelling);
  const lower = canonical.toLowerCase();
  const known = CANONICAL_NAMES[lower];
  if (known === undefined) {
    CANONICAL_NAMES[lower] = canonical;
    log.debug('Leaving learnName().');
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
  log.debug('Leaving learnName().');
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

// And the SCIM mapping's two inventions, `scimActive` and `scimExternalId`, for
// the same reason and from the same kind of source. They are a FIFTH list, which
// is one more than the comment above learnName() named — and the check is what
// makes a fifth affordable: the two names are this service's own, nothing else
// spells them, and if that ever stops being true the warning says which table to
// look in. scim_map.js is a library that registers nothing and requires only
// helpers.js and vc_claims.js, so requiring it here moves no route and closes no
// cycle.
scimMap.OWN_NAMES.forEach(function (spelling) {
  learnName(spelling, 'the SCIM mapping');
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
  touchDirectory();
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
  const dcValue = baseDn().split(',')[0].split('=')[1] || 'example';
  putEntry(baseDn(), {
    objectClass: ['top', 'domain', 'dcObject'],
    dc: dcValue,
    description: 'The mock STS directory. Every bind succeeds; nothing here ' +
      'is a real account.'
  }, { origin: 'seed' });
  putEntry(usersDn(), {
    objectClass: ['top', 'organizationalUnit'],
    ou: 'users',
    description: 'People. An entry appears here for anyone who authenticates ' +
      'to this service through any protocol.'
  }, { origin: 'seed' });
  putEntry(groupsDn(), {
    objectClass: ['top', 'organizationalUnit'],
    ou: 'groups',
    description: 'Groups, as groupOfNames — membership is the multi-valued ' +
      '`member` attribute holding the DN of each member.'
  }, { origin: 'seed' });
  putEntry(applicationsDn(), {
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
  putEntry(federationsDn(), {
    objectClass: ['top', 'organizationalUnit'],
    ou: 'federations',
    description: 'Federation relationships: the foreign identity providers ' +
      'this service consumes assertions from, and the foreign service ' +
      'providers it asserts to. THIS CONTAINER IS THE REGISTER — an ' +
      'ldapmodify of fedSigningCertificate here changes which signer the next ' +
      'assertion is verified against, and an ldapmodify of fedEnabled turns a ' +
      'partner on. It is the one store in this directory whose contents are a ' +
      'SECURITY DECISION rather than a record: everything else here is ' +
      'permissive by design, and a federation endpoint cannot be. ' +
      'federation/federation.js holds the schema; GET /admin/ldap/federations ' +
      'publishes it.'
  }, { origin: 'seed' });
  putEntry(spiffeDn(), {
    objectClass: ['top', 'organizationalUnit'],
    ou: 'spiffe',
    description: 'The SPIFFE trust domain this service is the issuing ' +
      'authority for. Two containers beneath: entries (registration entries, ' +
      'which decide what gets issued) and agents (what has attested). ' +
      'spiffe_registry.js holds the schema; GET /admin/ldap/spiffe publishes it.'
  }, { origin: 'seed' });
  putEntry(spiffeEntriesDn(), {
    objectClass: ['top', 'organizationalUnit'],
    ou: 'entries',
    description: 'SPIFFE registration entries. THIS CONTAINER IS THE ' +
      'REGISTRY — an ldapmodify of spiffeX509SvidTtl here changes the ' +
      'lifetime of the next SVID the Workload API hands out, because nothing ' +
      'caches these.'
  }, { origin: 'seed' });
  putEntry(spiffeAgentsDn(), {
    objectClass: ['top', 'organizationalUnit'],
    ou: 'agents',
    description: 'SPIFFE agents that have attested here. A RECORD rather ' +
      'than configuration: everything on these entries was written by this ' +
      'service, and nothing about an agent is editable from the console. ' +
      'Node attestation is never verified — whatever an agent claimed is ' +
      'what is written down.'
  }, { origin: 'seed' });
  putEntry('cn=admin,' + baseDn(), {
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
    putEntry('uid=' + person.uid + ',' + usersDn(), {
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
  putEntry('cn=developers,' + groupsDn(), {
    objectClass: ['top', 'groupOfNames'],
    cn: 'developers',
    description: 'A groupOfNames. Membership is the `member` attribute.',
    member: ['uid=alice,' + usersDn(), 'uid=bob,' + usersDn()]
  }, { origin: 'seed' });
  putEntry('cn=directory-admins,' + groupsDn(), {
    objectClass: ['top', 'groupOfNames'],
    cn: 'directory-admins',
    description: 'A second group, so a search for groups returns more than one.',
    member: ['uid=carol,' + usersDn()]
  }, { origin: 'seed' });
  // This realm's own count. It reads `entries.size` through
  // realmEntryCount()'s walk either way now that the store is per realm, and
  // the walk is kept because the sentence it produces — "seeded N entries under
  // dc=acme,…" — is about a base rather than about a store, and that is the
  // number somebody checks a directory against.
  let seeded = 0;
  eachEntryInRealm(function () { seeded++; });
  log.info('ldap: seeded ' + seeded + ' entries under ' + baseDn() + '.');
  log.debug('Leaving seed().');
}

// The default realm's subtree, at require time, exactly as before realms
// existed: `realms.currentId()` is the default outside any request, so
// `baseDn()` is ROOT_DN and every DN seed() writes is the one it always wrote.
seed();

// ---------------------------------------------------------------------------
// A REALM'S SUBTREE IS BUILT WHEN THE REALM IS, AND EMPTIED WHEN IT IS REMOVED.
//
// **WHY ON CREATE RATHER THAN LAZILY.** Every other per-realm store in this
// service is built on first touch (`realms.keyed()`), and that works because
// every one of them is reached through a request that has already entered the
// realm. This one is not: an `ldapsearch` on 389 arrives with a base DN and no
// realm at all, so "first touch" for the directory can be a client asking for
// `dc=acme,dc=example,dc=com` — and the honest answer to that, if the subtree
// were not there, is LDAP_NO_SUCH_OBJECT. A realm that exists over HTTP and
// does not exist over LDAP is exactly the kind of half-truth this service is
// supposed to make impossible to build. So the subtree exists from the moment
// the realm does. `realms.onCreate()` was added for this and has one caller.
//
// **IT IS THE SAME seed(), RUN IN THE REALM.** Not a copy, and not a reduced
// version: a realm is a whole logical copy of this service, so its directory
// starts as the same smallest-useful tree — the six containers, the bind
// account, alice, bob, carol and the two groups — under its own base. Anything
// else would mean a realm where an `ldapsearch` teaches less than the default
// one does, and the seeded people are the reason that search shows anything at
// all. They are separate objects from the default realm's: `uid=alice,ou=users,
// dc=acme,dc=example,dc=com` shares nothing with `uid=alice,ou=users,
// dc=example,dc=com` but a first name.
//
// **THE TWO ADMIN ROLE GROUPS ARE NOT SEEDED ANYWHERE AND ARE NOT THE POINT
// HERE.** `ou=groups` under a realm is that realm's, but the console reads the
// roles from the DEFAULT realm only — see the note above the admin_rbac
// setDirectory() install further down. A `cn=admin-write` created inside `acme`
// is an ordinary group in acme's directory and grants nothing.
// ---------------------------------------------------------------------------
realms.onCreate(function (id) {
  log.debug('Entering the realm directory builder. id=' + id);
  realms.run(realms.get(id), function () {
    seed();
    // The vc-attribute sweep, for the reason it is run once after the default
    // seed: the seeded people are written before anything reads them, and a
    // realm whose alice had no birthdate while her credential asserted one is
    // the same disagreement in a new place.
    populateVcAttributes();
  });
  log.info('ldap: built the "' + id + '" realm\'s subtree at ' +
           realmBaseDn(id) + '.');
  log.debug('Leaving the realm directory builder.');
});

// ---------------------------------------------------------------------------
// AND REMOVING A REALM TAKES ITS SUBTREE WITH IT.
//
// The same argument `realms.js` makes for every other store: a realm created
// again under the same id must not inherit the last one's people, groups,
// applications, federation relationships or SPIFFE registrations. Here it is
// sharper than elsewhere, because those are the things somebody would go
// looking for by DN — a re-created `acme` whose `uid=alice` was somebody else's
// alice is a directory that lies.
//
// **NOTHING IS EVER DELETED FROM `ou=users` — EXCEPT WITH THE REALM THAT OWNED
// IT.** That rule is about a PERSON being removed while their realm stands, and
// it holds: no door here deletes an entry from a realm that still exists. This
// is the realm itself going away, and leaving its subtree behind would not be
// keeping the rule, it would be leaking a tree nobody can reach — every path to
// it, HTTP and LDAP alike, named a realm that is gone.
// ---------------------------------------------------------------------------
realms.onRemove(function (id) {
  log.debug('Entering the realm directory purge. id=' + id);
  // **THIS NO LONGER DELETES ANYTHING, AND THE HANDLER IS KEPT ANYWAY.** It
  // used to walk the one shared Map deleting every DN under the realm's base;
  // the store is `realms.map()` now, which registers its own purge, so the
  // realm's whole directory is dropped in one reference. There is nothing left
  // behind to find: the realm's root entry, its six containers and everything
  // written into them lived in that store and nowhere else.
  //
  // It stays because this is where a reader looks for the answer to "what
  // happens to the directory when a realm goes", and finding an empty file
  // there would read as the question never having been asked. The log line is
  // the other half — a realm's directory vanishing silently is the kind of
  // thing somebody notices an hour later.
  //
  // ORDERING, since it is the only reason a count is not reported: realms.js
  // runs purges in REGISTRATION order, and `realms.map()`'s purge was
  // registered when `entries` was created near the top of this file — long
  // before this handler. So by the time this runs the Map is already gone, and
  // any number it printed would be zero.
  touchDirectory();
  log.info('ldap: the "' + id + '" realm\'s directory at ' + realmBaseDn(id) +
           ' went with the realm; its store is dropped whole.');
  log.debug('Leaving the realm directory purge.');
});

// ---------------------------------------------------------------------------
// AND THE DIRECTORY HANDS ITSELF TO PERSISTENCE.
//
// Two functions, installed WHOLE at require time. `persistence.js` validates
// the pair when it is given them rather than testing for each at every call,
// for `admin.js`'s logout-reader reason: a half-filled slot would leave that
// module able to READ this directory and unable to restore it, which looks
// exactly like an empty database and is the one failure mode that costs a day.
//
// **BOTH TAKE A REALM ID AND NEITHER ENTERS THE REALM**, which is deliberate
// and is the opposite of what every LDAP handler in this file does. A handler
// resolves a realm from the DN it was given and runs its body inside
// `realms.run()`, because everything below it reads `entries` ambiently. These
// two do not have a DN, they have a realm id, and `entries.realmMap(id)` names
// a realm's store directly — so entering the realm would buy nothing and would
// mean a restore of twelve realms did twelve `AsyncLocalStorage` entries for no
// reason.
//
// **replaceRealm() DOES NOT GO THROUGH putEntry(), AND THAT IS THE POINT.**
// putEntry() stamps `createTimestamp` and `modifyTimestamp` with NOW, which is
// exactly right for an entry being created and exactly wrong for one being
// restored: every person in a restored directory would report having been
// created at the moment the process started. So the stored object is
// reconstructed as it was written, timestamps included, and the two
// operational attributes it carries are left alone. The DN is re-normalised
// through this file's `normalizeDn()` rather than trusting the key the store
// wrote, because that function is the one place in this service that decides
// two spellings are one entry and a stored key from an older version of it must
// not be believed over the current one.
// ---------------------------------------------------------------------------
persistence.setDirectory({
  // Every entry in one realm, keyed the way the store keys it, for the diff
  // that decides what to write.
  realmEntries: function (realmId) {
    const out = [];
    entries.realmMap(realmId).forEach(function (entry, key) {
      out.push({ key: key, entry: entry });
    });
    return out;
  },

  // One realm's whole directory, replaced by what was read back. Called only
  // from persistence.start(), before the HTTP listener binds and before the
  // LDAP socket is opened, so nothing can be reading this store while it is
  // being swapped.
  replaceRealm: function (realmId, list) {
    log.debug('Entering replaceRealm(). realmId=' + realmId);
    const store = entries.realmMap(realmId);
    // CLEARED rather than merged. A restore is "this is the directory", not
    // "these entries as well as the seed": a merge would leave behind an entry
    // that was deleted in the last run and reseeded in this one, and the
    // person who deleted it would find it back.
    store.clear();
    list.forEach(function (row) {
      const stored = {
        dn: String(row.dn),
        attributes: row.attributes || {},
        createdAt: row.createdAt || null,
        modifiedAt: row.modifiedAt || row.createdAt || null
      };
      if (row.origin) {
        stored.origin = String(row.origin);
      }
      store.set(normalizeDn(stored.dn), stored);
    });
    // The reverse group index describes a directory that is no longer there.
    // This is the one call to touchDirectory() in this file that is NOT a
    // write to be persisted — persistence.js ignores it, because it is
    // restoring — and it is still required, for the index.
    touchDirectory();

    // -------------------------------------------------------------------
    // AND THE PEOPLE ARE PUT BACK IN THE IDENTITY REGISTER, WHICH IS A
    // SEPARATE STORE AND WAS THE FIRST BUG THIS FEATURE HAD.
    //
    // `/admin/users`, `/admin-api/users` and the user drill-down do not read
    // this directory. They read `admin_stats.js`'s identity register, which
    // until 2026-08-27 could only be filled by somebody AUTHENTICATING — and
    // that was a complete account of how a person came to be known, because
    // until then a person could only come to be known that way. A restored
    // directory is the first thing that ever put an entry under `ou=users`
    // without a sign-in, and the symptom was exact and misleading: twenty
    // entries restored, `ldapsearch` and `/ldap/directory` showing all of
    // them, `/admin/users` reporting `known: 0`. It reads as a failed
    // restore and is a page reading a different store.
    //
    // They are registered as RESTORED rather than as authenticated —
    // `noteRestoredIdentity()` argues the distinction and why the counts are
    // deliberately not brought back with them.
    //
    // **THIS IS THE ONE PART OF replaceRealm() THAT ENTERS THE REALM**, and it
    // is the exception the header above it warns is coming. Everything else
    // here reaches the store through `entries.realmMap(id)`, which names a
    // realm directly and needs no ambient one. These two do not have that
    // shape: `isPersonEntry()` compares against `usersDn()`, and the identity
    // register is itself a `realms.map()`. Both are ambient by construction,
    // so this pass runs inside the realm and the rest does not.
    // -------------------------------------------------------------------
    realms.run(realms.get(realmId) || realms.DEFAULT_REALM, function () {
      let people = 0;
      store.forEach(function (stored) {
        if (!isPersonEntry(stored)) {
          return;
        }
        // ---------------------------------------------------------------
        // A SEEDED PERSON IS SKIPPED, AND THAT IS WHAT KEEPS A RESTORED
        // PROCESS'S /admin/users IDENTICAL TO A FRESH ONE'S.
        //
        // alice, bob and carol are written by seed() on every start, in every
        // realm, and have never been in the identity register — that page's
        // own description is "every userid this service has been given as part
        // of an interaction that SUCCEEDED", and being seeded is not an
        // interaction. Registering them here would mean a fresh service listed
        // nobody and the same service after one restart listed three people
        // who had still done nothing, which is a difference somebody would
        // reasonably read as a bug.
        //
        // So what gets registered is what a fresh process would also have had:
        // people somebody CREATED (`origin: 'console'`, and the SCIM and
        // management API doors that share it), people an `ldapadd` wrote, and
        // people who AUTHENTICATED — whose counts start at zero again either
        // way, because those are statistics about a process.
        // ---------------------------------------------------------------
        if (stored.origin === 'seed') {
          return;
        }
        // The `uid` if there is one, and the DN otherwise. A person written by
        // any door in this service has a uid; one added by hand with ldapadd
        // may not, and a person the console cannot name at all is worse than
        // one it names by DN.
        const uid = (stored.attributes.uid || [])[0];
        if (stats.noteKnownIdentity(uid || stored.dn, 'restored')) {
          people++;
        }
      });
      log.info('ldap: ' + people + ' restored person/people in the "' +
               realmId + '" realm are known to /admin/users, marked as ' +
               'restored rather than as having authenticated here — they ' +
               'have not, in this process.');
    });
    log.debug('Leaving replaceRealm(). ' + store.size + ' entry/entries.');
  }
});

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
  log.debug('Entering addValues().');
  const key = String(name).toLowerCase();
  const have = stored.attributes[key] || [];
  const added = valuesOf(values).filter(function (value) {
    return value !== '' && have.indexOf(value) === -1;
  });
  if (!added.length) {
    log.debug('Leaving addValues().');
    return false;
  }
  stored.attributes[key] = have.concat(added);
  touchDirectory();
  log.debug('Leaving addValues().');
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

// A SPIFFE ID, which is the FOURTH shape of identity this directory files. The
// test is the scheme and nothing more: `spiffe_id.js` owns what a valid one is,
// and a second grammar here would be a second definition that eventually
// disagrees with it. Anything scheme-shaped and invalid never reaches this
// module — recordAuthentication() is only called with an identity a credential
// was accepted for, and spiffe_auth.js parses before it accepts.
const SPIFFE_SHAPED = /^spiffe:\/\//i;

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
// ONE ENTRY PER PERSON, WHATEVER PROTOCOL BROUGHT THEM — and the two functions
// below are the whole of how that is kept true.
//
// It was already true for most of this service and by accident rather than by
// design: identityOf() in admin_stats.js strips the `urn:sts-mock:user:` prefix
// and the Kerberos realm, so `rcbj`, `urn:sts-mock:user:rcbj` and
// `rcbj@STS.MOCK` reach autoCreateUser() as one key and namePlan() builds one
// DN from it. Every name-shaped family — OAuth 2.0, OpenID Connect,
// WS-Federation, WS-Trust, both SAML profiles, Kerberos, SPNEGO, an LDAP bind —
// therefore landed on `uid=rcbj,ou=users` already.
//
// What did NOT fold was the one identity that is a DN rather than a name. A
// client certificate `CN=rcbj,O=Example` becomes `cn=rcbj,ou=users`
// (certificatePlan()'s second rule), which is a SECOND object for a person who
// already had one — and the reverse order produces the same pair, since a
// password sign-in after a handshake would build `uid=rcbj` beside the
// `cn=rcbj` the certificate made. Two entries for one person is the failure
// this service already refuses everywhere else it can: /admin/users keys on the
// normalised name for exactly this reason, and a directory disagreeing with it
// makes both pages wrong about how many people are here.
//
// So a plan that is about to name an entry asks first whether this person
// already has one, and folds onto it where they do. The lookup is by the two
// things that can carry a username on an entry under ou=users:
//
//   * the `uid` attribute, which is what namePlan() writes and what every
//     name-shaped identity here is filed under;
//   * the entry's own NAMING RDN VALUE, which is what a certificate's entry is
//     called (`cn=rcbj`) and what an entry added by an LDAP client is called
//     whatever attribute type it used.
//
// Case-insensitively, because the store already keys DNs lower-cased — `uid=RCBJ`
// and `uid=rcbj` were one entry before this function existed, and a lookup that
// was stricter than the store would report "no such person" about an entry the
// very next putEntry() would collide with.
//
// SCOPED TO ENTRIES DIRECTLY UNDER ou=users, and that is the same placement rule
// /admin/groups reports by and the one the add handler enforces. This directory
// is schemaless: a client can put a `person` objectClass on a group, so believing
// the class would fold a person onto a group. Placement is the rule that cannot
// be lied to.
// ---------------------------------------------------------------------------
function usernameOfEntry(stored) {
  const rdn = splitRdns(stored.dn)[0] || '';
  const pairs = rdnPairs(rdn);
  return pairs.length ? unescapeDnValue(pairs[0].value) : '';
}

// THE ENTRY THAT ALREADY RECORDS THIS DECENTRALIZED IDENTIFIER, wherever it is
// and whatever it is named.
//
// It is found by what the entry RECORDED and never by rebuilding the digest,
// which is the rule locateEntry() already stated for itself and which now
// matters twice over: since a linked DID goes onto its owner's entry
// (didPlan()), the digest is not where it lives at all. A wallet that was issued
// a credential as `erin` and later presents it to the Verifier arrives with the
// DID alone and no link — and without this lookup that presentation would create
// the very second entry the link exists to avoid, for a person whose entry
// already names that identifier.
function entryByDidSubject(did) {
  log.debug('Entering entryByDidSubject().');
  const wanted = String(did == null ? '' : did).trim();
  if (!wanted) {
    log.debug('Leaving entryByDidSubject().');
    return null;
  }
  let found = null;
  eachEntryInRealm(function (entry) {
    if (found) {
      return;
    }
    if ((entry.attributes.didsubject || []).indexOf(wanted) >= 0) {
      found = entry;
    }
  });
  log.debug('Leaving entryByDidSubject().');
  return found;
}

// The entry that already records this SPIFFE identity, wherever it is and
// whatever it is named — the same lookup `entryByDidSubject()` performs and for
// the same reason. An SVID presented at the SPIRE Server API, a JWT-SVID
// validated at the Workload API and an agent attesting can all name one
// identity, and rebuilding the digest would be a second definition of where the
// entry lives.
function entryBySpiffeSubject(id) {
  log.debug('Entering entryBySpiffeSubject().');
  const wanted = String(id == null ? '' : id).trim();
  if (!wanted) {
    log.debug('Leaving entryBySpiffeSubject().');
    return null;
  }
  let found = null;
  eachEntryInRealm(function (entry) {
    if (found) {
      return;
    }
    if ((entry.attributes.spiffesubject || []).indexOf(wanted) >= 0) {
      found = entry;
    }
  });
  log.debug('Leaving entryBySpiffeSubject().');
  return found;
}

function existingUserEntry(name) {
  log.debug('Entering existingUserEntry().');
  const wanted = String(name == null ? '' : name).trim().toLowerCase();
  if (!wanted) {
    log.debug('Leaving existingUserEntry().');
    return null;
  }
  // The common case first and without a scan: this is called on every
  // authentication, and the overwhelming majority of them are a returning person
  // whose entry is exactly where namePlan() put it.
  const direct = getEntry('uid=' + name + ',' + usersDn());
  if (direct) {
    log.debug('Leaving existingUserEntry().');
    return direct;
  }
  const parent = normalizeDn(usersDn());
  let found = null;
  eachEntryInRealm(function (entry) {
    if (found) {
      return;
    }
    if (normalizeDn(parentDn(entry.dn)) !== parent) {
      return;
    }
    const names = (entry.attributes.uid || []).concat([usernameOfEntry(entry)]);
    const hit = names.filter(function (value) {
      return String(value).trim().toLowerCase() === wanted;
    });
    if (hit.length) {
      found = entry;
    }
  });
  log.debug('Leaving existingUserEntry().');
  return found;
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
  const already = naming ? existingUserEntry(naming.value) : null;
  if (subject && isUnder(subject, baseDn()) && getEntry(parentDn(subject))) {
    dn = subject;
  } else if (already) {
    // THE PERSON THIS CERTIFICATE NAMES IS ALREADY HERE, so this is not a new
    // entry — it is a second credential for one that exists. `CN=rcbj` and the
    // `rcbj` who signed in at the password screen are one person as far as this
    // service is concerned (it authenticates nobody, so a name is a name), and
    // filing them apart would put two objects in the directory for one row on
    // /admin/users.
    //
    // Nothing is lost by folding: `merge` below carries the whole subject, the
    // issuer, the serial and the validity onto the entry, so what the
    // certificate said is recorded on the person it said it about. What it
    // COSTS is the same collapse the header already accepts one paragraph up,
    // reaching one step further — two `CN=rcbj` from different CAs were already
    // one entry, and now they are the same entry as the login name. The full
    // subjects are all listed in `x509subject`, so it stays visible rather than
    // silent, and the console still files them as separate identities because
    // it keys on the whole DN.
    dn = already.dn;
  } else if (naming) {
    dn = naming.attribute + '=' + naming.rdnValue + ',' + usersDn();
  } else {
    // A subject with no parsable RDN at all. It is still an identity that
    // authenticated, so it gets an entry rather than being dropped; `uid=` is
    // the shape every other auto-created entry here uses.
    dn = 'uid=' + escapeDnValue(subject || 'unknown') + ',' + usersDn();
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
  // THE OTHER HALF OF THE FOLD certificatePlan() does, and it is needed because
  // the two credentials can arrive in either order. Where a client certificate
  // came first this person's entry is called `cn=rcbj,ou=users`, and building
  // `uid=rcbj,ou=users` beside it would be the second object the fold exists to
  // prevent — so the name lands on the entry that is already theirs.
  //
  // `uid` is MERGED onto it in that case: the entry was named by whatever
  // attribute the other credential used, and the username is a fact about this
  // person that nothing on it recorded. It also makes the next lookup the cheap
  // one — existingUserEntry() finds a uid without a scan.
  const already = existingUserEntry(name);
  log.debug('Leaving namePlan().' + (already ? ' Folding onto ' + already.dn + '.' : ''));
  return {
    dn: already ? already.dn : 'uid=' + name + ',' + usersDn(),
    attributes: {
      objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
      uid: name,
      cn: persona.display,
      sn: persona.family,
      givenName: persona.given,
      displayName: persona.display + ' (mock)',
      mail: persona.email
    },
    merge: already ? { uid: name } : {}
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
  // ---------------------------------------------------------------------
  // WHERE THIS SERVICE KNOWS WHOSE DID IT IS, THE ENTRY IS THEIRS.
  //
  // A DID names nobody by itself — that is the whole of why the entry below is
  // named by a digest — so most of the time there is nothing to fold onto and
  // the digest-named entry is the honest answer. But at the Credential
  // Endpoint there IS a link, and it is exact: vc_issuer.js decides who a
  // credential is about from the access token and derives the holder's did:jwk
  // from the key the wallet proved possession of, in one call, so it passes the
  // username through as `linkedTo`. A DID arriving with one is this person's
  // second identifier and not a second person.
  //
  // What this reverses is an argument written at that call site and worth
  // stating rather than deleting: one wallet can hold several holder keys for
  // one person, and filing them all under the access token's name was said to
  // lose the ability to tell them apart. It does not — `didSubject` is
  // multi-valued and every DID is listed on the entry, so all of them are
  // visible on one object instead of one each on several. One person is one
  // entry here, which is the rule that wins.
  //
  // A DID presented with no link — the OID4VP Verifier is shown one, or
  // /did/generate mints one — still gets its own entry. There is nothing to
  // attach it to, and inventing a person to attach it to would be worse than a
  // digest for a name. If it was linked EARLIER, locateEntry() finds the entry
  // by `didSubject` before this plan is ever consulted, so no duplicate
  // appears.
  // ---------------------------------------------------------------------
  const linked = String(info.linkedTo || '').trim();
  if (linked) {
    const plan = namePlan(linked);
    const facts = { didSubject: did, didMethod: method };
    // On BOTH, because autoCreateUser() reads `attributes` when it creates the
    // entry and `merge` when it finds one — this person may or may not have
    // authenticated by name before their wallet asked for a credential.
    plan.attributes = Object.assign({}, plan.attributes, facts);
    plan.merge = Object.assign({}, plan.merge, facts);
    plan.note = note;
    // The invented person is seeded from the USERNAME and not from the DID.
    // Without this the entry would be filled by two different personas — the
    // one the sign-in path invented for `rcbj` and the one a digest invents —
    // which disagree on every attribute the credential asserts.
    plan.personaKey = linked;
    log.debug('Leaving didPlan(). Linked to ' + linked + ' at ' + plan.dn + '.');
    return plan;
  }
  // NOT LINKED, so this identifier names its own entry — unless one already
  // records it. That happens on the ordinary path through the Decentralized
  // Identity endpoints: the DID was linked to a person when their credential was
  // ISSUED, and the wallet then presents it to the Verifier with nothing saying
  // whose it is. Rebuilding the digest there would file one identifier in two
  // places.
  const recorded = entryByDidSubject(did);
  const dn = recorded ? recorded.dn
                      : 'uid=' + escapeDnValue(uid) + ',' + usersDn();
  log.debug('Leaving didPlan(). ' + (recorded ? 'Already recorded at ' + dn + '.'
                                              : 'uid=' + uid + ' for ' + did.slice(0, 48)));
  // Nothing to merge onto an entry that already exists. Unlike a certificate,
  // which is reissued with a new serial and a new validity for the same person,
  // a DID presented a second time is byte-for-byte the DID that named this entry
  // in the first place.
  return {
    dn: dn,
    // The persona on an entry that already exists is not rewritten — plan
    // attributes are read only when one is CREATED — but the key it was seeded
    // from must still be that entry's own, or the fill below would invent a
    // second person for it. personaKeyOf() answers that from the entry itself.
    personaKey: recorded ? personaKeyOf(recorded) : did,
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
// THE FOURTH SHAPE: A SPIFFE IDENTITY.
//
// `spiffe://sts.mock/ns/default/sa/db` is not a name, not a DN and not a DID.
// It is closest to a DID — one opaque identifier with structure inside it that
// this service must not try to read as a person's name — so it is filed the
// same way and for the same reasons, which are worth restating because each one
// was a decision:
//
//   **NAMED BY A DIGEST.** `uid=spiffe-<12 hex>,ou=users`. Written out as a DN
//   the identity would carry `//` and `:`, and the last path segment (`db`,
//   `web`, `api`) is exactly the kind of short common word that collides with a
//   person somebody signed in as. A workload called `db` and a DBA called `db`
//   are not the same identity and must not fold onto one entry — which is the
//   opposite of what `existingUserEntry()` does for names, deliberately, and is
//   why this plan does not consult it.
//
//   **FOUND BY WHAT IT RECORDED.** `spiffeSubject` is multi-valued and
//   `entryBySpiffeSubject()` is what `locateEntry()` uses, so the naming rule
//   can change without orphaning every entry written under the old one. It also
//   means the same identity arriving three ways — an X509-SVID at the SPIRE
//   Server API, an agent attesting, a JWT-SVID validated at the Workload API —
//   REUSES one entry rather than creating three. That is the whole of "if the
//   identity is already present, reuse it".
//
//   **THE TRUST DOMAIN AND THE PATH ARE SPLIT OUT**, because those are the two
//   questions somebody browsing this directory asks — "who is from example.org"
//   and "what is under /spire/agent" — and neither is answerable by substring
//   matching on the identifier without also matching things that merely contain
//   it.
//
// **A WORKLOAD IS FILED WITH THE PEOPLE, WHICH IS A DECISION AND NOT AN
// OVERSIGHT.** `ou=applications` exists (rule 3g) and a workload is arguably
// one. But `ou=users` here is not "humans" — it is every identity that
// PRESENTED A CREDENTIAL AND HAD IT ACCEPTED, which is what /admin/users lists
// and what a TLS client certificate for a machine already lands in.
// `ou=applications` is the registry of things this service was ASKED ABOUT, and
// an application there is the audience of a token rather than the subject of
// one. A SPIFFE identity is a subject.
// ---------------------------------------------------------------------------
function spiffeUid(id) {
  return 'spiffe-' + crypto.createHash('sha256').update(String(id), 'utf8')
    .digest('hex').slice(0, 12);
}

function spiffePlan(info) {
  log.debug('Entering spiffePlan().');
  const id = String(info.key || '').trim();
  // The two halves, taken apart HERE and not by a second parser. Anything that
  // is not `spiffe://<trust domain>/<path>` cannot reach this — see
  // SPIFFE_SHAPED — so the split is arithmetic rather than validation.
  const withoutScheme = id.slice('spiffe://'.length);
  const slash = withoutScheme.indexOf('/');
  const domain = slash >= 0 ? withoutScheme.slice(0, slash) : withoutScheme;
  const path = slash >= 0 ? withoutScheme.slice(slash) : '';
  const persona = vcClaims.personaFor(id);
  const uid = spiffeUid(id);
  // Its own sentence, like didPlan()'s, because the default — "authenticated
  // through X" — is not quite what happened: a workload presented a credential
  // this service or another part of this trust domain issued, and no human was
  // anywhere near it.
  //
  // AND A SECOND SENTENCE FOR THE SECOND WAY IN. An ISSUANCE is not a
  // presentation and must not describe itself as one: the entry exists because
  // this trust domain minted a certificate naming this identity, which is a
  // weaker statement than "it authenticated" and is the honest one. Both
  // sentences can end up on one entry — `description` accumulates — and that is
  // the point, because "issued to, and has since presented one" is a different
  // history from either alone.
  const note = info.event === 'issuance'
    ? 'was issued an X509-SVID by this trust domain'
    : 'named by a SPIFFE identity presented through ' +
      String(info.protocol || 'an unstated protocol') +
      (info.method ? ' (' + info.method + ')' : '');
  // An entry that already records this identity, wherever it is. This is what
  // makes the three acceptance points — an X509-SVID over mutual TLS, an agent
  // attesting, a JWT-SVID validated — land on ONE entry.
  const recorded = entryBySpiffeSubject(id);
  const dn = recorded ? recorded.dn
                      : 'uid=' + escapeDnValue(uid) + ',' + usersDn();
  log.debug('Leaving spiffePlan(). ' + (recorded ? 'Already recorded at ' + dn + '.'
                                                 : 'uid=' + uid + ' for ' + id));
  return {
    dn: dn,
    // See didPlan(): the persona on an entry that already exists is that
    // entry's own, or the sweep fills it from a second invented person.
    personaKey: recorded ? personaKeyOf(recorded) : id,
    attributes: {
      objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
      uid: uid,
      cn: persona.display,
      sn: persona.family,
      givenName: persona.given,
      // Marked (SPIFFE) for didPlan()'s reason: every value on every entry here
      // is invented, and what this one needs to say first is that this is a
      // WORKLOAD identity and not somebody who typed a password.
      displayName: persona.display + ' (SPIFFE)',
      mail: persona.email,
      spiffeSubject: id,
      spiffeTrustDomain: domain,
      spiffePath: path
    },
    // Nothing to merge onto an entry that already exists: a SPIFFE ID
    // presented a second time is byte-for-byte the one that named this entry.
    //
    // **THE CERTIFICATE IS NOT MERGED EITHER, AND THAT IS NO LONGER THE SAME
    // AS NOT BEING RECORDED.** `merge` is APPENDED by autoCreateUser(), which
    // is right for a client certificate — a renewal is a new serial for the
    // same person and rare — and would be ruinous here: an SVID is minted
    // afresh at half its lifetime for as long as the workload runs, so six
    // values an hour would accumulate for ever, which is applyVcAttributes()'s
    // second rule met in a new place. So the certificate goes on the entry
    // through applySpiffeCertificate() instead, which ASSIGNS the same six
    // `x509*` attributes the TLS path writes and keeps a count and two
    // timestamps beside them. Read that function before adding anything here.
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
// A GROUP GRANTS NOTHING here — bar the two that decide who may use /admin, see
// `admin-ui/admin_rbac.js` — and neither does this: no endpoint reads these
// attributes, no token carries them, and nothing decides anything on them. They
// are a record of what happened, on the page an LDAP client can see it from.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// WHAT A FOREIGN IDENTITY PROVIDER SAID, WRITTEN ONTO THE ENTRY.
//
// This runs on an entry created because somebody signed in SOMEWHERE ELSE, and
// it is the only path here of that shape. Three rules, and each is a decision
// rather than a default:
//
// **THE PARTNER'S VALUES ARE ASSIGNED, NOT MERGED, AND THEY WIN.** This is the
// opposite of `applyVcAttributes()`, which fills only what is ABSENT — and the
// two have to differ, because that one writes an INVENTED persona and this one
// writes what a real identity provider actually asserted. If it merged, then
// `alice@example.invalid` — invented for the credential catalogue the first
// time anybody named alice — would beat the address her employer's identity
// provider just sent, permanently, with nothing on any page saying why. And if
// it accumulated, an entry would carry one `mail` value per sign-in.
//
// **ONLY THE ATTRIBUTES THE PARTNER SENT ARE TOUCHED.** An attribute that was
// on the entry before and is not in this assertion is LEFT ALONE rather than
// removed. A partner that stopped releasing `title` has not said the person has
// no title, and a directory that deleted attributes on the strength of an
// omission would lose data on a partner's configuration change.
//
// **IT RECORDS WHICH ONES CAME FROM THERE.** `federationAttribute` is the list,
// and it is the whole reason this function is not three lines: a federated
// `mail` and an invented `mail` are indistinguishable on the entry, and telling
// them apart is exactly the question a person reading a federated directory
// entry has.
//
// `federation_map.js` has already turned the partner's vocabulary into this
// directory's, so nothing here knows what a `urn:oid:` name is — the same
// division of labour `applications.js` keeps with this file about the
// applications schema.
// ---------------------------------------------------------------------------
function applyFederatedAttributes(stored, info) {
  log.debug('Entering applyFederatedAttributes(). dn=' + (stored && stored.dn));
  const federated = info && info.federation;
  if (!stored || !federated) {
    log.debug('Leaving applyFederatedAttributes(). Not a federated sign-in.');
    return false;
  }
  let changed = false;
  // The three facts about WHERE they came from. Multi-valued and accumulated,
  // because one person can federate through two partners and the second must
  // not erase the first — the same reason `description` accumulates one line
  // per protocol.
  if (addValues(stored, 'federationRelationship', [String(federated.id || '')])) changed = true;
  if (federated.peer &&
      addValues(stored, 'federationIssuer', [String(federated.peer)])) changed = true;
  if (federated.subject &&
      addValues(stored, 'federationSubject', [String(federated.subject)])) changed = true;

  const attributes = federated.attributes || {};
  const written = [];
  Object.keys(attributes).forEach(function (name) {
    const values = (Array.isArray(attributes[name]) ? attributes[name] : [attributes[name]])
      .map(function (one) { return String(one); })
      .filter(function (one) { return one !== ''; });
    if (!values.length) return;
    // NEVER the naming attribute, and never the two operational ones. `uid` is
    // what `namePlan()` put in the RDN, so a partner sending a `uid` that
    // differs from the username would leave an entry whose DN and whose uid
    // name two different people — and every lookup here that finds somebody by
    // name goes through one or the other. The username mapping is where a
    // partner's own idea of the local name belongs, and it has its own setting.
    const lower = name.toLowerCase();
    if (lower === 'uid' || lower === 'objectclass' ||
        lower === 'createtimestamp' || lower === 'modifytimestamp' ||
        lower === 'entrydn') {
      log.debug('applyFederatedAttributes(): not writing "' + name + '" — it names the ' +
                'entry rather than describing the person.');
      return;
    }
    const canonical = canonicalName(lower);
    const existing = stored.attributes[lower] || [];
    const same = existing.length === values.length &&
      existing.every(function (one, at) { return one === values[at]; });
    if (!same) {
      stored.attributes[lower] = values;
      changed = true;
    }
    written.push(canonical);
  });
  written.forEach(function (name) {
    if (addValues(stored, 'federationAttribute', [name])) changed = true;
  });
  // ASSIGNED, unlike the three above it: it is a fact about the LAST federated
  // sign-in, and a history of timestamps would say nothing the audit log does
  // not already say better.
  const now = generalizedTime();
  if ((stored.attributes.federationlastseen || [])[0] !== now) {
    stored.attributes.federationlastseen = [now];
    changed = true;
  }
  if (!changed) {
    log.debug('Leaving applyFederatedAttributes(). It already said all of this.');
    return false;
  }
  stored.attributes.modifytimestamp = [now];
  log.info('ldap: ' + stored.dn + ' records a federated sign-in through ' +
           federated.id + (federated.peer ? ' (' + federated.peer + ')' : '') + '. ' +
           (written.length ? written.length + ' attribute(s) came from the partner and ' +
                             'OVERWROTE whatever was there: ' + written.join(', ') + '.'
                           : 'The partner sent no attributes this directory maps.') +
           (federated.unmapped && federated.unmapped.length
             ? ' ' + federated.unmapped.length + ' more were sent under names nothing ' +
               'maps and were NOT written: ' + federated.unmapped.join(', ') + '.'
             : ''));
  log.debug('Leaving applyFederatedAttributes(). The entry was updated.');
  return true;
}

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
// THE CERTIFICATE A SPIFFE IDENTITY CURRENTLY HOLDS, WRITTEN ONTO ITS ENTRY.
//
// This is the SPIFFE half of what `certificatePlan()` does for a verified TLS
// client certificate, and it writes THE SAME SIX ATTRIBUTES — `x509subject`,
// `x509issuer`, `x509serialNumber`, `x509notBefore`, `x509notAfter`,
// `x509fingerprint256` — in the same strings. The strings being identical is a
// requirement rather than a nicety: `spiffe_ca.js` reads them back off the
// certificate it has just issued with node's own parser and renders both DNs
// through the one `dnRfc4514()` in `helpers.js`, so an `ldapsearch` filter
// written against a client certificate's entry matches an SVID holder's too.
// Two spellings of one DN is two people on /admin/users, and the same is true
// one column over of a serial number with colons in it.
//
// **THE ONE RULE THAT DIFFERS FROM THE TLS PATH IS APPEND VERSUS ASSIGN, AND IT
// HAD TO.** `certificatePlan()` APPENDS its facts, deliberately: a renewed
// client certificate is a new serial for the same person, renewals are rare,
// and seeing both is the point. An X509-SVID is minted afresh at half its
// lifetime for as long as the workload runs — the default puts that at half an
// hour — so appending would grow this entry by six values an hour, for ever,
// and the entry that grows without bound is precisely the trap
// `applyVcAttributes()`'s second rule and `applyAuthenticationFactors()`'s
// `mfaAuthenticated` are both written about. `spiffePlan()` used to state this
// as a reason to record NOTHING; the answer it was missing is that the six are
// the CURRENT certificate and belong assigned.
//
// What assignment loses is the history, so three attributes of this path's own
// carry the part of it worth keeping — how many have been issued, when the
// first was, and when the last was. A reader who wants the individual serials
// has them on /admin/metrics, where every SVID is an artifact row.
//
// **A ROTATION IS THE SAME OBJECT AND NEEDS NO CODE HERE TO MAKE IT SO.** The
// entry is found by `entryBySpiffeSubject()`, which keys on the SPIFFE ID and
// not on anything about the certificate, so the fiftieth SVID for
// `spiffe://…/sa/db` lands on the entry the first one created. That is the same
// property that already made an X509-SVID at the SPIRE Server API, an attesting
// agent and a validated JWT-SVID one entry.
//
// **AN ISSUANCE MAKES AN IDENTITY ACTIVE AGAIN.** If the entry says `revoked` —
// its registration entry was deleted, or its agent was banned — and a
// certificate has just been minted for it anyway, the status is wrong and this
// is the point at which the service knows it. That happens for real: unbanning
// an agent and re-registering an identity both restore issuance, and
// `spiffe.authRequired` off makes the whole registry advisory.
// ---------------------------------------------------------------------------
function applySpiffeCertificate(stored, certificate) {
  log.debug('Entering applySpiffeCertificate(). dn=' + (stored && stored.dn));
  if (!stored || !certificate) {
    log.debug('Leaving applySpiffeCertificate(). There is nothing to write.');
    return false;
  }
  // The same six names certificatePlan() writes, in the same order, so the two
  // functions can be read side by side. An empty value is skipped rather than
  // written blank: certificateFacts() returns '' for anything node could not
  // read, and an attribute present and empty reads as a fact rather than as an
  // absence.
  const facts = {
    x509subject: certificate.subject || '',
    x509issuer: certificate.issuer || '',
    x509serialnumber: certificate.serialNumber || '',
    x509notbefore: certificate.validFrom || '',
    x509notafter: certificate.validTo || '',
    x509fingerprint256: certificate.fingerprint256 || ''
  };
  let changed = false;
  Object.keys(facts).forEach(function (name) {
    if (!facts[name]) {
      return;
    }
    // ASSIGNED, not appended. See the header — this is the one place this
    // module writes these six that way, and the comment is here as well as
    // there because the two functions look alike enough to be "fixed" into
    // agreement by somebody reading only one.
    if ((stored.attributes[name] || [])[0] !== facts[name] ||
        (stored.attributes[name] || []).length !== 1) {
      stored.attributes[name] = [facts[name]];
      changed = true;
    }
  });
  const now = generalizedTime();
  const issued = Number((stored.attributes.x509svidsissued || [])[0] || 0) + 1;
  stored.attributes.x509svidsissued = [String(issued)];
  if (!(stored.attributes.x509firstissued || []).length) {
    // Written once and never again — the counterpart of x509lastIssued, and the
    // pair is what makes "47 SVIDs since 09:00" readable without keeping 47
    // values.
    stored.attributes.x509firstissued = [now];
  }
  stored.attributes.x509lastissued = [now];
  changed = true;
  // See the header: a certificate has just been minted for this identity, so
  // whatever the registry last said about it, it is being issued credentials.
  if ((stored.attributes.spiffecredentialstatus || [])[0] === 'revoked') {
    applySpiffeCredentialStatus(stored, 'active',
      'an X509-SVID was issued for this identity after it was marked revoked, ' +
      'so it is being issued credentials again');
  }
  stored.attributes.modifytimestamp = [now];
  touchDirectory();
  log.info('ldap: ' + stored.dn + ' holds X509-SVID serial ' +
           (certificate.serialNumber || '(unreadable)') + '; ' + issued +
           ' issued to this identity so far.');
  log.debug('Leaving applySpiffeCertificate(). The entry was updated.');
  return changed;
}

// ---------------------------------------------------------------------------
// AND WHETHER IT MAY STILL BE ISSUED ONE, WHICH IS NOT A CERTIFICATE STATUS.
//
// **NOTHING HERE REVOKES A CERTIFICATE AND NOTHING READS THIS BACK.** SPIFFE
// has no revocation: there is no CRL, no OCSP and no serial list, the answer is
// a short lifetime and rotation, and `GET /spiffe` states that as one of the
// things this service deliberately does not do. An SVID already in a workload's
// hands goes on verifying against the bundle until it expires whatever this
// attribute says, and that is correct behaviour rather than a gap — a mock that
// quietly refused a certificate on a revocation list SPIFFE does not have would
// teach a client something false about every SPIRE server it will ever meet.
//
// What this DOES record is the three things in the registry that end an
// identity's ability to obtain a NEW credential here, which is the honest
// nearest thing and is what somebody asking "is this workload still live"
// wants:
//
//   * its LAST registration entry was deleted — the qualifier matters, and
//     `spiffe_registry.js` checks it, because several entries may name one
//     SPIFFE ID and deleting one of them ends nothing;
//   * its AGENT was banned, which is the one refusal that module makes;
//   * its AGENT was deleted.
//
// Each is reversible and the reverse is recorded the same way, so the flag is
// the CURRENT state rather than a tombstone. **THE ENTRY IS NEVER REMOVED.** An
// identity this trust domain used to issue certificates to is exactly what a
// directory is for, and deleting the object would answer "was there ever a
// workload called db?" with silence.
//
// Three attributes, following `applyAuthenticationFactors()`'s split for the
// same reason — merging them loses one of the three:
//
//   spiffeCredentialStatus        `active` or `revoked`, ASSIGNED. The current
//                                 state, so it flips back.
//   spiffeCredentialStatusReason  why it is in THAT state, ASSIGNED with it.
//                                 The two are written together by the one
//                                 function that writes either, or a reason
//                                 would outlive the status it explains.
//   spiffeRevokedAt               when it was LAST revoked, and never cleared.
//                                 That is the history the flag above does not
//                                 keep, and it is `mfaLastAuthTime`'s rule.
// ---------------------------------------------------------------------------
function applySpiffeCredentialStatus(stored, status, reason) {
  log.debug('Entering applySpiffeCredentialStatus(). dn=' +
            (stored && stored.dn) + ', status=' + status);
  if (!stored) {
    log.debug('Leaving applySpiffeCredentialStatus(). There is no entry.');
    return false;
  }
  const wanted = String(status || '').trim().toLowerCase();
  if (wanted !== 'active' && wanted !== 'revoked') {
    // Refused rather than written through. This attribute has exactly two
    // values and a third would be a value every reader of the page has to
    // guess at — the same reason `mfaAuthenticated` is TRUE or FALSE and not
    // whatever a caller passed.
    log.warn('ldap: "' + status + '" is not a SPIFFE credential status; only ' +
             '`active` and `revoked` are written, so nothing was.');
    log.debug('Leaving applySpiffeCredentialStatus(). Not a status.');
    return false;
  }
  const text = String(reason || '').trim();
  let changed = false;
  if ((stored.attributes.spiffecredentialstatus || [])[0] !== wanted) {
    stored.attributes.spiffecredentialstatus = [wanted];
    changed = true;
  }
  if (text && (stored.attributes.spiffecredentialstatusreason || [])[0] !== text) {
    stored.attributes.spiffecredentialstatusreason = [text];
    changed = true;
  }
  if (wanted === 'revoked') {
    // Never cleared on the way back to `active`. See the header.
    stored.attributes.spifferevokedat = [generalizedTime()];
    changed = true;
  }
  if (!changed) {
    log.debug('Leaving applySpiffeCredentialStatus(). It already said this.');
    return false;
  }
  stored.attributes.modifytimestamp = [generalizedTime()];
  touchDirectory();
  log.info('ldap: ' + stored.dn + ' is now ' + wanted +
           ' as far as being issued a SPIFFE credential goes' +
           (text ? ' (' + text + ')' : '') + '. No certificate was revoked; ' +
           'SPIFFE has no revocation.');
  log.debug('Leaving applySpiffeCredentialStatus(). The entry was updated.');
  return true;
}

// ---------------------------------------------------------------------------
// THE OBSERVER ITSELF, WHICH IS NOW A DISPATCHER OVER THREE EVENTS.
//
// `admin_stats.js` offers ONE slot to this directory (see the header, and rule
// 3e for why it is a slot and not a require), and it is now offered three kinds
// of thing through it rather than one. The discriminator is `detail.event`, and
// **AN ABSENT `event` MEANS AN AUTHENTICATION** — deliberately, so that a copy
// of `admin_stats.js` without the field, or any caller that reaches this
// function directly, behaves exactly as it did before the other two existed.
//
//   authentication      a credential was ACCEPTED, anywhere in this service.
//                       The original path, unchanged, and the only one of the
//                       three that creates an entry for an identity of any
//                       shape.
//   issuance            this trust domain MINTED an X509-SVID naming a SPIFFE
//                       identity. It creates the entry the same way, through
//                       the same plan, and then writes the certificate onto it.
//                       Being issued a credential is not authenticating with
//                       one, which is why it is a separate event and not a
//                       fifteenth protocol.
//   credential-status   the registry ended — or restored — an identity's
//                       ability to obtain one. It NEVER creates an entry: a
//                       revocation for something this directory has no record
//                       of issuing to is nothing to write down, and creating an
//                       entry in order to mark it dead would put a workload in
//                       the directory that was never here.
//
// A kind this copy does not know is IGNORED rather than treated as an
// authentication. The other direction — a newer `admin_stats.js` inventing a
// fourth event and this file silently seeding a user entry for it — is the
// failure that would be hard to find.
// ---------------------------------------------------------------------------
function observeIdentity(detail) {
  log.debug('Entering observeIdentity().');
  const info = detail || {};
  const event = String(info.event || 'authentication');
  log.debug('Entering observeIdentity(). event=' + event +
            ', key=' + (info.key || '?'));
  if (event === 'authentication') {
    const record = autoCreateUser(info);
    log.debug('Leaving observeIdentity(). An authentication.');
    log.debug('Leaving observeIdentity().');
    return record;
  }
  if (event === 'issuance') {
    const record = recordSpiffeIssuance(info);
    log.debug('Leaving observeIdentity(). An issuance.');
    log.debug('Leaving observeIdentity().');
    return record;
  }
  if (event === 'credential-status') {
    const record = recordSpiffeCredentialStatus(info);
    log.debug('Leaving observeIdentity(). A credential status change.');
    log.debug('Leaving observeIdentity().');
    return record;
  }
  log.warn('ldap: the identity funnel offered a "' + event + '" event, which ' +
           'this directory does not know about, so nothing was written. That ' +
           'is a version skew between admin_stats.js and this module rather ' +
           'than anything a caller did.');
  log.debug('Leaving observeIdentity(). Unknown event.');
  log.debug('Leaving observeIdentity().');
  return null;
}

// ---------------------------------------------------------------------------
// AN X509-SVID WAS MINTED FOR A SPIFFE IDENTITY.
//
// The entry is created exactly as an acceptance would create it — same plan,
// same cap, same credential-claim sweep, same audit row — because it is the
// same identity and a second creation path would be the fifth door
// `createUser()`'s header warns about. What is added afterwards is the
// certificate, through `applySpiffeCertificate()`.
//
// **IT IS GUARDED ON THE SHAPE OF THE IDENTITY, and the guard is not
// defensive.** Only `spiffe_ca.js` mints these, so only a SPIFFE ID can reach
// here today — but the six `x509*` attributes this writes ASSIGNED are the same
// six `certificatePlan()` writes APPENDED, and if some later caller sent a
// DN-shaped identity through this event the two rules would meet on one entry
// and the appended history would start being overwritten by the assigned one.
// That is a data loss nothing would report, so the shape is checked here rather
// than assumed.
// ---------------------------------------------------------------------------
function recordSpiffeIssuance(detail) {
  log.debug('Entering recordSpiffeIssuance(). key=' + (detail && detail.key));
  const info = detail || {};
  const id = String(info.key || '').trim();
  if (!id || !SPIFFE_SHAPED.test(id)) {
    log.warn('ldap: an issuance was reported for "' + id + '", which is not a ' +
             'SPIFFE identity. Nothing was written — see the header for why ' +
             'this is refused rather than filed under certificatePlan().');
    log.debug('Leaving recordSpiffeIssuance(). Not a SPIFFE identity.');
    return null;
  }
  // autoCreateUser() rather than a creation of its own: it holds the cap, the
  // fold, the persona sweep and the audit row, and `spiffePlan()` reads
  // `info.event` to describe the entry as issued-to rather than presented-by.
  const stored = autoCreateUser(info);
  if (!stored) {
    // Three ways to get here and none is an error: ldap.autocreateUsers is off,
    // the directory is at its cap, or there was no identity. Each already
    // logged its own reason, and the SVID itself is unaffected either way.
    log.debug('Leaving recordSpiffeIssuance(). There is no entry to write to.');
    return null;
  }
  applySpiffeCertificate(stored, info.issuedCertificate);
  log.debug('Leaving recordSpiffeIssuance(). ' + stored.dn + ' records the ' +
            'certificate.');
  return stored;
}

// ---------------------------------------------------------------------------
// AND THE REGISTRY ENDED, OR RESTORED, AN IDENTITY'S ABILITY TO GET ONE.
//
// It creates NOTHING. See `observeIdentity()`: an entry that is not here was
// never issued a certificate by this service, and inventing one in order to
// mark it revoked would put a workload in the directory on the strength of its
// registration entry being deleted. The lookup is `entryBySpiffeSubject()`, the
// same one every other SPIFFE path uses, so a status lands on the entry a
// rotation would have landed on.
// ---------------------------------------------------------------------------
function recordSpiffeCredentialStatus(detail) {
  log.debug('Entering recordSpiffeCredentialStatus(). key=' +
            (detail && detail.key));
  const info = detail || {};
  const id = String(info.key || '').trim();
  if (!id || !SPIFFE_SHAPED.test(id)) {
    log.debug('Leaving recordSpiffeCredentialStatus(). Not a SPIFFE identity.');
    return null;
  }
  const stored = entryBySpiffeSubject(id);
  if (!stored) {
    log.debug('Leaving recordSpiffeCredentialStatus(). This directory has no ' +
              'entry for that identity, so there is nothing to mark.');
    return null;
  }
  applySpiffeCredentialStatus(stored, info.credentialStatus,
                              info.credentialStatusReason);
  log.debug('Leaving recordSpiffeCredentialStatus(). ' + stored.dn +
            ' was updated.');
  return stored;
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
  // AND THE PER-RELATIONSHIP SWITCH, which is the one place a federated sign-in
  // is treated differently from every other kind here. `ldap.autocreateUsers`
  // above is the service-wide answer; `fedAutocreateUsers` is one partner's,
  // and it exists because a federation partner is the one source of identities
  // this service does not control the volume of — a partner with ten thousand
  // people behind it would otherwise fill ou=users the first time somebody
  // pointed a load generator at it. Off means a session and no entry, which is
  // a state worth being able to watch.
  if (info.federation && info.federation.autocreate === false) {
    log.debug('Leaving autoCreateUser(). fedAutocreateUsers is off on ' +
              info.federation.id + ', so this federated sign-in leaves no entry.');
    return null;
  }
  // FOUR shapes of identity and one placement function each, chosen here and
  // decided there. A client CERTIFICATE identity is a DN (certificatePlan()); a
  // DECENTRALIZED IDENTIFIER is one long opaque string (didPlan()); a SPIFFE
  // IDENTITY is another (spiffePlan()); everything else is a name and becomes
  // `uid=<name>,ou=users` (namePlan()).
  //
  // The order matters in one direction only: a certificate's identity is a
  // subject DN, so it is tested first and the other two tests never see it.
  // Nothing else here can be more than one — a DN begins `<attributetype>=`, a
  // DID begins `did:` and a SPIFFE ID begins `spiffe://`.
  //
  // A SPIFFE identity arriving with a client certificate is the one case worth
  // stating: `info.certificate` means a TLS client certificate on this
  // service's OWN listeners, where the identity is the subject DN. An X509-SVID
  // presented to the SPIRE Server API does not set it — `spiffe_auth.js` passes
  // the SPIFFE ID, which is what the certificate NAMES rather than what it is —
  // so an SVID holder is filed by identity and not by `C=US,O=SPIRE`, which is
  // the subject every SVID here shares and would fold every workload in the
  // trust domain onto one entry.
  const plan = info.certificate
    ? certificatePlan(info)
    : (DID_SHAPED.test(name) ? didPlan(info)
       : (SPIFFE_SHAPED.test(name) ? spiffePlan(info) : namePlan(name)));
  const dn = plan.dn;
  // Whose invented person fills what this entry lacks. It is the identity by
  // default and the plan's own where it has one: a DID that arrived with a
  // username attached is that person's second identifier, so the persona has to
  // be seeded from the username or the entry gets attributes invented for two
  // different people (see didPlan()'s linked branch).
  const personaName = plan.personaKey || name;
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
    if (applyVcAttributes(existing, personaName)) {
      changed = true;
    }
    // And how they authenticated this time, where the protocol says. This is
    // the whole of what a WebAuthn SECOND FACTOR adds to a directory: the
    // person already has this entry — the password step named them — so the
    // key writes a flag and creates nothing.
    if (applyAuthenticationFactors(existing, info)) {
      changed = true;
    }
    // AFTER the persona sweep above, and that order is load-bearing: the sweep
    // fills only what is absent and this OVERWRITES, so a partner's real email
    // address beats the invented one whichever way round the entry was created.
    // Reversed, an entry created by a federated sign-in would have its real
    // values quietly replaced by invented ones on the very next sign-in.
    if (applyFederatedAttributes(existing, info)) {
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
  if (totalEntries() >= maxEntries()) {
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
  applyVcAttributes(created, personaName);
  // Before the audit row below, so that the attributes it lists are the ones the
  // entry actually has. On a PASSWORDLESS WebAuthn sign-in this is what says the
  // single factor was a key rather than a password, on an entry that exists
  // because that sign-in was an authentication in its own right.
  applyAuthenticationFactors(created, info);
  // Last, for applyVcAttributes()'s sake: see the note on the returning-person
  // branch above. What a foreign identity provider asserted about somebody
  // beats what this service invented for them.
  applyFederatedAttributes(created, info);
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
              entriesNow: totalEntries(),
              note: 'created by this service, not by an LDAP client; ' +
                    'ldap.autocreateUsers is on' }
  });
  log.debug('Leaving autoCreateUser(). The entry was created.');
  return created;
}

// The characters RFC 4514 section 2.4 reserves inside a DN. Written once,
// because THREE doors now need the same answer: createUser() below (the
// console's and the management API's), and scim.js's create of a User and of a
// Group. A name carrying one of these would build a DN that means something
// other than what was typed, and this service files people and groups BY NAME
// everywhere — /admin/users, /admin/groups, the persona, the SCIM id, which IS
// the DN. An `ldapadd` can still create such an entry with the escaping written
// out by the client, which is the line applications.js already draws between
// what a door offers and what it merely does not prevent.
//
// Three copies of this regex would be three doors that eventually disagree
// about whether `a+b` is a name, and the one that said yes would be the one
// that produced the unreachable entry.
const DN_RESERVED = /[,=+<>#;"\\]/;

function nameUsableInDn(name) {
  return !DN_RESERVED.test(String(name == null ? '' : name));
}

// ---------------------------------------------------------------------------
// A PERSON CREATED ON PURPOSE, rather than because they authenticated.
//
// autoCreateUser() above is the automatic door: somebody presented a credential
// somewhere in this service and an entry appeared. This is the deliberate one,
// and it exists because the console and the management API had NO way to put a
// person in this directory at all — `ou=applications` could be filled by hand
// from three directions (LDAP, a form, an API call) and `ou=users` could only
// be filled by authenticating or by an `ldapadd`.
//
// THE SAME FUNCTION SERVES BOTH SURFACES, which is the rule `applications.js`
// already keeps: /admin/users's form and POST /admin-api/users/create call this,
// so a form post and an API call are one act arriving by two routes and cannot
// drift into two readings of what creating a user means.
//
// Three things about it:
//
//   * IT REFUSES A NAME THAT IS TAKEN, which is the whole point of the ask it
//     was written for. The lookup is existingUserEntry(), the same one the add
//     handler and both plans use, so "already exists" means the same thing at
//     every door — including a person whose only entry is the one a client
//     certificate created under a different naming attribute.
//   * IT IS NOT GOVERNED BY `ldap.autocreateUsers`. That setting says whether
//     authenticating somewhere else should silently seed a directory entry;
//     this is somebody asking for one outright, and refusing it because the
//     automatic door is shut would be answering a question nobody asked.
//   * THE NAME IS CHECKED FOR DN SYNTAX rather than escaped. A username
//     containing a comma or an equals sign would build a DN that means
//     something else entirely, and this service files people by name
//     everywhere — /admin/users, the persona, the groups page — so the honest
//     answer is that such a thing is not a username here. An `ldapadd` can
//     still create it, with the escaping spelled out by the client, which is
//     the same line applications.js draws between what it offers and what it
//     merely does not prevent.
// ---------------------------------------------------------------------------
function createUser(name, options) {
  log.debug('Entering createUser(). name=' + name);
  const opts = options || {};
  const wanted = String(name == null ? '' : name).trim();
  if (!wanted) {
    log.debug('Leaving createUser(). No name.');
    return { ok: false, errors: ['Which user? Send `username` with the name ' +
                                 'they will authenticate under — the same ' +
                                 'string that would appear in a token\'s `sub` ' +
                                 'and on /admin/users.'] };
  }
  if (DN_SHAPED.test(wanted)) {
    log.debug('Leaving createUser(). That is a DN.');
    return { ok: false, errors: ['"' + wanted + '" is a DN and not a username. ' +
                                 'An entry named by a distinguished name gets ' +
                                 'here by presenting a client certificate, ' +
                                 'where the DN is the identity; there is ' +
                                 'nothing to create one from by hand.'] };
  }
  if (DID_SHAPED.test(wanted)) {
    log.debug('Leaving createUser(). That is a DID.');
    return { ok: false, errors: ['"' + wanted.slice(0, 48) + '" is a ' +
                                 'decentralized identifier and not a username. ' +
                                 'A DID reaches this directory by being ' +
                                 'presented, and where this service knows whose ' +
                                 'it is the identifier goes onto that person\'s ' +
                                 'entry as didSubject.'] };
  }
  if (SPIFFE_SHAPED.test(wanted)) {
    log.debug('Leaving createUser(). That is a SPIFFE ID.');
    return { ok: false, errors: ['"' + wanted.slice(0, 64) + '" is a SPIFFE ' +
                                 'identity and not a username. A workload ' +
                                 'identity reaches this directory by being ' +
                                 'PRESENTED — an X509-SVID over mutual TLS at ' +
                                 'the SPIRE Server API, an agent attesting, a ' +
                                 'JWT-SVID validated at the Workload API — ' +
                                 'and its entry is named by a digest with the ' +
                                 'identity on it as spiffeSubject. What you ' +
                                 'probably want instead is a REGISTRATION ' +
                                 'ENTRY, which is a different thing in a ' +
                                 'different container: /admin/spiffe/entries, ' +
                                 'POST /admin-api/spiffe/entries/create, or ' +
                                 'BatchCreateEntry.'] };
  }
  if (!nameUsableInDn(wanted)) {
    log.debug('Leaving createUser(). The name carries DN syntax.');
    return { ok: false, errors: ['"' + wanted + '" cannot be a username here: ' +
                                 'it carries a character RFC 4514 reserves in a ' +
                                 'DN (one of , = + < > # ; " \\), so the entry ' +
                                 'would be named something other than what was ' +
                                 'typed. An ldapadd can still create such an ' +
                                 'entry, with the escaping written out.'] };
  }
  const clash = existingUserEntry(wanted);
  if (clash) {
    log.debug('Leaving createUser(). That username is taken.');
    return { ok: false,
             errors: ['There is already a user called "' + wanted + '" here, at ' +
                      clash.dn + '. One entry per person is the rule this ' +
                      'directory keeps at every door — whatever protocol ' +
                      'authenticated them, and whichever attribute their entry ' +
                      'happens to be named by.'],
             existing: { dn: clash.dn, origin: clash.origin || '' } };
  }
  if (totalEntries() >= maxEntries()) {
    log.debug('Leaving createUser(). The directory is full.');
    return { ok: false, errors: ['This directory holds its maximum of ' +
                                 maxEntries() + ' entries.'] };
  }
  const plan = namePlan(wanted);
  const note = String(opts.note || '').trim() ||
    'created by hand rather than by authenticating';
  const created = putEntry(plan.dn, Object.assign({}, plan.attributes,
                                                  { description: [note] }),
                           { origin: opts.origin || 'console' });
  // The same fill autoCreateUser() does, and for the same reason: the entry an
  // LDAP client reads and the credential a wallet is handed have to say the
  // same thing about this person from the moment the entry exists.
  applyVcAttributes(created, wanted);
  // ---------------------------------------------------------------------
  // AND THE PERSON IS PUT IN THE IDENTITY REGISTER, WHICH IS WHAT MAKES THEM
  // VISIBLE ON /admin/users. THIS WAS A PRE-EXISTING GAP, found while building
  // persistence.
  //
  // `/admin/users`, `/admin-api/users` and the user drill-down do not read this
  // directory — they read `admin_stats.js`'s register, which until 2026-08-27
  // could only be filled by somebody AUTHENTICATING. So a person created
  // through this function got a directory entry that `ldapsearch`,
  // `/ldap/directory` and SCIM could all see, and appeared on the console's
  // Users page NOWHERE until they signed in — while `/admin/users`'s own blurb
  // said "a person can be created here ahead of their first sign-in". Three
  // doors reach this function (the console, `POST /admin-api/users/create` and
  // a SCIM create) and all three had it.
  //
  // They are registered as KNOWN WITHOUT A SIGN-IN — `authenticated` false on
  // the row — so `authenticatedHere` keeps counting sign-ins rather than
  // people. `noteKnownIdentity()` argues that distinction; its early return is
  // also what keeps this call safe on the authentication path, where
  // `recordAuthentication()` reaches `autoCreateUser()` and then here.
  // ---------------------------------------------------------------------
  stats.noteKnownIdentity(wanted, 'created');
  log.info('ldap: created ' + created.dn + ' because somebody asked for it.');
  audit.recordDirectory({
    action: 'user.create',
    actor: String(opts.actor || ''),
    target: created.dn,
    // Passed through rather than fixed at '' (which recordDirectory reads as
    // LDAP), because this function now serves a THIRD door: a SCIM create says
    // SCIM here, and a row that called it LDAP would be the audit log's one
    // job — saying what happened and through what — done wrong.
    protocol: String(opts.protocol || ''),
    channel: opts.channel || 'internal',
    summary: 'created ' + created.dn + ' on request; ' + note,
    detail: { reason: note,
              attributes: Object.keys(created.attributes).join(', '),
              entriesNow: totalEntries(),
              note: 'created by hand through the console or the management ' +
                    'API, not by an LDAP client and not by an authentication' }
  });
  log.debug('Leaving createUser(). ' + created.dn + ' was created.');
  return { ok: true, dn: created.dn, username: wanted,
           entry: { dn: created.dn, origin: created.origin || '',
                    attributes: created.attributes } };
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
    touchDirectory();
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
  log.debug('Entering personaKeyOf().');
  // The DID first, where there is one, and this line is load-bearing: on a
  // DID-named entry the uid is a DIGEST of the identity rather than the identity
  // (see didPlan()), so seeding from it would invent a SECOND person for
  // somebody the authentication path had already invented one for — and the two
  // would disagree on every attribute the sweep filled in.
  //
  // ONLY WHERE IT NAMED THE ENTRY, which is the qualification the fold added.
  // A DID now also lands on the entry of the person it was issued to (see
  // didPlan()'s linked branch), and there the uid IS the identity — the
  // username somebody typed — so preferring the DID would do the very thing
  // this paragraph exists to prevent, in the other direction. The test is
  // exact rather than a guess: the entry is DID-named when its uid is the
  // digest didPlan() would have built from that DID.
  const did = (stored.attributes.didsubject || [])[0];
  const uid = (stored.attributes.uid || [])[0];
  if (did && (!uid || String(uid) === didUid(String(did)))) {
    log.debug('Leaving personaKeyOf().');
    return String(did);
  }
  // The same test for a SPIFFE identity, and it has to be the same shape rather
  // than "does this entry carry a spiffeSubject": the identifier is
  // multi-valued and an entry could hold one without having been NAMED by it,
  // and seeding a person from an identity that did not name them is the second
  // invented person this paragraph exists to prevent.
  const spiffe = (stored.attributes.spiffesubject || [])[0];
  if (spiffe && (!uid || String(uid) === spiffeUid(String(spiffe)))) {
    log.debug('Leaving personaKeyOf().');
    return String(spiffe);
  }
  if (uid) {
    log.debug('Leaving personaKeyOf().');
    return String(uid);
  }
  const cn = (stored.attributes.cn || [])[0];
  if (cn) {
    log.debug('Leaving personaKeyOf().');
    return String(cn);
  }
  log.debug('Leaving personaKeyOf().');
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
  eachEntryInRealm(function (stored) {
    if (!isUnder(stored.dn, usersDn()) || normalizeDn(stored.dn) === normalizeDn(usersDn())) {
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
  eachEntryInRealm(function (stored) {
    if (before.has(stored.dn)) {
      values += Object.keys(stored.attributes).length - before.get(stored.dn);
    }
  });
  log.info('ldap: swept ' + examined + ' entry/entries under ' + usersDn() + ' for the ' +
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
// ahead of the console's, which reorders the express router that
// /admin/sts-metadata reads. So admin.js offers a slot and this module fills
// it, exactly as admin_stats.js does for the observer.
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
    // A DN is the one identity shape a caller can hand this function that names
    // a PLACE rather than a person, so it was the one that could reach out of
    // the realm — for two days, while the store was shared, this line needed a
    // containment check of its own. The store is per realm now, so `getEntry()`
    // cannot see another realm's entry and the check is the store's job.
    const direct = getEntry(key);
    if (direct) {
      log.debug('Leaving locateEntry(). The DN names an entry in this realm directly.');
      return { dn: direct.dn, stored: direct };
    }
    let found = null;
    eachEntryInRealm(function (entry) {
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
    const found = entryByDidSubject(key);
    if (found) {
      log.debug('Leaving locateEntry(). Found by didSubject: ' + found.dn);
      return { dn: found.dn, stored: found };
    }
    const plan = didPlan({ key: key });
    log.debug('Leaving locateEntry(). Nothing yet; it would go at ' + plan.dn);
    return { dn: plan.dn, stored: null };
  }
  // A SPIFFE IDENTITY, the fourth shape, found the same way a DID is and never
  // by rebuilding the digest — see spiffePlan(). This is what makes the same
  // workload reached through three different acceptance points one entry.
  if (SPIFFE_SHAPED.test(key)) {
    const found = entryBySpiffeSubject(key);
    if (found) {
      log.debug('Leaving locateEntry(). Found by spiffeSubject: ' + found.dn);
      return { dn: found.dn, stored: found };
    }
    const plan = spiffePlan({ key: key });
    log.debug('Leaving locateEntry(). Nothing yet; it would go at ' + plan.dn);
    return { dn: plan.dn, stored: null };
  }
  // A NAME, and it is asked of the store rather than answered by rebuilding the
  // DN. `uid=<name>,ou=users` is where namePlan() puts one and is still the
  // answer for almost everybody — but a person whose entry was created by a
  // client certificate is at `cn=<name>,ou=users`, and rebuilding the name would
  // report "nothing here" about an entry this directory holds and every
  // authentication now folds onto.
  const already = existingUserEntry(key);
  if (already) {
    log.debug('Leaving locateEntry(). A name, found at ' + already.dn + '.');
    return { dn: already.dn, stored: already };
  }
  const dn = 'uid=' + key + ',' + usersDn();
  log.debug('Leaving locateEntry(). A name, so ' + dn + ' (nothing there yet).');
  return { dn: dn, stored: null };
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
  // the entry that is this person's. A SPIFFE identity is skipped for exactly
  // that second reason.
  const alsoNamed = [];
  if (key && !DN_SHAPED.test(key) && !DID_SHAPED.test(key) &&
      !SPIFFE_SHAPED.test(key)) {
    eachEntryInRealm(function (entry) {
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
    baseDn: baseDn(),
    usersDn: usersDn(),
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
    entryCount: realmEntryCount(),
    maxEntries: maxEntries(),
    // Not `entryCount >= maxEntries` computed by the caller: the cap is this
    // module's and a second copy of the comparison is a second thing to keep
    // right.
    full: totalEntries() >= maxEntries()
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
  log.debug('Entering groupRuleFor().');
  const under = isUnder(stored.dn, groupsDn()) &&
                normalizeDn(stored.dn) !== normalizeDn(groupsDn());
  const classes = (stored.attributes.objectclass || []).map(function (value) {
    return String(value).toLowerCase();
  });
  const classed = classes.some(function (value) {
    return GROUP_CLASSES.indexOf(value) >= 0;
  });
  if (under && classed) {
    log.debug('Leaving groupRuleFor().');
    return 'both';
  }
  if (under) {
    log.debug('Leaving groupRuleFor().');
    return 'placement';
  }
  if (classed) {
    log.debug('Leaving groupRuleFor().');
    return 'objectClass';
  }
  log.debug('Leaving groupRuleFor().');
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
  log.debug('Entering resolveMember().');
  const raw = String(value == null ? '' : value);
  const holds = attribute.holds;
  const dn = holds === 'uid' ? 'uid=' + raw + ',' + usersDn() : raw;
  // A member value naming an entry in ANOTHER realm resolves to nothing and is
  // shown as DANGLING, which falls out of the store being per realm rather than
  // being decided here. The value itself is still printed — it is this group's
  // own attribute and hiding it would be a different lie — but "present" on
  // this page has always meant "this directory holds it", and this realm's
  // directory does not.
  const stored = getEntry(dn);
  const rule = stored ? groupRuleFor(stored) : '';
  log.debug('Leaving resolveMember().');
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
  log.debug('Entering claimedMembersOf().');
  const listed = {};
  const stored = getEntry(groupDn);
  if (stored) {
    membersOf(stored).forEach(function (member) {
      listed[normalizeDn(member.dn)] = true;
    });
  }
  const out = [];
  const key = normalizeDn(groupDn);
  eachEntryInRealm(function (entry) {
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
  log.debug('Leaving claimedMembersOf().');
  return out.sort(function (a, b) {
    return normalizeDn(a.dn) < normalizeDn(b.dn) ? -1 : 1;
  });
}

// The directory-level facts every one of the console's LDAP sections needs. The
// same six objectFor() reports, out of one function so that the two pages cannot
// come to disagree about whether a socket is up.
function directoryState() {
  return {
    baseDn: baseDn(),
    usersDn: usersDn(),
    groupsDn: groupsDn(),
    port: boundPort,
    listening: listening,
    listenError: listenError,
    ldapsPort: secureServer ? boundTlsPort : null,
    ldapsListening: tlsListening,
    entryCount: realmEntryCount(),
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
  eachEntryInRealm(function (entry) {
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

  // `wanted` comes off a query string, and this is the lookup that rendered the
  // DEFAULT realm's group in full under /realm/acme — members, attributes and
  // all, beside a `groupsDn` saying acme's — for as long as one Map held every
  // realm. It reads the realm's own store now. groupRuleFor() still decides
  // whether it IS a group; the store decides whose it is.
  const stored = getEntry(wanted);
  if (!stored) {
    log.debug('Leaving groupsFor(). There is no entry at ' + wanted + ' in this realm.');
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
// ---------------------------------------------------------------------------
// THE MEMBERSHIP, INVERTED — and why this is the one thing here with an index.
//
// groupsOfUser() below is called ONCE PER TOKEN, for every access token, ID
// Token and both SAML assertions (see group_claims.js). It used to answer by
// walking every entry in the tree and, for each one that turned out to be a
// group, normalising every value of its three membership attributes. That is
// O(entries x members) per issuance against a store this service will let grow
// to `ldap.maxEntries`, which is 2,000 by default — and it showed: normalizeDn()
// was the third-heaviest application function in a CPU profile of the token
// endpoint under load, above anything in oauth2.js.
//
// The walk is now done ONCE per change and kept, which turns the per-token cost
// into two Map lookups and a sort of the handful of groups the person is
// actually in.
//
// **THE PROPERTY THAT MATTERS IS PRESERVED: an ldapadd changes the very next
// token.** That is the whole reason group_claims.js reads the membership per
// token and caches nothing, and it is the thing somebody came to a mock
// directory to watch. This is not a time-based cache and there is no staleness
// window — `directoryVersion` is bumped by every writer (see touchDirectory()
// beside the store), and a bumped version rebuilds on the next read, before it
// answers. What was rejected was a cache with a TTL, which would have bought
// the same speed and broken exactly that.
//
// Two maps, because the membership is asserted from two ends and this service
// deliberately does not reconcile them (see claimedMembersOf()):
//
//   byMember  a normalised member DN -> the groups whose OWN member attributes
//             name it, each with the attribute names that did the naming.
//   byDn      a normalised group DN -> enough of the group to build a row.
//             This is what answers the other direction: a person's `memberOf`
//             is looked up here, and a value naming an entry that is not a
//             group finds nothing and is skipped — which is what the old walk
//             did by returning early on an empty rule.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE INDEX IS PER REALM, AND IT HAS TO BE.
//
// `buildGroupIndex()` walks the AMBIENT realm's subtree and classifies each
// entry with `groupRuleFor()`, which asks `isUnder(dn, groupsDn())` — an
// ambient question. So an index built while the default realm was ambient
// describes the default realm and describes it wrongly for every other one, and
// a single module-level cache would have handed it out to all of them. The
// symptom would have been the worst kind: a `groups` claim in a token issued
// under `/realm/acme` naming the DEFAULT realm's groups, correct-looking,
// verifiable, and wrong.
//
// `realms.keyed()` is the ordinary tool for this — one value per realm, built
// lazily, purged with the realm. The four fields travel together in one object
// because they are one cache: a version that outlived its index would rebuild
// nothing and answer from a stale one.
//
// `size` is compared against `entries.size`, which is THIS REALM'S store since
// the split — and that is now a tighter net than it was, not a looser one. It
// is the second line of defence described above touchDirectory(), against a
// writer that forgot to bump the version; while one Map held every realm it
// also fired on another realm's writes, costing a rebuild for a change that
// could not have affected this index. Same net, no false positives.
// ---------------------------------------------------------------------------
const groupIndexes = realms.keyed(function () {
  return { index: null, version: -1, size: -1, builds: 0 };
});

const NO_GROUPS = new Map();

function buildGroupIndex() {
  log.debug('Entering buildGroupIndex().');
  const byMember = new Map();
  const byDn = new Map();
  eachEntryInRealm(function (entry) {
    const rule = groupRuleFor(entry);
    if (!rule) {
      return;
    }
    const groupKey = normalizeDn(entry.dn);
    byDn.set(groupKey, {
      dn: entry.dn,
      // The same two sources groupsFor() uses and in the same order, so the cn
      // in a token is the cn on the page. An entry under ou=groups with no cn
      // still has a name — its RDN — and a group with no name in a claim would
      // be an empty string in a list.
      cn: (entry.attributes.cn || [])[0] || commonNameOf(entry.dn),
      rule: rule
    });
    // MEMBER_ATTRIBUTES is walked in ITS order, once per group, which is what
    // keeps each `via` list in the order the old code produced: member,
    // uniqueMember, memberUid. A caller comparing two runs would otherwise see
    // the same membership described in a different order for no reason.
    MEMBER_ATTRIBUTES.forEach(function (attribute) {
      (entry.attributes[attribute.name] || []).forEach(function (value) {
        const raw = String(value == null ? '' : value);
        // memberUid holds a bare name where member and uniqueMember hold a DN.
        // Resolving it to the DN it MEANS here, at build time, is what lets the
        // lookup be a single Map.get — and it is exactly the resolution the old
        // walk did per value per token.
        const dn = attribute.holds === 'uid' ? 'uid=' + raw + ',' + usersDn() : raw;
        const memberKey = normalizeDn(dn);
        let groups = byMember.get(memberKey);
        if (!groups) {
          groups = new Map();
          byMember.set(memberKey, groups);
        }
        let via = groups.get(groupKey);
        if (!via) {
          via = [];
          groups.set(groupKey, via);
        }
        const name = canonicalName(attribute.name);
        // A group that names the same person twice through one attribute is a
        // directory a client wrote by hand, and it is not an error here — but
        // the attribute should appear once in `via`, as it did when the old
        // walk used some() rather than counting.
        if (via.indexOf(name) === -1) {
          via.push(name);
        }
      });
    });
  });
  groupIndexes().builds++;
  log.debug('Leaving buildGroupIndex(). ' + byDn.size + ' group(s) and ' +
            byMember.size + ' member name(s), built ' + groupIndexes().builds +
            ' time(s) so far.');
  return { byMember: byMember, byDn: byDn };
}

// The index, rebuilt if anything has been written since it was made. See the
// block above for why the size is checked as well as the version.
function groupIndexNow() {
  const cache = groupIndexes();
  if (cache.index && cache.version === directoryVersion &&
      cache.size === entries.size) {
    return cache.index;
  }
  cache.index = buildGroupIndex();
  cache.version = directoryVersion;
  cache.size = entries.size;
  return cache.index;
}

function groupsOfUser(key) {
  log.debug('Entering groupsOfUser(). key=' + key);
  const wanted = String(key == null ? '' : key).trim();
  const out = { key: wanted, dn: '', entryFound: false, groups: [],
                baseDn: baseDn(), groupsDn: groupsDn() };
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

  const index = groupIndexNow();
  // Keyed on the normalised group DN so that the two directions below meet on
  // the same row: a group that both lists the person AND is named by their own
  // memberOf is one group with both facts on it, which is what the old walk
  // produced by computing `via` and `viaMemberOf` on a single pass.
  const hits = new Map();

  (index.byMember.get(personDn) || NO_GROUPS).forEach(function (via, groupKey) {
    const group = index.byDn.get(groupKey);
    hits.set(groupKey, {
      dn: group.dn,
      cn: group.cn,
      rule: group.rule,
      // COPIED, not handed out: this array lives in the index and a caller that
      // sorted or spliced it would be editing the directory's own answer for
      // every token after it.
      via: via.slice(0),
      viaMemberOf: false
    });
  });

  // The other end of the disagreement: what the PERSON's entry claims. A value
  // naming something that is not a group finds nothing in byDn and is skipped,
  // which is what the old walk's empty rule did.
  if (located.stored) {
    (located.stored.attributes.memberof || []).forEach(function (value) {
      const groupKey = normalizeDn(value);
      const group = index.byDn.get(groupKey);
      if (!group) {
        return;
      }
      const already = hits.get(groupKey);
      if (already) {
        already.viaMemberOf = true;
        return;
      }
      hits.set(groupKey, {
        dn: group.dn,
        cn: group.cn,
        rule: group.rule,
        via: [],
        viaMemberOf: true
      });
    });
  }

  hits.forEach(function (row) {
    out.groups.push(row);
  });
  out.groups.sort(function (a, b) {
    return normalizeDn(a.dn) < normalizeDn(b.dn) ? -1 : 1;
  });
  log.debug('Leaving groupsOfUser(). ' + located.dn + ' is in ' +
            out.groups.length + ' group(s).');
  return out;
}

// The inverted hook. See the header for why the direction is this way round,
// and observeIdentity() for why what is installed is a dispatcher now rather
// than autoCreateUser() itself: the one slot carries three kinds of event.
stats.setUserObserver(observeIdentity);

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

// The console's THIRD slot, and the only one of the three that WRITES. It is
// deliberately not counted in with the cross-module numbering below, because
// what makes it different is not where it sits in the require order but what it
// does: the other two answer questions about the directory, and this one puts a
// person in it.
//
// It carries createUser() and not putEntry(): the console must not be a second
// definition of what creating a user means, any more than /admin/applications is
// a third door onto the registry. The refusal that matters — a username that is
// already here — is inside that function, so the form, the management API and an
// `ldapadd` all get the same answer about the same name.
//
// Guarded like the other two, and for the same reason.
if (typeof admin.setDirectoryWriter === 'function') {
  admin.setDirectoryWriter(createUser);
} else {
  log.warn('ldap: the admin console offers no setDirectoryWriter(), so ' +
           '/admin/users cannot create a person. The directory itself is ' +
           'unaffected, and an ldapadd still reaches it.');
}

// The fourth, and the only one that goes to a module this file also requires
// outright. That is not a contradiction: vc_claims.js is required above for the
// catalogue and the invented people, and it calls back into these two functions
// through a slot because IT must not require THIS module — it is read by
// vc_issuer.js, which server.js requires fifty lines before ./admin, and a
// require from there would drag this directory's routes to the front of the
// express router that /admin/sts-metadata is built by walking. Guarded like the
// two above: an older vc_claims.js without the slot costs a warning, not a
// service that will not start.
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

// ---------------------------------------------------------------------------
// CONSENT: THE FOUR FUNCTIONS THAT PUT AN ANSWER ON A PERSON'S ENTRY, AND READ
// IT BACK.
//
// `common/consent.js` owns the MODEL — the value's grammar, what "outstanding"
// means, the global override, the register both halves are read from. This
// module owns the STORE, which is `oauthConsent` on an entry under ou=users,
// and that division is the one `group_claims.js` and `applications.js` already
// have: neither file knows the other's half.
//
// **NOTHING HERE CREATES AN ENTRY.** A consent is written for somebody who has
// just authenticated, so their entry exists — `observeIdentity()` made it on
// the way past. Where it does not (`ldap.autoCreateUsers` off, or an entry
// deleted between the sign-in and the button), the write is REFUSED and says
// why, and consent.js turns that into "they will be asked again" rather than
// into a failed authorization. Creating a person here in order to file their
// consent would put somebody in the directory that `autoCreateUsers` had just
// been set to keep out.
//
// **THE IDENTITY IS ALREADY NORMALISED WHEN IT ARRIVES.** consent.js runs it
// through `admin_stats.js`'s identityKeyOf() first, which is the same
// normalisation `autoCreateUser()` used to place the entry — so `alice`,
// `alice@EXAMPLE.COM` and `urn:sts-mock:user:alice` reach `locateEntry()` as
// one key and find one entry. A second normalisation here would be a second
// opinion about who somebody is.
// ---------------------------------------------------------------------------

// Everything one person's entry holds. `found: false` for an identity with no
// entry, which is not an error — it is what a person who has never
// authenticated in this realm looks like.
function consentValuesOf(key) {
  log.debug('Entering consentValuesOf(). key=' + key);
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    log.debug('Leaving consentValuesOf(). There is no entry at ' + located.dn + '.');
    return { dn: located.dn, found: false, values: [] };
  }
  const values = (stored.attributes.oauthconsent || []).slice(0);
  log.debug('Leaving consentValuesOf(). ' + values.length + ' value(s) on ' + stored.dn + '.');
  return { dn: stored.dn, found: true, values: values };
}

// ADD values, through addValues() so that a value already there is not written
// twice — two identical consents would be two rows on /admin/consent for one
// answer, and revoking would remove one of them.
function addConsentValues(key, values) {
  log.debug('Entering addConsentValues(). key=' + key);
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    log.warn('ldap: "' + key + '" has no entry in this realm, so the consent they ' +
             'gave was not recorded. They will be asked again. This is what ' +
             'ldap.autoCreateUsers being off looks like from the consent screen.');
    log.debug('Leaving addConsentValues(). Nothing to write to.');
    return { ok: false, dn: located.dn, reason: 'noEntry' };
  }
  const changed = addValues(stored, 'oauthConsent', values);
  if (changed) {
    stored.attributes.modifytimestamp = [generalizedTime()];
    touchDirectory();
  }
  log.debug('Leaving addConsentValues(). ' + (changed ? 'Written.' : 'Already there.'));
  return { ok: true, dn: stored.dn, changed: changed };
}

// REMOVE values. An exact match on the whole value, because that is what the
// register handed out: the timestamp is part of it, so two consents to the same
// scope agreed at different times are two values and removing one leaves the
// other — which is the honest reading of an attribute somebody may have edited
// by hand.
function removeConsentValues(key, values) {
  log.debug('Entering removeConsentValues(). key=' + key);
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    log.debug('Leaving removeConsentValues(). There is no entry.');
    return { ok: false, dn: located.dn, reason: 'noEntry' };
  }
  const wanted = valuesOf(values);
  const have = stored.attributes.oauthconsent || [];
  const left = have.filter(function (one) {
    return wanted.indexOf(one) < 0;
  });
  if (left.length === have.length) {
    log.debug('Leaving removeConsentValues(). Nothing matched.');
    return { ok: false, dn: stored.dn, reason: 'notHeld' };
  }
  if (left.length) {
    stored.attributes.oauthconsent = left;
  } else {
    // THE ATTRIBUTE GOES RATHER THAN BECOMING EMPTY. LDAP has no empty
    // attribute — RFC 4511's modify with no values is a delete — so leaving
    // `oauthconsent: []` behind would put a value on the wire that no client
    // can read as anything and would show on /admin/ldap/directory as an
    // attribute with nothing in it.
    delete stored.attributes.oauthconsent;
  }
  stored.attributes.modifytimestamp = [generalizedTime()];
  touchDirectory();
  log.debug('Leaving removeConsentValues(). ' + (have.length - left.length) + ' removed.');
  return { ok: true, dn: stored.dn, removed: have.length - left.length };
}

// EVERY person in THIS REALM who has consented anything. It walks the realm's
// entries rather than reading a list, for `applications.js`'s reason about the
// registry: a Map of who has consented what would be a second store that looked
// right on its own and silently disagreed with an `ldapmodify`.
function listConsentValues() {
  log.debug('Entering listConsentValues().');
  const rows = [];
  eachEntryInRealm(function (entry) {
    const values = entry.attributes.oauthconsent || [];
    if (!values.length) {
      return;
    }
    rows.push({ dn: entry.dn, username: usernameOfEntry(entry), values: values.slice(0) });
  });
  log.debug('Leaving listConsentValues(). ' + rows.length + ' entry/entries.');
  return rows;
}

// The SEVENTH slot, and the second one that hands over a WRITER as well as
// readers. Guarded like the six above: an older `common/consent.js` without the
// slot costs a warning rather than a service that will not start — and the
// warning says what is lost, which is that the screen would draw for ever
// because nothing it recorded could be read back.
if (typeof consent.setDirectory === 'function') {
  consent.setDirectory({
    consentsOf: consentValuesOf,
    addConsent: addConsentValues,
    removeConsent: removeConsentValues,
    listConsents: listConsentValues
  });
} else {
  log.warn('ldap: common/consent.js offers no setDirectory(), so nothing a ' +
           'person agrees to at /oauth2/consent can be written down or read ' +
           'back. With oauth2.consentRequired on, the screen is drawn on every ' +
           'authorization request. The directory itself is unaffected.');
}

// The SIXTH, and it is the first one that hands over a WRITER as well as
// readers — which is the whole of what makes the admin console's two roles work
// the way every other membership in this service works.
//
// `admin_rbac.js` decides who may use `/admin`, and it decides it out of two
// ORDINARY GROUPS in this directory: `cn=admin-read` and `cn=admin-write` under
// `ou=groups` by default. It is a slot rather than a require in the other
// direction for exactly the reason the console's own five are (rule 3e): a
// require of this module from there would pull every `/ldap` route into the
// express router ahead of every `/admin` route, and `GET /admin/sts-metadata`
// is built by walking that router.
//
// WHAT CROSSES IS THIS MODULE'S OWN FUNCTIONS AND NOT A COPY OF ITS RULES, the
// same division the five above keep. `groupsOfUser()` answers whether somebody
// is in a group — by the three-shaped lookup, and in BOTH directions, so an
// administrator added by writing `memberOf` on their entry really holds the
// role — and `readGroupEntry`/`writeGroupEntry` are the same two functions SCIM
// writes a Group with. That is the point: a role granted on `/admin/rbac`, one
// granted by `POST /admin-api/rbac/grant`, one granted with an `ldapmodify` on
// 389 or 636 and one granted by a SCIM PATCH all leave the IDENTICAL entry,
// because all four end here. A membership store of the console's own would have
// been a second answer to "is alice an admin" that no directory client could
// see.
//
// It is ONE object where the console takes five separate slots, and the concern
// stated over there — a filler that installed only half of it would silently
// disable the other half — is answered rather than ignored: `setDirectory()`
// checks every member it needs and refuses a partial object with an error line
// naming what was missing. Guarded like the five above, so an older
// `admin_rbac.js` costs a warning rather than a service that will not start.
// ---------------------------------------------------------------------------
// AND EVERY ONE OF THEM IS PINNED TO THE DEFAULT REALM. THIS IS THE WHOLE OF
// "THE CONSOLE AUTHENTICATES AGAINST THE DEFAULT REALM".
//
// The directory is per realm now, so `groupsOfUser('alice')` means a different
// thing in each one — and the two console roles must not. A role is permission
// to change what EVERY realm's protocol endpoints do: `/admin/config` reached
// under `/realm/acme` writes acme's overrides, `/admin/realms` can delete a
// realm outright, and `/admin/applications` edits a registry the SAML and OAuth
// endpoints read. If the roster were per realm then anybody who could create a
// realm could grant themselves both roles inside it and walk back out into the
// default one — the realm feature would have become a privilege escalation.
//
// So `inDefaultRealm()` wraps each function in `realms.run(DEFAULT_REALM, …)`.
// Nine functions rather than a note asking callers to remember, because the
// caller is `admin_rbac.js` and it has no business knowing that realms exist:
// what it asked for was "the directory", and what it gets is the one directory
// that decides this.
//
// **THE ADMINISTRATORS THEMSELVES ARE THEREFORE DEFAULT-REALM PEOPLE.**
// `allPersons()` and `existingUserEntry()` are pinned with the rest, so the
// roster page lists the default realm's `ou=users` and a grant names an entry
// there. Somebody who exists only under `dc=acme,dc=example,dc=com` cannot hold
// a role and cannot be granted one — which is the point, and is why
// `authn.js`'s console gate resolves its session in the default realm too.
// The two halves have to agree: a gate that accepted an acme session while the
// roster could only name default-realm people would let somebody in and then
// insist they were nobody.
//
// It is deliberately NOT applied to `setDirectoryReader()` and
// `setDirectoryWriter()` above. Those draw the console's USER pages, and
// `/realm/acme/admin/users` showing the default realm's people instead of
// acme's would be a console that cannot see the realm it is pointed at. Reading
// a realm is the console's job; being let in is not the realm's decision.
// ---------------------------------------------------------------------------
function inDefaultRealm(fn) {
  return function () {
    const args = arguments;
    return realms.run(realms.DEFAULT_REALM, function () {
      return fn.apply(null, args);
    });
  };
}

if (typeof adminRbac.setDirectory === 'function') {
  adminRbac.setDirectory({
    groupsOfUser: inDefaultRealm(groupsOfUser),
    readGroupEntry: inDefaultRealm(readGroupEntry),
    writeGroupEntry: inDefaultRealm(writeGroupEntry),
    groupDnFor: inDefaultRealm(groupDnFor),
    normalizeDn: normalizeDn,
    existingUserEntry: inDefaultRealm(existingUserEntry),
    usernameOfEntry: usernameOfEntry,
    nameUsableInDn: nameUsableInDn,
    allPersons: inDefaultRealm(allPersons),
    // THE OTHER DIRECTION OF MEMBERSHIP. `readGroupEntry()` answers what the
    // GROUP lists; this answers who CLAIMS the group through their own
    // `memberOf` while the group does not list them back. `groupsOfUser()`
    // already honours both directions, so somebody added that way really holds
    // the role — and without this the roster page would have shown a console
    // they could use and a list they were not on, which is the one thing a
    // permissions page must never do.
    claimedMembersOf: inDefaultRealm(claimedMembersOf),
    // STRINGS, and the DEFAULT realm's — evaluated once, here, rather than read
    // per call. That is correct precisely because these are pinned: the default
    // realm's base DN cannot change while the process runs, so there is nothing
    // to re-read, and a function would only invite somebody to make it ambient.
    usersDn: realms.run(realms.DEFAULT_REALM, usersDn),
    groupsDn: realms.run(realms.DEFAULT_REALM, groupsDn)
  });
} else {
  log.warn('ldap: admin_rbac.js offers no setDirectory(), so the admin ' +
           'console cannot read or grant its two roles. With ' +
           'admin.authRequired on that leaves /admin reachable only while ' +
           'admin.openWhenEmpty is on. The directory itself is unaffected.');
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
// Every handler is registered against '' — the ROOT DSE and everything else —
// and each decides for itself whether the DN it was given is inside ROOT_DN. A
// client that binds before it knows the base DN reads the root DSE first, and a
// server that had no handler for it answers LDAP_UNAVAILABLE, which reads as the
// server being down.
//
// Registering at '' rather than at the base is also what lets one socket serve
// every trust realm: a realm's subtree is `dc=<id>,` + ROOT_DN, and the handlers
// reach it because they were never scoped to a base in the first place.
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
// being true: an absence recorded and published on GET /admin/ldap/service is worth more than
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
  // else, which GET /admin/ldap/service says out loud rather than leaving somebody to work
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

// ---------------------------------------------------------------------------
// AND THE ONE PLACE THAT DECIDES WHICH REALM'S DIRECTORY AN OPERATION TOUCHES.
//
// Every store in this service is per trust realm and the realm is AMBIENT — an
// AsyncLocalStorage that `app.js`'s first middleware enters on an HTTP request.
// **THERE IS NO HTTP REQUEST HERE.** A connection to 389 carries no path, no
// header and no realm; what it carries is a DN, and since the directory is a
// subtree per realm that DN NAMES ONE. So every handler below is wrapped, once,
// at registration: `realmFor(req.dn)` picks the realm and `realms.run()` enters
// it, after which `entries` inside the handler is that realm's store and every
// helper this file has is that realm's too. Not one of the eight handlers
// mentions a realm, and none of them should have to.
//
// WHY WRAPPED HERE RATHER THAN IN EACH HANDLER. Eight bodies each remembering
// to enter a realm is eight chances to forget, and the thing forgotten would be
// invisible: the operation would succeed against the DEFAULT realm's store and
// answer "no such object" for an entry that plainly exists. This is the same
// argument the store's own comment makes one level down — make it structural,
// not remembered.
//
// `unbind` has no DN and needs no realm: it ends a connection. It is left
// unwrapped rather than wrapped with a default, so that a reader wondering
// whether it was forgotten finds the answer here.
//
// A DN outside the naming context resolves to the default realm and is then
// refused by the handler's own `isUnder(dn, ROOT_DN)` check, exactly as before.
// ---------------------------------------------------------------------------
const REALMLESS_OPERATIONS = ['unbind'];

function inRealmOfRequest(handler) {
  return function (req, res, next) {
    const dn = req && req.dn ? req.dn.toString() : '';
    return inRealmOf(dn, function () {
      return handler(req, res, next);
    });
  };
}

const server = {};
OPERATIONS.forEach(function (operation) {
  server[operation] = function () {
    const args = Array.prototype.slice.call(arguments);
    if (REALMLESS_OPERATIONS.indexOf(operation) < 0) {
      // The handler is the LAST argument — ldapjs takes (dn, [middleware…],
      // handler) — and only it is wrapped, so a route registered with
      // middleware would keep its shape.
      args[args.length - 1] = inRealmOfRequest(args[args.length - 1]);
    }
    servers.forEach(function (one) {
      one[operation].apply(one, args);
    });
    // ldapjs returns the server for chaining and nothing here chains, but a
    // fan-out that returned undefined would break the first caller that did.
    return server;
  };
});

// ---------------------------------------------------------------------------
// THE LIVE CONNECTIONS, AND WHY THIS DIRECTORY HAS TO KEEP ITS OWN LIST.
//
// RFC 4511 section 4.2: a Bind establishes the authorization state of a
// CONNECTION, and it lasts until the next Bind or an Unbind. So in LDAP the
// connection IS the session — there is no ticket, no cookie and no token — and
// the only sign-out this protocol has is the connection ending. That is what
// the protocol-independent `/logout` needs to be able to reach.
//
// ldapjs cannot answer it. Its `Server` exposes `connections`, which is node's
// deprecated net.Server COUNT — a number — and nothing that enumerates the
// sockets or the DNs bound on them. The submodule is used unmodified (see this
// repository's CLAUDE.md), so the list is kept HERE, on the underlying
// net/tls server's own `connection`/`secureConnection` event, which fires for
// every socket ldapjs will then set up.
//
// Three things about it are deliberate:
//
//   * **It is a Set of the sockets themselves and nothing else.** The bound DN
//     is read off `socket.ldap.bindDN` at the moment somebody asks, never
//     copied here — ldapjs owns that value and re-binding on one connection
//     changes it. A copy would be a second store of one fact, and the one that
//     goes stale exactly when it matters.
//   * **Removal is on `close`**, which node emits for every socket however it
//     ended, so nothing has to be swept and a client that vanished does not
//     leave a row behind claiming to be signed in.
//   * **`listening` on the ldapjs Server is not required.** These handlers are
//     attached at require time, before `listen()` is called from server.js, so
//     a connection cannot arrive before there is somewhere to record it.
// ---------------------------------------------------------------------------
const liveConnections = new Set();

servers.forEach(function (one) {
  // `one.server` is the net.Server (or tls.Server) ldapjs built; see
  // node-ldapjs/lib/server.js, where it is assigned in the constructor. The TLS
  // one emits `secureConnection` rather than `connection` for a socket that has
  // completed its handshake, and ldapjs sets its own state up on that same
  // socket — so both names are listened for and a socket that somehow arrived
  // twice is a Set member added twice, which is once.
  ['connection', 'secureConnection'].forEach(function (event) {
    one.server.on(event, function (socket) {
      liveConnections.add(socket);
      socket.on('close', function () { liveConnections.delete(socket); });
    });
  });
});

// Every connection this process currently holds, with who is bound on it. The
// DN is read live, per the note above; `key` is the console's identity key for
// that person, derived the same way every other door here derives it, so a row
// on /logout and a row on /admin/users name one person rather than two.
function boundConnections() {
  log.debug("Entering boundConnections().");
  const out = [];
  liveConnections.forEach(function (socket) {
    const dn = (socket.ldap && socket.ldap.bindDN) ? String(socket.ldap.bindDN) : '';
    // ldapjs seeds an unbound connection with cn=anonymous rather than leaving
    // it empty — the same trap boundDnOf() documents — and an anonymous
    // connection is the absence of a bind, so it is reported as one.
    const bound = dn.toLowerCase() === 'cn=anonymous' ? '' : dn;
    out.push({
      id: (socket.ldap && socket.ldap.id) || ((socket.remoteAddress || '?') + ':' +
                                              (socket.remotePort || '?')),
      dn: bound,
      // The console's key for whoever is bound. `getEntry()` is passed so that
      // an entry's own `uid` wins over the DN's RDN — the same order every
      // other caller of consoleKeyFor() uses, and the reason a person bound as
      // `cn=alice,ou=users` (which is how a TLS client certificate seeds one)
      // still resolves to `alice` rather than to nothing.
      key: bound ? consoleKeyFor(bound, getEntry(bound)) : '',
      secure: !!socket.encrypted,
      port: socket.encrypted ? boundTlsPort : boundPort,
      socket: socket
    });
  });
  log.debug("Leaving boundConnections(). " + out.length + " connection(s).");
  return out;
}

// Close every connection bound as this person, and say which. It is the only
// sign-out LDAP has (see above), and what the client sees is its socket closing
// mid-conversation — which is what a directory server revoking a session looks
// like from the other end, and is worth being able to point a client at.
//
// `destroy()` rather than `end()`: end() sends a FIN and waits, and a client
// that is mid-search can keep the connection alive for as long as it likes,
// which would make a logout report success and leave the session up. An
// UNSOLICITED NOTICE OF DISCONNECTION (RFC 4511 section 4.4.1) would be the
// polite form and ldapjs has no way to send one, which is stated on /logout
// rather than left as a difference somebody discovers.
function dropConnectionsFor(key) {
  log.debug("Entering dropConnectionsFor(). key=" + key);
  const wanted = String(key || '');
  const dropped = [];
  boundConnections().forEach(function (row) {
    if (!row.key || row.key !== wanted) return;
    dropped.push({ id: row.id, dn: row.dn, secure: row.secure, port: row.port });
    try {
      row.socket.destroy();
    } catch (e) {
      // A socket that was already gone throws here, and that is the outcome
      // being asked for rather than a failure: it is counted as dropped because
      // it is not connected any more, which is what the caller asked about.
      log.debug('ldap: a connection bound as ' + row.dn + ' was already gone: ' + e.message);
    }
    liveConnections.delete(row.socket);
  });
  if (dropped.length) {
    log.info('ldap: dropped ' + dropped.length + ' connection(s) bound as ' + wanted +
             ' — RFC 4511 section 4.2 makes the bind the authorization state of the ' +
             'CONNECTION, so closing it is the only sign-out this protocol has.');
  }
  log.debug("Leaving dropConnectionsFor(). " + dropped.length + " dropped.");
  return dropped;
}

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
  log.debug('Entering membershipsNaming().');
  const key = normalizeDn(dn);
  const uid = (splitRdns(dn)[0] || '').toLowerCase().indexOf('uid=') === 0
    ? unescapeDnValue(rdnPairs(splitRdns(dn)[0])[0].value) : '';
  let count = 0;
  eachEntryInRealm(function (entry) {
    const names = MEMBER_ATTRIBUTES.some(function (attribute) {
      return (entry.attributes[attribute.name] || []).some(function (value) {
        return attribute.holds === 'uid'
          ? (uid && String(value).toLowerCase() === uid.toLowerCase())
          : normalizeDn(value) === key;
      });
    });
    if (names) count++;
  });
  log.debug('Leaving membershipsNaming().');
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
  // ROOT_DN, not baseDn(): THIS IS THE SOCKET, and the socket has no realm.
  // An LDAP client operating on `dc=acme,dc=example,dc=com` arrives with no
  // ambient realm at all, so asking whether its DN is under the DEFAULT realm's
  // base would refuse every realm's subtree — which is the one thing putting the
  // realm in the DN exists to make possible. The naming context this server
  // holds is the whole tree; which realm a DN belongs to is decided by where it
  // sits in that tree, and nothing here has to know.
  if (!isUnder(dn, ROOT_DN)) {
    log.debug('Leaving the LDAP add handler. Outside the naming context.');
    return next(new ldap.NoSuchObjectError(ROOT_DN));
  }
  if (getEntry(dn)) {
    log.debug('Leaving the LDAP add handler. It is already there.');
    return next(new ldap.EntryAlreadyExistsError(dn));
  }
  // ---------------------------------------------------------------------
  // AND ONE ENTRY PER PERSON, WHICH IS A DIFFERENT REFUSAL FROM THE ONE
  // ABOVE.
  //
  // That one is about the DN and every directory makes it. This is about the
  // USERNAME, and without it the fold the authentication path now does could
  // be undone from the other side in one operation: `uid=rcbj,ou=users`
  // exists, an add of `cn=rcbj,ou=users` succeeds, and this directory holds
  // two objects for one person again — with nothing having gone wrong that a
  // reader could point at.
  //
  // WHAT COUNTS AS A USERNAME is the two things existingUserEntry() looks at,
  // asked of the entry being added: the value of its naming RDN, whatever
  // attribute type names it, and any `uid` it carries. So `uid=rcbj,ou=users`,
  // `cn=rcbj,ou=users` and `sn=someone,ou=users` with `uid: rcbj` on it are
  // all refused once any one of them is here.
  //
  // SCOPED TO ou=users for the reason every other rule in this module is
  // scoped that way: placement is what decides that an entry is a person,
  // because a schemaless directory cannot believe an objectClass. An add of
  // `cn=rcbj,ou=people` is not a user by that rule and is not refused — this
  // enforces one entry per person in the container people live in, which is
  // the container everything else here reads.
  //
  // LDAP_ENTRY_ALREADY_EXISTS (68) rather than a constraint violation, and it
  // names the DN that already holds the name: a client that gets 68 back
  // looks for the entry it collided with, which is exactly what the message
  // hands it.
  // ---------------------------------------------------------------------
  if (normalizeDn(parentDn(dn)) === normalizeDn(usersDn())) {
    const proposed = [usernameOfEntry({ dn: dn })].concat(
      req.attributes.filter(function (attr) {
        return String(attr.type).toLowerCase() === 'uid';
      }).reduce(function (all, attr) {
        return all.concat(attr.values);
      }, []));
    let clash = null;
    proposed.forEach(function (candidate) {
      if (clash) {
        return;
      }
      clash = existingUserEntry(candidate);
    });
    if (clash) {
      log.info('ldap: refusing to add ' + dn + '; ' + clash.dn + ' already ' +
               'names that user. One entry per person, whatever protocol or ' +
               'operation brought them.');
      log.debug('Leaving the LDAP add handler. That username is taken.');
      return next(new ldap.EntryAlreadyExistsError(clash.dn));
    }
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
  if (totalEntries() >= maxEntries()) {
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
                                     { users: usersDn(), groups: groupsDn() }),
    target: dn,
    summary: 'added ' + dn + ' with ' + Object.keys(attributes).length +
             ' attribute(s)',
    detail: { attributes: Object.keys(attributes).join(', '),
              attributeCount: Object.keys(attributes).length,
              objectClass: (attributes.objectClass || attributes.objectclass ||
                            []).join(', '),
              entriesNow: totalEntries() }
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
  touchDirectory();
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
                                     { users: usersDn(), groups: groupsDn() }),
    target: dn,
    summary: 'deleted ' + dn,
    detail: { attributeCount: Object.keys(stored.attributes).length,
              danglingLeft: dangling,
              entriesNow: totalEntries(),
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
  touchDirectory();
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
                                     { users: usersDn(), groups: groupsDn() }),
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
  // ROOT_DN, not baseDn(): THIS IS THE SOCKET, and the socket has no realm of
  // its own. An LDAP client operating on `dc=acme,dc=example,dc=com` arrives
  // with nothing ambient, so asking whether its DN is under the DEFAULT realm's
  // base would refuse every realm's subtree — the one thing putting the realm
  // in the DN exists to make possible. Which realm a DN belongs to is decided
  // by where it sits, and `realmFor()` did that before this handler ran.
  if (!isUnder(target, ROOT_DN)) {
    log.debug('Leaving the LDAP modifyDN handler. Outside the naming context.');
    return next(new ldap.NoSuchObjectError(ROOT_DN));
  }
  // A RENAME MAY NOT CROSS A REALM, and this is the one operation that could
  // try. Every handler runs in the realm of the DN it was GIVEN, so a modifyDN
  // whose target is in another realm would delete the entry from this store and
  // write it back into this same store under a DN that names somebody else's —
  // an entry filed in the wrong directory, which is the one state the split is
  // supposed to make unreachable. Refused with LDAP_AFFECTS_MULTIPLE_DSAS,
  // which is what a real directory answers when a modifyDN would move an entry
  // out of the DSA that holds it: two realms here are two directories, and this
  // is that error being true rather than borrowed.
  if (realmFor(target).id !== realmFor(dn).id) {
    log.info('ldap: refusing to rename ' + dn + ' into the "' +
             realmFor(target).id + '" realm; a rename may not cross a trust ' +
             'realm, because each realm is a separate directory.');
    log.debug('Leaving the LDAP modifyDN handler. It would cross a realm.');
    return next(new ldap.AffectsMultipleDsasError(target));
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
  touchDirectory();
  // The kind is taken from the NEW DN, because that is what the entry is now —
  // and a rename can move an entry between containers, which is exactly the
  // case where the two DNs would disagree. Both are on the row, so a rename out
  // of ou=users shows as a `user.rename` or an `entry.rename` with the other
  // name beside it rather than as a row that quietly picked one.
  auditLdap(req, {
    action: audit.directoryActionFor('rename', target,
                                     { users: usersDn(), groups: groupsDn() }),
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
          // EVERY REALM'S BASE, not just ROOT_DN, and this changed on
          // 2026-08-25 with the search scoping below. A search from ROOT_DN
          // now answers about the DEFAULT realm only, so publishing it alone
          // would have left a client no way to discover that the others are
          // there — and discovery is the one job the root DSE has. Each realm
          // is a container a client can search from and gets its own value;
          // with no realms defined this is a single-valued attribute holding
          // exactly what it always held.
          namingcontexts: namingContexts(),
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
  // ROOT_DN, and this is the line that makes `ldapsearch -b
  // "dc=acme,dc=example,dc=com"` work: a realm's subtree is INSIDE the naming
  // context, so a search based there is in-context and is answered from the one
  // tree. Comparing against the ambient realm's base instead would have made
  // every realm unreachable from 389 and 636, which is the whole reason the
  // realm is in the DN rather than in a partitioned store.
  if (!isUnder(base, ROOT_DN)) {
    log.debug('Leaving the LDAP search handler. Outside the naming context.');
    return next(new ldap.NoSuchObjectError(base));
  }
  if (!getEntry(base)) {
    log.debug('Leaving the LDAP search handler. The base does not exist.');
    return next(new ldap.NoSuchObjectError(base));
  }
  // ---------------------------------------------------------------------
  // WHICH REALM THIS SEARCH IS IN was decided before this handler ran: every
  // operation is wrapped in `realms.run(realmFor(req.dn))` at registration, so
  // `entries` below is the store of the realm the BASE names and there is
  // nothing here to filter. `-b "dc=example,dc=com"` is the default realm's
  // directory; `-b "dc=acme,dc=example,dc=com"` is acme's; the root DSE
  // publishes both so a client can find them.
  //
  // THIS BLOCK ARGUED THE OPPOSITE UNTIL 2026-08-25. The rule was that a
  // subtree search from the naming context returns EVERY realm's entries,
  // because that is what a naming context is and a directory that hid part of
  // its own tree would be lying about the one thing LDAP exists to answer. It
  // is a good argument and it lost to a better one: it left port 389 as the
  // single door through which one realm's people, groups and applications were
  // visible from another, while the console, `/scim/v2`, the group claim and
  // every enumerator in this file showed a realm only its own. A naming context
  // narrower than the process is a smaller surprise than that.
  //
  // WITH NO REALMS DEFINED there is one store and one context, and every byte
  // of this answer is what it always was.
  // ---------------------------------------------------------------------
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
    if (isUnder(stored.dn, usersDn()) && normalizeDn(stored.dn) !== normalizeDn(usersDn())) {
      usersSent++;
    }
  }
  // The other naming contexts are NAMED on a search that found nothing useful
  // in this one, rather than left for somebody to deduce. A client searching
  // `dc=example,dc=com` for a person who is in `acme` gets an empty answer that
  // is correct and unhelpful; this is the line that says where to look. It is
  // logged rather than returned, because LDAP has no field for "try over
  // there" — the root DSE is where a client is supposed to read it.
  const otherContexts = namingContexts().filter(function (context) {
    return normalizeDn(context) !== normalizeDn(realmBaseDn(realms.currentId()));
  });
  log.info('ldap: the search considered ' + considered + ' entry/entries in ' +
           'scope and returned ' + sent + '.' +
           (otherContexts.length
             ? ' This is the "' + realms.currentId() + '" realm\'s directory; ' +
               otherContexts.length + ' other naming context(s) exist (' +
               otherContexts.join(', ') + ') and hold their own entries.'
             : ''));
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
// GET /admin/sts-metadata is built by walking the express router, so a protocol
// that registers no route is invisible to it — which is exactly what a raw TCP
// listener is. The FIVE routes below are what make this directory visible from
// a browser AND what make it appear in that index; the two listeners
// themselves are described by hand there, as the KDC's are.
//
// THEY ARE ADMIN CONSOLE PAGES SINCE 2026-09-01 (`/admin/ldap/*`, drawn in
// that console's shell through `admin.respond()`), and the long block above
// the first of them argues the move. They were `/ldap`, `/ldap/directory`,
// `/ldap/applications`, `/ldap/federations` and `/ldap/spiffe`; those paths
// answer nothing now, deliberately, rather than redirecting — a service that
// keeps a path alive forever is a service whose endpoint list stops meaning
// anything, and `/admin/sts-metadata` is built by reading that list.
// ---------------------------------------------------------------------------

// What this directory is, as data. Shared by the page and by ?format=json so
// the two cannot disagree — which is the same reason /admin/sts-metadata reads
// the router rather than a written-down list.
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
    baseDn: baseDn(),
    usersDn: usersDn(),
    groupsDn: groupsDn(),
    // WHAT A SEARCH FROM EACH OF THESE ANSWERS ABOUT, published rather than
    // left to be discovered: since 2026-08-25 a subtree search is scoped to the
    // trust realm whose base it started from, so `-b "dc=example,dc=com"` is
    // the default realm's directory rather than every realm's. With no realms
    // defined there is one context here and the sentence is about the whole
    // store, exactly as it always was.
    namingContexts: namingContexts(),
    searchScope: realms.active()
      ? 'a subtree search answers about the trust realm whose base DN it ' +
        'started from. ' + namingContexts().join(' and ') + ' are the ' +
        'contexts; an entry belonging to another realm is filtered out of a ' +
        'search based above it, and is reached by searching from that ' +
        'realm\'s own base. An operation that names ONE DN — add, modify, ' +
        'delete, compare, or a base-scope search — is answered wherever that ' +
        'DN is, because spelling the DN out names the realm'
      : 'no trust realms are defined, so there is one context (' + ROOT_DN +
        ') and a subtree search from it answers about the whole store',
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
    // ---------------------------------------------------------------------
    // WHETHER THIS DIRECTORY SURVIVES A RESTART, AND IT DID NOT UNTIL
    // 2026-08-27.
    //
    // Published HERE, on the page that describes the directory, rather than
    // only on /admin/persistence, because this is the page somebody reads
    // before they trust the thing with anything — and because /admin is gated
    // and this is not, so a test driving the directory can see it. The answer
    // is persistence.js's own status object verbatim rather than a summary of
    // it: a second sentence about what is persisted is a second sentence that
    // will disagree with the first.
    //
    // In the default memory mode it says `mode: "memory"`, which is what every
    // reader of this page saw implicitly for the whole life of this service.
    // ---------------------------------------------------------------------
    persistence: persistence.status(),
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
          tlsPorts.tls + ' and ' + tlsPorts.mtls + ' serve. It is ' +
          tlsServer.certificateProvenance() + ': GET ' +
          '/tls/server-certificate hands it out in PEM. One anchor for all ' +
          'three sockets is why they share it.'
      }
    },
    autoCreateUsers: autocreateUsers(),
    autoCreateRule: 'an entry uid=<name>,' + usersDn() + ' appears the first ' +
      'time <name> authenticates to this service through ANY protocol. An ' +
      'LDAP bind does not seed one (it presents a DN, not a user name) and ' +
      'neither does an OAuth client. A verified TLS CLIENT CERTIFICATE is the ' +
      'one identity that is already a DN: its entry keeps the subject\'s own ' +
      'leaf RDN — cn=alice,' + usersDn() + ' for CN=alice,O=Example — or the ' +
      'whole subject where that already lies under ' + baseDn() + ', and the ' +
      'full subject, issuer, serial and validity are on the entry as x509* ' +
      'attributes, which are this service\'s own names and not schema. A ' +
      'DECENTRALIZED IDENTIFIER is the third shape and is neither a name nor a ' +
      'DN: an issued credential\'s did:jwk subject, whatever DID presents to ' +
      'the OID4VP Verifier, the one /did/generate mints. Its entry goes at ' +
      'uid=did-<12 hex of the SHA-256 of the DID>,' + usersDn() + ' — a ' +
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
      'a group here grants nothing — bar the two groups that decide who may ' +
      'use the admin console, which is the one exception anywhere in this ' +
      'directory and is confined to that console.',
    enforcedRules: [
      'an add whose parent does not exist is LDAP_NO_SUCH_OBJECT (32)',
      'a delete of an entry with children is LDAP_NOT_ALLOWED_ON_NONLEAF (66)',
      'a modify delete of an attribute that is not present is ' +
        'LDAP_NO_SUCH_ATTRIBUTE (16)',
      'deleting the last value of an attribute deletes the attribute',
      'an add under ou=users whose username is already here is ' +
        'LDAP_ENTRY_ALREADY_EXISTS (68), naming the entry that holds it. ' +
        'ONE ENTRY PER PERSON: the username is the entry\'s naming RDN value ' +
        'and any uid it carries, so uid=rcbj and cn=rcbj are the same person ' +
        'and only one of them can be here. It is the same refusal the console ' +
        'and POST /admin-api/users/create give, and the same rule every ' +
        'protocol here folds onto when it authenticates somebody'
    ],
    limits: {
      maxEntries: maxEntries(),
      maxSearchResults: maxSearchResults(),
      currentEntries: entries.size,
      // The cap is on the PROCESS and `currentEntries` is this realm's, so the
      // two would look like a contradiction on a page that showed only them.
      currentEntriesEverywhere: totalEntries()
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

// ---------------------------------------------------------------------------
// THE FIVE HTML VIEWS, WHICH ARE ADMIN CONSOLE PAGES SINCE 2026-09-01.
//
// They were `/ldap`, `/ldap/directory`, `/ldap/applications`,
// `/ldap/federations` and `/ldap/spiffe` — five pages in a shell of their own,
// with their own stylesheet, no sidebar, no breadcrumb, no realm switcher and
// no gate. Every one of them answers a question about what is in THIS
// SERVICE'S DIRECTORY, which is the question the four pages under the
// console's *Directory* heading already answer; the only thing that made them
// a separate surface was that they happened to have been written here.
//
// So they are `/admin/ldap/*` now, drawn by `admin.respond()` in the console's
// own shell. Four things about that arrangement are worth knowing before
// touching any of it.
//
//   * **THEY ARE STILL BUILT HERE, and that is not a leftover.** A console
//     page is a `path` and a `label` in `admin-ui/admin.js`'s `SECTIONS`
//     whoever builds the body — `/admin/sts-metadata` is built by
//     `../sts_metadata.js` for the same reason and has been since 2026-08-24.
//     Moving these bodies into that file would mean moving `description()`,
//     `eachEntryInRealm()` and `entryObject()` with them, or exporting all
//     three; the directory's own store belongs to the directory's own module.
//   * **THEY ARE GATED NOW.** `admin.js` registers its gate as one
//     `app.use('/admin', ...)` above its own routes, and this module is
//     required at #21 — far below — so a route registered here under `/admin`
//     is behind it. That is a real change in what an unauthenticated caller
//     can reach and it is the right one: a dump of every attribute of every
//     entry prints `oauthClientSecret` and `fedClientSecret` in the clear, and
//     these were the one surface in this service handing those to anybody who
//     could reach the port. `/admin-api` mirrors all five and is still
//     ungated, which is what a test drives.
//   * **NOTHING ABOUT THE CONTENT CHANGED, bar the paging and the
//     shortening.** These pages still show the store rather than a copy of it;
//     `?format=json` still answers with the same payload; the schemas each one
//     publishes are still read out of the module that owns them.
//   * **THE PAGING AND THE SHORTENING ARE THE CONSOLE'S, not this file's.**
//     `admin.pagedRows()`, `admin.pageNavPair()`, `admin.perPageOptions()` and
//     `admin.clipped()` are the same functions `/admin/tokens` and
//     `/admin/applications` use. A control on one of these pages that behaved
//     differently from the identical-looking control on the page next door
//     would be the worst possible outcome of moving them here.
//
// The `?format=json` half of each is a `view()` function returning
// `{ title, inner, json }` — the shape every view in `admin.js` returns — and
// the five are handed to `admin.setDirectoryPages()` at the foot of this file
// so that `mgmt-api/admin_api.js` can answer them without requiring this
// module. See the block above that slot in `admin.js`.
// ---------------------------------------------------------------------------

// The two facts every one of these pages needs about the reader's query, in
// one place: which page of which size they are looking at. Written out rather
// than inlined five times because the FILTER differs per page and the paging
// does not.
function directoryPaging(req, rows, noun, name) {
  return admin.pagedRows(req.query, rows,
                         { noun: noun, name: name || null });
}

// The `per` a control has to carry onward. Empty unless the reader chose one,
// so the URL of an unfiltered first page is still the bare path — the rule
// `queryWith()` follows for every other value.
function perOf(req, paging) {
  return req.query.per ? String(paging.perPage) : '';
}

// ---------------------------------------------------------------------------
// GET /admin/ldap/service — what the directory IS, right now.
//
// The only page in this console that can tell a running listener from one
// whose port was taken: it is HTTP and answers either way, and the two raw
// sockets are invisible to everything that walks the express router.
//
// It is deliberately NOT `/admin/ldap`, which is the LDAP / LDAPS SETTINGS
// page under *Protocols*. The two answer different questions and the
// difference is the useful one: that page says what the sockets are SET to and
// lets somebody change it, and this one says what actually happened when the
// process tried. Each links to the other rather than restating it.
// ---------------------------------------------------------------------------
function ldapServiceView(req) {
  log.debug('Entering ldapServiceView().');
  const info = description(req);
  const rows = [
    ['URL', info.url],
    ['LDAPS URL', info.tls.ldaps
      ? info.tls.url
      : 'not offered — ' + (info.tls.error || 'no reason was recorded')],
    ['Base DN', info.baseDn],
    ['People', info.usersDn],
    ['Groups', info.groupsDn],
    // Only where there is more than one, so the ordinary single-realm page is
    // exactly the page it was — a row that always said the same thing as the
    // one above it would be noise on every deployment that has no realms.
    ...(info.namingContexts.length > 1
      ? [['Naming contexts', info.namingContexts.join(', ')],
         ['What a search answers about', info.searchScope]]
      : []),
    ['Protocol version', 'LDAPv3'],
    ['Transport', 'plain TCP on ' + info.port + ', and LDAPS — TLS from the ' +
      'first byte — on ' + (info.tls.port || LDAPS_PORT) + '. There is no ' +
      'StartTLS: it is an extended operation and this library implements none.'],
    ['Entries right now', String(info.limits.currentEntries)],
    // The one row on this page that answers "and will any of this still be
    // here tomorrow". See description()'s `persistence` member.
    ['Persistence', info.persistence.mode === 'memory'
      ? 'NONE — this directory is in memory and goes when the process does, ' +
        'which is what this service did until 2026-08-27. Set ' +
        'persistence.mode to ldif (a file per realm, no database) or ' +
        'postgres (a shared store) to change that.'
      : info.persistence.mode + ' — ' +
        (info.persistence.mode === 'ldif'
          ? 'an RFC 2849 LDIF file per realm in ' + info.persistence.dataDir
          : 'PostgreSQL at ' +
            (info.persistence.database ? info.persistence.database.host + ':' +
             info.persistence.database.port + '/' +
             info.persistence.database.database : 'a connection string')) +
        '. ' + info.persistence.entriesTracked + ' entry/entries written; ' +
        (info.persistence.lastError
          ? 'THE LAST WRITE FAILED (' + info.persistence.lastError + ') — the ' +
            'directory is unaffected and is still answering from memory, and ' +
            'the next change will try again'
          : 'last write ' + (info.persistence.lastWriteAt || 'not yet')) +
        '. Sessions, tokens, codes, artifacts and tickets are NEVER persisted ' +
        'in any mode.'],
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
    // The VALUE is clipped and the LABEL is not: a label here is four words
    // and a value is a sentence or a DN. admin.clipped() leaves anything
    // under its limit exactly as it was, so the short rows are untouched and
    // the two long ones stop pushing the table past the card.
    return '<tr><td>' + xmlEscape(pair[0]) + '</td><td>' +
      admin.clipped(pair[1], 150) + '</td></tr>';
  }).join('');

  // The two sockets as TILES, which is the console's own way of saying
  // "here are the numbers, and here is the one that is wrong". A listener
  // that failed to bind is the single most useful fact on this page and it
  // was previously the eleventh row of a fourteen-row table.
  const tiles = '<div class="tiles">' +
    admin.tile(info.limits.currentEntries, 'Entries in this realm') +
    admin.tile(info.limits.currentEntriesEverywhere, 'Entries in the process') +
    admin.tile(info.listening ? 'up' : 'down', 'TCP ' + info.port) +
    admin.tile(info.tls.listening ? 'up' : 'down',
               'LDAPS ' + (info.tls.port || LDAPS_PORT)) +
    '</div>';

  const inner = '<p class="sub">LDAPv3 over TCP ' + LDAP_PORT + ', and over ' +
    'TLS on ' + LDAPS_PORT + ', RFC 4511. A browser cannot speak it &mdash; ' +
    'the debugger&rsquo;s api opens the socket. What the sockets are SET to ' +
    'is <a href="/admin/ldap">LDAP / LDAPS</a>; this page is what actually ' +
    'happened when this process tried to bind them.</p>' +
    tiles +
    '<table><tr><th>Thing</th><th>Value</th></tr>' + rows + '</table>' +
    '<h2>It authenticates nobody</h2>' +
    admin.note(xmlEscape(info.bindPolicy) + '.') +
    '<h2>Where an identity&rsquo;s entry goes</h2>' +
    admin.note(xmlEscape(info.autoCreateRule)) +
    '<h2>And how they authenticated</h2>' +
    admin.note(xmlEscape(info.authenticationFacts)) +
    '<h2>LDAPS, and what it does not change</h2>' +
    admin.note('Port ' + (info.tls.port || LDAPS_PORT) + ' is the same ' +
    'directory over TLS &mdash; the same entries, the same handlers, the same ' +
    'every-bind-succeeds. What TLS adds is that the password is not on the ' +
    'wire in the clear; it does not make it <em>checked</em>. The certificate ' +
    'is <strong>the one the HTTPS listeners serve</strong>: ' +
    '<code>' + xmlEscape(info.tls.certificate.subject) + '</code>, SHA-256 ' +
    '<code>' + xmlEscape(info.tls.certificate.fingerprint256) + '</code>, ' +
    xmlEscape(tlsServer.certificateProvenance()) + '. Fetch it from ' +
    '<a href="/tls/server-certificate">/tls/server-certificate</a> and put it ' +
    'in your truststore &mdash; <code>LDAPTLS_REQCERT=never</code> is the ' +
    'habit this endpoint exists to avoid, and it would also hide the one ' +
    'thing worth checking here.') +
    admin.note(xmlEscape(info.tls.clientCertificates) + ' There is no ' +
    'StartTLS: it is an extended operation (RFC 4511 &sect;4.14) and ldapjs ' +
    'implements none, and this service does not patch that submodule. LDAPS ' +
    'is the one of the two no RFC defines &mdash; RFC 4513 standardised ' +
    'StartTLS and left <code>ldaps://</code> as the de-facto scheme every ' +
    'client speaks anyway.') +
    '<h2>It has no schema</h2>' +
    admin.note(xmlEscape(info.schema)) +
    '<h2>What it does still enforce</h2>' +
    info.enforcedRules.map(function (rule) {
      return admin.bullet(xmlEscape(rule));
    }).join('') +
    admin.note('And one thing it does <em>not</em>: deleting a user leaves ' +
    'its DN in every group that lists it as a <code>member</code>. ' +
    'Referential integrity is a directory feature, not a protocol rule.') +
    '<h2>The containers</h2>' +
    admin.note('The tree has three containers. <code>ou=users</code> holds ' +
    'people, one per identity that has authenticated here through any ' +
    'protocol. <code>ou=groups</code> holds groups, which grant nothing. ' +
    '<code>ou=applications</code> holds the OTHER side of those ' +
    'authentications &mdash; every OAuth client, relying party, service ' +
    'provider and Kerberos service this service has been asked about &mdash; ' +
    'and it is different from the other two in one way worth knowing: ' +
    '<strong>it is a registry rather than a record</strong>. The RFC 7591 ' +
    'client registrations live there and nothing caches them, so an ' +
    '<code>ldapmodify</code> of an application entry changes what the ' +
    'protocol endpoints do. ' +
    '<a href="/admin/ldap/applications">What is in it, and the schema it ' +
    'uses</a>.') +
    '<p class="sub"><a href="/admin/ldap/service?format=json">This page as ' +
    'JSON</a> &middot; <a href="/admin/ldap/applications">the application ' +
    'registry</a> &middot; <a href="/admin/ldap/directory">every entry in the ' +
    'directory</a> &middot; <a href="/admin/ldap">the settings behind these ' +
    'sockets</a> &middot; <a href="/admin/sts-metadata">everything this ' +
    'service speaks</a></p>';
  log.debug('Leaving ldapServiceView().');
  return { title: 'The directory service', inner: inner, json: info };
}

app.get('/admin/ldap/service', function (req, res) {
  log.debug('Entering GET /admin/ldap/service.');
  const view = ldapServiceView(req);
  admin.respond(req, res, view.json, view.title, '/admin/ldap/service',
                view.inner);
  log.debug('Leaving GET /admin/ldap/service.');
});

// ---------------------------------------------------------------------------
// GET /admin/ldap/directory — every entry, paged.
//
// THE PAGING IS NEW AND IT IS NOT A CONVENIENCE. This page prints one row per
// entry with EVERY attribute of that entry in the last column, and the cap on
// the store (`ldap.maxEntries`) is in the hundreds — so a service that has
// been driven by a test suite for an hour answered this path with a document
// several megabytes long and a browser that took seconds to lay it out. It
// pages the way every other list in this console pages, through the same two
// functions, so `?per=` and `?page=` mean here exactly what they mean on
// `/admin/tokens`.
//
// THE FILTER IS OVER THE WHOLE ENTRY AND NOT ONLY THE DN, which is the one
// thing about it worth stating: somebody looking for the entry that carries a
// particular client secret or thumbprint has the VALUE and not the name. So
// `q` matches the DN, any attribute name and any attribute value, and the
// page says so under the box rather than leaving it to be discovered.
// ---------------------------------------------------------------------------
function ldapDirectoryView(req) {
  log.debug('Entering ldapDirectoryView().');
  const listed = [];
  eachEntryInRealm(function (stored) {
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

  const wantedText = String(req.query.q || '').trim();
  const wantedOrigin = String(req.query.origin || '').trim();
  const needle = wantedText.toLowerCase();
  const filtered = listed.filter(function (entry) {
    if (wantedOrigin && entry.origin !== wantedOrigin) {
      return false;
    }
    if (!needle) {
      return true;
    }
    if (entry.dn.toLowerCase().indexOf(needle) >= 0) {
      return true;
    }
    // The NAMES and the VALUES both. See the header: the reader who needs
    // this box most often has a value in hand and no idea which entry it is
    // on, which a DN-only search cannot answer at all.
    return Object.keys(entry.attributes).some(function (name) {
      if (name.toLowerCase().indexOf(needle) >= 0) {
        return true;
      }
      return entry.attributes[name].some(function (value) {
        return String(value).toLowerCase().indexOf(needle) >= 0;
      });
    });
  });

  const paged = directoryPaging(req, filtered, 'entries');
  const paging = paged.paging;

  if (String(req.query.format || '').toLowerCase() === 'json') {
    log.debug('Leaving ldapDirectoryView(). JSON, ' + paged.shown.length +
              ' of ' + filtered.length + ' entry/entries.');
  }

  // ORIGINS COUNTED OVER EVERYTHING and never over the filtered set, for the
  // reason /admin/applications gives about its Kind select: options that
  // renumber themselves as the reader narrows the list cannot be used to find
  // out where the rows went.
  const origins = [];
  listed.forEach(function (entry) {
    if (origins.indexOf(entry.origin) < 0) {
      origins.push(entry.origin);
    }
  });
  origins.sort();
  const originOptions = ['<option value=""' + (wantedOrigin ? '' : ' selected') +
                         '>any origin</option>']
    .concat(origins.map(function (origin) {
      const n = listed.filter(function (e) { return e.origin === origin; }).length;
      return '<option value="' + xmlEscape(origin) + '"' +
             (origin === wantedOrigin ? ' selected' : '') + '>' +
             xmlEscape(origin) + ' (' + n + ')</option>';
    })).join('');

  const filterParams = { q: wantedText || '', origin: wantedOrigin || '',
                         per: perOf(req, paging) };
  const nav = admin.pageNavPair('/admin/ldap/directory', filterParams, paging);

  const rows = paged.shown.map(function (entry) {
    const attrs = Object.keys(entry.attributes).sort().map(function (name) {
      return '<div><code>' + xmlEscape(name) + '</code>: ' +
        admin.clippedValues(entry.attributes[name]) + '</div>';
    }).join('');
    return '<tr><td class="dn">' + admin.clipped(entry.dn, 60) +
      '</td><td class="from">' + xmlEscape(entry.origin) +
      '</td><td class="attrs">' + attrs + '</td></tr>';
  }).join('');

  const inner = '<p class="sub">' + listed.length + ' entry/entries under ' +
    '<code>' + xmlEscape(baseDn()) + '</code>. This page is not LDAP &mdash; ' +
    'it is this service showing its own store, which is how you can tell an ' +
    'empty directory from a search filter that matched nothing.</p>' +
    '<div class="tiles">' +
    admin.tile(listed.length, 'Entries in this realm') +
    admin.tile(filtered.length, 'Matching the filter') +
    admin.tile(origins.length, 'Origins') +
    '</div>' +
    '<form method="get" action="/admin/ldap/directory"><div class="formrow">' +
    '<label for="q">Anywhere in the entry</label>' +
    '<input type="text" id="q" name="q" value="' + xmlEscape(wantedText) +
    '" size="30" placeholder="a DN, an attribute name, or a value">' +
    '<label for="origin">Came from</label>' +
    '<select id="origin" name="origin">' + originOptions + '</select>' +
    '<label for="per">Show</label>' +
    '<select id="per" name="per">' +
    admin.perPageOptions(paging.perPage) + '</select>' +
    '<button type="submit">Filter</button>' +
    ((wantedText || wantedOrigin)
      ? ' <a href="/admin/ldap/directory">clear</a>' : '') +
    '</div></form>' +
    admin.note('The box matches the DN, any attribute NAME and any attribute ' +
    'VALUE, case-insensitively. Values are searched because the reader who ' +
    'needs this most often has a thumbprint or a secret in hand and no idea ' +
    'which entry carries it, which a search over DNs alone cannot answer.') +
    nav.head +
    '<table><tr><th class="dn">DN</th><th class="from">Came from</th>' +
    '<th>Attributes</th></tr>' +
    (rows || '<tr><td colspan="3">No entry matches. ' +
             ((wantedText || wantedOrigin)
               ? 'The filter above may be hiding some.'
               : 'This realm&rsquo;s directory is empty.') + '</td></tr>') +
    '</table>' +
    nav.foot +
    admin.note('<strong>A value too long for its column is shortened, and ' +
    'the whole of it is one hover away.</strong> Hovering a shortened value ' +
    'opens a box holding it in full; one click inside that box selects all ' +
    'of it, so it can be copied. Nothing is lost by the shortening &mdash; ' +
    '<code>?format=json</code> below is the whole store with nothing cut, ' +
    'and the full value is in this page&rsquo;s markup either way.') +
    '<p class="sub"><a href="/admin/ldap/directory?format=json">This page as ' +
    'JSON</a> &middot; <a href="/admin/ldap/service">what this directory ' +
    'is</a> &middot; <a href="/admin/users">the people in it</a> &middot; ' +
    '<a href="/admin/groups">the groups in it</a></p>';

  log.debug('Leaving ldapDirectoryView(). ' + paged.shown.length + ' row(s) of ' +
            filtered.length + ' matched.');
  return {
    title: 'Every entry in the directory',
    inner: inner,
    json: {
      baseDn: baseDn(),
      // `count` is every entry in this realm and `matched` is what the filter
      // left. The first name is kept because it is what this endpoint has
      // always answered with and a caller reads it; the second is the console's
      // own word for the same idea on every other list.
      count: listed.length,
      matched: filtered.length,
      shown: paged.shown.length,
      filter: { q: wantedText || null, origin: wantedOrigin || null },
      origins: origins,
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      entries: paged.shown
    }
  };
}

app.get('/admin/ldap/directory', function (req, res) {
  log.debug('Entering GET /admin/ldap/directory.');
  const view = ldapDirectoryView(req);
  admin.respond(req, res, view.json, view.title, '/admin/ldap/directory',
                view.inner);
  log.debug('Leaving GET /admin/ldap/directory.');
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
  return 'cn=' + escapeDnValue(applications.labelFor(identifier)) + ',' + applicationsDn();
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
  eachEntryInRealm(function (stored) {
    if (found || !isUnder(stored.dn, applicationsDn())) {
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
//
// IT IS NOT ONLY AN APPLICATION'S SHAPE ANY MORE. `scim.js` reads people and
// groups through the same function, because "the entry, whole, canonically
// spelled, with the DN synthesised on it" is one question and the container it
// is asked about does not change the answer. That is why it is called
// entryObject() rather than applicationObject(): a second copy differing only in
// the container it was written for is the two-lists mistake this file already
// warns about three times.
// ---------------------------------------------------------------------------
function entryObject(stored) {
  log.debug('Entering entryObject().');
  const attributes = {};
  Object.keys(stored.attributes).sort().forEach(function (attribute) {
    attributes[canonicalName(attribute)] = stored.attributes[attribute].slice(0);
  });
  // Synthesised rather than stored, exactly as matchable() does it: the DN is
  // where the entry IS, so holding a copy of it on the entry would be a second
  // definition of the same fact and the one that goes stale on a rename.
  attributes[canonicalName('entrydn')] = [stored.dn];
  log.debug('Leaving entryObject().');
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
  return stored ? entryObject(stored) : null;
}

function applicationCount() {
  let n = 0;
  eachEntryInRealm(function (stored) {
    if (isUnder(stored.dn, applicationsDn()) && normalizeDn(stored.dn) !== normalizeDn(applicationsDn())) {
      n++;
    }
  });
  return n;
}

function allApplications() {
  log.debug('Entering allApplications().');
  const rows = [];
  eachEntryInRealm(function (stored) {
    if (isUnder(stored.dn, applicationsDn()) &&
        normalizeDn(stored.dn) !== normalizeDn(applicationsDn())) {
      rows.push(entryObject(stored));
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
  if (totalEntries() >= maxEntries() && !existing) {
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
  touchDirectory();
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
  containerDn: function () { return applicationsDn(); },
  maxApplications: maxApplications
});

// ---------------------------------------------------------------------------
// THE FEDERATION CONTAINER AS A STORE.
//
// The applications container's arrangement made again, and a deliberate copy
// rather than a coincidence for the reason stated above the SPIFFE ones: this
// file owns WHERE an entry lives, how it is created and what the cap is, and
// `federation/federation.js` owns what an entry IS. Neither knows the other's
// half, which is what lets an `ldapmodify`, the console and `/admin-api` be
// three doors onto one register rather than three registers.
//
// **THE DN IS THE ID, with no digest case.** An application entry may be named
// `cn=app-<12 hex>` because its identifier is whatever a protocol presented and
// can be any length; a relationship id is CONFIGURED, so `federation.js` simply
// requires it to be RDN-safe and short and refuses one that is not. That is the
// difference between a register that is written down and one that is observed,
// and it is why there is no `federationEntry()` walk equivalent to
// `applicationEntry()`'s — except that there is, for exactly one case: an entry
// somebody RENAMED with an ldapmodrdn. The identifier is still on it, so the
// walk finds it, and the alternative is a register that loses a relationship
// because somebody tidied a DN.
// ---------------------------------------------------------------------------
function federationDn(id) {
  return 'cn=' + escapeDnValue(String(id)) + ',' + federationsDn();
}

function federationEntry(id) {
  log.debug('Entering federationEntry(). id=' + id);
  const direct = getEntry(federationDn(id));
  if (direct) {
    log.debug('Leaving federationEntry(). Found at its DN.');
    return direct;
  }
  const wanted = String(id);
  let found = null;
  eachEntryInRealm(function (stored) {
    if (found || !isUnder(stored.dn, federationsDn())) {
      return;
    }
    if ((stored.attributes.fedid || [])[0] === wanted) {
      found = stored;
    }
  });
  log.debug('Leaving federationEntry(). ' + (found ? 'Found by fedId.' : 'Not here.'));
  return found;
}

function readFederation(id) {
  const stored = federationEntry(id);
  return stored ? entryObject(stored) : null;
}

function federationCount() {
  let n = 0;
  eachEntryInRealm(function (stored) {
    if (isUnder(stored.dn, federationsDn()) &&
        normalizeDn(stored.dn) !== normalizeDn(federationsDn())) {
      n++;
    }
  });
  return n;
}

function allFederations() {
  log.debug('Entering allFederations().');
  const rows = [];
  eachEntryInRealm(function (stored) {
    if (isUnder(stored.dn, federationsDn()) &&
        normalizeDn(stored.dn) !== normalizeDn(federationsDn())) {
      rows.push(entryObject(stored));
    }
  });
  log.debug('Leaving allFederations(). ' + rows.length + ' relationship(s).');
  return rows;
}

// Create or replace. REPLACE for `writeApplication()`'s reason, which applies
// with more force here: the record being written was read from this entry a
// moment ago and changed, so merging would make it impossible ever to REMOVE a
// value — and the value somebody most wants to be able to remove from one of
// these entries is a signing certificate that should no longer be trusted.
function writeFederation(id, attributes) {
  log.debug('Entering writeFederation(). id=' + id);
  const existing = federationEntry(id);
  const dn = existing ? existing.dn : federationDn(id);
  if (!existing && federationCount() >= maxFederations()) {
    log.warn('ldap: not creating ' + dn + '; ou=federations holds its maximum of ' +
             maxFederations() + ' entry/entries (federation.max).');
    log.debug('Leaving writeFederation(). The container is full.');
    return false;
  }
  if (totalEntries() >= maxEntries() && !existing) {
    log.warn('ldap: not creating ' + dn + '; the directory holds its maximum of ' +
             maxEntries() + ' entries.');
    log.debug('Leaving writeFederation(). The directory is full.');
    return false;
  }
  const created = existing ? existing.createdAt : generalizedTime();
  const stored = putEntry(dn, attributes, { origin: existing ? existing.origin : 'federation' });
  stored.createdAt = created;
  stored.attributes.createtimestamp = [created];
  stored.attributes.modifytimestamp = [generalizedTime()];
  auditFederationDirectory(existing ? 'entry.update' : 'entry.create', dn, attributes, !existing);
  log.debug('Leaving writeFederation(). The entry was ' +
            (existing ? 'updated.' : 'created.'));
  return true;
}

function deleteFederationEntry(id) {
  log.debug('Entering deleteFederationEntry(). id=' + id);
  const stored = federationEntry(id);
  if (!stored) {
    log.debug('Leaving deleteFederationEntry(). It was not here.');
    return false;
  }
  entries.delete(normalizeDn(stored.dn));
  touchDirectory();
  auditFederationDirectory('entry.delete', stored.dn, stored.attributes, false);
  log.debug('Leaving deleteFederationEntry(). ' + entries.size + ' entry/entries left.');
  return true;
}

// NO VALUES ARE NAMED, only attribute names — the rule every other LDAP row
// here follows, and it matters more on these entries than on any other in the
// directory: `fedClientSecret` is a real credential at a real foreign service,
// which is a stronger statement than anything oauthClientSecret can make.
function auditFederationDirectory(action, dn, attributes, created) {
  audit.audit({
    action: action,
    actor: '',
    protocol: 'LDAP',
    channel: 'internal',
    target: dn,
    summary: 'The federation relationship entry ' + dn + ' was ' +
             (action === 'entry.delete' ? 'deleted' : (created ? 'created' : 'updated')),
    detail: { attributes: Object.keys(attributes || {}).sort().join(', ') }
  });
}

federation.setDirectory({
  readFederation: readFederation,
  writeFederation: writeFederation,
  allFederations: allFederations,
  countFederations: federationCount,
  deleteFederation: deleteFederationEntry,
  containerDn: function () { return federationsDn(); },
  maxFederations: maxFederations
});

// AND THE TWO APPLICATIONS THAT ARE THIS PROCESS, immediately after — because
// this line is the earliest moment at which there is a container to write into,
// and the entries have to be there before anything can ask for them.
//
// It is here rather than in seed() above for a reason worth keeping: seed()
// builds the TREE, this module's half of the arrangement, while what these two
// entries hold is a pair of RFC 7591 registrations, which is that module's
// half. Writing them up there would mean this file knowing the application
// schema — the exact division the four functions above exist to avoid — and it
// could not run there anyway, since the slot they go through is filled on the
// line above this one. `applications.seedInternal` decides whether it happens
// at all, and is read over there.
applications.seedInternalApplications();

// ---------------------------------------------------------------------------
// THE SPIFFE CONTAINERS AS A STORE.
//
// The applications container's arrangement, made again for the two containers
// above — and it is a deliberate copy rather than a coincidence: this file owns
// WHERE an entry lives, how it is created and what the cap is, and
// `spiffe_registry.js` owns what an entry IS. Neither knows the other's half,
// which is what lets `ldapmodify`, the console and both gRPC surfaces be three
// doors onto one store rather than three stores.
//
// **The dependency is NOT inverted, and that is worth the sentence rule 3e
// asks for.** This file requires `spiffe_registry.js` directly and fills its
// slot; that module does not require this one. Neither of the two things that
// force a slot in the other direction applies here — there is no cycle (that
// module knows nothing about this one) and no route moves, because its slot is
// filled at THIS module's require time, by which point every /ldap route is
// already registered.
//
// **An entry is named by its ID, and an agent by a DIGEST of its SPIFFE ID.**
// A registration entry id is 32 hex characters, which is a perfectly good RDN.
// An agent's identity is a SPIFFE ID — long, and holding characters a DN would
// have to escape — so its entry is `cn=agent-<12 hex>` with the identifier
// whole on the entry as `spiffeAgentId`, which is `didPlan()`'s device and has
// the same consequence: ON THESE ENTRIES THE cn IS NOT THE IDENTITY.
// ---------------------------------------------------------------------------
function spiffeEntryDn(id) {
  return 'cn=' + escapeDnValue(String(id)) + ',' + spiffeEntriesDn();
}

function spiffeAgentDn(id) {
  return 'cn=' + escapeDnValue(spiffeRegistry.agentCnFor(id)) + ',' +
         spiffeAgentsDn();
}

// Find one by its own identifier rather than by its DN, because somebody may
// have renamed the entry — the same walk `applicationEntry()` does, affordable
// for the same reason (a few hundred entries in one process) and correct for
// the same reason (the identifier is on the entry; the DN is where it happens
// to live).
function spiffeStored(containerDn, attributeName, identifier) {
  log.debug('Entering spiffeStored(). identifier=' + identifier);
  const wanted = String(identifier);
  const key = String(attributeName).toLowerCase();
  let found = null;
  eachEntryInRealm(function (stored) {
    if (found || !isUnder(stored.dn, containerDn)) {
      return;
    }
    if (normalizeDn(stored.dn) === normalizeDn(containerDn)) {
      return;
    }
    if ((stored.attributes[key] || [])[0] === wanted) {
      found = stored;
    }
  });
  log.debug('Leaving spiffeStored(). ' + (found ? 'Found.' : 'Not here.'));
  return found;
}

function spiffeChildren(containerDn) {
  const rows = [];
  eachEntryInRealm(function (stored) {
    if (isUnder(stored.dn, containerDn) &&
        normalizeDn(stored.dn) !== normalizeDn(containerDn)) {
      rows.push(entryObject(stored));
    }
  });
  return rows;
}

function spiffeChildCount(containerDn) {
  let n = 0;
  eachEntryInRealm(function (stored) {
    if (isUnder(stored.dn, containerDn) &&
        normalizeDn(stored.dn) !== normalizeDn(containerDn)) {
      n++;
    }
  });
  return n;
}

// REPLACES rather than merges, exactly as writeApplication() does and for the
// identical reason: the record being written was read from this entry a moment
// ago, so merging would make it impossible ever to REMOVE a value — a DNS name
// deleted with ldapmodify would come back on the next write. The operational
// attributes are preserved, because createTimestamp belongs to the entry rather
// than to the record.
function spiffeWrite(containerDn, attributeName, identifier, attributes, originLabel) {
  log.debug('Entering spiffeWrite(). identifier=' + identifier);
  const existing = spiffeStored(containerDn, attributeName, identifier);
  const dn = existing ? existing.dn
    : (containerDn === spiffeEntriesDn() ? spiffeEntryDn(identifier)
                                         : spiffeAgentDn(identifier));
  if (!existing && totalEntries() >= maxEntries()) {
    // Warned rather than thrown, as a full directory always is here: whatever
    // the caller was doing succeeded, and a registry that could fail an SVID
    // request would be the tail wagging the dog.
    log.warn('ldap: not creating ' + dn + '; the directory holds its maximum ' +
             'of ' + maxEntries() + ' entries.');
    log.debug('Leaving spiffeWrite(). The directory is full.');
    return false;
  }
  const created = existing ? existing.createdAt : generalizedTime();
  const stored = putEntry(dn, attributes,
                          { origin: existing ? existing.origin : originLabel });
  stored.createdAt = created;
  stored.attributes.createtimestamp = [created];
  stored.attributes.modifytimestamp = [generalizedTime()];
  spiffeAuditDirectory(existing ? 'entry.update' : 'entry.create', dn,
                       attributes, !existing);
  log.debug('Leaving spiffeWrite(). The entry was ' +
            (existing ? 'updated.' : 'created.'));
  return true;
}

function spiffeDelete(containerDn, attributeName, identifier) {
  log.debug('Entering spiffeDelete(). identifier=' + identifier);
  const stored = spiffeStored(containerDn, attributeName, identifier);
  if (!stored) {
    log.debug('Leaving spiffeDelete(). It was not here.');
    return false;
  }
  entries.delete(normalizeDn(stored.dn));
  touchDirectory();
  spiffeAuditDirectory('entry.delete', stored.dn, stored.attributes, false);
  log.debug('Leaving spiffeDelete(). ' + entries.size + ' entry/entries left.');
  return true;
}

// The DIRECTORY's own row, which is a different fact from spiffe_registry.js's
// `spiffe.entry.create`: that one says a registration entry was created, this
// one says an entry in the tree changed. Both are recorded for the reason the
// applications container gives — /admin/audit's directory filter would
// otherwise show every entry this service writes except these.
//
// NO VALUES ARE NAMED, only attribute names, like every other LDAP row here.
function spiffeAuditDirectory(action, dn, attributes, created) {
  audit.audit({
    action: action,
    actor: '',
    protocol: 'LDAP',
    channel: 'internal',
    target: dn,
    summary: 'The SPIFFE entry ' + dn + ' was ' +
             (action === 'entry.delete' ? 'deleted' : (created ? 'created' : 'updated')),
    detail: { attributes: Object.keys(attributes || {}).sort().join(', ') }
  });
}

spiffeRegistry.setDirectory({
  readEntry: function (id) {
    const stored = spiffeStored(spiffeEntriesDn(), 'spiffeEntryId', id);
    return stored ? entryObject(stored) : null;
  },
  writeEntry: function (id, attributes) {
    return spiffeWrite(spiffeEntriesDn(), 'spiffeEntryId', id, attributes,
                       'spiffe-entry');
  },
  deleteEntry: function (id) {
    return spiffeDelete(spiffeEntriesDn(), 'spiffeEntryId', id);
  },
  allEntries: function () { return spiffeChildren(spiffeEntriesDn()); },
  countEntries: function () { return spiffeChildCount(spiffeEntriesDn()); },
  readAgent: function (id) {
    const stored = spiffeStored(spiffeAgentsDn(), 'spiffeAgentId', id);
    return stored ? entryObject(stored) : null;
  },
  writeAgent: function (id, attributes) {
    return spiffeWrite(spiffeAgentsDn(), 'spiffeAgentId', id, attributes,
                       'spiffe-agent');
  },
  deleteAgent: function (id) {
    return spiffeDelete(spiffeAgentsDn(), 'spiffeAgentId', id);
  },
  allAgents: function () { return spiffeChildren(spiffeAgentsDn()); },
  countAgents: function () { return spiffeChildCount(spiffeAgentsDn()); },
  // Where the containers are, for the pages that report it. Here rather than in
  // that module because that module deliberately does not know.
  entriesContainerDn: function () { return spiffeEntriesDn(); },
  agentsContainerDn: function () { return spiffeAgentsDn(); },
  containerDn: function () { return spiffeDn(); }
});

// ---------------------------------------------------------------------------
// THE PEOPLE AND THE GROUPS AS A STORE, WHICH IS WHAT `scim.js` PROVISIONS INTO.
//
// The same division the applications container above draws, made again for the
// two containers that were already here: `scim_map.js` owns the SCHEMA (which
// LDAP attribute each SCIM member is, in both directions) and this file owns the
// DIRECTORY (where the containers are, what counts as a person or a group, how
// an entry is created, what the cap is, and what an audit row says). Neither
// knows the other's half.
//
// **THE DEPENDENCY IS NOT INVERTED HERE, and that is worth a sentence because
// five other things in this file are.** `scim.js` requires this module directly
// and `server.js` requires it AFTER this one, so neither of the two things that
// force a slot applies: there is no cycle (this module knows nothing about SCIM)
// and no route moves (the /ldap routes are already registered by the time the
// /scim ones are). Rule 3e says a slot is what you reach for when a require
// would close a cycle or move a route, and to check a new proposal both ways
// round before adding one. This proposal fails that test both ways round, so it
// is a plain require.
//
// **THERE IS NO SECOND STORE AND NO CACHE**, exactly as the registry has none.
// A SCIM POST and an `ldapadd` write the same entry, a SCIM PATCH and an
// `ldapmodify` change it the same way, and a person provisioned over SCIM is
// visible on /admin/users, gets a directory entry swept for credential claims,
// and lands in whatever group a client puts them in. That is the whole point of
// building SCIM onto this directory rather than beside it — a provisioning
// client and an LDAP client pointed at this service are shown one truth.
//
// **A PERSON IS AN ENTRY UNDER ou=users AND A GROUP IS WHATEVER groupRuleFor()
// SAYS ONE IS.** Both rules are already written down in this file and neither is
// re-decided here: `populateVcAttributes()` uses the first and `groupsFor()`
// uses the second, and a third opinion in a SCIM module would be the second
// definition that eventually disagrees. The consequence is one a SCIM client
// will meet: a group a client `ldapadd`ed under ou=people with a groupOfNames
// objectClass IS a SCIM Group and is returned by GET /Groups, because it is one
// by this directory's rules and SCIM is a view of this directory.
// ---------------------------------------------------------------------------

// Is this entry a person? Under ou=users, the container itself excepted — the
// same test populateVcAttributes() applies, and for the same reason: this
// directory is schemaless, so what an entry IS cannot be read off an
// objectClass, and placement is the only rule that cannot be argued with.
function isPersonEntry(stored) {
  return isUnder(stored.dn, usersDn()) &&
         normalizeDn(stored.dn) !== normalizeDn(usersDn());
}

function personCount() {
  let n = 0;
  eachEntryInRealm(function (stored) {
    if (isPersonEntry(stored)) n++;
  });
  return n;
}

// Every person, as entry objects. Sorted by normalised DN so that the order a
// SCIM list response comes back in is stable across calls — scimmy sorts and
// pages on top of this, and a list whose underlying order changed between two
// pages would drop and repeat people with nothing looking wrong.
function allPersons() {
  log.debug('Entering allPersons().');
  const rows = [];
  eachEntryInRealm(function (stored) {
    if (isPersonEntry(stored)) {
      rows.push(stored);
    }
  });
  rows.sort(function (a, b) {
    return normalizeDn(a.dn) < normalizeDn(b.dn) ? -1 : 1;
  });
  const out = rows.map(entryObject);
  log.debug('Leaving allPersons(). ' + out.length + ' person(s).');
  return out;
}

// One person BY DN, which is what a SCIM id is. Null for a DN that names
// nothing AND for one that names something outside ou=users: a SCIM client
// asking for a User must not be handed an application entry because it guessed
// the right DN, and answering 404 for it is the same answer any other directory
// would give for a resource that is not of the type asked for.
function readPerson(dn) {
  log.debug('Entering readPerson(). dn=' + dn);
  const stored = getEntry(dn);
  if (!stored || !isPersonEntry(stored)) {
    log.debug('Leaving readPerson(). ' + (stored ? 'Not under ' + usersDn() + '.' : 'Nothing there.'));
    return null;
  }
  log.debug('Leaving readPerson(). Found ' + stored.dn + '.');
  return entryObject(stored);
}

// WHERE A NEW PERSON GOES IS NOT DECIDED HERE, and there used to be a
// personDnFor() on this line that decided it.
//
// It built `uid=<userName>,ou=users` directly, which is right until it is not:
// namePlan() FOLDS a new name onto an entry that is already this person's under
// a different naming attribute (a client certificate's `cn=rcbj,ou=users`, say),
// and a second rule that always built a `uid=` DN would have created
// `uid=rcbj` beside it — two objects for one person, which is the exact thing
// that fold exists to prevent. createUser() applies namePlan(), refuses a taken
// name through existingUserEntry() and refuses DN syntax through
// nameUsableInDn(), so scim.js calls THAT and takes the DN it returns. One
// definition of what creating a person means, at all three doors.

// Create or replace a person's entry. The caller has already merged whatever it
// means to keep (see scim_map.js's window rule), so this REPLACES, exactly as
// writeApplication() does and for the same reason: a merge here would make it
// impossible for a SCIM client ever to remove a value.
//
// Returns a result object rather than a boolean, because a SCIM client is owed a
// reason. `full` is the one refusal this can produce, and it is a refusal rather
// than a warning — unlike writeApplication(), where the application's own
// request had already succeeded and only the record was at stake, here the
// request IS the write.
function writePerson(dn, attributes) {
  log.debug('Entering writePerson(). dn=' + dn);
  const existing = getEntry(dn);
  if (existing && !isPersonEntry(existing)) {
    log.debug('Leaving writePerson(). ' + dn + ' is not under ' + usersDn() + '.');
    return { ok: false, reason: 'notAPerson', dn: dn };
  }
  if (!existing && totalEntries() >= maxEntries()) {
    log.warn('ldap: not creating ' + dn + '; the directory holds its maximum of ' +
             maxEntries() + ' entries (ldap.maxEntries).');
    log.debug('Leaving writePerson(). The directory is full.');
    return { ok: false, reason: 'full', dn: dn };
  }
  // The parent has to exist, which is the same structural rule the LDAP add
  // handler enforces. It always does here — seed() creates ou=users — but a
  // client can delete it, and an entry under a container that is gone is
  // unreachable by every search this service answers.
  if (!getEntry(parentDn(dn))) {
    log.debug('Leaving writePerson(). There is no ' + parentDn(dn) + '.');
    return { ok: false, reason: 'noParent', dn: dn, parent: parentDn(dn) };
  }
  const created = existing ? existing.createdAt : generalizedTime();
  const stored = putEntry(dn, attributes, { origin: existing ? existing.origin : 'scim' });
  stored.createdAt = created;
  stored.attributes.createtimestamp = [created];
  stored.attributes.modifytimestamp = [generalizedTime()];
  log.debug('Leaving writePerson(). The entry was ' + (existing ? 'updated.' : 'created.'));
  return { ok: true, created: !existing, dn: stored.dn, entry: entryObject(stored) };
}

// Delete a person's entry. It leaves that DN behind in every group that lists
// it, which is deliberate and is the same non-feature `GET /admin/ldap/service` documents:
// referential integrity is a directory feature and not a protocol rule, and a
// dangling member is exactly what /admin/groups exists to report. A SCIM client
// that means to remove somebody from their groups has to say so.
function deletePerson(dn) {
  log.debug('Entering deletePerson(). dn=' + dn);
  const stored = getEntry(dn);
  if (!stored || !isPersonEntry(stored)) {
    log.debug('Leaving deletePerson(). It was not a person here.');
    return { ok: false, reason: 'notFound', dn: dn };
  }
  if (hasChildren(stored.dn)) {
    log.debug('Leaving deletePerson(). It has children.');
    return { ok: false, reason: 'notLeaf', dn: stored.dn };
  }
  entries.delete(normalizeDn(stored.dn));
  touchDirectory();
  log.debug('Leaving deletePerson(). ' + entries.size + ' entry/entries left.');
  return { ok: true, dn: stored.dn, dangling: membershipsNaming(stored.dn) };
}

// Every group, as entry objects, by BOTH of groupRuleFor()'s rules. The rule
// each one matched comes back on it, because a SCIM client that finds a Group
// outside ou=groups deserves to be able to see why this service thinks it is
// one.
function allGroupEntries() {
  log.debug('Entering allGroupEntries().');
  const rows = [];
  eachEntryInRealm(function (stored) {
    if (groupRuleFor(stored)) {
      rows.push(stored);
    }
  });
  rows.sort(function (a, b) {
    return normalizeDn(a.dn) < normalizeDn(b.dn) ? -1 : 1;
  });
  const out = rows.map(function (stored) {
    const object = entryObject(stored);
    object.rule = groupRuleFor(stored);
    object.members = membersOf(stored);
    return object;
  });
  log.debug('Leaving allGroupEntries(). ' + out.length + ' group(s).');
  return out;
}

// THE THREE DOORS BELOW WERE A CROSS-REALM WRITE, and the record is worth
// keeping because the shape recurs. `/scim/v2` answers under every realm prefix
// and a SCIM id here IS a DN, so while one Map held every realm's entries the
// realm's endpoint could read, rewrite and — verified — DELETE a group in the
// default realm: `DELETE /realm/acme/scim/v2/Groups/cn=x,ou=groups,dc=example,dc=com`
// answered 204 and the group was gone. The person half never had the hole,
// because isPersonEntry() tests placement under the AMBIENT realm's usersDn();
// groupRuleFor() answers "this is a group" wherever it sits, on purpose, so
// nothing about a group's own definition could have caught it. Each door was
// guarded by hand first and the store split made the guard structural — these
// now read the realm's own store and could not reach another's if they tried.
function readGroupEntry(dn) {
  log.debug('Entering readGroupEntry(). dn=' + dn);
  const stored = getEntry(dn);
  if (!stored || !groupRuleFor(stored)) {
    log.debug('Leaving readGroupEntry(). ' +
              (stored ? 'It is an entry and not a group.' : 'Nothing there.'));
    return null;
  }
  const object = entryObject(stored);
  object.rule = groupRuleFor(stored);
  object.members = membersOf(stored);
  log.debug('Leaving readGroupEntry(). ' + object.members.length + ' member value(s).');
  return object;
}

// Where a new group goes: `cn=<displayName>,ou=groups`. Placement AND an
// objectClass — scim_map.js adds groupOfNames — so a group created over SCIM is
// one by both rules rather than by where it happens to sit, and stays one if a
// client moves it.
function groupDnFor(displayName) {
  return 'cn=' + escapeDnValue(String(displayName)) + ',' + groupsDn();
}

// `origin` says WHICH DOOR wrote it, and it is a parameter rather than the
// constant it used to be because there are now three: SCIM (the caller this
// function was written for), the admin console's RBAC screen, and the
// management API behind it. It shows in the `Came from` column on
// /admin/groups, which is the one place a reader can tell a group somebody
// PATCHed over SCIM from one the console created. It defaults to `scim`, so the
// call site that predates the parameter says exactly what it always meant.
function writeGroupEntry(dn, attributes, origin) {
  log.debug('Entering writeGroupEntry(). dn=' + dn + ', origin=' + (origin || 'scim'));
  // A DN in another realm is simply not here, and neither is its parent, so a
  // cross-realm PUT falls through to the parent check below and is answered
  // `noParent` — a write into a container this directory does not have, which
  // is exactly what it is from in here.
  const existing = getEntry(dn);
  if (existing && !groupRuleFor(existing)) {
    log.debug('Leaving writeGroupEntry(). ' + dn + ' is an entry and not a group.');
    return { ok: false, reason: 'notAGroup', dn: dn };
  }
  if (!existing && totalEntries() >= maxEntries()) {
    log.warn('ldap: not creating ' + dn + '; the directory holds its maximum of ' +
             maxEntries() + ' entries (ldap.maxEntries).');
    log.debug('Leaving writeGroupEntry(). The directory is full.');
    return { ok: false, reason: 'full', dn: dn };
  }
  if (!getEntry(parentDn(dn))) {
    log.debug('Leaving writeGroupEntry(). There is no ' + parentDn(dn) + ' in this realm.');
    return { ok: false, reason: 'noParent', dn: dn, parent: parentDn(dn) };
  }
  const created = existing ? existing.createdAt : generalizedTime();
  const stored = putEntry(dn, attributes,
                          { origin: existing ? existing.origin : (origin || 'scim') });
  stored.createdAt = created;
  stored.attributes.createtimestamp = [created];
  stored.attributes.modifytimestamp = [generalizedTime()];
  log.debug('Leaving writeGroupEntry(). The entry was ' + (existing ? 'updated.' : 'created.'));
  return { ok: true, created: !existing, dn: stored.dn, entry: readGroupEntry(stored.dn) };
}

function deleteGroupEntry(dn) {
  log.debug('Entering deleteGroupEntry(). dn=' + dn);
  const stored = getEntry(dn);
  if (!stored || !groupRuleFor(stored)) {
    log.debug('Leaving deleteGroupEntry(). It was not a group here.');
    return { ok: false, reason: 'notFound', dn: dn };
  }
  if (hasChildren(stored.dn)) {
    log.debug('Leaving deleteGroupEntry(). It has children.');
    return { ok: false, reason: 'notLeaf', dn: stored.dn };
  }
  entries.delete(normalizeDn(stored.dn));
  touchDirectory();
  log.debug('Leaving deleteGroupEntry(). ' + entries.size + ' entry/entries left.');
  return { ok: true, dn: stored.dn };
}

// ---------------------------------------------------------------------------
// GET /admin/ldap/spiffe — the SPIFFE containers, and their schema.
//
// The same page `/admin/ldap/applications` is, for the same reason: this
// directory is SCHEMALESS, so a container whose entries carry thirty invented
// attribute names needs somewhere to publish what they mean, or a client
// reading one back is guessing. It sits here rather than in
// `spiffe_registry.js` because it is a view of the CONTAINERS — where they
// are, how full they are — which is this file's half of the division.
//
// IT IS THE ONE OF THE FIVE WITH TWO LISTS ON IT, so it is also the one that
// needs `pagedRows()`'s `name` option: registration entries and attested
// agents page separately and share one `per`, exactly as the console's two
// drill-downs do. A single `page` would have meant clicking "next" under the
// agents silently advancing the entries above them.
// ---------------------------------------------------------------------------
function ldapSpiffeView(req) {
  log.debug('Entering ldapSpiffeView().');
  const entries_ = spiffeRegistry.allEntries();
  const agents = spiffeRegistry.allAgents();

  const wantedEntry = String(req.query.entryq || '').trim().toLowerCase();
  const wantedAgent = String(req.query.agentq || '').trim().toLowerCase();
  const matchedEntries = entries_.filter(function (row) {
    if (!wantedEntry) {
      return true;
    }
    return String(row.spiffeId).toLowerCase().indexOf(wantedEntry) >= 0 ||
           String(row.dn).toLowerCase().indexOf(wantedEntry) >= 0;
  });
  const matchedAgents = agents.filter(function (row) {
    if (!wantedAgent) {
      return true;
    }
    return String(row.id).toLowerCase().indexOf(wantedAgent) >= 0 ||
           String(row.dn).toLowerCase().indexOf(wantedAgent) >= 0;
  });

  const pagedEntries = directoryPaging(req, matchedEntries, 'entries', 'entries');
  const pagedAgents = directoryPaging(req, matchedAgents, 'agents', 'agents');
  const carried = { entryq: String(req.query.entryq || '').trim(),
                    agentq: String(req.query.agentq || '').trim(),
                    entriesPage: req.query.entriesPage || '',
                    agentsPage: req.query.agentsPage || '',
                    per: perOf(req, pagedEntries.paging) };
  const entriesNav = admin.pageNavPair('/admin/ldap/spiffe', carried,
                                       pagedEntries.paging);
  const agentsNav = admin.pageNavPair('/admin/ldap/spiffe', carried,
                                      pagedAgents.paging);

  const payload = {
    baseDn: baseDn(),
    container: spiffeDn(),
    entriesContainer: spiffeEntriesDn(),
    agentsContainer: spiffeAgentsDn(),
    entries: entries_.length,
    agents: agents.length,
    maxEntries: spiffeRegistry.maxEntries(),
    maxAgents: spiffeRegistry.maxAgents(),
    sourceOfTruth: 'These entries ARE the SPIFFE registry. An ldapmodify under ' +
      'ou=entries changes what the next SVID looks like — spiffeX509SvidTtl ' +
      'changes its lifetime, spiffeDnsName changes its subjectAltName, and ' +
      'spiffeId changes whose identity it is — because nothing caches them. ' +
      'The two containers hold different KINDS of thing: entries are ' +
      'CONFIGURATION and agents are a RECORD, which is why nothing about an ' +
      'agent is editable from the console.',
    editable: spiffeRegistry.EDITABLE,
    schema: spiffeRegistry.SCHEMA,
    filter: { entryq: carried.entryq || null, agentq: carried.agentq || null },
    entriesPaging: admin.pagingJson(pagedEntries.paging),
    agentsPaging: admin.pagingJson(pagedAgents.paging),
    // THE PAGE OF EACH LIST rather than the whole of it, which is the one way
    // this payload differs from what `/ldap/spiffe` answered with before
    // 2026-09-01. The paging members above say which page, and `entries` and
    // `agents` at the top are still the totals — a caller reading those is
    // unaffected.
    registrationEntries: pagedEntries.shown,
    attestedAgents: pagedAgents.shown
  };

  const classRows = spiffeRegistry.SCHEMA.objectClasses.map(function (one) {
    return '<tr><td><code>' + xmlEscape(one.name) + '</code></td><td>' +
      xmlEscape(one.where) + (one.standard ? '' : ' <strong>(invented here)</strong>') +
      '</td><td>' + xmlEscape(one.what) + '</td></tr>';
  }).join('');
  const attrRows = spiffeRegistry.SCHEMA.attributes.map(function (row) {
    return '<tr><td><code>' + xmlEscape(row.name) + '</code></td><td>' +
      xmlEscape(row.kind) + '</td><td>' +
      (row.editable ? 'yes' : 'no') + '</td><td>' + xmlEscape(row.from) +
      '</td><td>' + xmlEscape(row.what) + '</td></tr>';
  }).join('');
  const entryRows = pagedEntries.shown.map(function (row) {
    return '<tr><td>' + admin.clipped(row.spiffeId, 52) +
      '<div class="sub">' + admin.clipped(row.dn, 52) + '</div></td><td>' +
      admin.clipped(row.selectors.map(spiffeRegistry.selectorText).join(', ') ||
                    '(none — matches every workload)', 60) +
      '</td><td>' + xmlEscape(row.origin) + '</td><td class="num">' +
      row.svidsIssued + '</td></tr>';
  }).join('');
  const agentRows = pagedAgents.shown.map(function (row) {
    return '<tr><td>' + admin.clipped(row.id, 52) +
      '<div class="sub">' + admin.clipped(row.dn, 52) + '</div></td><td>' +
      xmlEscape(row.attestationType) + '</td><td>' +
      (row.banned ? '<span class="state-revoked">banned</span>'
                  : '<span class="state-valid">active</span>') +
      '</td><td class="num">' + row.attestations + '</td></tr>';
  }).join('');

  const inner = '<p class="sub">Registration entries live under <code>' +
    xmlEscape(spiffeEntriesDn()) + '</code> and attested agents under ' +
    '<code>' + xmlEscape(spiffeAgentsDn()) + '</code>. ' +
    '<a href="/spiffe">What SPIFFE is here</a> &middot; ' +
    '<a href="/admin/spiffe">the console page for it</a>.</p>' +
    '<div class="tiles">' +
    admin.tile(entries_.length, 'Registration entries') +
    admin.tile(spiffeRegistry.maxEntries(), 'Maximum entries') +
    admin.tile(agents.length, 'Attested agents') +
    admin.tile(spiffeRegistry.maxAgents(), 'Maximum agents') +
    '</div>' +
    admin.note(xmlEscape(payload.sourceOfTruth)) +
    '<form method="get" action="/admin/ldap/spiffe"><div class="formrow">' +
    '<input type="hidden" name="entryq" value="' + xmlEscape(carried.entryq) + '">' +
    '<input type="hidden" name="agentq" value="' + xmlEscape(carried.agentq) + '">' +
    '<label for="per">Rows per table</label>' +
    '<select id="per" name="per">' +
    admin.perPageOptions(pagedEntries.paging.perPage) + '</select>' +
    '<button class="secondary" type="submit">Apply</button>' +
    '</div></form>' +
    admin.note('Both tables below are paged separately and they share this ' +
    'size. Changing it starts each of them at its first page.') +
    '<h2>Registration entries</h2>' +
    '<form method="get" action="/admin/ldap/spiffe"><div class="formrow">' +
    '<input type="hidden" name="agentq" value="' + xmlEscape(carried.agentq) + '">' +
    '<input type="hidden" name="per" value="' + xmlEscape(carried.per) + '">' +
    '<label for="entryq">SPIFFE ID or DN</label>' +
    '<input type="text" id="entryq" name="entryq" size="30" value="' +
    xmlEscape(carried.entryq) + '" placeholder="spiffe://…, or part of a DN">' +
    '<button type="submit">Search</button>' +
    (carried.entryq ? ' <a href="/admin/ldap/spiffe">clear</a>' : '') +
    '</div></form>' +
    entriesNav.head +
    '<table><tr><th>SPIFFE ID / DN</th><th>Selectors</th><th>Origin</th>' +
    '<th class="num">SVIDs</th></tr>' +
    (entryRows || '<tr><td colspan="4">None.</td></tr>') + '</table>' +
    entriesNav.foot +
    '<h2>Attested agents</h2>' +
    '<form method="get" action="/admin/ldap/spiffe"><div class="formrow">' +
    '<input type="hidden" name="entryq" value="' + xmlEscape(carried.entryq) + '">' +
    '<input type="hidden" name="per" value="' + xmlEscape(carried.per) + '">' +
    '<label for="agentq">Agent or DN</label>' +
    '<input type="text" id="agentq" name="agentq" size="30" value="' +
    xmlEscape(carried.agentq) + '" placeholder="an agent SPIFFE ID, or part of a DN">' +
    '<button type="submit">Search</button>' +
    (carried.agentq ? ' <a href="/admin/ldap/spiffe">clear</a>' : '') +
    '</div></form>' +
    agentsNav.head +
    '<table><tr><th>Agent / DN</th><th>Attestor</th><th>State</th>' +
    '<th class="num">Attestations</th></tr>' +
    (agentRows ||
     '<tr><td colspan="4">None. Nothing has attested here.</td></tr>') +
    '</table>' +
    agentsNav.foot +
    '<h2>Object classes</h2><table><tr><th>Class</th><th>Where from</th>' +
    '<th>What</th></tr>' + classRows + '</table>' +
    '<h2>Attributes</h2>' +
    admin.note('Declared is what an entry may DO and is editable from the ' +
    'console; derived is what HAPPENED and is not. <code>ldapmodify</code> ' +
    'reaches everything either way &mdash; refusing it in the console is the ' +
    'difference between offering an operation and merely not preventing it.') +
    '<table><tr><th>Attribute</th><th>Values</th><th>Editable</th>' +
    '<th>Written by</th><th>What</th></tr>' + attrRows + '</table>' +
    '<p class="sub"><a href="/admin/ldap/spiffe?format=json">This page as ' +
    'JSON</a> &middot; <a href="/admin/spiffe/entries">the entries as the ' +
    'console edits them</a> &middot; <a href="/admin/ldap/directory">every ' +
    'entry in the directory</a> &middot; <a href="/admin/ldap/service">what ' +
    'this directory is</a></p>';

  log.debug('Leaving ldapSpiffeView(). ' + pagedEntries.shown.length +
            ' entry row(s), ' + pagedAgents.shown.length + ' agent row(s).');
  return { title: 'SPIFFE entries in the directory', inner: inner,
           json: payload };
}

app.get('/admin/ldap/spiffe', function (req, res) {
  log.debug('Entering GET /admin/ldap/spiffe.');
  const view = ldapSpiffeView(req);
  admin.respond(req, res, view.json, view.title, '/admin/ldap/spiffe',
                view.inner);
  log.debug('Leaving GET /admin/ldap/spiffe.');
});

// ---------------------------------------------------------------------------
// GET /admin/ldap/applications — the registry, and the schema that defines it.
//
// Two things on one page because they answer one question. The TABLE is what
// this service has been asked about; the SCHEMA below it is what an entry may
// carry and where each attribute comes from — published rather than left to be
// read out of the source, for the reason `/admin/ldap/service` publishes the
// bind policy: a directory whose shape you have to infer is one every client
// infers differently.
//
// It is a view of the store rather than a store of its own: every row is read
// through applications.js, which reads these very entries. The page cannot
// disagree with the directory because it has nothing to disagree with.
//
// AND IT IS NOT `/admin/applications`, which is the page next door and is not
// this one. That page is the registry as the CONSOLE works with it — one row
// per application, the counters, the six actions, the drill-down. This is the
// registry as the DIRECTORY holds it: the DN, every attribute with every
// value, and the vocabulary. The two are the same entries read for two
// different purposes and each links to the other.
// ---------------------------------------------------------------------------
function ldapApplicationsView(req) {
  log.debug('Entering ldapApplicationsView().');
  const all = applications.list();
  const wantedText = String(req.query.q || '').trim();
  const needle = wantedText.toLowerCase();
  const filtered = all.filter(function (row) {
    if (!needle) {
      return true;
    }
    if (String(row.identifier).toLowerCase().indexOf(needle) >= 0 ||
        String(row.name).toLowerCase().indexOf(needle) >= 0 ||
        String(row.dn || '').toLowerCase().indexOf(needle) >= 0) {
      return true;
    }
    // The ATTRIBUTES too, for the reason the directory dump searches values:
    // somebody looking for the entry that carries a particular redirect URI
    // has the URI and not the client_id.
    return Object.keys(row.attributes || {}).some(function (name) {
      const value = row.attributes[name];
      const values = Array.isArray(value) ? value : [value];
      return values.some(function (one) {
        return String(one).toLowerCase().indexOf(needle) >= 0;
      });
    });
  });
  const paged = directoryPaging(req, filtered, 'applications');
  const paging = paged.paging;
  const filterParams = { q: wantedText || '', per: perOf(req, paging) };
  const nav = admin.pageNavPair('/admin/ldap/applications', filterParams, paging);

  const payload = {
    baseDn: baseDn(),
    container: applicationsDn(),
    count: all.length,
    matched: filtered.length,
    shown: paged.shown.length,
    max: maxApplications(),
    filter: { q: wantedText || null },
    page: paging.page, pages: paging.pages, perPage: paging.perPage,
    firstRow: paging.firstRow, lastRow: paging.lastRow,
    sourceOfTruth: 'These entries ARE the registry. An ldapmodify here changes what the ' +
      'protocol endpoints do — adding a value to oauthRedirectUri adds a redirect URI ' +
      'that RFC 9700 mode will then accept by exact match.',
    kinds: applications.KINDS,
    schema: applications.SCHEMA,
    applications: paged.shown
  };

  const appRows = paged.shown.map(function (row) {
    // EVERY attribute, which now includes the operational ones and entryDN. A
    // search would withhold those unless they were asked for by name (RFC 4511
    // section 4.5.1.8); this is the service showing its own store, so it shows
    // them, and the column heading below says so.
    const attrs = Object.keys(row.attributes).sort().map(function (name) {
      return '<div><code>' + xmlEscape(name) + '</code>: ' +
        admin.clippedValues(row.attributes[name]) + '</div>';
    }).join('');
    // The DN on every row. This is the page headed "the registry as the
    // directory sees it", and the directory sees an entry by its DN — a row that
    // named only the identifier left the one address an ldapsearch needs to be
    // reconstructed by the reader from a naming rule published nowhere.
    return '<tr><td>' + admin.clipped(row.identifier, 40) +
      (row.dn ? '<div class="sub">' + admin.clipped(row.dn, 40) +
        (row.identifier === row.dnLabel ? '' :
          ' &mdash; the identifier is too long for a readable RDN, so the cn is a ' +
          'digest of it and <code>appIdentifier</code> is the identity') +
        '</div>' : '') +
      '</td><td>' + xmlEscape(row.name) + '</td><td>' +
      xmlEscape(row.kinds.join(', ') || '(unstated)') + '<div class="sub">' +
      xmlEscape(row.protocols.join(', ')) + '</div></td><td>' +
      (row.registered ? '<span class="state-valid">yes</span>'
                      : '<span class="state-none">no</span>') +
      '</td><td class="counts">' + row.authentications + ' auth<br>' +
      row.sessions + ' session(s)<br>' + row.users +
      ' user(s)</td><td class="attrs">' + attrs + '</td></tr>';
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

  const inner = '<p class="sub">' + all.length + ' of a maximum ' +
    maxApplications() + ' under <code>' + xmlEscape(applicationsDn()) +
    '</code>: every OAuth client, OpenID Connect relying party, SAML service ' +
    'provider, WS-Federation application, WS-Trust relying party, OpenID4VP ' +
    'verifier and Kerberos service this instance has been asked about. One ' +
    'entry per unique identifier, so an application that speaks two protocols ' +
    'under one name is one row with two kinds rather than two rows.</p>' +
    '<div class="tiles">' +
    admin.tile(all.length, 'Application entries') +
    admin.tile(filtered.length, 'Matching the filter') +
    admin.tile(maxApplications(), 'Maximum held') +
    '</div>' +
    admin.note('<strong>These entries are the registry, not a copy of ' +
    'one.</strong> An <code>ldapmodify</code> here changes what the protocol ' +
    'endpoints do: add a value to <code>oauthRedirectUri</code> and RFC 9700 ' +
    'mode accepts that redirect URI by exact match on the next authorization ' +
    'request. Nothing caches them. To EDIT one, ' +
    '<a href="/admin/applications">Applications</a> is the page with the ' +
    'controls on it; this one is the dump.') +
    '<form method="get" action="/admin/ldap/applications"><div class="formrow">' +
    '<label for="q">Anywhere in the entry</label>' +
    '<input type="text" id="q" name="q" value="' + xmlEscape(wantedText) +
    '" size="30" placeholder="an identifier, a name, a DN or any value">' +
    '<label for="per">Show</label>' +
    '<select id="per" name="per">' +
    admin.perPageOptions(paging.perPage) + '</select>' +
    '<button type="submit">Filter</button>' +
    (wantedText ? ' <a href="/admin/ldap/applications">clear</a>' : '') +
    '</div></form>' +
    nav.head +
    '<table><tr><th>Identifier</th><th>Name</th><th>Kind</th>' +
    '<th>Registered</th><th>Seen</th><th>Every attribute</th></tr>' +
    (appRows || '<tr><td colspan="6">' +
      (wantedText
        ? 'No application matches. The filter above may be hiding some.'
        : 'Nothing yet. An entry appears the first time a client_id, wtrealm, ' +
          'AppliesTo, entityID or service principal name is accepted.') +
      '</td></tr>') +
    '</table>' +
    nav.foot +
    '<h2>What an application can be</h2>' +
    '<table><tr><th>Kind</th><th>Label</th><th>What it means</th></tr>' +
    kindRows + '</table>' +
    '<h2>The object classes</h2>' +
    admin.note('node-ldapjs has no schema subsystem &mdash; it is protocol ' +
    'machinery, and it is a submodule this repository does not modify &mdash; ' +
    'and this directory is schemaless on purpose. So this is a VOCABULARY ' +
    'rather than a constraint: nothing rejects an entry for disobeying it. ' +
    'Where a registered class fits, it is used.') +
    '<table><tr><th>Class</th><th>Where from</th><th>What it brings</th></tr>' +
    classRows + '</table>' +
    '<h2>The attributes</h2>' +
    admin.note('<code>multi</code> accumulates a repeat, <code>single</code> ' +
    'is assigned &mdash; which is what stops a counter growing a value per ' +
    'sign-in. Two attributes hold CREDENTIALS in the clear, for the reason ' +
    '<code>/krb5/principals</code> prints the Kerberos passwords; they are ' +
    'never written to the audit log.') +
    '<table><tr><th>Attribute</th><th>Values</th><th>Set by</th>' +
    '<th>What it is</th></tr>' + attrRows + '</table>' +
    '<p class="sub"><a href="/admin/ldap/applications?format=json">This page ' +
    'as JSON</a> &middot; <a href="/admin/applications">the same registry ' +
    'with the controls on it</a> &middot; ' +
    '<a href="/admin/ldap/directory">every entry in the directory</a> ' +
    '&middot; <a href="/admin/ldap/service">what this directory is</a></p>';

  log.debug('Leaving ldapApplicationsView(). ' + paged.shown.length +
            ' row(s) of ' + filtered.length + ' matched.');
  return { title: 'Application entries', inner: inner, json: payload };
}

app.get('/admin/ldap/applications', function (req, res) {
  log.debug('Entering GET /admin/ldap/applications.');
  const view = ldapApplicationsView(req);
  admin.respond(req, res, view.json, view.title, '/admin/ldap/applications',
                view.inner);
  log.debug('Leaving GET /admin/ldap/applications.');
});

// ---------------------------------------------------------------------------
// GET /admin/ldap/federations — the register as the directory sees it.
//
// The applications page's twin, and a page of its own rather than a section of
// that one for the reason the container is a container of its own: half these
// entries are FOREIGN IDENTITY PROVIDERS, which ask this service for nothing.
//
// It says one thing that page does not have to: **an ldapmodify here is a
// SECURITY CHANGE.** Everywhere else in this directory an edit changes what
// this service will hand out; on `fedSigningCertificate` it changes whose
// assertions this service will believe, and on `fedEnabled` it turns a partner
// on. That sentence is the whole difference between this container and every
// other one, so it is at the top rather than in a footnote.
// ---------------------------------------------------------------------------
function ldapFederationsView(req) {
  log.debug('Entering ldapFederationsView().');
  const all = federation.list();
  const wantedText = String(req.query.q || '').trim();
  const needle = wantedText.toLowerCase();
  const filtered = all.filter(function (row) {
    if (!needle) {
      return true;
    }
    return String(row.fedId).toLowerCase().indexOf(needle) >= 0 ||
           String(row.dn).toLowerCase().indexOf(needle) >= 0 ||
           String(row.fedProtocol || '').toLowerCase().indexOf(needle) >= 0 ||
           String(row.fedRole || '').toLowerCase().indexOf(needle) >= 0;
  });
  const paged = directoryPaging(req, filtered, 'relationships');
  const paging = paged.paging;
  const filterParams = { q: wantedText || '', per: perOf(req, paging) };
  const nav = admin.pageNavPair('/admin/ldap/federations', filterParams, paging);

  const payload = {
    baseDn: baseDn(),
    container: federationsDn(),
    count: all.length,
    matched: filtered.length,
    shown: paged.shown.length,
    max: maxFederations(),
    filter: { q: wantedText || null },
    page: paging.page, pages: paging.pages, perPage: paging.perPage,
    firstRow: paging.firstRow, lastRow: paging.lastRow,
    sourceOfTruth: 'These entries ARE the register. An ldapmodify here is a SECURITY ' +
      'change: fedSigningCertificate decides whose assertions this service will ' +
      'believe, and fedEnabled turns a partner on. Nothing caches them.',
    roles: federation.ROLES,
    protocols: federation.PROTOCOLS,
    schema: federation.SCHEMA,
    relationships: paged.shown.map(function (row) {
      // The record MINUS the credential, and the entry beside it. The whole
      // entry's attributes are shown below in the table, secret included — this
      // is the page that says what the directory holds, and hiding a value here
      // while an ldapsearch shows it would be a page that lies about its own
      // subject. What is redacted is the JSON, which is what a script reads.
      const out = {};
      Object.keys(row).forEach(function (name) {
        if (name === 'entry') return;
        if (name === 'fedClientSecret') {
          out[name] = row[name] ? '(set — see the entry below)' : '';
          return;
        }
        out[name] = row[name];
      });
      out.ready = federation.readinessOf(row).ready;
      out.missing = federation.readinessOf(row).missing;
      return out;
    })
  };

  const relRows = paged.shown.map(function (row) {
    const attrs = Object.keys(row.entry.attributes).sort().map(function (name) {
      return '<div><code>' + xmlEscape(name) + '</code>: ' +
        admin.clippedValues(row.entry.attributes[name]) + '</div>';
    }).join('');
    const readiness = federation.readinessOf(row);
    return '<tr><td>' + admin.clipped(row.fedId, 40) +
      '<div class="sub">' + admin.clipped(row.dn, 40) + '</div></td>' +
      '<td>' + xmlEscape((federation.roleRow(row.fedRole) || {}).short || row.fedRole) +
      '<div class="sub">' +
      xmlEscape((federation.protocolRow(row.fedProtocol) || {}).label || row.fedProtocol) +
      '</div></td>' +
      '<td>' + (federation.isEnabled(row)
        ? (readiness.ready
            ? '<span class="state-valid">enabled and ready</span>'
            : '<span class="state-expired">ENABLED, not configured</span>' +
              '<div class="sub">' +
              xmlEscape(readiness.missing.join(', ')) + '</div>')
        : '<span class="state-none">disabled</span>') + '</td>' +
      '<td>' + xmlEscape(row.fedAuthentications || '0') + ' sign-in(s)<br>' +
      xmlEscape(row.fedUsers || '0') + ' person/people</td>' +
      '<td class="attrs">' + attrs + '</td></tr>';
  }).join('');
  const classRows = federation.SCHEMA.objectClasses.map(function (one) {
    return '<tr><td><code>' + xmlEscape(one.name) + '</code></td><td>' +
      xmlEscape(one.where) + (one.standard ? '' : ' <strong>(invented here)</strong>') +
      '</td><td>' + xmlEscape(one.what) + '</td></tr>';
  }).join('');
  const attrRows = federation.SCHEMA.attributes.map(function (row) {
    return '<tr><td><code>' + xmlEscape(row.name) + '</code>' +
      (row.sensitive ? ' <strong>(credential)</strong>' : '') +
      '</td><td>' + xmlEscape(row.kind) + '</td><td>' + xmlEscape(row.role) +
      '</td><td>' + xmlEscape(row.what) + '</td></tr>';
  }).join('');

  const inner = '<p class="sub">' + all.length + ' of a maximum ' +
    maxFederations() + ' under <code>' + xmlEscape(federationsDn()) +
    '</code>: the foreign identity providers this service consumes assertions ' +
    'from, and the foreign service providers it asserts to. One relationship ' +
    'is one DIRECTION, so a partner in both is two entries.</p>' +
    '<div class="tiles">' +
    admin.tile(all.length, 'Relationships') +
    admin.tile(all.filter(function (r) { return federation.isEnabled(r); }).length,
               'Enabled') +
    admin.tile(maxFederations(), 'Maximum held') +
    '</div>' +
    admin.warn('<strong>An ldapmodify here is a security change, which is not ' +
    'true of any other container in this directory.</strong> ' +
    '<code>fedSigningCertificate</code> decides whose assertions this service ' +
    'will believe; <code>fedEnabled</code> turns a partner on. Everywhere ' +
    'else here an edit changes what this service hands out, and every bind to ' +
    'this directory succeeds &mdash; so this container is exactly as ' +
    'protected as the rest of it, which is to say not at all. That is the ' +
    'honest state of a mock, and it is why federation is the one feature here ' +
    'that refuses by default.') +
    '<form method="get" action="/admin/ldap/federations"><div class="formrow">' +
    '<label for="q">Relationship</label>' +
    '<input type="text" id="q" name="q" value="' + xmlEscape(wantedText) +
    '" size="30" placeholder="an id, a DN, a protocol or a direction">' +
    '<label for="per">Show</label>' +
    '<select id="per" name="per">' +
    admin.perPageOptions(paging.perPage) + '</select>' +
    '<button type="submit">Filter</button>' +
    (wantedText ? ' <a href="/admin/ldap/federations">clear</a>' : '') +
    '</div></form>' +
    nav.head +
    '<table><tr><th>Relationship</th><th>Direction</th><th>State</th>' +
    '<th>Seen</th><th>Every attribute</th></tr>' +
    (relRows || '<tr><td colspan="5">' +
      (wantedText
        ? 'No relationship matches. The filter above may be hiding some.'
        : 'Nothing yet, and nothing will appear by itself: unlike every other ' +
          'container here, this one is CONFIGURED. Add a relationship on ' +
          '<a href="/admin/federation">/admin/federation</a> or through ' +
          '<code>POST /admin-api/federation/create</code>.') +
      '</td></tr>') +
    '</table>' +
    nav.foot +
    '<h2>The two directions</h2>' +
    '<table><tr><th>Role</th><th>What it means</th></tr>' +
    federation.ROLES.map(function (one) {
      return '<tr><td>' + xmlEscape(one.short) + '</td><td>' + xmlEscape(one.what) +
        '</td></tr>';
    }).join('') + '</table>' +
    '<h2>The five protocols</h2>' +
    '<table><tr><th>Protocol</th><th>What happens</th><th>Needs</th></tr>' +
    federation.PROTOCOLS.map(function (one) {
      return '<tr><td>' + xmlEscape(one.label) + '</td><td>' + xmlEscape(one.what) +
        '</td><td><code>' + xmlEscape(one.needs.join(', ')) + '</code></td></tr>';
    }).join('') + '</table>' +
    '<h2>The object classes</h2>' +
    '<table><tr><th>Class</th><th>Where from</th><th>What it brings</th></tr>' +
    classRows + '</table>' +
    '<h2>The attributes</h2>' +
    admin.note('<code>multi</code> accumulates a repeat, <code>single</code> ' +
    'is assigned. The <code>role</code> column says which direction an ' +
    'attribute is for; one belonging to the other direction is refused by the ' +
    'console and by the management API, and an <code>ldapmodify</code> can ' +
    'still write it, where it will be ignored. <code>fedClientSecret</code> ' +
    'is THIS SERVICE\'S OWN CREDENTIAL AT THE PARTNER &mdash; a real secret ' +
    'at a real foreign service, which is a stronger statement than anything ' +
    'else in this directory &mdash; and it is here in the clear for the ' +
    'reason <code>/krb5/principals</code> prints the Kerberos passwords. It ' +
    'is never written to the audit log and never shown in the console.') +
    '<table><tr><th>Attribute</th><th>Values</th><th>Direction</th>' +
    '<th>What it is</th></tr>' + attrRows + '</table>' +
    '<p class="sub"><a href="/admin/ldap/federations?format=json">This page ' +
    'as JSON</a> &middot; <a href="/admin/federation">configure them in the ' +
    'console</a> &middot; <a href="/federation">what federation is here</a> ' +
    '&middot; <a href="/admin/ldap/service">what this directory is</a></p>';

  log.debug('Leaving ldapFederationsView(). ' + paged.shown.length +
            ' row(s) of ' + filtered.length + ' matched.');
  return { title: 'Federation entries', inner: inner, json: payload };
}

app.get('/admin/ldap/federations', function (req, res) {
  log.debug('Entering GET /admin/ldap/federations.');
  const view = ldapFederationsView(req);
  admin.respond(req, res, view.json, view.title, '/admin/ldap/federations',
                view.inner);
  log.debug('Leaving GET /admin/ldap/federations.');
});

// ---------------------------------------------------------------------------
// THE NINTH SLOT ON admin.js, FILLED HERE.
//
// `mgmt-api/admin_api.js` mirrors every page of the console (rule 7) and sits
// two positions ABOVE this module in the require order, so it cannot require
// this file to reach these five views without dragging every route registered
// here ahead of its own. The slot is the way across; see the block above
// `setDirectoryPages()` in `admin.js` for the argument, and the guard below is
// the one every other install in this file uses — an older copy of `admin.js`
// (the parent project's) costs a warning rather than a crash at require time.
// ---------------------------------------------------------------------------
if (typeof admin.setDirectoryPages === 'function') {
  admin.setDirectoryPages({
    service: ldapServiceView,
    directory: ldapDirectoryView,
    applications: ldapApplicationsView,
    federations: ldapFederationsView,
    spiffe: ldapSpiffeView
  });
} else {
  log.warn('ldap: this copy of admin-ui/admin.js offers no ' +
           'setDirectoryPages() slot, so /admin-api will not mirror the five ' +
           'directory pages. The pages themselves are unaffected.');
}

function listen() {
  log.debug('Entering listen().');
  const whenPlain = new Promise(function (resolve, reject) {
    plainServer.listen(LDAP_PORT, '0.0.0.0', function () {
      const address = plainServer.address();
      boundPort = address ? address.port : LDAP_PORT;
      listening = true;
      listenError = '';
      // ROOT_DN: what this SOCKET serves. A realm's subtree is under it and
      // is reported per realm on GET /admin/ldap/service, which does have a realm.
      log.info('ldap: listening on TCP ' + boundPort + ' with base DN ' +
               ROOT_DN + '; ' + totalEntries() +
               ' entry/entries across ' + realms.count() + ' trust realm(s), ' +
               'each with a directory of its own; GET /admin/ldap/service describes it.');
      resolve({ port: boundPort, baseDn: ROOT_DN });
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
  // started. It is recorded, logged, and published on GET /admin/ldap/service — the same
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
               serverCertificate.fingerprint256 + '). It is ' +
               tlsServer.certificateProvenance() + ', so fetch it from ' +
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
  baseDn: baseDn,
  usersDn: usersDn,
  groupsDn: groupsDn,
  autocreateUsers: autocreateUsers,
  REFUSED_PASSWORD: REFUSED_PASSWORD,
  maxEntries: maxEntries,
  maxSearchResults: maxSearchResults,
  entries: entries,
  autoCreateUser: autoCreateUser,
  createUser: createUser,
  existingUserEntry: existingUserEntry,
  objectFor: objectFor,
  groupsFor: groupsFor,
  groupsOfUser: groupsOfUser,
  applicationsDn: applicationsDn,
  spiffeDn: spiffeDn,
  spiffeEntriesDn: spiffeEntriesDn,
  spiffeAgentsDn: spiffeAgentsDn,
  maxApplications: maxApplications,
  // The people and group containers as a store, for scim.js. A plain export
  // rather than a slot somebody fills, because that module is required AFTER
  // this one and knows about it: neither of the two things that force an
  // inversion applies. See the section above them for the whole argument.
  isPersonEntry: isPersonEntry,
  personCount: personCount,
  allPersons: allPersons,
  readPerson: readPerson,
  writePerson: writePerson,
  deletePerson: deletePerson,
  groupDnFor: groupDnFor,
  // The live connections, and the only sign-out LDAP has. Read by
  // ../logout/logout.js, which requires this module in the ordinary direction:
  // server.js loads it long before that one, so the require moves no route and
  // closes no cycle, and rule 3e's test therefore asks for no slot. See the
  // block above boundConnections().
  boundConnections: boundConnections,
  dropConnectionsFor: dropConnectionsFor,
  // The DN-syntax rule, shared with createUser() above so that the three doors
  // that create something named cannot disagree about what a name may be.
  nameUsableInDn: nameUsableInDn,
  // DN COMPARISON, exported for the same reason: scim.js has to ask whether two
  // DNs name the same entry, and a second implementation over there would
  // eventually disagree with this one about `cn=alice, ou=users` — which is a
  // difference only visible as a uniqueness check that stops firing.
  normalizeDn: normalizeDn,
  // WHAT A PERSON IS CALLED WHEN THEIR ENTRY HAS NO `uid`, and exported for the
  // third time for that same reason. Not every person entry has one:
  // certificatePlan() names a client certificate's entry `cn=<CN>,ou=users` and
  // writes no `uid` at all, and an `ldapadd` may create whatever it likes. This
  // is the rule existingUserEntry() matches a typed name against — the RDN
  // value, unescaped — so scim.js reporting a `userName` any other way would
  // mean SCIM naming somebody one thing while a create of that same name
  // collided with them under another.
  usernameOfEntry: usernameOfEntry,
  allGroupEntries: allGroupEntries,
  readGroupEntry: readGroupEntry,
  writeGroupEntry: writeGroupEntry,
  deleteGroupEntry: deleteGroupEntry,
  // The sweep, so that somebody provisioned over SCIM gets the same credential
  // claim attributes an authenticated person does. Exported rather than called
  // from inside writePerson(), because a batch of fifty creates should sweep
  // once and the caller is what knows the batch is over.
  populateVcAttributes: populateVcAttributes,
  // THIS REALM's entries, not the Map's. See realmEntryCount().
  entryCount: realmEntryCount
};
