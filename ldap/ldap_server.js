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
// the `file:node-ldapjs` entry in package.json. Two consequences follow and
// both have already been paid for once:
//
//   * `git clone` of this repository does not bring it. `git submodule update
//     --init --recursive` does, and the parent project's launchers pass
//     --recursive for exactly this reason. An uninitialised submodule is an
//     EMPTY DIRECTORY, so the failure is `Cannot find module 'ldapjs'` from
//     this file — which names a package rather than a submodule.
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
// that could not produce a 49 would make "the bind failed" untestable, and 49
// is the result code an LDAP client's error handling is built around.
//
// It is SCHEMALESS on purpose. No objectClass is enforced, no attribute is
// checked against a syntax, and `must`/`may` are not consulted — so a debugger
// can add an entry with whatever attributes it wants and see them come back. A
// real directory would refuse most of that, and where the difference matters (a
// missing objectClass, an unknown attribute type) it is a difference a reader
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
//   * a modify naming an attribute that is not there is LDAP_NO_SUCH_ATTRIBUTE
//     (16) for `delete` and `replace`-with-values-absent, and succeeds for
//     `add`.
//   * ONE ENTRY PER PERSON: an add under `ou=users` whose username is already
//     here is LDAP_ENTRY_ALREADY_EXISTS (68), naming the entry that holds it.
//     This one is not a protocol rule — LDAP has no notion of a username, and a
//     real directory gets this from a uniqueness constraint in its schema,
//     which is exactly the subsystem this mock does not have. It is enforced
//     because every OTHER door onto this container now folds onto one entry per
//     person (see existingUserEntry()), and a directory that let an `ldapadd`
//     undo that in one operation would be keeping the rule nowhere.
//
// And one that is NOT enforced, stated here rather than discovered: deleting a
// user does not remove it from the groups that list it as a `member`.
// Referential integrity is a feature of some directories and not of the
// protocol; OpenLDAP needs an overlay for it and Active Directory does it in
// the DSA. Leaving the dangling member is the honest default and is what a
// `member`-based group search will then show.
//
// ---------------------------------------------------------------------------
// AN LDAP OBJECT FOR EVERY USER WHO AUTHENTICATES.
//
// `LDAP_AUTOCREATE_USERS` (default ON) makes this directory grow a
// `uid=<name>,ou=users,<base>` entry the first time a person authenticates
// ANYWHERE in this service — the OAuth2 login screen, WS-Trust, WS-Federation,
// a Kerberos AS-REQ, a WebAuthn assertion. That is one hook and not twelve,
// because `admin_stats.recordAuthentication()` is already the single funnel
// every one of those call sites goes through at the moment the credential is
// ACCEPTED.
//
// The hook is INVERTED for the reason helpers.js's setJwtRecorder is: this
// module requires admin_stats.js (it needs the identity normalisation), so
// admin_stats.js cannot require this one back without a cycle, and a cycle in
// node hands back a half-initialised module whose exports are undefined. So
// admin_stats.js offers a slot and this file installs itself in it at require
// time.
//
// Two identities are skipped, and both are deliberate:
//
//   * an LDAP bind. The identity presented to a bind is a DN — it names an
//     object in this very directory — so creating `uid=cn=admin\,dc=example...`
//     from one would be nonsense. A bind is recorded in the admin console like
//     any other authentication; it just does not seed an entry.
//   * an OAuth CLIENT (client_credentials, client authentication at the token
//     endpoint). A client is not a person, and `ou=users` is for people. The
//     admin console makes the same distinction with its `isClient` flag, which
//     is what this reads.
//
// And ONE identity is not a name at all: a verified TLS CLIENT CERTIFICATE. Its
// subject is already a DN, so it does not become `uid=<name>` — see
// certificatePlan() for where it goes instead and what that costs. It arrives
// through the same observer as everything else, with the certificate's own
// facts riding along beside the identity.
//
// ONE ENTRY PER PERSON, HOWEVER MANY WAYS THEY GET IN. `rcbj` signing in at the
// login screen, `urn:uuid:<entryUUID>` in a token, `rcbj@STS.MOCK` in a
// Kerberos AS-REQ and `rcbj` on a WS-Security UsernameToken have always been
// one entry — identityOf() in admin_stats.js normalises all four to one key
// before this hook ever sees them. What did NOT fold was the identity that is a
// DN rather than a name, and now does: a certificate saying `CN=rcbj` lands on
// the entry rcbj already has, and a password sign-in after a handshake lands on
// the one the certificate made. existingUserEntry() is the whole of it, and the
// same function answers at the other two doors — an `ldapadd` under `ou=users`
// and createUser(), which the console and the management API share. A DID is
// the one identity that names nobody by itself and so cannot generally fold;
// where this service KNOWS whose it is, it does. See didPlan().
// ---------------------------------------------------------------------------

// For one thing only: the short, stable uid a DID-named entry is placed at.
// See didPlan().
const crypto = require('crypto');
const ldap = require('ldapjs');
const app = require('../common/app');
const { log, xmlEscape, dnRfc4514 } = require('../common/helpers');
// The subject resolver slot this module fills (2026-09-14). Named apart from
// the destructure above because it is a FILLING, not a use.
const helpers = require('../common/helpers');
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
// THE DIRECTORY CONNECTIONS OF OTHER NODES (2026-09-14, #46 section 4): the
// cluster table and the sign-out instruction. A LIBRARY that registers nothing
// and requires nothing of this file — the sockets reach it through hooks
// installed below boundConnections(). See ldap_cluster_connections.js.
const clusterConnections = require('./ldap_cluster_connections');
// ONE CREATE OF A NAME AT A TIME ACROSS NODES (2026-09-14, #46 section 3). A
// LIBRARY that registers nothing and requires nothing of this file; the names
// it claims are computed here by `createClaimSpec()`.
const createClaims = require('./directory_create_claims');
// The revocation register, for the CRL container below. A LEAF (rule 3): it
// registers no route, so requiring it here moves nothing.
const pkiRevocation = require('../common/pki_revocation');
const stats = require('../common/admin_stats');
// The application registry. This module is its STORE — see the applications
// section below — so the dependency runs both ways in the shape rule 6
// describes: a plain require here for the schema and the two conversions, and
// an inverted slot filled at the bottom of this file for the four functions
// that read and write the container.
const applications = require('../common/applications');
// THE inetOrgPerson CLASS DEFINITION (2026-09-11). A LIBRARY (rule 3) that
// requires only `common/helpers.js`, so it can neither move a route nor join a
// cycle. Two things come from it: the canonical spellings, merged into
// `learnName()` below so that a disagreement with the standard list is
// reported; and the list itself, handed to `/portal` across the slot this
// module fills, so that the account page a person reads and the directory they
// read it out of cannot come to disagree about what a person IS.
const inetOrgPerson = require('../common/inetorgperson');
// THE USER PORTAL, for the slot filled at the foot of this file. It is at 8b
// and this module is at 21, so by the time this line runs the require is a
// CACHE HIT and registers nothing — the same arrangement this module already
// has with `admin.js`, and the reason the slot is filled here rather than a
// require being added over there. See the install itself for rule 3e's test.
const portal = require('../portal/portal');
// THE PERSON-ASSERTION REGISTER (2026-09-11), for the slot filled at the foot
// of this file. A LIBRARY (rule 3) — it registers nothing, holds no store, and
// requires only `helpers.js` and `keystore.js`, so requiring it here can move
// no route and close no cycle. What it needs from this module is a read, a
// write and the list of people in the realm; see the install for rule 3e's
// test, which it passes both ways round.
const personAssertions = require('../common/person_assertions');
// The certificate-enrollment register (2026-09-13), whose store is the entry a
// certificate names; it is filled with a slot below.
const certEnrollment = require('../common/cert_enrollment');
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
// The XACML policy repository and the PIP. Both are LIBRARIES that own a
// schema and take their directory functions through a setDirectory() slot
// filled below at require time — the same arrangement federation.js,
// spiffe_registry.js and scim_map.js have, and for the same reason: a require
// in the other direction would drag every /ldap route into the router at
// whatever point those files were first loaded.
const xacmlStore = require('../xacml/xacml_store');
const xacmlPepRegistry = require('../xacml/xacml_pep_registry');
const xacmlPip = require('../xacml/xacml_pip');
// The audit log. A plain require and it cannot become anything else: audit.js
// requires helpers.js and config.js only, so it can be reached from the deepest
// module here without dragging a graph behind it.
//
// This is the module with the MOST recording sites in the service — one per
// LDAP operation, seven of them — and unlike the HTTP call log there is no
// single funnel to put them behind: ldapjs dispatches straight into the handler
// for each operation, and what an audit row has to say differs per operation (a
// modify names its changed attributes, a search names how many entries came
// back). What IS written once is the rule that decides whether an add is a
// user, a group or something else, and that lives in audit.directoryActionFor()
// rather than being spelled out at four of the seven.
const audit = require('../common/audit');
// Every refusal an LDAP handler answers, and every failure this module has on
// its own, carries an STS-LDAP-* code — see common/error_codes.js. A leaf.
const errorCodes = require('../common/error_codes');
// The PROXY protocol v2 reader (2026-09-14, #46), a LIBRARY: installed on the
// net.Server and tls.Server ldapjs built, in listen().
const proxyProtocol = require('../common/proxy_protocol');
// The admin console, for ONE reason: to hand it the reader below so that a
// user's page can show that user's directory entry. It is required here rather
// than the other way round because server.js requires ./admin BEFORE this
// module (rule 6), so admin.js must not require this one back — see the note
// above objectFor().
const admin = require('../admin-ui/admin');
// THE PAGING HELPERS MOVED ON 2026-09-12. `pagedRows()` and `pagingJson()`
// went to the read layer with the views that use them — they are pure
// arithmetic over a row count — and the eight /admin/ldap/* pages this
// module draws page with the same ones. This module is at 21 in the require
// order, well past the 18 that layer may first be loaded at, so this is a
// cache hit. See admin-core/CLAUDE.md.
// The paging helpers moved to the read layer on 2026-09-12 — `pagedRows()` and
// `pagingJson()` are pure arithmetic over a row count, and the eight
// /admin/ldap/* pages this module draws page with the same ones the views do.
// This module is at 21 and the layer may first be required at 18, so this is a
// cache hit. See admin-core/CLAUDE.md.
const adminViews = require('../admin-core/admin_views');
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
// plain require and not a third inversion, for the same reasons as
// tls_server.js above: vc_claims.js is a LIBRARY — it registers no route, so
// requiring it adds nothing to the express router and cannot reorder
// /admin/sts-metadata — and it requires only helpers.js, so there is no cycle
// to make. The traffic in the other direction, this module's two functions that
// IT calls, does go through a slot: see the setDirectory() install further
// down.
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
// The ROLE REGISTER. `ou=roles` is its store the way ou=policies is the policy
// repository's, and this file fills its directory slot below — a require in
// the other direction would drag every /ldap route to the front of the router.
const roles = require('../common/roles');
// The admin console's two roles, which are two groups in THIS directory.
// Required outright rather than through a slot in the other direction because
// it registers no route (rule 3), so nothing about the require order changes by
// naming it here; the slot below is what carries this module's functions the
// other way.
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
// The credential store's other half. A LEAF (rule 3) that registers no route
// and requires nothing here, so this require can neither move a route nor close
// a cycle; what crosses is the two functions the slot below installs.
const credentials = require('../common/credentials');
// THE PASSWORD POLICY REGISTER (2026-09-12). `ou=passwordPolicies` is its
// store the way `ou=roles` is the role register's, and for `roles.js`'s reason
// it is a LEAF — requiring `helpers.js`, `mode.js` and an npm package — so this
// require moves no route and closes no cycle; what crosses the other way is the
// three store functions its slot below installs.
const passwordPolicy = require('../common/password_policy');
const mode = require('../common/mode');
// THE RATE LIMITER THE SIGN-IN SCREEN AND THE PORTAL ALREADY USE, for failed
// binds (2026-09-12). A LIBRARY that requires only helpers, config, crypto,
// realms and error_codes, so the require closes no cycle and moves no route.
const websecurity = require('../common/websecurity');
// STORED KERBEROS KEYS (2026-09-12) — a directory person's, derived from their
// password, and a service principal's random ones. A LIBRARY (rule 3) that
// registers no route; the modules it requires are the principal database and
// the codec (loaded at 15), and `common/` leaves already loaded far above this
// line, so this require moves no route and closes no cycle. What crosses is the
// six directory functions its slot below installs — and it is THIS require
// that loads it in a process with no console, which is what fills the two
// slots it offers the credential store and the KDC.
const krb5PersonKeys = require('../kerberos/krb5_person_keys');

// The port. 389 is the assigned one and this process is root in the container,
// so it binds it directly; a host run is not root, which is why the variable
// exists. Changing it means the parent project's api has to allow the new port
// in `ldapAllowedPorts` or its LDAP client will refuse to reach it — the same
// coupling KRB5_KDC_PORT has with krb5AllowedPorts, and for the same reason.
const LDAP_PORT = config.value('ldap.port');

// The LDAPS port. 636 is the IANA-assigned one for LDAP over TLS and, like 389,
// it is privileged — so the container binds it and a host run usually cannot. A
// failure to bind is RECORDED and published on GET /admin/ldap/service exactly
// as the plain listener's is, and it is not fatal to the plain listener: the
// two sockets are started independently and either can be up while the other is
// not, which is the commonest outcome of a host run and is why they have
// separate state below rather than one `listening` flag that would have to lie
// about one.
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
// AsyncLocalStorage that `app.js`'s first middleware enters, and that
// middleware runs on an HTTP request. **LDAP has no HTTP request.** An
// `ldapsearch` arrives on 389 carrying a bind DN and a base DN and nothing else
// — no path, no header, nowhere to put a realm segment — so if the partition
// were a Map per realm, selected by an ambient value, an LDAP client could
// never reach any realm but the default one. Putting the realm IN THE DN is
// what makes `ldapsearch -b "dc=acme,dc=example,dc=com"` mean what it says, and
// it is the only shape that does. One Map keyed by DN also leaves
// `groupIndexNow()`, the root DSE and every containment check exactly as they
// were.
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
  log.debug("Entering realmBaseDn().");
  if (!id || id === realms.DEFAULT_ID) {
    log.debug("Leaving realmBaseDn().");
    return ROOT_DN;
  }
  log.debug("Leaving realmBaseDn().");
  return REALM_RDN_TYPE + '=' + id + ',' + ROOT_DN;
}


// ===========================================================================
// THE CRL CONTAINER, AND WHY THIS DIRECTORY PUBLISHES ONE (2026-09-11).
//
// Every certificate this service issues carries three CRL distribution points
// — `http(s)://`, `ldap://` and `ldaps://` — and the last two are addresses IN
// THIS DIRECTORY. An `ldap://` URI in a certificate that resolves to nothing
// is worse than no URI at all: a client configured to fetch CRLs over LDAP
// reports a revocation check it could not complete, which most stacks treat as
// a hard failure.
//
// **RFC 4523 SECTION 4 IS THE SHAPE.** A CRL lives in
// `certificateRevocationList;binary` on an entry of class
// `cRLDistributionPoint`, and the `;binary` transfer option is what says the
// value is DER rather than a string. The URI in the certificate names that
// attribute explicitly, which is what makes a fetch return the list rather
// than an empty attribute.
//
// **THE ENTRY IS A CACHE AND THE REGISTER IS THE TRUTH.** `pki_revocation.js`
// builds and signs a CRL on demand; this writes the result down so the socket
// can serve it. A stale entry is therefore possible — the CRL is republished
// on every revocation and on every start — and that is the honest trade for a
// protocol with no way to ask a directory to compute something.
// ===========================================================================
// The containers between a realm's base and one CRL entry, outermost first:
// `ou=crl` always, and `ou=service` or `ou=process` beneath it for the two
// starred scopes. Derived from the DN `pkiRevocation.crlDn()` answers rather
// than composed here, because a second composition is how the address in a
// certificate and the address of the entry came to name one entry for two
// authorities (2026-09-13 — see `crlDn()`).
function crlContainersFor(dn, base) {
  log.debug("Entering crlContainersFor().");
  const containers = [];
  let parent = dn.slice(dn.indexOf(',') + 1);
  while (parent && normalizeDn(parent) !== normalizeDn(base) &&
         parent.indexOf(',') > 0) {
    containers.unshift(parent);
    parent = parent.slice(parent.indexOf(',') + 1);
  }
  log.debug("Leaving crlContainersFor().");
  return containers;
}

// A PKI scope id as a REALM id. The two starred scopes — the service Root and
// the process branch — belong to no realm, so their CRLs live in the DEFAULT
// realm's subtree: it is the one every process has, and a client fetching the
// Root's CRL has no realm to be in.
function scopeIdToRealm(scopeId) {
  log.debug("Entering scopeIdToRealm().");
  const id = String(scopeId || '');
  if (id === '*service' || id === '*process') {
    log.debug("Leaving scopeIdToRealm().");
    return realms.DEFAULT_ID;
  }
  log.debug("Leaving scopeIdToRealm().");
  return id || realms.DEFAULT_ID;
}

// Write one authority's CRL into the directory. Called by
// `common/pki_revocation.js` through the slot it offers — see `setDirectory()`
// there for why it is an inverted hook rather than a require.
function publishCrl(scopeId, caId, der) {
  log.debug('Entering publishCrl(). scope=' + scopeId + ' ca=' + caId);
  if (!config.value('pki.publishCrlToDirectory')) {
    log.debug('Leaving publishCrl(). Switched off.');
    return false;
  }
  const base = realmBaseDn(scopeIdToRealm(scopeId));
  const dn = pkiRevocation.crlDn(scopeId, caId);
  // **IN THE REALM THE DN NAMES, AND UNTIL 2026-09-13 IT WAS IN WHICHEVER
  // REALM HAPPENED TO BE AMBIENT.** `putEntry()` writes the ambient realm's
  // store, and the two callers that publish every list — the startup pass and
  // the refresh timer — run in NO request, so every realm's lists landed in
  // the DEFAULT realm's store under a DN beginning `dc=<realm>`. The socket
  // answers a DN out of the store its realm names (`inRealmOf()`), so each of
  // those entries was unreachable and every `ldap://` distribution point in
  // every realm's certificates answered `noSuchObject`. It is the same
  // sentence every LDAP handler here already acts on: the DN decides the
  // store.
  log.debug('Leaving publishCrl(). Entering the realm of ' + dn + '.');
  return inRealmOf(dn, function () {
    return writeCrlEntry(scopeId, caId, der, base, dn);
  });
}

function writeCrlEntry(scopeId, caId, der, base, dn) {
  log.debug('Entering writeCrlEntry(). ' + dn);
  try {
    // The containers, made on demand. `putEntry()` is a SET, so writing one
    // again is harmless and there is no "does it exist" to get wrong.
    crlContainersFor(dn, base).forEach(function (container) {
      const ou = container.slice(0, container.indexOf(',')).replace(/^ou=/i,
                                                                     '');
      putEntry(container, {
        objectClass: ['top', 'organizationalUnit'],
        ou: [ou],
        description: [ou === 'crl'
          ? 'Certificate revocation lists published by this ' +
            'service\'s own certificate authorities (RFC 4523). ' +
            'Each entry carries a signed DER CRL in ' +
            'certificateRevocationList;binary, and the ldap:// ' +
            'distribution point in every certificate this service ' +
            'issues names one of them.'
          : 'The CRLs of the "' + ou + '" branch, which belongs to no ' +
            'realm and so lives beneath the default realm\'s ou=crl. A ' +
            'container of its own, because its authorities share ids ' +
            '(`intermediate`) with the default realm\'s own.']
      }, { origin: 'pki' });
    });
    putEntry(dn, {
      objectClass: ['top', 'cRLDistributionPoint'],
      cn: [String(caId)],
      // **THE ATTRIBUTE NAME CARRIES THE `;binary` OPTION**, because that is
      // what the URI in the certificate asks for and what RFC 4523 defines.
      // Writing it without the option produces an entry that answers an
      // `ldapsearch` for `certificateRevocationList` and NOT the one the
      // certificate names, which is a fetch that succeeds and returns nothing.
      'certificateRevocationList;binary': [der.toString('base64')],
      description: ['The CRL signed by the "' + String(caId) + '" ' +
                    'certificate authority of the ' +
                    '"' + String(scopeId || 'default') +
                    '" scope. Republished on every revocation, whenever ' +
                    'the authority\'s branch changes, and at half of ' +
                    'pki.crlLifetimeMinutes so the copy here is never past ' +
                    'its nextUpdate; the register in the keystore row is the ' +
                    'truth and this is a cache of what it currently signs.']
    }, { origin: 'pki' });
    log.debug('Leaving writeCrlEntry(). ' + dn + ', ' + der.length +
              ' bytes.');
    return true;
  } catch (e) {
    // Named and swallowed: a CRL that could not be written to the directory is
    // still served over HTTPS, and a directory write must not be able to fail
    // a revocation. The two LDAP distribution points are the ones that then
    // fetch nothing, which is what this message is for.
    log.error(errorCodes.tag('STS-LDAP-0031') +
              'ldap: the "' + caId + '" CRL could not be published at ' + dn +
              ': ' + e.message + '. It is still served over HTTP — the ' +
              'ldap:// distribution point in certificates this ' +
              'authority signed will fetch nothing.');
    log.debug('Leaving writeCrlEntry(). It threw.');
    return false;
  }
}

// The base DN of whatever realm is ambient. THE function every DN below is
// built from — the same shape `helpers.baseUrlOf()` has for URLs, and for the
// same reason: one place that knows about realms, and a hundred call sites that
// do not.
function baseDn() {
  log.debug("Entering baseDn().");
  log.debug("Leaving baseDn().");
  return realmBaseDn(realms.currentId());
}

// Where auto-created people and hand-made groups live. Derived rather than
// configured: two values that could disagree with the base would produce
// entries in a tree nobody is searching.
function usersDn() {
  log.debug("Entering usersDn().");
  log.debug("Leaving usersDn().");
  return 'ou=users,' + baseDn();
}

function groupsDn() {
  log.debug("Entering groupsDn().");
  log.debug("Leaving groupsDn().");
  return 'ou=groups,' + baseDn();
}

// The third container, and the one whose entries are a REGISTRY rather than a
// description of one. See the applications section further down.
function applicationsDn() {
  log.debug("Entering applicationsDn().");
  log.debug("Leaving applicationsDn().");
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
  log.debug("Entering federationsDn().");
  log.debug("Leaving federationsDn().");
  return 'ou=federations,' + baseDn();
}

// ou=policies IS the XACML policy repository — not a copy of one kept
// elsewhere. `xacml/xacml_store.js` argues why the store is the directory
// rather than a table of its own, and owns the schema for what an entry here
// carries.
function policiesDn() {
  log.debug("Entering policiesDn().");
  log.debug("Leaving policiesDn().");
  return 'ou=policies,' + baseDn();
}

// ou=roles IS the role register. A container of its own rather than a corner of
// ou=groups, and the difference is not filing: a GROUP is a set of PEOPLE, and
// a role is a name that a person, a group OR AN APPLICATION may hold. The third
// one is what makes them different kinds of thing — `client_credentials` has no
// person in it, and an application holding a role is the only way there is
// anything to decide about that grant. Folding roles into ou=groups would mean
// every reader of ou=groups had to filter out the entries that are not sets of
// people. `common/roles.js` holds the schema; /admin/roles publishes it.
function rolesDn() {
  log.debug("Entering rolesDn().");
  log.debug("Leaving rolesDn().");
  return 'ou=roles,' + baseDn();
}

// ou=peps is the register of REMOTE Policy Enforcement Points — the processes
// that pull this repository and enforce it somewhere else. A container of its
// own rather than a corner of ou=policies, and the reason is the one that
// decides every container split here: a policy is a RULE and a PEP is a
// PARTY, and the question "which policies do I have" and the question "who is
// enforcing them" are different questions that a single container could only
// answer by making every reader filter. `xacml/xacml_pep_registry.js` owns the
// schema.
function pepsDn() {
  log.debug("Entering pepsDn().");
  log.debug("Leaving pepsDn().");
  return 'ou=peps,' + baseDn();
}

// ou=trustAnchors is the DURABLE half of the client-certificate truststore
// (2026-09-12) — one entry per anchor somebody added at runtime, through
// /admin/tls/trust, POST /admin-api/tls/trust/add or (in development)
// POST /tls/trust. It is in the DEFAULT realm's tree and only there, because
// the truststore is one array for every listener in the process: a container
// per realm would be a per-realm truststore this service does not have.
//
// **WHY THE DIRECTORY AND NOT A STORE OF ITS OWN.** An anchor is configuration
// somebody TYPED, and the directory is the one thing this service persists in
// every store mode (`ldif` and `postgres`) and replicates between processes
// through the change log — so an anchor added in one front process survives a
// restart and reaches every other front process with no mechanism written for
// it. The keystore's row family was the alternative and it is product-only and
// never adopted across processes; an appconfig override was the other, and a
// bundle of PEM blocks is not a setting. `tls/tls_server.js` owns what an
// anchor IS; this container is only where one is written down. Anchors read
// from `tls.trustAnchorsFile` are NOT written here: they come back from the
// file.
function trustAnchorsDn() {
  log.debug("Entering trustAnchorsDn().");
  log.debug("Leaving trustAnchorsDn().");
  return 'ou=trustAnchors,' + baseDn();
}

function trustAnchorDn(fingerprint) {
  log.debug("Entering trustAnchorDn().");
  log.debug("Leaving trustAnchorDn().");
  return 'cn=' + escapeDnValue(String(fingerprint)) + ',' + trustAnchorsDn();
}

// ou=passwordPolicies is the PASSWORD POLICY register (2026-09-12). A container
// of its own rather than a corner of ou=policies, for the rule that decides
// every split here: ou=policies holds XACML documents a PDP evaluates, and a
// password policy is a profile of numbers `credentials.setPassword()` checks —
// two kinds of entry sharing one word, which is the reason not to share one
// container. The name is `ou=policies` in OpenLDAP's own ppolicy examples and
// could not be here. `common/password_policy.js` owns the schema.
function passwordPoliciesDn() {
  log.debug("Entering passwordPoliciesDn().");
  log.debug("Leaving passwordPoliciesDn().");
  return 'ou=passwordPolicies,' + baseDn();
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
  log.debug("Entering spiffeDn().");
  log.debug("Leaving spiffeDn().");
  return 'ou=spiffe,' + baseDn();
}

function spiffeEntriesDn() {
  log.debug("Entering spiffeEntriesDn().");
  log.debug("Leaving spiffeEntriesDn().");
  return 'ou=entries,' + spiffeDn();
}

function spiffeAgentsDn() {
  log.debug("Entering spiffeAgentsDn().");
  log.debug("Leaving spiffeAgentsDn().");
  return 'ou=agents,' + spiffeDn();
}

// Only an explicit "0" or "false" turns the auto-creation off, so a missing or
// misspelled variable leaves it ON — the safe direction here, because the
// feature is what makes the directory non-empty for somebody who has just
// signed in and gone looking for themselves.
// **PRODUCT MODE IS A CEILING ON THIS SETTING AND NOT A SECOND OPINION ABOUT
// IT** (2026-09-06). `ldap.autocreateUsers` says whether an operator wants
// entries seeded from authentications; `mode.autoCreates()` says whether this
// service invents objects at all. Product mode refuses regardless of the
// setting, and the setting can still turn seeding off in development — which is
// the right shape for a policy that a mode tightens: the AND cannot be
// loosened by editing configuration.
function autocreateUsers() {
  log.debug("Entering autocreateUsers().");
  log.debug("Leaving autocreateUsers().");
  return mode.autoCreates() && config.value('ldap.autocreateUsers');
}

// The password that is refused. See the header: this is the service's standing
// convention rather than an authentication policy.
//
// **REFUSED IN BOTH MODES, DELIBERATELY, AND NOT A HARD-CODED BACKDOOR TO
// REMOVE.** `common/credentials.js` refuses the same literal
// (`RESERVED_REFUSAL`) before it looks at any store, at every door that takes a
// password. In development it is what makes result code 49 reachable at all,
// since nothing else is checked. In product mode it changes nothing an attacker
// can use: it can only turn a bind that would have been verified into a
// REFUSAL, never a refusal into a success — so the one effect is that nobody
// can hold "invalid" as a real password, which is a password nobody should
// hold. Keeping it in both modes means a negative test means the same thing
// against either.
const REFUSED_PASSWORD = 'invalid';

// The characters RFC 4514 reserves in a DN value. See nameUsableInDn() for why
// there is one copy; it is up here only so that it exists when seed() runs.
const DN_RESERVED = /[,=+<>#;"\\]/;

// A ceiling on how large this directory may grow. It is in memory and it grows
// on its own (every authentication can add an entry), so an unbounded one is a
// memory leak with a protocol in front of it. When it is reached, new entries
// are refused with LDAP_ADMIN_LIMIT_EXCEEDED rather than silently dropped.
function maxEntries() {
  log.debug("Entering maxEntries().");
  log.debug("Leaving maxEntries().");
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
  log.debug("Entering maxApplications().");
  log.debug("Leaving maxApplications().");
  return config.value('applications.max');
}

// How many entries may live under ou=federations. The same directory-limit rule
// applications.max follows — it REFUSES rather than evicting — and it matters
// more here than there: an evicted application entry is a record that has been
// lost, and an evicted federation relationship is a partner that silently
// stopped being trusted.
function maxFederations() {
  log.debug("Entering maxFederations().");
  log.debug("Leaving maxFederations().");
  return config.value('federation.max');
}

function maxPolicies() {
  log.debug("Entering maxPolicies().");
  log.debug("Leaving maxPolicies().");
  return config.value('xacml.maxPolicies');
}

function maxRoles() {
  log.debug("Entering maxRoles().");
  log.debug("Leaving maxRoles().");
  return config.value('roles.maxRoles');
}

function maxPeps() {
  log.debug("Entering maxPeps().");
  log.debug("Leaving maxPeps().");
  return config.value('xacml.maxPeps');
}

function maxSearchResults() {
  log.debug("Entering maxSearchResults().");
  log.debug("Leaving maxSearchResults().");
  return config.value('ldap.sizeLimit');
}

// Whether the socket is up, and on which port. Declared HERE, beside the other
// module state, rather than beside listen() where it is written: the HTTP views
// read it, they are registered above listen(), and a `let` further down the
// file is in the temporal dead zone until module evaluation reaches it. Nothing
// calls those views during evaluation, so it works either way — but a reader
// should not have to establish that. `boundPort` starts at the configured value
// so the page is not wrong before listen() has run; it is replaced with the
// port that was actually bound, which differs when LDAP_PORT is 0.
let listening = false;
let listenError = '';
let boundPort = LDAP_PORT;
// The LDAPS listener's own three. Separate rather than a flag on the ones
// above, for the reason LDAPS_PORT gives: "389 is up and 636 is not" is a state
// a host run reaches almost every time, and a single pair could only report one
// of them.
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
// net.Server. Attribute names are stored in lower case because that is what
// arrives — @ldapjs/attribute lower-cases a type on the way in, so an entry
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
  log.debug("Entering totalEntries().");
  let n = 0;
  realms.list().forEach(function (realm) {
    n += entries.realmMap(realm.id).size;
  });
  log.debug("Leaving totalEntries().");
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
  log.debug("Entering realmFor().");
  let best = realms.DEFAULT_REALM;
  let bestLength = ROOT_DN.length;
  if (!realms.active()) {
    log.debug("Leaving realmFor().");
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
  log.debug("Leaving realmFor().");
  return best;
}

// Run `fn` in the realm the DN names, which is what every LDAP handler does
// with the DN it was given. One function so that "which store does this
// operation touch" has one answer and one place to read it.
function inRealmOf(dn, fn) {
  log.debug("Entering inRealmOf().");
  log.debug("Leaving inRealmOf().");
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

// ---------------------------------------------------------------------------
// A NUL BYTE IN A DIRECTORY VALUE, WHICH IS THE ONE THING THIS SOCKET REFUSES
// ABOUT WHAT A VALUE CONTAINS (2026-09-06).
//
// **THIS SERVICE ACCEPTS ANY BIND, ANY DN AND ANY ATTRIBUTE, AND THAT DOES NOT
// CHANGE.** The directory is schemaless on purpose and its permissiveness is
// the product. What is refused here is one byte, and the argument is that a NUL
// is not an odd value somebody might legitimately be testing with — it is
// malformed under every LDAP string syntax there is, and it is uniquely
// dangerous downstream in a way the other control characters are not.
//
// Measured before it was refused: an `ldapadd` carrying
// `before\u0000after\r\nInjected: yes` was ACCEPTED, stored, and read back
// byte for byte.
//
// The CR and LF in that value are fine and stay fine — every sink this service
// has for a directory value already escapes them. `esc()` handles the console
// pages, bunyan JSON-encodes a log line, the XML escaper handles a SAML
// AttributeValue, `JSON.stringify` handles a token claim, and RFC 2849 base64s
// an LDIF value that needs it. **The NUL is the one that is not merely
// escaped-or-not**: half the libraries under this service are C underneath and
// stop reading at it while node does not, so the value one layer believes it
// has and the value the next layer acts on are different strings.
//
// This repository has already lost an afternoon to exactly that, one layer up:
// a single stray NUL in a source file makes it invisible to `grep` while `sed`,
// `node` and the tests all still see it.
//
// `InvalidAttributeSyntaxError` is RFC 4511's own answer (resultCode 21) and is
// what a client can act on; the alternative was to strip the byte, which would
// be this service quietly storing something other than what was sent.
// ---------------------------------------------------------------------------
// The code for the condition, carried on the ldapjs error — or on the
// `{ ok: false }` result a library function hands its caller — under the
// non-enumerable Symbol errorCodes.mark() uses, so whoever sends the refusal
// records it (ldapRefusal() here; `errorCodes.codeOf(result)` in SCIM and the
// console). Nothing ldapjs encodes and no JSON serialisation reads a Symbol, so
// what a client receives is unchanged.
function coded(code, err) {
  log.debug("Entering coded().");
  log.debug("Leaving coded().");
  return errorCodes.mark(err, code);
}

function refuseNulValues(type, values) {
  log.debug('Entering refuseNulValues(). type=' + type);
  for (let i = 0; i < values.length; i++) {
    const value = values[i];
    if (typeof value === 'string' && value.indexOf('\u0000') >= 0) {
      log.warn('ldap: refused a value for "' + type + '" carrying a NUL byte.');
      log.debug('Leaving refuseNulValues(). Refused.');
      return coded('STS-LDAP-0008', new ldap.InvalidAttributeSyntaxError(
        'The value for "' + type + '" contains a NUL byte. It is malformed ' +
        'under every LDAP string syntax, and a value that half this stack ' +
        'reads as shorter than the other half is worse than no value at all.'));
    }
  }
  log.debug('Leaving refuseNulValues(). ' + values.length + ' value(s) are ' +
      'clean.');
  return null;
}

function touchDirectory(dn) {
  log.debug("Entering touchDirectory().");
  directoryVersion++;
  // WHERE IT LANDED, when the caller said so. See subtreeClocks() below: a
  // caller that names the DN it wrote lets a listing of some OTHER container
  // survive this write, and a caller that says nothing invalidates every
  // listing. **Never make this argument required** — about thirty callers here
  // are held to touchDirectory() by prose rather than by the compiler, and the
  // safe answer has to stay the one they get for free.
  if (dn === undefined || dn === null || dn === '') {
    noteWriteAnywhere();
  } else {
    noteWriteUnder(dn);
  }
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
  // AND WHERE, when the caller said. `persistence.js` keeps a journal of the
  // DNs that moved and diffs only those; a change with no DN makes it diff
  // everything, which is what it always did. Same safe-by-default shape as the
  // subtree clocks above, and the same argument: about thirty callers reach
  // this function and only the hot ones name a DN.
  // **NORMALISED, because that is the key the store is written under.**
  // `entries` is keyed by `normalizeDn(dn)` and `realmEntries()` hands
  // persistence those keys, so a journal holding the RAW dn would match
  // nothing: the flush would find no live entry under it, emit no upsert, and
  // the write would be lost with nothing failing. The raw form is what
  // `touchDirectory()` is called with everywhere, so it is converted here —
  // once, in the module that owns the key form — rather than trusted to
  // thirty callers.
  persistence.directoryChanged(dn ? normalizeDn(dn) : undefined);
  log.debug("Leaving touchDirectory().");
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
  log.debug("Entering eachEntryInRealm().");
  entries.forEach(fn);
  log.debug("Leaving eachEntryInRealm().");
}

// ---------------------------------------------------------------------------
// THE USERNAME INDEX, AND WHY IT IS INCREMENTAL WHERE THE GROUP INDEX IS NOT.
//
// `existingUserEntry()` is where the one-entry-per-person rule is enforced:
// every door that creates somebody asks it first, and a hit is a refusal. Its
// fast path is a lookup at `uid=<name>,ou=users` and answers a RETURNING person
// in one Map hit — but it MISSES BY DEFINITION for somebody who is not there
// yet, which is exactly what a create is. So every create fell through to a
// walk of the whole realm, and five thousand creates walked a store that was
// five thousand entries long by the end of it.
//
// **THE 2026-09-06 BULK-LOAD BASELINE MEASURED THAT WITHOUT NAMING IT**: 9ms at
// the 500th person and 54ms at the 5,000th, through all three doors, on a
// service doing no more work per person. A create is not supposed to be a
// function of directory size and it was one.
//
// So the fall-through is a Map lookup now. The index holds every name an entry
// under `ou=users` answers to — its `uid` values AND its RDN value, which is
// the pair the walk compared — against that entry's key in the store.
//
// **IT IS MAINTAINED INCREMENTALLY, WHICH `groupIndexNow()` DELIBERATELY IS
// NOT, and the difference is the shape of the load rather than a change of
// mind.** A group index is read once per token and written rarely, so
// rebuilding it on the first read after any write costs nothing. A username
// index is read and written by the SAME operation — a create asks it, is told
// no, and then adds to it — so a rebuild-on-write cache would rebuild once per
// create and leave the quadratic exactly where it was.
//
// **AND A STALE ANSWER IS STILL IMPOSSIBLE, BY THE MECHANISM THAT WAS ALREADY
// THERE.** The cache carries the `directoryVersion` it is current for, and
// `touchDirectory()` — which every writer in this service is required to call,
// argued at length beside it — bumps that version. ONLY putEntry() updates the
// index in step, and only for a DN that held nothing; every other writer, and
// every overwrite, simply leaves the version behind and the next read rebuilds.
// So a writer nobody hooked costs a rebuild and can never cost a wrong answer,
// which is what makes hooking one site rather than fifteen the safe choice
// rather than the lazy one.
//
// The `usersDn()` it was built against is kept and compared as well, which the
// group index does not do. That container moves when `ldap.baseDn` changes and
// a settings change bumps no directory version at all — so without it, changing
// the base would leave an index describing a container nothing is in any more.
// ---------------------------------------------------------------------------
const usernameIndexes = realms.keyed(function () {
  return { index: null, version: -1, usersDn: '', builds: 0 };
});

// Every name this entry answers to, lower-cased and without repeats: its `uid`
// values and the value of its own RDN.
//
// **NO `Entering`/`Leaving` PAIR, deliberately**: this is called once per entry
// inside buildUsernameIndex()'s walk, so at `debug` the pair would be two lines
// per entry in the directory for one rebuild — which is the same reason
// normalizeDn() beside the store has none. The style rule is about functions a
// reader follows, not about a helper in an inner loop.
//
// BOTH sources, because that is the pair the walk
// compared — an entry added by hand as `cn=Alice Example,ou=users` carrying
// `uid: alice` was found under either, and an index holding one of them would
// have quietly narrowed the rule it is enforcing.
function usernameKeysOf(entry) {
  log.debug("Entering usernameKeysOf().");
  const names = (entry.attributes.uid || []).concat([usernameOfEntry(entry)]);
  const out = [];
  names.forEach(function (value) {
    const key = String(value == null ? '' : value).trim().toLowerCase();
    if (key && out.indexOf(key) === -1) {
      out.push(key);
    }
  });
  log.debug("Leaving usernameKeysOf().");
  return out;
}

function buildUsernameIndex() {
  log.debug('Entering buildUsernameIndex().');
  const parent = normalizeDn(usersDn());
  const index = new Map();
  eachEntryInRealm(function (entry) {
    if (normalizeDn(parentDn(entry.dn)) !== parent) {
      return;
    }
    usernameKeysOf(entry).forEach(function (key) {
      // FIRST ENTRY WINS, because the walk this replaces stopped at its first
      // hit and the store iterates in insertion order — so the entry named here
      // is the entry that walk would have returned. Two entries claiming one
      // name is a directory somebody built by hand over the raw socket, and
      // reconciling it is not this index's job.
      if (!index.has(key)) {
        index.set(key, normalizeDn(entry.dn));
      }
    });
  });
  usernameIndexes().builds++;
  log.debug('Leaving buildUsernameIndex(). ' + index.size + ' name(s), built ' +
            usernameIndexes().builds + ' time(s) so far.');
  return index;
}

// The index, rebuilt if anything has been written since it was made.
function usernameIndexNow() {
  log.debug("Entering usernameIndexNow().");
  const cache = usernameIndexes();
  const container = normalizeDn(usersDn());
  if (cache.index && cache.version === directoryVersion &&
      cache.usersDn === container) {
    log.debug("Leaving usernameIndexNow().");
    return cache.index;
  }
  cache.index = buildUsernameIndex();
  cache.version = directoryVersion;
  cache.usersDn = container;
  log.debug("Leaving usernameIndexNow().");
  return cache.index;
}

// One entry added, folded in rather than invalidating — the whole point of the
// block above. Called from putEntry() AFTER the write and after
// touchDirectory(), and it declines in three cases, each of which costs a
// rebuild and nothing else:
//
//   * the index was already behind, so it stays behind;
//   * the DN already held an entry, because putEntry() is a SET and the names
//     the old one answered to would still be in here pointing at a person who
//     no longer has them;
//   * the entry is not in this realm's `ou=users`, so no name of it belongs in
//     here at all — and that is most of them: every group, application,
//     federation, role, policy and PEP entry reaches putEntry() too.
function noteUsernameIndexPut(stored, hadNames, wasCurrent) {
  log.debug('Entering noteUsernameIndexPut().');
  const cache = usernameIndexes();
  if (!wasCurrent || !cache.index) {
    log.debug('Leaving noteUsernameIndexPut(). Left to be rebuilt.');
    return;
  }
  if (normalizeDn(parentDn(stored.dn)) === cache.usersDn) {
    const key = normalizeDn(stored.dn);
    const now = usernameKeysOf(stored);
    // ---------------------------------------------------------------------
    // AN OVERWRITE IS FOLLOWED PRECISELY RATHER THAN DECLINED, and the first
    // implementation declined it — which was safe, and cost the whole benefit
    // on the SCIM door for the second time in one afternoon.
    //
    // `putEntry()` is a SET, and a SCIM create is TWO writes: `createUser()`
    // puts the entry, and then `writePerson()` puts it again with the SCIM
    // attributes merged over it. So every create through that door ended with
    // an overwrite, the index declined to follow it, and the next create
    // rebuilt by walking the realm. `/admin-api` and LDAP never showed it
    // because neither writes twice.
    //
    // What made declining tempting is real: the names the OLD entry answered
    // to would still be in here, pointing at somebody who may no longer have
    // them. So they are taken out — but only the ones that pointed AT THIS
    // ENTRY, because a name mapping to a different DN belongs to whichever
    // entry the walk would have found first and is not this write's to remove.
    // ---------------------------------------------------------------------
    (hadNames || []).forEach(function (name) {
      if (now.indexOf(name) === -1 && cache.index.get(name) === key) {
        cache.index.delete(name);
      }
    });
    now.forEach(function (name) {
      // Not overwritten unless it was already ours, for buildUsernameIndex()'s
      // reason: an existing mapping to a DIFFERENT entry names the one the
      // walk would have found first, and this one is later.
      if (!cache.index.has(name)) {
        cache.index.set(name, key);
      }
    });
  }
  // Current again — including for an entry that put no name in it, which is
  // still a write this index is unaffected by.
  cache.version = directoryVersion;
  log.debug('Leaving noteUsernameIndexPut(). ' + cache.index.size +
            ' name(s).');
}

// An entry that was ALREADY in the store and has GAINED a name — which is the
// one other shape of write this index can follow without a rebuild, and it has
// exactly one caller: applyVcAttributes(), which fills attributes that are
// ABSENT and never replaces one. `uid` is among the attributes it can fill, so
// an entry can genuinely start answering to a name it did not answer to before.
//
// **IT IS ONLY VALID FOR A MUTATION THAT ADDS NAMES AND REMOVES NONE**, and
// that is not a caution, it is the precondition: this folds the entry's current
// names in and stamps the version, so a mutation that took a name AWAY would
// leave the old one here pointing at an entry that no longer answers to it.
// Anything else must leave the version behind and let the next read rebuild.
// ---------------------------------------------------------------------------
// WHERE THE LAST WRITE LANDED, AND WHY THAT IS WORTH KEEPING.
//
// Three functions here answer "every entry under this container" —
// allPolicies(), allRoles() and applicationEntry()'s fallback — and each did it
// by walking the WHOLE REALM and testing every entry with isUnder(). The
// containers are tiny: a handful of policies, a handful of roles, a few dozen
// applications. The realm is not.
//
// **THEY ARE ON THE PER-REQUEST PATH**, because the XACML access gate asks for
// the policies and the roles on every gated request, so every call to `/scim`,
// `/admin`, `/admin-api`, `/portal` and `/xacml` walked the directory three
// times. A CPU profile of five thousand SCIM creates put `normalizeDn` at 24%
// of all non-idle time, called from those three walks and from the isUnder()
// beside each of them — on a service whose store held a few dozen policies and
// roles between them.
//
// ---------------------------------------------------------------------------
// WHY THIS IS NOT KEYED ON `directoryVersion` LIKE THE USERNAME INDEX ABOVE.
//
// It cannot be, and the reason is the whole design. `directoryVersion` is
// bumped by EVERY writer, so a policy listing keyed on it would be invalidated
// by every person created — which is exactly the load these walks are expensive
// under. It would have been a cache that is correct and worth nothing, which is
// the failure this file has already had twice (see applyVcAttributes()'s note,
// and populateVcAttributesAt()'s).
//
// So the clock is PER CONTAINER: a write records the version against every
// ancestor of the DN it landed on, and a listing of `ou=policies` is current
// until something is written under `ou=policies`. Creating five thousand people
// bumps `ou=users` and the realm root five thousand times and does not touch
// the policy container once.
//
// **INVALIDATION IS SAFE BY DEFAULT AND THAT IS LOAD-BEARING.** There are about
// thirty callers of touchDirectory() in this file and they are held to the rule
// by prose rather than by the compiler. A caller that says WHERE it wrote gets
// a precise invalidation; **a caller that says nothing invalidates every
// container at once**, which is what `everywhere` is. So the failure mode of
// forgetting to annotate a writer — or of adding a new one — is a slower cache
// and never a wrong answer, and only the two writers on the hot path are
// annotated at all.
//
// Only ANCESTORS are recorded, never the DN written to itself:
// `subtreeVersion()` is asked about containers, and recording every leaf would
// put one key in here per entry in the directory for nothing.
// ---------------------------------------------------------------------------
const subtreeClocks = realms.keyed(function () {
  return { everywhere: 0, containers: new Map(), listings: new Map() };
});

function noteWriteUnder(dn) {
  log.debug("Entering noteWriteUnder().");
  const clock = subtreeClocks();
  let key = normalizeDn(dn);
  let comma = key.indexOf(',');
  while (comma >= 0) {
    key = key.slice(comma + 1);
    clock.containers.set(key, directoryVersion);
    comma = key.indexOf(',');
  }
  log.debug("Leaving noteWriteUnder().");
}

// A write whose location was not declared. Every container listing is stale
// after this, which is the conservative answer and the one a writer gets for
// free.
function noteWriteAnywhere() {
  log.debug("Entering noteWriteAnywhere().");
  subtreeClocks().everywhere = directoryVersion;
  log.debug("Leaving noteWriteAnywhere().");
}

function subtreeVersion(containerDn) {
  log.debug("Entering subtreeVersion().");
  const clock = subtreeClocks();
  const named = clock.containers.get(normalizeDn(containerDn)) || 0;
  log.debug("Leaving subtreeVersion().");
  return named > clock.everywhere ? named : clock.everywhere;
}

// Every entry strictly under `containerDn`, kept until something is written
// there. The rows are the LIVE stored objects, exactly as eachEntryInRealm()
// hands them out — so an attribute changed in place is visible through a cached
// listing, and only MEMBERSHIP of the container is what this has to invalidate
// on.
function entriesUnder(containerDn) {
  log.debug('Entering entriesUnder(). container=' + containerDn);
  const key = normalizeDn(containerDn);
  const clock = subtreeClocks();
  const version = subtreeVersion(containerDn);
  const hit = clock.listings.get(key);
  if (hit && hit.version === version) {
    log.debug('Leaving entriesUnder(). ' + hit.rows.length + ' cached row(s).');
    return hit.rows;
  }
  const rows = [];
  eachEntryInRealm(function (stored) {
    if (isUnder(stored.dn, containerDn) && normalizeDn(stored.dn) !== key) {
      rows.push(stored);
    }
  });
  clock.listings.set(key, { version: version, rows: rows });
  log.debug('Leaving entriesUnder(). ' + rows.length + ' row(s), walked.');
  return rows;
}

function noteUsernameIndexRefresh(stored, wasCurrent) {
  log.debug('Entering noteUsernameIndexRefresh().');
  const cache = usernameIndexes();
  if (!wasCurrent || !cache.index) {
    log.debug('Leaving noteUsernameIndexRefresh(). Left to be rebuilt.');
    return;
  }
  if (normalizeDn(parentDn(stored.dn)) === cache.usersDn) {
    const key = normalizeDn(stored.dn);
    usernameKeysOf(stored).forEach(function (name) {
      if (!cache.index.has(name)) {
        cache.index.set(name, key);
      }
    });
  }
  cache.version = directoryVersion;
  log.debug('Leaving noteUsernameIndexRefresh(). ' + cache.index.size +
            ' name(s).');
}

// Whether the index is current for THIS realm and THIS container right now.
// Read BEFORE a write, because afterwards `directoryVersion` has moved on and
// the cache can no longer answer the question about itself.
function usernameIndexIsCurrent() {
  log.debug("Entering usernameIndexIsCurrent().");
  const cache = usernameIndexes();
  log.debug("Leaving usernameIndexIsCurrent().");
  return !!cache.index && cache.version === directoryVersion &&
    cache.usersDn === normalizeDn(usersDn());
}

// ---------------------------------------------------------------------------
// THE GROUP INDEX'S CACHE IS DECLARED HERE RATHER THAN BESIDE ITS BUILDER, and
// the reason is a temporal dead zone rather than tidiness: `putEntry()` keeps
// it current (see noteGroupIndexPut() below), `putEntry()` is called while this
// module is still loading — the seeding does it — and a `const` declared
// further down the file would not exist yet when the first seeded entry was
// written. `buildGroupIndex()`, `groupIndexNow()` and everything else about it
// stay where they are, with a pointer.
// ---------------------------------------------------------------------------
const groupIndexes = realms.keyed(function () {
  return { index: null, version: -1, size: -1, builds: 0 };
});

const NO_GROUPS = new Map();

function groupIndexIsCurrent() {
  log.debug("Entering groupIndexIsCurrent().");
  const cache = groupIndexes();
  log.debug("Leaving groupIndexIsCurrent().");
  return !!cache.index && cache.version === directoryVersion &&
    cache.size === entries.size;
}

// ---------------------------------------------------------------------------
// A WRITE THAT CANNOT HAVE CHANGED THE GROUP INDEX, kept rather than rebuilt.
//
// **THE INVARIANT THIS RESTS ON IS NARROW AND HAS TO BE STATED**, because it is
// the only thing making this safe: `buildGroupIndex()` calls `groupRuleFor()`
// on every entry and RETURNS EARLY on a falsy one, so a non-group entry
// contributes nothing to either half of that index. A person's own `memberOf`
// is not in there either — `groupsOfUser()` reads it live off the entry and
// looks the value up in `byDn` — so writing a person cannot change it by that
// route. **If either of those ever stops being true, this stamp has to go.**
//
// Why it is worth having: `groupIndexNow()` rebuilds on ANY write, which is
// right when reads are rare relative to writes and quadratic when they are
// not. A SCIM User resource carries `groups`, so a bulk create asks for this
// index once per person and invalidated it once per person — 0.379ms at the
// 500th and 2.567ms at the 3,000th, measured in process, on top of a create
// that is now flat. The LDAP door never showed it because an `add` builds no
// SCIM resource.
//
// The size is stamped as well as the version. That check is described where
// the builder is as a second line of defence against a writer that forgot to
// bump the version, and leaving it alone would have made this stamp a no-op:
// a create changes `entries.size` by definition.
// ---------------------------------------------------------------------------
function noteGroupIndexPut(stored, wasCurrent) {
  log.debug('Entering noteGroupIndexPut().');
  const cache = groupIndexes();
  if (!wasCurrent || !cache.index) {
    log.debug('Leaving noteGroupIndexPut(). Left to be rebuilt.');
    return;
  }
  if (groupRuleFor(stored)) {
    // A group, by placement or by object class. This genuinely changes the
    // index, so it is left to rebuild — which is the ordinary path and the
    // one every membership write takes.
    log.debug('Leaving noteGroupIndexPut(). It is a group; left to rebuild.');
    return;
  }
  cache.version = directoryVersion;
  cache.size = entries.size;
  log.debug('Leaving noteGroupIndexPut(). Still current.');
}

// THE NAMING CONTEXTS THIS SOCKET SERVES: the root, and one per defined realm.
// A list rather than a single value since 2026-08-25 — each realm's directory
// is a separate store reached by naming its base, so publishing only the root
// would leave a client no way to discover that the others are there, and
// discovery is the one job the root DSE has. With no realms defined this is a
// single-valued attribute holding exactly what it always held.
function namingContexts() {
  log.debug("Entering namingContexts().");
  const out = [ROOT_DN];
  if (!realms.active()) {
    log.debug("Leaving namingContexts().");
    return out;
  }
  realms.list().forEach(function (realm) {
    const base = realmBaseDn(realm.id);
    if (normalizeDn(base) !== normalizeDn(ROOT_DN)) {
      out.push(base);
    }
  });
  log.debug("Leaving namingContexts().");
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
  log.debug("Entering realmEntryCount().");
  log.debug("Leaving realmEntryCount().");
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
// them. The directory is SCHEMALESS on purpose: a client can `add` any
// attribute it likes to any entry, and two of the families here write entries
// nobody typed — a TLS client certificate's subject becomes attributes RDN by
// RDN, so whichever types are in that subject arrive whether or not this
// service has ever heard of them. A table holding only what this service
// happens to write would be right about its own entries and wrong about
// everybody else's, which is worse than having none: the reader who most needs
// the conventional spelling is the one looking at an attribute this service did
// not write. `seeAlso` is what made the point — a perfectly ordinary RFC 4519
// type, rendering as `seealso` on the one page whose job is to show an entry
// faithfully.
//
// WHAT IS NOT HERE. No spelling is invented for a name nobody published. Where
// two specifications disagree about the capitalisation of one name the older
// registered one wins and the disagreement is noted, because picking silently
// is how a table like this becomes a third opinion.
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

  // RFC 4523 — the PKI types. `certificateRevocationList` is the one this
  // service WRITES, on every `cRLDistributionPoint` entry under `ou=crl`, and
  // it was coming back as `certificaterevocationlist;binary` to a client
  // reading the distribution point a certificate named.
  'authorityRevocationList', 'cACertificate', 'certificateRevocationList',
  'crossCertificatePair', 'deltaRevocationList', 'supportedAlgorithms',

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
  // rather than describe it. `entryDN` is load-bearing beyond the display: it
  // is what matchable() calls the DN when a filter matches on it, and what
  // entryObject() publishes the DN as, so those two and this table have to
  // agree or an ldapsearch filter and a console page name one fact two things.
  'entryDN', 'entryUUID',

  // PKCS#9, and it arrives on this directory inside a certificate subject —
  // certificatePlan() turns every RDN of a verified client certificate's
  // subject into an attribute, so which types turn up is decided by whoever
  // issued the certificate and not by anything here.
  'emailAddress',

  // NOT REGISTERED ANYWHERE, and here anyway. `memberOf` is the reverse of
  // group membership as Active Directory and most directories in the wild
  // implement it, and it has never been standardised —
  // draft-ietf-ldapext-memberof expired. It cannot go in this service's own
  // list either, because this service did not invent it: a client writes it,
  // and /admin/groups reports the disagreement when an entry's own memberOf
  // names a group that does not list it back. NOTHING HERE MAINTAINS IT — that
  // page says so, and the spelling being conventional must not be read as the
  // attribute being managed.
  'memberOf'
];

// ---------------------------------------------------------------------------
// This service's own names. Not standard, and listed here for the display only.
// Each group says why nothing standard was used instead, because "we invented
// an attribute type" is a claim that needs one.
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
  // attribute type for "the DID this entry is", which is unsurprising — DID
  // Core postdates the LDAP schema documents by two decades and nobody
  // registered one.
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
  // attributes, which are Microsoft's own names for something else entirely,
  // and pretending to be one of those would be worse than obviously not being
  // one.
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
  // kinds are ordinary directory attributes and look identical, and
  // applyVcAttributes() fills in `mail`, `givenName` and the rest for everybody
  // — so without this there is no way to tell a real email address a partner
  // sent from one this service made up, which is exactly the question a
  // federated directory entry raises. Nothing reads it; it is there to be read.
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
  'oauthConsent',

  // ---------------------------------------------------------------------
  // THE CREDENTIALS ON A PERSON'S OWN ENTRY THAT ARE NOT `userPassword`.
  //
  // `common/credentials.js` writes all four. The first three have been
  // written since 2026-09-06 and were NOT in this table until 2026-09-10,
  // which is the ordinary way this table goes wrong: nothing fails, the name
  // simply renders lower-cased on `/admin/ldap/directory` — the one page
  // whose whole job is to show an entry faithfully — and the attribute looks
  // like something a foreign client added rather than something this service
  // wrote.
  //
  // There is no standard type for any of them and none is invented lightly:
  // WebAuthn, RFC 6238 and the notion of an activation link all postdate the
  // LDAP schema documents, and `userPassword` (RFC 4519 section 2.41) is the
  // only credential attribute those documents define.
  //
  // **TWO OF THE FOUR HOLD A VERIFIER AND TWO HOLD SOMETHING ELSE**, which is
  // the distinction to keep in mind when reading an entry: `userPassword` and
  // `stsActivationToken` are scrypt hashes and are useless to whoever reads
  // them; a WebAuthn public key is published by design; and
  // `stsTotpCredential` carries a SHARED SECRET, which is the one credential
  // in this directory that can be read back and used — sealed under the
  // key-encryption key in product mode for exactly that reason, and in the
  // clear in development where the key would not survive a restart.
  // `common/credentials.js` argues all of it.
  'stsWebauthnCredential', 'stsActivationToken', 'stsActivationExpires',
  'stsTotpCredential',

  // THE BOOTSTRAP ADMINISTRATOR'S FLAGS (2026-09-13) — see readPersonFlags().
  // `pwdReset` is draft-behera-ldap-password-policy's name, spelt as that draft
  // spells it, beside the `pwd*` names the password policy already uses.
  'pwdReset', 'stsBootstrapAdministrator', 'stsConsoleClaimedAt',
  // WHAT AN ADMINISTRATOR PUT ON A PERSON FROM THEIR /admin/users PAGE
  // (2026-09-13) — see readPersonFlags(): a second factor required of them, and
  // the hash of a password reset link.
  'stsMfaRequired', 'stsPasswordResetToken', 'stsPasswordResetExpires',

  // THE CLIENT TRUSTSTORE'S DURABLE HALF (2026-09-12): one entry per anchor
  // under ou=trustAnchors in the DEFAULT realm. A CA certificate is public, so
  // nothing here is sealed; what makes the container sensitive is that an
  // entry decides whose client certificate becomes an identity. See
  // `trustAnchorsDn()`.
  'stsTrustAnchor', 'stsTrustAnchorCertificate', 'stsTrustAnchorFingerprint',
  'stsTrustAnchorAddedBy',

  // AND A FIFTH SINCE 2026-09-10: the RECOVERY CODES. It belongs with the four
  // above and it is the SECOND of them that can be read back and used — a set
  // of single-use strings, issued automatically the first time somebody
  // enrols a second factor, sealed under the key-encryption key wherever that
  // key outlives the process and stored as the strings they were shown as
  // where it does not.
  //
  // **IT IS ENCRYPTED RATHER THAN HASHED FOR A REASON THAT IS NOT ABOUT
  // CRYPTOGRAPHY**: a person may look at their remaining codes again on
  // `/portal/mfa`, and a hash cannot be shown. `common/backup_codes.js`
  // argues it, `common/credentials.js` does the sealing, and this module —
  // which holds no key — only ever sees whatever of the two it was handed.
  'stsBackupCodes',

  // AND A SIXTH SINCE 2026-09-11: the RFC 7523 SIGNING KEY PAIR a person may
  // hold. Six attributes and a declaration, and they are the PERSON's
  // counterpart to `oauthAssertion*` on an application — no code path crosses
  // the two sets, which is the same rule `applications.js` states about its
  // own pair. `common/person_assertions.js` is the register and argues the
  // whole thing, including the one refusal it exists for: a person's key
  // signs an assertion ABOUT THAT PERSON and about nobody else.
  //
  // **`stsAssertionPrivateKey` IS THE THIRD ATTRIBUTE IN THIS DIRECTORY THAT
  // CAN BE READ BACK AND USED**, after the authenticator's shared secret and
  // the recovery codes, and it is sealed under the key-encryption key
  // wherever that key outlives the process for exactly their reason. The
  // other five are public by construction: a certificate, a chain, a JWKS, a
  // kid and an expiry are all things a relying party is MEANT to be given.
  'stsAssertionIssuer', 'stsAssertionJwks', 'stsAssertionCertificate',
  'stsAssertionCertificateChain', 'stsAssertionPrivateKey',
  'stsAssertionKid', 'stsAssertionExpiresAt', 'stsAssertionKeySource',

  // AND THE PERSON'S RFC 7522 KEY PAIR, SINCE 2026-09-13 — a fourth set,
  // sharing no name with the three above it for the reason they share none
  // with each other. `stsSamlAssertionPrivateKey` is sealed like its JWT twin;
  // the thumbprint is the handle an XML Signature's certificate is matched by.
  // `…KeySource` on both records whether the pair was issued here or a
  // certificate was uploaded in its place.
  'stsSamlAssertionIssuer', 'stsSamlAssertionCertificate',
  'stsSamlAssertionCertificateChain', 'stsSamlAssertionPrivateKey',
  'stsSamlAssertionThumbprint', 'stsSamlAssertionExpiresAt',
  'stsSamlAssertionKeySource',

  // AND A SEVENTH SINCE 2026-09-12: A PERSON'S KERBEROS LONG-TERM KEYS, derived
  // from their own password by `kerberos/krb5_person_keys.js` so that a
  // product-mode KDC can authenticate them. `stsKrb5Keys` is ONE sealed value
  // carrying every enctype's key beside the name and a stamp of the password
  // hash they were derived beside; `stsKrb5KeyInfo` is the public half — kvno,
  // enctypes, when. **The first is password-equivalent and is WITHHELD** from
  // the directory dump and from an LDAP search, ciphertext included, which is
  // one step further than the three credentials above it go: nothing ever reads
  // a Kerberos key back out, so there is no reader whose view it would spoil.
  'stsKrb5Keys', 'stsKrb5KeyInfo',

  // AND AN EIGHTH SINCE 2026-09-13: what ACME, EST and SCEP issued to a person,
  // the two protocol credentials, and the host names an administrator
  // registered — `common/cert_enrollment.js` is the register. The private key,
  // the EAB key and the challenge are WITHHELD from every dump and search in
  // every mode (`cert_enrollment.withheldValues()`); the certificates and the
  // host names are public.
  'stsEnrolledCertificate', 'stsEnrolledPrivateKey', 'stsAcmeEabKey',
  'stsScepChallenge', 'stsCertificateHostName'
];

// The table itself, built from the two lists. `learnName()` is the ONE way in,
// so the disagreement check below cannot be bypassed by a later merge — and
// there are three of those.
const CANONICAL_NAMES = {};

// A name is learnt once. A SECOND spelling of the same name is a real defect
// and is reported rather than silently resolved: the two lists here, the
// credential claim catalogue and the applications schema are four independently
// maintained sets of spellings, and "whichever was merged first wins" is how
// one of them comes to be quietly wrong about `schacDateOfBirth` while all four
// look right read alone. Reported and not thrown, because a table of how to
// CAPITALISE a name must never be able to stop this service starting.
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
    log.warn('ldap: two spellings of the attribute type "' + lower + '" — "' +
             known +
             '" is already known and ' + source + ' says "' + canonical +
             '". ' +
                 'Keeping "' +
             known + '". They match identically either way (RFC 4512 section ' +
             '2.5 makes attribute descriptions case-insensitive) so nothing ' +
             'is found or missed differently; it is only the spelling shown ' +
             'on a page, and one of the two lists is wrong.');
  }
  log.debug('Leaving learnName().');
}

STANDARD_NAMES.forEach(function (spelling) {
  learnName(spelling, 'the ' + 'standard list');
});
OWN_NAMES.forEach(function (spelling) {
  learnName(spelling, "this service's " + "own list");
});

// AND THE inetOrgPerson CLASS DEFINITION (2026-09-11), for the reason every
// other merge below is done: `common/inetorgperson.js` is a fourth
// independently maintained list of spellings — it is what `/portal` draws its
// account page from — and it names most of the same types the standard list
// above does. Merged rather than trusted, so that a disagreement between the
// page a PERSON reads and the page an OPERATOR reads is REPORTED at startup
// instead of one of them quietly rendering `seealso`.
//
// It is a require of a LIBRARY (rule 3) that reaches no further than
// `common/helpers.js`, so it can neither move a route nor join a cycle.
Object.keys(inetOrgPerson.CANONICAL_NAMES).forEach(function (lower) {
  learnName(inetOrgPerson.CANONICAL_NAMES[lower], 'the inetOrgPerson schema');
});

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

// And the applications registry's, for the same reason and from the same kind
// of source: `applications.js` owns that schema and spells every attribute the
// way `/ldap/applications` publishes it — `oauthClientId`,
// `appRegistrationJson`, `samlEntityId`. Without this merge every applications
// page and every reply from the management API showed `oauthclientid` beside a
// published schema that says `oauthClientId`, which reads as a bug in the page
// rather than as what it is: the store lower-casing a name because
// @ldapjs/attribute does.
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

// AND THE FEDERATION REGISTER'S, which is the OLDEST instance of this and was
// the last to be fixed. It never showed, because `/admin/ldap/federations`
// draws its columns from `federation.list()` records and that module reads an
// attribute case-insensitively (`valueOf()` walks the keys), so the only place
// the lower-cased spellings surfaced was the raw entry dump beside a published
// schema saying `fedSigningCertificate`. That is precisely the symptom the
// applications merge below was written for — a page that reads as though IT
// were wrong, when what is wrong is that the store lower-cases a name because
// @ldapjs/attribute does.
//
// It is merged here rather than left alone because the defence is in the wrong
// place: `federation.js` being careful protects `federation.js`, and the next
// reader of one of these entries — a console page, an `/admin-api` operation,
// something that has not been written yet — gets `undefined` from
// `fedEnabled` and reports something plausible. The three merges below found
// exactly that bug twice on the day they were written.
federation.SCHEMA.attributes.forEach(function (row) {
  learnName(row.name, 'the federation schema');
});

// AND THE THREE CONTAINERS WHOSE PAGES LANDED ON 2026-09-05, for exactly the
// reason the applications merge above gives, found exactly the way that one
// was: `/admin/ldap/roles` counted a role's members by reading
// `roleMemberUser` off the entry and reported `0 user(s)` for a role somebody
// plainly held, because the store had `rolememberuser` — and
// `/admin/ldap/policies` showed every policy's kind as `(unstated)` and, worse,
// showed a DISABLED policy as enabled, since a missing `xacmlEnabled` is not
// the string `false`. That last one is why these are merged rather than read
// case-insensitively at each site: a lookup that silently misses answers
// something plausible, and the three pages are not the only readers of these
// entries.
//
// Same source of truth in all three cases — the module that owns the container
// owns the spelling, and `learnName()` reports a disagreement rather than
// resolving it by merge order.
roles.SCHEMA.attributes.forEach(function (row) {
  learnName(row.name, 'the roles schema');
});
// The password policy's, BOTH halves: the attributes on a profile entry and the
// two the policy maintains on a PERSON (`pwdHistory`, `pwdChangedTime`). Merged
// from the schema rather than added to OWN_NAMES above, because the module that
// gives those two their meaning is the one that spells them — and because an
// unlearnt `pwdInHistory` read back as `pwdinhistory` is exactly the lookup
// that silently misses and answers "the built-in default".
passwordPolicy.SCHEMA.attributes.concat(passwordPolicy.SCHEMA.personAttributes)
  .forEach(function (row) {
    learnName(row.name, 'the password policy schema');
  });
xacmlStore.SCHEMA.attributes.forEach(function (row) {
  learnName(row.name, 'the XACML policy schema');
});
xacmlPepRegistry.SCHEMA.attributes.forEach(function (row) {
  learnName(row.name, 'the XACML PEP registry schema');
});

// And the SCIM mapping's two inventions, `scimActive` and `scimExternalId`, for
// the same reason and from the same kind of source. They are a FIFTH list,
// which is one more than the comment above learnName() named — and the check is
// what makes a fifth affordable: the two names are this service's own, nothing
// else spells them, and if that ever stops being true the warning says which
// table to look in. scim_map.js is a library that registers nothing and
// requires only helpers.js and vc_claims.js, so requiring it here moves no
// route and closes no cycle.
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
  log.debug("Entering normalizeDn().");
  const text = String(value == null ? '' : value).trim();
  log.debug("Leaving normalizeDn().");
  return text.split(',').map(function (part) {
    return part.trim().toLowerCase();
  }).join(',');
}

// The parent of a DN, or '' for a naming context with nothing above it.
function parentDn(value) {
  log.debug("Entering parentDn().");
  const parts = String(value == null ? '' : value).split(',');
  if (parts.length <= 1) {
    log.debug("Leaving parentDn().");
    return '';
  }
  log.debug("Leaving parentDn().");
  return parts.slice(1).join(',').trim();
}

// Is `dn` at or below `base`? Used by every scope decision and by the check
// that refuses to operate outside this server's naming context.
function isUnder(dn, base) {
  log.debug("Entering isUnder().");
  const a = normalizeDn(dn);
  const b = normalizeDn(base);
  if (!b) {
    log.debug("Leaving isUnder().");
    return true;
  }
  if (a === b) {
    log.debug("Leaving isUnder().");
    return true;
  }
  log.debug("Leaving isUnder().");
  return a.endsWith(',' + b);
}

// How many commas separate a DN from a base — 0 for the base itself, 1 for its
// immediate children. This is what tells `one` from `sub`.
function depthUnder(dn, base) {
  log.debug("Entering depthUnder().");
  const a = normalizeDn(dn);
  const b = normalizeDn(base);
  if (a === b) {
    log.debug("Leaving depthUnder().");
    return 0;
  }
  const rest = a.slice(0, a.length - b.length - 1);
  log.debug("Leaving depthUnder().");
  return rest.split(',').length;
}

function canonicalName(lower) {
  log.debug("Entering canonicalName().");
  // AN ATTRIBUTE DESCRIPTION MAY CARRY OPTIONS (RFC 4512 section 2.5) —
  // `certificateRevocationList;binary` — and the table knows TYPES, so the
  // type is spelt and the options are kept as written.
  const at = String(lower).indexOf(';');
  if (at > 0) {
    const type = lower.slice(0, at);
    log.debug("Leaving canonicalName(). With options.");
    return (CANONICAL_NAMES[type] || type) + lower.slice(at);
  }
  log.debug("Leaving canonicalName().");
  return CANONICAL_NAMES[lower] || lower;
}

// The attribute TYPE of a stored attribute name, with the `;binary` transfer
// option taken off. RFC 4522 section 3: *an attribute description with the
// binary option references exactly the same attribute as the attribute
// description without the binary option* — so a request for
// `certificateRevocationList` and one for `certificateRevocationList;binary`
// are asking for one attribute, and a filter on either names it too. The
// entries this service writes store the CRL under the `;binary` spelling, and
// until 2026-09-13 a request or a filter naming the plain type found nothing.
function withoutBinaryOption(lower) {
  log.debug("Entering withoutBinaryOption().");
  log.debug("Leaving withoutBinaryOption().");
  return String(lower).replace(/;binary$/i, '');
}

// The scope, as one of 'base' | 'one' | 'sub'.
//
// Read from the NUMBER on the wire (RFC 4511 section 4.5.1.2: baseObject 0,
// singleLevel 1, wholeSubtree 2) and not from ldapjs's `scopeName`, which
// spells the middle two 'single' and 'subtree'. That difference cost a search:
// a handler comparing scopeName against 'one' and 'sub' matched neither, fell
// through to its default, and answered every one-level search as a subtree — so
// the results were a superset, every assertion about them still passed, and the
// only visible symptom was one extra entry. A wrong scope is invisible in
// exactly the direction that makes it hardest to notice.
function scopeOf(req) {
  log.debug("Entering scopeOf().");
  const value = typeof req.scope === 'number' ? req.scope : 2;
  if (value === 0) {
    log.debug("Leaving scopeOf().");
    return 'base';
  }
  if (value === 1) {
    log.debug("Leaving scopeOf().");
    return 'one';
  }
  log.debug("Leaving scopeOf().");
  return 'sub';
}

// Attribute values are always an array of strings on the way in, whatever the
// caller handed us. LDAP has no scalars, and a store that sometimes held one is
// a store every reader has to test the type of.
function valuesOf(value) {
  log.debug("Entering valuesOf().");
  if (value === undefined || value === null) {
    log.debug("Leaving valuesOf().");
    return [];
  }
  if (Array.isArray(value)) {
    log.debug("Leaving valuesOf().");
    return value.map(function (v) { return String(v); });
  }
  log.debug("Leaving valuesOf().");
  return [String(value)];
}

// A generalized time, which is what createTimestamp and modifyTimestamp are:
// YYYYMMDDHHMMSSZ. Written out rather than taken from a library because the one
// place it differs from an ISO 8601 string is the punctuation, and a debugger
// showing an ISO string where a directory shows a generalized time is showing
// the wrong thing.
function generalizedTime(when) {
  log.debug("Entering generalizedTime().");
  const d = when instanceof Date ? when : new Date();
  const pad = function (n, width) {
    log.debug("Entering pad().");
    log.debug("Leaving pad().");
    return String(n).padStart(width || 2, '0');
  };
  log.debug("Leaving generalizedTime().");
  return pad(d.getUTCFullYear(), 4) + pad(d.getUTCMonth() + 1) +
    pad(d.getUTCDate()) + pad(d.getUTCHours()) + pad(d.getUTCMinutes()) +
    pad(d.getUTCSeconds()) + 'Z';
}

// ---------------------------------------------------------------------------
// Reading and writing entries.
// ---------------------------------------------------------------------------

function getEntry(dn) {
  log.debug("Entering getEntry().");
  log.debug("Leaving getEntry().");
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

// ---------------------------------------------------------------------------
// `entryUUID` (RFC 4530): THE ONE THING ABOUT AN ENTRY THAT NEVER CHANGES
// (2026-09-14).
//
// **IT IS WHAT A PERSON'S `sub` IS NOW**: `urn:uuid:<entryUUID>`, in both
// modes, through `helpers.setSubjectResolver()`. It replaced
// `urn:sts:user:<username>`, which a rename changed and a person deleted and
// re-created under the same name inherited — the account-recycling hole a
// relying party linking on `sub` falls straight into. `authn/CLAUDE.md`, *What
// an authenticated identity is here*, carries the design and rcbj's choices.
//
// Four rules, each enforced in one place:
//
//   * **ASSIGNED IN `putEntry()` AND CARRIED THROUGH EVERY OVERWRITE.** Every
//     writer in this file reaches the store through that function, and most of
//     them REBUILD the attribute set (`writePerson()`, `writeApplication()`,
//     the CRL containers), so the value is taken from the entry already at that
//     DN
//     and never from the attributes a caller handed in. A delete followed by a
//     create at the same DN is a NEW entry and gets a new value — which is the
//     whole difference from a name-derived subject.
//   * **A RENAME KEEPS IT**, because `modifyDN` moves the stored object rather
//     than writing a new one.
//   * **A SEEDED ENTRY'S IS DETERMINISTIC** — a name-based (version 5) UUID
//     over the realm and the DN — and every other entry's is random (version
//     4). The seed runs on every start, so a random value would give alice a
//     new `sub` on every restart of a development service; nothing created by
//     a door is
//     treated that way, because a deterministic value is exactly what makes a
//     re-created person the same subject again (rcbj's choice).
//   * **A RESTORED OR REPLICATED ROW WITHOUT ONE IS BACKFILLED THE SAME WAY**
//     (version 5 over the realm and the stored key), so every process that
//     reads a row written before this change computes the SAME value without
//     having to write it back first.
//
// It is NO-USER-MODIFICATION (RFC 4530 section 2), refused on an add or modify
// in BOTH modes — see `ALWAYS_PROTECTED_OPERATIONAL` — and returned on a search
// only when it is asked for by name, like every other operational attribute.
// ---------------------------------------------------------------------------
const ENTRY_UUID_NAMESPACE = Buffer.from('3b2f8c4e6d1a4e9f8a7c5d2e1f0b9a86',
                                        'hex');

const UUID_SHAPED =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Whether another process can create the same entry at the same moment: this
// process is a node of a cluster (asked of `cluster/cluster.js` LAZILY — a leaf
// this file needs only at this one decision), or one of several request
// workers answering one port (`workers.requestCount` with something in
// `workers.dispatch`, the question `persistence_minted.js` asks the same way).
// See putEntry()'s note on a sign-in's entry.
function clusteredNode() {
  log.debug("Entering clusteredNode().");
  const cluster = require('../cluster/cluster');
  const workers = (Number(config.value('workers.requestCount')) || 0) > 0 &&
    String(config.value('workers.dispatch') || '').trim() !== '';
  log.debug("Leaving clusteredNode().");
  return cluster.mode() !== 'off' || workers;
}

// RFC 9562 section 5.5: SHA-1 over the namespace and the name, the version and
// variant bits set. Node has a v4 generator and no v5 one.
function nameBasedUuid(name) {
  log.debug("Entering nameBasedUuid().");
  const hash = crypto.createHash('sha1').update(ENTRY_UUID_NAMESPACE)
    .update(String(name), 'utf8').digest();
  const bytes = Buffer.from(hash.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  log.debug("Leaving nameBasedUuid().");
  return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) +
         '-' + hex.slice(16, 20) + '-' + hex.slice(20);
}

// The value a seeded entry, or a row read back without one, is given: one
// answer in every process, from the realm and the store key alone.
function backfilledEntryUuid(realmId, key) {
  log.debug("Entering backfilledEntryUuid().");
  log.debug("Leaving backfilledEntryUuid().");
  return nameBasedUuid(String(realmId || realms.DEFAULT_ID) + '\n' +
                       String(key));
}

function entryUuidOf(stored) {
  log.debug("Entering entryUuidOf().");
  const value = stored && stored.attributes &&
                (stored.attributes.entryuuid || [])[0];
  log.debug("Leaving entryUuidOf().");
  return value ? String(value).toLowerCase() : '';
}

// ---------------------------------------------------------------------------
// TWO PROCESSES THAT CREATE ONE PERSON AT ONCE (2026-09-14).
//
// `putEntry()` gives a door-created entry a random UUID, and a request worker
// knows only its own store until replication reaches it. So two workers that
// create the same person inside one replication interval — two first sign-ins
// by one person, a SCIM create racing an auto-create — each assign a value,
// each issue tokens whose `sub` carries it, and each write the entry; the
// store keeps the LAST row and the other value names nobody. Every token the
// losing worker issued then fails at UserInfo, refuses to refresh
// (`STS-OAUTH-0511`) and has its console row filed under nobody.
//
// **THE LOSING VALUE IS KEPT AS AN ALIAS**, on `stsEntryUuidAlias`, and both
// values resolve to the entry. Which is primary is decided by the values
// alone — the lower one — so every process that sees both rows reaches the
// same entry in whatever order they arrive, and writes it back once; when
// the rows it then receives already carry that answer, nothing is written.
//
// **ONLY FOR TWO CREATES, NOT FOR A RE-CREATE.** A person deleted and created
// again is a NEW subject, which is the whole point of `entryUUID` — and a
// replication page that coalesced the delete away would look like this race.
// The two are told apart by the creation instants: a race is two creations
// within `CREATE_RACE_WINDOW_S` of each other, and a re-create is later than
// the entry it replaced by at least however long that person existed.
// `mergeCreateRace()` and `applyEntry()` below are the whole of it.
// ---------------------------------------------------------------------------
const ENTRY_UUID_ALIAS = 'stsentryuuidalias';
const CREATE_RACE_WINDOW_S = 60;

function entryUuidAliasesOf(stored) {
  log.debug("Entering entryUuidAliasesOf().");
  const values = (stored && stored.attributes &&
                  stored.attributes[ENTRY_UUID_ALIAS]) || [];
  log.debug("Leaving entryUuidAliasesOf().");
  return values.map(function (one) {
    return String(one).toLowerCase();
  });
}

// Seconds since the epoch of a generalized time this file wrote, or NaN.
function generalizedTimeSeconds(text) {
  log.debug("Entering generalizedTimeSeconds().");
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(
    String(text || ''));
  log.debug("Leaving generalizedTimeSeconds().");
  return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) / 1000
           : NaN;
}

// What the entry should say after `incoming` replaced `local` at one key:
// `{ uuid, aliases }`, or null when there is nothing to reconcile. Pure, so
// the rule can be asked without a store.
function mergeCreateRace(local, incoming) {
  log.debug("Entering mergeCreateRace().");
  const mine = entryUuidOf(local);
  const theirs = entryUuidOf(incoming);
  if (!mine || !theirs) {
    log.debug("Leaving mergeCreateRace(). A side has no UUID.");
    return null;
  }
  const aliases = {};
  entryUuidAliasesOf(local).concat(entryUuidAliasesOf(incoming))
    .forEach(function (one) {
      aliases[one] = true;
    });
  let uuid = theirs;
  if (mine !== theirs && !aliases[mine] && !aliases[theirs]) {
    const apart = Math.abs(generalizedTimeSeconds(local.createdAt) -
                           generalizedTimeSeconds(incoming.createdAt));
    if (!(apart <= CREATE_RACE_WINDOW_S)) {
      log.debug("Leaving mergeCreateRace(). A re-create, not a race.");
      return null;
    }
    uuid = mine < theirs ? mine : theirs;
    aliases[mine] = true;
    aliases[theirs] = true;
  } else if (mine !== theirs) {
    // One side already carries the other as an alias: the primary that is
    // not an alias of anything wins.
    uuid = aliases[theirs] ? mine : theirs;
    aliases[mine] = true;
    aliases[theirs] = true;
  }
  delete aliases[uuid];
  const list = Object.keys(aliases).sort();
  const unchanged = uuid === theirs &&
    list.join(',') === entryUuidAliasesOf(incoming).sort().join(',');
  log.debug("Leaving mergeCreateRace(). " +
            (unchanged ? 'Nothing to change.' : 'Reconciled.'));
  return unchanged ? null : { uuid: uuid, aliases: list };
}

// ---------------------------------------------------------------------------
// ENTRY BY UUID, AND WHY THE INDEX VALIDATES RATHER THAN BEING KEPT IN STEP.
//
// A token's `sub` is looked up on every token record, every console row and
// every refresh, so a walk per lookup is the quadratic the username index was
// written to remove. Unlike a name a UUID is never changed by a caller — so a
// hit is checked against the store (is that entry still under that key, and
// does it still carry that value?) and a miss or a stale hit rebuilds once per
// directory version. A writer nobody hooked therefore costs a rebuild and can
// never cost a wrong answer, which is the username index's bargain; and a
// lookup for a UUID this directory never issued — a foreign partner's `sub`, a
// credential's random subject — rebuilds at most once per write rather than
// once per lookup.
// ---------------------------------------------------------------------------
const uuidIndexes = realms.keyed(function () {
  return { index: null, version: -1 };
});

// ---------------------------------------------------------------------------
// A RESOURCE ID AND A DN, BOTH WAYS (2026-09-14). SCIM's `id` was the entry's
// DN, so a rename gave the same person a new id — which RFC 7643 section 3.1
// says an id must never do ("MUST NOT be reassigned"). It is the entry's
// `entryUUID` now. A DN handed in still resolves, for every caller that is not
// SCIM and for a client that stored an id before the change; a dangling DN
// (a member whose entry is gone) has no UUID and is reported as itself.
// ---------------------------------------------------------------------------
function dnForResourceId(id) {
  log.debug("Entering dnForResourceId().");
  const text = String(id == null ? '' : id).trim();
  if (/^urn:uuid:/i.test(text) || UUID_SHAPED.test(text)) {
    const found = entryByUuid(text);
    log.debug("Leaving dnForResourceId(). " + (found ? 'A UUID.' : 'Nobody.'));
    return found ? found.dn : text;
  }
  log.debug("Leaving dnForResourceId(). A DN.");
  return text;
}

function resourceIdOfDn(dn) {
  log.debug("Entering resourceIdOfDn().");
  const value = entryUuidOf(getEntry(String(dn || '')));
  log.debug("Leaving resourceIdOfDn().");
  return value || String(dn || '');
}

function entryByUuid(uuid) {
  log.debug("Entering entryByUuid().");
  const wanted = String(uuid || '').trim().toLowerCase()
    .replace(/^urn:uuid:/, '');
  if (!UUID_SHAPED.test(wanted)) {
    log.debug("Leaving entryByUuid(). Not a UUID.");
    return null;
  }
  const cache = uuidIndexes();
  const lookup = function () {
    const key = cache.index ? cache.index.get(wanted) : null;
    const stored = key ? entries.get(key) : null;
    return stored && (entryUuidOf(stored) === wanted ||
                      entryUuidAliasesOf(stored).indexOf(wanted) >= 0)
      ? stored : null;
  };
  let found = lookup();
  if (!found && cache.version !== directoryVersion) {
    const index = new Map();
    eachEntryInRealm(function (entry, key) {
      const value = entryUuidOf(entry);
      if (value && !index.has(value)) {
        index.set(value, key);
      }
    });
    // An alias second, so a primary value always wins the slot.
    eachEntryInRealm(function (entry, key) {
      entryUuidAliasesOf(entry).forEach(function (alias) {
        if (!index.has(alias)) {
          index.set(alias, key);
        }
      });
    });
    cache.index = index;
    cache.version = directoryVersion;
    found = lookup();
  }
  log.debug("Leaving entryByUuid(). " + (found ? found.dn : 'None.'));
  return found;
}

// Put an entry in the store. `attributes` is a plain object whose values may be
// a string or an array; the operational attributes are added here so that every
// entry has them however it was created.
function putEntry(dn, attributes, options) {
  log.debug('Entering putEntry(). dn=' + dn);
  const opts = options || {};
  const now = generalizedTime();
  const stored = { dn: String(dn), attributes: {}, createdAt: now,
                   modifiedAt: now };
  Object.keys(attributes || {}).forEach(function (name) {
    stored.attributes[String(name).toLowerCase()] = valuesOf(attributes[name]);
  });
  stored.attributes.createtimestamp = [now];
  stored.attributes.modifytimestamp = [now];
  if (opts.origin) stored.origin = String(opts.origin);
  // BOTH READ BEFORE THE WRITE, and they have to be: afterwards there is no way
  // to tell a create from an overwrite, and `directoryVersion` has moved on so
  // "was the index current a moment ago" is no longer a question the cache can
  // answer about itself. See noteUsernameIndexPut().
  const usernameIndexWasCurrent = usernameIndexIsCurrent();
  const groupIndexWasCurrent = groupIndexIsCurrent();
  // The names the entry at this DN answered to BEFORE this write, so that an
  // overwrite can take out the ones it no longer answers to. Read here because
  // afterwards the old attributes are gone. Empty for a create.
  const previous = entries.get(normalizeDn(dn));
  const hadNames = previous ? usernameKeysOf(previous) : [];
  // THE ENTRY'S OWN, CARRIED, NEVER THE CALLER'S — see `entryUUID` above. A
  // writer that rebuilt the attribute set from a copy of the entry may well be
  // handing one back, and one that did not is handing none; neither decides.
  //
  // **AND AN ENTRY A SIGN-IN CREATED ON A CLUSTERED NODE (2026-09-14, #46)**
  // takes the seed's deterministic value too — rcbj's choice, narrowed to the
  // one case that needs it. `autoCreateUser()` runs synchronously inside every
  // protocol's credential check, so two nodes seeing a name's first sign-in at
  // once both create `uid=<name>,ou=users` and cannot claim it first; with a
  // random value each, the directory merge keeps one entry and the other
  // node's tokens carry a `sub` naming nobody. With the value derived from the
  // realm and the DN both nodes create the SAME entry, and the merge makes them
  // one. The cost is the one the rule above was written against — a person
  // deleted and signing in again under the same name gets the same subject —
  // and it is taken only where two processes can race (a cluster, or a
  // dispatched pool): auto-create is development mode's (`mode.autoCreates()`),
  // and a single process keeps random values.
  stored.attributes.entryuuid = [entryUuidOf(previous) ||
    (stored.origin === 'seed' || (stored.origin === 'authentication' &&
                                  clusteredNode())
      ? backfilledEntryUuid(realms.currentId(), normalizeDn(dn))
      : crypto.randomUUID())];
  // And its aliases, the same way: the entry's, never the caller's.
  delete stored.attributes[ENTRY_UUID_ALIAS];
  if (entryUuidAliasesOf(previous).length) {
    stored.attributes[ENTRY_UUID_ALIAS] = entryUuidAliasesOf(previous);
  }
  entries.set(normalizeDn(dn), stored);
  touchDirectory(stored.dn);
  noteUsernameIndexPut(stored, hadNames, usernameIndexWasCurrent);
  noteGroupIndexPut(stored, groupIndexWasCurrent);
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
  log.debug("Entering matchable().");
  const out = {};
  Object.keys(stored.attributes).forEach(function (name) {
    out[name] = stored.attributes[name].slice(0);
    // A filter naming the TYPE matches a value stored under its `;binary`
    // spelling — see `withoutBinaryOption()`.
    const type = withoutBinaryOption(name);
    if (type !== name && !out[type]) {
      out[type] = stored.attributes[name].slice(0);
    }
  });
  out.entrydn = [stored.dn];
  log.debug("Leaving matchable().");
  return out;
}

// The entry as ldapjs wants it on the wire, honouring the requested attribute
// list. An empty list means "all user attributes", which per RFC 4511 section
// 4.5.1.8 does NOT include the operational ones — so createTimestamp and
// modifyTimestamp come back only when they were asked for by name. That
// distinction is one of the commonest surprises in LDAP and is worth
// reproducing rather than smoothing over.
const OPERATIONAL = ['createtimestamp', 'modifytimestamp', 'entrydn',
                     'entryuuid', ENTRY_UUID_ALIAS];

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
    const type = withoutBinaryOption(name);
    // RFC 4522 sections 3 and 5: either spelling asks for the attribute, and
    // an attribute stored in binary form is RETURNED in it either way.
    const askedFor = wanted.indexOf(name) !== -1 ||
      (type !== name && (wanted.indexOf(type) !== -1 ||
                         wanted.indexOf(type + ';binary') !== -1));
    // A CREDENTIAL IS NOT SENT AT ALL IN PRODUCT MODE, asked for by name or not
    // (2026-09-12) — see *THE DIRECTORY'S READ AND BIND SECURITY*.
    if (withheldFromReaders(name)) {
      return;
    }
    if (askedFor || (all && !isOperational)) {
      // WITHHELD ON THE WIRE TOO (2026-09-12): a search is the one door onto a
      // Kerberos key that needs no page, and in development every bind
      // succeeds. The KDC reads the store and never a search result, so nothing
      // that needs the key is behind this.
      attributes[canonicalName(name)] =
        certEnrollment.withheldValues(name,
          krb5PersonKeys.withheldValues(name,
                                        stored.attributes[name].slice(0)));
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
// empty directory shows nothing and teaches nothing: the first search returns
// no entries and the reader cannot tell that from a filter they got wrong. What
// is here is the smallest tree that makes every operation the debugger offers
// demonstrable — two containers, three people, two groups, and one account that
// looks like the one a client would bind as.
// ---------------------------------------------------------------------------
function seed() {
  log.debug('Entering seed().');
  const dcValue = baseDn().split(',')[0].split('=')[1] || 'example';
  putEntry(baseDn(), {
    objectClass: ['top', 'domain', 'dcObject'],
    dc: dcValue,
    // The two sentences that describe development mode were true of every
    // directory this service built until product mode existed; in product
    // mode a bind is verified and nobody is created by authenticating, and a
    // description saying otherwise is the first thing an `ldapsearch` reads.
    description: mode.verifiesCredentials()
      ? 'The STS directory. A simple bind is verified against the entry\'s ' +
        'userPassword.'
      : 'The mock STS directory. Every bind succeeds; nothing here ' +
        'is a real account.'
  }, { origin: 'seed' });
  putEntry(usersDn(), {
    objectClass: ['top', 'organizationalUnit'],
    ou: 'users',
    description: mode.autoCreates()
      ? 'People. An entry appears here for anyone who authenticates ' +
        'to this service through any protocol.'
      : 'People, as provisioned — through the console, /admin-api, SCIM or ' +
        'an LDAP add. Authenticating creates nobody.'
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
      'ldapmodify of fedSigningCertificate here changes which signer the ' +
      'next assertion is verified against, and an ldapmodify of fedEnabled ' +
      'turns a partner on. It is the one store in this directory whose ' +
      'contents are a SECURITY DECISION rather than a record: everything ' +
      'else here is permissive by design, and a federation endpoint cannot ' +
      'be. federation/federation.js holds the schema; GET ' +
      '/admin/ldap/federations publishes it.'
  }, { origin: 'seed' });
  putEntry(policiesDn(), {
    objectClass: ['top', 'organizationalUnit'],
    ou: 'policies',
    description: 'XACML 3.0 policies. THIS CONTAINER IS THE POLICY ' +
      'REPOSITORY — an ldapmodify of xacmlPolicyDocument here changes what ' +
      'the PDP decides on the next request, and an ldapmodify of ' +
      'xacmlEnabled takes a policy out of the decision without deleting it. ' +
      'The entry holds the XACML XML AS AUTHORED and everything else on it ' +
      'is derived from that document at write time, so where the two ' +
      'disagree the document wins. xacml/xacml_store.js holds the schema.'
  }, { origin: 'seed' });
  putEntry(rolesDn(), {
    objectClass: ['top', 'organizationalUnit'],
    ou: 'roles',
    description: 'ROLES: the one thing here a user, a group AND an ' +
      'application can all be mapped into. An entry is named by the role and ' +
      'everything on it is MEMBERSHIP — who holds it. What a role is ' +
      'REQUIRED for is NOT here: that lives in appRequiredRole on the ' +
      'application entry that requires it, because it is a fact about the ' +
      'application. Six more roles exist and are in no container at all — ' +
      'EVERYBODY, ALL_AUTHENTICATED_USERS, ALL_UNAUTHENTICATED_USERS, ' +
      'ALL_APPLICATIONS, ALL_AUTHENTICATED_APPLICATIONS and ' +
      'ALL_UNAUTHENTICATED_APPLICATIONS are COMPUTED from the security ' +
      'context of the decision being made. common/roles.js holds the schema; ' +
      'GET /admin/roles publishes it.'
  }, { origin: 'seed' });
  // THE CONTAINER AND NOT THE PROFILE. The tree is structural and is seeded
  // in both modes; `cn=default` is written the first time an operator saves
  // it, and until then the built-in defaults are in force — see
  // `common/password_policy.js` for why a seeded profile would be the wrong
  // answer in every realm created after this one.
  putEntry(passwordPoliciesDn(), {
    objectClass: ['top', 'organizationalUnit'],
    ou: 'passwordPolicies',
    description: 'PASSWORD POLICY profiles, in the shape of ' +
      'draft-behera-ldap-password-policy (pwdPolicy, pwdMinLength, ' +
      'pwdInHistory) with this service\'s composition rules beside them. ' +
      'An ldapmodify here changes what the NEXT password set in this realm ' +
      'must look like, and nothing already stored. The profile is ' +
      'cn=default; while it is absent the built-in defaults are in force. ' +
      'ENFORCED IN PRODUCT MODE. common/password_policy.js holds the schema; ' +
      'GET /admin/policies publishes it.'
  }, { origin: 'seed' });
  putEntry(pepsDn(), {
    objectClass: ['top', 'organizationalUnit'],
    ou: 'peps',
    description: 'Remote XACML Policy Enforcement Points that have ' +
      'registered with this PDP. A ROW HERE IS A RECORD AND NOT A ' +
      'PERMISSION: a PEP that never registers can still pull ' +
      'GET /xacml/pep/policies and enforce, because a policy is a rule and a ' +
      'rule nobody can read is a rule nobody can check. What a row buys is a ' +
      'place on /admin/xacml/peps and an address for the change nudge. ' +
      'xacml/xacml_pep_registry.js holds the schema.'
  }, { origin: 'seed' });
  // STRUCTURAL, so not behind `mode.seedsDemoData()` below — and in the DEFAULT
  // realm only, because the truststore is the process's. See trustAnchorsDn().
  if (realms.currentId() === realms.DEFAULT_ID) {
    putEntry(trustAnchorsDn(), {
      objectClass: ['top', 'organizationalUnit'],
      ou: 'trustAnchors',
      description: 'The client-certificate TRUSTSTORE\'s runtime anchors — ' +
        'one stsTrustAnchor entry per CA certificate added at ' +
        '/admin/tls/trust or POST /admin-api/tls/trust/add, restored into ' +
        'every TLS listener at start and whenever another process changes ' +
        'this container. An entry here decides whose client certificate this ' +
        'service will VERIFY, so writing one is an administrative act. ' +
        'Anchors from tls.trustAnchorsFile are not stored here. ' +
        'tls/tls_server.js owns what an anchor is.'
    }, { origin: 'seed' });
  }
  putEntry(spiffeDn(), {
    objectClass: ['top', 'organizationalUnit'],
    ou: 'spiffe',
    description: 'The SPIFFE trust domain this service is the issuing ' +
      'authority for. Two containers beneath: entries (registration entries, ' +
      'which decide what gets issued) and agents (what has attested). ' +
      'spiffe_registry.js holds the schema; GET /admin/ldap/spiffe publishes ' +
      'it.'
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
  // -------------------------------------------------------------------------
  // EVERYTHING BELOW THE CONTAINERS IS DEMONSTRATION DATA, AND PRODUCT MODE
  // SEEDS NONE OF IT (2026-09-12).
  //
  // The bind account, three people with invented titles — carol's
  // `employeeType: admin` among them, which the seeded XACML policy reads — and
  // two groups: a debugger opened against an empty directory teaches nothing,
  // which is the whole argument above. A PRODUCT directory is not a debugger:
  // an invented admin is an identity somebody else's policy may grant, and a
  // person nobody provisioned is a person nobody is accountable for.
  // `mode.seedsDemoData()` answers in the realm being seeded — at require time
  // that is the process's mode, and for a realm created later it is that
  // realm's own, since this runs inside `realms.run()`.
  //
  // What is left in product mode is the tree: the base and the containers
  // above, which every door that provisions somebody writes UNDER. An `ldapadd`
  // needs its parent, and a directory without `ou=users` is one nobody can
  // put a person in.
  // -------------------------------------------------------------------------
  const demo = mode.seedsDemoData();
  if (demo) {
    putEntry('cn=admin,' + baseDn(), {
      objectClass: ['top', 'person', 'organizationalRole'],
      cn: 'admin',
      sn: 'Administrator',
      description: 'A bind account. So is every other DN in the universe: ' +
        'this server accepts any bind except the password "invalid".'
    }, { origin: 'seed' });
    // `employeeType` IS HERE BECAUSE THE SEEDED XACML POLICY READS IT. The two
    // seeds have to agree or neither demonstrates anything: a policy that
    // grants on `employeeType=staff` against a directory whose people have no
    // employeeType answers Deny for everybody, which looks exactly like a
    // broken PDP. Carol is the admin because she is the Directory
    // Administrator, which is the one of the three titles that already meant
    // it.
    [
      { uid: 'alice', cn: 'Alice Anderson', sn: 'Anderson', given: 'Alice',
        title: 'Principal Engineer', employeeType: 'staff' },
      { uid: 'bob', cn: 'Bob Brown', sn: 'Brown', given: 'Bob',
        title: 'Support Analyst', employeeType: 'staff' },
      { uid: 'carol', cn: 'Carol Carter', sn: 'Carter', given: 'Carol',
        title: 'Directory Administrator', employeeType: 'admin' }
    ].forEach(function (person) {
      putEntry('uid=' + person.uid + ',' + usersDn(), {
        objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
        uid: person.uid,
        cn: person.cn,
        sn: person.sn,
        givenName: person.given,
        displayName: person.cn,
        title: person.title,
        employeeType: person.employeeType,
        mail: person.uid + '@sts.example',
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
      description: 'A second group, so a search for groups returns more than ' +
                   'one.',
      member: ['uid=carol,' + usersDn()]
    }, { origin: 'seed' });
  }
  // -------------------------------------------------------------------------
  // THE REMOTE PEP'S IDENTITY, AND THE GROUP THAT GRANTS IT ANYTHING
  // (2026-09-06).
  //
  // A remote XACML Policy Enforcement Point authenticates with a CLIENT
  // CERTIFICATE, and this service resolves that certificate to a directory
  // entry exactly as it resolves one arriving on 8443 or 636: by the subject
  // DN, through `locateEntry()`. So the entry below is what a certificate for
  // `CN=remote-pep-1` lands on, and the group beneath it is what turns that
  // identity into a PERMISSION.
  //
  // **THE TWO ARE SEPARATE ON PURPOSE AND THE SEPARATION IS THE FEATURE.** The
  // certificate says WHO — a chain this service verified against an anchor in
  // its own truststore — and the group says WHETHER THEY MAY. A PEP that
  // presents a perfectly valid certificate for some other common name resolves
  // to some other entry, holds no REMOTE_PEPS role, and is refused at
  // `/xacml/pep/*` while being fully authenticated. That is the case worth
  // being able to demonstrate, and it is unreachable if membership is granted
  // by the act of connecting.
  //
  // SEEDED RATHER THAN CREATED ON DEMAND, because a gate whose grant appears
  // the moment somebody knocks is not a gate. The DN is predictable —
  // `tests/tools/pep-credential.js` mints `CN=remote-pep-1` by default and
  // `certificateIdentity()` files it here — so the ordinary path works out of
  // the box, and a deployment using a different common name adds its own
  // member to this group, which is one line on /admin/ldap/directory.
  //
  // **THE GROUP IS NAMED BY `roles.remotePepGroup`, AND UNTIL 2026-09-12 THIS
  // WROTE THE LITERAL `cn=remote-peps`** while `common/roles.js` read the
  // setting — so a deployment that renamed the group got a gate reading a
  // group that was never seeded, beside a seeded group granting nothing. The
  // setting is what is seeded now, and an empty one (NOBODY holds the role)
  // seeds no group at all. Its default is the old literal.
  //
  // **IN PRODUCT MODE THE IDENTITY IS NOT SEEDED AND THE GROUP IS EMPTY.**
  // `cn=remote-pep-1` is a privileged identity whose name is predictable and
  // printed in this repository; anybody whose certificate a trust anchor here
  // verifies with that common name would be admitted to the documents this
  // service enforces its own access with. The empty group stays, so admitting
  // a real enforcement point is one member added — the same act a deployment
  // with a different common name always had to perform.
  const remotePepGroup = String(config.value('roles.remotePepGroup') ||
                                '').trim();
  const remotePepMembers = [];
  if (demo) {
    remotePepMembers.push('cn=remote-pep-1,' + usersDn());
    putEntry('cn=remote-pep-1,' + usersDn(), {
      objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
      cn: 'remote-pep-1',
      sn: 'remote-pep-1',
      displayName: 'Remote XACML PEP #1',
      description: 'THE IDENTITY OF A REMOTE XACML POLICY ENFORCEMENT POINT, ' +
                   'not a person. A client certificate whose subject common ' +
                   'name is "remote-pep-1" resolves to this entry, and its ' +
                   'membership of cn=remote-peps below is what lets it reach ' +
                   '/xacml/pep/register, /xacml/pep/policies and ' +
                   '/xacml/pep/heartbeat. Seeded, and authenticated by ' +
                   'nothing until a certificate arrives.'
    }, { origin: 'seed' });
  }
  if (remotePepGroup && nameUsableInDn(remotePepGroup)) {
    putEntry(groupDnFor(remotePepGroup), Object.assign({
      objectClass: ['top', 'groupOfNames'],
      cn: remotePepGroup,
      description: 'Members hold the built-in REMOTE_PEPS role, which is ' +
                   'what the three /xacml/pep endpoints require. The group ' +
                   'is named by roles.remotePepGroup; emptying it closes ' +
                   'those endpoints to everybody, and adding a member is how ' +
                   'a second enforcement point is admitted.'
    }, remotePepMembers.length ? { member: remotePepMembers } : {}),
    { origin: 'seed' });
  } else if (remotePepGroup) {
    log.warn(errorCodes.tag('STS-LDAP-0041') +
             'ldap: roles.remotePepGroup is "' + remotePepGroup + '", which ' +
             'carries DN syntax, so no group was seeded for it.');
  }
  // -------------------------------------------------------------------------
  // AND THE SAME PAIR FOR THE XACML SURFACE PROPER.
  //
  // **A SECOND IDENTITY AND A SECOND GROUP RATHER THAN A SECOND MEMBER OF THE
  // PAIR ABOVE**, and that is the whole reason these four entries exist rather
  // than two. `GET /xacml`, `POST /xacml/pdp`, `GET /xacml/policies` and
  // `GET /xacml/protected` require `XACML_USER`; `/xacml/pep/*` requires
  // `REMOTE_PEPS`, and those endpoints hand out the documents this service
  // enforces its own access with. One group granting both would make admitting
  // a caller to the demonstration surface silently admit it to those, which is
  // exactly the case `common/roles.js` keeps the two roles apart to prevent —
  // and it is the case somebody tidying this file will be tempted to collapse.
  //
  // Seeded for the reason the pair above is: a gate whose grant appears the
  // moment somebody knocks is not a gate, and the DN is predictable, so
  // `tests/tools/pep-credential.js --subject="CN=xacml-user-1,…"` produces a
  // certificate that lands here with nothing else configured. The `=` is
  // load-bearing: that tool splits each argument on the first one and reports
  // a space-separated value as an unknown option.
  //
  // **A PERSON GOES IN THE GROUP, NOT IN A ROLE ENTRY.** `XACML_USER` is
  // computed rather than stored, so granting it to `alice` is adding
  // `uid=alice` to `cn=xacml-users` below — one line on
  // /admin/ldap/directory or one `ldapmodify` — and it takes effect on the
  // very next request, because membership is resolved at decision time.
  //
  // Named by `roles.xacmlUserGroup` and seeded without its identity in product
  // mode, for the two reasons the pair above gives.
  // -------------------------------------------------------------------------
  const xacmlUserGroup = String(config.value('roles.xacmlUserGroup') ||
                                '').trim();
  const xacmlUserMembers = [];
  if (demo) {
    xacmlUserMembers.push('cn=xacml-user-1,' + usersDn());
    putEntry('cn=xacml-user-1,' + usersDn(), {
      objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
      cn: 'xacml-user-1',
      sn: 'xacml-user-1',
      displayName: 'XACML surface caller #1',
      description: 'THE IDENTITY OF A CALLER OF THE XACML ENDPOINTS, which ' +
                   'is usually another service rather than a person. A ' +
                   'client certificate whose subject common name is ' +
                   '"xacml-user-1" resolves to this entry, and its ' +
                   'membership of cn=xacml-users below is what lets it reach ' +
                   'GET /xacml, POST /xacml/pdp, GET /xacml/policies and GET ' +
                   '/xacml/protected. It is NOT a member of cn=remote-peps ' +
                   'and must not be made one: those three endpoints publish ' +
                   'the documents this service enforces its own access with. ' +
                   'Seeded, and authenticated by nothing until a certificate ' +
                   'arrives.'
    }, { origin: 'seed' });
  }
  if (xacmlUserGroup && nameUsableInDn(xacmlUserGroup)) {
    putEntry(groupDnFor(xacmlUserGroup), Object.assign({
      objectClass: ['top', 'groupOfNames'],
      cn: xacmlUserGroup,
      description: 'Members hold the built-in XACML_USER role, which is what ' +
                   'the four XACML endpoints proper require — GET /xacml, ' +
                   'POST /xacml/pdp, GET /xacml/policies and GET ' +
                   '/xacml/protected. The group is named by ' +
                   'roles.xacmlUserGroup; emptying it closes those four ' +
                   'endpoints to everybody, and adding a member — a person, ' +
                   'or the DN a client certificate resolves to — is how a ' +
                   'caller is admitted. It is deliberately NOT ' +
                   'cn=remote-peps: that group reaches /xacml/pep/*, which ' +
                   'publishes the documents this service enforces its own ' +
                   'access with.'
    }, xacmlUserMembers.length ? { member: xacmlUserMembers } : {}),
    { origin: 'seed' });
  } else if (xacmlUserGroup) {
    log.warn(errorCodes.tag('STS-LDAP-0041') +
             'ldap: roles.xacmlUserGroup is "' + xacmlUserGroup + '", which ' +
             'carries DN syntax, so no group was seeded for it.');
  }
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
    // AND THE APPLICATIONS THAT ARE THIS PROCESS, filtered to the ones a REALM
    // needs — which is the user portal's client and nothing else (2026-09-06).
    // `/portal` is a relying party of this service's own authorization server
    // and reads the AMBIENT realm's session, so a realm without this entry has
    // a portal that cannot sign anybody in; the console's client is the
    // default realm's alone, because its gate accepts that realm's session
    // wherever it is reached. `applications.js`'s rows carry `realmScope` and
    // argue all three answers.
    //
    // It is INSIDE the `realms.run()` because the registry writes through the
    // directory slot, which resolves the container from the ambient realm —
    // the same reason `seed()` is in here.
    applications.seedInternalApplications({ scope: 'every' });
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
  // -------------------------------------------------------------------------
  // ONE ENTRY ANOTHER PROCESS WROTE (2026-09-06). The cross-process
  // coordination layer hands this a row it read out of `sts_ldap_entries` and
  // this puts it where a local write would have put it.
  //
  // **IT GOES THROUGH THE SAME STORE AND THE SAME `touchDirectory()` AS EVERY
  // OTHER WRITE**, which is what keeps the reverse group index correct for
  // entries this process never wrote. That index is the reason
  // `touchDirectory()` exists at all, and a replicated write that skipped it
  // would produce exactly the stale groups claim it was written to prevent.
  //
  // `persistence.js` suppresses its own journal around the call, so applying
  // somebody else's write does not make this process report it as its own and
  // write it straight back — which would be an infinite exchange between two
  // processes, each one's write waking the other.
  // -------------------------------------------------------------------------
  applyEntry: function (realmId, key, row) {
    log.debug('Entering applyEntry(). realmId=' + realmId + ', key=' + key);
    const store = entries.realmMap(realmId);
    const stored = {
      dn: String(row.dn),
      attributes: row.attributes || {},
      createdAt: row.createdAt || null,
      modifiedAt: row.modifiedAt || row.createdAt || null
    };
    if (row.origin) {
      stored.origin = String(row.origin);
    }
    // A row written before `entryUUID` existed: every process computes the same
    // value from the realm and the key, so none has to write it back first.
    if (!entryUuidOf(stored)) {
      stored.attributes.entryuuid = [backfilledEntryUuid(realmId, key)];
    }
    // TWO CREATES OF ONE ENTRY IN TWO PROCESSES — see `mergeCreateRace()`.
    // The row is applied AS STORED first, because the caller records what it
    // applied as what the store holds; the reconciliation is then this
    // process's OWN write, in a microtask — after the caller has recorded the
    // row and before any request can read the entry in between.
    const local = store.get(key);
    const reconcile = mergeCreateRace(local, stored);
    if (reconcile) {
      queueMicrotask(function () {
        realms.run(realms.get(realmId) || realms.DEFAULT_REALM, function () {
          if (entries.get(key) !== stored) {
            return;
          }
          stored.attributes.entryuuid = [reconcile.uuid];
          stored.attributes[ENTRY_UUID_ALIAS] = reconcile.aliases;
          stored.modifiedAt = generalizedTime();
          stored.attributes.modifytimestamp = [stored.modifiedAt];
          log.info('ldap: ' + stored.dn + ' was created in two processes ' +
                   'at once; it is ' + reconcile.uuid + ', and ' +
                   reconcile.aliases.join(', ') + ' is kept as an alias so ' +
                   'the tokens already issued under it still name this entry.');
          touchDirectory(stored.dn);
        });
      });
    }
    // ---------------------------------------------------------------------
    // THE INDEXES ARE KEPT HERE TOO, AND NOT KEEPING THEM WAS A QUADRATIC
    // (2026-09-08).
    //
    // `putEntry()` reads whether each index is current BEFORE it writes and
    // tells it what the entry gained AFTER, so an ordinary create costs O(1)
    // rather than a rebuild. This applier did neither: it wrote the entry and
    // called `touchDirectory()`, which moves `directoryVersion` — so every
    // entry replicated from another process left both indexes stale, and the
    // next lookup rebuilt them by walking the whole realm.
    //
    // In ONE process that never happens, which is why it was invisible: there
    // is nothing to replicate. With three request workers each create arrives
    // at the other two, so each of them rebuilt an index per create — the
    // measured shape exactly, a SCIM bulk load at 35ms per create at the
    // 1,500th entry and 98ms at the 5,000th, against 2.35ms flat in one
    // process.
    //
    // READ BEFORE THE WRITE, for the reason `usernameIndexIsCurrent()` states:
    // afterwards `directoryVersion` has moved and the cache can no longer
    // answer the question about itself.
    // ---------------------------------------------------------------------
    const usernameWasCurrent = usernameIndexIsCurrent();
    const groupWasCurrent = groupIndexIsCurrent();
    store.set(key, stored);
    // THE DN IS NAMED. `touchDirectory()` with no argument marks every listing
    // in this realm invalid and makes the next flush diff the whole directory;
    // this applier knows exactly which entry moved, and the entry it is being
    // told about is the one thing it can always name.
    touchDirectory(stored.dn);
    noteUsernameIndexRefresh(stored, usernameWasCurrent);
    noteGroupIndexPut(stored, groupWasCurrent);
    // AN ANCHOR ANOTHER PROCESS ADDED reaches this process's listeners here:
    // the entry is in the store now, and the truststore array is what a
    // handshake reads. See `tls_server.js`'s `reloadStoredAnchors()`.
    if (isTrustAnchorKey(realmId, key)) {
      reloadTrustAnchorsQuietly();
    }
    // AND THE IDENTITY REGISTER, for `replaceRealm()`'s reason one row at a
    // time: `/admin/users` reads a different store from this one, and a person
    // created in another process would otherwise be in the directory here and
    // absent from the page that lists people. Seeded entries are skipped on
    // the same argument made at length below.
    if (stored.origin !== 'seed') {
      realms.run(realms.get(realmId) || realms.DEFAULT_REALM, function () {
        if (!isPersonEntry(stored)) {
          return;
        }
        const uid = (stored.attributes.uid || [])[0];
        // ---------------------------------------------------------------
        // `created`, NOT `restored` (2026-09-08). Those are two different
        // provenances and this applier had been reporting the wrong one.
        //
        // `restored` means "this person was in a store when this service
        // started and nobody here saw how they got there" — which is exactly
        // what the STARTUP restore below reports, and is right there. THIS
        // function is the replication applier: the entry was written by a
        // DOOR, in another process, moments ago, in this run. The service
        // watched it happen; only this process did not.
        //
        // The consequence was visible on `/admin/users` and through the
        // management API: a person created through `POST
        // /admin-api/users/create` read back as `knownBy: "created"` on the
        // worker that made them and `"restored"` on the other two, so the
        // answer depended on which worker replied.
        // `sts_admin_api_operations` caught it — "the register should say
        // this entry is known because it was CREATED".
        //
        // `noteKnownIdentity()` never overwrites an existing record, so this
        // cannot downgrade somebody who has actually signed in here.
        // ---------------------------------------------------------------
        stats.noteKnownIdentity(uid || stored.dn, 'created');
      });
    }
    log.debug('Leaving applyEntry().');
  },

  // The same, for an entry another process DELETED. A separate function rather
  // than `applyEntry(…, null)` because "the entry is gone" and "the entry has
  // no attributes" are different states and one call could not say which.
  removeEntry: function (realmId, key) {
    log.debug('Entering removeEntry(). realmId=' + realmId + ', key=' + key);
    const store = entries.realmMap(realmId);
    const gone = store.delete(key);
    if (gone) {
      touchDirectory();
    }
    if (gone && isTrustAnchorKey(realmId, key)) {
      reloadTrustAnchorsQuietly();
    }
    log.debug('Leaving removeEntry(). ' + (gone ? 'Removed.' : 'It was not ' +
        'here.'));
  },

  // Every entry in one realm, keyed the way the store keys it, for the diff
  // that decides what to write.
  realmEntries: function (realmId) {
    log.debug("Entering realmEntries().");
    const out = [];
    entries.realmMap(realmId).forEach(function (entry, key) {
      out.push({ key: key, entry: entry });
    });
    log.debug("Leaving realmEntries().");
    return out;
  },

  // ---------------------------------------------------------------------
  // ONE ENTRY, BY THE KEY THE STORE IS WRITTEN UNDER (2026-09-08).
  //
  // `realmEntries()` above materialises a realm's whole directory, and
  // `persistence.js` called it on EVERY flush to build the snapshot it
  // diffed. That is fine debounced — a burst of writes coalesces into one
  // walk — and it is quadratic when every request forces its own flush,
  // which is exactly what a request-worker pool does: each request announces
  // its commit, so each create paid one walk of everything created before
  // it. Measured over a SCIM bulk load in dispatch mode: 65ms per create at
  // the five hundredth entry, 109ms at the four thousandth, against 2.35ms
  // flat in one process.
  //
  // So the journalled flush looks up the keys it already knows about instead
  // of walking to find them. Same rows written, same diff, no snapshot.
  // ---------------------------------------------------------------------
  entryAt: function (realmId, key) {
    log.debug("Entering entryAt().");
    log.debug("Leaving entryAt().");
    return entries.realmMap(realmId).get(key) || null;
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
      if (!entryUuidOf(stored)) {
        stored.attributes.entryuuid =
          [backfilledEntryUuid(realmId, normalizeDn(stored.dn))];
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

// ---------------------------------------------------------------------------
// THE SUBJECT RESOLVER (2026-09-14): `helpers.userFor()` asks it for a
// person's `sub`, and `admin_stats.js`'s `identityOf()` asks it who a `sub`
// names.
//
// A SLOT, AND RULE 3e's TEST ANSWERS YES BOTH WAYS ROUND. `helpers.js` is a
// leaf this module requires, so a require back would close the cycle rule 2
// exists for; and a require of this module from `helpers.js` would register
// every `/admin/ldap/*` route at #3 in the router, ahead of everything. Two
// functions, validated whole at the other end.
//
// Both answer in the AMBIENT realm, like every other lookup here: a realm's
// people have that realm's subjects and no other realm's.
// ---------------------------------------------------------------------------
function subjectForName(name) {
  log.debug('Entering subjectForName(). name=' + name);
  const key = stats.identityKeyOf(name);
  const located = key ? locateEntry(key) : null;
  const stored = located && located.stored;
  const uuid = stored && isPersonEntry(stored) ? entryUuidOf(stored) : '';
  log.debug('Leaving subjectForName(). ' + (uuid ? 'Found.' : 'Nobody.'));
  return uuid ? 'urn:uuid:' + uuid : '';
}

// The name the rest of this service files a person under: their `uid` where
// they have one, and otherwise the identifier their entry was created FROM —
// a certificate subject, a DID, a SPIFFE ID — which is what `autoCreateUser()`
// was handed as the identity key in the first place.
function nameForSubject(subject) {
  log.debug('Entering nameForSubject().');
  const stored = entryByUuid(subject);
  if (!stored || !isPersonEntry(stored)) {
    log.debug('Leaving nameForSubject(). Nobody.');
    return '';
  }
  const name = personNameOf(stored);
  log.debug('Leaving nameForSubject(). ' + name);
  return name;
}

// The name a person entry is filed under — see `nameForSubject()`.
function personNameOf(stored) {
  log.debug('Entering personNameOf().');
  const a = stored.attributes;
  const name = (a.uid || [])[0] || (a.x509subject || [])[0] ||
               (a.didsubject || [])[0] || (a.spiffesubject || [])[0] ||
               usernameOfEntry(stored);
  log.debug('Leaving personNameOf().');
  return String(name || '');
}

helpers.setSubjectResolver({ subjectFor: subjectForName,
                             nameFor: nameForSubject });

// An RFC 4514 DN split into its RDNs, leaf first. The split is on commas that
// are NOT escaped, because a value may legitimately contain one — `O=Example\,
// Ltd` is one RDN and not two — and splitting there would produce components
// that name nothing. Like normalizeDn() this honours escaping and does not
// parse attribute-value syntax; that is enough for the DNs this service and the
// certificates it is shown are written with.
function splitRdns(dn) {
  log.debug("Entering splitRdns().");
  log.debug("Leaving splitRdns().");
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
  log.debug("Entering rdnPairs().");
  log.debug("Leaving rdnPairs().");
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
// purpose: that one renders node's certificate object into a DN and belongs
// with the code that reads certificates, and this one is used wherever this
// directory builds a DN of its own. Sharing would mean one of the two modules
// requiring the other for a string function.
function escapeDnValue(value) {
  log.debug("Entering escapeDnValue().");
  const text = String(value == null ? '' : value);
  let out = text.replace(/([\\,+"<>;=])/g, '\\$1');
  if (out.indexOf('#') === 0) {
    out = '\\' + out;
  }
  log.debug("Leaving escapeDnValue().");
  return out.replace(/^ /, '\\ ').replace(/ $/, '\\ ');
}

function unescapeDnValue(value) {
  log.debug("Entering unescapeDnValue().");
  log.debug("Leaving unescapeDnValue().");
  return String(value == null ? '' : value).replace(/\\(.)/g, '$1');
}

// Append the values an attribute does not already have, and say whether
// anything changed. The caller uses the answer to decide whether
// modifyTimestamp moves: a timestamp that advanced on a reconnection that wrote
// nothing would make every handshake look like a write.
function addValues(stored, name, values) {
  log.debug('Entering addValues().');
  const key = String(name).toLowerCase();
  // Never an operational attribute this directory maintains — `entryUUID` is a
  // person's subject, and `certificatePlan()` turns whatever RDNs a certificate
  // carries into calls to this function.
  if (CLIENT_WRITTEN_OPERATIONAL.indexOf(key) !== -1) {
    log.debug('Leaving addValues(). An operational attribute.');
    return false;
  }
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

// And is it a DECENTRALIZED IDENTIFIER? A third shape of identity, arriving
// from the Decentralized Identity endpoints — an ldp_vc's `did:jwk:…` subject,
// whatever DID the OID4VP Verifier was shown, the one /did/generate mints. Like
// DN_SHAPED this is deliberately not shared with admin_stats.js's
// identical-looking test: that one decides whether to split an identity at an
// '@', this one decides where an entry goes, and one knob turning both would
// couple two decisions that only look alike.
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
  log.debug("Entering commonNameOf().");
  const pairs = splitRdns(dn).map(rdnPairs).reduce(function (a, b) {
    return a.concat(b);
  }, []);
  const cn =
      pairs.filter(function (pair) { return pair.attribute === 'cn'; })[0];
  log.debug("Leaving commonNameOf().");
  return cn ? unescapeDnValue(cn.value) : '';
}

// ---------------------------------------------------------------------------
// ONE ENTRY PER PERSON, WHATEVER PROTOCOL BROUGHT THEM — and the two functions
// below are the whole of how that is kept true.
//
// It was already true for most of this service and by accident rather than by
// design: identityOf() in admin_stats.js resolves a `urn:uuid:` subject to the
// entry's name (and strips the retired `urn:sts:user:` prefix) and the Kerberos
// realm, so `rcbj`, a token's subject and `rcbj@STS.MOCK` reach
// autoCreateUser() as one key and namePlan() builds one DN from it. Every
// name-shaped family — OAuth 2.0, OpenID Connect, WS-Federation, WS-Trust, both
// SAML profiles, Kerberos, SPNEGO, an LDAP bind — therefore landed on
// `uid=rcbj,ou=users` already.
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
// Case-insensitively, because the store already keys DNs lower-cased —
// `uid=RCBJ` and `uid=rcbj` were one entry before this function existed, and a
// lookup that was stricter than the store would report "no such person" about
// an entry the very next putEntry() would collide with.
//
// SCOPED TO ENTRIES DIRECTLY UNDER ou=users, and that is the same placement
// rule /admin/groups reports by and the one the add handler enforces. This
// directory is schemaless: a client can put a `person` objectClass on a group,
// so believing the class would fold a person onto a group. Placement is the
// rule that cannot be lied to.
// ---------------------------------------------------------------------------
function usernameOfEntry(stored) {
  log.debug("Entering usernameOfEntry().");
  const rdn = splitRdns(stored.dn)[0] || '';
  const pairs = rdnPairs(rdn);
  log.debug("Leaving usernameOfEntry().");
  return pairs.length ? unescapeDnValue(pairs[0].value) : '';
}

// THE ENTRY THAT ALREADY RECORDS THIS DECENTRALIZED IDENTIFIER, wherever it is
// and whatever it is named.
//
// It is found by what the entry RECORDED and never by rebuilding the digest,
// which is the rule locateEntry() already stated for itself and which now
// matters twice over: since a linked DID goes onto its owner's entry
// (didPlan()), the digest is not where it lives at all. A wallet that was
// issued a credential as `erin` and later presents it to the Verifier arrives
// with the DID alone and no link — and without this lookup that presentation
// would create the very second entry the link exists to avoid, for a person
// whose entry already names that identifier.
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
  // authentication, and the overwhelming majority of them are a returning
  // person whose entry is exactly where namePlan() put it.
  const direct = getEntry('uid=' + name + ',' + usersDn());
  if (direct) {
    log.debug('Leaving existingUserEntry().');
    return direct;
  }
  // AND THE FALL-THROUGH IS A LOOKUP RATHER THAN A WALK, which is the whole of
  // the username index beside the store: this branch is reached by EVERY
  // create — a person who is not here yet cannot be at the DN tried above — so
  // the walk it replaces made a create cost a pass over the whole directory.
  // The index answers the same question over the same pair of names, in the
  // same first-entry-wins order.
  const key = usernameIndexNow().get(wanted);
  const found = key ? (entries.get(key) || null) : null;
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
//     exists, the entry is created AT it, unchanged. It names an object here,
//     so putting it anywhere else would be inventing a second one.
//   * otherwise the subject's CN — or its leaf RDN where it has no CN — names
//     an entry under ou=users: `CN=alice,O=Example Corp,C=US` becomes
//     `cn=alice,ou=users,<base>`, and every other RDN of the subject goes on
//     that entry as an attribute rather than being dropped. Grafting the whole
//     subject under ou=users instead would need `o=example
//     corp,c=us,ou=users,<base>` to exist as entries, and a tree with holes in
//     it is worse than a shortened DN — this directory enforces "an add needs
//     its parent" and would be breaking its own rule to seed one.
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
// **PRECONDITION: `subject` AND `issuer` ARRIVE AS STRINGS.** This function
// does `String()` on both, and node's own `getPeerCertificate()` hands back
// NULL-PROTOTYPE OBJECTS of RDN types — on which `String()` does not produce a
// DN, it throws "Cannot convert object to primitive value". Every caller here
// has always satisfied that by putting them through `helpers.dnRfc4514()`
// first, so the requirement was real and written down nowhere; phase five's
// PEP registration met it twice, once per field. Written here rather than
// defended against inside, because the conversion is also what makes two
// spellings of one DN impossible: `dnRfc4514()` is the single spelling in this
// service and a fallback here would quietly become a second one.
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
  // `C=US,O=Example,CN=alice,emailAddress=alice@example.com` is the address,
  // and `emailAddress=alice@example.com,ou=users` is not how a directory names
  // a person. Where there is no CN the leaf is the best name there is and is
  // used as it stands. Either way the value is ESCAPED in the DN and stored
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
// get `dave`, `Mock` and `dave@sts.example`, one string three times over.
//
// The change is deliberate and it is not cosmetic: those three are attributes a
// credential asserts, so a directory that derived all of them from the login
// name made every issued credential say the login name back. `given_name:
// "dave"` is not a given name, and a wallet developer testing what their UI
// does with a person's name learned nothing from it. What the entry keeps from
// the login name is the two things that ARE the identity — the DN and the `uid`
// — which is also how a real directory looks: somebody's uid rarely is their
// name.
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
  log.debug('Leaving namePlan().' +
            (already ? ' Folding onto ' + already.dn + '.' : ''));
  // THE FIVE PERSONA ATTRIBUTES ARE INVENTED, AND PRODUCT MODE INVENTS NONE OF
  // THEM (2026-09-12). A `displayName` ending "(mock)", a surname out of a
  // persona table and an address at a domain nobody owns are exactly the
  // invented facts `mode.inventsClaimValues()` exists to keep off an entry a
  // relying party will read. The entry is still a person to an LDAP client —
  // its object classes and its `uid` are the identity, not an invention — and
  // `createUser()` already drops the same five for `invent: false`, so both
  // halves of that rule now agree about product mode too.
  const attributes = {
    objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
    uid: name
  };
  if (mode.inventsClaimValues()) {
    attributes.cn = persona.display;
    attributes.sn = persona.family;
    attributes.givenName = persona.given;
    attributes.displayName = persona.display + ' (mock)';
    attributes.mail = persona.email;
  }
  log.debug("Leaving namePlan().");
  return {
    dn: already ? already.dn : 'uid=' + name + ',' + usersDn(),
    attributes: attributes,
    merge: already ? { uid: name } : {}
  };
}

// ---------------------------------------------------------------------------
// WHERE A DECENTRALIZED IDENTIFIER'S ENTRY GOES, which is the second placement
// decision in this module with no obviously right answer — and it is the
// OPPOSITE problem from a certificate's.
//
// A certificate subject is already a DN and needs a PLACE. A DID is neither a
// DN nor a name: it is one long opaque string, and the two obvious things to do
// with it are both wrong in a way worth writing down.
//
//   * `uid=<the did>,ou=users` verbatim. Correct, and unusable: a did:jwk
//     carries a base64url-encoded JWK, so the DN runs to several hundred
//     characters and every page, every log line and every ldapsearch output
//     naming this person is mostly key material.
//   * A container of its own, `ou=dids`. Tidy, and it would put these people
//     outside the two sweeps that matter: populateVcAttributes() walks
//     ou=users, and /admin/groups reports membership from there. A DID subject
//     that no credential claim reaches is a DID subject this service cannot
//     issue a credential about, which is the one thing it exists to do.
//
// So the entry goes under ou=users with everybody else and is NAMED by a short,
// stable digest of the DID — `uid=did-<12 hex>` — with the identifier itself
// kept whole on the entry as `didSubject`. Twelve hex characters is 48 bits; at
// the few thousand entries maxEntries() allows, a collision is not a risk worth
// a longer name for.
//
// What that costs is one thing and it is worth saying plainly: THE UID IS NOT
// THE IDENTITY. Everywhere else here `uid` is what the person typed and what
// /admin/users files them under; on these entries it is a name this service
// made up. `didSubject` is the identity — locateEntry() finds the entry by it,
// and personaKeyOf() invents the person FROM it, so the startup sweep and the
// authentication path seed one invented person rather than two.
// ---------------------------------------------------------------------------
function didUid(did) {
  log.debug("Entering didUid().");
  log.debug("Leaving didUid().");
  return 'did-' + crypto.createHash('sha256').update(String(did), 'utf8')
    .digest('hex').slice(0, 12);
}

function didPlan(info) {
  log.debug('Entering didPlan().');
  const did = String(info.key || '').trim();
  // The method name — `jwk`, `web`, `key`. Kept because it is the one fact
  // about a DID that is readable without resolving it, so "which methods has
  // this service seen" becomes an ordinary filter on /ldap/directory rather
  // than a question nobody can ask.
  const method = (did.split(':')[1] || '').toLowerCase();
  const persona = vcClaims.personaFor(did);
  const uid = didUid(did);
  // The description says how this entry came to exist, and for a DID the
  // default — "authenticated through X" — would be the wrong sentence in both
  // halves: nobody typed a password, and at /did/generate nobody presented
  // anything at all. So this plan carries its own.
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
    log.debug('Leaving didPlan(). Linked to ' + linked + ' at ' + plan.dn +
              '.');
    return plan;
  }
  // NOT LINKED, so this identifier names its own entry — unless one already
  // records it. That happens on the ordinary path through the Decentralized
  // Identity endpoints: the DID was linked to a person when their credential
  // was ISSUED, and the wallet then presents it to the Verifier with nothing
  // saying whose it is. Rebuilding the digest there would file one identifier
  // in two places.
  const recorded = entryByDidSubject(did);
  const dn = recorded ? recorded.dn
                      : 'uid=' + escapeDnValue(uid) + ',' + usersDn();
  log.debug('Leaving didPlan(). ' +
            (recorded ? 'Already recorded at ' + dn + '.'
                                              : 'uid=' + uid + ' for ' +
                                                did.slice(0, 48)));
  // Nothing to merge onto an entry that already exists. Unlike a certificate,
  // which is reissued with a new serial and a new validity for the same person,
  // a DID presented a second time is byte-for-byte the DID that named this
  // entry in the first place.
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
  log.debug("Entering spiffeUid().");
  log.debug("Leaving spiffeUid().");
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
  log.debug('Leaving spiffePlan(). ' +
            (recorded ? 'Already recorded at ' + dn + '.'
                                                 : 'uid=' + uid + ' for ' +
                                                   id));
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
function applyFederatedAttributes(stored, info, how) {
  log.debug('Entering applyFederatedAttributes(). dn=' + (stored && stored.dn));
  const federated = info && info.federation;
  // WHETHER THE PARTNER'S VALUES MAY OVERWRITE WHAT THE ENTRY HOLDS
  // (2026-09-14): always when this sign-in created the entry, and on a
  // returning person only while `fedUpdateUserAttributes` is on. The three
  // facts about where the person came from are recorded either way — they are
  // about this sign-in, not claims about the person.
  const createdNow = !!(how && how.created);
  const updates = createdNow ||
                  !(federated && federated.updateAttributes === false);
  if (!stored || !federated) {
    log.debug('Leaving applyFederatedAttributes(). Not a federated sign-in.');
    return false;
  }
  let changed = false;
  // The three facts about WHERE they came from. Multi-valued and accumulated,
  // because one person can federate through two partners and the second must
  // not erase the first — the same reason `description` accumulates one line
  // per protocol.
  if (addValues(stored, 'federationRelationship',
                [String(federated.id || '')])) changed = true;
  if (federated.peer &&
      addValues(stored, 'federationIssuer',
                [String(federated.peer)])) changed = true;
  if (federated.subject &&
      addValues(stored, 'federationSubject',
                [String(federated.subject)])) changed = true;

  const attributes = updates ? (federated.attributes || {}) : {};
  if (!updates) {
    log.debug('applyFederatedAttributes(): fedUpdateUserAttributes is off on ' +
              federated.id + ' and this entry already existed, so the ' +
              'partner\'s attributes are not written.');
  }
  const written = [];
  Object.keys(attributes).forEach(function (name) {
    const values = (Array.isArray(attributes[name]) ? attributes[name] :
                    [attributes[name]])
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
        lower === 'entrydn' || lower === 'entryuuid' ||
        lower === ENTRY_UUID_ALIAS) {
      log.debug('applyFederatedAttributes(): not writing "' + name + '" — it ' +
                'names the entry rather than describing the person.');
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
    log.debug('Leaving applyFederatedAttributes(). It already said all of ' +
              'this.');
    return false;
  }
  stored.attributes.modifytimestamp = [now];
  log.info('ldap: ' + stored.dn + ' records a federated sign-in through ' +
           federated.id + (federated.peer ? ' (' + federated.peer + ')' : '') +
           '. ' +
           (written.length ? written.length + ' attribute(s) came from the ' +
                             'partner and OVERWROTE whatever was ' +
                             'there: ' + written.join(', ') + '.'
                           : 'The partner sent no attributes this directory ' +
                             'maps.') +
           (federated.unmapped && federated.unmapped.length
             ? ' ' + federated.unmapped.length + ' more were sent under ' +
               'names nothing maps and were NOT ' +
               'written: ' + federated.unmapped.join(', ') + '.'
             : ''));
  log.debug('Leaving applyFederatedAttributes(). The entry was updated.');
  return true;
}

function applyAuthenticationFactors(stored, info) {
  log.debug('Entering applyAuthenticationFactors(). dn=' +
            (stored && stored.dn));
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
           (amr.length ? amr.join(', ') : acr) + '; mfaAuthenticated is ' +
           flag + '.');
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
// an agent and re-registering an identity both restore issuance, and a SPIRE
// Server API that authenticates nobody makes the whole registry advisory.
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
      'an X509-SVID was issued for this identity after it was marked ' +
      'revoked, so it is being issued credentials again');
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
  if (text &&
      (stored.attributes.spiffecredentialstatusreason || [])[0] !== text) {
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
  // A SECURITY KEY WAS ENROLLED (2026-09-06). The entry is created exactly as
  // an authentication would create it — `autoCreateUser()` is the one door, so
  // the plan, the cap, the credential-claim sweep and the audit row are all the
  // same — and the DIFFERENCE is that nothing counts it as an authentication,
  // because nobody authenticated by enrolling a key. That distinction is
  // `admin_stats.js`'s to make and it makes it by not calling
  // `recordAuthentication()`; what arrives here is only the identity.
  //
  // Its own event rather than reusing `authentication` for exactly that reason:
  // the two differ in what they MEAN and not in what they write, and a shared
  // name would make the difference invisible the moment either side changes.
  if (event === 'enrolment') {
    const record = autoCreateUser(info);
    log.debug('Leaving observeIdentity(). A security key enrolment.');
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
    log.warn('ldap: an issuance was reported for "' + id + '", which is not ' +
             'a SPIFFE identity. Nothing was written — see the header for ' +
             'why this is refused rather than filed under certificatePlan().');
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
    log.debug('Leaving autoCreateUser(). That identity is a client, not a ' +
              'person.');
    return null;
  }
  // A SUBJECT THIS DIRECTORY COULD NOT RESOLVE IS NOBODY TO CREATE
  // (2026-09-14). `admin_stats.js`'s `identityOf()` turns a `urn:uuid:` it can
  // resolve into the person's name before it reaches here, so what arrives in
  // that shape is a subject naming nobody in this realm: another instance's, a
  // deleted person's, a credential's random one. Creating `uid=urn:uuid:…`
  // for it would be a phantom person named after a subject, holding a
  // DIFFERENT subject of its own.
  if (/^urn:uuid:/i.test(name) || UUID_SHAPED.test(name)) {
    log.info(errorCodes.tag('STS-LDAP-0091') +
             'ldap: not creating an entry for "' + name + '": it is a ' +
             'subject identifier naming nobody in this realm\'s directory, ' +
             'not a username.');
    log.debug('Leaving autoCreateUser(). An unresolved subject.');
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
  // AND THE PER-RELATIONSHIP SWITCH, which is the one place a federated sign-in
  // is treated differently from every other kind here. `ldap.autocreateUsers`
  // above is the service-wide answer; `fedAutocreateUsers` is one partner's,
  // and it exists because a federation partner is the one source of identities
  // this service does not control the volume of — a partner with ten thousand
  // people behind it would otherwise fill ou=users the first time somebody
  // pointed a load generator at it.
  //
  // **IT IS ASKED AFTER THE LOOKUP, WHERE IT WAS ASKED BEFORE (2026-09-14).**
  // Off used to mean "a session and no entry" and returned before anything
  // was looked up, so a person PROVISIONED ahead of time — by SCIM, the
  // pre-provisioned shape rcbj wants — was never folded onto and never had a
  // partner's attributes written. A session needs an entry to be the subject
  // of now, so off means exactly "do not CREATE one": an existing entry is
  // used and updated, and a missing one is left missing for
  // `authn.startSession()` to refuse.
  if (!existing && info.federation && info.federation.autocreate === false) {
    log.debug('Leaving autoCreateUser(). fedAutocreateUsers is off on ' +
              info.federation.id + ' and nobody was provisioned at ' + dn +
              ', so nothing is created.');
    return null;
  }
  // What the entry's description says about why it exists. A plan may state its
  // own — didPlan() does, because "authenticated through W3C DID Core" would be
  // the wrong sentence for an identifier nobody signed in with.
  // **AN ENROLMENT SAYS SO RATHER THAN SAYING "authenticated"** (2026-09-06).
  // A security key registered for somebody creates their entry through this
  // same function — one door, so the plan, the cap and the credential-claim
  // sweep are all the same — and the sentence it writes must not be the one a
  // sign-in writes. Nobody authenticated by enrolling a key; for a PASSWORDLESS
  // key the person may not have authenticated at all yet, and an entry claiming
  // they did would be this directory asserting the one thing the whole event
  // distinction exists to avoid.
  //
  // Same shape as didPlan()'s exception two lines up, and for the same reason:
  // "authenticated through W3C DID Core" is the wrong sentence for an
  // identifier nobody signed in with.
  // **THE FIRST CEREMONY IS BOTH, AND THE ENTRY ENDS UP SAYING BOTH.** A
  // `webauthn.create` that succeeds falls straight through to `startSession()`
  // — the person really did prove possession of the key and really is signed
  // in — so the sign-in writes its own `authenticated through WebAuthn` a few
  // lines later and `addValues()` accumulates the two. The sentence here is
  // therefore about the ENROLMENT alone and does not claim anything about a
  // session either way: what it must not do is say "authenticated", because
  // enrolment is also reachable WITHOUT a sign-in — an administrator
  // registering a key on somebody's behalf — and that is the case the separate
  // event exists for.
  const note = plan.note || (String(info.event || '') === 'enrolment'
    ? 'a security key was enrolled for them (' +
      String(info.protocol || 'WebAuthn') + ') — a credential being GIVEN ' +
      'rather than presented, which is a different act from signing in even ' +
      'when the same ceremony does both'
    : 'authenticated through ' +
      String(info.protocol || 'an unstated protocol'));
  if (existing) {
    // Already here. Record the protocol if it is one this entry has not seen —
    // which is what makes the entry say something a second sign-in did not
    // already say, without growing without bound — and, for a certificate, any
    // fact this one carries that the last one did not: a renewal is a new
    // serial and a new validity for the same person.
    let changed = addValues(existing, 'description', [note]);
    Object.keys(plan.merge).forEach(function (attribute) {
      if (plan.merge[attribute] &&
          addValues(existing, attribute, [String(plan.merge[attribute])])) {
        changed = true;
      }
    });
    // And whatever the credential claim set now wants that this entry does not
    // carry. It runs on a RETURNING person and not only on a new one, because
    // the selection can change between two sign-ins: somebody who ticks `title`
    // on /admin/vc gets the whole directory populated then (that page runs the
    // same sweep), and this is what covers the person who authenticates for the
    // first time after that but whose entry was created before it.
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
    if (applyFederatedAttributes(existing, info, { created: false })) {
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
    log.warn(errorCodes.tag('STS-LDAP-0007') +
             'ldap: not creating ' + dn + '; the directory holds its maximum ' +
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
  // Before the audit row below, so that the attributes it lists are the ones
  // the entry actually has. On a PASSWORDLESS WebAuthn sign-in this is what
  // says the single factor was a key rather than a password, on an entry that
  // exists because that sign-in was an authentication in its own right.
  applyAuthenticationFactors(created, info);
  // Last, for applyVcAttributes()'s sake: see the note on the returning-person
  // branch above. What a foreign identity provider asserted about somebody
  // beats what this service invented for them.
  applyFederatedAttributes(created, info, { created: true });
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
// (`DN_RESERVED` itself is declared near the top of this file, beside
// REFUSED_PASSWORD, since 2026-09-12: `seed()` runs at require time and now
// checks the two role-group names it seeds with this function, and a `const`
// declared down here does not exist yet when it does.)

function nameUsableInDn(name) {
  log.debug("Entering nameUsableInDn().");
  log.debug("Leaving nameUsableInDn().");
  return !DN_RESERVED.test(String(name == null ? '' : name));
}

// ---------------------------------------------------------------------------
// THE ATTRIBUTES A CALLER MAY PUT ON A PERSON, AND WHAT HAPPENS TO A NAME THAT
// IS NOT ONE (2026-09-06).
//
// `/admin/users/new` lets an operator TYPE a person's details instead of
// accepting the invented ones, and `POST /admin-api/users/create` takes the
// same values in an `attributes` object. Both arrive here, which is the whole
// reason this function is in this file rather than in the console: what a
// person in this directory HAS is a statement about this store.
//
// **THE LIST IS `vc_claims.js`'s CATALOGUE AND NOT A SECOND ONE.** That module
// already publishes every attribute a person here carries — it has to, because
// it invents values for them and /admin/vc chooses which ones a credential
// asserts — so `personField()` is asked rather than a regex written. A second
// list would be a form offering a field this function drops, which is the one
// failure a create form must not have: everything looks like it worked.
//
// **AN UNKNOWN NAME IS REFUSED AND NOT IGNORED**, which is the rule
// `common/validation.js` argues at length for repeated parameters and is
// sharper here. The console's form cannot produce one, so a caller sending
// `userPassword`, `oauthClientSecret` or `memberOf` is either testing what this
// door will take or has misspelt something — and silently dropping the value
// would answer "created" to a request that asked for something this did not
// do. A password is set through `credentials.setPassword()`, which hashes it;
// an attribute door that took `userPassword` verbatim would write one in the
// clear.
//
// **THE NAME COMES BACK IN THE CATALOGUE'S SPELLING.** The store lower-cases
// every attribute name on the way in, so the case does not decide anything —
// but `namePlan()`'s own attributes are canonically spelt, and merging
// `givenname` over `givenName` would produce an entry carrying both.
// ---------------------------------------------------------------------------
function personAttributesFrom(given) {
  log.debug('Entering personAttributesFrom().');
  const out = {};
  const unknown = [];
  const source = (given && typeof given === 'object') ? given : {};
  Object.keys(source).forEach(function (name) {
    const row = vcClaims.personField(name);
    if (!row) {
      unknown.push(String(name).slice(0, 64));
      return;
    }
    // valuesOf() is the store's own coercion, so a string, an array and a
    // number all land the way an LDAP add of the same thing would. Empty
    // strings are dropped rather than stored: a blank box on the form means
    // "no value", and an attribute present with an empty value is a different
    // and much more confusing thing to find in an ldapsearch.
    const values = valuesOf(source[name]).map(function (one) {
      return String(one).trim();
    }).filter(function (one) { return one !== ''; });
    if (!values.length) {
      return;
    }
    out[row.ldap] = values;
  });
  if (unknown.length) {
    log.debug('Leaving personAttributesFrom(). ' + unknown.length +
              ' unknown.');
    return coded('STS-LDAP-0047', { ok: false,
             errors: ['A person here does not have ' +
                      (unknown.length === 1 ? 'an attribute' : 'attributes') +
                      ' called ' + unknown.join(', ') + '. The attributes a ' +
                      'create may write are the catalogue on /admin/vc, ' +
                      'which /admin/users/new draws as its form and GET ' +
                      '/admin-api/users/new publishes. A PASSWORD IS NOT ONE ' +
                      'OF THEM: it is set through the `credential` option on ' +
                      'this same call, or by POST ' +
                      '/admin-api/users/set-password, so that it is hashed ' +
                      'rather than written down.'],
             unknown: unknown });
  }
  log.debug('Leaving personAttributesFrom(). ' + Object.keys(out).length +
            ' attribute(s).');
  return { ok: true, attributes: out };
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
// already keeps: /admin/users's form and POST /admin-api/users/create call
// this, so a form post and an API call are one act arriving by two routes and
// cannot drift into two readings of what creating a user means.
//
// Five things about it, and the last two arrived on 2026-09-06 with
// /admin/users/new — the screen on which an operator types a person's details
// rather than accepting the invented ones:
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
//   * IT TAKES THE ATTRIBUTES SOMEBODY TYPED, in `options.attributes`, checked
//     against `vc_claims.js`'s catalogue by `personAttributesFrom()` above. A
//     name that is not on it is REFUSED rather than dropped, and the argument
//     is at that function.
//   * `options.invent` SAYS WHETHER TO MAKE THE REST UP, and it defaults to
//     TRUE because that is what this function has always done — every caller
//     that predates the option gets exactly the behaviour it had. **What
//     `false` turns off is BOTH halves of the invention and that is easy to get
//     wrong**: `applyVcAttributes()` is the obvious one, and `namePlan()` is
//     the one that bites, because it puts a `cn`, `sn`, `givenName`,
//     `displayName` and `mail` on the entry before this function has looked at
//     anything. A create that skipped only the first would still have written
//     five invented facts about a person somebody was in the middle of
//     describing by hand — which is precisely the promise /admin/users/new
//     makes and would have silently broken. With `invent: false` the entry
//     carries its objectClasses, its `uid`, a description and NOTHING ELSE
//     except what was typed.
//
//     **IT IS NOT A PROMISE THAT THE ENTRY STAYS EMPTY.** `populateVcAttributes()`
//     — the sweep behind Populate on /admin/vc, and the one run when a realm is
//     created — fills every MISSING selected attribute on every person under
//     `ou=users`, and it does not know or care which of them were created by
//     hand. That is the right behaviour for the sweep (its whole job is that
//     the directory and an issued credential agree) and it means "no value
//     recorded" is a statement about this create rather than a permanent
//     property of the entry. /admin/users/new says so on the page.
// ---------------------------------------------------------------------------
function createUser(name, options) {
  log.debug('Entering createUser(). name=' + name);
  const opts = options || {};
  const wanted = String(name == null ? '' : name).trim();
  if (!wanted) {
    log.debug('Leaving createUser(). No name.');
    return coded('STS-LDAP-0042', { ok: false, errors: ['Which user? Send ' +
                                 '`username` with the name they will ' +
                                 'authenticate under — the same string that ' +
                                 'would appear in a token\'s `sub` and on ' +
                                 '/admin/users.'] });
  }
  if (DN_SHAPED.test(wanted)) {
    log.debug('Leaving createUser(). That is a DN.');
    return coded('STS-LDAP-0043', { ok: false, errors: ['"' + wanted + '" is ' +
                                 'a DN and not a username. An entry named by ' +
                                 'a distinguished name gets here by ' +
                                 'presenting a client certificate, where the ' +
                                 'DN is the identity; there is nothing to ' +
                                 'create one from by hand.'] });
  }
  // A SUBJECT IS NOT A USERNAME (2026-09-14). `urn:uuid:<entryUUID>` is what
  // a token's `sub` holds now, and a create under that string would put a
  // second person in the directory named after the first one's subject — one
  // whose own subject is a different UUID, so every lookup by either would
  // find the wrong one. A bare UUID is refused for the same reason.
  if (/^urn:uuid:/i.test(wanted) || UUID_SHAPED.test(wanted)) {
    log.debug('Leaving createUser(). That is a subject identifier.');
    return coded('STS-LDAP-0090', { ok: false, errors: ['"' + wanted + '" ' +
                                 'is a subject identifier and not a ' +
                                 'username. Every person here is given one — ' +
                                 'their entryUUID — and a token\'s sub is ' +
                                 'urn:uuid:<that value>, so a person named ' +
                                 'after one would be a second person ' +
                                 'answering to somebody else\'s ' +
                                 'subject.'] });
  }
  if (DID_SHAPED.test(wanted)) {
    log.debug('Leaving createUser(). That is a DID.');
    return coded('STS-LDAP-0044',
                 { ok: false, errors: ['"' + wanted.slice(0, 48) + '" ' +
                                 'is a decentralized identifier and not a ' +
                                 'username. A DID reaches this directory by ' +
                                 'being presented, and where this service ' +
                                 'knows whose it is the identifier goes onto ' +
                                 'that person\'s entry as didSubject.'] });
  }
  if (SPIFFE_SHAPED.test(wanted)) {
    log.debug('Leaving createUser(). That is a SPIFFE ID.');
    return coded('STS-LDAP-0045',
                 { ok: false, errors: ['"' + wanted.slice(0, 64) + '" ' +
                                 'is a SPIFFE identity and not a username. A ' +
                                 'workload identity reaches this directory ' +
                                 'by being PRESENTED — an X509-SVID over ' +
                                 'mutual TLS at the SPIRE Server API, an ' +
                                 'agent attesting, a JWT-SVID validated at ' +
                                 'the Workload API — and its entry is named ' +
                                 'by a digest with the identity on it as ' +
                                 'spiffeSubject. What you probably want ' +
                                 'instead is a REGISTRATION ENTRY, which is ' +
                                 'a different thing in a different ' +
                                 'container: /admin/spiffe/entries, POST ' +
                                 '/admin-api/spiffe/entries/create, or ' +
                                 'BatchCreateEntry.'] });
  }
  if (!nameUsableInDn(wanted)) {
    log.debug('Leaving createUser(). The name carries DN syntax.');
    return coded('STS-LDAP-0046', { ok: false, errors: ['"' + wanted + '" ' +
                                 'cannot be a username here: it carries a ' +
                                 'character RFC 4514 reserves in a DN (one ' +
                                 'of , = + < > # ; " \\), so the entry would ' +
                                 'be named something other than what was ' +
                                 'typed. An ldapadd can still create such an ' +
                                 'entry, with the escaping written out.'] });
  }
  const clash = existingUserEntry(wanted);
  if (clash) {
    log.debug('Leaving createUser(). That username is taken.');
    return coded('STS-LDAP-0005', { ok: false,
             errors: ['There is already a user called "' + wanted + '" here, ' +
                 'at ' +
                      clash.dn + '. One entry per person is the rule this ' +
                      'directory keeps at every door — whatever protocol ' +
                      'authenticated them, and whichever attribute their ' +
                      'entry happens to be named by.'],
             existing: { dn: clash.dn, origin: clash.origin || '' } });
  }
  if (totalEntries() >= maxEntries()) {
    log.debug('Leaving createUser(). The directory is full.');
    return coded('STS-LDAP-0007', { ok: false, errors: [
      'This directory holds its maximum of ' + maxEntries() + ' entries.'] });
  }
  // WHAT THE CALLER TYPED, before anything is written: a refusal here must
  // leave the directory exactly as it was, and putEntry() is not undoable.
  const supplied = personAttributesFrom(opts.attributes);
  if (!supplied.ok) {
    log.debug('Leaving createUser(). An attribute name is not a person\'s.');
    return supplied;
  }
  // A CEILING, in the shape `autocreateUsers()` is one: the caller may ask for
  // no invention, and product mode (`mode.inventsClaimValues()` false) is a
  // ceiling no caller can raise — SCIM calls this with the default `true`, and
  // that must not put a persona on a person provisioned into a product
  // directory.
  const invent = (opts.invent === undefined ? true : !!opts.invent) &&
    mode.inventsClaimValues();
  const plan = namePlan(wanted);
  // THE FIVE INVENTED ATTRIBUTES namePlan() ADDS, dropped when nothing is to be
  // invented. `objectClass` and `uid` are kept in both branches and are not on
  // that list: the object classes are what makes this entry a person to an LDAP
  // client, and the uid IS the username — an entry at `uid=alice,ou=users`
  // whose uid attribute was missing would be found by nothing that looks a
  // person up.
  const INVENTED_BY_PLAN = ['cn', 'sn', 'givenName', 'displayName', 'mail'];
  const base = {};
  Object.keys(plan.attributes).forEach(function (attribute) {
    if (!invent && INVENTED_BY_PLAN.indexOf(attribute) >= 0) {
      return;
    }
    base[attribute] = plan.attributes[attribute];
  });
  const note = String(opts.note || '').trim() ||
    'created by hand rather than by authenticating';
  // A TYPED `description` WINS OVER THE NOTE, and it is the one attribute where
  // the two could collide: `description` is in the catalogue (an operator may
  // want to say something about a person) and it is also where this function
  // records why the entry exists. Two values would be an entry answering the
  // question twice; the operator's own sentence is the more useful one, and
  // the audit row still records that this was a hand-made create.
  const attributes = Object.assign({}, base, supplied.attributes);
  if (!attributes.description) {
    attributes.description = [note];
  }
  const created = putEntry(plan.dn, attributes,
                           { origin: opts.origin || 'console' });
  // The same fill autoCreateUser() does, and for the same reason: the entry an
  // LDAP client reads and the credential a wallet is handed have to say the
  // same thing about this person from the moment the entry exists.
  //
  // SKIPPED WHEN NOTHING IS TO BE INVENTED. It is absent-only, so it would not
  // overwrite what was typed — but it would fill in every field the operator
  // deliberately left blank, which is the same lie by a slower route.
  if (invent) {
    applyVcAttributes(created, wanted);
  }
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
              // WHICH OF THEM SOMEBODY TYPED, and whether the rest were made
              // up. Recorded because it is the difference between a person
              // this service invented and a person an operator described, and
              // an audit row that said only "created" could not tell them
              // apart afterwards. The VALUES are not here: an audit log
              // carrying somebody's date of birth is a second copy of it in a
              // place nothing expects one.
              typed: Object.keys(supplied.attributes).join(', '),
              invented: invent,
              entriesNow: totalEntries(),
              note: 'created by hand through the console or the management ' +
                    'API, not by an LDAP client and not by an authentication' }
  });
  log.debug('Leaving createUser(). ' + created.dn + ' was created.');
  return { ok: true, dn: created.dn, username: wanted,
           typed: Object.keys(supplied.attributes),
           invented: invent,
           entry: { dn: created.dn, origin: created.origin || '',
                    attributes: created.attributes } };
}

// ---------------------------------------------------------------------------
// THE FACTS A CREDENTIAL NEEDS, INVENTED ONCE AND KEPT HERE.
//
// /admin/vc chooses which attributes an issued credential carries. Those
// attributes have to have VALUES, and this service authenticates nobody — there
// is no source of a real birthdate, and there had better not be. So
// vc_claims.js invents a consistent person per username and this function
// writes what is missing onto their entry.
//
// Three rules, and each of them is the answer to a way this could go wrong:
//
//   * ABSENT ONLY. An attribute the entry already carries is never touched.
//     That covers the seeded people (alice keeps `Alice Anderson`, and only
//     gains the attributes she had none of), a certificate's RDNs, and — the
//     one that matters most — anything an operator set through LDAP. A sweep
//     that overwrote `mail` after somebody had just ldapmodify'd it would be a
//     directory that argues with its own clients.
//   * ONE VALUE. These are single-valued facts; addValues() would happily
//     append a second `mail` on the next sweep if the first were ever edited,
//     and an entry that accumulated a birthdate per sign-in would be the
//     visible symptom of a bug nobody could locate.
//   * A NAME, NOT A DN, seeds the person. A TLS client certificate's identity
//     is a DN, and `uid` holding one would contradict the entry it sits on — so
//     the row that carries the username is skipped for those. Everything else
//     is invented from the DN string quite happily; it is only a seed.
// ---------------------------------------------------------------------------
function applyVcAttributes(stored, key) {
  log.debug('Entering applyVcAttributes(). dn=' + (stored && stored.dn));
  if (!stored) {
    log.debug('Leaving applyVcAttributes(). There is no entry.');
    return false;
  }
  // **EVERY VALUE THIS WRITES IS GENERATED**, so product mode writes none
  // (2026-09-12). This is the one function the startup sweep, a realm's
  // creation, Populate on /admin/vc, a SCIM create and a returning person's
  // sign-in all come through, which is why the refusal is here rather than at
  // those five callers. A credential then carries what the entry holds or
  // omits the claim — see `oid4vc/vc_claims.js`.
  if (!mode.inventsClaimValues()) {
    log.debug('Leaving applyVcAttributes(). This service invents no claim ' +
              'value in this mode.');
    return false;
  }
  const name = String(key == null ? '' : key).trim() ||
               commonNameOf(stored.dn) ||
               (stored.attributes.uid || [])[0] || stored.dn;
  const isDn = DN_SHAPED.test(name);
  const generated = vcClaims.generatedFor(name);
  const added = [];
  // Read before the first mutation — see usernameIndexIsCurrent().
  const usernameIndexWasCurrent = usernameIndexIsCurrent();
  const groupIndexWasCurrent = groupIndexIsCurrent();
  Object.keys(generated).forEach(function (attribute) {
    const have = stored.attributes[attribute] || [];
    if (have.length) {
      return;
    }
    if (isDn && attribute === 'uid') {
      // See the third rule: this entry is named by a certificate subject, and a
      // uid holding that subject would name the person something the DN does
      // not.
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
  // ---------------------------------------------------------------------
  // ONE `touchDirectory()` FOR ONE LOGICAL CHANGE, and it used to be one PER
  // ATTRIBUTE — nine of them for a person who arrived with nothing.
  //
  // That was not merely wasteful. `touchDirectory()` bumps `directoryVersion`,
  // and the username index beside the store is current only for the version it
  // was built at — so nine bumps immediately AFTER putEntry() had folded this
  // person in left the index stale before the very next create, which then
  // rebuilt it by walking the whole realm. **The quadratic the index was added
  // to remove survived here in full**, on the `invent: true` path only: a
  // create measured 0.63ms at the 500th person and 13.03ms at the 5,000th,
  // which is exactly what SCIM does, because `scim.js` calls createUser()
  // without `invent: false` while `/admin-api` sends it.
  //
  // The index is then told the entry has GAINED names rather than being left
  // to rebuild — which is sound here and nowhere else, because this function
  // fills attributes that are ABSENT and never replaces one. See
  // noteUsernameIndexRefresh().
  // ---------------------------------------------------------------------
  touchDirectory(stored.dn);
  noteUsernameIndexRefresh(stored, usernameIndexWasCurrent);
  noteGroupIndexPut(stored, groupIndexWasCurrent);
  log.info('ldap: ' + stored.dn + ' gained ' + added.join(', ') +
           ' so that an issued credential has something to assert.');
  log.debug('Leaving applyVcAttributes(). ' + added.length + ' attribute(s) ' +
      'added.');
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
  // DID-named entry the uid is a DIGEST of the identity rather than the
  // identity (see didPlan()), so seeding from it would invent a SECOND person
  // for somebody the authentication path had already invented one for — and the
  // two would disagree on every attribute the sweep filled in.
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
// objectClass of person would be a sweep doing damage in a place nobody asked
// it to look. The container itself is excepted because it is an
// organizationalUnit — an `ou=users` carrying a nationality is not a person, it
// is a bug that reads as one.
// ---------------------------------------------------------------------------
function populateVcAttributes() {
  log.debug('Entering populateVcAttributes().');
  const wanted = vcClaims.selectedNames();
  // Nothing to fill in a mode that invents nothing (see applyVcAttributes()),
  // and a walk of the whole realm to learn that would be a walk for nothing.
  // Said in the result, so the page behind Populate reports it rather than
  // "0 entries changed" about a sweep that did not run.
  if (!mode.inventsClaimValues()) {
    log.info('ldap: the credential attribute sweep did not run — this ' +
             'service invents no claim value in product mode, so an entry ' +
             'carries what was provisioned onto it and nothing generated.');
    log.debug('Leaving populateVcAttributes(). Not in this mode.');
    return { examined: 0, changed: 0, values: 0, attributes: wanted,
             skipped: 'product mode invents no claim value ' +
                      '(mode.inventsClaimValues())' };
  }
  let examined = 0;
  let changed = 0;
  const before = new Map();
  eachEntryInRealm(function (stored) {
    if (!isUnder(stored.dn, usersDn()) ||
        normalizeDn(stored.dn) === normalizeDn(usersDn())) {
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
  log.info('ldap: swept ' + examined + ' entry/entries under ' + usersDn() +
      ' ' +
      'for the ' +
           wanted.length + ' attribute(s) the credential claim set asks for; ' +
      changed +
           ' entry/entries gained ' + values + ' value(s).');
  log.debug('Leaving populateVcAttributes(). ' + changed + ' of ' + examined +
      ' ' +
      'changed.');
  return { examined: examined, changed: changed, values: values,
           attributes: wanted };
}

// ---------------------------------------------------------------------------
// THE SAME THING FOR ONE ENTRY, WHICH IS WHAT A CREATE ACTUALLY NEEDS.
//
// The sweep above is exported with a comment saying that a batch of fifty
// creates should sweep once "and the caller is what knows the batch is over".
// **SCIM HAS NO BATCH.** Every POST /scim/v2/Users is one create, so `scim.js`
// called the whole-realm sweep once per person — twice round every entry in the
// realm to fix up the ONE entry that had just been written. That is O(n) work
// on every create and therefore O(n²) over a load, and it is the whole of why
// the SCIM door measured 8.18ms at the 500th person and 39.42ms at the 5,000th
// while `/admin-api` and LDAP stayed flat at 0.78ms and 0.43ms against a
// directory twice the size — 197.6s against 4.1s and 2.2s for the same five
// thousand people.
//
// **THAT COMPARISON IS THE ONE THE BULK-LOAD JOBS TELL YOU NOT TO MAKE**, and
// it was right to make it here: the three doors run against one directory that
// nothing deletes from, so the later door is normally reading a bigger store —
// but SCIM runs FIRST, against 227 entries, and was still forty times slower
// than a door reading ten thousand. When the caveat and the numbers disagree
// that badly, the caveat is what needs checking.
//
// A create is the batch-of-one case, and this is it. The sweep is untouched and
// still right for the two callers that mean every entry: startup, and the
// change of WHICH attributes the claim set asks for — which is a fact about the
// whole directory rather than about one person.
//
// The two tests below are the sweep's own, applied to the one entry so that it
// is treated exactly as the walk would have treated it.
// ---------------------------------------------------------------------------
function populateVcAttributesAt(dn) {
  log.debug('Entering populateVcAttributesAt(). dn=' + dn);
  const stored = getEntry(dn);
  if (!stored) {
    log.debug('Leaving populateVcAttributesAt(). There is no entry at ' + dn +
              '.');
    return { examined: 0, changed: 0, values: 0 };
  }
  if (!isUnder(stored.dn, usersDn()) ||
      normalizeDn(stored.dn) === normalizeDn(usersDn())) {
    log.debug('Leaving populateVcAttributesAt(). ' + stored.dn +
              ' is not a person under ' + usersDn() + '.');
    return { examined: 0, changed: 0, values: 0 };
  }
  const before = Object.keys(stored.attributes).length;
  const changed = applyVcAttributes(stored, personaKeyOf(stored));
  const values = Object.keys(stored.attributes).length - before;
  log.debug('Leaving populateVcAttributesAt(). ' + (changed ? 1 : 0) +
            ' entry changed, ' + values + ' value(s).');
  return { examined: 1, changed: changed ? 1 : 0, values: values,
           attributes: vcClaims.selectedNames() };
}

// What one person's entry holds, for vc_claims.js to read a claim value out of.
// The attribute names are the stored (lower-cased) ones, which is what that
// module compares against — see the note on its directoryAttributes().
//
// It is given the same identity key the console files a person under, so
// locateEntry() answers for both shapes of identity: a name is
// `uid=<name>,ou=users` and a certificate's DN is found by the subject the
// entry recorded. Nothing is invented here — a missing entry is null, and the
// caller's own fallback is what fills the claim.
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
            Object.keys(located.stored.attributes).length +
            ' attribute(s) at ' +
            located.stored.dn + '.');
  return located.stored.attributes;
}

// ---------------------------------------------------------------------------
// ONE USER'S ENTRY, FOR THE ADMIN CONSOLE.
//
// /admin/users?user=<name> is the page that answers "what does this service
// hold about this person", and the directory entry autoCreateUser() seeded
// above is part of that answer — so the console shows it there rather than
// making a reader find the same object again on /ldap/directory.
//
// The direction of the dependency is inverted here for the same reason the
// observer above is, and it is worth stating because it is the OPPOSITE way
// round from what the call graph looks like. admin.js renders this; it would
// naturally require this module and read `entries`. It must not: server.js
// requires ./admin before ./ldap_server (rule 6 — this module needs
// admin_stats' identity normalisation), and a require from admin.js would drag
// this module's routes in ahead of the console's, which reorders the express
// router that /admin/sts-metadata reads. So admin.js offers a slot and this
// module fills it, exactly as admin_stats.js does for the observer.
//
// It is given the IDENTITY KEY the console files a person under — the local
// name, with a subject already resolved and any realm stripped — which is the
// same
// string autoCreateUser() built the DN from, so the two cannot drift.
//
// What comes back is deliberately more than the entry: the DN is reported
// whether or not anything is there, because "no entry at uid=bob,ou=users" and
// "the directory is not running" and "auto-creation is off" are three different
// answers and a null would be all three at once. The console phrases which one
// it is; this function states the facts it needs to do that.
// ---------------------------------------------------------------------------
//
// Finding it is three rules, because there are three shapes of identity here. A
// NAME is `uid=<name>,ou=users` and always was. A DN — which is what a TLS
// client certificate's identity is — is looked up by the subject the entry
// RECORDED, in `x509subject`, because that is exact and stays right if
// certificatePlan()'s naming rule ever changes; and where the subject lies
// inside this directory's own tree, the entry it names directly is the answer.
// A DECENTRALIZED IDENTIFIER is looked up the same way and for the same reason,
// by `didSubject`, which on those entries is the identity where the uid is only
// a digest of it. Failing all of that, the DN the matching plan WOULD have
// built is reported, so the page can say where the entry would have gone rather
// than naming a place nothing was ever going to be.
function locateEntry(key) {
  log.debug('Entering locateEntry(). key=' + key);
  // A SUBJECT (2026-09-14): `urn:uuid:<entryUUID>`, which is what a token's
  // `sub` holds. It names an entry by the one thing about it that never
  // changes, so it is looked up and never rebuilt — and where nothing here
  // carries it there is nowhere an entry "would go", because a subject is
  // assigned to an entry and never the other way round.
  if (/^urn:uuid:/i.test(String(key || ''))) {
    const found = entryByUuid(key);
    log.debug('Leaving locateEntry(). A subject: ' +
              (found ? found.dn : 'nobody here.'));
    return { dn: found ? found.dn : '', stored: found };
  }
  if (DN_SHAPED.test(key)) {
    // A DN is the one identity shape a caller can hand this function that names
    // a PLACE rather than a person, so it was the one that could reach out of
    // the realm — for two days, while the store was shared, this line needed a
    // containment check of its own. The store is per realm now, so `getEntry()`
    // cannot see another realm's entry and the check is the store's job.
    const direct = getEntry(key);
    if (direct) {
      log.debug('Leaving locateEntry(). The DN names an entry in this realm ' +
                'directly.');
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
  // A DECENTRALIZED IDENTIFIER, which is the third shape and the one that
  // CANNOT be looked up by rebuilding its name and reading the store. It could
  // — the digest is deterministic — but doing it that way would make
  // didPlan()'s naming rule impossible to change without orphaning every entry
  // already written under the old one. So the entry is found by what it
  // RECORDED, exactly as a certificate's is, and didPlan() is consulted only to
  // say where an entry WOULD go when there is none.
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
  // client certificate is at `cn=<name>,ou=users`, and rebuilding the name
  // would report "nothing here" about an entry this directory holds and every
  // authentication now folds onto.
  const already = existingUserEntry(key);
  if (already) {
    log.debug('Leaving locateEntry(). A name, found at ' + already.dn + '.');
    return { dn: already.dn, stored: already };
  }
  const dn = 'uid=' + key + ',' + usersDn();
  log.debug('Leaving locateEntry(). A name, so ' + dn +
            ' (nothing there yet).');
  return { dn: dn, stored: null };
}

function objectFor(name) {
  log.debug('Entering objectFor(). name=' + name);
  const key = String(name == null ? '' : name).trim();
  const located = key ? locateEntry(key) : { dn: '', stored: null };
  const dn = located.dn;
  const stored = located.stored;

  // Every OTHER entry in the tree whose uid names this same person. A client
  // can add `cn=alice,ou=people` through the protocol, and a page that reported
  // only the auto-created DN would say "no entry" while the directory held one.
  // Only the DNs are listed — the dump below is of the entry the console is
  // about.
  //
  // Skipped for a DN identity: `uid` holds names, so matching a whole DN
  // against it can only ever find nothing, and the entry for that identity was
  // found by its subject above rather than by a name at all. Skipped for a DID
  // for the same reason and one more — the uid on a DID-named entry is a DIGEST
  // of the identity, so comparing the identity against it would find nothing
  // even on the entry that is this person's. A SPIFFE identity is skipped for
  // exactly that second reason.
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
    // this is not a search, it is this service showing its own store, and a
    // dump that silently dropped two of the entry's attributes would be the one
    // thing a dump must not do.
    const attributes = {};
    Object.keys(stored.attributes).sort().forEach(function (attribute) {
      // An enrollment credential is withheld here too (2026-09-13) — see
      // `cert_enrollment.withheldValues()`.
      attributes[canonicalName(attribute)] = certEnrollment.withheldValues(
        attribute, stored.attributes[attribute].slice(0));
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
  log.debug('Leaving objectFor(). ' +
            (stored ? 'The entry is there.' : 'There ' +
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
// entry that names them — the inverse of the `uid=<name>,ou=users`
// locateEntry() builds, and the reason a member row can link to
// /admin/users?user=... at all.
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
  log.debug("Entering consoleKeyFor().");
  if (stored && (stored.attributes.uid || []).length) {
    log.debug("Leaving consoleKeyFor().");
    return String(stored.attributes.uid[0]);
  }
  const leaf = splitRdns(dn)[0] || '';
  const pairs = rdnPairs(leaf).filter(function (pair) {
    return pair.attribute === 'uid';
  });
  log.debug("Leaving consoleKeyFor().");
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
    // these groups at all. Saying which members are groups is what lets a
    // reader see the nesting they wrote; claiming to have flattened it would be
    // a lie about a feature that is not here.
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
  log.debug("Entering membersOf().");
  const out = [];
  MEMBER_ATTRIBUTES.forEach(function (attribute) {
    (stored.attributes[attribute.name] || []).forEach(function (value) {
      out.push(resolveMember(value, attribute));
    });
  });
  log.debug("Leaving membersOf().");
  return out;
}

// The OTHER answer to "who is in this group": entries elsewhere in the tree
// whose own `memberOf` names it and which the group's member attributes do NOT
// list back.
//
// This is not a nicety. `memberOf` is maintained by the SERVER in every
// directory that has it (it is not even a standard attribute — it is
// Microsoft's and OpenLDAP's, through an overlay), and this one maintains
// nothing: a client that writes `memberOf: cn=developers,...` onto a user
// creates exactly this disagreement, and it is one of the two or three things a
// person would come to a mock directory to try. Listing them separately, under
// their own heading, says which side of the disagreement each name came from —
// merging them into the member list would manufacture a consistency this
// directory never claimed.
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
// same six objectFor() reports, out of one function so that the two pages
// cannot come to disagree about whether a socket is up.
function directoryState() {
  log.debug("Entering directoryState().");
  log.debug("Leaving directoryState().");
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
// the list costs one pass over a store capped at maxEntries() and it is what
// lets the detail page carry its own way back to the siblings.
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
      // whose seven members resolve to five entries is the
      // referential-integrity story, and a single count tells it as "seven
      // members" with nothing wrong.
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
  // whether it IS a group; the store decides whose it is. A SCIM id — the
  // group's entryUUID since 2026-09-14 — names the same group as its DN.
  const stored = getEntry(dnForResourceId(wanted));
  if (!stored) {
    log.debug('Leaving groupsFor(). There is no entry at ' + wanted + ' in ' +
        'this realm.');
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
    log.debug('Leaving groupsFor(). ' + stored.dn + ' is an entry but not a ' +
                                                    'group.');
    return out;
  }

  // Canonically spelled and OPERATIONAL ATTRIBUTES INCLUDED, for the reason
  // objectFor() gives: this is not a search, it is the service showing its own
  // store, and a dump that dropped two attributes would be the one thing a dump
  // must not do.
  const attributes = {};
  Object.keys(stored.attributes).sort().forEach(function (attribute) {
    attributes[canonicalName(attribute)] = stored.attributes[attribute].slice(
        0);
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
            ' member value(s), ' + out.group.danglingCount + ' of them ' +
                'dangling.');
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
// to `ldap.maxEntries`, which is 2,000 by default — and it showed:
// normalizeDn() was the third-heaviest application function in a CPU profile of
// the token endpoint under load, above anything in oauth2.js.
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
// The cache itself is declared beside the username index, up by the store —
// see the note there. Everything else about it is here.

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
        const dn = attribute.holds === 'uid' ? 'uid=' + raw + ',' + usersDn() :
                   raw;
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
  log.debug("Entering groupIndexNow().");
  const cache = groupIndexes();
  if (cache.index && cache.version === directoryVersion &&
      cache.size === entries.size) {
    log.debug("Leaving groupIndexNow().");
    return cache.index;
  }
  cache.index = buildGroupIndex();
  cache.version = directoryVersion;
  cache.size = entries.size;
  log.debug("Leaving groupIndexNow().");
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
// parent project's — costs a warning rather than `admin.setDirectoryReader is
// not a function` thrown at require time, which would take the whole service
// down over one section of one page. A directory whose entries nobody renders
// is still a working directory.
if (typeof admin.setDirectoryReader === 'function') {
  admin.setDirectoryReader(objectFor);
} else {
  log.warn('ldap: the admin console offers no setDirectoryReader(), so a ' +
           'user page will not show that user\'s directory entry. The ' +
           'directory itself is unaffected.');
}

// The third, and guarded for the same reason: an older admin.js without the
// slot costs a warning rather than a TypeError at require time, which would
// take the whole service down over one page.
if (typeof admin.setGroupReader === 'function') {
  admin.setGroupReader(groupsFor);
} else {
  log.warn('ldap: the admin console offers no setGroupReader(), so ' +
           '/admin/groups will report that no directory is loaded. The ' +
           'directory itself is unaffected.');
}

// The console's THIRD slot, and the only one of the three that WRITES. It is
// deliberately not counted in with the cross-module numbering below, because
// what makes it different is not where it sits in the require order but what it
// does: the other two answer questions about the directory, and this one puts a
// person in it.
//
// It carries createUser() and not putEntry(): the console must not be a second
// definition of what creating a user means, any more than /admin/applications
// is a third door onto the registry. The refusal that matters — a username that
// is already here — is inside that function, so the form, the management API
// and an `ldapadd` all get the same answer about the same name.
//
// Guarded like the other two, and for the same reason.
if (typeof admin.setDirectoryWriter === 'function') {
  admin.setDirectoryWriter(createUser);
} else {
  log.warn('ldap: the admin console offers no setDirectoryWriter(), so ' +
           '/admin/users cannot create a person. The directory itself is ' +
           'unaffected, and an ldapadd still reaches it.');
}

// THE GROUP HALF OF THAT SLOT, AND IT IS A SLOT OF ITS OWN RATHER THAN A THIRD
// ARGUMENT TO THAT ONE (2026-09-06).
//
// `setDirectoryWriter()` carries ONE function and every caller of it means "put
// a person in the directory". Widening it into an object would have been a
// change to a slot four callers already fill correctly, in order to add
// something none of them wants; a separate slot is one more indirection and no
// edit to the working one.
//
// IT CARRIES BOTH FUNCTIONS AND IS VALIDATED WHOLE, for `setLogoutReader()`'s
// reason: a console able to CREATE a group and unable to put anybody in it is a
// page whose second button answers "no directory is loaded" on a service whose
// directory plainly is. Guarded like the three above — an older admin.js
// without the slot costs a warning rather than a TypeError at require time.
if (typeof admin.setGroupWriter === 'function') {
  admin.setGroupWriter({ createGroup: createGroup,
                         addGroupMember: addGroupMember });
} else {
  log.warn('ldap: the admin console offers no setGroupWriter(), so ' +
           '/admin/groups cannot create a group or add a member to one. The ' +
           'directory itself is unaffected, and an ldapadd, an ldapmodify ' +
           'and a SCIM create all still reach it.');
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
  vcClaims.setDirectory({ attributesFor: vcAttributesFor,
                          populate: populateVcAttributes });
} else {
  log.warn('ldap: vc_claims.js offers no setDirectory(), so issued ' +
           'credentials will carry invented values rather than what this ' +
           'directory holds. The directory itself is unaffected.');
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
// THE CRL CONTAINER (2026-09-11).
//
// `common/pki_revocation.js` offers the slot and this fills it. It is an
// INVERTED HOOK for rule 3e's test in both directions: that module is a LEAF
// required by `common/pki.js` and by the certificate authority's own startup,
// so a require from it to THIS module would drag every `/ldap` route into the
// router ahead of everything — and a require the other way is exactly what
// happens, harmlessly, because this module is at 21 and that one registers
// nothing.
//
// It carries TWO functions and is validated whole, for `setLogoutReader()`'s
// reason: a filler that installed `baseDnFor` and not `publishCrl` would put
// the right DN in every certificate and write nothing to the directory — so
// the `ldap://` distribution points would be correct addresses for entries
// that do not exist, which is the one failure a reader checking three schemes
// would not think to look for.
// ---------------------------------------------------------------------------
if (typeof pkiRevocation.setDirectory === 'function') {
  pkiRevocation.setDirectory({
    publishCrl: publishCrl,
    baseDnFor: function (scopeId) {
      log.debug("Entering baseDnFor().");
      log.debug("Leaving baseDnFor().");
      return realmBaseDn(scopeIdToRealm(scopeId));
    }
  });
} else {
  log.warn('ldap: common/pki_revocation.js offers no setDirectory(), so no ' +
           'CRL is published into this directory and the ldap:// ' +
           'distribution point in certificates this service issues ' +
           'will fetch nothing. They are still served over HTTP.');
}

// ---------------------------------------------------------------------------
// XACML: THE POLICY REPOSITORY AND THE PIP.
//
// Two slots on two modules, and they are two rather than one because they are
// about two different things: `xacml_store.js` needs ou=policies and nothing
// else, and `xacml_pip.js` needs to find a PERSON and nothing else. Folding
// them into one install would hand each module three functions it must not
// use, and the whole point of a slot is that what crosses it is the smallest
// thing that works.
//
// Guarded like every other install here: an older copy of either module
// without the slot costs a warning rather than a service that will not start.
// THE ROLE REGISTER'S CONTAINER, AND ITS GROUP LOOKUP.
//
// Two functions rather than one slot's worth, because resolving a role needs
// both halves and only this module has either: `ou=roles` says which groups
// hold a role, and `groupsOfUser()` says which groups a person is in. Handing
// over the container alone would leave `roles.js` able to list roles and
// unable to answer whether anybody holds one.
//
// The group names are FLATTENED to their common names here. `groupsOfUser()`
// answers rows carrying a DN, a cn and how the membership was established,
// which is what /admin/groups draws; a role only ever compares names, and
// passing the rows would put the shape of a console page into the resolver.
if (typeof roles.setDirectory === 'function') {
  roles.setDirectory({
    allRoles: allRoles,
    writeRole: writeRole,
    deleteRole: deleteRole,
    groupsOfUser: function (name) {
      log.debug("Entering groupsOfUser().");
      log.debug("Leaving groupsOfUser().");
      return (groupsOfUser(name).groups || []).map(function (one) {
        return one.cn;
      });
    }
  });
} else {
  log.warn('ldap: common/roles.js offers no setDirectory(), so ou=roles is ' +
           'unreachable and only the six built-in roles answer. An ' +
           'application requiring EVERYBODY still admits everybody, so ' +
           'nothing is refused that was not refused before.');
}

// THE PASSWORD POLICY REGISTER'S CONTAINER. Three functions, the shape of the
// role register's, and guarded the same way: an older copy of that module
// without the slot costs a warning and leaves the BUILT-IN default profile in
// force — which is the policy an unedited service enforces anyway, so nothing
// becomes weaker by its absence.
if (typeof passwordPolicy.setDirectory === 'function') {
  passwordPolicy.setDirectory({
    allPasswordPolicies: allPasswordPolicies,
    writePasswordPolicy: writePasswordPolicy,
    deletePasswordPolicy: deletePasswordPolicy
  });
} else {
  log.warn('ldap: common/password_policy.js offers no setDirectory(), so ' +
           'ou=passwordPolicies is unreachable and the built-in default ' +
           'password policy cannot be edited.');
}

if (typeof xacmlStore.setDirectory === 'function') {
  xacmlStore.setDirectory({ allPolicies: allPolicies,
                            writePolicy: writePolicy,
                            deletePolicy: deletePolicy });
  // THE SEEDED POLICY IS WRITTEN HERE AND NOT IN seed() ABOVE, and the reason
  // is an ordering that cost a boot: `seed()` runs at require time, and the
  // slot it needs is filled by the line above it — so a seed written up there
  // is refused with "there is no embedded directory", the repository comes up
  // empty, and every decision is NotApplicable with nothing in the log that
  // names a policy. Here the store can reach ou=policies.
  //
  // Guarded on the repository being EMPTY rather than on the container being
  // new, because those are different facts once persistence is in play: a
  // restore has not happened yet at require time, so "new container" is true
  // on every start under `postgres` and `ldif` and would re-seed a policy the
  // operator deleted on purpose. An empty repository is the only state where
  // seeding is unambiguously right.
  //
  // It goes through the ordinary write path, so the seeded document is parsed
  // and STATICALLY VALIDATED like any other — a seed that stopped
  // typechecking is refused at startup and says so, rather than becoming the
  // one policy in the repository nobody ever checked.
  if (typeof xacmlStore.seed === 'function' && policyCount() === 0) {
    xacmlStore.seed();
  }
} else {
  log.warn('ldap: xacml_store.js offers no setDirectory(), so the XACML ' +
           'policy repository is empty and the PDP answers NotApplicable to ' +
           'everything. The directory itself is unaffected.');
}

// ---------------------------------------------------------------------------
// THE REMOTE PEP REGISTER: A THIRD SLOT ON A THIRD XACML MODULE, and it is
// three rather than two for the reason the comment above gives about two —
// what crosses a slot is the smallest thing that works. `xacml_store.js` needs
// ou=policies, `xacml_pip.js` needs to find a person, and this one needs
// ou=peps and ONE MORE THING that neither of the others could be given without
// handing it a function it must not use.
//
// **THAT ONE MORE THING IS `certificateIdentity`, AND IT IS THE WHOLE REASON
// THE REGISTER DOES NOT INVENT A NAMING RULE OF ITS OWN.** A remote PEP is
// identified by its client certificate, and this service already has exactly
// one answer to "what identity is this certificate" — `certificatePlan()`,
// which every verified client certificate on 8443, 9443 and 636 goes through.
// A second mapping written in `xacml_pep_registry.js` would be a second answer
// to that question, and two answers is how one component ends up filed under
// two names on two pages.
//
// WHAT CROSSES IS THE NAMING AND NOT THE ENTRY CREATION. This returns the DN
// and the common name and writes nothing: a registration does not put a PEP
// into ou=users, because a PEP is a component rather than a person and
// /admin/users counts people. That is the same line `spiffe_registry.js` had
// to draw between an ISSUANCE and an AUTHENTICATION, and getting it wrong
// there made an agent holding a stream open read as hundreds of sign-ins.
if (typeof xacmlPepRegistry.setDirectory === 'function') {
  xacmlPepRegistry.setDirectory({
    allPeps: allPeps,
    writePep: writePep,
    deletePep: deletePep,
    certificateIdentity: function (certificate) {
      log.debug('Entering certificateIdentity().');
      // **THE SUBJECT HAS TO BE A STRING BEFORE IT GETS HERE, AND NODE HANDS
      // BACK AN OBJECT.** `getPeerCertificate()` returns `subject` as a
      // null-prototype object of RDN types, and `certificatePlan()` does
      // `String(certificate.subject || ...)` on it — which does not produce a
      // DN, it THROWS "Cannot convert object to primitive value", because a
      // null-prototype object has no toString. The registration then answered
      // 500 with a stack in it.
      //
      // `helpers.dnRfc4514()` is the one spelling of that conversion in this
      // service — `tls_server.js` puts every client certificate's subject and
      // issuer through it before recording either — and using it here is what
      // makes a PEP's `x509subject` byte-for-byte the string the same
      // certificate would write arriving on 8443 or 636. Two spellings of one
      // DN is two identities, which `spiffe/CLAUDE.md` lists as an assertion a
      // test should make.
      // BOTH DN FIELDS, not just the subject: `certificatePlan()` does the
      // same `String()` on `certificate.issuer` a few lines further down, so
      // fixing one of them moved the throw rather than removing it.
      const given = certificate || {};
      const subject = typeof given.subject === 'string'
        ? given.subject : dnRfc4514(given.subject);
      const issuer = typeof given.issuer === 'string'
        ? given.issuer : dnRfc4514(given.issuer);
      const plan = certificatePlan({
        certificate: Object.assign({}, given,
                                   { subject: subject, issuer: issuer })
      });
      const common = (plan.attributes.cn || [])[0] || '';
      log.debug('Leaving certificateIdentity(). dn=' + plan.dn);
      return { dn: plan.dn, commonName: common, subject: subject };
    }
  });
} else {
  log.warn('ldap: xacml_pep_registry.js offers no setDirectory(), so no ' +
           'remote Policy Enforcement Point can register and ' +
           '/admin/xacml/peps is empty. Policy DISTRIBUTION is unaffected — ' +
           'a PEP pulls GET /xacml/pep/policies without registering — so ' +
           'what is lost is the register and the nudge, not the mechanism.');
}

// `locateEntry` and nothing else. It is the function that already resolves all
// three shapes of identity this service files a person under — a bare name, a
// DN, and a TLS client certificate's subject — so the PIP gets that behaviour
// rather than a fourth lookup that would agree with it until it did not.
if (typeof xacmlPip.setDirectory === 'function') {
  xacmlPip.setDirectory({ locateEntry: locateEntry });
} else {
  log.warn('ldap: xacml_pip.js offers no setDirectory(), so an XACML ' +
           'decision sees only the attributes the request carried. That is ' +
           'the pure-XACML behaviour and is not a failure.');
}

// ---------------------------------------------------------------------------
// THE CLIENT TRUSTSTORE'S DURABLE HALF (2026-09-12).
//
// `tls/tls_server.js` is already required at the top of this file — this
// module serves its certificate on 636 — so filling its slot is a call in the
// ORDINARY direction and costs no require at all. The other direction is out:
// `tls_server.js` is loaded from inside `admin-ui/admin.js`'s require, long
// before this module, and a require from there to here would register every
// /ldap route and the eight /admin/ldap/* pages ahead of the console's (rule
// 3e). Three functions, validated whole over there, all pinned to the DEFAULT
// realm because the truststore belongs to the process.
// ---------------------------------------------------------------------------
if (typeof tlsServer.setTrustAnchorStore === 'function') {
  tlsServer.setTrustAnchorStore({
    list: inDefaultRealm(allTrustAnchors),
    write: inDefaultRealm(writeTrustAnchor),
    remove: inDefaultRealm(deleteTrustAnchor)
  });
} else {
  log.warn('ldap: tls_server.js offers no setTrustAnchorStore(), so an ' +
           'anchor added at runtime is lost at the next start. ' +
           'tls.trustAnchorsFile is unaffected.');
}

// The replication appliers' call into the truststore. Quiet because it runs
// inside an applier that must not fail because a LISTENER could not take a new
// context: the entry is stored either way, and `applyAnchors()` logs its own
// failure.
function reloadTrustAnchorsQuietly() {
  log.debug("Entering reloadTrustAnchorsQuietly().");
  if (typeof tlsServer.reloadStoredAnchors !== 'function') {
    log.debug("Leaving reloadTrustAnchorsQuietly().");
    return;
  }
  try {
    tlsServer.reloadStoredAnchors();
  } catch (e) {
    // Swallowed on purpose: this is called from a replication applier, and a
    // truststore that could not be re-read must not stop the directory
    // applying the change that prompted it. The failure is logged here and the
    // next change, or a restart, reads the container again.
    log.error(errorCodes.tag('STS-LDAP-0051') +
              'ldap: the truststore could not be reloaded after a replicated ' +
              'change to ou=trustAnchors: ' + e.message);
  }
  log.debug("Leaving reloadTrustAnchorsQuietly().");
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
// `alice@EXAMPLE.COM` and `urn:uuid:<entryUUID>` reach `locateEntry()` as
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
    log.debug('Leaving consentValuesOf(). There is no entry at ' + located.dn +
              '.');
    return { dn: located.dn, found: false, values: [] };
  }
  const values = (stored.attributes.oauthconsent || []).slice(0);
  log.debug('Leaving consentValuesOf(). ' + values.length + ' value(s) on ' +
            stored.dn + '.');
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
    log.warn(errorCodes.tag('STS-LDAP-0040') +
             'ldap: "' + key + '" has no entry in this realm, so the consent ' +
             'they gave was not recorded. They will be asked again. This is ' +
             'what ldap.autoCreateUsers being off looks like from the ' +
             'consent screen.');
    log.debug('Leaving addConsentValues(). Nothing to write to.');
    return { ok: false, dn: located.dn, reason: 'noEntry' };
  }
  const changed = addValues(stored, 'oauthConsent', values);
  if (changed) {
    stored.attributes.modifytimestamp = [generalizedTime()];
    touchDirectory();
  }
  log.debug('Leaving addConsentValues(). ' +
            (changed ? 'Written.' : 'Already ' +
      'there.'));
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
  log.debug('Leaving removeConsentValues(). ' + (have.length - left.length) +
      ' ' +
      'removed.');
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
    rows.push({ dn: entry.dn, username: usernameOfEntry(entry),
                values: values.slice(0) });
  });
  log.debug('Leaving listConsentValues(). ' + rows.length + ' entry/entries.');
  return rows;
}

// ---------------------------------------------------------------------------
// THE CREDENTIAL STORE (2026-09-06). `userPassword` on a person's own entry.
//
// **RFC 4519 SECTION 2.41's ATTRIBUTE, AND THE NAME IS THE POINT**: an entry
// this service writes a credential onto is one an ordinary LDAP client
// recognises, and this directory has answered `compare` on `userPassword` since
// it existed — it just never had a value to compare against, which is why
// `crypto_metadata.js` said in as many words that no `userPassword` is stored.
//
// THE VALUE IS A SCRYPT HASH and never a password. `common/credentials.js`
// hashes before it gets here, so this module never sees a plaintext credential
// at all — which is what keeps the decision about HOW in one place, beside
// every other cryptographic decision this service makes.
//
// **THE READ RETURNS THE STORED VALUE AND THE CALLER COMPARES**, rather than
// this taking a password and answering yes or no. That looks like the weaker
// arrangement and is the stronger one: the comparison is constant-time and
// lives in `crypto.js` with every other secret comparison here, so a second
// implementation of it cannot appear in this file by somebody reaching for
// `===`.
// ---------------------------------------------------------------------------
function readStoredPassword(key) {
  log.debug('Entering readStoredPassword(). key=' + key);
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    log.debug('Leaving readStoredPassword(). No entry at ' + located.dn + '.');
    return '';
  }
  // Lower-cased attribute keys, like every other read here — the store
  // lower-cases a name on the way in, and a reader that looks for the camel
  // case finds nothing on an entry that plainly has it. That mistake cost
  // `ou=roles` a page reporting `0 user(s)` for a role somebody held.
  const values = stored.attributes.userpassword || [];
  log.debug('Leaving readStoredPassword(). ' +
            (values.length ? 'A credential is set.' : 'None is set.'));
  return values.length ? String(values[0]) : '';
}

// THE PASSWORD HISTORY (2026-09-12): `pwdHistory` on the same entry, one value
// per remembered previous password in draft-behera-ldap-password-policy's
// `time#syntaxOID#length#data` form. The values are BUILT by
// `common/password_policy.js` and CHOSEN by `common/credentials.js`; this
// module stores strings, which is the same division `userPassword` beside it
// already has — so this file never learns what a history value means, and
// never holds the decision about how many to keep.
function readPasswordHistory(key) {
  log.debug('Entering readPasswordHistory(). key=' + key);
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    log.debug('Leaving readPasswordHistory(). No entry.');
    return [];
  }
  const values = (stored.attributes.pwdhistory || []).map(String);
  log.debug('Leaving readPasswordHistory(). ' + values.length + ' value(s).');
  return values;
}

// ---------------------------------------------------------------------------
// A PASSWORD WRITTEN OVER THE SOCKET (2026-09-12).
//
// **THIS WAS THE ONE DOOR THAT WROTE `userPassword` AS IT WAS GIVEN** — an
// `ldapadd` or `ldapmodify` carrying one stored the value verbatim, in the
// clear, past every rule `credentials.setPassword()` applies, beside four other
// doors that all hash and all ask the password policy. So a product-mode
// deployment with a password policy had a policy an LDAP client was not told
// about. Now the add and modify handlers bring the value here, and it goes
// through `credentials.preparePassword()` — the same function every other door
// ends in — and what is stored is its hash.
//
// **IT IS APPLIED TO THE WORKING COPY AND NOTHING IS WRITTEN HERE**, because a
// modify is atomic across all of its changes (RFC 4511 section 4.6): a policy
// refusal has to leave the entry exactly as it was, and the handler has not
// committed anything until every change has been accepted.
//
// Three things, and the first is the one that differs by mode:
//
//   * **A VALUE THAT IS ALREADY A SCRYPT HASH** is kept as given in
//     development — that is how a directory is moved between two instances of
//     this service — and REFUSED in product mode, because a hash cannot be
//     checked against a policy and accepting one would be the way round it.
//   * **`pwdHistory` AND `pwdChangedTime` ARE THE SERVICE'S TO MAINTAIN** and a
//     change naming either is refused in product mode: a history anybody can
//     empty is not a history.
//   * **ONE VALUE.** An entry with two `userPassword` values is an entry where
//     the old password still works, which `writeStoredPassword()` refuses to
//     produce and this refuses to accept.
//
// Answers null or the ldapjs error to hand to `next()`. A CONSTRAINT VIOLATION
// (19) is what draft-behera-ldap-password-policy's servers answer for a
// password that fails quality or history, and it is what an LDAP client's error
// handling expects to meet there.
// ---------------------------------------------------------------------------
function passwordWriteRefusal(dn, attributes, previous, touched, written) {
  log.debug('Entering passwordWriteRefusal(). dn=' + dn);
  const before = previous || {};
  const keyOf = function (lower) {
    log.debug("Entering keyOf().");
    log.debug("Leaving keyOf().");
    return Object.keys(attributes).filter(function (key) {
      return key.toLowerCase() === lower;
    })[0];
  };
  if (mode.verifiesCredentials() &&
      (touched.indexOf('pwdhistory') >= 0 ||
       touched.indexOf('pwdchangedtime') >= 0)) {
    log.debug('Leaving passwordWriteRefusal(). An operational attribute.');
    return coded('STS-LDAP-0009', new ldap.ConstraintViolationError(
      'pwdHistory and pwdChangedTime are maintained by this service\'s ' +
      'password policy and cannot be written'));
  }
  if (touched.indexOf('userpassword') < 0) {
    log.debug('Leaving passwordWriteRefusal(). No password in this change.');
    return null;
  }
  const key = keyOf('userpassword');
  const values = key ? (attributes[key] || []).map(String) : [];
  if (!values.length) {
    // Taking a password away is not setting one. The history stays: removing
    // somebody's password and giving them the old one back must still meet it.
    log.debug('Leaving passwordWriteRefusal(). The password was removed.');
    return null;
  }
  if (values.length > 1) {
    log.debug('Leaving passwordWriteRefusal(). Two values.');
    return coded('STS-LDAP-0010', new ldap.ConstraintViolationError(
      'an entry holds one userPassword; replace it rather than adding a ' +
      'second'));
  }
  const value = values[0];
  const had = (before.userpassword || [])[0];
  if (had !== undefined && String(had) === value) {
    log.debug('Leaving passwordWriteRefusal(). Unchanged.');
    return null;
  }
  if (value.indexOf('$scrypt$') === 0) {
    if (mode.verifiesCredentials()) {
      log.debug('Leaving passwordWriteRefusal(). A hash, in product mode.');
      return coded('STS-LDAP-0011', new ldap.ConstraintViolationError(
        'a pre-hashed userPassword cannot be checked against the password ' +
        'policy; send the password itself (over LDAPS), or set it through ' +
        '/admin-api/users/set-password'));
    }
    log.debug('Leaving passwordWriteRefusal(). A hash, kept as given.');
    return null;
  }
  const prepared = credentials.preparePassword(usernameOfEntry({ dn: dn }),
                                               value, {
    current: had === undefined ? '' : String(had),
    history: (before.pwdhistory || []).map(String)
  });
  if (!prepared.ok) {
    log.info('ldap: a userPassword for ' + dn + ' was refused: ' +
             (prepared.errors || []).join(' '));
    log.debug('Leaving passwordWriteRefusal(). Refused by the policy.');
    // The policy's own code for which rule refused it, or this one.
    return coded(errorCodes.codeOf(prepared) || 'STS-LDAP-0012',
      new ldap.ConstraintViolationError((prepared.errors || []).join(' ')));
  }
  attributes[key] = [prepared.hash];
  // What was accepted, for the caller to announce once it has COMMITTED — the
  // Kerberos key register derives from it. Not announced here, because this
  // is the working copy and the modify may yet be refused.
  if (written) {
    written.name = usernameOfEntry({ dn: dn });
    written.password = value;
  }
  const historyKey = keyOf('pwdhistory') || 'pwdhistory';
  if (prepared.history.length) {
    attributes[historyKey] = prepared.history;
  } else {
    delete attributes[historyKey];
  }
  attributes[keyOf('pwdchangedtime') || 'pwdchangedtime'] = [generalizedTime()];
  log.debug('Leaving passwordWriteRefusal(). Hashed.');
  return null;
}

// ---------------------------------------------------------------------------
// WHO MAY WRITE THIS DIRECTORY OVER THE SOCKET (2026-09-12).
//
// Until this date nothing did. Product mode VERIFIED a bind, and then the
// connection that had proved who it was could add, modify, rename or delete any
// entry in any realm — `ou=trustAnchors` (which is the client-certificate
// truststore), `ou=federations` (whose signing certificates decide whose
// assertions this service believes), `ou=policies`, `ou=roles` and every
// person. And one write was an escalation rather than a vandalism:
// `admin_rbac.js` reads a person's OWN `memberOf` when it decides whether they
// hold a console role, so `memberOf: cn=admin-write,…` on your own entry made
// you an administrator of the whole service.
//
// **THE RULE IS THREE LINES.**
//
//   * an ANONYMOUS connection writes nothing;
//   * an ADMINISTRATOR writes anything — somebody whose bound DN names an entry
//     in the DEFAULT realm's directory whose identity holds Admin Write;
//   * anybody else may MODIFY THEIR OWN ENTRY, and only the attributes
//     `ldap.selfWritableAttributes` names. No add, no delete, no rename.
//
// **ADMIN WRITE AND NOT A GROUP OF THE DIRECTORY'S OWN.** The console, the
// management API and SCIM's write scope already answer "who may change what
// this service holds", and a second roster for the socket would be a second
// answer that drifts from the first the day somebody is granted one and not the
// other. **THE DEFAULT REALM ONLY**, for the reason the roster itself is pinned
// there: a person in `acme` sharing a name with a default-realm administrator
// is a different person, and anybody who can provision a realm can provision
// one.
//
// **THE CONSOLE'S EMPTY-ROSTER RULE DOES NOT COUNT HERE.** While no role group
// has a member `rolesOf()` may answer that everybody holds both
// (`admin.openWhenEmpty`); that is the console being reachable at all on a
// fresh service. Carried over, it would make every bound connection an
// administrator of the directory on exactly the deployment nobody has set up,
// so a role held only through `open` is not a role here.
//
// **THE ALLOWLIST IS AN ALLOWLIST** because this directory is schemaless — a
// client can write any attribute name at all — and the names that matter look
// ordinary: `memberOf` grants the console roles, `employeeType` is what the
// seeded XACML policy decides on, `mail` and `cn` are asserted in every token
// as facts this service vouches for, and every `sts*` attribute is a
// credential. A list of what is refused would be complete on the day it was
// written. `userPassword` is on the default list and still meets the password
// policy in `passwordWriteRefusal()`, exactly as at every other door.
//
// **PRODUCT MODE ONLY** (`mode.authorizesDirectoryWrites()`). Development binds
// any DN with any password, so the bound DN proves nothing and a check keyed on
// it would refuse the suite while protecting nothing.
//
// **ASKED BEFORE WHETHER THE TARGET EXISTS**, so a connection that may not
// write an entry cannot learn from the refusal whether it is there.
//
// Answers null or the ldapjs error, already recorded, to hand to `next()`.
// `changedTypes` is the lower-cased attribute names a modify touches, and is
// ignored for the other three operations.
// ---------------------------------------------------------------------------
function selfWritableAttributes() {
  log.debug("Entering selfWritableAttributes().");
  const listed = config.value('ldap.selfWritableAttributes');
  log.debug("Leaving selfWritableAttributes().");
  return (Array.isArray(listed) ? listed : String(listed || '').split(','))
    .map(function (name) { return String(name).trim().toLowerCase(); })
    .filter(function (name) { return name.length > 0; });
}

// Whether the entry this bound DN names holds Admin Write, asked in the DEFAULT
// realm whichever realm the operation is in. A DN under another realm's base is
// never an administrator, and a role held only because the roster is empty is
// not one either (see above).
function boundDnIsDirectoryAdministrator(boundDn) {
  log.debug('Entering boundDnIsDirectoryAdministrator(). dn=' + boundDn);
  if (!boundDn) {
    log.debug('Leaving boundDnIsDirectoryAdministrator(). Nobody is bound.');
    return false;
  }
  // NO SEPARATE "IS THIS DN IN THE DEFAULT REALM" TEST, and that is not an
  // omission. The lookup below runs in the default realm's STORE, and a DN
  // under another realm's base is never an entry there — the stores are one per
  // realm, not subtrees of one. A realm check written in front of it was
  // mutation-tested and could change no answer, so it was removed rather than
  // left looking like the thing that decides.
  const answer = inDefaultRealm(function () {
    const stored = getEntry(boundDn);
    if (!stored) {
      return false;
    }
    const roles = adminRbac.rolesOf(consoleKeyFor(stored.dn, stored),
                                    realms.DEFAULT_ID);
    return roles.write === true && roles.open !== true;
  })();
  log.debug('Leaving boundDnIsDirectoryAdministrator(). ' + answer);
  return answer;
}

// A REALM'S OWN ADMINISTRATOR (2026-09-14, #32): a bound DN in the realm the
// operation is in, holding Admin Write in THAT realm's roster, may write that
// realm's directory and no other. The operation's store is the ambient realm's,
// so a DN bound under another realm is simply not an entry here, which is the
// same argument the default-realm check above makes one realm along.
function boundDnIsRealmAdministrator(boundDn) {
  log.debug('Entering boundDnIsRealmAdministrator(). dn=' + boundDn);
  const here = realms.currentId();
  if (!boundDn || here === realms.DEFAULT_ID) {
    log.debug('Leaving boundDnIsRealmAdministrator(). Not a realm operation.');
    return false;
  }
  const stored = getEntry(boundDn);
  if (!stored) {
    log.debug('Leaving boundDnIsRealmAdministrator(). Not in this realm.');
    return false;
  }
  const roles = adminRbac.rolesOf(consoleKeyFor(stored.dn, stored), here);
  const answer = roles.write === true && roles.open !== true;
  log.debug('Leaving boundDnIsRealmAdministrator(). ' + answer);
  return answer;
}

function directoryWriteRefusal(req, operation, dn, changedTypes) {
  log.debug('Entering directoryWriteRefusal(). ' + operation + ' ' + dn);
  if (!mode.authorizesDirectoryWrites()) {
    log.debug('Leaving directoryWriteRefusal(). This mode does not authorize ' +
              'writes.');
    return null;
  }
  const boundDn = boundDnOf(req);
  if (!boundDn) {
    log.info('ldap: refusing an anonymous ' + operation + ' of ' + dn + '.');
    log.debug('Leaving directoryWriteRefusal(). Anonymous.');
    return ldapRefusal(req, 'STS-LDAP-0052', 'an anonymous connection asked ' +
      'for a ' + operation + ' of ' + dn,
      new ldap.InsufficientAccessRightsError(
        'an anonymous connection may not write this directory; bind first'),
      dn);
  }
  if (boundDnIsDirectoryAdministrator(boundDn) ||
      boundDnIsRealmAdministrator(boundDn)) {
    log.debug('Leaving directoryWriteRefusal(). An administrator.');
    return null;
  }
  const own = operation === 'modify' &&
              normalizeDn(boundDn) === normalizeDn(dn) &&
              getEntry(dn) && isPersonEntry(getEntry(dn));
  if (!own) {
    log.info('ldap: refusing a ' + operation + ' of ' + dn + ' by ' + boundDn +
             ', who does not hold Admin Write.');
    log.debug('Leaving directoryWriteRefusal(). Not an administrator.');
    return ldapRefusal(req, 'STS-LDAP-0053', boundDn + ' asked for a ' +
      operation + ' of ' + dn + ' without holding Admin Write',
      new ldap.InsufficientAccessRightsError(
        operation === 'modify'
          ? 'only an administrator may modify an entry other than your own'
          : 'only an administrator may ' + operation + ' an entry'), dn);
  }
  const allowed = selfWritableAttributes();
  const refused = (changedTypes || []).filter(function (type, index, all) {
    return allowed.indexOf(type) < 0 && all.indexOf(type) === index;
  });
  if (refused.length) {
    log.info('ldap: refusing ' + boundDn + ' a change to ' +
             refused.join(', ') +
             ' on their own entry; ldap.selfWritableAttributes does not name ' +
             'it.');
    log.debug('Leaving directoryWriteRefusal(). An attribute is not ' +
              'self-writable.');
    return ldapRefusal(req, 'STS-LDAP-0054', boundDn + ' asked to change ' +
      refused.join(', ') + ' on their own entry, which is not self-writable',
      new ldap.InsufficientAccessRightsError(
        'you may not change ' + refused.join(', ') + ' on your own entry'), dn);
  }
  log.debug('Leaving directoryWriteRefusal(). A permitted change to their ' +
            'own entry.');
  return null;
}

// ---------------------------------------------------------------------------
// THE DIRECTORY'S READ AND BIND SECURITY (2026-09-12).
//
// node-ldapjs decides nothing about who may do what. It records the DN a
// successful bind named on the connection (`conn.ldap.bindDN`, `cn=anonymous`
// until then) and leaves every question after that to these handlers — no
// access control, no attribute visibility, no rule about which listener a
// password may cross, no limit on guesses. `directoryWriteRefusal()` above is
// the write half. This is the rest, and all of it is PRODUCT MODE ONLY, for
// that function's reason: development binds any DN with any password, so a
// bound DN proves nothing there.
//
// **A READ REQUIRES A BIND** (`mode.requiresDirectoryBind()`). A search or
// compare on a connection that never bound as somebody is refused with
// insufficientAccessRights (50) — asked BEFORE whether the target exists, so
// the refusal says nothing about the tree. **THE ROOT DSE IS THE EXCEPTION**
// and has to be: a client reads it to learn the naming contexts before it knows
// where to bind, and a server with no answer there looks like a server that is
// down. Anonymous and unauthenticated binds are refused at the bind handler, so
// what a connection can be is "bound as somebody" or "not bound at all".
//
// **CREDENTIALS NEVER LEAVE ON THE WIRE** (`mode.withholdsDirectorySecrets()`).
// `SECRET_ATTRIBUTES` is a LIST rather than a rule because the directory is
// schemaless and the names that matter look ordinary. Three doors, and the
// second is the one a naive implementation misses:
//
//   * a search never RETURNS one (`toSearchEntry()`);
//   * a search FILTER cannot see one (`matchableForReader()`) — otherwise
//     `(oauthClientSecret=a*)`, then `(oauthClientSecret=ab*)`, reads a secret
//     one character at a time off whether an entry came back. An attribute the
//     reader may not see is absent to the filter, which is how a directory with
//     access control evaluates a term naming it (Undefined, so no match);
//   * a COMPARE against one is refused, because a compare IS an oracle — it
//     answers "is this the password" without a bind, and with no rate limit.
//
// **AN ADMINISTRATOR IS NOT EXCEPTED.** The console, the management API and
// every protocol read these through this module's functions and never through
// a search, so nothing that needs a credential is behind this — and a socket
// that handed an administrator every client secret in the directory is a socket
// whose one stolen administrator password is every application's.
//
// **OPERATIONAL ATTRIBUTES ARE THE DIRECTORY'S TO WRITE**
// (`mode.protectsOperationalAttributes()`): createTimestamp, modifyTimestamp
// and entryDN are refused on an add or a modify with constraintViolation (19),
// which is what RFC 4512 section 3.3.1's NO-USER-MODIFICATION attributes answer
// — administrator included, because a timestamp anybody can set is not
// evidence. pwdHistory and pwdChangedTime are refused by
// `passwordWriteRefusal()` already.
// ---------------------------------------------------------------------------
const SECRET_ATTRIBUTES = [
  'userpassword', 'pwdhistory',
  'oauthclientsecret', 'appregistrationaccesstoken', 'fedclientsecret',
  'oauthassertionprivatekey', 'oauthsamlassertionprivatekey',
  'stsassertionprivatekey', 'stssamlassertionprivatekey',
  'ststotpcredential', 'stsbackupcodes', 'stsactivationtoken',
  // A password reset link's hash (2026-09-13), for the activation token's
  // reason beside it.
  'stspasswordresettoken',
  'stskrb5keys', 'krb5servicekeys',
  // Certificate enrollment (2026-09-13): a private key this service generated
  // for an enrolled certificate, an ACME EAB key and a SCEP challenge record.
  'stsenrolledprivatekey', 'appenrolledprivatekey',
  'stsacmeeabkey', 'appacmeeabkey', 'stsscepchallenge', 'appscepchallenge',
  // GNAP (2026-09-12): a client's shared secret for a key reference, and a
  // resource server's macaroon root key. Either one mints a working credential.
  'gnapsymmetrickey', 'gnapmacaroonkey'
];

const CLIENT_WRITTEN_OPERATIONAL = ['createtimestamp', 'modifytimestamp',
                                    'entrydn', 'entryuuid', ENTRY_UUID_ALIAS];

// The operational attributes refused in EVERY mode (2026-09-14). `entryUUID`
// is a person's `sub`; a client that could write one could make their entry
// the subject of somebody else's tokens, which is not a development-mode
// convenience but an identity theft with a result code.
const ALWAYS_PROTECTED_OPERATIONAL = ['entryuuid', ENTRY_UUID_ALIAS];

function isSecretAttribute(name) {
  log.debug("Entering isSecretAttribute().");
  log.debug("Leaving isSecretAttribute().");
  return SECRET_ATTRIBUTES.indexOf(String(name || '').toLowerCase()) !== -1;
}

// Whether THIS reader of the socket is refused sight of an attribute. One
// question, asked by all three doors, so they cannot disagree.
function withheldFromReaders(name) {
  log.debug("Entering withheldFromReaders().");
  log.debug("Leaving withheldFromReaders().");
  return mode.withholdsDirectorySecrets() && isSecretAttribute(name);
}

// `matchable()` as a READER of the socket may see it. A separate function
// rather than a flag on that one, because `matchable()` has callers that are
// not a reader on the wire.
function matchableForReader(stored) {
  log.debug("Entering matchableForReader().");
  const out = matchable(stored);
  if (!mode.withholdsDirectorySecrets()) {
    log.debug("Leaving matchableForReader().");
    return out;
  }
  Object.keys(out).forEach(function (name) {
    if (isSecretAttribute(name)) {
      delete out[name];
    }
  });
  log.debug("Leaving matchableForReader().");
  return out;
}

// A search or compare on a connection that has not bound as anybody. Answers
// null or the recorded ldapjs error. The root DSE is never refused here — the
// search handler answers it before this is asked.
//
// **ONE READ IS ALLOWED UNBOUND, IN BOTH MODES AND ON BOTH LISTENERS: A BASE
// SEARCH OF A CRL ENTRY (2026-09-13).** Every certificate this service issues
// names an `ldap://` CRL distribution point, and the relying party that follows
// it holds no credential for this directory and never will — RFC 4523's
// `cRLDistributionPoint` exists to be read anonymously, which is how every CA
// directory publishes one. Product mode refused it: the plain listener binds
// nobody (13) and a read needs a bind (50), so the one LDAP address a
// certificate carries answered a refusal to exactly the reader it was written
// for. A CRL is a SIGNED PUBLIC DOCUMENT — the HTTP distribution point beside it
// is ungated in every mode for that reason — so what is exempted is that and
// nothing wider: base scope, an entry of class `cRLDistributionPoint` under an
// `ou=crl` container. A one-level or subtree search, a compare, and a search of
// anything else still need the bind.
function isCrlDistributionEntry(req, operation, dn) {
  log.debug("Entering isCrlDistributionEntry().");
  if (operation !== 'search' || !req || scopeOf(req) !== 'base' ||
      !/,ou=crl,/i.test(normalizeDn(dn))) {
    log.debug("Leaving isCrlDistributionEntry(). Not a base read of ou=crl.");
    return false;
  }
  const entry = getEntry(dn);
  const classes = entry ? valuesOf(entry.attributes.objectclass) : [];
  log.debug("Leaving isCrlDistributionEntry().");
  return classes.some(function (one) {
    return String(one).toLowerCase() === 'crldistributionpoint';
  });
}

function directoryReadRefusal(req, operation, dn) {
  log.debug('Entering directoryReadRefusal(). ' + operation + ' ' + dn);
  if (!mode.requiresDirectoryBind() || boundDnOf(req)) {
    log.debug('Leaving directoryReadRefusal(). Allowed.');
    return null;
  }
  if (isCrlDistributionEntry(req, operation, dn)) {
    log.debug('Leaving directoryReadRefusal(). A CRL, which is public.');
    return null;
  }
  log.info('ldap: refusing an unauthenticated ' + operation + ' of ' + dn +
           '; product mode requires a bind before a read.');
  log.debug('Leaving directoryReadRefusal(). Not bound.');
  return ldapRefusal(req, 'STS-LDAP-0074', 'a ' + operation + ' of ' + dn +
    ' arrived on a connection that has not bound as anybody',
    new ldap.InsufficientAccessRightsError(
      'bind as somebody before reading this directory'), dn);
}

// A compare that names a credential attribute.
function secretCompareRefusal(req, dn, type) {
  log.debug("Entering secretCompareRefusal().");
  if (!withheldFromReaders(type)) {
    log.debug("Leaving secretCompareRefusal().");
    return null;
  }
  log.info('ldap: refusing a compare of ' + type + ' on ' + dn +
           '; credential attributes cannot be compared over this socket.');
  log.debug("Leaving secretCompareRefusal().");
  return ldapRefusal(req, 'STS-LDAP-0075', 'a compare on ' + dn + ' named ' +
    type + ', a credential attribute no reader of this socket may test',
    new ldap.InsufficientAccessRightsError(
      type + ' cannot be compared over LDAP'), dn);
}

// An add or modify naming an attribute this directory maintains itself.
// `types` is the lower-cased attribute names the operation writes.
function operationalWriteRefusal(req, operation, dn, types) {
  log.debug('Entering operationalWriteRefusal(). ' + operation + ' ' + dn);
  const protectedHere = mode.protectsOperationalAttributes()
    ? CLIENT_WRITTEN_OPERATIONAL : ALWAYS_PROTECTED_OPERATIONAL;
  const named = (types || []).filter(function (type, index, all) {
    return protectedHere.indexOf(type) !== -1 &&
           all.indexOf(type) === index;
  });
  if (!named.length) {
    log.debug('Leaving operationalWriteRefusal(). None named.');
    return null;
  }
  log.info('ldap: refusing a ' + operation + ' of ' + dn + ' that writes ' +
           named.join(', ') + ', which this directory maintains itself.');
  log.debug('Leaving operationalWriteRefusal(). Refused.');
  return ldapRefusal(req, 'STS-LDAP-0076', 'a ' + operation + ' of ' + dn +
    ' named ' + named.join(', ') + ', which this directory maintains itself',
    new ldap.ConstraintViolationError(
      named.join(', ') + ' is maintained by this directory and cannot be ' +
                         'written'),
    dn);
}

// What `websecurity` counts a bind against: the connection's address, which is
// on the real socket and on the dispatched stub alike (`operationRequest()`
// carries it). An empty address would put every dispatched bind in one bucket,
// and one attacker would lock out everybody.
function limiterRequestOf(req) {
  log.debug("Entering limiterRequestOf().");
  const connection = (req && req.connection) || {};
  log.debug("Leaving limiterRequestOf().");
  return { headers: {},
           socket: { remoteAddress: String(connection.remoteAddress ||
                                           'unknown') } };
}

// `options.history`, when given, is the WHOLE history to leave on the entry —
// an empty array removes the attribute — and `pwdChangedTime` is stamped with
// it. When it is NOT given the history is left exactly as it was, so a caller
// that predates the policy writes a password and nothing else.
function writeStoredPassword(key, hashed, options) {
  log.debug('Entering writeStoredPassword(). key=' + key);
  const opts = options || {};
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    // NOT created here, and that is product mode's second requirement working
    // rather than a limitation: setting a password for somebody who does not
    // exist would create them, which is exactly what product mode refuses.
    log.warn(errorCodes.tag('STS-LDAP-0040') +
             'ldap: "' + key + '" has no entry in this realm, so no ' +
             'credential was written. In product mode every referenced ' +
             'object must be created ahead of time.');
    log.debug('Leaving writeStoredPassword(). No entry.');
    return false;
  }
  // REPLACED and not added: an entry with two `userPassword` values is an entry
  // where the old password still works, which is the whole of what changing one
  // is meant to stop.
  stored.attributes.userpassword = [String(hashed)];
  if (Array.isArray(opts.history)) {
    if (opts.history.length) {
      stored.attributes.pwdhistory = opts.history.map(String);
    } else {
      // LDAP has no empty attribute (RFC 4511 section 4.1.7), so a history
      // that is kept at nothing is an attribute that is not there.
      delete stored.attributes.pwdhistory;
    }
    stored.attributes.pwdchangedtime = [generalizedTime()];
  }
  // ONE touch for the password and its history together: one logical change,
  // one version bump, one scheduled persistence write — the rule
  // `applyVcAttributes()` learnt the expensive way.
  touchDirectory();
  log.debug('Leaving writeStoredPassword(). Written to ' + stored.dn + '.');
  return true;
}

// TAKE THE PASSWORD OFF AN ENTRY (2026-09-13). What issuing a password reset
// link does to the password the person had: after it, nothing verifies against
// this entry until the link sets a new one. `options.history` is the history
// `credentials.js` computed with the removed hash on the front, so the password
// the administrator took away cannot simply be chosen again through the link.
// `pwdChangedTime` is stamped, because a password going away is a change to it.
// It answers false for an entry that is not here, like the writer above.
function clearStoredPassword(key, options) {
  log.debug('Entering clearStoredPassword(). key=' + key);
  const opts = options || {};
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    log.debug('Leaving clearStoredPassword(). No entry.');
    return false;
  }
  delete stored.attributes.userpassword;
  if (Array.isArray(opts.history)) {
    if (opts.history.length) {
      stored.attributes.pwdhistory = opts.history.map(String);
    } else {
      delete stored.attributes.pwdhistory;
    }
  }
  stored.attributes.pwdchangedtime = [generalizedTime()];
  touchDirectory();
  log.debug('Leaving clearStoredPassword(). Removed from ' + stored.dn + '.');
  return true;
}

// DOES ANYBODY IN THIS REALM HOLD ONE? What the product-mode bootstrap asks
// before it creates anything — the question is "can somebody get in", not "does
// the admin account exist", so a deployment whose administrator is called
// something else does not get a second one created beside them.
function anybodyHoldsACredential() {
  log.debug('Entering anybodyHoldsACredential().');
  // `eachEntryInRealm()` and not a walk of the store: it is this module's one
  // iterator and it is scoped to the AMBIENT realm, which is what makes the
  // bootstrap a per-realm question. A new realm switched to product mode gets
  // its own bootstrap account rather than being judged by the default realm's.
  let found = false;
  eachEntryInRealm(function (entry) {
    if (found) return;
    if (entry && entry.attributes &&
        (entry.attributes.userpassword || []).length > 0) {
      found = true;
    }
  });
  log.debug('Leaving anybodyHoldsACredential(). ' + (found ? 'Yes.' : 'No.'));
  return found;
}

// ---------------------------------------------------------------------------
// THE SECURITY KEYS, ON THE SAME ENTRY AS THE PASSWORD (2026-09-06).
//
// MULTI-VALUED, because a person may hold several — a laptop and a phone is the
// ordinary case and is why WebAuthn has a credential id at all. Each value is
// one JSON record carrying the credential id, the public key, the signature
// counter and the ROLE (primary or mfa).
//
// **THE PUBLIC KEY IS NOT HASHED AND MUST NOT BE.** That is the one place this
// departs from `userPassword` beside it: a WebAuthn public key is published by
// design — the whole point of the scheme is that what the verifier holds is
// useless to an attacker — so hashing it would make it useless for the only
// thing it is for.
// ---------------------------------------------------------------------------
function readWebauthnValues(key) {
  log.debug('Entering readWebauthnValues(). key=' + key);
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    log.debug('Leaving readWebauthnValues(). No entry.');
    return [];
  }
  const values = (stored.attributes.stswebauthncredential || []).slice(0);
  log.debug('Leaving readWebauthnValues(). ' + values.length + ' key(s).');
  return values;
}

function writeWebauthnValue(key, value) {
  log.debug('Entering writeWebauthnValue(). key=' + key);
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    log.warn(errorCodes.tag('STS-LDAP-0040') +
             'ldap: "' + key + '" has no entry in this realm, so no security ' +
             'key was recorded.');
    log.debug('Leaving writeWebauthnValue(). No entry.');
    return false;
  }
  // ADDED and not replaced — a second key is a second key, not a replacement
  // for the first, which is the whole reason the attribute is multi-valued.
  const have = stored.attributes.stswebauthncredential || [];
  stored.attributes.stswebauthncredential = have.concat([String(value)]);
  touchDirectory();
  log.debug('Leaving writeWebauthnValue(). Written to ' + stored.dn + '.');
  return true;
}

// The whole set at once — what a counter update and a removal both need, since
// each rewrites every value.
function replaceWebauthnValues(key, values) {
  log.debug('Entering replaceWebauthnValues(). key=' + key);
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    log.debug('Leaving replaceWebauthnValues(). No entry.');
    return false;
  }
  if (!values || !values.length) {
    delete stored.attributes.stswebauthncredential;
  } else {
    stored.attributes.stswebauthncredential = values.map(String);
  }
  touchDirectory();
  log.debug('Leaving replaceWebauthnValues(). ' +
            ((values || []).length) + ' key(s) left.');
  return true;
}

// ---------------------------------------------------------------------------
// THE AUTHENTICATOR APP'S SHARED SECRET (2026-09-10).
//
// **SINGLE-VALUED, WHERE THE SECURITY KEY BESIDE IT IS MULTI-VALUED.** A
// WebAuthn assertion names the credential that produced it; a TOTP code is six
// digits and names nothing, so a second secret would mean trying both and would
// leave RFC 6238 section 5.2's replay guard with no answer to *which counter
// was spent*. `common/credentials.js` argues it; this function is the half that
// makes it true of the store — `writeTotp()` ASSIGNS, so enrolling again
// replaces.
//
// **THIS IS THE ONE ATTRIBUTE IN THIS DIRECTORY THAT MAY HOLD A USABLE
// CREDENTIAL IN THE CLEAR**, and the reason is arithmetic rather than a lapse:
// verifying a code means COMPUTING it, so the secret cannot be hashed the way
// `userPassword` and `stsActivationToken` are. In product mode it arrives here
// already sealed under the key-encryption key — that is `credentials.js`'s
// doing and not this function's, which is right, because what is sealed is a
// question about the KEY and this module has none.
//
// A `null` value DELETES, which is what an operator's Clear on that person's
// row under `/admin/users` and
// a person's own removal on `/portal/mfa` both come down to.
// ---------------------------------------------------------------------------
function readTotp(key) {
  log.debug('Entering readTotp(). key=' + key);
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    log.debug('Leaving readTotp(). No entry.');
    return '';
  }
  const value = (stored.attributes.ststotpcredential || [])[0];
  log.debug('Leaving readTotp(). ' + (value ? 'Enrolled.' : 'None.'));
  return value ? String(value) : '';
}

function writeTotp(key, value) {
  log.debug('Entering writeTotp(). key=' + key);
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    // NOT created here, for `writeStoredPassword()`'s reason: enrolling a
    // credential for somebody who does not exist would create them, and
    // product mode refuses exactly that.
    log.warn(errorCodes.tag('STS-LDAP-0040') +
             'ldap: "' + key + '" has no entry in this realm, so no ' +
             'authenticator enrolment was recorded.');
    log.debug('Leaving writeTotp(). No entry.');
    return false;
  }
  if (value === null || value === undefined || value === '') {
    delete stored.attributes.ststotpcredential;
  } else {
    // ASSIGNED and not appended — see the header. Two values would be two
    // secrets and a code that names neither.
    stored.attributes.ststotpcredential = [String(value)];
  }
  touchDirectory();
  log.debug('Leaving writeTotp(). ' +
            (value ? 'Written to ' : 'Removed from ') + stored.dn + '.');
  return true;
}

// ---------------------------------------------------------------------------
// THE RECOVERY CODES (2026-09-10).
//
// **SINGLE-VALUED, LIKE THE AUTHENTICATOR SECRET ABOVE AND UNLIKE THE SECURITY
// KEYS.** The value is one JSON object carrying the whole set — a sealed (or
// plain) list of codes, and the counts beside it in the clear so that a page
// can say *7 of 10 unused* without opening anything. `writeBackupCodes()`
// ASSIGNS, so a person holds one set and never two: `common/credentials.js`
// issues a set exactly once and an operator's Clear is the only way to
// another, and two values would make *which set am I holding* a question with
// no answer.
//
// **THIS IS THE SECOND ATTRIBUTE IN THIS DIRECTORY THAT MAY HOLD A USABLE
// CREDENTIAL IN THE CLEAR**, and the reason is different from the first one's.
// A TOTP secret cannot be hashed because verifying a code means COMPUTING it —
// that is arithmetic. A recovery code COULD be hashed, and is not, because a
// person may look at their remaining codes again and a hash cannot be shown.
// `common/backup_codes.js` argues the trade at length. In product mode it
// arrives here already sealed, which is that module's doing and not this
// function's — right, because what is sealed is a question about the KEY and
// this module has none.
//
// A `null` value DELETES, which is what an operator's Clear on that person's
// row under `/admin/users` comes down to. There is deliberately no
// self-service removal: a way back that the person themselves can throw away
// is one they throw away by accident.
// ---------------------------------------------------------------------------
function readBackupCodes(key) {
  log.debug('Entering readBackupCodes(). key=' + key);
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    log.debug('Leaving readBackupCodes(). No entry.');
    return '';
  }
  const value = (stored.attributes.stsbackupcodes || [])[0];
  log.debug('Leaving readBackupCodes(). ' + (value ? 'Issued.' : 'None.'));
  return value ? String(value) : '';
}

function writeBackupCodes(key, value) {
  log.debug('Entering writeBackupCodes(). key=' + key);
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    // NOT created here, for `writeTotp()`'s reason: writing a credential for
    // somebody who does not exist would create them, and product mode refuses
    // exactly that.
    log.warn(errorCodes.tag('STS-LDAP-0040') +
             'ldap: "' + key + '" has no entry in this realm, so no recovery ' +
             'codes were recorded.');
    log.debug('Leaving writeBackupCodes(). No entry.');
    return false;
  }
  if (value === null || value === undefined || value === '') {
    delete stored.attributes.stsbackupcodes;
  } else {
    // ASSIGNED and not appended — see the header. Two values would be two
    // sets and no way to say which one a person is holding.
    stored.attributes.stsbackupcodes = [String(value)];
  }
  touchDirectory();
  log.debug('Leaving writeBackupCodes(). ' +
            (value ? 'Written to ' : 'Removed from ') + stored.dn + '.');
  return true;
}

// THE ACTIVATION TOKEN, hashed. It is the one credential in this service that
// completes an account setup on its own, so a leaked one is an account
// takeover — which is why it is stored the way a password is and never in the
// clear.
function readActivation(key) {
  log.debug("Entering readActivation().");
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    log.debug("Leaving readActivation().");
    return null;
  }
  const hash = (stored.attributes.stsactivationtoken || [])[0];
  if (!hash) {
    log.debug("Leaving readActivation().");
    return null;
  }
  log.debug("Leaving readActivation().");
  return { hash: String(hash),
           expires: Number((stored.attributes.stsactivationexpires ||
                            [])[0] || 0) };
}

function writeActivation(key, hash, expires) {
  log.debug("Entering writeActivation().");
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    log.debug("Leaving writeActivation().");
    return false;
  }
  if (!hash) {
    delete stored.attributes.stsactivationtoken;
    delete stored.attributes.stsactivationexpires;
  } else {
    stored.attributes.stsactivationtoken = [String(hash)];
    stored.attributes.stsactivationexpires = [String(expires)];
  }
  touchDirectory();
  log.debug("Leaving writeActivation().");
  return true;
}

// The EIGHTH slot. Guarded like the seven above: an older
// `common/credentials.js` without it costs a warning rather than a service that
// will not start — and the warning says what is lost, which in product mode is
// every sign-in.
if (typeof credentials.setDirectory === 'function') {
  credentials.setDirectory({
    readPassword: readStoredPassword,
    writePassword: writeStoredPassword,
    // The password history (2026-09-12). Checked where it is used, like the
    // pairs below: an older `common/credentials.js` still gets a working
    // password write, and simply keeps no history.
    readPasswordHistory: readPasswordHistory,
    anyCredential: anybodyHoldsACredential,
    readWebauthn: readWebauthnValues,
    writeWebauthn: writeWebauthnValue,
    replaceWebauthn: replaceWebauthnValues,
    readActivation: readActivation,
    writeActivation: writeActivation,
    // The authenticator app (2026-09-10). Checked WHERE THEY ARE USED rather
    // than in `setDirectory()`'s required list, exactly as the security-key
    // and activation functions are: an older `common/credentials.js` that
    // knows nothing about them still gets a working password sign-in.
    readTotp: readTotp,
    writeTotp: writeTotp,
    // The recovery codes (2026-09-10). Checked WHERE THEY ARE USED for the
    // reason the pair above is: an older `common/credentials.js` that knows
    // nothing about them still gets a working password sign-in, and
    // `ensureBackupCodes()` reports `no-store` rather than throwing.
    readBackupCodes: readBackupCodes,
    writeBackupCodes: writeBackupCodes,
    // WHO IS IN THIS REALM, for `secondFactorHolders()` — the operator's view
    // on `/admin/users`. It hands over NAMES and not entries, deliberately:
    // what the credential store needs is a list to ask itself about, and
    // handing it whole entries would let a caller start reading attributes off
    // them, which is how a second implementation of *what an enrolment is* gets
    // written.
    //
    // It is the AMBIENT realm's, unlike the nine functions `admin_rbac.js`
    // takes: those decide who may administer the service and are pinned to the
    // default realm on purpose, and this one is a page LOOKING AT a realm.
    persons: function () {
      log.debug("Entering persons().");
      log.debug("Leaving persons().");
      return allPersons().map(function (entry) {
        return usernameOfEntry(entry);
      }).filter(function (name) { return !!name; });
    },
    // **THE ONE EXCEPTION TO "PRODUCT MODE CREATES NOTHING", AND IT IS NARROW
    // ON PURPOSE.** `createUser()` is this module's ordinary door and is not
    // mode-gated — it is what the console and /admin-api call, and an operator
    // creating somebody deliberately is the opposite of an object appearing
    // because a protocol named it. What is passed here is that same function,
    // and the only caller is `credentials.bootstrap()`, which runs once,
    // before the listener binds, and only when NOBODY in the realm holds a
    // credential.
    //
    // Without it the bootstrap is caught by the rule it exists to break: a
    // fresh product deployment has an empty directory, so the account that
    // would be given the generated password does not exist, and product mode
    // refuses to create it. The service then starts with every door shut and
    // no way through any of them.
    createPerson: function (name) {
      log.debug("Entering createPerson().");
      log.debug("Leaving createPerson().");
      return createUser(name, {});
    },
    // A PASSWORD THAT MUST BE CHANGED (2026-09-13): `pwdReset` on the person's
    // own entry, in the AMBIENT realm like the password itself.
    readPasswordReset: function (key) {
      log.debug("Entering readPasswordReset().");
      const flags = readPersonFlags(key);
      log.debug("Leaving readPasswordReset().");
      return !!(flags && flags.pwdReset);
    },
    writePasswordReset: function (key, value) {
      log.debug("Entering writePasswordReset().");
      log.debug("Leaving writePasswordReset().");
      return writePersonFlag(key, 'pwdReset', value ? true : '');
    },
    // A SECOND FACTOR REQUIRED OF ONE PERSON (2026-09-13), in the ambient
    // realm like the rest of their credentials.
    readMfaRequired: function (key) {
      log.debug("Entering readMfaRequired().");
      const flags = readPersonFlags(key);
      log.debug("Leaving readMfaRequired().");
      return !!(flags && flags.mfaRequired);
    },
    writeMfaRequired: function (key, value) {
      log.debug("Entering writeMfaRequired().");
      log.debug("Leaving writeMfaRequired().");
      return writePersonFlag(key, 'stsMfaRequired', value ? true : '');
    },
    // A PASSWORD RESET LINK (2026-09-13): the hash and the expiry, written and
    // cleared together, which is `writeActivation()`'s shape.
    readPasswordResetLink: function (key) {
      log.debug("Entering readPasswordResetLink().");
      const flags = readPersonFlags(key);
      log.debug("Leaving readPasswordResetLink().");
      return flags && flags.passwordResetToken
        ? { hash: flags.passwordResetToken,
            expires: flags.passwordResetExpires }
        : null;
    },
    writePasswordResetLink: function (key, hash, expires) {
      log.debug("Entering writePasswordResetLink().");
      if (!hash) {
        const cleared = writePersonFlag(key, 'stsPasswordResetToken', '') &&
                        writePersonFlag(key, 'stsPasswordResetExpires', '');
        log.debug("Leaving writePasswordResetLink(). Cleared.");
        return cleared;
      }
      const written =
        writePersonFlag(key, 'stsPasswordResetToken', String(hash)) &&
        writePersonFlag(key, 'stsPasswordResetExpires', String(expires));
      log.debug("Leaving writePasswordResetLink(). Written.");
      return written;
    },
    // TAKING A PASSWORD AWAY (2026-09-13), for a reset link that revokes the
    // one the person had. `clearStoredPassword()` below says what it keeps.
    clearPassword: clearStoredPassword,
    // IS THERE AN ENTRY AT ALL (2026-09-13)? `readPassword()` answers '' for
    // an absent entry and for one with no password alike, so a credential
    // action that must refuse "nobody by that name" asks this instead.
    personExists: function (key) {
      log.debug("Entering personExists().");
      const found = !!readPersonFlags(key);
      log.debug("Leaving personExists(). " + found);
      return found;
    }
  });

// ---------------------------------------------------------------------------
// THE USER PORTAL'S OWN SLOT (2026-09-11), and it is the FIRST one that
// application has ever offered.
//
// `/portal`'s Overview answers *what does this identity provider hold about
// me*, and it had been answering out of the SESSION — four facts a sign-in
// happened to carry. It draws the person's real entry now, against the fixed
// list in `common/inetorgperson.js`.
//
// **IT IS A SLOT FOR THE ORDINARY REASON AND THE DIRECTION IS THE INTERESTING
// HALF.** `portal/portal.js` sits at 8b and this module at 21, so a require
// from there to here would register every `/ldap` route and the eight
// `/admin/ldap/*` pages ahead of the authorization server and the console
// (rule 1); a require from here to there would move every `/portal` route
// behind the management API. Rule 3e's test answers yes both ways round, which
// is what a slot is for.
//
// **IT HANDS OVER THE WHOLE ENTRY, WHERE `credentials.persons()` ABOVE
// DELIBERATELY HANDS OVER ONLY NAMES**, and the difference is worth reading
// beside it. That one is handing a list to a module which must not start
// reading attributes off entries, because that is how a second implementation
// of *what an enrolment is* gets written. This one's whole purpose IS the
// attributes — and what stops the portal reading something it should not is
// not the shape of this hook but the FIXED LIST at the other end, which has no
// `sts`-prefixed credential on it and cannot grow one by accident.
//
// Guarded like the rest: an older `portal/portal.js` without the slot costs a
// warning rather than a service that will not start, and the warning says what
// is lost.
// ---------------------------------------------------------------------------
if (typeof portal.setDirectory === 'function') {
  portal.setDirectory({
    // **THE AMBIENT REALM'S**, like `credentials.persons()` above and unlike
    // the RBAC functions: a person reading their own account page is reading
    // it in the realm they signed in to, and a realm is a logical copy of this
    // service with its own people.
    personEntry: function (username) {
      log.debug('Entering personEntry(). username=' + username);
      const located = locateEntry(String(username || ''));
      if (!located.stored) {
        log.debug('Leaving personEntry(). Nothing at ' + located.dn + '.');
        return null;
      }
      log.debug('Leaving personEntry(). ' +
                Object.keys(located.stored.attributes).length +
                ' attribute(s) at ' + located.stored.dn + '.');
      // The stored map itself is not handed over — a caller holding it could
      // write through it, and this module's whole contract is that the store
      // changes through `touchDirectory()`. A shallow copy is enough: the
      // value arrays are read, never mutated, by anything that draws them.
      return { dn: located.stored.dn,
               attributes: Object.assign({}, located.stored.attributes) };
    }
  });
} else {
  log.warn('ldap: the user portal offers no setDirectory(), so its Overview ' +
           'will draw the four facts a session carries rather than the ' +
           'person\'s directory entry. That is the older portal and is not ' +
           'an error; the page says which it is showing.');
}

// ---------------------------------------------------------------------------
// THE PERSON-ASSERTION SLOT (2026-09-11), and it is the one that lets somebody
// in `ou=users` be an RFC 7523 issuer.
//
// `common/person_assertions.js` owns what a person's assertion key pair IS —
// the seven attributes, the sealing, the refusal that a person may only assert
// about themselves — and this module owns the store it lives in. That is the
// same division `applications.js`, `federation.js` and the two XACML registers
// already have with this file.
//
// **RULE 3e's TEST ANSWERS YES BOTH WAYS ROUND.** That module is required by
// `oauth-oidc/assertion_grant.js`, which `oauth2.js` requires at 9, so a
// require from there to this module would register every `/ldap` route and all
// eight `/admin/ldap/*` console pages ahead of the authorization server (rule
// 1); and a require from this module to `assertion_grant.js` would be a second
// path to it through a module at 21, which is where a cycle starts.
//
// **THREE FUNCTIONS AND THEY ARE THE THREE SHAPES THIS FILE ALREADY HANDS
// OVER.** `read()` answers ONE PERSON'S assertion attributes in their canonical
// spelling — not the whole entry, which is what the portal's slot takes,
// because this register has no business with the other fifty; `write()` is one
// attribute at a time so that the caller can report WHICH one failed, which
// matters here more than anywhere else in this file (`common/pki.js` hands a
// private key over once and keeps no copy); and `persons()` is the list of
// NAMES, exactly as `credentials.persons()` takes it and for that comment's
// reason.
//
// Guarded like the rest: an older `common/person_assertions.js` costs a
// warning rather than a service that will not start, and the warning says what
// is lost.
// ---------------------------------------------------------------------------
if (typeof personAssertions.setDirectory === 'function') {
  personAssertions.setDirectory({
    // **THE AMBIENT REALM'S**, like the portal's and `credentials.persons()`:
    // a realm is a logical copy of this service with its own people, and an
    // assertion presented at `/realm/acme/oauth2/token` is about somebody in
    // `acme`.
    read: function (username) {
      log.debug('Entering read(). username=' + username);
      const located = locateEntry(String(username || ''));
      if (!located.stored) {
        log.debug('Leaving read(). Nothing at ' + located.dn + '.');
        return null;
      }
      // CANONICAL SPELLINGS OUT, lower-cased ones in the store. This is the
      // one place that translation happens for these attributes, so the
      // register never has to know that this directory lower-cases an
      // attribute name — which is the fact that made `ou=roles` report
      // `0 user(s)` for a role somebody held.
      const out = {};
      personAssertions.ATTRIBUTES.forEach(function (name) {
        const values = located.stored.attributes[name.toLowerCase()];
        if (values && values.length) {
          out[name] = values.slice();
        }
      });
      log.debug('Leaving read(). ' + Object.keys(out).length +
                ' attribute(s).');
      return out;
    },
    write: function (username, name, value) {
      log.debug('Entering write(). username=' + username + ' name=' + name);
      const located = locateEntry(String(username || ''));
      const stored = located.stored;
      if (!stored) {
        // NOT created here, for `writeStoredPassword()`'s reason: issuing a
        // credential to somebody who does not exist would create them, and
        // product mode refuses exactly that.
        log.warn(errorCodes.tag('STS-LDAP-0040') +
                 'ldap: "' + username + '" has no entry in this realm, so no ' +
                 'assertion key material was written.');
        log.debug('Leaving write(). No entry.');
        return false;
      }
      const attribute = String(name).toLowerCase();
      if (value === null || value === undefined || value === '') {
        delete stored.attributes[attribute];
      } else {
        // ASSIGNED and not appended. Two JWKS values would be two public keys
        // under one `kid` attribute, and a verifier that read the second would
        // be checking a signature against a key nobody meant.
        stored.attributes[attribute] = [String(value)];
      }
      touchDirectory();
      log.debug('Leaving write(). ' +
                (value ? 'Written to ' : 'Removed from ') +
                stored.dn + '.');
      return true;
    },
    persons: function () {
      log.debug("Entering persons().");
      log.debug("Leaving persons().");
      return allPersons().map(function (entry) {
        return usernameOfEntry(entry);
      }).filter(function (name) { return !!name; });
    }
  });
} else {
  log.warn('ldap: common/person_assertions.js offers no setDirectory(), so ' +
           'nobody in ou=users can hold an RFC 7523 signing key pair and an ' +
           'assertion naming a person as its issuer will be refused for want ' +
           'of a registered issuer. That is the older register and is not an ' +
           'error; /admin/pki says so on the control.');
}
} else {
  log.warn('ldap: common/credentials.js offers no setDirectory(), so no ' +
           'password can be verified or set. Development mode is unaffected ' +
           'because it verifies nothing; PRODUCT MODE WOULD REFUSE EVERY ' +
           'SIGN-IN, which credentials.js reports rather than passing.');
}

// ---------------------------------------------------------------------------
// CERTIFICATE ENROLLMENT'S SLOT (2026-09-13).
//
// `common/cert_enrollment.js` keeps what ACME, EST and SCEP issued — and the
// two protocol credentials, and an administrator's registered host names — ON
// THE ENTRY THE CERTIFICATE NAMES, a person's or an application's. Rule 3e's
// test answers yes both ways round, for `personAssertions.setDirectory()`'s
// reason: that module is required by the three protocol families, and a
// require from it to this file would register every `/ldap` route ahead of
// them.
//
// THREE FUNCTIONS, AND THEY ARE GENERIC OVER AN ATTRIBUTE NAME on purpose: the
// module on the far end owns which names it uses, and this file owns where an
// entry is and how a name is spelt in the store. `write()` REPLACES the
// attribute with the list it is given — an enrollment record is rewritten when
// it is revoked, so an add-only door would be a door that could never say so.
// **Neither kind of entry is created here**, for `writeStoredPassword()`'s
// reason: issuing a certificate to somebody who does not exist would create
// them.
// ---------------------------------------------------------------------------
if (typeof certEnrollment.setDirectory === 'function') {
  const enrollmentEntry = function (kind, id) {
    if (kind === 'person') {
      return locateEntry(String(id || '')).stored || null;
    }
    if (kind === 'application') {
      return applicationEntry(String(id || '')) || null;
    }
    return null;
  };
  certEnrollment.setDirectory({
    // THE AMBIENT REALM'S, like every other slot here: a certificate enrolled
    // at /realm/acme/.well-known/est is about somebody in acme.
    read: function (kind, id, names) {
      log.debug('Entering read(). kind=' + kind + ' id=' + id);
      const stored = enrollmentEntry(kind, id);
      if (!stored) {
        log.debug('Leaving read(). No entry.');
        return null;
      }
      const out = {};
      (names || []).forEach(function (name) {
        const values = stored.attributes[String(name).toLowerCase()];
        if (values && values.length) {
          out[name] = values.slice();
        }
      });
      log.debug('Leaving read(). ' + Object.keys(out).length +
                ' attribute(s).');
      return { dn: stored.dn, attributes: out };
    },
    write: function (kind, id, name, values) {
      log.debug('Entering write(). kind=' + kind + ' id=' + id + ' name=' +
                name);
      const stored = enrollmentEntry(kind, id);
      if (!stored) {
        log.warn(errorCodes.tag('STS-LDAP-0040') +
                 'ldap: the ' + kind + ' "' + id + '" has no entry in this ' +
                 'realm, so no enrollment attribute was written.');
        log.debug('Leaving write(). No entry.');
        return false;
      }
      const attribute = String(name).toLowerCase();
      const list = (values || []).map(function (one) {
        return String(one);
      });
      if (!list.length) {
        delete stored.attributes[attribute];
      } else {
        stored.attributes[attribute] = list;
      }
      touchDirectory(stored.dn);
      log.debug('Leaving write(). ' + list.length + ' value(s) on ' +
                stored.dn + '.');
      return true;
    },
    holders: function (kind, name) {
      log.debug('Entering holders(). kind=' + kind + ' name=' + name);
      const attribute = String(name).toLowerCase();
      const out = [];
      if (kind === 'person') {
        eachEntryInRealm(function (stored) {
          if (isPersonEntry(stored) &&
              (stored.attributes[attribute] || []).length) {
            const username = usernameOfEntry(stored);
            if (username) {
              out.push(username);
            }
          }
        });
      } else if (kind === 'application') {
        entriesUnder(applicationsDn()).forEach(function (stored) {
          const identifier = (stored.attributes.appidentifier || [])[0];
          if (identifier && (stored.attributes[attribute] || []).length) {
            out.push(String(identifier));
          }
        });
      }
      log.debug('Leaving holders(). ' + out.length + '.');
      return out;
    }
  });
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
           'back. With oauth2.consentRequired on, the screen is drawn on ' +
           'every authorization request. The directory itself is unaffected.');
}

// ---------------------------------------------------------------------------
// THE KERBEROS KEY REGISTER'S SLOT (2026-09-12), and it is the one directory
// slot in this file that is pinned to the DEFAULT realm for a reason that is
// not about administrators.
//
// `kerberos/krb5_person_keys.js` owns what a stored Kerberos key IS — the
// sealed record, the stamp, the kvno, the keytab — and this module owns where
// it lives: `stsKrb5Keys` / `stsKrb5KeyInfo` on a person's entry under
// `ou=users`, and `krb5ServiceKeys` / `krb5ServiceKeyInfo` on an application
// entry under `ou=applications`. That is the division `person_assertions.js`
// has with this file one slot up.
//
// **RULE 3e ANSWERS YES BOTH WAYS ROUND.** That module is required by the two
// `admin-core/` halves at 18, so a require from there to this module would
// register every `/ldap` route and all eight `/admin/ldap/*` pages ahead of the
// management API (rule 1); and it requires `krb5_principals.js`, which the KDC
// at 15 requires, so the directory reached from the KDC's side would move them
// further still.
//
// **EVERY FUNCTION RUNS IN THE AMBIENT REALM SINCE 2026-09-15**, where all six
// were wrapped in `inDefaultRealm()` before it. The paragraph here read *the
// KDC's sockets and `krb5.realm` are process-wide … so the KDC answers in no
// trust realm, and its people are the default realm's people*. It does now:
// each trust realm whose Kerberos is on has a Kerberos realm and a principal
// database of its own, and the KDC ENTERS that realm before it looks anybody
// up — so a person reached from a request in `acme` is exactly the principal of
// `acme`'s KDC, and their keys belong on their entry in `acme`'s subtree. The
// register asks `principals.enabledIn()` before deriving for a realm with no
// KDC.
//
// **THE WRITES GO STRAIGHT ONTO THE STORED ENTRY, AND FOR AN APPLICATION THAT
// IS DELIBERATE.** `applications.updateApplication()` quotes the value it wrote
// in its audit summary, its log line and its reply, and the value here is key
// material. The two attributes are rows in `applications.js`'s SCHEMA, which is
// what makes a later `writeApplication()` — which REPLACES an entry from its
// record — carry them rather than erase them.
// ---------------------------------------------------------------------------
function firstValue(stored, lowerName) {
  log.debug("Entering firstValue().");
  const values = stored.attributes[lowerName] || [];
  log.debug("Leaving firstValue().");
  return values.length ? String(values[0]) : '';
}

function assignOrDelete(stored, lowerName, value) {
  log.debug("Entering assignOrDelete().");
  if (value === null || value === undefined || value === '') {
    delete stored.attributes[lowerName];
  } else {
    stored.attributes[lowerName] = [String(value)];
  }
  log.debug("Leaving assignOrDelete().");
}

if (typeof krb5PersonKeys.setDirectory === 'function') {
  krb5PersonKeys.setDirectory({
    readPerson: function (username) {
      log.debug('Entering readPerson(). username=' + username);
      const located = locateEntry(String(username || ''));
      if (!located.stored || !isPersonEntry(located.stored)) {
        log.debug('Leaving readPerson(). No person at ' + located.dn + '.');
        return null;
      }
      const stored = located.stored;
      log.debug('Leaving readPerson(). ' + stored.dn);
      return { dn: stored.dn, username: usernameOfEntry(stored),
               keys: firstValue(stored, 'stskrb5keys'),
               info: firstValue(stored, 'stskrb5keyinfo'),
               passwordHash: firstValue(stored, 'userpassword') };
    },
    writePerson: function (username, keysValue, infoValue) {
      log.debug('Entering writePerson(). username=' + username);
      const located = locateEntry(String(username || ''));
      if (!located.stored || !isPersonEntry(located.stored)) {
        // NOT created here, for `writeStoredPassword()`'s reason.
        log.warn(errorCodes.tag('STS-LDAP-0040') + 'ldap: "' + username +
                 '" has no entry in this trust realm, so no Kerberos key ' +
                 'was written.');
        log.debug('Leaving writePerson(). No entry.');
        return false;
      }
      // BOTH IN ONE WRITE, so the public half can never describe a generation
      // of keys the secret half does not hold.
      assignOrDelete(located.stored, 'stskrb5keys', keysValue);
      assignOrDelete(located.stored, 'stskrb5keyinfo', infoValue);
      touchDirectory(located.stored.dn);
      log.debug('Leaving writePerson(). ' + located.stored.dn);
      return true;
    },
    personKeyInfos: function () {
      log.debug('Entering personKeyInfos().');
      const out = [];
      eachEntryInRealm(function (stored) {
        if (isPersonEntry(stored) && (stored.attributes.stskrb5keyinfo ||
                                      stored.attributes.stskrb5keys)) {
          out.push({ username: usernameOfEntry(stored) || stored.dn,
                     info: firstValue(stored, 'stskrb5keyinfo'),
                     passwordHash: firstValue(stored, 'userpassword') });
        }
      });
      log.debug('Leaving personKeyInfos(). ' + out.length + ' person(s).');
      return out;
    },
    readService: function (identifier) {
      log.debug('Entering readService(). identifier=' + identifier);
      const stored = applicationEntry(String(identifier || ''));
      if (!stored) {
        log.debug('Leaving readService(). No entry.');
        return null;
      }
      log.debug('Leaving readService(). ' + stored.dn);
      return { dn: stored.dn, keys: firstValue(stored, 'krb5servicekeys'),
               info: firstValue(stored, 'krb5servicekeyinfo') };
    },
    writeService: function (identifier, keysValue, infoValue) {
      log.debug('Entering writeService(). identifier=' + identifier);
      const stored = applicationEntry(String(identifier || ''));
      if (!stored) {
        log.debug('Leaving writeService(). No entry.');
        return false;
      }
      assignOrDelete(stored, 'krb5servicekeys', keysValue);
      assignOrDelete(stored, 'krb5servicekeyinfo', infoValue);
      touchDirectory(stored.dn);
      log.debug('Leaving writeService(). ' + stored.dn);
      return true;
    },
    serviceKeyInfos: function () {
      log.debug('Entering serviceKeyInfos().');
      const out = [];
      entriesUnder(applicationsDn()).forEach(function (stored) {
        if (stored.attributes.krb5servicekeyinfo ||
            stored.attributes.krb5servicekeys) {
          out.push({ identifier: firstValue(stored, 'appidentifier') ||
                                 stored.dn,
                     info: firstValue(stored, 'krb5servicekeyinfo'),
                     hasKeys: !!firstValue(stored, 'krb5servicekeys') });
        }
      });
      log.debug('Leaving serviceKeyInfos(). ' + out.length + ' entr(ies).');
      return out;
    }
  });
} else {
  log.warn('ldap: kerberos/krb5_person_keys.js offers no setDirectory(), so ' +
           'no person can hold Kerberos keys and no service principal key ' +
           'can be stored. That is the older register and is not an error.');
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
// AND EVERY ONE OF THEM IS BOUND TO ONE REALM — THE DEFAULT ONE UNLESS A CALLER
// NAMES ANOTHER.
//
// The directory is per realm, so `groupsOfUser('alice')` means a different
// thing in each one. Until 2026-09-14 every member was pinned to the DEFAULT
// realm, because a role was permission to change what EVERY realm's protocol
// endpoints do and a per-realm roster would have let anybody who could create
// a realm grant themselves both roles and walk back out into the default one.
//
// **THAT ARGUMENT IS ANSWERED RATHER THAN DROPPED (#32).** Each realm now has a
// roster of its own, and what a member of it may reach is narrowed by
// `admin-ui/admin_scope.js`: that realm's pages and actions, and nothing about
// the process — no other realm, no realm created or removed, no per-process
// setting, no service Root. So the escalation the pinning prevented is closed
// by the SCOPE instead, and the default realm's roster is still the only one
// that administers the service. `rosterViewFor(realm)` below binds these same
// functions to a named realm; the default view is still what a caller that
// names nothing gets.
//
// **SO AN ADMINISTRATOR IS A PERSON OF THE REALM WHOSE ROSTER NAMES THEM.** A
// default-realm person holds the service roles; somebody under
// `dc=acme,dc=example,dc=com` can hold acme's and nothing else. The console
// gate asks the roster of the realm the SESSION was signed in through
// (`admin_views.gateStateFor()`), which is what keeps the two halves agreeing:
// a gate that accepted an acme session while reading the default roster would
// let somebody in and then insist they were nobody.
//
// It is deliberately NOT applied to `setDirectoryReader()` and
// `setDirectoryWriter()` above. Those draw the console's USER pages, and
// `/realm/acme/admin/users` showing the default realm's people instead of
// acme's would be a console that cannot see the realm it is pointed at. Reading
// a realm is the console's job; being let in is not the realm's decision.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE THREE FLAGS OF THE BOOTSTRAP ADMINISTRATOR (2026-09-13), on the person's
// own entry so that they persist, replicate and show in an ldapsearch like
// everything else about them:
//
//   pwdReset                   draft-behera-ldap-password-policy's name: TRUE
//                              means the password must be changed at the next
//                              sign-in (`authn.js` enforces it).
//   stsBootstrapAdministrator  TRUE on the account `admin_rbac.js` seeded.
//   stsConsoleClaimedAt        when that account first signed in to the
//                              console, which is what ends the window in which
//                              every signed-in person may use it.
//   stsMfaRequired             TRUE when an administrator requires this person
//                              to sign in with a second factor (2026-09-13).
//                              `authn.js` asks them to enrol one at the sign-in
//                              screen when they hold none.
//   stsPasswordResetToken      the scrypt hash of a password reset link an
//   stsPasswordResetExpires    administrator issued, and when it stops working
//                              (2026-09-13). The token is a SECRET_ATTRIBUTE:
//                              it is a hash, and still one this directory never
//                              hands to a reader.
//
// One reader and one writer for them, narrowed to exactly these names, so that
// neither slot below becomes a general attribute writer.
// ---------------------------------------------------------------------------
const PERSON_FLAGS = ['pwdReset', 'stsBootstrapAdministrator',
                      'stsConsoleClaimedAt', 'stsMfaRequired',
                      'stsPasswordResetToken', 'stsPasswordResetExpires'];

function readPersonFlags(key) {
  log.debug('Entering readPersonFlags(). key=' + key);
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    log.debug('Leaving readPersonFlags(). No entry.');
    return null;
  }
  const one = function (name) {
    log.debug('Entering one().');
    const values = stored.attributes[name.toLowerCase()] || [];
    log.debug('Leaving one().');
    return values.length ? String(values[0]) : '';
  };
  log.debug('Leaving readPersonFlags().');
  return { dn: stored.dn,
           pwdReset: one('pwdReset').toUpperCase() === 'TRUE',
           bootstrapAdministrator:
             one('stsBootstrapAdministrator').toUpperCase() === 'TRUE',
           consoleClaimedAt: one('stsConsoleClaimedAt'),
           mfaRequired: one('stsMfaRequired').toUpperCase() === 'TRUE',
           passwordResetToken: one('stsPasswordResetToken'),
           passwordResetExpires: Number(one('stsPasswordResetExpires') || 0) };
}

function writePersonFlag(key, name, value) {
  log.debug('Entering writePersonFlag(). key=' + key + ', name=' + name);
  if (PERSON_FLAGS.indexOf(name) < 0) {
    log.debug('Leaving writePersonFlag(). Not one of the flags.');
    return false;
  }
  const located = locateEntry(String(key || ''));
  const stored = located.stored;
  if (!stored) {
    log.warn(errorCodes.tag('STS-LDAP-0078') + 'ldap: "' + key + '" has no ' +
             'entry in this realm, so ' + name + ' was not written.');
    log.debug('Leaving writePersonFlag(). No entry.');
    return false;
  }
  if (value === null || value === undefined || value === '' ||
      value === false) {
    delete stored.attributes[name.toLowerCase()];
  } else {
    stored.attributes[name.toLowerCase()] =
      [value === true ? 'TRUE' : String(value)];
  }
  stored.attributes.modifytimestamp = [generalizedTime()];
  touchDirectory(stored.dn);
  log.debug('Leaving writePersonFlag().');
  return true;
}

function inDefaultRealm(fn) {
  log.debug("Entering inDefaultRealm().");
  log.debug("Leaving inDefaultRealm().");
  return function () {
    const args = arguments;
    return realms.run(realms.DEFAULT_REALM, function () {
      return fn.apply(null, args);
    });
  };
}

// ---------------------------------------------------------------------------
// THE ROSTER'S VIEW OF ONE REALM (2026-09-14, #32). Every member below was
// pinned to the DEFAULT realm with `inDefaultRealm()`, because the console had
// one roster and it was that realm's. Now each realm has its own and the
// default realm's is the SERVICE roster, so the same members are built for a
// NAMED realm: `rosterViewFor(realm)` binds each function to that realm, and
// the object installed is the default realm's view plus `forRealm(id)`, which
// builds another realm's view on demand. `admin_rbac.js` binds a realm only
// when a caller names one, so a caller that names none still reads the default
// realm — the pinning argument survives as the default.
// ---------------------------------------------------------------------------
function rosterViewFor(realm) {
  log.debug("Entering rosterViewFor(). realm=" + realm.id);
  const inRealm = function (fn) {
    log.debug("Entering inRealm().");
    log.debug("Leaving inRealm().");
    return function () {
      const args = arguments;
      return realms.run(realm, function () {
        return fn.apply(null, args);
      });
    };
  };
  log.debug("Leaving rosterViewFor().");
  return {
    groupsOfUser: inRealm(groupsOfUser),
    readGroupEntry: inRealm(readGroupEntry),
    writeGroupEntry: inRealm(writeGroupEntry),
    groupDnFor: inRealm(groupDnFor),
    normalizeDn: normalizeDn,
    existingUserEntry: inRealm(existingUserEntry),
    usernameOfEntry: usernameOfEntry,
    nameUsableInDn: nameUsableInDn,
    allPersons: inRealm(allPersons),
    // THE OTHER DIRECTION OF MEMBERSHIP. `readGroupEntry()` answers what the
    // GROUP lists; this answers who CLAIMS the group through their own
    // `memberOf` while the group does not list them back. `groupsOfUser()`
    // already honours both directions, so somebody added that way really holds
    // the role — and without this the roster page would have shown a console
    // they could use and a list they were not on, which is the one thing a
    // permissions page must never do.
    claimedMembersOf: inRealm(claimedMembersOf),
    // THE BOOTSTRAP ADMINISTRATOR (2026-09-13): its entry made if absent, and
    // its flags read and written — see readPersonFlags(). Optional members,
    // checked where they are used, so an older admin_rbac.js still installs.
    createPerson: inRealm(function (name) {
      log.debug("Entering createPerson().");
      log.debug("Leaving createPerson().");
      return createUser(name, {});
    }),
    readPersonFlags: inRealm(readPersonFlags),
    writePersonFlag: inRealm(writePersonFlag),
    // STRINGS, and THIS realm's — evaluated once, when the view is built,
    // rather than read per call. A realm's base DN cannot change while the
    // process runs, so there is nothing to re-read, and a function would only
    // invite somebody to make it ambient.
    usersDn: realms.run(realm, usersDn),
    groupsDn: realms.run(realm, groupsDn),
    realmId: realm.id
  };
}

if (typeof adminRbac.setDirectory === 'function') {
  const defaultView = rosterViewFor(realms.DEFAULT_REALM);
  defaultView.forRealm = function (id) {
    log.debug("Entering forRealm(). id=" + id);
    const realm = realms.get(String(id || ''));
    log.debug("Leaving forRealm(). " + (realm ? "Built." : "No such realm."));
    return realm ? rosterViewFor(realm) : null;
  };
  adminRbac.setDirectory(defaultView);
} else {
  log.warn('ldap: admin_rbac.js offers no setDirectory(), so the admin ' +
           'console cannot read or grant its two roles. The console gate is ' +
           'unconditional, so that leaves /admin reachable only while ' +
           'admin.openWhenEmpty is on. The directory itself is unaffected.');
}

// And once, now. The seeded people were written before any of this existed and
// the claim set already has ten attributes selected, so without this sweep
// alice would have no birthdate in the directory while her credential asserted
// one — the two disagreeing from the very first request, which is the exact
// confusion this whole arrangement exists to avoid.
populateVcAttributes();

// ---------------------------------------------------------------------------
// The server, and its handlers.
//
// Every handler is registered against '' — the ROOT DSE and everything else —
// and each decides for itself whether the DN it was given is inside ROOT_DN. A
// client that binds before it knows the base DN reads the root DSE first, and a
// server that had no handler for it answers LDAP_UNAVAILABLE, which reads as
// the server being down.
//
// Registering at '' rather than at the base is also what lets one socket serve
// every trust realm: a realm's subtree is `dc=<id>,` + ROOT_DN, and the
// handlers reach it because they were never scoped to a base in the first
// place.
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
// being true: an absence recorded and published on GET /admin/ldap/service is
// worth more than a TypeError out of a constructor, which is the same trade
// every listen path here makes.
// ---------------------------------------------------------------------------
const plainServer = ldap.createServer({ log: log });

// The TLS protocol policy, asked of the module that states it. An older copy of
// `tls_server.js` without the function gets node's defaults, which is what
// LDAPS always had.
function tlsProtocolOptions() {
  log.debug("Entering tlsProtocolOptions().");
  log.debug("Leaving tlsProtocolOptions().");
  return typeof tlsServer.protocolOptions === 'function'
    ? tlsServer.protocolOptions() : {};
}

// Where both sockets bind: `global.host`, which every other listener here
// honours. They bound the literal '0.0.0.0' until 2026-09-12, so a service
// confined to 127.0.0.1 still offered its directory on every interface.
function ldapListenHost() {
  log.debug("Entering ldapListenHost().");
  log.debug("Leaving ldapListenHost().");
  return String(config.value('global.host') || '0.0.0.0').replace(/^\[|\]$/g,
                                                                  '');
}

const serverCertificate = tlsServer.serverCertificate();

let secureServer = null;
if (serverCertificate && serverCertificate.certPem &&
    serverCertificate.privateKeyPem) {
  // `certificate` and `key` are the option names ldapjs checks for, and it
  // hands the whole options object to tls.createServer(). No client certificate
  // is asked for here: this listener proves the SERVER's identity and nothing
  // else, which GET /admin/ldap/service says out loud rather than leaving
  // somebody to work out why the client certificate they offered was never
  // requested. The permissive and strict client-certificate listeners are the
  // HTTPS ones next door, where the whole content is the answer to that
  // question. `tls.minVersion` and `tls.ciphers` go in too (2026-09-12): ldapjs
  // hands this whole object to `tls.createServer()`, so LDAPS takes the same
  // protocol floor and cipher list as 8443, 9443 and the main port rather than
  // node's defaults behind their back.
  secureServer = ldap.createServer(Object.assign({
    log: log,
    certificate: serverCertificate.certPem,
    key: serverCertificate.privateKeyPem
  }, tlsProtocolOptions()));
} else {
  tlsListenError = 'there was no server certificate at startup';
  log.warn(errorCodes.tag('STS-LDAP-0029') +
           'ldap: no server certificate is available, so LDAPS will not be ' +
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
  log.debug("Entering inRealmOfRequest().");
  log.debug("Leaving inRealmOfRequest().");
  return function (req, res, next) {
    const dn = req && req.dn ? req.dn.toString() : '';
    return inRealmOf(dn, function () {
      return handler(req, res, next);
    });
  };
}

// ---------------------------------------------------------------------------
// AN ADD CLAIMS WHAT IT CREATES (2026-09-14, #46 section 3). Outside the
// realm wrapper and the request pool, so the claim is made once by the process
// holding the socket whichever process runs the handler; inert (no round trip)
// unless several processes write one store — `directory_create_claims.js`.
// Released when the add is refused, and after the write is flushed when it
// succeeded, which is what `res.end()` without a preceding error means.
// ---------------------------------------------------------------------------
function claimingTheAdd(handler) {
  log.debug("Entering claimingTheAdd().");
  log.debug("Leaving claimingTheAdd().");
  return function (req, res, next) {
    if (!createClaims.active()) {
      return handler(req, res, next);
    }
    const dn = req && req.dn ? req.dn.toString() : '';
    const uids = (req.attributes || []).filter(function (attr) {
      return String(attr.type).toLowerCase() === 'uid';
    }).reduce(function (all, attr) {
      return all.concat(attr.values || []);
    }, []);
    return inRealmOf(dn, function () {
      return claimCreate({ dn: dn, uids: uids });
    }).then(function (held) {
      if (!held.ok) {
        return inRealmOf(dn, function () {
          if (held.reason === 'store') {
            return next(ldapRefusal(req, 'STS-LDAP-0093', 'an add of ' + dn +
              ' was refused: ' + createClaims.refusalMessage(held),
              new ldap.UnavailableError(createClaims.refusalMessage(held)),
              dn));
          }
          return next(ldapRefusal(req, 'STS-LDAP-0092', 'an add of ' + dn +
            ' was refused: ' + createClaims.refusalMessage(held),
            new ldap.EntryAlreadyExistsError(dn), dn));
        });
      }
      const end = res.end;
      res.end = function () {
        held.settle(true);
        return end.apply(res, arguments);
      };
      return handler(req, res, function (err) {
        if (err) {
          held.settle(false);
        }
        return next(err);
      });
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
    // ---------------------------------------------------------------------
    // AND THE SECOND WRAPPER: THE REQUEST-WORKER POOL (2026-09-12).
    //
    // It is HERE, at registration, for exactly `inRealmOfRequest()`'s reason
    // one line up — seven bodies each remembering to offer themselves to the
    // pool is seven chances to forget, and the thing forgotten would be
    // invisible: the operation would simply run in the front process and
    // everything would work, slightly slower, for ever.
    //
    // The realm wrapper goes on FIRST and is therefore what a worker runs:
    // `LOCAL_HANDLERS` holds the realm-entering function, so a worker enters
    // the realm of the DN it was handed exactly as the socket does. Wrapping
    // the other way round would leave a worker running the raw handler with
    // no realm ambient, which answers "no such object" for entries that
    // plainly exist — the failure this registration point was built to
    // prevent, reintroduced one layer out.
    // ---------------------------------------------------------------------
    if (DISPATCHABLE_OPERATIONS.indexOf(operation) >= 0) {
      LOCAL_HANDLERS[operation] = args[args.length - 1];
      args[args.length - 1] = throughTheRequestPool(operation,
                                                    LOCAL_HANDLERS[operation]);
    }
    // AND THE THIRD, OUTERMOST, FOR AN ADD ONLY (2026-09-14, #46): the DN
    // and the username it takes are claimed before anything else runs, in the
    // process that holds the socket, so two adds of one name on two nodes
    // cannot both succeed. See `claimingTheAdd()`.
    if (operation === 'add') {
      args[args.length - 1] = claimingTheAdd(args[args.length - 1]);
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

// ---------------------------------------------------------------------------
// AND THE SAME QUESTION ASKED IN A PROCESS THAT HOLDS NO SOCKETS (2026-09-09).
//
// `common/request_pool.js` runs the whole protocol stack in N request workers,
// and a worker BINDS NOTHING — `common/request_worker.js` loads this module for
// its HTTP views and never calls `listen()`. So the Set above is permanently
// empty there, and every question about directory connections was answered
// "there are none" by the process that answers `/logout`.
//
// **THAT IS NOT A DEGRADED ANSWER, IT IS A WRONG ONE, AND IT WAS SILENT.** The
// sign-out driver in ../logout/logout.js ends what `collect()` finds; an empty
// list is nothing to end and nothing to report, so a global logout in dispatch
// mode said it had ended everything while a bound LDAP connection — which IS
// the session, RFC 4511 section 4.2 — went on being signed in. It cost a whole
// mode of the suite: `sts_global_logout` failed on "the bound LDAP connection
// is still open" and nothing else in the run said why.
//
// TWO HOOKS AND NOT ONE, because reading and closing fail differently:
//
//   * `setConnectionMirror()` answers WHAT IS OPEN. The front process pushes a
//     snapshot whenever the set changes, and a worker's boundConnections()
//     reads it. A mirror rather than a request-and-wait because every caller of
//     boundConnections() is SYNCHRONOUS — `collect()` is called inside a
//     forEach over the families — and making one of them asynchronous means
//     making terminate() asynchronous and every one of its seven callers with
//     it. **IT IS A SNAPSHOT AND IT IS ALLOWED TO BE STALE**, by exactly the
//     interval between a connection changing and the next push: a row that has
//     gone is reported as "already closed" by the drop below, and a row that
//     has just arrived is caught by the next sign-out. What it may never be is
//     EMPTY on a service that has connections, which is what it was.
//   * `setRemoteDropper()` CLOSES. Only the process holding the socket can, so
//     a worker states the intent and the front process performs it. See that
//     function's header for why it goes out ON THE RESPONSE rather than over
//     the IPC channel beside it.
//
// A process with neither installed is a process that holds its own sockets, and
// behaves exactly as this module always has — which is every process this
// service has ever run in until dispatching was turned on.
// ---------------------------------------------------------------------------
let connectionMirror = null;
let remoteDropper = null;

// Filled by common/request_worker.js, with the rows the front process has just
// published — every push replaces the whole snapshot, because a delta would be
// a second thing to get wrong for no saving on a list this short.
//
// **INSTALLING IT IS WHAT MAKES THIS A MIRRORED PROCESS**, and the first push
// is what says so in the log: there is no separate "am I a worker" flag here,
// because the question this module actually has is "can I reach these sockets",
// and holding somebody else's snapshot is exactly the answer no.
//
// **AN ARRAY INSTALLS AND ANYTHING ELSE UNINSTALLS**, which is the difference
// between "the front process is holding nothing" and "there is no front
// process holding anything for me". The first is an ordinary empty snapshot —
// a service nobody has bound to — and must leave this process mirrored; the
// second is how a test puts itself back to holding its own sockets.
function setConnectionMirror(rows) {
  log.debug("Entering setConnectionMirror().");
  const first = connectionMirror === null;
  if (!Array.isArray(rows)) {
    connectionMirror = null;
    log.debug("Leaving setConnectionMirror(). Not mirrored.");
    return;
  }
  connectionMirror = rows.slice(0);
  if (first) {
    log.info('ldap: this process holds no directory listener, so its view of ' +
             'bound connections is the front process\'s — see ' +
             'common/request_pool.js. A sign-out here states what it wants ' +
             'closed and the process holding the socket closes it.');
  }
  log.debug("Leaving setConnectionMirror(). " + connectionMirror.length +
            " connection(s).");
}

// Filled by the same module, with a function that carries a key to the front
// process. It returns nothing: what it has to promise is not a value but an
// ORDER — that the socket is closed before the answer to this request reaches
// the client — and the mechanism that keeps that promise is the response
// itself.
function setRemoteDropper(fn) {
  log.debug("Entering setRemoteDropper().");
  remoteDropper = (typeof fn === 'function') ? fn : null;
  log.debug("Leaving setRemoteDropper().");
}

// The rows the mirror is holding. A worker asking before the front process has
// pushed anything gets an empty list, which is the truth about a service that
// has just started rather than a failure.
function mirroredConnections() {
  log.debug("Entering mirroredConnections().");
  const rows = (connectionMirror || []).slice(0);
  log.debug("Leaving mirroredConnections(). " + rows.length + " row(s).");
  return rows;
}

// Take rows out of the snapshot the moment they have been asked for, so that
// the next call in the same sign-out does not report them again. The front
// process's next push replaces the whole snapshot and is the authority; this is
// only about the seconds in between, and it is the same bookkeeping the
// single-process path does with `liveConnections.delete()`.
function forgetMirrored(key) {
  log.debug("Entering forgetMirrored(). key=" + key);
  const wanted = String(key || '');
  connectionMirror = (connectionMirror || []).filter(function (row) {
    return !(row.key && row.key === wanted);
  });
  log.debug("Leaving forgetMirrored(). " + connectionMirror.length + " left.");
}

servers.forEach(function (one) {
  // `one.server` is the net.Server (or tls.Server) ldapjs built; see
  // node-ldapjs/lib/server.js, where it is assigned in the constructor. The TLS
  // one emits `secureConnection` rather than `connection` for a socket that has
  // completed its handshake, and ldapjs sets its own state up on that same
  // socket — so both names are listened for and a socket that somehow arrived
  // twice is a Set member added twice, which is once.
  ['connection', 'secureConnection'].forEach(function (event) {
    one.server.on(event, function (socket) {
      holdSocket(socket);
    });
  });
});

// A socket this process now holds, until it closes. A function of its own so
// that `tests/ldap_cluster_signout.js` can hand it a socket without a listener:
// the cross-node close is only worth asserting against the real Set.
function holdSocket(socket) {
  log.debug("Entering holdSocket().");
  liveConnections.add(socket);
  publishConnectionsSoon();
  socket.on('close', function () {
    liveConnections.delete(socket);
    publishConnectionsSoon();
  });
  log.debug("Leaving holdSocket().");
}

// ---------------------------------------------------------------------------
// AND THE SAME QUESTION ASKED ACROSS NODES (2026-09-14, #46 section 4).
//
// `boundConnections()` answers for the WHOLE CLUSTER in active-active mode:
// this process's own connections (its sockets, or its front process's mirror)
// followed by what every other node has published — rows without a socket,
// marked `remote` and naming their node. `localBoundConnections()` is this
// node's alone, and it is what the in-container mirror and the cluster table
// publish, because a row another node published must never be re-published as
// this node's. `ldap_cluster_connections.js` argues the table and the
// instruction; the hooks below are the only way it reaches a socket.
// ---------------------------------------------------------------------------
function boundConnections() {
  log.debug("Entering boundConnections().");
  const local = localBoundConnections();
  const remote = clusterConnections.remoteRows();
  log.debug("Leaving boundConnections(). " + local.length + " local, " +
            remote.length + " on other nodes.");
  return remote.length ? local.concat(remote) : local;
}

// Every connection this process currently holds, with who is bound on it. The
// DN is read live, per the note above; `key` is the console's identity key for
// that person, derived the same way every other door here derives it, so a row
// on /logout and a row on /admin/users name one person rather than two.
function localBoundConnections() {
  log.debug("Entering localBoundConnections().");
  // A PROCESS WITH NO LISTENER ANSWERS OUT OF THE MIRROR. See the block above:
  // the Set below can only ever be empty here, and answering "none" out of it
  // is how a sign-out came to report that it had ended everything while a bound
  // connection stayed open.
  if (connectionMirror) {
    const mirrored = mirroredConnections();
    log.debug("Leaving localBoundConnections(). " + mirrored.length +
              " mirrored connection(s).");
    return mirrored;
  }
  const out = [];
  liveConnections.forEach(function (socket) {
    const dn = (socket.ldap && socket.ldap.bindDN) ?
                String(socket.ldap.bindDN) : '';
    // ldapjs seeds an unbound connection with cn=anonymous rather than leaving
    // it empty — the same trap boundDnOf() documents — and an anonymous
    // connection is the absence of a bind, so it is reported as one.
    const bound = dn.toLowerCase() === 'cn=anonymous' ? '' : dn;
    out.push({
      id: (socket.ldap &&
           socket.ldap.id) || ((socket.remoteAddress || '?') + ':' +
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
      // When the bind that made this connection somebody's session happened.
      // Zero on a connection bound before this service recorded it, or by a
      // path that is not the bind handler — reported as "not recorded" rather
      // than as the epoch.
      boundAt: socket.stsBoundAt || 0,
      socket: socket
    });
  });
  log.debug("Leaving localBoundConnections(). " + out.length +
            " connection(s).");
  return out;
}

// What the cluster table needs of this module. `holdsSockets` is true only in
// the process that owns the listeners: a mirrored worker's rows are its front
// process's, which that process publishes itself.
clusterConnections.install({
  holdsSockets: function () {
    log.debug("Entering holdsSockets().");
    log.debug("Leaving holdsSockets().");
    return !connectionMirror &&
           (listening || tlsListening || liveConnections.size > 0);
  },
  localRows: function () {
    log.debug("Entering localRows().");
    log.debug("Leaving localRows().");
    return localBoundConnections();
  },
  closeLocal: function (key) {
    log.debug("Entering closeLocal().");
    log.debug("Leaving closeLocal().");
    return dropConnectionsFor(key, { localOnly: true });
  }
});

// The rows of OTHER nodes bound as `wanted`, as a sign-out reports them: asked
// for, not closed. Forgotten once reported, for `forgetMirrored()`'s reason —
// the next call in the same sign-out must not report them again.
function remoteDropsFor(wanted) {
  log.debug("Entering remoteDropsFor().");
  const rows = clusterConnections.remoteRows().filter(function (row) {
    return row.key && row.key === wanted;
  }).map(function (row) {
    return { id: row.id, dn: row.dn, secure: row.secure, port: row.port,
             node: row.node, nodeName: row.nodeName, remote: true,
             pending: true };
  });
  if (rows.length) {
    clusterConnections.forgetRemote(wanted);
  }
  log.debug("Leaving remoteDropsFor(). " + rows.length + ".");
  return rows;
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
//
// **AND ON EVERY OTHER NODE, IN ACTIVE-ACTIVE MODE (2026-09-14, #46).** Unless
// `options.localOnly` — which is how the front process acts on a worker's
// header and how another node's instruction is carried out, both of which
// already had their instruction written — a sign-out writes the cluster
// instruction for this identity FIRST, whatever this process can see, and the
// rows other nodes have published are returned after this node's with
// `remote: true, pending: true`: instructed, closed when that node applies the
// change log. See ldap_cluster_connections.js.
function dropConnectionsFor(key, options) {
  log.debug("Entering dropConnectionsFor(). key=" + key);
  const wanted = String(key || '');
  const opts = options || {};
  if (!opts.localOnly) {
    clusterConnections.instructSignOut(wanted);
  }
  const remote = opts.localOnly ? [] : remoteDropsFor(wanted);
  // -------------------------------------------------------------------------
  // IN A REQUEST WORKER, SAY WHAT IS TO BE CLOSED AND LET THE OWNER CLOSE IT.
  //
  // The socket belongs to the front process and nothing here can reach it —
  // there is no file descriptor to destroy, and a `destroy()` on a mirrored row
  // would be a method call on a plain object. So the intent travels, and the
  // rows this returns come from the mirror: they are what the front process
  // held when it last published, which is what the caller is about to report as
  // ended.
  //
  // THEY ARE REMOVED FROM THE MIRROR TOO, so that the second call for the same
  // person finds nothing left and says "already closed" — which is what the
  // single-process path does, and ../logout/logout.js's ldap family depends on
  // it: a global logout calls this once per row and every call after the first
  // must not re-report the same connection.
  // -------------------------------------------------------------------------
  if (connectionMirror) {
    const mine = mirroredConnections().filter(function (row) {
      return row.key && row.key === wanted;
    }).map(function (row) {
      return { id: row.id, dn: row.dn, secure: row.secure, port: row.port };
    });
    // -----------------------------------------------------------------------
    // A FAILED ASK THROWS, AND THAT IS THE POINT RATHER THAN AN OVERSIGHT.
    //
    // ../logout/logout.js's driver catches whatever a family's terminate()
    // throws and records the row as NOT ended, with the message. Returning the
    // rows here instead would report "the directory connection was closed"
    // about a socket nobody had been asked to close — which is the bug this
    // whole mechanism exists to fix, restated one layer up. A sign-out that
    // cannot reach the process holding the socket has to SAY so.
    // -----------------------------------------------------------------------
    if (!remoteDropper) {
      throw new Error('this process holds no directory listener and no way ' +
        'to ask the one that does, ' +
        'so ' + mine.length + ' connection(s) bound as ' +
        wanted + ' cannot be closed from here');
    }
    try {
      remoteDropper(wanted);
    } catch (e) {
      throw new Error('the process holding these connections could not be ' +
        'asked to close them: ' + e.message);
    }
    forgetMirrored(wanted);
    log.debug("Leaving dropConnectionsFor(). " + mine.length +
              " asked of the front process.");
    return remote.length ? mine.concat(remote) : mine;
  }
  const dropped = [];
  localBoundConnections().forEach(function (row) {
    if (!row.key || row.key !== wanted) return;
    dropped.push({ id: row.id, dn: row.dn, secure: row.secure,
                   port: row.port });
    try {
      row.socket.destroy();
    } catch (e) {
      // A socket that was already gone throws here, and that is the outcome
      // being asked for rather than a failure: it is counted as dropped because
      // it is not connected any more, which is what the caller asked about.
      log.debug('ldap: a connection bound as ' + row.dn +
                ' was already gone: ' + e.message);
    }
    liveConnections.delete(row.socket);
  });
  if (dropped.length) {
    log.info('ldap: dropped ' + dropped.length + ' connection(s) bound as ' +
             wanted +
             ' — RFC 4511 section 4.2 makes the bind the authorization state ' +
             'of the CONNECTION, so closing it is the only sign-out this ' +
             'protocol has.');
  }
  log.debug("Leaving dropConnectionsFor(). " + dropped.length + " dropped.");
  return remote.length ? dropped.concat(remote) : dropped;
}

// NOT fanned out: an error says which listener it came from. Two sockets and
// one message about "the server" would send a reader to the wrong port, and the
// two fail in different ways — 389 loses a race with the host's own slapd, 636
// is refused because the process is not root.
plainServer.on('error', function (err) {
  // Reported rather than thrown: the rest of this service is still useful, and
  // a listener that dies silently surfaces later as a directory that never
  // answers.
  log.error(errorCodes.tag('STS-LDAP-0025') +
            'ldap: the plain listener (' + boundPort + ') reported an error: ' +
            err.message);
});

if (secureServer) {
  secureServer.on('error', function (err) {
    log.error(errorCodes.tag('STS-LDAP-0026') +
              'ldap: the LDAPS listener (' + boundTlsPort + ') reported an ' +
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
// registers against — so a handler cannot tell them apart, and a page that
// could not either would be unable to answer the question somebody turning on
// LDAPS actually has, which is whether anything is using it. `req.connection`
// is the raw socket and a TLS one carries `encrypted`.
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
  log.debug("Entering ldapChannelOf().");
  log.debug("Leaving ldapChannelOf().");
  return (req.connection && req.connection.encrypted) ? 'ldaps' : 'ldap';
}

function boundDnOf(req) {
  log.debug("Entering boundDnOf().");
  const bound = req.connection && req.connection.ldap &&
                req.connection.ldap.bindDN;
  if (!bound) {
    log.debug("Leaving boundDnOf().");
    return '';
  }
  const text = String(bound);
  log.debug("Leaving boundDnOf().");
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
// All three membership attributes are counted, resolved the way
// MEMBER_ATTRIBUTES says: `memberUid` holds a bare name where `member` and
// `uniqueMember` hold a DN, and counting the three alike is exactly how every
// posixGroup member gets missed.
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
  log.debug("Entering auditLdap().");
  const boundDn = boundDnOf(req);
  audit.recordDirectory(Object.assign({
    channel: ldapChannelOf(req),
    protocol: ldapChannelOf(req) === 'ldaps' ? 'LDAPS' : 'LDAP',
    actor: boundDn ? consoleKeyFor(boundDn, getEntry(boundDn)) : '',
    actorForm: boundDn
  }, fields));
  log.debug("Leaving auditLdap().");
}

// ---------------------------------------------------------------------------
// A REFUSAL NO HANDLER WROTE A ROW FOR. Records the operator's code for the
// condition and hands back the SAME ldapjs error, untouched, for `next()` — so
// what the client receives is exactly what it was. The code is the one given,
// or the one a helper marked on the error where the condition was decided
// (refuseNulValues(), passwordWriteRefusal()). Written in whichever process
// runs the handler, which is where the condition was known. `outcome` is
// 'error' only where this service, rather than the request, is what failed.
// ---------------------------------------------------------------------------
function ldapRefusal(req, code, summary, err, target, outcome) {
  log.debug("Entering ldapRefusal().");
  const boundDn = req ? boundDnOf(req) : '';
  const channel = req ? ldapChannelOf(req) : 'ldap';
  audit.failure(code || errorCodes.codeOf(err), {
    channel: channel,
    protocol: channel === 'ldaps' ? 'LDAPS' : 'LDAP',
    actor: boundDn ? consoleKeyFor(boundDn, getEntry(boundDn)) : '',
    actorForm: boundDn,
    target: target || '',
    summary: summary,
    outcome: outcome || 'refused',
    detail: { result: err && err.name, resultCode: err && err.code }
  });
  log.debug("Leaving ldapRefusal().");
  return err;
}

// ---------------------------------------------------------------------------
// THE DIRECTORY AS AN OPERATION: WHAT CROSSES TO A REQUEST WORKER, AND WHAT
// CANNOT (2026-09-12).
//
// `common/request_pool.js` dispatches HTTP by proxying real HTTP over a unix
// socket, and its header spends a page on why a FAKE `req`/`res` pair was
// refused there: `http.ServerResponse` has an enormous surface, the handlers
// here use most of it, and `app.js`'s response-flush CSP re-check hangs off the
// real object. Every one of those arguments is about HTTP and **not one of them
// reaches LDAP**, which is why the decision here comes out the other way.
//
// An LDAP response, as these seven handlers use it, is THREE METHODS AND ONE
// PROPERTY: `res.send(entry)`, `res.end()`, `res.end(matched)` and
// `res.messageId`. A request is a DN, a filter, a list of attributes and a
// handful of scalars. There is no chunking, no content type, no header, no
// trailer and no middleware that rewrites the body on the way out. So the pair
// is reproduced rather than proxied, and the thing that makes it faithful is
// not care — it is that **both processes parse with the same ldapjs
// submodule**: a DN and a filter travel as the strings they arrived as and are
// re-parsed by `ldap.parseDN()` and `ldap.parseFilter()` at the far end. That
// is the HTTP path's "node's own parser at both ends" argument, transposed.
//
// **THE FRONT PROCESS KEEPS THE SOCKET AND THE FRAMING.** It accepts the
// connection, ldapjs decodes the BER, this file turns the request into a plain
// object, a worker does the work, and the front process writes the reply. What
// a worker never touches is the file descriptor — which is the whole of why
// `unbind` is not on the list below.
//
// ---------------------------------------------------------------------------
// FOUR THINGS DELIBERATELY DO NOT CROSS, AND EACH IS A DIFFERENT REASON.
//
//   * **`unbind`.** RFC 4511 section 4.3: it ends the connection, and a
//     connection is a file descriptor the front process holds. There is
//     nothing in it for a worker to do.
//   * **THE BIND'S EFFECT ON THE SOCKET.** The DECISION crosses — is this
//     password right, is this DN refused, write the audit rows — and
//     `req.connection.stsBoundAt` and `publishConnectionsSoon()` stay here,
//     applied by `applyOperationResult()` when the worker says the bind
//     succeeded. A worker stamping its own copy of a socket it does not hold
//     would be the mirror bug of the one `setConnectionMirror()` exists to
//     fix, pointing the other way.
//   * **THE SEARCH IS COLLECTED, NOT STREAMED.** A worker fills an array and
//     the front process sends it. That is a real cost and it is bounded on
//     purpose: `maxSearchResults()` already caps a search, and the cap is the
//     same number whether the search ran here or in a worker — so the array is
//     never larger than an answer this service was already willing to build.
//     A client raising `sizeLimit` past `ldap.sizeLimit` gets the service's
//     limit, exactly as it did.
//   * **THE `SearchEntry` MESSAGE ITSELF.** `toSearchEntry()` decides WHICH
//     attributes go back — requested, operational, canonically spelled — and
//     that is store logic, so it runs in the worker. What comes back is the
//     plain `{ objectName, attributes }` inside it, and the front process
//     builds the message with ITS OWN `res.messageId`. Sending the worker's
//     would be the "SearchEntry messageId mismatch" that function's header
//     already records having cost an afternoon.
// ---------------------------------------------------------------------------
const DISPATCHABLE_OPERATIONS = ['bind', 'add', 'del', 'modify', 'modifyDN',
                                 'compare', 'search'];

// The realm-entering handler for each, captured at registration. It is what a
// worker runs and what the front process falls back to.
const LOCAL_HANDLERS = {};

// The pool, required LAZILY inside the functions that use it. A top-level
// require would be this module (21) reaching up into the process's own
// bootstrap — `common/app.js` loads the pool, and app.js is above every route
// — and by the time an LDAP operation arrives it is a cache hit.
function requestPool() {
  log.debug("Entering requestPool().");
  try {
    log.debug("Leaving requestPool().");
    return require('../common/request_pool');
  } catch (e) {
    log.debug("Caught in requestPool(): " + ((e && e.message) || e));
    log.debug("Leaving requestPool().");
    // A process that has no pool module at all is a process that cannot
    // dispatch, which is the ordinary state of every in-process loader of this
    // tree. Answering null puts the caller on the local path.
    return null;
  }
}

// What a worker is stuck to. **THE CONNECTION, and `request_pool.js`'s
// operations header argues it at length**: RFC 4511 section 4.2 makes the
// connection the unit of authorization state, a client may have several
// operations outstanding on one, and an `ldapadd` followed by an `ldapsearch`
// down one socket is one conversation rather than two callers. It is a
// LOCALITY measure — the read barrier is what makes the write visible — and a
// connection this process cannot name falls back to fanning out.
function connectionAffinity(req) {
  log.debug("Entering connectionAffinity().");
  const socket = req && req.connection;
  if (!socket) {
    log.debug("Leaving connectionAffinity().");
    return '';
  }
  log.debug("Leaving connectionAffinity().");
  return (socket.ldap && socket.ldap.id) ||
         ((socket.remoteAddress || '?') + ':' + (socket.remotePort || '?'));
}

// An ldapjs Attribute or Change carries class instances; the channel carries
// structured clones. Both are read by the handlers as plain `{type, values}`
// and `{operation, modification}`, so plain is what travels.
function plainAttributes(attributes) {
  log.debug("Entering plainAttributes().");
  log.debug("Leaving plainAttributes().");
  return (attributes || []).map(function (attribute) {
    return { type: String(attribute.type),
             values: (attribute.values || []).map(function (v) {
               return String(v);
             }) };
  });
}

function plainChanges(changes) {
  log.debug("Entering plainChanges().");
  log.debug("Leaving plainChanges().");
  return (changes || []).map(function (change) {
    const modification = change.modification || {};
    return { operation: String(change.operation || ''),
             modification: { type: String(modification.type || ''),
                             values: (modification.values || []).map(
                                 function (v) {
                               return String(v);
                             }) } };
  });
}

// ---------------------------------------------------------------------------
// THE REQUEST, AS A PLAIN OBJECT. It throws rather than guessing: a shape this
// function cannot describe is one the caller must run HERE, because a worker
// handed a half-described request would answer confidently about the wrong
// thing.
// ---------------------------------------------------------------------------
function operationRequest(operation, req) {
  log.debug('Entering operationRequest(). operation=' + operation);
  const shape = {
    dn: req.dn ? req.dn.toString() : '',
    // THE BOUND DN TRAVELS, and it is the one fact a worker could not possibly
    // work out for itself: the connection is this process's, so who is on it
    // is this process's to say. `auditLdap()` reads it through `boundDnOf()`
    // at the far end, out of the connection stub `operationContext()` builds.
    boundDn: boundDnOf(req),
    channel: ldapChannelOf(req),
    // THE CLIENT'S ADDRESS (2026-09-12), for the failed-bind rate limit. A
    // worker has no socket to read it off, and a stub without it would count
    // every dispatched bind against one address.
    remoteAddress: String((req.connection &&
                           req.connection.remoteAddress) || '')
  };
  if (operation === 'bind') {
    shape.credentials = req.credentials === undefined ? '' :
                        String(req.credentials);
  } else if (operation === 'add') {
    shape.attributes = plainAttributes(req.attributes);
  } else if (operation === 'modify') {
    shape.changes = plainChanges(req.changes);
  } else if (operation === 'modifyDN') {
    shape.newRdn = req.newRdn ? req.newRdn.toString() : '';
    shape.newSuperior = req.newSuperior ? req.newSuperior.toString() : '';
    // Carried since 2026-09-14, when the handler started honouring it: a rename
    // answered by a worker would otherwise leave the old name resolving.
    shape.deleteOldRdn = !!req.deleteOldRdn;
  } else if (operation === 'compare') {
    shape.attribute = String(req.attribute || '');
    shape.value = String(req.value === undefined ? '' : req.value);
  } else if (operation === 'search') {
    // THE SCOPE TRAVELS AS THE NUMBER ldapjs PUT ON THE REQUEST, because
    // `scopeOf()` reads `req.scope` and defaults a non-number to 2 (sub).
    // Sending the word and re-deriving the number at the far end would be a
    // second spelling of the same three values.
    shape.scope = typeof req.scope === 'number' ? req.scope : 2;
    shape.filter = req.filter ? req.filter.toString() : '(objectclass=*)';
    shape.attributes = (req.attributes || []).map(function (a) {
      return String(a);
    });
    shape.sizeLimit = parseInt(req.sizeLimit, 10) || 0;
  }
  log.debug('Leaving operationRequest().');
  return shape;
}

// The other end: a request object the handlers can read, out of that shape.
// **A FILTER IS RE-PARSED AND NEVER RECONSTRUCTED** — the handler calls
// `req.filter.matches()`, which no plain object has, and the submodule that
// parsed it on the way in is the one parsing it here.
function operationContext(operation, shape) {
  log.debug('Entering operationContext(). operation=' + operation);
  const req = {
    dn: ldap.parseDN(shape.dn || ''),
    // A STUB CARRYING THE TWO THINGS THE HANDLERS ASK A CONNECTION FOR:
    // whether it is encrypted (`ldapChannelOf()`) and who is bound on it
    // (`boundDnOf()`). `cn=anonymous` where nobody is, because that is what
    // ldapjs seeds an unbound connection with and what `boundDnOf()` reads
    // back as the absence of a bind — a stub with an empty string there would
    // take a different path through a function whose whole job is that
    // distinction.
    connection: { encrypted: shape.channel === 'ldaps',
                  remoteAddress: shape.remoteAddress || '',
                  ldap: { bindDN: shape.boundDn || 'cn=anonymous' } }
  };
  if (operation === 'bind') {
    req.credentials = shape.credentials || '';
  } else if (operation === 'add') {
    req.attributes = shape.attributes || [];
  } else if (operation === 'modify') {
    req.changes = shape.changes || [];
  } else if (operation === 'modifyDN') {
    req.newRdn = shape.newRdn || '';
    req.newSuperior = shape.newSuperior || '';
    req.deleteOldRdn = !!shape.deleteOldRdn;
  } else if (operation === 'compare') {
    req.attribute = shape.attribute || '';
    req.value = shape.value || '';
  } else if (operation === 'search') {
    req.scope = typeof shape.scope === 'number' ? shape.scope : 2;
    req.filter = ldap.parseFilter(shape.filter || '(objectclass=*)');
    req.attributes = shape.attributes || [];
    req.sizeLimit = shape.sizeLimit || 0;
  }
  log.debug('Leaving operationContext().');
  return req;
}

// ---------------------------------------------------------------------------
// AN ERROR CROSSES AS ITS NAME AND ITS MESSAGE, AND IS REBUILT FROM THE SAME
// ldapjs THAT MADE IT.
//
// **NOT AS A HAND-WRITTEN CODE TABLE**, which was the first version and is a
// second copy of something the submodule already states — the kind of copy
// that agrees on the day it is written and is wrong about the tenth error
// somebody adds. The name is looked up on the module's own exports and the
// result is CHECKED: it has to be a constructor whose instances carry a
// numeric `code`, or this is not an LDAP error at all and the front process
// must not turn an arbitrary export into one.
//
// A name that fails those tests becomes an `OperationsError` (result code 1)
// with the original wording, logged loudly. That is the honest answer — the
// operation genuinely failed and this process cannot say precisely how — and
// it is far better than the alternative of resolving successfully, which would
// answer a failed add with LDAP_SUCCESS.
// ---------------------------------------------------------------------------
function ldapErrorNamed(name, message) {
  log.debug('Entering ldapErrorNamed(). name=' + name);
  const candidate = /Error$/.test(String(name || '')) ? ldap[name] : null;
  if (typeof candidate === 'function') {
    try {
      const built = new candidate(message);
      if (typeof built.code === 'number') {
        log.debug('Leaving ldapErrorNamed(). Rebuilt ' + name + '.');
        return built;
      }
    } catch (e) {
      // Falls through to the generic error below, which is what an ldapjs
      // error constructor that does not take a message looks like from here.
      log.warn('ldap: the error "' + name + '" could not be rebuilt: ' +
               e.message);
    }
  }
  log.warn('ldap: a request worker refused an operation with "' + name +
           '", which is not an LDAP error this process can rebuild. The ' +
           'client is being told LDAP_OPERATIONS_ERROR with the original ' +
           'wording.');
  audit.failure('STS-LDAP-0023', {
    channel: 'ldap', protocol: 'LDAP',
    summary: 'a request worker refused an LDAP operation with "' +
             String(name || '') + '", which this process could not rebuild, ' +
             'so the client was told LDAP_OPERATIONS_ERROR',
    outcome: 'error'
  });
  log.debug('Leaving ldapErrorNamed(). Generic.');
  return coded('STS-LDAP-0023', new ldap.OperationsError(message ||
    'the request worker refused this operation'));
}

// ---------------------------------------------------------------------------
// THE RESPONSE A WORKER WRITES INTO. Three methods and one property — see the
// header above for why that is the whole surface and why reproducing it here
// is not the thing `request_worker.js` refused to do for HTTP.
//
// `send()` takes the `SearchEntry` `toSearchEntry()` built and keeps the two
// members that are the ANSWER, dropping the message id, which belongs to the
// response this worker is not writing.
// ---------------------------------------------------------------------------
function collectingResponse() {
  log.debug("Entering collectingResponse().");
  const out = { entries: [], ended: false, endArg: undefined };
  log.debug("Leaving collectingResponse().");
  return {
    // Any number will do and none of it travels; it is here because
    // `toSearchEntry()` reads it and would otherwise default to 1 and trip
    // ldapjs's own mismatch check inside the worker.
    messageId: 1,
    collected: out,
    send: function (entry) {
      log.debug("Entering send().");
      out.entries.push({
        objectName: String(entry.objectName === undefined ? entry.dn :
                           entry.objectName),
        attributes: plainAttributes(entry.attributes)
      });
      log.debug("Leaving send().");
    },
    end: function (arg) {
      log.debug("Entering end().");
      out.ended = true;
      out.endArg = arg;
      log.debug("Leaving end().");
    }
  };
}

// ---------------------------------------------------------------------------
// ONE OPERATION, IN WHICHEVER PROCESS IS RUNNING IT. The handler is the SAME
// function the socket would have called, which is what makes "an operation
// behaves identically in a worker and in the front process" true by
// construction rather than by a comparison somebody maintains.
//
// **A HANDLER THAT NEITHER ENDED NOR FAILED IS A DEFECT AND IS REPORTED AS
// ONE.** That state is what `next()` with no `res.end()` produces, and
// `ldap/CLAUDE.md` records it hanging every client for ever when the size-limit
// branch did it on the socket. Here it would hang them just as completely, one
// process further away, so it is turned into a refusal naming the operation.
// ---------------------------------------------------------------------------
function performOperation(operation, shape) {
  log.debug('Entering performOperation(). operation=' + operation);
  const handler = LOCAL_HANDLERS[operation];
  if (!handler) {
    throw new Error('this process has no handler registered for the LDAP "' +
      operation + '" operation.');
  }
  const req = operationContext(operation, shape);
  const res = collectingResponse();
  let failure = null;
  let called = false;
  let signal = null;
  const finished = new Promise(function (resolve) {
    signal = resolve;
  });
  handler(req, res, function (err) {
    called = true;
    if (err) {
      failure = err;
    }
    signal();
  });
  // A HANDLER THAT SAID IT WENT ASYNCHRONOUS (2026-09-14, #46): the bind asks
  // the cluster's shared rate limiter before it looks at a password. The
  // answer is a promise then — `request_worker.js`'s `handleOperation()`
  // resolves whatever an operation returns — and the same reading below.
  if (!called && req.stsAsyncOperation) {
    log.debug('Leaving performOperation(). Waiting for the handler.');
    return finished.then(function () {
      return operationOutcome(operation, req, res, failure);
    });
  }
  log.debug('Leaving performOperation(). Reading the outcome.');
  return operationOutcome(operation, req, res, failure);
}

// What `performOperation()` answers once its handler has ended or failed.
function operationOutcome(operation, req, res, failure) {
  log.debug('Entering operationOutcome(). operation=' + operation);
  if (failure) {
    // ---------------------------------------------------------------------
    // THE ENTRIES ALREADY SENT TRAVEL WITH THE REFUSAL, AND DROPPING THEM WAS
    // A REAL DEFECT (2026-09-12).
    //
    // **A REFUSAL IS NOT ALWAYS AN EMPTY ANSWER.** The search handler's
    // size-limit branch sends N entries and THEN fails with
    // `SizeLimitExceededError` — RFC 4511 section 4.5.2 requires exactly that:
    // the entries already sent are a valid PARTIAL answer and result code 4 is
    // how the client learns it is partial. This function returned only the
    // error, so a size-limited search run in a worker answered **zero entries
    // and code 4** where the front process answers five hundred entries and
    // code 4.
    //
    // That is worse than it first reads. A client that handles code 4 properly
    // — which is the whole reason the branch sends it — would report "0 of
    // many" and be believed. And `ldap/CLAUDE.md` records this branch already
    // having cost this service months once, by hanging every client; the
    // dispatched version would have broken it a second time, differently, in
    // the one mode nothing routine exercises.
    //
    // **NOTHING IN EITHER SUITE WOULD HAVE SEEN IT** for the reason recorded
    // there: `ldap.sizeLimit` is 500 and the seeded directory holds about
    // thirty entries, so the only thing anywhere that reaches this branch is
    // `tests/vendored/sts_directory_bulk_load_ldap.js` — over a socket, in a
    // stack, with operations off.
    // ---------------------------------------------------------------------
    log.debug('Leaving operationOutcome(). Refused with ' +
              res.collected.entries.length + ' entry/entries already sent.');
    return { ok: false, errorName: failure.name || 'OperationsError',
             error: failure.message || '',
             entries: res.collected.entries };
  }
  if (!res.collected.ended) {
    log.debug('Leaving operationOutcome(). The handler ended nothing.');
    audit.failure('STS-LDAP-0024', {
      channel: ldapChannelOf(req), protocol: 'LDAP', target: operation,
      summary: 'the LDAP "' + operation + '" handler finished without ' +
               'sending a result message or failing',
      outcome: 'error'
    });
    log.debug("Leaving operationOutcome().");
    return { ok: false, errorName: 'OperationsError',
             error: 'the "' + operation + '" handler finished without ' +
               'sending a result message. See ldap/CLAUDE.md — a handler ' +
               'that neither ends nor fails hangs the client for ever.' };
  }
  log.debug('Leaving operationOutcome(). ' + res.collected.entries.length +
            ' entry/entries.');
  return { ok: true, entries: res.collected.entries,
           endArg: res.collected.endArg };
}

// ---------------------------------------------------------------------------
// AND THE RESULT, WRITTEN TO THE REAL RESPONSE.
//
// The SOCKET-side effects of a bind live here and nowhere else — see the
// header: the worker decides, this process stamps the connection and publishes
// the snapshot, because the connection is this process's.
// ---------------------------------------------------------------------------
function applyOperationResult(operation, req, res, next, result) {
  log.debug('Entering applyOperationResult(). operation=' + operation);
  // THE ENTRIES GO OUT FIRST, WHETHER OR NOT THE OPERATION SUCCEEDED. A
  // size-limited search is a PARTIAL ANSWER plus result code 4 (RFC 4511
  // section 4.5.2), so sending them only on the success path answers zero
  // entries and code 4 — see performOperation()'s block on the same subject.
  // Every other refusal collected none, so this loop does nothing for them.
  if (operation === 'search') {
    (result && result.entries || []).forEach(function (entry) {
      res.send(new ldap.SearchEntry({
        // THE RESPONSE'S OWN MESSAGE ID. See toSearchEntry()'s header for what
        // sending anything else costs.
        messageId: res.messageId,
        objectName: entry.objectName,
        attributes: (entry.attributes || []).map(function (attribute) {
          return new ldap.Attribute({ type: attribute.type,
                                      values: attribute.values });
        })
      }));
    });
  }
  if (!result || !result.ok) {
    const err = ldapErrorNamed(result && result.errorName,
                               result && result.error);
    log.debug('Leaving applyOperationResult(). Refused.');
    return next(err);
  }
  if (operation === 'bind') {
    // THE TWO THINGS A WORKER CANNOT DO. Both are exactly what the bind
    // handler does on its own success path, and they are ordered the same way:
    // stamp the socket, then publish a TICK LATER, because ldapjs sets the
    // bound DN only once the handler chain has returned.
    if (req.connection) {
      req.connection.stsBoundAt = Date.now();
    }
    publishConnectionsSoon();
  }
  // `res.end(matched)` for a compare and `res.end()` for everything else — the
  // argument is carried rather than reconstructed, so a handler that starts
  // ending with something new needs no edit here.
  if (result.endArg === undefined) {
    res.end();
  } else {
    res.end(result.endArg);
  }
  log.debug('Leaving applyOperationResult(). Ended.');
  return next();
}

// ---------------------------------------------------------------------------
// THE WRAPPER THE SOCKET ACTUALLY CALLS.
//
// **IT FALLS BACK TO RUNNING HERE ONLY WHERE NOTHING RAN ANYWHERE.** A pool
// that is off, an operation not named in `workers.dispatch`, no worker to take
// it — `runOperation()` answers `{ dispatched: false }` for all three and this
// process does the work, which is what `workers.requestCount = 0` means and is
// a supported configuration rather than a degraded one.
//
// **A REJECTION IS A REFUSAL AND NOT A SECOND ATTEMPT**, which is
// `request_pool.js`'s "never silently half-dispatched" rule read for a
// protocol that has no 503. A worker that died mid-add may have written the
// entry; running the handler here as well would then refuse with
// LDAP_ENTRY_ALREADY_EXISTS for an entry this client had just successfully
// created, or — worse, on a modify — apply a change twice. Answering
// LDAP_UNAVAILABLE says what is true: this service could not complete the
// operation, and the client may try again.
// ---------------------------------------------------------------------------
function throughTheRequestPool(operation, local) {
  log.debug("Entering throughTheRequestPool().");
  log.debug("Leaving throughTheRequestPool().");
  return function (req, res, next) {
    const pool = requestPool();
    if (!pool || typeof pool.runOperation !== 'function') {
      return local(req, res, next);
    }
    let shape = null;
    try {
      shape = operationRequest(operation, req);
    } catch (e) {
      // A request this process cannot describe is one it runs itself. It is
      // worth a line: the alternative is a surface that silently stops being
      // dispatched and nobody knows why it got slower.
      log.warn('ldap: the ' + operation + ' request could not be described ' +
               'for a request worker (' + e.message + '), so it is being ' +
               'handled in this process.');
      return local(req, res, next);
    }
    pool.runOperation('ldap.' + operation, shape,
                      { affinity: connectionAffinity(req) })
      .then(function (answer) {
        if (!answer || !answer.dispatched) {
          return local(req, res, next);
        }
        return applyOperationResult(operation, req, res, next, answer.result);
      })
      .catch(function (err) {
        log.error(errorCodes.tag('STS-LDAP-0022') +
                  'ldap: a request worker failed the ' + operation +
                  ' operation: ' + err.message + '. The client is being told ' +
                  'LDAP_UNAVAILABLE rather than having it retried here, ' +
                  'because a worker that died part way through may already ' +
                  'have written.');
        return next(ldapRefusal(req, 'STS-LDAP-0022',
          'a request worker failed the ' + operation + ' operation, so the ' +
          'client was told LDAP_UNAVAILABLE',
          new ldap.UnavailableError(
            'the request worker handling this operation did not complete it: ' +
            err.message), '', 'error'));
      });
  };
}

// ---------------------------------------------------------------------------
// AND THE REGISTRATION ON THE WORKER SIDE.
//
// `common/request_worker.js` offers `register(kind, fn)` and its header says
// the table is filled BY THE MODULE THAT OWNS THE OPERATION — so this is that
// module doing it, at require time, exactly as requiring a protocol module is
// what registers its routes (rule 1).
//
// **IT IS GUARDED AND SILENT IN A PROCESS THAT IS NOT A WORKER.** Requiring
// `request_worker.js` from the front process is harmless (its child wiring is
// behind the `begin` message), but registering there would be filling a table
// nothing will ever read, and `register()` THROWS on a second registration —
// which in a process that loads this module twice would turn a duplicate
// require into a startup failure about a feature that is off.
// ---------------------------------------------------------------------------
function registerWorkerOperations() {
  log.debug('Entering registerWorkerOperations().');
  // ONLY IN A PROCESS THAT IS ACTUALLY A WORKER (2026-09-12). Requiring
  // `request_worker.js` pulls `common/service_state.js` in at module scope —
  // the store, the keys, the minted rows and coordination — and installs
  // `process.on('message')` handlers, which in a process that will never
  // answer an operation is a table nothing reads bought with half the
  // service's startup machinery. `spiffe_grpc.js`'s `registerWorkerMethod()`
  // carries the argument and the test it cost. `LOCAL_HANDLERS` is filled at
  // registration either way, because it is also the fallback path.
  if (!process.env.STS_REQUEST_WORKER) {
    log.debug('Leaving registerWorkerOperations(). Not a request worker.');
    return;
  }
  let worker = null;
  try {
    worker = require('../common/request_worker');
  } catch (e) {
    log.debug("Caught in registerWorkerOperations(): " +
              ((e && e.message) || e));
    log.debug('Leaving registerWorkerOperations(). No worker module.');
    return;
  }
  if (!worker || typeof worker.register !== 'function') {
    log.debug('Leaving registerWorkerOperations(). Nothing to register with.');
    return;
  }
  DISPATCHABLE_OPERATIONS.forEach(function (operation) {
    const kind = 'ldap.' + operation;
    if (worker.OPERATIONS && worker.OPERATIONS.has(kind)) {
      return;
    }
    worker.register(kind, function (shape) {
      return performOperation(operation, shape);
    });
  });
  log.debug('Leaving registerWorkerOperations(). ' +
            DISPATCHABLE_OPERATIONS.length + ' operation(s) registered.');
}

// --- bind ------------------------------------------------------------------
server.bind('', function (req, res, next) {
  log.debug('Entering the LDAP bind handler.');
  const dn = req.dn ? req.dn.toString() : '';
  // NAMED `credentials_value` AND NOT `credentials` since 2026-09-06: the
  // module now requires `common/credentials.js` under that name, and a local
  // shadowing it here would make the verifier unreachable from the one handler
  // that most needs it — silently, because the shadow is a string and calling
  // `.verify()` on it is a TypeError at the first bind rather than at load.
  const credentials_value = req.credentials === undefined ? '' :
                            String(req.credentials);
  log.info('ldap: BIND dn="' + dn + '" (' +
           (dn ? 'named' : 'anonymous') + '), ' + credentials_value.length +
           ' character password.');
  // ---------------------------------------------------------------------
  // THE FOUR PRODUCT-MODE REFUSALS THAT COME BEFORE A PASSWORD IS READ
  // (2026-09-12). See *THE DIRECTORY'S READ AND BIND SECURITY*. Their order is
  // the design: none of them looks at the password, and the rate limit is last
  // so that a caller refused for a reason that has nothing to do with guessing
  // is never counted as a guesser.
  //
  // **AN ANONYMOUS BIND** (no name) is refused with inappropriateAuthentication
  // (48), which is what RFC 4513 section 5.1.1 says a server that does not
  // offer anonymous access answers. The paragraph lower down that calls one "a
  // legal operation" is still right about DEVELOPMENT — it is legal, and a
  // server MAY support it — and product mode is a server that does not.
  // ---------------------------------------------------------------------
  if (mode.requiresDirectoryBind() && !dn) {
    log.debug('Leaving the LDAP bind handler. Anonymous, in product mode.');
    return next(ldapRefusal(req, 'STS-LDAP-0070', 'an anonymous bind was ' +
      'refused; product mode requires a bind as somebody',
      new ldap.InappropriateAuthenticationError(
        'anonymous binds are not accepted; bind with a DN and a password'),
      '(anonymous)'));
  }
  // **A PASSWORD ON THE PLAIN LISTENER** is refused with
  // confidentialityRequired (13) BEFORE it is checked. It has already crossed
  // the network in the clear by the time this line runs, so the refusal cannot
  // protect this password — what it does is stop 389 being a port where a
  // correct password WORKS, so no client is ever configured to send one there.
  if (mode.requiresConfidentialDirectoryBinds() &&
      ldapChannelOf(req) !== 'ldaps') {
    log.debug('Leaving the LDAP bind handler. A password over plain LDAP.');
    return next(ldapRefusal(req, 'STS-LDAP-0071', 'a bind as ' + dn + ' on ' +
      'the plain LDAP listener was refused before its password was read; ' +
      'binds require LDAPS', new ldap.ConfidentialityRequiredError(
        'binds on this listener are refused; use LDAPS (ldap.tlsPort)'), dn));
  }
  // **A NAME WITH NO PASSWORD** is RFC 4513 section 5.1.2's unauthenticated
  // bind, which a client library sends when a password field was left empty —
  // and which, accepted, looks like a successful login as that name. Section
  // 5.1.2 says a server SHOULD refuse it with unwillingToPerform (53) by
  // default.
  if (mode.requiresDirectoryBind() && credentials_value === '') {
    log.debug('Leaving the LDAP bind handler. An unauthenticated bind.');
    return next(ldapRefusal(req, 'STS-LDAP-0072', 'an unauthenticated bind ' +
      '(a DN with an empty password) as ' + dn + ' was refused',
      new ldap.UnwillingToPerformError(
        'unauthenticated binds are not accepted; supply the password'), dn));
  }
  // **FAILED BINDS ARE RATE LIMITED**, and this reads the buckets without
  // counting. A caller over either limit is refused whether or not this
  // password is right, so a correct guess during a lockout teaches nothing.
  //
  // **ONE BUDGET FOR THE CLUSTER SINCE 2026-09-14 (#46)**: the buckets are read
  // with `blockedShared()`, which counts in the store every node shares and is
  // `blocked()` where none is shared. That is a round trip, so the rest of the
  // bind is `finishBind()` below, run when the answer is in — ldapjs's `next`
  // is a callback and does not care which tick it is called on.
  //
  // **AND ONLY WHERE A STORE IS SHARED.** With none, `blocked()` answers in the
  // same tick exactly as before — so a bind stays synchronous in memory mode,
  // which `performOperation()`'s callers and every in-process test rely on.
  // Where it does go asynchronous the request says so
  // (`stsAsyncOperation`), and `performOperation()` waits for `next`.
  const bindLimited = mode.limitsDirectoryBindFailures();
  if (!bindLimited) {
    log.debug('Leaving the LDAP bind handler. Unlimited; finishing.');
    return finishBind();
  }
  const refuseLockedOut = function (lockedOut) {
    log.debug("Entering refuseLockedOut().");
    log.info('ldap: refusing a bind as ' + dn + '; too many failed ' +
             'binds (' + lockedOut.kind + ' limit ' + lockedOut.limit + ').');
    log.debug("Leaving refuseLockedOut().");
    return next(ldapRefusal(req, 'STS-LDAP-0073', 'a bind as ' + dn +
      ' was refused without checking its password: too many failed ' +
      'binds for this ' + (lockedOut.kind === 'address' ? 'address' : 'DN') +
      ' (limit ' + lockedOut.limit + ')',
      new ldap.UnwillingToPerformError('too many failed binds; retry in ' +
        lockedOut.retryAfterS + ' seconds'), dn));
  };
  if (!websecurity.sharesLimits()) {
    const lockedOut = websecurity.blocked('ldap-bind', limiterRequestOf(req),
                                          dn);
    log.debug('Leaving the LDAP bind handler. Limited in this process.');
    return lockedOut ? refuseLockedOut(lockedOut) : finishBind();
  }
  req.stsAsyncOperation = true;
  // `next` from here on is called once, whichever path answers.
  let nextCalled = false;
  const answerOnce = next;
  next = function (err) {
    nextCalled = true;
    return answerOnce(err);
  };
  websecurity.blockedShared('ldap-bind', limiterRequestOf(req), dn)
    .then(function (lockedOut) {
      return lockedOut ? refuseLockedOut(lockedOut) : finishBind();
    })
    .catch(function (e) {
      log.error(errorCodes.tag('STS-LDAP-0094') + 'ldap: a bind as ' + dn +
                ' could not be completed: ' + ((e && e.stack) || e));
      // EXACTLY ONE RESULT: a throw from inside a `next` that already ran
      // (the refusal or `finishBind()`'s own) must not send a second.
      if (nextCalled) {
        return undefined;
      }
      return next(coded('STS-LDAP-0094',
        new ldap.OperationsError('the bind could not be completed')));
    });
  log.debug('Leaving the LDAP bind handler. Asking the rate limiter.');
  return undefined;

  // EVERYTHING AFTER THE RATE LIMIT, unchanged but for its exits. Hoisted, so
  // both paths above reach it; it closes over the handler's own names.
  function finishBind() {
  log.debug("Entering finishBind().");
  if (credentials_value === REFUSED_PASSWORD) {
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
      action: 'directory.bind', outcome: 'refused', errorCode: 'STS-LDAP-0001',
      // Not the connection's bound DN, which for a REFUSED bind is whatever the
      // connection was before: the DN this attempt named.
      actor: dn ? consoleKeyFor(dn, getEntry(dn)) : '', actorForm: dn,
      target: dn || '(anonymous)',
      summary: 'a bind as ' + (dn || '(anonymous)') + ' was refused with ' +
               'LDAP_INVALID_CREDENTIALS (49)',
      detail: { resultCode: 49,
                reason: 'the password is the literal string "' +
                        REFUSED_PASSWORD + '", the one this service refuses ' +
                        'in every protocol' }
    });
    if (bindLimited && websecurity.sharesLimits()) {
      // AWAITED WHERE THE COUNT IS SHARED (2026-09-14): a failure whose
      // increment took the bucket past the limit is answered with the
      // lockout — `websecurity.failedShared()` argues it.
      log.debug("Leaving finishBind(). Counting the failure first.");
      return websecurity.failedShared('ldap-bind', limiterRequestOf(req), dn)
        .then(function (overLimit) {
          return overLimit ? refuseLockedOut(overLimit)
            : next(coded('STS-LDAP-0001', new ldap.InvalidCredentialsError()));
        });
    }
    if (bindLimited) {
      // In this process's buckets, where nothing is shared: synchronous, and
      // one process cannot race itself.
      websecurity.attemptShared('ldap-bind', limiterRequestOf(req), dn);
    }
    log.debug('Leaving the LDAP bind handler. LDAP_INVALID_CREDENTIALS.');
    log.debug("Leaving finishBind().");
    return next(coded('STS-LDAP-0001', new ldap.InvalidCredentialsError()));
  }
  // ---------------------------------------------------------------------
  // THE CREDENTIAL (2026-09-06). Product mode verifies it; development checks
  // nothing, which is what this door has always done.
  //
  // **AN ANONYMOUS BIND IS NOT VERIFIED IN EITHER MODE**, and that is RFC 4511
  // section 5.1.1 rather than a permission: a bind with an empty name and an
  // empty password is the unauthenticated bind the specification defines, and
  // refusing it in product mode would be refusing a legal operation. What it
  // gets is an unauthenticated connection, which is what it asks for.
  //
  // The person is named by the DN, so the verification is keyed on the DN and
  // `credentials.js` resolves it through the same `locateEntry()` every other
  // reader here uses — a bind as `uid=alice,ou=users,...` verifies alice's own
  // `userPassword`, which is what an LDAP client expects and what makes this
  // directory usable as a credential store by something that is not this
  // service.
  // WHETHER A PASSWORD WAS ACTUALLY CHECKED, for the two rows below. They both
  // said "no password was checked" on every successful bind until 2026-09-12,
  // which stopped being true the day product mode started verifying: an audit
  // log asserting the opposite of what happened is worse than one saying
  // nothing. It is read off the verifier's own answer rather than off the
  // mode, so the row describes THIS bind — an anonymous bind is unverified in
  // both modes, and `reason: 'verified'` is the only answer that means a hash
  // was compared.
  let verified = false;
  if (dn) {
    const checked = credentials.verify(dn, credentials_value,
                                       { via: 'an LDAP simple bind' });
    verified = !!(checked && checked.ok && checked.reason === 'verified');
    if (!checked.ok) {
      log.info('ldap: refusing the bind for ' + dn + ' (' + checked.reason +
               '): ' + checked.detail);
      auditLdap(req, {
        action: 'directory.bind',
        actor: consoleKeyFor(dn, getEntry(dn)), actorForm: dn,
        target: dn, outcome: 'failure',
        // The verifier's own code for WHY (common/credentials.js), or this one.
        errorCode: errorCodes.codeOf(checked) || 'STS-LDAP-0002',
        summary: 'a simple bind as ' + dn + ' was refused',
        detail: { reason: checked.reason, note: checked.detail }
      });
      // COUNTED, and only here and at the literal-password refusal above: a
      // FAILURE is what the limit is about. See `websecurity.blocked()`.
      if (bindLimited && websecurity.sharesLimits()) {
        // Awaited, as at the literal-password refusal above.
        log.debug("Leaving finishBind(). Counting the failure first.");
        return websecurity.failedShared('ldap-bind', limiterRequestOf(req), dn)
          .then(function (overLimit) {
            return overLimit ? refuseLockedOut(overLimit)
              : next(coded(errorCodes.codeOf(checked) || 'STS-LDAP-0002',
                           new ldap.InvalidCredentialsError()));
          });
      }
      if (bindLimited) {
        websecurity.attemptShared('ldap-bind', limiterRequestOf(req), dn);
      }
      log.debug("Leaving finishBind(). The credential was refused.");
      return next(coded(errorCodes.codeOf(checked) || 'STS-LDAP-0002',
                        new ldap.InvalidCredentialsError()));
    }
    if (bindLimited && websecurity.sharesLimits()) {
      // A VERIFIED PASSWORD IS ANSWERED ONLY WHILE THE BUCKETS ARE UNDER THE
      // LIMIT (2026-09-14): a right guess racing a burst that spent the budget
      // is refused like the burst. A read, so a pool binding fifty connections
      // at once costs nothing. `websecurity.failedShared()` argues it.
      log.debug("Leaving finishBind(). Settling the success first.");
      return websecurity.succeededShared('ldap-bind', limiterRequestOf(req),
        dn, { keepAddress: true, unlessBlocked: true })
        .then(function (racedOut) {
          return racedOut ? refuseLockedOut(racedOut) : bindAccepted();
        });
    }
    if (bindLimited) {
      websecurity.succeededShared('ldap-bind', limiterRequestOf(req), dn,
                                  { keepAddress: true });
    }
  }
  log.debug("Leaving finishBind(). Accepted.");
  return bindAccepted();

  // THE ACCEPTED BIND, split out so the shared limiter's answer can come first.
  function bindAccepted() {
  log.debug("Entering bindAccepted().");
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
              passwordVerified: verified,
              note: verified
                ? 'the password was verified against this entry\'s userPassword'
                : !dn
                  ? 'an anonymous bind: RFC 4511 section 5.1.1 defines it as ' +
                    'unauthenticated, so there was no password to check'
                  : 'no password was checked; every bind here succeeds ' +
                    'except the password "' + REFUSED_PASSWORD + '"' }
  });
  stats.recordAuthentication({
    presented: dn || '(anonymous)',
    protocol: 'ldap',
    method: dn ? 'simple bind' : 'anonymous simple bind',
    note: verified ? 'the password was verified' : 'no password was checked'
  });
  // WHEN THIS CONNECTION BECAME THIS PERSON'S SESSION (2026-09-04). In LDAP the
  // connection IS the session (RFC 4511 section 4.2), and until this line there
  // was no record anywhere of when one started — so /admin/sessions could say a
  // directory connection was live and not since when, which is the one fact a
  // reader of that page wants about a session with no expiry. It is stamped on
  // the SOCKET rather than kept in a map here, because the socket is the thing
  // that dies: a Map would be a second answer to "is this still live", which is
  // the rule logout.js keeps.
  //
  // It is set on every successful bind, including a re-bind on a connection
  // that was already bound as somebody else — that is a new session on the same
  // socket, and dating it from the first bind would age it wrongly.
  if (req.connection) {
    req.connection.stsBoundAt = Date.now();
  }
  // AND TELL THE REQUEST WORKERS, because this is the event that matters to
  // them: an unbound socket is nobody's session and a bound one is, so a
  // snapshot taken before this line is a snapshot in which this person is not
  // signed in. **A TICK LATER, because the DN this bind established is not on
  // the connection yet** — see publishConnectionsSoon().
  publishConnectionsSoon();
  res.end();
  log.debug('Leaving the LDAP bind handler. The bind succeeded.');
  log.debug("Leaving bindAccepted().");
  return next();
  }
  }
});

// ---------------------------------------------------------------------------
// THE OTHER END OF THE MIRROR: THIS PROCESS TELLING THE WORKERS.
//
// Filled by common/request_pool.js in the FRONT process, which is the one that
// holds the sockets. It is an inverted hook for rule 3e's reason read in the
// usual direction: this module is required at 21 and the pool is a library the
// listener process loads before anything, so a require from here to there would
// be this file reaching up into the process's own bootstrap.
//
// **A SNAPSHOT IS PUSHED ON CHANGE AND NOT ON A TIMER.** Three things change
// it — a connection arriving, a connection closing, and a BIND, which is the
// one that turns an anonymous socket into somebody's session and is therefore
// the only one that can make a row worth ending. A poll would put a sign-out's
// correctness on an interval; there are single-digit numbers of these events in
// an ordinary run.
// ---------------------------------------------------------------------------
let connectionWatcher = null;

function setConnectionWatcher(fn) {
  log.debug("Entering setConnectionWatcher().");
  connectionWatcher = (typeof fn === 'function') ? fn : null;
  log.debug("Leaving setConnectionWatcher().");
}

// What travels: everything boundConnections() reports EXCEPT the socket, which
// is the one member that cannot cross a process boundary and the one no reader
// but dropConnectionsFor() has ever used.
function connectionSnapshot() {
  log.debug("Entering connectionSnapshot().");
  // THIS NODE'S ONLY: another node's rows reach a worker through the cluster
  // table, and mirrored as well they would be listed twice.
  const rows = localBoundConnections().map(function (row) {
    return { id: row.id, dn: row.dn, key: row.key, secure: row.secure,
             port: row.port, boundAt: row.boundAt };
  });
  log.debug("Leaving connectionSnapshot(). " + rows.length + " row(s).");
  return rows;
}

// Called from the three places the set can change. Guarded, because a watcher
// that threw would take down a bind — publishing is bookkeeping and a bind is
// the protocol.
function publishConnections() {
  log.debug("Entering publishConnections().");
  if (!connectionWatcher) {
    log.debug("Leaving publishConnections().");
    return;
  }
  try {
    connectionWatcher(connectionSnapshot());
  } catch (e) {
    log.warn(errorCodes.tag('STS-LDAP-0033') +
             'ldap: the connection watcher failed: ' + e.message +
             '. A request worker may be holding a stale list of connections, ' +
             'so a sign-out there could miss one.');
  }
  log.debug("Leaving publishConnections().");
}

// ---------------------------------------------------------------------------
// A TICK LATER, AND THAT IS NOT A PRECAUTION — IT IS WHERE THE DN IS.
//
// **ldapjs sets `conn.ldap.bindDN` AFTER the handler chain has run**, in
// `node-ldapjs/lib/server.js` at the point where it finds no handler left:
// `conn.ldap.bindDN = DN.fromString(req.dn)`. So a snapshot taken INSIDE the
// bind handler is a snapshot of an anonymous connection — every row carries an
// empty DN, `consoleKeyFor()` therefore derives no key, and `logout.js`'s ldap
// family filters on exactly that key. The first version of this published
// there and a worker's mirror filled up with rows belonging to nobody: the
// sign-out found nothing to end, which is the original bug wearing the
// mechanism that was meant to fix it.
//
// It also COALESCES, which the connect and close sites want anyway: a client
// that opens and closes several connections in a burst publishes once.
// ---------------------------------------------------------------------------
let publishScheduled = false;

function publishConnectionsSoon() {
  log.debug("Entering publishConnectionsSoon().");
  // The cluster table first, and whatever the in-container watcher is doing:
  // a node with no request workers has no watcher and still has a table row.
  clusterConnections.noteLocalChange();
  if (!connectionWatcher || publishScheduled) {
    log.debug("Leaving publishConnectionsSoon().");
    return;
  }
  publishScheduled = true;
  setImmediate(function () {
    publishScheduled = false;
    publishConnections();
  });
  log.debug("Leaving publishConnectionsSoon().");
}

// --- add -------------------------------------------------------------------
server.add('', function (req, res, next) {
  log.debug('Entering the LDAP add handler.');
  const dn = req.dn.toString();
  log.info('ldap: ADD ' + dn);
  const addRefusal = directoryWriteRefusal(req, 'add', dn);
  if (addRefusal) {
    log.debug('Leaving the LDAP add handler. Not authorized.');
    return next(addRefusal);
  }
  const addOperationalRefusal = operationalWriteRefusal(req, 'add', dn,
    (req.attributes || []).map(function (attr) {
      return String(attr.type || '').toLowerCase();
    }));
  if (addOperationalRefusal) {
    log.debug('Leaving the LDAP add handler. An operational attribute.');
    return next(addOperationalRefusal);
  }
  // ROOT_DN, not baseDn(): THIS IS THE SOCKET, and the socket has no realm. An
  // LDAP client operating on `dc=acme,dc=example,dc=com` arrives with no
  // ambient realm at all, so asking whether its DN is under the DEFAULT realm's
  // base would refuse every realm's subtree — which is the one thing putting
  // the realm in the DN exists to make possible. The naming context this server
  // holds is the whole tree; which realm a DN belongs to is decided by where it
  // sits in that tree, and nothing here has to know.
  if (!isUnder(dn, ROOT_DN)) {
    log.debug('Leaving the LDAP add handler. Outside the naming context.');
    return next(ldapRefusal(req, 'STS-LDAP-0003', 'an add of ' + dn +
      ' named a DN outside this directory\'s naming context',
      new ldap.NoSuchObjectError(ROOT_DN), dn));
  }
  if (getEntry(dn)) {
    log.debug('Leaving the LDAP add handler. It is already there.');
    return next(ldapRefusal(req, 'STS-LDAP-0004', 'an add of ' + dn +
      ' named an entry that already exists',
      new ldap.EntryAlreadyExistsError(dn), dn));
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
      return next(ldapRefusal(req, 'STS-LDAP-0005', 'an add of ' + dn +
        ' named a username ' + clash.dn + ' already holds',
        new ldap.EntryAlreadyExistsError(clash.dn), dn));
    }
  }
  const parent = parentDn(dn);
  if (parent && !getEntry(parent)) {
    // A directory is a tree. See the header: this refusal is one of the three
    // real rules this schemaless mock still enforces.
    log.info('ldap: refusing to add ' + dn + '; its parent ' + parent +
             ' does not exist.');
    log.debug('Leaving the LDAP add handler. The parent is missing.');
    return next(ldapRefusal(req, 'STS-LDAP-0006', 'an add of ' + dn +
      ' named a parent that does not exist',
      new ldap.NoSuchObjectError(parent), dn));
  }
  if (totalEntries() >= maxEntries()) {
    log.debug('Leaving the LDAP add handler. The directory is full.');
    return next(ldapRefusal(req, 'STS-LDAP-0007', 'an add of ' + dn +
      ' was refused because the directory holds its maximum of ' +
      maxEntries() + ' entries',
      new ldap.AdminLimitExceededError(
        'this directory holds its maximum of ' + maxEntries() + ' entries'),
      dn));
  }
  const attributes = {};
  let nulRefusal = null;
  req.attributes.forEach(function (attr) {
    nulRefusal = nulRefusal || refuseNulValues(attr.type, attr.values);
    attributes[attr.type] = attr.values.slice(0);
  });
  if (nulRefusal) {
    // BEFORE putEntry(), so a refused add writes nothing at all — a partial
    // entry would be worse than the value it was refused for.
    log.debug('Leaving the LDAP add handler. A value carried a NUL byte.');
    return next(ldapRefusal(req, '', 'an add of ' + dn +
      ' carried a value with a NUL byte', nulRefusal, dn));
  }
  // A PERSON ADDED WITH A PASSWORD meets the password policy and is stored as
  // a hash, like a password set at any other door. Placement decides it is a
  // person, for the reason the username check above states; also BEFORE
  // putEntry(), for the NUL refusal's reason.
  const addedPassword = {};
  if (normalizeDn(parentDn(dn)) === normalizeDn(usersDn())) {
    const policyRefusal = passwordWriteRefusal(dn, attributes, {},
      Object.keys(attributes).map(function (key) { return key.toLowerCase(); }),
      addedPassword);
    if (policyRefusal) {
      log.debug('Leaving the LDAP add handler. The password was refused.');
      return next(ldapRefusal(req, '', 'an add of ' + dn +
        ' carried a userPassword the password policy refused',
        policyRefusal, dn));
    }
  }
  const addedEntry = putEntry(dn, attributes, { origin: 'ldap add' });
  if (addedPassword.password) {
    credentials.passwordWritten(addedPassword.name, addedPassword.password);
  }
  if (isPersonEntry(addedEntry)) {
    noteAccountChange('created', addedEntry.dn, {},
                      attributeSnapshot(addedEntry));
  }
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
  const deleteRefusal = directoryWriteRefusal(req, 'delete', dn);
  if (deleteRefusal) {
    log.debug('Leaving the LDAP delete handler. Not authorized.');
    return next(deleteRefusal);
  }
  const stored = getEntry(dn);
  if (!stored) {
    log.debug('Leaving the LDAP delete handler. There is no such entry.');
    return next(ldapRefusal(req, 'STS-LDAP-0013', 'a delete named ' + dn +
      ', which does not exist', new ldap.NoSuchObjectError(dn), dn));
  }
  if (isBootstrapAdministratorEntry(stored)) {
    log.debug('Leaving the LDAP delete handler. The bootstrap administrator.');
    return next(ldapRefusal(req, 'STS-LDAP-0077', 'a delete of ' + dn +
      ' was refused: it is the default realm\'s bootstrap administrator, ' +
      'which cannot be deleted', new ldap.UnwillingToPerformError(dn), dn));
  }
  if (hasChildren(dn)) {
    log.debug('Leaving the LDAP delete handler. It is not a leaf.');
    return next(ldapRefusal(req, 'STS-LDAP-0014', 'a delete of ' + dn +
      ' was refused because it has entries beneath it',
      new ldap.NotAllowedOnNonLeafError(dn), dn));
  }
  const deletedPerson = isPersonEntry(stored);
  const deletedAttributes = attributeSnapshot(stored);
  const deletedName = usernameOfEntry(stored);
  entries.delete(normalizeDn(dn));
  touchDirectory();
  if (deletedPerson) {
    noteAccountChange('deleted:' + deletedName, stored.dn, deletedAttributes,
                      {});
  }
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
  log.info('ldap: MODIFY ' + dn + ' with ' + req.changes.length +
           ' change(s).');
  const modifyRefusal = directoryWriteRefusal(req, 'modify', dn,
    req.changes.map(function (change) {
      return String(change.modification.type || '').toLowerCase();
    }));
  if (modifyRefusal) {
    log.debug('Leaving the LDAP modify handler. Not authorized.');
    return next(modifyRefusal);
  }
  const modifyOperationalRefusal = operationalWriteRefusal(req, 'modify', dn,
    req.changes.map(function (change) {
      return String(change.modification.type || '').toLowerCase();
    }));
  if (modifyOperationalRefusal) {
    log.debug('Leaving the LDAP modify handler. An operational attribute.');
    return next(modifyOperationalRefusal);
  }
  const stored = getEntry(dn);
  if (!stored) {
    log.debug('Leaving the LDAP modify handler. There is no such entry.');
    return next(ldapRefusal(req, 'STS-LDAP-0013', 'a modify named ' + dn +
      ', which does not exist', new ldap.NoSuchObjectError(dn), dn));
  }
  if (!req.changes.length) {
    log.debug('Leaving the LDAP modify handler. It asked for no changes.');
    return next(ldapRefusal(req, 'STS-LDAP-0015', 'a modify of ' + dn +
      ' carried no changes',
      new ldap.ProtocolError('a modify must carry at least one change'), dn));
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
  // The same snapshot writePerson() takes, and for the same reason: `working`
  // becomes `stored.attributes` below, so anything captured by reference would
  // read back as unchanged.
  const beforeModify = attributeSnapshot(stored);
  for (let i = 0; i < req.changes.length; i++) {
    const change = req.changes[i];
    const operation = String(change.operation || '').toLowerCase();
    const type = String(change.modification.type || '').toLowerCase();
    const values = change.modification.values.map(function (v) {
      return String(v);
    });
    const nulInChange = refuseNulValues(type, values);
    if (nulInChange) {
      // RFC 4511 section 4.6 says the changes are applied as one unit, so this
      // returns before ANY of them is applied rather than part way through.
      log.debug('Leaving the LDAP modify handler. Change ' + (i + 1) +
                ' carried a NUL byte.');
      return next(ldapRefusal(req, '', 'a modify of ' + dn +
        ' carried a value with a NUL byte', nulInChange, dn));
    }
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
        log.debug('Leaving the LDAP modify handler. ' + type +
                  ' is not there.');
        return next(ldapRefusal(req, 'STS-LDAP-0017', 'a modify of ' + dn +
          ' deleted the attribute ' + type + ', which the entry does not hold',
          new ldap.NoSuchAttributeError(type), dn));
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
      return next(ldapRefusal(req, 'STS-LDAP-0016', 'a modify of ' + dn +
        ' named an unknown change operation',
        new ldap.ProtocolError('unknown modify operation "' + operation + '"'),
        dn));
    }
  }
  // AND A PASSWORD THIS MODIFY SETS meets the password policy against the
  // entry as it was BEFORE the modify — its current password and its history —
  // and is hashed into the working copy. Here, after every change is applied
  // and before any is committed, so a refusal leaves the entry untouched.
  const modifiedPassword = {};
  if (isPersonEntry(stored)) {
    const policyRefusal = passwordWriteRefusal(stored.dn, working,
      stored.attributes, req.changes.map(function (change) {
        return String(change.modification.type || '').toLowerCase();
      }), modifiedPassword);
    if (policyRefusal) {
      log.debug('Leaving the LDAP modify handler. The password was refused.');
      return next(ldapRefusal(req, '', 'a modify of ' + dn +
        ' was refused by the password rules', policyRefusal, dn));
    }
  }
  // A ROW WITH NO createTimestamp (one imported, or written by hand into a
  // store) used to be given `undefined` here, and the next reader of the
  // entry that copies each value — `entryObject()`, behind every SCIM list —
  // threw on it (2026-09-14). The entry's own creation instant is the value
  // when there is one; otherwise the attribute stays absent.
  if (stored.attributes.createtimestamp) {
    working.createtimestamp = stored.attributes.createtimestamp;
  } else if (stored.createdAt) {
    working.createtimestamp = [String(stored.createdAt)];
  } else {
    delete working.createtimestamp;
  }
  // AND THE UUID, for the same reason and one more: it is the subject of every
  // token this entry's person holds, so a modify that dropped it would sign
  // them out of every relying party that links on `sub`. The refusal above
  // stops a client NAMING it; this stops a `replace` of the whole entry's
  // attributes from losing it.
  if (stored.attributes.entryuuid) {
    working.entryuuid = stored.attributes.entryuuid;
  }
  delete working[ENTRY_UUID_ALIAS];
  if (stored.attributes[ENTRY_UUID_ALIAS]) {
    working[ENTRY_UUID_ALIAS] = stored.attributes[ENTRY_UUID_ALIAS];
  }
  working.modifytimestamp = [generalizedTime()];
  stored.attributes = working;
  touchDirectory();
  stored.modifiedAt = working.modifytimestamp[0];
  if (modifiedPassword.password) {
    credentials.passwordWritten(modifiedPassword.name,
                                modifiedPassword.password);
  }
  if (isPersonEntry(stored)) {
    noteAccountChange('updated', stored.dn, beforeModify,
                      attributeSnapshot(stored));
  }
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
  const newSuperior = req.newSuperior ? req.newSuperior.toString() :
                      parentDn(dn);
  const target = newRdn + (newSuperior ? ',' + newSuperior : '');
  log.info('ldap: MODIFYDN ' + dn + ' -> ' + target);
  const renameRefusal = directoryWriteRefusal(req, 'rename', dn);
  if (renameRefusal) {
    log.debug('Leaving the LDAP modifyDN handler. Not authorized.');
    return next(renameRefusal);
  }
  const stored = getEntry(dn);
  if (!stored) {
    log.debug('Leaving the LDAP modifyDN handler. There is no such entry.');
    return next(ldapRefusal(req, 'STS-LDAP-0013', 'a rename named ' + dn +
      ', which does not exist', new ldap.NoSuchObjectError(dn), dn));
  }
  if (isBootstrapAdministratorEntry(stored)) {
    log.debug('Leaving the LDAP modifyDN handler. The bootstrap administrator.');
    return next(ldapRefusal(req, 'STS-LDAP-0077', 'a rename of ' + dn +
      ' was refused: it is the default realm\'s bootstrap administrator, ' +
      'and a rename would delete that account under another name',
      new ldap.UnwillingToPerformError(dn), dn));
  }
  if (hasChildren(dn)) {
    // Moving a subtree means rewriting every DN below it, which this mock does
    // not do — and doing half of it would leave orphans. Refusing is honest.
    log.debug('Leaving the LDAP modifyDN handler. It has children.');
    return next(ldapRefusal(req, 'STS-LDAP-0014', 'a rename of ' + dn +
      ' was refused because it has entries beneath it',
      new ldap.NotAllowedOnNonLeafError(dn), dn));
  }
  if (getEntry(target)) {
    log.debug('Leaving the LDAP modifyDN handler. The target exists.');
    return next(ldapRefusal(req, 'STS-LDAP-0004', 'a rename of ' + dn +
      ' named ' + target + ', which already exists',
      new ldap.EntryAlreadyExistsError(target), dn));
  }
  // ROOT_DN, not baseDn(): THIS IS THE SOCKET, and the socket has no realm of
  // its own. An LDAP client operating on `dc=acme,dc=example,dc=com` arrives
  // with nothing ambient, so asking whether its DN is under the DEFAULT realm's
  // base would refuse every realm's subtree — the one thing putting the realm
  // in the DN exists to make possible. Which realm a DN belongs to is decided
  // by where it sits, and `realmFor()` did that before this handler ran.
  if (!isUnder(target, ROOT_DN)) {
    log.debug('Leaving the LDAP modifyDN handler. Outside the naming context.');
    return next(ldapRefusal(req, 'STS-LDAP-0003', 'a rename of ' + dn +
      ' named a DN outside this directory\'s naming context',
      new ldap.NoSuchObjectError(ROOT_DN), dn));
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
    return next(ldapRefusal(req, 'STS-LDAP-0018', 'a rename of ' + dn +
      ' would have moved it into another trust realm',
      new ldap.AffectsMultipleDsasError(target), dn));
  }
  const before = attributeSnapshot(stored);
  const nameBefore = isPersonEntry(stored) ? personNameOf(stored) : '';
  entries.delete(normalizeDn(dn));
  stored.dn = target;
  // The RDN's own attribute has to hold the new value, or the entry no longer
  // describes itself. deleteOldRdn says whether the OLD value goes; a client
  // that clears it and never sets the new one is the commonest way to end up
  // with an entry whose cn does not match its DN.
  //
  // **AND THAT SENTENCE DESCRIBED NOTHING UNTIL 2026-09-14**: `deleteOldRdn`
  // (RFC 4511 section 4.9) was ignored, so renaming `uid=alice` to
  // `uid=alicia` left `uid: alice` behind and the old name went on resolving to
  // the renamed person — through `existingUserEntry()`, a sign-in and every
  // lookup a token names. A curiosity while a `sub` was a name; a defect now
  // that a rename is an ordinary event the subject survives.
  if (req.deleteOldRdn) {
    const oldParts = String(dn).split(/(?<!\\),/)[0].split('=');
    if (oldParts.length >= 2) {
      const oldType = oldParts[0].trim().toLowerCase();
      const oldValue = oldParts.slice(1).join('=').trim().toLowerCase();
      const held = stored.attributes[oldType] || [];
      const kept = held.filter(function (value) {
        return String(value).toLowerCase() !== oldValue;
      });
      if (kept.length) {
        stored.attributes[oldType] = kept;
      } else {
        delete stored.attributes[oldType];
      }
    }
  }
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
  // A RENAME OF A PERSON IS AN ACCOUNT CHANGE and says so, where it used to
  // tell nobody: the SSF and RISC registers key on the name that just moved.
  if (isPersonEntry(stored)) {
    // AND THE IDENTITY REGISTER'S ROW MOVES WITH THEM (2026-09-14), or
    // /admin/users shows the renamed person as two people: everything before
    // the rename under a name that names nobody now.
    const nameAfter = personNameOf(stored);
    if (nameBefore && nameAfter && nameBefore !== nameAfter) {
      stats.renameIdentity(nameBefore, nameAfter);
    }
    noteAccountChange('updated', stored.dn, before, attributeSnapshot(stored));
  }
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
              movedContainer: normalizeDn(parentDn(dn)) !== normalizeDn(
                  newSuperior),
              note: 'any group listing the OLD DN as a member still does; ' +
                    'this directory does not do referential integrity' }
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
  // The VALUE is not logged, for the reason the audit row below gives: a
  // compare against userPassword is a password check, and the value is the
  // password. It was logged at info until 2026-09-12.
  log.info('ldap: COMPARE ' + dn + ' ' + type + ' (' +
           String(req.value === undefined ? '' : req.value).length +
           ' character value)');
  const compareReadRefusal = directoryReadRefusal(req, 'compare', dn);
  if (compareReadRefusal) {
    log.debug('Leaving the LDAP compare handler. Not bound.');
    return next(compareReadRefusal);
  }
  const compareSecretRefusal = secretCompareRefusal(req, dn, type);
  if (compareSecretRefusal) {
    log.debug('Leaving the LDAP compare handler. A credential attribute.');
    return next(compareSecretRefusal);
  }
  const stored = getEntry(dn);
  if (!stored) {
    log.debug('Leaving the LDAP compare handler. There is no such entry.');
    return next(ldapRefusal(req, 'STS-LDAP-0013', 'a compare named ' + dn +
      ', which does not exist', new ldap.NoSuchObjectError(dn), dn));
  }
  if (!stored.attributes[type]) {
    log.debug('Leaving the LDAP compare handler. The attribute is not there.');
    return next(ldapRefusal(req, 'STS-LDAP-0019', 'a compare on ' + dn +
      ' named the attribute ' + type + ', which the entry does not hold',
      new ldap.NoSuchAttributeError(type), dn));
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
          description: [(mode.verifiesCredentials()
                          ? 'Binds are verified, and a read requires one. '
                          : 'Every bind succeeds except the password ' +
                            '"invalid". ') +
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
    return next(ldapRefusal(req, 'STS-LDAP-0020', 'a ' + scope + ' search of ' +
      'the root DSE was refused; only a base search reads it',
      new ldap.NoSuchObjectError(''), '(root DSE)'));
  }
  // ROOT_DN, and this is the line that makes `ldapsearch -b
  // "dc=acme,dc=example,dc=com"` work: a realm's subtree is INSIDE the naming
  // context, so a search based there is in-context and is answered from the one
  // tree. Comparing against the ambient realm's base instead would have made
  // every realm unreachable from 389 and 636, which is the whole reason the
  // realm is in the DN rather than in a partitioned store.
  // A BIND BEFORE A READ, in product mode, and asked before anything about
  // whether the base exists. The root DSE has already been answered above.
  const readRefusal = directoryReadRefusal(req, 'search', base);
  if (readRefusal) {
    log.debug('Leaving the LDAP search handler. Not bound.');
    return next(readRefusal);
  }
  if (!isUnder(base, ROOT_DN)) {
    log.debug('Leaving the LDAP search handler. Outside the naming context.');
    return next(ldapRefusal(req, 'STS-LDAP-0003', 'a search based at ' + base +
      ' named a DN outside this directory\'s naming context',
      new ldap.NoSuchObjectError(base), base));
  }
  if (!getEntry(base)) {
    log.debug('Leaving the LDAP search handler. The base does not exist.');
    return next(ldapRefusal(req, 'STS-LDAP-0013', 'a search named the base ' +
      base + ', which does not exist', new ldap.NoSuchObjectError(base), base));
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
      // nothing here while `(cn=developers)` matched: a presence filter
      // compares the attribute name it was given, `objectClass`, against a key
      // spelled `objectclass`. The symptom is the worst kind — a search that
      // succeeds and returns zero entries, which reads as an empty directory
      // rather than as a filter that could not see it. `matchableForReader()`:
      // a credential is invisible to a filter, or the filter is an oracle for
      // it. See *THE DIRECTORY'S READ AND BIND SECURITY*.
      matches = req.filter.matches(matchableForReader(stored), false);
    } catch (e) {
      // A filter this store cannot evaluate is not a match, and it is worth a
      // line: an extensible-match filter or an unknown matching rule lands
      // here, and silently returning nothing would look like an empty
      // directory rather than an unsupported filter.
      log.warn(errorCodes.tag('STS-LDAP-0034') +
               'ldap: the filter could not be evaluated against ' + stored.dn +
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
        outcome: 'refused', errorCode: 'STS-LDAP-0021',
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
      // ---------------------------------------------------------------
      // AND THE RESULT MESSAGE IS SENT, WHICH IT WAS NOT UNTIL 2026-09-06.
      //
      // **THIS LINE WAS `return next()` AND THAT HUNG EVERY CLIENT, FOR EVER.**
      // A bare `next()` here ends the handler chain without `res.end()` and
      // without an error, so this server sent N SearchResultEntry messages and
      // then NO SearchResultDone at all. RFC 4511 section 4.5.2 makes that
      // message mandatory — it is how a search finishes — so the client sat on
      // an open connection waiting for a reply that was never coming. Not slow:
      // STOPPED, with this process idle beside it.
      //
      // **THE COMMENT DIRECTLY ABOVE IS WHAT MAKES IT WORTH THIS MANY LINES.**
      // It says the client has an incomplete answer and does not know it
      // "unless it reads result code 4" — and nothing sent result code 4. The
      // audit row said `resultCode: 4` too. So the log, the audit trail and the
      // prose all described a behaviour the code did not have, and the one
      // place it was visible was on the wire.
      //
      // **NOTHING COULD HAVE SEEN IT.** `ldap.sizeLimit` is 500 and the seeded
      // directory holds about twenty-six entries, so no search in either suite
      // had ever reached this branch; and until
      // `sts_directory_bulk_load_ldap.js` (2026-09-06) nothing in this
      // repository drove the raw socket at all — every other reader of this
      // directory comes in over HTTP, through this module's FUNCTIONS rather
      // than its PROTOCOL. Five thousand entries and one subtree search found
      // it in the first minute.
      //
      // `SizeLimitExceededError` IS result code 4, and ldapjs turns an error
      // passed to `next()` into the SearchResultDone carrying it. The entries
      // already sent stay sent, which is what section 4.5.2 requires: they are
      // a valid partial answer and the code is how the client knows it is
      // partial.
      return next(coded('STS-LDAP-0021', new ldap.SizeLimitExceededError(
        'this search returned its limit of ' + limit + ' entry/entries and ' +
        'the answer is INCOMPLETE; ask for less with a filter, or raise ' +
        'ldap.sizeLimit')));
    }
    res.send(toSearchEntry(stored, req.attributes, res.messageId));
    sent++;
    if (isUnder(stored.dn, usersDn()) &&
        normalizeDn(stored.dn) !== normalizeDn(usersDn())) {
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
    return normalizeDn(context) !== normalizeDn(realmBaseDn(
        realms.currentId()));
  });
  log.info('ldap: the search considered ' + considered + ' entry/entries in ' +
           'scope and returned ' + sent + '.' +
           (otherContexts.length
             ? ' This is the "' + realms.currentId() +
               '" realm\'s directory; ' +
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
  log.debug('Leaving the LDAP search handler. ' + sent +
            ' entry/entries sent.');
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
// AND NOW THAT EVERY HANDLER IS REGISTERED, OFFER THEM TO THE WORKER POOL.
//
// **THE POSITION IS THE WHOLE OF IT.** `LOCAL_HANDLERS` is filled by the
// registrations above, so a call placed before them would register seven
// operations that resolve to nothing — and `performOperation()` would throw
// for every one, in the worker, where the failure reaches a client as
// LDAP_OPERATIONS_ERROR and reaches a reader as nothing at all. It is here for
// the reason `sts_metadata.js` is required last: it reads what everything
// above it registered.
// ---------------------------------------------------------------------------
registerWorkerOperations();

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
        fingerprint256: serverCertificate ? serverCertificate.fingerprint256 :
                        '',
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
      'neither does an OAuth client. A verified TLS CLIENT CERTIFICATE is ' +
      'the one identity that is already a DN: its entry keeps the subject\'s ' +
      'own leaf RDN — ' +
      'cn=alice,' + usersDn() + ' for CN=alice,O=Example — or the ' +
      'whole subject where that already lies under ' + baseDn() + ', and the ' +
      'full subject, issuer, serial and validity are on the entry as x509* ' +
      'attributes, which are this service\'s own names and not schema. A ' +
      'DECENTRALIZED IDENTIFIER is the third shape and is neither a name nor ' +
      'a DN: an issued credential\'s did:jwk subject, whatever DID presents ' +
      'to the OID4VP Verifier, the one /did/generate mints. Its entry goes ' +
      'at uid=did-<12 hex of the SHA-256 of the DID>,' + usersDn() + ' — a ' +
      'did:jwk written out in full is a DN of several hundred characters, ' +
      'most of it key material — with the identifier itself kept whole on ' +
      'the entry as didSubject, and its method as didMethod. Search for the ' +
      'person by didSubject, not by uid: on those entries the uid is a ' +
      'digest and the didSubject is the identity.',
    authenticationFacts: 'where the protocol that accepted the credential ' +
      'says HOW it was presented — which today is the sign-in screen and ' +
      'nothing else, since amr is an OIDC vocabulary — the entry also ' +
      'carries authnMethod (every RFC 8176 method this person has used here, ' +
      'accumulated), mfaAuthenticated (TRUE or FALSE for the MOST RECENT ' +
      'authentication, overwritten each time) and mfaLastAuthTime (when ' +
      'multi-factor last happened, never cleared). These are this service\'s ' +
      'own names and not schema. A WebAuthn ceremony after a password writes ' +
      'TRUE; the same ceremony used passwordless writes authnMethod hwk with ' +
      'no pwd beside it and mfaAuthenticated FALSE, because one factor is ' +
      'one factor however phishing-resistant it is. Nothing here READS them: ' +
      'no token carries them and no endpoint decides anything on them, ' +
      'exactly as a group here grants nothing — bar the two groups that ' +
      'decide who may use the admin console, which is the one exception ' +
      'anywhere in this directory and is confined to that console.',
    enforcedRules: [
      'an add whose parent does not exist is LDAP_NO_SUCH_OBJECT (32)',
      'a delete of an entry with children is LDAP_NOT_ALLOWED_ON_NONLEAF (66)',
      'a modify delete of an attribute that is not present is ' +
        'LDAP_NO_SUCH_ATTRIBUTE (16)',
      'deleting the last value of an attribute deletes the attribute',
      'an add under ou=users whose username is already here is ' +
        'LDAP_ENTRY_ALREADY_EXISTS (68), naming the entry that holds it. ONE ' +
        'ENTRY PER PERSON: the username is the entry\'s naming RDN value and ' +
        'any uid it carries, so uid=rcbj and cn=rcbj are the same person and ' +
        'only one of them can be here. It is the same refusal the console ' +
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
//     `adminViews.pagedRows()`, `admin.pageNavPair()`, `admin.perPageOptions()`
//     and `admin.clipped()` are the same functions `/admin/tokens` and
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
  log.debug("Entering directoryPaging().");
  log.debug("Leaving directoryPaging().");
  return adminViews.pagedRows(req.query, rows,
                         { noun: noun, name: name || null });
}

// The `per` a control has to carry onward. Empty unless the reader chose one,
// so the URL of an unfiltered first page is still the bare path — the rule
// `queryWith()` follows for every other value.
function perOf(req, paging) {
  log.debug("Entering perOf().");
  log.debug("Leaving perOf().");
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
      'StartTLS: it is an extended operation and this library implements ' +
      'none.'],
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
          ? 'THE LAST WRITE FAILED (' + info.persistence.lastError + ') — ' +
            'the directory is unaffected and is still answering from memory, ' +
            'and the next change will try again'
          : 'last write ' + (info.persistence.lastWriteAt || 'not yet')) +
        '. Sessions, tokens, codes, artifacts and tickets are NEVER ' +
        'persisted in any mode.'],
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
    'directory over TLS &mdash; the same entries, the same handlers, the ' +
    'same every-bind-succeeds. What TLS adds is that the password is not on ' +
    'the wire in the clear; it does not make it <em>checked</em>. The ' +
    'certificate is <strong>the one the HTTPS listeners serve</strong>: ' +
    '<code>' + xmlEscape(info.tls.certificate.subject) + '</code>, SHA-256 ' +
    '<code>' + xmlEscape(info.tls.certificate.fingerprint256) + '</code>, ' +
    xmlEscape(tlsServer.certificateProvenance()) + '. Fetch it from <a ' +
    'href="/tls/server-certificate">/tls/server-certificate</a> and put it ' +
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
    'registry</a> &middot; <a href="/admin/ldap/directory">every entry in ' +
    'the directory</a> &middot; <a href="/admin/ldap">the settings behind ' +
    'these sockets</a> &middot; <a href="/admin/sts-metadata">everything ' +
    'this service speaks</a></p>';
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
      // A KERBEROS KEY IS WITHHELD, ciphertext included (2026-09-12) — see
      // `kerberos/krb5_person_keys.js`. This page's job is to show an entry
      // faithfully and the sentence says exactly what was kept back.
      attributes[canonicalName(name)] =
        certEnrollment.withheldValues(name,
          krb5PersonKeys.withheldValues(name,
                                        stored.attributes[name].slice(0)));
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
  const originOptions = ['<option value=""' +
                         (wantedOrigin ? '' : ' selected') +
                         '>any origin</option>']
    .concat(origins.map(function (origin) {
      const n =
          listed.filter(function (e) { return e.origin === origin; }).length;
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

  log.debug('Leaving ldapDirectoryView(). ' + paged.shown.length +
            ' row(s) of ' +
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
// is a read of these entries, which is what makes an `ldapmodify` take effect
// on the next request rather than after a restart. That is the whole point of
// the directory being the source of truth, and a cache added for speed would
// quietly undo it — on a mock, where the whole store is a Map in this process,
// there is nothing to be gained by one anyway.
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
  log.debug("Entering applicationDn().");
  log.debug("Leaving applicationDn().");
  return 'cn=' + escapeDnValue(applications.labelFor(identifier)) + ',' +
         applicationsDn();
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
  // entriesUnder(), for allPolicies()'s reason: this fallback runs on every
  // lookup that misses at the DN, which is every lookup of an application by an
  // identifier that is not its RDN.
  entriesUnder(applicationsDn()).forEach(function (stored) {
    if (found) {
      return;
    }
    if ((stored.attributes.appidentifier || [])[0] === wanted) {
      found = stored;
    }
  });
  log.debug('Leaving applicationEntry(). ' +
            (found ? 'Found by appIdentifier.' : 'Not ' +
      'here.'));
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
//   * THE DN. It is not an attribute — it is the key the entry is stored under
//     — so a caller handed `stored.attributes` had no way to learn where the
//     entry lives, and every applications page could show the `cn` and nothing
//     else. It is published as `entryDN` (RFC 5020) because matchable() already
//     uses that name for the same fact, so an ldapsearch filter and this dump
//     agree about what the DN is called.
//   * THE OPERATIONAL ATTRIBUTES, createTimestamp and modifyTimestamp. A SEARCH
//     withholds those unless they are asked for by name (RFC 4511 section
//     4.5.1.8) and toSearchEntry() honours it — but this is not a search, it is
//     this service showing its own store, and `operational` names which ones a
//     search would have withheld so a page can say so rather than pretend the
//     distinction does not exist.
//   * THE CANONICAL SPELLING. The store lower-cases every attribute name
//     because that is how @ldapjs/attribute delivers it; a page showing
//     `oauthclientid` where the published schema says `oauthClientId` reads as
//     a bug in the page. canonicalName() now knows the applications schema's
//     names too — see the merge beside CANONICAL_NAMES.
//
// IT IS NOT ONLY AN APPLICATION'S SHAPE ANY MORE. `scim.js` reads people and
// groups through the same function, because "the entry, whole, canonically
// spelled, with the DN synthesised on it" is one question and the container it
// is asked about does not change the answer. That is why it is called
// entryObject() rather than applicationObject(): a second copy differing only
// in the container it was written for is the two-lists mistake this file
// already warns about three times.
// ---------------------------------------------------------------------------
function entryObject(stored) {
  log.debug('Entering entryObject().');
  const attributes = {};
  Object.keys(stored.attributes).sort().forEach(function (attribute) {
    attributes[canonicalName(attribute)] = stored.attributes[attribute].slice(
        0);
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
  log.debug("Entering readApplication().");
  const stored = applicationEntry(identifier);
  log.debug("Leaving readApplication().");
  return stored ? entryObject(stored) : null;
}

function applicationCount() {
  log.debug("Entering applicationCount().");
  // The same listing allApplications() reads, for its reason.
  const n = entriesUnder(applicationsDn()).length;
  log.debug("Leaving applicationCount().");
  return n;
}

function allApplications() {
  log.debug('Entering allApplications().');
  // entriesUnder() RATHER THAN A WALK OF THE REALM (2026-09-12), for
  // allPolicies()'s reason. `ssf/ssf_streams.js` asks the registry for every
  // application on each event, per stream, to find a stream owner named by an
  // `ssfReceiverId` — and a walk normalises every DN in the realm, people
  // included. A SCIM bulk load in the dispatch mode emits an event per person,
  // so each create paid for a scan of all the people already there: one worker
  // spent half its CPU in normalizeDn(), the read barrier timed out thousands
  // of times behind it, and the job was killed at thirty minutes. The listing
  // is kept until something is written under ou=applications.
  const rows = entriesUnder(applicationsDn()).map(function (stored) {
    return entryObject(stored);
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
// The operational attributes are the exception and are preserved:
// createTimestamp belongs to the entry rather than to the record, and an entry
// that reported being created afresh on every sign-in would make the audit log
// unreadable.
function writeApplication(identifier, attributes) {
  log.debug('Entering writeApplication(). identifier=' + identifier);
  const existing = applicationEntry(identifier);
  const dn = existing ? existing.dn : applicationDn(identifier);
  if (!existing && applicationCount() >= maxApplications()) {
    // Warned rather than thrown, exactly as a full directory is when somebody
    // authenticates: whatever this application was doing succeeded, and a
    // registry that could fail a token request would be the tail wagging the
    // dog.
    log.warn(errorCodes.tag('STS-LDAP-0035') +
             'ldap: not creating ' + dn + '; ou=applications holds its ' +
                                          'maximum of ' +
             maxApplications() + ' entry/entries (applications.max). The ' +
             'application itself is unaffected — it simply goes unrecorded.');
    log.debug('Leaving writeApplication(). The container is full.');
    return false;
  }
  if (totalEntries() >= maxEntries() && !existing) {
    log.warn(errorCodes.tag('STS-LDAP-0007') +
             'ldap: not creating ' + dn + '; the directory holds its maximum ' +
                                          'of ' +
             maxEntries() + ' entries.');
    log.debug('Leaving writeApplication(). The directory is full.');
    return false;
  }
  const created = existing ? existing.createdAt : generalizedTime();
  const stored = putEntry(dn, attributes,
                          { origin: existing ? existing.origin :
                                    'application' });
  stored.createdAt = created;
  stored.attributes.createtimestamp = [created];
  stored.attributes.modifytimestamp = [generalizedTime()];
  auditDirectory(existing ? 'entry.update' : 'entry.create', dn, attributes,
                 !existing);
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
  log.debug('Leaving deleteApplicationEntry(). ' + entries.size + ' ' +
      'entry/entries left.');
  return true;
}

// The directory's own audit row for an application entry, which is a DIFFERENT
// fact from applications.js's `application.create`: that one says an
// application was seen, this one says an entry in the tree changed. Both are
// recorded because /admin/audit's directory filter would otherwise show every
// entry this service writes except these, and a blind spot in a directory log
// is worse than a row somebody has to read past.
//
// NO VALUES ARE NAMED, only attribute names — the same rule every other LDAP
// row here follows, and it matters more on these entries than on any other:
// oauthClientSecret and appRegistrationAccessToken are among the attributes.
function auditDirectory(action, dn, attributes, created) {
  log.debug("Entering auditDirectory().");
  audit.audit({
    action: action,
    actor: '',
    protocol: 'LDAP',
    channel: 'internal',
    target: dn,
    summary: 'The application entry ' + dn + ' was ' +
             (action === 'entry.delete' ? 'deleted' :
              (created ? 'created' : 'updated')),
    detail: { attributes: Object.keys(attributes || {}).sort().join(', ') }
  });
  log.debug("Leaving auditDirectory().");
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
  // entries live and how many will fit. They are here rather than in that
  // module because that module deliberately does not know where the container
  // is.
  containerDn: function () {
    log.debug("Entering containerDn().");
    log.debug("Leaving containerDn().");
    return applicationsDn();
  },
  // WHEN ANYTHING UNDER ou=applications LAST CHANGED, in the ambient realm —
  // what `applications.ssfAllowedEventsFor()` keys its answers on (2026-09-14).
  // A write through writeApplication() moves it, and a write that names no
  // location (an LDAP modify) moves every container, so it cannot lag a change.
  applicationsVersion: function () {
    log.debug("Entering applicationsVersion().");
    log.debug("Leaving applicationsVersion().");
    return subtreeVersion(applicationsDn());
  },
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
  log.debug("Entering federationDn().");
  log.debug("Leaving federationDn().");
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
  log.debug('Leaving federationEntry(). ' +
            (found ? 'Found by fedId.' : 'Not ' +
      'here.'));
  return found;
}

function readFederation(id) {
  log.debug("Entering readFederation().");
  const stored = federationEntry(id);
  log.debug("Leaving readFederation().");
  return stored ? entryObject(stored) : null;
}

function federationCount() {
  log.debug("Entering federationCount().");
  let n = 0;
  eachEntryInRealm(function (stored) {
    if (isUnder(stored.dn, federationsDn()) &&
        normalizeDn(stored.dn) !== normalizeDn(federationsDn())) {
      n++;
    }
  });
  log.debug("Leaving federationCount().");
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
    log.warn(errorCodes.tag('STS-LDAP-0036') +
             'ldap: not creating ' + dn + '; ou=federations holds its ' +
                                          'maximum of ' +
             maxFederations() + ' entry/entries (federation.max).');
    log.debug('Leaving writeFederation(). The container is full.');
    return false;
  }
  if (totalEntries() >= maxEntries() && !existing) {
    log.warn(errorCodes.tag('STS-LDAP-0007') +
             'ldap: not creating ' + dn + '; the directory holds its maximum ' +
                                          'of ' +
             maxEntries() + ' entries.');
    log.debug('Leaving writeFederation(). The directory is full.');
    return false;
  }
  const created = existing ? existing.createdAt : generalizedTime();
  const stored = putEntry(dn, attributes,
                          { origin: existing ? existing.origin :
                                    'federation' });
  stored.createdAt = created;
  stored.attributes.createtimestamp = [created];
  stored.attributes.modifytimestamp = [generalizedTime()];
  auditFederationDirectory(existing ? 'entry.update' : 'entry.create', dn,
                           attributes, !existing);
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
  log.debug('Leaving deleteFederationEntry(). ' + entries.size + ' ' +
      'entry/entries left.');
  return true;
}

// ---------------------------------------------------------------------------
// ou=policies AS A STORE.
//
// The same three functions the federation register has, and a fourth thing
// worth saying about them: a policy entry is named by a LABEL somebody chose
// (`cn=default`), not by the PolicyId inside the document. The two are
// different identifiers on purpose — a PolicyId is a URI, is often long, and
// changes when a policy is re-issued, so naming the entry after it would make
// a version bump into a delete and a create. `xacmlPolicyId` carries the
// document's own identifier and is what a PolicyIdReference resolves against.
// ---------------------------------------------------------------------------
function policyDn(name) {
  log.debug("Entering policyDn().");
  log.debug("Leaving policyDn().");
  return 'cn=' + escapeDnValue(String(name)) + ',' + policiesDn();
}

function policyEntry(name) {
  log.debug('Entering policyEntry(). name=' + name);
  const direct = getEntry(policyDn(name));
  log.debug('Leaving policyEntry(). ' + (direct ? 'Found.' : 'Not here.'));
  return direct || null;
}

function policyCount() {
  log.debug("Entering policyCount().");
  let n = 0;
  eachEntryInRealm(function (stored) {
    if (isUnder(stored.dn, policiesDn()) &&
        normalizeDn(stored.dn) !== normalizeDn(policiesDn())) {
      n++;
    }
  });
  log.debug("Leaving policyCount().");
  return n;
}

function allPolicies() {
  log.debug('Entering allPolicies().');
  // entriesUnder() RATHER THAN A WALK OF THE REALM, because the XACML access
  // gate asks for this on EVERY gated request — see subtreeClocks(). It already
  // excludes the container entry itself, which is what the second half of the
  // test this replaced was for.
  const rows = entriesUnder(policiesDn()).map(function (stored) {
    const object = entryObject(stored);
    // The NAME is the cn, which is the handle every console control and
    // every /admin-api operation uses. Derived here rather than in
    // xacml_store.js so that a renamed entry (an ldapmodrdn) reports its
    // new name rather than a stale one held elsewhere.
    object.name = (stored.attributes.cn || [])[0] ||
                  stored.dn.split(',')[0].replace(/^cn=/i, '');
    return object;
  });
  log.debug('Leaving allPolicies(). ' + rows.length + ' policy(ies).');
  return rows;
}

// Create or REPLACE, for writeFederation()'s reason: the record being written
// was read from this entry a moment ago and changed, so merging would make it
// impossible to remove a value — and here the value somebody most wants to
// remove is `xacmlIsRoot` from a policy that should no longer be the root.
function writePolicy(name, attributes) {
  log.debug('Entering writePolicy(). name=' + name);
  const existing = policyEntry(name);
  const dn = existing ? existing.dn : policyDn(name);
  if (!existing && policyCount() >= maxPolicies()) {
    log.warn(errorCodes.tag('STS-LDAP-0037') +
             'ldap: not creating ' + dn + '; ou=policies holds its maximum ' +
             'of ' + maxPolicies() + ' entry/entries (xacml.maxPolicies).');
    log.debug('Leaving writePolicy(). The container is full.');
    return false;
  }
  if (totalEntries() >= maxEntries() && !existing) {
    log.warn(errorCodes.tag('STS-LDAP-0007') +
             'ldap: not creating ' + dn + '; the directory holds its ' +
             'maximum of ' + maxEntries() + ' entries.');
    log.debug('Leaving writePolicy(). The directory is full.');
    return false;
  }
  const created = existing ? existing.createdAt : generalizedTime();
  const stored = putEntry(dn, Object.assign({ cn: String(name) }, attributes),
                          { origin: existing ? existing.origin : 'xacml' });
  stored.createdAt = created;
  stored.attributes.createtimestamp = [created];
  stored.attributes.modifytimestamp = [generalizedTime()];
  auditPolicyDirectory(existing ? 'entry.update' : 'entry.create', dn,
                       stored.attributes, !existing);
  log.debug('Leaving writePolicy(). The entry was ' +
            (existing ? 'updated.' : 'created.'));
  return true;
}

function deletePolicy(name) {
  log.debug('Entering deletePolicy(). name=' + name);
  const stored = policyEntry(name);
  if (!stored) {
    log.debug('Leaving deletePolicy(). It was not here.');
    return false;
  }
  entries.delete(normalizeDn(stored.dn));
  touchDirectory();
  auditPolicyDirectory('entry.delete', stored.dn, stored.attributes, false);
  log.debug('Leaving deletePolicy(). ' + entries.size + ' entry/entries left.');
  return true;
}

// ---------------------------------------------------------------------------
// ou=roles AS A STORE.
//
// The same three functions again. One thing about them is worth saying: a role
// entry is named by the ROLE NAME itself and there is no second identifier —
// unlike a policy, whose entry name and PolicyId are deliberately different
// things. A role IS its name: it is what a token claim carries, what an
// application's requirement list names, and what a XACML policy matches on, so
// a role with a handle and a separate display name would be three places for
// one string to disagree with itself.
// ---------------------------------------------------------------------------
function roleDn(name) {
  log.debug("Entering roleDn().");
  log.debug("Leaving roleDn().");
  return 'cn=' + escapeDnValue(String(name)) + ',' + rolesDn();
}

function roleEntry(name) {
  log.debug('Entering roleEntry(). name=' + name);
  const direct = getEntry(roleDn(name));
  log.debug('Leaving roleEntry(). ' + (direct ? 'Found.' : 'Not here.'));
  return direct || null;
}

function roleCount() {
  log.debug("Entering roleCount().");
  let n = 0;
  eachEntryInRealm(function (stored) {
    if (isUnder(stored.dn, rolesDn()) &&
        normalizeDn(stored.dn) !== normalizeDn(rolesDn())) {
      n++;
    }
  });
  log.debug("Leaving roleCount().");
  return n;
}

function allRoles() {
  log.debug('Entering allRoles().');
  // entriesUnder(), for allPolicies()'s reason: the access gate asks for the
  // roles on every gated request too.
  const rows = entriesUnder(rolesDn()).map(function (stored) {
    const object = entryObject(stored);
    object.name = (stored.attributes.cn || [])[0] ||
                  stored.dn.split(',')[0].replace(/^cn=/i, '');
    return object;
  });
  log.debug('Leaving allRoles(). ' + rows.length + ' role(s).');
  return rows;
}

// Create or REPLACE, for writePolicy()'s reason: the record being written was
// read from this entry a moment ago and changed, so merging would make it
// impossible to REMOVE a member — and removing a member from a role is the
// half of this register that has a security consequence.
function writeRole(name, attributes) {
  log.debug('Entering writeRole(). name=' + name);
  const existing = roleEntry(name);
  const dn = existing ? existing.dn : roleDn(name);
  if (!existing && roleCount() >= maxRoles()) {
    log.warn(errorCodes.tag('STS-LDAP-0038') +
             'ldap: not creating ' + dn + '; ou=roles holds its maximum of ' +
             maxRoles() + ' entry/entries (roles.maxRoles).');
    log.debug('Leaving writeRole(). The container is full.');
    return false;
  }
  if (totalEntries() >= maxEntries() && !existing) {
    log.warn(errorCodes.tag('STS-LDAP-0007') +
             'ldap: not creating ' + dn + '; the directory holds its ' +
             'maximum of ' + maxEntries() + ' entries.');
    log.debug('Leaving writeRole(). The directory is full.');
    return false;
  }
  const created = existing ? existing.createdAt : generalizedTime();
  const stored = putEntry(dn, Object.assign({ cn: String(name) }, attributes),
                          { origin: existing ? existing.origin : 'roles' });
  stored.createdAt = created;
  stored.attributes.createtimestamp = [created];
  stored.attributes.modifytimestamp = [generalizedTime()];
  auditPolicyDirectory(existing ? 'entry.update' : 'entry.create', dn,
                       stored.attributes, !existing);
  log.debug('Leaving writeRole(). The entry was ' +
            (existing ? 'updated.' : 'created.'));
  return true;
}

function deleteRole(name) {
  log.debug('Entering deleteRole(). name=' + name);
  const stored = roleEntry(name);
  if (!stored) {
    log.debug('Leaving deleteRole(). It was not here.');
    return false;
  }
  entries.delete(normalizeDn(stored.dn));
  touchDirectory();
  auditPolicyDirectory('entry.delete', stored.dn, stored.attributes, false);
  log.debug('Leaving deleteRole(). ' + entries.size + ' entry/entries left.');
  return true;
}

// ---------------------------------------------------------------------------
// ou=passwordPolicies AS A STORE (2026-09-12).
//
// The same three functions a fourth time, named by the PROFILE (`cn=default`).
// Two things differ from ou=roles and both are small: there is no cap of its
// own, because `common/password_policy.js` refuses every profile name but one
// before a write reaches here; and the CONTAINER is put back if it is missing,
// because a directory restored from a store written before this container
// existed has none, and a profile whose parent is absent is an entry an
// `ldapsearch` of the realm cannot reach.
// ---------------------------------------------------------------------------
function passwordPolicyDn(name) {
  log.debug("Entering passwordPolicyDn().");
  log.debug("Leaving passwordPolicyDn().");
  return 'cn=' + escapeDnValue(String(name)) + ',' + passwordPoliciesDn();
}

function allPasswordPolicies() {
  log.debug('Entering allPasswordPolicies().');
  const rows = entriesUnder(passwordPoliciesDn()).map(function (stored) {
    const object = entryObject(stored);
    object.name = (stored.attributes.cn || [])[0] ||
                  stored.dn.split(',')[0].replace(/^cn=/i, '');
    return object;
  });
  log.debug('Leaving allPasswordPolicies(). ' + rows.length + ' profile(s).');
  return rows;
}

// REPLACED rather than merged, for writeRole()'s reason with a sharper edge:
// the record is every field of the profile, and a merge could not take a
// description away — nor, which matters more, notice that a value it was not
// given should not still be there.
function writePasswordPolicy(name, attributes) {
  log.debug('Entering writePasswordPolicy(). name=' + name);
  const dn = passwordPolicyDn(name);
  const existing = getEntry(dn);
  if (!existing && totalEntries() >= maxEntries()) {
    log.warn(errorCodes.tag('STS-LDAP-0007') +
             'ldap: not creating ' + dn + '; the directory holds its ' +
             'maximum of ' + maxEntries() + ' entries.');
    log.debug('Leaving writePasswordPolicy(). The directory is full.');
    return false;
  }
  if (!getEntry(passwordPoliciesDn())) {
    putEntry(passwordPoliciesDn(), {
      objectClass: ['top', 'organizationalUnit'],
      ou: 'passwordPolicies'
    }, { origin: 'password policy' });
  }
  const created = existing ? existing.createdAt : generalizedTime();
  const stored = putEntry(dn, Object.assign({ cn: String(name) }, attributes),
                          { origin: existing ? existing.origin : 'password ' +
                              'policy' });
  stored.createdAt = created;
  stored.attributes.createtimestamp = [created];
  stored.attributes.modifytimestamp = [generalizedTime()];
  auditPolicyDirectory(existing ? 'entry.update' : 'entry.create', dn,
                       stored.attributes, !existing);
  log.debug('Leaving writePasswordPolicy(). The entry was ' +
            (existing ? 'updated.' : 'created.'));
  return true;
}

function deletePasswordPolicy(name) {
  log.debug('Entering deletePasswordPolicy(). name=' + name);
  const stored = getEntry(passwordPolicyDn(name));
  if (!stored) {
    log.debug('Leaving deletePasswordPolicy(). It was not here.');
    return false;
  }
  entries.delete(normalizeDn(stored.dn));
  touchDirectory();
  auditPolicyDirectory('entry.delete', stored.dn, stored.attributes, false);
  log.debug('Leaving deletePasswordPolicy(). ' + entries.size +
            ' entry/entries left.');
  return true;
}

// ---------------------------------------------------------------------------
// ou=peps AS A STORE.
//
// The same three functions again, and one difference from ou=policies worth
// knowing: a PEP entry is named from its CLIENT CERTIFICATE rather than from a
// label somebody chose, so the name is not free text and a re-registration
// lands on the entry that is already there. `xacml_pep_registry.js` does that
// folding — it is the module that knows what a certificate common name may
// contain — and this file is handed a name that is already an entry name.
// ---------------------------------------------------------------------------
function pepDn(name) {
  log.debug("Entering pepDn().");
  log.debug("Leaving pepDn().");
  return 'cn=' + escapeDnValue(String(name)) + ',' + pepsDn();
}

function pepEntry(name) {
  log.debug('Entering pepEntry(). name=' + name);
  const direct = getEntry(pepDn(name));
  log.debug('Leaving pepEntry(). ' + (direct ? 'Found.' : 'Not here.'));
  return direct || null;
}

function pepCount() {
  log.debug("Entering pepCount().");
  let n = 0;
  eachEntryInRealm(function (stored) {
    if (isUnder(stored.dn, pepsDn()) &&
        normalizeDn(stored.dn) !== normalizeDn(pepsDn())) {
      n++;
    }
  });
  log.debug("Leaving pepCount().");
  return n;
}

function allPeps() {
  log.debug('Entering allPeps().');
  const rows = [];
  eachEntryInRealm(function (stored) {
    if (isUnder(stored.dn, pepsDn()) &&
        normalizeDn(stored.dn) !== normalizeDn(pepsDn())) {
      const object = entryObject(stored);
      object.name = (stored.attributes.cn || [])[0] ||
                    stored.dn.split(',')[0].replace(/^cn=/i, '');
      rows.push(object);
    }
  });
  log.debug('Leaving allPeps(). ' + rows.length + ' registered PEP(s).');
  return rows;
}

// Create or REPLACE, for writePolicy()'s reason and one of its own: the record
// being written was read from this entry a moment ago and changed, and the
// value somebody most wants to be able to clear here is a notify URL — a PEP
// that re-registers without one has stopped wanting to be nudged, and a merge
// would keep dialling the address it used to have.
function writePep(name, attributes) {
  log.debug('Entering writePep(). name=' + name);
  const existing = pepEntry(name);
  const dn = existing ? existing.dn : pepDn(name);
  if (!existing && pepCount() >= maxPeps()) {
    log.warn(errorCodes.tag('STS-LDAP-0039') +
             'ldap: not creating ' + dn + '; ou=peps holds its maximum of ' +
             maxPeps() + ' entry/entries (xacml.maxPeps).');
    log.debug('Leaving writePep(). The container is full.');
    return false;
  }
  if (totalEntries() >= maxEntries() && !existing) {
    log.warn(errorCodes.tag('STS-LDAP-0007') +
             'ldap: not creating ' + dn + '; the directory holds its ' +
             'maximum of ' + maxEntries() + ' entries.');
    log.debug('Leaving writePep(). The directory is full.');
    return false;
  }
  const created = existing ? existing.createdAt : generalizedTime();
  const stored = putEntry(dn, Object.assign({ cn: String(name) }, attributes),
                          { origin: existing ? existing.origin : 'xacml' });
  stored.createdAt = created;
  stored.attributes.createtimestamp = [created];
  stored.attributes.modifytimestamp = [generalizedTime()];
  auditPolicyDirectory(existing ? 'entry.update' : 'entry.create', dn,
                       stored.attributes, !existing);
  log.debug('Leaving writePep(). The entry was ' +
            (existing ? 'updated.' : 'created.'));
  return true;
}

// ---------------------------------------------------------------------------
// THE TRUSTSTORE'S DURABLE HALF: read, write and delete one anchor.
//
// All three are handed to `tls/tls_server.js` pinned to the DEFAULT realm (see
// the slot fill), so they read `baseDn()` there whatever realm a request is in.
// The fingerprint is the RDN, normalised to upper-case hex with no colons, so a
// second add of one certificate overwrites rather than duplicates and a remove
// can name the entry without reading the container.
// ---------------------------------------------------------------------------
function allTrustAnchors() {
  log.debug('Entering allTrustAnchors().');
  const rows = [];
  const base = normalizeDn(trustAnchorsDn());
  eachEntryInRealm(function (stored) {
    if (!isUnder(stored.dn, trustAnchorsDn()) ||
        normalizeDn(stored.dn) === base) {
      return;
    }
    const pem = (stored.attributes.ststrustanchorcertificate || [])[0] || '';
    if (!pem) {
      return;
    }
    rows.push({
      fingerprint: (stored.attributes.ststrustanchorfingerprint || [])[0] || '',
      pem: pem,
      addedAt: stored.createdAt || '',
      addedBy: (stored.attributes.ststrustanchoraddedby || [])[0] || ''
    });
  });
  log.debug('Leaving allTrustAnchors(). ' + rows.length + ' stored anchor(s).');
  return rows;
}

function writeTrustAnchor(fingerprint, pem, meta) {
  log.debug('Entering writeTrustAnchor(). fingerprint=' + fingerprint);
  const dn = trustAnchorDn(fingerprint);
  const existing = entries.get(normalizeDn(dn));
  if (!existing && totalEntries() >= maxEntries()) {
    log.warn('ldap: not storing trust anchor ' + fingerprint + '; the ' +
             'directory holds its maximum of ' + maxEntries() + ' entries, ' +
             'so this anchor is in force until the next start and no longer.');
    log.debug('Leaving writeTrustAnchor(). The directory is full.');
    return false;
  }
  const stored = putEntry(dn, {
    objectClass: ['top', 'stsTrustAnchor'],
    cn: String(fingerprint),
    stsTrustAnchorFingerprint: String(fingerprint),
    stsTrustAnchorCertificate: String(pem),
    stsTrustAnchorAddedBy: String((meta && meta.addedBy) || '')
  }, { origin: 'truststore' });
  if (existing) {
    stored.createdAt = existing.createdAt;
    stored.attributes.createtimestamp = [existing.createdAt];
  }
  log.debug('Leaving writeTrustAnchor(). ' +
            (existing ? 'Replaced.' : 'Created.'));
  return true;
}

function deleteTrustAnchor(fingerprint) {
  log.debug('Entering deleteTrustAnchor(). fingerprint=' + fingerprint);
  const dn = trustAnchorDn(fingerprint);
  const gone = entries.delete(normalizeDn(dn));
  if (gone) {
    touchDirectory(dn);
  }
  log.debug('Leaving deleteTrustAnchor(). ' + (gone ? 'Removed.' : 'It was ' +
      'not stored.'));
  return gone;
}

// Whether a directory KEY names an entry in the truststore container of the
// DEFAULT realm — the test the replication appliers ask, so that an anchor
// another process added or removed reaches this process's listeners.
function isTrustAnchorKey(realmId, key) {
  log.debug("Entering isTrustAnchorKey().");
  if (String(realmId || realms.DEFAULT_ID) !== realms.DEFAULT_ID) {
    log.debug("Leaving isTrustAnchorKey().");
    return false;
  }
  const container = realms.run(realms.DEFAULT_REALM, function () {
    return normalizeDn(trustAnchorsDn());
  });
  const k = String(key || '');
  log.debug("Leaving isTrustAnchorKey().");
  return k !== container &&
         k.slice(-(container.length + 1)) === ',' + container;
}

function deletePep(name) {
  log.debug('Entering deletePep(). name=' + name);
  const stored = pepEntry(name);
  if (!stored) {
    log.debug('Leaving deletePep(). It was not here.');
    return false;
  }
  entries.delete(normalizeDn(stored.dn));
  touchDirectory();
  auditPolicyDirectory('entry.delete', stored.dn, stored.attributes, false);
  log.debug('Leaving deletePep(). ' + entries.size + ' entry/entries left.');
  return true;
}

// NO VALUES ARE NAMED, only attribute names — every other LDAP audit row here
// follows that rule, and this container is the one where breaking it would be
// most tempting and least wise: `xacmlPolicyDocument` is the whole policy, and
// an audit log that carried it would grow without bound and would put the
// authorization rules of the service into a second place that has to be
// protected as carefully as the first.
function auditPolicyDirectory(action, dn, attributes, created) {
  log.debug("Entering auditPolicyDirectory().");
  audit.audit({
    action: action,
    actor: '',
    protocol: 'LDAP',
    detail: (created ? 'Created ' : 'Changed ') + dn + ' with ' +
            Object.keys(attributes || {}).sort().join(', ') + '.'
  });
  log.debug("Leaving auditPolicyDirectory().");
}

// NO VALUES ARE NAMED, only attribute names — the rule every other LDAP row
// here follows, and it matters more on these entries than on any other in the
// directory: `fedClientSecret` is a real credential at a real foreign service,
// which is a stronger statement than anything oauthClientSecret can make.
function auditFederationDirectory(action, dn, attributes, created) {
  log.debug("Entering auditFederationDirectory().");
  audit.audit({
    action: action,
    actor: '',
    protocol: 'LDAP',
    channel: 'internal',
    target: dn,
    summary: 'The federation relationship entry ' + dn + ' was ' +
             (action === 'entry.delete' ? 'deleted' :
              (created ? 'created' : 'updated')),
    detail: { attributes: Object.keys(attributes || {}).sort().join(', ') }
  });
  log.debug("Leaving auditFederationDirectory().");
}

federation.setDirectory({
  readFederation: readFederation,
  writeFederation: writeFederation,
  allFederations: allFederations,
  countFederations: federationCount,
  deleteFederation: deleteFederationEntry,
  containerDn: function () {
    log.debug("Entering containerDn().");
    log.debug("Leaving containerDn().");
    return federationsDn();
  },
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
  log.debug("Entering spiffeEntryDn().");
  log.debug("Leaving spiffeEntryDn().");
  return 'cn=' + escapeDnValue(String(id)) + ',' + spiffeEntriesDn();
}

function spiffeAgentDn(id) {
  log.debug("Entering spiffeAgentDn().");
  log.debug("Leaving spiffeAgentDn().");
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
  log.debug("Entering spiffeChildren().");
  const rows = [];
  eachEntryInRealm(function (stored) {
    if (isUnder(stored.dn, containerDn) &&
        normalizeDn(stored.dn) !== normalizeDn(containerDn)) {
      rows.push(entryObject(stored));
    }
  });
  log.debug("Leaving spiffeChildren().");
  return rows;
}

function spiffeChildCount(containerDn) {
  log.debug("Entering spiffeChildCount().");
  let n = 0;
  eachEntryInRealm(function (stored) {
    if (isUnder(stored.dn, containerDn) &&
        normalizeDn(stored.dn) !== normalizeDn(containerDn)) {
      n++;
    }
  });
  log.debug("Leaving spiffeChildCount().");
  return n;
}

// REPLACES rather than merges, exactly as writeApplication() does and for the
// identical reason: the record being written was read from this entry a moment
// ago, so merging would make it impossible ever to REMOVE a value — a DNS name
// deleted with ldapmodify would come back on the next write. The operational
// attributes are preserved, because createTimestamp belongs to the entry rather
// than to the record.
function spiffeWrite(containerDn, attributeName, identifier, attributes,
                     originLabel) {
  log.debug('Entering spiffeWrite(). identifier=' + identifier);
  const existing = spiffeStored(containerDn, attributeName, identifier);
  const dn = existing ? existing.dn
    : (containerDn === spiffeEntriesDn() ? spiffeEntryDn(identifier)
                                         : spiffeAgentDn(identifier));
  if (!existing && totalEntries() >= maxEntries()) {
    // Warned rather than thrown, as a full directory always is here: whatever
    // the caller was doing succeeded, and a registry that could fail an SVID
    // request would be the tail wagging the dog.
    log.warn(errorCodes.tag('STS-LDAP-0007') +
             'ldap: not creating ' + dn + '; the directory holds its maximum ' +
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
  log.debug("Entering spiffeAuditDirectory().");
  audit.audit({
    action: action,
    actor: '',
    protocol: 'LDAP',
    channel: 'internal',
    target: dn,
    summary: 'The SPIFFE entry ' + dn + ' was ' +
             (action === 'entry.delete' ? 'deleted' :
              (created ? 'created' : 'updated')),
    detail: { attributes: Object.keys(attributes || {}).sort().join(', ') }
  });
  log.debug("Leaving spiffeAuditDirectory().");
}

spiffeRegistry.setDirectory({
  readEntry: function (id) {
    log.debug("Entering readEntry().");
    const stored = spiffeStored(spiffeEntriesDn(), 'spiffeEntryId', id);
    log.debug("Leaving readEntry().");
    return stored ? entryObject(stored) : null;
  },
  writeEntry: function (id, attributes) {
    log.debug("Entering writeEntry().");
    log.debug("Leaving writeEntry().");
    return spiffeWrite(spiffeEntriesDn(), 'spiffeEntryId', id, attributes,
                       'spiffe-entry');
  },
  deleteEntry: function (id) {
    log.debug("Entering deleteEntry().");
    log.debug("Leaving deleteEntry().");
    return spiffeDelete(spiffeEntriesDn(), 'spiffeEntryId', id);
  },
  allEntries: function () {
    log.debug("Entering allEntries().");
    log.debug("Leaving allEntries().");
    return spiffeChildren(spiffeEntriesDn());
  },
  countEntries: function () {
    log.debug("Entering countEntries().");
    log.debug("Leaving countEntries().");
    return spiffeChildCount(spiffeEntriesDn());
  },
  readAgent: function (id) {
    log.debug("Entering readAgent().");
    const stored = spiffeStored(spiffeAgentsDn(), 'spiffeAgentId', id);
    log.debug("Leaving readAgent().");
    return stored ? entryObject(stored) : null;
  },
  writeAgent: function (id, attributes) {
    log.debug("Entering writeAgent().");
    log.debug("Leaving writeAgent().");
    return spiffeWrite(spiffeAgentsDn(), 'spiffeAgentId', id, attributes,
                       'spiffe-agent');
  },
  deleteAgent: function (id) {
    log.debug("Entering deleteAgent().");
    log.debug("Leaving deleteAgent().");
    return spiffeDelete(spiffeAgentsDn(), 'spiffeAgentId', id);
  },
  allAgents: function () {
    log.debug("Entering allAgents().");
    log.debug("Leaving allAgents().");
    return spiffeChildren(spiffeAgentsDn());
  },
  countAgents: function () {
    log.debug("Entering countAgents().");
    log.debug("Leaving countAgents().");
    return spiffeChildCount(spiffeAgentsDn());
  },
  // Where the containers are, for the pages that report it. Here rather than in
  // that module because that module deliberately does not know.
  entriesContainerDn: function () {
    log.debug("Entering entriesContainerDn().");
    log.debug("Leaving entriesContainerDn().");
    return spiffeEntriesDn();
  },
  agentsContainerDn: function () {
    log.debug("Entering agentsContainerDn().");
    log.debug("Leaving agentsContainerDn().");
    return spiffeAgentsDn();
  },
  containerDn: function () {
    log.debug("Entering containerDn().");
    log.debug("Leaving containerDn().");
    return spiffeDn();
  }
});

// ---------------------------------------------------------------------------
// THE PEOPLE AND THE GROUPS AS A STORE, WHICH IS WHAT `scim.js` PROVISIONS
// INTO.
//
// The same division the applications container above draws, made again for the
// two containers that were already here: `scim_map.js` owns the SCHEMA (which
// LDAP attribute each SCIM member is, in both directions) and this file owns
// the DIRECTORY (where the containers are, what counts as a person or a group,
// how an entry is created, what the cap is, and what an audit row says).
// Neither knows the other's half.
//
// **THE DEPENDENCY IS NOT INVERTED HERE, and that is worth a sentence because
// five other things in this file are.** `scim.js` requires this module directly
// and `server.js` requires it AFTER this one, so neither of the two things that
// force a slot applies: there is no cycle (this module knows nothing about
// SCIM) and no route moves (the /ldap routes are already registered by the time
// the /scim ones are). Rule 3e says a slot is what you reach for when a require
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
// SAYS ONE IS.** Both rules are already written down in this file and neither
// is re-decided here: `populateVcAttributes()` uses the first and `groupsFor()`
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
  log.debug("Entering isPersonEntry().");
  log.debug("Leaving isPersonEntry().");
  return isUnder(stored.dn, usersDn()) &&
         normalizeDn(stored.dn) !== normalizeDn(usersDn());
}

function personCount() {
  log.debug("Entering personCount().");
  let n = 0;
  eachEntryInRealm(function (stored) {
    if (isPersonEntry(stored)) n++;
  });
  log.debug("Leaving personCount().");
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
  // A SCIM id is the entry's `entryUUID` since 2026-09-14; a DN still
  // resolves, which is what every other caller hands this.
  dn = dnForResourceId(dn);
  const stored = getEntry(dn);
  if (!stored || !isPersonEntry(stored)) {
    log.debug('Leaving readPerson(). ' +
              (stored ? 'Not under ' + usersDn() + '.' : 'Nothing ' +
        'there.'));
    return null;
  }
  log.debug('Leaving readPerson(). Found ' + stored.dn + '.');
  return entryObject(stored);
}

// ---------------------------------------------------------------------------
// THE ACCOUNT OBSERVER, AND IT IS AN INVERTED HOOK FOR THE REASON
// `authn.setSessionObserver()` IS ONE.
//
// RISC is a vocabulary about ACCOUNTS, and the acts it reports — an account
// disabled, enabled, purged, an identifier changed — happen HERE, in the
// directory, and nowhere else. `ssf/risc.js` is what turns one into a Security
// Event Token, and it cannot be required from this file: this module is loaded
// early enough to bind port 389 and `ssf/` is 23b in the require order, so a
// require in that direction would drag every `/ssf` route ahead of the
// management API's. The hook goes the other way, exactly as CAEP's does.
//
// **IT SITS ON THE STORE AND NOT ON A DOOR**, which is the whole reason there
// are five call sites below rather than one in `scim.js`. The same act reaches
// this directory over SCIM, over LDAP and from the console, and a RISC feature
// that only noticed the SCIM one would report a deprovisioning to a receiver
// when it was done with a PATCH and stay silent when it was done with an
// `ldapmodify` — which is not a smaller feature, it is a transmitter that lies
// by omission about half its own traffic. That is precisely the defect CAEP
// shipped with for one revision (`session-presented` from the OAuth2
// authorization endpoint alone) and it took a test naming every protocol to
// find, because a count of zero is also what "nobody asked for that type"
// looks like.
//
// **IT IS HANDED THE ATTRIBUTES BEFORE AND AFTER, AND IT DECIDES.** This file
// knows what a write is; it does not know that `scimActive` going false is an
// `account-disabled` and that `mail` moving is an `identifier-changed`. Those
// are RISC's readings and they belong in RISC's file — a version of this that
// answered "a disable happened" would be the vocabulary leaking into the
// store, and the third vocabulary would have had to undo it.
//
// **AND IT NEVER THROWS INTO A WRITE.** The observer signs a JWS and POSTs it
// to somebody else's endpoint; an `ldapmodify` that failed because a receiver's
// TLS handshake did would be a directory whose writes depend on a third party
// being up.
// ---------------------------------------------------------------------------
let accountObserver = null;

function setAccountObserver(fn) {
  log.debug('Entering setAccountObserver().');
  accountObserver = typeof fn === 'function' ? fn : null;
  log.debug('Leaving setAccountObserver(). ' +
            (accountObserver ? 'Installed.' : 'Cleared.'));
}

// A snapshot of one entry's attributes, deep enough to survive the write that
// follows. A shallow copy would hand the observer the SAME arrays the modify
// handler is about to rewrite in place, so every "before" would equal its
// "after" and nothing would ever look changed — which is a feature that is
// silently off rather than one that fails.
function attributeSnapshot(stored) {
  log.debug('Entering attributeSnapshot().');
  const out = {};
  if (stored && stored.attributes) {
    Object.keys(stored.attributes).forEach(function (name) {
      out[name] = (stored.attributes[name] || []).slice(0);
    });
  }
  log.debug('Leaving attributeSnapshot(). ' + Object.keys(out).length +
            ' attribute(s).');
  return out;
}

function noteAccountChange(kind, dn, before, after) {
  log.debug('Entering noteAccountChange(). ' + kind + ' ' + dn);
  if (!accountObserver) {
    log.debug('Leaving noteAccountChange(). Nobody is observing.');
    return;
  }
  try {
    accountObserver({ kind: String(kind), dn: String(dn),
      username: canonicalUsernameOfDn(dn), realm: realmFor(dn).id,
      before: before || {}, after: after || {} });
  } catch (e) {
    log.error(errorCodes.tag('STS-LDAP-0032') +
              'ldap: the account observer threw and the write stands: ' +
              e.message);
  }
  log.debug('Leaving noteAccountChange().');
}

// What a person is CALLED, from a DN alone, for a register that is keyed on
// people rather than on entries. It reads the stored entry where there is one
// — `usernameOfEntry()` is the directory's own rule and a second one here
// would mean RISC naming somebody one thing while a create of that name
// collided with them under another — and falls back to the RDN value for an
// entry that has just been deleted and is no longer there to read.
function canonicalUsernameOfDn(dn) {
  log.debug('Entering canonicalUsernameOfDn().');
  const stored = getEntry(dn);
  if (stored) {
    const name = usernameOfEntry(stored);
    log.debug('Leaving canonicalUsernameOfDn(). From the entry.');
    return name;
  }
  const rdn = splitRdns(String(dn || ''))[0] || '';
  const pairs = rdnPairs(rdn);
  const value = pairs.length ? String(pairs[0].value || '') : '';
  log.debug('Leaving canonicalUsernameOfDn(). From the RDN.');
  return value;
}

// WHERE A NEW PERSON GOES IS NOT DECIDED HERE, and there used to be a
// personDnFor() on this line that decided it.
//
// It built `uid=<userName>,ou=users` directly, which is right until it is not:
// namePlan() FOLDS a new name onto an entry that is already this person's under
// a different naming attribute (a client certificate's `cn=rcbj,ou=users`,
// say), and a second rule that always built a `uid=` DN would have created
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
// Returns a result object rather than a boolean, because a SCIM client is owed
// a reason. `full` is the one refusal this can produce, and it is a refusal
// rather than a warning — unlike writeApplication(), where the application's
// own request had already succeeded and only the record was at stake, here the
// request IS the write.
function writePerson(dn, attributes) {
  log.debug('Entering writePerson(). dn=' + dn);
  const existing = getEntry(dn);
  // Taken BEFORE putEntry() replaces the attributes, because this function is
  // a REPLACE and the observer's whole question is what moved.
  const before = attributeSnapshot(existing);
  if (existing && !isPersonEntry(existing)) {
    log.debug('Leaving writePerson(). ' + dn + ' is not under ' + usersDn() +
              '.');
    return coded('STS-LDAP-0048', { ok: false, reason: 'notAPerson', dn: dn });
  }
  if (!existing && totalEntries() >= maxEntries()) {
    log.warn(errorCodes.tag('STS-LDAP-0007') +
             'ldap: not creating ' + dn + '; the directory holds its maximum ' +
                                          'of ' +
             maxEntries() + ' entries (ldap.maxEntries).');
    log.debug('Leaving writePerson(). The directory is full.');
    return coded('STS-LDAP-0007', { ok: false, reason: 'full', dn: dn });
  }
  // The parent has to exist, which is the same structural rule the LDAP add
  // handler enforces. It always does here — seed() creates ou=users — but a
  // client can delete it, and an entry under a container that is gone is
  // unreachable by every search this service answers.
  if (!getEntry(parentDn(dn))) {
    log.debug('Leaving writePerson(). There is no ' + parentDn(dn) + '.');
    return coded('STS-LDAP-0006', { ok: false, reason: 'noParent', dn: dn,
                                    parent: parentDn(dn) });
  }
  const created = existing ? existing.createdAt : generalizedTime();
  const stored = putEntry(dn, attributes,
                          { origin: existing ? existing.origin : 'scim' });
  stored.createdAt = created;
  stored.attributes.createtimestamp = [created];
  stored.attributes.modifytimestamp = [generalizedTime()];
  noteAccountChange(existing ? 'updated' : 'created', stored.dn, before,
                    attributeSnapshot(stored));
  log.debug('Leaving writePerson(). The entry was ' +
            (existing ? 'updated.' : 'created.'));
  return { ok: true, created: !existing, dn: stored.dn,
           entry: entryObject(stored) };
}

// ---------------------------------------------------------------------------
// THE BOOTSTRAP ADMINISTRATOR CANNOT BE DELETED OR RENAMED (2026-09-13).
//
// `admin.bootstrapUsername` in the DEFAULT realm is the account a new instance
// is administered through: seeded into both console roles, forced to change its
// password, and — until it first signs in to the console — the reason every
// signed-in person may use the console (`admin-ui/admin_rbac.js`). Deleting it
// would leave a service whose console roster is whatever happened to be left,
// and renaming it is a delete under another name. So every door that removes a
// person refuses it: SCIM (through `deletePerson()` here), an LDAP delete and an
// LDAP rename. The name is compared case-insensitively, as a username is
// everywhere in this directory.
//
// **EVERY REALM HAS ONE SINCE 2026-09-14 (#32)**, and this said "the rule is
// the DEFAULT realm's only — a trust realm's `admin` is an ordinary person
// there" until then. A realm's own bootstrap administrator is how that realm
// is administered, so it is protected in its realm for the same reason. It is
// recognised by the `stsBootstrapAdministrator` flag the seed writes, so a
// realm's ordinary person who merely shares the name — made before that realm
// was seeded, say — is still an ordinary person; the default realm's account
// is protected by name, as before.
// ---------------------------------------------------------------------------
function isBootstrapAdministratorEntry(stored) {
  log.debug('Entering isBootstrapAdministratorEntry().');
  const wanted = String(config.value('admin.bootstrapUsername') || '')
    .trim().toLowerCase();
  const flagged = !!(stored && stored.attributes &&
    (stored.attributes.stsbootstrapadministrator || [])
      .some(function (value) {
        return String(value).toUpperCase() === 'TRUE';
      }));
  const answer = !!(stored && wanted && (realms.isDefault() || flagged) &&
                    isPersonEntry(stored) &&
                    String(usernameOfEntry(stored)).toLowerCase() === wanted);
  log.debug('Leaving isBootstrapAdministratorEntry(). ' + answer);
  return answer;
}

// Delete a person's entry. It leaves that DN behind in every group that lists
// it, which is deliberate and is the same non-feature `GET /admin/ldap/service`
// documents: referential integrity is a directory feature and not a protocol
// rule, and a dangling member is exactly what /admin/groups exists to report. A
// SCIM client that means to remove somebody from their groups has to say so.
function deletePerson(dn) {
  log.debug('Entering deletePerson(). dn=' + dn);
  // A SCIM id is the entry's `entryUUID` since 2026-09-14; a DN still
  // resolves, which is what every other caller hands this.
  dn = dnForResourceId(dn);
  const stored = getEntry(dn);
  if (!stored || !isPersonEntry(stored)) {
    log.debug('Leaving deletePerson(). It was not a person here.');
    return coded('STS-LDAP-0013', { ok: false, reason: 'notFound', dn: dn });
  }
  if (isBootstrapAdministratorEntry(stored)) {
    log.warn(errorCodes.tag('STS-LDAP-0077') + 'ldap: refused to delete ' +
             stored.dn + ' — it is its realm\'s bootstrap ' +
             'administrator (admin.bootstrapUsername).');
    log.debug('Leaving deletePerson(). The bootstrap administrator.');
    return coded('STS-LDAP-0077', { ok: false, reason: 'protected',
                                    dn: stored.dn });
  }
  if (hasChildren(stored.dn)) {
    log.debug('Leaving deletePerson(). It has children.');
    return coded('STS-LDAP-0014',
                 { ok: false, reason: 'notLeaf', dn: stored.dn });
  }
  const goneAttributes = attributeSnapshot(stored);
  const goneName = usernameOfEntry(stored);
  entries.delete(normalizeDn(stored.dn));
  touchDirectory();
  // AFTER the entry is gone, so a RISC account-purged reports a purge that
  // actually happened; and with the name carried, because
  // canonicalUsernameOfDn() can no longer read an entry that is not there.
  noteAccountChange('deleted:' + goneName, stored.dn, goneAttributes, {});
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
// default realm: `DELETE
// /realm/acme/scim/v2/Groups/cn=x,ou=groups,dc=example,dc=com` answered 204 and
// the group was gone. The person half never had the hole, because
// isPersonEntry() tests placement under the AMBIENT realm's usersDn();
// groupRuleFor() answers "this is a group" wherever it sits, on purpose, so
// nothing about a group's own definition could have caught it. Each door was
// guarded by hand first and the store split made the guard structural — these
// now read the realm's own store and could not reach another's if they tried.
function readGroupEntry(dn) {
  log.debug('Entering readGroupEntry(). dn=' + dn);
  // A SCIM id is the entry's `entryUUID` since 2026-09-14; a DN still
  // resolves, which is what every other caller hands this.
  dn = dnForResourceId(dn);
  const stored = getEntry(dn);
  if (!stored || !groupRuleFor(stored)) {
    log.debug('Leaving readGroupEntry(). ' +
              (stored ? 'It is an entry and not a group.' : 'Nothing there.'));
    return null;
  }
  const object = entryObject(stored);
  object.rule = groupRuleFor(stored);
  object.members = membersOf(stored);
  log.debug('Leaving readGroupEntry(). ' + object.members.length + ' member ' +
      'value(s).');
  return object;
}

// Where a new group goes: `cn=<displayName>,ou=groups`. Placement AND an
// objectClass — scim_map.js adds groupOfNames — so a group created over SCIM is
// one by both rules rather than by where it happens to sit, and stays one if a
// client moves it.
function groupDnFor(displayName) {
  log.debug("Entering groupDnFor().");
  log.debug("Leaving groupDnFor().");
  return 'cn=' + escapeDnValue(String(displayName)) + ',' + groupsDn();
}

// ---------------------------------------------------------------------------
// WHAT A CREATE IS ABOUT TO TAKE, for `directory_create_claims.js` (#46
// section 3) — in the AMBIENT realm, and computed here because a DN and a
// username are this file's to decide. `username` is a person created by name
// (`createUser()`'s DN and the name itself), `group` a group by display name,
// `dn` an entry by DN with the `uid` values an LDAP add carries — the names
// the add handler's one-entry-per-person check reads.
// ---------------------------------------------------------------------------
function createClaimSpec(what) {
  log.debug("Entering createClaimSpec().");
  const o = what || {};
  const dns = [];
  const usernames = [];
  if (o.username) {
    const name = String(o.username).trim();
    if (name && nameUsableInDn(name)) {
      dns.push(normalizeDn(namePlan(name).dn));
    }
    usernames.push(name);
  }
  if (o.group) {
    dns.push(normalizeDn(groupDnFor(String(o.group).trim())));
  }
  if (o.dn) {
    dns.push(normalizeDn(o.dn));
    if (normalizeDn(parentDn(o.dn)) === normalizeDn(usersDn())) {
      usernames.push(usernameOfEntry({ dn: String(o.dn) }));
      (o.uids || []).forEach(function (uid) {
        usernames.push(String(uid));
      });
    }
  }
  log.debug("Leaving createClaimSpec().");
  return { realm: realms.currentId(), dns: dns,
           usernames: usernames.filter(Boolean) };
}

// The same, claimed. Resolves to the answer `directory_create_claims.claim()`
// gives.
function claimCreate(what) {
  log.debug("Entering claimCreate().");
  let spec = null;
  try {
    spec = createClaimSpec(what);
  } catch (e) {
    log.debug("Caught in claimCreate(): " + ((e && e.message) || e));
    // A name this file cannot place is refused by the create itself, with its
    // own sentence; there is nothing to claim for it.
    log.debug("Leaving claimCreate(). Nothing placeable.");
    return Promise.resolve({ ok: true, settle: function () {} });
  }
  log.debug("Leaving claimCreate().");
  return createClaims.claim(spec);
}

// `origin` says WHICH DOOR wrote it, and it is a parameter rather than the
// constant it used to be because there are now three: SCIM (the caller this
// function was written for), the admin console's RBAC screen, and the
// management API behind it. It shows in the `Came from` column on
// /admin/groups, which is the one place a reader can tell a group somebody
// PATCHed over SCIM from one the console created. It defaults to `scim`, so the
// call site that predates the parameter says exactly what it always meant.
function writeGroupEntry(dn, attributes, origin) {
  log.debug('Entering writeGroupEntry(). dn=' + dn + ', origin=' +
            (origin || 'scim'));
  // A DN in another realm is simply not here, and neither is its parent, so a
  // cross-realm PUT falls through to the parent check below and is answered
  // `noParent` — a write into a container this directory does not have, which
  // is exactly what it is from in here.
  const existing = getEntry(dn);
  if (existing && !groupRuleFor(existing)) {
    log.debug('Leaving writeGroupEntry(). ' + dn + ' is an entry and not a ' +
                                                   'group.');
    return coded('STS-LDAP-0048', { ok: false, reason: 'notAGroup', dn: dn });
  }
  if (!existing && totalEntries() >= maxEntries()) {
    log.warn(errorCodes.tag('STS-LDAP-0007') +
             'ldap: not creating ' + dn + '; the directory holds its maximum ' +
                                          'of ' +
             maxEntries() + ' entries (ldap.maxEntries).');
    log.debug('Leaving writeGroupEntry(). The directory is full.');
    return coded('STS-LDAP-0007', { ok: false, reason: 'full', dn: dn });
  }
  if (!getEntry(parentDn(dn))) {
    log.debug('Leaving writeGroupEntry(). There is no ' + parentDn(dn) + ' ' +
        'in this realm.');
    return coded('STS-LDAP-0006', { ok: false, reason: 'noParent', dn: dn,
                                    parent: parentDn(dn) });
  }
  const created = existing ? existing.createdAt : generalizedTime();
  const stored = putEntry(dn, attributes,
                          { origin: existing ? existing.origin :
                                    (origin || 'scim') });
  stored.createdAt = created;
  stored.attributes.createtimestamp = [created];
  stored.attributes.modifytimestamp = [generalizedTime()];
  log.debug('Leaving writeGroupEntry(). The entry was ' +
            (existing ? 'updated.' : 'created.'));
  return { ok: true, created: !existing, dn: stored.dn,
           entry: readGroupEntry(stored.dn) };
}

function deleteGroupEntry(dn) {
  log.debug('Entering deleteGroupEntry(). dn=' + dn);
  // A SCIM id is the entry's `entryUUID` since 2026-09-14; a DN still
  // resolves, which is what every other caller hands this.
  dn = dnForResourceId(dn);
  const stored = getEntry(dn);
  if (!stored || !groupRuleFor(stored)) {
    log.debug('Leaving deleteGroupEntry(). It was not a group here.');
    return coded('STS-LDAP-0013', { ok: false, reason: 'notFound', dn: dn });
  }
  if (hasChildren(stored.dn)) {
    log.debug('Leaving deleteGroupEntry(). It has children.');
    return coded('STS-LDAP-0014',
                 { ok: false, reason: 'notLeaf', dn: stored.dn });
  }
  entries.delete(normalizeDn(stored.dn));
  touchDirectory();
  log.debug('Leaving deleteGroupEntry(). ' + entries.size + ' entry/entries ' +
      'left.');
  return { ok: true, dn: stored.dn };
}

// ---------------------------------------------------------------------------
// CREATING A GROUP BY HAND, AND PUTTING SOMEBODY IN ONE (2026-09-06).
//
// **THESE TWO ARE TO A GROUP WHAT createUser() IS TO A PERSON, and they exist
// because until today there was no such pair at all.** `/admin/groups` and
// `GET /admin-api/groups` were a READ and nothing else, so the only two ways to
// put a group in this directory were an `ldapadd` on the raw socket and
// `POST /scim/v2/Groups` — which meant the console could report a dangling
// member, a claimed membership and a group that grants the console itself, and
// could not create the group any of that is about. The management API had the
// same hole and it was louder there: `POST /admin-api/users/create` puts a
// person in, and nothing put them in a group.
//
// THEY LIVE HERE FOR createUser()'s REASON, said again rather than cited. The
// console must not be a second definition of what creating a group means, any
// more than it is a second definition of what creating a person means. The
// refusals that matter — a name that cannot be an RDN, a group that is already
// there, a directory that is full — are in this file, so the console's form,
// `POST /admin-api/groups/create` and (for the name rule) a SCIM create all get
// the same answer about the same name.
//
// **WHY SCIM STILL HAS ITS OWN INGRESS AND IS NOT ROUTED THROUGH
// createGroup().** That handler is SCIMMY-shaped: it is handed a resource,
// throws `SCIMMY.Types.Error` with a `scimType`, and has to serve PUT and PATCH
// — an UPDATE of a group that exists — as well as a create. Making it call this
// would mean this function growing an update mode and a second error
// vocabulary, which is how one function ends up being two functions in a
// trenchcoat. What the two share is the part that could disagree: the DN
// (`groupDnFor()`), the name rule (`nameUsableInDn()`) and the write
// (`writeGroupEntry()`). They agree about the store because they are the same
// three calls, not because anybody remembered to keep them in step.
//
// **AN EMPTY GROUP IS ALLOWED AND RFC 4519 SAYS IT SHOULD NOT BE.** `member` is
// MUST on `groupOfNames`, and /admin/groups' own note says outright that a real
// directory refuses an empty one. This creates one anyway when no member is
// named, for one reason: SCIM already does. A console stricter than SCIM about
// the same store would be two doors disagreeing about what this directory
// holds, which is the exact failure every slot in this file is arranged to
// avoid — and the page that reports the state is right there to say it
// happened.
// ---------------------------------------------------------------------------
function createGroup(displayName, options) {
  log.debug('Entering createGroup(). displayName=' + displayName);
  const opts = options || {};
  const wanted = String(displayName == null ? '' : displayName).trim();
  if (!wanted) {
    log.debug('Leaving createGroup(). No name.');
    return coded('STS-LDAP-0042', { ok: false, errors: ['Which group? Send ' +
                                 '`group` with the name it will be known by ' +
                                 '— that string becomes both the `cn` and ' +
                                 'the RDN, so it is the whole of what names ' +
                                 'the entry.'] });
  }
  if (DN_SHAPED.test(wanted)) {
    // The same refusal createUser() makes about a username, and it is worth
    // making here for a sharper reason: a caller that pastes
    // `cn=developers,ou=groups,dc=example,dc=com` in here means the group at
    // that DN, and what they would get is `cn=cn\=developers\,ou\=groups...`
    // — a second group whose name is the first one's DN.
    log.debug('Leaving createGroup(). That is a DN.');
    return coded('STS-LDAP-0043', { ok: false, errors: ['"' + wanted + '" is ' +
                                 'a DN and not a group name. Send the `cn` ' +
                                 'alone; this function puts it ' +
                                 'under ' + groupsDn() + '. A group ' +
                                 'somewhere else in the tree is an `ldapadd` ' +
                                 'and is still a group here by the ' +
                                 'objectClass rule /admin/groups reports.'] });
  }
  if (!nameUsableInDn(wanted)) {
    log.debug('Leaving createGroup(). The name carries DN syntax.');
    return coded('STS-LDAP-0046', { ok: false, errors: ['"' + wanted + '" ' +
                                 'cannot name a group here: it carries a ' +
                                 'character RFC 4514 section 2.4 reserves in ' +
                                 'a DN (one of , = + < > # ; " \\), so the ' +
                                 'entry would be named something other than ' +
                                 'what was typed. Refused rather than ' +
                                 'escaped, exactly as a username is, and for ' +
                                 'the same reason: an `ldapadd` can still ' +
                                 'create it with the escaping written out.'] });
  }
  const dn = groupDnFor(wanted);
  const existing = getEntry(dn);
  if (existing) {
    log.debug('Leaving createGroup(). It is already there.');
    return coded('STS-LDAP-0004', { ok: false,
             errors: ['There is already an entry at ' + dn + '.' +
                      (groupRuleFor(existing)
                        ? ' Add members to it rather than creating it again.'
                        : ' It is not counted as a group — see /admin/groups ' +
                          'for which rule catches what — so this would be a ' +
                          'create over the top of something else.')],
             existing: { dn: existing.dn, origin: existing.origin || '' } });
  }
  // THE MEMBERS THE CREATE CARRIES, resolved the way addGroupMember() resolves
  // one, so that a group created with three people in it and a group created
  // empty and then filled hold the same three values. A member that names
  // nothing is written anyway; see addGroupMember() for why.
  const asked = [].concat(opts.members || []).map(function (one) {
    return String(one == null ? '' : one).trim();
  }).filter(function (one) { return one !== ''; });
  const members = [];
  const dangling = [];
  asked.forEach(function (one) {
    const value = memberDnFor(one);
    if (members.indexOf(value.dn) >= 0) {
      return;
    }
    members.push(value.dn);
    if (!value.present) {
      dangling.push(value.dn);
    }
  });
  const note = String(opts.note || '').trim() ||
    'created by hand rather than by a directory client';
  const attributes = {
    objectClass: ['top', 'groupOfNames'],
    cn: [wanted],
    description: [note]
  };
  if (members.length) {
    attributes.member = members;
  }
  const written = writeGroupEntry(dn, attributes, opts.origin || 'console');
  if (!written.ok) {
    log.debug('Leaving createGroup(). The directory refused: ' +
              written.reason);
    return coded(errorCodes.codeOf(written),
                 { ok: false, reason: written.reason,
             errors: [written.reason === 'full'
               ? 'This directory holds its maximum of ' + maxEntries() +
                 ' entries (ldap.maxEntries). Nothing was written.'
               : written.reason === 'noParent'
                 ? 'There is no ' + (written.parent || groupsDn()) + ' in ' +
                   'this realm, so there is no container to put a group in.'
                 : 'The entry at ' + dn + ' could not be written (' +
                   written.reason + ').'] });
  }
  log.info('ldap: created the group ' + written.dn + ' with ' + members.length +
           ' member(s) because somebody asked for it.');
  audit.recordDirectory({
    action: 'group.create',
    actor: String(opts.actor || ''),
    target: written.dn,
    // Passed through rather than fixed, for createUser()'s reason: this
    // function serves the console and the management API, and a row that called
    // either of them LDAP would be the audit log's one job done wrong.
    protocol: String(opts.protocol || ''),
    channel: opts.channel || 'internal',
    summary: 'created the group ' + written.dn + ' with ' + members.length +
             ' member(s); ' + note,
    detail: { reason: note,
              members: members.join(', '),
              memberCount: members.length,
              // ON THE ROW BECAUSE NOTHING ELSE RECORDS THE MOMENT. This
              // directory does no referential integrity, so a member that names
              // nothing is a state /admin/groups reports and cannot date.
              danglingAtCreate: dangling.length,
              entriesNow: totalEntries() }
  });
  log.debug('Leaving createGroup(). ' + written.dn + ' was created.');
  return { ok: true, dn: written.dn, group: wanted,
           members: members, dangling: dangling,
           entry: written.entry };
}

// WHERE A MEMBERSHIP VALUE POINTS, and it is `admin_rbac.js`'s memberValueFor()
// with one thing added rather than a copy of it: a caller here may name a
// person OR pass a DN outright, because `POST /admin-api/groups/add-member` is
// how a group gets a member that is itself a group, and there is no username
// that names one.
//
// A bare name resolves to the person's OWN entry wherever it is — somebody
// seeded by a client certificate is at `cn=<name>,ou=users` and not at
// `uid=<name>,ou=users`, and a membership written in the uid form would dangle
// beside the entry it was meant to name. With nobody there, the uid form is
// where a person created later will be, so the value resolves the moment they
// arrive.
function memberDnFor(nameOrDn) {
  log.debug('Entering memberDnFor(). ' + nameOrDn);
  const wanted = String(nameOrDn == null ? '' : nameOrDn).trim();
  if (DN_SHAPED.test(wanted)) {
    const stored = getEntry(wanted);
    log.debug('Leaving memberDnFor(). A DN, ' +
              (stored ? 'and something is there.' : 'and nothing is there.'));
    return { dn: stored ? stored.dn : wanted, present: !!stored, wasDn: true };
  }
  const existing = existingUserEntry(wanted);
  if (existing) {
    log.debug('Leaving memberDnFor(). Their entry is at ' + existing.dn + '.');
    return { dn: existing.dn, present: true, wasDn: false };
  }
  const dn = 'uid=' + escapeDnValue(wanted) + ',' + usersDn();
  log.debug('Leaving memberDnFor(). Nothing there yet; ' + dn + ' is where ' +
            'they would go.');
  return { dn: dn, present: false, wasDn: false };
}

// ---------------------------------------------------------------------------
// ONE PERSON INTO ONE GROUP.
//
// THREE THINGS IT DELIBERATELY DOES NOT DO, and each is a rule stated somewhere
// else in this service that would be contradicted by doing it:
//
//   * **IT DOES NOT REFUSE A MEMBER THAT NAMES NOTHING.** The SCIM ingress
//     gives the argument in full and it is the same one: this directory does no
//     referential integrity — a delete leaves the DN in every group that listed
//     it — so refusing a dangling member here would make it impossible to
//     produce, from this door, the state /admin/groups exists to report. It is
//     LOGGED and it is on the answer, so it is visible rather than silent.
//   * **IT DOES NOT WRITE `memberOf` ONTO THE PERSON.** Nothing in this service
//     maintains that attribute — it is not even standard — and `admin_rbac.js`
//     refuses a revoke of a membership held that way for exactly this reason.
//     Writing it here would make this the one door that creates a fact no other
//     door can undo.
//   * **IT DOES NOT NEST-EXPAND.** A member that is itself a group is stored as
//     one value and nobody inside it is counted; /admin/groups says so on the
//     page. Nothing here walks a group tree, and a function that flattened on
//     the way in would be claiming a feature this service does not have.
//
// AND IT IS IDEMPOTENT, which is `admin_rbac.js`'s grant() rule and is worth
// the sentence: adding somebody who is already in the group is the state the
// caller wanted, so it answers ok with `changed: false`. A 400 there would make
// a script that adds on every run fail on its second one — and the bulk-load
// jobs in tests/vendored are exactly such a script.
// ---------------------------------------------------------------------------
function addGroupMember(group, member, options) {
  log.debug('Entering addGroupMember(). group=' + group + ', member=' + member);
  const opts = options || {};
  const wantedGroup = String(group == null ? '' : group).trim();
  const wantedMember = String(member == null ? '' : member).trim();
  if (!wantedGroup) {
    log.debug('Leaving addGroupMember(). No group.');
    return coded('STS-LDAP-0042', { ok: false, errors: [
      'Which group? Send `group` with its `cn` or its whole DN.'] });
  }
  if (!wantedMember) {
    log.debug('Leaving addGroupMember(). No member.');
    return coded('STS-LDAP-0049', { ok: false, errors: ['Who? Send `member` ' +
                                 'with a username, or with the DN of any ' +
                                 'entry — a group can hold another group, ' +
                                 'and no username names one.'] });
  }
  // A `cn` OR A DN, because the two callers arrive with different things in
  // hand: the console's form is on a page whose rows are DNs, and a script
  // filling fifty groups has the name it just created them under.
  const dn = DN_SHAPED.test(wantedGroup) ? wantedGroup :
             groupDnFor(wantedGroup);
  const existing = readGroupEntry(dn);
  if (!existing) {
    const stored = getEntry(dn);
    log.debug('Leaving addGroupMember(). No such group.');
    return coded('STS-LDAP-0050', { ok: false,
             errors: [stored
               ? 'There is an entry at ' + dn + ' and it is not counted as a ' +
                 'group — it neither sits under ' + groupsDn() + ' nor ' +
                 'carries a group objectClass. /admin/groups says which rule ' +
                 'catches what.'
               : 'There is no group at ' + dn + '. Create it first, or name ' +
                 'an existing one — this does not create a group as a side ' +
                 'effect of adding somebody to it, because a typo in a name ' +
                 'would then be a new group rather than an error.'] });
  }
  const target = memberDnFor(wantedMember);
  // ASKED ACROSS ALL THREE MEMBERSHIP ATTRIBUTES, because the answer has to be
  // the one /admin/groups and the groups claim give: somebody listed as
  // `memberUid` is in this group, and an add that could not see that would
  // write a second value for one membership.
  const already = existing.members.filter(function (one) {
    if (one.holds === 'uid') {
      return String(one.value).trim().toLowerCase() ===
             wantedMember.trim().toLowerCase();
    }
    return normalizeDn(one.value) === normalizeDn(target.dn) ||
           (one.present && normalizeDn(one.dn) === normalizeDn(target.dn));
  });
  if (already.length) {
    log.debug('Leaving addGroupMember(). Already a member.');
    return { ok: true, changed: false, dn: existing.dn, member: target.dn,
             present: target.present,
             message: target.dn + ' is already listed by ' + existing.dn +
                      ' (as ' + already[0].attribute + '). Nothing was ' +
                      'changed.' };
  }
  const attributes = {};
  Object.keys(existing.attributes).forEach(function (name) {
    // The operational three, and `entrydn` is the one that matters: it is
    // SYNTHESISED by entryObject() rather than stored, and writing the read
    // object straight back would turn it into a real attribute — the one thing
    // every door onto this directory is told never to do.
    if (OPERATIONAL.indexOf(name.toLowerCase()) >= 0) {
      return;
    }
    attributes[name] = existing.attributes[name].slice(0);
  });
  // ONTO `member`, whatever else the entry carries. A group holding
  // `uniqueMember` values gains a `member` one rather than having its own
  // convention extended, and that is deliberate: this service's own group
  // claim, the console and RFC 4519 all read `member` first, and guessing which
  // of three attributes an operator meant would be this function deciding
  // something the caller did not say.
  const key = Object.keys(attributes).filter(function (name) {
    return name.toLowerCase() === 'member';
  })[0] || 'member';
  attributes[key] = (attributes[key] || []).concat([target.dn]);

  const written = writeGroupEntry(existing.dn, attributes,
                                  opts.origin || 'console');
  if (!written.ok) {
    log.debug('Leaving addGroupMember(). The directory refused: ' +
              written.reason);
    return coded(errorCodes.codeOf(written),
                 { ok: false, reason: written.reason,
             errors: ['The membership could not be written onto ' +
                      existing.dn +
                      ' (' + written.reason + ').'] });
  }
  if (!target.present) {
    log.info('ldap: ' + existing.dn + ' now lists ' + target.dn + ' and ' +
             'nothing is stored there. It is written anyway — this directory ' +
             'does no referential integrity, and a dangling member is a ' +
             'state worth being able to produce.');
  }
  audit.recordDirectory({
    action: 'group.add-member',
    actor: String(opts.actor || ''),
    target: existing.dn,
    protocol: String(opts.protocol || ''),
    channel: opts.channel || 'internal',
    summary: target.dn + ' was added to ' + existing.dn,
    detail: { member: target.dn,
              // WHETHER IT RESOLVED, on the row, because this is the moment a
              // dangling membership is created and nothing else records it.
              resolves: target.present,
              attribute: key,
              membersNow: (attributes[key] || []).length }
  });
  log.debug('Leaving addGroupMember(). ' + existing.dn + ' now lists ' +
            target.dn + '.');
  return { ok: true, changed: true, dn: existing.dn, member: target.dn,
           present: target.present, attribute: key,
           memberCount: (attributes[key] || []).length,
           entry: written.entry,
           message: target.dn + ' is now a member of ' + existing.dn + '.' +
                    (target.present ? ''
                                    : ' NOTHING IS AT THAT DN — they have ' +
                                      'not authenticated here and nobody has ' +
                                      'created them, so the membership ' +
                                      'DANGLES until one of those happens. ' +
                                      'It is written rather than refused ' +
                                      'because this directory does no ' +
                                      'referential integrity in either ' +
                                      'direction.') };
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

  const pagedEntries = directoryPaging(req, matchedEntries, 'entries',
                                       'entries');
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
    sourceOfTruth: 'These entries ARE the SPIFFE registry. An ldapmodify ' +
      'under ou=entries changes what the next SVID looks like — ' +
      'spiffeX509SvidTtl changes its lifetime, spiffeDnsName changes its ' +
      'subjectAltName, and spiffeId changes whose identity it is — because ' +
      'nothing caches them. The two containers hold different KINDS of ' +
      'thing: entries are CONFIGURATION and agents are a RECORD, which is ' +
      'why nothing about an agent is editable from the console.',
    editable: spiffeRegistry.EDITABLE,
    schema: spiffeRegistry.SCHEMA,
    filter: { entryq: carried.entryq || null, agentq: carried.agentq || null },
    entriesPaging: adminViews.pagingJson(pagedEntries.paging),
    agentsPaging: adminViews.pagingJson(pagedAgents.paging),
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
      xmlEscape(one.where) + (one.standard ? '' : ' <strong>(invented ' +
                                                  'here)</strong>') +
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
    '<input type="hidden" name="entryq" value="' + xmlEscape(carried.entryq) +
    '"><input ' +
    'type="hidden" name="agentq" ' +
    'value="' + xmlEscape(carried.agentq) + '"><label ' +
    'for="per">Rows per table</label><select id="per" name="per">' +
    admin.perPageOptions(pagedEntries.paging.perPage) + '</select>' +
    '<button class="secondary" type="submit">Apply</button>' +
    '</div></form>' +
    admin.note('Both tables below are paged separately and they share this ' +
    'size. Changing it starts each of them at its first page.') +
    '<h2>Registration entries</h2>' +
    '<form method="get" action="/admin/ldap/spiffe"><div class="formrow">' +
    '<input type="hidden" name="agentq" value="' + xmlEscape(carried.agentq) +
    '"><input ' +
    'type="hidden" name="per" value="' + xmlEscape(carried.per) + '">' +
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
    '<input type="hidden" name="entryq" value="' + xmlEscape(carried.entryq) +
    '"><input ' +
    'type="hidden" name="per" value="' + xmlEscape(carried.per) + '">' +
    '<label for="agentq">Agent or DN</label>' +
    '<input type="text" id="agentq" name="agentq" size="30" value="' +
    xmlEscape(carried.agentq) + '" placeholder="an agent SPIFFE ID, or part ' +
    'of a DN"><button type="submit">Search</button>' +
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
  const nav = admin.pageNavPair('/admin/ldap/applications', filterParams,
                                paging);

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
    sourceOfTruth: 'These entries ARE the registry. An ldapmodify here ' +
      'changes what the protocol endpoints do — adding a value to ' +
      'oauthRedirectUri adds a redirect URI that RFC 9700 mode will then ' +
      'accept by exact match.',
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
    // directory sees it", and the directory sees an entry by its DN — a row
    // that named only the identifier left the one address an ldapsearch needs
    // to be reconstructed by the reader from a naming rule published nowhere.
    return '<tr><td>' + admin.clipped(row.identifier, 40) +
      (row.dn ? '<div class="sub">' + admin.clipped(row.dn, 40) +
        (row.identifier === row.dnLabel ? '' :
          ' &mdash; the identifier is too long for a readable RDN, so the cn ' +
          'is a digest of it and <code>appIdentifier</code> is the identity') +
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
      xmlEscape(one.where) + (one.standard ? '' : ' <strong>(invented ' +
                                                  'here)</strong>') +
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
    'entry per unique identifier, so an application that speaks two ' +
    'protocols under one name is one row with two kinds rather than two ' +
    'rows.</p><div class="tiles">' +
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
    '<form method="get" action="/admin/ldap/applications"><div ' +
    'class="formrow"><label for="q">Anywhere in the entry</label><input ' +
    'type="text" id="q" name="q" value="' + xmlEscape(wantedText) +
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
        : 'Nothing yet. An entry appears the first time a client_id, ' +
          'wtrealm, AppliesTo, entityID or service principal name is ' +
          'accepted.') +
      '</td></tr>') +
    '</table>' +
    nav.foot +
    '<h2>What an application can be</h2>' +
    '<table><tr><th>Kind</th><th>Label</th><th>What it means</th></tr>' +
    kindRows + '</table>' +
    '<h2>The object classes</h2>' +
    admin.note('node-ldapjs has no schema subsystem &mdash; it is protocol ' +
    'machinery, and it is a submodule this repository does not modify ' +
    '&mdash; and this directory is schemaless on purpose. So this is a ' +
    'VOCABULARY rather than a constraint: nothing rejects an entry for ' +
    'disobeying it. Where a registered class fits, it is used.') +
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
  const nav = admin.pageNavPair('/admin/ldap/federations', filterParams,
                                paging);

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
    sourceOfTruth: 'These entries ARE the register. An ldapmodify here is a ' +
      'SECURITY change: fedSigningCertificate decides whose assertions this ' +
      'service will believe, and fedEnabled turns a partner on. Nothing ' +
      'caches them.',
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
      '<td>' +
      xmlEscape((federation.roleRow(row.fedRole) || {}).short || row.fedRole) +
      '<div class="sub">' +
      xmlEscape((federation.protocolRow(row.fedProtocol) ||
                 {}).label || row.fedProtocol) +
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
      xmlEscape(one.where) + (one.standard ? '' : ' <strong>(invented ' +
                                                  'here)</strong>') +
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
    '</code>: the foreign identity providers this service consumes ' +
    'assertions from, and the foreign service providers it asserts to. One ' +
    'relationship is one DIRECTION, so a partner in both is two ' +
    'entries.</p><div class="tiles">' +
    admin.tile(all.length, 'Relationships') +
    admin.tile(all.filter(function (r) {
      return federation.isEnabled(r);
    }).length,
               'Enabled') +
    admin.tile(maxFederations(), 'Maximum held') +
    '</div>' +
    admin.warn('<strong>An ldapmodify here is a security change, which is ' +
    'not true of any other container in this directory.</strong> ' +
    '<code>fedSigningCertificate</code> decides whose assertions this ' +
    'service will believe; <code>fedEnabled</code> turns a partner on. ' +
    'Everywhere else here an edit changes what this service hands out, and ' +
    'every bind to this directory succeeds &mdash; so this container is ' +
    'exactly as protected as the rest of it, which is to say not at all. ' +
    'That is the honest state of a mock, and it is why federation is the one ' +
    'feature here that refuses by default.') +
    '<form method="get" action="/admin/ldap/federations"><div ' +
    'class="formrow"><label for="q">Relationship</label><input type="text" ' +
    'id="q" name="q" value="' + xmlEscape(wantedText) +
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
        : 'Nothing yet, and nothing will appear by itself: unlike every ' +
          'other container here, this one is CONFIGURED. Add a relationship ' +
          'on <a href="/admin/federation">/admin/federation</a> or through ' +
          '<code>POST /admin-api/federation/create</code>.') +
      '</td></tr>') +
    '</table>' +
    nav.foot +
    '<h2>The two directions</h2>' +
    '<table><tr><th>Role</th><th>What it means</th></tr>' +
    federation.ROLES.map(function (one) {
      return '<tr><td>' + xmlEscape(one.short) + '</td><td>' +
        xmlEscape(one.what) +
        '</td></tr>';
    }).join('') + '</table>' +
    '<h2>The five protocols</h2>' +
    '<table><tr><th>Protocol</th><th>What happens</th><th>Needs</th></tr>' +
    federation.PROTOCOLS.map(function (one) {
      return '<tr><td>' + xmlEscape(one.label) + '</td><td>' +
        xmlEscape(one.what) +
        '</td><td><code>' + xmlEscape(one.needs.join(
            ', ')) + '</code></td></tr>';
    }).join('') + '</table>' +
    '<h2>The object classes</h2>' +
    '<table><tr><th>Class</th><th>Where from</th><th>What it brings</th></tr>' +
    classRows + '</table>' +
    '<h2>The attributes</h2>' +
    admin.note('<code>multi</code> accumulates a repeat, <code>single</code> ' +
    'is assigned. The <code>role</code> column says which direction an ' +
    'attribute is for; one belonging to the other direction is refused by ' +
    'the console and by the management API, and an <code>ldapmodify</code> ' +
    'can still write it, where it will be ignored. ' +
    '<code>fedClientSecret</code> is THIS SERVICE\'S OWN CREDENTIAL AT THE ' +
    'PARTNER &mdash; a real secret at a real foreign service, which is a ' +
    'stronger statement than anything else in this directory &mdash; and it ' +
    'is here in the clear for the reason <code>/krb5/principals</code> ' +
    'prints the Kerberos passwords. It is never written to the audit log and ' +
    'never shown in the console.') +
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
// GET /admin/ldap/roles — the role register as the directory sees it.
//
// The fourth container page, and the three above it establish the shape: a
// container of entries carrying invented attribute names needs somewhere to
// say what they mean, because this directory is schemaless and a client
// reading one back is otherwise guessing.
//
// IT SAYS TWO THINGS `/admin/roles` DOES NOT HAVE TO, and both are properties
// of the CONTAINER rather than of the feature:
//
//   * **HALF THE FEATURE IS NOT IN HERE.** A role has two relations —
//     MEMBERSHIP, which is on the role entry and is what this container
//     holds, and REQUIREMENT, which is `appRequiredRole` on an APPLICATION
//     entry under `ou=applications`. A reader looking at `ou=roles` for the
//     reason somebody was refused would find nothing that refuses anybody,
//     and would be looking at the wrong container rather than at a broken
//     one. `common/roles.js` argues why they are kept apart.
//   * **THE SIX BUILT-IN ROLES ARE IN NO CONTAINER AT ALL.** They are
//     computed from the context of the decision being made, so `EVERYBODY`
//     has no entry here and never will. An empty `ou=roles` is therefore the
//     ordinary state of a service that is deciding every issuance against
//     `EVERYBODY` and refusing nobody — which is what this service does
//     before anybody configures anything, and is exactly the state that looks
//     like the feature not being loaded.
//
// AN ldapmodify HERE GRANTS A ROLE. The entries are the register and nothing
// caches them, so adding a value to `roleMemberUser` is answered by the very
// next issuance decision. That is one of the two halves of a refusal; the
// other is on the application entry.
// ---------------------------------------------------------------------------
function ldapRolesView(req) {
  log.debug('Entering ldapRolesView().');
  const all = allRoles();
  const wantedText = String(req.query.q || '').trim();
  const needle = wantedText.toLowerCase();
  const filtered = all.filter(function (row) {
    if (!needle) {
      return true;
    }
    if (String(row.name).toLowerCase().indexOf(needle) >= 0 ||
        String(row.dn || '').toLowerCase().indexOf(needle) >= 0) {
      return true;
    }
    // The VALUES too, for the reason the applications page searches them:
    // somebody asking "which role is alice in" has the member's name and not
    // the role's.
    return Object.keys(row.attributes || {}).some(function (name) {
      const value = row.attributes[name];
      const values = Array.isArray(value) ? value : [value];
      return values.some(function (one) {
        return String(one).toLowerCase().indexOf(needle) >= 0;
      });
    });
  });
  const paged = directoryPaging(req, filtered, 'roles');
  const paging = paged.paging;
  const filterParams = { q: wantedText || '', per: perOf(req, paging) };
  const nav = admin.pageNavPair('/admin/ldap/roles', filterParams, paging);

  const payload = {
    baseDn: baseDn(),
    container: rolesDn(),
    count: all.length,
    matched: filtered.length,
    shown: paged.shown.length,
    max: maxRoles(),
    filter: { q: wantedText || null },
    page: paging.page, pages: paging.pages, perPage: paging.perPage,
    firstRow: paging.firstRow, lastRow: paging.lastRow,
    sourceOfTruth: 'These entries ARE the membership half of the role ' +
      'register. An ldapmodify adding a value to roleMemberUser grants that ' +
      'role, and the next issuance decision is made against it. What ' +
      'REQUIRES a role is appRequiredRole on an application entry under ' +
      'ou=applications, which is a different container.',
    builtIn: roles.BUILT_IN_NAMES,
    schema: roles.SCHEMA,
    roles: paged.shown
  };

  const roleRows = paged.shown.map(function (row) {
    const attrs = Object.keys(row.attributes).sort().map(function (name) {
      return '<div><code>' + xmlEscape(name) + '</code>: ' +
        admin.clippedValues(row.attributes[name]) + '</div>';
    }).join('');
    const held = function (name) {
      log.debug("Entering held().");
      const value = row.attributes[name];
      if (!value) {
        log.debug("Leaving held().");
        return 0;
      }
      log.debug("Leaving held().");
      return Array.isArray(value) ? value.length : 1;
    };
    return '<tr><td>' + admin.clipped(row.name, 40) +
      (row.dn ? '<div class="sub">' + admin.clipped(row.dn, 40) + '</div>' :
       '') +
      '</td><td class="counts">' + held('roleMemberUser') + ' user(s)<br>' +
      held('roleMemberGroup') + ' group(s)<br>' +
      held('roleMemberApplication') + ' application(s)</td>' +
      '<td class="attrs">' + attrs + '</td></tr>';
  }).join('');
  const classRows = roles.SCHEMA.objectClasses.map(function (one) {
    return '<tr><td><code>' + xmlEscape(one.name) + '</code></td><td>' +
      xmlEscape(one.what) + '</td></tr>';
  }).join('');
  const attrRows = roles.SCHEMA.attributes.map(function (row) {
    return '<tr><td><code>' + xmlEscape(row.name) + '</code></td><td>' +
      xmlEscape(row.what) + '</td></tr>';
  }).join('');
  const builtInRows = roles.builtInCatalogue().map(function (one) {
    return '<tr><td><code>' + xmlEscape(one.name) + '</code></td><td>' +
      xmlEscape(one.what || one.description || '') + '</td></tr>';
  }).join('');

  const inner = '<p class="sub">' + all.length + ' of a maximum ' +
    maxRoles() + ' under <code>' + xmlEscape(rolesDn()) +
    '</code>: one entry per role, and everything on it is MEMBERSHIP — who ' +
    'holds it. A person, a group and an application are all first-class ' +
    'members, which is what lets a client_credentials grant with no person ' +
    'in it be decided at all.</p><div class="tiles">' +
    admin.tile(all.length, 'Role entries') +
    admin.tile(roles.BUILT_IN_NAMES.length, 'Built in, in no container') +
    admin.tile(maxRoles(), 'Maximum held') +
    '</div>' +
    admin.note('<strong>Half the feature is not in this container.</strong> ' +
    'A role has two relations and they live apart on purpose: MEMBERSHIP is ' +
    'here, and the REQUIREMENT — which roles an application demands before ' +
    'anything is issued for it — is <code>appRequiredRole</code> on the ' +
    'application\'s own entry under <code>ou=applications</code>. So nothing ' +
    'in this container refuses anybody by itself, and a reader looking here ' +
    'for the reason somebody was turned away is one container across from ' +
    'it. <a href="/admin/roles">Roles</a> is the page with both halves and ' +
    'the controls on it; <a href="/admin/ldap/applications">Application ' +
    'entries</a> is where the other half is stored.') +
    '<form method="get" action="/admin/ldap/roles"><div class="formrow">' +
    '<label for="q">Anywhere in the entry</label>' +
    '<input type="text" id="q" name="q" value="' + xmlEscape(wantedText) +
    '" size="30" placeholder="a role name, a DN, or a member">' +
    '<label for="per">Show</label>' +
    '<select id="per" name="per">' +
    admin.perPageOptions(paging.perPage) + '</select>' +
    '<button type="submit">Filter</button>' +
    (wantedText ? ' <a href="/admin/ldap/roles">clear</a>' : '') +
    '</div></form>' +
    nav.head +
    '<table><tr><th>Role</th><th>Who holds it</th>' +
    '<th>Every attribute</th></tr>' +
    (roleRows || '<tr><td colspan="3">' +
      (wantedText
        ? 'No role matches. The filter above may be hiding some.'
        : 'Nothing yet, which is the ORDINARY state rather than an empty ' +
          'one: an application that names no required role requires ' +
          'EVERYBODY, everybody holds EVERYBODY, and nothing is refused. ' +
          'A role is made on the Roles page or through POST ' +
          '/admin-api/roles/create-role.') +
      '</td></tr>') +
    '</table>' +
    nav.foot +
    '<h2>The six that are in no container</h2>' +
    admin.note('These are COMPUTED from the context of the decision being ' +
    'made rather than stored, so they have no entry here, no members to ' +
    'list, and cannot be created, edited or deleted. They are the reason an ' +
    'empty container above is not the feature being switched off: ' +
    '<code>EVERYBODY</code> is what an application requires when its entry ' +
    'names nothing, and everybody holds it.') +
    '<table><tr><th>Role</th><th>Who holds it</th></tr>' +
    builtInRows + '</table>' +
    '<h2>The object classes</h2>' +
    admin.note('node-ldapjs has no schema subsystem and this directory is ' +
    'schemaless on purpose, so this is a VOCABULARY rather than a ' +
    'constraint: nothing rejects an entry for disobeying it.') +
    '<table><tr><th>Class</th><th>What it brings</th></tr>' +
    classRows + '</table>' +
    '<h2>The attributes</h2>' +
    '<table><tr><th>Attribute</th><th>What it is</th></tr>' + attrRows +
    '</table>' +
    '<p class="sub"><a href="/admin/ldap/roles?format=json">This page as ' +
    'JSON</a> &middot; <a href="/admin/roles">the same register with the ' +
    'controls on it</a> &middot; <a href="/admin/ldap/directory">every entry ' +
    'in the directory</a> &middot; <a href="/admin/ldap/service">what this ' +
    'directory is</a></p>';

  log.debug('Leaving ldapRolesView(). ' + paged.shown.length +
            ' row(s) of ' + filtered.length + ' matched.');
  return { title: 'Role entries', inner: inner, json: payload };
}

app.get('/admin/ldap/roles', function (req, res) {
  log.debug('Entering GET /admin/ldap/roles.');
  const view = ldapRolesView(req);
  admin.respond(req, res, view.json, view.title, '/admin/ldap/roles',
                view.inner);
  log.debug('Leaving GET /admin/ldap/roles.');
});

// ---------------------------------------------------------------------------
// GET /admin/ldap/policies — the XACML policy repository as the directory
// sees it.
//
// `ou=policies` IS the repository, the way `ou=federations` is the federation
// register, and this page is the one place that says so in the directory's own
// terms.
//
// **AN ldapmodify HERE IS NOT VALIDATED, AND THAT IS THE SENTENCE THIS PAGE
// EXISTS FOR.** Every write through `/admin/xacml` and `/admin-api/xacml`
// goes through `xacml_store.js`, which parses the document and STATICALLY
// TYPECHECKS it — a policy that does not typecheck is refused at write time
// rather than going Indeterminate on every request, which is a decision this
// family made on purpose and tests. A write over LDAP reaches the entry
// directly and skips all of it. Nothing caches these entries, so the very next
// request is decided against whatever was written, and a document that no
// longer typechecks answers Indeterminate — which a PEP with a deny bias turns
// into a refusal of everybody and a PEP with a permit bias turns into the
// opposite.
// ---------------------------------------------------------------------------
function ldapPoliciesView(req) {
  log.debug('Entering ldapPoliciesView().');
  const all = allPolicies();
  const wantedText = String(req.query.q || '').trim();
  const needle = wantedText.toLowerCase();
  const filtered = all.filter(function (row) {
    if (!needle) {
      return true;
    }
    if (String(row.name).toLowerCase().indexOf(needle) >= 0 ||
        String(row.dn || '').toLowerCase().indexOf(needle) >= 0) {
      return true;
    }
    // Including the DOCUMENT, which is where a rule's own identifier lives:
    // somebody looking for the policy that names a particular resource has
    // the resource and not the policy's name.
    return Object.keys(row.attributes || {}).some(function (name) {
      const value = row.attributes[name];
      const values = Array.isArray(value) ? value : [value];
      return values.some(function (one) {
        return String(one).toLowerCase().indexOf(needle) >= 0;
      });
    });
  });
  const paged = directoryPaging(req, filtered, 'policies');
  const paging = paged.paging;
  const filterParams = { q: wantedText || '', per: perOf(req, paging) };
  const nav = admin.pageNavPair('/admin/ldap/policies', filterParams, paging);

  const first = function (row, name) {
    log.debug("Entering first().");
    const value = (row.attributes || {})[name];
    if (!value) {
      log.debug("Leaving first().");
      return '';
    }
    log.debug("Leaving first().");
    return String(Array.isArray(value) ? value[0] : value);
  };

  const payload = {
    baseDn: baseDn(),
    container: policiesDn(),
    count: all.length,
    matched: filtered.length,
    shown: paged.shown.length,
    max: maxPolicies(),
    filter: { q: wantedText || null },
    page: paging.page, pages: paging.pages, perPage: paging.perPage,
    firstRow: paging.firstRow, lastRow: paging.lastRow,
    sourceOfTruth: 'These entries ARE the policy repository. An ldapmodify ' +
      'of xacmlPolicyDocument changes what the PDP decides on the very next ' +
      'request and is NOT statically validated on the way in, unlike every ' +
      'write through /admin/xacml — so a document that stops typechecking ' +
      'answers Indeterminate rather than being refused.',
    schema: xacmlStore.SCHEMA,
    policies: paged.shown
  };

  const policyRows = paged.shown.map(function (row) {
    const attrs = Object.keys(row.attributes).sort().map(function (name) {
      return '<div><code>' + xmlEscape(name) + '</code>: ' +
        admin.clippedValues(row.attributes[name]) + '</div>';
    }).join('');
    // 'FALSE' AND 'TRUE', not 'false' and 'true'. RFC 4517's Boolean syntax
    // is upper case and `xacml_store.js` writes it that way, so this reads it
    // the way that module reads it — `at('xacmlEnabled') !== 'FALSE'` — rather
    // than inventing a third spelling. The lower-case comparison this replaced
    // drew every DISABLED policy as enabled, which is the direction that
    // matters: a page that overstates what is switched on.
    const enabled = first(row, 'xacmlEnabled') !== 'FALSE';
    const isRoot = first(row, 'xacmlIsRoot') === 'TRUE';
    return '<tr><td>' + admin.clipped(row.name, 40) +
      (row.dn ? '<div class="sub">' + admin.clipped(row.dn, 40) + '</div>' :
       '') +
      '</td><td>' + xmlEscape(first(row, 'xacmlKind') || '(unstated)') +
      '<div class="sub">' + admin.clipped(first(row, 'xacmlPolicyId'), 40) +
      '</div></td><td>' +
      (enabled ? '<span class="state-valid">enabled</span>'
               : '<span class="state-none">disabled</span>') +
      (isRoot ? '<div class="sub">the root</div>' : '') +
      '</td><td class="attrs">' + attrs + '</td></tr>';
  }).join('');
  const classRows = xacmlStore.SCHEMA.objectClasses.map(function (one) {
    return '<tr><td><code>' + xmlEscape(one.name) + '</code></td><td>' +
      xmlEscape(one.what) + '</td></tr>';
  }).join('');
  const attrRows = xacmlStore.SCHEMA.attributes.map(function (row) {
    return '<tr><td><code>' + xmlEscape(row.name) + '</code></td><td>' +
      xmlEscape(row.what) + '</td></tr>';
  }).join('');

  const inner = '<p class="sub">' + all.length + ' of a maximum ' +
    maxPolicies() + ' under <code>' + xmlEscape(policiesDn()) +
    '</code>: one entry per policy or policy set, holding the XACML document ' +
    'itself. Exactly one of them is the ROOT — a PDP evaluates one document ' +
    'and reaches the rest through PolicyIdReference.</p>' +
    '<div class="tiles">' +
    admin.tile(all.length, 'Policy entries') +
    admin.tile(all.filter(function (row) {
      return first(row, 'xacmlEnabled') !== 'FALSE';
    }).length, 'Enabled') +
    admin.tile(maxPolicies(), 'Maximum held') +
    '</div>' +
    admin.warn('<strong>A write here skips the typechecker, which is not ' +
    'true of any other door into this repository.</strong> Every write ' +
    'through <a href="/admin/xacml">XACML</a> and ' +
    '<code>/admin-api/xacml</code> parses the document and statically ' +
    'typechecks it, so a policy that does not typecheck is refused at WRITE ' +
    'time instead of going Indeterminate on every request. An ' +
    '<code>ldapmodify</code> of <code>xacmlPolicyDocument</code> reaches the ' +
    'entry directly and skips that, and nothing caches these entries — so ' +
    'the next request is decided against whatever was written.') +
    '<form method="get" action="/admin/ldap/policies"><div class="formrow">' +
    '<label for="q">Anywhere in the entry</label>' +
    '<input type="text" id="q" name="q" value="' + xmlEscape(wantedText) +
    '" size="30" placeholder="a name, a DN, a PolicyId or anything in the ' +
    'document"><label for="per">Show</label><select id="per" name="per">' +
    admin.perPageOptions(paging.perPage) + '</select>' +
    '<button type="submit">Filter</button>' +
    (wantedText ? ' <a href="/admin/ldap/policies">clear</a>' : '') +
    '</div></form>' +
    nav.head +
    '<table><tr><th>Policy</th><th>Kind</th><th>State</th>' +
    '<th>Every attribute</th></tr>' +
    (policyRows || '<tr><td colspan="4">' +
      (wantedText
        ? 'No policy matches. The filter above may be hiding some.'
        : 'Nothing yet. A repository with no policies in it answers ' +
          'NotApplicable to every request, which a PEP turns into a refusal ' +
          'or an allow according to its bias.') +
      '</td></tr>') +
    '</table>' +
    nav.foot +
    '<h2>The object classes</h2>' +
    admin.note('node-ldapjs has no schema subsystem and this directory is ' +
    'schemaless on purpose, so this is a VOCABULARY rather than a ' +
    'constraint: nothing rejects an entry for disobeying it.') +
    '<table><tr><th>Class</th><th>What it brings</th></tr>' +
    classRows + '</table>' +
    '<h2>The attributes</h2>' +
    '<table><tr><th>Attribute</th><th>What it is</th></tr>' + attrRows +
    '</table>' +
    '<p class="sub"><a href="/admin/ldap/policies?format=json">This page as ' +
    'JSON</a> &middot; <a href="/admin/xacml">the same repository with the ' +
    'controls on it</a> &middot; <a href="/admin/ldap/peps">the PEPs that ' +
    'pull it</a> &middot; <a href="/admin/ldap/directory">every entry in the ' +
    'directory</a></p>';

  log.debug('Leaving ldapPoliciesView(). ' + paged.shown.length +
            ' row(s) of ' + filtered.length + ' matched.');
  return { title: 'Policy entries', inner: inner, json: payload };
}

app.get('/admin/ldap/policies', function (req, res) {
  log.debug('Entering GET /admin/ldap/policies.');
  const view = ldapPoliciesView(req);
  admin.respond(req, res, view.json, view.title, '/admin/ldap/policies',
                view.inner);
  log.debug('Leaving GET /admin/ldap/policies.');
});

// ---------------------------------------------------------------------------
// GET /admin/ldap/peps — the registered remote Policy Enforcement Points.
//
// The SPIFFE page's closest relative in this directory, and for the same
// reason: **almost everything in this container is a RECORD of what happened
// rather than configuration somebody typed.** A PEP registers itself, and its
// identity is taken from the CLIENT CERTIFICATE it presented and never from
// the body it sent — which is the one defect in that family that would have
// been a security bug, and is why `xacmlPepCertificateSubject` and
// `xacmlPepThumbprint` are on the entry at all.
//
// TWO ATTRIBUTES ARE NOT A RECORD AND AN ldapmodify OF EITHER IS A REAL
// CHANGE: `xacmlPepEnabled` is an administrator's decision and a PEP that
// reconnects does NOT clear it, and `xacmlPepNotifyUrl` is one of the three
// addresses this service will dial. Everything else — the counters, the last
// seen, the sync token — is written by this service as PEPs come and go.
//
// **AN EMPTY CONTAINER IS NOT A FEATURE THAT IS OFF.** A remote PEP pulls
// `GET /xacml/pep/policies` and converges without registering at all;
// registering is what buys it the nudge and a row on the console. So policy
// distribution can be working perfectly with nothing in here.
// ---------------------------------------------------------------------------
function ldapPepsView(req) {
  log.debug('Entering ldapPepsView().');
  const all = allPeps();
  const wantedText = String(req.query.q || '').trim();
  const needle = wantedText.toLowerCase();
  const filtered = all.filter(function (row) {
    if (!needle) {
      return true;
    }
    if (String(row.name).toLowerCase().indexOf(needle) >= 0 ||
        String(row.dn || '').toLowerCase().indexOf(needle) >= 0) {
      return true;
    }
    return Object.keys(row.attributes || {}).some(function (name) {
      const value = row.attributes[name];
      const values = Array.isArray(value) ? value : [value];
      return values.some(function (one) {
        return String(one).toLowerCase().indexOf(needle) >= 0;
      });
    });
  });
  const paged = directoryPaging(req, filtered, 'peps');
  const paging = paged.paging;
  const filterParams = { q: wantedText || '', per: perOf(req, paging) };
  const nav = admin.pageNavPair('/admin/ldap/peps', filterParams, paging);

  const first = function (row, name) {
    log.debug("Entering first().");
    const value = (row.attributes || {})[name];
    if (!value) {
      log.debug("Leaving first().");
      return '';
    }
    log.debug("Leaving first().");
    return String(Array.isArray(value) ? value[0] : value);
  };

  const payload = {
    baseDn: baseDn(),
    container: pepsDn(),
    count: all.length,
    matched: filtered.length,
    shown: paged.shown.length,
    max: maxPeps(),
    filter: { q: wantedText || null },
    page: paging.page, pages: paging.pages, perPage: paging.perPage,
    firstRow: paging.firstRow, lastRow: paging.lastRow,
    sourceOfTruth: 'Almost every attribute here is a RECORD this service ' +
      'wrote as a PEP registered, pulled or reported. The two that are not ' +
      'are xacmlPepEnabled, which an administrator sets and a reconnecting ' +
      'PEP does not clear, and xacmlPepNotifyUrl, which is one of the three ' +
      'addresses this service dials.',
    schema: xacmlPepRegistry.SCHEMA,
    peps: paged.shown
  };

  const pepRows = paged.shown.map(function (row) {
    const attrs = Object.keys(row.attributes).sort().map(function (name) {
      return '<div><code>' + xmlEscape(name) + '</code>: ' +
        admin.clippedValues(row.attributes[name]) + '</div>';
    }).join('');
    // 'FALSE', for the reason the policies page above states.
    const enabled = first(row, 'xacmlPepEnabled') !== 'FALSE';
    return '<tr><td>' + admin.clipped(row.name, 40) +
      (row.dn ? '<div class="sub">' + admin.clipped(row.dn, 40) + '</div>' :
       '') +
      '</td><td>' + admin.clipped(first(row, 'xacmlPepCertificateSubject') ||
        '(no client certificate)', 40) +
      '<div class="sub">' +
      admin.clipped(first(row, 'xacmlPepThumbprint'), 24) +
      '</div></td><td>' +
      (enabled ? '<span class="state-valid">enabled</span>'
               : '<span class="state-none">disabled by an administrator</span>') +
      '<div class="sub">' + xmlEscape(first(row, 'xacmlPepLastSeen') ||
        'never seen') + '</div></td>' +
      '<td class="counts">' +
      xmlEscape(first(row, 'xacmlPepDecisions') || '0') +
      ' decision(s)<br>' + xmlEscape(first(row, 'xacmlPepAllowed') || '0') +
      ' allowed<br>' + xmlEscape(first(row, 'xacmlPepRefused') || '0') +
      ' refused</td>' +
      '<td class="attrs">' + attrs + '</td></tr>';
  }).join('');
  const classRows = xacmlPepRegistry.SCHEMA.objectClasses.map(function (one) {
    return '<tr><td><code>' + xmlEscape(one.name) + '</code></td><td>' +
      xmlEscape(one.what) + '</td></tr>';
  }).join('');
  const attrRows = xacmlPepRegistry.SCHEMA.attributes.map(function (row) {
    return '<tr><td><code>' + xmlEscape(row.name) + '</code></td><td>' +
      xmlEscape(row.what) + '</td></tr>';
  }).join('');

  const inner = '<p class="sub">' + all.length + ' of a maximum ' +
    maxPeps() + ' under <code>' + xmlEscape(pepsDn()) +
    '</code>: the remote Policy Enforcement Points that have registered with ' +
    'this PDP. Each holds its own copy of the engine, pulls the policy ' +
    'repository, and decides in its own process.</p>' +
    '<div class="tiles">' +
    admin.tile(all.length, 'Registered PEPs') +
    admin.tile(all.filter(function (row) {
      return first(row, 'xacmlPepEnabled') !== 'FALSE';
    }).length, 'Enabled') +
    admin.tile(maxPeps(), 'Maximum held') +
    '</div>' +
    admin.note('<strong>An empty container is not a feature that is ' +
    'off.</strong> A remote PEP pulls <code>GET /xacml/pep/policies</code> ' +
    'and converges whether or not it ever registers; registering is what ' +
    'buys it the change nudge and a row here. And an identity in this ' +
    'container was taken from the CLIENT CERTIFICATE the PEP presented, ' +
    'never from the body it sent — so a PEP cannot name itself anything it ' +
    'cannot prove. <a href="/admin/xacml/peps">XACML PEPs</a> is the page ' +
    'with the controls on it.') +
    '<form method="get" action="/admin/ldap/peps"><div class="formrow">' +
    '<label for="q">Anywhere in the entry</label>' +
    '<input type="text" id="q" name="q" value="' + xmlEscape(wantedText) +
    '" size="30" placeholder="a name, a DN, a certificate subject or a URL">' +
    '<label for="per">Show</label>' +
    '<select id="per" name="per">' +
    admin.perPageOptions(paging.perPage) + '</select>' +
    '<button type="submit">Filter</button>' +
    (wantedText ? ' <a href="/admin/ldap/peps">clear</a>' : '') +
    '</div></form>' +
    nav.head +
    '<table><tr><th>PEP</th><th>What it proved</th><th>State</th>' +
    '<th>What it has decided</th><th>Every attribute</th></tr>' +
    (pepRows || '<tr><td colspan="5">' +
      (wantedText
        ? 'No PEP matches. The filter above may be hiding some.'
        : 'Nothing has registered. Policy distribution is unaffected: a PEP ' +
          'that pulls GET /xacml/pep/policies without registering converges ' +
          'on the same repository and appears nowhere.') +
      '</td></tr>') +
    '</table>' +
    nav.foot +
    '<h2>The object classes</h2>' +
    admin.note('node-ldapjs has no schema subsystem and this directory is ' +
    'schemaless on purpose, so this is a VOCABULARY rather than a ' +
    'constraint: nothing rejects an entry for disobeying it.') +
    '<table><tr><th>Class</th><th>What it brings</th></tr>' +
    classRows + '</table>' +
    '<h2>The attributes</h2>' +
    '<table><tr><th>Attribute</th><th>What it is</th></tr>' + attrRows +
    '</table><p class="sub"><a href="/admin/ldap/peps?format=json">This page ' +
    'as JSON</a> &middot; <a href="/admin/xacml/peps">the same registry with ' +
    'the controls on it</a> &middot; <a href="/admin/ldap/policies">what ' +
    'they pull</a> &middot; <a href="/admin/ldap/directory">every entry in ' +
    'the directory</a></p>';

  log.debug('Leaving ldapPepsView(). ' + paged.shown.length +
            ' row(s) of ' + filtered.length + ' matched.');
  return { title: 'PEP entries', inner: inner, json: payload };
}

app.get('/admin/ldap/peps', function (req, res) {
  log.debug('Entering GET /admin/ldap/peps.');
  const view = ldapPepsView(req);
  admin.respond(req, res, view.json, view.title, '/admin/ldap/peps',
                view.inner);
  log.debug('Leaving GET /admin/ldap/peps.');
});

// ---------------------------------------------------------------------------
// THE NINTH SLOT ON admin.js, FILLED HERE.
//
// `mgmt-api/admin_api.js` mirrors every page of the console (rule 7) and sits
// two positions ABOVE this module in the require order, so it cannot require
// this file to reach these eight views without dragging every route registered
// here ahead of its own.
//
// THREE OF THE EIGHT ARRIVED ON 2026-09-05 and they are the reason to read this
// block rather than assume it. `ou=roles`, `ou=policies` and `ou=peps` each had
// a published SCHEMA in its owning module and no page publishing it — three
// copies of a comment claiming a page that did not exist, from three different
// weeks. They are drawn HERE, beside the other five, because this module
// already requires all three of those modules to fill their own
// `setDirectory()` slots: the schemas are already in scope, so the pages cost
// no new require, close no cycle and move no route. The slot is the way across;
// see the block above `setDirectoryPages()` in `admin.js` for the argument, and
// the guard below is the one every other install in this file uses — an older
// copy of `admin.js` (the parent project's) costs a warning rather than a crash
// at require time.
// ---------------------------------------------------------------------------
if (typeof admin.setDirectoryPages === 'function') {
  admin.setDirectoryPages({
    service: ldapServiceView,
    directory: ldapDirectoryView,
    applications: ldapApplicationsView,
    federations: ldapFederationsView,
    spiffe: ldapSpiffeView,
    roles: ldapRolesView,
    policies: ldapPoliciesView,
    peps: ldapPepsView
  });
} else {
  log.warn('ldap: this copy of admin-ui/admin.js offers no ' +
           'setDirectoryPages() slot, so /admin-api will not mirror the ' +
           'eight directory pages. The pages themselves are unaffected.');
}

function listen() {
  log.debug('Entering listen().');
  const whenPlain = new Promise(function (resolve, reject) {
    // -------------------------------------------------------------------
    // THE PLAIN LISTENER CAN BE LEFT UNBOUND (2026-09-12),
    // `ldap.plainListener`.
    //
    // It always started. A simple bind on 389 carries its password in the
    // clear, which did not matter while no bind was checked; in product mode
    // every bind IS checked against the person's own `userPassword`, so that
    // socket hands a real credential to anybody on the path. Off leaves LDAPS
    // as the only way in. It RESOLVES rather than rejecting, with the reason
    // recorded where a bind failure's would be, because a listener somebody
    // switched off is not a directory that failed to start — and
    // `GET /admin/ldap/service` then says which of the two it was.
    //
    // Product mode with it ON is allowed and WARNED about, rather than refused:
    // a deployment terminating LDAP inside a private network may accept the
    // trade, and the warning names the setting that ends it.
    // -------------------------------------------------------------------
    if (!config.value('ldap.plainListener')) {
      listening = false;
      listenError = 'not started: ldap.plainListener is off, so this ' +
        'directory answers over LDAPS only';
      log.info('ldap: the plain listener on ' + LDAP_PORT + ' was NOT ' +
               'started (ldap.plainListener is off); LDAPS ' +
               'on ' + LDAPS_PORT + ' is ' +
               'the only way in.');
      resolve({ port: null, baseDn: ROOT_DN, plainListener: false });
      return;
    }
    if (mode.verifiesCredentials()) {
      // Refused rather than merely warned about since 2026-09-12: a bind on
      // this listener is answered confidentialityRequired before its password
      // is read. The listener still answers the root DSE, and a client that
      // sends a password here has still sent it in the clear — which is what
      // this line is left to say.
      log.warn('ldap: product mode refuses every bind on the plain listener on ' +
               LDAP_PORT + ' (confidentialityRequired) and every read that ' +
               'has not bound, so it answers nothing but the root DSE — and ' +
               'a client that sends a password to it has still sent that ' +
               'password IN THE CLEAR. Set ldap.plainListener ' +
               '(LDAP_PLAIN_LISTENER) to false to answer over LDAPS ' +
               'on ' + LDAPS_PORT + ' only.');
    }
    // THE PROXY PROTOCOL (2026-09-14): on ldapjs's own net.Server, so the
    // connection ldapjs builds its `c.ldap.id` from, the bind limiter and the
    // audit all read the header's address. A no-op when it is off.
    proxyProtocol.install(plainServer.server, {
      label: 'LDAP (' + LDAP_PORT + ')', channel: 'ldap' });
    plainServer.listen(LDAP_PORT, ldapListenHost(), function () {
      const address = plainServer.address();
      boundPort = address ? address.port : LDAP_PORT;
      listening = true;
      listenError = '';
      // ROOT_DN: what this SOCKET serves. A realm's subtree is under it and is
      // reported per realm on GET /admin/ldap/service, which does have a realm.
      log.info('ldap: listening on TCP ' + boundPort + ' with base DN ' +
               ROOT_DN + '; ' + totalEntries() +
               ' entry/entries across ' + realms.count() + ' trust realm(s), ' +
               'each with a directory of its own; GET /admin/ldap/service ' +
               'describes it.');
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
      log.error(errorCodes.tag('STS-LDAP-0027') +
                'ldap: could not bind TCP ' + LDAP_PORT + ': ' + listenError +
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
  // started. It is recorded, logged, and published on GET /admin/ldap/service —
  // the same treatment a failure on 389 gets, minus the rejection.
  const whenSecure = new Promise(function (resolve) {
    if (!secureServer) {
      // No certificate material. Already logged and recorded where that was
      // discovered; this only has to answer.
      resolve({ ldapsPort: null, ldapsListening: false,
                ldapsError: tlsListenError });
      return;
    }
    // -------------------------------------------------------------------
    // RE-READ THE CERTIFICATE BEFORE BINDING (2026-09-11).
    //
    // The record above was taken at REQUIRE time, and this module is required
    // at 21 — before `pki.start()`, which is what certifies the listener
    // certificate under this service's own Root and REPLACES it on
    // `tls_server.js`'s record. So 636 would present the self-signed
    // certificate this process threw away, while 8443, 9443 and the main port
    // presented the certified one: "one anchor covers all four" said on this
    // module's own page, and false on the one socket it is about.
    //
    // The chain goes with it for the reason `tls_server.js`'s
    // `secureContextOptions()` gives — a client holding only the Root cannot
    // build a path without the two certificates between them, and the failure
    // is `unable to get local issuer certificate`, which names nothing.
    //
    // `setSecureContext()` rather than a second `createServer()`: the handlers
    // were registered on this server object at require time and a new one
    // would have none of them.
    // -------------------------------------------------------------------
    try {
      const current = tlsServer.serverCertificate();
      Object.assign(serverCertificate, current);
      secureServer.server.setSecureContext(Object.assign({
        cert: (current.chainPem && current.chainPem.length)
          ? [current.certPem].concat(current.chainPem).join('')
          : current.certPem,
        key: current.privateKeyPem
      }, tlsProtocolOptions()));
    } catch (e) {
      // The listener still has the context it was built with, so this is a
      // certificate that verifies against a different anchor rather than a
      // directory that does not answer. Named rather than swallowed.
      log.warn(errorCodes.tag('STS-LDAP-0030') +
               'ldap: LDAPS could not be re-keyed with the certificate this ' +
               'service ended up with (' + e.message + '); it is serving the ' +
               'one built at require time, which may not be the one 8443, ' +
               '9443 and the main port present.');
    }
    // Before TLS, on the tls.Server ldapjs built — see the plain listener.
    proxyProtocol.install(secureServer.server, {
      label: 'LDAPS (' + LDAPS_PORT + ')', channel: 'ldaps' });
    secureServer.listen(LDAPS_PORT, ldapListenHost(), function () {
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
      log.error(errorCodes.tag('STS-LDAP-0028') +
                'ldap: could not bind TCP ' + LDAPS_PORT + ' for LDAPS: ' +
                tlsListenError + '. The plain listener and everything else ' +
                'in this service are unaffected; set LDAPS_PORT to a free, ' +
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
  // WHAT A CREATE TAKES, CLAIMED ACROSS NODES (#46 section 3), for the SCIM
  // and management-API doors. See `directory_create_claims.js`.
  claimCreate: claimCreate,
  // THE ENTRY UUID (2026-09-14): the lookups a person's `sub` and a SCIM id
  // go through, exported for SCIM and for the tests.
  entryByUuid: entryByUuid,
  entryUuidOf: entryUuidOf,
  mergeCreateRace: mergeCreateRace,
  dnForResourceId: dnForResourceId,
  resourceIdOfDn: resourceIdOfDn,
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
  // ---------------------------------------------------------------------
  // THE OPERATION CODEC, EXPORTED FOR `tests/ldap_operations.js` AND FOR
  // NOTHING ELSE IN THE SERVICE.
  //
  // The socket reaches these through the wrapper installed at registration and
  // a worker reaches `performOperation()` through the table it registered, so
  // no module here calls any of them. They are exported because the claim they
  // carry — that a dispatched operation is the same answer — can only be
  // checked by running both halves against each other, and a test that reached
  // into the closure instead would be a test of a copy.
  //
  // `localHandler()` is a FUNCTION rather than the table itself, so that a
  // caller cannot install one: `LOCAL_HANDLERS` is what a worker runs, and a
  // handle on it would be a second door onto the seven handlers.
  // ---------------------------------------------------------------------
  dispatchableOperations: function () {
    log.debug("Entering dispatchableOperations().");
    log.debug("Leaving dispatchableOperations().");
    return DISPATCHABLE_OPERATIONS.slice(0);
  },
  // Exported so that `tests/ldap_operations.js` can drive the registration in
  // the one state it happens in — a request worker — without forking one. It
  // is idempotent (a kind already registered is skipped), which is what makes
  // calling it a second time safe rather than a throw.
  registerWorkerOperations: registerWorkerOperations,
  localHandler: function (operation) {
    log.debug("Entering localHandler().");
    log.debug("Leaving localHandler().");
    return LOCAL_HANDLERS[operation];
  },
  operationRequest: operationRequest,
  operationContext: operationContext,
  performOperation: performOperation,
  applyOperationResult: applyOperationResult,
  ldapErrorNamed: ldapErrorNamed,
  // The live connections, and the only sign-out LDAP has. Read by
  // ../logout/logout.js, which requires this module in the ordinary direction:
  // server.js loads it long before that one, so the require moves no route and
  // closes no cycle, and rule 3e's test therefore asks for no slot. See the
  // block above boundConnections().
  boundConnections: boundConnections,
  dropConnectionsFor: dropConnectionsFor,
  // This node's connections alone, and the door a socket is held through —
  // the second for tests/ldap_cluster_signout.js, which hands it a socket
  // without binding a port. See the block above boundConnections().
  localBoundConnections: localBoundConnections,
  holdSocket: holdSocket,
  // A global sign-out's instruction to every other node, whether or not this
  // process listed anything for the identity (logout.js's terminate()). Null
  // outside active-active. See ldap_cluster_connections.js.
  signOutAcrossCluster: function (key) {
    log.debug("Entering signOutAcrossCluster().");
    log.debug("Leaving signOutAcrossCluster().");
    return clusterConnections.instructSignOut(key);
  },
  clusterConnectionsReport: function () {
    log.debug("Entering clusterConnectionsReport().");
    log.debug("Leaving clusterConnectionsReport().");
    return clusterConnections.report();
  },
  // THE FOUR THAT MAKE BOTH OF THE ABOVE WORK IN A PROCESS THAT HOLDS NO
  // SOCKET (2026-09-09). `setConnectionWatcher()` and `connectionSnapshot()`
  // are the FRONT process's half, filled and read by common/request_pool.js;
  // `setConnectionMirror()` and `setRemoteDropper()` are a request worker's,
  // filled by common/request_worker.js. A process that uses none of them is a
  // process that holds its own listeners and behaves as this module always
  // has. See the block above boundConnections().
  setConnectionWatcher: setConnectionWatcher,
  connectionSnapshot: connectionSnapshot,
  // EXPORTED FOR ONE ASSERTION, and it is the assertion that keeps the whole
  // mechanism honest: that a publish requested from inside a handler is
  // DELIVERED AFTER that handler returns. ldapjs sets the bound DN once the
  // chain is exhausted, so a snapshot taken any earlier belongs to nobody —
  // see publishConnectionsSoon(). tests/ldap_logout.js pins it.
  publishConnectionsSoon: publishConnectionsSoon,
  setConnectionMirror: setConnectionMirror,
  setRemoteDropper: setRemoteDropper,
  // THE ACCOUNT OBSERVER, filled by ssf/risc.js's host ssf/ssf.js at require
  // time. See setAccountObserver()'s header: this is the only direction that
  // works, and it is on the STORE rather than on any one door because the
  // same act reaches this directory over SCIM, over LDAP and from the console.
  setAccountObserver: setAccountObserver,
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
  // The two by-hand doors onto a group, exported for the same reason
  // createUser() is: tests/ drives them in process, with no port and no
  // console, which is where their refusals are asserted.
  createGroup: createGroup,
  addGroupMember: addGroupMember,
  memberDnFor: memberDnFor,
  deleteGroupEntry: deleteGroupEntry,
  // The sweep, so that somebody provisioned over SCIM gets the same credential
  // claim attributes an authenticated person does. Exported rather than called
  // from inside writePerson(), because a batch of fifty creates should sweep
  // once and the caller is what knows the batch is over.
  populateVcAttributes: populateVcAttributes,
  // THE SAME THING FOR ONE ENTRY, which is what every CREATE wants and what
  // the sweep above was being used as. A door that has just written one person
  // calls this; the sweep is for the two callers that mean the whole directory.
  populateVcAttributesAt: populateVcAttributesAt,
  // THIS REALM's entries, not the Map's. See realmEntryCount().
  entryCount: realmEntryCount
};
