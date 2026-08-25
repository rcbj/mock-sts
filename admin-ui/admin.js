'use strict';
//
// File: admin.js
//
// ---------------------------------------------------------------------------
// The admin console: five pages over the state admin_stats.js holds, and one more —
// /admin/groups — over the embedded LDAP directory next door.
//
//   GET  /admin           what the console is, and what it can do to this service
//   GET  /admin/metrics   every call, every artifact, and both kinds of session
//   GET  /admin/users     everyone this service has authenticated; with ?user= it is
//                         one of them, their sessions, and what was issued on each
//   GET  /admin/groups    every group in the embedded LDAP directory; with ?group= it
//                         is one of them, every attribute it has, and everybody in it
//   GET  /admin/tokens    what was issued — every JWT, every SAML assertion and every
//                         Kerberos ticket, filtered and paged — and the buttons that
//                         invalidate the ones that can be
//   POST /admin/tokens    revoke / restore, one token or a whole class of them
//   GET  /admin/audit     what happened here, in order — every authentication,
//                         session, directory operation, console interaction,
//                         management API call and protocol endpoint call, as
//                         rows rather than as counters, filtered and paged
//   GET  /admin/claims    the custom claims every new token will carry
//   POST /admin/claims    add, remove, clear, or replace a whole set
//   GET  /admin/saml-attributes   the same two halves for the two SAML sets
//   POST /admin/saml-attributes   the same seven actions, on those two sets
//
// Every GET also answers `?format=json`, and every POST answers JSON when it was
// sent JSON. That is not decoration: the four tests this repository still owes the
// parent project are plain node scripts driven over HTTP with no browser, and a
// console reachable only by clicking is a console no test can assert against.
//
// **This module renders; it decides nothing.** All the state, all the caps and all
// the rules about what a claim may be called live in admin_stats.js, so a test can
// exercise them without going near an HTML page, and so this file stays the one
// place the markup is. The only thing it reaches for elsewhere is the browser
// sign-on session store, which oauth2.js owns.
//
// **It must therefore come AFTER oauth2.js in server.js**, and that is a dependency
// rather than a preference, the same one wsfed.js has: it reads the `sessions` map
// oauth2.js exports so the metrics page can report real sign-on sessions beside the
// ones derived from what was issued. The dependency is one way — oauth2.js knows
// nothing about this module — so it is not a cycle.
//
// ---------------------------------------------------------------------------
// THIS CONSOLE IS PROTECTED NOW, AND THE OLD PARAGRAPH IS KEPT BELOW BECAUSE
// MOST OF IT IS STILL TRUE.
//
// `admin.authRequired` is ON by default. Every page and every form under /admin
// needs a browser sign-on session from `../authn/authn.js` and one of two roles
// — Admin Read and Admin Write — held as two ordinary groups in the embedded
// directory. The gate is one `app.use('/admin', ...)` further down this file and
// the roles are `./admin_rbac.js`; both have headers of their own.
//
// **IT IS A TURNSTILE AND NOT A LOCK, and that distinction is the same one SCIM's
// authentication carries.** This service still checks no password anywhere — the
// username typed at the sign-in screen simply becomes the identity — so what the
// gate proves is that somebody TYPED a name that holds a role. What it buys is
// what a mock is for: a client, or a person, can now be driven through 302 to a
// sign-in screen, 401 with no session, 403 with the wrong role and a role model
// that can be granted and revoked, none of which was reachable here before.
//
// **AND `/admin-api` IS NOT GATED**, deliberately: it is how a test drives this
// console, it is the way back in when nobody holds a role, and gating it would
// have broken the parent project's `tests/admin_api.js`. So the sentence below
// is still true of this PORT even though it is no longer true of this PAGE —
// which is why it stays rather than being deleted:
//
//   anyone who can reach this port can revoke every token this service has
//   issued and add a claim to every token it issues next. That is fine for a
//   mock on a laptop or on a compose network and is not fine on a public
//   address, which is the same thing that was already true of /oauth2/token —
//   it will mint a token for any username asked of it. Do not put this service
//   on a public address.
//
// Every page says which of the three states it is in (see gateBanner()), because
// "protected" and "protected, but nobody holds a role so anybody who signs in is
// an administrator" are very different things to be reading a console under.
// ---------------------------------------------------------------------------

const app = require('../common/app');
const { log, xmlEscape, baseUrlOf, parseBody, b64uDecode,
        // ONE named realm's signing key, for /admin/realms — which lists every
        // realm's `kid` and is therefore the one page here that needs a key
        // belonging to a realm other than the one it is being read in.
        stsKeysFor } = require('../common/helpers');
const config = require('../common/config');
// TRUST REALMS: the registry behind /admin/realms, and the switcher this shell
// draws on every page. It requires config.js and nothing else here, registers
// no route, and is already loaded by helpers.js — so its position is not a
// position at all.
const realms = require('../common/realms');
const stats = require('../common/admin_stats');
// The browser sign-on sessions, from the authentication service that creates
// them — shared between the OAuth 2.0 / OIDC flow, WS-Federation and SAML 2.0.
//
// **THIS FILE STILL READS THEM AND NEVER ENDS ONE, AND THE REASON CHANGED ON
// 2026-08-24.** It used to be that ending a session from a third place would be
// a third way to get the cleanup wrong: /oauth2/logout and wsignout1.0 each had
// a fan-out written into it, and a console button would have been a third copy
// that quietly notified nobody.
//
// That is no longer the argument, because the fan-outs are now FUNCTIONS rather
// than copies — `wsfed.cleanupTargetsFor()`, `saml2_sso.logoutTargetsFor()` and
// `frontchannel_logout.js`, each owned by the module whose protocol it belongs
// to — and `authn.js`'s `dropSession()` is the single place a session actually
// stops existing. So /admin/logout DOES end sessions, and it ends them through
// exactly those functions.
//
// What is still true is the line this file holds to: this map is READ here and
// written nowhere here. The console's page calls `logout.js`, which calls
// `authn.js`. A `sessions.delete()` in this file would be the fourth way, and
// the one that skipped the RFC 9700 refresh revocation and the audit row.
//
// THREE MORE THINGS COME FROM THAT MODULE NOW, and they are the whole of how
// this console is protected: `consoleSession()` reads the cookie,
// `beginAuthentication()`
// stashes the page somebody asked for and hands back the URL of the sign-in
// screen, and `LOGIN_PATH` is where they are sent. Nothing about signing in is
// implemented here — see the guard below — because a console with a login screen
// of its own would be a second authentication service, and this service has
// exactly one on purpose.
//
// **`consoleSession()` AND NOT `sessionOf()`, AND IT IS THE ONE CALLER OF IT.**
// The protocol reader answers out of the ambient realm's partition, which is
// exactly right for `/oauth2/authorize` and exactly wrong here: the realm
// SWITCHER at the top of every page in this console is a link to the same page
// in another realm, and with the per-realm reader every click on it landed on
// the sign-in screen — then overwrote the browser's only session cookie, so
// clicking back landed there again.
//
// **IT IS THE DEFAULT REALM'S SESSION, ALWAYS**, and that is the second half of
// a decision whose first half is in `ldap_server.js`: the embedded directory is
// per realm since 2026-08-25, so the two console roles are groups in the DEFAULT
// realm's `ou=groups` and nowhere else, and `admin_rbac.js`'s whole directory is
// pinned there. If a session minted in `acme` still opened this console, anybody
// who could create a realm could grant themselves both roles inside it and walk
// back out into the default realm. The gate and the roster have to agree about
// which realm decides, and they do. `authn.js`'s header above `consoleSession()`
// argues it at length, including why this ALSO ends the switcher loop rather
// than merely surviving it.
const { sessions, consoleSession, beginAuthentication, LOGIN_PATH } =
  require('../authn/authn');
// WHO MAY USE THIS CONSOLE. A library (rule 3): it registers no route, so
// requiring it here moves nothing in the router, and it requires only config.js,
// helpers.js and audit.js — none of which requires it back. The two roles it
// decides from are two ORDINARY GROUPS in the embedded directory, which it
// reaches through a slot ldap_server.js fills; see its header for why that is a
// directory group rather than a store of this console's own.
const rbac = require('./admin_rbac');
// The credential claim set: which LDAP attributes an issued Verifiable Credential
// carries, and the invented values behind them. A library like admin_stats.js —
// it registers no route — so requiring it here neither adds to the express router
// nor makes a cycle, and /admin/vc below is the page that sets it. The DIRECTORY
// half of it (populating entries, reading values back) is ldap_server.js's, wired
// into that module through a slot for the route-order reason rule 6 gives.
const vcClaims = require('../oid4vc/vc_claims');
// The other end of that: which of those claims the mock OID4VP Verifier — the
// "bar door" at /oid4vp/verifier — ASKS a wallet for, and in which credential
// format. A library like vc_claims.js and admin_stats.js, registering no route,
// so requiring it here neither moves a route nor makes a cycle; vc_verifier.js
// reads the same module from the other side of the require order.
const vpConfig = require('../oid4vc/vc_verifier_config');
// The THIRD reader of that same catalogue: which LDAP attributes a token or an
// assertion carries, per claim set. A library like the two above, registering no
// route, so requiring it here neither moves a route nor makes a cycle — it
// requires admin_stats.js and vc_claims.js, and neither requires it back. It is
// what turns /admin/claims from a page of typed constants into one that can put
// what the directory says into an access token. See its header for why the
// selection is per-set and why nothing is selected on a fresh start.
const claimAttributes = require('../common/claim_attributes');
// The FOURTH library over that catalogue's territory: which LDAP attribute each
// SCIM member is, in both directions. Read here for the mapping tables on
// /admin/scim, and by scim.js for the conversions themselves. It registers no
// route and requires only helpers.js and vc_claims.js, so requiring it here
// neither moves a route nor makes a cycle — which is exactly why the conversions
// live in a library rather than in scim.js, where a require from this file would
// have dragged every /scim and /ldap route ahead of the console's own.
const scimMap = require('../scim/scim_map');
// The groups claim: which directory groups reach a token, whether it is on, and
// what it would say about one person. A LIBRARY like the line above — it
// registers no route, so requiring it here cannot reorder the router
// /admin/sts-metadata is built by walking, and it requires helpers.js,
// config.js and admin_stats.js, none of which requires this file. It is
// required for the same reason claim_attributes.js is: the page and the
// management API both report this feature, and neither should be reading its
// four settings itself.
const groupClaims = require('../common/group_claims');
// The audit log: what happened here, in order, as rows rather than as counters.
// A library like the three above — it registers no route — so requiring it here
// neither moves a route nor makes a cycle. It holds the events and this file
// renders them at /admin/audit, which is the same split admin_stats.js has and
// for the same reason: a test can walk the log over JSON without going near an
// HTML page.
const auditLog = require('../common/audit');
// The application registry, whose store is the ou=applications container in the
// embedded directory. A library that registers no route, so requiring it from
// the console cannot move anything in the route order — unlike ldap_server.js,
// which is why the user and group readers below are hooks rather than requires.
// Nothing is cached on either side: every read here is a directory read, which
// is what lets this page show an ldapmodify that happened a second ago.
const applications = require('../common/applications');
// The SAML 2.0 Web Browser SSO profile, for the slug rule, the per-application
// entityID and the endpoint URLs — so that /admin/saml2 names the same
// addresses the metadata document publishes rather than rebuilding them here.
// A page that computed its own would be the console and the endpoints
// disagreeing about a URL, which is the failure a service provider meets as a
// 404 that looks like this service being down.
//
// **A PLAIN REQUIRE IN THE ORDINARY DIRECTION, AND NOT A SIXTH SLOT.** Rule
// 3e's test is whether a require would close a cycle or move a route, and this
// one does neither: `server.js` requires `saml/saml2_sso.js` at position 10a
// and this file at 18, so that module's routes are already in the router by the
// time this line runs, and it requires nothing from here.
const saml2 = require('../saml/saml2_sso');
// The SAML 1.1 browser profiles, for the same reason and on the same terms: this
// page must name the endpoints and the providerID that module names, because a
// console that derived a URL of its own would be a console telling somebody to
// configure a path nothing serves. It is required at position 10b in server.js
// and this file at 18, so this is a plain require in the ordinary direction —
// not a sixth inverted slot, and rule 3e's test is why.
const saml11 = require('../saml/saml11_sso');
// The authorization server profiles — what each discovery document publishes.
// A library that registers no route, so requiring it here moves nothing.
const authorizationServers = require('../oauth-oidc/authorization_servers');
// The federation REGISTER, and only the register. It is a library that
// registers no route, so requiring it here moves nothing and closes no cycle —
// rule 3e's test again, and it passes both ways round: that module requires
// only config.js, helpers.js and audit.js.
//
// **`federation/federation_sp.js` is deliberately NOT required here**, and it
// is the same line drawn around `spiffe_server.js` twenty lines down: that
// module registers /federation and its four endpoints, and `server.js`
// requires it at position 10c — BEFORE this file — so a require from here
// would be harmless today and would silently become the reason a route moved
// the day somebody reorders the two. What this page needs from it is the shape
// the URLs to configure at the partner, and those come from `federation.PATHS`
// — one copy of the strings, in the library both sides may reach, so this page
// and that router cannot come to name different paths. See that constant's
// header, where the failure it prevents is spelt out.
const federation = require('../federation/federation');
// The two SPIFFE LIBRARIES, and only those two. `spiffe_ca.js` holds the trust
// domain's authorities and `spiffe_registry.js` the registration entries and
// agents; both register nothing, so requiring them here moves no route and
// cannot close a cycle. `spiffe_id.js` comes with them for the server ID.
//
// **`spiffe_server.js` is deliberately NOT required here.** That module
// registers the bundle endpoint and /spiffe, and server.js requires this file
// FIRST — so a require from here would pull those routes into the express
// router ahead of the console's own, and GET /admin/sts-metadata is built by
// walking that router. What this page needs from it is two facts about sockets,
// and they arrive through a reader slot instead: the same inversion
// setDirectoryReader(), setGroupReader() and setScimReader() already use, and
// justified by rule 3e's test in exactly the same way.
const spiffeCa = require('../spiffe/spiffe_ca');
const spiffeRegistry = require('../spiffe/spiffe_registry');
// WHO MAY CALL THE SPIRE SERVER API. A library like the two above it — it
// registers nothing and starts nothing — so neither thing that forces a slot
// applies, and it is required directly rather than read through
// `setSpiffeReader()`. What DOES need the slot is which of the four sockets
// bound, which is a fact about a socket and only `spiffe_server.js` knows it.
const spiffeAuth = require('../spiffe/spiffe_auth');
const spiffeIdLib = require('../spiffe/spiffe_id');
// For the DRIFT report: the document this service would publish, to compare a
// profile's overrides against. oauth2.js is required before admin.js in
// server.js (rule 5), so this is a plain require in the ordinary direction.
const oauth2 = require('../oauth-oidc/oauth2');
// WHO ACTED ON WHOSE BEHALF. A library like the four above — it registers no
// route — so requiring it here neither moves a route nor closes a cycle. It
// holds the acts and this file renders them at /admin/delegation, the same
// split audit.js has.
const delegation = require('../common/delegation');
// THE PICTURE OF THAT REGISTER, at /admin/delegation/map. A library like
// `./admin_rbac.js` — it registers no route, requires only helpers.js and
// @dagrejs/dagre, and knows nothing about this console: it is HANDED a resolver
// that says what each box is, because what a party IS belongs here (the registry
// and the directory reader are here) and where a box GOES belongs there. Its own
// header weighs the dependency and argues why the layout is not hand-rolled.
const delegationMap = require('./delegation_map');
// The CONFIGURED half of that page: which Kerberos principals may delegate to
// which, out of the two attributes that decide it. It is read from the module
// that OWNS the principal database, for the reason every store rule here is
// where it is — what those two attributes mean is a statement about that store,
// and this file renders and decides nothing.
//
// A plain require in the ordinary direction, and both tests that would force a
// slot pass: `krb5_principals.js` registers no route (the KDC's own `/KdcProxy`
// and `/krb5/principals` are in `krb5_kdc.js`), and server.js requires the
// Kerberos modules BEFORE this one, so nothing here can be the reason a route
// moved. It is the same argument the two SPIFFE libraries above are required
// under.
const krb5Principals = require('../kerberos/krb5_principals');
// THE PROTOCOL-INDEPENDENT LOGOUT IS NOT REQUIRED HERE, AND THAT IS RULE 3e's
// TEST ANSWERING YES FOR THE SIXTH TIME. It is reached through a SLOT below —
// setLogoutReader(), which `../logout/logout.js` fills at its own require time,
// exactly as ldap_server.js, spiffe_server.js and scim.js fill the five above
// it.
//
// A plain require would close a cycle AND move routes, which is both halves of
// the test at once: that module requires `ldap_server.js` (for the bound
// connections that are the LDAP session), and `ldap_server.js` requires THIS
// file to fill those five slots — so `admin.js -> logout.js -> ldap_server.js
// -> admin.js` hands ldap_server.js a half-initialised console whose
// `setDirectoryReader` is undefined, and the symptom arrives as something that
// is not a function. It would also drag every `/ldap` route into the router
// ahead of the console's own, which is rule 6 read backwards.
//
// See the slot itself, further down, beside the other five.

// How many rows of a list a page will draw. A cap is needed — 5,000 token rows is
// a page no browser enjoys — and what it hid is always stated underneath, because a
// truncated table that does not say it was truncated reads as the whole truth.
//
// On the tokens page this is now the ceiling on ONE PAGE rather than on the whole
// list: everything held is reachable by paging, so nothing is hidden any more. The
// cap stays because the reason for it never went away — `?per=` is a number a caller
// types, and without a ceiling `?per=5000` is the page the cap existed to prevent.
const MAX_ROWS = 300;

// Rows per page when nobody said. Small enough that the table is the first thing on
// screen rather than the last, and the paging controls above and below it say what
// the rest of the list is.
const DEFAULT_PER_PAGE = 50;

// Rows per page for a list whose ROW IS A TABLE. There is one of those — the session
// blocks on the users drill-down, where each row of the list is a session heading, a
// facts table and a token table under it — and giving it DEFAULT_PER_PAGE would put
// fifty tables on one page, each of which is itself paged at fifty rows. The list
// pages get away with one number because a row there is a row.
//
// `?per=` still overrides it, for the same reason it overrides everything else: a
// number somebody typed is a number they meant.
const DEFAULT_BLOCKS_PER_PAGE = 5;

// How many subjects the metrics page names in one "Who" cell before it says how
// many more there are. A separate cap from MAX_ROWS because it bounds a cell rather
// than a list: the ceiling that matters here is the width of one row, and the full
// list is on /admin/users and in `?format=json` either way.
const MAX_WHO = 12;

// ---------------------------------------------------------------------------
// The page shell.
//
// One for all five pages, with the nav in it, so a page cannot be added without a
// way back — which held for the SECTIONS and did not hold for the pages under them
// until `up` existed, because the nav's answer on a drill-down was the section's
// own tab, drawn as text. See navBar(). The CSS is inline because app.js sets `default-src 'none'` with
// `style-src 'unsafe-inline'`: a stylesheet as its own resource would need its own
// exception and would buy nothing.
//
// There is NO SCRIPT anywhere here, and that constrains the design rather than
// merely describing it — `script-src 'none'` is what makes the whole family of
// reflected-content problems moot for this service, so the console does not get an
// exception. Every control on these pages is therefore a plain form POST, and
// every list is sorted server-side.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE NAVIGATION, WHICH IS NOW A LIST DOWN THE LEFT RATHER THAN A ROW ACROSS
// THE TOP, AND IS GROUPED.
//
// Seventeen tabs on one line wrapped to three rows on a laptop and to five on
// anything narrower, and a reader looking for `Verifier request` had to read all
// seventeen labels to find out it was not `Credential claims`. What the row could
// not express is that these pages are not seventeen peers: some are about
// PROTOCOLS this service speaks, some are about what is in its DIRECTORY, one is
// history, and the rest are about the service itself.
//
// So SECTIONS is the structure and `NAV` below is derived from it. Two rules
// about that and both are load-bearing:
//
//   * **`NAV` is DERIVED and never written by hand.** `upTo()` and `trailBar()`
//     look a path up in it to label a breadcrumb, so a page in SECTIONS that was
//     not in NAV would leave a drill-down whose trail names a path instead of a
//     section. Deriving it makes that impossible rather than merely unlikely.
//   * **The section a page is in is NOT a crumb.** A section has no page of its
//     own, so a crumb for it could not be a link, and a trail with a dead crumb
//     in the middle of it teaches a reader not to trust the ones beside it — the
//     rule the LAST crumb already follows for the same reason. The section is
//     visible where it is useful, which is the sidebar: the heading above the
//     page you are on is the answer to "what else is near this".
//
// WHERE THE PAGES THE ASK DID NOT NAME WENT. Four sections were asked for by
// name — Protocols (SCIM, SPIFFE, Verifier request, Credential claims, Custom
// claims), Directory (Users, Groups, Applications), Monitoring (Audit log) and
// Server configuration (Service metadata) — and seven pages were not mentioned.
// They are placed by the same question rather than left dangling: SPIFFE's
// registration entries and agents are SPIFFE, and authorization servers are
// OAuth, so all three are protocol pages; the console index, the metrics and the
// issued-token list describe the SERVICE'S OWN state rather than any one
// protocol, so they were an Overview at the top; and the configuration page and
// the admin roles below it are what this service is set up with, so they sit
// with the service metadata.
//
// TWO OF THOSE THREE MOVED TO MONITORING ON 2026-08-24, and what the move
// corrected is the question the section was answering. "Describes the service's
// own state rather than a protocol" is true of Metrics and Tokens, and it is
// equally true of the Audit log — which was in Monitoring by itself — so the
// old split was not between two kinds of page, it was between two kinds of
// ANSWER: a number, a list, and a history of what this service has done. Those
// are three ways of asking one question, and a reader who wants to know what
// happened should find all three under one heading rather than learn that the
// counters are filed away from the events they count.
//
// So Monitoring holds them in widening detail — Metrics (how much), Tokens
// (what came out), Audit log (what happened, in order) — and its `what` was
// rewritten with them, because "history rather than state" was the sentence
// that made the old split sound principled and is now false of two of its three
// pages. A section description that survives the pages moving under it is a
// description that was never about them.
//
// OVERVIEW IS A SECTION OF ONE NOW, and that is deliberate rather than a
// leftover. `/admin` is where a reader LANDS: it is the only page here whose job
// is to point at the others, so it is the one page that cannot sit under a
// heading naming a kind of content. Folding it into Monitoring would put the
// front door inside one of the rooms. The rule this trades against is the one
// stated for GROUPS below — a group of one is a heading buying nothing, which is
// why SCIM is ungrouped — and it does not reach here: a group's heading competes
// with the pages beside it inside a section, while a section's heading is the
// top-level structure, and dropping this one would leave `/admin` as a page
// under no heading at all in a sidebar where every other page has one.
//
// PROTOCOLS HAS A THIRD LEVEL NOW, AND ONLY PROTOCOLS DOES. Eight pages under
// one heading is the same list the row across the top was — a reader looking
// for `Registration entries` had to know that entries are a SPIFFE idea before
// the label could tell them anything — and the eight are not eight peers
// either: three configure what this service ISSUES over OAuth2/OIDC, three are
// the workload-identity side, one is the verifier's request and one is
// provisioning. So an item in a section may be a page (`path` + `label`) or a
// GROUP (`title` + `items`), and `isNavGroup()` is the one place that decides
// which. Three rules about a group, each the section rule one level down:
//
//   * A GROUP IS NOT A CRUMB AND HAS NO PAGE, for exactly the reason a section
//     does not. `trailBar()` is therefore untouched by this and must stay that
//     way — the trail is still `Admin console › Registration entries › <id>`.
//   * `NAV` IS STILL DERIVED, now through `sectionPages()`, which flattens a
//     group's pages into the section that holds it. Everything downstream —
//     `upTo()`, the trail, `consoleJson().pages` — reads NAV and so cannot tell
//     a grouped page from an ungrouped one, which is the point: grouping is a
//     fact about the SIDEBAR, not about the pages.
//   * NESTING STOPS HERE. A group holds pages, never another group. Nothing
//     enforces it beyond `sectionPages()` not recursing, which is deliberate —
//     a fourth level would be a sidebar that needs its own breadcrumb.
//
// ONE PLACEMENT IN HERE IS A JUDGEMENT RATHER THAN AN OBVIOUS FACT, and it is
// worth knowing which. `Credential claims` (`/admin/vc`) is the OID4VCI
// ISSUER's claim configuration, so it could be argued into OAuth2 / OIDC — the
// issuer is an OAuth2 authorization server wearing another hat, and the page
// sits beside `Custom claims` in the code. It is under Verifiable Credentials
// because the reader looking for it is thinking about a CREDENTIAL rather than
// about a token, and because the two halves of the credential lifecycle —
// what the issuer puts in and what the verifier asks for — answer each other
// and are worth reading together.
//
// `SAML` IS A GROUP WITH ONE PAGE IN IT AND THAT IS AN EXCEPTION WORTH
// ARGUING, because the rule right beside it says the opposite: `SCIM` is left
// ungrouped for the smaller reason that a group of one is a heading buying
// nothing, and it still is. What makes SAML different is that the heading names
// a PROTOCOL FAMILY this service speaks in two versions and two profiles, and
// the page under it — `Custom SAML attributes` (`/admin/saml-attributes`), the
// two assertion claim sets, moved off `/admin/claims` on 2026-08-24 — is one
// aspect of that family rather than the whole of it. A reader looking for what
// a WS-Federation assertion will carry looks for the word SAML; ungrouped, that
// page would sit among the protocol pages reading as something OAuth-adjacent,
// which is exactly the confusion the grouping was introduced to end. SCIM's one
// page IS the whole of SCIM here, so its heading would say the label twice.
// The test for a second group of one is that question and not this precedent:
// does the heading name more than the page under it does?
// ONE ROW BELOW IS A PAGE THIS FILE DOES NOT DRAW. `Service metadata`
// (`/admin/sts-metadata`) is built by `../sts_metadata.js`, which derives its
// whole content from the live express router and therefore has to be the LAST
// module server.js loads; it calls `respond()` for this shell. Nothing about
// the nav knows that, and that is the point — a page here is a `path` and a
// `label` whoever builds it. It was `/sts-metadata`, outside the console
// altogether, until 2026-08-24.
//
// EVERY PAGE ROW CARRIES A `blurb`, AND THAT IS WHAT `/admin` IS BUILT FROM.
// The Overview page's *What this console is* list used to be a hand-written
// `<ul>` in the index route, and it drifted exactly the way this repository
// warns everything else about: it described seven pages while the sidebar
// offered twenty-five, so the front door of this console was quietly the least
// complete description of it. The list is DERIVED from this table now
// (`consoleGuide()` below), so a page added here appears there with no second
// edit — and a page added here with no `blurb` appears there SAYING SO, in the
// same spirit as `/admin/sts-metadata` reporting an undescribed route rather
// than omitting it. A blurb is prose about ONE page and belongs beside that
// page's `path` and `label` for the same reason its label does; a second table
// keyed by path would be the drift back again with an extra lookup.
const SECTIONS = [
  { title: 'Overview',
    what: 'Where a reader lands, and what it points at.',
    items: [
      // NO `blurb`, and that is not an omission. `consoleGuide()` drops the
      // page it is being drawn ON before it looks for one, and this is the
      // only page it is ever drawn on — a row here describing this page would
      // be text nothing can render, which is the kind of thing that is edited
      // for years after it stopped being read.
      { path: '/admin', label: 'Console' }
    ] },
  { title: 'Protocols',
    what: 'One page per family, each configuring or reporting what that ' +
          'protocol does here.',
    items: [
      { title: 'OAuth2 / OIDC',
        what: 'Which authorization server a flow runs against, how long what ' +
              'it issues lasts, and what this service puts into it.',
        items: [
          { path: '/admin/authorization-servers',
            label: 'Authorization servers',
            blurb: 'Several authorization servers in ONE process, told apart ' +
                   'by the path component the two discovery shapes already ' +
                   'carry — RFC 8414 inserts it after the well-known segment ' +
                   'and OpenID Connect Discovery appends the segment to it. ' +
                   'Each has its own issuer, its own keys and its own idea of ' +
                   'what it will accept, so a client can be pointed at a ' +
                   'second one without a second process. A path nobody has ' +
                   'configured publishes the document this service always ' +
                   'published, which is what keeps a client that has never ' +
                   'heard of this page unaffected by it.' },
          { path: '/admin/token-lifetimes', label: 'Token lifetimes',
            blurb: 'How long an access token, an ID Token and a refresh ' +
                   'token issued here are good for, and how far out a clock ' +
                   'may be before this service stops believing one of its ' +
                   'own. Four configuration settings with a page of their ' +
                   'own, written through the same function ' +
                   '<a href="/admin/config">Configuration</a> writes ' +
                   'through — a change made on either page is one change.' },
          { path: '/admin/claims', label: 'Custom claims',
            blurb: 'What to add to every OAuth 2.0 access token and every ' +
                   'OIDC ID Token this service issues FROM NOW ON. Two sets, ' +
                   'because those two go to different readers and the ' +
                   'interesting configuration is usually the one where they ' +
                   'DIFFER. Additive only: a custom claim is never allowed ' +
                   'to displace one the protocol defines, because an ' +
                   '<code>exp</code> settable from a web form would produce ' +
                   'tokens that fail to verify with nothing pointing back at ' +
                   'the page. Nothing already issued changes — a token is a ' +
                   'signed document and this page cannot reach inside one.' }
        ] },
      { title: 'SAML',
        what: 'BOTH identity providers — SAML 2.0\'s Web Browser SSO profile ' +
              'and SAML 1.1\'s two browser profiles, each with its relying ' +
              'parties and the metadata each one is configured from — and what ' +
              'this service puts into an assertion, 2.0 and 1.1 alike, which ' +
              'is also what WS-Trust and WS-Federation carry. The two profiles ' +
              'are separate pages because they are separate implementations: ' +
              'SAML 1.1 has no request message and no Single Logout, so half ' +
              'of what the 2.0 page reports has no spelling over there.',
        items: [
          { path: '/admin/saml2', label: 'SAML 2.0 identity provider',
            blurb: 'Every service provider this identity provider has been ' +
                   'asked about, what each one was sent and over which ' +
                   'binding, and the settings behind the next assertion. ' +
                   'Metadata is published PER service provider — the ' +
                   'identity provider names itself differently to each one, ' +
                   'the way Okta and Ping do — and it is minted for anything ' +
                   'asked for, so nothing has to be registered here first: ' +
                   'asking for a service provider\'s metadata is what ' +
                   'creates it.' },
          { path: '/admin/saml11', label: 'SAML 1.1 identity provider',
            blurb: 'The same, for the older profiles, and it is a SEPARATE ' +
                   'implementation rather than a version flag. SAML 1.1 has ' +
                   'no request message, so a relying party cannot identify ' +
                   'itself in the protocol at all — it is named by ' +
                   'Shibboleth\'s <code>providerId</code>, by the path ' +
                   'segment of a scoped endpoint, or GUESSED from the origin ' +
                   'of the <code>TARGET</code> — and there is no Single ' +
                   'Logout to configure and no request signature to record. ' +
                   'What it has that 2.0 does not is a SOAP responder that ' +
                   'is also an attribute authority.' },
          { path: '/admin/saml-attributes', label: 'Custom SAML attributes',
            blurb: 'The same two halves for the assertions: every SAML 2.0 ' +
                   'and SAML 1.1 attribute added to what the two identity ' +
                   'providers, WS-Trust and WS-Federation issue from now on. ' +
                   'One store behind this page and ' +
                   '<a href="/admin/claims">Custom claims</a>; two ' +
                   'vocabularies, because 2.0 has <code>Name</code> and an ' +
                   'optional <code>NameFormat</code> where 1.1 has ' +
                   '<code>AttributeName</code> and a REQUIRED ' +
                   '<code>AttributeNamespace</code>, and one list could not ' +
                   'have served both.' }
        ] },
      { title: 'Verifiable Credentials',
        what: 'Both halves: what the OID4VCI issuer puts in a credential, ' +
              'and what the OID4VP verifier asks a wallet to present.',
        items: [
          { path: '/admin/vc', label: 'Credential claims',
            blurb: 'Which claims a Verifiable Credential issued from now on ' +
                   'carries, chosen from a catalogue of LDAP attribute TYPES ' +
                   'rather than of claim names: the value of a claim is the ' +
                   'value on that person\'s directory entry. Saving a ' +
                   'selection also populates the directory, so an LDAP ' +
                   'client and a wallet describe one person. It applies to ' +
                   'all five OID4VCI configurations at once.' },
          { path: '/admin/vc-verifier-config', label: 'Verifier request',
            blurb: 'The other end of that lifecycle: what the mock Verifier ' +
                   'at <code>/oid4vp/verifier</code> asks a wallet for, and ' +
                   'in which credential format. It reaches the wire as the ' +
                   '<code>dcql_query</code> of the next OID4VP ' +
                   'Authorization Request, and it is what the presentation ' +
                   'is then checked against — a claim asked for and not ' +
                   'presented fails by name.' }
        ] },
      { title: 'SPIFFE',
        what: 'Workload identity: the trust domain, the entries that decide ' +
              'what a workload gets, and the agents that ask for it.',
        items: [
          { path: '/admin/spiffe', label: 'SPIFFE',
            blurb: 'The trust domain, the signing authority behind every ' +
                   'X509-SVID and JWT-SVID, the four sockets the Workload ' +
                   'API and the SPIRE Server API answer on, and how a caller ' +
                   'at the Workload API is identified — the ' +
                   '<code>transport:</code>, <code>endpoint:</code> and ' +
                   '<code>peer:</code> selectors, and whether an ASSERTED ' +
                   'one is believed. This service attests no workload and no ' +
                   'node; that is the one thing on this page that no setting ' +
                   'turns on.' },
          { path: '/admin/spiffe/entries', label: 'Registration entries',
            blurb: 'Which workload gets which SPIFFE ID, and what an SVID ' +
                   'issued against that entry carries. The store is the ' +
                   'embedded directory under ' +
                   '<code>ou=entries,ou=spiffe</code>, so a form here, an ' +
                   '<code>ldapmodify</code> and the SPIRE Server API\'s ' +
                   '<code>BatchUpdateEntry</code> are three doors onto one ' +
                   'entry, and nothing caches it — a change takes effect on ' +
                   'the next SVID.' },
          { path: '/admin/spiffe/agents', label: 'Agents',
            blurb: 'Every agent that has attested, with what it was given ' +
                   'and when. These entries are a RECORD rather than ' +
                   'configuration — this service wrote all of it when the ' +
                   'agent attested — which is why nothing on an agent is ' +
                   'editable and the ban is the only control.' } ] },
      { path: '/admin/scim', label: 'SCIM',
        blurb: 'The provisioning endpoint at <code>/scim/v2</code>: what it ' +
               'requires of a caller, which of RFC 7644 section 2\'s six ' +
               'schemes it will take, and what it has written. It is the ' +
               'only protocol family here whose purpose is to WRITE, and ' +
               'what it writes is the embedded directory — there is no ' +
               'second store and no cache, so a <code>POST ' +
               '/scim/v2/Users</code> and an <code>ldapadd</code> create the ' +
               'same entry and somebody provisioned over SCIM appears on ' +
               '<a href="/admin/users">Users</a>.' },
      // UNGROUPED, beside SCIM, and the placement needed the same argument the
      // delegation page needed. Federation spans FIVE protocol families, so
      // under any one of the groups above it would mean choosing which four
      // fifths of the answer to hide — which is exactly what put
      // /admin/delegation in Monitoring. It does not go there, though: that
      // page is an OBSERVATION and this one is CONFIGURATION, and it is the
      // only page in this console that configures something a protocol
      // endpoint will REFUSE on. A section of its own was considered and
      // fails this console's own test for one — the heading would name
      // nothing the page under it does not.
      { path: '/admin/federation', label: 'Federation',
        blurb: 'Relationships with a FOREIGN identity service, in either ' +
               'direction, in five protocols — consuming somebody else\'s ' +
               'assertions as a service provider, or asserting to a foreign ' +
               'service provider with a per-partner attribute release ' +
               'policy. It is the one page in this console that configures a ' +
               'REFUSAL: everywhere else this service accepts what it is ' +
               'given, and it cannot do that at an assertion consumer ' +
               'service, because what arrives there is an unauthenticated ' +
               'request claiming to be a person and the session it would ' +
               'produce is the same one every other family and this console ' +
               'read. So a relationship is created DISABLED and an assertion ' +
               'is refused unless it verifies against the certificate ' +
               'configured on it.' }
    ] },
  { title: 'Directory',
    what: 'The embedded LDAP directory, and the identities this service has ' +
          'seen. The two are different questions and these pages keep them ' +
          'apart.',
    items: [
      { path: '/admin/users', label: 'Users',
        blurb: 'Every userid this service has been given as part of an ' +
               'interaction that SUCCEEDED, across all sixteen protocol ' +
               'families, with what each one holds. Click a name for the ' +
               'sessions they are signed in on, the tokens issued on each of ' +
               'those sessions, and the assertions, tickets and credentials ' +
               'issued to them. It also lists the subjects that were never ' +
               'here at all — an exchanged token names one, so does a ' +
               'WS-Trust <code>OnBehalfOf</code> and a Kerberos S4U request ' +
               '— and says so on the row. A person can be created here ' +
               'ahead of their first sign-in; nobody is ever removed.' },
      { path: '/admin/groups', label: 'Groups',
        blurb: 'Every group in the embedded LDAP directory, with how many of ' +
               'its members name an entry that is actually there. Click one ' +
               'for every attribute it holds and everybody in it, each ' +
               'member linked back to their row on Users. It reports the ' +
               'DIRECTORY rather than what this service has issued, and the ' +
               'one thing to know about it is that <strong>a group here ' +
               'grants nothing</strong>: no endpoint reads one and nothing ' +
               'decides anything on one. A token can CARRY one — see ' +
               '<code>groups.claim</code> — which is a different sentence. ' +
               'The two named on <a href="/admin/rbac">Admin roles</a> are ' +
               'the exception and grant exactly one thing: this console.' },
      { path: '/admin/applications', label: 'Applications',
        blurb: 'Every relying party this service has been asked about — a ' +
               '<code>client_id</code> at the token endpoint, a ' +
               '<code>wtrealm</code> on a sign-in response, an entityID on ' +
               'an AuthnRequest — with what each one was given and when. An ' +
               'entry usually appears because an identifier was ACCEPTED, ' +
               'and one can also be created here ahead of the first ' +
               'connection, which is what RFC 9700 mode needs if it is to ' +
               'judge a client against its own redirect URIs rather than ' +
               'against a setting. A hand-made entry records that it was ' +
               'made by hand, so it cannot be mistaken for one that turned ' +
               'up once and never came back.' }
    ] },
  { title: 'Monitoring',
    what: 'What this service has done: how much of it, what came out, and ' +
          'what happened in order.',
    items: [
      { path: '/admin/metrics', label: 'Metrics',
        blurb: 'Every endpoint call by route and status class, every token ' +
               'and artifact this service has issued with how many are still ' +
               'valid, and sessions counted BOTH ways: the browser sign-on ' +
               'sessions this service really holds, and the sessions implied ' +
               'by what it has issued. Every figure is computed when the ' +
               'page is drawn rather than kept up to date as things happen, ' +
               'because "valid" and "expired" are functions of the clock.' },
      { path: '/admin/tokens', label: 'Tokens',
        blurb: 'Everything issued and still remembered, in ONE table: every ' +
               'JWT, every SAML assertion (WS-Trust\'s, WS-Federation\'s and ' +
               'both browser profiles\' alike) and every Kerberos ticket, ' +
               'newest first — one table rather than three because a ' +
               'sign-in that produced an ID Token and an assertion is one ' +
               'event. And the buttons that invalidate the ones that can be: ' +
               'one access token, one ID Token, one refresh token, ' +
               'everything for one subject, or everything of one kind. ' +
               'Revocation here is the SAME revocation RFC 7009\'s ' +
               '<code>/oauth2/revoke</code> performs, so introspection, ' +
               'UserInfo and the refresh grant all honour it.' },
      // Beside the tokens it points at rather than under Protocols, and that
      // was the decision: delegation is the one feature here that is
      // deliberately NOT a protocol family — six of its eight mechanisms come
      // from three different families and the whole value is reading them
      // against each other in one table. Under Protocols it would have had to
      // be filed under one of the three.
      { path: '/admin/delegation', label: 'Delegation',
        blurb: 'Who acted on whose behalf, through what, to reach what: ' +
               'eight mechanisms from three protocol families — Kerberos\'s ' +
               'S4U2Self, two flavours of S4U2Proxy and a forwarded TGT, ' +
               'WS-Trust\'s <code>OnBehalfOf</code> and <code>ActAs</code>, ' +
               'and RFC 8693\'s impersonation and delegation — against ONE ' +
               'model, because the question a reader arrives with is ' +
               'protocol-independent. Beside them, who MAY delegate to whom, ' +
               'which only Kerberos polices; that asymmetry is the most ' +
               'useful thing on the page. ' +
               '<a href="/admin/delegation/map">The picture</a> draws the ' +
               'same acts as a graph, laid out on the SERVER because this ' +
               'console runs no script.' },
      // Beside the tokens page rather than under Protocols, and for the same
      // reason delegation is: signing somebody out is deliberately NOT a
      // protocol family. It reaches nine stores across six families and the
      // whole value is doing all of them at once, so filing it under one would
      // be filing it under the wrong one. It is an ACTION page in a section
      // whose heading says "what this service has done" — which /admin/tokens
      // already is, since revoking is a control and that page has four of them.
      { path: '/admin/logout', label: 'Sign-out',
        blurb: 'Name an identity to see everything this service is still ' +
               'holding for them — every browser sign-on session, every ' +
               'token it can still revoke, every outstanding authorization ' +
               'code and credential offer, every directory connection bound ' +
               'as them, and the Kerberos sign-out instant — and to end any ' +
               'of it. It is <a href="/logout">/logout</a> done to somebody ' +
               'else: the same nine stores through the same functions, ' +
               'except that the notifications cannot be delivered from ' +
               'here.' },
      { path: '/admin/audit', label: 'Audit log',
        blurb: 'What this service was ASKED to do, in the order it was ' +
               'asked, newest first. Every other page here is state; this ' +
               'one is history — Metrics can say the directory holds eleven ' +
               'entries, and only this page can say that a twelfth was ' +
               'created at 14:02 and deleted at 14:03 by somebody bound as ' +
               '<code>uid=carol</code> over LDAPS. It is a ring with a ' +
               'settable cap, so the oldest rows are dropped rather than ' +
               'kept forever.' }
    ] },
  { title: 'Server configuration',
    what: 'What this service is set up with, and who may change it.',
    items: [
      // FIRST in this section, above Configuration, and the order is an
      // argument rather than a preference: every page in this console shows one
      // realm, and Configuration in particular WRITES to the realm it is being
      // read in. Somebody who does not yet know that realms exist should meet
      // the page that says so before the page that acts on it.
      { path: '/admin/realms', label: 'Trust realms',
        blurb: 'Several logical copies of this service in one process, told ' +
               'apart by a segment at the front of the path. A realm has its ' +
               'own configuration, its own signing key, its own sessions, ' +
               'codes, tokens, artifacts, statistics and audit log — so a ' +
               'token minted in one does not verify against another\'s ' +
               'JWKS, which is the point of a realm rather than a side ' +
               'effect. What a realm separates is what this service ISSUES: ' +
               'the embedded directory is SHARED, and so are Kerberos, the ' +
               'two TLS listeners and SPIFFE\'s four sockets, because a ' +
               'socket has no path to put a realm segment in.' },
      { path: '/admin/config', label: 'Configuration',
        blurb: 'Every setting this service has, grouped by the protocol it ' +
               'belongs to, with where each value came from: a runtime ' +
               'override set here, an environment variable, the appconfig ' +
               'file this process was started with, or the defaults that one ' +
               'is unioned on top of. Higher beats lower, and a setting with ' +
               'a value NOWHERE stops the service from starting rather than ' +
               'defaulting quietly. Like every writing page here, it writes ' +
               'the realm it is read IN.' },
      { path: '/admin/rbac', label: 'Admin roles',
        blurb: 'Who holds the two roles that grant this console — Admin ' +
               'Read and Admin Write — granted and revoked here. They are ' +
               'ORDINARY GROUPS in the shared directory rather than a store ' +
               'of the console\'s own, so this page, ' +
               '<code>/admin-api</code>, an <code>ldapmodify</code> on 389 ' +
               'or 636 and a SCIM PATCH are four doors onto one membership ' +
               '— which is the point, since a role no test can grant is a ' +
               'role no test can exercise. While NEITHER group has a member, ' +
               'anybody who signs in holds both.' },
      { path: '/admin/sts-metadata', label: 'Service metadata',
        blurb: 'Every endpoint this process registered, read off the LIVE ' +
               'express router, with the specification each one claims and ' +
               'how much of that specification is really implemented. ' +
               'Because it is read off the router it cannot go stale, and it ' +
               'reports both kinds of drift: a route registered and ' +
               'undescribed, and a description whose path is not registered ' +
               '— which is what a rename produces. A protocol that registers ' +
               'no route at all is its one blind spot, so the KDC\'s raw ' +
               '88 and the directory\'s 389 and 636 are described by hand.' }
    ] }
];

// Is this row of a section's `items` a GROUP of pages rather than a page? One
// predicate, used by both the flattening and the sidebar, so the two cannot
// disagree about what they are looking at. A group has `items`; a page has a
// `path` and never has `items`.
function isNavGroup(item) {
  return item != null && Array.isArray(item.items);
}

// Every PAGE in one section, in sidebar order, with a group's pages spliced in
// where the group sits. One level only — see the note above SECTIONS.
function sectionPages(section) {
  log.debug("Entering sectionPages(). section=" + section.title);
  const pages = [];
  section.items.forEach(function (item) {
    if (isNavGroup(item)) {
      item.items.forEach(function (page) {
        pages.push(page);
      });
      return;
    }
    pages.push(item);
  });
  log.debug("Leaving sectionPages(). " + pages.length + " page(s).");
  return pages;
}

// Every page in every section, flattened, with the section it belongs to on each
// row. Derived rather than typed for the reason above; the `section` member is
// what lets the sidebar bold the right heading without a second lookup. A page
// inside a group is flattened to the same shape as one outside it, so nothing
// downstream of here can tell them apart.
const NAV = [];
SECTIONS.forEach(function (section) {
  sectionPages(section).forEach(function (item) {
    NAV.push({ path: item.path, label: item.label, section: section.title });
  });
});

function esc(v) { return xmlEscape(v == null ? '' : String(v)); }

// A list of names, each in its own <code>. Written as a function because the
// obvious one-liner — join with the markup and escape the result — escapes the
// markup too, and the page then shows the tags it was supposed to render. It did.
function codeList(names) {
  return names.map(function (name) { return '<code>' + esc(name) + '</code>'; }).join(', ');
}

// WHICH QUERY PARAMETERS BELONG TO A SECTION'S LIST rather than to the page under
// it — the filter the reader typed and the page they had reached.
//
// It is a WHITELIST per section rather than "everything that is not ours", for the
// same reason the tokens page rebuilds its `back` field from a list of names
// instead of echoing it: what comes out of here is put into a URL this service
// hands to a browser, so the set of names has to be one this file wrote. It is
// also why a section that cannot be drilled into has no row — carrying a filter
// through a page nothing hangs under would be state nobody can get back to.
const LIST_PARAMS = {
  '/admin/users': ['q', 'protocol', 'per', 'page'],
  '/admin/groups': ['q', 'per', 'page'],
  '/admin/applications': ['q', 'kind', 'per', 'page'],
  '/admin/saml2': ['q', 'per', 'page'],
  '/admin/saml11': ['q', 'per', 'page'],
  '/admin/authorization-servers': ['per', 'page'],
  '/admin/spiffe/entries': ['q', 'origin', 'per', 'page'],
  '/admin/spiffe/agents': ['q', 'per', 'page'],
  '/admin/rbac': ['q', 'role', 'per', 'page'],
  // `family` rather than `q`: this page's filter is a family and there are ten
  // of them, so it is chosen by clicking a row of the summary table rather than
  // typed. `user` is deliberately NOT here — it is the drill-down's own leaf,
  // not the list's filter, and carrying it in the section crumb would make the
  // way back point at the page the reader is already on.
  // The delegation table's five filters and its paging. `/admin/delegation/map`
  // is the drill-down that spends them, and it carries the filters onward
  // through a form of its own — the picture and the table are filtered by one
  // control, so a reader who narrowed the table and then drew it gets the
  // picture of what they were looking at.
  '/admin/delegation': ['type', 'mode', 'outcome', 'protocol', 'q', 'per', 'page'],
  '/admin/logout': ['family', 'per', 'page'],
  '/admin/realms': ['per', 'page'],
  '/admin/federation': ['q', 'role', 'per', 'page']
};

// The list AS THE READER LEFT IT, picked out of a query by that table.
//
// This is what makes the trail a way back to where somebody was rather than to the
// top of an unfiltered list. A drill-down link carries it, every control on the
// drill-down carries it onward (pageParamsOf() takes the whole query through), and
// the trail's section crumb spends it. Nothing on the drill-down reads these keys
// for anything else: their names belong to the list's filter form, and a page
// showing one application has no `q`.
function listViewOf(section, query) {
  log.debug("Entering listViewOf(). section=" + section);
  const out = {};
  (LIST_PARAMS[section] || []).forEach(function (key) {
    const raw = (query || {})[key];
    // Express hands back an array when a parameter is repeated, and String() on one
    // is "a,b" — a filter nothing matches, reached by a link somebody clicked twice.
    // The same first-wins rule pageParamsOf() uses.
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (value !== undefined && value !== null && String(value) !== '') {
      out[key] = String(value);
    }
  });
  log.debug("Leaving listViewOf(). " + Object.keys(out).length + " parameter(s) carried.");
  return out;
}

// The same thing out of a form's `back` field, which is a query string a browser
// sent us rather than one we are looking at.
//
// It is REBUILT and never echoed: the names come from LIST_PARAMS, the values are
// re-encoded by queryWith(), and anything else in the field is dropped. That is
// the guarantee backTo() gives the tokens page and it is needed here for the same
// reason — a redirect target taken out of a request body is an open redirect, and
// one carrying a newline is a header injection. The worst a hand-written `back`
// can now reach is another page of the same list.
function listViewFromBack(section, raw) {
  log.debug("Entering listViewFromBack(). section=" + section);
  let params = null;
  try {
    params = new URLSearchParams(String(raw || '').replace(/^\?/, ''));
  } catch (e) {
    // Unparseable; the bare list is the right answer and is what a form carrying no
    // `back` at all gets anyway.
    log.debug("Leaving listViewFromBack(). Unparseable: " + e.message);
    return {};
  }
  const query = {};
  params.forEach(function (value, key) {
    // First wins, for the reason listViewOf() takes the first of a repeated
    // parameter: a field sent twice is one value, not "a,b".
    if (!Object.prototype.hasOwnProperty.call(query, key)) {
      query[key] = value;
    }
  });
  log.debug("Leaving listViewFromBack().");
  return listViewOf(section, query);
}

// The section a DRILL-DOWN hangs under: where "back" goes, what that section is
// called, and what the reader has drilled INTO.
//
// The label comes out of NAV rather than the call site, so a renamed tab cannot
// leave a way back that names the old one. A path with no NAV row falls back to
// the path itself, which is visible rather than silent — a drill-down under a
// section that is not in the nav is worth noticing.
//
// `listView` is listViewOf()'s answer, and it is what the href carries: the reader
// goes back to page 3 of the filter they were looking at rather than to the top of
// everything. `leaf` is the thing drilled into, for the last crumb.
function upTo(path, leaf, listView) {
  log.debug("Entering upTo(). path=" + path);
  const item = NAV.filter(function (row) { return row.path === path; })[0];
  const view = listView || {};
  log.debug("Leaving upTo(). " + (item ? "labelled " + item.label : "no nav row") +
            ", " + Object.keys(view).length + " list parameter(s).");
  return { href: path + queryWith(view, {}), label: item ? item.label : path,
           leaf: leaf, filtered: Object.keys(view).length > 0 };
}

// `up` is set on a drill-down — a page reached from a link on one of the sections
// below rather than one of the sections itself — and what it changes is the ACTIVE
// TAB.
//
// That tab was drawn as plain text on every page whose `active` matched, and
// `active` is the section's path on the list page and on every page underneath it
// alike. So on a drill-down the one control that pointed at the list was the one
// control this shell had turned off, and the only way back from
// /admin/applications?application=x was the browser's own Back button or a link at
// the foot of a long page. On a drill-down the tab is a LINK: still bold, because
// the reader is inside that section, and underlined so that "the section you are
// in" cannot be read as "not clickable".
//
// It is one `<nav>` holding one `<ul>` per section with a heading above it. The
// heading is plain text and NOT a link, for the reason the section is not a
// crumb: there is no page behind it. The section containing the page being drawn
// is marked, so a reader who arrived on a deep link can see where they are
// without reading every label.
//
// A GROUP inside a section is drawn as an `<li>` holding a heading and a `<ul>`
// of its own, rather than as a second `<ul>` beside the first: a group belongs
// INSIDE the section's list — it is three of that list's items said together —
// and a sibling list would tell a screen reader the section ended where the
// group began. Its heading is plain text for the same reason the section's is,
// and the marker on the group holding the current page is a rule down the left
// like the section's, one level in.
function navBar(active, up, req) {
  log.debug("Entering navBar(). active=" + active);
  const html = '<nav aria-label="Admin console sections">' +
    // FIRST, inside this card rather than above it. It does not select a page
    // — it selects which service the pages are about — but it is the first
    // question a reader has about the column, so it is the first thing in it.
    realmChooser(req) +
    SECTIONS.map(function (section) {
      const inThisSection = sectionPages(section).filter(function (item) {
        return item.path === active;
      }).length > 0;
      const links = section.items.map(function (item) {
        return navItem(item, active, up);
      }).join('');
      return '<div class="navsec' + (inThisSection ? ' open' : '') + '">' +
        '<p class="navhead" title="' + esc(section.what) + '">' +
        esc(section.title) + '</p><ul>' + links + '</ul></div>';
    }).join('') + '</nav>';
  log.debug("Leaving navBar(). " + SECTIONS.length + " section(s).");
  return html;
}

// One row of a section's list: a page, or a group holding pages.
function navItem(item, active, up) {
  log.debug("Entering navItem(). " + (isNavGroup(item) ? 'group ' + item.title
                                                       : 'page ' + item.path));
  if (!isNavGroup(item)) {
    log.debug("Leaving navItem(). A page.");
    return navLink(item, active, up);
  }
  const open = item.items.filter(function (page) {
    return page.path === active;
  }).length > 0;
  const html = '<li class="navgrp' + (open ? ' open' : '') + '">' +
    '<p class="navsub" title="' + esc(item.what) + '">' + esc(item.title) +
    '</p><ul>' + item.items.map(function (page) {
      return navLink(page, active, up);
    }).join('') + '</ul></li>';
  log.debug("Leaving navItem(). A group of " + item.items.length + " page(s).");
  return html;
}

// One page's link. Split out of navBar() when groups arrived so that a page
// draws the same way at either depth — the active-tab-is-a-link rule above is
// the kind that gets applied to one of two copies.
function navLink(item, active, up) {
  log.debug("Entering navLink(). path=" + item.path);
  if (item.path === active) {
    if (up) {
      log.debug("Leaving navLink(). Active, and a drill-down.");
      return '<li><a class="here" href="' + esc(up.href) + '" title="Back to ' +
             esc(up.label) + '">' + esc(item.label) + '</a></li>';
    }
    log.debug("Leaving navLink(). Active.");
    return '<li><span class="here">' + esc(item.label) + '</span></li>';
  }
  log.debug("Leaving navLink().");
  return '<li><a href="' + esc(item.path) + '">' + esc(item.label) +
         '</a></li>';
}

// How long a leaf crumb may be before it is cut. A group's leaf is a DN and a
// user's can be a did:jwk — a few hundred characters of base64url with nowhere a
// browser will break a line — and a trail that wraps to four lines is not a trail.
// The full name is in the <h1> immediately below it and in the `title` here, so
// nothing is lost by cutting: what the crumb is for is the LINKS to its left.
const MAX_CRUMB = 44;

function shortCrumb(text) {
  const value = String(text == null ? '' : text);
  return value.length > MAX_CRUMB ? value.slice(0, MAX_CRUMB - 1) + '…' : value;
}

// THE BREADCRUMB TRAIL, AND IT IS ON EVERY PAGE RATHER THAN ONLY ON A DRILL-DOWN.
//
// One line under the nav saying where the reader is and offering every level above
// them: `Admin console › Applications › rfc9700-debugger`. The nav answers "what
// else is there"; the trail answers "where am I and how do I get back", which are
// different questions — the tab for the section you are standing in is exactly the
// tab that tells you nothing about the page you are standing on.
//
// Three things about it are deliberate.
//
// The section crumb on a drill-down is `up.href`, which carries THE FILTER AND THE
// PAGE the reader clicked in from (see listViewOf()), so the trail goes back to
// where they were rather than to the top of an unfiltered list. That is the whole
// difference between a breadcrumb and a link to the section.
//
// The last crumb is NOT a link. It is the page being drawn, and a crumb that
// reloads the page you are on is a control that does nothing — which teaches a
// reader not to trust the ones beside it.
//
// The root crumb is `Admin console` on every page including `/admin` itself, where
// it is the only crumb and is not a link. A trail that appeared on some pages and
// not others would be a trail nobody looks for.
function trailBar(active, up, title) {
  log.debug("Entering trailBar(). active=" + active);
  const crumbs = [{ label: 'Admin console', href: active === '/admin' ? null : '/admin' }];
  if (active !== '/admin') {
    const item = NAV.filter(function (row) { return row.path === active; })[0];
    const label = item ? item.label : active;
    if (up) {
      crumbs.push({ label: label, href: up.href,
                    // Said in the tooltip rather than in the crumb, because "as you
                    // left it" is reassurance for somebody who wonders and noise for
                    // everybody else — and a crumb whose text changes with the
                    // filter is a crumb that moves under the pointer.
                    title: up.filtered
                      ? 'Back to ' + label + ' — the filter and page you came from'
                      : 'Back to ' + label });
      crumbs.push({ label: shortCrumb(up.leaf || title), title: String(up.leaf || title) });
    } else {
      crumbs.push({ label: label });
    }
  }
  const html = '<p class="crumb">' + crumbs.map(function (crumb, index) {
    const sep = index ? '<span class="sep">&rsaquo;</span>' : '';
    if (!crumb.href) {
      return sep + '<span class="leaf"' +
        (crumb.title ? ' title="' + esc(crumb.title) + '"' : '') + '>' +
        esc(crumb.label) + '</span>';
    }
    return sep + '<a href="' + esc(crumb.href) + '"' +
      (crumb.title ? ' title="' + esc(crumb.title) + '"' : '') + '>' +
      esc(crumb.label) + '</a>';
  }).join('') + '</p>';
  log.debug("Leaving trailBar(). " + crumbs.length + " crumb(s).");
  return html;
}

// ---------------------------------------------------------------------------
// THE BANNER EVERY PAGE CARRIES, AND IT NOW HAS THREE THINGS TO SAY RATHER THAN
// ONE.
//
// It is repeated on all of them rather than shown once on the index, because the
// pages are linkable and the one somebody arrives at directly is exactly the one
// that needs to say this. What it says depends on the state of the gate, and the
// three states are genuinely different warnings rather than one warning with a
// detail changed:
//
//   * THE GATE IS OFF (`admin.authRequired`). The old banner, unchanged and
//     still true: nothing here checks anything. It stays because that state is
//     deliberately reachable — every refusal in this service is switchable — and
//     because a console that used to say this and now says nothing would leave
//     somebody who turned the setting off believing they were still protected.
//   * THE GATE IS ON AND NOBODY HOLDS A ROLE. The most dangerous state and the
//     one nothing else would report: a person has signed in, sees a working
//     console, and it is working because the roster is EMPTY rather than because
//     they were allowed. Said loudly, with what to do about it, because the
//     moment somebody grants the first role the door shuts behind whoever is not
//     in it — including, quite possibly, them.
//   * THE GATE IS ON AND THE ROSTER IS ENFORCED. Not a warning at all: who is
//     signed in and what they hold. It is still on every page, because "am I
//     read-only here" is the question behind every button a reader does not find.
//
// It takes what `respond()` worked out rather than asking again, so the banner
// and the guard that let the request through cannot come to disagree about who
// somebody is.
// ---------------------------------------------------------------------------
const OPEN_BANNER =
  '<div class="warn"><strong>This console is not protected.</strong> ' +
  '<code>admin.authRequired</code> is OFF, so nothing here checks a credential — and nothing ' +
  'else in this service does either: the username typed at the sign-in screen is the identity ' +
  'in every token it issues. Anyone who can reach this port can revoke every token and change ' +
  'what the next one contains. That is fine on a laptop or a compose network and is not fine on ' +
  'a public address. Turn it on from <a href="/admin/config">Configuration</a>, and say who may ' +
  'get in on <a href="/admin/rbac">Admin roles</a>.</div>';

// SAID WHEN — AND ONLY WHEN — THE SESSION BELONGS TO ANOTHER REALM.
//
// The console follows its reader across realms (see `sessionAnywhere()` in
// authn.js), which is what makes the switcher a switcher rather than a
// sign-in screen. Doing it silently would be the wrong kind of quiet: a realm
// is a whole logical copy of this service, so a reader looking at the default
// realm's tokens on a session minted in `acme` is one keystroke from believing
// the two realms share the sessions as well — and the next thing they conclude
// is that `/oauth2/authorize` would have accepted it, which it would not.
//
// So the banner names the realm the session is held by, and says the one thing
// that is easy to get wrong about it. It is empty in every other case,
// including every service that has defined no realm.
function foreignSessionNote(info) {
  if (!info.foreignSession || !info.sessionRealm) {
    return '';
  }
  return ' Your session belongs to the trust realm <strong>' +
    esc(info.sessionRealm.name) + '</strong> (<code>' + esc(info.sessionRealm.id) +
    '</code>) and this console follows it into every realm, because the two ' +
    'console roles are groups in the one shared directory. <strong>The protocol ' +
    'endpoints do not:</strong> in this realm ' +
    '<code>/oauth2/authorize</code>, <code>/wsfed</code> and the two SAML ' +
    'profiles see no session at all and would ask you to sign in. ' +
    '<a href="/admin/realms">What a realm separates</a>.';
}

function gateBanner(gate) {
  log.debug("Entering gateBanner().");
  const info = gate || {};
  if (!info.enforced) {
    log.debug("Leaving gateBanner(). The gate is off.");
    return OPEN_BANNER;
  }
  const who = '<code>' + esc(info.username || '(nobody)') + '</code>';
  const elsewhere = foreignSessionNote(info);
  if (info.open) {
    log.debug("Leaving gateBanner(). The roster is empty.");
    return '<div class="warn"><strong>Signed in as ' + who + ', and holding both roles ' +
      'because NOBODY HOLDS EITHER.</strong> <code>admin.authRequired</code> is on, so this ' +
      'console asked you to sign in — but neither <code>' + esc(info.readGroup) + '</code> nor ' +
      '<code>' + esc(info.writeGroup) + '</code> has a single member, and while that is true ' +
      'anyone who signs in has the whole console. This service has no password to bootstrap an ' +
      'administrator with, which is why the empty roster opens rather than closes ' +
      '(<code>admin.openWhenEmpty</code>). <strong>Grant somebody a role on ' +
      '<a href="/admin/rbac">Admin roles</a></strong> and the roster is enforced from that ' +
      'moment — including against you, so grant yourself one first.' + elsewhere + '</div>';
  }
  if (info.closed) {
    // Rendered for completeness rather than because a reader will meet it: a
    // request in this state is refused before a page is drawn. It is reachable
    // on the refusal page itself, which IS drawn.
    log.debug("Leaving gateBanner(). The roster is empty and closed.");
    return '<div class="err"><strong>Nobody can use this console.</strong> ' +
      '<code>admin.authRequired</code> is on, <code>admin.openWhenEmpty</code> is off, and no ' +
      'role has a member. <code>POST /admin-api/rbac/grant</code> is the way back in — the ' +
      'management API is not gated.</div>';
  }
  const held = (info.roles || []).map(function (id) {
    const role = rbac.roleFor(id);
    return '<strong>' + esc(role ? role.label : id) + '</strong>';
  }).join(' and ');
  log.debug("Leaving gateBanner(). Enforced; " + (info.roles || []).length + " role(s).");
  return '<div class="ok">Signed in as ' + who + ', holding ' +
    (held || '<strong>no console role</strong>') + '. ' +
    (info.write
      ? 'Every control on these pages is yours.'
      : 'This is a READ-ONLY view: the forms are drawn so that you can see what ' +
        'they do, and posting one is refused. ' + esc(info.writeGroup) + ' is the role that ' +
        'changes that.') +
    ' <a href="/admin/rbac">Who holds what</a>. Ending this session: ' +
    '<a href="/logout">/logout</a> signs you out of everything this service holds — every ' +
    'protocol at once — and <a href="/oauth2/logout">/oauth2/logout</a> is OIDC\'s own ' +
    'RP-initiated one. <a href="/admin/logout">/admin/logout</a> is the operator\'s view of ' +
    'the same lists, for somebody else.' + elsewhere + '</div>';
}

// ---------------------------------------------------------------------------
// THE REALM CHOOSER, at the top of the sidebar's own card.
//
// A trust realm is a whole logical copy of this service (common/realms.js), and
// every page here shows exactly one of them — the one whose prefix the request
// arrived under. That is not something a reader can see from the content: an
// empty tokens table looks the same in a realm that has issued nothing as it
// does in a service that has issued nothing, and /admin/config in a realm both
// reads and WRITES that realm. So the realm is named on every page.
//
// It is INSIDE the nav card and above the sections rather than in a card of its
// own. It was its own card, and that was one surface too many in a column whose
// whole job is to be one list: a reader looking for where they are should find
// it at the top of the thing they are already reading.
//
// **IT IS A FORM AND NOT AN onchange, BECAUSE THIS CONSOLE RUNS NO SCRIPT.**
// `script-src 'none'` (common/app.js) is what makes the whole js/reflected-xss
// family moot here rather than merely unlikely, and a select that navigated on
// change would need an inline handler the browser would refuse to run — so the
// control would silently do nothing. A select and a button is the same shape
// every filter on this console already uses.
//
// **THE ACTION IS AN ABSOLUTE URL, and that is required rather than tidy.**
// app.js rewrites every root-relative `href`, `action` and `src` in an HTML
// response to carry the current realm's prefix, which is what makes this file's
// several hundred hand-written links work inside a realm without one of them
// being edited — and it is exactly wrong for the one control whose job is to
// LEAVE the current realm. An absolute URL names a host, so it passes through
// untouched, and the route it reaches is the one at the root.
//
// It draws NOTHING AT ALL when no realm is defined. This console had no such
// control before realms existed and a service that is not using them should not
// grow one — the row would be a permanent "default", which is a control that
// only ever says the same thing.
// ---------------------------------------------------------------------------
const REALM_SWITCH_PATH = '/admin/realm-switch';

// The base URL with the CURRENT realm's prefix taken back off, so that what is
// built from it starts at the root. baseUrlOf() adds the ambient prefix by
// design — this and the switch route below are the two callers in this service
// that do not want it, and they say so here rather than working around it
// somewhere else.
function realmRoot(req) {
  const withRealm = baseUrlOf(req);
  return withRealm.slice(0, withRealm.length - realms.currentPrefix().length);
}

// Where the reader is, INSIDE the realm. req.url has already had the prefix
// stripped by the time any route sees it, which is the whole trick, and is also
// what makes this the path to re-enter in the other realm — so switching lands
// on the same page with the same filter rather than back at /admin.
function realmRelativePath(req) {
  const here = String(req.originalUrl || '/admin');
  return here.slice(realms.currentPrefix().length) || '/admin';
}

// WHERE "REFRESH" POINTS: the page the reader is on, with the message
// parameters taken back off.
//
// Root-relative and WITHOUT the realm prefix, which is the one thing here that
// is easy to get wrong. app.js rewrites every `href="/…` on the way out to
// carry the realm being read, so handing it `req.originalUrl` — which already
// carries one — would produce /realm/acme/realm/acme/admin/tokens and a 404 a
// long way from this function. realmRelativePath() is that same URL with the
// prefix off, which is exactly what the rewrite expects to be given.
//
// `notice` and `error` come off because respondToAction() puts them there on
// the redirect after a form POST: they describe something that has ALREADY
// happened, and a Refresh that carried them would re-announce "12 tokens
// revoked" over a page where nothing had been revoked this time. Everything
// else survives — the filter, the page number, the search — because that is
// what the reader is looking at, which is why this is a subtraction and not a
// bare path.
function refreshHref(req) {
  log.debug("Entering refreshHref().");
  const here = realmRelativePath(req);
  const cut = here.indexOf('?');
  if (cut < 0) {
    log.debug("Leaving refreshHref(). No query string.");
    return here;
  }
  const params = new URLSearchParams(here.slice(cut + 1));
  params.delete('notice');
  params.delete('error');
  const query = params.toString();
  log.debug("Leaving refreshHref(). " + (query ? "Kept " + query : "Kept nothing") + ".");
  return query ? here.slice(0, cut) + '?' + query : here.slice(0, cut);
}

// THE REFRESH CONTROL, at the top of every page in this console.
//
// A LINK RATHER THAN A BUTTON, and this service's own CSP is the reason rather
// than taste: `script-src 'none'` (see CLAUDE.md) means there is no
// `location.reload()` to be had anywhere in here, and a <form method="get"> to
// the same path would silently drop the query string it was submitted with
// unless every parameter were re-emitted as a hidden field. An <a> to the
// current URL fetches the page again either way, because respond() sends every
// page `Cache-Control: no-store` — so this is a real refresh and not a
// possibly-cached one.
//
// It is worth having at all because every page in this console describes LIVE
// state held in memory — counts, sessions, tokens expiring while they are being
// read, a directory something else is writing — so "is this still true?" is a
// question a reader has on all of them, and until now the only answer was the
// browser's own reload with a stale `?notice=` still on the URL.
//
// It is drawn in the QUIET form of a.btn on purpose. It is on every page beside
// the heading, and a solid dark button in that position would read as the most
// important thing on the page on all of them.
function refreshLink(req) {
  return '<a class="btn secondary" href="' + esc(refreshHref(req)) +
    '" title="Load this page again. Everything in this console is live state ' +
    'held in memory.">Refresh</a>';
}

function realmChooser(req) {
  log.debug("Entering realmChooser().");
  if (!realms.active()) {
    log.debug("Leaving realmChooser(). No realms are defined.");
    return '';
  }
  const currentId = realms.currentId();
  const options = realms.list().map(function (realm) {
    return '<option value="' + esc(realm.id) + '"' +
      (realm.id === currentId ? ' selected' : '') + '>' +
      esc(realm.name) + '</option>';
  }).join('');
  log.debug("Leaving realmChooser(). " + realms.count() + " realm(s).");
  return '<form class="realmpick" method="get" action="' +
    esc(realmRoot(req) + REALM_SWITCH_PATH) + '">' +
    '<label for="realmpick">Trust realm</label>' +
    '<input type="hidden" name="to" value="' +
      esc(realmRelativePath(req)) + '">' +
    '<div class="realmpickrow">' +
      '<select id="realmpick" name="realm">' + options + '</select>' +
      '<button class="secondary">Go</button>' +
    '</div></form>';
}

function page(title, active, inner, up, gate, req) {
  log.debug("Entering page(). title=" + title + ", up=" + (up ? up.href : "none"));
  const html = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + esc(title) + ' — mock STS admin</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'padding:2rem 1rem;color:#222;line-height:1.45}' +
    // THE TWO COLUMNS. Flex rather than grid because the behaviour wanted at a
    // narrow width is "the sidebar stops being a column and becomes a block
    // above the page", which is what `flex-wrap` does for nothing — and this
    // console runs no script, so a layout that needed one would not be an
    // option anyway. The sidebar's `flex` is `0 0 auto` with a fixed basis so
    // that a long label wraps inside it instead of widening it and squeezing
    // the tables, which is the failure mode of letting it size to content.
    '.shell{display:flex;flex-wrap:wrap;align-items:flex-start;gap:18px;' +
    'max-width:92rem;margin:0 auto}' +
    '.side{flex:0 0 13.5rem;position:sticky;top:1rem}' +
    // `min-width:0` on a flex child is what stops a wide table inside the card
    // from pushing the whole layout past the viewport: without it the card's
    // minimum width is its content's, and one long DN widens the page rather
    // than scrolling inside its own cell.
    '.main{flex:1 1 32rem;min-width:0}' +
    '.brand{font-size:.82em;font-weight:700;color:#12107c;margin:0 0 2px;letter-spacing:.02em}' +
    '.brandsub{font-size:.72em;color:#666;margin:0 0 14px}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:24px 28px;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}' +
    'h1{font-size:1.35em;margin:0 0 4px;color:#12107c}' +
    // THE HEAD ROW — the title, and the refresh control pushed to the far end
    // of it. `align-items:baseline` so a control that much smaller sits on the
    // heading's baseline rather than being centred against a taller box, and
    // `flex-wrap` so that at a narrow width it drops underneath the title
    // instead of squeezing it to one word a line. The bottom margin is what
    // `p.sub` used to contribute before the issuer line came off this shell;
    // without it every page's breadcrumb trail sits up against its heading.
    '.pagehead{display:flex;flex-wrap:wrap;gap:10px;align-items:baseline;' +
    'justify-content:space-between;margin:0 0 14px}' +
    '.pagehead h1{margin:0}' +
    'h2{font-size:1.05em;margin:1.8em 0 .5em;color:#12107c;border-bottom:1px solid #eee;padding-bottom:.2em}' +
    'h3{font-size:.92em;margin:1.2em 0 .4em}' +
    'p.sub{color:#666;font-size:.85em;margin:0 0 14px}' +
    // THE SIDEBAR. A list per section with a heading over it, in the same card
    // material as the page so the two read as one surface rather than as a
    // frame around a document.
    'nav{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:14px 14px 8px;' +
    'font-size:.85em;box-shadow:0 6px 24px rgba(0,0,0,.06)}' +
    // THE REALM CHOOSER, first inside the nav card and separated from the
    // sections by a hairline rather than by a card of its own. Its label is
    // `.navhead`'s metrics on purpose: it sits above a list of choices in the
    // same column, so anything else would read as a different KIND of thing
    // and put the reader back to wondering which pane it belonged to.
    '.realmpick{margin:0 0 12px;padding:0 0 10px;' +
    'border-bottom:1px solid #e6e6ee}' +
    '.realmpick label{display:block;margin:0 0 4px;font-size:.7em;' +
    'text-transform:uppercase;letter-spacing:.06em;color:#8a8a99;' +
    'font-weight:700}' +
    // The select takes the room and the button takes what it needs, so a long
    // realm name is readable in the column rather than truncated to fit a
    // button beside it.
    '.realmpickrow{display:flex;gap:6px;align-items:stretch}' +
    '.realmpick select{flex:1 1 auto;min-width:0;font-size:1em;padding:3px 4px;' +
    'border:1px solid #c9c9d4;border-radius:5px;background:#fff;color:#222}' +
    '.realmpick button{flex:0 0 auto;padding:3px 9px;font-size:.92em}' +
    '.navsec{margin:0 0 12px}' +
    '.navsec:last-child{margin-bottom:4px}' +
    // The section heading. Not a link and it must not look like one — there is
    // no page behind a section, which is the same reason it is not a crumb.
    '.navhead{margin:0 0 4px;font-size:.7em;text-transform:uppercase;letter-spacing:.06em;' +
    'color:#8a8a99;font-weight:700}' +
    // The section the current page is in. A rule down its left rather than a
    // background, so that the mark reads as "you are in here" and not as a
    // second selected item beside the selected one.
    '.navsec.open{border-left:3px solid #12107c;margin-left:-14px;padding-left:11px}' +
    '.navsec.open .navhead{color:#12107c}' +
    // A GROUP INSIDE A SECTION. It is an <li>, so `nav li` has already given it
    // the item metrics; what these rules do is take the item LOOK back off it
    // (it is a heading with a list under it, not a thing to click) and indent
    // the list it holds behind a hairline, which is what says "these three are
    // one thing" without a second colour or a box.
    '.navgrp{margin:6px 0 4px}' +
    // The group heading. Smaller than the section's and sentence-cased rather
    // than upper, so that two headings above one link cannot be read as two
    // sections — the section is the shout, the group is the aside.
    '.navsub{margin:0 0 3px;padding:0 6px;font-size:.78em;color:#6a6a80;' +
    'font-weight:700;letter-spacing:.01em}' +
    '.navgrp.open .navsub{color:#12107c}' +
    '.navgrp>ul{margin:0;padding-left:8px;border-left:1px solid #e2e2ea}' +
    '.navgrp.open>ul{border-left-color:#c3c0e0}' +
    'nav ul{list-style:none;margin:0;padding:0}' +
    'nav li{margin:0;font-size:1em}' +
    'nav a,nav .here{display:block;padding:3px 6px;border-radius:5px;text-decoration:none;' +
    'line-height:1.3}' +
    'nav a{color:#12107c}nav a:hover{background:#f0f0f7}' +
    'nav .here{font-weight:700;color:#222;background:#eceaf6}' +
    // The active item on a DRILL-DOWN. It keeps the weight and the fill `.here`
    // gives it, because the reader is still inside that section, and takes back
    // the link colour and an underline, because it is a link again and a bold
    // black label reads as text nobody can click — which is exactly what it was.
    'nav a.here{color:#12107c;text-decoration:underline;background:#eceaf6}' +
    '.crumb{font-size:.82em;margin:0 0 14px;color:#666}' +
    '.crumb a{text-decoration:none;font-weight:600}' +
    '.crumb a:hover{text-decoration:underline}' +
    '.crumb .sep{margin:0 .45em;color:#aaa}' +
    // The last crumb is the page being drawn. It is not a link and must not look
    // like one, or the one crumb that does nothing is the one a reader clicks.
    '.crumb .leaf{color:#222;font-weight:600}' +
    '.warn{background:#fff8e1;border:1px solid #ffe082;padding:9px 12px;border-radius:5px;' +
    'font-size:.82em;margin:0 0 16px}' +
    '.ok{background:#e8f5e9;border:1px solid #a5d6a7;padding:8px 11px;border-radius:5px;' +
    'font-size:.85em;margin:0 0 14px}' +
    '.err{background:#fdecea;border:1px solid #f5c6c2;color:#b00020;padding:8px 11px;border-radius:5px;' +
    'font-size:.85em;margin:0 0 14px}' +
    '.tiles{display:flex;flex-wrap:wrap;gap:10px;margin:.6em 0 1em}' +
    '.tile{border:1px solid #e2e2ea;border-radius:8px;padding:10px 14px;min-width:9rem;background:#fbfbfd}' +
    '.tile .n{font-size:1.5em;font-weight:700;color:#12107c;line-height:1.1}' +
    '.tile .l{font-size:.74em;color:#666;text-transform:uppercase;letter-spacing:.03em}' +
    'table{border-collapse:collapse;width:100%;margin:.4rem 0 .9rem;font-size:.8em}' +
    'th,td{border:1px solid #e2e2ea;padding:.3rem .5rem;text-align:left;vertical-align:top}' +
    'th{background:#f0f0f5;font-weight:600}tr:nth-child(even) td{background:#fafafc}' +
    'td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}' +
    // A cell holding a list of opaque identifiers. `overflow-wrap:anywhere` is the
    // one that also shrinks the cell's MINIMUM width, which is the property that
    // matters: break-all alone wraps the text and still lets one unbreakable
    // did:jwk widen the whole table past the card it sits in.
    'td.who{overflow-wrap:anywhere;line-height:1.9}' +
    'td.who code{white-space:normal}' +
    '.state-valid{color:#0b6b4f;font-weight:600}.state-expired{color:#8a6d00}' +
    '.state-revoked{color:#b00020;font-weight:600}.state-none{color:#666}' +
    'form.inline{display:inline;margin:0}' +
    'button{padding:5px 10px;border-radius:5px;border:1px solid #12107c;background:#12107c;color:#fff;' +
    'font-size:.8em;cursor:pointer}button.secondary{background:#fff;color:#12107c}' +
    'button.danger{background:#b00020;border-color:#b00020}' +
    // `number` joined this list with /admin/token-lifetimes, whose four inputs
    // are the console's first. Without it they are the one control in the card
    // drawn in the browser's default chrome, beside a form that matches
    // everything else — which reads as a half-finished page rather than as a
    // missing selector.
    'input[type=text],input[type=number],textarea,select{box-sizing:border-box;padding:6px 8px;border:1px solid #bbb;' +
    'border-radius:5px;font-size:.85em;font-family:inherit}' +
    'textarea{width:100%;min-height:7rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}' +
    '.formrow{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:.5em 0}' +
    '.formrow label{font-size:.78em;font-weight:600;color:#555}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em;background:#f4f4f8;' +
    'padding:.1rem .25rem;border-radius:3px;word-break:break-all}a{color:#12107c}' +
    '.note{font-size:.78em;color:#666;margin:.3em 0 1em}' +
    // THE OVERVIEW PAGE'S DERIVED LIST OF EVERY PAGE HERE (consoleGuide()).
    // Its shape is the sidebar's — sections, one group level under Protocols,
    // pages under that — so it is given the sidebar's rhythm rather than the
    // body text's: the section heading close to its own list, the section's
    // `what` tight under the heading rather than at `.note`'s full paragraph
    // spacing, and a group's title and description on their own lines above
    // its three pages. Without the last of those a group reads as a fourth
    // page whose blurb happens to be long.
    '.guide h3{margin:1.6em 0 .1em;color:#12107c}' +
    '.guide p.note{margin:.1em 0 .5em}' +
    '.guide li{margin:.5em 0}' +
    '.guide .grp{display:block;font-weight:700;color:#12107c}' +
    '.guide .grpwhat{display:block;font-size:.92em;color:#666;margin:.1em 0 .2em}' +
    // A page in the nav that nobody described. Marked rather than dropped —
    // see consoleGuide() — so it has to LOOK like a report and not like prose
    // somebody wrote on purpose.
    '.guide .undescribed{color:#a33}' +
    '.meta{margin-top:22px;padding-top:12px;border-top:1px solid #eee;font-size:.76em;color:#666}' +
    '.meta div{margin:3px 0}ul{margin:.3em 0;padding-left:1.2em}li{margin:.25em 0;font-size:.85em}' +
    '.pagenav{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:.5em 0;font-size:.8em}' +
    '.pagenav a,.pagenav .here,.pagenav .off{display:inline-block;padding:3px 8px;border-radius:5px;' +
    'border:1px solid #d5d5dd;background:#fff;text-decoration:none;min-width:1.6em;text-align:center}' +
    '.pagenav .here{background:#12107c;border-color:#12107c;color:#fff;font-weight:700}' +
    '.pagenav .off{color:#aaa;background:#f7f7fa}' +
    '.pagenav .where{border:0;background:none;color:#666;padding-left:.4em}' +
    // ---------------------------------------------------------------------
    // THE SERVICE METADATA PAGE'S OWN CLASSES, AND WHY THEY ARE IN THIS FILE
    // RATHER THAN IN THE ONE THAT USES THEM.
    //
    // `/admin/sts-metadata` is built by `../sts_metadata.js` — it derives its
    // whole content from the live express router, which is why it is the last
    // module server.js loads — but it is drawn by page() like every other
    // console page, and page() emits the ONLY <style> this console has. A
    // <style> of its own would have to sit inside <body>, which browsers accept
    // and no validator does, and there would then be two stylesheets to keep in
    // step. So its classes live here, the way .tile's and .state-valid's do: a
    // shared stylesheet with a few page-specific rules in it.
    // ---------------------------------------------------------------------
    // A paragraph of explanation above a table. Wider and quieter than body
    // text; `.sub` is the page subtitle and cannot double as this, because that
    // one is metrics-sized and appears once.
    '.lead{color:#555;font-size:.85em;margin:0 0 12px;max-width:62rem}' +
    '.m{font-weight:600;color:#0b6b4f;white-space:nowrap}' +
    '.none{color:#999}' +
    // Why a path is not a link, beside the path. Italic and grey because it is
    // an aside about the row rather than part of it.
    '.why{color:#999;font-size:.85em;font-style:italic}' +
    '.eff{color:#b26a00;cursor:help}' +
    '.bad{color:#b00020;font-weight:600}' +
    'td.p{width:22%}td.n{width:16%}td.s{width:14%}' +
    'td.p a{text-decoration:none}td.p a:hover code{text-decoration:underline}' +
    // A LINK THAT LOOKS LIKE A BUTTON, which is not decoration here: the
    // download control has to be an <a download> — this service serves no
    // script anywhere, so nothing else can hand a browser a file — and a
    // control that saves a document should not read as a sentence.
    'a.btn{display:inline-block;padding:5px 10px;border-radius:5px;' +
    'border:1px solid #12107c;background:#12107c;color:#fff;font-size:.8em;' +
    'text-decoration:none}' +
    'a.btn:hover{background:#0d0b5e;color:#fff}' +
    // The quiet form, matching button.secondary below, for a link that is on
    // every page and is nobody's next action. Both rules out-specify the two
    // above them, so the order they are written in here does not matter.
    'a.btn.secondary{background:#fff;color:#12107c}' +
    'a.btn.secondary:hover{background:#eef0fb;color:#12107c}' +
    // The protocol cards at the top of that page. Flex rather than grid for the
    // reason the shell is: what is wanted at a narrow width is "the row becomes
    // fewer columns", which flex-wrap does for nothing. `flex:1 1 15rem` lets
    // the last row stretch rather than leaving a ragged gap.
    '.protos{display:flex;flex-wrap:wrap;gap:9px;margin:.6em 0 1.4em}' +
    '.proto{flex:1 1 15rem;border:1px solid #e2e2ea;border-radius:8px;' +
    'padding:9px 12px;background:#fbfbfd}' +
    '.proto a,.proto .n{font-weight:700;font-size:.85em;line-height:1.3}' +
    '.proto .n{color:#222}' +
    '.proto .d{font-size:.75em;color:#666;margin-top:3px;line-height:1.4}' +
    // The count and the specification links. Smallest thing on the card,
    // because it is the one part a reader scans rather than reads.
    '.proto .c{font-size:.72em;color:#8a8a99;margin-top:5px}' +
    // ---------------------------------------------------------------------
    // /admin/delegation/map's OWN CLASSES, here for the reason the service
    // metadata page's are: page() emits the console's ONLY <style>, and a
    // second one inside <body> is markup no validator accepts.
    // ---------------------------------------------------------------------
    // THE FRAME ROUND THE DIAGRAM, AND `overflow:auto` IS THE WHOLE OF IT. An
    // SVG is generated at its natural size and a busy one is wider than the
    // card; without this the picture either widens the page past the viewport
    // (the failure `min-width:0` on `.main` exists to prevent, arriving by
    // another door) or is squeezed to fit and becomes unreadable. It scrolls
    // inside its own box instead, and the filter above it is how a reader makes
    // it small enough not to need to.
    '.diagram{overflow:auto;max-width:100%;border:1px solid #e2e2ea;' +
    'border-radius:8px;background:#fff;padding:12px;margin:.6em 0 .4em}' +
    // `max-width:none` states that the picture is not to be scaled to the box,
    // because a diagram scaled down is one whose labels have stopped being
    // legible while still looking as though they should be.
    '.diagram svg{display:block;max-width:none}' +
    // The key. A table like every other, with the shape column sized to the
    // swatches rather than to its heading.
    'table.key td.art{width:5.5rem;text-align:center;vertical-align:middle;' +
    'background:#fff}' +
    'table.key td.art svg{vertical-align:middle}' +
        // The narrow case. One breakpoint and no more: below it the sidebar stops
    // being sticky and sits above the page as an ordinary block, which is what
    // flex-wrap has already done to it by then — the rule only undoes the
    // stickiness, which on a full-width block would pin the whole nav to the
    // top of the viewport and take the screen with it.
    '@media (max-width:56rem){.side{position:static;flex:1 1 100%}' +
    '.navsec{display:inline-block;vertical-align:top;min-width:11rem;margin-right:1.2em}' +
    '.navsec.open{margin-left:0;padding-left:0;border-left:0;border-top:3px solid #12107c;' +
    'padding-top:6px}}' +
    '</style></head><body><div class="shell">' +
    '<aside class="side">' +
    '<p class="brand">Mock STS admin</p>' +
    // WHAT THIS SERVICE IS AND WHICH REALM YOU ARE IN, rather than the WS-Trust
    // issuer identifier that used to be here.
    //
    // That identifier is `wstrust.issuer`, and it was never the name of this
    // service — it is what ONE of the sixteen protocol families puts in an
    // <Issuer> element. In the corner of a console whose other fifteen families
    // never mention it, it read as the service's identity and is not; and it is
    // the one line on the page that is drawn before the reader knows what the
    // page is about, so it should say something true of the whole of it.
    //
    // THE REALM IS THE THING WORTH SAYING THERE. Every page in this console
    // shows exactly one realm, `/admin/config` WRITES the one it is read in, and
    // a realm is a whole logical copy of this service — so "which one am I
    // looking at" is the question a reader most needs answered before they act.
    // The switcher below says it too, but only when a realm has been DEFINED:
    // it is absent in the ordinary case, which is precisely the case where the
    // corner was saying nothing useful at all.
    //
    // THE ISSUER IDENTIFIER IS NOT IN THIS SHELL AT ALL ANY MORE, and that is
    // the second half of one decision rather than a later reversal of it. It
    // came out of this corner on 2026-08-24 into the line under the heading,
    // and off the shell entirely on 2026-08-25, for the reason above read once
    // more: a name that ONE of sixteen protocol families uses, repeated at the
    // top of every page in the console, reads as the service's identity on all
    // of them and means something on the handful about WS-Trust.
    //
    // NOTHING IS LOST, and here is where each half of it went. It is on
    // `/admin/sts-metadata`, the one page whose subject is what this service
    // IS; it is on `/admin/config` under WS-Trust, which is where it is SET;
    // and it is in this line's tooltip, because somebody who had learnt to read
    // it off the shell should find it where they look rather than have to hunt.
    '<p class="brandsub" title="' +
      esc('This console is showing the trust realm "' + realms.current().name +
          '" (id: ' + realms.currentId() + '). Its WS-Trust issuer identifier ' +
          'is ' + config.value('wstrust.issuer') + ', which is what that ' +
          'protocol puts in an <Issuer> element and is not the name of this ' +
          'service.') +
      '">Mock STS &middot; ' + esc(realms.current().name) + '</p>' +
    navBar(active, up, req) +
    '</aside><div class="main"><div class="card">' +
    // THE HEAD ROW: the page's title, and the one control that is on every
    // page of this console. See refreshLink() for why it is a link.
    '<div class="pagehead"><h1>' + esc(title) + '</h1>' + refreshLink(req) + '</div>' +
    trailBar(active, up, title) + gateBanner(gate) + inner +
    '<div class="meta">' +
    '<div>Everything on these pages is held in memory and dies with the process, like the signing ' +
    'key this service regenerates on every start. There is nothing to persist and a statistics file ' +
    'that outlived the key that signed the tokens it described would be worse than none.</div>' +
    '<div>Every page here also answers <code>?format=json</code>, and every form also accepts a ' +
    'JSON body, so a test can drive this console without a browser.</div>' +
    // FOUR closing divs now, not two: the .meta block, the .card it is inside,
    // the .main column that holds the card and the .shell that holds the two
    // columns. Getting this wrong leaves a document that renders and does not
    // parse, which is the kind of thing only a parser notices — and with a flex
    // layout it is worse than that, because one missing tag nests the next
    // page's sidebar inside the last one's card and the failure looks like a CSS
    // bug.
    '</div></div></div></div></body></html>\n';
  log.debug("Leaving page(). " + html.length + " bytes.");
  return html;
}

// Both response shapes for a page, chosen by ?format=json. `no-store` on all of
// them: they describe live state, and a cached metrics page is a wrong one.
// `up`, when given, is what upTo() returned for the section this page hangs
// under. Only a drill-down passes it; a section's own list page does not, and the
// JSON answer ignores it either way — a way back up is a property of a page a
// person is reading, and a caller of ?format=json has the URL it asked for.
function respond(req, res, json, title, active, html, up) {
  log.debug("Entering respond(). title=" + title);
  res.set('Cache-Control', 'no-store');
  if (String(req.query.format || '') === 'json') {
    res.status(200).type('application/json').send(JSON.stringify(json, null, 2));
    log.debug("Leaving respond(). Answered JSON.");
    return;
  }
  res.status(200).type('text/html').send(page(title, active, html, up, gateStateFor(req), req));
  log.debug("Leaving respond(). Answered HTML.");
}

// A POST answers the way it was asked: JSON in, JSON out; a form, and the browser
// is sent back to the page it came from with a message. The redirect is a 303 so
// that the reload after it is a GET — a 302 here leaves the browser able to repeat
// the POST on refresh, which for "revoke everything" is a surprise.
function respondToAction(req, res, target, result) {
  log.debug("Entering respondToAction(). ok=" + result.ok);
  const type = String(req.headers['content-type'] || '');
  if (/json/i.test(type)) {
    res.status(result.ok ? 200 : 400).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(result, null, 2));
    log.debug("Leaving respondToAction(). Answered JSON.");
    return;
  }
  const key = result.ok ? 'notice' : 'error';
  const message = result.ok ? result.message : (result.errors || []).join(' ');
  // `&` when the target already carries a query string, `?` when it does not. The
  // tokens page sends the reader back to the page and filter the button was on, so
  // this is no longer always a bare path — and a second `?` does not start a second
  // query string, it becomes part of the previous parameter's value, which loses the
  // message and corrupts the parameter it landed on in one go.
  const joiner = target.indexOf('?') < 0 ? '?' : '&';
  res.set('Cache-Control', 'no-store')
     .redirect(303, target + joiner + key + '=' + encodeURIComponent(String(message).slice(0, 500)));
  log.debug("Leaving respondToAction(). Redirected to " + target + ".");
}

// ---------------------------------------------------------------------------
// THE GATE. WHO GETS INTO THIS CONSOLE AT ALL.
//
// It is ONE `app.use('/admin', ...)` registered here, above every route in this
// file, and that placement is the whole of how it works: express applies
// middleware only to routes added AFTER it (rule 1), so a route added below this
// line is guarded and a route added above it would not be. There are none above
// it, and a new console page must go below — which it will, since every route in
// this file is below.
//
// FOUR THINGS ABOUT IT ARE DELIBERATE.
//
// **It authenticates NOTHING itself.** `authn.js` owns the session and the
// sign-in screen; this asks `sessionAnywhere()` who is here and, when nobody is,
// sends the browser to `beginAuthentication()`'s URL with the page they wanted stashed
// on the pending record. A login screen of this console's own would be a second
// authentication service, and the one consequence of sharing the first is the
// good one: sign in at `/authn/login` with a security key and this console knows
// it, because it is the same session WS-Federation and the authorization
// endpoint read.
//
// **A BROWSER IS REDIRECTED AND A PROGRAM IS REFUSED, and telling them apart is
// not a nicety.** Every page here answers `?format=json` and every form accepts
// a JSON body, precisely so a test can drive this console without a browser —
// and a 302 to an HTML login screen is not an answer such a caller can read. It
// would arrive as a 200 full of markup where JSON was expected, which is the
// shape of failure that costs an afternoon. So: `?format=json`, a JSON
// content-type or an `Accept` that asks for JSON gets 401 or 403 with a body
// saying which, and everything else gets the screen.
//
// **IT GUARDS `/admin` AND NOT `/admin-api`.** Express matches a `use` path on
// segment boundaries, so `/admin-api` does not match `/admin` — that is not an
// accident being relied on, it is the arrangement: the management API stays open
// (`mgmt-api/CLAUDE.md` rule 7 covers what that costs) and is therefore the way
// back in for somebody who has locked themselves out of the console, which is a
// state `admin.openWhenEmpty: false` makes reachable. It is also why turning
// this on does not break the parent project's `tests/admin_api.js`.
//
// **A REFUSAL IS A PAGE AND NOT A BARE STATUS.** 403 with an empty body is the
// single least useful thing this could answer: the reader is signed in, the
// console plainly exists, and nothing tells them that a directory group is what
// they are missing. The refusal names the role, names the group, and says which
// four doors can grant it.
// ---------------------------------------------------------------------------

// Everything the banner and the guard both need, worked out ONCE per request.
//
// Both were written separately at first and disagreed within the hour: the guard
// let somebody through on the empty-roster rule and the banner, asking again,
// found a roster that a concurrent grant had just filled — so the page said
// "signed in, holding no role" above a console it had just allowed. One function,
// one answer.
function gateStateFor(req) {
  log.debug("Entering gateStateFor().");
  const enforced = !!config.value('admin.authRequired');
  // THE DEFAULT REALM'S SESSION, whichever realm is being read, and only here —
  // see the require at the top of this file for why the console asks the
  // question that way and why no other module may.
  const found = consoleSession(req);
  const session = found ? found.session : null;
  const username = session ? session.user.username : '';
  const held = rbac.rolesOf(username);
  const state = {
    enforced: enforced,
    available: rbac.available(),
    session: session,
    username: username,
    readGroup: config.value('admin.readGroup'),
    writeGroup: config.value('admin.writeGroup'),
    // With the gate OFF everybody may do everything, which is what this console
    // did before any of this existed. Said as `true` here rather than checked
    // separately at each call site, so a caller cannot ask "may they write" and
    // get an answer that ignores the setting.
    // WHICH REALM'S MAP HOLDS THE SESSION, and whether that is the realm being
    // read. Carried on the state rather than worked out again in the banner,
    // for the reason the whole of this function exists: two answers to one
    // question drift within the hour. `sessionRealm` is null when nobody is
    // signed in, and `foreignSession` is false in a service with no realms —
    // which is what keeps every banner in that service the sentence it was.
    sessionRealm: found ? found.realm : null,
    foreignSession: !!(found && found.foreign),
    read: enforced ? held.read : true,
    write: enforced ? held.write : true,
    roles: enforced ? held.roles : rbac.ROLE_IDS.slice(0),
    open: enforced && held.open,
    closed: enforced && held.empty && !held.open && !held.roles.length,
    empty: held.empty
  };
  log.debug("Leaving gateStateFor(). enforced=" + enforced + ", read=" + state.read +
            ", write=" + state.write + ".");
  return state;
}

// Does this caller want JSON rather than a page? See the header for why the
// question matters more than it looks.
//
// `?format=json` is first because it is the one this console documents on every
// page. The content-type is what a form-less POST carries. `Accept` is last and
// is checked for JSON BEFORE html deliberately: a browser sends
// `text/html,...,*/*` and would match a naive "does it mention json" test on the
// wildcard alone, so the html half is what decides when both are present.
function wantsJson(req) {
  if (String((req.query || {}).format || '') === 'json') {
    return true;
  }
  if (/json/i.test(String(req.headers['content-type'] || ''))) {
    return true;
  }
  const accept = String(req.headers.accept || '');
  return /json/i.test(accept) && !/text\/html/i.test(accept);
}

// A refusal, in whichever of the two shapes the caller can read. The HTML one
// goes through page() like everything else, so it carries the nav and the
// banner: a reader who is refused one page can still see the ones they are
// allowed, which is the difference between a permission and a wall.
function refuse(req, res, status, code, title, message, detail) {
  log.debug("Entering refuse(). status=" + status + ", code=" + code);
  res.set('Cache-Control', 'no-store');
  if (wantsJson(req)) {
    res.status(status).type('application/json').send(JSON.stringify({
      error: code,
      error_description: message,
      // Named rather than left to be inferred from the status, because the two
      // refusals are genuinely different instructions — one says "sign in", the
      // other says "you are signed in and it is not enough" — and a client that
      // retried the second the way it retries the first would loop.
      needed: detail.needed || '',
      group: detail.group || '',
      signIn: detail.signIn || '',
      roles: detail.roles || []
    }, null, 2));
    log.debug("Leaving refuse(). Answered JSON.");
    return;
  }
  const inner = '<div class="err"><strong>' + esc(title) + '</strong> ' + esc(message) + '</div>' +
    (detail.html || '');
  res.status(status).type('text/html')
     .send(page(title, '', inner, null, gateStateFor(req), req));
  log.debug("Leaving refuse(). Answered HTML.");
}

// The default realm's sign-in screen as an ABSOLUTE URL. See the note at its
// one caller for why absolute: a root-relative href in an HTML body is rewritten
// by app.js to carry the realm being read, and this link must not be.
function defaultRealmSignInUrl(req) {
  return realms.run(realms.DEFAULT_REALM, function () {
    return baseUrlOf(req) + LOGIN_PATH;
  });
}

// ---------------------------------------------------------------------------
// WHERE THE CONSOLE SENDS SOMEBODY TO SIGN IN, AND WHY IT IS NEVER THIS REALM'S
// LOGIN SCREEN.
//
// The gate accepts the DEFAULT realm's session and nothing else (see
// `consoleSession()`), so the sign-in it sends an anonymous reader to has to
// mint one there. Two things stand in the way of just handing back LOGIN_PATH,
// and both are `app.js` doing exactly what it was built to do:
//
//   * `res.location()` is wrapped in a realm to prepend that realm's prefix, so
//     `/authn/login` becomes `/realm/acme/authn/login` on the way out;
//   * `beginAuthentication()` stashes the pending transaction in a per-realm
//     store, so a record created while `acme` is ambient cannot be redeemed at
//     the default realm's screen — the reader would arrive at a sign-in that
//     had never heard of the page they asked for.
//
// Running BOTH inside `realms.run(DEFAULT_REALM, …)` settles both at once: the
// record lands in the default realm's store, and `realms.href()` — which reads
// the prefix at call time — prepends nothing. The URL that comes out is
// `/authn/login?authn=…`, which is what it says.
//
// `returnTo` is deliberately NOT run in the default realm. It is
// `req.originalUrl`, which `app.js` leaves alone precisely so that it still
// carries the realm — `/realm/acme/admin/users` — so signing in at the default
// realm's screen returns the reader to the realm's page they asked for. That is
// the whole shape of this feature in one line: sign in once, in one realm, read
// every realm.
// ---------------------------------------------------------------------------
function sendToConsoleSignIn(req, res) {
  log.debug("Entering sendToConsoleSignIn().");
  realms.run(realms.DEFAULT_REALM, function () {
    const where = beginAuthentication({
      returnTo: String(req.originalUrl || '/admin'),
      protocol: 'Admin console',
      details: [
        { label: 'Signing in to', value: 'the mock STS admin console' },
        { label: 'Page you asked for', value: String(req.originalUrl || '/admin') },
        // Said on the screen rather than only here, because the person about
        // to type a username is exactly the one who needs to know that the
        // username decides whether the console lets them in.
        { label: 'What decides access',
          value: 'membership of ' + config.value('admin.readGroup') + ' or ' +
                 config.value('admin.writeGroup') + ' in the directory' },
        // And WHICH directory, because there are several now and only one of
        // them decides this. A reader who has just created a realm and put
        // themselves in its admin group would otherwise be refused with no way
        // to tell why.
        { label: 'Which directory', value: 'the DEFAULT realm\'s ou=groups. A ' +
          'trust realm has its own directory and its own groups, and neither ' +
          'grants this console.' }
      ]
    });
    res.set('Cache-Control', 'no-store').redirect(302, where);
  });
  log.debug("Leaving sendToConsoleSignIn().");
}

app.use('/admin', function (req, res, next) {
  log.debug("Entering the admin console gate. " + req.method + " " + req.originalUrl);
  if (!config.value('admin.authRequired')) {
    log.debug("Leaving the admin console gate. admin.authRequired is off; everything is allowed.");
    next();
    return;
  }

  const state = gateStateFor(req);

  if (!state.session) {
    if (wantsJson(req)) {
      refuse(req, res, 401, 'login_required',
             'Sign in first.',
             'This console needs a browser sign-on session from the DEFAULT ' +
             'realm\'s ' + LOGIN_PATH + ', and this request carries none. It has ' +
             'to be that realm\'s: a trust realm has its own directory and its ' +
             'own groups, and the two roles this console decides from are ' +
             'groups in the default realm\'s ou=groups only. The session is a ' +
             'cookie, so a program driving this console has to sign in at that ' +
             'screen and keep it — or turn admin.authRequired off, or use ' +
             '/admin-api, which is not gated.',
             { needed: 'session', signIn: LOGIN_PATH, signInRealm: realms.DEFAULT_ID });
      log.debug("Leaving the admin console gate. Refused 401 to a JSON caller.");
      return;
    }
    // GET and HEAD only. A POST with no session is NOT redirected: the browser
    // would repeat it as a GET after signing in — a 303 turns the method into
    // GET by definition — and the form's fields would be gone, so "revoke
    // everything" would come back as a page view of the tokens list with the
    // click silently discarded. Better to say what happened and let them post it
    // again.
    if (req.method === 'GET' || req.method === 'HEAD') {
      sendToConsoleSignIn(req, res);
      log.debug("Leaving the admin console gate. Sent to the sign-in screen.");
      return;
    }
    refuse(req, res, 401, 'login_required', 'Sign in first.',
           'This form needs a browser sign-on session and this request carries none — ' +
           'the session it was posted with has probably expired.',
           { needed: 'session', signIn: LOGIN_PATH, signInRealm: realms.DEFAULT_ID,
             // AN ABSOLUTE URL, and that is not decoration. `app.js` rewrites
             // every root-relative href in an HTML response to carry the realm
             // being read, so `href="/authn/login"` would send this reader to
             // THIS realm's sign-in screen — where they would sign in
             // successfully and still be refused, because the gate accepts the
             // default realm's session only. An absolute URL is not matched by
             // that rewrite, which is what makes it the right shape here rather
             // than a way around it.
             html: '<p class="note"><a href="' + esc(defaultRealmSignInUrl(req)) +
                   '">Sign in to the default realm</a>, then post ' +
                   'the form again. It is not resubmitted for you: a redirect after a POST ' +
                   'becomes a GET and the fields would be lost, so a control you did not ' +
                   'press twice would not fire twice.</p>' });
    log.debug("Leaving the admin console gate. Refused 401 to a form POST.");
    return;
  }

  // WRITE for anything that is not a read. Every control on this console is a
  // POST — there is no script here, so nothing uses any other method — and the
  // test is written as "not GET and not HEAD" rather than "is POST" so that a
  // method added later is refused by default rather than allowed by omission.
  const needsWrite = req.method !== 'GET' && req.method !== 'HEAD';
  if (needsWrite ? state.write : state.read) {
    log.debug("Leaving the admin console gate. Allowed: " + state.username + " holds " +
              (state.roles.join(', ') || '(the empty roster)') + ".");
    next();
    return;
  }

  const group = needsWrite ? state.writeGroup : state.readGroup;
  const role = rbac.roleFor(needsWrite ? 'write' : 'read');
  refuse(req, res, 403, 'insufficient_role',
         'You are signed in and that is not enough.',
         'Signed in as ' + state.username + ', holding ' +
         (state.roles.length ? state.roles.join(' and ') : 'no console role') + '. ' +
         (needsWrite ? 'Posting a form on this console' : 'Reading this console') +
         ' needs ' + role.label + ', which is membership of cn=' + group + '.',
         { needed: needsWrite ? 'write' : 'read', group: group,
           roles: state.roles,
           html: '<p class="note">The role is an ordinary group in the embedded LDAP ' +
                 'directory, and there are four doors onto it: the <a href="/admin/rbac">Admin ' +
                 'roles</a> screen (which you also need a role to use), ' +
                 '<code>POST /admin-api/rbac/grant</code> (the management API is NOT gated, ' +
                 'so this is the one that works from here), an <code>ldapmodify</code> on 389 ' +
                 'or 636, and a SCIM PATCH of the group.</p>' +
                 '<p class="note">Nothing else about this service is affected. Every protocol ' +
                 'endpoint is exactly as open as it was — these two groups grant this console ' +
                 'and nothing else.</p>' });
  log.debug("Leaving the admin console gate. Refused 403 to " + state.username + ".");
});

// The message a redirect brought back, if any. Escaped where it is rendered; capped
// where it is read, so a hand-written URL cannot make the page arbitrarily long.
function messagesOf(req) {
  const notice = String(req.query.notice || '').slice(0, 500);
  const error = String(req.query.error || '').slice(0, 500);
  return (notice ? '<div class="ok">' + esc(notice) + '</div>' : '') +
         (error ? '<div class="err">' + esc(error) + '</div>' : '');
}

function tile(n, label) {
  return '<div class="tile"><div class="n">' + esc(n) + '</div><div class="l">' + esc(label) + '</div></div>';
}

// The three formatters below are deliberately without entering/leaving logs: they
// are called once per table cell and would drown everything else in the log.
function whenText(ms) {
  if (!ms) return '—';
  return new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}

function durationText(ms) {
  const s = Math.floor((ms || 0) / 1000);
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  const parts = [];
  if (days) parts.push(days + 'd');
  if (days || hours) parts.push(hours + 'h');
  parts.push(minutes + 'm');
  parts.push((s % 60) + 's');
  return parts.join(' ');
}

function stateClass(state) {
  if (state === 'valid') return 'state-valid';
  if (state === 'expired' || state === 'not yet valid') return 'state-expired';
  if (state === 'revoked') return 'state-revoked';
  return 'state-none';
}

// A long opaque value, shortened for the table but recoverable: the full string is
// the title attribute, so it can be hovered and read. Truncating with no way back
// would make the jti column decorative, and the jti is the thing every button on
// the tokens page acts on.
function shortened(value, keep) {
  const text = String(value || '');
  if (text.length <= (keep || 18)) return '<code title="' + esc(text) + '">' + esc(text || '—') + '</code>';
  return '<code title="' + esc(text) + '">' + esc(text.slice(0, keep || 18)) + '&hellip;</code>';
}

// ---------------------------------------------------------------------------
// One table, three families.
//
// The tokens page lists JWTs, SAML assertions and Kerberos tickets together and
// newest first, because that is the order they happened in: a WS-Federation
// sign-in that produced an ID Token and a SAML 1.1 assertion is one event, and a
// page that showed the two halves of it in two places would be a page somebody has
// to correlate by timestamp by hand.
//
// What that costs is that most columns mean something slightly different depending
// on which family the row belongs to, and the way a table like that goes wrong is a
// column that quietly means two things. So the mapping is written down twice over:
// once here as ONE FUNCTION PER COLUMN answering for all three families — which is
// what makes a header like "Client, audience or service" checkable against the
// three answers underneath it — and once on the page itself as a legend, for the
// reader, who cannot see this comment.
//
// Which families exist and what is in them is decided in admin_stats.js. Nothing
// here chooses what the list contains; these functions only say how a row is drawn.
// ---------------------------------------------------------------------------

// A JWT has two names for one person — the `username` that was typed at the login
// screen and the `sub` derived from it — and seeing both is how you tell those two
// apart. A SAML NameID and a Kerberos client principal are ONE name each, so they
// fill the Subject column and leave this one empty rather than being printed twice
// to avoid an empty cell.
function userCell(record) {
  if (record.family === 'token') return esc(record.username || '—');
  return '<span class="state-none" title="' +
    esc('A SAML assertion names a Subject and a Kerberos ticket names a client principal. ' +
        'Neither carries a second, human-readable name beside it the way a JWT carries ' +
        'username beside sub, so the one name it has is in the Subject column.') +
    '">—</span>';
}

function subjectCell(record) {
  if (record.family === 'token') return shortened(record.sub, 30);
  return shortened(record.subject, 30);
}

// Who it was issued FOR: the party meant to accept it.
function partyCell(record) {
  if (record.family === 'assertion') {
    if (record.audience) return shortened(record.audience, 30);
    return '<span class="state-none" title="' +
      esc('This assertion carries no AudienceRestriction — WS-Trust was asked to Issue with no ' +
          'AppliesTo. Any relying party may accept it, which is the thing an audience restriction ' +
          'exists to prevent, so it is named here rather than shown as a dash.') +
      '">unrestricted</span>';
  }
  if (record.family === 'ticket') {
    // The realm recorded with a ticket is the realm that ANSWERED, which under a
    // cross-realm referral is not the service's own realm. So it is stated as the
    // issuer in the tooltip rather than appended to the service name as though it
    // were part of the principal — which is what it would look like, since a
    // Kerberos principal is written service/host@REALM.
    return '<code title="' + esc(String(record.service || '') +
      (record.realm ? ' — issued by the ' + record.realm + ' KDC' : '')) + '">' +
      esc(record.service || '—') + '</code>';
  }
  return esc(record.client_id || '—');
}

// The one extra fact each family has that no other column has room for. It is
// headed Detail rather than Scope, because the three are not answers to the same
// question — a scope says what an access token authorises, an enc-type says which
// cipher sealed a ticket — and a header naming one of them would make the other two
// rows look like answers to it.
function detailCell(record) {
  if (record.family === 'assertion') {
    if (record.signed === false) {
      return '<span class="state-revoked" title="' +
        esc('Signing threw and the assertion went out unsigned rather than not at all, so that a ' +
            'relying party can reject it for the right reason. The log line says what failed.') +
        '">unsigned</span>';
    }
    return '<span title="' +
      esc('An enveloped XML signature over the assertion, its reference naming the ID (SAML 2.0) ' +
          'or the AssertionID (SAML 1.1).') + '">signed</span>';
  }
  if (record.family === 'ticket') {
    return '<code title="' + esc('The enc-type the ticket and its session key were sealed with.') +
      '">' + esc(record.etype || '—') + '</code>';
  }
  return esc(record.scope || '—');
}

// How the holder gets to use it, which is the question the DPoP column was already
// asking and which the other two families have their own answers to.
function presentedCell(record) {
  if (record.family === 'assertion') {
    return '<span title="' +
      esc('Both builders write a bearer SubjectConfirmation: whoever holds the assertion may ' +
          'present it. There is no holder-of-key confirmation here, so there is nothing for this ' +
          'column to distinguish between.') + '">bearer</span>';
  }
  if (record.family === 'ticket') {
    if (record.kind === 'Kerberos TGT') {
      return '<span title="' +
        esc('A TGT goes back to the KDC in a TGS-REQ to get a service ticket. It is never ' +
            'presented to a service, which is why it is the Kerberos session rather than one use ' +
            'of one.') + '">TGS-REQ</span>';
    }
    return '<span title="' +
      esc('A service ticket is presented to the service it names, in an AP-REQ — over raw ' +
          'Kerberos, or wrapped in SPNEGO over HTTP.') + '">AP-REQ</span>';
  }
  if (record.jkt) {
    return '<span title="' +
      esc('Bound to a key: cnf.jkt is in the token and a DPoP proof over that key has to ' +
          'accompany it.') + '">DPoP</span>';
  }
  return 'Bearer';
}

// The handle the row can be quoted by — and for one family there is none, which is
// worth saying rather than leaving as a bare dash beside two columns full of them.
function identifierCell(record) {
  if (record.family === 'ticket') {
    return '<span class="state-none" title="' +
      esc('A Kerberos ticket carries no identifier anybody can quote: no jti, no ID. It is named ' +
          'by its client, its service and when it was issued — the columns to the left — and the ' +
          'KDC keeps no handle on it either, because the KDC is stateless and the ticket is the ' +
          'state.') + '">—</span>';
  }
  return shortened(record.identifier, 12);
}

// The button, or why there is not one. Two different reasons, and they are not
// interchangeable: a signed UserInfo response has no jti to act on, and a SAML
// assertion has an identifier and still cannot be revoked because nothing out there
// would ask this service about it.
function actionCell(record, backRow) {
  if (record.family !== 'token') {
    return '<span class="state-none" title="' +
      esc('Nothing consults this service about a SAML assertion or a Kerberos ticket. An ' +
          'assertion is valid because its signature verifies and its Conditions hold; a ticket is ' +
          'valid because the service it names can decrypt it with a key it already has. A button ' +
          'here would change a number on this page and nothing at all out there.') + '">—</span>';
  }
  if (!record.revocable) {
    return '<span class="state-none" title="' +
      esc('Only access tokens, ID Tokens and refresh tokens can be revoked — the others are ' +
          'replies rather than credentials, or carry no jti to act on.') + '">—</span>';
  }
  return '<form method="post" action="/admin/tokens" class="inline">' +
    '<input type="hidden" name="action" value="' + (record.revoked ? 'restore' : 'revoke') + '">' +
    '<input type="hidden" name="target" value="' + esc(record.jti) + '">' +
    '<input type="hidden" name="back" value="' + esc(backRow) + '">' +
    '<button class="' + (record.revoked ? 'secondary' : 'danger') + '">' +
    (record.revoked ? 'Restore' : 'Revoke') + '</button></form>';
}

function issuedRow(record, backRow) {
  return '<tr><td>' + esc(record.kind) + '</td>' +
    '<td class="' + stateClass(record.state) + '">' + esc(record.state) + '</td>' +
    '<td>' + userCell(record) + '</td>' +
    '<td>' + subjectCell(record) + '</td>' +
    '<td>' + partyCell(record) + '</td>' +
    '<td>' + detailCell(record) + '</td>' +
    '<td>' + presentedCell(record) + '</td>' +
    '<td>' + esc(whenText(record.issuedAt)) + '</td>' +
    '<td>' + esc(record.expiresAtMs ? whenText(record.expiresAtMs) : '—') + '</td>' +
    '<td>' + identifierCell(record) + '</td>' +
    '<td>' + actionCell(record, backRow) + '</td></tr>';
}

// The legend for the above, on the page, because a reader cannot see the comment
// this file opens the section with and a table whose columns shift meaning between
// rows has to say so where the rows are.
const COLUMN_LEGEND =
  '<table><tr><th>Column</th><th>A JWT</th><th>A SAML assertion</th><th>A Kerberos ticket</th></tr>' +
  '<tr><td>User</td><td><code>username</code>, as typed at the sign-in screen</td>' +
    '<td colspan="2">nothing: each of these has one name, and it is in Subject</td></tr>' +
  '<tr><td>Subject</td><td><code>sub</code></td><td>the <code>NameID</code></td>' +
    '<td>the client principal, <code>name@REALM</code></td></tr>' +
  '<tr><td>Client, audience or service</td><td><code>client_id</code> (or <code>azp</code>, or the ' +
    '<code>aud</code>)</td><td>the <code>AudienceRestriction</code>, or <em>unrestricted</em> when ' +
    'WS-Trust was given no <code>AppliesTo</code></td><td>the service the ticket is for; hover for ' +
    'the realm that issued it</td></tr>' +
  '<tr><td>Detail</td><td><code>scope</code></td><td>whether the signature was written — an ' +
    'assertion that failed to sign still went out</td><td>the enc-type it was sealed with</td></tr>' +
  '<tr><td>Presented as</td><td>Bearer, or DPoP when <code>cnf.jkt</code> binds it to a key</td>' +
    '<td>bearer <code>SubjectConfirmation</code>; there is no holder-of-key form here</td>' +
    '<td>in a TGS-REQ (a TGT) or an AP-REQ (a service ticket)</td></tr>' +
  '<tr><td>jti or ID</td><td>the <code>jti</code>, which is what every button acts on</td>' +
    '<td>the <code>ID</code> / <code>AssertionID</code></td>' +
    '<td>none exists — a ticket has no identifier to quote, and the KDC keeps no handle on ' +
    'one</td></tr></table>';

// ---------------------------------------------------------------------------
// Paging.
//
// There is no script on these pages — `script-src 'none'`, see the shell above — so
// paging is links and a query parameter and nothing else. That is also why every
// number is settled server-side before the markup is built: a page that renders
// "page 4 of 2" and leaves the browser to sort it out has nothing to sort it out
// with.
//
// Both parameters are read defensively. `?page=abc`, `?page=-3` and `?page=999` all
// have to land somewhere sensible, because they arrive from hand-edited URLs and
// from a stale bookmark taken when the list was longer — a revocation sweep can
// shorten it between two clicks, and an out-of-range page must be the last page
// rather than an empty table that reads as "nothing matched".
//
// ONE PAGE CAN HOLD SEVERAL LISTS, and that is what `options.name` is for. The three
// list views have one list each and read the bare `page`, which is what they have
// always done and what every bookmark and every caller of the management API already
// says. The two DRILL-DOWNS have five and two: a users page holds its sessions, the
// tokens under each of them, the tokens on ended sessions, the tokens on no session
// and the artifacts, and a group page holds its members and the entries claiming it.
// A single `page` cannot serve those — clicking "next" under the artifacts would
// silently advance the sessions above it — so each list gets a page parameter named
// after itself and `per` stays shared, because "rows per table" is one choice a
// reader makes for the whole page rather than seven.
//
// `per` is shared for a second reason worth stating: it is the parameter with the
// cap on it, and one capped parameter is one place the cap can be got right.
// ---------------------------------------------------------------------------
function pagingOf(query, total, options) {
  const opts = options || {};
  const param = opts.name ? opts.name + 'Page' : 'page';
  log.debug("Entering pagingOf(). total=" + total + ", param=" + param);
  const askedPer = parseInt(String(query.per || ''), 10);
  const perPage = (isFinite(askedPer) && askedPer > 0)
    ? Math.min(askedPer, MAX_ROWS)
    : (opts.defaultPer || DEFAULT_PER_PAGE);
  // At least one page even when nothing matched, so "page 1 of 1" is what an empty
  // list says rather than "page 1 of 0".
  const pages = Math.max(1, Math.ceil(total / perPage));
  const askedPage = parseInt(String(query[param] || ''), 10);
  const page = Math.min(Math.max(isFinite(askedPage) ? askedPage : 1, 1), pages);
  const offset = (page - 1) * perPage;
  log.debug("Leaving pagingOf(). page=" + page + " of " + pages + ", perPage=" + perPage + ".");
  return {
    page: page, perPage: perPage, pages: pages, offset: offset, total: total,
    // 1-based and inclusive, for the "rows 51–100 of 312" line. Zero and zero when
    // nothing matched, which is what the line then has to say.
    firstRow: total ? offset + 1 : 0,
    lastRow: Math.min(offset + perPage, total),
    // Which query parameter this list moves on, carried on the result rather than
    // passed to pageNav() a second time: the one place that decides the name is the
    // one place that builds the links, so a control cannot come to page a list other
    // than the one it is drawn under.
    param: param,
    // What a row of this list IS, for the summary line. Seven controls on one page
    // all saying "rows" would leave the reader counting tables to work out which
    // number belongs to which.
    noun: opts.noun || 'rows'
  };
}

// The paging members of a reply, for a page that carries more than one list and
// therefore cannot put them at the top level the way the three list views do.
// Same names one level down, deliberately: a caller that has learned to walk
// `page`/`pages` on /admin-api/tokens reads `sessionsPaging.page` without being
// told anything new. `total` is here and not up there because up there it is
// `matched`, which is the count AFTER a filter — there is no filter on a
// drill-down's lists, so the honest name for the number is the plain one.
function pagingJson(pg) {
  return {
    page: pg.page, pages: pg.pages, perPage: pg.perPage,
    firstRow: pg.firstRow, lastRow: pg.lastRow, total: pg.total
  };
}

// The slice, with the paging that produced it. Written once because seven lists
// across the two drill-downs do exactly this and a hand-written eighth would be the
// one that forgets to slice.
function pagedRows(query, rows, options) {
  const pg = pagingOf(query, rows.length, options);
  return { paging: pg, shown: rows.slice(pg.offset, pg.offset + pg.perPage) };
}

// The parameters every control on a drill-down has to carry.
//
// The list views name theirs one by one, and they can: their parameter set is the
// filter form beside them and it is written down two lines above the call. A
// drill-down's is not written down anywhere — one of its lists has a page parameter
// PER SESSION BLOCK, so the set depends on what the reader has been clicking — and
// listing the ones that exist today is how paging the artifacts comes to reset the
// members six months from now. So the current query is carried through whole and
// each control overrides its own key.
//
// Three things are dropped and each for its own reason. `format`, for the reason the
// tokens page gives about its own links: JSON has no page to click, so a nav link
// carrying it would answer a click with a download. And `notice` and `error`, which
// are the message a revoke's redirect brought back — they belong to the act that has
// just happened and not to the view, so carrying them would leave "Revoked …" at the
// top of every page the reader clicked to afterwards, and would put a stale one in
// the `back` field of the next revoke, which answers with two.
const NOT_A_VIEW = ['format', 'notice', 'error'];

function pageParamsOf(query) {
  log.debug("Entering pageParamsOf().");
  const out = {};
  Object.keys(query || {}).forEach(function (key) {
    if (NOT_A_VIEW.indexOf(key) >= 0) {
      return;
    }
    // Express hands back an array when a parameter is repeated. The first is taken
    // rather than String()'d, because String(['2','5']) is "2,5" — a page number
    // nothing can parse, silently reached by a link somebody clicked twice.
    const value = Array.isArray(query[key]) ? query[key][0] : query[key];
    out[key] = value == null ? '' : String(value);
  });
  log.debug("Leaving pageParamsOf(). " + Object.keys(out).length + " parameter(s).");
  return out;
}

// The per-page select, written once because five surfaces offer it and a sixth
// written by hand is the one that forgets to add a hand-typed size to the list.
//
// MAX_ROWS is offered as the largest choice so the old behaviour — everything on one
// page, up to the cap — is still one click away for anyone who wants to search the
// table with the browser's own find.
//
// A hand-typed `?per=7` is ADDED to the list rather than ignored, or the select would
// show a size that is not the one being used and would silently change it on the next
// Filter — which is a control that lies about the page it is on.
function perPageOptions(perPage) {
  const choices = [25, DEFAULT_PER_PAGE, 100, MAX_ROWS];
  if (choices.indexOf(perPage) < 0) {
    choices.push(perPage);
    choices.sort(function (a, b) { return a - b; });
  }
  return choices.map(function (n) {
    return '<option value="' + n + '"' + (n === perPage ? ' selected' : '') + '>' +
           n + ' rows</option>';
  }).join('');
}

// The same control as a form of its own, for the two DRILL-DOWNS — which have no
// filter form to hang it on, and which need it more than the lists do because they
// carry several tables at once.
//
// Submitting it drops every page parameter, which is deliberate rather than an
// oversight of the hidden inputs: a GET form posts its own fields and nothing else,
// and page 4 of fifty-row pages is not page 4 of anything after the size changes.
// Going back to the top of each list is the only answer that is true of all of them.
//
// `carry` is the list's FILTER, and it has to be spelt out as hidden inputs for the
// reason above: a GET form posts its own fields and nothing else, so without them
// this control quietly empties the breadcrumb's way back to the list the reader
// came from. Its PAGE is deliberately not carried — `per` is the thing this form
// changes, and page 4 of fifty-row pages is not page 4 of anything afterwards,
// which is the same sentence as the paragraph above about the tables below.
function perPageForm(path, key, value, perPage, extraNote, carry) {
  log.debug("Entering perPageForm(). path=" + path);
  const carried = Object.keys(carry || {}).map(function (name) {
    return '<input type="hidden" name="' + esc(name) + '" value="' + esc(carry[name]) + '">';
  }).join('');
  const html = '<form method="get" action="' + esc(path) + '"><div class="formrow">' +
    '<input type="hidden" name="' + esc(key) + '" value="' + esc(value) + '">' + carried +
    '<label for="per">Rows per table</label>' +
    '<select id="per" name="per">' + perPageOptions(perPage) + '</select>' +
    '<button class="secondary">Apply</button>' +
    '<span class="note">Every table below is paged separately and they share this ' +
    'size. Changing it starts each of them at its first page.' +
    (extraNote ? ' ' + extraNote : '') + '</span>' +
    '</div></form>';
  log.debug("Leaving perPageForm().");
  return html;
}

// The FILTER half of a carried list view — everything except the two parameters
// that describe how the list was being paged. Written once because both of the
// controls that need it need the same half: a form that changes the page size, and
// anything else that lands the reader at the top of a list rather than where they
// were in it.
function filterOnly(view) {
  const out = {};
  Object.keys(view || {}).forEach(function (key) {
    if (key !== 'page' && key !== 'per') {
      out[key] = view[key];
    }
  });
  return out;
}

// A query string built from what the caller is already looking at plus an override.
// Every paging link goes through this, because a "next" that dropped `?kind=` would
// be page 2 of a different list — the bug this exists to make impossible rather than
// merely avoidable. Empty values are omitted so the URL of the unfiltered first page
// is the bare path.
function queryWith(params, overrides) {
  const merged = Object.assign({}, params, overrides);
  const parts = [];
  Object.keys(merged).forEach(function (key) {
    const value = merged[key];
    if (value === '' || value === null || value === undefined) {
      return;
    }
    parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(String(value)));
  });
  return parts.length ? '?' + parts.join('&') : '';
}

// The paging control. Drawn above and below the table both, because the reason to
// want the next page is usually that you have just read to the bottom of this one.
//
// The numbered links are a WINDOW around the current page rather than one per page:
// 5,000 tokens at 50 a page is 100 links, which is a worse navigation aid than none.
// First and last are always offered so the ends stay one click away.
function pageNav(path, params, pg) {
  log.debug("Entering pageNav(). pages=" + pg.pages + ", param=" + pg.param);
  if (pg.pages <= 1) {
    log.debug("Leaving pageNav(). One page; no control drawn.");
    return '';
  }
  function link(page, label, title) {
    const move = {};
    // The list's OWN parameter, off pg, so that a drill-down's five controls move
    // five different lists. Everything else in `params` rides along untouched,
    // which is what keeps the other four where the reader left them.
    move[pg.param] = page;
    return '<a href="' + esc(path + queryWith(params, move)) + '"' +
           (title ? ' title="' + esc(title) + '"' : '') + '>' + label + '</a>';
  }
  const out = [];
  if (pg.page > 1) {
    out.push(link(1, '&laquo; first', 'The newest rows'));
    out.push(link(pg.page - 1, '&lsaquo; prev'));
  } else {
    out.push('<span class="off">&laquo; first</span><span class="off">&lsaquo; prev</span>');
  }
  const from = Math.max(1, Math.min(pg.page - 3, pg.pages - 6));
  const to = Math.min(pg.pages, Math.max(pg.page + 3, 7));
  for (let n = from; n <= to; n++) {
    out.push(n === pg.page ? '<span class="here">' + n + '</span>' : link(n, String(n)));
  }
  if (pg.page < pg.pages) {
    out.push(link(pg.page + 1, 'next &rsaquo;'));
    out.push(link(pg.pages, 'last &raquo;', 'The oldest rows still held'));
  } else {
    out.push('<span class="off">next &rsaquo;</span><span class="off">last &raquo;</span>');
  }
  out.push('<span class="where">page ' + pg.page + ' of ' + pg.pages + ' — ' + pg.noun + ' ' +
           pg.firstRow + '&ndash;' + pg.lastRow + ' of ' + pg.total + '</span>');
  log.debug("Leaving pageNav(). Drew " + out.length + " element(s).");
  return '<div class="pagenav">' + out.join('') + '</div>';
}

// ---------------------------------------------------------------------------
// GET /admin — the index.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE JSON VIEWS, AND WHY EVERY ONE OF THEM IS NOW A FUNCTION.
//
// Each page here answers `?format=json`, and until admin_api.js existed each of
// those objects was built inline in the route handler that also built the
// markup. That was fine while there was one caller. There are two now — this
// console and the management API at /admin-api — and two hand-built copies of
// the same object is precisely the drift the console's own text keeps warning
// about elsewhere: two views that each look correct alone and never see each
// other.
//
// So the JSON is a function per page, and where the markup needs the same
// intermediate work (the filtered, paged token list; a user drill-down that is
// one of three answers) the WHOLE VIEW is the function and the route is what
// chooses between HTML and JSON. admin_api.js calls these and nothing else — it
// holds no second opinion about what a metrics reply contains.
//
// One cost is worth stating rather than discovering: usersView() and
// groupsView() build the HTML as well, and the API throws it away. That is what
// `/admin/users?format=json` has always done, it is a string concatenation on a
// mock, and the alternative — a second set of builders for the same data — is
// the thing this whole arrangement exists to prevent.
// ---------------------------------------------------------------------------
function consoleJson() {
  log.debug("Entering consoleJson().");
  const snap = stats.snapshot();
  const json = {
    issuer: config.value('wstrust.issuer'),
    startedAt: new Date(snap.startedAt).toISOString(),
    uptimeMs: snap.uptimeMs,
    calls: snap.calls.total, tokensHeld: snap.tokens.held,
    tokensRevoked: snap.tokens.revoked,
    artifactsHeld: snap.artifacts.held, signOnSessions: sessions.size,
    usersKnown: snap.users.known,
    usersAuthenticatedHere: snap.users.authenticatedHere,
    pages: NAV.map(function (n) { return n.path; })
  };
  log.debug("Leaving consoleJson().");
  return json;
}

// ---------------------------------------------------------------------------
// THE OVERVIEW PAGE'S OWN LIST OF WHAT IS HERE, DERIVED FROM `SECTIONS`.
//
// It was a hand-written `<ul>` in the route below until 2026-08-25, and it had
// drifted to describing SEVEN of twenty-five pages — so the one page whose
// whole job is to point at the others was the least complete description of
// this console in the repository. Nothing could have shown that: a list of
// links is correct-looking whatever it omits, which is exactly the shape of
// problem `/admin/sts-metadata` exists to make impossible for endpoints.
//
// So it is built from the same table the sidebar is built from, and three
// rules follow from that rather than from taste:
//
//   * **A page with no `blurb` is DRAWN, marked as undescribed.** The
//     tempting alternative — skip it — is the bug over again with a mechanism
//     behind it, since a page added to `SECTIONS` and not described here would
//     silently vanish from the front door exactly as nineteen of them had.
//   * **The page being drawn ON is dropped**, which is `/admin` and only ever
//     `/admin`. `trailBar()`'s last-crumb rule is the same one: a link that
//     reloads the page you are standing on teaches a reader not to trust the
//     ones beside it. A section left empty by that drop is dropped with it,
//     rather than leaving a heading over nothing.
//   * **The GROUPS are kept**, unlike `sectionPages()`, which flattens them.
//     The sidebar's grouping is a fact about the sidebar — but this list is
//     the sidebar EXPLAINED, and a reader looking for `Registration entries`
//     needs the same "these three are SPIFFE" that made the group worth
//     having.
//
// The blurbs are prose in `SECTIONS` beside each page's `path` and `label`.
// This function knows nothing about any particular page, which is what stops
// it becoming a second place a page has to be described.
function guideItem(page) {
  if (!page.blurb) {
    // NOT an omission and not a throw. A console that will not start is worse
    // than one line that says what is missing — the same call `admin_rbac.js`
    // makes about a slot nobody filled — and this is the only report anything
    // makes about a page nobody described.
    log.debug("guideItem(). No blurb for " + page.path + ".");
    return '<li><a href="' + esc(page.path) + '">' + esc(page.label) + '</a> — ' +
           '<span class="undescribed">this page has no description in ' +
           '<code>SECTIONS</code>. It was added to the nav and not described ' +
           'here; the list you are reading is derived from that table, so ' +
           'this row is the report rather than a gap.</span></li>';
  }
  return '<li><a href="' + esc(page.path) + '">' + esc(page.label) + '</a> — ' +
         page.blurb + '</li>';
}

function consoleGuide(activePath) {
  log.debug("Entering consoleGuide(). activePath=" + activePath);
  const out = [];
  SECTIONS.forEach(function (section) {
    const items = [];
    section.items.forEach(function (item) {
      if (isNavGroup(item)) {
        const pages = item.items.filter(function (page) {
          return page.path !== activePath;
        });
        if (!pages.length) {
          return;
        }
        items.push('<li><span class="grp">' + esc(item.title) + '</span>' +
                   '<span class="grpwhat">' + esc(item.what) + '</span>' +
                   '<ul>' + pages.map(guideItem).join('') + '</ul></li>');
        return;
      }
      if (item.path === activePath) {
        return;
      }
      items.push(guideItem(item));
    });
    if (!items.length) {
      log.debug("consoleGuide(). Section " + section.title + " is empty here.");
      return;
    }
    out.push('<h3>' + esc(section.title) + '</h3>' +
             '<p class="note">' + esc(section.what) + '</p>' +
             '<ul>' + items.join('') + '</ul>');
  });
  log.debug("Leaving consoleGuide(). " + out.length + " section(s) drawn.");
  return '<div class="guide">' + out.join('') + '</div>';
}
app.get('/admin', function (req, res) {
  log.debug("Entering the admin console index.");
  const snap = stats.snapshot();
  const base = baseUrlOf(req);
  const inner = messagesOf(req) +
    '<div class="tiles">' +
      tile(snap.calls.total, 'endpoint calls') +
      tile(snap.tokens.held, 'tokens issued') +
      tile(snap.tokens.revoked, 'tokens revoked') +
      tile(snap.artifacts.held, 'other artifacts') +
      tile(snap.users.known, 'users known') +
      tile(sessions.size, 'sign-on sessions') +
      tile(durationText(snap.uptimeMs), 'uptime') +
    '</div>' +
    '<h2>What this console is</h2>' +
    '<p class="note">This service exists to exercise clients, and the pages here exist to ' +
    'exercise the parts of a client that only show themselves when something changes underneath it: ' +
    'what happens when a token it holds stops being valid, and what happens when a token it reads ' +
    'grows a claim it was not expecting.</p>' +
    '<p class="note">Every page in the sidebar is below, in the sidebar\'s own order and grouping, ' +
    'because this list is DERIVED from the same table the sidebar is drawn from. A page cannot be ' +
    'added to this console and left out of here; one added without a description says so on its ' +
    'own row rather than going quietly.</p>' +
    consoleGuide('/admin') +
    '<h2>What it deliberately does not do</h2>' +
    '<p class="note">Worth knowing before looking for a control that is not here. Most of these ' +
    'are things this console CANNOT do rather than things somebody has not got to yet, and each ' +
    'says which.</p>' +
    '<ul>' +
    '<li><strong>It does not invalidate a SAML assertion, a Kerberos ticket or a credential.</strong> ' +
    'It counts them, it lists the first two on the tokens page beside the JWTs, and it says when ' +
    'each expires — but none of those has a revocation mechanism a relying party consults. A SAML ' +
    'assertion is valid because its signature verifies and its Conditions hold, and a Kerberos ' +
    'ticket because the service it names can decrypt it; nothing about this service is asked in ' +
    'either case. A button claiming to revoke one would change a number here and nothing at all ' +
    'out there, which is why those rows carry a dash and the reason for it. The same is true one ' +
    'family further out: <strong>an X509-SVID already handed to a workload keeps working until it ' +
    'expires</strong>, and banning a SPIFFE identity records who may still be ISSUED one, which is ' +
    'a different claim.</li>' +
    '<li><strong>It DOES end a sign-on session now, and it used to say it did not.</strong> ' +
    'The old reason was a good one: <code>/oauth2/logout</code> and ' +
    'WS-Federation\'s <code>wsignout1.0</code> each had a fan-out written into it, so a third ' +
    'button here would have been a third copy that quietly notified nobody. What changed on ' +
    '2026-08-24 is that those fan-outs became FUNCTIONS owned by the protocol module they ' +
    'belong to, and one function in <code>authn.js</code> is the only place a session actually ' +
    'stops existing. <a href="/admin/logout">/admin/logout</a> calls them; so does ' +
    '<a href="/logout">/logout</a>, which is the same act without a console role. What this ' +
    'console still cannot do is DELIVER the notifications — a front-channel logout is an ' +
    'iframe in the signed-out person\'s own browser, and this is not that browser.</li>' +
    '<li><strong>It does not keep the tokens themselves</strong>, only their claims. A page listing ' +
    'a thousand live bearer credentials in a form a browser will render is a page that leaks them, ' +
    'and the <code>jti</code> is all any button here needs. One configured field is held back for ' +
    'the same reason and no stronger one: a federation relationship\'s ' +
    '<code>fedClientSecret</code> is this service\'s own credential AT a real foreign service, so ' +
    'it is never printed here and never reaches the audit log — an <code>ldapsearch</code> shows ' +
    'it anyway, and this console not being a second way to read it is not a security boundary.</li>' +
    '<li><strong>It persists nothing, and a restart is not a reload.</strong> Every store behind ' +
    'these pages is in memory — the counters, the token and artifact registries, the audit ring, ' +
    'the sessions, the role roster, the embedded directory and every setting changed here — and ' +
    'the signing key is REGENERATED on every start, so a token issued by the previous process no ' +
    'longer verifies against the published JWKS. That is deliberate rather than a limitation: a ' +
    'mock whose state survives is a mock a test has to clean up after.</li>' +
    '<li><strong>It does not remember everything, either.</strong> The token, artifact and user ' +
    'registries and the audit ring are CAPPED and drop their oldest rows — and each says how many ' +
    'it dropped rather than pretending they were never there: <code>forgotten</code> on ' +
    '<a href="/admin/metrics">Metrics</a>, <code>dropped</code> on ' +
    '<a href="/admin/audit">the audit log</a>, and one collapsed row for the paths that matched no ' +
    'route. A count that grew without limit would be one a scanner inventing URLs could ' +
    'exhaust.</li>' +
    '<li><strong>It checks no password — not even at its own door.</strong> The gate proves that ' +
    'somebody typed a name that holds one of two roles, and nothing verifies that it is them. ' +
    'The roles are ordinary directory groups, so an <code>ldapmodify</code> or a SCIM PATCH grants ' +
    'them too; while neither group has a member, anybody who signs in holds both; and ' +
    '<strong><code>/admin-api</code> is deliberately NOT gated</strong>, which is what a test ' +
    'drives and the way back in when nobody holds a role — and also means anybody who can reach ' +
    'this port can grant themselves both. The gate exists so a client can be driven through ' +
    '302, 401, 403 and a role model. It does not make this port safe to expose.</li>' +
    '<li><strong>It enforces nothing by default, and widening is what most of these pages do.</strong> ' +
    'RFC 9700 mode is the one MODE that makes this service refuse what it would otherwise accept, ' +
    'and it is off unless <a href="/admin/config">Configuration</a> turns it on. Three surfaces ' +
    'ask for a credential without it — <a href="/admin/scim">SCIM</a>, the SPIRE Server API and ' +
    'this console — and all three are a turnstile rather than a lock: each can be switched off, ' +
    'and none of them checks a password. <a href="/admin/federation">Federation</a> is the one ' +
    'refusal that is not a mode and cannot be switched off, because at an assertion consumer ' +
    'service there is no permissive answer available.</li>' +
    '<li><strong>It does not decide who may delegate to whom.</strong> ' +
    '<a href="/admin/delegation">Delegation</a> reports eight mechanisms and polices none of ' +
    'them: Kerberos is the only family here that polices delegation at all, and that policy ' +
    'belongs to the principal database rather than to this console. WS-Trust\'s ' +
    '<code>OnBehalfOf</code> and RFC 8693\'s token exchange are unpoliced, and the rows say so ' +
    'rather than being tidied into an em dash.</li>' +
    '<li><strong>It does not attest a workload or a node</strong>, and no setting on ' +
    '<a href="/admin/spiffe">SPIFFE</a> turns that on. The Workload API authenticates nobody ' +
    'because its specification says it MUST NOT — a workload has no root of trust until that ' +
    'call gives it one — so what is missing there is attestation rather than authentication.</li>' +
    '<li><strong>It deletes CONFIGURATION and never a person.</strong> An authorization server, a ' +
    'SPIFFE registration entry, an attested agent\'s record and a federation relationship can all ' +
    'be removed here. A PERSON cannot be: somebody can be created on ' +
    '<a href="/admin/users">Users</a> ahead of their first sign-in and a SPIFFE identity can be ' +
    'banned so that no further SVID is issued to it, but no control in this console deletes an ' +
    'entry under <code>ou=users</code>. One name is ONE entry however that name authenticated, ' +
    'which is the property most of these pages are reading. <a href="/admin/scim">SCIM</a> is the ' +
    'exception and it is a whole protocol rather than a button — a <code>DELETE ' +
    '/scim/v2/Users/{id}</code> really does remove the entry, while its <code>active: false</code> ' +
    'deactivates nobody at all.</li>' +
    '<li><strong>It shows ONE trust realm at a time, and it writes the one it is read in.</strong> ' +
    'Every page here reports the realm in the path it was reached by, and the switcher above the ' +
    'nav is how you leave it — so a setting saved on <a href="/admin/config">Configuration</a> ' +
    'changes that realm and no other. There is deliberately no per-realm administrator: the two ' +
    'roles are groups in the ONE shared directory, so somebody who holds Admin Write holds it ' +
    'everywhere, and the console\'s own sign-on follows the roles rather than the sessions.</li>' +
    '<li><strong>It runs no script, and that costs one thing worth naming.</strong> ' +
    '<code>script-src \'none\'</code> holds over every page in this console, which is what makes ' +
    'a family of reflected-content problems moot here rather than merely unlikely. ' +
    '<a href="/admin/delegation/map">The delegation picture</a> is therefore laid out on the ' +
    'SERVER and arrives as ordinary markup, so it does not pan or zoom — ' +
    '<code>?format=svg</code> hands over the document for something that does.</li>' +
    '</ul>' +
    '<h2>Reading it from a test</h2>' +
    '<p class="note">Every page above answers <code>?format=json</code>, and so does every ' +
    'drill-down under one — the same object, the same 200, the same ' +
    '<code>Cache-Control: no-store</code>. A caller that asks for JSON is never redirected to a ' +
    'sign-in screen either: it gets 401 or 403 with a body, because a 302 to an HTML login page ' +
    'arrives at a program as a 200 full of markup. Every form takes a JSON body, and the same ' +
    'service is at <a href="/admin-api">/admin-api</a>, which is not gated at all.</p>' +
    '<ul>' +
    '<li><code>GET ' + esc(base) + '/admin/metrics?format=json</code></li>' +
    '<li><code>GET ' + esc(base) + '/admin/groups?format=json</code>, and ' +
    '<code>GET ' + esc(base) + '/admin/groups?group=cn=developers,ou=groups,...&amp;format=json' +
    '</code> — the second carries every attribute of that group and every member resolved.</li>' +
    '<li><code>GET ' + esc(base) + '/admin/users?format=json</code>, and ' +
    '<code>GET ' + esc(base) + '/admin/users?user=alice&amp;format=json</code> — the second carries ' +
    '<code>sessions</code>, each with the tokens issued on it, plus the tokens that belong to no ' +
    'session and the artifacts</li>' +
    '<li><code>GET ' + esc(base) + '/admin/tokens?format=json&amp;page=1&amp;per=100</code> — the ' +
    'reply carries <code>page</code>, <code>pages</code> and <code>matched</code>, so walking the ' +
    'whole list needs no guess about where it ends. Every paged list here answers the same three ' +
    'fields, so one walker serves all of them.</li>' +
    '<li><code>GET ' + esc(base) + '/admin/sts-metadata?format=json</code> — every endpoint this ' +
    'process registered, which is the list to check a client\'s assumptions against rather than ' +
    'this page.</li>' +
    '<li><code>GET ' + esc(base) + '/admin/delegation/map?format=json</code> for the graph, and ' +
    '<code>?format=svg</code> for the drawing alone — the one page here with a fourth shape.</li>' +
    '<li><code>POST ' + esc(base) + '/admin/tokens</code> with ' +
    '<code>{"action":"revoke","target":"&lt;jti or token&gt;"}</code></li>' +
    '<li><code>POST ' + esc(base) + '/admin/claims</code> with ' +
    '<code>{"action":"replace","set":"id_token","claims":[{"name":"dept","value":"engineering"}]}</code></li>' +
    '</ul>';
  respond(req, res, consoleJson(), 'Admin console', '/admin', inner);
  log.debug("Leaving the admin console index.");
});

// ---------------------------------------------------------------------------
// GET /admin/metrics
// ---------------------------------------------------------------------------

// The browser sign-on sessions, as rows. Expired ones are still in the map until
// something reads them (sessionOf() drops one when it finds it stale), so the state
// is computed here rather than assumed — otherwise the console would report a
// session that no request would honour.
function signOnSessionRows() {
  log.debug("Entering signOnSessionRows().");
  const nowMs = Date.now();
  const rows = [];
  sessions.forEach(function (session, id) {
    rows.push({
      id: id,
      username: (session.user && session.user.username) || '',
      sub: (session.user && session.user.sub) || '',
      amr: (session.amr || []).join(', '),
      acr: session.acr || '',
      authTime: (session.authTime || 0) * 1000,
      expires: session.expires || 0,
      expired: !!session.expires && session.expires <= nowMs,
      // Which WS-Federation relying parties this session signed into. It is the
      // list wsignout1.0 has to fan out to, and seeing it is the only way to know
      // in advance what a sign-out is about to do.
      wsfedRealms: Object.keys(session.wsfedRealms || {})
    });
  });
  rows.sort(function (a, b) { return b.authTime - a.authTime; });
  log.debug("Leaving signOnSessionRows(). " + rows.length + " session(s).");
  return rows;
}

function callTable(snap) {
  log.debug("Entering callTable().");
  const rows = snap.calls.rows.slice(0, MAX_ROWS);
  const body = rows.map(function (row) {
    return '<tr><td><code>' + esc(row.method) + '</code></td>' +
      '<td><code>' + esc(row.path) + '</code>' +
      (row.matched ? '' : ' <span class="state-expired">no route</span>') + '</td>' +
      '<td class="num">' + row.count + '</td>' +
      '<td class="num">' + (row.statuses['2xx'] || 0) + '</td>' +
      '<td class="num">' + (row.statuses['3xx'] || 0) + '</td>' +
      '<td class="num">' + (row.statuses['4xx'] || 0) + '</td>' +
      '<td class="num">' + (row.statuses['5xx'] || 0) + '</td>' +
      '<td class="num">' + Math.round(row.totalMs / Math.max(row.count, 1)) + '</td>' +
      '<td class="num">' + row.maxMs + '</td>' +
      '<td>' + esc(whenText(row.lastAt)) + '</td></tr>';
  }).join('');
  const hidden = snap.calls.rows.length - rows.length;
  log.debug("Leaving callTable(). " + rows.length + " row(s).");
  return '<table><tr><th>Method</th><th>Route</th><th class="num">Calls</th>' +
    '<th class="num">2xx</th><th class="num">3xx</th><th class="num">4xx</th><th class="num">5xx</th>' +
    '<th class="num">Avg ms</th><th class="num">Max ms</th><th>Last</th></tr>' +
    (body || '<tr><td colspan="10">No call has been recorded yet.</td></tr>') + '</table>' +
    (hidden > 0 ? '<p class="note">' + hidden + ' further route(s) are not shown; the table draws the ' +
                  MAX_ROWS + ' busiest.</p>' : '') +
    (snap.calls.pathsCollapsed > 0
      ? '<p class="note">' + snap.calls.pathsCollapsed + ' request(s) to paths that matched no route ' +
        'were counted in the single <code>' + esc('(other unmatched paths)') + '</code> row: the table ' +
        'is capped so that a scanner inventing URLs cannot grow it without limit.</p>'
      : '');
}

function tokenKindTable(snap) {
  log.debug("Entering tokenKindTable(). " + snap.tokens.byKind.length + " kind(s).");
  const body = snap.tokens.byKind.map(function (row) {
    return '<tr><td>' + esc(row.kind) + '</td>' +
      '<td class="num">' + row.issued + '</td>' +
      '<td class="num state-valid">' + row.valid + '</td>' +
      '<td class="num state-expired">' + row.expired + '</td>' +
      '<td class="num state-revoked">' + row.revoked + '</td>' +
      '<td class="num">' + row.notYetValid + '</td>' +
      '<td class="num">' + row.noExpiry + '</td>' +
      '<td class="num">' + row.bound + '</td></tr>';
  }).join('');
  log.debug("Leaving tokenKindTable().");
  return '<table><tr><th>Token</th><th class="num">Issued</th><th class="num">Valid</th>' +
    '<th class="num">Expired</th><th class="num">Revoked</th><th class="num">Not yet valid</th>' +
    '<th class="num">No expiry</th><th class="num">DPoP-bound</th></tr>' +
    (body || '<tr><td colspan="8">No token has been issued yet.</td></tr>') + '</table>';
}

function artifactKindTable(snap) {
  log.debug("Entering artifactKindTable(). " + snap.artifacts.byKind.length + " kind(s).");
  const body = snap.artifacts.byKind.map(function (row) {
    return '<tr><td>' + esc(row.kind) + '</td>' +
      '<td class="num">' + row.issued + '</td>' +
      '<td class="num state-valid">' + row.valid + '</td>' +
      '<td class="num state-expired">' + row.expired + '</td>' +
      '<td class="num">' + row.noExpiry + '</td></tr>';
  }).join('');
  log.debug("Leaving artifactKindTable().");
  return '<table><tr><th>Artifact</th><th class="num">Issued</th><th class="num">Valid</th>' +
    '<th class="num">Expired</th><th class="num">No expiry</th></tr>' +
    (body || '<tr><td colspan="5">No assertion, ticket or credential has been issued yet.</td></tr>') +
    '</table>';
}

// The metrics reply: the whole snapshot, with the sign-on sessions beside it.
// The snapshot's own keys are at the TOP LEVEL of it rather than under a
// `snapshot` member, which is what /admin/metrics?format=json has always
// answered and what the parent project's tests read — so the route below uses
// this object for the markup too rather than taking a second snapshot a few
// microseconds later.
function metricsJson() {
  log.debug("Entering metricsJson().");
  const snap = stats.snapshot();
  const signOn = signOnSessionRows();
  const live = signOn.filter(function (s) { return !s.expired; });
  const json = Object.assign({}, snap, {
    startedAtIso: new Date(snap.startedAt).toISOString(),
    signOnSessions: { held: signOn.length, active: live.length, rows: signOn }
  });
  log.debug("Leaving metricsJson(). " + signOn.length + " sign-on session(s).");
  return json;
}

app.get('/admin/metrics', function (req, res) {
  log.debug("Entering the admin metrics page.");
  const json = metricsJson();
  // The snapshot's keys are the top level of that object; see the note on it.
  const snap = json;
  const signOn = json.signOnSessions.rows;
  const liveSignOn = signOn.filter(function (s) { return !s.expired; });

  // The Who column holds SUBJECTS, and one family's are not names in any readable
  // sense: an OID4VCI credential's subject is a `did:jwk:` — a couple of hundred
  // characters of base64url with not one place in it a browser will break a line.
  // Emitted as plain text that made the cell's minimum width wider than the card,
  // so the table overflowed and took the OAuth 2.0 / OIDC row's column with it,
  // even though `urn:sts-mock:user:alice` is short and never the problem. So each
  // subject is drawn the way the tokens page draws a jti — shortened, with the
  // whole string in the title so it is still recoverable by hovering — and inside
  // <code>, which the stylesheet already lets break mid-string.
  const sessionFamilyRows = snap.sessions.families.map(function (row) {
    const shown = row.who.slice(0, MAX_WHO).map(function (subject) {
      return shortened(subject, 28);
    }).join(' ');
    return '<tr><td>' + esc(row.family) + '</td><td class="num">' + row.subjects + '</td>' +
      '<td class="who">' + shown +
      (row.who.length > MAX_WHO ? ' &hellip; and ' + (row.who.length - MAX_WHO) + ' more' : '') +
      '</td></tr>';
  }).join('');

  const signOnRows = signOn.slice(0, MAX_ROWS).map(function (s) {
    return '<tr><td>' + esc(s.username) + '</td>' +
      '<td class="' + (s.expired ? 'state-expired' : 'state-valid') + '">' +
        (s.expired ? 'expired, not yet swept' : 'active') + '</td>' +
      '<td>' + esc(s.amr || '—') + '</td><td>' + esc(s.acr || '—') + '</td>' +
      '<td>' + esc(whenText(s.authTime)) + '</td>' +
      '<td>' + esc(whenText(s.expires)) + '</td>' +
      '<td>' + (s.wsfedRealms.length ? esc(s.wsfedRealms.join(', ')) : '—') + '</td></tr>';
  }).join('');

  const inner = messagesOf(req) +
    '<div class="tiles">' +
      tile(snap.calls.total, 'endpoint calls') +
      tile(snap.calls.paths, 'routes called') +
      tile(snap.tokens.held, 'tokens issued') +
      tile(snap.tokens.revoked, 'tokens revoked') +
      tile(snap.artifacts.held, 'assertions, tickets, credentials') +
      tile(liveSignOn.length, 'sign-on sessions') +
      tile(snap.sessions.distinctSubjects, 'subjects with a live artifact') +
      tile(durationText(snap.uptimeMs), 'uptime') +
    '</div>' +
    '<p class="note">Since <code>' + esc(whenText(snap.startedAt)) + '</code>. Every figure on this ' +
    'page is computed when the page is drawn rather than kept up to date as things happen, because ' +
    '&ldquo;valid&rdquo; and &ldquo;expired&rdquo; are functions of the clock: a counter incremented ' +
    'at issuance would be wrong a second later.</p>' +

    '<h2>Endpoint calls</h2>' +
    '<p class="note">Keyed on the route Express matched, not on the URL requested, so ' +
    '<code>/oauth2/register/:client_id</code> is one row rather than one row per client. These are ' +
    'the same route patterns <a href="/admin/sts-metadata">' +
    '/admin/sts-metadata</a> lists.</p>' +
    callTable(snap) +

    '<h2>Tokens</h2>' +
    '<p class="note">Every JWT this service signs, by <code>typ</code> — which is the only thing ' +
    'that tells them apart, since all of them are RS256 and signed with the same key. ' +
    '<a href="/admin/tokens">The tokens page</a> lists them one by one — beside the SAML ' +
    'assertions and Kerberos tickets, which it also lists — and can invalidate these.</p>' +
    tokenKindTable(snap) +
    (snap.tokens.forgotten > 0
      ? '<p class="note">' + snap.tokens.forgotten + ' older token(s) have been forgotten: the ' +
        'registry holds the most recent ' + snap.tokens.cap + '. Their revocations are NOT ' +
        'forgotten — the set of revoked <code>jti</code>s is kept separately and is not capped, so ' +
        'a token revoked long ago stays revoked.</p>'
      : '') +

    '<h2>Assertions, tickets and credentials</h2>' +
    '<p class="note">The artifacts that are not JWTs. None of them can be revoked and the console ' +
    'does not pretend otherwise — see the index for why — so the only distinction here is whether ' +
    'the validity window has closed. The assertions and the tickets are listed one by one on ' +
    '<a href="/admin/tokens">the tokens page</a>, beside the JWTs and in the order they were all ' +
    'issued; the credentials are counted here and nowhere else.</p>' +
    artifactKindTable(snap) +
    (snap.artifacts.forgotten > 0
      ? '<p class="note">' + snap.artifacts.forgotten + ' older artifact(s) have been forgotten; the ' +
        'registry holds the most recent ' + snap.artifacts.cap + '.</p>'
      : '') +

    '<h2>Sessions, counted both ways</h2>' +
    '<p class="note">The two numbers mean different things and disagree on purpose. A ' +
    '<strong>sign-on session</strong> is a real one: a browser holding the ' +
    '<code>sts_mock_session</code> cookie, shared between the OAuth 2.0 / OIDC login screen and ' +
    'WS-Federation, which is what makes single sign-on across the two work. An ' +
    '<strong>artifact-derived session</strong> is an inference: a subject that holds at least one ' +
    'artifact from that protocol family which is still valid. A <code>client_credentials</code> ' +
    'token is the second and not the first (there is no human and no browser behind it); a browser ' +
    'that has signed in but been issued nothing yet is the first and not the second; a Kerberos ' +
    'client is never the first at all. Both are counted here per family; ' +
    '<a href="/admin/users">the users page</a> is where one person\'s sessions and the tokens ' +
    'issued on each of them are.</p>' +
    '<h3>Sign-on sessions (' + liveSignOn.length + ' active of ' + signOn.length + ' held)</h3>' +
    '<table><tr><th>User</th><th>State</th><th>amr</th><th>acr</th><th>Signed in</th>' +
    '<th>Expires</th><th>WS-Fed relying parties signed into</th></tr>' +
    (signOnRows || '<tr><td colspan="7">Nobody is signed in.</td></tr>') + '</table>' +
    '<p class="note">An expired session stays in the map until something reads it — ' +
    '<code>sessionOf()</code> drops one when it finds it stale — so it is listed as held but not ' +
    'active rather than quietly omitted.</p>' +
    '<h3>Artifact-derived sessions (' + snap.sessions.distinctSubjects + ' distinct subject(s))</h3>' +
    '<table><tr><th>Protocol family</th><th class="num">Subjects</th><th>Who</th></tr>' +
    (sessionFamilyRows || '<tr><td colspan="3">Nothing valid has been issued yet.</td></tr>') +
    '</table>' +
    '<p class="note">A Kerberos TGT is counted as a session and a service ticket is not, because ' +
    'that is what they are: the TGT is the credential the session consists of, and a service ticket ' +
    'is one use of it. Counting both would report the same session twice.</p>';

  respond(req, res, json, 'Metrics', '/admin/metrics', inner);
  log.debug("Leaving the admin metrics page.");
});

// ---------------------------------------------------------------------------
// GET /admin/tokens, POST /admin/tokens
// ---------------------------------------------------------------------------

// The jti a caller named, from whichever of the two forms they used. A jti is
// accepted directly, and so is a whole token — because the thing somebody has in
// their hand when they want to invalidate it is the token, not its jti.
//
// The token's SIGNATURE IS NOT VERIFIED here, and that is safe rather than sloppy:
// the only thing read out of it is the jti, which is then looked up in this
// service's own registry. A forged token yields a jti this service never issued, and
// revoking a jti that was never issued invalidates nothing. RFC 7009's endpoint does
// verify, because there the token is the credential being presented; here it is
// merely a way of typing a jti that is 22 characters long.
function jtiFrom(target) {
  log.debug("Entering jtiFrom().");
  const text = String(target || '').trim();
  if (!text) {
    log.debug("Leaving jtiFrom(). Nothing was given.");
    return { jti: '', how: 'nothing was given' };
  }
  const parts = text.split('.');
  if (parts.length !== 3) {
    log.debug("Leaving jtiFrom(). Treating it as a jti.");
    return { jti: text, how: 'read as a jti' };
  }
  try {
    const claims = JSON.parse(b64uDecode(parts[1]).toString('utf8'));
    log.debug("Leaving jtiFrom(). Read the jti out of a JWT.");
    return { jti: String(claims.jti || ''), how: 'read out of the JWT payload without verifying it',
             claims: claims };
  } catch (e) {
    // Three dot-separated parts that are not a JWT. Fall back to treating the whole
    // string as a jti rather than refusing: it costs nothing and a jti containing
    // two dots is not forbidden anywhere.
    log.debug("Leaving jtiFrom(). It has three parts but is not a JWT: " + e.message);
    return { jti: text, how: 'read as a jti (it looked like a JWT but did not decode)' };
  }
}

function tokenAction(body) {
  log.debug("Entering tokenAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');

  if (action === 'revoke' || action === 'restore') {
    const found = jtiFrom(body.target || body.jti || body.token);
    if (!found.jti) {
      log.debug("Leaving tokenAction(). No jti was given.");
      return { ok: false, errors: ['Give a jti, or paste the whole token and the jti will be read ' +
                                   'out of it.'] };
    }
    if (action === 'restore') {
      const was = stats.restore(found.jti);
      log.debug("Leaving tokenAction(). Restored.");
      return { ok: true, jti: found.jti,
               message: was ? 'The token with jti ' + found.jti + ' is no longer revoked (NON-SPEC — ' +
                              'a real authorization server cannot undo a revocation).'
                            : 'The token with jti ' + found.jti + ' was not revoked, so nothing changed.' };
    }
    const first = stats.revoke(found.jti, 'the admin console');
    log.debug("Leaving tokenAction(). Revoked.");
    return { ok: true, jti: found.jti,
             message: (first ? 'Revoked ' : 'Already revoked: ') + found.jti + ' (' + found.how +
                      '). Introspection now reports it inactive, UserInfo refuses it, and it will ' +
                      'not refresh.' };
  }

  if (action === 'revoke-kind') {
    const kind = String(body.kind || '');
    if (stats.REVOCABLE_KINDS.indexOf(kind) < 0) {
      log.debug("Leaving tokenAction(). Not a revocable kind.");
      return { ok: false, errors: ['"' + kind + '" is not a kind that can be revoked. The three are: ' +
                                   stats.REVOCABLE_KINDS.join(', ') + '.'] };
    }
    const count = stats.revokeWhere(function (record) { return record.kind === kind; },
                                    'the admin console (every ' + kind + ')');
    log.debug("Leaving tokenAction(). Revoked " + count + " by kind.");
    return { ok: true, revoked: count, message: 'Revoked ' + count + ' ' + kind + '(s).' };
  }

  if (action === 'revoke-subject') {
    const subject = String(body.subject || '').trim();
    if (!subject) {
      log.debug("Leaving tokenAction(). No subject was given.");
      return { ok: false, errors: ['Give a subject or a username.'] };
    }
    const count = stats.revokeWhere(function (record) {
      return record.sub === subject || record.username === subject;
    }, 'the admin console (everything for ' + subject + ')');
    log.debug("Leaving tokenAction(). Revoked " + count + " for a subject.");
    return { ok: true, revoked: count,
             message: 'Revoked ' + count + ' token(s) for ' + subject + '.' };
  }

  // The users page's button. It is not the same thing as revoke-subject above, and
  // the difference is the reason it exists: that one matches a `sub` or a `username`
  // EXACTLY, which is what somebody typing into the box on the tokens page means,
  // while a user on the users page is an identity that has been seen under several
  // spellings — `alice`, `urn:sts-mock:user:alice`, `alice@STS.MOCK`. Revoking "for
  // alice" from that page has to mean all of them, or the page would offer a button
  // that visibly missed half of its own table.
  if (action === 'revoke-user') {
    const key = String(body.user || '').trim();
    if (!key) {
      log.debug("Leaving tokenAction(). No user was given.");
      return { ok: false, errors: ['Give a user, as the users page names them.'] };
    }
    const count = stats.revokeWhere(function (record) {
      return stats.identityKeyOf(record.username || record.sub) === key;
    }, 'the admin console (everything for the user ' + key + ')');
    log.debug("Leaving tokenAction(). Revoked " + count + " for a user.");
    return { ok: true, revoked: count, user: key,
             message: 'Revoked ' + count + ' token(s) for ' + key + ' — every spelling of that ' +
                      'identity, not just the one the row showed.' };
  }

  if (action === 'revoke-all') {
    const count = stats.revokeWhere(function () { return true; }, 'the admin console (everything)');
    log.debug("Leaving tokenAction(). Revoked everything: " + count + ".");
    return { ok: true, revoked: count,
             message: 'Revoked ' + count + ' token(s) — every access token, ID Token and refresh ' +
                      'token this service has issued and still remembers.' };
  }

  log.debug("Leaving tokenAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The six are: revoke, restore, ' +
                               'revoke-kind, revoke-subject, revoke-user, revoke-all.'] };
}

// Where a form POST sends the browser back to. Revoking the token on page 4 and
// landing on page 1 of an unfiltered list is the paging bug everybody has met, so
// the row forms carry the view they were rendered in as a `back` field.
//
// It is REBUILT rather than echoed, and that is the whole point of doing it here: a
// redirect target taken from a request body is an open redirect, and one carrying a
// newline is a header injection. Only the parameters this page understands survive,
// each of them re-encoded, so the worst a hand-written `back` can produce is a
// different page of this same table.
//
// The list below has to be kept in step with the filter form. A parameter the form
// offers and this function drops is a filter that silently resets itself the moment
// somebody revokes a token — which looks like the console losing your place rather
// than like a missing line here.
//
// The users page posts to this same endpoint, so `from` says which of the two pages
// a button was on. It is read as an ENUM and never as a path: the two paths below
// are written here, and a `from` naming anything else falls through to the tokens
// page. That is what keeps the open-redirect property while letting a second page
// share the handler — a `back` field carrying `//evil.example` would otherwise become
// a redirect off this service the moment a path came from the body.
// The drill-down's page parameters, out of a `back` field, for the redirect that
// follows a revoke.
//
// The named parameters above are a WHITELIST, which is the right shape for a
// redirect target built out of a form field somebody posted — but a whitelist cannot
// cover this set, because one of the users page's lists has a page parameter per
// session block and the names therefore depend on which sessions exist. So the rule
// is a shape rather than a list: a key ending in `Page`, made of the characters a
// name and a base64url session id are made of, whose value is a positive integer.
// The value is REBUILT from parseInt rather than passed through, so what lands in
// the URL is a number this function produced.
//
// What it buys is the thing a reader notices immediately: revoking a token from page
// three of a session's table used to answer with page one of everything, so the row
// you had just acted on was no longer on screen and neither was its neighbour.
function drillDownPages(params) {
  log.debug("Entering drillDownPages().");
  const out = {};
  params.forEach(function (value, key) {
    if (!/^[A-Za-z0-9_-]+Page$/.test(key)) {
      return;
    }
    const n = parseInt(String(value), 10);
    if (isFinite(n) && n > 0) {
      out[key] = String(n);
    }
  });
  log.debug("Leaving drillDownPages(). " + Object.keys(out).length + " page parameter(s).");
  return out;
}

function backTo(body) {
  log.debug("Entering backTo().");
  let params = null;
  try {
    params = new URLSearchParams(String(body.back || '').replace(/^\?/, ''));
  } catch (e) {
    // Unparseable; the bare page is the right answer and is what the forms that
    // carry no `back` at all get anyway.
    log.debug("Leaving backTo(). Unparseable back field: " + e.message);
    return '/admin/tokens';
  }
  if (String(body.from || '') === 'users') {
    const usersTarget = '/admin/users' + queryWith(Object.assign({
      user: params.get('user') || '',
      q: params.get('q') || '',
      protocol: params.get('protocol') || '',
      per: params.get('per') || '',
      page: params.get('page') || ''
    }, drillDownPages(params)), {});
    log.debug("Leaving backTo(). " + usersTarget);
    return usersTarget;
  }
  const target = '/admin/tokens' + queryWith({
    family: params.get('family') || '',
    kind: params.get('kind') || '',
    state: params.get('state') || '',
    per: params.get('per') || '',
    page: params.get('page') || ''
  }, {});
  log.debug("Leaving backTo(). " + target);
  return target;
}

app.post('/admin/tokens', function (req, res) {
  log.debug("Entering the admin token action endpoint.");
  const body = parseBody(req);
  const result = tokenAction(body);
  respondToAction(req, res, backTo(body), result);
  log.debug("Leaving the admin token action endpoint.");
});

// The filtered, paged token list and the reply built from it. The WHOLE view
// rather than only its JSON, because the markup below needs every intermediate
// step of it — and a second walk of the same list a few lines later is how a
// table and the JSON beside it come to disagree about a revocation that
// happened in between.
function tokensView(query) {
  log.debug("Entering tokensView().");
  const wantedFamily = String(query.family || '');
  const wantedKind = String(query.kind || '');
  const wantedState = String(query.state || '');
  // Not tokenList(): this page lists every JWT, every SAML assertion (whether
  // WS-Trust or WS-Federation issued it) and every Kerberos ticket, in one table in
  // the order they were issued.
  const all = stats.issuedList();
  const filtered = all.filter(function (record) {
    if (wantedFamily && record.family !== wantedFamily) return false;
    if (wantedKind && record.kind !== wantedKind) return false;
    if (wantedState && record.state !== wantedState) return false;
    return true;
  });
  // Filter first, then page: paging a list and then filtering it would give a page 2
  // whose length depends on what page 1 happened to contain.
  const paging = pagingOf(query, filtered.length);
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  // How much of each family is held, for the line under the table. Counted from this
  // list rather than taken from the snapshot, because the snapshot's artifact count
  // includes the OID4VCI credentials this page does not list — two totals on one
  // page differing by a number of credentials is a page nobody can check.
  const heldByFamily = {};
  all.forEach(function (record) {
    heldByFamily[record.family] = (heldByFamily[record.family] || 0) + 1;
  });
  log.debug("Leaving tokensView(). " + shown.length + " row(s) of " +
            filtered.length + ".");
  return {
    wantedFamily: wantedFamily, wantedKind: wantedKind,
    wantedState: wantedState,
    all: all, filtered: filtered, paging: paging, shown: shown,
    heldByFamily: heldByFamily,
    json: {
      held: all.length, matched: filtered.length, shown: shown.length,
      heldByFamily: stats.ISSUED_FAMILIES.reduce(function (out, entry) {
        out[entry.family] = heldByFamily[entry.family] || 0;
        return out;
      }, {}),
      filter: { family: wantedFamily || null, kind: wantedKind || null,
                state: wantedState || null },
      // The clamped values, not what was asked for: `?page=999` on a two-page
      // list reports page 2, which is the page whose rows are in the reply.
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      families: stats.ISSUED_FAMILIES,
      revocableKinds: stats.REVOCABLE_KINDS,
      revokedCount: stats.revokedCount(),
      // `issued` rather than `tokens`, because the array is no longer only
      // tokens and a key that says otherwise is the kind of thing a test
      // asserts against once and then trusts. Nothing outside this repository
      // read the old name.
      issued: shown
    }
  };
}

app.get('/admin/tokens', function (req, res) {
  log.debug("Entering the admin tokens page.");
  const view = tokensView(req.query);
  const wantedFamily = view.wantedFamily;
  const wantedKind = view.wantedKind;
  const wantedState = view.wantedState;
  const all = view.all;
  const filtered = view.filtered;
  const paging = view.paging;
  const shown = view.shown;
  const heldByFamily = view.heldByFamily;
  // What every paging link has to carry with it. The page number is not in here —
  // pageNav() supplies that per link — and neither is `format`, because JSON has no
  // links in it and a caller asking for JSON passes its own parameters anyway.
  const filterParams = { family: wantedFamily, kind: wantedKind, state: wantedState,
                         per: req.query.per ? paging.perPage : '' };
  const nav = pageNav('/admin/tokens', filterParams, paging);
  // What the POST handler sends the browser back to. A row button returns to THIS
  // page of THIS filter; the bulk buttons below keep the filter but not the page,
  // because after "revoke everything" the list they were looking at is a different
  // list and page 7 of it means nothing.
  const backRow = queryWith(filterParams, { page: paging.page });
  const backFilter = queryWith(filterParams, {});

  const rows = shown.map(function (record) {
    return issuedRow(record, backRow);
  }).join('');

  const familyOptions = ['<option value=""' + (wantedFamily ? '' : ' selected') + '>any family</option>']
    .concat(stats.ISSUED_FAMILIES.map(function (entry) {
      return '<option value="' + esc(entry.family) + '"' +
             (entry.family === wantedFamily ? ' selected' : '') + '>' + esc(entry.label) + '</option>';
    })).join('');

  // Grouped by family rather than flat, because "SAML 2.0" and "id_token" in one
  // list of nine reads as nine unrelated things. Both this and the family select are
  // built from the same structure in admin_stats.js, so the two cannot come to
  // disagree about which kind belongs to which family — which they would, being two
  // hand-written lists of the same nine strings.
  const kindOptions = '<option value=""' + (wantedKind ? '' : ' selected') + '>any kind</option>' +
    stats.ISSUED_FAMILIES.map(function (entry) {
      return '<optgroup label="' + esc(entry.label) + '">' + entry.kinds.map(function (k) {
        return '<option value="' + esc(k) + '"' + (k === wantedKind ? ' selected' : '') + '>' +
               esc(k) + '</option>';
      }).join('') + '</optgroup>';
    }).join('');
  const stateOptions = ['', 'valid', 'expired', 'revoked', 'not yet valid', 'no expiry stated']
    .map(function (s) {
      return '<option value="' + esc(s) + '"' + (s === wantedState ? ' selected' : '') + '>' +
             esc(s || 'any state') + '</option>';
    }).join('');
  const perOptions = perPageOptions(paging.perPage);

  const inner = messagesOf(req) +
    '<p class="note">Everything this service has issued and still remembers: every JWT, every SAML ' +
    'assertion — whether WS-Trust issued it or a WS-Federation sign-in did — and every Kerberos ' +
    'ticket the KDC minted, in one table, newest first. One table rather than three because a ' +
    'WS-Federation sign-in that produced an ID Token and a SAML 1.1 assertion is <em>one event</em>, ' +
    'and three tables would leave it to be reassembled by comparing timestamps.</p>' +
    '<p class="note">Only the JWTs can be invalidated. Revoking one here is the SAME operation ' +
    'RFC 7009\'s <code>/oauth2/revoke</code> performs — there is one set of revoked ' +
    '<code>jti</code>s in this service, not one per page. So a token revoked here immediately ' +
    'introspects as inactive at <code>/oauth2/introspect</code>, is refused by ' +
    '<code>/oauth2/userinfo</code> with <code>invalid_token</code>, and fails the refresh grant ' +
    'with <code>invalid_grant</code>. Two sets would each look correct on their own and never see ' +
    'each other, which is a debugging session with no error message anywhere in it.</p>' +
    '<p class="note">An assertion and a ticket have no button and are listed anyway, which is the ' +
    'point of listing them: <strong>nothing consults this service about either</strong>. An ' +
    'assertion is valid because its signature verifies and its <code>Conditions</code> hold, and a ' +
    'ticket because the service it names can decrypt it with a key it already has. So the only ' +
    'thing that ends one is its own expiry, and the only way to see when that is — or to see that ' +
    'a sign-in produced one at all — is a page that shows it.</p>' +

    '<h2>Invalidate</h2>' +
    '<form method="post" action="/admin/tokens">' +
      '<input type="hidden" name="action" value="revoke">' +
      '<input type="hidden" name="back" value="' + esc(backFilter) + '">' +
      '<div class="formrow"><label for="target">A jti, or paste the whole token</label>' +
      '<input type="text" id="target" name="target" size="60" placeholder="jti, or eyJhbGciOi...">' +
      '<button class="danger">Revoke</button></div></form>' +
    '<p class="note">Pasting a token is read for its <code>jti</code> and the signature is not ' +
    'checked, which is safe: a forged token yields a jti this service never issued, and revoking ' +
    'one of those invalidates nothing. To undo a revocation, use the Restore button in the table — ' +
    'a NON-SPEC operation no real authorization server can offer, kept because otherwise getting ' +
    'back to a working token means restarting this service.</p>' +
    '<div class="formrow">' +
      ['access_token', 'id_token', 'refresh_token'].map(function (kind) {
        return '<form method="post" action="/admin/tokens" class="inline">' +
          '<input type="hidden" name="action" value="revoke-kind">' +
          '<input type="hidden" name="kind" value="' + esc(kind) + '">' +
          '<input type="hidden" name="back" value="' + esc(backFilter) + '">' +
          '<button class="danger">Revoke every ' + esc(kind) + '</button></form>';
      }).join(' ') +
      '<form method="post" action="/admin/tokens" class="inline">' +
      '<input type="hidden" name="action" value="revoke-all">' +
      '<input type="hidden" name="back" value="' + esc(backFilter) + '">' +
      '<button class="danger">Revoke everything</button></form>' +
    '</div>' +
    '<form method="post" action="/admin/tokens">' +
      '<input type="hidden" name="action" value="revoke-subject">' +
      '<input type="hidden" name="back" value="' + esc(backFilter) + '">' +
      '<div class="formrow"><label for="subject">Everything for one subject or username</label>' +
      '<input type="text" id="subject" name="subject" size="40" placeholder="alice, or urn:sts-mock:user:alice">' +
      '<button class="danger">Revoke</button></div></form>' +

    '<h2>What has been issued</h2>' +
    // No `page` input in this form, and that is the point: changing the filter or the
    // page size sends the reader back to page 1. Carrying the old page number over
    // would land somebody on page 6 of a two-page result, and the clamp in pagingOf()
    // would then quietly move them again.
    '<form method="get" action="/admin/tokens"><div class="formrow">' +
      '<label for="family">Family</label><select id="family" name="family">' + familyOptions +
      '</select>' +
      '<label for="kind">Kind</label><select id="kind" name="kind">' + kindOptions + '</select>' +
      '<label for="state">State</label><select id="state" name="state">' + stateOptions + '</select>' +
      '<label for="per">Per page</label><select id="per" name="per">' + perOptions + '</select>' +
      '<button class="secondary">Filter</button>' +
      (wantedFamily || wantedKind || wantedState ? ' <a href="/admin/tokens">clear</a>' : '') +
    '</div></form>' +
    // Family and Kind are ANDed, like any two filters, so a contradictory pair
    // (Kerberos tickets, id_token) matches nothing. Said here rather than prevented,
    // because the alternative is a page that silently ignores one of the two
    // selects the reader can see it obeying.
    '<p class="note">Family and Kind narrow together: choosing a family and a kind from a ' +
    'different one matches nothing, which is what an empty table below then means.</p>' +
    nav +
    '<table><tr><th>Kind</th><th>State</th><th>User</th><th>Subject</th>' +
    '<th>Client, audience or service</th><th>Detail</th>' +
    '<th>Presented as</th><th>Issued</th><th>Expires</th><th>jti or ID</th><th></th></tr>' +
    (rows || '<tr><td colspan="11">Nothing matches.</td></tr>') + '</table>' +
    nav +
    '<p class="note">' + filtered.length + ' row(s) match' +
    (paging.pages > 1 ? ', of which rows ' + paging.firstRow + '&ndash;' + paging.lastRow +
                        ' are on this page (' + paging.page + ' of ' + paging.pages + ')' : '') +
    '; ' + all.length + ' held in total — ' +
    stats.ISSUED_FAMILIES.map(function (entry) {
      return (heldByFamily[entry.family] || 0) + ' ' + esc(entry.label);
    }).join(', ') +
    '. Newest first, so page 1 is what somebody is most likely to be debugging. Only the claims ' +
    'and the facts below are kept, never the signed token, the assertion XML or the ticket: a page ' +
    'rendering a thousand live credentials in a form a browser will display is a page that leaks ' +
    'them, and the <code>jti</code> is all any button here needs.</p>' +

    '<h3>What each column means</h3>' +
    '<p class="note">Three families in one table, so most columns answer a slightly different ' +
    'question depending on the row. Rather than leave that to be inferred:</p>' +
    COLUMN_LEGEND +
    '<p class="note">OID4VCI credentials are <strong>not</strong> in this table. They are recorded ' +
    'and counted on <a href="/admin/metrics">the metrics page</a> and listed nowhere. That is a ' +
    'gap rather than a principle — a credential is as much an issued artifact as an assertion is — ' +
    'and it is named here so that "everything this service has issued" above is read as the three ' +
    'families it says and not as four.</p>' +

    '<p class="note">Paging is <code>?page=</code> and <code>?per=</code> (at most ' + MAX_ROWS +
    ' rows a page), and both work with <code>?format=json</code> — where the reply carries ' +
    '<code>page</code>, <code>pages</code> and <code>matched</code>, so a test can walk the whole ' +
    'list without guessing when it has reached the end. The rows are in <code>issued</code> there, ' +
    'each carrying its <code>family</code>; it was <code>tokens</code> when this page listed only ' +
    'JWTs. Every button on this page acts on a <code>jti</code> and never on a row number, so a ' +
    'revocation between two clicks cannot make the wrong token the target — the most it can do is ' +
    'shift a row onto another page.</p>';

  respond(req, res, view.json, 'Tokens', '/admin/tokens', inner);
  log.debug("Leaving the admin tokens page.");
});

// ---------------------------------------------------------------------------
// GET /admin/audit — what happened here, in order.
//
// The other pages on this console are STATE: how many calls, which tokens are
// still valid, who is in cn=developers. This one is HISTORY, and the difference
// is the reason it exists. The metrics page can tell you the directory holds
// eleven entries; only this one can tell you that a twelfth was created at
// 14:02 and deleted at 14:03, by somebody bound as uid=carol, over LDAPS.
//
// Six categories, and every event in the service arrives through one of five
// funnels rather than from a recording site per feature:
//
//   authentication   admin_stats.recordAuthentication(), the single point all
//                    sixteen protocol families already pass through when a
//                    credential is ACCEPTED — SCIM being the fifteenth, for
//                    the three of its schemes that present a credential per
//                    request, and SPIFFE the sixteenth, for an X509-SVID
//                    presented over mutual TLS, an agent attesting and a
//                    JWT-SVID validated
//   session          authn.js's startSession / endSession, which is where both
//                    OAuth 2.0 / OIDC and WS-Federation sign in and out
//   directory        the seven LDAP handlers in ldap_server.js, plus the
//                    entries this service creates for people who authenticated
//                    somewhere else
//   admin / api      app.js's call log, classified by path
//   protocol         the same call log, everything else
//
// **ONE ACT USUALLY PRODUCES SEVERAL ROWS.** A sign-in at /authn/login writes
// three: the HTTP call, the credential being accepted, and the session that came
// out of it. They are three facts at three layers rather than one fact three
// times — and which of them you want depends on the question, which is exactly
// why the log does not choose. The page says so under the table.
//
// **IT OBSERVES ITSELF.** Drawing this page is console access, so it records an
// `admin.view` row, so the list is one longer than when you asked for it.
// Suppressing that would put a blind spot exactly where the person reading the
// audit log stands. It is stated instead, and `?category=` reads past it.
// ---------------------------------------------------------------------------

// Everything the page and the API both need out of one query string. Written as
// a view function for the reason the comment above consoleJson() gives: this
// console and /admin-api are two callers, and two hand-built copies of the same
// filtering would be two answers that each look right alone.
function auditView(query) {
  log.debug("Entering auditView().");
  const wantedCategory = String(query.category || '');
  const wantedAction = String(query.action || '');
  const wantedOutcome = String(query.outcome || '');
  const wantedActor = String(query.actor || '');
  const wantedText = String(query.q || '');
  const all = auditLog.list();
  const needle = wantedText.toLowerCase();
  const actorNeedle = wantedActor.toLowerCase();
  const filtered = all.filter(function (row) {
    if (wantedCategory && row.category !== wantedCategory) return false;
    if (wantedAction && row.action !== wantedAction) return false;
    if (wantedOutcome && row.outcome !== wantedOutcome) return false;
    // Substring rather than equality, and case-insensitively, because the actor
    // on a directory row may be the console key (`alice`) while the one on a
    // Kerberos row arrived as `alice@STS.MOCK` — the collapse to one key is done
    // where an identity is normalised and cannot be done for a row whose actor
    // is a bind DN. A substring finds the person either way.
    if (actorNeedle && (row.actor + ' ' + row.actorForm).toLowerCase()
                         .indexOf(actorNeedle) < 0) return false;
    // One free-text box over the three columns somebody would look in. The
    // summary alone would miss a DN that only appears in `target`, and a box
    // that silently searched one column while the reader assumed three is worse
    // than no box.
    if (needle && (row.summary + ' ' + row.target + ' ' + row.action)
                    .toLowerCase().indexOf(needle) < 0) return false;
    return true;
  });
  // Filter first, then page — the same order the tokens page uses and for the
  // same reason: paging a list and then filtering it gives a page 2 whose length
  // depends on what page 1 happened to hold.
  const paging = pagingOf(query, filtered.length);
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  const summary = auditLog.summary();
  log.debug("Leaving auditView(). " + shown.length + " row(s) of " +
            filtered.length + ".");
  return {
    wantedCategory: wantedCategory, wantedAction: wantedAction,
    wantedOutcome: wantedOutcome, wantedActor: wantedActor,
    wantedText: wantedText,
    all: all, filtered: filtered, paging: paging, shown: shown,
    summary: summary,
    json: {
      held: summary.held,
      // Everything ever recorded and everything dropped, both, because `held`
      // alone reads as "this is all there was" the moment the cap has bitten.
      recorded: summary.recorded, dropped: summary.dropped,
      maxEvents: summary.maxEvents, protocolCalls: summary.protocolCalls,
      matched: filtered.length, shown: shown.length,
      // The lowest and highest sequence numbers still held. A caller polling
      // this endpoint uses them rather than a timestamp: `seq` is monotonic and
      // never reused, so "everything after 4,102" is exact, and a gap between
      // the last seq you saw and `oldestSeq` is precisely how many events you
      // missed.
      oldestSeq: summary.oldestSeq, newestSeq: summary.newestSeq,
      byCategory: summary.byCategory, byOutcome: summary.byOutcome,
      byAction: summary.byAction,
      filter: { category: wantedCategory || null, action: wantedAction || null,
                outcome: wantedOutcome || null, actor: wantedActor || null,
                q: wantedText || null },
      // The clamped values, not what was asked for: `?page=999` on a two-page
      // list reports page 2, which is the page whose rows are in the reply.
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      // The vocabulary, off the data rather than out of a list in a test: what
      // the `category`, `action` and `outcome` filters take.
      categories: auditLog.CATEGORIES, actions: auditLog.ACTIONS,
      outcomes: auditLog.OUTCOMES,
      events: shown
    }
  };
}

// The outcome, in the same three colours the token states use — so that a page
// somebody has learned to skim once reads the same way here. `refused` is amber
// rather than red on purpose: it is this service working correctly and saying
// no, which is most of what a debugger of a protocol client wants to see, and
// painting it as a failure would bury the 5xx rows that are one.
function outcomeCell(outcome) {
  const cls = outcome === 'success' ? 'state-valid'
            : (outcome === 'refused' ? 'state-expired' : 'state-revoked');
  return '<span class="' + cls + '">' + esc(outcome) + '</span>';
}

// The detail object as one cell. Rendered as `key=value` pairs rather than as
// JSON because the column is narrow and a reader is scanning for one fact, not
// parsing a document; `?format=json` has the object itself for anything that is
// not a person.
function auditDetailCell(detail) {
  const keys = Object.keys(detail || {});
  if (!keys.length) return '<span class="state-none">—</span>';
  return keys.map(function (key) {
    return '<code>' + esc(key) + '=' + esc(detail[key]) + '</code>';
  }).join(' ');
}

// Who did it. The console key links to their page where this service has seen
// them authenticate, following the same three-state rule the groups page uses —
// a name it knows, a name it could file somebody under but never has, and no
// name at all. The PRESENTED form is shown underneath when it differs, because
// the collapse from `uid=alice,ou=users,dc=example,dc=com` to `alice` is a thing
// an auditor has to be able to see rather than take on trust.
function auditActorCell(row, known) {
  if (!row.actor && !row.actorForm) {
    return '<span class="state-none" title="Nothing here names an actor. An ' +
      'unauthenticated protocol call and an anonymous LDAP bind both look like ' +
      'this, and both are ordinary on a service that authenticates nobody.">—</span>';
  }
  const parts = [];
  if (row.actor) {
    parts.push(known[row.actor]
      ? '<a href="' + esc('/admin/users' + queryWith({ user: row.actor }, {})) +
        '">' + esc(row.actor) + '</a>'
      : '<span class="state-none" title="The console has no row for this name: ' +
        'nothing has authenticated as them in this process. A directory bind DN ' +
        'yields a name without there being anybody behind it.">' +
        esc(row.actor) + ' <em>(never here)</em></span>');
  }
  if (row.actorForm && row.actorForm !== row.actor) {
    parts.push('<code>' + esc(row.actorForm) + '</code>');
  }
  return parts.join('<br>');
}

function auditRow(row, known) {
  return '<tr>' +
    '<td class="num">' + esc(row.seq) + '</td>' +
    '<td>' + esc(whenText(row.at)) + '</td>' +
    '<td>' + esc(row.category) + '</td>' +
    '<td><code>' + esc(row.action) + '</code></td>' +
    '<td>' + outcomeCell(row.outcome) + '</td>' +
    '<td class="who">' + auditActorCell(row, known) + '</td>' +
    '<td class="who">' + (row.target ? '<code>' + esc(row.target) + '</code>'
                                     : '<span class="state-none">—</span>') +
      (row.channel ? '<br><span class="state-none">' + esc(row.channel) +
                     (row.protocol ? ' — ' + esc(row.protocol) : '') + '</span>' : '') +
    '</td>' +
    '<td>' + esc(row.summary) + '</td>' +
    '<td class="who">' + auditDetailCell(row.detail) + '</td>' +
    '</tr>';
}

// ---------------------------------------------------------------------------
// GET /admin/logout — WHAT ONE IDENTITY IS STILL SIGNED INTO, ANYWHERE, AND
// THE CONTROLS THAT END IT.
//
// The operator's half of `/logout`. The two are one behaviour — both call
// `logout.js`'s `inventoryFor()` and `terminate()` and neither decides anything
// the other does not — and they differ in exactly three ways, each of which is
// why this page exists rather than a link to the other:
//
//   * IT NAMES SOMEBODY ELSE. `/logout` defaults to whoever is holding the
//     cookie; this page always asks about a `user`, because an operator is
//     looking AT a person rather than being one.
//   * IT IS BEHIND THE CONSOLE'S TWO ROLES. Reading it needs Admin Read and the
//     form needs Admin Write, through the one gate at the top of this file.
//     `/logout` is behind neither, because signing yourself out must not
//     require a role.
//   * IT HAS AN UNDO, and `/logout` deliberately has not. A revoked token can
//     be restored and a Kerberos sign-out instant can be cleared — NON-SPEC in
//     both cases, and labelled so, for the reason /admin/tokens gives about its
//     own restore button: no authorization server could offer it, and having to
//     restart this service to get back to a working ticket turns a two-second
//     test into a two-minute one.
//
// THE PAGE PAGES AND THE OTHER ONE DOES NOT, which is the standing convention
// here rather than an inconsistency: a console list page gets paging and a
// management API resource beside it in the same change. `/logout` groups by
// family because a person reads it once; this filters and pages because an
// operator looking at a load generator's identity may have five hundred rows.
// ---------------------------------------------------------------------------

// Answered as an empty inventory rather than null when the slot is unfilled, so
// the page renders its own explanation instead of every caller guarding. Same
// shape spiffeListeners() uses one screen up.
function logoutInventoryFor(key) {
  log.debug("Entering logoutInventoryFor(). key=" + key);
  if (!logoutReader) {
    log.debug("Leaving logoutInventoryFor(). No logout reader is installed.");
    return null;
  }
  const inventory = logoutReader.inventoryFor(key, '');
  log.debug("Leaving logoutInventoryFor(). " + inventory.total + " row(s).");
  return inventory;
}

// The families, for the summary table and for the filter. Read off the slot so
// that a family added to logout.js appears here with no edit — the reason the
// prose lives over there and not in this file.
function logoutFamilies() {
  return logoutReader ? logoutReader.FAMILIES : [];
}

function logoutNoReaderNote() {
  return '<div class="err"><strong>The logout module is not loaded in this process.</strong> ' +
    'That is a require-order fault rather than a configuration one: <code>logout/logout.js</code> ' +
    'fills this console\'s slot at its own require time, and <code>server.js</code> requires it ' +
    'second to last. Nothing else on this console is affected.</div>';
}

// One row of the flattened table. The family is a COLUMN here where /logout
// makes it a heading, because this table is filtered and paged across families
// and a heading that appeared and vanished with the filter would be worse than
// a column that is always there.
// The opaque `back` field every form on this page carries, so that ending one
// item does not cost the reader their place in the list. Three other pages here
// build the same input as a local `const`; this is a function because six forms
// on this one page need it and a sixth hand-written copy is the one that would
// forget. It is REBUILT by listViewFromBack() on the way in and never echoed —
// the guarantee that keeps a hand-written `back` from reaching anything but
// another page of this same list.
function logoutBackField(back) {
  return '<input type="hidden" name="back" value="' + esc(back) + '">';
}

function logoutRowHtml(row, canWrite, back) {
  const button = row.terminable && canWrite
    ? '<form method="post" action="/admin/logout" style="display:inline">' +
      '<input type="hidden" name="action" value="end">' +
      '<input type="hidden" name="user" value="' + esc(row.user) + '">' +
      '<input type="hidden" name="select" value="' + esc(row.id) + '">' +
      logoutBackField(back) +
      '<button type="submit">End</button></form>'
    : (row.terminable ? '<span class="state-none">—</span>'
                      : '<span class="state-none" title="' + esc(row.why) + '">cannot</span>');
  return '<tr><td>' + esc(row.family) + '</td>' +
    // shortened() emits its OWN <code title=…> wrapper — the title is how the
    // full value stays recoverable — so it must NOT be escaped or wrapped again:
    // esc() around it prints the tags, which is what this cell did.
    '<td>' + shortened(row.label, 44) + '<br><span class="sub">' +
    esc(row.detail) + '</span>' +
    (row.terminable ? '' : '<br><span class="sub">' + esc(row.why) + '</span>') + '</td>' +
    '<td>' + esc(row.kind) + '</td>' +
    '<td class="sub">' + esc(whenText(row.startedAt)) + '</td>' +
    '<td class="sub">' + esc(whenText(row.expiresAt)) + '</td>' +
    '<td>' + button + '</td></tr>';
}

// The action behind every control on this page, and behind
// POST /admin-api/logout/{action}. Four of them, and the two NON-SPEC ones are
// labelled as such wherever they appear — see the header.
function logoutAction(body) {
  log.debug("Entering logoutAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const user = String(body.user || body.username || '').trim();
  if (!logoutReader) {
    log.debug("Leaving logoutAction(). No logout reader is installed.");
    return { ok: false, errors: ['The logout module is not loaded in this process, so there is ' +
                                 'nothing to end. See /admin/logout, which says why.'] };
  }
  if (!user) {
    log.debug("Leaving logoutAction(). No user was named.");
    return { ok: false, errors: ['Name the identity to act on in `user`. This page always acts ' +
                                 'on somebody by name — it is the operator\'s door, and ' +
                                 '/logout is the one that defaults to whoever is signed in.'] };
  }
  const key = stats.identityKeyOf(user);

  if (action === 'global') {
    const result = logoutReader.terminate(key, [], {
      actor: user, channel: 'console', by: 'the admin console at /admin/logout'
    });
    log.debug("Leaving logoutAction(). A global logout ended " + result.terminated.length + ".");
    return { ok: true, result: result, message: result.message +
             ' The relying parties that had to be NOTIFIED cannot be reached from here: a ' +
             'front-channel notification is an iframe in the signed-out person\'s browser, ' +
             'and this console is not that browser. /logout is where those load.' };
  }

  if (action === 'end') {
    const raw = body.select === undefined ? [] : body.select;
    const selection = (Array.isArray(raw) ? raw : [raw]).filter(Boolean).map(String);
    if (!selection.length) {
      // Deliberately NOT treated as a global logout here, which is the one
      // place this console departs from /logout's default. A form posting an
      // empty selection is a reader who ticked nothing and pressed a button; a
      // POST to /logout with an empty body is a caller who asked for
      // everything. Same absence, opposite intent, and the difference is which
      // door it arrived at.
      log.debug("Leaving logoutAction(). Nothing was selected.");
      return { ok: false, errors: ['Nothing was selected. Use the global logout button to end ' +
                                   'everything — this action ends only what it is given, so ' +
                                   'that an empty form cannot sign somebody out of everything ' +
                                   'by accident.'] };
    }
    const result = logoutReader.terminate(key, selection, {
      actor: user, channel: 'console', by: 'the admin console at /admin/logout'
    });
    log.debug("Leaving logoutAction(). Ended " + result.terminated.length + ".");
    return { ok: true, result: result, message: result.message };
  }

  if (action === 'restore-token') {
    // NON-SPEC, and it is /admin/tokens' restore reached from here rather than a
    // second one: stats.restore() is the same function against the same set.
    const jti = jtiFrom(String(body.jti || body.target || ''));
    if (!jti) {
      return { ok: false, errors: ['Name the token to restore in `jti`.'] };
    }
    const was = stats.restore(jti);
    return { ok: true, message: 'NON-SPEC: the token with jti ' + jti +
             (was ? ' is no longer revoked.' : ' was not revoked, so nothing changed.') +
             ' No authorization server could offer this — RFC 7009 has no such operation and a ' +
             'resource server may already have cached the refusal.' };
  }

  if (action === 'restore-kerberos') {
    // NON-SPEC in the same sense and for the same reason: it is what makes a
    // sign-out something a person can experiment with rather than restart out of.
    const was = krb5Principals.clearSignOut([key], krb5Principals.REALM);
    return { ok: true, message: 'NON-SPEC: the sign-out instant on ' + key + '@' +
             krb5Principals.REALM +
             (was ? ' (' + was.toISOString() + ') is cleared, so tickets issued before it are ' +
                    'accepted again.'
                  : ' was not set, so nothing changed.') +
             ' A real KDC has no such operation; a fresh AS-REQ is the supported way back and ' +
             'clears it too.' };
  }

  log.debug("Leaving logoutAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". There are four: global, end, ' +
                               'restore-token, restore-kerberos.'] };
}

// One route, two answers, and the choice is here rather than in the route so
// that /admin-api/logout makes the same one — the rule every view in this file
// follows.
function logoutView(req) {
  log.debug("Entering logoutView().");
  const wantedUser = String(req.query.user || '').trim();
  const gate = gateStateFor(req);
  const params = pageParamsOf(req.query);
  const back = queryWith(params, {});
  const families = logoutFamilies();

  if (!wantedUser) {
    // No name is not an error and not a 404: this page is a lookup, and the
    // list of everybody is /admin/users' job rather than a second copy here.
    const inner = messagesOf(req) +
      (logoutReader ? '' : logoutNoReaderNote()) +
      '<p class="note">Name an identity to see everything this service is still holding for ' +
      'them — every browser sign-on session, every token it can still revoke, every ' +
      'outstanding code, every directory connection bound as them, and the Kerberos ' +
      'sign-out instant — and to end any of it.</p>' +
      '<form method="get" action="/admin/logout">' +
      '<label>Identity <input name="user" value="" placeholder="alice"></label> ' +
      '<button type="submit">Look</button></form>' +
      '<h2>What a logout reaches</h2>' +
      '<table><thead><tr><th>Family</th><th>Protocol</th><th>Can it be ended?</th>' +
      '<th>What it is</th></tr></thead><tbody>' +
      families.map(function (family) {
        return '<tr><td>' + esc(family.label) + '</td><td>' + esc(family.protocol) + '</td>' +
          '<td>' + (family.terminable ? 'yes' : '<span class="state-none">no</span>') + '</td>' +
          '<td class="sub">' + esc(family.what) + '<br><em>' + esc(family.spec) + '</em></td></tr>';
      }).join('') + '</tbody></table>' +
      '<p class="note">The families that cannot be ended are listed on purpose. Nothing ' +
      'consults this service when a SAML assertion, a Kerberos service ticket or an X509-SVID ' +
      'is presented, so there is no revocation any issuer could perform — and a page that hid ' +
      'them would make a global logout look complete when it is not.</p>' +
      '<p class="note">A person signing THEMSELVES out uses <code>/logout</code>, which needs ' +
      'no console role and is where the front-channel notifications actually load: those are ' +
      'iframes in the signed-out person\'s own browser, and this console is not that browser.</p>';
    log.debug("Leaving logoutView(). The lookup form.");
    return { json: { user: '', known: false, families: families }, inner: inner,
             title: 'Sign-out' };
  }

  const key = stats.identityKeyOf(wantedUser);
  const inventory = logoutInventoryFor(key);
  if (!inventory) {
    log.debug("Leaving logoutView(). No logout reader.");
    return { json: { user: wantedUser, known: false, error: 'no logout reader is installed' },
             inner: messagesOf(req) + logoutNoReaderNote(), title: 'Sign-out',
             up: upTo('/admin/logout', wantedUser, listViewOf('/admin/logout', req.query)) };
  }

  // Flattened, because this table filters and pages ACROSS families — see the
  // header. The family's own prose stays on the summary above it.
  const all = [];
  inventory.families.forEach(function (family) {
    family.rows.forEach(function (r) {
      all.push(Object.assign({ user: wantedUser, familyLabel: family.label }, r));
    });
  });
  const wantedFamily = String(req.query.family || '').trim();
  const filtered = wantedFamily
    ? all.filter(function (r) { return r.family === wantedFamily; }) : all;
  const pg = pagedRows(req.query, filtered, { name: 'page', noun: 'live items' });
  const canWrite = gate.write;

  const summary = '<table><thead><tr><th>Family</th><th>Live</th><th>Endable</th>' +
    '<th>Protocol</th></tr></thead><tbody>' +
    inventory.families.map(function (family) {
      return '<tr><td><a href="' +
        esc('/admin/logout' + queryWith(params, { user: wantedUser, family: family.id,
                                                  page: '' })) + '">' +
        esc(family.label) + '</a></td>' +
        '<td>' + family.held + (family.notListed ? ' (' + family.notListed + ' not listed)' : '') +
        '</td>' +
        '<td>' + (family.terminable ? 'yes' : '<span class="state-none">no</span>') + '</td>' +
        '<td class="sub">' + esc(family.protocol) + '</td></tr>';
    }).join('') + '</tbody></table>';

  const inner = messagesOf(req) +
    '<p class="note"><strong>' + inventory.total + '</strong> live item(s) for <code>' +
    esc(wantedUser) + '</code>, in ' +
    inventory.families.filter(function (f) { return f.held; }).length + ' family/families. ' +
    'Filed under the key <code>' + esc(key) + '</code>, which is what folds <code>' +
    esc(wantedUser) + '</code>, <code>' + esc(wantedUser) + '@' +
    esc(krb5Principals.REALM) + '</code> and a <code>urn:</code> subject into one person.</p>' +
    summary +
    (canWrite
      ? '<form method="post" action="/admin/logout">' +
        '<input type="hidden" name="action" value="global">' +
        '<input type="hidden" name="user" value="' + esc(wantedUser) + '">' +
        logoutBackField(back) +
        '<p><button type="submit">Global logout — end everything above</button> ' +
        '<span class="sub">Everything endable, in every family, in one act. What cannot be ' +
        'ended is reported rather than skipped silently.</span></p></form>'
      : '<p class="note">Ending anything needs the Admin Write role.</p>') +
    '<h2>Live items' + (wantedFamily ? ' — ' + esc(wantedFamily) : '') + '</h2>' +
    perPageForm('/admin/logout', 'family', wantedFamily, pg.paging.perPage,
                'Filter by family, and choose how many rows a page holds.',
                { user: wantedUser }) +
    (pg.shown.length
      ? '<table><thead><tr><th>Family</th><th>What</th><th>Kind</th><th>Since</th>' +
        '<th>Until</th><th>End</th></tr></thead><tbody>' +
        pg.shown.map(function (r) { return logoutRowHtml(r, canWrite, back); }).join('') +
        '</tbody></table>' + pageNav('/admin/logout', params, pg.paging)
      : '<p class="note">Nothing live' + (wantedFamily ? ' in that family' : '') + '.</p>') +
    (canWrite
      ? '<h2>Undo — both NON-SPEC</h2>' +
        '<p class="note">Neither of these is an operation any real deployment could offer, and ' +
        'they are here for the reason /admin/tokens\' restore button is: having to restart this ' +
        'service to get back to a working credential turns a two-second test into a ' +
        'two-minute one.</p>' +
        '<form method="post" action="/admin/logout">' +
        '<input type="hidden" name="action" value="restore-kerberos">' +
        '<input type="hidden" name="user" value="' + esc(wantedUser) + '">' +
        logoutBackField(back) +
        '<p><button type="submit">Clear the Kerberos sign-out instant</button> ' +
        '<span class="sub">Tickets issued before it are accepted again. A fresh AS-REQ does ' +
        'this too, and is the supported way back.</span></p></form>' +
        '<form method="post" action="/admin/logout">' +
        '<input type="hidden" name="action" value="restore-token">' +
        '<input type="hidden" name="user" value="' + esc(wantedUser) + '">' +
        logoutBackField(back) +
        '<p><label>Restore a token by jti <input name="jti" placeholder="jti"></label> ' +
        '<button type="submit">Restore</button> ' +
        '<span class="sub">RFC 7009 has no such operation: a resource server may already have ' +
        'cached the refusal.</span></p></form>'
      : '');

  log.debug("Leaving logoutView(). " + inventory.total + " live item(s).");
  return {
    json: Object.assign({ user: wantedUser, known: true, canWrite: canWrite },
                        inventory, { rows: pg.shown, paging: pagingJson(pg.paging) }),
    inner: inner,
    title: 'Sign-out — ' + wantedUser,
    up: upTo('/admin/logout', wantedUser, listViewOf('/admin/logout', req.query))
  };
}

app.get('/admin/logout', function (req, res) {
  log.debug("Entering the admin sign-out page.");
  const view = logoutView(req);
  respond(req, res, view.json, view.title, '/admin/logout', view.inner, view.up);
  log.debug("Leaving the admin sign-out page.");
});

app.post('/admin/logout', function (req, res) {
  log.debug("Entering the admin sign-out action endpoint.");
  const body = parseBody(req);
  const result = logoutAction(body);
  // Back to the same person's page carrying whatever filter and page the form
  // came from — the rule every form on this console follows.
  const back = '/admin/logout' +
    queryWith(listViewFromBack('/admin/logout', body.back), { user: String(body.user || '') });
  respondToAction(req, res, back, result);
  log.debug("Leaving the admin sign-out action endpoint.");
});

app.get('/admin/audit', function (req, res) {
  log.debug("Entering the admin audit page.");
  const view = auditView(req.query);
  const paging = view.paging;
  const summary = view.summary;
  const known = knownUserKeys();
  // What every paging link carries with it. The page number is not in here —
  // pageNav() supplies that per link — for the reason the tokens page gives: a
  // "next" that dropped the filter would be page 2 of a different list.
  const filterParams = { category: view.wantedCategory, action: view.wantedAction,
                         outcome: view.wantedOutcome, actor: view.wantedActor,
                         q: view.wantedText,
                         per: req.query.per ? paging.perPage : '' };
  const nav = pageNav('/admin/audit', filterParams, paging);

  const rows = view.shown.map(function (row) {
    return auditRow(row, known);
  }).join('');

  const categoryOptions = ['<option value=""' + (view.wantedCategory ? '' : ' selected') +
                           '>any category</option>']
    .concat(auditLog.CATEGORIES.map(function (entry) {
      return '<option value="' + esc(entry.category) + '"' +
             (entry.category === view.wantedCategory ? ' selected' : '') + '>' +
             esc(entry.label) + ' (' + (summary.byCategory[entry.category] || 0) + ')</option>';
    })).join('');

  // Grouped by category, and built from the SAME table the category select is,
  // so the two cannot come to disagree about which action belongs where — which
  // they would, being two hand-written lists of the same twenty-four strings.
  const actionOptions = '<option value=""' + (view.wantedAction ? '' : ' selected') +
    '>any action</option>' +
    auditLog.CATEGORIES.map(function (entry) {
      const inGroup = auditLog.ACTIONS.filter(function (a) {
        return a.category === entry.category;
      });
      return '<optgroup label="' + esc(entry.label) + '">' + inGroup.map(function (a) {
        return '<option value="' + esc(a.action) + '"' +
               (a.action === view.wantedAction ? ' selected' : '') + '>' +
               esc(a.action) + ' (' + (summary.byAction[a.action] || 0) + ')</option>';
      }).join('') + '</optgroup>';
    }).join('');

  const outcomeOptions = ['<option value=""' + (view.wantedOutcome ? '' : ' selected') +
                          '>any outcome</option>']
    .concat(auditLog.OUTCOMES.map(function (name) {
      return '<option value="' + esc(name) + '"' +
             (name === view.wantedOutcome ? ' selected' : '') + '>' + esc(name) +
             ' (' + (summary.byOutcome[name] || 0) + ')</option>';
    })).join('');

  const perOptions = perPageOptions(paging.perPage);

  const filtering = view.wantedCategory || view.wantedAction || view.wantedOutcome ||
                    view.wantedActor || view.wantedText;

  const inner = messagesOf(req) +
    '<div class="tiles">' +
      tile(summary.held, 'events held') +
      tile(summary.recorded, 'events recorded') +
      tile(summary.dropped, 'dropped (oldest first)') +
      tile(summary.byCategory.directory || 0, 'directory') +
      tile(summary.byCategory.authentication || 0, 'authentications') +
      tile(summary.byCategory.session || 0, 'session events') +
    '</div>' +

    '<p class="note">What this service has been asked to do, in the order it was ' +
    'asked, newest first. The other pages here are <em>state</em> — how many calls, ' +
    'which tokens are still valid, who is in <code>cn=developers</code>. This one is ' +
    '<em>history</em>: the metrics page can say the directory holds eleven entries, and ' +
    'only this page can say that a twelfth was created at 14:02 and deleted at 14:03 by ' +
    'somebody bound as <code>uid=carol</code>, over LDAPS.</p>' +

    '<p class="note"><strong>No credential is ever recorded here.</strong> Not a ' +
    'password, not a bearer token, not an assertion, and no request or response body. ' +
    'An event carries the facts of what happened — who, what, where, the outcome — and ' +
    'the identifiers that are already safe to show. A modify names the attributes it ' +
    'changed and never their values, because a modify is where a <code>userPassword</code> ' +
    'gets set; a compare says whether it matched and not what was tried; an ' +
    '<code>authorization code</code> in a query string is replaced with ' +
    '<code>(redacted)</code>. The debug log is where somebody who wants the bodies looks, ' +
    'and it is a log rather than a web page.</p>' +

    '<p class="note"><strong>One act usually produces several rows, and they are not ' +
    'duplicates.</strong> Signing in at <code>/authn/login</code> writes three: the HTTP ' +
    'call (<code>protocol.call</code>), the credential being accepted ' +
    '(<code>authentication</code>) and the session that came out of it ' +
    '(<code>session.start</code>). Those are three facts at three layers, and which one ' +
    'answers your question depends on the question — a Kerberos AS-REQ authenticates ' +
    'somebody and starts no session at all, and an LDAP bind does both without an HTTP ' +
    'request anywhere in it. Collapsing them would mean choosing, once and for everybody, ' +
    'which of the three this page can answer.</p>' +

    '<p class="note"><strong>This log observes itself.</strong> Drawing this page is ' +
    'console access, so fetching it records an <code>admin.view</code> event and the list ' +
    'is one row longer than it was when you asked. That is not a defect being left ' +
    'unfixed: suppressing it would put a blind spot exactly where the person reading the ' +
    'audit log stands. Filter by category to read past it.</p>' +

    '<h2>What happened</h2>' +
    // No `page` input in this form, deliberately: changing a filter or the page
    // size returns to page 1. Carrying the old page number over would land
    // somebody on page 6 of a two-page result and the clamp in pagingOf() would
    // then move them again, which reads as the form ignoring them.
    '<form method="get" action="/admin/audit"><div class="formrow">' +
      '<label for="category">Category</label><select id="category" name="category">' +
        categoryOptions + '</select>' +
      '<label for="action">Action</label><select id="action" name="action">' +
        actionOptions + '</select>' +
      '<label for="outcome">Outcome</label><select id="outcome" name="outcome">' +
        outcomeOptions + '</select>' +
      '<label for="per">Per page</label><select id="per" name="per">' + perOptions +
        '</select>' +
    '</div><div class="formrow">' +
      '<label for="actor">Actor</label>' +
      '<input type="text" id="actor" name="actor" size="20" value="' +
        esc(view.wantedActor) + '" placeholder="alice">' +
      '<label for="q">Text</label>' +
      '<input type="text" id="q" name="q" size="30" value="' + esc(view.wantedText) +
        '" placeholder="a DN, a path, anything in the summary">' +
      '<button class="secondary">Filter</button>' +
      (filtering ? ' <a href="/admin/audit">clear</a>' : '') +
    '</div></form>' +
    '<p class="note">Category and Action narrow together, like any two filters, so an ' +
    'action from another category matches nothing — which is what an empty table below ' +
    'then means. Actor matches a substring of either spelling of the name, because the ' +
    'actor on a directory row is a bind DN and the one on a Kerberos row is ' +
    '<code>alice@REALM</code>; the collapse to a single key can only be done where an ' +
    'identity is normalised.</p>' +
    nav +
    '<table><tr><th class="num">#</th><th>When</th><th>Category</th><th>Action</th>' +
    '<th>Outcome</th><th>Actor</th><th>Target</th><th>What happened</th><th>Detail</th></tr>' +
    (rows || '<tr><td colspan="9">Nothing matches.</td></tr>') + '</table>' +
    nav +

    '<p class="note">' + view.filtered.length + ' row(s) match' +
    (paging.pages > 1 ? ', of which rows ' + paging.firstRow + '&ndash;' + paging.lastRow +
                        ' are on this page (' + paging.page + ' of ' + paging.pages + ')' : '') +
    '; ' + summary.held + ' held of ' + summary.recorded + ' recorded since this process ' +
    'started' +
    (summary.dropped
      ? ', and <strong>' + summary.dropped + ' dropped</strong> — the log holds at most ' +
        summary.maxEvents + ' events and discards the oldest first. Raise ' +
        '<code>audit.maxEvents</code> on <a href="/admin/config">the configuration page</a> ' +
        'if that is losing something you need.'
      : '. The cap is ' + summary.maxEvents + ' events and nothing has been dropped yet.') +
    '</p>' +

    '<p class="note">The <strong>#</strong> column is a sequence number, and it is ' +
    'monotonic and never reused — including across a drop. That is what makes it a stable ' +
    'name for an event: a caller can say &ldquo;I have read up to ' +
    (summary.newestSeq || 0) + '&rdquo; and mean it, where a row number would silently ' +
    'name a different event as soon as anything was discarded. <code>?format=json</code> ' +
    'carries <code>oldestSeq</code> and <code>newestSeq</code> for exactly that: a gap ' +
    'between the last one you saw and <code>oldestSeq</code> is how many events you ' +
    'missed.</p>' +

    '<h3>Where the rows come from</h3>' +
    '<p class="note">Six categories and five recording points, rather than a recording ' +
    'site per feature. Each of these is a funnel this service already had:</p>' +
    '<ul>' + auditLog.CATEGORIES.map(function (entry) {
      return '<li><strong>' + esc(entry.label) + '</strong> (<code>' + esc(entry.category) +
             '</code>, ' + (summary.byCategory[entry.category] || 0) + ') — ' +
             esc(entry.what) + '</li>';
    }).join('') + '</ul>' +

    '<p class="note"><strong>What is deliberately not on a row: the client\'s address.</strong> ' +
    'On a mock this service is reached over a compose bridge, through a published port, or ' +
    'from the same machine, so what it would record is the bridge — a fact about docker ' +
    'rather than about whoever made the call. A column that was right on a laptop and ' +
    'quietly wrong everywhere else is worse than no column. What a row does say is the ' +
    'CHANNEL it arrived on — <code>http</code>, <code>ldap</code>, <code>ldaps</code>, or ' +
    '<code>internal</code> for the things this service did on its own — which is the part ' +
    'that is actually knowable and is what somebody turning on LDAPS wants to check.</p>' +

    '<p class="note"><strong>It is in memory and dies with the process</strong>, like the ' +
    'counters, the sessions and the signing key. There is no compliance story here to ' +
    'serve: this service checks no password anywhere, so an audit log of it is a debugging ' +
    'aid and not a record of anything. It also has no clear button, and that is a decision ' +
    'rather than an omission — an erase control on an unprotected console would make the ' +
    'page unable to answer the one question an audit log exists for. Restarting the ' +
    'service is how you get an empty one.</p>' +

    '<p class="note">Two settings on <a href="/admin/config">the configuration page</a> ' +
    'change this page and both take effect immediately: <code>audit.maxEvents</code> (now ' +
    summary.maxEvents + ') is the cap, and <code>audit.protocolCalls</code> (now ' +
    (summary.protocolCalls ? 'on' : '<strong>off</strong>') + ') is whether ordinary ' +
    'protocol endpoint calls get a row at all. That last one is the noisy category — every ' +
    'JWKS poll and metadata fetch is an event — so turning it off is how somebody watching ' +
    'the directory or the console gets a readable page. It never affects the other five ' +
    'categories, and <a href="/admin/metrics">the metrics page</a> counts every call either ' +
    'way.</p>' +

    '<p class="note"><strong>One request is deliberately never a row here: ' +
    '<code>GET /healthcheck</code> when it answered 200.</strong> It is asked ' +
    'every few seconds for the whole life of this service — by the compose ' +
    'healthcheck and by every launcher that waits for it to come up — and it ' +
    'always answers the same thing, so recorded it would be by a wide margin ' +
    'the most common row on this page and would push everything you came here ' +
    'to read off the end of the cap above. A probe that answered anything ' +
    'ELSE is recorded as usual, which is the half worth knowing: a failing ' +
    'healthcheck is exactly the event somebody hunting a start-up failure is ' +
    'looking for. <a href="/admin/metrics">The metrics page</a> counts every ' +
    'probe either way.</p>' +

    '<p class="note">Paging is <code>?page=</code> and <code>?per=</code> (at most ' +
    MAX_ROWS + ' rows a page) and both work with <code>?format=json</code>, whose reply ' +
    'carries <code>page</code>, <code>pages</code> and <code>matched</code> so a test can ' +
    'walk the whole list without guessing where it ends. The same list is at ' +
    '<code>GET /admin-api/audit</code> with the same parameters.</p>';

  respond(req, res, view.json, 'Audit log', '/admin/audit', inner);
  log.debug("Leaving the admin audit page.");
});

// ---------------------------------------------------------------------------
// GET /admin/delegation — WHO ACTED ON WHOSE BEHALF, THROUGH WHAT, TO REACH WHAT.
//
// TWO TABLES, and the split between them is the point of the page rather than a
// layout choice:
//
//   * WHAT HAPPENED — one row per delegation ACT, from common/delegation.js.
//     Every mechanism in three protocol families, in one vocabulary, refusals
//     included.
//   * WHO MAY DELEGATE TO WHOM — the CONFIGURED policy, from
//     krb5_principals.js. It answers *why would this be refused* before anybody
//     has tried, and it is Kerberos-only because Kerberos is the only family
//     here that polices delegation at all. That absence is stated on the page
//     rather than left to be inferred from an empty column.
//
// **IT IS DELIBERATELY NOT A PROTOCOL PAGE**, which is why it is in Monitoring
// beside the tokens it points at and not under Protocols beside SAML and SCIM.
// A reader arriving here has a chain in their head — *alice hit the portal, the
// portal called the API* — and wants to know which hop invented which identity.
// Filing that under one of the three families would mean choosing which two
// thirds of the answer to hide.
//
// **NO FORM, AND THAT IS A DECISION.** Everything on this page is an
// observation: an act happened or it did not, and a policy row is somewhere
// else's configuration. There is nothing here to change, so rule 7 is satisfied
// by `GET /admin-api/delegation` alone — the same shape /admin/audit has, and
// for a related reason. A control that let somebody TYPE a chain would put
// invented rows in a table whose whole worth is that its rows are what actually
// happened.
// ---------------------------------------------------------------------------

// One party of a chain — up to two links, because a party can be a person AND an
// application and routinely is.
//
// `HTTP/frontend.example.com` has an entry under ou=users (it authenticates, so
// the funnel files it with the people) and an entry under ou=applications (a
// ticket was issued FOR it, so applications.js recorded it). A cell that showed
// one of them would send half the readers to the wrong page.
//
// Both links follow the three-state rule /admin/groups uses for a member: a name
// this console knows, a name it could file somebody under and never has, and no
// name at all. An application NOT in the registry is the ordinary case for an
// RFC 8693 `audience` and is worth seeing rather than hiding — the registry
// holds what this service was ASKED ABOUT, and a delegation naming something
// nobody has otherwise mentioned is exactly the row to notice.
function delegationPartyCell(party, known) {
  const parts = [];
  if (party.key) {
    parts.push(usersPageCell(party.key, known));
    if (party.presented && party.presented !== party.key) {
      parts.push('<code>' + esc(party.presented) + '</code>');
    }
  } else if (party.presented) {
    parts.push('<code>' + esc(party.presented) + '</code>');
  }
  if (party.application) {
    const registered = !!applications.get(party.application);
    parts.push(registered
      ? '<a href="' + esc('/admin/applications' +
          queryWith({ application: party.application }, {})) + '" title="This ' +
        'application is in the registry (ou=applications).">' +
        esc(party.application) + '</a>'
      : '<span class="state-none" title="No entry under ou=applications names ' +
        'this. The registry holds what this service has been ASKED ABOUT — a ' +
        'client_id presented, an AppliesTo a token was issued for, an SPN a ' +
        'ticket was cut for — and this delegation named something nobody has ' +
        'otherwise mentioned. That is ordinary for an RFC 8693 audience and is ' +
        'worth seeing rather than hiding.">' + esc(party.application) +
        ' <em>(not in the registry)</em></span>');
  }
  if (!parts.length) {
    return '<span class="state-none" title="Nothing here names this party, and ' +
      'on some mechanisms nothing can: a forwarded ticket-granting ticket is ' +
      'handed to whichever service the client chooses, and this KDC is never ' +
      'told which.">&mdash;</span>';
  }
  return parts.join('<br>');
}

// What a delegation CONSUMED or PRODUCED, as one cell. `key=value` pairs rather
// than JSON for the reason the audit log's detail cell gives — the column is
// narrow and a reader is scanning for one fact — and `?format=json` carries the
// objects for anything that is not a person.
function credentialCell(list, label) {
  if (!list || !list.length) {
    // NOTHING rather than a dash, because the two directions share one cell now:
    // a dash under the arrow for a direction that genuinely has no credential
    // reads as a value that failed to load, where an absent line reads as what
    // it is. The empty cell — no credential either way — is the one case that
    // still needs a mark, and it gets one from the caller having drawn neither.
    return '';
  }
  // A DIV rather than a run of spans, because the cell holds BOTH directions
  // now and everything in them is inline: without a block the "out" label
  // continued the last note of the "in" list on the same line, which read as one
  // sentence made of two.
  return '<div><span class="state-none">' + label + '</span><br>' +
    list.map(function (one) {
      return '<code>' + esc(one.kind) + '</code>' +
        // NOT esc()'d and not wrapped: shortened() returns the <code> element
        // with the whole value in its title. Escaping it printed the markup.
        (one.identifier ? ' ' + shortened(one.identifier, 10) : '') +
        (one.note ? '<br><span class="state-none">' + esc(one.note) + '</span>' : '');
    }).join('<br>') + '</div>';
}

// Impersonation is drawn as the LOUDER of the two, which is a judgement worth
// stating rather than leaving in a colour. It is not "worse" — both are ordinary
// and both are configured on purpose — but it is the one whose consequence is
// invisible everywhere else: nothing in the credential records that a middle
// tier was involved, so this table is the only place it will ever be seen. A
// delegation carries its own chain and can be read off the token later.
function modeCell(mode) {
  if (mode === 'impersonation') {
    return '<span class="state-expired" title="What came out names the initial ' +
      'identity and nothing else. The far end cannot tell an intermediary was ' +
      'involved, and neither can anybody reading the credential afterwards — ' +
      'which is why the issuer is the only place this is ever visible.">' +
      'impersonation</span>';
  }
  if (mode === 'delegation') {
    return '<span class="state-valid" title="What came out CARRIES the chain: ' +
      'an `act` claim, a composite ActAs, or S4U_DELEGATION_INFO in the PAC. ' +
      'The far end can see who is really asking.">delegation</span>';
  }
  return '<span class="state-none">&mdash;</span>';
}

function delegationOutcomeCell(row) {
  if (row.outcome === 'issued') {
    return '<span class="state-valid">issued</span>';
  }
  return '<span class="state-revoked" title="This service refused the ' +
    'delegation. The reason is the KDC\'s own words — the same text the client ' +
    'was sent — rather than a second wording written for this page.">refused</span>';
}

// TEN COLUMNS RATHER THAN TWELVE, and the two that were merged were merged
// because the table became unreadable rather than merely wide. `.who` breaks a
// long identifier anywhere (or one DN would widen the whole page), so every
// extra column costs the ones beside it: `HTTP/frontend.example.com@EXAMPLE.COM`
// wrapped over five lines at twelve and reads at ten.
//
// The protocol went into the mechanism cell because the mechanism id already
// carries it — every one of them begins `krb5-`, `wstrust-` or `oauth-` — so the
// column was saying a second time what the cell beside it said first. The two
// credential columns became one because a row usually has one of each and the
// arrows say which: what went IN, what came OUT.
// `options.listView` is what the reader had the table filtered to, carried into
// the drill-down so that its way back is the page they left rather than the top
// of an unfiltered list — the rule listViewOf() states. `options.chainLink` is
// false on the chain page itself, where every row belongs to the chain being
// drawn and the link would point at the page it is on.
function delegationRow(row, known, options) {
  const opts = options || {};
  const chainLink = opts.chainLink === undefined ? true : !!opts.chainLink;
  return '<tr>' +
    // THE WAY TO THE PICTURE OF THIS ONE RELATIONSHIP, in the narrowest column
    // on the page rather than in an eleventh of its own. The header above says
    // why this table is ten columns and not twelve: `.who` breaks a long
    // identifier anywhere, so every column costs the ones beside it. `#` is the
    // one cell whose content is four digits and can carry a second line for
    // nothing.
    //
    // It goes to the CHAIN and not to the act, which the link says out loud —
    // an act has no picture of its own, and a reader who clicked expecting one
    // would read the times off a diagram that has them taken out.
    '<td class="num">' + esc(row.seq) +
      (chainLink
        ? '<br><a href="' + esc('/admin/delegation/chain' +
            queryWith(opts.listView || {}, { chain: row.chainKey })) +
          '" title="Draw THIS relationship on its own — the whole chain this ' +
          'act belongs to, with everything else in the service left out.">chain</a>'
        : '') + '</td>' +
    '<td>' + esc(whenText(row.at)) + '</td>' +
    '<td><code>' + esc(row.type) + '</code><br>' +
      '<span class="state-none">' + esc(row.typeLabel) + '</span><br>' +
      '<span class="state-none">' + esc(row.protocol) +
      (row.spec ? ' &middot; ' + esc(row.spec) : '') + '</span></td>' +
    '<td>' + modeCell(row.mode) + '</td>' +
    '<td>' + delegationOutcomeCell(row) + '</td>' +
    '<td class="who">' + delegationPartyCell(row.initial, known) + '</td>' +
    '<td class="who">' + delegationPartyCell(row.intermediary, known) + '</td>' +
    '<td class="who">' + delegationPartyCell(row.target, known) + '</td>' +
    '<td>' + (row.outcome === 'refused'
              ? esc(row.reason)
              : (row.authorizedBy ? esc(row.authorizedBy)
                                  : '<span class="state-none">&mdash;</span>')) +
      (row.note ? '<br><span class="state-none">' + esc(row.note) + '</span>' : '') +
    '</td>' +
    '<td class="who">' + credentialCell(row.consumed, '&rarr; in') +
      credentialCell(row.produced, '&larr; out') + '</td>' +
    '</tr>';
}

// One configured pair. `setOn` is the column to read first and is why the two
// mechanisms are in ONE table rather than two: the messages are identical, the
// KDC options are identical, and the whole difference is which of the two
// accounts carries the permission. Two tables would have let a reader learn one
// of them without ever meeting that fact.
// FIVE COLUMNS, and `requires` is not one of them although the JSON carries it
// per pair. It is a property of the MECHANISM rather than of the pair — every
// classic row has the same sentence and every resource-based row has the other
// — so as a column it was the same two paragraphs repeated down the table,
// squeezing the three columns that DO differ per row into unreadable shreds.
// It is said once above the table instead. The API keeps it on every pair,
// because a caller reading one pair should not have to know that.
function policyPairRow(pair) {
  return '<tr>' +
    '<td><code>' + esc(pair.mechanism) + '</code><br><span class="state-none">' +
      esc(pair.type) + '</span></td>' +
    '<td class="who"><code>' + esc(pair.frontEnd) + '</code></td>' +
    '<td class="who"><code>' + esc(pair.target) + '</code>' +
      (pair.targetKnown ? ''
        : '<br><span class="state-revoked">no such principal here</span>') +
    '</td>' +
    '<td class="who"><code>' + esc(pair.attribute) + '</code><br>' +
      '<span class="state-none">on the ' + esc(pair.setOnRole) + ', <code>' +
      esc(pair.setOn) + '</code></span></td>' +
    '<td>' + (pair.warning
              ? '<span class="state-expired">' + esc(pair.warning) + '</span>'
              : '<span class="state-valid">nothing else is missing</span>') +
    '</td>' +
    '</tr>';
}

function policyAccountRow(account) {
  const flags = [];
  if (account.notDelegated) flags.push('NOT_DELEGATED');
  if (account.trustedToAuthenticateForDelegation) {
    flags.push('TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION');
  }
  if (account.okAsDelegate) flags.push('ok-as-delegate');
  return '<tr>' +
    '<td class="who"><code>' + esc(account.principal) + '</code></td>' +
    '<td>' + flags.map(function (f) {
      return '<code>' + esc(f) + '</code>';
    }).join('<br>') + '</td>' +
    '<td>' + account.effects.map(function (e) {
      return esc(e);
    }).join('<br><br>') + '</td>' +
    '</tr>';
}

// The whole view, filtered and paged, for the page AND for
// GET /admin-api/delegation. One function for the reason the block above
// consoleJson() gives: the filtering and the paging are work both need, and two
// copies of it would be two answers that each looked right alone.
function delegationView(query) {
  log.debug("Entering delegationView().");
  const wantedType = String(query.type || '');
  const wantedMode = String(query.mode || '');
  const wantedOutcome = String(query.outcome || '');
  const wantedProtocol = String(query.protocol || '');
  const wantedText = String(query.q || '');
  const all = delegation.list();
  const needle = wantedText.toLowerCase();
  const filtered = all.filter(function (row) {
    if (wantedType && row.type !== wantedType) return false;
    if (wantedMode && row.mode !== wantedMode) return false;
    if (wantedOutcome && row.outcome !== wantedOutcome) return false;
    if (wantedProtocol && row.protocol !== wantedProtocol) return false;
    // One free-text box over every party of the chain and both explanations,
    // because the question a reader arrives with names ONE of them — a person,
    // an SPN, an attribute — and does not know which column it will be in. A
    // box that silently searched one column while the reader assumed six is
    // worse than no box.
    if (needle) {
      const hay = [row.initial.key, row.initial.presented, row.initial.application,
                   row.intermediary.key, row.intermediary.presented,
                   row.intermediary.application,
                   row.target.key, row.target.presented, row.target.application,
                   row.authorizedBy, row.reason, row.note]
                    .join(' ').toLowerCase();
      if (hay.indexOf(needle) < 0) return false;
    }
    return true;
  });
  // Filter first, then page — the same order the tokens and audit pages use and
  // for the same reason: paging a list and then filtering it gives a page 2
  // whose length depends on what page 1 happened to hold.
  const paging = pagingOf(query, filtered.length, { noun: 'acts' });
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  const summary = delegation.summary();
  // The chains of what MATCHED rather than of everything held: a reader who has
  // filtered to one person wants that person's chains, and a count that ignored
  // the filter would disagree with the table under it.
  const chains = delegation.chainList(filtered);
  // THE PICTURE'S MODEL, BUILT HERE AND NOT IN THE ROUTE THAT DRAWS IT, for the
  // reason the whole of this function exists: /admin/delegation/map, this page's
  // ?format=json and GET /admin-api/delegation must all be describing the same
  // graph, and three calls to delegation.graph() with three ideas about which
  // acts to pass it would be three answers that each looked right alone. Of the
  // matched acts rather than the paged ones — a diagram of one page of a list is
  // a diagram of the pagination.
  const graph = delegation.graph(filtered);
  // EVERY APPLICATION AMONG THE MATCHED ACTS, in whatever role it played. It
  // follows the filter for the same reason `chains` does — a reader who has
  // narrowed to one person wants that person's applications — and there is one
  // consequence worth stating rather than leaving to be met: the PAGE this
  // chooser opens is not filtered. `/admin/delegation/application` shows
  // everything that application has ever been part of, because "what exists
  // because of this thing" is not a question a half-answer is useful for. The
  // chooser says so.
  const applicationsInvolved = delegation.applicationList(filtered);
  const policy = krb5Principals.delegationPolicy();
  log.debug("Leaving delegationView(). " + shown.length + " act(s) of " +
            filtered.length + ", " + chains.length + " chain(s).");
  return {
    wantedType: wantedType, wantedMode: wantedMode, wantedOutcome: wantedOutcome,
    wantedProtocol: wantedProtocol, wantedText: wantedText,
    all: all, filtered: filtered, paging: paging, shown: shown,
    summary: summary, chains: chains, graph: graph, policy: policy,
    applications: applicationsInvolved,
    json: {
      held: summary.held,
      // Everything ever recorded and everything dropped, both, because `held`
      // alone reads as "this is all there was" the moment the cap has bitten.
      recorded: summary.recorded, dropped: summary.dropped,
      maxRecords: summary.maxRecords,
      matched: filtered.length, shown: shown.length,
      // The lowest and highest sequence numbers still held. A caller polling
      // this endpoint uses them rather than a timestamp, for the reason
      // /admin-api/audit gives: `seq` is monotonic and never reused, so
      // "everything after 41" is exact.
      oldestSeq: summary.oldestSeq, newestSeq: summary.newestSeq,
      byType: summary.byType, byMode: summary.byMode,
      byOutcome: summary.byOutcome, byProtocol: summary.byProtocol,
      filter: { type: wantedType || null, mode: wantedMode || null,
                outcome: wantedOutcome || null, protocol: wantedProtocol || null,
                q: wantedText || null },
      // The clamped values, not what was asked for: `?page=999` on a two-page
      // list reports page 2, which is the page whose rows are in the reply.
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      // The vocabulary, off the store rather than out of a list here: what the
      // `type`, `mode` and `outcome` filters take, and what each of them means.
      // A mechanism cannot be recordable and unfilterable, nor offered and
      // never occur.
      types: delegation.TYPES, modes: delegation.MODES,
      outcomes: delegation.OUTCOMES, roles: delegation.ROLES,
      acts: shown,
      // The DISTINCT chains among what matched — one entry per (type, initial,
      // intermediary, target) — which is what the visualisation will be drawn
      // from and is already the more useful answer for a caller asking "what
      // talks to what".
      chains: chains,
      // THE APPLICATIONS among what matched, in whatever role each played, with
      // the counts the chooser on the page is built from. It is a strictly
      // different question from `chains` and cannot be derived from one: an
      // application is keyed on its IDENTIFIER — see applicationList() in
      // delegation.js — and a chain names three parties, one of which routinely
      // carries an application identifier that is not its identity.
      applications: applicationsInvolved,
      // THE PICTURE, as a graph. The nodes and edges /admin/delegation/map
      // draws, with the credentials folded onto each edge and the list of what
      // was issued — so a test can assert what that page shows without parsing
      // an SVG, which is the only way a drawing can be kept honest from outside.
      // It is a strictly different shape from `chains` and not a second copy of
      // it: a chain has three parties and therefore up to TWO edges, and the
      // boxes are SHARED between chains, which is the whole reason to draw one.
      graph: graph,
      // The configured policy: who MAY delegate to whom, and the account flags
      // that decide what delegation can do to somebody. Kerberos only, because
      // it is the only family here that polices this at all.
      policy: policy
    }
  };
}

app.get('/admin/delegation', function (req, res) {
  log.debug("Entering the admin delegation page.");
  const view = delegationView(req.query);
  const paging = view.paging;
  const summary = view.summary;
  const policy = view.policy;
  const known = knownUserKeys();
  // What every paging link carries with it. The page number is not in here —
  // pageNav() supplies that per link — for the reason the tokens page gives: a
  // "next" that dropped the filter would be page 2 of a different list.
  const filterParams = { type: view.wantedType, mode: view.wantedMode,
                         outcome: view.wantedOutcome,
                         protocol: view.wantedProtocol, q: view.wantedText,
                         per: req.query.per ? paging.perPage : '' };
  const nav = pageNav('/admin/delegation', filterParams, paging);

  const listView = listViewOf('/admin/delegation', req.query);
  const rows = view.shown.map(function (row) {
    return delegationRow(row, known, { listView: listView });
  }).join('');

  // Grouped by protocol and built from the SAME table the filter offers, so the
  // two cannot come to disagree about which mechanism belongs to which family.
  const protocolsInOrder = [];
  delegation.TYPES.forEach(function (entry) {
    if (protocolsInOrder.indexOf(entry.protocol) < 0) {
      protocolsInOrder.push(entry.protocol);
    }
  });
  const typeOptions = '<option value=""' + (view.wantedType ? '' : ' selected') +
    '>any mechanism</option>' +
    protocolsInOrder.map(function (protocol) {
      return '<optgroup label="' + esc(protocol) + '">' +
        delegation.TYPES.filter(function (entry) {
          return entry.protocol === protocol;
        }).map(function (entry) {
          return '<option value="' + esc(entry.type) + '"' +
                 (entry.type === view.wantedType ? ' selected' : '') + '>' +
                 esc(entry.label) + ' (' + (summary.byType[entry.type] || 0) +
                 ')</option>';
        }).join('') + '</optgroup>';
    }).join('');

  const modeOptions = ['<option value=""' + (view.wantedMode ? '' : ' selected') +
                       '>either kind</option>']
    .concat(delegation.MODES.map(function (entry) {
      return '<option value="' + esc(entry.mode) + '"' +
             (entry.mode === view.wantedMode ? ' selected' : '') + '>' +
             esc(entry.label) + ' (' + (summary.byMode[entry.mode] || 0) + ')</option>';
    })).join('');

  const outcomeOptions = ['<option value=""' + (view.wantedOutcome ? '' : ' selected') +
                          '>any outcome</option>']
    .concat(delegation.OUTCOMES.map(function (name) {
      return '<option value="' + esc(name) + '"' +
             (name === view.wantedOutcome ? ' selected' : '') + '>' + esc(name) +
             ' (' + (summary.byOutcome[name] || 0) + ')</option>';
    })).join('');

  const perOptions = perPageOptions(paging.perPage);

  const filtering = view.wantedType || view.wantedMode || view.wantedOutcome ||
                    view.wantedProtocol || view.wantedText;

  const inner = messagesOf(req) +
    '<div class="tiles">' +
      tile(summary.held, 'acts held') +
      tile(view.chains.length, 'distinct chains') +
      tile(summary.byMode.impersonation || 0, 'impersonations') +
      tile(summary.byMode.delegation || 0, 'delegations') +
      tile(summary.byOutcome.refused || 0, 'refused') +
      tile(policy.pairs.length, 'configured pairs') +
    '</div>' +

    '<p class="note"><strong>Who acted on whose behalf, through what, to reach ' +
    'what.</strong> Three of the protocol families here can delegate and each ' +
    'calls it something different — Kerberos has S4U2Self, two flavours of ' +
    'S4U2Proxy and a forwarded ticket-granting ticket; WS-Trust has ' +
    '<code>OnBehalfOf</code> and <code>ActAs</code>; OAuth 2.0 Token Exchange ' +
    'has impersonation and delegation. This page records all eight against one ' +
    'model, because the question people arrive with is protocol-independent: ' +
    '<em>alice never touched the back end, so why is there a ticket to it in ' +
    'her name, and who asked for it?</em></p>' +

    '<p class="note"><strong>The three columns in the middle are the layers of ' +
    'the architecture</strong>, and the names are this page\'s own rather than ' +
    'any protocol\'s — a Kerberos front end, a WS-Trust requester and an OAuth ' +
    'client doing an exchange are the same position in the same picture:</p>' +
    '<ul>' + delegation.ROLES.map(function (entry) {
      return '<li><strong>' + esc(entry.label) + '</strong> — ' + esc(entry.what) +
             '</li>';
    }).join('') + '</ul>' +
    '<p class="note">A party can be a <em>person</em>, an <em>application</em>, ' +
    'or both, and the middle one routinely is both: ' +
    '<code>HTTP/frontend.example.com</code> has an entry under ' +
    '<code>ou=users</code> (it authenticates, so this service files it with the ' +
    'people) and an entry under <code>ou=applications</code> (tickets are issued ' +
    'FOR it). Each cell links to whichever of the two exist. An application ' +
    'marked <em>not in the registry</em> is not an error — the registry holds ' +
    'what this service has been ASKED ABOUT, and an RFC 8693 <code>audience</code> ' +
    'nobody has otherwise mentioned is exactly that.</p>' +

    '<p class="note"><strong>Impersonation and delegation are the axis worth ' +
    'filtering on</strong>, and they are not a matter of degree. Under a ' +
    'delegation the credential CARRIES the chain — an <code>act</code> claim, a ' +
    'composite <code>ActAs</code>, <code>S4U_DELEGATION_INFO</code> in the PAC — ' +
    'so the far end can see who is really asking and can decide differently ' +
    'because of it. Under an impersonation nothing does, which means <strong>this ' +
    'page is the only place it will ever be visible</strong>: no reading of the ' +
    'token afterwards, at the resource server or in a log, can recover the fact ' +
    'that a middle tier was involved.</p>' +

    '<p class="note"><strong>Refusals are recorded and are most of what this ' +
    'page is for.</strong> A delegation that worked tells you the plumbing is ' +
    'connected. A delegation that was refused names the two accounts, the two ' +
    'attributes and which of them was missing, at the moment the KDC decided — ' +
    'and the text in the <em>Authorized by / why not</em> column is the KDC\'s ' +
    'OWN words, the same sentence the client was sent, rather than a second ' +
    'wording that could come to disagree with it.</p>' +

    // THE WAY TO THE PICTURE, ABOVE THE TABLE RATHER THAN UNDER IT. The chains
    // table lower down is what the diagram is drawn from and the obvious place
    // to put this link is beside it — which is most of a page below the fold on
    // a busy day. A reader who wants the shape of things wants it before they
    // have read four hundred rows, so the offer is here and is repeated where
    // the chains are.
    //
    // It carries the CURRENT FILTER AND NOT THE PAGE: the picture has no paging
    // (see that route's header) and a `page` in its query would be a parameter
    // that does nothing.
    '<p class="note"><a class="btn" href="' +
      esc('/admin/delegation/map' + queryWith({ type: view.wantedType,
        mode: view.wantedMode, outcome: view.wantedOutcome,
        protocol: view.wantedProtocol, q: view.wantedText }, {})) +
      '">See this as a picture &rarr;</a> ' +
    '<strong>The same acts drawn as a diagram</strong> — a stick figure per ' +
    'person, a rectangle per application, a hexagon for this service in this ' +
    'trust realm, and a line per relationship: who acts for whom, and what each ' +
    'credential was FOR. ' + (filtering
      ? 'It opens with the filter you have set here.'
      : 'Filter first if this list is long — the picture is drawn from ' +
        'everything that matches, not from one page.') + '</p>' +

    // THE SECOND WAY IN, BESIDE THE PICTURE AND ABOVE THE TABLE. The picture
    // link answers "what does all of this look like"; this answers "what has
    // this one application got itself into", which is the other question a
    // person arrives with and the one the tables below cannot be sorted into.
    // Both are here rather than at the foot, because a reader who wants either
    // wants it before reading four hundred rows.
    '<p class="note"><strong>Or pivot on an application.</strong> A delegation ' +
    'has three parties and an application can be two of them — the ' +
    '<em>intermediary</em> that acts on somebody\'s behalf, and the ' +
    '<em>target</em> the credential is for. Choose one and see everything that ' +
    'has been delegated through it or to it, in either role, with every ' +
    'credential that came out. <strong>The chooser follows the filter above and ' +
    'the page it opens does not</strong>: it shows everything that application ' +
    'has ever been part of, because <em>what exists because of this thing</em> ' +
    'is not a question a half-answer is useful for.</p>' +
    delegationApplicationChooser(view.applications, '', listView) +

    '<h2>What happened</h2>' +
    // No `page` input in this form, deliberately: changing a filter or the page
    // size returns to page 1. Carrying the old page number over would land
    // somebody on page 6 of a two-page result and the clamp in pagingOf() would
    // then move them again, which reads as the form ignoring them.
    '<form method="get" action="/admin/delegation"><div class="formrow">' +
      '<label for="type">Mechanism</label><select id="type" name="type">' +
        typeOptions + '</select>' +
      '<label for="mode">Kind</label><select id="mode" name="mode">' +
        modeOptions + '</select>' +
      '<label for="outcome">Outcome</label><select id="outcome" name="outcome">' +
        outcomeOptions + '</select>' +
      '<label for="per">Per page</label><select id="per" name="per">' + perOptions +
        '</select>' +
    '</div><div class="formrow">' +
      '<label for="q">Text</label>' +
      '<input type="text" id="q" name="q" size="40" value="' + esc(view.wantedText) +
        '" placeholder="a person, an SPN, a client_id, an attribute">' +
      '<button class="secondary">Filter</button>' +
      (filtering ? ' <a href="/admin/delegation">clear</a>' : '') +
    '</div></form>' +
    '<p class="note">The text box searches every party of the chain and both ' +
    'explanations at once, because the fact somebody arrives with names one of ' +
    'them and they do not know which column it will be in.</p>' +
    '<p class="note">The <strong>chain</strong> link under each row\'s number ' +
    'draws THAT RELATIONSHIP on its own — the whole chain the act belongs to, ' +
    'with everything else in the service left out. It goes to the chain rather ' +
    'than to the act because an act has no picture of its own: a diagram has ' +
    'the times taken out, and four acts a second apart between the same three ' +
    'parties are one line.</p>' +
    nav +
    '<table><tr><th class="num">#</th><th>When</th><th>Mechanism</th>' +
    '<th>Kind</th><th>Outcome</th><th>Initial identity</th>' +
    '<th>Intermediary</th><th>Target</th><th>Authorized by / why not</th>' +
    '<th>Credentials</th></tr>' +
    (rows || '<tr><td colspan="10">' +
      (view.all.length
        ? 'Nothing matches this filter.'
        : 'Nothing has delegated anything yet. Three things put a row here: a ' +
          'Kerberos S4U2Self, S4U2Proxy or forwarded-TGT request at the KDC; a ' +
          'WS-Trust <code>RequestSecurityToken</code> carrying ' +
          '<code>&lt;wst:OnBehalfOf&gt;</code> or <code>&lt;wst14:ActAs&gt;</code>; ' +
          'and an RFC 8693 token exchange at <code>/oauth2/token</code>. A ' +
          'REFUSED attempt counts — the delegation page in the debugger will ' +
          'produce one on purpose.') +
      '</td></tr>') + '</table>' +
    nav +

    '<p class="note">' + view.filtered.length + ' act(s) match' +
    (paging.pages > 1 ? ', of which rows ' + paging.firstRow + '&ndash;' + paging.lastRow +
                        ' are on this page (' + paging.page + ' of ' + paging.pages + ')' : '') +
    '; ' + summary.held + ' held of ' + summary.recorded + ' recorded since this ' +
    'process started' +
    (summary.dropped
      ? ', and <strong>' + summary.dropped + ' dropped</strong> — this page holds ' +
        'at most ' + summary.maxRecords + ' acts and discards the oldest first. ' +
        'Raise <code>delegation.maxRecords</code> on ' +
        '<a href="/admin/config">the configuration page</a> if that is losing ' +
        'something you need.'
      : '. The cap is ' + summary.maxRecords + ' acts and nothing has been ' +
        'dropped yet.') +
    ' The <strong>#</strong> column is a sequence number and is monotonic and ' +
    'never reused, including across a drop, so <code>?format=json</code>\'s ' +
    '<code>oldestSeq</code> and <code>newestSeq</code> let a caller poll this ' +
    'without guessing what it missed.</p>' +

    '<h2>The chains</h2>' +
    '<p class="note">The same acts with the time and the credentials taken out: ' +
    'one row per distinct <em>(mechanism, initial, intermediary, target)</em>. ' +
    '<a href="/admin/delegation/map">This is what the picture is drawn from</a> ' +
    '— one edge per row, and up to TWO lines per row, because a chain has three ' +
    'parties. It is already the more useful answer to <em>what talks to what</em>. ' +
    'The outcome ' +
    'is deliberately NOT part of a chain\'s identity, so a chain refused nine ' +
    'times and then fixed is one row that changes rather than two that do not ' +
    'meet. <strong>The last column draws one row alone</strong>, which is the ' +
    'answer to <em>what is this one, exactly</em> on a service that has been ' +
    'driven for an afternoon and whose whole picture is forty boxes.</p>' +
    '<table><tr><th>Mechanism</th><th>Kind</th><th>Initial identity</th>' +
    '<th>Intermediary</th><th>Target</th><th>Acts</th><th>Last seen</th>' +
    '<th>Just this one</th></tr>' +
    (view.chains.map(function (chain) {
      return '<tr>' +
        '<td><code>' + esc(chain.type) + '</code></td>' +
        '<td>' + modeCell(chain.mode) + '</td>' +
        '<td class="who">' + delegationPartyCell(chain.initial, known) + '</td>' +
        '<td class="who">' + delegationPartyCell(chain.intermediary, known) + '</td>' +
        '<td class="who">' + delegationPartyCell(chain.target, known) + '</td>' +
        '<td class="num">' + esc(chain.acts) + ' — ' +
          '<span class="state-valid">' + esc(chain.issued) + ' issued</span>, ' +
          (chain.refused
            ? '<span class="state-revoked">' + esc(chain.refused) + ' refused</span>'
            : '<span class="state-none">0 refused</span>') + '</td>' +
        '<td>' + esc(whenText(chain.lastAt)) + '</td>' +
        // An eighth column here where the acts table above puts the same link
        // inside its `#` cell, and the difference is width: this table's five
        // party columns are already narrow, but it has seven of them against
        // that one's ten and none of the long explanation cells. A column can be
        // afforded here and cannot be there.
        '<td><a href="' + esc('/admin/delegation/chain' +
          queryWith(listView, { chain: chain.chainKey })) +
          '">picture &rarr;</a></td>' +
        '</tr>';
    }).join('') || '<tr><td colspan="8">No chains yet.</td></tr>') + '</table>' +

    '<h2>Who may delegate to whom</h2>' +
    '<p class="note"><strong>This half is CONFIGURATION rather than history, and ' +
    'it is Kerberos only.</strong> That is not an omission: Kerberos is the one ' +
    'family here that polices delegation at all. WS-Trust puts no authorization ' +
    'on <code>OnBehalfOf</code> or <code>ActAs</code> and this service adds none; ' +
    'RFC 8693 leaves the policy to the authorization server and this one has ' +
    'none, so any client may exchange any token for a token about anybody. Both ' +
    'of those are stated on every row they produce above, in the same column ' +
    'that names an attribute for a Kerberos row — <strong>the asymmetry is the ' +
    'most useful thing on this page</strong>: the same picture, policed at one ' +
    'end and not at the other.</p>' +
    '<p class="note">The whole of the KDC\'s decision rests on two attributes on ' +
    'two OPPOSITE accounts, which is why they are in one table with a column ' +
    'saying which account carries the permission. Same messages, same KDC ' +
    'options, opposite direction of trust — and the second one turns <em>I can ' +
    'write to this computer object</em> into <em>I can reach this service as ' +
    'anybody</em>.</p>' +
    '<p class="note">Each mechanism needs one thing BEYOND the attribute, and ' +
    'it is the same thing on every row of that kind, so it is here rather than ' +
    'in a column: <strong>classic</strong> needs a FORWARDABLE evidence ' +
    'ticket, which S4U2Self returns only to an account flagged ' +
    '<code>TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION</code>; ' +
    '<strong>resource-based</strong> needs <code>PA-PAC-OPTIONS</code> ' +
    '(padata type 167) carrying the resource-based bit, and [MS-SFU] requires ' +
    'a KDC to answer <code>KDC_ERR_BADOPTION</code> without it — an error that ' +
    'says nothing about padata. Resource-based needs no forwardable evidence ' +
    'and no flag on the front end at all, which is why it is the easier ' +
    'path.</p>' +
    '<table><tr><th>Mechanism</th><th>Front end (who acts)</th>' +
    '<th>Target (what is reached)</th><th>Attribute, and where it lives</th>' +
    '<th>Anything missing?</th></tr>' +
    (policy.pairs.map(policyPairRow).join('') ||
      '<tr><td colspan="5">No principal here is configured for constrained ' +
      'delegation of either kind.</td></tr>') + '</table>' +

    '<h3>Account flags</h3>' +
    '<p class="note">Two of these three STOP delegation rather than permit it, ' +
    'and the third is not a control at all. An account appears here whether or ' +
    'not any pair above names it, because an account named in no pair is ' +
    'precisely the one somebody is wondering about.</p>' +
    '<table><tr><th>Principal</th><th>Flags</th><th>What each one does</th></tr>' +
    (policy.accounts.map(policyAccountRow).join('') ||
      '<tr><td colspan="3">No principal here carries one of these flags.</td></tr>') +
    '</table>' +

    '<h3>The mechanisms</h3>' +
    '<p class="note">Read off the same table this page records against, so a ' +
    'mechanism cannot be recordable and undocumented, nor described here and ' +
    'never occur.</p>' +
    '<ul>' + delegation.TYPES.map(function (entry) {
      return '<li><strong>' + esc(entry.label) + '</strong> (<code>' +
        esc(entry.type) + '</code>, ' + esc(entry.protocol) + ', ' +
        esc(entry.spec) + ' — ' + (summary.byType[entry.type] || 0) + ' recorded) ' +
        '— ' + esc(entry.what) +
        (entry.policed
          ? ' <strong>This service decides who may do it.</strong>'
          : ' <strong>Nothing here checks who may do it.</strong>') +
        '</li>';
    }).join('') + '</ul>' +

    '<p class="note"><strong>It is in memory and dies with the process</strong>, ' +
    'like the counters, the audit log, the sessions and the signing key. It also ' +
    'has no clear button and no way to add a row by hand, which is a decision ' +
    'rather than an omission: every row here is something that actually ' +
    'happened, and a table mixing those with typed-in ones would be worth much ' +
    'less than either. Restarting the service is how you get an empty one.</p>' +

    '<p class="note"><strong>A delegation that SUCCEEDED also appears on ' +
    '<a href="/admin/audit">the audit log</a></strong> as an ordinary ' +
    '<code>authentication</code> row, and on <a href="/admin/users">the users ' +
    'page</a> as a credential accepted for the initial identity — which is right: ' +
    'this service did accept one. A delegation that was REFUSED appears in ' +
    'NEITHER, because nothing was accepted, and that gap is the reason this page ' +
    'keeps its own list rather than a filter over one of theirs.</p>' +

    '<p class="note">Paging is <code>?page=</code> and <code>?per=</code> (at ' +
    'most ' + MAX_ROWS + ' rows a page) and both work with ' +
    '<code>?format=json</code>, whose reply carries <code>page</code>, ' +
    '<code>pages</code> and <code>matched</code> so a test can walk the whole ' +
    'list without guessing where it ends — along with <code>chains</code> and ' +
    'the configured <code>policy</code>, which have no paging because neither ' +
    'can be longer than the list they are derived from. The same data is at ' +
    '<code>GET /admin-api/delegation</code> with the same parameters.</p>';

  respond(req, res, view.json, 'Delegation', '/admin/delegation', inner);
  log.debug("Leaving the admin delegation page.");
});

// ---------------------------------------------------------------------------
// GET /admin/delegation/map — THE SAME ACTS, AS A PICTURE.
//
// A DRILL-DOWN OF /admin/delegation AND NOT A SECTION OF ITS OWN. It has no NAV
// row, it passes `up`, and its active tab is the delegation page's — which is
// what makes the trail read `Admin console › Delegation › The picture` and what
// makes the way back carry the filter the reader came in with. The test rule 7a
// states is the one that decided it: a parameter that merely FILTERS a list is
// not a drill-down, and this is not a filter — it is a second VIEW of the list,
// which is exactly what a drill-down is. Putting it in the sidebar was considered
// and would have been a nineteenth tab that shows nothing the tab above it does
// not already hold.
//
// **IT IS THE SAME VIEW FUNCTION.** `delegationView(req.query)` builds it, so
// every filter on the table filters the picture, and the two can never come to
// disagree about which acts they are describing. There is one deliberate
// difference and it is the whole reason to state it: **the picture is drawn from
// `view.filtered` and the table is drawn from `view.shown`** — paging a picture
// would draw the boxes that happen to be on page 2 and the lines that happen to
// join them, which is a diagram of the pagination rather than of the service.
// The page says so where the count is printed.
//
// **THERE IS NO FORM AND THEREFORE NO NEW OPERATION ON /admin-api** — rule 7,
// satisfied the same way `/admin/delegation` itself satisfies it. What this page
// shows is reachable without a browser at `?format=json`, and the same graph is
// on `GET /admin-api/delegation` in the `graph` member, because a picture a test
// cannot assert against is a picture that can go wrong quietly.
//
// **AND `?format=svg` ANSWERS THE DOCUMENT ALONE.** It is the one shape this
// console has that is worth saving — a diagram is a thing people put in a
// ticket — and it is not a fourth response format bolted on: `respond()` still
// answers HTML and JSON, and this route answers SVG before calling it. The
// standalone document carries NO LINKS, deliberately: `app.js` rewrites
// root-relative hrefs into the current realm on the way out of a `text/html`
// response only, so a link inside an `image/svg+xml` body would be a link that
// silently leaves the realm — and in a saved file it would be a link to
// somebody's own machine.
//
// **`?format=svg` GETS THE 302 AND NOT THE 401, and that is the gate's rule
// rather than an oversight here.** The guard answers a program with a status and
// a body and a BROWSER with the sign-in screen, and it decides which by looking
// for JSON — `?format=json`, a JSON content-type, a JSON-only `Accept`. Nothing
// else is a program as far as it is concerned, and this format in particular is
// reached by clicking a link on this page, so a browser that has been signed out
// should meet the screen and come back to the document. A caller that wants the
// picture without a session wants `?format=json` and the graph, which is the
// shape a test can assert against anyway.
// ---------------------------------------------------------------------------

// WHAT A BOX IS, WHICH IS THE ONE QUESTION `delegation_map.js` DELIBERATELY
// CANNOT ANSWER. It is handed this function and asks it once per node.
//
// The three states are `delegationPartyCell()`'s three states, and they are the
// same three on purpose: a name this console can resolve, a name it could file
// somebody under and never has, and a name for something the registry has never
// seen. What the picture does with them is what a picture can do and a table
// cannot — the first two get a SHAPE and the third gets a DASHED one — and the
// row under the diagram still draws the cell, so nothing that was linkable in
// the table stops being linkable here.
//
// **THE LABEL IS THE CN WHERE THERE IS ONE.** A directory entry's `cn` and an
// application entry's `appName` are what somebody CALLED this thing, and the
// identifier is what a protocol spelled it as; on a diagram the first is worth
// more than the second, and the second is one line below it and in the tooltip.
// Where there is no entry there is no cn, and the identifier is all there is.
function delegationNodeLook(node, known) {
  if (node.kind === 'sts') {
    // The one box that is not a party. It carries the REALM because a realm is a
    // whole logical copy of this service — two realms' pictures are two
    // different services' pictures — and it says `default` rather than nothing
    // in the realm that has no prefix, since a hexagon labelled only `mock STS`
    // would be silent about the one thing this box is here to say.
    return {
      shape: 'sts',
      label: 'mock STS',
      sublabel: 'realm: ' + (node.realm ? node.realm.name : 'Default') +
                (node.realm && !node.realm.isDefault ? ' (' + node.realm.id + ')' : ''),
      title: 'THIS SERVICE, in the trust realm ' +
        (node.realm ? node.realm.name + ' (' + node.realm.id + ')' : 'default') +
        '.\nIssuer: ' + (node.issuer || '(unset)') +
        '\nEvery line in this picture exists because this service issued or ' +
        'refused a credential: ' + node.issued + ' issued, ' + node.refused +
        ' refused.\nThe dashed lines leaving it go to whoever ASKED — the ' +
        'intermediary where a chain has one, the initial identity where it ' +
        'does not.',
      href: '/admin/realms',
      dashed: false
    };
  }

  // The directory's own answer about a PERSON. `directoryReader` is a slot and
  // is empty in a build with no `ldap_server.js`, which is a state this console
  // reports everywhere else rather than guessing through — so with no directory
  // every party falls back to the role's shape, dashed, and the page says why.
  let entry = null;
  if (directoryReader && node.key) {
    const info = directoryReader(node.key);
    entry = info && info.found ? info.entry : null;
  }
  // The registry's answer about an APPLICATION. Looked up by the identifier the
  // ACT carried rather than by the node's id: the id is normalised (see
  // `nodeIdOf()` in delegation.js) and `ou=applications` is keyed by what a
  // caller actually presented.
  const application = node.application ? applications.get(node.application) : null;

  const isPerson = !!entry;
  const isApplication = !!application;
  const shape = isPerson && isApplication ? 'both'
              : isApplication ? 'application'
              : isPerson ? 'person'
              // Nothing is known. The ROLE decides, which is the ROLES table
              // read as a drawing: an initial identity is a person, a target is
              // an application, and an intermediary is drawn as an application
              // because that is what a front-end service is.
              : node.chiefRole === 'initial' ? 'person' : 'application';

  const cn = entry ? firstAttributeValue(entry, 'cn') : '';
  const appName = application ? (application.name || application.dnLabel) : '';
  const label = cn || appName || node.id;

  const parts = [];
  if (isPerson) parts.push('person');
  if (isApplication) parts.push('application');
  // WHICH STORE HAS NOT HEARD OF IT, and the two are different sentences. A
  // target drawn as a rectangle is missing from `ou=applications` — the REGISTRY
  // — and an initial identity drawn as a figure is missing from `ou=users` — the
  // DIRECTORY. One word for both would send half the readers to the wrong page
  // to look for it, which is the mistake `delegationPartyCell()` avoids by
  // drawing up to two links rather than one.
  const missing = shape === 'person' ? 'not in the directory' : 'not in the registry';
  const sublabel = parts.length ? parts.join(' + ')
                 : (node.chiefRole ? node.chiefRole + ', ' + missing : missing);

  // Where the box goes when it is clicked. ONE link, where the table draws up to
  // two — an SVG shape can be inside one anchor and the party table under the
  // picture carries both, which is where a reader who wants the other one looks.
  // The person's page wins when this console has SEEN them authenticate, because
  // that page answers the question a delegation raises (what else was issued in
  // their name); the application page otherwise.
  let href = '';
  if (node.key && known[node.key]) {
    href = '/admin/users' + queryWith({ user: node.key }, {});
  } else if (isApplication) {
    href = '/admin/applications' + queryWith({ application: node.application }, {});
  }

  const title = [
    label === node.id ? node.id : label + ' — ' + node.id,
    node.presented && node.presented !== node.id
      ? 'presented as ' + node.presented : '',
    node.application && node.application !== node.id
      ? 'named as an application: ' + node.application : '',
    entry ? 'In the directory at ' + entry.dn + '.'
          : (node.key ? 'No entry under ou=users names this.' : ''),
    application ? 'In the applications registry' +
      (application.dn ? ' at ' + application.dn : '') + '.'
      : (node.application ? 'NOT in the applications registry — the registry ' +
         'holds what this service has been ASKED ABOUT, and a delegation naming ' +
         'something nobody has otherwise mentioned is ordinary for an RFC 8693 ' +
         'audience.' : ''),
    'Roles: initial ' + node.roles.initial + ', intermediary ' +
      node.roles.intermediary + ', target ' + node.roles.target + '.',
    node.selfTarget
      ? 'Some act named this party as BOTH the intermediary and the target — a ' +
        'ticket to ITSELF, which is what S4U2Self is. There is no line for it ' +
        'because an arrow leaving a box and coming back is a drawing of nothing.'
      : '',
    node.protocols.length ? 'Seen over: ' + node.protocols.join(', ') + '.' : '',
    node.what || ''
  ].filter(Boolean).join('\n');

  return { shape: shape, label: label, sublabel: sublabel, title: title,
           href: href, dashed: !isPerson && !isApplication };
}

// One attribute off an entry the directory reader handed back, canonically
// spelled or not. `objectFor()` returns them canonically spelled and a caller
// asking for `cn` should not have to know that.
function firstAttributeValue(entry, name) {
  if (!entry || !entry.attributes) {
    return '';
  }
  const wanted = String(name).toLowerCase();
  const key = Object.keys(entry.attributes).filter(function (one) {
    return String(one).toLowerCase() === wanted;
  })[0];
  const values = key ? entry.attributes[key] : null;
  return (values && values.length) ? String(values[0]) : '';
}

// THE KEY. Drawn out of `delegation_map.js`'s own glyph functions and its own
// palette rather than out of a second set of shapes written for the legend,
// because a legend that is drawn separately is a legend that will eventually
// describe a picture this service no longer draws.
function delegationMapKey() {
  const swatch = function (inner, width) {
    return '<svg width="' + width + '" height="40" viewBox="0 0 ' + width +
      ' 40" aria-hidden="true">' + inner + '</svg>';
  };
  const C = delegationMap.COLOURS;
  const line = function (colour, dash) {
    return '<path d="M4 20H50" stroke="' + colour + '" stroke-width="1.8" fill="none"' +
      (dash ? ' stroke-dasharray="' + dash + '"' : '') + '/>' +
      '<path d="M50 15L58 20L50 25z" fill="' + colour + '"/>';
  };
  const items = [
    { art: swatch(delegationMap.personGlyph(9, 3, C.indigo, false, 1), 44),
      what: '<strong>A person.</strong> Something with an entry under ' +
            '<code>ou=users</code> — anybody this service has authenticated, in ' +
            'any of the sixteen families.' },
    { art: swatch('<rect x="3" y="9" width="56" height="22" rx="5" fill="' + C.panel +
                  '" stroke="' + C.indigo + '" stroke-width="1.5"/>', 64),
      what: '<strong>An application.</strong> Something with an entry under ' +
            '<code>ou=applications</code> — an OAuth client, a service provider, ' +
            'a Kerberos service, a WS-Trust relying party.' },
    { art: swatch('<rect x="3" y="4" width="56" height="32" rx="5" fill="' + C.panel +
                  '" stroke="' + C.indigo + '" stroke-width="1.5"/>' +
                  delegationMap.personGlyph(7, 3, C.indigo, false, 0.85), 64),
      what: '<strong>Both, which the middle tier usually is.</strong> ' +
            '<code>HTTP/frontend.example.com</code> authenticates (so the funnel ' +
            'files it with the people) AND has tickets issued FOR it (so the ' +
            'registry has it). Two entries, one party.' },
    { art: swatch('<path d="' + delegationMap.hexPath(3, 6, 58, 28) + '" fill="' +
                  C.wash + '" stroke="' + C.indigo + '" stroke-width="1.8"/>', 64),
      what: '<strong>This service, in one trust realm.</strong> Every line here ' +
            'exists because it issued or refused a credential. The realm is on ' +
            'the box because a realm is a whole logical copy of this service.' },
    { art: swatch(delegationMap.personGlyph(9, 3, C.grey, true, 1), 44),
      what: '<strong>A dashed outline is something neither store knows.</strong> ' +
            'It is drawn in the shape its ROLE implies and is not an error: an ' +
            'RFC 8693 <code>audience</code> nobody has otherwise mentioned is ' +
            'exactly this.' },
    { art: swatch(line(C.amber, ''), 64),
      what: '<strong>acts for &mdash; an IMPERSONATION.</strong> What came out ' +
            'names the initial identity and nothing else, so nothing at the far ' +
            'end can tell an intermediary was involved. Amber because this ' +
            'picture is the only place that fact will ever exist.' },
    { art: swatch(line(C.green, ''), 64),
      what: '<strong>acts for &mdash; a DELEGATION.</strong> What came out ' +
            'CARRIES the chain: an <code>act</code> claim, a composite ' +
            '<code>ActAs</code>, <code>S4U_DELEGATION_INFO</code> in the PAC.' },
    { art: swatch(line(C.indigo, ''), 64),
      what: '<strong>reaches &mdash; the TRUST relationship.</strong> What the ' +
            'credential is FOR: the back-end service, the <code>AppliesTo</code>, ' +
            'the audience or resource. The label says whose name it carries.' },
    { art: swatch(line(C.indigo, '7 4'), 64),
      what: '<strong>A broken line jumps a party nobody named.</strong> A ' +
            'forwarded ticket-granting ticket has no intermediary and cannot ' +
            'have one — the client gives it to whichever service it chooses and ' +
            'this KDC is never told which.' },
    { art: swatch(line(C.red, '5 3'), 64),
      what: '<strong>Red is a chain nothing was ever issued on.</strong> The ' +
            'tooltip carries the KDC\'s own words for why, which is the same ' +
            'sentence the client was sent.' },
    { art: swatch(line(C.grey, '4 3'), 64),
      what: '<strong>Grey and dashed, from the hexagon: this service ISSUED to ' +
            'that party.</strong> It goes to whoever ASKED — the intermediary ' +
            'where a chain has one, the initial identity where it does not.' }
  ];
  return '<table class="key"><tr><th>Shape</th><th>What it means</th></tr>' +
    items.map(function (one) {
      return '<tr><td class="art">' + one.art + '</td><td>' + one.what + '</td></tr>';
    }).join('') + '</table>';
}

// One node, as a row of the party index under the picture. The party cell is
// `delegationPartyCell()`'s, so a box that links to one page in the diagram
// still offers BOTH links here — see the note in delegationNodeLook().
function delegationNodeRow(node, known, look) {
  if (node.kind === 'sts') {
    return '';
  }
  const party = { key: node.key, presented: node.presented,
                  application: node.application, what: node.what };
  const roles = [];
  if (node.roles.initial) roles.push(node.roles.initial + ' × initial identity');
  if (node.roles.intermediary) roles.push(node.roles.intermediary + ' × intermediary');
  if (node.roles.target) roles.push(node.roles.target + ' × target');
  return '<tr>' +
    '<td>' + esc(look.label) + '</td>' +
    '<td>' + (look.shape === 'both'
                ? 'person <strong>and</strong> application'
                : look.shape === 'person' ? 'person'
                : look.shape === 'application' ? 'application' : look.shape) +
      (look.dashed
        ? '<br><span class="state-none" title="Neither ou=users nor ' +
          'ou=applications holds an entry for this. The shape is the one its ' +
          'role implies.">drawn from its role &mdash; neither store knows it</span>'
        : '') + '</td>' +
    '<td class="who">' + delegationPartyCell(party, known) + '</td>' +
    '<td>' + (roles.join('<br>') || '<span class="state-none">&mdash;</span>') +
      (node.selfTarget
        ? '<br><span class="state-expired" title="S4U2Self is a request for a ' +
          'ticket to yourself, so the intermediary and the target are one party. ' +
          'There is no line for it in the picture because an arrow leaving a box ' +
          'and coming back is a drawing of nothing.">also its own target</span>'
        : '') + '</td>' +
    '<td class="num">' + esc(node.acts) + ' — ' +
      '<span class="state-valid">' + esc(node.issued) + ' issued</span>, ' +
      (node.refused
        ? '<span class="state-revoked">' + esc(node.refused) + ' refused</span>'
        : '<span class="state-none">0 refused</span>') + '</td>' +
    '<td>' + (node.protocols.map(esc).join('<br>') ||
              '<span class="state-none">&mdash;</span>') + '</td>' +
    '</tr>';
}

// One edge, as a row of the relationship index. The columns are the picture read
// as a sentence — who, to whom, meaning what, over what, how it came out — so
// that everything the diagram says in colour is also said in words. A picture
// nobody can read as text is one nobody can quote in a bug report.
function delegationEdgeRow(edge, lookOf) {
  const relation = edge.relation === 'issued'
    ? '<span class="state-none" title="This service handed that party a ' +
      'credential. It goes to whoever ASKED.">issued to</span>'
    : edge.relation === 'acts-for'
      ? '<strong>acts for</strong>'
      : '<strong>reaches</strong>' +
        (edge.subject ? '<br><span class="state-none">as ' + esc(edge.subject) +
                        '</span>' : '');
  return '<tr>' +
    '<td class="who">' + esc(lookOf(edge.from)) + '</td>' +
    '<td class="who">' + esc(lookOf(edge.to)) + '</td>' +
    '<td>' + relation +
      ((edge.skipped || []).length
        ? '<br><span class="state-expired" title="Nobody named this party on ' +
          'these acts, so the line jumps it. A forwarded ticket-granting ticket ' +
          'has no intermediary and cannot have one.">jumps the ' +
          esc(edge.skipped.join(' and ')) + '</span>'
        : '') + '</td>' +
    '<td>' + (edge.typeLabel
                ? '<code>' + esc(edge.type) + '</code><br>' +
                  '<span class="state-none">' + esc(edge.typeLabel) + '</span><br>' +
                  '<span class="state-none">' + esc(edge.protocol) +
                  (edge.spec ? ' &middot; ' + esc(edge.spec) : '') + '</span>'
                : '<span class="state-none">' +
                  esc((edge.protocols || []).join(', ') || '&mdash;') + '</span>') +
    '</td>' +
    '<td>' + modeCell(edge.mode) + '</td>' +
    '<td class="num">' + esc(edge.acts) + ' — ' +
      '<span class="state-valid">' + esc(edge.issued) + ' issued</span>, ' +
      (edge.refused
        ? '<span class="state-revoked">' + esc(edge.refused) + ' refused</span>'
        : '<span class="state-none">0 refused</span>') + '</td>' +
    '<td class="who">' + (edge.produced.length
      ? edge.produced.map(function (one) {
          return '<code>' + esc(one.kind) + '</code> × ' + esc(one.count) +
            (one.identifiers.length
              ? '<br>' + one.identifiers.map(function (id) {
                  // shortened() brings its own <code title=…> — see the note
                  // in credentialCell().
                  return shortened(id, 10);
                }).join(' ') +
                (one.moreIdentifiers ? ' <span class="state-none">+' +
                  esc(one.moreIdentifiers) + ' more</span>' : '')
              : '');
        }).join('<br>')
      : '<span class="state-none">&mdash;</span>') + '</td>' +
    // WHY, AND THE UNPOLICED FAMILIES ARE COLLAPSED. This is the delegation
    // page's own rule about its *Also requires* column read again: a sentence
    // that is a property of the MECHANISM and identical on every row of its kind
    // is not a column, it is a paragraph. `authorizedBy` on a WS-Trust or an RFC
    // 8693 row is exactly that — *nothing checks this, and here is the
    // paragraph* — repeated down the table it squeezed the four columns that DO
    // differ per row into shreds, which is the failure that took that page from
    // twelve columns to ten.
    //
    // So a REFUSAL prints in full, because it is specific to the act and is most
    // of what this page is for; a POLICED grant prints its attribute, because
    // that is short and names an account; and an unpoliced grant becomes three
    // words with the paragraph in the tooltip. Nothing is lost — the line's own
    // tooltip in the picture carries the same text.
    '<td>' + (edge.reason
              ? esc(edge.reason)
              : edge.relation === 'issued'
                ? '<span class="state-none">&mdash;</span>'
                : edge.policed
                  ? (edge.authorizedBy ? esc(edge.authorizedBy)
                                       : '<span class="state-none">&mdash;</span>')
                  : '<span class="state-expired" title="' +
                    esc(edge.authorizedBy || 'Nothing in this service decides ' +
                        'who may perform this act.') +
                    '">nothing checks this</span>') +
    '</td>' +
    '</tr>';
}

// ---------------------------------------------------------------------------
// THE APPLICATION CHOOSER, DRAWN IN THREE PLACES AND THEREFORE A FUNCTION.
//
// It is on /admin/delegation (where somebody looking at the table wants to
// pivot), on /admin/delegation/application with nothing selected (where it IS
// the page), and again under a selected application (so that comparing two is
// one click rather than two). Three copies of a `<select>` built from the same
// list would be three chances for one of them to offer an option the route
// cannot resolve.
//
// **THE OPTION'S VALUE IS A SPELLING AND NOT THE NORMALISED KEY**, deliberately.
// The route normalises whatever it is given (see its header), so both work — and
// the identifier is what a reader recognises in the address bar and in a link
// they paste into a ticket. A URL carrying `HTTP%2Fbackend%40EXAMPLE.COM` is one
// somebody can check; one carrying a key they have never seen is not.
//
// A SELECT rather than a list of links because there can be thirty of these and
// a wall of thirty links above the table would push the table itself off the
// screen. The full list IS drawn as links, below, where it is the content rather
// than a control.
// ---------------------------------------------------------------------------
// `carry` is the delegation table's own filter, spelt out as hidden inputs for
// the reason perPageForm() gives: a GET form posts its own fields and NOTHING
// else, so without them this control quietly empties the breadcrumb's way back
// to the list the reader came from.
function delegationApplicationChooser(catalogue, selectedKey, carry) {
  log.debug("Entering delegationApplicationChooser().");
  if (!catalogue.length) {
    log.debug("Leaving delegationApplicationChooser(). Nothing to choose from.");
    return '<p class="note"><strong>No delegation held here names an ' +
      'application yet</strong>, so there is nothing to choose between. An ' +
      'application arrives in this list the moment something delegates through ' +
      'it or to it: an RFC 8693 <code>audience</code> or the <code>client_id</code> ' +
      'that performed the exchange, a WS-Trust <code>AppliesTo</code>, or the ' +
      'service principal a Kerberos S4U request asked for a ticket to.</p>';
  }
  const options = catalogue.map(function (entry) {
    const roles = [];
    if (entry.roles.intermediary) roles.push(entry.roles.intermediary + ' as the intermediary');
    if (entry.roles.target) roles.push(entry.roles.target + ' as the target');
    if (entry.roles.initial) roles.push(entry.roles.initial + ' as the initial identity');
    return '<option value="' + esc(entry.identifier) + '"' +
      (entry.key === selectedKey ? ' selected' : '') + '>' +
      esc(entry.identifier) + ' — ' + esc(entry.acts) + ' act(s): ' +
      esc(roles.join(', ')) + '</option>';
  }).join('');
  log.debug("Leaving delegationApplicationChooser(). " + catalogue.length + " option(s).");
  const carried = Object.keys(carry || {}).map(function (name) {
    return '<input type="hidden" name="' + esc(name) + '" value="' +
           esc((carry || {})[name]) + '">';
  }).join('');
  return '<form method="get" action="/admin/delegation/application">' +
    '<div class="formrow">' + carried +
      '<label for="application">Application</label>' +
      '<select id="application" name="application">' +
        (selectedKey ? '' : '<option value="">choose one&hellip;</option>') +
        options +
      '</select>' +
      '<button class="secondary">Everything delegated through or to it</button>' +
    '</div></form>';
}

// The same list as CONTENT: every application some act named, with what it did
// and the way in. It is not the same as `/admin/applications` and the page says
// so — that page is the REGISTRY, which holds what this service has been asked
// about; this is what has actually delegated, which can name something the
// registry has never seen.
function delegationApplicationTable(catalogue, known, carry) {
  log.debug("Entering delegationApplicationTable().");
  const rows = catalogue.map(function (entry) {
    const roles = [];
    if (entry.roles.intermediary) {
      roles.push(esc(entry.roles.intermediary) + ' × intermediary');
    }
    if (entry.roles.target) {
      roles.push(esc(entry.roles.target) + ' × target');
    }
    if (entry.roles.initial) {
      roles.push(esc(entry.roles.initial) + ' × initial identity');
    }
    const registered = entry.spellings.filter(function (spelling) {
      return !!applications.get(spelling);
    }).length > 0;
    return '<tr>' +
      '<td class="who"><a href="' + esc('/admin/delegation/application' +
        queryWith(carry || {}, { application: entry.identifier })) + '"><code>' +
        esc(entry.identifier) + '</code></a>' +
        (entry.spellings.length > 1
          ? '<br><span class="state-none" title="' +
            esc(entry.spellings.join(', ')) + '">' + esc(entry.spellings.length) +
            ' spellings, collapsed</span>'
          : '') +
        (registered ? ''
          : '<br><span class="state-none" title="No entry under ' +
            'ou=applications names this. The registry holds what this service ' +
            'has been ASKED ABOUT; a delegation can name something nobody has ' +
            'otherwise mentioned.">not in the registry</span>') +
        (entry.identityKey
          ? '<br>' + usersPageCell(entry.identityKey, known)
          : '') + '</td>' +
      '<td>' + (roles.join('<br>') || '<span class="state-none">&mdash;</span>') +
        '</td>' +
      '<td class="num">' + esc(entry.acts) + ' — ' +
        '<span class="state-valid">' + esc(entry.issued) + ' issued</span>, ' +
        (entry.refused
          ? '<span class="state-revoked">' + esc(entry.refused) + ' refused</span>'
          : '<span class="state-none">0 refused</span>') + '</td>' +
      '<td class="num">' + esc(entry.credentials) + '</td>' +
      '<td class="num">' + esc(entry.chains) + '</td>' +
      '<td>' + esc(whenText(entry.lastAt)) + '</td>' +
      '</tr>';
  }).join('');
  log.debug("Leaving delegationApplicationTable(). " + catalogue.length + " row(s).");
  return '<table><tr><th>Application</th><th>Roles it has played</th>' +
    '<th>Acts</th><th>Credentials</th><th>Relationships</th><th>Last seen</th></tr>' +
    (rows || '<tr><td colspan="6">No delegation held here names an ' +
     'application.</td></tr>') + '</table>';
}

// ---------------------------------------------------------------------------
// THE THREE THINGS EVERY PICTURE PAGE NEEDS, EXTRACTED BECAUSE THERE ARE NOW
// THREE OF THEM.
//
// `/admin/delegation/map` drew the whole graph; `/admin/delegation/chain` draws
// ONE relationship and `/admin/delegation/application` draws one application's.
// They differ in which acts they pass to `delegation.graph()` and in nothing
// else, so the three functions below are shared rather than copied.
//
// That is the same argument `delegationView()` makes one layer up and it is
// worth restating here because the failure it prevents is quiet: three copies of
// the label rule would be three pages that disagree about what a box is CALLED,
// and a reader comparing the whole picture with one chain's would have no way to
// tell that from two boxes that really are different parties.
// ---------------------------------------------------------------------------

// What every box is called and how it is drawn, worked out once per page.
// `labelOf` is separate because a `reaches` line names a party that is NEITHER
// of its ends — see the map route's call — and the renderer has no `resolve()`
// answer for it.
function delegationLooks(graph, known) {
  log.debug("Entering delegationLooks().");
  const looks = {};
  graph.nodes.forEach(function (node) {
    looks[node.id] = delegationNodeLook(node, known);
  });
  log.debug("Leaving delegationLooks(). " + graph.nodes.length + " box(es).");
  return {
    looks: looks,
    resolve: function (node) { return looks[node.id]; },
    labelOf: function (id) { return looks[id] ? looks[id].label : id; }
  };
}

// One credential that came out of an act in the picture. `extra` is an optional
// leading cell — the application page uses it for the ROLE that application
// played in the act that produced this, which is the whole question that page
// answers and is a fact about the act rather than about the credential.
function delegationTokenRow(token, labelOf, extra) {
  return '<tr>' +
    '<td class="num">' + esc(token.seq) + '</td>' +
    '<td>' + esc(whenText(token.at)) + '</td>' +
    (extra === undefined ? '' : '<td>' + extra + '</td>') +
    '<td class="who"><code>' + esc(token.kind) + '</code>' +
      (token.identifier
        ? '<br>' + shortened(token.identifier, 14)
        : '<br><span class="state-none" title="A Kerberos ticket has no ' +
          'identifier this service could quote — there is no jti and no ' +
          'AssertionID in one.">no identifier</span>') +
      (token.note ? '<br><span class="state-none">' + esc(token.note) +
                    '</span>' : '') + '</td>' +
    '<td class="who">' + esc(labelOf(token.subject) ||
      '<span class="state-none">&mdash;</span>') + '</td>' +
    '<td class="who">' + (token.actor ? esc(labelOf(token.actor))
      : '<span class="state-none" title="A forwarded ticket-granting ticket ' +
        'has no intermediary this KDC was told about.">&mdash;</span>') + '</td>' +
    '<td class="who">' + (token.target ? esc(labelOf(token.target))
      : '<span class="state-none">&mdash;</span>') + '</td>' +
    '<td><code>' + esc(token.type) + '</code><br>' +
      '<span class="state-none">' + esc(token.protocol) + '</span></td>' +
    '</tr>';
}

// The drawing itself, and the two links under it. `path` and `params` are the
// route's own, because the document-on-its-own link has to come back to the
// page it was offered on carrying whatever selected these acts — a `chain=` or
// an `application=`, not the map's filters.
//
// The SVG document is rendered a SECOND time with `links: false` rather than the
// page's markup being reused, and that is not waste: the standalone document
// carries no links deliberately (see the map route's header — `app.js` rewrites
// root-relative hrefs into the current realm on the way out of a `text/html`
// response only, so a link inside an `image/svg+xml` body would silently leave
// the realm, and in a saved file it would point at somebody's own machine).
function delegationDrawing(graph, look, path, params, label) {
  log.debug("Entering delegationDrawing().");
  const drawn = delegationMap.render(graph, {
    resolve: look.resolve, labelOf: look.labelOf,
    links: true, id: 'delmap', label: label
  });
  const html = '<div class="diagram">' + drawn.svg + '</div>' +
    '<p class="note">' + drawn.width + '&times;' + drawn.height + ' — ' +
    '<a href="' + esc(path + queryWith(params, { format: 'svg' })) +
    '">the document on its own</a> (SVG, no links in it), or ' +
    '<a href="' + esc(path + queryWith(params, { format: 'json' })) +
    '">the graph as JSON</a>.' +
    (drawn.failed ? ' <span class="state-revoked">The layout failed: ' +
      esc(drawn.failed) + '</span>' : '') + '</p>';
  log.debug("Leaving delegationDrawing(). " + drawn.width + "x" + drawn.height + ".");
  return { drawn: drawn, html: html };
}

// `?format=svg` — the document alone. Every picture page answers it the same
// way, so the answer is one function: a fourth copy of "render it again without
// links, set no-store, send it as image/svg+xml" is a fourth chance for one of
// them to keep the links.
function sendDelegationSvg(res, graph, look, label) {
  log.debug("Entering sendDelegationSvg().");
  const bare = delegationMap.render(graph, {
    resolve: look.resolve, labelOf: look.labelOf,
    links: false, id: 'delmap', label: label
  });
  res.set('Cache-Control', 'no-store').type('image/svg+xml').send(bare.svg);
  log.debug("Leaving sendDelegationSvg(). " + bare.svg.length + " bytes.");
}

app.get('/admin/delegation/map', function (req, res) {
  log.debug("Entering the admin delegation map page.");
  const view = delegationView(req.query);
  const known = knownUserKeys();
  // THE PICTURE IS OF EVERYTHING THAT MATCHED, not of the page that is showing —
  // see the header. It is `delegationView()`'s graph rather than a second call
  // to `delegation.graph()`, so this page and `GET /admin-api/delegation` cannot
  // come to disagree about what is in it.
  const graph = view.graph;

  // The labels and the shapes, worked out once. `labelOf` is handed to the
  // renderer separately because a `reaches` line says WHOSE name the credential
  // carries, and that party is neither end of it — so the renderer has no
  // `resolve()` answer for it and would otherwise print the raw identity beside
  // two boxes labelled with their cn. One name per party, wherever it appears.
  const look = delegationLooks(graph, known);
  const looks = look.looks;
  const labelOf = look.labelOf;
  const drawingLabel = 'Delegation relationships in this service, as a diagram';

  if (String(req.query.format || '') === 'svg') {
    // The document alone, for saving or embedding. No links (see the header) and
    // `no-store` like every other page here, because it describes live state.
    sendDelegationSvg(res, graph, look, drawingLabel);
    log.debug("Leaving the admin delegation map page. Answered SVG.");
    return;
  }

  const filterParams = { type: view.wantedType, mode: view.wantedMode,
                         outcome: view.wantedOutcome,
                         protocol: view.wantedProtocol, q: view.wantedText,
                         per: req.query.per ? view.paging.perPage : '' };
  // The drawing and the two links under it. The `per` is dropped from the links
  // deliberately — this page has no paging, so carrying a page size into the
  // document link would be a parameter that does nothing.
  const picture = delegationDrawing(graph, look, '/admin/delegation/map',
    { type: view.wantedType, mode: view.wantedMode, outcome: view.wantedOutcome,
      protocol: view.wantedProtocol, q: view.wantedText }, drawingLabel);
  const drawn = picture.drawn;
  const up = upTo('/admin/delegation', 'The picture',
                  listViewOf('/admin/delegation', req.query));

  const filtering = view.wantedType || view.wantedMode || view.wantedOutcome ||
                    view.wantedProtocol || view.wantedText;

  // The filter, exactly the table's, so that narrowing the picture and narrowing
  // the table are one control rather than two that could take different values.
  // It is a GET form and carries no `page`: this page has none, and a page
  // number carried into a view with no paging is a parameter that does nothing
  // and comes back with the reader on the next hop.
  const protocolsInOrder = [];
  delegation.TYPES.forEach(function (entry) {
    if (protocolsInOrder.indexOf(entry.protocol) < 0) {
      protocolsInOrder.push(entry.protocol);
    }
  });
  const typeOptions = '<option value=""' + (view.wantedType ? '' : ' selected') +
    '>any mechanism</option>' +
    protocolsInOrder.map(function (protocol) {
      return '<optgroup label="' + esc(protocol) + '">' +
        delegation.TYPES.filter(function (entry) {
          return entry.protocol === protocol;
        }).map(function (entry) {
          return '<option value="' + esc(entry.type) + '"' +
                 (entry.type === view.wantedType ? ' selected' : '') + '>' +
                 esc(entry.label) + ' (' + (view.summary.byType[entry.type] || 0) +
                 ')</option>';
        }).join('') + '</optgroup>';
    }).join('');
  const modeOptions = ['<option value=""' + (view.wantedMode ? '' : ' selected') +
                       '>either kind</option>']
    .concat(delegation.MODES.map(function (entry) {
      return '<option value="' + esc(entry.mode) + '"' +
             (entry.mode === view.wantedMode ? ' selected' : '') + '>' +
             esc(entry.label) + ' (' + (view.summary.byMode[entry.mode] || 0) +
             ')</option>';
    })).join('');
  const outcomeOptions = ['<option value=""' + (view.wantedOutcome ? '' : ' selected') +
                          '>any outcome</option>']
    .concat(delegation.OUTCOMES.map(function (name) {
      return '<option value="' + esc(name) + '"' +
             (name === view.wantedOutcome ? ' selected' : '') + '>' + esc(name) +
             ' (' + (view.summary.byOutcome[name] || 0) + ')</option>';
    })).join('');

  const parties = graph.nodes.filter(function (node) {
    return node.kind !== 'sts';
  });

  const inner = messagesOf(req) +
    // THE WAY BACK, AT THE TOP, ABOVE EVERYTHING. The trail under the nav already
    // offers it and this is deliberately a second one: the trail is a strip of
    // small grey text a reader learns to look at, and somebody who followed a
    // link into a diagram is looking at the diagram. It carries the filter, so
    // "back" means the table they came from and not the top of an unfiltered one.
    '<p class="note"><a class="btn" href="' + esc(up.href) + '">&larr; Back to ' +
    'the delegation table</a></p>' +

    '<div class="tiles">' +
      tile(parties.length, 'parties') +
      tile(graph.edges.filter(function (e) { return e.relation !== 'issued'; }).length,
           'relationships') +
      tile(graph.chains, 'distinct chains') +
      tile(graph.acts, 'acts drawn') +
      tile(view.summary.byMode.impersonation || 0, 'impersonations') +
      tile(graph.tokens.length, 'credentials issued') +
    '</div>' +

    '<p class="note"><strong>The same acts as ' +
    '<a href="' + esc(up.href) + '">the table</a>, with the time taken out and ' +
    'the parties shared.</strong> A party that is the intermediary of six chains ' +
    'is ONE box here with six lines leaving it, which is the thing a table of ' +
    'rows cannot show and the reason to draw this at all. Every box and every ' +
    'line carries the whole story in its tooltip; the two tables under the ' +
    'picture say the same things in words, because a diagram nobody can quote is ' +
    'a diagram nobody can put in a bug report.</p>' +

    '<p class="note"><strong>It is drawn from everything that MATCHED the filter ' +
    'and not from one page of it.</strong> ' + view.filtered.length + ' act(s) ' +
    'match' + (view.all.length !== view.filtered.length
      ? ' of ' + view.all.length + ' held' : '') +
    ', and all of them are in the picture — paging a diagram would draw the boxes ' +
    'that happen to be on page 2 and the lines that happen to join them, which is ' +
    'a picture of the pagination.</p>' +

    '<form method="get" action="/admin/delegation/map"><div class="formrow">' +
      '<label for="type">Mechanism</label><select id="type" name="type">' +
        typeOptions + '</select>' +
      '<label for="mode">Kind</label><select id="mode" name="mode">' +
        modeOptions + '</select>' +
      '<label for="outcome">Outcome</label><select id="outcome" name="outcome">' +
        outcomeOptions + '</select>' +
    '</div><div class="formrow">' +
      '<label for="q">Text</label>' +
      '<input type="text" id="q" name="q" size="40" value="' + esc(view.wantedText) +
        '" placeholder="a person, an SPN, a client_id, an attribute">' +
      '<button class="secondary">Redraw</button>' +
      (filtering ? ' <a href="/admin/delegation/map">clear</a>' : '') +
    '</div></form>' +
    '<p class="note">The same filter the table has, so narrowing one narrows the ' +
    'other. <strong>Filtering to one person is how a busy picture is read</strong> ' +
    '— the text box searches every party of the chain and both explanations at ' +
    'once.</p>' +

    (graph.acts
      ? picture.html
      : '<p class="note"><strong>Nothing has delegated anything yet' +
        (filtering ? ' that matches this filter' : '') + ', so there is nothing ' +
        'to draw.</strong> Three things put a box on this page: a Kerberos ' +
        'S4U2Self, S4U2Proxy or forwarded-TGT request at the KDC; a WS-Trust ' +
        '<code>RequestSecurityToken</code> carrying ' +
        '<code>&lt;wst:OnBehalfOf&gt;</code> or <code>&lt;wst14:ActAs&gt;</code>; ' +
        'and an RFC 8693 token exchange at <code>/oauth2/token</code>. A REFUSED ' +
        'attempt counts and is drawn in red.</p>') +

    '<h2>The key</h2>' +
    '<p class="note">The shapes are drawn by the same functions the picture uses, ' +
    'so a legend cannot come to describe a diagram this service no longer draws.</p>' +
    delegationMapKey() +

    '<h2>The parties</h2>' +
    '<p class="note">Every box, with both of its links where it has two. The ' +
    'picture can only put a shape inside ONE anchor, so a party that is a person ' +
    'AND an application links to the users page there and to both here.' +
    (directoryReader ? '' :
      ' <strong>No LDAP directory is loaded in this process</strong>, so nothing ' +
      'here can be resolved to a person and every box is drawn from its role. ' +
      'That is a build without <code>ldap_server.js</code> and not a failure.') +
    '</p>' +
    '<table><tr><th>Label</th><th>Drawn as</th><th>Identity</th>' +
    '<th>Roles it played</th><th>Acts</th><th>Protocols</th></tr>' +
    (parties.map(function (node) {
      return delegationNodeRow(node, known, looks[node.id]);
    }).join('') || '<tr><td colspan="6">No parties yet.</td></tr>') + '</table>' +

    '<h2>The relationships</h2>' +
    '<p class="note">Every line, as a sentence. <strong>The two kinds are ' +
    'different claims and the picture colours them differently</strong>: ' +
    '<em>acts for</em> is the DELEGATION relationship — who is acting on whose ' +
    'behalf — and <em>reaches</em> is the TRUST relationship, what the credential ' +
    'is FOR, which is the question <em>what is this token\'s audience</em> asked ' +
    'as a picture. The grey lines from the hexagon are neither: they are this ' +
    'service handing a credential to whoever asked for one.</p>' +
    '<p class="note"><strong>The last column collapses one sentence and it is ' +
    'the same collapse the delegation table makes.</strong> Kerberos is the only ' +
    'family here that polices delegation at all, so a Kerberos row names an ' +
    'ATTRIBUTE and an account — short, and different on every row — while every ' +
    'WS-Trust and RFC 8693 row carries the identical paragraph saying that ' +
    'nothing checked it. Repeated down a table that paragraph is the column, so ' +
    'it is <em>nothing checks this</em> with the wording in the tooltip. ' +
    '<strong>A REFUSAL is never collapsed</strong> and prints in full: it is the ' +
    'KDC\'s own words, the same sentence the client was sent, and it is specific ' +
    'to the act rather than to the mechanism.</p>' +
    '<table><tr><th>From</th><th>To</th><th>Relationship</th><th>Mechanism</th>' +
    '<th>Kind</th><th>Acts</th><th>What came out</th>' +
    '<th>Authorized by / why not</th></tr>' +
    (graph.edges.map(function (edge) {
      return delegationEdgeRow(edge, labelOf);
    }).join('') || '<tr><td colspan="8">No relationships yet.</td></tr>') +
    '</table>' +

    '<h2>What was issued</h2>' +
    '<p class="note"><strong>Every credential that came out of an act in this ' +
    'picture</strong>, newest first — a Kerberos service ticket, a SAML ' +
    'assertion, an access token — with the chain it came out of. <strong>NO ' +
    'CREDENTIAL IS EVER HERE, only its kind and its identifier</strong>, which is ' +
    'the rule the audit log follows and which applies here for one more reason: a ' +
    'delegation act is precisely the request that carries two credentials at ' +
    'once. A Kerberos ticket genuinely has no identifier to quote, which this ' +
    'says rather than leaving a blank column to be read as a bug.</p>' +
    '<p class="note">A REFUSED act produced nothing by definition, so it is not ' +
    'in this list — which is why ' + graph.tokens.length + ' credential(s) sit ' +
    'under ' + graph.acts + ' act(s) and the two numbers do not have to agree.</p>' +
    '<table><tr><th class="num">#</th><th>When</th><th>Credential</th>' +
    '<th>Subject</th><th>Actor</th><th>Target</th><th>Mechanism</th></tr>' +
    (graph.tokens.map(function (token) {
      return delegationTokenRow(token, labelOf);
    }).join('') || '<tr><td colspan="7">Nothing has been issued through a ' +
      'delegation yet. A REFUSED act produces nothing, so a page of red lines ' +
      'and an empty table here is a consistent state rather than a broken ' +
      'one.</td></tr>') + '</table>' +
    (graph.tokensLeftOff
      ? '<p class="note"><strong>' + graph.tokensLeftOff + ' more credential(s) ' +
        'are not listed.</strong> This list holds at most ' + graph.maxTokenRows +
        ' and keeps the newest; every one of them is still COUNTED on its line in ' +
        'the picture and in the relationship table, so what is lost is the ' +
        'individual identifiers of the oldest. Filter to narrow it.</p>'
      : '') +

    '<h2>What this picture cannot say</h2>' +
    '<p class="note"><strong>An IMPERSONATION is invisible everywhere else, and ' +
    'that is why the amber lines matter.</strong> Under a delegation the ' +
    'credential carries the chain, so a resource server can read the actor off ' +
    'the token afterwards. Under an impersonation nothing does: no reading of the ' +
    'token, at the far end or in a log, can recover the fact that a middle tier ' +
    'was involved. This diagram and the table behind it are the only places that ' +
    'fact will ever exist.</p>' +
    '<p class="note"><strong>A line is a RELATIONSHIP and not a request.</strong> ' +
    'Four acts a second apart between the same three parties are one line with ' +
    '<em>4 issued</em> on it; the outcome is deliberately not part of a chain\'s ' +
    'identity, so a chain refused nine times and then fixed is one line that ' +
    'changes colour rather than two that never meet. ' +
    '<a href="' + esc(up.href) + '">The table</a> is where the individual acts ' +
    'are, in order, with their times.</p>' +
    '<p class="note"><strong>Who MAY delegate to whom is not on this page</strong>, ' +
    'because it is CONFIGURATION rather than history and it is Kerberos-only — ' +
    'Kerberos is the one family here that polices delegation at all. It is the ' +
    'second half of <a href="' + esc(up.href) + '">the delegation page</a>, and ' +
    'the asymmetry between the two is worth reading there: the same picture, ' +
    'policed at one end and not at the other.</p>' +
    '<p class="note"><strong>This page runs no script and neither does anything ' +
    'else in this console.</strong> The diagram is generated on the server and ' +
    'arrives as markup, which is why it does not pan, zoom or drag — and why ' +
    'nothing here relaxes <code>script-src \'none\'</code>. Use the filter to ' +
    'narrow a busy picture, or take the document and open it in something that ' +
    'does zoom.</p>' +
    '<p class="note"><code>?format=json</code> carries the whole graph — the ' +
    'nodes, the edges, the credentials folded onto each edge, and the token list ' +
    '— and it is also in the <code>graph</code> member of ' +
    '<code>GET /admin-api/delegation</code>, so a test can assert what this page ' +
    'draws without parsing an SVG. <code>?format=svg</code> is the document ' +
    'alone.</p>';

  respond(req, res, Object.assign({}, graph, {
    // The filter that produced it, so a caller polling this endpoint can tell a
    // picture of everything from a picture of one person.
    filter: view.json.filter,
    matched: view.filtered.length,
    held: view.summary.held,
    // The rendered size, which is the one fact about the DRAWING rather than the
    // graph that a caller might reasonably want — an empty picture and a picture
    // that failed to lay out are otherwise indistinguishable in JSON.
    drawing: { width: drawn.width, height: drawn.height,
               failed: drawn.failed || null }
  }), 'Delegation — the picture', '/admin/delegation', inner, up);
  log.debug("Leaving the admin delegation map page.");
});

// ---------------------------------------------------------------------------
// GET /admin/delegation/chain?chain=… — ONE RELATIONSHIP, DRAWN ALONE.
//
// A second drill-down of /admin/delegation, beside /admin/delegation/map, and it
// exists because of what the whole picture cannot do: on a service that has been
// driven for an afternoon the map is forty boxes, and the question somebody
// brings to a ROW of the table — *what is this one, exactly* — is answered by
// deleting everything else. Every row of both tables on that page links here.
//
// **IT IS THE SAME GRAPH FUNCTION OVER A SUBSET, AND THAT IS THE WHOLE
// IMPLEMENTATION.** `delegation.graph()` takes the acts it is to draw (its
// header says so), so this route hands it one chain's and everything below —
// the shapes, the labels, the two tables, the credential list — is the map's
// own, through the three helpers above. A second drawing routine for "one
// chain" would be a second answer to what a box is called, and the reader
// comparing this page with the map would have no way to tell that from two
// boxes that really are different parties.
//
// **THE KEY IN THE URL IS THE `chainKey` AND NOT AN INDEX**, for the reason
// `actsOfChain()`'s header gives: an index into a capped list moves when the cap
// bites, so a link somebody put in a ticket would come back describing a
// DIFFERENT relationship rather than nothing. The key is long and that is the
// price; it is exact, and a link that has gone stale says so.
//
// **A CHAIN THAT IS NOT HELD IS NOT A 404**, which is the rule /admin/logout's
// lookup follows and it matters more here: this store is capped and drops the
// oldest, so "no acts under this key" is the ORDINARY outcome of an old link
// rather than a mistake. The page says which of the two it is — a key nobody
// ever recorded, or one whose acts have been dropped — and offers the way back.
//
// No form, so no operation on /admin-api — rule 7, satisfied exactly as
// /admin/delegation and its map satisfy it. `?format=json` is the graph and the
// acts; `?format=svg` is the document alone.
// ---------------------------------------------------------------------------
app.get('/admin/delegation/chain', function (req, res) {
  log.debug("Entering the admin delegation chain page.");
  const wanted = String(req.query.chain || '');
  const known = knownUserKeys();
  const all = delegation.list();
  const acts = delegation.actsOfChain(all, wanted);
  // chainList() over the acts of ONE chain returns exactly one row, and it is
  // that function's answer rather than a shape built here — the counts, the
  // first and last times and the rule about which explanation wins are all
  // decisions it makes, and a second copy of them would drift.
  const chain = delegation.chainList(acts)[0] || null;
  const graph = delegation.graph(acts);
  const look = delegationLooks(graph, known);
  const labelOf = look.labelOf;
  const drawingLabel = chain
    ? 'One delegation relationship: ' + chain.typeLabel
    : 'A delegation relationship that is no longer held';

  if (String(req.query.format || '') === 'svg') {
    sendDelegationSvg(res, graph, look, drawingLabel);
    log.debug("Leaving the admin delegation chain page. Answered SVG.");
    return;
  }

  const listView = listViewOf('/admin/delegation', req.query);
  const up = upTo('/admin/delegation', 'One relationship', listView);
  const back = '<p class="note"><a class="btn" href="' + esc(up.href) +
    '">&larr; Back to the delegation table</a></p>';

  const json = {
    chain: chain, chainKey: wanted, found: !!chain,
    acts: acts, graph: graph,
    held: delegation.summary().held
  };

  if (!chain) {
    const inner = messagesOf(req) + back +
      (wanted
        ? '<p class="note"><strong>No act held here belongs to that ' +
          'relationship.</strong> <code>' + esc(wanted) + '</code> names a ' +
          'chain this page can describe only while at least one of its acts is ' +
          'still held, and this store is CAPPED — it keeps at most ' +
          esc(delegation.summary().maxRecords) + ' acts and drops the oldest ' +
          'first. So an old link coming back empty is the ordinary outcome ' +
          'rather than a mistake, and so is a link from a service that has ' +
          'restarted since: nothing here is persisted. Raise ' +
          '<code>delegation.maxRecords</code> on <a href="/admin/config">the ' +
          'configuration page</a> if this keeps happening to something you ' +
          'need.</p>'
        : '<p class="note"><strong>Name a relationship.</strong> This page draws ' +
          'ONE of them, and the way to it is a link on ' +
          '<a href="' + esc(up.href) + '">the delegation table</a> — every row ' +
          'of both tables there has one, because the key that identifies a chain ' +
          'is <em>(mechanism, initial identity, intermediary, target)</em> and ' +
          'is not something worth typing.</p>') +
      '<p class="note"><a href="/admin/delegation/map">The whole picture</a> is ' +
      'everything that is still held, drawn together.</p>';
    respond(req, res, json, 'Delegation — one relationship', '/admin/delegation',
            inner, up);
    log.debug("Leaving the admin delegation chain page. Nothing under that key.");
    return;
  }

  const parties = graph.nodes.filter(function (node) {
    return node.kind !== 'sts';
  });
  const picture = delegationDrawing(graph, look, '/admin/delegation/chain',
                                    Object.assign({}, listView, { chain: wanted }),
                                    drawingLabel);
  json.drawing = { width: picture.drawn.width, height: picture.drawn.height,
                   failed: picture.drawn.failed || null };

  // The chain as ONE SENTENCE, above everything. It is the row the reader
  // clicked, said in words: the table gave them four columns and this page has
  // to open by confirming it is describing the same four, or a reader who
  // followed the wrong link finds out three tables later.
  const sentence =
    '<p class="note"><strong>' +
    esc(chain.initial.presented || chain.initial.application || 'somebody nobody named') +
    '</strong> — ' +
    (chain.intermediary.presented || chain.intermediary.application
      ? 'acted for by <strong>' +
        esc(chain.intermediary.presented || chain.intermediary.application) +
        '</strong>'
      : '<span class="state-none">with no intermediary this service was ever ' +
        'told the name of</span>') +
    ' — reaching <strong>' +
    esc(chain.target.application || chain.target.presented || 'nothing in particular') +
    '</strong>, by <code>' + esc(chain.type) + '</code> (' +
    esc(chain.typeLabel) + ', ' + esc(chain.protocol) + '). ' +
    'It is an ' + modeCell(chain.mode) + ' and it has happened ' +
    esc(chain.acts) + ' time(s) — first ' + esc(whenText(chain.firstAt)) +
    ', last ' + esc(whenText(chain.lastAt)) + '.</p>';

  const inner = messagesOf(req) + back +
    '<div class="tiles">' +
      tile(chain.acts, 'acts on it') +
      tile(chain.issued, 'issued') +
      tile(chain.refused, 'refused') +
      tile(graph.tokens.length, 'credentials issued') +
      tile(parties.length, 'parties') +
      tile(graph.edges.filter(function (e) { return e.relation !== 'issued'; }).length,
           'lines') +
    '</div>' +

    sentence +

    '<p class="note"><strong>This is one row of ' +
    '<a href="' + esc(up.href) + '">the chains table</a> drawn on its own</strong> ' +
    ', with everything else in the service left out. A chain is ' +
    '<em>(mechanism, initial identity, intermediary, target)</em> and the ' +
    'OUTCOME is deliberately not part of it, so a relationship refused nine ' +
    'times and then fixed is this one page rather than two that never meet — ' +
    'which is why the acts below can be red and green at once. ' +
    '<a href="/admin/delegation/map">The whole picture</a> is every ' +
    'relationship at once, where this one\'s parties are shared with the ' +
    'others they take part in.</p>' +

    (graph.acts
      ? picture.html
      : '<p class="note">There is nothing to draw.</p>') +

    '<h2>The key</h2>' +
    '<p class="note">The shapes are drawn by the same functions the picture ' +
    'uses, so a legend cannot come to describe a diagram this service no longer ' +
    'draws.</p>' +
    delegationMapKey() +

    '<h2>The parties</h2>' +
    '<p class="note">Up to three boxes — the layers of the architecture — with ' +
    'both of a party\'s links where it has two. <strong>A box here can carry ' +
    'more acts than this relationship has</strong> only if it played two roles ' +
    'in one of them, which is what S4U2Self is: the requester asks for a ticket ' +
    'to itself, so it is the intermediary AND the target.</p>' +
    '<table><tr><th>Label</th><th>Drawn as</th><th>Identity</th>' +
    '<th>Roles it played</th><th>Acts</th><th>Protocols</th></tr>' +
    (parties.map(function (node) {
      return delegationNodeRow(node, known, look.looks[node.id]);
    }).join('') || '<tr><td colspan="6">No parties.</td></tr>') + '</table>' +

    '<h2>The relationships</h2>' +
    '<p class="note">A chain has three parties and therefore up to TWO lines, ' +
    'and they are different claims: <em>acts for</em> is the DELEGATION ' +
    'relationship — who is acting on whose behalf — and <em>reaches</em> is the ' +
    'TRUST relationship, what the credential is FOR. The grey line from the ' +
    'hexagon is neither: it is this service handing a credential to whoever ' +
    'asked for one.</p>' +
    '<table><tr><th>From</th><th>To</th><th>Relationship</th><th>Mechanism</th>' +
    '<th>Kind</th><th>Acts</th><th>What came out</th>' +
    '<th>Authorized by / why not</th></tr>' +
    (graph.edges.map(function (edge) {
      return delegationEdgeRow(edge, labelOf);
    }).join('') || '<tr><td colspan="8">No relationships.</td></tr>') +
    '</table>' +

    '<h2>What was issued on it</h2>' +
    '<p class="note"><strong>Every credential that came out of this ' +
    'relationship</strong>, newest first. <strong>NO CREDENTIAL IS EVER HERE, ' +
    'only its kind and its identifier</strong> — the rule the audit log follows, ' +
    'and one that applies here for one more reason: a delegation act is ' +
    'precisely the request that carries two credentials at once. A REFUSED act ' +
    'produced nothing by definition, which is why ' + graph.tokens.length +
    ' credential(s) sit under ' + chain.acts + ' act(s).</p>' +
    '<table><tr><th class="num">#</th><th>When</th><th>Credential</th>' +
    '<th>Subject</th><th>Actor</th><th>Target</th><th>Mechanism</th></tr>' +
    (graph.tokens.map(function (token) {
      return delegationTokenRow(token, labelOf);
    }).join('') || '<tr><td colspan="7">Nothing was issued on this ' +
      'relationship. A page of red acts and an empty table here is a consistent ' +
      'state rather than a broken one.</td></tr>') + '</table>' +

    '<h2>Every act on it</h2>' +
    '<p class="note">The same rows <a href="' + esc(up.href) + '">the delegation ' +
    'table</a> holds, narrowed to this relationship and not paged — there are ' +
    esc(acts.length) + ' of them and the cap on the whole store is ' +
    esc(delegation.summary().maxRecords) + '. This is where the TIMES are: the ' +
    'picture has them taken out, because four acts a second apart between the ' +
    'same three parties are one line.</p>' +
    '<table><tr><th class="num">#</th><th>When</th><th>Mechanism</th>' +
    '<th>Kind</th><th>Outcome</th><th>Initial identity</th>' +
    '<th>Intermediary</th><th>Target</th><th>Authorized by / why not</th>' +
    '<th>Credentials</th></tr>' +
    acts.map(function (row) {
      // No `chain` link on this table: every row on it belongs to the chain
      // being drawn, so the link would point at the page it is on.
      return delegationRow(row, known, { chainLink: false });
    }).join('') + '</table>' +

    '<p class="note"><code>?format=json</code> carries this chain, its acts and ' +
    'the graph behind the picture; <code>?format=svg</code> is the document ' +
    'alone, with no links in it. There is no form on this page and therefore no ' +
    'operation on <code>/admin-api</code> — everything here is an observation, ' +
    'and the acts are in <code>GET /admin-api/delegation</code> where a caller ' +
    'can filter them.</p>';

  respond(req, res, json, 'Delegation — one relationship', '/admin/delegation',
          inner, up);
  log.debug("Leaving the admin delegation chain page. " + acts.length + " act(s).");
});

// What a ROLE is called on this console, off `delegation.ROLES` rather than out
// of a list here — the same rule the mechanism filter follows. A role that
// existed in the store and was unnamed on a page would be a blank cell.
function delegationRoleLabel(role) {
  const entry = delegation.ROLES.filter(function (one) {
    return one.role === role;
  })[0];
  return entry ? entry.label : role;
}

// The roles an application played in one act, as cells. Two is possible and is
// S4U2Self — the requester asks for a ticket to ITSELF, so it is the
// intermediary and the target of the same act.
function delegationRoleCell(roles) {
  if (!roles || !roles.length) {
    return '<span class="state-none">&mdash;</span>';
  }
  return roles.map(function (role) {
    const entry = delegation.ROLES.filter(function (one) {
      return one.role === role;
    })[0];
    return '<span title="' + esc(entry ? entry.what : '') + '">' +
           esc(entry ? entry.label : role) + '</span>';
  }).join('<br>');
}

// ---------------------------------------------------------------------------
// GET /admin/delegation/application?application=… — ONE APPLICATION, IN EVERY
// ROLE IT HAS EVER PLAYED, AND EVERYTHING DELEGATED THROUGH OR TO IT.
//
// The third drill-down of /admin/delegation and the one that asks a different
// question from the other two. The map and the chain page are both *what talks
// to what*; this one is **what has been issued because of this application**,
// which is the question somebody brings when they are about to turn one off,
// or when a resource server is seeing tokens it did not expect.
//
// **REGARDLESS OF ROLE, AND THAT IS THE WHOLE POINT OF THE PAGE.** A middle tier
// is the intermediary of the chains it acts on and the TARGET of the ones that
// reach it, and those two lists are the same application seen from two sides.
// Splitting them into two pages — or offering only the targets, which is the
// easy half — would leave somebody able to see what was issued FOR a service
// and not what was issued THROUGH it, and the second is the interesting half of
// a delegation. The credentials table therefore carries a ROLE column rather
// than being filtered by one.
//
// **THE CHOICE IS FROM A LIST AND NOT A TEXT BOX**, which is the one place this
// page departs from /admin/logout's lookup. That page takes an identity, and any
// name a person can type is a legitimate thing to ask about — nothing has to
// have happened first. Here the question only means anything for an application
// some act NAMED, so the console offers what it has rather than inviting
// somebody to guess a spelling and be told nothing matched. `applicationList()`
// in delegation.js is where that list comes from, and its header says why an
// application is keyed on its IDENTIFIER rather than on a box in the picture.
//
// **A BARE PAGE IS THE CHOOSER, NOT A 404** — /admin/logout's rule, for the same
// reason: this is a lookup, and arriving with nothing selected is how somebody
// gets here from the sidebar or a bookmark.
//
// No form that CHANGES anything, so no operation on /admin-api — rule 7 exactly
// as the other two satisfy it. `?format=json` carries the chooser's list or the
// selected application's acts and graph; `?format=svg` is the picture alone.
// ---------------------------------------------------------------------------
app.get('/admin/delegation/application', function (req, res) {
  log.debug("Entering the admin delegation application page.");
  const asked = String(req.query.application || '').trim();
  // Normalised the same way the store normalises one, so a link carrying the
  // RAW identifier — which is what a reader will paste out of the acts table —
  // finds the same application the chooser's own link does.
  const key = delegation.applicationKeyOf(asked);
  const known = knownUserKeys();
  const all = delegation.list();
  const catalogue = delegation.applicationList(all);
  const entry = catalogue.filter(function (one) { return one.key === key; })[0] || null;
  const acts = entry ? delegation.actsForApplication(all, key) : [];
  const graph = delegation.graph(acts);
  const look = delegationLooks(graph, known);
  const labelOf = look.labelOf;
  const drawingLabel = entry
    ? 'Everything delegated through or to ' + entry.identifier
    : 'Applications with delegated access';

  if (String(req.query.format || '') === 'svg') {
    sendDelegationSvg(res, graph, look, drawingLabel);
    log.debug("Leaving the admin delegation application page. Answered SVG.");
    return;
  }

  const listView = listViewOf('/admin/delegation', req.query);
  const up = upTo('/admin/delegation', 'One application', listView);
  const back = '<p class="note"><a class="btn" href="' + esc(up.href) +
    '">&larr; Back to the delegation table</a></p>';

  // The chooser itself, drawn on the bare page AND under a selected application
  // — the second is what makes comparing two of them one click rather than two.
  const chooser = delegationApplicationChooser(catalogue, key, listView);

  if (!entry) {
    const inner = messagesOf(req) + back +
      (asked
        ? '<p class="note"><strong>No act held here names ' +
          '<code>' + esc(asked) + '</code> as an application.</strong> Three ' +
          'things could be true and they are different: nothing has ever ' +
          'delegated through or to it; something did and the acts have been ' +
          'DROPPED, because this store keeps at most ' +
          esc(delegation.summary().maxRecords) + ' and discards the oldest; or ' +
          'the name is spelled differently from the way a protocol presented ' +
          'it. The list below is every application some act actually named, ' +
          'which settles the third.</p>'
        : '') +
      '<p class="note"><strong>Choose an application to see everything that has ' +
      'been delegated through it or to it.</strong> A delegation has three ' +
      'parties and an application can be two of them — the INTERMEDIARY that ' +
      'acts on somebody\'s behalf, and the TARGET the credential is for — so ' +
      'this page shows both sides of one application rather than making you ' +
      'pick a side. That is the question worth asking before turning a middle ' +
      'tier off: not <em>what reaches it</em>, but <em>what exists because of ' +
      'it</em>.</p>' +
      chooser +
      delegationApplicationTable(catalogue, known, listView) +
      '<p class="note">The list is built from the ACTS rather than from ' +
      '<a href="/admin/applications">the registry</a>, which is why an entry ' +
      'here can be marked <em>not in the registry</em>: the registry holds what ' +
      'this service has been asked about, and an RFC 8693 <code>audience</code> ' +
      'nobody has otherwise mentioned is a real delegation target that nothing ' +
      'else in this console knows the name of.</p>';
    respond(req, res, { application: null, asked: asked || null,
                        applications: catalogue, held: delegation.summary().held },
            'Delegation — one application', '/admin/delegation', inner, up);
    log.debug("Leaving the admin delegation application page. " +
              (asked ? "Nothing named that." : "Drew the chooser."));
    return;
  }

  // WHICH ROLES THIS APPLICATION PLAYED IN THE ACT EACH CREDENTIAL CAME OUT OF.
  // Keyed on `seq`, which is the act's own identifier and is monotonic and never
  // reused — so this cannot attach a role to the wrong credential even after the
  // cap has dropped something between the two walks.
  const rolesBySeq = {};
  acts.forEach(function (row) {
    rolesBySeq[row.seq] = delegation.applicationRolesIn(row, key);
  });

  const parties = graph.nodes.filter(function (node) {
    return node.kind !== 'sts';
  });
  const picture = delegationDrawing(graph, look, '/admin/delegation/application',
                                    Object.assign({}, listView,
                                                  { application: entry.identifier }),
                                    drawingLabel);

  // The registry's answer, tried against every spelling: `ou=applications` is
  // keyed by what a caller presented, and this page's key is normalised — so
  // asking with the normalised form alone would report "not in the registry"
  // for an application that is in it under the realm-qualified name.
  let registered = null;
  entry.spellings.forEach(function (spelling) {
    if (!registered) {
      registered = applications.get(spelling) || null;
    }
  });

  const inner = messagesOf(req) + back +
    '<div class="tiles">' +
      tile(entry.acts, 'acts') +
      tile(entry.issued, 'issued') +
      tile(entry.refused, 'refused') +
      tile(graph.tokens.length, 'credentials issued') +
      tile(entry.chains, 'relationships') +
      tile(entry.roles.intermediary, 'as the intermediary') +
    '</div>' +

    '<p class="note"><strong><code>' + esc(entry.identifier) + '</code></strong> — ' +
    (registered
      ? '<a href="' + esc('/admin/applications' +
          queryWith({ application: entry.identifier }, {})) + '">in the ' +
        'registry</a> as <strong>' +
        esc(registered.name || registered.dnLabel || entry.identifier) +
        '</strong>'
      : '<span class="state-none" title="No entry under ou=applications names ' +
        'this. The registry holds what this service has been ASKED ABOUT, and a ' +
        'delegation naming something nobody has otherwise mentioned is ordinary ' +
        '— an RFC 8693 audience is exactly that.">not in the registry</span>') +
    (entry.identityKey
      ? '. It has also PRESENTED a credential of its own, so it is a person here ' +
        'as well as an application: ' +
        usersPageCell(entry.identityKey, known) + ' on the users page. That is ' +
        'the middle tier being both, which is ordinary — a service account ' +
        'authenticates, so the identity funnel files it under ' +
        '<code>ou=users</code>, and tickets are issued FOR it, so the registry ' +
        'files it under <code>ou=applications</code>.'
      : '.') +
    (entry.spellings.length > 1
      ? ' <strong>It has been spelled ' + entry.spellings.length + ' ways</strong> ' +
        'and they are one application here: ' + codeList(entry.spellings) +
        '. Two spellings of one identity is two people, so they are collapsed on ' +
        'the same normalisation the picture uses — the spellings are kept so ' +
        'that the collapse is something you can see rather than take on trust.'
      : '') +
    ' Protocols: ' + (entry.protocols.length ? codeList(entry.protocols) : 'none') +
    '. First seen ' + esc(whenText(entry.firstAt)) + ', last ' +
    esc(whenText(entry.lastAt)) + '.</p>' +

    '<h2>What it does in a delegation</h2>' +
    '<p class="note"><strong>Both sides of one application.</strong> The counts ' +
    'below are of ACTS, and one act can count twice here — an S4U2Self names the ' +
    'requester as the intermediary and as the target, because the ticket is to ' +
    'itself.</p>' +
    '<table><tr><th>Role</th><th>Acts</th><th>What the role is</th></tr>' +
    delegation.ROLES.map(function (role) {
      const n = entry.roles[role.role] || 0;
      return '<tr>' +
        '<td>' + esc(role.label) + '</td>' +
        '<td class="num">' + (n
          ? '<strong>' + esc(n) + '</strong>'
          : '<span class="state-none">0</span>') + '</td>' +
        '<td>' + esc(role.what) + '</td>' +
        '</tr>';
    }).join('') + '</table>' +

    (graph.acts
      ? '<h2>The relationships it is part of</h2>' +
        '<p class="note">Every chain this application appears in, drawn ' +
        'together — so a middle tier shows the people it acts for on one side ' +
        'and what it reaches on the other, which is the shape a list of rows ' +
        'cannot show. The <strong>chain</strong> link beside each act at the ' +
        'foot of this page draws ONE of them alone.</p>' + picture.html
      : '') +

    '<h2>The key</h2>' +
    '<p class="note">The shapes are drawn by the same functions the picture ' +
    'uses, so a legend cannot come to describe a diagram this service no longer ' +
    'draws.</p>' +
    delegationMapKey() +

    '<h2>The parties it deals with</h2>' +
    '<p class="note">Every box in the picture above, including this application ' +
    'itself.</p>' +
    '<table><tr><th>Label</th><th>Drawn as</th><th>Identity</th>' +
    '<th>Roles it played</th><th>Acts</th><th>Protocols</th></tr>' +
    (parties.map(function (node) {
      return delegationNodeRow(node, known, look.looks[node.id]);
    }).join('') || '<tr><td colspan="6">No parties.</td></tr>') + '</table>' +

    '<h2>Every delegated credential related to it</h2>' +
    '<p class="note"><strong>This is the list this page exists for.</strong> ' +
    'Every credential that came out of an act this application took part in, ' +
    'newest first, WHATEVER ROLE IT PLAYED — so a token issued THROUGH it (it ' +
    'was the intermediary) and one issued FOR it (it was the target) are both ' +
    'here, with the role in its own column. <strong>NO CREDENTIAL IS EVER HERE, ' +
    'only its kind and its identifier</strong>, which is the rule the audit log ' +
    'follows; a Kerberos ticket genuinely has no identifier to quote. A REFUSED ' +
    'act produced nothing by definition, which is why ' + graph.tokens.length +
    ' credential(s) sit under ' + entry.acts + ' act(s).</p>' +
    '<table><tr><th class="num">#</th><th>When</th><th>Its role</th>' +
    '<th>Credential</th><th>Subject</th><th>Actor</th><th>Target</th>' +
    '<th>Mechanism</th></tr>' +
    (graph.tokens.map(function (token) {
      return delegationTokenRow(token, labelOf,
                                delegationRoleCell(rolesBySeq[token.seq]));
    }).join('') || '<tr><td colspan="8">Nothing has been issued through this ' +
      'application or to it. A page of red acts and an empty table here is a ' +
      'consistent state rather than a broken one.</td></tr>') + '</table>' +
    (graph.tokensLeftOff
      ? '<p class="note"><strong>' + graph.tokensLeftOff + ' more credential(s) ' +
        'are not listed.</strong> This list holds at most ' + graph.maxTokenRows +
        ' and keeps the newest; every one of them is still COUNTED on its line ' +
        'in the picture, so what is lost is the individual identifiers of the ' +
        'oldest.</p>'
      : '') +

    '<h2>Every act it took part in</h2>' +
    '<p class="note">The rows <a href="' + esc(up.href) + '">the delegation ' +
    'table</a> holds, narrowed to this application and not paged. This is where ' +
    'the TIMES and the REFUSALS are — a refusal produced no credential, so it ' +
    'is in this table and not in the one above.</p>' +
    '<table><tr><th class="num">#</th><th>When</th><th>Mechanism</th>' +
    '<th>Kind</th><th>Outcome</th><th>Initial identity</th>' +
    '<th>Intermediary</th><th>Target</th><th>Authorized by / why not</th>' +
    '<th>Credentials</th></tr>' +
    acts.map(function (row) {
      return delegationRow(row, known, { listView: listView });
    }).join('') + '</table>' +

    '<h2>Another application</h2>' + chooser +
    delegationApplicationTable(catalogue, known, listView) +

    '<p class="note"><code>?format=json</code> carries this application, its ' +
    'acts and the graph behind the picture; <code>?format=svg</code> is the ' +
    'document alone. There is no form that changes anything on this page and ' +
    'therefore no operation on <code>/admin-api</code> — the acts are in ' +
    '<code>GET /admin-api/delegation</code>, where a caller can filter them by ' +
    'the same free text.</p>';

  respond(req, res, {
    application: entry,
    asked: asked,
    registered: !!registered,
    acts: acts,
    graph: graph,
    // The role played per act, keyed by the act's sequence number. It is the one
    // thing here a caller could not work out from `acts` without reimplementing
    // the normalisation — which is exactly the drift the store owns that rule to
    // prevent.
    rolesBySeq: rolesBySeq,
    applications: catalogue,
    held: delegation.summary().held,
    drawing: { width: picture.drawn.width, height: picture.drawn.height,
               failed: picture.drawn.failed || null }
  }, 'Delegation — one application', '/admin/delegation', inner, up);
  log.debug("Leaving the admin delegation application page. " + acts.length +
            " act(s), " + graph.tokens.length + " credential(s).");
});

// ---------------------------------------------------------------------------
// GET /admin/users — who this service has authenticated, and one of them in full.
//
// One route and two pages: without `?user=` it is the list, with it the drill-down.
// That is deliberate rather than lazy. A path parameter would have been the obvious
// shape and cannot be used here, because the identities this service holds contain
// the characters a path is made of — a Kerberos service principal is `HTTP/host` and
// a subject is a `urn:` — so `/admin/users/HTTP/web.example.com` is a two-segment
// path naming nobody. A query parameter carries any of them unaltered and keeps the
// console to one row in the metrics table for the whole feature.
//
// **What "a user" means here, and the two ways it can surprise you.** The list is
// built in admin_stats.js from the authentications this service recorded, PLUS every
// subject that appears on something it issued — so a subject that never authenticated
// here (an exchanged foreign token, a WS-Trust OnBehalfOf, a Kerberos S4U2Self) is
// listed and marked as such, rather than being absent from a page whose whole job is
// to answer "who has this service seen". And the identity is keyed on the local name,
// so one row covers `alice`, `urn:sts-mock:user:alice` and `alice@STS.MOCK`, which is
// right on a mock where the name you type is who you are everywhere — and would be
// wrong on a real system with two realms. The Realms column exists so that collapse
// is visible.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE EMBEDDED DIRECTORY'S VIEW OF ONE USER, AND WHY IT ARRIVES THROUGH A SLOT.
//
// ldap_server.js grows an entry under `ou=users` for everybody who authenticates
// anywhere in this service, so by the time a person has a page here they usually
// have a directory object too — and showing it beside their tokens is the point:
// the two are the same authentication seen from two sides.
//
// This module does NOT require ldap_server.js to get at it, and the reason is the
// route order rather than a cycle. server.js requires ./admin before
// ./ldap_server (that module needs admin_stats' identity normalisation, and the
// console reads oauth2's sessions), so a require from here would pull the
// directory's routes into the router AHEAD of the console's — and
// /admin/sts-metadata is built by walking that router. So the direction is
// inverted the same way admin_stats.js's user observer is: this file offers a
// slot, and ldap_server.js fills it at its own require time.
//
// It stays null when that module was never required. That is a real state — the
// directory is the newest thing here and a build without it must still render this
// page — so the section says "no directory is loaded" rather than being absent,
// which would read as "this user has no entry".
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// The two things every LDAP section of this console draws, in one place each
// because there are now three such sections — a user's entry, the groups list
// and one group in full.
// ---------------------------------------------------------------------------

// What a section is showing, in the four grammatical forms the listener warning
// needs. A warning about sockets has to name the thing the reader came for —
// the whole point of it is the gap between "this service holds it" and "an LDAP
// client can fetch it" — and that sentence needs a noun that agrees with itself.
const ENTRY_SUBJECT = { upper: 'The entry below', lower: 'the entry below',
                        verb: 'is', pronoun: 'it' };
const GROUPS_SUBJECT = { upper: 'The groups below', lower: 'the groups below',
                         verb: 'are', pronoun: 'they' };
const GROUP_SUBJECT = { upper: 'The group below', lower: 'the group below',
                        verb: 'is', pronoun: 'it' };

// The state of the directory's two sockets as a banner, or '' when both are up.
//
// Three cases rather than two, because plain 389 and LDAPS 636 are independent
// sockets and either can be up while the other is not — which is the commonest
// outcome of a host run, where 636 is privileged and 389 has usually lost the
// port to the host's own slapd. A page that said "no client can connect" while
// LDAPS was answering would be wrong in the direction that costs somebody an
// afternoon looking for a directory that was there all along.
function directoryListenerWarning(info, subject) {
  if (!info.listening && !info.ldapsListening) {
    return '<div class="warn"><strong>The directory\'s listeners are not up</strong> — ' +
      esc(info.listenError || 'it never bound') + '. ' + subject.upper + ' ' + subject.verb +
      ' in this process\'s store and ' + subject.verb + ' what an LDAP client WOULD read; ' +
      'right now no client can connect, most likely because TCP ' + esc(info.port) +
      ' was already taken. This page is HTTP and answers either way.</div>';
  }
  if (!info.listening) {
    return '<div class="warn"><strong>The directory\'s plain listener is not up</strong> — ' +
      esc(info.listenError || 'it never bound') + ' — but <strong>LDAPS on ' +
      esc(info.ldapsPort) + ' is</strong>, so ' + subject.lower + ' ' + subject.verb +
      ' reachable over TLS. TCP ' + esc(info.port) + ' was most likely already taken.</div>';
  }
  if (info.ldapsPort && !info.ldapsListening) {
    return '<div class="warn">The plain listener on ' + esc(info.port) + ' is up; ' +
      '<strong>LDAPS is not</strong>. That affects how ' + subject.lower + ' can be ' +
      'reached, not whether ' + subject.pronoun + ' ' + subject.verb + ' there.</div>';
  }
  return '';
}

// Every attribute of one entry, operational ones included, as the table both the
// user page and the group page draw. `entry` is what the directory's readers
// return: canonically spelled names, values already arrays, and `operational`
// naming which of them a search would have withheld.
function attributeTable(entry) {
  const rows = Object.keys(entry.attributes).map(function (name) {
    const values = entry.attributes[name];
    const operational = entry.operational.indexOf(name) >= 0;
    return '<tr><td><code>' + esc(name) + '</code>' +
      (operational
        ? ' <span class="state-none" title="An operational attribute. A search returns it only ' +
          'when it is asked for by name (RFC 4511 section 4.5.1.8) — this dump shows it always.' +
          '">(operational)</span>'
        : '') + '</td>' +
      '<td class="num">' + values.length + '</td>' +
      '<td>' + (values.map(function (value) {
        return '<code>' + esc(value) + '</code>';
      }).join('<br>') || '—') + '</td></tr>';
  }).join('');
  return '<table><tr><th>Attribute</th><th class="num">Values</th><th>Value(s)</th></tr>' +
    rows + '</table>';
}

let directoryReader = null;

function setDirectoryReader(fn) {
  directoryReader = fn;
  log.debug("A directory reader was installed; a user's page will now show that " +
            "user's LDAP entry.");
}

// The groups pages read through their own slot, installed the same way and by the
// same module, for the reason above: this file must not require ldap_server.js.
//
// Two slots rather than one object with two functions, because they were added at
// different times and a single slot would mean an ldap_server.js that filled it
// with only one of them silently disabling the other. A missing slot is already
// handled — each page says "no directory is loaded" — and two of those are cheaper
// than one half-filled reader nothing reports.
let groupReader = null;

function setGroupReader(fn) {
  groupReader = fn;
  log.debug("A group reader was installed; /admin/groups will now show the " +
            "directory's groups.");
}

// The FOURTH slot, and the third of the ones that READ. Same direction and same
// reason as the two above, and it passes rule 3e's test for the same two
// grounds: requiring scim.js from here would pull every /scim route — and, since
// that module requires ldap_server.js, every /ldap route too — into the express
// router ahead of the console's own, and /admin/sts-metadata is built by
// walking that router.
//
// What it holds is scim.js's description(), which is the same object GET
// /scim?format=json answers with. So /admin/scim shows what that page shows
// rather than a second account of the same feature: the endpoint list, what SCIM
// deliberately does not do, and the reachable negatives are written ONCE, in the
// module that implements them, and this page renders them. A console page
// carrying its own copy of "active: false deactivates nobody" would be the copy
// that stops being true.
// The SPIFFE listeners, through a slot for the reason given beside the requires
// above: this file must not require spiffe_server.js. What it holds is that
// module's `bindings()` and its bundle path — two facts about SOCKETS, which
// neither this page nor /admin/sts-metadata can see any other way, so a page
// without this reports "nothing bound" and cannot tell that from a listener
// whose port was taken.
let spiffeReader = null;

function setSpiffeReader(fn) {
  spiffeReader = fn;
  log.debug("A SPIFFE reader was installed; /admin/spiffe will now report " +
            "which gRPC listeners bound.");
}

// Answered with empty listeners rather than null when the slot is unfilled, so
// every caller renders the same "nothing bound" table instead of each having to
// guard. The bundle path falls back to the configured value, which is what that
// module reads too — one setting, two readers, no third opinion.
function spiffeListeners() {
  const read = spiffeReader ? spiffeReader() : null;
  return read || { workload: [], api: [],
                   bundlePath: config.value('spiffe.bundlePath') };
}

// ---------------------------------------------------------------------------
// AND THE SIXTH, WHICH IS THE PROTOCOL-INDEPENDENT LOGOUT.
//
// Same direction and both halves of rule 3e's test at once — see the note
// beside the requires at the top of this file. `logout.js` requires
// `ldap_server.js`, which requires THIS module, so a require in the obvious
// direction closes a cycle; and it would drag every `/ldap` route into the
// router ahead of the console's own.
//
// It holds THREE things and they are one object, validated when it is
// installed: `FAMILIES` (the prose about what a logout reaches, so this page
// does not carry a second copy that goes stale the day a family is added),
// `inventoryFor` (what is live for one identity) and `terminate` (ending it).
// One object rather than three slots for the reason the directory writer's note
// gives one screen up: a module that filled a combined slot with only the
// readers would silently disable the action with nothing reporting it, so the
// object is checked whole and refused whole.
let logoutReader = null;

function setLogoutReader(reader) {
  const complete = reader && typeof reader.inventoryFor === 'function' &&
                   typeof reader.terminate === 'function' && Array.isArray(reader.FAMILIES);
  if (!complete) {
    // A warning and not a throw, for the reason admin_rbac.js's install has:
    // a console that will not start is worse than a console with one page that
    // says why it cannot answer.
    log.warn('admin: a logout reader was offered that does not carry ' +
             'inventoryFor(), terminate() and FAMILIES. It is refused whole — a partial one ' +
             'would leave /admin/logout listing what is live and unable to end any of it, ' +
             'which is the worst of the two halves.');
    return;
  }
  logoutReader = reader;
  log.debug("A logout reader was installed; /admin/logout will now list and end " +
            "live sessions across every protocol family.");
}

let scimReader = null;

function setScimReader(fn) {
  scimReader = fn;
  log.debug("A SCIM reader was installed; /admin/scim will now describe the " +
            "SCIM 2.0 endpoints.");
}

// And the one that WRITES, which is the third of these and the only one of the
// three that changes anything. Same direction and same reason as the two above —
// this file must not require ldap_server.js — and a third slot rather than a
// member on one of theirs, for the reason stated there: a module that filled a
// combined slot with only the readers would silently disable creation with
// nothing reporting it.
//
// It holds createUser() and NOT a way to write an arbitrary entry. The console
// is not a second definition of what a user is: what a name may be, and the
// refusal of one that is already here, live in that function so that this form,
// the management API and an `ldapadd` cannot come to disagree about the same
// name.
let directoryWriter = null;

function setDirectoryWriter(fn) {
  directoryWriter = fn;
  log.debug("A directory writer was installed; /admin/users can now create a " +
            "person in the directory.");
}

// The whole section, as HTML and as the object that goes into ?format=json. Both
// come out of one call so that the page and the JSON cannot disagree about what
// the directory holds, which is the same rule /ldap follows for its own two views.
//
// `row` is the user record: it is what tells a missing entry apart from an entry
// that was never going to exist. Four of the five reasons for an absence are facts
// about the USER rather than about the directory — a client is not a person, an
// LDAP bind presents a DN and not a user name, an identity that only ever appeared
// as the subject of something never authenticated at all — and a section that said
// only "not found" would send a reader to look for a bug in the directory.
function ldapObjectSection(row, key) {
  log.debug("Entering ldapObjectSection(). key=" + key);
  const heading = '<h2>This user in the LDAP directory</h2>';
  if (!directoryReader) {
    log.debug("Leaving ldapObjectSection(). No directory is loaded.");
    return {
      html: heading +
        '<p class="note">No LDAP directory is loaded in this process, so there is no entry to ' +
        'show. That is a build of this service without <code>ldap_server.js</code> and not a ' +
        'failure — every other section of this page is unaffected.</p>',
      json: null
    };
  }
  const info = directoryReader(key);
  const link = '<p class="note"><a href="/ldap">What this directory is</a> &middot; ' +
    '<a href="/ldap/directory">every entry in it</a> &middot; ' +
    '<a href="/ldap/directory?format=json">the same as JSON</a>.</p>';
  // Said on every branch, including the ones with an entry: the entry can be there
  // and the socket down, and a reader who trusts this page to mean "an LDAP client
  // can fetch this" needs to know which.
  const listener = directoryListenerWarning(info, ENTRY_SUBJECT);
  const alsoNamed = info.alsoNamed.length
    ? '<p class="note">' + info.alsoNamed.length + ' other entr' +
      (info.alsoNamed.length === 1 ? 'y names' : 'ies name') + ' this uid: ' +
      codeList(info.alsoNamed) + '. Those were written through the protocol rather than seeded ' +
      'by an authentication — this directory has no schema and does not require a uid to be ' +
      'unique, so they are shown rather than merged.</p>'
    : '';

  if (!info.found) {
    // Why not, in the order that makes the first true one the real answer. The DN
    // is quoted with it, EXCEPT where the identity is an LDAP bind DN — there the
    // name this console files the person under is itself a DN, so the place an
    // entry would have gone is `uid=<a whole DN>,ou=users,...`, and leading with
    // that reads as a malformed directory rather than as the explanation that
    // follows it.
    let because;
    let intro = 'There is no entry at <code>' + esc(info.dn) + '</code>.';
    if (!info.autoCreateUsers) {
      because = 'An entry per authenticated user is switched OFF in this process ' +
        '(<code>LDAP_AUTOCREATE_USERS</code>), so nothing here seeds one.';
    } else if (row.isClient) {
      because = 'This identity is a <strong>client</strong>, not a person. ' +
        '<code>client_credentials</code> produces tokens with a subject and nobody behind them, ' +
        'and a directory of people is the wrong place for it, so the directory declines to ' +
        'invent one.';
    } else if (!row.authenticated) {
      because = 'This identity has <strong>never authenticated here</strong>. The entry is ' +
        'seeded at the moment a credential is ACCEPTED, and this one is known only as the ' +
        'subject of something that was issued — so there was no such moment.';
    } else if (row.protocols.length === 1 && row.protocols[0].protocol === 'ldap') {
      intro = 'Nothing was seeded for this identity.';
      because = 'Everything this identity has done here is an <strong>LDAP bind</strong>, which ' +
        'presents a DN rather than a user name. Seeding <code>uid=&lt;a whole DN&gt;</code> under ' +
        '<code>' + esc(info.usersDn) + '</code> would put a second, malformed object beside the ' +
        'one the DN already names.';
    } else if (info.full) {
      because = 'The directory holds its maximum of ' + esc(info.maxEntries) + ' entries, so it ' +
        'stopped creating them. The authentication itself was unaffected — a full directory ' +
        'must never fail one.';
    } else {
      because = 'It was there and is not now: an entry can be <code>delete</code>d or ' +
        '<code>modifyDN</code>&rsquo;d through the protocol like any other, and nothing puts it ' +
        'back until this name authenticates again.';
    }
    log.debug("Leaving ldapObjectSection(). There is no entry at " + info.dn + ".");
    return {
      html: heading + listener +
        '<p class="note">' + intro + ' ' + because + '</p>' + alsoNamed + link,
      json: info
    };
  }

  const entry = info.entry;

  const html = heading + listener +
    '<p class="note">The entry the embedded directory holds for this person &mdash; the object ' +
    'itself and not a copy of it, so an LDAP client bound to <code>ldap://&lt;host&gt;:' +
    esc(info.port) + '</code> reading <code>' + esc(entry.dn) + '</code> sees exactly this. It ' +
    'appeared the first time they authenticated through any protocol here, and it carries no ' +
    'password: <strong>every bind to this directory succeeds anyway</strong>, whatever DN and ' +
    'whatever password, so nothing in this object is a credential.</p>' +
    '<table><tr><th>DN</th><th>Came from</th><th>Created</th><th>Last modified</th></tr>' +
    '<tr><td><code>' + esc(entry.dn) + '</code></td>' +
    '<td>' + esc(entry.origin) + '</td>' +
    '<td><code>' + esc(entry.createdAt) + '</code></td>' +
    '<td><code>' + esc(entry.modifiedAt) + '</code></td></tr></table>' +
    '<p class="note">The two timestamps are <em>generalized time</em> ' +
    '(<code>YYYYMMDDHHMMSSZ</code>), which is what a directory shows &mdash; not the ISO 8601 ' +
    'strings the rest of this console uses. The difference is only punctuation and it is kept ' +
    'because a debugger that showed one where the protocol carries the other would be showing ' +
    'the wrong thing.</p>' +
    attributeTable(entry) +
    '<p class="note">Every attribute the entry has, operational ones included. This directory is ' +
    '<strong>schemaless</strong>: no <code>objectClass</code> is enforced and no value is checked ' +
    'against a syntax, so an attribute a real directory would refuse is here because something ' +
    'wrote it. The <code>description</code> values are this service\'s own note of which ' +
    'protocols this person has authenticated through &mdash; one line per protocol, added the ' +
    'first time each is seen.</p>' +
    alsoNamed + link;

  log.debug("Leaving ldapObjectSection(). " + Object.keys(entry.attributes).length +
            " attribute(s) dumped.");
  return { html: html, json: info };
}

// The live sign-on sessions belonging to one user. Sessions are keyed by an opaque
// id and hold a user object, so the match is on the identity rather than the string:
// the session says `alice` and the tokens say `urn:sts-mock:user:alice`, and these
// have to end up on the same page.
function sessionRowsFor(key) {
  log.debug("Entering sessionRowsFor(). key=" + key);
  const rows = signOnSessionRows().filter(function (session) {
    return stats.identityKeyOf(session.username || session.sub) === key;
  });
  log.debug("Leaving sessionRowsFor(). " + rows.length + " session(s).");
  return rows;
}

// The tokens of one user, split by the session they were issued on.
//
// Three buckets, and the third is the one worth explaining. A token whose record
// names a session that is no longer held is not an error: sessions expire and are
// swept, and the token outlives the sign-on it came from — that is exactly the state
// an OIDC client is in when its ID Token still verifies and the browser would be
// asked to sign in again. Showing those under "no session" would say something false
// about how they were issued.
function tokensBySession(tokens, sessionRows) {
  log.debug("Entering tokensBySession(). " + tokens.length + " token(s).");
  const held = {};
  sessionRows.forEach(function (session) { held[session.id] = []; });
  const ended = [];
  const sessionless = [];
  tokens.forEach(function (record) {
    if (!record.sessionId) {
      sessionless.push(record);
      return;
    }
    if (held[record.sessionId]) {
      held[record.sessionId].push(record);
      return;
    }
    ended.push(record);
  });
  log.debug("Leaving tokensBySession(). " + Object.keys(held).length + " session(s), " +
            ended.length + " on an ended session, " + sessionless.length + " with none.");
  return { held: held, ended: ended, sessionless: sessionless };
}

// One user's tokens as a table. The columns are the ones that differ WITHIN a user:
// their name and subject are the same on every row by construction and are stated
// once above the table instead of repeated down it.
function userTokenTable(records, back, empty) {
  log.debug("Entering userTokenTable(). " + records.length + " row(s).");
  const rows = records.map(function (record) {
    const button = record.revocable
      ? '<form method="post" action="/admin/tokens" class="inline">' +
        '<input type="hidden" name="action" value="' + (record.revoked ? 'restore' : 'revoke') + '">' +
        '<input type="hidden" name="target" value="' + esc(record.jti) + '">' +
        '<input type="hidden" name="from" value="users">' +
        '<input type="hidden" name="back" value="' + esc(back) + '">' +
        '<button class="' + (record.revoked ? 'secondary' : 'danger') + '">' +
        (record.revoked ? 'Restore' : 'Revoke') + '</button></form>'
      : '<span class="state-none" title="Only access tokens, ID Tokens and refresh tokens can be ' +
        'revoked — the others are replies rather than credentials, or carry no jti to act on.">—</span>';
    return '<tr><td>' + esc(record.kind) + '</td>' +
      '<td class="' + stateClass(record.state) + '">' + esc(record.state) + '</td>' +
      '<td>' + esc(record.grant || '—') + '</td>' +
      '<td>' + esc(record.client_id || '—') + '</td>' +
      '<td>' + esc(record.scope || '—') + '</td>' +
      '<td>' + (record.jkt ? 'DPoP' : 'Bearer') + '</td>' +
      '<td>' + esc(whenText(record.issuedAt)) + '</td>' +
      '<td>' + esc(record.exp ? whenText(record.exp * 1000) : '—') + '</td>' +
      '<td>' + shortened(record.jti, 12) + '</td>' +
      '<td>' + button + '</td></tr>';
  }).join('');
  log.debug("Leaving userTokenTable().");
  return '<table><tr><th>Token</th><th>State</th><th>Grant</th><th>Client</th><th>Scope</th>' +
    '<th>Presented as</th><th>Issued</th><th>Expires</th><th>jti</th><th></th></tr>' +
    (rows || '<tr><td colspan="10">' + esc(empty) + '</td></tr>') + '</table>';
}

// The artifacts that are not JWTs. One table for all three kinds, with a single
// Detail column, because an assertion's audience, a ticket's service and enc-type
// and a credential's configuration id are each the one thing worth reading about
// that row and giving each its own column would leave two thirds of the table empty.
function userArtifactTable(records) {
  log.debug("Entering userArtifactTable(). " + records.length + " row(s).");
  const rows = records.map(function (record) {
    const detail = record.service
      ? 'service ' + record.service + (record.etype ? ', ' + record.etype : '') +
        (record.realm ? ', realm ' + record.realm : '')
      : (record.audience ? 'audience ' + record.audience
                         : (record.configId ? 'configuration ' + record.configId : ''));
    return '<tr><td>' + esc(record.kind) + '</td>' +
      '<td class="' + stateClass(record.state) + '">' + esc(record.state) + '</td>' +
      '<td>' + esc(detail || '—') + '</td>' +
      '<td>' + (record.id ? shortened(record.id, 20) : '<span class="state-none" ' +
        'title="A Kerberos ticket has no identifier to quote: it is named by the client and ' +
        'service it is for.">—</span>') + '</td>' +
      '<td>' + esc(whenText(record.issuedAt)) + '</td>' +
      '<td>' + esc(record.expiresAt ? whenText(record.expiresAt) : '—') + '</td></tr>';
  }).join('');
  log.debug("Leaving userArtifactTable().");
  return '<table><tr><th>Artifact</th><th>State</th><th>Detail</th><th>Identifier</th>' +
    '<th>Issued</th><th>Expires</th></tr>' +
    (rows || '<tr><td colspan="6">Nothing that is not a JWT has been issued to this user.</td></tr>') +
    '</table>';
}

// How they authenticated, most recent first. The whole point of the table is the
// Method column: "sign-in screen (password)" and "AS-REQ with PA-ENC-TIMESTAMP" are
// both authentications and only one of them checked anything.
function authenticationTable(row) {
  log.debug("Entering authenticationTable(). " + row.events.length + " event(s).");
  const rows = row.events.slice().reverse().map(function (event) {
    return '<tr><td>' + esc(whenText(event.at)) + '</td>' +
      '<td>' + esc(event.protocol) + '</td>' +
      '<td>' + esc(event.method) + '</td>' +
      '<td>' + esc(event.presented) + '</td>' +
      '<td>' + esc(event.amr || '—') + '</td>' +
      '<td>' + esc(event.acr || '—') + '</td>' +
      '<td>' + esc(event.client_id || '—') + '</td>' +
      '<td>' + (event.sessionId ? shortened(event.sessionId, 10) : '—') + '</td>' +
      '<td>' + esc(event.note || '') + '</td></tr>';
  }).join('');
  log.debug("Leaving authenticationTable().");
  return '<table><tr><th>When</th><th>Protocol</th><th>Method</th><th>Presented as</th>' +
    '<th>amr</th><th>acr</th><th>Client</th><th>Session</th><th>Note</th></tr>' +
    (rows || '<tr><td colspan="9">No authentication was recorded for this identity. See above: ' +
             'they are known here only as the subject of something that was issued.</td></tr>') +
    '</table>' +
    (row.eventsForgotten > 0
      ? '<p class="note">The most recent ' + stats.MAX_EVENTS_PER_USER + ' of ' +
        (row.eventsForgotten + row.events.length) + ' authentication(s); the rest have been ' +
        'forgotten. The counts above them are of all of them and are not capped.</p>'
      : '');
}

// One session and everything issued on it. This is the answer to the question the
// page exists for — "what does this person hold right now, and where did it come
// from" — so the session's own facts and its tokens are drawn as one block rather
// than as two tables somebody has to join by eye.
//
// Its token table is PAGED, and paged separately from every other block on the page.
// One browser session can hold most of the five thousand tokens this service
// remembers — a refresh grant in a loop is all it takes — so the block that answers
// "what does this person hold right now" is the one table here that can genuinely
// run away, and a single `page` shared with the block above it would move both.
// Hence a page parameter named after the session id: it names the block it moves, so
// a bookmark still moves the same session after the list around it has changed,
// which an index into the session list would not.
function sessionBlock(session, tokenPage, back, params) {
  log.debug("Entering sessionBlock(). id=" + session.id);
  const nav = pageNav('/admin/users', params, tokenPage.paging);
  const html = '<h3>Session ' + shortened(session.id, 12) + ' &mdash; ' +
    '<span class="' + (session.expired ? 'state-expired' : 'state-valid') + '">' +
    (session.expired ? 'expired, not yet swept' : 'active') + '</span></h3>' +
    '<table><tr><th>Signed in</th><th>Expires</th><th>amr</th><th>acr</th>' +
    '<th>WS-Fed relying parties signed into</th></tr>' +
    '<tr><td>' + esc(whenText(session.authTime)) + '</td>' +
    '<td>' + esc(whenText(session.expires)) + '</td>' +
    '<td>' + esc(session.amr || '—') + '</td>' +
    '<td>' + esc(session.acr || '—') + '</td>' +
    '<td>' + (session.wsfedRealms.length ? esc(session.wsfedRealms.join(', ')) : '—') + '</td></tr></table>' +
    nav +
    userTokenTable(tokenPage.shown, back,
      'Nothing has been issued on this session yet. A browser can hold a sign-on session and have ' +
      'been given no token at all — it is what the authorization endpoint reads before it issues ' +
      'anything.') +
    nav;
  log.debug("Leaving sessionBlock().");
  return html;
}

// The drill-down. Returns null when the identity is not one this service knows,
// which the route below turns into an honest empty page rather than a 404: a user
// can genuinely be forgotten to the cap between the click and the page.
function userDetailPage(req, key) {
  log.debug("Entering userDetailPage(). key=" + key);
  const detail = stats.userDetail(key);
  if (!detail) {
    log.debug("Leaving userDetailPage(). No such user.");
    return null;
  }
  const row = detail.user;
  const sessionRows = sessionRowsFor(key);
  const live = sessionRows.filter(function (s) { return !s.expired; });
  const split = tokensBySession(detail.tokens, sessionRows);
  // Where a revoke button on this page returns to: this user's page, which is the
  // only sensible answer — the reader is looking at one person and wants to see the
  // effect on that person. It carries the whole query and not just the name, so the
  // answer is the page of the table the button was on rather than the first page of
  // all five; backTo() picks the page parameters back out by shape.
  //
  // `params` is the whole current query carried through, and every control on this
  // page rides on it, so moving one of the five lists leaves the other four where
  // they are. See pageParamsOf() for why it is carried rather than listed.
  const params = pageParamsOf(req.query);
  const back = queryWith(params, {});
  const valid = detail.tokens.filter(function (t) { return t.state === 'valid'; }).length;
  // Counted beside `valid` because "issued" minus "valid" is not "expired" — a
  // revoked token, one not yet valid and one with no expiry stated all sit in
  // that difference, and a reader doing the subtraction gets the wrong answer
  // silently. It is its own tile for the same reason the users table grew its
  // own column: a token running out of time is the ordinary end of a token and
  // the first thing to check when a client starts being refused.
  const expired = detail.tokens.filter(function (t) { return t.state === 'expired'; }).length;
  // Read before the markup is assembled rather than inside it, because it is also
  // one of the keys of the JSON view below and reading it twice could show a page
  // and a JSON body that disagree about a directory another request just changed.
  const directory = ldapObjectSection(row, key);

  // Five lists on one page, each with its own page parameter and all of them sharing
  // `per` — see pagingOf() for why it is that way round.
  //
  // What is deliberately NOT paged here: the names this identity has been seen under,
  // the protocols it authenticated through, and the authentication events. The first
  // two are bounded by how many spellings and protocols exist, and the third is
  // capped at stats.MAX_EVENTS_PER_USER — fifty — by the registry itself, which is
  // the note authenticationTable() already prints. Paging a list that cannot exceed
  // fifty would buy a control nobody will see, and it would cost something real: all
  // three live on `row`, which goes out whole as this reply's `user`, so slicing them
  // for the table would either corrupt that object or duplicate it, and leaving the
  // JSON whole while the table paged is the console-and-API disagreement this file
  // keeps warning about.
  const sessionPage = pagedRows(req.query, sessionRows,
    { name: 'sessions', noun: 'sessions', defaultPer: DEFAULT_BLOCKS_PER_PAGE });
  const sessionsNav = pageNav('/admin/users', params, sessionPage.paging);
  // The token paging of each session that is on this page of sessions, kept beside
  // the block rather than recomputed for the JSON below: two calls with the same
  // arguments would be two chances for the page and the reply to disagree about
  // which tokens a reader is looking at.
  const sessionTokenPages = sessionPage.shown.map(function (session) {
    return pagedRows(req.query, split.held[session.id] || [],
                     { name: 'session-' + session.id, noun: 'tokens' });
  });
  const sessionBlocks = sessionPage.shown.map(function (session, index) {
    return sessionBlock(session, sessionTokenPages[index], back, params);
  }).join('');

  // ONE NAME PER LIST, and it is the name the reply's array carries: the parameter is
  // `<array>Page` and the paging object beside it is `<array>Paging`. Shortening
  // these two to `endedPage` and `sessionlessPage` read better and was wrong — a
  // caller reading `tokensWithNoSession` in the reply had to be told separately that
  // the parameter moving it was called something else, which is the sort of thing a
  // document gets right and a client author never finds.
  const endedPage = pagedRows(req.query, split.ended,
                              { name: 'tokensOnEndedSessions', noun: 'tokens' });
  const endedNav = pageNav('/admin/users', params, endedPage.paging);
  const sessionlessPage = pagedRows(req.query, split.sessionless,
                                    { name: 'tokensWithNoSession', noun: 'tokens' });
  const sessionlessNav = pageNav('/admin/users', params, sessionlessPage.paging);
  const artifactPage = pagedRows(req.query, detail.artifacts,
                                 { name: 'artifacts', noun: 'artifacts' });
  const artifactNav = pageNav('/admin/users', params, artifactPage.paging);

  const inner = messagesOf(req) +
    '<div class="tiles">' +
      tile(row.authentications, 'authentications') +
      tile(row.protocols.length, 'protocols') +
      tile(live.length, 'active sessions') +
      tile(detail.tokens.length, 'tokens issued') +
      tile(valid, 'tokens still valid') +
      tile(expired, 'tokens expired') +
      tile(detail.artifacts.length, 'assertions, tickets, credentials') +
    '</div>' +
    '<p class="note">Everything below is about the identity <code>' + esc(row.name) + '</code>, ' +
    'which is <a href="/admin/users">one row of the users list</a>. ' +
    (row.authenticated
      ? 'They have presented a credential to this service ' + row.authentications + ' time(s).'
      : '<strong>They have never authenticated here.</strong> This identity is known only because ' +
        'something was issued naming them as its subject — an exchanged token from another issuer, ' +
        'a WS-Trust <code>OnBehalfOf</code>, or a Kerberos S4U request made by a service. Nothing ' +
        'about this row says the person was ever present.') +
    (row.isClient
      ? ' <strong>This is a client, not a person</strong>: it appears here because ' +
        '<code>client_credentials</code> produces tokens with a subject and no human behind them.'
      : '') + '</p>' +

    '<h2>Names this identity has been seen under</h2>' +
    '<p class="note">One person reaches this service under several spellings and they are the same ' +
    'row here — see the note at the top of the users list for what that costs.</p>' +
    '<table><tr><th>As presented</th><th class="num">Times</th></tr>' +
    (row.forms.map(function (form) {
      return '<tr><td><code>' + esc(form.form) + '</code></td><td class="num">' + form.count + '</td></tr>';
    }).join('') || '<tr><td colspan="2">—</td></tr>') + '</table>' +
    (row.realms.length
      ? '<p class="note">Kerberos realm(s): ' +
        codeList(row.realms.map(function (r) { return r.realm; })) + '.</p>'
      : '') +

    '<h2>How they authenticated</h2>' +
    '<table><tr><th>Protocol</th><th class="num">Times</th><th>Methods</th><th>Last</th></tr>' +
    (row.protocols.map(function (family) {
      return '<tr><td>' + esc(family.protocol) + '</td>' +
        '<td class="num">' + family.count + '</td>' +
        '<td>' + esc(family.methods.map(function (m) {
          return m.method + ' ×' + m.count;
        }).join('; ')) + '</td>' +
        '<td>' + esc(whenText(family.lastAt)) + '</td></tr>';
    }).join('') || '<tr><td colspan="4">Never, here.</td></tr>') + '</table>' +
    authenticationTable(row) +

    perPageForm('/admin/users', 'user', key, artifactPage.paging.perPage,
                'The session BLOCKS below start at ' + DEFAULT_BLOCKS_PER_PAGE +
                ' rather than ' + DEFAULT_PER_PAGE + ', because each of them is ' +
                'itself a table; setting a size here applies to those too.',
                filterOnly(listViewOf('/admin/users', req.query))) +

    '<h2>Sessions, and what was issued on each</h2>' +
    '<p class="note">A <strong>sign-on session</strong> is a browser holding the ' +
    '<code>sts_mock_session</code> cookie, shared between the OAuth 2.0 / OIDC login screen and ' +
    'WS-Federation. A token is placed under a session because the issuance said so — no token ' +
    'this service issues carries a session identifier, and OIDC\'s <code>sid</code> claim is for ' +
    'front-channel logout, so inventing one to make this page easier would change what every ' +
    'client receives. The link is recorded out of band at issuance instead, and it survives a ' +
    'refresh: a refreshed token is looked up by the refresh token\'s <code>jti</code> and lands ' +
    'under the same session.</p>' +
    sessionsNav +
    (sessionBlocks || '<p class="note">This user holds no sign-on session. That is the normal state ' +
      'for every identity that never used a browser here — a password grant, a Kerberos client, a ' +
      'WS-Trust requester — and for anyone whose session has expired and been swept.</p>') +
    sessionsNav +

    (split.ended.length
      ? '<h3>Issued on a session that has since ended</h3>' +
        '<p class="note">These name a session this service no longer holds. It is not an error and ' +
        'it is the ordinary end state: the session expired or was signed out, and the tokens it ' +
        'produced outlived it — which is exactly the position a client is in when its access token ' +
        'still verifies and the browser would be asked to sign in again.</p>' +
        endedNav + userTokenTable(endedPage.shown, back, '') + endedNav
      : '') +

    (split.sessionless.length
      ? '<h3>Issued with no browser session at all</h3>' +
        '<p class="note">The grants that never involve a browser: <code>password</code>, ' +
        '<code>client_credentials</code>, OID4VCI\'s pre-authorized code, and token exchange. The ' +
        'Grant column says which. An empty Grant means the token was minted somewhere that states ' +
        'nothing about how — WS-Trust\'s JWT and the credential issuer both sign directly.</p>' +
        sessionlessNav + userTokenTable(sessionlessPage.shown, back, '') + sessionlessNav
      : '') +

    '<h2>Assertions, tickets and credentials</h2>' +
    '<p class="note">None of these can be revoked here and the console does not pretend otherwise: ' +
    'nothing consults this service about a SAML assertion, a Kerberos ticket or a credential, so a ' +
    'button would change a number on this page and nothing at all out there. The only distinction ' +
    'is whether the validity window has closed.</p>' +
    artifactNav + userArtifactTable(artifactPage.shown) + artifactNav +

    directory.html +

    '<h2>Invalidate everything for this user</h2>' +
    '<p class="note">Every access token, ID Token and refresh token held for this identity under ' +
    'any of its spellings, revoked through the same set <code>/oauth2/revoke</code> writes to. ' +
    'Assertions and tickets are untouched, for the reason above.</p>' +
    '<form method="post" action="/admin/tokens">' +
      '<input type="hidden" name="action" value="revoke-user">' +
      '<input type="hidden" name="user" value="' + esc(key) + '">' +
      '<input type="hidden" name="from" value="users">' +
      '<input type="hidden" name="back" value="' + esc(back) + '">' +
      '<div class="formrow"><button class="danger">Revoke everything for ' + esc(row.name) +
      '</button></div></form>';

  log.debug("Leaving userDetailPage(). " + sessionPage.shown.length + " session(s), " +
            artifactPage.shown.length + " artifact(s) shown of " + detail.tokens.length +
            " token(s) held.");
  return {
    inner: inner,
    json: {
      user: row,
      // Every array here is THE PAGE, not the whole list, exactly as `users` is on
      // the list view — and every one of them is answered by a `*Paging` object
      // carrying the same member names one level down, so a caller walks a
      // drill-down's five lists the way it already walks the three flat ones. A
      // session's own tokens are paged too and its paging travels with it, because
      // there is one such list per session and no top-level place to put five of
      // them that would still say which was which.
      sessions: sessionPage.shown.map(function (session, index) {
        return Object.assign({}, session, {
          tokens: sessionTokenPages[index].shown,
          tokensPaging: pagingJson(sessionTokenPages[index].paging)
        });
      }),
      sessionsPaging: pagingJson(sessionPage.paging),
      tokensOnEndedSessions: endedPage.shown,
      tokensOnEndedSessionsPaging: pagingJson(endedPage.paging),
      tokensWithNoSession: sessionlessPage.shown,
      tokensWithNoSessionPaging: pagingJson(sessionlessPage.paging),
      artifacts: artifactPage.shown,
      artifactsPaging: pagingJson(artifactPage.paging),
      // null when no directory is loaded in this process, which is a different
      // answer from an entry that is not there — that one is an object whose
      // `found` is false and which says where it would have been.
      ldap: directory.json
    }
  };
}

// The list. Filtered by a name fragment and by protocol, and paged with the same
// controls the tokens page uses.
function usersListPage(req) {
  log.debug("Entering usersListPage().");
  const wantedText = String(req.query.q || '').trim();
  const wantedProtocol = String(req.query.protocol || '');
  const all = stats.userRows();
  // Every protocol any known user authenticated through, for the filter. Read off the
  // data rather than written down, so a protocol that starts recording authentications
  // appears in the dropdown by itself and one that never has cannot offer a filter
  // that matches nothing.
  const protocolsSeen = {};
  all.forEach(function (row) {
    row.protocols.forEach(function (family) { protocolsSeen[family.protocol] = true; });
  });
  const filtered = all.filter(function (row) {
    if (wantedText && row.key.toLowerCase().indexOf(wantedText.toLowerCase()) < 0) return false;
    if (wantedProtocol && !row.protocols.some(function (f) { return f.protocol === wantedProtocol; })) {
      return false;
    }
    return true;
  });
  const paging = pagingOf(req.query, filtered.length);
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  const filterParams = { q: wantedText, protocol: wantedProtocol,
                         per: req.query.per ? paging.perPage : '' };
  const nav = pageNav('/admin/users', filterParams, paging);

  // Sessions are counted per user here rather than fetched per row inside the loop:
  // one pass over the session map instead of one per user, and more importantly one
  // definition of "active" for the list and the drill-down both.
  const liveByUser = {};
  signOnSessionRows().forEach(function (session) {
    if (session.expired) return;
    const key = stats.identityKeyOf(session.username || session.sub);
    liveByUser[key] = (liveByUser[key] || 0) + 1;
  });

  const listView = listViewOf('/admin/users', req.query);
  const rows = shown.map(function (row) {
    // The link carries the list AS IT IS BEING VIEWED, which is what lets the
    // trail on the other side come back to this page of this filter rather than to
    // the top of everything. See listViewOf().
    const href = '/admin/users' + queryWith(listView, { user: row.key });
    // Shortened for the same reason the metrics page's Who column is, and the
    // Decentralized Identity endpoints are what made it reach this table too: a
    // did:jwk is a couple of hundred characters of base64url with not one place
    // in it a browser will break a line, so drawn in full it sets this cell's
    // minimum width and pushes every column after it off the card — including
    // the rows of people whose names are three letters long. 40 keeps
    // `urn:sts-mock:user:alice` and an ordinary DID whole; shortened() puts the
    // rest in the title attribute, so nothing is lost, only hidden.
    return '<tr><td><a href="' + esc(href) + '">' + shortened(row.name, 40) + '</a></td>' +
      '<td>' + (row.isClient ? 'client' : 'user') + '</td>' +
      '<td class="' + (row.authenticated ? 'state-valid' : 'state-none') + '">' +
        (row.authenticated ? row.authentications + '&times;' : 'never') + '</td>' +
      '<td>' + esc(row.protocols.map(function (f) { return f.protocol; }).join(', ') || '—') + '</td>' +
      '<td>' + esc(row.realms.map(function (r) { return r.realm; }).join(', ') || '—') + '</td>' +
      '<td class="num">' + (liveByUser[row.key] || 0) + '</td>' +
      '<td class="num">' + row.tokens.issued + '</td>' +
      '<td class="num state-valid">' + row.tokens.valid + '</td>' +
      // EXPIRED IS ITS OWN COLUMN. It was counted in userRows() and shown
      // nowhere, so this table drew "12 issued, 1 valid" and left the other
      // eleven to be read as revoked, forgotten or broken. They are none of
      // those: a token whose lifetime ran out is the ordinary end of a token,
      // and it is the specific thing somebody comes to this page to check
      // after a client started being refused. Same clock as everywhere else —
      // tokenStateOf(), which applies oauth2.clockSkewS.
      '<td class="num state-expired">' + row.tokens.expired + '</td>' +
      '<td class="num state-revoked">' + row.tokens.revoked + '</td>' +
      '<td class="num">' + row.artifacts + '</td>' +
      '<td>' + esc(row.firstAt ? whenText(row.firstAt) : '—') + '</td>' +
      '<td>' + esc(whenText(row.lastActivityAt)) + '</td>' +
      '<td><a href="' + esc(href) + '">sessions and tokens &rsaquo;</a></td></tr>';
  }).join('');

  const protocolOptions = [''].concat(Object.keys(protocolsSeen).sort()).map(function (p) {
    return '<option value="' + esc(p) + '"' + (p === wantedProtocol ? ' selected' : '') + '>' +
           esc(p || 'any protocol') + '</option>';
  }).join('');
  const perOptions = perPageOptions(paging.perPage);

  const authenticatedHere = all.filter(function (row) { return row.authenticated; }).length;
  const inner = messagesOf(req) +
    '<div class="tiles">' +
      tile(all.length, 'identities known') +
      tile(authenticatedHere, 'authenticated here') +
      tile(all.length - authenticatedHere, 'seen only as a subject') +
      tile(all.filter(function (row) { return row.isClient; }).length, 'clients, not people') +
      tile(Object.keys(liveByUser).length, 'with an active session') +
    '</div>' +
    '<p class="note">Every userid this service has been given as part of an interaction that ' +
    'succeeded — the name typed at either sign-in screen, the one on a password grant, the subject ' +
    'of a WS-Security <code>UsernameToken</code>, the client principal in a Kerberos AS-REQ or an ' +
    'accepted AP-REQ, and the subject of an exchanged token. A request that was REFUSED records ' +
    'nothing, so this is a list of identities that got somewhere rather than of names that were ' +
    'tried. Click a name for its sessions and everything issued to it.</p>' +
    // WHERE AN ISSUED SPIFFE IDENTITY LANDS ON THIS TABLE, said here because
    // the row it produces is easy to misread. It has an artifact and NO
    // authentication, so it falls in the "seen only as a subject" tile above —
    // which is exactly right and is what that tile has always been for.
    // Counting an issuance as a sign-in would be the wrong answer twice over:
    // receiving a credential is not presenting one, and an agent holding
    // FetchX509SVID open re-mints every half-lifetime, so one workload left
    // running overnight would read as several hundred authentications.
    '<p class="note"><strong>An identity this trust domain has only ISSUED a ' +
    'certificate to is here with <em>never</em> in the Authenticated column' +
    '</strong> &mdash; it counts under &ldquo;seen only as a subject&rdquo;. ' +
    'Being issued a credential is not presenting one, and an agent re-mints ' +
    'every half-hour, so counting issuances would turn one workload into ' +
    'hundreds of sign-ins. It also gets a directory entry under ' +
    '<code>ou=users</code> carrying the certificate it currently holds &mdash; ' +
    'see <a href="/ldap/directory">the directory</a> and ' +
    '<a href="/admin/spiffe">SPIFFE</a>.</p>' +
    '<div class="warn"><strong>One row is one local name, across every protocol.</strong> The same ' +
    'person arrives here as <code>alice</code> at the login screen, ' +
    '<code>urn:sts-mock:user:alice</code> in every token and <code>alice@STS.MOCK</code> as a ' +
    'Kerberos principal, and showing three rows for that would be a worse answer than one — the ' +
    'premise of this service is that the name you type is who you are in every protocol at once. ' +
    'What it costs: two different people called <code>alice</code> in two Kerberos realms are one ' +
    'row here. The Realms column is what makes that visible. Case is never collapsed, because ' +
    'nothing in this service treats <code>Alice</code> and <code>alice</code> as one.</div>' +

    '<form method="get" action="/admin/users"><div class="formrow">' +
      '<label for="q">Name contains</label>' +
      '<input type="text" id="q" name="q" size="20" value="' + esc(wantedText) + '">' +
      '<label for="protocol">Authenticated through</label>' +
      '<select id="protocol" name="protocol">' + protocolOptions + '</select>' +
      '<label for="per">Per page</label><select id="per" name="per">' + perOptions + '</select>' +
      '<button class="secondary">Filter</button>' +
      (wantedText || wantedProtocol ? ' <a href="/admin/users">clear</a>' : '') +
    '</div></form>' +

    // The one control on this page. It writes to the DIRECTORY and not to the
    // table below it, which the note says outright — see usersAction() for why
    // that sentence is not optional. The `back` field carries the filter and
    // page so that creating somebody does not throw the reader back to the top
    // of an unfiltered list; the handler rebuilds it through the whitelist
    // rather than echoing it.
    '<form method="post" action="/admin/users">' +
      '<input type="hidden" name="action" value="create">' +
      '<input type="hidden" name="back" value="' + esc(queryWith(listView, {})) + '">' +
      '<div class="formrow">' +
        '<label for="new-username">Create a user</label>' +
        '<input type="text" id="new-username" name="username" size="20" ' +
               'placeholder="username" required>' +
        '<button>Create</button>' +
      '</div>' +
      '<p class="note">Puts an entry in the embedded LDAP directory at ' +
      // THE REALM'S OWN CONTAINER, ASKED FOR RATHER THAN BUILT HERE. This read
      // `ou=users,` + config.value('ldap.baseDn') until 2026-08-25, which is
      // the NAMING CONTEXT and is the default realm's container only: under
      // /realm/acme the page named a DN in a different realm than the one the
      // button writes to, and named it on the very control whose whole subject
      // is where the entry goes. `ldap_server.js` answers the question for the
      // ambient realm, and the fallback is the old string for the build with no
      // directory loaded, where the slot is empty and there is no realm to ask
      // about anyway.
      '<code>uid=&lt;name&gt;,' + esc(newUserContainer()) + '</code>, with the invented person ' +
      'behind that name written onto it, so an issued credential and an ' +
      '<code>ldapsearch</code> agree from the start. <strong>One entry per person:</strong> a ' +
      'name that is already here is refused, whichever protocol brought them and whatever ' +
      'attribute their entry is named by — the same refusal an <code>ldapadd</code> and ' +
      '<code>POST /admin-api/users/create</code> get, because all three call one function. ' +
      'The new user will not appear in the table below until they authenticate somewhere: that ' +
      'is who this service has SEEN, and this is what the directory HOLDS. No password is set, ' +
      'because none is ever checked.</p>' +
    '</form>' +
    nav +
    '<table><tr><th>User</th><th>Kind</th><th>Authenticated</th><th>Protocols</th><th>Realms</th>' +
    '<th class="num">Sessions</th><th class="num">Tokens</th><th class="num">Valid</th>' +
    '<th class="num">Expired</th>' +
    '<th class="num">Revoked</th><th class="num">Artifacts</th><th>First seen</th>' +
    '<th>Last activity</th><th></th></tr>' +
    (rows || '<tr><td colspan="14">Nobody matches. Nothing has authenticated here yet unless a ' +
             'filter above is hiding it.</td></tr>') + '</table>' +
    nav +
    '<p class="note">' + filtered.length + ' identit' + (filtered.length === 1 ? 'y' : 'ies') +
    ' match; ' + all.length + ' known in total, most recently active first. An identity marked ' +
    '<em>never</em> under Authenticated has been issued something without ever presenting a ' +
    'credential here: an exchanged token from another issuer, a WS-Trust <code>OnBehalfOf</code>, ' +
    'or a Kerberos S4U request that a service made in their name. Listing them is the point — a ' +
    'users page that showed only the sign-ins would deny the existence of subjects the tokens ' +
    'page is showing at the same moment.</p>' +
    '<p class="note">All of it is in memory and dies with the process, and the registry holds the ' +
    'most recent ' + stats.MAX_USERS + ' identities.' +
    '</p>';

  log.debug("Leaving usersListPage(). " + shown.length + " row(s) drawn.");
  return {
    inner: inner,
    json: {
      known: all.length, matched: filtered.length, shown: shown.length,
      authenticatedHere: authenticatedHere,
      filter: { q: wantedText || null, protocol: wantedProtocol || null },
      protocols: Object.keys(protocolsSeen).sort(),
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      users: shown
    }
  };
}

// ---------------------------------------------------------------------------
// THE ONE THING THIS PAGE CAN CHANGE.
//
// Everything else on /admin/users is a report: who has authenticated, what they
// were issued, what the directory holds about them. This creates a person in the
// directory, and it is here rather than on /admin/groups or /ldap because this is
// the page a reader is on when they discover that somebody is missing.
//
// IT DECIDES NOTHING. Every rule about what a username may be, and the refusal
// of one that already exists, is in ldap_server.js's createUser() — reached
// through the slot above. This function reads the form and phrases the answer,
// which is the same split /admin/applications keeps with applications.js and the
// reason POST /admin-api/users/create can call straight into this without a
// second reading of any of it.
//
// WHAT IT DOES NOT DO is make the person appear in the list on this page. That
// list is identities this service has SEEN authenticate; the entry is in the
// DIRECTORY. The two are different questions — it is the same distinction
// /admin/groups draws when it marks a member "never here" — and the message says
// so outright, because an operator who created a user and could not find them in
// the table above would reasonably conclude the button was broken.
// ---------------------------------------------------------------------------
function usersAction(body) {
  log.debug("Entering usersAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');

  if (action === 'create') {
    if (!directoryWriter) {
      log.debug("Leaving usersAction(). No directory is loaded.");
      return { ok: false, errors: ['No LDAP directory is loaded in this process, so there is ' +
                                   'nowhere to put a person. The rest of this page is ' +
                                   'unaffected — it reports what this service has seen, which ' +
                                   'does not come from the directory.'] };
    }
    const username = String(body.username || body.user || '').trim();
    const result = directoryWriter(username, {
      origin: 'console',
      note: String(body.note || '').trim() ||
            'created by hand on the admin console rather than by authenticating',
      channel: 'console'
    });
    if (!result.ok) {
      log.debug("Leaving usersAction(). create refused.");
      return result;
    }
    log.debug("Leaving usersAction(). Created " + result.dn + ".");
    return { ok: true, dn: result.dn, username: result.username, entry: result.entry,
             message: result.dn + ' now exists in the directory, with the invented person ' +
                      'behind that name written onto it — so a credential issued for ' +
                      result.username + ' and an ldapsearch for that entry say the same ' +
                      'thing. They will NOT appear in the table on this page until they ' +
                      'authenticate somewhere: this list is who this service has seen, and ' +
                      'the entry is what the directory holds. Nothing here checks a ' +
                      'password, so there is none to set.' };
  }

  log.debug("Leaving usersAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". There is one: create.'] };
}

// One route, three answers, and the choice between them is here rather than in
// the route so that /admin-api/users makes the same one. `known: false` is the
// third and it is not a 404 — see the comment inside it.
// WHERE A USER CREATED ON THIS PAGE LANDS, in the realm the page is being read
// in. `directoryReader('')` is the same slot the drill-down uses, asked with no
// name: it answers about the DIRECTORY rather than about a person, which is
// what a note above an empty form has to do.
function newUserContainer() {
  log.debug("Entering newUserContainer().");
  if (!directoryReader) {
    log.debug("Leaving newUserContainer(). No directory is loaded.");
    return 'ou=users,' + config.value('ldap.baseDn');
  }
  const info = directoryReader('');
  log.debug("Leaving newUserContainer(). " + info.usersDn);
  return info.usersDn;
}

function usersView(req) {
  log.debug("Entering usersView().");
  const wantedUser = String(req.query.user || '').trim();
  if (wantedUser) {
    const detail = userDetailPage(req, wantedUser);
    if (!detail) {
      // Not a 404: this service has simply never seen the name, or has forgotten it
      // to the cap since the link was drawn. Both are answers rather than errors, and
      // a 404 here would send a test looking for a routing problem.
      const inner = messagesOf(req) +
        '<p class="note">Nothing here has authenticated as <code>' + esc(wantedUser) + '</code>, ' +
        'and nothing has been issued naming them. Either the name is not one this service has ' +
        'seen, or it has been forgotten — the registry holds the most recent ' + stats.MAX_USERS +
        ' identities, and everything in it dies with the process.</p>' +
        // The same href the trail's section crumb carries, so the two ways back off
        // this page cannot land in different places.
        '<p class="note"><a href="' +
        esc('/admin/users' + queryWith(listViewOf('/admin/users', req.query), {})) +
        '">Back to the list</a>.</p>';
      log.debug("Leaving usersView(). No such user.");
      return { json: { user: wantedUser, known: false }, inner: inner,
               title: 'User',
               up: upTo('/admin/users', wantedUser, listViewOf('/admin/users', req.query)) };
    }
    log.debug("Leaving usersView(). The drill-down.");
    return { json: Object.assign({ known: true }, detail.json),
             inner: detail.inner, title: 'User ' + wantedUser,
             up: upTo('/admin/users', wantedUser,
                      listViewOf('/admin/users', req.query)) };
  }
  const list = usersListPage(req);
  log.debug("Leaving usersView(). The list.");
  return { json: list.json, inner: list.inner, title: 'Users' };
}

app.get('/admin/users', function (req, res) {
  log.debug("Entering the admin users page.");
  const view = usersView(req);
  respond(req, res, view.json, view.title, '/admin/users', view.inner, view.up);
  log.debug("Leaving the admin users page. " + view.title + ".");
});

app.post('/admin/users', function (req, res) {
  log.debug("Entering the admin users action endpoint.");
  const body = parseBody(req);
  const result = usersAction(body);
  // Back to the list carrying whatever filter and page the form came from, so
  // that creating somebody does not cost the reader their place — the rule every
  // form on this console follows.
  const back = '/admin/users' + queryWith(listViewFromBack('/admin/users', body.back), {});
  respondToAction(req, res, back, result);
  log.debug("Leaving the admin users action endpoint.");
});

// ---------------------------------------------------------------------------
// GET /admin/groups — every group in the embedded directory, and one of them in
// full.
//
// The one page in this console whose whole content comes from another module.
// Everything else here reads admin_stats.js; this reads the directory through
// the slot ldap_server.js fills, and it renders exactly what that returns
// without deciding anything — including what counts as a group, which is that
// module's rule and is stated on the page rather than reimplemented here.
//
// A GROUP IS NOT AN AUTHORISATION HERE, and the page says so where a reader will
// see it. Nothing in this service reads these groups: no token carries them, no
// SAML assertion has them as an attribute, no endpoint checks one. They are a
// directory's objects for a directory client to read, and a console that listed
// them beside the tokens page without saying that would let somebody conclude
// that adding a user to `cn=directory-admins` changed what their token could do.
// ---------------------------------------------------------------------------

// The heading a group's link carries, and the fallback when it has no cn — an
// entry can be a group by placement alone, and `(no cn)` is a truer label than an
// empty cell that reads as a rendering fault.
function groupLabel(group) {
  return group.cn || '(no cn)';
}

// Why this entry counted as a group, in words. The rule is ldap_server.js's; this
// is only its three values spelled out, and it is on the page because "developers
// is a group" is uninteresting next to "this entry is a group because somebody put
// it under ou=groups and it carries no group objectClass at all".
const GROUP_RULES = {
  both: { label: 'placement + objectClass',
          title: 'It is under ou=groups AND carries a group objectClass. This is what a group ' +
                 'written the conventional way looks like.' },
  placement: { label: 'placement only',
               title: 'It is under ou=groups but carries no group objectClass. This directory ' +
                      'is schemaless, so nothing refused the add — it is listed here because ' +
                      'of where it sits.' },
  objectClass: { label: 'objectClass only',
                 title: 'It carries a group objectClass but sits outside ou=groups. Nothing ' +
                        'here requires a group to live under the groups container.' }
};

function groupRuleCell(rule) {
  const rendered = GROUP_RULES[rule];
  if (!rendered) {
    return '<span class="state-none">' + esc(rule || 'unstated') + '</span>';
  }
  return '<span title="' + esc(rendered.title) + '">' + esc(rendered.label) + '</span>';
}

// THE TWO LISTS ARE DIFFERENT QUESTIONS, and this is where that shows.
//
// The directory holds an entry for anybody somebody wrote one for — the three it
// seeds at startup, and whatever a client has added since. The users page holds
// everybody who has actually presented a credential to this service. `alice` is
// in the directory from the moment the process starts and is on the users page
// only once somebody signs in as her, so a member row that always linked there
// would usually land on "nothing here has authenticated as alice", which reads
// as a broken link rather than as the fact it is.
//
// So the console's own user registry is consulted, and a member it does not know
// is named without a link and with the reason. Reading it once per page rather
// than once per row is deliberate: userRows() walks the whole registry.
function knownUserKeys() {
  const known = {};
  stats.userRows().forEach(function (row) {
    known[row.key] = true;
  });
  return known;
}

// A member's link. To the group page when the member is itself a group, so
// nesting can be walked; to the users page when this console has actually seen
// that person authenticate. Neither, and the DN stands on its own — which is the
// commonest case in a directory nobody has signed in to yet.
function memberLink(member, known) {
  const label = '<code>' + esc(member.dn) + '</code>';
  if (member.kind === 'group') {
    return '<a href="' + esc('/admin/groups' + queryWith({ group: member.dn }, {})) +
      '">' + label + '</a>';
  }
  if (member.userKey && known[member.userKey]) {
    return '<a href="' + esc('/admin/users' + queryWith({ user: member.userKey }, {})) +
      '">' + label + '</a>';
  }
  return label;
}

// The "On the users page" cell, for a member and for a memberOf claimant alike.
// Three states and they are all worth telling apart: a name this console has seen
// authenticate, a name it could file somebody under but never has, and an entry
// named in a way that yields no user name at all.
function usersPageCell(userKey, known) {
  if (!userKey) {
    return '<span class="state-none" title="This entry is not named uid=&lt;name&gt; and carries ' +
      'no uid, so there is no name to look it up by. The console files people under the local ' +
      'name userFor() derives; an entry named some other way — a cn=, or the one a TLS client ' +
      'certificate seeds — has none.">—</span>';
  }
  if (!known[userKey]) {
    return '<span class="state-none" title="The directory holds an entry for them and nothing ' +
      'has authenticated as this name in this process, so the users page has no row to link to. ' +
      'The two lists answer different questions: the directory is what somebody wrote into it, ' +
      'the users page is who has actually presented a credential here.">' + esc(userKey) +
      ' <em>(never here)</em></span>';
  }
  return '<a href="' + esc('/admin/users' + queryWith({ user: userKey }, {})) + '">' +
    esc(userKey) + '</a>';
}

// What this directory's groups are and are not, said on both pages. Repeated
// rather than shown once on the list, for the reason the open-console banner is
// repeated: the page somebody arrives at directly is exactly the one that needs it.
// It used to say the two halves as one sentence — nothing reads a group AND no
// token carries one — and the second half stopped being true when the groups
// claim was added. They are split now, in that order, because the one a reader
// most needs is still the first: CARRYING a fact and ACTING on it are different
// claims, and this is the same line this service already draws between an
// identity being recorded and an identity being authenticated.
const GROUPS_CAVEAT =
  '<p class="note"><strong>A group here grants nothing, with exactly two exceptions and they ' +
  'are named below.</strong> No <em>endpoint</em> in this service checks a group, and nothing ' +
  'in any protocol decides anything on one. Adding somebody to ' +
  '<code>cn=directory-admins</code> changes what a directory client sees, and what a token ' +
  '<em>says</em>, and changes nothing at all about what that token can DO &mdash; on a service ' +
  'that authenticates nobody, it could hardly be otherwise.</p>' +
  // THE EXCEPTION, said HERE and not only on the page that owns it. A reader
  // meeting this caveat on the groups page and then finding cn=admin-write in
  // the table above it would be entitled to conclude that one of the two was
  // lying. The general claim is still the one that matters — it is true of every
  // group but these two, and true of these two everywhere except one console —
  // so it is qualified rather than dropped.
  '<p class="note"><strong>The two exceptions are <code>' +
  esc(config.value('admin.readGroup')) + '</code> and <code>' +
  esc(config.value('admin.writeGroup')) + '</code>, which decide who may use THIS CONSOLE</strong> ' +
  '&mdash; see <a href="/admin/rbac">Admin roles</a>, where they are granted and taken away. ' +
  'They are ordinary groups and appear in the table above like any other, deliberately: the ' +
  'alternative was a membership store of the console\'s own that an <code>ldapmodify</code> ' +
  'could not see. Even those two grant nothing outside <code>/admin</code> &mdash; no token, ' +
  'assertion, ticket, PAC or credential is changed by being in one, and every protocol endpoint ' +
  'answers a member exactly as it answers anybody else.</p>' +
  '<p class="note"><strong>A token can now carry one.</strong> With ' +
  '<code>groups.claim</code> on &mdash; it is on by default &mdash; every OAuth 2.0 access ' +
  'token, OIDC ID Token, SAML 2.0 assertion and SAML 1.1 assertion this service issues carries ' +
  'a claim naming the groups its subject is in, read from these entries at the moment it is ' +
  'minted. Somebody in no group gets no claim at all rather than an empty list. What it is ' +
  'called, whether each value is a <code>cn</code> or a whole DN, and whether a person\'s own ' +
  '<code>memberOf</code> counts are on <a href="/admin/config">the configuration page</a>; ' +
  '<a href="/admin/claims">the claims page</a> shows what it would say about one person. No ' +
  'Kerberos PAC and no WS-Federation-specific token carries a group either way.</p>';

function noGroupDirectorySection() {
  return '<p class="note">No LDAP directory is loaded in this process, so there are no groups to ' +
    'show. That is a build of this service without <code>ldap_server.js</code> and not a failure ' +
    '&mdash; every other page of this console is unaffected.</p>';
}

const GROUPS_LINKS =
  '<p class="note"><a href="/ldap">What this directory is</a> &middot; ' +
  '<a href="/ldap/directory">every entry in it</a> &middot; ' +
  '<a href="/ldap/directory?format=json">the same as JSON</a> &middot; ' +
  '<a href="/admin/users">the people who have authenticated here</a>.</p>';

// The list.
function groupsListPage(req) {
  log.debug("Entering groupsListPage().");
  const info = groupReader('');
  const wantedText = String(req.query.q || '').trim();
  const needle = wantedText.toLowerCase();
  const filtered = info.groups.filter(function (group) {
    if (!needle) {
      return true;
    }
    // The DN and the cn both, because a person looking for a group has one or the
    // other in mind and which one depends on whether they came from an LDAP client
    // or from this console.
    return group.dn.toLowerCase().indexOf(needle) >= 0 ||
           String(group.cn).toLowerCase().indexOf(needle) >= 0;
  });
  const paging = pagingOf(req.query, filtered.length);
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  const filterParams = { q: wantedText || '',
                         per: req.query.per ? paging.perPage : '' };
  const nav = pageNav('/admin/groups', filterParams, paging);

  const listView = listViewOf('/admin/groups', req.query);
  const rows = shown.map(function (group) {
    // The link carries the list AS IT IS BEING VIEWED, which is what lets the
    // trail on the other side come back to this page of this filter rather than to
    // the top of everything. See listViewOf().
    const href = '/admin/groups' + queryWith(listView, { group: group.dn });
    return '<tr><td><a href="' + esc(href) + '">' + esc(groupLabel(group)) + '</a></td>' +
      '<td class="who"><code>' + esc(group.dn) + '</code></td>' +
      '<td>' + groupRuleCell(group.rule) + '</td>' +
      '<td class="num">' + group.memberCount + '</td>' +
      '<td class="num">' + (group.presentCount
        ? '<span class="state-valid">' + group.presentCount + '</span>'
        : '<span class="state-none">0</span>') + '</td>' +
      '<td class="num">' + (group.danglingCount
        ? '<span class="state-revoked" title="Membership values naming an entry this directory ' +
          'does not hold. Deleting a user does not remove it from the groups that list it — ' +
          'referential integrity is a directory feature and not a protocol rule, and this ' +
          'directory deliberately does not have it.">' + group.danglingCount + '</span>'
        : '<span class="state-none">0</span>') + '</td>' +
      '<td class="num">' + (group.claimedCount
        ? '<span class="state-expired" title="Entries whose own memberOf names this group and ' +
          'which this group does not list back. Nothing here maintains memberOf, so a client ' +
          'that writes it creates exactly this disagreement.">' + group.claimedCount + '</span>'
        : '<span class="state-none">0</span>') + '</td>' +
      '<td class="num">' + group.attributeCount + '</td>' +
      '<td>' + esc(group.origin) + '</td>' +
      '<td><code>' + esc(group.modifiedAt) + '</code></td></tr>';
  }).join('');

  const totalMembers = info.groups.reduce(function (n, g) { return n + g.memberCount; }, 0);
  const totalDangling = info.groups.reduce(function (n, g) { return n + g.danglingCount; }, 0);

  const inner = messagesOf(req) +
    directoryListenerWarning(info, GROUPS_SUBJECT) +
    '<div class="tiles">' +
    tile(info.groupCount, 'Groups') +
    tile(totalMembers, 'Membership values') +
    tile(totalDangling, 'Dangling') +
    tile(info.entryCount, 'Entries in the directory') +
    '</div>' +
    '<form method="get" action="/admin/groups"><div class="formrow">' +
    '<label for="q">Group</label>' +
    '<input type="text" id="q" name="q" value="' + esc(wantedText) + '" size="28" ' +
    'placeholder="part of a cn or a DN">' +
    '<label for="per">Per page</label>' +
    '<select id="per" name="per">' + perPageOptions(paging.perPage) + '</select>' +
    '<button type="submit">Filter</button>' +
    (wantedText ? ' <a href="/admin/groups">clear</a>' : '') +
    '</div></form>' +
    nav +
    '<table><tr><th>Group</th><th>DN</th><th>Counted because</th><th class="num">Members</th>' +
    '<th class="num">Resolve</th><th class="num">Dangling</th><th class="num">Claimed</th>' +
    '<th class="num">Attributes</th><th>Came from</th><th>Last modified</th></tr>' +
    (rows || '<tr><td colspan="10">No group matches. ' +
             (wantedText ? 'The filter above may be hiding some.' : 'This directory holds none — ' +
              'the two it seeds can be deleted through the protocol like any other entry.') +
             '</td></tr>') + '</table>' +
    nav +
    '<p class="note">A group is an entry that sits under <code>' + esc(info.groupsDn) + '</code>, ' +
    'or that carries one of the group object classes (<code>groupOfNames</code>, ' +
    '<code>groupOfUniqueNames</code>, <code>posixGroup</code>, <code>groupOfURLs</code>) wherever ' +
    'it sits &mdash; either rule is enough, and the column above says which one caught each. Both ' +
    'are applied because this directory is <strong>schemaless</strong>: nothing stops a client ' +
    'adding a <code>groupOfNames</code> under <code>' + esc(info.usersDn) + '</code>, or an entry ' +
    'with no <code>objectClass</code> at all under the groups container, and a page that applied ' +
    'only one rule would answer for one of those and quietly lose the other.</p>' +
    '<p class="note"><strong>Members</strong> counts the values of <code>member</code>, ' +
    '<code>uniqueMember</code> and <code>memberUid</code> together; <strong>Resolve</strong> is ' +
    'how many of them name an entry this directory actually holds and <strong>Dangling</strong> ' +
    'is the rest. The two are shown apart because a group whose seven members resolve to five is ' +
    'this directory doing exactly what it says it does &mdash; deleting a user leaves its DN in ' +
    'every group that listed it &mdash; and one combined number would report that as seven ' +
    'members with nothing wrong. <strong>Claimed</strong> is the disagreement in the other ' +
    'direction: entries whose own <code>memberOf</code> names the group while the group does not ' +
    'list them back.</p>' +
    GROUPS_CAVEAT + GROUPS_LINKS;

  log.debug("Leaving groupsListPage(). " + shown.length + " row(s) drawn of " +
            info.groupCount + " group(s).");
  return {
    inner: inner,
    json: {
      groupCount: info.groupCount, matched: filtered.length, shown: shown.length,
      membershipValues: totalMembers, dangling: totalDangling,
      filter: { q: wantedText || null },
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      baseDn: info.baseDn, groupsDn: info.groupsDn, usersDn: info.usersDn,
      port: info.port, listening: info.listening, listenError: info.listenError,
      ldapsPort: info.ldapsPort, ldapsListening: info.ldapsListening,
      groups: shown
    }
  };
}

// One group: every attribute it has, and everybody in it.
function groupDetailPage(req, wantedDn) {
  log.debug("Entering groupDetailPage(). dn=" + wantedDn);
  const info = groupReader(wantedDn);
  // The same href the trail's section crumb carries — see listViewOf(). Two ways
  // back off one page that land in different places is worse than one.
  const back = '<p class="note"><a href="' +
    esc('/admin/groups' + queryWith(listViewOf('/admin/groups', req.query), {})) +
    '">Back to the groups</a>.</p>';

  if (!info.found) {
    // Three ways to be here and they are different answers, so they get different
    // words. A 404 is none of them: the console linked here from a list it drew
    // from this same store, and the interesting case is precisely that the store
    // has changed since — a client can delete a group, rename it out of
    // ou=groups, or strip its objectClass through the protocol between one click
    // and the next.
    const because = info.notAGroup
      ? 'There <strong>is</strong> an entry at <code>' + esc(info.entryDn) + '</code>, and it is ' +
        'not a group: it sits outside <code>' + esc(info.groupsDn) + '</code> and carries no ' +
        'group <code>objectClass</code>. A <code>modifyDN</code> out of the groups container or ' +
        'a <code>modify</code> that deleted the <code>objectClass</code> does exactly this, and ' +
        'neither is refused &mdash; this directory has no schema. ' +
        '<a href="/ldap/directory">The full dump</a> still shows it.'
      : 'Nothing is at <code>' + esc(wantedDn) + '</code>. Either it was <code>delete</code>d or ' +
        '<code>modifyDN</code>&rsquo;d through the protocol since the link was drawn, or the DN ' +
        'was typed. DNs are compared case-folded and with the space after each comma ignored, so ' +
        'the spelling is not what is wrong.';
    log.debug("Leaving groupDetailPage(). Not a group.");
    return {
      inner: messagesOf(req) + directoryListenerWarning(info, GROUP_SUBJECT) +
        '<p class="note">' + because + '</p>' + back,
      json: Object.assign({ found: false }, info)
    };
  }

  const group = info.group;
  const known = knownUserKeys();

  // Two lists on this page and a page parameter each, sharing `per` — the same
  // arrangement the users drill-down has, and for the same reason: one `page` would
  // move both, and the two disagreements this page exists to show are read against
  // each other, so advancing the members while the claimants jumped with them would
  // be the one navigation that makes the page harder to read than no navigation.
  //
  // The counts above the tables — memberCount, presentCount, danglingCount — stay
  // counts of the WHOLE list and are read off the directory rather than off the
  // slice, because "seven members, five resolve" is the fact the page is for and
  // "five members on this page" is not an answer to it.
  const params = pageParamsOf(req.query);
  const memberPage = pagedRows(req.query, group.members, { name: 'members', noun: 'members' });
  const membersNav = pageNav('/admin/groups', params, memberPage.paging);
  const claimedPage = pagedRows(req.query, group.claimed, { name: 'claimed', noun: 'entries' });
  const claimedNav = pageNav('/admin/groups', params, claimedPage.paging);

  const memberRows = memberPage.shown.map(function (member) {
    const state = member.present
      ? '<span class="state-valid">in the directory</span>'
      : '<span class="state-revoked" title="The value names an entry this directory does not ' +
        'hold. It is shown rather than dropped: nothing here enforces referential integrity, ' +
        'so this is the state the protocol leaves behind when a member is deleted.">dangling' +
        '</span>';
    return '<tr><td class="who">' + memberLink(member, known) + '</td>' +
      '<td><code>' + esc(member.attribute) + '</code></td>' +
      '<td>' + state + '</td>' +
      '<td>' + esc(member.kind === 'group' ? 'a group' :
                   member.kind === 'entry' ? 'an entry' : '—') + '</td>' +
      '<td>' + (member.cn ? esc(member.cn) : '<span class="state-none">—</span>') + '</td>' +
      '<td>' + (member.mail ? '<code>' + esc(member.mail) + '</code>'
                            : '<span class="state-none">—</span>') + '</td>' +
      '<td>' + usersPageCell(member.userKey, known) + '</td>' +
      // The raw value, last, because for `member` and `uniqueMember` it is the DN
      // in the first column all over again — and for `memberUid` it is not, which
      // is the whole reason the column is here.
      '<td class="who"><code>' + esc(member.value) + '</code></td></tr>';
  }).join('');

  const claimedRows = claimedPage.shown.map(function (entry) {
    return '<tr><td class="who"><code>' + esc(entry.dn) + '</code></td>' +
      '<td>' + (entry.cn ? esc(entry.cn) : '<span class="state-none">—</span>') + '</td>' +
      '<td>' + (entry.mail ? '<code>' + esc(entry.mail) + '</code>'
                           : '<span class="state-none">—</span>') + '</td>' +
      '<td>' + usersPageCell(entry.userKey, known) + '</td></tr>';
  }).join('');

  const claimedSection = group.claimed.length
    ? '<h2>Entries that claim this group, and that it does not list</h2>' +
      claimedNav +
      '<table><tr><th>DN</th><th>cn</th><th>mail</th><th>On the users page</th></tr>' +
      claimedRows + '</table>' +
      claimedNav +
      '<p class="note">Each of these carries a <code>memberOf</code> naming this group while this ' +
      'group&rsquo;s own <code>member</code> does not name them back. <strong>Nothing here ' +
      'maintains <code>memberOf</code></strong> &mdash; it is not a standard attribute at all ' +
      '(Microsoft&rsquo;s directory and OpenLDAP&rsquo;s <code>memberof</code> overlay both write ' +
      'it, the server keeping it in step with <code>member</code> itself), and a schemaless mock ' +
      'that neither writes nor checks it lets a client create exactly this disagreement in one ' +
      '<code>modify</code>. They are listed apart from the members above rather than merged into ' +
      'them, because which side of the disagreement a name came from is the only interesting ' +
      'thing about it.</p>'
    : '';

  const inner = messagesOf(req) +
    directoryListenerWarning(info, GROUP_SUBJECT) +
    '<h2>' + esc(groupLabel(group)) + '</h2>' +
    '<table><tr><th>DN</th><th>Counted as a group because</th><th>Came from</th>' +
    '<th>Created</th><th>Last modified</th></tr>' +
    '<tr><td class="who"><code>' + esc(group.dn) + '</code></td>' +
    '<td>' + groupRuleCell(group.rule) + '</td>' +
    '<td>' + esc(group.origin) + '</td>' +
    '<td><code>' + esc(group.createdAt) + '</code></td>' +
    '<td><code>' + esc(group.modifiedAt) + '</code></td></tr></table>' +
    '<p class="note">The two timestamps are <em>generalized time</em> ' +
    '(<code>YYYYMMDDHHMMSSZ</code>), which is what a directory shows &mdash; not the ISO 8601 ' +
    'strings the rest of this console uses. An LDAP client bound to <code>ldap://&lt;host&gt;:' +
    esc(info.port) + '</code> reading <code>' + esc(group.dn) + '</code> sees exactly the object ' +
    'below, because it <em>is</em> that object and not a copy of it.</p>' +

    perPageForm('/admin/groups', 'group', group.dn, memberPage.paging.perPage, '',
                filterOnly(listViewOf('/admin/groups', req.query))) +

    '<h2>Members</h2>' +
    '<div class="tiles">' +
    tile(group.memberCount, 'Membership values') +
    tile(group.presentCount, 'Resolve to an entry') +
    tile(group.danglingCount, 'Dangling') +
    tile(group.claimed.length, 'Claim it back') +
    '</div>' +
    (group.memberCount
      ? membersNav +
        '<table><tr><th>Member</th><th>From</th><th>State</th><th>What it is</th><th>cn</th>' +
        '<th>mail</th><th>On the users page</th><th>The value as stored</th></tr>' +
        memberRows + '</table>' + membersNav
      : '<p class="note">This group lists nobody. An empty <code>groupOfNames</code> is something ' +
        'a real directory refuses &mdash; RFC 4519 makes <code>member</code> MUST &mdash; and ' +
        'this one has no schema, so it is here because something wrote it.</p>') +
    '<p class="note">Membership is read from <code>' + esc(group.memberAttributes.join('</code>, ' +
    '<code>')) + '</code>. The first two hold a <strong>DN</strong>; <code>memberUid</code> holds ' +
    'a bare user name, which is looked up under <code>' + esc(info.usersDn) + '</code> &mdash; ' +
    'treating the three alike is how a page ends up reporting every <code>posixGroup</code> ' +
    'member as dangling. <strong>Nesting is shown and not expanded</strong>: a member that is ' +
    'itself a group links to its own page, and nobody inside it is counted here, because nothing ' +
    'in this service walks a group tree and a flattened list would be claiming a feature that is ' +
    'not here.</p>' +
    '<p class="note">The last column links to the users page only for somebody this service has ' +
    'actually seen <strong>authenticate</strong>. The other members are marked <em>never ' +
    'here</em>, and that is not a fault: the directory holds whatever somebody wrote into it — ' +
    'the three people it seeds at startup, and anything a client has added since — while the ' +
    'users page holds whoever has presented a credential to this process. <code>alice</code> is ' +
    'in this directory from the moment it starts and appears on the users page only once ' +
    'somebody signs in as her. A link that was always drawn would usually land on &ldquo;nothing ' +
    'here has authenticated as alice&rdquo;, which reads as a broken link rather than as the ' +
    'answer it is.</p>' +
    claimedSection +

    '<h2>Every attribute this group has</h2>' +
    attributeTable(group) +
    '<p class="note">The whole object, operational attributes included &mdash; a search returns ' +
    'those only when they are asked for by name (RFC 4511 &sect;4.5.1.8), and this is a dump ' +
    'rather than a search. The membership attributes are in here too, as the raw values the ' +
    'store holds; the table above is the same values resolved. This directory is ' +
    '<strong>schemaless</strong>: no <code>objectClass</code> is enforced and no value is checked ' +
    'against a syntax, so an attribute a real directory would refuse is here because something ' +
    'wrote it.</p>' +
    GROUPS_CAVEAT + back + GROUPS_LINKS;

  log.debug("Leaving groupDetailPage(). " + memberPage.shown.length + " of " +
            group.memberCount + " member value(s) shown, " +
            Object.keys(group.attributes).length + " attribute(s).");
  // The entry is copied rather than sliced in place. groupsFor() builds a fresh
  // object per call today, so mutating it would work — but that is a fact about
  // another module, and a reader of this one cannot see it. `members` and `claimed`
  // go out as THE PAGE, like every other list here; the paging objects sit beside
  // `group` rather than inside it because they describe this reply and not the
  // directory entry, whose own counts are untouched next to them.
  const pagedGroup = Object.assign({}, group, {
    members: memberPage.shown, claimed: claimedPage.shown
  });
  return {
    inner: inner,
    json: Object.assign({ found: true }, info, {
      group: pagedGroup,
      membersPaging: pagingJson(memberPage.paging),
      claimedPaging: pagingJson(claimedPage.paging)
    })
  };
}

// Three answers again, and the first of them — no directory in this process —
// is the one an API caller is most likely to meet and least likely to expect,
// because it answers 200 with `directory: false` rather than failing.
function groupsView(req) {
  log.debug("Entering groupsView().");
  if (!groupReader) {
    // A build without ldap_server.js. Answered rather than 404'd, and with the
    // nav intact, for the same reason the user page's directory section says it
    // in words: the page exists, the directory does not, and those are different
    // facts about this process.
    log.debug("Leaving groupsView(). No directory is loaded.");
    return { json: { directory: false, groups: [] }, title: 'Groups',
             inner: messagesOf(req) + noGroupDirectorySection() };
  }
  const wantedDn = String(req.query.group || '').trim();
  if (wantedDn) {
    const detail = groupDetailPage(req, wantedDn);
    log.debug("Leaving groupsView(). The drill-down.");
    return { json: detail.json, inner: detail.inner,
             title: 'Group ' + wantedDn,
             // The whole DN is the leaf and shortCrumb() cuts it if it has to,
             // rather than being cut to its first RDN here: a leaf trimmed at the
             // shell keeps its full text in the tooltip, and a DN cut here would
             // lose the container it is in with nowhere left to say so. What the
             // cut drops is the tail, which is the part every entry shares.
             up: upTo('/admin/groups', wantedDn,
                      listViewOf('/admin/groups', req.query)) };
  }
  const list = groupsListPage(req);
  log.debug("Leaving groupsView(). The list.");
  return { json: list.json, inner: list.inner, title: 'Groups' };
}

// ---------------------------------------------------------------------------
// GET /admin/applications
//
// The other side of /admin/users. That page lists every identity that has
// authenticated here; this one lists what they authenticated TO — every OAuth
// client, OpenID Connect relying party, SAML 2.0 or 1.1 service provider,
// WS-Federation application, WS-Trust relying party, OpenID4VP verifier and
// Kerberos service this instance has been asked about.
//
// **It reads the directory and holds nothing.** The registry IS the
// ou=applications container (see applications.js), so this page cannot come to
// disagree with what an LDAP client sees — there is no second copy for it to
// disagree with. An `ldapmodify` made a second ago shows up on the next refresh.
//
// **There is no form on it, and that is a decision rather than an omission.**
// The write paths into this registry are the protocol endpoints and LDAP
// itself, and both are the point: a client is recorded because it turned up, and
// an operator changes one with `ldapmodify` — which is what makes the directory
// the source of truth rather than a display of one. A console form would be a
// third door onto the same store, and the one a reader would then expect to be
// authoritative. It is the same shape /admin/audit has and for a related
// reason, so it needs no POST on /admin-api either (see rule 7 in CLAUDE.md:
// the parity is about CONTROLS, and there are none here).
// ---------------------------------------------------------------------------
const APPLICATIONS_CAVEAT =
  '<p class="note"><strong>An entry here grants nothing.</strong> Being in this ' +
  'registry does not let an application do anything it could not do before &mdash; ' +
  'this service issues a token to any client_id that asks. The one place it is READ ' +
  'is RFC 9700 mode (<code>oauth2.rfc9700</code>), which matches a redirect_uri ' +
  'against <code>oauthRedirectUri</code> by exact string comparison, decides ' +
  'public-versus-confidential from <code>oauthTokenEndpointAuthMethod</code>, and ' +
  'checks <code>oauthClientSecret</code> at the token endpoint. With that mode off, ' +
  'these entries are a record and nothing more.</p>' +
  '<p class="note"><strong>Two attributes hold credentials in the clear</strong> ' +
  '&mdash; <code>oauthClientSecret</code> and <code>appRegistrationAccessToken</code> ' +
  '&mdash; in a directory where every bind succeeds. That is the same decision ' +
  '<code>/krb5/principals</code> makes about the Kerberos passwords and it costs more ' +
  'here than it does there: in RFC 9700 mode that secret is checked, so anyone who can ' +
  'read this directory can authenticate as that client. They are never written to the ' +
  'audit log.</p>';

const APPLICATIONS_LINKS =
  '<p class="sub"><a href="/ldap/applications">the same registry as the directory ' +
  'sees it, with the schema</a> &middot; <a href="/admin/users">the identities on the ' +
  'other side of these</a> &middot; <a href="/ldap/directory">every entry in the ' +
  'directory</a></p>';

// One application's kinds as cells, since a record commonly carries two — an
// OAuth client that asked for the openid scope is also a relying party, and a
// wtrealm handed a SAML 2.0 assertion in one request and the 1.1 default in the
// next is both of those. The registry accumulates rather than choosing, so the
// cell has to.
function kindCells(kinds) {
  if (!kinds.length) {
    return '<span class="state-none">unstated</span>';
  }
  return kinds.map(function (kind) {
    return '<code>' + esc(kind) + '</code>';
  }).join('<br>');
}

// ---------------------------------------------------------------------------
// POST /admin/applications — the six actions.
//
// **The console is not a second door onto this registry**, and that is the whole
// design of these: every one calls a function in `applications.js` which does
// the same read-modify-write `seen()` does, through the same two conversions,
// against the same `ou=applications` entries. The store stays one store; what is
// added here is a set of controls in front of it. An `ldapmodify` and a form
// post are the same act arriving by two routes, and both are visible to the
// other immediately because nothing caches.
//
// **What may be changed is DECLARED and not DERIVED**, and that line is drawn in
// `applications.js`'s EDITABLE table rather than here: redirect URIs, grant
// types, scopes, the secret, whether the client is confidential — configuration,
// which is what RFC 9700 mode reads — but never the counters, the sightings, the
// kinds or the protocols, which are what happened. LDAP can still reach those;
// the difference between offering an operation and merely not preventing it is
// the point. This handler renders and decides nothing: it validates that an
// action exists and hands the rest over, exactly as the console does for groups.
// ---------------------------------------------------------------------------
function applicationsAction(body) {
  log.debug("Entering applicationsAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const identifier = String(body.application || '').trim();
  const needsOne = ['set', 'add', 'remove', 'revoke-registration', 'forget'];
  if (needsOne.indexOf(action) >= 0 && !identifier) {
    log.debug("Leaving applicationsAction(). No application named.");
    return { ok: false, errors: ['Which application? Send `application` with the identifier ' +
                                 'exactly as this registry holds it — the client_id, wtrealm, ' +
                                 'AppliesTo, entityID or service principal name.'] };
  }

  if (action === 'create') {
    const result = applications.createApplication({
      identifier: String(body.identifier || body.application || ''),
      name: String(body.name || ''),
      kind: String(body.kind || '')
    });
    log.debug("Leaving applicationsAction(). create " + (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) return result;
    return { ok: true, application: result.application,
             message: '"' + result.application.identifier + '" is in the registry. It has ' +
                      'authenticated nothing yet — the counters are zero and the entry says ' +
                      'it was created by hand, so it cannot be mistaken for one that turned ' +
                      'up once. Give it the redirect URIs and grant types it is allowed, and ' +
                      'RFC 9700 mode will judge it against them.' };
  }

  if (action === 'set' || action === 'add' || action === 'remove') {
    const result = applications.updateApplication(identifier, {
      mode: action,
      attribute: String(body.attribute || ''),
      value: body.value === undefined ? '' : String(body.value)
    });
    log.debug("Leaving applicationsAction(). " + action + " " + (result.ok ? 'ok' : 'refused') + ".");
    return result;
  }

  if (action === 'revoke-registration') {
    // Not a delete: the entry stays and its history with it. This is RFC 7592's
    // delete reached from the console instead of from the client that holds the
    // registration access token — the same function, so the outcome is the same
    // one and not a second reading of what "unregistered" means.
    const before = applications.get(identifier);
    if (!before) {
      return { ok: false, errors: ['There is no application called "' + identifier + '" here.'] };
    }
    if (!before.registered) {
      return { ok: false, errors: ['"' + identifier + '" has no registration to revoke. It is ' +
                                   'a client_id this service has seen rather than one that ' +
                                   'went through POST /oauth2/register, which RFC 9700 mode ' +
                                   'already treats as public.'] };
    }
    applications.forgetRegistration(identifier);
    log.debug("Leaving applicationsAction(). The registration was revoked.");
    return { ok: true, application: applications.get(identifier),
             message: 'The RFC 7591 registration for "' + identifier + '" is gone, along with ' +
                      'its client_secret and its registration access token. The ENTRY stays, ' +
                      'with everything it had recorded — losing that this application was ever ' +
                      'here because its registration was withdrawn would be losing the fact ' +
                      'rather than the configuration. RFC 9700 mode now treats it as an ' +
                      'unregistered, public client and judges its redirect_uri against the ' +
                      'oauth2.redirectUris setting.' };
  }

  if (action === 'forget') {
    const result = applications.deleteApplication(identifier);
    log.debug("Leaving applicationsAction(). forget " + (result.ok ? 'ok' : 'refused') + ".");
    return result;
  }

  log.debug("Leaving applicationsAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The six are: create, set, ' +
                               'add, remove, revoke-registration, forget.'] };
}

app.post('/admin/applications', function (req, res) {
  log.debug("Entering the admin applications action endpoint.");
  const body = parseBody(req);
  const result = applicationsAction(body);
  // Back to the drill-down the form was posted from, when there was one, so a
  // reader who has just added a redirect URI is looking at the entry that now
  // carries it rather than at the top of the list — and carrying the list state
  // that came in on the form's `back` field either way, so the breadcrumb on the
  // page they land on still offers the filter and page they came from. Without
  // that, editing an application silently costs the reader their place in the
  // list, which is exactly what the trail exists to keep.
  const listView = listViewFromBack('/admin/applications', body.back);
  const back = String(body.application || '').trim() && result.ok !== false
    ? '/admin/applications' + queryWith(listView, { application: String(body.application).trim() })
    : '/admin/applications' + queryWith(listView, {});
  respondToAction(req, res, back, result);
  log.debug("Leaving the admin applications action endpoint.");
});

// The two selects the edit forms offer, built from applications.js's EDITABLE
// table so that a form cannot offer a field the action would refuse — the same
// reason the audit page's filters are built from the audit vocabulary.
function editableOptions(mode, selected) {
  return applications.editableAttributes(mode).map(function (row) {
    return '<option value="' + esc(row.name) + '"' +
      (row.name === selected ? ' selected' : '') + '>' + esc(row.name) +
      (row.sensitive ? ' (credential)' : '') + '</option>';
  }).join('');
}

// What one attribute of an application entry IS, as the drill-down's third
// column. Split out of that page because the entry carries FOUR kinds of
// attribute and the table only ever described one of them — so everything else
// came out as "not in the published schema", which is true of `objectClass` and
// `createTimestamp` in the narrowest sense and useless as an explanation.
//
// The order is the order of certainty: the registry's own table first, since it
// is the same table the entry was written from; then the operational ones, which
// the DIRECTORY sets and no schema of this module's would ever mention; then the
// object classes, published one heading further down `/ldap/applications`; and
// only then the honest "somebody wrote this by hand", which is a real state —
// this directory is schemaless and an ldapmodify can put anything on an entry.
//
// No description is invented for an attribute nothing here knows. Saying
// something confident about a name written by hand is how a page starts lying.
function applicationAttributeNote(name, operational) {
  const lower = String(name).toLowerCase();
  const spec = applications.SCHEMA.attributes.filter(function (one) {
    return one.name.toLowerCase() === lower;
  })[0];
  if (spec) {
    return { text: spec.what, sensitive: !!spec.sensitive };
  }
  if (lower === 'entrydn') {
    return { text: 'WHERE THE ENTRY IS. RFC 5020, and the directory synthesises it ' +
                   'rather than storing it: the DN is the key the entry is held under, ' +
                   'so a stored copy would be a second definition of the same fact and ' +
                   'the one that goes stale the moment the entry is renamed. It is the ' +
                   'name an ldapsearch filter matches this by, which is why the dump ' +
                   'calls it the same thing.' };
  }
  if (lower === 'createtimestamp' || lower === 'modifytimestamp') {
    return { text: 'The directory\'s own, not the registry\'s: when this ENTRY was ' +
                   (lower === 'createtimestamp' ? 'created' : 'last written') + '. ' +
                   'Different from appFirstSeen and appLastSeen one row up, which are ' +
                   'when the APPLICATION was seen — an ldapmodify moves this one and ' +
                   'not those.' };
  }
  if (lower === 'objectclass') {
    return { text: 'The classes this entry claims, from the registry\'s vocabulary: ' +
                   applications.SCHEMA.objectClasses.map(function (one) {
                     return one.name;
                   }).join(', ') + '. A VOCABULARY and not a constraint — node-ldapjs ' +
                   'has no schema subsystem and this directory is schemaless on ' +
                   'purpose, so nothing rejects an entry for disobeying it.' };
  }
  if (operational) {
    // An operational attribute this function has no sentence for, which means
    // ldap_server.js's OPERATIONAL list grew and this one did not. Saying so is
    // better than the "written by hand" answer below, which would be flatly
    // wrong about an attribute the directory sets itself.
    return { text: 'An operational attribute the directory sets. A search returns it only ' +
                   'when it is asked for by name (RFC 4511 section 4.5.1.8); this dump is ' +
                   'not a search, so it is here. This page has nothing more specific to ' +
                   'say about it.' };
  }
  return { text: 'Not in the published schema and not one the directory sets — written ' +
                 'by hand into this entry, which nothing here prevents and which is what ' +
                 'a schemaless directory means. The registry\'s own writes REPLACE the ' +
                 'entry, so a value here survives only until the next time this ' +
                 'application is seen.' };
}

function applicationsListPage(req) {
  log.debug("Entering applicationsListPage().");
  const all = applications.list();
  const wantedText = String(req.query.q || '').trim();
  const wantedKind = String(req.query.kind || '').trim();
  const needle = wantedText.toLowerCase();
  const filtered = all.filter(function (row) {
    if (wantedKind && row.kinds.indexOf(wantedKind) < 0) {
      return false;
    }
    if (!needle) {
      return true;
    }
    // The identifier and the name both, because somebody looking for an
    // application has one or the other in mind and which one depends on whether
    // they came from a client's configuration or from this console.
    return row.identifier.toLowerCase().indexOf(needle) >= 0 ||
           String(row.name).toLowerCase().indexOf(needle) >= 0;
  });
  const paged = pagedRows(req.query, filtered, { noun: 'applications' });
  const paging = paged.paging;
  const filterParams = { q: wantedText || '', kind: wantedKind || '',
                         per: req.query.per ? paging.perPage : '' };
  const nav = pageNav('/admin/applications', filterParams, paging);

  const listView = listViewOf('/admin/applications', req.query);
  const rows = paged.shown.map(function (row) {
    // The link carries the list AS IT IS BEING VIEWED, which is what lets the
    // trail on the other side come back to this page of this filter rather than to
    // the top of everything. See listViewOf().
    const href = '/admin/applications' + queryWith(listView, { application: row.identifier });
    return '<tr><td><a href="' + esc(href) + '"><code>' + esc(row.identifier) + '</code></a>' +
      // The DN on every row rather than only where the RDN is a digest. These
      // entries ARE the registry, so the DN is what an ldapsearch or ldapmodify
      // is aimed at; showing it only in the odd case made it look like a note
      // about a special entry instead of the address of every one of them.
      (row.dn ? '<div class="sub"><code>' + esc(row.dn) + '</code>' +
        (row.identifier === row.dnLabel ? '' :
          ' &mdash; the identifier is too long for a readable RDN, so the ' +
          '<code>cn</code> is a digest of it') + '</div>' : '') +
      '</td><td>' + esc(row.name) + '</td>' +
      '<td>' + kindCells(row.kinds) + '</td>' +
      '<td>' + esc(row.protocols.join(', ')) + '</td>' +
      '<td>' + (row.registered
        ? '<span class="state-valid">yes</span>'
        : '<span class="state-none">no</span>') + '</td>' +
      '<td class="num">' + row.authentications + '</td>' +
      '<td class="num">' + row.sessions + '</td>' +
      '<td class="num">' + row.users + '</td>' +
      '<td><code>' + esc(row.lastSeen) + '</code></td></tr>';
  }).join('');

  const kindOptions = ['<option value=""' + (wantedKind ? '' : ' selected') +
                       '>any kind</option>']
    .concat(applications.KINDS.map(function (one) {
      // Counted over EVERYTHING rather than over the filtered set, so the
      // numbers do not change as the reader narrows the list — a select whose
      // options renumber themselves on every Filter is one nobody can use to
      // find out where the rows went.
      const n = all.filter(function (row) { return row.kinds.indexOf(one.kind) >= 0; }).length;
      return '<option value="' + esc(one.kind) + '"' +
             (one.kind === wantedKind ? ' selected' : '') + '>' +
             esc(one.label) + ' (' + n + ')</option>';
    })).join('');

  const registeredCount = all.filter(function (row) { return row.registered; }).length;

  const inner = messagesOf(req) +
    '<div class="tiles">' +
    tile(all.length, 'Applications') +
    tile(registeredCount, 'Registered (RFC 7591)') +
    tile(all.reduce(function (n, r) { return n + r.authentications; }, 0), 'Authentications') +
    tile(applications.maxApplications ? applications.maxApplications() : '', 'Maximum held') +
    '</div>' +
    '<form method="get" action="/admin/applications"><div class="formrow">' +
    '<label for="q">Application</label>' +
    '<input type="text" id="q" name="q" value="' + esc(wantedText) + '" size="28" ' +
    'placeholder="client_id, wtrealm, entityID, SPN or name">' +
    '<label for="kind">Kind</label>' +
    '<select id="kind" name="kind">' + kindOptions + '</select>' +
    '<label for="per">Show</label>' +
    '<select id="per" name="per">' + perPageOptions(paging.perPage) + '</select>' +
    '<button type="submit">Filter</button>' +
    ((wantedText || wantedKind)
      ? ' <a href="/admin/applications">clear</a>' : '') +
    '</div></form>' +
    nav +
    '<table><tr><th>Identifier</th><th>Name</th><th>Kind</th><th>Protocols</th>' +
    '<th>Registered</th><th class="num">Auth</th><th class="num">Sessions</th>' +
    '<th class="num">Users</th><th>Last seen</th></tr>' +
    (rows || '<tr><td colspan="9">No application matches. ' +
             ((wantedText || wantedKind)
               ? 'The filter above may be hiding some.'
               : 'One appears the first time a client_id, wtrealm, AppliesTo, entityID ' +
                 'or service principal name is accepted here.') + '</td></tr>') +
    '</table>' +
    nav +
    '<h2>Add an application</h2>' +
    '<p class="note">For a relying party that has not connected yet. An entry usually appears ' +
    'because an identifier was ACCEPTED — a client_id at the token endpoint, a wtrealm on a ' +
    'sign-in response — and this is how to get one in ahead of that, which is what RFC 9700 ' +
    'mode needs if it is to judge a client against its own redirect URIs rather than against ' +
    'the <code>oauth2.redirectUris</code> setting. It records that it was created by hand, so ' +
    'it cannot be mistaken for one that turned up once and never came back.</p>' +
    '<form method="post" action="/admin/applications"><div class="formrow">' +
    '<input type="hidden" name="action" value="create">' +
    '<label for="identifier">Identifier</label>' +
    '<input type="text" id="identifier" name="identifier" size="30" required ' +
    'placeholder="client_id, wtrealm, entityID or SPN">' +
    '<label for="newname">Name</label>' +
    '<input type="text" id="newname" name="name" size="18" placeholder="optional">' +
    '<label for="newkind">Kind</label>' +
    '<select id="newkind" name="kind">' +
    '<option value="">unstated</option>' +
    applications.KINDS.map(function (one) {
      return '<option value="' + esc(one.kind) + '">' + esc(one.label) + '</option>';
    }).join('') +
    '</select>' +
    '<button type="submit">Add</button>' +
    '</div></form>' +
    '<p class="note"><strong>One entry per identifier, whatever protocol brought it.</strong> ' +
    'The key is the identifier exactly as it arrived &mdash; not lower-cased and not ' +
    'namespaced by protocol &mdash; so an application appearing under one name in two ' +
    'protocols is one row with two kinds rather than two rows. That is the same rule that ' +
    'makes <code>alice</code>, <code>urn:sts-mock:user:alice</code> and ' +
    '<code>alice@REALM</code> one person on the users page.</p>' +
    '<p class="note"><strong>Sessions and Users are counts of CHANGES, not of distinct ' +
    'sets.</strong> The ids themselves are deliberately not kept on the entry &mdash; an ' +
    'application used by two thousand people would otherwise carry two thousand values ' +
    '&mdash; so the count moves when the id differs from the last one recorded. Right for ' +
    'the ordinary case, and it undercounts somebody alternating between two applications.</p>' +
    APPLICATIONS_CAVEAT + APPLICATIONS_LINKS;

  log.debug("Leaving applicationsListPage(). " + paged.shown.length + " row(s) of " +
            filtered.length + " matched.");
  return {
    inner: inner,
    json: {
      applicationCount: all.length, matched: filtered.length, shown: paged.shown.length,
      registered: registeredCount,
      filter: { q: wantedText || null, kind: wantedKind || null },
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      container: applications.containerDn ? applications.containerDn() : null,
      max: applications.maxApplications ? applications.maxApplications() : null,
      kinds: applications.KINDS,
      applications: paged.shown
    }
  };
}

// The drill-down. Its one list is the ATTRIBUTE table, which is paged under a
// name of its own (`attributesPage`) rather than the bare `page` — the
// convention pagingOf()'s header describes for a view that holds more than the
// list views do, and the shape to grow into when this page gains a second list.
function applicationDetailPage(req, identifier) {
  log.debug("Entering applicationDetailPage(). identifier=" + identifier);
  // THE LIST THE READER CAME FROM, carried on every form on this page as one
  // opaque field. A form POST answers with a redirect, and a redirect built from
  // the identifier alone lands back here with the list state gone — so the
  // breadcrumb above would then offer the top of an unfiltered list to somebody
  // who arrived from page 3 of a filter. It is one field rather than four because
  // an action reads its own body by name, and `q` or `kind` loose in there is a
  // field an action added later could pick up by accident. The handler REBUILDS a
  // query from it through listViewOf()'s whitelist rather than echoing it, which
  // is what backTo() does with the tokens page's and for the same reason: a
  // redirect target taken out of a request body is an open redirect, and one
  // carrying a newline is a header injection.
  const carryBack = '<input type="hidden" name="back" value="' +
    esc(queryWith(listViewOf('/admin/applications', req.query), {})) + '">';
  const row = applications.get(identifier);
  if (!row) {
    log.debug("Leaving applicationDetailPage(). No such application.");
    return {
      inner: messagesOf(req) +
        '<p class="warn">No application called <code>' + esc(identifier) + '</code> is ' +
        'recorded here. That is not the same as one this service has refused: an entry ' +
        'appears the first time an identifier is ACCEPTED, so a client whose every request ' +
        'was turned away has none.</p>' + APPLICATIONS_LINKS,
      json: { found: false, identifier: identifier }
    };
  }
  // EVERY attribute the entry carries, operational ones and entryDN included.
  // This used to be the schema half minus the twelve names applications.js reads
  // into named members, under a heading that said "every attribute the entry
  // carries" — so objectClass, cn, appIdentifier, both timestamps and the DN
  // itself were all missing from the one table on this service whose whole job
  // is to be complete.
  const attributeRows = Object.keys(row.attributes).sort().map(function (name) {
    const value = row.attributes[name];
    return { name: name, values: Array.isArray(value) ? value : [String(value)],
             operational: (row.operational || []).indexOf(name) >= 0 };
  });
  const paged = pagedRows(req.query, attributeRows,
                          { name: 'attributes', noun: 'attributes' });
  const paging = paged.paging;
  const nav = pageNav('/admin/applications', pageParamsOf(req.query), paging);

  const attrHtml = paged.shown.map(function (attr) {
    // What each attribute MEANS rather than only what it holds. The registry's
    // own table is the first answer and is the same table the entry was written
    // from — a second description here would be the one that went stale — and
    // applicationAttributeNote() carries the other three cases.
    const note = applicationAttributeNote(attr.name, attr.operational);
    return '<tr><td><code>' + esc(attr.name) + '</code>' +
      (note.sensitive ? ' <span class="state-revoked">credential</span>' : '') +
      (attr.operational
        ? ' <span class="state-none" title="An operational attribute. A search returns it ' +
          'only when it is asked for by name (RFC 4511 section 4.5.1.8) — this dump shows ' +
          'it always.">(operational)</span>'
        : '') +
      '</td><td>' + attr.values.map(function (v) {
        return '<code>' + esc(v) + '</code>';
      }).join('<br>') + '</td><td class="sub">' + esc(note.text) + '</td></tr>';
  }).join('');

  const inner = messagesOf(req) +
    '<h2><code>' + esc(row.identifier) + '</code></h2>' +
    '<div class="tiles">' +
    tile(row.authentications, 'Authentications') +
    tile(row.sessions, 'Sessions') +
    tile(row.users, 'Users') +
    tile(row.registered ? 'yes' : 'no', 'Registered') +
    '</div>' +
    '<table><tr><th>Thing</th><th>Value</th></tr>' +
    // FIRST, because it is the thing this page could not previously answer:
    // where in the tree this application lives. The registry is the directory,
    // so the DN is what an ldapsearch or an ldapmodify is aimed at, and a
    // console that showed only the cn made an operator reconstruct it.
    '<tr><td>Distinguished name</td><td>' + (row.dn
      ? '<code>' + esc(row.dn) + '</code>' +
        (row.identifier === row.dnLabel ? '' :
          '<div class="sub">The RDN is a digest &mdash; <code>' + esc(row.identifier) +
          '</code> is longer than 64 characters, which is not a readable RDN. ' +
          '<code>appIdentifier</code> is the identity, not the <code>cn</code>.</div>')
      : '<span class="state-none">no directory is loaded in this process, so there is ' +
        'no entry and no registry</span>') + '</td></tr>' +
    '<tr><td>Name</td><td>' + esc(row.name) + '</td></tr>' +
    '<tr><td>Kind</td><td>' + kindCells(row.kinds) + '</td></tr>' +
    '<tr><td>Protocols</td><td>' + esc(row.protocols.join(', ')) + '</td></tr>' +
    '<tr><td>First seen</td><td><code>' + esc(row.firstSeen) + '</code></td></tr>' +
    '<tr><td>Last seen</td><td><code>' + esc(row.lastSeen) + '</code></td></tr>' +
    '<tr><td>How it got here</td><td>' + (row.descriptions.length
      ? row.descriptions.map(function (d) { return esc(d); }).join('<br>')
      : '<span class="state-none">nothing recorded</span>') + '</td></tr>' +
    '</table>' +
    '<h2>Its directory entry</h2>' +
    '<p class="sub">Every attribute the entry carries &mdash; the operational ones and ' +
    '<code>entryDN</code> included, which a SEARCH would return only when asked for by ' +
    'name (RFC 4511 section 4.5.1.8) &mdash; with what each one is. This IS the entry ' +
    '&mdash; the registry is the <code>ou=applications</code> container and nothing ' +
    'caches it &mdash; so an <code>ldapmodify</code> shows here on the next refresh, and ' +
    'changes what RFC 9700 mode enforces at the same moment.</p>' +
    (row.dn
      ? '<p class="sub"><code>' + esc(row.dn) + '</code>' +
        (row.createdAt ? ' &middot; created <code>' + esc(row.createdAt) + '</code>' : '') +
        (row.modifiedAt ? ' &middot; last written <code>' + esc(row.modifiedAt) +
                          '</code>' : '') +
        (row.origin ? ' &middot; written by <code>' + esc(row.origin) + '</code>' : '') +
        '</p>'
      : '') +
    nav +
    '<table><tr><th>Attribute</th><th>Value</th><th>What it is</th></tr>' +
    // Reachable only where no directory is loaded in this process. Every real
    // entry carries objectClass, cn, appIdentifier and its two timestamps at the
    // least, so "no attributes" is now a statement about the STORE rather than
    // about this application — which is what it says.
    (attrHtml || '<tr><td colspan="3">No directory is loaded in this process, so there ' +
     'is no <code>ou=applications</code> container and no entry to show. This module ' +
     'keeps no store of its own on purpose.</td></tr>') +
    '</table>' +
    nav +

    '<h2>Change what it is allowed to do</h2>' +
    '<p class="note">These write the same entry an <code>ldapmodify</code> writes, through the ' +
    'same functions &mdash; the console is a set of controls in front of this registry and not ' +
    'a second copy of it. A change here is what RFC 9700 mode enforces on the very next ' +
    'request: add to <code>oauthRedirectUri</code> and that URI is accepted by exact match, set ' +
    '<code>oauthTokenEndpointAuthMethod</code> to <code>none</code> and the client becomes ' +
    'public, so PKCE is required of it and its secret stops being checked.</p>' +
    '<form method="post" action="/admin/applications">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="set">' +
    '<input type="hidden" name="application" value="' + esc(row.identifier) + '">' +
    '<label for="setattr">Set</label>' +
    '<select id="setattr" name="attribute">' + editableOptions('set', '') + '</select>' +
    '<label for="setval">to</label>' +
    '<input type="text" id="setval" name="value" size="34" placeholder="empty clears it">' +
    '<button type="submit">Set</button>' +
    '</div></form>' +
    '<form method="post" action="/admin/applications">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="add">' +
    '<input type="hidden" name="application" value="' + esc(row.identifier) + '">' +
    '<label for="addattr">Add to</label>' +
    '<select id="addattr" name="attribute">' + editableOptions('multi', 'oauthRedirectUri') +
    '</select>' +
    '<label for="addval">the value</label>' +
    '<input type="text" id="addval" name="value" size="34" required>' +
    '<button type="submit">Add</button>' +
    '</div></form>' +
    '<form method="post" action="/admin/applications">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="remove">' +
    '<input type="hidden" name="application" value="' + esc(row.identifier) + '">' +
    '<label for="remattr">Remove from</label>' +
    '<select id="remattr" name="attribute">' + editableOptions('multi', 'oauthRedirectUri') +
    '</select>' +
    '<label for="remval">the value</label>' +
    '<input type="text" id="remval" name="value" size="34" required>' +
    '<button type="submit">Remove</button>' +
    '</div></form>' +
    '<p class="note"><strong>What these will not change, and why.</strong> The counters, the ' +
    'first and last sighting, the kinds and the protocols are DERIVED &mdash; they are what ' +
    'happened rather than what this application may do &mdash; and a form that could rewrite ' +
    'them would make this page lie about the service\'s own behaviour, in a way ' +
    'indistinguishable from the recording being broken. <code>ldapmodify</code> still reaches ' +
    'every one of them: an operator with an LDAP client is doing something deliberate, and ' +
    'refusing them HERE is the difference between offering an operation and merely not ' +
    'preventing it. <code>appRegistrationJson</code> is not offered either &mdash; edit the ' +
    'attributes beside it instead, which is what the registration is rebuilt from.</p>' +

    '<h2>Take it out of the registry</h2>' +
    (row.registered
      ? '<form method="post" action="/admin/applications">' + carryBack + '<div class="formrow">' +
        '<input type="hidden" name="action" value="revoke-registration">' +
        '<input type="hidden" name="application" value="' + esc(row.identifier) + '">' +
        '<button type="submit">Revoke the RFC 7591 registration</button>' +
        '<span class="sub">The entry and its history stay; the client_secret, the registration ' +
        'access token and the registration itself go. Afterwards RFC 9700 mode treats it as an ' +
        'unregistered, public client.</span>' +
        '</div></form>'
      : '<p class="note">It has no RFC 7591 registration to revoke &mdash; it is an identifier ' +
        'this service has seen rather than a client that registered, which RFC 9700 mode ' +
        'already treats as public.</p>') +
    '<form method="post" action="/admin/applications">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="forget">' +
    '<input type="hidden" name="application" value="' + esc(row.identifier) + '">' +
    '<button type="submit" class="danger">Delete this entry</button>' +
    '<span class="sub">The only control here that LOSES a fact: the entry goes and takes its ' +
    row.authentications + ' recorded authentication(s) with it. It will reappear, empty, the ' +
    'next time this identifier is accepted by a protocol.</span>' +
    '</div></form>' +
    APPLICATIONS_CAVEAT +
    '<p class="sub"><a href="' +
    esc('/admin/applications' + queryWith(listViewOf('/admin/applications', req.query), {})) +
    '">back to the list</a> &middot; ' +
    '<a href="/ldap/applications">the registry as the directory sees it</a></p>';

  log.debug("Leaving applicationDetailPage(). " + paged.shown.length + " attribute row(s).");
  return {
    inner: inner,
    json: Object.assign({ found: true }, row, {
      attributesShown: paged.shown,
      attributesPaging: pagingJson(paging)
    })
  };
}

function applicationsView(req) {
  log.debug("Entering applicationsView().");
  const wanted = String(req.query.application || '').trim();
  if (wanted) {
    const detail = applicationDetailPage(req, wanted);
    log.debug("Leaving applicationsView(). The drill-down.");
    return { json: detail.json, inner: detail.inner, title: 'Application ' + wanted,
             up: upTo('/admin/applications', wanted,
                      listViewOf('/admin/applications', req.query)) };
  }
  const list = applicationsListPage(req);
  log.debug("Leaving applicationsView(). The list.");
  return { json: list.json, inner: list.inner, title: 'Applications' };
}

app.get('/admin/applications', function (req, res) {
  log.debug("Entering the admin applications page.");
  const view = applicationsView(req);
  respond(req, res, view.json, view.title, '/admin/applications', view.inner, view.up);
  log.debug("Leaving the admin applications page. " + view.title + ".");
});

// ---------------------------------------------------------------------------
// GET /admin/authorization-servers, POST /admin/authorization-servers
//
// RFC 9700 section 2.6 asks an authorization server to PUBLISH its metadata so
// that clients stop hard-coding security capabilities. This page is the other
// side of that: it decides what the published document SAYS, per authorization
// server, so that a client which reads the metadata can be shown reading it —
// and a client which does not can be shown not to.
//
// **A profile changes the document and not the endpoints**, and the page says so
// three times because it is the one thing here that could mislead badly.
// Everywhere else in this service a document disagreeing with the code is a
// defect — /admin/sts-metadata exists to report exactly that — and here it is
// the feature. So every view computes the DRIFT: which overridden members
// disagree with what this service would actually publish, and which removals
// hide something real.
// ---------------------------------------------------------------------------
const AS_CAVEAT =
  '<p class="note"><strong>What a document says is what that authorization server DOES.</strong> ' +
  'Advertise <code>code_challenge_methods_supported: ["S256"]</code> here and this server\'s own ' +
  'authorization endpoint refuses <code>plain</code> — at <code>/{id}/oauth2/authorize</code>, ' +
  'and nowhere else. The members marked <em>enforced</em> below drive behaviour; the rest are ' +
  'published and cannot be made true by this service, which is still useful (a document a ' +
  'client did not expect is a client error path worth running) and is listed as <em>drift</em> ' +
  'so that nobody discovers it the hard way.</p>' +
  '<p class="note"><strong>Every authorization server starts equal.</strong> A new one — or one ' +
  'created by somebody simply asking for it — has exactly the capabilities the default server ' +
  'has, and differs only where it has been made to. <strong>Every client may use every one of ' +
  'them</strong>: nothing here restricts a client to a server, and ' +
  '<a href="/admin/applications">the applications page</a> records which ones each client has ' +
  'actually used. What does NOT cross between them is a credential — an authorization code ' +
  'issued by one is refused at another\'s token endpoint.</p>';

const AS_LINKS =
  '<p class="sub"><a href="/.well-known/oauth-authorization-server">the default RFC 8414 ' +
  'document</a> &middot; <a href="/.well-known/openid-configuration">the default OpenID ' +
  'Provider Configuration</a> &middot; <a href="/admin/applications">the clients that read ' +
  'them</a></p>';

function asDriftRows(id) {
  // The document this service would publish for THIS profile if the profile
  // said nothing — built from the same function the endpoints serve, so the
  // comparison cannot go stale as that document grows members. `truthFor()`
  // gives it a request-shaped object because asMetadata() derives every URL in
  // it from the one the request arrived on.
  return authorizationServers.driftOf(id, oauth2.asMetadata(asTruthRequest()));
}

// A request-shaped stand-in, so the document can be built outside a request.
// The host is this service's own default, which is what /admin/config and
// /admin/sts-metadata already assume when they name a URL: the console is being
// read by somebody who reached this process, and the comparison is about
// MEMBERS rather than about hostnames.
function asTruthRequest() {
  return {
    protocol: config.value('global.https') ? 'https' : 'http',
    get: function (name) {
      return String(name).toLowerCase() === 'host'
        ? 'localhost:' + config.value('global.port') : '';
    },
    query: {}
  };
}

function asAction(body) {
  log.debug("Entering asAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const id = String(body.profile || body.id || '').trim();

  if (action === 'create') {
    const result = authorizationServers.create({
      id: id, label: String(body.label || ''), description: String(body.description || '')
    });
    log.debug("Leaving asAction(). create " + (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) return result;
    return { ok: true, profile: result.profile,
             message: 'The "' + result.profile.id + '" authorization server is published at ' +
                      result.profile.urls.oauth + ' and ' + result.profile.urls.oidc + '. It ' +
                      'has no overrides yet, so both documents say exactly what this service ' +
                      'says about itself — which is the right place to start from.' };
  }
  if (action === 'set') {
    const result = authorizationServers.setMember(id, body.member, body.value);
    log.debug("Leaving asAction(). set " + (result.ok ? 'ok' : 'refused') + ".");
    return result;
  }
  if (action === 'remove') {
    const result = authorizationServers.removeMember(id, body.member);
    log.debug("Leaving asAction(). remove " + (result.ok ? 'ok' : 'refused') + ".");
    return result;
  }
  if (action === 'reset') {
    const result = authorizationServers.resetMember(id, body.member);
    log.debug("Leaving asAction(). reset " + (result.ok ? 'ok' : 'refused') + ".");
    return result;
  }
  if (action === 'delete') {
    const result = authorizationServers.remove(id);
    log.debug("Leaving asAction(). delete " + (result.ok ? 'ok' : 'refused') + ".");
    return result;
  }
  log.debug("Leaving asAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The five are: create, set, ' +
                               'remove, reset, delete.'] };
}

function asMemberOptions(selected) {
  return authorizationServers.GROUPS.map(function (group) {
    const inGroup = authorizationServers.MEMBERS.filter(function (row) {
      return row.group === group;
    });
    return '<optgroup label="' + esc(group) + '">' + inGroup.map(function (row) {
      return '<option value="' + esc(row.name) + '"' +
        (row.name === selected ? ' selected' : '') + '>' + esc(row.name) + '</option>';
    }).join('') + '</optgroup>';
  }).join('');
}

function asListPage(req) {
  log.debug("Entering asListPage().");
  const all = authorizationServers.list();
  const paged = pagedRows(req.query, all, { noun: 'authorization servers' });
  const paging = paged.paging;
  const nav = pageNav('/admin/authorization-servers',
                      { per: req.query.per ? paging.perPage : '' }, paging);

  const listView = listViewOf('/admin/authorization-servers', req.query);
  const rows = paged.shown.map(function (row) {
    const drift = asDriftRows(row.id);
    // The link carries the list AS IT IS BEING VIEWED, which is what lets the
    // trail on the other side come back to this page of this filter rather than to
    // the top of everything. See listViewOf().
    const href = '/admin/authorization-servers' + queryWith(listView, { profile: row.id });
    return '<tr><td><a href="' + esc(href) + '"><code>' + esc(row.id) + '</code></a></td>' +
      '<td>' + esc(row.label || '') + '</td>' +
      '<td class="num">' + Object.keys(row.overrides).length + '</td>' +
      '<td class="num">' + row.removed.length + '</td>' +
      '<td class="num">' + (drift.length
        ? '<span class="state-expired" title="Members whose published value disagrees with ' +
          'what this service would publish.">' + drift.length + '</span>'
        : '<span class="state-none">0</span>') + '</td>' +
      '<td><code>' + esc(row.urls.authorize) + '</code><br><code>' + esc(row.urls.token) +
      '</code><div class="sub">metadata at <code>' + esc(row.urls.oidc) + '</code></div>' +
      '</td>' +
      '<td>' + (row.autoCreated
        ? '<span class="sub">asked for</span>' : '<span class="sub">configured</span>') +
      '</td><td class="num">' + esc(row.seen) + '</td></tr>';
  }).join('');

  const inner = messagesOf(req) +
    '<div class="tiles">' +
    tile(all.length, 'Profiles') +
    tile(all.reduce(function (n, r) { return n + Object.keys(r.overrides).length; }, 0), 'Overrides') +
    tile(all.reduce(function (n, r) { return n + asDriftRows(r.id).length; }, 0), 'Drifting members') +
    '</div>' +
    '<p class="note"><strong>One process, several authorization servers.</strong> The path ' +
    'component the two discovery shapes already carry now selects a CONFIGURATION as well as ' +
    'an issuer identifier &mdash; RFC 8414 section 3.1 <em>inserts</em> it after the well-known ' +
    'segment and OpenID Connect Discovery section 4 <em>appends</em> the well-known segment to ' +
    'it, which is the commonest reason a discovery fetch 404s, and this service has answered ' +
    'both for a long time. <strong>A path nobody has configured publishes the document this ' +
    'service always published</strong>, so nothing that worked before this page existed ' +
    'behaves differently.</p>' +
    nav +
    '<table><tr><th>Authorization server</th><th>Label</th><th class="num">Overrides</th>' +
    '<th class="num">Removed</th><th class="num">Drift</th><th>Its endpoints</th>' +
    '<th>Came from</th><th class="num">Asked for</th></tr>' +
    (rows || '<tr><td colspan="8">No authorization server has been named. Every discovery URL answers with ' +
             'the document this service builds for itself, which is what RFC 9700 section 2.6 ' +
             'asks for &mdash; these are for when you need it to say something else.</td></tr>') +
    '</table>' +
    nav +
    '<h2>Add an authorization server</h2>' +
    '<form method="post" action="/admin/authorization-servers"><div class="formrow">' +
    '<input type="hidden" name="action" value="create">' +
    '<label for="asid">Id</label>' +
    '<input type="text" id="asid" name="id" size="18" required placeholder="tenant1">' +
    '<label for="aslabel">Label</label>' +
    '<input type="text" id="aslabel" name="label" size="20" placeholder="optional">' +
    '<label for="asdesc">Note</label>' +
    '<input type="text" id="asdesc" name="description" size="28" placeholder="what it is for">' +
    '<button type="submit">Add</button>' +
    '</div></form>' +
    '<p class="note">The id is a single URL path segment &mdash; letters, digits, dot, dash, ' +
    'underscore or tilde &mdash; because it has to appear in a URL without being escaped. One ' +
    'that had to be escaped would be one nobody could find again.</p>' +
    AS_CAVEAT + AS_LINKS;

  log.debug("Leaving asListPage(). " + paged.shown.length + " row(s).");
  return {
    inner: inner,
    json: {
      profileCount: all.length, shown: paged.shown.length,
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      members: authorizationServers.MEMBERS,
      authorizationServers: paged.shown.map(function (row) {
        return Object.assign({}, row, { drift: asDriftRows(row.id) });
      })
    }
  };
}

function asDetailPage(req, id) {
  log.debug("Entering asDetailPage(). id=" + id);
  // THE LIST THE READER CAME FROM, carried on every form on this page as one
  // opaque field. A form POST answers with a redirect, and a redirect built from
  // the identifier alone lands back here with the list state gone — so the
  // breadcrumb above would then offer the top of an unfiltered list to somebody
  // who arrived from page 3 of a filter. It is one field rather than four because
  // an action reads its own body by name, and `q` or `kind` loose in there is a
  // field an action added later could pick up by accident. The handler REBUILDS a
  // query from it through listViewOf()'s whitelist rather than echoing it, which
  // is what backTo() does with the tokens page's and for the same reason: a
  // redirect target taken out of a request body is an open redirect, and one
  // carrying a newline is a header injection.
  const carryBack = '<input type="hidden" name="back" value="' +
    esc(queryWith(listViewOf('/admin/authorization-servers', req.query), {})) + '">';
  const profile = authorizationServers.get(id);
  if (!profile) {
    log.debug("Leaving asDetailPage(). No such profile.");
    return {
      inner: messagesOf(req) +
        '<p class="warn">There is no authorization server profile called <code>' + esc(id) +
        '</code>. Its discovery URLs still answer &mdash; with the document this service ' +
        'builds and the issuer taken from the path &mdash; because an unconfigured path ' +
        'component has always been served that way rather than 404\'d.</p>' + AS_LINKS,
      json: { found: false, id: id }
    };
  }
  const drift = asDriftRows(id);
  // The document this authorization server publishes, which is the same object
  // its endpoints read their capabilities out of.
  const capabilities = authorizationServers.capabilitiesOf(id, oauth2.asMetadata(asTruthRequest(), true));
  const memberRows = Object.keys(profile.overrides).sort().map(function (member) {
    const spec = authorizationServers.MEMBERS.filter(function (row) {
      return row.name === member;
    })[0];
    const bad = drift.filter(function (d) { return d.member === member; })[0];
    return '<tr><td><code>' + esc(member) + '</code></td>' +
      '<td><code>' + esc(JSON.stringify(profile.overrides[member])) + '</code></td>' +
      '<td>' + (bad
        ? '<span class="state-expired">' + esc(bad.kind) + '</span><div class="sub">' +
          esc(bad.what) + '</div>'
        : '<span class="state-valid">agrees</span>') + '</td>' +
      '<td class="sub">' + esc(spec ? spec.what : 'Not a member this service recognises — ' +
        'which is allowed, and is half the point: publishing something a client did not ' +
        'expect is what this page is for.') + '</td>' +
      '<td><form method="post" action="/admin/authorization-servers">' + carryBack +
      '<input type="hidden" name="action" value="reset">' +
      '<input type="hidden" name="profile" value="' + esc(id) + '">' +
      '<input type="hidden" name="member" value="' + esc(member) + '">' +
      '<button type="submit">Reset</button></form></td></tr>';
  }).join('');

  const removedRows = profile.removed.map(function (member) {
    return '<tr><td><code>' + esc(member) + '</code></td><td class="sub">Not published at all. ' +
      'A client reading this document cannot tell that this server supports it &mdash; which ' +
      'is not the same as learning that it does not, and is the difference RFC 9700 section ' +
      '2.6 is arguing about.</td>' +
      '<td><form method="post" action="/admin/authorization-servers">' + carryBack +
      '<input type="hidden" name="action" value="reset">' +
      '<input type="hidden" name="profile" value="' + esc(id) + '">' +
      '<input type="hidden" name="member" value="' + esc(member) + '">' +
      '<button type="submit">Put it back</button></form></td></tr>';
  }).join('');

  const inner = messagesOf(req) +
    '<h2><code>' + esc(profile.id) + '</code>' +
    (profile.label ? ' &mdash; ' + esc(profile.label) : '') + '</h2>' +
    (profile.description ? '<p class="note">' + esc(profile.description) + '</p>' : '') +
    '<table><tr><th>Thing</th><th>Value</th></tr>' +
    '<tr><td>RFC 8414 document</td><td><a href="' + esc(profile.urls.oauth) + '"><code>' +
    esc(profile.urls.oauth) + '</code></a></td></tr>' +
    '<tr><td>OpenID Provider Configuration</td><td><a href="' + esc(profile.urls.oidc) +
    '"><code>' + esc(profile.urls.oidc) + '</code></a></td></tr>' +
    '<tr><td>Last changed</td><td><code>' + esc(profile.changedAt) + '</code></td></tr>' +
    '</table>' +
    (drift.length
      ? '<div class="warn"><strong>' + drift.length + ' member(s) of this document do not ' +
        'describe this service.</strong> That is allowed and is often the point &mdash; but ' +
        'a client configured from this document will behave as though these were true.</div>'
      : '<div class="ok">Every member of this document agrees with what this service would ' +
        'publish. A client configured from it is configured correctly.</div>') +
    '<h2>What this authorization server does</h2>' +
    '<p class="sub">Its effective capabilities — the defaults every authorization server here ' +
    'starts with, plus whatever this one has been given. This IS the document it publishes and ' +
    'it IS what its endpoints enforce; there is no second table that could disagree with it.</p>' +
    '<table><tr><th>Capability</th><th>This server</th><th>Enforced</th></tr>' +
    authorizationServers.MEMBERS.filter(function (row) { return row.enforces; })
      .map(function (row) {
        const value = capabilities[row.name];
        return '<tr><td><code>' + esc(row.name) + '</code></td>' +
          '<td>' + (value === undefined
            ? '<span class="state-none">not published — the check does not run</span>'
            : '<code>' + esc(JSON.stringify(value)) + '</code>') + '</td>' +
          '<td class="sub">' + esc(row.enforces) + '</td></tr>';
      }).join('') +
    '</table>' +
    '<h2>Overridden members</h2>' +
    '<table><tr><th>Member</th><th>Published as</th><th>Agreement</th><th>What it is</th>' +
    '<th></th></tr>' +
    (memberRows || '<tr><td colspan="5">Nothing is overridden, so this document says exactly ' +
                   'what this service says about itself.</td></tr>') + '</table>' +
    (removedRows
      ? '<h2>Removed members</h2><table><tr><th>Member</th><th>What that means</th><th></th></tr>' +
        removedRows + '</table>'
      : '') +
    '<h2>Publish a member</h2>' +
    '<p class="note">The value is read as JSON first and as a plain string if that fails, so ' +
    '<code>["S256"]</code> is a list, <code>false</code> is a boolean and ' +
    '<code>https://example.com/token</code> is a string. <strong>Any member name is accepted</strong> ' +
    '&mdash; the list below is help rather than a schema, and one this service has never heard ' +
    'of is published just the same.</p>' +
    '<form method="post" action="/admin/authorization-servers">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="set">' +
    '<input type="hidden" name="profile" value="' + esc(id) + '">' +
    '<label for="asmember">Member</label>' +
    '<select id="asmember" name="member">' + asMemberOptions('') + '</select>' +
    '<label for="asvalue">as</label>' +
    '<input type="text" id="asvalue" name="value" size="36" placeholder=\'["S256"]\'>' +
    '<button type="submit">Publish</button>' +
    '</div></form>' +
    '<form method="post" action="/admin/authorization-servers">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="set">' +
    '<input type="hidden" name="profile" value="' + esc(id) + '">' +
    '<label for="asother">Or any member</label>' +
    '<input type="text" id="asother" name="member" size="30" required ' +
    'placeholder="a name this service has never heard of">' +
    '<label for="asothervalue">as</label>' +
    '<input type="text" id="asothervalue" name="value" size="26">' +
    '<button type="submit">Publish</button>' +
    '</div></form>' +
    '<h2>Stop publishing a member</h2>' +
    '<form method="post" action="/admin/authorization-servers">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="remove">' +
    '<input type="hidden" name="profile" value="' + esc(id) + '">' +
    '<label for="asrem">Remove</label>' +
    '<select id="asrem" name="member">' + asMemberOptions('code_challenge_methods_supported') +
    '</select>' +
    '<button type="submit">Remove it from the document</button>' +
    '<span class="sub">Different from resetting it: reset undoes an override, this publishes ' +
    'an ABSENCE.</span>' +
    '</div></form>' +
    '<h2>Delete this authorization server</h2>' +
    '<form method="post" action="/admin/authorization-servers">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="delete">' +
    '<input type="hidden" name="profile" value="' + esc(id) + '">' +
    '<button type="submit" class="danger">Delete</button>' +
    '<span class="sub">The two URLs go on answering &mdash; with this service\'s own document ' +
    '&mdash; because an unconfigured path has always been served that way.</span>' +
    '</div></form>' +
    AS_CAVEAT + AS_LINKS;

  log.debug("Leaving asDetailPage(). " + drift.length + " drifting member(s).");
  return { inner: inner, json: Object.assign({ found: true }, profile, { drift: drift }) };
}

function authorizationServersView(req) {
  log.debug("Entering authorizationServersView().");
  const wanted = String(req.query.profile || '').trim();
  if (wanted) {
    const detail = asDetailPage(req, wanted);
    log.debug("Leaving authorizationServersView(). The drill-down.");
    return { json: detail.json, inner: detail.inner,
             title: 'Authorization server ' + wanted,
             up: upTo('/admin/authorization-servers', wanted,
                      listViewOf('/admin/authorization-servers', req.query)) };
  }
  const list = asListPage(req);
  log.debug("Leaving authorizationServersView(). The list.");
  return { json: list.json, inner: list.inner, title: 'Authorization servers' };
}

app.get('/admin/authorization-servers', function (req, res) {
  log.debug("Entering the admin authorization servers page.");
  const view = authorizationServersView(req);
  respond(req, res, view.json, view.title, '/admin/authorization-servers', view.inner,
          view.up);
  log.debug("Leaving the admin authorization servers page.");
});

app.post('/admin/authorization-servers', function (req, res) {
  log.debug("Entering the admin authorization servers action endpoint.");
  const body = parseBody(req);
  const result = asAction(body);
  const id = String(body.profile || body.id || '').trim();
  // The list state the form carried, for the reason the applications action gives.
  const listView = listViewFromBack('/admin/authorization-servers', body.back);
  const back = id && result.ok !== false
    ? '/admin/authorization-servers' + queryWith(listView, { profile: id })
    : '/admin/authorization-servers' + queryWith(listView, {});
  respondToAction(req, res, back, result);
  log.debug("Leaving the admin authorization servers action endpoint.");
});

// ---------------------------------------------------------------------------
// GET /admin/saml2, POST /admin/saml2 — THE SAML 2.0 IDENTITY PROVIDER.
//
// This page exists for ONE question that nothing else here can answer: WHICH
// METADATA DOCUMENT DO I CONFIGURE THIS SERVICE PROVIDER FROM? The profile
// publishes a document PER APPLICATION — a distinct identity provider entityID
// and its own SSO, SLO and artifact endpoints, the way Okta and Ping do it — so
// "the metadata URL" is not one URL, and somebody who has just been handed an
// entityID has no way to derive the slug in its path by hand.
//
// **IT HOLDS NOTHING.** Every row on it comes out of the applications registry,
// which is the embedded directory, and both of its writes go through
// `applications.updateApplication()` — the same function `/admin/applications`
// posts to and the same one an `ldapmodify` reaches. That is the one-store rule
// this console follows everywhere it has been tempted otherwise: a page keeping
// its own copy of a service provider's logout address would be a second answer
// to "where does the LogoutResponse go" that the profile could not see.
//
// **WHY IT IS NOT JUST A FILTER ON /admin/applications**, which was the obvious
// objection and is worth answering rather than leaving: that page reports what
// an application IS and what it has DONE, in the vocabulary of eight protocols
// at once. What a person configuring a service provider needs is four URLs, one
// entityID, and the two settings that decide whether the assertion they are
// about to receive is signed — none of which is a fact about the application at
// all. Three of them are facts about THIS SERVICE. So the drill-down here links
// to that page for the entry and does not reproduce it.
// ---------------------------------------------------------------------------
const SAML2_SP_KIND = 'saml2-service-provider';

// Every application this profile has answered for. Read off the registry rather
// than kept, so a service provider created by an `ldapadd` appears here with no
// help from this file.
function saml2ServiceProviders() {
  log.debug("Entering saml2ServiceProviders().");
  const rows = applications.list().filter(function (row) {
    return row.kinds.indexOf(SAML2_SP_KIND) >= 0;
  });
  log.debug("Leaving saml2ServiceProviders(). " + rows.length + " service provider(s).");
  return rows;
}

// One service provider's four URLs and its entityID, from the profile's own
// functions. Never rebuilt here — see the require at the top of this file.
function saml2Facts(base, identifier) {
  const where = saml2.endpointsFor(base, identifier);
  return {
    identifier: identifier,
    slug: saml2.slugOf(identifier),
    idpEntityId: saml2.idpEntityIdFor(identifier),
    metadataUrl: where.metadata,
    ssoUrl: where.sso,
    sloUrl: where.slo,
    arsUrl: where.ars
  };
}

// The settings that decide what a service provider receives. They are on this
// page as READINGS with a link to the one form that changes them, and not as a
// second form: `/admin/config` owns every setting in this service, and a second
// door onto one of them is exactly what /admin/scim's header refuses. The
// difference from /admin/token-lifetimes — which IS a second door, and argued
// for it — is that these are set once when a service provider is integrated,
// not turned up and down inside a session to watch something happen.
const SAML2_SETTINGS = ['saml2.entityId', 'saml2.perApplicationEntityId',
                        'saml2.assertionLifetimeMin', 'saml2.signAssertion',
                        'saml2.signResponse', 'saml2.nameIdFormat',
                        'saml2.artifactTtlS', 'saml2.autocreateApplications',
                        'saml2.defaultSingleLogoutService'];

function saml2SettingRows() {
  return SAML2_SETTINGS.map(function (key) {
    // `describe()` takes the SETTING and not its key — `configSettingFor()` is
    // the lookup this file already uses everywhere else it reads one, and
    // passing the key straight in throws rather than answering.
    const described = config.describe(configSettingFor(key));
    return '<tr><td><code>' + esc(key) + '</code></td>' +
      '<td>' + esc(String(config.value(key))) + '</td>' +
      '<td>' + esc(described.label || '') + '</td></tr>';
  }).join('');
}

function saml2ListPage(req) {
  log.debug("Entering saml2ListPage().");
  const base = baseUrlOf(req);
  const all = saml2ServiceProviders();
  const needle = String(req.query.q || '').trim().toLowerCase();
  const filtered = needle
    ? all.filter(function (row) {
        return row.identifier.toLowerCase().indexOf(needle) >= 0 ||
               String(row.name).toLowerCase().indexOf(needle) >= 0;
      })
    : all;
  const paged = pagedRows(req.query, filtered, { noun: 'service providers' });
  const paging = paged.paging;
  const filterParams = { q: String(req.query.q || '') || '',
                         per: req.query.per ? paging.perPage : '' };
  const nav = pageNav('/admin/saml2', filterParams, paging);
  const listView = listViewOf('/admin/saml2', req.query);

  const rows = paged.shown.map(function (row) {
    const facts = saml2Facts(base, row.identifier);
    const href = '/admin/saml2' + queryWith(listView, { sp: row.identifier });
    const acs = row.fields.samlAssertionConsumerService;
    const slo = row.fields.samlSingleLogoutService;
    return '<tr><td><a href="' + esc(href) + '"><code>' + esc(row.identifier) + '</code></a>' +
      '<div class="sub">its identity provider: <code>' + esc(facts.idpEntityId) + '</code></div>' +
      '</td>' +
      '<td><a href="' + esc(facts.metadataUrl) + '">metadata</a></td>' +
      '<td>' + (acs ? codeList(Array.isArray(acs) ? acs : [acs]) : '<span class="sub">none seen</span>') +
      '</td>' +
      '<td>' + (slo ? codeList(Array.isArray(slo) ? slo : [slo])
                    : '<span class="sub">not declared &mdash; guessed</span>') + '</td>' +
      '<td>' + esc(String(row.authentications)) + '</td>' +
      '<td>' + esc(row.lastSeen ? row.lastSeen.replace('T', ' ').slice(0, 19) : '') + '</td></tr>';
  }).join('');

  const inner = '<h1>SAML 2.0 identity provider</h1>' +
    '<p class="sub">The Web Browser SSO profile, all three bindings, and Single Logout. This ' +
    'page holds nothing: every row is an entry in <code>ou=applications</code>.</p>' +
    '<p class="note"><strong>Every service provider gets its own metadata document.</strong> The ' +
    'identity provider names itself differently to each one and publishes endpoints scoped to it, ' +
    'which is what Okta and Ping do. <strong>And it is minted for anything asked for</strong> — a ' +
    'service provider does not have to appear here before it can be pointed at this service, ' +
    'because asking for its metadata is what creates it. The unscoped document at ' +
    '<a href="/saml2/metadata">/saml2/metadata</a> works too and names one identity provider for ' +
    'everybody.</p>' +
    '<p class="sub"><a href="/saml2">what the profile is</a> &middot; ' +
    '<a href="/saml2/sp">the mock service provider</a> &middot; ' +
    '<a href="/admin/saml-attributes">what goes into an assertion</a> &middot; ' +
    '<a href="/admin/applications?kind=' + SAML2_SP_KIND + '">these entries on the applications ' +
    'page</a></p>' +
    '<form method="get" action="/admin/saml2"><div class="formrow">' +
    '<label for="q">Search</label>' +
    '<input type="text" id="q" name="q" value="' + esc(String(req.query.q || '')) + '" ' +
    'placeholder="an entityID or a name">' +
    (req.query.per ? '<input type="hidden" name="per" value="' + esc(paging.perPage) + '">' : '') +
    '<button class="secondary">Filter</button>' +
    (String(req.query.q || '') ? ' <a href="/admin/saml2">clear</a>' : '') +
    '</div></form>' +
    nav +
    (rows
      ? '<table><thead><tr><th>Service provider (entityID)</th><th>Its metadata</th>' +
        '<th>Assertion consumer service</th><th>Single logout service</th>' +
        '<th>Responses</th><th>Last seen</th></tr></thead><tbody>' + rows + '</tbody></table>' + nav
      : '<p>No service provider has used this profile yet' +
        (needle ? ' under that filter' : '') + '. Start one at ' +
        '<a href="/saml2/sp">the mock service provider</a>, or register an entityID below.</p>') +
    '<h2>Register a service provider</h2>' +
    '<p class="sub">Optional, and it changes nothing about whether a request is accepted — an ' +
    'entityID is accepted whether or not it is here. What it buys is a metadata document to hand ' +
    'somebody before they have sent anything.</p>' +
    '<form method="post" action="/admin/saml2"><div class="formrow">' +
    '<input type="hidden" name="action" value="register">' +
    '<label for="new_sp">entityID</label>' +
    '<input type="text" id="new_sp" name="sp" placeholder="https://sp.example.com/saml">' +
    '<button>Register</button>' +
    '<span class="note">The same thing a request or a metadata fetch would do.</span>' +
    '</div></form>' +
    '<h2>What every assertion this profile issues is governed by</h2>' +
    '<table><thead><tr><th>Setting</th><th>Value</th><th>What it is</th></tr></thead><tbody>' +
    saml2SettingRows() + '</tbody></table>' +
    '<p class="sub">Readings, not a form: <a href="/admin/config">the configuration page</a> owns ' +
    'every setting here, and a second door onto one of them is what this console refuses ' +
    'elsewhere. <a href="/admin/saml-attributes">Custom SAML attributes</a> is the page that ' +
    'changes what an assertion CONTAINS, and its SAML 2.0 set reaches this profile through the ' +
    'same assertion builder that serves WS-Trust and WS-Federation.</p>' +
    perPageForm('/admin/saml2', 'q', String(req.query.q || ''), paging.perPage, '', {});

  log.debug("Leaving saml2ListPage(). " + paged.shown.length + " row(s) of " +
            filtered.length + ".");
  return {
    inner: inner,
    json: {
      serviceProviders: paged.shown.map(function (row) {
        return Object.assign(saml2Facts(base, row.identifier), {
          name: row.name, authentications: row.authentications, sessions: row.sessions,
          users: row.users, firstSeen: row.firstSeen, lastSeen: row.lastSeen,
          assertionConsumerServices: valuesFor(row.fields.samlAssertionConsumerService),
          singleLogoutServices: valuesFor(row.fields.samlSingleLogoutService),
          nameIdFormats: valuesFor(row.fields.samlNameIdFormat),
          responseBindings: valuesFor(row.fields.samlResponseBinding),
          lastRequestSigned: row.fields.samlAuthnRequestSigned === 'TRUE'
        });
      }),
      paging: paging,
      unscopedMetadata: saml2Facts(base, '').metadataUrl,
      settings: SAML2_SETTINGS.reduce(function (out, key) {
        out[key] = config.value(key);
        return out;
      }, {}),
      // Two numbers about the PROFILE rather than about any one service
      // provider, and both are the kind of thing that is invisible until it is
      // wrong: artifacts waiting to be resolved, and AuthnRequests held while a
      // browser is at the sign-in screen. A count that never falls is a leak.
      artifactsAwaitingResolution: saml2.artifactCount(),
      requestsHeldForSignIn: saml2.pendingRequestCount()
    }
  };
}

// An attribute's values as a plain array whatever the schema's `kind` is. The
// registry hands back a string for a single-valued attribute and an array for a
// multi-valued one, and a JSON reply that varied between the two shapes would be
// one a caller has to test the type of.
function valuesFor(value) {
  if (value === undefined || value === null || value === '') {
    return [];
  }
  return Array.isArray(value) ? value.slice(0) : [String(value)];
}

function saml2DetailPage(req, identifier) {
  log.debug("Entering saml2DetailPage(). sp=" + identifier);
  const base = baseUrlOf(req);
  const facts = saml2Facts(base, identifier);
  const row = applications.get(identifier);
  const listView = listViewOf('/admin/saml2', req.query);
  const carryBack = '<input type="hidden" name="back" value="' +
    esc(queryWith(listView, {})) + '">';
  const fields = (row && row.fields) || {};
  const acs = valuesFor(fields.samlAssertionConsumerService);
  const slo = valuesFor(fields.samlSingleLogoutService);

  const endpointRows = [
    ['entityID of the identity provider', facts.idpEntityId,
     config.value('saml2.perApplicationEntityId')
       ? 'Unique to this service provider. saml2.perApplicationEntityId turns that off, and then ' +
         'every document names the same identity provider.'
       : 'The same for every service provider, because saml2.perApplicationEntityId is off. The ' +
         'ENDPOINTS below are still this service provider\'s own.'],
    ['Metadata', facts.metadataUrl, 'Signed, and served no-store because the signing key is ' +
     'regenerated on every start. This is the URL to configure the service provider from.'],
    ['Single Sign-On', facts.ssoUrl, 'HTTP Redirect and HTTP POST both. Which binding the ' +
     'RESPONSE comes back on is the AuthnRequest\'s own ProtocolBinding.'],
    ['Single Logout', facts.sloUrl, 'A LogoutRequest arriving from this service provider, and a ' +
     'bare GET to start one from here.'],
    ['Artifact Resolution', facts.arsUrl, 'SOAP over HTTP, and a back channel: the browser never ' +
     'touches it. An artifact resolves exactly once.']
  ].map(function (r) {
    return '<tr><td>' + esc(r[0]) + '</td><td><code>' + esc(r[1]) + '</code></td>' +
      '<td class="sub">' + esc(r[2]) + '</td></tr>';
  }).join('');

  const inner = '<h1><code>' + esc(identifier) + '</code></h1>' +
    '<p class="sub">A SAML 2.0 service provider. Its entry is ' +
    (row ? '<a href="/admin/applications?application=' + encodeURIComponent(identifier) +
           '">in the applications registry</a>'
         : 'NOT in the registry yet — this page is showing what it WOULD be given') + '.</p>' +
    '<h2>The endpoints it is configured from</h2>' +
    '<table><thead><tr><th>What</th><th>Where</th><th></th></tr></thead><tbody>' +
    endpointRows + '</tbody></table>' +
    '<p class="sub">The path segment is <code>' + esc(facts.slug) + '</code>' +
    (facts.slug === identifier ? '' :
      ', which is a digest of the entityID because the entityID is not safe in a URL path ' +
      'segment. The percent-encoded entityID works in the same place') + '.</p>' +
    '<h2>What this service has recorded</h2>' +
    '<table><tbody>' +
    '<tr><td>Assertion consumer services seen</td><td>' +
      (acs.length ? codeList(acs) : '<span class="sub">none</span>') + '</td></tr>' +
    '<tr><td>NameID formats asked for</td><td>' +
      (valuesFor(fields.samlNameIdFormat).length
        ? codeList(valuesFor(fields.samlNameIdFormat))
        : '<span class="sub">none — it has never named one, so it gets saml2.nameIdFormat</span>') +
      '</td></tr>' +
    '<tr><td>Response bindings asked for</td><td>' +
      (valuesFor(fields.samlResponseBinding).length
        ? codeList(valuesFor(fields.samlResponseBinding)) : '<span class="sub">none</span>') +
      '</td></tr>' +
    '<tr><td>Its last AuthnRequest was signed</td><td>' +
      (fields.samlAuthnRequestSigned === 'TRUE' ? 'yes' :
        (fields.samlAuthnRequestSigned === 'FALSE' ? 'no' : '<span class="sub">unknown</span>')) +
      ' <span class="sub">&mdash; RECORDED AND NOT CHECKED. This service verifies no request ' +
      'signature, which is the same posture it takes to every credential; the certificate below ' +
      'is what a verification would read.</span></td></tr>' +
    '<tr><td>Responses issued to it</td><td>' + esc(String((row && row.authentications) || 0)) +
      '</td></tr>' +
    '</tbody></table>' +
    '<h2>Where its LogoutResponse goes</h2>' +
    '<p class="note">A <code>&lt;samlp:LogoutRequest&gt;</code> carries no return address — only ' +
    'SP metadata does, and this service does not consume SP metadata. So with nothing declared ' +
    'here the profile falls back to <code>saml2.defaultSingleLogoutService</code> and then to the ' +
    'assertion consumer service URL this service provider last used, <strong>which is a guess and ' +
    'is logged as one</strong>. Declaring it removes the guess.</p>' +
    (slo.length
      ? '<table><thead><tr><th>Declared</th><th></th></tr></thead><tbody>' +
        slo.map(function (one) {
          return '<tr><td><code>' + esc(one) + '</code></td><td>' +
            '<form method="post" action="/admin/saml2">' + carryBack +
            '<input type="hidden" name="action" value="remove-logout-service">' +
            '<input type="hidden" name="sp" value="' + esc(identifier) + '">' +
            '<input type="hidden" name="value" value="' + esc(one) + '">' +
            '<button class="secondary">Remove</button></form></td></tr>';
        }).join('') + '</tbody></table>'
      : '<p>Nothing is declared, so the fallback above applies' +
        (acs.length ? ' — and it would guess <code>' + esc(acs[acs.length - 1]) + '</code>' : '') +
        '.</p>') +
    '<form method="post" action="/admin/saml2">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="set-logout-service">' +
    '<input type="hidden" name="sp" value="' + esc(identifier) + '">' +
    '<label for="slo">Add one</label>' +
    '<input type="text" id="slo" name="value" placeholder="https://sp.example.com/saml/slo">' +
    '<button>Add</button>' +
    '<span class="note">Writes <code>samlSingleLogoutService</code> on the entry. An ' +
    '<code>ldapmodify</code> of the same attribute does exactly this.</span>' +
    '</div></form>' +
    '<h2>Its signing certificate</h2>' +
    '<p class="sub">Taken off the <code>ds:KeyInfo</code> of a signed AuthnRequest when one ' +
    'carries it, and settable here. It is public key material, so unlike a client secret it is ' +
    'worth nothing to whoever reads this directory — and nothing reads it today, because no ' +
    'request signature is verified. It is here so that a verification has somewhere to read from ' +
    'the day one is wanted.</p>' +
    (fields.samlSigningCertificate
      ? '<pre>' + esc(String(fields.samlSigningCertificate).replace(/(.{72})/g, '$1\n')) + '</pre>'
      : '<p>None recorded.</p>') +
    '<form method="post" action="/admin/saml2">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="set-signing-certificate">' +
    '<input type="hidden" name="sp" value="' + esc(identifier) + '">' +
    '<label for="cert">Set it</label>' +
    '<input type="text" id="cert" name="value" placeholder="base64 DER, no PEM header">' +
    '<button>Set</button>' +
    '<span class="note">Empty clears it.</span>' +
    '</div></form>' +
    '<p class="sub"><a href="' + esc(facts.metadataUrl) + '">its metadata</a> &middot; ' +
    '<a href="/saml2">the profile</a>' +
    (row ? ' &middot; <a href="/admin/applications?application=' +
           encodeURIComponent(identifier) + '">its registry entry, with every attribute</a>' : '') +
    '</p>';

  log.debug("Leaving saml2DetailPage().");
  return {
    inner: inner,
    json: Object.assign({ found: !!row }, facts, {
      name: (row && row.name) || '',
      authentications: (row && row.authentications) || 0,
      assertionConsumerServices: acs,
      singleLogoutServices: slo,
      nameIdFormats: valuesFor(fields.samlNameIdFormat),
      responseBindings: valuesFor(fields.samlResponseBinding),
      lastRequestSigned: fields.samlAuthnRequestSigned === 'TRUE',
      signingCertificate: fields.samlSigningCertificate || ''
    })
  };
}

// The four writes. Every one of them goes through the applications registry —
// see the header — so this function decides nothing except which attribute and
// which mode, and the registry refuses an attribute that is derived rather than
// declared without being asked twice.
function saml2Action(body) {
  log.debug("Entering saml2Action(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const identifier = String(body.sp || body.serviceProvider || '').trim();
  if (!identifier) {
    log.debug("Leaving saml2Action(). No service provider named.");
    return { ok: false, errors: ['Name the service provider by its entityID, in `sp`.'] };
  }

  if (action === 'register') {
    const result = applications.createApplication({
      identifier: identifier, kind: SAML2_SP_KIND, protocol: 'SAML 2.0',
      note: 'registered as a SAML 2.0 service provider from the admin console',
      fields: { samlEntityId: identifier }
    });
    log.debug("Leaving saml2Action(). register " + (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) return result;
    return { ok: true, application: result.application,
             message: 'Registered. Its identity provider metadata is at /saml2/metadata/' +
                      encodeURIComponent(saml2.slugOf(identifier)) + ', and it would have been ' +
                      'created by the first AuthnRequest or metadata fetch anyway — registering ' +
                      'it early is what gives you a document to hand somebody now.' };
  }
  if (action === 'set-logout-service' || action === 'remove-logout-service') {
    const result = applications.updateApplication(identifier, {
      attribute: 'samlSingleLogoutService',
      mode: action === 'set-logout-service' ? 'add' : 'remove',
      value: String(body.value || '')
    });
    log.debug("Leaving saml2Action(). " + action + " " + (result.ok ? 'ok' : 'refused') + ".");
    return result;
  }
  if (action === 'set-signing-certificate') {
    const result = applications.updateApplication(identifier, {
      attribute: 'samlSigningCertificate', mode: 'set',
      // Whitespace and any PEM armour stripped, because what the schema holds is
      // base64 DER — which is what a ds:X509Certificate carries and what the
      // metadata publishes. A PEM pasted in here would be stored as something no
      // reader of that attribute expects, and nothing would say so until the day
      // something tried to use it.
      value: String(body.value || '').replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')
    });
    log.debug("Leaving saml2Action(). set-signing-certificate " +
              (result.ok ? 'ok' : 'refused') + ".");
    return result;
  }
  log.debug("Leaving saml2Action(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The four are: register, ' +
                               'set-logout-service, remove-logout-service, ' +
                               'set-signing-certificate.'] };
}

function saml2View(req) {
  log.debug("Entering saml2View().");
  const wanted = String(req.query.sp || '').trim();
  if (wanted) {
    const detail = saml2DetailPage(req, wanted);
    log.debug("Leaving saml2View(). The drill-down.");
    return { json: detail.json, inner: detail.inner,
             title: 'SAML 2.0 service provider ' + wanted,
             up: upTo('/admin/saml2', wanted, listViewOf('/admin/saml2', req.query)) };
  }
  const list = saml2ListPage(req);
  log.debug("Leaving saml2View(). The list.");
  return { json: list.json, inner: list.inner, title: 'SAML 2.0 identity provider' };
}

app.get('/admin/saml2', function (req, res) {
  log.debug("Entering the admin SAML 2.0 page.");
  const view = saml2View(req);
  respond(req, res, view.json, view.title, '/admin/saml2', view.inner, view.up);
  log.debug("Leaving the admin SAML 2.0 page.");
});

app.post('/admin/saml2', function (req, res) {
  log.debug("Entering the admin SAML 2.0 action endpoint.");
  const body = parseBody(req);
  const result = saml2Action(body);
  const identifier = String(body.sp || body.serviceProvider || '').trim();
  // The list state the form carried, REBUILT rather than echoed — see
  // listViewFromBack(), and the note in admin-ui/CLAUDE.md about a new form on a
  // drill-down needing `carryBack` in it.
  const listView = listViewFromBack('/admin/saml2', body.back);
  const back = identifier && result.ok !== false
    ? '/admin/saml2' + queryWith(listView, { sp: identifier })
    : '/admin/saml2' + queryWith(listView, {});
  respondToAction(req, res, back, result);
  log.debug("Leaving the admin SAML 2.0 action endpoint.");
});

// ---------------------------------------------------------------------------
// GET /admin/saml11, POST /admin/saml11 — THE SAML 1.1 IDENTITY PROVIDER.
//
// The same question /admin/saml2 exists for — WHICH METADATA DOCUMENT DO I
// CONFIGURE THIS RELYING PARTY FROM — and a second question that page never has
// to answer: **WHAT IS THIS RELYING PARTY CALLED?** SAML 1.1 has no request
// message, so nothing in the protocol makes a relying party identify itself. The
// profile takes the name from Shibboleth's `providerId` parameter, from the path
// segment, or it GUESSES from the origin of the TARGET. A guessed audience is
// the one thing on this page that is not a fact, and it is marked as such,
// because an assertion whose audience is `https://app.example.com` when the
// relying party expected `urn:example:app` fails inside a signature check with
// nothing saying why.
//
// **IT IS A SEPARATE PAGE FROM /admin/saml2 AND THAT IS NOT SYMMETRY FOR ITS OWN
// SAKE**, which was the obvious objection: half of what that page reports has no
// spelling here. There is no Single Logout in SAML 1.1, so there is no logout
// return address to declare and no `saml11.defaultSingleLogoutService` to fall
// back to. There is no request, so there is no request signature to record and
// no signing certificate to hold. What this page has instead is the artifact
// profile's own state and an attribute authority the 2.0 profile does not offer.
// One page with two modes would have been a page whose every row needed a
// footnote.
//
// **IT HOLDS NOTHING**, like every page in this console: every row comes out of
// the applications registry, which is the embedded directory, and its one write
// goes through `applications.createApplication()` — the same function
// /admin/applications posts to and the same one an `ldapadd` reaches.
// ---------------------------------------------------------------------------
const SAML11_RP_KIND = saml11.RP_KIND;

// Every application this profile has answered for. Read off the registry rather
// than kept, so a relying party created by an `ldapadd` appears here with no
// help from this file.
//
// **THE KIND IS SHARED WITH WS-FEDERATION AND THAT IS DELIBERATE.**
// `saml11-relying-party` is what a WS-Federation relying party handed a 1.1
// assertion has always been recorded as, and a relying party that takes the same
// assertion through the passive requestor profile and through Browser/POST is
// ONE application with one audience. Giving the browser profiles a kind of their
// own would have split one entry into two, which is the defect this repository
// calls two spellings of one DN. The consequence to know when reading this list:
// a row here may have arrived through /wsfed and never touched /saml11, which is
// why the profiles column says what it has actually used.
function saml11RelyingParties() {
  log.debug("Entering saml11RelyingParties().");
  const rows = applications.list().filter(function (row) {
    return row.kinds.indexOf(SAML11_RP_KIND) >= 0;
  });
  log.debug("Leaving saml11RelyingParties(). " + rows.length + " relying party/parties.");
  return rows;
}

// One relying party's three URLs and its providerID, from the profile's own
// functions. Never rebuilt here — see the require at the top of this file.
function saml11Facts(base, identifier) {
  const where = saml11.endpointsFor(base, identifier);
  return {
    identifier: identifier,
    slug: saml11.slugOf(identifier),
    idpProviderId: saml11.providerIdFor(identifier),
    metadataUrl: where.metadata,
    ssoUrl: where.sso,
    responderUrl: where.responder
  };
}

// Which of the two browser profiles a recorded binding value names, in words. The
// registry holds the profile URI, which is what the metadata publishes and what
// a person reading a table does not want to compare character by character.
function saml11ProfileLabel(value) {
  if (value === saml11.PROFILE_POST) {
    return 'Browser/POST';
  }
  if (value === saml11.PROFILE_ARTIFACT) {
    return 'Browser/Artifact';
  }
  return value;
}

// The settings that decide what a relying party receives. READINGS with a link
// to the one form that changes them, and not a second form: /admin/config owns
// every setting in this service, which is the rule /admin/saml2 states at length
// and this page follows rather than restating.
const SAML11_SETTINGS = ['saml11.providerId', 'saml11.perApplicationProviderId',
                         'saml11.assertionLifetimeMin', 'saml11.signAssertion',
                         'saml11.signResponse', 'saml11.nameIdFormat',
                         'saml11.defaultProfile', 'saml11.artifactTtlS',
                         'saml11.autocreateApplications'];

function saml11SettingRows() {
  return SAML11_SETTINGS.map(function (key) {
    // `describe()` takes the SETTING and not its key — the same trap
    // saml2SettingRows() records.
    const described = config.describe(configSettingFor(key));
    return '<tr><td><code>' + esc(key) + '</code></td>' +
      '<td>' + esc(String(config.value(key))) + '</td>' +
      '<td>' + esc(described.label || '') + '</td></tr>';
  }).join('');
}

function saml11ListPage(req) {
  log.debug("Entering saml11ListPage().");
  const base = baseUrlOf(req);
  const all = saml11RelyingParties();
  const needle = String(req.query.q || '').trim().toLowerCase();
  const filtered = needle
    ? all.filter(function (row) {
        return row.identifier.toLowerCase().indexOf(needle) >= 0 ||
               String(row.name).toLowerCase().indexOf(needle) >= 0;
      })
    : all;
  const paged = pagedRows(req.query, filtered, { noun: 'relying parties' });
  const paging = paged.paging;
  const filterParams = { q: String(req.query.q || '') || '',
                         per: req.query.per ? paging.perPage : '' };
  const nav = pageNav('/admin/saml11', filterParams, paging);
  const listView = listViewOf('/admin/saml11', req.query);

  const rows = paged.shown.map(function (row) {
    const facts = saml11Facts(base, row.identifier);
    const href = '/admin/saml11' + queryWith(listView, { rp: row.identifier });
    const acs = row.fields.samlAssertionConsumerService;
    const profiles = valuesFor(row.fields.samlResponseBinding)
      .filter(function (v) {
        return v === saml11.PROFILE_POST || v === saml11.PROFILE_ARTIFACT;
      })
      .map(saml11ProfileLabel);
    return '<tr><td><a href="' + esc(href) + '"><code>' + esc(row.identifier) + '</code></a>' +
      '<div class="sub">its identity provider: <code>' + esc(facts.idpProviderId) + '</code></div>' +
      '</td>' +
      '<td><a href="' + esc(facts.metadataUrl) + '">metadata</a></td>' +
      '<td>' + (acs ? codeList(Array.isArray(acs) ? acs : [acs])
                    : '<span class="sub">none seen</span>') + '</td>' +
      '<td>' + (profiles.length ? esc(profiles.join(', '))
                                : '<span class="sub">none &mdash; it has only ever been handed a ' +
                                  '1.1 assertion through another door</span>') + '</td>' +
      '<td>' + esc(String(row.authentications)) + '</td>' +
      '<td>' + esc(row.lastSeen ? row.lastSeen.replace('T', ' ').slice(0, 19) : '') + '</td></tr>';
  }).join('');

  const inner = '<h1>SAML 1.1 identity provider</h1>' +
    '<p class="sub">Both browser profiles, and the SAML responder behind one of them. This page ' +
    'holds nothing: every row is an entry in <code>ou=applications</code>.</p>' +
    '<p class="note"><strong>SAML 1.1 has no request message</strong>, which is where most of ' +
    'the differences from <a href="/admin/saml2">the SAML 2.0 page</a> come from. A relying ' +
    'party cannot identify itself in the protocol, so it is named by Shibboleth\'s ' +
    '<code>providerId</code> parameter, by the path segment of a scoped endpoint, or it is ' +
    'GUESSED from the origin of the <code>TARGET</code>. There is also no Single Logout to ' +
    'configure &mdash; it arrived with SAML 2.0 &mdash; and no request signature to record.</p>' +
    '<p class="note"><strong>Every relying party gets its own metadata document</strong>, minted ' +
    'for anything asked for, exactly as the 2.0 profile does. It is a SAML 2.0 metadata document ' +
    'describing a SAML 1.1 identity provider, which is what every relying party actually ' +
    'consumes: SAML 1.1 never had a metadata specification. The unscoped document at ' +
    '<a href="/saml11/metadata">/saml11/metadata</a> works too and names one identity provider ' +
    'for everybody.</p>' +
    '<p class="sub"><a href="/saml11">what the profile is</a> &middot; ' +
    '<a href="/saml11/rp">the mock relying party</a> &middot; ' +
    '<a href="/admin/saml-attributes">what goes into an assertion</a> &middot; ' +
    '<a href="/admin/applications?kind=' + SAML11_RP_KIND + '">these entries on the applications ' +
    'page</a></p>' +
    '<form method="get" action="/admin/saml11"><div class="formrow">' +
    '<label for="q">Search</label>' +
    '<input type="text" id="q" name="q" value="' + esc(String(req.query.q || '')) + '" ' +
    'placeholder="an identifier or a name">' +
    (req.query.per ? '<input type="hidden" name="per" value="' + esc(paging.perPage) + '">' : '') +
    '<button class="secondary">Filter</button>' +
    (String(req.query.q || '') ? ' <a href="/admin/saml11">clear</a>' : '') +
    '</div></form>' +
    nav +
    (rows
      ? '<table><thead><tr><th>Relying party</th><th>Its metadata</th>' +
        '<th>Assertion consumer (shire)</th><th>Profiles used</th>' +
        '<th>Assertions</th><th>Last seen</th></tr></thead><tbody>' + rows + '</tbody></table>' + nav
      : '<p>No relying party has taken a SAML 1.1 assertion yet' +
        (needle ? ' under that filter' : '') + '. Start one at ' +
        '<a href="/saml11/rp">the mock relying party</a>, or register an identifier below.</p>') +
    '<h2>Register a relying party</h2>' +
    '<p class="sub">Optional, and it changes nothing about whether a flow is accepted &mdash; any ' +
    'identifier is accepted whether or not it is here. What it buys is a metadata document to ' +
    'hand somebody before they have sent anything, and a name to use in ' +
    '<code>providerId</code> so that nothing has to be guessed.</p>' +
    '<form method="post" action="/admin/saml11"><div class="formrow">' +
    '<input type="hidden" name="action" value="register">' +
    '<label for="new_rp">Identifier</label>' +
    '<input type="text" id="new_rp" name="rp" placeholder="urn:example:app">' +
    '<button>Register</button>' +
    '<span class="note">The same thing a flow or a metadata fetch would do.</span>' +
    '</div></form>' +
    '<h2>What every assertion this profile issues is governed by</h2>' +
    '<table><thead><tr><th>Setting</th><th>Value</th><th>What it is</th></tr></thead><tbody>' +
    saml11SettingRows() + '</tbody></table>' +
    '<p class="sub">Readings, not a form: <a href="/admin/config">the configuration page</a> owns ' +
    'every setting here. <a href="/admin/saml-attributes">Custom SAML attributes</a> is the page ' +
    'that changes what an assertion CONTAINS, and its SAML 1.1 set reaches this profile through ' +
    'the same assertion builder that serves WS-Trust and WS-Federation.</p>' +
    perPageForm('/admin/saml11', 'q', String(req.query.q || ''), paging.perPage, '', {});

  log.debug("Leaving saml11ListPage(). " + paged.shown.length + " row(s) of " +
            filtered.length + ".");
  return {
    inner: inner,
    json: {
      relyingParties: paged.shown.map(function (row) {
        return Object.assign(saml11Facts(base, row.identifier), {
          name: row.name, authentications: row.authentications, sessions: row.sessions,
          users: row.users, firstSeen: row.firstSeen, lastSeen: row.lastSeen,
          assertionConsumerServices: valuesFor(row.fields.samlAssertionConsumerService),
          nameIdFormats: valuesFor(row.fields.samlNameIdFormat),
          profiles: valuesFor(row.fields.samlResponseBinding).filter(function (v) {
            return v === saml11.PROFILE_POST || v === saml11.PROFILE_ARTIFACT;
          })
        });
      }),
      paging: paging,
      unscopedMetadata: saml11Facts(base, '').metadataUrl,
      settings: SAML11_SETTINGS.reduce(function (out, key) {
        out[key] = config.value(key);
        return out;
      }, {}),
      // Three numbers about the PROFILE rather than about any one relying party,
      // and all three are the kind of thing that is invisible until it is wrong:
      // artifacts minted and not yet resolved, assertions held for an
      // AssertionIDReference, and flows held while a browser is at the sign-in
      // screen. A count that never falls is a leak; the middle one is CAPPED
      // rather than swept, so it is the one that should sit at its ceiling.
      artifactsAwaitingResolution: saml11.artifactCount(),
      assertionsHeldByReference: saml11.cachedAssertionCount(),
      flowsHeldForSignIn: saml11.pendingFlowCount()
    }
  };
}

function saml11DetailPage(req, identifier) {
  log.debug("Entering saml11DetailPage(). rp=" + identifier);
  const base = baseUrlOf(req);
  const facts = saml11Facts(base, identifier);
  const row = applications.get(identifier);
  const fields = (row && row.fields) || {};
  const acs = valuesFor(fields.samlAssertionConsumerService);
  const profiles = valuesFor(fields.samlResponseBinding).filter(function (v) {
    return v === saml11.PROFILE_POST || v === saml11.PROFILE_ARTIFACT;
  });

  const endpointRows = [
    ['providerID of the identity provider', facts.idpProviderId,
     config.value('saml11.perApplicationProviderId')
       ? 'Unique to this relying party. saml11.perApplicationProviderId turns that off, and then ' +
         'every document names the same identity provider — and every artifact carries the same ' +
         'SourceID, because that is a hash of this value.'
       : 'The same for every relying party, because saml11.perApplicationProviderId is off. The ' +
         'ENDPOINTS below are still this relying party\'s own.'],
    ['Metadata', facts.metadataUrl,
     'Signed, and served no-store because the signing key is regenerated on every start. This is ' +
     'the URL to configure the relying party from. It carries an IDPSSODescriptor for the browser ' +
     'profiles AND an AttributeAuthorityDescriptor for the responder, because a Shibboleth ' +
     'service provider looks for its attribute authority in the second.'],
    ['Inter-site transfer', facts.ssoUrl,
     'Where a browser is sent to be signed in. SAML 1.1\'s name for what SAML 2.0 calls the ' +
     'Single Sign-On service. Send TARGET, and shire for where the assertion goes.'],
    ['SAML responder', facts.responderUrl,
     'SOAP over HTTP POST, and a back channel: the browser never touches it. It resolves ' +
     'artifacts (once each), returns assertions by AssertionID, and answers AttributeQuery and ' +
     'AuthenticationQuery — which is SAML 1.1\'s attribute authority.']
  ].map(function (r) {
    return '<tr><td>' + esc(r[0]) + '</td><td><code>' + esc(r[1]) + '</code></td>' +
      '<td class="sub">' + esc(r[2]) + '</td></tr>';
  }).join('');

  // A relying party whose identifier looks like a bare origin is very likely one
  // this service GUESSED, and saying so here is the whole reason the guess is
  // survivable. It is a heuristic and is worded as one: somebody may perfectly
  // well have registered `https://app.example.com` on purpose.
  const looksGuessed = /^https?:\/\/[^/]+$/i.test(identifier);

  const inner = '<h1><code>' + esc(identifier) + '</code></h1>' +
    '<p class="sub">A SAML 1.1 relying party. Its entry is ' +
    (row ? '<a href="/admin/applications?application=' + encodeURIComponent(identifier) +
           '">in the applications registry</a>'
         : 'NOT in the registry yet — this page is showing what it WOULD be given') + '.</p>' +
    (looksGuessed
      ? '<p class="note"><strong>This identifier is a bare origin, which is what this service ' +
        'writes down when nobody told it the relying party\'s name.</strong> SAML 1.1 has no ' +
        'request message, so a flow that sent no <code>providerId</code> and used no scoped ' +
        'endpoint leaves the audience to be guessed from the origin of the TARGET. The assertion ' +
        'is issued to THIS string, so a relying party expecting a different audience refuses it ' +
        'inside a signature check with nothing saying why. Send <code>providerId</code>, or use ' +
        'the scoped endpoint above, to make it exact.</p>'
      : '') +
    '<h2>The endpoints it is configured from</h2>' +
    '<table><thead><tr><th>What</th><th>Where</th><th></th></tr></thead><tbody>' +
    endpointRows + '</tbody></table>' +
    '<p class="sub">The path segment is <code>' + esc(facts.slug) + '</code>' +
    (facts.slug === identifier ? '' :
      ', which is a digest of the identifier because the identifier is not safe in a URL path ' +
      'segment. The percent-encoded identifier works in the same place') +
    '. It is THE SAME SLUG <a href="/admin/saml2">the SAML 2.0 profile</a> uses for this ' +
    'application, deliberately: one application has one handle, or the console would show one ' +
    'entry as two.</p>' +
    '<h2>What this service has recorded</h2>' +
    '<table><tbody>' +
    '<tr><td>Assertion consumers seen</td><td>' +
      (acs.length ? codeList(acs) : '<span class="sub">none</span>') +
      ' <span class="sub">&mdash; the <code>shire</code> parameter. Not checked against any ' +
      'registration, like every other return URL here.</span></td></tr>' +
    '<tr><td>Browser profiles used</td><td>' +
      (profiles.length ? esc(profiles.map(saml11ProfileLabel).join(', '))
                       : '<span class="sub">none &mdash; it has only ever been handed a 1.1 ' +
                         'assertion through WS-Federation or WS-Trust</span>') + '</td></tr>' +
    '<tr><td>NameIdentifier formats asked for</td><td>' +
      (valuesFor(fields.samlNameIdFormat).length
        ? codeList(valuesFor(fields.samlNameIdFormat))
        : '<span class="sub">none &mdash; and in this protocol that is the ordinary case, ' +
          'because there is no NameIDPolicy to ask in. It gets saml11.nameIdFormat unless the ' +
          'non-spec <code>format</code> parameter says otherwise.</span>') + '</td></tr>' +
    '<tr><td>Assertions issued to it</td><td>' + esc(String((row && row.authentications) || 0)) +
      '</td></tr>' +
    '</tbody></table>' +
    '<h2>What is NOT here, and why</h2>' +
    '<p class="sub">The SAML 2.0 page has three rows this one does not, and none of them is ' +
    'missing work. <strong>No logout return address</strong>: SAML 1.1 has no Single Logout, so ' +
    'there is nothing to send anywhere. <strong>No request signature and no signing ' +
    'certificate</strong>: there is no request, so there is nothing for a relying party to sign. ' +
    '<strong>No response binding</strong>: which of the two browser profiles is used is chosen ' +
    'HERE, by <code>saml11.defaultProfile</code> or the non-spec <code>profile</code> parameter, ' +
    'because nothing in SAML 1.1 lets a relying party ask.</p>' +
    '<p class="sub"><a href="/saml11/rp">The mock relying party</a> will run either profile ' +
    'against this service and show every check.</p>';

  log.debug("Leaving saml11DetailPage().");
  return {
    inner: inner,
    json: Object.assign(facts, {
      registered: !!row,
      identifierLooksGuessed: looksGuessed,
      name: row ? row.name : '',
      authentications: row ? row.authentications : 0,
      assertionConsumerServices: acs,
      nameIdFormats: valuesFor(fields.samlNameIdFormat),
      profiles: profiles
    })
  };
}

// ONE action, where /admin/saml2 has four, and the three it does not have are
// the three SAML 1.1 has no protocol for: a logout service to declare, a request
// signature to record, and a signing certificate to hold it in.
function saml11Action(body) {
  log.debug("Entering saml11Action(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const identifier = String(body.rp || body.relyingParty || '').trim();
  if (!identifier) {
    log.debug("Leaving saml11Action(). No relying party named.");
    return { ok: false, errors: ['Name the relying party by its identifier, in `rp`.'] };
  }

  if (action === 'register') {
    const result = applications.createApplication({
      identifier: identifier, kind: SAML11_RP_KIND, protocol: 'SAML 1.1',
      note: 'registered as a SAML 1.1 relying party from the admin console',
      fields: { samlEntityId: identifier }
    });
    log.debug("Leaving saml11Action(). register " + (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) {
      return result;
    }
    return { ok: true, application: result.application,
             message: 'Registered. Its identity provider metadata is at /saml11/metadata/' +
                      encodeURIComponent(saml11.slugOf(identifier)) + ', and it would have been ' +
                      'created by the first flow or metadata fetch anyway — registering it early ' +
                      'is what gives you a document to hand somebody now, and a name to put in ' +
                      'providerId so that nothing has to be guessed.' };
  }
  log.debug("Leaving saml11Action(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". There is one: register.'] };
}

function saml11View(req) {
  log.debug("Entering saml11View().");
  const wanted = String(req.query.rp || '').trim();
  if (wanted) {
    const detail = saml11DetailPage(req, wanted);
    log.debug("Leaving saml11View(). The drill-down.");
    return { json: detail.json, inner: detail.inner,
             title: 'SAML 1.1 relying party ' + wanted,
             up: upTo('/admin/saml11', wanted, listViewOf('/admin/saml11', req.query)) };
  }
  const list = saml11ListPage(req);
  log.debug("Leaving saml11View(). The list.");
  return { json: list.json, inner: list.inner, title: 'SAML 1.1 identity provider' };
}

app.get('/admin/saml11', function (req, res) {
  log.debug("Entering the admin SAML 1.1 page.");
  const view = saml11View(req);
  respond(req, res, view.json, view.title, '/admin/saml11', view.inner, view.up);
  log.debug("Leaving the admin SAML 1.1 page.");
});

app.post('/admin/saml11', function (req, res) {
  log.debug("Entering the admin SAML 1.1 action endpoint.");
  const body = parseBody(req);
  const result = saml11Action(body);
  const identifier = String(body.rp || body.relyingParty || '').trim();
  // The list state the form carried, REBUILT rather than echoed — see
  // listViewFromBack(), and the note in admin-ui/CLAUDE.md about a new form on a
  // drill-down needing `carryBack` in it.
  const listView = listViewFromBack('/admin/saml11', body.back);
  const back = identifier && result.ok !== false
    ? '/admin/saml11' + queryWith(listView, { rp: identifier })
    : '/admin/saml11' + queryWith(listView, {});
  respondToAction(req, res, back, result);
  log.debug("Leaving the admin SAML 1.1 action endpoint.");
});

app.get('/admin/groups', function (req, res) {
  log.debug("Entering the admin groups page.");
  const view = groupsView(req);
  respond(req, res, view.json, view.title, '/admin/groups', view.inner, view.up);
  log.debug("Leaving the admin groups page. " + view.title + ".");
});

// ---------------------------------------------------------------------------
// GET /admin/rbac, POST /admin/rbac — WHO MAY USE THIS CONSOLE.
//
// The page behind the gate above, and the second page here (after /admin/groups)
// whose content comes from the directory rather than from this service's own
// memory. It renders and decides nothing: `admin_rbac.js` holds the two roles,
// the empty-roster rule and both writes, and this draws them — the same division
// /admin/groups keeps with `ldap_server.js`, and for the same reason. A second
// opinion here about who is an administrator is the one bug in this feature that
// would be genuinely dangerous.
//
// **ONE TABLE OF GRANTS RATHER THAN ONE TABLE PER ROLE**, which is a rendering
// decision with a reason. Two tables would each need their own filter, their own
// page parameter and their own per-page control — three sets of controls for a
// list that is usually four rows long — and a reader's question is "who has
// access", not "who is in cn=admin-read". So a row is one GRANT: a person and a
// role. Somebody holding both roles is two rows, which is honest — they were
// granted twice and can be revoked once.
//
// **THE GRANT FORM IS TWO FORMS AND THAT IS DELIBERATE.** One picks from a list
// of people this service knows about, which is what somebody wants nine times in
// ten and is the only one that can be used without knowing how names are spelt
// here. The other takes a typed name, because the interesting case for a mock is
// granting a role to somebody who has NEVER been here — then watching them
// arrive already holding it. A single control doing both would have to be a text
// box with a datalist, and the list would then look like a set of options while
// silently accepting anything, which is a control that lies about what it takes.
// ---------------------------------------------------------------------------

// The caveat, on the page rather than only in a comment. It is the exact
// counterpart of GROUPS_CAVEAT and it says the opposite thing about two named
// groups, which is why it is worded to leave the general claim standing.
const RBAC_CAVEAT =
  '<p class="note"><strong>These two groups are the only groups in this service that grant ' +
  'anything, and what they grant is this console.</strong> Every other group here still grants ' +
  'nothing at all — see <a href="/admin/groups">Groups</a>, which says so — and even these two ' +
  'grant nothing outside <code>/admin</code>: no token\'s scopes change, no assertion gains an ' +
  'attribute, no Kerberos PAC is affected, and a member of ' +
  '<code>admin-write</code> gets exactly the same answer from <code>/oauth2/token</code> as ' +
  'anybody else. They are also ordinary directory entries, so <code>ldapmodify</code>, a SCIM ' +
  'PATCH, this page and <code>POST /admin-api/rbac/grant</code> are four doors onto one ' +
  'membership — which is the point rather than a leak: a role no test can grant is a role no ' +
  'test can exercise.</p>';

// A membership value that names an entry which is not there. It is a normal
// state here rather than a fault — see the grant form's note — so it is marked
// and explained rather than hidden or repaired.
function rbacMemberCell(row, knownKeys) {
  const name = esc(row.username || row.value);
  if (row.userKey && knownKeys[row.userKey]) {
    return '<a href="' + esc('/admin/users?user=' + encodeURIComponent(row.userKey)) + '">' +
           name + '</a>';
  }
  if (row.present) {
    // In the directory, but this service has never seen them authenticate. The
    // same distinction /admin/groups draws on its member rows, and drawn the
    // same way so the two pages cannot be read as disagreeing.
    return name + ' <span class="state-none" title="This person has an entry in the ' +
           'directory, but nothing here has authenticated as them yet, so there is no ' +
           'page about them on Users.">never here</span>';
  }
  return name + ' <span class="state-expired" title="Nothing is at this DN. The role still ' +
         'counts — it resolves the moment somebody authenticates under this name or the entry ' +
         'is created — but until then no directory client can see who it names.">dangling</span>';
}

// The mark on a row whose membership is on the PERSON'S entry rather than in the
// group. It really grants the role — `groupsOfUser()` reads both directions, so
// admin_rbac.js merges these in — which is why it is on this list at all; and it
// cannot be taken away from here, so the row says that too rather than offering
// a button that would report success and change nothing.
function rbacClaimedMark(row) {
  if (row.kind !== 'claimed') {
    return '';
  }
  return ' <span class="state-expired" title="Their own entry&#39;s memberOf names this group ' +
         'and the group does not list them back. Nothing here maintains memberOf — a client ' +
         'wrote it — and it grants the role all the same, so it is on this list. The Revoke ' +
         'button cannot remove it: the value is on the person, and this console writes only ' +
         'to groups.">via their own memberOf</span>';
}

function rbacListPage(req) {
  log.debug("Entering rbacListPage().");
  const info = rbac.describe();
  const state = gateStateFor(req);

  // One row per grant, flattened out of the two rosters. Sorted by name and then
  // by role so that somebody holding both is two adjacent rows rather than two
  // rows a page apart.
  const grants = [];
  info.roles.forEach(function (role) {
    role.members.forEach(function (member) {
      grants.push({
        username: member.username, role: role.role, roleLabel: role.label,
        cn: role.cn, dn: role.dn, value: member.value, attribute: member.attribute,
        holds: member.holds, memberDn: member.dn, present: member.present,
        kind: member.kind, userKey: member.userKey
      });
    });
  });
  grants.sort(function (a, b) {
    const an = String(a.username).toLowerCase();
    const bn = String(b.username).toLowerCase();
    if (an !== bn) {
      return an < bn ? -1 : 1;
    }
    return a.role < b.role ? -1 : 1;
  });

  const wantedText = String(req.query.q || '').trim();
  const needle = wantedText.toLowerCase();
  const wantedRole = String(req.query.role || '').trim().toLowerCase();
  const filtered = grants.filter(function (row) {
    if (wantedRole && row.role !== wantedRole) {
      return false;
    }
    if (!needle) {
      return true;
    }
    return String(row.username).toLowerCase().indexOf(needle) >= 0 ||
           String(row.value).toLowerCase().indexOf(needle) >= 0;
  });

  const paging = pagingOf(req.query, filtered.length, { noun: 'grants' });
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  const filterParams = { q: wantedText || '', role: wantedRole || '',
                         per: req.query.per ? paging.perPage : '' };
  const nav = pageNav('/admin/rbac', filterParams, paging);
  const carryBack = '<input type="hidden" name="back" value="' +
    esc(queryWith(listViewOf('/admin/rbac', req.query), {})) + '">';

  const knownKeys = knownUserKeys();
  const rows = shown.map(function (row) {
    return '<tr><td>' + rbacMemberCell(row, knownKeys) + rbacClaimedMark(row) + '</td>' +
      '<td>' + esc(row.roleLabel) + '</td>' +
      '<td><a href="' + esc('/admin/groups?group=' + encodeURIComponent(row.dn)) + '"><code>' +
        esc(row.dn) + '</code></a></td>' +
      '<td><code>' + esc(row.attribute) + '</code>: <code>' + esc(row.value) + '</code></td>' +
      '<td>' +
        (row.kind === 'claimed'
          ? '<span class="state-expired" title="The membership is on their own entry as ' +
            'memberOf, so there is nothing in the group to remove. An ldapmodify or a SCIM ' +
            'PATCH of the PERSON takes it away.">not from here</span>'
          : state.write
          ? '<form class="inline" method="post" action="/admin/rbac">' +
            '<input type="hidden" name="action" value="revoke">' +
            '<input type="hidden" name="username" value="' + esc(row.username) + '">' +
            '<input type="hidden" name="role" value="' + esc(row.role) + '">' + carryBack +
            '<button class="danger">Revoke</button></form>'
          : '<span class="state-none">read-only</span>') +
      '</td></tr>';
  }).join('');

  // WHO CAN BE PICKED. `stats.userRows()` is who has authenticated and the
  // directory is who has an entry; admin_rbac.js unions them, because a select
  // built from either alone would silently omit half the people somebody wants
  // to grant a role to.
  const candidates = rbac.candidates(Object.keys(knownKeys));
  const options = candidates.map(function (row) {
    const where = row.inDirectory && row.seen ? 'directory, and has signed in'
      : (row.inDirectory ? 'in the directory' : 'has signed in');
    return '<option value="' + esc(row.username) + '">' + esc(row.username) +
           ' — ' + esc(where) + '</option>';
  }).join('');
  const roleOptions = rbac.ROLES.map(function (role) {
    return '<option value="' + esc(role.id) + '">' + esc(role.label) + '</option>';
  }).join('');

  const tiles = '<div class="tiles">' +
    info.roles.map(function (role) {
      return tile(role.memberCount, role.label);
    }).join('') +
    tile(candidates.length, 'People who could hold one') +
    '</div>';

  const status = info.closedToEveryone
    ? '<div class="err"><strong>Nobody can use this console.</strong> The gate is on, no role ' +
      'has a member, and <code>admin.openWhenEmpty</code> is off. Anything you are reading here ' +
      'you are reading through <code>/admin-api</code> or with the gate off.</div>'
    : (info.openToAnyone
        ? '<div class="warn"><strong>No role has a member, so anybody who signs in has the ' +
          'whole console.</strong> The first grant made on this page ends that — for everybody, ' +
          'including whoever makes it. <strong>Grant yourself a role before you grant anybody ' +
          'else one</strong>, or the next page you click will be a 403.</div>'
        : (info.enforced
            ? '<div class="ok">The roster is enforced. ' + info.grantCount + ' grant(s) across ' +
              'two roles; everybody else is refused at every page of this console.</div>'
            : '<div class="warn"><strong>None of this is in force.</strong> ' +
              '<code>admin.authRequired</code> is OFF, so the console is open to anybody who ' +
              'can reach this port and these roles decide nothing. They are still real ' +
              'directory groups and can be granted now — turn the setting on from ' +
              '<a href="/admin/config">Configuration</a> when the roster looks right.</div>'));

  const noDirectory = info.available ? '' :
    '<div class="err">No LDAP directory is loaded in this process, so there is nowhere to hold ' +
    'these roles and nothing on this page can be granted. That is a build of this service ' +
    'without <code>ldap_server.js</code> rather than a failure — but with ' +
    '<code>admin.authRequired</code> on it leaves this console reachable only while ' +
    '<code>admin.openWhenEmpty</code> is on.</div>';

  const forms = state.write && info.available
    ? '<h2>Grant a role</h2>' +
      '<form method="post" action="/admin/rbac"><div class="formrow">' +
      '<input type="hidden" name="action" value="grant">' + carryBack +
      '<label for="username">Person</label>' +
      '<select id="username" name="username">' +
        (options || '<option value="">nobody yet</option>') + '</select>' +
      '<label for="role">Role</label>' +
      '<select id="role" name="role">' + roleOptions + '</select>' +
      '<button type="submit">Grant</button>' +
      '</div></form>' +
      '<p class="note">The list is everybody with an entry in the directory and everybody this ' +
      'service has seen authenticate — two different sets, which is why both are offered and ' +
      'why each row says which it came from.</p>' +
      '<h3>Grant to a name that is not listed</h3>' +
      '<form method="post" action="/admin/rbac"><div class="formrow">' +
      '<input type="hidden" name="action" value="grant">' + carryBack +
      '<label for="typed">Name</label>' +
      '<input type="text" id="typed" name="username" size="24" placeholder="the name they ' +
      'will sign in as">' +
      '<label for="typedrole">Role</label>' +
      '<select id="typedrole" name="role">' + roleOptions + '</select>' +
      '<button type="submit" class="secondary">Grant</button>' +
      '</div></form>' +
      '<p class="note">The membership will DANGLE until that person exists — it names a DN this ' +
      'directory does not hold yet — and the role counts from the moment they first sign in. ' +
      'That is the interesting case for a mock and is why this form is here: nothing about a ' +
      'grant requires the person to have been seen. A name carrying a character RFC 4514 ' +
      'reserves in a DN is refused, the same refusal creating a person gets.</p>'
    : (info.available && info.enforced && !state.write
        ? '<p class="note">Granting and revoking need <strong>Admin Write</strong>. The table ' +
          'above is what you can see with <strong>Admin Read</strong>.</p>'
        : '');

  const inner = messagesOf(req) + noDirectory + status + tiles +
    '<form method="get" action="/admin/rbac"><div class="formrow">' +
    '<label for="q">Person</label>' +
    '<input type="text" id="q" name="q" value="' + esc(wantedText) + '" size="22" ' +
    'placeholder="part of a name">' +
    '<label for="rolefilter">Role</label>' +
    '<select id="rolefilter" name="role"><option value="">both</option>' +
    rbac.ROLES.map(function (role) {
      return '<option value="' + esc(role.id) + '"' +
             (wantedRole === role.id ? ' selected' : '') + '>' + esc(role.label) + '</option>';
    }).join('') + '</select>' +
    '<label for="per">Per page</label>' +
    '<select id="per" name="per">' + perPageOptions(paging.perPage) + '</select>' +
    '<button type="submit">Filter</button>' +
    (wantedText || wantedRole ? ' <a href="/admin/rbac">clear</a>' : '') +
    '</div></form>' +
    nav +
    '<table><tr><th>Person</th><th>Role</th><th>Group</th><th>Membership value</th>' +
    '<th>Take it away</th></tr>' +
    (rows || '<tr><td colspan="5">' +
      (wantedText || wantedRole
        ? 'No grant matches. The filter above may be hiding some.'
        : 'Nobody holds either role.' +
          (info.openToAnyone ? ' Which is why anybody who signs in can read this page.' : '')) +
      '</td></tr>') +
    '</table>' + nav +
    (info.roles.some(function (r) { return r.claimedCount; })
      ? '<p class="note"><strong>Some of those grants are on the PERSON rather than in the ' +
        'group.</strong> An entry whose own <code>memberOf</code> names a role group holds ' +
        'the role — the directory is asked in both directions — and nothing here maintains ' +
        '<code>memberOf</code>, so a client wrote it. They are listed because a page ' +
        'answering &ldquo;who has access&rdquo; that omitted them would be showing a console ' +
        'somebody could use and a list they were not on. They cannot be revoked from here: ' +
        'the value is on their entry, and this console writes only to groups. One edge worth ' +
        'knowing — a <code>memberOf</code> naming a role group that has <em>never been ' +
        'created</em> grants nothing, and starts granting the moment the first ordinary ' +
        'grant creates it.</p>'
      : '') + forms +
    '<h2>What the two roles are</h2>' +
    '<table><tr><th>Role</th><th>Group</th><th>What it allows</th><th class="num">Members</th></tr>' +
    info.roles.map(function (role) {
      return '<tr><td><strong>' + esc(role.label) + '</strong></td>' +
        '<td><code>' + esc(role.dn || ('cn=' + role.cn)) + '</code>' +
        (role.exists ? '' : ' <span class="state-none" title="The group is created by the ' +
          'first grant rather than at startup, so &quot;no group&quot; and &quot;no ' +
          'members&quot; are the same state here.">not created yet</span>') + '</td>' +
        '<td>' + esc(role.what) + '</td>' +
        '<td class="num">' + role.memberCount +
        (role.claimedCount
          ? ' <span class="state-expired" title="Of which ' + role.claimedCount +
            ' are claimed by the person&#39;s own memberOf rather than listed by the ' +
            'group.">(' + role.claimedCount + ')</span>'
          : '') + '</td></tr>';
    }).join('') + '</table>' +
    '<p class="note"><strong>Write implies read.</strong> A member of <code>' +
    esc(info.roles[1] ? info.roles[1].cn : '') + '</code> does not also need <code>' +
    esc(info.roles[0] ? info.roles[0].cn : '') + '</code>: a role that could post a form to a ' +
    'page it was not allowed to look at would be a trap rather than a permission.</p>' +
    '<h2>How the gate is set</h2>' +
    '<table><tr><th>Setting</th><th>Now</th><th>What it does</th></tr>' +
    '<tr><td><code>admin.authRequired</code></td><td>' +
      (info.enforced ? '<span class="state-valid">on</span>' : '<span class="state-revoked">off</span>') +
      '</td><td>Whether any of this is in force. Off, the console is completely open — which ' +
      'is what it was before this existed and stays deliberately reachable.</td></tr>' +
    '<tr><td><code>admin.openWhenEmpty</code></td><td>' +
      (info.openWhenEmpty ? '<span class="state-expired">on</span>' : 'off') +
      '</td><td>What happens while NO role has a member: on, anybody who signs in holds both; ' +
      'off, nobody gets in at all. On by default because this service has no password to ' +
      'bootstrap an administrator with and the roster dies with the process.</td></tr>' +
    '<tr><td><code>admin.readGroup</code> / <code>admin.writeGroup</code></td><td><code>' +
      esc(info.roles[0] ? info.roles[0].cn : '') + '</code> / <code>' +
      esc(info.roles[1] ? info.roles[1].cn : '') + '</code></td>' +
      '<td>Which groups these roles are. Renaming one does not move anybody: the members stay ' +
      'in the old group, which stops granting anything the moment the name changes.</td></tr>' +
    '</table>' +
    '<p class="note">All four are on <a href="/admin/config">Configuration</a> and every one of ' +
    'them takes effect on the next request. <code>/admin-api</code> is NOT gated by any of ' +
    'them, which is on purpose: it is the way back in when the roster is empty and ' +
    '<code>admin.openWhenEmpty</code> is off, and it is why turning this on does not break a ' +
    'test suite driving the management API.</p>' +
    RBAC_CAVEAT;

  log.debug("Leaving rbacListPage(). " + shown.length + " row(s) drawn of " +
            grants.length + " grant(s).");
  return {
    inner: inner,
    json: {
      enforced: info.enforced, openWhenEmpty: info.openWhenEmpty,
      openToAnyone: info.openToAnyone, closedToEveryone: info.closedToEveryone,
      available: info.available, groupsDn: info.groupsDn, usersDn: info.usersDn,
      grantCount: info.grantCount, matched: filtered.length, shown: shown.length,
      filter: { q: wantedText || null, role: wantedRole || null },
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      // WHO IS ASKING, which is on the reply rather than only in the banner
      // because a caller driving this over JSON has no banner and the answer to
      // "why did that 403" is here.
      you: { username: state.username, roles: state.roles,
             read: state.read, write: state.write, viaEmptyRoster: state.open },
      roles: info.roles,
      grants: shown,
      candidates: candidates
    }
  };
}

function rbacView(req) {
  log.debug("Entering rbacView().");
  const list = rbacListPage(req);
  log.debug("Leaving rbacView().");
  return { json: list.json, inner: list.inner, title: 'Admin roles' };
}

// Both writes, and neither decides anything: admin_rbac.js holds the rules and
// this reads two fields off a body. `actor` is threaded through so the
// `admin.role.change` audit row can say WHO made the grant — the one question an
// audit log of permissions changes exists to answer, and the one nothing else on
// the row could reconstruct.
function rbacAction(body, context) {
  log.debug("Entering rbacAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const username = String(body.username || body.user || '').trim();
  const role = String(body.role || '').trim();
  const ctx = { via: (context || {}).via || 'console',
                actor: (context || {}).actor || '' };

  if (action === 'grant') {
    const result = rbac.grant(username, role, ctx);
    log.debug("Leaving rbacAction(). grant " + (result.ok ? "ok." : "refused."));
    return result;
  }
  if (action === 'revoke') {
    const result = rbac.revoke(username, role, ctx);
    log.debug("Leaving rbacAction(). revoke " + (result.ok ? "ok." : "refused."));
    return result;
  }

  log.debug("Leaving rbacAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". There are two: grant and ' +
                               'revoke.'] };
}

app.get('/admin/rbac', function (req, res) {
  log.debug("Entering the admin roles page.");
  const view = rbacView(req);
  respond(req, res, view.json, view.title, '/admin/rbac', view.inner, view.up);
  log.debug("Leaving the admin roles page.");
});

app.post('/admin/rbac', function (req, res) {
  log.debug("Entering the admin roles action endpoint.");
  const body = parseBody(req);
  // The actor is the person whose session got them through the gate above, and
  // it is read here rather than inside admin_rbac.js because that module has no
  // request — the management API calls the same function with an actor of its
  // own, and a module that reached for a cookie would only work from one of
  // them.
  const state = gateStateFor(req);
  const result = rbacAction(body, { via: 'console', actor: state.username });
  const back = '/admin/rbac' + queryWith(listViewFromBack('/admin/rbac', body.back), {});
  respondToAction(req, res, back, result);
  log.debug("Leaving the admin roles action endpoint.");
});

// ---------------------------------------------------------------------------
// GET /admin/claims, POST /admin/claims
// GET /admin/saml-attributes, POST /admin/saml-attributes
// ---------------------------------------------------------------------------
// TWO PAGES, ONE ACTION FUNCTION AND ONE STORE. The four claim sets used to be
// four sections of /admin/claims; since 2026-08-24 the two JWT sets are there
// and the two SAML ones are on /admin/saml-attributes, under the console's own
// SAML group. What did NOT split is anything underneath: `CLAIM_SETS` is one
// object in admin_stats.js, `setClaimSet()` is the one door onto it, and this
// one function is what both pages and both /admin-api resources post to. A
// second action function would have been a second set of rules about reserved
// names and duplicates that agreed with the first until one of them changed.
//
// `names` is the second argument for the same reason vcAction() has one: a list
// that may appear more than once in a form body is not something
// helpers.parseBody() can answer, so the caller reads it with listField() and
// hands it in. It is only read by the `attributes` action; the other six ignore
// it.
//
// `allowed` is the third and it is what makes the SPLIT real rather than
// cosmetic: it is the set ids the door being knocked on carries, so a POST to
// /admin/claims naming `saml2` is refused by name instead of quietly changing a
// set whose page it is not on and then redirecting to a page that cannot show
// what it did. It defaults to all four, which is what a caller that has not
// been given a family — nothing today — would get.
function claimsAction(body, names, allowed) {
  log.debug("Entering claimsAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const setId = String(body.set || '');
  const sets = allowed && allowed.length ? allowed : stats.CLAIM_SET_IDS;
  if (sets.indexOf(setId) < 0) {
    log.debug("Leaving claimsAction(). No such set here.");
    return { ok: false, errors: ['There is no claim set called "' + setId + '" here. The ones ' +
                                 'this door carries are: ' + sets.join(', ') + '.'] };
  }
  const label = stats.CLAIM_SETS[setId].label;

  if (action === 'add') {
    const entry = { name: String(body.name || '').trim(), value: String(body.value == null ? '' : body.value) };
    if (body.nameFormat) entry.nameFormat = String(body.nameFormat).trim();
    if (body.namespace) entry.namespace = String(body.namespace).trim();
    const result = stats.setClaimSet(setId, stats.claimSet(setId).concat([entry]));
    log.debug("Leaving claimsAction(). add -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, claims: result.claims,
          message: 'Added "' + entry.name + '" to the ' + label + ' claim set. Every one of those ' +
                   'issued from now on carries it; nothing already issued changes.' }
      : result;
  }

  if (action === 'remove') {
    const name = String(body.name || '').trim();
    const remaining = stats.claimSet(setId).filter(function (c) { return c.name !== name; });
    if (remaining.length === stats.claimSet(setId).length) {
      log.debug("Leaving claimsAction(). Nothing named that.");
      return { ok: false, errors: ['The ' + label + ' claim set has no claim called "' + name + '".'] };
    }
    const result = stats.setClaimSet(setId, remaining);
    log.debug("Leaving claimsAction(). remove -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, claims: result.claims,
          message: 'Removed "' + name + '" from the ' + label + ' claim set.' }
      : result;
  }

  if (action === 'clear') {
    stats.setClaimSet(setId, []);
    log.debug("Leaving claimsAction(). Cleared.");
    return { ok: true, set: setId, claims: [],
             message: 'The ' + label + ' claim set is empty again.' };
  }

  if (action === 'replace') {
    let entries = body.claims;
    if (typeof entries === 'string') {
      try {
        entries = JSON.parse(entries || '[]');
      } catch (e) {
        log.debug("Leaving claimsAction(). The JSON did not parse.");
        return { ok: false, errors: ['That is not valid JSON: ' + e.message] };
      }
    }
    if (!Array.isArray(entries)) {
      log.debug("Leaving claimsAction(). Not an array.");
      return { ok: false, errors: ['Give a JSON ARRAY of {"name": ..., "value": ...} objects. An ' +
                                   'empty array clears the set.'] };
    }
    const result = stats.setClaimSet(setId, entries);
    log.debug("Leaving claimsAction(). replace -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, claims: result.claims,
          message: 'The ' + label + ' claim set now has ' + result.claims.length + ' custom claim(s).' }
      : result;
  }

  // ------------------------------------------------------------------------
  // The three that act on the DIRECTORY ATTRIBUTE half of a set rather than on
  // the typed claims above.
  //
  // They are three actions and not one with a mode, because each is a different
  // thing to authorise and a different row in the audit log: `attributes`
  // carries a list somebody chose, and the other two carry nothing and mean the
  // extremes. A single action taking a list would make "select all" a caller's
  // job to construct — the whole catalogue in a POST body to say "all of them" —
  // which is a list that has to be updated every time the catalogue is.
  //
  // What the split does NOT do is make an empty `attributes` unambiguous, and it
  // is worth being plain about that rather than implying otherwise. An empty
  // list and an absent one both mean "the selection is nothing", so a caller
  // that misspells the field clears the set. Three things make that recoverable
  // rather than silent, and they are the reason it is not refused instead: the
  // reply names every attribute it `removed`, the audit log keeps a row saying
  // the same, and unticking every box and pressing Update is a legitimate way to
  // clear a set that a refusal would have to break. `attributes-clear` exists so
  // that a caller which MEANS it can say so, and so that the console's button
  // does not depend on submitting an empty form.
  //
  // The console's buttons are form posts for the same reason every other control
  // here is: app.js sets `script-src 'none'` for the whole service, so a
  // browser-side "tick every box" is not available and would not be taken if it
  // were — a server-side select-all leaves an audit row, and a scripted one
  // would leave the boxes ticked and the set unchanged until somebody pressed
  // Update.
  // ------------------------------------------------------------------------
  if (action === 'attributes') {
    const result = claimAttributes.setSelection(setId, names || [], 'select');
    log.debug("Leaving claimsAction(). attributes -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, attributes: result.attributes,
          added: result.added, removed: result.removed,
          message: 'The ' + label + ' set now carries ' + result.attributes.length +
                   ' directory attribute(s): ' + (result.attributes.join(', ') || '(none)') +
                   '. Every one of those issued from now on carries them, with the value on ' +
                   'that person\'s entry; nothing already issued changes.' }
      : result;
  }

  if (action === 'attributes-all') {
    const result = claimAttributes.selectAll(setId);
    log.debug("Leaving claimsAction(). attributes-all -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, attributes: result.attributes,
          added: result.added, removed: result.removed,
          message: 'The ' + label + ' set now carries every attribute in the catalogue — ' +
                   result.attributes.length + ' of them. That is a legitimate thing to test ' +
                   'and it makes a large token; it is not a mistake this page will correct.' }
      : result;
  }

  if (action === 'attributes-clear') {
    const result = claimAttributes.clearSelection(setId);
    log.debug("Leaving claimsAction(). attributes-clear -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, attributes: [], added: [], removed: result.removed,
          message: 'The ' + label + ' set carries no directory attribute again. Removed: ' +
                   (result.removed.join(', ') || 'nothing — it was already empty') + '. The ' +
                   'typed claims on this set, if any, are untouched.' }
      : result;
  }

  log.debug("Leaving claimsAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The seven are: add, remove, ' +
                               'clear, replace, attributes, attributes-all, attributes-clear.'] };
}

app.post('/admin/claims', function (req, res) {
  log.debug("Entering the admin claims action endpoint.");
  const body = parseBody(req);
  // Two names for the list, exactly as /admin/vc takes them and for the same
  // reason: a checkbox column is one `attribute` repeated, and a JSON body
  // carries one `attributes` array. Neither spelling is wrong and refusing
  // either would make the console's own form and the API's document disagree.
  const names = listField(req, body, 'attribute').concat(listField(req, body, 'attributes'));
  const result = claimsAction(body, names, stats.JWT_CLAIM_SET_IDS);
  // Back to the page the reader was on, preview user and all: the two tables
  // show that person's values, and a redirect that dropped the parameter would
  // answer "what did that do" with somebody else's row.
  respondToAction(req, res, claimsPageUrl(req.query), result);
  log.debug("Leaving the admin claims action endpoint.");
});

// The same handler for the SAML half, and it is a SEPARATE ROUTE rather than a
// hidden field on the one above for two reasons that are both about the reply:
// the redirect has to land back on the page the form was on, and the refusal
// for a set this page does not carry has to name the sets it does. Everything
// between those two lines is the same function on the same store.
app.post('/admin/saml-attributes', function (req, res) {
  log.debug("Entering the admin SAML attributes action endpoint.");
  const body = parseBody(req);
  const names = listField(req, body, 'attribute').concat(listField(req, body, 'attributes'));
  const result = claimsAction(body, names, stats.SAML_CLAIM_SET_IDS);
  respondToAction(req, res, samlAttributesPageUrl(req.query), result);
  log.debug("Leaving the admin SAML attributes action endpoint.");
});

// Which person the four tables show values for, and where the page sends itself
// back to. Capped because the string is echoed, and defaulted to somebody the
// directory actually holds from startup so a fresh process shows real values
// rather than an invented person nobody can look up — the same rule and the same
// default /admin/vc uses, deliberately, so the two pages preview the same person
// unless somebody says otherwise.
function claimsPreviewUser(query) {
  const asked = String((query && query.user) || 'alice').trim();
  return asked.slice(0, 64) || 'alice';
}

// The page's own URL with the preview user on it. Every form on this page posts
// to THIS rather than to the bare path, so that the 303 after an action lands
// back on the person the reader was looking at. A form that dropped the
// parameter would answer "what did that do?" with somebody else's values, which
// reads as the action having done something it did not.
function claimsPageUrl(query) {
  return '/admin/claims?user=' + encodeURIComponent(claimsPreviewUser(query));
}

// The same for the SAML page. Two functions rather than one taking a path,
// because these are the two strings the two POST handlers redirect to and a
// caller that passed the wrong path would send a reader to the page their form
// was NOT on — which is the one failure this helper exists to prevent. The
// preview user is read by the same function for both, deliberately: the two
// pages preview the same person unless somebody says otherwise, exactly as
// /admin/vc already does.
function samlAttributesPageUrl(query) {
  return '/admin/saml-attributes?user=' + encodeURIComponent(claimsPreviewUser(query));
}

// ---------------------------------------------------------------------------
// THE DIRECTORY ATTRIBUTE HALF OF ONE SET.
//
// A checkbox per attribute type in the catalogue, a column saying what it would
// put in a token for the person being previewed, and three buttons. It is
// repeated for each of the four sets rather than being one table with four
// checkbox columns, because the four sets are chosen for different reasons — an
// access token goes to a resource server and an ID Token goes to a client, and
// the interesting configuration is usually the one where they DIFFER. A single
// grid would make four independent decisions look like one, and would have to
// post all four sets at once, so changing the ID Token would rewrite the access
// token's selection as a side effect.
//
// THE THREE BUTTONS ARE THREE FORMS, and unticking a box in one of the other
// three sets' tables does nothing to this one: only the form that is submitted
// sends anything, so each Update button carries exactly its own set's boxes.
// That is worth stating because a page with four checkbox tables and one Update
// button would be the obvious design and would be wrong in the direction nobody
// notices — it would clear the three sets whose tables were rendered before the
// reader ticked anything.
// ---------------------------------------------------------------------------
function claimAttributeSection(setId, previewUser, values, pageUrl) {
  log.debug("Entering claimAttributeSection(). setId=" + setId);
  const selected = claimAttributes.selectedNames(setId);

  const rows = claimAttributes.CATALOGUE.map(function (row) {
    const on = claimAttributes.isSelected(setId, row.ldap);
    const found = values.byLdap[row.ldap.toLowerCase()];
    // `description` is the one row with no generator: this service writes it on
    // every entry itself, to record the protocols that person has used. So it is
    // the one attribute whose value is a real fact, and it is absent rather than
    // invented for somebody with no entry.
    const valueCell = found
      ? '<td><code>' + esc(found.value) + '</code></td><td>' + esc(found.source) + '</td>'
      : '<td><span class="state-none">—</span></td><td>' +
        (row.from ? 'would be generated' : 'the entry\'s own') + '</td>';
    return '<tr><td><input type="checkbox" name="attribute" value="' + esc(row.ldap) + '"' +
      (on ? ' checked' : '') + '></td>' +
      '<td><code>' + esc(row.ldap) + '</code></td>' +
      '<td>' + esc(row.schema) + '</td>' +
      '<td><code>' + esc(row.claim.join('.')) + '</code></td>' +
      valueCell + '</tr>';
  }).join('');

  log.debug("Leaving claimAttributeSection(). " + selected.length + " of " +
            claimAttributes.CATALOGUE.length + " selected.");
  return '<p class="note">' + (selected.length
      ? 'Carries ' + selected.length + ' directory attribute(s): ' + codeList(selected) + '.'
      : 'Carries no directory attribute. Tick some and press Update.') + '</p>' +
    '<form method="post" action="' + esc(pageUrl) + '">' +
    '<input type="hidden" name="action" value="attributes">' +
    '<input type="hidden" name="set" value="' + esc(setId) + '">' +
    '<table><tr><th>In</th><th>LDAP attribute</th><th>Defined by</th>' +
    '<th>' + (setId === 'saml2' || setId === 'saml11' ? 'Attribute name' : 'Claim') + '</th>' +
    '<th>For ' + esc(previewUser) + '</th><th>Source</th></tr>' +
    rows + '</table>' +
    '<div class="formrow"><button>Update</button>' +
    '<span class="note">The ticked boxes become the whole selection for this set: unticking is ' +
    'how an attribute is removed.</span></div></form>' +
    '<div class="formrow">' +
    '<form method="post" action="' + esc(pageUrl) + '" class="inline">' +
    '<input type="hidden" name="action" value="attributes-all">' +
    '<input type="hidden" name="set" value="' + esc(setId) + '">' +
    '<button class="secondary">Select all</button></form> ' +
    '<form method="post" action="' + esc(pageUrl) + '" class="inline">' +
    '<input type="hidden" name="action" value="attributes-clear">' +
    '<input type="hidden" name="set" value="' + esc(setId) + '">' +
    '<button class="secondary">Delete all</button></form>' +
    '<span class="note">Both act immediately — there is no script on this page, so these are ' +
    'form posts and not a way of ticking the boxes above.</span></div>';
}

// One set, rendered: what is in it, a way to remove each, and a way to add another.
// The three sets differ in the extra field each needs, which is why the form is
// built from the set's kind rather than being one form four times.
//
// IT IS THE SAME FUNCTION ON BOTH PAGES and only the NOUN changes: a JWT set
// carries claims and a SAML set carries attributes, which is what each
// protocol's own readers call them, and a page headed "Custom SAML attributes"
// whose tables said "claim" would be teaching the wrong word for the thing it
// is about to put in an assertion. Everything else — the two halves, the three
// buttons, the precedence — is one behaviour and is drawn once.
function claimSetSection(setId, previewUser, values, pageUrl) {
  log.debug("Entering claimSetSection(). setId=" + setId);
  const set = stats.CLAIM_SETS[setId];
  const claims = stats.claimSet(setId);
  const isSaml2 = setId === 'saml2';
  const isSaml11 = setId === 'saml11';
  const isSaml = isSaml2 || isSaml11;
  const noun = isSaml ? 'attribute' : 'claim';
  const carrier = isSaml ? 'assertions' : 'tokens';
  const extraHeader = isSaml2 ? '<th>NameFormat</th>' : (isSaml11 ? '<th>AttributeNamespace</th>' : '');

  const rows = claims.map(function (claim) {
    const extraCell = isSaml2 ? '<td>' + esc(claim.nameFormat || '—') + '</td>'
                    : (isSaml11 ? '<td>' + shortened(claim.namespace, 44) + '</td>' : '');
    return '<tr><td><code>' + esc(claim.name) + '</code></td>' + extraCell +
      '<td><code>' + esc(claim.value) + '</code></td>' +
      '<td><form method="post" action="' + esc(pageUrl) + '" class="inline">' +
      '<input type="hidden" name="action" value="remove">' +
      '<input type="hidden" name="set" value="' + esc(setId) + '">' +
      '<input type="hidden" name="name" value="' + esc(claim.name) + '">' +
      '<button class="secondary">Remove</button></form></td></tr>';
  }).join('');

  const extraInput = isSaml2
    ? '<label for="nf-' + setId + '">NameFormat</label>' +
      '<input type="text" id="nf-' + setId + '" name="nameFormat" size="28" placeholder="(optional)">'
    : (isSaml11
      ? '<label for="ns-' + setId + '">Namespace</label>' +
        '<input type="text" id="ns-' + setId + '" name="namespace" size="34" placeholder="' +
        esc(stats.DEFAULT_SAML11_NAMESPACE) + '">'
      : '');

  log.debug("Leaving claimSetSection(). " + claims.length + " claim(s).");
  return '<h3>' + esc(set.label) + ' <code>' + esc(setId) + '</code></h3>' +
    // The two halves in this order because the second is the one that changes
    // per person, and a reader who has just pressed Update wants to see the
    // table they pressed it under rather than scroll past a form they did not
    // touch. The headings say which half is which: they are configured
    // separately, audited separately, and only one of them can be wrong in a way
    // the directory explains.
    '<p class="sub">Typed ' + noun + 's &mdash; a name and a value, the same for everybody.</p>' +
    '<table><tr><th>Name</th>' + extraHeader + '<th>Value</th><th></th></tr>' +
    (rows || '<tr><td colspan="' + (extraHeader ? 4 : 3) + '">No custom ' + noun + ' is configured; ' +
             'these ' + carrier + ' carry only what the protocol puts in them.</td></tr>') + '</table>' +
    '<form method="post" action="' + esc(pageUrl) + '"><div class="formrow">' +
      '<input type="hidden" name="action" value="add">' +
      '<input type="hidden" name="set" value="' + esc(setId) + '">' +
      '<label for="n-' + setId + '">Name</label>' +
      '<input type="text" id="n-' + setId + '" name="name" size="20">' +
      extraInput +
      '<label for="v-' + setId + '">Value</label>' +
      '<input type="text" id="v-' + setId + '" name="value" size="28">' +
      '<button>Add</button>' +
      '</div></form>' +
    (claims.length
      ? '<form method="post" action="' + esc(pageUrl) + '" class="inline">' +
        '<input type="hidden" name="action" value="clear">' +
        '<input type="hidden" name="set" value="' + esc(setId) + '">' +
        '<button class="secondary">Clear this set</button></form>'
      : '') +
    '<p class="sub">Directory attributes &mdash; a value read off each person\'s own entry.</p>' +
    claimAttributeSection(setId, previewUser, values, pageUrl);
}

// ---------------------------------------------------------------------------
// THE GROUPS CLAIM, on the page that already answers "what will the next token
// carry".
//
// READ-ONLY here, and that is a decision rather than an omission. Its four
// settings live in config.js's table, which means /admin/config and POST
// /admin-api/config/set already change them — a second form here would be a
// second door to one setting, which is exactly the two-stores mistake this
// service keeps out of everything else. So this section reports and links; the
// parity rule (a control gets an API operation in the same commit) is satisfied
// by there being no new control.
//
// What it does add is the thing no configuration page can: what the claim WOULD
// say about the person being previewed, built by groupsOf() — the same function
// the issuance path calls — so a preview that agreed with the page and
// disagreed with the token is not possible.
// ---------------------------------------------------------------------------
function groupClaimSection(previewUser) {
  log.debug("Entering groupClaimSection(). user=" + previewUser);
  const state = groupClaims.state();
  const answer = groupClaims.groupsOf(previewUser);
  const rows = answer.groups.map(function (group) {
    // WHY this group is in the list, which is the whole of the memberOf
    // disagreement in one cell: `member` and its two siblings are the GROUP
    // saying so, memberOf is the PERSON saying so, and this directory maintains
    // neither from the other.
    const how = group.via.length
      ? group.via.map(function (name) { return '<code>' + esc(name) + '</code>'; }).join(', ')
      : '';
    const counted = group.via.length || state.memberOfCounts;
    return '<tr><td><code>' + esc(group.dn) + '</code></td>' +
      '<td>' + esc(group.cn) + '</td>' +
      '<td>' + (how || '&mdash;') +
      (group.viaMemberOf
        ? (how ? ', ' : '') + 'the person\'s own <code>memberOf</code>' +
          (state.memberOfCounts ? '' : ' <em>(not counted)</em>')
        : '') + '</td>' +
      '<td>' + (counted ? 'yes' : 'no') + '</td></tr>';
  }).join('');

  const values = answer.values.length
    ? '<p class="note">The claim <code>' + esc(state.claim) + '</code> would carry ' +
      codeList(answer.values) + '.</p>'
    : '<p class="note">No claim at all for this person &mdash; not an empty list, absent. ' +
      esc(answer.reason) + '</p>';

  log.debug("Leaving groupClaimSection(). " + answer.values.length + " value(s).");
  return '<h2>The groups claim</h2>' +
    '<p class="note">The one thing on this page that is <strong>not</strong> chosen per set: ' +
    'with <code>groups.claim</code> on, all four carry it, for anybody who is a member of a ' +
    'group in <a href="/admin/groups">the embedded directory</a>. The membership is read at the ' +
    'moment a token is minted, so an <code>ldapmodify</code> changes the next one, and somebody ' +
    'in no group gets no claim rather than an empty list &mdash; which is why this can be on by ' +
    'default without changing what an existing client receives.</p>' +

    '<div class="' + (state.enabled && !state.problem ? 'note' : 'warn') + '">' +
    (state.enabled
      ? (state.problem
          ? '<strong>On, and not arriving.</strong> ' + esc(state.problem)
          : '<strong>On.</strong> Every access token, ID Token and both SAML assertions carry ' +
            '<code>' + esc(state.claim) + '</code>, each value being ' +
            (state.valueForm === 'dn' ? 'the group\'s whole DN' : 'the group\'s <code>cn</code>') +
            '. A person\'s own <code>memberOf</code> ' +
            (state.memberOfCounts ? 'counts' : 'does NOT count') + ' as membership.')
      : '<strong>Off.</strong> No token or assertion carries a groups claim. ' +
        'Turn it on with <code>groups.claim</code>.') +
    ' Change any of it on <a href="/admin/config">the configuration page</a>: ' +
    codeList(state.settings) + '.' +
    (state.loaded ? '' : ' <strong>The embedded directory is not loaded in this process</strong>, ' +
                         'so there are no groups to read.') +
    '</div>' +

    '<div class="warn"><strong>Carrying a group is not granting one.</strong> No endpoint here ' +
    'reads this claim and nothing decides anything on it &mdash; the same sentence ' +
    '<a href="/admin/groups">the groups page</a> has always carried, and the half of it that ' +
    'changed is that a token now says so out loud.</div>' +

    '<p class="note">A typed claim above, and a ticked directory attribute above, both win over ' +
    'this one where the names collide: those were named on this page about this service, and ' +
    'this comes from a setting and a directory.</p>' +

    '<h3>What ' + esc(previewUser) + ' would get</h3>' +
    values +
    (answer.groups.length
      ? '<table><tr><th>Group</th><th>cn</th><th>Named by</th><th>Counted</th></tr>' +
        rows + '</table>'
      : '<p class="note">' + esc(previewUser) + ' is named by no group here' +
        (answer.entryFound ? '' : ', and has no entry in the directory either') + '. ' +
        'The entry would be at <code>' + esc(answer.dn) + '</code>.</p>');
}

// One family of sets and the rules that govern them. The rules are in the reply
// and not only on the page because the first thing a caller of POST
// .../claims/add needs is the list of names it will refuse.
//
// TWO CALLERS, ONE BUILDER, for the reason claimsAction() has one: the two
// pages differ in WHICH sets they carry and in one rule each — the reserved JWT
// names apply to a token and the default SAML 1.1 namespace to an assertion —
// and everything else about the reply is the same fact answered twice. Two
// builders would have been two previews that could disagree about one person,
// which is precisely the thing every preview here is built through the issuance
// path to prevent.
function claimSetsJson(ids, previewUser) {
  log.debug("Entering claimSetsJson(). " + ids.length + " set(s).");
  const user = previewUser || 'alice';
  const json = {
    placeholders: stats.PLACEHOLDERS,
    // The catalogue every set chooses from, so a caller can discover the legal
    // values of `attributes` without reading this service's source or guessing
    // at LDAP spellings. `sets` says which of the FOUR carries each — all four,
    // not only the ones in this reply, because the catalogue is one list and a
    // per-page view of it would answer "which sets carry mail" with half the
    // truth.
    attributeCatalogue: claimAttributes.catalogueRows(),
    // Stated rather than left to be discovered, because the two halves of a set
    // are one screen apart and the precedence only shows up when both name one
    // claim.
    precedence: 'A typed claim wins over a directory attribute of the same name.',
    sets: ids.map(function (id) {
      const preview = claimAttributes.previewFor(id, user);
      return { id: id, label: stats.CLAIM_SETS[id].label,
               claims: stats.claimSet(id),
               attributes: claimAttributes.selectedNames(id),
               // What those attributes would actually put in this set right now,
               // built by the function the ISSUANCE path calls. A caller with no
               // browser has no other way to ask "what would this issue", and a
               // preview built by a second walk of the catalogue would be a
               // preview that can disagree with the token.
               attributeClaims: preview.claims,
               attributeReport: preview.report };
    }),
    // Whether the directory holds this person at all, and what every attribute
    // in the catalogue would say about them — selected or not, so a caller can
    // see what ticking a box would do before ticking it. Read through
    // catalogueValuesFor() rather than off one of the previews above, because a
    // set with nothing selected reports no entry: that is the right answer to
    // "what does this set carry" and the wrong answer to "is this person in the
    // directory".
    preview: Object.assign({ user: user }, claimAttributes.catalogueValuesFor(user)),
    // The groups claim, which is the one thing here that is not chosen per set:
    // all four carry it or none does — which is also why it is reported by BOTH
    // pages' replies rather than by the one it was written on. Its settings are
    // config.js's, so this is a report and there is no operation beside it —
    // POST /admin-api/config/set is the door, and a second one would be a
    // second store for one setting.
    //
    // `preview` is built by the function the ISSUANCE path calls, for the
    // reason every other preview here is: a caller with no browser has no other
    // way to ask "what would this token carry", and a second walk of the
    // directory would be a preview that can disagree with the token.
    groups: Object.assign(groupClaims.state(),
                          { preview: groupClaims.groupsOf(user) })
  };
  log.debug("Leaving claimSetsJson(). " + json.sets.length + " set(s).");
  return json;
}

// The two JWT sets, and the one rule that is theirs alone: the claim names this
// service sets itself and refuses. It is in the reply rather than only in the
// document because the first thing a caller of POST /admin-api/claims/add needs
// is the list of names it will be refused for.
function claimsJson(previewUser) {
  log.debug("Entering claimsJson(). previewUser=" + previewUser);
  const json = Object.assign(
    { reservedJwtClaims: stats.RESERVED_JWT_CLAIMS },
    claimSetsJson(stats.JWT_CLAIM_SET_IDS, previewUser));
  log.debug("Leaving claimsJson(). " + json.sets.length + " set(s).");
  return json;
}

// The two SAML sets, and the one rule that is theirs: the namespace a SAML 1.1
// attribute gets when nobody names one. THERE IS NO `reservedJwtClaims` HERE
// and its absence is the honest answer rather than an oversight — that list is
// enforced for a JWT set only (admin_stats.js's setClaimSet() checks `kind`),
// because an assertion attribute called `exp` collides with nothing. Reporting
// it here would have told a caller their call would be refused when it will
// succeed.
function samlAttributesJson(previewUser) {
  log.debug("Entering samlAttributesJson(). previewUser=" + previewUser);
  const json = Object.assign(
    { defaultSaml11Namespace: stats.DEFAULT_SAML11_NAMESPACE },
    claimSetsJson(stats.SAML_CLAIM_SET_IDS, previewUser));
  log.debug("Leaving samlAttributesJson(). " + json.sets.length + " set(s).");
  return json;
}

// ---------------------------------------------------------------------------
// THE PROSE BOTH PAGES NEED, WRITTEN ONCE.
//
// /admin/claims and /admin/saml-attributes are the same two halves — a typed
// entry and a ticked directory attribute — put into two different vocabularies,
// so most of what each page has to explain is one explanation. It is factored
// into these four helpers rather than copied, because the copy that is not
// edited alongside the other is the one a reader believes: two pages disagreeing
// about what `${username}` does, or about whether a typed entry wins, would be
// worse than either page saying nothing.
//
// `family` is 'jwt' or 'saml' and is the ONLY thing that varies. Where the two
// genuinely differ — a JWT value is typed and a SAML one is always text, a JWT
// nests and an assertion cannot — the difference is stated rather than
// generalised away, because that pair of facts is exactly what somebody
// comparing an ID Token with an assertion has come here to find.
// ---------------------------------------------------------------------------
function claimHalvesNote(family) {
  const noun = family === 'saml' ? 'attribute' : 'claim';
  const carrier = family === 'saml' ? 'assertion' : 'token';
  return '<p class="note">Each set has <strong>two halves</strong>. A <em>typed ' + noun +
    '</em> is a name and a value somebody wrote here, the same for everybody except where it ' +
    'carries a <code>${placeholder}</code>. A <em>directory attribute</em> is ticked from the ' +
    'catalogue below and its value is whatever that person\'s entry under <code>ou=users</code> ' +
    'says — so an <code>ldapmodify</code> changes the next ' + carrier + ', and an LDAP client ' +
    'and a relying party pointed at this service are shown the same person. That is the half ' +
    'worth exercising, and until the catalogue existed only a Verifiable Credential could do ' +
    'it.</p>';
}

// The "show me somebody" form. It is a GET form posting to the page's own path,
// so the preview user survives in the URL and every action form on the page can
// carry it into its redirect — see claimsPageUrl().
function claimPreviewForm(path, previewUser, values) {
  return '<form method="get" action="' + esc(path) + '"><div class="formrow">' +
    '<label for="user">Show the values for</label>' +
    '<input type="text" id="user" name="user" size="20" value="' + esc(previewUser) + '">' +
    '<button class="secondary">Show</button>' +
    '<span class="note">' + (values.entryFound
      ? 'This person has an entry in the directory, so the values marked <em>directory</em> are ' +
        'what an LDAP client reads from it.'
      : 'This person has no entry in the directory — nobody has authenticated as them and nothing ' +
        'was added by hand — so every value below is generated. It will be the same one next ' +
        'time: the invented person is seeded from the username.') + '</span></div></form>';
}

function attributeCatalogueNotes(family) {
  const saml = family === 'saml';
  const otherPage = saml
    ? '<a href="/admin/claims">the custom claims page</a>'
    : '<a href="/admin/saml-attributes">the SAML attributes page</a>';
  const otherThing = saml ? 'an access token or an ID Token carries' : 'an assertion carries';
  return '<h2>Where a directory attribute comes from, and what it does not do</h2>' +
    '<p class="note">The catalogue is of <strong>LDAP attribute types</strong> and not of ' +
    (saml ? 'attribute names' : 'claim names') + ', and it is the same catalogue ' +
    otherPage + ' and <a href="/admin/vc">the credential claims page</a> choose from — one list ' +
    'of spellings, because two would eventually disagree about what <code>schacDateOfBirth</code> ' +
    'is called while both looked right. The value is the one on that person\'s entry under ' +
    '<code>ou=users</code>; where the entry has nothing, it is invented from the username — the ' +
    'same invented person every time, across restarts, in obviously fictional ranges. Three rows ' +
    'are not RFC 4519/4524/2798: there is no standard attribute type for a birthdate or a ' +
    'nationality, so the SCHAC schema\'s names are borrowed rather than invented.</p>' +
    '<p class="note">The <strong>four selections are independent</strong>, and that is the point ' +
    'of having four: an access token carrying <code>employee_number</code> and a SAML 2.0 ' +
    'assertion carrying <code>email</code> is a normal arrangement and a single list could not ' +
    'express it. The two on this page are independent of what ' + otherThing + ' — ticked on ' +
    otherPage + ' — and of what a <a href="/admin/vc">credential</a> carries and what the ' +
    '<a href="/admin/vc-verifier-config">Verifier asks for</a>, deliberately: that is what keeps ' +
    '"issue a credential carrying a claim the access token does not" reachable.</p>' +
    (saml
      ? '<p class="note">A <strong>nested</strong> claim cannot stay nested here. A SAML ' +
        'Attribute\'s content model is a name and text values, so <code>address.locality</code> ' +
        'arrives as an attribute whose NAME is the dotted path, where a JWT would carry a ' +
        '<code>locality</code> member of an <code>address</code> object (OIDC Core 5.1.1). Both ' +
        'families then call one claim by one name, which is the property somebody comparing an ' +
        'ID Token with an assertion needs.</p>'
      : '<p class="note">A <strong>nested</strong> claim stays nested in a JWT: ' +
        '<code>address.locality</code> is a <code>locality</code> member of an <code>address</code> ' +
        'object, which is what OIDC Core 5.1.1 defines. A SAML Attribute has no way to spell that — ' +
        'the content model is a name and text values — so the assertion carries the dotted path as ' +
        'the attribute\'s name. Both families then call one claim by one name, which is the ' +
        'property somebody comparing an ID Token with an assertion needs.</p>') +
    '<p class="note"><strong>A typed ' + (saml ? 'attribute' : 'claim') + ' of the same name ' +
    'wins.</strong> Somebody who wrote <code>email</code> by hand on the set that also has ' +
    '<code>mail</code> ticked has said something specific, and the specific thing beats the ' +
    'general one. In an assertion that has to be a filter rather than an overwrite: two ' +
    '<code>&lt;Attribute&gt;</code> elements with one name would leave a relying party reading ' +
    'whichever the builder emitted first.</p>' +
    (saml
      ? '<p class="note"><strong>And the protocol\'s own attribute beats both</strong>, which is ' +
        'worth knowing before it is discovered in an assertion. A SAML 2.0 assertion sets ' +
        '<code>name</code> from the sign-in and a WS-Federation one sets the whole identity claim ' +
        'list, so ticking <code>cn</code>, <code>givenName</code>, <code>sn</code>, ' +
        '<code>uid</code> or <code>mail</code> may change nothing a relying party sees. The rule ' +
        'is not this page\'s: a configured attribute is ADDED to an assertion and never ' +
        'substituted into one, because an attribute a relying party keys off that a web form ' +
        'could displace would break a sign-in somewhere that looks nothing like this page.</p>'
      : '<p class="note"><strong>And the protocol\'s own claim beats both</strong>, which is worth ' +
        'knowing before it is discovered on a token. An ID Token always carries <code>name</code>, ' +
        '<code>given_name</code>, <code>family_name</code>, <code>preferred_username</code> and ' +
        '<code>email</code> built from the sign-in, so ticking <code>cn</code>, ' +
        '<code>givenName</code>, <code>sn</code>, <code>uid</code> or <code>mail</code> <em>on ' +
        'that set</em> changes nothing the client sees — the same five reach an access token, ' +
        'where the protocol sets none of them, and reach it from the directory. The rule is not ' +
        'new and is not this page\'s: a configured claim is added to a token and never ' +
        'substituted into one, because a claim a relying party keys off that a web form could ' +
        'displace would break a sign-in somewhere that looks nothing like this page.</p>') +
    '<p class="note"><strong>None of it is verified and none of it grants anything.</strong> This ' +
    'service authenticates nobody — the username typed at the sign-in screen is the identity in ' +
    'everything it issues — so a birthdate from here is a birthdate from a web form. No endpoint ' +
    'here reads one of these back or decides anything on one. That is true of the groups claim as ' +
    'well: it is carried, and a group on that person\'s entry still grants them nothing &mdash; ' +
    'see <a href="/admin/groups">the groups page</a>.</p>';
}

// WHICH PLACEHOLDERS ACTUALLY EXPAND IN AN ASSERTION, which is not the list the
// claims page advertises and is worth being exact about rather than tidy.
//
// A placeholder is expanded against the CONTEXT the issuance path hands
// admin_stats.expandValue(), and the two assertion builders hand it
// `{ subject, audience }` — saml2.js and saml11.js, the same one line each —
// where oauth2.js hands a token's whole claim context. So `${username}`,
// `${email}` and the rest of PLACEHOLDERS reach an assertion as the characters
// they were written as. That is the documented behaviour of an unknown
// placeholder (it names itself rather than silently becoming empty), and it is
// not a defect of this page — but a page that recited the JWT list under a SAML
// heading would be telling somebody their attribute will carry a name when it
// will carry `${username}`. `${now}` and `${iso}` are computed inside
// expandValue() and so work everywhere.
const SAML_PLACEHOLDERS = ['subject', 'audience', 'now', 'iso'];

function claimValueNotes(family) {
  const saml = family === 'saml';
  return '<h2>Values</h2>' +
    '<p class="note">A value may contain <code>${placeholders}</code>, because a value that can ' +
    'only be a constant cannot exercise the thing worth testing — that an ' +
    (saml ? 'attribute' : 'claim') + ' carrying the signed-in user\'s identity reaches the ' +
    'relying party. ' +
    (saml
      ? 'The ones an ASSERTION expands are ' + codeList(SAML_PLACEHOLDERS) + ', and that is a ' +
        'shorter list than <a href="/admin/claims">the token page\'s</a> on purpose rather than ' +
        'by oversight: an assertion is built from a subject and an audience, so the names a ' +
        'JWT context carries — <code>${username}</code>, <code>${email}</code> and the rest — ' +
        'have nothing to expand against here and arrive as the characters they were written as. ' +
        '<code>${subject}</code> is the one that carries the signed-in identity.'
      : 'The ones understood are ' + codeList(stats.PLACEHOLDERS) + '.') +
    ' An unknown one ' +
    'is left as it was written rather than replaced with nothing: <code>${dept}</code> that ' +
    'silently became an empty string is a bug that looks like a configuration mistake, and one ' +
    'that still says <code>${dept}</code> names itself.</p>' +
    (saml
      ? '<p class="note"><strong>A SAML attribute value is never typed.</strong> The XML content ' +
        'model is text, so <code>true</code> and <code>{"a":1}</code> reach the relying party as ' +
        'the characters they were written as — which is the opposite of what the same value does ' +
        'in a JWT, where it would arrive as a boolean and an object. That difference is worth ' +
        'knowing rather than discovering: a client library that parses an assertion attribute ' +
        'into a boolean is doing that on its own.</p>'
      : '<p class="note">A JWT claim value is typed: text that unambiguously looks like JSON — an ' +
        'object, an array, a bare <code>true</code>/<code>false</code>/<code>null</code>, or a ' +
        'number — is used as that JSON, and anything else is a string. One consequence, stated ' +
        'rather than left to be discovered: a claim whose value is genuinely the four characters ' +
        '<code>true</code> cannot be configured, because a text field cannot tell the two apart. ' +
        'Write <code>"true"</code>, which parses as the JSON string. <a href="/admin/saml-' +
        'attributes">SAML attribute values</a> are never typed — the XML content model is ' +
        'text.</p>');
}

// The "replace a whole set" form, which is the one a test wants: POST the same
// thing as JSON and get JSON back. The SELECT is built from the ids the page
// carries, so the SAML page cannot offer a token set and the claims page cannot
// offer an assertion one — the same restriction claimsAction()'s `allowed`
// enforces on the way in, said in the markup so it is not only a refusal.
function replaceSetForm(ids, pageUrl, family) {
  const options = ids.map(function (id) {
    return '<option value="' + esc(id) + '">' + esc(stats.CLAIM_SETS[id].label) + '</option>';
  }).join('');
  const noun = family === 'saml' ? 'attributes' : 'claims';
  return '<h2>Replace a whole set</h2>' +
    '<p class="note">The form a test wants. POST the same thing as JSON to get JSON back. This ' +
    'replaces the <em>typed</em> ' + noun + ' only; the directory attributes ticked above are a ' +
    'separate action (<code>attributes</code>) and are left alone by it.</p>' +
    '<form method="post" action="' + esc(pageUrl) + '">' +
      '<input type="hidden" name="action" value="replace">' +
      '<div class="formrow"><label for="set">Set</label>' +
      '<select id="set" name="set">' + options + '</select></div>' +
      '<textarea name="claims" spellcheck="false">[{"name": "dept", "value": "engineering"}, ' +
      '{"name": "on_behalf_of", "value": "${username}"}]</textarea>' +
      '<div class="formrow"><button>Replace</button></div>' +
    '</form>';
}

app.get('/admin/claims', function (req, res) {
  log.debug("Entering the admin claims page.");
  const previewUser = claimsPreviewUser(req.query);
  const pageUrl = claimsPageUrl(req.query);
  // ONE read of the directory and one invented persona for the whole page, not
  // one per set: both tables show the same catalogue of values for the same
  // person, and a read of one entry per section would be one that exists only
  // because the sections were written separately.
  const values = claimAttributes.catalogueValuesFor(previewUser);

  const inner = messagesOf(req) +
    '<p class="note">What to add to every <strong>token</strong> this service issues <em>from now ' +
    'on</em>. Nothing already issued changes — a token is a signed document and this page cannot ' +
    'reach inside one. Two sets, because an OAuth 2.0 access token and an OIDC ID Token go to ' +
    'different readers: one to a resource server and one to a client, and the interesting ' +
    'configuration is usually the one where they DIFFER.</p>' +

    '<p class="note">The other two sets are next door. <strong>SAML 2.0 and SAML 1.1 assertions ' +
    'are configured on <a href="/admin/saml-attributes">Custom SAML attributes</a></strong>, ' +
    'under SAML, because those two spell an attribute differently enough from a JWT claim — and ' +
    'from each other — that one page had to explain three vocabularies before a reader could ' +
    'change one. The store is the same one either way, and so is the audit row.</p>' +

    claimHalvesNote('jwt') +

    claimPreviewForm('/admin/claims', previewUser, values) +

    '<div class="warn"><strong>Custom claims are additive.</strong> A configured claim is added to ' +
    'what the protocol already puts in the token and never replaces one. The names this service ' +
    'sets itself are refused rather than silently ignored: ' +
    codeList(stats.RESERVED_JWT_CLAIMS) + '. Every one of them is ' +
    'load-bearing somewhere here — an <code>exp</code> settable from a web form would produce ' +
    'tokens that fail to verify with nothing pointing back at this page. The list is a JWT rule ' +
    'and only a JWT rule: an <a href="/admin/saml-attributes">assertion attribute</a> called ' +
    '<code>exp</code> collides with nothing and is allowed.</div>' +

    '<h2>The two token sets</h2>' +
    stats.JWT_CLAIM_SET_IDS.map(function (id) {
      return claimSetSection(id, previewUser, values, pageUrl);
    }).join('') +

    groupClaimSection(previewUser) +

    attributeCatalogueNotes('jwt') +

    claimValueNotes('jwt') +

    replaceSetForm(stats.JWT_CLAIM_SET_IDS, pageUrl, 'jwt');

  respond(req, res, claimsJson(previewUser), 'Custom claims', '/admin/claims', inner);
  log.debug("Leaving the admin claims page.");
});

// ---------------------------------------------------------------------------
// GET /admin/saml-attributes
//
// THE SAME TWO HALVES FOR THE TWO ASSERTION VOCABULARIES, on their own page and
// under the console's own SAML group since 2026-08-24. It was four sections of
// /admin/claims, and the reason for moving is not tidiness: a reader who has
// come to add an attribute to a WS-Federation assertion had to read past an
// OAuth access token and an OIDC ID Token, in a page whose every warning was
// about JWT claim names that do not apply to them. The two SAML sets differ
// from the JWT pair in three ways that all have to be said on whichever page
// carries them — a NameFormat, an AttributeNamespace, and a content model that
// is text and cannot nest — so saying them here costs one page and buys two
// that are each about one thing.
//
// WHAT DID NOT MOVE IS THE STORE. admin_stats.js still holds one CLAIM_SETS
// object with all four sets in it, setClaimSet() is still the one door onto it,
// and claimsAction() is still the one function both pages post to. This page is
// a VIEW of two of those sets and an `allowed` list on the way in; it is not a
// second place assertions are configured.
// ---------------------------------------------------------------------------
app.get('/admin/saml-attributes', function (req, res) {
  log.debug("Entering the admin SAML attributes page.");
  const previewUser = claimsPreviewUser(req.query);
  const pageUrl = samlAttributesPageUrl(req.query);
  const values = claimAttributes.catalogueValuesFor(previewUser);

  const inner = messagesOf(req) +
    '<p class="note">What to add to every <strong>SAML assertion</strong> this service issues ' +
    '<em>from now on</em>. Nothing already issued changes — an assertion is a signed document and ' +
    'this page cannot reach inside one. Two sets, because SAML 2.0 and SAML 1.1 spell an ' +
    'attribute differently enough that one list could not serve both: 2.0 has ' +
    '<code>Name</code> and an optional <code>NameFormat</code>, and 1.1 has ' +
    '<code>AttributeName</code> and a required <code>AttributeNamespace</code>.</p>' +

    '<p class="note"><strong>Where these assertions come from.</strong> The SAML 2.0 set reaches ' +
    'every assertion <a href="/admin/sts-metadata">WS-Trust</a> issues with a 2.0 token type; the ' +
    'SAML 1.1 set reaches the 1.1 ones, which is what <strong>WS-Federation\'s passive requestor ' +
    'profile</strong> carries — so the 1.1 half is the one a browser sign-in exercises. There is ' +
    'no SAML 2.0 Web SSO profile here, deliberately, so no assertion of that kind reaches a ' +
    'browser: the 2.0 set is exercised by a WS-Trust client.</p>' +

    '<p class="note">Tokens are next door. <strong>The OAuth 2.0 access token and the OIDC ID ' +
    'Token are configured on <a href="/admin/claims">Custom claims</a></strong>, under OAuth2 / ' +
    'OIDC. The store behind both pages is one store — the same four sets, the same ' +
    '<code>ldapmodify</code>-visible directory attributes, and one row in ' +
    '<a href="/admin/audit">the audit log</a> per change whichever page made it.</p>' +

    claimHalvesNote('saml') +

    claimPreviewForm('/admin/saml-attributes', previewUser, values) +

    '<div class="warn"><strong>Custom attributes are additive.</strong> A configured attribute is ' +
    'added to what the protocol already puts in the assertion and never replaces one — a SAML 2.0 ' +
    'assertion sets <code>name</code> from the sign-in and a WS-Federation one sets the whole ' +
    'identity claim list, and neither can be displaced from here. <strong>The reserved list on ' +
    '<a href="/admin/claims">the claims page</a> does not apply to these two sets</strong>: those ' +
    'names are load-bearing in a JWT, and an assertion attribute called <code>exp</code> or ' +
    '<code>scope</code> collides with nothing. What is refused here is the same thing that is ' +
    'refused there — an entry with no name, and two entries of one name, because the second would ' +
    'win silently.</div>' +

    '<h2>The two assertion sets</h2>' +
    stats.SAML_CLAIM_SET_IDS.map(function (id) {
      return claimSetSection(id, previewUser, values, pageUrl);
    }).join('') +

    groupClaimSection(previewUser) +

    attributeCatalogueNotes('saml') +

    claimValueNotes('saml') +

    '<h2>The SAML 1.1 namespace</h2>' +
    '<p class="note">A SAML 1.1 attribute is a NAME IN A NAMESPACE, and an attribute configured ' +
    'without one gets <code>' + esc(stats.DEFAULT_SAML11_NAMESPACE) + '</code> — the claim ' +
    'namespace every WS-Federation relying party already reads. That default is why an attribute ' +
    'added with a name and a value alone arrives somewhere useful instead of in a namespace ' +
    'nothing looks in. SAML 2.0 has no equivalent: <code>NameFormat</code> is optional there and ' +
    'is left off unless it is typed.</p>' +

    replaceSetForm(stats.SAML_CLAIM_SET_IDS, pageUrl, 'saml');

  respond(req, res, samlAttributesJson(previewUser), 'Custom SAML attributes',
          '/admin/saml-attributes', inner);
  log.debug("Leaving the admin SAML attributes page.");
});

// ---------------------------------------------------------------------------
// GET /admin/vc, POST /admin/vc
//
// WHICH CLAIMS AN ISSUED CREDENTIAL CARRIES. The page is a list of LDAP attribute
// types rather than of claim names, and vc_claims.js says at length why; the short
// version is that this service has a directory, so a claim can have a value that
// something other than the credential can see.
//
// It is the second page here that CHANGES what the protocol endpoints do, and the
// first that writes to the directory: saving a selection sweeps every person under
// ou=users and fills in what they are missing. That sweep is the whole point of
// the page rather than a side effect — without it, ticking `title` would change
// every future credential and change nothing an LDAP client could see, and the two
// halves of this service would quietly stop describing the same people.
// ---------------------------------------------------------------------------

// The values of a field that may appear MORE THAN ONCE in the body — which is what
// a list of checkboxes is, and what nothing else on this console needed until now.
//
// helpers.parseBody() cannot answer it: it builds a plain object, so a repeated
// field keeps only its LAST value and a form with ten boxes ticked would arrive as
// a selection of one. That is not a bug there — every other form on this console
// has scalar fields, and changing the shape of that function would change what
// eight other handlers see — so the repetition is read here, from the raw body,
// beside the parsed one.
function listField(req, body, name) {
  log.debug("Entering listField(). name=" + name);
  const type = String(req.headers['content-type'] || '');
  if (/json/i.test(type)) {
    const value = body[name];
    const out = Array.isArray(value) ? value.map(String)
              : (value == null || value === '' ? [] : [String(value)]);
    log.debug("Leaving listField(). " + out.length + " value(s) from a JSON body.");
    return out;
  }
  const raw = typeof req.body === 'string' ? req.body : '';
  const out = new URLSearchParams(raw).getAll(name);
  log.debug("Leaving listField(). " + out.length + " value(s) from a form body.");
  return out;
}

// The sweep's outcome as a sentence, appended to whatever message the action
// itself produced. It is stated on EVERY selection change, including the ones that
// changed nothing in the directory, because "0 entries gained anything" and "there
// is no directory here" are different facts and the page must not read the same
// for both.
function sweepText(sweep) {
  if (!sweep.loaded) {
    return ' The embedded directory is not loaded, so no entry was populated; ' +
           'credentials still carry these claims, generated per user.';
  }
  if (!sweep.ok) {
    return ' The directory could not be populated: ' + (sweep.errors || []).join(' ');
  }
  return ' Swept ' + sweep.examined + ' directory entry/entries; ' + sweep.changed +
         ' of them gained ' + sweep.values + ' value(s).';
}

function vcAction(body, names) {
  log.debug("Entering vcAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const current = vcClaims.selectedNames();

  if (action === 'select' || action === 'replace') {
    // `replace` is the same operation under the name a test would look for, and
    // the same name /admin/claims uses for "here is the whole set at once".
    const result = vcClaims.setSelection(names);
    if (!result.ok) {
      log.debug("Leaving vcAction(). The selection was refused.");
      return result;
    }
    const sweep = vcClaims.populateDirectory();
    log.debug("Leaving vcAction(). Selected " + result.selected.length + " attribute(s).");
    return { ok: true, selected: result.selected, added: result.added, removed: result.removed,
             sweep: sweep,
             message: 'A credential issued from now on carries ' + result.selected.length +
                      ' claim(s). Added: ' + (result.added.join(', ') || 'nothing') +
                      '. Removed: ' + (result.removed.join(', ') || 'nothing') + '.' +
                      sweepText(sweep) };
  }

  if (action === 'add' || action === 'remove') {
    const name = String(body.attribute || body.name || '').trim();
    if (!name) {
      log.debug("Leaving vcAction(). No attribute was named.");
      return { ok: false, errors: ['Name the attribute to ' + action + '.'] };
    }
    const lower = name.toLowerCase();
    const already = current.some(function (n) { return n.toLowerCase() === lower; });
    if (action === 'add' && already) {
      log.debug("Leaving vcAction(). Already selected.");
      return { ok: false, errors: ['"' + name + '" is already in the claim set.'] };
    }
    if (action === 'remove' && !already) {
      log.debug("Leaving vcAction(). Not selected.");
      return { ok: false, errors: ['"' + name + '" is not in the claim set.'] };
    }
    const wanted = action === 'add' ? current.concat([name])
                                    : current.filter(function (n) { return n.toLowerCase() !== lower; });
    const result = vcClaims.setSelection(wanted);
    if (!result.ok) {
      log.debug("Leaving vcAction(). The attribute was refused.");
      return result;
    }
    const sweep = vcClaims.populateDirectory();
    log.debug("Leaving vcAction(). " + action + " -> " + result.selected.length + " selected.");
    return { ok: true, selected: result.selected, sweep: sweep,
             message: (action === 'add' ? 'Added ' : 'Removed ') + name +
                      '. A credential issued from now on carries ' + result.selected.length +
                      ' claim(s).' + sweepText(sweep) };
  }

  if (action === 'defaults') {
    const result = vcClaims.resetSelection();
    const sweep = vcClaims.populateDirectory();
    log.debug("Leaving vcAction(). Restored the defaults.");
    return { ok: true, selected: result.selected, sweep: sweep,
             message: 'The claim set is the default ' + result.selected.length +
                      ' attribute(s) again — the six claims this issuer carried before this ' +
                      'page existed.' + sweepText(sweep) };
  }

  if (action === 'populate') {
    const sweep = vcClaims.populateDirectory();
    log.debug("Leaving vcAction(). Populated only.");
    return { ok: sweep.ok, errors: sweep.errors, selected: current, sweep: sweep,
             message: 'Populated the directory for the current claim set.' + sweepText(sweep) };
  }

  log.debug("Leaving vcAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The five are: select, add, ' +
                               'remove, defaults, populate.'] };
}

app.post('/admin/vc', function (req, res) {
  log.debug("Entering the admin credential-claims action endpoint.");
  const body = parseBody(req);
  // Two names for the list, because the two callers spell it differently and
  // neither spelling is wrong: a checkbox is one `attribute` repeated, and a JSON
  // body carries one `attributes` array.
  const names = listField(req, body, 'attribute').concat(listField(req, body, 'attributes'));
  const result = vcAction(body, names);
  respondToAction(req, res, '/admin/vc', result);
  log.debug("Leaving the admin credential-claims action endpoint.");
});

// The one preview row: what this attribute would put in a credential for the
// person the page is previewing, and where that value came from.
function vcExampleCell(row, persona, byLdap) {
  const found = byLdap[row.ldap.toLowerCase()];
  if (found) {
    return '<td><code>' + esc(found.value) + '</code></td><td>' + esc(found.source) + '</td>';
  }
  if (!row.from) {
    // The only row with no generator: `description`, which this service already
    // writes on every entry to record the protocols that person has used. Saying
    // so is the point — it is the one attribute whose value is a real fact.
    return '<td>—</td><td>the entry\'s own</td>';
  }
  // Shown in the form the CLAIM would take rather than the form the attribute
  // holds, because that is what the column above it is showing for the selected
  // rows and a table with two conventions in one column is a table nobody can
  // read. The two differ for exactly two attributes — a date and a postal
  // address — and both differences are punctuation.
  const raw = persona[row.from] == null ? '' : String(persona[row.from]);
  return '<td><code>' + esc(row.toClaim ? row.toClaim(raw) : raw) +
         '</code></td><td>would be generated</td>';
}

function vcAttributeTable(previewUser) {
  log.debug("Entering vcAttributeTable(). previewUser=" + previewUser);
  const persona = vcClaims.personaFor(previewUser);
  const built = vcClaims.subjectClaimsFor(previewUser, {});
  const byLdap = {};
  built.report.forEach(function (item) { byLdap[item.ldap.toLowerCase()] = item; });

  const rows = vcClaims.VC_ATTRIBUTES.map(function (row) {
    const on = vcClaims.isSelected(row.ldap);
    return '<tr><td><input type="checkbox" name="attribute" value="' + esc(row.ldap) + '"' +
      (on ? ' checked' : '') + '></td>' +
      '<td><code>' + esc(row.ldap) + '</code></td>' +
      '<td>' + esc(row.schema) + '</td>' +
      '<td><code>' + esc(row.claim.join('.')) + '</code></td>' +
      '<td>' + (row.ldpTerm ? '<code>' + esc(row.ldpTerm) + '</code>' : '<span class="state-none">—</span>') +
      '</td>' + vcExampleCell(row, persona, byLdap) + '</tr>';
  }).join('');

  log.debug("Leaving vcAttributeTable(). " + vcClaims.VC_ATTRIBUTES.length + " row(s).");
  return '<form method="post" action="/admin/vc">' +
    '<input type="hidden" name="action" value="select">' +
    '<table><tr><th>In</th><th>LDAP attribute</th><th>Defined by</th><th>Claim</th>' +
    '<th>ldp_vc term</th><th>In a credential for ' + esc(previewUser) + '</th><th>Source</th></tr>' +
    rows + '</table>' +
    '<div class="formrow"><button>Save this selection</button>' +
    '<span class="note">Saving also populates the directory: every person under ' +
    '<code>ou=users</code> gains the attributes they are missing.</span></div></form>' +
    '<div class="formrow">' +
    '<form method="post" action="/admin/vc" class="inline">' +
    '<input type="hidden" name="action" value="defaults">' +
    '<button class="secondary">Restore the six default claims</button></form> ' +
    '<form method="post" action="/admin/vc" class="inline">' +
    '<input type="hidden" name="action" value="populate">' +
    '<button class="secondary">Populate the directory now</button></form></div>';
}

// What a credential for this person would actually assert, claim by claim. It is
// built by the same function the issuer calls, not by a second walk of the
// catalogue — a preview that agreed with the page and disagreed with the
// credential would be worse than no preview.
function vcPreviewSection(previewUser) {
  log.debug("Entering vcPreviewSection(). previewUser=" + previewUser);
  const built = vcClaims.subjectClaimsFor(previewUser, {});
  const rows = built.report.map(function (item) {
    return '<tr><td><code>' + esc(item.claim) + '</code></td>' +
      '<td><code>' + esc(item.value) + '</code></td>' +
      '<td>' + esc(item.source) + '</td>' +
      '<td>' + (item.ldpTerm ? 'yes' : '<span class="state-none">no</span>') + '</td></tr>';
  }).join('');
  const omitted = vcClaims.ldpOmitted();

  log.debug("Leaving vcPreviewSection(). " + built.report.length + " claim(s).");
  return '<form method="get" action="/admin/vc"><div class="formrow">' +
    '<label for="user">Preview the credential for</label>' +
    '<input type="text" id="user" name="user" size="20" value="' + esc(previewUser) + '">' +
    '<button class="secondary">Show</button></div></form>' +
    '<p class="note">' + (built.entryFound
      ? 'This person has an entry in the directory, so the values below marked ' +
        '<em>directory</em> are what an LDAP client reads from it.'
      : 'This person has no entry in the directory — nobody has authenticated as them and ' +
        'nothing was added by hand — so every value below is generated. It will be the same ' +
        'one next time: the invented person is seeded from the username.') + '</p>' +
    '<table><tr><th>Claim</th><th>Value</th><th>From</th><th>In ldp_vc</th></tr>' +
    (rows || '<tr><td colspan="4">No attribute is selected, so a credential carries nothing ' +
             'but its subject identifier. That is a legitimate thing to test and is not a ' +
             'mistake this page will correct.</td></tr>') + '</table>' +
    (omitted.length
      ? '<p class="note"><strong>' + codeList(omitted) + '</strong> ' +
        (omitted.length === 1 ? 'is selected and does' : 'are selected and do') +
        ' not appear in an <code>ldp_vc</code> credential. That format is signed over ' +
        'canonicalized JSON-LD, so it can only carry terms the vendored context defines, and ' +
        'the context is vendored precisely because editing it would invalidate every ' +
        'credential already issued against it. The two JOSE-secured formats carry all of ' +
        'them.</p>'
      : '');
}

// Somebody the directory actually holds, so the page shows real values on a
// fresh start rather than an invented person nobody can look up. The parameter
// wins where it is given; the cap is there because this string is echoed.
function vcPreviewUser(query) {
  const asked = String((query && query.user) || 'alice').trim();
  return asked.slice(0, 64) || 'alice';
}

// The catalogue, the selection, and one person's claims as they would be minted
// right now. The preview is in the JSON as well as on the page because "what
// would this issue" is the question the selection exists to answer, and a
// caller with no browser has no other way to ask it.
function vcJson(previewUser) {
  log.debug("Entering vcJson(). previewUser=" + previewUser);
  const json = {
    selected: vcClaims.selectedNames(),
    defaults: vcClaims.DEFAULT_SELECTION,
    ldpOmitted: vcClaims.ldpOmitted(),
    attributes: vcClaims.VC_ATTRIBUTES.map(function (row) {
      return { ldap: row.ldap, claim: row.claim.join('.'), label: row.label,
               schema: row.schema, ldpTerm: row.ldpTerm || '',
               selected: vcClaims.isSelected(row.ldap) };
    }),
    preview: { user: previewUser,
               claims: vcClaims.subjectClaimsFor(previewUser, {}) }
  };
  log.debug("Leaving vcJson().");
  return json;
}

app.get('/admin/vc', function (req, res) {
  log.debug("Entering the admin credential-claims page.");
  const previewUser = vcPreviewUser(req.query);

  const inner = messagesOf(req) +
    '<p class="note">Which claims a Verifiable Credential issued by this service carries, ' +
    '<em>from now on</em>. Nothing already issued changes — a credential is a signed document ' +
    'and this page cannot reach inside one. It applies to all five OID4VCI configurations: the ' +
    'SD-JWT VC, the <code>jwt_vc_json</code> W3C credential, the <code>ldp_vc</code> one with a ' +
    'BBS proof, and the two whose only difference is that the issuer names itself by DID.</p>' +

    '<p class="note">The list is of <strong>LDAP attribute types</strong> and not of claim ' +
    'names, because this service has a directory and a claim with a value nothing else can see ' +
    'is half a demonstration. A selected attribute becomes the claim named beside it, and the ' +
    'value is the one on that person\'s entry under <code>ou=users</code> — so an LDAP client ' +
    'and an OID4VCI wallet pointed at this service are shown the same person. Three rows are ' +
    'not RFC 4519/4524/2798: there is no standard attribute type for a birthdate or a ' +
    'nationality, so the SCHAC schema\'s names are borrowed rather than invented.</p>' +

    '<div class="warn"><strong>None of this is verified, and the values are garbage on ' +
    'purpose.</strong> This service authenticates nobody — the username typed at the sign-in ' +
    'screen is the identity in every token and credential it issues — so there is no source of ' +
    'a real birthdate here and there had better not be. What a person is missing is invented ' +
    'from their username: the same invented person every time, across restarts, so that two ' +
    'credentials issued a minute apart describe one human being rather than two. A verifier ' +
    'that believed any of it would be believing this page.</div>' +

    '<h2>The attributes</h2>' +
    vcAttributeTable(previewUser) +

    '<h2>What a credential would carry</h2>' +
    vcPreviewSection(previewUser) +

    '<h2>Where a value comes from</h2>' +
    '<p class="note">Three sources, in this order. <strong>The access token</strong>, where it ' +
    'carries a claim of that name — that is a statement this service already made about the ' +
    'person, from the sign-in or from the <a href="/admin/claims">custom claims</a> page, and a ' +
    'credential contradicting the token that authorised it would be indefensible. Then <strong>' +
    'the directory entry</strong>, which is where the generated values live once an entry ' +
    'exists and also where an <code>ldapmodify</code> lands: change <code>mail</code> on ' +
    '<code>uid=alice,ou=users</code> and the next credential says so. Then <strong>the ' +
    'generated persona</strong>, for a person with no entry, or an entry without that ' +
    'attribute, or a directory that is not running.</p>' +
    '<p class="note">Populating never overwrites. An attribute an entry already carries is left ' +
    'exactly as it is — which is why the three seeded people keep their names and only gain what ' +
    'they had nothing for, and why a sweep run twice does nothing the second time.</p>' +

    '<h2>What these claims do not do</h2>' +
    '<p class="note">Nothing reads them back. No access token, ID Token, SAML assertion or ' +
    'Kerberos PAC carries a claim from this page, and no endpoint makes a decision on one — it ' +
    'reaches a credential and stops there. The <a href="/admin/users">users</a> page shows the ' +
    'directory entry each of these values was written onto.</p>';

  respond(req, res, vcJson(previewUser), 'Credential claims', '/admin/vc',
          inner);
  log.debug("Leaving the admin credential-claims page.");
});


// ---------------------------------------------------------------------------
// GET /admin/vc-verifier-config, POST /admin/vc-verifier-config
//
// WHAT THE BAR DOOR ASKS FOR — the other end of the page above. /admin/vc decides
// what an issued credential CARRIES; this decides what the Verifier at
// /oid4vp/verifier ASKS FOR, and the two are deliberately separate settings
// because the interesting states are the ones where they disagree. A Verifier
// asking for a claim the issuer is not minting is the negative that exercises a
// wallet's "I cannot satisfy this request" path, and there is no way to reach it
// if one page sets both.
//
// The catalogue is vc_claims.js's, grouped into CLAIMS rather than listed as
// attribute types, and vc_verifier_config.js says at length why: a credential
// carries one Disclosure per top-level claim, so `address` is one unit of
// disclosure however many attribute types feed it. Offering six address
// checkboxes would offer a choice that does not exist on the wire.
//
// It is the third page here that changes what a protocol endpoint does, and the
// only one whose effect is visible in a document this service SENDS rather than
// in one it issues — the dcql_query in the next Authorization Request.
// ---------------------------------------------------------------------------
function vpConfigAction(body, names) {
  log.debug("Entering vpConfigAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');

  if (action === 'select' || action === 'replace') {
    // An empty list is a legitimate save and not an empty form: DCQL with no
    // `claims` member asks for the WHOLE credential, so unticking everything is
    // how somebody tests that. It is stated in the message rather than left to be
    // discovered from a presentation that disclosed everything.
    const result = vpConfig.setRequested(names);
    if (!result.ok) {
      log.debug("Leaving vpConfigAction(). The selection was refused.");
      return result;
    }
    log.debug("Leaving vpConfigAction(). " + result.requested.length + " claim(s) requested.");
    return { ok: true, requested: result.requested, added: result.added, removed: result.removed,
             message: result.requested.length
               ? 'The next Authorization Request asks for ' + result.requested.length +
                 ' claim(s): ' + result.requested.join(', ') + '. Added: ' +
                 (result.added.join(', ') || 'nothing') + '. Removed: ' +
                 (result.removed.join(', ') || 'nothing') + '.'
               : 'The next Authorization Request names no claims at all, which in DCQL asks for ' +
                 'the WHOLE credential — the query carries no claims member. Removed: ' +
                 (result.removed.join(', ') || 'nothing') + '.' };
  }

  if (action === 'add') {
    const name = String(body.claim || body.name || '').trim();
    const result = vpConfig.addRequested(name);
    if (!result.ok) {
      log.debug("Leaving vpConfigAction(). The claim was refused.");
      return result;
    }
    const known = vpConfig.rowFor(name);
    log.debug("Leaving vpConfigAction(). Added " + name + ".");
    return { ok: true, requested: result.requested,
             message: 'Now asking for ' + name + '.' + (known ? '' :
               ' It is not in the catalogue, so no credential this service issues carries it — ' +
               'which is what makes it a test of what your wallet does with a request it cannot ' +
               'satisfy. This Verifier will refuse the presentation on the "Requested claims" ' +
               'check and name it.') };
  }

  if (action === 'remove') {
    const name = String(body.claim || body.name || '').trim();
    const result = vpConfig.removeRequested(name);
    if (!result.ok) {
      log.debug("Leaving vpConfigAction(). Nothing named that.");
      return result;
    }
    log.debug("Leaving vpConfigAction(). Removed " + name + ".");
    return { ok: true, requested: result.requested,
             message: 'No longer asking for ' + name + '.' };
  }

  if (action === 'defaults') {
    const result = vpConfig.resetRequested();
    log.debug("Leaving vpConfigAction(). Restored the startup request.");
    return { ok: true, requested: result.requested,
             message: 'Back to what this process started with: ' +
                      (result.requested.join(', ') || '(no claims)') + '. That is OID4VP_CLAIMS ' +
                      'where it was set and given_name, family_name where it was not.' };
  }

  if (action === 'format') {
    const result = vpConfig.setDefaultFormat(String(body.format || ''));
    if (!result.ok) {
      log.debug("Leaving vpConfigAction(). No such format.");
      return result;
    }
    log.debug("Leaving vpConfigAction(). Default format is " + result.format + ".");
    return { ok: true, format: result.format,
             message: 'A request that does not name a format now asks for a ' + result.format +
                      ' credential. The three format links on the bar door name one explicitly ' +
                      'and are unaffected.' };
  }

  log.debug("Leaving vpConfigAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The five are: select, add, ' +
                               'remove, defaults, format.'] };
}

app.post('/admin/vc-verifier-config', function (req, res) {
  log.debug("Entering the admin verifier-request action endpoint.");
  const body = parseBody(req);
  // Two names for the list, for the reason /admin/vc has two: a checkbox is one
  // `claim` repeated, and a JSON body carries one `claims` array.
  const names = listField(req, body, 'claim').concat(listField(req, body, 'claims'));
  const result = vpConfigAction(body, names);
  respondToAction(req, res, '/admin/vc-verifier-config', result);
  log.debug("Leaving the admin verifier-request action endpoint.");
});

// Whether the ISSUER currently mints the claim this Verifier is asking for. The
// two pages are separate settings on purpose (see the header), so the disagreement
// is a state to report rather than one to prevent — and reporting it is what stops
// "the wallet disclosed nothing" being investigated as a wallet bug.
function vpIssuedCell(claimName) {
  const carried = vpConfig.carriedNow(claimName);
  if (!carried.known) {
    return '<td><span class="state-none">not a claim this service issues</span></td>';
  }
  if (!carried.carried.length) {
    return '<td><span class="state-expired">no — not selected on ' +
           '<a href="/admin/vc">/admin/vc</a></span></td>';
  }
  if (carried.missing.length) {
    return '<td><span class="state-expired">partly — ' + codeList(carried.missing) +
           ' not selected</span></td>';
  }
  return '<td><span class="state-valid">yes</span></td>';
}

// One catalogue row. The DCQL path column is shown for the format the next
// unqualified request will use, because a path is not a property of the claim: the
// same claim is ["given_name"], ["credentialSubject","given_name"] or
// ["credentialSubject","birthDate"] depending on what is being asked for, and a
// column that picked one silently would be wrong two-thirds of the time.
function vpClaimRow(row, format) {
  const on = vpConfig.isRequested(row.claim);
  const paths = vpConfig.dcqlPathsFor(format, row.claim);
  const attributes = row.members.map(function (member) {
    return '<code>' + esc(member.ldap) + '</code> <span class="state-none">(' +
           esc(member.schema) + ')</span>';
  }).join('<br>');
  return '<tr><td><input type="checkbox" name="claim" value="' + esc(row.claim) + '"' +
    (on ? ' checked' : '') + '></td>' +
    '<td><code>' + esc(row.claim) + '</code>' +
    (row.nested ? '<br><span class="state-none">one object, ' + row.members.length +
                  ' attributes</span>' : '') + '</td>' +
    '<td>' + esc(row.label) + '</td>' +
    '<td>' + attributes + '</td>' +
    '<td>' + (paths.length
      ? paths.map(function (path) { return '<code>' + esc(JSON.stringify(path)) + '</code>'; }).join('<br>')
      : '<span class="state-expired">cannot be asked for in this format</span>') + '</td>' +
    '<td>' + (row.ldpTerms.length ? codeList(row.ldpTerms)
                                  : '<span class="state-none">—</span>') + '</td>' +
    vpIssuedCell(row.claim) + '</tr>';
}

// The claims being asked for that are NOT in the catalogue. Rendered as ticked
// checkboxes in the same form rather than as a separate list with its own Save,
// because a form that dropped them the moment somebody saved the table above would
// silently undo a deliberate configuration.
function vpExtraRows(format) {
  const extras = vpConfig.requestedRows().filter(function (row) { return !row.inCatalogue; });
  if (!extras.length) {
    return '';
  }
  return '<h3>Asked for, and not in the catalogue</h3>' +
    '<p class="note">Nothing this service issues carries these, which is what makes them worth ' +
    'asking for: it is the only way to see what a wallet does with a request it cannot satisfy, ' +
    'and what this Verifier says when it checks. They are ticked below so that saving the table ' +
    'above keeps them — untick one to stop asking for it.</p>' +
    '<table><tr><th>In</th><th>Claim</th><th>DCQL path (' + esc(format) + ')</th></tr>' +
    extras.map(function (row) {
      const paths = vpConfig.dcqlPathsFor(format, row.claim);
      return '<tr><td><input type="checkbox" name="claim" value="' + esc(row.claim) + '" checked></td>' +
        '<td><code>' + esc(row.claim) + '</code></td>' +
        '<td>' + paths.map(function (path) {
          return '<code>' + esc(JSON.stringify(path)) + '</code>';
        }).join('<br>') + '</td></tr>';
    }).join('') + '</table>';
}

function vpClaimsSection(format) {
  log.debug("Entering vpClaimsSection(). format=" + format);
  const rows = vpConfig.REQUESTABLE.map(function (row) { return vpClaimRow(row, format); }).join('');
  const omitted = format === 'ldp_vc' ? vpConfig.ldpOmitted() : [];
  log.debug("Leaving vpClaimsSection(). " + vpConfig.REQUESTABLE.length + " row(s).");
  return '<form method="post" action="/admin/vc-verifier-config">' +
    '<input type="hidden" name="action" value="select">' +
    '<table><tr><th>Ask</th><th>Claim</th><th>Label</th><th>LDAP attribute (defined by)</th>' +
    '<th>DCQL path (' + esc(format) + ')</th><th>ldp_vc term</th>' +
    '<th>Issued now</th></tr>' + rows + '</table>' +
    vpExtraRows(format) +
    '<div class="formrow"><button>Save this request</button>' +
    '<span class="note">It applies to the next Authorization Request. One already in flight ' +
    'keeps the claims it was built with — a Verifier that judged a presentation against a list ' +
    'changed after it asked would refuse a wallet for answering the question it was really ' +
    'asked.</span></div></form>' +
    (omitted.length
      ? '<p class="note"><strong>' + codeList(omitted) + '</strong> ' +
        (omitted.length === 1 ? 'is asked for and is' : 'are asked for and are') +
        ' dropped from an <code>ldp_vc</code> query. That format is signed over canonicalized ' +
        'JSON-LD, so only terms the vendored context defines can be named at all, and asking ' +
        'under a name it does not define would fail canonicalization rather than return less. ' +
        'The two JOSE-secured formats ask for all of them.</p>'
      : '') +
    '<div class="formrow">' +
    '<form method="post" action="/admin/vc-verifier-config" class="inline">' +
    '<input type="hidden" name="action" value="add">' +
    '<label for="claim">Also ask for a claim that is not in the catalogue</label>' +
    '<input type="text" id="claim" name="claim" size="24" placeholder="drivers_licence_number">' +
    '<button class="secondary">Add</button></form> ' +
    '<form method="post" action="/admin/vc-verifier-config" class="inline">' +
    '<input type="hidden" name="action" value="defaults">' +
    '<button class="secondary">Back to what this process started with</button></form></div>';
}

// The credential types a wallet may submit, and which one an unqualified request
// asks for. One request is for ONE of them: a presentation cannot convert between
// formats, so a wallet holding a jwt_vc_json credential has nothing to answer a
// dc+sd-jwt query with — and the honest outcome is that it says so rather than
// that this page pretends the choice does not matter.
function vpFormatsSection(format) {
  log.debug("Entering vpFormatsSection(). format=" + format);
  const rows = vpConfig.FORMATS.map(function (item) {
    const configs = item.configs.map(function (id) {
      return '<code>' + esc(id) + '</code>';
    }).join('<br>');
    return '<tr><td><input type="radio" name="format" value="' + esc(item.id) + '"' +
      (item.id === format ? ' checked' : '') + '></td>' +
      '<td><code>' + esc(item.id) + '</code><br>' + esc(item.label) + '</td>' +
      '<td><code>' + esc(item.identifiedBy) + '</code><br><code>' +
      esc(item.identifierText) + '</code></td>' +
      '<td>' + esc(item.selectiveDisclosure) + '</td>' +
      '<td>' + esc(item.holderBinding) + '</td>' +
      '<td>' + configs + '</td>' +
      '<td><a href="' + esc('/oid4vp/verifier?format=' + encodeURIComponent(item.id)) +
      '">Present one</a></td></tr>';
  }).join('');
  log.debug("Leaving vpFormatsSection(). " + vpConfig.FORMATS.length + " row(s).");
  return '<form method="post" action="/admin/vc-verifier-config">' +
    '<input type="hidden" name="action" value="format">' +
    '<table><tr><th>Default</th><th>Format</th><th>Identified in DCQL by</th>' +
    '<th>Selective disclosure</th><th>Holder binding</th><th>Issued here as</th><th></th></tr>' +
    rows + '</table>' +
    '<div class="formrow"><button>Ask for this one by default</button>' +
    '<span class="note">The default is what <code>/oid4vp/start</code> asks for when the link ' +
    'that reached it names no format. The bar door\'s three format buttons name one explicitly, ' +
    'so they are unaffected — a button saying "present an SD-JWT VC" that asked for something ' +
    'else would be lying in the one place a reader is most likely to trust it.</span></div>' +
    '</form>' +
    '<p class="note">' + vpConfig.FORMATS.map(function (item) {
      return '<strong>' + esc(item.id) + '</strong> — ' + esc(item.what);
    }).join('<br><br>') + '</p>' +
    '<p class="note">The identifying values are not settable here. They are what this service\'s ' +
    'own issuer mints (<code>vc_configs.js</code>), and a Verifier asking for a <code>vct</code> ' +
    'nobody here issues would be a request no wallet in this stack could ever satisfy — a ' +
    'negative worth having, but one that belongs to the issuer\'s configuration rather than to a ' +
    'text box on this page.</p>';
}

// What the bar door asks for, and the dcql_query that carries it. The query is
// built by the function that builds the REAL one — see the note in
// vc_verifier_config.js — so a caller reading this reply is reading the next
// Authorization Request rather than a description of one.
function vpConfigJson() {
  log.debug("Entering vpConfigJson().");
  const format = vpConfig.defaultFormatId();
  const json = {
    requested: vpConfig.requestedClaims(),
    defaults: vpConfig.defaultRequested(),
    format: format,
    formats: vpConfig.FORMATS.map(function (item) {
      return { id: item.id, label: item.label, identifiedBy: item.identifiedBy,
               identifier: item.identifier,
               selectiveDisclosure: item.selectiveDisclosure,
               holderBinding: item.holderBinding,
               configurations: item.configs };
    }),
    ldpOmitted: vpConfig.ldpOmitted(),
    catalogue: vpConfig.REQUESTABLE.map(function (row) {
      return { claim: row.claim, label: row.label, nested: row.nested,
               attributes: row.members.map(function (member) {
                 return { ldap: member.ldap, schema: member.schema };
               }),
               ldpTerms: row.ldpTerms,
               paths: vpConfig.dcqlPathsFor(format, row.claim),
               requested: vpConfig.isRequested(row.claim),
               issued: vpConfig.carriedNow(row.claim) };
    }),
    dcqlQuery: vpConfig.dcqlQuery(format)
  };
  log.debug("Leaving vpConfigJson(). Asking for " + json.requested.length +
            " claim(s).");
  return json;
}

app.get('/admin/vc-verifier-config', function (req, res) {
  log.debug("Entering the admin verifier-request page.");
  const format = vpConfig.defaultFormatId();
  const requested = vpConfig.requestedClaims();
  const query = vpConfig.dcqlQuery(format);

  const inner = messagesOf(req) +
    '<p class="note">What the mock Verifier at <a href="/oid4vp/verifier">/oid4vp/verifier</a> — ' +
    'the pages call it <em>The Bar Door</em> — asks a wallet for, and in which credential format. ' +
    'It reaches the wire as the <code>dcql_query</code> of the next OID4VP Authorization Request, ' +
    'and it is what the Verifier then checks the presentation against: a claim asked for and not ' +
    'presented fails the <em>Requested claims</em> check by name.</p>' +

    '<p class="note">The claims are the same catalogue <a href="/admin/vc">/admin/vc</a> fills a ' +
    'credential from, grouped into <strong>claims</strong> rather than listed as attribute types. ' +
    'A credential carries one Disclosure per top-level claim, so <code>address</code> is one unit ' +
    'of disclosure however many LDAP attributes feed it — asking for it gets the street, the ' +
    'locality, the region, the postal code and the country together, and a page offering six ' +
    'address checkboxes would be offering a choice that does not exist on the wire.</p>' +

    '<div class="warn"><strong>This asks; it does not admit anybody.</strong> A presentation that ' +
    'verifies here starts no session, issues no token and grants no access — the door says yes and ' +
    'that is the whole of it. Nothing else in this service reads what was presented. The two ' +
    'settings are also deliberately separate: this page decides what is ASKED FOR and ' +
    '<a href="/admin/vc">/admin/vc</a> decides what is ISSUED, so that asking for a claim the ' +
    'issuer does not mint stays reachable. That is the negative worth testing, and one page ' +
    'setting both would make it impossible to reach.</div>' +

    '<h2>The claims</h2>' +
    (requested.length
      ? '<p class="note">Asking for ' + requested.length + ': ' + codeList(requested) + '.</p>'
      : '<div class="warn"><strong>No claim is selected, and that is a real request rather than ' +
        'an empty form.</strong> DCQL reads an absent <code>claims</code> member as the WHOLE ' +
        'credential, so the query below carries none and the wallet is being asked for ' +
        'everything — the opposite of what selective disclosure is for, which is exactly why it ' +
        'is worth being able to ask for it.</div>') +
    vpClaimsSection(format) +

    '<h2>The credential types that can be submitted</h2>' +
    vpFormatsSection(format) +

    '<h2>The query this builds</h2>' +
    '<p class="note">Built by the function that builds the real one, not by a second walk of the ' +
    'table above — a preview that agreed with this page and disagreed with the request would be ' +
    'worse than no preview. It is the <code>dcql_query</code> parameter of the next ' +
    'Authorization Request, by value or inside the signed Request Object.</p>' +
    '<textarea readonly spellcheck="false">' + esc(JSON.stringify(query, null, 2)) + '</textarea>' +

    '<h2>What this page does not change</h2>' +
    '<p class="note">Not what the issuer mints — that is <a href="/admin/vc">/admin/vc</a>, and ' +
    'the <em>Issued now</em> column above is this page reporting on that one. Not a request ' +
    'already in flight, which keeps the claims it was built with. Not the <code>vct</code> or the ' +
    'type array a credential is identified by. And not what a verified presentation is worth: ' +
    'nothing here turns one into a credential of any kind.</p>';

  respond(req, res, vpConfigJson(), 'Verifier request',
          '/admin/vc-verifier-config', inner);
  log.debug("Leaving the admin verifier-request page.");
});



// ---------------------------------------------------------------------------
// /admin/realms — SEVERAL LOGICAL COPIES OF THIS SERVICE, IN ONE PROCESS.
//
// A TRUST REALM is a whole mock identity service: its own configuration, its
// own signing key, its own sessions, authorization codes, tokens, offers,
// service providers, statistics and audit log — answering on the SAME sockets
// as every other and told apart by a segment at the front of the path.
//
//   http://host:8081/oauth2/token                the default realm
//   http://host:8081/realm/acme/oauth2/token     the realm `acme`
//
// WHAT THIS PAGE IS FOR, and it is not "somewhere to keep a list". Two things
// nothing else here can tell you:
//
//   * WHAT A REALM'S ENDPOINTS ACTUALLY ARE. The prefix segment is a setting,
//     the ids are whatever somebody typed, and a client being pointed at a
//     realm has no way to derive either. Every row here carries the realm's
//     base URL, and the drill-down carries the four URLs a client asks for
//     first.
//   * WHICH FAMILIES ARE REALM-AWARE AND WHICH ARE NOT, WHICH IS NOT A TIDY
//     ANSWER. What a realm separates completely is what it ISSUES and what it
//     is holding while it issues it. What it does not separate at all is the
//     embedded DIRECTORY — one ou=users, one ou=groups and one ou=applications
//     for the whole process, because LDAP answers on a socket with no path to
//     put a realm segment in. So OAuth client registrations, SAML service
//     provider entries, the SPIFFE registry and the two admin roles are shared,
//     and so are Kerberos, the two TLS listeners and SPIFFE's four sockets.
//     Saying so is the whole reason the table at the foot of this page exists:
//     a person who assumed a realm was a boundary everywhere would find out
//     from an `ldapsearch`.
//
// **IT KEEPS NOTHING OF ITS OWN.** The registry is common/realms.js's, the
// per-realm settings are config.js's — set through the same
// `config.setOverride()` that /admin/config, /admin/token-lifetimes and
// POST /admin-api/config/set call, against the realm's own override map — and
// the signing key is helpers.js's. That is the one-store rule this console
// follows everywhere: a page holding its own copy of what a realm sets would be
// a second answer to "what is this realm configured with" that the protocol
// endpoints could not see.
//
// **THE DEFAULT REALM IS NOT A ROW SOMEBODY CREATED** and cannot be removed,
// renamed or re-prefixed. Every URL this service published before realms
// existed is a URL in it, so an operator who could delete it could delete the
// service.
// ---------------------------------------------------------------------------
const REALMS_CAVEAT =
  '<p class="note"><strong>A realm separates what this service ISSUES, not who it knows.</strong> ' +
  'Each realm has its own signing key, so a token minted in one does not verify against ' +
  'another\'s JWKS — that is the point of a realm rather than a side effect. What every realm ' +
  'SHARES is the embedded directory: one <code>ou=users</code>, one <code>ou=groups</code> and ' +
  'one <code>ou=applications</code> for the whole process, because LDAP answers on a socket with ' +
  'no path to put a realm segment in. So the same person can sign in to two realms and be one ' +
  'entry, a client registered once can be used in both, and <strong>the two admin roles are ' +
  'held once</strong> — there is no per-realm administrator. The table at the foot of this page ' +
  'is the whole list of what is separated how.</p>' +
  '<p class="note"><strong>Nothing here is persisted.</strong> Realms are held in memory like ' +
  'everything else in this service and die with the process, along with the keys they signed ' +
  'with. Define them from <code>POST /admin-api/realms</code> in whatever starts your stack if ' +
  'you want them back.</p>';

// The base URL of this service WITHOUT any realm prefix. Every URL this page
// prints is built from it, because a page read inside `acme` still has to be
// able to name `default`'s endpoints — and baseUrlOf() adds the ambient prefix
// by design.
function realmRootUrl(req) {
  const withRealm = baseUrlOf(req);
  return withRealm.slice(0, withRealm.length - realms.currentPrefix().length);
}

// What a realm sets, as rows. `config.describe()` is not used here and the
// reason is worth a line: describing a setting means RESOLVING it, and resolving
// it answers for the realm that is ambient rather than for the realm being
// listed. So the raw value the realm carries is shown, beside what that setting
// is called — which is what a person checking a realm's configuration is
// actually reading.
function realmSettingRows(realm) {
  log.debug("Entering realmSettingRows(). realm=" + realm.id);
  const rows = Object.keys(realm.overrides).sort().map(function (key) {
    const setting = configSettingFor(key);
    return { key: key, value: String(realm.overrides[key]),
             label: setting ? setting.label : key,
             group: setting ? setting.group : '' };
  });
  log.debug("Leaving realmSettingRows(). " + rows.length + " setting(s).");
  return rows;
}

// One realm as JSON. The same shape the list and the drill-down both answer
// with, and the same shape GET /admin-api/realms answers with, so that a test
// reading one has read all three.
function realmJson(req, realm) {
  const prefix = realms.prefixOf(realm);
  const base = realmRootUrl(req) + prefix;
  return {
    id: realm.id,
    name: realm.name,
    description: realm.description,
    builtin: !!realm.builtin,
    pathPrefix: prefix,
    baseUrl: base,
    // The kid of the realm's signing key. It is the one fact on this page that
    // PROVES the realms are separate rather than asserting it — two realms
    // showing one kid would be two names for one authorization server.
    //
    // Reading it MINTS it for a realm that has not signed anything yet, which is
    // a 2048-bit RSA generation and about a tenth of a second. That is accepted
    // deliberately: a console page that could not show a realm's key identifier
    // until something had used the realm would be showing a blank for exactly
    // the realm somebody had just created and was checking.
    kid: stsKeysFor.of(realm.id).kid,
    settings: realmSettingRows(realm),
    // The four a client asks for first, in this realm.
    endpoints: {
      openidConfiguration: base + '/.well-known/openid-configuration',
      authorizationServerMetadata: base + '/.well-known/oauth-authorization-server',
      jwks: base + '/oauth2/jwks',
      samlMetadata: base + '/saml2/metadata'
    }
  };
}

function realmsJson(req) {
  log.debug("Entering realmsJson().");
  const out = {
    // The SETTING, and whether any prefix is actually answering. They differ in
    // the one case that matters — the feature on with no realm defined — and a
    // single flag reported that as "off". See GET /realms, which answers the
    // same pair.
    enabled: config.value('realms.enabled'),
    active: realms.active(),
    pathSegment: realms.pathSegment(),
    current: realms.currentId(),
    // The ids a realm may not be called, read off the live router. It is here
    // rather than only in the refusal because somebody choosing a name wants to
    // know before they type it, not after.
    reserved: realms.reserved().sort(),
    realms: realms.list().map(function (realm) { return realmJson(req, realm); }),
    support: realms.realmSupport()
  };
  log.debug("Leaving realmsJson(). " + out.realms.length + " realm(s).");
  return out;
}

// HOW a family is separated, in the words the row itself carries. This used to
// print the literal "by path" for every `full` row, which was true of all of
// them until the embedded directory became per realm: LDAP is separated by DN —
// a subtree per realm inside one naming context — and a table that called that
// "by path" would be describing the one family whose separation is NOT a path
// segment as though it were.
function separatedBy(by) {
  const how = String(by || 'path');
  return 'by ' + (how === 'dn' ? 'DN' : how);
}

function realmSupportTable() {
  const rows = realms.realmSupport().map(function (row) {
    const state = row.state === 'full'
      ? '<span class="m">' + esc(separatedBy(row.by)) + '</span>'
      : (row.state === 'partial'
          ? '<span class="eff" title="Realm-aware, but not wholly">' + esc(row.by) + '</span>'
          : '<span class="none">shared</span>');
    return '<tr><td>' + esc(row.family) + '</td><td>' + state + '</td><td>' +
           esc(row.note) + '</td></tr>';
  }).join('');
  return '<table><tr><th>Family</th><th>Separated</th><th>What that means</th></tr>' +
         rows + '</table>';
}

function realmsListPage(req) {
  log.debug("Entering realmsListPage().");
  const json = realmsJson(req);
  const listView = listViewOf('/admin/realms', req.query);
  const paged = pagedRows(req.query, json.realms, { path: '/admin/realms' });
  const pg = paged.paging;
  const rows = paged.shown.map(function (row) {
    const href = '/admin/realms' + queryWith(listView, { realm: row.id });
    return '<tr><td><a href="' + esc(href) + '"><code>' + esc(row.id) + '</code></a>' +
      (row.builtin ? ' <span class="why">built in</span>' : '') +
      '</td><td>' + esc(row.name) + '</td>' +
      '<td><code>' + esc(row.pathPrefix || '/') + '</code></td>' +
      '<td><code>' + esc(row.kid) + '</code></td>' +
      '<td class="num">' + row.settings.length + '</td></tr>';
  }).join('');

  const carryBack = '<input type="hidden" name="back" value="' +
    esc(queryWith(listView, {})) + '">';

  const inner =
    '<p class="sub">' + realms.count() + ' realm(s). Everything under a realm\'s ' +
    'prefix is that realm; everything under no prefix is the default one.</p>' +
    REALMS_CAVEAT +

    // `realms.active()` IS FALSE FOR TWO DIFFERENT REASONS AND THIS USED TO NAME
    // ONLY ONE OF THEM. It is `realms.size > 0 && config.value('realms.enabled')`,
    // and the banner here said "`realms.enabled` is false" whenever it came back
    // false — which on a service with the setting ON and no realm yet defined is
    // a page asserting something untrue about a setting a reader can go and look
    // at. That is the worst shape a console message can take: it sent somebody
    // to Configuration to turn on a thing that was already on.
    //
    // So the two states are told apart, and the second is not a warning at all.
    // "The flag is on and nothing has been defined" is the ORDINARY state of
    // this service — the contract `common/realms.js` states is that a service
    // with no realms defined behaves exactly as it did before realms existed —
    // so it is a note saying what to do next, not a yellow box saying something
    // is wrong.
    (realms.active()
      ? ''
      : !config.value('realms.enabled')
        ? '<div class="warn"><strong>Trust realms are switched off.</strong> ' +
          '<code>realms.enabled</code> is false, so every prefix below answers 404 ' +
          'and this whole service is the default realm. The definitions are ' +
          'untouched — that is what this setting is for: it lets a realm be ruled ' +
          'out as the cause of something without anything being deleted. Turn it ' +
          'back on from <a href="/admin/config">Configuration</a>.</div>'
        : '<p class="note"><strong>Trust realms are switched ON and none has been ' +
          'defined, which is this service\'s ordinary state rather than something ' +
          'to fix.</strong> <code>realms.enabled</code> is <code>true</code>; the ' +
          'feature does nothing until a realm exists, because the built-in ' +
          '<code>default</code> realm has an empty prefix and IS this service. ' +
          'That is a property rather than a coincidence — a service with no realm ' +
          'defined behaves exactly as it did before realms existed, which is what ' +
          'keeps every client, container and test that predates them working ' +
          'unchanged. <strong>Define one below</strong> and its prefix starts ' +
          'answering immediately: a switcher appears on every page of this ' +
          'console, and <code>GET /realms</code> starts reporting ' +
          '<code>active: true</code>.</p>') +

    '<h2>The realms</h2>' +
    '<table><tr><th>Id</th><th>Name</th><th>Path prefix</th><th>Signing key</th>' +
    '<th class="num">Settings</th></tr>' + rows + '</table>' +
    pageNav('/admin/realms', pageParamsOf(req.query), pg) +
    perPageForm('/admin/realms', 'per', req.query.per, pg.perPage, '', listView) +

    '<h2>Define a realm</h2>' +
    '<p class="note">The id becomes a path segment, so it is lower-case letters, ' +
    'digits and hyphens. It may not be <code>default</code> and it may not be the ' +
    'first segment of a path this service already serves — ' +
    (json.reserved.length ? codeList(json.reserved.slice(0, 12)) +
      (json.reserved.length > 12 ? ' and ' + (json.reserved.length - 12) + ' more' : '')
      : 'nothing is registered yet') +
    ' — whatever <code>realms.pathSegment</code> is set to, precisely so that ' +
    'clearing that setting cannot turn an existing realm into a shadow over the ' +
    'console or the authorization server.</p>' +
    '<form method="post" action="/admin/realms">' + carryBack +
    '<input type="hidden" name="action" value="create">' +
    '<div class="formrow"><label for="rid">Id</label>' +
    '<input type="text" id="rid" name="id" size="16" placeholder="acme" required>' +
    '<label for="rname">Name</label>' +
    '<input type="text" id="rname" name="name" size="22" placeholder="Acme Corporation">' +
    '<label for="rdesc">Description</label>' +
    '<input type="text" id="rdesc" name="description" size="40">' +
    '<button type="submit">Define it</button></div></form>' +

    '<h2>What is separated, and what is shared</h2>' +
    '<p class="lead">A realm separates what this service ISSUES and everything ' +
    'it is holding while it issues it — keys, sessions, codes, tokens, offers, ' +
    'artifacts, statistics and the audit log. It does not separate the ' +
    'embedded directory, and four families answer on sockets with no path in ' +
    'them at all. This table is the whole list, and <code>GET /realms</code> ' +
    'answers the same thing to a client that cannot read a console.</p>' +
    realmSupportTable();

  log.debug("Leaving realmsListPage().");
  return { json: json, inner: inner };
}

function realmDetailPage(req, wanted) {
  log.debug("Entering realmDetailPage(). realm=" + wanted);
  const realm = realms.get(wanted);
  if (!realm) {
    log.debug("Leaving realmDetailPage(). No such realm.");
    return { json: { error: 'no_such_realm', realm: wanted },
             inner: '<div class="err">No realm called <code>' + esc(wanted) +
                    '</code> is defined. <a href="/admin/realms">The list</a> ' +
                    'is what there is.</div>' };
  }
  const json = realmJson(req, realm);
  const listView = listViewOf('/admin/realms', req.query);
  const carryBack = '<input type="hidden" name="back" value="' +
    esc(queryWith(listView, {})) + '">';
  const inRealm = realms.currentId() === realm.id;

  const settingRows = json.settings.length
    ? json.settings.map(function (row) {
        return '<tr><td><code>' + esc(row.key) + '</code></td>' +
               '<td>' + esc(row.label) + '</td>' +
               '<td><code>' + esc(row.value) + '</code></td>' +
               '<td><form method="post" action="/admin/realms" class="inline">' +
               carryBack + '<input type="hidden" name="action" value="unset">' +
               '<input type="hidden" name="id" value="' + esc(realm.id) + '">' +
               '<input type="hidden" name="key" value="' + esc(row.key) + '">' +
               '<button type="submit" class="secondary">Unset</button>' +
               '</form></td></tr>';
      }).join('')
    : '<tr><td colspan="4" class="none">Nothing. This realm is configured ' +
      'exactly as the process is — which is a realm that differs only in its ' +
      'key, its sessions and what it has issued.</td></tr>';

  const endpointRows = Object.keys(json.endpoints).map(function (name) {
    return '<tr><td>' + esc(name) + '</td><td class="who"><a href="' +
           esc(json.endpoints[name]) + '"><code>' + esc(json.endpoints[name]) +
           '</code></a></td></tr>';
  }).join('');

  const inner =
    '<p class="sub">' + esc(realm.name) +
    (realm.builtin ? ' — the built-in realm' : '') + '</p>' +
    (realm.description ? '<p class="lead">' + esc(realm.description) + '</p>' : '') +

    (inRealm
      ? '<div class="ok">You are reading this console <strong>inside</strong> ' +
        'this realm. <a href="/admin/config">Configuration</a> writes here.</div>'
      : '<div class="warn">You are reading this console in the <strong>' +
        esc(realms.current().name) + '</strong> realm. The switcher on the left ' +
        'moves to this one; until then <a href="/admin/config">Configuration</a> ' +
        'writes to the realm you are in, not to this one.</div>') +

    '<h2>Where it answers</h2>' +
    '<p class="note">Path prefix <code>' + esc(json.pathPrefix || '(none — this is ' +
    'the default realm)') + '</code>. Every HTTP endpoint this service has is ' +
    'under it, unchanged: what is <code>/oauth2/token</code> in the default realm ' +
    'is <code>' + esc(json.pathPrefix) + '/oauth2/token</code> here.</p>' +
    '<table><tr><th>Document</th><th>URL</th></tr>' + endpointRows + '</table>' +
    '<p class="note">The signing key is <code>' + esc(json.kid) + '</code>, ' +
    'generated for this realm and held only in memory. A token minted here does ' +
    'not verify against any other realm\'s JWKS, which is what makes two realms ' +
    'two authorization servers rather than one served twice.</p>' +

    '<h2>What this realm sets</h2>' +
    '<p class="note">Every setting in <a href="/admin/config">this service\'s ' +
    'table</a> can be set per realm, above whatever the process as a whole is ' +
    'configured with and below nothing. The two exceptions are ' +
    '<code>realms.enabled</code> and <code>realms.pathSegment</code>: a realm ' +
    'that could switch realms off, or move the prefix it was found under, would ' +
    'be doing it half way through the request that found it.</p>' +
    '<table><tr><th>Key</th><th>Setting</th><th>Value</th><th></th></tr>' +
    settingRows + '</table>' +
    '<form method="post" action="/admin/realms">' + carryBack +
    '<input type="hidden" name="action" value="set">' +
    '<input type="hidden" name="id" value="' + esc(realm.id) + '">' +
    '<div class="formrow"><label for="skey">Key</label>' +
    '<input type="text" id="skey" name="key" size="30" placeholder="saml2.entityId" required>' +
    '<label for="sval">Value</label>' +
    '<input type="text" id="sval" name="value" size="30">' +
    '<button type="submit">Set it here</button></div></form>' +

    '<h2>Name and description</h2>' +
    '<form method="post" action="/admin/realms">' + carryBack +
    '<input type="hidden" name="action" value="update">' +
    '<input type="hidden" name="id" value="' + esc(realm.id) + '">' +
    '<div class="formrow"><label for="uname">Name</label>' +
    '<input type="text" id="uname" name="name" size="22" value="' + esc(realm.name) + '">' +
    '<label for="udesc">Description</label>' +
    '<input type="text" id="udesc" name="description" size="46" value="' +
    esc(realm.description) + '">' +
    '<button type="submit">Save</button></div></form>' +

    (realm.builtin
      ? '<h2>It cannot be removed</h2>' +
        '<p class="note">Every URL this service published before trust realms ' +
        'existed is a URL in this realm, so removing it would remove the ' +
        'service. There is deliberately no button.</p>'
      : '<h2>Remove it</h2>' +
        '<p class="note"><strong>Everything it holds goes with it</strong> — its ' +
        'sessions, its authorization codes, its tokens, its offers, its service ' +
        'providers, its statistics, its audit log and its signing key. That is ' +
        'deliberate rather than thorough: a realm re-created with the same id ' +
        'inheriting the last one\'s sessions would be the single most surprising ' +
        'thing a re-created realm could do. Nothing is removed from the shared ' +
        'directory, because nothing there belongs to a realm.</p>' +
        '<form method="post" action="/admin/realms">' + carryBack +
        '<input type="hidden" name="action" value="remove">' +
        '<input type="hidden" name="id" value="' + esc(realm.id) + '">' +
        '<button type="submit" class="danger">Remove ' + esc(realm.id) + '</button></form>');

  log.debug("Leaving realmDetailPage().");
  return { json: json, inner: inner };
}

// The four writes. One function, the way every other page here has one, so that
// the console form and POST /admin-api/realms cannot come to disagree about what
// "remove" means.
function realmsAction(body) {
  log.debug("Entering realmsAction(). action=" + (body && body.action));
  const action = String((body && body.action) || '').trim();
  const id = String((body && body.id) || '').trim();

  if (action === 'create') {
    // `overrides` IS PASSED THROUGH, and until 2026-08-25 it was not. The
    // management API documents the field, gives it an example
    // (`{"saml2.entityId": "urn:acme:idp"}`) and says it wins over the six
    // seeded names — and this function built its argument out of three
    // properties and dropped the fourth, so a create carrying overrides
    // answered 200 and made a realm configured differently from the one that
    // was asked for. Nothing could have shown it: `realms.create()` validates
    // and merges overrides properly, the console's own form has no such field,
    // and a silently ignored parameter has no failure to point at.
    //
    // It is `undefined` rather than `{}` when nobody sent one, because
    // `create()` distinguishes them: an empty object is still merged over the
    // seeded names — harmlessly, but the intent is "the caller sent nothing".
    const result = realms.create({ id: id.toLowerCase(), name: body.name,
                                   description: body.description,
                                   overrides: body.overrides });
    if (!result.ok) {
      log.debug("Leaving realmsAction(). create refused.");
      return result;
    }
    log.debug("Leaving realmsAction(). create ok, " +
              Object.keys(result.realm.overrides).length + " setting(s).");
    return { ok: true, realm: result.realm.id,
             message: 'The realm "' + result.realm.id + '" is defined. Every ' +
                      'HTTP endpoint this service has now answers under ' +
                      realms.prefixOf(result.realm) + '/ as well, with its own ' +
                      'signing key and nothing issued yet.' };
  }

  if (action === 'update') {
    const result = realms.update(id, { name: body.name, description: body.description });
    if (!result.ok) {
      log.debug("Leaving realmsAction(). update refused.");
      return result;
    }
    log.debug("Leaving realmsAction(). update ok.");
    return { ok: true, realm: id, message: 'Saved.' };
  }

  if (action === 'set') {
    const key = String(body.key || '').trim();
    const result = realms.setOverride(id, key, body.value);
    if (!result.ok) {
      log.debug("Leaving realmsAction(). set refused.");
      return result;
    }
    log.debug("Leaving realmsAction(). set ok.");
    return { ok: true, realm: id, key: key,
             message: key + ' is set on the "' + id + '" realm. It applies to ' +
                      'the next request that arrives under that realm\'s prefix, ' +
                      'and to nothing else.' };
  }

  if (action === 'unset') {
    const key = String(body.key || '').trim();
    const result = realms.clearOverride(id, key);
    if (!result.ok) {
      log.debug("Leaving realmsAction(). unset refused.");
      return result;
    }
    log.debug("Leaving realmsAction(). unset ok.");
    return { ok: true, realm: id, key: key,
             message: key + ' is no longer set on the "' + id + '" realm; it ' +
                      'comes from whatever this service as a whole is ' +
                      'configured with.' };
  }

  if (action === 'remove') {
    // ------------------------------------------------------------------
    // A REALM MAY NOT REMOVE ITSELF, and this is the one refusal here that is
    // about the request rather than about the realm.
    //
    // The response to this POST is a 303 back to /admin/realms — a path that
    // app.js is about to rewrite into the realm that is being deleted, because
    // that is the realm the request arrived in. The reader would be redirected
    // into a prefix that had stopped existing one instruction earlier and would
    // meet `Cannot GET`. Everything else about the removal would have worked,
    // which is what makes it worth refusing rather than fixing: the fix is to
    // do it from another realm, and that is a sentence rather than a special
    // case in the redirect.
    // ------------------------------------------------------------------
    if (id && id === realms.currentId()) {
      log.debug("Leaving realmsAction(). A realm may not remove itself.");
      return { ok: false, errors: ['This request arrived inside the "' + id +
        '" realm, so removing it would leave the caller on a path that no ' +
        'longer exists — the console would be redirected into a prefix that ' +
        'had stopped existing one instruction earlier. Do it from another ' +
        'realm: the switcher at the top of the console sidebar, or the same ' +
        'call under a different prefix.'] };
    }
    const result = realms.remove(id);
    if (!result.ok) {
      log.debug("Leaving realmsAction(). remove refused.");
      return result;
    }
    log.debug("Leaving realmsAction(). remove ok.");
    return { ok: true, realm: id,
             message: 'The realm "' + id + '" is gone, with its sessions, its ' +
                      'tokens, its statistics, its audit log and its signing ' +
                      'key. Nothing was removed from the shared directory.' };
  }

  log.debug("Leaving realmsAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The five are: ' +
    'create, update, set, unset, remove.'] };
}

function realmsView(req) {
  log.debug("Entering realmsView().");
  const wanted = String(req.query.realm || '').trim();
  if (wanted) {
    const detail = realmDetailPage(req, wanted);
    log.debug("Leaving realmsView(). The drill-down.");
    return { json: detail.json, inner: detail.inner,
             title: 'Trust realm ' + wanted,
             up: upTo('/admin/realms', wanted, listViewOf('/admin/realms', req.query)) };
  }
  const list = realmsListPage(req);
  log.debug("Leaving realmsView(). The list.");
  return { json: list.json, inner: list.inner, title: 'Trust realms' };
}

// ---------------------------------------------------------------------------
// WHERE THE REALM CHOOSER SUBMITS.
//
// A `<select>` cannot navigate on its own without script, and this console runs
// none (`script-src 'none'`, see common/app.js) — so the chooser is a GET form
// and this is what it submits to. It exists only to turn a realm id and a path
// into one redirect.
//
// **THE TARGET IS BUILT HERE AND NOT ECHOED.** `to` arrives in a query string
// and ends up in a `Location` header, which is the shape of every open-redirect
// there has ever been. So it is accepted only as a single-slash-rooted path —
// `//host` and `https://host` and anything else is refused rather than
// corrected — and the realm is looked up in the registry rather than trusted,
// with `/admin` as the answer to both refusals. What goes out is
// root + the chosen realm's prefix + a path this service has vouched for.
//
// **THE REDIRECT IS ABSOLUTE, for the reason the form's action is.** app.js
// wraps `res.location()` so that a root-relative target gains the CURRENT
// realm's prefix — which is right for the six modules that send a browser to
// the sign-in screen and exactly wrong here, where the whole point is to land
// in a DIFFERENT realm. An absolute URL names a host, so that wrapper passes it
// through.
//
// 303 rather than 302 so the reload after it is a GET, like every other action
// on this console.
// ---------------------------------------------------------------------------
app.get('/admin/realm-switch', function (req, res) {
  log.debug("Entering the admin realm switch endpoint.");
  const wanted = String(req.query.realm || '').trim();
  const target = realms.get(wanted);
  const asked = String(req.query.to || '');
  // A path this service is willing to put in a Location header: rooted, one
  // slash, no scheme, and short enough not to be a place to hide one.
  const path = (/^\/(?!\/)[^\s]*$/.test(asked) && asked.length <= 2000) ?
    asked : '/admin';
  if (!target) {
    log.debug("Leaving the admin realm switch endpoint. No such realm " +
      JSON.stringify(wanted) + ".");
    res.set('Cache-Control', 'no-store')
       .redirect(303, realmRoot(req) + realms.currentPrefix() + path);
    return;
  }
  const to = realmRoot(req) + realms.prefixOf(target) + path;
  log.debug("Leaving the admin realm switch endpoint. To " + to + ".");
  res.set('Cache-Control', 'no-store').redirect(303, to);
});

app.get('/admin/realms', function (req, res) {
  log.debug("Entering the admin trust realms page.");
  const view = realmsView(req);
  respond(req, res, view.json, view.title, '/admin/realms', view.inner, view.up);
  log.debug("Leaving the admin trust realms page.");
});

app.post('/admin/realms', function (req, res) {
  log.debug("Entering the admin trust realms action endpoint.");
  const body = parseBody(req);
  const result = realmsAction(body);
  const listView = listViewFromBack('/admin/realms', body.back);
  const id = String(body.id || '').trim();
  // Back to the realm that was acted on, EXCEPT after a removal — there is
  // nothing to drill into any more, and a 303 to a drill-down for a realm that
  // has just gone would answer with this page's own "no such realm" message,
  // which reads as a failure after an action that succeeded.
  const back = (id && result.ok !== false && String(body.action) !== 'remove')
    ? '/admin/realms' + queryWith(listView, { realm: id })
    : '/admin/realms' + queryWith(listView, {});
  respondToAction(req, res, back, result);
  log.debug("Leaving the admin trust realms action endpoint.");
});

// ---------------------------------------------------------------------------
// /admin/config — every setting this service has, in one page.
//
// The sections are the PROTOCOLS, in the order config.js's table declares them,
// because that is where a reader looks: somebody who wants the Kerberos realm
// looks under Kerberos, not under an alphabetical list of forty-five keys. The
// grouping is not decided here — `config.groups()` is the same call the
// management API makes, so the page and the API cannot come to describe
// different sets of settings.
//
// EVERY ROW SAYS WHERE ITS VALUE CAME FROM. That is the question this page
// exists to answer and it is the one that used to require a grep: a value can
// arrive from a runtime override, from an environment variable (its own or the
// legacy STS_ISSUER), from the appconfig file this process was started with, or
// from env/defaults.js under it — and the four are indistinguishable once they
// have been read.
//
// THERE IS NO FIFTH, since 2026-08-24: a setting with a value in none of them
// stops this service from starting rather than quietly taking a constant out of
// a module. So a value shown here is a value somebody can find in a file, which
// is what makes the Source column worth reading at all.
//
// A restart-only row is SHOWN and its input is DISABLED, with the reason beside
// it. Both halves matter. Hiding it would answer "what is this service
// configured with?" with three quarters of the answer; letting it be typed into
// would accept a change that does nothing, which reads as having worked.
//
// No script here, like every other page in this console: each section is a
// plain form that posts the whole section at once (`set-many`), and each row
// has a Reset button of its own. See the shell's note above — `script-src
// 'none'` is what makes reflected content moot for this service, and the
// explorer at /admin-api/docs is the single exception.
// ---------------------------------------------------------------------------

// The five sources, as a phrase a reader can act on. `env-legacy` is its own
// case rather than being folded into `env`, because the variable it names is
// not the one the rest of the row talks about — being told the value comes from
// "the environment" while STS_SAML_ISSUER is unset is the kind of true answer
// that costs twenty minutes.
//
// `defaults` is a case for exactly the same reason. The appconfig layer is TWO
// files unioned — env/defaults.js, and whatever CONFIG_FILE names over it — and
// telling somebody a value comes from "the appconfig file" when their file does
// not mention it would send them to edit a line that is not there. So the two
// halves of that layer are named separately and each names its own file.
//
// The last line is now unreachable for anything but a `derived` setting:
// config.js refuses to start when a non-derived setting has no value in either
// file and no environment variable. It stays because the three derived ones DO
// resolve through their `dflt`, which is a function of a neighbour rather than a
// literal anybody could have written in a file.
function sourceNote(setting) {
  if (setting.source === 'override') {
    return 'set here, in memory only';
  }
  if (setting.source === 'env') {
    return 'from ' + setting.env;
  }
  if (setting.source === 'env-legacy') {
    return 'from ' + setting.legacyEnv + ' (the legacy variable)';
  }
  if (setting.source === 'appconfig') {
    return 'from ' + (process.env.CONFIG_FILE || 'the appconfig file');
  }
  if (setting.source === 'defaults') {
    return 'from ' + config.DEFAULTS_FILE + ' (the default appconfig file)';
  }
  return 'derived from another setting';
}

function configRow(setting) {
  const id = 'cfg-' + setting.key.replace(/\./g, '-');
  const input = setting.type === 'enum'
    ? '<select name="' + esc(setting.key) + '" id="' + esc(id) + '"' +
      (setting.editable ? '' : ' disabled') + '>' +
      setting.enumValues.map(function (option) {
        return '<option value="' + esc(option) + '"' +
          (option === setting.text ? ' selected' : '') + '>' + esc(option) + '</option>';
      }).join('') + '</select>'
    : (setting.type === 'bool'
      ? '<select name="' + esc(setting.key) + '" id="' + esc(id) + '"' +
        (setting.editable ? '' : ' disabled') + '>' +
        ['true', 'false'].map(function (option) {
          return '<option value="' + option + '"' +
            (option === setting.text ? ' selected' : '') + '>' + option + '</option>';
        }).join('') + '</select>'
      : '<input type="text" name="' + esc(setting.key) + '" id="' + esc(id) + '"' +
        ' size="34" value="' + esc(setting.text) + '"' +
        (setting.editable ? '' : ' disabled') + '>');

  // The Reset button is its own form. It has to be: it is a different action
  // from the section's Save, and a second submit button inside one form would
  // post every field in the section with it.
  const reset = setting.overridden
    ? '<form method="post" action="/admin/config" class="inline">' +
      '<input type="hidden" name="action" value="reset">' +
      '<input type="hidden" name="key" value="' + esc(setting.key) + '">' +
      '<button class="secondary">Reset</button></form>'
    : '';

  const provenance = setting.overridden
    ? '<strong>' + esc(sourceNote(setting)) + '</strong>'
    : esc(sourceNote(setting));

  const note = setting.editable
    ? ''
    : '<div class="note"><strong>Restart to apply:</strong> ' +
      esc(setting.restartReason) + '.</div>';

  return '<tr>' +
    '<td><label for="' + esc(id) + '"><code>' + esc(setting.key) + '</code></label>' +
    '<div class="note">' + esc(setting.label) + '. ' + esc(setting.description) + '</div>' +
    note + '</td>' +
    '<td>' + input + '</td>' +
    '<td>' + provenance + '</td>' +
    '<td>' + reset + '</td></tr>';
}

function configSection(group) {
  log.debug("Entering configSection(). group=" + group.group);
  const rows = group.settings.map(configRow).join('');
  const anyEditable = group.settings.some(function (setting) { return setting.editable; });
  const save = anyEditable
    ? '<p><button>Save ' + esc(group.group) + '</button> ' +
      '<span class="note">Applies to the next token, assertion, ticket or ' +
      'search — nothing already issued changes.</span></p>'
    : '<p class="note">Every setting in this section is read at startup, so ' +
      'there is nothing here to save. Change them in ' +
      esc(process.env.CONFIG_FILE || 'the appconfig file') + ' or in the ' +
      'environment and restart.</p>';
  log.debug("Leaving configSection(). " + group.settings.length + " setting(s).");
  return '<h3>' + esc(group.group) + '</h3>' +
    '<form method="post" action="/admin/config">' +
    '<input type="hidden" name="action" value="set-many">' +
    '<table><tr><th>Setting</th><th>Value</th><th>Source</th><th></th></tr>' +
    rows + '</table>' + save + '</form>';
}

// The action switch. `set` and `reset` name one setting; `set-many` is what a
// section's Save posts, and it is not a convenience — a section is how a person
// changes configuration, and turning that into one call per field would make a
// partly-applied section the ordinary outcome of a mistake in any one of them.
// So set-many is ALL-OR-NOTHING: every field is checked before any is written.
function configAction(body) {
  log.debug("Entering configAction(). action=" + (body && body.action));
  const action = String((body && body.action) || '').trim();

  if (action === 'set') {
    const key = String(body.key || '').trim();
    const result = config.setOverride(key, body.value);
    if (!result.ok) {
      log.debug("Leaving configAction(). set refused.");
      return result;
    }
    log.debug("Leaving configAction(). set ok.");
    return { ok: true, key: key, setting: config.describe(configSettingFor(key)),
             message: key + ' is now "' + config.text(key) + '". It applies to ' +
                      'the next token, assertion, ticket or search, and is gone ' +
                      'on restart.' };
  }

  if (action === 'set-many') {
    // Only the keys this service knows and that were actually posted. A form
    // posts its disabled inputs not at all, so a section holding restart-only
    // rows submits the editable ones and nothing else — which is why an absent
    // key is silently skipped rather than treated as an attempt to clear it.
    const wanted = Object.keys(body).filter(function (name) {
      return name !== 'action' && configKnows(name);
    });
    if (!wanted.length) {
      log.debug("Leaving configAction(). set-many named nothing.");
      return { ok: false, errors: ['No settings were posted. Every name must be ' +
        'one of the keys GET /admin/config?format=json lists.'] };
    }
    // Checked first, every one of them, and only then written. A section that
    // applied its first three fields and refused the fourth would leave the
    // service in a state nobody asked for and the page showing it.
    const errors = [];
    wanted.forEach(function (key) {
      const problem = config.checkOverride(key, body[key]);
      if (problem) errors.push(problem);
    });
    if (errors.length) {
      log.debug("Leaving configAction(). set-many refused: " + errors.length + " problem(s).");
      return { ok: false, errors: errors };
    }
    const changed = [];
    wanted.forEach(function (key) {
      const before = config.text(key);
      config.setOverride(key, body[key]);
      if (config.text(key) !== before) changed.push(key);
    });
    log.debug("Leaving configAction(). set-many ok, " + changed.length + " changed.");
    return { ok: true, applied: wanted, changed: changed,
             settings: wanted.map(function (key) {
               return config.describe(configSettingFor(key));
             }),
             message: changed.length
               ? changed.length + ' setting(s) changed: ' + changed.join(', ') +
                 '. Gone on restart.'
               : 'Nothing changed — every value posted was the one already in force.' };
  }

  if (action === 'reset') {
    const key = String(body.key || '').trim();
    const result = config.clearOverride(key);
    if (!result.ok) {
      log.debug("Leaving configAction(). reset refused.");
      return result;
    }
    log.debug("Leaving configAction(). reset ok.");
    return { ok: true, key: key, setting: config.describe(configSettingFor(key)),
             message: key + ' is back to its ' + config.sourceOf(key) + ' value, "' +
                      config.text(key) + '".' };
  }

  if (action === 'reset-all') {
    const result = config.clearAllOverrides();
    log.debug("Leaving configAction(). reset-all ok.");
    return { ok: true, cleared: result.cleared,
             message: result.cleared.length
               ? result.cleared.length + ' runtime override(s) cleared: ' +
                 result.cleared.join(', ') + '.'
               : 'There were no runtime overrides to clear.' };
  }

  log.debug("Leaving configAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The four are: ' +
    'set, set-many, reset, reset-all.'] };
}

// Whether this service has a setting of that name. Asked before `describe()`,
// which throws on an unknown key by design — the throw is right for a caller
// that has a key it believes in, and wrong for a form body whose field names
// arrived from outside.
function configKnows(key) {
  return config.SETTINGS.some(function (setting) { return setting.key === key; });
}

function configSettingFor(key) {
  return config.SETTINGS.filter(function (setting) {
    return setting.key === key;
  })[0];
}

function configJson() {
  log.debug("Entering configJson().");
  const json = config.snapshot();
  log.debug("Leaving configJson(). " + json.settingCount + " setting(s).");
  return json;
}

app.post('/admin/config', function (req, res) {
  log.debug("Entering the admin configuration action endpoint.");
  const body = parseBody(req);
  const result = configAction(body);
  respondToAction(req, res, '/admin/config', result);
  log.debug("Leaving the admin configuration action endpoint.");
});

// ---------------------------------------------------------------------------
// /admin/token-lifetimes — HOW LONG WHAT THIS SERVICE ISSUES IS GOOD FOR.
//
// Four settings, all of them `config.js` rows, on a page of their own under
// Protocols › OAuth2 / OIDC. They were three module-level `const`s in
// `../oauth-oidc/oauth2.js` until 2026-08-24 and could not be changed at all
// without a restart.
//
// WHY THIS IS A PAGE AND NOT JUST FOUR MORE ROWS ON /admin/config, which is the
// question `/admin/scim`'s header answers the other way — it has no form
// precisely because everything about SCIM that can be changed is a config row
// and "a second form here would be a second door to one setting". The rule that
// header is applying is the ONE-STORE rule, and it is untouched here: there is
// no store. This page holds nothing, decides nothing, and writes through
// `config.setOverride()` — the same function `/admin/config`'s Save and
// `POST /admin-api/config/set` call, against the same override map. What would
// break the rule is a second PLACE THE VALUE LIVES, and there is none. What is
// different from SCIM's case is what the reader is doing:
//
//   * These four are a QUANTITY somebody sets to a specific number to watch
//     something happen, over and over, in a session — "make it a minute so I
//     can see my client refresh". `/admin/config`'s form is a table of
//     forty-nine settings with a text box each; finding four of them in it,
//     every time, is the cost this page removes.
//   * They INTERACT, and a page can say so where a flat table cannot. An access
//     token that outlives the refresh token is a grant that can never be
//     renewed; a clock skew larger than the lifetime is a token that is never
//     expired. Both are legal here — this service refuses nothing it can
//     merely explain — and both are worth being told about before the client
//     author debugs their own code for an hour.
//   * The answer to "why is my client being refused" is usually "the token
//     expired", and the numbers that decide it are worth having beside the
//     count of what already has.
//
// The test for a THIRD page like this one is the same as rule 3e's for a hook:
// it earns its place when the reader's task is not the one /admin/config
// serves, and it costs a reader nothing only while it writes through the same
// function. A page that started keeping its own copy of a value would be the
// thing both rules exist to prevent.
//
// NOTHING ALREADY ISSUED CHANGES, and the page says so twice. A lifetime is
// stamped into a token as `exp` when it is signed, so a change here reaches the
// NEXT token. That is a fact about signed statements, not a limitation, and
// somebody who did not expect it will read the tokens table below and conclude
// the setting did not take.
// ---------------------------------------------------------------------------

// The four keys, in the order the page draws them: the three lifetimes, then
// the allowance applied when reading one back. Written once, and every part of
// this page and its two API operations is derived from it, so a fifth setting
// is one entry here.
const TOKEN_LIFETIME_KEYS = ['oauth2.accessTokenTtlS', 'oauth2.idTokenTtlS',
                             'oauth2.refreshTokenTtlS', 'oauth2.clockSkewS'];

// Which token kind each lifetime governs, so the page can put the count of what
// is already out there beside the number that decided it. `oauth2.clockSkewS`
// governs no kind — it is applied when a token of any kind is read back — and
// is deliberately absent rather than mapped to something plausible.
const TOKEN_LIFETIME_KINDS = {
  'oauth2.accessTokenTtlS': 'access_token',
  'oauth2.idTokenTtlS': 'id_token',
  'oauth2.refreshTokenTtlS': 'refresh_token'
};

// Seconds as a person reads them. Deliberately approximate above an hour and
// exact below one: the interesting settings on this page are the short ones,
// and "90 minutes" is the answer somebody wants for 5400 while "1.04 days" is
// nobody's answer for 90000. The exact number is always beside it in its own
// column, so this is a gloss rather than the value.
function humanSeconds(seconds) {
  const n = Number(seconds) || 0;
  if (n === 0) return 'no allowance at all';
  if (n < 60) return n + ' second' + (n === 1 ? '' : 's');
  if (n < 3600) {
    const minutes = n / 60;
    return (Number.isInteger(minutes) ? minutes : minutes.toFixed(1)) +
           ' minute' + (minutes === 1 ? '' : 's');
  }
  if (n < 86400) {
    const hours = n / 3600;
    return (Number.isInteger(hours) ? hours : hours.toFixed(1)) +
           ' hour' + (hours === 1 ? '' : 's');
  }
  const days = n / 86400;
  return (Number.isInteger(days) ? days : days.toFixed(1)) + ' day' + (days === 1 ? '' : 's');
}

// One row of the form. A `number` input rather than the text box /admin/config
// draws, with `min`, `max` and `step` off the setting itself — the bounds are
// declared in config.js's table and are rendered here rather than repeated, so
// the browser's own refusal and the server's are the same three numbers. The
// server still checks: an input attribute is a convenience for a person and no
// constraint at all on a JSON body or a curl.
function tokenLifetimeRow(setting, snapshot) {
  const id = 'tl-' + setting.key.replace(/\./g, '-');
  const kind = TOKEN_LIFETIME_KINDS[setting.key];
  const counts = kind
    ? (snapshot.tokens.byKind.filter(function (row) { return row.kind === kind; })[0] || null)
    : null;
  const issued = counts
    ? '<span class="state-valid">' + counts.valid + ' valid</span>, ' +
      '<span class="state-expired">' + counts.expired + ' expired</span>, ' +
      '<span class="state-revoked">' + counts.revoked + ' revoked</span>'
    : '<span class="state-none">—</span>';
  return '<tr>' +
    '<td><label for="' + esc(id) + '">' + esc(setting.label) + '</label>' +
    '<div class="note"><code>' + esc(setting.key) + '</code>' +
    (setting.env ? ', <code>' + esc(setting.env) + '</code>' : '') + '</div></td>' +
    '<td><input type="number" name="' + esc(setting.key) + '" id="' + esc(id) + '"' +
      ' value="' + esc(setting.text) + '"' +
      (typeof setting.min === 'number' ? ' min="' + setting.min + '"' : '') +
      (typeof setting.max === 'number' ? ' max="' + setting.max + '"' : '') +
      (typeof setting.step === 'number' ? ' step="' + setting.step + '"' : '') +
      ' size="10"></td>' +
    '<td>' + esc(humanSeconds(setting.value)) + '</td>' +
    '<td>' + esc(String(typeof setting.min === 'number' ? setting.min : 0)) + '&ndash;' +
      esc(String(typeof setting.max === 'number' ? setting.max : '')) +
      (typeof setting.step === 'number'
        ? ', in ' + esc(String(setting.step)) + 's'
        : '') + '</td>' +
    '<td>' + (setting.overridden
      ? '<strong>' + esc(sourceNote(setting)) + '</strong>'
      : esc(sourceNote(setting))) + '</td>' +
    '<td>' + issued + '</td></tr>';
}

// The two ways these four can be set to something legal and surprising. Neither
// is refused — this service exists to be pointed at a client and made to
// misbehave on purpose, and both of these are reachable states a real
// deployment can get into — but a page that showed the numbers and not the
// consequence would leave the consequence to be discovered from a client that
// stopped working.
function tokenLifetimeWarnings() {
  const access = config.value('oauth2.accessTokenTtlS');
  const refresh = config.value('oauth2.refreshTokenTtlS');
  const skew = config.value('oauth2.clockSkewS');
  const notes = [];
  if (access >= refresh) {
    notes.push('<strong>The access token lives at least as long as the refresh token</strong> (' +
      esc(humanSeconds(access)) + ' against ' + esc(humanSeconds(refresh)) + '). That is legal ' +
      'and it is issued exactly as configured, but the grant can never usefully be renewed: by ' +
      'the time a client needs a new access token, the credential it would renew with has ' +
      'expired too. It is a good way to watch a client discover that it has no way back.');
  }
  if (skew >= access) {
    notes.push('<strong>The clock skew is at least as long as the access token’s own ' +
      'lifetime</strong> (' + esc(humanSeconds(skew)) + ' against ' + esc(humanSeconds(access)) +
      '). Every endpoint that reads one back will accept it for its whole life and then for as ' +
      'long again, so an expired access token is never refused anywhere here — including at ' +
      'introspection, which will keep reporting it active. Lower the skew, or raise the ' +
      'lifetime, unless that is the thing being tested.');
  }
  if (!notes.length) return '';
  return notes.map(function (note) { return '<div class="warn">' + note + '</div>'; }).join('');
}

// The action switch. Two actions, and both write through config.js.
//
// `set` is ALL-OR-NOTHING for the reason configAction()'s set-many is: this
// form posts four fields at once, and applying two of them before refusing the
// third would leave the service issuing tokens with a lifetime combination
// nobody asked for and the page showing it as though it had been chosen.
//
// `defaults` clears the runtime override on these four ONLY. It is not
// config.js's reset-all, which would also drop an unrelated override somebody
// set on another page — that is the sort of button that is used once and
// regretted, and "reset all" already exists on /admin/config for whoever wants
// it.
function tokenLifetimesAction(body) {
  log.debug("Entering tokenLifetimesAction(). action=" + (body && body.action));
  const action = String((body && body.action) || '').trim();

  if (action === 'set') {
    // Only the four this page owns, and only the ones actually posted. A JSON
    // caller that sends one of them is setting one of them; a form sends all
    // four. A field named here that is NOT one of the four is refused by name
    // rather than ignored, because this action's whole surface is four keys and
    // a caller that misspelt one deserves to be told rather than to watch
    // nothing happen.
    const posted = Object.keys(body || {}).filter(function (name) { return name !== 'action'; });
    const unknown = posted.filter(function (name) {
      return TOKEN_LIFETIME_KEYS.indexOf(name) < 0;
    });
    if (unknown.length) {
      log.debug("Leaving tokenLifetimesAction(). Unknown field(s): " + unknown.join(', '));
      return { ok: false, errors: ['This action sets only ' + TOKEN_LIFETIME_KEYS.join(', ') +
        '. It was also given: ' + unknown.join(', ') + '. Every other setting is on ' +
        '/admin/config and POST /admin-api/config/set.'] };
    }
    const wanted = posted.filter(function (name) { return TOKEN_LIFETIME_KEYS.indexOf(name) >= 0; });
    if (!wanted.length) {
      log.debug("Leaving tokenLifetimesAction(). Nothing was posted.");
      return { ok: false, errors: ['No lifetime was posted. Name at least one of ' +
        TOKEN_LIFETIME_KEYS.join(', ') + '.'] };
    }
    const errors = [];
    wanted.forEach(function (key) {
      const problem = config.checkOverride(key, body[key]);
      if (problem) errors.push(problem);
    });
    if (errors.length) {
      log.debug("Leaving tokenLifetimesAction(). Refused: " + errors.length + " problem(s).");
      return { ok: false, errors: errors };
    }
    const changed = [];
    wanted.forEach(function (key) {
      const before = config.text(key);
      config.setOverride(key, body[key]);
      if (config.text(key) !== before) changed.push(key);
    });
    log.debug("Leaving tokenLifetimesAction(). " + changed.length + " changed.");
    return { ok: true, applied: wanted, changed: changed,
             settings: wanted.map(function (key) {
               return config.describe(configSettingFor(key));
             }),
             message: (changed.length
               ? changed.length + ' setting(s) changed: ' + changed.map(function (key) {
                   return key + ' = ' + config.text(key) + 's';
                 }).join(', ') + '.'
               : 'Nothing changed — every value posted was the one already in force.') +
               ' It applies to the NEXT token signed; nothing already issued is affected, ' +
               'because a lifetime is stamped into a token as its exp claim. Gone on restart.' };
  }

  if (action === 'defaults') {
    // clearOverride() refuses a key that was never overridden, which is the
    // right answer for a caller naming one key and the wrong one for a button
    // meaning "put these four back". So the refusals are counted rather than
    // returned: a page where three of the four were overridden must not fail
    // because the fourth was already where it belonged.
    const cleared = [];
    TOKEN_LIFETIME_KEYS.forEach(function (key) {
      if (config.clearOverride(key).ok) cleared.push(key);
    });
    log.debug("Leaving tokenLifetimesAction(). Cleared " + cleared.length + ".");
    return { ok: true, cleared: cleared,
             settings: TOKEN_LIFETIME_KEYS.map(function (key) {
               return config.describe(configSettingFor(key));
             }),
             message: cleared.length
               ? cleared.length + ' override(s) cleared: ' + cleared.join(', ') + '. Each is ' +
                 'back to its environment or appconfig value.'
               : 'None of the four was overridden here, so nothing changed — they are ' +
                 'already coming from the environment or from one of the two appconfig ' +
                 'files.' };
  }

  log.debug("Leaving tokenLifetimesAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The two are: set, defaults.'] };
}

// The JSON view, answered by GET /admin/token-lifetimes?format=json and by
// GET /admin-api/token-lifetimes. Built here rather than in the route so the
// page and the API cannot come to describe different settings — the rule
// usersView() and groupsView() follow for the same reason.
function tokenLifetimesJson() {
  log.debug("Entering tokenLifetimesJson().");
  const snapshot = stats.snapshot();
  const settings = TOKEN_LIFETIME_KEYS.map(function (key) {
    return config.describe(configSettingFor(key));
  });
  const json = {
    // The effective seconds, flat, for a caller that wants the number and not
    // the provenance. The `settings` array beside it is the whole row —
    // bounds, source, default, description — which is what a console or an
    // explorer needs and what a test asserting "it is 3600" does not.
    lifetimes: {
      accessTokenTtlS: config.value('oauth2.accessTokenTtlS'),
      idTokenTtlS: config.value('oauth2.idTokenTtlS'),
      refreshTokenTtlS: config.value('oauth2.refreshTokenTtlS'),
      clockSkewS: config.value('oauth2.clockSkewS')
    },
    settings: settings,
    // What is already out there, per kind, against the same clock the endpoints
    // use — stats.tokenStateOf() applies oauth2.clockSkewS, so a token this
    // says is expired is one /oauth2/introspect will call inactive.
    tokens: {
      held: snapshot.tokens.held, forgotten: snapshot.tokens.forgotten,
      cap: snapshot.tokens.cap, revoked: snapshot.tokens.revoked,
      byKind: snapshot.tokens.byKind
    },
    now: snapshot.now
  };
  log.debug("Leaving tokenLifetimesJson(). " + settings.length + " setting(s).");
  return json;
}

app.get('/admin/token-lifetimes', function (req, res) {
  log.debug("Entering the admin token lifetimes page.");
  const json = tokenLifetimesJson();
  const settings = json.settings;
  const snapshot = { tokens: json.tokens };
  const anyOverridden = settings.some(function (setting) { return setting.overridden; });

  const inner = messagesOf(req) +
    '<p class="note">How long an access token, an ID Token and a refresh token issued here are ' +
    'good for, and how far out a clock may be before this service stops believing one of its ' +
    'own. All four are <a href="/admin/config">configuration settings</a> and this page is a ' +
    'shorter way to the same four rows — it writes through the same function, so a change ' +
    'made here and one made there are one change.</p>' +

    '<div class="warn"><strong>A change applies to the NEXT token and to nothing already ' +
    'issued.</strong> A lifetime is stamped into a token as its <code>exp</code> claim when it ' +
    'is signed, so a token in a client’s hands cannot be shortened or extended afterwards ' +
    'by anything on this page. That is a property of a signed statement rather than a ' +
    'limitation here — to take an issued token out of circulation, revoke it on ' +
    '<a href="/admin/tokens">the tokens page</a>. Changes are in memory and are gone on ' +
    'restart; to make one stick, put it in <code>' +
    esc(process.env.CONFIG_FILE || 'env/local.js') + '</code>.</div>' +

    tokenLifetimeWarnings() +

    '<h2>The four settings</h2>' +
    '<p class="note">Every lifetime is a whole number of <strong>thirty-second</strong> units. ' +
    'That is not a formatting rule: these exist to be set short and watched, and below half a ' +
    'minute a token expires between the response being written and the client reading it, which ' +
    'is an hour spent debugging the wrong half. The clock skew is capped at <strong>300 ' +
    'seconds</strong> — five minutes is the allowance Kerberos uses here ' +
    '(<code>krb5.clockSkew</code>), and a window wider than that has stopped being a tolerance ' +
    'and become a lifetime extension nobody asked for.</p>' +
    '<form method="post" action="/admin/token-lifetimes">' +
    '<input type="hidden" name="action" value="set">' +
    '<table><tr><th>Setting</th><th>Seconds</th><th>Which is</th><th>Allowed</th>' +
    '<th>Source</th><th>Tokens of that kind held here</th></tr>' +
    settings.map(function (setting) { return tokenLifetimeRow(setting, snapshot); }).join('') +
    '</table>' +
    '<p><button>Save lifetimes</button> ' +
    '<span class="note">All four are checked before any is applied — a form that took two ' +
    'and refused the third would leave this service issuing a combination nobody chose.</span>' +
    '</p></form>' +

    (anyOverridden
      ? '<div class="ok">' +
        esc(String(settings.filter(function (s) { return s.overridden; }).length)) +
        ' of the four are set here, in memory only. ' +
        '<form method="post" action="/admin/token-lifetimes" class="inline">' +
        '<input type="hidden" name="action" value="defaults">' +
        '<button class="secondary">Put these four back</button></form>' +
        ' It clears the override on these four only, and leaves any other setting alone — ' +
        '<a href="/admin/config">Configuration</a> has the reset-all.</div>'
      : '<p class="note">None of the four is overridden: each is coming from its environment ' +
        'variable, from <code>' + esc(process.env.CONFIG_FILE || 'the appconfig file') +
        '</code>, or from <code>' + esc(config.DEFAULTS_FILE) + '</code> under it. ' +
        'The <em>Source</em> column says which.</p>') +

    '<h2>The clock skew is not a lifetime, and it is not the assertion skew either</h2>' +
    '<p class="note"><code>oauth2.clockSkewS</code> is the allowance applied to <code>exp</code> ' +
    'and <code>nbf</code> at every place this service reads back a token it signed: ' +
    '<code>/oauth2/introspect</code>, UserInfo, the refresh grant, token exchange, the ' +
    'DPoP-bound access token check the four protected endpoints share, and the state column on ' +
    'every console screen that reports one. It never changes what goes INTO a token. ' +
    'It is deliberately a different setting from <code>oauth2.clientAssertionSkewS</code>, ' +
    'which is how far out a <em>client’s</em> assertion may be under RFC 7523 ' +
    '(<code>private_key_jwt</code> and <code>client_secret_jwt</code>): one is about somebody ' +
    'else’s clock and one is about this service’s, and a deployment wanting a strict ' +
    'check on one and a forgiving reading of the other has to be able to say so.</p>' +

    '<h2>What is already out there</h2>' +
    '<p class="note">Counted against the same clock the endpoints use — the skew above is ' +
    'applied here too, so a token this table calls expired is one ' +
    '<code>/oauth2/introspect</code> will report inactive. ' +
    esc(String(json.tokens.held)) + ' token(s) are held, of the most recent ' +
    esc(String(json.tokens.cap)) + '; ' + esc(String(json.tokens.forgotten)) +
    ' older one(s) have been forgotten. Every one of them, with its own expiry, is on ' +
    '<a href="/admin/tokens">the tokens page</a>.</p>' +
    '<table><tr><th>Kind</th><th class="num">Issued</th><th class="num">Valid</th>' +
    '<th class="num">Expired</th><th class="num">Revoked</th><th class="num">Not yet valid</th>' +
    '<th class="num">No expiry stated</th></tr>' +
    (json.tokens.byKind.map(function (row) {
      return '<tr><td><code>' + esc(row.kind) + '</code></td>' +
        '<td class="num">' + row.issued + '</td>' +
        '<td class="num state-valid">' + row.valid + '</td>' +
        '<td class="num state-expired">' + row.expired + '</td>' +
        '<td class="num state-revoked">' + row.revoked + '</td>' +
        '<td class="num state-expired">' + row.notYetValid + '</td>' +
        '<td class="num state-none">' + row.noExpiry + '</td></tr>';
    }).join('') || '<tr><td colspan="7">Nothing has been issued yet.</td></tr>') +
    '</table>' +

    '<h2>Two lifetimes this page does not set</h2>' +
    '<p class="note">An <strong>authorization code</strong> is good for five minutes and is not ' +
    'configurable: it is redeemed within seconds of being issued or it is a bug in the client, ' +
    'and a code that could be made long-lived would be an invitation to build one that is. ' +
    'RFC 9700 mode’s <strong>refresh idle timeout</strong> ' +
    '(<code>oauth2.refreshIdleSeconds</code>, on <a href="/admin/config">Configuration</a>) is a ' +
    'different question from the refresh lifetime above: it is measured from the last time any ' +
    'token in a refresh CHAIN was redeemed rather than from issuance, so a busy client keeps its ' +
    'grant indefinitely and a quiet one is cut off. The lifetime here is a wall the chain cannot ' +
    'be refreshed past however busy it is.</p>' +

    '<p class="note">The same four over JSON are at ' +
    '<code>/admin/token-lifetimes?format=json</code> and ' +
    '<code>GET /admin-api/token-lifetimes</code>; the two actions on this page are ' +
    '<code>POST /admin-api/token-lifetimes/set</code> and <code>/defaults</code>. They are also ' +
    'four ordinary rows of <code>GET /admin-api/config</code>.</p>';

  respond(req, res, json, 'Token lifetimes', '/admin/token-lifetimes', inner);
  log.debug("Leaving the admin token lifetimes page.");
});

app.post('/admin/token-lifetimes', function (req, res) {
  log.debug("Entering the admin token lifetimes action endpoint.");
  const body = parseBody(req);
  const result = tokenLifetimesAction(body);
  respondToAction(req, res, '/admin/token-lifetimes', result);
  log.debug("Leaving the admin token lifetimes action endpoint.");
});


// ---------------------------------------------------------------------------
// /admin/scim — WHAT THE PROVISIONING SURFACE HAS DONE.
//
// The one page here that reports a protocol family rather than an artifact this
// service issued, and it reports two different kinds of thing on purpose:
//
//   * the COUNTERS, from admin_stats.js. Which SCIM operation was performed how
//     many times, on which resource type, and what was refused with which
//     `scimType`. Every row of both vocabularies is drawn INCLUDING the zeroes,
//     because "does this server do PATCH" is the question somebody comes here
//     with and a table that only listed what had happened would answer it by
//     omission.
//   * the SURFACE, from scim.js through the reader slot — the endpoints, what it
//     deliberately does not do, and the things you can make fail. Written once,
//     in the module that implements them, and rendered here. See setScimReader().
//
// **IT HAS NO CONTROLS, AND THAT IS WHY IT NEEDS ONLY A GET ON /admin-api.**
// Everything about SCIM that can be changed is a `config.js` row —
// `scim.enabled`, the three limits, and the thirteen authentication settings
// (which scheme is offered, the two scope names, the realm, the shared Digest
// password, the two lifetimes) — so /admin/config already has the form
// and POST /admin-api/config/set already has the operation. A second form here
// would be a second door to one setting, which is the mistake rule 5 exists for
// and the same argument group_claims.js makes about `groups.claim`.
//
// **THE BULK COUNT DOES NOT TALLY WITH THE REST, ON PURPOSE.** One
// POST /scim/v2/Bulk carrying five creates is one `bulk` row AND five `create`
// rows, because each operation inside really is performed. Said on the page,
// because a reader adding the column up will otherwise conclude the counting is
// broken.
// ---------------------------------------------------------------------------
function scimJson(req) {
  log.debug("Entering scimJson().");
  const counters = stats.scimSnapshot();
  const surface = scimReader ? scimReader(req) : null;
  const out = {
    // Distinguished from `enabled` deliberately: a process whose scim.js never
    // loaded is a different thing from one where scim.enabled is false, and a
    // page that reported both as "off" would send somebody to the wrong setting.
    installed: !!surface,
    enabled: surface ? surface.enabled : false,
    baseUrl: surface ? surface.baseUrl : null,
    specifications: surface ? surface.specifications : ['RFC 7642', 'RFC 7643', 'RFC 7644'],
    store: surface ? surface.store : null,
    identifiers: surface ? surface.identifiers : null,
    // The six schemes, whether each is on, and the access control policy —
    // from scim_auth.js's table by way of scim.js's description(). Null when
    // SCIM is not loaded, which is a different thing from every scheme being
    // off and is why it is not defaulted to an empty list.
    authentication: surface ? surface.authentication : null,
    endpoints: surface ? surface.endpoints : [],
    doesNotDo: surface ? surface.doesNotDo : [],
    reachableNegatives: surface ? surface.reachableNegatives : [],
    mapping: { user: scimMap.USER_ATTRIBUTES.map(scimMappingRow),
               group: scimMap.GROUP_ATTRIBUTES.map(scimMappingRow) },
    counters: counters
  };
  log.debug("Leaving scimJson(). " + counters.total + " request(s) counted.");
  return out;
}

// ---------------------------------------------------------------------------
// THE AUTHENTICATION SECTION OF /admin/scim.
//
// Two tables and a list, and the division between them is the one this page
// already draws everywhere else: the SCHEMES come from scim.js's description()
// — which is scim_auth.js's table, the same one that builds the
// WWW-Authenticate challenge and the ServiceProviderConfig — while the COUNTS
// come from admin_stats.js. So a scheme that is offered cannot be missing from
// this page and a count cannot be attributed to a scheme that does not exist.
//
// Every scheme is drawn INCLUDING the ones at zero and the ones turned off,
// for the reason the operations table below draws its zeroes: "can I use Digest
// against this server" is the question somebody arrives with, and a table that
// listed only what had been used would answer it by omission.
//
// There are no CONTROLS here, which is what keeps rule 7 satisfied with only a
// GET on /admin-api/scim: every one of these is a config.js row, so
// /admin/config already has the form and POST /admin-api/config/set already has
// the operation. A second form here would be a second door to one setting.
// ---------------------------------------------------------------------------
function authenticationSection(auth, counters) {
  log.debug("Entering authenticationSection().");
  const counts = (counters && counters.byAuthScheme) || {};
  const rows = auth.schemes.map(function (row) {
    return '<tr><td>' + esc(row.name) +
      (row.primary ? ' <span class="sub">(primary)</span>' : '') +
      '<div class="sub">' + esc(row.description) + '</div></td>' +
      '<td><code>' + esc(row.type) + '</code>' +
      (row.canonical ? '' : '<div class="sub">no canonical value in RFC 7643 ' +
        'section 5 — published beside the four that have one</div>') + '</td>' +
      '<td>' + (row.enabled
        ? '<span class="state-valid">offered</span>'
        : '<span class="state-none">off</span>') +
      '<div class="sub"><code>' + esc(row.setting) + '</code></div></td>' +
      '<td>' + (row.scoped ? 'what its scopes say' : 'everything') + '</td>' +
      '<td class="num">' + (counts[row.id] || 0) + '</td></tr>';
  }).join('');
  const extra = ['anonymous', 'refused'].map(function (name) {
    return '<tr><td>' + esc(name === 'anonymous'
      ? 'Nothing (an open discovery call, or authentication turned off)'
      : 'Refused before any handler ran') + '</td><td></td><td></td><td></td>' +
      '<td class="num">' + (counts[name] || 0) + '</td></tr>';
  }).join('');
  const policy = auth.policy.map(function (text) {
    return '<li>' + esc(text) + '</li>';
  }).join('');
  const out = '<h2>Authentication</h2>' +
    '<p class="note">RFC 7644 section 2 defines no credential of its own — it ' +
    'delegates to TLS and RFC 7235 and NAMES six schemes, and all six are ' +
    'here. Its one SHALL is that the schemes be indicated in ' +
    '<code>WWW-Authenticate</code>, which every 401 from these endpoints ' +
    'carries; its one MUST is that an authenticated client be mappable to an ' +
    'access control policy, which is the list below. Realm <code>' +
    esc(auth.realm) + '</code>. Discovery is ' +
    (auth.discoveryOpen
      ? 'OPEN, because a client has to be able to read which schemes exist ' +
        'before it can use one'
      : 'closed as well (<code>scim.authDiscovery</code>)') + '. Every switch ' +
    'here is on <a href="/admin/config">Configuration</a>.</p>' +
    '<table><tr><th>Scheme</th><th>type</th><th>State</th><th>May do</th>' +
    '<th class="num">Requests</th></tr>' + rows + extra + '</table>' +
    '<p class="note">The two OAuth scopes are <code>' + esc(auth.scopes.read) +
    '</code> and <code>' + esc(auth.scopes.write) + '</code> — the first scope ' +
    'requirement anywhere in this service — and they are published in ' +
    '<code>scopes_supported</code> in both discovery documents. Digest offers ' +
    esc(auth.digestAlgorithms.join(', ')) + '; HOBA keys are registered at ' +
    '<code>' + esc(auth.hobaRegistration) + '</code> and land on the person\'s ' +
    'own directory entry, so <a href="/admin/users">Users</a> shows them.</p>' +
    '<h3>The access control policy</h3><ul class="note">' + policy + '</ul>';
  log.debug("Leaving authenticationSection(). " + auth.schemes.length + " scheme(s).");
  return out;
}

// One row of the mapping, as the page and the API both want it. The `note` is
// carried through because several of them are the whole reason the row is not
// obvious — `groups` being read-only, `active` deactivating nobody, `manager`
// being passed through rather than resolved.
function scimMappingRow(row) {
  return { scim: row.scim, ldap: row.ldap, kind: row.kind,
           readOnly: !!row.readOnly, required: !!row.required,
           extension: !!row.extension, schema: row.schema || '',
           note: row.note || '' };
}

app.get('/admin/scim', function (req, res) {
  log.debug("Entering the admin SCIM page.");
  const json = scimJson(req);
  const counters = json.counters;

  const tiles = tile(counters.total, 'SCIM requests') +
    tile(counters.ok, 'answered') +
    tile(counters.failed, 'refused') +
    tile(json.store ? json.store.userCount : '—', 'people in the directory') +
    tile(json.store ? json.store.groupCount : '—', 'groups') +
    tile(json.store ? json.store.entryCount + ' / ' + json.store.maxEntries : '—', 'entries / max');

  const operationRows = counters.operations.map(function (row) {
    return '<tr><td><code>' + esc(row.method) + '</code> ' + esc(row.label) + '</td>' +
      '<td class="num">' + row.count + '</td>' +
      '<td class="sub">' + esc(row.what) + '</td></tr>';
  }).join('');

  const typeRows = counters.resourceTypes.map(function (row) {
    return '<tr><td><code>' + esc(row.resourceType) + '</code></td>' +
      '<td class="num">' + row.count + '</td></tr>';
  }).join('');

  const statusRows = Object.keys(counters.byStatus).sort().map(function (code) {
    return '<tr><td><code>' + esc(code) + '</code></td><td class="num">' +
      counters.byStatus[code] + '</td></tr>';
  }).join('') || '<tr><td colspan="2">Nothing has been answered yet.</td></tr>';

  const scimTypeRows = Object.keys(counters.byScimType).sort().map(function (name) {
    return '<tr><td><code>' + esc(name) + '</code></td><td class="num">' +
      counters.byScimType[name] + '</td></tr>';
  }).join('') || '<tr><td colspan="2">Nothing has been refused yet, which on a ' +
                 'server this permissive usually means nothing has tried the ' +
                 'error paths.</td></tr>';

  const endpointRows = json.endpoints.map(function (row) {
    return '<tr><td><code>' + esc(row.method) + '</code></td><td><code>' +
      esc(row.path) + '</code></td><td class="sub">' + esc(row.what) + '</td></tr>';
  }).join('');

  const negativeRows = json.reachableNegatives.map(function (row) {
    return '<tr><td>' + esc(row.what) + '</td><td>' + esc(row.answer) + '</td></tr>';
  }).join('');

  function mappingTable(rows) {
    return '<table><tr><th>SCIM</th><th>LDAP attribute</th><th>How</th>' +
      '<th>Defined by</th></tr>' +
      rows.map(function (row) {
        return '<tr><td><code>' + esc(row.scim) + '</code>' +
          (row.required ? ' <span class="state-valid">required</span>' : '') +
          (row.extension ? ' <span class="sub">(enterprise extension)</span>' : '') +
          '</td>' +
          '<td><code>' + esc(row.ldap) + '</code></td>' +
          '<td>' + esc(row.kind) + (row.readOnly ? ', read-only' : '') +
          (row.note ? '<div class="sub">' + esc(row.note) + '</div>' : '') + '</td>' +
          '<td class="sub">' + esc(row.schema) + '</td></tr>';
      }).join('') + '</table>';
  }

  const inner = messagesOf(req) +
    (!json.installed
      ? '<div class="err"><strong>SCIM is not loaded in this process.</strong> ' +
        'The module registers no routes here, so there is nothing to report. ' +
        'Everything else on this console is unaffected.</div>'
      : '') +
    (json.installed && !json.enabled
      ? '<div class="warn"><strong>SCIM is turned off</strong> ' +
        '(<code>scim.enabled</code>). The routes are still registered and answer ' +
        '<code>501</code> rather than <code>404</code>, because the feature ' +
        'being off and the URL being wrong are different sentences to a client. ' +
        'Turn it back on at <a href="/admin/config">Configuration</a>.</div>'
      : '') +

    '<p class="note">SCIM 2.0 — RFC 7642, 7643 and 7644 — at <code>' +
    esc(json.baseUrl || '/scim/v2') + '</code>. It is the only protocol family ' +
    'here whose purpose is to WRITE, and what it writes is the embedded LDAP ' +
    'directory: there is no second store and no cache. A ' +
    '<code>POST /scim/v2/Users</code> and an <code>ldapadd</code> create the ' +
    'same entry, so somebody provisioned over SCIM appears on ' +
    '<a href="/admin/users">Users</a>, gains whatever attributes ' +
    '<a href="/admin/vc">Credential claims</a> selects, and lands in whatever ' +
    'group a client puts them in on <a href="/admin/groups">Groups</a>.</p>' +

    '<div class="warn"><strong>These endpoints create and delete accounts, and ' +
    'they are the one surface in this service that requires a credential' +
    (json.authentication && !json.authentication.required
      ? ' — except that <code>scim.authRequired</code> is currently OFF, so ' +
        'right now they do not'
      : '') + '.</strong> Almost nothing is checked about it: every scheme ' +
    'below is permissive, so this is a turnstile rather than a lock. What it ' +
    'buys is that a client\'s 401, 403 and challenge-response paths can be ' +
    'exercised at all. <strong>And <code>active: false</code> deactivates ' +
    'nobody</strong> — it is stored on the entry as <code>scimActive</code> ' +
    'and read by nothing here: no bind is refused, no token withheld, no ' +
    'session ended. Deprovisioning is the commonest thing a SCIM client does, ' +
    'so that one is worth reading twice.</div>' +

    tiles +

    (json.authentication ? authenticationSection(json.authentication, counters) : '') +

    '<h2>Operations</h2>' +
    '<p class="note">Every operation this server implements, including the ones ' +
    'nothing has used yet — a table listing only what has happened would answer ' +
    '&ldquo;does this support PATCH?&rdquo; by omission. <strong>The column does ' +
    'not tally</strong>, on purpose: one <code>Bulk</code> carrying five creates ' +
    'is one bulk AND five creates, because each of the five really is performed.</p>' +
    '<table><tr><th>Operation</th><th class="num">Count</th><th>What it is</th></tr>' +
    operationRows + '</table>' +

    '<h2>By resource type</h2>' +
    '<table><tr><th>Resource type</th><th class="num">Count</th></tr>' + typeRows +
    '</table>' +

    '<h2>What went back</h2>' +
    '<p class="note">The HTTP status of every answer, and the <code>scimType</code> ' +
    'of every refusal (RFC 7644 section 3.12). <code>(none)</code> is a refusal ' +
    'that carried no such code — a 404 has none — and is counted rather than ' +
    'dropped, so the two failure tables agree with each other.</p>' +
    '<div class="tiles" style="align-items:flex-start">' +
    '<div><table><tr><th>Status</th><th class="num">Count</th></tr>' + statusRows +
    '</table></div>' +
    '<div><table><tr><th>scimType</th><th class="num">Count</th></tr>' +
    scimTypeRows + '</table></div></div>' +

    (json.identifiers
      ? '<h2>The <code>id</code> is the DN</h2>' +
        '<p class="note">' + esc(json.identifiers.why) + '</p>' +
        '<p class="note">For example: <code>' + esc(json.identifiers.example) +
        '</code></p>'
      : '') +

    (endpointRows
      ? '<h2>Endpoints</h2><table><tr><th>Method</th><th>Path</th><th>What</th>' +
        '</tr>' + endpointRows + '</table>'
      : '') +

    (json.doesNotDo.length
      ? '<h2>What it deliberately does not do</h2><ul>' +
        json.doesNotDo.map(function (text) {
          return '<li>' + esc(text) + '</li>';
        }).join('') + '</ul>'
      : '') +

    (negativeRows
      ? '<h2>Things you can make fail</h2>' +
        '<p class="note">A permissive server is hard to write error handling ' +
        'against, so these are here on purpose — the same device as the reserved ' +
        'password <code>invalid</code> everywhere else in this service.</p>' +
        '<table><tr><th>Do this</th><th>Get this</th></tr>' + negativeRows +
        '</table>'
      : '') +

    '<h2>The User mapping</h2>' +
    '<p class="note">Which LDAP attribute each SCIM member is. The attribute ' +
    'spellings are the same catalogue <a href="/admin/vc">Credential claims</a> ' +
    'and <a href="/admin/claims">Custom claims</a> read, checked against it at ' +
    'startup rather than copied — four independently maintained lists of ' +
    'spellings is how one of them comes to be quietly wrong.</p>' +
    mappingTable(json.mapping.user) +

    '<h2>The Group mapping</h2>' +
    mappingTable(json.mapping.group) +

    '<p class="note">Nothing on this page is a control, because everything about ' +
    'SCIM that can be changed is a configuration row: <code>scim.enabled</code> ' +
    'and the three limits, on <a href="/admin/config">Configuration</a>. A form ' +
    'here would be a second door to one setting.</p>' +

    '<p class="note"><a href="/scim">What this is, for a person</a> &middot; ' +
    '<a href="/admin/scim?format=json">this page as JSON</a> &middot; ' +
    '<a href="/admin-api/scim">the same over the management API</a> &middot; ' +
    '<a href="/ldap">the directory it writes into</a></p>';

  respond(req, res, json, 'SCIM 2.0', '/admin/scim', inner);
  log.debug("Leaving the admin SCIM page.");
});

app.get('/admin/config', function (req, res) {
  log.debug("Entering the admin configuration page.");
  const snapshot = config.snapshot();
  const overridden = snapshot.overridden.length;

  const inner = messagesOf(req) +
    '<p class="note">Every setting this service has, grouped by the protocol it ' +
    'belongs to. A value can arrive from four places and the <em>Source</em> ' +
    'column says which: a runtime override set on this page, an environment ' +
    'variable, the appconfig file this process was started with (<code>' +
    esc(snapshot.configFile || '(none)') + '</code>), or <code>' +
    esc(snapshot.defaultsFile) + '</code> — the default appconfig file that one ' +
    'is unioned on top of. Higher beats lower, so an environment variable set ' +
    'on the container still wins over the file — which is what keeps every ' +
    'existing deployment working unchanged.</p>' +

    '<p class="note"><strong>There is no fifth place.</strong> A setting with no ' +
    'value in either appconfig file and no environment variable stops this ' +
    'service from starting, by name, rather than falling back to a constant ' +
    'buried in a module. So every value below is one somebody can find in a ' +
    'file — which is what makes the <em>Source</em> column worth reading.</p>' +

    '<div class="warn"><strong>Changes here are in memory and are gone on ' +
    'restart.</strong> Nothing writes to the appconfig file. That is the same ' +
    'arrangement as the custom claims and the credential claims next door, and ' +
    'it is deliberate: a service that edited a file checked into a repository ' +
    'would leave a test\'s forgotten change behind permanently. To make ' +
    'something stick, put it in <code>' + esc(snapshot.configFile || 'env/local.js') +
    '</code>.</div>' +

    '<div class="warn"><strong>' + esc(String(snapshot.settingCount - snapshot.editableCount)) +
    ' of these ' + esc(String(snapshot.settingCount)) + ' cannot be changed while ' +
    'this service runs</strong>, and they are shown with their inputs disabled ' +
    'and the reason beside them rather than hidden. They are the ones already ' +
    'consumed by the time the service was listening: a bound socket, the TLS ' +
    'certificate\'s names, the Kerberos principal database and its long-term ' +
    'keys, and the directory\'s base DN. Accepting a change to one of those ' +
    'would do nothing and read as having worked.</div>' +

    '<h2>' + esc(String(snapshot.settingCount)) + ' settings, ' +
    esc(String(snapshot.editableCount)) + ' of them changeable here</h2>' +

    (overridden
      ? '<div class="ok">' + esc(String(overridden)) + ' runtime override(s) in ' +
        'force: ' + codeList(snapshot.overridden) + '. ' +
        '<form method="post" action="/admin/config" class="inline">' +
        '<input type="hidden" name="action" value="reset-all">' +
        '<button class="secondary">Reset all</button></form></div>'
      : '<p class="note">No runtime overrides are in force: every value below ' +
        'is coming from the environment or from one of the two appconfig ' +
        'files.</p>') +

    snapshot.groups.map(configSection).join('') +

    '<p class="note">The same table over JSON is at <code>/admin/config?format=json</code> ' +
    'and <code>GET /admin-api/config</code>; the four actions on this page are ' +
    '<code>POST /admin-api/config/set</code>, <code>/set-many</code>, ' +
    '<code>/reset</code> and <code>/reset-all</code>.</p>';

  respond(req, res, configJson(), 'Configuration', '/admin/config', inner);
  log.debug("Leaving the admin configuration page.");
});

// ---------------------------------------------------------------------------
// /admin/spiffe, /admin/spiffe/entries, /admin/spiffe/agents — THE SPIFFE
// SECTION.
//
// Three pages rather than one, and the split is by what the reader is doing
// rather than by what the data is:
//
//   /admin/spiffe           the TRUST DOMAIN — its authorities, the bundle,
//                           the four gRPC listeners, the federated bundles.
//                           The forms here rotate an authority and set or
//                           remove a federated bundle.
//   /admin/spiffe/entries   the REGISTRATION ENTRIES: a list with a filter and
//                           paging, a drill-down per entry, and the forms that
//                           create, change and delete one.
//   /admin/spiffe/agents    the ATTESTED AGENTS: the same shape, and the forms
//                           ban, unban and delete.
//
// **The second and third are separate sections rather than drill-downs**, which
// is why each has its own NAV row and its own LIST_PARAMS whitelist. A
// drill-down's section crumb points at the list it came from, and an entries
// list hanging under /admin/spiffe would make the crumb point at a page that
// does not hold that list — the exact defect rule 7a describes.
//
// **THIS PAGE DECIDES NOTHING.** Every form posts to an action function that
// calls into `spiffe_registry.js` or `spiffe_ca.js` — the same functions the
// SPIRE Server API's `BatchCreateEntry`, `BanAgent` and
// `BatchSetFederatedBundle` call, and the same store an `ldapmodify` under
// `ou=spiffe` writes to. Three doors, one store, which is the one-store rule
// this service already applies to revocation, to the applications registry and
// to SCIM.
//
// **AND IT SAYS, ON EVERY PAGE, THAT NOTHING IS ATTESTED.** A console that
// listed registration entries beside the tokens page without saying so would
// let somebody conclude that a selector on an entry restricts who can get that
// identity. Nothing here restricts anything: any caller that reaches the
// Workload API socket is handed every identity in the trust domain.
// ---------------------------------------------------------------------------

// The warning that goes at the top of all three, written once. It is the SPIFFE
// analogue of the "a group here grants nothing" line on /admin/groups, and it
// matters more, because what comes out of these pages is a credential another
// service will believe.
// The banner every SPIFFE page carries. It is a FUNCTION rather than a constant
// now, because half of what it says depends on a setting that can be off: a
// fixed string would go on describing mutual TLS on a port that had been bound
// plain, which is the silent disagreement this repository keeps warning about.
//
// TWO PARAGRAPHS, and the split is the point — the two surfaces are
// authenticated differently because their specifications say opposite things,
// and a single sentence covering both was what made the old note wrong in one
// direction as soon as one of them changed.
function spiffePostureNote() {
  const enforced = spiffeAuth.authRequired();
  return '<div class="warn"><strong>Nothing here is attested.</strong> A real ' +
    'SPIFFE agent reads the peer credentials of its socket — pid, uid, gid, ' +
    'and from those the executable, the container, the pod — and hands a ' +
    'workload only the identities those selectors match. Node cannot read ' +
    'them at all, so this service identifies a Workload API caller by the ' +
    'transport it arrived on, the endpoint it reached and its peer address, ' +
    'and nothing else. Those DO now decide which entries answer ' +
    '(<code>spiffe.attestWorkloads</code>), and they prove nothing about who ' +
    'is calling: anybody who can reach the socket can still get an identity. ' +
    'Node attestation is taken on trust too, which is why every agent below ' +
    'carries an <code>unverified:true</code> selector.</div>' +
    '<div class="' + (enforced ? 'note' : 'warn') + '">' +
    (enforced
      ? '<strong>The SPIRE Server API is the exception.</strong> Its TCP port ' +
        'is mutual TLS: a caller presents an X509-SVID from this trust ' +
        'domain, and every method is authorized against SPIRE\'s own table — ' +
        'so an entry marked <code>admin</code> or <code>downstream</code> ' +
        'below now decides what its holder may do. Its Unix socket is the ' +
        '<code>local</code> entity and needs no credential. The Workload API ' +
        'is deliberately untouched: its specification says a client MUST NOT ' +
        'be required to authenticate.'
      : '<strong>And nobody is authenticated on the SPIRE Server API either, ' +
        'because <code>spiffe.authRequired</code> is off.</strong> That port ' +
        'is plain gRPC, any caller can create a registration entry granting ' +
        'any identity here and then collect an SVID for it, and the ' +
        '<code>admin</code> and <code>downstream</code> flags below are ' +
        'recorded and read by nothing. It is restart-only, because it decides ' +
        'how the socket is bound.') +
    ' <a href="/spiffe">GET /spiffe</a> has the whole table and the full list ' +
    'of what is and is not checked.</div>';
}

function spiffeSelectorText(selector) {
  return spiffeRegistry.selectorText(selector);
}

// ---------------------------------------------------------------------------
// THE TRUST DOMAIN PAGE.
// ---------------------------------------------------------------------------
function spiffeJson(req) {
  log.debug("Entering spiffeJson().");
  const state = spiffeCa.state();
  const bindings = spiffeListeners();
  const json = {
    enabled: state.enabled,
    ready: state.ready,
    error: state.error,
    trustDomain: state.trustDomain,
    trustDomainId: state.trustDomainId,
    serverId: state.serverId,
    bundle: {
      path: bindings.bundlePath,
      sequence: state.sequence,
      refreshHint: state.refreshHint
    },
    authorities: { x509: state.x509Authorities, jwt: state.jwtAuthorities,
                   maxRetained: spiffeCa.MAX_RETAINED_AUTHORITIES },
    listeners: { workloadApi: bindings.workload, serverApi: bindings.api },
    federated: state.federated,
    counts: { entries: spiffeRegistry.entryCount(),
              agents: spiffeRegistry.agentCount(),
              maxEntries: spiffeRegistry.maxEntries(),
              maxAgents: spiffeRegistry.maxAgents(),
              maxFederatedBundles: config.value('spiffe.maxFederatedBundles') },
    keyTypes: state.keyTypes,
    // WHO MAY CALL, from the one table `GET /spiffe` and the management API
    // read too. Built there rather than here for the reason the two discovery
    // documents are built from one object: three surfaces describing what is
    // enforced three ways is two of them eventually wrong.
    authentication: spiffeAuth.state(),
    // Which settings shape this, so that a reader who wants to change something
    // knows where to go rather than hunting /admin/config. The same courtesy
    // /admin/scim pays.
    settings: ['spiffe.enabled', 'spiffe.trustDomain', 'spiffe.x509KeyType',
               'spiffe.jwtKeyType', 'spiffe.caTtl', 'spiffe.svidTtl',
               'spiffe.jwtSvidTtl', 'spiffe.refreshHint', 'spiffe.svidSubject',
               'spiffe.autoCreateEntries', 'spiffe.requireSecurityHeader',
               'spiffe.authRequired', 'spiffe.trustLocalSocket',
               'spiffe.adminIds', 'spiffe.clockSkew',
               'spiffe.attestWorkloads', 'spiffe.acceptAssertedSelectors',
               'spiffe.maxEntries', 'spiffe.maxAgents',
               'spiffe.maxFederatedBundles', 'spiffe.bundlePath',
               'spiffe.workloadSocketEnabled', 'spiffe.workloadSocket',
               'spiffe.workloadPort', 'spiffe.serverPort',
               'spiffe.serverSocketEnabled', 'spiffe.serverSocket',
               'spiffe.grpcHost'].map(function (key) {
      return { key: key, value: config.text(key) };
    })
  };
  log.debug("Leaving spiffeJson(). ready=" + json.ready);
  return json;
}

// A listener row, and the fourth column is WHAT A CALLER HAS TO PRESENT ON IT.
// Not decoration: the four sockets have three different postures — plain,
// plain-and-trusted-as-local, and mutual TLS — and a reader who cannot see
// which is which meets the difference as a handshake failure with no message.
// The same courtesy /tls says about which port needs verification turned off.
function spiffeListenerRows(bindings, what) {
  if (!bindings.length) {
    return '<tr><td colspan="4">Nothing bound for ' + esc(what) + '. Either ' +
      'both transports are off in configuration, or the process has not ' +
      'finished starting.</td></tr>';
  }
  return bindings.map(function (binding) {
    return '<tr><td>' + esc(what) + '</td><td><code>' + esc(binding.address) +
      '</code>' + (binding.tls ? ' <span class="note">(mutual TLS)</span>' : '') +
      '</td><td>' + (binding.listening ? 'listening'
        : '<strong>did not bind</strong> &mdash; ' + esc(binding.error)) +
      '</td><td>' + esc(binding.authentication || '') + '</td></tr>';
  }).join('');
}

function spiffePage(req) {
  log.debug("Entering spiffePage().");
  const json = spiffeJson(req);
  const state = spiffeCa.state();
  const x509Rows = state.x509Authorities.map(function (authority) {
    return '<tr><td><code>' + esc(authority.id) + '</code></td><td>' +
      (authority.active ? '<strong>active</strong>' : 'retired, still published') +
      '</td><td>' + esc(authority.keyType) + '</td><td>' +
      esc(authority.notAfter) + '</td><td><code>' + esc(authority.subject) +
      '</code></td></tr>';
  }).join('');
  const jwtRows = state.jwtAuthorities.map(function (authority) {
    return '<tr><td><code>' + esc(authority.id) + '</code></td><td>' +
      (authority.active ? '<strong>active</strong>' : 'retired, still published') +
      '</td><td>' + esc(authority.keyType) + ' / ' + esc(authority.alg) +
      '</td><td>' + esc(new Date(authority.createdAt).toISOString()) +
      '</td><td>&mdash;</td></tr>';
  }).join('');
  const federatedRows = state.federated.map(function (entry) {
    return '<tr><td><code>' + esc(entry.trustDomainId) + '</code></td><td>' +
      entry.x509Keys + ' x509, ' + entry.jwtKeys + ' jwt</td><td>' +
      esc(entry.bundleEndpointProfile) + '<br><span class="note">' +
      esc(entry.bundleEndpointUrl || '(no endpoint URL recorded)') +
      '</span></td><td>' + esc(entry.sequence) + '</td><td>' +
      '<form method="post" action="/admin/spiffe" class="inline">' +
      '<input type="hidden" name="action" value="federation-remove">' +
      '<input type="hidden" name="trustDomain" value="' + esc(entry.trustDomain) + '">' +
      '<button class="danger">Remove</button></form> ' +
      '<a href="/spiffe/federated/' + encodeURIComponent(entry.trustDomain) +
      '">document</a></td></tr>';
  }).join('') || '<tr><td colspan="5">None. This trust domain federates with ' +
    'nobody.</td></tr>';

  const inner = messagesOf(req) + spiffePostureNote() +
    (json.enabled ? '' : '<div class="warn">SPIFFE is turned OFF ' +
      '(<code>spiffe.enabled</code>): the bundle endpoint answers 404 and every ' +
      'gRPC call is refused with <code>Unavailable</code>. Turn it back on from ' +
      '<a href="/admin/config">Configuration</a>; it needs no restart.</div>') +
    (json.ready ? '' : '<div class="warn">' + (json.error
      ? 'The issuing authority could not be built, so nothing here will issue ' +
        'an SVID: ' + esc(json.error)
      : 'The issuing authority is still being generated &mdash; an RSA-4096 key ' +
        'takes a few seconds. Reload.') + '</div>') +

    '<h2>The trust domain</h2>' +
    '<p>This service is the issuing authority for <code>' +
    esc(json.trustDomainId) + '</code>. Its own identity as a SPIFFE server is ' +
    '<code>' + esc(json.serverId || '(not yet)') + '</code>, and every ' +
    'registration entry hangs beneath that by default. The trust domain is ' +
    'restart-only (<code>spiffe.trustDomain</code>): every authority ' +
    'certificate names it.</p>' +
    '<p>The bundle is published at <a href="' + esc(json.bundle.path) +
    '"><code>' + esc(json.bundle.path) + '</code></a> &mdash; sequence <code>' +
    esc(json.bundle.sequence) + '</code>, refresh hint ' +
    esc(json.bundle.refreshHint) + ' seconds. The sequence changes whenever the ' +
    'bundle does and never otherwise, which is what lets a consumer tell ' +
    '&ldquo;I have the current bundle&rdquo; from &ldquo;I have a ' +
    'bundle&rdquo;.</p>' +

    '<h2>Authorities</h2>' +
    '<p>Generated per start and held in memory, exactly like the STS signing ' +
    'key and the TLS certificate &mdash; so a workload holding a bundle from ' +
    'before a restart will fail to verify every SVID minted after it. ' +
    'Rotating PREPENDS a new authority and keeps the old one published: an SVID ' +
    'minted a minute ago has to go on verifying, which is what a bundle is for. ' +
    'At most ' + esc(json.authorities.maxRetained) + ' are retained, and past ' +
    'that the oldest is dropped &mdash; anything it signed stops verifying at ' +
    'that moment.</p>' +
    '<table><tr><th>Id</th><th>State</th><th>Key</th><th>Until</th>' +
    '<th>Subject</th></tr>' + x509Rows + jwtRows + '</table>' +
    '<form method="post" action="/admin/spiffe"><div class="formrow">' +
    '<input type="hidden" name="action" value="rotate">' +
    '<label for="which">Rotate</label>' +
    '<select id="which" name="which">' +
    '<option value="x509">the X.509 authority</option>' +
    '<option value="jwt">the JWT authority</option>' +
    '<option value="both">both</option></select>' +
    '<button>Rotate</button>' +
    '<span class="note">New SVIDs are signed with the new authority ' +
    'immediately; existing ones keep verifying until they expire.</span>' +
    '</div></form>' +

    '<h2>The gRPC listeners</h2>' +
    '<p>Neither <code>/admin/sts-metadata</code> nor this page can see a ' +
    'socket, so ' +
    'this table is the only place that reports whether each one actually ' +
    'bound. All four are restart-only.</p>' +
    '<table><tr><th>Surface</th><th>Address</th><th>State</th>' +
    '<th>What a caller presents</th></tr>' +
    spiffeListenerRows(json.listeners.workloadApi, 'Workload API') +
    spiffeListenerRows(json.listeners.serverApi, 'SPIRE Server API') +
    '</table>' +

    '<h2>Who may call the SPIRE Server API</h2>' +
    '<p>' + esc(json.authentication.what || '') + '</p>' +
    '<p>A caller may be several of these at once and the check asks whether it ' +
    'is <em>any</em> of the ones a method allows, which is what SPIRE\'s own ' +
    'policy does: the <code>spire-server</code> CLI on this host is ' +
    '<code>local</code>, and an agent that also holds an entry marked ' +
    '<code>admin</code> is both.</p>' +
    '<table><tr><th>Entity</th><th>What it means</th></tr>' +
    json.authentication.entities.map(function (entity) {
      return '<tr><td><code>' + esc(entity.id) + '</code></td><td>' +
        esc(entity.what) + '</td></tr>';
    }).join('') + '</table>' +
    '<p>Administrators by configuration ' +
    '(<a href="/admin/config"><code>spiffe.adminIds</code></a>): ' +
    (json.authentication.adminIds.length
      ? json.authentication.adminIds.map(function (id) {
          return '<code>' + esc(id) + '</code>';
        }).join(', ') + '. '
      : 'none. ') +
    'The other way to make one is to mark a registration entry ' +
    '<code>admin</code> on <a href="/admin/spiffe/entries">the entries ' +
    'page</a>; SPIRE has both, and neither is cached, so either takes effect ' +
    'on the next call.</p>' +
    '<p class="note">Workload API selectors: a caller there is identified as ' +
    '<code>transport:</code>, <code>endpoint:</code> and <code>peer:</code>, ' +
    'and ' + (json.authentication.attestWorkloads
      ? 'those decide which entries answer it ' +
        '(<code>spiffe.attestWorkloads</code>).'
      : 'that decides nothing at the moment &mdash; ' +
        '<code>spiffe.attestWorkloads</code> is off, so every caller is ' +
        'answered with every entry.') +
    ' Asserted selectors (<code>' +
    esc(json.authentication.assertedSelectorHeader) + '</code>) are ' +
    (json.authentication.acceptAssertedSelectors
      ? '<strong>believed</strong>, and nothing verifies them.'
      : 'ignored (<code>spiffe.acceptAssertedSelectors</code> is off).') +
    '</p>' +
    '<h3>The per-method table</h3>' +
    '<p>Copied from SPIRE\'s own <code>policy_data.json</code> rather than ' +
    'reasoned out: a table derived from what each method &ldquo;obviously&rdquo; ' +
    'needs disagrees with SPIRE in two or three places, and the client author ' +
    'who meets the disagreement cannot tell which end is wrong. ' +
    '<code>any</code> means the method is open here and in a real server too ' +
    '&mdash; <code>AttestAgent</code> because an agent has no SVID until that ' +
    'call gives it one, <code>GetBundle</code> because a trust bundle is ' +
    'public.</p>' +
    '<table><tr><th>Method</th><th>Allowed to</th></tr>' +
    json.authentication.policy.map(function (row) {
      return '<tr><td><code>' + esc(row.method) + '</code></td><td>' +
        esc(row.allow.join(', ')) + '</td></tr>';
    }).join('') + '</table>' +

    '<h2>Federated trust domains</h2>' +
    '<p><strong>A foreign bundle is given to this service and never fetched by ' +
    'it.</strong> The federation specification has a bundle endpoint URL in the ' +
    'relationship and a real implementation polls it; this one records the URL ' +
    'and refuses to follow it, because fetching a URL somebody registered in ' +
    'order to obtain a credential-verification key is a server-side request ' +
    'forgery with a citation attached &mdash; the same refusal this service ' +
    'gives WS-Federation\'s <code>wreqptr</code> and a client\'s ' +
    '<code>jwks_uri</code>. Paste the bundle in below, or push it with ' +
    '<code>BatchSetFederatedBundle</code>.</p>' +
    '<table><tr><th>Trust domain</th><th>Keys</th><th>Profile / endpoint</th>' +
    '<th>Sequence</th><th></th></tr>' + federatedRows + '</table>' +
    '<form method="post" action="/admin/spiffe">' +
    '<div class="formrow">' +
    '<input type="hidden" name="action" value="federation-set">' +
    '<label for="fed-td">Trust domain</label>' +
    '<input id="fed-td" name="trustDomain" placeholder="other.example" size="24">' +
    '<label for="fed-url">Bundle endpoint URL</label>' +
    '<input id="fed-url" name="bundleEndpointUrl" placeholder="https://other.example/bundle" size="34">' +
    '<label for="fed-profile">Profile</label>' +
    '<select id="fed-profile" name="bundleEndpointProfile">' +
    '<option value="https_web">https_web</option>' +
    '<option value="https_spiffe">https_spiffe</option></select>' +
    '</div><div class="formrow">' +
    '<label for="fed-doc">Bundle document</label>' +
    '<textarea id="fed-doc" name="document" rows="6" cols="80" ' +
    'placeholder=\'{"keys":[{"kty":"EC","use":"x509-svid","x5c":["..."]}],"spiffe_sequence":1,"spiffe_refresh_hint":300}\'></textarea>' +
    '<button>Set</button>' +
    '<span class="note">A JWK Set. Every key needs <code>use</code> of ' +
    '<code>x509-svid</code>, <code>jwt-svid</code> or <code>wit-svid</code>: a ' +
    'consumer MUST IGNORE one without it, so a bundle of keys missing that ' +
    'member verifies nothing and reports no error, which is why it is refused ' +
    'here rather than stored.</span></div></form>' +

    '<h2>Elsewhere</h2><ul>' +
    '<li><a href="/admin/spiffe/entries">Registration entries</a> &mdash; ' +
    esc(json.counts.entries) + ' of at most ' + esc(json.counts.maxEntries) +
    '</li>' +
    '<li><a href="/admin/spiffe/agents">Attested agents</a> &mdash; ' +
    esc(json.counts.agents) + ' of at most ' + esc(json.counts.maxAgents) +
    '</li>' +
    '<li><a href="/spiffe">What this is, and what it does not check</a></li>' +
    '<li><a href="/ldap/spiffe">The containers and their schema</a></li>' +
    '<li><a href="/admin-api/spiffe">The same, over JSON</a></li>' +
    '</ul>';
  log.debug("Leaving spiffePage().");
  return { json: json, inner: inner, title: 'SPIFFE' };
}

// ---------------------------------------------------------------------------
// THE REGISTRATION ENTRIES.
// ---------------------------------------------------------------------------
function spiffeEntriesJson(req) {
  log.debug("Entering spiffeEntriesJson().");
  const q = String(req.query.q || '').trim().toLowerCase();
  const origin = String(req.query.origin || '').trim();
  const all = spiffeRegistry.allEntries();
  const rows = all.filter(function (entry) {
    if (origin && entry.origin !== origin) return false;
    if (!q) return true;
    return (entry.spiffeId + ' ' + entry.parentId + ' ' + entry.id + ' ' +
            entry.hint + ' ' +
            entry.selectors.map(spiffeSelectorText).join(' ')).toLowerCase()
      .indexOf(q) >= 0;
  });
  const pg = pagingOf(req.query, rows.length, { unit: 'entry' });
  const json = {
    total: all.length,
    matched: rows.length,
    filter: { q: q, origin: origin },
    origins: all.map(function (entry) { return entry.origin; })
      .filter(function (value, index, list) { return list.indexOf(value) === index; })
      .sort(),
    paging: { page: pg.page, pages: pg.pages, perPage: pg.perPage,
              total: pg.total },
    max: spiffeRegistry.maxEntries(),
    container: 'ou=entries,ou=spiffe',
    entries: rows.slice(pg.offset, pg.offset + pg.perPage)
  };
  log.debug("Leaving spiffeEntriesJson(). " + rows.length + " matched.");
  return { json: json, paging: pg };
}

function spiffeEntriesListPage(req) {
  log.debug("Entering spiffeEntriesListPage().");
  const view = spiffeEntriesJson(req);
  const json = view.json;
  const listView = listViewOf('/admin/spiffe/entries', req.query);
  const rows = json.entries.map(function (entry) {
    return '<tr><td><a href="/admin/spiffe/entries' +
      queryWith(listView, { entry: entry.id }) + '"><code>' +
      esc(entry.spiffeId) + '</code></a>' +
      (entry.expired ? ' <strong>(expired)</strong>' : '') +
      '<br><span class="note"><code>' + esc(entry.id) + '</code></span></td>' +
      '<td>' + esc(entry.selectors.map(spiffeSelectorText).join(', ') ||
                   '(none — matches every workload)') + '</td>' +
      '<td>' + esc(entry.origin) + '</td>' +
      '<td>' + esc(entry.hint || '—') + '</td>' +
      '<td>' + entry.svidsIssued + '</td>' +
      '<td>rev ' + entry.revisionNumber + '</td></tr>';
  }).join('') || '<tr><td colspan="6">No registration entry matches.</td></tr>';
  const originOptions = ['<option value="">every origin</option>'].concat(
    json.origins.map(function (name) {
      return '<option value="' + esc(name) + '"' +
        (json.filter.origin === name ? ' selected' : '') + '>' + esc(name) +
        '</option>';
    })).join('');
  const inner = messagesOf(req) + spiffePostureNote() +
    '<p>' + esc(json.total) + ' registration entry/entries, of at most ' +
    esc(json.max) + ' (<code>spiffe.maxEntries</code>). The store is the ' +
    'embedded directory under <code>' + esc(json.container) + '</code>: ' +
    'an <code>ldapmodify</code> there, a form here and the SPIRE Server API\'s ' +
    '<code>BatchUpdateEntry</code> are three doors onto one entry, and nothing ' +
    'caches it &mdash; so a change takes effect on the next SVID.</p>' +
    '<form method="get" action="/admin/spiffe/entries"><div class="formrow">' +
    '<label for="q">Search</label>' +
    '<input id="q" name="q" value="' + esc(json.filter.q) + '" size="28" ' +
    'placeholder="a SPIFFE ID, a selector, an entry id">' +
    '<label for="origin">Origin</label>' +
    '<select id="origin" name="origin">' + originOptions + '</select>' +
    '<label for="per">Rows</label>' +
    '<select id="per" name="per">' + perPageOptions(view.paging.perPage) +
    '</select><button class="secondary">Filter</button>' +
    '<span class="note">Origin is how the entry got here: <code>seed</code> ' +
    'at startup, <code>console</code>, <code>api</code>, <code>grpc</code>, ' +
    '<code>auto</code> (invented for a workload that matched nothing) or ' +
    '<code>ldap</code>.</span></div></form>' +
    '<table><tr><th>SPIFFE ID / entry id</th><th>Selectors</th><th>Origin</th>' +
    '<th>Hint</th><th>SVIDs</th><th>Revision</th></tr>' + rows + '</table>' +
    pageNav('/admin/spiffe/entries', filterOnly(listView), view.paging) +
    spiffeCreateEntryForm() ;
  log.debug("Leaving spiffeEntriesListPage().");
  return { json: json, inner: inner };
}

function spiffeCreateEntryForm() {
  return '<h2>Create a registration entry</h2>' +
    '<p>The SPIFFE ID must be in this trust domain and outside the reserved ' +
    '<code>/spire</code> path &mdash; those two refusals are the whole of what ' +
    'is checked. The parent defaults to this server\'s own identity, which is ' +
    'what SPIRE uses for an entry describing a workload rather than a node.</p>' +
    '<form method="post" action="/admin/spiffe/entries"><div class="formrow">' +
    '<input type="hidden" name="action" value="create">' +
    '<label for="e-id">SPIFFE ID</label>' +
    '<input id="e-id" name="spiffeId" size="40" placeholder="spiffe://' +
    esc(spiffeCa.trustDomain()) + '/ns/default/sa/web">' +
    '<label for="e-parent">Parent</label>' +
    '<input id="e-parent" name="parentId" size="34" placeholder="(this server)">' +
    '</div><div class="formrow">' +
    '<label for="e-sel">Selectors</label>' +
    '<input id="e-sel" name="selectors" size="40" ' +
    'placeholder="unix:uid:1000, k8s:ns:default">' +
    '<label for="e-dns">DNS names</label>' +
    '<input id="e-dns" name="dnsNames" size="26" placeholder="web.default.svc">' +
    '</div><div class="formrow">' +
    '<label for="e-x509ttl">X509-SVID TTL</label>' +
    '<input id="e-x509ttl" name="x509SvidTtl" size="6" placeholder="3600">' +
    '<label for="e-jwtttl">JWT-SVID TTL</label>' +
    '<input id="e-jwtttl" name="jwtSvidTtl" size="6" placeholder="300">' +
    '<label for="e-hint">Hint</label>' +
    '<input id="e-hint" name="hint" size="12" placeholder="internal">' +
    '<label for="e-fed">Federates with</label>' +
    '<input id="e-fed" name="federatesWith" size="20" placeholder="other.example">' +
    '<button>Create</button>' +
    '<span class="note">Selectors, DNS names and trust domains are ' +
    'comma-separated. A selector is <code>type:value</code>, split on the ' +
    'FIRST colon only &mdash; so <code>docker:label:app:web</code> is type ' +
    '<code>docker</code>.</span></div></form>';
}

function spiffeEntryDetailPage(req, id) {
  log.debug("Entering spiffeEntryDetailPage(). id=" + id);
  const entry = spiffeRegistry.entryById(id);
  const listView = listViewOf('/admin/spiffe/entries', req.query);
  const back = queryWith(listView, {});
  if (!entry) {
    log.debug("Leaving spiffeEntryDetailPage(). Not here.");
    return { json: { error: 'No registration entry has the id ' + id },
             inner: messagesOf(req) +
               '<p>No registration entry has the id <code>' + esc(id) +
               '</code>. It may have been deleted &mdash; from this page, ' +
               'with <code>BatchDeleteEntry</code>, or with an ' +
               '<code>ldapdelete</code> under <code>ou=entries,ou=spiffe</code>, ' +
               'which are three doors onto one store.</p>' +
               '<p><a href="/admin/spiffe/entries' + esc(back) +
               '">Back to the entries</a>.</p>' };
  }
  const attributeRows = Object.keys(entry.attributes || {}).sort()
    .map(function (name) {
      const value = entry.attributes[name];
      return '<tr><td><code>' + esc(name) + '</code></td><td>' +
        esc(Array.isArray(value) ? value.join(' | ') : String(value)) +
        '</td></tr>';
    }).join('');
  const json = { entry: entry, editable: spiffeRegistry.EDITABLE };
  const carried = '<input type="hidden" name="back" value="' + esc(back) + '">' +
                  '<input type="hidden" name="entry" value="' + esc(entry.id) + '">';
  const inner = messagesOf(req) + spiffePostureNote() +
    '<h2><code>' + esc(entry.spiffeId) + '</code></h2>' +
    '<p>Entry <code>' + esc(entry.id) + '</code>, revision ' +
    esc(entry.revisionNumber) + ', created by <code>' + esc(entry.origin) +
    '</code>. It lives at <code>' + esc(entry.dn) + '</code>' +
    (entry.expired ? ' and <strong>has expired</strong> &mdash; it is kept and ' +
      'reported rather than deleted, because an entry that vanished is ' +
      'indistinguishable from one nobody created' : '') + '.</p>' +
    '<table><tr><th>Field</th><th>Value</th></tr>' +
    '<tr><td>Parent</td><td><code>' + esc(entry.parentId) + '</code></td></tr>' +
    '<tr><td>Selectors</td><td>' +
    esc(entry.selectors.map(spiffeSelectorText).join(', ') ||
        '(none — this entry matches every workload)') + '</td></tr>' +
    '<tr><td>DNS names</td><td>' + esc(entry.dnsNames.join(', ') || '—') +
    '</td></tr>' +
    '<tr><td>Federates with</td><td>' +
    esc(entry.federatesWith.join(', ') || '—') + '</td></tr>' +
    '<tr><td>X509-SVID TTL</td><td>' +
    (entry.x509SvidTtl || ('default (' + esc(config.text('spiffe.svidTtl')) + ')')) +
    '</td></tr>' +
    '<tr><td>JWT-SVID TTL</td><td>' +
    (entry.jwtSvidTtl || ('default (' + esc(config.text('spiffe.jwtSvidTtl')) + ')')) +
    '</td></tr>' +
    '<tr><td>Hint</td><td>' + esc(entry.hint || '—') + '</td></tr>' +
    '<tr><td>admin / downstream / storeSvid</td><td>' +
    (entry.admin ? 'admin' : '') + (entry.downstream ? ' downstream' : '') +
    (entry.storeSvid ? ' storeSvid' : '') +
    ((entry.admin || entry.downstream || entry.storeSvid) ? '' : '—') +
    ' <span class="note">recorded and never read &mdash; nothing here decides ' +
    'anything on one</span></td></tr>' +
    '<tr><td>SVIDs issued</td><td>' + entry.svidsIssued +
    (entry.lastSvidAt ? ', most recently ' + esc(entry.lastSvidAt) : '') +
    '</td></tr></table>' +

    '<h3>Change it</h3>' +
    '<p>Only the DECLARED half is editable here &mdash; what the entry may DO. ' +
    'The derived half (the revision number, the SVID counter, when it was ' +
    'created) is what HAPPENED, and a form that could rewrite it would make ' +
    'this page lie about the service\'s own behaviour. <code>ldapmodify</code> ' +
    'reaches everything: refusing it here is the difference between offering ' +
    'an operation and merely not preventing it.</p>' +
    '<form method="post" action="/admin/spiffe/entries"><div class="formrow">' +
    '<input type="hidden" name="action" value="update">' + carried +
    '<label for="u-field">Field</label>' +
    '<select id="u-field" name="field">' +
    ['spiffeId', 'parentId', 'selectors', 'dnsNames', 'federatesWith',
     'x509SvidTtl', 'jwtSvidTtl', 'hint', 'expiresAt', 'admin', 'downstream',
     'storeSvid'].map(function (name) {
      return '<option value="' + esc(name) + '">' + esc(name) + '</option>';
    }).join('') + '</select>' +
    '<label for="u-value">Value</label>' +
    '<input id="u-value" name="value" size="40">' +
    '<button>Set</button>' +
    '<span class="note">A list field takes comma-separated values and an ' +
    'empty value clears it. A boolean takes true or false.</span>' +
    '</div></form>' +
    '<form method="post" action="/admin/spiffe/entries"><div class="formrow">' +
    '<input type="hidden" name="action" value="delete">' + carried +
    '<button class="danger">Delete this entry</button>' +
    '<span class="note">Whatever holds an SVID minted from it keeps that SVID ' +
    'until it expires. SPIFFE has no revocation &mdash; the answer is a short ' +
    'lifetime, which is why the default is an hour.</span></div></form>' +

    '<h3>The directory entry</h3>' +
    '<p>Every attribute, operational ones included. This is the store rather ' +
    'than a description of it.</p>' +
    '<table><tr><th>Attribute</th><th>Value</th></tr>' + attributeRows +
    '</table>';
  log.debug("Leaving spiffeEntryDetailPage().");
  return { json: json, inner: inner };
}

function spiffeEntriesView(req) {
  log.debug("Entering spiffeEntriesView().");
  const wanted = String(req.query.entry || '').trim();
  if (wanted) {
    const detail = spiffeEntryDetailPage(req, wanted);
    log.debug("Leaving spiffeEntriesView(). The drill-down.");
    return { json: detail.json, inner: detail.inner,
             title: 'Registration entry ' + wanted,
             up: upTo('/admin/spiffe/entries', wanted,
                      listViewOf('/admin/spiffe/entries', req.query)) };
  }
  const list = spiffeEntriesListPage(req);
  log.debug("Leaving spiffeEntriesView(). The list.");
  return { json: list.json, inner: list.inner, title: 'Registration entries' };
}

// ---------------------------------------------------------------------------
// THE AGENTS.
// ---------------------------------------------------------------------------
function spiffeAgentsJson(req) {
  log.debug("Entering spiffeAgentsJson().");
  const q = String(req.query.q || '').trim().toLowerCase();
  const all = spiffeRegistry.allAgents();
  const rows = all.filter(function (agent) {
    if (!q) return true;
    return (agent.id + ' ' + agent.attestationType + ' ' +
            agent.selectors.map(spiffeSelectorText).join(' ')).toLowerCase()
      .indexOf(q) >= 0;
  });
  const pg = pagingOf(req.query, rows.length, { unit: 'agent' });
  const json = {
    total: all.length,
    matched: rows.length,
    filter: { q: q },
    max: spiffeRegistry.maxAgents(),
    container: 'ou=agents,ou=spiffe',
    paging: { page: pg.page, pages: pg.pages, perPage: pg.perPage,
              total: pg.total },
    agents: rows.slice(pg.offset, pg.offset + pg.perPage)
  };
  log.debug("Leaving spiffeAgentsJson(). " + rows.length + " matched.");
  return { json: json, paging: pg };
}

function spiffeAgentsListPage(req) {
  log.debug("Entering spiffeAgentsListPage().");
  const view = spiffeAgentsJson(req);
  const json = view.json;
  const listView = listViewOf('/admin/spiffe/agents', req.query);
  const rows = json.agents.map(function (agent) {
    return '<tr><td><a href="/admin/spiffe/agents' +
      queryWith(listView, { agent: agent.id }) + '"><code>' +
      esc(agent.id) + '</code></a></td>' +
      '<td>' + esc(agent.attestationType) + '</td>' +
      '<td>' + (agent.banned ? '<strong>banned</strong>' : 'active') + '</td>' +
      '<td>' + agent.attestations + '</td>' +
      '<td>' + esc(agent.lastSeen || '—') + '</td></tr>';
  }).join('') || '<tr><td colspan="5">No agent has attested here. An agent ' +
    'appears when it calls <code>AttestAgent</code> on the SPIRE Server ' +
    'API.</td></tr>';
  const inner = messagesOf(req) + spiffePostureNote() +
    '<p>' + esc(json.total) + ' agent(s), of at most ' + esc(json.max) +
    ' (<code>spiffe.maxAgents</code>). These entries are a RECORD rather than ' +
    'configuration &mdash; everything on them was written by this service when ' +
    'an agent attested &mdash; which is why nothing about an agent is editable ' +
    'and only the ban is.</p>' +
    '<div class="warn"><strong>Node attestation is never verified.</strong> ' +
    'Whatever attestor an agent names and whatever payload it sends are ' +
    'written down as claimed. That is why every agent carries a selector ' +
    'valued <code>unverified:true</code>: an agent\'s selectors here are ' +
    'claims, not attested facts.</div>' +
    '<form method="get" action="/admin/spiffe/agents"><div class="formrow">' +
    '<label for="q">Search</label>' +
    '<input id="q" name="q" value="' + esc(json.filter.q) + '" size="30" ' +
    'placeholder="an agent id, an attestor, a selector">' +
    '<label for="per">Rows</label>' +
    '<select id="per" name="per">' + perPageOptions(view.paging.perPage) +
    '</select><button class="secondary">Filter</button></div></form>' +
    '<table><tr><th>Agent</th><th>Attestor</th><th>State</th>' +
    '<th>Attestations</th><th>Last seen</th></tr>' + rows + '</table>' +
    pageNav('/admin/spiffe/agents', filterOnly(listView), view.paging);
  log.debug("Leaving spiffeAgentsListPage().");
  return { json: json, inner: inner };
}

function spiffeAgentDetailPage(req, id) {
  log.debug("Entering spiffeAgentDetailPage(). id=" + id);
  const agent = spiffeRegistry.agentById(id);
  const listView = listViewOf('/admin/spiffe/agents', req.query);
  const back = queryWith(listView, {});
  if (!agent) {
    log.debug("Leaving spiffeAgentDetailPage(). Not here.");
    return { json: { error: 'No agent has attested here as ' + id },
             inner: messagesOf(req) +
               '<p>No agent has attested here as <code>' + esc(id) +
               '</code>.</p><p><a href="/admin/spiffe/agents' + esc(back) +
               '">Back to the agents</a>.</p>' };
  }
  const attributeRows = Object.keys(agent.attributes || {}).sort()
    .map(function (name) {
      const value = agent.attributes[name];
      return '<tr><td><code>' + esc(name) + '</code></td><td>' +
        esc(Array.isArray(value) ? value.join(' | ') : String(value)) +
        '</td></tr>';
    }).join('');
  const carried = '<input type="hidden" name="back" value="' + esc(back) + '">' +
                  '<input type="hidden" name="agent" value="' + esc(agent.id) + '">';
  const inner = messagesOf(req) + spiffePostureNote() +
    '<h2><code>' + esc(agent.id) + '</code></h2>' +
    '<p>Attested with <code>' + esc(agent.attestationType) + '</code>, ' +
    esc(agent.attestations) + ' time(s), first at ' + esc(agent.firstSeen) +
    ' and most recently at ' + esc(agent.lastSeen) + '. It lives at <code>' +
    esc(agent.dn) + '</code> &mdash; the RDN is a digest of the SPIFFE ID, ' +
    'because a SPIFFE ID is too long for a readable one, so <strong>the cn is ' +
    'not the identity here</strong>: <code>spiffeAgentId</code> is.</p>' +
    '<table><tr><th>Field</th><th>Value</th></tr>' +
    '<tr><td>State</td><td>' + (agent.banned
      ? '<strong>banned</strong> — AttestAgent refuses it, which is one of ' +
        'the few refusals in this service and is what keeps the button below ' +
        'from being a lie'
      : 'active') + '</td></tr>' +
    '<tr><td>Its directory entry</td><td>' +
    'Every identity this trust domain issues an X509-SVID to has one under ' +
    '<code>ou=users</code>, carrying the current certificate as the same six ' +
    '<code>x509*</code> attributes a verified TLS client certificate writes. ' +
    'Banning or deleting this agent marks that entry ' +
    '<code>spiffeCredentialStatus: revoked</code> and never removes it; ' +
    'unbanning marks it active again. <span class="note">That is not a ' +
    'certificate status. SPIFFE has no revocation, nothing reads the flag ' +
    'back, and whatever SVID this agent holds keeps working until it ' +
    'expires.</span></td></tr>' +
    '<tr><td>Can reattest</td><td>' + (agent.canReattest ? 'yes' : 'no') +
    '</td></tr>' +
    '<tr><td>Selectors</td><td>' +
    esc(agent.selectors.map(spiffeSelectorText).join(', ') || '—') +
    ' <span class="note">claimed, never verified</span></td></tr>' +
    '<tr><td>SVID</td><td>' + esc(agent.svidHash || '—') +
    (agent.expiresAt ? ', expires ' +
      esc(new Date(agent.expiresAt * 1000).toISOString()) : '') +
    '</td></tr></table>' +
    '<form method="post" action="/admin/spiffe/agents"><div class="formrow">' +
    '<input type="hidden" name="action" value="' +
    (agent.banned ? 'unban' : 'ban') + '">' + carried +
    '<button class="' + (agent.banned ? 'secondary' : 'danger') + '">' +
    (agent.banned ? 'Unban' : 'Ban') + ' this agent</button>' +
    '<span class="note">A banned agent is refused at <code>AttestAgent</code> ' +
    'with <code>PermissionDenied</code>. Whatever SVID it already holds keeps ' +
    'working until it expires &mdash; there is no revocation in SPIFFE.</span>' +
    '</div></form>' +
    '<form method="post" action="/admin/spiffe/agents"><div class="formrow">' +
    '<input type="hidden" name="action" value="delete">' + carried +
    '<button class="danger">Delete this agent</button>' +
    '<span class="note">It reappears the next time it attests, because ' +
    'attestation is not checked &mdash; deleting is forgetting, not ' +
    'revoking.</span></div></form>' +
    '<h3>The directory entry</h3>' +
    '<table><tr><th>Attribute</th><th>Value</th></tr>' + attributeRows +
    '</table>';
  log.debug("Leaving spiffeAgentDetailPage().");
  return { json: { agent: agent }, inner: inner };
}

function spiffeAgentsView(req) {
  log.debug("Entering spiffeAgentsView().");
  const wanted = String(req.query.agent || '').trim();
  if (wanted) {
    const detail = spiffeAgentDetailPage(req, wanted);
    log.debug("Leaving spiffeAgentsView(). The drill-down.");
    return { json: detail.json, inner: detail.inner, title: 'Agent ' + wanted,
             up: upTo('/admin/spiffe/agents', wanted,
                      listViewOf('/admin/spiffe/agents', req.query)) };
  }
  const list = spiffeAgentsListPage(req);
  log.debug("Leaving spiffeAgentsView(). The list.");
  return { json: list.json, inner: list.inner, title: 'Attested agents' };
}

// ---------------------------------------------------------------------------
// THE ACTIONS.
//
// Three handlers, one per page, and each is what BOTH the console form and the
// management API call — with `action` taken from the URL there instead of from
// a hidden input here. That is rule 7's arrangement, and it is what makes an
// API operation most of the cost of a console control rather than a second
// implementation of it.
//
// Each returns `{ ok, errors, message }` and DECIDES NOTHING ITSELF: the work
// is in `spiffe_registry.js` and `spiffe_ca.js`, which the SPIRE Server API
// also calls.
// ---------------------------------------------------------------------------
function spiffeCommaList(value) {
  return String(value == null ? '' : value).split(',')
    .map(function (part) { return part.trim(); })
    .filter(Boolean);
}

// The known actions, as a list, so that an unknown one can be answered by
// NAMING the ones that exist. The parent project's tests/admin_api.js reads
// exactly that reply to assert console/API parity — it asks each handler for an
// action that does not exist and compares what comes back with the API's
// operations — so this list is not decoration.
const SPIFFE_ACTIONS = ['rotate', 'federation-set', 'federation-remove'];
const SPIFFE_ENTRY_ACTIONS = ['create', 'update', 'delete'];
const SPIFFE_AGENT_ACTIONS = ['ban', 'unban', 'delete'];

function spiffeUnknownAction(action, known) {
  return { ok: false, errors: ['Unknown action "' + String(action) + '". ' +
    'The actions here are: ' + known.join(', ') + '.'] };
}

async function spiffeAction(body) {
  log.debug("Entering spiffeAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  if (action === 'rotate') {
    const which = String(body.which || 'x509');
    const done = [];
    try {
      if (which === 'x509' || which === 'both') {
        const authority = await spiffeCa.rotateX509Authority();
        done.push('a new X.509 authority (' + authority.id + ')');
      }
      if (which === 'jwt' || which === 'both') {
        const authority = await spiffeCa.rotateJwtAuthority();
        done.push('a new JWT authority (kid ' + authority.id + ')');
      }
    } catch (e) {
      log.debug("Leaving spiffeAction(). Rotation failed.");
      return { ok: false, errors: ['The authority could not be rotated: ' +
                                   e.message] };
    }
    if (!done.length) {
      log.debug("Leaving spiffeAction(). Nothing named.");
      return { ok: false, errors: ['Rotate what? `which` is x509, jwt or both.'] };
    }
    auditLog.audit({ action: 'spiffe.bundle.change', actor: '', protocol: 'SPIFFE',
                  channel: 'internal', target: spiffeCa.trustDomainId(),
                  summary: 'An authority was rotated from the console',
                  detail: { which: which, sequence: spiffeCa.sequence() } });
    log.debug("Leaving spiffeAction(). Rotated.");
    return { ok: true, message: 'Rotated: ' + done.join(' and ') + '. The ' +
      'previous authority is still published in the bundle, so SVIDs already ' +
      'issued go on verifying; the bundle sequence is now ' +
      spiffeCa.sequence() + '.' };
  }

  if (action === 'federation-set') {
    const name = String(body.trustDomain || '').trim().toLowerCase();
    if (!name) {
      log.debug("Leaving spiffeAction(). No trust domain.");
      return { ok: false, errors: ['Which trust domain? Send `trustDomain` ' +
                                   'with its name — other.example, not ' +
                                   'spiffe://other.example.'] };
    }
    const result = spiffeCa.setFederatedBundle(name, body.document, {
      bundleEndpointUrl: String(body.bundleEndpointUrl || ''),
      bundleEndpointProfile: String(body.bundleEndpointProfile || 'https_web'),
      endpointSpiffeId: String(body.endpointSpiffeId || '')
    });
    if (!result.ok) {
      log.debug("Leaving spiffeAction(). Refused.");
      return { ok: false, errors: [result.reason] };
    }
    auditLog.audit({ action: 'spiffe.bundle.change', actor: '', protocol: 'SPIFFE',
                  channel: 'internal', target: name,
                  summary: 'A federated bundle for ' + name + ' was set from ' +
                           'the console',
                  detail: { created: result.created } });
    log.debug("Leaving spiffeAction(). Federated bundle set.");
    return { ok: true, message: 'The bundle for ' + name + ' was ' +
      (result.created ? 'added' : 'replaced') + '. Any registration entry that ' +
      'federates with it will now hand it to its workloads. The endpoint URL ' +
      'is recorded and will not be fetched — see the note on this page.' };
  }

  if (action === 'federation-remove') {
    const name = String(body.trustDomain || '').trim().toLowerCase();
    const removed = spiffeCa.deleteFederatedBundle(name);
    if (!removed) {
      log.debug("Leaving spiffeAction(). Not held.");
      return { ok: false, errors: ['This service holds no bundle for the ' +
                                   'trust domain ' + name + '.'] };
    }
    auditLog.audit({ action: 'spiffe.bundle.change', actor: '', protocol: 'SPIFFE',
                  channel: 'internal', target: name,
                  summary: 'A federated bundle for ' + name + ' was removed ' +
                           'from the console', detail: {} });
    log.debug("Leaving spiffeAction(). Removed.");
    return { ok: true, message: 'The bundle for ' + name + ' is gone. Any ' +
      'entry that federates with it keeps the name and simply contributes no ' +
      'bundle, which is the same state as a relationship configured before its ' +
      'bundle arrives.' };
  }

  log.debug("Leaving spiffeAction(). Unknown action.");
  return spiffeUnknownAction(action, SPIFFE_ACTIONS);
}

function spiffeEntriesAction(body) {
  log.debug("Entering spiffeEntriesAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const trustDomain = spiffeCa.trustDomain();

  if (action === 'create') {
    const result = spiffeRegistry.createEntry({
      spiffeId: String(body.spiffeId || '').trim(),
      parentId: String(body.parentId || '').trim() ||
                spiffeIdLib.serverId(trustDomain),
      selectors: spiffeCommaList(body.selectors)
        .map(spiffeRegistry.parseSelector).filter(Boolean),
      dnsNames: spiffeCommaList(body.dnsNames),
      federatesWith: spiffeCommaList(body.federatesWith),
      x509SvidTtl: parseInt(String(body.x509SvidTtl || '0'), 10) || 0,
      jwtSvidTtl: parseInt(String(body.jwtSvidTtl || '0'), 10) || 0,
      hint: String(body.hint || '').trim()
    }, 'console', trustDomain, '');
    log.debug("Leaving spiffeEntriesAction(). create " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) return result;
    return { ok: true, id: result.id, entry: result.entry,
             message: 'The entry is in the registry as ' + result.id +
                      '. The next FetchX509SVID will include an SVID ' +
                      'for ' + result.entry.spiffeId + ' — this service hands ' +
                      'every caller every identity, so the selectors do not ' +
                      'narrow that.' };
  }

  if (action === 'update') {
    const id = String(body.entry || '').trim();
    if (!id) {
      log.debug("Leaving spiffeEntriesAction(). No entry named.");
      return { ok: false, errors: ['Which entry? Send `entry` with its id.'] };
    }
    const field = String(body.field || '').trim();
    if (spiffeRegistry.EDITABLE.indexOf(fieldToAttribute(field)) < 0) {
      log.debug("Leaving spiffeEntriesAction(). Not editable.");
      return { ok: false, errors: ['"' + field + '" is not a field this page ' +
        'may change. The editable ones are what the entry may DO: ' +
        'spiffeId, parentId, selectors, dnsNames, federatesWith, ' +
        'x509SvidTtl, jwtSvidTtl, hint, expiresAt, admin, downstream, ' +
        'storeSvid. The rest is what HAPPENED, and only ldapmodify reaches it.'] };
    }
    const raw = body.value === undefined ? '' : String(body.value);
    const changes = {};
    if (field === 'selectors') {
      changes.selectors = spiffeCommaList(raw)
        .map(spiffeRegistry.parseSelector).filter(Boolean);
    } else if (field === 'dnsNames' || field === 'federatesWith') {
      changes[field] = spiffeCommaList(raw);
    } else if (field === 'x509SvidTtl' || field === 'jwtSvidTtl' ||
               field === 'expiresAt') {
      changes[field] = parseInt(raw, 10) || 0;
    } else if (field === 'admin' || field === 'downstream' ||
               field === 'storeSvid') {
      changes[field] = /^(1|true|yes|on)$/i.test(raw.trim());
    } else {
      changes[field] = raw.trim();
    }
    const result = spiffeRegistry.updateEntry(id, changes, trustDomain, '');
    log.debug("Leaving spiffeEntriesAction(). update " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) return result;
    return { ok: true, id: id, entry: result.entry,
             message: field + ' is set. The entry is now at revision ' +
                      result.entry.revisionNumber + ', and the change applies ' +
                      'to the NEXT SVID issued from it — nothing caches this ' +
                      'and nothing already issued changes.' };
  }

  if (action === 'delete') {
    const id = String(body.entry || '').trim();
    if (!id) {
      log.debug("Leaving spiffeEntriesAction(). No entry named.");
      return { ok: false, errors: ['Which entry? Send `entry` with its id.'] };
    }
    const result = spiffeRegistry.deleteEntry(id, '');
    log.debug("Leaving spiffeEntriesAction(). delete " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) return result;
    return { ok: true, id: id,
             message: 'The entry is gone. Anything holding an SVID minted from ' +
                      'it keeps that SVID until it expires — SPIFFE has no ' +
                      'revocation.' };
  }

  log.debug("Leaving spiffeEntriesAction(). Unknown action.");
  return spiffeUnknownAction(action, SPIFFE_ENTRY_ACTIONS);
}

// The console names a field the way the record does and the EDITABLE table
// names it the way the DIRECTORY does. One map, here, rather than two
// vocabularies that drift: a form offering `dnsNames` while the table says
// `spiffeDnsName` would refuse every edit the form offers.
const SPIFFE_FIELD_ATTRIBUTES = {
  spiffeId: 'spiffeId', parentId: 'spiffeParentId', selectors: 'spiffeSelector',
  dnsNames: 'spiffeDnsName', federatesWith: 'spiffeFederatesWith',
  x509SvidTtl: 'spiffeX509SvidTtl', jwtSvidTtl: 'spiffeJwtSvidTtl',
  hint: 'spiffeHint', expiresAt: 'spiffeEntryExpiresAt', admin: 'spiffeAdmin',
  downstream: 'spiffeDownstream', storeSvid: 'spiffeStoreSvid'
};

function fieldToAttribute(field) {
  return SPIFFE_FIELD_ATTRIBUTES[String(field)] || '';
}

function spiffeAgentsAction(body) {
  log.debug("Entering spiffeAgentsAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const id = String(body.agent || '').trim();
  if (SPIFFE_AGENT_ACTIONS.indexOf(action) >= 0 && !id) {
    log.debug("Leaving spiffeAgentsAction(). No agent named.");
    return { ok: false, errors: ['Which agent? Send `agent` with its SPIFFE ' +
                                 'ID, which is under /spire/agent/.'] };
  }
  if (action === 'ban' || action === 'unban') {
    const result = spiffeRegistry.setAgentBanned(id, action === 'ban', '');
    log.debug("Leaving spiffeAgentsAction(). " + action + " " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) return result;
    return { ok: true, id: id, agent: result.agent,
             message: action === 'ban'
               ? 'That agent is banned: AttestAgent now refuses it with ' +
                 'PermissionDenied. Whatever SVID it already holds keeps ' +
                 'working until it expires.'
               : 'That agent may attest again.' };
  }
  if (action === 'delete') {
    const result = spiffeRegistry.deleteAgent(id, '');
    log.debug("Leaving spiffeAgentsAction(). delete " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) return result;
    return { ok: true, id: id,
             message: 'That agent is forgotten. It reappears the moment it ' +
                      'attests again, because attestation is not checked — ' +
                      'deleting is forgetting, not revoking. Ban it instead if ' +
                      'that is what you meant.' };
  }
  log.debug("Leaving spiffeAgentsAction(). Unknown action.");
  return spiffeUnknownAction(action, SPIFFE_AGENT_ACTIONS);
}

// ---------------------------------------------------------------------------
// THE ROUTES.
// ---------------------------------------------------------------------------
app.get('/admin/spiffe', function (req, res) {
  log.debug("Entering the admin SPIFFE page.");
  const view = spiffePage(req);
  respond(req, res, view.json, view.title, '/admin/spiffe', view.inner);
  log.debug("Leaving the admin SPIFFE page.");
});

// The one action handler here that is ASYNCHRONOUS, because rotating an
// authority generates a key and key generation is async. `respondToAction`
// takes the resolved result, so the await is here rather than inside it — every
// other action in this console is synchronous and making that function async
// would change the shape of all of them for one caller.
app.post('/admin/spiffe', function (req, res) {
  log.debug("Entering the admin SPIFFE action endpoint.");
  const body = parseBody(req);
  spiffeAction(body).then(function (result) {
    respondToAction(req, res, '/admin/spiffe', result);
    log.debug("Leaving the admin SPIFFE action endpoint.");
  }).catch(function (err) {
    // A throw out of the action itself. Answered rather than left to express's
    // handler, which would replace the Content-Security-Policy header — see the
    // frame-ancestors note in CLAUDE.md.
    log.error('The SPIFFE console action threw: ' + err.message);
    respondToAction(req, res, '/admin/spiffe',
                    { ok: false, errors: [err.message] });
    log.debug("Leaving the admin SPIFFE action endpoint. It threw.");
  });
});

app.get('/admin/spiffe/entries', function (req, res) {
  log.debug("Entering the admin SPIFFE entries page.");
  const view = spiffeEntriesView(req);
  respond(req, res, view.json, view.title, '/admin/spiffe/entries', view.inner,
          view.up);
  log.debug("Leaving the admin SPIFFE entries page. " + view.title + ".");
});

app.post('/admin/spiffe/entries', function (req, res) {
  log.debug("Entering the admin SPIFFE entries action endpoint.");
  const body = parseBody(req);
  const result = spiffeEntriesAction(body);
  // Back to the drill-down the form was posted from where there was one, and
  // carrying the list state off the form's `back` field either way — so an edit
  // does not silently cost the reader their place in the list. Rule 7a: a new
  // form on this page needs `carryBack` in it, and nothing can check that it
  // has one.
  const listView = listViewFromBack('/admin/spiffe/entries', body.back);
  const target = String(body.entry || '').trim() && result.ok !== false
    ? '/admin/spiffe/entries' + queryWith(listView,
        { entry: String(body.entry).trim() })
    : '/admin/spiffe/entries' + queryWith(listView, {});
  respondToAction(req, res, target, result);
  log.debug("Leaving the admin SPIFFE entries action endpoint.");
});

app.get('/admin/spiffe/agents', function (req, res) {
  log.debug("Entering the admin SPIFFE agents page.");
  const view = spiffeAgentsView(req);
  respond(req, res, view.json, view.title, '/admin/spiffe/agents', view.inner,
          view.up);
  log.debug("Leaving the admin SPIFFE agents page. " + view.title + ".");
});

app.post('/admin/spiffe/agents', function (req, res) {
  log.debug("Entering the admin SPIFFE agents action endpoint.");
  const body = parseBody(req);
  const result = spiffeAgentsAction(body);
  const listView = listViewFromBack('/admin/spiffe/agents', body.back);
  const target = String(body.agent || '').trim() && result.ok !== false &&
                 String(body.action || '') !== 'delete'
    ? '/admin/spiffe/agents' + queryWith(listView,
        { agent: String(body.agent).trim() })
    : '/admin/spiffe/agents' + queryWith(listView, {});
  respondToAction(req, res, target, result);
  log.debug("Leaving the admin SPIFFE agents action endpoint.");
});


// ---------------------------------------------------------------------------
// GET /admin/federation, POST /admin/federation
//
// THE ONE PAGE IN THIS CONSOLE THAT CONFIGURES A REFUSAL.
//
// Every other page here either reports what happened or widens what this
// service will accept. This one is the opposite in both directions, and the
// page says so at the top rather than leaving it to be discovered: a
// relationship is created DISABLED, an assertion is refused unless it verifies
// against the certificate configured on it, and a relationship that is enabled
// but half-configured refuses rather than half-working.
//
// It reads and writes ONE store — `ou=federations`, through
// `federation/federation.js` — and holds nothing of its own, like every other
// page in this file. What it deliberately does NOT hold is anything the
// applications registry already holds: an identity-provider-side relationship
// NAMES an application and stops, so its entityID, its redirect URIs and its
// certificate stay on `/admin/applications` where every protocol module reads
// them.
// ---------------------------------------------------------------------------
const FEDERATION_CAVEAT =
  '<p class="note"><strong>This is the one feature here that has to be configured before it ' +
  'will do anything, and the one page in this console that configures a REFUSAL.</strong> ' +
  'Everywhere else this service accepts what it is given — any username, any client_id, any ' +
  'entityID, any LDAP bind. It cannot do that at an assertion consumer service: what arrives ' +
  'there is an unauthenticated HTTP request claiming to be a person, and the session it would ' +
  'produce is the same one <code>/oauth2/authorize</code>, <code>/wsfed</code>, ' +
  '<code>/saml2</code> and this console all read. A permissive version of it would not be a ' +
  'permissive mock; it would be an authentication bypass for every protocol in this ' +
  'process.</p>' +
  '<p class="note"><strong>The gate is on the SIGNER, not on the subject.</strong> Once a ' +
  'relationship is configured and enabled, everything downstream is as permissive as the rest ' +
  'of this service: any username in the assertion is accepted, any attribute is mapped, ' +
  'nothing about the person is checked, and a directory entry is created for them.</p>';

const FEDERATION_LINKS =
  '<p class="sub"><a href="' + federation.PATHS.base + '">the federation index</a> &middot; ' +
  '<a href="/admin/applications">the applications registry</a> &middot; ' +
  '<a href="/admin/users">who has signed in</a> &middot; ' +
  '<a href="/ldap/federations">the register as the directory sees it</a></p>';

// One row's summary, shared by the list and the JSON. It is a function rather
// than being built inline twice because the READINESS is computed here — the
// page prints it and the API answers it, and two computations of "is this
// partner usable" would be two answers to the question the whole page is about.
function federationRow(record) {
  const readiness = federation.readinessOf(record);
  return {
    id: record.fedId,
    name: record.fedName || record.fedId,
    role: record.fedRole,
    roleLabel: (federation.roleRow(record.fedRole) || {}).short || record.fedRole,
    protocol: record.fedProtocol,
    protocolLabel: (federation.protocolRow(record.fedProtocol) || {}).label || record.fedProtocol,
    peer: record.fedPeer || '',
    application: record.fedApplication || '',
    enabled: federation.isEnabled(record),
    ready: readiness.ready,
    missing: readiness.missing,
    usable: federation.isEnabled(record) && readiness.ready,
    releases: (record.fedRelease || []).slice(0),
    mappings: (record.fedAttributeMap || []).slice(0),
    authentications: parseInt(record.fedAuthentications, 10) || 0,
    users: parseInt(record.fedUsers, 10) || 0,
    lastUser: record.fedLastUser || '',
    lastSeen: record.fedLastSeen || '',
    lastError: record.fedLastError || '',
    lastErrorAt: record.fedLastErrorAt || '',
    dn: record.dn || ''
  };
}

// THE STATE CELL, and it is the most important thing on the page. Four states
// and each is a different instruction to the reader, which is why they are four
// sentences rather than a boolean and a tooltip.
function federationStateCell(row) {
  if (row.usable) return '<td class="ok">ready</td>';
  if (!row.enabled) {
    return '<td class="off">disabled' +
      (row.ready ? '' : ' <span class="sub">and not configured</span>') + '</td>';
  }
  return '<td class="bad">ENABLED, not configured<span class="sub">' +
    esc(row.missing.join(', ')) + ' still to set. It refuses rather than half-working.' +
    '</span></td>';
}

function federationListPage(req) {
  log.debug("Entering federationListPage().");
  const all = federation.list().map(federationRow);
  const wantedText = String(req.query.q || '').trim().toLowerCase();
  const wantedRole = String(req.query.role || '').trim();
  const filtered = all.filter(function (row) {
    if (wantedRole && row.role !== wantedRole) return false;
    if (!wantedText) return true;
    return (row.id + ' ' + row.name + ' ' + row.peer + ' ' + row.application)
      .toLowerCase().indexOf(wantedText) >= 0;
  });
  const paging = pagingOf(req.query, filtered.length, {});
  const paged = pagedRows(req.query, filtered, {});
  const nav = pageNav('/admin/federation', pageParamsOf(req.query), paging);

  const rows = paged.shown.map(function (row) {
    return '<tr><td><a href="/admin/federation' +
      esc(queryWith(listViewOf('/admin/federation', req.query), { relationship: row.id })) +
      '">' + esc(row.id) + '</a>' +
      (row.name !== row.id ? '<span class="sub">' + esc(row.name) + '</span>' : '') + '</td>' +
      '<td>' + esc(row.roleLabel) + '</td>' +
      '<td>' + esc(row.protocolLabel) + '</td>' +
      '<td class="who">' + esc(row.peer || row.application || '') +
      (!row.peer && !row.application ? '<span class="sub">nothing named yet</span>' : '') +
      '</td>' +
      federationStateCell(row) +
      '<td class="num">' + row.authentications + '</td>' +
      '<td class="num">' + row.users + '</td>' +
      '<td>' + (row.lastError
        ? '<span class="bad">' + shortened(row.lastError, 60) + '</span>'
        : '<span class="sub">none recorded</span>') + '</td></tr>';
  }).join('');

  const roleOptions = ['<option value="">any role</option>'].concat(
    federation.ROLES.map(function (one) {
      const n = all.filter(function (r) { return r.role === one.role; }).length;
      return '<option value="' + esc(one.role) + '"' +
        (one.role === wantedRole ? ' selected' : '') + '>' + esc(one.short) +
        ' (' + n + ')</option>';
    })).join('');

  const inner = messagesOf(req) +
    '<div class="tiles">' +
    tile(all.length, 'Relationships') +
    tile(all.filter(function (r) { return r.usable; }).length, 'Ready') +
    tile(all.filter(function (r) { return r.enabled && !r.ready; }).length,
         'Enabled, not configured') +
    tile(all.reduce(function (n, r) { return n + r.authentications; }, 0),
         'Federated sign-ins') +
    '</div>' +
    FEDERATION_CAVEAT +
    '<form method="get" action="/admin/federation"><div class="formrow">' +
    '<label for="q">Relationship</label>' +
    '<input type="text" id="q" name="q" value="' + esc(String(req.query.q || '')) +
    '" size="24" placeholder="id, name, partner or application">' +
    '<label for="role">Role</label><select id="role" name="role">' + roleOptions + '</select>' +
    '<label for="per">Show</label>' +
    '<select id="per" name="per">' + perPageOptions(paging.perPage) + '</select>' +
    '<button type="submit">Filter</button>' +
    ((wantedText || wantedRole) ? ' <a href="/admin/federation">clear</a>' : '') +
    '</div></form>' + nav +
    '<table><tr><th>Relationship</th><th>This service is</th><th>Protocol</th>' +
    '<th>Partner</th><th>State</th><th class="num">Sign-ins</th><th class="num">People</th>' +
    '<th>Last refusal</th></tr>' +
    (rows || '<tr><td colspan="8">No federation relationship ' +
      ((wantedText || wantedRole) ? 'matches. The filter above may be hiding some.'
        : 'is configured. Nothing federated happens until one is — and then not until it ' +
          'is enabled, which is a second, deliberate act.') + '</td></tr>') +
    '</table>' + nav +
    federationCreateForm() +
    '<h2>The two directions</h2>' +
    '<table><tr><th>This service is</th><th>What it means</th></tr>' +
    federation.ROLES.map(function (one) {
      return '<tr><td>' + esc(one.short) + '</td><td>' + esc(one.what) + '</td></tr>';
    }).join('') + '</table>' +
    '<p class="note"><strong>One relationship is one DIRECTION.</strong> A partner this ' +
    'service both consumes from and asserts to is two relationships with two ids, because ' +
    'everything that configures one differs by direction — the endpoints are theirs or ours, ' +
    'the certificate is theirs or ours, the attribute mapping runs inbound or the release ' +
    'list runs outbound.</p>' +
    '<h2>The five protocols</h2>' +
    '<table><tr><th>Protocol</th><th>What happens</th><th>Specification</th></tr>' +
    federation.PROTOCOLS.map(function (one) {
      return '<tr><td>' + esc(one.label) + '</td><td>' + esc(one.what) + '</td>' +
        '<td class="sub">' + esc(one.spec) + '</td></tr>';
    }).join('') + '</table>' +
    FEDERATION_LINKS;

  log.debug("Leaving federationListPage(). " + paged.shown.length + " row(s) of " +
            filtered.length + " matched.");
  return {
    inner: inner,
    json: {
      relationshipCount: all.length, matched: filtered.length, shown: paged.shown.length,
      ready: all.filter(function (r) { return r.usable; }).length,
      filter: { q: String(req.query.q || '') || null, role: wantedRole || null },
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      container: federation.containerDn(), max: federation.maxRelationships(),
      roles: federation.ROLES, protocols: federation.PROTOCOLS,
      paths: federation.PATHS,
      relationships: paged.shown
    }
  };
}

function federationCreateForm() {
  return '<h2>Add a relationship</h2>' +
    '<p class="note">It is created <strong>disabled</strong>, whatever is filled in here, ' +
    'and nothing about it does anything until it is enabled on its own page. That is not ' +
    'caution for its own sake: a partner that half-exists and silently accepts assertions is ' +
    'the failure this whole register is arranged to prevent, and enabling is the second, ' +
    'deliberate act that says the configuration is finished.</p>' +
    '<form method="post" action="/admin/federation"><div class="formrow">' +
    '<input type="hidden" name="action" value="create">' +
    '<label for="fedid">Id</label>' +
    '<input type="text" id="fedid" name="id" size="16" required placeholder="partner-a">' +
    '<label for="fedrole">This service is</label>' +
    '<select id="fedrole" name="role">' +
    federation.ROLES.map(function (one) {
      return '<option value="' + esc(one.role) + '">' + esc(one.short) + '</option>';
    }).join('') + '</select>' +
    '<label for="fedprotocol">Protocol</label>' +
    '<select id="fedprotocol" name="protocol">' +
    federation.PROTOCOLS.map(function (one) {
      return '<option value="' + esc(one.protocol) + '">' + esc(one.label) + '</option>';
    }).join('') + '</select>' +
    '<label for="fedname">Name</label>' +
    '<input type="text" id="fedname" name="name" size="16" placeholder="optional">' +
    '<label for="fedpeer">Partner</label>' +
    '<input type="text" id="fedpeer" name="peer" size="26" ' +
    'placeholder="their entityID, issuer or realm">' +
    '<button type="submit">Add</button>' +
    '</div></form>' +
    '<p class="note">The <strong>id</strong> is the key, the RDN and a URL segment, so it has ' +
    'to start with a letter or a digit and hold only letters, digits, dot, dash and ' +
    'underscore. <strong>Partner</strong> is their own identifier in whatever their protocol ' +
    'calls it, and on a service-provider-side relationship it is CHECKED: an assertion whose ' +
    'issuer is not that string is refused, even when the signature verifies.</p>';
}

// The drill-down. It is the page that actually does the work, because a
// relationship is configured field by field and the fields differ by role and
// by protocol — which is why the form is BUILT from the schema rather than
// typed out: `fieldsForRole()` is the same call the action validates against,
// so this page cannot offer a field the action would refuse.
function federationDetailPage(req, id) {
  log.debug("Entering federationDetailPage(). id=" + id);
  const carryBack = '<input type="hidden" name="back" value="' +
    esc(queryWith(listViewOf('/admin/federation', req.query), {})) + '">';
  const record = federation.get(id);
  if (!record) {
    log.debug("Leaving federationDetailPage(). No such relationship.");
    return {
      inner: messagesOf(req) +
        '<p class="warn">There is no federation relationship called <code>' + esc(id) +
        '</code>. Unlike almost everything else in this console, one does not appear because ' +
        'somebody used it: this register is configured and nothing creates an entry in it by ' +
        'turning up.</p>' + FEDERATION_LINKS,
      json: { found: false, id: id }
    };
  }
  const row = federationRow(record);
  const base = 'http://' + String(req.get('host') || ('localhost:' + config.value('global.port')));
  const acs = base + federation.PATHS.acs + '/' + encodeURIComponent(row.id);
  const login = federation.PATHS.login + '/' + encodeURIComponent(row.id);
  const metadata = base + federation.PATHS.metadata + '/' + encodeURIComponent(row.id);

  const setFields = federation.fieldsForRole(row.role, 'set').filter(function (field) {
    // The four booleans get their own two-button control below, because a text
    // box a person types TRUE into is a text box a person types "true", "yes"
    // and "1" into — and one of those is how a relationship stays disabled
    // while the page says it is on.
    return ['fedEnabled', 'fedAutocreateUsers', 'fedSignRequest',
            'fedAllowUnsolicited'].indexOf(field.name) === -1;
  });
  const multiFields = federation.fieldsForRole(row.role, 'multi');

  const fieldRows = setFields.map(function (field) {
    const value = record[field.name] || '';
    return '<tr><td><code>' + esc(field.name) + '</code></td>' +
      '<td><form method="post" action="/admin/federation"><div class="formrow">' + carryBack +
      '<input type="hidden" name="action" value="set">' +
      '<input type="hidden" name="id" value="' + esc(row.id) + '">' +
      '<input type="hidden" name="field" value="' + esc(field.name) + '">' +
      '<input type="text" name="value" size="42" value="' +
      esc(field.sensitive && value ? '' : value) + '"' +
      (field.sensitive ? ' placeholder="set — not shown"' : '') + '>' +
      '<button type="submit">Set</button></div></form></td>' +
      '<td class="sub">' + esc(field.what) +
      (field.sensitive
        ? ' <strong>Never printed on this page or in the audit log</strong>, though an ' +
          'ldapsearch of this directory will show it — see the note at the foot.'
        : '') + '</td></tr>';
  }).join('');

  const switches = ['fedEnabled'].concat(
    row.role === 'service-provider'
      ? ['fedAutocreateUsers', 'fedAllowUnsolicited', 'fedSignRequest']
      : []).map(function (name) {
    const field = federation.SCHEMA.attributes.filter(function (f) { return f.name === name; })[0];
    if (!field) return '';
    const dflt = name === 'fedAutocreateUsers';
    const on = federation.boolOf(record[name], dflt);
    return '<tr><td><code>' + esc(name) + '</code></td>' +
      '<td class="' + (on ? 'ok' : 'off') + '">' + (on ? 'TRUE' : 'FALSE') + '</td>' +
      '<td><form method="post" action="/admin/federation"><div class="formrow">' + carryBack +
      '<input type="hidden" name="action" value="set">' +
      '<input type="hidden" name="id" value="' + esc(row.id) + '">' +
      '<input type="hidden" name="field" value="' + esc(name) + '">' +
      '<input type="hidden" name="value" value="' + (on ? 'FALSE' : 'TRUE') + '">' +
      '<button type="submit"' + (name === 'fedEnabled' && !on && !row.ready ? ' class="danger"' : '') +
      '>' + (on ? 'Turn off' : 'Turn on') + '</button></div></form></td>' +
      '<td class="sub">' + esc(field.what) + '</td></tr>';
  }).join('');

  const multiSections = multiFields.map(function (field) {
    const values = record[field.name] || [];
    return '<h3><code>' + esc(field.name) + '</code></h3>' +
      '<p class="note">' + esc(field.what) + '</p>' +
      (values.length
        ? '<table><tr><th>Value</th><th></th></tr>' + values.map(function (value) {
            return '<tr><td class="who"><code>' + esc(value) + '</code></td>' +
              '<td><form method="post" action="/admin/federation"><div class="formrow">' +
              carryBack +
              '<input type="hidden" name="action" value="remove-value">' +
              '<input type="hidden" name="id" value="' + esc(row.id) + '">' +
              '<input type="hidden" name="field" value="' + esc(field.name) + '">' +
              '<input type="hidden" name="value" value="' + esc(value) + '">' +
              '<button type="submit">Remove</button></div></form></td></tr>';
          }).join('') + '</table>'
        : '<p class="sub">None' +
          (field.name === 'fedRelease'
            ? ' — <strong>and that means no release policy rather than release nothing</strong>. ' +
              'This partner receives exactly what /admin/claims and /admin/saml-attributes ' +
              'would give anybody. Adding the first name here starts filtering.'
            : '') + '.</p>') +
      '<form method="post" action="/admin/federation"><div class="formrow">' + carryBack +
      '<input type="hidden" name="action" value="add-value">' +
      '<input type="hidden" name="id" value="' + esc(row.id) + '">' +
      '<input type="hidden" name="field" value="' + esc(field.name) + '">' +
      '<input type="text" name="value" size="40" placeholder="' +
      (field.name === 'fedAttributeMap' ? 'incoming name=ldapAttribute'
        : (field.name === 'fedRelease' ? 'a claim or attribute name' : 'a value')) + '">' +
      '<button type="submit">Add</button></div></form>';
  }).join('');

  const inner = messagesOf(req) +
    '<div class="tiles">' +
    tile(row.authentications, 'Federated sign-ins') +
    tile(row.users, 'Distinct people') +
    tile(row.usable ? 'ready' : (row.enabled ? 'NOT READY' : 'disabled'), 'State') +
    '</div>' +
    (row.lastError
      ? '<p class="warn"><strong>The last attempt was refused.</strong> ' + esc(row.lastError) +
        (row.lastErrorAt ? ' <span class="sub">at ' + esc(row.lastErrorAt) + '</span>' : '') +
        ' A success clears this, so it standing here means nothing has worked since.</p>'
      : '') +
    (row.enabled && !row.ready
      ? '<p class="warn"><strong>Enabled and not configured.</strong> ' +
        esc(row.missing.join(', ')) + ' still to set. Every endpoint for this relationship ' +
        'refuses in this state rather than half-working — a federated sign-in that got half ' +
        'way and produced a session would be the worst possible outcome.</p>'
      : '') +
    '<table><tr><th>What</th><th>Value</th></tr>' +
    '<tr><td>This service is</td><td>' + esc(row.roleLabel) + '</td></tr>' +
    '<tr><td>Protocol</td><td>' + esc(row.protocolLabel) + '</td></tr>' +
    '<tr><td>Partner</td><td class="who"><code>' + esc(row.peer || '(none named)') +
      '</code></td></tr>' +
    (row.role === 'identity-provider'
      ? '<tr><td>Application</td><td class="who">' +
        (row.application
          ? '<a href="/admin/applications?application=' + encodeURIComponent(row.application) +
            '"><code>' + esc(row.application) + '</code></a>'
          : '<span class="sub">none named — this relationship configures nothing until one ' +
            'is</span>') + '</td></tr>'
      : '') +
    '<tr><td>Last used</td><td>' + esc(row.lastSeen || '(never)') +
      (row.lastUser ? ' <span class="sub">by ' + esc(row.lastUser) + '</span>' : '') +
      '</td></tr>' +
    '<tr><td>Directory entry</td><td class="who"><code>' + esc(row.dn) + '</code></td></tr>' +
    '</table>' +
    (row.role === 'service-provider'
      ? '<h2>What to configure at the partner</h2>' +
        '<p class="note">These are the URLs to give whoever runs the identity provider. The ' +
        'assertion consumer service is the one that matters: a partner sending its answer ' +
        'anywhere else produces a 404 in a browser AFTER a successful sign-in somewhere ' +
        'else, which is the least diagnosable failure this feature has.</p>' +
        '<table><tr><th>What they need</th><th>Value</th></tr>' +
        '<tr><td>Assertion consumer service / <code>wreply</code> / ' +
          '<code>redirect_uri</code></td><td class="who"><code>' + esc(acs) +
          '</code></td></tr>' +
        '<tr><td>Our entityID / <code>wtrealm</code></td><td class="who"><code>' + esc(acs) +
          '</code><span class="sub">the same string, deliberately: one name for this ' +
          'service per partner, so a partner keying its trust store off an entityID gets ' +
          'one that is only ours-with-them</span></td></tr>' +
        ((row.protocol === 'saml2' || row.protocol === 'saml11')
          ? '<tr><td>Our SAML metadata</td><td class="who"><a href="' +
            esc(federation.PATHS.metadata + '/' + encodeURIComponent(row.id)) + '"><code>' +
            esc(metadata) + '</code></a><span class="sub">unsigned, deliberately — a ' +
            'signature over it made by the very key it publishes proves nothing they did ' +
            'not already have to trust</span></td></tr>'
          : '') +
        '</table>' +
        '<p><a class="btn" href="' + esc(login) + '">Start a federated sign-in through this ' +
        'partner</a> ' + (row.usable ? '' : '<span class="sub">— it will refuse until this ' +
        'relationship is enabled and configured</span>') + '</p>'
      : '<h2>What this relationship does</h2>' +
        '<p class="note">Every protocol endpoint here already issues to anybody that asks, ' +
        'so this relationship changes nothing about whether the partner is answered. What it ' +
        'adds is two things: the partner is marked as a FEDERATION PARTNER rather than a test ' +
        'client, and <code>fedRelease</code> below decides which attributes are released to ' +
        'it.</p>' +
        '<p class="note"><strong>The release list can only remove, and only from what ' +
        '<a href="/admin/claims">custom claims</a>, <a href="/admin/saml-attributes">custom ' +
        'SAML attributes</a> and the groups claim would add.</strong> It cannot touch ' +
        '<code>sub</code>, <code>iss</code>, <code>exp</code>, a NameID or anything else the ' +
        'protocol puts in an artifact itself — those are what make the artifact verifiable, ' +
        'and a release list that could drop <code>iss</code> would produce tokens that fail ' +
        'to verify with nothing pointing back at this page.</p>') +
    '<h2>Settings</h2>' +
    '<table><tr><th>Field</th><th>Value</th><th>What it is</th></tr>' + fieldRows + '</table>' +
    '<h2>Switches</h2>' +
    '<table><tr><th>Field</th><th>Now</th><th></th><th>What it is</th></tr>' + switches +
    '</table>' +
    '<h2>Lists</h2>' + multiSections +
    '<h2>Delete</h2>' +
    '<form method="post" action="/admin/federation"><div class="formrow">' + carryBack +
    '<input type="hidden" name="action" value="delete">' +
    '<input type="hidden" name="id" value="' + esc(row.id) + '">' +
    '<button type="submit" class="danger">Delete this relationship</button>' +
    '<span class="sub">The entry goes and takes its ' + row.authentications +
    ' recorded sign-in(s) with it. The PEOPLE it authenticated keep their entries under ' +
    '<code>ou=users</code> — nothing is ever deleted from there — and any session they hold ' +
    'is unaffected until it expires or is ended.</span>' +
    '</div></form>' +
    '<p class="note"><strong>Everything on this page is an attribute on one directory ' +
    'entry</strong>, so an <code>ldapmodify</code> of <code>' + esc(row.dn) + '</code> does ' +
    'exactly what these forms do — two doors onto one register, not two registers. That cuts ' +
    'both ways: <code>fedClientSecret</code> is this service\'s own credential AT the ' +
    'partner, held in the clear, in a directory where every bind succeeds. It is never shown ' +
    'here and never written to the audit log, and anybody who can read this directory can ' +
    'authenticate as this service at that partner. A deployment federating with something ' +
    'real should know that.</p>' +
    FEDERATION_CAVEAT +
    '<p class="sub"><a href="' +
    esc('/admin/federation' + queryWith(listViewOf('/admin/federation', req.query), {})) +
    '">back to the list</a></p>' + FEDERATION_LINKS;

  log.debug("Leaving federationDetailPage(). " + row.id + ".");
  return {
    inner: inner,
    json: Object.assign({ found: true }, row, {
      endpoints: { assertionConsumerService: acs, login: login,
                   metadata: (row.protocol === 'saml2' || row.protocol === 'saml11')
                     ? metadata : null },
      // The whole record, MINUS the one sensitive field. `fedClientSecret` is
      // replaced by a boolean saying whether one is set — which is the fact a
      // caller actually needs ("is this configured?") without the API being a
      // second way to read a credential out of this process. An ldapsearch is
      // still that way, deliberately and loudly.
      fields: (function () {
        const out = {};
        federation.SCHEMA.attributes.forEach(function (field) {
          if (field.sensitive) {
            out[field.name] = record[field.name] ? '(set — not returned)' : '';
            return;
          }
          out[field.name] = record[field.name];
        });
        return out;
      })(),
      editable: federation.fieldsForRole(row.role)
    })
  };
}

// ---------------------------------------------------------------------------
// THE ACTION FUNCTION. `/admin-api/federation/:action` calls exactly this, with
// `action` off the URL instead of out of a hidden input — rule 7, and it is
// what makes "every console control has an API operation" a property of the
// code rather than a promise in a comment.
//
// It decides NOTHING itself. Every branch calls `federation.js`, which owns the
// schema, the modes and the refusals — the same division `applicationsAction()`
// keeps with `applications.js`. A validation written here would be a second
// opinion about what a relationship may hold, and the one an `ldapmodify` never
// saw.
// ---------------------------------------------------------------------------
function federationAction(body) {
  log.debug("Entering federationAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const id = String(body.id || body.relationship || '').trim();

  if (action === 'create') {
    const result = federation.create({
      fedId: id,
      fedRole: String(body.role || ''),
      fedProtocol: String(body.protocol || ''),
      fedName: String(body.name || ''),
      fedPeer: String(body.peer || ''),
      fedApplication: String(body.application || '')
    });
    log.debug("Leaving federationAction(). create " + (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) return result;
    return Object.assign({}, result, {
      message: 'Registered, and DISABLED. Set what it needs — ' +
        (result.readiness.missing.length
          ? result.readiness.missing.join(', ')
          : 'nothing is missing') +
        ' — and then enable it. A relationship does nothing at all until both are done.'
    });
  }

  if (!id) {
    log.debug("Leaving federationAction(). No relationship named.");
    return { ok: false, errors: ['Name the relationship by its id, in `id`.'] };
  }

  if (action === 'set' || action === 'add-value' || action === 'remove-value') {
    const result = federation.update(id, {
      field: String(body.field || ''),
      value: String(body.value == null ? '' : body.value),
      mode: action === 'remove-value' ? 'remove' : 'add'
    });
    log.debug("Leaving federationAction(). " + action + " " +
              (result.ok ? 'ok' : 'refused') + ".");
    return result;
  }

  if (action === 'enable' || action === 'disable') {
    const result = federation.update(id, {
      field: 'fedEnabled', value: action === 'enable' ? 'TRUE' : 'FALSE'
    });
    log.debug("Leaving federationAction(). " + action + " " +
              (result.ok ? 'ok' : 'refused') + ".");
    return result;
  }

  if (action === 'delete') {
    const result = federation.remove(id);
    log.debug("Leaving federationAction(). delete " + (result.ok ? 'ok' : 'refused') + ".");
    return result;
  }

  log.debug("Leaving federationAction(). Unknown action.");
  return { ok: false,
           errors: ['Unknown action "' + action + '". The seven are: create, set, ' +
                    'add-value, remove-value, enable, disable, delete.'] };
}

function federationView(req) {
  log.debug("Entering federationView().");
  const wanted = String(req.query.relationship || '').trim();
  if (wanted) {
    const detail = federationDetailPage(req, wanted);
    log.debug("Leaving federationView(). The drill-down.");
    return { json: detail.json, inner: detail.inner,
             title: 'Federation relationship ' + wanted,
             up: upTo('/admin/federation', wanted,
                      listViewOf('/admin/federation', req.query)) };
  }
  const list = federationListPage(req);
  log.debug("Leaving federationView(). The list.");
  return { json: list.json, inner: list.inner, title: 'Federation' };
}

app.get('/admin/federation', function (req, res) {
  log.debug("Entering the admin federation page.");
  const view = federationView(req);
  respond(req, res, view.json, view.title, '/admin/federation', view.inner, view.up);
  log.debug("Leaving the admin federation page. " + view.title + ".");
});

app.post('/admin/federation', function (req, res) {
  log.debug("Entering the admin federation action endpoint.");
  const body = parseBody(req);
  const result = federationAction(body);
  const id = String(body.id || body.relationship || '').trim();
  // The list state the form carried, REBUILT rather than echoed — see
  // listViewFromBack(), and the note in admin-ui/CLAUDE.md about a new form on
  // a drill-down needing `carryBack` in it. Every form on the drill-down above
  // has it.
  const listView = listViewFromBack('/admin/federation', body.back);
  // A DELETE goes back to the LIST and everything else stays on the
  // drill-down, which is the one place this differs from the SAML 2.0 page's
  // handler: landing on the detail page of something that no longer exists
  // would answer with "there is no relationship called…", which reads as the
  // delete having failed.
  const back = (id && result.ok !== false && String(body.action || '') !== 'delete')
    ? '/admin/federation' + queryWith(listView, { relationship: id })
    : '/admin/federation' + queryWith(listView, {});
  respondToAction(req, res, back, result);
  log.debug("Leaving the admin federation action endpoint.");
});

module.exports = {
  // THE SHELL, for the one module outside this file that draws a console page:
  // `../sts_metadata.js`, which builds `/admin/sts-metadata` from the live
  // express router and cannot live in here (it must be the LAST module
  // server.js loads, or it would be the reason a route is missing from its own
  // list). `respond()` is what it calls; `page()` is exported beside it because
  // a caller that needed the shell without the ?format=json half would
  // otherwise reimplement respond() badly. Neither decides anything: what that
  // page SAYS is entirely that module's.
  respond: respond,
  page: page,
  // Filled by ldap_server.js at its require time; see the note above it.
  setDirectoryReader: setDirectoryReader,
  // Filled by spiffe_server.js at its require time, for the reason beside the
  // requires at the top: this file must not require that module.
  setSpiffeReader: setSpiffeReader,
  setScimReader: setScimReader,
  setGroupReader: setGroupReader,
  setDirectoryWriter: setDirectoryWriter,
  // Filled by logout/logout.js at ITS require time — the sixth slot, and rule
  // 3e's test answers yes for the same two reasons at once. See the block above
  // setLogoutReader().
  setLogoutReader: setLogoutReader,
  usersAction: usersAction,
  // The sign-out page's view and its four actions, for admin_api.js. Rule 7:
  // the API calls exactly these, so an action added to that switch is most of
  // adding it there — and the refusal sentence that names the four is what the
  // parent project's tests/admin_api.js reads to check the parity.
  logoutView: logoutView,
  logoutAction: logoutAction,
  jtiFrom: jtiFrom,
  // The four action functions. admin_api.js calls exactly these — it decides
  // nothing about a revocation or a claim that this console does not — which is
  // what makes "every /admin control has an /admin-api operation" a property of
  // the code rather than a promise in a comment.
  tokenAction: tokenAction,
  claimsAction: claimsAction,
  vcAction: vcAction,
  vpConfigAction: vpConfigAction,
  configAction: configAction,
  // The trust realm registry's five writes and its whole view, for
  // mgmt-api/admin_api.js. Rule 7 — every page of this console and every action
  // of its handlers has an operation on /admin-api, driven through the SAME
  // function, so that a realm created over the API and a realm created on the
  // form cannot come to mean two different things.
  realmsAction: realmsAction,
  // The token-lifetimes page's own action. It writes through config.js like
  // configAction does — see the header above it for why it is a page of its own
  // and not four more rows on /admin/config — and it is exported separately
  // because rule 7 is about the CONTROL: the form on that page has two actions,
  // so the API has two operations, and pointing them at configAction instead
  // would give a caller a door that took any of forty-nine settings under a
  // name that promised four.
  tokenLifetimesAction: tokenLifetimesAction,
  // The JSON views, one per page, for the same reason. See the block comment
  // above consoleJson().
  consoleJson: consoleJson,
  metricsJson: metricsJson,
  tokensView: tokensView,
  // The audit log's view is the whole function rather than a JSON builder, for
  // the reason the block above consoleJson() gives: the filtering and the paging
  // are work both the page and the API need, and two copies of it would be two
  // answers that each looked right alone.
  auditView: auditView,
  // The delegation page's view, and the whole function for the same reason the
  // audit log's is: the filtering, the paging and the collapse to chains are
  // work both the page and the API need. It is the second read-only resource
  // here — rule 7 asks for an operation per CONTROL, and this page has none.
  delegationView: delegationView,
  usersView: usersView,
  groupsView: groupsView,
  applicationsView: applicationsView,
  applicationsAction: applicationsAction,
  // The three SPIFFE views and their three action handlers. admin_api.js calls
  // exactly these — rule 7 again: the API decides nothing the console does not,
  // and an action added to one of these switches is most of adding it there.
  spiffeView: spiffePage,
  spiffeAction: spiffeAction,
  spiffeEntriesView: spiffeEntriesView,
  spiffeEntriesAction: spiffeEntriesAction,
  spiffeAgentsView: spiffeAgentsView,
  spiffeAgentsAction: spiffeAgentsAction,
  authorizationServersView: authorizationServersView,
  authorizationServersAction: asAction,
  // The SAML 2.0 identity provider page and its four writes. Rule 7 again: the
  // API calls exactly these, so an action added to that switch is most of
  // adding it to /admin-api.
  saml2View: saml2View,
  saml2Action: saml2Action,
  saml11View: saml11View,
  saml11Action: saml11Action,
  // The roles page and its two writes. Rule 7 again — and this one is the page
  // most in need of the API half rather than least: the management API is not
  // gated, so `POST /admin-api/rbac/grant` is the only door onto the roster that
  // still works when nobody holds a role and `admin.openWhenEmpty` is off.
  rbacView: rbacView,
  rbacAction: rbacAction,
  // The federation register's page and its seven writes. Rule 7 again: the API
  // calls exactly these, so an action added to that switch is most of adding it
  // to /admin-api. This one matters more than most — the management API is not
  // gated, so `POST /admin-api/federation/create` is how a test configures a
  // partner with no browser at all, which is the only way the feature can be
  // exercised automatically.
  federationView: federationView,
  federationAction: federationAction,
  // The gate's answer for one request, so admin_api.js's own /rbac view can say
  // WHO IS ASKING without a second reading of the cookie that could disagree
  // with this one.
  gateStateFor: gateStateFor,
  claimsJson: claimsJson,
  // The SAML half of the same store, as its own view, because it is its own
  // page: GET /admin-api/saml-attributes answers this and GET /admin-api/claims
  // answers the one above. There is no third function underneath them — both
  // are claimSetsJson() with a different list of set ids and the one rule that
  // is theirs alone.
  samlAttributesJson: samlAttributesJson,
  // Which person the claims page shows attribute values for. Exported for the
  // same reason vcPreviewUser is: GET /admin-api/claims takes the same `user`
  // parameter, and a second reader of that query string would be a second cap
  // and a second default.
  claimsPreviewUser: claimsPreviewUser,
  vcJson: vcJson,
  vcPreviewUser: vcPreviewUser,
  vpConfigJson: vpConfigJson,
  scimJson: scimJson,
  configJson: configJson,
  // It takes the REQUEST, unlike most of the views here, and for a reason worth
  // the line: every URL it prints is built from the one the call arrived on —
  // that is what makes a realm's base URL correct through a published port, on
  // a compose network and behind a proxy alike, and a snapshot built without a
  // request could only ever name localhost.
  realmsJson: realmsJson,
  tokenLifetimesJson: tokenLifetimesJson,
  // A body field that may appear more than once. Exported because the
  // management API takes the same two spellings of a list (`attribute` and
  // `attributes`), and reading a repeated form field is not something
  // helpers.parseBody() can answer.
  listField: listField,
  // The console's own paging rules, so that /admin-api reports and clamps `per`
  // and `page` the way every page here does rather than inventing a second
  // ceiling.
  MAX_ROWS: MAX_ROWS,
  DEFAULT_PER_PAGE: DEFAULT_PER_PAGE,
  // The drill-downs' session blocks start smaller, and the API documents that
  // number rather than repeating it: a document saying 50 beside a service doing
  // 5 is worse than a document that says nothing.
  DEFAULT_BLOCKS_PER_PAGE: DEFAULT_BLOCKS_PER_PAGE
};
