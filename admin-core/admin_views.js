'use strict';
//
// File: admin_views.js
//
// ===========================================================================
// WHAT THE TWO ADMIN SURFACES BOTH READ. The other half of `admin_actions.js`,
// and the half that could not simply be moved.
//
// The actions came across on 2026-09-12 verbatim, because not one of them had
// ever touched `req`, `res` or markup. **The views were not like that**: a
// `*View()` on the console returns `{ json, inner }` — the machine answer and
// the HTML — computed together from one pass over the data, which is the
// strongest form of rule 7 there is. A page and its operation cannot disagree
// when one function computes both.
//
// So the split had to be made on a measurement rather than a hunch. Of the
// eighty-nine view-shaped functions in `admin-ui/admin.js`, forty-six return a
// json half, and **only three of those separate at a clean boundary** — the
// other forty-three build row markup part-way through the computation, inside
// the `.map()` that walks the rows. Splitting those is real surgery on
// interleaved code and is NOT what this file is.
//
// **THIS FILE IS THE PART THAT NEEDED NO SURGERY.** Thirty-seven functions
// that were already pure: they compute a JSON answer and reach no markup at
// all, directly or through anything they call. They moved exactly as the
// actions did, with the comments that argued them, and the behaviour is
// intended to be identical to the line.
//
// ---------------------------------------------------------------------------
// WHAT STAYED BEHIND, AND THE LINE IS NOT "IS IT PURE".
//
// Two kinds of thing are still on `admin-ui/admin.js` and belong there:
//
//   * **Anything that builds HTML**, which is the forty-three above plus the
//     views that wrap them. That is the next increment and it is bespoke.
//   * **THE CONSOLE'S OWN STRUCTURE**, even though it is perfectly pure:
//     `consoleJson()` (which pages exist, from `NAV`), `configJson()` and
//     `settingsGroupsFor()` (where a settings group is edited, from
//     `SETTING_HOMES`), `protocolSettingsJsonFor()` and
//     `configSettingsJson()`. A caller asking *what pages does this console
//     have* and *where is this setting edited* is asking the console about
//     itself, and the answer is not a thing a layer beneath it could know.
//     Purity was not the test; ownership was.
//
// `scimJson()` is the one function here that reaches back for that knowledge —
// it embeds the SCIM settings block in its answer — and it does so through
// `configSettingsJson`, which the console hands over like any other
// collaborator. The alternative was for the console page and
// `/admin-api/scim` to assemble that block separately, which is precisely the
// drift rule 7 exists to prevent.
//
// ---------------------------------------------------------------------------
// THE SAME TWO RULES AS `admin_actions.js`, FOR THE SAME REASONS.
//
// No route may be registered here — two modules require this file, so a route
// would be registered twice and rule 1 means the second can never win. And
// nothing here may build markup: the moment one of these functions returns a
// string with a tag in it, the console is no longer the only thing that
// renders and there are two places a page can come from.
//
// It may be required at 18 or later and nowhere earlier, for
// `admin_actions.js`'s reason: the modules below include route-registering
// ones, and from `common/` or from anything earlier in the order this file
// would pull them into the router ahead of themselves.
// `tests/admin_actions_layer.js` pins every one of these.
// ===========================================================================

// The helpers this half reaches for. `baseUrlOf` builds the issuer and endpoint
// URLs `realmsJson()` reports and `stsKeysFor` is the per-realm key set
// `keysView()` describes. Both were missed on the first pass — the
// destructure they come from in admin-ui/admin.js is spread over thirty
// comment-interleaved lines, which is the same trap that cost the action
// half `numberWord` and `signJwt`. The symptom was `GET /admin-api/realms`
// answering 500 with `baseUrlOf is not defined`, found by the job that
// drives all 273 operations and by nothing else.
const { log, baseUrlOf, stsKeysFor, userFor,
        subjectForName } = require('../common/helpers');
// The credential store, for the ways-in list the new-person form offers.
const credentials = require('../common/credentials');
// The two second factors, for the roster columns on /admin/users.
const totp = require('../common/totp');
const webauthnPolicy = require('../authn/webauthn_policy');
const backupCodes = require('../common/backup_codes');
// THE SIGN-ON SESSION MAP, which `signOnSessionRows()` walks. It is the same
// destructured-require trap one module along: admin.js pulls fourteen names
// out of two modules through multi-line destructures, and a name taken from
// the second one is exactly as invisible to a move as one taken from the
// first. `authn` is position 8 in the require order, so this is a cache hit
// wherever this file is legitimately loaded.
const { sessions, sessionStartedAt } = require('../authn/authn');
const config = require('../common/config');
const mode = require('../common/mode');
const realms = require('../common/realms');
const stats = require('../common/admin_stats');
const oidcRp = require('../common/oidc_rp');
const rbac = require('../admin-ui/admin_rbac');
const vcClaims = require('../oid4vc/vc_claims');
const vpConfig = require('../oid4vc/vc_verifier_config');
const claimAttributes = require('../common/claim_attributes');
const scimMap = require('../scim/scim_map');
const groupClaims = require('../common/group_claims');
const applications = require('../common/applications');
// A PERSON's assertion key pairs, for the Credentials section of their own
// page (2026-09-13). A library: it holds no store and registers no route.
const personAssertions = require('../common/person_assertions');
// Whether a private key written onto an entry is sealed at rest, which is
// `persists()` and not `sealed()` — `person_assertions.js` argues why.
const keystore = require('../common/keystore');
// THE CERTIFICATE AUTHORITY, for the Credentials section of an application's
// page: whether this realm can issue a key pair at all, and from what. A
// LIBRARY (rule 3) — it registers no route — so requiring it here moves
// nothing.
const pki = require('../common/pki');
const nodeCrypto = require('crypto');
const appPermissions = require('../common/app_permissions');
const consent = require('../common/consent');
const roles = require('../common/roles');
// THE PASSWORD POLICY REGISTER (2026-09-12), for /admin/policies. A leaf that
// registers no route, so this require is a cache hit wherever it is reached.
const passwordPolicy = require('../common/password_policy');
// Four more with the second batch: the audit log the audit view pages, the
// delegation register the delegation view reads, the Kerberos principal
// database beside it, and the token registry /admin/tokens lists.
const auditLog = require('../common/audit');
// THE ERROR CODE TABLE. A leaf that requires nothing, so it cannot close a
// cycle from here; `errorCodesView()` below is its one reader in this layer.
const errorCodes = require('../common/error_codes');
// THE USED-ASSERTION HISTORY (2026-09-13), for `/admin/used-assertions` and
// `GET /admin-api/used-assertions`. A LIBRARY in `common/` that requires
// nothing here, so the require moves no route and closes no cycle.
const usedAssertions = require('../common/used_assertions');
const delegation = require('../common/delegation');
const krb5Principals = require('../kerberos/krb5_principals');
// Stored Kerberos keys (2026-09-12), a plain require for the reason
// `admin_actions.js` gives beside its own.
const krb5PersonKeys = require('../kerberos/krb5_person_keys');
const oauth2 = require('../oauth-oidc/oauth2');
// RFC 7591 section 2.3 (2026-09-13): what a statement on an entry says, and the
// settings that decide what one is worth. A library that registers no route.
const softwareStatement = require('../oauth-oidc/software_statement');
const assertionGrant = require('../oauth-oidc/assertion_grant');
// RFC 8705 (2026-09-13): the TLS client certificates an application holds, the
// five subject parameters it may register instead, and whether the main port
// can bind a token at all. Three libraries that register no route.
const tlsClientCertificates = require('../common/tls_client_certificates');
const certificateSubject = require('../common/certificate_subject');
const mtls = require('../oauth-oidc/mtls');
// The two SAML profiles, for the artifact and pending-request counts their
// pages publish.
const saml2 = require('../saml/saml2_sso');
const saml11 = require('../saml/saml11_sso');
const authorizationServers = require('../oauth-oidc/authorization_servers');
const federation = require('../federation/federation');
// The receiver half of Shared Signals, which the three reports below draw
// this service's own registered streams from.
const signals = require('../ssf/ssf_receivers');
// The SPIFFE libraries the three reports below read: the registry that holds
// the entries, the authority that signs an SVID, and the authenticator whose
// per-method table the SPIRE Server API is authorized against.
const spiffeRegistry = require('../spiffe/spiffe_registry');
const spiffeCa = require('../spiffe/spiffe_ca');
const spiffeAuth = require('../spiffe/spiffe_auth');

// ---------------------------------------------------------------------------
// THE TABLES AND HELPERS THIS HALF SHARES WITH THE OTHER ONE. They went to
// `admin_actions.js` when the actions moved, because that is where they are
// DISPATCHED on — and a view reads the same table to draw the buttons, or to
// report which settings a page owns. One table, two readers, which is the
// arrangement that stops a page offering a control its action does not have.
//
// This is the only require between the two halves and it goes ONE WAY:
// nothing in `admin_actions.js` reaches back here, and it must not — a view
// is a thing an action has no business consulting.
// ---------------------------------------------------------------------------
const adminActions = require('./admin_actions');
const SAML2_SP_KIND = adminActions.SAML2_SP_KIND;
const SAML11_RP_KIND = adminActions.SAML11_RP_KIND;
const SAML_ASSERTION_KEYS = adminActions.SAML_ASSERTION_KEYS;
const SAML_ASSERTION_SETTINGS = adminActions.SAML_ASSERTION_SETTINGS;
const TOKEN_LIFETIME_KEYS = adminActions.TOKEN_LIFETIME_KEYS;
const configSettingFor = adminActions.configSettingFor;
const noXacml = adminActions.noXacml;
const samlAssertionRowFor = adminActions.samlAssertionRowFor;

// ---------------------------------------------------------------------------
// WHAT THE CONSOLE HANDS OVER. Five of these are inverted hooks on
// `admin-ui/admin.js` (rule 3e) filled by the module that owns the subsystem
// — `crypto_metadata.js`, `xacml_admin.js`, `ldap_server.js`, `scim.js` and
// `xacml_role_pep.js`. The sixth is the console's own settings-block builder,
// which `scimJson()` embeds; see the header for why it is asked for rather
// than reimplemented.
//
// The slots do not move: every filler in the tree names the console module,
// and so does every rule 3e sentence in CLAUDE.md. The console forwards from
// inside the setter it already had.
// ---------------------------------------------------------------------------
// `logoutReader` is the SECOND collaborator both halves need — sessionsView()
// reads what is live and sessionsAction() ends it — so the console's one
// setter now writes here as well as into admin_actions.js.
// THE THREE REPORTERS, filled by ssf/ssf.js. They are the same slots the
// action half holds — the reports READ what the actions ACT on — so the
// console's one setter writes into both.
// Filled by spiffe/spiffe_server.js through the console, like the rest.
// The two directory slots the new-person answer needs: the writer says
// whether an entry can be created at all, the reader finds the container.
// The group slots: the reader lists them, the writer says whether the page
// may offer a control. Both are the console's, forwarded like the rest.
let groupReader = null;
let groupWriter = null;
let directoryWriter = null;
let directoryReader = null;
let spiffeReader = null;
let signalsReporter = null;
let caepReporter = null;
let riscReporter = null;
let logoutReader = null;
let cryptoReporter = null;
let xacmlPages = null;
let directoryPages = null;
let scimReader = null;
let rolePreviewer = null;
let configSettingsJson = null;
// The client-certificate truststore (2026-09-12). Forwarded by
// `admin-ui/admin.js`'s `setTruststore()`, which `common/protocol_stack.js`
// fills; that setter carries the argument.
let truststore = null;

function setGroupReader(value) {
  log.debug("Entering setGroupReader().");
  groupReader = value;
  log.debug("Leaving setGroupReader().");
}

function setGroupWriter(value) {
  log.debug("Entering setGroupWriter().");
  groupWriter = value;
  log.debug("Leaving setGroupWriter().");
}

function setDirectoryWriter(value) {
  log.debug("Entering setDirectoryWriter().");
  directoryWriter = value;
  log.debug("Leaving setDirectoryWriter().");
}

function setDirectoryReader(value) {
  log.debug("Entering setDirectoryReader().");
  directoryReader = value;
  log.debug("Leaving setDirectoryReader().");
}

function setSpiffeReader(value) {
  log.debug("Entering setSpiffeReader().");
  spiffeReader = value;
  log.debug("Leaving setSpiffeReader().");
}

function setSignalsReporter(value) {
  log.debug("Entering setSignalsReporter().");
  signalsReporter = value;
  log.debug("Leaving setSignalsReporter().");
}

function setCaepReporter(value) {
  log.debug("Entering setCaepReporter().");
  caepReporter = value;
  log.debug("Leaving setCaepReporter().");
}

function setRiscReporter(value) {
  log.debug("Entering setRiscReporter().");
  riscReporter = value;
  log.debug("Leaving setRiscReporter().");
}

function setLogoutReader(value) {
  log.debug("Entering setLogoutReader().");
  logoutReader = value;
  log.debug("Leaving setLogoutReader().");
}

function setCryptoReporter(value) {
  log.debug("Entering setCryptoReporter().");
  cryptoReporter = value;
  log.debug("Leaving setCryptoReporter().");
}

function setXacmlPages(value) {
  log.debug("Entering setXacmlPages().");
  xacmlPages = value;
  log.debug("Leaving setXacmlPages().");
}

function setDirectoryPages(value) {
  log.debug("Entering setDirectoryPages().");
  directoryPages = value;
  log.debug("Leaving setDirectoryPages().");
}

function setScimReader(value) {
  log.debug("Entering setScimReader().");
  scimReader = value;
  log.debug("Leaving setScimReader().");
}

function setRolePreviewer(value) {
  log.debug("Entering setRolePreviewer().");
  rolePreviewer = value;
  log.debug("Leaving setRolePreviewer().");
}

function setConfigSettingsJson(value) {
  log.debug("Entering setConfigSettingsJson().");
  configSettingsJson = value;
  log.debug("Leaving setConfigSettingsJson().");
}

function setTruststore(value) {
  log.debug("Entering setTruststore().");
  truststore = value;
  log.debug("Leaving setTruststore().");
}

// ---------------------------------------------------------------------------
// THE SESSION THIS CONSOLE READS (2026-09-06), AND IT IS NO LONGER THE SIGN-ON
// SESSION.
//
// This console is a RELYING PARTY of this service's own authorization server:
// it holds a session of its own, established from an ID Token, in its own
// cookie. `authn.js`'s `consoleSession()` reads the SIGN-ON session — what a
// person has with the identity provider — and the two are different facts with
// different lifetimes, which is the whole reason this move was worth making.
//
// **THE RETURN SHAPE IS `consoleSession()`'s ON PURPOSE.** Every caller in this
// file wants `{ session, realm, foreign }` and none of them cares which of the
// two it is looking at; keeping the shape is what made this a change to one
// function rather than to seventy pages. `foreign` is now always false — a
// relying-party session belongs to the surface that minted it and there is no
// realm to be foreign to — and the member is kept because the banner reads it.
//
// The realm is the DEFAULT one whatever realm is being read, which is the rule
// this console has had since realms existed and is unchanged: the roster is the
// default realm's `ou=groups`, so a session minted in `acme` must not open this
// console. `oidc_rp.js` runs the console's whole flow in that realm for exactly
// that reason.
// ---------------------------------------------------------------------------
function consoleRpSession(req) {
  log.debug("Entering consoleRpSession().");
  const session = oidcRp.sessionFor(req, 'admin');
  log.debug("Leaving consoleRpSession(). " +
            (session ? "Signed in as " + session.user.username + "." :
             "None."));
  return session
    ? { session: session, realm: realms.DEFAULT_REALM, foreign: false }
    : null;
}

// Everything the banner and the guard both need, worked out ONCE per request.
//
// Both were written separately at first and disagreed within the hour: the
// guard let somebody through on the empty-roster rule and the banner, asking
// again, found a roster that a concurrent grant had just filled — so the page
// said "signed in, holding no role" above a console it had just allowed. One
// function, one answer.
function gateStateFor(req) {
  log.debug("Entering gateStateFor().");
  // THE MODE, since 2026-09-06, where this read `admin.authRequired`. That
  // setting is gone: "is authentication required here" had four answers across
  // this service and now has one. See common/mode.js.
  const enforced = mode.gatesConsole();
  // THE DEFAULT REALM'S SESSION, whichever realm is being read, and only here —
  // see the require at the top of this file for why the console asks the
  // question that way and why no other module may.
  const found = consoleRpSession(req);
  const session = found ? found.session : null;
  const username = session ? session.user.username : '';
  // ---------------------------------------------------------------------
  // WHOSE ROSTER DECIDES, AND WHERE ITS ANSWER HOLDS (2026-09-14, #32).
  //
  // The console's own session lives in the default realm's partition and its
  // SIGN-ON session lives wherever the code flow ran — `derivedFromRealm`
  // names that realm, and an absent value means the default realm. That realm
  // is who this person IS, so it is whose roster is asked:
  //
  //   * signed in through the DEFAULT realm: the default realm's roster, which
  //     is the SERVICE roster — its answer holds in every realm, exactly as
  //     before;
  //   * signed in through realm `acme`: acme's roster, whose answer holds while
  //     acme is the realm being read and in no other. Reaching the default
  //     realm or another realm with that session grants nothing, and service
  //     pages are refused even in acme (`admin-ui/admin_scope.js`).
  //
  // Until #32 every console session was asked the default realm's roster BY
  // NAME, so a person in any realm who shared a service administrator's
  // username held that administrator's roles. Asking the roster of the realm
  // the person authenticated in is what closes that.
  // ---------------------------------------------------------------------
  const identityRealm = session
    ? String(session.derivedFromRealm || realms.DEFAULT_ID) : '';
  const authority = !session ? null
    : (identityRealm === realms.DEFAULT_ID ? 'service' : 'realm');
  const ambientRealm = realms.currentId();
  const outsideRealm = authority === 'realm' && ambientRealm !== identityRealm;
  const asked = rbac.rolesOf(username, identityRealm || realms.DEFAULT_ID);
  const held = outsideRealm
    ? Object.assign({}, asked, { roles: [], read: false, write: false,
                                 open: false, openable: false })
    : asked;
  const state = {
    enforced: enforced,
    available: rbac.available(),
    session: session,
    username: username,
    // `service` for a default-realm identity and `realm` for any other; null
    // when nobody is signed in.
    authority: authority,
    identityRealm: identityRealm || null,
    // A realm administrator reading a realm that is not theirs holds nothing
    // here; the gate says why rather than drawing a page of refusals.
    outsideRealm: outsideRealm,
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
    empty: held.empty,
    // The bootstrap administrator (2026-09-13), for the banner that says whose
    // arrival closes the open console. See admin_rbac.js's bootstrapState().
    bootstrap: held.bootstrap || null
  };
  log.debug("Leaving gateStateFor(). enforced=" + enforced + ", read=" +
            state.read +
            ", write=" + state.write + ".");
  return state;
}

// The browser sign-on sessions, as rows. Expired ones are still in the map
// until something reads them (sessionOf() drops one when it finds it stale), so
// the state is computed here rather than assumed — otherwise the console would
// report a session that no request would honour.
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
      // TWO INSTANTS SINCE 2026-09-14, and they stopped being one when a
      // session learned to hold several authentications: `startedAt` is when
      // it BEGAN (its first event) and `authTime` the MOST RECENT
      // authentication, which a step-up or `max_age` moves. A column called
      // "Signed in" drawn from `authTime` showed an hour-old session as a
      // minute old.
      startedAt: sessionStartedAt(session),
      authTime: (session.authTime || 0) * 1000,
      authentications: (Array.isArray(session.events)
        ? session.events.length : 1) + (session.eventsDropped || 0),
      expires: session.expires || 0,
      expired: !!session.expires && session.expires <= nowMs,
      // Which WS-Federation relying parties this session signed into. It is the
      // list wsignout1.0 has to fan out to, and seeing it is the only way to
      // know in advance what a sign-out is about to do.
      wsfedRealms: Object.keys(session.wsfedRealms || {})
    });
  });
  rows.sort(function (a, b) { return b.startedAt - a.startedAt; });
  log.debug("Leaving signOnSessionRows(). " + rows.length + " session(s).");
  return rows;
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

// ---------------------------------------------------------------------------
// GET /admin/tokens/set?id=… — THE CREDENTIALS THAT CAME BACK IN ONE REPLY.
//
// **THE TOKENS PAGE'S SECOND DRILL-DOWN, AND IT IS THE OLD TABLE SCOPED TO ONE
// ISSUANCE.** Since 2026-09-05 that list draws a row per reply rather than a
// row per credential, which is what the reader wants nineteen times out of
// twenty and exactly wrong the twentieth: when somebody is chasing ONE token
// they need its own jti, its own expiry and its own button back. So the members
// are drawn here by `issuedRow()` — the very function the list used to call —
// and the column legend on the list describes this table without a word
// changing.
//
// It hangs under /admin/tokens the way /admin/tokens/credential does and for
// the same reasons: no `NAV` row, `active` is '/admin/tokens', and `up` carries
// the filter and the page the reader left, so the trail reads `Tokens › One
// issuance` and the way back is the row they clicked on.
//
// **IT IS ADDRESSED BY `setKey` AND NOT BY THE SET ID**, and the difference
// matters for exactly one case. A grouped set's key is `set:<id>`; a set of one
// has no id at all and its key is `one:<this service's own row handle>`. The
// list only ever links here from a group — for one credential this page would
// be a click that added nothing, so those rows still open the lineage directly
// — but the KEY space covers both, so `GET /admin-api/tokens/set` can open any
// row of that table and a test need not know which kind it has in its hand.
// ---------------------------------------------------------------------------
function tokenSetView(query) {
  log.debug("Entering tokenSetView().");
  const asked = String((query && query.id) || '').trim();
  const set = asked ? stats.issuedSetByKey(asked) : null;
  log.debug("Leaving tokenSetView(). " +
            (set ? set.size + " member(s)." : "No " +
      "such set."));
  return {
    asked: asked,
    set: set,
    json: {
      // The key that was ASKED FOR, echoed even when nothing holds it, because
      // a caller walking a list it drew a minute ago needs to know which of its
      // keys came back empty and not merely that one did.
      setKey: asked || null,
      // Null rather than an empty object for a set nothing holds — which is the
      // ORDINARY answer for one forgotten to the cap, not an error — and the
      // sentence beside it says which of the two happened.
      set: set,
      found: !!set,
      why: set ? null : (asked
        ? 'Nothing here is called "' + asked + '". Either it was never a ' +
          'set, or it has been forgotten to the cap since the list naming it ' +
          'was drawn.'
        : 'Name a set. Every grouped row of GET /admin-api/tokens carries ' +
          'its `setKey`, and so does every row of `sets`.')
    }
  };
}

// The register and its picture, in one place so that the page, `?format=json`
// and `GET /admin-api/permissions` cannot come to disagree about what is in it
// — the same property `delegationView()` gives the acts half.
function permissionsView() {
  log.debug("Entering permissionsView().");
  const register = appPermissions.register();
  const graph = appPermissions.graph(register.grants);
  // THE GROUPINGS, off the register that has just been read rather than off a
  // second walk of `ou=applications`. `appPermissions.clusters()` will do the
  // walk itself when it is handed nothing, and every caller here has the answer
  // in hand already — so passing it is what keeps the whole-register picture,
  // the group list under it and `GET /admin-api/permissions` describing ONE
  // reading of the registry rather than three taken a few milliseconds apart.
  const groups = appPermissions.clusters(register);
  log.debug("Leaving permissionsView(). " + register.counts.grants + " " +
      "grant(s) in " +
            groups.counts.clusters + " group(s).");
  return { register: register, graph: graph, clusters: groups };
}

// The crypto report as JSON, for `admin_api.js`. It calls exactly this, so the
// API cannot compute an answer the console does not draw — which is what makes
// "every /admin page has an /admin-api operation" a property of the code.
function cryptoView(req) {
  log.debug("Entering cryptoView().");
  if (!cryptoReporter) {
    log.debug("Leaving cryptoView(). No reporter.");
    return null;
  }
  const report = cryptoReporter.report(baseUrlOf(req));
  log.debug("Leaving cryptoView(). " +
            ((report.families || []).length) + " identity service(s).");
  return report;
}

// The key inventory, for admin_api.js. A LIST and never key material: the
// export is the other function, so a caller that only wanted to know what this
// process holds cannot be handed a private key by accident.
function keysView(req) {
  log.debug("Entering keysView().");
  if (!cryptoReporter) {
    log.debug("Leaving keysView(). No reporter.");
    return null;
  }
  const report = cryptoReporter.keys(baseUrlOf(req));
  log.debug("Leaving keysView(). " + ((report.keys || []).length) + " key(s).");
  return report;
}

// The export, for admin_api.js. Returns the vendored exporter's own answer —
// `{ok, files, status}` or `{ok: false, errors}` — and decides nothing, so the
// API and the page cannot refuse different things.
function keysExport(key, format, password) {
  log.debug("Entering keysExport(). key=" + key + ", format=" + format);
  if (!cryptoReporter) {
    log.debug("Leaving keysExport(). No reporter.");
    return null;
  }
  log.debug("Leaving keysExport().");
  return cryptoReporter.exportKey(key, format, password);
}

function xacmlView(req) {
  log.debug('Entering xacmlView().');
  const json = xacmlPages ? xacmlPages.overview(req) : noXacml();
  log.debug('Leaving xacmlView().');
  return json;
}

function xacmlPoliciesView(req) {
  log.debug('Entering xacmlPoliciesView().');
  const json = xacmlPages ? xacmlPages.policies(req) : noXacml();
  log.debug('Leaving xacmlPoliciesView().');
  return json;
}

function xacmlEditorView(req) {
  log.debug('Entering xacmlEditorView().');
  const json = xacmlPages
    ? xacmlPages.editor(String((req.query || {}).policy || '')) : noXacml();
  log.debug('Leaving xacmlEditorView().');
  return json;
}

function xacmlPepsView(req) {
  log.debug('Entering xacmlPepsView().');
  const json = xacmlPages ? xacmlPages.peps(req) : noXacml();
  log.debug('Leaving xacmlPepsView().');
  return json;
}

function xacmlDecideView(req) {
  log.debug('Entering xacmlDecideView().');
  const json = xacmlPages ? xacmlPages.decide(req.query || {}) : noXacml();
  log.debug('Leaving xacmlDecideView().');
  return json;
}

// THE SEVENTH, and the only one of them that reports TRAFFIC rather than
// configuration. It takes no argument at all — there is nothing to filter and
// nothing to name — which is why it is the shortest of the seven and not a
// sign that something was left out.
function xacmlMonitorView(req) {
  log.debug('Entering xacmlMonitorView().');
  const json = xacmlPages ? xacmlPages.monitor() : noXacml();
  log.debug('Leaving xacmlMonitorView().');
  return json;
}

// What `mgmt-api/admin_api.js` calls. The `?format=json` half of each page,
// which is the same object the page itself is built from.
function directoryPageJson(name, req) {
  log.debug('Entering directoryPageJson(). name=' + name);
  if (!directoryPages) {
    log.debug('Leaving directoryPageJson(). No directory is loaded.');
    return { directory: false,
             message: 'No LDAP directory is loaded in this process, so there ' +
                      'is no store to report. ldap/ldap_server.js fills this ' +
                      'reader when it is required.' };
  }
  const view = directoryPages[name](req);
  log.debug('Leaving directoryPageJson().');
  return view.json;
}

// The register, in one place so that the page, `?format=json` and
// `GET /admin-api/consent` cannot come to disagree about what is in it — the
// same property `permissionsView()` gives the delegated permission register.
function consentView() {
  log.debug("Entering consentView().");
  const register = consent.register();
  log.debug("Leaving consentView(). " + register.counts.globals + " " +
      "override(s), " +
            register.counts.consents + " recorded.");
  return register;
}

// ---------------------------------------------------------------------------
// THE REGISTER, IN ONE PLACE so that the page, `?format=json` and
// `GET /admin-api/roles` cannot come to disagree about what is in it — the
// same property `consentView()` and `permissionsView()` give their registers.
// ---------------------------------------------------------------------------
function rolesRegister() {
  log.debug("Entering rolesRegister().");
  const configured = roles.all();
  // WHICH APPLICATIONS REQUIRE WHAT, computed from the applications registry
  // rather than kept anywhere: the requirement lives on the application entry
  // and this is a READING of it. `requiresNarrowedRoles()` is what tells an
  // application somebody has deliberately restricted from one that merely has
  // the default — and the difference matters, because every application in
  // this service requires EVERYBODY and listing all of them would bury the
  // handful that were narrowed.
  const requiring = applications.list().filter(function (row) {
    return applications.requiresNarrowedRoles(row.identifier);
  }).map(function (row) {
    const required = applications.requiredRolesOf(row.identifier);
    return {
      application: row.identifier,
      name: row.name || row.identifier,
      required: required,
      // WHETHER ANYBODY AT ALL COULD SATISFY IT. A role named on an
      // application entry that no role entry defines and that is not built in
      // is a requirement NOBODY can hold — which refuses everybody, silently
      // and correctly, and looks exactly like the application being broken.
      // This is the one thing this page can say that neither the application
      // page nor the role table can.
      unknown: required.filter(function (name) {
        return !roles.isBuiltIn(name) && !configured.some(function (role) {
          return role.name === name;
        });
      })
    };
  });
  const out = {
    // The store, so a reader can say where these entries are and reach them
    // with an ldapsearch.
    container: roles.directoryInstalled() ? 'ou=roles' : '',
    storable: !!roles.directoryInstalled(),
    defaultRequired: roles.DEFAULT_REQUIRED_ROLE,
    claim: config.value('roles.claim') !== false,
    claimName: String(config.value('roles.claimName') || 'roles'),
    enforced: config.value('roles.enforceIssuance') !== false,
    gated: !!rolePreviewer,
    policy: rolePreviewer ? rolePreviewer.policy() : null,
    builtIn: roles.builtInCatalogue(),
    roles: configured,
    requiring: requiring,
    counts: {
      builtIn: roles.BUILT_IN_NAMES.length,
      configured: configured.length,
      members: configured.reduce(function (n, one) {
        return n + one.users.length + one.groups.length +
               one.applications.length;
      }, 0),
      requiring: requiring.length,
      unsatisfiable: requiring.filter(function (one) {
        return one.unknown.length > 0;
      }).length
    }
  };
  log.debug("Leaving rolesRegister(). " + out.counts.configured +
            " configured role(s).");
  return out;
}

function rolesView() {
  log.debug("Entering rolesView().");
  const register = rolesRegister();
  log.debug("Leaving rolesView(). " + register.counts.configured + " role(s).");
  return register;
}

// ---------------------------------------------------------------------------
// WHAT /admin/policies AND GET /admin-api/policies ANSWER (2026-09-12).
//
// ONE COMPUTATION, TWO RENDERINGS, which is this file's whole reason: the page
// draws its form, its schema table and its sentence about enforcement from the
// model below, and the operation hands the same model back as JSON.
//
// **THE PAGE IS "POLICIES" AND THE FIRST KIND ON IT IS THE PASSWORD POLICY**,
// which is why the answer is shaped as KINDS of policy each holding PROFILES
// rather than as a password policy with a page wrapped round it: the next kind
// is a row in `kinds` and a member beside `password`, not a new resource.
//
// **IT IS NOT THE XACML POLICY REPOSITORY.** `/admin/xacml/policies` and
// `/admin/ldap/policies` draw `ou=policies`, which holds documents a PDP
// evaluates; this draws `ou=passwordPolicies`, which holds numbers
// `credentials.setPassword()` checks. `kinds[].container` says which container
// each kind lives in so that a reader does not have to take the page's word.
//
// The profile list is PAGED like every list this console draws, though it has
// one row today: nothing assigns a second profile yet, and a list whose paging
// arrives the day a second row does is a list somebody has to remember to page.
// ---------------------------------------------------------------------------
function passwordGeneratorFacts() {
  log.debug("Entering passwordGeneratorFacts().");
  let version = '';
  try {
    version = require('generate-password/package.json').version;
  } catch (e) {
    log.debug("Caught in passwordGeneratorFacts(): " + ((e && e.message) || e));
    // Not installed, or a build that stripped package.json files. The page says
    // "unknown version" rather than failing to draw; generate() would already
    // have thrown at require time if the module itself were missing.
    version = '';
  }
  log.debug("Leaving passwordGeneratorFacts().");
  return {
    module: 'generate-password',
    version: version,
    source: 'crypto.randomBytes, with rejection sampling so that no ' +
            'character of the pool is likelier than another',
    pools: ['lowercase letters', 'uppercase letters', 'digits', 'symbols'],
    excluded: ['"', '`'],
    drawsUntil: 'the password satisfies the profile, so every generated ' +
                'password is uniform over the passwords the profile accepts'
  };
}

function passwordPoliciesView(query) {
  log.debug("Entering passwordPoliciesView().");
  const q = query || {};
  const profiles = passwordPolicy.list();
  const listed = pagedRows(q, profiles);
  const profile = passwordPolicy.read(passwordPolicy.DEFAULT_PROFILE);
  const enforced = mode.verifiesCredentials();
  const out = {
    mode: mode.current(),
    enforced: enforced,
    enforcement: enforced
      ? 'ENFORCED. This realm is in product mode, so every password set here ' +
        '— at every door below — must meet the profile, and a new password ' +
        'may not repeat a remembered one.'
      : 'NOT ENFORCED. This realm is in development mode, where no password ' +
        'is checked at any door, so a rule about one would be a rule about a ' +
        'credential nothing reads. The history is still RECORDED, so a realm ' +
        'switched to product mode starts with one. A GENERATED password ' +
        'meets the profile in both modes.',
    kinds: [
      { id: 'password', label: 'Password policy',
        container: 'ou=passwordPolicies', profiles: profiles.length,
        governs: 'userPassword' }
    ],
    password: {
      profile: profile,
      rules: passwordPolicy.describe(profile),
      defaults: Object.assign({}, passwordPolicy.DEFAULTS),
      fields: passwordPolicy.FIELDS.map(function (field) {
        return { key: field.key, attribute: field.attribute, label: field.label,
                 type: field.type, min: field.min, max: field.max,
                 unit: field.unit || '', default: field.dflt,
                 value: profile[field.key], source: profile.sources[field.key],
                 what: field.what };
      }),
      schema: passwordPolicy.SCHEMA,
      generator: passwordGeneratorFacts(),
      // THE DOORS, named so that "enforced" is a claim a reader can check
      // rather than one they have to take. Every one ends in
      // `credentials.preparePassword()`.
      doors: [
        { door: '/admin/users/new and /admin/users (Set password)',
          via: 'credentials.setPassword()' },
        { door:
            'POST /admin-api/users/create and /admin-api/users/set-password',
          via: 'credentials.setPassword()' },
        { door: '/portal/password', via: 'credentials.setPassword()' },
        { door: '/portal/activate (the first password a person sets)',
          via: 'credentials.setPassword()' },
        { door: 'an LDAP add or modify of userPassword on 389 or 636',
          via: 'credentials.preparePassword()' }
      ],
      notDoors: 'SCIM carries no password (this service advertises ' +
                'changePassword: false), and a password is never set by ' +
                'signing in. Passwords stored BEFORE a rule changed are not ' +
                're-checked: nothing here holds a password in a form that ' +
                'could be, and the rule applies from the next change.'
    },
    profiles: listed.shown.map(function (one) {
      return { kind: 'password', name: one.name, stored: one.stored, dn: one.dn,
               problems: one.problems };
    }),
    paging: pagingJson(listed.paging),
    actions: ['save-password-policy', 'reset-password-policy']
  };
  log.debug("Leaving passwordPoliciesView(). The profile is " +
            (profile.stored ? 'stored.' : 'the built-in default.'));
  return out;
}

// ---------------------------------------------------------------------------
// THE DRY RUN. Asked through the SAME call the nine issuance sites make, so a
// preview that agreed with the enforcement only by coincidence is impossible —
// which is the property that makes it worth having at all.
// ---------------------------------------------------------------------------
function rolesPreview(query) {
  log.debug("Entering rolesPreview().");
  const asked = query || {};
  const application = String(asked.application || '').trim();
  const who = String(asked.subject || asked.username || '').trim();
  const kind = String(asked.subjectKind || 'user') === 'application'
    ? 'application' : 'user';
  const issuance = String(asked.kind || '');
  if (!application || !who) {
    log.debug("Leaving rolesPreview(). Nothing asked.");
    return null;
  }
  if (!rolePreviewer) {
    log.debug("Leaving rolesPreview(). No previewer.");
    return { asked: { application: application, subject: who,
                      subjectKind: kind, kind: issuance },
             available: false,
             why: 'The XACML family is not loaded in this process, so there ' +
                  'is no PDP to ask and nothing is gated: every issuance is ' +
                  'allowed. That is what issuance_gate.check() answers with ' +
                  'an empty decider, and it is why a process without the ' +
                  'engine is a smaller service rather than a broken one.' };
  }
  const answer = rolePreviewer.preview({
    application: application,
    kind: issuance || undefined,
    subject: { kind: kind, name: who, authenticated: true }
  });
  log.debug("Leaving rolesPreview(). " +
            (answer.allowed ? 'Permit.' : 'Refused.'));
  return Object.assign({ asked: { application: application, subject: who,
                                  subjectKind: kind, kind: issuance },
                         available: true }, answer);
}

// Which person the four tables show values for, and where the page sends itself
// back to. Capped because the string is echoed, and defaulted to somebody the
// directory actually holds from startup so a fresh process shows real values
// rather than an invented person nobody can look up — the same rule and the
// same default /admin/vc uses, deliberately, so the two pages preview the same
// person unless somebody says otherwise.
function claimsPreviewUser(query) {
  log.debug("Entering claimsPreviewUser().");
  const asked = String((query && query.user) || 'alice').trim();
  log.debug("Leaving claimsPreviewUser().");
  return asked.slice(0, 64) || 'alice';
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
    // at LDAP spellings. `sets` says which of the FIVE carries each — all five,
    // not only the ones in this reply, because the catalogue is one list and a
    // per-page view of it would answer "which sets carry mail" with half the
    // truth.
    attributeCatalogue: claimAttributes.catalogueRows(),
    // Stated rather than left to be discovered, because the two halves of a set
    // are one screen apart and the precedence only shows up when both name one
    // claim.
    precedence: 'A typed claim wins over a directory attribute of the same ' +
                'name.',
    sets: ids.map(function (id) {
      const preview = claimAttributes.previewFor(id, user);
      return { id: id, label: stats.CLAIM_SETS[id].label,
               claims: stats.claimSet(id),
               attributes: claimAttributes.selectedNames(id),
               // What those attributes would actually put in this set right
               // now, built by the function the ISSUANCE path calls. A caller
               // with no browser has no other way to ask "what would this
               // issue", and a preview built by a second walk of the catalogue
               // would be a preview that can disagree with the token.
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
    preview: Object.assign({ user: user },
                           claimAttributes.catalogueValuesFor(user)),
    // The groups claim, which is the one thing here that is not chosen per set:
    // all five carry it or none does — which is also why it is reported by ALL
    // THREE pages' replies rather than by the one it was written on. Its
    // settings are config.js's, so this is a report and there is no operation
    // beside it — POST /admin-api/config/set is the door, and a second one
    // would be a second store for one setting.
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

// The claims request being previewed, as the characters somebody typed. Capped
// because it is echoed and because it is parsed — and the cap is larger than
// the other echoed fields on this console for one reason: this one is a JSON
// document rather than a name, and a cap that truncated a legitimate request
// would produce a parse error that pointed at this service instead of at the
// request.
function claimsRequestParameter(query) {
  log.debug("Entering claimsRequestParameter().");
  const asked = String((query && query.request) || '').trim();
  log.debug("Leaving claimsRequestParameter().");
  return asked.slice(0, 2048);
}

// Somebody the directory actually holds, so the page shows real values on a
// fresh start rather than an invented person nobody can look up. The parameter
// wins where it is given; the cap is there because this string is echoed.
function vcPreviewUser(query) {
  log.debug("Entering vcPreviewUser().");
  const asked = String((query && query.user) || 'alice').trim();
  log.debug("Leaving vcPreviewUser().");
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

// The base URL of this service WITHOUT any realm prefix. Every URL this page
// prints is built from it, because a page read inside `acme` still has to be
// able to name `default`'s endpoints — and baseUrlOf() adds the ambient prefix
// by design.
function realmRootUrl(req) {
  log.debug("Entering realmRootUrl().");
  const withRealm = baseUrlOf(req);
  log.debug("Leaving realmRootUrl().");
  return withRealm.slice(0, withRealm.length - realms.currentPrefix().length);
}

// What a realm sets, as rows. `config.describe()` is not used here and the
// reason is worth a line: describing a setting means RESOLVING it, and
// resolving it answers for the realm that is ambient rather than for the realm
// being listed. So the raw value the realm carries is shown, beside what that
// setting is called — which is what a person checking a realm's configuration
// is actually reading.
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
  log.debug("Entering realmJson().");
  const prefix = realms.prefixOf(realm);
  const base = realmRootUrl(req) + prefix;
  log.debug("Leaving realmJson().");
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
    // Reading it MINTS it for a realm that has not signed anything yet, which
    // is a 2048-bit RSA generation and about a tenth of a second. That is
    // accepted deliberately: a console page that could not show a realm's key
    // identifier until something had used the realm would be showing a blank
    // for exactly the realm somebody had just created and was checking.
    kid: stsKeysFor.of(realm.id).kid,
    settings: realmSettingRows(realm),
    // The four a client asks for first, in this realm.
    endpoints: {
      openidConfiguration: base + '/.well-known/openid-configuration',
      authorizationServerMetadata: base +
                                   '/.well-known/oauth-authorization-server',
      jwks: base + '/oauth2/jwks',
      samlMetadata: base + '/saml2/metadata'
    }
  };
}

function realmsJson(req) {
  log.debug("Entering realmsJson().");
  // A REALM ADMINISTRATOR SEES THEIR OWN REALM (2026-09-14, #32). The registry
  // is the service's and so is the list of who else is on it; a realm
  // administrator's page lists the one row they administer.
  const gate = req ? gateStateFor(req) : null;
  const onlyRealm = gate && gate.authority === 'realm' ? gate.identityRealm
                                                       : '';
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
    realms: realms.list()
                  .filter(function (realm) {
                    return !onlyRealm || realm.id === onlyRealm;
                  })
                  .map(function (realm) { return realmJson(req, realm); }),
    support: realms.realmSupport()
  };
  log.debug("Leaving realmsJson(). " + out.realms.length + " realm(s).");
  return out;
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
  log.debug("Leaving tokenLifetimesJson(). " + settings.length +
            " setting(s).");
  return json;
}

// The setting's value in SECONDS, whatever unit its row is written in. Every
// comparison on this page — skew against lifetime, the warnings below — has to
// be made in one unit, and doing it at each comparison is how two of them come
// to disagree.
function samlAssertionSeconds(key) {
  log.debug("Entering samlAssertionSeconds().");
  const row = samlAssertionRowFor(key);
  const value = Number(config.value(key)) || 0;
  log.debug("Leaving samlAssertionSeconds().");
  return row && row.unit === 'min' ? value * 60 : value;
}

// The JSON view, answered by GET /admin/saml-assertions?format=json and by
// GET /admin-api/saml-assertions. Built here rather than in the route so the
// page and the API cannot come to describe different settings.
function samlAssertionsJson() {
  log.debug("Entering samlAssertionsJson().");
  const snapshot = stats.snapshot();
  const settings = SAML_ASSERTION_KEYS.map(function (key) {
    return config.describe(configSettingFor(key));
  });
  // Only the two SAML kinds. `artifacts.byKind` also carries Kerberos tickets
  // and verifiable credentials, and a page about assertions reporting those
  // would be answering a question nobody asked it.
  const kinds = SAML_ASSERTION_SETTINGS.filter(function (
      row) { return row.kind; })
    .map(function (row) {
      return snapshot.artifacts.byKind.filter(function (k) {
        return k.kind === row.kind;
      })[0] || { kind: row.kind, issued: 0, valid: 0, expired: 0, noExpiry: 0 };
    });
  const json = {
    // The effective numbers, flat, for a caller that wants the value and not
    // the provenance — and `windowS`, which is the thing a caller actually has
    // to reason about and which no single setting states: the whole width of
    // the window written into an assertion, skew included at both ends.
    assertions: {
      saml2LifetimeMin: config.value('saml2.assertionLifetimeMin'),
      saml11LifetimeMin: config.value('saml11.assertionLifetimeMin'),
      clockSkewS: config.value('saml.clockSkewS'),
      saml2WindowS: samlAssertionSeconds('saml2.assertionLifetimeMin') +
                    2 * samlAssertionSeconds('saml.clockSkewS'),
      saml11WindowS: samlAssertionSeconds('saml11.assertionLifetimeMin') +
                     2 * samlAssertionSeconds('saml.clockSkewS')
    },
    // WHICH OF THESE AN APPLICATION MAY OVERRIDE, AND WHAT THE ATTRIBUTE IS
    // CALLED. Read off the same table the form is drawn from, so a caller that
    // wants to write the exception does not have to be told the attribute names
    // in prose somewhere else — and so that a row added to that table cannot
    // reach the page without reaching this reply.
    perApplication: SAML_ASSERTION_SETTINGS.filter(function (row) {
      return row.field;
    }).map(function (row) {
      return { setting: row.key, attribute: row.field, profile: row.profile };
    }),
    settings: settings,
    // What is already out there, per profile. Counted against this service's
    // own clock with no allowance applied — the skew above is written INTO an
    // assertion rather than applied when one is read here, so an assertion this
    // calls expired is one whose stated NotOnOrAfter has passed.
    assertionsIssued: {
      held: snapshot.artifacts.held, forgotten: snapshot.artifacts.forgotten,
      cap: snapshot.artifacts.cap, byKind: kinds
    },
    now: snapshot.now
  };
  log.debug("Leaving samlAssertionsJson(). " + settings.length +
            " setting(s).");
  return json;
}

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
//   * the SURFACE, from scim.js through the reader slot — the endpoints, what
//     it deliberately does not do, and the things you can make fail. Written
//     once, in the module that implements them, and rendered here. See
//     setScimReader().
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
    // page that reported both as "off" would send somebody to the wrong
    // setting.
    installed: !!surface,
    enabled: surface ? surface.enabled : false,
    baseUrl: surface ? surface.baseUrl : null,
    specifications: surface ? surface.specifications :
                    ['RFC 7642', 'RFC 7643', 'RFC ' +
        '7644'],
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
    counters: counters,
    // The eighteen scim.* rows this page now edits, described. It answers the
    // question the rest of this reply cannot: not what the server does, but
    // where the value that decides it came from.
    settings: configSettingsJson('/admin/scim')
  };
  log.debug("Leaving scimJson(). " + counters.total + " request(s) counted.");
  return out;
}

// ---------------------------------------------------------------------------
// /admin/scim/monitor — WHAT THE PROVISIONING SURFACE IS ACTUALLY DOING.
//
// **IT IS UNDER MONITORING AND NOT UNDER PROTOCOLS**, which is the same filing
// decision `/admin/xacml/monitor` records and is made on the same test: where a
// page goes is decided by the QUESTION IT ANSWERS and never by the module that
// draws it or the path space it sits in. `/admin/scim` answers "what is this
// surface, and what will it do" — the schemes, the endpoints, the attribute
// mapping, the eighteen settings. This one answers "how much traffic is there,
// from whom, and how much of it is failing", which is the question somebody has
// when a provisioning client is misbehaving, and it is a monitoring question.
// It shares a path prefix with the protocol page because the path is where the
// module's other page is; `SECTIONS` is the only place placement is stated.
//
// ---------------------------------------------------------------------------
// ONE STORE, TWO VIEWS, AND THAT IS WHY THE TWO PAGES CANNOT DISAGREE.
//
// `/admin/scim` carries the headline counts already and goes on carrying them:
// a page about a surface with no evidence anything ever called it is a page
// about a hypothesis. What it does NOT carry is anything on this page below the
// tiles, and the division is deliberate rather than incidental — those two
// pages read `stats.scimSnapshot()` and `stats.scimMonitorSnapshot()`, which
// are two functions over ONE set of counters in `common/admin_stats.js`. There
// is no second tally anywhere and there must never be one: a second tally is a
// second answer to "how many SCIM calls have there been", and this repository
// has the same rule about that as it has about everything else it counts once.
//
// ---------------------------------------------------------------------------
// FOUR THINGS ON THIS PAGE ARE EASY TO MISREAD AND EACH IS SAID ON IT.
//
//   * **A CLIENT IS AN AUTHENTICATED PRINCIPAL, NOT A CONNECTION.** SCIM is
//     stateless HTTP — no session, no registration, nothing to be connected —
//     so the only honest reading of "how many clients" is how many distinct
//     names have successfully authenticated since this process started. The
//     figure never goes down, because a provisioning client that has stopped
//     calling looks exactly like one that is between calls.
//   * **A REFUSED CALLER IS NOT A CLIENT.** Basic and Digest both put a name on
//     the wire and the gate can still turn it away; those calls are counted
//     under `refused` and appear in no client row. Attributing traffic to an
//     identity this service declined to believe is the one mistake this page
//     could make that would matter.
//   * **THE OPERATION COLUMN DOES NOT TALLY WITH THE CALL TOTAL.** One `POST
//     /scim/v2/Bulk` carrying five creates is one `bulk` row AND five `create`
//     rows, because each of the five really is performed. `/admin/scim` already
//     says this about its own table and it is said again here rather than
//     cross-referenced, because a reader adding a column up is not going to
//     another page first.
//   * **A LATENCY IS ABSENT AND NOT ZERO WHERE NOTHING WAS MEASURED.** An
//     operation nothing has called shows `—`, never `0.0ms`, which would read
//     as a service answering instantly.
//
// ---------------------------------------------------------------------------
// NO RESET BUTTON, AND IT WAS REFUSED RATHER THAN FORGOTTEN.
//
// `admin_stats.js` exports `resetScimForTests()` and nothing on this console
// calls it. A console that could zero its own monitoring would make every
// number on this page a number somebody might have zeroed — and the durable
// record of what SCIM was asked to do is the audit log, which cannot be reset
// either. Same argument as `/admin/xacml/monitor`'s, made again rather than
// cited, because the second refusal is not cheaper than the first.
// ---------------------------------------------------------------------------
function scimMonitorJson(req) {
  log.debug("Entering scimMonitorJson().");
  const counters = stats.scimMonitorSnapshot();
  const surface = scimReader ? scimReader(req) : null;
  const out = {
    // Distinguished from `enabled` deliberately, exactly as scimJson() does it:
    // a process whose scim.js never loaded has no /scim routes at all, where
    // one with scim.enabled false has routes answering 501. Reporting both as
    // "off" would send a reader to the wrong setting — and on THIS page it
    // would also make a call total of zero mean two different things.
    installed: !!surface,
    enabled: surface ? surface.enabled : false,
    baseUrl: surface ? surface.baseUrl : null,
    // THE SCHEME VOCABULARY, so that the by-scheme table can draw the ones at
    // zero. It is scim_auth.js's own table by way of scim.js's description(),
    // for the reason admin_stats.js's comment on `byAuthScheme` gives: the
    // counters are a plain tally and this module cannot require the module
    // that owns the list, so the ZEROES are supplied by the reader. A scheme
    // that is turned off and has never been used is the most interesting row
    // on that table for somebody asking why a client cannot get in.
    schemes: surface && surface.authentication
      ? surface.authentication.schemes : [],
    authRequired: !!(surface && surface.authentication &&
                     surface.authentication.required),
    // What SCIM wrote, which is the other half of "is provisioning working".
    // It is not a counter — it is the directory counted now — and it is here
    // because a page reporting 400 successful creates beside a directory
    // holding three people is reporting something worth knowing.
    store: surface ? surface.store : null,
    counters: counters
  };
  log.debug("Leaving scimMonitorJson(). " + counters.calls + " request(s), " +
            counters.authentication.distinct + " client(s).");
  return out;
}

// One row of the mapping, as the page and the API both want it. The `note` is
// carried through because several of them are the whole reason the row is not
// obvious — `groups` being read-only, `active` deactivating nobody, `manager`
// being passed through rather than resolved.
// ONE PROJECTION, AND IT IS scim_map.js's SINCE 2026-09-06.
//
// This function used to build the row itself, and `scim.js`'s `description()`
// built a DIFFERENT one for `GET /scim` — the same table, published by one
// service at two endpoints, describing itself with different members. Nothing
// failed, because nothing read either of them; that changed when a job started
// building SCIM resources out of the published mapping rather than out of a
// copy, and needed `type` and `parent` that neither projection carried.
//
// It is kept as a named function rather than passing `scimMap.describeRow`
// straight to `.map()`: `Array.prototype.map` hands the callback an INDEX as
// its second argument, and a projection that later grew a second parameter
// would start receiving row numbers.
function scimMappingRow(row) {
  log.debug("Entering scimMappingRow().");
  log.debug("Leaving scimMappingRow().");
  return scimMap.describeRow(row);
}

// ---------------------------------------------------------------------------
// THE SECOND BATCH (2026-09-12), and it is here because a false positive was
// keeping it on the console.
//
// The first pass classified these as markup-reaching and left them behind. They
// are not: the taint was `page` — which is this console's HTML SHELL and also
// the commonest local variable name in the file it came from, a page NUMBER —
// so `pagingOf(query, total)` computing a `page` read as a call to the shell.
// Six views and the nine helpers they share were held back by a name collision.
//
// The lesson is in the analysis rather than the code: a reachability check over
// a file this size has to know a local from a module-scope name, or it reports
// that everything renders and nothing can move.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Paging.
//
// There is no script on these pages — `script-src 'none'`, see the shell above
// — so paging is links and a query parameter and nothing else. That is also why
// every number is settled server-side before the markup is built: a page that
// renders "page 4 of 2" and leaves the browser to sort it out has nothing to
// sort it out with.
//
// Both parameters are read defensively. `?page=abc`, `?page=-3` and `?page=999`
// all have to land somewhere sensible, because they arrive from hand-edited
// URLs and from a stale bookmark taken when the list was longer — a revocation
// sweep can shorten it between two clicks, and an out-of-range page must be the
// last page rather than an empty table that reads as "nothing matched".
//
// ONE PAGE CAN HOLD SEVERAL LISTS, and that is what `options.name` is for. The
// three list views have one list each and read the bare `page`, which is what
// they have always done and what every bookmark and every caller of the
// management API already says. The two DRILL-DOWNS have five and two: a users
// page holds its sessions, the tokens under each of them, the tokens on ended
// sessions, the tokens on no session and the artifacts, and a group page holds
// its members and the entries claiming it. A single `page` cannot serve those —
// clicking "next" under the artifacts would silently advance the sessions above
// it — so each list gets a page parameter named after itself and `per` stays
// shared, because "rows per table" is one choice a reader makes for the whole
// page rather than seven.
//
// `per` is shared for a second reason worth stating: it is the parameter with
// the cap on it, and one capped parameter is one place the cap can be got
// right.
// ---------------------------------------------------------------------------
function pagingOf(query, total, options) {
  log.debug("Entering pagingOf().");
  const opts = options || {};
  const param = opts.name ? opts.name + 'Page' : 'page';
  log.debug("Entering pagingOf(). total=" + total + ", param=" + param);
  const askedPer = parseInt(String(query.per || ''), 10);
  const perPage = (isFinite(askedPer) && askedPer > 0)
    ? Math.min(askedPer, MAX_ROWS)
    : (opts.defaultPer || DEFAULT_PER_PAGE);
  // At least one page even when nothing matched, so "page 1 of 1" is what an
  // empty list says rather than "page 1 of 0".
  const pages = Math.max(1, Math.ceil(total / perPage));
  const askedPage = parseInt(String(query[param] || ''), 10);
  const page = Math.min(Math.max(isFinite(askedPage) ? askedPage : 1, 1),
                        pages);
  const offset = (page - 1) * perPage;
  log.debug("Leaving pagingOf(). page=" + page + " of " + pages + ", perPage=" +
            perPage + ".");
  return {
    page: page, perPage: perPage, pages: pages, offset: offset, total: total,
    // 1-based and inclusive, for the "rows 51–100 of 312" line. Zero and zero
    // when nothing matched, which is what the line then has to say.
    firstRow: total ? offset + 1 : 0,
    lastRow: Math.min(offset + perPage, total),
    // Which query parameter this list moves on, carried on the result rather
    // than passed to pageNavPair() a second time: the one place that decides
    // the name is the one place that builds the links, so a control cannot come
    // to page a list other than the one it is drawn under.
    param: param,
    // What a row of this list IS, for the summary line. Seven controls on one
    // page all saying "rows" would leave the reader counting tables to work out
    // which number belongs to which.
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
  log.debug("Entering pagingJson().");
  log.debug("Leaving pagingJson().");
  return {
    page: pg.page, pages: pg.pages, perPage: pg.perPage,
    firstRow: pg.firstRow, lastRow: pg.lastRow, total: pg.total
  };
}

// The slice, with the paging that produced it. Written once because seven lists
// across the two drill-downs do exactly this and a hand-written eighth would be
// the one that forgets to slice.
function pagedRows(query, rows, options) {
  log.debug("Entering pagedRows().");
  const pg = pagingOf(query, rows.length, options);
  log.debug("Leaving pagedRows().");
  return { paging: pg, shown: rows.slice(pg.offset, pg.offset + pg.perPage) };
}

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
  // WHICH SESSION A CREDENTIAL WAS ISSUED ON (2026-09-04). Every row of
  // /admin/sessions links here with it set, because "what came out of this
  // session" was a question this table held the answer to and could not be
  // asked. It is an EXACT match on the session id and not a search: the id is
  // what a token records, and a substring of one is not a session.
  //
  // A credential with NO session behind it — the two direct grants, a
  // pre-authorized code, a token exchange, every assertion and every ticket —
  // is therefore filtered out rather than shown, which is right: it was not
  // issued on that session, and the empty answer is the honest one for a
  // session nothing was issued on.
  const wantedSession = String(query.session || '');
  // Not tokenList(), and since 2026-09-05 not issuedList() either: this page
  // lists what came back in ONE REPLY. Every JWT, every SAML assertion (whether
  // WS-Trust or WS-Federation issued it), every Kerberos ticket and every SVID
  // is still here — grouped where the protocol grouped them, which is OAuth 2.0
  // and OIDC and nowhere else. See issuedSetRow() above for the argument, and
  // stats.issuedSets() for the grouping, which is decided by a set id the
  // ISSUER stated rather than by anything this file could infer from these
  // rows.
  const all = stats.issuedSets();
  // EVERY FILTER MATCHES A SET WHEN ANY MEMBER MATCHES, and that is the one
  // thing about this page a reader has to be told rather than left to work out.
  // Asking for `kind=id_token` answers with the SETS that contain an ID Token —
  // showing the access token and the refresh token beside it, which is the
  // reply that ID Token arrived in and the thing somebody filtering for it is
  // looking at. A filter that hid the neighbours would be the old
  // per-credential table wearing this one's clothes, and the note under the
  // form says so on the page.
  //
  // `family` and `session` are per-set facts in practice — every member of a
  // set shares them — but they are asked of the members for the same reason, so
  // that one rule covers all four and a family that starts grouping later needs
  // no second one.
  const matches = function (set, test) {
    log.debug("Entering matches().");
    log.debug("Leaving matches().");
    return set.members.some(test);
  };
  const filtered = all.filter(function (set) {
    if (wantedFamily &&
        !matches(set,
                 function (r) {
                   return r.family === wantedFamily;
                 })) return false;
    if (wantedKind &&
        !matches(set,
                 function (r) { return r.kind === wantedKind; })) return false;
    if (wantedState &&
        !matches(set,
                 function (r) {
                   return r.state === wantedState;
                 })) return false;
    if (wantedSession &&
        !matches(set,
                 function (r) {
                   return String(r.sessionId || '') === wantedSession;
                 })) return false;
    return true;
  });
  // Filter first, then page: paging a list and then filtering it would give a
  // page 2 whose length depends on what page 1 happened to contain.
  //
  // PAGED BY SET AND NOT BY CREDENTIAL, which is what makes a page of this
  // table a whole number of replies. Twenty rows is now twenty issuances and
  // somewhere between twenty and sixty credentials, and the line under the
  // table says both — paging by credential would put the access token of one
  // reply at the bottom of page 1 and its refresh token at the top of page 2,
  // which is precisely the reassembly-by-eye this change exists to remove.
  const paging = pagingOf(query, filtered.length);
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  // How much of each family is held, for the line under the table. Counted in
  // CREDENTIALS rather than sets, because "612 JWTs" is the figure the metrics
  // page prints and two pages of one console disagreeing about how much has
  // been issued is worse than this line being in different units from the one
  // above it — which it says. Counted from this list rather than taken from the
  // snapshot, because the snapshot's artifact count includes the OID4VCI
  // credentials this page does not list.
  const heldByFamily = {};
  let heldCredentials = 0;
  all.forEach(function (set) {
    set.members.forEach(function (record) {
      heldByFamily[record.family] = (heldByFamily[record.family] || 0) + 1;
      heldCredentials += 1;
    });
  });
  const countMembers = function (sets) {
    log.debug("Entering countMembers().");
    log.debug("Leaving countMembers().");
    return sets.reduce(function (n, set) { return n + set.size; }, 0);
  };
  const matchedCredentials = countMembers(filtered);
  const shownCredentials = countMembers(shown);
  // The flatten of what this page holds, in the order the table draws it: each
  // set's members in issuance order, sets newest first. It is DERIVED from
  // `shown` rather than filtered again out of issuedList(), which is the whole
  // reason the two can be published side by side — a second walk of the
  // register is how a table and the JSON beside it come to disagree about a
  // revocation that happened in between.
  const shownRecords = shown.reduce(function (out, set) {
    return out.concat(set.members);
  }, []);
  log.debug("Leaving tokensView(). " + shown.length + " set(s) of " +
            filtered.length + ", holding " + shownCredentials + " " +
                "credential(s).");
  return {
    wantedFamily: wantedFamily, wantedKind: wantedKind,
    wantedState: wantedState, wantedSession: wantedSession,
    all: all, filtered: filtered, paging: paging, shown: shown,
    heldByFamily: heldByFamily, heldCredentials: heldCredentials,
    matchedCredentials: matchedCredentials, shownCredentials: shownCredentials,
    json: {
      // IN CREDENTIALS. `held` has meant this since the day the page had a
      // total on it, and a resource that quietly changed its unit under a name
      // nobody had to re-read would be the worst kind of breaking change — so
      // the SET counts are new members beside it rather than a new meaning for
      // an old one.
      held: heldCredentials,
      heldSets: all.length,
      // IN SETS, both of them, because sets are what this resource now lists
      // and what its paging counts. The credential figures are beside them.
      matched: filtered.length, matchedCredentials: matchedCredentials,
      shown: shown.length, shownCredentials: shownCredentials,
      heldByFamily: stats.ISSUED_FAMILIES.reduce(function (out, entry) {
        out[entry.family] = heldByFamily[entry.family] || 0;
        return out;
      }, {}),
      filter: { family: wantedFamily || null, kind: wantedKind || null,
                state: wantedState || null, session: wantedSession || null },
      // The clamped values, not what was asked for: `?page=999` on a two-page
      // list reports page 2, which is the page whose rows are in the reply.
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      families: stats.ISSUED_FAMILIES,
      revocableKinds: stats.REVOCABLE_KINDS,
      revokedCount: stats.revokedCount(),
      // WHAT THIS RESOURCE LISTS SINCE 2026-09-05: one entry per issuance,
      // each carrying its members. A caller that wants the credentials
      // ungrouped has `issued` below and need not walk two levels.
      sets: shown,
      // `issued` rather than `tokens`, because the array is no longer only
      // tokens and a key that says otherwise is the kind of thing a test
      // asserts against once and then trusts. Nothing outside this repository
      // read the old name.
      //
      // IT IS THE FLATTEN OF `sets` AND NOT A SECOND LIST. Same rows, same
      // order, ungrouped — so every caller written against the per-credential
      // shape still reads what it read, and the two cannot come to disagree
      // because one is built out of the other. What DID change under it is the
      // paging: a page is now a whole number of sets, so this array is between
      // `perPage` and three times it rather than exactly `perPage`.
      issued: shownRecords
    }
  };
}

// The protocols this list can hold, for the filter. Built from the rows
// themselves rather than written down, because the set depends on what people
// have signed in THROUGH — `session.via` is a federation relationship's name on
// a federated sign-in — and a hand-written list would be a select with entries
// that match nothing beside sign-ins it cannot name.
function sessionProtocolsIn(rows) {
  log.debug("Entering sessionProtocolsIn().");
  const out = [];
  rows.forEach(function (row) {
    if (row.protocol && out.indexOf(row.protocol) < 0) {
      out.push(row.protocol);
    }
  });
  out.sort();
  log.debug("Leaving sessionProtocolsIn(). " + out.length + " protocol(s).");
  return out;
}

// One route, two answers, and the choice is here rather than in the route so
// that GET /admin-api/sessions makes the same one — the rule every view in this
// file follows, and the reason the management API cannot come to disagree with
// the page about who is signed in.
function sessionsView(req) {
  log.debug("Entering sessionsView().");
  const query = req.query || {};
  if (!logoutReader) {
    log.debug("Leaving sessionsView(). No logout reader.");
    return { installed: false, all: [], protocols: [], shown: [], paging: null,
             wantedText: '', wantedProtocol: '',
             json: { installed: false, held: 0, matched: 0, shown: 0,
                     sessions: [],
                     note: 'logout/logout.js is not loaded in this process, ' +
                           'so there is no reader for what is live.' } };
  }
  const all = logoutReader.liveSessions();
  const wantedText = queryOne(query, 'q').trim();
  const wantedProtocol = queryOne(query, 'protocol').trim();
  // Filter first, then page — pagingOf()'s rule, and for its reason.
  const filtered = all.filter(function (row) {
    if (wantedProtocol && row.protocol !== wantedProtocol) return false;
    return chooserMatches([row.username, row.sub, row.handle, row.key,
                           row.kind, row.protocol], wantedText);
  });
  const paging = pagingOf(query, filtered.length, { noun: 'sessions' });
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  const byKind = {};
  all.forEach(function (row) {
    byKind[row.family] = (byKind[row.family] || 0) + 1;
  });
  // THE UNAUTHENTICATED ONES, AS A LIST OF THEIR OWN (2026-09-05).
  //
  // NOT FILTERED AND NOT PAGED, deliberately, where the table above it is
  // both. The two lists answer different questions: the main one is *what is
  // live*, which is long and needs narrowing, and this one is *is anybody in
  // here without having signed in*, which is a question about the whole
  // service and would be answered wrongly by a filter somebody had left set.
  // A search box that could hide one of these rows would make the section
  // worse than not having it.
  //
  // It is a SECTION rather than a column on the table above because the answer
  // is almost always "none", and a column that is the same on every row for
  // weeks at a time stops being read. A section that is empty says so in one
  // line and a section with rows in it is the thing somebody notices.
  const unauthenticated = all.filter(function (row) {
    return row.authenticated === false;
  });
  log.debug("Leaving sessionsView(). " + shown.length + " row(s) of " +
            filtered.length + " (" + all.length + " live).");
  return {
    installed: true, all: all, filtered: filtered, shown: shown,
    paging: paging, byKind: byKind, unauthenticated: unauthenticated,
    protocols: sessionProtocolsIn(all),
    wantedText: wantedText, wantedProtocol: wantedProtocol,
    json: {
      installed: true,
      held: all.length, matched: filtered.length, shown: shown.length,
      heldByKind: byKind,
      // Rule 7: the page grew a section, so the API grew the same answer. The
      // COUNT and the ROWS both, because "are there any" and "which ones" are
      // the two things a caller asks and deriving the first from the second
      // would make an empty list and an absent field look alike.
      unauthenticatedHeld: unauthenticated.length,
      unauthenticatedSessions: unauthenticated.map(function (row) {
        return { id: row.id, family: row.family, username: row.username,
                 sub: row.sub, protocol: row.protocol, sessionId: row.sessionId,
                 startedAt: row.startedAt, expiresAt: row.expiresAt,
                 carries: row.carries, key: row.key };
      }),
      filter: { q: wantedText || null, protocol: wantedProtocol || null },
      // The clamped values, not what was asked for: `?page=999` on a two-page
      // list reports page 2, which is the page whose rows are in the reply.
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      at: Date.now(),
      // The rules, once, beside the rows rather than repeated on each of them:
      // a caller reading `expiresAt` needs to know which of the three
      // arithmetics produced it, and every row already says which family it is.
      expiryRules: logoutReader.SESSION_EXPIRY_RULES || {},
      sessions: shown
    }
  };
}

// ---------------------------------------------------------------------------
// THE ERROR CODES, AS /admin/error-codes AND GET /admin-api/error-codes DRAW
// THEM (2026-09-12).
//
// The table is `common/error_codes.js`'s and nothing here restates it: this is
// the table FILTERED and PAGED, with one column the documentation page cannot
// have — how many rows in this realm's audit log carry each code right now.
// That column is what makes the page worth having beside `docs/error-codes.md`:
// the page answers *what does STS-FED-0012 mean* and *which failures has this
// service actually been producing*, and only a running service can answer the
// second.
//
// **THE COUNT IS OF THE HELD AUDIT LOG IN THIS REALM**, the same rows
// `/admin/audit` lists, so it drops as that ring's cap discards the oldest and
// it is zero for a code logged only as a line (`tag()`) — a startup refusal, or
// anything the remote PEP container records. The page says so rather than
// letting a zero read as "never happens".
//
// **A CODE ON A ROW THAT THE TABLE DOES NOT HOLD IS REPORTED**, not dropped:
// `mark()` and `audit()` both record an unregistered code as given, precisely
// so that the one row saying the table is incomplete survives, and this is the
// page somebody would look for it on.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE USED-ASSERTION HISTORY — every RFC 7523 JWT and RFC 7522 SAML assertion
// this realm has accepted and that has not yet expired (2026-09-13).
//
// **A PROMISE, WHICH ALMOST NO VIEW HERE IS**, because on a postgres store the
// history is not in this process at all: the database IS the history, so that
// every process against it agrees, and reading it is a query. The page and the
// operation both await this one function, so they cannot disagree about a
// row.
//
// **IT IS READ-ONLY AND MUST STAY SO.** Forgetting a row would make that
// assertion acceptable again while it is still valid, which is the one thing
// the history exists to prevent; the only thing that removes a row is the
// assertion expiring. `common/used_assertions.js` argues the rest.
//
// The page is clamped the way `pagingOf()` clamps every list here, and a page
// asked for beyond the end is re-read at the last page rather than drawn empty
// under a line saying rows matched.
// ---------------------------------------------------------------------------
function usedAssertionsView(query) {
  log.debug("Entering usedAssertionsView().");
  const q = query || {};
  const filter = { q: String(q.q || '').trim(), format: String(q.format || ''),
                   use: String(q.use || ''), state: String(q.state || '') };
  const asked = pagingOf(q, Number.MAX_SAFE_INTEGER);
  log.debug("Leaving usedAssertionsView().");
  return usedAssertions.list(Object.assign({}, filter, {
    limit: asked.perPage, offset: asked.offset
  })).then(function (first) {
    const paging = pagingOf(q, first.matched);
    if (paging.offset === asked.offset) {
      return { page: first, paging: paging };
    }
    return usedAssertions.list(Object.assign({}, filter, {
      limit: paging.perPage, offset: paging.offset
    })).then(function (again) {
      return { page: again, paging: paging };
    });
  }).then(function (read) {
    const summary = usedAssertions.summary();
    const page = read.page;
    const json = Object.assign({
      store: summary.store,
      persistent: summary.persistent,
      atomicAcrossProcesses: summary.atomicAcrossProcesses,
      storeNote: summary.why,
      cap: summary.cap,
      live: page.live,
      matched: page.matched,
      shown: page.rows.length,
      filter: page.filter,
      formats: usedAssertions.FORMATS,
      uses: usedAssertions.USES,
      states: usedAssertions.STATES,
      rows: page.rows
    }, pagingJson(read.paging));
    return { json: json, rows: page.rows, paging: read.paging,
             filter: page.filter, summary: summary, live: page.live };
  });
}

function errorCodesView(query) {
  log.debug("Entering errorCodesView().");
  const wantedSubsystem = String(query.subsystem || '').trim().toUpperCase();
  const wantedText = String(query.q || '').trim();
  const wantedSeen = ['1', 'true', 'on', 'yes'].indexOf(
    String(query.seen || '').toLowerCase()) >= 0;
  const needle = wantedText.toLowerCase();

  // One pass over the held rows. `lastSeenAt` is the newest because list() is
  // newest first, so the first sighting of a code is its latest.
  const seen = {};
  auditLog.list().forEach(function (row) {
    const code = row && row.errorCode;
    if (!code) return;
    if (!seen[code]) {
      seen[code] = { count: 0, lastSeenAt: row.at || 0 };
    }
    seen[code].count++;
  });

  const subsystems = errorCodes.SUBSYSTEMS.map(function (s) {
    const rows = errorCodes.CODES.filter(function (r) {
      return errorCodes.subsystemOf(r.code) === s.id;
    });
    let seenRows = 0;
    rows.forEach(function (r) {
      if (seen[r.code]) seenRows += seen[r.code].count;
    });
    return { id: s.id, prefix: 'STS-' + s.id, label: s.label, where: s.where,
             what: s.what, codes: rows.length, seen: seenRows };
  });

  const all = errorCodes.CODES.map(function (r) {
    const sighting = seen[r.code];
    return { code: r.code, subsystem: errorCodes.subsystemOf(r.code),
             summary: r.summary, spec: r.spec || '', retired: !!r.retired,
             seen: sighting ? sighting.count : 0,
             lastSeenAt: sighting ? sighting.lastSeenAt : 0 };
  });

  const filtered = all.filter(function (r) {
    if (wantedSubsystem && r.subsystem !== wantedSubsystem) return false;
    if (wantedSeen && !r.seen) return false;
    // One box over the three columns a reader would search: a code pasted out
    // of a log line, a word from what failed, or a protocol's own error name.
    if (needle && (r.code + ' ' + r.summary + ' ' + r.spec).toLowerCase()
                    .indexOf(needle) < 0) return false;
    return true;
  });

  const unregisteredSeen = Object.keys(seen).filter(function (code) {
    return !errorCodes.isKnown(code);
  }).sort().map(function (code) {
    return { code: code, seen: seen[code].count,
             lastSeenAt: seen[code].lastSeenAt };
  });

  const paging = pagingOf(query, filtered.length);
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  let heldWithCode = 0;
  Object.keys(seen)
        .forEach(function (code) { heldWithCode += seen[code].count; });
  log.debug("Leaving errorCodesView(). " + shown.length + " of " +
            filtered.length + " code(s).");
  return {
    wantedSubsystem: wantedSubsystem, wantedText: wantedText,
    wantedSeen: wantedSeen, paging: paging, shown: shown, filtered: filtered,
    subsystems: subsystems, unregisteredSeen: unregisteredSeen,
    json: {
      registered: all.length,
      retired: all.filter(function (r) { return r.retired; }).length,
      subsystemCount: subsystems.length,
      matched: filtered.length, shown: shown.length,
      // What the audit log held when this was drawn, so a zero can be read
      // against how much there was to find it in.
      auditRowsHeld: auditLog.summary().held,
      auditRowsWithCode: heldWithCode,
      distinctCodesSeen: Object.keys(seen).length,
      filter: { subsystem: wantedSubsystem || null, q: wantedText || null,
                seen: wantedSeen || null },
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      documentation: 'docs/error-codes.md',
      neverSentToClients: true,
      subsystems: subsystems,
      unregisteredSeen: unregisteredSeen,
      codes: shown
    }
  };
}

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
  // An error code, or the front of one: a whole code is one condition and
  // `STS-OAUTH` is a whole subsystem. A PREFIX rather than a substring, so
  // `STS-OAUTH` cannot match inside `STS-XOAUTH-…` if such a subsystem is ever
  // added — the codes are a hierarchy and the match reads them as one.
  const wantedCode = String(query.code || '').trim().toUpperCase();
  const all = auditLog.list();
  const needle = wantedText.toLowerCase();
  const actorNeedle = wantedActor.toLowerCase();
  const filtered = all.filter(function (row) {
    if (wantedCategory && row.category !== wantedCategory) return false;
    if (wantedAction && row.action !== wantedAction) return false;
    if (wantedOutcome && row.outcome !== wantedOutcome) return false;
    if (wantedCode && String(row.errorCode || '').indexOf(wantedCode) !== 0) {
      return false;
    }
    // Substring rather than equality, and case-insensitively, because the actor
    // on a directory row may be the console key (`alice`) while the one on a
    // Kerberos row arrived as `alice@STS.MOCK` — the collapse to one key is
    // done where an identity is normalised and cannot be done for a row whose
    // actor is a bind DN. A substring finds the person either way.
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
  // same reason: paging a list and then filtering it gives a page 2 whose
  // length depends on what page 1 happened to hold.
  const paging = pagingOf(query, filtered.length);
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  const summary = auditLog.summary();
  log.debug("Leaving auditView(). " + shown.length + " row(s) of " +
            filtered.length + ".");
  return {
    wantedCategory: wantedCategory, wantedAction: wantedAction,
    wantedOutcome: wantedOutcome, wantedActor: wantedActor,
    wantedText: wantedText, wantedCode: wantedCode,
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
                q: wantedText || null, code: wantedCode || null },
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
      const hay = [row.initial.key, row.initial.presented,
                   row.initial.application,
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
  // DELEGATION_PER_PAGE rather than the console-wide fifty, and it is passed
  // HERE rather than at the page, so that `GET /admin-api/delegation` and the
  // page it mirrors agree about what one page of acts is. A caller walking the
  // API with `?page=` and a reader clicking `next ›` must not be reading two
  // different pagings of one list.
  const paging = pagingOf(query, filtered.length,
                          { noun: 'acts', defaultPer: DELEGATION_PER_PAGE });
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  const summary = delegation.summary();
  // The chains of what MATCHED rather than of everything held: a reader who has
  // filtered to one person wants that person's chains, and a count that ignored
  // the filter would disagree with the table under it.
  const chains = delegation.chainList(filtered);
  // THE PICTURE'S MODEL, BUILT HERE AND NOT IN THE ROUTE THAT DRAWS IT, for the
  // reason the whole of this function exists: /admin/delegation/map, this
  // page's ?format=json and GET /admin-api/delegation must all be describing
  // the same graph, and three calls to delegation.graph() with three ideas
  // about which acts to pass it would be three answers that each looked right
  // alone. Of the matched acts rather than the paged ones — a diagram of one
  // page of a list is a diagram of the pagination.
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
    wantedType: wantedType, wantedMode: wantedMode,
    wantedOutcome: wantedOutcome,
    wantedProtocol: wantedProtocol, wantedText: wantedText,
    all: all, filtered: filtered, paging: paging, shown: shown,
    summary: summary, chains: chains, graph: graph, policy: policy,
    applications: applicationsInvolved,
    json: {
      held: summary.held,
      // AND HOW MANY PROCESSES THAT IS, beside how many of them are this
      // one's. `held` is a fan-in across every request worker since
      // 2026-09-11; a client that compared it with `recorded` below without
      // these two would have no way to see why the second is smaller.
      heldHere: summary.heldHere, processes: summary.processes,
      // Everything ever recorded and everything dropped, both, because `held`
      // alone reads as "this is all there was" the moment the cap has bitten.
      // BY THIS PROCESS — see the store's own comment: there is no counter
      // store to fan in and inventing one to make the numbers match would be a
      // store nothing else reads.
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
                outcome: wantedOutcome || null,
                protocol: wantedProtocol || null,
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
      // an SVG, which is the only way a drawing can be kept honest from
      // outside. It is a strictly different shape from `chains` and not a
      // second copy of it: a chain has three parties and therefore up to TWO
      // edges, and the boxes are SHARED between chains, which is the whole
      // reason to draw one.
      graph: graph,
      // The configured policy: who MAY delegate to whom, and the account flags
      // that decide what delegation can do to somebody. Kerberos only, because
      // it is the only family here that polices this at all.
      policy: policy
    }
  };
}

// One group as a REPLY carries: what it is and how big, and not the rows.
//
// The rows are on the group's own page and in its own `?format=json`. A list of
// groups that carried every grant would repeat the whole register once per
// group in the worst case — a caller asking *what is joined to what* would be
// handed the answer to a question they did not ask, and the reply would grow
// with the square of the register on exactly the service where that matters.
function clusterSummary(group) {
  log.debug("Entering clusterSummary().");
  log.debug("Leaving clusterSummary().");
  return { key: group.key, members: group.members, counts: group.counts };
}

// THE GROUPINGS AS A REPLY, AND THE ONE FUNCTION BOTH DOORS ONTO THEM GO
// THROUGH.
//
// `GET /admin-api/permissions/groups` calls it and so does
// /admin/delegation/cluster's own `?format=json`, for the reason
// `delegationView()` and `permissionsView()` both give: two hand-built copies
// of one object is precisely the drift this console's own text keeps warning
// about, and it is invisible — each looks right alone and neither ever sees the
// other.
//
// `view` is an optional `permissionsView()` already in hand. The route has one
// because it is drawing the page from it; the management API has not and this
// function makes its own. Passing it is what keeps a page's markup and its JSON
// describing ONE read of `ou=applications` rather than two taken a few
// milliseconds apart — which on a register somebody is editing is the
// difference between a table and a picture that agree and two that nearly do.
//
// **`application` DECIDES THE SHAPE and there is only one operation**, because
// the two are the same question at two scales: without it, every group with its
// counts and none of its rows; with it, the ONE group that application is in,
// with its grants, its permissions and the graph the picture is drawn from.
// An application this register has never heard of is `group: null` and a 200 —
// having no permissions configured is the ordinary state of most entries in
// the registry, and it is a fact rather than an error.
function permissionGroupsView(query, view) {
  log.debug("Entering permissionGroupsView().");
  const permissions = view || permissionsView();
  const groups = permissions.clusters;
  const asked = queryOne(query, 'application').trim();

  if (asked) {
    const group = appPermissions.clusterFor(asked, groups);
    // The SAME paging the page's own grants table uses, by the same name, so
    // that a caller reading `?format=json` off a page they are looking at gets
    // the rows they can see. `graph()` of an absent group is an empty graph
    // rather than a null, because every caller of this member hands it to a
    // renderer and a renderer takes a graph.
    const grantPage = pagedRows(query, group ? group.grants : [],
                                { name: 'groupGrants', noun: 'grants' });
    const permissionPage = pagedRows(query, group ? group.permissions : [],
                                     { name: 'groupPermissions',
                                       noun: 'permissions' });
    const answer = {
      application: asked,
      group: group ? clusterSummary(group) : null,
      grants: grantPage.shown,
      grantsPaging: pagingJson(grantPage.paging),
      permissions: permissionPage.shown,
      permissionsPaging: pagingJson(permissionPage.paging),
      graph: appPermissions.graph(group ? group.grants : []),
      counts: groups.counts
    };
    log.debug("Leaving permissionGroupsView(). " +
              (group ? group.counts.applications + " application(s) in the " +
                                                   "group."
                     : "Nothing configured names that."));
    return answer;
  }

  const groupPage = pagedRows(query, groups.clusters,
                              { name: 'groups', noun: 'groups' });
  const answer = {
    application: null,
    groups: groupPage.shown.map(clusterSummary),
    counts: groups.counts,
    paging: pagingJson(groupPage.paging)
  };
  log.debug("Leaving permissionGroupsView(). " + groups.counts.clusters +
            " group(s), " + groupPage.shown.length + " on this page.");
  return answer;
}

// One query parameter, first-wins. Express hands back an array when a parameter
// is repeated, and String() on one is "a,b" — a search nothing matches, reached
// by a link somebody clicked twice. The same rule pageParamsOf() applies.
function queryOne(query, key) {
  log.debug("Entering queryOne().");
  const raw = (query || {})[key];
  const value = Array.isArray(raw) ? raw[0] : raw;
  log.debug("Leaving queryOne().");
  return value === undefined || value === null ? '' : String(value);
}

// Does one catalogue entry match what was typed? Case-insensitive, and over
// EVERY spelling the catalogue holds rather than the one it shows: an
// application arrives as `HTTP/backend@EXAMPLE.COM` and as `HTTP/backend`, a
// person as `alice`, as `alice@STS.MOCK` and as `urn:uuid:<entryUUID>`, and
// each chooser draws one of them. A reader searching for a name they pasted out
// of the acts table four inches up the page is pasting the OTHER one about half
// the time, and a search that answers "nothing matches" to a string printed on
// the same page is worse than no search at all.
// How many results a chooser pane shows at a time. One number for the console
// (chooserPane()) and for the replies that page the same list, so a page and
// its resource cannot come to show different twenties.
const CHOOSER_HITS = 20;

function chooserMatches(names, wanted) {
  log.debug("Entering chooserMatches().");
  if (!wanted) {
    log.debug("Leaving chooserMatches().");
    return true;
  }
  const needle = wanted.toLowerCase();
  log.debug("Leaving chooserMatches().");
  return (names || []).some(function (name) {
    return String(name == null ? '' : name).toLowerCase().indexOf(needle) >= 0;
  });
}

// ---------------------------------------------------------------------------
// WHAT A CLAIMS REQUEST WOULD RETURN, for the person being previewed.
//
// Built by oauth2.js's parseClaimsRequest() and requestedClaimsOf() — the two
// functions the UserInfo endpoint itself calls — rather than by a second reader
// of section 5.5 written for this page. The rule is claim_attributes.js's and
// is not new here: a preview that agreed with the page and disagreed with the
// endpoint would be worse than no preview at all, and section 5.5 is exactly
// the kind of thing two implementations would come to disagree about (is `{}`
// the same as `null`? does an unknown top-level member refuse?).
//
// A MALFORMED REQUEST IS SHOWN AS AN ERROR AND IS NOT AN ERROR ON THE PAGE. The
// endpoint answers `invalid_request` for the same string, so what this shows is
// the refusal a client would get — which is the thing somebody is here to see.
// ---------------------------------------------------------------------------
function claimsRequestPreview(previewUser, raw) {
  log.debug("Entering claimsRequestPreview(). user=" + previewUser);
  if (!raw) {
    log.debug("Leaving claimsRequestPreview(). Nothing was asked for.");
    return { asked: false };
  }
  const parsed = oauth2.parseClaimsRequest(raw);
  if (parsed.error) {
    log.debug("Leaving claimsRequestPreview(). " + parsed.error);
    return { asked: true, ok: false, error: parsed.error, request: raw };
  }
  const answer = oauth2.requestedClaimsOf(parsed.claims, 'userinfo',
                                          previewUser,
                                          userFor(previewUser));
  log.debug("Leaving claimsRequestPreview(). " + answer.report.length + " " +
      "claim(s) resolved.");
  return { asked: true, ok: true, request: raw, parsed: parsed.claims,
           ignoredMembers: parsed.ignored || [],
           idTokenNames: oauth2.requestedClaimNames(parsed.claims, 'id_token'),
           claims: answer.claims, report: answer.report,
           unresolvable: answer.unknown,
           essentialAndAbsent: answer.missingEssential,
           valueMismatches: answer.mismatched,
           entryFound: answer.entryFound };
}

// The section 5.5 half of the page, and of the API's reply. It is one builder
// for both, for the reason claimSetsJson() is: the vocabulary a client may ask
// for is the thing a caller with no browser most needs, and a list published by
// the page that the API answered differently would be two answers to one
// question.
function claimsRequestJson(previewUser, raw) {
  log.debug("Entering claimsRequestJson().");
  const json = {
    supported: true,
    members: oauth2.CLAIMS_REQUEST_MEMBERS.slice(0),
    maxClaims: oauth2.MAX_REQUESTED_CLAIMS,
    // Every name a request may use, in the two spellings the resolver indexes:
    // the flat claim name of each catalogue row, and the top-level name of a
    // nested one (`address`), which is the spelling section 5.5.1's own example
    // uses and which returns the whole Address Claim of OIDC Core 5.1.1.
    requestable: claimAttributes.requestableClaims(),
    // The six this service invents from the username rather than reading off an
    // entry. They are answerable too, and they are listed separately because
    // the DIFFERENCE is the interesting part: an `ldapmodify` moves everything
    // in `requestable` and moves none of these.
    fromTheSignIn: oauth2.PERSONA_CLAIMS.slice(0),
    precedence: [
      'the configured UserInfo set on this page (typed claims, ticked ' +
        'directory attributes, the groups claim)',
      'OIDC Core 5.4\'s scope-driven claims (profile, email)',
      'OIDC Core 5.5\'s individually requested claims, read off ou=users',
      'sub, which no layer may displace (OIDC Core 5.3.2)'
    ],
    notEnforced: [
      '`essential` is carried and is a hint: section 5.5.1 says a server ' +
        'MUST NOT error because a requested claim is unavailable, so an ' +
        'essential claim this service cannot produce is simply absent and is ' +
        'logged.',
      '`value` and `values` are CHECKED and not honoured. This service could ' +
        'echo back whatever a client asked it to assert and deliberately ' +
        'does not — everything it says about a person comes from the ' +
        'directory or from the invented persona, and a mock that agreed with ' +
        'the request could not be used to test anything. A mismatch is ' +
        'reported in the log and in the response\'s artifact.',
      'A claims request IS filtered by the federation release policy, ' +
        'exactly as a custom claim set is. The list is about what an ' +
        'audience may see rather than about which mechanism produced the ' +
        'value, so a partner released `email` alone cannot ASK for ' +
        '`birthdate` and be given it — which is precisely the hole a release ' +
        'list exists to close.'
    ],
    // NON-SPEC, and labelled in the reply rather than only on the page: a
    // caller reading this document is exactly the caller who would otherwise
    // have to run a browser flow per variation.
    directParameter: {
      note: 'NON-SPEC. The UserInfo endpoint also accepts a claims request ' +
            'on the request itself, which section 5.3.1 does not define — it ' +
            'takes an access token and nothing else. It exists because ' +
            'exercising section 5.5 through the specified route means a ' +
            'whole authorization flow per variation. It is a UNION with what ' +
            'the access token carries and can never take a claim away from it.',
      spellings: ['GET /oauth2/userinfo?claims={"userinfo":{"birthdate":null}}',
                  'GET /oauth2/userinfo?claim=birthdate&claim=address',
                  'POST /oauth2/userinfo with the same two, form-encoded'],
      malformedIsRefused: 'invalid_request, with the reason. Ignoring a ' +
                          'debugging parameter that was typed wrong would ' +
                          'produce the same response as one never sent.'
    },
    preview: claimsRequestPreview(previewUser, raw)
  };
  log.debug("Leaving claimsRequestJson().");
  return json;
}

// The one UserInfo set, the rules that are its own, and the section 5.5 half.
// `reservedJwtClaims` IS here, unlike the SAML page's reply, and the reason is
// in the page header: every name on that list is load-bearing in at least one
// of this response's two shapes.
function userinfoClaimsJson(previewUser, raw) {
  log.debug("Entering userinfoClaimsJson(). previewUser=" + previewUser);
  const json = Object.assign(
    { reservedJwtClaims: stats.RESERVED_JWT_CLAIMS,
      claimsRequest: claimsRequestJson(previewUser, raw) },
    claimSetsJson(stats.USERINFO_CLAIM_SET_IDS, previewUser));
  log.debug("Leaving userinfoClaimsJson(). " + json.sets.length + " set(s).");
  return json;
}

// Rows per page when nobody said. Small enough that the table is the first
// thing on screen rather than the last, and the paging controls above and below
// it say what the rest of the list is.
const DEFAULT_PER_PAGE = 50;

// Rows per page for EVERY list on /admin/delegation, which is the one page here
// that carries seven of them at once.
//
// It is a tenth of DEFAULT_PER_PAGE and that is the point rather than a tuning
// choice. The other pages in this console are ONE list under one heading, where
// fifty rows is a table somebody scrolls; this page is seven — the acts, the
// chains, the permissions a resource exposes, the grants between two
// applications, the two Kerberos policy tables and the mechanism catalogue —
// with several screens of prose between them, so fifty rows apiece is a
// document tens of thousands of pixels long in which the seventh heading is
// unreachable by anything but the scrollbar. Ten keeps every section's control
// within a screen of its heading, which is what makes the page navigable at
// all; everything above ten is one click away and the control says how much.
//
// `?per=` still overrides it for all seven together, exactly as it does on the
// drill-downs, and perPageOptions() offers this value because it offers
// whatever is in force. A number somebody typed is a number they meant.
const DELEGATION_PER_PAGE = 10;

// How many rows of a list a page will draw. A cap is needed — 5,000 token rows
// is a page no browser enjoys — and what it hid is always stated underneath,
// because a truncated table that does not say it was truncated reads as the
// whole truth.
//
// On the tokens page this is now the ceiling on ONE PAGE rather than on the
// whole list: everything held is reachable by paging, so nothing is hidden any
// more. The cap stays because the reason for it never went away — `?per=` is a
// number a caller types, and without a ceiling `?per=5000` is the page the cap
// existed to prevent.
const MAX_ROWS = 300;

// ---------------------------------------------------------------------------
// THE THIRD BATCH (2026-09-12): the Shared Signals reports, found last because
// the console EXPORTS them under different names than it defines them by.
//
// `/admin-api` calls `admin.ssfView()`, `admin.caepView()` and four more; the
// functions behind those exports are `ssfJson()`, `caepJson()` and so on, and
// an analysis keyed on the name the API says was looking at a function that
// does not exist. Six pure reports sat behind that indirection for two passes.
// ---------------------------------------------------------------------------
// The reply BOTH doors answer with — `/admin/signals?format=json` and
// GET /admin-api/signals are the same document, rule 7 — built by the
// receiver module so that the console, the management API and the portal
// cannot come to three different opinions about what a delivered event is.
function signalsJson(req) {
  log.debug("Entering signalsJson().");
  // THE CONSOLE SEES EVERYTHING IN THE REALM IT IS READING, which is the
  // `sees: 'all'` on its row over there. It is an administrative surface: the
  // question it answers is "what has this service been telling its receivers",
  // and a per-person filter here would be the portal's page drawn in the wrong
  // application.
  const view = signals.view(signals.ADMIN, {});
  const state = signalsState(req, view);
  log.debug("Leaving signalsJson(). " + view.received.length + " row(s).");
  return Object.assign({}, view, {
    filter: { received: state.wanted || null },
    received: state.page.shown,
    total: view.received.length,
    paging: { received: pagingJson(state.page.paging) }
  });
}

// Filter first, then page — `pagingOf()`'s rule, for its reason: paging a list
// and then filtering it gives a page 2 whose length depends on what page 1
// happened to hold.
//
// THE SEARCH IS OVER WHAT A READER ARRIVES HOLDING: a username or an address
// out of a complaint, an event name, a `jti` out of a transmitter's log, or a
// stream id. They do not know which column it will be in, so it is one box
// over all of them rather than four.
function signalsState(req, view) {
  log.debug("Entering signalsState().");
  const wanted = queryOne(req.query, 'sigq').trim().toLowerCase();
  const rows = wanted
    ? view.received.filter(function (row) {
        return [row.name, row.subject, row.jti, row.stream, row.vocabulary,
                row.issuer, row.audience].concat(row.types)
          .some(function (value) {
            return String(value || '').toLowerCase().indexOf(wanted) >= 0;
          });
      })
    : view.received;
  const page = pagedRows(req.query, rows,
    { name: 'received', noun: 'events' });
  log.debug("Leaving signalsState(). " + rows.length + " match(es).");
  return { wanted: wanted, page: page };
}

// ---------------------------------------------------------------------------
// THE CLIENT-CERTIFICATE TRUSTSTORE, AS `/admin/tls/trust` AND
// `GET /admin-api/tls/trust` BOTH ANSWER IT (2026-09-12).
//
// One function for both, rule 7. It reads `req.query` for the paging and
// nothing else off the request. The rows are `tls/tls_server.js`'s own
// description of each anchor — this computes nothing about a certificate — and
// they are the same in every realm, because the array is the PROCESS's: the
// listeners are shared by every realm, so a realm-scoped view of them would be
// a filter over something that has no realm in it.
//
// **NO PRIVATE KEY IS IN THIS REPLY, AND NOT BECAUSE ONE IS REMOVED**: the
// truststore holds certificates and nothing else. Each row carries its PEM,
// which is the half of a key pair meant to be handed around.
// ---------------------------------------------------------------------------
function truststoreJson(req) {
  log.debug("Entering truststoreJson().");
  const openToAnybody = realms.run(realms.get(realms.DEFAULT_ID), function () {
    return mode.opensTestControls();
  });
  const doors = {
    console: '/admin/tls/trust',
    api: '/admin-api/tls/trust',
    testControls: { add: '/tls/trust', clear: '/tls/trust/clear',
                    open: openToAnybody }
  };
  const notes = {
    persisted: 'A RUNTIME ANCHOR IS WRITTEN TO ou=trustAnchors in the ' +
      'directory as it is added, so it survives a restart wherever the ' +
      'directory is persisted (persistence.mode ldif or postgres) and ' +
      'reaches every other process against the same store; each row says ' +
      'whether it was. An anchor from tls.trustAnchorsFile is not stored ' +
      'there and comes back at the next start however it was removed.',
    scope: 'ONE TRUSTSTORE FOR THE PROCESS, not one per trust realm: 8443, ' +
      '9443, LDAPS 636 and the main port are shared by every realm, so this ' +
      'answer is the same under every realm prefix.',
    effect: 'A change applies to the NEXT handshake. Connections already ' +
      'open keep the truststore they were made under.',
    revocation: 'Nothing checks revocation against these anchors — a ' +
      'certificate revoked by its issuer still verifies here.'
  };
  if (!truststore) {
    log.debug("Leaving truststoreJson(). Not installed.");
    return { installed: false, anchors: [], total: 0, fromFile: 0,
             atRuntime: 0, max: 0, anchorsFile: '', persisted: false,
             actions: [], doors: doors, notes: notes,
             note: 'tls/tls_server.js was not handed to the console in this ' +
                   'process, so there is no truststore to report on.' };
  }
  const listed = truststore.list();
  const rows = listed.anchors;
  const page = pagedRows(req.query || {}, rows, { noun: 'anchors' });
  const fromFile = rows.filter(function (one) {
    return one.source === 'file';
  }).length;
  log.debug("Leaving truststoreJson(). " + rows.length + " anchor(s).");
  return {
    installed: true,
    anchors: page.shown,
    total: rows.length,
    fromFile: fromFile,
    atRuntime: rows.length - fromFile,
    max: listed.max,
    anchorsFile: listed.file,
    loadedFromFile: listed.loadedFromFile,
    persisted: listed.stored === true,
    actions: adminActions.TRUSTSTORE_ACTIONS.slice(),
    doors: doors,
    notes: notes,
    page: page.paging.page, pages: page.paging.pages,
    perPage: page.paging.perPage, paging: pagingJson(page.paging)
  };
}

// ---------------------------------------------------------------------------
// THE KERBEROS PRINCIPALS, AS `/admin/kerberos/principals` AND
// `GET /admin-api/kerberos/principals` BOTH ANSWER IT (2026-09-12).
//
// Two lists, paged separately (`?peoplePage=`, `?servicesPage=`, one `per`):
// the directory people who hold Kerberos keys, and the service principals an
// operator stored a random key for. **NO KEY IS IN EITHER** — both lists are
// built from the PUBLIC info attributes, and nothing is opened to draw them.
// A person row says whether the keys match the password the entry holds NOW,
// which is the question somebody arrives with after a KDC refused a person
// with "sign in once".
//
// **IT ANSWERS FOR THE REALM IT IS READ IN SINCE 2026-09-15.** It read the same
// under every realm prefix while the KDC was the process's; a trust realm now
// has a Kerberos realm and a principal database of its own, so the people and
// service principals here are that realm's — and a realm whose `krb5.enabled`
// is off has none, which `kerberos` below says rather than showing an empty
// table that looks like a service with nothing in it.
// ---------------------------------------------------------------------------
function kerberosPrincipalsJson(req) {
  log.debug("Entering kerberosPrincipalsJson().");
  const query = (req && req.query) || {};
  const people = krb5PersonKeys.listPeople();
  const services = krb5PersonKeys.listServices();
  // `name` and NOT `param`: pagingOf() builds the parameter as `<name>Page`
  // and reads no `param` option at all. This passed `param` until 2026-09-13,
  // so both lists read the bare `?page=` while the page's links wrote
  // `peoplePage` and `servicesPage` — every next and previous link on
  // /admin/kerberos/principals reloaded the same first page.
  const peoplePage = pagedRows(query, people,
                               { name: 'people', noun: 'people' });
  const servicesPage = pagedRows(query, services,
                                 { name: 'services', noun: 'service ' +
                                     'principals' });
  const account = krb5Principals.serviceAccount();
  log.debug("Leaving kerberosPrincipalsJson(). " + people.length + " " +
      "person(s), " +
            services.length + " service principal(s).");
  const kerberos = krb5Principals.kerberosRealmOf();
  return {
    installed: krb5PersonKeys.installed(),
    realm: krb5Principals.REALM,
    trustRealm: realms.currentId(),
    // WHETHER THIS REALM HAS A KDC AT ALL, and if not why (2026-09-15):
    // `enabled` is the realm's own `krb5.enabled`, `served` the Kerberos realm
    // names its KDC answers for, and `reason` the sentence behind an off one.
    kerberos: kerberos,
    productKdc: krb5PersonKeys.productKdc(),
    personKeys: krb5PersonKeys.personKeysEnabled(),
    enctypes: krb5Principals.KDC_ETYPES.slice(),
    startingKvno: Number(config.value('krb5.kvno')),
    // THE PREVIOUS-VERSION WINDOW AS IT STANDS NOW: how many a key keeps and
    // for how long, in seconds, with zero in the setting already turned into
    // the ticket lifetime plus the clock skew it means. Each row's `retained`
    // lists the versions inside it — kvno, enctypes, expiry, and never a key.
    retention: { versions: krb5PersonKeys.retainedVersionsLimit(),
                 ttlSeconds: krb5PersonKeys.retainedTtlSeconds(),
                 ttlSetting: Number(config.value('krb5.retainedKeyTtlS')) },
    acceptor: { spn: account.spn, available: account.available,
                storedKey: !!account.storedKey },
    actions: adminActions.KERBEROS_PRINCIPAL_ACTIONS.slice(),
    people: peoplePage.shown,
    peopleTotal: people.length,
    peoplePaging: pagingJson(peoplePage.paging),
    services: servicesPage.shown,
    servicesTotal: services.length,
    servicesPaging: pagingJson(servicesPage.paging),
    notes: {
      keys: 'No key material is in this answer or on the page. A person\'s ' +
        'keys are derived from their password when it is set or verified and ' +
        'are never shown; a service principal\'s keytab is handed over ONCE, ' +
        'by the create or rotate that made it.',
      mode: krb5PersonKeys.productKdc()
        ? 'This KDC is a PRODUCT one: a person authenticates with their own ' +
          'password through the keys stored on their directory entry, and a ' +
          'person with none is refused with "sign in once".'
        : 'This KDC is a DEVELOPMENT one: every user is keyed from ' +
          'krb5.userPassword and people are never given stored keys. Service ' +
          'principals created here are used in both modes.',
      realm: kerberos.enabled
        ? 'A KDC PER TRUST REALM: these are the people and applications of ' +
          'the trust realm this page is read in, as principals of its own ' +
          'Kerberos realm ' + (kerberos.kerberosRealm || '') + '.'
        : 'THIS TRUST REALM HAS NO KDC: ' + (kerberos.reason ||
          'krb5.enabled is off for it') + '. Set krb5.realm on the realm ' +
          'and turn ' +
          'krb5.enabled on to give it one; port 88 routes a request by the ' +
          'Kerberos realm name inside it.',
      window: 'Keys are derived AFTER a password is set or verified and take ' +
        'a few tens of milliseconds to land; until they do, the KDC refuses ' +
        'the person rather than accepting an older key.',
      previous: 'A password change or a rotation keeps the version it ' +
        'replaced — at most krb5.retainedKeyVersions of them, each for ' +
        'krb5.retainedKeyTtlS — so a ticket issued under it is still ' +
        'accepted until it could have expired. A previous version only ever ' +
        'OPENS such a ticket: nothing is issued under it and an old password ' +
        'never signs in. "Drop previous versions" ends the window at once, ' +
        'after a compromise.'
    }
  };
}

// The whole report, for this page and for `GET /admin-api/ssf`. One function,
// so the page and the API cannot disagree about what this transmitter is
// doing — which is rule 7's entire subject.
function ssfJson(req) {
  log.debug("Entering ssfJson().");
  if (!signalsReporter) {
    log.debug("Leaving ssfJson(). Not installed.");
    return { installed: false, enabled: false, streamDetail: [],
             receivedDetail: [], settings: configSettingsJson('/admin/ssf'),
             note: 'ssf/ssf.js is not loaded in this process, so nothing ' +
                   'here can report on the Shared Signals Framework.' };
  }
  const report = signalsReporter.report(req);
  report.installed = true;
  report.settings = configSettingsJson('/admin/ssf');
  log.debug("Leaving ssfJson(). " + report.streamDetail.length + " stream(s).");
  return report;
}

// ---------------------------------------------------------------------------
// MONITORING -> SHARED SIGNALS -> DEAD LETTERS (2026-09-14).
//
// What every dead-letter queue in the realm holds, counted, and the letters
// themselves searched and paged. `ssf/ssf_dead_letter_report.js` computes the
// report; this adds only the search and the slice, for both doors —
// `/admin/ssf/dead-letters` and `GET /admin-api/ssf/dead-letters` — so the two
// cannot disagree about what was filtered (rule 7).
//
// THREE NARROWINGS AND THEY COMBINE. `dlstream` and `dlcause` are EXACT: a
// stream id and a cause id are what the page's own links carry, and a
// substring of a stream id is not a stream. `dlq` is the box over everything a
// reader arrives holding — a jti out of a receiver's log, an error code, an
// event name, a status, a phrase from a reason. The counts above the list are
// the WHOLE realm's whatever is narrowed, because "how many are there" and
// "which ones am I looking at" are two questions, and `matched` answers the
// second.
// ---------------------------------------------------------------------------
function ssfDeadLettersState(req, report) {
  log.debug("Entering ssfDeadLettersState().");
  const wanted = queryOne(req.query, 'dlq').trim().toLowerCase();
  const stream = queryOne(req.query, 'dlstream').trim();
  const cause = queryOne(req.query, 'dlcause').trim();
  const rows = (report.letters || []).filter(function (row) {
    if (stream && row.stream_id !== stream) {
      return false;
    }
    if (cause && row.cause !== cause) {
      return false;
    }
    if (!wanted) {
      return true;
    }
    const event = row.event || { name: '', types: [], subject: '' };
    return [row.jti, row.stream_id, row.reason, row.errorCode,
            String(row.status), event.name, event.subject]
      .concat(event.types)
      .some(function (value) {
        return String(value || '').toLowerCase().indexOf(wanted) >= 0;
      });
  });
  const page = pagedRows(req.query, rows,
    { name: 'letters', noun: 'dead letters' });
  log.debug("Leaving ssfDeadLettersState(). " + rows.length + " match(es).");
  return { wanted: wanted, stream: stream, cause: cause, rows: rows,
           page: page };
}

function ssfDeadLettersJson(req) {
  log.debug("Entering ssfDeadLettersJson().");
  if (!signalsReporter || typeof signalsReporter.deadLetters !== 'function') {
    log.debug("Leaving ssfDeadLettersJson(). Not installed.");
    return { installed: false, enabled: false, letters: [], streams: [],
             causes: [], byCode: [], byStatus: [], byEventType: [],
             totals: { held: 0 }, matched: 0,
             filter: { q: null, stream: null, cause: null },
             paging: { letters: pagingJson(pagingOf(req.query, 0,
               { name: 'letters', noun: 'dead letters' })) },
             note: 'ssf/ssf.js is not loaded in this process, so nothing ' +
                   'here can report on the Shared Signals dead-letter ' +
                   'queues.' };
  }
  const report = signalsReporter.deadLetters();
  const state = ssfDeadLettersState(req, report);
  log.debug("Leaving ssfDeadLettersJson(). " + state.page.shown.length +
            " of " + state.rows.length + " shown.");
  return Object.assign({}, report, {
    installed: true,
    filter: { q: state.wanted || null, stream: state.stream || null,
              cause: state.cause || null },
    matched: state.rows.length,
    letters: state.page.shown,
    paging: { letters: pagingJson(state.page.paging) }
  });
}

// The whole report, for both pages and for `GET /admin-api/caep`. ONE
// function, so the two pages and the API cannot come to disagree about what
// this transmitter has said — rule 7's entire subject.
function caepJson(req) {
  log.debug("Entering caepJson().");
  if (!caepReporter) {
    log.debug("Leaving caepJson(). Not installed.");
    return { installed: false, enabled: false, sessions: [], eventTypes: [],
             streams: [], totals: {}, tracked: 0,
             settings: configSettingsJson('/admin/caep'),
             note: 'ssf/ssf.js is not loaded in this process, so nothing ' +
                   'here can report on the Continuous Access Evaluation ' +
                   'Profile.' };
  }
  const report = caepReporter.report(req);
  report.installed = true;
  report.catalogue = caepReporter.eventTypes();
  report.settings = configSettingsJson('/admin/caep');
  log.debug("Leaving caepJson(). " + report.tracked + " session(s).");
  return report;
}

// ---------------------------------------------------------------------------
// MONITORING -> CAEP SESSIONS.
//
// **THE REGISTER OUTLIVES THE SESSION AND THAT IS THE POINT.** `authn.js`
// forgets a session the moment it is signed out; a row here whose state is
// `revoked` is the only remaining evidence that the session existed and was
// revoked, and "did anything go out when I signed that person out?" is the
// question this page is for.
//
// It is under Monitoring rather than beside the settings for the reason
// /admin/delegation is: that section's heading says *what this service has
// done*, and this is an OBSERVATION. The settings are a configuration and live
// at /admin/caep.
// ---------------------------------------------------------------------------
// THE SEARCH AND THE SLICE, as one pure function called twice — by the page and
// by GET /admin-api/caep/sessions. Written once for the reason
// `permissionsListState()` is: the markup and the reply have to agree about
// what was filtered and what was drawn, and two walks of one list is how they
// come to disagree about a session that ended in between.
function caepSessionsState(req, report) {
  log.debug("Entering caepSessionsState().");
  const wanted = queryOne(req.query, 'sessq').trim();
  const matched = (report.sessions || []).filter(function (row) {
    return chooserMatches([row.username, row.sub, row.sessionId, row.subject,
                           row.protocol], wanted);
  });
  const page = pagedRows(req.query, matched,
    { name: 'sessions', noun: 'sessions' });
  log.debug("Leaving caepSessionsState(). " + page.shown.length + " of " +
            matched.length + ".");
  return { wanted: wanted, matched: matched, page: page };
}

// THE PER-RECEIVER SECTION'S SEARCH AND SLICE, the same shape
// `caepSessionsState()` has and for the same reason: the markup and the reply
// have to agree about what was filtered and what was drawn.
//
// The search is over the RECEIVER — its identifier, its name, and the `aud` its
// SETs are addressed to — because those are the three strings a reader arrives
// holding and they are routinely different. It is NOT over the event types: a
// receiver that takes none of the eight is exactly the row somebody is looking
// for when they ask why nothing arrived, and a search that hid it would hide
// the answer.
function caepApplicationsState(req, report) {
  log.debug("Entering caepApplicationsState().");
  const wanted = queryOne(req.query, 'appq').trim();
  const matched = (report.applications || []).filter(function (row) {
    return chooserMatches([row.identifier, row.name, row.audiences.join(' ')],
                          wanted);
  });
  const page = pagedRows(req.query, matched,
    { name: 'applications', noun: 'receivers' });
  log.debug("Leaving caepApplicationsState(). " + page.shown.length + " of " +
            matched.length + ".");
  return { wanted: wanted, matched: matched, page: page };
}

// The reply BOTH doors answer with. `/admin/caep-sessions?format=json` and
// GET /admin-api/caep/sessions are the same document — rule 7 — and the drill-
// down is `?session=`, which is one operation answering two shapes for the
// reason /admin-api/permissions/groups gives: they are the same question at two
// scales and the console draws them with one register.
function caepSessionsJson(req) {
  log.debug("Entering caepSessionsJson().");
  const json = caepJson(req);
  const asked = String(req.query.session || '').trim();
  if (asked) {
    const row = (json.sessions || []).filter(function (one) {
      return String(one.sessionId) === asked;
    })[0] || null;
    const eventPage = pagedRows(req.query, (row && row.events) || [],
      { name: 'events', noun: 'events' });
    log.debug("Leaving caepSessionsJson(). One session.");
    return { installed: json.installed, id: asked, session: row,
             eventTypes: json.eventTypes || [],
             events: eventPage.shown,
             paging: { events: pagingJson(eventPage.paging) } };
  }
  const state = caepSessionsState(req, json);
  const appState = caepApplicationsState(req, json);
  log.debug("Leaving caepSessionsJson(). The list.");
  return Object.assign({}, json, {
    filter: { sessions: state.wanted || null,
              applications: appState.wanted || null },
    paging: { sessions: pagingJson(state.page.paging),
              applications: pagingJson(appState.page.paging) }
  });
}

// The whole report, for both pages and for `GET /admin-api/risc`. ONE
// function, so the two pages and the API cannot come to disagree about what
// this transmitter has said — rule 7's entire subject.
function riscJson(req) {
  log.debug("Entering riscJson().");
  if (!riscReporter) {
    log.debug("Leaving riscJson(). Not installed.");
    return { installed: false, enabled: false, accounts: [], eventTypes: [],
             streams: [], totals: {}, tracked: 0,
             settings: configSettingsJson('/admin/risc'),
             note: 'ssf/ssf.js is not loaded in this process, so nothing ' +
                   'here can report on the Risk Incident Sharing and ' +
                   'Coordination profile.' };
  }
  const report = riscReporter.report(req);
  report.installed = true;
  report.catalogue = riscReporter.eventTypes();
  report.settings = configSettingsJson('/admin/risc');
  log.debug("Leaving riscJson(). " + report.tracked + " account(s).");
  return report;
}

// ---------------------------------------------------------------------------
// MONITORING -> RISC ACCOUNTS.
//
// **THE REGISTER OUTLIVES THE ACCOUNT, AND MORE STARKLY THAN THE CAEP ONE
// OUTLIVES A SESSION.** That register keeps a row for a session the session
// store has forgotten. This one keeps a row for an account that has been
// DELETED FROM THE DIRECTORY ENTIRELY — the row whose lifecycle says `purged`
// is the only remaining evidence anywhere that this service ever told anybody
// the account was purged, and *"did anything go out when I deleted that
// person?"* is the entire question this page answers.
//
// It is under Monitoring rather than beside the settings for the reason
// /admin/caep-sessions is: that section's heading says *what this service has
// done*, and this is an OBSERVATION.
// ---------------------------------------------------------------------------
// THE SEARCH AND THE SLICE, as one pure function called twice — by the page
// and by the management API — for the reason caepSessionsState() is one.
//
// The search reaches `formerIdentifiers` as well as the current ones, and that
// is not thoroughness: an `identifier-changed` is an event ABOUT the key, so
// the address a reader arrives holding — out of a log, off an event they are
// chasing — is routinely the one the account no longer has. A search that
// matched only the current spelling would hide exactly the row somebody came
// to find.
function riscAccountsState(req, report) {
  log.debug("Entering riscAccountsState().");
  const wanted = queryOne(req.query, 'acctq').trim();
  const matched = (report.accounts || []).filter(function (row) {
    return chooserMatches([row.accountId, row.username, row.sub, row.email,
                           row.phone, row.subject, row.dn].concat(
                           row.formerIdentifiers || []), wanted);
  });
  const page = pagedRows(req.query, matched,
    { name: 'accounts', noun: 'accounts' });
  log.debug("Leaving riscAccountsState(). " + page.shown.length + " of " +
            matched.length + ".");
  return { wanted: wanted, matched: matched, page: page };
}

function riscApplicationsState(req, report) {
  log.debug("Entering riscApplicationsState().");
  const wanted = queryOne(req.query, 'rappq').trim();
  const matched = (report.applications || []).filter(function (row) {
    return chooserMatches([row.identifier, row.name, row.audiences.join(' ')],
                          wanted);
  });
  const page = pagedRows(req.query, matched,
    { name: 'rapplications', noun: 'receivers' });
  log.debug("Leaving riscApplicationsState(). " + page.shown.length + " of " +
            matched.length + ".");
  return { wanted: wanted, matched: matched, page: page };
}

// The reply BOTH doors answer with. `/admin/risc-accounts?format=json` and
// GET /admin-api/risc/accounts are the same document — rule 7 — and the
// drill-down is `?account=`, one operation answering two shapes for the reason
// the CAEP pair gives: they are the same question at two scales and the
// console draws them from one register.
function riscAccountsJson(req) {
  log.debug("Entering riscAccountsJson().");
  const json = riscJson(req);
  const asked = String(req.query.account || '').trim();
  if (asked) {
    const row = (json.accounts || []).filter(function (one) {
      return String(one.accountId) === asked;
    })[0] || null;
    const eventPage = pagedRows(req.query, (row && row.events) || [],
      { name: 'events', noun: 'events' });
    log.debug("Leaving riscAccountsJson(). One account.");
    return { installed: json.installed, id: asked, account: row,
             eventTypes: json.eventTypes || [],
             events: eventPage.shown,
             paging: { events: pagingJson(eventPage.paging) } };
  }
  const state = riscAccountsState(req, json);
  const appState = riscApplicationsState(req, json);
  log.debug("Leaving riscAccountsJson(). The list.");
  return Object.assign({}, json, {
    filter: { accounts: state.wanted || null,
              applications: appState.wanted || null },
    paging: { accounts: pagingJson(state.page.paging),
              applications: pagingJson(appState.page.paging) }
  });
}

// ---------------------------------------------------------------------------
// THE SPIFFE REPORTS (2026-09-12), and this family was already split.
//
// `spiffeAgentsListPage()` on the console opens with `const view =
// spiffeAgentsJson(req)` and does nothing but render what comes back. Somebody
// drew that line here long before there was anywhere to move the computation
// TO — which is why these three came across whole while the other twelve views
// still compute and render in one pass.
// ---------------------------------------------------------------------------
// Answered with empty listeners rather than null when the slot is unfilled, so
// every caller renders the same "nothing bound" table instead of each having to
// guard. The bundle path falls back to the configured value, which is what that
// module reads too — one setting, two readers, no third opinion.
function spiffeListeners() {
  log.debug("Entering spiffeListeners().");
  const read = spiffeReader ? spiffeReader() : null;
  log.debug("Leaving spiffeListeners().");
  return read || { workload: [], api: [],
                   bundlePath: config.value('spiffe.bundlePath') };
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
    authorities: { source: state.authoritySource,
                   realm: state.realm,
                   x509: state.x509Authorities, jwt: state.jwtAuthorities,
                   trustAnchors: state.trustAnchors,
                   chainSubjects: state.chainSubjects,
                   root: state.root,
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
               'spiffe.trustLocalSocket',
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
      .filter(function (value, index, list) {
        return list.indexOf(value) === index;
      })
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

function spiffeSelectorText(selector) {
  log.debug("Entering spiffeSelectorText().");
  log.debug("Leaving spiffeSelectorText().");
  return spiffeRegistry.selectorText(selector);
}

// ---------------------------------------------------------------------------
// THE NEW-APPLICATION FORM'S ANSWER (2026-09-12), and the first view whose
// computation was SPLIT rather than moved.
//
// `newApplicationPage()` on the console computed four facts, decided whether
// there was a directory to create anything in, and then built both a form and
// the JSON that describes it. The form stays there; this is the rest.
//
// **THE PAGE NOW RENDERS FROM WHAT THIS RETURNS**, rather than from its own
// copy of the same four values — so the vocabulary the form offers and the
// vocabulary `/admin-api` publishes are one computation, which is the property
// rule 7 asks for and the reason the json was next to the markup to begin
// with.
// ---------------------------------------------------------------------------
function newApplicationJson(req) {
  log.debug("Entering newApplicationJson().");
  const container = applications.containerDn ? applications.containerDn() :
                    null;
  const max = applications.maxApplications ? applications.maxApplications() :
              null;
  const held = applications.count();
  const realm = realms.current();
  // NO DIRECTORY IN THIS PROCESS — the page draws no form at all in this
  // case, and this is the answer it publishes instead. See the page.
  if (!container) {
    log.debug("Leaving newApplicationJson(). There is no directory.");
  return { directory: false, container: null, max: null, applicationCount: held,
          realm: { id: realms.currentId(), name: realm ? realm.name : '' },
          kinds: applications.KINDS, protocols: applications.PROTOCOLS,
          declarations: applications.declarationAttributes() };
  }
  log.debug("Leaving newApplicationJson().");
  return {
      directory: true,
      container: container,
      max: max,
      applicationCount: held,
      realm: { id: realms.currentId(), name: realm ? realm.name : '' },
      // The two vocabularies this form is built from, published rather than
      // described: a caller of POST /admin-api/applications/create reads these
      // to learn what it may send, which is what stops a document and a form
      // offering different sets. The `editable` list is what comes NEXT — the
      // attributes a create cannot take and `set`/`add` can.
      // `kinds` is still published and the form no longer offers it, which is
      // not a contradiction: `createApplication()` still TAKES a kind — the two
      // SAML register buttons pass one — so a caller of POST
      // /admin-api/applications/create may send one and needs the vocabulary to
      // send it from. What was removed is a person being asked to guess.
      kinds: applications.KINDS,
      protocols: applications.PROTOCOLS,
      // THE FIELDS THIS FORM DRAWS, in the order it draws them: the identifier
      // and redirect-URI attributes, deduped by attribute, each carrying the
      // families it serves and whether it holds a list. A caller reads this to
      // learn what may go in `fields` on a create, which is the same walk of
      // the PROTOCOLS table the page itself renders — so the document cannot
      // offer a field the form has never heard of, nor the other way round.
      declarations: applications.declarationAttributes(),
      editable: applications.editableAttributes().map(function (row) {
        // `families` where the attribute has one, and ABSENT where it does not,
        // so that a caller reading this document to learn what it may send is
        // told about the one refusal it could otherwise only discover by being
        // refused. An empty array here would have said "applies to no family",
        // which is the opposite of what an absent member means.
        const published = { name: row.name, mode: row.editable,
                            sensitive: !!row.sensitive };
        if (row.families && row.families.length) {
          published.families = row.families.slice(0);
        }
        return published;
      })
  };
}

// ---------------------------------------------------------------------------
// THE NEW-PERSON FORM'S ANSWER (2026-09-12). Split from newUserPage() the way
// newApplicationJson() was split from its own page, and for the same reason:
// the attribute catalogue this form draws its boxes from and the one
// `/admin-api` publishes were the same computation written twice in one
// function, with a form between them.
// ---------------------------------------------------------------------------
function newUserJson(req, prefill) {
  log.debug("Entering newUserJson().");
  const given = prefill || {};
  const values = given.fields || {};
  const username = String(given.username === undefined
    ? (req.query.user || '') : given.username).trim();
  const credential = String(given.credential || DEFAULT_CREDENTIAL);
  const realm = realms.current();
  const container = directoryReader ? newUserContainer() : null;
  const fields = vcClaims.personFields();
  const development = mode.isDevelopment();

  // NO DIRECTORY IN THIS PROCESS. The form is left OUT rather than drawn and
  // refused, which is `newApplicationPage()`'s shape and is right for the same
  // reason: `createUser()` would answer with exactly this sentence, and a form
  // whose only possible outcome is that message is a control that lies about
  // what it does.
  if (!directoryWriter || !container) {
    log.debug("Leaving newUserJson(). There is no directory to write to.");
    return { directory: false, container: null,
        realm: { id: realms.currentId(), name: realm ? realm.name : '' },
        fields: [], credentials: CREDENTIAL_CHOICES.map(function (one) {
          return { id: one.id, label: one.label };
        }) }
  }
  log.debug("Leaving newUserJson().");
  return {
    directory: true,
    container: container,
    realm: { id: realms.currentId(), name: realm ? realm.name : '' },
    mode: mode.current(),
    // WHETHER THE BUTTON IS THERE, published rather than left to be inferred
    // from `mode`: a caller of GET /admin-api/users/new reading this document
    // to find out what the console offers should not have to know which
    // predicate in mode.js decides it.
    offersExampleData: development,
    // THE FIELDS THIS FORM DRAWS, in the order it draws them, each with the
    // attribute name a create takes and the claim it reaches. A caller reads
    // this to learn what may go in `attributes` on a create — the same
    // catalogue `createUser()` checks against, so the document cannot offer a
    // field the writer has never heard of, nor the other way round.
    fields: fields.map(function (row) {
      return { attribute: row.ldap, label: row.label, schema: row.schema,
               claim: row.claim.slice(0), invented: !!row.from };
    }),
    credentials: CREDENTIAL_CHOICES.map(function (one) {
      return { id: one.id, label: one.label };
    }),
    // WHAT A CREATE THAT NAMES NO CREDENTIAL GETS (2026-09-12), and the rules a
    // typed or generated password meets — published so that a caller learns
    // both from the document rather than from a refusal.
    defaultCredential: DEFAULT_CREDENTIAL,
    credential: credential,
    passwordPolicy: credentials.passwordRules(username)
  }
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

// The credential choice, as four radios. A RADIO GROUP rather than a select for
// once, because each option needs a paragraph beside it: what an operator is
// choosing between here is not four values of one thing but four different
// stories about how this person first gets in, and three of them have a
// consequence that cannot be undone from this console.
//
// **`generate` IS THE DEFAULT SINCE 2026-09-12, AND `none` WAS BEFORE IT** —
// at rcbj's request, on both doors: this form preselects it and
// `POST /admin-api/users/create` uses it when `credential` is not sent. `none`
// was the default because it was what this door did before there were any
// choices, and in development it is enough to sign in; but a person created by
// hand with no credential is, in PRODUCT mode, a person who cannot sign in, and
// the default should be the thing that works in the mode this service is
// becoming. `none` is still one click or one field away.
const DEFAULT_CREDENTIAL = adminActions.DEFAULT_CREDENTIAL;

const CREDENTIAL_CHOICES = [
  { id: 'none', label: 'No credential at all',
    what: 'The entry exists and nothing is set on it. <strong>In development ' +
          'mode this is enough to sign in</strong> — no password is checked ' +
          'anywhere in this service — so it is the right choice for a test ' +
          'subject. In PRODUCT mode a person with no credential cannot sign ' +
          'in at all, and the way to give them one afterwards is an ' +
          'activation link.' },
  { id: 'password', label: 'A password I type',
    what: 'Hashed with scrypt by <code>credentials.js</code> and written to ' +
          '<code>userPassword</code> on the entry. <strong>It is never shown ' +
          'again by anything</strong>, including this console and an ' +
          '<code>ldapsearch</code>, because what is stored is the hash. ' +
          'Typed twice, because a mistyped password that nobody can read ' +
          'back is a person who cannot sign in and nobody who can say why.' },
  { id: 'generate', label: 'A password generated for me (the default)',
    what: 'Drawn from a cryptographically secure source by the ' +
          '<code>generate-password</code> package until it satisfies this ' +
          'realm\'s <a href="/admin/policies">password policy</a>, set the ' +
          'same way, and <strong>shown to you exactly once</strong> on the ' +
          'page that comes back. This service cannot produce it a second ' +
          'time — only replace it. It is the same generator the product-mode ' +
          'bootstrap account uses.' },
  { id: 'activation', label: 'No credential, and an activation link',
    what: 'The person holds nothing, and you are given a single-use, ' +
          'time-limited URL <strong>once</strong> to send them by whatever ' +
          'channel you already use. At it they choose a password, a security ' +
          'key, or both. <strong>Anybody holding that link can complete this ' +
          'account</strong>, so it is a credential and is treated as one: ' +
          'this service stores only a hash of it, issuing another ' +
          'invalidates the first, and it is spent when the setup FINISHES ' +
          'rather than when the link is opened — a link burned by a mail ' +
          'scanner would strand the person it was for.' }
];

// ---------------------------------------------------------------------------
// WHAT /admin/rbac ANSWERS (2026-09-12). The console page is a long one — two
// tables, a status block, four forms — and all of it is drawn from the twelve
// facts computed at the top of it, which are now computed here.
//
// `candidates` comes with them although the page declares it half way down,
// among the markup: it is `rbac.candidates()` over the keys of a map, the
// json publishes it, and a second call to work it out again for the document
// would be the page and the API asking the register two different questions.
// ---------------------------------------------------------------------------
function rbacListJson(req) {
  log.debug("Entering rbacListJson().");
  log.debug("Entering rbacListPage().");
  // The roster of the realm being read (2026-09-14, #32): the service roster
  // in the default realm, that realm's own anywhere else.
  const info = rbac.describe(realms.currentId());
  const state = gateStateFor(req);

  // One row per grant, flattened out of the two rosters. Sorted by name and
  // then by role so that somebody holding both is two adjacent rows rather than
  // two rows a page apart.
  const grants = [];
  info.roles.forEach(function (role) {
    role.members.forEach(function (member) {
      grants.push({
        username: member.username, role: role.role, roleLabel: role.label,
        cn: role.cn, dn: role.dn, value: member.value,
        attribute: member.attribute,
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
  const knownKeys = knownUserKeys();
  const candidates = rbac.candidates(Object.keys(knownKeys),
                                    realms.currentId());

  // WHO CAN BE PICKED, SEARCHED AND PAGED (2026-09-13). This was a `<select>`
  // holding every candidate, and a realm bulk loaded with thousands of people
  // made it a control nobody could use — and made this reply thousands of
  // rows long for a caller that wanted the roster. It is /admin/delegation's
  // person chooser now: `personq` narrows, `personfrom` pages by
  // CHOOSER_HITS, a stale offset is clamped rather than obeyed, and `person`
  // is the one a result link picked. The page draws the pane from the same
  // list with the same rule (chooserPane() in admin-ui/admin.js), so what the
  // page shows and what `candidates` answers are the same twenty.
  //
  // `person` is RESOLVED against the candidates rather than echoed. The grant
  // form it opens says "picked from the list", and a name typed into the URL
  // that the list does not hold belongs on the typed form, which says what a
  // dangling grant is.
  const personWanted = queryOne(req.query, 'personq').trim();
  const candidateMatched = candidates.filter(function (row) {
    return chooserMatches([row.username], personWanted);
  });
  // PAGED THE WAY EVERY SECOND LIST IN A REPLY IS PAGED HERE: `candidatesPage`
  // and a `candidatesPaging` object beside the array, with `per` shared with
  // the grants — detailPagingParameters()'s naming, so a caller that can read
  // the reply can write the request. Two things differ from a drill-down's
  // lists and both are for the console's pane:
  //
  //   * the default page size is CHOOSER_HITS rather than DEFAULT_PER_PAGE,
  //     because the pane shows twenty and a reply that defaulted to fifty
  //     would be a second answer to "which people are on this page";
  //   * `personfrom`, the pane's own OFFSET, is honoured when `candidatesPage`
  //     is absent, as the page that offset falls on. chooserPane() pages by
  //     offset for every chooser in this console, and the pane's links carry
  //     one; `candidatesPage` wins when both are sent.
  const candidateOptions = { name: 'candidates', defaultPer: CHOOSER_HITS,
                             noun: 'people' };
  let candidatePaging = pagingOf(req.query, candidateMatched.length,
                                 candidateOptions);
  const offsetAsked = parseInt(queryOne(req.query, 'personfrom'), 10);
  if (queryOne(req.query, 'candidatesPage') === '' && isFinite(offsetAsked) &&
      offsetAsked > 0 && offsetAsked < candidateMatched.length) {
    const asPage = Object.assign({}, req.query, {
      candidatesPage: String(Math.floor(offsetAsked /
                                        candidatePaging.perPage) + 1)
    });
    candidatePaging = pagingOf(asPage, candidateMatched.length,
                               candidateOptions);
  }
  const candidateShown = candidateMatched.slice(candidatePaging.offset,
      candidatePaging.offset + candidatePaging.perPage);
  const personAsked = queryOne(req.query, 'person').trim();
  const picked = personAsked
    ? (candidates.filter(function (row) {
        return row.username.toLowerCase() === personAsked.toLowerCase();
      })[0] || null)
    : null;
  // The grants table's own controls carry the search, so that paging or
  // filtering the table does not clear the pane the reader is still using.
  filterParams.personq = personWanted;
  filterParams.personfrom = queryOne(req.query, 'personfrom');
  filterParams.person = personAsked;
  log.debug("Leaving rbacListJson(). " + candidateMatched.length + " of " +
            candidates.length + " candidate(s) match.");
  return {
    // `an` and `bn` are NOT here: they are locals inside the sort comparator
    // above, and a first pass of this split lifted them as though they were
    // the page's, which is a ReferenceError the moment anything asks.
    info: info, state: state, grants: grants,
    wantedText: wantedText, needle: needle, wantedRole: wantedRole,
    filtered: filtered, paging: paging, shown: shown,
    filterParams: filterParams, knownKeys: knownKeys, candidates: candidates,
    personWanted: personWanted, personAsked: personAsked, picked: picked,
    candidateMatched: candidateMatched,
    json: (function () {
    return {
        enforced: info.enforced, openWhenEmpty: info.openWhenEmpty,
        openToAnyone: info.openToAnyone,
        closedToEveryone: info.closedToEveryone,
        // THE BOOTSTRAP ADMINISTRATOR (2026-09-13): who it is, whether it was
        // seeded, and when it first signed in to the console — the moment
        // `openToAnyone` stopped being true. See admin_rbac.js.
        bootstrap: info.bootstrap,
        available: info.available, groupsDn: info.groupsDn,
        usersDn: info.usersDn,
        grantCount: info.grantCount, matched: filtered.length,
        shown: shown.length,
        settings: configSettingsJson('/admin/rbac'),
        filter: { q: wantedText || null, role: wantedRole || null },
        page: paging.page, pages: paging.pages, perPage: paging.perPage,
        firstRow: paging.firstRow, lastRow: paging.lastRow,
        // WHO IS ASKING, which is on the reply rather than only in the banner
        // because a caller driving this over JSON has no banner and the answer
        // to "why did that 403" is here.
        you: { username: state.username, roles: state.roles,
               read: state.read, write: state.write,
               viaEmptyRoster: state.open },
        // THE ROLES WITHOUT THEIR MEMBER LISTS (2026-09-13). `members` and
        // `claimed` were every membership value of each role, unpaged, and
        // they are the same rows `grants` carries — paged, and narrowed to one
        // role by `?role=`. So a role here is what it is and how many hold
        // it; who holds it is `grants`.
        roles: info.roles.map(function (role) {
          const out = Object.assign({}, role);
          delete out.members;
          delete out.claimed;
          return out;
        }),
        grants: shown,
        // THE SLICE, NOT THE REGISTER — see the comment above. The paging
        // object beside it says how much there is, so a caller can tell twenty
        // of twenty from twenty of five thousand.
        candidates: candidateShown,
        candidatesPaging: pagingJson(candidatePaging),
        candidateSearch: {
          q: personWanted || null, total: candidates.length,
          matched: candidateMatched.length
        },
        picked: personAsked
          ? { asked: personAsked, candidate: picked }
          : null
    };
    }())
  };
}

// THE TWO LISTS ARE DIFFERENT QUESTIONS, and this is where that shows.
//
// The directory holds an entry for anybody somebody wrote one for — the three
// it seeds at startup, and whatever a client has added since. The users page
// holds everybody who has actually presented a credential to this service.
// `alice` is in the directory from the moment the process starts and is on the
// users page only once somebody signs in as her, so a member row that always
// linked there would usually land on "nothing here has authenticated as alice",
// which reads as a broken link rather than as the fact it is.
//
// So the console's own user registry is consulted, and a member it does not
// know is named without a link and with the reason. Reading it once per page
// rather than once per row is deliberate: userRows() walks the whole registry.
function knownUserKeys() {
  log.debug("Entering knownUserKeys().");
  const known = {};
  stats.userRows().forEach(function (row) {
    known[row.key] = true;
  });
  log.debug("Leaving knownUserKeys().");
  return known;
}

// ---------------------------------------------------------------------------
// WHAT /admin/saml2 ANSWERS. The list, and the drill-down below it.
//
// The page keeps `nav`, `listView` and the row markup; everything those are
// built FROM is here, and so is the json, so the table a person reads and the
// document a client fetches are one pass over the registry.
// ---------------------------------------------------------------------------
function saml2ListJson(req) {
  log.debug("Entering saml2ListJson().");
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

  log.debug("Leaving saml2ListJson(). " + filtered.length + " of " +
            all.length + ".");
  return {
    base: base, all: all, needle: needle, filtered: filtered,
    paged: paged, paging: paging, filterParams: filterParams,
    json: (function () {
    return {
        serviceProviders: paged.shown.map(function (row) {
          return Object.assign(saml2Facts(base, row.identifier), {
            name: row.name, authentications: row.authentications,
            sessions: row.sessions,
            users: row.users, firstSeen: row.firstSeen, lastSeen: row.lastSeen,
            assertionConsumerServices: valuesFor(
                row.fields.samlAssertionConsumerService),
            singleLogoutServices: valuesFor(row.fields.samlSingleLogoutService),
            nameIdFormats: valuesFor(row.fields.samlNameIdFormat),
            responseBindings: valuesFor(row.fields.samlResponseBinding),
            lastRequestSigned: row.fields.samlAuthnRequestSigned === 'TRUE'
          });
        }),
        paging: paging,
        unscopedMetadata: saml2Facts(base, '').metadataUrl,
        // The settings this page now EDITS, in the shape every page that owns
        // settings answers with: described rows carrying their source and
        // whether they can be changed while the service runs. It was a flat
        // key-to-value map while they were readings, which could say what a
        // value was and not where it came from — the question a person asking
        // about somebody else's deployment actually has.
        settings: configSettingsJson('/admin/saml2'),
        // Two numbers about the PROFILE rather than about any one service
        // provider, and both are the kind of thing that is invisible until it
        // is wrong: artifacts waiting to be resolved, and AuthnRequests held
        // while a browser is at the sign-in screen. A count that never falls is
        // a leak.
        artifactsAwaitingResolution: saml2.artifactCount(),
        requestsHeldForSignIn: saml2.pendingRequestCount()
    };
    }())
  };
}

function saml2DetailJson(req, identifier) {
  log.debug("Entering saml2DetailJson(). identifier=" + identifier);
  log.debug("Entering saml2DetailPage(). sp=" + identifier);
  const base = baseUrlOf(req);
  const facts = saml2Facts(base, identifier);
  const row = applications.get(identifier);
  const fields = (row && row.fields) || {};
  const acs = valuesFor(fields.samlAssertionConsumerService);
  const slo = valuesFor(fields.samlSingleLogoutService);
  log.debug("Leaving saml2DetailJson(). found=" + !!row);
  return {
    base: base, facts: facts, row: row, fields: fields, acs: acs, slo: slo,
    json: (function () {
    return Object.assign({ found: !!row }, facts, {
        name: (row && row.name) || '',
        authentications: (row && row.authentications) || 0,
        assertionConsumerServices: acs,
        singleLogoutServices: slo,
        nameIdFormats: valuesFor(fields.samlNameIdFormat),
        responseBindings: valuesFor(fields.samlResponseBinding),
        lastRequestSigned: fields.samlAuthnRequestSigned === 'TRUE',
        signingCertificate: fields.samlSigningCertificate || ''
    });
    }())
  };
}

// WHICH OF THE TWO A REQUEST IS ASKING FOR, decided the way the page decides
// it — `?sp=` means the drill-down. It is here rather than in the management
// API so that the page and the document cannot disagree about what a query
// string means.
function saml2Json(req) {
  log.debug("Entering saml2Json().");
  const wanted = String((req.query || {}).sp || '').trim();
  log.debug("Leaving saml2Json().");
  return wanted ? saml2DetailJson(req, wanted).json : saml2ListJson(req).json;
}

// Every application this profile has answered for. Read off the registry rather
// than kept, so a service provider created by an `ldapadd` appears here with no
// help from this file.
function saml2ServiceProviders() {
  log.debug("Entering saml2ServiceProviders().");
  const rows = applications.list().filter(function (row) {
    return row.kinds.indexOf(SAML2_SP_KIND) >= 0;
  });
  log.debug("Leaving saml2ServiceProviders(). " + rows.length + " service " +
      "provider(s).");
  return rows;
}

// One service provider's four URLs and its entityID, from the profile's own
// functions. Never rebuilt here — see the require at the top of this file.
function saml2Facts(base, identifier) {
  log.debug("Entering saml2Facts().");
  const where = saml2.endpointsFor(base, identifier);
  log.debug("Leaving saml2Facts().");
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

// An attribute's values as a plain array whatever the schema's `kind` is. The
// registry hands back a string for a single-valued attribute and an array for a
// multi-valued one, and a JSON reply that varied between the two shapes would
// be one a caller has to test the type of.
function valuesFor(value) {
  log.debug("Entering valuesFor().");
  if (value === undefined || value === null || value === '') {
    log.debug("Leaving valuesFor().");
    return [];
  }
  log.debug("Leaving valuesFor().");
  return Array.isArray(value) ? value.slice(0) : [String(value)];
}

// WHAT /admin/saml11 ANSWERS. Built the same way as the SAML 2.0 pair above
// and kept separate from it for the reason saml/CLAUDE.md gives about the two
// profiles: they share a framework and almost no spelling.
function saml11ListJson(req) {
  log.debug("Entering saml11ListJson().");
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
  log.debug("Leaving saml11ListJson().");
  return {
    base: base, all: all, needle: needle, filtered: filtered,
    paged: paged, paging: paging, filterParams: filterParams,
    json: (function () {
    return {
        relyingParties: paged.shown.map(function (row) {
          return Object.assign(saml11Facts(base, row.identifier), {
            name: row.name, authentications: row.authentications,
            sessions: row.sessions,
            users: row.users, firstSeen: row.firstSeen, lastSeen: row.lastSeen,
            assertionConsumerServices: valuesFor(
                row.fields.samlAssertionConsumerService),
            nameIdFormats: valuesFor(row.fields.samlNameIdFormat),
            profiles: valuesFor(row.fields.samlResponseBinding).filter(
                function (v) {
              return v === saml11.PROFILE_POST || v === saml11.PROFILE_ARTIFACT;
            })
          });
        }),
        paging: paging,
        unscopedMetadata: saml11Facts(base, '').metadataUrl,
        // The shape every page that owns settings answers with. See the SAML
        // 2.0 page's equivalent for why it is no longer a flat map.
        settings: configSettingsJson('/admin/saml11'),
        // Three numbers about the PROFILE rather than about any one relying
        // party, and all three are the kind of thing that is invisible until it
        // is wrong: artifacts minted and not yet resolved, assertions held for
        // an AssertionIDReference, and flows held while a browser is at the
        // sign-in screen. A count that never falls is a leak; the middle one is
        // CAPPED rather than swept, so it is the one that should sit at its
        // ceiling.
        artifactsAwaitingResolution: saml11.artifactCount(),
        assertionsHeldByReference: saml11.cachedAssertionCount(),
        flowsHeldForSignIn: saml11.pendingFlowCount()
    };
    }())
  };
}

function saml11DetailJson(req, identifier) {
  log.debug("Entering saml11DetailJson(). identifier=" + identifier);
  log.debug("Entering saml11DetailPage(). rp=" + identifier);
  const base = baseUrlOf(req);
  const facts = saml11Facts(base, identifier);
  const row = applications.get(identifier);
  const fields = (row && row.fields) || {};
  const acs = valuesFor(fields.samlAssertionConsumerService);
  const profiles = valuesFor(fields.samlResponseBinding).filter(function (v) {
    return v === saml11.PROFILE_POST || v === saml11.PROFILE_ARTIFACT;
  });

  // WHETHER THE ENDPOINTS WERE GUESSED, which the page also decides for its
  // own warning line. It is one regex over the identifier; both halves say
  // the same thing about it because both compute it from the same input.
  const looksGuessed = /^https?:\/\/[^/]+$/i.test(identifier);
  log.debug("Leaving saml11DetailJson(). found=" + !!row);
  return {
    base: base, facts: facts, row: row, fields: fields,
    acs: acs, profiles: profiles,
    json: (function () {
    return Object.assign(facts, {
        registered: !!row,
        identifierLooksGuessed: looksGuessed,
        name: row ? row.name : '',
        authentications: row ? row.authentications : 0,
        assertionConsumerServices: acs,
        nameIdFormats: valuesFor(fields.samlNameIdFormat),
        profiles: profiles
    });
    }())
  };
}

// `?rp=` means the drill-down here where SAML 2.0 uses `?sp=` — one of the
// six spellings saml/CLAUDE.md tabulates.
function saml11Json(req) {
  log.debug("Entering saml11Json().");
  const wanted = String((req.query || {}).rp || '').trim();
  log.debug("Leaving saml11Json().");
  return wanted ? saml11DetailJson(req, wanted).json : saml11ListJson(req).json;
}

// Every application this profile has answered for. Read off the registry rather
// than kept, so a relying party created by an `ldapadd` appears here with no
// help from this file.
//
// **THE KIND IS SHARED WITH WS-FEDERATION AND THAT IS DELIBERATE.**
// `saml11-relying-party` is what a WS-Federation relying party handed a 1.1
// assertion has always been recorded as, and a relying party that takes the
// same assertion through the passive requestor profile and through Browser/POST
// is ONE application with one audience. Giving the browser profiles a kind of
// their own would have split one entry into two, which is the defect this
// repository calls two spellings of one DN. The consequence to know when
// reading this list: a row here may have arrived through /wsfed and never
// touched /saml11, which is why the profiles column says what it has actually
// used.
function saml11RelyingParties() {
  log.debug("Entering saml11RelyingParties().");
  const rows = applications.list().filter(function (row) {
    return row.kinds.indexOf(SAML11_RP_KIND) >= 0;
  });
  log.debug("Leaving saml11RelyingParties(). " + rows.length + " relying " +
      "party/parties.");
  return rows;
}

// One relying party's three URLs and its providerID, from the profile's own
// functions. Never rebuilt here — see the require at the top of this file.
function saml11Facts(base, identifier) {
  log.debug("Entering saml11Facts().");
  const where = saml11.endpointsFor(base, identifier);
  log.debug("Leaving saml11Facts().");
  return {
    identifier: identifier,
    slug: saml11.slugOf(identifier),
    idpProviderId: saml11.providerIdFor(identifier),
    metadataUrl: where.metadata,
    ssoUrl: where.sso,
    responderUrl: where.responder
  };
}

// WHAT /admin/authorization-servers ANSWERS: the profiles, and one of them.
function asListJson(req) {
  log.debug("Entering asListJson().");
  log.debug("Entering asListPage().");
  const all = authorizationServers.list();
  const paged = pagedRows(req.query, all, { noun: 'authorization servers' });
  const paging = paged.paging;
  log.debug("Leaving asListJson().");
  return {
    all: all, paged: paged, paging: paging,
    json: (function () {
    return {
        profileCount: all.length, shown: paged.shown.length,
        page: paging.page, pages: paging.pages, perPage: paging.perPage,
        firstRow: paging.firstRow, lastRow: paging.lastRow,
        members: authorizationServers.MEMBERS,
        authorizationServers: paged.shown.map(function (row) {
          return Object.assign({}, row, { drift: asDriftRows(row.id) });
        })
    };
    }())
  };
}

// The drill-down. `capabilities` is the document the authorization server
// publishes and `drift` is where its members disagree with this service's own
// — both are what the page draws AND what the resource answers.
function asDetailJson(req, id) {
  log.debug("Entering asDetailJson(). id=" + id);
  const profile = authorizationServers.get(id);
  if (!profile) {
    log.debug("Leaving asDetailJson(). No such profile.");
    return { profile: null, json: { found: false, id: id } };
  }
  const drift = asDriftRows(id);
  // The document this authorization server publishes, which is the same object
  // its endpoints read their capabilities out of.
  const capabilities = authorizationServers.capabilitiesOf(id,
                                                           oauth2.asMetadata(
                                                               asTruthRequest(),
                                                               true));
  log.debug("Leaving asDetailJson(). " + drift.length + " drifting member(s).");
  return {
    profile: profile, drift: drift, capabilities: capabilities,
    json: Object.assign({ found: true }, profile, { drift: drift })
  };
}

// `?profile=` means the drill-down.
function authorizationServersJson(req) {
  log.debug("Entering authorizationServersJson().");
  const wanted = String((req.query || {}).profile || '').trim();
  log.debug("Leaving authorizationServersJson().");
  return wanted ? asDetailJson(req, wanted).json : asListJson(req).json;
}

function asDriftRows(id) {
  log.debug("Entering asDriftRows().");
  log.debug("Leaving asDriftRows().");
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
  log.debug("Entering asTruthRequest().");
  log.debug("Leaving asTruthRequest().");
  return {
    protocol: config.value('global.https') ? 'https' : 'http',
    get: function (name) {
      log.debug("Entering get().");
      log.debug("Leaving get().");
      return String(name).toLowerCase() === 'host'
        ? 'localhost:' + config.value('global.port') : '';
    },
    query: {}
  };
}

// WHAT /admin/groups ANSWERS. The two totals come with the computation
// although the page declares them among its markup: they are one reduce each
// over the same list, and the tiles a person reads are the numbers the
// resource publishes.
function groupsListJson(req) {
  log.debug("Entering groupsListJson().");
  log.debug("Entering groupsListPage().");
  const info = groupReader('');
  const wantedText = String(req.query.q || '').trim();
  const needle = wantedText.toLowerCase();
  const filtered = info.groups.filter(function (group) {
    if (!needle) {
      return true;
    }
    // The DN and the cn both, because a person looking for a group has one or
    // the other in mind and which one depends on whether they came from an LDAP
    // client or from this console.
    return group.dn.toLowerCase().indexOf(needle) >= 0 ||
           String(group.cn).toLowerCase().indexOf(needle) >= 0;
  });
  const paging = pagingOf(req.query, filtered.length);
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  const filterParams = { q: wantedText || '',
                         per: req.query.per ? paging.perPage : '' };
  const totalMembers = info.groups.reduce(function (n, g) {
    return n + g.memberCount;
  }, 0);
  const totalDangling = info.groups.reduce(function (n, g) {
    return n + g.danglingCount;
  }, 0);
  log.debug("Leaving groupsListJson().");
  return {
    info: info, wantedText: wantedText, needle: needle, filtered: filtered,
    paging: paging, shown: shown, filterParams: filterParams,
    totalMembers: totalMembers, totalDangling: totalDangling,
    json: (function () {
    return {
        groupCount: info.groupCount, matched: filtered.length,
        shown: shown.length,
        // WHETHER THE TWO CONTROLS ARE THERE, on the JSON as well as on the
        // page. A caller of /admin-api/groups that got a 400 saying "no
        // directory is loaded" from the create beside it would otherwise have
        // no way to tell that from a create it had got wrong.
        canWrite: !!groupWriter,
        membershipValues: totalMembers, dangling: totalDangling,
        settings: configSettingsJson('/admin/groups'),
        filter: { q: wantedText || null },
        page: paging.page, pages: paging.pages, perPage: paging.perPage,
        firstRow: paging.firstRow, lastRow: paging.lastRow,
        baseDn: info.baseDn, groupsDn: info.groupsDn, usersDn: info.usersDn,
        port: info.port, listening: info.listening, listenError:
                                                      info.listenError,
        ldapsPort: info.ldapsPort, ldapsListening: info.ldapsListening,
        groups: shown
    };
    }())
  };
}

// The group drill-down. Two paged lists on one page, so the answer carries
// both pagings; the page draws the navs from them.
function groupDetailJson(req, wantedDn) {
  log.debug("Entering groupDetailJson(). dn=" + wantedDn);
  const info = groupReader(wantedDn);
  if (!info.found) {
    log.debug("Leaving groupDetailJson(). Not a group.");
    return { info: info, json: Object.assign({ found: false }, info) };
  }
  const group = info.group;
  const known = knownUserKeys();

  // Two lists on this page and a page parameter each, sharing `per` — the same
  // arrangement the users drill-down has, and for the same reason: one `page`
  // would move both, and the two disagreements this page exists to show are
  // read against each other, so advancing the members while the claimants
  // jumped with them would be the one navigation that makes the page harder to
  // read than no navigation.
  //
  // The counts above the tables — memberCount, presentCount, danglingCount —
  // stay counts of the WHOLE list and are read off the directory rather than
  // off the slice, because "seven members, five resolve" is the fact the page
  // is for and "five members on this page" is not an answer to it.
  const params = pageParamsOf(req.query);
  const memberPage = pagedRows(req.query, group.members,
                               { name: 'members', noun: 'members' });
  const claimedPage = pagedRows(req.query, group.claimed,
                                { name: 'claimed', noun: 'entries' });

  // THE GROUP AS THIS PAGE OF IT, which the page used to build after its own
  // row markup — so the first pass of this split returned a name nothing
  // here declared. Recovered from the committed file rather than retyped.
  const pagedGroup = Object.assign({}, group, {
    members: memberPage.shown, claimed: claimedPage.shown
  });
  log.debug("Leaving groupDetailJson().");
  return {
    info: info, group: group, known: known, params: params,
    memberPage: memberPage, claimedPage: claimedPage, pagedGroup: pagedGroup,
    json: Object.assign({ found: true }, info, {
      canWrite: !!groupWriter,
      group: pagedGroup,
      membersPaging: pagingJson(memberPage.paging),
      claimedPaging: pagingJson(claimedPage.paging)
    })
  };
}

// `?group=` means the drill-down — and the NO-DIRECTORY branch comes first,
// exactly as it does on the page. Without it a build with no ldap_server.js
// reaches `groupReader(...)` and throws, where the page answers "the page
// exists, the directory does not", which are different facts about a process.
function groupsJson(req) {
  log.debug("Entering groupsJson().");
  if (!groupReader) {
    log.debug("groupsJson(): no directory is loaded.");
    log.debug("Leaving groupsJson().");
    return { directory: false, groups: [] };
  }
  const wanted = String((req.query || {}).group || '').trim();
  log.debug("Leaving groupsJson().");
  return wanted ? groupDetailJson(req, wanted).json : groupsListJson(req).json;
}

function pageParamsOf(query) {
  log.debug("Entering pageParamsOf().");
  const out = {};
  Object.keys(query || {}).forEach(function (key) {
    if (NOT_A_VIEW.indexOf(key) >= 0) {
      return;
    }
    // Express hands back an array when a parameter is repeated. The first is
    // taken rather than String()'d, because String(['2','5']) is "2,5" — a page
    // number nothing can parse, silently reached by a link somebody clicked
    // twice.
    const value = Array.isArray(query[key]) ? query[key][0] : query[key];
    out[key] = value == null ? '' : String(value);
  });
  log.debug("Leaving pageParamsOf(). " + Object.keys(out).length + " " +
      "parameter(s).");
  return out;
}

// The parameters every control on a drill-down has to carry.
//
// The list views name theirs one by one, and they can: their parameter set is
// the filter form beside them and it is written down two lines above the call.
// A drill-down's is not written down anywhere — one of its lists has a page
// parameter PER SESSION BLOCK, so the set depends on what the reader has been
// clicking — and listing the ones that exist today is how paging the artifacts
// comes to reset the members six months from now. So the current query is
// carried through whole and each control overrides its own key.
//
// Three things are dropped and each for its own reason. `format`, for the
// reason the tokens page gives about its own links: JSON has no page to click,
// so a nav link carrying it would answer a click with a download. And `notice`
// and `error`, which are the message a revoke's redirect brought back — they
// belong to the act that has just happened and not to the view, so carrying
// them would leave "Revoked …" at the top of every page the reader clicked to
// afterwards, and would put a stale one in the `back` field of the next revoke,
// which answers with two.
const NOT_A_VIEW = ['format', 'notice', 'error'];

// WHAT /admin/applications ANSWERS. `registeredCount` comes with the
// computation although the page declares it among the markup: the tile a
// person reads and the number the resource publishes are one count.
function applicationsListJson(req) {
  log.debug("Entering applicationsListJson().");
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
  const registeredCount =
      all.filter(function (row) { return row.registered; }).length;
  log.debug("Leaving applicationsListJson().");
  return {
    all: all, wantedText: wantedText, wantedKind: wantedKind, needle: needle,
    filtered: filtered, paged: paged, paging: paging,
    filterParams: filterParams, registeredCount: registeredCount,
    json: (function () {
    return {
        applicationCount: all.length, matched: filtered.length,
        shown: paged.shown.length,
        registered: registeredCount,
        filter: { q: wantedText || null, kind: wantedKind || null },
        page: paging.page, pages: paging.pages, perPage: paging.perPage,
        firstRow: paging.firstRow, lastRow: paging.lastRow,
        container: applications.containerDn ? applications.containerDn() : null,
        max: applications.maxApplications ? applications.maxApplications() :
             null,
        kinds: applications.KINDS,
        settings: configSettingsJson('/admin/applications'),
        applications: paged.shown
    };
    }())
  };
}

// The application drill-down: the entry, its attributes as a paged list, and
// the delegated permissions it holds and exposes.
function applicationDetailJson(req, identifier) {
  log.debug("Entering applicationDetailJson(). identifier=" + identifier);
  const row = applications.get(identifier);
  if (!row) {
    log.debug("Leaving applicationDetailJson(). No such application.");
    return { row: null, json: { found: false, identifier: identifier } };
  }
  const attributeRows = Object.keys(row.attributes).sort().map(function (name) {
    const value = row.attributes[name];
    // ---------------------------------------------------------------------
    // THE ONE ATTRIBUTE THIS TABLE DOES NOT SHOW AS THE ENTRY HOLDS IT.
    //
    // `oauthAssertionPrivateKey` is sealed at rest in product mode — see
    // `common/applications.js`'s SEALED_FIELDS — so what the ENTRY carries is
    // `$aesgcm$…` and what `row.fields` carries is the PEM, because that
    // module opened it on the way out. This page shows the opened value and
    // says the store holds it encrypted.
    //
    // **THAT IS A DECISION AND `/admin/ldap/applications` MAKES THE OPPOSITE
    // ONE**, which is why it is argued here rather than done quietly: the seal
    // protects the STORE — an ldapsearch on 389 where every bind succeeds, an
    // ldif file, a postgres row, a backup of either — and not this console,
    // which is behind a session and a role and is where an operator goes to
    // collect a credential this service issued them. The directory page is
    // headed "the registry as the directory sees it" and shows the ciphertext,
    // because an opened value there would be a page lying about its subject.
    // ---------------------------------------------------------------------
    const opened = applications.isSealed(value) && row.fields
      ? row.fields[name] : null;
    const shown = opened && !applications.isSealed(opened) ? opened : value;
    return { name: name, values: Array.isArray(shown) ? shown : [String(shown)],
             sealedAtRest: shown !== value,
             operational: (row.operational || []).indexOf(name) >= 0 };
  });
  const paged = pagedRows(req.query, attributeRows,
                          { name: 'attributes', noun: 'attributes' });
  const paging = paged.paging;
  // THE RETURN ADDRESSES AWAITING CONFIRMATION (2026-09-12), the second list
  // on this page and paged under a name of its own for pagingOf()'s reason.
  // The rows are `row.returnAddressesObserved`, which `applications.view()`
  // built from the one function that decides whether an address counts —
  // so the page, this reply and the check at the protocol door cannot
  // disagree about which addresses product mode withholds.
  const observedPaged = pagedRows(req.query, row.returnAddressesObserved || [],
                                  { name: 'observed',
                                    noun: 'observed addresses' });
  const permissionState = applicationPermissionsState(req.query,
                                                      row.identifier);
  const credentialsState = applicationCredentialsState(row);
  const softwareStatementState = applicationSoftwareStatementState(row);
  log.debug("Leaving applicationDetailJson().");
  return {
    row: row, attributeRows: attributeRows, paged: paged, paging: paging,
    observedPaged: observedPaged,
    permissionState: permissionState,
    credentialsState: credentialsState,
    softwareStatementState: softwareStatementState,
    json: (function () {
    return Object.assign({ found: true }, row, {
        attributesShown: paged.shown,
        attributesPaging: pagingJson(paging),
        // `returnAddressesObserved` itself is WHOLE, on the row, beside the
        // slice the page draws — the same arrangement `delegatedPermissions`
        // makes below, because the slicing is this page's layout and not a
        // fact about the entry.
        returnAddressesObservedShown: observedPaged.shown,
        returnAddressesObservedPaging: pagingJson(observedPaged.paging),
        // THE CREDENTIALS SECTION, AS DATA (2026-09-13) — which key pair is
        // managed per profile, where it came from, the chain, and the keys the
        // party registered itself. No secret and no private key: see
        // applicationCredentialsState().
        credentials: credentialsState.json,
        // THE SOFTWARE STATEMENTS SECTION, AS DATA (2026-09-13): the issuers
        // this application vouches for as a publisher, the statement this realm
        // issued it, and how it registered if a statement let it in. A
        // statement is not a secret, so the issued one is here whole.
        softwareStatements: softwareStatementState.json,
        // THE RESOLVED DELEGATED PERMISSIONS, because the page draws a section
        // of them and a reply that carried only the raw attribute would leave a
        // caller to compose `baseUri + name` for itself — which is the one
        // string in this feature that must not be worked out in two places.
        // WHOLE, with the paging beside it rather than applied to it, for the
        // reason /admin/delegation's own `allowed` member gives: the slicing is
        // this page's layout and not a fact about the entry, and
        // `GET /admin-api/permissions` answers with the same register under its
        // own name.
        delegatedPermissions: {
          held: permissionState.held,
          exposes: permissionState.exposes,
          offerable: permissionState.offerable.map(function (one) {
            return one.id;
          }),
          paging: { held: pagingJson(permissionState.heldPage.paging),
                    exposes: pagingJson(permissionState.exposedPage.paging) }
        }
    });
    }())
  };
}

// ---------------------------------------------------------------------------
// AN APPLICATION'S CREDENTIALS, IN ONE PLACE (2026-09-13).
//
// The client secret, and for each assertion profile the key pair this service
// manages — issued here or a certificate uploaded in its place — beside the
// keys the party registered itself. Every fact was already on the entry and in
// the attribute table under it; what was missing is the READING: which
// certificate, issued by whom, through what chain, expiring when, and whether
// this service holds the private half. So this parses the certificates and
// names the attributes from `applications.KEY_PAIR_ATTRIBUTES`, the one table
// the writer (`admin-ui/pki_admin.js`) reads too.
//
// **THE JSON CARRIES NO SECRET AND NO PRIVATE KEY.** Both are already in the
// reply's `fields`, opened, for a caller holding `admin:read` — that is the
// registry's decision and this does not repeat it; a second copy of a
// credential in one reply is one more place a log line or a screenshot picks
// it up. The page reads the values from the state, which never leaves this
// process as JSON.
// ---------------------------------------------------------------------------
function certificateSummary(pem) {
  log.debug("Entering certificateSummary().");
  try {
    const cert = new nodeCrypto.X509Certificate(String(pem));
    const notAfter = new Date(cert.validTo);
    const summary = {
      subject: String(cert.subject || '').split('\n').filter(Boolean)
        .join(', '),
      issuer: String(cert.issuer || '').split('\n').filter(Boolean)
        .join(', '),
      serialHex: String(cert.serialNumber || '').toLowerCase(),
      notBefore: new Date(cert.validFrom).toISOString(),
      notAfter: notAfter.toISOString(),
      expired: notAfter.getTime() < Date.now(),
      selfSigned: cert.subject === cert.issuer,
      keyType: cert.publicKey.asymmetricKeyType,
      thumbprint: nodeCrypto.createHash('sha256').update(cert.raw)
        .digest('base64url')
    };
    log.debug("Leaving certificateSummary().");
    return summary;
  } catch (e) {
    log.debug("Caught in certificateSummary(): " + ((e && e.message) || e));
    // An attribute an `ldapmodify` reaches: reported as unreadable rather
    // than dropped, so the section says what the entry holds.
    log.debug("Leaving certificateSummary(). Unreadable.");
    return { unreadable: String((e && e.message) || e) };
  }
}

function pemCertificatesIn(value) {
  log.debug("Entering pemCertificatesIn().");
  const text = Array.isArray(value) ? value.join('\n') : String(value || '');
  const blocks = text.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  log.debug("Leaving pemCertificatesIn(). " + blocks.length + " block(s).");
  return blocks;
}

function registeredJwksKeys(value) {
  log.debug("Entering registeredJwksKeys().");
  if (!value) {
    log.debug("Leaving registeredJwksKeys(). None.");
    return { keys: [], problem: '' };
  }
  try {
    const doc = typeof value === 'string' ? JSON.parse(value) : value;
    const keys = (doc && Array.isArray(doc.keys) ? doc.keys : []).map(
        function (jwk) {
      return { kid: jwk.kid ? String(jwk.kid) : '', kty: String(jwk.kty || ''),
               alg: jwk.alg ? String(jwk.alg) : '',
               use: jwk.use ? String(jwk.use) : '',
               certificate: Array.isArray(jwk.x5c) && jwk.x5c.length
                 ? certificateSummary('-----BEGIN CERTIFICATE-----\n' +
                                      String(jwk.x5c[0]) +
                                      '\n-----END CERTIFICATE-----')
                 : null };
    });
    log.debug("Leaving registeredJwksKeys(). " + keys.length + " key(s).");
    return { keys: keys, problem: '' };
  } catch (e) {
    log.debug("Caught in registeredJwksKeys(): " + ((e && e.message) || e));
    // The verifier reports the same thing when it reads it; the page says it
    // before anybody has to find out that way.
    log.debug("Leaving registeredJwksKeys(). Not JSON.");
    return { keys: [], problem: 'not valid JSON: ' + e.message };
  }
}

function applicationCredentialsState(row) {
  log.debug("Entering applicationCredentialsState(). identifier=" +
            (row && row.identifier));
  const fields = (row && row.fields) || {};
  const one = function (name) {
    log.debug("Entering one().");
    const value = name ? fields[name] : undefined;
    log.debug("Leaving one().");
    return Array.isArray(value) ? value.join('\n') : String(value || '');
  };
  const chainAvailable = pki.hasChain();
  const described = chainAvailable ? pki.describe() : null;
  const purposes = pki.PURPOSES.map(function (purpose) {
    const names = applications.KEY_PAIR_ATTRIBUTES[purpose.id];
    const certificatePem = one(names.certificate);
    const privateKeyPem = one(names.privateKey);
    const recorded = one(names.source);
    const source = recorded ||
      (privateKeyPem ? 'issued' : (certificatePem ? 'unrecorded' : ''));
    const registeredText = one(names.registered);
    return {
      id: purpose.id,
      label: purpose.label,
      attributes: names,
      held: !!(certificatePem || privateKeyPem),
      source: source,
      privateKeyHeld: !!privateKeyPem,
      sealedAtRest: applications.isSealed((row.attributes || {})[
        names.privateKey]),
      certificate: certificatePem ? certificateSummary(certificatePem) : null,
      certificatePem: certificatePem,
      chain: pemCertificatesIn(one(names.chain)).map(certificateSummary),
      handle: one(names.handle),
      handleLabel: names.handleLabel,
      issuers: [].concat(fields[names.issuer] || []).map(String),
      registered: purpose.id === 'jwt'
        ? Object.assign({ attribute: names.registered },
                        registeredJwksKeys(registeredText))
        : { attribute: names.registered,
            certificates: pemCertificatesIn(registeredText)
              .map(certificateSummary),
            problem: registeredText && !pemCertificatesIn(registeredText).length
              ? 'it holds no PEM certificate block' : '' }
    };
  });
  // WHETHER THE TWO ASSERTION PROFILES ARE DRAWN AT ALL (2026-09-13). RFC
  // 7523 and RFC 7522 are both used at the TOKEN ENDPOINT, so an application
  // that has not been declared an OAuth 2.0 client or an OpenID Connect
  // relying party — the two families whose identifier is a client_id — has no
  // use for either section, and the page leaves them out. It is the
  // DECLARATION (`appAllowedProtocol`) and not the recorded kinds, because
  // that is the checkbox an operator ticks to say what the application is
  // for. Hiding a section grants and removes nothing: a key pair already on
  // the entry still verifies, and the page says so when one is there.
  const declared = [].concat(row.allowedProtocols || []);
  const oauthDeclared = declared.indexOf('oauth2') >= 0 ||
                        declared.indexOf('oidc') >= 0;
  const secret = one('oauthClientSecret');
  const state = {
    oauthDeclared: oauthDeclared,
    clientSecret: {
      held: !!secret,
      value: secret,
      authMethod: one('oauthTokenEndpointAuthMethod'),
      registered: !!row.registered,
      registrationAccessTokenHeld: !!one('appRegistrationAccessToken'),
      registrationAccessToken: one('appRegistrationAccessToken')
    },
    purposes: purposes,
    ca: {
      available: chainAvailable,
      keyAlg: described && described.keyAlg ? String(described.keyAlg) : '',
      keyAlgorithms: pki.keyAlgorithms(),
      leafLifetimeDays: pki.leafLifetimeDays()
    },
    sources: applications.KEY_SOURCES.slice(),
    mtls: applicationMtlsState(row, one, chainAvailable)
  };
  state.json = {
    clientSecret: { held: state.clientSecret.held,
                    authMethod: state.clientSecret.authMethod,
                    registered: state.clientSecret.registered,
                    registrationAccessTokenHeld:
                      state.clientSecret.registrationAccessTokenHeld },
    keyPairs: purposes.map(function (p) {
      return { purpose: p.id, label: p.label, held: p.held, source: p.source,
               privateKeyHeld: p.privateKeyHeld, certificate: p.certificate,
               chain: p.chain, handle: p.handle, handleLabel: p.handleLabel,
               issuers: p.issuers, attributes: p.attributes,
               registered: p.registered };
    }),
    caAvailable: chainAvailable,
    oauthDeclared: oauthDeclared,
    sources: state.sources,
    mtls: state.mtls
  };
  log.debug("Leaving applicationCredentialsState().");
  return state;
}

// ---------------------------------------------------------------------------
// RFC 8705 ON AN APPLICATION'S PAGE (2026-09-13).
//
// What the token endpoint will accept from this application and do with its
// tokens, read from the same places it reads them: the declared method, the
// TLS client certificates this realm issued to it (the IMPLICIT mapping, whose
// record `tls_client_certificates.stillHeld()` asks), the one subject
// parameter it may register instead (the EXPLICIT one), the section 2.2
// thumbprint, and the section 3.4 flag. Certificates it enrolled over ACME,
// EST or SCEP authenticate it too and are listed on those protocols' pages,
// not here — this section issues and lists its own.
// ---------------------------------------------------------------------------
function applicationMtlsState(row, one, caAvailable) {
  log.debug("Entering applicationMtlsState().");
  const identifier = String((row && row.identifier) || '');
  let held = [];
  try {
    held = tlsClientCertificates.listFor(undefined, identifier, 'application')
      .map(function (cert) {
        return { serialHex: cert.serialHex, label: cert.label,
                 subject: cert.subject, keyAlg: cert.keyAlg,
                 notBefore: cert.notBefore, notAfter: cert.notAfter,
                 thumbprint: cert.thumbprint, state: cert.state,
                 reason: cert.reason, revokedAt: cert.revokedAt,
                 certificatePem: cert.certificatePem };
      });
  } catch (e) {
    // No certificate authority in this process: nothing issued, nothing held.
    log.debug("Caught in applicationMtlsState(): " + ((e && e.message) || e));
    held = [];
  }
  const subjects = certificateSubject.MEMBER_NAMES.map(function (member) {
    const described = certificateSubject.MEMBERS[member];
    return { member: member, attribute: described.attribute,
             label: described.label, value: one(described.attribute) };
  });
  const method = one('oauthTokenEndpointAuthMethod');
  log.debug("Leaving applicationMtlsState(). " + held.length + " held.");
  return {
    authMethod: method,
    certificateMethod: mtls.CERTIFICATE_METHODS.indexOf(method) >= 0,
    implicitName: tlsClientCertificates.APPLICATION_URN + identifier,
    certificates: held,
    active: held.filter(function (cert) {
      return cert.state === 'valid';
    }).length,
    max: tlsClientCertificates.maxPerHolder('application'),
    subjects: subjects,
    registeredSubject: subjects.filter(function (s) {
      return !!s.value;
    }).map(function (s) {
      return s.member;
    }),
    boundTokensAttribute: applications.TLS_BOUND_TOKENS_ATTRIBUTE,
    boundTokens: one(applications.TLS_BOUND_TOKENS_ATTRIBUTE).toUpperCase() ===
                 'TRUE',
    selfSignedThumbprint: one('oauthTlsClientCertificateThumbprint'),
    bindingAvailable: mtls.available(),
    caAvailable: !!caAvailable,
    keyAlgorithms: tlsClientCertificates.KEY_ALGS.slice(),
    defaultKeyAlg: tlsClientCertificates.DEFAULT_KEY_ALG,
    revocationReasons: tlsClientCertificates.REVOCATION_REASONS.slice(),
    passwordMin: tlsClientCertificates.PKCS12_PASSWORD_MIN
  };
}

// ---------------------------------------------------------------------------
// SOFTWARE STATEMENTS ON AN APPLICATION'S PAGE (RFC 7591 section 2.3,
// 2026-09-13).
//
// Three facts from three places, read here so the page and
// `GET /admin-api/applications?application=` cannot disagree about them:
// `oauthSoftwareStatementIssuer` and whether the entry holds a key a statement
// could verify under (the publisher half); `oauthIssuedSoftwareStatement`,
// decoded and checked against the realm's key NOW (the issued half); and the
// three `appSoftwareStatement*` facts a registration wrote (the client half).
// ---------------------------------------------------------------------------
function applicationSoftwareStatementState(row) {
  log.debug("Entering applicationSoftwareStatementState().");
  const fields = (row && row.fields) || {};
  const issuers = [].concat(fields.oauthSoftwareStatementIssuer || [])
    .map(String);
  const keys = assertionGrant.keysForParty(fields, 'application');
  const issuedToken = String([].concat(
    fields.oauthIssuedSoftwareStatement || [])[0] || '');
  const issued = issuedToken ? softwareStatement.describe(issuedToken) : null;
  const registeredWith = row
    ? applications.softwareStatementFactsOf(row.identifier) : null;
  const settings = {
    requireTrustedIssuer: softwareStatement.requiresTrustedIssuer(),
    opensRegistration: softwareStatement.opensRegistration(),
    required: softwareStatement.required(),
    lifetimeSeconds: softwareStatement.issuedLifetimeSeconds()
  };
  const state = {
    issuers: issuers,
    usableKeys: keys.keys.length,
    keyProblems: keys.problems,
    issuedToken: issuedToken,
    issued: issued,
    registeredWith: registeredWith,
    settings: settings
  };
  state.json = {
    declaredIssuers: issuers,
    usableKeys: keys.keys.length,
    issued: issued ? Object.assign({ statement: issuedToken }, issued) : null,
    registeredWith: registeredWith,
    settings: settings
  };
  log.debug("Leaving applicationSoftwareStatementState().");
  return state;
}

// ---------------------------------------------------------------------------
// A PERSON'S KEY PAIRS, ON THEIR OWN PAGE (2026-09-13).
//
// The application's section above, for the other kind of holder: for each
// assertion profile, the key pair on the person's own entry — issued here or a
// certificate uploaded in its place — read into which certificate, issued by
// whom, through what chain, and whether this service holds the private half.
// `person_assertions.KEY_PAIR_ATTRIBUTES` names the attributes, which is the
// table the writer uses.
//
// **THERE IS NO PRIVATE KEY IN THE STATE, EITHER HALF**, and that is a
// difference from the application's which is the point rather than an
// omission. An application's private key is readable through
// `applications.view()`; a person's has no read door — it is handed over once,
// by the issue — so this reports whether one is HELD and never what it is.
// `recordFor()` opens the seal to answer that, and nothing opened leaves this
// function.
// ---------------------------------------------------------------------------
function personCredentialsState(key) {
  log.debug("Entering personCredentialsState(). key=" + key);
  const storable = personAssertions.storable();
  const record = storable ? personAssertions.recordFor(key) : null;
  const chainAvailable = pki.hasChain();
  const described = chainAvailable ? pki.describe() : null;
  const labels = {};
  pki.PURPOSES.forEach(function (purpose) {
    labels[purpose.id] = purpose.label;
  });
  const purposes = personAssertions.PURPOSE_IDS.map(function (id) {
    const names = personAssertions.KEY_PAIR_ATTRIBUTES[id];
    const value = function (name) {
      log.debug("Entering value().");
      log.debug("Leaving value().");
      return record && name ? String(record[name] || '') : '';
    };
    const certificatePem = value(names.certificate);
    const privateKeyHeld = !!value(names.privateKey);
    const held = !!(record && (id === 'saml' ? record.hasSamlKeyPair
                                             : record.hasKeyPair));
    const declared = record
      ? (id === 'saml' ? record.samlIssuers : record.issuers) : [];
    return {
      id: id,
      label: labels[id] || id,
      attributes: { issuer: names.issuer, certificate: names.certificate,
                    chain: names.chain, privateKey: names.privateKey,
                    handle: names.handle, source: names.source,
                    expiresAt: names.expiresAt, jwks: names.jwks },
      held: held,
      source: value(names.source) ||
        (privateKeyHeld ? 'issued' : (certificatePem ? 'unrecorded' : '')),
      privateKeyHeld: privateKeyHeld,
      certificate: certificatePem ? certificateSummary(certificatePem) : null,
      chain: pemCertificatesIn(value(names.chain)).map(certificateSummary),
      handle: value(names.handle),
      handleLabel: names.handleLabel,
      expiresAt: value(names.expiresAt),
      issuers: declared.slice(),
      effectiveIssuers: record
        ? (id === 'saml' ? record.samlEffectiveIssuers
                         : record.effectiveIssuers).slice() : []
    };
  });
  const state = {
    storable: storable,
    found: !!record,
    username: record ? record.username : String(key || ''),
    purposes: purposes,
    ca: {
      available: chainAvailable,
      keyAlg: described && described.keyAlg ? String(described.keyAlg) : '',
      keyAlgorithms: pki.keyAlgorithms(),
      leafLifetimeDays: pki.leafLifetimeDays()
    },
    sealsAtRest: storable && keystore.persists(),
    selfService: !!config.value('pki.personSelfService'),
    sources: applications.KEY_SOURCES.slice()
  };
  state.json = {
    storable: storable,
    found: state.found,
    keyPairs: purposes.map(function (p) {
      return { purpose: p.id, label: p.label, held: p.held, source: p.source,
               privateKeyHeld: p.privateKeyHeld, certificate: p.certificate,
               chain: p.chain, handle: p.handle, handleLabel: p.handleLabel,
               expiresAt: p.expiresAt, issuers: p.issuers,
               effectiveIssuers: p.effectiveIssuers,
               attributes: p.attributes };
    }),
    caAvailable: chainAvailable,
    sealsAtRest: state.sealsAtRest,
    selfService: state.selfService,
    sources: state.sources
  };
  log.debug("Leaving personCredentialsState(). found=" + state.found);
  return state;
}

// `?application=` means the drill-down.
function applicationsJson(req) {
  log.debug("Entering applicationsJson().");
  const wanted = String((req.query || {}).application || '').trim();
  log.debug("Leaving applicationsJson().");
  return wanted ? applicationDetailJson(req, wanted).json :
         applicationsListJson(req).json;
}

// ---------------------------------------------------------------------------
// DELEGATED PERMISSIONS, ON THE APPLICATION'S OWN PAGE (2026-09-01).
//
// THE GRANT FORM LIVED ON /admin/delegation AND IT IS HERE NOW, and the reason
// is the shape of the control rather than the length of that page.
//
// There it was two `<select>`s: every application in the registry beside every
// permission anybody exposes, with the reader asked to get BOTH right. That is
// the one write in this whole register where choosing the wrong option still
// SUCCEEDS and stays plausible — a grant is a value on the CLIENT's entry, so
// writing it to the resource instead produces a row that resolves in both
// directions, reads correctly on the delegation page's own grants table, and
// is wrong only at the token endpoint, later, to somebody else.
// `tests/vendored/sts_delegated_permissions_example.js` asserts exactly that
// pair of halves landing on the right entries, which is how much care the
// distinction is worth.
//
// Here the first select does not exist: the client is the entry the reader is
// standing on, and this page cannot be reached without having named it. A
// control that could be half wrong became one that cannot be.
//
// **IT POSTS TO /admin/delegation AND THAT IS DELIBERATE.** A
// `grant-permission` action on this page's own handler would mean a sixth entry
// in APPLICATION_ACTIONS, and rule 7's parity check reads that list off the
// handler's refusal sentence — so it would then want a `POST
// /admin-api/applications/grant-permission` beside the `POST
// /admin-api/permissions/grant-permission` that already exists, which is two
// API operations for one write. Moving a FORM is not moving an ACTION. The
// settings forms on twenty-one pages already do this: they are drawn where the
// setting belongs and post to /admin/config, which sends the reader back to the
// page the form was on. `from` is that field here, and permissionsReturnTo()
// rebuilds the destination rather than echoing it, for configReturnTo()'s
// reason.
//
// WHAT IS NOT OFFERED, and each for its own reason:
//   * this application's OWN permissions — the token would be audienced to
//     itself, which is what an ID Token already is, and app_permissions.js
//     refuses it anyway. Offering an option whose only outcome is a refusal is
//     a control that can only fail.
//   * permissions it ALREADY holds — the second grant is a no-op and the
//     sentence it comes back with says nothing the table above it does not.
//   * permissions with no identifier — nothing can ever ask for one, so a
//     grant of it is a value no request will match. The delegation page says
//     which ones those are and why.
//
// The table above the form is the read-back and it is what makes this a
// section rather than a stray button: a write whose result you cannot see on
// the page that took it is a write you have to go somewhere else to trust.
// ---------------------------------------------------------------------------
// The two halves of ONE application's delegated permissions, and what may still
// be granted to it — in a pure function for permissionsListState()'s reason:
// the drill-down's `?format=json` has to report the same answer, and there is
// no reading it back out of a string of markup.
function applicationPermissionsState(query, identifier) {
  log.debug("Entering applicationPermissionsState(). identifier=" + identifier);
  const register = appPermissions.register();
  // WHAT THIS APPLICATION HOLDS, off the same register the delegation page
  // draws rather than off the entry's attribute — the attribute is the raw
  // identifier and nothing else, and everything a reader needs beside it
  // (which application exposes it, what the token will say, whether it has
  // ever been asked for) is the resolution that module does.
  const held = register.grants.filter(function (one) {
    return one.client === identifier;
  });
  // AND WHAT IT EXPOSES, which is the other half of the same question and is
  // read-only on that page: `Expose an API` and `Define a permission` stay on
  // /admin/delegation, where the resource half of this feature is configured.
  const exposes = register.permissions.filter(function (one) {
    return one.resource === identifier;
  });
  const heldIds = held.map(function (one) { return one.permissionId; });
  log.debug("Leaving applicationPermissionsState(). " + held.length +
            " held, " + exposes.length + " exposed.");
  return {
    register: register,
    held: held,
    exposes: exposes,
    // WHAT MAY STILL BE GRANTED. See the section's header for why each of the
    // three exclusions is an exclusion rather than an option that refuses.
    offerable: register.permissions.filter(function (one) {
      return !!one.id && one.resource !== identifier &&
             heldIds.indexOf(one.id) < 0;
    }),
    // BOTH TABLES ARE PAGED, at the same ten rows /admin/delegation uses and
    // for the same reason: neither is bounded by anything — one client can be
    // granted every permission in the registry, and one resource can expose any
    // number — and that drill-down already carries the attribute table above
    // them. They take page parameters of their own (`heldPage`, `exposedPage`)
    // so that moving one moves neither the other nor the attributes, and they
    // share the page's single `per` with the attribute table, which is the
    // arrangement perPageForm()'s header describes.
    //
    // NEITHER IS IN LIST_PARAMS AND THAT IS DELIBERATE — `attributesPage` is
    // not either. Those names are a DRILL-DOWN's own leaves; what LIST_PARAMS
    // carries is the state of the LIST the page hangs under, and a page number
    // from in here would be spent by /admin/applications, which has no such
    // table.
    heldPage: pagedRows(query, held,
      { name: 'held', noun: 'permissions', defaultPer: DELEGATION_PER_PAGE }),
    exposedPage: pagedRows(query, exposes,
      { name: 'exposed', noun: 'permissions', defaultPer: DELEGATION_PER_PAGE })
  };
}

// WHAT /admin/federation ANSWERS: the relationships, and one of them.
function federationListJson(req) {
  log.debug("Entering federationListJson().");
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
  log.debug("Leaving federationListJson().");
  return {
    all: all, wantedText: wantedText, wantedRole: wantedRole,
    filtered: filtered, paging: paging, paged: paged,
    json: (function () {
    return {
        relationshipCount: all.length, matched: filtered.length,
        shown: paged.shown.length,
        ready: all.filter(function (r) { return r.usable; }).length,
        filter: { q: String(req.query.q || '') || null,
                  role: wantedRole || null },
        page: paging.page, pages: paging.pages, perPage: paging.perPage,
        firstRow: paging.firstRow, lastRow: paging.lastRow,
        container: federation.containerDn(), max: federation.maxRelationships(),
        settings: configSettingsJson('/admin/federation'),
        roles: federation.ROLES, protocols: federation.PROTOCOLS,
        paths: federation.PATHS,
        relationships: paged.shown
    };
    }())
  };
}

// The relationship drill-down. The three URLs are the ones the page prints
// AND the ones the resource publishes — computed once so a partner reading
// the document and an operator reading the page are told the same endpoint.
function federationDetailJson(req, id) {
  log.debug("Entering federationDetailJson(). id=" + id);
  const record = federation.get(id);
  if (!record) {
    log.debug("Leaving federationDetailJson(). No such relationship.");
    return { record: null, row: null, json: { found: false, id: id } };
  }
  const row = federationRow(record);
  // ---------------------------------------------------------------------
  // THE ADDRESSES TO GIVE THE PARTNER, and they are the whole point of this
  // page: an operator copies them into somebody else's identity service, where
  // being wrong is a federation that fails at the far end with nothing here to
  // point at.
  //
  // `baseUrlOf(req)` is the ONLY way to build one. This was
  // `'http://' + req.get('host')` until 2026-08-26 — the one place in this file
  // that did not go through that helper — and it was wrong three ways at once,
  // each of them invisible on a default deployment:
  //
  //   * NO REALM PREFIX. A relationship is an entry in one realm's own
  //     register and its assertion consumer service answers only under that
  //     realm's prefix, so the URL printed here named a path that 404s — while
  //     the AuthnRequest this service actually sends carries the right one,
  //     because federation_sp.js does use baseUrlOf(). The page and the wire
  //     disagreed, and the page is the half a person reads.
  //   * ALWAYS `http://`, on a service that binds TLS whenever `global.https`
  //     is set — which every launcher in the parent project's suite does.
  //   * NO FORWARDED HEADERS, so a deployment behind a proxy with
  //     `global.trustProxy` on was told its own internal address.
  // ---------------------------------------------------------------------
  const base = baseUrlOf(req);
  const acs = base + federation.PATHS.acs + '/' + encodeURIComponent(row.id);
  const login = federation.PATHS.login + '/' + encodeURIComponent(row.id);
  const metadata = base + federation.PATHS.metadata + '/' +
                   encodeURIComponent(row.id);
  // AND THE SAME PATH AGAIN, PREFIXED, FOR THE JSON — which is not a
  // duplicate. `login` above is used in an `href` on this page and must stay
  // ROOT-RELATIVE, because app.js's realm middleware rewrites root-relative
  // hrefs in an HTML response on the way out and its regex has no idempotence
  // guard: a path prefixed here would leave the page carrying
  // /realm/acme/realm/acme/federation/login/x. That rewrite runs on `text/html`
  // ONLY, so the JSON reply is never touched and has to carry the prefix
  // itself. `realms.href()` is the guarded version and is safe either way.
  const loginPath = realms.href(login);

  const setFields = federation.fieldsForRole(row.role, 'set')
                              .filter(function (field) {
    // The four booleans get their own two-button control below, because a text
    // box a person types TRUE into is a text box a person types "true", "yes"
    // and "1" into — and one of those is how a relationship stays disabled
    // while the page says it is on.
    return ['fedEnabled', 'fedAutocreateUsers', 'fedUpdateUserAttributes',
            'fedSignRequest', 'fedAllowUnsolicited'].indexOf(field.name) === -1;
  });
  const multiFields = federation.fieldsForRole(row.role, 'multi');

  log.debug("Leaving federationDetailJson().");
  return {
    record: record, row: row, base: base, acs: acs, login: login,
    metadata: metadata, loginPath: loginPath,
    setFields: setFields, multiFields: multiFields,
    json: (function () {
    return Object.assign({ found: true }, row, {
        endpoints: { assertionConsumerService: acs, login: loginPath,
                     metadata: (row.protocol === 'saml2' ||
                                row.protocol === 'saml11')
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
              out[field.name] = record[field.name] ? '(set — not returned)' :
                                '';
              return;
            }
            out[field.name] = record[field.name];
          });
          return out;
        })(),
        editable: federation.fieldsForRole(row.role)
    });
    }())
  };
}

// `?relationship=` means the drill-down — NOT `?id=`, which is what a first
// pass of this assumed from the detail function's parameter name. The dispatch
// has to read the same query key the page reads, or the resource answers the
// LIST for every drill-down and a caller asking about one relationship is told
// about all of them.
function federationJson(req) {
  log.debug("Entering federationJson().");
  const wanted = String((req.query || {}).relationship || '').trim();
  log.debug("Leaving federationJson().");
  return wanted ? federationDetailJson(req, wanted).json :
         federationListJson(req).json;
}

// One row's summary, shared by the list and the JSON. It is a function rather
// than being built inline twice because the READINESS is computed here — the
// page prints it and the API answers it, and two computations of "is this
// partner usable" would be two answers to the question the whole page is about.
function federationRow(record) {
  log.debug("Entering federationRow().");
  const readiness = federation.readinessOf(record);
  log.debug("Leaving federationRow().");
  return {
    id: record.fedId,
    name: record.fedName || record.fedId,
    role: record.fedRole,
    roleLabel: (federation.roleRow(record.fedRole) ||
                {}).short || record.fedRole,
    protocol: record.fedProtocol,
    protocolLabel: (federation.protocolRow(record.fedProtocol) ||
                    {}).label || record.fedProtocol,
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

// WHAT /admin/users ANSWERS: the population, and one person.
//
// `authenticatedHere` and `factorCounts` come with the computation although
// the page declares them among its markup — they are filters over the same
// list, and the tiles a person reads must be the numbers the resource
// publishes. The second-factor roster is exactly that: one tally, two
// renderings.
function usersListJson(req) {
  log.debug("Entering usersListJson().");
  log.debug("Entering usersListPage().");
  const wantedText = String(req.query.q || '').trim();
  const wantedProtocol = String(req.query.protocol || '');
  // THE UNION, not `stats.userRows()` — see peopleRows(). The registry is
  // capped at two thousand and the directory is not, so on a realm that has
  // been bulk loaded this is the difference between a page that answers *who
  // holds no second factor* and one that answers it for the first two thousand
  // people it happens to remember.
  const population = peopleRows();
  const all = population.rows;
  // The second-factor filter, which arrived with the roster on 2026-09-10. It
  // is `factor` rather than `mfa` because that is the name `/admin/mfa` used
  // and a link somebody bookmarked should keep working against the page that
  // absorbed it — the same courtesy `listViewFromBack()` extends to a filter
  // carried across a form.
  const wantedFactor = String(req.query.factor || '');
  // Every protocol any known user authenticated through, for the filter. Read
  // off the data rather than written down, so a protocol that starts recording
  // authentications appears in the dropdown by itself and one that never has
  // cannot offer a filter that matches nothing.
  const protocolsSeen = {};
  all.forEach(function (row) {
    row.protocols.forEach(function (family) {
      protocolsSeen[family.protocol] = true;
    });
  });
  const filtered = all.filter(function (row) {
    if (wantedText &&
        row.key.toLowerCase()
               .indexOf(wantedText.toLowerCase()) < 0) return false;
    if (wantedProtocol &&
        !row.protocols.some(function (f) {
          return f.protocol === wantedProtocol;
        })) {
      return false;
    }
    // `factors` is null where no credential store answered at all. Such a row
    // matches NO factor filter rather than matching `none`, because "this
    // service cannot tell" and "this person holds none" are different answers
    // and the second one is the dangerous one to guess.
    const factors = row.factors;
    if (wantedFactor === 'totp' && !(factors && factors.totp)) return false;
    if (wantedFactor === 'key' &&
        !(factors && factors.mfaKeys > 0)) return false;
    if (wantedFactor === 'any' &&
        !(factors && factors.mfaRequired)) return false;
    if (wantedFactor === 'none' &&
        !(factors && !factors.mfaRequired)) return false;
    if (wantedFactor === 'unreadable' &&
        !(factors && factors.totp && !factors.totpUsable)) return false;
    return true;
  });
  const paging = pagingOf(req.query, filtered.length);
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  const filterParams = { q: wantedText, protocol: wantedProtocol,
                         factor: wantedFactor,
                         per: req.query.per ? paging.perPage : '' };
  const authenticatedHere = all.filter(function (
      row) { return row.authenticated; }).length;
  const factorCounts = {
    withSecond: all.filter(function (r) {
      return r.factors && r.factors.mfaRequired;
    }).length,
    withTotp: all.filter(function (r) {
      return r.factors && r.factors.totp;
    }).length,
    withKeys: all.filter(function (r) {
      return r.factors && r.factors.mfaKeys > 0;
    }).length,
    primaryKeys: all.filter(function (r) {
      return r.factors && r.factors.primaryKeys > 0;
    }).length,
    passwordOnly: all.filter(function (r) {
      return r.factors && r.factors.password && !r.factors.mfaRequired;
    }).length,
    unreadable: all.filter(function (r) {
      return r.factors && r.factors.totp && !r.factors.totpUsable;
    }).length,
    // NOBODY CAN SIGN IN AS THEM. A person with an entry and no password and
    // no primary key — the ordinary state of somebody provisioned and not yet
    // activated, and the state an activation link exists to end. It is counted
    // beside the second-factor tiles because it is the OTHER question an
    // operator brings to a roster of people.
    noCredential: all.filter(function (r) {
      return r.factors && !r.factors.usable && !r.isClient;
    }).length
  };
  log.debug("Leaving usersListJson().");
  return {
    wantedText: wantedText, wantedProtocol: wantedProtocol,
    population: population,
    all: all, wantedFactor: wantedFactor, protocolsSeen: protocolsSeen,
    filtered: filtered, paging: paging, shown: shown, filterParams:
                                                        filterParams,
    authenticatedHere: authenticatedHere, factorCounts: factorCounts,
    json: (function () {
    return {
        known: all.length, matched: filtered.length, shown: shown.length,
        authenticatedHere: authenticatedHere,
        // THE SECOND-FACTOR ROSTER, HERE RATHER THAN ON A RESOURCE OF ITS OWN
        // (2026-09-10). `GET /admin-api/mfa` answers out of this same view, so
        // there is one tally and the console and the API cannot disagree about
        // how many people hold a second factor. Each row carries its own
        // `factors` object; these are the counts over the whole population.
        factors: factorCounts,
        // WHICH POPULATION THIS IS, so a caller reading `known` knows what it
        // counted. `capped` is the one to check on a bulk-loaded realm: past it
        // the credential columns are absent rather than false.
        store: population.store, scanned: population.scanned,
        capped: population.capped, scanLimit: population.limit,
        registryCap: population.registryCap,
        filter: { q: wantedText || null, protocol: wantedProtocol || null,
                  factor: wantedFactor || null },
        protocols: Object.keys(protocolsSeen).sort(),
        page: paging.page, pages: paging.pages, perPage: paging.perPage,
        firstRow: paging.firstRow, lastRow: paging.lastRow,
        users: shown
    };
    }())
  };
}

// The list. Filtered by a name fragment and by protocol, and paged with the
// same controls the tokens page uses.
// ===========================================================================
// EVERYBODY THIS REALM KNOWS ABOUT, AND WHAT EACH OF THEM CAN SIGN IN WITH
// (2026-09-10).
//
// **THIS PAGE'S POPULATION WIDENED ON THE DAY `/admin/mfa` WAS TAKEN AWAY.**
// It was `stats.userRows()` — identities this service has SEEN — and its own
// lead paragraph said so. `/admin/mfa` drew a different population: the union
// of that with this realm's DIRECTORY people, because the question it answered
// was *who holds no second factor* and the people most likely to hold none are
// exactly the ones who have never signed in.
//
// Folding that roster into this page without widening the population would
// have answered that question wrongly and quietly. So this function is the
// union, and the page says which side of it each row came from.
//
// ---------------------------------------------------------------------------
// THE GAP IS SMALLER THAN IT LOOKS AND IT IS NOT ZERO, WHICH IS WHY THIS IS
// NOT A ONE-LINE CHANGE.
//
// Most directory people are ALREADY on `stats.userRows()`: every door that
// creates one — the console, `POST /admin-api/users/create`, a SCIM create, an
// LDAP add, a restore from the persistence store — calls
// `stats.noteKnownIdentity()`, which is what put `knownBy` on a row. So on a
// small service the union adds nothing at all.
//
// **THE REGISTRY IS CAPPED AT `stats.MAX_USERS` AND THE DIRECTORY IS NOT.**
// Two thousand against `ldap.maxEntries`, so a realm with five thousand people
// has at most two thousand of them here — and the three thousand missing are
// invisible on every console page that asks a question about people. That is
// the case this union exists for, and it is the case a bulk load produces.
//
// ---------------------------------------------------------------------------
// KEYED BY THE IDENTITY KEY AND NOT BY THE NAME.
//
// `credentials.secondFactorHolders()` dedupes case-insensitively on the raw
// name; this page's whole premise is that ONE ROW IS ONE LOCAL NAME ACROSS
// EVERY PROTOCOL, which is `stats.identityKeyOf()`. Two spellings that reach
// the same identity key have to fold into one row here or the warning at the
// top of the table stops being true. Where they do fold, the factor facts are
// UNIONED rather than one of them winning: holding a key under one spelling
// and an app under another is holding both.
// ===========================================================================
function peopleRows() {
  log.debug("Entering peopleRows().");
  const seen = stats.userRows();
  const byKey = new Map();
  seen.forEach(function (row) {
    // `factors` is filled below. Declared here so that every row has the member
    // whether or not the credential store answered — a page that read
    // `row.factors.totp` off a row that had none would throw on the one
    // deployment with no directory, which is the deployment least able to
    // report it.
    row.factors = null;
    row.inDirectory = false;
    byKey.set(row.key, row);
  });

  const holders = credentials.secondFactorHolders(seen.map(function (row) {
    return row.key;
  }));

  holders.rows.forEach(function (holder) {
    const key = stats.identityKeyOf(holder.username);
    if (!key) return;
    let row = byKey.get(key);
    if (!row) {
      // A DIRECTORY PERSON THIS SERVICE HAS NEVER SEEN. Synthesised with the
      // same shape `blankUserRow()` produces, because every cell of this table
      // and every member of the JSON reply reads it — a row missing `tokens`
      // would be a column that throws rather than a column that says nothing.
      // **THE SHAPE `userRows()` RETURNS AND NOT THE ONE `blankUserRow()`
      // BUILDS.** Those differ: the registry counts forms, realms, protocols
      // and artifact kinds in OBJECTS and converts every one of them to an
      // ARRAY on the way out. A row synthesised from the blank shape reaches
      // this page with `row.realms.map is not a function` — which is what the
      // first version of this did, on the one row type nothing else produces.
      row = { key: key, name: holder.username, forms: [], realms: [],
              protocols: [], authentications: 0, firstAt: 0, lastAt: 0,
              isClient: false, authenticated: false, knownBy: 'directory',
              events: [], eventsForgotten: 0,
              tokens: { issued: 0, valid: 0, expired: 0, revoked: 0, other: 0 },
              artifactKinds: [], artifacts: 0, lastActivityAt: 0,
              factors: null, inDirectory: false };
      byKey.set(key, row);
    }
    row.inDirectory = row.inDirectory || !!holder.inDirectory;
    row.factors = mergeFactors(row.factors, holder);
  });

  const rows = Array.from(byKey.values());
  rows.sort(function (a, b) {
    return String(a.name).toLowerCase() < String(b.name).toLowerCase() ? -1 : 1;
  });
  log.debug("Leaving peopleRows(). " + rows.length + " person/people, " +
            holders.scanned + " scanned in the directory.");
  return { rows: rows, store: holders.store, scanned: holders.scanned,
           capped: holders.capped, limit: holders.limit,
           registryCap: stats.MAX_USERS };
}

// TWO SPELLINGS THAT FOLD INTO ONE ROW HOLD THE UNION OF WHAT EACH HELD. Taking
// the first would answer "no second factor" for somebody who has one under
// their other name, which is the wrong answer in the direction that matters:
// this table is read to find people who are NOT protected.
function mergeFactors(into, holder) {
  log.debug("Entering mergeFactors().");
  if (!into) {
    log.debug("Leaving mergeFactors().");
    return {
      password: !!holder.password,
      primaryKeys: holder.primaryKeys || 0,
      mfaKeys: holder.mfaKeys || 0,
      totp: !!holder.totp,
      totpUsable: !!holder.totpUsable,
      totpDetail: holder.totpDetail || null,
      mfaRequired: !!holder.mfaRequired,
      secondFactor: holder.secondFactor || '',
      usable: !!holder.usable,
      // **THE RECOVERY CODES (2026-09-11), AND THIS FUNCTION IS WHERE THEY
      // WERE BEING LOST.** `credentials.secondFactorHolders()` has always put
      // a `backupCodes` member on every row, and this merge built an explicit
      // shape without it — so the counts reached neither `/admin/users` nor
      // `GET /admin-api/mfa`, and an operator could see that somebody held an
      // authenticator and not that they had used nine of their ten ways back.
      //
      // Counts and never codes: `backupCodeStatus()` is what the member is
      // built from and it carries none.
      backupCodes: holder.backupCodes || null,
      recoveryAdvised: !!holder.recoveryAdvised
    };
  }
  into.password = into.password || !!holder.password;
  into.primaryKeys += (holder.primaryKeys || 0);
  into.mfaKeys += (holder.mfaKeys || 0);
  // `totpUsable` is only meaningful where `totp` is, so the two move together —
  // an enrolment this process cannot read must not be reported as absent, which
  // would sign somebody in on one factor.
  if (holder.totp && !into.totp) {
    into.totp = true;
    into.totpUsable = !!holder.totpUsable;
    into.totpDetail = holder.totpDetail || null;
  }
  into.mfaRequired = into.mfaRequired || !!holder.mfaRequired;
  into.usable = into.usable || !!holder.usable;
  // **A SET FOUND UNDER EITHER SPELLING WINS, WHICH IS `totp`'s RULE ABOVE
  // AND FOR ITS REASON.** This table is read to find people who are NOT
  // protected, so taking the first row's answer would report "no recovery
  // codes" for somebody who holds a set under their other name — the wrong
  // answer in the direction that matters.
  if (holder.backupCodes && holder.backupCodes.present && !(into.backupCodes &&
      into.backupCodes.present)) {
    into.backupCodes = holder.backupCodes;
  } else if (!into.backupCodes) {
    into.backupCodes = holder.backupCodes || null;
  }
  // **AND THE ADVICE IS THE OTHER WAY ROUND: ALL OF THEM MUST WANT IT.** It is
  // true of somebody with a second factor and no set, so a spelling that holds
  // the set makes it false for the person — the union of two rows must not
  // tell an operator to chase somebody who is already covered.
  into.recoveryAdvised = (into.recoveryAdvised || !!holder.recoveryAdvised) &&
                         !(into.backupCodes && into.backupCodes.present);
  into.secondFactor = into.mfaKeys > 0 ? 'webauthn'
                    : (into.totp ? 'totp' : '');
  log.debug("Leaving mergeFactors().");
  return into;
}

// One person: their sessions, what was issued on each, and the credentials
// they hold. The four paged lists come with the computation although the page
// declares them among its markup — the resource publishes each one's paging.
function userDetailJson(req, key) {
  log.debug("Entering userDetailJson(). key=" + key);
  log.debug("Entering userDetailPage(). key=" + key);
  let detail = stats.userDetail(key);
  if (!detail) {
    // ---------------------------------------------------------------------
    // A PERSON THE DIRECTORY HOLDS AND THE REGISTRY DOES NOT (2026-09-10).
    //
    // **THE LIST ABOVE STARTED LISTING THEM ON THIS DAY** — see peopleRows()
    // — and until this branch existed, clicking one landed on *nothing here
    // has authenticated as alice*. That is a true sentence and a useless
    // page: it is exactly the person whose second factor an operator has come
    // to look at, and both Clear buttons are on this page.
    //
    // So the registry's absence is filled with a blank record rather than
    // treated as a missing person. Every section below reads `detail.tokens`,
    // `detail.artifacts` and the row's counted arrays, and every one of them
    // is legitimately empty here: this identity has never signed in, so it
    // holds no session and nothing has been issued to it. The DIRECTORY and
    // SECOND FACTOR sections are the two that have something to say, and they
    // are the two that were unreachable.
    // ---------------------------------------------------------------------
    const inDirectory = !!(directoryReader && directoryReader(key).found);
    if (!inDirectory) {
      log.debug("Leaving userDetailPage(). No such user, and no entry either.");
      return null;
    }
    detail = {
      user: { key: key, name: key, forms: [], realms: [], protocols: [],
              authentications: 0, firstAt: 0, lastAt: 0, isClient: false,
              authenticated: false, knownBy: 'directory', events: [],
              eventsForgotten: 0,
              tokens: { issued: 0, valid: 0, expired: 0, revoked: 0, other: 0 },
              artifactKinds: [], artifacts: 0, lastActivityAt: 0 },
      tokens: [], artifacts: []
    };
    log.debug("userDetailPage(). Directory-only: a blank registry record.");
  }
  const row = detail.user;
  const sessionRows = sessionRowsFor(key);
  const live = sessionRows.filter(function (s) { return !s.expired; });
  const split = tokensBySession(detail.tokens, sessionRows);
  // Where a revoke button on this page returns to: this user's page, which is
  // the only sensible answer — the reader is looking at one person and wants to
  // see the effect on that person. It carries the whole query and not just the
  // name, so the answer is the page of the table the button was on rather than
  // the first page of all five; backTo() picks the page parameters back out by
  // shape.
  //
  // `params` is the whole current query carried through, and every control on
  // this page rides on it, so moving one of the five lists leaves the other
  // four where they are. See pageParamsOf() for why it is carried rather than
  // listed.
  const params = pageParamsOf(req.query);
  const back = queryWith(params, {});
  const valid =
      detail.tokens.filter(function (t) { return t.state === 'valid'; }).length;
  // Counted beside `valid` because "issued" minus "valid" is not "expired" — a
  // revoked token, one not yet valid and one with no expiry stated all sit in
  // that difference, and a reader doing the subtraction gets the wrong answer
  // silently. It is its own tile for the same reason the users table grew its
  // own column: a token running out of time is the ordinary end of a token and
  // the first thing to check when a client starts being refused.
  const expired = detail.tokens.filter(function (
      t) { return t.state === 'expired'; }).length;
  // Read before the markup is assembled rather than inside it, because it is
  // also one of the keys of the JSON view below and reading it twice could show
  // a page and a JSON body that disagree about a directory another request just
  // changed. The two panels' answers, from the functions above rather than from
  // the console sections that draw them.
  const directory = { json: ldapObjectJson(key) };
  // The second factors, on the same terms and for the same reason (2026-09-10).
  // `gateStateFor()` decides whether the two removals are drawn at all; it is
  // read HERE rather than inside the section because the section is also called
  // for `?format=json`, where there is no button to draw and the answer is
  // still needed for the write half of `/admin-api/users`.
  const mfa = { json: mfaJson(key) };
  // The assertion key pairs (2026-09-13), read once for the reason the two
  // panels above are: the page and the reply must not disagree about one read.
  const credentialsState = personCredentialsState(key);

  // Five lists on one page, each with its own page parameter and all of them
  // sharing `per` — see pagingOf() for why it is that way round.
  //
  // What is deliberately NOT paged here: the names this identity has been seen
  // under, the protocols it authenticated through, and the authentication
  // events. The first two are bounded by how many spellings and protocols
  // exist, and the third is capped at stats.MAX_EVENTS_PER_USER — fifty — by
  // the registry itself, which is the note authenticationTable() already
  // prints. Paging a list that cannot exceed fifty would buy a control nobody
  // will see, and it would cost something real: all three live on `row`, which
  // goes out whole as this reply's `user`, so slicing them for the table would
  // either corrupt that object or duplicate it, and leaving the JSON whole
  // while the table paged is the console-and-API disagreement this file keeps
  // warning about.
  const sessionPage = pagedRows(req.query, sessionRows,
    { name: 'sessions', noun: 'sessions',
      defaultPer: DEFAULT_BLOCKS_PER_PAGE });
  const sessionTokenPages = sessionPage.shown.map(function (session) {
    return pagedRows(req.query, split.held[session.id] || [],
                     { name: 'session-' + session.id, noun: 'tokens' });
  });
  const endedPage = pagedRows(req.query, split.ended,
                              { name: 'tokensOnEndedSessions',
                                noun: 'tokens' });
  const sessionlessPage = pagedRows(req.query, split.sessionless,
                                    { name: 'tokensWithNoSession',
                                      noun: 'tokens' });
  const artifactPage = pagedRows(req.query, detail.artifacts,
                                 { name: 'artifacts', noun: 'artifacts' });
  log.debug("Leaving userDetailJson().");
  return {
    detail: detail, row: row, sessionRows: sessionRows, live: live,
    split: split,
    // `back` is handed over with the rest: the page's sign-out and revoke
    // forms carry it, and a first pass of the split left it out, so both
    // forms posted `back=undefined`.
    params: params, back: back, valid: valid, expired: expired, directory:
                                                                  directory,
    mfa: mfa, credentialsState: credentialsState,
    sessionPage: sessionPage, sessionTokenPages: sessionTokenPages,
    endedPage: endedPage, sessionlessPage: sessionlessPage, artifactPage:
                                                              artifactPage,
    json: (function () {
    return {
        user: row,
        // THE PERSON'S SUBJECT (2026-09-14): `urn:uuid:<entryUUID>`, the `sub`
        // every token issued to them carries — '' where the directory holds
        // no entry for them. Said here because it is no longer derivable from
        // the name, and "which sub is this person" is the first thing somebody
        // matching a relying party's records to this page needs.
        subject: subjectForName(key),
        // WHAT THEY CAN SIGN IN WITH, and what they are asked for as a second
        // factor (2026-09-10). It is `factors` here and on every row of the
        // list, so a caller reads one member name whichever view it fetched.
        factors: mfa.json,
        // Every array here is THE PAGE, not the whole list, exactly as `users`
        // is on the list view — and every one of them is answered by a
        // `*Paging` object carrying the same member names one level down, so a
        // caller walks a drill-down's five lists the way it already walks the
        // three flat ones. A session's own tokens are paged too and its paging
        // travels with it, because there is one such list per session and no
        // top-level place to put five of them that would still say which was
        // which.
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
        // null when no directory is loaded in this process, which is a
        // different answer from an entry that is not there — that one is an
        // object whose `found` is false and which says where it would have
        // been.
        ldap: directory.json,
        // THE ASSERTION KEY PAIRS (2026-09-13) — `credentials`, the member
        // name an application's drill-down uses for its own. No private key,
        // for the reason personCredentialsState() gives.
        credentials: credentialsState.json
    };
    }())
  };
}

// `?user=` means the drill-down.
// `?user=` means the drill-down.
//
// **`known: true` IS ADDED HERE AND THAT IS NOT DECORATION.** The console's
// `usersView()` wrapped the detail as `Object.assign({ known: true },
// detail.json)`, and a first pass of this returned the bare json — so
// `/admin-api/users?user=…` answered a complete record with no `known` in it,
// and the one job that asks about a DIRECTORY-ONLY person read that as "this
// person does not exist". The page was right and the resource was wrong, which
// is the exact shape of disagreement this whole directory exists to prevent.
function usersJson(req) {
  log.debug("Entering usersJson().");
  const wanted = String((req.query || {}).user || '').trim();
  if (!wanted) {
    log.debug("Leaving usersJson().");
    return usersListJson(req).json;
  }
  const detail = userDetailJson(req, wanted);
  if (!detail) {
    log.debug("Leaving usersJson().");
    return { user: wanted, known: false };
  }
  log.debug("Leaving usersJson().");
  return Object.assign({ known: true }, detail.json);
}

// THE SECOND-FACTOR ANSWER FOR ONE PERSON. `mfaSection()` on the console
// draws the panel and takes its json from here, so the card a person reads and
// the resource a machine fetches describe one set of credentials.
//
// IT CARRIES NO CODES AND NO PUBLIC KEYS — see the comments inside. A caller
// holding admin:read is never handed a working second factor.
function mfaJson(key) {
  log.debug("Entering mfaJson(). key=" + key);
  const mech = credentials.mechanismsFor(key);
  if (!mech) {
    log.debug("Leaving mfaJson(). No credential store.");
    return null;
  }
  const totpLive = totp.settings();
  const keyLive = webauthnPolicy.settings();
  const recoveryLive = backupCodes.settings();
  log.debug("Leaving mfaJson().");
  return {
    // The mechanisms as the credential store answers them, minus the public
    // keys — a JWK per credential is several hundred bytes of no use to a
    // caller asking who holds what, and this reply is already the largest on
    // the console.
    password: mech.password,
    // WHAT AN ADMINISTRATOR HAS DECIDED ABOUT THEM (2026-09-13): whether the
    // password must be changed at their next sign-in, a password reset link
    // outstanding (an expiry, never a token), and whether a second factor is
    // REQUIRED of them — by their own entry or by the realm — which is a
    // different question from `mfaRequired` below, what they HOLD.
    passwordChangeRequired: credentials.passwordResetRequired(key),
    passwordResetLink: mech.passwordResetLink || null,
    mfaRequirement: mech.mfaRequirement ||
      { required: false, byUser: false, byRealm: false },
    usable: mech.usable,
    activated: mech.activated,
    mfaRequired: mech.mfaRequired,
    secondFactor: mech.secondFactor || null,
    totp: mech.totp,
    totpUsable: mech.totpUsable,
    totpDetail: mech.totpDetail,
    // THE RECOVERY CODES AS A STATUS AND NEVER AS CODES — see the block
    // above. `credentials.backupCodeStatus()` is what fills it and it
    // carries none, so there is no shape of this reply in which a caller
    // holding `admin:read` is handed a working second factor.
    backupCodes: mech.backupCodes,
    keys: (mech.keys || []).map(function (one) {
      return { credentialId: one.credentialId, role: one.role,
               label: one.label || null, signCount: one.signCount || 0,
               enrolledAt: one.enrolledAt || 0 };
    }),
    primaryKeys: mech.primaryKeys,
    mfaKeys: mech.mfaKeys,
    // WHAT THE REALM ALLOWS, beside what the person holds, because the two
    // together are the answer to "why can they not enrol one" — and a caller
    // that had to fetch /admin-api/webauthn as well would be reading a
    // second request's answer against this one's.
    policy: { totpEnabled: totpLive.enabled,
              backupCodesEnabled: recoveryLive.enabled,
              backupCodesCount: recoveryLive.count,
              webauthnEnabled: keyLive.enabled,
              primaryAllowed: keyLive.primaryAllowed,
              mfaAllowed: keyLive.mfaAllowed,
              maxKeysPerPerson: keyLive.maxKeysPerPerson }
  };
}

// THIS PERSON'S DIRECTORY ENTRY, which is the whole json half of the panel
// `ldapObjectSection()` draws: `directoryReader(key)`, or null where no
// directory is loaded in this process. The section keeps the markup and takes
// this for its answer.
function ldapObjectJson(key) {
  log.debug("Entering ldapObjectJson(). key=" + key);
  if (!directoryReader) {
    log.debug("Leaving ldapObjectJson(). No directory is loaded.");
    return null;
  }
  log.debug("Leaving ldapObjectJson().");
  return directoryReader(key);
}

// A query string built from what the caller is already looking at plus an
// override. Every paging link goes through this, because a "next" that dropped
// `?kind=` would be page 2 of a different list — the bug this exists to make
// impossible rather than merely avoidable. Empty values are omitted so the URL
// of the unfiltered first page is the bare path.
function queryWith(params, overrides) {
  log.debug("Entering queryWith().");
  const merged = Object.assign({}, params, overrides);
  const parts = [];
  Object.keys(merged).forEach(function (key) {
    const value = merged[key];
    if (value === '' || value === null || value === undefined) {
      return;
    }
    parts.push(encodeURIComponent(key) + '=' +
               encodeURIComponent(String(value)));
  });
  log.debug("Leaving queryWith().");
  return parts.length ? '?' + parts.join('&') : '';
}

// The live sign-on sessions belonging to one user. Sessions are keyed by an
// opaque id and hold a user object, so the match is on the identity rather than
// the string: the session says `alice` and the tokens say
// `urn:uuid:<entryUUID>`, and these have to end up on the same page.
function sessionRowsFor(key) {
  log.debug("Entering sessionRowsFor(). key=" + key);
  const rows = signOnSessionRows().filter(function (session) {
    return stats.holderKeyOf(session.username, session.sub) === key;
  });
  log.debug("Leaving sessionRowsFor(). " + rows.length + " session(s).");
  return rows;
}

// The tokens of one user, split by the session they were issued on.
//
// Three buckets, and the third is the one worth explaining. A token whose
// record names a session that is no longer held is not an error: sessions
// expire and are swept, and the token outlives the sign-on it came from — that
// is exactly the state an OIDC client is in when its ID Token still verifies
// and the browser would be asked to sign in again. Showing those under "no
// session" would say something false about how they were issued.
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
  log.debug("Leaving tokensBySession(). " + Object.keys(held).length + " " +
      "session(s), " +
            ended.length + " on an ended session, " + sessionless.length + " " +
                "with none.");
  return { held: held, ended: ended, sessionless: sessionless };
}

// Rows per page for a list whose ROW IS A TABLE. There is one of those — the
// session blocks on the users drill-down, where each row of the list is a
// session heading, a facts table and a token table under it — and giving it
// DEFAULT_PER_PAGE would put fifty tables on one page, each of which is itself
// paged at fifty rows. The list pages get away with one number because a row
// there is a row.
//
// `?per=` still overrides it, for the same reason it overrides everything else:
// a number somebody typed is a number they meant.
const DEFAULT_BLOCKS_PER_PAGE = 5;

// ---------------------------------------------------------------------------
// WHAT `GET /admin-api/mfa` AND `POST /admin-api/mfa/:action` CALL NOW.
//
// **THE RESOURCE IS KEPT AND ITS PAGE IS GONE**, which is rule 7 read the way
// round it is usually not. The rule says a console control owes an API
// operation; it says nothing about an operation whose page moved, and deleting
// a working one to tidy a table would be a regression dressed as consistency —
// the same argument `mgmt-api/admin_api.js` makes about `GET
// /admin-api/users/new`.
//
// **BOTH ANSWER OUT OF THE USERS VIEW**, so there is ONE tally. A second scan
// of the credential store would be a second answer to how many people hold a
// second factor, and the two would agree until the day they did not.
//
// The reply keeps its own SHAPE — a flat `people` array, one object per person,
// exactly the members it always carried — because a caller that reads
// `people[].mfaRequired` is not a caller that should have to learn this page
// moved. `GET /admin-api/users` is where the rows carry `factors` instead.
// ---------------------------------------------------------------------------
function mfaRosterJson(req) {
  log.debug("Entering mfaRosterJson().");
  const list = usersListJson(req);
  const people = (list.json.users || []).map(function (row) {
    const f = row.factors || {};
    return {
      username: row.name,
      inDirectory: !!row.inDirectory,
      known: !!row.authenticated || row.knownBy !== 'directory',
      // FALSE AND NOT NULL where no credential store answered, because every
      // one of these was a boolean before this moved and a caller comparing
      // with `=== false` must not start seeing `null`. `store` on the reply is
      // where "this service could not tell" is said, and it always was.
      password: !!f.password,
      primaryKeys: f.primaryKeys || 0,
      mfaKeys: f.mfaKeys || 0,
      totp: !!f.totp,
      totpUsable: !!f.totpUsable,
      totpDetail: f.totpDetail || null,
      mfaRequired: !!f.mfaRequired,
      secondFactor: f.secondFactor || '',
      usable: !!f.usable,
      // **THE RECOVERY CODES, AS COUNTS AND NEVER AS CODES (2026-09-11).**
      // `secondFactorHolders()` has always built this member and this mapping
      // dropped it, so `/admin/users` drew "7 of 10 unused" for an operator
      // and `GET /admin-api/mfa` answered about the same person without it —
      // which is rule 7's drift in the direction that check cannot see, since
      // the console side was never missing.
      //
      // `backupCodeStatus()` is what the whole member is built from and it
      // carries no codes, which is what makes it safe to publish here: an
      // operator reading this roster must never be handed a working second
      // factor. `hashed` and `legacy` are on it so that a set written by an
      // older build is visible as one rather than looking identical to a
      // hashed set that simply has not been used.
      backupCodes: f.backupCodes || null,
      // And whether this person should be TOLD to generate a set, which is
      // what replaced the automatic issue on 2026-09-11 and is therefore the
      // number an operator now has to be able to see across a population.
      recoveryAdvised: !!f.recoveryAdvised
    };
  });
  const json = {
    offered: totp.offered(),
    totp: totp.report(),
    webauthn: webauthnPolicy.report(),
    counts: Object.assign({ people: list.json.known }, list.json.factors),
    store: list.json.store, scanned: list.json.scanned,
    capped: list.json.capped, scanLimit: list.json.scanLimit,
    filter: list.json.filter,
    page: list.json.page, pages: list.json.pages, perPage: list.json.perPage,
    firstRow: list.json.firstRow, lastRow: list.json.lastRow,
    matched: list.json.matched, shown: list.json.shown,
    people: people
  };
  log.debug("Leaving mfaRosterJson(). " + people.length + " person/people.");
  // THE ROSTER ITSELF. The console page this belonged to split into
  // /admin/totp and /admin/webauthn on 2026-09-10 and the columns moved onto
  // /admin/users, so nothing here draws from this any more — it is the
  // resource, and only the resource.
  return json;
}

// WHAT /admin/logout ANSWERS for one identity: what is live across every
// family, and what a sign-out would reach. `canWrite` is the gate's, because
// the page draws a button and the resource says whether it would be honoured.
// EVERY BRANCH RETURNS THE SAME SHAPE — a model with a `json` in it. The first
// version answered the json directly on its two early paths and a model on the
// third, which left the management API calling it twice to find out which it
// had been given.
function logoutJson(req) {
  log.debug("Entering logoutJson().");
  const wantedUser = String((req.query || {}).user || '').trim();
  const gate = gateStateFor(req);
  const params = pageParamsOf(req.query);
  const families = logoutFamilies();
  if (!wantedUser) {
    log.debug("Leaving logoutJson(). Nobody was named.");
    return { families: families,
             json: { user: '', known: false, families: families } };
  }
  const key = stats.identityKeyOf(wantedUser);
  const inventory = logoutInventoryFor(key);
  // NO LOGOUT READER IN THIS PROCESS. The page draws a note and the trail; this
  // is only the answer half of that branch.
  if (!inventory) {
    log.debug("Leaving logoutJson(). No logout reader.");
    return { inventory: null,
             json: { user: wantedUser, known: false,
                     error: 'no logout reader is installed' } };
  }

  // Flattened, because this table filters and pages ACROSS families — see the
  // header. The family's own prose stays on the summary above it.
  const all = [];
  inventory.families.forEach(function (family) {
    family.rows.forEach(function (r) {
      all.push(Object.assign({ user: wantedUser, familyLabel: family.label },
                             r));
    });
  });
  const wantedFamily = String(req.query.family || '').trim();
  const filtered = wantedFamily
    ? all.filter(function (r) { return r.family === wantedFamily; }) : all;
  const pg = pagedRows(req.query, filtered,
                       { name: 'page', noun: 'live items' });

  const canWrite = gate.write;
  log.debug("Leaving logoutJson(). " + inventory.total + " live item(s).");
  return {
    wantedUser: wantedUser, gate: gate, params: params, families: families,
    key: key, inventory: inventory, all: all, wantedFamily: wantedFamily,
    filtered: filtered, pg: pg, canWrite: canWrite,
    json: Object.assign({ user: wantedUser, known: true, canWrite: canWrite },
                        inventory,
                        { rows: pg.shown, paging: pagingJson(pg.paging) })
  };
}

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
  log.debug("Entering logoutFamilies().");
  log.debug("Leaving logoutFamilies().");
  return logoutReader ? logoutReader.FAMILIES : [];
}

module.exports = {
  logoutInventoryFor: logoutInventoryFor,
  logoutFamilies: logoutFamilies,
  logoutJson: logoutJson,
  mfaRosterJson: mfaRosterJson,
  DEFAULT_BLOCKS_PER_PAGE: DEFAULT_BLOCKS_PER_PAGE,
  queryWith: queryWith,
  sessionRowsFor: sessionRowsFor,
  tokensBySession: tokensBySession,
  ldapObjectJson: ldapObjectJson,
  // The person's `sub` for the console's drill-down (2026-09-14): the same
  // answer the JSON half's `subject` member carries.
  userDetailSubject: subjectForName,
  mfaJson: mfaJson,
  userDetailJson: userDetailJson,
  personCredentialsState: personCredentialsState,
  usersJson: usersJson,
  peopleRows: peopleRows,
  mergeFactors: mergeFactors,
  usersListJson: usersListJson,
  federationRow: federationRow,
  federationDetailJson: federationDetailJson,
  federationJson: federationJson,
  federationListJson: federationListJson,
  applicationPermissionsState: applicationPermissionsState,
  applicationDetailJson: applicationDetailJson,
  applicationsJson: applicationsJson,
  applicationsListJson: applicationsListJson,
  NOT_A_VIEW: NOT_A_VIEW,
  pageParamsOf: pageParamsOf,
  groupDetailJson: groupDetailJson,
  groupsJson: groupsJson,
  setGroupReader: setGroupReader,
  setGroupWriter: setGroupWriter,
  groupsListJson: groupsListJson,
  asDriftRows: asDriftRows,
  asTruthRequest: asTruthRequest,
  asDetailJson: asDetailJson,
  authorizationServersJson: authorizationServersJson,
  asListJson: asListJson,
  saml11RelyingParties: saml11RelyingParties,
  saml11Facts: saml11Facts,
  saml11DetailJson: saml11DetailJson,
  saml11Json: saml11Json,
  saml11ListJson: saml11ListJson,
  saml2ServiceProviders: saml2ServiceProviders,
  saml2Facts: saml2Facts,
  valuesFor: valuesFor,
  saml2DetailJson: saml2DetailJson,
  saml2Json: saml2Json,
  saml2ListJson: saml2ListJson,
  knownUserKeys: knownUserKeys,
  rbacListJson: rbacListJson,
  setDirectoryWriter: setDirectoryWriter,
  setDirectoryReader: setDirectoryReader,
  CREDENTIAL_CHOICES: CREDENTIAL_CHOICES,
  newUserContainer: newUserContainer,
  newUserJson: newUserJson,
  newApplicationJson: newApplicationJson,
  spiffeSelectorText: spiffeSelectorText,
  setSpiffeReader: setSpiffeReader,
  spiffeListeners: spiffeListeners,
  spiffeJson: spiffeJson,
  spiffeEntriesJson: spiffeEntriesJson,
  spiffeAgentsJson: spiffeAgentsJson,
  setSignalsReporter: setSignalsReporter,
  setCaepReporter: setCaepReporter,
  setRiscReporter: setRiscReporter,
  signalsJson: signalsJson,
  signalsState: signalsState,
  ssfDeadLettersJson: ssfDeadLettersJson,
  ssfDeadLettersState: ssfDeadLettersState,
  ssfJson: ssfJson,
  caepJson: caepJson,
  caepSessionsState: caepSessionsState,
  caepApplicationsState: caepApplicationsState,
  caepSessionsJson: caepSessionsJson,
  riscJson: riscJson,
  riscAccountsState: riscAccountsState,
  riscApplicationsState: riscApplicationsState,
  riscAccountsJson: riscAccountsJson,
  setLogoutReader: setLogoutReader,
  DEFAULT_PER_PAGE: DEFAULT_PER_PAGE,
  DELEGATION_PER_PAGE: DELEGATION_PER_PAGE,
  MAX_ROWS: MAX_ROWS,
  pagingOf: pagingOf,
  pagingJson: pagingJson,
  pagedRows: pagedRows,
  tokensView: tokensView,
  sessionProtocolsIn: sessionProtocolsIn,
  sessionsView: sessionsView,
  auditView: auditView,
  errorCodesView: errorCodesView,
  usedAssertionsView: usedAssertionsView,
  delegationView: delegationView,
  clusterSummary: clusterSummary,
  permissionGroupsView: permissionGroupsView,
  queryOne: queryOne,
  chooserMatches: chooserMatches,
  CHOOSER_HITS: CHOOSER_HITS,
  claimsRequestPreview: claimsRequestPreview,
  claimsRequestJson: claimsRequestJson,
  userinfoClaimsJson: userinfoClaimsJson,
  setCryptoReporter: setCryptoReporter,
  setXacmlPages: setXacmlPages,
  setDirectoryPages: setDirectoryPages,
  setScimReader: setScimReader,
  setRolePreviewer: setRolePreviewer,
  setConfigSettingsJson: setConfigSettingsJson,
  setTruststore: setTruststore,
  truststoreJson: truststoreJson,
  kerberosPrincipalsJson: kerberosPrincipalsJson,
  consoleRpSession: consoleRpSession,
  gateStateFor: gateStateFor,
  signOnSessionRows: signOnSessionRows,
  metricsJson: metricsJson,
  tokenSetView: tokenSetView,
  permissionsView: permissionsView,
  cryptoView: cryptoView,
  keysView: keysView,
  keysExport: keysExport,
  xacmlView: xacmlView,
  xacmlPoliciesView: xacmlPoliciesView,
  xacmlEditorView: xacmlEditorView,
  xacmlPepsView: xacmlPepsView,
  xacmlDecideView: xacmlDecideView,
  xacmlMonitorView: xacmlMonitorView,
  directoryPageJson: directoryPageJson,
  consentView: consentView,
  rolesRegister: rolesRegister,
  rolesView: rolesView,
  passwordPoliciesView: passwordPoliciesView,
  DEFAULT_CREDENTIAL: DEFAULT_CREDENTIAL,
  rolesPreview: rolesPreview,
  claimsPreviewUser: claimsPreviewUser,
  claimSetsJson: claimSetsJson,
  claimsJson: claimsJson,
  samlAttributesJson: samlAttributesJson,
  claimsRequestParameter: claimsRequestParameter,
  vcPreviewUser: vcPreviewUser,
  vcJson: vcJson,
  vpConfigJson: vpConfigJson,
  realmRootUrl: realmRootUrl,
  realmSettingRows: realmSettingRows,
  realmJson: realmJson,
  realmsJson: realmsJson,
  tokenLifetimesJson: tokenLifetimesJson,
  samlAssertionSeconds: samlAssertionSeconds,
  samlAssertionsJson: samlAssertionsJson,
  scimJson: scimJson,
  scimMappingRow: scimMappingRow,
  scimMonitorJson: scimMonitorJson
};
