// File: sts_roles.js
//
// ---------------------------------------------------------------------------
// ROLES, AND THE NINE DOORS THEY REFUSE PEOPLE AT.
//
// `tests/roles.js` holds the register and the gate in process: the five things
// about them that no running service can be asked — a gate with no decider, a
// decider that throws, the three shapes of an incoming claim, a directory that
// throws under a lookup, and the four contexts of the six built-in roles. It
// makes not one HTTP request, so until this file existed **nothing anywhere
// checked that a role refuses anybody.**
//
// That gap is the whole feature. The register being right says nothing about
// whether `/oauth2/token` reads it, whether the refusal is `access_denied`
// rather than a 500, whether a person who holds the role still gets their
// token, or whether the roles claim reaches a client. Every one of those is a
// property of the nine ISSUANCE SITES and of nothing the in-process suite
// touches.
//
// ---------------------------------------------------------------------------
// WHY THIS IS THIS REPOSITORY'S OWN (`local: true`) AND NOT THE PARENT'S.
//
// The same argument `sts_consent.js` and the two XACML jobs make, and it is
// as strong here as it is there: **every assertion below spans an AUTHORING
// door and a DECIDING door.** A role is made on `/admin-api/roles`, an
// application is narrowed on `/admin-api/applications`, and what that changes
// is what `/oauth2/token`, `/oauth2/authorize` and `/wstrust` answer. A test
// with the two halves in two repositories could not make the assertion that
// matters, which is that a console control changed what a PROTOCOL endpoint
// does.
//
// ---------------------------------------------------------------------------
// IT RUNS IN A TRUST REALM OF ITS OWN, AND THE REASON IS SHARPER THAN TIDINESS.
//
// `ou=roles` is per realm and so is `ou=applications`, so a throwaway realm
// gives this job a register whose entire contents it wrote — which is what
// makes "alice holds exactly one role" an exact claim rather than "at least
// one". But the load-bearing reason is that **this feature REFUSES people**:
// a job that narrowed an application in the default realm and died before
// clearing it would leave every later job in the run signing in to a service
// that turned them away, and the failure would name the wrong file. Inside a
// realm nothing it does reaches anything else, and removing the realm at the
// end takes the roles, the applications and the settings with it.
//
// `roles.enforceIssuance` is turned off and on in section 8, and that is the
// second reason: it is process-wide at the top level and realm-scoped here.
//
// ---------------------------------------------------------------------------
// MOSTLY NEGATIVES, for `tests/sts_dpop.js`'s reason.
//
// A service that issues a token to somebody who holds the role looks finished
// and can be worth nothing: it is what an unmodified service does for
// everybody. What is worth asserting is that somebody is REFUSED, that the
// refusal is in the protocol's own words, that the person beside them is not
// refused, and that clearing the requirement lets them back in — which is the
// only shape of assertion that distinguishes a working gate from a service
// that happens to be refusing for some other reason.
//
// ---------------------------------------------------------------------------
// IT WAS MUTATION-TESTED AGAINST EIGHT MUTANTS BEFORE IT WAS COMMITTED, which
// is `tests/CLAUDE.md`'s rule and is not optional here. Each was applied to a
// COPY of the tree, driven, and reverted:
//
//   1. `issue()` in oauth2.js no longer calling `checkIssuance()` — caught by
//      section 4, and it is the mutant the whole file exists for;
//   2. the authorization endpoint's gate removed — **it SURVIVED the first
//      round**, and the reason is the most useful thing in this list: section
//      5 asked the PREVIEW whether that request would be refused, which goes
//      through `decide()` and never through the endpoint. A preview is not the
//      thing it previews. The browser flow in that section was written to
//      catch it and does;
//   3. `requiredRolesOf()` answering `[]` instead of `[EVERYBODY]` for an
//      application that names none — caught by section 1, which is the section
//      that looks like it is testing nothing;
//   4. the roles claim built from `rolesOf()` rather than `configuredRolesOf()`,
//      so it carries the built-in roles too — caught by section 2;
//   5. `rolesOf()` ignoring the group membership half — caught by section 6;
//   6. the token endpoint's refusal answered 500 `server_error` rather than
//      400 `access_denied` — caught by section 4, which reads the error CODE
//      and not only the status;
//   7. `roles.enforceIssuance` going unhonoured — caught by section 8;
//   8. an application's membership read out of the USERS list — caught by
//      section 6, and it is the one that would let anybody who could pick a
//      username reach a client's role.
//
// The third is the one to keep in mind when this file is edited: it is the
// mutant that makes the service refuse EVERYBODY, and the only assertion that
// catches it is the one that looks like it is testing nothing.
//
// **THE HARNESS ITSELF LIED TWICE BEFORE IT WAS TRUSTED**, which is worth
// recording beside the list: a mutant server that had not released its port
// left the NEXT mutant's service unable to bind, so the readiness probe was
// answered by the previous tree and two mutants were reported as surviving
// when they had never been run. A mutation harness that reports a false
// survivor is worse than none — it sends somebody to write an assertion that
// already exists. Check that the process holding the port is the one you
// started.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const { Command, Option } = require("commander");
const names = require("./random_username.js");

var appconfig;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_roles",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const REALM = ("roles-" + names.runStamp()).toLowerCase()
    .replace(/[^a-z0-9-]/g, "").slice(0, 40);

// THE THREE PARTIES, fixed rather than random, because every refusal sentence
// below quotes them and a name that changed per run would make a failing log
// unreadable.
const HOLDER = "alice";        // holds `staff` directly
const IN_GROUP = "bob";        // holds it only through a group
const OUTSIDER = "mallory";    // holds nothing
// THE GROUP IS NAMED BY ITS `cn` AND NOT BY ITS DN, because that is what the
// register compares against: `ldap_server.js` fills `roles.setDirectory()`
// with a `groupsOfUser()` that answers cns. A DN here would be a value nothing
// ever matched, which is the exact shape of the mistake this file's third
// mutant is about — it looks configured and refuses everybody.
const GROUP = "role-testers";
const ROLE = "staff";
const NARROWED = "roles-narrowed-app";
const OPEN = "roles-open-app";
const ROBOT = "roles-robot-client";

var checks = 0;
function check(what, fn) {
  fn();
  checks += 1;
  log.debug("check passed: " + what);
}

function realmUrl(path) { return base + "/realm/" + REALM + path; }
function api(path) { return realmUrl("/admin-api" + path); }

// ---------------------------------------------------------------------------
// THE VERBS.
// ---------------------------------------------------------------------------
async function fetchJson(url, options) {
  log.debug("Entering fetchJson(). url=" + url);
  const r = await fetch(url, options || {});
  const text = await r.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch (e) {
    // Not JSON — an HTML page or a redirect with no body. The caller reports
    // the status and the raw text, which says more than a parse error would.
    body = null;
  }
  log.debug("Leaving fetchJson(). status=" + r.status);
  return { status: r.status, body: body, text: text,
           location: r.headers.get("location") || "" };
}

function get(url) { return fetchJson(url); }

function postJson(url, payload) {
  return fetchJson(url, { method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: JSON.stringify(payload || {}) });
}

function postForm(url, fields) {
  const body = Object.keys(fields).map(function (k) {
    return encodeURIComponent(k) + "=" + encodeURIComponent(fields[k]);
  }).join("&");
  return fetchJson(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body,
    redirect: "manual"
  });
}

// An /admin-api action that must have worked. The refusal is quoted whole:
// these handlers answer `errors` with a sentence naming what they wanted, and
// a test reporting only the status would throw that away.
async function act(resource, action, payload, what) {
  const r = await postJson(api("/" + resource + "/" + action), payload || {});
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST /admin-api/" + resource + "/" + action + " should have " + what +
    "; it answered " + r.status + " " +
    JSON.stringify((r.body && (r.body.errors || r.body.why)) ||
                   r.body || r.text).slice(0, 400));
  return r.body;
}

async function setSetting(key, value) {
  const r = await postJson(api("/config/set"), { key: key, value: value });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "setting " + key + " in the realm should have worked; it answered " +
    r.status + " " + String(r.text).slice(0, 300));
}

async function resetSetting(key) {
  // `reset` RATHER THAN WRITING THE OLD VALUE BACK, for the reason
  // tests/saml11_sso.js records: a `set` leaves `source: override` behind and
  // tests/vendored/admin_api.js reads that field.
  const r = await postJson(api("/config/reset"), { key: key });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "resetting " + key + " should have worked; it answered " + r.status);
}

// A password grant, which is this file's workhorse: it is the one grant that
// names a PERSON and needs no browser, so a refusal in it is a refusal of that
// person and of nothing about a session.
function tokenFor(username, clientId, scope) {
  const body = "grant_type=password&username=" + encodeURIComponent(username) +
    "&password=whatever&client_id=" + encodeURIComponent(clientId) +
    "&scope=" + encodeURIComponent(scope || "openid");
  return fetchJson(realmUrl("/oauth2/token"), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body
  });
}

function claimsOf(jwt) {
  const part = String(jwt).split(".")[1] || "";
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

// ---------------------------------------------------------------------------
// A BROWSER, for the two doors that need one.
//
// Manual redirects and a cookie jar of this file's own, because both
// assertions in section 5 are about WHICH redirect came back — a fetch that
// followed them would answer the question by hiding it. Copied in shape from
// `sts_consent.js`, which needs the same thing for the same reason.
// ---------------------------------------------------------------------------
function form(o) { return new URLSearchParams(o).toString(); }

function absolute(location) {
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
}

function browser() {
  const self = {
    cookie: "",
    async go(method, path, body) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = {};
      if (self.cookie) { headers.cookie = self.cookie; }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path), { method: method,
                                              redirect: "manual",
                                              headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) { self.cookie = String(one).split(";")[0]; });
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text };
    }
  };
  return self;
}

const REDIRECT_URI = "https://example.test/roles-callback";

function authorizeUrl(clientId) {
  return "/realm/" + REALM + "/oauth2/authorize?" + form({
    response_type: "code", client_id: clientId, redirect_uri: REDIRECT_URI,
    scope: "openid", state: "roles-" + REALM
  });
}

// ---------------------------------------------------------------------------
// SETUP AND TEARDOWN.
// ---------------------------------------------------------------------------
async function createTheRealm() {
  log.info("=== A throwaway trust realm ===");
  const r = await postJson(base + "/admin-api/realms/create",
                           { id: REALM, name: "roles under test" });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "creating the realm " + REALM + " should have worked; it answered " +
    r.status + " " + String(r.text).slice(0, 300));
  log.info("Created the throwaway realm " + REALM + ".");
}

async function removeTheRealm() {
  const r = await postJson(base + "/admin-api/realms/remove", { id: REALM });
  // ASSERTED RATHER THAN HOPED FOR. This job narrows applications and turns a
  // setting off; all of it lives in the realm, so a removal that silently did
  // not happen would leave exactly the mess the realm exists to prevent.
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "removing the realm " + REALM + " should have worked; it answered " +
    r.status + ". Everything this job configured is in that realm, so a " +
    "realm left behind is a service that refuses people for the rest of the " +
    "run.");
  log.info("Removed the throwaway realm " + REALM + ".");
}

// ---------------------------------------------------------------------------
// 1. THE REGISTER STARTS EMPTY AND EVERY APPLICATION REQUIRES EVERYBODY.
//
// **This is the section that looks like it is testing nothing and is not.** It
// is the only one that catches the mutant that makes this service refuse
// EVERYBODY: if an application naming no required role resolved to an empty
// requirement instead of to `EVERYBODY`, the intersection test would find
// nothing in common with anything and every issuance in the service would be
// denied. That failure is total and silent — it looks exactly like the feature
// working.
// ---------------------------------------------------------------------------
async function anUnconfiguredRealmRefusesNobody() {
  log.info("=== An unconfigured realm refuses nobody ===");

  const register = await get(api("/roles"));
  check("the register reads", function () {
    assert.strictEqual(register.status, 200,
      "GET /admin-api/roles should answer 200; it answered " +
      register.status);
  });
  check("a new realm has no configured role", function () {
    assert.strictEqual(register.body.roles.length, 0,
      "a realm's ou=roles starts empty; this one holds " +
      JSON.stringify(register.body.roles.map(function (r) { return r.name; })));
  });
  check("and the six built-in ones are there anyway", function () {
    assert.strictEqual(register.body.builtIn.length, 6,
      "the six are computed rather than stored, so an empty container has " +
      "them; this realm reports " + register.body.builtIn.length);
  });
  check("the default requirement is EVERYBODY", function () {
    assert.strictEqual(register.body.defaultRequired, "EVERYBODY",
      "which is the name every other assertion in this file rests on");
  });
  check("nothing has been narrowed", function () {
    assert.strictEqual(register.body.requiring.length, 0,
      "an unedited realm narrows nothing; this one lists " +
      JSON.stringify(register.body.requiring));
  });
  check("and the decision is being asked for", function () {
    assert.ok(register.body.gated && register.body.enforced,
      "this job asserts REFUSALS, so a run against a service where the XACML " +
      "family is not loaded (gated=" + register.body.gated + ") or " +
      "roles.enforceIssuance is off (enforced=" + register.body.enforced +
      ") would pass every one of them by doing nothing. It is checked here " +
      "rather than assumed.");
  });

  // AND THE THING THAT MATTERS: an application nobody has touched issues to
  // somebody nobody has heard of.
  const first = await tokenFor(OUTSIDER, OPEN, "openid");
  check("an unnarrowed application issues to anybody", function () {
    assert.strictEqual(first.status, 200,
      "an application requiring only EVERYBODY must behave exactly as this " +
      "service did before roles existed; it answered " + first.status + " " +
      String(first.text).slice(0, 300));
  });
}

// ---------------------------------------------------------------------------
// 2. THE CLAIM: what a token carries, and what it must not.
// ---------------------------------------------------------------------------
async function theClaim() {
  log.info("=== The roles claim ===");

  await act("roles", "create-role", { role: ROLE, description: "Works here" },
            "created the role");
  await act("roles", "add-member", { role: ROLE, kind: "user",
                                     member: HOLDER },
            "given " + HOLDER + " the role");

  const held = await tokenFor(HOLDER, OPEN, "openid");
  assert.strictEqual(held.status, 200,
    "the holder should still be issued a token by an unnarrowed application; " +
    "it answered " + held.status + " " + String(held.text).slice(0, 300));
  const claims = claimsOf(held.body.access_token);

  check("the access token carries the role", function () {
    assert.deepStrictEqual(claims.roles, [ROLE],
      "the roles claim should name exactly the configured role; it is " +
      JSON.stringify(claims.roles));
  });
  check("and NOT the built-in ones", function () {
    assert.ok(JSON.stringify(claims.roles || []).indexOf("EVERYBODY") < 0,
      "EVERYBODY and ALL_AUTHENTICATED_USERS are true of almost every token " +
      "this service issues, so carrying them would add two meaningless " +
      "members to every token every existing client parses. The claim is " +
      JSON.stringify(claims.roles));
  });
  check("the ID Token carries it too", function () {
    assert.deepStrictEqual(claimsOf(held.body.id_token).roles, [ROLE],
      "a relying party reads the ID Token and not the access token, so a " +
      "claim that reached only one of them would reach half the clients");
  });

  const none = await tokenFor(OUTSIDER, OPEN, "openid");
  check("somebody with no configured role gets NO CLAIM AT ALL", function () {
    assert.strictEqual(claimsOf(none.body.access_token).roles, undefined,
      "an EMPTY ARRAY is a claim, and a client reading one would be told " +
      "something false about a service that has no roles configured for " +
      "that person. It is " +
      JSON.stringify(claimsOf(none.body.access_token).roles));
  });
}

// ---------------------------------------------------------------------------
// 3. NARROWING AN APPLICATION, AND WHAT THE REGISTER THEN SAYS ABOUT IT.
// ---------------------------------------------------------------------------
async function narrowingAnApplication() {
  log.info("=== Narrowing an application ===");

  await act("applications", "create",
            { identifier: NARROWED, kind: "oauth2-client",
              name: "Narrowed" }, "created the application");
  await act("applications", "add",
            { application: NARROWED, attribute: "appRequiredRole",
              value: ROLE }, "narrowed it to " + ROLE);

  const register = await get(api("/roles"));
  check("the register now lists it as narrowed", function () {
    assert.strictEqual(register.body.requiring.length, 1,
      "exactly one application in this realm has been narrowed; the " +
      "register lists " + JSON.stringify(register.body.requiring));
  });
  check("naming the role it requires", function () {
    assert.deepStrictEqual(register.body.requiring[0].required, [ROLE],
      "it should require " + ROLE + "; it requires " +
      JSON.stringify(register.body.requiring[0].required));
  });
  check("and saying the role is one something defines", function () {
    assert.deepStrictEqual(register.body.requiring[0].unknown, [],
      "`unknown` names a role an application demands that NOTHING defines — " +
      "which refuses everybody while looking exactly like a broken " +
      "application. It should be empty here and is " +
      JSON.stringify(register.body.requiring[0].unknown));
  });

  // THE UNSATISFIABLE CASE, which is the one thing this register can say that
  // neither the application resource nor the role list can.
  await act("applications", "add",
            { application: NARROWED, attribute: "appRequiredRole",
              value: "no-such-role" }, "added a role nothing defines");
  const after = await get(api("/roles"));
  check("a role nothing defines is reported as unholdable", function () {
    assert.deepStrictEqual(after.body.requiring[0].unknown, ["no-such-role"],
      "it should name the undefined role; it names " +
      JSON.stringify(after.body.requiring[0].unknown));
  });
  await act("applications", "remove",
            { application: NARROWED, attribute: "appRequiredRole",
              value: "no-such-role" }, "removed it again");
}

// ---------------------------------------------------------------------------
// 4. THE TOKEN ENDPOINT REFUSES, AND IT REFUSES IN OAUTH'S OWN WORDS.
//
// The section the file exists for.
// ---------------------------------------------------------------------------
async function theTokenEndpointRefuses() {
  log.info("=== The token endpoint ===");

  const refused = await tokenFor(OUTSIDER, NARROWED, "openid");
  check("somebody holding none of the required roles is refused", function () {
    assert.strictEqual(refused.status, 400,
      "it should be refused 400; it answered " + refused.status + " " +
      String(refused.text).slice(0, 300));
  });
  check("with access_denied and not server_error", function () {
    assert.strictEqual(refused.body.error, "access_denied",
      "RFC 6749 section 4.1.2.1's own code for a request the authorization " +
      "server denied. A 500 or an invalid_request here would send a client " +
      "library looking for a fault of its own; it answered " +
      JSON.stringify(refused.body));
  });
  check("and the reason names the application, the requirement and what " +
        "they hold", function () {
    const why = String(refused.body.error_description || "");
    assert.ok(why.indexOf(NARROWED) >= 0 && why.indexOf(ROLE) >= 0 &&
              why.indexOf(OUTSIDER) >= 0,
      "a client whose operator cannot see WHY files a bug against this " +
      "service. The sentence is: " + why);
  });
  check("and nothing was issued", function () {
    assert.ok(!refused.body.access_token && !refused.body.id_token,
      "a refusal that also handed over a token would be the one failure " +
      "this feature must not have; it answered " +
      JSON.stringify(Object.keys(refused.body)));
  });

  // THE PERSON BESIDE THEM IS NOT REFUSED, which is what distinguishes a
  // working gate from a service that is refusing for some other reason.
  const allowed = await tokenFor(HOLDER, NARROWED, "openid");
  check("somebody who holds the role is issued one", function () {
    assert.strictEqual(allowed.status, 200,
      HOLDER + " holds " + ROLE + " and must still be issued a token; it " +
      "answered " + allowed.status + " " + String(allowed.text).slice(0, 300));
  });
  check("with all three tokens", function () {
    assert.ok(allowed.body.access_token && allowed.body.id_token &&
              allowed.body.refresh_token,
      "the gate is asked about each of the three separately, so a refusal " +
      "reaching one of them would show up as a response short by one member; " +
      "it carries " + JSON.stringify(Object.keys(allowed.body)));
  });

  // AND CLEARING THE REQUIREMENT LETS THEM BACK IN. Without this the section
  // above is consistent with the service refusing `mallory` for any reason at
  // all.
  await act("applications", "remove",
            { application: NARROWED, attribute: "appRequiredRole",
              value: ROLE }, "cleared the requirement");
  const back = await tokenFor(OUTSIDER, NARROWED, "openid");
  check("clearing the requirement lets the outsider back in", function () {
    assert.strictEqual(back.status, 200,
      "with no required role the application requires EVERYBODY again; it " +
      "answered " + back.status + " " + String(back.text).slice(0, 300));
  });
  await act("applications", "add",
            { application: NARROWED, attribute: "appRequiredRole",
              value: ROLE }, "narrowed it again");
}

// ---------------------------------------------------------------------------
// 5. THE AUTHORIZATION ENDPOINT REFUSES TO THE REDIRECT_URI.
//
// A different door with a different answer: the person is signed in, so what
// they get is not a page on this service but a redirect the CLIENT can read.
// ---------------------------------------------------------------------------
async function theAuthorizationEndpointRefuses() {
  log.info("=== The authorization endpoint ===");

  // The preview is what says the decision WOULD be a refusal, asked through
  // the same call the endpoint makes. It is checked first so that a failure
  // below can be told apart from a decision that was never going to refuse.
  const preview = await get(api("/roles/preview?application=" +
    encodeURIComponent(NARROWED) + "&subject=" + OUTSIDER +
    "&kind=issue-authorization-code"));
  check("the preview says it would be refused", function () {
    assert.ok(preview.body.answered === true && preview.body.allowed === false,
      "the dry run goes through the same call the nine issuance sites make, " +
      "so it cannot disagree with them; it answered " +
      JSON.stringify(preview.body).slice(0, 400));
  });
  const permitted = await get(api("/roles/preview?application=" +
    encodeURIComponent(NARROWED) + "&subject=" + HOLDER +
    "&kind=issue-authorization-code"));
  check("and permitted for the holder", function () {
    assert.strictEqual(permitted.body.allowed, true,
      "the same question about the person who holds the role; it answered " +
      JSON.stringify(permitted.body).slice(0, 400));
  });

  // THE CONSENT SCREEN IS TURNED OFF FOR THIS SECTION, in this realm only, and
  // the ORDER it would impose is asserted at the end of it rather than driven
  // through four times. `oauth2.consentRequired` is ON by default — the one
  // policy in this service that is — so every flow below would otherwise stop
  // at `/oauth2/consent`, and this job would be asserting the consent
  // screen's markup while claiming to be about roles.
  await setSetting("oauth2.consentRequired", false);

  // AND NOW THE ENDPOINT ITSELF, which is what the preview is a preview OF.
  // Without this the section above is satisfied by a gate that decides
  // correctly and is wired to nothing — the mutant that removes the
  // authorization endpoint's check leaves every preview assertion passing.
  //
  // THE SIGN-IN SCREEN IS PART OF THE ASSERTION AND NOT SCAFFOLDING. The
  // SESSION is gated too, at `authn.js`, and it is gated on the application
  // the sign-in is FOR — so a person refused at this application must be
  // refused at the screen and never reach the endpoint at all. That is why
  // the two people below are driven all the way from the authorization
  // request rather than from a session made some other way.
  const refusedBrowser = browser();
  let step = await refusedBrowser.go("GET", authorizeUrl(NARROWED));
  check("an unauthenticated authorization request goes to the sign-in screen",
    function () {
      assert.ok(/\/authn\/login\?authn=/.test(step.location),
        "it went to " + step.location);
    });
  const screen = await refusedBrowser.go("GET", step.location);
  const authnId = (screen.text.match(/name="authn_id" value="([^"]+)"/) ||
                   [])[1];
  assert.ok(authnId, "the sign-in screen carries no authn_id to post back.");

  const refusedSignIn = await refusedBrowser.go("POST",
    "/realm/" + REALM + "/authn/login",
    form({ authn_id: authnId, username: OUTSIDER, password: "any",
           action: "login" }));
  check("the sign-in screen itself refuses somebody who holds no required role",
    function () {
      assert.ok(refusedSignIn.status === 200 &&
                refusedSignIn.text.indexOf(ROLE) >= 0,
        "the SESSION is gated too, and on the application the sign-in is " +
        "for — so the screen is drawn again with the reason on it rather " +
        "than a session being minted and refused one door later. It " +
        "answered " + refusedSignIn.status + " and the page " +
        (refusedSignIn.text.indexOf(ROLE) >= 0 ? "names" : "does NOT name") +
        " the role");
    });
  check("and no session was established", function () {
    assert.strictEqual(refusedBrowser.cookie, "",
      "a refused sign-in must mint nothing; the jar holds " +
      refusedBrowser.cookie);
  });

  // THE HOLDER GOES ALL THE WAY THROUGH, which is what says the refusal above
  // is about the role and not about the screen being broken.
  const holderBrowser = browser();
  step = await holderBrowser.go("GET", authorizeUrl(NARROWED));
  const holderScreen = await holderBrowser.go("GET", step.location);
  const holderAuthn = (holderScreen.text
    .match(/name="authn_id" value="([^"]+)"/) || [])[1];
  const signedIn = await holderBrowser.go("POST",
    "/realm/" + REALM + "/authn/login",
    form({ authn_id: holderAuthn, username: HOLDER, password: "any",
           action: "login" }));
  check("somebody who holds the role signs in", function () {
    assert.ok((signedIn.status === 302 || signedIn.status === 303) &&
              holderBrowser.cookie,
      "it answered " + signedIn.status + " and the jar holds " +
      (holderBrowser.cookie ? "a session" : "nothing"));
  });
  const back = await holderBrowser.go("GET", signedIn.location);
  check("and the authorization endpoint hands them a code", function () {
    assert.ok(back.location.indexOf(REDIRECT_URI) === 0 &&
              /[?&]code=/.test(back.location),
      "it went to " + back.location);
  });

  // AND THE ENDPOINT REFUSES A SESSION THAT ALREADY EXISTS. This is the door
  // the sign-in screen cannot cover: the holder is signed in, and asking for a
  // DIFFERENT application they hold nothing for must be refused HERE — to the
  // redirect_uri, so the client sees a refusal it can render rather than a
  // page on this service its user has to read.
  await act("applications", "create",
            { identifier: "roles-second-app", kind: "oauth2-client",
              name: "Second" }, "created a second application");
  await act("applications", "add",
            { application: "roles-second-app", attribute: "appRequiredRole",
              value: "nobody-holds-this" }, "narrowed it to nothing");
  const second = await holderBrowser.go("GET",
    authorizeUrl("roles-second-app"));
  check("a LIVE session is refused at the authorization endpoint", function () {
    assert.ok(second.location.indexOf(REDIRECT_URI) === 0,
      "the refusal goes to the redirect_uri the client controls and NOT to a " +
      "page on this service; it went to " + second.location);
  });
  check("with access_denied on the query string", function () {
    assert.ok(/[?&]error=access_denied/.test(second.location),
      "RFC 6749 section 4.1.2.1's own code; the redirect is " +
      second.location);
  });
  check("and no code was issued", function () {
    assert.ok(!/[?&]code=/.test(second.location),
      "a refusal that also handed over a code would be the one failure this " +
      "feature must not have; the redirect is " + second.location);
  });

  // THE ORDER, in one request. With the consent screen back on, the SAME
  // request that was just refused stops at the screen instead — so a person is
  // asked what they agree to and then told whether they may, and never the
  // other way round. That falls out of where the role gate sits rather than
  // being arranged, and it is worth pinning: the other order would ask
  // somebody to consent to something they were about to be refused.
  await resetSetting("oauth2.consentRequired");
  const asksFirst = await holderBrowser.go("GET",
    authorizeUrl("roles-second-app"));
  check("the consent screen is drawn BEFORE the refusal, not after",
    function () {
      assert.ok(/\/oauth2\/consent\?consent=/.test(asksFirst.location),
        "it went to " + asksFirst.location);
    });
  await setSetting("oauth2.consentRequired", false);

  // A preview with nothing asked is a READ with no question in it and answers
  // 200 — it must NOT fall through to the gate, which allows a call naming no
  // application and would hand back a Permit meaning "you did not ask".
  const nothing = await get(api("/roles/preview"));
  check("a preview with nothing asked answers 200 and no decision",
    function () {
      assert.ok(nothing.status === 200 && nothing.body.answered === false &&
                nothing.body.decision === undefined,
        "there must be no `decision` member at all, or a caller who forgot a " +
        "parameter reads a Permit; it answered " + nothing.status + " " +
        JSON.stringify(nothing.body).slice(0, 300));
    });

  // PUT IT BACK. Everything this job changes lives in the throwaway realm, so
  // this costs nothing outside it — but a section that left a policy off would
  // make the next section's failures point at the wrong feature.
  await resetSetting("oauth2.consentRequired");
}

// ---------------------------------------------------------------------------
// 6. A GROUP, AND AN APPLICATION, AS MEMBERS.
//
// The two halves of this register that no other register here has.
// ---------------------------------------------------------------------------
async function groupsAndApplicationsHoldRoles() {
  log.info("=== A group and an application hold roles ===");

  // THE GROUP HALF. Nobody is added to the ROLE; a group is, and the person is
  // in the group — so the role is resolved through two lookups at decision
  // time rather than expanded on write.
  // THE GROUP IS MADE THROUGH SCIM, and that is not a detour. `/admin-api`
  // has no group-writing operation at all — `/admin-api/groups` is read-only,
  // deliberately, because the directory's own doors are what write it — so
  // SCIM is the door this service actually offers for creating a group with a
  // member in it over HTTP. `ldapmodify` is the other and needs a socket.
  // THE MEMBER IS A DN AND NOT A USERNAME, which cost a run to find out and is
  // worth the four lines. A SCIM Group member's `value` is the member's SCIM
  // id, and this service's SCIM id IS the directory entry's DN — so a bare
  // username produces a group with a DANGLING member: it is stored, it is
  // counted, `/admin/groups` shows it, and `groupsOfUser()` resolves nothing,
  // because that walk matches on the person's normalised DN. Every symptom is
  // "the group exists and nobody is in it", which reads as the ROLE not
  // working.
  //
  // It is read through SCIM rather than through `/admin-api/users`, which is a
  // different register entirely: that one lists who has AUTHENTICATED and this
  // needs a directory entry, and `bob` is one of the entries every realm's
  // directory is SEEDED with and has authenticated nowhere.
  const found = await fetchJson(realmUrl(
    "/scim/v2/Users?filter=" + encodeURIComponent('userName eq "' + IN_GROUP + '"')), {
    headers: { "Authorization": "Basic " +
                 Buffer.from("tester:whatever").toString("base64") } });
  const bob = (found.body && found.body.Resources || [])[0];
  assert.ok(bob && bob.id,
    IN_GROUP + " should be one of the entries this realm's directory is " +
    "seeded with; GET /scim/v2/Users answered " + found.status + " " +
    String(found.text).slice(0, 300));

  const group = await fetchJson(realmUrl("/scim/v2/Groups"), {
    method: "POST",
    headers: { "Content-Type": "application/scim+json",
               // Any password but the reserved one passes; the credential is
               // a turnstile, which scim/CLAUDE.md argues.
               "Authorization": "Basic " +
                 Buffer.from("tester:whatever").toString("base64") },
    body: JSON.stringify({
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
      displayName: GROUP,
      members: [{ value: bob.id }]
    })
  });
  assert.ok(group.status === 201 || group.status === 200,
    "POST /scim/v2/Groups should have created " + GROUP + "; it answered " +
    group.status + " " + String(group.text).slice(0, 300));

  await act("roles", "add-member",
            { role: ROLE, kind: "group", member: GROUP },
            "given the group the role");

  const viaGroup = await tokenFor(IN_GROUP, NARROWED, "openid");
  check("somebody who holds the role only through a GROUP is issued one",
    function () {
      assert.strictEqual(viaGroup.status, 200,
        IN_GROUP + " is in " + GROUP + ", which holds " + ROLE + "; it " +
        "answered " + viaGroup.status + " " +
        String(viaGroup.text).slice(0, 300));
    });
  check("and their token carries the role", function () {
    assert.deepStrictEqual(claimsOf(viaGroup.body.access_token).roles, [ROLE],
      "a role held through a group is a role held; the claim is " +
      JSON.stringify(claimsOf(viaGroup.body.access_token).roles));
  });

  await act("roles", "remove-member",
            { role: ROLE, kind: "group", member: GROUP },
            "taken the role off the group");
  const afterGroup = await tokenFor(IN_GROUP, NARROWED, "openid");
  check("and taking it off the group refuses them again", function () {
    assert.strictEqual(afterGroup.status, 400,
      "resolved at DECISION TIME, so the very next request changes; it " +
      "answered " + afterGroup.status);
  });

  // THE APPLICATION HALF, and it is the unusual one: a client_credentials
  // grant has no person in it at all, so until an application could hold a
  // role there was nothing to decide about one.
  await act("applications", "create",
            { identifier: ROBOT, kind: "oauth2-client", name: "Robot" },
            "created the client");
  await act("applications", "add",
            { application: ROBOT, attribute: "appRequiredRole",
              value: "robots" }, "narrowed it to a role nothing holds");

  const beforeRole = await fetchJson(realmUrl("/oauth2/token"), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials&client_id=" + ROBOT
  });
  check("a client_credentials grant is refused when the CLIENT holds no role",
    function () {
      assert.ok(beforeRole.status === 400 &&
                beforeRole.body.error === "access_denied",
        "there is no person in this grant, so the subject is the client " +
        "itself; it answered " + beforeRole.status + " " +
        String(beforeRole.text).slice(0, 300));
    });

  await act("roles", "create-role", { role: "robots" }, "created the role");
  await act("roles", "add-member",
            { role: "robots", kind: "application", member: ROBOT },
            "given the CLIENT the role");
  const afterRole = await fetchJson(realmUrl("/oauth2/token"), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials&client_id=" + ROBOT
  });
  check("and issued once the client itself holds it", function () {
    assert.strictEqual(afterRole.status, 200,
      "an application is a first-class member of a role precisely so that " +
      "this grant has a subject; it answered " + afterRole.status + " " +
      String(afterRole.text).slice(0, 300));
  });

  // AND THE SAME NAME AS A PERSON HOLDS NOTHING. The three membership lists
  // are three relations, not one list with a label on it — a bug that merged
  // them would let anybody who could pick a username reach a client's role.
  const asPerson = await tokenFor(ROBOT, ROBOT, "openid");
  check("the same name as a PERSON holds nothing", function () {
    assert.ok(asPerson.status === 400 &&
              asPerson.body.error === "access_denied",
      "roleMemberApplication and roleMemberUser are different attributes and " +
      "different questions; it answered " + asPerson.status + " " +
      String(asPerson.text).slice(0, 300));
  });
}

// ---------------------------------------------------------------------------
// 7. WS-TRUST, WHERE THE APPLICATION MAY BE ABSENT AND THAT IS NOT AN ERROR.
//
// The one issuance site here whose application is optional: AppliesTo is
// optional in an RST, and a token with no audience restriction is a state this
// service deliberately allows. So there is nothing to have a requirement, and
// the gate ALLOWS — which is the honest answer and the one most likely to be
// "fixed" into a refusal by somebody reading the table of nine kinds.
// ---------------------------------------------------------------------------
async function wsTrustWithNoAppliesTo() {
  log.info("=== WS-Trust ===");

  const rst = function (appliesTo) {
    return '<?xml version="1.0" encoding="UTF-8"?>' +
      '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' +
      '<soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/' +
      '2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
      '<wsse:UsernameToken><wsse:Username>' + OUTSIDER + '</wsse:Username>' +
      '<wsse:Password>whatever</wsse:Password></wsse:UsernameToken>' +
      '</wsse:Security></soap:Header><soap:Body>' +
      '<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/' +
      'ws-trust/200512">' +
      '<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/' +
      'Issue</wst:RequestType>' +
      (appliesTo
        ? '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/' +
          'policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/' +
          '08/addressing"><wsa:Address>' + appliesTo + '</wsa:Address>' +
          '</wsa:EndpointReference></wsp:AppliesTo>'
        : '') +
      '</wst:RequestSecurityToken></soap:Body></soap:Envelope>';
  };

  async function rstFor(appliesTo) {
    return fetchJson(realmUrl("/sts"), {
      method: "POST",
      headers: { "Content-Type": "application/soap+xml" },
      body: rst(appliesTo)
    });
  }

  const anonymous = await rstFor(null);
  check("an RST with NO AppliesTo is answered", function () {
    assert.strictEqual(anonymous.status, 200,
      "nothing named an application, so there is no requirement to check and " +
      "the honest answer is to issue. It answered " + anonymous.status + " " +
      String(anonymous.text).slice(0, 300));
  });

  const narrowed = await rstFor(NARROWED);
  check("and one naming a narrowed application is refused with a SOAP fault",
    function () {
      assert.strictEqual(narrowed.status, 403,
        "an RST is answered with an RSTR or with a Fault; an RSTR carrying " +
        "no token would be a success that issued nothing. It answered " +
        narrowed.status);
    });
  check("the fault carries the reason", function () {
    assert.ok(narrowed.text.indexOf(ROLE) >= 0 &&
              narrowed.text.indexOf("Fault") >= 0,
      "the sentence should name the role required; the body is " +
      String(narrowed.text).slice(0, 400));
  });
}

// ---------------------------------------------------------------------------
// 8. THE OFF SWITCH, which is the way back if a policy edit locks somebody out.
// ---------------------------------------------------------------------------
async function turningItOff() {
  log.info("=== roles.enforceIssuance, off ===");

  await setSetting("roles.enforceIssuance", false);
  const notAsked = await tokenFor(OUTSIDER, NARROWED, "openid");
  check("with enforcement off the outsider is issued a token", function () {
    assert.strictEqual(notAsked.status, 200,
      "turning it off stops the question being asked at all; it answered " +
      notAsked.status + " " + String(notAsked.text).slice(0, 300));
  });
  // Read through the API rather than inferred from the token above, because a
  // page that went on saying "enforced" while nothing was enforced is the
  // console lying about the service, which is the failure this whole console
  // is arranged to prevent. AWAITED OUTSIDE `check()`, which calls its
  // function synchronously: a promise returned into it would make a failed
  // assertion an unhandled rejection rather than a failed check.
  const offRegister = await get(api("/roles"));
  check("and the register says nothing is being decided", function () {
    assert.strictEqual(offRegister.body.enforced, false,
      "the register should report enforced=false; it reports " +
      offRegister.body.enforced);
  });

  await resetSetting("roles.enforceIssuance");
  const askedAgain = await tokenFor(OUTSIDER, NARROWED, "openid");
  check("and turning it back on refuses them again", function () {
    assert.strictEqual(askedAgain.status, 400,
      "it answered " + askedAgain.status + " " +
      String(askedAgain.text).slice(0, 300));
  });

  // THE CLAIM HAS ITS OWN SWITCH and it is a different one: a service may
  // carry roles in its tokens and decide nothing on them, or decide on them
  // and carry nothing. Collapsing the two settings would make one of those
  // impossible.
  await setSetting("roles.claim", false);
  const noClaim = await tokenFor(HOLDER, NARROWED, "openid");
  check("roles.claim off removes the claim and changes no decision",
    function () {
      assert.ok(noClaim.status === 200 &&
                claimsOf(noClaim.body.access_token).roles === undefined,
        "the holder is still issued a token and it carries no roles claim; " +
        "it answered " + noClaim.status + " " +
        JSON.stringify(claimsOf(noClaim.body.access_token || "x.e30.y").roles));
    });
  await resetSetting("roles.claim");
}

// ---------------------------------------------------------------------------
// 9. THE REGISTER'S OWN REFUSALS.
// ---------------------------------------------------------------------------
async function theRegisterRefuses() {
  log.info("=== What the register will not do ===");

  const builtIn = await postJson(api("/roles/create-role"),
                                 { role: "EVERYBODY" });
  check("a role may not shadow a built-in one", function () {
    assert.ok(builtIn.status === 400 &&
              String(JSON.stringify(builtIn.body)).indexOf("built-in") >= 0,
      "the built-in ones are computed and answered FIRST, so a stored role " +
      "of the same name could never be reached; it answered " +
      builtIn.status + " " + String(builtIn.text).slice(0, 300));
  });

  const member = await postJson(api("/roles/add-member"),
    { role: "ALL_AUTHENTICATED_USERS", kind: "user", member: HOLDER });
  check("and a built-in one cannot be given a member", function () {
    assert.ok(member.status === 400 &&
              String(JSON.stringify(member.body)).indexOf("BUILT-IN") >= 0,
      "the refusal must NAME it as built-in rather than say there is no such " +
      "role, which would be a flatly false sentence about a role the page " +
      "had just drawn; it answered " + member.status + " " +
      String(member.text).slice(0, 300));
  });

  const badKind = await postJson(api("/roles/add-member"),
    { role: ROLE, kind: "person", member: HOLDER });
  check("`kind` is one of three and a fourth is refused", function () {
    assert.strictEqual(badKind.status, 400,
      "the three lists are three relations looked up in three places, so a " +
      "kind nobody reads would write something that never matched; it " +
      "answered " + badKind.status);
  });

  const noSuch = await postJson(api("/roles/add-member"),
    { role: "not-a-role", kind: "user", member: HOLDER });
  check("and a role that is not there is refused rather than created",
    function () {
      assert.strictEqual(noSuch.status, 400,
        "creating one as a side effect of adding a member would make a typo " +
        "in the role name a new role; it answered " + noSuch.status);
    });

  // DELETING A ROLE SOMETHING STILL REQUIRES SUCCEEDS AND SAYS SO. Refusing
  // would mean a role could not be removed until every application naming it
  // had been edited — and those entries are usually what somebody is in the
  // middle of changing.
  const deleted = await postJson(api("/roles/delete-role"), { role: ROLE });
  check("deleting a role something still requires SUCCEEDS", function () {
    assert.ok(deleted.status === 200 && deleted.body.ok,
      "it answered " + deleted.status + " " +
      String(deleted.text).slice(0, 300));
  });
  check("and names what now requires something nobody can hold", function () {
    assert.ok((deleted.body.stillRequired || []).indexOf(NARROWED) >= 0,
      "the consequence is said at the moment it is created rather than " +
      "discovered later as a service that stopped working; it named " +
      JSON.stringify(deleted.body.stillRequired));
  });

  const orphaned = await tokenFor(HOLDER, NARROWED, "openid");
  check("and that application now issues to NOBODY", function () {
    assert.strictEqual(orphaned.status, 400,
      "the holder held a role that no longer exists, so the requirement can " +
      "be satisfied by nobody at all — which is exactly what the reply above " +
      "warned about; it answered " + orphaned.status);
  });
  const stillOpen = await tokenFor(HOLDER, OPEN, "openid");
  check("while every other application is unaffected", function () {
    assert.strictEqual(stillOpen.status, 200,
      "an unnarrowed application still requires EVERYBODY; it answered " +
      stillOpen.status);
  });
}

// ---------------------------------------------------------------------------
// THE RUN.
// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Driving the mock STS's role register and the nine issuance sites " +
           "at " + base);

  // A SERVICE THAT IS NOT THERE IS A FAILURE AND NOT A SKIP, which is the rule
  // CLAUDE.md records the 2026-08-28 default flip for: a job that reports
  // green having driven nothing is worse than one that is honestly absent.
  const status = await fetchJson(base + "/admin-api/status");
  assert.strictEqual(status.status, 200,
    "GET /admin-api/status answered " + status.status + " at " + base +
    ". This job needs the mock and nothing else.");

  await createTheRealm();
  try {
    await anUnconfiguredRealmRefusesNobody();
    await theClaim();
    await narrowingAnApplication();
    await theTokenEndpointRefuses();
    await theAuthorizationEndpointRefuses();
    await groupsAndApplicationsHoldRoles();
    await wsTrustWithNoAppliesTo();
    await turningItOff();
    await theRegisterRefuses();
  } finally {
    await removeTheRealm();
  }

  // A FLOOR ON THE COUNT, for the reason sts_admin_console.js gives: a section
  // that stops being called takes its assertions with it and the run still
  // says "passed", which is the one failure mode a suite cannot report about
  // itself.
  assert.ok(checks >= 45,
    "only " + checks + " checks ran. This file makes over forty against a " +
    "healthy service, so a count this low means a SECTION STOPPED BEING " +
    "CALLED rather than that the feature got simpler.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_roles")
  .description("Drive the mock STS's role register and the issuance sites it " +
      "gates, in a throwaway trust realm: the claim, a narrowed application " +
      "refusing at the token endpoint in OAuth's own words, a group and an " +
      "application holding roles, WS-Trust's optional AppliesTo, and the off " +
      "switch.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
