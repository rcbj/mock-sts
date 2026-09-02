// File: sts_consent.js
//
// ---------------------------------------------------------------------------
// THE CONSENT SCREEN, AND THE OVERRIDE THAT MAKES IT NOT APPEAR.
//
// `/oauth2/consent` is the one thing between a signed-in person and an
// authorization response since 2026-09-01. This job drives it over HTTP with no
// browser — the screen carries no script, so a form here is a form there — and
// it is MOSTLY NEGATIVES, for the reason `sts_dpop.js` gives at length: a
// consent screen that draws, takes an Allow and hands over a code looks
// finished and can be worth nothing. What makes it worth something is that it
// refuses a replay, refuses somebody else's session, records nothing on a Deny,
// and stops asking once — and only once — an answer exists.
//
// ---------------------------------------------------------------------------
// WHY IT IS THIS REPOSITORY'S OWN (`local: true`) AND NOT THE PARENT'S.
//
// CLAUDE.md's rule is that anything drivable over HTTP belongs in the parent
// project's suite, and half of this file plainly is. The other half is not, and
// it is the half the feature turns on: the GLOBAL CONSENT OVERRIDE is
// configured through `/admin-api/consent` and read on `/admin/consent`, and
// both of those are doors this repository owns and this repository's own jobs
// cover. A test that grants an override, watches a sign-in stop being asked,
// revokes it and watches the asking come back is a test of a CONSOLE CONTROL
// with a protocol consequence — which is exactly what
// `sts_admin_api_operations.js` and `sts_admin_console.js` are here for.
//
// Splitting it in two was considered and refused: the assertion that matters is
// that the override changes what the AUTHORIZATION ENDPOINT does, and a test
// with the grant in one repository and the sign-in in another could not make
// it.
//
// ---------------------------------------------------------------------------
// WHAT IT LEAVES BEHIND: NOTHING IT CAN TAKE BACK.
//
// Its applications, its global consents and its people are all named with a
// per-run suffix, and the global consents are revoked at the end — because
// `oauth2.consentRequired` is process-wide and a stray override on a shared
// application would make some LATER job stop being asked and never say why.
// The APPLICATION ENTRIES and the PEOPLE are left, like every other job here:
// this service has no way to delete a person, `ou=users` is append-only by
// design, and an application entry with a run id in its name collides with
// nothing.
//
// It does NOT touch `oauth2.consentRequired`. Turning it off would be the one
// change here that silently disarms every other job in the run.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");

var appconfig;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_consent",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

var api = base + "/admin-api";
var REDIRECT_URI = "http://localhost:9999/consent-callback";

// A suffix per run, so that two runs against one long-lived mock cannot see
// each other's applications, overrides or people. The registry is append-only
// in practice and the directory entirely so — see the header.
var RUN = String(Date.now()).slice(-8);
var CLIENT = "consent-client-" + RUN;
var OTHER_CLIENT = "consent-other-client-" + RUN;
var RESOURCE = "consent-resource-" + RUN;
var RESOURCE_BASE = "https://consent-resource-" + RUN + ".example1.com/";
var PERMISSION = RESOURCE_BASE + "read";

// ---------------------------------------------------------------------------
// THE VERBS. Manual redirects and a cookie jar of our own, because every
// assertion in this file is about WHICH redirect and about a session — a fetch
// that followed them would answer the question by hiding it.
// ---------------------------------------------------------------------------
function form(o) {
  return new URLSearchParams(o).toString();
}

function absolute(location) {
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
}

// One browser. `cookie` is the whole jar: this service sets exactly one cookie
// and every assertion here is about whose session is presenting it.
function browser(name) {
  const self = {
    name: name,
    cookie: "",
    async go(method, path, body) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = {};
      if (self.cookie) {
        headers.cookie = self.cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path), { method: method, redirect: "manual",
                                              headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) { self.cookie = String(one).split(";")[0]; });
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               csp: r.headers.get("content-security-policy") || "", text: text };
    }
  };
  return self;
}

async function get(path) {
  const r = await fetch(api + path);
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    // Not JSON — an HTML error page. The caller reports the status and the raw
    // text, which says more than a parse error would.
    body = raw;
  }
  return { status: r.status, body: body, raw: raw };
}

async function post(path, payload) {
  const r = await fetch(api + path, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {})
  });
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    // As above: an HTML page from a door that answers JSON is worth quoting
    // whole rather than reporting as a parse failure.
    body = raw;
  }
  return { status: r.status, body: body, raw: raw };
}

async function ok(path, payload, what) {
  const r = await post(path, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + path + " should have " + what + "; it answered " + r.status + " " +
    JSON.stringify((r.body && r.body.errors) || r.body).slice(0, 400));
  return r.body;
}

// ---------------------------------------------------------------------------
// THE FLOW, AS ONE FUNCTION, because every section below is a variation on it.
//
// It stops at whatever the authorization endpoint answers with rather than
// driving to a code: which redirect comes back IS the assertion in most of
// these sections.
// ---------------------------------------------------------------------------
function authorizeUrl(clientId, scope, extra) {
  return "/oauth2/authorize?" + form(Object.assign({
    response_type: "code", client_id: clientId, redirect_uri: REDIRECT_URI,
    scope: scope, state: "consent-" + RUN
  }, extra || {}));
}

// Sign in and stop at the FIRST thing the authorization endpoint says
// afterwards. Returns the browser and that answer.
async function signIn(who, clientId, scope, extra) {
  log.debug("Entering signIn(). who=" + who);
  const b = browser(who);
  let r = await b.go("GET", authorizeUrl(clientId, scope, extra));
  assert.ok(/\/authn\/login\?authn=/.test(r.location),
    "an unauthenticated authorization request should go to the sign-in " +
    "screen; it went to " + r.location);
  r = await b.go("GET", r.location);
  const authnId = (r.text.match(/name="authn_id" value="([^"]+)"/) || [])[1];
  assert.ok(authnId, "the sign-in screen carries no authn_id to post back.");
  r = await b.go("POST", "/authn/login",
                 form({ authn_id: authnId, username: who,
                        password: "any-password", action: "login" }));
  assert.ok(r.status === 303 || r.status === 302,
    "the sign-in form should redirect, got " + r.status);
  assert.ok(b.cookie, "signing in should establish a session.");
  r = await b.go("GET", r.location);
  log.debug("Leaving signIn(). " + r.status + " " + r.location);
  return { b: b, r: r };
}

// The consent screen the last answer pointed at, with its `consent_id` read out
// of the FORM rather than off the query string — because the form is what an
// answer is posted with, and reading the parameter instead would be asserting
// this file's reading of the page rather than the page.
async function screen(b, location) {
  log.debug("Entering screen().");
  assert.ok(/\/oauth2\/consent\?consent=/.test(location),
    "expected the consent screen, got " + location);
  const r = await b.go("GET", location);
  assert.strictEqual(r.status, 200,
    "the consent screen should be drawn, got " + r.status);
  const id = (r.text.match(/name="consent_id" value="([^"]+)"/) || [])[1];
  assert.ok(id, "the consent screen carries no consent_id to post back.");
  log.debug("Leaving screen().");
  return { id: id, page: r.text, csp: r.csp };
}

// The scopes the screen is ASKING about, out of its own list, so a section can
// assert what is on the page rather than what this file expected to be.
function askedOn(page) {
  const list = (String(page).match(/<ul class="scopes">([\s\S]*?)<\/ul>/) || [])[1] || "";
  // THE FIRST `<code>` OF EACH `<li>` AND NOT EVERY `<code>` IN THE LIST. A row
  // for a delegated permission carries two more of them in its explanation —
  // the application that exposes it and the base URI the token will be
  // addressed to — and a sweep of the whole block reads one question as three.
  return (list.match(/<li>[\s\S]*?<\/li>/g) || []).map(function (item) {
    const first = (item.match(/<code>([^<]*)<\/code>/) || [])[1] || "";
    return first.replace(/&#x2F;/g, "/").replace(/&amp;/g, "&");
  }).sort();
}

// Every consent recorded for one person, off /admin-api/consent.
async function recordedFor(username) {
  const r = await get("/consent");
  assert.strictEqual(r.status, 200,
    "GET /admin-api/consent should answer the register, got " + r.status);
  return (r.body.users || []).filter(function (one) {
    return one.username === username;
  });
}

// ---------------------------------------------------------------------------
// 1. THE SCREEN APPEARS, AND NOTHING IS ISSUED UNTIL IT IS ANSWERED.
// ---------------------------------------------------------------------------
async function theFirstSignInIsAsked() {
  log.debug("Entering theFirstSignInIsAsked().");
  log.info("=== The first sign-in for a scope is asked, and issues nothing ===");
  const who = usernameFor("consent-first");
  const { b, r } = await signIn(who, CLIENT, "openid profile");
  assert.ok(/\/oauth2\/consent\?consent=/.test(r.location),
    "a first sign-in should be sent to the consent screen; it went to " +
    r.location);
  assert.ok(!/[?&]code=/.test(r.location),
    "AND NOTHING WAS ISSUED. A consent screen that arrives beside a code is a " +
    "consent screen that is decoration: got " + r.location);

  const shown = await screen(b, r.location);
  assert.deepStrictEqual(askedOn(shown.page), ["openid", "profile"],
    "the screen should ask about exactly the two scopes that were requested " +
    "and neither more nor fewer; it asked about " +
    JSON.stringify(askedOn(shown.page)));

  // THE PAGE CARRIES NO SCRIPT, which is the whole reason it needs no CSP
  // relaxation and the reason this job can drive it with fetch. A `<script`
  // here would be a fifth scripted page in a service whose default is
  // `script-src 'none'`, and CLAUDE.md asks for that argument to be MADE rather
  // than inherited.
  assert.ok(shown.page.indexOf("<script") < 0,
    "the consent screen must carry no script: it is two buttons in a form, " +
    "and a page that needed one would be a fifth exception to this service's " +
    "script-src 'none'.");
  assert.ok(/script-src 'none'/.test(shown.csp),
    "and the policy on it should be the service-wide one, untouched; it was " +
    shown.csp);

  // A GET RECORDS NOTHING. Drawing the screen twice must leave the person
  // exactly as unasked as before — otherwise anything that prefetches a link
  // has consented on their behalf.
  await b.go("GET", r.location);
  assert.strictEqual((await recordedFor(who)).length, 0,
    "LOOKING AT THE SCREEN IS NOT ANSWERING IT. Nothing may be recorded by a " +
    "GET: a browser's prefetch, a chat client unfurling the URL and a scanner " +
    "all issue one, and any of them would otherwise have consented for " + who);

  const allowed = await b.go("POST", "/oauth2/consent",
                             form({ consent_id: shown.id, action: "allow" }));
  assert.strictEqual(allowed.status, 303,
    "RFC 9700 section 4.12: the answer to this POST must be a 303, so the " +
    "next request is a GET rather than a replay of the form. Got " +
    allowed.status);
  const back = await b.go("GET", allowed.location);
  assert.ok(/[?&]code=/.test(back.location),
    "Allow should return to the authorization request and issue a code; it " +
    "answered " + back.status + " " + back.location);

  const rows = await recordedFor(who);
  assert.deepStrictEqual(rows.map(function (one) { return one.scope; }).sort(),
    ["openid", "profile"],
    "ONE ROW PER SCOPE, not one per press. A record keyed on the request " +
    "would make the next request for a subset ask again; got " +
    JSON.stringify(rows.map(function (one) { return one.scope; })));
  rows.forEach(function (one) {
    assert.strictEqual(one.client, CLIENT,
      "each row names the client it was agreed for; got " + one.client);
    assert.ok(/^\d{14}Z$/.test(one.at),
      "and when it was agreed, as a GeneralizedTime; got " + one.at);
  });

  // A REPLAY OF THE ANSWER IS REFUSED. The record was spent, so the back
  // button cannot answer it again.
  const replay = await b.go("POST", "/oauth2/consent",
                            form({ consent_id: shown.id, action: "allow" }));
  assert.strictEqual(replay.status, 400,
    "a consent id must be spendable once: a second POST of the same id is a " +
    "back button answering for somebody twice. Got " + replay.status);

  log.debug("Leaving theFirstSignInIsAsked().");
  return { who: who, b: b };
}

// ---------------------------------------------------------------------------
// 2. THE SECOND TIME IS SILENT, AND A NEW SCOPE ASKS ABOUT ITSELF ALONE.
// ---------------------------------------------------------------------------
async function theSecondSignInIsSilent(first) {
  log.debug("Entering theSecondSignInIsSilent().");
  log.info("=== The second request is silent; a new scope asks about itself ===");
  const b = first.b;
  let r = await b.go("GET", authorizeUrl(CLIENT, "openid profile"));
  assert.ok(/[?&]code=/.test(r.location),
    "the same request again should issue a code with no screen; it went to " +
    r.location);

  // THE ORDER OF THE SCOPES MUST NOT MATTER. A consent recorded against the
  // whole `scope` string rather than against each scope would ask again here,
  // and the failure would look like a flaky screen.
  r = await b.go("GET", authorizeUrl(CLIENT, "profile openid"));
  assert.ok(/[?&]code=/.test(r.location),
    "the same two scopes in the other order are the same two scopes; it went " +
    "to " + r.location);

  r = await b.go("GET", authorizeUrl(CLIENT, "openid profile email"));
  assert.ok(/\/oauth2\/consent\?consent=/.test(r.location),
    "adding a scope should ask; it went to " + r.location);
  const shown = await screen(b, r.location);
  assert.deepStrictEqual(askedOn(shown.page), ["email"],
    "AND IT SHOULD ASK ABOUT THE NEW ONE ALONE. A screen that re-listed the " +
    "two already agreed to would be asking a question that has been answered, " +
    "which is how people learn to press Allow without reading; it asked about " +
    JSON.stringify(askedOn(shown.page)));
  assert.ok(/already agreed to/.test(shown.page),
    "the two already agreed to are on the page under a fold, so a screen that " +
    "somebody has seen before explains why it is shorter this time");

  // -----------------------------------------------------------------------
  // DENY. The client is told, and NOTHING is written down.
  // -----------------------------------------------------------------------
  const denied = await b.go("POST", "/oauth2/consent",
                            form({ consent_id: shown.id, action: "deny" }));
  assert.strictEqual(denied.status, 303, "Deny should redirect, got " + denied.status);
  const backAfterDeny = await b.go("GET", denied.location);
  assert.ok(/[?&]error=access_denied/.test(backAfterDeny.location),
    "Deny should reach the CLIENT as access_denied — the screen names the " +
    "outcome and the authorization endpoint decides how it travels, which in " +
    "form_post is not a redirect at all. It went to " + backAfterDeny.location);
  assert.ok(!/[?&]code=/.test(backAfterDeny.location),
    "and no code came with it: " + backAfterDeny.location);

  const rows = await recordedFor(first.who);
  assert.deepStrictEqual(rows.map(function (one) { return one.scope; }).sort(),
    ["openid", "profile"],
    "A REFUSAL RECORDS NOTHING, not even that it was refused. The two agreed " +
    "to before are untouched and `email` is not there; got " +
    JSON.stringify(rows.map(function (one) { return one.scope; })));

  // AND THE REFUSED SCOPE IS ASKED AGAIN, which is what "recorded nothing"
  // has to mean if it means anything.
  r = await b.go("GET", authorizeUrl(CLIENT, "openid profile email"));
  assert.ok(/\/oauth2\/consent\?consent=/.test(r.location),
    "the refused scope should be asked about again; it went to " + r.location);
  log.debug("Leaving theSecondSignInIsSilent().");
}

// ---------------------------------------------------------------------------
// 3. THE TWO PROMPT VALUES OIDC CORE DEFINES FOR THIS.
// ---------------------------------------------------------------------------
async function thePromptParameterIsHonoured(first) {
  log.debug("Entering thePromptParameterIsHonoured().");
  log.info("=== prompt=none and prompt=consent ===");
  const b = first.b;

  let r = await b.go("GET", authorizeUrl(CLIENT, "openid profile",
                                         { prompt: "none" }));
  assert.ok(/[?&]code=/.test(r.location),
    "prompt=none with everything already agreed to should issue a code; it " +
    "went to " + r.location);

  r = await b.go("GET", authorizeUrl(CLIENT, "openid profile email",
                                     { prompt: "none" }));
  assert.ok(/[?&]error=consent_required/.test(r.location),
    "OIDC Core section 3.1.2.6: prompt=none with a scope outstanding is " +
    "`consent_required` and not `interaction_required` — a client that gets " +
    "the general one cannot tell a missing session from a missing consent. It " +
    "went to " + r.location);

  r = await b.go("GET", authorizeUrl(CLIENT, "openid profile",
                                     { prompt: "consent" }));
  assert.ok(/\/oauth2\/consent\?consent=/.test(r.location),
    "prompt=consent should ask again whatever is on the entry; it went to " +
    r.location);
  const shown = await screen(b, r.location);
  assert.deepStrictEqual(askedOn(shown.page), ["openid", "profile"],
    "and it should ask about everything requested rather than nothing; it " +
    "asked about " + JSON.stringify(askedOn(shown.page)));

  // CANCELLING A RE-CONSENT MUST NOT DESTROY WHAT WAS ALREADY AGREED. This is
  // the assertion that stops `prompt=consent` being implemented by clearing
  // the entry first, which would make Deny destructive.
  const denied = await b.go("POST", "/oauth2/consent",
                            form({ consent_id: shown.id, action: "deny" }));
  await b.go("GET", denied.location);
  const rows = await recordedFor(first.who);
  assert.deepStrictEqual(rows.map(function (one) { return one.scope; }).sort(),
    ["openid", "profile"],
    "REFUSING A RE-CONSENT LEAVES THE ORIGINAL ANSWER STANDING. Implementing " +
    "prompt=consent by forgetting first would make this the one press in the " +
    "service that destroys something; got " +
    JSON.stringify(rows.map(function (one) { return one.scope; })));

  r = await b.go("GET", authorizeUrl(CLIENT, "openid profile"));
  assert.ok(/[?&]code=/.test(r.location),
    "and the next ordinary request is silent again; it went to " + r.location);
  log.debug("Leaving thePromptParameterIsHonoured().");
}

// ---------------------------------------------------------------------------
// 4. THE REFUSALS AT THE DOOR ITSELF.
//
// The one that matters most is the THIRD: a consent asked of one person and
// answered by another's browser is the only failure at this door that would
// write something untrue into the directory rather than merely refusing
// something.
// ---------------------------------------------------------------------------
async function theScreenRefusesWhatItShould() {
  log.debug("Entering theScreenRefusesWhatItShould().");
  log.info("=== What the consent screen refuses ===");

  const stranger = browser("stranger");
  let r = await stranger.go("GET", "/oauth2/consent");
  assert.strictEqual(r.status, 400,
    "the screen followed bare names no pending consent and must be refused; " +
    "got " + r.status);
  r = await stranger.go("GET", "/oauth2/consent?consent=never-minted-" + RUN);
  assert.strictEqual(r.status, 400,
    "and so must an id nothing ever minted; got " + r.status);

  // A REAL PENDING CONSENT, ANSWERED BY SOMEBODY ELSE.
  const who = usernameFor("consent-owner");
  const owner = await signIn(who, CLIENT, "openid profile");
  assert.ok(/\/oauth2\/consent\?consent=/.test(owner.r.location),
    "the owner should be asked; they went to " + owner.r.location);
  const id = (owner.r.location.match(/consent=([^&]+)/) || [])[1];

  const other = usernameFor("consent-interloper");
  const interloper = await signIn(other, OTHER_CLIENT, "openid");
  // The interloper is mid-consent of their own; what matters is that they hold
  // a session belonging to somebody else.
  const stolenScreen = await interloper.b.go("GET",
    "/oauth2/consent?consent=" + id);
  assert.strictEqual(stolenScreen.status, 400,
    "A CONSENT ASKED OF ONE PERSON MUST NOT BE DRAWN FOR ANOTHER. Their " +
    "session is perfectly good and belongs to somebody else; got " +
    stolenScreen.status);
  const stolenAnswer = await interloper.b.go("POST", "/oauth2/consent",
    form({ consent_id: id, action: "allow" }));
  assert.strictEqual(stolenAnswer.status, 400,
    "AND MUST NOT BE ANSWERED BY THEM. This is the one refusal at this door " +
    "whose absence would write something UNTRUE into the directory rather " +
    "than merely letting something through: the answer would be filed against " +
    "whoever happened to be signed in. Got " + stolenAnswer.status);
  assert.strictEqual((await recordedFor(who)).length, 0,
    "and nothing was recorded for " + who + " by somebody else's press");
  assert.strictEqual((await recordedFor(other)).length, 0,
    "nor for " + other + ", who pressed it");

  // WITH NO SESSION AT ALL. The record still exists; there is simply nobody to
  // record an answer for.
  const anonymous = browser("anonymous");
  const anon = await anonymous.go("POST", "/oauth2/consent",
    form({ consent_id: id, action: "allow" }));
  assert.strictEqual(anon.status, 400,
    "an answer from a browser with no session belongs to nobody; got " +
    anon.status);
  assert.strictEqual((await recordedFor(who)).length, 0,
    "and still nothing is recorded for " + who);

  // AND THE OWNER CAN STILL ANSWER IT. Every refusal above must have left the
  // pending record alone — a screen that spent itself on a refusal would turn
  // each of those into a denial of service against the person it was asked of.
  const shown = await screen(owner.b, owner.r.location);
  const allowed = await owner.b.go("POST", "/oauth2/consent",
    form({ consent_id: shown.id, action: "allow" }));
  assert.strictEqual(allowed.status, 303,
    "the person it was asked of can still answer it after all of that; got " +
    allowed.status);
  const back = await owner.b.go("GET", allowed.location);
  assert.ok(/[?&]code=/.test(back.location),
    "and the flow finishes; it went to " + back.location);
  log.debug("Leaving theScreenRefusesWhatItShould().");
}

// ---------------------------------------------------------------------------
// 5. THE GLOBAL CONSENT OVERRIDE, ON A DELEGATED PERMISSION.
//
// The section this job exists for. A permission is DEFINED on one application
// and GRANTED to another; a person asking for it by its whole identifier is
// asked about it; an operator consents it for everybody; the next person is not
// asked and NOTHING IS WRITTEN ABOUT THEM; the override is taken away and the
// asking comes back.
//
// Every assertion here is about the difference between an OVERRIDE and a
// RECORD, which is the one thing about this feature that is easy to implement
// as the same thing and impossible to tell apart afterwards.
// ---------------------------------------------------------------------------
async function theGlobalOverrideWorks() {
  log.debug("Entering theGlobalOverrideWorks().");
  log.info("=== Global consent: the override, on a delegated permission ===");

  await ok("/applications/create", {
    identifier: RESOURCE, name: "Consent test resource " + RUN,
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: RESOURCE }
  }, "created the resource application");
  await ok("/permissions/set-permission-base",
           { resource: RESOURCE, baseUri: RESOURCE_BASE },
           "given the resource its base URI");
  await ok("/permissions/define-permission",
           { resource: RESOURCE, name: "read",
             description: "Read the consent test resource on somebody's behalf" },
           "defined the permission");
  await ok("/permissions/grant-permission",
           { client: CLIENT, permission: PERMISSION },
           "granted the permission to the client");

  // -----------------------------------------------------------------------
  // WITHOUT THE OVERRIDE: a person is asked, by the WHOLE identifier.
  // -----------------------------------------------------------------------
  const asked = usernameFor("consent-perm-asked");
  const first = await signIn(asked, CLIENT, "openid " + PERMISSION);
  assert.ok(/\/oauth2\/consent\?consent=/.test(first.r.location),
    "a delegated permission nobody has consented should be asked about; it " +
    "went to " + first.r.location);
  const shown = await screen(first.b, first.r.location);
  assert.deepStrictEqual(askedOn(shown.page).filter(function (one) {
    return one === PERMISSION;
  }), [PERMISSION],
    "AND BY ITS WHOLE IDENTIFIER, never by the bare permission name: two " +
    "resources may each expose a `read`, and a screen that asked about `read` " +
    "would be asking a question whose answer covers an API nobody mentioned. " +
    "It asked about " + JSON.stringify(askedOn(shown.page)));
  assert.ok(shown.page.indexOf("Read the consent test resource") >= 0,
    "the description somebody typed on the permission is on the screen — a " +
    "page listing opaque URLs is a page that teaches people to press Allow");
  assert.ok(shown.page.indexOf(RESOURCE) >= 0,
    "and so is the application that EXPOSES it, so the person can see whose " +
    "API is being asked for");

  // -----------------------------------------------------------------------
  // THE OVERRIDE.
  // -----------------------------------------------------------------------
  await ok("/consent/grant-global-consent",
           { client: CLIENT, scope: PERMISSION },
           "consented the permission for everybody on this client");
  await ok("/consent/grant-global-consent",
           { client: CLIENT, scope: "openid" },
           "consented openid for everybody on this client");

  const register = await get("/consent");
  const overrides = (register.body.globals || []).filter(function (one) {
    return one.client === CLIENT;
  });
  assert.deepStrictEqual(overrides.map(function (one) { return one.scope; }).sort(),
    ["openid", PERMISSION].sort(),
    "both overrides are on the register; got " +
    JSON.stringify(overrides.map(function (one) { return one.scope; })));
  const permissionOverride = overrides.filter(function (one) {
    return one.scope === PERMISSION;
  })[0];
  assert.strictEqual(permissionOverride.resource, RESOURCE,
    "and the one that names a permission resolves to the application that " +
    "exposes it; got " + permissionOverride.resource);
  assert.strictEqual(permissionOverride.granted, true,
    "and says that this client also HOLDS the grant, which is a different " +
    "question from consent and is answered separately");

  const skipped = usernameFor("consent-perm-skipped");
  const second = await signIn(skipped, CLIENT, "openid " + PERMISSION);
  assert.ok(/[?&]code=/.test(second.r.location),
    "A PERSON WHO HAS NEVER BEEN HERE IS NOT ASKED. That is the whole of what " +
    "the override buys, and it is what distinguishes it from every other " +
    "consent in this register. They went to " + second.r.location);
  assert.strictEqual((await recordedFor(skipped)).length, 0,
    "AND NOTHING WAS WRITTEN ABOUT THEM. An override that recorded a consent " +
    "on the way past would be indistinguishable from an answer they gave, and " +
    "taking the override away would then leave them silently consented for " +
    "ever");

  // AND IT IS KEYED ON THE PAIR. A second application asking for the same
  // permission identifier is still asked.
  await ok("/applications/create", {
    identifier: OTHER_CLIENT, name: "Consent test other client " + RUN,
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: OTHER_CLIENT }
  }, "created the second client").catch(function () { /* may already exist */ });
  const elsewhere = usernameFor("consent-perm-elsewhere");
  const third = await signIn(elsewhere, OTHER_CLIENT, "openid " + PERMISSION);
  assert.ok(/\/oauth2\/consent\?consent=/.test(third.r.location),
    "THE OVERRIDE BELONGS TO ONE APPLICATION. A second client asking for the " +
    "same permission is still asked — a service-wide list of harmless scopes " +
    "would mean an application registered five minutes ago inheriting a " +
    "decision made about a different one. It went to " + third.r.location);

  // -----------------------------------------------------------------------
  // AND TAKING IT AWAY ASKS EVERYBODY AGAIN.
  // -----------------------------------------------------------------------
  await ok("/consent/revoke-global-consent",
           { client: CLIENT, scope: PERMISSION },
           "removed the override");
  const again = usernameFor("consent-perm-again");
  const fourth = await signIn(again, CLIENT, "openid " + PERMISSION);
  assert.ok(/\/oauth2\/consent\?consent=/.test(fourth.r.location),
    "removing the override asks again; they went to " + fourth.r.location);
  const askedAgain = await screen(fourth.b, fourth.r.location);
  assert.deepStrictEqual(askedOn(askedAgain.page), [PERMISSION],
    "AND ABOUT THE PERMISSION ALONE: `openid` is still overridden, so the " +
    "two halves of one request are answered by two different rules and only " +
    "one of them changed. It asked about " +
    JSON.stringify(askedOn(askedAgain.page)));

  // The person who was SKIPPED while the override stood is asked now, which is
  // the consequence the console page warns about in words.
  const skippedAgain = await browser("skipped-again");
  skippedAgain.cookie = second.b.cookie;
  const back = await skippedAgain.go("GET",
    authorizeUrl(CLIENT, "openid " + PERMISSION));
  assert.ok(/\/oauth2\/consent\?consent=/.test(back.location),
    "INCLUDING THE PEOPLE IT WAS COVERING, who would have said yes and were " +
    "never asked. That is the price of an override recording nothing, and it " +
    "is why the console says so on the page. They went to " + back.location);
  log.debug("Leaving theGlobalOverrideWorks().");
}

// ---------------------------------------------------------------------------
// 6. TAKING ONE PERSON'S ANSWER BACK.
// ---------------------------------------------------------------------------
async function aRecordedAnswerCanBeTakenBack(first) {
  log.debug("Entering aRecordedAnswerCanBeTakenBack().");
  log.info("=== Revoking one answer, and forgetting all of somebody's ===");

  const under = await post("/consent/revoke-consent",
    { username: first.who, client: CLIENT, scope: "email" });
  assert.strictEqual(under.status, 400,
    "revoking something nobody consented should be refused rather than " +
    "reported as done; got " + under.status);

  await ok("/consent/revoke-consent",
           { username: first.who, client: CLIENT, scope: "profile" },
           "revoked one answer");
  const left = await recordedFor(first.who);
  assert.deepStrictEqual(left.map(function (one) { return one.scope; }), ["openid"],
    "ONE ROW WENT AND THE OTHER STAYED. A revoke keyed on the pair rather " +
    "than the triple would have taken both; got " +
    JSON.stringify(left.map(function (one) { return one.scope; })));

  const r = await first.b.go("GET", authorizeUrl(CLIENT, "openid profile"));
  assert.ok(/\/oauth2\/consent\?consent=/.test(r.location),
    "and the revoked scope is asked about again; it went to " + r.location);
  const shown = await screen(first.b, r.location);
  assert.deepStrictEqual(askedOn(shown.page), ["profile"],
    "about the revoked one ALONE — `openid` is still on their entry; it asked " +
    "about " + JSON.stringify(askedOn(shown.page)));
  await first.b.go("POST", "/oauth2/consent",
                   form({ consent_id: shown.id, action: "allow" }));

  await ok("/consent/forget-user-consent", { username: first.who },
           "forgot everything for one person");
  assert.strictEqual((await recordedFor(first.who)).length, 0,
    "and their entry holds nothing at all afterwards");
  const empty = await post("/consent/forget-user-consent", { username: first.who });
  assert.strictEqual(empty.status, 400,
    "forgetting nothing is refused rather than reported as done; got " +
    empty.status);
  log.debug("Leaving aRecordedAnswerCanBeTakenBack().");
}

// ---------------------------------------------------------------------------
// AND PUT THE PROCESS-WIDE STATE BACK. The overrides are the only thing this
// job leaves that could change what a LATER job sees — a stray global consent
// on a shared application would make some other job stop being asked and never
// say why. tests/CLAUDE.md's second non-optional rule.
// ---------------------------------------------------------------------------
async function restore() {
  log.debug("Entering restore().");
  log.info("=== Restoring: removing this run's global consents ===");
  const register = await get("/consent");
  const mine = (register.body.globals || []).filter(function (one) {
    return one.client === CLIENT || one.client === OTHER_CLIENT;
  });
  for (const one of mine) {
    await ok("/consent/revoke-global-consent",
             { client: one.client, scope: one.scope },
             "removed the override on " + one.client + " for " + one.scope);
  }
  const after = await get("/consent");
  const left = (after.body.globals || []).filter(function (one) {
    return one.client === CLIENT || one.client === OTHER_CLIENT;
  });
  assert.strictEqual(left.length, 0,
    "this run should leave no global consent behind; " + left.length + " left");
  log.debug("Leaving restore(). " + mine.length + " override(s) removed.");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the consent screen at " + base + "/oauth2/consent, and the " +
           "register at " + base + "/admin-api/consent. Run id " + RUN + ".");

  // The client this job signs in to. Created up front so that the screen has a
  // NAME to show rather than a bare client_id — which is also what makes the
  // global consent controls able to name it.
  await ok("/applications/create", {
    identifier: CLIENT, name: "Consent test client " + RUN,
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: CLIENT, oauthRedirectUri: [REDIRECT_URI] }
  }, "created the client application");

  const first = await theFirstSignInIsAsked();
  await theSecondSignInIsSilent(first);
  await thePromptParameterIsHonoured(first);
  await theScreenRefusesWhatItShould();
  await theGlobalOverrideWorks();
  await aRecordedAnswerCanBeTakenBack(first);
  await restore();

  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_consent")
  .description("Drive the mock STS's consent screen over HTTP: that it is " +
      "asked once and not twice, that it records one row per scope, that it " +
      "refuses a replay and somebody else's session, that Deny records " +
      "nothing — and that a global consent on an application's entry stops " +
      "everybody being asked without writing anything about anybody.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
