// File: sts_xacml_endpoints.js
//
// ---------------------------------------------------------------------------
// THE SEVEN /xacml ENDPOINTS, DRIVEN OVER HTTP.
//
// `tests/xacml_conformance.js` holds the ENGINE to 455 cases somebody else
// wrote, `tests/xacml_service.js` holds the store, the PIP and the JSON
// Profile, and `tests/xacml_pep.js` holds the two things about the remote PEP
// that no running service can be asked. All three are in process, and between
// them they never make one HTTP request — so until this file existed, every
// route in `xacml/xacml.js` was uncovered: the decision endpoint, the
// repository, the embedded PEP and the three the remote PEP lives on.
//
// That gap is not academic. The engine being right says nothing about whether
// the endpoint in front of it PARSES what a PEP sends, whether a malformed
// request is a 400 rather than an Indeterminate, whether a disabled policy is
// left out of what a remote PEP pulls, or whether a registration can name
// itself as somebody else's PEP. Every one of those is a property of this
// file's subject and of nothing the in-process suite touches.
//
// ---------------------------------------------------------------------------
// WHY THIS IS THIS REPOSITORY'S OWN (`local: true`) AND NOT THE PARENT'S.
//
// CLAUDE.md's rule is that anything drivable over HTTP belongs in the parent
// project's suite, and a naive reading puts the whole of this file there. It
// does not survive the first assertion.
//
// **A PDP WITH AN EMPTY REPOSITORY ANSWERS NotApplicable TO EVERYTHING.** There
// is no interesting question to ask this surface until a policy exists, and the
// only way to put one there over HTTP is `/admin-api/xacml/create-from-template`
// — a door this repository owns, on the console this repository's own jobs
// cover. So every section below is a CONSOLE CONTROL WITH A PROTOCOL
// CONSEQUENCE: a template built through `/admin-api` decides at `/xacml/pdp`, a
// policy disabled on `/admin/xacml/policies` disappears from what a remote PEP
// pulls, an obligation added in the editor turns a Permit into a refusal at
// `/xacml/protected`, and a PEP disabled on `/admin/xacml/peps` stays disabled
// when it re-registers. That is exactly the argument `sts_consent.js` makes one
// file over, and splitting these in two was refused for its reason: the
// assertion that matters is that the authoring door changes what the DECIDING
// door says, and a test with the two halves in two repositories could not make
// it.
//
// ---------------------------------------------------------------------------
// IT RUNS IN A TRUST REALM OF ITS OWN, AND THAT IS NOT MERELY TIDINESS.
//
// `ou=policies` is per realm, and a realm's repository starts EMPTY — the
// seeded policy is written once, at require time, in the default realm. So a
// throwaway realm gives this job the one thing it cannot otherwise have: a
// repository whose entire contents it wrote. Every count below is exact rather
// than "at least", the sync token moves only when this file moves it, and the
// "no root policy" state — which the default realm can never be in — is
// reachable and asserted.
//
// It also makes the SETTINGS safe. Six sections turn `xacml.enabled`,
// `xacml.remotePeps`, `xacml.pepBias` and `xacml.pepRequireCertificate` off and
// on, and every one of those is process-wide when set at the top level: a job
// that turned XACML off and died would leave every later job in the run driving
// a service answering 501. Set inside the realm they reach nothing else, and
// removing the realm at the end takes them with it — which is why the teardown
// asserts the removal rather than hoping for it.
//
// ---------------------------------------------------------------------------
// THE CLIENT CERTIFICATE IS MINTED HERE, AND IT IS WHAT MAKES TWO OF THESE
// ASSERTIONS POSSIBLE AT ALL.
//
// `POST /xacml/pep/register` names a PEP from the COMMON NAME of the
// certificate it registered with, and falls back to the `name` in the body only
// when there is none — because a PEP that could name itself while holding a
// certificate could register as somebody else's PEP and take over their row.
// The heartbeat follows the same rule. Those are the two places in this family
// where a defect would be a security bug rather than a fidelity one, and
// neither can be checked without presenting a certificate: the refusal path
// proves only that something was demanded, not that what was presented was
// believed over what was claimed. So this file mints a self-signed pair with
// node-forge and sends the registration through `https.request`, which is also
// why those two requests are not `fetch` like everything else here.
//
// The certificate chains to nothing, deliberately: RFC 8705 section 3's
// argument is what this service rests on, that the same key completed the
// handshake — so a certificate that chained to something would be testing a
// property this door does not have.
// ---------------------------------------------------------------------------
//
// ---------------------------------------------------------------------------
// IT WAS MUTATION-TESTED AGAINST SIX MUTANTS BEFORE IT WAS COMMITTED, which is
// `tests/CLAUDE.md`'s rule and is not optional here either: a guard that has
// never failed has not been shown to guard anything. Each was applied to a
// COPY of the tree, driven, and reverted:
//
//   1. a malformed request answered `Indeterminate` instead of 400 — caught by
//      the four refusals in section 4, which is the mutant that section exists
//      for;
//   2. the embedded PEP taught to discharge the obligation it does not know —
//      caught by section 5, where the Permit stops being refused;
//   3. `GET /xacml/pep/policies` sending disabled policies too — caught by
//      section 6, which is a PEP enforcing a policy this service does not;
//   4. a registration taking its name from the BODY in preference to the
//      certificate — caught by section 7, and it is the security-shaped one;
//   5. `?since=` never answering 304 — caught by section 6;
//   6. `xacml.enabled` stopping being honoured — caught by section 9.
//
// The fourth is the one worth keeping in mind when this file is edited: it is
// the only mutant here whose effect is invisible to every other assertion, and
// the only one that needs a client certificate to see at all.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const https = require("https");
const { URL } = require("url");
const { Command, Option } = require("commander");
const forge = require("node-forge");
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
var log = bunyan.createLogger({ name: "sts_xacml_endpoints",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

// The throwaway realm. Lower-cased and folded to what a realm id may hold,
// because the registry refuses anything else and a job that fails on its own
// setup names the wrong thing.
const REALM = ("xacml-" + names.runStamp()).toLowerCase()
    .replace(/[^a-z0-9-]/g, "").slice(0, 40);

const POLICY = "rbac-under-test";
const PEP_CN = "pep-" + names.runStamp();

// The one obligation the embedded PEP knows how to discharge. Written out here
// rather than read from the service, because the whole assertion in section 5
// is that THIS string and no other is discharged — reading it from the module
// under test would make the check agree with whatever the module said.
const DISCHARGEABLE = "urn:sts-mock:xacml:obligation:log";

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
    // Not JSON — an HTML page or an empty 304. The caller reports the status
    // and the raw text, which says more than a parse error would.
    body = null;
  }
  log.debug("Leaving fetchJson(). status=" + r.status);
  return { status: r.status, body: body, text: text,
           etag: r.headers.get("etag") || "",
           type: r.headers.get("content-type") || "" };
}

function get(url) {
  return fetchJson(url);
}

function postJson(url, payload) {
  return fetchJson(url, { method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: JSON.stringify(payload || {}) });
}

// A raw body, for the three malformed requests in section 3. `JSON.stringify`
// cannot produce them, which is the point.
function postRaw(url, raw) {
  return fetchJson(url, { method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: raw });
}

// An /admin-api action that must have worked. The refusal is quoted whole:
// every one of these handlers answers `why` with a sentence naming what it
// wanted, and a test that reported only the status would throw that away.
async function act(action, payload, what) {
  const r = await postJson(api("/xacml/" + action), payload || {});
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST /admin-api/xacml/" + action + " should have " + what + "; it " +
    "answered " + r.status + " " +
    JSON.stringify((r.body && (r.body.why || r.body.error_description)) ||
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
  // tests/saml11_sso.js records: a `set` leaves `source: override` behind, and
  // tests/vendored/admin_api.js reads that field.
  const r = await postJson(api("/config/reset"), { key: key });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "resetting " + key + " should have worked; it answered " + r.status);
}

// ---------------------------------------------------------------------------
// A JSON PROFILE REQUEST, built the way a PEP would.
// ---------------------------------------------------------------------------
function requestFor(subject, action, resource) {
  const request = { Request: {} };
  if (subject !== null) {
    request.Request.AccessSubject = { Attribute: [
      { AttributeId: "urn:oasis:names:tc:xacml:1.0:subject:subject-id",
        Value: subject }
    ] };
  }
  request.Request.Action = { Attribute: [
    { AttributeId: "urn:oasis:names:tc:xacml:1.0:action:action-id",
      Value: action }
  ] };
  request.Request.Resource = { Attribute: [
    { AttributeId: "urn:oasis:names:tc:xacml:1.0:resource:resource-id",
      Value: resource || "https://example.test/records",
      DataType: "anyURI" }
  ] };
  return request;
}

async function decisionFor(subject, action, resource) {
  const r = await postJson(realmUrl("/xacml/pdp"),
                           requestFor(subject, action, resource));
  assert.strictEqual(r.status, 200,
    "POST /xacml/pdp should answer 200 with a JSON Profile response even when " +
    "the answer is a refusal; it answered " + r.status + " " +
    String(r.text).slice(0, 300));
  assert.ok(r.body && Array.isArray(r.body.Response) && r.body.Response.length,
    "a JSON Profile response is an object with a Response ARRAY; this one is " +
    String(r.text).slice(0, 300));
  return r.body.Response[0];
}

// ---------------------------------------------------------------------------
// A CLIENT CERTIFICATE, AND THE ONE REQUEST SHAPE THAT CAN CARRY ONE.
//
// `fetch` in node has no way to present a client certificate, so the two
// requests that need one go through `https.request`. Everything else here is
// fetch, deliberately — a second HTTP client used everywhere would be a second
// thing that could be wrong about a status code.
// ---------------------------------------------------------------------------
function selfSignedFor(commonName) {
  log.debug("Entering selfSignedFor(). cn=" + commonName);
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = "01" + Date.now().toString(16);
  certificate.validity.notBefore = new Date(Date.now() - 60 * 1000);
  certificate.validity.notAfter = new Date(Date.now() + 24 * 3600 * 1000);
  const attributes = [{ name: "commonName", value: commonName },
                      { name: "organizationName", value: "mock-sts tests" }];
  certificate.setSubject(attributes);
  certificate.setIssuer(attributes);
  certificate.sign(keys.privateKey, forge.md.sha256.create());
  log.debug("Leaving selfSignedFor().");
  return { cert: forge.pki.certificateToPem(certificate),
           key: forge.pki.privateKeyToPem(keys.privateKey) };
}

function postWithCertificate(url, payload, identity) {
  log.debug("Entering postWithCertificate(). url=" + url);
  return new Promise(function (resolve, reject) {
    const target = new URL(url);
    const data = JSON.stringify(payload || {});
    const request = https.request({
      host: target.hostname,
      port: target.port || 443,
      path: target.pathname + target.search,
      method: "POST",
      // THE SERVER'S certificate is not the subject here and is regenerated on
      // every start; `tests/tools/trust.js` hands the run an anchor for it and
      // node uses it, but a hand-run without one must still reach the door.
      rejectUnauthorized: false,
      cert: identity.cert,
      key: identity.key,
      headers: { "Content-Type": "application/json",
                 "Content-Length": Buffer.byteLength(data) }
    }, function (response) {
      let text = "";
      response.on("data", function (chunk) { text += chunk; });
      response.on("end", function () {
        let body;
        try {
          body = JSON.parse(text);
        } catch (e) {
          // As above: a non-JSON answer from a door that answers JSON is worth
          // reporting whole rather than as a parse failure.
          body = null;
        }
        log.debug("Leaving postWithCertificate(). status=" +
                  response.statusCode);
        resolve({ status: response.statusCode, body: body, text: text });
      });
    });
    request.on("error", reject);
    request.write(data);
    request.end();
  });
}

// ===========================================================================
// 1. THE SURFACE DESCRIBES ITSELF, AND THE DESCRIPTION IS READ OFF THE SERVICE.
//
// `GET /xacml` is the document a client meets first. The assertion is not that
// it renders: it is that the seven endpoints it advertises are the seven that
// answer, and that every count on it agrees with the endpoint that owns the
// number. A description that drifted from the surface it describes is the one
// defect a page like this can have.
// ===========================================================================
async function theSurfaceDescribesItself() {
  log.debug("Entering theSurfaceDescribesItself().");
  log.info("=== GET /xacml — what this surface says it is ===");

  const html = await get(realmUrl("/xacml"));
  check("GET /xacml draws a page", function () {
    assert.strictEqual(html.status, 200,
      "GET /xacml answered " + html.status);
    assert.ok(/text\/html/.test(html.type),
      "GET /xacml should be HTML for a person; it is " + html.type);
    assert.ok(html.text.indexOf("Policy Decision Point") > 0,
      "the page should say what this service is; it says " +
      html.text.slice(0, 200));
  });

  const doc = await get(realmUrl("/xacml?format=json"));
  check("?format=json answers the same document as JSON", function () {
    assert.strictEqual(doc.status, 200, "?format=json answered " + doc.status);
    assert.ok(doc.body && doc.body.enabled === true,
      "XACML should be on in a realm nobody has turned it off in; the " +
      "document says " + JSON.stringify(doc.body).slice(0, 200));
  });

  // THE SEVEN, ASKED FOR RATHER THAN COUNTED. Each is driven for real
  // elsewhere in this file; what is checked here is that the DOCUMENT names
  // exactly them, because a route added without a line here is invisible to
  // every client that reads this page.
  const advertised = (doc.body.endpoints || []).map(function (one) {
    return one.method + " " + one.path;
  }).sort();
  check("the document advertises exactly the seven endpoints", function () {
    assert.deepStrictEqual(advertised, [
      "GET /xacml",
      "GET /xacml/pep/policies",
      "GET /xacml/policies",
      "GET /xacml/protected",
      "POST /xacml/pdp",
      "POST /xacml/pep/heartbeat",
      "POST /xacml/pep/register"
    ], "GET /xacml advertises " + JSON.stringify(advertised) + ". A route " +
       "added to xacml.js without a line in description() is a route no " +
       "client reading this page can find.");
  });

  // THE COUNTS AGREE WITH THE ENDPOINT THAT OWNS THEM. This is the check that
  // would catch a description reading its own cached idea of the repository.
  const policies = await get(realmUrl("/xacml/policies"));
  check("the repository counts on /xacml agree with /xacml/policies",
        function () {
    assert.strictEqual(doc.body.repository.policies,
                       (policies.body.policies || []).length,
      "GET /xacml says " + doc.body.repository.policies + " policy(ies) and " +
      "GET /xacml/policies lists " + (policies.body.policies || []).length);
    assert.strictEqual(doc.body.repository.root, policies.body.root,
      "the two documents disagree about which policy is the root: " +
      doc.body.repository.root + " vs " + policies.body.root);
  });

  check("a brand new realm's repository is EMPTY", function () {
    assert.strictEqual((policies.body.policies || []).length, 0,
      "this realm was created seconds ago and its ou=policies holds " +
      JSON.stringify((policies.body.policies || []).map(function (one) {
        return one.name;
      })) + ". The seeded policy is written once, in the DEFAULT realm, at " +
      "require time — a realm that inherited it would mean every count in " +
      "this file is measuring somebody else's repository as well as its own.");
    assert.strictEqual(policies.body.root, null,
      "an empty repository has no root; this one names " + policies.body.root);
    assert.ok(String(policies.body.rootNote || "").indexOf("NotApplicable") > 0,
      "a repository with no root should SAY that every decision is " +
      "NotApplicable rather than leaving it to be discovered; it says " +
      policies.body.rootNote);
  });

  log.info("[surface] OK — the document names seven endpoints and its counts " +
           "come from the repository rather than from itself.");
  log.debug("Leaving theSurfaceDescribesItself().");
}

// ===========================================================================
// 2. AN EMPTY REPOSITORY, AND THE ONE CASE THE TWO PEP BIASES DISAGREE ABOUT.
//
// This section exists because it can only be run HERE. `NotApplicable` is what
// a PDP says when nothing applies, and the default realm always has a root
// policy — so the state where the two biases differ is unreachable there. XACML
// section 7.2's whole point is that deny-biased and permit-biased agree on
// every Permit and every Deny and differ on exactly this, which is the answer
// nobody writes a test for.
// ===========================================================================
async function anEmptyRepositoryDecidesNothing() {
  log.debug("Entering anEmptyRepositoryDecidesNothing().");
  log.info("=== An empty repository, and the bias that reads it ===");

  const answer = await decisionFor("carol", "GET");
  check("a PDP with no root policy answers NotApplicable", function () {
    assert.strictEqual(answer.Decision, "NotApplicable",
      "an empty repository has nothing to say about a request, which is " +
      "precisely NotApplicable. It answered " + answer.Decision);
    assert.strictEqual(answer.Status.StatusCode.Value,
                       "urn:oasis:names:tc:xacml:1.0:status:ok",
      "and it is not an ERROR — a repository with no policy in it is a " +
      "state, not a fault. The status is " +
      JSON.stringify(answer.Status));
  });

  const denied = await get(realmUrl("/xacml/protected?subject=carol&action=GET"));
  check("the deny-biased PEP refuses that with 403", function () {
    assert.strictEqual(denied.status, 403,
      "deny-biased means anything that is not Permit is a refusal; the " +
      "embedded PEP answered " + denied.status);
    assert.strictEqual(denied.body.decision, "NotApplicable",
      "and it should report the DECISION beside the enforcement, because " +
      "they are different facts; it reported " + denied.body.decision);
    assert.strictEqual(denied.body.allowed, false, "allowed should be false");
    assert.strictEqual(denied.body.bias, "deny-biased",
      "the bias it enforced with is " + denied.body.bias);
  });

  await setSetting("xacml.pepBias", "permit-biased");
  const allowed = await get(realmUrl("/xacml/protected?subject=carol&action=GET"));
  check("the SAME decision is allowed by a permit-biased PEP", function () {
    assert.strictEqual(allowed.status, 200,
      "permit-biased means anything that is not Deny is allowed; the PEP " +
      "answered " + allowed.status + " " + String(allowed.text).slice(0, 200));
    assert.strictEqual(allowed.body.decision, "NotApplicable",
      "THE PDP MUST NOT HAVE CHANGED ITS MIND. `xacml.pepBias` is the PEP's " +
      "decision and not the PDP's, so the decision either side of the flip " +
      "must be the same NotApplicable and only the enforcement differs. It " +
      "answered " + allowed.body.decision + ", which would mean the setting " +
      "reached the engine.");
    assert.strictEqual(allowed.body.allowed, true, "allowed should be true");
    assert.strictEqual(allowed.body.bias, "permit-biased",
      "the bias it enforced with is " + allowed.body.bias);
  });
  await resetSetting("xacml.pepBias");

  const back = await get(realmUrl("/xacml/protected?subject=carol&action=GET"));
  check("resetting the setting puts the refusal back", function () {
    assert.strictEqual(back.status, 403,
      "after /admin-api/config/reset the PEP should be deny-biased again; " +
      "it answered " + back.status);
  });

  log.info("[bias] OK — one decision, two enforcements, and the PDP said the " +
           "same thing both times.");
  log.debug("Leaving anEmptyRepositoryDecidesNothing().");
}

// ===========================================================================
// 3. A POLICY BUILT THROUGH THE CONSOLE'S API DECIDES AT /xacml/pdp.
//
// The template is the RBAC one: `employeeType=admin` may do anything,
// `employeeType=staff` may GET or HEAD, and the combining algorithm is
// deny-unless-permit so anything else is a Deny rather than a NotApplicable.
// The three seeded people carry those attributes in EVERY realm — carol is the
// admin, alice and bob are staff — which is what makes the decisions below
// predictable without this file writing a directory entry.
//
// THE ATTRIBUTE COMES FROM THE PIP AND NOT FROM THE REQUEST, which is the half
// worth stating: nothing below sends an `employeeType`, so a Permit here is the
// PDP having asked the embedded directory about the person the request names.
// ===========================================================================
async function aPolicyBuiltThroughTheApiDecides() {
  log.debug("Entering aPolicyBuiltThroughTheApiDecides().");
  log.info("=== A template built on /admin-api decides at /xacml/pdp ===");

  const built = await act("create-from-template", {
    template: "rbac", name: POLICY,
    p_roleAttribute: "employeeType",
    p_adminRoles: "admin",
    p_readerRoles: "staff",
    p_readerActions: "GET, HEAD"
  }, "created the policy");

  check("the first policy in an empty repository becomes the root", function () {
    assert.ok(String(built.what).indexOf("root") > 0,
      "a repository with a policy and no root decides nothing, so the first " +
      "one created should say it became the root. It said: " + built.what);
  });

  const listed = await get(realmUrl("/xacml/policies"));
  check("GET /xacml/policies now lists it, with its document", function () {
    const rows = listed.body.policies || [];
    assert.strictEqual(rows.length, 1, "the repository should hold exactly " +
      "the one policy this file created; it holds " + rows.length);
    assert.strictEqual(rows[0].name, POLICY);
    assert.strictEqual(listed.body.root, POLICY,
      "and it should be the root; the root is " + listed.body.root);
    // THE DOCUMENT IS PRESENT ON PURPOSE and is a deliberate departure from
    // how /admin/ldap/* treats the directory. A policy is a rule, and a rule
    // nobody can read is a rule nobody can check.
    assert.ok(String(rows[0].document).indexOf("<Policy") >= 0,
      "the policy DOCUMENT should be in this answer; the row carries " +
      Object.keys(rows[0]).join(", "));
    assert.deepStrictEqual(rows[0].problems, [],
      "a policy built from a template should type-check; it reports " +
      JSON.stringify(rows[0].problems));
  });

  const cases = [
    { who: "carol", action: "DELETE", decision: "Permit",
      why: "carol is the admin, and an admin may do anything" },
    { who: "carol", action: "GET", decision: "Permit",
      why: "an admin may GET as well" },
    { who: "alice", action: "GET", decision: "Permit",
      why: "alice is staff, and staff may GET" },
    { who: "alice", action: "DELETE", decision: "Deny",
      why: "staff may not DELETE, and deny-unless-permit denies rather than " +
           "answering NotApplicable" },
    { who: "nobody-at-all", action: "GET", decision: "Deny",
      why: "a person the directory has never heard of holds no employeeType, " +
           "so the PIP returns an EMPTY BAG and no rule matches" }
  ];
  for (const one of cases) {
    const answer = await decisionFor(one.who, one.action);
    check("POST /xacml/pdp: " + one.who + " " + one.action + " -> " +
          one.decision, function () {
      assert.strictEqual(answer.Decision, one.decision,
        one.who + " asking to " + one.action + " should be " + one.decision +
        " — " + one.why + ". The PDP said " + answer.Decision + " " +
        JSON.stringify(answer.Status));
    });
  }

  // A REQUEST WITH NO SUBJECT AT ALL. Not an error: a resource-only decision is
  // perfectly ordinary, and the PIP hands back an empty bag rather than
  // refusing to answer.
  const anonymous = await decisionFor(null, "GET");
  check("a request naming no subject is answered rather than refused",
        function () {
    assert.strictEqual(anonymous.Decision, "Deny",
      "a request with no subject-id gets an empty bag for every subject " +
      "attribute and no rule matches, so deny-unless-permit denies. It " +
      "answered " + anonymous.Decision);
    assert.strictEqual(anonymous.Status.StatusCode.Value,
                       "urn:oasis:names:tc:xacml:1.0:status:ok",
      "and it is not an error; the status is " + JSON.stringify(anonymous.Status));
  });

  log.info("[pdp] OK — five decisions, each resolved against an attribute " +
           "the request never carried.");
  log.debug("Leaving aPolicyBuiltThroughTheApiDecides().");
}

// ===========================================================================
// 4. A MALFORMED REQUEST IS A 400 AND NEVER AN INDETERMINATE.
//
// This is the distinction `xacml.js` argues at the endpoint and the one a PEP
// most needs: an Indeterminate is an answer ABOUT the request, and a 400 says
// there was no request to answer about. Collapsing them has a PEP enforce its
// bias over somebody's typo — under a permit-biased PEP, that is an allowance.
//
// All four are NEGATIVES, which is most of what this section is worth. A
// decision endpoint that answers good requests correctly looks finished.
// ===========================================================================
async function aMalformedRequestIsRefused() {
  log.debug("Entering aMalformedRequestIsRefused().");
  log.info("=== The four ways a request is not a request ===");

  const bad = [
    { what: "not JSON at all", body: "{ this is not json",
      says: "valid JSON" },
    { what: "JSON with no Request member", body: '{"nope":1}',
      says: "Request" },
    { what: "a Request that is not an object", body: '{"Request":"please"}',
      says: "Request" },
    { what: "an attribute with an unknown DataType",
      body: JSON.stringify({ Request: { AccessSubject: { Attribute: [
        { AttributeId: "x", Value: "y", DataType: "cheese" } ] } } }),
      says: "DataType" }
  ];
  for (const one of bad) {
    const r = await postRaw(realmUrl("/xacml/pdp"), one.body);
    check("a request that is " + one.what + " is refused 400", function () {
      assert.strictEqual(r.status, 400,
        "a malformed request must be a 400 and never a decision: an " +
        "Indeterminate here would be enforced by the PEP's bias, which under " +
        "permit-bias is an ALLOWANCE for somebody's typo. It answered " +
        r.status + " " + String(r.text).slice(0, 300));
      assert.strictEqual(r.body.error, "invalid_request",
        "the refusal should be invalid_request; it is " +
        JSON.stringify(r.body).slice(0, 200));
      assert.ok(String(r.body.error_description).indexOf(one.says) >= 0,
        "and it should say what was wrong — the description should mention " +
        '"' + one.says + '". It says: ' + r.body.error_description);
    });
  }

  // AND THE ENDPOINT IS STILL ALIVE AFTERWARDS. Four refusals in a row is
  // exactly the shape that catches a handler which throws past its own error
  // path and leaves the route wedged.
  const after = await decisionFor("carol", "GET");
  check("the endpoint still decides after four refusals", function () {
    assert.strictEqual(after.Decision, "Permit",
      "after four malformed requests the endpoint answered " + after.Decision);
  });

  log.info("[refusals] OK — four shapes refused 400, each naming what was " +
           "wrong, and the endpoint still decides.");
  log.debug("Leaving aMalformedRequestIsRefused().");
}

// ===========================================================================
// 5. THE EMBEDDED PEP, AND THE PART OF SECTION 7.2 IMPLEMENTATIONS SKIP.
//
// An obligation is the half of a decision that says "yes, AND you must also do
// this". A PEP that allows the access while dropping the obligation has
// enforced half a policy and reported success — so an obligation this PEP
// cannot discharge turns a Permit into a REFUSAL.
//
// The pair below is what makes that assertable: the editor's `add-obligation`
// mints `urn:sts-mock:xacml:obligation:1`, which this PEP has never heard of,
// and `edit-obligation` renames it to the one it knows. Same policy, same
// request, same Permit — and the enforcement flips, which is the only way to
// show that the refusal was about the OBLIGATION and not about the decision.
// ===========================================================================
async function anUndischargeableObligationRefuses() {
  log.debug("Entering anUndischargeableObligationRefuses().");
  log.info("=== The embedded PEP and an obligation it cannot discharge ===");

  const before = await get(realmUrl("/xacml/protected?subject=carol&action=GET"));
  check("carol is allowed before any obligation exists", function () {
    assert.strictEqual(before.status, 200,
      "carol is the admin and the policy permits her; the PEP answered " +
      before.status + " " + String(before.text).slice(0, 200));
    assert.deepStrictEqual(before.body.obligations, [],
      "and the decision carries no obligations yet; it carries " +
      JSON.stringify(before.body.obligations));
  });

  await act("add-policy-obligation", { policy: POLICY, path: "", on: "Permit" },
            "added an obligation to the policy");

  const refused = await get(realmUrl("/xacml/protected?subject=carol&action=GET"));
  check("an undischargeable obligation turns the Permit into a refusal",
        function () {
    assert.strictEqual(refused.status, 403,
      "section 7.2: a PEP that cannot discharge an obligation must refuse. " +
      "It answered " + refused.status + " " + String(refused.text).slice(0, 300));
    assert.strictEqual(refused.body.decision, "Permit",
      "AND THE DECISION IS STILL PERMIT, which is the whole point — the PDP " +
      "permitted and the PEP refused, and reporting the refusal as a Deny " +
      "would hide which of the two said no. It reported " +
      refused.body.decision);
    assert.strictEqual(refused.body.allowed, false);
    assert.ok(String(refused.body.why).indexOf("obligation") > 0,
      "and the refusal should name the obligation as the cause; it says: " +
      refused.body.why);
    assert.deepStrictEqual(refused.body.obligations,
      [{ id: "urn:sts-mock:xacml:obligation:1", discharged: false }],
      "the obligation should be reported UNDISCHARGED rather than omitted; " +
      "it reports " + JSON.stringify(refused.body.obligations));
  });

  // Find it in the tree rather than guessing its path: the editor's own view is
  // where a person would read it, and a hard-coded `obligations.0` would keep
  // passing if the tree stopped listing obligations at all.
  const tree = await get(api("/xacml/editor?policy=" + POLICY));
  const obligation = (tree.body.tree || []).filter(function (row) {
    return row.kind === "obligation";
  })[0];
  check("the editor's tree shows the obligation that was added", function () {
    assert.ok(obligation, "no obligation row in the editor tree: " +
      JSON.stringify((tree.body.tree || []).map(function (r) {
        return r.kind;
      })));
  });

  await act("edit-obligation",
            { policy: POLICY, path: obligation.path, id: DISCHARGEABLE,
              on: "Permit" },
            "renamed the obligation to the one this PEP knows");

  const discharged = await get(realmUrl("/xacml/protected?subject=carol&action=GET"));
  check("the one obligation this PEP knows IS discharged, and access returns",
        function () {
    assert.strictEqual(discharged.status, 200,
      "with the obligation renamed to " + DISCHARGEABLE + " the PEP can " +
      "discharge it and the Permit stands; it answered " + discharged.status +
      " " + String(discharged.text).slice(0, 300));
    assert.deepStrictEqual(discharged.body.obligations,
      [{ id: DISCHARGEABLE, discharged: true }],
      "and it should say so on the row rather than silently allowing; it " +
      "reports " + JSON.stringify(discharged.body.obligations));
  });

  // Put the policy back to what section 6 and 7 expect. The obligation was the
  // subject here; leaving it would make every later Permit carry one.
  await act("remove", { policy: POLICY, path: obligation.path },
            "removed the obligation again");
  const clean = await get(realmUrl("/xacml/protected?subject=carol&action=GET"));
  check("removing the obligation leaves an ordinary Permit", function () {
    assert.strictEqual(clean.status, 200);
    assert.deepStrictEqual(clean.body.obligations, [],
      "the obligation should be gone; the decision carries " +
      JSON.stringify(clean.body.obligations));
  });

  log.info("[obligations] OK — one Permit enforced three ways, and only the " +
           "obligation changed.");
  log.debug("Leaving anUndischargeableObligationRefuses().");
}

// ===========================================================================
// 6. WHAT A REMOTE PEP PULLS, AND THE THREE DIFFERENCES FROM WHAT A PERSON
//    READS.
//
// `GET /xacml/pep/policies` is for a MACHINE about to evaluate what it gets:
// disabled policies are left out, the static problem list is not there, and it
// carries a sync token and honours `?since=`. The last is what makes polling
// cheap enough to be the contract — and THE PULL IS THE CONTRACT is the claim
// the whole remote-PEP design rests on.
// ===========================================================================
async function aRemotePepPulls() {
  log.debug("Entering aRemotePepPulls().");
  log.info("=== What a remote PEP pulls ===");

  const first = await get(realmUrl("/xacml/pep/policies"));
  check("a pull answers the enabled policies with a sync token", function () {
    assert.strictEqual(first.status, 200, "the pull answered " + first.status);
    assert.ok(first.body.syncToken, "there is no syncToken on the answer: " +
      JSON.stringify(first.body).slice(0, 200));
    assert.strictEqual(first.etag, '"' + first.body.syncToken + '"',
      "the token should be in an ETag as well, so an ordinary HTTP cache or a " +
      "client library that already speaks conditional requests behaves " +
      "correctly knowing nothing about XACML. The ETag is " + first.etag);
    assert.strictEqual((first.body.policies || []).length, 1,
      "one enabled policy should come back; " +
      (first.body.policies || []).length + " did");
    assert.strictEqual(first.body.root, POLICY);
  });

  check("the pull carries the document and NOT the static problem list",
        function () {
    const row = first.body.policies[0];
    assert.ok(String(row.document).indexOf("<Policy") >= 0,
      "a PEP evaluates the document, so the document must be here");
    assert.strictEqual(row.problems, undefined,
      "the static problems are for a PERSON looking at /xacml/policies — a " +
      "PEP has its own validator and will refuse a bad document again. The " +
      "row carries " + Object.keys(row).join(", "));
  });

  const unchanged = await fetchJson(
    realmUrl("/xacml/pep/policies?since=" + encodeURIComponent(first.body.syncToken)));
  check("?since= with the current token answers 304 and no body", function () {
    assert.strictEqual(unchanged.status, 304,
      "an unchanged repository must answer 304 rather than 200 with a flag — " +
      "this is the answer a PEP polling every few seconds gets almost every " +
      "time. It answered " + unchanged.status);
    assert.strictEqual(unchanged.text, "",
      "a 304 carries no body; this one carried " +
      String(unchanged.text).slice(0, 200));
    assert.strictEqual(unchanged.etag, '"' + first.body.syncToken + '"',
      "and it should still carry the ETag; it carried " + unchanged.etag);
  });

  const stale = await fetchJson(realmUrl("/xacml/pep/policies?since=not-the-token"));
  check("?since= with a token this repository never had answers 200",
        function () {
    assert.strictEqual(stale.status, 200,
      "a PEP holding a token from another repository, or from before a " +
      "restart, must be given the policies rather than a 304 it would read " +
      "as 'you are current'. It answered " + stale.status);
  });

  // A DISABLED POLICY IS LEFT OUT RATHER THAN SENT WITH A FLAG, because a PEP
  // that loaded one would enforce a policy this service does not. That is the
  // difference from /xacml/policies, which lists it — asserted here in both
  // directions in one breath.
  await act("disable", { name: POLICY }, "disabled the policy");
  const withoutIt = await get(realmUrl("/xacml/pep/policies"));
  const stillListed = await get(realmUrl("/xacml/policies"));
  check("a disabled policy leaves the pull and stays on the repository page",
        function () {
    assert.strictEqual((withoutIt.body.policies || []).length, 0,
      "a disabled policy must not reach a PEP; the pull sent " +
      JSON.stringify((withoutIt.body.policies || []).map(function (one) {
        return one.name;
      })));
    assert.strictEqual(withoutIt.body.root, null,
      "and with the only policy disabled there is no root; the pull says " +
      withoutIt.body.root);
    assert.strictEqual((stillListed.body.policies || []).length, 1,
      "while /xacml/policies still lists it, because that answer is for " +
      "somebody looking at the repository. It listed " +
      (stillListed.body.policies || []).length);
    assert.strictEqual(stillListed.body.policies[0].enabled, false,
      "with enabled: false on the row");
  });

  check("the sync token moved when the repository changed", function () {
    assert.notStrictEqual(withoutIt.body.syncToken, first.body.syncToken,
      "the token is a digest of what would be SENT, so disabling the only " +
      "policy must move it. It is still " + withoutIt.body.syncToken);
  });

  await act("enable", { name: POLICY }, "enabled the policy again");
  const restored = await get(realmUrl("/xacml/pep/policies"));
  check("re-enabling it restores the token it had", function () {
    assert.strictEqual(restored.body.syncToken, first.body.syncToken,
      "the token is over the BYTES that would be sent, so a repository " +
      "returned to a previous state has its previous token — which is what " +
      "lets a PEP that missed both changes discover it never needed to pull. " +
      "It is " + restored.body.syncToken + " and was " + first.body.syncToken);
  });

  log.info("[pull] OK — 200, 304, a token that moves with the bytes, and a " +
           "disabled policy that reaches nobody.");
  log.debug("Leaving aRemotePepPulls().");
}

// ===========================================================================
// 7. REGISTERING, AND THE TWO PLACES A DEFECT WOULD BE A SECURITY BUG.
//
// Registering is the one door in this family that asks for a credential, and it
// asks a different question from every other gate here: not who the decision is
// about, but WHICH PEP IS THIS. What rests on the answer is a directory entry,
// a row on the console and an address this service will later dial.
//
// The two assertions that matter are the ones about NAMING. A PEP holding a
// certificate is named from the certificate and never from the body — on the
// registration and on the heartbeat alike — because otherwise anything that can
// complete a handshake could take over somebody else's row and file counters
// against it.
// ===========================================================================
async function registeringAPep() {
  log.debug("Entering registeringAPep().");
  log.info("=== Registering a remote PEP ===");

  const identity = selfSignedFor(PEP_CN);

  const refused = await postJson(realmUrl("/xacml/pep/register"),
                                 { name: "no-certificate-here" });
  check("a registration with no client certificate is refused 401", function () {
    assert.strictEqual(refused.status, 401,
      "xacml.pepRequireCertificate is on by default; the door answered " +
      refused.status + " " + String(refused.text).slice(0, 300));
    assert.strictEqual(refused.body.error, "invalid_client");
    assert.ok(String(refused.body.error_description)
                .indexOf("xacml.pepRequireCertificate") > 0,
      "the refusal should name the setting that caused it; it says: " +
      refused.body.error_description);
    assert.ok(String(refused.body.error_description)
                .indexOf("/xacml/pep/policies") > 0,
      "AND IT SHOULD SAY THAT REGISTERING IS NOT WHAT LETS A PEP ENFORCE. " +
      "The shape of this register looks like an access-control list and is " +
      "not one: an unregistered PEP pulls and decides perfectly. A refusal " +
      "that did not say so would send somebody looking for a permission " +
      "problem they do not have. It says: " + refused.body.error_description);
  });

  const registered = await postWithCertificate(
    realmUrl("/xacml/pep/register"),
    // THE BODY CLAIMS TO BE SOMEBODY ELSE. That is the test.
    { name: "somebody-elses-pep", notifyUrl: "https://127.0.0.1:9/notify",
      bias: "deny-biased", version: "test", resource: "https://example.test/" },
    identity);
  check("a registration with a certificate is named from the CERTIFICATE",
        function () {
    assert.strictEqual(registered.status, 201,
      "a first registration is a 201; it answered " + registered.status + " " +
      String(registered.text).slice(0, 300));
    assert.strictEqual(registered.body.name, PEP_CN,
      "THE NAME MUST COME FROM THE COMMON NAME OF THE CERTIFICATE AND NEVER " +
      "FROM THE BODY. This registration presented a certificate for " +
      PEP_CN + " and asked to be called \"somebody-elses-pep\"; it was " +
      "registered as \"" + registered.body.name + "\". A PEP that could name " +
      "itself while holding a certificate could take over another PEP's row, " +
      "which is the one thing in this family that would be a security bug " +
      "rather than a fidelity one.");
    assert.strictEqual(registered.body.authenticated, true,
      "and the row should record that something was proved");
    assert.ok(String(registered.body.identity).indexOf(PEP_CN) >= 0,
      "the identity should be the certificate's DN; it is " +
      registered.body.identity);
  });

  check("the registration answers the contract rather than implying it",
        function () {
    assert.ok(String(registered.body.note).indexOf("PULL IS THE CONTRACT") > 0,
      "the answer should say that polling is the mechanism and the nudge an " +
      "optimisation; it says: " + String(registered.body.note).slice(0, 200));
    assert.ok(registered.body.policiesUrl &&
              registered.body.policiesUrl.indexOf("/realm/" + REALM) > 0,
      "and it should hand back the URLs IN THE REALM it was registered in, " +
      "because a PEP given the default realm's would poll somebody else's " +
      "repository for ever. It handed back " + registered.body.policiesUrl);
    assert.strictEqual(registered.body.notify.usable, true,
      "an https notify URL is usable; the answer says " +
      JSON.stringify(registered.body.notify));
  });

  const again = await postWithCertificate(realmUrl("/xacml/pep/register"),
                                          { notifyUrl: "http://127.0.0.1:9/n" },
                                          identity);
  check("re-registering is a 200 and says so", function () {
    assert.strictEqual(again.status, 200,
      "a re-registration is not a creation; it answered " + again.status);
    assert.strictEqual(again.body.created, false);
  });
  check("a plain http notify URL is reported unusable, with the reason",
        function () {
    assert.strictEqual(again.body.notify.usable, false,
      "xacml.pepNotifyAllowInsecure is off, so an http notify URL cannot be " +
      "dialled. The answer says " + JSON.stringify(again.body.notify));
    assert.ok(String(again.body.notify.why).indexOf("pepNotifyAllowInsecure") > 0,
      "AND IT IS SAID BACK IMMEDIATELY rather than discovered the first time " +
      "a nudge is not delivered — a PEP whose notify URL this service will " +
      "never dial should find out while somebody is still looking at the " +
      "deployment. It says: " + again.body.notify.why);
  });

  // Put the usable URL back: section 8 saves a policy with this PEP registered
  // and asserts that the save does not wait on the nudge.
  await postWithCertificate(realmUrl("/xacml/pep/register"),
                            { notifyUrl: "https://127.0.0.1:9/notify" },
                            identity);

  const nameless = await postJson(realmUrl("/xacml/pep/heartbeat"), {});
  check("a heartbeat that says who it is from is refused 400", function () {
    assert.strictEqual(nameless.status, 400,
      "a nameless heartbeat answered " + nameless.status);
    assert.ok(String(nameless.body.error_description).indexOf("name") > 0,
      "and it should say how to name one; it says " +
      nameless.body.error_description);
  });

  const ghost = await postJson(realmUrl("/xacml/pep/heartbeat"),
                               { name: "never-registered" });
  check("a heartbeat from something that never registered is refused 404",
        function () {
    assert.strictEqual(ghost.status, 404,
      "a heartbeat must not CREATE a row — one made here would carry no " +
      "certificate, no notify URL and no registration date. It answered " +
      ghost.status);
    assert.ok(String(ghost.body.error_description).indexOf("register") > 0,
      "and it should name the registration endpoint; it says " +
      ghost.body.error_description);
  });

  const misfiled = await postWithCertificate(realmUrl("/xacml/pep/heartbeat"),
    { name: "somebody-elses-pep", syncToken: "a-stale-token", decisions: 7,
      allowed: 4, refused: 3 }, identity);
  check("a heartbeat with a certificate files against the CERTIFICATE's row",
        function () {
    assert.strictEqual(misfiled.status, 200,
      "the heartbeat answered " + misfiled.status + " " +
      String(misfiled.text).slice(0, 200));
    assert.strictEqual(misfiled.body.name, PEP_CN,
      "the same rule as the registration and for the same reason: a PEP " +
      "holding a certificate must not be able to file its counters against " +
      "somebody else's row. This one claimed to be \"somebody-elses-pep\" and " +
      "was filed as \"" + misfiled.body.name + "\".");
  });
  check("and it is TOLD it is behind rather than left to compare", function () {
    assert.strictEqual(misfiled.body.current, false,
      "the token it reported is not the repository's, so it is behind; the " +
      "answer says current=" + misfiled.body.current);
    assert.ok(String(misfiled.body.action).indexOf("pull") >= 0,
      "and it should be told what to do about it: " + misfiled.body.action);
  });

  const current = await get(realmUrl("/xacml/pep/policies"));
  const uptodate = await postWithCertificate(realmUrl("/xacml/pep/heartbeat"),
    { syncToken: current.body.syncToken, policyCount: 1 }, identity);
  check("a heartbeat holding the current token is told it is current",
        function () {
    assert.strictEqual(uptodate.body.current, true,
      "this PEP holds the repository's own token and was told current=" +
      uptodate.body.current);
    assert.ok(String(uptodate.body.action).indexOf("nothing") >= 0,
      "and the action should be nothing: " + uptodate.body.action);
  });

  // THE COUNTERS REACHED THE CONSOLE. A remote PEP's enforcement happened in
  // another process and this service saw none of it — the heartbeat is the only
  // way it is visible here at all, which makes the read-back the point rather
  // than a formality.
  const console_ = await get(api("/xacml/peps"));
  const row = (console_.body.peps || []).filter(function (one) {
    return one.name === PEP_CN;
  })[0];
  check("the PEP's counters are on /admin-api/xacml/peps", function () {
    assert.ok(row, "the register holds " +
      JSON.stringify((console_.body.peps || []).map(function (one) {
        return one.name;
      })));
    assert.strictEqual(row.decisions, 7,
      "the decisions it reported should be on its row; the row says " +
      row.decisions);
    assert.strictEqual(row.allowed, 4);
    assert.strictEqual(row.refused, 3);
    assert.strictEqual(row.authenticated, true,
      "and the row should record that it registered over mutual TLS");
  });

  // ---------------------------------------------------------------------------
  // THE ONE THAT WOULD HAVE BEEN A SECURITY-SHAPED MISTAKE THE OTHER WAY ROUND:
  // a PEP an administrator disabled must not be able to re-enable itself by
  // reconnecting.
  // ---------------------------------------------------------------------------
  await act("disable-pep", { name: PEP_CN }, "disabled the PEP");
  const afterDisable = await postWithCertificate(realmUrl("/xacml/pep/register"),
                                                 {}, identity);
  const rows = await get(api("/xacml/peps"));
  const still = (rows.body.peps || []).filter(function (one) {
    return one.name === PEP_CN;
  })[0];
  check("a disabled PEP cannot re-enable itself by re-registering", function () {
    assert.strictEqual(afterDisable.status, 200,
      "the re-registration itself is accepted; it answered " +
      afterDisable.status);
    assert.strictEqual(still.enabled, false,
      "BUT THE ROW MUST STAY DISABLED. An administrator disabled this PEP on " +
      "the console; a component that could undo that by reconnecting would " +
      "make the control on that page meaningless. The row says enabled=" +
      still.enabled);
  });

  // ---------------------------------------------------------------------------
  // WHAT A RE-REGISTRATION KEEPS AND WHAT IT TAKES FROM THE BODY, which is one
  // split rather than two behaviours and is easy to get backwards in either
  // direction. The registration above carried an EMPTY body:
  //
  //   * the COUNTERS and the registration date survive it, because a PEP that
  //     restarted has not un-enforced anything and a date that reset on every
  //     restart could never show a component restarting every few minutes;
  //   * the NOTIFY URL does not, because it is the PEP's own address — this is
  //     how one that moved says so, and how one that no longer wants to be
  //     nudged stops being. A URL that survived a registration omitting it
  //     could only be cleared by an administrator.
  // ---------------------------------------------------------------------------
  check("a re-registration keeps the counters and takes the address afresh",
        function () {
    assert.strictEqual(still.decisions, 7,
      "the counters this PEP reported before it re-registered should still be " +
      "on its row; it says decisions=" + still.decisions);
    assert.strictEqual(still.notifyUrl, "",
      "and the notify URL should have gone with the registration that did not " +
      "carry one; the row says " + JSON.stringify(still.notifyUrl));
    assert.ok(String(still.registeredAt || "").length > 0,
      "while the original registration date survives; the row says " +
      JSON.stringify(still.registeredAt));
  });

  await act("enable-pep", { name: PEP_CN }, "enabled the PEP again");
  // AND THE ADDRESS BACK, because section 8 asserts what happens when the
  // repository changes with an unreachable PEP registered.
  await postWithCertificate(realmUrl("/xacml/pep/register"),
                            { notifyUrl: "https://127.0.0.1:9/notify" },
                            identity);

  log.info("[register] OK — the certificate names the PEP on both doors, and " +
           "a disabled one stays disabled.");
  log.debug("Leaving registeringAPep().");
}

// ===========================================================================
// 8. A POLICY SAVE DOES NOT WAIT ON A PEP THAT IS NOT THERE.
//
// The registered PEP's notify URL points at a port nothing is listening on.
// When the repository changes, this service tries to nudge it — and NOTHING
// WAITS ON THAT: the promise is deliberately not awaited, because the console
// form that saved a policy has finished its work whether or not four PEPs
// answered. A save that blocked on somebody else's web server would be the
// mistake `saml/CLAUDE.md` records about not dialling a service provider's
// metadata URL while issuing.
//
// The assertion is a clock, which is unusual here and is the only way to make
// it: the save must return in far less than the nudge's own timeout.
// ===========================================================================
// The PEP's row once the nudge dispatcher has recorded an outcome on it, or the
// row as it stands after the wait — so the assertion reports what was actually
// there rather than a timeout.
async function waitForNotifyRecord() {
  log.debug("Entering waitForNotifyRecord().");
  let row = null;
  for (let i = 0; i < 60; i += 1) {
    const rows = await get(api("/xacml/peps"));
    row = ((rows.body || {}).peps || []).filter(function (one) {
      return one.name === PEP_CN;
    })[0] || null;
    if (row && String(row.lastNotify || "").length > 0) {
      log.debug("Leaving waitForNotifyRecord(). Recorded after " + i +
                " poll(s).");
      return row;
    }
    await new Promise(function (resolve) { setTimeout(resolve, 100); });
  }
  log.debug("Leaving waitForNotifyRecord(). Nothing was recorded.");
  return row;
}

async function aSaveDoesNotWaitOnTheNudge() {
  log.debug("Entering aSaveDoesNotWaitOnTheNudge().");
  log.info("=== A policy save with an unreachable PEP registered ===");

  // The nudge's own timeout, read off the page that owns it rather than
  // written down here: a deployment that raised it would otherwise make this
  // section's budget meaningless without anything saying so.
  const register = await get(api("/xacml/peps"));
  const notifyTimeout = ((register.body || {}).notify || {}).timeoutMs;
  const budget = 4000;
  const started = Date.now();
  await act("disable", { name: POLICY }, "disabled the policy");
  await act("enable", { name: POLICY }, "enabled it again");
  const took = Date.now() - started;

  check("two repository changes return promptly with a dead PEP registered",
        function () {
    assert.ok(took < budget,
      "two policy writes took " + took + "ms with a PEP registered whose " +
      "notify URL is a port nothing answers on. The nudge is dispatched and " +
      "never awaited, so this should be milliseconds — a number near the " +
      "notify timeout means a save is now waiting on somebody else's web " +
      "server. (xacml.pepNotifyTimeoutMs is " + notifyTimeout + ".)");
  });

  // POLLED, AND THE POLL IS THE OTHER HALF OF THE ASSERTION ABOVE. The record
  // of what a PEP answered cannot be there when the save returns — if it were,
  // the save had waited for it. So this waits for the dispatcher to finish
  // failing, which it does as fast as a refused connection to a closed port.
  const row = await waitForNotifyRecord();
  check("the failed nudge is recorded on the PEP's own row", function () {
    assert.ok(row, "the PEP should still be registered");
    assert.ok(String(row.lastNotify || "").length > 0,
      "what each PEP answered — or did not — is recorded on its row and read " +
      "on /admin/xacml/peps, because nothing was waiting to be told. The row " +
      "says lastNotify=" + JSON.stringify(row.lastNotify));
  });

  const pulled = await get(realmUrl("/xacml/pep/policies"));
  check("and the PEP converges by PULLING, nudge or no nudge", function () {
    assert.strictEqual(pulled.status, 200);
    assert.strictEqual((pulled.body.policies || []).length, 1,
      "the policy is enabled again and a pull returns it, which is the whole " +
      "contract: a PEP that is never successfully nudged still converges. " +
      "The pull returned " + (pulled.body.policies || []).length);
  });

  log.info("[nudge] OK — the save did not wait, the failure is on the row, " +
           "and the pull is unaffected.");
  log.debug("Leaving aSaveDoesNotWaitOnTheNudge().");
}

// ===========================================================================
// 9. TURNING IT OFF, IN TWO SENTENCES THAT ARE NOT THE SAME SENTENCE.
//
// `xacml.enabled` off means XACML is off here. `xacml.remotePeps` off means
// XACML is on and remote enforcement points are not. A caller told the first
// when the second is true goes looking in the wrong place — which is why there
// are two checks in `xacml.js` rather than one with a parameter.
//
// Both answer 501 and never 404: the routes stay REGISTERED, because the
// feature being off and the URL being wrong are different sentences to a
// client. And both are set IN THIS REALM, which is also the assertion that the
// default realm goes on answering — a job that turned XACML off process-wide
// would quietly disarm every later job in the run.
// ===========================================================================
async function turningItOff() {
  log.debug("Entering turningItOff().");
  log.info("=== xacml.enabled and xacml.remotePeps, off ===");

  await setSetting("xacml.remotePeps", false);
  const pepOff = [
    ["GET", "/xacml/pep/policies"],
    ["POST", "/xacml/pep/register"],
    ["POST", "/xacml/pep/heartbeat"]
  ];
  for (const [method, path] of pepOff) {
    const r = method === "GET" ? await get(realmUrl(path))
                               : await postJson(realmUrl(path), {});
    check("remotePeps off: " + method + " " + path + " answers 501",
          function () {
      assert.strictEqual(r.status, 501,
        method + " " + path + " answered " + r.status + " with remote PEPs " +
        "off. It must be 501 and not 404: the route is registered and the " +
        "feature is off, which is a different sentence from a wrong URL.");
      assert.ok(String(r.body.error_description).indexOf("xacml.remotePeps") > 0,
        "and the 501 should name the setting AND say that the register is " +
        "untouched; it says: " + r.body.error_description);
    });
  }
  const stillDeciding = await decisionFor("carol", "GET");
  check("remotePeps off leaves the PDP deciding", function () {
    assert.strictEqual(stillDeciding.Decision, "Permit",
      "turning remote enforcement points off must not turn the decision " +
      "endpoint off; it answered " + stillDeciding.Decision);
  });
  await resetSetting("xacml.remotePeps");

  await setSetting("xacml.enabled", false);
  const allOff = [
    ["POST", "/xacml/pdp"], ["GET", "/xacml/policies"],
    ["GET", "/xacml/protected"], ["GET", "/xacml/pep/policies"],
    ["POST", "/xacml/pep/register"], ["POST", "/xacml/pep/heartbeat"]
  ];
  for (const [method, path] of allOff) {
    const r = method === "GET" ? await get(realmUrl(path))
                               : await postJson(realmUrl(path), {});
    check("xacml off: " + method + " " + path + " answers 501", function () {
      assert.strictEqual(r.status, 501,
        method + " " + path + " answered " + r.status + " with XACML off");
      assert.ok(String(r.body.error_description).indexOf("xacml.enabled") > 0,
        "the 501 should name xacml.enabled; it says: " +
        r.body.error_description);
    });
  }

  // THE ONE THAT MAKES THE REALM WORTH USING. Every setting above is
  // process-wide when set at the top level.
  const elsewhere = await get(base + "/xacml/policies");
  check("the default realm goes on answering while this one is off",
        function () {
    assert.strictEqual(elsewhere.status, 200,
      "xacml.enabled was set INSIDE " + REALM + ", so every other realm — and " +
      "every later job in this run — must be untouched. The default realm's " +
      "repository answered " + elsewhere.status);
    assert.ok((elsewhere.body.policies || []).length >= 1,
      "and it should still hold its own seeded policy");
  });

  await resetSetting("xacml.enabled");
  const back = await get(realmUrl("/xacml/policies"));
  check("turning it back on decides against the same policies", function () {
    assert.strictEqual(back.status, 200, "it answered " + back.status);
    assert.strictEqual((back.body.policies || []).length, 1,
      "the repository in ou=policies is untouched by the setting, so the " +
      "policy is still here; the repository holds " +
      (back.body.policies || []).length);
    assert.strictEqual(back.body.root, POLICY);
  });

  log.info("[off] OK — two settings, two sentences, 501 both times, and the " +
           "default realm untouched.");
  log.debug("Leaving turningItOff().");
}

// ===========================================================================
// 10. THE REPOSITORY IS THIS REALM'S OWN.
//
// `ou=policies` is per realm, so the policy this file wrote must be invisible
// from the default realm and the seeded one invisible from here. It is one
// assertion and it is worth having explicitly: the store's readers take the
// realm from an AsyncLocalStorage, and a store declared `new Map()` rather than
// `realms.map()` would pass every other check in this file and pool every
// realm's policies into one repository.
// ===========================================================================
async function theRepositoryIsPerRealm() {
  log.debug("Entering theRepositoryIsPerRealm().");
  log.info("=== ou=policies is this realm's own ===");

  const here = await get(realmUrl("/xacml/policies"));
  const there = await get(base + "/xacml/policies");
  const hereNames = (here.body.policies || []).map(function (one) {
    return one.name;
  });
  const thereNames = (there.body.policies || []).map(function (one) {
    return one.name;
  });

  check("this realm's policy is not in the default realm's repository",
        function () {
    assert.ok(hereNames.indexOf(POLICY) >= 0,
      "the policy should be here; this realm holds " +
      JSON.stringify(hereNames));
    assert.ok(thereNames.indexOf(POLICY) < 0,
      "and it must NOT be in the default realm; that repository holds " +
      JSON.stringify(thereNames));
  });

  check("and the default realm's seeded policy is not in this one", function () {
    assert.ok(thereNames.indexOf("seeded-rbac") >= 0,
      "the default realm should still hold its seeded policy; it holds " +
      JSON.stringify(thereNames));
    assert.ok(hereNames.indexOf("seeded-rbac") < 0,
      "and this realm must not have inherited it; it holds " +
      JSON.stringify(hereNames));
  });

  const registers = await get(base + "/admin-api/xacml/peps");
  check("the PEP register is per realm too", function () {
    const there_ = (registers.body.peps || []).map(function (one) {
      return one.name;
    });
    assert.ok(there_.indexOf(PEP_CN) < 0,
      "the PEP registered in " + REALM + " must not appear in the default " +
      "realm's register, which holds " + JSON.stringify(there_));
  });

  log.info("[realm] OK — two repositories, two registers, nothing shared.");
  log.debug("Leaving theRepositoryIsPerRealm().");
}

// ---------------------------------------------------------------------------
// THE REALM, AND WHY THE TEARDOWN ASSERTS RATHER THAN HOPES.
//
// Removing the realm takes its directory subtree, its ou=policies, its ou=peps
// AND its configuration overrides with it. That last one is why the removal is
// checked: a realm left behind with `xacml.enabled: false` on it is harmless to
// every other job, but a teardown that silently did nothing is how a later run
// of this same file meets a realm it thinks it just created.
// ---------------------------------------------------------------------------
async function createTheRealm() {
  log.debug("Entering createTheRealm().");
  const r = await fetchJson(base + "/admin-api/realms/create", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id: REALM, name: "XACML endpoint test realm",
      description: "Created by tests/vendored/sts_xacml_endpoints.js; " +
                   "removed at the end."
    })
  });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "creating the throwaway realm " + REALM + " answered " + r.status + " " +
    String(r.text).slice(0, 300) + ". Every assertion in this file is made " +
    "inside it, so this is a failure and not something to work around.");
  log.info("Created the throwaway realm " + REALM + ".");
  log.debug("Leaving createTheRealm().");
}

async function removeTheRealm() {
  log.debug("Entering removeTheRealm().");
  const r = await fetchJson(base + "/admin-api/realms/remove", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id: REALM })
  });
  if (r.status !== 200 || !r.body || r.body.ok === false) {
    log.warn("Could not remove the throwaway realm " + REALM + ": " +
             r.status + " " + String(r.text).slice(0, 200));
    return;
  }
  const left = await fetchJson(base + "/admin-api/realms");
  const found = ((left.body && left.body.realms) || []).filter(function (one) {
    return one.id === REALM;
  });
  assert.strictEqual(found.length, 0,
    "the realm " + REALM + " is still in the registry after being removed. " +
    "Its ou=policies, its ou=peps and its configuration overrides go with it, " +
    "so a removal that did not happen leaves state behind for the next run of " +
    "this file to trip over.");
  log.info("Removed the throwaway realm " + REALM + ".");
  log.debug("Leaving removeTheRealm().");
}

// ---------------------------------------------------------------------------
// THE RUN.
// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Driving the mock STS's XACML endpoints at " + base + "/xacml");

  // A SERVICE THAT IS NOT THERE IS A FAILURE AND NOT A SKIP, which is the rule
  // CLAUDE.md records the 2026-08-28 default flip for: a job that reports green
  // having driven nothing is worse than one that is honestly absent.
  const status = await fetchJson(base + "/admin-api/status");
  assert.strictEqual(status.status, 200,
    "GET /admin-api/status answered " + status.status + " at " + base +
    ". This job needs the mock and nothing else.");

  await createTheRealm();
  try {
    await theSurfaceDescribesItself();
    await anEmptyRepositoryDecidesNothing();
    await aPolicyBuiltThroughTheApiDecides();
    await aMalformedRequestIsRefused();
    await anUndischargeableObligationRefuses();
    await aRemotePepPulls();
    await registeringAPep();
    await aSaveDoesNotWaitOnTheNudge();
    await turningItOff();
    await theRepositoryIsPerRealm();
  } finally {
    await removeTheRealm();
  }

  // A FLOOR ON THE COUNT, for the reason sts_admin_console.js gives: a section
  // that stops being called takes its assertions with it and the run still says
  // "passed", which is the one failure mode a suite cannot report about itself.
  assert.ok(checks >= 45,
    "only " + checks + " checks ran. This file makes well over fifty against " +
    "a healthy service, so a count this low means a SECTION STOPPED BEING " +
    "CALLED rather than that the surface got simpler.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_xacml_endpoints")
  .description("Drive the mock STS's seven /xacml endpoints over HTTP in a " +
      "throwaway trust realm: the decision endpoint and its refusals, the " +
      "repository, the embedded PEP's bias and its obligation rule, and the " +
      "three a remote PEP registers, pulls and reports on.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
