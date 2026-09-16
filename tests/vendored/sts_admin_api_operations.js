// File: sts_admin_api_operations.js
//
// ---------------------------------------------------------------------------
// EVERY OPERATION OF THE MOCK STS'S MANAGEMENT API, DRIVEN FOR REAL.
//
// `tests/admin_api.js` next door asserts that the API is SHAPED right: that the
// OpenAPI document is well formed, that every console page and every console
// action has an operation, that every documented RESPONSE property appears in a
// live reply, and that one revocation reaches RFC 7662 introspection. It is a
// parity and schema test, and it deliberately exercises a handful of the
// operations for real.
//
// This file is the other half: **does EVERY ONE of those operations DO what it
// says?** The count is not written down here on purpose — it was ninety when
// this file was written and it is over a hundred and thirty now, and a number
// in a comment is the first thing to go stale. What keeps the claim honest is
// the LEDGER at the end of the run: every operation the document declares must
// have been driven by this file, or hold a row in NOT_DRIVEN_HERE saying who
// drives it and why. Nothing in the mock can answer that about itself. Every
// POST there calls the same function the console's form posts to, so the two
// doors cannot drift from each other — but they can both be wrong together, and
// the arrangement that makes them one implementation is exactly what stops
// either of them noticing.
//
// SIX THINGS IT ASSERTS THAT NOTHING ELSE DOES, and the last two are about
// THIS FILE rather than about the service — they are what stop the four above
// from quietly covering less than they say.
//
//   * **THE DOCUMENTED EXAMPLE IS REPLAYED AGAINST THE SERVICE.** Every POST
//     operation but six carries an `examples` body in its request schema, and
//     that example is the thing a caller copies first. Each one is sent, and a
//     refusal whose reason is about the SHAPE of the request — "Which
//     application? Send `application` with…", "Name the relying party in
//     `rp`" — fails the job, because it means the document names a property the
//     handler does not read. `mgmt-api/CLAUDE.md` names this defect class
//     itself and says it is uncovered: *"a documented request property that
//     changes nothing is the same class of defect as a documented response
//     property that is never sent"*, and it records one that lived for months
//     (`createRealm` documenting an `overrides` field the shared action
//     function dropped). A refusal about the REFERENT — "there is no
//     application called my-web-app" — is legitimate and is allowed, because
//     an example has to name something.
//   * **THE ROUND TRIP.** A write is followed by a READ THROUGH A DIFFERENT
//     OPERATION, never by believing the write's own account of itself. A
//     handler that answers `{ok: true}` and changes nothing passes every check
//     in admin_api.js.
//   * **THE REFUSAL SENTENCES COUNT THEIR OWN LISTS.** Each action handler
//     answers an unknown action by naming the ones it knows — *"Unknown action
//     "x". The six are: …"* — and that sentence is not decoration: it is what
//     admin_api.js reads to check the console/API parity. So a sentence that
//     says "six" over a list of seven, or that omits an action the handler
//     really has, silently narrows the only check that notices a missing
//     operation. Both halves are asserted here: the count matches the list, and
//     the list matches the operations the document declares.
//   * **A CONFIGURATION CHANGE REACHES THE PERSISTENCE STORE.** Setting a value
//     and reading it back proves only that something is holding it in memory.
//     What `/admin/persistence` promises is that it was WRITTEN, so the write
//     counter, the dirty flag and the failure counter are read either side of
//     the change. When the service is running in `memory` mode — the default,
//     and what the containerized stack uses — that is REPORTED rather than
//     skipped silently, because "the store is off" and "the store did not
//     write" look identical from a distance and only one of them is fine.
//   * **EVERY DOCUMENTED OPERATION WAS DRIVEN — checked, not claimed.** The
//     walks here are driven off the document (every GET, and every POST that
//     carries an example), so an operation arriving with NO example and no
//     section of its own would be covered by nothing while this file went on
//     calling itself "every operation". A ledger of what was really called is
//     compared with the document at the end of the run, and an exemption is a
//     row in a table with a sentence in it. `resetAllSettings` was exactly
//     that hole when the ledger was added, and is driven now.
//   * **AND EVERY ACCEPTED WRITE WAS READ BACK.** The round trip above is a
//     rule this file keeps by hand, which means it is a rule the next section
//     can forget: four actions posted and none read would pass every other
//     check here AND be reported as four more operations covered. The same
//     ledger requires a GET of the resource each successful POST wrote, in the
//     scope it wrote it in — the structural half of the round trip, enforced
//     rather than remembered.
//
// ---------------------------------------------------------------------------
// ALMOST EVERYTHING HAPPENS IN A TRUST REALM THIS FILE CREATES AND REMOVES.
//
// A management API test is by definition a test that writes to the thing every
// other job reads. The mock holds its admin state in memory and never restarts
// between jobs, so a claim set left changed here changes what every later
// job's tokens contain — which is why admin_api.js restores everything it
// touches, one value at a time, and why it is EXCLUSIVE in run-report.js.
//
// Trust realms make that mostly unnecessary. A realm is a whole logical copy of
// this service under a path prefix, with its own directory subtree, its own
// applications registry, its own federation register, its own claim sets, its
// own tokens and its own configuration overrides. So this job creates one and
// performs every destructive thing inside it — `forget`, `revoke-all`,
// `reset-all`, `delete` — where none of it reaches anything else. **It does
// NOT remove the realm afterwards** (2026-09-06): a realm a test run created
// stays, because it is the record a person reads when the run went red. See
// theThrowawayRealmIsLeftBehind(). What is left to restore by hand is only
// what is genuinely
// process-wide, and that list is short and is named where it is touched: the
// two admin roles (groups in the DEFAULT realm, by design), the SPIFFE signing
// authority, and one process-wide setting.
//
// It is still EXCLUSIVE in run-report.js, for one reason that a realm cannot
// fix: `/admin-api/spiffe/rotate` replaces the signing authority for the whole
// process, and a SPIFFE job holding a stream open across that would see its
// SVID stop verifying with nothing to say why.
//
// Needs the STS mock and nothing else — no browser, no Keycloak.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Command, Option } = require("commander");
const common = require("./jwt_vc_json_common.js");
const names = require("./random_username.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_admin_api_operations",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

// The throwaway realm. The id has to satisfy realms.js's pattern — lower case,
// digits and hyphens — so the run stamp is lower-cased rather than used raw.
const REALM = ("adminapi-" + names.runStamp()).toLowerCase()
    .replace(/[^a-z0-9-]/g, "").slice(0, 40);

// Where the operations under test are reached. `api` is the throwaway realm's
// door and is what almost everything uses; `rootApi` is the default realm's,
// and is used only for the five realm-registry operations and for the two
// process-wide things this file has to touch.
var api = base + "/realm/" + REALM + "/admin-api";
var rootApi = base + "/admin-api";

// Set by the run so the summary at the end can say what it actually proved
// about the store rather than implying a mode it did not meet.
var persistenceMode = "unknown";

// ---------------------------------------------------------------------------
// A refusal is "about the shape" when it is telling the caller which FIELD to
// send. Those are the sentences the mock writes when the body did not carry the
// identifier the handler reads — which, for a body copied verbatim out of the
// service's own OpenAPI document, can only mean the document and the handler
// disagree about the field's name.
//
// It is deliberately a small set of literal openings rather than a guess at
// intent: a refusal about the REFERENT ("there is no application called x") is
// legitimate, common, and must not be caught here, and the two read alike to
// anything cleverer than a prefix match.
// ---------------------------------------------------------------------------
const SHAPE_REFUSALS = [
  /^Which\b/,          // "Which application? Send `application` with …"
  /^Name the\b/,       // "Name the relationship by its id, in `id`."
  /^A value is required/,
  /^Send\b/
];

function isShapeRefusal(message) {
  log.debug("Entering isShapeRefusal().");
  const text = String(message || "");
  log.debug("Leaving isShapeRefusal().");
  return SHAPE_REFUSALS.some(function (pattern) { return pattern.test(text); });
}

// The number words the mock's refusal sentences use to count their own lists.
// It writes "The six are: …" rather than "The 6 are: …" almost everywhere, and
// `common/claim_attributes.js` writes the digit — so both spellings are read.
const NUMBER_WORDS = {
  one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8,
  nine: 9, ten: 10, eleven: 11, twelve: 12, thirteen: 13, fourteen: 14,
  fifteen: 15
};

function wordToNumber(word) {
  log.debug("Entering wordToNumber().");
  const key = String(word || "").toLowerCase();
  if (Object.prototype.hasOwnProperty.call(NUMBER_WORDS, key)) {
    log.debug("Leaving wordToNumber().");
    return NUMBER_WORDS[key];
  }
  if (/^\d+$/.test(key)) {
    log.debug("Leaving wordToNumber().");
    return Number(key);
  }
  log.debug("Leaving wordToNumber().");
  return null;
}

// A list the mock wrote for a person to read, back into an array. It spells
// them two ways and both are ordinary English: "create, set, add, forget" for
// four or more, and "grant and revoke" for two — so a splitter that knew only
// about commas would read the second as one item called "grant and revoke",
// which is a check that then passes for the wrong reason on every two-action
// resource in the API.
function splitList(text) {
  log.debug("Entering splitList().");
  log.debug("Leaving splitList().");
  return String(text || "")
      .split(/,\s*|\s+and\s+/)
      .map(function (one) { return one.trim(); })
      .filter(Boolean);
}

// ---------------------------------------------------------------------------
// THE LEDGER: WHAT THIS FILE ACTUALLY DROVE, AND THE TWO THINGS IT IS ASKED AT
// THE END OF THE RUN.
//
// Both questions exist because of one weakness, and it is a weakness of the
// WALKS below rather than of the service. They are driven off the document —
// every GET in it, and every POST that carries an example — so an operation
// that arrives with NO example and no section of its own is driven by nothing
// and reported by nothing. Six POST operations already carry no example, which
// is exactly the shape of the hole, and the only guard against a seventh was a
// floor ("more than sixty examples were found") that a seventh would pass.
//
//   * **EVERY DOCUMENTED OPERATION WAS DRIVEN.** Read off the document at the
//     end of the run against the paths this file really called. An exemption is
//     A ROW IN A TABLE WITH A REASON IN IT, so that "not covered here" is a
//     sentence somebody wrote rather than an absence nobody can see — and the
//     rows are themselves checked against the document, because a row left
//     behind after an operation is renamed turns a check off silently.
//   * **EVERY ACCEPTED WRITE WAS READ BACK.** A POST that answered 200 must be
//     followed, before the run ends, by a GET of the resource it wrote: the
//     `/applications/create` by a `/applications`, the `/spiffe/entries/update`
//     by a `/spiffe/entries`. It is the structural half of the round-trip rule
//     this file already keeps by hand — a handler that answers `{ok: true}` and
//     changes nothing passes every other check here, and the assertion that
//     would have caught it is the one somebody forgot to write.
//
// The pairing is by RESOURCE and by SCOPE, and the scope half is not
// decoration: a write made at the root and read back under the realm prefix is
// a read of a different store, which is the exact defect
// theConfigurationDoorsRoundTrip() exists to catch.
//
// What it deliberately does NOT assert is the reverse direction — that every
// path this file drove is in the document. The probes below post to
// `/<resource>/__no_such_action__` on purpose, and console/API parity is
// tests/admin_api.js's question, asked against the console rather than against
// this file's own call list.
// ---------------------------------------------------------------------------
const ledger = [];

// Every call this file makes, in order. The sequence number is what makes
// "read back AFTERWARDS" a checkable claim — a read that happened before the
// write is not evidence about the write — and the query string is dropped
// because `/logout?user=x` and `/logout` are one resource read two ways.
function record(method, path, root, accepted) {
  log.debug("Entering record().");
  ledger.push({ method: method, path: String(path).split("?")[0],
                scope: root ? "root" : "realm", at: ledger.length + 1,
                accepted: accepted });
  log.debug("Leaving record().");
}

// ---------------------------------------------------------------------------
// The two verbs. Neither asserts anything about the status: an operation that
// is EXPECTED to refuse is as much a part of this surface as one that is
// expected to succeed, so the caller decides.
// ---------------------------------------------------------------------------
async function get(path, root) {
  log.debug("Entering get(). path=" + path);
  const r = await common.httpJson((root ? rootApi : api) + path);
  record("GET", path, root, r.status === 200);
  log.debug("Leaving get(). status=" + r.status);
  return r;
}

async function post(path, body, root) {
  log.debug("Entering post(). path=" + path);
  const r = await common.httpJson((root ? rootApi : api) + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  // A refusal is DRIVEN but not ACCEPTED: it changed nothing, so there is
  // nothing for a read to confirm, and requiring one would push this file into
  // reading a resource after every probe it makes.
  record("POST", path, root,
         r.status === 200 && !!r.body && r.body.ok !== false);
  log.debug("Leaving post(). status=" + r.status);
  return r;
}

// A POST that must succeed. The failure message carries the errors the service
// returned rather than the status alone, because every refusal here is a
// sentence written for a person and quoting it is most of the diagnosis.
async function ok(path, body, what, root) {
  log.debug("Entering ok(). path=" + path);
  const r = await post(path, body, root);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + path + " should have " + what + "; it answered " + r.status +
    " " + JSON.stringify((r.body && r.body.errors) || r.body).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

// A POST that must be REFUSED, and refused for a stated reason. `expect` is a
// regular expression against the joined errors: a 400 is not on its own
// evidence that the refusal was the intended one, and a check that accepted any
// 400 would pass against a handler that had started refusing everything.
async function refused(path, body, expect, what, root) {
  log.debug("Entering refused(). path=" + path);
  const r = await post(path, body, root);
  const errors = ((r.body && r.body.errors) || []).join(" | ");
  assert.strictEqual(r.status, 400,
    "POST " + path + " should refuse " + what + " with 400; it answered " +
    r.status + " " + JSON.stringify(r.body).slice(0, 300));
  assert.ok(expect.test(errors),
    "POST " + path + " refused " + what + ", which is right, but the reason " +
    "should match " + expect + " so that a caller can tell WHICH refusal it " +
    "met. It said: " + errors);
  log.debug("Leaving refused().");
  return r.body;
}

// ---------------------------------------------------------------------------
// THE SERVICE, AND WHY A MISSING ONE IS A SKIP AND A STALE ONE IS A FAILURE.
//
// Nothing listening is an ordinary state: half the jobs in this suite run
// against walt.id or a static deployment with no mock at all. A service that
// ANSWERS and has no /admin-api on it is not — it is the parent project's `sts`
// gitlink pinned at a commit older than the feature, and a skip there would
// report a hundred and thirty operations green having driven none of them.
// That is the rule tests/CLAUDE.md states and tests/sts_saml11.js already
// follows.
// ---------------------------------------------------------------------------
async function theServiceIsThere() {
  log.debug("Entering theServiceIsThere().");
  let reply;
  try {
    reply = await common.httpJson(rootApi + "/status");
  } catch (e) {
    log.warn("No STS is listening at " + base + " (" + e.message + "). " +
             "Skipping: this job needs the mock and nothing else.");
    log.debug("Leaving theServiceIsThere(). Nothing listening.");
    return false;
  }
  assert.strictEqual(reply.status, 200,
    "GET " + rootApi + "/status answered " + reply.status + ". A service is " +
    "listening at " + base + " and has no management API on it, which is " +
    "almost always the parent project's `sts` submodule pinned at a commit " +
    "older than /admin-api. This is a FAILURE and not a skip: a skip here " +
    "reports this API's whole surface green having driven none of it.");
  assert.ok(Array.isArray(reply.body.pages) && reply.body.pages.length > 20,
    "the status reply should carry the console's page list; got " +
    JSON.stringify(reply.body.pages));
  log.info("[service] OK — " + base + " answers, with " +
           reply.body.pages.length + " console pages behind it.");
  log.debug("Leaving theServiceIsThere(). It is there.");
  return true;
}

// ---------------------------------------------------------------------------
// THE THROWAWAY REALM, and the three properties of the realm registry that are
// asserted while making it. Those five operations are the only ones in this API
// that are NOT realm-scoped — there is one registry for the process — so they
// are exercised here, at the root, rather than inside the realm they create.
// ---------------------------------------------------------------------------
async function theRealmRegistryWorks() {
  log.debug("Entering theRealmRegistryWorks().");
  log.info("=== The realm registry (create, update, set, unset) ===");
  const before = await get("/realms", true);
  assert.strictEqual(before.status, 200, "GET /admin-api/realms should " +
                                         "answer 200.");
  assert.strictEqual(before.body.current, "default",
    "called at the root, the realm registry should say the call arrived in " +
    "the default realm; it said " + before.body.current + ". `current` is " +
    "the one member of this reply that differs per prefix and it is what a " +
    "caller uses to know which service it is talking to.");
  const existing = (before.body.realms || []).map(
      function (r) { return r.id; });
  assert.ok(existing.indexOf(REALM) < 0,
    "the realm " + REALM + " should not already exist — the id carries this " +
    "run's stamp so that two concurrent runs cannot collide. Found: " +
    existing.join(", "));

  // createRealm's `overrides` is the property mgmt-api/CLAUDE.md records as
  // having been documented, exampled, validated by realms.create() and DROPPED
  // by the shared action function in between, for months. It is asserted on the
  // way in for that reason: a create that answers 200 and produces a realm
  // configured differently from the one asked for is the exact defect.
  const created = await ok("/realms/create", {
    id: REALM,
    name: "Management API operations test",
    description: "Created by tests/sts_admin_api_operations.js; LEFT IN " +
                 "PLACE on purpose, so a failed run can be read afterwards.",
    overrides: { "saml2.entityId": "urn:test:" + REALM + ":idp" }
  }, "created the throwaway realm", true);
  assert.strictEqual(created.realm, REALM,
    "the create should name the realm it made.");

  const row = await realmRow();
  assert.ok(row, "the realm should be in GET /admin-api/realms after being " +
                 "created.");
  assert.strictEqual(row.name, "Management API operations test",
    "the create's `name` should be on the row; it says " + row.name);
  assert.strictEqual(realmSetting(row, "saml2.entityId"),
    "urn:test:" + REALM + ":idp",
    "THE `overrides` FIELD OF createRealm MUST REACH THE REALM. It is " +
    "documented, exampled and validated, and the shared realmsAction() " +
    "dropped it for months while answering 200 — mgmt-api/CLAUDE.md records " +
    "that as the case its parity rule cannot catch, because the console's " +
    "form has no such field for the API to disagree with. The row's " +
    "overrides are " + JSON.stringify(row.overrides));

  // And the setting really is in force under the realm's prefix — the row
  // carrying it is the registry's account of itself, which is the thing the
  // defect above was consistent with.
  const config = await get("/config");
  assert.strictEqual(config.status, 200,
    "GET " + api + "/config should answer 200 inside the new realm.");
  assert.strictEqual(config.body.realm, REALM,
    "the configuration read under /realm/" + REALM + " should say it is that " +
    "realm's; it said " + config.body.realm);
  assert.strictEqual(settingValue(config.body, "saml2.entityId"),
    "urn:test:" + REALM + ":idp",
    "and the override the realm was created with should be the effective " +
    "value of saml2.entityId inside it.");

  await ok("/realms/update", { id: REALM, description: "Updated by the test." },
    "updated the realm", true);
  assert.strictEqual((await realmRow()).description, "Updated by the test.",
    "`update` should change the description on the row.");

  await ok("/realms/set", { id: REALM, key: "saml.issuer",
                            value: "urn:test:" + REALM + ":issuer" },
    "set a realm setting", true);
  assert.strictEqual(realmSetting(await realmRow(), "saml.issuer"),
    "urn:test:" + REALM + ":issuer",
    "`set` should put the value on the realm's own settings.");

  await ok("/realms/unset", { id: REALM, key: "saml.issuer" },
    "unset a realm setting", true);
  // `unset` puts the SEEDED value back rather than removing the row: six
  // settings are seeded onto every realm at create time, because a realm whose
  // issuer was the default realm's would mint assertions the two could not be
  // told apart by. So what must change is the VALUE, not the row's presence.
  assert.notStrictEqual(realmSetting(await realmRow(), "saml.issuer"),
    "urn:test:" + REALM + ":issuer",
    "`unset` should take the value this test set back off the realm; it is " +
    "still there.");

  // The one refusal the registry has that nothing else does, and it is a real
  // one rather than a validation: removing the realm the CALL arrived in would
  // leave the caller talking to a prefix that had stopped existing.
  await refused("/realms/remove", { id: REALM },
    /current|the realm this|arrived|talking/i,
    "removing the realm the call arrived in");

  log.info("[realms] OK — created " + REALM + ", its create-time overrides " +
           "reached it, update/set/unset round-tripped, and `remove` refuses " +
           "the realm it is called in.");
  log.debug("Leaving theRealmRegistryWorks().");
}

// The throwaway realm's row in the registry, read fresh each time.
async function realmRow() {
  log.debug("Entering realmRow().");
  const listed = await get("/realms", true);
  const row = (listed.body.realms || []).filter(function (r) {
    return r.id === REALM;
  })[0];
  log.debug("Leaving realmRow(). " + (row ? "found" : "absent"));
  return row;
}

// One setting off a realm's registry row. The row carries `settings` — a list
// of {key, value} — rather than the `overrides` object the create takes, and
// the two are deliberately different shapes: the create is told what to
// override and the row reports what the realm ACTUALLY carries, which is those
// overrides plus the six seeded onto every realm so that two realms cannot
// mint assertions their audiences could not tell apart.
function realmSetting(row, key) {
  log.debug("Entering realmSetting().");
  const one = ((row && row.settings) || []).filter(function (setting) {
    return setting && setting.key === key;
  })[0];
  log.debug("Leaving realmSetting().");
  return one ? one.value : undefined;
}

// The effective value of one setting, out of the grouped /config reply. The
// document groups the settings, so a caller looking for one has to walk two
// levels — which is worth a function rather than four copies.
function settingValue(config, key) {
  log.debug("Entering settingValue(). key=" + key);
  let found;
  (config.groups || []).forEach(function (group) {
    (group.settings || []).forEach(function (setting) {
      if (setting.key === key) {
        found = setting;
      }
    });
  });
  log.debug("Leaving settingValue().");
  return found ? found.value : undefined;
}

function settingRow(config, key) {
  log.debug("Entering settingRow().");
  let found;
  (config.groups || []).forEach(function (group) {
    (group.settings || []).forEach(function (setting) {
      if (setting.key === key) {
        found = setting;
      }
    });
  });
  log.debug("Leaving settingRow().");
  return found;
}

// ---------------------------------------------------------------------------
// THE REFUSAL SENTENCES, BOTH WAYS ROUND.
//
// Every action handler answers an unknown action by naming the ones it knows.
// That sentence is not documentation — tests/admin_api.js READS it to check
// that every console action has an API operation — so it is load-bearing, and a
// sentence that is short by one action narrows the only check that would have
// noticed the missing operation.
//
// Two assertions, and they fail on different things:
//
//   * THE COUNT MATCHES THE LIST. "The six are:" over a list of seven is a
//     sentence that was edited at one end. It is the cheapest possible signal
//     that an action was added and the prose beside it was not, and it costs
//     nothing to check.
//   * THE LIST MATCHES THE DOCUMENT. The operations under a resource are
//     generated from the table that registers them, so the document is the
//     handler's real repertoire; the sentence is a second copy of it, written
//     by hand. Every documented action must be in the sentence, and every
//     action in the sentence must be documented.
//
// The probe bodies matter, and admin_api.js already learnt why: the three claim
// set doors validate their `set` BEFORE they look at the action, so a probe
// with an empty body comes back naming the claim SETS in a sentence of exactly
// this shape. Each probe therefore carries whatever that door needs to reach
// its own switch, and the value is read off the service — the sets each door
// carries are in its own GET — rather than typed here.
// ---------------------------------------------------------------------------
async function theRefusalSentencesAreHonest(doc) {
  log.debug("Entering theRefusalSentencesAreHonest().");
  log.info("=== The refusal sentences (count, and against the document) ===");

  // resource -> the extra fields a probe needs to get past the validation that
  // happens before the action switch. Read off the service where it can be.
  const claimSets = await claimSetIdsPerDoor();
  const probes = {
    "claims": { set: claimSets["claims"] },
    "saml-attributes": { set: claimSets["saml-attributes"] },
    "userinfo-claims": { set: claimSets["userinfo-claims"] },
    "federation": { id: "no-such-relationship" },
    "saml2": { sp: "urn:no:such:sp" },
    "saml11": { rp: "urn:no:such:rp" },
    "logout": { user: "nobody-at-all" }
  };

  const documented = documentedActions(doc);
  const resources = Object.keys(documented).sort();
  assert.ok(resources.length > 15,
    "the document should declare POST operations under more than fifteen " +
    "resources; it declares " + resources.length + ". A collapse here means " +
    "the walk below is asserting almost nothing.");

  for (const resource of resources) {
    const body = Object.assign({ }, probes[resource] || {});
    const reply = await post("/" + resource + "/__no_such_action__", body);
    const errors = ((reply.body && reply.body.errors) || []).join(" ");
    assert.strictEqual(reply.status, 400,
      "POST /" + resource + "/__no_such_action__ should be refused 400; it " +
      "answered " + reply.status + " " +
      JSON.stringify(reply.body).slice(0, 200));
    // THREE PHRASINGS, one sentence. The mock writes "The six are: …" on most
    // resources, "There are two: …" where two reads better, and "The actions
    // here are: …" on the three SPIFFE ones — all ordinary English, and all
    // read here, because the requirement is that the sentence NAMES the
    // actions and not that every handler spells the naming the same way.
    // What is asserted is the naming and the count, in that order.
    const sentence = errors.match(
      /Unknown action "[^"]*"\.\s*([^:]*):\s*([^.]+)\./);
    assert.ok(sentence,
      "the refusal from /" + resource + " must NAME the actions it knows. " +
      "tests/admin_api.js reads exactly that sentence to check that every " +
      "console action has an operation here, so a handler that stopped " +
      "writing it would turn that check off with nothing failing. It said: " +
      errors);

    const listed = splitList(sentence[2]);
    // The count, when the sentence carries one: "The six are", "There are
    // two". "The actions here are" carries none, and a resource is entitled to
    // write it that way — so the count check is made where there is a count
    // and the list check is made everywhere.
    const counted = String(sentence[1] || "")
        .match(/\bThe\s+(\S+)\s+are\b|\bThere\s+(?:are|is)\s+(\S+)/);
    const claimed = counted ? wordToNumber(counted[1] || counted[2]) : null;
    if (claimed !== null) {
      assert.strictEqual(listed.length, claimed,
        "/" + resource + " says it has " + claimed + " actions and then " +
        "lists " + listed.length + " of them (" + listed.join(", ") + "). A " +
        "sentence edited at one end is the cheapest available signal that an " +
        "action was added and the prose beside it was not — and this " +
        "sentence is what the parity check reads.");
    }

    const declared = documented[resource].slice().sort();
    const said = listed.slice().sort();
    assert.deepStrictEqual(said, declared,
      "the actions /" + resource + " NAMES in its refusal must be exactly " +
      "the ones the OpenAPI document declares for it. The document is " +
      "generated from the table that registers the routes, so it is the real " +
      "repertoire; the sentence is a hand-written second copy, and this is " +
      "where the two are compared.\n" +
      "  the sentence says: " + said.join(", ") + "\n" +
      "  the document says: " + declared.join(", ") + "\n" +
      "An action in the document and not in the sentence is INVISIBLE to " +
      "tests/admin_api.js's parity check, which reads the sentence: the " +
      "console could lose the operation entirely and nothing would fail.");
    log.debug("[refusals] /" + resource + ": " + listed.length + " action(s).");
  }
  log.info("[refusals] OK — all " + resources.length + " action resources " +
           "name their actions, count them correctly, and agree with the " +
           "document.");
  log.debug("Leaving theRefusalSentencesAreHonest().");
}

// The claim set ids each of the three claim-set doors carries, read off the
// service. They are the same seven actions over different sets, and a probe
// naming a set the door does not carry never reaches the action switch.
async function claimSetIdsPerDoor() {
  log.debug("Entering claimSetIdsPerDoor().");
  const out = {};
  for (const resource of ["claims", "saml-attributes", "userinfo-claims"]) {
    const probe = await post("/" + resource + "/__no_such_action__",
                             { set: "" });
    const errors = ((probe.body && probe.body.errors) || []).join(" ");
    const carried =
        errors.match(/(?:carries|carry|are)\s*(?:are)?:\s*([^.]+)\./);
    const first = carried ? carried[1].split(",")[0].trim() : "";
    assert.ok(first,
      "/" + resource + " asked with no `set` should name the sets it " +
      "carries, so that this file does not have to hold a second copy of " +
      "them. It said: " + errors);
    out[resource] = first;
    log.debug("[claim sets] /" + resource + " carries " + carried[1].trim());
  }
  log.debug("Leaving claimSetIdsPerDoor().");
  return out;
}

// resource -> [action, …], read out of the OpenAPI document. A path here is
// always /admin-api/<resource…>/<action>, and the resource may have two
// segments (spiffe/entries, spiffe/agents), so the action is the last one and
// the resource is everything before it.
function documentedActions(doc) {
  log.debug("Entering documentedActions().");
  const out = {};
  Object.keys(doc.paths).forEach(function (path) {
    if (!doc.paths[path].post) {
      return;
    }
    const parts = path.replace(/^\/admin-api\//, "").split("/");
    const action = parts.pop();
    const resource = parts.join("/");
    if (!resource) {
      return;
    }
    out[resource] = out[resource] || [];
    out[resource].push(action);
  });
  log.debug("Leaving documentedActions(). " + Object.keys(out).length + " " +
      "resource(s).");
  return out;
}

// ---------------------------------------------------------------------------
// THE DOCUMENTED EXAMPLE, REPLAYED.
//
// All but six of the POST operations carry an example body in their request
// schema, and that example is the first thing a caller copies. Sending
// it is therefore the cheapest possible test of the one thing this API's
// generated document CANNOT check about itself: the document is generated from
// the table that registers the routes, so an operation cannot be undocumented —
// but the request BODY in that table is prose typed beside the row, and nothing
// compares it with the fields the handler actually reads.
//
// mgmt-api/CLAUDE.md names this defect class and records one that survived for
// months: `createRealm` documented an `overrides` property, gave it an example,
// and the shared action function built its argument out of three other fields
// and dropped it — 200 every time, and a realm configured differently from the
// one that was asked for. Its own diagnosis is the reason this check is here:
// *"a documented request property that changes nothing is the same class of
// defect as a documented response property that is never sent"*, and *"what it
// cannot catch is a field the API accepts and the console's form does not
// have, because there is then no second implementation to disagree with."*
//
// WHAT COUNTS AS A FAILURE, AND WHY THE LINE IS WHERE IT IS. An example has to
// name something — an application, a relationship, an agent — and naming
// something that does not exist here is not a defect in the example. So a
// refusal about the REFERENT is allowed and counted. A refusal about the SHAPE
// is not: "Which application? Send `application` with…" in reply to a body the
// service itself published means the document named a field the handler does
// not read, and a caller following the document gets 400 for ever.
//
// THREE RESOURCES ARE HELD BACK, each because its example escapes the
// throwaway realm this job cleans up by removing:
//
//   * `realms/*`   — the registry is process-wide; the five operations are
//                    exercised in theRealmRegistryWorks() against a realm this
//                    file owns, rather than against the example's `acme`.
//   * `rbac/*`     — the two console roles are groups in the DEFAULT realm by
//                    design, read there from every realm, so a grant made here
//                    would close the console's roster for every other job.
//                    Exercised explicitly, and revoked, below.
//   * `spiffe/rotate` — it replaces the signing authority for the whole
//                    process and has no opposite. Exercised once, deliberately,
//                    in the SPIFFE section.
//   * `tls/trust/*` (2026-09-12) — the client-certificate truststore is ONE
//                    array for the process, whatever realm prefix a call
//                    carries, and every job after this one has its TLS
//                    handshakes judged against it. The documented examples
//                    are placeholders a replay would only see refused, and a
//                    rule that depended on that staying true would be one edit
//                    to a description away from leaving an anchor behind.
//                    Exercised in theTruststoreRoundTrips(), with a CA this
//                    file mints and removes.
// ---------------------------------------------------------------------------
//   * `kerberos/principals/*` (2026-09-12) — the documented example names a
//                    fixed SPN a replay would leave holding a random key for
//                    every later run to meet as "already holds a stored key".
//                    **The FIRST half of this reason expired on 2026-09-15**:
//                    it read *the KDC is ONE for the process, so a service
//                    principal created under any realm prefix is the DEFAULT
//                    realm's*, and each trust realm has a KDC of its own now —
//                    so a replay under a realm prefix would strand the SPN in
//                    that realm instead of the default one, which is the same
//                    problem in a different place. The second half is why it
//                    stays held back.
//                    Exercised in theKerberosPrincipalsRoundTrip(), with an SPN
//                    carrying this run's realm id, created and deleted.
//   * `pki/build-root` (2026-09-13) — it replaces the service Root AND the
//                    leaf the main port is serving, so every TLS handshake
//                    this process opens after it is judged against an anchor
//                    NODE_EXTRA_CA_CERTS no longer holds. This file used to
//                    replay it in the middle and PASSED ONLY BECAUSE undici
//                    went on reusing a connection opened before the swap: the
//                    day the rebuild took long enough for that connection to be
//                    replaced (three more Issuing CAs per realm, for ACME, EST
//                    and SCEP), the very next read failed with `unable to get
//                    local issuer certificate`. Driven LAST now, in
//                    theRootIsReplacedLast(), whose read-back trusts the new
//                    anchor explicitly.
const REPLAY_HELD_BACK = [/^\/realms\//, /^\/rbac\//, /^\/spiffe\/rotate$/,
                          /^\/tls\/trust\//, /^\/kerberos\/principals\//,
                          /^\/pki\/build-root$/];

async function everyDocumentedExampleIsAccepted(doc) {
  log.debug("Entering everyDocumentedExampleIsAccepted().");
  log.info("=== Every documented example body, replayed ===");
  const rows = [];
  Object.keys(doc.paths).forEach(function (path) {
    const operation = doc.paths[path].post;
    if (!operation) {
      return;
    }
    const relative = path.replace(/^\/admin-api/, "");
    if (REPLAY_HELD_BACK.some(function (p) { return p.test(relative); })) {
      return;
    }
    const schema = operation.requestBody &&
        operation.requestBody.content &&
        operation.requestBody.content["application/json"] &&
        operation.requestBody.content["application/json"].schema;
    const example = schema && Array.isArray(schema.examples) &&
                    schema.examples[0];
    if (!example) {
      return;
    }
    rows.push({ path: relative, example: example,
                operationId: operation.operationId });
  });

  assert.ok(rows.length > 60,
    "the document should carry an example body for most of its POST " +
    "operations; only " + rows.length + " were found. Either the examples " +
    "have gone or this walk is reading the schema in the wrong place, and " +
    "both make the check below vacuous.");

  const shapeFailures = [];
  let accepted = 0;
  let referent = 0;
  for (const row of rows) {
    const reply = await post(row.path, row.example);
    const errors = (reply.body && reply.body.errors) || [];
    if (reply.status === 200 && reply.body && reply.body.ok !== false) {
      accepted++;
      await theResourceReadsBack(row.path, row.operationId);
      continue;
    }
    const shaped = errors.filter(isShapeRefusal);
    if (shaped.length) {
      shapeFailures.push(row.operationId + " (POST " + row.path + "): " +
                         shaped.join(" | ") + "  — example was " +
                         JSON.stringify(row.example));
      continue;
    }
    assert.ok(reply.status === 400 && errors.length,
      "POST " + row.path + ", sent the document's own example, answered " +
      reply.status + " with no `errors` array: " +
      JSON.stringify(reply.body).slice(0, 300) + ". Every refusal on this " +
      "API carries `errors`, because a status alone is not something a " +
      "caller can act on.");
    referent++;
    log.debug("[example] " + row.operationId + " refused about its referent: " +
              errors.join(" | ").slice(0, 160));
  }

  assert.deepStrictEqual(shapeFailures, [],
    "THESE OPERATIONS REFUSED THEIR OWN DOCUMENTED EXAMPLE, AND REFUSED IT " +
    "FOR A REASON ABOUT THE SHAPE OF THE REQUEST — which means the OpenAPI " +
    "document names a property the handler does not read, and every caller " +
    "that copies the example gets 400 for ever:\n  " +
    shapeFailures.join("\n  "));

  log.info("[examples] OK — " + rows.length +
           " documented examples replayed: " +
           accepted + " accepted outright and read back through their own " +
           "resource, " + referent + " refused about a referent they name " +
           "and this service does not hold, none refused about the shape of " +
           "the body.");
  log.debug("Leaving everyDocumentedExampleIsAccepted().");
}

// ---------------------------------------------------------------------------
// THE READ BESIDE THE WRITE, for the sweep above.
//
// What it can assert is narrower than what the round-trip sections assert — a
// walk driven off the document has no idea what any particular example MEANT —
// but it is not nothing, and it is the half that generalises to an operation
// nobody has written a section for: the resource a write landed on must still
// answer, and must still answer JSON. This is the only place in the run where
// every resource is read IMMEDIATELY after being written to, so a handler that
// stores something its own listing then throws on is caught here rather than
// by the next person to load the page.
//
// Its other job is to keep this sweep inside the rule the whole file follows —
// a write is never believed on its own account. everyAcceptedWriteWasReadBack()
// is the enforcement of that rule, and this call is how the sixty-odd writes
// made here satisfy it.
// ---------------------------------------------------------------------------
async function theResourceReadsBack(path, operationId) {
  log.debug("Entering theResourceReadsBack(). path=" + path);
  const resource = path.split("/").slice(0, -1).join("/");
  const reply = await get(resource);
  assert.strictEqual(reply.status, 200,
    operationId + " accepted the document's own example, and GET " + api +
    resource + " — the read operation on the resource it just wrote — then " +
    "answered " + reply.status + " " + String(reply.raw).slice(0, 200) +
    ". A write that leaves its own resource unreadable is a 500 nobody meets " +
    "until the next page load.");
  assert.strictEqual(typeof reply.body, "object",
    operationId + " wrote " + resource + " and that resource then stopped " +
    "answering JSON: httpJson gave back " + typeof reply.body + " — " +
    String(reply.raw).slice(0, 200));
  log.debug("Leaving theResourceReadsBack().");
}

// ---------------------------------------------------------------------------
// THE ROOT IS REPLACED LAST (2026-09-13). See the `pki/build-root` note above
// REPLAY_HELD_BACK. The documented example is posted with the trust this run
// started with — the handshake happens before anything is replaced — and the
// read-back that the ledger requires is made over a connection that trusts
// the certificate the service serves AFTERWARDS, fetched the way
// `tools/trust.js` fetches it for every job. Nothing runs after this section
// but the two ledger checks, which make no request.
// ---------------------------------------------------------------------------
function getTrusting(path, anchorPem) {
  log.debug("Entering getTrusting(). path=" + path);
  const target = new URL(api + path);
  return new Promise(function (resolve, reject) {
    const req = require("https").get({
      host: target.hostname, port: target.port || 443,
      path: target.pathname + target.search, ca: anchorPem,
      agent: false,
      headers: process.env.STS_ADMIN_API_TOKEN
        ? { Authorization: "Bearer " + process.env.STS_ADMIN_API_TOKEN } : {}
    }, function (res) {
      let raw = "";
      res.setEncoding("utf8");
      res.on("data", function (chunk) {
        raw += chunk;
      });
      res.on("end", function () {
        let body = raw;
        try {
          body = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in getTrusting(): " + ((e && e.message) || e));
          // A non-JSON answer is reported by the caller's assertion.
        }
        record("GET", path, false, res.statusCode === 200);
        log.debug("Leaving getTrusting(). status=" + res.statusCode);
        resolve({ status: res.statusCode, body: body, raw: raw });
      });
    });
    req.on("error", reject);
  });
}

async function theRootIsReplacedLast(doc) {
  log.debug("Entering theRootIsReplacedLast().");
  log.info("=== The service Root, replaced last ===");
  const operation = doc.paths["/admin-api/pki/build-root"] &&
                    doc.paths["/admin-api/pki/build-root"].post;
  const schema = operation && operation.requestBody &&
    operation.requestBody.content["application/json"].schema;
  const example = (schema && schema.examples && schema.examples[0]) || {};
  const replaced = await post("/pki/build-root", example);
  assert.ok(replaced.status === 200 && replaced.body &&
            replaced.body.ok !== false,
    "POST /pki/build-root with the document's own example should replace " +
    "the Root; it answered " + replaced.status + " " +
    JSON.stringify(replaced.body).slice(0, 300));
  const trust = require(require("path").join(__dirname, "..", "tools",
                                             "trust.js"));
  const anchor = await trust.fetchCertificate(base);
  const reply = await getTrusting("/pki", anchor);
  assert.strictEqual(reply.status, 200,
    "GET /pki after the Root was replaced answered " + reply.status + " " +
    String(reply.raw).slice(0, 200));
  assert.strictEqual(typeof reply.body, "object",
    "GET /pki after the Root was replaced stopped answering JSON");
  log.info("[root] OK — the Root was replaced with the document's example " +
           "and the resource read back over a connection trusting the " +
           "anchor the service serves afterwards.");
  log.debug("Leaving theRootIsReplacedLast().");
}

// ---------------------------------------------------------------------------
// EVERY GET ANSWERS, AND ANSWERS ABOUT THIS REALM.
//
// Fifty-odd read operations, walked from the document. Two things are asserted
// beyond the status, and the second is the one that matters: the reply must be
// an OBJECT rather than the HTML of a redirect or an error page — `httpJson`
// hands back the raw text when it cannot parse, and a string body is how a
// route that quietly stopped being JSON would look — and every resource that
// names a container DN must name THIS REALM'S, because the whole claim of the
// path prefix is that every one of these operations already works per realm
// without any of them having been edited.
// ---------------------------------------------------------------------------
async function everyReadAnswersAboutThisRealm(doc) {
  log.debug("Entering everyReadAnswersAboutThisRealm().");
  log.info("=== Every read operation, under the realm prefix ===");
  const paths = Object.keys(doc.paths).filter(function (path) {
    return !!doc.paths[path].get;
  }).map(function (path) {
    return path.replace(/^\/admin-api/, "");
  });
  assert.ok(paths.length > 30,
    "the document should declare more than thirty read operations; it " +
    "declares " + paths.length);

  let withContainer = 0;
  for (const path of paths) {
    // THIS EXEMPTION IS GONE AND THE COMMENT IS KEPT AS THE RECORD. It read:
    // "The two documentation routes answer HTML and JavaScript rather than
    // JSON, on purpose — they are the explorer", and skipped `/docs` and
    // `/docs/explorer.js`. Those operations moved to the console on
    // 2026-09-09 — `/admin/api-explorer` — because this API began requiring
    // an access token a browser has no way to carry. Every remaining
    // operation here answers JSON, which is what this walk was always really
    // asserting, so it now has no exception at all. `tests/admin_api.js`
    // still owns the CSP half, at the page's new address.
    const reply = await get(path);
    assert.strictEqual(reply.status, 200,
      "GET " + api + path + " should answer 200; it answered " + reply.status +
      " " + String(reply.raw).slice(0, 200));
    assert.strictEqual(typeof reply.body, "object",
      "GET " + api + path + " should answer a JSON object. It answered " +
      typeof reply.body + ": " + String(reply.raw).slice(0, 200) + ". A " +
      "string body here is httpJson reporting that it could not parse the " +
      "reply, which is what a route that started returning HTML looks like.");
    const container = String(reply.body.container || reply.body.groupsDn || "");
    // ou=groups and ou=users on /rbac are DELIBERATELY the default realm's —
    // the two console roles are one roster for the process — so that resource
    // is the one exception and it is asserted the other way round below.
    if (container && path !== "/rbac" && /dc=/.test(container)) {
      assert.ok(container.indexOf("dc=" + REALM + ",") >= 0,
        "GET " + path + " names the container " + container + ", which is " +
        "not this realm's. Every store behind this API is per realm — that " +
        "is what makes /realm/<id>/admin-api a copy of the service rather " +
        "than a second view of one — so a container naming dc=example,dc=com " +
        "from inside " + REALM + " is a store that was left process-wide.");
      withContainer++;
    }
  }
  log.info("[reads] OK — " + (paths.length - 2) + " read operations answered " +
           "200 with a JSON object, and the " + withContainer + " that name " +
           "a directory container all named " + REALM + "'s.");
  log.debug("Leaving everyReadAnswersAboutThisRealm().");
}

// ---------------------------------------------------------------------------
// THE APPLICATIONS REGISTRY: all seven actions, each read back through the
// resource's own GET rather than believed off the write's reply.
//
// The two closed vocabularies this resource validates against are published by
// GET /applications/new for exactly this reason — a caller that reads them
// cannot construct a create the service will refuse — so they are read off the
// service and used, rather than typed here. That also makes the count check
// below possible, which is the one that has something to catch: the refusal
// names the kinds it knows AND says how many there are, in prose, and the two
// are edited independently.
// ---------------------------------------------------------------------------
async function theApplicationsRegistryRoundTrips() {
  log.debug("Entering theApplicationsRegistryRoundTrips().");
  log.info("=== Applications: create, set, add, remove, revoke-registration, " +
           "refresh-metadata, forget ===");
  const form = await get("/applications/new");
  assert.strictEqual(form.status, 200, "GET /applications/new should answer " +
                                       "200.");
  const kinds = (form.body.kinds || []).map(function (k) {
    return typeof k === "string" ? k : k.kind;
  });
  const families = (form.body.protocols || []).map(function (p) {
    return typeof p === "string" ? p : p.id;
  });
  assert.ok(kinds.length && families.length,
    "GET /applications/new should publish the kinds and the protocol " +
    "families a create is validated against; it published " +
    kinds.length + " and " + families.length + ".");
  assert.strictEqual(form.body.container,
    "ou=applications,dc=" + REALM + ",dc=example,dc=com",
    "and it should name THIS realm's container, since that is where a create " +
    "made through this prefix lands; it named " + form.body.container);

  // The kinds refusal counts its own list, and the two halves of that sentence
  // are edited independently — a ninth kind added to the table with the word
  // "eight" left beside it is a sentence that is wrong about the thing it
  // exists to explain.
  const badKind = await refused("/applications/create",
    { identifier: "kind-probe-" + REALM, kind: "no-such-kind" },
    /is not one of the kinds/, "an unknown kind");
  const kindSentence = (badKind.errors || []).join(" ")
      .match(/The\s+(\S+)\s+are:\s*([^.]+)\./);
  assert.ok(kindSentence,
    "the unknown-kind refusal should name the kinds it knows; it said " +
    (badKind.errors || []).join(" "));
  const kindsNamed = splitList(kindSentence[2]);
  assert.deepStrictEqual(kindsNamed.slice().sort(), kinds.slice().sort(),
    "the kinds the refusal names must be the kinds GET /applications/new " +
    "publishes — they are one table read through two doors.");
  assert.strictEqual(kindsNamed.length, wordToNumber(kindSentence[1]),
    "the unknown-kind refusal says there are " + kindSentence[1] + " kinds " +
    "and then lists " + kindsNamed.length + " of them: " +
    kindsNamed.join(", ") + ". The count is written into the sentence by " +
    "hand and the list is generated from the table, so they part company the " +
    "day a kind is added — which is the day the sentence is most likely to " +
    "be read.");

  const identifier = "app-" + names.usernameFor("stsapi-app");
  const created = await ok("/applications/create", {
    identifier: identifier,
    name: "Management API operations test",
    kind: kinds[0],
    protocols: [families[0]]
  }, "created an application");
  assert.ok(created.application && created.application.dn,
    "the create should answer with the entry it made, DN and all.");
  assert.ok(created.application.dn.indexOf("dc=" + REALM + ",") > 0,
    "and that entry should be in this realm's subtree; its DN is " +
    created.application.dn);

  assert.strictEqual((await application(identifier)).found, true,
    "and the entry should be findable through the registry's own read " +
    "operation immediately, rather than only in the create's account of " +
    "itself: every other assertion in this section reads through " +
    "GET /applications?application=…, so this is where that read is first " +
    "shown to see what the write made.");

  // An identifier names ONE application whatever protocol brought it, so a
  // second create is refused rather than merged. That refusal is what
  // tests/sts_applications.js reconciles against, so it is load-bearing
  // elsewhere in this suite.
  await refused("/applications/create", { identifier: identifier },
    /already/i, "a duplicate identifier");

  // set / add / remove, each confirmed by reading the ENTRY back. The
  // attributes are read off the service's own `editable` table: which
  // attributes take `set` and which take `add` is a fact about the mock's
  // EDITABLE table, and a copy of it here is the second definition that
  // mgmt-api/CLAUDE.md records going stale.
  const editable = form.body.editable || [];
  const single = editable.filter(function (row) {
    return row.mode === "set" && !row.sensitive;
  })[0];
  // The multi-valued one is taken from `declarations` rather than from
  // `editable`, and specifically from a row whose ROLE is `redirect`: several
  // multi-valued attributes hold a CLOSED VOCABULARY — appAllowedProtocol is
  // the list of declared families and refuses anything outside it — so a walk
  // that took the first multi-valued name it found would be asserting that
  // `add` refuses, which is a different (and already covered) claim. A
  // redirect attribute takes a URI and nothing here judges it.
  const declared = (form.body.declarations || []).filter(function (row) {
    return row.role === "redirect" && row.kind === "multi" && !row.sensitive;
  })[0];
  assert.ok(single && declared,
    "GET /applications/new should publish at least one single-valued " +
    "editable attribute and one multi-valued attribute that takes a free " +
    "value, since `set` and `add` are the two modes this table exists to " +
    "tell apart. It published " + editable.length + " editable rows and " +
    (form.body.declarations || []).length + " declarations.");
  const multi = { name: declared.attribute };

  await ok("/applications/set",
    { application: identifier, attribute: single.name,
      value: "set-by-the-test" },
    "set " + single.name);
  assert.ok(fieldValues(await application(identifier), single.name)
      .indexOf("set-by-the-test") >= 0,
    "`set` on " + single.name + " should be readable back through GET " +
    "/applications?application=…; the entry says " +
    JSON.stringify(fieldValues(await application(identifier), single.name)));

  await ok("/applications/add",
    { application: identifier, attribute: multi.name,
      value: "https://one.example/cb" },
    "added a first value to " + multi.name);
  await ok("/applications/add",
    { application: identifier, attribute: multi.name,
      value: "https://two.example/cb" },
    "added a second value to " + multi.name);
  let values = fieldValues(await application(identifier), multi.name);
  assert.ok(values.indexOf("https://one.example/cb") >= 0 &&
            values.indexOf("https://two.example/cb") >= 0,
    "`add` must ACCUMULATE on a multi-valued attribute rather than assign — " +
    "that is the whole difference between the two modes, and an `add` that " +
    "assigned would pass every single-value check in this file. " +
    multi.name + " holds " + JSON.stringify(values));

  await ok("/applications/remove",
    { application: identifier, attribute: multi.name,
      value: "https://one.example/cb" },
    "removed one value from " + multi.name);
  values = fieldValues(await application(identifier), multi.name);
  assert.ok(values.indexOf("https://one.example/cb") < 0 &&
            values.indexOf("https://two.example/cb") >= 0,
    "`remove` must take away the ONE value it was given and leave the rest; " +
    multi.name + " now holds " + JSON.stringify(values));

  // A derived attribute is refused BY NAME rather than written. That is the
  // property the `editable` table exists to give the console's two selects —
  // a form cannot offer what the action would refuse — and this is the door
  // that has no form in front of it.
  await refused("/applications/set",
    { application: identifier, attribute: "entryDN", value: "cn=nope" },
    /entryDN/, "a derived attribute");

  // ---------------------------------------------------------------------------
  // AN ATTRIBUTE SCOPED TO A PROTOCOL FAMILY, IN BOTH DIRECTIONS.
  //
  // A SCHEMA row may carry `families`, and the attribute may then be written
  // only onto an entry declared for one of them —
  // `oauthTokenExchangeRefreshToken` is the only one today, and it is refused
  // elsewhere because it decides what the TOKEN ENDPOINT does for a client_id,
  // so on an entry no token request could ever name it would read as a policy
  // in force. Everything else in this registry is inert rather than wrong on
  // the wrong entry, which is why this needs a test of its own.
  //
  // THE ATTRIBUTE AND THE FAMILIES ARE READ OFF THE SERVICE, from the
  // `families` member GET /applications/new publishes on its `editable` rows —
  // the same rule the kinds and the protocol vocabularies above follow, and for
  // the same reason: a name typed here is a second definition of the schema and
  // it goes stale in the file that is supposed to catch the schema changing.
  // The whole block is skipped, saying so, if nothing is family-scoped — which
  // is the honest answer when the last such row is removed.
  //
  // **THE ROW IS THE FIRST ONE THAT ACCEPTS THE PROBE VALUE, NOT THE FIRST ROW
  // (2026-09-13).** This took `[0]` until RFC 9701 put three
  // family-scoped attributes whose VALUES are checked ahead of
  // `oauthTokenExchangeRefreshToken` in the table, and `always` is not a JWS
  // algorithm — so the round trip below failed on the value, and the two
  // refusals before it passed on the VALUE's refusal rather than the family's,
  // because both sentences name the attribute. The probe is made on an entry
  // declared for every family any scoped row names, so the only thing that
  // can refuse it is the value; the first row that takes `always` is the one
  // this block drives, and no attribute name is typed here.
  const PROBE_VALUE = "always";
  const scopedRows = editable.filter(function (row) {
    return row.families && row.families.length && row.mode === "set" &&
      !row.sensitive;
  });
  let scoped = null;
  if (scopedRows.length) {
    const probeId = identifier + "-scope-probe";
    const probeFamilies = scopedRows.reduce(function (all, row) {
      row.families.forEach(function (id) {
        if (all.indexOf(id) < 0 && families.indexOf(id) >= 0) {
          all.push(id);
        }
      });
      return all;
    }, []);
    await ok("/applications/create",
             { identifier: probeId, protocols: probeFamilies },
             "created an entry declared for " + probeFamilies.join(", ") +
             " to find a family-scoped attribute that takes `" +
             PROBE_VALUE + "`");
    for (const row of scopedRows) {
      const r = await post("/applications/set",
        { application: probeId, attribute: row.name, value: PROBE_VALUE });
      if (r.status === 200 && r.body && r.body.ok !== false) {
        scoped = row;
        break;
      }
    }
    await ok("/applications/forget", { application: probeId },
             "forgot the scope probe");
    assert.ok(scoped,
      "none of the " + scopedRows.length + " family-scoped attributes (" +
      scopedRows.map(function (row) { return row.name; }).join(", ") +
      ") accepted `" + PROBE_VALUE + "` on an entry declared for their " +
      "families, so the family-scope checks below have no attribute to " +
      "drive. Either a value rule changed or PROBE_VALUE needs a companion.");
  }
  if (!scoped) {
    log.info("[applications] no attribute in the published `editable` table " +
             "is scoped to a protocol family, so the family-scope checks " +
             "have nothing to drive. That is a fact about the schema rather " +
             "than a skip: the rule is still enforced by " +
             "common/applications.js.");
  } else {
    const wrong = families.filter(function (id) {
      return scoped.families.indexOf(id) < 0;
    })[0];
    const right = scoped.families[0];
    // familyRefusal()'s own opening in common/applications.js. The attribute
    // NAME alone is not enough: a refusal of the VALUE names it too, and that
    // is how both refusals below passed for the wrong reason once.
    const familyRefusal = new RegExp('"' + scoped.name + '" applies to the');
    assert.ok(wrong,
      "every protocol family this service has is one `" + scoped.name + "` " +
      "applies to, so there is no entry the refusal could be provoked on. " +
      "That is not a bug in this test — it means the attribute is not " +
      "actually scoped to anything.");

    // A CREATE carrying it onto the wrong family is refused WHOLE. The entry
    // must not exist afterwards: a create that wrote the entry and dropped the
    // field would be the half-success createApplication()'s own comment refuses
    // to produce, and it would read as a complete declaration.
    const wrongId = identifier + "-" + wrong;
    await refused("/applications/create",
      { identifier: wrongId, protocols: [wrong],
        fields: (function () {
          const f = {};
          f[scoped.name] = PROBE_VALUE;
          return f;
        })() },
      familyRefusal,
      "a create putting " + scoped.name + " on an entry declared for " + wrong);
    assert.strictEqual((await application(wrongId)).found, false,
      "the refused create must have made NO entry: `" + wrongId + "` is in " +
      "the registry, so the create wrote the entry and then refused the " +
      "field — which leaves something that reads as a finished declaration.");

    // And a `set` onto an entry that already exists in the wrong family.
    await ok("/applications/create",
             { identifier: wrongId, protocols: [wrong] },
             "created an application declared for " + wrong + " alone");
    await refused("/applications/set",
      { application: wrongId, attribute: scoped.name, value: PROBE_VALUE },
      familyRefusal,
      "setting " + scoped.name + " on an entry declared for " + wrong);
    assert.deepStrictEqual(fieldValues(await application(wrongId), scoped.name),
      [],
      "and the refusal must have written NOTHING — a refusal that recorded " +
      "the value anyway is the one failure mode a 400 cannot be trusted to " +
      "rule out, since the caller never reads the entry.");

    // CLEARING IS NEVER REFUSED, which is the other half of the rule and the
    // half a reader would not predict: a value can arrive by `ldapmodify` or be
    // left behind when a family is untimed from the entry, so refusing the
    // clear would shut the one door that could tidy it up.
    await ok("/applications/set",
      { application: wrongId, attribute: scoped.name, value: "" },
      "clearing " + scoped.name + " on an entry of the wrong family");

    // DECLARE THE FAMILY AND THE SAME WRITE IS ACCEPTED. Without this the
    // block above would pass equally against a service that had simply stopped
    // accepting the attribute anywhere.
    await ok("/applications/add",
      { application: wrongId, attribute: "appAllowedProtocol", value: right },
      "declared " + right + " on it");
    await ok("/applications/set",
      { application: wrongId, attribute: scoped.name, value: PROBE_VALUE },
      "set " + scoped.name + " now that " + right + " is declared");
    assert.deepStrictEqual(fieldValues(await application(wrongId), scoped.name),
      [PROBE_VALUE],
      "and it must be readable back off the entry: the refusal is about the " +
      "FAMILY and not about the attribute, so declaring the family has to be " +
      "the whole of what was missing.");

    await ok("/applications/forget", { application: wrongId },
             "forgot the family-scope probe");
  }

  // Two refusals that name the referent rather than the field. They are the
  // ones this API answers most often, so their wording is worth pinning: a
  // caller that gets "which application?" when it sent one has a different
  // problem from one whose application is not here.
  await refused("/applications/revoke-registration",
    { application: identifier },
    /no registration to revoke|has no registration/i,
    "revoking a registration that was never made");
  await refused("/applications/refresh-metadata", { application: identifier },
    /metadata|samlSpMetadataUrl/i,
    "refreshing metadata from an entry that names no metadata URL");

  await ok("/applications/forget", { application: identifier },
    "forgot the application");
  assert.strictEqual((await application(identifier)).found, false,
    "after `forget` the entry must be gone from the registry; it is still " +
    "there.");

  log.info("[applications] OK — seven actions round-tripped against the " +
           "entry, both refusal vocabularies read off the service, and " +
           "`forget` really removed it.");
  log.debug("Leaving theApplicationsRegistryRoundTrips().");
}

// ---------------------------------------------------------------------------
// A RETURN ADDRESS A DEVELOPMENT-MODE REQUEST PUT ON AN ENTRY, CONFIRMED AND
// DISCARDED (2026-09-12).
//
// Development writes the SAML 1.1 `shire` a browser flow names onto the relying
// party's `samlAssertionConsumerService` and MARKS it on
// `appReturnAddressObserved`; product refuses a marked address until an
// operator confirms it. `confirm-address` and `discard-address` are the two
// operations that decide which way it goes, and neither can be driven with a
// fixture of this file's own making: the mark is DERIVED, so no write through
// this API can put one there. The sighting has to come from a PROTOCOL, and it
// is SAML 1.1's inter-site transfer service because that is the one door that
// records a return address before it needs a session — one POST, no browser.
//
// A POST and not a GET, and that is about the pool rather than the protocol:
// in `dispatch` mode what counts as a write for read-your-write is the METHOD,
// so a GET sighting could be answered by a worker the read below has not heard
// from. The read is POLLED anyway, for the modes with no barrier.
//
// **THE PRODUCT HALF IS DRIVEN TOO**, through the ROOT API's realm setting so
// that this realm's own `/admin-api` is never asked anything while the realm is
// in product mode. Each probe carries the routing cookie the pool hands out, so
// the probes that compare "refused" with "accepted" are answered by one worker;
// and each waits until a probe for an address that was NEVER on the entry is
// refused, which is what says that worker has the product setting at all.
// ---------------------------------------------------------------------------
async function theObservedReturnAddressesAreDecided() {
  log.debug("Entering theObservedReturnAddressesAreDecided().");
  log.info("=== Applications: confirm-address and discard-address ===");
  const rpId = "urn:test:" + REALM + ":observed-rp";
  const ONE = "https://observed-one.example.test/acs";
  const TWO = "https://observed-two.example.test/acs";
  const NEVER = "https://never-registered.example.test/acs";
  const sso = base + "/realm/" + REALM + "/saml11/sso";
  const jar = {};

  async function sight(shire) {
    log.debug("Entering sight().");
    const headers = { "Content-Type": "application/x-www-form-urlencoded" };
    const cookie = Object.keys(jar)
                         .map(function (k) { return k + "=" + jar[k]; })
                         .join("; ");
    if (cookie) {
      headers.Cookie = cookie;
    }
    const r = await fetch(sso, {
      method: "POST", redirect: "manual", headers: headers,
      body: new URLSearchParams({ providerId: rpId, shire: shire,
                                  TARGET: "https://observed-one.example.test/app" }).toString()
    });
    const set = typeof r.headers.getSetCookie === "function" ?
                r.headers.getSetCookie() : [];
    set.forEach(function (line) {
      const pair = String(line).split(";")[0];
      const at = pair.indexOf("=");
      if (at > 0) {
        jar[pair.slice(0, at)] = pair.slice(at + 1);
      }
    });
    log.debug("Leaving sight().");
    return { status: r.status, text: await r.text() };
  }

  async function observedOn() {
    log.debug("Entering observedOn().");
    const entry = await application(rpId);
    log.debug("Leaving observedOn().");
    return { entry: entry,
             rows: (entry && entry.returnAddressesObserved) || [] };
  }

  async function until(what, predicate, ms) {
    log.debug("Entering until().");
    const deadline = Date.now() + (ms || 8000);
    let last;
    while (Date.now() < deadline) {
      last = await predicate();
      if (last && last.done) {
        log.debug("Leaving until().");
        return last;
      }
      await new Promise(function (resolve) { setTimeout(resolve, 250); });
    }
    assert.fail(what + " did not happen within " + (ms || 8000) + "ms. Last: " +
                JSON.stringify(last && last.detail).slice(0, 400));
    log.debug("Leaving until().");
  }

  // --- the sightings, in DEVELOPMENT --------------------------------------
  for (const shire of [ONE, TWO]) {
    const seen = await sight(shire);
    assert.ok(seen.status < 400,
      "POST " + sso + " naming shire " + shire + " should be accepted in " +
      "development (a redirect to the sign-in screen); it " +
      "answered " + seen.status + " " +
      seen.text.slice(0, 200));
  }
  const both = await until("both sighted addresses marked observed on " + rpId,
                           async function () {
    const now = await observedOn();
    const values = now.rows.map(function (row) { return row.value; });
    return { done: values.indexOf(ONE) >= 0 && values.indexOf(TWO) >= 0,
             detail: now.rows, now: now };
  });
  both.now.rows.forEach(function (row) {
    assert.strictEqual(row.attribute, "samlAssertionConsumerService",
      "an observed row names the attribute the address is on; it said " +
      row.attribute);
    assert.ok(row.held === true && row.trusted === true,
      "in DEVELOPMENT an observed address is on the entry and still trusted " +
      "— the mode's behaviour is unchanged — and the row should say both; it " +
      "said " + JSON.stringify(row));
  });
  assert.ok(Array.isArray(both.now.entry.returnAddressesObservedShown) &&
            both.now.entry.returnAddressesObservedPaging &&
            both.now.entry.returnAddressesObservedPaging.total === both.now.rows.length,
    "the drill-down should carry the page the console draws its buttons from " +
    "and its paging, totalling the whole list; it carried " +
    JSON.stringify(both.now.entry.returnAddressesObservedPaging));

  // A mark is DERIVED: nothing may write one.
  await refused("/applications/add",
    { application: rpId, attribute: "appReturnAddressObserved",
      value: "samlAssertionConsumerService " + NEVER },
    /appReturnAddressObserved|not editable|DERIVED/i, "writing a provenance " +
                                                      "mark by hand");

  // --- product refuses the observed address ------------------------------
  await ok("/realms/set", { id: REALM, key: "global.mode", value: "product" },
    "put the realm in product mode", true);
  assert.strictEqual(realmSetting(await realmRow(), "global.mode"), "product",
    "the realm's registry row should carry global.mode=product after `set`.");
  try {
    await until("a product-mode worker refusing an address never on the entry",
                async function () {
      const probe = await sight(NEVER);
      return { done: probe.status === 400, detail: probe.status };
    }, 15000);
    const observed = await sight(ONE);
    assert.strictEqual(observed.status, 400,
      "in PRODUCT mode the shire development recorded must be refused; it " +
      "answered " +
      observed.status);
    assert.ok(/nobody has confirmed it/.test(observed.text) &&
              /confirm-address/.test(observed.text),
      "and the refusal should say the address was learnt in development and " +
      "how to confirm it, rather than that it is not registered anywhere: " +
      observed.text.replace(/<[^>]+>/g, " ").slice(0, 400));
  } finally {
    await ok("/realms/unset", { id: REALM, key: "global.mode" },
      "put the realm back in development mode", true);
  }
  // Outside the `finally`, because an assertion thrown there would replace
  // whatever failure got the run into it.
  assert.notStrictEqual(realmSetting(await realmRow(), "global.mode"),
    "product",
    "after `unset` the realm's row must no longer carry global.mode=product.");
  await until("the realm back in development mode", async function () {
    const probe = await sight(NEVER);
    return { done: probe.status < 400, detail: probe.status };
  }, 15000);
  // That development probe was itself a sighting, which is the behaviour being
  // kept: it is discarded below rather than left to read as a real address.

  // --- confirm -----------------------------------------------------------
  await refused("/applications/confirm-address",
    { application: rpId, attribute: "samlAssertionConsumerService",
      value: "https://not-on-the-entry.example.test/acs" },
    /not marked as observed/, "confirming an address that is not marked");
  await refused("/applications/confirm-address",
    { application: rpId, attribute: "oauthPostLogoutRedirectUri", value: ONE },
    /not a return-address attribute|must be equal to one of the allowed values|attribute/i,
    "confirming on an attribute that holds no return address");
  const confirmed = await ok("/applications/confirm-address",
    { application: rpId, attribute: "samlAssertionConsumerService",
      value: ONE },
    "confirmed a development-recorded shire");
  assert.ok(/confirmed/.test(confirmed.message || ""),
    "the confirm should say what it did; it said " + confirmed.message);
  const afterConfirm = await until("the confirm read back", async function () {
    const now = await observedOn();
    return { done: now.rows.every(function (row) { return row.value !== ONE; }),
             detail: now.rows,
             now: now };
  });
  assert.ok(fieldValues(afterConfirm.now.entry,
                        "samlAssertionConsumerService").indexOf(ONE) >= 0,
    "CONFIRM takes the mark off and KEEPS the address; " + ONE + " is gone " +
        "from " +
    JSON.stringify(fieldValues(afterConfirm.now.entry,
                               "samlAssertionConsumerService")));

  // --- product now believes the confirmed one -----------------------------
  await ok("/realms/set", { id: REALM, key: "global.mode", value: "product" },
    "put the realm in product mode again", true);
  assert.strictEqual(realmSetting(await realmRow(), "global.mode"), "product",
    "the realm's registry row should carry global.mode=product after the " +
    "second `set`.");
  try {
    await until("a product-mode worker refusing an address never registered",
                async function () {
      const probe = await sight("https://still-never.example.test/acs");
      return { done: probe.status === 400, detail: probe.status };
    }, 15000);
    const believed = await sight(ONE);
    assert.ok(believed.status < 400,
      "in PRODUCT mode the CONFIRMED shire must be delivered to (a redirect " +
      "to the sign-in screen), from the same worker that has just refused an " +
      "unregistered one; it answered " +
      believed.status + " " +
      believed.text.replace(/<[^>]+>/g, " ").slice(0, 300));
  } finally {
    await ok("/realms/unset", { id: REALM, key: "global.mode" },
      "put the realm back in development mode", true);
  }
  // Outside the `finally`, because an assertion thrown there would replace
  // whatever failure got the run into it.
  assert.notStrictEqual(realmSetting(await realmRow(), "global.mode"),
    "product",
    "after `unset` the realm's row must no longer carry global.mode=product.");
  await until("the realm back in development mode", async function () {
    const probe = await sight(ONE);
    return { done: probe.status < 400 && (await sight(NEVER)).status < 400,
             detail: probe.status };
  }, 15000);

  // --- discard -----------------------------------------------------------
  await ok("/applications/discard-address",
    { application: rpId, attribute: "samlAssertionConsumerService",
      value: TWO },
    "discarded a development-recorded shire");
  const afterDiscard = await until("the discard read back", async function () {
    const now = await observedOn();
    const acs = fieldValues(now.entry, "samlAssertionConsumerService");
    return { done:
               now.rows.every(function (row) { return row.value !== TWO; }) &&
                   acs.indexOf(TWO) < 0,
             detail: { rows: now.rows, acs: acs }, now: now };
  });
  assert.ok(fieldValues(afterDiscard.now.entry,
                        "samlAssertionConsumerService").indexOf(ONE) >= 0,
    "a discard takes only the address it named; the confirmed one must still " +
    "be there");
  await refused("/applications/discard-address",
    { application: rpId, attribute: "samlAssertionConsumerService",
      value: ONE },
    /not marked as observed/, "discarding a REGISTERED address, which " +
                              "`remove` is the door for");

  // The probes used to find out which mode a worker was in are sightings too
  // whenever development answered one, which is the development behaviour this
  // section is not allowed to change. Every mark they left is discarded, so the
  // entry left standing in the realm says only what the section meant it to.
  const leftovers = (await observedOn()).rows;
  for (const row of leftovers) {
    await ok("/applications/discard-address",
      { application: rpId, attribute: row.attribute, value: row.value },
      "discarded a probe's sighting of " + row.value);
  }
  await until("every probe sighting discarded", async function () {
    const now = await observedOn();
    return { done: now.rows.length === 0, detail: now.rows };
  });

  log.info("[applications] OK — two shires recorded in development were " +
           "marked observed, the first refused in product, confirmed and " +
           "then delivered to in product, and the second discarded; both " +
           "operations read back through the drill-down.");
  log.debug("Leaving theObservedReturnAddressesAreDecided().");
}

async function application(identifier) {
  log.debug("Entering application(). identifier=" + identifier);
  const reply = await get("/applications?application=" +
                          encodeURIComponent(identifier));
  assert.strictEqual(reply.status, 200,
    "GET /applications?application=… should answer 200 whether or not the " +
    "entry is there; it answered " + reply.status);
  log.debug("Leaving application(). found=" + reply.body.found);
  return reply.body;
}

// One attribute's values off an application entry. The reply is FLAT — the
// entry's members at the top level rather than wrapped in an `application`
// member the way the WRITES answer — which is the shape
// tests/sts_applications.js already relies on.
//
// `attributes` is the WHOLE entry and `fields` beside it is the narrower
// editable subset, so the read goes to `attributes` first: an assertion that
// looked only at `fields` would report an attribute missing whenever the
// editable table narrowed, which is a change to a form and not to the entry.
function fieldValues(entry, attribute) {
  log.debug("Entering fieldValues().");
  const fields = (entry && (entry.attributes || entry.fields)) || {};
  const held = fields[attribute];
  if (held === undefined || held === null) {
    log.debug("Leaving fieldValues().");
    return [];
  }
  log.debug("Leaving fieldValues().");
  return Array.isArray(held) ? held.map(String) : [String(held)];
}

// ---------------------------------------------------------------------------
// THE THREE CLAIM-SET DOORS: seven actions each, over different sets.
//
// /claims, /saml-attributes and /userinfo-claims are three resources over ONE
// action function, differing only in the set ids each carries — which is what
// makes them a mirror of the three PAGES rather than three models of one store.
// So the walk is one loop over the three doors, driven off each door's own set
// list, and what it asserts is that the seven actions behave the same through
// all three: fourteen operations built by one function is exactly the
// arrangement where six of them can be broken and nobody notices.
//
// THE `attributes` FAMILY IS THE HALF THAT NEEDS THIS MOST. `add`, `remove`,
// `clear` and `replace` write TYPED claims — a name and a literal value — and
// the other three select DIRECTORY ATTRIBUTES to carry into the same set. They
// are stored differently, in different modules, and only one of the two stores
// has ever been read per realm by anything in this suite.
// ---------------------------------------------------------------------------
const CLAIM_DOORS = ["claims", "saml-attributes", "userinfo-claims"];

async function theClaimSetDoorsRoundTrip() {
  log.debug("Entering theClaimSetDoorsRoundTrip().");
  log.info("=== The three claim-set doors: seven actions each ===");
  for (const door of CLAIM_DOORS) {
    const sets = await setsCarriedBy(door);
    assert.ok(sets.length,
      "/" + door + " should carry at least one claim set.");
    for (const set of sets) {
      await oneClaimSetRoundTrips(door, set);
    }
    log.info("[" + door + "] OK — seven actions over " + sets.length +
             " set(s): " + sets.join(", "));
  }
  await aClaimSetBelongsToItsRealm();
  log.debug("Leaving theClaimSetDoorsRoundTrip().");
}

// ---------------------------------------------------------------------------
// A CLAIM CONFIGURED IN ONE REALM MUST NOT BE CARRIED BY ANOTHER REALM'S
// TOKENS, and this is the assertion that says so from outside the process.
//
// It was not true until 2026-08-28. `CLAIM_SETS` in common/admin_stats.js was
// a plain object — one table for the process — so a custom claim added at
// /realm/acme/admin/claims was added to every realm's tokens at once, the
// DEFAULT realm's included, while each realm's console showed it as that
// realm's own configuration. The OTHER HALF of the same claim set was already
// per realm (the directory attributes, in common/claim_attributes.js), so one
// claim set disagreed with itself about whether it belonged to a realm.
//
// It is asserted HERE rather than by reading the two consoles, because the
// console reading the same table twice is exactly what the defect looked like
// from the console. What settles it is a TOKEN: mint one in each realm and
// look at what is in it.
// ---------------------------------------------------------------------------
async function aClaimSetBelongsToItsRealm() {
  log.debug("Entering aClaimSetBelongsToItsRealm().");
  log.info("=== A claim set belongs to the realm it was configured in ===");
  const claim = "only_in_" + REALM.replace(/-/g, "_");
  await ok("/claims/add",
    { set: "access_token", name: claim, value: "yes" },
    "added a custom claim in " + REALM);
  assert.strictEqual(typedClaim(await claimSet("claims", "access_token"),
                                claim),
    "yes",
    "the claim should be readable back through this realm's own /claims " +
    "before anything is minted — the token below says what the SIGNER did " +
    "with it, and this says what the CONSOLE holds, which are the two halves " +
    "that disagreed while CLAIM_SETS was one table for the process.");

  const mine = await mintTokens(names.usernameFor("stsapi-claimrealm"),
                                "claim-realm-client-" + REALM);
  assert.strictEqual(claimOf(mine.access, claim), "yes",
    "the claim should be in a token minted BY THE REALM IT WAS CONFIGURED IN.");

  // The default realm's own token endpoint, which nothing in this section
  // configured.
  // The client is named for this run: it is created in the DEFAULT realm,
  // which a run does not clean up, so a fixed name met the previous run's
  // client — holding the previous run's secret — on a long-lived service.
  const elsewhereUser = names.usernameFor("stsapi-elsewhere");
  const elsewhereClient = "claim-realm-elsewhere-" + REALM;
  await ensureTokenParties(elsewhereUser, elsewhereClient, true);
  const elsewhere = await common.httpJson(base + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=password&username=" + encodeURIComponent(elsewhereUser) +
        "&password=" + encodeURIComponent(MINT_PASSWORD) +
        "&client_id=" + encodeURIComponent(elsewhereClient) +
        "&client_secret=" + encodeURIComponent(MINT_CLIENT_SECRET) +
        "&scope=openid"
  });
  assert.strictEqual(elsewhere.status, 200,
    "the default realm's token endpoint should still mint a token; it " +
    "answered " + elsewhere.status);
  assert.strictEqual(claimOf(elsewhere.body.access_token, claim), "",
    "A CUSTOM CLAIM CONFIGURED IN " + REALM + " MUST NOT BE IN THE DEFAULT " +
    "REALM'S TOKENS. A trust realm is a whole logical copy of this service " +
    "with its own configuration — that is the entire claim the feature " +
    "makes — so a claim set held once for the process is configuration " +
    "leaking between realms in the artefact that matters most. The default " +
    "realm's access token carries " + claim + "=" +
    JSON.stringify(claimOf(elsewhere.body.access_token, claim)));

  // And the default realm's console must not SHOW it either, which is the
  // half an operator would notice.
  const theirs = await get("/claims", true);
  const names_ = ((theirs.body.sets || []).filter(function (row) {
    return row.id === "access_token";
  })[0] || {}).claims || [];
  assert.ok(!names_.some(function (row) { return row.name === claim; }),
    "and the default realm's /admin-api/claims must not list it; it lists " +
    JSON.stringify(names_.map(function (row) { return row.name; })));

  await ok("/claims/remove", { set: "access_token", name: claim },
    "removed the realm's custom claim again");
  assert.strictEqual(typedClaim(await claimSet("claims", "access_token"),
                                claim),
    undefined,
    "and it should be gone from this realm's claim set afterwards — the " +
    "restore matters here as much as the change, because this door is not " +
    "inside the throwaway realm's teardown for the DEFAULT realm's sake.");
  log.info("[claim realms] OK — a claim configured in " + REALM + " reaches " +
           "that realm's tokens and neither the default realm's tokens nor " +
           "its console.");
  log.debug("Leaving aClaimSetBelongsToItsRealm().");
}

// The set ids one door carries, read off its own refusal rather than typed.
async function setsCarriedBy(door) {
  log.debug("Entering setsCarriedBy(). door=" + door);
  const probe = await post("/" + door + "/__no_such_action__", { set: "" });
  const errors = ((probe.body && probe.body.errors) || []).join(" ");
  const carried = errors.match(/(?:carries|carry|are)\s*(?:are)?:\s*([^.]+)\./);
  assert.ok(carried,
    "/" + door + " asked with no `set` should name the sets it carries: " +
    errors);
  const sets = splitList(carried[1]);
  log.debug("Leaving setsCarriedBy(). " + sets.join(", "));
  return sets;
}

async function oneClaimSetRoundTrips(door, set) {
  log.debug("Entering oneClaimSetRoundTrips(). door=" + door + ", set=" + set);
  const claim = "test_" + set.replace(/[^a-z0-9]/gi, "_");

  // The typed claims: add, remove, replace, clear.
  await ok("/" + door + "/add", { set: set, name: claim, value: "one" },
    "added a typed claim to " + set);
  assert.strictEqual(typedClaim(await claimSet(door, set), claim), "one",
    "`add` on /" + door + " should put " + claim + " into the " + set +
    " set, readable through GET /" + door + "?set=" + set + ".");

  // `replace` takes the WHOLE set rather than one claim, which is what makes
  // it the action a form's "save" posts: the page shows every row and sends
  // them all back, so a partial application would leave the set in a state
  // nobody asked for. Sending two here also checks that it does not simply
  // append — a `replace` that behaved as `add` would pass a one-row check.
  await ok("/" + door + "/replace",
    { set: set, claims: [{ name: claim, value: "two" },
                         { name: claim + "_b", value: "three" }] },
    "replaced the typed claims of " + set);
  let held = await claimSet(door, set);
  assert.strictEqual(typedClaim(held, claim), "two",
    "`replace` should leave the claim it was given, with the value it was " +
    "given; it reads " + typedClaim(held, claim));
  assert.strictEqual(typedClaims(held).length, 2,
    "and it should leave EXACTLY what it was given — two claims — rather " +
    "than adding them to what was there. It left " +
    JSON.stringify(typedClaims(held).map(function (c) { return c.name; })));
  await ok("/" + door + "/remove", { set: set, name: claim + "_b" },
    "removed the second claim again");
  assert.strictEqual(typedClaim(await claimSet(door, set), claim + "_b"),
    undefined,
    "`remove` should take the second claim out too — it is read back for the " +
    "same reason the first one is: `replace` put both there in one call, so " +
    "a `remove` that only ever removed the LAST claim would pass a check " +
    "made against a set with one row in it.");

  await ok("/" + door + "/remove", { set: set, name: claim },
    "removed a typed claim from " + set);
  assert.strictEqual(typedClaim(await claimSet(door, set), claim), undefined,
    "`remove` should take it out again.");

  // A name the set reserves is refused BY NAME. This is the one refusal on
  // these doors that protects a protocol rather than the form: a custom claim
  // called `iss` would be overwritten by the issuer at signing time, so a
  // service that accepted it would be storing something it will never send.
  const reserved = await reservedNameFor(door);
  if (reserved) {
    await refused("/" + door + "/add",
      { set: set, name: reserved, value: "x" },
      new RegExp(reserved.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
      "a reserved claim name (" + reserved + ")");
  }

  // The DIRECTORY ATTRIBUTE half. `attributes` selects, `attributes-all`
  // selects everything in the catalogue and `attributes-clear` empties it —
  // three actions over a different store from the four above.
  const catalogue = await attributeCatalogue(door);
  assert.ok(catalogue.length > 1,
    "GET /" + door + " should publish the attribute catalogue the three " +
    "`attributes` actions select from; it published " + catalogue.length);

  await ok("/" + door + "/attributes",
    { set: set, attributes: [catalogue[0]] },
    "selected one directory attribute for " + set + " — AND THIS IS THE " +
    "ACTION THAT IS BROKEN IN EVERY NON-DEFAULT TRUST REALM IF THE STORE " +
    "BEHIND IT IS SEEDED ONCE AT REQUIRE TIME RATHER THAN PER REALM. The " +
    "refusal to watch for is `There is no claim set called \"" + set +
    "\". The N are: … " + set + " …` — a sentence that lists the set it is " +
    "refusing, which is what a lookup against an empty per-realm partition " +
    "produces beside a list read from the process-wide table");
  assert.deepStrictEqual(selectedAttributes(await claimSet(door, set)),
    [catalogue[0]],
    "`attributes` should leave exactly the attribute it was given selected.");

  await ok("/" + door + "/attributes-all", { set: set },
    "selected every directory attribute for " + set);
  assert.strictEqual(selectedAttributes(await claimSet(door, set)).length,
    catalogue.length,
    "`attributes-all` should select the whole catalogue — " + catalogue.length +
    " attributes — and it selected " +
    selectedAttributes(await claimSet(door, set)).length);

  await ok("/" + door + "/attributes-clear", { set: set },
    "cleared the directory attributes for " + set);
  assert.deepStrictEqual(selectedAttributes(await claimSet(door, set)), [],
    "`attributes-clear` should leave none selected.");

  // `clear` last, because it is the one that empties the typed claims and the
  // checks above want something in there.
  await ok("/" + door + "/add", { set: set, name: claim, value: "three" },
    "added a claim back so that `clear` has something to clear");
  await ok("/" + door + "/clear", { set: set }, "cleared " + set);
  assert.deepStrictEqual(typedClaims(await claimSet(door, set)), [],
    "`clear` should leave the typed claim set empty.");
  log.debug("Leaving oneClaimSetRoundTrips().");
}

async function claimSet(door, set) {
  log.debug("Entering claimSet(). door=" + door + ", set=" + set);
  const reply = await get("/" + door);
  assert.strictEqual(reply.status, 200,
    "GET /" + door + " should answer 200; it answered " + reply.status);
  // The reply carries EVERY set this door holds, each with its own typed
  // claims and its own selected attributes, rather than one set chosen by a
  // query parameter. That is the shape the console's page needs (it draws them
  // all) and it is what /admin-api hands back unchanged.
  const one = (reply.body.sets || []).filter(function (row) {
    return row && row.id === set;
  })[0];
  assert.ok(one,
    "GET /" + door + " should carry the set \"" + set + "\" in its `sets` " +
    "member; it carries " +
    JSON.stringify((reply.body.sets || []).map(function (r) { return r.id; })));
  log.debug("Leaving claimSet().");
  return one;
}

// The typed claims of one set — a list of {name, value} — and one of them by
// name. `claims` is the member; `attributes` beside it is the OTHER half of
// the same set and is asserted separately, because the two are different
// stores in different modules and only one of them was ever per realm.
function typedClaims(set) {
  log.debug("Entering typedClaims().");
  const held = (set && set.claims) || [];
  log.debug("Leaving typedClaims().");
  return Array.isArray(held) ? held : [];
}

function typedClaim(set, name) {
  log.debug("Entering typedClaim().");
  const row = typedClaims(set).filter(function (one) {
    return one && one.name === name;
  })[0];
  log.debug("Leaving typedClaim().");
  return row ? row.value : undefined;
}

// The directory attributes selected into one set, sorted so that a comparison
// is about membership rather than about the order the catalogue happens to be
// in — which the mock deliberately keeps in CATALOGUE order rather than in the
// order they were ticked, because that order reaches the token.
function selectedAttributes(set) {
  log.debug("Entering selectedAttributes().");
  const held = (set && set.attributes) || [];
  log.debug("Leaving selectedAttributes().");
  return Array.isArray(held) ? held.map(String).slice().sort() : [];
}

// Every attribute a set could select, off the door's own catalogue. The rows
// are keyed by their LDAP name, which is what the three `attributes` actions
// take.
async function attributeCatalogue(door) {
  log.debug("Entering attributeCatalogue(). door=" + door);
  const reply = await get("/" + door);
  const out = (reply.body.attributeCatalogue || []).map(function (row) {
    return typeof row === "string" ? row : row.ldap;
  }).filter(Boolean);
  log.debug("Leaving attributeCatalogue(). " + out.length);
  return out;
}

// A name this door will refuse, out of its own reserved list. Read off the
// service rather than typed here: the lists differ per family — a JWT reserves
// `iss` and `aud`, a SAML attribute set reserves nothing of the kind — and a
// copy in this file would be a second definition of a table that moves.
async function reservedNameFor(door) {
  log.debug("Entering reservedNameFor(). door=" + door);
  const reply = await get("/" + door);
  const reserved = reply.body.reservedJwtClaims || reply.body.reservedNames ||
      reply.body.reserved || [];
  const out = Array.isArray(reserved) && reserved.length ? String(reserved[0]) :
              "";
  log.debug("Leaving reservedNameFor(). " + (out || "(none)"));
  return out;
}

// ---------------------------------------------------------------------------
// THE FEDERATION REGISTER — the one resource on this API whose operations
// change what this service will BELIEVE.
//
// mgmt-api/CLAUDE.md says so in the sharpest form it says anything: this API is
// not gated, so `POST /admin-api/federation/create` is the door that works when
// the console cannot be reached — and it is also the door through which anybody
// who can reach this port configures a signing certificate this service will
// then trust, and mints themselves a session as anybody. That is not a new
// hole, but it makes these seven operations the ones worth driving properly.
//
// Two properties beyond the round trip, and both are about what the register
// REFUSES rather than what it stores:
//
//   * a relationship is created DISABLED, and `enable` is a separate act. The
//     whole feature is the one thing in this service that refuses by default,
//     and "created ready to use" would quietly undo that.
//   * `fedClientSecret` is never returned by this API. That is deliberately NOT
//     claimed as a security boundary — an ldapsearch of ou=federations shows it
//     — but it stops this API being a second way to read a credential that
//     belongs to somebody else's service.
// ---------------------------------------------------------------------------
async function theFederationRegisterRoundTrips() {
  log.debug("Entering theFederationRegisterRoundTrips().");
  log.info("=== Federation: create, set, add-value, remove-value, enable, " +
           "disable, delete ===");
  const index = await get("/federation");
  // Each row names itself by the field the CREATE takes — `role` and
  // `protocol` — rather than by a generic `id`, which is what makes this
  // listing usable as the vocabulary a caller constructs a create from.
  const roles = (index.body.roles || []).map(function (r) {
    return typeof r === "string" ? r : r.role;
  }).filter(Boolean);
  const protocols = (index.body.protocols || []).map(function (p) {
    return typeof p === "string" ? p : p.protocol;
  }).filter(Boolean);
  assert.ok(roles.length && protocols.length,
    "GET /federation should publish the roles and the protocols a create is " +
    "validated against; it published " + JSON.stringify(roles) + " and " +
    JSON.stringify(protocols));

  const id = "fed-" + names.usernameFor("stsapi-fed").toLowerCase()
      .replace(/[^a-z0-9-]/g, "");
  // WITH ITS PEER, which the create takes as `peer` (2026-09-12). A
  // relationship naming no partner identifier is not fully configured in ANY
  // mode now — `fedPeer` is what a service-provider-side relationship checks an
  // assertion's issuer against — so a create that left it for `set` below would
  // be building the half-configured relationship this register exists to
  // refuse. `set` still drives the attribute afterwards, to a different value.
  const created = await ok("/federation/create", {
    id: id, name: "Test relationship", role: roles[0], protocol: protocols[0],
    peer: "urn:partner:" + id
  }, "created a federation relationship");
  assert.strictEqual((await relationship(id)).peer, "urn:partner:" + id,
    "the peer given to the create should be on the relationship it made.");
  assert.ok(created.relationship,
    "the create should answer with the relationship it made.");

  const fresh = await relationship(id);
  assert.strictEqual(fresh.enabled, false,
    "A NEW RELATIONSHIP MUST BE DISABLED. Federation is the one feature here " +
    "that refuses by default — there is no permissive answer available at " +
    "/federation/acs/{id}, because 'accept any assertion' means letting " +
    "anybody who can reach this port POST a document naming themselves as " +
    "anybody — so a create that came out ready to use would undo the whole " +
    "posture while answering 200. It reads enabled=" + fresh.enabled);
  assert.ok(Array.isArray(fresh.missing) && fresh.missing.length,
    "and it should say what it is still MISSING before it could be used; it " +
    "says " + JSON.stringify(fresh.missing));

  await ok("/federation/enable", { id: id }, "enabled the relationship");
  assert.strictEqual((await relationship(id)).enabled, true,
    "`enable` should flip it.");
  await ok("/federation/disable", { id: id }, "disabled the relationship");
  assert.strictEqual((await relationship(id)).enabled, false,
    "`disable` should flip it back.");

  // `set` names one attribute of the relationship, and an attribute this
  // register does not have is refused BY NAME rather than written — the
  // register IS ou=federations, so an unknown attribute would otherwise become
  // a directory attribute nobody reads.
  await refused("/federation/set",
    { id: id, field: "fedNoSuchThing", value: "x" },
    /fedNoSuchThing|not an attribute/,
    "an attribute the federation schema does not have");

  // `fedPeer` is the partner's own identifier — an entityID, an issuer, a
  // wtrealm — and it is single-valued, which is what makes it the right one to
  // drive `set` with. GET /federation?relationship= reports it as `peer`.
  await ok("/federation/set",
    { id: id, field: "fedPeer", value: "urn:partner:test" }, "set fedPeer");
  assert.strictEqual((await relationship(id)).peer, "urn:partner:test",
    "`set` on fedPeer should be readable back off the relationship, where " +
    "the drill-down reports it as `peer`.");

  // `add-value` and `remove-value` take a MULTI-VALUED field, and which
  // fields those are depends on the relationship's ROLE — `fedAttributeMap` on
  // a service-provider-side one, `fedRelease` on an identity-provider-side one
  // — so the field is chosen off the relationship's own `editable` table
  // rather than named here. `description` is skipped because the register
  // writes its own lines into it, so a value added there is not the only thing
  // in the list.
  //
  // WHAT THIS PAIR CANNOT CATCH, and it is worth writing down beside the
  // check that does not make it: the operations DOCUMENT an enum of three
  // fields and federation.js's update() does not enforce it. A single-valued
  // field sent to `remove-value` takes the single-valued branch and is
  // ASSIGNED the value — so a caller asking for a value to be taken off
  // fedSsoUrl gets 200 and a fedSsoUrl set to it. Asserting that here would
  // either lock in the behaviour or fail against the service as it stands, so
  // it is reported rather than encoded.
  const multiField = ((await relationship(id)).editable || []).filter(
      function (row) {
    return row.editable === "multi" && row.name !== "description" &&
        (row.role === "both" || row.role === roles[0]);
  })[0];
  assert.ok(multiField,
    "the relationship should publish at least one multi-valued editable " +
    "field for `add-value` to drive; a " + roles[0] + "-side relationship " +
    "published none.");
  const mapping = "urn:test:" + REALM + ":attr=employeeNumber";
  await ok("/federation/add-value",
    { id: id, field: multiField.name, value: mapping },
    "added a value to " + multiField.name);
  assert.ok(JSON.stringify((await relationship(id)).fields[multiField.name] || [])
      .indexOf(mapping) >= 0,
    "`add-value` should be readable back off the relationship's own field; " +
    multiField.name + " holds " +
    JSON.stringify((await relationship(id)).fields[multiField.name]));
  await ok("/federation/remove-value",
    { id: id, field: multiField.name, value: mapping },
    "removed the value again");
  assert.ok(JSON.stringify((await relationship(id)).fields[multiField.name] || [])
      .indexOf(mapping) < 0,
    "AND `remove-value` SHOULD REALLY TAKE IT OFF. This is the pair that is " +
    "easiest to get wrong in one direction only — a `remove-value` that " +
    "answers 200 having matched nothing looks exactly like one that worked — " +
    "and this relationship is about to be deleted, so the only place it can " +
    "be caught is here. " + multiField.name + " still holds " +
    JSON.stringify((await relationship(id)).fields[multiField.name]));

  // The secret is write-only through this door, on every read of it.
  const listed = await get("/federation");
  const asJson = JSON.stringify(listed.body);
  assert.ok(asJson.indexOf("fedClientSecret\":\"") < 0 ||
            /"fedClientSecret":\s*("(\(set[^"]*\)|)")/.test(asJson),
    "`fedClientSecret` must never come back through this API with a value in " +
    "it. It is not claimed as a security boundary — an ldapsearch of " +
    "ou=federations shows it — but this API must not be a SECOND way to read " +
    "a credential belonging to somebody else's service. The listing carries: " +
    (asJson.match(/"fedClientSecret":[^,}]*/) || ["(absent)"])[0]);

  await ok("/federation/delete", { id: id }, "deleted the relationship");
  assert.strictEqual((await relationship(id)).found, false,
    "after `delete` the relationship must be gone.");
  log.info("[federation] OK — seven actions round-tripped, a new " +
           "relationship is disabled and incomplete, an unknown attribute is " +
           "refused by name, and the client secret is never returned.");
  log.debug("Leaving theFederationRegisterRoundTrips().");
}

async function relationship(id) {
  log.debug("Entering relationship(). id=" + id);
  const reply = await get("/federation?relationship=" + encodeURIComponent(id));
  assert.strictEqual(reply.status, 200,
    "GET /federation?relationship=… should answer 200; it answered " +
    reply.status);
  log.debug("Leaving relationship(). found=" + reply.body.found);
  return reply.body;
}

// ---------------------------------------------------------------------------
// DELEGATED PERMISSIONS — the CONFIGURED half of the delegation register, and
// the one resource here whose two halves live on TWO DIFFERENT ENTRIES.
//
// Everything else on this API writes an attribute and reads it back off the
// same object. A grant does not: `oauthPermission` lands on the RESOURCE
// application and `oauthDelegatedPermission` lands on the CLIENT, and the thing
// that joins them is a string composed from a third attribute on the first of
// them. So the read-backs below deliberately go through `GET /permissions`,
// which resolves both directions, rather than through `GET /applications` —
// reading the client's own entry would confirm that a value was written and
// prove nothing about whether it RESOLVES, which is the only interesting
// property this feature has.
//
// **THE ORDERING RULE IS THE SUBJECT.** A permission must be DEFINED before it
// can be GRANTED, and a permission needs a base URI before it can be defined.
// Both refusals are driven, in the order that makes them meaningful: BEFORE the
// thing they require exists, so that a run in which the rules had been dropped
// would fail here rather than silently accept both.
// ---------------------------------------------------------------------------
async function theDelegatedPermissionsRoundTrip() {
  log.debug("Entering theDelegatedPermissionsRoundTrip().");
  log.info("=== Delegated permissions: base, define, remove, grant, revoke " +
           "===");

  const resource = "api-" + names.usernameFor("stsapi-resource");
  const client = "app-" + names.usernameFor("stsapi-client");
  await ok("/applications/create",
    { identifier: resource, name: "Widget API", protocols: ["oauth2"] },
    "created the resource application");
  await ok("/applications/create",
    { identifier: client, name: "Portal", protocols: ["oauth2", "oidc"],
      fields: { oauthClientId: client, oauthClientSecret: MINT_CLIENT_SECRET,
                oauthTokenEndpointAuthMethod: "client_secret_post" } },
    "created the client application, with the secret its token request " +
    "presents");

  const base = "https://" + resource + ".example.com/";

  // BOTH REFUSALS FIRST, while the things they require genuinely do not exist.
  // Driven in this order on purpose: after the base and the permission are in
  // place these two calls would succeed, so a run that made them later would
  // assert nothing about the rules at all.
  await refused("/permissions/define-permission",
    { resource: resource, name: "write" },
    /no `oauthPermissionBaseUri`|base/i,
    "a permission on an application with no base URI");
  await refused("/permissions/grant-permission",
    { client: client, permission: base + "write" },
    /must be DEFINED before it can be GRANTED/,
    "a grant naming a permission nobody defines");

  // A base URI has to be absolute, because it becomes an access token's `aud`.
  await refused("/permissions/set-permission-base",
    { resource: resource, baseUri: "not-a-uri" },
    /absolute/i, "a base URI that is not absolute");

  await ok("/permissions/set-permission-base",
    { resource: resource, baseUri: base }, "set the permission base URI");
  await ok("/permissions/define-permission",
    { resource: resource, name: "write", description: "Change widgets" },
    "defined a permission");
  await ok("/permissions/define-permission",
    { resource: resource, name: "read" }, "defined a second permission");

  // A NAME THAT COULD NOT SURVIVE A SCOPE PARAMETER, and a duplicate. Both are
  // refusals a caller can actually provoke by hand, and both would be invisible
  // until a token came back wrong.
  await refused("/permissions/define-permission",
    { resource: resource, name: "read write" },
    /scope token|space/i, "a permission name with a space in it");
  await refused("/permissions/define-permission",
    { resource: resource, name: "write", description: "again" },
    /already defines/i, "a second permission with a name already taken");

  const defined = await permissionRegister();
  const written = defined.permissions.filter(function (one) {
    return one.resource === resource;
  });
  assert.strictEqual(written.length, 2,
    "the register should report both permissions this run defined; it " +
    "reported " + written.length + ".");
  assert.ok(written.some(function (one) { return one.id === base + "write"; }),
    "and each one's identifier should be the base URI followed by the name — " +
    "that string is what a client puts in a `scope` and what nothing else in " +
    "this service composes. It reported: " +
    written.map(function (one) { return one.id; }).join(", "));
  assert.ok(written.every(function (one) { return !one.grantedTo.length; }),
    "and NOTHING should hold either of them yet: defining a permission " +
    "grants it to nobody, which is the ordering this whole feature is built " +
    "on and is the assertion a handler that quietly granted on define would " +
    "fail.");

  // AN APPLICATION CANNOT BE GRANTED ITS OWN PERMISSION — the token would be
  // addressed to itself, and the picture would draw a line from a box back to
  // the same box.
  await refused("/permissions/grant-permission",
    { client: resource, permission: base + "write" },
    /DEFINES|itself/i, "an application granting itself its own permission");

  await ok("/permissions/grant-permission",
    { client: client, permission: base + "write" }, "granted a permission");
  await ok("/permissions/grant-permission",
    { client: client, permission: base + "read" },
    "granted a second permission on the same resource");

  const granted = await permissionRegister();
  const held = granted.grants.filter(function (one) {
    return one.client === client;
  });
  assert.strictEqual(held.length, 2,
    "TWO GRANTS BETWEEN TWO APPLICATIONS ARE TWO ROWS, not one row saying " +
    "`2`: the permission is what was granted and the pair of applications is " +
    "what it happens to join. The register reported " + held.length + ".");
  assert.ok(held.every(function (one) { return !one.dangling; }),
    "and neither should be dangling — both name a permission that resolves.");
  assert.ok(held.every(function (one) { return one.resource === resource; }),
    "and both should resolve back to the application that exposes them, " +
    "which is the whole of what this resource does that reading the client's " +
    "own entry could not.");

  // -----------------------------------------------------------------------
  // AND THE TWO HALVES ARE ON TWO DIFFERENT ENTRIES, read through the
  // APPLICATIONS registry rather than through the one above.
  //
  // This is the assertion `GET /permissions` cannot make about itself: that
  // resource resolves both directions and would report the same register
  // whichever entry the attributes had actually landed on. The failure it
  // guards against is a specific one and it is easy to write — a grant put on
  // the RESOURCE instead of the client, so the entry that answers "may this
  // request be honoured" is the API rather than its caller, and every lookup
  // at the token endpoint then finds nothing while this console looks right.
  // -----------------------------------------------------------------------
  const resourceEntry = await application(resource);
  assert.deepStrictEqual(fieldValues(resourceEntry, "oauthPermissionBaseUri"),
    [base], "the base URI belongs on the application that EXPOSES the API.");
  assert.deepStrictEqual(
    fieldValues(resourceEntry, "oauthPermission").slice().sort(),
    ["read", "write|Change widgets"],
    "and so do the permissions, one value each, with the description after " +
    "the first `|` — which is the spelling an ldapmodify has to match.");
  assert.deepStrictEqual(fieldValues(resourceEntry, "oauthDelegatedPermission"),
    [], "and the resource holds NO grant: exposing a permission is not being " +
        "granted one.");

  const clientEntry = await application(client);
  assert.deepStrictEqual(
    fieldValues(clientEntry, "oauthDelegatedPermission").slice().sort(),
    [base + "read", base + "write"],
    "THE GRANTS BELONG ON THE CLIENT, as whole permission identifiers. That " +
    "is the entry a token request identifies, so it is the entry that has to " +
    "answer whether the request may be honoured.");
  assert.deepStrictEqual(fieldValues(clientEntry, "oauthPermission"), [],
    "and the client exposes nothing: holding a permission is not defining " +
    "one.");

  // -----------------------------------------------------------------------
  // AND THE TOKEN, WHICH IS WHAT ALL OF IT IS FOR.
  //
  // Everything above asserts that a register was written. This asserts that
  // the register is READ, at the one place it changes what a client receives —
  // and it is the assertion that would still be missing if this file stopped
  // at the API, because a configuration nothing consults is a configuration
  // that can be perfectly correct and worth nothing.
  // -----------------------------------------------------------------------
  const minted = await mintPermissionToken(client,
                                           [base + "write", base + "read"]);
  assert.strictEqual(audienceOf(minted.access), base,
    "THE ACCESS TOKEN SHOULD BE AUDIENCED TO THE BASE URI. A client asked " +
    "for two permission identifiers and this is the resource they hang off, " +
    "which is what a resource server checks once before reading anything " +
    "else. It carried: " + JSON.stringify(claimOf(minted.access, "aud")));
  const scopes = String(claimOf(minted.access, "scope")).split(/\s+/);
  assert.ok(scopes.indexOf("write") >= 0 && scopes.indexOf("read") >= 0,
    "AND ITS SCOPE CLAIM SHOULD CARRY THE BARE PERMISSION NAMES, which is " +
    "what Microsoft Entra ID does and what makes a resource server's check " +
    "one comparison rather than a URL parse. It carried: " +
    claimOf(minted.access, "scope"));
  assert.ok(scopes.indexOf(base + "write") < 0,
    "and NOT the identifiers it was asked with — a scope value that became " +
    "the audience must come off the scope claim, or the token says the same " +
    "thing twice in two vocabularies. It carried: " +
    claimOf(minted.access, "scope"));

  // Asking for it is what makes `asked` true, and that column is the only
  // thing on this register that comes from what HAPPENED rather than from what
  // somebody typed. A run that never checked it would not notice the day it
  // stopped being recorded, which is exactly what a client_credentials client
  // did until the token endpoint began writing `oauthScope`.
  const used = await permissionRegister();
  assert.ok(used.grants.some(function (one) {
    return one.client === client && one.permissionName === "write" && one.asked;
  }), "the grant this client just spent should now read as ASKED FOR. That " +
      "column is the difference between a configured register and a useful " +
      "one — it is what makes `granted and never asked for` a question the " +
      "console can answer.");

  // -----------------------------------------------------------------------
  // REMOVE AND REVOKE, and the state in between them that nothing else here
  // produces: a grant whose permission has gone.
  // -----------------------------------------------------------------------
  await ok("/permissions/remove-permission",
    { resource: resource, name: "write" }, "removed a permission");
  const stranded = await permissionRegister();
  const orphan = stranded.grants.filter(function (one) {
    return one.client === client && one.permissionId === base + "write";
  })[0];
  assert.ok(orphan && orphan.dangling === true,
    "REMOVING A PERMISSION DOES NOT REVOKE THE GRANTS NAMING IT. They stay " +
    "on the clients' entries and are reported as DANGLING, because tidying " +
    "them would be one call writing to entries it did not name — and a grant " +
    "that silently vanished would be worse than one that is visibly broken. " +
    "The register said: " + JSON.stringify(orphan));

  await ok("/permissions/revoke-permission",
    { client: client, permission: base + "write" },
    "revoked the dangling grant");
  await ok("/permissions/revoke-permission",
    { client: client, permission: base + "read" }, "revoked the live one");
  const cleared = await permissionRegister();
  assert.deepStrictEqual(cleared.grants.filter(function (one) {
    return one.client === client;
  }), [], "and revoking clears them whether or not anything defines them — " +
          "which is the only way a dangling grant can ever be got rid of.");

  log.debug("Leaving theDelegatedPermissionsRoundTrip().");
}

async function permissionRegister() {
  log.debug("Entering permissionRegister().");
  const reply = await get("/permissions");
  assert.strictEqual(reply.status, 200,
    "GET /permissions should answer 200; it answered " + reply.status);
  assert.ok(Array.isArray(reply.body.grants) &&
            Array.isArray(reply.body.permissions),
    "and it should carry both directions of the register.");
  log.debug("Leaving permissionRegister(). " + reply.body.grants.length + " " +
      "grant(s).");
  return reply.body;
}

// A token asked for by PERMISSION rather than by scope name.
// `client_credentials` rather than the password grant `mintTokens()` uses,
// because what is being asserted is a property of the SCOPE LIST and there is
// no reason to involve a person in it.
async function mintPermissionToken(client, wanted) {
  log.debug("Entering mintPermissionToken(). client=" + client);
  const body = "grant_type=client_credentials&client_id=" +
      encodeURIComponent(client) +
      "&client_secret=" + encodeURIComponent(MINT_CLIENT_SECRET) +
      "&scope=" + encodeURIComponent(wanted.join(" "));
  const reply = await common.httpJson(base + "/realm/" + REALM +
                                      "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body
  });
  assert.strictEqual(reply.status, 200,
    "the realm's token endpoint should mint a token for a permission scope; " +
    "it answered " + reply.status + " " + String(reply.raw).slice(0, 300));
  log.debug("Leaving mintPermissionToken().");
  return { access: reply.body.access_token, scope: reply.body.scope };
}

// The `aud` as ONE value. RFC 7519 section 4.1.3 allows a string or an array,
// and this service sends an array when a token is addressed to more than one
// party — several RFC 8707 resources, for instance. (An `openid` token asking
// for a permission was one until 2026-09-13; RFC 9068 made it a token for the
// permission's API alone.) The permission's base URI is the one being asserted
// about, so any others are not an error.
function audienceOf(jwt) {
  log.debug("Entering audienceOf().");
  const aud = claimOf(jwt, "aud");
  log.debug("Leaving audienceOf().");
  return Array.isArray(aud) ? aud[0] : aud;
}

// ---------------------------------------------------------------------------
// THE TWO SAML REGISTRIES. They are SEPARATE IMPLEMENTATIONS rather than one
// with a version flag — SAML 1.1 has no request message, no Single Logout and a
// different spelling for almost every shared element — which is why /saml2 has
// four actions and /saml11 has one, and why a walk that treated them as one
// resource would be asserting the thing that is not true.
// ---------------------------------------------------------------------------
async function theSamlRegistriesRoundTrip() {
  log.debug("Entering theSamlRegistriesRoundTrip().");
  log.info("=== SAML 2.0 (four actions) and SAML 1.1 (one) ===");
  const sp = "urn:test:" + REALM + ":sp";
  // **`acs` USED TO BE IN THIS BODY AND WAS ALWAYS IGNORED (removed
  // 2026-09-06).** `saml2Action()`'s register branch reads `sp` and nothing
  // else, there is no action on this resource that sets an assertion consumer
  // service, and no assertion below ever looked for one — so the member did
  // nothing from the day it was written and this job passed regardless.
  //
  // It was found by ENFORCING the operation's own schema: every action here
  // declares a `requestBody` with `additionalProperties: false`, the OpenAPI
  // document has always published it, and since 2026-09-06 `admin_api.js`
  // compiles that same object with ajv and refuses a body that does not match.
  //
  // That is precisely the hazard the comment twenty lines below this one warns
  // about — *the handler reads `value`, and a body naming the field anything
  // else answers 200 having done nothing* — committed here, in the file that
  // warns about it. A silently ignored member is the one kind of API mistake a
  // passing test cannot see, which is the whole argument for the document being
  // enforced rather than descriptive.
  const registered = await ok("/saml2/register",
    { sp: sp },
    "registered a SAML 2.0 service provider");
  assert.ok(registered.application,
    "the register should answer with the application entry it made or found.");

  const one = await serviceProvider(sp);
  assert.ok(one.slug,
    "a registered service provider should have a SLUG: the metadata is " +
    "published per service provider, so the document's URL carries a digest " +
    "of the entityID rather than the entityID itself, and three shell " +
    "scripts in this suite compute that segment with sha256sum. A registry " +
    "that stopped publishing it would break them with nothing here failing.");
  assert.ok(String(one.metadataUrl || "").indexOf(one.slug) > 0,
    "and the metadata URL should carry that slug; it is " + one.metadataUrl);
  assert.ok(String(one.metadataUrl || "").indexOf("/realm/" + REALM + "/") > 0,
    "and the URL should be inside this realm, since the entry is; it is " +
    one.metadataUrl);

  // `binding` was here and is ignored too — `saml2Action()` reads `sp` and
  // `value` for this action and nothing else. Same finding as `acs` above.
  await ok("/saml2/set-logout-service",
    { sp: sp, value: "https://sp.example/slo" },
    "added a single logout service");
  assert.ok(JSON.stringify(await serviceProvider(sp))
                .indexOf("https://sp.example/slo") > 0,
    "the logout service should be readable back off the service provider.");
  await ok("/saml2/remove-logout-service",
    { sp: sp, value: "https://sp.example/slo" },
    "removed the single logout service");
  assert.ok(JSON.stringify(await serviceProvider(sp))
      .indexOf("https://sp.example/slo") < 0,
    "and the logout service should be gone from the entry afterwards. A " +
    "SAML 2.0 SP that is still listed as having a SingleLogoutService it no " +
    "longer wants is sent a LogoutRequest it will refuse, which is a " +
    "failure a person meets in a browser rather than here.");

  // The certificate operation is the one on this resource whose documented
  // field name is easiest to get wrong, and getting it wrong is SILENT: the
  // handler reads `value`, and a body naming the field anything else answers
  // 200 with `changed: false` and stores nothing. So the assertion is on the
  // ENTRY, and it is deliberately made through the documented name.
  const certificate = "MIIBtest" + "A".repeat(40);
  const set = await ok("/saml2/set-signing-certificate",
    { sp: sp, value: certificate }, "recorded a signing certificate");
  assert.strictEqual(set.changed, true,
    "`set-signing-certificate` should report that it CHANGED something. This " +
    "handler answers 200 with `changed: false` when the body named a field " +
    "it does not read — which is what a caller following a stale document " +
    "gets, silently, for ever — so the reply's own account of itself is the " +
    "assertion worth making here.");
  assert.ok(JSON.stringify(await serviceProvider(sp)).indexOf(certificate) > 0,
    "and the certificate should be on the entry afterwards.");

  const rp = "urn:test:" + REALM + ":rp";
  // `target` was here and `saml11Action()` never read it — the third ignored
  // member this file was sending, found the same way as `acs` and `binding`.
  await ok("/saml11/register", { rp: rp },
    "registered a SAML 1.1 relying party");
  const parties = (await get("/saml11")).body.relyingParties || [];
  assert.ok(parties.some(function (row) {
    return row.identifier === rp || row.rp === rp || row.entityId === rp;
  }), "the SAML 1.1 relying party should be in GET /saml11's list; it holds " +
      JSON.stringify(parties.map(function (r) {
        return r.identifier || r.rp || r.entityId;
      })));
  log.info("[saml] OK — SAML 2.0's four actions and SAML 1.1's one " +
           "round-tripped, and the metadata URL carries this realm and the " +
           "entityID's slug.");
  log.debug("Leaving theSamlRegistriesRoundTrip().");
}

async function serviceProvider(sp) {
  log.debug("Entering serviceProvider(). sp=" + sp);
  const reply = await get("/saml2?sp=" + encodeURIComponent(sp));
  assert.strictEqual(reply.status, 200,
    "GET /saml2?sp=… should answer 200; it answered " + reply.status);
  log.debug("Leaving serviceProvider(). found=" + reply.body.found);
  return reply.body;
}

// ---------------------------------------------------------------------------
// THE AUTHORIZATION SERVER PROFILES: five actions, and the one property that
// distinguishes `remove` from `reset` — which is the pair most likely to be
// collapsed into one by somebody tidying.
// ---------------------------------------------------------------------------
async function theAuthorizationServerProfilesRoundTrip() {
  log.debug("Entering theAuthorizationServerProfilesRoundTrip().");
  log.info("=== Authorization servers: create, set, remove, reset, delete ===");
  const index = await get("/authorization-servers");
  const members = (index.body.members || []).map(function (m) {
    return typeof m === "string" ? m : m.name;
  }).filter(Boolean);
  assert.ok(members.length,
    "GET /authorization-servers should publish the metadata members a " +
    "profile can override; it published none.");
  const member = members.filter(function (name) {
    return name === "code_challenge_methods_supported";
  })[0] || members[0];

  const id = "as-" + names.usernameFor("stsapi-as").toLowerCase()
      .replace(/[^a-z0-9-]/g, "");
  // `name` was here and `asAction()` reads `label` — so the profile's label was
  // never actually being set by this job and nothing noticed. Corrected to the
  // real field rather than dropped, because exercising it is the point.
  await ok("/authorization-servers/create", { id: id, label: "Test profile" },
    "created an authorization server profile");
  assert.ok(await profile(id),
            "the profile should be in the list after create.");

  await ok("/authorization-servers/set",
    { id: id, member: member, value: "S256" },
    "set a metadata member");
  assert.ok(JSON.stringify((await profile(id)).overrides || {})
                .indexOf("S256") > 0,
    "`set` should put the value in the profile's overrides; they are " +
    JSON.stringify((await profile(id)).overrides));

  // The distinction worth pinning: `remove` takes the member OUT of the
  // published document — an authorization server that says nothing about PKCE
  // is a different claim from one that says the default — and `reset` puts the
  // service's own value back. A tidy-up that made them one call would leave no
  // way to express the first, and both would still answer 200.
  await ok("/authorization-servers/remove", { id: id, member: member },
    "removed a metadata member");
  const removed = await profile(id);
  assert.ok((removed.removed || []).indexOf(member) >= 0,
    "`remove` should record the member as REMOVED rather than merely " +
    "unset — an authorization server whose metadata omits " + member + " is " +
    "making a different statement from one that carries the default, and " +
    "this profile's `removed` list is where that difference lives. It holds " +
    JSON.stringify(removed.removed));

  await ok("/authorization-servers/reset", { id: id, member: member },
    "reset a metadata member");
  const reset = await profile(id);
  assert.ok((reset.removed || []).indexOf(member) < 0 &&
            !Object.prototype.hasOwnProperty.call(reset.overrides || {},
                                                  member),
    "`reset` should undo both — neither overridden nor removed. It reads " +
    JSON.stringify({ overrides: reset.overrides, removed: reset.removed }));

  await ok("/authorization-servers/delete", { id: id }, "deleted the profile");
  assert.ok(!(await profile(id)),
    "after `delete` the profile must be gone from the list.");
  log.info("[authorization servers] OK — five actions round-tripped, and " +
           "`remove` and `reset` are two different things.");
  log.debug("Leaving theAuthorizationServerProfilesRoundTrip().");
}

async function profile(id) {
  log.debug("Entering profile(). id=" + id);
  const reply = await get("/authorization-servers");
  const one = (reply.body.authorizationServers || []).filter(function (row) {
    return row && row.id === id;
  })[0];
  log.debug("Leaving profile(). " + (one ? "found" : "absent"));
  return one;
}

// ---------------------------------------------------------------------------
// THE TWO VERIFIABLE-CREDENTIAL RESOURCES. Five actions each, over two
// different KINDS of list: /credential-claims selects from a catalogue and
// refuses anything outside it, and /verifier-request deliberately does NOT —
// asking for a claim no credential here carries is the whole point of a
// verifier, because what it tests is what the wallet does with a request it
// cannot satisfy. Two resources that look alike and disagree on their central
// rule is exactly the pair worth driving.
// ---------------------------------------------------------------------------
async function theCredentialResourcesRoundTrip() {
  log.debug("Entering theCredentialResourcesRoundTrip().");
  log.info("=== Credential claims and the verifier request: five actions " +
           "each ===");

  const claims = await get("/credential-claims");
  const catalogue = (claims.body.attributes || []).map(function (row) {
    return typeof row === "string" ? row : (row.ldap || row.name);
  }).filter(Boolean);
  assert.ok(catalogue.length > 1,
    "GET /credential-claims should publish the catalogue it selects from.");
  const before = (claims.body.selected || []).slice();

  await ok("/credential-claims/select", { attributes: [catalogue[0]] },
    "selected one credential claim");
  assert.deepStrictEqual((await get("/credential-claims")).body.selected,
    [catalogue[0]], "`select` should replace the whole selection.");

  await ok("/credential-claims/add", { name: catalogue[1] },
    "added a credential claim");
  assert.ok((await get("/credential-claims")).body.selected.indexOf(
      catalogue[1]) >= 0,
    "`add` should put it in.");
  await ok("/credential-claims/remove", { name: catalogue[1] },
    "removed a credential claim");
  assert.ok((await get("/credential-claims")).body.selected.indexOf(
      catalogue[1]) < 0,
    "`remove` should take it out.");

  await refused("/credential-claims/add", { name: "no_such_attribute_at_all" },
    /catalogue/i,
    "a claim outside the catalogue — THIS resource is the one that refuses " +
    "one, and /verifier-request next door is the one that must not");

  await ok("/credential-claims/defaults", {}, "restored the defaults");
  assert.deepStrictEqual((await get("/credential-claims")).body.selected,
    (await get("/credential-claims")).body.defaults,
    "`defaults` should put the selection back to the published defaults.");

  // `populate` writes the selected attributes onto directory entries so that a
  // credential issued for somebody has something to carry. It is the one
  // action here that touches the directory, which is why it is done inside the
  // throwaway realm and asserted against that realm's own count.
  const populated = await ok("/credential-claims/populate", {},
    "populated the directory");
  assert.ok(populated.message || populated.updated !== undefined,
    "`populate` should say what it wrote; it answered " +
    JSON.stringify(populated).slice(0, 200));
  // Read back through the resource's own GET, and the assertion is the one
  // that says the sweep and the selection are ONE list: `populate` writes the
  // attributes this page has selected, so a sweep that carried some other
  // list would be writing attributes nobody asked for onto every entry in the
  // realm — and it would answer 200 and report a count either way.
  const sweep = populated.sweep || {};
  assert.deepStrictEqual((sweep.attributes || []).slice().sort(),
    ((await get("/credential-claims")).body.selected || []).slice().sort(),
    "`populate` should sweep exactly the attributes GET /credential-claims " +
    "says are selected. It swept " + JSON.stringify(sweep.attributes));
  assert.ok(Number(sweep.examined) > 0,
    "and it should have examined at least one directory entry — this realm " +
    "has people in it by now, and a sweep that examined none is one that " +
    "found the wrong subtree. It examined " + sweep.examined);

  const request = await get("/verifier-request");
  const formats = (request.body.formats || []).map(function (f) {
    return typeof f === "string" ? f : f.id;
  }).filter(Boolean);
  assert.ok(formats.length > 1,
    "GET /verifier-request should publish the formats `format` chooses " +
    "between.");
  const startingFormat = request.body.format;

  await ok("/verifier-request/select", { claims: ["given_name"] },
    "selected one requested claim");
  assert.deepStrictEqual((await get("/verifier-request")).body.requested,
    ["given_name"],
    "`select` should REPLACE the whole request rather than add to it — it is " +
    "what a form's save posts, so a partial application leaves a verifier " +
    "asking for claims nobody ticked.");
  await ok("/verifier-request/add",
    { name: "not_a_claim_anything_here_issues" },
    "ASKED FOR A CLAIM NOTHING HERE ISSUES, which this resource must ALLOW. " +
    "A verifier that could only ask for claims the issuer beside it happens " +
    "to mint could never test what a wallet does with a request it cannot " +
    "satisfy, which is most of what a verifier is for");
  assert.ok((await get("/verifier-request")).body.requested
      .indexOf("not_a_claim_anything_here_issues") >= 0,
    "and the unsatisfiable claim should really be in the request.");
  await ok("/verifier-request/remove",
    { name: "not_a_claim_anything_here_issues" },
    "removed it again");
  assert.ok((await get("/verifier-request")).body.requested
      .indexOf("not_a_claim_anything_here_issues") < 0,
    "and it should really be out of the request afterwards: this resource " +
    "accepts a claim nothing here issues, so nothing else would ever fail if " +
    "`remove` quietly kept it.");

  const other =
      formats.filter(function (f) { return f !== startingFormat; })[0];
  await ok("/verifier-request/format", { format: other }, "changed the format");
  assert.strictEqual((await get("/verifier-request")).body.format, other,
    "`format` should change which credential format the request asks for.");
  const restored = await ok("/verifier-request/defaults", {},
    "restored the request defaults");
  const request2 = (await get("/verifier-request")).body;
  assert.deepStrictEqual(request2.requested, request2.defaults,
    "`defaults` should put the request back to what this process started " +
    "with — which the resource publishes as `defaults`, so the assertion is " +
    "against the service's own statement of them rather than against a copy " +
    "here. It answered " + JSON.stringify(restored.requested) + " and the " +
    "resource now reads " + JSON.stringify(request2.requested));
  // The FORMAT is deliberately not part of `defaults` — that action resets the
  // claims and says so — so it is put back by hand, for the reason every
  // section here restores what it changed: the verifier's configuration is
  // this realm's, and this realm is thrown away, but a reader who found the
  // format changed at the end of this section would reasonably think
  // `defaults` had failed to restore it.
  await ok("/verifier-request/format", { format: startingFormat },
    "put the format back");
  assert.strictEqual((await get("/verifier-request")).body.format,
    startingFormat,
    "and the format should be back where this section found it.");

  log.info("[credentials] OK — both resources' five actions round-tripped, " +
           "and the one that refuses an unknown claim and the one that must " +
           "not both behaved as they say.");
  log.debug("Leaving theCredentialResourcesRoundTrip(). before=" +
            before.length + " claim(s) were selected when it started.");
}

// ---------------------------------------------------------------------------
// SPIFFE: the registry's three actions, the agents' three, and the one that is
// process-wide.
//
// The registration entries and the agents are directory entries under this
// realm's ou=spiffe, so they are thrown away with the realm. `rotate` is not:
// there is ONE signing authority for the process, because a socket has no path
// to put a realm segment in. It is exercised once, here, and it is why this job
// is EXCLUSIVE in run-report.js — a SPIFFE job holding a stream open across a
// rotation would see its SVID stop verifying with nothing to say why.
// ---------------------------------------------------------------------------
async function theSpiffeDoorsRoundTrip() {
  log.debug("Entering theSpiffeDoorsRoundTrip().");
  log.info("=== SPIFFE: entries, agents, and the authority ===");
  const before = await get("/spiffe");
  assert.strictEqual(before.status, 200, "GET /spiffe should answer 200.");
  const trustDomain = before.body.trustDomain;
  assert.ok(trustDomain, "GET /spiffe should name the trust domain it issues " +
                         "for.");
  const sequenceBefore = Number((before.body.bundle || {}).sequence || 0);

  const spiffeId = "spiffe://" + trustDomain + "/test/" +
      names.usernameFor("stsapi-spiffe")
           .toLowerCase()
           .replace(/[^a-z0-9-]/g, "");
  const created = await ok("/spiffe/entries/create", {
    spiffeId: spiffeId,
    parentId: "spiffe://" + trustDomain + "/spire/agent/test",
    // A COMMA-SEPARATED STRING, which is what the operation's schema declares
    // and what `spiffeCommaList()` documents. It was `["unix:uid:1000"]` and
    // worked only by accident: that function does `String(value)`, and an
    // array stringifies to its comma-joined members — so a one-element array
    // happens to produce the right answer and a selector containing a comma
    // would not. The test now sends what a caller reading the document sends.
    selectors: "unix:uid:1000"
  }, "created a registration entry");
  assert.ok(created.id, "the create should answer with the entry's id.");
  const entryId = created.id;
  assert.ok(String(created.entry.dn).indexOf("dc=" + REALM + ",") > 0,
    "and the entry should be in THIS realm's subtree; its DN is " +
    created.entry.dn);

  // `update` changes ONE field at a time, named — which is why it takes
  // `field` and `value` rather than a whole entry: the entry also carries what
  // HAPPENED (when it was created, how many SVIDs it has issued), and a
  // whole-entry PUT would give a caller a way to rewrite that.
  await ok("/spiffe/entries/update",
    { entry: entryId, field: "hint", value: "changed-by-the-test" },
    "updated one field of the registration entry");
  const updated = (await get("/spiffe/entries")).body.entries.filter(
      function (row) {
    return row.id === entryId;
  })[0];
  assert.ok(updated && String(updated.hint) === "changed-by-the-test",
    "`update` should change the field it was given; the entry holds hint=" +
    JSON.stringify(updated && updated.hint));

  // And a field that describes what HAPPENED is refused BY NAME rather than
  // written. That is the same rule the applications registry keeps for its
  // derived attributes, and here it protects the count of SVIDs an identity
  // has been issued — which is evidence rather than configuration.
  await refused("/spiffe/entries/update",
    { entry: entryId, field: "x509svidsIssued", value: "0" },
    /is not a field this page may change/,
    "rewriting what HAPPENED rather than what the entry may DO");

  await ok("/spiffe/entries/delete", { entry: entryId },
    "deleted the registration entry");
  assert.ok(!(await get("/spiffe/entries")).body.entries.some(function (row) {
    return row.id === entryId;
  }), "after `delete` the entry must be gone.");

  // The three agent actions need an agent, and this realm has none: an agent
  // exists because one ATTESTED, and nothing in this file speaks the Workload
  // API. So what is asserted is the refusal, which is the half a test can
  // reach — and it must name the AGENT rather than the field, because a body
  // carrying `agent` and getting "which agent?" would mean the document and
  // the handler disagree about the name.
  const noAgent = "spiffe://" + trustDomain +
                  "/spire/agent/nothing-attested-here";
  for (const action of ["ban", "unban", "delete"]) {
    await refused("/spiffe/agents/" + action, { agent: noAgent },
      /No agent has the id/i,
      "acting on an agent that has never attested (" + action + ")");
  }
  assert.strictEqual((await get("/spiffe/agents")).body.total, 0,
    "and no agent should have appeared in this realm as a side effect.");

  // A federated bundle is a foreign trust domain's, and it is per realm.
  await ok("/spiffe/federation-set",
    { trustDomain: "other.example",
      bundleEndpointUrl: "https://other.example/bundle",
      bundleEndpointProfile: "https_web",
      document: { keys: [], spiffe_sequence: 1, spiffe_refresh_hint: 300 } },
    "recorded a federated bundle");
  assert.ok(JSON.stringify((await get("/spiffe")).body)
                .indexOf("other.example") > 0,
    "the federated trust domain should be readable back off GET /spiffe.");
  await ok("/spiffe/federation-remove", { trustDomain: "other.example" },
    "removed the federated bundle");
  assert.ok(JSON.stringify((await get("/spiffe")).body)
                .indexOf("other.example") < 0,
    "and the federated trust domain should be gone from GET /spiffe. A " +
    "bundle left behind is a foreign trust domain this authority goes on " +
    "publishing, which is the one thing in this pair that has a consequence " +
    "outside the console.");

  // Last, and once: rotating replaces the signing authority for the whole
  // process. The bundle's sequence number is what says it really happened —
  // a rotation that answered 200 and changed nothing would leave every
  // previously issued SVID verifying, which is the opposite of what was asked.
  const rotated = await ok("/spiffe/rotate", {},
                           "rotated the signing authority");
  assert.ok(rotated.ok !== false, "the rotation should report success.");
  const after = await get("/spiffe");
  assert.ok(Number((after.body.bundle || {}).sequence || 0) > sequenceBefore,
    "ROTATING MUST ADVANCE THE BUNDLE'S SEQUENCE. It was " + sequenceBefore +
    " and it is " + (after.body.bundle || {}).sequence + ". The sequence is " +
    "how a relying party knows the bundle it holds is stale, so a rotation " +
    "that left it alone would publish new keys nobody fetched.");
  log.info("[spiffe] OK — the registry's three actions and the two bundle " +
           "actions round-tripped, the three agent actions refuse by " +
           "referent, and a rotation advanced the bundle sequence from " +
           sequenceBefore + " to " + (after.body.bundle || {}).sequence + ".");
  log.debug("Leaving theSpiffeDoorsRoundTrip().");
}

// ---------------------------------------------------------------------------
// THE TOKEN DOORS. Eight actions — the two that act on a whole ISSUANCE are
// driven by theIssuedListGroupsByIssuance() below, beside the grouping they
// exist for — and the only ones on this API whose effect can
// be confirmed by a PROTOCOL endpoint rather than by another view of the same
// store — which is what makes them worth driving properly: the API's whole
// claim is that it is not a second implementation.
//
// tests/admin_api.js already proves that ONE revocation reaches
// /oauth2/introspect. What is left, and is here, is the other five: `restore`,
// which RFC 7009 defines no opposite for and which exists so that a test does
// not have to restart the service; and the four BULK revocations, each of which
// selects a different way and any of which could be selecting everything.
// ---------------------------------------------------------------------------
async function theTokenDoorsRoundTrip() {
  log.debug("Entering theTokenDoorsRoundTrip().");
  log.info("=== Tokens: revoke, restore, and the four bulk revocations ===");
  // Two identities, and they must be two NAMES rather than one name with a
  // suffix: random_username.js stamps once per PROCESS, so `usernameFor("x")`
  // called twice is the same person — which is right (a test file is one
  // actor) and is exactly wrong for the assertion below, where the whole
  // point is that revoking one person's tokens leaves somebody else's alone.
  const user = names.usernameFor("stsapi-tokens");
  const other = names.usernameFor("stsapi-tokens-other");
  const client = "token-client-" + REALM;

  const mine = await mintTokens(user, client);
  const theirs = await mintTokens(other, client);
  assert.ok(mine.access && theirs.access,
    "the realm's token endpoint should mint a token for any username; it is " +
    "the same permissive endpoint every other job in this suite uses.");

  // One token, revoked and restored, confirmed at the protocol endpoint.
  assert.strictEqual(await introspectActive(mine.access), true,
    "a freshly minted access token should introspect as active.");
  await ok("/tokens/revoke", { jti: mine.jti }, "revoked one token by jti");
  assert.strictEqual(await introspectActive(mine.access), false,
    "REVOKING THROUGH THIS API MUST REACH RFC 7662 INTROSPECTION. There is " +
    "one revocation set in admin_stats.js serving both this door and " +
    "/oauth2/revoke; a second set would look correct from either side and " +
    "never see the other.");
  await ok("/tokens/restore", { jti: mine.jti }, "restored one token by jti");
  assert.strictEqual(await introspectActive(mine.access), true,
    "AND `restore` MUST REACH IT TOO. RFC 7009 defines no un-revoke and this " +
    "operation says so in its own summary; it exists because restarting the " +
    "service to get back to a working credential turns a two-second test " +
    "into a two-minute one. An un-revoke that only cleared the console's " +
    "list would leave the token dead at the endpoint that matters.");

  // revoke-user selects by username, and the assertion that matters is the
  // NEGATIVE one: somebody else's token must still be alive. A bulk operation
  // that revoked everything would pass every check but this.
  await ok("/tokens/revoke-user", { user: user },
           "revoked one person's tokens");
  assert.strictEqual(await introspectActive(mine.access), false,
    "`revoke-user` should kill that person's token.");
  assert.strictEqual(await introspectActive(theirs.access), true,
    "AND IT MUST LEAVE EVERYBODY ELSE'S ALONE. This is the assertion the " +
    "four bulk operations exist to be checked by: each of them selects a " +
    "different way, and a selector that quietly matched everything would " +
    "satisfy every other check in this file.");

  // revoke-kind and revoke-subject select differently again. Both are checked
  // the same way and then everything is put back, one jti at a time, because
  // `revoke-all` has no opposite.
  const restoreThese = [mine.jti, mine.idJti, theirs.jti, theirs.idJti]
      .filter(Boolean);
  await ok("/tokens/revoke-kind", { kind: "id_token" },
    "revoked every ID Token");
  assert.strictEqual(await introspectActive(theirs.access), true,
    "`revoke-kind` on id_token must not touch an ACCESS token.");
  await ok("/tokens/revoke-subject", { subject: subjectOf(theirs) },
    "revoked one subject's tokens");
  assert.strictEqual(await introspectActive(theirs.access), false,
    "`revoke-subject` should kill the token whose `sub` it named.");

  await ok("/tokens/revoke-all", {}, "revoked everything in this realm");
  const listed = await get("/tokens");
  assert.ok(listed.body.revokedCount >= restoreThese.length,
    "`revoke-all` should leave everything this realm holds revoked; the " +
    "page reports " + listed.body.revokedCount + " revoked out of " +
    listed.body.held + " held.");

  for (const jti of restoreThese) {
    await ok("/tokens/restore", { jti: jti },
      "restored " + jti + " after the bulk revocations");
  }
  const afterRestores = await get("/tokens");
  assert.ok(afterRestores.body.revokedCount < listed.body.revokedCount,
    "the resource's own listing should show the restores too, not just the " +
    "protocol endpoint: it read " + listed.body.revokedCount + " revoked " +
    "after `revoke-all` and " + afterRestores.body.revokedCount + " after " +
    restoreThese.length + " restores. The two views are one revocation set " +
    "and this is where they are asked to agree.");
  assert.strictEqual(await introspectActive(mine.access), true,
    "and restoring one jti at a time should bring them back — which is the " +
    "only way back from `revoke-all`, and the reason `restore` exists.");
  log.info("[tokens] OK — six of the eight actions, each confirmed at " +
           "/oauth2/introspect " +
           "rather than in the console's own list, and each bulk revocation " +
           "shown to leave something alone.");
  log.debug("Leaving theTokenDoorsRoundTrip().");
}

// ---------------------------------------------------------------------------
// THE LIST IS GROUPED BY ISSUANCE, AND THE TWO SET DOORS ACT ON A WHOLE REPLY.
//
// Since 2026-09-05 an entry in `GET /admin-api/tokens` is one REPLY rather than
// one credential: OAuth 2.0 and OIDC are the only families this service speaks
// that hand back several at once, and a table that drew three rows for one
// token response left the reader to reassemble it by comparing timestamps.
//
// FOUR THINGS ARE ASSERTED HERE AND EACH WOULD BE INVISIBLE TO THE OTHERS.
//
//   * That a token response really does arrive as ONE entry holding three,
//     rather than as three entries that happen to agree.
//   * That `issued` is still the flatten of `sets`. A caller written against
//     the older per-credential shape has to go on reading what it read, and
//     the flatten is what makes that true without a second walk of the
//     register — so a set whose members were missing from `issued` would be a
//     silent breaking change for every such caller.
//   * That `revoke-set` reaches RFC 7662 introspection for EVERY member. This
//     is the assertion the feature exists for: revoking two credentials of
//     three and believing the grant is dead leaves a refresh token that mints
//     another, which is precisely the mistake one row per reply prevents.
//   * That a set holding nothing revocable is REFUSED. Nothing consults this
//     service about a SAML assertion or a Kerberos ticket, so a 200 saying
//     "revoked 0" would be a claim about the world that is not true — the same
//     answer `revoke-kind` already gives for an unrevocable kind.
// ---------------------------------------------------------------------------
async function theIssuedListGroupsByIssuance() {
  log.debug("Entering theIssuedListGroupsByIssuance().");
  log.info("=== Tokens: one entry per issuance, and the two set doors ===");

  const user = names.usernameFor("stsapi-sets");
  const client = "set-client-" + REALM;
  const minted = await mintTokens(user, client);
  assert.ok(minted.access && minted.id,
    "this check needs a reply carrying more than one credential, which is " +
    "what `scope=openid` on the password grant produces: an access token, a " +
    "refresh token and an ID Token.");

  const listed = await get("/tokens?per=200");
  assert.ok(Array.isArray(listed.body.sets),
    "GET /tokens should carry `sets`; it carried " +
    Object.keys(listed.body).join(", "));

  // The set holding the access token just minted. Found by the jti rather than
  // by position: this realm is shared with the section above and the list is
  // newest-first, so "the first entry" is whatever ran last.
  const mySet = listed.body.sets.filter(function (set) {
    return set.members.some(function (m) { return m.jti === minted.jti; });
  })[0];
  assert.ok(mySet,
    "the access token just minted should be in one of the sets; " +
    listed.body.sets.length + " set(s) came back and none held jti " +
    minted.jti + ".");
  assert.strictEqual(mySet.grouped, true,
    "A TOKEN RESPONSE IS ONE ENTRY. It carried an access token, a refresh " +
    "token and an ID Token, so the entry must say it is a group rather than " +
    "arriving as three entries that happen to agree on every field — which " +
    "is exactly what two people redeeming two codes at the same client in " +
    "the same millisecond would also look like.");
  assert.ok(mySet.members.length >= 2,
    "and hold every credential of that reply; it holds " +
    mySet.members.length + " (" + mySet.kinds.join(", ") + ").");
  assert.ok(mySet.members.some(function (m) { return m.jti === minted.idJti; }),
    "INCLUDING THE ID TOKEN, which is the member that makes this a grouping " +
    "rather than a rename: it was issued by the same call and is the one a " +
    "reader most often wants beside the access token.");
  assert.ok(mySet.setId,
    "the entry should carry the issuer's own set id, which is what says the " +
    "grouping was STATED rather than guessed from these fields.");
  assert.ok(mySet.members.every(function (m) {
    return m.setId === mySet.setId;
  }),
    "and every member should carry the same one.");

  // The flatten. Every member of every set on this page has to be in `issued`,
  // or a caller written against the older shape is quietly reading less.
  const flatJtis = {};
  (listed.body.issued ||
   []).forEach(function (row) { flatJtis[row.jti] = true; });
  const missingFromFlat = [];
  listed.body.sets.forEach(function (set) {
    set.members.forEach(function (m) {
      if (m.jti && !flatJtis[m.jti]) {
        missingFromFlat.push(m.jti);
      }
    });
  });
  assert.deepStrictEqual(missingFromFlat, [],
    "`issued` MUST BE THE FLATTEN OF `sets`. It is what every caller written " +
    "against the per-credential shape reads, and it is derived from that " +
    "array rather than gathered again precisely so the two cannot disagree. " +
    "These were in a set and not in the flatten: " +
    missingFromFlat.join(", "));

  // A filter matches a set when ANY member matches, and the neighbours come
  // with it. That is the one behaviour of this resource a caller would
  // otherwise read as the filter being ignored.
  const byKind = await get("/tokens?kind=id_token&per=200");
  const found = byKind.body.sets.filter(function (set) {
    return set.setKey === mySet.setKey;
  })[0];
  assert.ok(found,
    "?kind=id_token should find the set CONTAINING an ID Token.");
  assert.ok(found.members.some(function (m) {
    return m.kind === "access_token";
  }),
    "AND BRING ITS NEIGHBOURS WITH IT. The access token that came back in " +
    "the same reply is part of that reply; a filter that returned the ID " +
    "Token alone would be the old per-credential list wearing this one's " +
    "name.");

  // The set door, confirmed where it counts.
  assert.strictEqual(await introspectActive(minted.access), true,
    "the access token should be active before the set is revoked.");
  const revoked = await ok("/tokens/revoke-set", { set: mySet.setKey },
    "revoked one whole issuance");
  assert.ok(revoked.revoked >= 2,
    "`revoke-set` should report revoking every revocable member; it " +
    "reported " + JSON.stringify(revoked.revoked) + " of " +
    JSON.stringify(revoked.revocable) + ".");
  assert.strictEqual(await introspectActive(minted.access), false,
    "REVOKING A SET MUST REACH RFC 7662 INTROSPECTION, member by member. It " +
    "writes into the same revocation set /oauth2/revoke does — one act per " +
    "credential rather than a new mechanism — so a set door that only " +
    "changed a number in the console would leave every one of these tokens " +
    "alive at the endpoint that matters.");

  const opened = await get("/tokens/set?id=" +
                           encodeURIComponent(mySet.setKey));
  assert.strictEqual(opened.body.found, true,
    "GET /tokens/set should open the set by the key the list gave it.");
  assert.strictEqual(opened.body.set.state, "revoked",
    "and every member being revoked should make the SET revoked rather than " +
    "mixed; it reads " + opened.body.set.state + " with " +
    JSON.stringify(opened.body.set.states) + ".");

  await ok("/tokens/restore-set", { set: mySet.setKey },
    "restored the whole issuance");
  assert.strictEqual(await introspectActive(minted.access), true,
    "and `restore-set` should reach the protocol endpoint too — NON-SPEC, " +
    "for the reason `restore` is, and useless if it only cleared the list.");

  // A key nothing holds is the ORDINARY end of a set's life, so it is a 200
  // saying so rather than a 404.
  const absent = await get("/tokens/set?id=set:no-such-issuance");
  assert.strictEqual(absent.status, 200,
    "a key nothing holds should answer 200: a set forgotten to the " +
    "registry's cap is the ordinary end of its life, not a caller's mistake.");
  assert.strictEqual(absent.body.found, false, "with `found: false`");
  assert.ok(absent.body.why, "and a sentence saying which of the two it was.");

  // AN ASSERTION IS DISOWNED, NOT RECALLED, and this is where that pair is
  // driven end to end. A WS-Trust RST issues one into this realm; it is the
  // archetype of a credential this service cannot take back, and since
  // 2026-09-05 it is also one this service will record a POSITION on.
  await mintAssertion(user);
  const everything = await get("/tokens?per=200");
  const assertionSet = everything.body.sets.filter(function (set) {
    return set.members.some(function (m) {
      return m.revocationReach === "record-only";
    });
  })[0];
  assert.ok(assertionSet,
    "the WS-Trust RST above should have put an assertion in the issued " +
    "register, and every assertion carries `revocationReach: record-only`. " +
    "The sets held are: " + everything.body.sets.map(function (set) {
      return set.kinds.join("+");
    }).join(", "));

  const disowned = await ok("/tokens/revoke-set", { set: assertionSet.setKey },
    "disowned an assertion");
  assert.ok(disowned.recordOnly >= 1,
    "REVOKING A SET MUST REPORT HOW MUCH OF IT ANYBODY OUTSIDE WILL NOTICE. " +
    "It marked " + JSON.stringify(disowned.revoked) + " credential(s) and " +
    "reported `recordOnly: " + JSON.stringify(disowned.recordOnly) + "`. A " +
    "caller is entitled to know that what it just revoked goes on working, " +
    "and one count folding both kinds together would have hidden it.");
  assert.strictEqual(disowned.reachedProtocol, 0,
    "and nothing in an assertion-only set reaches a protocol; it reported " +
    JSON.stringify(disowned.reachedProtocol) + ".");
  assert.ok(/HOLDER|record|not been told|goes on working/i.test(
      String(disowned.message || "")),
    "AND THE MESSAGE MUST SAY THE HOLDER WAS NOT TOLD. This is the one " +
    "operation on this API whose success means less than success normally " +
    "means, so the sentence carrying that is part of the contract rather " +
    "than decoration. It said: " + JSON.stringify(disowned.message));

  const reopened = await get("/tokens/set?id=" +
                             encodeURIComponent(assertionSet.setKey));
  assert.strictEqual(reopened.body.set.state, "revoked",
    "and the register should now report the assertion revoked; it reads " +
    reopened.body.set.state + ".");
  await ok("/tokens/restore-set", { set: assertionSet.setKey },
    "stopped disowning it");

  // The single-credential door, which is what the tokens table draws on the
  // row.
  const one = assertionSet.members[0];
  const marked = await ok("/tokens/revoke-artifact", { artifact: one.key },
    "disowned one credential by its row handle");
  assert.strictEqual(marked.revocationReach, "record-only",
    "`revoke-artifact` must report that its reach is the record and nothing " +
    "further; it said " + JSON.stringify(marked.revocationReach) + ".");
  await ok("/tokens/restore-artifact", { artifact: one.key },
    "and stopped disowning it again");
  // READ IT BACK, which the ledger at the end of this run requires of every
  // write and which is worth doing here on its own account: a restore that
  // answered `{ok: true}` and left the credential disowned would satisfy every
  // assertion above, all of which read the REPLY.
  // `GET /tokens` and not `GET /tokens/set`: the ledger matches a write against
  // a read of THE RESOURCE THE WRITE LANDED ON, and these actions live under
  // /tokens. The drill-down is a different resource however well it answers the
  // same question, so it is read too — for what it says — but the list is what
  // discharges the obligation.
  const listedAgain = await get("/tokens?per=200");
  const restoredSet = (listedAgain.body.sets || []).filter(function (set) {
    return set.setKey === assertionSet.setKey;
  })[0];
  assert.ok(restoredSet && restoredSet.state === "valid",
    "after both restores the assertion should be valid again in this " +
    "service's record; it reads " +
    (restoredSet ? restoredSet.state : "(the set is gone)") + ".");

  log.info("[sets] OK — a token response arrives as ONE entry holding " +
           mySet.members.length + ", `issued` is still its flatten, a kind " +
           "filter brings the neighbours, and revoke-set/restore-set both " +
           "reach /oauth2/introspect.");
  log.debug("Leaving theIssuedListGroupsByIssuance().");
}

// A token set for one person, out of THIS REALM'S token endpoint. The password
// grant is used because this service checks no password anywhere and it needs
// no browser — which is the same reason every other node-only job in this
// suite reaches for it.
// ---------------------------------------------------------------------------
// THE PERSON AND THE CLIENT A TOKEN IS MINTED FOR, CREATED FIRST (2026-09-12).
//
// This used to name a person nobody had created and a client nobody had
// registered, with the username as the password — and it worked because
// development mode creates both on sight, invents a persona for the person,
// and checks neither the password nor a client secret. Product mode does none
// of that. So each party is created through this API before the grant names
// it: the person with the attributes a real account carries, `invent: false`
// and a password of at least twelve characters; the client with its identifier,
// a secret and the method that presents it. Both creates are READ BACK through
// the resource's own GET straight away, which is this file's rule for every
// accepted write and what keeps the ledger's pairing check true for them.
// `root` names the default realm's scope, for the one token minted there.
// ---------------------------------------------------------------------------
const MINT_PASSWORD = "admin-api-operations-Passw0rd!-" + REALM;
const MINT_CLIENT_SECRET = "admin-api-operations-client-secret-" + REALM;
const mintedParties = {};

async function ensureTokenParties(username, client, root) {
  log.debug("Entering ensureTokenParties(). username=" + username +
            ", client=" + client);
  const scope = root ? "root:" : "realm:";
  if (!mintedParties[scope + "user:" + username]) {
    await ok("/users/create", {
      username: username, invent: false,
      attributes: { cn: "Operations " + username, givenName: "Operations",
                    sn: username, displayName: "Operations " + username,
                    mail: username + "@admin-api-operations.test" },
      credential: "password", password: MINT_PASSWORD
    }, "created " + username + " before a token is minted for them", root);
    const back = await get("/users?user=" + encodeURIComponent(username), root);
    assert.strictEqual(back.status, 200,
      "GET /users?user=" + username + " should read the person just created; " +
      "it answered " + back.status);
    mintedParties[scope + "user:" + username] = true;
  }
  if (!mintedParties[scope + "client:" + client]) {
    await ok("/applications/create", {
      identifier: client, name: client, protocols: ["oauth2", "oidc"],
      fields: { oauthClientId: [client], oauthClientSecret: MINT_CLIENT_SECRET,
                oauthTokenEndpointAuthMethod: "client_secret_post",
                oauthGrantType: ["password", "client_credentials",
                                 "refresh_token"] }
    }, "registered " + client + " before it asks for a token", root);
    const back = await get("/applications?application=" +
                           encodeURIComponent(client), root);
    assert.strictEqual(back.status, 200,
      "GET /applications?application=" + client + " should read the client " +
      "just registered; it answered " + back.status);
    mintedParties[scope + "client:" + client] = true;
  }
  log.debug("Leaving ensureTokenParties().");
}

async function mintTokens(username, client) {
  log.debug("Entering mintTokens(). username=" + username);
  await ensureTokenParties(username, client, false);
  const body = "grant_type=password&username=" + encodeURIComponent(username) +
      "&password=" + encodeURIComponent(MINT_PASSWORD) +
      "&client_id=" + encodeURIComponent(client) +
      "&client_secret=" + encodeURIComponent(MINT_CLIENT_SECRET) +
      "&scope=openid";
  const reply = await common.httpJson(base + "/realm/" + REALM +
                                      "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body
  });
  assert.strictEqual(reply.status, 200,
    "the realm's token endpoint should mint a token for " + username +
    "; it answered " + reply.status + " " + String(reply.raw).slice(0, 200));
  const out = {
    access: reply.body.access_token,
    id: reply.body.id_token,
    jti: claimOf(reply.body.access_token, "jti"),
    idJti: claimOf(reply.body.id_token, "jti"),
    sub: claimOf(reply.body.access_token, "sub")
  };
  log.debug("Leaving mintTokens(). jti=" + out.jti);
  return out;
}

// A SAML ASSERTION IN THIS REALM, through WS-Trust, so that the set doors have
// something unrevocable to be refused about. The RST carries no AppliesTo — an
// audience restriction is optional there and this job needs the assertion, not
// the audience — and the username is a UsernameToken, which this service does
// not check any more than it checks a password anywhere else.
async function mintAssertion(username) {
  log.debug("Entering mintAssertion(). username=" + username);
  const rst = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' +
    '<soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/' +
    '2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
    '<wsse:UsernameToken><wsse:Username>' + username + '</wsse:Username>' +
    '<wsse:Password>' + MINT_PASSWORD +
    '</wsse:Password></wsse:UsernameToken></wsse:Security></soap:Header>' +
    '<soap:Body><wst:RequestSecurityToken ' +
    'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">' +
    '<wst:RequestType>' +
    'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>' +
    '</wst:RequestSecurityToken></soap:Body></soap:Envelope>';
  const reply = await common.httpJson(base + "/realm/" + REALM + "/sts", {
    method: "POST",
    headers: { "Content-Type": "application/soap+xml" },
    body: rst
  });
  assert.strictEqual(reply.status, 200,
    "the realm's WS-Trust endpoint should issue an assertion with no " +
    "AppliesTo — that is optional in an RST and this service allows it. It " +
    "answered " + reply.status + " " + String(reply.raw).slice(0, 200));
  log.debug("Leaving mintAssertion().");
  return reply;
}

function subjectOf(tokens) {
  log.debug("Entering subjectOf().");
  log.debug("Leaving subjectOf().");
  return tokens.sub;
}

// One claim out of a JWT, without verifying it: this file is asserting what the
// service RECORDED about a token, not whether the token is sound — sts_dpop.js
// and oauth2_sts_endpoints.js own that question.
function claimOf(jwt, name) {
  log.debug("Entering claimOf().");
  if (!jwt) {
    log.debug("Leaving claimOf().");
    return "";
  }
  const parts = String(jwt).split(".");
  if (parts.length < 2) {
    log.debug("Leaving claimOf().");
    return "";
  }
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url")
                                     .toString("utf8"));
    log.debug("Leaving claimOf().");
    return payload[name] || "";
  } catch (e) {
    log.debug("Caught in claimOf(): " + ((e && e.message) || e));
    log.debug("Leaving claimOf().");
    // A token this service minted is always decodable; a body that is not is
    // worth reporting as an empty claim rather than as a crash, because the
    // assertion that follows says more about what went wrong.
    return "";
  }
}

async function introspectActive(token) {
  log.debug("Entering introspectActive().");
  const reply = await common.httpJson(base + "/realm/" + REALM +
                                      "/oauth2/introspect", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "token=" + encodeURIComponent(token)
  });
  assert.strictEqual(reply.status, 200,
    "introspection should answer 200 whatever it thinks of the token; it " +
    "answered " + reply.status);
  log.debug("Leaving introspectActive(). active=" + reply.body.active);
  return reply.body.active === true;
}

// ---------------------------------------------------------------------------
// THE DIRECTORY DOOR AND THE SIGN-OUT DOOR.
//
// `/users/create` is the only write on this API that puts a PERSON in the
// directory, and the rule it keeps is the one every door here keeps: ONE ENTRY
// PER PERSON, whatever protocol authenticated them. So the assertion is the
// second create being refused, not the first succeeding.
//
// `/logout` is the resource where three doors onto one behaviour deliberately
// DISAGREE, and that disagreement is the thing worth pinning: `POST /logout`
// with an empty body is a GLOBAL logout and is documented as such, while `POST
// /admin-api/logout/end` with an empty selection is REFUSED. The absence is the
// same and the intent is opposite — an empty selection arriving at `end` is a
// caller that built a list and got nothing.
// ---------------------------------------------------------------------------
async function theDirectoryAndSignOutDoorsRoundTrip() {
  log.debug("Entering theDirectoryAndSignOutDoorsRoundTrip().");
  log.info("=== Users, and the sign-out resource's four actions ===");
  const username = names.usernameFor("stsapi-directory");
  // With the attributes a real account carries, nothing invented, and the
  // password the token minted for them below presents — see
  // ensureTokenParties(), which then finds this person already made.
  const created = await ok("/users/create", {
    username: username, invent: false,
    attributes: { cn: "Operations " + username, givenName: "Operations",
                  sn: username, displayName: "Operations " + username,
                  mail: username + "@admin-api-operations.test" },
    credential: "password", password: MINT_PASSWORD
  }, "created a person in the directory");
  mintedParties["realm:user:" + username] = true;
  assert.ok(String(created.dn || "").indexOf("dc=" + REALM + ",") > 0,
    "the entry should land in THIS realm's ou=users; its DN is " + created.dn);
  const listedUsers = await get("/users?q=" + encodeURIComponent(username));
  assert.strictEqual(listedUsers.status, 200,
    "GET /users?q=… should answer 200; it answered " + listedUsers.status);
  assert.strictEqual(listedUsers.body.matched, 1,
    "and the person just created should be the one row that matches their " +
    "own name — read through the resource's own listing rather than believed " +
    "off the create's reply. It matched " + listedUsers.body.matched + " of " +
    listedUsers.body.known + " known.");
  assert.strictEqual((listedUsers.body.users[0] || {}).knownBy, "created",
    "and the register should say this entry is known because it was CREATED " +
    "rather than because somebody authenticated as them: this door is the " +
    "only one on this API that puts a person in the directory without a " +
    "sign-in, and that provenance is the whole difference. It says " +
    JSON.stringify((listedUsers.body.users[0] || {}).knownBy));

  await refused("/users/create", { username: username },
    /already/i,
    "a second entry for one person — one object per person is the rule this " +
    "directory keeps at every door, whatever protocol authenticated them");

  // The sign-out resource acts on somebody by NAME — it is the operator's
  // door, and /logout is the one that defaults to whoever is signed in — so a
  // body with no user never reaches the action at all.
  await refused("/logout/end", { select: ["session:nothing"] },
    /Name the identity|in `user`/,
    "a sign-out with no identity named");

  const tokens = await mintTokens(username, "logout-client-" + REALM);
  const inventory = await get("/logout?user=" + encodeURIComponent(username));
  assert.strictEqual(inventory.status, 200,
    "GET /logout?user=… should answer 200; it answered " + inventory.status);
  assert.ok((inventory.body.families || []).length > 5,
    "the sign-out view should list every family a logout reaches — the " +
    "prose for those lives in logout/logout.js and is rendered by both " +
    "doors, so a family added there appears here with no edit. It listed " +
    (inventory.body.families || []).length);
  const rows = inventory.body.rows || [];
  assert.ok(rows.length,
    "and after minting a token for " + username + " there should be " +
    "something live to end; the view lists none.");

  await refused("/logout/end", { user: username, select: [] },
    /Nothing was selected|global/i,
    "AN EMPTY SELECTION — which is the one place three doors onto one " +
    "behaviour deliberately disagree. `POST /logout` with an empty body is a " +
    "global logout and is documented as such; an empty `select` here is a " +
    "caller that built a list and got nothing, and signing that caller out " +
    "of everything would be the worst available reading of it");

  const ended = await ok("/logout/end",
    { user: username, select: [rows[0].id] },
    "ended one live thing by id");
  assert.ok(ended.result || ended.terminated || ended.ok,
    "`end` should say what it ended; it answered " +
    JSON.stringify(ended).slice(0, 200));
  const afterEnd = await get("/logout?user=" + encodeURIComponent(username));
  assert.ok(!(afterEnd.body.rows || []).some(function (one) {
    return one.id === rows[0].id;
  }), "AND THE THING IT ENDED MUST BE GONE FROM THE VIEW. `end` reports what " +
      "it terminated in its own reply, which is exactly the account a " +
      "handler that terminated nothing would also give — so the inventory is " +
      "read again and the row is looked for by id. It still lists " +
      JSON.stringify((afterEnd.body.rows || []).map(function (one) {
        return one.id;
      })));

  const globally = await ok("/logout/global", { user: username },
    "signed the person out globally");
  const terminated = (globally.result && globally.result.terminated) ||
      globally.terminated || [];
  assert.ok(Array.isArray(terminated),
    "`global` should report what it terminated; it answered " +
    JSON.stringify(globally).slice(0, 200));
  const afterGlobal = await get("/logout?user=" + encodeURIComponent(username));
  assert.deepStrictEqual((afterGlobal.body.rows || []).filter(function (one) {
    return one.terminable;
  }).map(function (one) { return one.id; }), [],
    "AND NOTHING TERMINABLE MAY BE LEFT. That is what `global` means, and it " +
    "is the assertion the reply cannot make for itself: a handler that ended " +
    "the first family and stopped would report a list of things it really " +
    "did end. What is left is the non-terminable rows, which the view lists " +
    "on purpose. It still holds " +
    JSON.stringify((afterGlobal.body.rows || []).filter(function (one) {
      return one.terminable;
    }).map(function (one) { return one.label; })));
  assert.strictEqual(await introspectActive(tokens.access), false,
    "and a global sign-out must reach the token, not just the session: it is " +
    "the same revocation set /oauth2/revoke writes to.");

  // The two NON-SPEC actions, which say so in their own summaries. RFC 7009
  // defines no un-revoke and a real KDC has no clear-the-instant; both exist so
  // that a test does not have to restart the service to get back to a working
  // credential.
  await ok("/logout/restore-token", { user: username, jti: tokens.jti },
    "restored a token the sign-out revoked");
  assert.strictEqual(await introspectActive(tokens.access), true,
    "`restore-token` must reach introspection, for the same reason " +
    "`/tokens/restore` must.");
  assert.ok((await get("/logout?user=" + encodeURIComponent(username)))
      .body.rows.some(function (one) {
        return one.family === "token" && one.terminable;
      }),
    "and the restored token should be something the sign-out view can end " +
    "again — the inventory and the revocation set are one store read two " +
    "ways, and an un-revoke that only reached introspection would leave this " +
    "page unable to offer the thing it had just been told about.");

  await ok("/logout/restore-kerberos", { user: username },
    "cleared the Kerberos sign-out instant");
  const krb5Row = (await get("/logout?user=" + encodeURIComponent(username)))
      .body.rows.filter(function (one) { return one.family === "krb5"; })[0];
  assert.ok(krb5Row,
    "the sign-out view should always carry a Kerberos row, even when there " +
    "is no principal — the absence is the answer, and omitting it would read " +
    "as a global logout having skipped the KDC.");
  assert.ok(!krb5Row.startedAt,
    "AND NO SIGN-OUT INSTANT MAY STAND AFTER `restore-kerberos`. The row's " +
    "`startedAt` IS that instant — it is 0 when there is none — so this is " +
    "the one reading of that action a caller can make; its own reply says " +
    "\"nothing changed\" whether it cleared an instant or never found one. " +
    "It reads " + krb5Row.startedAt + " (" + krb5Row.detail + ")");

  log.info("[users/logout] OK — one entry per person is enforced, the " +
           "sign-out view lists what is live, `end` refuses an empty " +
           "selection while `global` means everything, and both non-spec " +
           "restores reach the protocol endpoint.");
  log.debug("Leaving theDirectoryAndSignOutDoorsRoundTrip().");
}

// ---------------------------------------------------------------------------
// THE CLIENT-CERTIFICATE TRUSTSTORE (2026-09-12): add a freshly minted CA,
// read it back, remove it, read back its absence — and touch nothing else.
//
// **THE TRUSTSTORE IS THE PROCESS'S AND NOT THE REALM'S**, so this is the
// second section here that works at the ROOT and has to clean up by hand. Every
// job after this one has its client certificates judged against that array —
// the remote PEP's among them — so two rules are not optional: the anchor this
// section adds is removed in a `finally` whatever happened above it, and the
// only anchor it ever removes is the one it added. It names that anchor by the
// fingerprint of a CA minted a moment earlier, which nobody else can hold.
//
// It also asserts the one refusal the gate is responsible for rather than
// this resource: a token carrying only `admin:read` may LIST the truststore and
// may not change it. That is `mgmt-api/admin_api.js`'s middleware, by method,
// and it is asserted HERE because a truststore anybody with a read token could
// add to would be `POST /tls/trust` all over again with a credential in front.
// ---------------------------------------------------------------------------
function trustFingerprintOf(pem) {
  log.debug("Entering trustFingerprintOf().");
  log.debug("Leaving trustFingerprintOf().");
  return new (require("crypto").X509Certificate)(pem).fingerprint256;
}

async function trustAnchorsHeld() {
  log.debug("Entering trustAnchorsHeld().");
  // `per` at the API's cap: the truststore holds at most 32, so one page is
  // all of it and a fingerprint cannot hide on page two.
  const reply = await get("/tls/trust?per=100", true);
  assert.strictEqual(reply.status, 200,
    "GET /admin-api/tls/trust should answer 200; it answered " + reply.status +
    " " + String(reply.raw).slice(0, 300));
  assert.ok(Array.isArray(reply.body.anchors) && reply.body.installed === true,
    "the truststore resource should be installed and list `anchors`: " +
    String(reply.raw).slice(0, 300));
  log.debug("Leaving trustAnchorsHeld().");
  return reply;
}

async function theTruststoreRoundTrips() {
  log.debug("Entering theTruststoreRoundTrips().");
  log.info("=== The client-certificate truststore: add, read, remove, read " +
           "===");
  const credentials = require("../tools/pep-credential.js");
  const minted = await credentials.mint({
    rootSubject: "CN=admin-api-operations truststore " + REALM +
                 ",O=mock-sts tests",
    subject: "CN=admin-api-operations-truststore-leaf,O=mock-sts tests" });
  const mine = trustFingerprintOf(minted.anchorPem);
  const notMine = trustFingerprintOf(minted.issuing.pem);

  const before = await trustAnchorsHeld();
  const heldBefore = before.body.anchors.map(function (one) {
    return one.fingerprint256;
  });
  assert.ok(heldBefore.indexOf(mine) < 0,
    "a CA minted this second is already in the truststore, which cannot " +
    "happen — the read is reporting something other than the truststore");

  let added = false;
  try {
    // A READ TOKEN LISTS AND DOES NOT CHANGE.
    const tokens = require("../tools/admin-api-token.js");
    const readOnly = await tokens.tokenFor(base, { scope: "admin:read" });
    const refusedWrite = await common.httpJson(rootApi + "/tls/trust/add", {
      method: "POST",
      headers: { "Content-Type": "application/json",
                 Authorization: "Bearer " + readOnly },
      body: JSON.stringify({ certificates: minted.anchorPem })
    });
    assert.strictEqual(refusedWrite.status, 403,
      "POST /admin-api/tls/trust/add with a token carrying only admin:read " +
      "must be refused 403 by the gate; it answered " + refusedWrite.status +
      " " + String(refusedWrite.raw).slice(0, 300));

    // A BLOCK OPENSSL CANNOT READ IS REFUSED, AND ADDS NOTHING.
    await refused("/tls/trust/add",
      { certificates: "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n" +
                      "-----END CERTIFICATE-----\n" },
      /could not be read by OpenSSL/,
      "a PEM block OpenSSL cannot parse", true);
    // A FINGERPRINT THIS TRUSTSTORE DOES NOT HOLD REMOVES NOTHING.
    await refused("/tls/trust/remove", { fingerprint: notMine },
      /holds no anchor/, "a fingerprint the truststore does not hold", true);

    const add = await ok("/tls/trust/add", { certificates: minted.anchorPem },
                         "added a freshly minted CA", true);
    added = true;
    assert.strictEqual(add.added, 1,
      "the add should report one anchor added: " + JSON.stringify(add));
    // PERSISTED SINCE 2026-09-12: a service with a directory writes a runtime
    // anchor to ou=trustAnchors, so the reply says so.
    assert.strictEqual(add.persisted, true,
      "the add should say the anchor was written down: " + JSON.stringify(add));

    const afterAdd = await trustAnchorsHeld();
    const row = afterAdd.body.anchors.filter(function (one) {
      return one.fingerprint256 === mine;
    })[0];
    assert.ok(row && row.source === "runtime" && row.ca === true &&
              /CN=admin-api-operations truststore/.test(row.subject) &&
              row.pem.replace(/\s+/g, "") === minted.anchorPem.replace(/\s+/g,
                                                                       ""),
      "READ BACK THROUGH GET /admin-api/tls/trust, the CA just added must be " +
      "listed as a runtime CA carrying its own subject and PEM. It listed: " +
      JSON.stringify(row || null).slice(0, 400));
    assert.ok(afterAdd.raw.indexOf("PRIVATE KEY") < 0,
      "the truststore resource must carry no private key");
    assert.strictEqual(afterAdd.body.total, heldBefore.length + 1,
      "exactly one anchor should have been added: " + afterAdd.body.total +
      " against " + heldBefore.length + " before");

    // THE SAME ARRAY UNDER THIS REALM'S PREFIX: the truststore has no realm.
    const inRealm = await get("/tls/trust?per=100");
    assert.ok(inRealm.status === 200 &&
              inRealm.body.anchors.some(function (one) {
      return one.fingerprint256 === mine;
    }), "GET /realm/" + REALM + "/admin-api/tls/trust must list the same " +
      "anchor — the listeners are shared by every realm, so a realm-scoped " +
      "truststore would be a filter over something with no realm in it.");

    const dup = await ok("/tls/trust/add", { certificates: minted.anchorPem },
                         "answered a duplicate add", true);
    assert.ok(dup.added === 0 && dup.duplicates === 1,
      "the same CA again must be counted as a duplicate and not added twice: " +
      JSON.stringify(dup));

    // REMOVED BY THE COLON-FREE SPELLING, which most tools print.
    const removed = await ok("/tls/trust/remove",
      { fingerprint: mine.replace(/:/g, "").toLowerCase() },
      "removed the CA this section added", true);
    added = false;
    assert.ok(removed.removed === 1 && removed.removedAnchor &&
              removed.removedAnchor.fingerprint256 === mine,
      "the remove should name the anchor it removed: " +
      JSON.stringify(removed));
  } finally {
    if (added) {
      // THE ONE ANCHOR THIS SECTION ADDED, AND NO OTHER. A failure above must
      // not leave a CA in a process-wide truststore for every later job.
      await post("/tls/trust/remove", { fingerprint: mine }, true);
    }
  }

  const afterRemove = await trustAnchorsHeld();
  assert.ok(afterRemove.body.anchors.every(function (one) {
    return one.fingerprint256 !== mine;
  }), "READ BACK AFTER THE REMOVE, the CA must be gone from GET " +
    "/admin-api/tls/trust — a remove that answers ok and leaves the anchor " +
    "listed is the defect this read exists for.");
  assert.deepStrictEqual(afterRemove.body.anchors.map(function (one) {
    return one.fingerprint256;
  }).sort(), heldBefore.slice().sort(),
    "the truststore must be exactly what it was before this section: it adds " +
    "one CA and removes that CA, and touches no anchor anybody else put " +
    "there.");
  log.info("[truststore] OK — a minted CA added, read back at the root and " +
           "under the realm prefix, refused as a duplicate, removed by " +
           "fingerprint and read back absent; a read-only token was refused " +
           "the write, and every other anchor was left where it was.");
  log.debug("Leaving theTruststoreRoundTrips().");
}

// ---------------------------------------------------------------------------
// THE STORED KERBEROS KEYS (2026-09-12): create, read, rotate, read, delete,
// read — and a person's clear, which on a development stack clears nothing.
//
// **THE KDC IS THE PROCESS'S**, so this is the third section here that works at
// the ROOT and cleans up by hand: the service principal it creates is the
// DEFAULT realm's whatever prefix a call carries, and every later job's
// Kerberos traffic is answered by the same KDC. The SPN carries this run's
// realm id, so nobody else holds it, and it is deleted in a `finally`.
//
// **THE KEYTAB IS THE ONE PIECE OF KEY MATERIAL THIS API EVER RETURNS**, so the
// assertions that matter are about where it is NOT: the read of the resource
// after the create carries no part of it, and the rotate's keytab is a
// different one at the next kvno. The header is checked to be MIT's 0x0502 and
// no more — `tests/kerberos_person_keys.js` reads the whole file with an
// independent parser, in process.
// ---------------------------------------------------------------------------
async function kerberosPrincipalsHeld(scopeRoot) {
  log.debug("Entering kerberosPrincipalsHeld().");
  const reply = await get("/kerberos/principals?per=100", scopeRoot);
  assert.strictEqual(reply.status, 200,
    "GET /admin-api/kerberos/principals should answer 200; it answered " +
    reply.status + " " + String(reply.raw).slice(0, 300));
  assert.ok(Array.isArray(reply.body.services) &&
            Array.isArray(reply.body.people),
    "the resource should list `services` and `people`: " +
    String(reply.raw).slice(0, 300));
  log.debug("Leaving kerberosPrincipalsHeld().");
  return reply;
}

async function theKerberosPrincipalsRoundTrip() {
  log.debug("Entering theKerberosPrincipalsRoundTrip().");
  log.info("=== Kerberos principals: create, rotate, delete a service key ===");
  const spn = "HTTP/" + REALM + ".example.com";
  let created = false;
  try {
    await refused("/kerberos/principals/create-service",
      { spn: "krbtgt/EXAMPLE.COM" }, /ticket-granting key/,
      "a krbtgt principal", true);
    await refused("/kerberos/principals/create-service", { spn: "not-an-spn" },
      /is not a service principal name/, "a one-component name", true);
    await refused("/kerberos/principals/rotate-service", { spn: spn },
      /holds no stored key to rotate/, "a rotate of a principal nobody made",
      true);

    const made = await ok("/kerberos/principals/create-service", { spn: spn },
                          "created a service principal with a random key",
                          true);
    created = true;
    assert.ok(typeof made.keytab === "string" && made.keytab.length > 100,
      "create-service must return the keytab, base64: " +
      JSON.stringify(Object.assign({}, made, { keytab: "(" +
        String(made.keytab || "").length + " chars)" })));
    const bytes = Buffer.from(made.keytab, "base64");
    assert.ok(bytes[0] === 0x05 && bytes[1] === 0x02,
      "the keytab must be MIT's version 0x0502; it starts " +
      bytes.subarray(0, 2).toString("hex"));
    assert.strictEqual(made.trustRealm, "default",
      "the reply must say the principal is the default trust realm's");

    const afterCreate = await kerberosPrincipalsHeld(true);
    const row = afterCreate.body.services.filter(function (one) {
      return one.spn === spn;
    })[0];
    assert.ok(row && row.kvno === made.kvno && row.held === true &&
              row.etypes.length === made.etypes.length,
      "READ BACK THROUGH GET /admin-api/kerberos/principals, the principal " +
      "must be listed at the kvno the create returned. It listed: " +
      JSON.stringify(row || null));
    assert.ok(afterCreate.raw.indexOf(made.keytab.slice(0, 48)) < 0 &&
              afterCreate.raw.indexOf("$aesgcm$") < 0,
      "THE READ MUST CARRY NO KEY MATERIAL: neither the keytab nor a sealed " +
      "value");

    // A KDC PER TRUST REALM SINCE 2026-09-15 (#33), AND THIS IS WHERE THE OLD
    // RULE WAS ASSERTED. It read: *THE SAME KDC UNDER THIS REALM'S PREFIX …
    // must list the same principal: the KDC is the process's*, with
    // `trustRealm === "default"` under every prefix. Each trust realm now has
    // a Kerberos realm and a principal database of its own, so this realm —
    // which the suite creates without one — reports ITSELF as the trust realm,
    // has no KDC, and lists none of the default realm's service principals.
    // That last clause is the one worth having: a key created in one realm
    // appearing in another would be exactly the leak the split exists to
    // prevent.
    const inRealm = await kerberosPrincipalsHeld(false);
    assert.strictEqual(inRealm.body.trustRealm, REALM,
      "GET /realm/" + REALM + "/admin-api/kerberos/principals must report " +
      "the realm it was read in as its trustRealm, not the default realm: " +
      JSON.stringify(inRealm.body.trustRealm));
    assert.ok(inRealm.body.kerberos && inRealm.body.kerberos.enabled === false &&
              typeof inRealm.body.kerberos.reason === "string" &&
              inRealm.body.kerberos.reason.length > 0,
      "a realm created without a krb5.realm of its own must say it has no " +
      "KDC, and why: " + JSON.stringify((inRealm.body || {}).kerberos || null));
    assert.ok(inRealm.body.services.every(function (one) {
      return one.spn !== spn;
    }), "and it must NOT list a service principal created in the default " +
        "realm — its keys belong to that realm's KDC alone");

    await refused("/kerberos/principals/create-service", { spn: spn },
      /already holds a stored key/, "a second create of the same SPN", true);

    const rotated = await ok("/kerberos/principals/rotate-service",
                             { spn: spn },
                             "rotated the service principal", true);
    assert.ok(rotated.kvno === made.kvno + 1 && rotated.keytab !== made.keytab,
      "rotate-service must move the kvno up by one and return a NEW keytab: " +
      made.kvno + " -> " + rotated.kvno);
    const afterRotate = await kerberosPrincipalsHeld(true);
    const rotatedRow = afterRotate.body.services.filter(function (one) {
      return one.spn === spn;
    })[0];
    assert.ok(rotatedRow && rotatedRow.kvno === rotated.kvno &&
              !!rotatedRow.rotatedAt,
      "READ BACK AFTER THE ROTATE, the listed kvno must be the new one: " +
      JSON.stringify(rotatedRow || null));

    // PREVIOUS KEY VERSIONS (2026-09-12). The rotate KEPT the version it
    // replaced — the reply's keytab carries both kvnos and `retained` says
    // until when — and drop-previous-service-keys ends that window, read back
    // as an empty `retained` with the current kvno unchanged.
    assert.ok(Array.isArray(rotated.keytabKvnos) &&
              rotated.keytabKvnos.join(",") === rotated.kvno + "," +
                                                made.kvno &&
              Array.isArray(rotated.retained) &&
              rotated.retained.length === 1 &&
              rotated.retained[0].kvno === made.kvno,
      "rotate-service must keep the previous version and put it in the keytab: " +
      JSON.stringify({ keytabKvnos: rotated.keytabKvnos,
                       retained: rotated.retained }));
    assert.ok(Array.isArray(rotatedRow.retained) &&
              rotatedRow.retained.length === 1 &&
              rotatedRow.retained[0].kvno === made.kvno &&
              !isNaN(Date.parse(rotatedRow.retained[0].expiresAt)) &&
              afterRotate.raw.indexOf(rotated.keytab.slice(0, 48)) < 0,
      "READ BACK AFTER THE ROTATE, the row must list the kept version with " +
      "its expiry and no key " +
      "material: " + JSON.stringify(rotatedRow.retained || null));
    const droppedPrevious =
        await ok("/kerberos/principals/drop-previous-service-keys",
      { spn:
          spn }, "dropped the service principal's previous key version", true);
    assert.ok(droppedPrevious.dropped === 1 &&
              JSON.stringify(droppedPrevious.kvnos) === JSON.stringify(
                  [made.kvno]),
      "drop-previous-service-keys must drop the one kept version: " +
      JSON.stringify(droppedPrevious));
    const afterDrop = await kerberosPrincipalsHeld(true);
    const droppedRow = afterDrop.body.services.filter(function (one) {
      return one.spn === spn;
    })[0];
    assert.ok(droppedRow && droppedRow.kvno === rotated.kvno &&
              Array.isArray(droppedRow.retained) &&
              droppedRow.retained.length === 0,
      "READ BACK AFTER THE DROP, the principal must keep its current kvno " +
      "and list nothing kept: " + JSON.stringify(droppedRow || null));
    // AND A SECOND DROP FINDS NOTHING. The list above is the PUBLIC half,
    // written beside the sealed record; this is the one question over HTTP
    // whose answer comes from inside the seal, so a drop that cleared the list
    // and kept the versions is caught here rather than only in process.
    const droppedAgain =
        await ok("/kerberos/principals/drop-previous-service-keys",
      { spn: spn }, "answered a second drop with nothing kept", true);
    assert.strictEqual(droppedAgain.dropped, 0,
      "a second drop must find nothing kept — the sealed record itself must " +
      "have lost the version, not only the " +
      "list: " + JSON.stringify(droppedAgain));
    await refused("/kerberos/principals/drop-previous-service-keys",
      { spn: "HTTP/nobody-" + REALM + ".example.com" },
      /holds no stored Kerberos key/,
      "a drop for an SPN with no stored key", true);
    // A PERSON: nobody on a development stack holds keys, so there is nothing
    // to drop, and that is a refusal naming why.
    await refused("/kerberos/principals/drop-previous-person-keys",
      { username: "alice" }, /holds no stored Kerberos key/,
      "a drop for a person with no stored keys", true);

    const removed = await ok("/kerberos/principals/delete-service",
                             { spn: spn },
                             "deleted the service principal's key", true);
    created = false;
    assert.ok(/is gone/.test(String(removed.message)),
      "the delete should say the key is gone: " + JSON.stringify(removed));
    const afterDelete = await kerberosPrincipalsHeld(true);
    assert.ok(afterDelete.body.services.every(function (
        one) { return one.spn !== spn; }),
      "READ BACK AFTER THE DELETE, the principal must be gone from the list");

    // A PERSON: nobody on a development stack holds keys, so the clear answers
    // `cleared: false` rather than a refusal — which is what lets a script
    // clear on every run — and a name nobody holds is refused.
    await refused("/kerberos/principals/clear-person-keys",
      { username: "nobody-" + REALM }, /nobody called/,
      "a clear for somebody not in the directory", true);
    const cleared = await ok("/kerberos/principals/clear-person-keys",
      { username: "alice" }, "answered a clear for a person with no keys",
      true);
    assert.strictEqual(cleared.cleared, false,
      "alice holds no Kerberos keys on a development stack: " +
      JSON.stringify(cleared));
    await kerberosPrincipalsHeld(true);
  } finally {
    if (created) {
      await post("/kerberos/principals/delete-service", { spn: spn }, true);
    }
  }
  log.info("[kerberos] OK — a service principal created with a keytab, read " +
           "back at the root with no key material and ABSENT under a realm " +
           "prefix whose own Kerberos is off, refused a second create, " +
           "rotated to the next kvno with " +
           "the previous version kept in the keytab and the list, that " +
           "version dropped and read back gone, deleted and read back " +
           "absent; krbtgt, a one-component name and two drops with nothing " +
           "stored were refused, and a person's clear answered.");
  log.debug("Leaving theKerberosPrincipalsRoundTrip().");
}

// ---------------------------------------------------------------------------
// THE ADMIN ROLES, A ROSTER PER REALM SINCE 2026-09-14 (#32).
//
// The two console roles are ordinary groups in the ou=groups of the realm
// being read: a grant made through /realm/<id>/admin-api/rbac/grant lands in
// that realm's directory and says so in its reply, and makes a person an
// administrator of THAT realm alone. The default realm's roster is the
// SERVICE roster. Until #32 this section asserted the opposite — every grant
// landed in the default realm — and it now asserts both halves of the new
// rule: a realm's grant is in the realm, and it leaves the service roster
// untouched.
//
// Which makes this the one section that must clean up after itself by hand, and
// the one that can lock every other job out of the console if it does not:
// while neither role group has a member, anybody who signs in holds both, and
// the FIRST grant closes that door for everybody who is not in the roster.
// ---------------------------------------------------------------------------
async function theAdminRolesRoundTrip() {
  log.debug("Entering theAdminRolesRoundTrip().");
  log.info("=== Admin roles: grant and revoke, in the DEFAULT realm ===");
  const before = await get("/rbac");
  assert.strictEqual(before.status, 200, "GET /rbac should answer 200.");
  // Each row names itself by the value the GRANT takes — `read` / `write` —
  // beside the group it really is (`cn=admin-read`). Both are published
  // because they are two different facts: one is what this API accepts and
  // the other is what an `ldapmodify` or a SCIM PATCH would write, and the
  // whole design of these roles is that those are four doors onto one
  // membership.
  const rolesAvailable = (before.body.roles || []).map(function (r) {
    return typeof r === "string" ? r : r.role;
  }).filter(Boolean);
  assert.ok(rolesAvailable.length === 2,
    "there should be exactly TWO console roles — read and write. They are " +
    "the whole of this console's authorization model, and a third would be a " +
    "design change rather than a configuration one. It published " +
    JSON.stringify(rolesAvailable));
  assert.ok(String(before.body.groupsDn || "").indexOf("dc=" + REALM) >= 0,
    "READ FROM INSIDE " + REALM + ", THE ROSTER IS THAT REALM'S (#32): each " +
    "realm has administrators of its own, and the default realm's are the " +
    "service's. It named " + before.body.groupsDn);
  const serviceBefore = await get("/rbac", true);
  assert.ok(String(serviceBefore.body.groupsDn || "").indexOf("dc=" + REALM) <
            0,
    "and read at the root, the roster is the DEFAULT realm's — the service " +
    "roster. It named " + serviceBefore.body.groupsDn);

  // EVERY LIST IN THE REPLY IS PAGED (2026-09-13). A directory of thousands
  // made `candidates` thousands of rows and `roles[].members` every
  // membership, on every read of the roster.
  const paged = await get("/rbac?per=1&candidatesPage=999999");
  assert.strictEqual(paged.status, 200, "GET /rbac?per=1 should answer 200.");
  const cp = paged.body.candidatesPaging || {};
  assert.ok(Array.isArray(paged.body.candidates) &&
            paged.body.candidates.length <= 1 && cp.perPage === 1,
    "`candidates` should be paged by the shared `per`, answered in " +
    "`candidatesPaging`; with per=1 it answered " +
    paged.body.candidates.length + " row(s) and " + JSON.stringify(cp));
  assert.ok(cp.page === cp.pages && cp.page >= 1,
    "a `candidatesPage` past the end should be CLAMPED to the last page, " +
    "as `page` is; it answered " + JSON.stringify(cp));
  assert.strictEqual((paged.body.candidateSearch || {}).matched, cp.total,
    "`candidatesPaging.total` should be how many candidates matched.");
  assert.ok((paged.body.grants || []).length <= 1 && paged.body.perPage === 1,
    "`grants` should be paged by the same `per`.");
  assert.ok((paged.body.roles || []).every(function (r) {
    return r.members === undefined && r.claimed === undefined &&
           typeof r.memberCount === "number";
  }), "`roles` should carry each role's counts and NOT its unpaged " +
      "`members` / `claimed` lists, which are the rows `grants` pages.");

  const grantedBefore = before.body.grantCount;
  const subject = names.usernameFor("stsapi-role");
  const granted = await ok("/rbac/grant",
    { username: subject, role: rolesAvailable[0] },
    "granted a console role");
  // The reply says WHERE it landed by naming the DN it wrote, which is a
  // better answer than the word "default" would be: it is the same DN an
  // `ldapmodify` or a SCIM PATCH would write, which is the point of these
  // roles being ordinary groups rather than a store of the console's own.
  assert.ok(granted.dn && granted.member,
    "a grant should name the group it wrote and the member it added, so a " +
    "caller can reach the same membership through the other three doors. It " +
    "answered " + JSON.stringify(granted).slice(0, 300));
  assert.ok(String(granted.dn).indexOf("dc=" + REALM) >= 0 &&
            String(granted.member).indexOf("dc=" + REALM) >= 0,
    "A GRANT MADE UNDER A REALM PREFIX LANDS IN THAT REALM (#32), and the DN " +
    "in the reply is how it says so: it made a " + REALM + " administrator " +
    "and nothing more. It wrote " + granted.dn + " / " + granted.member);
  const serviceDuring = await get("/rbac", true);
  assert.strictEqual(serviceDuring.body.grantCount,
                     serviceBefore.body.grantCount,
    "AND THE SERVICE ROSTER IS UNTOUCHED BY IT — a realm's grant that reached " +
    "the default realm's groups would make a realm's administrator the " +
    "service's. It reads " + serviceDuring.body.grantCount + " against " +
    serviceBefore.body.grantCount + " before.");
  assert.strictEqual(granted.changed, true,
    "and it should report that it CHANGED the membership rather than " +
    "finding it already there.");

  const during = await get("/rbac");
  assert.strictEqual(during.body.grantCount, grantedBefore + 1,
    "the roster should have grown by one.");
  assert.ok((during.body.grants || []).some(function (row) {
    return String(row.username || row.user || "").indexOf(subject) >= 0;
  }), "and the person granted should be on it.");

  await ok("/rbac/revoke", { username: subject, role: rolesAvailable[0] },
    "revoked the console role");
  const after = await get("/rbac");
  assert.strictEqual(after.body.grantCount, grantedBefore,
    "AND THE ROSTER MUST BE BACK WHERE IT STARTED. While neither role group " +
    "has a member, anybody who signs in holds both — so a grant left behind " +
    "here closes the console for every other job in the run, and the job " +
    "that fails is not this one. It reads " + after.body.grantCount +
    " grant(s) against " + grantedBefore + " before.");
  log.info("[rbac] OK — grant and revoke round-tripped in " + REALM + "'s " +
           "own roster, the service roster untouched, and the roster is " +
           "back where it started.");
  log.debug("Leaving theAdminRolesRoundTrip().");
}

// ---------------------------------------------------------------------------
// THE CONFIGURATION DOORS, AND THE TWO NARROW ONES BESIDE THEM.
//
// `/config` is the wide door: four actions over a hundred and fifty settings,
// and `set-many` deliberately IGNORES a key it does not know, because a form
// posts fields the resource never declared. That is right for what it is and
// wrong for a caller that means to set a lifetime — a misspelt
// `oauth2.accessTokenTtlsS` succeeds, changes nothing, and reports success.
//
// So there are two NARROW doors, `/token-lifetimes` and `/saml-assertions`,
// whose whole reason to exist is a refusal the wide one cannot give. That is
// the test mgmt-api/CLAUDE.md sets for a third such resource — *"does a caller
// of the general operation get a wrong answer here"* — and it is asserted from
// both ends: the narrow door refuses an unknown key BY NAME, and the wide door
// does not, and both of those are the intended behaviour.
//
// One more thing is checked about the narrow doors, and it is the drift this
// file exists for: THE PROPERTIES THE DOCUMENT DECLARES MUST BE THE SETTINGS
// THE HANDLER ACCEPTS. The handler names them in its own refusal, so the two
// lists are comparable — and a document that is short by two is a caller who
// never discovers that two of the settings are settable here at all.
// ---------------------------------------------------------------------------
async function theConfigurationDoorsRoundTrip(doc) {
  log.debug("Entering theConfigurationDoorsRoundTrip().");
  log.info("=== Configuration: the wide door and the two narrow ones ===");

  // A runtime setting whose value is a small integer, chosen off the service's
  // own table rather than named here: an integer on the wire cannot be
  // satisfied by an echo the way a string can, and reading the table means
  // this file does not go stale when a setting is renamed.
  const table = (await get("/config")).body;
  const candidate = runtimeIntegerSetting(table);
  assert.ok(candidate,
    "the configuration table should carry at least one runtime integer " +
    "setting for this check to drive; it carries none.");
  const original = candidate.value;
  const wanted = Number(original) + 1;

  await ok("/config/set", { key: candidate.key, value: wanted },
    "set " + candidate.key);
  let row = settingRow((await get("/config")).body, candidate.key);
  assert.strictEqual(Number(row.value), wanted,
    "`set` should change the effective value of " + candidate.key + "; it " +
    "reads " + row.value);
  assert.strictEqual(row.source, "realm",
    "AND THE ROW MUST SAY THE VALUE CAME FROM THIS REALM. The five layers " +
    "are what /admin/config is a view of, and a value that changed without " +
    "the source moving would be a second store — but the distinction that " +
    "matters here is finer than that: a setting written under a realm prefix " +
    "is the REALM'S (`source: realm`, held on the realm row) and one written " +
    "at the root is the process's (`source: override`, held in the appconfig " +
    "store). They are two different places, and the same POST reaches " +
    "whichever one the prefix names. It says " + row.source);

  // The same setting at the ROOT, to see the other branch. A caller that only
  // ever drove one of the two would never notice them collapsing into each
  // other, and the persistence section below depends on their being different.
  const rootBefore = settingRow((await get("/config", true)).body,
                                candidate.key);
  await ok("/config/set", { key: candidate.key, value: wanted + 1 },
    "set the same key at the root", true);
  const rootRow = settingRow((await get("/config", true)).body, candidate.key);
  assert.strictEqual(rootRow.source, "override",
    "the same setting written at the ROOT should be a process-wide override; " +
    "it says " + rootRow.source);
  assert.strictEqual(Number(settingRow((await get("/config")).body,
      candidate.key).value), wanted,
    "AND THE REALM'S VALUE MUST BE UNCHANGED BY IT. A realm override sits " +
    "above the process-wide one, so writing the process's must not reach " +
    "into a realm that has its own — which is the whole of what a realm is.");
  await ok("/config/reset", { key: candidate.key }, "reset it at the root",
           true);
  assert.strictEqual(settingRow((await get("/config", true)).body,
      candidate.key).source, rootBefore.source,
    "and the root's row should be back to " + rootBefore.source + ".");

  await ok("/config/reset", { key: candidate.key }, "reset " + candidate.key);
  row = settingRow((await get("/config")).body, candidate.key);
  assert.strictEqual(Number(row.value), Number(original),
    "`reset` should put the value back.");
  assert.notStrictEqual(row.source, "realm",
    "AND IT MUST TAKE THE OVERRIDE ROW AWAY, not merely write the old value " +
    "back. A `set` that restored the value would leave `source: override` on " +
    "the row for ever, which is what tests/admin_api.js trips over on the " +
    "next run against the same container — the reason tests/CLAUDE.md says " +
    "to restore with `reset` rather than with a second `set`. It says " +
    row.source);

  // set-many is all-or-nothing on the keys it KNOWS and silent about the ones
  // it does not. Both halves are deliberate and both are asserted, because
  // they look like the same behaviour from a single call.
  await ok("/config/set-many",
    { [candidate.key]: wanted, "no.such.setting.at.all": "ignored" },
    "set a section with an unknown field in it — which a FORM posts all the " +
    "time, and is why this door ignores it");
  assert.strictEqual(
    Number(settingRow((await get("/config")).body, candidate.key).value),
    wanted,
    "the known key in that section should have been applied.");
  await ok("/config/reset", { key: candidate.key }, "reset it again");

  // ---------------------------------------------------------------------
  // `reset-all`, IN THE REALM, AND ONLY IN THE REALM.
  //
  // config.js's clearAllOverrides() clears the overrides of the scope the
  // call ARRIVED IN — a realm's settings under a realm prefix, the process's
  // at the root — which is what makes it safe here and makes it the single
  // most destructive call in this suite at the root: it would drop whatever
  // every other job had pinned, and nothing would say so until one of them
  // failed for a reason that has nothing to do with itself.
  //
  // It is also the one operation on this API that carries no example body,
  // so nothing in the sweep reaches it. That is exactly the hole the coverage
  // ledger at the end of this run exists to keep shut.
  // ---------------------------------------------------------------------
  await ok("/config/set", { key: candidate.key, value: wanted },
    "set " + candidate.key + " again, so that `reset-all` has something to " +
                             "clear");
  const cleared = await ok("/config/reset-all", {},
    "cleared this realm's runtime overrides");
  assert.ok((cleared.cleared || []).indexOf(candidate.key) >= 0,
    "`reset-all` should NAME what it cleared — it is the one action on this " +
    "resource that a caller cannot predict the effect of, so the list is the " +
    "whole of its answer. It named " + JSON.stringify(cleared.cleared));
  row = settingRow((await get("/config")).body, candidate.key);
  assert.strictEqual(Number(row.value), Number(original),
    "and the value should be back where it started; it reads " + row.value);
  assert.notStrictEqual(row.source, "realm",
    "AND THE REALM'S OVERRIDE ROW MUST BE GONE, not merely holding the old " +
    "value again — the same distinction `reset` keeps one key at a time, " +
    "asked of the action that does the lot. It says " + row.source);

  // The narrow doors. Each is asked for its own list, twice: once out of the
  // OpenAPI document and once out of the handler's refusal.
  await aNarrowDoorRefusesByName(doc, "/token-lifetimes",
    "oauth2.accessTokenTtlS", "oauth2.accessTokenTtlsS");
  await aNarrowDoorRefusesByName(doc, "/saml-assertions",
    "saml2.assertionLifetimeMins", "saml2.assertionLifetimeMins");

  // The one member of /saml-assertions that earns the resource its place
  // beyond the parity: the WIDTH of the window an assertion actually states,
  // which is the lifetime plus TWICE the skew and which no setting states.
  const assertions = (await get("/saml-assertions")).body.assertions;
  assert.ok(assertions,
    "GET /saml-assertions should report the assertion settings.");
  assert.strictEqual(assertions.saml2WindowS,
    assertions.saml2LifetimeMin * 60 + 2 * assertions.clockSkewS,
    "saml2WindowS must be the lifetime plus TWICE the clock skew — the skew " +
    "is applied at both ends of the validity window, which is precisely the " +
    "thing a caller assembling this from the rows gets wrong, and is why " +
    "this resource reports it at all. It says " + assertions.saml2WindowS +
    " for a " + assertions.saml2LifetimeMin + "-minute lifetime and a " +
    assertions.clockSkewS + "-second skew.");

  // A RESTART-ONLY SETTING IS REFUSED BY NAME, WITH ITS REASON. That is the
  // property the whole five-layer arrangement rests on: only a runtime
  // setting can be overridden, which is what makes it safe for the
  // persistence store to re-apply saved overrides after every module has
  // loaded. A door that accepted one and ignored it would produce a console
  // showing a value the service is not using.
  const pinned = restartOnlySetting(table);
  assert.ok(pinned,
    "the configuration table should carry at least one restart-only setting.");
  await refused("/config/set", { key: pinned.key, value: pinned.value },
    /cannot be changed while this service is running/,
    "a restart-only setting (" + pinned.key + ")");
  assert.ok(/restart|listener|bound|process starts/i.test(
      JSON.stringify((await post("/config/set",
        { key: pinned.key, value: pinned.value })).body)),
    "and the refusal must say WHY it cannot be changed — `restartReason` is " +
    "on every such row precisely so that the answer is not just 'no'.");

  // Each narrow door SETS something through its own operation and is then
  // put back with `defaults`, and both halves are read off its rows. The set
  // is what makes the restore mean anything: `defaults` asked of a door that
  // nothing has changed passes whether it works or not.
  await aNarrowDoorSetsWhatItAccepts("/token-lifetimes");
  await ok("/token-lifetimes/defaults", {}, "restored the token lifetimes");
  await aNarrowDoorIsBackAtItsDefaults("/token-lifetimes");
  await aNarrowDoorSetsWhatItAccepts("/saml-assertions");
  await ok("/saml-assertions/defaults", {}, "restored the assertion lifetimes");
  await aNarrowDoorIsBackAtItsDefaults("/saml-assertions");
  log.info("[configuration] OK — set/reset/set-many round-tripped with the " +
           "source moving both ways, and both narrow doors refuse an " +
           "unknown key by name where the wide one ignores it.");
  log.debug("Leaving theConfigurationDoorsRoundTrip(). candidate was " +
            candidate.key);
  return candidate;
}

// A narrow door's `set`, driven with a value chosen off its own rows.
//
// The value is the published one moved by the published STEP, which is how
// this file avoids knowing anything about the setting: these are lifetimes in
// whole thirty-second or one-minute units, and a number typed here would be
// refused the day one of those bounds moved. Reading the row back is the
// assertion — `set` on these doors answers with a message either way.
async function aNarrowDoorSetsWhatItAccepts(path) {
  log.debug("Entering aNarrowDoorSetsWhatItAccepts(). path=" + path);
  const rows = (await get(path)).body.settings || [];
  const row = rows.filter(function (one) {
    return one.editable !== false && typeof one.value === "number";
  })[0];
  assert.ok(row,
    "GET " + path + " should publish at least one editable numeric setting; " +
    "it published " + rows.length + " row(s) and none that this can drive.");
  const step = Number(row.step) > 0 ? Number(row.step) : 1;
  const up = Number(row.value) + step;
  const wanted = (row.max === undefined || up <= Number(row.max))
    ? up
    : Number(row.value) - step;
  assert.ok(row.min === undefined || wanted >= Number(row.min),
    "the value this walk picked for " + row.key + " (" + wanted + ") is " +
    "outside the bounds the row publishes (" + row.min + ".." + row.max +
    "), which would make the refusal below say nothing about the door.");

  await ok(path + "/set", { [row.key]: wanted },
    "set " + row.key + " through " + path);
  const after = ((await get(path)).body.settings || []).filter(function (one) {
    return one.key === row.key;
  })[0];
  assert.strictEqual(Number(after.value), wanted,
    "`" + path + "/set` should change the value it was given: " + row.key +
    " was " + row.value + ", was sent " + wanted + ", and reads " +
    after.value +
    ". This is the door that exists BECAUSE /config/set-many answers 200 and " +
    "changes nothing when it does not recognise a key — so a narrow door " +
    "that did the same would be the defect it was built against, wearing the " +
    "refusal that proves it is a different resource.");
  assert.strictEqual(after.source, "realm",
    "and the row should say the value came from THIS REALM. These doors are " +
    "reached under the realm prefix like everything else here, so what they " +
    "write is the realm's own setting (`source: realm`) rather than the " +
    "process-wide override (`source: override`) the same call makes at the " +
    "root — which is why `overridden`, which is about the process-wide one, " +
    "is still false. It says source=" + after.source + ", overridden=" +
    after.overridden);
  log.debug("Leaving aNarrowDoorSetsWhatItAccepts(). " + row.key + "=" +
            wanted);
}

// A narrow door after its `defaults`, read back off the rows it publishes.
//
// It is the cheapest assertion in this section and the one most likely to have
// been left out, because `defaults` is what a test calls to TIDY UP and a
// tidy-up that quietly did nothing costs nothing until the next job — which
// finds a lifetime this file set, does not know it was set here, and fails
// somewhere else entirely. Each row carries its own `default` and its own
// `overridden` flag, so the check is against the service's statement of what a
// default is rather than against numbers typed in this file.
async function aNarrowDoorIsBackAtItsDefaults(path) {
  log.debug("Entering aNarrowDoorIsBackAtItsDefaults(). path=" + path);
  const rows = (await get(path)).body.settings || [];
  assert.ok(rows.length,
    "GET " + path + " should publish the settings rows this door writes; it " +
    "published none, and the check below then asserts nothing.");
  const stillSet = rows.filter(function (row) {
    return row.overridden || String(row.value) !== String(row.default);
  }).map(function (row) {
    return row.key + "=" + row.value + " (default " + row.default + ")";
  });
  assert.deepStrictEqual(stillSet, [],
    "AFTER " + path + "/defaults EVERY ONE OF ITS SETTINGS MUST BE AT ITS " +
    "DEFAULT, and hold no override row. `defaults` is what this file calls " +
    "to put back what it changed, so a `defaults` that answers 200 having " +
    "restored nothing leaves the damage AND the report that it was undone. " +
    "Still set: " + stillSet.join(", "));
  log.debug("Leaving aNarrowDoorIsBackAtItsDefaults(). " + rows.length + " " +
      "row(s).");
}

// One narrow door: the names it accepts, checked against the document AND
// against its own refusal, and then a misspelling refused by name.
async function aNarrowDoorRefusesByName(doc, path, goodKey, misspelling) {
  log.debug("Entering aNarrowDoorRefusesByName(). path=" + path);
  const refusal = await post(path + "/set", { "no.such.key.here": 1 });
  const errors = ((refusal.body && refusal.body.errors) || []).join(" ");
  assert.strictEqual(refusal.status, 400,
    "POST " + path + "/set must REFUSE a key outside its own list. That " +
    "refusal is the entire reason this resource exists beside " +
    "/config/set-many, which ignores an unknown key on purpose — so a narrow " +
    "door that stopped refusing would be two operations over one function " +
    "with nothing to tell them apart. It answered " + refusal.status + " " +
    JSON.stringify(refusal.body).slice(0, 300));
  assert.ok(/no\.such\.key\.here/.test(errors),
    "and it must name the key it is refusing, so that a caller who misspelt " +
    "one is told which. It said: " + errors);

  // The list is read up to "It was also given", not up to the first full
  // stop: every name in it CONTAINS full stops (`oauth2.accessTokenTtlS`), so
  // a lazy match on `.` reads exactly one word and the comparison below then
  // fails for a reason that has nothing to do with the service.
  const named = (errors.match(/sets only\s+(.+?)\.\s+It was also given/) ||
                 errors.match(/sets only\s+(.+?)\.\s+Every other/) || [])[1];
  assert.ok(named,
    "the refusal from " + path + " should say which settings it DOES set; " +
    "it said: " + errors);
  const handlerKeys = splitList(named).sort();

  const schema = doc.paths["/admin-api" + path + "/set"].post.requestBody
      .content["application/json"].schema;
  const documentedKeys = Object.keys(schema.properties || {}).sort();
  assert.deepStrictEqual(documentedKeys, handlerKeys,
    "THE SETTINGS " + path + "/set DOCUMENTS MUST BE THE SETTINGS IT " +
    "ACCEPTS. This resource's whole claim is that it refuses anything " +
    "outside its own list BY NAME — so a document naming fewer of them is a " +
    "caller who never discovers that the others are settable here at all, " +
    "and one naming more is a caller whose request is refused for following " +
    "the document.\n" +
    "  the document declares: " + documentedKeys.join(", ") + "\n" +
    "  the handler accepts:   " + handlerKeys.join(", "));

  // And the misspelling the resource exists to catch, which the wide door
  // would have accepted in silence.
  if (misspelling !== goodKey) {
    const typo = await post(path + "/set", { [misspelling]: 60 });
    assert.strictEqual(typo.status, 400,
      "POST " + path + "/set with the near-miss " + misspelling + " must be " +
      "refused. That is the exact wrong answer /config/set-many gives — it " +
      "succeeds, changes nothing, and reports success — and this resource " +
      "exists to give a different one.");
  }
  log.debug("Leaving aNarrowDoorRefusesByName(). " + handlerKeys.length + " " +
      "key(s).");
}

// A setting the table marks restart-only, for the refusal above. Like the one
// below it, it is CHOSEN off the service rather than named here.
function restartOnlySetting(table) {
  log.debug("Entering restartOnlySetting().");
  let chosen;
  (table.groups || []).forEach(function (group) {
    (group.settings || []).forEach(function (setting) {
      if (!chosen && setting.editable === false && setting.restartReason) {
        chosen = setting;
      }
    });
  });
  log.debug("Leaving restartOnlySetting(). " +
            (chosen ? chosen.key : "(none)"));
  return chosen;
}

// A runtime setting holding a small integer, off the service's own table. The
// candidate is chosen rather than named so that this file does not go stale
// when a setting is renamed — and integers are preferred because an integer on
// the wire cannot be satisfied by an echo the way a string can.
function runtimeIntegerSetting(table) {
  log.debug("Entering runtimeIntegerSetting().");
  let chosen;
  (table.groups || []).forEach(function (group) {
    (group.settings || []).forEach(function (setting) {
      // `editable` is the table's own word for "settable at runtime". A
      // restart-only setting is refused BY NAME with its reason rather than
      // accepted and ignored — which is asserted separately below — so it
      // must not be the one this walk drives.
      if (chosen || setting.editable !== true || setting.overridden) {
        return;
      }
      // AND IT MUST BE ONE A REALM MAY CARRY. The walk below drives a realm
      // override with whatever it picks, and two kinds of setting are refused
      // there by design: the `realms.*` pair, and anything marked `perProcess`
      // (a pool of child processes belongs to the OS process, not to a realm).
      // `workers.count` is a runtime integer in the Global group, so it became
      // the first candidate the day it was added and this walk drove it
      // straight into that refusal — the failure named the source column
      // rather than the setting.
      if (setting.realmSettable === false) {
        return;
      }
      if (setting.type !== "int" && setting.type !== "integer" &&
          typeof setting.value !== "number") {
        return;
      }
      if (!Number.isInteger(setting.value) ||
          setting.value < 1 || setting.value > 100000) {
        return;
      }
      // Not a lifetime: the two narrow doors below drive those, and a value
      // left over from this check would make their refusals ambiguous.
      if (/Ttl|Lifetime|clockSkew/i.test(setting.key)) {
        return;
      }
      chosen = setting;
    });
  });
  log.debug("Leaving runtimeIntegerSetting(). " +
            (chosen ? chosen.key : "(none)"));
  return chosen;
}

// ---------------------------------------------------------------------------
// AND THE HALF THAT IS NOT ABOUT MEMORY: DID THE CHANGE REACH THE STORE?
//
// Setting a value and reading it back proves that something is holding it. What
// /admin/persistence promises is that it was WRITTEN — to an RFC 2849 file per
// realm, or to Postgres — and nothing about the value coming back says whether
// that happened. The store's own account of itself does: a write counter, a
// dirty flag, a failure counter and a last-write timestamp, all in `status`.
//
// A REALM'S overrides and a PROCESS-WIDE one are two different files and two
// different tables, and this checks both, because `configChanged(realmId)` is
// one function with a branch in it and the branch is invisible from either
// side alone.
//
// **A SERVICE IN `memory` MODE IS REPORTED, NOT SKIPPED.** That is the default
// and it is what the containerized stack runs, so most runs of this job will
// meet it — and "the store is off" and "the store did not write" look
// identical from a distance while only one of them is fine. What is asserted
// in that mode is the thing that IS true there: the status must say so, and it
// must not claim a write it did not make.
// ---------------------------------------------------------------------------
async function theConfigurationChangeReachesTheStore(candidate) {
  log.debug("Entering theConfigurationChangeReachesTheStore().");
  log.info("=== Persistence: does a setting change reach the store? ===");
  const before = (await get("/persistence", true)).body.status;
  assert.ok(before && before.mode,
    "GET /admin-api/persistence should carry a `status` member saying what " +
    "the store is actually doing. It is the only operation in its group that " +
    "does, and the reason is that a persistence setting that is SET and a " +
    "store that is WORKING are two different facts.");
  persistenceMode = before.mode;

  if (!before.enabled) {
    assert.strictEqual(before.mode, "memory",
      "a store that is not enabled should be in `memory` mode; it says " +
      before.mode);
    assert.strictEqual(before.persistsAppconfig, false,
      "and it must not claim to persist the appconfig overrides.");
    assert.strictEqual(before.persistsDirectory, false,
      "or the directory.");
    assert.strictEqual(before.writes, 0,
      "and it must not report having WRITTEN anything, which is the one " +
      "claim that would be actively misleading: a mock that reported writes " +
      "it never made would send somebody looking for a file that is not " +
      "there.");
    log.info("[persistence] The store is OFF (persistence.mode=memory), " +
             "which is the default and what the containerized stack runs. " +
             "The value round trip above is asserted; the ON-DISK half is " +
             "not reachable from here and is asserted in mock-sts's own " +
             "tests/appconfig_persistence.js, which drives the store in " +
             "process against a temporary directory.");
    log.debug("Leaving theConfigurationChangeReachesTheStore(). Store off.");
    return;
  }

  assert.strictEqual(before.healthy, true,
    "the store is enabled and reports itself unhealthy: " + before.lastError);
  // WHAT THE STATUS SAYS MUST BE WHAT THIS PROCESS IS CONFIGURED TO DO, and
  // this asserted a constant `false` until 2026-09-07. That was right when it
  // was written — two processes against one database genuinely could not see
  // each other's writes — and it stopped being right on 2026-09-06, when the
  // change log landed and `persistence.coordinate` began turning it on. The
  // constant had quietly become a claim about the CONFIGURATION rather than
  // about the service, and it failed in every mode that switches it on.
  //
  // Read from the settings table rather than assumed either way: the status and
  // the setting are two reports of one fact, and the only assertion that cannot
  // go stale again is that they agree.
  const coordinateSetting = settingValue((await get("/config")).body,
                                         "persistence.coordinate");
  const shouldCoordinate = coordinateSetting === true ||
                           String(coordinateSetting) === "true";
  assert.strictEqual(before.coordinates, shouldCoordinate,
    "the persistence status and persistence.coordinate must agree about " +
    "whether this process coordinates. The setting says " +
    JSON.stringify(coordinateSetting) + " and the status says " +
    before.coordinates + ". Two processes pointed at one database that do " +
    "NOT coordinate each hold their own directory in memory and never see " +
    "each other's writes, so a status wrong in either direction is the one " +
    "sentence somebody deploys against.");

  // A process-wide override, then a realm one. They take different branches
  // and land in different places. The counters are compared as SNAPSHOTS —
  // one status per node — for the reason above settleThenStatus().
  const beforeWrites = await persistenceSnapshot();
  await ok("/config/set",
    { key: candidate.key, value: Number(candidate.value) + 2 },
    "set a process-wide setting to be persisted", true);
  const afterProcess = await settleThenStatus(beforeWrites);
  const wasProcess = comparable(beforeWrites, afterProcess);
  assert.ok(afterProcess.writes > wasProcess.writes,
    "A PROCESS-WIDE SETTING CHANGE MUST REACH THE STORE. persistence.mode=" +
    before.mode + " and persistsAppconfig=" + before.persistsAppconfig +
    ", and the write counter went from " + wasProcess.writes + " to " +
    afterProcess.writes + ". The flush is scheduled rather than immediate, " +
    "so this waited for it; a counter that never moves means the override " +
    "store's slot in config.js is not filled.");
  assert.strictEqual(afterProcess.failures, wasProcess.failures,
    "and the write must have SUCCEEDED. A failure is recorded rather than " +
    "thrown here — a mock that refused to start because a database blinked " +
    "would be the one failure mode a mock must not have — so the failure " +
    "counter is the only thing that says it did not work. It went from " +
    wasProcess.failures + " to " + afterProcess.failures + ": " +
    afterProcess.lastError);
  assert.strictEqual(afterProcess.pending, false,
    "and nothing should still be waiting to be written.");
  assert.strictEqual(Number(settingRow((await get("/config", true)).body,
      candidate.key).value), Number(candidate.value) + 2,
    "and the value the store was told about should be the one the " +
    "configuration resource holds — the write counter says something was " +
    "written and only this says WHAT.");
  await ok("/config/reset", { key: candidate.key },
    "reset the process-wide setting", true);
  assert.notStrictEqual(settingRow((await get("/config", true)).body,
      candidate.key).source, "override",
    "and the process-wide override must be gone again: this section runs " +
    "against the DEFAULT realm, which the throwaway realm's teardown does " +
    "not clean up, so a row left here is a row every later job reads.");

  const beforeRealm = await settleThenStatus(afterProcess);
  await ok("/realms/set",
    { id: REALM, key: "saml.issuer", value: "urn:test:" + REALM + ":stored" },
    "set a REALM setting to be persisted", true);
  const afterRealm = await settleThenStatus(beforeRealm);
  const wasRealm = comparable(beforeRealm, afterRealm);
  assert.ok(afterRealm.writes > wasRealm.writes,
    "A REALM'S OVERRIDES MUST REACH THE STORE TOO, and by a different route: " +
    "config.js decides whether an override is a realm's or the process's, " +
    "and persistence.js is TOLD which — a realm's lives on the realm row and " +
    "a process-wide one in the appconfig store, which are two different " +
    "files and two different tables. The counter went from " +
    wasRealm.writes + " to " + afterRealm.writes);
  assert.strictEqual(afterRealm.failures, wasRealm.failures,
    "and that write must have succeeded too: " + afterRealm.lastError);
  assert.ok(afterRealm.realmsTracked >= 1,
    "and the store should be tracking at least this realm; it tracks " +
    afterRealm.realmsTracked);
  assert.strictEqual(realmSetting(await realmRow(), "saml.issuer"),
    "urn:test:" + REALM + ":stored",
    "and the value that reached the store should be the one the registry " +
    "holds. The counters say a write happened; the registry row says it was " +
    "this write, which is the difference between a store that is working and " +
    "a store that is busy.");

  log.info("[persistence] OK — the store is " + before.mode + " at " +
           (before.dataDir || JSON.stringify(before.database)) + ". A " +
           "process-wide setting change and a realm setting change each " +
           "advanced the write counter with no failure and nothing left " +
           "pending, compared node for node across " + afterRealm.nodes +
           " node(s).");
  log.debug("Leaving theConfigurationChangeReachesTheStore().");
}

// The store's status, after giving a scheduled flush time to happen. The delay
// is `writeDelayMs` — the store's own, read off it rather than guessed — plus a
// margin, and it polls rather than sleeping the whole time so that a fast store
// does not cost the run a second.
//
// **BEHIND A LOAD BALANCER THE COUNTERS ARE EACH NODE'S OWN (2026-09-15, #51).**
// `writes`, `failures` and `pending` are counted by the process that answers,
// and with `STS_TEST_CLUSTER_NODES` above one every request may reach a
// different node — so the AWS cluster run compared node A's counter before
// with node B's after and reported it going from 2880 to 2393, about a store
// that had written the setting. A status read is therefore a SNAPSHOT: one
// status per node, keyed by the instant that node's replication started
// (`replication.startedAt`, which no two processes share), collected until
// every node has answered. `writes` and `failures` are SUMMED over the nodes
// both snapshots saw, so a counter still only ever moves forward and "some
// node wrote" is "the sum went up"; `pending` is any node's. With one node the
// snapshot is the one status read and nothing is summed, so a single-node run
// asserts exactly what it asserted before.
const CLUSTER_NODES =
  Math.max(1, Math.floor(Number(process.env.STS_TEST_CLUSTER_NODES) || 1));

async function persistenceSnapshot() {
  log.debug("Entering persistenceSnapshot().");
  const byNode = {};
  if (CLUSTER_NODES === 1) {
    byNode.self = (await get("/persistence", true)).body.status;
    log.debug("Leaving persistenceSnapshot(). One node.");
    return snapshotOf(byNode);
  }
  // Each read reaches one node the balancer chose, so reading until every
  // node has answered takes more reads than there are nodes; the cap turns a
  // node that never answers into a failure naming how many did.
  const maxReads = CLUSTER_NODES * 25;
  for (let i = 0; i < maxReads &&
       Object.keys(byNode).length < CLUSTER_NODES; i++) {
    const status = (await get("/persistence", true)).body.status;
    const key = status && status.replication && status.replication.startedAt;
    assert.ok(key,
      "IN THE CLUSTER MODE A PERSISTENCE STATUS MUST SAY WHICH PROCESS " +
      "ANSWERED, and this one carries no replication.startedAt — so its " +
      "counters cannot be told apart from another node's. " +
      JSON.stringify(status && status.replication));
    byNode[String(key)] = status;
  }
  assert.strictEqual(Object.keys(byNode).length, CLUSTER_NODES,
    "the persistence status should have been answered by all " +
    CLUSTER_NODES + " node(s) (STS_TEST_CLUSTER_NODES) within " + maxReads +
    " reads, and only " + Object.keys(byNode).length + " answered: " +
    Object.keys(byNode).join(", "));
  log.debug("Leaving persistenceSnapshot(). " + CLUSTER_NODES + " nodes.");
  return snapshotOf(byNode);
}

// The figures the assertions read, from a snapshot — summed over the nodes
// `previous` also saw when it is given, so a node answering only one of the
// two snapshots is never counted against the other.
function snapshotOf(byNode, previous) {
  log.debug("Entering snapshotOf().");
  const keys = Object.keys(byNode).filter(function (key) {
    return !previous || Object.prototype.hasOwnProperty.call(previous.byNode,
                                                             key);
  });
  const statuses = keys.map(function (key) { return byNode[key]; });
  const sum = function (member) {
    return statuses.reduce(function (total, status) {
      return total + Number(status[member] || 0);
    }, 0);
  };
  const failing = statuses.filter(function (status) {
    return status.lastError;
  });
  const snapshot = {
    byNode: byNode,
    nodes: keys.length,
    writes: sum("writes"),
    failures: sum("failures"),
    pending: statuses.some(function (status) { return !!status.pending; }),
    lastError: failing.length ? failing[0].lastError : null,
    realmsTracked: statuses.reduce(function (most, status) {
      return Math.max(most, Number(status.realmsTracked || 0));
    }, 0)
  };
  log.debug("Leaving snapshotOf().");
  return snapshot;
}

// `previous` re-summed over the nodes `current` saw, so the two are compared
// node for node.
function comparable(previous, current) {
  log.debug("Entering comparable().");
  log.debug("Leaving comparable().");
  return snapshotOf(previous.byNode, current);
}

async function settleThenStatus(previous) {
  log.debug("Entering settleThenStatus().");
  const first = previous.byNode[Object.keys(previous.byNode)[0]];
  const budget = Math.max(CLUSTER_NODES === 1 ? 3000 : 20000,
                          Number(first.writeDelayMs || 0) * 3);
  const until = Date.now() + budget;
  let snapshot = previous;
  while (Date.now() < until) {
    await new Promise(function (resolve) { setTimeout(resolve, 150); });
    const read = await persistenceSnapshot();
    snapshot = snapshotOf(read.byNode, previous);
    const was = comparable(previous, snapshot);
    if (!snapshot.pending && snapshot.writes > was.writes) {
      break;
    }
    if (snapshot.failures > was.failures) {
      break;
    }
  }
  log.debug("Leaving settleThenStatus(). writes=" + snapshot.writes +
            ", pending=" + snapshot.pending);
  return snapshot;
}

// ---------------------------------------------------------------------------
// THE LEDGER, ASKED. Both checks read the document and this run's own call
// list, and neither of them drives anything — so they go last, after every
// section above has had its turn.
//
// **`removeRealm` IS THE ONE OPERATION DRIVEN ONLY BY ITS REFUSAL SINCE
// 2026-09-06**, and it needs no exemption row because `post()` records a
// refusal as DRIVEN and not ACCEPTED — theRealmRegistryWorks() asks it to
// remove the realm the call arrived in and it says no. What used to drive it
// for real was the teardown, and there is no teardown: a realm a test run
// created stays, because it is what a person reads when the run went red. So
// the ledger stays honest without a row, and this paragraph is the record that
// the coverage of that one operation is a refusal rather than a removal.
// ---------------------------------------------------------------------------

// The operations this file does not drive, and why. It is a TABLE rather than
// a filter for the reason the rest of this file prefers tables: an exemption
// with no sentence beside it is indistinguishable from an operation somebody
// forgot, which is the whole condition this check exists to end.
//
// **IT IS EMPTY SINCE 2026-09-09, AND THAT IS THE POINT WORTH RECORDING.** It
// held two rows, both the explorer — `GET /docs` and `GET /docs/explorer.js` —
// which answered HTML and JavaScript rather than JSON and were therefore the
// only operations on this API a JSON walk could not drive.
//
// They are not exempt now because they are not here: the explorer moved to the
// admin console (`/admin/api-explorer`) when this API began requiring an
// access token a browser has no way to carry. So every operation this API
// documents answers JSON and every one of them is driven, which is the state
// this table was always an apology for.
//
// The table stays rather than the constant being deleted, because the next
// operation that cannot be driven here needs somewhere to say why — and an
// empty object is a much better prompt for that than no object at all.
const NOT_DRIVEN_HERE = {};

function everyDocumentedOperationWasDriven(doc) {
  log.debug("Entering everyDocumentedOperationWasDriven().");
  log.info("=== The ledger: every documented operation was driven ===");
  const documented = [];
  Object.keys(doc.paths).forEach(function (path) {
    const relative = path.replace(/^\/admin-api/, "");
    ["get", "post"].forEach(function (verb) {
      const operation = doc.paths[path][verb];
      if (!operation) {
        return;
      }
      documented.push({ key: verb.toUpperCase() + " " + relative,
                        operationId: operation.operationId });
    });
  });
  assert.ok(documented.length > 90,
    "the document should declare more than ninety operations; it declares " +
    documented.length + ". A collapse here would make this check pass by " +
    "having almost nothing to ask about, which is the one way a coverage " +
    "check can be worse than no coverage check.");

  const driven = {};
  ledger.forEach(function (call) {
    driven[call.method + " " + call.path] = true;
  });

  const missed = documented.filter(function (operation) {
    return !driven[operation.key] &&
        !Object.prototype.hasOwnProperty.call(NOT_DRIVEN_HERE, operation.key);
  }).map(function (operation) {
    return operation.operationId + "  (" + operation.key + ")";
  });
  assert.deepStrictEqual(missed, [],
    "THESE OPERATIONS ARE DOCUMENTED AND THIS FILE DRIVES NONE OF THEM. The " +
    "walks here are driven off the document — every GET, and every POST that " +
    "carries an example — so an operation that arrives with no example and " +
    "no section of its own is covered by nothing and reported by nothing. " +
    "Either drive it, or put a row in NOT_DRIVEN_HERE saying who does and " +
    "why:\n  " + missed.join("\n  "));

  // And the exemptions must still name real operations. A row left behind
  // after a rename excuses an operation that no longer exists while the one
  // that replaced it goes undriven — which is this check failing open.
  const keys = {};
  documented.forEach(function (operation) { keys[operation.key] = true; });
  const stale = Object.keys(NOT_DRIVEN_HERE).filter(function (key) {
    return !keys[key];
  });
  assert.deepStrictEqual(stale, [],
    "NOT_DRIVEN_HERE names operations this API does not have: " +
    stale.join(", ") + ". A stale exemption excuses an operation that is " +
    "gone and says nothing about the one that replaced it.");

  log.info("[ledger] OK — all " +
           (documented.length - Object.keys(NOT_DRIVEN_HERE).length) +
           " of this API's " + documented.length + " operations were driven " +
           "by this run; the " + Object.keys(NOT_DRIVEN_HERE).length +
           " exempt one(s) are the explorer, which tests/admin_api.js drives.");
  log.debug("Leaving everyDocumentedOperationWasDriven().");
}

// ---------------------------------------------------------------------------
// AND EVERY ACCEPTED WRITE WAS READ BACK THROUGH THE RESOURCE'S OWN GET.
//
// The sections above assert what each write MEANT — that the value is the one
// that was sent, that `add` accumulated where `set` assigned, that `remove`
// took away one thing and left the rest. This asserts the weaker property that
// makes those possible to trust: that a read happened at all, after the write,
// against the resource the write landed on and in the same scope.
//
// It is the check that catches the omission rather than the defect. A section
// added tomorrow that posts four actions and reads none of them would pass
// every other assertion in this file — including the coverage ledger above,
// which only asks whether an operation was DRIVEN — and would be reported as
// four more operations covered.
// ---------------------------------------------------------------------------
function everyAcceptedWriteWasReadBack() {
  log.debug("Entering everyAcceptedWriteWasReadBack().");
  log.info("=== The ledger: every accepted write was read back ===");
  const reads = ledger.filter(function (call) {
    return call.method === "GET" && call.accepted;
  });
  const writes = ledger.filter(function (call) {
    return call.method === "POST" && call.accepted;
  });
  assert.ok(writes.length > 40,
    "this file should have made more than forty accepted writes; it made " +
    writes.length + ". Below that the pairing check is asking about a run " +
    "that did not happen.");

  const unpaired = {};
  writes.forEach(function (write) {
    // `/spiffe/entries/create` is a write on `/spiffe/entries`, and
    // `/spiffe/federation-set` is a write on `/spiffe`: the action is the last
    // segment and the resource is everything before it, which is the same walk
    // documentedActions() does over the document.
    const resource = write.path.split("/").slice(0, -1).join("/");
    const paired = reads.some(function (read) {
      return read.path === resource && read.scope === write.scope &&
          read.at > write.at;
    });
    if (!paired) {
      unpaired["POST " + write.path + " (" + write.scope + ") — nothing read " +
               "GET " + resource + " in that scope afterwards"] = true;
    }
  });
  assert.deepStrictEqual(Object.keys(unpaired).sort(), [],
    "THESE WRITES SUCCEEDED AND NOTHING READ THEM BACK. Every write on this " +
    "API must be confirmed through the resource's own read operation, never " +
    "by believing the write's account of itself: a handler that answers " +
    "`{ok: true}` and changes nothing is the defect this whole file exists " +
    "to catch, and it passes every check that only looks at the reply.\n  " +
    Object.keys(unpaired).sort().join("\n  "));

  log.info("[ledger] OK — all " + writes.length + " accepted writes were " +
           "followed by a read of the resource they wrote, in the scope they " +
           "wrote it in.");
  log.debug("Leaving everyAcceptedWriteWasReadBack().");
}

// ---------------------------------------------------------------------------
// THERE IS NO TEARDOWN, AND THAT IS THE POINT (2026-09-06).
//
// This file used to remove the realm here, and the argument was that a realm
// left behind is one every later job's `GET /realms` can see and that one per
// failing run accumulates. **The operator requirement is the other way round:
// a realm a test run created STAYS, because it is what a person reads when the
// run went red.** Its directory subtree, its applications registry, its
// federation register, its claim sets, its SPIFFE registry, its tokens and its
// overrides are the record of what a hundred and thirty operations actually
// did — and removing it destroyed that record at exactly the moment it was
// worth something.
//
// The accumulation is real and is paid for elsewhere: the id carries
// `names.runStamp()`, so runs never collide, and nothing outside the realm is
// touched, so a service holding ten of these behaves exactly as it did with
// none. They go when the process does — a realm is not persisted unless a
// store is configured — and a person who wants them gone removes them by hand
// or restarts the mock.
// ---------------------------------------------------------------------------
function theThrowawayRealmIsLeftBehind() {
  log.debug("Entering theThrowawayRealmIsLeftBehind().");
  log.info("[teardown] The throwaway realm " + REALM + " is LEFT IN PLACE on " +
           "purpose, with everything this job created inside it. Read it at " +
           base + "/realm/" + REALM + "/admin, or remove it by hand when you " +
           "are done with it.");
  log.debug("Leaving theThrowawayRealmIsLeftBehind().");
}

// ---------------------------------------------------------------------------
// THE CERTIFICATE DETAILS DOOR (2026-09-13): `GET /certificates`, the list and
// one certificate with every field and its trust chain — what `/admin/pki` and
// `/admin/crypto-metadata` open in a dialog.
//
// The generic read walk above already asks the list for a 200. What is worth
// asserting here is what that walk cannot: that a certificate is described
// WHOLE, that its chain is BUILT and ends at the service Root, that the handle
// is a fingerprint in either spelling, and that the realm boundary holds — a
// certificate this realm holds is refused at the default realm's door, which
// is the dialog's version of `verifyLeaf()`'s rule.
// ---------------------------------------------------------------------------
async function theCertificateDetailsAnswer() {
  log.debug("Entering theCertificateDetailsAnswer().");
  log.info("=== The certificate details door ===");
  let list = null;
  let issuing = null;
  const deadline = Date.now() + 20000;
  // The realm's branch is built by a watcher when the realm is created, so it
  // is waited for rather than assumed.
  while (Date.now() < deadline) {
    list = await get("/certificates?per=100");
    issuing = ((list.body && list.body.certificates) || []).filter(function (
        row) {
      return row.appearances.some(function (a) {
        return /Issuing CA \(realm /.test(a.label);
      });
    })[0];
    if (issuing) {
      break;
    }
    await new Promise(function (resolve) { setTimeout(resolve, 250); });
  }
  assert.strictEqual(list.status, 200,
    "GET /certificates should answer the list; it answered " + list.status);
  assert.ok(list.body.certificates.length > 0 &&
            list.body.certificates.every(function (row) {
              return /^[0-9a-f]{64}$/.test(row.fingerprint) &&
                     row.appearances.length > 0;
            }),
    "every row of the certificate list should carry a SHA-256 fingerprint " +
    "and at least one place it appears: " + String(list.raw).slice(0, 400));
  assert.ok(String(list.raw).indexOf("PRIVATE KEY") < 0,
    "the certificate list must carry no private key");
  const root = list.body.certificates.filter(function (row) {
    return row.appearances.some(function (a) {
      return a.label === "Service Root CA";
    });
  })[0];
  assert.ok(root, "the list should include the service Root CA");
  assert.ok(issuing,
    "the list should include an Issuing CA of " + REALM + "'s own branch " +
    "within twenty seconds of the realm being created");

  const rootView = await get("/certificates?certificate=" + root.fingerprint);
  assert.strictEqual(rootView.status, 200,
    "the Root's details should answer 200; it answered " + rootView.status +
    " " + String(rootView.raw).slice(0, 300));
  const rv = rootView.body;
  assert.ok(rv.ok && rv.chain.length === 1 && rv.chainStatus === "complete" &&
            rv.chainTrusted === true && /Root CA/.test(rv.chain[0].anchor),
    "the Root is a one-link chain that ends at itself, trusted as this " +
    "service's Root: " + JSON.stringify({ status: rv.chainStatus,
      trusted: rv.chainTrusted, links: (rv.chain || []).length }));
  const tbs = rv.certificate.fields.tbsCertificate;
  assert.ok(tbs.version.value === 3 &&
            /^[0-9a-f]+$/.test(tbs.serialNumber.hex) &&
            tbs.subject.attributes.length > 0 &&
            tbs.subjectPublicKeyInfo.publicKeyOctets > 0 &&
            rv.certificate.fields.signatureValue.octets > 0 &&
            rv.certificate.fields.signatureAlgorithmsAgree === true,
    "the details should carry the tbsCertificate and the signature whole");
  assert.ok(tbs.extensions.some(function (e) {
    return e.name === "basicConstraints" && e.critical && e.value.ca === true;
  }) && tbs.extensions.some(function (e) {
    return e.name === "keyUsage" && e.value.indexOf("keyCertSign") >= 0;
  }), "the Root's extensions should be decoded, basicConstraints and " +
      "keyUsage among them");
  assert.ok(String(rootView.raw).indexOf("PRIVATE KEY") < 0,
    "a certificate's details must carry no private key");

  const colons = issuing.fingerprint.toUpperCase().match(/.{2}/g).join(":");
  const issuingView = await get("/certificates?certificate=" + colons);
  const iv = issuingView.body;
  assert.ok(issuingView.status === 200 && iv.ok && iv.chain.length === 3 &&
            iv.chainTrusted === true &&
            iv.chain[2].fingerprint === root.fingerprint &&
            iv.chain.every(function (link) {
              return link.signatureValid === true;
            }),
    "an Issuing CA of this realm, named in the colon-separated upper-case " +
    "spelling, should build a trusted three-link chain ending at the " +
    "service Root: " + String(issuingView.raw).slice(0, 400));

  const elsewhere = await get("/certificates?certificate=" +
                              issuing.fingerprint, true);
  assert.strictEqual(elsewhere.status, 404,
    "THE REALM BOUNDARY: an Issuing CA of " + REALM + " should be refused " +
    "404 at the default realm's door, whose catalogue does not hold another " +
    "realm's branch; it answered " + elsewhere.status);
  const malformed = await get("/certificates?certificate=not-a-fingerprint");
  assert.strictEqual(malformed.status, 400,
    "a value that is not a SHA-256 fingerprint should be refused 400; it " +
    "answered " + malformed.status);
  const unknown = await get("/certificates?certificate=" + "0".repeat(64));
  assert.ok(unknown.status === 404 &&
            /No certificate/.test((unknown.body.errors || []).join(" ")),
    "a fingerprint nothing here holds should be refused 404 by name; it " +
    "answered " + unknown.status + " " + String(unknown.raw).slice(0, 200));
  log.info("[certificates] OK — " + list.body.total + " certificate(s) held, " +
           "the Root and a three-link realm chain described and trusted, and " +
           "another realm's certificate refused.");
  log.debug("Leaving theCertificateDetailsAnswer().");
}

// ---------------------------------------------------------------------------
// THE KEY LIST SAYS WHICH KEY PAIRS ARE POST-QUANTUM (2026-09-13) — the `pqc`
// member behind the icon `/admin/keys` draws, so a caller reads the same answer
// the page shows. Every post-quantum signing key row is marked with its kind
// and the RSA and curve keys are not, which is the two halves a classifier
// that marked everything, or nothing, would each get wrong.
// ---------------------------------------------------------------------------
async function theKeyListMarksPostQuantumKeys() {
  log.debug("Entering theKeyListMarksPostQuantumKeys().");
  log.info("=== The key list marks post-quantum key pairs ===");
  const reply = await get("/keys");
  assert.strictEqual(reply.status, 200,
    "GET /keys should answer 200; it answered " + reply.status);
  const rows = reply.body.keys || [];
  const wrong = rows.filter(function (row) {
    const composite = /^ML-DSA-\d+-(ES\d+|Ed\d+)$/.test(row.alg);
    const pure = /^(ML-DSA-\d+|SLH-DSA-)/.test(row.alg) && !composite;
    const kind = row.pqc ? row.pqc.kind : null;
    return !Object.prototype.hasOwnProperty.call(row, "pqc") ||
           kind !== (composite ? "composite" : (pure ? "pq" : null));
  }).map(function (row) {
    return row.alg + " → " + JSON.stringify(row.pqc);
  });
  assert.ok(rows.some(function (row) { return row.pqc; }) &&
            rows.some(function (row) { return row.pqc === null; }),
    "the key list should hold both marked and unmarked key pairs: " +
    String(reply.raw).slice(0, 300));
  assert.deepStrictEqual(wrong, [],
    "every key row should carry `pqc` — `pq` for ML-DSA and SLH-DSA, " +
    "`composite` for the six composites, null for RSA and the curves — and " +
    "these do not: " + wrong.join("; "));
  log.info("[keys/pqc] OK — " + rows.filter(function (row) {
    return row.pqc;
  }).length + " of " + rows.length + " key pairs marked post-quantum.");
  log.debug("Leaving theKeyListMarksPostQuantumKeys().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving every operation of the management API at " + rootApi);
  if (!(await theServiceIsThere())) {
    log.info("Skipped: no STS mock at " + base + ".");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const doc = (await get("/openapi.json", true)).body;
  assert.ok(doc && doc.paths,
    "GET /admin-api/openapi.json should answer the document; this file " +
    "drives every operation off it and asserts almost nothing without one.");

  await theRealmRegistryWorks();
  try {
    await theRefusalSentencesAreHonest(doc);
    await everyDocumentedExampleIsAccepted(doc);
    await everyReadAnswersAboutThisRealm(doc);
    await theApplicationsRegistryRoundTrips();
    await theObservedReturnAddressesAreDecided();
    await theDelegatedPermissionsRoundTrip();
    await theClaimSetDoorsRoundTrip();
    await theFederationRegisterRoundTrips();
    await theSamlRegistriesRoundTrip();
    await theAuthorizationServerProfilesRoundTrip();
    await theCredentialResourcesRoundTrip();
    await theSpiffeDoorsRoundTrip();
    await theTokenDoorsRoundTrip();
    await theIssuedListGroupsByIssuance();
    await theDirectoryAndSignOutDoorsRoundTrip();
    await theAdminRolesRoundTrip();
    await theTruststoreRoundTrips();
    await theCertificateDetailsAnswer();
    await theKeyListMarksPostQuantumKeys();
    await theKerberosPrincipalsRoundTrip();
    const candidate = await theConfigurationDoorsRoundTrip(doc);
    await theConfigurationChangeReachesTheStore(candidate);
    await theRootIsReplacedLast(doc);
    everyDocumentedOperationWasDriven(doc);
    everyAcceptedWriteWasReadBack();
  } finally {
    theThrowawayRealmIsLeftBehind();
  }
  log.info("Test completed successfully. The store was in `" +
           persistenceMode + "` mode for this run.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_admin_api_operations")
  .description("Drive every operation of the mock STS's management API at " +
      "/admin-api for real: replay each documented example, round-trip each " +
      "write through a read, and check that a configuration change reaches " +
      "the persistence store.")
  // Accepted and ignored: run-report.js passes --url to every job, and
  // tests/jwk_pem_encoding.js fails the suite if a job does not declare it.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
