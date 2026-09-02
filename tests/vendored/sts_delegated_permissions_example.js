// File: sts_delegated_permissions_example.js
//
// ---------------------------------------------------------------------------
// FIVE APPLICATIONS IN A RING, EACH REACHING EXACTLY THE NEXT ONE'S API — THE
// DELEGATED PERMISSION FEATURE MADE READABLE, LEFT STANDING IN THE DEFAULT
// REALM FOR SOMEBODY TO LOOK AT.
//
// `abcapp1` … `abcapp5` are created here, declared for OAuth 2.0 and OpenID
// Connect, each one exposing `read` and `write` under a base URI of its own
// (`https://abcapp1.example1.com/` and so on). Then each is GRANTED both
// permissions on THE NEXT ONE ROUND: abcapp1 → abcapp2, abcapp2 → abcapp3,
// abcapp3 → abcapp4, abcapp4 → abcapp5, and abcapp5 → abcapp1. Five ordered
// pairs, two permissions each, TEN GRANTS between FIVE applications, with no
// application granted its own.
//
// WHY A RING AND NOT A COMPLETE MESH — it was a mesh of forty grants until
// 2026-09-01, and the change is worth its paragraph because the mesh was the
// stronger test and the weaker EXAMPLE, and this file is both.
//
// What the mesh bought was that every reading of the register was non-trivial
// at once: a lookup that quietly matched on a prefix, a host or the bare name
// was wrong thirty-six times out of forty. The ring keeps almost all of that
// and loses one part of it — see the two paragraphs below — while buying
// something the mesh could not have: a picture somebody can READ. Forty lines
// between five boxes is every box joined to every other, which is the one
// graph shape that looks the same however it is drawn and however it is
// wrong; five lines round a circle is a shape a person can check by eye
// against the sentence above, and the whole reason this example is left
// standing is that somebody opens `/admin/delegation/allowed` and looks at it.
//
// It is also the shape the feature is FOR. A complete mesh is not an
// arrangement anybody configures; a chain of services each calling the next
// on the signed-in person's behalf is exactly what a delegated permission is
// for, and the ring is that chain with its ends joined so that no application
// is a special case.
//
// WHAT THE RING STILL DISCRIMINATES, which is the part that matters for it
// being a test at all: every grant here still has to resolve to ONE resource
// out of FIVE, and the five bases differ only in a digit
// (`https://abcapp3.example1.com/`). A lookup matching on a prefix or on the
// bare name is wrong for four of the five pairs — abcapp1's `read` grant must
// resolve to abcapp2 and to none of the other four. What it no longer proves
// is the count: with one grant per pair per permission there is no pair for
// which a fold could halve anything, so `theAttributesLandOnTheRightEntries()`
// below carries the weight instead, asserting the EXACT list each entry holds
// rather than only its length.
//
// ---------------------------------------------------------------------------
// IT WRITES TO THE **DEFAULT REALM** AND IT DOES NOT CLEAN UP, AND BOTH ARE
// DELIBERATE — WHICH MAKES THIS THE ONE JOB IN THIS DIRECTORY THAT BREAKS THE
// CONVENTION `sts_admin_api_operations.js` ARGUES AT LENGTH.
//
// That job does everything inside a throwaway realm and removes it in a
// `finally`, because a realm left behind is a realm every later `GET /realms`
// can see. The reasoning is right and it does not reach this file, because
// what this file produces is not a side effect of a test — IT IS THE POINT.
// The example exists to be READ: `/admin/delegation/allowed`, which carries
// both the register and the picture drawn from it — `?format=svg` on that same
// path is the drawing on its own — and each entry's own drill-down on
// `/admin/applications`. A realm this job deleted on its way out would be an
// example nobody could open, and a picture drawn in a realm somebody has to
// know the name of is a picture nobody will find.
//
// Two things pay for that decision rather than merely excusing it:
//
//   * **IT IS IDEMPOTENT.** The identifiers are FIXED — `abcapp1` is the whole
//     point, and a run-stamped name would be five applications nobody asked
//     for — so a second run against the same service would otherwise meet
//     "already in this registry" five times. Every previous `abcapp*` is
//     forgotten before anything is created, which also means a run against a
//     service left up by `./local-run-tests.sh` starts from the same state as
//     a run against a fresh container.
//   * **NOTHING ELSE IN THE SUITE COUNTS APPLICATIONS.** The registry is
//     append-only from every other job's point of view: no job asserts a total,
//     and this one adds five entries under identifiers nothing else uses. It
//     runs after `sts_admin_console.js` in the manifest so that the console's
//     own coverage walks the console it has always walked.
//
// ---------------------------------------------------------------------------
// WHAT IT ASSERTS, AND WHY EACH ONE IS NOT ALREADY COVERED.
//
// `sts_admin_api_operations.js` drives all five permission operations — the
// base, define, remove, grant, revoke, both refusals and the ordering rule —
// against ONE resource and ONE client. Everything below is a property of the
// register that a single pair cannot exhibit:
//
//   * **THE TWO HALVES LAND ON TWENTY DIFFERENT ATTRIBUTE VALUES AND THE
//     REGISTER READS THEM BACK AS ONE THING.** Ten permissions on five entries,
//     ten grants spread two to an entry, and the register resolving every
//     grant to the entry that exposes it. A lookup that quietly matched on
//     something other than the whole identifier — a prefix, a host, the name
//     alone — is right for one pair and wrong here for four of the five, since
//     the five bases differ only in a digit.
//   * **EACH ENTRY HOLDS EXACTLY ITS SUCCESSOR'S TWO AND NOTHING ELSE**,
//     asserted as the exact list rather than as a count. This is the assertion
//     that carries the weight the mesh's arithmetic used to: `abcapp2` holding
//     `abcapp4`'s `read` would be a register that granted the wrong pair, and
//     no count anywhere would notice.
//   * **NO APPLICATION HOLDS ITS OWN PERMISSION**, asserted over the whole ring
//     rather than as one refusal. The refusal is driven as well, because the
//     ring being clean is only evidence that this file's own loop skipped the
//     diagonal.
//   * **THE PICTURE.** Five boxes, ten lines, `may-reach` on every one of
//     them, and `acts` zero everywhere — a configured grant has been exercised
//     nought times, and the renderer colours an edge as REFUSED when `acts &&
//     !issued`. Ten lines is where a graph that collapsed a pair of
//     applications into one edge would show up as five.
//   * **THE TOKEN, WHICH IS THE ONLY PLACE ANY OF IT CHANGES WHAT A CLIENT
//     RECEIVES.** `abcapp1` asks for two of `abcapp2`'s permissions — its own
//     successor, which is the only application it holds anything on — and gets
//     an access token audienced to `https://abcapp2.example1.com/` carrying the
//     BARE names on its scope claim. With five bases in the register this also
//     asserts that it picked the right one, which one resource cannot.
//
// WHAT IT DELIBERATELY DOES NOT DO IS TURN ENFORCEMENT ON.
// `oauth2.delegatedPermissionsEnforced` is off by default and turning it on
// here would mean changing a setting in the DEFAULT realm — process-wide state,
// in the realm every other job in this run uses, for a refusal that belongs
// beside the other refusals in `sts_admin_api_operations.js`'s throwaway realm.
// This file asserts the default contract instead: the grant is a QUESTION and
// the token is issued either way.
//
// Needs the STS mock and nothing else — no browser, no Keycloak.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Command, Option } = require("commander");
const common = require("./jwt_vc_json_common.js");

var appconfig;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_delegated_permissions_example",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

// THE DEFAULT REALM'S DOORS, and there is no second scope in this file. The
// default realm has an EMPTY prefix, which is why these two read as though
// realms did not exist — see common/realms.js.
var api = base + "/admin-api";
var tokenEndpoint = base + "/oauth2/token";

// ---------------------------------------------------------------------------
// THE EXAMPLE ITSELF, as data rather than as five sections of code. Everything
// below is derived from these three constants, so the ring cannot disagree with
// the assertions about it — the failure a hand-written expectation invites is a
// test that asserts the loop it was copied from.
// ---------------------------------------------------------------------------
const APPS = [1, 2, 3, 4, 5].map(function (n) {
  return {
    id: "abcapp" + n,
    n: n,
    name: "ABC App " + n,
    // The base URI a client puts in front of a permission name. It ENDS IN A
    // SEPARATOR here on purpose even though the service would add one:
    // normalisation is `sts_admin_api_operations.js`'s assertion, and a base
    // written the long way makes every expected identifier in this file a
    // plain concatenation that can be read at a glance.
    baseUri: "https://abcapp" + n + ".example1.com/"
  };
});

// `read` and `write`, with a description on each — the `name|description`
// spelling is the schema's and this file never writes it, which is the point of
// the two-argument operation.
const PERMISSIONS = [
  { name: "read",
    description: "Read this application's data on the signed-in person's behalf" },
  { name: "write",
    description: "Change this application's data on the signed-in person's behalf" }
];

// THE RING, AS ONE FUNCTION, and it is the only place in this file that
// decides who reaches whom. `abcapp1 -> abcapp2 -> abcapp3 -> abcapp4 ->
// abcapp5 -> abcapp1`: the successor of the LAST application is the FIRST,
// which is what closes the ring and is what stops any one of the five being a
// special case with nothing granted on it or nothing granted to it.
//
// The modulus is over `APPS.length` rather than over the literal 5 so that
// adding a sixth application to `APPS` extends the ring rather than leaving
// `abcapp6` outside it — the failure a hand-written pair list invites.
function successorOf(app) {
  return APPS[(APPS.indexOf(app) + 1) % APPS.length];
}

// The client this file spends a token as, and the resource it spends it on.
// SPENT_ON IS DERIVED FROM SPENDER rather than written down beside it, and
// that is load-bearing now that the graph is a ring: abcapp1 holds permissions
// on abcapp2 and on NOBODY ELSE, so naming any other application here would be
// a test asking the token endpoint for a permission this example never granted
// — which, with `oauth2.delegatedPermissionsEnforced` off, would still mint a
// token and still pass the audience assertion while proving nothing.
const SPENDER = APPS[0];
const SPENT_ON = successorOf(SPENDER);

function permissionId(app, name) {
  return app.baseUri + name;
}

// Every (client, resource, permission) this file intends to create. Five
// ordered pairs and two permissions each — the diagonal cannot occur, because
// no application is its own successor and `updateApplication()` would refuse
// one anyway.
function intendedGrants() {
  log.debug("Entering intendedGrants().");
  const out = [];
  APPS.forEach(function (client) {
    const resource = successorOf(client);
    PERMISSIONS.forEach(function (permission) {
      out.push({ client: client.id, resource: resource.id,
                 permission: permission.name,
                 id: permissionId(resource, permission.name) });
    });
  });
  log.debug("Leaving intendedGrants(). " + out.length + " grant(s).");
  return out;
}

// ---------------------------------------------------------------------------
// THE THREE VERBS. Copied in shape from sts_admin_api_operations.js rather than
// imported from it: that file is a job and not a helper, and a require between
// two jobs would make the manifest's job/helper split untrue.
// ---------------------------------------------------------------------------
async function get(path) {
  log.debug("Entering get(). path=" + path);
  const r = await common.httpJson(api + path);
  log.debug("Leaving get(). status=" + r.status);
  return r;
}

async function post(path, body) {
  log.debug("Entering post(). path=" + path);
  const r = await common.httpJson(api + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {})
  });
  log.debug("Leaving post(). status=" + r.status);
  return r;
}

// A POST that must succeed. The failure quotes the service's own refusal, which
// is a sentence written for a person and is most of the diagnosis.
async function ok(path, body, what) {
  log.debug("Entering ok(). path=" + path);
  const r = await post(path, body);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + path + " should have " + what + "; it answered " + r.status +
    " " + JSON.stringify((r.body && r.body.errors) || r.body).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

// A POST that must be REFUSED, and refused for a stated reason: a 400 alone is
// not evidence that the refusal was the intended one.
async function refused(path, body, expect, what) {
  log.debug("Entering refused(). path=" + path);
  const r = await post(path, body);
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
// Nothing listening is an ordinary state — half the jobs in this suite drive
// something else entirely. A service that ANSWERS and has no /admin-api on it
// is not: that is a checkout older than the feature, and a skip there would
// report this example green having created none of it.
// ---------------------------------------------------------------------------
async function theServiceIsThere() {
  log.debug("Entering theServiceIsThere().");
  let reply;
  try {
    reply = await common.httpJson(api + "/status");
  } catch (e) {
    log.warn("No STS is listening at " + base + " (" + e.message + "). " +
             "Skipping: this job needs the mock and nothing else.");
    log.debug("Leaving theServiceIsThere(). Nothing listening.");
    return false;
  }
  assert.strictEqual(reply.status, 200,
    "GET " + api + "/status answered " + reply.status + ". A service is " +
    "listening at " + base + " and has no management API on it, which is " +
    "almost always a checkout older than /admin-api. This is a FAILURE and " +
    "not a skip.");
  log.info("[service] OK — " + base + " answers.");
  log.debug("Leaving theServiceIsThere(). It is there.");
  return true;
}

// ---------------------------------------------------------------------------
// STEP 0: FORGET ANY PREVIOUS COPY OF THE EXAMPLE.
//
// The identifiers are fixed, so this is what makes a second run against the
// same service — the one `./local-run-tests.sh` now leaves up — start from the
// state a fresh container starts from. `forget` is the one operation in this
// API that loses a fact, and losing this one is the intention.
//
// A refusal is IGNORED and not asserted about, because the ordinary case is
// that there is nothing there: "no application called abcapp1" is the expected
// answer on a fresh service and the expected answer is not a failure.
// ---------------------------------------------------------------------------
async function forgetAnyPreviousExample() {
  log.debug("Entering forgetAnyPreviousExample().");
  log.info("=== Removing any abcapp1-5 left by an earlier run ===");
  let removed = 0;
  for (const app of APPS) {
    const reply = await post("/applications/forget", { application: app.id });
    if (reply.status === 200 && reply.body && reply.body.ok !== false) {
      removed++;
    }
  }
  const left = await registryEntry(APPS[0].id);
  assert.strictEqual(left.found, false,
    "after `forget`, " + APPS[0].id + " should not be in the registry — this " +
    "job creates five entries under FIXED identifiers, so a leftover entry " +
    "from an earlier run would be configured twice and every count below " +
    "would be about two examples at once.");
  log.info("[cleanup] OK — " + removed + " of " + APPS.length +
           " were there from an earlier run and are gone.");
  log.debug("Leaving forgetAnyPreviousExample().");
}

// ---------------------------------------------------------------------------
// STEP 1: THE FIVE APPLICATIONS, WITH THE SUPPORTING FIELDS FILLED IN.
//
// Each is declared for `oauth2` AND `oidc` — two families, because a
// confidential web application that asks for an ID Token is both and the
// registry keeps the declaration as a list rather than a kind. The rest of the
// fields are what such an application really carries: the client_id, two
// redirect URIs, a post-logout URI, front-channel logout with the session
// required, the grant and response types, a token endpoint authentication
// method with a secret to go with it, the four token lifetimes and the group
// claim mapping.
//
// **`oauthScope` IS DELIBERATELY NOT SET, AND THAT IS THE ONE TRAP IN THIS
// FUNCTION.** It records the scopes an application HAS ASKED FOR — it is the
// only evidence in this registry that a grant was ever used, and it is what
// `register()` reads to mark a grant `asked`. Seeding it would make all ten
// grants read as exercised before anything had been issued, which is exactly
// the distinction between a CONFIGURED register and an OBSERVED one that this
// whole feature exists to draw. The token minted at the end is what writes it,
// on two grants out of ten.
// ---------------------------------------------------------------------------
async function createTheFiveApplications() {
  log.debug("Entering createTheFiveApplications().");
  log.info("=== Creating abcapp1-5 in the DEFAULT realm ===");
  for (const app of APPS) {
    const host = "abcapp" + app.n + ".example1.com";
    await ok("/applications/create", {
      identifier: app.id,
      name: app.name,
      protocols: ["oauth2", "oidc"],
      fields: {
        oauthClientId: app.id,
        description: [
          app.name + " — one of five applications in the delegated permission " +
          "example. It exposes read and write on " + app.baseUri + " and holds " +
          "both permissions on " + successorOf(app).id + ", the next one round " +
          "the ring."
        ],
        oauthRedirectUri: [
          "https://" + host + "/oauth2/callback",
          "https://" + host + "/oidc/callback"
        ],
        oauthPostLogoutRedirectUri: ["https://" + host + "/signed-out"],
        oauthFrontchannelLogoutUri: "https://" + host + "/oidc/frontchannel-logout",
        oauthFrontchannelLogoutSessionRequired: "TRUE",
        oauthGrantType: ["authorization_code", "refresh_token", "client_credentials"],
        oauthResponseType: ["code"],
        oauthTokenEndpointAuthMethod: "client_secret_post",
        // A mock's secret, and it is checked nowhere unless RFC 9700 mode is
        // on — the entry carries it so the application reads as the
        // confidential client it is declared to be.
        oauthClientSecret: app.id + "-not-a-real-secret",
        oauthConfidential: "TRUE",
        oauthAccessTokenTtlS: "900",
        oauthIdTokenTtlS: "600",
        oauthRefreshTokenTtlS: "86400",
        oauthRefreshIdleSeconds: "3600",
        oauthRevokeRefreshOnLogout: "TRUE",
        appGroupsClaim: "TRUE",
        appGroupsClaimName: "groups",
        appGroupsClaimValue: "cn",
        appGroupsClaimFromMemberOf: "TRUE"
      }
    }, "created " + app.id);
  }

  // READ BACK THROUGH THE REGISTRY'S OWN GET, never through the create's
  // account of itself: a handler that answers `{ok: true}` and writes nothing
  // passes every check that only looks at the reply.
  for (const app of APPS) {
    const entry = await registryEntry(app.id);
    assert.strictEqual(entry.found, true,
      app.id + " should be in the registry after `create`.");
    assert.deepStrictEqual(fieldValues(entry, "appAllowedProtocol"),
      ["oauth2", "oidc"],
      "and it should be DECLARED for both families, in the registry's own " +
      "order — `appAllowedProtocol` is what somebody ticked, kept apart from " +
      "`appProtocol`, which is what has actually been seen.");
    assert.deepStrictEqual(fieldValues(entry, "appProtocol"), [],
      "AND `appProtocol` SHOULD BE EMPTY: nothing has connected as " + app.id +
      " yet. A create that wrote the observed list as well would make five " +
      "entries claim a past they do not have.");
    assert.deepStrictEqual(fieldValues(entry, "oauthScope"), [],
      "and it should have asked for no scope yet — that attribute is what " +
      "marks a grant as USED, and a seeded one would make the whole ring " +
      "read as exercised before a token existed.");
    assert.strictEqual(fieldValues(entry, "oauthRedirectUri").length, 2,
      "and both redirect URIs should be on it: a single-valued write here " +
      "would keep one and lose the other silently.");
  }
  log.info("[create] OK — five applications, declared for OAuth 2.0 and " +
           "OpenID Connect, with their supporting fields written and read back.");
  log.debug("Leaving createTheFiveApplications().");
}

// ---------------------------------------------------------------------------
// STEP 2: EACH ONE EXPOSES `read` AND `write` UNDER A BASE URI OF ITS OWN.
//
// The base first and the permissions after it, because a permission defined on
// an application with no base has no identifier and no client can ever ask for
// it — a state the register reports rather than hides, and one this example has
// no reason to be in.
// ---------------------------------------------------------------------------
async function exposeReadAndWrite() {
  log.debug("Entering exposeReadAndWrite().");
  log.info("=== Exposing read and write on each of the five ===");
  for (const app of APPS) {
    await ok("/permissions/set-permission-base",
      { resource: app.id, baseUri: app.baseUri },
      "set " + app.id + "'s permission base URI");
    for (const permission of PERMISSIONS) {
      await ok("/permissions/define-permission",
        { resource: app.id, name: permission.name,
          description: permission.description },
        "defined " + permission.name + " on " + app.id);
    }
  }

  const register = await permissionRegister();
  const ours = register.permissions.filter(function (one) {
    return isOurs(one.resource);
  });
  assert.strictEqual(ours.length, APPS.length * PERMISSIONS.length,
    "the register should report ten permissions across the five " +
    "applications; it reported " + ours.length + ".");
  const identifiers = ours.map(function (one) { return one.id; }).sort();
  const expected = [];
  APPS.forEach(function (app) {
    PERMISSIONS.forEach(function (permission) {
      expected.push(permissionId(app, permission.name));
    });
  });
  assert.deepStrictEqual(identifiers, expected.sort(),
    "AND EACH IDENTIFIER SHOULD BE ITS OWN APPLICATION'S BASE FOLLOWED BY THE " +
    "NAME. Ten identifiers over five bases is where a lookup that joined the " +
    "wrong pair — the first base, the last one, the client's rather than the " +
    "resource's — stops being invisible; with one resource every wrong answer " +
    "is also the right one.");
  assert.ok(ours.every(function (one) { return !one.grantedTo.length; }),
    "and NOTHING should hold any of them yet: defining a permission grants it " +
    "to nobody, which is the ordering this whole feature is built on.");
  assert.ok(ours.every(function (one) { return !!one.description; }),
    "and every one should carry its description, which is written as " +
    "`name|description` on the entry and split back out by the register — a " +
    "join this file never spells for itself.");
  log.info("[expose] OK — ten permissions, two on each of five bases, held " +
           "by nobody.");
  log.debug("Leaving exposeReadAndWrite().");
}

// ---------------------------------------------------------------------------
// STEP 3: THE RING. Every application granted both permissions on its
// SUCCESSOR — and the diagonal REFUSED rather than merely skipped.
//
// The refusal is driven first, while it is the only thing that could be
// producing an empty diagonal. Once the ring is up, "abcapp1 does not hold its
// own permission" is equally consistent with a service that refuses it and one
// whose loop never asked, and the assertion at the end would prove nothing
// about the service at all. That is a stronger reason here than it was under
// the mesh: a ring's loop never even considers the diagonal, so without this
// refusal nothing in the file would touch it.
// ---------------------------------------------------------------------------
async function grantTheRing() {
  log.debug("Entering grantTheRing().");
  log.info("=== Granting the ring: five successor pairs, two permissions each ===");

  await refused("/permissions/grant-permission",
    { client: SPENDER.id, permission: permissionId(SPENDER, "write") },
    /DEFINES|itself/i,
    "an application being granted its own permission — the access token " +
    "would be addressed to the party that asked for it, and the picture " +
    "would draw a line from a box back to the same box");

  const intended = intendedGrants();
  for (const one of intended) {
    await ok("/permissions/grant-permission",
      { client: one.client, permission: one.id },
      "granted " + one.client + " " + one.id);
  }
  log.info("[grant] OK — " + intended.length + " grants made, " +
           APPS.map(function (app) {
             return app.id + "->" + successorOf(app).id;
           }).join(", ") + ".");
  log.debug("Leaving grantTheRing().");
}

// ---------------------------------------------------------------------------
// THE REGISTER, READ AS ONE THING. This is what five applications buy over one
// pair: every assertion here is about a grant resolving to the RIGHT resource
// among five, which a register with one resource in it cannot get wrong.
// ---------------------------------------------------------------------------
async function theRegisterReadsBackAsARing() {
  log.debug("Entering theRegisterReadsBackAsARing().");
  log.info("=== The register: ten grants, five resources, nothing dangling ===");
  const register = await permissionRegister();

  const ours = register.grants.filter(function (one) {
    return isOurs(one.client);
  });
  const intended = intendedGrants();
  assert.strictEqual(ours.length, intended.length,
    "the register should report " + intended.length + " grants among the " +
    "five; it reported " + ours.length + ". TWO GRANTS BETWEEN TWO " +
    "APPLICATIONS ARE TWO ROWS — the permission is the relationship and the " +
    "pair is what it happens to join — so a register that folded a pair into " +
    "one row would report half of these.");

  // Every intended triple is there, matched on all three members at once. A
  // check that counted rows and looked no further would pass on a service that
  // granted every one of the ten to abcapp1.
  const seen = {};
  ours.forEach(function (one) {
    seen[one.client + " -> " + one.resource + " : " + one.permissionId] = one;
  });
  const missing = intended.filter(function (one) {
    return !seen[one.client + " -> " + one.resource + " : " + one.id];
  }).map(function (one) {
    return one.client + " -> " + one.id;
  });
  assert.deepStrictEqual(missing, [],
    "EVERY APPLICATION SHOULD HOLD BOTH OF ITS SUCCESSOR'S PERMISSIONS, and " +
    "each grant should resolve to the application that EXPOSES it rather than " +
    "to some other one with a similar base — the five bases here differ only " +
    "in a digit, so a lookup matching on a prefix or on the bare name lands " +
    "on the wrong one of the five. These did not: " + missing.join(", "));

  assert.ok(ours.every(function (one) { return !one.dangling; }),
    "and not one of them should be dangling — a dangling grant names a " +
    "permission nothing defines, and every one of these was granted after the " +
    "permission was defined.");
  assert.deepStrictEqual(ours.filter(function (one) {
    return one.client === one.resource;
  }), [], "AND NO APPLICATION HOLDS ITS OWN PERMISSION, over the whole ring " +
          "rather than over the one pair the refusal above covers.");

  // The counts the console draws its summary from, checked against the ring
  // rather than against themselves. `unused` is the one that makes a configured
  // register worth having beside an observed one: ten grants, none of them
  // asked for yet.
  const counts = register.counts || {};
  assert.ok(counts.resources >= APPS.length,
    "the register should count at least our five resources; it said " +
    counts.resources + ".");
  assert.strictEqual(ours.filter(function (one) { return one.asked; }).length, 0,
    "AND NONE OF THEM SHOULD READ AS ASKED FOR YET. That column comes from " +
    "what HAPPENED — `oauthScope` on the client's entry — and it is the whole " +
    "difference between this register and the acts register next door. One " +
    "token at the end of this file moves exactly two of these.");
  log.info("[register] OK — " + ours.length + " grants, every successor pair " +
           "present, none dangling, none self-directed, none yet used.");
  log.debug("Leaving theRegisterReadsBackAsARing().");
}

// ---------------------------------------------------------------------------
// AND THE TWO HALVES ARE ON THE RIGHT ENTRIES, read through the APPLICATIONS
// registry rather than through the register that joins them.
//
// The failure this guards against is easy to write and invisible from
// `/permissions`: a grant put on the RESOURCE instead of the client. The
// register would resolve it either way — it walks both attributes — while every
// lookup at the token endpoint found nothing, because the entry a token request
// identifies is the CLIENT's.
// ---------------------------------------------------------------------------
async function theAttributesLandOnTheRightEntries() {
  log.debug("Entering theAttributesLandOnTheRightEntries().");
  log.info("=== The entries: two permissions exposed and two grants held ===");
  for (const app of APPS) {
    const entry = await registryEntry(app.id);
    assert.deepStrictEqual(fieldValues(entry, "oauthPermissionBaseUri"),
      [app.baseUri],
      "the base URI belongs on the application that EXPOSES the API, and it " +
      "should be " + app.id + "'s own.");
    assert.deepStrictEqual(
      fieldValues(entry, "oauthPermission").slice().sort(),
      PERMISSIONS.map(function (one) {
        return one.name + "|" + one.description;
      }).sort(),
      "and so do the permissions, one value each, with the description after " +
      "the first `|` — the spelling an ldapmodify has to match.");

    // THE EXACT LIST AND NOT ITS LENGTH, and since 2026-09-01 this is the
    // assertion that carries the weight the mesh's arithmetic used to. In a
    // ring each entry holds exactly TWO values and there are ten in the
    // register, so a service that granted the wrong pair — abcapp2 holding
    // abcapp4's `read` — would have the right count everywhere and be wrong
    // about the only thing this example says. deepStrictEqual on the sorted
    // list is what refuses that.
    const held = fieldValues(entry, "oauthDelegatedPermission").slice().sort();
    const next = successorOf(app);
    const expected = PERMISSIONS.map(function (permission) {
      return permissionId(next, permission.name);
    });
    assert.deepStrictEqual(held, expected.sort(),
      "THE GRANTS BELONG ON THE CLIENT, as whole permission identifiers, and " +
      app.id + " should hold exactly " + next.id + "'s two — its successor " +
      "round the ring — and NOTHING ELSE: not its own, and not any of the " +
      "three applications it does not reach. That is the entry a token " +
      "request identifies, so it is the entry that has to answer whether the " +
      "request may be honoured.");
  }
  log.info("[entries] OK — each entry exposes its own two and holds exactly " +
           "its successor's two.");
  log.debug("Leaving theAttributesLandOnTheRightEntries().");
}

// ---------------------------------------------------------------------------
// THE PICTURE. `GET /admin-api/permissions` carries the same `{nodes, edges}`
// the console hands to the renderer, so the drawing can be asserted without a
// browser — which is what makes this worth checking at all, given that the
// reason the example exists is for somebody to LOOK at it.
//
// Every assertion here is about the difference between a CONFIGURED picture and
// the acts picture next door, which is drawn by the same renderer from the same
// shape: nothing has happened yet, so nothing may be coloured as though it had.
// ---------------------------------------------------------------------------
async function thePictureIsARingAndNotAnActsDiagram() {
  log.debug("Entering thePictureIsARingAndNotAnActsDiagram().");
  log.info("=== The graph: five boxes, ten lines, nothing exercised ===");
  const register = await permissionRegister();
  const graph = register.graph;
  assert.ok(graph && Array.isArray(graph.nodes) && Array.isArray(graph.edges),
    "GET /admin-api/permissions should carry the graph the console draws; it " +
    "carried " + JSON.stringify(graph).slice(0, 200));

  const nodes = graph.nodes.filter(function (one) { return isOurs(one.id); });
  const edges = graph.edges.filter(function (one) {
    return isOurs(one.from) && isOurs(one.to);
  });
  assert.strictEqual(nodes.length, APPS.length,
    "five applications should be five boxes; the graph had " + nodes.length +
    " of ours.");
  assert.strictEqual(edges.length, intendedGrants().length,
    "AND TEN GRANTS SHOULD BE TEN LINES — one edge per PERMISSION and not " +
    "one per pair. Five here would mean the picture had folded `read` and " +
    "`write` between the same two applications into one line labelled `2`, " +
    "which hides the only thing the picture is being asked.");
  assert.ok(edges.every(function (one) { return one.relation === "may-reach"; }),
    "and every line should be `may-reach` rather than `reaches` — that word " +
    "is the acts picture's claim that a credential was ISSUED for something, " +
    "and nothing here has been issued.");
  assert.ok(edges.every(function (one) { return one.acts === 0; }) &&
            nodes.every(function (one) { return one.acts === 0; }),
    "AND `acts` SHOULD BE ZERO ON EVERY BOX AND EVERY LINE. The renderer " +
    "colours an edge RED when `acts && !issued` — its way of saying `this was " +
    "tried and refused` — and a configured grant has been tried nought times, " +
    "so a non-zero count here would draw ten refusals that never happened.");
  assert.ok(nodes.every(function (one) { return one.selfTarget === false; }),
    "and no box should be marked as its own target: the diagonal was refused.");
  assert.ok(nodes.every(function (one) { return one.dangling === 0; }),
    "and none should carry a dangling grant.");
  assert.ok(nodes.every(function (one) {
    return one.grants === PERMISSIONS.length;
  }), "EVERY BOX SHOULD HOLD TWO AND EXPOSE TWO, which is what makes a ring " +
      "symmetrical and is the arithmetic a reader checks the picture " +
      "against — every application is somebody's successor exactly once, " +
      "which is the property that closing the ring buys. It reported: " +
      JSON.stringify(nodes.map(function (one) {
        return one.id + ":" + one.grants + "/" + one.exposes;
      })));
  assert.ok(nodes.every(function (one) {
    return one.exposes === PERMISSIONS.length;
  }), "and the same two from the other side — ONE client holding two " +
      "permissions on it. A box exposing nothing would be an application " +
      "nobody reaches, which in a ring means the ends were never joined.");
  log.info("[picture] OK — " + nodes.length + " boxes and " + edges.length +
           " lines round the ring, every one of them `may-reach` and none of " +
           "them exercised.");
  log.debug("Leaving thePictureIsARingAndNotAnActsDiagram().");
}

// ---------------------------------------------------------------------------
// AND THE TOKEN, WHICH IS THE ONE PLACE ANY OF THIS CHANGES WHAT A CLIENT
// RECEIVES. Everything above asserts that a register was written; a
// configuration nothing consults can be perfectly correct and worth nothing.
//
// `abcapp1` asks for two of `abcapp2`'s permissions — its successor, and the
// only application it holds anything on. With five bases in the register this
// asserts that the service picked the right one, which a single resource
// makes vacuously; and because the four it did NOT ask for are the four it was
// never granted, a service that resolved a permission by prefix or by bare
// name would answer with the wrong audience here rather than with a token
// that happens to be right.
// ---------------------------------------------------------------------------
async function theTokenSaysBothHalves() {
  log.debug("Entering theTokenSaysBothHalves().");
  log.info("=== The access token: the base becomes the audience, the names " +
           "become the scope ===");
  const wanted = PERMISSIONS.map(function (one) {
    return permissionId(SPENT_ON, one.name);
  });
  const body = "grant_type=client_credentials&client_id=" +
      encodeURIComponent(SPENDER.id) + "&scope=" +
      encodeURIComponent(wanted.join(" "));
  const reply = await common.httpJson(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body
  });
  assert.strictEqual(reply.status, 200,
    "the default realm's token endpoint should mint a token for a permission " +
    "scope; it answered " + reply.status + " " + String(reply.raw).slice(0, 300));

  const token = reply.body.access_token;
  const audience = claimOf(token, "aud");
  const audiences = Array.isArray(audience) ? audience : [audience];
  assert.ok(audiences.indexOf(SPENT_ON.baseUri) >= 0,
    "THE ACCESS TOKEN SHOULD BE AUDIENCED TO " + SPENT_ON.baseUri + " — the " +
    "base URI of the application whose permissions were asked for, and not " +
    "one of the other four. That is what a resource server checks once " +
    "before reading anything else. It carried: " + JSON.stringify(audience));
  const scopes = String(claimOf(token, "scope")).split(/\s+/);
  assert.ok(scopes.indexOf("read") >= 0 && scopes.indexOf("write") >= 0,
    "AND ITS SCOPE CLAIM SHOULD CARRY THE BARE PERMISSION NAMES, which is " +
    "what makes a resource server's check one comparison rather than a URL " +
    "parse. It carried: " + claimOf(token, "scope"));
  assert.ok(scopes.every(function (one) { return one.indexOf("://") < 0; }),
    "and NOT the identifiers it was asked with — a scope value that became " +
    "the audience must come off the scope claim, or the token says the same " +
    "thing twice in two vocabularies. It carried: " + claimOf(token, "scope"));

  // AND THE REGISTER NOTICES. `asked` is the only column on this page that
  // comes from what happened, and two of ten is the reading the console
  // exists to make: these grants were used, those eight were not.
  const after = await permissionRegister();
  const asked = after.grants.filter(function (one) {
    return isOurs(one.client) && one.asked;
  });
  assert.strictEqual(asked.length, PERMISSIONS.length,
    "EXACTLY THE TWO GRANTS THIS TOKEN SPENT SHOULD NOW READ AS ASKED FOR, " +
    "and the other eight should not. That column is what makes " +
    "`granted and never asked for` a question the console can answer, and a " +
    "service that marked every client's grants would report ten. It " +
    "reported: " + JSON.stringify(asked.map(function (one) {
      return one.client + " -> " + one.permissionId;
    })));
  assert.ok(asked.every(function (one) {
    return one.client === SPENDER.id && one.resource === SPENT_ON.id;
  }), "and both should be " + SPENDER.id + "'s on " + SPENT_ON.id + ".");
  log.info("[token] OK — audienced to " + SPENT_ON.baseUri + ", scope `" +
           claimOf(token, "scope") + "`, and two of " +
           intendedGrants().length + " grants now read as used.");
  log.debug("Leaving theTokenSaysBothHalves().");
}

// ---------------------------------------------------------------------------
// The small readers. Each is the one shape this file needs, kept together so
// that no assertion above has to know how a reply is put together.
// ---------------------------------------------------------------------------
async function permissionRegister() {
  log.debug("Entering permissionRegister().");
  const reply = await get("/permissions");
  assert.strictEqual(reply.status, 200,
    "GET /admin-api/permissions should answer 200; it answered " + reply.status);
  assert.ok(Array.isArray(reply.body.grants) &&
            Array.isArray(reply.body.permissions),
    "and it should carry both directions of the register.");
  log.debug("Leaving permissionRegister(). " + reply.body.grants.length +
            " grant(s).");
  return reply.body;
}

async function registryEntry(identifier) {
  log.debug("Entering registryEntry(). identifier=" + identifier);
  const reply = await get("/applications?application=" +
                          encodeURIComponent(identifier));
  assert.strictEqual(reply.status, 200,
    "GET /applications?application=… should answer 200 whether or not the " +
    "entry is there; it answered " + reply.status);
  log.debug("Leaving registryEntry(). found=" + reply.body.found);
  return reply.body;
}

// One attribute's values off an application entry. `attributes` is the WHOLE
// entry and `fields` beside it is the narrower editable subset, so the read
// goes to `attributes` first: an assertion that looked only at `fields` would
// report an attribute missing whenever the editable table narrowed, which is a
// change to a form and not to the entry.
function fieldValues(entry, attribute) {
  const fields = (entry && (entry.attributes || entry.fields)) || {};
  const held = fields[attribute];
  if (held === undefined || held === null) {
    return [];
  }
  return Array.isArray(held) ? held.map(String) : [String(held)];
}

// Whether an identifier is one of this example's. Everything this file counts
// is filtered through it, because the DEFAULT realm's registry holds whatever
// the rest of the run put there — the console job's applications, a SAML
// service provider, the console's own two entries — and an assertion about a
// TOTAL would be an assertion about the other jobs.
function isOurs(identifier) {
  return APPS.some(function (app) { return app.id === identifier; });
}

// One claim out of a JWT, without verifying it: this file asserts what the
// service put IN the token, not whether the token is sound — sts_dpop.js and
// oauth2_sts_endpoints.js own that question.
function claimOf(jwt, name) {
  if (!jwt) {
    return "";
  }
  const parts = String(jwt).split(".");
  if (parts.length < 2) {
    return "";
  }
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return payload[name] === undefined ? "" : payload[name];
  } catch (e) {
    // A token this service minted is always decodable; a body that is not is
    // worth reporting as an empty claim rather than as a crash, because the
    // assertion that follows says more about what went wrong.
    return "";
  }
}

async function test() {
  log.debug("Entering test().");
  log.info("Building the delegated permission example at " + api);
  if (!(await theServiceIsThere())) {
    log.info("Skipped: no STS mock at " + base + ".");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  await forgetAnyPreviousExample();
  await createTheFiveApplications();
  await exposeReadAndWrite();
  await grantTheRing();
  await theRegisterReadsBackAsARing();
  await theAttributesLandOnTheRightEntries();
  await thePictureIsARingAndNotAnActsDiagram();
  await theTokenSaysBothHalves();

  // NO TEARDOWN, and this line is where a reader is told so rather than
  // discovering it. See this file's header for the argument.
  log.info("Test completed successfully. THE EXAMPLE IS LEFT STANDING in the " +
           "default realm, deliberately: " + APPS.length + " applications, " +
           APPS.length * PERMISSIONS.length + " permissions and " +
           intendedGrants().length + " grants, in a ring: " +
           APPS.map(function (app) { return app.id; }).join(" -> ") + " -> " +
           APPS[0].id + ". Read it at " + base +
           "/admin/delegation/allowed, where the picture of it is drawn " +
           "below the tables (" + base +
           "/admin/delegation/allowed?format=svg for the drawing alone).");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_delegated_permissions_example")
  .description("Build a delegated permission example in the mock STS's " +
      "default realm — five applications in a ring, each exposing read and " +
      "write and each granted both on the next one round — and assert the " +
      "register, the entries, the picture and the token it produces. It " +
      "leaves the example behind on purpose.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
