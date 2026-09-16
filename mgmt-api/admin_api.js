'use strict';
//
// File: admin_api.js
//
// ---------------------------------------------------------------------------
// THE MANAGEMENT API. Everything the /admin console shows and everything it can
// change, at /admin-api, over JSON, with no browser and no HTML anywhere in it.
//
// It exists because the console's controls are forms. A form is the right shape
// for a person and the wrong one for anything else: a caller that wants to
// revoke a token from a script, or read what this issuer is about to mint from
// a CI job, was left either parsing a redirect or knowing which hidden field to
// post. Every page already answered `?format=json` — this is the other half of
// that, and the half the console never had.
//
// ---------------------------------------------------------------------------
// THE ONE RULE THAT MATTERS HERE, and it is a rule about the FUTURE rather than
// about this file: **a control added to /admin gets an operation here in the
// same commit.** Not eventually, and not "when somebody needs it" — an API that
// covers eight of nine controls is worse than one that covers none, because the
// ninth is discovered by a caller who has already written the code that assumes
// it.
//
// Two things make that cheap rather than a matter of discipline:
//
//   * **This module decides nothing.** Every POST here calls the SAME action
//     function the console's form posts to — adminActions.tokenAction,
//     claimsAction,
//     vcAction, vpConfigAction — with `action` taken from the URL instead of
//     from a hidden input, and every GET calls the same JSON view the page's
//     `?format=json` answers. So adding an action to the console's switch is
//     most of adding it here: what is left is one row of the table below.
//   * **The OpenAPI document is built from that table** (admin_api_spec.js), so
//     an operation cannot exist and be undocumented, and cannot be documented
//     and not exist. What no code can check is the direction that matters — a
//     new console control with no row here — and that is what the parent
//     project's tests/vendored/admin_api.js asserts, by walking the console's
//     own NAV and the action names each of its four handlers accepts.
//
// ---------------------------------------------------------------------------
// **PROTECTED SINCE 2026-09-09, AND THIS HEADER SAID THE OPPOSITE UNTIL THEN.**
// It read "NOT PROTECTED, deliberately", and gave three reasons. Every one of
// them was true and the third is what the change was for: anybody who could
// reach this port could grant themselves both console roles here.
//
// What gates it is an **OAuth 2.0 access token** audienced to this API —
// `admin:read` to read, `admin:write` to change anything — which become the
// built-in ADMIN_READ and ADMIN_WRITE roles, so the requirement is stated in
// the same `access-control` document every other access decision here is. One
// middleware on the base path covers every operation by construction.
//
// **It is a DIFFERENT credential from the console's, not the same gate
// widened**, and that distinction is the whole design: the console takes a
// browser session, this takes a token. `adminApi.authRequired` is the off
// switch and restores the open API exactly.
//
// **THE THREE REASONS IT WAS OPEN ARE KEPT VERBATIM IN `mgmt-api/CLAUDE.md`**
// rather than here, because they are now the argument for that off switch and
// an argument in two places is one that will disagree with itself. Both of the
// things they were defending still hold: a test still drives this API — the
// launchers mint a token before any job runs — and it is still the way back in
// when nobody holds a console role.
//
// The prediction that header made came true to the letter and is worth reading
// as one: it said that if this ever changed it would be a SEPARATE setting with
// a separate argument (`admin.apiAuthRequired` was the name considered) and
// never a quiet extension of `admin.authRequired` to this path. It was —
// `adminApi.authRequired`, in a group of its own. `admin.authRequired` itself
// no longer exists: `global.mode` replaced it on 2026-09-06.
//
// ---------------------------------------------------------------------------
// Route order: this module must come AFTER admin.js, and that is a plain
// dependency rather than a preference — it requires that module for the action
// functions and the JSON views. Nothing here collides with any path, and it
// registers no wildcard, so its position is otherwise free (rule 1).
//
// The four POST routes take the action as a PATH PARAMETER — /admin-api/
// tokens/revoke, one express pattern `:action` behind six real URLs. That keeps
// the router honest (one row in GET /admin/sts-metadata per resource, showing
// the parameter) while the OpenAPI document lists each URL as the separate
// operation it is, which is what makes the explorer's per-action forms
// possible. An unknown action is not a 404: it reaches the console's own
// handler and comes back as its "Unknown action" refusal, naming the ones that
// exist.
// ---------------------------------------------------------------------------

const app = require('../common/app');
// The error-code registry, a leaf. A refusal here is MARKED on the response for
// the call log and never written into the JSON a caller receives.
const errorCodes = require('../common/error_codes');
// Whether a create can race another node's, and the sentence a refused one
// carries (#46 section 3). A LIBRARY that registers nothing.
const createClaims = require('../ldap/directory_create_claims');
const helpers = require('../common/helpers');
const { log, parseBody, baseUrlOf, STS } = helpers;
// BOTH ARE LIBRARIES (rule 3): they register no route, so requiring them here
// cannot move one or join a cycle. `crypto.js` is THE one place this service
// verifies a signature, and `roles.js` is what turns an access token's scopes
// into the roles the access policy asks for — see the gate below.
const stsCrypto = require('../common/crypto');
const roles = require('../common/roles');
// The password policy's FIELD TABLE, which the request schema of
// `save-password-policy` is generated from — for `narrowDoorProperties()`'s
// reason: a hand-written list of what an operation accepts is a second
// definition of the table and goes stale in the document a caller trusts most.
const passwordPolicy = require('../common/password_policy');
const admin = require('../admin-ui/admin');
// WHAT A REALM ADMINISTRATOR MAY NOT REACH (2026-09-14, #32) — the console's
// table, asked of a realm's own token and a realm's own session here. A
// library with no route.
const adminScope = require('../admin-ui/admin_scope');
// ---------------------------------------------------------------------------
// THE ACTION LAYER (2026-09-12). Every operation below that CHANGES something
// calls a function here rather than one on the console module.
//
// **THAT IS THE WHOLE OF WHY THIS FILE STILL REQUIRES BOTH.** Rule 7 says a
// console control and an API operation must not be able to disagree, and the
// way that was enforced until today was that this file called the console's
// own functions — which worked, and which made the surface a machine drives
// downstream of the surface a person reads. The DECISIONS moved to
// admin-core/, which neither surface owns; what is still reached for on
// `admin` is what the console genuinely owns — the JSON views it renders
// beside its pages, and `respondToAction()`, which is transport.
// ---------------------------------------------------------------------------
const adminActions = require('../admin-core/admin_actions');
// AND THE READ HALF (2026-09-12). Thirty-eight functions that answer a
// question and build no markup; `admin-core/admin_views.js` argues the line.
// What is still reached for on `admin` below is the console's own structure
// — which pages exist, where a settings group is edited — and the views that
// draw HTML, whose json half is still computed in the same pass as the page.
const adminViews = require('../admin-core/admin_views');
// THE PKI PAGE'S VIEW AND ITS FOUR ACTIONS. A PLAIN REQUIRE IN THE ORDINARY
// DIRECTION, which is what rule 3e asks for when one is available: that module
// is loaded at 18a — before this file — so this is a cache hit, and it
// registers only `/admin/pki`, which is already in the router by now. Compare
// `admin-ui/crypto_metadata.js`, which is at 20a and therefore needed a slot.
const pkiAdmin = require('../admin-ui/pki_admin');
// The key algorithms a TLS listener certificate may be issued with, for the
// `issue-pep-certificate` request schema's enum (2026-09-13) — read from the
// module that refuses the others, so the document cannot offer one it would
// refuse. A LIBRARY (rule 3): a cache hit, and it registers nothing.
const pki = require('../common/pki');
// The certificate catalogue and details model both certificate dialogs read
// (2026-09-13). A LIBRARY in `admin-core/`, required at 19 like the two above.
const certificateViews = require('../admin-core/certificate_views');
// Which endpoints each Protocols page lists (2026-09-13). The console adds
// them in `respond()`; this file adds the same member to the GET that
// `mirrors` that page — see the registration loop and sendJson().
const protocolEndpoints = require('../admin-core/protocol_endpoints');
// 18b, required in the ORDINARY DIRECTION for the same reason as the line
// above: it registers `/admin/encryption` at its own require time, which
// `common/protocol_stack.js` reaches before this file, so this is a cache
// hit and moves no route.
const encryptionAdmin = require('../admin-ui/encryption_admin');
// 18c, same ordinary-direction require and the same reason.
const databaseAdmin = require('../admin-ui/database_admin');
const secretsAdmin = require('../admin-ui/secrets_admin');
// The embedded protocol debugger's report (2026-09-13). A page module required
// at 18 like the one above, and it reads the listener's status lazily, so this
// require moves no route.
const debuggerAdmin = require('../debugger/debugger_admin');
// The setting table, for the two narrow doors' request schemas: their
// properties are BUILT from the keys those doors refuse against, and the
// TYPE of each comes from the row config.js already holds for it. See
// narrowDoorProperties() below.
const config = require('../common/config');
// The two console roles, for the `enum` on the role parameter and on both
// request bodies. A library that registers nothing, so requiring it here moves
// no route; taking the ids from it rather than writing them twice is what stops
// the OpenAPI document offering a role this service does not have.
const rbac = require('../admin-ui/admin_rbac');
// The claim sets, for the `enum` on every `set` field below and for the two
// lists that decide which of them each action resource carries. Also a library
// that registers nothing — admin.js has required it long before this line — so
// taking the ids from it moves no route and cannot let this document offer a
// set the service does not have.
const stats = require('../common/admin_stats');
// The applications registry, for the `enum` of protocol family ids on the
// create body. A library too — it registers nothing and admin.js required it
// long before this line — so this moves no route, and taking the ids from the
// table the create VALIDATES against is what stops this document offering a
// family that call would refuse.
const applications = require('../common/applications');
// RFC 9728, for `load-resource-metadata`: the realm's authorization servers the
// document is compared with are addressed by the request, so this handler
// computes them and hands them to the action. A library that registers nothing.
const resourceMetadata = require('../oauth-oidc/protected_resource_metadata');
const spec = require('./admin_api_spec');

// ---------------------------------------------------------------------------
// THE DOCUMENT IS THE VALIDATOR (2026-09-06).
//
// Every action in the table below already carries a `requestBody` — a real
// JSON Schema with `properties`, `required` and `additionalProperties: false`
// — and `admin_api_spec.js` publishes it verbatim in the OpenAPI document.
// **Until now nothing checked a request against it.** The document described
// what to POST and the handlers read whatever arrived, so the two could
// disagree for as long as anybody liked and the only way to find out was to
// read both.
//
// ajv compiles THE SAME OBJECT the document publishes. Not a copy of it, not a
// second description of it in another notation — the identical value, reached
// through the identical table — which is what makes "the document is accurate"
// a property of the code rather than a claim somebody has to re-check. That is
// the same argument `sts_metadata.js` makes about the router and
// `crypto_metadata.js` makes about the algorithm tables, applied to request
// bodies.
//
// **WHY ajv HERE AND zod EVERYWHERE ELSE.** `common/validation.js` is zod
// because a protocol endpoint's rules are written in prose in an RFC and have
// to be expressed somewhere. This surface is the opposite case: the rules are
// ALREADY written down, as JSON Schema, because the document has to publish
// them. A zod schema here would be a second spelling of an existing artefact —
// the "one copy of each fact" rule, broken on purpose, in the one place the
// fact is already machine-readable.
//
// `strict: false` because these are OpenAPI schemas: they carry `examples` and
// `description` members that ajv's strict mode reports as unknown keywords.
// `allErrors` so a caller fixing a body sees everything wrong with it at once
// — the opposite of `common/validation.js`'s first-issue-only rule, and for a
// reason: this is a developer with a document open, not a browser mid-sign-in.
// ---------------------------------------------------------------------------
const Ajv = require('ajv');
const addFormats = require('ajv-formats');

const ajv = new Ajv({ strict: false, allErrors: true, coerceTypes: false });
addFormats(ajv);

// ---------------------------------------------------------------------------
// THE COMPONENTS THE DOCUMENT DEFINES, SO A `$ref` INTO THEM RESOLVES.
//
// Three request schemas here refer to a shared definition rather than
// repeating it — `replaceClaims`, `replaceUserInfoClaims` and
// `replaceSamlAttributes` all take a list of `#/components/schemas/ClaimEntry`,
// which is exactly the reuse the components section exists for.
//
// **A JSON POINTER STARTING `#/` IS RESOLVED AGAINST THE ROOT OF THE SCHEMA
// BEING COMPILED**, and a `requestBody` compiled on its own is its own root —
// so the pointer looks for `components` INSIDE the request body and finds
// nothing. The first version of this registered the components as a separate
// schema under `$id: '#'` and it made no difference for exactly that reason.
//
// So each schema is compiled wrapped in a root that carries the components
// beside it. `components` is not a JSON Schema keyword and ajv ignores it under
// `strict: false` — what it is there for is to be POINTED AT. Nothing about the
// published document changes: `admin_api_spec.js` still emits `requestBody`
// verbatim, and this wrapper exists only for the length of the compile.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// **WHAT IS ENFORCED IS STRUCTURE. `required` AND `enum` ARE STRIPPED FROM THE
// COMPILED COPY AND KEPT IN THE DOCUMENT.**
//
// The rule is the one this file rests on: *the validator adds the checks
// nothing else makes, and never duplicates a check the handler already makes
// better.* Two of the four JSON Schema assertions here fall on each side, and
// the suite decided it rather than taste.
//
// ENFORCED, because nothing else in this service checks them:
//
//   * `additionalProperties: false` — a member the operation does not define.
//     This is the one that catches the silently ignored field, which is the
//     failure a passing test cannot see. It found four in this repository's own
//     suite on the day it was written: `acs` and `binding` on the SAML 2.0
//     resource, `target` on SAML 1.1, and a `name` that should have been
//     `label` on the authorization-server create — every one of them a member
//     the handler never read and the job asserted nothing about.
//   * `type` — a number or an array where a string belongs.
//
// NOT ENFORCED, because a handler already answers them and says more:
//
//   * `enum` — `applicationsAction()` refuses an unknown kind by NAMING the
//     kinds and COUNTING them, and `sts_admin_api_operations.js` asserts all
//     three properties, because that list and the one
//     `GET /applications/new` publishes are one table read through two doors.
//   * `required` — `logoutAction()` answers a sign-out with no identity with
//     *Name the identity ... in `user`*, and the same job asserts that wording
//     SO THAT A CALLER CAN TELL WHICH REFUSAL IT MET.
//
// In both cases ajv runs first, so enforcing would replace a sentence a caller
// can act on with "must be equal to one of the allowed values" — and switch off
// an assertion in the same stroke. That is the opposite of the point.
//
// **Both stay in the published document**, where they are exactly right:
// documentation of the valid set and the mandatory members. What this decides
// is only WHICH LAYER refuses, and the answer is the layer that can explain
// itself. Stripped recursively, because these schemas nest — an array's `items`
// and a `$ref`'d `ClaimEntry` each carry their own.
// ---------------------------------------------------------------------------
const NOT_ENFORCED_HERE = ['enum', 'required'];

function structureOnly(node) {
  log.debug("Entering structureOnly().");
  if (Array.isArray(node)) {
    log.debug("Leaving structureOnly().");
    return node.map(structureOnly);
  }
  if (!node || typeof node !== 'object') {
    log.debug("Leaving structureOnly().");
    return node;
  }
  const out = {};
  Object.keys(node).forEach(function (key) {
    if (NOT_ENFORCED_HERE.indexOf(key) >= 0) {
      return;
    }
    out[key] = structureOnly(node[key]);
  });
  log.debug("Leaving structureOnly().");
  return out;
}

function compilable(schema) {
  log.debug("Entering compilable().");
  log.debug("Leaving compilable().");
  return Object.assign({}, structureOnly(schema),
                       { components: { schemas: structureOnly(
                           spec.SCHEMAS) } });
}

// Compiled once at require time, keyed by the operation the request will reach.
// A schema that will not compile is a MAINTAINER's mistake rather than a
// caller's, so it is logged loudly and that operation is left unvalidated
// rather than taking the whole service down at require time — the same
// judgement `ldap_server.js` makes about a listener that will not bind.
const validators = new Map();

function validatorKeyOf(route, action) {
  log.debug("Entering validatorKeyOf().");
  log.debug("Leaving validatorKeyOf().");
  return route + '\u0000' + (action || '');
}

function compileRequestSchemas() {
  log.debug("Entering compileRequestSchemas().");
  let built = 0;
  ROUTES.forEach(function (entry) {
    const route = entry.route || entry.path;
    const rows = entry.actions || [];
    rows.forEach(function (action) {
      if (!action.requestBody) {
        return;
      }
      try {
        validators.set(validatorKeyOf(route, action.action),
                       ajv.compile(compilable(action.requestBody)));
        built = built + 1;
      } catch (e) {
        // A schema this repository wrote that ajv will not compile. Logged by
        // operation so it names the row to fix; the operation goes on working
        // unvalidated, because a management API that would not start is worse
        // than one operation whose body is unchecked.
        log.error(errorCodes.tag('STS-API-0010') +
                  'admin-api: the request schema for ' + action.operationId +
                  ' would not compile and that operation is unvalidated: ' +
                  e.message);
      }
    });
    if (entry.requestBody) {
      try {
        validators.set(validatorKeyOf(route, ''),
                       ajv.compile(compilable(entry.requestBody)));
        built = built + 1;
      } catch (e) {
        log.error(errorCodes.tag('STS-API-0010') +
                  'admin-api: the request schema for ' +
                  (entry.operationId || route) +
                  ' would not compile and that operation is unvalidated: ' +
                  e.message);
      }
    }
  });
  log.debug("Leaving compileRequestSchemas(). " + built + " validator(s).");
  return built;
}

// ---------------------------------------------------------------------------
// Turn ajv's errors into the `{ ok: false, errors: [...] }` shape every refusal
// on this API already uses, so a caller parses one thing.
//
// `instancePath` is a JSON Pointer (`/redirect_uris/0`); the leading slash is
// dropped and the rest is written with dots, because a caller is reading it
// beside a body they typed rather than resolving a pointer.
// ---------------------------------------------------------------------------
function errorsFromAjv(errors) {
  log.debug("Entering errorsFromAjv().");
  const out = (errors || []).map(function (e) {
    const where = String(e.instancePath || '').replace(/^\//, '')
                                              .replace(/\//g, '.');
    const missing = e.params && e.params.missingProperty;
    const extra = e.params && e.params.additionalProperty;
    if (missing) {
      return '"' + missing + '" is required.';
    }
    if (extra) {
      return '"' + extra + '" is not a member of this request. The ' +
             'operation\'s schema in the OpenAPI document lists what is.';
    }
    return (where ? '"' + where + '" ' : 'the request ') + e.message + '.';
  });
  log.debug("Leaving errorsFromAjv(). " + out.length + " message(s).");
  return out.length ? out : ['The request body did not match this ' +
                             'operation\'s schema.'];
}

// ---------------------------------------------------------------------------
// The check itself, run before a handler sees the request.
//
// **`action` IS REMOVED BEFORE VALIDATING, and that is not a loophole.** Every
// action resource here is `/<resource>/:action`, so the action is a PATH
// segment and the schemas describe the body WITHOUT it — they carry
// `additionalProperties: false`, so leaving it in would refuse every request on
// this API. A caller that also puts `action` in the body is ignored exactly as
// it was before: `withAction()` takes the path parameter and overwrites.
// ---------------------------------------------------------------------------
function checkRequestBody(req) {
  log.debug("Entering checkRequestBody().");
  const route = req.__adminApiRoute || '';
  const action = String((req.params && req.params.action) || '');
  if (req.__adminApiHandlerOwnsBody) {
    // A NARROW DOOR: the handler validates the WHOLE body and refuses an
    // unknown member by naming the ones it accepts. See `handlerOwnsBody` on
    // the route table.
    log.debug("Leaving checkRequestBody(). The handler owns this body.");
    return { ok: true };
  }
  const validate = validators.get(validatorKeyOf(route, action)) ||
                   validators.get(validatorKeyOf(route, ''));
  if (!validate) {
    // No schema for this operation — a GET, an unknown action the handler is
    // about to refuse by name, or a row that carries none. Not this function's
    // business to invent one.
    log.debug("Leaving checkRequestBody(). No schema for this operation.");
    return { ok: true };
  }
  const body = parseBody(req);
  const subject = Object.assign({}, body);
  delete subject.action;
  if (validate(subject)) {
    log.debug("Leaving checkRequestBody(). Accepted.");
    return { ok: true };
  }
  log.debug("Leaving checkRequestBody(). Refused with " +
            (validate.errors || []).length + " error(s).");
  return { ok: false, errors: errorsFromAjv(validate.errors) };
}
const docs = require('./admin_api_docs');
// The trust realm this call arrived in — for the explorer, which is the one
// page in this service that builds its URLs in a script and therefore cannot
// have its markup rewritten. See docs.page().
const realms = require('../common/realms');
// RFC 9068 (2026-09-13): what an access token's type and issuer must be, read
// the way the other resource servers here read them. A library that registers
// no route; `oauth2.js` already required it, so this is a cache hit.
const jwtAccessToken = require('../oauth-oidc/jwt_access_token');
// RFC 8705 section 3.1 (2026-09-13): a certificate-bound access token is
// usable only on a connection made with its certificate — the check every
// other resource server here makes through `dpop.presentedAccessToken()`. A
// library that registers nothing; `oauth2.js` already required it.
const mtls = require('../oauth-oidc/mtls');
// THE VERSION, M.N.O. A LEAF (rule 3): registers nothing and requires nothing
// from this repository, so it cannot move a route or join a cycle.
//
// **IT USED TO BE `require('../package.json').version`**, which is M.N.0 — the
// manifest's placeholder patch, not the build number. So the index and the
// OpenAPI document's `info.version` both named a release and no build, and two
// containers built a month apart reported the same string. See
// common/version.js.
const version = require('../common/version');
const APP_VERSION = version.load();
const VERSION = APP_VERSION.version;

const BASE = '/admin-api';
// THE ACCESS GATE, armed by `xacml/xacml_access_pep.js` at 23c. A LEAF
// (rule 3): with no decider installed `check()` answers "allowed", so a
// process without the XACML family behaves exactly as this file did before.
const accessGate = require('../common/access_gate');
// The mode. A LEAF (rule 3): registers nothing, requires only `config`.
const mode = require('../common/mode');

// Every reply here is JSON, is never cached, and is pretty-printed. The last of
// those is not decoration: the caller of a mock's admin API is usually a person
// at a terminal or a test whose failure message is the body, and a 40 KB single
// line is unreadable in both.
function sendJson(res, status, body) {
  log.debug("Entering sendJson(). status=" + status);
  // The realm's endpoints for a Protocols page, when this is the GET that
  // mirrors one: the registration loop computed them onto `res.locals`, and
  // the member is added to a successful object answer the way the console's
  // `respond()` adds it to the page's JSON. Every other answer is untouched.
  const rows = res.locals && res.locals.protocolEndpoints;
  if (rows && status === 200 && body && typeof body === 'object' &&
      !Array.isArray(body)) {
    body = Object.assign({}, body, { protocolEndpoints: rows });
  }
  res.status(status).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(body, null, 2));
  log.debug("Leaving sendJson().");
}

// The action a POST names, from the path rather than the body. It is forced
// over whatever the body carried so that a body copied from the console's form
// — which does carry `action` — cannot mean something other than the URL it was
// sent to.
// ---------------------------------------------------------------------------
// A CREATE CLAIMS ITS NAME ACROSS NODES FIRST (2026-09-14, #46 section 3), for
// `POST /admin-api/users/create` and `/admin-api/groups/create` —
// `ldap/directory_create_claims.js` argues it. The directory module is looked
// up in the require CACHE and never required from here: it registers routes,
// it is below this module in the route order, and a process that never loaded
// it has no directory to race for (the action refuses on its own).
// Resolves to `{ ok, settle }` or the refusal; inert where nothing can race.
// ---------------------------------------------------------------------------
function claimForCreate(what) {
  log.debug("Entering claimForCreate().");
  let directory = null;
  try {
    const cached = require.cache[require.resolve('../ldap/ldap_server')];
    directory = cached && cached.loaded ? cached.exports : null;
  } catch (e) {
    log.debug("Caught in claimForCreate(): " + ((e && e.message) || e));
  }
  if (!directory || typeof directory.claimCreate !== 'function') {
    log.debug("Leaving claimForCreate(). No directory in this process.");
    return Promise.resolve({ ok: true, settle: function () {} });
  }
  log.debug("Leaving claimForCreate().");
  return directory.claimCreate(what);
}

// ---------------------------------------------------------------------------
// RUN AN ACTION, CLAIMING ITS NAME FIRST WHEN THERE IS ONE TO CLAIM. `what` is
// null for an action that creates nothing, and then — and wherever a create
// cannot race (`createClaims.active()` false, which is every single-process
// service) — `run` is called SYNCHRONOUSLY, exactly as the handler did before.
// Otherwise the claim is awaited, a refusal answered in this API's shape
// (409, or 503 when the store could not be asked), and `run` handed the claim
// to settle with the action's outcome.
// ---------------------------------------------------------------------------
function runClaimed(res, what, run) {
  log.debug("Entering runClaimed().");
  const idle = { ok: true, settle: function () {} };
  if (!what || !createClaims.active()) {
    log.debug("Leaving runClaimed(). Nothing to claim.");
    return run(idle);
  }
  log.debug("Leaving runClaimed(). Claiming first.");
  return claimForCreate(what).then(function (held) {
    if (!held.ok) {
      errorCodes.mark(res, held.code);
      sendJson(res, held.reason === 'store' ? 503 : 409,
               { ok: false, errors: [createClaims.refusalMessage(held)] });
      return;
    }
    try {
      run(held);
    } catch (e) {
      held.settle(false);
      log.error(errorCodes.tag('STS-API-0113') + 'admin-api: a create that ' +
                'had claimed its name threw: ' + ((e && e.message) || e));
      errorCodes.mark(res, 'STS-API-0113');
      sendJson(res, 500, { ok: false, errors: ['The create failed: ' +
                                               ((e && e.message) || e)] });
    }
  });
}

function withAction(req, body) {
  log.debug("Entering withAction().");
  log.debug("Leaving withAction().");
  return Object.assign({}, body, { action: String(req.params.action || '') });
}

// The two spellings of a list, joined. A JSON body carries one `attributes`
// array; a form body copied from the console carries `attribute` repeated. Both
// are accepted for the same reason the console accepts both.
function namesOf(req, body, one, many) {
  log.debug("Entering namesOf(). " + one + "/" + many);
  const names = admin.listField(req, body, one)
                     .concat(admin.listField(req, body, many));
  log.debug("Leaving namesOf(). " + names.length + " name(s).");
  return names;
}

// --- the shared parameter descriptions --------------------------------------
//
// Written once because three lists page identically, and because a caller that
// has learned to walk one of them has learned to walk all three.
function pagingParameters() {
  log.debug("Entering pagingParameters().");
  log.debug("Leaving pagingParameters().");
  return [
    { name: 'page', in: 'query', required: false,
      schema: { type: 'integer', minimum: 1 },
      description: 'Which page of the match to return. CLAMPED rather than ' +
                   'refused: a page past the end returns the last one, and ' +
                   'the reply says which page it actually is.' },
    { name: 'per', in: 'query', required: false,
      schema: { type: 'integer', minimum: 1, maximum: admin.MAX_ROWS },
      description: 'Rows per page. Defaults to ' + admin.DEFAULT_PER_PAGE +
                   ' and is capped at ' + admin.MAX_ROWS + '. On a ' +
                   'drill-down it is SHARED by every list in the reply, ' +
                   'which each carry a page number of their own.' }
  ];
}

// The page parameters of a DRILL-DOWN, which is a different shape from a list
// and has to be, because a drill-down answers with several lists at once — five
// on /users, two on /groups. One `page` would move all of them together, so
// each gets a parameter named after itself and `per` above stays shared.
//
// Every one is clamped the way `page` is, and every one is answered: the reply
// carries a `<name>Paging` object beside the array, with the same member names
// the flat lists put at the top level. A caller walks these exactly as it walks
// /tokens, one list at a time. ONE NAME PER LIST: the parameter is the reply
// array's own name with `Page` on the end, and the object answering it is that
// name with `Paging` on the end. A caller that can read the reply can therefore
// write the request without a table mapping one set of names onto the other.
function detailPagingParameters(lists) {
  log.debug("Entering detailPagingParameters().");
  log.debug("Leaving detailPagingParameters().");
  return lists.map(function (list) {
    return { name: list.name + 'Page', in: 'query', required: false,
             schema: { type: 'integer', minimum: 1 },
             description: 'Which page of `' + list.name + '` to return, ' +
                          'answered by `' + list.name + 'Paging`. ' +
                          list.description };
  });
}

// ---------------------------------------------------------------------------
// THE SEVEN ACTIONS OF A CLAIM SET, FOR WHICHEVER FAMILY OF SETS ASKED.
//
// The console has THREE pages onto one store since 2026-08-26 — /admin/claims
// for the two JWT sets, /admin/userinfo-claims for the UserInfo one and
// /admin/saml-attributes for the two SAML ones — so this API has three action
// resources, and rule 7 means each needs an operation per action. That is
// twenty-one operations describing seven behaviours, and the one thing that
// must not happen is twenty-one DESCRIPTIONS: the copy that is not edited
// beside the others is the one a caller believes, and a document that disagreed
// with itself about whether an empty `attributes` clears a set would be worse
// than one that said nothing.
//
// So the rows are built once, here, and the family is what varies:
//
//   * WHICH SET IDS the `enum` offers — which is the same restriction
//     claimsAction()'s `allowed` argument enforces on the way in, so a caller
//     reading this document cannot construct a call the service will refuse.
//   * THE NOUN. A JWT set carries claims and a SAML set carries attributes,
//     which is what each protocol's own readers call them.
//   * THE RESERVED-NAMES RULE, which is a JWT rule and only a JWT rule:
//     setClaimSet() checks it for `kind === 'jwt'`, because an assertion
//     attribute called `exp` collides with nothing. Documenting it on the SAML
//     operations would tell a caller their call will be refused when it will
//     succeed.
//
// operationIds cannot collide — a generated client would have two methods of
// one name — so each family carries its own, spelled out rather than derived
// from a suffix, because `addClaim` and `addSamlAttribute` are what a caller
// would guess and `addClaim2` is what a suffix would produce.
// ---------------------------------------------------------------------------
const JWT_CLAIM_FAMILY = {
  sets: stats.JWT_CLAIM_SET_IDS,
  noun: 'claim',
  carrier: 'token',
  example: 'id_token',
  reserved: true,
  ids: { add: 'addClaim', remove: 'removeClaim', clear: 'clearClaims',
         replace: 'replaceClaims', attributes: 'setClaimAttributes',
         all: 'selectAllClaimAttributes', none: 'clearClaimAttributes' }
};

// The third family, and the one that made the two above it a PATTERN rather
// than a pair. Nothing in claimSetActions() changed to add it — which is the
// test that the parameterisation was real: `sets`, `noun`, `carrier`,
// `example`, `reserved` and the operationIds were the whole of what varied
// between the first two, and they were the whole of what varied for the third.
//
// `reserved: true` is the one row a reader coming from SAML_CLAIM_FAMILY would
// get wrong. The reserved list is not a JWT rule with a JWT exception — it is
// the rule "this artefact has names this service sets itself", and a UserInfo
// response has them: `sub` is required by OIDC Core 5.3.2 and a client MUST
// check it against the ID Token's, and the SIGNED form of the same response is
// a JWT carrying `iss`, `aud` and `exp`. admin_stats.js's reservedNames() is
// where that is decided, once, for every door onto the store.
const USERINFO_CLAIM_FAMILY = {
  sets: stats.USERINFO_CLAIM_SET_IDS,
  noun: 'claim',
  carrier: 'UserInfo response',
  example: 'userinfo',
  reserved: true,
  ids: { add: 'addUserInfoClaim', remove: 'removeUserInfoClaim',
         clear: 'clearUserInfoClaims', replace: 'replaceUserInfoClaims',
         attributes: 'setUserInfoClaimAttributes',
         all: 'selectAllUserInfoClaimAttributes',
         none: 'clearUserInfoClaimAttributes' }
};

const SAML_CLAIM_FAMILY = {
  sets: stats.SAML_CLAIM_SET_IDS,
  noun: 'attribute',
  carrier: 'assertion',
  example: 'saml11',
  reserved: false,
  ids: { add: 'addSamlAttribute', remove: 'removeSamlAttribute',
         clear: 'clearSamlAttributes', replace: 'replaceSamlAttributes',
         attributes: 'setSamlDirectoryAttributes',
         all: 'selectAllSamlDirectoryAttributes',
         none: 'clearSamlDirectoryAttributes' }
};

function claimSetActions(family) {
  log.debug("Entering claimSetActions(). " + family.sets.length + " set(s).");
  const noun = family.noun;
  const setField = { type: 'string', enum: family.sets.slice() };
  const rows = [
    { action: 'add', operationId: family.ids.add,
      summary: 'Add one ' + noun + ' to one set',
      description: 'Every ' + family.carrier + ' of that kind issued from ' +
                   'now on carries it; nothing already issued ' +
                   'changes.\n\nADDITIVE ONLY. What the protocol puts in is ' +
                   'never displaced — an ID Token\'s `sub`, a SAML 2.0 ' +
                   'assertion\'s `name`, a WS-Federation assertion\'s whole ' +
                   'identity claim list.' +
                   (family.reserved
                     ? ' A name this service sets itself is REFUSED rather ' +
                       'than allowed to win, because every one of those is ' +
                       'load-bearing — a settable `exp` would produce tokens ' +
                       'that fail to verify with nothing pointing back at ' +
                       'the call that caused it. `GET /admin-api/claims` ' +
                       'lists the refused names.'
                     : ' There is NO reserved list here: those names are ' +
                       'load-bearing in a JWT, and an assertion attribute ' +
                       'called `exp` collides with nothing. An entry with no ' +
                       'name, and two entries of one name, are still refused.'),
      requestBodyRequired: true,
      requestBody: {
        type: 'object',
        properties: {
          set: setField,
          name: { type: 'string' },
          value: { type: 'string',
                   description: 'May carry a ${...} placeholder.' },
          nameFormat: { type: 'string',
                        description: 'The SAML 2.0 set only.' },
          namespace: { type: 'string',
                       description: 'The SAML 1.1 set only. Defaults to the ' +
                                    'WS-Federation claim namespace, which is ' +
                                    'what every relying party already reads.' }
        },
        required: ['set', 'name'],
        examples: [{ set: family.example, name: 'dept', value: 'engineering' }],
        additionalProperties: false
      },
      responseDescription: 'The set as it now stands, in `claims`.' },

    { action: 'remove', operationId: family.ids.remove,
      summary: 'Remove one ' + noun + ' from one set',
      description: 'By name. A name the set does not carry is refused ' +
                   'rather than treated as already done, because the two ' +
                   'are different facts and a caller that misspelt a name ' +
                   'would otherwise be told it succeeded.',
      requestBodyRequired: true,
      requestBody: {
        type: 'object',
        properties: { set: setField, name: { type: 'string' } },
        required: ['set', 'name'],
        examples: [{ set: family.example, name: 'dept' }],
        additionalProperties: false
      },
      responseDescription: 'The set as it now stands, in `claims`.' },

    { action: 'clear', operationId: family.ids.clear,
      summary: 'Empty one set',
      description: 'Those ' + family.carrier + 's then carry only what the ' +
                   'protocol puts in them.',
      requestBodyRequired: true,
      requestBody: {
        type: 'object',
        properties: { set: setField },
        required: ['set'],
        examples: [{ set: family.example }],
        additionalProperties: false
      },
      responseDescription: 'An empty `claims`.' },

    { action: 'replace', operationId: family.ids.replace,
      summary: 'Set a whole ' + noun + ' set at once',
      description: 'The array replaces whatever the set held. An EMPTY ' +
                   'array is a legitimate call and clears it. Every entry ' +
                   'is checked by the same rules `add` applies, and a ' +
                   'single bad entry refuses the whole call — a partial ' +
                   'replace would leave the set in a state nobody asked ' +
                   'for.',
      requestBodyRequired: true,
      requestBody: {
        type: 'object',
        properties: {
          set: setField,
          claims: { type: 'array',
                    items: { $ref: '#/components/schemas/ClaimEntry' } }
        },
        required: ['set', 'claims'],
        examples: [{ set: family.example, claims: [
          { name: 'dept', value: 'engineering' },
          { name: 'on_behalf_of', value: '${username}' }
        ] }],
        additionalProperties: false
      },
      responseDescription: 'The set as it now stands, in `claims`.' },

    // --- the directory-attribute half of a set ----------------------------
    //
    // Three operations rather than one with a mode, mirroring the console's
    // three buttons, and the reason is in admin.js beside them: an empty
    // `attributes` array would otherwise be ambiguous between "clear it" and
    // "my HTTP client dropped an empty array", which is a real behaviour of
    // real clients and the kind of ambiguity that silently empties a set.
    { action: 'attributes', operationId: family.ids.attributes,
      summary: 'Set which LDAP attributes one set carries',
      description: 'The array REPLACES the selection for that set. An ' +
                   'attribute not in the array is removed, which is how ' +
                   'removal is expressed — there is no per-attribute ' +
                   'remove, because the console\'s control is a table of ' +
                   'checkboxes and an API that removed differently would ' +
                   'be a second model of the same state.\n\nThe value a ' +
                   'selected attribute carries is the one on that ' +
                   'person\'s entry under ou=users, or — where the entry ' +
                   'has nothing — invented from their username, ' +
                   'deterministically, so one username is one invented ' +
                   'person across restarts. Unlike POST ' +
                   '/admin-api/credential-claims/select this does NOT ' +
                   'sweep the directory: the credential page writes the ' +
                   'attributes it needs onto every entry, and doing it ' +
                   'from here as well would mean two pages racing to ' +
                   'populate one directory. Selecting an attribute nobody ' +
                   'has an entry value for still produces a ' + noun + '; ' +
                   'it is generated, and `attributeReport` says so per ' +
                   'claim.\n\nAn unknown attribute name refuses the WHOLE ' +
                   'call rather than being skipped: the catalogue is fixed, ' +
                   'so an unknown name is either a hand-written request that ' +
                   'deserves an answer or a rename that left a caller ' +
                   'behind. `attributeCatalogue` in the GET beside this is ' +
                   'the list — and it is ONE catalogue for all four sets, so ' +
                   'either GET answers it in full.\n\nA TYPED ' + noun + ' ' +
                   'of the same name WINS over one of these, and THE ' +
                   'PROTOCOL\'S OWN beats both — which is worth knowing ' +
                   'before it is discovered on the wire. An ID Token always ' +
                   'carries name, given_name, family_name, ' +
                   'preferred_username and email built from the sign-in, so ' +
                   'selecting cn, givenName, sn, uid or mail ON THAT SET ' +
                   'changes nothing the client sees; the same five reach an ' +
                   'access token from the directory, because the protocol ' +
                   'sets none of them there. A SAML 2.0 assertion sets ' +
                   '`name` the same way and a WS-Federation one sets the ' +
                   'whole identity claim list. Both halves are reported by ' +
                   'that same GET.',
      requestBodyRequired: true,
      requestBody: {
        type: 'object',
        properties: {
          set: setField,
          attributes: { type: 'array', items: { type: 'string' },
                        description: 'LDAP attribute type names, from ' +
                                     '`attributeCatalogue`. An EMPTY ' +
                                     'array clears the selection — and so ' +
                                     'does an ABSENT one, so a misspelt ' +
                                     'field name empties the set rather ' +
                                     'than being refused. The reply names ' +
                                     'everything it `removed` and the ' +
                                     'audit log keeps a row saying the ' +
                                     'same, and `attributes-clear` is how ' +
                                     'a caller that means it says so.' }
        },
        required: ['set', 'attributes'],
        examples: [{ set: family.example,
                     attributes: ['mail', 'departmentNumber', 'title'] }],
        additionalProperties: false
      },
      responseDescription: 'What the set carries now, in `attributes`, ' +
                           'with `added` and `removed`.' },

    { action: 'attributes-all', operationId: family.ids.all,
      summary: 'Put every catalogued attribute in one set',
      description: 'Every attribute type in the catalogue, which is a ' +
                   'legitimate thing to test and makes a large ' +
                   family.carrier + '. It exists as its own operation so ' +
                   'that "all of them" does not mean a caller constructing ' +
                   'the whole list of names that has to be updated whenever ' +
                   'the catalogue is.',
      requestBodyRequired: true,
      requestBody: {
        type: 'object',
        properties: { set: setField },
        required: ['set'],
        examples: [{ set: family.example }],
        additionalProperties: false
      },
      responseDescription: 'The whole catalogue, in `attributes`.' },

    { action: 'attributes-clear', operationId: family.ids.none,
      summary: 'Take every directory attribute out of one set',
      description: 'The TYPED ' + noun + 's on that set are untouched — this ' +
                   'is the other half. Clearing both takes this and `clear`.' +
                   '\n\nNothing is deleted from the directory: what was ' +
                   'written onto an entry stays there, because an operator ' +
                   'may have set it and nothing here has the standing to ' +
                   'remove it.',
      requestBodyRequired: true,
      requestBody: {
        type: 'object',
        properties: { set: setField },
        required: ['set'],
        examples: [{ set: family.example }],
        additionalProperties: false
      },
      responseDescription: 'An empty `attributes`, and what was `removed`.' }
  ];
  log.debug("Leaving claimSetActions(). " + rows.length + " action(s).");
  return rows;
}

// ---------------------------------------------------------------------------
// THE TABLE. Express registration and the OpenAPI document are both built from
// it, which is what makes them incapable of disagreeing.
//
// A row is either a plain operation (`path` + `handler`) or an action resource
// (`route` with `:action` in it + `handler` + `actions`), where each action is
// one documented operation at its own concrete URL.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE EIGHT PROTOCOL SETTINGS PAGES, mirrored. Rule 7 wants an operation per
// console page, and on 2026-08-27 eight pages arrived at once — one per
// protocol family whose appconfig rows had no page of their own.
//
// THERE IS NO POST BESIDE ANY OF THEM, and that is the rule read exactly
// rather than a gap. Every form on those pages posts `set-many` to
// /admin/config, which `POST /admin-api/config/set-many` already mirrors, so
// a POST here would be eight more doors onto one function — the thing this
// parity exists to prevent. It is the same answer /admin-api/scim and
// /admin-api/applications/new give, for the same reason.
//
// They are BUILT FROM A TABLE for the reason the console's own eight pages
// are: the operations differ only in prose, and eight hand-written rows
// would be seven copies plus the one somebody edited. The generated OpenAPI
// document cannot tell the difference — `admin_api_spec.js` reads this array
// and nothing else.
// ---------------------------------------------------------------------------
const PROTOCOL_SETTINGS_OPERATIONS = [
  { path: '/oauth2', console: '/admin/oauth2', tag: 'OAuth 2.0 / OIDC',
    operationId: 'getOauth2Settings',
    summary: 'The authorization server\'s own settings',
    description: 'The `oauth2.*` settings: the issuer identifier, ' +
                 'RFC 9700 mode, OAuth 2.1 mode (`oauth2.oauth21`, ' +
                 'draft-ietf-oauth-v2-1-16, which implies RFC 9700 mode), ' +
                 'the registered redirect URIs and the ' +
                 'loopback port wildcard, Front-Channel Logout, the refresh ' +
                 'token idle timeout, whether a sign-out revokes refresh ' +
                 'tokens, the client assertion clock skew, the four ' +
                 'lifetimes `GET /token-lifetimes` also reports — and ' +
                 '`oauth2.breakIdTokenNonce`, which makes this service ' +
                 'return an ID Token whose `nonce` is WRONG so that a client ' +
                 'can be shown to check it.\n\n`oauth2.rfc9700` is ' +
                 'restart-only and says so in `restartReason`: ' +
                 '`global.https` derives from it and a listener\'s scheme is ' +
                 'settled when the socket is bound. A TRUST REALM can carry ' +
                 'it while the process does not, which is how one process ' +
                 'answers permissively at /oauth2/authorize and enforces the ' +
                 'BCP under a realm prefix.' },
  { path: '/oid4vci-settings', console: '/admin/oid4vci', tag: 'OpenID4VCI',
    operationId: 'getOid4vciSettings',
    summary: 'The credential issuer\'s own settings',
    description: 'The nine `oid4vci.*` settings: the wallet an offer sends a ' +
                 'holder to, the authorization server the credential ' +
                 'endpoint will take a token from, the batch size, the ' +
                 'deferred issuance timings, the offer username, whether a ' +
                 'credential request must be encrypted, and the two that ' +
                 'decide whether the SD-JWT VC and `ldp_vc` issuers name ' +
                 'themselves by `did:web` or by URL.\n\nThose two are ' +
                 'restart-only and they change what a VERIFIER has to ' +
                 'resolve — a key fetched from a DID document rather than ' +
                 'from JWKS. What a credential CONTAINS is `GET ' +
                 '/credential-claims`.' },
  { path: '/oid4vp-settings', console: '/admin/oid4vp', tag: 'OpenID4VP',
    operationId: 'getOid4vpSettings',
    summary: 'The mock Verifier\'s own settings',
    description: 'The four `oid4vp.*` settings: the client identifier the ' +
                 'verifier presents as, where it sends a holder to present, ' +
                 'the Key Binding JWT\'s maximum age, and the claims asked ' +
                 'for when nothing else has been ' +
                 'chosen.\n\n`oid4vp.walletUrl` is DERIVED: with no value of ' +
                 'its own it is the OID4VCI wallet, since it is the same ' +
                 'wallet in every arrangement this service is used in. Its ' +
                 '`source` is `default` for that reason and for no other. ' +
                 'The DCQL query itself is `GET /verifier-request`.' },
  // THE TWO SECOND FACTORS (2026-09-10). Rule 7: `/admin/totp` and
  // `/admin/webauthn` arrived on the console and owe an operation in the same
  // change. Both replies carry the page's `status` block — the MECHANISM, read
  // from the module that performs it — beside the settings, which is why they
  // are worth fetching rather than reading `GET /config`.
  { path: '/totp', console: '/admin/totp', tag: 'TOTP MFA',
    operationId: 'getTotpSettings',
    summary: 'The authenticator-app second factor\'s settings',
    description: 'The eight `totp.*` settings — the HMAC digest, the digits, ' +
                 'the seconds in a step, the steps of clock skew forgiven, ' +
                 'the shared secret length, the label an app shows, whether ' +
                 'new enrolments are offered at all, and how long an ' +
                 'unconfirmed one lives — with the RFC 6238 algorithm table ' +
                 'in `status`, read from `common/totp.js` rather than ' +
                 'written down here.\n\n**CHANGING THE DIGEST, THE DIGITS OR ' +
                 'THE PERIOD AFFECTS NEW ENROLMENTS ONLY.** An existing ' +
                 'secret is verified with the parameters it was enrolled ' +
                 'under — the ones the QR code told the app — because this ' +
                 'service cannot change them retrospectively. `totp.window` ' +
                 'is the exception and applies to everybody.\n\n**Codes are ' +
                 'verified FOR REAL in both modes**, which almost nothing ' +
                 'else in this service is. Who holds an enrolment is `GET ' +
                 '/users` (or `GET /mfa`), and clearing one is `POST ' +
                 '/users/clear-totp`.\n\nThese eight were on `GET ' +
                 '/admin-api/mfa` until 2026-09-10, when the console page ' +
                 'that drew them split into a mechanism page and a roster.' },
  // THE THIRD MECHANISM (2026-09-10). Rule 7 again: `/admin/backup-codes`
  // arrived on the console and owes an operation in the same change.
  { path: '/backup-codes', console: '/admin/backup-codes',
    tag: 'Recovery codes', operationId: 'getBackupCodesSettings',
    summary: 'The recovery-code mechanism\'s settings, and what a code is',
    description: 'The four `backupCodes.*` settings — whether a set is ' +
                 'issued at all, how many codes are in one, how long each ' +
                 'is, and how it is broken up for reading — with the ' +
                 'mechanism itself in `status`, read from ' +
                 '`common/backup_codes.js` rather than written down ' +
                 'here.\n\n**THIS IS THE ONLY MECHANISM IN THIS SERVICE THAT ' +
                 'NO SPECIFICATION DEFINES.** There is no RFC for a recovery ' +
                 'code, so `status` has no specification column: every field ' +
                 'in it is a decision this service made, and `bitsPerCode` ' +
                 'is the one worth reading first.\n\n**A SET IS ISSUED ' +
                 'AUTOMATICALLY AND ONCE**, by the act of enrolling a second ' +
                 'factor. Nothing on this API issues one on request and ' +
                 'nothing on it reads a code back; `POST ' +
                 '/users/clear-backup-codes` deletes a set, which is the ' +
                 'only route to a second one.\n\n**CHANGING THESE AFFECTS ' +
                 'NEW SETS ONLY, AND NO EXISTING SET IS INVALIDATED** — ' +
                 'unlike `totp.*`, this needs no paragraph about enrolments, ' +
                 'because nothing here was told to an app this service ' +
                 'cannot reach. A recovery code is a string compared against ' +
                 'a stored string.\n\nWho holds a set is `GET /users`, which ' +
                 'reports the counts and never the codes.' },
  { path: '/webauthn', console: '/admin/webauthn', tag: 'WebAuthn',
    operationId: 'getWebauthnSettings',
    summary:
      'The security-key ceremony\'s settings, and what a key may be here',
    description: 'The thirteen `webauthn.*` settings, in three kinds. **THE ' +
                 'CEREMONY**: the RP name, the RP ID override, the ' +
                 'algorithms offered, the user verification requirement, the ' +
                 'attestation conveyance and the timeout — handed to the ' +
                 'browser in the `PublicKeyCredential` options. **CTAP2**: ' +
                 'the authenticator attachment, whether the credential is ' +
                 'discoverable (a resident key), and whether `credProps` is ' +
                 'asked for. **POLICY**: whether a key may be a primary ' +
                 'credential, whether it may be a second factor, and how ' +
                 'many one person may hold — which are not WebAuthn at all ' +
                 'but what THIS service does with a key.\n\n**NOT ONE OF ' +
                 'THESE EXISTED UNTIL 2026-09-10.** Every ceremony parameter ' +
                 'was a literal in a string in `authn/authn.js`, and this ' +
                 'service said there was nothing an operator could usefully ' +
                 'turn — true of the cryptography and false of the ' +
                 'ceremony.\n\n**ONE IS ENFORCED AND THE REST ARE ' +
                 'REQUESTS.** `webauthn.userVerification` is sent to the ' +
                 'browser AND checked against the UV flag when the ceremony ' +
                 'returns, because that flag is inside the bytes the ' +
                 'authenticator signed. Nothing signed says what the browser ' +
                 'was asked about attestation, the resident key or the ' +
                 'attachment, so a check on those would compare against a ' +
                 'value this service itself supplied — what it does instead ' +
                 'is RECORD what came back.\n\n**NO ATTESTATION STATEMENT IS ' +
                 'VERIFIED** whatever is asked for: there is no metadata ' +
                 'service here, no vendor trust anchor and no model ' +
                 'allow-list. `status` carries the COSE algorithm table, ' +
                 'read from `authn/webauthn.js` — the module that checks the ' +
                 'signature — with the offered ones marked.\n\nWho holds a ' +
                 'key is `GET /users`, and removing one is `POST ' +
                 '/users/clear-key`.' },
  { path: '/kerberos', console: '/admin/kerberos', tag: 'Kerberos',
    operationId: 'getKerberosSettings',
    summary: 'The KDC\'s own settings',
    description: 'The nineteen `krb5.*` settings: the realm, the two raw ' +
                 'ports, the clock skew and the deliberate clock OFFSET, the ' +
                 'one password every user account shares, the names that ' +
                 'stay unknown, the long-term keys behind krbtgt and the ' +
                 'inter-realm trust, `s2kparams`, and the two that decide ' +
                 'whether a ticket presented at /authn/spnego may start a ' +
                 'browser session.\n\nMOST OF THEM ARE RESTART-ONLY, and one ' +
                 'fact is why: the principal database — every long-term key ' +
                 'in it — is built from these when the process starts, so a ' +
                 'realm or a password changed at runtime would leave every ' +
                 'existing ticket undecryptable by the service that issued ' +
                 'it.\n\nTWO OF THEM EXIST TO MAKE FAILURES REACHABLE. ' +
                 '`krb5.unknownUsers` names the only principals that can ' +
                 'produce `KDC_ERR_C_PRINCIPAL_UNKNOWN` — every other name ' +
                 'gets an account — and `krb5.clockOffset` moves this KDC\'s ' +
                 'idea of now so a client can be shown `KRB_AP_ERR_SKEW` ' +
                 'without anybody touching a system clock.' },
  { path: '/ldap', console: '/admin/ldap', tag: 'LDAP',
    operationId: 'getLdapSettings',
    summary: 'The embedded directory\'s own settings',
    description: 'The six `ldap.*` settings: the two raw ports, the base DN, ' +
                 'whether a name seen for the first time gets an entry, and ' +
                 'the two ceilings that keep a mock from being filled ' +
                 'up.\n\nNOTHING HERE REFUSES A BIND, and no setting is ' +
                 'missing: any DN with any password, and anonymous, are ' +
                 'accepted on 389 and 636 alike. There is no such behaviour ' +
                 'to turn on.\n\nThe base DN is the DEFAULT realm\'s ' +
                 'directory and every other realm is a subtree beneath it, ' +
                 'because a socket has no path to put a realm segment in and ' +
                 'a DN is the one name a client can carry. What is IN the ' +
                 'directory is `GET /users` and `GET /groups`.' },
  // The newest of these, 2026-08-27, and the only one whose reply carries a
  // `status` member: a persistence setting that is SET and a persistence store
  // that is WORKING are two different facts, and the gap between them is the
  // whole failure mode this feature has. See admin.js's
  // persistenceStatusBlock().
  { path: '/persistence', console: '/admin/persistence', tag: 'Persistence',
    operationId: 'getPersistenceSettings',
    summary: 'What survives a restart, where it is written, and whether that ' +
             'is working',
    description: 'The `persistence.*` settings AND — unlike every other ' +
                 'operation in this group — a `status` member saying what ' +
                 'the store is actually doing: which mode is in force, ' +
                 'whether it FELL BACK to memory because it could not be ' +
                 'opened, where it writes, how many entries and realms it ' +
                 'holds, when it last wrote, and the error if the last write ' +
                 'failed.\n\nTHREE THINGS PERSIST when a store is on: the ' +
                 'embedded LDAP directory (which is also the applications ' +
                 'registry, the federation register and the SPIFFE registry ' +
                 '— they are directory entries and nothing else), the trust ' +
                 'realm registry, and the runtime appconfig overrides that ' +
                 '`POST /admin-api/config/set` writes.\n\nAND, IN PRODUCT ' +
                 'MODE ON A POSTGRES STORE SINCE 2026-09-06, WHAT THIS ' +
                 'SERVICE MINTS: sessions, access tokens, ID Tokens, refresh ' +
                 'tokens, authorization codes, pre-authorized codes, SAML ' +
                 'artifacts, Kerberos principals and tickets, the replay ' +
                 'caches, the statistics and the audit log — each row ' +
                 'encrypted under the same key-encryption key that protects ' +
                 'the signing keys, so a dump of the table is not a set of ' +
                 'usable credentials. `status.minted` reports it.\n\nIN ' +
                 'DEVELOPMENT MODE NONE OF THAT PERSISTS, and the reason is ' +
                 'the one the rule always rested on: the signing key is ' +
                 'regenerated on every start there, so a token restored from ' +
                 'a disk would verify against nothing. Product mode keeps ' +
                 'its keys — which is why it requires a store — and that ' +
                 'single fact is what makes restoring the rest of it honest. ' +
                 'The ldif store holds no minted state in either mode: it ' +
                 'writes whole files per flush, which is right for a ' +
                 'directory somebody types into and wrong for a session ' +
                 'table that changes on every request.\n\nPROCESSES AGAINST ' +
                 'ONE POSTGRES STORE COORDINATE SINCE 2026-09-06, and this ' +
                 'paragraph said the opposite before it. Every change is ' +
                 'written to a monotonic log inside the transaction that ' +
                 'made it, and each process applies what the others ' +
                 'committed — the directory, the realms, the settings and ' +
                 'the minted rows alike. A LISTEN/NOTIFY nudge only makes ' +
                 'that prompt: the LOG is the contract, so a missed ' +
                 'notification costs latency and never a change. ' +
                 '`status.coordinates` and `status.replication` report it; ' +
                 '`persistence.coordinate` turns it off.\n\nTHE DATABASE ' +
                 'PASSWORD NEED NOT BE IN THE CONNECTION STRING SINCE ' +
                 '2026-09-12. `persistence.databasePasswordProvider` reads ' +
                 'it from the five places the key-encryption key comes from ' +
                 '— a mounted file, AWS Secrets Manager, Google Secret ' +
                 'Manager, Azure Key Vault, HashiCorp Vault — and by default ' +
                 'out of the SAME file or secret, told apart by a field. ' +
                 '`status.database.passwordFrom` says WHERE it came from and ' +
                 'never what it is, which is the rule this whole reply ' +
                 'follows about the connection string: the host, port, ' +
                 'database and user are parsed out of it and the string ' +
                 'itself is never returned.\n\nIT SHARES STATE AND NOT ' +
                 'SOCKETS. The KDC, both LDAP listeners, the two TLS ports ' +
                 'and SPIFFE\'s four are bound per process. And the replay ' +
                 'caches and DPoP jti sets CONVERGE rather than synchronise: ' +
                 'between a write in one process and its arrival in another ' +
                 'there is a window the size of persistence.pollInterval in ' +
                 'which a proof one process refused is accepted by ' +
                 'another.\n\nFIVE OF THE SIX SETTINGS ARE RESTART-ONLY, ' +
                 'because the store is opened and read before the HTTP ' +
                 'listener binds. `persistence.databaseUrl` is never echoed ' +
                 'back in `status` — it carries a password, so the host, ' +
                 'port, database and user are parsed out of it and reported ' +
                 'instead.' },
  // THE CLUSTER (2026-09-14, #46). Like `/persistence`, a `status` member beside
  // the settings, because `cluster.mode` SET and a cluster WORKING are two
  // facts. See admin.js's clusterStatusBlock().
  { path: '/cluster', console: '/admin/cluster', tag: 'Cluster',
    operationId: 'getClusterSettings',
    summary: 'Whether several nodes against one store behave as one ' +
             'service, and what active-active mode still waits for',
    description: 'The five `cluster.*` settings AND a `status` member: this ' +
                 'node\'s resolved mode, identity, heartbeat and leases; a ' +
                 'snapshot of every member row and every lease, read by the ' +
                 'database clock and at most one heartbeat old ' +
                 '(`status.snapshotAgeMs`); the capability table ' +
                 'active-active mode is held to (`status.self.capabilities`, ' +
                 'with `missing` and `acceptedMissing`); where each shared ' +
                 'secret\'s value came from (never the value); and the read ' +
                 'barrier\'s counters.\n\nIN ACTIVE-PASSIVE MODE ONE NODE ' +
                 'SERVES and every other node waits before it restores or ' +
                 'binds anything, so a standby never answers this operation ' +
                 '— what answers is the active node. IN ACTIVE-ACTIVE MODE ' +
                 'EVERY NODE SERVES, and a node refuses to start while a ' +
                 'capability is missing and not named in ' +
                 '`cluster.acceptMissingCapabilities`.\n\nEVERY CLUSTERED ' +
                 'WRITE IS FENCED by the node\'s membership (and in ' +
                 'active-passive mode by the service lease\'s token), and a ' +
                 'node that has lost either exits. A node\'s settings ' +
                 'fingerprint is never returned — only whether it agrees ' +
                 'with the node answering (`nodes[].agrees`).' },
  { path: '/wstrust', console: '/admin/wstrust', tag: 'WS-Trust',
    operationId: 'getWsTrustSettings',
    summary: 'The security token service\'s own setting',
    description: 'One setting — who a WS-Trust token says issued it — and it ' +
                 'is a different setting from `saml.issuer`, which is the ' +
                 'Issuer INSIDE the assertion. They share a default and were ' +
                 'one setting until they had to differ.\n\nWhat an assertion ' +
                 'CONTAINS is `GET /saml-attributes`: WS-Trust here issues ' +
                 'SAML 1.1 and SAML 2.0 assertions through the same two ' +
                 'builders the SAML profiles use.' },
  { path: '/wsfed', console: '/admin/wsfed', tag: 'WS-Federation',
    operationId: 'getWsFedSettings',
    summary: 'The passive requestor profile\'s own setting',
    description: 'One setting — the entity ID this service names itself by ' +
                 'in the WS-Federation metadata and in a sign-in ' +
                 'response.\n\nThe assertion it carries is a SAML 1.1 one, ' +
                 'so its Issuer is `saml.issuer` (on `GET /saml2` and `GET ' +
                 '/saml11`) and its contents are `GET /saml-attributes`. ' +
                 '`wauth` is recorded and not honoured and `wreqptr` is ' +
                 'never dereferenced; neither is a setting, and the page ' +
                 'says so rather than implying a missing one.' },
  { path: '/tls', console: '/admin/tls', tag: 'TLS',
    operationId: 'getTlsSettings',
    summary: 'The two TLS listeners\' own settings',
    description: 'The four `tls.*` settings: the two ports, and the ' +
                 'hostnames and IP addresses that go into the self-signed ' +
                 'certificate this service mints on every start.\n\nALL FOUR ' +
                 'ARE RESTART-ONLY: the certificate is minted and the ' +
                 'sockets are bound before anything is listening. One ' +
                 'certificate serves 8443, 9443, LDAPS 636 and — when ' +
                 '`global.https` is on — the main port, so a caller trusts ' +
                 'this service once rather than four times.\n\nWhether the ' +
                 'MAIN port is HTTPS is `global.https`, which is on `GET ' +
                 '/config` with the rest of the process\'s own settings: it ' +
                 'is a fact about the process rather than about these ' +
                 'listeners, and it defaults to whatever `oauth2.rfc9700` is.' }
].map(function (row) {
  return { method: 'GET', path: BASE + row.path, tag: row.tag,
           operationId: row.operationId,
           summary: row.summary,
           description: row.description +
             '\n\nTHERE IS NO POST BESIDE THIS ONE and that is not a gap: ' +
             'every form on the console page this mirrors posts `set-many` ' +
             'to /admin/config, so `POST /admin-api/config/set-many` is ' +
             'already the operation for it. One store, one action, two doors.',
           mirrors: 'GET ' + row.console,
           responseDescription: 'What the page says, and the settings it ' +
                                'draws — described rows carrying each ' +
                                'value\'s source and whether it can be ' +
                                'changed while the service runs.',
           responseSchema: { $ref: '#/components/schemas/PageSettings' },
           handler: function (req, res) {
             log.debug("Entering the management API " + row.console + " " +
                 "endpoint.");
             sendJson(res, 200, admin.protocolSettingsJsonFor(row.console));
             log.debug("Leaving the management API " + row.console + " " +
                 "endpoint.");
           } };
});

// ---------------------------------------------------------------------------
// THE REQUEST SCHEMA OF A NARROW DOOR, BUILT FROM THE LIST THAT DOOR ACTUALLY
// REFUSES AGAINST.
//
// `/token-lifetimes/set` and `/saml-assertions/set` exist to give a caller one
// refusal the wide `/config/set-many` cannot: a key outside their own list is
// refused BY NAME rather than ignored. That makes the list load-bearing in the
// document — a caller reads it to know what may be sent — and it was written
// out here BY HAND beside a list held in admin.js. Both had drifted: this
// document named four token-lifetime settings against six, and THREE assertion
// settings against sixteen. So it is derived, the way every operation in this
// file is derived from the table that registers it.
//
// The TYPE comes from config.js's own row for the setting, so a boolean does
// not arrive in the document as an integer.
function narrowDoorProperties(keys) {
  log.debug("Entering narrowDoorProperties(). " + keys.length + " key(s).");
  const out = {};
  const byKey = {};
  config.SETTINGS.forEach(function (setting) { byKey[setting.key] = setting; });
  keys.forEach(function (key) {
    const setting = byKey[key] || {};
    const type = setting.type === 'bool' ? 'boolean'
        : (setting.type === 'int' ? 'integer' : 'string');
    out[key] = { type: type, description: setting.label || '' };
  });
  log.debug("Leaving narrowDoorProperties().");
  return out;
}

// ---------------------------------------------------------------------------
// THE ATTRIBUTES SCOPED TO A PROTOCOL FAMILY, AS A SENTENCE, GENERATED.
//
// One row in `applications.SCHEMA` carries `families` today and the rule it
// declares is the only refusal in this registry that is about WHICH
// application rather than about which attribute — so a caller reading this
// document to learn what it may send has to be told, or it discovers the rule
// by being refused.
//
// GENERATED FROM THE SCHEMA AND NOT TYPED, for the reason the `set` and `add`
// descriptions above are: a hand-written list of what an operation accepts is a
// second definition of a table, and it goes wrong silently in exactly the
// document a caller trusts most. It answers with the empty string when nothing
// is family-scoped, so removing the last such row removes the paragraph.
function familyScopeNote() {
  log.debug("Entering familyScopeNote().");
  const scoped = applications.SCHEMA.attributes.filter(function (row) {
    return row.editable && row.families && row.families.length;
  });
  if (!scoped.length) {
    log.debug("Leaving familyScopeNote(). Nothing is family-scoped.");
    return '';
  }
  const listed = scoped.map(function (row) {
    const labels = row.families.map(function (id) {
      const family = applications.PROTOCOLS.filter(function (one) {
        return one.id === id;
      })[0];
      return family ? family.label : id;
    });
    return '`' + row.name + '` (' + labels.join(', ') + ')';
  }).join(', ');
  log.debug("Leaving familyScopeNote(). " + scoped.length + " attribute(s).");
  return '**' + (scoped.length === 1 ? 'One attribute is' : scoped.length +
         ' attributes are') + ' scoped to a PROTOCOL FAMILY and REFUSED on ' +
         'an application declared for none of ' +
         'them: ' + listed + '.** That is ' +
         'unlike every other attribute here, which is inert rather than ' +
         'wrong on an entry that never reaches the protocol it belongs to — ' +
         'these decide what an ENDPOINT does for an identifier, so on an ' +
         'entry no request could ever name they would read as a policy that ' +
         'was in force. Declare the family first (`protocols` on the create, ' +
         'or add to `appAllowedProtocol`). Clearing one is never refused, ' +
         'and `ldapmodify` reaches them like every other attribute.\n\n';
}

const ROUTES = [
  { method: 'GET', path: BASE, tag: 'Service',
    operationId: 'getIndex',
    summary: 'What this API is, and every operation in it',
    description: 'The index. Every operation with the console control it ' +
                 'mirrors, and where the OpenAPI document and the explorer ' +
                 'are. Nothing here changes anything.',
    mirrors: 'GET /admin',
    responseDescription: 'The index.',
    responseSchema: { $ref: '#/components/schemas/ApiIndex' },
    handler: function (req, res) {
      log.debug("Entering the management API index.");
      const base = baseUrlOf(req);
      sendJson(res, 200, {
        name: 'mock STS management API',
        version: VERSION,
        // THE PROVENANCE OF THAT NUMBER, BROKEN OUT rather than left as a
        // string to be parsed. A test asserting "this stack is running the
        // build it just made" wants the build number on its own, and a report
        // saying which commit an instance is on wants the commit — splitting
        // them here is the difference between a client reading a field and a
        // client writing a regular expression over `version`.
        //
        // `stamped` is the one that is easy to leave out and worth most: false
        // means this process computed its own number at startup because nothing
        // stamped an artifact, so the build number is the moment it STARTED and
        // comparing it with another instance's says nothing.
        build: APP_VERSION.build,
        commit: APP_VERSION.commit || undefined,
        builtAt: APP_VERSION.builtAt,
        stamped: APP_VERSION.stamped === true,
        openapi: base + BASE + '/openapi.json',
        // ------------------------------------------------------------
        // **READ FROM THE SETTING SINCE 2026-09-10; IT WAS THE LITERAL
        // `false`.** This API began requiring an access token on
        // 2026-09-09 and this field went on saying it did not — which a
        // caller could only ever read by presenting the credential the
        // field denied needing. The startup banner had the same bug and
        // was fixed the same day; this one and the OpenAPI document were
        // missed, and `admin_api_spec.js`'s own header argues why that
        // matters more for the document than for either sentence.
        // ------------------------------------------------------------
        protected: config.value('adminApi.authRequired') === true,
        // THE EXPLORER IS A CONSOLE PAGE SINCE 2026-09-09 and this field
        // still names it, because a client that read it wants to know
        // where the explorer IS rather than which path space it is in.
        // It moved when this API began requiring a token a browser has
        // no way to carry.
        docs: base + '/admin/api-explorer',
        console: base + '/admin',
        operations: operationSummaries()
      });
      log.debug("Leaving the management API index.");
    } },

  { method: 'GET', path: BASE + '/openapi.json', tag: 'Service',
    operationId: 'getOpenApi',
    summary: 'The OpenAPI 3.1 document for this API',
    description: 'Built from the same table that registers the routes, so it ' +
                 'describes what is actually there. `servers[0].url` is this ' +
                 'service as the request reached it, so a document fetched ' +
                 'through a proxy or a published port names the address the ' +
                 'caller can use.',
    mirrors: 'GET /admin/sts-metadata',
    responseDescription: 'The document.',
    responseSchema: { type: 'object',
                      description: 'An OpenAPI 3.1.0 document.' },
    handler: function (req, res) {
      log.debug("Entering the OpenAPI document endpoint.");
      sendJson(res, 200, spec.buildSpec(ROUTES, specOptions(req)));
      log.debug("Leaving the OpenAPI document endpoint.");
    } },

  // ---------------------------------------------------------------------
  // THE CRYPTO REPORT. It calls `adminViews.cryptoView()` and computes nothing
  // of its own, which is rule 7 read strictly: the page and this operation must
  // not be able to disagree about what this service's cryptography is, and the
  // way to make that impossible is for there to be one function.
  //
  // It answers 503 rather than 404 when the reporter was never installed —
  // which happens only if `admin-ui/crypto_metadata.js` was not required — and
  // the two are different facts: a route that exists and cannot answer is a
  // wiring mistake somebody can fix, and a route that does not exist is not.
  // The message names the module rather than saying "unavailable".
  // ---------------------------------------------------------------------
  { method: 'GET', path: BASE + '/crypto', tag: 'Service',
    operationId: 'getCryptoMetadata',
    summary: 'Every algorithm this service signs, verifies and encrypts with',
    description: 'What this service does with cryptography, for every ' +
                 'identity service it advertises: which digest, which ' +
                 'signature algorithm, which cipher, which key, and which ' +
                 'higher-level envelope each is wrapped in — JOSE, XMLDSIG ' +
                 'and XML Encryption, WS-Security, COSE, X.509, ' +
                 'Kerberos.\n\nEVERY ALGORITHM LIST IN THE REPLY IS READ ' +
                 'FROM THE MODULE THAT PERFORMS THE ALGORITHM, the way GET ' +
                 '/admin/sts-metadata reads its endpoint list off the live ' +
                 'express router — so it cannot claim something this service ' +
                 'does not do, and it reports drift against that page\'s own ' +
                 'family list in both directions.\n\nThe `postQuantum` ' +
                 'member is the one to read before quoting this reply: the ' +
                 'signatures are partly post-quantum and the key ' +
                 'establishment is entirely classical, and those are ' +
                 'reported separately because a signature is checked when it ' +
                 'is presented while captured ciphertext can be kept and ' +
                 'opened later.\n\nNOTHING HERE IS A SECRET: key types, key ' +
                 'identifiers, curve names, certificate fingerprints and ' +
                 'validity dates only, all of them already readable from ' +
                 '/oauth2/jwks, /tls/server-certificate and the SPIFFE ' +
                 'bundle endpoint. Nothing changes anything.',
    mirrors: 'GET /admin/crypto-metadata',
    responseDescription: 'The whole report.',
    responseSchema: { $ref: '#/components/schemas/CryptoMetadata' },
    handler: function (req, res) {
      log.debug("Entering the management API crypto metadata endpoint.");
      const report = adminViews.cryptoView(req);
      if (!report) {
        errorCodes.mark(res, 'STS-API-0011');
        sendJson(res, 503, { ok: false, errors: [
          'The crypto report is not installed in this process. ' +
          'admin-ui/crypto_metadata.js fills it at its own require time, and ' +
          'server.js requires that module after tls/tls_server. This is a ' +
          '503 and not a 404 because the route exists — what is missing is ' +
          'the module behind it.'] });
        log.debug("Leaving the management API crypto metadata endpoint. " +
                  "No reporter.");
        return;
      }
      sendJson(res, 200, report);
      log.debug("Leaving the management API crypto metadata endpoint.");
    } },

  // ---------------------------------------------------------------------
  // THE ENCRYPTION REPORT. `encryptionAdmin.encryptionView()` and nothing of
  // its own, which is rule 7 read the same strict way the crypto report above
  // it is: the console page and this operation must not be able to report
  // different NUMBERS for the same counters, and one function is the only way
  // to make that impossible.
  //
  // **IT NEEDS NO 503 BRANCH, unlike the operation above it**, and the
  // difference is worth stating rather than looking like an omission: that one
  // reaches its reporter across an inverted hook that a process may not have
  // filled, and this one reaches a module it requires directly. There is no
  // state in which the route exists and the function does not.
  // ---------------------------------------------------------------------
  { method: 'GET', path: BASE + '/encryption', tag: 'Service',
    operationId: 'getEncryption',
    summary: 'What this service encrypts at rest, and how much of it it has ' +
             'done',
    description: 'The at-rest half of this service\'s cryptography: which ' +
                 'data is sealed, where it lives, under which key and which ' +
                 'algorithm, and how many encryptions and decryptions have ' +
                 'happened in this process.\n\nIT IS NOT GET ' +
                 '/admin-api/crypto WITH FEWER FIELDS. That one answers what ' +
                 'this service DOES when it signs or encrypts — per protocol ' +
                 'family, read out of the module that performs each ' +
                 'algorithm — and reads identically on a service that ' +
                 'started a second ago. This one is TRAFFIC: `accounting` ' +
                 'goes up while something is happening, counted at the one ' +
                 'funnel both operations pass through rather than at the ' +
                 'call sites, because a total assembled from call sites is ' +
                 'wrong the first time somebody adds another one and is ' +
                 'wrong silently.\n\n`classes` LISTS WHAT IS DELIBERATELY ' +
                 'NOT SEALED BESIDE WHAT IS, each with the reason — ' +
                 'passwords are hashed rather than encrypted, which is ' +
                 'stronger; client secrets are in the clear because a ' +
                 'federation secret is SENT to somebody else\'s token ' +
                 'endpoint; the post-quantum keys, the TLS certificate and ' +
                 'the SPIFFE authorities are not persisted at all, so there ' +
                 'is nothing at rest to seal. A list of only the yeses would ' +
                 'answer "is X encrypted" by silence.\n\nTHE COUNTERS ARE ' +
                 'PROCESS-WIDE AND NOT PER REALM — a key-encryption key ' +
                 'belongs to the process — and they are in memory, so a ' +
                 'restart is how you get an empty one. Under ' +
                 '`workers.requestCount` each request worker keeps its own, ' +
                 'so a dispatched service answers this from whichever worker ' +
                 'took the call.\n\nNO CIPHERTEXT AND NO PLAINTEXT IS IN THE ' +
                 'REPLY, and there is no operation anywhere that opens a ' +
                 'sealed value on request: a sealed value is a private key, ' +
                 'an authenticator\'s shared secret or somebody\'s recovery ' +
                 'codes. `key.where` names the PROVIDER the key-encryption ' +
                 'key is read from and never the key.\n\n**`boundaries` IS ' +
                 'THE PART TO READ BEFORE ACTING ON THE REST**, and it is in ' +
                 'this reply rather than in a document because a machine ' +
                 'reader has no page to have read it on. Two limits and one ' +
                 'deployment mistake: there is ONE key-encryption key for ' +
                 'the service and NOT one per trust realm (`perRealmKey: ' +
                 'false`), so a realm is not a cryptographic boundary at ' +
                 'rest and rotating the key rotates every realm; everything ' +
                 'NOT in `classes` is plaintext in the store, because the ' +
                 'layer that covers a whole database belongs under it rather ' +
                 'than inside it (a column-level answer leaves plaintext in ' +
                 'the WAL, in spilled sorts, in a pg_dump, on replicas and ' +
                 'in query logs) — that layer is the operator\'s and ' +
                 'docs/encryption-at-rest.md is the write-up; and the key ' +
                 'must not live on the volume it protects, which is what the ' +
                 '`file` provider invites and why every other provider exists.',
    mirrors: 'GET /admin/encryption',
    responseDescription: 'The whole report.',
    responseSchema: { type: 'object',
      description: 'The encryption report: `mode`, `key` (present, durable ' +
                   'or ephemeral, and which provider), `algorithm` (read ' +
                   'from common/crypto.js\'s own table), `store`, `classes` ' +
                   '(what is sealed and what is not, each with its counts), ' +
                   '`accounting` (the totals and the breakdown by label), ' +
                   '`unclassified` (labels counted that the page has no row ' +
                   'for, reported rather than dropped) and `boundaries` — ' +
                   'the two limits of everything else in the reply, as ' +
                   'sentences plus the one field worth asserting on ' +
                   '(`perRealmKey: false`).' },
    handler: function (req, res) {
      log.debug("Entering the management API encryption report endpoint.");
      sendJson(res, 200, encryptionAdmin.encryptionView(req));
      log.debug("Leaving the management API encryption report endpoint.");
    } },

  // ---------------------------------------------------------------------
  // THE DATABASE REPORT. `databaseAdmin.databaseView()` and nothing else,
  // which is rule 7 read the strict way: the page and this operation must not
  // be able to report different numbers, and one function is the only way to
  // make that impossible.
  //
  // **IT IS THE ONE OPERATION ON THIS API WHOSE REPLY SHAPE IS DECIDED BY
  // SOMETHING OUTSIDE THIS SERVICE**, and a client has to be told so rather
  // than discovering it: the members under `probes.*.row` and `probes.*.rows`
  // are PostgreSQL's own columns, so they differ between major versions. A
  // client reading a named column should treat its absence as ordinary.
  // ---------------------------------------------------------------------
  { method: 'GET', path: BASE + '/database', tag: 'Service',
    operationId: 'getDatabase',
    summary: 'Everything PostgreSQL reports about itself, and this ' +
             'service\'s schema in it',
    description: 'Twenty probes against PostgreSQL\'s catalog views, each ' +
                 'run, timed and caught SEPARATELY: the server and its ' +
                 'uptime, the database size, every counter in ' +
                 '`pg_stat_database`, the backends and locks, the background ' +
                 'writer, the checkpointer, the write-ahead log and the ' +
                 'archiver, then per-table and per-index statistics, sizes, ' +
                 'columns and constraints for the schema this service ' +
                 'owns.\n\n**THE COLUMNS ARE THE SERVER\'S AND NOT THIS ' +
                 'API\'S.** Every statement is a `SELECT *`, because ' +
                 'PostgreSQL moves these views between major versions — ' +
                 '`pg_stat_bgwriter` has eleven columns on 16 and four on 17 ' +
                 'and later, when the checkpoint counters moved to a view ' +
                 'that does not exist before 17. So a client reading a named ' +
                 'column must treat its absence as ordinary rather than as ' +
                 'an error, and the reply is the right place to learn what ' +
                 'this server actually has.\n\n**A PROBE THAT FAILED IS A ' +
                 'MEMBER AND NOT AN ABSENCE**: `probes.<id>.ok` is false and ' +
                 '`code` carries PostgreSQL\'s SQLSTATE, because 42P01 (no ' +
                 'such relation — an older server) and 42501 (insufficient ' +
                 'privilege — this service does not hold `pg_monitor`) are ' +
                 'completely different things to do something about. ' +
                 '`failed` lists them.\n\n`derived` carries four RATIOS ' +
                 'PostgreSQL deliberately does not keep — cache hit, ' +
                 'rollback share, dead-tuple share, and indexes nothing has ' +
                 'ever scanned — all of them cumulative since `stats_reset`, ' +
                 'which is in the reply beside them. `schemaDrift` is the ' +
                 'one ASSERTION here rather than a measurement: the objects ' +
                 'the driver declares against the ones the server actually ' +
                 'has, a check nothing else in this service makes.\n\n**IT ' +
                 'ANSWERS 200 WITH `available: false` WHEN THERE IS NO ' +
                 'DATABASE**, which is the ordinary case: `persistence.mode` ' +
                 'defaults to `memory`. That is not an error — the question ' +
                 'was answerable and the answer is that there is nothing to ' +
                 'report — and `why` says which of three reasons it ' +
                 'is.\n\nNOTHING HERE CHANGES ANYTHING and no connection ' +
                 'string is in the reply: `target` names the host, port, ' +
                 'database and user, parsed by the one function in this ' +
                 'service that already does that without printing the ' +
                 'password.',
    mirrors: 'GET /admin/database',
    responseDescription: 'The whole report.',
    responseSchema: { type: 'object',
      description: 'The database report: `available` and `why`, `target`, ' +
                   '`pool` (this process\'s client-side pool, sampled before ' +
                   'the page borrows a connection), `probes` keyed by probe ' +
                   'id with the server\'s own columns inside, `derived`, ' +
                   '`schemaDrift` and `failed`.' },
    handler: function (req, res) {
      log.debug("Entering the management API database report endpoint.");
      // **AWAITED, AND THE HANDLER CATCHES.** Express 4 does not look at what
      // a handler returns, so a rejection here would be an unhandled
      // rejection and a request that never gets an answer — the same trap the
      // token endpoint's wrapper exists for. This is the only operation on
      // this API that talks to a database, so it is the only one that can
      // reject for a reason outside this process.
      databaseAdmin.databaseView().then(function (report) {
        sendJson(res, 200, report);
        log.debug("Leaving the management API database report endpoint.");
      }).catch(function (e) {
        errorCodes.mark(res, 'STS-API-0012');
        sendJson(res, 500, { ok: false, errors: [
          'The database report could not be built: ' +
          (e && e.message ? e.message : String(e))] });
        log.debug("Leaving the management API database report endpoint. It " +
                  "threw.");
      });
      log.debug("Leaving handler().");
    } },

  // ---------------------------------------------------------------------
  // THE SECRET-STORE REPORT. `secretsAdmin.secretsView()` and nothing else,
  // which is rule 7 read the strict way: the page and this operation must not
  // be able to report a different state of the same store.
  //
  // **NOTHING IN THE REPLY IS A SECRET AND NOTHING IN IT CAME FROM READING
  // ONE.** Every probe behind it is a metadata read — a stat of the key file,
  // a `sys` endpoint, a KV version history, a `DescribeSecret`, a listing of
  // version properties — and `common/secrets.js` deletes a deny-list of
  // member names from whatever a provider hands back before it leaves that
  // module. This operation is `admin:read`, like every other read here, and
  // there is deliberately no write beside it: a rotate would destroy
  // everything sealed under the key.
  // ---------------------------------------------------------------------
  { method: 'GET', path: BASE + '/secrets', tag: 'Service',
    operationId: 'getSecrets',
    summary: 'Where the key-encryption key and the database password come ' +
             'from, and what the store holding them is doing',
    description: 'The two primordial secrets this service READS and never ' +
                 'writes: the key-encryption key everything it seals is ' +
                 'sealed under, and the database password. For each — the ' +
                 'provider, the location, the field taken out of a JSON ' +
                 'value, whether it is sharing the other one\'s location, ' +
                 'and whether THIS PROCESS has actually read it, with the ' +
                 'instant and the error if the last attempt failed. That ' +
                 'last one is the fact no settings row can carry: a ' +
                 'development-mode service never asks for the key, so a ' +
                 'perfectly broken configuration and a working one look ' +
                 'identical until the mode changes.\n\n`stores` is one ' +
                 'member per STORE rather than per secret, because two ' +
                 'secrets kept in one place share its state. What is in it ' +
                 'depends on the provider: `file` answers the path, mode, ' +
                 'owner, mtime and which members the file holds if it is ' +
                 'JSON; `vault` answers the seal status, the health summary, ' +
                 'the leader, the certificate this service presents and when ' +
                 'it expires, the token the login produced, **what that ' +
                 'identity may actually do — asked of the store rather than ' +
                 'quoted from a policy file** — and the engines it can see; ' +
                 '`aws`, `gcp` and `azure` publish their metadata against ' +
                 'the secret itself.\n\n**NO PROBE FETCHES A SECRET VALUE ' +
                 'AND NONE IS IN THE REPLY.** Every one is a metadata read, ' +
                 'and the module they live in deletes a deny-list of member ' +
                 'names — `value`, `data`, `token`, `id` among them — from ' +
                 'whatever a provider answers before it leaves.\n\n**A PROBE ' +
                 'THAT FAILED IS A MEMBER AND NOT AN ABSENCE**, with `ok: ' +
                 'false` and, where the store gave one, the HTTP status in ' +
                 '`status`. Here half of them are SUPPOSED to fail: the ' +
                 'identity this service holds is bound to two read paths, so ' +
                 'a 403 against anything else is the policy working. Each is ' +
                 'bounded by `keys.storeProbeTimeoutMs` and they run in ' +
                 'parallel, so an unreachable store costs that bound once.',
    mirrors: 'GET /admin/secrets',
    responseDescription: 'The whole report.',
    responseSchema: { type: 'object',
      description: 'The secret-store report: `secrets` (one per secret, with ' +
                   '`configured`, `provider`, `where`, `field`, `shared`, ' +
                   '`lastRead` and its own `probes`), `stores` (one per ' +
                   'store, with `probes`), `mode`, `persistingKeys`, ' +
                   '`timeoutMs` and `failed`.' },
    handler: function (req, res) {
      log.debug("Entering the management API secret store report endpoint.");
      // **AWAITED, AND THE HANDLER CATCHES**, for `getDatabase`'s reason:
      // express 4 does not look at what a handler returns, so a rejection
      // would be an unhandled rejection and a request that never gets an
      // answer. This is the other operation here that talks to something
      // outside this process.
      secretsAdmin.secretsView().then(function (report) {
        sendJson(res, 200, report);
        log.debug("Leaving the management API secret store report endpoint.");
      }).catch(function (e) {
        errorCodes.mark(res, 'STS-API-0013');
        sendJson(res, 500, { ok: false, errors: [
          'The secret store report could not be built: ' +
          (e && e.message ? e.message : String(e))] });
        log.debug("Leaving the management API secret store report endpoint. " +
                  "It threw.");
      });
      log.debug("Leaving handler().");
    } },

  // ---------------------------------------------------------------------
  // THE EMBEDDED PROTOCOL DEBUGGER (2026-09-13). `debuggerAdmin.debuggerView()`
  // and nothing else — rule 7 — and read-only: the debugger's settings are
  // `config/set` like every other row, and who may USE it is the two console
  // roles, granted at `rbac/grant`. Pinned to the front process, which is the
  // only one holding the listener and the api child.
  // ---------------------------------------------------------------------
  { method: 'GET', path: BASE + '/debugger', tag: 'Service',
    operationId: 'getDebugger',
    summary: 'Whether the identity protocol debugger is embedded, where it ' +
             'answers, and what its api process is doing',
    description: 'The embedded identity protocol debugger: `embedded` and ' +
                 'the setting and mode that decided it, the listener\'s ' +
                 '`port` and whether it is `listening`, the client ' +
                 '(`clientId`), the resource server (`resource`), the ' +
                 'permission its api requires (`permission`) and the ' +
                 'audience a token for it carries (`audience`), and under ' +
                 '`api` the child process: its `state` (`starting`, ' +
                 '`running`, `restarting`, `given-up`, `not-installed`, ' +
                 '`stopped`), process id, socket, starts, consecutive ' +
                 'failures, last exit and last error, and — in product mode ' +
                 '— the `allowedRanges` it may dial. `settings` is the ' +
                 '`Protocol debugger` group as `/admin/debugger` draws ' +
                 'it.\n\nNothing here opens the debugger: its gate is the ' +
                 'permission, which the authorization server issues to ' +
                 'console administrators only.',
    mirrors: 'GET /admin/debugger',
    responseDescription: 'The debugger report.',
    responseSchema: { type: 'object',
      description: 'The debugger report: `embedded`, `setting`, `mode`, ' +
                   '`started`, `startProblem`, `listening`, `port`, ' +
                   '`listenError`, `scheme`, `publicBaseUrl`, ' +
                   '`uiDirectory`, `clientId`, `resource`, `permission`, ' +
                   '`audience`, `api` and `settings`.' },
    handler: function (req, res) {
      log.debug("Entering the management API debugger report endpoint.");
      try {
        sendJson(res, 200, debuggerAdmin.debuggerView());
      } catch (e) {
        log.debug("Caught in handler(): " + ((e && e.message) || e));
        errorCodes.mark(res, 'STS-DBG-0023');
        sendJson(res, 500, { ok: false, errors: [
          'The debugger report could not be built: ' +
          (e && e.message ? e.message : String(e))] });
      }
      log.debug("Leaving the management API debugger report endpoint.");
    } },

  // ---------------------------------------------------------------------
  // THE KEY PAIRS. Two operations, because LISTING what this process holds and
  // HANDING A KEY OVER are different acts and only the second is a write.
  // ---------------------------------------------------------------------
  { method: 'GET', path: BASE + '/keys', tag: 'Service',
    operationId: 'getKeys',
    summary: 'Every key pair this process generated at start, and what it is ' +
             'for',
    description: 'A LIST and never key material. The signing keys are per ' +
                 'trust realm and the TLS certificate belongs to the ' +
                 'process, and each row says which. `formats` is what that ' +
                 'key can be exported as, computed rather than listed: a key ' +
                 'with no certificate cannot be a PKCS#12, and a ' +
                 'post-quantum key has no PKCS#8 encoding at all, so the ' +
                 'answer differs per key for two different ' +
                 'reasons.\n\nNothing here is key material. POST ' +
                 '/admin-api/keys/export is the operation that hands one over.',
    mirrors: 'GET /admin/keys',
    responseDescription: 'The key pairs.',
    responseSchema: { $ref: '#/components/schemas/KeyList' },
    handler: function (req, res) {
      log.debug("Entering the management API key list endpoint.");
      const report = adminViews.keysView(req);
      if (!report) {
        errorCodes.mark(res, 'STS-API-0011');
        sendJson(res, 503, { ok: false, errors: [
          'The crypto reporter is not installed in this process. ' +
          'admin-ui/crypto_metadata.js fills it at its own require time.'] });
        log.debug("Leaving the management API key list endpoint. No reporter.");
        return;
      }
      sendJson(res, 200, report);
      log.debug("Leaving the management API key list endpoint.");
    } },

  // AN ACTION RESOURCE RATHER THAN A BARE POST, and the suite is why. Every
  // other POST here is `/<resource>/:action`, and `sts_admin_api_operations.js`
  // probes each of them with an action nobody has heard of and requires a 400
  // naming the ones that exist. A literal `/keys/export` looked like that
  // resource and was not one, so the probe got a 404 — the route pattern
  // simply did not match. One `export` action today; a second (an import, a
  // rotation) goes in the same list.
  { method: 'POST', route: BASE + '/keys/:action', tag: 'Service',
    mirrors: 'POST /admin/keys/export',
    handler: function (req, res) {
      log.debug("Entering the management API key export endpoint.");
      const body = withAction(req, parseBody(req));
      if (body.action !== 'export') {
        // THE SENTENCE IS THE SHAPE THE SUITE READS, and that is not a
        // formatting preference: `sts_admin_api_operations.js` matches
        // `Unknown action "x". <phrase>: <list>.` on every action resource,
        // because `admin_api.js` uses the same sentence to check that every
        // console action has an operation here. A handler that stopped writing
        // it would turn that check off with nothing failing.
        errorCodes.mark(res, 'STS-API-0014');
        sendJson(res, 400, { ok: false, errors: [
          'Unknown action "' + body.action + '". The actions here are: ' +
          'export.'] });
        log.debug("Leaving the management API key export endpoint. " +
                  "Unknown action.");
        return;
      }
      const pending = adminViews.keysExport(String(body.key || ''),
                                       String(body.format || 'pem'),
                                       String(body.password || ''));
      if (!pending) {
        errorCodes.mark(res, 'STS-API-0011');
        sendJson(res, 503, { ok: false, errors: [
          'The crypto reporter is not installed in this process.'] });
        log.debug("Leaving the management API key export endpoint. No " +
                  "reporter.");
        return;
      }
      pending.then(function (result) {
        if (!result.ok) {
          errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0015');
          sendJson(res, 400, result);
          log.debug("Leaving the management API key export endpoint. Refused.");
          return;
        }
        sendJson(res, 200, {
          ok: true,
          status: result.status,
          publicOnly: !!result.publicOnly,
          files: result.files.map(function (file) {
            const data = Buffer.isBuffer(file.data) ? file.data
              : (typeof file.data === 'string' ? Buffer.from(file.data, 'utf8')
                 : Buffer.from(file.data));
            return { name: file.name, mime: file.mime,
                     bytes: data.length,
                     base64: data.toString('base64') };
          })
        });
        log.debug("Leaving the management API key export endpoint. " +
                  result.files.length + " file(s).");
      }).catch(function (e) {
        errorCodes.mark(res, 'STS-API-0016');
        sendJson(res, 400, { ok: false, errors: ['The export failed: ' +
                                                 e.message] });
        log.debug("Leaving the management API key export endpoint. Threw.");
      });
      log.debug("Leaving handler().");
    },
    actions: [
      { action: 'export', operationId: 'exportKey',
        summary: 'Hand over one key pair, in a chosen keystore format',
        description: 'THIS OPERATION RETURNS PRIVATE KEY MATERIAL. It is the ' +
                 'API half of the one page in this console where reading is ' +
                 'taking.\n\nIt is defensible because of what these keys ' +
                 'are: generated at start, held only in memory, dead when ' +
                 'the process exits, and protecting nothing — this service ' +
                 'checks no password and validates no token it did not mint. ' +
                 '**This API is not gated at all**, so anybody who can reach ' +
                 'this port can call it; that is the same honest consequence ' +
                 'every other operation here has, stated again because this ' +
                 'one returns a key.\n\n`format` is one of `pem`, `der`, ' +
                 '`jwk` or `pkcs12`. A password is REQUIRED for `pkcs12` and ' +
                 'optional for the rest, where it encrypts the private half. ' +
                 'The reply carries the file base64-encoded rather than raw, ' +
                 'because this API answers JSON everywhere else and a caller ' +
                 'that suddenly got octets would have to special-case one ' +
                 'operation.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            key: { type: 'string',
                   description: 'The `id` from GET /admin-api/keys.' },
            format: { type: 'string', enum: ['pem', 'der', 'jwk', 'pkcs12'],
                      description: 'PKCS#12 is offered only for a key this ' +
                                   'service holds a certificate for — the ' +
                                   'signing key and the TLS key.' },
            password: { type: 'string',
                        description: 'REQUIRED for `pkcs12`; optional for ' +
                                     'the other three, where it encrypts the ' +
                                     'private half. Empty means the private ' +
                                     'key comes out in the clear.' }
          },
          required: ['key', 'format'],
          // THE EXAMPLE IS WHAT DRIVES THIS OPERATION IN THE SUITE.
          // `sts_admin_api_operations.js` walks every GET and every POST that
          // carries one; an operation with no example is covered by nothing
          // and reported by nothing, which is what its ledger refuses. `pem`
          // with no password is chosen deliberately — it is the one
          // combination that needs nothing set up and hands back a file every
          // tool reads.
          examples: [{ key: 'sts-rsa', format: 'pem', password: '' }],
          additionalProperties: false
        },
        responseDescription: 'The exported files.',
        responseSchema: { $ref: '#/components/schemas/KeyExport' } }
    ] },

  // ---------------------------------------------------------------------
  // THE EXPLORER USED TO BE HERE — `GET /admin-api/docs` and
  // `/admin-api/docs/explorer.js` — AND MOVED TO THE CONSOLE ON 2026-09-09.
  //
  // It is `/admin/api-explorer`, built by `admin-ui/api_explorer.js` at 19a.
  // The move happened because of the change three sections up: this API began
  // requiring an OAuth 2.0 access token, and a browser navigating to a URL
  // carries none — so the one page in this service written to be opened in a
  // browser had become the one page a browser could not open. The console
  // linked to it and the link answered 401.
  //
  // **THE OPERATION BELOW IS WHAT RULE 7 ASKS FOR NOW.** A console page gets an
  // operation here that names it, and this is that page's — it reports what the
  // explorer is reading and what the caller's roles would let them do, without
  // repeating the document, which `GET /admin-api/openapi.json` above already
  // is.
  //
  // Two things did NOT move and are worth saying so nobody goes looking:
  // `admin_api_docs.js` and `admin_api_explorer.js` are still in this
  // directory, because the style, the script and the realm-prefix argument
  // belong to this API's document rather than to the console's shell. The
  // console requires them.
  // ---------------------------------------------------------------------
  { method: 'GET', path: BASE + '/api-explorer', tag: 'Service',
    operationId: 'getApiExplorer',
    summary: 'What the console\'s API explorer reads, and what you may drive',
    description: 'The explorer is a page of the ADMIN CONSOLE at ' +
                 '`/admin/api-explorer` — it was `/admin-api/docs` until ' +
                 '2026-09-09, when this API began requiring an access token ' +
                 'a browser cannot carry. This operation reports where the ' +
                 'document is, how many paths and operations it describes, ' +
                 'and the audience a token for this API must name. It does ' +
                 'NOT repeat the document: `GET ' + BASE + '/openapi.json` ' +
                 'is the document.\n\nThe `scope` member is what the CONSOLE ' +
                 'SESSION\'s roles would grant — it is what the page puts in ' +
                 'the token it mints for the person reading it, so a reader ' +
                 'holding Admin Read alone sees `admin:read` and knows ' +
                 'before pressing anything that a write would be refused. ' +
                 '**It is EMPTY when this operation is called with an access ' +
                 'token rather than read off the page**, which is the ' +
                 'ordinary case here: there is no console session on such a ' +
                 'request, and reporting the token\'s own scopes back to the ' +
                 'caller that sent them would be telling somebody what they ' +
                 'just said.',
    mirrors: 'GET /admin/api-explorer',
    responseDescription: 'Where the explorer reads from, and what the caller ' +
                         'may drive.',
    responseSchema: { type: 'object', properties: {
      page: { type: 'string', description: 'The console page.' },
      api: { type: 'string', description: 'The API it drives.' },
      document: { type: 'string',
                  description: 'Where the page reads the OpenAPI document ' +
                               'from — a console path, so that it arrives on ' +
                               'the session the page was drawn with.' },
      version: { type: 'string', description: 'This build, M.N.O.' },
      paths: { type: 'integer', description: 'Paths in the document.' },
      operations: { type: 'integer', description: 'Operations in it.' },
      scope: { type: 'string',
               description: 'The scopes this caller\'s roles grant.' },
      audience: { type: 'string',
                  description: 'What a token for this API must name in ' +
                               '`aud`. Computed outside any realm, because ' +
                               'the credential is service-wide.' },
      tokenInReply: { type: 'boolean',
                      description: 'Always false, and named so that its ' +
                                   'absence is a statement rather than an ' +
                                   'omission: the console page is handed a ' +
                                   'token because it has already ' +
                                   'authenticated the person reading it, and ' +
                                   'this reply is read by scripts.' }
    } },
    handler: function (req, res) {
      log.debug("Entering the API explorer operation.");
      // LAZILY REQUIRED, and it is the one lazy require in this file. That
      // module is loaded at 19a — after this one — because it needs the route
      // table below to build its document; a require at the top of this file
      // would be a cycle, and one in the other direction would move routes.
      // The same arrangement `xacml.js` and `xacml_admin.js` have.
      sendJson(res, 200,
               require('../admin-ui/api_explorer').explorerJson(req));
      log.debug("Leaving the API explorer operation.");
    } },

  { method: 'GET', path: BASE + '/status', tag: 'Service',
    operationId: 'getStatus',
    summary: 'What this service is and how much it has done',
    description: 'The issuer, when it started, and the running totals. The ' +
                 'cheapest call here and the one to poll: it takes a ' +
                 'snapshot and counts, and reads no list.',
    mirrors: 'GET /admin',
    responseDescription: 'The current totals.',
    responseSchema: { $ref: '#/components/schemas/Status' },
    handler: function (req, res) {
      log.debug("Entering the management API status endpoint.");
      sendJson(res, 200, admin.consoleJson());
      log.debug("Leaving the management API status endpoint.");
    } },

  { method: 'GET', path: BASE + '/metrics', tag: 'Metrics',
    operationId: 'getMetrics',
    summary: 'Every call, every artifact, and both kinds of session',
    description: 'Endpoint calls by matched route and status class, tokens ' +
                 'and artifacts by kind with the state of each, and sessions ' +
                 'counted BOTH ways — the browser sign-on sessions this ' +
                 'process holds, and the sessions implied by what it has ' +
                 'issued. The two disagree on purpose; the schema says why.',
    mirrors: 'GET /admin/metrics',
    responseDescription: 'The snapshot.',
    responseSchema: { $ref: '#/components/schemas/Metrics' },
    handler: function (req, res) {
      log.debug("Entering the management API metrics endpoint.");
      sendJson(res, 200, adminViews.metricsJson());
      log.debug("Leaving the management API metrics endpoint.");
    } },

  { method: 'GET', path: BASE + '/users', tag: 'Users',
    operationId: 'getUsers',
    summary: 'Everyone this service has authenticated, or one of them in full',
    description: 'Without `user` it is the list. With it, one identity: the ' +
                 'names they were seen under, how they authenticated each ' +
                 'time, every sign-on session they hold with the tokens ' +
                 'issued ON each of those, and their LDAP entry. A name this ' +
                 'service has never seen answers 200 with `known: false` ' +
                 'rather than 404 — it is an answer about the identity, not ' +
                 'about the route.\n\nThe identity is a QUERY PARAMETER and ' +
                 'not a path segment on purpose: the identities here contain ' +
                 'the characters a path is made of (a Kerberos service ' +
                 'principal is `HTTP/host`, a subject is a `urn:`), so ' +
                 '/users/HTTP/web.example.com would be a two-segment path ' +
                 'naming nobody.\n\nONE PAGE PARAMETER IS NOT IN THE LIST ' +
                 'BELOW, because its name is data: each session\'s own token ' +
                 'list is moved by `session-<the session id>Page`, so ' +
                 '`?user=alice&session-8Qk3...Page=2` moves that block and ' +
                 'no other, and each session in the reply answers with its ' +
                 'own `tokensPaging`. It is named after the session rather ' +
                 'than numbered so that the link still moves the same ' +
                 'session after the list around it has changed, and it is ' +
                 'paged at all because one browser session can hold most of ' +
                 'the tokens this service remembers. OpenAPI cannot spell a ' +
                 'parameter whose name is built at runtime, and a ' +
                 '`session-{id}Page` in the list would generate a client ' +
                 'that sends a literal `{id}` — so it is here in words ' +
                 'instead.',
    mirrors: 'GET /admin/users',
    parameters: [
      { name: 'user', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'One identity, as the list\'s `key` names them. Returns ' +
                     'the drill-down instead of the list.' },
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the identity key, case-insensitive.' },
      { name: 'protocol', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'Only identities that authenticated through this ' +
                     'protocol family. The list\'s `protocols` member says ' +
                     'which values there are; it is read off the data, so a ' +
                     'family nobody has used is not offered.' }
    ].concat(pagingParameters()).concat(detailPagingParameters([
      { name: 'sessions',
        description: 'Sign-on session blocks, which default to ' +
                     admin.DEFAULT_BLOCKS_PER_PAGE + ' rather than ' +
                     admin.DEFAULT_PER_PAGE + ' because each one carries a ' +
                     'token list of its own. Only the sessions ON this page ' +
                     'are in the reply.' },
      { name: 'tokensOnEndedSessions',
        description: 'Tokens issued on a session this service no longer ' +
                     'holds.' },
      { name: 'tokensWithNoSession',
        description: 'Tokens issued with no browser session at all: the ' +
                     'grants that never involve one.' },
      { name: 'artifacts',
        description: 'SAML assertions, Kerberos tickets and credentials.' }
    ])),
    responseDescription: 'The list, or one identity.',
    responseSchema: { oneOf: [
      { $ref: '#/components/schemas/UserList' },
      { $ref: '#/components/schemas/UserDetail' }
    ] },
    handler: function (req, res) {
      log.debug("Entering the management API users endpoint.");
      sendJson(res, 200, adminViews.usersJson(req));
      log.debug("Leaving the management API users endpoint.");
    } },

  // RULE 7 FOR /admin/users/new, and it earns its place beyond the parity for
  // the same reason `getNewApplicationForm` does one resource along: what it
  // answers is the CLOSED CATALOGUE `createUser()` validates `attributes`
  // against. A caller that reads this cannot construct a create the service
  // will refuse with "a person here does not have an attribute called ...",
  // and it learns the list from the service rather than from a copy of it in a
  // document.
  //
  // THERE IS NO POST BESIDE IT, which is rule 7 read exactly rather than by
  // shape: that page's controls post `action=create` and `action=fill`, the
  // first is `createUser` below and already exists, and the second creates
  // nothing — it fills a FORM in for a person to edit, and the values it writes
  // are the ones `invent: true` on a create has always written directly. An
  // operation that returned form values to nobody would be an operation with no
  // act behind it.
  { method: 'GET', path: BASE + '/users/new', tag: 'Users',
    operationId: 'getNewUserForm',
    summary: 'Every attribute a person may be created with, and the four ' +
             'ways they can be given a way in',
    description: 'The ATTRIBUTE CATALOGUE a create takes in `attributes` — ' +
                 'one row per attribute a person in this directory may ' +
                 'carry, each naming the claim it reaches in an issued token ' +
                 'or credential and the document its name comes from — plus ' +
                 'the container DN the entry would land in, the realm, and ' +
                 'the four `credential` options.\n\n**It creates nobody**: ' +
                 'the create is `POST /admin-api/users/create`. This is the ' +
                 'list that call validates against, and an attribute name ' +
                 'that is not on it is REFUSED rather than dropped — so a ' +
                 'caller that reads this first cannot be told afterwards ' +
                 'that half of what it sent was ignored.\n\n**`uid` and ' +
                 '`userPassword` are deliberately not on it.** `uid` is the ' +
                 'username, sent as `username`, and a second way to set it ' +
                 'would allow an entry at `uid=alice` whose uid attribute ' +
                 'says `bob`. A password goes through `credential`, so that ' +
                 '`credentials.js` hashes it — an attribute door that took ' +
                 '`userPassword` would write one in the clear.\n\n**The ' +
                 'container is THIS REALM\'S.** The embedded directory is ' +
                 'per trust realm, so `/realm/acme/admin-api/users/new` ' +
                 'answers with acme\'s `ou=users` and a person created there ' +
                 'is invisible to every other realm.',
    mirrors: 'GET /admin/users/new',
    responseDescription: 'The attribute catalogue, the credential options, ' +
                         'the container and the realm.',
    responseSchema: { $ref: '#/components/schemas/NewUserForm' },
    handler: function (req, res) {
      log.debug("Entering the management API new-user endpoint.");
      // STRAIGHT TO THE LAYER, like the new-application resource beside it.
      sendJson(res, 200, adminViews.newUserJson(req));
      log.debug("Leaving the management API new-user endpoint.");
    } },

  { method: 'POST', route: BASE + '/users/:action', tag: 'Users',
    // TWO CONSOLE PATHS, AND BOTH ARE NAMED. One resource legitimately mirrors
    // several controls — /admin-api/xacml/{action} names three — and this
    // action switch is reached from the Users list and from /admin/users/new,
    // which posts to itself rather than to the list so that a generated
    // password and an activation link can be answered in a page body rather
    // than in a 303's query string. Naming only the first would leave the
    // console suite unable to tell that page's Create button from a control
    // that reaches nothing.
    mirrors: 'POST /admin/users and POST /admin/users/new',
    handler: function (req, res) {
      log.debug("Entering the management API users action endpoint.");
      const body = parseBody(req);
      const request = withAction(req, body);
      // A CREATE CLAIMS ITS NAME FIRST — see `claimForCreate()`.
      return runClaimed(res, request.action === 'create'
        ? { username: String(request.username || request.user || '') }
        : null, function (held) {
        // `via: 'api'` and whatever actor the caller named, for the audit rows
        // the two second-factor clears write — the same honesty
        // `rbacAction`'s caller keeps: this API authenticates a CLIENT rather
        // than a person, so an empty actor is the true answer rather than an
        // inconvenient one.
        const result = adminActions.usersAction(request,
                                         { via: 'api', actor: '',
                                           // The address a password reset
                                           // link is built on (2026-09-13).
                                           base: baseUrlOf(req) });
        held.settle(!!result.ok);
        if (!result.ok) {
          errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0030');
        }
        sendJson(res, result.ok ? 200 : 400, result);
        log.debug("Leaving the management API users action endpoint.");
      });
    },
    actions: [
      { action: 'issue-activation', operationId: 'issueActivationLink',
        summary: 'Issue a one-time activation link for a provisioned person',
        description: 'How somebody created through POST ' +
                     '/admin-api/users/create, SCIM or an LDAP add comes to ' +
                     'have a way in. They are provisioned with no ' +
                     'credential; this mints a single-use, time-limited URL ' +
                     'at which they choose a password, a security key, or ' +
                     'both.\n\n**THE URL IS RETURNED ONCE AND NEVER AGAIN.** ' +
                     'What is stored is a scrypt hash, so this service ' +
                     'cannot produce it a second time — only replace it, ' +
                     'which is what calling this again does. Treat it as the ' +
                     'credential it is: anybody holding it can complete the ' +
                     'account setup, so a leaked link is an account ' +
                     'takeover.\n\nIt expires after ' +
                     '`security.activationTtlMinutes` and is spent the ' +
                     'moment the setup FINISHES — not when the link is ' +
                     'opened, because a link burned by a mail scanner or a ' +
                     'browser prefetch would strand the person it was ' +
                     'for.\n\nThere is deliberately no self-service version: ' +
                     'with no mail channel here it would have to show the ' +
                     'link on screen, which is an account takeover with a ' +
                     'username as the only input.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            user: { type: 'string',
                    description: 'The person, as /admin-api/users names ' +
                                 'them. They must already exist.' },
            username: { type: 'string', description: 'Accepted for `user`.' }
          },
          required: ['user'],
          examples: [{ user: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'The activation URL, ONCE, and when it expires.' },

      { action: 'create', operationId: 'createUser',
        summary: 'Put a person in the directory before they authenticate',
        description: 'An entry under `ou=users` usually appears because ' +
                     'somebody AUTHENTICATED — at either sign-in screen, on ' +
                     'a password grant, with a `UsernameToken`, in a ' +
                     'Kerberos AS-REQ. This is how to get one in ahead of ' +
                     'that, which is what a client testing claims from the ' +
                     'directory needs: the entry carries the invented person ' +
                     'behind that name, so a credential issued for them and ' +
                     'an `ldapsearch` for the entry say the same thing from ' +
                     'the start.\n\n**One entry per person, and this is one ' +
                     'of three doors onto that rule.** A username already ' +
                     'here is refused with the DN that holds it — whatever ' +
                     'protocol brought them, and whichever attribute their ' +
                     'entry is named by, since a person whose entry was ' +
                     'created by a client certificate is at ' +
                     '`cn=<name>,ou=users` rather than ' +
                     '`uid=<name>,ou=users`. An `ldapadd` under `ou=users` ' +
                     'gets the same refusal as LDAP_ENTRY_ALREADY_EXISTS ' +
                     '(68), because all three call one function.\n\n**No ' +
                     'password is set unless one is ASKED FOR** through ' +
                     '`credential` below. That default is what this ' +
                     'operation has always done and is right in development ' +
                     'mode, where no password is checked here in this ' +
                     'protocol or any other; in product mode a person with ' +
                     'no credential cannot sign in, and `activation` is how ' +
                     'they are given one. Creating the entry does not put ' +
                     'the name in `GET /admin-api/users`: that lists ' +
                     'identities this service has SEEN authenticate, and ' +
                     'this writes what the directory HOLDS.\n\n**SINCE ' +
                     '2026-09-06 IT TAKES THE PERSON\'S DETAILS AND A ' +
                     'CREDENTIAL**, which is what the console\'s ' +
                     '/admin/users/new form posts. `attributes` are checked ' +
                     'against the catalogue `GET /admin-api/users/new` ' +
                     'publishes and an unknown name is REFUSED rather than ' +
                     'dropped; `invent` decides whether the rest are made ' +
                     'up, and it DEFAULTS TO TRUE so that a caller written ' +
                     'before this gets exactly what it always got.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            username: { type: 'string',
                        description: 'The name they will authenticate under ' +
                                     '— the same string that appears in a ' +
                                     'token\'s `sub` and on /admin/users. ' +
                                     'Not a DN and not a `did:`, and it may ' +
                                     'not carry a character RFC 4514 ' +
                                     'reserves in a DN: those name entries ' +
                                     'that get here by being presented ' +
                                     'rather than by being created.' },
            note: { type: 'string',
                    description: 'Optional. What the entry\'s `description` ' +
                                 'says about why it exists; the default says ' +
                                 'it was created by hand rather than by ' +
                                 'authenticating. An ' +
                                 '`attributes.description` wins over it, ' +
                                 'because an operator\'s own sentence about ' +
                                 'a person is the more useful one and two ' +
                                 'values would be the entry answering the ' +
                                 'question twice.' },
            attributes: {
              type: 'object',
              description: 'What is known about them, as `{attribute: ' +
                           'value}`. The names are the catalogue `GET ' +
                           '/admin-api/users/new` publishes, in that ' +
                           'document\'s own spelling, and they are the names ' +
                           'the entry carries — so an `ldapsearch` shows ' +
                           'exactly what was sent.\n\n**A NAME THAT IS NOT ' +
                           'ON THE CATALOGUE IS REFUSED and the whole create ' +
                           'fails**, rather than the value being ignored: ' +
                           'silently dropping it would answer "created" to a ' +
                           'request asking for something this did not do. ' +
                           '`userPassword` is refused by that rule — use ' +
                           '`credential` — and so is `uid`, which is ' +
                           '`username`.\n\nAn empty string is the same as ' +
                           'sending nothing: the attribute is absent from ' +
                           'the entry rather than present and empty.',
              additionalProperties: true
            },
            invent: {
              type: 'boolean',
              description: 'Whether to MAKE UP the attributes not sent. ' +
                           '**Defaults to TRUE**, which is what this ' +
                           'operation has always done and what its own ' +
                           'description above promises: `vc_claims.js` ' +
                           'invents a consistent person per username, so the ' +
                           'entry and any credential issued for them agree ' +
                           'from the start.\n\nSend `false` for an entry ' +
                           'carrying ONLY what you sent — its object ' +
                           'classes, its uid, a description and your ' +
                           'attributes. That is what the console\'s form ' +
                           'does. It is not a promise the entry stays that ' +
                           'way: the Populate button on /admin/vc fills ' +
                           'every missing SELECTED attribute on every ' +
                           'person, and does not know which were typed.'
            },
            credential: {
              type: 'string',
              description: 'How they first get in. **`generate` is the ' +
                           'DEFAULT since 2026-09-12**: a password drawn to ' +
                           'satisfy this realm\'s password policy (`GET ' +
                           '/admin-api/policies`), set, and RETURNED ONCE in ' +
                           '`password` — this service stores a scrypt hash ' +
                           'and cannot produce it again. It costs one hash ' +
                           'per create, about 70ms, so a bulk load that ' +
                           'wants nobody holding anything sends `none`. ' +
                           '`none` was the default before, and in ' +
                           'development mode it is enough to sign in, since ' +
                           'no password is checked there; `password`, ' +
                           'hashing the `password` field onto the entry, and ' +
                           'refused by the password policy in product mode ' +
                           'when it does not meet it; `activation`, issuing ' +
                           'a single-use link and returning it ONCE in ' +
                           '`activationUrl` for you to send them, at which ' +
                           'they choose a password, a security key or ' +
                           'both.\n\n**A CREDENTIAL STEP THAT FAILS DOES NOT ' +
                           'UNDO THE CREATE.** A password can only be ' +
                           'written onto an entry that exists, so the person ' +
                           'is there either way; the reply is `ok: true` ' +
                           'with `credentialError` set and says so, because ' +
                           'answering `ok: false` would send a caller to ' +
                           'create them again and meet "that username is ' +
                           'taken".',
              enum: ['none', 'password', 'generate', 'activation']
            },
            password: { type: 'string',
                        description: 'Read only when `credential` is ' +
                                     '`password`. Hashed with scrypt by ' +
                                     'credentials.js and never stored or ' +
                                     'logged in the clear; nothing in this ' +
                                     'service can show it again.' },
            passwordConfirm: { type: 'string',
                               description: 'Optional, and CHECKED WHERE ' +
                                            'SENT: the console\'s form ' +
                                            'always sends it, because a ' +
                                            'mistyped password nobody can ' +
                                            'read back is a person who ' +
                                            'cannot sign in and nobody who ' +
                                            'can say why. An API caller with ' +
                                            'one value has nothing to ' +
                                            'mistype against and may omit it.' }
          },
          required: ['username'],
          examples: [{ username: 'rcbj' },
                     { username: 'dana', invent: false,
                       attributes: { givenName: 'Dana', sn: 'Okafor',
                                     mail: 'dana@example.com',
                                     employeeNumber: 'E004417' },
                       credential: 'activation' }],
          additionalProperties: false
        },
        responseDescription: 'The entry as created, in `entry`, with its ' +
                             '`dn`; `typed` naming the attributes you sent ' +
                             'and `invented` whether the rest were made up. ' +
                             'A generated password is in `password` and an ' +
                             'activation link in `activationUrl` — EACH ' +
                             'RETURNED ONCE, because what is stored is a ' +
                             'hash and this service cannot produce either ' +
                             'again.' },

      // THE OPERATION THAT WAS DOCUMENTED BEFORE IT EXISTED (2026-09-06).
      // `common/credentials.js` names `POST /admin-api/users/set-password`
      // twice — in the sentence a refused sign-in gets, and in the banner the
      // product-mode bootstrap prints telling an operator to change the
      // generated password — and no such operation had ever been written.
      // Somebody following either instruction got a 404 naming an endpoint
      // this service documents.
      { action: 'set-password', operationId: 'setUserPassword',
        summary: 'Set or replace somebody\'s password',
        description: 'Hashed with scrypt by `credentials.js`, which is the ' +
                     'one place in this service a password is ever verified ' +
                     'or set, and written to `userPassword` on their ' +
                     'directory entry. **It cannot be read back by ' +
                     'anything** — not this API, not the console, not an ' +
                     '`ldapsearch`, which sees the hash — so a lost password ' +
                     'is replaced rather than recovered.\n\nSend `password`, ' +
                     'or `generate: true` to have one made up and RETURNED ' +
                     'ONCE. The person must already exist; this creates ' +
                     'nobody.\n\n**IN DEVELOPMENT MODE THIS CHANGES ALMOST ' +
                     'NOTHING AND IS STILL WORTH DOING.** Nothing here ' +
                     'checks a password in development — every one is ' +
                     'accepted — so setting one does not make a sign-in work ' +
                     'that would otherwise fail. What it does is put the ' +
                     'attribute on the entry, which is what an LDAP client ' +
                     'reads, what `hasPassword()` counts, and what product ' +
                     'mode would need. In PRODUCT mode it is the credential.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            user: { type: 'string',
                    description: 'The person, as /admin-api/users names ' +
                                 'them. They must already exist.' },
            username: { type: 'string', description: 'Accepted for `user`.' },
            password: { type: 'string',
                        description: 'The password to set. Required unless ' +
                                     '`generate` is true.' },
            passwordConfirm: { type: 'string',
                               description: 'Optional, checked where sent.' },
            generate: { type: 'boolean',
                        description: 'Make one up instead — 32 bytes of ' +
                                     'randomBytes, base64url, the same ' +
                                     'generator the product-mode bootstrap ' +
                                     'account uses. It is RETURNED ONCE in ' +
                                     '`password` and never again.' }
          },
          required: ['user'],
          examples: [{ user: 'alice', generate: true }],
          additionalProperties: false
        },
        responseDescription: 'Whether it was set, and — only where it was ' +
                             'GENERATED — the password, once. A password you ' +
                             'sent is never echoed back: you already hold ' +
                             'it, and returning it would put it in a second ' +
                             'place.' },

      // -----------------------------------------------------------------
      // THE TWO SECOND-FACTOR REMOVALS (2026-09-10). They are `POST
      // /admin-api/mfa/clear-totp` and `/clear-key` as well — the same two
      // acts through the same switch — and both spellings work because the
      // console control moved and a caller's script did not.
      //
      // **THERE IS NO ENROL BESIDE THEM AND THERE CANNOT BE.** Enrolling an
      // authenticator means being shown a shared secret, and a management
      // API that handed one out would be an administrative door that mints a
      // working second factor for any account — which is not a second factor
      // at all. A WebAuthn ceremony happens in the person's own browser
      // against their own authenticator, which no API can stand in for.
      // Both are `/portal`, or `/portal/activate` with a link that is itself
      // a credential.
      // -----------------------------------------------------------------
      { action: 'clear-totp', operationId: 'clearUserAuthenticatorApp',
        summary: 'Clear somebody\'s authenticator app enrolment',
        description: '**THE ONLY WAY BACK FOR SOMEBODY WHO HAS LOST THEIR ' +
                     'PHONE.** The shared secret lives on that device and ' +
                     'this service cannot reach it, and there is ' +
                     'deliberately no self-service reset anywhere — a second ' +
                     'factor anybody can remove is not a second ' +
                     'factor.\n\nIt CANNOT lock anybody out: a one-time code ' +
                     'is never a primary credential here, so clearing one ' +
                     'drops the account to one factor rather than to none. ' +
                     'The person sets a new one up at ' +
                     '`/portal/mfa`.\n\nClearing an enrolment nobody holds ' +
                     'answers 400 rather than 200: the caller asked to clear ' +
                     'a specific thing and it was not there.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            user: { type: 'string',
                    description:
                      'The person, as /admin-api/users names them.' },
            username: { type: 'string', description: 'Accepted for `user`.' }
          },
          required: ['user'],
          examples: [{ user: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'Whose enrolment was cleared.' },

      // -----------------------------------------------------------------
      // THE THIRD REMOVAL (2026-09-10), AND IT IS ALSO THE ONLY ISSUING
      // CONTROL THIS API HAS FOR RECOVERY CODES.
      //
      // There is no `issue-backup-codes` beside it and there will not be, for
      // the reason the two above have no `enrol`: a set is created by the ACT
      // of enrolling a second factor and by nothing else, and a management
      // API that minted one would be an administrative door handing a working
      // second factor to any account. What this operation does is DELETE a
      // set, which re-arms the automatic issue — the next second factor that
      // person enrols creates a new one.
      // -----------------------------------------------------------------
      { action: 'clear-backup-codes', operationId: 'clearUserBackupCodes',
        summary: 'Clear somebody\'s recovery codes',
        description: '**THE ONLY ROUTE TO A SECOND SET.** A set is issued ' +
                     'automatically, and ONCE, the first time somebody ' +
                     'asks for one from the user portal; ' +
                     'does nothing while a set exists, so clearing is what ' +
                     'lets the next enrolment issue one.\n\n**It cannot lock ' +
                     'anybody out** — a recovery code is never a way in on ' +
                     'its own — but it removes the way BACK, so somebody ' +
                     'whose set is cleared and who then loses their phone ' +
                     'needs an operator again.\n\n**There is no operation ' +
                     'that READS the codes and there will not be.** They are ' +
                     'a working second factor; `GET /users` reports how many ' +
                     'remain and never what they are. The person reads their ' +
                     'own set back on `/portal/mfa`, which is the only place ' +
                     'in this service that shows one.\n\nClearing a set ' +
                     'nobody holds answers 400 rather than 200, for ' +
                     '`clear-totp`\'s reason.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            user: { type: 'string',
                    description:
                      'The person, as /admin-api/users names them.' },
            username: { type: 'string', description: 'Accepted for `user`.' }
          },
          required: ['user'],
          examples: [{ user: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'Whose set was cleared.' },

      // -----------------------------------------------------------------
      // WHAT AN ADMINISTRATOR DOES TO SOMEBODY'S CREDENTIALS (2026-09-13),
      // mirroring the Password and second-factor controls on a person's
      // /admin/users page. Every one says what it did over Shared Signals —
      // a CAEP credential-change per credential, RISC
      // account-credential-change-required for a reset, RISC
      // recovery-information-changed for cleared recovery codes — to every
      // stream that asked for the type and covers the person.
      // -----------------------------------------------------------------
      { action: 'reset-password', operationId: 'resetUserPassword',
        summary: 'Reset somebody\'s password to a generated one, returned once',
        description: 'Generates a password under this realm\'s password ' +
                     'policy, sets it, and **returns it ONCE** in `password` ' +
                     '— the entry holds a scrypt hash and nothing can show ' +
                     'it ' +
                     'again. Then three things the ordinary `set-password` ' +
                     'does not do: `pwdReset` is set, so the person must ' +
                     'choose their own password at the sign-in screen before ' +
                     'anything is signed in; any password reset link ' +
                     'outstanding is spent; and they are **signed out of ' +
                     'everything** through the same function `POST ' +
                     '/admin-api/logout/global` calls.\n\n**Shared ' +
                     'Signals**: a CAEP `credential-change` (`password`, ' +
                     '`update`) and a RISC ' +
                     '`account-credential-change-required`, plus a CAEP ' +
                     '`session-revoked` for each session the sign-out ends. ' +
                     'They are sent after the reply, and ' +
                     '`caep.autoEmitTypes` ' +
                     'and `risc.autoEmitTypes` decide whether they go at all.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            user: { type: 'string',
                    description:
                      'The person, as /admin-api/users names them.' },
            username: { type: 'string', description: 'Accepted for `user`.' }
          },
          required: ['user'],
          examples: [{ user: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'The generated password, ONCE, whether the ' +
                             'forced change was recorded (`forcedChange`) ' +
                             'and what the sign-out ended (`signedOut`).' },

      { action: 'issue-password-reset', operationId: 'issuePasswordResetLink',
        summary: 'Revoke somebody\'s password and issue a one-time reset link',
        description: 'Mints a single-use link to `/portal/reset-password`, ' +
                     '**returned ONCE** in `resetUrl` (absolute, on the ' +
                     'address this request arrived at, realm prefix ' +
                     'included), valid for ' +
                     '`security.passwordResetTtlMinutes`. The token in it is ' +
                     'stored as a hash; issuing another replaces it.\n\n' +
                     '**The password the person had is REMOVED** and they ' +
                     'are ' +
                     '**signed out of everything**, so until the link is ' +
                     'used ' +
                     'they cannot sign in with a password. At the link they ' +
                     'choose a new one under the realm\'s password policy; ' +
                     'the removed password is in the history, so it cannot ' +
                     'simply be chosen again where the history is ' +
                     'enforced.\n\n**Shared Signals**: a CAEP ' +
                     '`credential-change` (`password`, `revoke`) where a ' +
                     'password was removed, a RISC ' +
                     '`account-credential-change-required`, and a CAEP ' +
                     '`credential-change` (`password`, `create`) when the ' +
                     'link is spent.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            user: { type: 'string',
                    description:
                      'The person, as /admin-api/users names them.' },
            username: { type: 'string', description: 'Accepted for `user`.' }
          },
          required: ['user'],
          examples: [{ user: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'The reset link, ONCE, when it expires, whether ' +
                             'a password was removed (`passwordRevoked`) and ' +
                             'what the sign-out ended.' },

      { action: 'disable-primary-keys', operationId: 'disableUserPasskeys',
        summary: 'Remove every primary security key, so a passkey no longer ' +
                 'signs somebody in',
        description: 'Removes every WebAuthn credential enrolled in the ' +
                     '`primary` role — the ones that sign the person in with ' +
                     'no password. A key in the `mfa` role is untouched.\n\n' +
                     '**Refused where it would leave no way in**: a person ' +
                     'with no password whose primary keys are their only ' +
                     'credential. Reset their password or issue a reset link ' +
                     'first. Refused too for somebody holding no primary ' +
                     'key.\n\n**Shared Signals**: a CAEP ' +
                     '`credential-change` (`fido2-roaming`, `delete`) per ' +
                     'key, ' +
                     'with its label as `friendly_name`.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            user: { type: 'string',
                    description:
                      'The person, as /admin-api/users names them.' },
            username: { type: 'string', description: 'Accepted for `user`.' }
          },
          required: ['user'],
          examples: [{ user: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'The keys removed — id, role, label and when ' +
                             'enrolled; never a public key.' },

      { action: 'disable-mfa', operationId: 'disableUserSecondFactors',
        summary: 'Remove every second factor somebody holds',
        description: 'Removes the authenticator app enrolment, every ' +
                     'security key in the `mfa` role and the recovery codes, ' +
                     'in one act. It cannot lock anybody out, because none ' +
                     'of ' +
                     'those is a way in. If a second factor is still ' +
                     'REQUIRED ' +
                     'of the person — `require-mfa`, or ' +
                     '`authn.mfaRequired` for the realm — their next sign-in ' +
                     'asks them to enrol a new one, which is how to reset ' +
                     'somebody\'s MFA.\n\nRefused for somebody who holds no ' +
                     'second factor.\n\n**Shared Signals**: a CAEP ' +
                     '`credential-change` (`delete`) for the authenticator ' +
                     'app (`app`) and for each key (`fido2-roaming`), and a ' +
                     'RISC `recovery-information-changed` where recovery ' +
                     'codes were removed.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            user: { type: 'string',
                    description:
                      'The person, as /admin-api/users names them.' },
            username: { type: 'string', description: 'Accepted for `user`.' }
          },
          required: ['user'],
          examples: [{ user: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'What was removed, and whether a second factor ' +
                             'is still required of them (`requirement`).' },

      { action: 'require-mfa', operationId: 'requireUserSecondFactor',
        summary: 'Require somebody to sign in with a second factor',
        description: 'Sets `stsMfaRequired` on the person\'s entry. At the ' +
                     'sign-in screen they are then asked for a second factor ' +
                     '— and, while they hold none, shown a step to enrol an ' +
                     'authenticator app or a security key before any session ' +
                     'is started. A passwordless security-key sign-in is ' +
                     'refused while it is required.\n\n**What it does not ' +
                     'reach** is every sign-in that never meets that screen: ' +
                     'federation, SPNEGO, a TLS client certificate, the ' +
                     'OAuth ' +
                     'password grant, an LDAP bind, WS-Trust and SCIM Basic. ' +
                     '`authn.mfaRequired` is the same requirement for every ' +
                     'person in the realm.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            user: { type: 'string',
                    description:
                      'The person, as /admin-api/users names them.' },
            username: { type: 'string', description: 'Accepted for `user`.' }
          },
          required: ['user'],
          examples: [{ user: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'The requirement as it now stands, by account ' +
                             'and by realm.' },

      { action: 'stop-requiring-mfa',
        operationId: 'stopRequiringUserSecondFactor',
        summary: 'Take the per-account second-factor requirement off',
        description: 'Clears `stsMfaRequired`. A realm requirement ' +
                     '(`authn.mfaRequired`) is unaffected and the reply says ' +
                     'whether one is in force. A second factor the person ' +
                     'holds goes on being asked for, as it always is.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            user: { type: 'string',
                    description:
                      'The person, as /admin-api/users names them.' },
            username: { type: 'string', description: 'Accepted for `user`.' }
          },
          required: ['user'],
          examples: [{ user: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'The requirement as it now stands.' },

      { action: 'clear-key', operationId: 'clearUserSecurityKey',
        summary: 'Remove one of somebody\'s security keys',
        description: 'Goes through the same `removeKey()` the person\'s own ' +
                     'portal calls, which is what carries the refusal that ' +
                     'matters: **it will not remove the last way in.** A ' +
                     'person with no password whose only PRIMARY key this is ' +
                     'would be locked out by an operator\'s call, and an ' +
                     'operator must not be able to do what the owner is ' +
                     'stopped from doing.\n\nThe credential id is the ' +
                     'base64url one on this person\'s `factors.keys`, on ' +
                     '`GET /admin-api/mfa`\'s rows, and on `/portal/keys`.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            user: { type: 'string' },
            username: { type: 'string', description: 'Accepted for `user`.' },
            credentialId: { type: 'string',
                            description: 'base64url, as WebAuthn produced it.' }
          },
          required: ['user', 'credentialId'],
          examples: [{ user: 'alice', credentialId: 'q1w2e3r4' }],
          additionalProperties: false
        },
        responseDescription: 'Whether the key was removed, or why it was not.' }
    ] },

  // ---------------------------------------------------------------------
  // SESSIONS. The other half of /tokens, and the resource behind
  // /admin/sessions — rule 7, in the same change as the page.
  //
  // It is a SEPARATE resource from /logout rather than a shape of it, and the
  // two questions are why: that one is *what is alice still signed into*, keyed
  // on one identity and reaching ten families; this one is *who is signed in at
  // all*, across everybody, in the three families that have a session. A `user`
  // parameter on the one below could not have answered it, because the answer
  // has no user in it.
  //
  // Both read `logout/logout.js`, which is the one model of what a live session
  // is — and the POST here is `terminate()` with a selection of one, the SAME
  // function `POST /admin-api/logout/selective` calls. Two operations over one
  // termination, which is the arrangement rule 7 asks for: the console grew a
  // button, so this grew the operation that mirrors it.
  { method: 'GET', path: BASE + '/sessions', tag: 'Sessions',
    operationId: 'getSessions',
    summary: 'Every session this service is holding right now, across the ' +
             'three protocols that have one',
    description: 'WHAT IS LIVE, as opposed to what has been ISSUED — which ' +
                 'is `GET /admin-api/tokens`, and everything in that list ' +
                 'outlives everything in this one.\n\nA session is state ' +
                 'THIS SERVICE holds that makes somebody currently ' +
                 'authenticated. Three protocols here have one and the other ' +
                 'seven do not:\n\n* the **browser sign-on session** from ' +
                 '`/authn/login`, which OAuth 2.0 / OIDC, WS-Federation, ' +
                 'SAML 2.0, SAML 1.1 and the admin console all share — so ' +
                 'one row may be carrying relying parties, realms and ' +
                 'service providers at once, and `protocol` says which ' +
                 'protocol the sign-in came THROUGH while `carries` says ' +
                 'what is riding on it;\n* the **Kerberos ticket-granting ' +
                 'ticket**, because a TGT is the Kerberos session and a ' +
                 'service ticket is one use of it;\n* the **LDAP ' +
                 'connection**, because RFC 4511 section 4.2 makes a Bind ' +
                 'the authorization state of a CONNECTION.\n\n**THE EXPIRY ' +
                 'IS WORKED OUT DIFFERENTLY IN EACH AND `expiryRule` SAYS ' +
                 'HOW.** A browser session expires at an absolute instant ' +
                 'fixed when it was created (`authn.sessionLifetimeS`) and ' +
                 'is NOT extended by use; `authn.sessionIdleTimeoutS`, off ' +
                 'by default, ends one earlier when it goes unused. A TGT ' +
                 'expires at the `endtime` the KDC sealed into the ticket, ' +
                 'which nothing can move. An LDAP connection has NO EXPIRY ' +
                 'and answers `expiresAt: 0`, which is not an expiry of the ' +
                 'epoch.\n\nEvery row carries the `key` and `id` that `POST ' +
                 '/admin-api/sessions/revoke` takes, and — for a browser ' +
                 'session — the `sessionId` that `GET ' +
                 '/admin-api/tokens?session=` takes.',
    mirrors: 'GET /admin/sessions',
    parameters: [
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Narrows to rows whose username, subject, handle, ' +
                     'identity key, kind or protocol contains this. One box ' +
                     'over all of them, because a reader arrives holding ' +
                     'exactly one and does not know which.' },
      { name: 'protocol', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'Only sessions started through this protocol. The ' +
                     '`protocol` values in the reply are what there is to ' +
                     'ask for; they are read off the live rows rather than ' +
                     'written down, because a federated sign-in names the ' +
                     'relationship it came through.' }
    ].concat(pagingParameters()),
    responseDescription: 'The live sessions, filtered and paged.',
    responseSchema: { $ref: '#/components/schemas/SessionList' },
    handler: function (req, res) {
      log.debug("Entering the management API sessions endpoint.");
      // `.json`, because sessionsView() returns the whole MODEL — the rows,
      // the paging and the filters the page needs, with the machine answer
      // inside it. The console used to export a wrapper that unwrapped it
      // here, and repointing this call at the layer without the unwrap
      // answered the model: `/admin-api/sessions` reported 0 sessions for a
      // person holding nine, with nothing erroring.
      sendJson(res, 200, adminViews.sessionsView(req).json);
      log.debug("Leaving the management API sessions endpoint.");
    } },

  { method: 'POST', route: BASE + '/sessions/:action', tag: 'Sessions',
    mirrors: 'POST /admin/sessions',
    handler: function (req, res) {
      log.debug("Entering the management API sessions action endpoint.");
      const body = parseBody(req);
      // `by` REACHES THE EVENT and not only the audit row: the session
      // family spends it as the `via` it hands `endSessionById()`, and
      // `dropSession()` decides CAEP's `initiating_entity` by looking for
      // `admin` or `console` in that string. "the management API" alone
      // reported a person signing themselves out, which is the one
      // distinction that member exists to draw.
      const result = adminActions.sessionsAction(withAction(req, body),
        { by: 'the management API at /admin-api/sessions' });
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0031');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API sessions action endpoint.");
    },
    actions: [
      { action: 'revoke', operationId: 'revokeSession',
        summary: 'End one live session',
        description: 'The Revoke button on every row of /admin/sessions, ' +
                     'driven without a browser. It is `terminate()` with a ' +
                     'selection of one — the SAME function a global logout ' +
                     'goes through — so it writes the same audit row, ' +
                     'honours the same two settings and gives the same ' +
                     'refusals.\n\n**IT IS NOT ONE ACT ACROSS THE THREE ' +
                     'KINDS AND THE DIFFERENCE MATTERS.** On a browser ' +
                     'session it ends that session and everything hanging ' +
                     'off it: the relying parties are notified, the refresh ' +
                     'tokens issued on it are revoked. On an LDAP row it ' +
                     'closes the socket, which the client sees as its ' +
                     'connection dropping mid-conversation. On a Kerberos ' +
                     'row it does MORE than the row it names — it stamps a ' +
                     'sign-out instant on the PRINCIPAL, after which every ' +
                     'ticket-granting ticket that principal authenticated ' +
                     'before now is refused KDC_ERR_TGT_REVOKED (20), ' +
                     'because Kerberos has no per-ticket revocation. It ' +
                     'still reaches no service ticket already in a cache: ' +
                     'accepting one never contacts this KDC. Every row\'s ' +
                     '`why` says which of the three it is before it is ' +
                     'pressed.\n\nA row that names nothing any more — it ' +
                     'ended between the read and the write — answers 400 ' +
                     'saying so rather than 200 having done nothing, and the ' +
                     'whole `terminate()` result is in `result`.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            key: { type: 'string',
                   description: 'Whose session it is: the normalised ' +
                                'identity key, which every row of GET ' +
                                '/admin-api/sessions carries as `key`. The ' +
                                'termination is keyed on an identity, which ' +
                                'is why this is needed beside the id.' },
            select: { type: 'string',
                      description: 'Which session, in the form the list ' +
                                   'gives it as `id`: `session:…`, `ldap:…` ' +
                                   'or `krb5:…@REALM`. It is the identifier ' +
                                   'POST /admin-api/logout/selective takes ' +
                                   'too, because both go through one ' +
                                   'termination.' }
          },
          required: ['key', 'select'],
          examples: [{ key: 'alice', select: 'session:8mJ2b1u0Qb' }],
          additionalProperties: false
        },
        responseDescription: 'What was ended, or why it could not be. The ' +
                             'whole termination result is in `result`, ' +
                             'including `skipped` and `unknown`.' }
    ] },

  { method: 'GET', path: BASE + '/logout', tag: 'Sign-out',
    operationId: 'getLiveSessions',
    summary: 'Everything this service is still holding for one identity, ' +
             'across every protocol family',
    description: 'The protocol-independent view of a person\'s live state. ' +
                 'Without `user` it is the FAMILY LIST — what a logout can ' +
                 'reach, what it cannot, and why — which is the same prose ' +
                 '/logout and /admin/logout print, read off one table in ' +
                 '`logout/logout.js` rather than copied here.\n\nWith `user` ' +
                 'it is that identity: every browser sign-on session, every ' +
                 'relying party, realm and service provider signed into on ' +
                 'one, every token still revocable, every outstanding ' +
                 'authorization and pre-authorized code, every directory ' +
                 'connection bound as them, and the Kerberos sign-out ' +
                 'instant.\n\n**The rows that CANNOT be ended are in the ' +
                 'reply on purpose** and carry `terminable: false` with a ' +
                 '`why`. A SAML assertion already issued, a Kerberos service ' +
                 'ticket already in a cache and an X509-SVID already minted ' +
                 'cannot be recalled by this service or by a real one — ' +
                 'nothing consults the issuer when they are presented — and ' +
                 'a reply that omitted them would make a global logout look ' +
                 'complete when it is not.\n\nThe identity is a QUERY ' +
                 'PARAMETER and not a path segment for the reason ' +
                 '/admin-api/users gives: the identities here contain the ' +
                 'characters a path is made of.',
    mirrors: 'GET /admin/logout',
    parameters: [
      { name: 'user', in: 'query', required: false, schema: { type: 'string' },
        description: 'The identity to look at, as typed. It is normalised ' +
                     'the way every other door here normalises one, so ' +
                     '`alice`, `alice@REALM` and a `urn:` subject are one ' +
                     'answer.' },
      { name: 'family', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'Only rows of this family. The `families` member of the ' +
                     'reply says which values there are; it is read off the ' +
                     'same table the endpoint acts on, so a family that ' +
                     'cannot occur is never offered.' }
    ].concat(pagingParameters()),
    responseDescription: 'The family list, or one identity\'s live state.',
    responseSchema: { $ref: '#/components/schemas/LogoutInventory' },
    handler: function (req, res) {
      log.debug("Entering the management API sign-out endpoint.");
      sendJson(res, 200, adminViews.logoutJson(req).json);
      log.debug("Leaving the management API sign-out endpoint.");
    } },

  { method: 'POST', route: BASE + '/logout/:action', tag: 'Sign-out',
    mirrors: 'POST /admin/logout',
    handler: function (req, res) {
      log.debug("Entering the management API sign-out action endpoint.");
      const body = parseBody(req);
      const result = adminActions.logoutAction(withAction(req, body));
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0032');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API sign-out action endpoint.");
    },
    actions: [
      { action: 'global', operationId: 'globalLogout',
        summary: 'End everything this service holds for one identity',
        description: 'The default a person gets from `POST /logout` with an ' +
                     'empty body, driven by name. Every browser sign-on ' +
                     'session, every relying party, realm and service ' +
                     'provider on one, every revocable token, every ' +
                     'outstanding code, every directory connection bound as ' +
                     'them, and a Kerberos sign-out instant after which a ' +
                     'TGS-REQ carrying an older ticket is refused ' +
                     'KDC_ERR_TGT_REVOKED (20).\n\n**What it cannot do is ' +
                     'reported rather than skipped.** The reply\'s `skipped` ' +
                     'array names every live thing that survived and says ' +
                     'why.\n\n**What it cannot do FROM HERE is different and ' +
                     'is also in the reply.** A front-channel logout ' +
                     'notification is an iframe in the signed-out person\'s ' +
                     'own browser and a WS-Federation cleanup is an image in ' +
                     'it; neither is something this process performs. They ' +
                     'come back in `notifications` and `cleanups` so a ' +
                     'caller can load them, and `/logout` is the page where ' +
                     'a browser does it by itself.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            user: { type: 'string',
                    description: 'The identity to sign out, as typed. ' +
                                 'Normalised the way the GET normalises one.' }
          },
          required: ['user'],
          examples: [{ user: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'The act, in `result`: `terminated`, `skipped`, ' +
                             '`unknown`, and the three fan-outs a browser ' +
                             'has to perform.' },
      { action: 'end', operationId: 'endLiveSessions',
        summary: 'End named items and nothing else',
        description: 'The selective half. `select` carries row ids from the ' +
                     'GET — `session:<id>`, `token:<jti>`, ' +
                     '`wsfed-rp:<session>|<realm>`, and so on.\n\n**An empty ' +
                     '`select` is REFUSED here and is a global logout at ' +
                     '`POST /logout`**, which is the one place the two doors ' +
                     'differ and is deliberate: an empty selection arriving ' +
                     'at this operation is a caller that built a list and ' +
                     'got nothing, where an empty body at /logout is a ' +
                     'caller asking for everything. Same absence, opposite ' +
                     'intent.\n\nIds are re-resolved against what is live ' +
                     'NOW rather than trusted, so an id that has since been ' +
                     'redeemed or expired ends nothing and is answered in ' +
                     '`unknown` or `skipped` rather than ending something ' +
                     'else.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            user: { type: 'string', description: 'The identity to act on.' },
            select: { type: 'array', items: { type: 'string' },
                      description:
                        'Row ids from `GET /admin-api/logout?user=`.' }
          },
          required: ['user', 'select'],
          examples: [{ user: 'alice', select: ['session:8Qk3', 'token:abc'] }],
          additionalProperties: false
        },
        responseDescription: 'The act, in `result`.' },
      { action: 'restore-token', operationId: 'restoreLoggedOutToken',
        summary: 'NON-SPEC: un-revoke a token a logout revoked',
        description: '**No authorization server could offer this.** RFC 7009 ' +
                     'defines no such operation and a real deployment could ' +
                     'not have one, because a resource server may already ' +
                     'have cached the refusal. It is here for the reason ' +
                     '`POST /admin-api/tokens/restore` is — it is the same ' +
                     'function against the same revocation set — and that ' +
                     'reason is that restarting this service to get back to ' +
                     'a working token turns a two-second test into a ' +
                     'two-minute one.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            user: { type: 'string', description: 'The identity, for the ' +
                                                 'audit row.' },
            jti: { type: 'string', description: 'The token to restore.' }
          },
          required: ['user', 'jti'],
          examples: [{ user: 'alice', jti: 'A-Rz5JpfK0j7V9azTcqmCw' }],
          additionalProperties: false
        },
        responseDescription: 'Whether it had been revoked.' },
      { action: 'restore-kerberos', operationId: 'clearKerberosSignOut',
        summary: 'NON-SPEC: clear the Kerberos sign-out instant',
        description: 'Removes the instant a logout stamped on the principal, ' +
                     'so a ticket-granting ticket authenticated before it is ' +
                     'accepted again.\n\n**A real KDC has no such ' +
                     'operation**, and it does not need one: a fresh AS-REQ ' +
                     'is the supported way back and clears the instant ' +
                     'itself. This exists so a test can put a signed-out ' +
                     'ticket back into service without re-running the AS ' +
                     'exchange.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            user: { type: 'string',
                    description: 'The identity whose principal to clear.' }
          },
          required: ['user'],
          examples: [{ user: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'Whether an instant had been set.' }
    ] },

  { method: 'GET', path: BASE + '/groups', tag: 'Groups',
    operationId: 'getGroups',
    summary: 'Every group in the embedded LDAP directory, or one in full',
    description: 'Without `group` it is the list. With it, one group: every ' +
                 'attribute it holds, operational ones included, and every ' +
                 'member resolved.\n\nTwo answers are easy to mistake for ' +
                 'failures and are neither. A process with no directory ' +
                 'loaded answers 200 with `directory: false`. A group that ' +
                 'is not there answers 200 with `found: false`, because a ' +
                 'client can delete or rename one through the protocol ' +
                 'between one call and the next, and that is the interesting ' +
                 'case rather than a routing problem.\n\nA GROUP HERE GRANTS ' +
                 'NOTHING, with two exceptions: no endpoint in this service ' +
                 'decides anything on a group, and the only two that do are ' +
                 '`admin.readGroup` and `admin.writeGroup`, which say who ' +
                 'may use the console. A token CAN carry one — ' +
                 '`groups.claim` is on by default and puts the subject\'s ' +
                 'groups in every access token, ID Token and SAML assertion ' +
                 '— and carrying a fact is not acting on one.',
    mirrors: 'GET /admin/groups',
    parameters: [
      { name: 'group', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'One group\'s DN. Returns the drill-down.' },
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the DN or the name, case-insensitive.' }
    ].concat(pagingParameters()).concat(detailPagingParameters([
      { name: 'members',
        description: 'The membership values of the group named by `group`, ' +
                     'resolved. `group.memberCount`, `presentCount` and ' +
                     '`danglingCount` beside them are counts of the WHOLE ' +
                     'list and not of the page — a group whose seven ' +
                     'members resolve to five is the fact this resource ' +
                     'exists to report, and a per-page count would not be ' +
                     'an answer to it.' },
      { name: 'claimed',
        description: 'Entries whose own memberOf names this group while it ' +
                     'does not list them back.' }
    ])),
    responseDescription: 'The list, or one group.',
    responseSchema: { oneOf: [
      { $ref: '#/components/schemas/GroupList' },
      { $ref: '#/components/schemas/GroupDetail' }
    ] },
    handler: function (req, res) {
      log.debug("Entering the management API groups endpoint.");
      sendJson(res, 200, adminViews.groupsJson(req));
      log.debug("Leaving the management API groups endpoint.");
    } },

  // ---------------------------------------------------------------------------
  // AND THE TWO WRITES (2026-09-06), WHICH CLOSED A HOLE RATHER THAN ADDING A
  // FEATURE.
  //
  // Until today `/admin-api/groups` was a READ and so was `/admin/groups`, and
  // the only two doors onto a group in this directory were an `ldapadd` on the
  // raw socket and `POST /scim/v2/Groups`. So this API could put a PERSON in
  // the directory (`/users/create`) and could not put them in a GROUP, and the
  // console could report a dangling member, a claimed membership and the two
  // groups that decide who may use it without being able to create any of them.
  //
  // **RULE 7 COULD NOT HAVE CAUGHT IT AND THAT IS THE INTERESTING PART.** That
  // rule is a parity check between the console and this API — every control
  // there has an operation here, every operation here names a control there —
  // and it is satisfied exactly when both are missing. It reports drift, not
  // absence. What found this was a load test that had to reach for SCIM to make
  // fifty groups on a service whose own management API creates users five
  // thousand at a time.
  //
  // THE ACTION SWITCH IS IN `adminActions.groupsAction()` and not here, exactly
  // as the users one is: two doors onto one action must not be two readings of
  // what was sent.
  // ---------------------------------------------------------------------------
  { method: 'POST', route: BASE + '/groups/:action', tag: 'Groups',
    mirrors: 'POST /admin/groups',
    handler: function (req, res) {
      log.debug("Entering the management API groups action endpoint.");
      const body = parseBody(req);
      const request = withAction(req, body);
      // A CREATE CLAIMS ITS NAME FIRST — see `claimForCreate()`.
      return runClaimed(res, request.action === 'create'
        ? { group: String(request.group || request.displayName ||
                          request.cn || '') }
        : null, function (held) {
        const result = adminActions.groupsAction(request);
        held.settle(!!result.ok);
        if (!result.ok) {
          errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0033');
        }
        sendJson(res, result.ok ? 200 : 400, result);
        log.debug("Leaving the management API groups action endpoint.");
      });
    },
    actions: [
      { action: 'create', operationId: 'createGroup',
        summary: 'Put a group in the directory',
        description: 'An entry under `ou=groups`, as a `groupOfNames` — so ' +
                     'it is counted as a group by BOTH of the rules ' +
                     '/admin/groups applies, its placement and its object ' +
                     'class, and stays one if a client moves it.\n\n**The ' +
                     'name becomes the `cn` AND the RDN**, so it is refused ' +
                     'if it carries a character RFC 4514 section 2.4 ' +
                     'reserves in a DN (one of `, = + < > # ; " \\`) — the ' +
                     'same rule a username is refused by, and refused rather ' +
                     'than escaped for the same reason: an `ldapadd` can ' +
                     'still create such an entry with the escaping written ' +
                     'out. A DN sent here is refused too, because what it ' +
                     'would create is a group whose name is another group\'s ' +
                     'DN.\n\n**A member that names nothing is WRITTEN, not ' +
                     'refused.** This directory does no referential ' +
                     'integrity in either direction — deleting a person ' +
                     'leaves their DN in every group that listed them — so a ' +
                     'create that refused a dangling member would make the ' +
                     'state /admin/groups exists to report impossible to ' +
                     'produce from this door. They come back in ' +
                     '`dangling`.\n\n**An empty group is allowed and RFC ' +
                     '4519 says it should not be** (`member` is MUST on ' +
                     '`groupOfNames`). SCIM already creates one; a ' +
                     'management API stricter than SCIM about the same store ' +
                     'would be two doors disagreeing about what this ' +
                     'directory holds.\n\n**IT GRANTS NOTHING.** No endpoint ' +
                     'here decides anything on a group. The two that do are ' +
                     '`admin.readGroup` and `admin.writeGroup`, and they are ' +
                     'granted at POST /admin-api/rbac rather than by ' +
                     'creating a group with the right name — though creating ' +
                     'one with the right name and adding somebody to it does ' +
                     'the same thing, because those two ARE ordinary groups ' +
                     'in this directory.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            group: { type: 'string',
                     description: 'The `cn`. Not a DN — this puts it under ' +
                                  '`ou=groups` in the realm the call is made ' +
                                  'in.' },
            displayName: { type: 'string',
                           description: 'Accepted for `group`, spelt the way ' +
                                        'SCIM spells it.' },
            note: { type: 'string',
                    description: 'What the entry\'s `description` says about ' +
                                 'why it exists. Defaults to a sentence ' +
                                 'saying it was created by hand rather than ' +
                                 'by a directory client.' },
            members: {
              description: 'Who is in it, as an array of user names or DNs — ' +
                           'a group can hold another group, and no user name ' +
                           'names one. A form sends one string, split on ' +
                           'newlines and commas. A bare name resolves to ' +
                           'that person\'s OWN entry wherever it is, because ' +
                           'somebody seeded by a client certificate is at ' +
                           '`cn=<name>,ou=users` and a value written in the ' +
                           '`uid=` form would dangle beside the entry it ' +
                           'meant to name.',
              oneOf: [{ type: 'array', items: { type: 'string' } },
                      { type: 'string' }]
            }
          },
          required: ['group'],
          examples: [{ group: 'developers', note: 'the people who write it',
                       members: ['alice', 'bob'] }],
          additionalProperties: false
        },
        responseDescription: 'The DN it was created at, the membership ' +
                             'values written, and which of them name ' +
                             'nothing.' },

      { action: 'add-member', operationId: 'addGroupMember',
        summary: 'Put somebody in a group that already exists',
        description: 'One membership value onto one group. `group` is its ' +
                     '`cn` or its whole DN; `member` is a user name or any ' +
                     'DN.\n\n**IT IS IDEMPOTENT.** Adding somebody already ' +
                     'listed answers `ok: true` with `changed: false` rather ' +
                     'than an error, so a script that adds on every run does ' +
                     'not fail on its second one. Membership is asked across ' +
                     '`member`, `uniqueMember` and `memberUid` together, ' +
                     'which is how /admin/groups and the groups claim ask it ' +
                     '— an add that could not see a `memberUid` would write ' +
                     'a second value for one membership.\n\n**It writes onto ' +
                     '`member`** whatever else the entry carries, rather ' +
                     'than extending whichever convention the group already ' +
                     'uses: this service\'s groups claim, the console and ' +
                     'RFC 4519 all read `member` first, and guessing which ' +
                     'of three attributes was meant would be this operation ' +
                     'deciding something the caller did not say.\n\n**It ' +
                     'does not create the group as a side effect.** A typo ' +
                     'in the name would then be a new group rather than an ' +
                     'error. And it writes nothing onto the PERSON: ' +
                     '`memberOf` is maintained by nothing here — it is not ' +
                     'even a standard attribute — and a value written there ' +
                     'is one no other door in this service can take ' +
                     'away.\n\n**Removing one is not here.** It is an ' +
                     '`ldapmodify` or a SCIM `PATCH`, and POST ' +
                     '/admin-api/rbac for the two groups that grant the ' +
                     'console.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            group: { type: 'string',
                     description: 'The group\'s `cn` or its whole DN.' },
            member: { type: 'string',
                      description: 'A user name, or the DN of any entry.' },
            user: { type: 'string', description: 'Accepted for `member`.' },
            username: { type: 'string', description: 'Accepted for `member`.' }
          },
          required: ['group', 'member'],
          examples: [{ group: 'developers', member: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'Whether anything changed, the value written, ' +
                             'and whether it resolves to an entry this ' +
                             'directory holds.' }
    ] },

  // --- The directory itself, entry by entry --------------------------------
  //
  // FIVE OPERATIONS ADDED ON 2026-09-01, ONE PER PAGE, AND THEY EXIST BECAUSE
  // OF RULE 7 RATHER THAN BECAUSE ANYBODY ASKED FOR THEM.
  //
  // `/ldap`, `/ldap/directory`, `/ldap/applications`, `/ldap/federations` and
  // `/ldap/spiffe` were five HTML pages outside the console until that day.
  // They are `/admin/ldap/*` now — console pages, in the console's shell,
  // behind its gate — and the rule this API is written under is that every
  // page of that console has an operation here that mirrors it. So here they
  // are, and the parity check in the suite is what would have noticed if they
  // were not.
  //
  // THE GATE IS THE POINT OF THEM AND NOT AN INCIDENTAL DIFFERENCE. Those
  // pages print `oauthClientSecret` and `fedClientSecret` in the clear, which
  // is why moving them behind the console's gate was the right half of the
  // change; this API is deliberately NOT gated, which is what keeps a test
  // able to read the directory without signing a browser in. Both halves of
  // that sentence are argued at the top of this file — the short version is
  // that a port which mints a token for any username asked of it is not made
  // safe by a password on one of its web pages, and the gate exists so a
  // client can be driven through 302 / 401 / 403.
  //
  // EVERY ONE OF THEM CALLS THE FUNCTION THAT DRAWS THE PAGE, through
  // `adminViews.directoryPageJson()` and the slot `ldap/ldap_server.js` fills —
  // see the block above `setDirectoryPages()` in `admin-ui/admin.js` for why it
  // cannot be a plain require from here. So a page and its operation cannot
  // come to disagree about what is in the directory: there is one function and
  // it is in the module that owns the store.
  { method: 'GET', path: BASE + '/ldap/directory', tag: 'LDAP',
    operationId: 'getDirectoryEntries',
    summary: 'Every entry in this realm\'s directory, paged',
    description: 'The whole store, DN by DN, with where each entry came from ' +
                 '— `seed`, an LDAP `add`, or an authentication — and every ' +
                 'attribute with every value.\n\nIT IS NOT AN LDAP SEARCH. ' +
                 'This is the service showing its own store, which is how a ' +
                 'caller tells an empty directory from a filter that matched ' +
                 'nothing, and it is why the operational attributes are ' +
                 'here: a search withholds `createTimestamp` and ' +
                 '`modifyTimestamp` unless they are asked for by name (RFC ' +
                 '4511 §4.5.1.8) and this is not a search.\n\n`q` matches ' +
                 'the DN, any attribute NAME and any attribute VALUE, ' +
                 'case-insensitively — values because the caller who needs ' +
                 'this most often has a thumbprint or a secret in hand and ' +
                 'no idea which entry carries it.\n\nTHE REPLY IS THIS ' +
                 'REALM\'S DIRECTORY AND NO OTHER. Since 2026-08-25 each ' +
                 'trust realm has a subtree of its own; reach another ' +
                 'realm\'s through its own path prefix.',
    mirrors: 'GET /admin/ldap/directory',
    parameters: [
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the DN, of an attribute name, or of an ' +
                     'attribute value. Case-insensitive.' },
      { name: 'origin', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'Only entries that came from here. The values actually ' +
                     'present are in `origins`.' }
    ].concat(pagingParameters()),
    responseDescription: 'The page of entries, with the filter and the paging.',
    responseSchema: { $ref: '#/components/schemas/DirectoryEntryList' },
    handler: function (req, res) {
      log.debug("Entering the management API directory entries endpoint.");
      sendJson(res, 200, adminViews.directoryPageJson('directory', req));
      log.debug("Leaving the management API directory entries endpoint.");
    } },

  { method: 'GET', path: BASE + '/ldap/applications', tag: 'LDAP',
    operationId: 'getDirectoryApplications',
    summary: 'The application registry as the directory holds it, and its ' +
             'schema',
    description: 'One entry per identifier under `ou=applications`, every ' +
                 'attribute on it, and the published SCHEMA — the object ' +
                 'classes and every attribute name with what sets it.\n\nTHE ' +
                 'SCHEMA IS WHY THIS IS NOT `GET /admin-api/applications`. ' +
                 'That operation is the registry as the console works with ' +
                 'it: the counters, the drill-down, the writes. This is the ' +
                 'registry as the DIRECTORY holds it, and the vocabulary is ' +
                 'the half a client reading an entry back over 389 actually ' +
                 'needs — this directory is schemaless, so an entry carrying ' +
                 'thirty invented attribute names is otherwise ' +
                 'guesswork.\n\nTHESE ENTRIES ARE THE REGISTRY rather than a ' +
                 'copy of one. Nothing caches them, so an `ldapmodify` of ' +
                 '`oauthRedirectUri` changes which redirect URI RFC 9700 ' +
                 'mode accepts on the next request.\n\nTwo attributes hold ' +
                 'CREDENTIALS in the clear, for the reason ' +
                 '`/krb5/principals` prints the Kerberos passwords. They are ' +
                 'never written to the audit log.',
    mirrors: 'GET /admin/ldap/applications',
    parameters: [
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the identifier, the name, the DN or any ' +
                     'attribute value. Case-insensitive.' }
    ].concat(pagingParameters()),
    responseDescription: 'The page of entries, the kinds and the schema.',
    responseSchema: { $ref: '#/components/schemas/DirectoryApplicationList' },
    handler: function (req, res) {
      log.debug("Entering the management API directory applications endpoint.");
      sendJson(res, 200, adminViews.directoryPageJson('applications', req));
      log.debug("Leaving the management API directory applications endpoint.");
    } },

  { method: 'GET', path: BASE + '/ldap/federations', tag: 'LDAP',
    operationId: 'getDirectoryFederations',
    summary:
      'The federation register as the directory holds it, and its schema',
    description: 'The application registry\'s twin, for `ou=federations` — ' +
                 'and THE ONE CONTAINER IN THIS DIRECTORY WHERE AN ' +
                 'LDAPMODIFY IS A SECURITY CHANGE. Everywhere else an edit ' +
                 'changes what this service HANDS OUT; ' +
                 '`fedSigningCertificate` decides whose assertions it will ' +
                 'BELIEVE and `fedEnabled` turns a partner on.\n\nIt is a ' +
                 'container of its own rather than a corner of ' +
                 '`ou=applications` because half its entries are FOREIGN ' +
                 'IDENTITY PROVIDERS, which ask this service for nothing at ' +
                 'all.\n\nThe schema carries a column the applications one ' +
                 'has no need of: which DIRECTION each attribute is ' +
                 'for.\n\n`fedClientSecret` is REDACTED in `relationships` ' +
                 'and present in the entry\'s own attributes, which is the ' +
                 'same split the page makes: what a script reads is ' +
                 'redacted, and a page claiming to say what the directory ' +
                 'holds may not hide a value an `ldapsearch` shows.',
    mirrors: 'GET /admin/ldap/federations',
    parameters: [
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the relationship id, the DN, the protocol ' +
                     'or the direction. Case-insensitive.' }
    ].concat(pagingParameters()),
    responseDescription: 'The page of relationships, the roles, the ' +
                         'protocols and the schema.',
    responseSchema: { $ref: '#/components/schemas/DirectoryFederationList' },
    handler: function (req, res) {
      log.debug("Entering the management API directory federations endpoint.");
      sendJson(res, 200, adminViews.directoryPageJson('federations', req));
      log.debug("Leaving the management API directory federations endpoint.");
    } },

  { method: 'GET', path: BASE + '/ldap/spiffe', tag: 'LDAP',
    operationId: 'getDirectorySpiffe',
    summary: 'The two SPIFFE containers as the directory holds them, and ' +
             'their schema',
    description: 'THE TWO CONTAINERS HOLD DIFFERENT KINDS OF THING, which is ' +
                 'why they are two. `ou=entries` is CONFIGURATION — which ' +
                 'SPIFFE ID a workload gets, under which parent, matching ' +
                 'which selectors — and `ou=agents` is a RECORD of what has ' +
                 'attested, which is why nothing about an agent is editable ' +
                 'anywhere.\n\nTHE ENTRIES ARE THE REGISTRY: nothing caches ' +
                 'them, so an `ldapmodify` of `spiffeX509SvidTtl` changes ' +
                 'the lifetime of the next SVID the Workload API hands ' +
                 'out.\n\nTHIS IS THE ONE DIRECTORY OPERATION WITH TWO LISTS ' +
                 'IN IT, so it pages the way the console\'s drill-downs do: ' +
                 '`entriesPage` and `agentsPage` move one list each and ' +
                 '`per` is shared, with an `entriesPaging` and an ' +
                 '`agentsPaging` object in the reply. `entries` and `agents` ' +
                 'at the top level are the TOTALS and not the page.',
    mirrors: 'GET /admin/ldap/spiffe',
    parameters: [
      { name: 'entryq', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'Substring of a registration entry\'s SPIFFE ID or DN.' },
      { name: 'agentq', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'Substring of an attested agent\'s id or DN.' }
    ].concat(pagingParameters()).concat(detailPagingParameters([
      { name: 'entries', description: 'The registration entries.' },
      { name: 'agents', description: 'The attested agents.' }
    ])),
    responseDescription: 'The two pages, the two containers and the schema.',
    responseSchema: { $ref: '#/components/schemas/DirectorySpiffe' },
    handler: function (req, res) {
      log.debug("Entering the management API directory SPIFFE endpoint.");
      sendJson(res, 200, adminViews.directoryPageJson('spiffe', req));
      log.debug("Leaving the management API directory SPIFFE endpoint.");
    } },

  // ---------------------------------------------------------------------
  // THE THREE ADDED ON 2026-09-05, and they are here for rule 7 rather than
  // by analogy: `ou=roles`, `ou=policies` and `ou=peps` each gained a console
  // page that day, and every page of the console has an operation. What made
  // the pages worth writing is that all three modules already PUBLISHED a
  // schema whose comment claimed a page under `/admin/ldap/*` and none of
  // them had one — `common/roles.js` from that afternoon,
  // `xacml/xacml_store.js` from XACML phase two, `xacml/xacml_pep_registry.js`
  // from phase five.
  // ---------------------------------------------------------------------
  { method: 'GET', path: BASE + '/ldap/roles', tag: 'LDAP',
    operationId: 'getDirectoryRoles',
    summary: 'The role entries as the directory holds them, and their schema',
    description: 'THIS CONTAINER IS HALF THE FEATURE. A role has two ' +
                 'relations and they are stored apart on purpose: MEMBERSHIP ' +
                 '— who holds it — is here on the role entry, and the ' +
                 'REQUIREMENT — which roles an application demands before ' +
                 'anything is issued for it — is `appRequiredRole` on the ' +
                 'APPLICATION entry, under a different container. So nothing ' +
                 'in this reply refuses anybody by itself, and a caller ' +
                 'looking for the reason somebody was turned away wants `GET ' +
                 '/admin-api/roles`, which resolves both halves.\n\n**THE ' +
                 'SIX BUILT-IN ROLES ARE IN NO CONTAINER.** They are ' +
                 'computed from the context of the decision being made, so ' +
                 '`EVERYBODY` has no entry here and never will — which is ' +
                 'why an empty `roles` array is the ORDINARY state of a ' +
                 'service refusing nobody rather than a sign that the ' +
                 'feature is not loaded.\n\nTHE ENTRIES ARE THE REGISTER: ' +
                 'nothing caches them, so an `ldapmodify` adding a value to ' +
                 '`roleMemberUser` is answered by the very next issuance ' +
                 'decision.',
    mirrors: 'GET /admin/ldap/roles',
    parameters: [
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of a role name, a DN, or any value on the ' +
                     'entry — which includes its members, so this is how to ' +
                     'find the roles one person holds by name.' }
    ].concat(pagingParameters()),
    responseDescription: 'The page of role entries, the six built-in names ' +
                         'and the schema.',
    responseSchema: { $ref: '#/components/schemas/DirectoryRoleList' },
    handler: function (req, res) {
      log.debug("Entering the management API directory roles endpoint.");
      sendJson(res, 200, adminViews.directoryPageJson('roles', req));
      log.debug("Leaving the management API directory roles endpoint.");
    } },

  { method: 'GET', path: BASE + '/ldap/policies', tag: 'LDAP',
    operationId: 'getDirectoryPolicies',
    summary: 'The policy repository as the directory holds it, and its schema',
    description: '`ou=policies` IS the XACML policy repository, the way ' +
                 '`ou=federations` is the federation register. One entry per ' +
                 'policy or policy set, holding the document itself, with ' +
                 'exactly one of them the root — a PDP evaluates one ' +
                 'document and reaches the rest through ' +
                 'PolicyIdReference.\n\n**A WRITE HERE SKIPS THE ' +
                 'TYPECHECKER, and that is the one thing this operation says ' +
                 'that `GET /admin-api/xacml/policies` does not.** Every ' +
                 'write through the console and through /admin-api/xacml ' +
                 'parses the document and statically typechecks it, so a ' +
                 'policy that does not typecheck is refused at WRITE time ' +
                 'rather than going Indeterminate on every request. An ' +
                 '`ldapmodify` of `xacmlPolicyDocument` reaches the entry ' +
                 'directly and skips all of it, and nothing caches these ' +
                 'entries.',
    mirrors: 'GET /admin/ldap/policies',
    parameters: [
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of a policy name, a DN, or any value on the ' +
                     'entry — the DOCUMENT included, so this finds the ' +
                     'policy that names a particular resource.' }
    ].concat(pagingParameters()),
    responseDescription: 'The page of policy entries and the schema.',
    responseSchema: { $ref: '#/components/schemas/DirectoryPolicyList' },
    handler: function (req, res) {
      log.debug("Entering the management API directory policies endpoint.");
      sendJson(res, 200, adminViews.directoryPageJson('policies', req));
      log.debug("Leaving the management API directory policies endpoint.");
    } },

  { method: 'GET', path: BASE + '/ldap/peps', tag: 'LDAP',
    operationId: 'getDirectoryPeps',
    summary: 'The registered remote PEPs as the directory holds them, and ' +
             'their schema',
    description: 'ALMOST EVERYTHING IN THIS CONTAINER IS A RECORD rather ' +
                 'than configuration, which is what it has in common with ' +
                 '`ou=agents` next door. A PEP registers itself, and its ' +
                 'identity is taken from the CLIENT CERTIFICATE it presented ' +
                 'and never from the body it sent.\n\nTwo attributes are not ' +
                 'a record and an `ldapmodify` of either is a real change: ' +
                 '`xacmlPepEnabled` is an administrator\'s decision and a ' +
                 'PEP that reconnects does not clear it, and ' +
                 '`xacmlPepNotifyUrl` is one of the three addresses this ' +
                 'service will dial.\n\n**AN EMPTY `peps` ARRAY IS NOT A ' +
                 'FEATURE THAT IS OFF.** A remote PEP pulls `GET ' +
                 '/xacml/pep/policies` and converges without registering at ' +
                 'all; registering is what buys it the change nudge and a ' +
                 'row on the console.',
    mirrors: 'GET /admin/ldap/peps',
    parameters: [
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of a PEP name, a DN, or any value on the ' +
                     'entry — a certificate subject or a notify URL included.' }
    ].concat(pagingParameters()),
    responseDescription: 'The page of registered PEPs and the schema.',
    responseSchema: { $ref: '#/components/schemas/DirectoryPepList' },
    handler: function (req, res) {
      log.debug("Entering the management API directory PEPs endpoint.");
      sendJson(res, 200, adminViews.directoryPageJson('peps', req));
      log.debug("Leaving the management API directory PEPs endpoint.");
    } },

  // LAST OF THE EIGHT, and it is the one that answers about the SOCKETS rather
  // than about what is in the store. It is deliberately not `GET
  // /admin-api/ldap`, which is the SETTINGS: that one says what the ports and
  // the base DN are SET to, and this one says what actually happened when the
  // process tried to bind them. On a host where the system's own slapd already
  // holds 389 those two replies disagree, and the disagreement is the whole
  // value of having both.
  { method: 'GET', path: BASE + '/ldap/service', tag: 'LDAP',
    operationId: 'getDirectoryService',
    summary: 'What the embedded directory IS, right now',
    description: 'The two raw sockets and the store behind them AS THEY ' +
                 'ACTUALLY ARE: whether TCP 389 and LDAPS 636 really bound ' +
                 'and the error if either did not, the base DN and each ' +
                 'realm\'s naming context, what a subtree search from each ' +
                 'one answers about, the bind policy, the four structural ' +
                 'rules this directory does still enforce, the entry count ' +
                 'and the persistence status.\n\nWHY IT IS NOT `GET ' +
                 '/admin-api/ldap`: that operation is the six `ldap.*` ' +
                 'SETTINGS — what the sockets are configured to be. This one ' +
                 'is what happened. A host whose own slapd already holds 389 ' +
                 'makes the two disagree, and nothing else in this service ' +
                 'can report that: `/admin/sts-metadata` is built by walking ' +
                 'the express router and a raw TCP listener is not on ' +
                 'it.\n\nNO BIND IS EVER REFUSED here, by any setting, ' +
                 'except the one literal password named in `refusedPassword` ' +
                 '— which exists so a negative test has something to fail on.',
    mirrors: 'GET /admin/ldap/service',
    parameters: [],
    responseDescription: 'The directory as it is right now.',
    responseSchema: { $ref: '#/components/schemas/DirectoryService' },
    handler: function (req, res) {
      log.debug("Entering the management API directory service endpoint.");
      sendJson(res, 200, adminViews.directoryPageJson('service', req));
      log.debug("Leaving the management API directory service endpoint.");
    } },

  // --- The console's own roles ---------------------------------------------
  //
  // TWO OPERATIONS, AND THIS RESOURCE MATTERS MORE THAN THE OTHERS RATHER THAN
  // LESS. Rule 7 says a console control gets an operation in the same change;
  // here the API half is not merely parity, it is the ONLY door onto the roster
  // that still works when nobody holds a role and `admin.openWhenEmpty` is off.
  // The console cannot let you fix that — you cannot reach it — so this can. It
  // reaches it with a DIFFERENT credential: an access token carrying
  // `admin:write`, rather than the console session the roster gates.
  //
  // **THIS COMMENT SAID `/admin-api` WAS UNGATED AND THAT WAS TRUE UNTIL
  // 2026-09-09.** It went on: WITH THE CONSOLE PROTECTED AND THIS API OPEN,
  // ANYBODY WHO CAN REACH THIS PORT CAN GRANT THEMSELVES BOTH ROLES — which is
  // exactly what `adminApi.authRequired` closed. What has NOT changed is that
  // the console's gate exists so a client can be driven through 302 / 401 / 403
  // and a role model, not to make this service safe to expose: in the default
  // development mode no password is checked anywhere and `/oauth2/token` will
  // mint a token for any username asked of it. Do not put this port on a public
  // address.
  { method: 'GET', path: BASE + '/rbac', tag: 'Admin roles',
    operationId: 'getAdminRoles',
    summary: 'Who may use the admin console, and how the gate is set',
    description: 'The two roles — **Admin Read** and **Admin Write** — with ' +
                 'every grant, the settings behind the gate, and who the ' +
                 'CALLER is (`you`).\n\nThe roles are two ORDINARY GROUPS in ' +
                 'the embedded LDAP directory (`admin.readGroup`, ' +
                 '`admin.writeGroup`), not a store of the console\'s own. So ' +
                 'this resource, `/admin/rbac`, an `ldapmodify` on 389 or ' +
                 '636 and a SCIM PATCH of the group are four doors onto one ' +
                 'membership, and a grant made through any of them is ' +
                 'visible through all of them.\n\n**WRITE IMPLIES READ.** A ' +
                 'member of the write group does not also need the read ' +
                 'group.\n\n**The bootstrap administrator** ' +
                 '(`admin.bootstrapUsername`, reported in `bootstrap`) is made ' +
                 'a member of both groups at startup. Until it first signs ' +
                 'in to `/admin` (`bootstrap.claimedAt`), `openToAnyone` is ' +
                 'true and anybody who signs in holds both roles. A process ' +
                 'that never seeded it (`bootstrap.seeded` false) keeps the ' +
                 'older rule: open while NEITHER group has a member. ' +
                 '`admin.openWhenEmpty` turns the open window off, and ' +
                 '`closedToEveryone` reports a console no browser can reach, ' +
                 'which is what this resource is the way out of.\n\n' +
                 '`enforced` reports whether the ' +
                 'roster decides anything. It is always true now — the ' +
                 'console gate became unconditional on 2026-09-06 — and the ' +
                 'field is kept because a client reading it should not have ' +
                 'to know that.\n\n**EVERY LIST IN THE REPLY IS PAGED.** ' +
                 '`grants` by `page` and `per`, with `page`, `pages`, ' +
                 '`perPage`, `firstRow`, `lastRow` and `matched` at the top ' +
                 'level; `candidates` by `candidatesPage` and the same ' +
                 '`per`, answered in `candidatesPaging`. `roles` carries ' +
                 'each role\'s counts (`memberCount`, `presentCount`, ' +
                 '`danglingCount`, `claimedCount`) and, since 2026-09-13, ' +
                 'not its `members` and `claimed` lists: those were every ' +
                 'membership unpaged, and they are the rows `grants` pages ' +
                 '— `?role=read` narrows it to one role.',
    mirrors: 'GET /admin/rbac',
    parameters: [
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the person\'s name or of the raw ' +
                     'membership value, case-insensitive.' },
      { name: 'role', in: 'query', required: false,
        schema: { type: 'string', enum: rbac.ROLE_IDS },
        description: 'Only grants of this role.' },
      { name: 'personq', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'Narrows `candidates` — the people a role could be ' +
                     'granted to, from the directory and from who has ' +
                     'signed in — to usernames containing this, ' +
                     'case-insensitive. `candidateSearch` says how many ' +
                     'candidates there are in all and how many matched.' },
      { name: 'candidatesPage', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Which page of the matching `candidates`, answered in ' +
                     '`candidatesPaging`. Clamped like `page`. The page size ' +
                     'is `per` when given — shared with `grants`, as on ' +
                     'every reply here carrying two lists — and otherwise ' +
                     'twenty, the size of the console\'s results pane. ' +
                     '`candidates` was the whole list until 2026-09-13, ' +
                     'which on a directory of thousands was thousands of ' +
                     'rows on every read of the roster.' },
      { name: 'personfrom', in: 'query', required: false,
        schema: { type: 'integer', minimum: 0 },
        description: 'The console results pane\'s OFFSET into the matching ' +
                     'candidates, answered as the page it falls on. Ignored ' +
                     'when `candidatesPage` is given, and when it is past ' +
                     'the end.' },
      { name: 'person', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'A username to look up among ALL the candidates, not ' +
                     'only the page shown. `picked.candidate` is its row, ' +
                     'or null when nobody by that name could be picked.' }
    ].concat(pagingParameters()),
    responseDescription: 'The roster, the settings, and who is asking.',
    handler: function (req, res) {
      log.debug("Entering the management API admin roles endpoint.");
      // The layer, not the page: rbacView() built two tables and four forms
      // and this resource used none of them.
      sendJson(res, 200, adminViews.rbacListJson(req).json);
      log.debug("Leaving the management API admin roles endpoint.");
    } },

  { method: 'POST', route: BASE + '/rbac/:action', tag: 'Admin roles',
    mirrors: 'POST /admin/rbac',
    handler: function (req, res) {
      log.debug("Entering the management API admin roles action endpoint.");
      const body = parseBody(req);
      // `via: 'api'` and the caller's own name, for the audit row. The console
      // passes its signed-in user here; this API has no session to read, so the
      // actor is empty unless the caller carried one — which is honest rather
      // than convenient, and is exactly what the audit row should say about an
      // unauthenticated management API call.
      const result = adminActions.rbacAction(withAction(req, body),
                                      { via: 'api', actor: '' });
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0034');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API admin roles action endpoint.");
    },
    actions: [
      { action: 'grant', operationId: 'grantAdminRole',
        summary: 'Give somebody a console role',
        description: 'Adds them to the role\'s group as a `member`, creating ' +
                     'the group if this is the first grant — which is why ' +
                     '"the group does not exist" and "the group has no ' +
                     'members" are the same state everywhere in this ' +
                     'feature.\n\n**The person need not exist.** A name ' +
                     'nothing here has seen, and that has no directory ' +
                     'entry, is granted anyway: the membership names the DN ' +
                     'they WILL be at (`uid=<name>,ou=users`) and dangles ' +
                     'until they first sign in or somebody creates them, and ' +
                     'the role counts from that moment. That is the ' +
                     'interesting case for a mock and is deliberately ' +
                     'reachable. What IS refused is a name carrying a ' +
                     'character RFC 4514 reserves in a DN — the same refusal ' +
                     '`POST /admin-api/users/create` gives, for the same ' +
                     'reason.\n\nGranting a role somebody already holds ' +
                     'answers 200 with `changed: false` rather than 400, so ' +
                     'a script that grants on every run does not fail on its ' +
                     'second one.\n\n**THE FIRST GRANT ON A SERVICE CLOSES ' +
                     'THE DOOR BEHIND IT.** While the roster is empty ' +
                     'anybody who signs in holds both roles; the moment one ' +
                     'grant exists, everybody not in one of the two groups ' +
                     'is refused at every page of the console. Grant ' +
                     'yourself first.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            username: { type: 'string',
                        description: 'The name they sign in as — the same ' +
                                     'string that appears in a token\'s ' +
                                     '`sub` and on /admin/users.' },
            role: { type: 'string', enum: rbac.ROLE_IDS,
                    description: '`write` includes `read`.' }
          },
          required: ['username', 'role'],
          examples: [{ username: 'rcbj', role: 'write' }],
          additionalProperties: false
        },
        responseDescription: 'What was granted, and where the membership was ' +
                             'written. `changed: false` means they already ' +
                             'held it.' },

      { action: 'revoke', operationId: 'revokeAdminRole',
        summary: 'Take a console role away',
        description: 'Removes them from the role\'s group — from EVERY ' +
                     'membership attribute that named them (`member`, ' +
                     '`uniqueMember`, `memberUid`) rather than from the ' +
                     'first one found, because a person listed twice by two ' +
                     'clients would otherwise still hold the role after a ' +
                     'revoke that reported success.\n\nRevoking a role ' +
                     'somebody does not hold answers 200 with `changed: ' +
                     'false`, and so does revoking from a group that does ' +
                     'not exist.\n\n**Taking away the LAST grant empties the ' +
                     'roster.** Where no bootstrap administrator was seeded ' +
                     'that re-opens the console to anybody who signs in (or ' +
                     'closes it to everybody, if `admin.openWhenEmpty` is ' +
                     'off); once the bootstrap administrator has signed in ' +
                     'it closes the console to everybody. The reply says ' +
                     'which.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            username: { type: 'string', description: 'Who to take it from.' },
            role: { type: 'string', enum: rbac.ROLE_IDS }
          },
          required: ['username', 'role'],
          examples: [{ username: 'rcbj', role: 'read' }],
          additionalProperties: false
        },
        responseDescription: 'What was removed, and whether the roster is ' +
                             'now empty.' }
    ] },


  // ---------------------------------------------------------------------
  // MULTI-FACTOR AUTHENTICATION (2026-09-10).
  //
  // **THE CONSOLE PAGE THIS MIRRORED IS GONE AND THIS RESOURCE IS NOT.**
  // `/admin/mfa` lasted hours: it edited the `totp.*` settings AND drew a
  // roster of who held a second factor, and one page could not be filed by
  // both halves. The settings are `/admin/totp` and `/admin/webauthn` under
  // Protocols; the roster is columns on `/admin/users` and the per-person
  // detail is on that person's own row.
  //
  // Rule 7 says a console control owes an operation. It says nothing about an
  // operation whose page moved, and deleting a working one to tidy a table
  // would be a regression dressed as consistency — the same argument `GET
  // /admin-api/users/new` is kept on. So this stays, `mirrors` points at the
  // page that absorbed it, and `adminViews.mfaRosterJson()` answers OUT OF THAT
  // VIEW so there is one tally rather than two scans that agree until they do
  // not.
  //
  // **THE READ IS A REPORT AND THE WRITE IS A RESET**, and there is
  // deliberately no ENROL operation here. Enrolling means being shown a shared
  // secret, and a management API that handed one out would be an
  // administrative door that mints a working second factor for any account —
  // which is not a second factor at all. Enrolment happens where the person
  // is: `/portal/mfa`, or `/portal/activate` with a link that is itself a
  // credential.
  // ---------------------------------------------------------------------
  { method: 'GET', path: BASE + '/mfa', tag: 'Multi-factor authentication',
    operationId: 'getMultiFactor',
    summary: 'Who holds a second factor, and how RFC 6238 is configured here',
    description: 'One row per person — this realm\'s directory people and ' +
                 'everybody this service has SEEN, unioned — saying whether ' +
                 'they hold a password, how many security keys are marked as ' +
                 'a SECOND factor, and whether an authenticator app is ' +
                 'enrolled.\n\n**TWO MECHANISMS COUNT AS A SECOND FACTOR ' +
                 'HERE**: a WebAuthn credential enrolled in the `mfa` role, ' +
                 'and an RFC 6238 authenticator app. A person holding either ' +
                 'is asked for it at the sign-in screen and a password alone ' +
                 'will not sign them in; `secondFactor` says which one they ' +
                 'will be asked for, and somebody holding both is asked for ' +
                 'the key with the code offered as the ' +
                 'alternative.\n\n**`totpUsable: false` IS THE ROW TO LOOK ' +
                 'FOR.** It means an enrolment exists that this process ' +
                 'cannot read — almost always a shared secret sealed under a ' +
                 'key-encryption key that has since been rotated. Those ' +
                 'people are REFUSED at the code step rather than let ' +
                 'through on one factor, so they cannot sign in at all until ' +
                 'the enrolment is cleared.\n\n**CODES ARE VERIFIED FOR REAL ' +
                 'IN BOTH MODES**, which almost nothing else in this service ' +
                 'is. `totp` carries the algorithm table, read from the ' +
                 'module that performs the algorithm.\n\nThe scan stops at ' +
                 '5,000 people (`capped`), because reading a credential per ' +
                 'person happens on the one thread that answers every socket ' +
                 'this service holds.',
    mirrors: 'GET /admin/users',
    parameters: [
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the person\'s name, case-insensitive.' },
      { name: 'factor', in: 'query', required: false,
        schema: { type: 'string',
                  enum: ['any', 'totp', 'key', 'none'] },
        description: '`any` is anybody holding a second factor of either ' +
                     'kind; `none` is the complement of it.' }
    ].concat(pagingParameters()),
    responseDescription: 'The roster, the counts, and the RFC 6238 settings.',
    handler: function (req, res) {
      log.debug("Entering the management API multi-factor endpoint.");
      sendJson(res, 200, adminViews.mfaRosterJson(req));
      log.debug("Leaving the management API multi-factor endpoint.");
    } },

  { method: 'POST', route: BASE + '/mfa/:action',
    tag: 'Multi-factor authentication',
    mirrors: 'POST /admin/users',
    handler: function (req, res) {
      log.debug("Entering the management API multi-factor action endpoint.");
      const body = parseBody(req);
      // `via: 'api'` and whatever actor the caller named, for the audit row —
      // the same honesty `rbacAction`'s caller keeps: this API authenticates a
      // CLIENT rather than a person, so an empty actor is the true answer
      // rather than an inconvenient one.
      const result = adminActions.mfaAction(withAction(req, body),
                                     { via: 'api', actor: '' });
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0035');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API multi-factor action endpoint.");
    },
    actions: [
      { action: 'clear-totp', operationId: 'clearAuthenticatorApp',
        summary: 'Clear somebody\'s authenticator app enrolment',
        description: '**THE ONLY WAY BACK FOR SOMEBODY WHO HAS LOST THEIR ' +
                     'PHONE.** The shared secret lives on that device and ' +
                     'this service cannot reach it, and there is ' +
                     'deliberately no self-service reset anywhere — a second ' +
                     'factor anybody can remove is not a second ' +
                     'factor.\n\nIt CANNOT lock anybody out: a one-time code ' +
                     'is never a primary credential here, so clearing one ' +
                     'drops the account to one factor rather than to none. ' +
                     'The person sets a new one up at ' +
                     '`/portal/mfa`.\n\nClearing an enrolment nobody holds ' +
                     'answers 400 rather than 200, because unlike a role ' +
                     'grant there is no idempotent reading of it that is ' +
                     'useful: the caller asked to clear a specific thing and ' +
                     'it was not there.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            username: { type: 'string',
                        description: 'The name they sign in as.' },
            // BOTH SPELLINGS, because this action and
            // `POST /admin-api/users/clear-totp` are ONE SWITCH reached two
            // ways — and the users resource names the person `user`, as every
            // other operation on it does. A schema that took one spelling
            // here and the other there would refuse a caller that had merely
            // followed the other path's example, with a message about a
            // member of the request rather than about the person.
            user: { type: 'string', description: 'Accepted for `username`.' }
          },
          required: ['username'],
          examples: [{ username: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'Whose enrolment was cleared.' },

      { action: 'clear-key', operationId: 'clearSecurityKey',
        summary: 'Remove one of somebody\'s security keys',
        description: 'Goes through the same `removeKey()` the person\'s own ' +
                     'portal calls, which is what carries the refusal that ' +
                     'matters: **it will not remove the last way in.** A ' +
                     'person with no password whose only PRIMARY key this is ' +
                     'would be locked out by an operator\'s call, and an ' +
                     'operator must not be able to do what the owner is ' +
                     'stopped from doing.\n\nThe credential id is the ' +
                     'base64url one on `GET /admin-api/mfa`\'s rows and on ' +
                     '`/portal/keys`.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            username: { type: 'string' },
            // See `clear-totp` above: one switch, two paths, one body shape.
            user: { type: 'string', description: 'Accepted for `username`.' },
            credentialId: { type: 'string',
                            description: 'base64url, as WebAuthn produced it.' }
          },
          required: ['username', 'credentialId'],
          examples: [{ username: 'alice', credentialId: 'q1w2e3r4' }],
          additionalProperties: false
        },
        responseDescription: 'How many keys are left.' }
    ] },

  { method: 'GET', path: BASE + '/tokens', tag: 'Tokens',
    operationId: 'getIssued',
    summary: 'Everything issued, grouped into what came back in one reply',
    description: 'One list, newest first, filtered and paged. Claims and ' +
                 'facts only — the signed token, the assertion XML and the ' +
                 'ticket are never kept, and the `jti` is all any operation ' +
                 'here needs.\n\n**AN ENTRY IS ONE ISSUANCE AND NOT ONE ' +
                 'CREDENTIAL, since 2026-09-05.** OAuth 2.0 and OIDC are the ' +
                 'only families here that hand back several credentials at ' +
                 'once — an access token, a refresh token and an ID Token ' +
                 'out of one code redemption — so those arrive as one entry ' +
                 'in `sets` carrying its `members`. Every other family ' +
                 'issues one credential per act, so a SAML assertion, a ' +
                 'Kerberos ticket and an SVID are each a set of one.\n\n' +
                 '`issued` is the same credentials flattened out of `sets`, ' +
                 'so a caller written against the older per-credential shape ' +
                 'reads exactly what it read. What changed under it is the ' +
                 'paging: a page is a whole number of replies, so `page`, ' +
                 '`pages`, `matched` and `shown` count SETS while `held` and ' +
                 '`matchedCredentials` count credentials.\n\nOID4VCI ' +
                 'credentials are NOT in this list. They are counted on ' +
                 '/admin-api/metrics and listed nowhere, which is a gap ' +
                 'rather than a principle and is said here so "everything ' +
                 'issued" is read as the four families it says.',
    mirrors: 'GET /admin/tokens',
    parameters: [
      { name: 'family', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'One protocol family. The reply\'s `families` member ' +
                     'lists them with the kinds in each.' },
      { name: 'kind', in: 'query', required: false, schema: { type: 'string' },
        description: 'One kind. ANDed with `family`, so a kind from another ' +
                     'family matches nothing — which is what an empty list ' +
                     'then means.\n\n**EVERY FILTER HERE MATCHES A SET WHEN ' +
                     'ANY MEMBER MATCHES.** Asking for `id_token` answers ' +
                     'with the replies that CONTAIN one — the access token ' +
                     'and the refresh token that came back with it are still ' +
                     'in `members`, because they are part of the same reply. ' +
                     'A caller that wants only the matching credentials ' +
                     'filters `issued` itself; a filter that hid the ' +
                     'neighbours would be the old per-credential list ' +
                     'wearing this one\'s name.' },
      { name: 'state', in: 'query', required: false,
        schema: { type: 'string',
                  enum: ['valid', 'expired', 'revoked', 'not yet valid',
                         'no expiry stated'] },
        description: 'One state, matched against any member — so a set ' +
                     'holding an expired access token and a valid refresh ' +
                     'token is found by both, and its own `state` reads ' +
                     '`mixed` rather than picking one.' },
      { name: 'session', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'Only what was issued UNDER one browser sign-on ' +
                     'session, matched exactly on the id — the `sessionId` ' +
                     'every row of GET /admin-api/sessions carries, and the ' +
                     'join between the two resources.\n\nOnly a credential ' +
                     'issued under a session records one, so an assertion, a ' +
                     'Kerberos ticket, a token from either direct grant and ' +
                     'anything an RFC 8693 exchange produced are absent by ' +
                     'construction rather than missing. That is a fact about ' +
                     'the credential and not a gap in the recording.' }
    ].concat(pagingParameters()),
    responseDescription: 'The matching sets, with the paging that found them ' +
                         'and their credentials flattened beside them.',
    responseSchema: { $ref: '#/components/schemas/IssuedList' },
    handler: function (req, res) {
      log.debug("Entering the management API issued-list endpoint.");
      sendJson(res, 200, adminViews.tokensView(req.query).json);
      log.debug("Leaving the management API issued-list endpoint.");
    } },

  { method: 'GET', path: BASE + '/tokens/set', tag: 'Tokens',
    operationId: 'getIssuedSet',
    summary: 'One issuance, and every credential it carried',
    description: 'What `GET /admin-api/tokens` groups, opened up. Every ' +
                 'entry in that reply\'s `sets` carries the `setKey` this ' +
                 'takes, so a caller walks the list and opens one entry ' +
                 'without having to know whether it holds three credentials ' +
                 'or one.\n\nIt is addressed by `setKey` and never by the ' +
                 'issuer\'s `setId`: a set of one has no issuance id at all, ' +
                 'and its key is `one:<row handle>` so that the key space ' +
                 'covers every row of that table. A key nothing holds ' +
                 'answers 200 with `found: false` rather than 404 — a set ' +
                 'dropped to the registry\'s cap is the ordinary end of a ' +
                 'set\'s life and not a caller\'s mistake, and `why` says ' +
                 'which of the two happened.',
    mirrors: 'GET /admin/tokens/set',
    parameters: [
      { name: 'id', in: 'query', required: true, schema: { type: 'string' },
        description: 'The `setKey` off a row of GET /admin-api/tokens.' }
    ],
    responseDescription: 'The set and its members, or `found: false` and the ' +
                         'reason.',
    responseSchema: { $ref: '#/components/schemas/IssuedSetDetail' },
    handler: function (req, res) {
      log.debug("Entering the management API issued-set endpoint.");
      sendJson(res, 200, adminViews.tokenSetView(req.query).json);
      log.debug("Leaving the management API issued-set endpoint.");
    } },

  { method: 'POST', route: BASE + '/tokens/:action', tag: 'Tokens',
    mirrors: 'POST /admin/tokens',
    handler: function (req, res) {
      log.debug("Entering the management API token action endpoint.");
      const body = parseBody(req);
      const result = adminActions.tokenAction(withAction(req, body));
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0036');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API token action endpoint.");
    },
    actions: [
      { action: 'revoke', operationId: 'revokeToken',
        summary: 'Revoke one token',
        description: 'By `jti`, or by pasting the whole token — what ' +
                     'somebody has in their hand when they want a token ' +
                     'invalidated is the token, not its identifier. A pasted ' +
                     'token\'s SIGNATURE IS NOT VERIFIED and that is safe ' +
                     'rather than sloppy: the only thing read out of it is ' +
                     'the `jti`, which is then looked up in this service\'s ' +
                     'own registry, so a forged token yields an identifier ' +
                     'this service never issued and revoking one of those ' +
                     'invalidates nothing.\n\nThis is the SAME revocation ' +
                     'set RFC 7009\'s /oauth2/revoke writes to, so the token ' +
                     'immediately introspects as inactive, is refused by ' +
                     'UserInfo with `invalid_token`, and fails the refresh ' +
                     'grant with `invalid_grant`.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            target: { type: 'string',
                      description: 'A jti, or a whole JWT.' },
            jti: { type: 'string', description: 'Accepted for `target`.' },
            token: { type: 'string', description: 'Accepted for `target`.' }
          },
          examples: [{ target: 'a1b2c3d4e5f6g7h8i9j0kl' }],
          additionalProperties: false
        },
        responseDescription: 'Revoked, or already revoked — both are `ok`, ' +
                             'and the message says which.' },

      { action: 'restore', operationId: 'restoreToken',
        summary: 'Un-revoke one token (NON-SPEC)',
        description: 'NON-SPEC, and named as such wherever it appears: no ' +
                     'real authorization server can undo a revocation. It is ' +
                     'here because otherwise getting back to a working token ' +
                     'means restarting the service.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            target: { type: 'string', description: 'A jti, or a whole JWT.' },
            jti: { type: 'string', description: 'Accepted for `target`.' },
            token: { type: 'string', description: 'Accepted for `target`.' }
          },
          examples: [{ target: 'a1b2c3d4e5f6g7h8i9j0kl' }],
          additionalProperties: false
        },
        responseDescription: 'Restored, or it was not revoked — both are ' +
                             '`ok`.' },

      { action: 'revoke-artifact', operationId: 'revokeIssuedArtifact',
        summary: 'Disown one assertion, ticket or SVID (RECORD ONLY)',
        description: '**THIS CHANGES NOTHING OUTSIDE THIS SERVICE AND THAT ' +
                     'IS NOT A DEFECT.** A relying party validates a SAML ' +
                     'assertion\'s signature and its Conditions and asks ' +
                     'nobody; a Kerberos service decrypts a ticket with a ' +
                     'key it already holds; an X509-SVID chains to a bundle. ' +
                     'None of them will ever consult this service, so the ' +
                     'credential goes on working until it expires and the ' +
                     'holder is not told.\n\nWhat it does is record that ' +
                     'THIS IDENTITY PROVIDER HAS DISOWNED the credential, ' +
                     'which is a different claim and a useful one: it is ' +
                     'what a global sign-out can report, what CAEP transmits ' +
                     'to a receiver that subscribed, and what SAML Single ' +
                     'Logout carries for an assertion issued through a ' +
                     'browser profile. A WS-Trust assertion has neither ' +
                     'channel and the mark is the whole of what exists for ' +
                     'it.\n\nUntil 2026-09-05 this was impossible and every ' +
                     'surface said so. What changed is the recognition that ' +
                     'what this service KNOWS and what a relying party will ' +
                     'HONOUR are two claims, and only the second was ever ' +
                     'out of reach. Every row of GET /admin-api/tokens ' +
                     'carries `revocationReach` to keep them apart.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            artifact: { type: 'string',
                        description: 'The `key` off a row of ' +
                                     'GET /admin-api/tokens. This service\'s ' +
                                     'own handle and NOT the protocol\'s — a ' +
                                     'Kerberos ticket carries no identifier ' +
                                     'anybody can quote, so `identifier` ' +
                                     'cannot address every row and this can.' },
            key: { type: 'string', description: 'Accepted for `artifact`.' }
          },
          required: ['artifact'],
          examples: [{ artifact: 'artifact-12' }],
          additionalProperties: false
        },
        responseDescription: 'What was marked, and a sentence saying the ' +
                             'holder was not told.' },

      { action: 'restore-artifact', operationId: 'restoreIssuedArtifact',
        summary: 'Stop disowning one assertion, ticket or SVID (NON-SPEC)',
        description: 'The opposite of `revoke-artifact`, and NON-SPEC for ' +
                     'the reason every restore here is. It is a smaller act ' +
                     'than the others, because what it takes back never ' +
                     'reached anybody: the credential was working throughout.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            artifact: { type: 'string',
                        description: 'The `key` off a row of ' +
                                     'GET /admin-api/tokens.' },
            key: { type: 'string', description: 'Accepted for `artifact`.' }
          },
          required: ['artifact'],
          examples: [{ artifact: 'artifact-12' }],
          additionalProperties: false
        },
        responseDescription: 'Whether it had been disowned.' },

      { action: 'revoke-set', operationId: 'revokeIssuedSet',
        summary: 'Revoke every revocable credential in one issuance',
        description: 'One act instead of one call per credential. It writes ' +
                     'NOWHERE NEW: each member goes through the same ' +
                     'revocation `/oauth2/revoke` performs, one at a time, ' +
                     'into the same set of revoked `jti`s — so a token ' +
                     'revoked here immediately introspects as inactive, is ' +
                     'refused by UserInfo with `invalid_token`, and fails ' +
                     'the refresh grant with `invalid_grant`.\n\nWhat it ' +
                     'saves is the mistake this whole resource was reshaped ' +
                     'to prevent: revoking two credentials of three and ' +
                     'believing the grant is dead, when the refresh token ' +
                     'left behind mints a new access token on request.\n\n' +
                     'THE MEMBERS ARE RE-READ AT THE MOMENT OF THE CALL and ' +
                     'never taken from the caller — the body carries a ' +
                     '`setKey` and nothing else — so a list drawn an hour ' +
                     'ago cannot revoke a `jti` that has since been ' +
                     'forgotten to the cap while missing one issued ' +
                     'since.\n\nA set holding nothing revocable is REFUSED ' +
                     'with 400 rather than answered with "revoked 0": ' +
                     'nothing consults this service about a SAML assertion, ' +
                     'a Kerberos ticket or an SVID, so a success would be a ' +
                     'claim about the world that is not true. That is the ' +
                     'same answer `revoke-kind` gives for an unrevocable ' +
                     'kind.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            set: { type: 'string',
                   description: 'The `setKey` off a row of ' +
                                'GET /admin-api/tokens.' },
            setKey: { type: 'string', description: 'Accepted for `set`.' }
          },
          required: ['set'],
          examples: [{ set: 'set:a1b2c3d4e5f6' }],
          additionalProperties: false
        },
        responseDescription: 'How many were revocable, how many actually ' +
                             'moved, and which kinds they were. A member ' +
                             'already revoked is counted as revocable and ' +
                             'not as moved, so `revoked: 0` on an `ok` reply ' +
                             'means the set was already dead.' },

      { action: 'restore-set', operationId: 'restoreIssuedSet',
        summary: 'Un-revoke every revocable credential in one issuance ' +
                 '(NON-SPEC)',
        description: 'The opposite of `revoke-set`, and NON-SPEC for the ' +
                     'reason `restore` is: no real authorization server can ' +
                     'undo a revocation, because a resource server may ' +
                     'already have cached the refusal. It is here because ' +
                     'otherwise getting back to a working grant means ' +
                     'restarting the service.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            set: { type: 'string',
                   description: 'The `setKey` off a row of ' +
                                'GET /admin-api/tokens.' },
            setKey: { type: 'string', description: 'Accepted for `set`.' }
          },
          required: ['set'],
          examples: [{ set: 'set:a1b2c3d4e5f6' }],
          additionalProperties: false
        },
        responseDescription: 'How many were revocable and how many were ' +
                             'actually put back.' },

      { action: 'revoke-kind', operationId: 'revokeTokensByKind',
        summary: 'Revoke every token of one kind',
        description: 'Only the three JWT kinds can be revoked. Nothing ' +
                     'consults this service about a SAML assertion or a ' +
                     'Kerberos ticket — an assertion is valid because its ' +
                     'signature verifies and its Conditions hold, a ticket ' +
                     'because the service it names can decrypt it — so ' +
                     'naming one of those is refused rather than silently ' +
                     'doing nothing. `GET /admin-api/tokens` lists the three ' +
                     'under `revocableKinds`.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            kind: { type: 'string',
                    enum: ['access_token', 'id_token', 'refresh_token'] }
          },
          required: ['kind'],
          examples: [{ kind: 'access_token' }],
          additionalProperties: false
        },
        responseDescription: 'How many were revoked, in `revoked`.' },

      { action: 'revoke-subject', operationId: 'revokeTokensBySubject',
        summary: 'Revoke everything for one subject or username',
        description: 'Matches `sub` or `username` EXACTLY. That is the ' +
                     'difference from `revoke-user` beside it: this is the ' +
                     'one to use when you have a string off a token, and ' +
                     'that one is for an identity the users list names, ' +
                     'which may have been seen under several spellings.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { subject: { type: 'string' } },
          required: ['subject'],
          examples: [{
            subject: 'urn:uuid:016dc8f1-1bc4-55d9-9657-9b2ebb3cd4d2' }],
          additionalProperties: false
        },
        responseDescription: 'How many were revoked, in `revoked`.' },

      { action: 'revoke-user', operationId: 'revokeTokensByUser',
        summary: 'Revoke everything for one identity, under every spelling',
        description: 'The users list\'s `key`, and every spelling of it — ' +
                     '`alice`, her `urn:uuid:<entryUUID>` subject and ' +
                     '`alice@STS.MOCK` are one identity here, so revoking ' +
                     '"for alice" means all of them. Use `revoke-subject` ' +
                     'when you want an exact string instead.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { user: { type: 'string' } },
          required: ['user'],
          examples: [{ user: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'How many were revoked, in `revoked`.' },

      { action: 'revoke-all', operationId: 'revokeAllTokens',
        summary: 'Revoke every access token, ID Token and refresh token',
        description: 'Everything this service has issued and still ' +
                     'remembers. Assertions, tickets and credentials are ' +
                     'untouched, for the reason `revoke-kind` gives.',
        requestBodyRequired: false,
        requestBody: { type: 'object', properties: {}, examples: [{}],
                       additionalProperties: false },
        responseDescription: 'How many were revoked, in `revoked`.' }
    ] },

  // ---------------------------------------------------------------------
  // TRUST REALMS — several logical copies of this service in one process.
  //
  // TWO THINGS ABOUT THESE OPERATIONS ARE UNUSUAL AND BOTH ARE THE POINT.
  //
  // First, THIS WHOLE API IS ITSELF REALM-SCOPED. `/admin-api/config` is the
  // default realm's configuration; `/realm/acme/admin-api/config` is `acme`'s,
  // and a `set` posted there sets it on `acme` alone. That is not a special
  // case anybody wrote here — it falls out of the same path-prefix middleware
  // that makes /oauth2/token realm-scoped, and it means every one of the
  // ninety-odd operations below already works per realm. These five are only
  // the ones that manage the REGISTRY.
  //
  // Second, THE REGISTRY ITSELF IS NOT REALM-SCOPED, and it could not sensibly
  // be: there is one list of realms in this process, so `GET /admin-api/realms`
  // answers the same list whichever prefix it is called under. What differs is
  // `current`, which names the realm the CALL arrived in — and `remove` refuses
  // to remove that one, for the reason the console gives.
  //
  // A realm's SIGNING KEY is held in memory like everything else this service
  // MINTS, and dies with the process — so a token minted in a realm today
  // verifies against nothing tomorrow, restart or no restart. THE REALM ROW
  // ITSELF is written down since 2026-08-27 when `persistence.realms` has a
  // store under it, along with that realm's own directory; see
  // `GET /admin-api/persistence`. In the default memory mode it is not, and a
  // stack that wants its realms back creates them from these operations —
  // which is why `create` is worth having rather than a config file entry: the
  // thing that starts the stack already speaks this API.
  // ---------------------------------------------------------------------
  { method: 'GET', path: BASE + '/realms', tag: 'Trust realms',
    operationId: 'getRealms',
    summary: 'Every trust realm, its endpoints and what it sets',
    description: 'A TRUST REALM is a whole logical copy of this service: its ' +
                 'own configuration, its own signing key, and its own ' +
                 'sessions, authorization codes, tokens, credential offers, ' +
                 'service providers, statistics and audit log — answering on ' +
                 'the same sockets as every other realm and told apart by a ' +
                 'segment at the front of the path.\n\nThe DEFAULT realm has ' +
                 'no prefix, cannot be removed and cannot be renamed: every ' +
                 'URL this service published before realms existed is a URL ' +
                 'in it. A process with no realms defined behaves exactly as ' +
                 'it did before this feature existed, which is a property of ' +
                 'one predicate rather than a claim.\n\nEach row carries the ' +
                 'realm\'s `pathPrefix`, its `baseUrl`, the `kid` of its ' +
                 'signing key — two realms showing one kid would be two ' +
                 'names for one authorization server — the settings it sets, ' +
                 'and the four discovery documents a client asks for ' +
                 'first.\n\n`support` is the part answered nowhere else: ' +
                 'WHICH protocol families a realm actually separates, which ' +
                 'is not a tidy answer. A realm separates what this service ' +
                 'ISSUES and everything it holds while issuing it — keys, ' +
                 'sessions, codes, tokens, offers, artifacts, statistics and ' +
                 'the audit log. It does NOT separate the embedded ' +
                 'directory: LDAP answers on a socket with no path to put a ' +
                 'segment in, so there is one set of people, groups and ' +
                 'applications for the whole process — which means OAuth ' +
                 'client registrations, SAML service provider entries, the ' +
                 'SPIFFE registry and the two admin console roles are ' +
                 'shared. Kerberos, the two TLS listeners and SPIFFE\'s four ' +
                 'sockets are shared for the same reason.\n\n`reserved` is ' +
                 'the list of ids a realm may not be called, read off the ' +
                 'live router: they are the first segments of paths this ' +
                 'service already serves, and the refusal stands whatever ' +
                 '`realms.pathSegment` is set to precisely so that clearing ' +
                 'that setting cannot turn an existing realm into a shadow ' +
                 'over the console or the authorization server.',
    mirrors: 'GET /admin/realms',
    responseDescription: 'The realms, and the support table.',
    handler: function (req, res, next) {
      log.debug("Entering the management API trust realms endpoint.");
      // EVERY ROW SHOWS ITS REALM'S `kid`, and reading one MAKES the key set
      // of a realm this node holds none for — twenty realms created on
      // another node were twenty back-to-back generations inside this call,
      // long enough to cost the node its cluster membership (#46). So the
      // sets are made off the event loop first; `prepareKeySets()` never
      // rejects.
      helpers.prepareKeySets(realms.list().map(function (one) {
        return one.id;
      })).then(function () {
        sendJson(res, 200, adminViews.realmsJson(req));
        log.debug("Leaving the management API trust realms endpoint.");
      }).catch(function (e) {
        log.debug("Caught in the management API trust realms endpoint: " +
                  ((e && e.message) || e));
        next(e);
      });
    } },

  { method: 'POST', route: BASE + '/realms/:action', tag: 'Trust realms',
    mirrors: 'POST /admin/realms',
    handler: function (req, res) {
      log.debug("Entering the management API trust realms action endpoint.");
      const body = parseBody(req);
      const result = adminActions.realmsAction(withAction(req, body));
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0037');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API trust realms action endpoint.");
    },
    actions: [
      { action: 'create', operationId: 'createRealm',
        summary: 'Define a trust realm',
        description: 'Every HTTP endpoint this service has begins answering ' +
                     'under the new realm\'s prefix immediately, with a ' +
                     'signing key of its own and nothing issued yet.\n\n' +
                     'The `id` becomes a PATH SEGMENT, so it is lower-case ' +
                     'letters, digits and hyphens, starts with a letter or a ' +
                     'digit, and is at most 31 characters. It may not be ' +
                     '`default`, and it may not be the first segment of a ' +
                     'path this service already serves — `GET ' +
                     '/admin-api/realms` lists those in `reserved`.\n\n' +
                     'SIX SETTINGS ARE SEEDED ON A NEW REALM and they are ' +
                     'the six that are NAMES rather than behaviour: the SAML ' +
                     '2.0 entityID, the SAML 1.1 providerID, the ' +
                     'WS-Federation entityID, the WS-Trust issuer, the SAML ' +
                     'assertion issuer and the OpenID4VP verifier client id. ' +
                     'Each is the process\'s value with the realm id ' +
                     'appended, because two realms carrying one entityID is ' +
                     'not a configuration choice — it is two identity ' +
                     'providers claiming one name, which a service provider ' +
                     'is entitled to refuse. They are ORDINARY settings on ' +
                     'the realm: pass `overrides` to choose your own, or ' +
                     'unset them afterwards to go back to sharing the ' +
                     'process\'s name, which is a case worth being able to ' +
                     'build on a mock.\n\n' +
                     'The OAuth issuer is deliberately NOT seeded: it ' +
                     'defaults to naming the base URL a request arrived on, ' +
                     'and that already carries the realm prefix.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            id: { type: 'string',
                  description: 'Lower-case letters, digits and hyphens. It ' +
                               'is the path segment.' },
            name: { type: 'string',
                    description: 'What a person calls it. Free text; ' +
                                 'defaults to the id.' },
            description: { type: 'string' },
            overrides: { type: 'object',
                         description: 'Settings to set on the realm, named ' +
                                      'by the dot paths GET ' +
                                      '/admin-api/config lists. They win ' +
                                      'over the six seeded names. ' +
                                      '`realms.enabled` and ' +
                                      '`realms.pathSegment` are refused: a ' +
                                      'realm that could switch realms off, ' +
                                      'or move the prefix it was found ' +
                                      'under, would be doing it half way ' +
                                      'through the request that found it.' }
          },
          required: ['id'],
          examples: [{ id: 'acme', name: 'Acme Corporation',
                       overrides: { 'saml2.entityId': 'urn:acme:idp' } }],
          additionalProperties: false
        },
        responseDescription: 'The realm id, in `realm`.' },

      { action: 'update', operationId: 'updateRealm',
        summary: 'Rename a realm, or describe it',
        description: 'The `id` cannot be changed, because it is the path ' +
                     'segment every client was given. Define a new realm and ' +
                     'remove this one if that is what is wanted — and note ' +
                     'that the new one gets a new signing key, which is the ' +
                     'honest consequence of it being a different realm.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { id: { type: 'string' }, name: { type: 'string' },
                        description: { type: 'string' } },
          required: ['id'],
          examples: [{ id: 'acme', name: 'Acme Corporation (staging)' }],
          additionalProperties: false
        },
        responseDescription: 'The realm id, in `realm`.' },

      { action: 'set', operationId: 'setRealmSetting',
        summary: 'Set one setting on one realm',
        description: 'The value applies to the next request that arrives ' +
                     'under that realm\'s prefix and to nothing else — above ' +
                     'whatever the process as a whole is configured with, ' +
                     'and below nothing.\n\nThis is the same store `POST ' +
                     '/realm/<id>/admin-api/config/set` writes to, and ' +
                     'either is fine; the difference is only which realm you ' +
                     'have to be in to make the call. A setting whose ' +
                     '`editable` is false is refused with the reason, ' +
                     'exactly as it is on the service-wide resource, and ' +
                     '`realms.enabled` and `realms.pathSegment` are refused ' +
                     'outright.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { id: { type: 'string' }, key: { type: 'string' },
                        value: {} },
          required: ['id', 'key', 'value'],
          examples: [{ id: 'acme', key: 'saml2.entityId',
                       value: 'urn:acme:idp' }],
          additionalProperties: false
        },
        responseDescription: 'The realm and the key, in `realm` and `key`.' },

      { action: 'unset', operationId: 'unsetRealmSetting',
        summary: 'Drop one setting from one realm',
        description: 'The realm falls back to whatever this service as a ' +
                     'whole is configured with — which may itself be a ' +
                     'runtime override, and is left alone. A key the realm ' +
                     'does not set is refused rather than treated as already ' +
                     'done, because the two are different facts and a caller ' +
                     'that misspelt a key would otherwise be told it ' +
                     'succeeded.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { id: { type: 'string' }, key: { type: 'string' } },
          required: ['id', 'key'],
          examples: [{ id: 'acme', key: 'saml2.entityId' }],
          additionalProperties: false
        },
        responseDescription: 'The realm and the key, in `realm` and `key`.' },

      { action: 'remove', operationId: 'removeRealm',
        summary: 'Remove a realm, and everything it holds',
        description: 'EVERYTHING IT ACCUMULATED GOES WITH IT: its sessions, ' +
                     'its authorization codes, its tokens, its refresh ' +
                     'families, its credential offers, its service ' +
                     'providers, its statistics, its audit log and its ' +
                     'signing key. That is deliberate rather than thorough — ' +
                     'a realm re-created with the same id inheriting the ' +
                     'last one\'s sessions and tokens would be the single ' +
                     'most surprising thing a re-created realm could ' +
                     'do.\n\nNOTHING IS REMOVED FROM THE DIRECTORY, because ' +
                     'nothing there belongs to a realm: `ou=users`, ' +
                     '`ou=groups` and `ou=applications` are shared by every ' +
                     'realm in this process.\n\nA realm cannot remove ITSELF ' +
                     '— a call to `/realm/acme/admin-api/realms/remove` ' +
                     'naming `acme` is refused. Everything about the removal ' +
                     'would work; what would not is the caller, which would ' +
                     'be talking to a prefix that had stopped existing. Call ' +
                     'it from another realm, or from the default one.\n\nThe ' +
                     'DEFAULT realm cannot be removed at all.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { id: { type: 'string' } },
          required: ['id'],
          examples: [{ id: 'acme' }],
          additionalProperties: false
        },
        responseDescription: 'The realm id, in `realm`.' } ] },

  { method: 'GET', path: BASE + '/config', tag: 'Configuration',
    operationId: 'getConfig',
    summary: 'Every setting this service has, and where each value came from',
    description: 'Every setting, grouped by protocol, each with its ' +
                 'effective value and the SOURCE of that value: a runtime ' +
                 'override, an environment variable, the appconfig file ' +
                 'CONFIG_FILE names, or `env/defaults.js` under it. The ' +
                 'source is the part that was not answerable before this ' +
                 'resource existed — the four are indistinguishable once a ' +
                 'value has been read, and the question "why is the issuer ' +
                 'that?" used to be a grep. There is no fifth source: a ' +
                 'setting with a value in none of them stops this service ' +
                 'from STARTING rather than falling back to a constant in a ' +
                 'module.\n\nIt also says which settings can be CHANGED ' +
                 'while the service runs. The ones that cannot were consumed ' +
                 'at startup — a bound socket, the TLS certificate\'s names, ' +
                 'the Kerberos principal database and its long-term keys, ' +
                 'the directory\'s base DN — and each carries the reason.',
    mirrors: 'GET /admin/config',
    responseDescription: 'The whole table.',
    responseSchema: { $ref: '#/components/schemas/Config' },
    handler: function (req, res) {
      log.debug("Entering the management API configuration endpoint.");
      sendJson(res, 200, admin.configJson());
      log.debug("Leaving the management API configuration endpoint.");
    } },

  { method: 'POST', route: BASE + '/config/:action', tag: 'Configuration',
    mirrors: 'POST /admin/config',
    handler: function (req, res) {
      log.debug("Entering the management API configuration action endpoint.");
      const body = parseBody(req);
      const result = adminActions.configAction(withAction(req, body));
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0038');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API configuration action endpoint.");
    },
    actions: [
      { action: 'set', operationId: 'setSetting',
        summary: 'Change one setting',
        description: 'A RUNTIME OVERRIDE — the top of config.js\'s five ' +
                     'layers. Whether it outlives the process is ' +
                     '`persistence.appconfig`: in the default memory mode it ' +
                     'is gone on restart, and with a store on it is written ' +
                     'down and re-applied at the next start through this ' +
                     'same function, which is why it adds no sixth layer. ' +
                     'See `GET /admin-api/persistence`.\n\nNOTHING HERE ' +
                     'WRITES TO THE APPCONFIG FILE in either mode, and that ' +
                     'is deliberate rather than unfinished: a service that ' +
                     'edited a file checked into a repository would leave a ' +
                     'test\'s forgotten change behind permanently. The ' +
                     'durable copy goes to the persistent store, which is ' +
                     'not a place anything is checked in from.\n\nThe change ' +
                     'applies to the next token, assertion, ticket or ' +
                     'search. Nothing already issued changes, because a ' +
                     'token is a signed document.\n\nA setting whose ' +
                     '`editable` is false is REFUSED with the reason rather ' +
                     'than accepted, and a value that does not fit the ' +
                     'setting\'s type is refused by name.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            key: { type: 'string',
                   description: 'The dot path, as GET /admin-api/config ' +
                                'lists it.' },
            value: { description: 'A string is always accepted and is ' +
                                  'coerced to the setting\'s type, so the ' +
                                  'environment spelling works here too; a ' +
                                  'JSON number, boolean or array of strings ' +
                                  'is accepted where the type takes one.' }
          },
          required: ['key', 'value'],
          examples: [{ key: 'saml.issuer', value: 'urn:example:idp' }],
          additionalProperties: false
        },
        responseDescription: 'The setting as it now stands, in `setting`.' },

      { action: 'set-many', operationId: 'setSettings',
        summary: 'Change a whole section at once',
        description: 'What the console\'s per-section Save posts, and it is ' +
                     'not a convenience: a section is how a person changes ' +
                     'configuration, and one call per field would make a ' +
                     'partly-applied section the ordinary outcome of a ' +
                     'mistake in any one of them.\n\nALL-OR-NOTHING. Every ' +
                     'value is checked before any is written, so a body with ' +
                     'one bad field changes nothing and names it. A key this ' +
                     'service does not know is ignored rather than refused, ' +
                     'because a form posts fields this resource never ' +
                     'declared; `applied` says which were taken and ' +
                     '`changed` which actually differed from what was ' +
                     'already in force.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          description: 'One property per setting, named by its dot path.',
          properties: {},
          examples: [{ 'oid4vci.batchSize': 8,
                       'oid4vci.offerUsername': 'alice' }],
          additionalProperties: true
        },
        responseDescription: 'What was applied, in `applied`, and what ' +
                             'actually changed, in `changed`.' },

      { action: 'reset', operationId: 'resetSetting',
        summary: 'Drop one runtime override',
        description: 'The setting falls back to whatever it would have used ' +
                     'had nothing ever been set here — its environment ' +
                     'variable, the appconfig file, or `env/defaults.js`. ' +
                     'A setting with no override is refused rather than ' +
                     'treated as already done, because the two are different ' +
                     'facts and a caller that misspelt a key would otherwise ' +
                     'be told it succeeded.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { key: { type: 'string' } },
          required: ['key'],
          examples: [{ key: 'saml.issuer' }],
          additionalProperties: false
        },
        responseDescription: 'The setting as it now stands, in `setting`.' },

      { action: 'reset-all', operationId: 'resetAllSettings',
        summary: 'Drop every runtime override',
        description: 'Returns the whole service to the configuration it ' +
                     'started with, without restarting it. This is what a ' +
                     'test should call to put the service back: the mock\'s ' +
                     'admin state survives between jobs, so a setting left ' +
                     'changed here changes what every later job sees.',
        requestBodyRequired: false,
        requestBody: { type: 'object', properties: {},
                       additionalProperties: false },
        responseDescription: 'The keys that were cleared, in `cleared`.' } ] },

  // ---------------------------------------------------------------------
  // The token lifetimes, which are four of the settings above under a name
  // that promises four rather than forty-nine.
  //
  // Rule 7 is satisfied twice over here and it is worth saying which way
  // round. `/admin/token-lifetimes` grew a form, so it gets its operations —
  // that is the rule as written. What it does NOT get is a second store: the
  // handler calls `adminActions.tokenLifetimesAction`, which writes through
  // `config.setOverride()`, which is the same function `POST /config/set`
  // calls against the same override map. So these two operations and the four
  // Configuration ones are two doors onto one thing, deliberately, in the way
  // `/admin/rbac` and `ldapmodify` are four doors onto one membership.
  //
  // What the narrow door buys a CALLER, which is why it is not merely a
  // convenience for the page: `POST /config/set-many` takes any key and
  // ignores what it does not know, which is right for a form posting a whole
  // section and wrong for a test that means to set a lifetime — a misspelt
  // key there succeeds and changes nothing. This one refuses anything that is
  // not one of the four, by name.
  ...PROTOCOL_SETTINGS_OPERATIONS,

  { method: 'GET', path: BASE + '/token-lifetimes', tag: 'Token lifetimes',
    operationId: 'getTokenLifetimes',
    summary: 'How long tokens issued here are good for',
    description: 'The three lifetimes — access token, ID Token, refresh ' +
                 'token — and the clock skew applied wherever this service ' +
                 'reads one of its own tokens back.\n\nAll four are ' +
                 'ordinary configuration settings and appear in ' +
                 '`GET /config` too; `settings` here is the same row shape, ' +
                 'carrying each one\'s bounds, its source and its default. ' +
                 '`lifetimes` beside it is just the four numbers, for a ' +
                 'caller that wants the value rather than the ' +
                 'provenance.\n\nIt also reports WHAT IS ALREADY OUT ' +
                 'THERE, per kind, counted against the same clock the ' +
                 'endpoints use — the skew is applied to that count, so a ' +
                 'token this calls expired is one POST /oauth2/introspect ' +
                 'will report inactive.\n\nA LIFETIME IS STAMPED INTO A ' +
                 'TOKEN WHEN IT IS SIGNED, so changing one reaches the next ' +
                 'token and nothing already issued. To take an issued token ' +
                 'out of circulation, revoke it under Tokens.',
    mirrors: 'GET /admin/token-lifetimes',
    responseDescription: 'The four settings, and what has been issued under ' +
                         'them.',
    responseSchema: { $ref: '#/components/schemas/TokenLifetimes' },
    handler: function (req, res) {
      log.debug("Entering the management API token lifetimes endpoint.");
      sendJson(res, 200, adminViews.tokenLifetimesJson());
      log.debug("Leaving the management API token lifetimes endpoint.");
    } },

  { method: 'POST', route: BASE + '/token-lifetimes/:action',
    // ---------------------------------------------------------------------
    // A NARROW DOOR: THE HANDLER OWNS THE WHOLE BODY, so the ajv wrapper at
    // the foot of this file stands aside for it.
    //
    // **REFUSING AN UNKNOWN KEY BY NAME IS THE ENTIRE REASON THIS RESOURCE
    // EXISTS BESIDE `/config/set-many`**, which ignores one on purpose — so a
    // narrow door that stopped refusing would be two operations over one
    // function with nothing to tell them apart. The handler's refusal names
    // the key it refused AND lists the ones it sets, and
    // `sts_admin_api_operations.js` asserts both halves.
    //
    // A schema error cannot say either thing: `additionalProperties: false`
    // answers "not a member of this request" and stops. Letting ajv go first
    // would replace a refusal a caller can act on with a worse one and switch
    // off the assertion that guards it, which is the same judgement
    // `structureOnly()` makes about `enum` and `required` one level up.
    // ---------------------------------------------------------------------
    handlerOwnsBody: true,
    tag: 'Token lifetimes',
    mirrors: 'POST /admin/token-lifetimes',
    handler: function (req, res) {
      log.debug("Entering the management API token lifetimes action.");
      const body = parseBody(req);
      const result = adminActions.tokenLifetimesAction(withAction(req, body));
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0039');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API token lifetimes action.");
    },
    actions: [
      { action: 'set', operationId: 'setTokenLifetimes',
        summary: 'Set one or more of the four',
        description: 'A RUNTIME OVERRIDE, like every other change made ' +
                     'through this API: gone on restart in the default ' +
                     'memory mode, and written down and re-applied at the ' +
                     'next start when `persistence.appconfig` has a store ' +
                     'under it. Nothing writes to the appconfig file in ' +
                     'either case.\n\nName any of the four; the console ' +
                     'form posts all four at once and a caller may post ' +
                     'one. ALL-OR-NOTHING: every value is checked before any ' +
                     'is written, so a body with one bad field changes ' +
                     'nothing and names it.\n\nUNLIKE ' +
                     '`POST /config/set-many`, a property that is not one of ' +
                     'the four is REFUSED rather than ignored. That door is ' +
                     'for a form posting a whole section, where an unknown ' +
                     'field is ordinary; this one is for a caller that means ' +
                     'to set a lifetime, where a misspelt key that succeeded ' +
                     'and changed nothing is the worst possible ' +
                     'answer.\n\nEvery lifetime must be a whole number of ' +
                     'THIRTY-SECOND units, between 30 and 2592000 (thirty ' +
                     'days). The skew is 0 to 300 in the same units. Those ' +
                     'bounds are on each setting\'s row in the GET, so a ' +
                     'client can render them rather than repeat ' +
                     'them.\n\nThe change applies to the NEXT token ' +
                     'signed. Nothing already issued is affected: a lifetime ' +
                     'is a claim inside a signed statement.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          description: 'One property per setting, named by its dot path. ' +
                       'THESE AND NO OTHERS, and the list below is BUILT ' +
                       'from the one this action refuses against rather than ' +
                       'typed beside it: the door refuses anything outside ' +
                       'it BY NAME, which is the whole reason it exists ' +
                       'beside `POST /config/set-many` — that one IGNORES a ' +
                       'key it does not know, which is right for a form ' +
                       'posting a section and wrong for a caller who ' +
                       'misspelt a lifetime. A document short by one is then ' +
                       'a caller refused for following it.',
          properties: narrowDoorProperties(adminActions.tokenLifetimeKeys()),
          examples: [{ 'oauth2.accessTokenTtlS': 60,
                       'oauth2.idTokenTtlS': 60,
                       'oauth2.refreshTokenTtlS': 86400,
                       'oauth2.clockSkewS': 30 }],
          additionalProperties: false
        },
        responseDescription: 'What was applied, in `applied`, and what ' +
                             'actually changed, in `changed`.' },

      { action: 'defaults', operationId: 'resetTokenLifetimes',
        summary: 'Put the four back',
        description: 'Clears the runtime override on THESE FOUR ONLY, so ' +
                     'each falls back to its environment variable, the ' +
                     'appconfig file, or `env/defaults.js` — one hour, ' +
                     'one hour, twenty-four hours and thirty ' +
                     'seconds.\n\nIt is deliberately not ' +
                     '`POST /config/reset-all`, which would also drop an ' +
                     'override somebody set on an unrelated page. A test ' +
                     'that changed only the lifetimes should call this to ' +
                     'put the service back; one that changed more should ' +
                     'call that one.\n\nA setting that was not overridden ' +
                     'is skipped rather than refused, because this means ' +
                     '"put these four back" rather than "undo this one ' +
                     'change" — the per-key refusal is on ' +
                     '`POST /config/reset`, where it is the right answer.',
        requestBodyRequired: false,
        requestBody: { type: 'object', properties: {},
                       additionalProperties: false },
        responseDescription: 'The keys that had an override cleared, in ' +
                             '`cleared`.' } ] },

  // ---------------------------------------------------------------------
  // The SAML assertion window, which is three of the settings above under a
  // name that promises three rather than a hundred and sixty-one.
  //
  // Rule 7 is satisfied the same way /token-lifetimes satisfies it, and the
  // parallel is exact: /admin/saml-assertions grew a form, so it gets its
  // operations. It gets no second store either — the handler calls
  // adminActions.samlAssertionsAction, which writes through
  // config.setOverride() against the same override map POST /config/set writes
  // to, and the same map the two identity provider pages' own forms write to.
  // Four doors, one thing.
  //
  // What the narrow door buys a CALLER is what it buys there: POST
  // /config/set-many ignores a key it does not know, which is right for a
  // form posting a whole section and wrong for a test that means to set an
  // assertion lifetime, where a misspelt key succeeds and changes nothing.
  { method: 'GET', path: BASE + '/saml-assertions', tag: 'SAML assertions',
    operationId: 'getSamlAssertions',
    summary: 'How long an issued assertion is valid, and the clock skew '
             + 'written into it',
    description: 'The two assertion lifetimes — SAML 2.0 and SAML 1.1 — and ' +
                 'the clock skew added to BOTH ENDS of each, which is what ' +
                 'this service writes into `Conditions/NotBefore` and ' +
                 '`NotOnOrAfter`.\n\nAll three are ordinary configuration ' +
                 'settings and appear in `GET /config` too; `settings` here ' +
                 'is the same row shape, carrying each one\'s bounds, its ' +
                 'source and its default. `assertions` beside it is the ' +
                 'numbers, and includes `saml2WindowS` and `saml11WindowS` — ' +
                 'the WHOLE width of the stated window, which is the ' +
                 'lifetime plus TWICE the skew and is the figure a caller ' +
                 'actually has to reason about. No single setting states ' +
                 'it.\n\nTHE LIFETIMES ARE PER PROFILE AND THE SKEW IS NOT. ' +
                 'SAML 2.0 and SAML 1.1 are separate implementations here, ' +
                 'consumed differently, so each has its own lifetime; the ' +
                 'skew is a fact about the clocks in the estate this service ' +
                 'issues into, which a deployment decides once. All three ' +
                 'reach WS-Trust and WS-Federation as well — their ' +
                 'assertions come out of the same two builders — and a ' +
                 'WS-Federation sign-in carries a SAML 1.1 assertion, so ' +
                 '`saml11.assertionLifetimeMin` governs ' +
                 'it.\n\n`saml.clockSkewS` IS NOT `oauth2.clockSkewS`. This ' +
                 'one is written INTO a document this service issues. That ' +
                 'one is the tolerance applied wherever this service READS ' +
                 'one back, including an inbound federation partner\'s ' +
                 'assertion, and it is on `GET /token-lifetimes`.\n\nIt also ' +
                 'reports what has already been issued, per profile, counted ' +
                 'against this service\'s own clock with no allowance ' +
                 'applied.\n\nA WINDOW IS STAMPED INTO AN ASSERTION WHEN IT ' +
                 'IS SIGNED, so changing one reaches the next assertion and ' +
                 'nothing already issued.',
    mirrors: 'GET /admin/saml-assertions',
    responseDescription: 'The three settings, and what has been issued ' +
                         'under them.',
    responseSchema: { $ref: '#/components/schemas/SamlAssertions' },
    handler: function (req, res) {
      log.debug("Entering the management API SAML assertions endpoint.");
      sendJson(res, 200, adminViews.samlAssertionsJson());
      log.debug("Leaving the management API SAML assertions endpoint.");
    } },

  { method: 'POST', route: BASE + '/saml-assertions/:action',
    // ---------------------------------------------------------------------
    // A NARROW DOOR: THE HANDLER OWNS THE WHOLE BODY, so the ajv wrapper at
    // the foot of this file stands aside for it.
    //
    // **REFUSING AN UNKNOWN KEY BY NAME IS THE ENTIRE REASON THIS RESOURCE
    // EXISTS BESIDE `/config/set-many`**, which ignores one on purpose — so a
    // narrow door that stopped refusing would be two operations over one
    // function with nothing to tell them apart. The handler's refusal names
    // the key it refused AND lists the ones it sets, and
    // `sts_admin_api_operations.js` asserts both halves.
    //
    // A schema error cannot say either thing: `additionalProperties: false`
    // answers "not a member of this request" and stops. Letting ajv go first
    // would replace a refusal a caller can act on with a worse one and switch
    // off the assertion that guards it, which is the same judgement
    // `structureOnly()` makes about `enum` and `required` one level up.
    // ---------------------------------------------------------------------
    handlerOwnsBody: true,
    tag: 'SAML assertions',
    mirrors: 'POST /admin/saml-assertions',
    handler: function (req, res) {
      log.debug("Entering the management API SAML assertions action.");
      const body = parseBody(req);
      const result = adminActions.samlAssertionsAction(withAction(req, body));
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0040');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API SAML assertions action.");
    },
    actions: [
      { action: 'set', operationId: 'setSamlAssertions',
        summary: 'Set one or more of the SAML assertion settings',
        description: 'A RUNTIME OVERRIDE, like every other change made ' +
                     'through this API: gone on restart in the default ' +
                     'memory mode, and written down and re-applied at the ' +
                     'next start when `persistence.appconfig` has a store ' +
                     'under it. Nothing writes to the appconfig file in ' +
                     'either case.\n\nName any of the three; the console ' +
                     'form posts all three at once and a caller may post ' +
                     'one. ALL-OR-NOTHING: every value is checked before ' +
                     'any is written, so a body with one bad field changes ' +
                     'nothing and names it.\n\nUNLIKE ' +
                     '`POST /config/set-many`, a property that is not one ' +
                     'of the three is REFUSED rather than ignored, for the ' +
                     'reason `POST /token-lifetimes/set` gives.\n\nTHE TWO ' +
                     'LIFETIMES ARE MINUTES AND THE SKEW IS SECONDS. That ' +
                     'is not a formatting accident: a lifetime is set to a ' +
                     'number of minutes to watch an assertion go stale, and ' +
                     'a skew is a handful of seconds covering the ' +
                     'difference between two machines. The skew is 0 to ' +
                     '300 — five minutes is what Kerberos allows here ' +
                     '(`krb5.clockSkew`), and wider than that the window ' +
                     'has stopped being a tolerance. The bounds are on each ' +
                     'setting\'s row in the GET, so a client can render ' +
                     'them rather than repeat them.\n\nThe change applies ' +
                     'to the NEXT assertion signed. Nothing already issued ' +
                     'is affected: a validity window is two attributes ' +
                     'inside a signed document.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          description: 'One property per setting, named by its dot path, ' +
                       'BUILT from the list this action refuses against ' +
                       'rather than typed here — it named three of them for ' +
                       'months while the action accepted sixteen. The ' +
                       'lifetimes are in MINUTES and the skew and the ' +
                       'artifact lifetimes are in SECONDS; each row of the ' +
                       'GET carries its own unit and bounds.',
          properties: narrowDoorProperties(adminActions.samlAssertionKeys()),
          examples: [{ 'saml2.assertionLifetimeMin': 1,
                       'saml11.assertionLifetimeMin': 1,
                       'saml.clockSkewS': 30 }],
          additionalProperties: false
        },
        responseDescription: 'What was applied, in `applied`, and what ' +
                             'actually changed, in `changed`.' },

      { action: 'defaults', operationId: 'resetSamlAssertions',
        summary: 'Put the three back',
        description: 'Clears the runtime override on THESE THREE ONLY, so ' +
                     'each falls back to its environment variable, the ' +
                     'appconfig file, or `env/defaults.js` — sixty ' +
                     'minutes, sixty minutes and no skew at ' +
                     'all.\n\nIt is deliberately not ' +
                     '`POST /config/reset-all`, which would also drop an ' +
                     'override somebody set on an unrelated page.\n\nA ' +
                     'setting that was not overridden is skipped rather ' +
                     'than refused, because this means "put these three ' +
                     'back" rather than "undo this one change" — the ' +
                     'per-key refusal is on `POST /config/reset`.',
        requestBodyRequired: false,
        requestBody: { type: 'object', properties: {},
                       additionalProperties: false },
        responseDescription: 'The keys that had an override cleared, in ' +
                             '`cleared`.' } ] },

  { method: 'GET', path: BASE + '/claims', tag: 'Custom claims',
    operationId: 'getClaims',
    summary: 'The custom claims every new token and assertion will carry',
    description: 'The four sets — OAuth 2.0 access token, OIDC ID Token, ' +
                 'SAML 2.0 Attribute, SAML 1.1 Attribute — with the rules ' +
                 'that govern them: the claim names this service sets itself ' +
                 'and will not let you override, and the placeholders a ' +
                 'value may use.\n\nEach set has TWO HALVES and they are ' +
                 'configured by different operations. `claims` are TYPED: a ' +
                 'name and a value somebody wrote, the same for everybody ' +
                 'except where a ${placeholder} carries the sign-in. ' +
                 '`attributes` are LDAP ATTRIBUTE TYPES chosen from ' +
                 '`attributeCatalogue`, whose value is read off that ' +
                 'person\'s entry under ou=users — so an `ldapmodify` ' +
                 'changes the next token, and an LDAP client and an OIDC ' +
                 'client pointed at this service are shown the same ' +
                 'person.\n\n`attributeClaims` is what the current selection ' +
                 'would actually put in each set for the previewed person, ' +
                 'built by the same function the issuance path calls. A ' +
                 'caller with no browser has no other way to ask "what would ' +
                 'this issue".',
    mirrors: 'GET /admin/claims',
    parameters: [
      { name: 'user', in: 'query', required: false,
        schema: { type: 'string', default: 'alice' },
        description: 'Whose attribute values to preview. Defaults to a ' +
                     'person the directory holds from startup, so the ' +
                     'preview shows real values on a fresh process. Somebody ' +
                     'with no entry gets generated values — the same ' +
                     'invented person every time, seeded from the name — and ' +
                     '`preview.entryFound` says which of the two happened.' }
    ],
    responseDescription: 'The four sets, the attribute catalogue and the ' +
                         'preview.',
    responseSchema: { $ref: '#/components/schemas/ClaimSets' },
    handler: function (req, res) {
      log.debug("Entering the management API claims endpoint.");
      sendJson(res, 200,
               adminViews.claimsJson(adminViews.claimsPreviewUser(req.query)));
      log.debug("Leaving the management API claims endpoint.");
    } },

  { method: 'POST', route: BASE + '/claims/:action', tag: 'Custom claims',
    mirrors: 'POST /admin/claims',
    handler: function (req, res) {
      log.debug("Entering the management API claims action endpoint.");
      const body = parseBody(req);
      // The `attributes` action's list, in both spellings, exactly as the
      // credential-claims row below takes it. The other six actions ignore it.
      const names = namesOf(req, body, 'attribute', 'attributes');
      // The THIRD argument is the family, and it is what makes this resource
      // the mirror of /admin/claims rather than of the store: a `set` of
      // `saml2` here is refused by name and sent to /admin-api/saml-attributes,
      // exactly as the console's own form post is. The action function, the
      // store and the audit row are the same ones either way.
      const result = adminActions.claimsAction(withAction(req, body), names,
                                        stats.JWT_CLAIM_SET_IDS);
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0041');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API claims action endpoint.");
    },
    actions: claimSetActions(JWT_CLAIM_FAMILY) },

  // -------------------------------------------------------------------------
  // THE USERINFO HALF OF THE SAME STORE, and the half a client can add to.
  //
  // Its own resource for the reason the SAML one has its own: rule 7 is about
  // the CONTROL, and /admin/userinfo-claims is its own page with its own forms.
  // But it carries something neither of the others does — the OIDC Core section
  // 5.5 vocabulary, in `claimsRequest` — because that is the half of this
  // endpoint's behaviour an administrator does NOT decide, and a caller with no
  // browser has no other way to learn what a claims request may name.
  // -------------------------------------------------------------------------
  { method: 'GET', path: BASE + '/userinfo-claims', tag: 'UserInfo claims',
    operationId: 'getUserInfoClaims',
    summary: 'What every UserInfo response will carry, and what a client may ' +
             'ask it for',
    description: 'The `userinfo` claim set — the fifth of the five, and the ' +
                 'only one whose subject is not something this service ' +
                 'ISSUES.\n\n**A UserInfo response is built on EVERY call.** ' +
                 'An access token, an ID Token and both SAML assertions are ' +
                 'signed documents: a claim added to one of those sets ' +
                 'reaches a client at its next sign-in and never reaches ' +
                 'what it already holds. A claim added here reaches the next ' +
                 '`GET /oauth2/userinfo` from a client that signed in an ' +
                 'hour ago and has done nothing since. That is the whole ' +
                 'reason it is configured separately from the ID Token set ' +
                 'rather than being the same list under two names.\n\nThe ' +
                 'set has the same TWO HALVES as every other and they are ' +
                 'configured by different operations. `claims` are TYPED: a ' +
                 'name and a value somebody wrote, the same for everybody ' +
                 'except where a ${placeholder} carries the sign-in. ' +
                 '`attributes` are LDAP ATTRIBUTE TYPES chosen from ' +
                 '`attributeCatalogue`, whose value is read off that ' +
                 'person\'s entry under ou=users — so an `ldapmodify` ' +
                 'changes the next response, with no new sign-in at ' +
                 'all.\n\n`reservedJwtClaims` IS here, unlike GET ' +
                 '/admin-api/saml-attributes, and the reason is worth ' +
                 'reading before assuming it is a copy-paste: `sub` is ' +
                 'REQUIRED in this response (OIDC Core 5.3.2, and a client ' +
                 'MUST check it against the ID Token\'s), and when a client ' +
                 'has registered a `userinfo_signed_response_alg` the whole ' +
                 'response is a JWT carrying `iss`, `aud` and ' +
                 '`exp`.\n\n`claimsRequest` is the half no operation here ' +
                 'sets: OIDC Core section 5.5 lets a CLIENT name individual ' +
                 'claims in the `claims` request parameter, and this service ' +
                 'answers them off the same catalogue. It lists every name a ' +
                 'request may use, the four layers of precedence, what is ' +
                 'carried and NOT enforced (`essential`, `value`, `values`), ' +
                 'and the non-spec way to send one straight to the endpoint.',
    mirrors: 'GET /admin/userinfo-claims',
    parameters: [
      { name: 'user', in: 'query', required: false,
        schema: { type: 'string', default: 'alice' },
        description: 'Whose attribute values to preview. The same parameter, ' +
                     'the same cap and the same default GET ' +
                     '/admin-api/claims takes, deliberately: the three ' +
                     'replies preview one person unless asked otherwise. ' +
                     '`preview.entryFound` says whether the directory holds ' +
                     'them or the values were invented from the username.' },
      { name: 'request', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'A section 5.5 claims request, as the JSON a client ' +
                     'would send — for example ' +
                     '`{"userinfo":{"birthdate":null,"address":null}}`. The ' +
                     'reply\'s `claimsRequest.preview` then says exactly ' +
                     'what that request would return for `user`, computed by ' +
                     'the two functions the UserInfo endpoint itself calls. ' +
                     'A MALFORMED one is reported in ' +
                     '`claimsRequest.preview.error` and does NOT fail this ' +
                     'call: what it shows is the `invalid_request` a client ' +
                     'would be given, which is the thing a caller is asking ' +
                     'about.' }
    ],
    responseDescription: 'The UserInfo set, the attribute catalogue, the ' +
                         'preview and the section 5.5 vocabulary.',
    responseSchema: { $ref: '#/components/schemas/UserInfoClaimSets' },
    handler: function (req, res) {
      log.debug("Entering the management API UserInfo claims endpoint.");
      sendJson(res, 200,
               adminViews.userinfoClaimsJson(adminViews.claimsPreviewUser(
                   req.query),
                                        adminViews.claimsRequestParameter(
                                            req.query)));
      log.debug("Leaving the management API UserInfo claims endpoint.");
    } },

  { method: 'POST', route: BASE + '/userinfo-claims/:action',
    tag: 'UserInfo claims',
    mirrors: 'POST /admin/userinfo-claims',
    handler: function (req, res) {
      log.debug("Entering the management API UserInfo claims action endpoint.");
      const body = parseBody(req);
      const names = namesOf(req, body, 'attribute', 'attributes');
      const result = adminActions.claimsAction(withAction(req, body), names,
                                        stats.USERINFO_CLAIM_SET_IDS);
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0042');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API UserInfo claims action endpoint.");
    },
    actions: claimSetActions(USERINFO_CLAIM_FAMILY) },

  // -------------------------------------------------------------------------
  // THE SAML HALF OF THE SAME STORE, mirroring the console page that carries
  // it. Two resources rather than one taking four sets, because rule 7 is about
  // the CONTROL: /admin/saml-attributes is its own page with its own forms, and
  // an API that answered for it under a name promising tokens would leave a
  // caller reading `getClaims` to find out what an assertion will carry.
  // -------------------------------------------------------------------------
  { method: 'GET', path: BASE + '/saml-attributes', tag: 'Custom SAML ' +
      'attributes',
    operationId: 'getSamlAttributes',
    summary: 'The custom attributes every new SAML assertion will carry',
    description: 'The two SAML sets — SAML 2.0 Attribute and SAML 1.1 ' +
                 'Attribute (WS-Federation) — with the rules that govern ' +
                 'them. The 2.0 set reaches every assertion WS-Trust issues ' +
                 'with a 2.0 token type; the 1.1 set reaches the 1.1 ones, ' +
                 'which is what WS-Federation\'s passive requestor profile ' +
                 'carries, so the 1.1 half is the one a browser sign-in ' +
                 'exercises.\n\nEach set has TWO HALVES and they are ' +
                 'configured by different operations. `claims` are TYPED: a ' +
                 'name and a value somebody wrote, the same for everybody ' +
                 'except where a ${placeholder} carries the sign-in. ' +
                 '`attributes` are LDAP ATTRIBUTE TYPES chosen from ' +
                 '`attributeCatalogue`, whose value is read off that ' +
                 'person\'s entry under ou=users — so an `ldapmodify` ' +
                 'changes the next assertion, and an LDAP client and a SAML ' +
                 'relying party pointed at this service are shown the same ' +
                 'person.\n\nTHERE IS NO `reservedJwtClaims` HERE and the ' +
                 'absence is the answer rather than an omission: that list ' +
                 'is enforced for a JWT set only, because an assertion ' +
                 'attribute called `exp` collides with nothing. ' +
                 '`defaultSaml11Namespace` is the rule that IS this ' +
                 'family\'s — the namespace a 1.1 attribute gets when the ' +
                 'call does not name one.\n\nThe two JWT sets are at GET ' +
                 '/admin-api/claims. One store behind both, and one audit ' +
                 'row per change whichever door made it.',
    mirrors: 'GET /admin/saml-attributes',
    parameters: [
      { name: 'user', in: 'query', required: false,
        schema: { type: 'string', default: 'alice' },
        description: 'Whose attribute values to preview. Defaults to a ' +
                     'person the directory holds from startup, so the ' +
                     'preview shows real values on a fresh process. Somebody ' +
                     'with no entry gets generated values — the same ' +
                     'invented person every time, seeded from the name — and ' +
                     '`preview.entryFound` says which of the two happened. ' +
                     'It is the same parameter, the same cap and the same ' +
                     'default GET /admin-api/claims takes, deliberately: the ' +
                     'two replies preview one person unless asked otherwise.' }
    ],
    responseDescription: 'The two SAML sets, the attribute catalogue and the ' +
                         'preview.',
    responseSchema: { $ref: '#/components/schemas/SamlAttributeSets' },
    handler: function (req, res) {
      log.debug("Entering the management API SAML attributes endpoint.");
      sendJson(res, 200,
               adminViews.samlAttributesJson(adminViews.claimsPreviewUser(
                   req.query)));
      log.debug("Leaving the management API SAML attributes endpoint.");
    } },

  { method: 'POST', route: BASE + '/saml-attributes/:action',
    tag: 'Custom SAML attributes',
    mirrors: 'POST /admin/saml-attributes',
    handler: function (req, res) {
      log.debug("Entering the management API SAML attributes action endpoint.");
      const body = parseBody(req);
      const names = namesOf(req, body, 'attribute', 'attributes');
      const result = adminActions.claimsAction(withAction(req, body), names,
                                        stats.SAML_CLAIM_SET_IDS);
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0043');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API SAML attributes action endpoint.");
    },
    actions: claimSetActions(SAML_CLAIM_FAMILY) },

  { method: 'GET', path: BASE + '/credential-claims', tag: 'Credential claims',
    operationId: 'getCredentialClaims',
    summary: 'Which claims an issued Verifiable Credential carries',
    description: 'The catalogue, what is selected from it, and a preview of ' +
                 'what one person\'s credential would carry if it were ' +
                 'issued now.\n\nThe catalogue is of LDAP ATTRIBUTE TYPES ' +
                 'and not of claim names, because this service has a ' +
                 'directory and a claim whose value nothing else can see is ' +
                 'half a demonstration: the value of a claim is the value on ' +
                 'that person\'s entry under ou=users.',
    mirrors: 'GET /admin/vc',
    parameters: [
      { name: 'user', in: 'query', required: false,
        schema: { type: 'string', default: 'alice' },
        description: 'Whose credential to preview. Defaults to a person the ' +
                     'directory holds from startup, so the preview shows ' +
                     'real values on a fresh process.' }
    ],
    responseDescription: 'The catalogue, the selection and the preview.',
    responseSchema: { $ref: '#/components/schemas/CredentialClaims' },
    handler: function (req, res) {
      log.debug("Entering the management API credential-claims endpoint.");
      sendJson(res, 200,
               adminViews.vcJson(adminViews.vcPreviewUser(req.query)));
      log.debug("Leaving the management API credential-claims endpoint.");
    } },

  { method: 'POST', route: BASE + '/credential-claims/:action',
    tag: 'Credential claims',
    mirrors: 'POST /admin/vc',
    handler: function (req, res) {
      log.debug("Entering the management API credential-claims action.");
      const body = parseBody(req);
      const names = namesOf(req, body, 'attribute', 'attributes');
      const result = adminActions.vcAction(withAction(req, body), names);
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0044');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API credential-claims action.");
    },
    actions: [
      { action: 'select', operationId: 'selectCredentialClaims',
        summary: 'Set the whole credential claim set',
        description: 'Replaces the selection, and then SWEEPS THE DIRECTORY: ' +
                     'every person under ou=users gains the selected ' +
                     'attributes they are missing, invented from their ' +
                     'username — deterministically, so one username is one ' +
                     'invented person across restarts. An attribute already ' +
                     'there is never overwritten, so an operator\'s ' +
                     '`ldapmodify` and the seeded people\'s own names ' +
                     'survive.\n\nThe sweep is the point rather than a side ' +
                     'effect: without it, selecting `title` would change ' +
                     'every future credential and change nothing an LDAP ' +
                     'client could see, and the two halves of this service ' +
                     'would stop describing the same people. The reply\'s ' +
                     '`sweep` says what it did, including when there was no ' +
                     'directory to do it to.\n\nThe issuer METADATA is built ' +
                     'from this same selection, so what is advertised cannot ' +
                     'drift from what is minted.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            attributes: { type: 'array', items: { type: 'string' },
                          description: 'LDAP attribute type names, from the ' +
                                       'catalogue.' }
          },
          required: ['attributes'],
          examples: [{ attributes: ['givenName', 'sn', 'mail'] }],
          additionalProperties: false
        },
        responseDescription: 'What is selected now, what changed, and what ' +
                             'the sweep did.' },

      { action: 'add', operationId: 'addCredentialClaim',
        summary: 'Add one attribute to the credential claim set',
        description: 'Sweeps the directory afterwards, as `select` does. An ' +
                     'attribute already selected is refused rather than ' +
                     'treated as done.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            attribute: { type: 'string' },
            name: { type: 'string',
                    description: 'An alias for `attribute`; `vcAction()` ' +
                                 'reads `body.attribute || body.name`, so ' +
                                 'both spellings have always worked and only ' +
                                 'one was published.' }
          },
          anyOf: [{ required: ['attribute'] }, { required: ['name'] }],
          examples: [{ attribute: 'title' }],
          additionalProperties: false
        },
        responseDescription: 'What is selected now, and what the sweep did.' },

      { action: 'remove', operationId: 'removeCredentialClaim',
        summary: 'Remove one attribute from the credential claim set',
        description: 'Future credentials stop carrying it. What was already ' +
                     'written onto a directory entry stays there — nothing ' +
                     'here deletes an attribute value, because an operator ' +
                     'may have set it.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            attribute: { type: 'string' },
            name: { type: 'string',
                    description: 'An alias for `attribute`; `vcAction()` ' +
                                 'reads `body.attribute || body.name`, so ' +
                                 'both spellings have always worked and only ' +
                                 'one was published.' }
          },
          anyOf: [{ required: ['attribute'] }, { required: ['name'] }],
          examples: [{ attribute: 'title' }],
          additionalProperties: false
        },
        responseDescription: 'What is selected now.' },

      { action: 'defaults', operationId: 'resetCredentialClaims',
        summary: 'Back to the default selection',
        description: 'The attributes this issuer carried before the page ' +
                     'existed. Sweeps afterwards, as `select` does.',
        requestBodyRequired: false,
        requestBody: { type: 'object', properties: {}, examples: [{}],
                       additionalProperties: false },
        responseDescription: 'The default selection, and what the sweep did.' },

      { action: 'populate', operationId: 'populateDirectory',
        summary: 'Sweep the directory without changing the selection',
        description: 'For a directory that gained entries after the last ' +
                     'change — or one that was not running when it happened. ' +
                     'Running it twice does nothing the second time, because ' +
                     'the sweep only fills what is absent.',
        requestBodyRequired: false,
        requestBody: { type: 'object', properties: {}, examples: [{}],
                       additionalProperties: false },
        responseDescription: 'What the sweep examined and changed.' }
    ] },

  { method: 'GET', path: BASE + '/verifier-request', tag: 'Verifier request',
    operationId: 'getVerifierRequest',
    summary: 'What the mock OID4VP Verifier asks a wallet for',
    description: 'The claims, the credential format, and the `dcql_query` ' +
                 'they build — from the function that builds the real one, ' +
                 'so this is the next Authorization Request rather than a ' +
                 'description of it.\n\nEach catalogue row also says whether ' +
                 'the ISSUER currently mints that claim. The two settings ' +
                 'are deliberately separate and their disagreeing is a state ' +
                 'to report rather than one to prevent: a Verifier asking ' +
                 'for a claim nothing here issues is the only way to ' +
                 'exercise what a wallet does with a request it cannot ' +
                 'satisfy.',
    mirrors: 'GET /admin/vc-verifier-config',
    responseDescription: 'The request as it now stands.',
    responseSchema: { $ref: '#/components/schemas/VerifierRequest' },
    handler: function (req, res) {
      log.debug("Entering the management API verifier-request endpoint.");
      sendJson(res, 200, adminViews.vpConfigJson());
      log.debug("Leaving the management API verifier-request endpoint.");
    } },

  { method: 'POST', route: BASE + '/verifier-request/:action',
    tag: 'Verifier request',
    mirrors: 'POST /admin/vc-verifier-config',
    handler: function (req, res) {
      log.debug("Entering the management API verifier-request action.");
      const body = parseBody(req);
      const names = namesOf(req, body, 'claim', 'claims');
      const result = adminActions.vpConfigAction(withAction(req, body), names);
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0045');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API verifier-request action.");
    },
    actions: [
      { action: 'select', operationId: 'selectRequestedClaims',
        summary: 'Set the whole list of requested claims',
        description: 'Reaches the wire as the `claims` member of the next ' +
                     'Authorization Request\'s dcql_query.\n\nAn EMPTY array ' +
                     'is a legitimate call and not an empty form: DCQL reads ' +
                     'an absent `claims` member as the WHOLE credential, so ' +
                     'requesting nothing asks the wallet for everything — ' +
                     'the opposite of what selective disclosure is for, ' +
                     'which is exactly why being able to ask for it ' +
                     'matters.\n\nThe claims a request asks for are FROZEN ' +
                     'onto the transaction when it is built, so a change ' +
                     'here never re-judges a presentation already in flight.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            claims: { type: 'array', items: { type: 'string' },
                      description: 'Top-level claim names. A credential ' +
                                   'carries one Disclosure per top-level ' +
                                   'claim, so `address` is one unit however ' +
                                   'many attributes feed it.' }
          },
          required: ['claims'],
          examples: [{ claims: ['given_name', 'family_name'] }],
          additionalProperties: false
        },
        responseDescription: 'What is requested now, and what changed.' },

      { action: 'add', operationId: 'addRequestedClaim',
        summary: 'Ask for one more claim',
        description: 'A claim NOT in the catalogue is accepted, and is the ' +
                     'point rather than a loose end: nothing here issues it, ' +
                     'so it is the only way to exercise what a wallet does ' +
                     'with a request it cannot satisfy. The reply says so, ' +
                     'and the Verifier will then refuse the presentation on ' +
                     'the "Requested claims" check and name it.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            claim: { type: 'string' },
            name: { type: 'string',
                    description: 'An alias for `claim`; `vpConfigAction()` ' +
                                 'reads `body.claim || body.name`, so both ' +
                                 'spellings have always worked and only one ' +
                                 'was published.' }
          },
          anyOf: [{ required: ['claim'] }, { required: ['name'] }],
          examples: [{ claim: 'birthdate' }],
          additionalProperties: false
        },
        responseDescription: 'What is requested now.' },

      { action: 'remove', operationId: 'removeRequestedClaim',
        summary: 'Stop asking for one claim',
        description: 'A claim that is not being asked for is refused rather ' +
                     'than treated as done.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            claim: { type: 'string' },
            name: { type: 'string',
                    description: 'An alias for `claim`; `vpConfigAction()` ' +
                                 'reads `body.claim || body.name`, so both ' +
                                 'spellings have always worked and only one ' +
                                 'was published.' }
          },
          anyOf: [{ required: ['claim'] }, { required: ['name'] }],
          examples: [{ claim: 'birthdate' }],
          additionalProperties: false
        },
        responseDescription: 'What is requested now.' },

      { action: 'defaults', operationId: 'resetRequestedClaims',
        summary: 'Back to what this process started with',
        description: 'OID4VP_CLAIMS where that was set in the environment, ' +
                     'and given_name, family_name where it was not.',
        requestBodyRequired: false,
        requestBody: { type: 'object', properties: {}, examples: [{}],
                       additionalProperties: false },
        responseDescription: 'The startup request.' },

      { action: 'format', operationId: 'setRequestFormat',
        summary: 'Set the credential format a request asks in',
        description: 'Applies to a request that does not name a format ' +
                     'itself; the three format links on the Verifier page ' +
                     'name one explicitly and are unaffected.\n\nThe DCQL ' +
                     'PATH DIFFERS BY FORMAT and the reply shows it: top ' +
                     'level for dc+sd-jwt, under credentialSubject for ' +
                     'jwt_vc_json, and under the vendored JSON-LD context\'s ' +
                     'own term for ldp_vc — which cannot carry every claim ' +
                     'at all.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            format: { type: 'string',
                      description: 'A format id. `GET ' +
                                   '/admin-api/verifier-request` lists them ' +
                                   'under `formats`.' },
            name: { type: 'string',
                  description: 'An alias for `claim`; `vpConfigAction()` ' +
                               'reads `body.claim || body.name`, so both ' +
                               'spellings have always worked and only one ' +
                               'was published.' },
            name: { type: 'string',
                  description: 'An alias for `claim`; `vpConfigAction()` ' +
                               'reads `body.claim || body.name`, so both ' +
                               'spellings have always worked and only one ' +
                               'was published.' }
          },
          required: ['format'],
          examples: [{ format: 'dc+sd-jwt' }],
          additionalProperties: false
        },
        responseDescription: 'The format now in force.' }
    ] },

  // The authorization server profiles — what each discovery document publishes.
  //
  // RFC 9700 section 2.6 asks a server to publish its metadata so that clients
  // stop hard-coding security capabilities. These operations decide what the
  // published document SAYS, per authorization server, which is the other side
  // of that: a client which reads the metadata can be shown reading it, and one
  // which does not can be shown not to.
  //
  // ANY MEMBER IS ACCEPTED, including one this service has never heard of. That
  // is the difference between this and every other resource here — the
  // applications registry REFUSES an attribute outside its schema, because that
  // schema is a published contract about what an entry carries. This has no
  // schema on purpose: publishing something a client did not expect is half the
  // point of a mock.
  // ---------------------------------------------------------------------
  // THE SAML 2.0 IDENTITY PROVIDER.
  //
  // The resource a caller needs before it can drive the Web Browser SSO
  // profile at all, and the reason is the feature itself: the metadata is PER
  // SERVICE PROVIDER, so "the metadata URL" is not a constant a test can
  // hard-code — it is a per-entityID fact this reply carries. A test that
  // guessed the slug rule would be a second implementation of it.
  // ---------------------------------------------------------------------
  // ---------------------------------------------------------------------
  // FEDERATION. Rule 7, and it pays here more than anywhere except /rbac:
  // this API is NOT gated, so these operations are how a TEST configures a
  // federation partner with no browser and no cookie jar — which is the only
  // way the feature can be exercised automatically at all.
  //
  // The consequence is the same one mgmt-api/CLAUDE.md states for /rbac and it
  // is worth restating here because what is at stake is different: anybody who
  // can reach this port can configure a federation partner, which means
  // configuring a signing certificate this service will then believe. That is
  // not a new hole — the same caller can already grant themselves both admin
  // roles and mint a token for any username — but it is the sharpest form of
  // it, and the honest sentence is better than the omission.
  // ---------------------------------------------------------------------
  { method: 'GET', path: BASE + '/federation', tag: 'Federation',
    operationId: 'getFederationRelationships',
    summary: 'Every federation relationship, in either direction',
    description: 'This service can be EITHER END of a federation ' +
                 'relationship, in five protocols: SAML 2.0, SAML 1.1, ' +
                 'WS-Federation 1.2, OpenID Connect and OAuth 2.0.\n\n**This ' +
                 'is the one feature here that has to be configured before ' +
                 'it will do anything.** Everywhere else this service ' +
                 'accepts what it is given — any username, any client_id, ' +
                 'any entityID, any LDAP bind. It cannot do that at an ' +
                 'assertion consumer service: what arrives there is an ' +
                 'unauthenticated HTTP request claiming to be a person, and ' +
                 'the session it produces is the same one ' +
                 '`/oauth2/authorize`, `/wsfed`, `/saml2` and the admin ' +
                 'console all read. So a relationship is created DISABLED, ' +
                 'and an assertion is refused unless it verifies against the ' +
                 'certificate configured on it.\n\n**The gate is on the ' +
                 'SIGNER, not on the subject.** Once a relationship is ' +
                 'enabled and configured, everything downstream is as ' +
                 'permissive as the rest of this service: any username in ' +
                 'the assertion is accepted, any attribute is mapped, and a ' +
                 'directory entry is created for the ' +
                 'person.\n\n`?relationship=<id>` returns one of them, with ' +
                 'everything it holds and the URLs to configure at the ' +
                 'partner. It answers 200 with `found: false` for an id that ' +
                 'is not registered.\n\nThis resource holds nothing: every ' +
                 'row is an entry under `ou=federations`, the same one an ' +
                 '`ldapsearch` reads.',
    mirrors: 'GET /admin/federation',
    parameters: [
      { name: 'relationship', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'One relationship, by its id.' },
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Filter the list by id, name, partner or application.' },
      { name: 'role', in: 'query', required: false,
        schema: { type: 'string',
                  enum: ['service-provider', 'identity-provider'] },
        description: 'Only the relationships in which this service takes ' +
                     'that role. `service-provider` is the direction that ' +
                     'CONSUMES somebody else\'s assertions.' }
    ].concat(pagingParameters()),
    responseDescription: 'The relationships with the paging that found them, ' +
                         'or one of them with its endpoints, its fields and ' +
                         'what has crossed it.',
    responseSchema: { $ref: '#/components/schemas/FederationRelationshipList' },
    handler: function (req, res) {
      log.debug("Entering the management API federation endpoint.");
      sendJson(res, 200, adminViews.federationJson(req));
      log.debug("Leaving the management API federation endpoint.");
    } },

  { method: 'POST', route: BASE + '/federation/:action',
    tag: 'Federation',
    mirrors: 'POST /admin/federation',
    handler: function (req, res) {
      log.debug("Entering the management API federation action endpoint.");
      const body = parseBody(req);
      const result = adminActions.federationAction(withAction(req, body));
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0046');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API federation action endpoint.");
    },
    actions: [
      { action: 'create', operationId: 'createFederationRelationship',
        summary: 'Register a federation relationship',
        description: 'It is created **DISABLED**, whatever this request ' +
                     'says, and nothing about it does anything until ' +
                     '`enable` is called. That is the one place this ' +
                     'operation overrides its input, and it is deliberate: a ' +
                     'partner that half-exists and silently accepts ' +
                     'assertions is the failure this whole register is ' +
                     'arranged to prevent, so enabling is a second act that ' +
                     'says the configuration is finished.\n\n**ONE ' +
                     'RELATIONSHIP IS ONE DIRECTION.** A partner this ' +
                     'service both consumes from and asserts to is two ' +
                     'relationships with two ids, because everything that ' +
                     'configures one differs by direction.\n\nThe reply ' +
                     'carries `readiness.missing` — the fields this protocol ' +
                     'and role still need — so a caller can go straight on ' +
                     'to `set` for each of them without knowing the schema ' +
                     'in advance.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            id: { type: 'string',
                  description: 'The key, the RDN and a URL segment. It has ' +
                               'to start with a letter or a digit and hold ' +
                               'only letters, digits, dot, dash and ' +
                               'underscore, up to 63 characters.' },
            role: { type: 'string',
                    enum: ['service-provider', 'identity-provider'],
                    description: 'Which end THIS SERVICE is. ' +
                                 '`service-provider` means a foreign ' +
                                 'identity provider authenticates the person ' +
                                 'and this service consumes what it issues.' },
            protocol: { type: 'string',
                        enum: ['saml2', 'saml11', 'wsfed', 'oidc', 'oauth2'],
                        description: 'The protocol the relationship runs in.' },
            name: { type: 'string',
                    description: 'What to call the partner on a page. The id ' +
                                 'is the name when this is omitted.' },
            peer: { type: 'string',
                    description: 'The partner\'s own identifier — a SAML ' +
                                 'entityID, an OpenID Connect issuer, a ' +
                                 'WS-Federation wtrealm. On a ' +
                                 'service-provider-side relationship it is ' +
                                 'CHECKED: an assertion whose issuer is not ' +
                                 'this string is refused even when the ' +
                                 'signature verifies.' },
            application: { type: 'string',
                           description: 'On an identity-provider-side ' +
                                        'relationship only: the identifier ' +
                                        'of the partner\'s entry in ' +
                                        '`ou=applications`. Its entityID, ' +
                                        'redirect URIs and certificate stay ' +
                                        'THERE, where every protocol module ' +
                                        'reads them — this register holds a ' +
                                        'pointer and not a copy.' }
          },
          required: ['id', 'role', 'protocol'],
          examples: [{ id: 'partner-a', role: 'service-provider',
                       protocol: 'saml2', name: 'Partner A',
                       peer: 'https://idp.partner.example/saml' }],
          additionalProperties: false
        },
        responseDescription: 'The relationship as created, and what it still ' +
                             'needs before it can be enabled usefully.' },

      { action: 'set', operationId: 'setFederationField',
        summary: 'Set one single-valued field on a relationship',
        description: 'The field must be one of this relationship\'s — a ' +
                     'field belonging to the other ROLE is refused by name ' +
                     'rather than written and ignored, and so is one that ' +
                     'records what HAPPENED (the counters, the last ' +
                     'error).\n\n`fedId`, `fedRole` and `fedProtocol` are ' +
                     'refused too, and that is a third category rather than ' +
                     'an oversight: they are the relationship\'s identity, ' +
                     'and changing one would leave a SAML relationship ' +
                     'carrying a token endpoint. Delete it and make another ' +
                     '— there is no state to lose but the counters.\n\n`GET ' +
                     '/admin-api/federation?relationship=<id>` returns ' +
                     '`editable`, which is exactly the list this operation ' +
                     'accepts, so a caller need not guess.\n\nThe reply ' +
                     'always carries `readiness`, so setting the last ' +
                     'missing field tells you it was the last one.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'The relationship.' },
            field: { type: 'string',
                     description: 'The attribute name, e.g. `fedSsoUrl`, ' +
                                  '`fedSigningCertificate`, `fedClientId`.' },
            value: { type: 'string',
                     description: 'The new value. An empty string clears it. ' +
                                  '`fedSigningCertificate` is normalised — ' +
                                  'PEM armour and whitespace are stripped, ' +
                                  'because what the schema holds is the ' +
                                  'base64 DER a ds:X509Certificate carries.' }
          },
          required: ['id', 'field', 'value'],
          examples: [{ id: 'partner-a', field: 'fedSsoUrl',
                       value: 'https://idp.partner.example/sso' }],
          additionalProperties: false
        },
        responseDescription: 'The relationship as it now stands, and whether ' +
                             'it is ready.' },

      { action: 'add-value', operationId: 'addFederationValue',
        summary: 'Add a value to a multi-valued field',
        description: 'Two fields take values: `fedAttributeMap` on a ' +
                     'service-provider-side relationship, and `fedRelease` ' +
                     'on an identity-provider-side ' +
                     'one.\n\n**`fedAttributeMap`** is written `<incoming ' +
                     'name>=<LDAP attribute>` and is split at the FIRST ' +
                     'equals sign — which matters, because an incoming name ' +
                     'can be a URL and a URL can hold one. It is only needed ' +
                     'for a partner\'s own inventions: the ordinary OpenID ' +
                     'Connect claims, the SAML `urn:oid:` names and the AD ' +
                     'FS claim URIs are mapped already.\n\n**`fedRelease`** ' +
                     'names an attribute or claim released to that partner, ' +
                     'and it can only REMOVE — from what /admin/claims, ' +
                     '/admin/saml-attributes and the groups claim would add, ' +
                     'and from nothing else. It cannot touch `sub`, `iss`, ' +
                     '`exp` or a NameID. **NO VALUES MEANS NO POLICY, not ' +
                     'release nothing**: adding the first value here is what ' +
                     'starts the filtering.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'The relationship.' },
            field: { type: 'string',
                     enum: ['fedAttributeMap', 'fedRelease', 'description'],
                     description: 'Which list.' },
            value: { type: 'string', description: 'The value to add.' }
          },
          required: ['id', 'field', 'value'],
          examples: [{ id: 'partner-a', field: 'fedAttributeMap',
                       value: 'http://partner.example/claims/dept=departmentNumber' }],
          additionalProperties: false
        },
        responseDescription: 'The relationship with the value added.' },

      { action: 'remove-value', operationId: 'removeFederationValue',
        summary: 'Remove one value from a multi-valued field',
        description: 'Refused if that value is not there, rather than ' +
                     'succeeding silently: a caller removing a mapping it ' +
                     'thinks exists wants to hear that it does not.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'The relationship.' },
            field: { type: 'string',
                     enum: ['fedAttributeMap', 'fedRelease', 'description'],
                     description: 'Which list.' },
            value: { type: 'string',
                     description: 'The value to remove, exactly as it stands.' }
          },
          required: ['id', 'field', 'value'],
          additionalProperties: false
        },
        responseDescription: 'The relationship with the value gone.' },

      { action: 'enable', operationId: 'enableFederationRelationship',
        summary: 'Turn a relationship on',
        description: 'The second, deliberate act. **It is allowed on a ' +
                     'relationship that is not fully configured**, and that ' +
                     'is not a gap: a half-configured partner is a state ' +
                     'somebody is passing through, and refusing to save it ' +
                     'would mean configuring everything in one request with ' +
                     'no way back. What happens in that state is that every ' +
                     'endpoint for the relationship REFUSES and says which ' +
                     'fields are missing — it never half-works — and the ' +
                     'reply to this operation says so too.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { id: { type: 'string',
                              description: 'The relationship.' } },
          required: ['id'],
          examples: [{ id: 'partner-a' }],
          additionalProperties: false
        },
        responseDescription:
          'The relationship, and whether it is now usable.' },

      { action: 'disable', operationId: 'disableFederationRelationship',
        summary: 'Turn a relationship off',
        description: 'A response arriving for a disabled relationship is ' +
                     'refused without being looked at, which is what ' +
                     'disabling is for. Nothing else is lost: the ' +
                     'configuration, the counters and the mappings all stay, ' +
                     'and the people it authenticated keep their directory ' +
                     'entries and their sessions.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { id: { type: 'string',
                              description: 'The relationship.' } },
          required: ['id'],
          additionalProperties: false
        },
        responseDescription: 'The relationship, now disabled.' },

      { action: 'delete', operationId: 'deleteFederationRelationship',
        summary: 'Delete a relationship',
        description: 'The entry goes and takes its recorded sign-ins with ' +
                     'it. **The PEOPLE it authenticated keep their entries ' +
                     'under `ou=users`** — nothing is ever deleted from ' +
                     'there — and any session they hold is unaffected until ' +
                     'it expires or is ended, which is what `POST ' +
                     '/admin-api/logout` is for.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { id: { type: 'string',
                              description: 'The relationship.' } },
          required: ['id'],
          additionalProperties: false
        },
        responseDescription: 'Confirmation, and what was deliberately left ' +
                             'behind.' }
    ] },

  { method: 'GET', path: BASE + '/saml2', tag: 'SAML 2.0',
    operationId: 'getSaml2ServiceProviders',
    summary: 'Every SAML 2.0 service provider, and the endpoints each is ' +
             'configured from',
    description: 'A full SAML 2.0 identity provider: HTTP Redirect and HTTP ' +
                 'POST for the AuthnRequest, and HTTP POST, HTTP Redirect or ' +
                 'HTTP Artifact for the Response, with a SOAP artifact ' +
                 'resolution service behind the third.\n\n**Every service ' +
                 'provider gets its own identity provider metadata** — a ' +
                 'distinct entityID and its own endpoints — and **a document ' +
                 'is minted for any entityID asked for**, so nothing has to ' +
                 'be provisioned before a service provider can be pointed at ' +
                 'this service. That is why `metadataUrl` is on every row ' +
                 'rather than being one constant.\n\nThis resource holds ' +
                 'nothing: every row is an entry in `ou=applications`, the ' +
                 'same one `GET /admin-api/applications` ' +
                 'reports.\n\n`?sp=<entityID>` returns one of them, with ' +
                 'what has been recorded about it — and answers 200 with ' +
                 '`found: false` for an entityID that is not registered, ' +
                 'whose metadata is still served and whose AuthnRequest ' +
                 'would still be answered.',
    mirrors: 'GET /admin/saml2',
    parameters: [
      { name: 'sp', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'One service provider, by its entityID.' }
    ].concat(pagingParameters()),
    responseDescription: 'The service providers with the paging that found ' +
                         'them, or one of them with its endpoints and its ' +
                         'record.',
    responseSchema: { $ref: '#/components/schemas/Saml2ServiceProviderList' },
    handler: function (req, res) {
      log.debug("Entering the management API SAML 2.0 endpoint.");
      // The layer decides list-or-detail off `?sp=` exactly as the page does.
      sendJson(res, 200, adminViews.saml2Json(req));
      log.debug("Leaving the management API SAML 2.0 endpoint.");
    } },

  { method: 'POST', route: BASE + '/saml2/:action',
    tag: 'SAML 2.0',
    mirrors: 'POST /admin/saml2',
    handler: function (req, res) {
      log.debug("Entering the management API SAML 2.0 action endpoint.");
      const body = parseBody(req);
      const result = adminActions.saml2Action(withAction(req, body));
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0047');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API SAML 2.0 action endpoint.");
    },
    actions: [
      { action: 'register', operationId: 'registerSaml2ServiceProvider',
        summary: 'Register a service provider by entityID',
        description: 'OPTIONAL, and it changes nothing about whether a ' +
                     'request is accepted: this identity provider accepts ' +
                     'any entityID, and the first AuthnRequest or metadata ' +
                     'fetch creates the entry anyway. What registering early ' +
                     'buys is a metadata document to hand somebody before ' +
                     'they have sent anything.\n\nIt is refused for an ' +
                     'entityID that is already in the registry — an ' +
                     'identifier names ONE application here whatever ' +
                     'protocol brought it, so the answer to "it is already ' +
                     'there" is to change what it holds rather than to ' +
                     'create it twice.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            sp: { type: 'string', description: 'The service provider\'s ' +
                                               'entityID.' }
          },
          required: ['sp'],
          examples: [{ sp: 'https://sp.example.com/saml' }],
          additionalProperties: false
        },
        responseDescription: 'The application entry, and where its metadata ' +
                             'is served.' },

      { action: 'set-logout-service', operationId: 'addSaml2LogoutService',
        summary: 'Declare where this service provider\'s LogoutResponse goes',
        description: 'A `<samlp:LogoutRequest>` CARRIES NO RETURN ADDRESS — ' +
                     'only SP metadata does, and this service does not ' +
                     'consume SP metadata. With nothing declared the profile ' +
                     'falls back to `saml2.defaultSingleLogoutService` and ' +
                     'then to the assertion consumer service URL that ' +
                     'service provider last used, WHICH IS A GUESS and is ' +
                     'logged as one. This is how to remove the guess.\n\nIt ' +
                     'writes `samlSingleLogoutService` on the application ' +
                     'entry, so an `ldapmodify` of the same attribute does ' +
                     'exactly this — two doors onto one value, not two stores.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            sp: { type: 'string', description: 'The service provider\'s ' +
                                               'entityID.' },
            value: { type: 'string', description: 'An absolute URL.' }
          },
          required: ['sp', 'value'],
          examples: [{ sp: 'https://sp.example.com/saml',
                       value: 'https://sp.example.com/saml/slo' }],
          additionalProperties: false
        },
        responseDescription: 'The application entry as it now stands.' },

      { action: 'remove-logout-service',
        operationId: 'removeSaml2LogoutService',
        summary: 'Take a logout return address off a service provider',
        description: 'The attribute holds a LIST, so values are removed by ' +
                     'name rather than the list being replaced. Removing the ' +
                     'last one puts the fallback back.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            sp: { type: 'string' },
            value: { type: 'string', description: 'The exact value to remove.' }
          },
          required: ['sp', 'value'],
          examples: [{ sp: 'https://sp.example.com/saml',
                       value: 'https://sp.example.com/saml/slo' }],
          additionalProperties: false
        },
        responseDescription: 'The application entry as it now stands.' },

      { action: 'set-signing-certificate',
        operationId: 'setSaml2SigningCertificate',
        summary: 'Record the certificate this service provider signs with',
        description: 'Base64 DER — PEM armour and whitespace are stripped, ' +
                     'because what the attribute holds is what a ' +
                     '`ds:X509Certificate` carries, and a PEM stored there ' +
                     'would be something no reader of it expects with ' +
                     'nothing to say so until the day one tried to use ' +
                     'it.\n\n**IT IS NOT CHECKED AGAINST ANYTHING.** This ' +
                     'service records whether an AuthnRequest was signed and ' +
                     'verifies no signature, which is the same posture it ' +
                     'takes to every credential — see `saml/CLAUDE.md`. This ' +
                     'is the material a verification would read the day one ' +
                     'is wanted, and it is public key material, so unlike a ' +
                     'client secret it is worth nothing to whoever reads ' +
                     'this directory. An empty value clears it.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            sp: { type: 'string' },
            value: { type: 'string', description: 'Base64 DER, or a PEM to ' +
                                                  'be stripped.' }
          },
          required: ['sp'],
          examples: [{ sp: 'https://sp.example.com/saml', value: 'MIIC...' }],
          additionalProperties: false
        },
        responseDescription: 'The application entry as it now stands.' }
    ] },

  { method: 'GET', path: BASE + '/saml11', tag: 'SAML 1.1',
    operationId: 'getSaml11RelyingParties',
    summary: 'Every SAML 1.1 relying party, and the endpoints each is ' +
             'configured from',
    description: 'A full SAML 1.1 identity provider: both browser profiles — ' +
                 'Browser/POST and Browser/Artifact — and the SAML responder ' +
                 'behind the second, which also answers AttributeQuery and ' +
                 'AuthenticationQuery and is therefore this service\'s ' +
                 'attribute authority.\n\n**IT IS NOT AN OLDER SPELLING OF ' +
                 '`GET /admin-api/saml2`.** SAML 1.1 has no request message, ' +
                 'so a relying party cannot identify itself in the protocol: ' +
                 '`identifier` comes from Shibboleth\'s `providerId` ' +
                 'parameter, from a scoped endpoint\'s path segment, or it ' +
                 'is GUESSED from the origin of the TARGET. It has no Single ' +
                 'Logout, so there is no logout service to declare, and no ' +
                 'request signature to record. It has an attribute ' +
                 'authority, which the 2.0 profile does not.\n\n**Every ' +
                 'relying party gets its own metadata document** and one is ' +
                 'minted for any identifier asked for, so nothing has to be ' +
                 'provisioned before a relying party can be pointed at this ' +
                 'service.\n\nThis resource holds nothing: every row is an ' +
                 'entry in `ou=applications`, the same one `GET ' +
                 '/admin-api/applications` reports — and the KIND is shared ' +
                 'with WS-Federation, because a relying party handed the ' +
                 'same assertion through the passive requestor profile is ' +
                 'the same application. `profiles` says which of the two ' +
                 'browser profiles it has actually used, and an empty list ' +
                 'means it has only ever been handed a 1.1 assertion through ' +
                 'another door.\n\n`?rp=<identifier>` returns one of them, ' +
                 'with what has been recorded about it — and answers 200 ' +
                 'with `found: false` for an identifier that is not ' +
                 'registered, whose metadata is still served and whose flow ' +
                 'would still be answered.',
    mirrors: 'GET /admin/saml11',
    parameters: [
      { name: 'rp', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'One relying party, by its identifier.' }
    ].concat(pagingParameters()),
    responseDescription: 'The relying parties with the paging that found ' +
                         'them, or one of them with its endpoints and its ' +
                         'record.',
    responseSchema: { $ref: '#/components/schemas/Saml11RelyingPartyList' },
    handler: function (req, res) {
      log.debug("Entering the management API SAML 1.1 endpoint.");
      sendJson(res, 200, adminViews.saml11Json(req));
      log.debug("Leaving the management API SAML 1.1 endpoint.");
    } },

  { method: 'POST', route: BASE + '/saml11/:action',
    tag: 'SAML 1.1',
    mirrors: 'POST /admin/saml11',
    handler: function (req, res) {
      log.debug("Entering the management API SAML 1.1 action endpoint.");
      const body = parseBody(req);
      const result = adminActions.saml11Action(withAction(req, body));
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0048');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API SAML 1.1 action endpoint.");
    },
    actions: [
      { action: 'register', operationId: 'registerSaml11RelyingParty',
        summary: 'Register a relying party by identifier',
        description: 'OPTIONAL, and it changes nothing about whether a flow ' +
                     'is accepted: this identity provider accepts any ' +
                     'identifier, and the first flow or metadata fetch ' +
                     'creates the entry anyway.\n\nIt buys two things here ' +
                     'rather than the one it buys on the SAML 2.0 side. A ' +
                     'metadata document to hand somebody before they have ' +
                     'sent anything — and **a NAME to put in `providerId`**, ' +
                     'which matters more in this protocol than in any other ' +
                     'here: with no name sent, the audience of the assertion ' +
                     'is guessed from the origin of the TARGET, and a ' +
                     'relying party expecting a different audience refuses ' +
                     'the assertion inside a signature check with nothing ' +
                     'saying why.\n\nIt is refused for an identifier already ' +
                     'in the registry — an identifier names ONE application ' +
                     'here whatever protocol brought it, and a WS-Federation ' +
                     'relying party taking 1.1 assertions is already one of ' +
                     'these.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            rp: { type: 'string', description: 'The relying party\'s ' +
                                               'identifier.' }
          },
          required: ['rp'],
          examples: [{ rp: 'urn:example:app' }],
          additionalProperties: false
        },
        responseDescription: 'The application entry, and where its metadata ' +
                             'is served.' }
    ] },

  { method: 'GET', path: BASE + '/authorization-servers',
    tag: 'Authorization ' +
      'servers',
    operationId: 'getAuthorizationServers',
    summary: 'Every authorization server profile, and what its document says',
    description: 'One process, several authorization servers. The path ' +
                 'component the two discovery shapes already carry — RFC ' +
                 '8414 section 3.1 INSERTS it after the well-known segment, ' +
                 'OpenID Connect Discovery section 4 APPENDS the well-known ' +
                 'segment to it — now selects a CONFIGURATION as well as an ' +
                 'issuer identifier.\n\n**A path nobody has configured ' +
                 'publishes the document this service always published**, so ' +
                 'nothing that worked before behaves differently.\n\nEvery ' +
                 'reply carries `drift`: the members whose published value ' +
                 'disagrees with what this service would publish, and the ' +
                 'removals that hide something real. A profile that lies is ' +
                 'often exactly what is wanted — it is how you find out ' +
                 'whether a client reads the metadata — but a mock that let ' +
                 'somebody publish a misleading document QUIETLY would be a ' +
                 'trap.\n\n`?profile=<id>` returns one of them with every ' +
                 'override, every removal and its drift.',
    mirrors: 'GET /admin/authorization-servers',
    parameters: [
      { name: 'profile', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'One profile, by the path component that selects it. ' +
                     'Answers 200 with `found: false` for one that is not ' +
                     'configured — whose discovery URLs still answer, with ' +
                     'this service\'s own document.' }
    ].concat(pagingParameters()),
    responseDescription: 'The profiles with the paging that found them, or ' +
                         'one profile with its overrides and drift.',
    responseSchema: { $ref: '#/components/schemas/AuthorizationServerList' },
    handler: function (req, res) {
      log.debug("Entering the management API authorization servers endpoint.");
      sendJson(res, 200, adminViews.authorizationServersJson(req));
      log.debug("Leaving the management API authorization servers endpoint.");
    } },

  { method: 'POST', route: BASE + '/authorization-servers/:action',
    tag: 'Authorization servers',
    mirrors: 'POST /admin/authorization-servers',
    handler: function (req, res) {
      log.debug("Entering the management API authorization servers action " +
                "endpoint.");
      const body = parseBody(req);
      const result = adminActions.asAction(withAction(req, body));
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0049');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API authorization servers action " +
                "endpoint.");
    },
    actions: [
      { action: 'create', operationId: 'createAuthorizationServer',
        summary: 'Add an authorization server profile',
        description: 'The `id` is a single URL path segment, because it has ' +
                     'to appear in a discovery URL without being escaped — ' +
                     'one that had to be escaped would be one nobody could ' +
                     'find again. A new profile has no overrides, so both ' +
                     'its documents say exactly what this service says about ' +
                     'itself, which is the right place to start from.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            id: { type: 'string',
                  description: '1-64 characters of letters, digits, dot, ' +
                               'dash, underscore or tilde, starting with a ' +
                               'letter or a digit.' },
            label: { type: 'string', description: 'Optional display name.' },
            description: { type: 'string', description: 'Optional note.' }
          },
          required: ['id'],
          examples: [{ id: 'tenant1', label: 'Tenant One',
                       description: 'advertises plain PKCE, to see what a ' +
                                    'client does' }],
          additionalProperties: false
        },
        responseDescription:
          'The profile and the two URLs it is published at.' },

      { action: 'set', operationId: 'setAuthorizationServerMember',
        summary: 'Publish a metadata member with a chosen value',
        description: 'The value is read as JSON first and as a plain string ' +
                     'if that fails, so `["S256"]` is a list, `false` is a ' +
                     'boolean and `https://example.com/token` is a ' +
                     'string.\n\n**Any member name is accepted**, including ' +
                     'one this service has never heard of; the catalogue in ' +
                     'the GET reply is help for whoever fills the form ' +
                     'rather than a constraint. A member that is also ' +
                     'removed stops being removed, or the call would appear ' +
                     'to do nothing.\n\nWhat this does NOT change is what ' +
                     'the endpoints do. Advertise ' +
                     '`code_challenge_methods_supported: ["plain"]` and the ' +
                     'token endpoint still verifies S256 — which is the ' +
                     'point, and is reported as drift rather than left to be ' +
                     'discovered.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            profile: { type: 'string', description: 'The profile id.' },
            member: { type: 'string',
                      description: 'Any metadata member name.' },
            value: { description: 'JSON if it parses as JSON, otherwise the ' +
                                  'string.' },
            id: { type: 'string',
                description: 'An alias for `profile`; `asAction()` reads ' +
                             '`body.profile || body.id`, so both spellings ' +
                             'have always worked and only one was published.' }
          },
          required: ['member'],
          anyOf: [{ required: ['profile'] }, { required: ['id'] }],
          examples: [{ profile: 'tenant1',
                       member: 'code_challenge_methods_supported',
                       value: ['S256'] }],
          additionalProperties: false
        },
        responseDescription: 'The profile as it now stands.' },

      { action: 'remove', operationId: 'removeAuthorizationServerMember',
        summary: 'Stop publishing a member at all',
        description: 'DIFFERENT FROM `reset`, and the difference is the ' +
                     'reason both exist: reset undoes an override and this ' +
                     'publishes an ABSENCE. A client that cannot find ' +
                     '`code_challenge_methods_supported` does not learn that ' +
                     'PKCE is unavailable — it learns nothing, and RFC 9700 ' +
                     'section 2.6 is entirely about that difference.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            profile: { type: 'string' },
            member: { type: 'string' },
            id: { type: 'string',
                description: 'An alias for `profile`; `asAction()` reads ' +
                             '`body.profile || body.id`, so both spellings ' +
                             'have always worked and only one was published.' }
          },
          required: ['member'],
          anyOf: [{ required: ['profile'] }, { required: ['id'] }],
          examples: [{ profile: 'tenant1',
                       member: 'code_challenge_methods_supported' }],
          additionalProperties: false
        },
        responseDescription: 'The profile as it now stands.' },

      { action: 'reset', operationId: 'resetAuthorizationServerMember',
        summary: 'Put one member back to what this service publishes',
        description: 'Undoes an override or a removal for a single member, ' +
                     'leaving the rest of the profile alone.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            profile: { type: 'string' },
            member: { type: 'string' },
            id: { type: 'string',
                description: 'An alias for `profile`; `asAction()` reads ' +
                             '`body.profile || body.id`, so both spellings ' +
                             'have always worked and only one was published.' }
          },
          required: ['member'],
          anyOf: [{ required: ['profile'] }, { required: ['id'] }],
          examples: [{ profile: 'tenant1', member: 'token_endpoint' }],
          additionalProperties: false
        },
        responseDescription: 'The profile as it now stands.' },

      { action: 'delete', operationId: 'deleteAuthorizationServer',
        summary: 'Delete a profile',
        description: 'The two discovery URLs go on answering — with this ' +
                     'service\'s own document and the issuer taken from the ' +
                     'path — because an unconfigured path component has ' +
                     'always been served that way rather than 404\'d.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            profile: { type: 'string' },
            id: { type: 'string',
                  description: 'An alias for `profile`; `asAction()` reads ' +
                               '`body.profile || body.id`, so both spellings ' +
                               'have always worked and only one was ' +
                               'published.' }
          },
          anyOf: [{ required: ['profile'] }, { required: ['id'] }],
          examples: [{ profile: 'tenant1' }],
          additionalProperties: false
        },
        responseDescription: 'A message saying what still answers.' }
    ] },

  // The application registry, read and written.
  //
  // The write half is NOT a third store beside the protocol endpoints and LDAP:
  // every action below calls a function in applications.js which does the same
  // read-modify-write against the same ou=applications entries, so a form post
  // and an ldapmodify are one act arriving by two routes. That is what keeps
  // the one-store rule intact with three ways in.
  //
  // What may be changed is DECLARED and not DERIVED — configuration, which is
  // what RFC 9700 mode reads, but never the counters or the sightings, which
  // are what happened. The line is drawn by applications.js's EDITABLE table,
  // so this file offers no opinion about it and the console's selects are built
  // from the same rows these actions validate against.
  { method: 'GET', path: BASE + '/applications', tag: 'Applications',
    operationId: 'getApplications',
    summary: 'Every application this service has been asked about, filtered ' +
             'and paged',
    description: 'The other side of /admin-api/users. That resource lists ' +
                 'every identity that has authenticated here; this lists ' +
                 'what they authenticated TO — every OAuth client, OpenID ' +
                 'Connect relying party, SAML 2.0 or 1.1 service provider, ' +
                 'WS-Federation application, WS-Trust relying party, ' +
                 'OpenID4VP verifier and Kerberos service.\n\n**The entries ' +
                 'ARE the registry.** They live under `ou=applications` in ' +
                 'the embedded LDAP directory and nothing caches them, so an ' +
                 '`ldapmodify` is visible here on the next call — and ' +
                 'changes what RFC 9700 mode enforces at the same moment. ' +
                 'The RFC 7591 client registrations are those entries ' +
                 'too.\n\n**One entry per identifier, whatever protocol ' +
                 'brought it.** The key is the identifier exactly as it ' +
                 'arrived, so an application appearing under one name in two ' +
                 'protocols is one row with two `kinds` rather than two ' +
                 'rows.\n\n`?application=<id>` returns ONE of them with ' +
                 'every attribute of its directory entry and what the ' +
                 'published schema says each attribute is; that reply pages ' +
                 'its attribute list under `attributesPage` rather than ' +
                 '`page`, which is the convention for a reply holding a list ' +
                 'that is not the top-level one.\n\n**Two attributes hold ' +
                 'credentials in the clear** — `oauthClientSecret` and ' +
                 '`appRegistrationAccessToken` — for the reason GET ' +
                 '/krb5/principals prints the Kerberos passwords. In RFC ' +
                 '9700 mode that secret is CHECKED, so anyone who can reach ' +
                 'this endpoint can authenticate as that client.',
    mirrors: 'GET /admin/applications',
    parameters: [
      { name: 'application', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'One application, by its identifier exactly — the ' +
                     'client_id, wtrealm, AppliesTo, entityID or service ' +
                     'principal name. Answers 200 with `found: false` for ' +
                     'one this service has never accepted, which is a ' +
                     'different fact from one it has refused: an entry ' +
                     'appears when an identifier is ACCEPTED, so a client ' +
                     'whose every request was turned away has none.' },
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the identifier or the name, ' +
                     'case-insensitive. Ignored when `application` is given.' },
      { name: 'kind', in: 'query', required: false,
        schema: { type: 'string',
                  enum: ['oauth2-client', 'oidc-relying-party',
                         'saml2-service-provider', 'saml11-relying-party',
                         'wsfed-relying-party', 'wstrust-relying-party',
                         'oid4vp-verifier', 'kerberos-service'] },
        description: 'One kind. A record carrying SEVERAL matches on any of ' +
                     'them — an OAuth client that asked for the openid scope ' +
                     'is also a relying party — so these are not disjoint ' +
                     'sets and the counts in the reply\'s `kinds` member do ' +
                     'not sum to the total.' },
      { name: 'attributesPage', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Which page of the attribute list, on the ' +
                     '`?application=` reply only. Named rather than the bare ' +
                     '`page` because it moves a list inside the reply rather ' +
                     'than the reply itself.' }
    ].concat(pagingParameters()),
    responseDescription: 'The matching applications with the paging that ' +
                         'found them, or one application with its directory ' +
                         'entry when `application` was given.',
    responseSchema: { $ref: '#/components/schemas/ApplicationList' },
    handler: function (req, res) {
      log.debug("Entering the management API applications endpoint.");
      sendJson(res, 200, adminViews.applicationsJson(req));
      log.debug("Leaving the management API applications endpoint.");
    } },

  // WHAT A CREATE MAY SAY, read off the service. Rule 7 asks for an operation
  // per console page and this is /admin/applications/new's — but it earns its
  // place beyond the parity, because what it answers is the two CLOSED
  // VOCABULARIES `create` validates against: the eight kinds and the fourteen
  // protocol families, each with what it means. A caller that reads this cannot
  // construct a create the service will refuse, which is the property
  // editableAttributes() gives the console's two selects and this gives an API
  // client.
  //
  // THERE IS NO POST BESIDE IT, and that is rule 7 read exactly rather than by
  // shape. The rule is about CONTROLS: that page's one control posts
  // `action=create` to /admin/applications, so the operation mirroring it is
  // `createApplication` below and already exists. A second create here would be
  // two operations over one function, which is the thing the parity rule is
  // trying to prevent rather than an instance of it.
  { method: 'GET', path: BASE + '/applications/new', tag: 'Applications',
    operationId: 'getNewApplicationForm',
    summary: 'The vocabulary a new application may be created with, and ' +
             'where it would land',
    description: 'The eight KINDS and the fourteen PROTOCOL FAMILIES a ' +
                 'create takes, each with what it means, the FIELDS the ' +
                 'console\'s form is drawn from (`declarations` — the ' +
                 'per-protocol identifiers and the redirect URIs, deduped by ' +
                 'attribute and each naming the families it serves), plus ' +
                 'the container DN a new entry would be created under and ' +
                 'how many that container will hold.\n\n**It creates ' +
                 'nothing** — the create is `POST ' +
                 '/admin-api/applications/create`. This is the list that ' +
                 'call validates against, published so that a caller learns ' +
                 'what it may send from the service rather than from a copy ' +
                 'of the list in a document.\n\n**The container is THIS ' +
                 'REALM\'S.** The embedded directory is per trust realm, so ' +
                 '`/realm/acme/admin-api/applications/new` answers with ' +
                 'acme\'s `ou=applications` and an application created there ' +
                 'is invisible to every other realm — including in an ' +
                 '`ldapsearch`, which reaches it only under that realm\'s ' +
                 'base DN.\n\n**Declaring a protocol family grants and ' +
                 'refuses nothing.** No endpoint in this service reads ' +
                 '`appAllowedProtocol`: an application declared for SAML 2.0 ' +
                 'alone is still issued an access token. It is a record of ' +
                 'intent on the entry, and it is deliberately not a ' +
                 'permission — a mock that refused a protocol would remove a ' +
                 'test case rather than add one. The configuration that DOES ' +
                 'take effect is in `editable`.',
    mirrors: 'GET /admin/applications/new',
    responseDescription: 'The two vocabularies, the fields a create may ' +
                         'carry, the container and the realm.',
    responseSchema: { $ref: '#/components/schemas/NewApplicationForm' },
    handler: function (req, res) {
      log.debug("Entering the management API new-application endpoint.");
      // STRAIGHT TO THE LAYER (2026-09-12). This used to go through the
      // console's newApplicationView(), which built the whole page and threw
      // the markup away — so every call here rendered a form nobody read.
      sendJson(res, 200, adminViews.newApplicationJson(req));
      log.debug("Leaving the management API new-application endpoint.");
    } },

  { method: 'POST', route: BASE + '/applications/:action', tag: 'Applications',
    // TWO CONSOLE PATHS REACH THIS SWITCH SINCE 2026-09-13: the list page, and
    // /admin/applications/new's RFC 9728 import, whose load and create post to
    // that page so a refusal can redraw it. The console suite reads this field
    // to learn which console paths take a POST.
    mirrors: 'POST /admin/applications and POST /admin/applications/new',
    handler: function (req, res) {
      log.debug("Entering the management API applications action endpoint.");
      const body = parseBody(req);
      // The declared protocol families, in the two spellings the console takes
      // them in — `protocol` repeated, as a checkbox column posts it, and one
      // `protocols` array, as a JSON body carries it. Read through listField()
      // rather than off `body` for the reason namesOf() exists at all:
      // helpers.parseBody() builds a plain object, so a repeated field arrives
      // as whichever value came last and every other one is silently gone.
      // Ignored by every action but `create`, which is where the vocabulary is
      // validated.
      const protocols = namesOf(req, body, 'protocol', 'protocols');
      const result = adminActions.applicationsAction(withAction(req, body),
                                                     protocols, {
        authorizationServers: resourceMetadata.authorizationServersOf(req),
        // For `issue-software-statement`: the issuer a statement names is the
        // one published at the address this request arrived on.
        base: baseUrlOf(req)
      });
      // `refresh-metadata` is asynchronous — it dials the service provider's
      // metadata URL — and every other action is not. See that action's comment
      // in admin.js for why one promise is cheaper than forty awaits.
      if (result && typeof result.then === 'function') {
        result.then(function (answer) {
          if (!answer.ok) {
            errorCodes.mark(res, errorCodes.codeOf(answer) || 'STS-API-0050');
          }
          sendJson(res, answer.ok ? 200 : 400, answer);
          log.debug("Leaving the management API applications action " +
                    "endpoint. Fetched.");
        });
        log.debug("Leaving handler().");
        return;
      }
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0050');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API applications action endpoint.");
    },
    actions: [
      { action: 'create', operationId: 'createApplication',
        summary: 'Put an application in the registry before it connects',
        description: 'An entry usually appears because an identifier was ' +
                     'ACCEPTED — a client_id at the token endpoint, a ' +
                     'wtrealm on a sign-in response, an SPN on a TGS-REP. ' +
                     'This is how to get one in ahead of that, which is what ' +
                     'RFC 9700 mode needs if a client is to be judged ' +
                     'against its OWN redirect URIs rather than against the ' +
                     '`oauth2.redirectUris` setting.\n\nIt is created with ' +
                     'zero counters and a description saying it was created ' +
                     'by hand, so it cannot be mistaken for an application ' +
                     'that turned up once and never came back. Give it its ' +
                     'redirect URIs and grant types with `add` afterwards.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            identifier: { type: 'string',
                          description: 'The client_id, wtrealm, AppliesTo, ' +
                                       'entityID or service principal name. ' +
                                       'One application per identifier ' +
                                       'whatever protocol brings it, so this ' +
                                       'is refused if one is already here.' },
            name: { type: 'string', description: 'Optional friendly name.' },
            kind: { type: 'string',
                    description: 'Optional, one of the eight. It is a claim ' +
                                 'about what this application IS, which is ' +
                                 'why a value the registry does not know is ' +
                                 'refused rather than recorded.\n\n**No ' +
                                 'console form offers this any more** and it ' +
                                 'is still taken here. It was a select on ' +
                                 '/admin/applications/new beside the ' +
                                 'protocol families, which is two ' +
                                 'vocabularies for one question — eight ' +
                                 'kinds against fourteen families, five of ' +
                                 'them with no kind at all — and it is ' +
                                 'DERIVED rather than declared: a kind is ' +
                                 'written when a protocol actually ' +
                                 'recognises the identifier, so a form ' +
                                 'choosing one asserted a sighting that had ' +
                                 'not happened. Prefer `protocols`.' },
            protocols: {
              type: 'array',
              items: { type: 'string', enum: applications.PROTOCOL_IDS },
              description: 'THE PROTOCOL FAMILIES THIS APPLICATION IS ' +
                           'DECLARED FOR, as ids from the closed vocabulary ' +
                           'GET /admin-api/applications/new publishes. They ' +
                           'land on `appAllowedProtocol`, and one that is ' +
                           'not in that list is REFUSED rather than recorded ' +
                           '— a typo that silently became a new family is ' +
                           'how one application comes to be declared for two ' +
                           'spellings of one thing.\n\n**IT GRANTS AND ' +
                           'REFUSES NOTHING.** Nothing in this service reads ' +
                           'the attribute: an application declared for ' +
                           '`saml2` alone is still issued an access token at ' +
                           '/oauth2/token, and one declared for nothing is ' +
                           'treated exactly as it would have been. It is a ' +
                           'record of INTENT, kept apart from `appProtocol` ' +
                           '— which is what has actually happened and is not ' +
                           'editable — so the two lists on an entry can be ' +
                           'read against each other.\n\nA form-encoded body ' +
                           'may repeat `protocol` instead, which is how the ' +
                           'console\'s checkbox column posts it, and a ' +
                           'single string may carry several separated by ' +
                           'spaces or commas.' },
            fields: {
              type: 'object', additionalProperties: true,
              description: 'THE ATTRIBUTES THE ENTRY IS CREATED WITH, keyed ' +
                           'by the schema\'s own attribute name and valued ' +
                           'with a string or an array of strings. This is ' +
                           'where the per-protocol identifiers and the ' +
                           'redirect URIs go — `oauthClientId`, ' +
                           '`samlEntityId`, `wsfedRealm`, ' +
                           '`krb5ServicePrincipalName`, `oauthRedirectUri`, ' +
                           '`samlAssertionConsumerService`, `wsfedReplyUrl` ' +
                           'and the rest.\n\nGET /admin-api/applications/new ' +
                           'publishes the list as `declarations`, with the ' +
                           'families each attribute serves and whether it ' +
                           'holds a list; it is the same walk of the ' +
                           'protocol table the console\'s form is drawn ' +
                           'from, so this document and that page cannot ' +
                           'offer different fields. GET ' +
                           '/admin/ldap/applications publishes every ' +
                           'attribute in the schema with an `editable` ' +
                           'member.\n\n**Only DECLARED attributes may be ' +
                           'given.** A derived one — a counter, a sighting, ' +
                           '`appProtocol`, `appRedirectUriObserved` — is ' +
                           'REFUSED by name rather than written, because an ' +
                           'entry created with one would be asserting a past ' +
                           'it does not have. A single-valued attribute ' +
                           'given several values is refused as well, rather ' +
                           'than truncated to the first: the only one you ' +
                           'are likely to meet is ' +
                           '`oauthTlsClientAuthSubjectDn`, which an RFC 8705 ' +
                           'check compares by exact string equality, and ' +
                           'quietly keeping one of two is exactly the wrong ' +
                           'answer there.\n\n**Nothing given here is CHECKED ' +
                           'except the OAuth redirect URIs, and those only ' +
                           'in RFC 9700 mode.** The rest are recorded, in ' +
                           'the way being in this registry at all is a ' +
                           'record.\n\n' +
                           familyScopeNote() }
          },
          required: ['identifier'],
          examples: [{ identifier: 'urn:example:crm', name: 'CRM',
                       protocols: ['wsfed', 'saml11'],
                       fields: { wsfedRealm: 'urn:example:crm',
                                 wsfedReplyUrl: [
                                   'https://crm.example.com/wsfed'],
                                 samlEntityId: 'urn:example:crm' } }],
          additionalProperties: false
        },
        responseDescription: 'The application as it now stands, in ' +
                             '`application`.' },

      { action: 'set', operationId: 'setApplicationAttribute',
        summary: 'Set a single-valued attribute',
        // THE LIST IS READ OFF THE SCHEMA rather than typed here, and this and
        // the one on `add` below were typed until 2026-08-25. Making the
        // per-protocol identifiers multi-valued moved six names from this
        // sentence to that one — and neither sentence noticed, which is the
        // whole argument: a hand-written list of what an operation accepts is a
        // second definition of the EDITABLE table, and it goes wrong silently
        // in the document a caller trusts most.
        description: 'For the attributes that hold ONE value — ' +
                     applications.editableAttributes('set').map(function (row) {
                       return '`' + row.name + '`';
                     }).join(', ') + '. An empty `value` CLEARS the ' +
                     'attribute.\n\n**What may be changed is DECLARED and ' +
                     'not DERIVED.** Configuration — what this application ' +
                     'is allowed to do, which is what RFC 9700 mode reads — ' +
                     'is editable. The counters, the sightings, the kinds ' +
                     'and the protocols are what HAPPENED, and are refused ' +
                     'with a list of what is not: a call that could rewrite ' +
                     'them would make this registry lie about the service\'s ' +
                     'own behaviour, in a way indistinguishable from the ' +
                     'recording being broken. `ldapmodify` still reaches ' +
                     'every attribute, which is a deliberate difference — ' +
                     'refusing them HERE is the difference between offering ' +
                     'an operation and merely not preventing ' +
                     'it.\n\n' + familyScopeNote() +
                     'This writes the same entry LDAP ' +
                     'writes, through the same functions, so it takes effect ' +
                     'on the very next authorization request.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            application: { type: 'string',
                           description: 'The identifier, exactly as the ' +
                                        'registry holds it.' },
            attribute: { type: 'string',
                         description: 'One of the editable single-valued ' +
                                      'attributes. GET ' +
                                      '/admin/ldap/applications publishes ' +
                                      'the schema with an `editable` member ' +
                                      'on every row.' },
            value: { type: 'string',
                     description: 'The new value; empty clears the attribute.' }
          },
          required: ['application', 'attribute'],
          examples: [{ application: 'my-web-app',
                       attribute: 'oauthTokenEndpointAuthMethod',
                       value: 'none' }],
          additionalProperties: false
        },
        responseDescription: 'The application as it now stands, with ' +
                             '`changed` saying whether anything actually ' +
                             'differed.' },

      { action: 'add', operationId: 'addApplicationValue',
        summary: 'Add a value to a multi-valued attribute',
        // Read off the schema, for the reason `set` above gives.
        description: 'For the attributes that hold a LIST — ' +
                     applications.editableAttributes('multi')
                                 .map(function (row) {
                       return '`' + row.name + '`';
                     }).join(', ') + '.\n\nThis is the one that matters ' +
                     'most: a value added to `oauthRedirectUri` is a ' +
                     'redirect URI RFC 9700 mode accepts by exact string ' +
                     'match on the next authorization request. Note that it ' +
                     'is the REGISTERED list — `appRedirectUriObserved`, ' +
                     'which records what a client actually used, is not ' +
                     'editable, because "registered" and "used" are ' +
                     'different facts and section 2.1 is entirely about not ' +
                     'confusing them.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            application: { type: 'string' },
            attribute: { type: 'string' },
            value: { type: 'string' }
          },
          required: ['application', 'attribute', 'value'],
          examples: [{ application: 'my-web-app', attribute: 'oauthRedirectUri',
                       value: 'https://app.example.com/callback' }],
          additionalProperties: false
        },
        responseDescription: 'The application as it now stands.' },

      { action: 'remove', operationId: 'removeApplicationValue',
        summary: 'Remove a value from a multi-valued attribute',
        description: 'The inverse of `add`. Removing the LAST value takes ' +
                     'the attribute with it, which is what the LDAP modify ' +
                     'handler does for every other entry in this directory ' +
                     'and what an operator reading it with an LDAP client ' +
                     'will expect.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            application: { type: 'string' },
            attribute: { type: 'string' },
            value: { type: 'string' }
          },
          required: ['application', 'attribute', 'value'],
          examples: [{ application: 'my-web-app', attribute: 'oauthRedirectUri',
                       value: 'https://old.example.com/callback' }],
          additionalProperties: false
        },
        responseDescription: 'The application as it now stands.' },

      // THE PROVENANCE PAIR (2026-09-12). The console's application page draws
      // a Confirm and a Discard button beside every return address a
      // development-mode request put on the entry; rule 7 owes each an
      // operation here, and both call the one action function that page posts
      // to. `applications.returnAddressesOf()` is the rule they change the
      // answer of.
      { action: 'confirm-address',
        operationId: 'confirmApplicationReturnAddress',
        summary: 'Confirm a return address a development-mode request recorded',
        description: 'A return address — a SAML ACS URL or `shire` on ' +
                     '`samlAssertionConsumerService`, a WS-Federation ' +
                     '`wreply` on `wsfedReplyUrl`, or a callback this ' +
                     'service learnt for its own console or portal on ' +
                     '`oauthRedirectUri` — that a request NAMED while the ' +
                     'realm was in DEVELOPMENT mode is written onto the ' +
                     'entry and MARKED on `appReturnAddressObserved` ' +
                     '(`<attribute> <address>`). **PRODUCT mode refuses a ' +
                     'marked address** exactly as it refuses one that is not ' +
                     'on the entry, so a realm switched from development to ' +
                     'product does not trust what development ' +
                     'learnt.\n\nThis takes the mark OFF and keeps the ' +
                     'address, so product believes it from the next request. ' +
                     'An address that is not marked is REFUSED by name ' +
                     'rather than confirmed silently — it is already ' +
                     'registered, or it is not on the entry. `add` of the ' +
                     'same address confirms it too, because an explicit ' +
                     'write is a registration.\n\nGET ' +
                     '/admin-api/applications?application=… lists the marked ' +
                     'addresses as `returnAddressesObserved`, each with ' +
                     '`trusted` saying whether THIS realm\'s mode believes ' +
                     'it. Addresses recorded before this service marked ' +
                     'sightings carry no mark and cannot be told apart from ' +
                     'registered ones.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            application: { type: 'string',
                           description: 'The identifier, exactly as the ' +
                                        'registry holds it.' },
            attribute: { type: 'string',
                         enum: applications.RETURN_ADDRESS_ATTRIBUTES,
                         description: 'The return-address attribute the ' +
                                      'address is on.' },
            value: { type: 'string',
                     description:
                       'The address, exactly as the entry holds it.' }
          },
          required: ['application', 'attribute', 'value'],
          examples: [{ application: 'https://sp.example.com',
                       attribute: 'samlAssertionConsumerService',
                       value: 'https://sp.example.com/acs' }],
          additionalProperties: false
        },
        responseDescription: 'The application as it now stands, with the ' +
                             'mark gone from `returnAddressesObserved`.' },

      { action: 'discard-address',
        operationId: 'discardApplicationReturnAddress',
        summary: 'Discard a return address a development-mode request recorded',
        description: 'The opposite answer to `confirm-address`: the address ' +
                     'was recorded from a request in DEVELOPMENT mode and is ' +
                     'NOT this application\'s, so the mark on ' +
                     '`appReturnAddressObserved` AND the address itself are ' +
                     'taken off the entry. Product mode then refuses it as ' +
                     'an address that is not there; development records it ' +
                     'again, marked, if a request names it again.\n\nAn ' +
                     'address that is not marked is REFUSED rather than ' +
                     'removed — discarding is not the door for taking a ' +
                     'REGISTERED address off an entry, and `remove` is, ' +
                     'which says so.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            application: { type: 'string' },
            attribute: { type: 'string',
                         enum: applications.RETURN_ADDRESS_ATTRIBUTES },
            value: { type: 'string' }
          },
          required: ['application', 'attribute', 'value'],
          examples: [{ application: 'urn:example:crm',
                       attribute: 'wsfedReplyUrl',
                       value: 'https://evil.example/wsfed' }],
          additionalProperties: false
        },
        responseDescription: 'The application as it now stands, without the ' +
                             'address or its mark.' },

      // THE CREDENTIALS SECTION'S SECRET CONTROL (2026-09-13).
      { action: 'regenerate-secret',
        operationId: 'regenerateApplicationClientSecret',
        summary: 'Mint a new client secret for an application, replacing the ' +
                 'old one',
        description: 'Mints `oauth2.registeredSecretBytes` random bytes, ' +
                     'base64url — the way `POST /oauth2/register` mints one ' +
                     '— onto `oauthClientSecret`, and into the stored RFC ' +
                     '7591 registration document where there is one, with ' +
                     '`client_secret_expires_at` recomputed from ' +
                     '`oauth2.registeredSecretLifetimeS`.\n\n**THE OLD ' +
                     'SECRET STOPS AUTHENTICATING AT ONCE**, wherever the ' +
                     'token endpoint checks a secret (RFC 9700 mode, product ' +
                     'mode). **THIS REPLY IS THE ONE PLACE THE NEW VALUE IS ' +
                     'HANDED OUT BY THIS ACT** — the audit row names the ' +
                     'attribute and never the value — though `GET ' +
                     '/admin-api/applications?application=` reads the ' +
                     'entry\'s secret back for an `admin:read` token, as it ' +
                     'always has.\n\nThe console\'s and the portal\'s own ' +
                     'seeded clients read their secret off the entry on ' +
                     'every sign-in, so regenerating one is safe. ' +
                     '`sts-management-api` is REFUSED while ' +
                     '`adminApi.clientSecret` pins its secret: every token ' +
                     'for this API is minted with that setting, and seeding ' +
                     'never writes over an existing entry.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { application: { type: 'string' } },
          required: ['application'],
          examples: [{ application: 'my-web-app' }],
          additionalProperties: false
        },
        responseDescription: 'The new secret in `clientSecret`, whether one ' +
                             'was replaced, and the application as it now ' +
                             'stands.' },

      // THE CREDENTIALS SECTION'S MUTUAL TLS CONTROLS (RFC 8705, 2026-09-13).
      { action: 'issue-tls-client-certificate',
        operationId: 'issueApplicationTlsClientCertificate',
        summary: 'Issue an application a TLS client certificate from this ' +
                 'realm\'s CA',
        description: 'Generates a key pair and certifies it from the ' +
                     'realm\'s `tls-client` Issuing CA with `clientAuth`, ' +
                     'the application\'s identifier as the common name and ' +
                     '`urn:sts:application:<identifier>` as its ' +
                     'subjectAltName — the name RFC 8705\'s IMPLICIT mapping ' +
                     'reads, so the certificate authenticates the ' +
                     'application under `tls_client_auth` with nothing ' +
                     'registered, and every access token issued on a ' +
                     'connection presenting it carries `cnf["x5t#S256"]`.\n\n' +
                     '**THIS REPLY IS THE ONLY COPY OF THE PRIVATE KEY.** ' +
                     '`files` holds a PKCS#12 (base64), an encrypted PKCS#8 ' +
                     'PEM key and the PEM chain, all protected by ' +
                     '`password`, which is neither stored nor audited. ' +
                     'Refused past `pki.applicationTlsClientCertificateMax` ' +
                     'valid certificates, for a key algorithm outside `' +
                     'rsa-2048`, `rsa-3072`, `ec-p256`, `ec-p384`, and in a ' +
                     'realm with no certificate authority.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            application: { type: 'string' },
            password: { type: 'string', minLength: 8, maxLength: 256 },
            confirm: { type: 'string' },
            keyAlg: { type: 'string',
                      enum: ['rsa-2048', 'rsa-3072', 'ec-p256', 'ec-p384'] },
            label: { type: 'string', maxLength: 40 },
            days: { type: 'integer', minimum: 1 }
          },
          required: ['application', 'password'],
          examples: [{ application: 'my-api-client',
                       password: 'correct horse battery',
                       keyAlg: 'ec-p256', label: 'instance 1' }],
          additionalProperties: false
        },
        responseDescription: 'The certificate (serial, subject, thumbprint, ' +
                             'PEM and chain, the implicit name), the three ' +
                             'files, and the application as it now stands.' },
      { action: 'revoke-tls-client-certificate',
        operationId: 'revokeApplicationTlsClientCertificate',
        summary: 'Revoke one of an application\'s TLS client certificates',
        description: 'Revokes a certificate `issue-tls-client-certificate` ' +
                     'issued to THIS application — a serial belonging to ' +
                     'anybody else matches nothing — onto the Issuing CA\'s ' +
                     'CRL and OCSP responder. The certificate stops ' +
                     'authenticating the application at the token endpoint ' +
                     'at once. An access token already bound to it stays ' +
                     'usable until it expires: a resource server checks the ' +
                     'binding, not revocation (RFC 8705 section 6.2).',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            application: { type: 'string' },
            serialHex: { type: 'string' },
            reason: { type: 'string',
                      enum: ['cessationOfOperation', 'keyCompromise'] }
          },
          required: ['application', 'serialHex'],
          examples: [{ application: 'my-api-client', serialHex: '1a2b3c',
                       reason: 'keyCompromise' }],
          additionalProperties: false
        },
        responseDescription: 'The revoked certificate, the reason, and the ' +
                             'application as it now stands.' },

      // THE SOFTWARE STATEMENTS SECTION'S CONTROL (RFC 7591 section 2.3,
      // 2026-09-13).
      { action: 'issue-software-statement',
        operationId: 'issueApplicationSoftwareStatement',
        summary: 'Sign a software statement for an application, as this realm',
        description: 'Signs an RFC 7591 section 2.3 software statement with ' +
                     'this realm\'s key and writes it onto the entry as ' +
                     '`oauthIssuedSoftwareStatement`, replacing the one ' +
                     'before. The application is the software PUBLISHER: ' +
                     'hand the statement to whoever ships the software, and ' +
                     'a client presenting it at `POST /oauth2/register` is ' +
                     'registered with the members it fixes — they take ' +
                     'precedence over the registration\'s own JSON ' +
                     '(section 3.1.1), and whatever the statement does not ' +
                     'fix, the client chooses.\n\n**WHAT IS SIGNED:** ' +
                     '`metadata` (RFC 7591 client metadata, e.g. ' +
                     '`redirect_uris`, `grant_types`, ' +
                     '`token_endpoint_auth_method`), with `software_id` ' +
                     'defaulting to the application\'s identifier; `iss` is ' +
                     'the issuer this realm publishes at the address THIS ' +
                     'REQUEST arrived on, `sub` the application, `iat`, a ' +
                     '`jti`, and `exp` after `lifetimeSeconds` ' +
                     '(`oauth2.softwareStatementLifetimeS` when omitted; 0 ' +
                     'for none). The header is `typ: ' +
                     'software-statement+jwt`, which is how this service ' +
                     'tells its statements from its other JWTs. A JWT claim ' +
                     'or a member only registration assigns (`client_id`, ' +
                     'the secret, the registration access token) is ' +
                     'refused, and so is an address a registration would ' +
                     'refuse.\n\n**IT IS A TRUSTED STATEMENT EVERYWHERE IN ' +
                     'THIS REALM**: nothing has to be declared for it, and ' +
                     'where `oauth2.softwareStatementOpensRegistration` is ' +
                     'on it admits a client to an endpoint closed to ' +
                     'everybody else (product mode with ' +
                     '`oauth2.openRegistration` off). It stops verifying ' +
                     'when it expires or when the realm\'s signing key is ' +
                     'replaced — in development mode, every restart. NOT A ' +
                     'SECRET: a statement ships with the software.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            application: { type: 'string',
                           description: 'The publisher\'s identifier, ' +
                                        'exactly as the registry holds it.' },
            metadata: { oneOf: [{ type: 'object' }, { type: 'string' }],
                        description: 'The client metadata the statement ' +
                                     'fixes, as an object or as JSON text.' },
            lifetimeSeconds: { oneOf: [{ type: 'integer' },
                                       { type: 'string' }],
                               description: 'Seconds until `exp`; 0 for no ' +
                                            'expiry. Defaults to ' +
                                            'oauth2.softwareStatementLifetimeS' +
                                            '.' }
          },
          required: ['application'],
          examples: [{ application: 'acme-mobile',
                       metadata: { software_id: 'acme-mobile-app',
                                   software_version: '4.2',
                                   redirect_uris: [
                                     'com.acme.mobile:/oauth2/cb'],
                                   grant_types: ['authorization_code',
                                                 'refresh_token'],
                                   token_endpoint_auth_method: 'none' },
                       lifetimeSeconds: 31536000 }],
          additionalProperties: false
        },
        responseDescription: 'The statement in `softwareStatement`, its ' +
                             'signed `claims`, and the application as it now ' +
                             'stands.' },

      { action: 'revoke-registration',
        operationId: 'revokeApplicationRegistration',
        summary: 'Withdraw an RFC 7591 registration, keeping the entry',
        description: 'RFC 7592\'s delete reached from here instead of from ' +
                     'the client that holds the registration access token — ' +
                     'the same function, so the outcome is the same one ' +
                     'rather than a second reading of what "unregistered" ' +
                     'means.\n\n**The ENTRY stays**, with everything it had ' +
                     'recorded; the `client_secret`, the registration access ' +
                     'token and the registration document go. Losing that an ' +
                     'application was ever here because its registration was ' +
                     'withdrawn would be losing the fact rather than the ' +
                     'configuration.\n\nAfterwards RFC 9700 mode treats it ' +
                     'as an unregistered, PUBLIC client: PKCE is required of ' +
                     'it, its secret is no longer checked, and its ' +
                     'redirect_uri is judged against the ' +
                     '`oauth2.redirectUris` setting rather than against its ' +
                     'own list.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { application: { type: 'string' } },
          required: ['application'],
          examples: [{ application: 'sts-client-Ab12Cd34' }],
          additionalProperties: false
        },
        responseDescription: 'The application as it now stands, with ' +
                             '`registered` false.' },

      { action: 'refresh-metadata', operationId: 'refreshApplicationMetadata',
        summary: 'Fetch this service provider\'s SAML metadata and store its ' +
                 'encryption certificate',
        description: 'Dials the `samlSpMetadataUrl` ON THE ENTRY — never a ' +
                     'URL in the request body — parses the document, and ' +
                     'writes `samlSpMetadata` and ' +
                     '`samlEncryptionCertificate` back. That certificate is ' +
                     'what an assertion for this service provider is ' +
                     'encrypted to when `saml2.encryptAssertion` (or ' +
                     '`saml2EncryptAssertion` on the entry) is on.\n\nIT IS ' +
                     'THE ONLY OPERATION IN THIS API THAT MAKES AN OUTBOUND ' +
                     'REQUEST, and the second surface in this service that ' +
                     'makes one at all — federation is the other. The same ' +
                     'refusals apply: https only unless ' +
                     '`federation.outboundAllowInsecure` is on, a timeout of ' +
                     '`federation.outboundTimeoutMs`, no redirects followed, ' +
                     'and a size cap.\n\nISSUING NEVER FETCHES. This writes ' +
                     'the certificate onto the entry and an assertion reads ' +
                     'the entry, so no sign-in waits on somebody else\'s web ' +
                     'server.\n\nA FAILURE CHANGES NOTHING — not the ' +
                     'document, not the certificate — so an application that ' +
                     'was working does not stop working because a metadata ' +
                     'host was down.\n\nThe `use="encryption"` KeyDescriptor ' +
                     'is taken, falling back to one with no `use` at all; a ' +
                     '`use="signing"` descriptor is deliberately NOT taken. ' +
                     'The endpoints in the document are REPORTED and not ' +
                     'applied.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          description: 'The application whose metadata should be refreshed.',
          properties: { application: { type: 'string' } },
          required: ['application'],
          examples: [{ application: 'https://sp.example.com' }],
          additionalProperties: false
        },
        responseDescription: 'What the document said: its entityID, which ' +
                             'KeyDescriptor the certificate came from, and ' +
                             'the endpoints it describes.' },

      { action: 'load-resource-metadata',
        operationId: 'loadProtectedResourceMetadata',
        summary: 'Read an RFC 9728 protected resource metadata document and ' +
                 'answer with the application it describes',
        description: 'Give ONE of `document` (the JSON, as text or as an ' +
                     'object) or `url` (where it is published). It is ' +
                     'parsed and checked, compared with this trust realm, ' +
                     'and answered with `plan`: the application it ' +
                     'describes — `name`, `oauthPermissionBaseUri` and ' +
                     '`oauthAudience` from `resource`, one permission per ' +
                     '`scopes_supported` value with the resource prefix ' +
                     'taken off, a client_id generated at random, and ' +
                     '`oauth2` as the declared family.\n\n**IT CREATES ' +
                     'NOTHING.** Create the application with `create`, ' +
                     'passing those values in `fields` together with ' +
                     '`oauthResourceMetadata` (the document, as JSON) and, ' +
                     'where it was fetched, `oauthResourceMetadataUrl`. ' +
                     'Every value may be changed first — this answer is a ' +
                     'proposal.\n\n`authorizationServers` compares the ' +
                     'document\'s `authorization_servers` with the issuers ' +
                     'this realm\'s authorization servers publish at the ' +
                     'address this request arrived on: `allMatched` when ' +
                     'every one is this realm\'s, `anyUnmatched` otherwise. ' +
                     'A mismatch is reported and is NOT a refusal.\n\n' +
                     '**A FETCH FOLLOWS THE OUTBOUND POLICY**: ' +
                     '`federation.outbound` must be on, https unless ' +
                     '`federation.outboundAllowInsecure`, no redirect ' +
                     'followed, `federation.maxResponseBytes` and ' +
                     '`federation.outboundTimeoutMs`. In product mode the ' +
                     'host may not resolve to a loopback, private, ' +
                     'link-local or reserved address, and a document whose ' +
                     '`resource` is not the identifier its well-known URL ' +
                     'was built from (RFC 9728 section 3.3), or is not ' +
                     'https, is refused; development mode reports both in ' +
                     '`warnings` and answers. A malformed document is ' +
                     'refused in both modes.\n\nThe console\'s upload ' +
                     'posts the document as a multipart `file`; a JSON ' +
                     'caller sends `document` instead.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            document: { anyOf: [{ type: 'string' }, { type: 'object' }],
                        description: 'The protected resource metadata ' +
                                     'document, as JSON text or as a JSON ' +
                                     'object.' },
            url: { type: 'string',
                   description: 'Where the document is published, ' +
                                'usually `https://<host>' +
                                resourceMetadata.WELL_KNOWN +
                                '[/<path>]`.' }
          },
          examples: [{ document: {
            resource: 'https://api.example.com',
            authorization_servers: ['https://sts.example.com'],
            scopes_supported: ['https://api.example.com/read',
                               'https://api.example.com/write'],
            bearer_methods_supported: ['header']
          } }],
          additionalProperties: false
        },
        responseDescription: 'The document, its members, the section 3.3 ' +
                             'verdict, the authorization-server comparison ' +
                             'and the proposed application in `plan`.' },

      { action: 'forget', operationId: 'deleteApplication',
        summary: 'Delete an application entry entirely',
        description: 'THE ONE OPERATION HERE THAT LOSES A FACT, which is why ' +
                     'it is separate from `revoke-registration` rather than ' +
                     'something that one does as well. The entry goes and ' +
                     'takes its counters, its sightings and its attributes ' +
                     'with it — for a client_id somebody typed wrong, or a ' +
                     'realm from a test that is over.\n\nIt will reappear, ' +
                     'EMPTY, the next time that identifier is accepted by a ' +
                     'protocol: this registry records what this service has ' +
                     'seen, and it is still seeing.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { application: { type: 'string' } },
          required: ['application'],
          examples: [{ application: 'typo-clientt' }],
          additionalProperties: false
        },
        responseDescription: 'A message saying what went with it.' }
    ] },

  // The audit log. READ ONLY, and that is a decision rather than an operation
  // nobody got round to. Every other resource here has a POST beside it because
  // the console control it mirrors is a form; this one mirrors a page with no
  // form on it, because a clear button on an unprotected console would make an
  // audit log unable to answer the one question it exists for. There is nothing
  // to change, so there is nothing to document as changeable.
  // --- Shared Signals -----------------------------------------------------
  //
  // A GET and a POST, and unlike SCIM's the POST is not optional: /admin/ssf
  // has FOUR CONTROLS on it — set a status, transmit an event, delete a
  // stream, clear what has been received — and rule 7 is about controls. Every
  // one of them calls the same function the console's form posts to, with
  // `action` taken from the URL instead of from a hidden input.
  //
  // **THERE IS DELIBERATELY NO `create` ACTION**, and that is the rule read
  // exactly rather than a gap. A stream carries a delivery endpoint THIS
  // SERVICE WILL DIAL, and the one place that URL may come from is a receiver
  // that authenticated at `POST /ssf/stream` and asked. A management API that
  // could mint one would be a second, ungated door onto the outbound request
  // `ssf/ssf_http.js` spends its header bounding — so the console has no
  // create form either, and the parity holds because there is no control to
  // mirror.
  // ---------------------------------------------------------------------
  // XACML. THREE READS AND ONE WRITE, and the write is the whole PAP: the
  // console's two POST endpoints (`/admin/xacml/policies` and
  // `/admin/xacml/editor`) are ONE action function here, because a caller
  // should not have to work out which page owns "enable". The console keeps
  // two because a form posts back to the page it came from.
  //
  // RULE 7 IS WHY THIS IS IN THE SAME COMMIT AS THE PAGES. Every control the
  // console grows owes an operation here, and the one that is easiest to
  // forget is not the protocol's own endpoint — it is exactly this.
  { method: 'GET', path: BASE + '/xacml', tag: 'XACML',
    operationId: 'getXacml',
    summary: 'The Policy Decision Point: whether it is on, what it decides ' +
             'with, and where the attributes come from',
    description: 'Everything /admin/xacml draws, as JSON.\n\nTHIS IS THE ' +
                 'ONLY FAMILY ON THIS SERVICE THAT ANSWERS A QUESTION ABOUT ' +
                 'SOMEBODY ELSE\'S BOUNDARY. Every other protocol here ' +
                 'authenticates or provisions a person; this one is handed a ' +
                 'subject who was authenticated somewhere else and asked ' +
                 'whether they may.\n\n`pepBias` is the embedded Policy ' +
                 'ENFORCEMENT point\'s setting and not the PDP\'s. ' +
                 'Deny-biased and permit-biased agree on every Permit and ' +
                 'every Deny and differ on Indeterminate and NotApplicable, ' +
                 'which is exactly the case nobody tests.',
    mirrors: 'GET /admin/xacml',
    responseDescription: 'The PDP, its repository and its PIP.',
    responseSchema: { $ref: '#/components/schemas/Xacml' },
    handler: function (req, res) {
      log.debug("Entering the management API XACML endpoint.");
      sendJson(res, 200, adminViews.xacmlView(req));
      log.debug("Leaving the management API XACML endpoint.");
    } },

  { method: 'GET', path: BASE + '/xacml/policies', tag: 'XACML',
    operationId: 'getXacmlPolicies',
    summary: 'The policy repository, with the type-check problems of each',
    description: 'Everything /admin/xacml/policies draws.\n\nTHE STORE IS ' +
                 '`ou=policies` IN THE EMBEDDED DIRECTORY — that container ' +
                 'IS the repository rather than a copy of one, so an ' +
                 '`ldapmodify` of `xacmlPolicyDocument` changes what the PDP ' +
                 'decides on the next request.\n\nEXACTLY ONE POLICY IS THE ' +
                 'ROOT. A PDP evaluates one document and reaches the rest ' +
                 'through PolicyIdReference, so the root is where evaluation ' +
                 'starts; a repository with none decides nothing and reports ' +
                 '`root: null`.\n\n`templates` is what POST ' +
                 '/admin-api/xacml/create-from-template will build, with the ' +
                 'parameters each takes.',
    mirrors: 'GET /admin/xacml/policies',
    responseDescription: 'The policies, the root, and the templates.',
    responseSchema: { $ref: '#/components/schemas/XacmlPolicies' },
    handler: function (req, res) {
      log.debug("Entering the management API XACML policies endpoint.");
      sendJson(res, 200, adminViews.xacmlPoliciesView(req));
      log.debug("Leaving the management API XACML policies endpoint.");
    } },

  { method: 'GET', path: BASE + '/xacml/editor', tag: 'XACML',
    operationId: 'getXacmlEditor',
    summary: 'One policy as an editable tree, with what may legally be added ' +
             'at each node',
    description: 'Everything /admin/xacml/editor draws. `?policy=<name>` ' +
                 'chooses one; without it, the root.\n\nEach node in `tree` ' +
                 'carries `options.additions` — the elements XACML allows AT ' +
                 'THAT POINT, computed against the real function library by ' +
                 'the same code that validates the result. That is what ' +
                 'makes this usable as an API and not only as a page: a ' +
                 'caller can walk the tree, read the legal moves, and POST ' +
                 'one, without a second copy of the grammar.',
    mirrors: 'GET /admin/xacml/editor',
    responseDescription: 'The policy as a tree of editable nodes, with the ' +
                         'stored XML and the same policy rendered as ALFA.',
    responseSchema: { $ref: '#/components/schemas/XacmlEditor' },
    handler: function (req, res) {
      log.debug("Entering the management API XACML editor endpoint.");
      sendJson(res, 200, adminViews.xacmlEditorView(req));
      log.debug("Leaving the management API XACML editor endpoint.");
    } },

  { method: 'GET', path: BASE + '/xacml/decide', tag: 'XACML',
    operationId: 'getXacmlDecision',
    summary: 'Ask the PDP about somebody and see the decision, which ' +
             'policies applied, and what the embedded PEP would do with it',
    description: 'Everything /admin/xacml/decide draws. `subject`, `action` ' +
                 'and `resource` are query parameters; with none of them it ' +
                 'answers `asked: false` rather than deciding about ' +
                 'nobody.\n\nTHE DECISION AND THE ENFORCEMENT ARE TWO ' +
                 'DIFFERENT ANSWERS and both are here, which is the whole ' +
                 'point of the page: the PDP says Permit, Deny, ' +
                 'NotApplicable or Indeterminate, and the PEP then applies ' +
                 'its bias and the obligation rule to get to allowed or ' +
                 'refused. When a policy "is not working" it is nearly ' +
                 'always because only one of those was being looked ' +
                 'at.\n\nThis is NOT POST /xacml/pdp. That endpoint takes ' +
                 'a JSON Profile request and is what a PEP calls; this ' +
                 'builds a three-category request out of three parameters ' +
                 'and is what a person asks.',
    mirrors: 'GET /admin/xacml/decide',
    responseDescription: 'The decision, what applied, and what the embedded ' +
                         'PEP would do.',
    responseSchema: { $ref: '#/components/schemas/XacmlDecision' },
    handler: function (req, res) {
      log.debug("Entering the management API XACML decision endpoint.");
      sendJson(res, 200, adminViews.xacmlDecideView(req));
      log.debug("Leaving the management API XACML decision endpoint.");
    } },

  // THE ONLY XACML OPERATION ABOUT TRAFFIC. The other six describe the
  // repository — what policies exist, what one says, what the PDP would decide
  // about a subject you name. This one answers what is actually HAPPENING, and
  // it is the operation somebody reaches for when authorization is
  // misbehaving rather than when it is being set up.
  //
  // NO POST BESIDE IT, and that is rule 7 read exactly rather than by shape:
  // the page it mirrors has no control. A reset was refused rather than
  // forgotten — a console that could zero its own monitoring would make every
  // number on it a number somebody might have zeroed, and the audit log, which
  // is the durable record, cannot be reset either.
  // -------------------------------------------------------------------------
  // GNAP (RFC 9635 + RFC 9767), 2026-09-12. Three operations mirroring the two
  // pages `gnap/gnap_admin.js` draws and the one form on the first of them.
  // Both doors call `gnap/gnap_console.js`, the view and action layer of this
  // family, so a page and its operation cannot disagree (rule 7). REQUIRED
  // LAZILY: this module is 19 in the require order and GNAP is 23d, and every
  // module that file loads is a library — but a lazy require keeps that true
  // by construction rather than by a reading of today's require graph.
  // -------------------------------------------------------------------------
  { method: 'GET', path: BASE + '/gnap', tag: 'GNAP', operationId: 'getGnap',
    summary: 'The GNAP authorization server: endpoints, capabilities, ' +
             'grants, resource sets, settings',
    description: 'Everything /admin/gnap draws. The endpoints of this ' +
                 'realm\'s GNAP authorization server (RFC 9635) and its ' +
                 'RS-facing API (RFC 9767); the section 9 capabilities of ' +
                 'the default authorization server and of every named one, ' +
                 'after that profile\'s GNAP overrides — which are what each ' +
                 'grant endpoint ENFORCES; the five token formats and the ' +
                 'public material that verifies the self-contained ones; the ' +
                 'grants this realm holds (paged, `grantsPage`, and filtered ' +
                 'by `state`); the registered resource sets (paged, ' +
                 '`resourcesPage`); and the `gnap.*` settings, which are ' +
                 'written through POST /admin-api/config/set-many.',
    mirrors: 'GET /admin/gnap',
    responseDescription: 'The authorization server as the page draws it.',
    responseSchema: { $ref: '#/components/schemas/GnapServer' },
    handler: function (req, res) {
      log.debug("Entering the management API GNAP endpoint.");
      sendJson(res, 200, require('../gnap/gnap_console').gnapView(req));
      log.debug("Leaving the management API GNAP endpoint.");
    } },

  { method: 'GET', path: BASE + '/gnap/monitor', tag: 'GNAP',
    operationId: 'getGnapMonitor',
    summary: 'Every application that uses GNAP, and what each has done',
    description: 'Everything /admin/gnap/monitor draws: one row per ' +
                 'application declared for GNAP, seen speaking it, or ' +
                 'counted — client instances and resource servers — with the ' +
                 'grants it holds by state, its live tokens, and its ' +
                 'counters since the process started: grants requested, ' +
                 'approved and denied, tokens issued by format, rotations, ' +
                 'revocations, failed key proofs, introspections, ' +
                 'registrations, derivations, and the GNAP error codes it ' +
                 'was answered with. Per trust realm, and with no reset: the ' +
                 'durable record is GET /admin-api/audit.',
    mirrors: 'GET /admin/gnap/monitor',
    responseDescription: 'The totals, and one row per application.',
    responseSchema: { $ref: '#/components/schemas/GnapMonitor' },
    handler: function (req, res) {
      log.debug("Entering the management API GNAP monitor endpoint.");
      sendJson(res, 200, require('../gnap/gnap_console').gnapMonitorView(req));
      log.debug("Leaving the management API GNAP monitor endpoint.");
    } },

  { method: 'POST', route: BASE + '/gnap/:action', tag: 'GNAP',
    mirrors: 'POST /admin/gnap',
    handler: function (req, res) {
      log.debug("Entering the management API GNAP action endpoint.");
      const result = require('../gnap/gnap_console').gnapAction(
          withAction(req, parseBody(req)),
                                                                 { via: 'api',
                                                                   req: req });
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-GNAP-0665');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API GNAP action endpoint.");
    },
    actions: [
      { action: 'revoke-grant', operationId: 'revokeGnapGrant',
        summary: 'Revoke a GNAP grant, as its client could (RFC 9635 section ' +
                 '5.4)',
        description: 'Finalizes the grant and revokes every access token ' +
                     'issued under it, through the same path the client\'s ' +
                     'own DELETE on the continuation URI takes — so the ' +
                     'client sees exactly what it would have seen had it ' +
                     'revoked the grant itself, and a CAEP session-revoked ' +
                     'is sent to every stream that takes it. A grant already ' +
                     'finalized is reported unchanged rather than refused.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { grant: { type: 'string', description: 'The grant ' +
              'identifier, from GET /admin-api/gnap.' } },
          required: ['grant'],
          examples: [{ grant: 'no-such-grant-example' }],
          additionalProperties: false
        },
        responseDescription: 'The grant as it now stands.' },
      { action: 'delete-resource-set', operationId: 'deleteGnapResourceSet',
        summary: 'Delete a registered resource set (RFC 9767 section 3.4)',
        description: 'Removes the resource set, after which its reference no ' +
                     'longer resolves in a grant request. Tokens already ' +
                     'issued keep the rights they carry.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { reference: { type: 'string', description: 'The ' +
              'resource reference, from GET /admin-api/gnap.' } },
          required: ['reference'],
          examples: [{ reference: 'no-such-reference' }],
          additionalProperties: false
        },
        responseDescription: 'The reference that was deleted.' }
    ] },

  { method: 'GET', path: BASE + '/xacml/monitor', tag: 'XACML',
    operationId: 'getXacmlMonitor',
    summary: 'How many authorization decisions are being made, by which ' +
             'enforcement point, and how many are refusals',
    description: 'Everything /admin/xacml/monitor draws: the global figures ' +
                 '— policies, enforcement points, decisions, allows, ' +
                 'declines — and then every PEP with its own counts, ' +
                 'EMBEDDED and REMOTE in one list.\n\n**A DECISION IS NOT ' +
                 'AN ENFORCEMENT.** XACML has four decisions (Permit, Deny, ' +
                 'NotApplicable, Indeterminate) and a PEP has two outcomes, ' +
                 'and what maps between them is the PEP\'s BIAS: a ' +
                 'deny-biased PEP refuses a NotApplicable that a ' +
                 'permit-biased one allows, from the same decision on the ' +
                 'same request. An obligation the PEP cannot discharge also ' +
                 'turns a Permit into a refusal (section 7.2) — the one ' +
                 'enforcement outcome that looks like a bug from the client ' +
                 'side and is the specification working. So `allowed` is not ' +
                 '`permit`, and both are reported.\n\n**WHAT THIS SERVICE ' +
                 'SAW IS NOT WHAT IT WAS TOLD.** `decisions.here` was ' +
                 'counted by this process as it happened; `decisions.remote` ' +
                 'is what registered PEPs REPORT on their heartbeats, ' +
                 'cumulative in their own memory, and a PEP that restarts ' +
                 'makes it go down. `decisions.combined` adds the two, which ' +
                 'is the figure a deployment wants and is arithmetic over ' +
                 'two kinds of evidence rather than a ' +
                 'measurement.\n\n**THE EMBEDDED PEPS ARE NOT ' +
                 '"REGISTERED" AND CANNOT BE.** They are compiled into this ' +
                 'process, so their existence is a fact about the build. A ' +
                 'remote PEP registers because it has no other way to be ' +
                 'known about — and even that is not a permission: an ' +
                 'unregistered PEP can pull GET /xacml/pep/policies and ' +
                 'enforce perfectly, and appears here nowhere. This is every ' +
                 'enforcement point the service KNOWS ABOUT, which is a ' +
                 'smaller claim than every one that exists.\n\nThe ' +
                 'counters are IN MEMORY, start with the process (`since`) ' +
                 'and are per trust realm. The durable record of a refusal ' +
                 'is GET /admin-api/audit, which has the reason as well as ' +
                 'the count.',
    mirrors: 'GET /admin/xacml/monitor',
    responseDescription: 'The global figures, and one row per enforcement ' +
                         'point.',
    responseSchema: { $ref: '#/components/schemas/XacmlMonitor' },
    handler: function (req, res) {
      log.debug("Entering the management API XACML monitor endpoint.");
      sendJson(res, 200, adminViews.xacmlMonitorView(req));
      log.debug("Leaving the management API XACML monitor endpoint.");
    } },

  { method: 'GET', path: BASE + '/xacml/peps', tag: 'XACML',
    operationId: 'getXacmlPeps',
    summary: 'The REMOTE Policy Enforcement Points that pull this ' +
             'repository, and whether they are deciding with the same ' +
             'policy this service holds',
    description: 'Everything /admin/xacml/peps draws.\n\nA REMOTE PEP runs ' +
                 'in another process, holds its own copy of the engine and ' +
                 'PULLS the enabled policies from GET /xacml/pep/policies. ' +
                 'The pull is the contract; the nudge this service sends to ' +
                 '`notifyUrl` when the repository changes is an optimisation ' +
                 'over the polling interval and never a replacement for it, ' +
                 'so a PEP that is never nudged still converges.\n\n' +
                 'REGISTERING IS NOT A PERMISSION. An unregistered PEP can ' +
                 'pull and enforce exactly as well — GET /xacml/pep/policies ' +
                 'requires no credential, because a policy is a rule and a ' +
                 'rule nobody can read is a rule nobody can check. What a ' +
                 'row buys is this listing and an address for the ' +
                 'nudge.\n\n`current` is a COMPARISON this service ' +
                 'performs between `syncToken` on the row and the ' +
                 'repository\'s own, not a claim the PEP makes; `stale` is ' +
                 'how long since it was last heard from against ' +
                 'xacml.pepStaleAfterS and changes nothing this service ' +
                 'does. The decision counts are the PEP\'s own, cumulative ' +
                 'in its process — this service saw none of those ' +
                 'decisions, which is what a remote PEP is — so a PEP that ' +
                 'restarts makes them go down.',
    mirrors: 'GET /admin/xacml/peps',
    responseDescription: 'The register, and what each PEP last reported.',
    responseSchema: { $ref: '#/components/schemas/XacmlPeps' },
    handler: function (req, res) {
      log.debug("Entering the management API XACML remote PEPs endpoint.");
      sendJson(res, 200, adminViews.xacmlPepsView(req));
      log.debug("Leaving the management API XACML remote PEPs endpoint.");
    } },

  { method: 'POST', route: BASE + '/xacml/:action', tag: 'XACML',
    mirrors: 'POST /admin/xacml/policies, POST /admin/xacml/editor and ' +
             'POST /admin/xacml/peps',
    handler: function (req, res) {
      log.debug("Entering the management API XACML action endpoint.");
      const body = parseBody(req);
      // SETTLED EITHER WAY: `issue-pep-certificate` answers a promise and the
      // other actions answer a result (see `xacmlAction()`), and a rejection
      // is a defect here rather than something a request can cause — so it is
      // a 500 naming the message rather than an unhandled rejection that hangs
      // the request.
      Promise.resolve(adminActions.xacmlAction(withAction(req, body)))
        .then(function (result) {
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0051');
          }
          // THE PRIVATE KEY IN AN ISSUE REPLY IS THE POINT OF THE CALL, handed
          // over once — and `sendJson()` already answers `no-store`, which is
          // what keeps it out of every cache between here and the caller.
          sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API XACML action endpoint.");
        }, function (e) {
          log.error(errorCodes.tag('STS-XACML-0072') + 'admin_api: an XACML ' +
                    'action threw: ' + ((e && e.stack) || e));
          errorCodes.mark(res, 'STS-XACML-0072');
          sendJson(res, 500, { ok: false,
                               errors: ['That action failed: ' +
                                        ((e && e.message) || e)] });
          log.debug("Leaving the management API XACML action endpoint. " +
                    "It threw.");
        });
    },
    actions: [
      { action: 'create-from-template', operationId: 'createXacmlPolicy',
        summary: 'Create a policy from a template',
        description: 'A template is a working, valid, evaluable policy in a ' +
                     'shape people actually write — the first twenty clicks ' +
                     'of the editor already made. `template` names one (see ' +
                     'GET /admin-api/xacml/policies), `name` names the ' +
                     'directory entry, and each parameter is sent as ' +
                     '`p_<name>`; anything omitted takes the template\'s own ' +
                     'default, so a call with only `template` produces the ' +
                     'documented example.\n\n`blank` is the one template ' +
                     'that is not an example: it builds an EMPTY Policy, or ' +
                     'an empty PolicySet with `p_kind=policyset` — which is ' +
                     'the only way to create one of those without ALFA. An ' +
                     'empty deny-unless-permit document DENIES rather than ' +
                     'answering NotApplicable, so build it before making it ' +
                     'the root.\n\nA template BUILDS THE MODEL and ' +
                     'the writer serializes it, rather than substituting ' +
                     'into XML text — so a role called `a"b` cannot produce ' +
                     'a document that will not parse.\n\nThe FIRST policy in ' +
                     'an empty repository becomes the root, because a ' +
                     'repository with a policy and no root decides nothing.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            template: { type: 'string',
                      description: 'Which template. GET ' +
                                   '/admin-api/xacml/policies lists them ' +
                                   'with the parameters each takes.' },
            name: { type: 'string',
                      description: 'Names the DIRECTORY ENTRY. The PolicyId ' +
                                   'inside the document is a separate ' +
                                   'identifier and may be any URI.' }
          },
          required: ['template'],
          examples: [{
            template: 'rbac',
            name: 'example-rbac'
          }],
          additionalProperties: true
        } },
      { action: 'import-alfa', operationId: 'importXacmlAlfa',
        summary: 'Create a policy from ALFA',
        description: 'ALFA — the Abbreviated Language For Authorization — is ' +
                     'the readable syntax for XACML: forty lines of XML are ' +
                     'eight of ALFA. Send it as `alfa` and a name as ' +
                     '`name`.\n\nIT IS PARSED, CONVERTED AND STORED AS ' +
                     'XACML XML. The repository holds ONE representation, ' +
                     'because two would be two documents that could disagree ' +
                     '— GET /admin-api/xacml/editor renders the ALFA back ' +
                     'from the model whenever you want to read it.\n\nEVERY ' +
                     'ATTRIBUTE MUST BE DECLARED BEFORE IT IS USED. That is ' +
                     'ALFA\'s own rule and it is the most useful refusal in ' +
                     'the parser: a typo in an attribute name is otherwise a ' +
                     'policy that quietly matches nothing, which looks ' +
                     'exactly like a policy that is working and denying ' +
                     'you.\n\nALFA IS AN OASIS COMMITTEE SPECIFICATION ' +
                     'DRAFT, not a ratified standard — no conformance suite, ' +
                     'no schema, no second implementation to disagree with. ' +
                     'The contract offered is the one that can be kept: ' +
                     'anything this service EMITS as ALFA it reads back, and ' +
                     'the policy decides identically either way.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            alfa: { type: 'string',
                      description: 'The ALFA source. Parsed, converted and ' +
                                   'stored as XACML XML — the repository ' +
                                   'holds ONE representation.' },
            name: { type: 'string',
                      description: 'Names the directory entry.' }
          },
          required: ['alfa', 'name'],
          examples: [{
            name: 'example-alfa',
            alfa: 'namespace example {\n' +
              '    attribute employeeType {\n' +
              '        id = "employeeType"\n' +
              '        type = "string"\n' +
              '        category = subjectCat\n' +
              '    }\n' +
              '    policy exampleAlfa {\n' +
              '        apply denyUnlessPermit\n' +
              '        rule allowStaff {\n' +
              '            permit\n' +
              '            target clause employeeType == "staff"\n' +
              '        }\n' +
              '    }\n' +
              '}'
          }],
          additionalProperties: false
        } },
      { action: 'enable', operationId: 'enableXacmlPolicy',
        summary: 'Put a policy back into the decision',
        description: 'Sets `xacmlEnabled` on its directory entry.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            name: { type: 'string',
                      description: 'The policy\'s directory entry name.' }
          },
          required: ['name'],
          examples: [{
            name: 'my-policy'
          }],
          additionalProperties: false
        } },
      { action: 'disable', operationId: 'disableXacmlPolicy',
        summary: 'Take a policy out of the decision without deleting it',
        description: 'The point of having this separate from delete: a ' +
                     'disabled policy is still there to be read, edited and ' +
                     'put back, which is what you want while working on it — ' +
                     'the editor is LIVE, so a policy being edited is a ' +
                     'policy the PDP is deciding with unless it is off.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            name: { type: 'string',
                      description: 'The policy\'s directory entry name.' }
          },
          required: ['name'],
          examples: [{
            name: 'my-policy'
          }],
          additionalProperties: false
        } },
      { action: 'set-root', operationId: 'setXacmlRootPolicy',
        summary: 'Choose the policy the PDP starts from',
        description: 'Clears the flag on the incumbent first, because the ' +
                     'store refuses a second root. Done in that order ' +
                     'deliberately: a failure then leaves the repository ' +
                     'with NO root rather than with two, which is the ' +
                     'recoverable one of the two bad states.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            name: { type: 'string',
                      description: 'The policy\'s directory entry name.' }
          },
          required: ['name'],
          examples: [{
            name: 'my-policy'
          }],
          additionalProperties: false
        } },
      { action: 'delete', operationId: 'deleteXacmlPolicy',
        summary: 'Remove a policy from the repository',
        description: 'Deleting the ROOT leaves the repository deciding ' +
                     'nothing, and the reply says so rather than letting it ' +
                     'be discovered by a Deny.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            name: { type: 'string',
                      description: 'The policy\'s directory entry name.' }
          },
          required: ['name'],
          examples: [{
            name: 'my-policy'
          }],
          additionalProperties: false
        } },
      { action: 'edit-policy', operationId: 'editXacmlPolicy',
        summary: 'Change a policy\'s id, description or combining algorithm',
        description: 'The combining algorithm is the single most ' +
                     'consequential line in a policy, which is why it is ' +
                     'here rather than only in the document.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            id: { type: 'string',
                      description: 'A new PolicySetId or PolicyId. Any URI.' },
            description: { type: 'string',
                      description: 'The document\'s own <Description>.' },
            combiningAlgId: { type: 'string',
                      description: 'One of the rule-combining algorithms ' +
                                   'this editor offers; anything else is ' +
                                   'refused rather than written. THE SINGLE ' +
                                   'MOST CONSEQUENTIAL LINE IN A POLICY.' }
          },
          required: ['policy'],
          examples: [{
            policy: 'my-policy',
            path: '',
            id: 'urn:example:policy:staff'
          }],
          additionalProperties: false
        } },
      { action: 'add-rule', operationId: 'addXacmlRule',
        summary: 'Add a rule to a policy',
        description: 'Every element this editor adds arrives COMPLETE AND ' +
                     'VALID — a new rule has a Target, an Effect and an id. ' +
                     'An editor that produced half-built elements would hold ' +
                     'a document that could not be saved, and a document ' +
                     'that cannot be saved cannot be evaluated, which is ' +
                     'when you most want to look at it.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            effect: { type: 'string',
                      description: 'Permit or Deny. Defaults to Permit.' }
          },
          required: ['policy'],
          examples: [{
            policy: 'my-policy',
            path: '',
            effect: 'Permit'
          }],
          additionalProperties: false
        } },
      { action: 'edit-match', operationId: 'editXacmlMatch',
        summary: 'Change a Match\'s function, value or attribute',
        description: 'THE DATATYPE FOLLOWS THE FUNCTION. A Match whose ' +
                     'literal is a string and whose designator is an integer ' +
                     'does not type-check, so choosing the function sets ' +
                     'both sides rather than letting them be picked ' +
                     'independently and refused later.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            matchId: { type: 'string',
                      description: 'The match function. Defaults to ' +
                                   'string-equal. THE DATATYPE FOLLOWS IT on ' +
                                   'both sides, so choosing the function ' +
                                   'settles the literal\'s type and the ' +
                                   'designator\'s together.' },
            value: { type: 'string',
                      description: 'The literal to test against.' },
            category: { type: 'string',
                      description: 'The attribute category. Defaults to ' +
                                   'access-subject.' },
            attributeId: { type: 'string',
                      description: 'The attribute to read. A bare name or ' +
                                   'the `urn:sts:xacml:attribute:` prefix ' +
                                   'reaches the directory through the PIP; ' +
                                   'anything else must be in the request.' },
            mustBePresent: { type: 'boolean',
                      description: 'Whether an absent attribute is an empty ' +
                                   'bag (false) or makes the whole ' +
                                   'expression Indeterminate (true).' }
          },
          required: ['policy', 'path'],
          examples: [{
            policy: 'my-policy',
            path: 'target.anyOf.0.allOf.0.matches.0',
            matchId: 'urn:oasis:names:tc:xacml:1.0:function:string-equal',
            value: 'staff',
            attributeId: 'employeeType'
          }],
          additionalProperties: false
        } },
      { action: 'remove', operationId: 'removeXacmlNode',
        summary: 'Remove any node from a policy',
        description: 'By `path`, which is the address GET ' +
                     '/admin-api/xacml/editor gave you. A path is only valid ' +
                     'against the document it was read from: remove rule 0 ' +
                     'and every path naming rule 1 now means rule 0. Re-read ' +
                     'the tree after each edit rather than reusing paths.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' }
          },
          required: ['policy', 'path'],
          examples: [{
            policy: 'my-policy',
            path: 'rules.0'
          }],
          additionalProperties: false
        } },
      // ---------------------------------------------------------------
      // THE REST OF THE EDITOR, AND THE REASON THESE NINETEEN ARRIVED LATE.
      //
      // Phase three documented ten of the twenty-nine actions and shipped.
      // Rule 7 says a control added to the console gets an operation in the
      // same commit, and `tests/vendored/sts_admin_api_operations.js` is the
      // check — it compares the actions this document DECLARES against the
      // ones the handler's refusal sentence NAMES, in both directions,
      // because that sentence is what `admin_api.js`'s parity check reads to
      // find out what a resource can do. Nineteen actions the sentence named
      // and the document did not meant nineteen console controls that could
      // have lost their operation with nothing failing.
      //
      // It went unnoticed until phase five because that job is this
      // repository's own and had not been run against this branch.
      //
      // EVERY ONE OF THESE TAKES A `path`, which is the address
      // GET /admin-api/xacml/editor gave you, and every one of them is only
      // valid against the document that reply was read from — remove rule 0
      // and every path naming rule 1 now means rule 0. Re-read the tree after
      // each edit rather than reusing paths.
      // ---------------------------------------------------------------
      { action: 'add-target-anyof', operationId: 'addXacmlTargetClause',
        summary: 'Add a Target clause to a policy, a rule or a Target',
        description: 'A `<Target>` is a list of clauses and **every one of ' +
                     'them must match** — they are ANDed. Inside a clause ' +
                     'the alternatives are ORed and inside an alternative ' +
                     'the Matches are ANDed again, so the quantifier flips ' +
                     'at each of the three levels.\n\nThat is why the ' +
                     'element names read backwards from what they do: ' +
                     '`AnyOf` holds `AllOf` holds `Match`, and the ' +
                     '`AnyOf`s themselves are ANDed. Getting it wrong ' +
                     'produces a policy that applies to more or less than ' +
                     'was meant and never an error.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            matchId: { type: 'string',
                      description: 'The match function. Defaults to ' +
                                   'string-equal. THE DATATYPE FOLLOWS IT on ' +
                                   'both sides, so choosing the function ' +
                                   'settles the literal\'s type and the ' +
                                   'designator\'s together.' },
            value: { type: 'string',
                      description: 'The literal to test against.' },
            category: { type: 'string',
                      description: 'The attribute category. Defaults to ' +
                                   'access-subject.' },
            attributeId: { type: 'string',
                      description: 'The attribute to read. A bare name or ' +
                                   'the `urn:sts:xacml:attribute:` prefix ' +
                                   'reaches the directory through the PIP; ' +
                                   'anything else must be in the request.' }
          },
          required: ['policy'],
          examples: [{
            policy: 'my-policy',
            path: '',
            matchId: 'urn:oasis:names:tc:xacml:1.0:function:string-equal',
            value: 'staff',
            category:
              'urn:oasis:names:tc:xacml:1.0:subject-category:access-subject',
            attributeId: 'employeeType'
          }],
          additionalProperties: false
        } },
      { action: 'add-allof', operationId: 'addXacmlAlternative',
        summary: 'Add an alternative to a Target clause',
        description: 'ANY of a clause\'s alternatives matching satisfies it ' +
                     '— they are ORed. Within one alternative every Match ' +
                     'must hold.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            matchId: { type: 'string',
                      description: 'The match function. Defaults to ' +
                                   'string-equal. THE DATATYPE FOLLOWS IT on ' +
                                   'both sides, so choosing the function ' +
                                   'settles the literal\'s type and the ' +
                                   'designator\'s together.' },
            value: { type: 'string',
                      description: 'The literal to test against.' },
            category: { type: 'string',
                      description: 'The attribute category. Defaults to ' +
                                   'access-subject.' },
            attributeId: { type: 'string',
                      description: 'The attribute to read. A bare name or ' +
                                   'the `urn:sts:xacml:attribute:` prefix ' +
                                   'reaches the directory through the PIP; ' +
                                   'anything else must be in the request.' }
          },
          required: ['policy', 'path'],
          examples: [{
            policy: 'my-policy',
            path: 'target.anyOf.0',
            matchId: 'urn:oasis:names:tc:xacml:1.0:function:string-equal',
            value: 'admin',
            attributeId: 'employeeType'
          }],
          additionalProperties: false
        } },
      { action: 'add-match', operationId: 'addXacmlMatch',
        summary: 'Add a Match to an alternative',
        description: 'One attribute tested against one value. It arrives ' +
                     'COMPLETE AND VALID — a function, a literal and a ' +
                     'designator — because an editor that produced ' +
                     'half-built elements would hold a document that cannot ' +
                     'be saved, and a document that cannot be saved cannot ' +
                     'be evaluated, which is when you most want to look at ' +
                     'it. Use edit-match to change any of the three.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            matchId: { type: 'string',
                      description: 'The match function. Defaults to ' +
                                   'string-equal. THE DATATYPE FOLLOWS IT on ' +
                                   'both sides, so choosing the function ' +
                                   'settles the literal\'s type and the ' +
                                   'designator\'s together.' },
            value: { type: 'string',
                      description: 'The literal to test against.' },
            category: { type: 'string',
                      description: 'The attribute category. Defaults to ' +
                                   'access-subject.' },
            attributeId: { type: 'string',
                      description: 'The attribute to read. A bare name or ' +
                                   'the `urn:sts:xacml:attribute:` prefix ' +
                                   'reaches the directory through the PIP; ' +
                                   'anything else must be in the request.' }
          },
          required: ['policy', 'path'],
          examples: [{
            policy: 'my-policy',
            path: 'target.anyOf.0.allOf.0',
            matchId: 'urn:oasis:names:tc:xacml:1.0:function:string-equal',
            value: 'GET',
            attributeId: 'actionId'
          }],
          additionalProperties: false
        } },
      { action: 'edit-rule', operationId: 'editXacmlRule',
        summary: 'Change a rule\'s id, effect or description',
        description: 'The EFFECT is the consequential one: it is what this ' +
                     'rule contributes to the combining algorithm when its ' +
                     'Target and Condition hold, and flipping it between ' +
                     'Permit and Deny changes what the policy decides ' +
                     'without changing anything a reader is looking at.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            id: { type: 'string',
                      description: 'A new RuleId.' },
            effect: { type: 'string',
                      description: 'Permit or Deny.' },
            description: { type: 'string',
                      description: 'The rule\'s own description.' }
          },
          required: ['policy'],
          examples: [{
            policy: 'my-policy',
            path: 'rules.0',
            effect: 'Deny'
          }],
          additionalProperties: false
        } },
      { action: 'add-condition', operationId: 'addXacmlCondition',
        summary: 'Add a Condition to a rule',
        description: 'A boolean expression evaluated AFTER the Target ' +
                     'matches. **At most one per rule** — the schema allows ' +
                     'exactly one, and the editor stops offering this on a ' +
                     'rule that has one rather than offering it and then ' +
                     'refusing, because an option that is offered and ' +
                     'refused teaches a caller that the menu is not to be ' +
                     'trusted.\n\nIt must evaluate to EXACTLY ONE BOOLEAN. ' +
                     'A condition returning a bag, or an integer, is a ' +
                     'static type error and the policy is refused at write ' +
                     'time rather than going Indeterminate on every ' +
                     'request.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' }
          },
          required: ['policy', 'path'],
          examples: [{
            policy: 'my-policy',
            path: 'rules.0'
          }],
          additionalProperties: false
        } },
      { action: 'set-expression-apply', operationId: 'setXacmlApply',
        summary: 'Make an expression a function call',
        description: 'Replaces whatever is at `path` with an `<Apply>` of ' +
                     'the function named in `functionId`, with arguments ' +
                     'the function\'s own signature requires. Every ' +
                     'expression slot in a policy takes any of the four ' +
                     'shapes, which is why these are four actions on one ' +
                     'target rather than four kinds of node.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            functionId: { type: 'string',
                      description: 'The function to apply. Its arguments are ' +
                                   'PRE-BUILT to the declared arity and ' +
                                   'types, so the expression typechecks the ' +
                                   'moment it exists.' }
          },
          required: ['policy', 'path'],
          examples: [{
            policy: 'my-policy',
            path: 'rules.0.condition',
            functionId: 'urn:oasis:names:tc:xacml:1.0:function:string-equal'
          }],
          additionalProperties: false
        } },
      { action: 'set-expression-value', operationId: 'setXacmlValue',
        summary: 'Make an expression a literal',
        description: 'An `<AttributeValue>` of `dataType` with `lexical` in ' +
                     'it. The lexical form is parsed against the datatype ' +
                     'when the policy is written, so `2026-13-01` as a date ' +
                     'is refused there rather than becoming an ' +
                     'Indeterminate at decision time.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            type: { type: 'string',
                      description: 'The datatype URI. Defaults to xs:string.' },
            lexical: { type: 'string',
                      description: 'The value, in that datatype\'s lexical ' +
                                   'form.' }
          },
          required: ['policy', 'path'],
          examples: [{
            policy: 'my-policy',
            path: 'rules.0.condition.args.0',
            type: 'http://www.w3.org/2001/XMLSchema#string',
            lexical: 'staff'
          }],
          additionalProperties: false
        } },
      { action: 'set-expression-designator',
        operationId: 'setXacmlDesignator',
        summary: 'Make an expression an attribute reference',
        description: 'An `<AttributeDesignator>`: reads an attribute out of ' +
                     'the REQUEST, or out of the directory through the PIP ' +
                     'when the id is a bare name or carries the ' +
                     '`urn:sts:xacml:attribute:` prefix.\n\n**IT ' +
                     'RETURNS A BAG**, always, even when it finds exactly ' +
                     'one value — which is why `string-one-and-only` exists ' +
                     'and why most functions need it wrapped. Nothing in ' +
                     'this engine ever holds a bare value, so there is no ' +
                     'code path where somebody has to remember to wrap ' +
                     'one.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            category: { type: 'string',
                      description: 'The attribute category. Defaults to ' +
                                   'access-subject.' },
            attributeId: { type: 'string',
                      description: 'The attribute to read.' },
            dataType: { type: 'string',
                      description: 'The datatype URI. Defaults to xs:string.' }
          },
          required: ['policy', 'path'],
          examples: [{
            policy: 'my-policy',
            path: 'rules.0.condition.args.1',
            category:
              'urn:oasis:names:tc:xacml:1.0:subject-category:access-subject',
            attributeId: 'employeeType',
            dataType: 'http://www.w3.org/2001/XMLSchema#string'
          }],
          additionalProperties: false
        } },
      { action: 'set-expression-variable', operationId: 'setXacmlVariable',
        summary: 'Make an expression a variable reference',
        description: 'A `<VariableReference>` to a `<VariableDefinition>` ' +
                     'in the same policy. The reference is checked at write ' +
                     'time, so one naming a variable that is not there is ' +
                     'refused rather than deciding Indeterminate.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            variableId: { type: 'string',
                      description: 'The VariableDefinition to reference. It ' +
                                   'must exist in the same policy — the ' +
                                   'reference is checked at write time.' }
          },
          required: ['policy', 'path'],
          examples: [{
            policy: 'my-policy',
            path: 'rules.0.condition.args.0',
            variableId: 'v1'
          }],
          additionalProperties: false
        } },
      { action: 'add-argument', operationId: 'addXacmlArgument',
        summary: 'Add an argument to a function call',
        description: 'Offered only on an `<Apply>` — every other expression ' +
                     'is a leaf and may only be REPLACED, which the four ' +
                     'set-expression actions already do. The argument ' +
                     'arrives as a literal of the type the function expects ' +
                     'in that position.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' }
          },
          required: ['policy', 'path'],
          examples: [{
            policy: 'my-policy',
            path: 'rules.0.condition'
          }],
          additionalProperties: false
        } },
      { action: 'edit-apply', operationId: 'editXacmlApply',
        summary: 'Change which function a call applies',
        description: 'THE ARGUMENTS ARE RESHAPED TO THE NEW SIGNATURE. A ' +
                     'function taking two strings changed for one taking ' +
                     'two integers cannot keep its arguments, and leaving ' +
                     'them would hold a document that does not typecheck ' +
                     'and therefore cannot be saved.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            functionId: { type: 'string',
                      description: 'The function to apply instead. The ' +
                                   'arguments are reshaped to the new ' +
                                   'signature.' }
          },
          required: ['policy', 'path'],
          examples: [{
            policy: 'my-policy',
            path: 'rules.0.condition',
            functionId: 'urn:oasis:names:tc:xacml:1.0:function:string-equal'
          }],
          additionalProperties: false
        } },
      { action: 'edit-value', operationId: 'editXacmlValue',
        summary: 'Change a literal\'s datatype or lexical form',
        description: 'The lexical form is parsed against the datatype, so a ' +
                     'value that is not of its type is refused here rather ' +
                     'than at decision time.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            type: { type: 'string',
                      description: 'A new datatype URI.' },
            lexical: { type: 'string',
                      description: 'A new lexical form, parsed against that ' +
                                   'datatype.' }
          },
          required: ['policy', 'path'],
          examples: [{
            policy: 'my-policy',
            path: 'rules.0.condition.args.0',
            lexical: 'admin'
          }],
          additionalProperties: false
        } },
      { action: 'edit-designator', operationId: 'editXacmlDesignator',
        summary: 'Change an attribute reference',
        description: 'Its category, attribute id, datatype and ' +
                     '`MustBePresent`. **`MustBePresent` is the one that ' +
                     'surprises people**: with it false an absent attribute ' +
                     'is an empty bag, and with it true the whole ' +
                     'expression is Indeterminate — which the combining ' +
                     'algorithms then treat quite differently from a Deny.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            category: { type: 'string',
                      description: 'A new category.' },
            attributeId: { type: 'string',
                      description: 'A new attribute id.' },
            dataType: { type: 'string',
                      description: 'A new datatype URI.' },
            mustBePresent: { type: 'boolean',
                      description: 'False makes an absent attribute an empty ' +
                                   'bag; true makes the whole expression ' +
                                   'Indeterminate, which the combining ' +
                                   'algorithms treat quite differently from ' +
                                   'a Deny.' }
          },
          required: ['policy', 'path'],
          examples: [{
            policy: 'my-policy',
            path: 'rules.0.condition.args.1',
            attributeId: 'department',
            mustBePresent: false
          }],
          additionalProperties: false
        } },
      { action: 'add-rule-obligation', operationId: 'addXacmlRuleObligation',
        summary: 'Add an obligation to a rule',
        description: 'Fires when this RULE\'s Effect is the decision. An ' +
                     'obligation is the half of a decision that says "yes, ' +
                     'AND you must also do this", and section 7.2 makes it ' +
                     'binding: a PEP that cannot discharge one MUST NOT ' +
                     'grant the access. Both PEPs here implement that — the ' +
                     'embedded one at /xacml/protected and the remote ' +
                     'container — and it is the part implementations ' +
                     'skip.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            on: { type: 'string',
                      description: 'Permit or Deny — the effect this fires ' +
                                   'on. Defaults to Permit. An obligation ' +
                                   'attached to the wrong effect is silently ' +
                                   'never discharged.' }
          },
          required: ['policy', 'path'],
          examples: [{
            policy: 'my-policy',
            path: 'rules.0',
            on: 'Permit'
          }],
          additionalProperties: false
        } },
      { action: 'add-policy-obligation',
        operationId: 'addXacmlPolicyObligation',
        summary: 'Add an obligation to a policy',
        description: 'Fires on the POLICY\'s decision rather than on one ' +
                     'rule\'s. Same binding force — see ' +
                     'addXacmlRuleObligation.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            on: { type: 'string',
                      description: 'Permit or Deny. Defaults to Permit.' }
          },
          required: ['policy'],
          examples: [{
            policy: 'my-policy',
            path: '',
            on: 'Deny'
          }],
          additionalProperties: false
        } },
      { action: 'add-rule-advice', operationId: 'addXacmlRuleAdvice',
        summary: 'Add advice to a rule',
        description: 'Something the PEP MAY do. **It is allowed to ignore ' +
                     'this, and that is the whole difference from an ' +
                     'obligation** — advice a PEP drops is a PEP behaving ' +
                     'correctly, where an obligation it drops is half a ' +
                     'policy enforced and reported as success.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            on: { type: 'string',
                      description: 'Permit or Deny. Defaults to Permit.' }
          },
          required: ['policy', 'path'],
          examples: [{
            policy: 'my-policy',
            path: 'rules.0',
            on: 'Permit'
          }],
          additionalProperties: false
        } },
      { action: 'add-policy-advice', operationId: 'addXacmlPolicyAdvice',
        summary: 'Add advice to a policy',
        description: 'On the policy\'s decision rather than on one rule\'s. ' +
                     'See addXacmlRuleAdvice for why advice and an ' +
                     'obligation are not the same thing.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            on: { type: 'string',
                      description: 'Permit or Deny. Defaults to Permit.' }
          },
          required: ['policy'],
          examples: [{
            policy: 'my-policy',
            path: '',
            on: 'Permit'
          }],
          additionalProperties: false
        } },
      { action: 'edit-obligation', operationId: 'editXacmlObligation',
        summary: 'Change an obligation\'s or advice\'s id, or when it fires',
        description: 'The FULFILL-ON is the consequential field: an ' +
                     'obligation set to fire on Permit contributes nothing ' +
                     'to a Deny, and one attached to the wrong effect is ' +
                     'silently never discharged.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            id: { type: 'string',
                      description: 'A new obligation or advice identifier.' },
            on: { type: 'string',
                      description: 'Permit or Deny — the effect it fires on.' }
          },
          required: ['policy', 'path'],
          examples: [{
            policy: 'my-policy',
            path: 'obligations.0',
            id: 'urn:example:obligation:log',
            on: 'Permit'
          }],
          additionalProperties: false
        } },
      { action: 'add-assignment', operationId: 'addXacmlAssignment',
        summary: 'Add an attribute assignment to an obligation or advice',
        description: 'A value handed to the PEP along with the obligation ' +
                     '— what to log, whom to notify, which record to ' +
                     'stamp. Its expression takes any of the four shapes ' +
                     'the set-expression actions produce.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' }
          },
          required: ['policy', 'path'],
          examples: [{
            policy: 'my-policy',
            path: 'obligations.0'
          }],
          additionalProperties: false
        } },
      // ---------------------------------------------------------------
      // THE POLICY SET, THE VARIABLES, THE SELECTORS AND THE FUNCTION
      // REFERENCES.
      //
      // Everything below reaches a part of the XACML syntax the editor could
      // not build before. Four of them are not new controls so much as a
      // repair: `add-policy` exists because a PolicySet used to be offered
      // `add-rule`, which the writer then discarded — an edit accepted,
      // reported as done, and absent from the stored document.
      //
      // EVERY ONE TAKES A `path`, and it is only valid against the document
      // GET /admin-api/xacml/editor returned. Re-read the tree after each
      // edit rather than reusing paths.
      // ---------------------------------------------------------------
      { action: 'add-policy', operationId: 'addXacmlPolicyToSet',
        summary: 'Add a Policy inside a PolicySet',
        description: 'A PolicySet holds POLICIES; a Policy holds RULES. ' +
                     'They are not two spellings of one thing, and asking ' +
                     'for a rule on a policy set is refused rather than ' +
                     'written somewhere it will not be read.\n\nThe new ' +
                     'policy arrives with `deny-unless-permit` and no rules, ' +
                     'which decides Deny. That is deliberate: this editor is ' +
                     'LIVE, so a child added to the running root takes ' +
                     'effect on the next request, and one that began ' +
                     'permissive would be a hole opened by pressing Add.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
          },
          required: ['policy', 'path'],
          examples: [{ policy: 'my-policy-set', path: '' }],
          additionalProperties: false
        } },
      { action: 'add-policyset', operationId: 'addXacmlPolicySetToSet',
        summary: 'Add a nested PolicySet inside a PolicySet',
        description: 'There is no depth limit. It arrives with ' +
                     '`deny-unless-permit` — the POLICY-combining spelling, ' +
                     'which is a different URI from the rule-combining one ' +
                     'of the same name.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
          },
          required: ['policy', 'path'],
          examples: [{ policy: 'my-policy-set', path: '' }],
          additionalProperties: false
        } },
      { action: 'add-policy-reference',
        operationId: 'addXacmlPolicyReference',
        summary: 'Reference a policy stored separately in the repository',
        description: 'THIS IS HOW A PDP REACHES MORE THAN ONE DOCUMENT. ' +
                     'Evaluation starts at the root policy and a ' +
                     '`PolicyIdReference` is resolved against the ' +
                     'repository WHEN A DECISION IS MADE, not when the ' +
                     'document is loaded — so referencing a policy that has ' +
                     'not been written yet is allowed and is not an error. ' +
                     'An unresolved reference is reported on the decision ' +
                     'instead, which is what keeps the order two policies ' +
                     'are authored in from mattering.\n\nThe `ref` is the ' +
                     'PolicyId INSIDE the other document, not its directory ' +
                     'entry name.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            ref: { type: 'string',
                      description: 'The PolicyId being referenced. Any URI.' },
            version: { type: 'string',
                      description: 'An optional version constraint. Omit for ' +
                                   'no constraint.' }
          },
          required: ['policy', 'path'],
          examples: [{ policy: 'my-policy-set', path: '',
                       ref: 'urn:example:policy:staff' }],
          additionalProperties: false
        } },
      { action: 'add-policyset-reference',
        operationId: 'addXacmlPolicySetReference',
        summary: 'Reference a policy SET stored separately',
        description: 'The same as add-policy-reference, naming a ' +
                     'PolicySetId. The element name says which kind of ' +
                     'document is being named, so the two are separate ' +
                     'actions rather than one with a flag.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            ref: { type: 'string',
                      description: 'The PolicySetId being referenced.' },
            version: { type: 'string',
                      description: 'An optional version constraint.' }
          },
          required: ['policy', 'path'],
          examples: [{ policy: 'my-policy-set', path: '',
                       ref: 'urn:example:policyset:hr' }],
          additionalProperties: false
        } },
      { action: 'edit-reference', operationId: 'editXacmlReference',
        summary: 'Change what a policy reference names',
        description: 'An empty `version` means NO version constraint, which ' +
                     'is a different document from one naming a version — so ' +
                     'it is written as absent rather than as an empty string.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            ref: { type: 'string',
                      description: 'The PolicyId or PolicySetId to name.' },
            version: { type: 'string',
                      description: 'A version constraint, or empty for none.' }
          },
          required: ['policy', 'path'],
          examples: [{ policy: 'my-policy-set', path: 'children.0',
                       ref: 'urn:example:policy:staff' }],
          additionalProperties: false
        } },
      { action: 'add-variable', operationId: 'addXacmlVariable',
        summary: 'Add a VariableDefinition to a policy',
        description: 'Names an expression so several rules can share it — ' +
                     'and so it is evaluated ONCE per request rather than ' +
                     'once per use.\n\nITS SCOPE IS THE POLICY IT IS ON. A ' +
                     'sibling policy in the same set cannot name it (section ' +
                     '5.24), which is why GET /admin-api/xacml/editor is ' +
                     'the only reliable source of what a VariableReference ' +
                     'at a given path may legally name.\n\nIt arrives ' +
                     'holding a designator, because a VariableDefinition ' +
                     'with no expression is a document that will not load. ' +
                     'Replace it with any of the set-expression actions.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            variableId: { type: 'string',
                      description: 'The name. Defaults to the next free ' +
                                   '`v<n>`. A duplicate is refused — the ' +
                                   'reader rejects a document defining one ' +
                                   'id twice, so allowing it here would ' +
                                   'write a policy this service cannot load ' +
                                   'back.' }
          },
          required: ['policy', 'path'],
          examples: [{ policy: 'my-policy', path: '',
                       variableId: 'staffTypes' }],
          additionalProperties: false
        } },
      { action: 'edit-variable', operationId: 'renameXacmlVariable',
        summary: 'Rename a variable, and every reference with it',
        description: 'EVERY `VariableReference` NAMING IT IS REWRITTEN. The ' +
                     'alternative — refusing to rename one that is used — ' +
                     'is safe and useless, since a variable nobody ' +
                     'references is the only one nobody wants to rename; and ' +
                     'a rename that left the references behind would produce ' +
                     'a document that does not load, so the write would be ' +
                     'refused and nothing would change. The reply says how ' +
                     'many references moved.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            variableId: { type: 'string',
                      description: 'The new name.' }
          },
          required: ['policy', 'path'],
          examples: [{ policy: 'my-policy', path: 'variables.v1',
                       variableId: 'staffTypes' }],
          additionalProperties: false
        } },
      { action: 'set-expression-selector',
        operationId: 'setXacmlExpressionSelector',
        summary: 'Replace an expression with an AttributeSelector',
        description: 'An XPath over the `<Content>` of a request category, ' +
                     'rather than a named attribute — and it returns a ' +
                     'BAG exactly as a designator does, so most functions ' +
                     'still need a `one-and-only` around it.\n\nThe ' +
                     'namespace bindings its prefixes need TRAVEL WITH THE ' +
                     'DOCUMENT: a prefix in the path means nothing without ' +
                     'one, and an unresolvable prefix is an empty bag, which ' +
                     'is NotApplicable, which looks exactly like a policy ' +
                     'that decided you may not. Set them with edit-selector.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            category: { type: 'string',
                      description: 'The request category whose content the ' +
                                   'path runs over. Defaults to resource.' },
            path_xpath: { type: 'string',
                      description: 'Sent as `path` — but `path` is already ' +
                                   'the node address on this endpoint, so ' +
                                   'set the XPath with edit-selector ' +
                                   'immediately afterwards. The selector ' +
                                   'arrives with `//*`, which is complete ' +
                                   'and valid.' }
          },
          required: ['policy', 'path'],
          examples: [{ policy: 'my-policy',
                       path: 'rules.0.condition.args.0' }],
          additionalProperties: false
        } },
      { action: 'edit-selector', operationId: 'editXacmlSelector',
        summary: 'Change an AttributeSelector\'s path, category or bindings',
        description: 'ONE NAMESPACE BINDING AT A TIME, because the console ' +
                     'this mirrors has no JavaScript and cannot grow a row: ' +
                     'send `namespacePrefix` with `namespaceUri` to add or ' +
                     'change one, and `namespacePrefix` with an empty ' +
                     '`namespaceUri` to remove it.\n\n' +
                     '`ContextSelectorId` names an attribute holding the ' +
                     'node the path starts from; absent means the whole ' +
                     'content.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            path_xpath: { type: 'string',
                      description: 'Sent as `path` collides with the node ' +
                                   'address; this operation reads the XPath ' +
                                   'from `path` ONLY when it is not the ' +
                                   'address — see the console form, which ' +
                                   'posts them separately.' },
            category: { type: 'string',
                      description: 'The category whose content is selected.' },
            dataType: { type: 'string',
                      description: 'The datatype of the bag it returns.' },
            contextSelectorId: { type: 'string',
                      description: 'An attribute naming the starting node, ' +
                                   'or empty for the whole content.' },
            mustBePresent: { type: 'string',
                      description: '"true" or "false". Absent KEEPS the ' +
                                   'current value rather than clearing it.' },
            namespacePrefix: { type: 'string',
                      description: 'A prefix to bind, rebind or remove.' },
            namespaceUri: { type: 'string',
                      description: 'What to bind it to. Empty removes it.' }
          },
          required: ['policy', 'path'],
          examples: [{ policy: 'my-policy',
                       path: 'rules.0.condition.args.0',
                       namespacePrefix: 'md',
                       namespaceUri: 'http://www.medico.com/schemas/record' }],
          additionalProperties: false
        } },
      { action: 'set-expression-function',
        operationId: 'setXacmlExpressionFunction',
        summary: 'Replace an expression with a Function reference',
        description: 'A function named as a VALUE rather than applied: ' +
                     '`<Function FunctionId="..."/>`, which is what the ' +
                     'first argument of a higher-order function such as ' +
                     '`any-of`, `all-of` or `map` takes.\n\nAPPLYING IT ' +
                     'THERE INSTEAD is the commonest way to write one of ' +
                     'those wrongly, and it is why choosing a higher-order ' +
                     'function from set-expression-apply now builds this ' +
                     'shape for you rather than an AttributeValue the ' +
                     'validator refuses.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            functionId: { type: 'string',
                      description: 'The function to name. Defaults to ' +
                                   'string-equal.' }
          },
          required: ['policy', 'path'],
          examples: [{ policy: 'my-policy',
                       path: 'rules.0.condition.args.0',
                       functionId:
                         'urn:oasis:names:tc:xacml:1.0:function:string-equal' }],
          additionalProperties: false
        } },
      { action: 'edit-function', operationId: 'editXacmlFunctionReference',
        summary: 'Change which function a Function reference names',
        description: 'The whole content of the element is which function it ' +
                     'names, so this is its only field.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            functionId: { type: 'string',
                      description: 'Any identifier in the function library.' }
          },
          required: ['policy', 'path'],
          examples: [{ policy: 'my-policy',
                       path: 'rules.0.condition.args.0',
                       functionId:
                         'urn:oasis:names:tc:xacml:1.0:function:integer-equal' }],
          additionalProperties: false
        } },
      { action: 'edit-assignment', operationId: 'editXacmlAssignment',
        summary: 'Change an attribute assignment\'s id, category or issuer',
        description: 'The three attributes of an ' +
                     '`AttributeAssignmentExpression`. Its VALUE is the ' +
                     'expression underneath it, edited with the ' +
                     'set-expression and edit-value actions at the ' +
                     '`...assignments.<n>.expression` path.\n\nCategory and ' +
                     'Issuer are OPTIONAL and empty means absent, not empty: ' +
                     'an assignment with no category is a plain named value ' +
                     'handed to the PEP.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            policy: { type: 'string',
                      description: 'The directory entry name of the policy ' +
                                   'to edit — the `cn` under ou=policies, ' +
                                   'not the PolicyId inside the document.' },
            path: { type: 'string',
                      description: 'The node\'s address, from GET ' +
                                   '/admin-api/xacml/editor. ONLY VALID ' +
                                   'AGAINST THE DOCUMENT IT WAS READ FROM: ' +
                                   'remove rule 0 and every path naming rule ' +
                                   '1 now means rule 0.' },
            attributeId: { type: 'string',
                      description: 'The name the PEP receives it under.' },
            category: { type: 'string',
                      description: 'An optional category. Empty removes it.' },
            issuer: { type: 'string',
                      description: 'An optional issuer. Empty removes it.' }
          },
          required: ['policy', 'path'],
          examples: [{ policy: 'my-policy',
                       path: 'rules.0.obligations.0.assignments.0',
                       attributeId: 'urn:example:notify' }],
          additionalProperties: false
        } },
      { action: 'disable-pep', operationId: 'disableXacmlPep',
        summary: 'Stop nudging a registered remote PEP',
        description: 'IT DOES NOT STOP IT ENFORCING, and the reply says so ' +
                     'rather than letting that be discovered. A remote PEP ' +
                     'holds its own copy of the engine and its own copy of ' +
                     'the policy; nothing in this API reaches into another ' +
                     'process. What changes is that this service no longer ' +
                     'dials it when the repository changes, so it converges ' +
                     'only on its own polling interval.\n\nNamed with a ' +
                     '`-pep` suffix rather than reusing `disable` because ' +
                     'this endpoint dispatches on the action name across ' +
                     'the whole family, and a second `disable` would be ' +
                     'ambiguous between a policy and a PEP.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            name: { type: 'string',
                      description: 'The registered PEP\'s name.' }
          },
          required: ['name'],
          examples: [{
            name: 'pep-1'
          }],
          additionalProperties: false
        } },
      { action: 'enable-pep', operationId: 'enableXacmlPep',
        summary: 'Nudge a registered remote PEP again',
        description: 'Puts it back into the set this service dials when the ' +
                     'repository changes. A PEP that re-registers does NOT ' +
                     'clear this by itself — a component an administrator ' +
                     'stopped nudging must not be able to undo that by ' +
                     'reconnecting.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            name: { type: 'string',
                      description: 'The registered PEP\'s name, which is the ' +
                                   'one its client certificate gave it.' }
          },
          required: ['name'],
          examples: [{
            name: 'pep-1'
          }],
          additionalProperties: false
        } },
      { action: 'forget-pep', operationId: 'forgetXacmlPep',
        summary: 'Remove a remote PEP from the register',
        description: 'Removes the row in ou=peps. THE PROCESS IS ' +
                     'UNAFFECTED: it may still be pulling and enforcing, ' +
                     'and the next time it registers it simply appears ' +
                     'again. Use it for a PEP that is genuinely gone; use ' +
                     'disable-pep for one that is not.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            name: { type: 'string',
                      description: 'The registered PEP\'s name.' }
          },
          required: ['name'],
          examples: [{
            name: 'pep-1'
          }],
          additionalProperties: false
        } },
      { action: 'issue-pep-certificate',
        operationId: 'issueXacmlPepCertificate',
        summary: 'Issue a remote PEP the certificate and private key for its ' +
                 'HTTPS listener',
        description: 'Generates a key pair and certifies it from the Remote ' +
                     'PEP listeners (`pep-tls`) Issuing CA of THE REALM THE ' +
                     'PEP REGISTERED TO — the realm this call is made in, ' +
                     'because ou=peps is per realm — so a client that ' +
                     'installed this service\'s Root CA verifies the PEP, ' +
                     'and ' +
                     'the chain says which realm vouched for it. A realm ' +
                     'whose branch was built before that Issuing CA existed ' +
                     'gets it added under its existing Intermediate; nothing ' +
                     'already issued is replaced.\n\nThe PEP must be ' +
                     'REGISTERED: its row is the one record that it exists ' +
                     'in this realm. That is not a permission check on the ' +
                     'PEP — registering is still not what lets it pull or ' +
                     'enforce.\n\nTHE CERTIFICATE NAMES the PEP\'s ' +
                     'registered ' +
                     'name (where that is a DNS name) and the host of its ' +
                     'notify URL, plus any `dnsNames` and `ipAddresses` ' +
                     'sent. ' +
                     'It certifies `serverAuth` and nothing else.\n\n**THE ' +
                     'PRIVATE KEY IS IN THIS REPLY AND NOWHERE ELSE.** This ' +
                     'service records the certificate — its issuer\'s CRL ' +
                     'and OCSP responder answer for it — and keeps no copy ' +
                     'of the ' +
                     'key, so nothing can read it back. To put the pair in ' +
                     'the container, write `fullChainPem` (the leaf followed ' +
                     'by its Issuing CA and the realm Intermediate) and ' +
                     '`privateKeyPem` to the files `PEP_HTTPS_CERT` and ' +
                     '`PEP_HTTPS_KEY` name; the PEP picks up a pair written ' +
                     'after it started. `anchorPem` is the service Root a ' +
                     'client of that listener installs.\n\nIssuing again ' +
                     'REPLACES: the certificate it replaces goes on its ' +
                     'issuer\'s revocation list as `superseded` ' +
                     '(`replacedSerialHex`).',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            name: { type: 'string',
                      description: 'The registered PEP\'s name, as GET ' +
                                   '/admin-api/xacml/peps lists it.' },
            dnsNames: { oneOf: [{ type: 'array', items: { type: 'string' } },
                                { type: 'string' }],
                      description: 'DNS names to ADD to the two derived from ' +
                                   'the registration. An array, or one ' +
                                   'string separated by commas or ' +
                                   'whitespace. A `*.` wildcard is ' +
                                   'accepted in the first label.' },
            ipAddresses: { oneOf: [{ type: 'array',
                                     items: { type: 'string' } },
                                   { type: 'string' }],
                      description: 'IPv4 or IPv6 addresses to add, in the ' +
                                   'same two spellings.' },
            keyAlg: { type: 'string',
                      enum: pki.TLS_SERVER_KEY_ALGS.slice(),
                      description: 'The key algorithm. Defaults to ' +
                                   '`' + pki.DEFAULT_TLS_SERVER_KEY_ALG +
                                   '`. Only the RSA and NIST-curve ECDSA ' +
                                   'keys ' +
                                   'a TLS stack serves are offered.' },
            days: { type: 'integer', minimum: 1,
                      description: 'The lifetime. Defaults to ' +
                                   '`pki.leafLifetimeDays`, and is shortened ' +
                                   'to the Issuing CA\'s own expiry.' }
          },
          required: ['name'],
          examples: [{
            name: 'pep-1',
            dnsNames: ['pep-1.example.test'],
            ipAddresses: ['127.0.0.1']
          }],
          additionalProperties: false
        } }
    ] },

  { method: 'GET', path: BASE + '/ssf', tag: 'Shared Signals',
    operationId: 'getSsf',
    summary: 'The Shared Signals transmitter: its streams, their subjects, ' +
             'their queues and what a receiver refused',
    description: 'Everything /admin/ssf draws, as JSON. Per stream: the ' +
                 'configuration a receiver agreed, who it is about, what is ' +
                 'waiting to be delivered, the counters, and the stream\'s ' +
                 'own log — which is the only place a REFUSED PUSH is ' +
                 'recorded, because a push a receiver rejected is invisible ' +
                 'from the receiving end by definition.\n\nSSF IS THE PIPE ' +
                 'AND NOT THE VOCABULARY. It defines how two parties agree a ' +
                 'stream, who the events are about (RFC 9493), what they ' +
                 'travel in (RFC 8417) and how they get there (RFC 8935 ' +
                 'push, RFC 8936 poll) — and two events of its own, both ' +
                 'about the pipe. CAEP and RISC are the vocabularies spoken ' +
                 'over it; CAEP is implemented and its own register is at ' +
                 'GET /admin-api/caep, and RISC has one of its own at ' +
                 'GET /admin-api/risc.\n\nTHE ' +
                 'RECEIVER\'S `authorization_header` IS NOT IN THIS REPLY. ' +
                 'It is a credential belonging to somebody else\'s endpoint ' +
                 'and it goes back only to the receiver that set it, at ' +
                 'GET /ssf/stream.',
    mirrors: 'GET /admin/ssf',
    responseDescription: 'The transmitter, its streams and what it has ' +
                         'received.',
    responseSchema: { $ref: '#/components/schemas/Ssf' },
    handler: function (req, res) {
      log.debug("Entering the management API Shared Signals endpoint.");
      sendJson(res, 200, adminViews.ssfJson(req));
      log.debug("Leaving the management API Shared Signals endpoint.");
    } },

  // ---------------------------------------------------------------------
  // WHAT COULD NOT BE DELIVERED, COUNTED (2026-09-14) — rule 7's half of
  // Monitoring → Shared Signals → Dead letters. A GET beside the POST
  // `/ssf/:action` below, which it cannot collide with: one method each.
  // No POST of its own, because the page has no control; the two that act on
  // dead letters are that operation's `revive` and `clear-dead-letters`.
  // ---------------------------------------------------------------------
  { method: 'GET', path: BASE + '/ssf/dead-letters', tag: 'Shared Signals',
    operationId: 'getSsfDeadLetters',
    summary: 'What the Shared Signals transmitter could not deliver, counted',
    description: 'Everything /admin/ssf/dead-letters draws, as JSON: every ' +
                 'Security Event Token held on a dead-letter queue in this ' +
                 'realm, counted by cause, error code, the receiver\'s HTTP ' +
                 'status and event type, over time across the retention ' +
                 'window, and per stream with each push stream\'s delivery ' +
                 'state — then the letters themselves, newest first, ' +
                 'searched and paged, without their tokens.\n\n**THE COUNTS ' +
                 'ARE THE WHOLE REALM\'S WHATEVER IS NARROWED.** `dlq`, ' +
                 '`dlstream` and `dlcause` narrow `letters` and `matched` ' +
                 'only.\n\n**`process` IS THE ANSWERING PROCESS\'S.** Its ' +
                 'push cap is shared by every realm in that process, and ' +
                 'its sweeps are its own; the rest is the shared store.',
    mirrors: 'GET /admin/ssf/dead-letters',
    parameters: [
      { name: 'dlq', in: 'query', required: false,
        schema: { type: 'string', maxLength: 256 },
        description: 'Narrows the letters to those whose jti, stream, ' +
                     'reason, error code, status, event name, type URI or ' +
                     'subject contains this.' },
      { name: 'dlstream', in: 'query', required: false,
        schema: { type: 'string', maxLength: 256 },
        description: 'Only this stream\'s letters. An exact stream id.' },
      { name: 'dlcause', in: 'query', required: false,
        schema: { type: 'string',
                  enum: ['push-failed', 'backlog-full', 'declared-dead',
                         'dead-stream'] },
        description: 'Only letters of this cause.' },
      { name: 'lettersPage', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Which page of the matched letters. Clamped, like every ' +
                     'page parameter here.' }
    ].concat(pagingParameters()),
    responseDescription: 'The dead-letter queues of this realm, counted, and ' +
                         'a page of their letters.',
    responseSchema: { $ref: '#/components/schemas/SsfDeadLetters' },
    handler: function (req, res) {
      log.debug("Entering the management API dead letters endpoint.");
      sendJson(res, 200, adminViews.ssfDeadLettersJson(req));
      log.debug("Leaving the management API dead letters endpoint.");
    } },

  { method: 'POST', route: BASE + '/ssf/:action', tag: 'Shared Signals',
    mirrors: 'POST /admin/ssf',
    handler: function (req, res) {
      log.debug("Entering the management API Shared Signals action endpoint.");
      const body = parseBody(req);
      // THE ONE HANDLER IN THIS FILE THAT AWAITS. Transmitting a Security
      // Event Token signs a JWS — which may be ML-DSA or SLH-DSA on the
      // worker pool — and then POSTs it to somebody else's endpoint. Neither
      // can be done synchronously, and answering before either had happened
      // would be this API reporting "sent" about nothing.
      adminActions.ssfAction(withAction(req, body)).then(function (result) {
        if (!result.ok) {
          errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0052');
        }
        sendJson(res, result.ok ? 200 : 400, result);
        log.debug("Leaving the management API Shared Signals action " +
                  "endpoint.");
      }).catch(function (e) {
        // A rejection here is a bug in ssf/ssf.js rather than anything a
        // request can cause — its action function resolves a refusal rather
        // than throwing one — so it is reported as a refusal instead of
        // becoming an unhandled rejection that ends the process.
        errorCodes.mark(res, 'STS-API-0018');
        log.error('admin-api: the Shared Signals action threw: ' + e.message);
        sendJson(res, 500, { ok: false,
          errors: ['The action failed: ' + e.message] });
        log.debug("Leaving the management API Shared Signals action " +
                  "endpoint. Threw.");
      });
      log.debug("Leaving handler().");
    },
    actions: [
      { action: 'status', operationId: 'setSsfStreamStatus',
        summary: 'Enable, pause or disable a stream',
        description: 'The three values and what separates them: a PAUSED ' +
                     'stream keeps QUEUEING and delivers nothing, so what ' +
                     'happened while it was paused is still there when it is ' +
                     'enabled again; a DISABLED one DROPS what is waiting. ' +
                     'That is the difference between "I was not listening" ' +
                     'and "it did not happen", and it is the whole reason a ' +
                     'Shared Signals receiver has a pause.\n\nA change here ' +
                     'also emits a **stream updated** event ON the stream, ' +
                     'if the receiver agreed that type — the one event a ' +
                     'receiver gets without asking for it, and the one whose ' +
                     'absence is hardest to notice.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            stream_id: { type: 'string',
                         description: 'The stream, as GET /admin-api/ssf ' +
                                      'lists it.' },
            status: { type: 'string', enum: ['enabled', 'paused', 'disabled'],
                      description: 'The new status.' },
            reason: { type: 'string',
                      description: 'Optional. Why, in words — it rides in ' +
                                   'the stream-updated event\'s `reason` ' +
                                   'member, which nothing parses.' }
          },
          required: ['stream_id', 'status'],
          examples: [{ stream_id: 'ssf-0123456789ab', status: 'paused',
                       reason: 'maintenance' }],
          additionalProperties: false
        },
        responseDescription: 'What happened, and whether the stream-updated ' +
                             'event went with it.' },

      { action: 'transmit', operationId: 'transmitSsfEvent',
        summary: 'Send a Security Event Token on a stream',
        description: 'Builds the SET, signs it with `ssf.signingAlgorithm`, ' +
                     'queues it on the stream and — for a PUSH stream — ' +
                     'POSTs it to the receiver\'s delivery endpoint. On a ' +
                     'POLL stream it stays queued until the receiver asks.' +
                     '\n\n**IT IS THE ONLY WAY AN EVENT HAPPENS HERE.** ' +
                     'Nothing in this service watches a session and emits ' +
                     'when it changes: SSF defines no event about a session, ' +
                     'so a transmitter that invented one would be inventing ' +
                     'a vocabulary. That changes with CAEP.\n\nA failed ' +
                     'push is NOT retried and the event stays on the queue. ' +
                     'A mock that retried would make a receiver\'s one-shot ' +
                     'failure invisible — a client answering 500 then 202 ' +
                     'looks, from its own logs, like a client that works.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            stream_id: { type: 'string', description: 'The stream.' },
            type: { type: 'string',
                    description: 'The event type URI. It must be one the ' +
                                 'stream DELIVERS — the intersection of what ' +
                                 'the receiver requested and what this ' +
                                 'transmitter supports — and a refusal lists ' +
                                 'what that is.' },
            payload: { type: 'object',
                       description: 'The event\'s own members. A ' +
                                    'verification event takes an optional ' +
                                    '`state`; a stream-updated event takes a ' +
                                    'required `status` and an optional ' +
                                    '`reason`. An unrecognised member is ' +
                                    'CARRIED with a warning rather than ' +
                                    'refused: an event vocabulary extends, ' +
                                    'and a receiver is expected to ignore ' +
                                    'what it does not know.' },
            subject: { type: 'object',
                       description: 'Optional `sub_id` (RFC 9493), simple or ' +
                                    'complex. Neither SSF event takes one — ' +
                                    'both are about the STREAM — so this is ' +
                                    'here for the vocabularies that come ' +
                                    'next. Each format\'s member set is ' +
                                    'CLOSED and an extra member is refused ' +
                                    'by name.' },
            txn: { type: 'string',
                   description: 'Optional RFC 8417 `txn`, tying several ' +
                                'events to one act.' }
          },
          required: ['stream_id', 'type'],
          examples: [{ stream_id: 'ssf-0123456789ab',
            type: 'https://schemas.openid.net/secevent/ssf/event-type/' +
                  'verification',
            payload: { state: 'a-value-the-receiver-chose' } }],
          additionalProperties: false
        },
        responseDescription: 'The jti, whether it was delivered or only ' +
                             'queued, and what the receiver said.' },

      { action: 'delete', operationId: 'deleteSsfStream',
        summary: 'Delete a stream',
        description: 'The stream, its subjects and everything queued on it. ' +
                     'The receiver is NOT told — SSF has no event for "your ' +
                     'stream is gone", and a stream-updated with status ' +
                     'disabled would be a lie about something that still ' +
                     'exists. A receiver finds out on its next call, with a ' +
                     '404 naming the stream_id.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            stream_id: { type: 'string', description: 'The stream.' }
          },
          required: ['stream_id'],
          examples: [{ stream_id: 'ssf-0123456789ab' }],
          additionalProperties: false
        },
        responseDescription: 'Confirmation, or a refusal naming the ' +
                             'stream_id.' },

      { action: 'revive', operationId: 'reviveSsfStream',
        summary: 'Revive a dead push stream',
        description: 'A push stream whose pushes have all failed for ' +
                     '`ssf.deadStreamTimeoutS` is declared DEAD: nothing ' +
                     'more is pushed to it, its SETs go to its dead-letter ' +
                     'queue, and a sweep pushes one as a probe every period. ' +
                     'This revives it at once, so the next SET is pushed. ' +
                     'Refused for a stream that is not dead. The dead ' +
                     'letters are kept, and nothing resends them.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            stream_id: { type: 'string', description: 'The stream.' },
            reason: { type: 'string',
                      description: 'Optional; written on the stream\'s log.' }
          },
          required: ['stream_id'],
          examples: [{ stream_id: 'ssf-0123456789ab' }],
          additionalProperties: false
        },
        responseDescription: 'Confirmation, or a refusal naming the ' +
                             'stream_id or saying it is not dead.' },

      { action: 'clear-dead-letters', operationId: 'clearSsfDeadLetters',
        summary: 'Drop a stream\'s dead letters',
        description: 'Empties the stream\'s dead-letter queue: SETs that ' +
                     'could not be delivered, each kept with its reason for ' +
                     '`ssf.deadLetterRetentionS`. Nothing is sent. GET ' +
                     '/admin-api/ssf lists them per stream as `deadLetters`.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            stream_id: { type: 'string', description: 'The stream.' }
          },
          required: ['stream_id'],
          examples: [{ stream_id: 'ssf-0123456789ab' }],
          additionalProperties: false
        },
        responseDescription: 'How many were dropped, or a refusal naming the ' +
                             'stream_id.' },

      { action: 'clear-received', operationId: 'clearSsfReceived',
        summary: 'Drop what has been pushed AT this service',
        description: 'Empties the list `POST /ssf/receive` fills — this ' +
                     'service acting as a RECEIVER, which is the roles ' +
                     'reversed and what a client acting as the TRANSMITTER ' +
                     'pushes to. It touches no stream and no queue: those ' +
                     'are the transmitter half and have nothing to do with ' +
                     'this one.',
        requestBodyRequired: false,
        requestBody: {
          type: 'object',
          properties: {},
          examples: [{}],
          additionalProperties: false
        },
        responseDescription: 'How many were dropped.' }
    ] },

  // ---------------------------------------------------------------------
  // CAEP. A GET and a POST, and the POST is not optional: /admin/caep and
  // /admin/caep-sessions carry THREE controls between them — emit an event by
  // hand, reset one session's CAEP state, clear the register — and rule 7 is
  // about controls. All three call the same function the console's forms post
  // to, with `action` taken from the URL instead of from a hidden input.
  //
  // **THERE IS DELIBERATELY NO WAY TO END A SESSION FROM HERE**, and that is
  // the same reading of rule 7 that leaves SSF without a `create`. Emitting a
  // `session-revoked` says a session was revoked; it does not revoke one, and
  // a management API that did both would make "tell the receivers" and "sign
  // this person out" one act — which is exactly the conflation CAEP exists to
  // separate. /logout, /admin/logout and POST /admin-api/logout end sessions,
  // and a sign-out through any of them emits the event on its own.
  { method: 'GET', path: BASE + '/caep', tag: 'CAEP',
    operationId: 'getCaep',
    summary: 'The CAEP session register: what state each session is in and ' +
             'how many events of which type have been sent about it',
    description: 'Everything /admin/caep and /admin/caep-sessions draw, as ' +
                 'JSON. Per session: who it belongs to, when it was ' +
                 'established, the CAEP state it is in — established, ' +
                 'presented, revoked — its assurance level, its device ' +
                 'compliance, its risk level, the claims that have changed, ' +
                 'and a count per event type.\n\nTHE REGISTER OUTLIVES THE ' +
                 'SESSION AND THAT IS THE POINT. The session store forgets ' +
                 'one the moment it is signed out, so a row saying `revoked` ' +
                 'is the only remaining evidence that it existed and was ' +
                 'revoked.\n\nCAEP IS A VOCABULARY AND NOT A FAMILY. Its ' +
                 'events travel on SSF streams, are signed by the SSF signer ' +
                 'and are delivered by the two SSF deliveries, so ' +
                 'GET /admin-api/ssf is where the streams themselves are. ' +
                 '`streams` here says only which of them would take a CAEP ' +
                 'event at all, because a session with a count of zero ' +
                 'almost always means nobody asked for that type — and SSF ' +
                 'gives a receiver no other notice of that.',
    mirrors: 'GET /admin/caep',
    responseDescription: 'The register, the catalogue and the settings.',
    responseSchema: { $ref: '#/components/schemas/Caep' },
    handler: function (req, res) {
      log.debug("Entering the management API CAEP endpoint.");
      sendJson(res, 200, adminViews.caepJson(req));
      log.debug("Leaving the management API CAEP endpoint.");
    } },

  // THE SECOND CAEP READ, AND IT EXISTS BECAUSE OF RULE 7 RATHER THAN BECAUSE
  // THE DOCUMENT IS DIFFERENT. `/admin/caep-sessions` is a page of the console
  // and had no operation naming it — the GET above mirrors `/admin/caep`, and
  // one operation cannot mirror two pages. That gap was invisible until the
  // parity check in tests/vendored/admin_api.js named it.
  //
  // ONE OPERATION ANSWERS BOTH SHAPES, `?session=` deciding which, for the
  // reason /admin-api/permissions/groups gives: the list and the drill-down are
  // the same question at two scales and the console draws them from one
  // register, so two operations would be two places to disagree about what a
  // session's history is.
  { method: 'GET', path: BASE + '/caep/sessions', tag: 'CAEP',
    operationId: 'getCaepSessions',
    summary: 'The CAEP session register, searched and paged — or one ' +
             'session with everything that has been said about it',
    description: 'What /admin/caep-sessions draws. Without `session` it is ' +
                 'the register: one row per session this service has HELD, ' +
                 'including the ones it no longer holds, with its CAEP ' +
                 'state, assurance, device compliance, risk and a count per ' +
                 'event type — searched with `sessq` and paged with ' +
                 '`sessionsPage` and `per`. Beside it, `applications`: what ' +
                 'this transmitter has said to each RECEIVER across every ' +
                 'session, searched with `appq` and paged with ' +
                 '`applicationsPage`. That is the third question this page ' +
                 'answers and the one somebody arrives with once more than ' +
                 'one receiver exists — the sessions are per SESSION, the ' +
                 'streams are per STREAM, and this is per ' +
                 'APPLICATION.\n\nWith `session` it is that one session ' +
                 'opened out: the events actually sent about it, in order, ' +
                 'with the jti and the stream each went out on and what the ' +
                 'register noticed as it was applied, paged with ' +
                 '`eventsPage`.\n\n**THE REGISTER OUTLIVES THE SESSION AND ' +
                 'THAT IS THE POINT.** The session store forgets one the ' +
                 'moment it is signed out, so a row saying `revoked` is the ' +
                 'only remaining evidence that it existed and was revoked — ' +
                 'and it is why this is not the same list as GET ' +
                 '/admin-api/sessions, which is what is LIVE.\n\nA `session` ' +
                 'that names nothing answers 200 with `session: null` rather ' +
                 'than 404: this register is capped at ' +
                 '`caep.maxSessionsTracked` and drops the oldest, so an old ' +
                 'identifier coming back empty is an ordinary outcome and ' +
                 'not a missing resource.',
    mirrors: 'GET /admin/caep-sessions',
    parameters: [
      { name: 'sessq', in: 'query', required: false, schema: { type: 'string' },
        description: 'Narrows the register to rows whose username, `sub`, ' +
                     'session id, SSF subject or protocol contains this.' },
      { name: 'session', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'One session id. The reply is then that session and its ' +
                     'events rather than the list.' },
      { name: 'sessionsPage', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Which page of the register. Clamped, like every page ' +
                     'parameter here.' },
      { name: 'appq', in: 'query', required: false, schema: { type: 'string' },
        description: 'Narrows the per-receiver list to rows whose ' +
                     'application name, identifier or stream `aud` contains ' +
                     'this. It deliberately does NOT match event types: a ' +
                     'receiver that takes none of the eight is exactly the ' +
                     'row somebody is looking for when they ask why nothing ' +
                     'arrived.' },
      { name: 'applicationsPage', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Which page of the per-receiver list. It shares `per` ' +
                     'with the register above it, which is the arrangement ' +
                     'every page here that carries two lists has.' },
      { name: 'eventsPage', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Which page of ONE session\'s events, with `session`.' }
    ].concat(pagingParameters()),
    responseDescription: 'The register, or one session and its events.',
    responseSchema: { $ref: '#/components/schemas/Caep' },
    handler: function (req, res) {
      log.debug("Entering the management API CAEP sessions endpoint.");
      sendJson(res, 200, adminViews.caepSessionsJson(req));
      log.debug("Leaving the management API CAEP sessions endpoint.");
    } },

  { method: 'POST', route: BASE + '/caep/:action', tag: 'CAEP',
    mirrors: 'POST /admin/caep',
    handler: function (req, res) {
      log.debug("Entering the management API CAEP action endpoint.");
      const body = parseBody(req);
      // AWAITS, like the Shared Signals handler above and for the same
      // reason: emitting a CAEP event signs a JWS — possibly ML-DSA or
      // SLH-DSA on the worker pool — and then POSTs it to somebody else's
      // endpoint.
      adminActions.caepAction(withAction(req, body)).then(function (result) {
        if (!result.ok) {
          errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0053');
        }
        sendJson(res, result.ok ? 200 : 400, result);
        log.debug("Leaving the management API CAEP action endpoint.");
      }).catch(function (e) {
        errorCodes.mark(res, 'STS-API-0019');
        log.error('admin-api: the CAEP action threw: ' + e.message);
        sendJson(res, 500, { ok: false,
          errors: ['The action failed: ' + e.message] });
        log.debug("Leaving the management API CAEP action endpoint. Threw.");
      });
      log.debug("Leaving handler().");
    },
    actions: [
      { action: 'emit', operationId: 'emitCaepEvent',
        summary: 'Send one CAEP event about one session',
        description: 'Builds the payload, adds the four claims CAEP gives ' +
                     'every event, composes the SUBJECT from the session — ' +
                     'SSF\'s complex subject, naming the person AND the ' +
                     'session, because the person is not revoked and one ' +
                     'session of theirs is — and transmits it on every ' +
                     'stream that both delivers the type and covers that ' +
                     'subject.\n\nFIVE OF THE EIGHT ARE ONLY EVER PRODUCED ' +
                     'THIS WAY. No device reports compliance to this service ' +
                     'and no risk engine talks to it, so `credential-' +
                     'change`, `assurance-level-change`, `device-compliance-' +
                     'change`, `risk-level-change` and `token-claims-change` ' +
                     'have no act here that could cause them. The other ' +
                     'three fire on their own when `caep.autoEmit` is ' +
                     'on.\n\nA TYPE NO STREAM TAKES IS NOT AN ERROR. The ' +
                     'session\'s state is still updated and the reply says ' +
                     'nothing was sent, because "the event happened and ' +
                     'nobody had asked to hear about it" is a different fact ' +
                     'from a failure and is the one that is usually true.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            session_id: { type: 'string',
              description: 'The session it is about, from GET ' +
                           '/admin-api/caep.' },
            type: { type: 'string',
              description: 'The event type: a short name such as ' +
                           '`session-revoked`, or the whole URI.' },
            initiating_entity: { type: 'string',
              description: 'admin | user | policy | system. It is the ' +
                           'member that lets a receiver tell "an ' +
                           'administrator revoked this" from "a risk engine ' +
                           'did".' },
            payload: { type: 'string',
              description: 'The event-specific members, as JSON. Empty for ' +
                           'a conforming specimen of the type.' },
            reason_admin: { type: 'string',
              description: 'Why, for a log. Sent as an object keyed by ' +
                           '`caep.reasonLanguage` — CAEP makes it a language ' +
                           'map and a string there is the commonest mistake ' +
                           'in the profile.' },
            reason_user: { type: 'string',
              description: 'The same, in words meant for the person.' }
          },
          required: ['session_id', 'type'],
          examples: [{ session_id: 'abcdef0123456789abcdef01',
            type: 'session-revoked', initiating_entity: 'admin',
            reason_admin: 'Policy 4.2 was violated' },
          { session_id: 'abcdef0123456789abcdef01',
            type: 'device-compliance-change',
            payload: '{"previous_status":"compliant",' +
                     '"current_status":"not-compliant"}' }],
          additionalProperties: false
        },
        responseDescription: 'How many streams took it, or why none did.' },

      { action: 'reset-session', operationId: 'resetCaepSession',
        summary: 'Put one session\'s CAEP state back to where it started',
        description: 'Clears the state, the assurance level, the device ' +
                     'compliance, the risk level, the changed claims and ' +
                     'every counter on one row, keeping the row.\n\nIT SIGNS ' +
                     'NOBODY OUT. This register is a record of what has been ' +
                     'SAID about a session; resetting it forgets the record. ' +
                     'The session itself is untouched and every token issued ' +
                     'on it is still good, which is the distinction this ' +
                     'whole page rests on.\n\nIt is a reset and not a delete ' +
                     'because the identity and the sign-in instant are still ' +
                     'true — a delete would take the row off the page, which ' +
                     'reads as the session having gone.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            session_id: { type: 'string', description: 'The session.' }
          },
          required: ['session_id'],
          examples: [{ session_id: 'abcdef0123456789abcdef01' }],
          additionalProperties: false
        },
        responseDescription: 'Confirmation, or a refusal naming the id.' },

      { action: 'clear', operationId: 'clearCaepSessions',
        summary: 'Drop every row in the CAEP session register',
        description: 'Forgets what has been said about every session. ' +
                     'Nobody is signed out, no stream is touched and no ' +
                     'queued event is dropped — those are the SSF half, at ' +
                     'POST /admin-api/ssf/delete and /clear-received.\n\nIt ' +
                     'is worth knowing what this throws away: rows for ' +
                     'sessions this service NO LONGER HOLDS are the only ' +
                     'evidence that those sessions existed and were revoked, ' +
                     'and nothing else in this service records it.',
        requestBodyRequired: false,
        requestBody: {
          type: 'object',
          properties: {},
          examples: [{}],
          additionalProperties: false
        },
        responseDescription: 'How many rows were dropped.' }
    ] },

  // ---------------------------------------------------------------------
  // RISC. A GET, a second GET and a POST, on exactly the CAEP block's terms
  // and for its reasons: /admin/risc and /admin/risc-accounts carry three
  // controls between them — emit an event by hand, reset one account's RISC
  // state, clear the register — and rule 7 is about controls.
  //
  // **THERE IS DELIBERATELY NO WAY TO DISABLE OR DELETE AN ACCOUNT FROM
  // HERE**, which is the same reading of rule 7 that leaves CAEP without a
  // way to end a session. Emitting an `account-disabled` says an account was
  // disabled; it does not disable one, and a management API that did both
  // would make "tell the receivers" and "deprovision this person" one act —
  // which is exactly the conflation RISC exists to separate. The directory
  // half is POST /admin-api/users and SCIM, and a write through either emits
  // the event on its own when `risc.autoEmit` is on.
  { method: 'GET', path: BASE + '/risc', tag: 'RISC',
    operationId: 'getRisc',
    summary: 'The RISC account register: what state each account is in and ' +
             'how many events of which type have been sent about it',
    description: 'Everything /admin/risc and /admin/risc-accounts draw, as ' +
                 'JSON. Per account: who it is, the SSF subject a receiver ' +
                 'was sent, and THREE states rather than one — the lifecycle ' +
                 '(active, disabled, purged), the RISC section 2.8 opt-out ' +
                 'state (opt-in, opt-out-initiated, opt-out) and whether a ' +
                 'credential has been reported compromised. They move ' +
                 'independently: an account can be opted out and perfectly ' +
                 'healthy, or compromised and still enabled.\n\nTHE ' +
                 'REGISTER OUTLIVES THE ACCOUNT, MORE STARKLY THAN THE CAEP ' +
                 'ONE OUTLIVES A SESSION. A purged account is gone from the ' +
                 'directory entirely, so the row whose lifecycle says ' +
                 '`purged` is the only remaining evidence anywhere that this ' +
                 'service ever told anybody it was.\n\nRISC IS A VOCABULARY ' +
                 'AND NOT A FAMILY. Its events travel on SSF streams, are ' +
                 'signed by the SSF signer and are delivered by the two SSF ' +
                 'deliveries, so GET /admin-api/ssf is where the streams ' +
                 'themselves are. `streams` here says only which of them ' +
                 'would take a RISC event at all.\n\n`suppressed` is the one ' +
                 'counter with no CAEP equivalent: events this transmitter ' +
                 'built and did NOT send, because the account is in the ' +
                 'opt-out state and `risc.honourOptOut` is on. It is the ' +
                 'only number here that says a receiver heard nothing ON ' +
                 'PURPOSE.',
    mirrors: 'GET /admin/risc',
    responseDescription: 'The register, the catalogue and the settings.',
    responseSchema: { $ref: '#/components/schemas/Risc' },
    handler: function (req, res) {
      log.debug("Entering the management API RISC endpoint.");
      sendJson(res, 200, adminViews.riscJson(req));
      log.debug("Leaving the management API RISC endpoint.");
    } },

  // THE SECOND RISC READ, for the reason the second CAEP read exists:
  // /admin/risc-accounts is a page of the console and one operation cannot
  // mirror two pages. `?account=` decides the shape, the list or the
  // drill-down, because they are the same question at two scales.
  { method: 'GET', path: BASE + '/risc/accounts', tag: 'RISC',
    operationId: 'getRiscAccounts',
    summary: 'The RISC account register, searched and paged — or one ' +
             'account with everything that has been said about it',
    description: 'What /admin/risc-accounts draws. Without `account` it is ' +
                 'the register: one row per account this service has been ' +
                 'told anything about, including ones that no longer exist, ' +
                 'searched with `acctq` and paged with `accountsPage` and ' +
                 '`per`. Beside it, `applications`: what this transmitter ' +
                 'has said to each RECEIVER across every account, searched ' +
                 'with `rappq`.\n\nWith `account` it is that one account ' +
                 'opened out: the events actually sent about it, in order, ' +
                 'with the jti and the stream each went out on and what the ' +
                 'register noticed as it was applied, paged with ' +
                 '`eventsPage`.\n\nTHE SEARCH REACHES IDENTIFIERS THE ' +
                 'ACCOUNT NO LONGER HAS, and that is not thoroughness: ' +
                 '`identifier-changed` is an event ABOUT the key, so the ' +
                 'address a caller is holding — out of a log, off an event ' +
                 'it is chasing — is routinely the superseded one. A search ' +
                 'that matched only the current spelling would hide exactly ' +
                 'the row somebody came to find.\n\nAn `account` that names ' +
                 'nothing answers 200 with `account: null` rather than 404: ' +
                 'this register is capped at `risc.maxAccountsTracked` and ' +
                 'drops the oldest.',
    mirrors: 'GET /admin/risc-accounts',
    parameters: [
      { name: 'acctq', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'Narrows the register to rows whose account id, ' +
                     'username, `sub`, email address, telephone number, SSF ' +
                     'subject, directory DN or any FORMER identifier ' +
                     'contains this.' },
      { name: 'account', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'One account id. The reply is then that account and ' +
                     'its events rather than the list.' },
      { name: 'accountsPage', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Which page of the register. Clamped, like every page ' +
                     'parameter here.' },
      { name: 'rappq', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'Narrows the per-receiver list to rows whose ' +
                     'application name, identifier or stream `aud` contains ' +
                     'this. It deliberately does NOT match event types: a ' +
                     'receiver that takes none of the fourteen is exactly ' +
                     'the row somebody is looking for when they ask why ' +
                     'nothing arrived.' },
      { name: 'rapplicationsPage', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Which page of the per-receiver list. It shares `per` ' +
                     'with the register above it.' },
      { name: 'eventsPage', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Which page of ONE account\'s events, with `account`.' }
    ].concat(pagingParameters()),
    responseDescription: 'The register, or one account and its events.',
    responseSchema: { $ref: '#/components/schemas/Risc' },
    handler: function (req, res) {
      log.debug("Entering the management API RISC accounts endpoint.");
      sendJson(res, 200, adminViews.riscAccountsJson(req));
      log.debug("Leaving the management API RISC accounts endpoint.");
    } },

  { method: 'POST', route: BASE + '/risc/:action', tag: 'RISC',
    mirrors: 'POST /admin/risc',
    handler: function (req, res) {
      log.debug("Entering the management API RISC action endpoint.");
      const body = parseBody(req);
      // AWAITS, like the CAEP handler above and for the same reason.
      adminActions.riscAction(withAction(req, body)).then(function (result) {
        if (!result.ok) {
          errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0054');
        }
        sendJson(res, result.ok ? 200 : 400, result);
        log.debug("Leaving the management API RISC action endpoint.");
      }).catch(function (e) {
        errorCodes.mark(res, 'STS-API-0020');
        log.error('admin-api: the RISC action threw: ' + e.message);
        sendJson(res, 500, { ok: false,
          errors: ['The action failed: ' + e.message] });
        log.debug("Leaving the management API RISC action endpoint. Threw.");
      });
      log.debug("Leaving handler().");
    },
    actions: [
      { action: 'emit', operationId: 'emitRiscEvent',
        summary: 'Send one RISC event about one account',
        description: 'Builds the payload, composes the SUBJECT from the ' +
                     'account in the format `risc.subjectFormat` names, and ' +
                     'transmits it on every stream that both delivers the ' +
                     'type and covers that subject.\n\nELEVEN OF THE ' +
                     'FOURTEEN CARRY NO PAYLOAD MEMBERS AT ALL, so for those ' +
                     'the subject is the entire message and `payload` is ' +
                     'left empty. Only `credential-compromise` has a ' +
                     'REQUIRED member, `credential_type`, which RISC defines ' +
                     'by reference to CAEP\'s `credential-change` — the two ' +
                     'lists are the same list.\n\nTEN OF THE FOURTEEN ARE ' +
                     'ONLY EVER PRODUCED THIS WAY. No breach corpus is ' +
                     'searched by this service and no recovery flow runs in ' +
                     'it. The other four fire on their own when the ' +
                     'DIRECTORY changes and `risc.autoEmit` is on — a person ' +
                     'deleted, `active` going false or true, a mail address ' +
                     'or telephone number moving.\n\nFOUR OF THEM CHANGE ' +
                     'REAL STATE WHEN THEY GO. RISC section 2.8 defines each ' +
                     'opt-out event as "the account is in this state" rather ' +
                     'than as a report that it moved, so emitting `opt-out-' +
                     'effective` here IS the transition — and the next event ' +
                     'about that account is suppressed while ' +
                     '`risc.honourOptOut` is on.\n\nAN ACCOUNT THIS SERVICE ' +
                     'HAS NEVER HELD IS ACCEPTED, which is the opposite of ' +
                     'what emitCaepEvent does with an unknown session. A ' +
                     'session identifier this service never minted is one it ' +
                     'can compose no subject from; an account is a person, ' +
                     'and RISC is aimed ACROSS providers, so the account a ' +
                     'receiver is warned about is usually one it has never ' +
                     'seen.\n\nA TYPE NO STREAM TAKES IS NOT AN ERROR. The ' +
                     'account\'s state is still updated and the reply says ' +
                     'nothing was sent.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            account_id: { type: 'string',
              description: 'The account it is about, from GET ' +
                           '/admin-api/risc. A name no row carries is ' +
                           'accepted and opens one.' },
            type: { type: 'string',
              description: 'The event type: a short name such as ' +
                           '`account-disabled`, or the whole URI.' },
            payload: { type: 'string',
              description: 'The event-specific members, as JSON. Empty for ' +
                           'a conforming specimen of the type, which is what ' +
                           'eleven of the fourteen always are. Note the ' +
                           'HYPHEN in `identifier-changed`\'s `new-value`: ' +
                           'it is the only hyphenated member name in any of ' +
                           'the three vocabularies, and `new_value` is ' +
                           'carried and silently ignored by a receiver.' },
            reason_admin: { type: 'string',
              description: 'Why, for a log. Sent as an object keyed by ' +
                           '`risc.reasonLanguage`. It reaches the wire for ' +
                           'ONE of the fourteen types — RISC gives the ' +
                           'reason members to `credential-compromise` and to ' +
                           'nothing else — and is dropped by the catalogue ' +
                           'on any other, rather than being sent as a member ' +
                           'the specification does not define.' },
            reason_user: { type: 'string',
              description: 'The same, in words meant for the person. Same ' +
                           'one type.' }
          },
          required: ['account_id', 'type'],
          examples: [{ account_id: 'alice', type: 'account-disabled',
            payload: '{"reason":"hijacking"}',
            reason_admin: 'Credential seen in a breach corpus' },
          { account_id: 'alice', type: 'identifier-changed',
            payload: '{"new-value":"alice.roe@example.com"}' },
          { account_id: 'alice', type: 'credential-compromise',
            payload: '{"credential_type":"password"}' }],
          additionalProperties: false
        },
        responseDescription: 'How many streams took it, why none did, or ' +
                             'that the opt-out gate suppressed it.' },

      { action: 'reset-account', operationId: 'resetRiscAccount',
        summary: 'Put one account\'s RISC state back to where it started',
        description: 'Clears the lifecycle, the opt-out state, the ' +
                     'credential standing, the identifier history and every ' +
                     'counter on one row, keeping the row.\n\nIT DISABLES ' +
                     'AND DELETES NOBODY. This register is a record of what ' +
                     'has been SAID about an account; resetting it forgets ' +
                     'the record. The directory entry is untouched, which is ' +
                     'the distinction this whole page rests on — and it is ' +
                     'sharper here than for a session, because a row saying ' +
                     '`purged` may describe a person who really is gone.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            account_id: { type: 'string', description: 'The account.' }
          },
          required: ['account_id'],
          examples: [{ account_id: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'Confirmation, or a refusal naming the id.' },

      { action: 'clear', operationId: 'clearRiscAccounts',
        summary: 'Drop every row in the RISC account register',
        description: 'Forgets what has been said about every account. ' +
                     'Nobody is disabled, nobody is deleted and no directory ' +
                     'entry is touched.\n\nIt is worth knowing what this ' +
                     'throws away: a row for an account that has been PURGED ' +
                     'is the only evidence anywhere in this service that the ' +
                     'account existed and that receivers were told it was ' +
                     'deleted. The directory cannot supply it, because the ' +
                     'entry is gone.',
        requestBodyRequired: false,
        requestBody: {
          type: 'object',
          properties: {},
          examples: [{}],
          additionalProperties: false
        },
        responseDescription: 'How many rows were dropped.' }
    ] },

  { method: 'GET', path: BASE + '/scim', tag: 'SCIM',
    operationId: 'getScim',
    summary: 'The SCIM 2.0 provisioning surface, and what it has been asked ' +
             'to do',
    description: 'Counters and capabilities in one reply. The counters say ' +
                 'which SCIM operation was performed how many times, on ' +
                 'which resource type, and what was refused with which ' +
                 '`scimType`; every operation and resource type is listed ' +
                 'INCLUDING the ones at zero, because "does this server do ' +
                 'PATCH" is otherwise answered by omission. The capabilities ' +
                 'say what the endpoints are, what SCIM here deliberately ' +
                 'does not do, and which LDAP attribute each SCIM member ' +
                 'is.\n\nTHERE IS NO POST BESIDE THIS ONE and that is not a ' +
                 'gap: everything about SCIM that can be changed is a ' +
                 'configuration row — `scim.enabled`, the three limits and ' +
                 'the authentication settings — so POST ' +
                 '/admin-api/config/set is already the operation for it. The ' +
                 'console page has no form on it either, which is the parity ' +
                 'rule holding rather than being broken.\n\nWHAT SCIM WROTE ' +
                 'is not here: it went into the embedded directory, so a ' +
                 'person provisioned over SCIM is on /admin-api/users and ' +
                 'their groups are on /admin-api/groups. There is no second ' +
                 'store to report.',
    mirrors: 'GET /admin/scim',
    responseDescription: 'The counters and the capabilities.',
    responseSchema: { $ref: '#/components/schemas/Scim' },
    handler: function (req, res) {
      log.debug("Entering the management API SCIM endpoint.");
      sendJson(res, 200, adminViews.scimJson(req));
      log.debug("Leaving the management API SCIM endpoint.");
    } },

  // WHAT THAT SURFACE IS ACTUALLY DOING, as opposed to what it is. The
  // operation above mirrors /admin/scim, which is a page about the SURFACE;
  // this one mirrors /admin/scim/monitor, which the console files under
  // MONITORING because where a page goes is decided by the question it
  // answers. Both read one set of counters in common/admin_stats.js through
  // two functions, so there is no second tally for them to disagree over.
  //
  // NO POST BESIDE IT, and that is rule 7 read exactly rather than by shape:
  // the page it mirrors has no control. A reset was refused rather than
  // forgotten — a console that could zero its own monitoring would make every
  // number on it a number somebody might have zeroed, and the audit log, which
  // is the durable record, cannot be reset either.
  // ---------------------------------------------------------------------------
  // PKI — the certificate authority this service maintains per trust realm.
  //
  // Rule 7: `/admin/pki` has four controls, so this API has the same four
  // through the SAME functions — `pkiAction()` in `admin-ui/pki_admin.js` —
  // and decides nothing that console does not.
  //
  // **THE MODULE IS REQUIRED IN THE ORDINARY DIRECTION AND NEEDS NO SLOT**,
  // which is the one thing about this resource worth knowing. That module sits
  // at 18a in `common/protocol_stack.js` — after `admin-ui/admin` and BEFORE
  // this file — so by the time this require runs it is a cache hit and
  // registers nothing. It requires only `admin.js` and `common/pki.js`, and
  // `pki.js` is a LIBRARY (rule 3), so there is no route this could move and
  // no cycle it could close.
  // ---------------------------------------------------------------------------
  { method: 'GET', path: BASE + '/pki', tag: 'PKI',
    operationId: 'getPki',
    summary: 'The certificate authority this trust realm holds, and what has ' +
             'been issued from it',
    description: 'Everything /admin/pki draws: the three CA tiers with their ' +
                 'subjects, serials, validity, key and signature algorithms, ' +
                 'thumbprints and CERTIFICATES; the key and signature ' +
                 'algorithms a build may ask for; the two assertion PROFILES ' +
                 'a key pair may be issued for, with the attributes each one ' +
                 'writes; and every application in this realm that holds an ' +
                 'issued key pair or declares an assertion issuer — **ONE ' +
                 'ROW PER APPLICATION AND PER PROFILE**, so an application ' +
                 'holding both an RFC 7523 and an RFC 7522 key pair appears ' +
                 'twice. A single row with a pair of columns was the first ' +
                 'shape of this and was wrong for a reason worth keeping: ' +
                 'every fact on it — the key handle, the expiry, the ' +
                 'declared issuer, whether there is a key pair to take off — ' +
                 'is per profile.\n\n**NO PRIVATE KEY IS EVER IN THIS ' +
                 'REPLY.** `common/pki.js` drops every one of them on the ' +
                 'way out, so a caller here could not leak the Root\'s key ' +
                 'by forgetting. The CERTIFICATES are in full, because a ' +
                 'certificate is the half of a key pair that is meant to be ' +
                 'handed around and the Root is the one thing a relying ' +
                 'party has to be given out of band. An application\'s own ' +
                 'private key is on its directory entry as ' +
                 '`oauthAssertionPrivateKey`, sealed under the same ' +
                 'key-encryption key as the hierarchy wherever that key ' +
                 'outlives the process, and opened for a caller that holds a ' +
                 'credential.\n\n**IT IS PER REALM.** A trust realm is a ' +
                 'logical identity service with its own signing key and its ' +
                 'own applications, so a CA shared across realms would be ' +
                 'one authority vouching for several services. Reach this ' +
                 'under a realm prefix for that realm\'s hierarchy.\n\n**AND ' +
                 'SO IS `tree`, SINCE 2026-09-11 — IT NARROWED AND THIS IS ' +
                 'THE RECORD OF IT.** It carried the Root, the process ' +
                 'branch and EVERY REALM\'S Intermediate for a day; it now ' +
                 'carries the Root, the process branch (TLS and SPIFFE, ' +
                 'which certify sockets every realm answers on) and the ' +
                 'Intermediate of the realm THIS REQUEST WAS REACHED IN, ' +
                 'with its Issuing CAs. `revocation` narrowed with it, so a ' +
                 'Revoke here can only name an authority this realm is ' +
                 'under. Reach the resource under another realm\'s prefix ' +
                 'for that realm\'s branch — which is the same answer the ' +
                 'console gives, because this reply and that page are one ' +
                 'function.\n\n**REVOCATION IS PUBLISHED AND NEVER ' +
                 'CONSULTED, SINCE 2026-09-11.** Every authority signs a CRL ' +
                 '(/pki/crl/{scope}/{ca}) and answers OCSP ' +
                 '(/pki/ocsp/{scope}/{ca}); `revocation` in the reply is the ' +
                 'REGISTER — one entry per authority with what it issued, ' +
                 'what is on its list, and its addresses over http and ldap ' +
                 '— and `revocation-certificate` below puts a serial on one. ' +
                 'What this service does NOT do is consult a list, its own ' +
                 'included, so a certificate revoked here still ' +
                 'authenticates here. **AND `revoke` BELOW IS A DIFFERENT ' +
                 'ACT WITH THE SAME WORD IN IT**: it takes a key pair off an ' +
                 'application and puts nothing on any list. `revocationNote` ' +
                 'and `residency` are the durable statement of what each ' +
                 'means.',
    mirrors: 'GET /admin/pki',
    // THE TWO KEY-PAIR TABLES ARE PAGED ON THE PAGE (2026-09-13), and the
    // reply says which page each drew without slicing either list:
    // `issued` and `persons` stay WHOLE, because every reader of this
    // resource looks an application up in `issued` by identifier and a
    // reply holding one page would answer "not there" about page two.
    // `admin-ui/pki_admin.js`'s `keyPairPaging()` argues it.
    parameters: pagingParameters().filter(function (one) {
      return one.name === 'per';
    }).concat(detailPagingParameters([
      { name: 'issued',
        description: 'The Applications table on /admin/pki, twenty-five ' +
                     'rows by default. `issued` itself is the WHOLE list ' +
                     'whatever page is asked for; `issuedPaging` says which ' +
                     'rows the page drew.' },
      { name: 'persons',
        description: 'The People table on /admin/pki, paged by PERSON — a ' +
                     'person holding both profiles is one member of ' +
                     '`persons` and two rows on the page. `persons` is the ' +
                     'WHOLE list; `personsPaging` says which people the ' +
                     'page drew.' }
    ])),
    responseDescription: 'The hierarchy, the algorithm vocabularies, the two ' +
                         'assertion profiles, and one row per application ' +
                         'per profile for those holding an issued key pair, ' +
                         'with `issuedPaging` and `personsPaging` beside ' +
                         'the two lists.',
    handler: function (req, res) {
      log.debug("Entering the management API PKI endpoint.");
      sendJson(res, 200, pkiAdmin.pkiView(req));
      log.debug("Leaving the management API PKI endpoint.");
    } },

  // ---------------------------------------------------------------------
  // RULE 7 FOR THE CERTIFICATE DETAILS DIALOG (2026-09-13). `/admin/pki` and
  // `/admin/crypto-metadata` open a certificate's every field and its trust
  // chain over the page; this is the same answer for a machine, from the same
  // view layer — so a certificate cannot be openable on one door and unknown
  // on the other. Without `certificate` it is the LIST a caller finds the
  // fingerprint in.
  // ---------------------------------------------------------------------
  { method: 'GET', path: BASE + '/certificates', tag: 'PKI',
    operationId: 'getCertificates',
    summary: 'Every certificate this trust realm holds, or one of them with ' +
             'every X.509 field and its trust chain',
    description: 'Without `certificate`: a LIST of every certificate this ' +
                 'service holds in the trust realm the request was reached ' +
                 'in — the service Root, the process branch (TLS and ' +
                 'SPIFFE), this realm\'s Intermediate, Issuing CAs and what ' +
                 'they certified, the signing-key certificates, the ' +
                 'certificate authority workbench, the TLS listener ' +
                 'certificates, the SPIFFE authorities, and the key pairs ' +
                 'issued to applications and people — one row per ' +
                 'certificate with every place it appears.\n\nWith ' +
                 '`certificate`: that certificate described WHOLE — the ' +
                 'tbsCertificate in RFC 5280 section 4.1\'s order (version, ' +
                 'serial, inner signature algorithm, issuer and subject ' +
                 'RDN by RDN, validity with its ASN.1 time type, the ' +
                 'public key with its parameters and bytes, both unique ' +
                 'identifiers, every extension decoded), the outer ' +
                 'signature algorithm and value, both fingerprints — and ' +
                 '`chain`, the path to a self-signed certificate BUILT from ' +
                 'what this service holds by matching each issuer\'s name ' +
                 'AND verifying its signature, with `chainStatus` saying ' +
                 'where and why a path stopped. Every certificate in the ' +
                 'chain is described with the same fields.\n\n**A ' +
                 'certificate is named by its SHA-256 fingerprint and looked ' +
                 'up, never sent.** A fingerprint of anything this realm ' +
                 'does not hold is refused, so a certificate from another ' +
                 'realm is reached under that realm\'s prefix. Mirrors the ' +
                 'dialog both pages open with `?certificate=`.',
    mirrors: 'GET /admin/pki and GET /admin/crypto-metadata',
    parameters: [
      { name: 'certificate', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'A SHA-256 certificate fingerprint, 64 hexadecimal ' +
                     'digits with or without colons — the `fingerprint` of ' +
                     'a row of the list. Returns that certificate\'s ' +
                     'details instead of the list.' },
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the subject, the issuer or where the ' +
                     'certificate appears, case-insensitive.' }
    ].concat(pagingParameters()),
    responseDescription: 'The list, or one certificate with its chain.',
    handler: function (req, res) {
      log.debug("Entering the management API certificates endpoint.");
      if (!String(req.query.certificate || '').trim()) {
        sendJson(res, 200, certificateViews.listView(req));
        log.debug("Leaving the management API certificates endpoint. List.");
        return;
      }
      certificateViews.detailsView(req).then(function (view) {
        if (!view.ok) {
          const code = errorCodes.codeOf(view) || 'STS-API-0080';
          errorCodes.mark(res, code);
          sendJson(res, code === 'STS-ADMIN-0641' ? 404
            : (code === 'STS-ADMIN-0642' ? 500 : 400), view);
          log.debug("Leaving the management API certificates endpoint. " +
                    "Refused.");
          return;
        }
        sendJson(res, 200, view);
        log.debug("Leaving the management API certificates endpoint. One.");
      }).catch(function (e) {
        errorCodes.mark(res, 'STS-ADMIN-0642');
        log.error(errorCodes.tag('STS-ADMIN-0642') + 'admin_api: the ' +
                  'certificate details view failed: ' + e.message);
        sendJson(res, 500, { ok: false, errors: [e.message] });
      });
    } },

  { method: 'POST', route: BASE + '/pki/:action', tag: 'PKI',
    // TWO CONSOLE PATHS, because the pane answers with a PAGE rather than a
    // redirect and needs a route of its own to do it. This field is how the
    // console suite builds "console paths that take a POST", so a control
    // posting somewhere other than its list page has to be named here or that
    // check quietly stops covering it — which is what /admin/users/new
    // records.
    mirrors: 'POST /admin/pki, POST /admin/pki/certificate and POST ' +
             '/admin/pki/person',
    handler: function (req, res) {
      log.debug("Entering the management API PKI action endpoint.");
      const body = parseBody(req);
      // **AWAITED, AND THE REJECTION IS TURNED INTO A REFUSAL.** Issuing a
      // certificate is Web Crypto all the way down, so this is the second
      // action handler in this API that resolves rather than returning
      // (`/ssf/:action` is the first, and for a related reason: it signs and
      // then POSTs). Express 4 does not look at what a handler returns, so an
      // unhandled rejection here would be a request that never gets an answer.
      pkiAdmin.pkiAction(withAction(req, body)).then(function (result) {
        if (!result.ok) {
          errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0055');
        }
        sendJson(res, result.ok ? 200 : 400, result);
        log.debug("Leaving the management API PKI action endpoint.");
      }).catch(function (e) {
        errorCodes.mark(res, 'STS-API-0021');
        log.error('the management API PKI action threw: ' +
                  (e && e.stack ? e.stack : e));
        sendJson(res, 500, { ok: false,
                             errors: ['That action failed: ' +
                                      (e && e.message ? e.message : e)] });
      });
      log.debug("Leaving handler().");
    },
    actions: [
      { action: 'build', operationId: 'buildPkiChain',
        summary: 'Build this realm\'s certificate authority — all three tiers',
        description: 'Root CA, Intermediate CA and Issuing CA, generated and ' +
                     'signed in one act.\n\n**ALL THREE OR NONE, and that is ' +
                     'not laziness.** A trust chain is only worth anything ' +
                     'whole: an Issuing CA with no Intermediate above it is ' +
                     'a two-tier chain wearing a three-tier name, and a ' +
                     'half-built hierarchy is exactly the state in which ' +
                     'somebody issues a certificate that verifies here and ' +
                     'nowhere else. A failure at any tier stores ' +
                     'nothing.\n\n**CALLING IT AGAIN REPLACES WHAT IS ' +
                     'THERE**, and everything issued from the old hierarchy ' +
                     'chains to nothing the moment it does. This service ' +
                     'keeps no copy of what it issued, so none of it can be ' +
                     'listed — the key pairs are on the application entries ' +
                     'and go on SIGNING; what stops is this service being ' +
                     'able to see that it issued them.\n\n**WHERE IT ' +
                     'SURVIVES A RESTART depends on the mode.** In product ' +
                     'mode the hierarchy is written to `sts_keys`, sealed ' +
                     'under the same key-encryption key as the signing keys. ' +
                     'In development — the default — it lives exactly as ' +
                     'long as the process, which is the rule the signing key ' +
                     'follows and for the same reason.',
        requestBodyRequired: false,
        requestBody: {
          type: 'object',
          properties: {
            keyAlg: { type: 'string',
                      description: 'One of the ids in `keyAlgorithms` on GET ' +
                                   '/admin-api/pki: rsa-2048, rsa-3072, ' +
                                   'rsa-4096, ec-p256, ec-p384, ec-p521 or ' +
                                   'ed25519. One algorithm for all three ' +
                                   'tiers — the LEAF\'s signature algorithm ' +
                                   'is decided by the Issuing CA\'s key, and ' +
                                   'that is what a client library has to be ' +
                                   'able to verify. Defaults to ' +
                                   '`pki.keyAlgorithm`.' },
            signatureAlg: { type: 'string',
                            description: 'One of the ids in ' +
                                         '`signatureAlgorithms`. OMIT IT for ' +
                                         '"the right one for the key ' +
                                         'algorithm", which is almost always ' +
                                         'what is wanted: an EC key\'s ' +
                                         'digest is decided by its CURVE, so ' +
                                         'naming one here can hand a P-521 ' +
                                         'key SHA-256 — legal, verifying, ' +
                                         'and nobody\'s intention. A pair ' +
                                         'whose families disagree is refused ' +
                                         'with the list beside it.' },
            organisation: { type: 'string',
                            description: 'The O= every tier carries, and ' +
                                         'what the tiers are named after ' +
                                         'when no common name is given. ' +
                                         'Defaults to `pki.organisation`.' },
            country: { type: 'string',
                       description: 'The C=, two letters, optional. It is ' +
                                    'encoded as a PrintableString, which is ' +
                                    'interoperability rather than taste — ' +
                                    'several validators refuse a UTF8String ' +
                                    'country and report it as a signature ' +
                                    'problem.' },
            cn_root: { type: 'string', description: 'The Root CA\'s common ' +
                                                    'name.' },
            cn_intermediate: { type: 'string',
                               description: 'The Intermediate CA\'s common ' +
                                            'name.' },
            cn_issuing: { type: 'string',
                          description: 'The Issuing CA\'s common name.' },
            years_root: { type: 'integer',
                          description: 'How long the Root is valid. Defaults ' +
                                       'to the certificate profile\'s own ' +
                                       'twenty years.' },
            years_intermediate: { type: 'integer',
                                  description: 'Ten by default.' },
            years_issuing: { type: 'integer', description: 'Five by default.' }
          },
          examples: [{ keyAlg: 'ec-p384', organisation: 'Acme',
                       country: 'US' }],
          additionalProperties: false
        },
        responseDescription: 'The hierarchy that was built, without its ' +
                             'private keys.' },

      { action: 'issue', operationId: 'issuePkiKeyPair',
        summary: 'Issue a signing key pair to an application — or, with ' +
                 'target=person, to somebody in ou=users — from the ' +
                 'Issuing CA',
        description: 'Generates a key pair, signs a leaf certificate for it ' +
                     'with this realm\'s Issuing CA, and writes the whole ' +
                     'lot onto that application\'s directory ' +
                     'entry.\n\n**WHICH ATTRIBUTES DEPENDS ON `purpose`, AND ' +
                     'THE TWO SETS SHARE NONE.** `jwt` (the default, RFC ' +
                     '7523) writes seven — `oauthAssertionPrivateKey`, ' +
                     '`oauthAssertionCertificate`, ' +
                     '`oauthAssertionCertificateChain`, `oauthAssertionJwks` ' +
                     '(with `x5c` and `x5t#S256` on the key), ' +
                     '`oauthAssertionKid`, `oauthAssertionExpiresAt` and ' +
                     '`oauthAssertionKeySource` (`issued`). ' +
                     '`saml` (RFC 7522) writes six under ' +
                     '`oauthSamlAssertion*`, with no JWKS among them because ' +
                     'SAML has none — what a party registers for that ' +
                     'profile IS a certificate — and with a ' +
                     '`oauthSamlAssertionThumbprint` where the other has a ' +
                     '`kid`, because those are the handles the two formats ' +
                     'actually carry.\n\n**AN APPLICATION MAY HOLD BOTH KEY ' +
                     'PAIRS AND NEITHER CAN SIGN FOR THE OTHER\'S PROFILE.** ' +
                     'No verifier reads the other set, so issuing one leaves ' +
                     'the other untouched and taking one off leaves the ' +
                     'other working. The SAML leaf also carries the RFC 7522 ' +
                     'grant-type URI as a second URI subjectAltName, so a ' +
                     'certificate read out of context says which profile it ' +
                     'was issued for.\n\n**THIS SERVICE KEEPS NO SECOND COPY ' +
                     'OF THE PRIVATE KEY.** `common/pki.js` hands it over ' +
                     'once and forgets it, so the entry is where it ' +
                     'lives.\n\n**AND IT IS SEALED THERE.** AES-256-GCM ' +
                     'under the key-encryption key, through ' +
                     '`common/keystore.js` — the same mechanism and the same ' +
                     'key that seal this service\'s own signing keys and the ' +
                     'CA hierarchy this leaf was issued from — wherever that ' +
                     'key outlives the process, which is product mode. So an ' +
                     'ldapsearch on TCP 389 where every bind succeeds, an ' +
                     'ldif file, a database row and a backup of either hold ' +
                     '`$aesgcm$…`. `GET /admin-api/applications` opens it ' +
                     'for you, because it comes through ' +
                     '`common/applications.js` and you are holding an ' +
                     '`admin:read` token; in development mode it is in the ' +
                     'clear, where the key-encryption key is ephemeral and ' +
                     'would not survive the restart the entry does. Issuing ' +
                     'again replaces.\n\n**THE LEAF IS A `digital-signature` ' +
                     'CERTIFICATE and deliberately carries no extended key ' +
                     'usage.** What it signs is a JWT, not a TLS handshake; ' +
                     'giving it `clientAuth` would make it usable for RFC ' +
                     '8705 as well, which is a DIFFERENT credential with a ' +
                     'different registration attribute, and one certificate ' +
                     'quietly doing both is how a deployment ends up unable ' +
                     'to revoke either.\n\n**A KEY PAIR IS NOT A TRUST ' +
                     'DECISION.** It lets the application SIGN, which is all ' +
                     'RFC 7523 section 2.2 (client authentication) needs. ' +
                     'For section 2.1 — the authorization grant — the `iss` ' +
                     'it will use must also be declared on ' +
                     '`oauthAssertionIssuer`, through POST ' +
                     '/admin-api/applications/add. RFC 7522 is the same two ' +
                     'acts with its own declaration, ' +
                     '`oauthSamlAssertionIssuer`.\n\n**THE LIFETIME IS ' +
                     'CLAMPED to the Issuing CA\'s own expiry** rather than ' +
                     'refused where it would overshoot: the ordinary cause ' +
                     'is a five-year Issuing CA in its fifth year.\n\n**AND ' +
                     'SINCE 2026-09-11 THE SUBJECT MAY BE A PERSON.** ' +
                     '`target=person` issues to somebody in `ou=users` ' +
                     'instead: the same hierarchy, the same profile, the ' +
                     'same certificate, written onto their own entry as ' +
                     '`stsAssertionJwks`, `stsAssertionCertificate`, ' +
                     '`stsAssertionCertificateChain`, `stsAssertionKid`, ' +
                     '`stsAssertionExpiresAt` and a SEALED ' +
                     '`stsAssertionPrivateKey` — an attribute set that ' +
                     'shares no name with the application\'s and is read by ' +
                     'nothing else, which is the same rule the two profiles ' +
                     'above follow. RFC 7523 section 3 asks only that `iss` ' +
                     'be a unique identifier for the issuer and says the ' +
                     '`sub` of an authorization grant typically identifies a ' +
                     'resource owner, so a person signing for themselves is ' +
                     'the profile read literally.\n\n**A PERSON MAY ONLY ' +
                     'ASSERT ABOUT THEMSELVES**, and the grant refuses ' +
                     'anything else: a key issued to one resource owner is ' +
                     'that person\'s credential rather than permission to ' +
                     'speak for the others, and the certificate carries ' +
                     '`urn:sts:person:<name>` as a URI subjectAltName so ' +
                     'that the rule holds for an assertion presented on its ' +
                     '`x5c` alone. A party that may assert about OTHER ' +
                     'people is an application with `oauthAssertionIssuer` ' +
                     'declared on it.\n\n**AND THIS REPLY CARRIES THE ' +
                     'PRIVATE KEY, WHICH THE APPLICATION\'S DOES NOT.** An ' +
                     'application\'s is readable through `GET ' +
                     '/admin-api/applications`, which opens the seal for an ' +
                     '`admin:read` token; a person\'s entry is not drawn ' +
                     'through any module that would open it, so the ' +
                     'alternatives were a page that prints somebody\'s ' +
                     'private key on every visit or a key nobody can ever ' +
                     'obtain. `privateKeyPem` is in the reply to ' +
                     '`target=person` and in no other answer this API gives, ' +
                     'and it is not shown again.\n\n**AND SINCE 2026-09-13 ' +
                     'A PERSON MAY HOLD AN RFC 7522 KEY PAIR TOO**: ' +
                     '`target=person` with `purpose=saml` writes ' +
                     '`stsSamlAssertionCertificate`, its chain, a ' +
                     'thumbprint, ' +
                     'the expiry, the provenance and a sealed ' +
                     '`stsSamlAssertionPrivateKey` — a fourth attribute set ' +
                     'sharing no name with the others. The SAML 2.0 bearer ' +
                     'grant reads it under the same rule: the ' +
                     '`<Subject>` must be that person.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            identifier: { type: 'string',
                          description: 'The application to issue to — or the ' +
                                       'USERNAME, with `target=person`. It ' +
                                       'must ALREADY EXIST in this realm — ' +
                                       'creating one here would be this ' +
                                       'endpoint inventing an application, ' +
                                       'or a person, in order to give it a ' +
                                       'credential.' },
            target: { type: 'string', enum: ['application', 'person'],
                      description: 'WHO the key pair is for. Defaults to ' +
                                   '`application`, which is what every ' +
                                   'caller written before this field existed ' +
                                   'sends. `person` writes `stsAssertion*` ' +
                                   '(or `stsSamlAssertion*` for ' +
                                   '`purpose=saml`) onto a `ou=users` entry ' +
                                   'instead and returns the private key ' +
                                   'once.' },
            issuer: { type: 'string',
                      description: '`target=person` only: the `iss` (or ' +
                                   'SAML `<Issuer>`) their assertions will ' +
                                   'carry, written as `stsAssertionIssuer` ' +
                                   'or `stsSamlAssertionIssuer`. Defaults to ' +
                                   'their ' +
                                   'username, which the grant accepts ' +
                                   'without anything being declared — asking ' +
                                   'an operator to write a name down twice ' +
                                   'is a configuration step with no decision ' +
                                   'in it.' },
            purpose: { type: 'string', enum: ['jwt', 'saml'],
                       description: 'Which assertion profile the key pair is ' +
                                    'for: `jwt` for RFC 7523 and `saml` for ' +
                                    'RFC 7522. Defaults to `jwt`, which is ' +
                                    'what every caller written before this ' +
                                    'field existed sends and is why it is ' +
                                    'the default rather than a required ' +
                                    'field. A value this service does not ' +
                                    'know is REFUSED rather than defaulted — ' +
                                    'a caller that asked for a profile wants ' +
                                    'a certificate for something, and ' +
                                    'quietly handing back the other one ' +
                                    'would put a key pair on the wrong ' +
                                    'attribute set with nothing saying so.' },
            commonName: { type: 'string',
                          description: 'The leaf\'s CN. Defaults to the ' +
                                       'identifier. The identifier also goes ' +
                                       'into a URI subjectAltName either ' +
                                       'way, because a CN is a display name ' +
                                       'and a SAN is the machine-readable ' +
                                       'one.' },
            keyAlg: { type: 'string',
                      description: 'The LEAF\'s key algorithm. Defaults to ' +
                                   'the Issuing CA\'s, which is the chain a ' +
                                   'client library is least likely to be ' +
                                   'surprised by.' },
            days: { type: 'integer',
                    description: 'How long the certificate is valid. ' +
                                 'Defaults to `pki.leafLifetimeDays`.' }
          },
          required: ['identifier'],
          examples: [{ identifier: 'webapp1', days: 90 },
                     { identifier: 'webapp1', purpose: 'saml', days: 90 }],
          additionalProperties: false
        },
        responseDescription: 'The `purpose`, the attributes it wrote, the ' +
                             'key handle (`kid` and `thumbprint` — both are ' +
                             'returned whichever profile was asked for, ' +
                             'because both are computed at issuance), the ' +
                             'expiry and the JWS algorithm the issued key ' +
                             'signs with. The key material itself is on the ' +
                             'application entry.' },

      { action: 'revoke', operationId: 'revokePkiKeyPair',
        summary: 'Take an issued key pair off an application, or off a ' +
                 'person — which is NOT revocation',
        description: 'Clears the attributes the issue wrote FOR ONE PROFILE ' +
                     '— seven for `jwt` and six for `saml`. An application ' +
                     'commonly holds both key pairs and this takes ONE off; ' +
                     'clearing both would be an operation whose name said ' +
                     'one thing and did two.\n\n**THIS OPERATION IS NOT THE ' +
                     'ONE THAT REVOKES A CERTIFICATE, AND SINCE 2026-09-11 ' +
                     'THERE IS ONE.** `revoke-certificate` puts a serial on ' +
                     'an issuer\'s revocation list; this takes a key pair ' +
                     'off an application entry and puts nothing on any list. ' +
                     'After it the certificate is still valid, still chains ' +
                     'to this realm\'s Root, and would still verify anywhere ' +
                     'that trusts that Root. What changes is that THIS ' +
                     'service will no longer accept an assertion signed with ' +
                     'that key, because the key is no longer registered ' +
                     'against the application. The name is `revoke` because ' +
                     'that is the word on the button; the description is ' +
                     'where the claim is kept honest.\n\n**`target=person` ' +
                     'TAKES A PERSON\'S KEY PAIR OFF INSTEAD**, and it ' +
                     'clears the `stsAssertionIssuer` DECLARATION with it ' +
                     'where the application arm deliberately leaves ' +
                     '`oauthAssertionIssuer` alone. The difference is a fact ' +
                     'about the two: an application may hold a JWKS it ' +
                     'registered itself beside the one this service issued, ' +
                     'and a person may not — everything in `stsAssertion*` ' +
                     'was put there by the issue, so leaving the declaration ' +
                     'would leave somebody declared as an issuer with no key ' +
                     'to issue with. Since 2026-09-13 it takes ONE PROFILE ' +
                     'off a person too — `stsSamlAssertion*` for ' +
                     '`purpose=saml` — and leaves the other.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            identifier: { type: 'string',
                          description: 'The application to take the key pair ' +
                                       'off — or the USERNAME, with ' +
                                       '`target=person`.' },
            target: { type: 'string', enum: ['application', 'person'],
                      description: 'WHOSE key pair. Defaults to ' +
                                   '`application`, which is what every ' +
                                   'caller written before this field existed ' +
                                   'sends. `person` clears one profile\'s ' +
                                   'set off a `ou=users` entry, the ' +
                                   'declaration included — `stsAssertion*` ' +
                                   'or, for `purpose=saml`, ' +
                                   '`stsSamlAssertion*`.' },
            purpose: { type: 'string', enum: ['jwt', 'saml'],
                       description: 'Which profile\'s key pair to take off. ' +
                                    'Defaults to `jwt`. The other one is ' +
                                    'untouched either way.' }
          },
          required: ['identifier'],
          examples: [{ identifier: 'webapp1' },
                     { identifier: 'webapp1', purpose: 'saml' },
                     { identifier: 'alice', target: 'person' },
                     { identifier: 'alice', target: 'person',
                       purpose: 'saml' }],
          additionalProperties: false
        },
        responseDescription: 'Whether anything was taken off, and the ' +
                             'sentence saying what that did and did not do.' },

      // THE OTHER WAY A KEY PAIR IS REPLACED (2026-09-13), drawn beside
      // `issue` on an application's own console page. `common/pki.js`'s
      // `registerCertificate()` decides whether the chain is acceptable.
      { action: 'upload-certificate', operationId: 'uploadPkiCertificate',
        summary: 'Replace an application\'s or a person\'s key pair with a ' +
                 'certificate it already holds — issued by this realm\'s ' +
                 'CA, or by another with its full chain',
        description: 'The application generated its own key pair and brings ' +
                     'the CERTIFICATE; this writes it over the key pair this ' +
                     'service manages for one profile, onto the same ' +
                     'attributes an `issue` writes — seven for `jwt`, six ' +
                     'for `saml` — with the private key attribute CLEARED ' +
                     'and ' +
                     '`oauthAssertionKeySource` / ' +
                     '`oauthSamlAssertionKeySource` saying where it came ' +
                     'from. **No private key is taken**: an upload carrying ' +
                     'one is refused and nothing is stored.\n\n**WHAT THE ' +
                     'CHAIN MUST BE DEPENDS ON WHO ISSUED IT.** A ' +
                     'certificate from THIS REALM\'s own certificate ' +
                     'authority may be sent alone — the service holds every ' +
                     'tier above it — and is held to the path check an `x5c` ' +
                     'is: it must pass through this realm\'s own ' +
                     'Intermediate and nothing on it may be revoked ' +
                     '(`uploaded-realm-ca`). A certificate from ANY OTHER ' +
                     'authority must arrive with its WHOLE chain, every ' +
                     'intermediate and a SELF-SIGNED root, in either field ' +
                     'and in any order (`uploaded-external-ca`). Every link ' +
                     'is verified — signature, issuer name, validity — every ' +
                     'issuer must be a CA permitted keyCertSign within its ' +
                     'path length constraint, the leaf must not be a CA and ' +
                     'must permit digitalSignature, and its revocation is ' +
                     'checked the way a registered certificate is when it ' +
                     'is used. An incomplete chain, an unrelated extra ' +
                     'certificate, a self-signed leaf, and a chain to this ' +
                     'SERVICE\'s Root through ANOTHER realm\'s ' +
                     'Intermediate are each refused by name. The external ' +
                     'root need not be trusted by anything here: the ' +
                     'application is registering a KEY and the chain is the ' +
                     'evidence for it.\n\n**THE KEY MUST BE ONE THE ' +
                     'PROFILE\'s VERIFIER CAN USE**: RSA of at least 2048 ' +
                     'bits, ECDSA on P-256, P-384 or P-521 — and for `jwt` ' +
                     'also secp256k1 or Ed25519. The chain is stored WITH ' +
                     'its root for an external authority, because ' +
                     'revocation checking needs every issuer; the JWKS ' +
                     'written for `jwt` carries it in `x5c`.\n\nLike ' +
                     '`issue`, a key pair is not a trust decision: the ' +
                     'issuer the application will assert as still has to be ' +
                     'declared for section 2.1.\n\n**`target=person` ' +
                     '(2026-09-13) REPLACES A PERSON\'s KEY PAIR** — ' +
                     '`stsAssertion*` or `stsSamlAssertion*` on their ' +
                     '`ou=users` entry — under the same chain rules, with ' +
                     'one more: a certificate this realm issued must name ' +
                     'THAT person (`urn:sts:person:<name>`), so an ' +
                     'application\'s leaf or another person\'s is refused. ' +
                     'For an application, a leaf this realm issued to a ' +
                     'PERSON is refused. A self-signed certificate is ' +
                     'refused for a person with no by-value alternative, ' +
                     'and the grant ' +
                     'still holds an uploaded key to assertions about the ' +
                     'person alone.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            identifier: { type: 'string',
                          description: 'The application, exactly as the ' +
                                       'registry holds it — or the USERNAME, ' +
                                       'with `target=person`.' },
            purpose: { type: 'string', enum: ['jwt', 'saml'],
                       description: 'Which profile\'s key pair to replace. ' +
                                    'Defaults to `jwt`; the other is ' +
                                    'untouched.' },
            certificate: { type: 'string',
                           description: 'The leaf certificate, PEM. It may ' +
                                        'be followed by its chain in the ' +
                                        'same value.' },
            chain: { type: 'string',
                     description: 'The certificates above it, PEM, in any ' +
                                  'order: every intermediate and the ' +
                                  'self-signed root for an external ' +
                                  'authority, nothing for this realm\'s ' +
                                  'own.' },
            from: { type: 'string',
                    description: 'Console only: the page to return to. ' +
                                 'Ignored by this API.' },
            target: { type: 'string', enum: ['application', 'person'],
                      description: 'WHOSE key pair. Defaults to ' +
                                   '`application`; `person` replaces the ' +
                                   'key pair on a `ou=users` entry, which ' +
                                   'must already exist.' }
          },
          required: ['identifier', 'certificate'],
          examples: [{ identifier: 'webapp1', purpose: 'jwt',
                       certificate: '-----BEGIN CERTIFICATE-----\n…\n' +
                                    '-----END CERTIFICATE-----',
                       chain: '-----BEGIN CERTIFICATE-----\n…\n' +
                              '-----END CERTIFICATE-----' }],
          additionalProperties: false
        },
        responseDescription: 'The source, the subject and issuer, the chain ' +
                             'it was checked through, the key handle and the ' +
                             'expiry — or the refusal naming what is wrong ' +
                             'with the chain.' },

      { action: 'clear', operationId: 'clearPkiChain',
        summary: 'Remove this realm\'s certificate authority entirely',
        description: 'Destructive, and it says so: every certificate issued ' +
                     'from the hierarchy chains to nothing the moment this ' +
                     'returns, and this service keeps no copy of what it ' +
                     'issued, so nothing here can list what broke. The key ' +
                     'pairs stay on the application entries and go on ' +
                     'signing; what stops is this service being able to see ' +
                     'that it issued them.',
        requestBodyRequired: false,
        requestBody: { type: 'object', properties: {}, examples: [{}],
                       additionalProperties: false },
        responseDescription: 'How many certificates had been issued from the ' +
                             'hierarchy that was removed.' },

      // =====================================================================
      // THE CERTIFICATE & KEY CONFIGURATION PANE (2026-09-10).
      //
      // Eight operations, and every one of them takes and returns THE WHOLE
      // FORM. That is not an API shaped by a page: the pane has a hundred and
      // fifteen fields, `apply-profile` rewrites twenty-two of them, and a
      // caller that had to reconstruct the result itself would be a second
      // implementation of what a profile MEANS. So the reply carries `draft`
      // — the form as it should now be — and a caller does `apply-profile`,
      // edits three fields of what came back, and posts it to
      // `issue-certificate`.
      //
      // **THE FIELD NAMES ARE THE DEBUGGER PKI / X.509 PAGE'S, VERBATIM**
      // (`pki_dn_cn`, `pki_ext_bc`, `pki_ku_keyCertSign`). The two are one
      // form over one encoder; `GET /admin-api/pki` publishes the whole list
      // as `workbench.fields`, so a client reads the vocabulary from the
      // service rather than from a copy of it in a document.
      // =====================================================================
      { action: 'apply-profile', operationId: 'applyPkiProfile',
        summary: 'Fill the certificate form in from a profile',
        description: 'Rewrites the twenty-two extension boxes, the default ' +
                     'validity and the profile’s Common Name from the ' +
                     'profile named in `pki_profile`, and narrows the two ' +
                     'algorithm menus to the approach in `pki_pq_mode`. ' +
                     'Nothing is issued.\n\n**A COMMON NAME SOMEBODY TYPED ' +
                     'IS NEVER OVERWRITTEN** — an empty one, or one still ' +
                     'holding ANY profile’s own default, is replaced. ' +
                     'Picking Intermediate CA after Root CA would otherwise ' +
                     'issue an intermediate called "RootCA", which chains ' +
                     'correctly and reads as a bug for as long as it takes ' +
                     'somebody to notice.\n\nPost the whole form back; ' +
                     'anything omitted falls to its default rather than ' +
                     'being kept.',
        requestBodyRequired: false,
        requestBody: { type: 'object', properties: {},
                       examples: [{ pki_profile: 'tls-server',
                                    pki_pq_mode: 'classical' }],
                       additionalProperties: true },
        responseDescription: 'The form, as it should now be drawn, in ' +
                             '`draft`.' },

      { action: 'generate-keys', operationId: 'generatePkiKeyPair',
        summary: 'Generate a key pair into the form without issuing anything',
        description: 'Puts a fresh pair in `pki_private_key` and ' +
                     '`pki_public_key`, in the algorithm named by ' +
                     '`pki_key_alg`.\n\n**IT EXISTS BECAUSE GENERATION CAN ' +
                     'BE SLOW.** An SLH-DSA pair takes seconds and this ' +
                     'process is single-threaded, so making one and then ' +
                     'issuing four certificates from it (with ' +
                     '`pki_reuse_key`) is the difference between a usable ' +
                     'surface and one that stalls the whole service four ' +
                     'times over.',
        requestBodyRequired: false,
        requestBody: { type: 'object', properties: {},
                       examples: [{ pki_key_alg: 'ec-p384' }],
                       additionalProperties: true },
        responseDescription: 'The form with the new pair in it, in `draft`.' },

      { action: 'generate-alt-keys', operationId: 'generatePkiAltKeyPair',
        summary: 'Generate the alternative (hybrid) key pair',
        description: 'The second key of a hybrid certificate — ITU-T X.509 ' +
                     '(2019) clause 9.8’s `subjectAltPublicKeyInfo`. ' +
                     'The list is the post-quantum algorithms that can sign, ' +
                     'because a hybrid certificate whose second key is also ' +
                     'RSA is a certificate signed twice by the same century. ' +
                     'Issuing with `pki_pq_mode=hybrid` generates one anyway ' +
                     'if the boxes are empty.',
        requestBodyRequired: false,
        requestBody: { type: 'object', properties: {},
                       examples: [{ pki_alt_key_alg: 'ml-dsa-65' }],
                       additionalProperties: true },
        responseDescription: 'The form with the alternative pair in it.' },

      { action: 'issue-certificate', operationId: 'issuePkiCertificate',
        summary: 'Issue a certificate from the form — any profile, any ' +
                 'issuer, every extension',
        description: 'The pane’s own button. Generates a key pair ' +
                     '(unless `pki_reuse_key` names one in the boxes), ' +
                     'builds the certificate from the subject, the validity ' +
                     'and the twenty-two extensions, signs it with the ' +
                     'authority `pki_issuer` names — or with its own key ' +
                     'under a self-signed profile — and keeps both in this ' +
                     'realm’s store.\n\n**THE SIGNATURE IS CONSTRAINED ' +
                     'BY THE ISSUER’S KEY AND NOT THE SUBJECT’S.** ' +
                     'A pair whose families disagree is refused HERE with ' +
                     'the list of what that key can produce, rather than by ' +
                     'the primitive, which reports it as a key-usage error ' +
                     'naming neither.\n\n**A REFUSAL CARRIES THE FORM BACK** ' +
                     'in `draft`: a hundred and fifteen fields discarded ' +
                     'because one line of a subjectAltName would not parse ' +
                     'is not a refusal anybody can act on.',
        requestBodyRequired: true,
        requestBody: { type: 'object', properties: {},
                       examples: [{ pki_profile: 'tls-server',
                                    pki_issuer: 'tier:issuing',
                                    pki_key_alg: 'ec-p256',
                                    pki_dn_cn: 'www.example.test',
                                    pki_ext_san: '1',
                                    pki_san: 'dns:www.example.test',
                                    pki_ext_ku: '1',
                                    pki_ku_digitalSignature: '1',
                                    pki_ext_eku: '1',
                                    pki_eku_serverAuth: '1',
                                    pki_save_keys: '1' }],
                       additionalProperties: true },
        responseDescription: 'The stored object (no private key in it), and ' +
                             'the form with a FRESH SERIAL in it — a serial ' +
                             'that stayed put would be re-used by the next ' +
                             'certificate the same authority signs, and two ' +
                             'certificates from one issuer sharing a serial ' +
                             'are indistinguishable to anything that ' +
                             'revokes, caches or pins by (issuer, serial).' },

      { action: 'use-key', operationId: 'usePkiStoredKey',
        summary: 'Load a stored object’s key pair back into the form',
        description: 'What a CA renewing its own certificate does. It ticks ' +
                     '`pki_reuse_key` itself, because a pair loaded into the ' +
                     'boxes and then silently replaced by a fresh one at the ' +
                     'next issue is the most confusing thing this surface ' +
                     'could do. Everything else on the form is kept.',
        requestBodyRequired: true,
        requestBody: { type: 'object',
                       properties: {
                         objectId: { type: 'string',
                                     description: 'The `id` of a row in ' +
                                                  '`workbench.objects`.' } },
                       required: ['objectId'],
                       examples: [{ objectId: 'ca-1f2e3d4c5b6a7980' }],
                       additionalProperties: true },
        responseDescription: 'The form with that key pair in it.' },

      { action: 'remove-object', operationId: 'removePkiObject',
        summary: 'Remove one object from this realm’s store',
        description: 'The key pair is gone. **Anything it ISSUED is kept** — ' +
                     'those certificates are still valid documents — and ' +
                     'will now say that their issuer is missing.',
        requestBodyRequired: true,
        requestBody: { type: 'object',
                       properties: {
                         objectId: { type: 'string',
                                     description: 'The `id` of a row in ' +
                                                  '`workbench.objects`.' } },
                       required: ['objectId'],
                       examples: [{ objectId: 'leaf-1f2e3d4c5b6a7980' }],
                       additionalProperties: true },
        responseDescription: 'The sentence saying what that did and did not ' +
                             'do.' },

      { action: 'clear-store', operationId: 'clearPkiObjects',
        summary: 'Empty this realm’s object store',
        description: 'Every key pair and certificate the pane issued in this ' +
                     'realm is discarded. **The three-tier hierarchy is NOT ' +
                     'touched** — that is `clear` — and anything these keys ' +
                     'signed is still a valid document that still chains to ' +
                     'whatever signed IT.',
        requestBodyRequired: false,
        requestBody: { type: 'object', properties: {}, examples: [{}],
                       additionalProperties: true },
        responseDescription: 'How many objects were discarded.' },

      { action: 'export', operationId: 'exportPkiKeyPair',
        summary: 'Write a key pair out as PEM, DER, a JWK set or a PKCS#12',
        description: 'The same export `/admin/keys` uses ' +
                     '(`common/vendored/key_material.js`), so a `.p12` from ' +
                     'here imports identically into keytool, OpenSSL, ' +
                     'Windows and macOS.\n\n**THE CONSOLE DOES NOT COME ' +
                     'THROUGH HERE**: `POST /admin/pki/export` answers with ' +
                     'the FILE, because that is what a browser asked for. ' +
                     'This arm answers JSON with the bytes base64’d, ' +
                     'which is what a machine asked for. One function ' +
                     'underneath either way.\n\n**IT HANDS OVER A PRIVATE ' +
                     'KEY**, so like every other such door here it needs ' +
                     '`admin:write` rather than `admin:read`.',
        requestBodyRequired: false,
        requestBody: { type: 'object',
                       properties: {
                         objectId: { type: 'string',
                                     description: 'The object to write out. ' +
                                                  'Omitted, the key pair in ' +
                                                  '`pki_private_key` and ' +
                                                  '`pki_public_key` is ' +
                                                  'used.' } },
                       examples: [{ objectId: 'leaf-1f2e3d4c5b6a7980',
                                    pki_ks_format: 'pkcs12',
                                    pki_ks_password: 'changeit',
                                    pki_ks_include_chain: '1' }],
                       additionalProperties: true },
        responseDescription: 'One entry per member of `files`: its name, its ' +
                             'media type and its bytes as base64. A DER ' +
                             'export is two files and the console’s own ' +
                             'door sends only the private one, which is the ' +
                             'single difference between them.' },

      // =====================================================================
      // THE HIERARCHY ITSELF (2026-09-11). One Root for the service, an
      // Intermediate per scope, an Issuing CA per use case — and every key
      // pair this service generates as a leaf of it.
      //
      // **`scope` IS A REALM ID, `*service` OR `*process`.** A realm id is
      // `[a-z0-9-]` and must start with a letter or a digit, so the two
      // starred names cannot collide with one. Omitted, it means the realm the
      // request arrived in, which is what every other control here means by
      // saying nothing.
      // =====================================================================
      { action: 'build-root', operationId: 'buildPkiRoot',
        summary: 'Build or replace the Root CA for the whole service',
        description: 'One Root, shared by every realm and by the process ' +
                     'branch — which is what lets an operator install ONE ' +
                     'anchor and have it cover 8443, 9443, LDAPS 636, the ' +
                     'main port and every token this service ' +
                     'signs.\n\n**REPLACING IT RE-ISSUES EVERY BRANCH IN THE ' +
                     'SAME ACT**, because an Intermediate still hanging from ' +
                     'the old Root chains to nothing — a new Root with the ' +
                     'old branches under it is a service whose tree does not ' +
                     'reach its own anchor, and every path check fails while ' +
                     'the page looks right.\n\n**ANYTHING TRUSTING THE OLD ' +
                     'ROOT STOPS TRUSTING THIS SERVICE.** That is the cost ' +
                     'of one anchor covering everything. The signing keys ' +
                     'themselves are untouched, so nothing that verifies ' +
                     'against the published JWKS is affected.',
        requestBodyRequired: false,
        requestBody: {
          type: 'object',
          properties: {
            keyAlg: { type: 'string',
                      description: 'One of the ids in `keyAlgorithms`. ' +
                                   'Defaults to `pki.keyAlgorithm`.' },
            commonName: { type: 'string',
                          description: 'The Root’s CN. Defaults to the ' +
                                       'organisation followed by "Root CA".' },
            years: { type: 'integer',
                     description: 'How long it is valid for. Defaults to the ' +
                                  'root-ca profile’s own twenty years.' }
          },
          examples: [{ keyAlg: 'ec-p384', years: 30 }],
          additionalProperties: false },
        responseDescription: 'The new Root, and how many branches were ' +
                             're-issued under it.' },

      { action: 'build-scope', operationId: 'buildPkiScope',
        summary: 'Build or rebuild one scope’s branch — its Intermediate and ' +
                 'every Issuing CA under it',
        description: 'A scope is a trust realm or the process. **ALL OF IT ' +
                     'OR NONE OF IT**: a branch with an Intermediate and two ' +
                     'of its three Issuing CAs is the state in which one use ' +
                     'case silently has no authority and its keys come out ' +
                     'uncertified, so a failure anywhere stores ' +
                     'nothing.\n\n**THE ROOT IS NOT TOUCHED** — every other ' +
                     'scope hangs from it — and an IMPORTED authority in ' +
                     'this branch is left alone unless `replaceImported` ' +
                     'says otherwise: somebody who pasted a corporate CA in ' +
                     'did not press this to have it thrown ' +
                     'away.\n\nEverything the old authorities had certified ' +
                     'is re-minted from the new ones in the same act.',
        requestBodyRequired: false,
        requestBody: {
          type: 'object',
          properties: {
            scope: { type: 'string',
                     description: 'A realm id, `*process`, or omitted for ' +
                                  'the realm this request arrived in.' },
            keyAlg: { type: 'string',
                      description: 'The key algorithm every CA in this ' +
                                   'branch is generated with.' },
            replaceImported: { type: 'boolean',
                               description: 'Replace an imported authority ' +
                                            'too. Default false.' }
          },
          examples: [{ scope: '*process', keyAlg: 'ec-p256' }],
          additionalProperties: false },
        responseDescription: 'The branch, and how many certificates were ' +
                             're-minted under it.' },

      { action: 'reissue-use-case', operationId: 'reissuePkiUseCase',
        summary: 'Give one use case’s Issuing CA a new key pair',
        description: 'Re-issues that one authority from its scope’s ' +
                     'Intermediate with a NEW KEY, then re-certifies ' +
                     'everything that hung under it. **The other use cases ' +
                     'are untouched**, which is the whole reason each has an ' +
                     'authority of its own rather than sharing one: an ' +
                     'operator who wants to replace what signs their SAML ' +
                     'documents should not thereby replace what signs their ' +
                     'tokens.\n\nIt is NOT the same as `recertify` — see ' +
                     'that one.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            scope: { type: 'string', description: 'A realm id or `*process`.' },
            useCase: { type: 'string',
                       description: 'One of `jose`, `xml`, `assertions`, ' +
                                    '`spiffe`, `pep-tls` (a realm) or `tls` ' +
                                    '(the process). Asking for one in the ' +
                                    'wrong ' +
                                    'scope is refused and the refusal says ' +
                                    'which scope it belongs to.' }
          },
          required: ['useCase'],
          examples: [{ scope: '', useCase: 'jose' }],
          additionalProperties: false },
        responseDescription: 'How many certificates were re-minted under the ' +
                             'new authority.' },

      { action: 'recertify', operationId: 'recertifyPkiUseCase',
        summary:
          'Renew the certificates under one Issuing CA, keeping the keys',
        description: 'Re-issues every certificate that authority has minted, ' +
                     'from the SAME authority, with fresh serials and a ' +
                     'fresh validity window.\n\n**THE KEYS ARE UNTOUCHED, ' +
                     'WHICH IS WHAT MAKES THIS A RENEWAL**: the subject ' +
                     'public key is read back out of the certificate being ' +
                     'replaced, so nothing that verifies against the ' +
                     'published JWKS stops verifying. `reissue-use-case` is ' +
                     'the other one — it replaces the authority, and ' +
                     'everything it had signed chains to nothing until it is ' +
                     're-minted.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            scope: { type: 'string', description: 'A realm id or `*process`.' },
            useCase: { type: 'string', description: 'The use case to renew.' }
          },
          required: ['useCase'],
          examples: [{ scope: '', useCase: 'jose' }],
          additionalProperties: false },
        responseDescription: 'How many certificates were renewed.' },

      { action: 'import-ca', operationId: 'importPkiCa',
        summary: 'Use a certificate authority this service did not generate',
        description: 'Paste a CA certificate and its private key. With ' +
                     '`useCase: "root"` it becomes the service Root and ' +
                     '**every branch must then be rebuilt under it**; ' +
                     'otherwise it becomes one scope’s Issuing CA for one ' +
                     'use case, and everything under that authority is ' +
                     're-minted from it.\n\n**THREE CHECKS HAPPEN BEFORE ' +
                     'ANYTHING IS STORED**, and the middle one is the one ' +
                     'that matters: both halves must be present (a ' +
                     'certificate with no key is a trust anchor rather than ' +
                     'an authority), the KEY MUST BELONG TO THE CERTIFICATE ' +
                     '(an authority whose key is somebody else’s issues ' +
                     'certificates that verify nowhere, and the failure ' +
                     'arrives at a relying party rather than here), and the ' +
                     'certificate must be a CA at all — `cA:FALSE` means ' +
                     'nothing it signs is accepted by a path ' +
                     'validator.\n\n**THE KEY IS STORED AS THIS SERVICE ' +
                     'STORES ITS OWN**: in the keystore row, sealed under ' +
                     'the key-encryption key wherever that key outlives the ' +
                     'process.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            scope: { type: 'string',
                     description: '`*service` for the Root, otherwise a ' +
                                  'realm id or `*process`.' },
            useCase: { type: 'string',
                       description: '`root`, or one of the use cases.' },
            certificatePem: { type: 'string',
                              description: 'The CA certificate.' },
            privateKeyPem: { type: 'string', description: 'Its private key.' }
          },
          required: ['useCase', 'certificatePem', 'privateKeyPem'],
          examples: [{ scope: '*service', useCase: 'root',
                       certificatePem: '-----BEGIN CERTIFICATE-----…',
                       privateKeyPem: '-----BEGIN PRIVATE KEY-----…' }],
          additionalProperties: false },
        responseDescription: 'The authority as it was read, and what has to ' +
                             'happen next.' },

      { action: 'pin-key', operationId: 'pinPkiKeyPair',
        summary: 'Use a key pair of your own for one slot',
        description: 'A SLOT is a use case and an algorithm — `jose` / ' +
                     '`ES256:P-256`, say — which is the granularity an ' +
                     'operator actually wants: *what signs my ES384*, not ' +
                     '*the key that happened to be there on Tuesday*. A ' +
                     '`kid` would not do, because it changes whenever the ' +
                     'key does.\n\n**WITH NO CERTIFICATE THIS SERVICE ISSUES ' +
                     'ONE** from that use case’s Issuing CA, so your key ' +
                     'chains to this service’s Root exactly as a generated ' +
                     'one would — which is what somebody who wants their own ' +
                     'key under this hierarchy is asking for. **WITH a ' +
                     'certificate** the pair is used as supplied and chains ' +
                     'wherever that certificate chains, which is the other ' +
                     'thing somebody might mean.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            scope: { type: 'string', description: 'A realm id or `*process`.' },
            useCase: { type: 'string', description: 'The use case.' },
            slot: { type: 'string',
                    description: 'The algorithm, as it appears in that use ' +
                                 'case’s certified list — `RS256`, ' +
                                 '`ES256:P-256`, `EdDSA:Ed25519`.' },
            privateKeyPem: { type: 'string', description: 'Your private key.' },
            certificatePem: { type: 'string',
                              description: 'Optional. Omit it and this ' +
                                           'service issues one from its own ' +
                                           'authority.' }
          },
          required: ['useCase', 'slot', 'privateKeyPem'],
          examples: [{ scope: '', useCase: 'jose', slot: 'ES256:P-256',
                       privateKeyPem: '-----BEGIN PRIVATE KEY-----…' }],
          additionalProperties: false },
        responseDescription: 'What this service will now use for that slot, ' +
                             'and whether it chains to this service’s Root ' +
                             'or to yours.' },

      // ---------------------------------------------------------------
      // THE REVOCATION PANE'S TWO, SINCE 2026-09-11.
      //
      // They arrived on `/admin/pki` and on `PKI_ACTIONS` and NOT here,
      // which is rule 7 unpaid — and the thing that caught it was not the
      // parity check: `tests/vendored/sts_admin_api_operations.js` compares
      // the refusal SENTENCE this endpoint prints for an unknown action
      // against the actions this document declares, and the sentence is
      // generated from `PKI_ACTIONS`. So the console had two controls whose
      // operations nothing could find, and the API accepted both of them
      // the whole time: the route is `/pki/:action`, so an undeclared action
      // still WORKS — what it does not do is appear in the document, which
      // is the only place a machine driving this API can read the repertoire
      // from.
      // ---------------------------------------------------------------
      { action: 'revoke-certificate', operationId: 'revokePkiCertificate',
        summary: 'Put a serial on one certificate authority\'s revocation ' +
                 'list — which is NOT `revoke`',
        description: 'RFC 5280 revocation: the serial goes on the named ' +
                     'authority\'s CRL and its OCSP responder answers ' +
                     '`revoked` for it from that moment. The list is rebuilt ' +
                     'and signed on demand at `/pki/crl/{scope}/{ca}`, so ' +
                     'the next fetch there already carries the entry, and ' +
                     'the copy published into the directory under `ou=crl` ' +
                     'is rewritten too — the `ldap://` and `ldaps://` ' +
                     'addresses in every certificate this authority signed ' +
                     'point at a DOCUMENT, and a document goes on saying ' +
                     'what it said before unless somebody rewrites ' +
                     'it.\n\n**THIS IS NOT `revoke`, WHICH IS A DIFFERENT ' +
                     'ACT WITH THE SAME WORD IN IT.** That one takes an ' +
                     'issued key pair off an application\'s directory entry ' +
                     'and puts nothing on any list. This one puts a serial ' +
                     'on a list and takes nothing off anybody. The names are ' +
                     'deliberately not `revoke` and `revoke-key`: this ' +
                     'action list is published and a machine chooses from ' +
                     'it, so renaming the older one to make room would have ' +
                     'broken every caller that already had ' +
                     'it.\n\n**IT IS IDEMPOTENT AND THE EARLIER ENTRY ' +
                     'WINS** — revoking twice answers 200 with ' +
                     '`already: true` and does not move the date, because a ' +
                     'validator is entitled to act on the first moment it ' +
                     'was told about.\n\n**AND THIS SERVICE DOES NOT ' +
                     'CONSULT ITS OWN LISTS.** A client certificate revoked ' +
                     'here still authenticates on 8443, 9443, the main port ' +
                     'and LDAPS 636, because those check the anchors on ' +
                     '`/tls/trust` and fetch nothing. What this operation ' +
                     'buys is that a relying party which DOES check can now ' +
                     'find out.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            scope: { type: 'string',
                     description: 'Which branch the issuer is in: a realm ' +
                                  'id, `*service` for the one Root, ' +
                                  '`*process` for the process branch, or ' +
                                  'omitted for the realm this request ' +
                                  'arrived in.' },
            ca: { type: 'string',
                  description: 'The issuing authority, as `GET ' +
                               '/admin-api/pki` names it in `revocation`: ' +
                               '`root`, `intermediate`, or a use case id for ' +
                               'an Issuing CA. **A revocation is made BY AN ' +
                               'ISSUER** — a serial is only unique within ' +
                               'one, which is why there is a list per CA and ' +
                               'not one per realm.' },
            serialHex: { type: 'string',
                         description: 'The certificate\'s serial number in ' +
                                      'hex. Case, leading zeros and ' +
                                      'separators are all ignored: a CRL ' +
                                      'carries a DER integer and an OCSP ' +
                                      'request carries a string somebody ' +
                                      'typed, and two spellings of one ' +
                                      'serial is a certificate that is ' +
                                      'revoked and reports as good.' },
            reason: { type: 'string',
                      enum: ['unspecified', 'keyCompromise', 'cACompromise',
                             'affiliationChanged', 'superseded',
                             'cessationOfOperation', 'certificateHold',
                             'privilegeWithdrawn', 'aACompromise'],
                      description: 'RFC 5280 section 5.3.1. Defaults to ' +
                                   '`superseded`, which is what this service ' +
                                   'uses when it rotates or reissues ' +
                                   'something itself. `certificateHold` is ' +
                                   'the only one `release-hold` can undo; ' +
                                   '`unspecified` writes no reason code at ' +
                                   'all, which is what that value means on ' +
                                   'the wire.' },
            subject: { type: 'string',
                       description: 'Optional. The subject DN, kept for the ' +
                                    'operator reading the list — it is not ' +
                                    'on the CRL, which carries serials.' },
            note: { type: 'string',
                    description: 'Optional. Why, in your own words, for the ' +
                                 'same reader.' }
          },
          required: ['ca', 'serialHex'],
          examples: [{ ca: 'intermediate', serialHex: '0a1b2c3d',
                       reason: 'keyCompromise' },
                     { scope: '*service', ca: 'root', serialHex: '1f',
                       reason: 'certificateHold', note: 'pending review' }],
          additionalProperties: false },
        responseDescription: 'The entry as it now stands, `already` when it ' +
                             'was on the list before, and the sentence ' +
                             'saying what this did and did not change.' },

      { action: 'release-hold', operationId: 'releasePkiCertificateHold',
        summary: 'Lift a `certificateHold` — the one revocation RFC 5280 ' +
                 'lets you undo',
        description: 'Takes the serial back off the authority\'s list and ' +
                     'bumps the CRL number, so the next CRL and the next ' +
                     'OCSP answer call it good again.\n\n**ONLY A HOLD.** A ' +
                     'serial revoked for any other reason is refused with ' +
                     'the reason named: everything else RFC 5280 defines is ' +
                     'PERMANENT, and a validator is entitled to cache a ' +
                     'permanent revocation for as long as the CRL it read ' +
                     'says it is fresh — so undoing one here would produce a ' +
                     'certificate this service calls good and half the world ' +
                     'still calls revoked.\n\n**AND EVEN A HOLD IS NOT ' +
                     'LIFTED INSTANTLY ANYWHERE BUT HERE**: a validator ' +
                     'holding the previous list goes on refusing until that ' +
                     'copy expires, which is `pki.crlLifetimeMinutes`.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            scope: { type: 'string',
                     description: 'As on `revoke-certificate`: a realm id, ' +
                                  '`*service`, `*process`, or omitted for ' +
                                  'the realm this request arrived in.' },
            ca: { type: 'string',
                  description: 'The issuing authority the hold is on. It has ' +
                               'to be the same one that took it — a serial ' +
                               'is only unique within an issuer.' },
            serialHex: { type: 'string',
                         description: 'The held certificate\'s serial, ' +
                                      'spelt however you like.' }
          },
          required: ['ca', 'serialHex'],
          examples: [{ ca: 'intermediate', serialHex: '0a1b2c3d' }],
          additionalProperties: false },
        responseDescription: 'The sentence saying the hold is lifted, and ' +
                             'that a validator which cached the earlier list ' +
                             'still has it.' }
    ] },

  { method: 'GET', path: BASE + '/scim/monitor', tag: 'SCIM',
    operationId: 'getScimMonitor',
    summary: 'How many SCIM calls there have been, from whom, of what kind, ' +
             'and how many failed',
    description: 'Everything /admin/scim/monitor draws: the call totals, one ' +
                 'row per operation with its successes, failures, latency ' +
                 'and bytes returned, one row per resource type, one row per ' +
                 'authenticated client, the authentication schemes with the ' +
                 'ones at zero included, what went back by status class, ' +
                 'status and `scimType`, and the last fifty requests ' +
                 'individually.\n\n**A CLIENT IS AN AUTHENTICATED PRINCIPAL, ' +
                 'NOT A CONNECTION.** SCIM is stateless HTTP — no session, ' +
                 'no registration, nothing to be connected — so ' +
                 '`authentication.distinct` is how many different names have ' +
                 'successfully authenticated since this process started. It ' +
                 'never goes down: a provisioning client that has stopped ' +
                 'calling is indistinguishable from one that is between ' +
                 'calls.\n\n**A REFUSED CALLER IS NOT A CLIENT.** Calls the ' +
                 'gate turned away are counted in `authentication.refused` ' +
                 'and appear in no `clients` row, even when the credential ' +
                 'carried a name — Basic and Digest both put one on the ' +
                 'wire. Attributing traffic to an identity this service ' +
                 'declined to believe is the one mistake this reply could ' +
                 'make that would matter.\n\n**THE OPERATION COUNTS DO NOT ' +
                 'SUM TO `calls`.** One `POST /scim/v2/Bulk` carrying five ' +
                 'creates is one `bulk` AND five `create`s, because each of ' +
                 'the five really is performed.\n\n**AN ABSENT MEASUREMENT ' +
                 'IS NULL AND NOT ZERO.** `averageMs`, `maxMs` and ' +
                 '`successRate` are null where nothing has been called: an ' +
                 'average over no samples is absent, and a 100% success rate ' +
                 'on zero requests is the most misleading number ' +
                 'here.\n\nThe counters are IN MEMORY, start with the ' +
                 'process (`since`) and are PER TRUST REALM, like the ' +
                 'directory SCIM writes into. The durable record of what ' +
                 'SCIM was asked to do is GET /admin-api/audit, which has ' +
                 'the actor and the target as well as the count.',
    mirrors: 'GET /admin/scim/monitor',
    responseDescription: 'The call totals, the per-operation, per-resource, ' +
                         'per-client and per-scheme breakdowns, and the ' +
                         'recent requests.',
    responseSchema: { $ref: '#/components/schemas/ScimMonitor' },
    handler: function (req, res) {
      log.debug("Entering the management API SCIM monitor endpoint.");
      sendJson(res, 200, adminViews.scimMonitorJson(req));
      log.debug("Leaving the management API SCIM monitor endpoint.");
    } },

  // ---------------------------------------------------------------------
  // WHAT THE CONSOLE WAS TOLD, AND WHY IT IS A RESOURCE OF ITS OWN RATHER
  // THAN A MEMBER OF /admin-api/ssf.
  //
  // That resource is the TRANSMITTER's: the streams, their subjects, their
  // queues and what went out on each. This one is the RECEIVER's, and the
  // whole value of keeping them apart is that this one goes empty when
  // delivery is broken while the other does not — a reply that carried both
  // would answer "what has been said" and "what has been heard" with one
  // document and lose exactly the disagreement worth having.
  // ---------------------------------------------------------------------
  { method: 'GET', path: BASE + '/signals', tag: 'Shared Signals',
    operationId: 'getSignals',
    summary: 'Every security event delivered TO this console',
    description: 'This service\'s own admin console is a registered Shared ' +
                 'Signals receiver: it has a stream of its own ' +
                 '(`sts-admin-console`), seeded in EVERY trust realm, asking ' +
                 'for every CAEP and every RISC event type, and each event ' +
                 'is POSTed to it over RFC 8935 push at ' +
                 '/admin/signals/receive with that stream\'s own bearer ' +
                 'token. This is what arrived.\n\n**IT IS SEEDED IN EVERY ' +
                 'REALM AND THE CONSOLE\'S CLIENT ENTRY IS IN ONE**, and the ' +
                 'disagreement is deliberate: a client entry is about ' +
                 'signing somebody IN, and this console\'s gate reads the ' +
                 'DEFAULT realm\'s session wherever it is reached; a stream ' +
                 'is about what HAPPENED, and events happen in the realm ' +
                 'they happen in.\n\n**READ `status.why` BEFORE CONCLUDING ' +
                 'NOTHING HAS HAPPENED.** An empty `received` has five ' +
                 'causes and only one of them is that: `ssf.enabled` off, ' +
                 '`ssf.internalReceivers` off, the stream deleted (it is an ' +
                 'ORDINARY stream — delete it here or at /admin/ssf and it ' +
                 'stays deleted until a restart), `ssf.pushDelivery` off, or ' +
                 '`caep.enabled` / `risc.enabled` off under it.\n\n**WHAT A ' +
                 'PERSON SEES IS A DIFFERENT RECEIVER.** The user portal has ' +
                 'a stream of its own and shows each person only the events ' +
                 'whose subject is them; there is no operation here for that ' +
                 'view, because it is a person\'s own page and not an ' +
                 'administrative one.\n\nThe inbox is IN MEMORY, per trust ' +
                 'realm, capped at `ssf.maxReceivedEvents`. The durable ' +
                 'record of every delivery is GET /admin-api/audit, which ' +
                 'cannot be cleared.',
    mirrors: 'GET /admin/signals',
    parameters: [
      { name: 'sigq', in: 'query', required: false, schema: { type: 'string' },
        description: 'Narrows the list to rows whose event name, type URI, ' +
                     'subject, issuer, audience, `jti` or stream id contains ' +
                     'this. One box over all of them, because a reader ' +
                     'arrives holding one and does not know which column it ' +
                     'is in.' },
      { name: 'receivedPage', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Which page of the delivered events. Clamped, like ' +
                     'every page parameter here.' }
    ].concat(pagingParameters()),
    responseDescription: 'This receiver and its stream, and the delivered ' +
                         'events.',
    responseSchema: { $ref: '#/components/schemas/Signals' },
    handler: function (req, res) {
      log.debug("Entering the management API signals endpoint.");
      sendJson(res, 200, adminViews.signalsJson(req));
      log.debug("Leaving the management API signals endpoint.");
    } },

  { method: 'POST', route: BASE + '/signals/:action', tag: 'Shared Signals',
    mirrors: 'POST /admin/signals',
    handler: function (req, res) {
      log.debug("Entering the management API signals action endpoint.");
      const body = parseBody(req);
      const result = adminActions.signalsAction(withAction(req, body));
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0056');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API signals action endpoint.");
    },
    actions: [
      { action: 'clear', operationId: 'clearSignalsInbox',
        summary: 'Empty the console\'s Shared Signals inbox',
        description: 'Drops every delivered event held for the admin ' +
                     'console in this trust realm.\n\n**IT DOES NOT TOUCH ' +
                     'THE STREAM.** Clearing what a receiver has been shown ' +
                     'and tearing down the agreement to send it more are two ' +
                     'different acts; the second one is ' +
                     'POST /admin-api/ssf/delete-stream. This receiver goes ' +
                     'on taking delivery the moment this ' +
                     'returns.\n\n**AND IT DOES NOT TOUCH THE RECORD.** ' +
                     'Every delivery wrote an `ssf.event.receive` row to the ' +
                     'audit log, which has no clear operation anywhere — ' +
                     'which is what makes it the durable half.',
        requestBodyRequired: false,
        // THE EMPTY EXAMPLE IS WHAT DRIVES IT.
        // `tests/vendored/sts_admin_api_operations.js` replays every POST that
        // carries an example and then asserts that every documented operation
        // was driven by something — so an action taking no parameters and
        // declaring no example is covered by nothing and reported by nothing,
        // which is what this one was until that ledger went red on it. `{}` is
        // the shape `revoke-all` and `clear-store` use for the same reason.
        requestBody: { type: 'object', properties: {}, examples: [{}],
                       additionalProperties: true },
        responseDescription: 'How many delivered events were dropped.' }
    ] },

  // ---------------------------------------------------------------------------
  // THE CLIENT-CERTIFICATE TRUSTSTORE (2026-09-12).
  //
  // Rule 7: `/admin/tls/trust` has two controls, so this resource has the same
  // two, through `truststoreAction()` and `truststoreJson()` in `admin-core/`,
  // which reach `tls/tls_server.js` through `admin.setTruststore()`.
  //
  // **BOTH OPERATIONS ARE PINNED TO THE FRONT PROCESS** in `workers.dispatch`
  // mode (`common/request_pool.js`'s `NEVER_DISPATCHED`): the anchors are the
  // configuration of listeners only that process holds, and a worker changing
  // its own copy would change nothing a handshake reads. They are FANNED out
  // nowhere, answered nowhere else, and carry no realm: the array is the
  // process's, so every realm prefix reads and writes the same one.
  //
  // **THIS IS THE RUNTIME DOOR PRODUCT MODE HAD NONE OF.** `POST /tls/trust`
  // needs no credential and product mode refuses it; this API's own access
  // token is the credential here, `admin:read` to list and `admin:write` to
  // change — the gate below every operation, by method, so nothing in these two
  // rows re-checks it.
  // ---------------------------------------------------------------------------
  { method: 'GET', path: BASE + '/tls/trust', tag: 'TLS',
    operationId: 'getTruststore',
    summary: 'Every client-certificate trust anchor, and where each came from',
    description: 'The anchors 8443, 9443, LDAPS 636 and the main HTTPS port ' +
                 'verify a CLIENT certificate against. A certificate that ' +
                 'chains to one of these is verified, and a verified ' +
                 'certificate is an identity here — it starts a sign-on ' +
                 'session and it is what admits a remote XACML PEP to ' +
                 '`/xacml/pep/*` — so this list is whose certificates this ' +
                 'service believes.\n\nEach row carries the subject, issuer, ' +
                 'serial, validity, SHA-256 fingerprint (the colon form ' +
                 '`openssl x509 -fingerprint -sha256` prints), whether it is ' +
                 'a CA, the PEM, and `source`: `file` for one read from ' +
                 '`tls.trustAnchorsFile` at startup, `runtime` for one added ' +
                 'while the process was running, with `persisted` saying ' +
                 'whether it was written down.\n\n**A RUNTIME ANCHOR IS ' +
                 'PERSISTED** in `ou=trustAnchors` in the default realm\'s ' +
                 'directory, so it survives a restart wherever the directory ' +
                 'does (`persistence.mode` ldif or postgres) and reaches ' +
                 'every other process against the same store. A `file` ' +
                 'anchor is not stored there and comes back at the next ' +
                 'start however it was removed.\n\n**ONE TRUSTSTORE FOR THE ' +
                 'PROCESS, NOT PER REALM.** The listeners are shared by ' +
                 'every trust realm, so this answers the same list under ' +
                 'every realm prefix.\n\n**NO PRIVATE KEY IS IN THIS REPLY** ' +
                 '— the truststore holds certificates and nothing else.',
    mirrors: 'GET /admin/tls/trust',
    parameters: pagingParameters(),
    responseDescription: 'The anchors on this page with their paging, the ' +
                         'counts by source, the configured anchors file, and ' +
                         'which doors can change the list.',
    responseSchema: { type: 'object',
                      description: 'The truststore, paged.' },
    handler: function (req, res) {
      log.debug("Entering the management API truststore endpoint.");
      const json = adminViews.truststoreJson(req);
      if (!json.installed) {
        errorCodes.mark(res, 'STS-API-0017');
      }
      sendJson(res, json.installed ? 200 : 503, json);
      log.debug("Leaving the management API truststore endpoint.");
    } },

  { method: 'POST', route: BASE + '/tls/trust/:action', tag: 'TLS',
    mirrors: 'POST /admin/tls/trust',
    handler: function (req, res) {
      log.debug("Entering the management API truststore action endpoint.");
      const body = parseBody(req);
      const result = adminActions.truststoreAction(withAction(req, body),
                                                   { via: 'api' });
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0057');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API truststore action endpoint.");
    },
    actions: [
      { action: 'add', operationId: 'addTrustAnchors',
        summary: 'Trust client certificates issued by one or more CAs',
        description: 'Adds every `-----BEGIN CERTIFICATE-----` block in ' +
                     '`certificates` — the root, or the whole chain above ' +
                     'the leaf — and applies the new truststore to every ' +
                     'listener with `setSecureContext()`. The next handshake ' +
                     'is judged against it; connections already open keep ' +
                     'the truststore they were made under.\n\n**ALL OR ' +
                     'NOTHING ON A BLOCK OPENSSL CANNOT READ.** If any block ' +
                     'does not parse, none is added: an anchor the listener ' +
                     'cannot parse makes the next truststore change throw on ' +
                     'every listener. A certificate already held is counted ' +
                     'in `duplicates` and not added twice. The truststore ' +
                     'holds at most 32 anchors; an add that fills it keeps ' +
                     'what went in and says why the rest did not in ' +
                     '`warning`.\n\n**PERSISTED** in `ou=trustAnchors` ' +
                     'wherever the directory is; `persisted` in the reply ' +
                     'says whether every anchor this call added was written ' +
                     'down.\n\n**THIS IS THE GATED TWIN OF `POST ' +
                     '/tls/trust`**, which needs no credential and is ' +
                     'refused in product mode. This operation answers in ' +
                     'both modes. The reply names what was added and carries ' +
                     'no private key, because none is involved.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            certificates: { type: 'string',
                            description: 'One or more PEM certificates, ' +
                                         'concatenated. An array of PEM ' +
                                         'strings is accepted too.' }
          },
          required: ['certificates'],
          examples: [{ certificates: '-----BEGIN CERTIFICATE-----\n' +
                       'MIIBszCCAVmgAwIBAgIU…the Root CA of the client ' +
                       'certificates to trust…\n-----END CERTIFICATE-----\n' }],
          additionalProperties: false
        },
        responseDescription: 'How many anchors were added, how many were ' +
                             'already held, the new total, and the subject ' +
                             'and fingerprint of each one added.' },

      { action: 'remove', operationId: 'removeTrustAnchor',
        summary: 'Stop trusting one anchor, named by its fingerprint',
        description: 'Removes the ONE anchor whose SHA-256 fingerprint is ' +
                     '`fingerprint` — colon-separated or plain hex, either ' +
                     'case — and applies the smaller truststore to every ' +
                     'listener.\n\n**THERE IS NO BULK CLEAR ON THIS API, AND ' +
                     'THAT IS DELIBERATE.** A clear is the one change whose ' +
                     'reach is every client certificate every other caller ' +
                     'relies on; `POST /tls/trust/clear` exists as a ' +
                     'development test control and is refused in product ' +
                     'mode. Remove the rows you mean.\n\n**A `file` ANCHOR ' +
                     'MAY BE REMOVED AND COMES BACK AT THE NEXT START**, ' +
                     'when `tls.trustAnchorsFile` is read again; the reply ' +
                     'says so. A fingerprint this truststore does not hold ' +
                     'is refused and removes nothing.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            fingerprint: { type: 'string',
                           description: 'The anchor\'s SHA-256 fingerprint, ' +
                                        'as `GET /admin-api/tls/trust` lists ' +
                                        'it in `fingerprint256`.' }
          },
          required: ['fingerprint'],
          examples: [{ fingerprint: '3F:1A:9C:00:5B:7E:12:D4:88:6A:0B:C2:' +
                       '4E:91:7D:33:A0:5F:E6:21:9B:48:C7:0D:2E:84:16:F9:' +
                       '5A:C3:77:B0' }],
          additionalProperties: false
        },
        responseDescription: 'The anchor that was removed, where it came ' +
                             'from, and the new total.' }
    ] },

  // ---------------------------------------------------------------------------
  // THE STORED KERBEROS KEYS (2026-09-12).
  //
  // Rule 7: `/admin/kerberos/principals` has six controls — the two "Drop
  // previous versions" buttons joined the four on 2026-09-12 — so this resource
  // has the same six, through `kerberosPrincipalsAction()` and
  // `kerberosPrincipalsJson()` in `admin-core/`, which reach
  // `kerberos/krb5_person_keys.js` by a plain require.
  //
  // **NO KEY IS IN ANY REPLY BUT TWO**, and those two are the whole reason a
  // service principal can be created from a machine: `create-service` and
  // `rotate-service` return the KEYTAB, base64, ONCE. Nothing reads a stored
  // key back out afterwards — a lost keytab is replaced by rotating. The GET is
  // built from the public half of each pair of attributes and opens nothing.
  //
  // **A KDC PER TRUST REALM SINCE 2026-09-15**, so a call under a realm prefix
  // reads and writes THAT realm's principals — the people in its directory and
  // the service principals in its registry — and each reply says `trustRealm`.
  // A realm whose `krb5.enabled` is off has no principals and says so. Until
  // that date there was one KDC for the process and every prefix reached the
  // default realm's.
  // ---------------------------------------------------------------------------
  { method: 'GET', path: BASE + '/kerberos/principals', tag: 'Kerberos',
    operationId: 'getKerberosPrincipals',
    summary: 'Who the KDC holds a stored long-term key for',
    description: 'Two lists, paged separately with `?peoplePage=` and ' +
                 '`?servicesPage=` and one `?per=`.\n\n`people` — the ' +
                 'directory people whose Kerberos keys were derived from ' +
                 'their own password when it was set or verified (PRODUCT ' +
                 'MODE): the principal, the kvno, the enctypes, when and on ' +
                 'what event the keys were derived, whether they are sealed, ' +
                 'and `current` — whether they still match the password the ' +
                 'entry holds. A person whose keys are not current is ' +
                 'refused by the KDC until their next verified sign-in ' +
                 'derives new ones.\n\n`services` — the service principals ' +
                 'created with a RANDOM key: the principal, the kvno, the ' +
                 'enctypes, when created and last rotated.\n\n**NO KEY ' +
                 'MATERIAL IS IN THIS REPLY**, sealed or otherwise — both ' +
                 'lists are built from the public info attributes. The KDC ' +
                 'is the process\'s, so this answers the default trust ' +
                 'realm\'s principals under every realm prefix.',
    mirrors: 'GET /admin/kerberos/principals',
    // `per` and the two lists' own page parameters — NOT pagingParameters(),
    // whose `page` this resource never reads.
    parameters: pagingParameters().filter(function (one) {
      return one.name === 'per';
    }).concat(detailPagingParameters([
      { name: 'people',
        description: 'Directory people holding keys derived from their ' +
                     'own password.' },
      { name: 'services',
        description: 'Service principals created with a random key.' }
    ])),
    responseDescription: 'Both lists with their paging, whether this is a ' +
                         'product KDC, whether krb5.personKeys is on, the ' +
                         'enctypes and starting kvno, and the acceptor\'s SPN.',
    responseSchema: { type: 'object',
                      description: 'The stored Kerberos principals, paged.' },
    handler: function (req, res) {
      log.debug("Entering the management API Kerberos principals endpoint.");
      sendJson(res, 200, adminViews.kerberosPrincipalsJson(req));
      log.debug("Leaving the management API Kerberos principals endpoint.");
    } },

  { method: 'POST', route: BASE + '/kerberos/principals/:action',
    tag: 'Kerberos',
    mirrors: 'POST /admin/kerberos/principals',
    handler: function (req, res) {
      log.debug("Entering the management API Kerberos principals action " +
                "endpoint.");
      const body = parseBody(req);
      const result = adminActions.kerberosPrincipalsAction(
          withAction(req, body),
                                                           { via: 'api' });
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0065');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API Kerberos principals action " +
                "endpoint.");
    },
    actions: [
      { action: 'create-service', operationId: 'createKerberosServicePrincipal',
        summary: 'Create a service principal with a random key, and get its ' +
                 'keytab once',
        description: 'Makes a RANDOM key for every enctype in ' +
                     '`krb5.enctypes`, at kvno `krb5.kvno`, for `spn` in ' +
                     'this KDC\'s realm, stores them SEALED on the ' +
                     'application entry for `<spn>@<realm>` (creating that ' +
                     'entry if it is not there), and answers with an MIT ' +
                     'keytab (format 0x502) in `keytab`, base64.\n\n**THE ' +
                     'KEYTAB IS IN THIS REPLY AND NOWHERE ELSE**: it cannot ' +
                     'be downloaded again. A lost one is replaced by ' +
                     '`rotate-service`.\n\nThe KDC issues tickets for that ' +
                     'SPN under the stored key from the next request, in ' +
                     'both modes, and this service\'s own acceptor prefers ' +
                     'it when the SPN is `krb5.servicePrincipal`. Refused ' +
                     'for an SPN that already holds a stored key, for ' +
                     '`krbtgt/*`, for another realm, and for anything that ' +
                     'is not two or more `/`-separated components.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            spn: { type: 'string',
                   description: 'The service principal name, e.g. ' +
                                '`HTTP/web.example.com`, with or without ' +
                                '`@<realm>`.' }
          },
          required: ['spn'],
          examples: [{ spn: 'HTTP/app.example.com' }],
          additionalProperties: false
        },
        responseDescription: 'The principal, kvno, enctypes, the keytab ' +
                             '(base64) and a file name for it.' },

      { action: 'rotate-service', operationId: 'rotateKerberosServicePrincipal',
        summary: 'Replace a service principal\'s key, and get the new keytab ' +
                 'once',
        description: 'New random keys at the stored kvno PLUS ONE, and the ' +
                     'new keytab in `keytab`, base64.\n\n**THE VERSION IT ' +
                     'REPLACES IS KEPT** — at most ' +
                     '`krb5.retainedKeyVersions` previous versions, each for ' +
                     '`krb5.retainedKeyTtlS` (by default the ticket lifetime ' +
                     'plus the clock skew) — and **the keytab carries them ' +
                     'too**, as MIT\'s `ktadd` leaves one: `keytabKvnos` ' +
                     'lists every version in it and `retained` says until ' +
                     'when each is accepted. A ticket already issued under a ' +
                     'kept version is still accepted by this KDC and its ' +
                     'acceptor; nothing new is issued under it, and past its ' +
                     'window it is refused KRB_AP_ERR_BADKEYVER. ' +
                     '`drop-previous-service-keys` ends the window at once. ' +
                     'Refused for an SPN with no stored key.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            spn: { type: 'string', description: 'The service principal name.' }
          },
          required: ['spn'],
          examples: [{ spn: 'HTTP/app.example.com' }],
          additionalProperties: false
        },
        responseDescription: 'The principal, the new kvno, the enctypes and ' +
                             'the new keytab (base64).' },

      { action: 'delete-service', operationId: 'deleteKerberosServicePrincipal',
        summary: 'Delete a service principal\'s stored key',
        description: 'Removes the stored key and its info from the ' +
                     'application entry. The entry itself stays, as every ' +
                     'entry this registry records does. A ticket for that ' +
                     'SPN is then keyed as it was before a key was stored: ' +
                     'from `krb5.servicePassword` if it is the acceptor\'s ' +
                     'own name, and not at all in product mode otherwise.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            spn: { type: 'string', description: 'The service principal name.' }
          },
          required: ['spn'],
          examples: [{ spn: 'HTTP/app.example.com' }],
          additionalProperties: false
        },
        responseDescription: 'The principal whose key was deleted.' },

      { action: 'clear-person-keys', operationId: 'clearKerberosPersonKeys',
        summary: 'Clear a directory person\'s Kerberos keys',
        description: 'Removes the Kerberos keys derived from `username`\'s ' +
                     'password. Their next AS-REQ is refused with "sign in ' +
                     'once"; their next verified sign-in derives new keys at ' +
                     'the next kvno. Somebody with no keys answers `cleared: ' +
                     'false` rather than a refusal, so a script may clear on ' +
                     'every run. There is no operation that SETS a person\'s ' +
                     'keys: they come from the person\'s password and from ' +
                     'nothing else.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            username: { type: 'string',
                        description: 'The person, as they sign in — in the ' +
                                     'default trust realm\'s directory.' }
          },
          required: ['username'],
          examples: [{ username: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'Whether anything was cleared.' },

      { action: 'drop-previous-service-keys',
        operationId: 'dropKerberosServicePreviousKeys',
        summary: 'Stop accepting tickets under a service principal\'s ' +
                 'previous key versions, now',
        description: 'Removes the PREVIOUS key versions a rotation kept for ' +
                     '`spn`, leaving the current key and its keytab ' +
                     'untouched. A ticket issued under a dropped version is ' +
                     'refused KRB_AP_ERR_BADKEYVER from the next request, ' +
                     'rather than when `krb5.retainedKeyTtlS` would have ' +
                     'ended its window — which is what an operator wants ' +
                     'after a keytab is compromised. Nothing kept answers ' +
                     '`dropped: 0` rather than a refusal. Refused for an SPN ' +
                     'with no stored key, and for a key this service cannot ' +
                     'open.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            spn: { type: 'string', description: 'The service principal name.' }
          },
          required: ['spn'],
          examples: [{ spn: 'HTTP/app.example.com' }],
          additionalProperties: false
        },
        responseDescription: 'How many previous versions were dropped, their ' +
                             'kvnos, and the current kvno.' },

      { action: 'drop-previous-person-keys',
        operationId: 'dropKerberosPersonPreviousKeys',
        summary: 'Stop accepting tickets under a person\'s previous key ' +
                 'versions, now',
        description: 'Removes the PREVIOUS key versions a password change ' +
                     'kept for `username`, leaving their current keys — and ' +
                     'so their sign-in — untouched. A ticket sealed under a ' +
                     'dropped version is refused KRB_AP_ERR_BADKEYVER from ' +
                     'the next request. A previous version was never a way ' +
                     'in: pre-authentication uses the current keys only, so ' +
                     'an old password is refused whether or not this is ' +
                     'called. Nothing kept answers `dropped: 0`.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            username: { type: 'string',
                        description: 'The person, as they sign in — in the ' +
                                     'default trust realm\'s directory.' }
          },
          required: ['username'],
          examples: [{ username: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'How many previous versions were dropped, their ' +
                             'kvnos, and the current kvno.' }
    ] },

  { method: 'GET', path: BASE + '/audit', tag: 'Audit log',
    operationId: 'getAudit',
    summary: 'What happened here, in order, filtered and paged',
    description: 'Every authentication, session, LDAP directory operation, ' +
                 'console interaction, management API call and protocol ' +
                 'endpoint call, newest first.\n\nThis is HISTORY where the ' +
                 'rest of this API is STATE. /admin-api/metrics can say the ' +
                 'directory holds eleven entries; only this can say a ' +
                 'twelfth was created at 14:02 and deleted at 14:03 by ' +
                 'somebody bound as `uid=carol`, over LDAPS.\n\n**NO ' +
                 'CREDENTIAL IS EVER IN A ROW.** Not a password, not a ' +
                 'bearer token, not an assertion, and no request or response ' +
                 'body. A modify names the attributes it changed and never ' +
                 'their values, because a modify is where a `userPassword` ' +
                 'gets set; a compare says whether it matched and not what ' +
                 'was tried; an authorization code in a query string is ' +
                 'replaced with `(redacted)`.\n\n**One act usually produces ' +
                 'several events.** A sign-in writes three — the HTTP call, ' +
                 'the credential being accepted, and the session that came ' +
                 'out of it. They are three facts at three layers, and a ' +
                 'Kerberos AS-REQ authenticates somebody and starts no ' +
                 'session at all.\n\nWALK IT BY `seq`, not by page. That ' +
                 'number is monotonic and never reused, including across a ' +
                 'drop, so "everything after 4102" is exact; a gap between ' +
                 'the last one you saw and `oldestSeq` is precisely how many ' +
                 'events you missed while the cap discarded them.',
    mirrors: 'GET /admin/audit',
    parameters: [
      { name: 'category', in: 'query', required: false,
        schema: { type: 'string',
                  enum: ['authentication', 'session', 'directory', 'admin',
                         'api', 'application', 'protocol', 'spiffe',
                         'signals', 'authorization', 'service'] },
        description: 'One of the categories. The reply\'s `categories` ' +
                     'member describes each of them.' },
      { name: 'action', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'One action. ANDed with `category`, so an action from ' +
                     'another category matches nothing — which is what an ' +
                     'empty list then means. The reply\'s `actions` member ' +
                     'lists every action with the category it belongs to.' },
      { name: 'outcome', in: 'query', required: false,
        schema: { type: 'string', enum: ['success', 'refused', 'error'] },
        description: 'Three rather than two on purpose: a `refused` is this ' +
                     'service working correctly and saying no, an `error` is ' +
                     'this service failing, and collapsing them would bury ' +
                     'the one row worth paging somebody about under the ' +
                     'fifty that are a client getting its parameters wrong.' },
      { name: 'actor', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'Substring of either spelling of the actor, ' +
                     'case-insensitive — the normalised key (`alice`) or the ' +
                     'form it was presented in (a bind DN, `alice@REALM`, an ' +
                     'X.509 subject). A substring because the collapse to ' +
                     'one key can only be done where an identity is ' +
                     'normalised, and a directory row\'s actor is a DN.' },
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the summary, the target or the action, ' +
                     'case-insensitive.' },
      { name: 'code', in: 'query', required: false, schema: { type: 'string' },
        description: 'The FRONT of an error code: a whole code is one ' +
                     'failure condition and `STS-OAUTH` every failure in ' +
                     'that subsystem. docs/error-codes.md lists them. Every ' +
                     'refused or failed request carries a code; no code is ' +
                     'ever sent to the client that made the request.' }
    ].concat(pagingParameters()),
    responseDescription: 'The matching events, with the paging that found ' +
                         'them and the vocabulary the filters take.',
    responseSchema: { $ref: '#/components/schemas/AuditList' },
    handler: function (req, res) {
      log.debug("Entering the management API audit endpoint.");
      sendJson(res, 200, adminViews.auditView(req.query).json);
      log.debug("Leaving the management API audit endpoint.");
    } },

  // THE ERROR CODES (2026-09-12). A read with no write beside it, which is rule
  // 7 read exactly: the page it mirrors has no control, because the table is
  // source and a code's meaning cannot change at runtime without making every
  // alert rule written against it a statement about something else.
  { method: 'GET', path: BASE + '/error-codes', tag: 'Audit log',
    operationId: 'getErrorCodes',
    summary: 'Every failure condition this service can produce, and how ' +
             'often each is on the held audit log',
    description: 'The central table of error codes, ' +
                 '`STS-<SUBSYSTEM>-<NNNN>`, filtered and paged: each code ' +
                 'with the subsystem it belongs to, what failed, and what ' +
                 'the CLIENT is told in its protocol\'s own vocabulary ' +
                 '(`spec`).\n\n**A CODE IS NEVER SENT TO A CLIENT.** It is ' +
                 'recorded on the audit row (`errorCode` on GET ' +
                 '/admin-api/audit, filterable there with `?code=`) and at ' +
                 'the front of the service log line; every protocol response ' +
                 'is exactly what it was.\n\n`seen` counts the rows the ' +
                 'audit log holds IN THIS REALM right now, so it falls as ' +
                 'the log\'s cap discards the oldest, and it is zero for a ' +
                 'failure recorded only as a log line — a startup refusal, ' +
                 'or anything the remote PEP container records. ' +
                 '`unregisteredSeen` lists codes found on held rows that the ' +
                 'table does not hold, each a failure site whose code was ' +
                 'never registered.\n\nThe same table is published as ' +
                 'docs/error-codes.md, generated from common/error_codes.js.',
    mirrors: 'GET /admin/error-codes',
    parameters: [
      { name: 'subsystem', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'One subsystem id — `OAUTH`, `LDAP`, `XPEP` — as ' +
                     '`subsystems[].id` lists them. Case-insensitive.' },
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the code, the summary or what the client ' +
                     'sees, case-insensitive — a code pasted out of a log ' +
                     'line, or a protocol error name such as ' +
                     '`invalid_grant`.' },
      { name: 'seen', in: 'query', required: false, schema: { type: 'string' },
        description: '`1` for only the codes on at least one held audit row.' }
    ].concat(pagingParameters()),
    responseDescription: 'The matching codes, the subsystems with their ' +
                         'counts, and the paging that found them.',
    responseSchema: { type: 'object',
      description: 'The error code table: `codes` (this page, each with ' +
                   '`code`, `subsystem`, `summary`, `spec`, `retired`, ' +
                   '`seen` and `lastSeenAt`), `subsystems` (each with `id`, ' +
                   '`prefix`, `label`, `where`, `what`, `codes` and `seen`), ' +
                   '`unregisteredSeen`, `registered`, `retired`, ' +
                   '`auditRowsHeld`, `auditRowsWithCode`, ' +
                   '`distinctCodesSeen`, `filter` and the paging members.' },
    handler: function (req, res) {
      log.debug("Entering the management API error codes endpoint.");
      sendJson(res, 200, adminViews.errorCodesView(req.query).json);
      log.debug("Leaving the management API error codes endpoint.");
    } },

  // THE USED-ASSERTION HISTORY (2026-09-13). A read with no write beside it,
  // which is rule 7 read exactly: the page it mirrors has no control, because
  // forgetting a row would make a still-valid assertion usable again. A
  // PROMISE, because on a postgres store the history is the database's.
  { method: 'GET', path: BASE + '/used-assertions', tag: 'Tokens',
    operationId: 'getUsedAssertions',
    summary: 'Every RFC 7523 and RFC 7522 assertion this realm has accepted ' +
             'and that has not yet expired',
    description: 'The used-assertion history: every RFC 7523 JWT and RFC ' +
                 '7522 SAML assertion accepted in THIS REALM — as client ' +
                 'authentication (`client_assertion`) or as an ' +
                 'authorization grant (`assertion`) — and not yet expired, ' +
                 'newest first, filtered and paged.\n\n**AN ASSERTION IS ' +
                 'ACCEPTED ONCE, EVER.** One history for both uses and both ' +
                 'profiles, keyed by format, issuer and `jti`/`ID`, so a JWT ' +
                 'that authenticated a client is refused as a grant and the ' +
                 'reverse. `state` is `reserved` while the token request it ' +
                 'came with has not finished, and `spent` once that response ' +
                 'was a 2xx; a request that failed for another reason ' +
                 'releases the assertion and it is not listed.\n\n' +
                 '`persistent` says whether the history survives a restart ' +
                 '(it does in the `ldif` and `postgres` stores, in both ' +
                 'modes), and `atomicAcrossProcesses` whether recording a use ' +
                 'is one claim every process agrees on at once (postgres). A ' +
                 'row is kept until `expiresAt` — the assertion\'s own expiry ' +
                 'plus the skew allowed when it was read — and `live` is how ' +
                 'many are held against `cap` ' +
                 '(`oauth2.assertionReplayCacheSize`). No assertion and no ' +
                 'credential is in any row.\n\nREAD ONLY.',
    mirrors: 'GET /admin/used-assertions',
    parameters: [
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the issuer, the `jti` or `ID`, the client ' +
                     'or the subject, case-insensitive.' },
      { name: 'format', in: 'query', required: false,
        schema: { type: 'string', enum: ['jwt', 'saml'] },
        description: '`jwt` (RFC 7523) or `saml` (RFC 7522).' },
      { name: 'use', in: 'query', required: false,
        schema: { type: 'string',
                  enum: ['client-authentication', 'authorization-grant'] },
        description: 'What the assertion was accepted AS.' },
      { name: 'state', in: 'query', required: false,
        schema: { type: 'string', enum: ['reserved', 'spent'] },
        description: '`reserved` (its token request has not finished) or ' +
                     '`spent` (tokens were issued).' }
    ].concat(pagingParameters()),
    responseDescription: 'This realm\'s unexpired used assertions, where the ' +
                         'history is held, and the paging that found them.',
    responseSchema: { type: 'object',
      description: 'The used-assertion history: `rows` (this page, each with ' +
                   '`format`, `formatLabel`, `use`, `useLabel`, `issuer`, ' +
                   '`identifier`, `clientId`, `subject`, `state`, `usedAt`, ' +
                   '`spentAt`, `expiresAt` and `origin`, times in ' +
                   'milliseconds), `store`, `persistent`, ' +
                   '`atomicAcrossProcesses`, `storeNote`, `cap`, `live`, ' +
                   '`matched`, `shown`, `filter`, `formats`, `uses`, `states` ' +
                   'and the paging members.' },
    handler: function (req, res) {
      log.debug("Entering the management API used assertions endpoint.");
      adminViews.usedAssertionsView(req.query).then(function (view) {
        sendJson(res, 200, view.json);
        log.debug("Leaving the management API used assertions endpoint.");
      }).catch(function (e) {
        errorCodes.mark(res, 'STS-API-0081');
        sendJson(res, 500, { ok: false, errors: [
          'The used-assertion history could not be read: ' +
          (e && e.message ? e.message : String(e))] });
        log.debug("Leaving the management API used assertions endpoint. It " +
                  "threw.");
      });
      log.debug("Leaving handler().");
    } },

  // Delegation. THE SECOND READ-ONLY RESOURCE HERE, and for a related reason to
  // the audit log's: it mirrors a console page with no form on it. Everything
  // that page shows is an observation — an act happened or it did not, and the
  // policy half is the KERBEROS principal database's configuration, which is
  // not settable from anywhere in this service. There is nothing to change, so
  // there is nothing to document as changeable, and rule 7 is satisfied by this
  // GET alone.
  { method: 'GET', path: BASE + '/delegation', tag: 'Delegation',
    operationId: 'getDelegation',
    summary: 'Who acted on whose behalf, through what, to reach what',
    description: 'Every delegation this service has performed or REFUSED, in ' +
                 'one model across three protocol families, plus the ' +
                 'configured policy that decides the Kerberos ones.\n\nEight ' +
                 'mechanisms: Kerberos S4U2Self, S4U2Proxy (classic and ' +
                 'resource-based) and a forwarded ticket-granting ticket; ' +
                 'WS-Trust `OnBehalfOf` and `ActAs`; RFC 8693 token exchange ' +
                 'in both its shapes. They are recorded against ONE model ' +
                 'because the question is protocol-independent: which hop ' +
                 'invented which identity.\n\n**The axis worth filtering on ' +
                 'is `mode`.** Under a `delegation` the credential CARRIES ' +
                 'the chain — an `act` claim, a composite `ActAs`, ' +
                 '`S4U_DELEGATION_INFO` in the PAC — so the far end can see ' +
                 'who is really asking. Under an `impersonation` nothing ' +
                 'does, which means this endpoint is the ONLY place that ' +
                 'fact is ever visible: no reading of the token afterwards ' +
                 'can recover it.\n\n**Refusals are here and are most of the ' +
                 'value.** A refused act carries `reason` — the KDC\'s own ' +
                 'words, the same sentence the client was sent — naming the ' +
                 'two accounts and the two attributes and which was missing. ' +
                 'A refused delegation appears in NO other resource here: ' +
                 'nothing was accepted, so /admin-api/audit and ' +
                 '/admin-api/users have nothing to say about ' +
                 'it.\n\n**Nothing checks who may delegate except the KDC.** ' +
                 'WS-Trust and token exchange are unpoliced here, and each ' +
                 'act says so in the field that names an attribute for a ' +
                 'Kerberos one.\n\nBesides the paged acts the reply carries ' +
                 '`chains` — the distinct (mechanism, initial, intermediary, ' +
                 'target) tuples among what MATCHED, one per edge of the ' +
                 'picture — `applications`, every application an act named ' +
                 'in WHATEVER ROLE it played (the console draws one of them ' +
                 'in full at /admin/delegation/application) — and `policy`, ' +
                 'which is who may delegate to whom before anybody has ' +
                 'tried.\n\n**THIS IS THE DELEGATION REGISTER AND NOT ' +
                 'EVERYTHING A PERSON WAS ISSUED.** An ordinary grant is not ' +
                 'a delegation act and is not here: for one identity END TO ' +
                 'END — every credential with the exact grant or flow that ' +
                 'produced it, beside the acts naming them — the console ' +
                 'unions this register with the issued one at ' +
                 '/admin/delegation/user?user=…&format=json, and the tokens ' +
                 'alone are in GET /admin-api/users.\n\nWALK IT BY `seq`: ' +
                 'monotonic and never reused, including across a drop.',
    mirrors: 'GET /admin/delegation',
    parameters: [
      { name: 'type', in: 'query', required: false,
        schema: { type: 'string',
                  enum: ['krb5-s4u2self', 'krb5-s4u2proxy-classic',
                         'krb5-s4u2proxy-rbcd', 'krb5-forwarded',
                         'wstrust-onbehalfof', 'wstrust-actas',
                         'oauth-impersonation', 'oauth-delegation'] },
        description: 'One mechanism. The reply\'s `types` member describes ' +
                     'each of them, with the specification it comes from and ' +
                     'whether this service polices it.' },
      { name: 'mode', in: 'query', required: false,
        schema: { type: 'string', enum: ['impersonation', 'delegation'] },
        description: 'The protocol-independent axis: whether what came out ' +
                     'carries the chain. ANDed with `type`, so a mode that ' +
                     'does not match the mechanism matches nothing.' },
      { name: 'outcome', in: 'query', required: false,
        schema: { type: 'string', enum: ['issued', 'refused'] },
        description: 'Two rather than the audit log\'s three: a delegation ' +
                     'is DECIDED rather than performed, so there is no third ' +
                     'answer between issuing the credential and refusing to.' },
      { name: 'protocol', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'The family, spelled as /admin-api/users spells it — ' +
                     '`Kerberos v5`, `WS-Trust`, `OAuth 2.0`. Free text ' +
                     'rather than an enum, for the reason the audit log\'s ' +
                     '`protocol` is.' },
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of ANY party of the chain (normalised name, ' +
                     'presented form or application) or of either ' +
                     'explanation, case-insensitive. One box over six ' +
                     'fields, because the fact a caller has names one of ' +
                     'them and not which column it is in.' }
    ].concat(pagingParameters()),
    responseDescription: 'The matching acts, the distinct chains among them, ' +
                         'the configured Kerberos policy, and the vocabulary ' +
                         'the filters take.',
    responseSchema: { $ref: '#/components/schemas/DelegationList' },
    handler: function (req, res) {
      log.debug("Entering the management API delegation endpoint.");
      sendJson(res, 200, adminViews.delegationView(req.query).json);
      log.debug("Leaving the management API delegation endpoint.");
    } },

  // -------------------------------------------------------------------------
  // DELEGATED PERMISSIONS — the CONFIGURED half of /admin/delegation.
  //
  // A RESOURCE OF ITS OWN RATHER THAN MORE ACTIONS ON `/delegation`, and the
  // reason is the same one the console gives for putting two headings on one
  // page: the acts and the permissions are two registers, and an API that
  // answered both under one path would make a caller tell them apart by the
  // shape of a row.
  //
  // THIS COMMENT SAID `GET /admin-api/delegation` CARRIES THE REGISTER IN AN
  // `allowed` MEMBER, AND IT NEVER HAS (corrected 2026-09-01). Only the
  // CONSOLE route adds that member; this endpoint answers
  // `delegationView(query).json`, which is the ACTS view, the one shared with
  // /admin/delegation/map. The behaviour is right — see that function's
  // header, where folding a second register into it is refused because every
  // caller of the acts view would then pay for a walk of ou=applications it
  // did not ask for — so the sentence went and the code stayed. This resource
  // is where the register is reachable under its own name.
  //
  // THE FIVE ACTION NAMES STUTTER SLIGHTLY UNDER THIS PATH
  // (`/permissions/define-permission`) AND THAT IS DELIBERATE. They are the
  // names in the console's hidden `action` inputs, where the page they sit on
  // is `/admin/delegation` and `define` alone would say nothing about what is
  // being defined — and `remove` and `revoke` are two different things here
  // (one removes a permission somebody exposes, the other takes a grant away
  // from a client). One vocabulary for both doors is worth more than a shorter
  // URL, and rule 7's parity check reads the console's own list.
  // -------------------------------------------------------------------------
  { method: 'GET', path: BASE + '/permissions', tag: 'Delegation',
    operationId: 'getPermissions',
    summary: 'Which applications may reach which, decided in advance',
    description: 'The CONFIGURED delegation register, in Microsoft Entra ' +
                 'ID\'s shape. It is the other half of `GET ' +
                 '/admin-api/delegation`: that one is what HAPPENED — acts, ' +
                 'evidence, one row per exchange — and this one is INTENT, ' +
                 'typed in before anybody asked for anything.\n\n**How it ' +
                 'works.** A RESOURCE application is given a base URI ' +
                 '(`oauthPermissionBaseUri`; Entra calls it the Application ' +
                 'ID URI and spells it `api://<guid>`, and anything absolute ' +
                 'works here) and permissions on it (`oauthPermission`). A ' +
                 'permission is identified by the two joined — ' +
                 '`https://example.com/` + `write` = ' +
                 '`https://example.com/write` — and a CLIENT application is ' +
                 'granted some of them (`oauthDelegatedPermission`). All ' +
                 'three are ordinary attributes on ordinary entries in ' +
                 '`ou=applications`, so an `ldapmodify` is a configuration ' +
                 'change here exactly as it is for a redirect URI.\n\n**What ' +
                 'the token then says.** A client asks for a permission as ' +
                 'an ordinary OAuth `scope`, and the access token comes back ' +
                 'AUDIENCED to the base URI with the permission NAME on its ' +
                 'scope claim: `scope=openid https://example.com/write` ' +
                 'produces `aud: https://example.com/` and `scope: openid ' +
                 'write`. Each grant row spells that out, because it is two ' +
                 'facts a caller would otherwise have to compose.\n\n**It ' +
                 'refuses nothing by default.** An ungranted permission is ' +
                 'honoured exactly as a granted one is and marked here; only ' +
                 '`oauth2.delegatedPermissionsEnforced` turns it into ' +
                 '`invalid_scope`, at the authorization endpoint where the ' +
                 'client can still be told.\n\n`grants[].dangling` is a ' +
                 'grant naming a permission no application defines — a ' +
                 'deleted resource, a permission removed from under it, or ' +
                 'an `ldapmodify`, since both console doors refuse to create ' +
                 'one. `grants[].asked` is whether the client has ever ' +
                 'requested that scope, read off its own `oauthScope`: ' +
                 'evidence rather than proof, and the one thing here that ' +
                 'comes from what happened.\n\nThe `graph` member is the ' +
                 'same picture /admin/delegation/allowed draws, in the shape ' +
                 '`GET /admin-api/delegation`\'s `graph` uses.',
    mirrors: 'GET /admin/delegation',
    responseDescription: 'Every application exposing an API, every ' +
                         'permission defined, every grant between two ' +
                         'applications, and the graph of them.',
    responseSchema: { type: 'object',
                      description: 'The configured delegated permission ' +
                                   'register, both directions.' },
    handler: function (req, res) {
      log.debug("Entering the management API permissions endpoint.");
      const view = adminViews.permissionsView();
      sendJson(res, 200,
               Object.assign({}, view.register, { graph: view.graph }));
      log.debug("Leaving the management API permissions endpoint.");
    } },

  // -------------------------------------------------------------------------
  // THE GROUPINGS, AS A RESOURCE OF ITS OWN (2026-09-02).
  //
  // A MEMBER ON `GET /permissions` WOULD HAVE BEEN THE SHORTER CHANGE AND IT IS
  // THE WRONG ONE, for the reason that reply's own `graph` member is the
  // boundary rather than an example. `graph` is one document about the whole
  // register and its size is the register's; a list of groups that carried its
  // grants would repeat the register once per group, and one that did not would
  // leave a caller no way to ask for a single group's rows at all. It also
  // needs PAGING — the console's own list of groups is paged, and a member of
  // somebody else's reply has nowhere to put a page number.
  //
  // ONE OPERATION ANSWERS BOTH SHAPES, `?application=` deciding which, because
  // they are the same question at two scales and the console draws them with
  // one function: without it, every group with its counts; with it, the ONE
  // group that application is in, with its grants, its permissions and the
  // graph /admin/delegation/cluster draws. Two operations would have been two
  // places to disagree about what a group is.
  //
  // It mirrors `GET /admin/delegation` like the register beside it — the
  // console pages it belongs to are drill-downs of that tab, and rule 7's
  // parity check reads a NAV path.
  // -------------------------------------------------------------------------
  { method: 'GET', path: BASE + '/permissions/groups', tag: 'Delegation',
    operationId: 'getPermissionGroups',
    summary: 'Which applications are joined to each other by delegated ' +
             'permissions',
    description: 'The configured register PARTITIONED: a group is a set of ' +
                 'applications that can be reached from one another by ' +
                 'following grants, **ignoring which way each grant ' +
                 'points**.\n\nDirection is dropped for MEMBERSHIP and kept ' +
                 'on every line of the picture. Following the arrows would ' +
                 'answer *what can this client eventually reach*, which is a ' +
                 'question about a chain, and a permission register has no ' +
                 'chains in it: holding a permission on an API grants nobody ' +
                 'that API\'s own permissions. Following a grant either way ' +
                 'is the only reading under which an API and the three front ' +
                 'ends holding permissions on it come out as ONE group ' +
                 'rather than as four.\n\n**The membership universe is what ' +
                 'the CONFIGURED register touches**: every application ' +
                 'carrying a base URI or a permission of its own, and every ' +
                 'application holding a grant. An entry in `ou=applications` ' +
                 'that is neither is in no group, because this register has ' +
                 'nothing to say about it.\n\nThree states join no two ' +
                 'applications, and each produces a group of ONE rather than ' +
                 'being left out: a DANGLING grant (no application defines ' +
                 'the permission, so there is no far end), a grant an ' +
                 'application made to ITSELF (one application however it is ' +
                 'drawn), and a resource nobody holds anything on — which is ' +
                 'the most interesting group of one there is, since somebody ' +
                 'described an API and nothing may reach it.\n\nA group is ' +
                 'NAMED after the identifier of its members that sorts ' +
                 'first. That is a property of the SET, so adding a grant ' +
                 'inside a group does not rename it.\n\nWith no ' +
                 '`application`, every group with its counts and no rows, ' +
                 'biggest first and paged on `groupsPage` — the shape ' +
                 '/admin/delegation/allowed lists. With `application`, the ' +
                 'ONE group that application is in, with its permissions ' +
                 'paged on `groupPermissionsPage`, its grants paged on ' +
                 '`groupGrantsPage`, and the `graph` ' +
                 '/admin/delegation/cluster draws, in the shape `GET ' +
                 '/admin-api/delegation`\'s `graph` uses. An application the ' +
                 'configured register has never heard of answers 200 with ' +
                 '`group: null`, not 404: having no permissions configured ' +
                 'is the ordinary state of most entries in this registry, ' +
                 'and it is a fact rather than an error. **The identifier is ' +
                 'matched EXACTLY** — nothing in this service case-folds ' +
                 'one, so `WebApp1` and `webapp1` are two applications.',
    mirrors: 'GET /admin/delegation',
    parameters: [
      { name: 'application', in: 'query',
        description: 'One application\'s identifier. Answers the group it is ' +
                     'in, with its rows and its graph, instead of the list ' +
                     'of every group. Matched exactly.',
        schema: { type: 'string' } },
      { name: 'groupsPage', in: 'query',
        description: 'Which page of the group LIST. The same name the ' +
                     'console page uses, because a group list is one of ' +
                     'several lists a delegation page can hold and a bare ' +
                     '`page` would move them together. Not read when ' +
                     '`application` is given.',
        schema: { type: 'integer', minimum: 1 } },
      { name: 'groupGrantsPage', in: 'query',
        description: 'Which page of the GRANTS inside one group. Read only ' +
                     'when `application` is given.',
        schema: { type: 'integer', minimum: 1 } },
      { name: 'groupPermissionsPage', in: 'query',
        description: 'Which page of the PERMISSIONS the applications in one ' +
                     'group expose, granted or not. Read only when ' +
                     '`application` is given.',
        schema: { type: 'integer', minimum: 1 } },
      { name: 'per', in: 'query',
        description: 'Rows per page, shared by both lists above — one `per` ' +
                     'per page is this console\'s rule and this operation ' +
                     'follows it.',
        schema: { type: 'integer', minimum: 1 } }
    ],
    responseDescription: 'Every group with its members and counts, or the ' +
                         'one group an application is in with its grants, ' +
                         'its permissions and its graph.',
    responseSchema: { type: 'object',
                      description: 'The configured register partitioned into ' +
                                   'groups of applications that can reach ' +
                                   'one another, direction ignored.' },
    handler: function (req, res) {
      log.debug("Entering the management API permission groups endpoint.");
      sendJson(res, 200, adminViews.permissionGroupsView(req.query));
      log.debug("Leaving the management API permission groups endpoint.");
    } },

  { method: 'POST', route: BASE + '/permissions/:action', tag: 'Delegation',
    mirrors: 'POST /admin/delegation',
    handler: function (req, res) {
      log.debug("Entering the management API permissions action endpoint.");
      const body = parseBody(req);
      const result = adminActions.permissionsAction(withAction(req, body));
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0058');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API permissions action endpoint.");
    },
    actions: [
      { action: 'set-permission-base', operationId: 'setPermissionBase',
        summary: 'Give an application the base URI its permissions hang off',
        description: 'The first step of exposing an API, and the one that ' +
                     'makes every permission on the entry NAMEABLE: a ' +
                     'permission is identified by this value followed by its ' +
                     'name, so an application with permissions and no base ' +
                     'has permissions no client can ever ask for.\n\nIt must ' +
                     'be ABSOLUTE, because it becomes the `aud` of an access ' +
                     'token and an audience that is not absolute is one ' +
                     'nothing can compare against. A trailing separator is ' +
                     'ADDED where there is none — `https://example.com` ' +
                     'becomes `https://example.com/` — because the ' +
                     'identifier is a plain concatenation and the two would ' +
                     'otherwise join into one word. An `ldapmodify` is not ' +
                     'normalised and means exactly what it says.\n\nSending ' +
                     'an empty value CLEARS it. The permissions stay on the ' +
                     'entry with no identifier, which `GET ' +
                     '/admin-api/permissions` reports, and grants already ' +
                     'made become `dangling` on the clients holding them. ' +
                     'Neither is tidied up: that would be this operation ' +
                     'writing to entries the caller did not name.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            resource: { type: 'string',
                        description: 'The application that EXPOSES the API, ' +
                                     'by its identifier exactly as ' +
                                     '`ou=applications` holds it.' },
            baseUri: { type: 'string',
                       description: 'An absolute URI. Empty clears it.' }
          },
          required: ['resource'],
          examples: [{ resource: 'api1', baseUri: 'https://example.com/' }],
          additionalProperties: false
        },
        responseDescription: 'The application as it now stands, and what a ' +
                             'permission on it is now called.' },

      { action: 'define-permission', operationId: 'definePermission',
        summary: 'Expose one permission on an application',
        description: 'Entra ID\'s `oauth2PermissionScopes`, one at a ' +
                     'time.\n\nThe NAME is what ends up on the access ' +
                     'token\'s `scope` claim, so it must be a legal OAuth ' +
                     'scope token: any printable ASCII except space, double ' +
                     'quote and backslash (RFC 6749 section 3.3), and not ' +
                     '`|`, which separates the name from the description in ' +
                     'the attribute. The DESCRIPTION is optional and is ' +
                     'stored after the first `|` in the same ' +
                     'value.\n\n**Defining a permission grants it to ' +
                     'nobody.** That is the ordering this feature is built ' +
                     'on and the reason this operation and ' +
                     '`grant-permission` are two: a permission must exist ' +
                     'before anything can be granted it, and the check is in ' +
                     '`applications.updateApplication()` so that this ' +
                     'operation, the console form and the generic `POST ' +
                     '/admin-api/applications/update` cannot disagree about ' +
                     'it.\n\nA second permission of the SAME NAME is refused ' +
                     'rather than merged — a permission has one description, ' +
                     'and two rows with one name would leave the second ' +
                     'unreachable. Remove it and define it again to change ' +
                     'the wording.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            resource: { type: 'string',
                        description: 'The application that exposes it.' },
            name: { type: 'string',
                    description: 'The permission name — the word a client ' +
                                 'will send inside a `scope`.' },
            description: { type: 'string',
                           description: 'Optional prose, shown wherever the ' +
                                        'permission is.' }
          },
          required: ['resource', 'name'],
          examples: [{ resource: 'api1', name: 'write',
                       description: 'Change widgets on somebody\'s behalf' }],
          additionalProperties: false
        },
        responseDescription: 'The permission\'s identifier, and what a ' +
                             'request naming it would be issued.' },

      { action: 'remove-permission', operationId: 'removePermission',
        summary: 'Stop exposing a permission',
        description: 'Named by its NAME rather than by the raw attribute ' +
                     'value, because that value is `name|description` and a ' +
                     'caller holding a stale description would fail to ' +
                     'remove anything.\n\n**Grants naming it are NOT ' +
                     'revoked.** They stay on the clients\' entries and ' +
                     'become `dangling`, which `GET /admin-api/permissions` ' +
                     'reports and the reply here counts. Revoking them would ' +
                     'be this operation writing to entries the caller did ' +
                     'not name; define the permission again and every one of ' +
                     'them resolves exactly as before.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            resource: { type: 'string',
                        description: 'The application that exposes it.' },
            name: { type: 'string', description: 'The permission name.' }
          },
          required: ['resource', 'name'],
          examples: [{ resource: 'api1', name: 'write' }],
          additionalProperties: false
        },
        responseDescription: 'What was removed, and how many grants it ' +
                             'stranded.' },

      { action: 'grant-permission', operationId: 'grantPermission',
        summary: 'Grant a client application a permission on another one',
        description: '**THE DELEGATION RELATIONSHIP ITSELF** — Entra ID\'s ' +
                     '`requiredResourceAccess`, one permission at a ' +
                     'time.\n\nIt lands on the CLIENT\'s entry, as a value ' +
                     'of `oauthDelegatedPermission`, because the client is ' +
                     'the party that will name the permission in a `scope` — ' +
                     'so the entry that answers *may this request be ' +
                     'honoured* is the entry the request identifies. One ' +
                     'client granted three permissions is three calls and ' +
                     'three values; three clients granted one permission is ' +
                     'one value on each of three entries. That is how ' +
                     'one-to-many and many-to-one both work with no store of ' +
                     'their own.\n\n**The permission must already be ' +
                     'DEFINED**, matched EXACTLY rather than as a prefix of ' +
                     'a registered base — so a client cannot address a token ' +
                     'to somebody\'s API by inventing a word after their ' +
                     'base URI. An application cannot be granted its own ' +
                     'permission: the token would be addressed to itself, ' +
                     'which is what an ID Token already is.\n\n**It changes ' +
                     'nothing about what is issued** unless ' +
                     '`oauth2.delegatedPermissionsEnforced` is on. With it ' +
                     'off — the default — the request was already producing ' +
                     'the audience and the scope, and what the grant changes ' +
                     'is that the console stops marking it ungranted.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            client: { type: 'string',
                      description: 'The application that WILL ASK — the one ' +
                                   'whose `client_id` appears on the token ' +
                                   'request. Not the one exposing the API.' },
            permission: { type: 'string',
                          description: 'The whole permission identifier, ' +
                                       'base URI and name together.' }
          },
          required: ['client', 'permission'],
          examples: [{ client: 'webapp1',
                       permission: 'https://example.com/write' }],
          additionalProperties: false
        },
        responseDescription: 'The grant, and what an access token asking for ' +
                             'it will carry.' },

      { action: 'revoke-permission', operationId: 'revokePermission',
        summary: 'Take a permission away from a client application',
        description: 'The opposite of `grant-permission`, and with the ' +
                     'setting off it changes nothing about what is issued ' +
                     'either: the permission still becomes an audience and a ' +
                     'scope, and those requests are simply reported as ' +
                     'UNGRANTED — which is the state ' +
                     '`oauth2.delegatedPermissionsEnforced` turns into a ' +
                     'refusal.\n\nIt is also how a DANGLING grant is ' +
                     'cleared: send the identifier exactly as it appears on ' +
                     'the entry, and it goes whether or not anything defines ' +
                     'it.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            client: { type: 'string',
                      description: 'The application holding it.' },
            permission: { type: 'string',
                          description: 'The whole permission identifier.' }
          },
          required: ['client', 'permission'],
          examples: [{ client: 'webapp1',
                       permission: 'https://example.com/write' }],
          additionalProperties: false
        },
        responseDescription: 'What was revoked.' }
    ] },

  // -------------------------------------------------------------------------
  // CONSENT — the THIRD register in this family and the first whose rows have a
  // PERSON in them.
  //
  // A resource of its own rather than more actions on `/permissions`, for the
  // reason that one is a resource of its own rather than more actions on
  // `/delegation`: a caller that had to tell an act from an intent from a
  // consent by the shape of a row would be told nothing by any of them. The
  // console draws it on a page of its own for the same reason and rule 7's
  // parity check is what keeps the two in step.
  //
  // THE FOUR ACTION NAMES SAY WHICH HALF THEY TOUCH, and the stutter under this
  // path (`/consent/grant-global-consent`) is deliberate exactly as
  // `/permissions/define-permission`'s is. They are the names in the console's
  // hidden `action` inputs, where the page is `/admin/consent` and `grant`
  // alone would not say whether it meant the override or somebody's answer —
  // and those two are the pair a caller most needs kept apart, because removing
  // the wrong one asks the wrong people again.
  // -------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // ROLES. Three operations against `adminViews.rolesView()`,
  // `adminViews.rolesPreview()` and `adminActions.rolesAction()` — the same
  // three functions the console calls, so rule 7's parity is a property of the
  // wiring rather than of two lists agreeing.
  //
  // **THE PREVIEW GETS AN OPERATION OF ITS OWN AND NOT A QUERY ON THE FIRST**,
  // and that is the one decision here worth arguing. On the console it IS a
  // query parameter, because a `<form method="get">` is what a page with no
  // script has; over HTTP the two are different questions — one reads a
  // register and the other asks the PDP — and a caller that got a decision by
  // adding two parameters to a listing would have no way to discover it.
  // ---------------------------------------------------------------------------
  { method: 'GET', path: BASE + '/roles', tag: 'Roles',
    operationId: 'getRoles',
    summary: 'Who holds a role, and what requires one',
    description: 'The role register, both relations.\n\n**A role is a name ' +
                 'somebody may hold, and holding one is what an ISSUANCE is ' +
                 'decided on.** Three kinds of thing can be mapped into one ' +
                 '— a person, a GROUP (so every member of it holds the role, ' +
                 'resolved at decision time) and an APPLICATION, which is ' +
                 'what a `client_credentials` grant is decided on where ' +
                 'there is no person at all.\n\n**`roles` is MEMBERSHIP and ' +
                 '`requiring` is REQUIREMENT, and they are opposite.** ' +
                 'Membership is stored on the ROLE entry under `ou=roles` ' +
                 'and is written through this resource. A requirement is ' +
                 '`appRequiredRole` on an APPLICATION\'s own entry and is ' +
                 'written through `POST /admin-api/applications/add` — one ' +
                 'store, one door that writes it. It is READ here because ' +
                 'this is the only surface that can resolve it: ' +
                 '`requiring[].unknown` names a role an application demands ' +
                 'that NOTHING defines, which refuses everybody, silently ' +
                 'and correctly, and looks exactly like the application ' +
                 'being broken.\n\n**Only NARROWED applications are in ' +
                 '`requiring`.** An application that names no required role ' +
                 'requires `EVERYBODY`, everybody holds `EVERYBODY`, and ' +
                 'nothing is refused — which is how this service behaved ' +
                 'before roles existed and is what makes the feature off by ' +
                 'default without being absent.\n\n**The six `builtIn` roles ' +
                 'are COMPUTED and in no container.** They cannot be ' +
                 'created, edited or deleted, they have no members, and ' +
                 'every one of them is answered from the CONTEXT of the ' +
                 'decision being made. They are never in the roles claim ' +
                 'either: `EVERYBODY` and `ALL_AUTHENTICATED_USERS` are true ' +
                 'of almost every token this service issues, so carrying ' +
                 'them would tell a relying party nothing it did not know ' +
                 'from holding the token.\n\n`gated: false` means the XACML ' +
                 'family is not loaded in this process, so ' +
                 '`common/issuance_gate.js` has no decider and every ' +
                 'issuance is allowed whatever this register says. ' +
                 '`enforced: false` means `roles.enforceIssuance` is off, ' +
                 'which is the same outcome by a different route and is the ' +
                 'way back if a policy edit locks something out.',
    mirrors: 'GET /admin/roles',
    responseDescription: 'The six built-in roles, every configured role with ' +
                         'its three membership lists, every application that ' +
                         'has been narrowed, and whether the decision is ' +
                         'being asked for at all.',
    responseSchema: { type: 'object',
                      description: 'The role register, both relations.' },
    handler: function (req, res) {
      log.debug("Entering the management API roles endpoint.");
      sendJson(res, 200, adminViews.rolesView());
      log.debug("Leaving the management API roles endpoint.");
    } },

  { method: 'GET', path: BASE + '/roles/preview', tag: 'Roles',
    operationId: 'previewRoleIssuance',
    summary: 'Would this be issued?',
    description: 'Asks the embedded PEP whether this service would issue ' +
                 'something, without issuing it and without recording ' +
                 'anything.\n\n**It is the SAME call the nine issuance sites ' +
                 'make** — `common/issuance_gate.check()`, through ' +
                 '`xacml/xacml_role_pep.js`, against the policy ' +
                 '`xacml.issuancePolicy` names — so a preview that agreed ' +
                 'with the enforcement only by coincidence is impossible. ' +
                 'That is the only reason it is worth having.\n\nIt is not ' +
                 '`POST /xacml/pdp`, which asks the same engine a different ' +
                 'question: an arbitrary request against the repository ' +
                 'ROOT, which is the policy about somebody else\'s boundary. ' +
                 'Two questions, two documents.\n\n`available: false` means ' +
                 'the XACML family is not loaded in this process: nothing is ' +
                 'gated and every issuance is allowed.\n\n**`application` ' +
                 'and `subject` are both needed and neither is declared ' +
                 'required**, because this is a READ and a read with no ' +
                 'question in it has nothing to refuse — it answers 200 with ' +
                 '`answered: false` and says what was missing, exactly as a ' +
                 'GET of /admin/roles with no parameters draws the form and ' +
                 'no answer. **Read `answered` first.** There is ' +
                 'deliberately no `decision` member on that reply: the gate ' +
                 'ALLOWS a call that names no application, so an operation ' +
                 'that fell through to it would hand back a Permit meaning ' +
                 '"you did not ask".',
    mirrors: 'GET /admin/roles',
    parameters: [
      { name: 'application', in: 'query',
        schema: { type: 'string' },
        description: 'What something would be issued FOR — a `client_id`, a ' +
                     'wtrealm, a SAML entityID, an SPN. An application no ' +
                     'entry names requires EVERYBODY, because this service ' +
                     'registers one on first sight and refusing the first ' +
                     'request from a new client is precisely the ' +
                     'permissiveness it is for.' },
      { name: 'subject', in: 'query',
        schema: { type: 'string' },
        description: 'Who it would be issued to — a username, or a client_id ' +
                     'where `subjectKind` is `application`.' },
      { name: 'subjectKind', in: 'query',
        schema: { type: 'string', enum: ['user', 'application'] },
        description: 'Whether the subject is a person or a client ' +
                     'authenticating as itself. Defaults to `user`.' },
      { name: 'kind', in: 'query',
        schema: { type: 'string' },
        description: 'Which issuance. It becomes the XACML `action-id`, so a ' +
                     'policy may permit an access token and refuse a refresh ' +
                     'token. `GET /admin-api/roles` lists the nine in ' +
                     '`issuanceKinds`; the default is `issue-access-token`.' }
    ],
    responseDescription: 'The decision, the sentence explaining it, the ' +
                         'roles the subject holds and the roles the ' +
                         'application requires.',
    responseSchema: { type: 'object',
                      description: 'One issuance decision, made and thrown ' +
                                   'away.' },
    handler: function (req, res) {
      log.debug("Entering the management API role preview endpoint.");
      const answer = adminViews.rolesPreview(req.query);
      if (!answer) {
        // NOTHING ASKED IS `answered: false` AND NOT A 400, and that is this
        // operation MIRRORING ITS PAGE rather than being lenient. A GET of
        // /admin/roles with no parameters draws the form and no answer, so
        // this answers the same thing: it is a READ, and a read of this
        // resource with no question in it has nothing to refuse.
        //
        // The hazard the other spelling was guarding against is gone by
        // construction. `issuance_gate.check()` ALLOWS a call that names no
        // application, so an operation that fell through to the gate would
        // hand back a Permit meaning "you did not ask" — which is why there
        // is no `decision` member on this reply at all, and why `answered` is
        // the first thing to read.
        sendJson(res, 200, {
          answered: false, available: !!adminViews.rolesView().gated,
          why: '`application` and `subject` are both needed. A decision ' +
               'needs something being issued FOR and somebody it is being ' +
               'issued TO, and an issuance named with neither is allowed by ' +
               'definition rather than by policy — so nothing was asked and ' +
               'there is no decision here to read.' });
        log.debug("Leaving the management API role preview endpoint. Nothing " +
                  "asked.");
        return;
      }
      sendJson(res, 200, Object.assign({ answered: true }, answer));
      log.debug("Leaving the management API role preview endpoint.");
    } },

  { method: 'POST', route: BASE + '/roles/:action', tag: 'Roles',
    mirrors: 'POST /admin/roles',
    handler: function (req, res) {
      log.debug("Entering the management API roles action endpoint.");
      const body = parseBody(req);
      const result = adminActions.rolesAction(withAction(req, body),
                                              { via: 'api' });
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0059');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API roles action endpoint.");
    },
    actions: [
      { action: 'create-role', operationId: 'createRole',
        summary: 'Make a role',
        description: 'Writes one entry under `ou=roles` with no members. ' +
                     'Adding members is `add-member`; the two are separate ' +
                     'because a role is worth creating before anybody holds ' +
                     'it — an application can be narrowed to it first, and ' +
                     'the register will then say so.\n\nThe name becomes an ' +
                     'LDAP RDN and a value in a token claim, so it is up to ' +
                     '64 characters of letters, digits, and `. _ : @ -` or a ' +
                     'space. **It may not be one of the six built-in ' +
                     'roles**: those are computed and answered first, so a ' +
                     'stored role of the same name could never be reached.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            role: { type: 'string', description: 'The role\'s name.' },
            description: { type: 'string',
                           description: 'What it is for, for the next person.' }
          },
          required: ['role'],
          examples: [{ role: 'staff', description: 'People who work here' }],
          additionalProperties: false
        },
        responseDescription: 'The role that was made.' },

      { action: 'delete-role', operationId: 'deleteRole',
        summary: 'Remove a role',
        description: 'Deletes the entry. **Applications that still REQUIRE ' +
                     'it are named in the reply and the delete still ' +
                     'happens**, which is deliberate: refusing would mean a ' +
                     'role could not be removed until every application ' +
                     'naming it had been edited, and those entries are ' +
                     'usually the thing somebody is in the middle of ' +
                     'changing. Each of them now requires a role NOBODY ' +
                     'holds and is therefore issued nothing at all — so the ' +
                     'consequence is said at the moment it is created rather ' +
                     'than discovered later as a service that stopped ' +
                     'working.\n\nNothing already ISSUED is touched. A token ' +
                     'minted while somebody held the role is still valid and ' +
                     'still carries it in the roles claim.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            role: { type: 'string', description: 'The role to remove.' }
          },
          required: ['role'],
          examples: [{ role: 'staff' }],
          additionalProperties: false
        },
        responseDescription: 'What was removed, and which applications now ' +
                             'require something nobody can hold.' },

      { action: 'describe-role', operationId: 'describeRole',
        summary: 'Change what a role says it is for',
        description: 'Replaces the `description` and leaves the membership ' +
                     'exactly as it was. It is an action of its own rather ' +
                     'than a field on `create-role` because creating an ' +
                     'existing role is refused: roles are edited in place.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            role: { type: 'string', description: 'The role.' },
            description: { type: 'string',
                           description: 'The new description. An empty ' +
                                        'string clears it.' }
          },
          required: ['role'],
          examples: [{ role: 'staff',
                       description: 'Anybody with a desk in the building' }],
          additionalProperties: false
        },
        responseDescription: 'The role that was changed.' },

      { action: 'add-member', operationId: 'addRoleMember',
        summary: 'Give somebody a role',
        description: 'Adds one value to the role entry. **Which of the three ' +
                     'lists it goes in is `kind`, and the three are looked ' +
                     'up in three different places**, so naming the wrong ' +
                     'one succeeds and writes something that will never ' +
                     'match:\n\n* `user` — a username. The person need not ' +
                     'exist: this service creates a directory entry for any ' +
                     'name on first sight, so a role can be granted before ' +
                     'its holder has ever signed in.\n* `group` — a group in ' +
                     '`ou=groups`. Every member holds the role, **resolved ' +
                     'at DECISION TIME** rather than expanded on write, so ' +
                     'an `ldapmodify` adding somebody to the group changes ' +
                     'the very next token.\n* `application` — an application ' +
                     'that holds the role AS ITSELF, which is what a ' +
                     '`client_credentials` grant is decided on.\n\nIt is NOT ' +
                     'the same relation as `appRequiredRole` on an ' +
                     'application entry, which is what that application ' +
                     'DEMANDS of others. An application appears in both and ' +
                     'means opposite things in each.\n\nA BUILT-IN role is ' +
                     'refused by name: those six are computed and have no ' +
                     'membership to edit.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            role: { type: 'string', description: 'The role being given.' },
            kind: { type: 'string', enum: ['user', 'group', 'application'],
                    description: 'Which of the three lists the member goes ' +
                                 'in.' },
            member: { type: 'string',
                      description: 'The person, group or application. Named ' +
                                   '`member` rather than `name` on purpose: ' +
                                   '`role` is the role\'s own name, and a ' +
                                   'body that confused the two would succeed ' +
                                   'and create something plausible.' }
          },
          required: ['role', 'kind', 'member'],
          examples: [{ role: 'staff', kind: 'user', member: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'Who now holds what.' },

      { action: 'remove-member', operationId: 'removeRoleMember',
        summary: 'Take a role away',
        description: 'Removes one value from the role entry. Matched ' +
                     'case-insensitively, for the reason the register gives: ' +
                     'a username here arrives from a login form, a SAML ' +
                     'subject, a Kerberos principal and a `client_id`, and ' +
                     'this service has always treated those as one identity ' +
                     'however they were typed.\n\n**Nothing already ISSUED ' +
                     'is touched**, exactly as revoking a delegated ' +
                     'permission does not re-judge a grant already made. The ' +
                     'next issuance is decided without the role; a token ' +
                     'minted a minute ago still carries it.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            role: { type: 'string', description: 'The role being taken away.' },
            kind: { type: 'string', enum: ['user', 'group', 'application'],
                    description: 'Which list to remove it from.' },
            member: { type: 'string',
                      description: 'The person, group or application.' }
          },
          required: ['role', 'kind', 'member'],
          examples: [{ role: 'staff', kind: 'user', member: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'Who no longer holds what.' }
    ] },

  // ---------------------------------------------------------------------------
  // POLICIES (2026-09-12). Two operations over
  // `adminViews.passwordPoliciesView()` and
  // `adminActions.passwordPoliciesAction()` — the same two functions
  // /admin/policies calls, so the page and this resource cannot disagree.
  //
  // **THE SAVE'S REQUEST SCHEMA IS BUILT FROM `password_policy.FIELDS`**, so a
  // rule added there is a property here the same day. Each field takes its JSON
  // type OR a string, because a form-encoded body copied from the console
  // carries `"12"` and `"TRUE"`, and `coerceTypes` is off in this file's ajv
  // for a reason stated beside it; the module parses both spellings and refuses
  // anything else by name.
  // ---------------------------------------------------------------------------
  { method: 'GET', path: BASE + '/policies', tag: 'Policies',
    operationId: 'getPolicies',
    summary: 'The policies this realm holds a credential to',
    description: 'Every kind of policy and its profiles — today the PASSWORD ' +
                 'POLICY and its one profile, ' +
                 '`default`.\n\n**`password.profile` is the profile IN ' +
                 'FORCE**, which is the stored ' +
                 '`cn=default,ou=passwordPolicies` entry where there is one ' +
                 '(`stored: true`) and the built-in defaults where there is ' +
                 'not. `sources` says which of the two each value came from, ' +
                 'and `problems` names any stored value that could not be ' +
                 'read — the built-in default is in force for that ' +
                 'field.\n\n**`enforced` is whether this realm checks it**, ' +
                 'which is product mode: development checks no password at ' +
                 'any door, so the rules are recorded and not applied there. ' +
                 'A GENERATED password meets the profile in both ' +
                 'modes.\n\n`password.rules` is the profile as a person ' +
                 'reads it — the same sentences the user portal prints — and ' +
                 '`password.doors` names every door that sets a password and ' +
                 'the one function each ends in.\n\nIt is NOT the XACML ' +
                 'policy repository, which is `GET /admin-api/xacml/policies`.',
    mirrors: 'GET /admin/policies',
    parameters: pagingParameters(),
    responseDescription: 'The kinds of policy, the password profile in force ' +
                         'with its field table and schema, where it is ' +
                         'enforced, the generator, and the paged profiles.',
    responseSchema: { type: 'object',
                      description: 'The policies register.' },
    handler: function (req, res) {
      log.debug("Entering the management API policies endpoint.");
      sendJson(res, 200, adminViews.passwordPoliciesView(req.query));
      log.debug("Leaving the management API policies endpoint.");
    } },

  { method: 'POST', route: BASE + '/policies/:action', tag: 'Policies',
    mirrors: 'POST /admin/policies',
    handler: function (req, res) {
      log.debug("Entering the management API policies action endpoint.");
      const body = parseBody(req);
      const result = adminActions.passwordPoliciesAction(withAction(req, body),
                                                         { via: 'api' });
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0060');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API policies action endpoint.");
    },
    actions: [
      { action: 'save-password-policy', operationId: 'savePasswordPolicy',
        summary: 'Set the password policy profile',
        description: 'Writes `cn=default,ou=passwordPolicies` in this ' +
                     'realm\'s directory, REPLACING what is there. **Every ' +
                     'field is required** and one left out is refused by ' +
                     'name rather than reset to a default, because a save ' +
                     'that quietly loosened a rule nobody mentioned is the ' +
                     'mistake nobody sees.\n\nTwo rules relate fields: ' +
                     '`generatedLength` must be at least `minLength`, and at ' +
                     'least twice `minSymbols` plus two. **A change applies ' +
                     'to the NEXT password set in this realm and to nothing ' +
                     'already stored**, which is a hash and cannot be ' +
                     're-checked.\n\nThe only profile is `default`: nothing ' +
                     'assigns a profile to a person yet, so another name is ' +
                     'refused rather than stored.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: (function () {
            const out = {
              profile: { type: 'string', enum: [passwordPolicy.DEFAULT_PROFILE],
                         description: 'Which profile. Only `default` exists.' },
              description: { type: 'string',
                             description: 'What the profile is for, for the ' +
                                          'next person. Optional.' }
            };
            passwordPolicy.FIELDS.forEach(function (field) {
              out[field.key] = field.type === 'bool'
                ? { oneOf: [{ type: 'boolean' }, { type: 'string' }],
                    description: field.what + ' (`true`/`false`, or `TRUE`/' +
                                 '`FALSE` from a form.) Default ' +
                                 field.dflt + '.' }
                : { oneOf: [{ type: 'integer', minimum: field.min,
                              maximum: field.max },
                            { type: 'string' }],
                    description: field.what + ' Between ' + field.min +
                                 ' and ' +
                                 field.max + '. Default ' + field.dflt + '.' };
            });
            return out;
          })(),
          required: passwordPolicy.FIELDS.map(function (field) {
            return field.key;
          }),
          examples: [Object.assign({ profile: passwordPolicy.DEFAULT_PROFILE },
                                   passwordPolicy.DEFAULTS, { minLength: 14 })],
          additionalProperties: false
        },
        responseDescription: 'The profile now in force, the rules as a ' +
                             'person reads them, and whether this realm ' +
                             'enforces them.' },

      { action: 'reset-password-policy', operationId: 'resetPasswordPolicy',
        summary: 'Put the built-in password policy back',
        description: 'Deletes the stored profile, after which the built-in ' +
                     'defaults are in force. `removed: false` means nothing ' +
                     'was stored, so the defaults already were. Nothing ' +
                     'already stored is touched, as with a save.',
        requestBody: {
          type: 'object',
          properties: {
            profile: { type: 'string', enum: [passwordPolicy.DEFAULT_PROFILE],
                       description: 'Which profile. Only `default` exists.' }
          },
          examples: [{ profile: passwordPolicy.DEFAULT_PROFILE }],
          additionalProperties: false
        },
        responseDescription: 'Whether anything was removed, and the profile ' +
                             'now in force.' }
    ] },

  { method: 'GET', path: BASE + '/consent', tag: 'Delegation',
    operationId: 'getConsent',
    summary: 'What people agreed applications may ask for on their behalf',
    description: 'Both halves of the consent register.\n\n**How it works.** ' +
                 'With `oauth2.consentRequired` on — it is ON by default, ' +
                 'and it is the one policy in this service that is — the ' +
                 'authorization endpoint draws `/oauth2/consent` the first ' +
                 'time a given username signs in to a given `client_id` for ' +
                 'a given scope, and issues nothing until they answer. Allow ' +
                 'writes one `oauthConsent` value per scope onto that ' +
                 'person\'s own entry under `ou=users`; Deny returns ' +
                 '`access_denied` to the client and records ' +
                 'nothing.\n\n**`globals` is CONFIGURATION and `users` is a ' +
                 'RECORD**, and the difference decides what removing a row ' +
                 'does. A global consent is `oauthGlobalConsent` on an ' +
                 'APPLICATION\'s entry, one value per scope: everybody who ' +
                 'signs in to that application skips the prompt for it and ' +
                 'nothing is written about anybody — so revoking it asks ' +
                 'EVERYBODY again, including the people who would have said ' +
                 'yes. A recorded consent is one person\'s answer, and ' +
                 'revoking it asks that one person.\n\n**A delegated ' +
                 'permission is recorded by its WHOLE identifier** — ' +
                 '`https://example.com/write`, never the bare `write` — ' +
                 'because two resources may both expose a permission of that ' +
                 'name and a consent to one must not cover the other. ' +
                 '`globals[].resource` says which application exposes it ' +
                 'where the scope resolves to one, and `globals[].granted` ' +
                 'whether that client has also been GRANTED it: the two are ' +
                 'independent, and a consented permission the client does ' +
                 'not hold is still refused when ' +
                 '`oauth2.delegatedPermissionsEnforced` is ' +
                 'on.\n\n`users[].unreadable` is a value on somebody\'s ' +
                 'entry that is not in the shape this service writes — an ' +
                 '`ldapmodify` put it there. It consents nothing and is ' +
                 'reported rather than dropped.\n\n`storable: false` means ' +
                 'no directory is installed behind the register, so an ' +
                 'answer is honoured for one request and forgotten and the ' +
                 'screen is drawn every time. That is deliberate: an ' +
                 'agreement that cannot be remembered is one nobody gave.',
    mirrors: 'GET /admin/consent',
    responseDescription: 'Every scope consented for everybody on an ' +
                         'application, every answer a person has given, and ' +
                         'whether the screen is being drawn at all.',
    responseSchema: { type: 'object',
                      description: 'The consent register, both halves.' },
    handler: function (req, res) {
      log.debug("Entering the management API consent endpoint.");
      sendJson(res, 200, adminViews.consentView());
      log.debug("Leaving the management API consent endpoint.");
    } },

  { method: 'POST', route: BASE + '/consent/:action', tag: 'Delegation',
    mirrors: 'POST /admin/consent',
    handler: function (req, res) {
      log.debug("Entering the management API consent action endpoint.");
      const body = parseBody(req);
      const result = adminActions.consentAction(withAction(req, body));
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0061');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API consent action endpoint.");
    },
    actions: [
      { action: 'grant-global-consent', operationId: 'grantGlobalConsent',
        summary: 'Consent a scope for everybody who signs in to an application',
        description: 'Adds one value to `oauthGlobalConsent` on the ' +
                     'application\'s own entry. Nobody is asked about that ' +
                     'scope on that application again, and **nothing is ' +
                     'written about anybody** — this is an OVERRIDE and not ' +
                     'a record.\n\nThat is the whole difference from a ' +
                     'person pressing Allow, and it decides what removing it ' +
                     'does: `revoke-global-consent` asks everybody again, ' +
                     'because there is no record of who would have agreed. ' +
                     'Somebody who consented the same scope personally — ' +
                     'before or after — still has that on their entry and is ' +
                     'still not asked.\n\n**It is keyed on the pair, not on ' +
                     'the scope.** Consenting `read` here consents it for ' +
                     'THIS application; an application registered five ' +
                     'minutes later that spells the same word is still ' +
                     'asked. There is no service-wide list of scopes nobody ' +
                     'is ever asked about, deliberately: it would mean an ' +
                     'application nobody has reviewed inheriting a decision ' +
                     'made about a different one.\n\nThe scope must be a ' +
                     'legal RFC 6749 section 3.3 scope token, because a ' +
                     'value with a space in it is two scopes and could never ' +
                     'match one. It need NOT name a permission any ' +
                     'application defines — most scopes are not permissions, ' +
                     'and refusing an unrecognised one would make it ' +
                     'impossible to consent `openid`.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            client: { type: 'string',
                      description: 'The application people sign in to, by ' +
                                   'its identifier exactly as ' +
                                   '`ou=applications` holds it. This is the ' +
                                   'CLIENT — the party that will name the ' +
                                   'scope in a request — and not the ' +
                                   'resource that exposes it.' },
            scope: { type: 'string',
                     description: 'The scope, exactly as a client puts it in ' +
                                  'a `scope` parameter. A delegated ' +
                                  'permission is its WHOLE identifier.' }
          },
          required: ['client', 'scope'],
          examples: [{ client: 'webapp1', scope: 'openid' }],
          additionalProperties: false
        },
        responseDescription: 'The application as it now stands, and what ' +
                             'skipping the prompt for that scope now means.' },

      { action: 'revoke-global-consent', operationId: 'revokeGlobalConsent',
        summary: 'Stop consenting a scope for everybody',
        description: 'Removes one value from `oauthGlobalConsent`. **The ' +
                     'next person to sign in asking for that scope is ' +
                     'PROMPTED**, including everybody the override was ' +
                     'covering, because an override records nothing about ' +
                     'the people it covers. Somebody who agreed to it ' +
                     'personally is unaffected — their answer is on their ' +
                     'own entry and `revoke-consent` is what takes that ' +
                     'away.\n\nNothing already ISSUED is touched. An access ' +
                     'token minted while the override stood is still valid, ' +
                     'exactly as revoking a delegated permission does not ' +
                     're-judge a grant already made.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            client: { type: 'string',
                      description: 'The application holding it.' },
            scope: { type: 'string', description: 'The scope to stop ' +
                                                  'consenting.' }
          },
          required: ['client', 'scope'],
          examples: [{ client: 'webapp1', scope: 'openid' }],
          additionalProperties: false
        },
        responseDescription: 'What was removed, and who is asked again.' },

      { action: 'revoke-consent', operationId: 'revokeConsent',
        summary: 'Take back one answer one person gave',
        description: 'Removes the `oauthConsent` value naming this person, ' +
                     'this application and this scope. They are asked again ' +
                     'the next time that application requests that scope; ' +
                     'nobody else is affected.\n\n**All three are required ' +
                     'and that is not pedantry.** One person may consent the ' +
                     'same scope to several applications, and revoking the ' +
                     'wrong pair is invisible until somebody is asked again ' +
                     '— which is a week later and looks like a bug in the ' +
                     'screen.\n\nA scope covered by GLOBAL consent is not on ' +
                     'anybody\'s entry, so there is nothing here to remove ' +
                     'and this refuses rather than pretending: ' +
                     '`revoke-global-consent` is the operation for that, and ' +
                     'the refusal says so. Nothing already issued is touched.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            username: { type: 'string',
                        description: 'The person, exactly as /admin/users ' +
                                     'names them. It is normalised the same ' +
                                     'way every identity here is, so `alice` ' +
                                     'and her urn:uuid: subject are one ' +
                                     'person.' },
            client: { type: 'string',
                      description: 'The application they consented it to.' },
            scope: { type: 'string', description: 'The scope they consented.' }
          },
          required: ['username', 'client', 'scope'],
          examples: [{ username: 'alice', client: 'webapp1', scope: 'openid' }],
          additionalProperties: false
        },
        responseDescription: 'What was removed, and what is asked again.' },

      { action: 'forget-user-consent', operationId: 'forgetUserConsent',
        summary: 'Forget everything one person agreed to',
        description: 'Every `oauthConsent` value on one person\'s entry, in ' +
                     'one call, so that every application asks them again. A ' +
                     'separate operation rather than a loop over ' +
                     '`revoke-consent` because being asked again is the one ' +
                     'thing somebody wants after testing this screen, and ' +
                     'doing it a row at a time for a person with thirty ' +
                     'consents is a chore rather than a control.\n\nIt ' +
                     'reaches nothing under GLOBAL consent, because there is ' +
                     'nothing on their entry to reach — a scope they were ' +
                     'never asked about leaves no record, which is what lets ' +
                     'the register tell the two apart at all. Nothing ' +
                     'already issued is touched.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            username: { type: 'string',
                        description: 'The person whose answers are forgotten.' }
          },
          required: ['username'],
          examples: [{ username: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'How many answers were forgotten.' }
    ] },

  // -------------------------------------------------------------------------
  // SPIFFE. Three resources, mirroring the three console pages one for one, and
  // each POST calls the SAME action function the console's form posts to — with
  // `action` taken from the URL instead of from a hidden input. Rule 7.
  //
  // There is a fourth SPIFFE surface that is deliberately NOT here: the SPIRE
  // Server API itself. It is gRPC, it already does all of this, and wrapping it
  // in JSON would be a second implementation of forty-two methods that could
  // then disagree with the first. What this API covers is the CONSOLE — the
  // trust domain, its authorities, its federated bundles, the registration
  // entries and the agents — which is the parity rule's actual subject.
  // -------------------------------------------------------------------------
  { method: 'GET', path: BASE + '/spiffe', tag: 'SPIFFE',
    operationId: 'getSpiffe',
    summary: 'The trust domain: its authorities, its bundle, its listeners',
    description: 'What this service is as a SPIFFE issuing authority. The ' +
                 'X.509 and JWT authorities (the ACTIVE one first, with the ' +
                 'retired ones that are still published behind it), the ' +
                 'bundle path and its sequence, every federated trust ' +
                 'domain, and whether each of the four gRPC listeners ' +
                 'actually bound — which nothing else can tell you, because ' +
                 'neither this API nor GET /admin/sts-metadata can see a ' +
                 'socket.\n\nThe reply also carries `authentication`: ' +
                 'whether the SPIRE Server API is enforcing mutual TLS, ' +
                 'which identities are administrators, and the whole ' +
                 'per-method authorization table, which is SPIRE\'s own ' +
                 '`policy_data.json` row for row.\n\n**Nothing here attests ' +
                 'a workload or a node.** A Workload API caller is ' +
                 'identified only by the transport it arrived on, the ' +
                 'endpoint it reached and its peer address — node cannot ' +
                 'read a Unix socket\'s peer credentials — and an agent\'s ' +
                 'attestation payload is taken on trust. Where the SPIRE ' +
                 'Server API authenticates nobody, any caller that reaches ' +
                 'its port can create a registration entry granting any ' +
                 'identity here. GET /spiffe carries the full list of what ' +
                 'is and is not checked.\n\nNo private key is in this reply. ' +
                 'The authority CERTIFICATE is published, as GET ' +
                 '/tls/server-certificate publishes that one.',
    mirrors: 'GET /admin/spiffe',
    responseDescription: 'The trust domain, its authorities, its federated ' +
                         'bundles and its listeners.',
    responseSchema: { type: 'object',
                      description: 'The SPIFFE trust domain as this service ' +
                                   'holds it.' },
    handler: function (req, res) {
      log.debug("Entering the management API SPIFFE endpoint.");
      // NO `.json` HERE, where its two siblings need one: `spiffeJson()`
      // returns the answer itself, and `spiffeEntriesJson()` and
      // `spiffeAgentsJson()` return `{ json, paging }` because their pages
      // need the paging beside it. The console hid that difference behind
      // one export shape; repointing all three the same way sent this
      // resource `undefined`, which reaches a caller as a string.
      sendJson(res, 200, adminViews.spiffeJson(req));
      log.debug("Leaving the management API SPIFFE endpoint.");
    } },

  { method: 'POST', route: BASE + '/spiffe/:action', tag: 'SPIFFE',
    mirrors: 'POST /admin/spiffe',
    handler: function (req, res) {
      log.debug("Entering the management API SPIFFE action endpoint.");
      const body = parseBody(req);
      // The one action handler in this API that is ASYNCHRONOUS: rotating an
      // authority generates a key pair, and key generation is async. Every
      // other handler here is synchronous, so the await is local rather than a
      // change to the shape of all of them.
      adminActions.spiffeAction(withAction(req, body)).then(function (result) {
        if (!result.ok) {
          errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0062');
        }
        sendJson(res, result.ok ? 200 : 400, result);
        log.debug("Leaving the management API SPIFFE action endpoint.");
      }).catch(function (err) {
        errorCodes.mark(res, 'STS-API-0022');
        log.error('The SPIFFE management API action threw: ' + err.message);
        sendJson(res, 500, { ok: false, errors: [err.message] });
        log.debug("Leaving the management API SPIFFE action endpoint. It " +
                  "threw.");
      });
      log.debug("Leaving handler().");
    },
    actions: [
      { action: 'rotate', operationId: 'rotateSpiffeAuthority',
        summary: 'Rotate the X.509 authority, the JWT authority, or both',
        description: 'A new authority is PREPENDED — everything is signed ' +
                     'with it from that moment — and the old one stays in ' +
                     'the published bundle, so SVIDs already in the field go ' +
                     'on verifying. That is what a bundle is FOR, and ' +
                     'dropping the old one is the difference between a ' +
                     'rotation and an outage.\n\nThe bundle ' +
                     '`spiffe_sequence` changes, which is how a consumer ' +
                     'that polls the bundle endpoint knows to refetch. At ' +
                     'most four authorities are retained; past that the ' +
                     'oldest is dropped and anything it signed stops ' +
                     'verifying at that moment.\n\nThis is also the ONLY way ' +
                     'to add an authority to this trust domain. The SPIRE ' +
                     'Server API\'s AppendBundle and PublishJWTAuthority are ' +
                     'refused, because they would publish a signing key ' +
                     'nothing here holds.',
        requestBodyRequired: false,
        requestBody: {
          type: 'object',
          properties: {
            which: { type: 'string', enum: ['x509', 'jwt', 'both'],
                     description: 'Which authority. Defaults to x509.' }
          },
          examples: [{ which: 'both' }],
          additionalProperties: false
        },
        responseDescription: 'What was rotated, and the new bundle sequence.' },

      { action: 'federation-set', operationId: 'setSpiffeFederatedBundle',
        summary: 'Add or replace a foreign trust domain\'s bundle',
        description: '**The bundle is PUSHED here and never PULLED by this ' +
                     'service.** The SPIFFE federation specification puts a ' +
                     'bundle endpoint URL in the relationship and a real ' +
                     'implementation polls it; this one records the URL and ' +
                     'refuses to follow it — the SPIRE Server API\'s ' +
                     'RefreshBundle says so in terms — because fetching a ' +
                     'URL somebody registered, in order to obtain a key that ' +
                     'will then verify credentials, is a server-side request ' +
                     'forgery with a citation attached. The same refusal ' +
                     'this service gives WS-Federation\'s `wreqptr` and a ' +
                     'client\'s `jwks_uri`.\n\n**A trust domain this service ' +
                     'itself serves is REFUSED** — any realm\'s, whether or ' +
                     'not SPIFFE is on in it (2026-09-12). The bundles are ' +
                     'held per realm, and a federated entry naming a served ' +
                     'domain would let an authority somebody registered in ' +
                     'one realm authenticate workloads as another ' +
                     'realm\'s.\n\nThe document is CHECKED, which is unusual ' +
                     'for this service: every JWK needs a `use` of ' +
                     '`x509-svid`, `jwt-svid` or `wit-svid`, because a ' +
                     'consumer MUST IGNORE one without it — so a bundle of ' +
                     'keys missing that member is stored happily and then ' +
                     'verifies nothing, with no error anywhere pointing back ' +
                     'here.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            trustDomain: { type: 'string',
                           description: 'The trust domain NAME — ' +
                                        '`other.example`, not ' +
                                        '`spiffe://other.example`. This ' +
                                        'service\'s own is refused: a trust ' +
                                        'domain does not federate with ' +
                                        'itself, and accepting it would give ' +
                                        'it two bundles that could disagree.' },
            document: { type: 'object',
                        description: 'The bundle, as a JWK Set with ' +
                                     '`spiffe_sequence` and ' +
                                     '`spiffe_refresh_hint`. A JSON string ' +
                                     'is accepted too, which is what the ' +
                                     'console\'s textarea sends.' },
            bundleEndpointUrl: { type: 'string',
                                 description: 'Recorded and never fetched. ' +
                                              'It is reported back so an ' +
                                              'operator can see what the ' +
                                              'relationship says.' },
            bundleEndpointProfile: { type: 'string',
                                     enum: ['https_web', 'https_spiffe'],
                                     description: 'Which profile the partner ' +
                                                  'expects. Recorded.' },
            endpointSpiffeId: { type: 'string',
                                description: 'For `https_spiffe`, the SPIFFE ' +
                                             'ID the partner\'s endpoint ' +
                                             'presents. Recorded.' }
          },
          required: ['trustDomain', 'document'],
          examples: [{ trustDomain: 'other.example',
                       bundleEndpointUrl: 'https://other.example/bundle',
                       bundleEndpointProfile: 'https_web',
                       document: { keys: [], spiffe_sequence: 1,
                                   spiffe_refresh_hint: 300 } }],
          additionalProperties: false
        },
        responseDescription: 'Whether it was added or replaced.' },

      { action: 'federation-remove', operationId: 'removeSpiffeFederatedBundle',
        summary: 'Forget a foreign trust domain\'s bundle',
        description: 'Any registration entry that federates with it keeps ' +
                     'the name and simply contributes no bundle to its ' +
                     'workloads, which is the same state as a relationship ' +
                     'configured before its bundle has arrived. The entries ' +
                     'are left alone deliberately; the SPIRE Server API\'s ' +
                     'BatchDeleteFederatedBundle is where the three modes ' +
                     'RESTRICT, DELETE and DISSOCIATE live.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            trustDomain: { type: 'string',
                           description: 'The trust domain name.' }
          },
          required: ['trustDomain'],
          examples: [{ trustDomain: 'other.example' }],
          additionalProperties: false
        },
        responseDescription: 'That it is gone.' }
    ] },

  { method: 'GET', path: BASE + '/spiffe/entries', tag: 'SPIFFE',
    operationId: 'getSpiffeEntries',
    summary: 'The registration entries, filtered and paged',
    description: 'A registration entry says which SPIFFE ID a workload gets, ' +
                 'under which parent, matching which selectors. It is the ' +
                 'most important object in a SPIFFE deployment: the Workload ' +
                 'API answers out of it.\n\n**The entries ARE the ' +
                 'registry.** They live under `ou=entries,ou=spiffe` in the ' +
                 'embedded LDAP directory and nothing caches them, so an ' +
                 '`ldapmodify` is visible here on the next call and changes ' +
                 'what the next SVID looks like.\n\n**The selectors restrict ' +
                 'nothing here.** They are recorded, reported, and used by ' +
                 'the SPIRE Server API\'s GetAuthorizedEntries — and the ' +
                 'Workload API hands every caller every identity, because ' +
                 'nothing in this service attests a workload.',
    mirrors: 'GET /admin/spiffe/entries',
    parameters: [
      { name: 'entry', in: 'query', required: false, schema: { type: 'string' },
        description: 'One entry, by its id — the 32 hex characters this ' +
                     'registry minted, which is what the SPIRE Server API ' +
                     'calls `id`. The reply then carries that entry with ' +
                     'every attribute of its directory entry.' },
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the SPIFFE ID, the parent, the entry id, ' +
                     'the hint or any selector, case-insensitive.' },
      { name: 'origin', in: 'query', required: false,
        schema: { type: 'string',
                  enum: ['seed', 'console', 'api', 'grpc', 'auto', 'ldap'] },
        description: 'How the entry got here. `auto` is one this service ' +
                     'INVENTED for a workload that matched nothing, which is ' +
                     'the setting `spiffe.autoCreateEntries` — telling those ' +
                     'from entries somebody meant is the whole reason this ' +
                     'field exists.' }
    ].concat(pagingParameters()),
    responseDescription: 'The matching registration entries with the paging ' +
                         'that found them, or one entry with its directory ' +
                         'entry when `entry` was given.',
    responseSchema: { type: 'object',
                      description: 'Registration entries and their paging.' },
    handler: function (req, res) {
      log.debug("Entering the management API SPIFFE entries endpoint.");
      sendJson(res, 200, adminViews.spiffeEntriesJson(req).json);
      log.debug("Leaving the management API SPIFFE entries endpoint.");
    } },

  { method: 'POST', route: BASE + '/spiffe/entries/:action', tag: 'SPIFFE',
    mirrors: 'POST /admin/spiffe/entries',
    handler: function (req, res) {
      log.debug("Entering the management API SPIFFE entries action endpoint.");
      const body = parseBody(req);
      const result = adminActions.spiffeEntriesAction(withAction(req, body));
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0063');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API SPIFFE entries action endpoint.");
    },
    actions: [
      { action: 'create', operationId: 'createSpiffeEntry',
        summary: 'Register an identity',
        description: 'Three refusals and no others: a SPIFFE ID that is not ' +
                     'one, a SPIFFE ID in ANOTHER trust domain (this service ' +
                     'is the issuing authority for exactly one, and cannot ' +
                     'sign for somebody else\'s — that is what federation is ' +
                     'for), and a SPIFFE ID under the reserved `/spire` ' +
                     'path, which belongs to this server and the agents it ' +
                     'attests.\n\nA DUPLICATE SPIFFE ID IS ALLOWED. Two ' +
                     'entries granting one identity under different parents ' +
                     'is a real configuration and SPIRE permits it.\n\nThis ' +
                     'is the same function `BatchCreateEntry` on the SPIRE ' +
                     'Server API calls, writing the same directory entry an ' +
                     '`ldapadd` would.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            spiffeId: { type: 'string',
                        description: 'The identity this entry grants.' },
            parentId: { type: 'string',
                        description: 'The agent or server it hangs beneath. ' +
                                     'Defaults to this server\'s own SPIFFE ' +
                                     'ID, which is what SPIRE uses for an ' +
                                     'entry describing a workload rather ' +
                                     'than a node.' },
            selectors: { type: 'string',
                         description: 'Comma-separated `type:value` pairs, ' +
                                      'split on the FIRST colon only — so ' +
                                      '`docker:label:app:web` is type ' +
                                      '`docker` and value `label:app:web`. ' +
                                      'An entry with NO selectors matches ' +
                                      'every workload, which is how a ' +
                                      'catch-all is written and is also the ' +
                                      'shape of one somebody forgot to ' +
                                      'finish.' },
            dnsNames: { type: 'string',
                        description: 'Comma-separated DNS subjectAltNames, ' +
                                     'added beside the SPIFFE ID. What makes ' +
                                     'an SVID usable by TLS software that ' +
                                     'checks a hostname and cannot read a ' +
                                     'SPIFFE ID.' },
            federatesWith: { type: 'string',
                             description: 'Comma-separated trust domain ' +
                                          'names whose bundles are handed to ' +
                                          'a holder of this identity. A name ' +
                                          'with no bundle here contributes ' +
                                          'nothing rather than failing.' },
            x509SvidTtl: { type: 'integer',
                           description: 'Seconds. 0 means spiffe.svidTtl.' },
            jwtSvidTtl: { type: 'integer',
                          description: 'Seconds. 0 means spiffe.jwtSvidTtl.' },
            hint: { type: 'string',
                    description: 'Operator guidance when a workload gets ' +
                                 'more than one SVID — `internal`, ' +
                                 '`external`. Passed through verbatim; ' +
                                 'nothing here reads it.' }
          },
          required: ['spiffeId'],
          examples: [{ spiffeId: 'spiffe://example.org/ns/prod/sa/api',
                       selectors: 'k8s:ns:prod, k8s:sa:api',
                       dnsNames: 'api.prod.svc', hint: 'external',
                       x509SvidTtl: 900 }],
          additionalProperties: false
        },
        responseDescription: 'The entry as it now stands, with its new id.' },

      { action: 'update', operationId: 'updateSpiffeEntry',
        summary: 'Change one field of an entry',
        description: '**What may be changed is DECLARED and not DERIVED.** ' +
                     'The declared half is what the entry may DO — the ' +
                     'SPIFFE ID, the parent, the selectors, the DNS names, ' +
                     'the lifetimes, the hint, the flags — and it is what ' +
                     'the Workload API reads. The derived half is what ' +
                     'HAPPENED: the revision number, the SVID counter, when ' +
                     'it was created. Those are refused with a list of what ' +
                     'is not, because a call that could rewrite them would ' +
                     'make this registry lie about the service\'s own ' +
                     'behaviour in a way indistinguishable from the ' +
                     'recording being broken.\n\n`ldapmodify` still reaches ' +
                     'everything, which is deliberate: refusing it HERE is ' +
                     'the difference between offering an operation and ' +
                     'merely not preventing it.\n\nThe change applies to the ' +
                     'NEXT SVID issued from this entry. Nothing already ' +
                     'issued changes, and there is nothing to invalidate — ' +
                     'SPIFFE has no revocation.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            entry: { type: 'string', description: 'The entry id.' },
            field: { type: 'string',
                     enum: ['spiffeId', 'parentId', 'selectors', 'dnsNames',
                            'federatesWith', 'x509SvidTtl', 'jwtSvidTtl',
                            'hint', 'expiresAt', 'admin', 'downstream',
                            'storeSvid'],
                     description: 'Which field. Anything else is refused ' +
                                  'naming these.' },
            value: { type: 'string',
                     description: 'A list field takes comma-separated values ' +
                                  'and an empty value CLEARS it; a boolean ' +
                                  'takes true or false; a TTL takes seconds.' }
          },
          required: ['entry', 'field'],
          examples: [{ entry: '0f5a…', field: 'hint', value: 'internal' }],
          additionalProperties: false
        },
        responseDescription:
          'The entry as it now stands, at its new revision.' },

      { action: 'delete', operationId: 'deleteSpiffeEntry',
        summary: 'Remove an entry',
        description: 'Anything holding an SVID minted from it keeps that ' +
                     'SVID until it expires. SPIFFE has no revocation — the ' +
                     'answer is a short lifetime and rotation, which is why ' +
                     'the default X509-SVID lifetime here is an hour and the ' +
                     'JWT-SVID one is five minutes.\n\nIf this was the LAST ' +
                     'entry naming that SPIFFE ID, the identity\'s directory ' +
                     'entry under `ou=users` is marked ' +
                     '`spiffeCredentialStatus: revoked` with the reason on ' +
                     'it. The entry is NOT deleted, and that flag is not a ' +
                     'certificate status: nothing reads it back and no SVID ' +
                     'is refused because of it. Deleting one of several ' +
                     'entries that name the same identity changes nothing ' +
                     'there.\n\nA seeded entry stays deleted until a ' +
                     'restart: nothing here is persisted, but nothing ' +
                     're-creates it either, because an operator who deleted ' +
                     'it meant to.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            entry: { type: 'string', description: 'The entry id.' }
          },
          required: ['entry'],
          examples: [{ entry: '0f5a…' }],
          additionalProperties: false
        },
        responseDescription: 'That it is gone.' }
    ] },

  { method: 'GET', path: BASE + '/spiffe/agents', tag: 'SPIFFE',
    operationId: 'getSpiffeAgents',
    summary: 'The agents that have attested here, filtered and paged',
    description: 'An agent appears when it calls `AttestAgent` on the SPIRE ' +
                 'Server API. These entries are a RECORD rather than ' +
                 'configuration — everything on them was written by this ' +
                 'service — which is why nothing about an agent is editable ' +
                 'and the only write is the ban.\n\n**Node attestation is ' +
                 'never verified.** Whatever attestor an agent names and ' +
                 'whatever payload it sends are written down as claimed, ' +
                 'which is why every agent carries a selector valued ' +
                 '`unverified:true`: an agent\'s selectors here are claims, ' +
                 'not attested facts.',
    mirrors: 'GET /admin/spiffe/agents',
    parameters: [
      { name: 'agent', in: 'query', required: false, schema: { type: 'string' },
        description: 'One agent, by its SPIFFE ID — always under ' +
                     '`/spire/agent/`. The reply then carries its directory ' +
                     'entry, where the cn is a DIGEST of the SPIFFE ID and ' +
                     '`spiffeAgentId` is the identity.' },
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the agent id, the attestation type or any ' +
                     'selector, case-insensitive.' }
    ].concat(pagingParameters()),
    responseDescription: 'The matching agents with the paging that found them.',
    responseSchema: { type: 'object',
                      description: 'Attested agents and their paging.' },
    handler: function (req, res) {
      log.debug("Entering the management API SPIFFE agents endpoint.");
      sendJson(res, 200, adminViews.spiffeAgentsJson(req).json);
      log.debug("Leaving the management API SPIFFE agents endpoint.");
    } },

  { method: 'POST', route: BASE + '/spiffe/agents/:action', tag: 'SPIFFE',
    mirrors: 'POST /admin/spiffe/agents',
    handler: function (req, res) {
      log.debug("Entering the management API SPIFFE agents action endpoint.");
      const body = parseBody(req);
      const result = adminActions.spiffeAgentsAction(withAction(req, body));
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-API-0064');
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API SPIFFE agents action endpoint.");
    },
    actions: [
      { action: 'ban', operationId: 'banSpiffeAgent',
        summary: 'Refuse this agent at AttestAgent',
        description: 'ONE OF THE FEW REFUSALS IN THIS SERVICE, and it earns ' +
                     'its place: a ban that did not refuse would make the ' +
                     'button a lie. A banned agent gets `PermissionDenied` ' +
                     'from `AttestAgent`.\n\nWhatever SVID it already holds ' +
                     'keeps working until it expires. There is no revocation ' +
                     'in SPIFFE, so a ban stops the NEXT identity rather ' +
                     'than the current one.\n\nThe agent\'s own entry under ' +
                     '`ou=users` — the one every identity this trust domain ' +
                     'issues a certificate to gets — is marked ' +
                     '`spiffeCredentialStatus: revoked`, and unbanning marks ' +
                     'it active again. It is never deleted, and nothing ' +
                     'reads that flag back.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            agent: { type: 'string', description: 'The agent\'s SPIFFE ID.' }
          },
          required: ['agent'],
          examples:
            [{ agent: 'spiffe://example.org/spire/agent/k8s_psat/abc' }],
          additionalProperties: false
        },
        responseDescription: 'The agent as it now stands.' },

      { action: 'unban', operationId: 'unbanSpiffeAgent',
        summary: 'Let this agent attest again',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            agent: { type: 'string', description: 'The agent\'s SPIFFE ID.' }
          },
          required: ['agent'],
          examples:
            [{ agent: 'spiffe://example.org/spire/agent/k8s_psat/abc' }],
          additionalProperties: false
        },
        responseDescription: 'The agent as it now stands.' },

      { action: 'delete', operationId: 'deleteSpiffeAgent',
        summary: 'Forget an agent',
        description: '**Deleting is forgetting, not revoking.** It reappears ' +
                     'the moment it attests again, because attestation is ' +
                     'not checked here. Ban it if the intention was to stop ' +
                     'it.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            agent: { type: 'string', description: 'The agent\'s SPIFFE ID.' }
          },
          required: ['agent'],
          examples:
            [{ agent: 'spiffe://example.org/spire/agent/k8s_psat/abc' }],
          additionalProperties: false
        },
        responseDescription: 'That it is forgotten.' }
    ] },
  // CERTIFICATE ENROLLMENT (2026-09-13). Each family's operations are declared
  // beside the family, in a file that registers no route and requires its view
  // model lazily inside each handler — so requiring it here, at 19, moves no
  // route (rule 1), exactly as the GNAP rows above reach `gnap_console.js`.
  ...require('../acme/acme_api').ROUTES,
  ...require('../est/est_api').ROUTES,
  ...require('../scep/scep_api').ROUTES,
  // THE OAUTH 2.0 / OIDC MONITORING PAGE (2026-09-13), declared beside its
  // family in the same shape: no route registered there, and its view model
  // required lazily inside each handler.
  ...require('../oauth-oidc/oauth2_monitor_api').ROUTES
];

// Every operation, flattened, for the index. The same walk buildSpec() does,
// and deliberately not a second list: an index that could disagree with the
// document would be the first thing to go stale.
function operationSummaries() {
  log.debug("Entering operationSummaries().");
  const out = [];
  ROUTES.forEach(function (entry) {
    if (!entry.actions) {
      out.push({ method: entry.method, path: entry.path,
                 operationId: entry.operationId, summary: entry.summary,
                 mirrors: entry.mirrors || '' });
      return;
    }
    entry.actions.forEach(function (action) {
      out.push({ method: entry.method,
                 path: entry.route.replace(':action', action.action),
                 operationId: action.operationId, summary: action.summary,
                 mirrors: action.mirrors || entry.mirrors || '' });
    });
  });
  log.debug("Leaving operationSummaries(). " + out.length + " operation(s).");
  return out;
}

// --- registration -----------------------------------------------------------
//
// One express route per row, which for the four action resources is one pattern
// behind every action in it. Registering at require time is what every module
// here does; see rule 1.
// ---------------------------------------------------------------------------
// THE GATE (2026-09-06), AND IT IS THE ONLY THING BETWEEN THIS API AND A TOTAL
// AUTHENTICATION BYPASS IN PRODUCT MODE.
//
// **THIS RESOURCE IS UNGATED IN DEVELOPMENT AND THAT IS DELIBERATE** — it is
// what the tests drive, and it is the way back in when nobody holds a role,
// which a service that checks no password needs because there is otherwise no
// way to bootstrap an administrator. `mgmt-api/CLAUDE.md` has argued that since
// this API existed, and every word of it is still true of development mode.
//
// It cannot survive into a product. Anybody who can reach this port can grant
// themselves both console roles through `POST /admin-api/rbac/grant`, so an
// ungated management API is not "a convenience beside a secured console" — it
// is the console's gate with a documented way around it.
//
// **ONE MIDDLEWARE RATHER THAN A CHECK PER HANDLER**, and the reason is this
// file's shape: there are 232 operations behind 30-odd routes, and a check per
// handler is 232 chances to add the 233rd without one. Registered BEFORE the
// routes below, because express applies middleware only to routes added after
// it — rule 1's other half.
//
// **THE EXPLORER AND ITS DOCUMENT ARE GATED TOO.** They describe every
// operation this service offers, which is a map of the administrative surface;
// a product deployment that served that to anybody would be handing out the
// floor plan. They are HTML and JavaScript rather than JSON, so the refusal is
// shaped for a browser.
// ---------------------------------------------------------------------------
// AND SINCE 2026-09-09 THE FIRST QUESTION IS AN ACCESS TOKEN, IN EVERY MODE.
//
// The paragraphs above are the record of what this surface used to be and are
// kept because the argument they make is still the argument for the OFF
// switch: `adminApi.authRequired` restores the open API exactly, and it is
// the way back in when nobody can mint a token.
//
// What changed is the default. `/admin-api` is a MACHINE surface — no browser,
// no session, no sign-in screen — so it is reached the way a machine reaches a
// resource server: an OAuth 2.0 access token this service issued, audienced to
// this API, carrying `admin:read` for a read and `admin:write` for anything
// that changes state. Three things are checked and each refuses differently,
// because they are three different mistakes:
//
//   * NO TOKEN, or one this service did not sign, or an expired one — 401 with
//     a `WWW-Authenticate` header naming the scopes, which is what an OAuth
//     client is built to read.
//   * A TOKEN FOR SOMETHING ELSE — 403. An access token is a bearer
//     credential, so one minted for another resource server must not be
//     replayable here; that is the whole purpose of `aud` and it is the check
//     most often left out.
//   * A TOKEN WITHOUT THE SCOPE THE OPERATION NEEDS — 403 from the POLICY,
//     not from this code. The scopes become the built-in ADMIN_READ and
//     ADMIN_WRITE roles (see `common/roles.js`) and the XACML access-control
//     document asks for the one the action requires, so what this surface
//     demands is stated where every other access decision in this service is
//     stated rather than in an `if` here.
//
// THE SCOPE IS NOT THE ROLE AND THE MAPPING IS DELIBERATE. A scope is what a
// client asked for and the authorization server granted; a role is what a
// policy names. Keeping them apart is what lets a deployment write "a read of
// the management API needs ADMIN_READ" without the document knowing that OAuth
// exists.
// ---------------------------------------------------------------------------
function bearerOf(req) {
  log.debug("Entering bearerOf().");
  const said = String((req.headers && req.headers.authorization) || '');
  if (!/^bearer\s+/i.test(said)) {
    log.debug("Leaving bearerOf().");
    return '';
  }
  log.debug("Leaving bearerOf().");
  return said.replace(/^bearer\s+/i, '').trim();
}

// What `aud` has to name. The CONFIGURED audience first — since 2026-09-13
// `adminApi.audience` defaults to the base URL of this API
// (`config.managementApiBaseUrl()`) rather than to the empty string — and,
// while that row is still at its default or set empty, `/admin-api` under the
// host the request arrived on as well, which is exactly what a client gets by
// asking `resource=<base>/admin-api` at the token endpoint. A default cannot
// see a request, so taking it as the only answer would refuse every token
// minted under another name for this same process. An operator who sets a
// value pins that one value, as before.
function wantedAudiences(req) {
  log.debug("Entering wantedAudiences().");
  const pinned = String(config.value('adminApi.audience') || '').trim();
  const atDefault = config.sourceOf('adminApi.audience') === 'default';
  if (pinned && !atDefault) {
    log.debug("Leaving wantedAudiences().");
    return [pinned];
  }
  // COMPUTED OUTSIDE ANY REALM, for the reason the signing key is taken from
  // the default realm below: THIS credential is service-wide. `baseUrlOf()`
  // glues on `realms.currentPrefix()`, so under `/realm/acme` it would answer
  // `https://host/realm/acme/admin-api` — a different audience per realm.
  // Running in the default realm gives the empty prefix and one audience
  // everywhere. A realm's OWN token (2026-09-14, #32) carries the realm's
  // audience instead and is checked by `realmAudienceAccepted()`, which is
  // the one place a per-realm audience is accepted.
  const fromRequest = realms.run(realms.get(realms.DEFAULT_ID), function () {
    return baseUrlOf(req);
  }) + BASE;
  const wanted = [pinned || config.managementApiBaseUrl()];
  if (wanted.indexOf(fromRequest) < 0) {
    wanted.push(fromRequest);
  }
  log.debug("Leaving wantedAudiences().");
  return wanted;
}

// The one audience a refusal or a 401 names: the request-relative one where it
// is accepted, because that is the `resource` the caller reading the message
// can actually ask for under the name it used.
function wantedAudience(req) {
  log.debug("Entering wantedAudience().");
  const wanted = wantedAudiences(req);
  log.debug("Leaving wantedAudience().");
  return wanted[wanted.length - 1];
}

function audienceAccepted(claims, req) {
  log.debug("Entering audienceAccepted().");
  const wanted = wantedAudiences(req);
  const held = Array.isArray(claims.aud) ? claims.aud
    : (claims.aud === undefined || claims.aud === null ? [] : [claims.aud]);
  log.debug("Leaving audienceAccepted().");
  return held.map(String).some(function (aud) {
    return wanted.indexOf(aud) >= 0;
  });
}

// ---------------------------------------------------------------------------
// RFC 9068 SECTION 4 STEP 3 — WHO ISSUED IT (2026-09-13).
//
// The addresses this API answers under, as authorization-server bases: every
// wanted audience that is `<base>/admin-api`, the request's own default-realm
// base, and the configured base of this API. A token's `iss` must be an issuer
// one of this service's authorization servers publishes at one of them — the
// default one, or a named one beneath it — which is `jwt_access_token.js`'s
// `isHostedIssuer()`, the same reading the other resource servers here make.
//
// SEVERAL BASES AND NOT ONE, for `wantedAudiences()`'s reason: this process
// is reached under more than one name, and the suite mints a token at the
// address it will call. A token minted under one of them names that one as
// its issuer and its audience together, so accepting the issuers of exactly
// the addresses whose audiences are accepted is what keeps the two checks
// telling the same story. A pinned `adminApi.audience` names no base, which is
// why the request's own and the configured one are always in the list.
//
// ASKED IN THE DEFAULT REALM, because that realm's key verified the token and
// a pinned `oauth2.issuer` is read per realm.
// ---------------------------------------------------------------------------
function issuerAccepted(claims, req) {
  log.debug("Entering issuerAccepted().");
  const bases = [];
  const addBase = function (url) {
    const text = String(url || '');
    if (text.length > BASE.length && text.slice(-BASE.length) === BASE) {
      const base = text.slice(0, -BASE.length);
      if (bases.indexOf(base) < 0) {
        bases.push(base);
      }
    }
  };
  const accepted = realms.run(realms.get(realms.DEFAULT_ID), function () {
    wantedAudiences(req).forEach(addBase);
    addBase(baseUrlOf(req) + BASE);
    addBase(config.managementApiBaseUrl());
    return bases.some(function (base) {
      return jwtAccessToken.isHostedIssuer(claims.iss, base);
    });
  });
  log.debug("Leaving issuerAccepted(). accepted=" + accepted);
  return accepted;
}

// ---------------------------------------------------------------------------
// A REALM TOKEN'S THREE BOUNDS (2026-09-14, #32). See the gate below.
// ---------------------------------------------------------------------------

// Its issuer is THIS realm's: a hosted issuer under the realm's own base.
function realmIssuerAccepted(claims, req) {
  log.debug("Entering realmIssuerAccepted().");
  const accepted = jwtAccessToken.isHostedIssuer(claims.iss, baseUrlOf(req));
  log.debug("Leaving realmIssuerAccepted(). " + accepted);
  return accepted;
}

// Its audience is THIS realm's management API — the request's own base under
// the realm prefix, which is what `resource=<base>/realm/<id>/admin-api` at
// that realm's token endpoint gives. `adminApi.audience` pins the SERVICE's
// audience and is not consulted: it names the unprefixed API.
function realmAudienceAccepted(claims, req) {
  log.debug("Entering realmAudienceAccepted().");
  const wanted = baseUrlOf(req) + BASE;
  const held = Array.isArray(claims.aud) ? claims.aud
    : (claims.aud === undefined || claims.aud === null ? [] : [claims.aud]);
  const accepted = held.map(String).indexOf(wanted) >= 0;
  log.debug("Leaving realmAudienceAccepted(). " + accepted);
  return accepted;
}

// The operation a request is, as the CONSOLE path it mirrors and the action
// it names: `/admin-api/pki/build-root` is a POST of `build-root` to
// `/admin/pki`, `/admin-api/config/set-many` one of `set-many` to
// `/admin/config`. An action route is recognised off ROUTES, so a path segment
// is only ever an action where this API declares one.
function consoleOperationOf(req) {
  log.debug("Entering consoleOperationOf().");
  const path = BASE + String(req.path || '');
  let action = '';
  let resource = path;
  ROUTES.forEach(function (entry) {
    const route = String(entry.route || '');
    if (!action && route.slice(-':action'.length) === ':action') {
      const prefix = route.slice(0, -':action'.length);
      const rest = path.slice(prefix.length);
      if (path.indexOf(prefix) === 0 && rest && rest.indexOf('/') < 0) {
        action = rest;
        resource = prefix.replace(/\/$/, '');
      }
    }
  });
  log.debug("Leaving consoleOperationOf(). " + resource + " " + action);
  return { path: '/admin' + resource.slice(BASE.length), action: action };
}

// The client, and the scope table. Answers null, or `{ code, detail }`.
//
// **ONLY THIS REALM'S `sts-management-api`.** The token endpoint does not
// restrict who may ask for `admin:*`, so without this any client registered in
// the realm — by an operator, by dynamic registration — could mint itself
// Admin Write over the realm. The seeded client is the realm's door.
function realmTokenRefusal(claims, req) {
  log.debug("Entering realmTokenRefusal().");
  if (String(claims.client_id || '') !== 'sts-management-api') {
    log.debug("Leaving realmTokenRefusal(). Another client.");
    return { code: 'STS-API-0111',
             detail: 'A trust realm\'s own access token is accepted only ' +
                     'from that realm\'s sts-management-api client, and this ' +
                     'one was issued to ' +
                     JSON.stringify(claims.client_id || null) + '.' };
  }
  const operation = consoleOperationOf(req);
  const body = req.method === 'GET' || req.method === 'HEAD'
    ? null : Object.assign({}, parseBody(req));
  if (body && operation.action) {
    body.action = operation.action;
  }
  const refusal = adminScope.refusalFor(
    { authority: 'realm', identityRealm: realms.currentId() },
    operation.path, body, req.query);
  log.debug("Leaving realmTokenRefusal(). " +
            (refusal ? refusal.reason : 'allowed'));
  return refusal
    ? { code: 'STS-API-0112',
        detail: refusal.detail + ' A realm\'s token reaches that realm\'s ' +
                'operations only; a service administrator\'s token, from ' +
                'the default realm, reaches this one.' }
    : null;
}

app.use(BASE, function (req, res, next) {
  if (config.value('adminApi.authRequired')) {
    const scopesWanted = req.method === 'GET' ? 'admin:read' : 'admin:write';
    const presented = bearerOf(req);
    if (!presented) {
      errorCodes.mark(res, 'STS-API-0001');
      res.set('WWW-Authenticate',
              'Bearer realm="' + BASE + '", scope="admin:read admin:write"');
      return sendJson(res, 401, { error: 'unauthorized', errors: [
        'This API requires an OAuth 2.0 access token. Ask ' +
        '/oauth2/token for one with `grant_type=client_credentials`, ' +
        '`scope=admin:read admin:write` and `resource=' +
        wantedAudience(req) + '`, then send it as `Authorization: Bearer`. ' +
        'adminApi.authRequired turns this off.'] });
    }
    // ---------------------------------------------------------------------
    // VERIFIED AGAINST THE DEFAULT REALM'S KEY, WHEREVER THIS IS REACHED.
    //
    // `STS` is a proxy over the AMBIENT realm's key set, so under
    // `/realm/<id>/admin-api` it is that realm's — and a token minted at the
    // default realm's token endpoint then fails to verify, which is a 401 on a
    // perfectly good credential.
    //
    // Taking the default realm's key is not a workaround for that; it is the
    // SERVICE credential, and the service roster is the default realm's too.
    // A token a realm's key signed would be believed nowhere else if it were
    // believed here, which is why that case is its own block below: since
    // 2026-09-14 (#32) a realm has administrators of its own, their token is
    // tried only under their realm's prefix, and `admin_scope.js` refuses it
    // every service-wide operation. Believing a realm-minted token AS the
    // service credential would be the hole — anybody who could create a realm
    // minting a token for everything — and this key is what keeps it shut.
    //
    // The AUDIENCE needs no such care: `baseUrlOf()` answers scheme and host
    // with no path, so `<base>/admin-api` is the same string in every realm.
    // ---------------------------------------------------------------------
    let claims = null;
    try {
      const certPem = realms.run(realms.get(realms.DEFAULT_ID),
                                 function () { return STS.certPem; });
      claims = stsCrypto.verifyJws(presented, certPem);
    } catch (e) {
      log.debug("Caught in a callback in module scope: " +
                ((e && e.message) || e));
      claims = null;
    }
    // -------------------------------------------------------------------
    // A REALM'S OWN TOKEN (2026-09-14, #32).
    //
    // A trust realm has administrators of its own, and rule 7 owes them the
    // machine door to their realm. A token that does not verify under the
    // default realm's key is tried under the AMBIENT realm's key — and only
    // when the request is under a realm prefix, so a realm's key is never
    // tried at `/admin-api` itself or at another realm's. What such a token
    // may do is then bounded three ways below: its issuer and audience are
    // this realm's, it was issued to this realm's `sts-management-api`
    // client, and `admin-ui/admin_scope.js` refuses it every service-wide
    // operation.
    //
    // This is the hole the comment above the default-realm key named — a
    // realm-minted credential its API believes — answered rather than
    // reopened: the credential is believed IN THAT REALM ONLY.
    // -------------------------------------------------------------------
    let tokenRealm = realms.DEFAULT_ID;
    if (!claims && realms.currentId() !== realms.DEFAULT_ID) {
      try {
        claims = stsCrypto.verifyJws(presented, STS.certPem);
        tokenRealm = realms.currentId();
      } catch (e) {
        log.debug("Caught in a callback in module scope: " +
                  ((e && e.message) || e));
        claims = null;
      }
    }
    if (!claims) {
      errorCodes.mark(res, 'STS-API-0002');
      res.set('WWW-Authenticate',
              'Bearer error="invalid_token", scope="' + scopesWanted + '"');
      return sendJson(res, 401, { error: 'invalid_token', errors: [
        'That access token was not issued by this service, or its signature ' +
        'does not verify. Tokens are signed with the key at /oauth2/jwks and ' +
        'that key is regenerated on every start in development mode.'] });
    }
    const now = Math.floor(Date.now() / 1000);
    if (claims.exp && Number(claims.exp) <= now) {
      errorCodes.mark(res, 'STS-API-0003');
      res.set('WWW-Authenticate',
              'Bearer error="invalid_token", scope="' + scopesWanted + '"');
      return sendJson(res, 401, { error: 'invalid_token', errors: [
        'That access token expired at ' +
        new Date(Number(claims.exp) * 1000).toISOString() + '.'] });
    }
    // RFC 9068 SECTION 4, STEPS 1 AND 3, in its order: the TYPE before the
    // issuer, and both before the audience. Every token this service signs is
    // signed with this key, so without the header an ID Token audienced to a
    // client named `…/admin-api` would be an administrative credential here.
    const typ = jwtAccessToken.typOf(presented);
    if (!jwtAccessToken.isAccessTokenType(typ)) {
      errorCodes.mark(res, 'STS-API-0082');
      res.set('WWW-Authenticate',
              'Bearer error="invalid_token", scope="' + scopesWanted + '"');
      return sendJson(res, 401, { error: 'invalid_token', errors: [
        'RFC 9068 section 4: a JWT access token\'s typ header must be ' +
        '"at+jwt", and this token\'s is ' + (typ ? '"' + typ + '"' : 'absent') +
        '. An ID Token or a refresh token is not an access token, and a ' +
        'token minted before this service issued at+jwt is refused too; ask ' +
        '/oauth2/token for a new one.'] });
    }
    if (tokenRealm === realms.DEFAULT_ID ? !issuerAccepted(claims, req)
                                         : !realmIssuerAccepted(claims, req)) {
      errorCodes.mark(res, 'STS-API-0083');
      res.set('WWW-Authenticate',
              'Bearer error="invalid_token", scope="' + scopesWanted + '"');
      return sendJson(res, 401, { error: 'invalid_token', errors: [
        'RFC 9068 section 4: the iss claim must exactly match an issuer this ' +
        'service publishes, and this token names ' +
        JSON.stringify(claims.iss || null) + '. An issuer is an address, so ' +
        'a token minted under one host name is refused under another; mint ' +
        'it at the address you call this API at, or set ' +
        'global.publicBaseUrl.'] });
    }
    const audienceOk = tokenRealm === realms.DEFAULT_ID
      ? audienceAccepted(claims, req) : realmAudienceAccepted(claims, req);
    if (!audienceOk) {
      errorCodes.mark(res, 'STS-API-0004');
      return sendJson(res, 403, { error: 'forbidden', errors: [
        'That access token is for a different audience. It carries ' +
        JSON.stringify(claims.aud || null) + ' and this API answers to ' +
        wantedAudiences(req).map(function (aud) {
          return '"' + aud + '"';
        }).join(' or ') + '. A bearer token minted for another resource ' +
        'server must not be replayable here, which is what `aud` is for.'] });
    }
    // RFC 8705 SECTION 3.1 (2026-09-13). This gate verified a token's
    // signature, type, issuer and audience and never looked at
    // `cnf["x5t#S256"]`, so a certificate-bound administrative token was a
    // bearer token here — the one resource server in the service where
    // sender-constraining would matter most. 401 invalid_token, section 3's
    // answer. `true`: the signature was verified above.
    const certificateProblem = mtls.checkBinding(claims, req, true);
    if (certificateProblem) {
      errorCodes.mark(res, 'STS-API-0110');
      res.set('WWW-Authenticate',
              'Bearer error="invalid_token", scope="' + scopesWanted + '"');
      return sendJson(res, 401, { error: 'invalid_token',
                                  errors: [certificateProblem.description] });
    }
    const scopes = String(claims.scope || '').split(/\s+/).filter(Boolean);
    const who = String(claims.client_id || claims.sub || '(a client)');
    if (tokenRealm !== realms.DEFAULT_ID) {
      const realmRefusal = realmTokenRefusal(claims, req);
      if (realmRefusal) {
        errorCodes.mark(res, realmRefusal.code);
        // error-code: none — the code is realmRefusal.code, marked above
        return sendJson(res, 403, { error: 'forbidden',
                                    errors: [realmRefusal.detail] });
      }
    }
    const held = roles.rolesOf({ kind: 'application', name: who,
                                 authenticated: true, scopes: scopes });
    const policy = accessGate.check({
      resource: accessGate.RESOURCE.MANAGEMENT_API,
      action: req.method === 'GET' ? accessGate.ACTION.READ
                                   : accessGate.ACTION.WRITE,
      // THE REQUIREMENT IS STATED HERE AND ENFORCED THERE. `requiredRoles`
      // travels in the REQUEST — the `access-control` document is written to
      // take it from there, which is what lets one policy decide for every
      // surface — so naming the role per action is the whole of encoding
      // "a read needs ADMIN_READ and a write needs ADMIN_WRITE" in XACML.
      // Nothing in this file decides the outcome; it decides the question.
      requiredRoles: [req.method === 'GET' ? 'ADMIN_READ' : 'ADMIN_WRITE'],
      subject: { name: who, authenticated: true, roles: held, sessionId: null },
      context: { method: req.method, path: req.originalUrl || req.url }
    });
    if (!policy.allowed) {
      log.info('admin-api: the access policy refused ' + req.method + ' ' +
               (req.originalUrl || req.url) + ' for ' + who + '. ' +
               policy.why);
      errorCodes.mark(res, 'STS-API-0005');
      return sendJson(res, 403, { error: 'forbidden', errors: [
        'The access policy refused this request. ' + policy.why +
        ' This token carries the scope(s) ' +
        (scopes.length ? scopes.join(', ') : '(none)') + ', which is the ' +
        'role(s) ' + (held.length ? held.join(', ') : '(none)') + '. A ' +
        (req.method === 'GET' ? 'read needs admin:read (ADMIN_READ)'
                              : 'write needs admin:write (ADMIN_WRITE)') +
        '. The document is on /admin/xacml and xacml.enforceAccess turns ' +
        'the layer off.'] });
    }
    return next();
  }
  if (!mode.gatesManagementApi()) {
    return next();
  }
  const gate = adminViews.gateStateFor(req);
  // A REALM ADMINISTRATOR'S SESSION (2026-09-14, #32) holds nothing outside
  // its realm — `gateStateFor()` has already said so — and in its realm is
  // refused the service-wide operations, exactly as at the console's gate.
  if (gate.authority === 'realm') {
    const operation = consoleOperationOf(req);
    const body = req.method === 'GET' || req.method === 'HEAD'
      ? null : Object.assign({}, parseBody(req));
    if (body && operation.action) {
      body.action = operation.action;
    }
    const scoped = gate.outsideRealm
      ? { detail: 'This session administers the "' + gate.identityRealm +
                  '" realm and this request is for another.' }
      : adminScope.refusalFor(gate, operation.path, body, req.query);
    if (scoped) {
      errorCodes.mark(res, 'STS-API-0112');
      return sendJson(res, 403, { error: 'forbidden',
                                  errors: [scoped.detail] });
    }
  }
  // THE SAME TWO ROLES THE CONSOLE USES, and the same asymmetry: a GET needs
  // Admin Read and anything else needs Admin Write. Asking `admin.js` rather
  // than re-deriving it is what stops this becoming a second answer to who may
  // administer this service — the mistake `logout.js` exists to prevent one
  // layer down.
  const needed = req.method === 'GET' ? gate.read : gate.write;
  if (needed) {
    // -------------------------------------------------------------------
    // AND THEN THE POLICY (2026-09-06), which is the layer ABOVE the roles
    // and not a replacement for them.
    //
    // The two console roles decide who may administer this service and stay
    // exactly where they are — `adminViews.gateStateFor()` is still the one
    // answer to that, which is what stops this becoming a second one. What the
    // gate adds is that a deployment can narrow this surface by POLICY, with
    // the subject taken from the SESSION that got the caller through the check
    // above and never from anything on the request.
    //
    // **IT RUNS ONLY WHERE THIS SURFACE IS GATED AT ALL**, which is the same
    // `mode.gatesManagementApi()` branch three lines up. In development this
    // API is open by design — there is no credential, so no session, so no
    // subject — and asking a policy whose built-in document refuses an
    // unauthenticated subject would close the door the tests drive and the
    // door somebody locked out of the console gets back in through. A policy
    // layer must not be the thing that removes the recovery path.
    //
    // On an unedited product deployment it permits: the built-in document
    // asks for a role only where somebody has required one, and the caller
    // has already been shown to hold Admin Read or Admin Write.
    const policy = accessGate.check({
      resource: accessGate.RESOURCE.MANAGEMENT_API,
      action: req.method === 'GET' ? accessGate.ACTION.READ
                                   : accessGate.ACTION.WRITE,
      subject: { name: gate.username,
                 authenticated: !!(gate.session &&
                                   gate.session.authenticated !== false),
                 roles: gate.roles || [],
                 sessionId: gate.session ? gate.session.id : null },
      context: { method: req.method, path: req.originalUrl || req.url }
    });
    if (!policy.allowed) {
      log.info('admin-api: the access policy refused ' + req.method + ' ' +
               (req.originalUrl || req.url) + ' for ' +
               (gate.username || '(nobody)') + '. ' + policy.why);
      errorCodes.mark(res, 'STS-API-0006');
      return sendJson(res, 403, {
        error: 'forbidden',
        errors: ['The access policy refused this request. ' + policy.why +
                 ' This is a POLICY decision rather than a missing role: ' +
                 (gate.username || 'the caller') + ' holds ' +
                 ((gate.roles && gate.roles.length)
                   ? gate.roles.join(', ') : 'no role') +
                 ' and passed the role check. The document is on ' +
                 '/admin/xacml and xacml.enforceAccess turns the layer off.']
      });
    }
    return next();
  }
  log.info('admin-api: product mode refused ' + req.method + ' ' +
           (req.originalUrl || req.url) + ' — ' +
           (gate.username ? gate.username + ' holds ' +
              (gate.roles.length ? gate.roles.join(', ') : 'no role')
            : 'nobody is signed in') + '.');
  const wantsHtml = /html/i.test(String(req.headers.accept || ''));
  if (wantsHtml) {
    errorCodes.mark(res, gate.username ? 'STS-API-0008' : 'STS-API-0007');
    return res.status(403).type('html').send(
      '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
      '<title>Forbidden</title></head><body><h1>403 Forbidden</h1>' +
      '<p>This service is in <strong>product mode</strong>, where the ' +
      'management API requires the same sign-in and roles the console does. ' +
      '<a href="/admin">Sign in</a>.</p></body></html>');
  }
  errorCodes.mark(res, gate.username ? 'STS-API-0008' : 'STS-API-0007');
  return sendJson(res, gate.username ? 403 : 401, {
    error: 'forbidden',
    errors: ['This service is in product mode, where ' + BASE + ' requires ' +
             'the same sign-in and the same two roles /admin does — ' +
             (req.method === 'GET' ? gate.readGroup : gate.writeGroup) +
             ' for a ' + req.method + '. ' +
             (gate.username
               ? 'You are signed in as ' + gate.username + ' and hold ' +
                 (gate.roles.length ? gate.roles.join(', ') : 'no role') + '.'
               : 'Nobody is signed in on this request.') +
             ' In development mode this API is open, which is what the tests ' +
             'drive and the way back in when nobody holds a role.']
  });
});

compileRequestSchemas();

// ---------------------------------------------------------------------------
// REGISTRATION IS THE CHOKE POINT, and it has to be: there is no generic
// dispatcher here. Every handler in the table above reads its own body with
// `parseBody(req)` and refuses in its own words, so a check written inside them
// would be a hundred and fifty-one checks and the hundred and fifty-second
// would be forgotten. Here it is one wrapper, driven by the same table the
// OpenAPI document is built from, so an operation cannot acquire a schema
// without acquiring its enforcement.
//
// A GET is registered exactly as before. Nothing about a query string goes
// through here — that is `common/validation.js`'s guard and the per-page
// schemas.
// ---------------------------------------------------------------------------
ROUTES.forEach(function (entry) {
  const path = entry.route || entry.path;
  if (entry.method === 'GET') {
    // A GET that `mirrors` exactly one Protocols page answers that page's
    // endpoints as well, which is rule 7 for the section `respond()` draws
    // there. `mirrors` is the join because it is already the column that
    // says which page an operation is the machine's door to; one naming two
    // pages is not a mirror of either and gets nothing.
    const mirrored = /^GET (\/admin\S*)$/.exec(String(entry.mirrors || ''));
    const page = mirrored &&
                 protocolEndpoints.pages().indexOf(mirrored[1]) >= 0 ?
                 mirrored[1] : null;
    if (!page) {
      app.get(path, entry.handler);
      return;
    }
    app.get(path, function (req, res) {
      res.locals.protocolEndpoints = protocolEndpoints.forPage(req, page);
      return entry.handler(req, res);
    });
    return;
  }
  app.post(path, function (req, res) {
    // The route this request matched, so the wrapper can find its schema
    // without re-deriving the path from what express matched.
    req.__adminApiRoute = path;
    req.__adminApiHandlerOwnsBody = !!entry.handlerOwnsBody;
    const checked = checkRequestBody(req);
    if (!checked.ok) {
      log.debug("The management API refused a request body against " +
                (entry.operationId || path) + "'s schema.");
      errorCodes.mark(res, 'STS-API-0009');
      sendJson(res, 400, { ok: false, errors: checked.errors });
      return undefined;
    }
    return entry.handler(req, res);
  });
});

// WHAT THIS BANNER SAYS CHANGED ON 2026-09-08 AND THE OLD TEXT IS WORTH
// RECORDING, because it was true for as long as this file existed and is now
// exactly wrong: it read "It is NOT protected", and told a reader that this
// was the surface to reach for when nobody holds a console role. Anybody
// working from a log line from an older build will look for that sentence, so
// the replacement contradicts it in the same place rather than going quiet.
//
// It is computed at require time and says "currently", because
// `adminApi.authRequired` is changeable while running — a banner that stated
// it as a fact would be a line in a log claiming something the operator turned
// off ten minutes later.
log.info('The management API is at ' + BASE + ': ' +
         operationSummaries().length + ' operations over the same functions ' +
         'the /admin console calls. Its OpenAPI document is at ' + BASE +
         '/openapi.json and an explorer that calls it is at ' + BASE +
         '/docs. ' +
         (config.value('adminApi.authRequired')
           ? 'It REQUIRES an OAuth 2.0 access token (adminApi.authRequired): ' +
             'audience ' +
             (config.sourceOf('adminApi.audience') === 'default'
               ? config.value('adminApi.audience') + ' (or ' + BASE +
                 ' under the host a request arrives on)'
               : (config.value('adminApi.audience') || BASE)) + ', ' +
             'scope admin:read to read and admin:write to write, checked as ' +
             'a XACML access decision against the ADMIN_READ and ADMIN_WRITE ' +
             'roles. Get one from the client_credentials grant as the seeded ' +
             'application sts-management-api, whose secret is ' +
             'adminApi.clientSecret. THAT SETTING IS THE BOOTSTRAP: this ' +
             'surface used to be the way back in when nobody held a console ' +
             'role, and it is only still that if the secret was pinned ' +
             'before the start — a secret minted per start is readable only ' +
             'through the API it unlocks.'
           : 'It is NOT protected (adminApi.authRequired is off) — and the ' +
             'console is gated unconditionally, so this is the surface to ' +
             'reach for when nobody holds a console role: POST ' + BASE +
             '/rbac/grant.'));

// ---------------------------------------------------------------------------
// WHAT THE OPENAPI DOCUMENT IS BUILT FROM, IN ONE PLACE.
//
// `admin_api_spec.js` is a pure function over the route table and takes every
// fact about the running service as an option — that is its own rule, and it
// is what keeps the document from describing one moment. The cost of that rule
// is that each CALLER has to supply those facts, and there are three: this
// file's `/admin-api/openapi.json`, and the two in
// `admin-ui/api_explorer.js` (the console's copy of the document, and the
// `?format=json` view that counts its operations).
//
// **THREE CALLERS ASSEMBLING THE SAME OPTIONS BY HAND IS THREE ANSWERS
// WAITING TO DIVERGE**, and one of them already had: the gate's state was not
// among the options at all, so the document said no credential was needed by
// an API that requires one. So the options are gathered HERE, beside the table
// they describe, and a fourth caller gets the same three facts by asking
// rather than by remembering. `tests/admin_api_document_security.js` asserts
// that every call site goes through this function.
// ---------------------------------------------------------------------------
function specOptions(req) {
  log.debug("Entering specOptions().");
  const options = {
    baseUrl: baseUrlOf(req),
    version: VERSION,
    // The one that was missing. `=== true` rather than a truthy test because
    // this becomes a claim in a published document: an unset value is the
    // setting's default, which config.js already resolves, and anything else
    // here would be this file inventing a policy.
    authRequired: config.value('adminApi.authRequired') === true
  };
  log.debug("Leaving specOptions(). authRequired=" + options.authRequired);
  return options;
}

module.exports = {
  BASE: BASE,
  // The three facts the OpenAPI document is built from, gathered in one place
  // so that this file's document and the console explorer's cannot disagree
  // about what this API requires. See specOptions().
  specOptions: specOptions,
  // The table, so that the parent project's tests can assert what this file
  // covers against what the console offers rather than against a list somebody
  // typed into a test.
  ROUTES: ROUTES,
  operationSummaries: operationSummaries
};
