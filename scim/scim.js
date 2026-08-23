'use strict';
//
// File: scim.js
//
// ---------------------------------------------------------------------------
// SCIM 2.0 — SYSTEM FOR CROSS-DOMAIN IDENTITY MANAGEMENT (RFC 7642, 7643, 7644).
//
// The fifteenth protocol family here, and the first one whose whole purpose is
// to WRITE. Every other family in this service answers a question about somebody
// who is already there — issue this person a token, tell me who signed in, seal
// this ticket. SCIM is how an identity provider PUTS somebody there in the first
// place, and what it provisions into is the embedded LDAP directory, entry for
// entry, with no store of its own.
//
// That is the whole design and it is worth stating before anything else:
//
//     POST /scim/v2/Users            ->  uid=alice,ou=users,dc=example,dc=com
//     ldapsearch -b ou=users         ->  the same entry
//     GET /admin/users?user=alice    ->  the same entry
//     an access token for alice      ->  carries that entry's attributes
//
// One store, reached four ways. A SCIM server with a Map of its own beside the
// directory would have been half the code and would have taught a provisioning
// client nothing: the interesting thing about SCIM is that what it writes is
// what everything else then reads.
//
// ---------------------------------------------------------------------------
// IT IS BUILT ON SCIMMY, WHICH IS THE SECOND npm DEPENDENCY THIS SERVICE HAS
// TAKEN ON FOR A PROTOCOL, AND THE REASONING IS THE SAME ONE THAT REFUSED
// swagger-ui-dist.
//
// What was weighed. `scimmy` 1.3.5 is 735 KB unpacked with NO runtime
// dependencies and an MIT licence, and it brings the three things that are
// genuinely hard about SCIM and boring to get right: the RFC 7643 schema
// definitions with their attribute characteristics (required, canonical values,
// mutability, returned, uniqueness) and the coercion that enforces them; the
// section 3.4.2.2 filter grammar; and the section 3.5.2 PATCH path grammar,
// which is where every hand-rolled SCIM server is subtly wrong — `emails[type eq
// "work"].value` is a path, and treating it as a property name is the defect
// that makes a provisioning client's updates land in the wrong place.
//
// Writing those by hand would have been the larger part of two thousand lines
// for a mock, and would have been wrong in exactly the places a client is trying
// to test. This is the opposite case from Swagger UI, where 11.7 MB and a
// telemetry dependency bought a familiar look for an API with no authentication.
//
// **THE ROUTES ARE THIS FILE'S AND NOT `scimmy-routers`'.** That package exists
// and would have registered the endpoints in a line, and it was not used, for
// two specific reasons rather than taste. It mounts an express Router, and
// `registeredRoutes()` in sts_metadata.js walks `app._router.stack` skipping any
// layer with no `.route` — so every SCIM endpoint would have been INVISIBLE to
// the drift check, silently, which is the one thing that page exists to prevent.
// And its constructor REQUIRES an authentication scheme and a handler — ONE of
// each, where RFC 7644 section 2 names six schemes and this service now offers
// all of them, and where the handler it wanted would have had to be a single
// function answering for a bearer token, a Digest nonce exchange and a HOBA
// signature at once. When that argument was first written the objection was
// simpler (there was no authentication at all here, so what it would have
// installed was a handler that accepted everything, dressed as a check) and the
// conclusion has only got stronger since. Registering the routes here costs
// about two hundred lines and keeps both of those honest.
//
// ---------------------------------------------------------------------------
// WHERE IT SITS IN THE REQUIRE ORDER, WHICH IS A DEPENDENCY AND NOT A
// PREFERENCE.
//
// **It must come AFTER `ldap_server.js`.** It requires that module directly, for
// the twelve functions that make ou=users and ou=groups a store, and requiring
// it from anywhere EARLIER would pull every /ldap route into the express router
// at that point — the same reason `server.js` requires ./tls_server before
// ./ldap_server. Note what this is NOT: it is not one of the five inverted hooks
// in that file. Rule 3e says a slot is what you reach for when a require would
// close a cycle or move a route, and to test a new proposal both ways round.
// This one fails that test both ways: there is no cycle (ldap_server.js knows
// nothing about SCIM) and no route moves (the /ldap routes are already
// registered by the time this file is read). So it is a plain require.
//
// It must still come BEFORE `sts_metadata.js`, which is last for everybody.
//
// ---------------------------------------------------------------------------
// WHAT IT DOES NOT DO, AND WHY EACH ONE IS DELIBERATE.
//
// **IT AUTHENTICATES, AND IT IS THE ONLY SURFACE HERE THAT DOES.** That is a
// reversal of what this file used to say and the reason for it is the sentence
// that was already here: a SCIM endpoint is the most dangerous URL an identity
// provider exposes, because it creates and DELETES accounts. So `scim_auth.js`
// offers all six schemes RFC 7644 section 2 names — OAuth 2.0 bearer and DPoP
// tokens, HTTP Basic, HTTP Digest, HOBA, the session cookie and a TLS client
// certificate — a credential is REQUIRED by default (`scim.authRequired`), and
// the OAuth ones must carry `scim:read` or `scim:write` for what they are
// about to do. That is the first scope requirement anywhere in this service.
//
// **IT IS STILL PERMISSIVE, WHICH IS A DIFFERENT SENTENCE.** Anybody can get a
// token with either scope from this service's own token endpoint, with any
// grant. Any username with any password but `invalid` passes Basic. Any
// username passes Digest with the one shared password. Anybody can register a
// HOBA key for any name. It is a turnstile rather than a lock, and what it
// makes possible is a client's 401, 403, challenge-response and scope-handling
// paths — none of which an unauthenticated endpoint can exercise at all. Do
// not put this port on a public address on the strength of it.
//
// The whole of that lives in `scim_auth.js`; what is in THIS file is one call
// in `handle()` and a `need` on each route.
//
// **`active: false` DEACTIVATES NOBODY.** It is stored on the entry as
// `scimActive` and read by nothing: no bind is refused, no token withheld, no
// session ended. This is the same distinction this service already draws about a
// group — carrying a fact is not acting on one — and it matters more here than
// anywhere else, because deprovisioning is the single most common thing a SCIM
// client is built to do, and a mock that pretended to disable an account would
// let somebody ship a deprovisioning path that has never actually worked. It is
// on /admin/scim and on GET /scim in those words.
//
// **THERE IS NO ETag AND NO `changePassword`.** Both are advertised as
// unsupported rather than half-implemented. An ETag over an entry whose
// modifyTimestamp has one-second resolution would produce a version that two
// different states share, which is worse than no concurrency control because a
// client would trust it. `changePassword` has nothing to change: no password in
// this service is checked, so there is none to set.
//
// **`/Me` IS AN ALIAS NOW, AND ITS 501 IS STILL REACHABLE.** It answered 501
// for one reason — there was never an authenticated subject — and that stopped
// being true when these endpoints started requiring a credential. So it
// resolves the caller to a directory entry and delegates to the same User
// handlers /Users/{id} uses. The 501 remains the right answer in two cases and
// is kept for both: an ANONYMOUS caller (authentication turned off) has no
// subject to alias, and POST /Me would create a subject that by definition
// already exists. A credential naming somebody with no entry — a
// client_credentials token, a client certificate — gets a 404 instead, which
// is the alias resolving to nothing rather than the alias being unavailable.
//
// **THE DISCOVERY ENDPOINTS ARE OPEN.** /ServiceProviderConfig, /ResourceTypes
// and /Schemas answer without a credential unless `scim.authDiscovery` says
// otherwise, which is the bootstrapping argument POST /tls/trust already makes:
// the ServiceProviderConfig is where a client READS which schemes exist, so
// demanding a credential to fetch it means a client must already know the
// answer to the question it is asking. RFC 7644 section 4 says nothing either
// way, so both are conforming and the other one is a setting away.
//
// **ONE userName IS REFUSED.** `invalid`, exactly as one password is refused on
// the password grant, on WS-Trust, at the WS-Federation sign-in screen and at
// every LDAP bind. A SCIM client's error handling is built around `scimType`
// codes it can be hard to provoke from a permissive server, so creating a user
// with that name answers 400 `invalidValue` and creating a second user with a
// userName somebody already has answers 409 `uniqueness`. Those two, plus the
// 404 a missing id gives and the 400 `invalidFilter` a bad filter gives, are
// most of what a client's error paths need.
//
// ---------------------------------------------------------------------------
// A CREATE IS THE DIRECTORY'S DOOR, NOT THIS MODULE'S.
//
// SCIM is the FOURTH way a person can be put in `ou=users` — after an
// `ldapadd`, the console's form and `POST /admin-api/users/create` — and the
// last two already share `createUser()` in `ldap_server.js` so that "creating a
// user" cannot come to mean two things. This module calls the SAME function,
// and what it keeps for itself is only the translation: that function returns
// errors for a person to read on a web page, and a SCIM client needs a status
// and a `scimType`. Same split `oauth2_bcp.js` has with `oauth2.js` — one
// decides, the other says it in its own protocol.
//
// What comes with that door and did not come with the one this module used to
// have: `namePlan()`'s FOLD (a name lands on the entry that is already this
// person's under a different naming attribute, rather than beside it),
// `existingUserEntry()`'s uniqueness (which matches the RDN value as well as
// `uid`, so somebody whose entry a client certificate named is not created
// twice), and the refusals of a DN-shaped name, a DID-shaped name and RFC
// 4514's reserved characters. Each of those was a rule this module had a weaker
// version of, and the weakest was the uniqueness scan: it compared `uid` only,
// so the one case the fold exists for was invisible to it.
//
// A GROUP has no such door — nothing but an `ldapadd` and this creates one — so
// `writeGroupEntry()` is called directly. The name CHECK is still shared
// (`nameUsableInDn()`), because three copies of that regex would be three doors
// that eventually disagree about whether `a+b` is a name.
// ---------------------------------------------------------------------------

const SCIMMY = require('scimmy');

const app = require('../common/app');
const { log, xmlEscape, baseUrlOf } = require('../common/helpers');
const config = require('../common/config');
const stats = require('../common/admin_stats');
const audit = require('../common/audit');
const directory = require('../ldap/ldap_server');
// WHO IS ASKING. A library like scim_map.js — it registers nothing and never
// touches `res`; it decides and this module answers, which is the same split
// oauth2_bcp.js has with oauth2.js. Everything about the six schemes RFC 7644
// section 2 names lives there, including the table that builds the
// WWW-Authenticate challenge and this document's authenticationSchemes.
const scimAuth = require('./scim_auth');
// The console, for its reader slot only — see the bottom of this file. Requiring
// it moves nothing: server.js requires ./admin long before ./scim, so node
// already has it in hand.
const adminConsole = require('../admin-ui/admin');
const scimMap = require('./scim_map');

// The base path. NOT a setting: it is baked into every `meta.location` and every
// Location header, a client stores those, and a base path that could move at
// runtime would leave a provisioning client holding URLs that stopped resolving
// with nothing to point at. `/scim/v2` is what every implementation uses.
const BASE = '/scim/v2';

// The one refused name, beside the one refused password. See the header.
const REFUSED_USERNAME = 'invalid';

function enabled() {
  return config.value('scim.enabled') !== false;
}

function maxResults() {
  return config.value('scim.maxResults');
}

function bulkMaxOperations() {
  return config.value('scim.bulkMaxOperations');
}

function bulkMaxPayloadSize() {
  return config.value('scim.bulkMaxPayloadSize');
}

// ---------------------------------------------------------------------------
// WHAT THIS SERVER SAYS IT CAN DO.
//
// SCIMMY.Config is what builds the ServiceProviderConfig document, and it is the
// ONE place those capabilities are stated — the handlers below carry no second
// opinion about whether filtering works. Same arrangement
// `authorization_servers.js` has for the OAuth metadata and there for the same
// reason: a document that IS the server cannot drift from it.
//
// **IT IS APPLIED TWICE AND THAT IS WHAT KEEPS THREE SETTINGS RUNTIME.** Once
// here, so the capabilities are right before the first request arrives, and
// again at the top of the ServiceProviderConfig handler, so that a change made
// at /admin/config reaches the published document. Without the second call
// `scim.maxResults` would be enforced live (queryParams() reads it per request,
// which is the rule for a runtime setting) while the document went on
// advertising the number this process started with — a captured `const` in
// disguise, and the exact silent disagreement config.js's header warns about.
//
// It is one FUNCTION called twice rather than two `set()` calls, because two
// would be two doors to one set of capabilities, which is the mistake rule 5
// exists for in miniature.
// ---------------------------------------------------------------------------
function applyCapabilities(base) {
  log.debug("Entering applyCapabilities(). base=" + (base || '(none yet)'));
  SCIMMY.Config.set({
    patch: true,
    bulk: { supported: true, maxOperations: bulkMaxOperations(),
            maxPayloadSize: bulkMaxPayloadSize() },
    filter: { supported: true, maxResults: maxResults() },
    changePassword: false,
    sort: true,
    etag: false
  });
  // -------------------------------------------------------------------------
  // THE SCHEMES, AND THE RESET IN FRONT OF THEM WHICH IS NOT OPTIONAL.
  //
  // `authenticationSchemes` is the one configuration property scimmy treats as
  // CUMULATIVE: `set` PUSHES onto the array, and only an empty value clears it.
  // This function is deliberately called more than once — at require time and
  // again at the top of the ServiceProviderConfig handler, so that a scheme
  // turned off at /admin/config disappears from the published document — so
  // without the reset the array would grow by four every time somebody read
  // the document, and a client would be handed the same scheme fourteen times
  // with nothing in the code looking wrong.
  //
  // Only the CANONICAL-TYPED schemes go through here; the other three are
  // appended to the serialised document by the handler below. The reason is
  // scimmy's, and it is a correct reading of RFC 7643 rather than a defect —
  // see schemesForConfig() in scim_auth.js.
  // -------------------------------------------------------------------------
  SCIMMY.Config.set('authenticationSchemes', []);
  const schemes = scimAuth.schemesForConfig(base || '');
  if (schemes.length) {
    SCIMMY.Config.set('authenticationSchemes', schemes);
  }
  log.debug("Leaving applyCapabilities(). " + schemes.length + " canonical scheme(s).");
}

applyCapabilities();

// ---------------------------------------------------------------------------
// The location prefix for `meta.location` and the Location header.
//
// Built from the request the way every other URL in this service is — through
// baseUrlOf(), which honours a forwarded header only when global.trustProxy says
// to. Do not pin a scheme or a host here: this service answers correctly as
// localhost, as `sts` on a compose network and through a published port because
// nothing in it is told which, and a SCIM `meta.location` pointing at the wrong
// one is a URL a provisioning client will store and keep using.
// ---------------------------------------------------------------------------
function locationPrefix(req, type) {
  return baseUrlOf(req) + BASE + '/' + type + '/';
}

// ---------------------------------------------------------------------------
// A SCIM ERROR, WHICH IS THE ONE THING A MOCK MUST GET EXACTLY RIGHT.
//
// RFC 7644 section 3.12: a JSON object with the Error schema URN, the HTTP
// status AS A STRING, and an optional `scimType` from a closed list. The status
// being a string is the detail everybody gets wrong and every client checks.
//
// It is built through SCIMMY.Messages.ErrorResponse rather than by hand so that
// the shape comes from the same library that produced the error, and the
// counting happens HERE — one place, at the moment an answer goes out — rather
// than at each handler, which is the reasoning that keeps signJwt() the single
// token counter.
// ---------------------------------------------------------------------------
function sendScimError(req, res, info, ex) {
  log.debug("Entering sendScimError(). status=" + (ex && ex.status));
  const error = (ex instanceof SCIMMY.Types.Error) ? ex
    : new SCIMMY.Types.Error(500, null, String((ex && ex.message) || ex));
  const body = new SCIMMY.Messages.ErrorResponse(error);
  stats.recordScim({ operation: info.operation, resourceType: info.resourceType,
                     status: error.status, ok: false, scimType: error.scimType,
                     // Which scheme got this far. A refusal from the
                     // authentication gate has none by definition, and is
                     // counted as `refused` rather than being attributed to
                     // whatever the caller attempted — the status and scimType
                     // tables beside it already say what happened.
                     authScheme: (req.scimAuth && req.scimAuth.ok &&
                                  req.scimAuth.scheme) || 'refused' });
  // end() rather than send() — see the note on sendScim().
  res.status(error.status)
     .type('application/scim+json')
     .set('Cache-Control', 'no-store')
     .end(JSON.stringify(body, null, 2));
  log.debug("Leaving sendScimError(). " + error.status + " " +
            (error.scimType || '(no scimType)') + ": " + error.message);
}

// ---------------------------------------------------------------------------
// A SUCCESSFUL SCIM ANSWER.
//
// `res.end()` rather than `res.send()`, and that is not a micro-optimisation:
// express computes a weak ETag for every `send()` body, and this server
// ADVERTISES `etag: {supported: false}` in its ServiceProviderConfig. A document
// that says there is no version control, on responses carrying a version, is
// exactly the drift building the document out of SCIMMY.Config was meant to
// prevent — and a client that noticed the header and started sending `If-Match`
// would get its precondition ignored, which is the worst of the three possible
// behaviours. `app.set('etag', false)` would have fixed it too and would have
// turned the header off for the whole service, which is not this module's call
// to make.
// ---------------------------------------------------------------------------
function sendScim(req, res, info, status, body, location) {
  log.debug("Entering sendScim(). status=" + status);
  stats.recordScim({ operation: info.operation, resourceType: info.resourceType,
                     status: status, ok: true, scimType: '',
                     authScheme: (req.scimAuth && req.scimAuth.scheme) || 'anonymous' });
  if (location) {
    res.set('Location', location);
  }
  res.status(status)
     .type('application/scim+json')
     .set('Cache-Control', 'no-store')
     .end(body === undefined ? '' : JSON.stringify(body, null, 2));
  log.debug("Leaving sendScim(). " + status + ".");
}

// ---------------------------------------------------------------------------
// THE WRAPPER EVERY HANDLER GOES THROUGH.
//
// Three things happen here and each would otherwise be repeated seventeen times,
// which is how one of them comes to be missing from the eighteenth:
//
//   * the OFF switch. `scim.enabled` is checked once, at the top, and answers
//     501 rather than 404 — the routes exist, the feature is turned off, and
//     those are different sentences to a client trying to work out whether it
//     has the wrong URL.
//   * the error funnel. Anything a handler throws becomes a proper SCIM error
//     response. That matters more than it looks with scimmy in the stack:
//     Resource#read() and #write() CATCH anything that is not a Types.Error and
//     re-throw it as a 404 "Resource not found", so an ordinary programming
//     mistake inside an egress handler surfaces to the client as a missing user.
//     Logging the original here is what makes that findable.
//   * the counting, which happens in the two senders above.
//   * AUTHENTICATION, added last and belonging here for exactly the reason the
//     other three do. Every SCIM route goes through this function, so this is
//     one gate and not eighteen — and the eighteenth is the one that would have
//     been missed. `info.need` says what the operation costs: 'read', 'write',
//     or 'none' for the discovery endpoints, which are open unless
//     `scim.authDiscovery` says otherwise.
//
// The ORDER of the first two matters. The OFF switch answers before the gate,
// so that a service with SCIM turned off says so rather than demanding a
// credential for an endpoint that would refuse it anyway — "the feature is off"
// and "you are not authenticated" send somebody to two different places.
// ---------------------------------------------------------------------------
function handle(info, fn) {
  return function (req, res) {
    log.debug("Entering the SCIM " + info.operation + " handler for " + info.resourceType + ".");
    if (!enabled()) {
      sendScimError(req, res, info, new SCIMMY.Types.Error(501, null,
        'SCIM is turned off on this service (scim.enabled). The routes are ' +
        'registered, which is why this is a 501 and not a 404. Turn it back on ' +
        'at /admin/config or with SCIM_ENABLED=true.'));
      log.debug("Leaving the SCIM handler. It is turned off.");
      return;
    }

    // WHO IS ASKING. scim_auth.js decides and never touches `res`; the answer
    // is turned into SCIM's own error shape here, because what a refusal LOOKS
    // like is protocol knowledge and stays in the protocol module. The headers
    // it hands back are set either way: on a refusal they are the
    // WWW-Authenticate challenges RFC 7644 section 2 makes a SHALL (and, in the
    // DPoP nonce handshake, the DPoP-Nonce a wallet needs to retry), and on
    // success they can be the RFC 7616 Authentication-Info that lets a client
    // authenticate this server back.
    const decision = scimAuth.authenticate(req, info.need || 'none');
    Object.keys(decision.headers || {}).forEach(function (name) {
      res.set(name, decision.headers[name]);
    });
    // Stashed on the request rather than passed down: the handlers below build
    // their own info objects at each call site, and threading a fifth argument
    // through all of them is how one of them comes to be missing it. It is read
    // by the two senders (for the per-scheme counters), by auditScim() (for the
    // actor) and by /Me (for the subject).
    req.scimAuth = decision;
    if (!decision.ok) {
      sendScimError(req, res, info,
        new SCIMMY.Types.Error(decision.status, decision.scimType, decision.detail));
      log.debug("Leaving the SCIM handler. The caller was refused with " + decision.status + ".");
      return;
    }

    Promise.resolve()
      .then(function () { return fn(req, res); })
      .catch(function (ex) {
        if (!(ex instanceof SCIMMY.Types.Error)) {
          // Logged whole, because scimmy will already have flattened anything
          // that reached it into a 404 and the real message is the only way to
          // tell a genuine "no such user" from a defect in this file.
          log.error('scim: the ' + info.operation + ' handler for ' +
                    info.resourceType + ' threw: ' + (ex && ex.stack ? ex.stack : ex));
        }
        sendScimError(req, res, info, ex);
      });
    log.debug("Leaving the SCIM handler (the answer is on its way).");
  };
}

// The request body, as SCIM sends it. app.js parses every body as TEXT (one
// bodyParser for the whole service), and `application/scim+json` is not
// `application/json` — so helpers.parseBody() would fall through to its
// form-encoded branch and hand back an object with one very long key. Parsed
// here, and a body that is not JSON is `invalidSyntax` rather than an empty
// object silently failing a required-attribute check three frames later.
function scimBody(req) {
  log.debug("Entering scimBody(). content-type=" + (req.headers['content-type'] || '(none)'));
  const raw = typeof req.body === 'string' ? req.body : '';
  if (!raw.trim()) {
    log.debug("Leaving scimBody(). There was no body.");
    return undefined;
  }
  try {
    const parsed = JSON.parse(raw);
    log.debug("Leaving scimBody(). Parsed " + raw.length + " byte(s).");
    return parsed;
  } catch (e) {
    log.debug("Leaving scimBody(). It was not JSON.");
    throw new SCIMMY.Types.Error(400, 'invalidSyntax',
      'The request body is not JSON: ' + e.message);
  }
}

// ---------------------------------------------------------------------------
// THE QUERY PARAMETERS, TURNED INTO WHAT scimmy'S RESOURCE CONSTRUCTOR WANTS.
//
// One conversion matters and is easy to miss: `startIndex` and `count` arrive
// off a query string as STRINGS, and that constructor tests them with
// Number.isInteger() — so `?count=5` is silently DROPPED and the client gets the
// default page size while believing it asked for five. Parsed here, and a value
// that is not a number is refused rather than ignored, because a client that
// asked for a page size and got a different one has no way to find out.
//
// `count` is also clamped to `scim.maxResults`, which is what the
// ServiceProviderConfig advertises as `filter.maxResults`. RFC 7644 section
// 3.4.2.4 permits exactly this and requires the response to say what actually
// happened, which the ListResponse's `itemsPerPage` does.
// ---------------------------------------------------------------------------
function queryParams(req) {
  log.debug("Entering queryParams().");
  const query = req.query || {};
  const params = {};
  ['filter', 'attributes', 'excludedAttributes', 'sortBy', 'sortOrder'].forEach(function (name) {
    const raw = query[name];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (value !== undefined && String(value) !== '') {
      params[name] = String(value);
    }
  });
  ['startIndex', 'count'].forEach(function (name) {
    const raw = query[name];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (value === undefined || String(value) === '') {
      return;
    }
    const parsed = Number(value);
    if (!Number.isInteger(parsed)) {
      throw new SCIMMY.Types.Error(400, 'invalidValue',
        'Expected ' + name + ' to be an integer; got "' + String(value) + '".');
    }
    params[name] = parsed;
  });
  if (params.count === undefined || params.count > maxResults()) {
    params.count = maxResults();
  }
  log.debug("Leaving queryParams(). " + Object.keys(params).length + " parameter(s).");
  return params;
}

// The URN a SearchRequest body must carry (section 3.4.3), written once.
const SEARCH_REQUEST_URN = 'urn:ietf:params:scim:api:messages:2.0:SearchRequest';

// A SearchRequest body (section 3.4.3) carries the same members in JSON. Same
// clamp, same integer rule — and the same function shape, so the two doors to
// one query cannot drift.
//
// ONE CONVERSION IS NOT COSMETIC. In a SearchRequest body `attributes` and
// `excludedAttributes` are MULTI-VALUED — a JSON array — while on a query string
// they are one comma-separated string, and scimmy's Resource constructor wants
// the query-string spelling. `String(["a","b"])` is `"a,b"`, which is exactly
// right, and that is why this is written as a String() rather than left to
// happen: an array reaching that constructor unconverted is `["a","b"] pr` in a
// filter, which parses as nothing and silently returns every attribute.
function searchParams(body) {
  log.debug("Entering searchParams().");
  const source = body || {};
  const params = {};
  ['filter', 'attributes', 'excludedAttributes', 'sortBy', 'sortOrder'].forEach(function (name) {
    if (source[name] !== undefined && String(source[name]) !== '') {
      params[name] = String(source[name]);
    }
  });
  ['startIndex', 'count'].forEach(function (name) {
    if (source[name] === undefined) {
      return;
    }
    const parsed = Number(source[name]);
    if (!Number.isInteger(parsed)) {
      throw new SCIMMY.Types.Error(400, 'invalidValue',
        'Expected ' + name + ' to be an integer; got "' + String(source[name]) + '".');
    }
    params[name] = parsed;
  });
  if (params.count === undefined || params.count > maxResults()) {
    params.count = maxResults();
  }
  log.debug("Leaving searchParams(). " + Object.keys(params).length + " parameter(s).");
  return params;
}

// ---------------------------------------------------------------------------
// FILTERING, WHICH IS DONE HERE AND NOT BY scimmy — AND A DEFECT IT ROUTES
// AROUND.
//
// `Resource#read()` does NOT apply the filter it parsed. It parses it, hands the
// resource instance (carrying `.filter`) to the egress handler and wraps
// whatever comes back — so a handler that ignores `.filter` returns everybody
// for every query, which looks like a working server right up until somebody
// filters. The sort and the pagination ARE applied for us, by ListResponse.
//
// **THE DEFECT.** `SCIMMY.Types.Filter#match()` in scimmy 1.3.5 handles a nested
// attribute by diving into it — `new Filter([expressions]).match([actual])` —
// without first checking that `actual` is there. When it is not, the recursive
// call reaches `Object.entries(undefined)` and THROWS. So a filter naming any
// sub-attribute (`emails.value co "@example.com"`, `name.familyName sw "Sm"`)
// blows up on the first resource that lacks that member, which in a directory is
// the ordinary case and not an edge one. The exception surfaces as a 400
// `invalidValue` saying "Cannot convert undefined or null to object", which
// points at nothing.
//
// It is routed around in `scim_map.js`'s toScimUser(), which pads every
// multi-valued and complex member so that the value is always at least an empty
// array or object, and `prune()` takes the padding off before the resource goes
// on the wire. That is the same kind of workaround `toSearchEntry()` uses for
// ldapjs's SearchResponse.send(), and it is documented in both places for the
// same reason: it is two lines that look like a stylistic choice.
//
// The try/catch here is the belt to that braces. A filter this service cannot
// evaluate is refused as `invalidFilter` — an honest answer a client can act on
// — rather than surfacing as a 500 or, worse, as an empty list that reads as "no
// such user".
// ---------------------------------------------------------------------------
function applyFilter(filter, values) {
  log.debug("Entering applyFilter(). " + values.length + " candidate(s).");
  if (!filter) {
    log.debug("Leaving applyFilter(). There was no filter.");
    return values;
  }
  try {
    const matched = filter.match(values);
    log.debug("Leaving applyFilter(). " + matched.length + " matched.");
    return matched;
  } catch (ex) {
    log.warn('scim: a filter could not be evaluated (' + ex.message + '). ' +
             'This is refused rather than answered with an empty list, because ' +
             '"no results" and "I could not read your filter" are different ' +
             'answers and a client can only act on the second.');
    throw new SCIMMY.Types.Error(400, 'invalidFilter',
      'This filter could not be evaluated against the resources here: ' + ex.message);
  }
}

// ---------------------------------------------------------------------------
// THE USER RESOURCE.
//
// The three handlers are the whole of the persistence layer. Everything above
// them — the schema, the coercion, the filter grammar, PATCH, the ListResponse —
// is scimmy's; everything below them is ldap_server.js's; and this is the
// boundary, which is why it is short.
// ---------------------------------------------------------------------------

// The groups a person is in, in the shape scim_map.js wants. Read through the
// SAME function the groups claim reads (`groupsOfUser()`), so a SCIM resource
// and an access token cannot disagree about who is in what — which they would
// within a week if this walked the tree itself.
function groupsOf(dn) {
  const answer = directory.groupsOfUser(dn);
  return (answer.groups || []).map(function (group) {
    return { dn: group.dn, cn: group.cn };
  });
}

function userResourceFor(entry, req) {
  return scimMap.toScimUser(entry, {
    groups: groupsOf(entry.dn),
    location: locationPrefix(req, 'Users'),
    // WHAT THIS PERSON IS CALLED WHEN THEIR ENTRY HAS NO `uid` — which is an
    // ordinary entry here and not a broken one, since a client certificate's
    // is named `cn=<CN>,ou=users` and carries none. Read through the
    // directory's own function rather than parsed out of the DN here, for the
    // reason normalizeDn() is exported: a second reading of a DN in this
    // module would eventually disagree with the one existingUserEntry()
    // matches a name against. What is DONE with it is scim_map.js's decision
    // and the whole of it is in toScimUser().
    rdnName: directory.usernameOfEntry(entry)
  });
}

// EXTENDED WITH THE ENTERPRISE USER SCHEMA (RFC 7643 section 4.3), and the
// extension has to be DECLARED rather than merely mapped. scim_map.js has
// carried employeeNumber, department, organization, division and manager since
// SCIM arrived here, but an attribute scimmy's schema definition does not know
// about is dropped by its coercion in both directions — so those five went out
// of a POST and came back as nothing, and /Schemas listed two documents while
// this service claimed three. Declaring it puts the URN in /Schemas and in the
// User resource type's schemaExtensions, and makes the namespaced member on the
// wire the one the mapping writes.
//
// `required` is left false: RFC 7643 section 4.3 defines the extension, and a
// User carrying none of it is an ordinary User rather than an invalid one.
SCIMMY.Resources.declare(SCIMMY.Resources.User)
  .extend(SCIMMY.Schemas.EnterpriseUser)
  .egress(function (resource, ctx) {
    log.debug("Entering the SCIM User egress handler. id=" + (resource.id || '(a list)'));
    const req = (ctx || {}).req;
    if (resource.id) {
      const entry = directory.readPerson(resource.id);
      if (!entry) {
        // Thrown as a Types.Error rather than returned as null, because
        // Resource#read() turns a null into "Unexpected empty value returned by
        // egress handler" — a 500 — where this is a perfectly ordinary 404.
        throw new SCIMMY.Types.Error(404, null,
          'There is no entry at ' + resource.id + ' under ' + directory.USERS_DN + '.');
      }
      log.debug("Leaving the SCIM User egress handler. One resource.");
      return userResourceFor(entry, req);
    }
    const all = directory.allPersons().map(function (entry) {
      return userResourceFor(entry, req);
    });
    const matched = applyFilter(resource.filter, all);
    log.debug("Leaving the SCIM User egress handler. " + matched.length +
              " of " + all.length + " resource(s).");
    // Pruned only now: the padding exists for the matcher and this is where it
    // stops being useful. See scim_map.js's toScimUser().
    return matched.map(scimMap.prune);
  })
  .ingress(function (resource, data, ctx) {
    log.debug("Entering the SCIM User ingress handler. id=" + (resource.id || '(a create)'));
    const req = (ctx || {}).req;

    // TRIMMED ONCE, AND WRITTEN BACK ONTO THE RESOURCE, which is the whole point
    // of doing it here rather than in three places. The name is read three
    // times — to build the DN, to check uniqueness, and to become the `uid`
    // attribute — and trimming it for the first two and not the third produced
    // an entry whose DN said `uid=lead` while its `uid` attribute held
    // `" lead"`. That is one name with two spellings in one entry: the DN a
    // client is handed as its id does not name what the entry says it is,
    // `existingUserEntry()` finds it by one and not the other, and the
    // uniqueness check below stops matching, so the same person can be created
    // twice.
    const userName = String(data.userName || '').trim();
    if (data.userName !== undefined) {
      data.userName = userName;
    }

    if (userName.toLowerCase() === REFUSED_USERNAME) {
      // The reachable negative. See the header: a SCIM client's error handling
      // is built around scimType codes that a permissive server never produces.
      throw new SCIMMY.Types.Error(400, 'invalidValue',
        'The userName "' + REFUSED_USERNAME + '" is refused on purpose, so that ' +
        'a negative test has something to fail on — the same reserved value the ' +
        'password grant, WS-Trust, the WS-Federation sign-in screen and every ' +
        'LDAP bind here refuse. Nothing else about this request was wrong.');
    }

    const existing = resource.id ? directory.readPerson(resource.id) : null;
    if (resource.id && !existing) {
      throw new SCIMMY.Types.Error(404, null,
        'There is no entry at ' + resource.id + ' under ' + directory.USERS_DN + '.');
    }

    // -----------------------------------------------------------------------
    // A CREATE GOES THROUGH `createUser()`, WHICH IS THE DIRECTORY'S OWN DOOR,
    // AND THIS IS THE ONE THING IN THIS FILE MOST WORTH NOT UNDOING.
    //
    // SCIM is the FOURTH way a person can be put in this directory — after an
    // `ldapadd`, the console's form and POST /admin-api/users/create — and the
    // last three already share one function so that "creating a user" cannot
    // come to mean three things. This one used to build its own DN, run its own
    // uniqueness scan and apply its own name-syntax rule, and each of the three
    // was subtly weaker:
    //
    //   * THE DN. createUser() applies namePlan(), which FOLDS a new name onto
    //     an entry that is already this person's under a different naming
    //     attribute — a client certificate's `cn=rcbj,ou=users`, say. Building
    //     `uid=rcbj,ou=users` directly would have created a second object for
    //     one person, which is precisely what that fold exists to prevent.
    //   * UNIQUENESS. createUser() asks existingUserEntry(), which matches on
    //     the `uid` attribute AND on the RDN value. The scan here compared only
    //     `uid`, so a person whose entry a certificate had named by `cn` was
    //     invisible to it and SCIM would happily create them a second time —
    //     the "one entry per person at every door" rule broken at the newest
    //     door.
    //   * THE NAME. Both refused RFC 4514's reserved characters and the two
    //     lists had already drifted by one (`#` anywhere, versus only leading).
    //     There is now one regex, `nameUsableInDn()`, and all three doors read
    //     it.
    //
    // What SCIM keeps for itself is the ANSWER SHAPE: createUser() returns
    // errors for a human to read on a web page, and a SCIM client needs a
    // status and a `scimType`. That translation is this module's job and stays
    // here, which is the same split oauth2_bcp.js has with oauth2.js — one
    // decides, the other says it in its own protocol.
    // -----------------------------------------------------------------------
    let dn;
    if (existing) {
      // An update keeps the DN it has. A SCIM id IS the DN, so moving the entry
      // would change the id underneath a client that is holding it, and a
      // rename is an LDAP modrdn rather than a PUT.
      dn = existing.dn;

      // UNIQUENESS on an update, which createUser() cannot answer because
      // nothing is being created. The same lookup it uses, so both doors agree
      // about what "taken" means — and compared by DN, so that leaving somebody's
      // userName as it was is not a conflict with themselves.
      const clash = directory.existingUserEntry(userName);
      if (clash && directory.normalizeDn(clash.dn) !== directory.normalizeDn(existing.dn)) {
        throw new SCIMMY.Types.Error(409, 'uniqueness',
          'There is already a user called "' + userName + '" here, at ' + clash.dn +
          '. RFC 7643 section 4.1.1 makes userName unique, and this directory ' +
          'keeps one entry per person at every door.');
      }
    } else {
      const made = directory.createUser(userName, {
        origin: 'scim',
        channel: 'http',
        protocol: 'SCIM',
        // WHO provisioned them. It used to be blank, because nothing at these
        // endpoints authenticated and audit.js's actor resolver reads the
        // browser session — which a provisioning client does not have. Now
        // there is a credential, so the row can say whose act this was; it is
        // passed rather than resolved because only this request knows.
        actor: (req && req.scimAuth && req.scimAuth.principal) || '',
        note: 'provisioned over SCIM 2.0' +
              ((req && req.scimAuth && req.scimAuth.scheme &&
                req.scimAuth.scheme !== 'anonymous')
                ? ' (' + req.scimAuth.scheme + ')' : '')
      });
      if (!made.ok) {
        // `existing` on the refusal is how createUser() reports a name that is
        // taken, and it is the only one of its refusals that is a 409 rather
        // than a 400 — a client retries a conflict differently from the way it
        // retries a bad value.
        throw new SCIMMY.Types.Error(made.existing ? 409 : 400,
          made.existing ? 'uniqueness' : 'invalidValue',
          (made.errors || []).join(' '));
      }
      dn = made.dn;
    }

    // Read back rather than reusing what came in, because on a create the entry
    // createUser() just wrote is what the SCIM attributes are merged OVER —
    // objectClass, the description saying where it came from, and the invented
    // persona values it filled. The window rule then does the rest: what SCIM
    // sent replaces what it maps, and everything else stays.
    const before = directory.readPerson(dn);
    const converted = scimMap.fromScimUser(data, before ? before.attributes : {});
    if (converted.errors.length) {
      throw new SCIMMY.Types.Error(400, 'invalidValue', converted.errors.join(' '));
    }

    const written = directory.writePerson(dn, converted.attributes);
    if (!written.ok) {
      throw new SCIMMY.Types.Error(written.reason === 'full' ? 507 : 400,
        written.reason === 'full' ? null : 'invalidValue',
        written.reason === 'full'
          ? 'The directory holds its maximum of ' + directory.maxEntries() +
            ' entries (ldap.maxEntries). Nothing was written.'
          : 'The entry could not be written at ' + dn + ' (' + written.reason + ').');
    }

    // The credential-claim sweep. createUser() already ran applyVcAttributes()
    // on the entry it made — but the write just above REPLACED the attribute
    // set with SCIM's window merged over it, so a mapped attribute the client
    // did not send (a `street` the persona had invented, say) is gone again.
    // This puts back only what is ABSENT, so nothing the SCIM client sent is
    // touched, and /admin/vc's selection reaches a provisioned person exactly as
    // it reaches one who signed in.
    if (!existing) {
      directory.populateVcAttributes();
    }

    // ONLY THE UPDATE IS RECORDED HERE. createUser() writes its own
    // `user.create` row — naming SCIM, because it now takes a protocol — and a
    // second row from this module would be one act counted twice at the SAME
    // layer, which is the double-recording rule 3c warns about. The HTTP call
    // is a different layer and is recorded by app.js either way.
    if (existing) {
      auditScim('user.update', dn, converted.attributes, req);
    }

    const entry = directory.readPerson(dn);
    log.debug("Leaving the SCIM User ingress handler. The entry was " +
              (written.created ? 'created.' : 'updated.'));
    return scimMap.prune(userResourceFor(entry, req));
  })
  .degress(function (resource, ctx) {
    log.debug("Entering the SCIM User degress handler. id=" + resource.id);
    const removed = directory.deletePerson(resource.id);
    if (!removed.ok) {
      throw new SCIMMY.Types.Error(removed.reason === 'notLeaf' ? 400 : 404,
        removed.reason === 'notLeaf' ? 'invalidValue' : null,
        removed.reason === 'notLeaf'
          ? 'The entry at ' + resource.id + ' has children, and this directory ' +
            'refuses a delete of anything that is not a leaf (RFC 4511 section ' +
            '4.8). Delete what is under it first.'
          : 'There is no entry at ' + resource.id + ' under ' + directory.USERS_DN + '.');
    }
    // The dangling memberships this delete just created, logged rather than
    // repaired: referential integrity is a directory feature and not a protocol
    // rule, and /admin/groups exists to report exactly this. A SCIM client that
    // means to remove somebody from their groups has to say so.
    if ((removed.dangling || []).length) {
      log.info('scim: ' + resource.id + ' was deleted and is still listed as a ' +
               'member by ' + removed.dangling.length + ' group(s). This ' +
               'directory does no referential integrity on purpose; ' +
               '/admin/groups reports them as dangling members.');
    }
    auditScim('user.delete', resource.id, {}, (ctx || {}).req);
    log.debug("Leaving the SCIM User degress handler.");
  });

// ---------------------------------------------------------------------------
// THE GROUP RESOURCE.
//
// Shorter than the user's and with one thing that is not obvious: what comes
// back from GET /Groups is every group by BOTH of ldap_server.js's rules — under
// ou=groups, OR carrying a group objectClass wherever it sits. So a group a
// client added under ou=people IS a SCIM Group here. That is not a leak: it is
// this service having exactly one answer to "what is a group", which the console
// and the groups claim already use, and a SCIM view with a third opinion would
// be the second definition that eventually disagrees.
// ---------------------------------------------------------------------------
function groupResourceFor(entry, req) {
  return scimMap.toScimGroup(entry, {
    members: entry.members || [],
    location: locationPrefix(req, 'Groups')
  });
}

SCIMMY.Resources.declare(SCIMMY.Resources.Group)
  .egress(function (resource, ctx) {
    log.debug("Entering the SCIM Group egress handler. id=" + (resource.id || '(a list)'));
    const req = (ctx || {}).req;
    if (resource.id) {
      const entry = directory.readGroupEntry(resource.id);
      if (!entry) {
        throw new SCIMMY.Types.Error(404, null,
          'There is no group at ' + resource.id + '. An entry that exists and is ' +
          'not a group answers the same way: it is not a Group resource either.');
      }
      log.debug("Leaving the SCIM Group egress handler. One resource.");
      return groupResourceFor(entry, req);
    }
    const all = directory.allGroupEntries().map(function (entry) {
      return groupResourceFor(entry, req);
    });
    const matched = applyFilter(resource.filter, all);
    log.debug("Leaving the SCIM Group egress handler. " + matched.length +
              " of " + all.length + " group(s).");
    return matched.map(scimMap.prune);
  })
  .ingress(function (resource, data, ctx) {
    log.debug("Entering the SCIM Group ingress handler. id=" + (resource.id || '(a create)'));
    const req = (ctx || {}).req;
    // Trimmed and written back for the reason the User handler's userName is:
    // this becomes both the RDN value and the `cn` attribute, and trimming one
    // of the two is one group with two names.
    const displayName = String(data.displayName || '').trim();
    if (data.displayName !== undefined) {
      data.displayName = displayName;
    }
    const existing = resource.id ? directory.readGroupEntry(resource.id) : null;
    if (resource.id && !existing) {
      throw new SCIMMY.Types.Error(404, null, 'There is no group at ' + resource.id + '.');
    }

    const converted = scimMap.fromScimGroup(data, existing ? existing.attributes : {});
    if (converted.errors.length) {
      throw new SCIMMY.Types.Error(400, 'invalidValue', converted.errors.join(' '));
    }

    // The same DN-syntax rule createUser() applies to a username, read from the
    // one place it is written (see nameUsableInDn() in ldap_server.js). A group
    // has no createUser() of its own to defer to — nothing but an `ldapadd` and
    // this creates one — so the CHECK is shared even though the door is not.
    // Only on a create: an update keeps the DN it has, so a displayName that
    // could not have been an RDN moves nothing, and refusing it would make a
    // group an `ldapadd` put there with an awkward name un-editable over SCIM.
    if (!existing && !directory.nameUsableInDn(displayName)) {
      throw new SCIMMY.Types.Error(400, 'invalidValue',
        'This displayName carries a character RFC 4514 section 2.4 reserves in ' +
        'a DN (one of , = + < > # ; " \\). The SCIM id of a group here IS its ' +
        'entry\'s DN, so such a name would produce a group that cannot be read ' +
        'back. Refused rather than escaped, for the reason createUser() refuses ' +
        'the same characters in a username: an `ldapadd` can still create it, ' +
        'with the escaping written out by the client.');
    }

    const dn = existing ? existing.dn : directory.groupDnFor(displayName);
    if (!existing && directory.readGroupEntry(dn)) {
      throw new SCIMMY.Types.Error(409, 'uniqueness',
        'There is already a group at ' + dn + '.');
    }

    // A MEMBER THAT NAMES NOTHING IS NOT REFUSED, and that is deliberate rather
    // than an omission. This directory does no referential integrity — a delete
    // leaves the DN behind in every group that listed it — so refusing a member
    // here would make it impossible to reproduce the dangling-member state that
    // /admin/groups exists to report, and would be this service enforcing in one
    // direction what it explicitly does not enforce in the other. Logged, so it
    // is visible rather than silent.
    (converted.attributes.member || []).forEach(function (value) {
      if (!directory.readPerson(value) && !directory.readGroupEntry(value)) {
        log.info('scim: ' + dn + ' lists ' + value + ' as a member and nothing ' +
                 'is stored there. It is written anyway — this directory does ' +
                 'no referential integrity, and a dangling member is a state ' +
                 'worth being able to produce.');
      }
    });

    const written = directory.writeGroupEntry(dn, converted.attributes);
    if (!written.ok) {
      throw new SCIMMY.Types.Error(written.reason === 'full' ? 507 : 400,
        written.reason === 'full' ? null : 'invalidValue',
        written.reason === 'full'
          ? 'The directory holds its maximum of ' + directory.maxEntries() +
            ' entries (ldap.maxEntries). Nothing was written.'
          : 'The entry could not be written at ' + dn + ' (' + written.reason + ').');
    }

    auditScim(written.created ? 'group.create' : 'group.update', dn,
              converted.attributes, req);

    log.debug("Leaving the SCIM Group ingress handler. The entry was " +
              (written.created ? 'created.' : 'updated.'));
    return scimMap.prune(groupResourceFor(directory.readGroupEntry(dn), req));
  })
  .degress(function (resource, ctx) {
    log.debug("Entering the SCIM Group degress handler. id=" + resource.id);
    const removed = directory.deleteGroupEntry(resource.id);
    if (!removed.ok) {
      throw new SCIMMY.Types.Error(removed.reason === 'notLeaf' ? 400 : 404,
        removed.reason === 'notLeaf' ? 'invalidValue' : null,
        removed.reason === 'notLeaf'
          ? 'The entry at ' + resource.id + ' has children and this directory ' +
            'refuses a delete of anything that is not a leaf.'
          : 'There is no group at ' + resource.id + '.');
    }
    auditScim('group.delete', resource.id, {}, (ctx || {}).req);
    log.debug("Leaving the SCIM Group degress handler.");
  });

// ---------------------------------------------------------------------------
// THE AUDIT ROW FOR A SCIM WRITE.
//
// It uses the DIRECTORY vocabulary — `user.create`, `group.update` and the rest
// — rather than a set of SCIM actions of its own, and that is the decision worth
// recording. A SCIM POST and an `ldapadd` are the same act arriving by two
// routes; giving them different action names would mean a reader filtering
// /admin/audit for "a user was created" seeing only half the creations, which is
// the blind spot rule 3c warns about. The PROTOCOL column is what says which
// door it came through, and the channel is `http` because it did.
//
// NO VALUES ARE NAMED, only attribute names — audit.js's rule, unchanged. It
// matters here as much as anywhere: a SCIM body is somebody's HR record.
//
// The HTTP call itself is ALSO recorded, by app.js's call log, as a protocol
// endpoint call. That is one act producing two rows at two layers, which the
// audit page already says happens and is why this does not try to suppress it.
// ---------------------------------------------------------------------------
function auditScim(action, dn, attributes, req) {
  audit.audit({
    action: action,
    // The authenticated caller, which this surface has had since the SCIM
    // endpoints started requiring one. It is passed in rather than resolved by
    // audit.js's actor resolver, because that resolver reads the browser
    // session and a provisioning client has none — the whole point of the
    // schemes in scim_auth.js is that a caller can be somebody without one.
    actor: (req && req.scimAuth && req.scimAuth.principal) || '',
    protocol: 'SCIM',
    channel: 'http',
    target: dn,
    summary: 'SCIM ' + (action.indexOf('.create') > 0 ? 'created' :
                        action.indexOf('.delete') > 0 ? 'deleted' : 'updated') +
             ' ' + dn,
    detail: { attributes: Object.keys(attributes || {}).sort().join(', ') }
  });
}

// ---------------------------------------------------------------------------
// THE ROUTES.
//
// Registered against the shared app one by one, in the order RFC 7644 section
// 3.2 tabulates them. Two ordering notes:
//
//   * `.search` is registered BEFORE `/:id` for each resource type. It does not
//     matter today, because `.search` is a POST and there is no POST on `/:id` —
//     but the day somebody adds one, `/Users/.search` would start being routed
//     as an id of `.search`, and the failure would be a 404 for a request that
//     looks perfectly correct.
//   * every one of these is visible to `GET /sts-metadata`, which is the reason
//     they are here rather than behind a mounted Router. See the header.
// ---------------------------------------------------------------------------

// --- discovery (section 4) -------------------------------------------------

app.get(BASE + '/ServiceProviderConfig', handle(
  { operation: 'discovery', resourceType: 'ServiceProviderConfig', need: 'none' },
  async function (req, res) {
    // Re-applied so that a runtime change to scim.maxResults, either bulk
    // limit, or which authentication schemes are offered is in the document as
    // well as in the enforcement. See applyCapabilities().
    applyCapabilities(baseUrlOf(req));
    const document = await new SCIMMY.Resources.ServiceProviderConfig().read();
    const body = JSON.parse(JSON.stringify(document));

    // -----------------------------------------------------------------------
    // THE THREE SCHEMES RFC 7643 HAS NO NAME FOR, AND THE `primary` FLAG.
    //
    // RFC 7644 section 2 names six ways to authenticate and RFC 7643 section 5
    // gives `authenticationSchemes.type` five canonical values, and the two
    // lists do not cover each other: there is no canonical value for a client
    // certificate, a cookie or HOBA. scimmy enforces the canonical five (its
    // ServiceProviderConfig definition carries them as canonicalValues and its
    // coercion throws on anything else), which is a correct reading of that
    // document — so the four it can validate go through SCIMMY.Config and the
    // other three are appended HERE, to the serialised document, carrying an
    // honest type of their own. Both halves come from ONE table in
    // scim_auth.js, so the document cannot advertise a scheme that is turned
    // off nor omit one that is on.
    //
    // A ServiceProviderConfig listing four of the seven ways in would be the
    // most misleading document this service publishes, and it is the first
    // thing a SCIM client reads. `primary` is added here for the same reason:
    // RFC 7643's example in section 8.5 carries it and its schema definition
    // does not define it, so scimmy rejects it as an unknown sub-attribute.
    // -----------------------------------------------------------------------
    body.authenticationSchemes = (body.authenticationSchemes || [])
      .concat(scimAuth.schemesBeyondTheCanonicalList(baseUrlOf(req)));
    const primary = scimAuth.primarySchemeId();
    body.authenticationSchemes.forEach(function (scheme) {
      if (primary && scheme.type === 'oauthbearertoken') {
        scheme.primary = true;
      }
    });
    // The documentation link is built per request rather than set once in
    // SCIMMY.Config, for the reason every other URL here is: this service
    // answers on more than one address and none of them is written down.
    body.documentationUri = baseUrlOf(req) + '/scim';
    body.meta = Object.assign({}, body.meta, {
      location: baseUrlOf(req) + BASE + '/ServiceProviderConfig'
    });
    sendScim(req, res, { operation: 'discovery', resourceType: 'ServiceProviderConfig' },
             200, body);
  }));

app.get(BASE + '/ResourceTypes', handle(
  { operation: 'discovery', resourceType: 'ResourceType', need: 'none' },
  async function (req, res) {
    const list = await new SCIMMY.Resources.ResourceType(queryParams(req)).read();
    sendScim(req, res, { operation: 'discovery', resourceType: 'ResourceType' }, 200, list);
  }));

app.get(BASE + '/ResourceTypes/:id', handle(
  { operation: 'discovery', resourceType: 'ResourceType', need: 'none' },
  async function (req, res) {
    const one = await new SCIMMY.Resources.ResourceType(String(req.params.id)).read();
    sendScim(req, res, { operation: 'discovery', resourceType: 'ResourceType' }, 200, one);
  }));

app.get(BASE + '/Schemas', handle(
  { operation: 'discovery', resourceType: 'Schema', need: 'none' },
  async function (req, res) {
    const list = await new SCIMMY.Resources.Schema(queryParams(req)).read();
    sendScim(req, res, { operation: 'discovery', resourceType: 'Schema' }, 200, list);
  }));

app.get(BASE + '/Schemas/:id', handle(
  { operation: 'discovery', resourceType: 'Schema', need: 'none' },
  async function (req, res) {
    const one = await new SCIMMY.Resources.Schema(String(req.params.id)).read();
    sendScim(req, res, { operation: 'discovery', resourceType: 'Schema' }, 200, one);
  }));

// ---------------------------------------------------------------------------
// /Me (section 3.11), WHICH USED TO BE A REFUSAL AND IS NOW AN ALIAS.
//
// It answered 501 for one reason — "nothing here authenticates, so there is
// never a subject to alias" — and that sentence stopped being true the moment
// these endpoints started requiring a credential. Leaving the 501 in place
// would have been the most easily-noticed lie on this surface: a client reads
// the ServiceProviderConfig, authenticates, and is told there is nobody to be.
//
// So it resolves the authenticated subject to a directory entry and delegates
// to the SAME User handlers /Users/{id} uses — no second read path, no second
// write path, and therefore nothing that can come to disagree about what a User
// resource is.
//
// **THE 501 IS STILL REACHABLE AND IS STILL THE RIGHT ANSWER IN TWO CASES**,
// which is why it was worth keeping rather than replacing: when the caller is
// ANONYMOUS (authentication turned off, or a discovery-only request), because
// there genuinely is no subject; and on POST, because /Me creates the
// authenticated subject and the subject of a request is by definition already
// there. A caller whose credential names somebody with no directory entry gets
// a 404 instead — the alias resolved and there is nothing at the end of it,
// which is a different sentence.
//
// The COMMON case for that 404 is worth knowing: a client_credentials token has
// no person behind it, and a client certificate authenticates a DN. Both are
// perfectly good credentials for provisioning somebody else and neither is
// anybody /Me could be.
// ---------------------------------------------------------------------------
function meSubject(req) {
  log.debug("Entering meSubject().");
  const decision = req.scimAuth || {};
  if (!decision.ok || decision.anonymous || !decision.principal) {
    log.debug("Leaving meSubject(). Nobody authenticated.");
    throw new SCIMMY.Types.Error(501, null,
      '/Me is an alias for the subject the request authenticated as (RFC 7644 section 3.11), ' +
      'and this request authenticated as nobody — authentication is turned off here ' +
      '(scim.authRequired), so there is no subject to alias. Present a credential, or ask for ' +
      'the user by id. This is a 501 rather than a 404 because the alias is unavailable, not ' +
      'because the resource is missing.');
  }
  // Through the identity normalisation every other reader of this directory
  // uses, so that `alice`, `urn:sts-mock:user:alice` and `alice@REALM` reach
  // ONE entry — the same fold recordAuthentication() applies, and the reason
  // this is not a lookup by the raw principal. objectFor() then handles all
  // three identity shapes, including the DN of a client certificate and a DID,
  // which a lookup by username could not.
  const key = stats.identityOf(decision.principal).key || decision.principal;
  const located = directory.objectFor(key);
  if (!located || !located.found) {
    log.debug("Leaving meSubject(). " + key + " has no entry.");
    throw new SCIMMY.Types.Error(404, null,
      'This request authenticated as "' + decision.principal + '", and there is no entry for ' +
      'them under ' + directory.USERS_DN + ' — so the alias resolves to nothing. That is the ' +
      'ordinary answer for a client_credentials token or a client certificate, neither of ' +
      'which has a person behind it: both are good credentials for provisioning somebody ' +
      'else, and neither is anybody /Me could be. Create the entry first, or use /Users.');
  }
  log.debug("Leaving meSubject(). " + located.dn);
  return located.dn;
}

app.get(BASE + '/Me', handle(
  { operation: 'read', resourceType: 'Self', need: 'read' },
  async function (req, res) {
    const one = await new SCIMMY.Resources.User(meSubject(req), queryParams(req))
      .read({ req: req });
    sendScim(req, res, { operation: 'read', resourceType: 'Self' }, 200, one);
  }));

app.put(BASE + '/Me', handle(
  { operation: 'replace', resourceType: 'Self', need: 'write' },
  async function (req, res) {
    const updated = await new SCIMMY.Resources.User(meSubject(req), queryParams(req))
      .write(scimBody(req), { req: req });
    sendScim(req, res, { operation: 'replace', resourceType: 'Self' }, 200, updated);
  }));

app.patch(BASE + '/Me', handle(
  { operation: 'modify', resourceType: 'Self', need: 'write' },
  async function (req, res) {
    const patched = await new SCIMMY.Resources.User(meSubject(req), queryParams(req))
      .patch(scimBody(req), { req: req });
    if (patched === undefined) {
      sendScim(req, res, { operation: 'modify', resourceType: 'Self' }, 204, undefined);
      return;
    }
    sendScim(req, res, { operation: 'modify', resourceType: 'Self' }, 200, patched);
  }));

app.delete(BASE + '/Me', handle(
  { operation: 'delete', resourceType: 'Self', need: 'write' },
  async function (req, res) {
    // It deletes the caller's own entry, and nothing here stops it. That is the
    // same permissiveness as the rest of this surface rather than an oversight
    // — a provisioning client's deprovisioning path is exactly what this mock
    // exists to let somebody run, and refusing self-deletion would be this
    // service inventing a rule the specification does not have.
    await new SCIMMY.Resources.User(meSubject(req)).dispose({ req: req });
    sendScim(req, res, { operation: 'delete', resourceType: 'Self' }, 204, undefined);
  }));

app.post(BASE + '/Me', handle(
  { operation: 'create', resourceType: 'Self', need: 'write' },
  function (req) {
    // Section 3.11 lists POST among the methods /Me accepts, and there is
    // nothing sensible for it to mean here: the subject of an authenticated
    // request already exists by the time the request is being handled. Refused
    // with the reason rather than aliased onto a create, which would put the
    // caller's own name on somebody else's body.
    meSubject(req);
    throw new SCIMMY.Types.Error(501, null,
      'POST /Me would create the subject this request authenticated as, and that subject ' +
      'already exists — it is what the credential named. Create somebody with ' +
      'POST ' + BASE + '/Users. The other four methods on /Me do work.');
  }));

// ---------------------------------------------------------------------------
// REGISTERING A HOBA PUBLIC KEY — RFC 7486 section 7.
//
// The one endpoint in this feature that is NOT under /scim/v2 and NOT behind
// the authentication gate, and both of those are deliberate:
//
//   * The PATH is the specification's. RFC 7486 puts client public key
//     registration at /.well-known/hoba/register, and a client that speaks HOBA
//     looks there. Inventing /scim/v2/hoba-keys would have been tidier and
//     would have been a path nothing knows about.
//   * It is UNAUTHENTICATED for the reason POST /tls/trust is: it is how a
//     caller GETS a credential, so requiring one to reach it would make the
//     scheme unusable by anybody who did not already have another. Anybody may
//     register any key for any name, which is the same statement as "every LDAP
//     bind succeeds" — the signature is then really verified, which is the half
//     that makes the scheme worth implementing at all.
//
// GET describes it, because a well-known path that answers 404 to a browser is
// indistinguishable from one nobody implemented.
// ---------------------------------------------------------------------------
const HOBA_REGISTER_PATH = '/.well-known/hoba/register';

app.get(HOBA_REGISTER_PATH, function (req, res) {
  log.debug("Entering GET " + HOBA_REGISTER_PATH + ".");
  const auth = scimAuth.describe(req);
  const hoba = auth.schemes.filter(function (row) { return row.id === 'hoba'; })[0] || {};
  res.status(200).type('application/json').set('Cache-Control', 'no-store').send(JSON.stringify({
    what: 'Client public key registration for HOBA (RFC 7486 section 7), which is one of the ' +
          'authentication schemes the SCIM endpoints here accept.',
    enabled: !!hoba.enabled,
    method: 'POST',
    contentType: 'application/x-www-form-urlencoded',
    parameters: {
      pub: 'REQUIRED. A PEM SubjectPublicKeyInfo block — an RSA public key. RFC 7486 ' +
           'registers algorithm 0 (RSA-SHA256) and 1 (RSA-SHA1); this service accepts 0.',
      username: 'REQUIRED unless the request carries a browser session cookie. Who the key ' +
                'is for. This parameter is this service\'s own: RFC 7486 registers a key ' +
                'inside an already-authenticated context and there is rarely one here.',
      kid: 'Optional. The key id you will send in the credential. Defaults to a hash of the ' +
           'key itself, so that two keys cannot claim one id.'
    },
    answers: 'On success, 201 with the header Hobareg: regok (RFC 7486 section 7) and a JSON ' +
             'body naming the kid, the username and the directory entry the key went on.',
    thenAuthenticateWith: 'Authorization: HOBA result="kid.challenge.nonce.sig"',
    theChallengeIsOn: 'any 401 from ' + BASE + ', in a WWW-Authenticate header',
    nothingIsCheckedAboutTheRegistration:
      'Anybody may register any key for any name, and the name is created in the directory if ' +
      'it is new. The SIGNATURE is then really verified, which is the half that makes this ' +
      'worth having — a signature check that passed anything would not be the scheme.',
    storedAs: 'hobaPublicKey on the person\'s entry under ' + directory.USERS_DN + ', as ' +
              '"<kid> <base64 DER>". An ldapsearch and /admin/users show it.',
    console: baseUrlOf(req) + '/admin/scim',
    surface: baseUrlOf(req) + '/scim'
  }, null, 2));
  log.debug("Leaving GET " + HOBA_REGISTER_PATH + ".");
});

app.post(HOBA_REGISTER_PATH, function (req, res) {
  log.debug("Entering POST " + HOBA_REGISTER_PATH + ".");
  if (!enabled()) {
    res.status(501).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify({ error: 'SCIM is turned off on this service (scim.enabled), and ' +
                                     'HOBA registration is part of its authentication ' +
                                     'surface. The route is registered, which is why this is ' +
                                     'a 501 and not a 404.' }, null, 2));
    log.debug("Leaving POST " + HOBA_REGISTER_PATH + ". SCIM is off.");
    return;
  }
  const result = scimAuth.registerHobaKey(req);
  Object.keys(result.headers || {}).forEach(function (name) {
    res.set(name, result.headers[name]);
  });
  if (!result.ok) {
    res.status(result.status).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify({ error: result.detail }, null, 2));
    log.debug("Leaving POST " + HOBA_REGISTER_PATH + ". " + result.status + ".");
    return;
  }
  // The directory row, in the directory's own vocabulary — a registration is an
  // entry being updated, and a reader filtering /admin/audit for "what happened
  // to this person" wants it beside the rest. The action is `user.update`
  // rather than one of its own for the reason auditScim() gives: one act, one
  // vocabulary, whichever door it came through.
  audit.audit({
    action: 'user.update', actor: result.body.username, protocol: 'SCIM', channel: 'http',
    target: result.body.dn,
    summary: 'a HOBA public key was registered for ' + result.body.username,
    detail: { attributes: result.body.attribute, kid: result.body.kid }
  });
  res.status(result.status).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(result.body, null, 2));
  log.debug("Leaving POST " + HOBA_REGISTER_PATH + ". Registered " + result.body.kid + ".");
});

// --- Users (sections 3.3 to 3.6) -------------------------------------------

function listHandler(type, Resource) {
  return async function (req, res) {
    const list = await new Resource(queryParams(req)).read({ req: req });
    sendScim(req, res, { operation: 'list', resourceType: type }, 200, list);
  };
}

function searchHandler(type, Resource) {
  return async function (req, res) {
    const body = scimBody(req) || {};
    // The schema URN is REQUIRED on a SearchRequest (section 3.4.3) and is
    // checked, unlike most things here: a POST to .search carrying an ordinary
    // resource body is a client that meant to create something, and answering it
    // as an empty search would be the most confusing possible reply.
    const schemas = Array.isArray(body.schemas) ? body.schemas : [];
    if (schemas.indexOf(SEARCH_REQUEST_URN) < 0) {
      throw new SCIMMY.Types.Error(400, 'invalidSyntax',
        'A .search body must carry schemas: ["' + SEARCH_REQUEST_URN + '"] ' +
        '(RFC 7644 section 3.4.3).');
    }
    const list = await new Resource(searchParams(body)).read({ req: req });
    sendScim(req, res, { operation: 'search', resourceType: type }, 200, list);
  };
}

function readHandler(type, Resource) {
  return async function (req, res) {
    const one = await new Resource(String(req.params.id), queryParams(req)).read({ req: req });
    sendScim(req, res, { operation: 'read', resourceType: type }, 200, one);
  };
}

function createHandler(type, Resource) {
  return async function (req, res) {
    const body = scimBody(req);
    const created = await new Resource(queryParams(req)).write(body, { req: req });
    sendScim(req, res, { operation: 'create', resourceType: type }, 201, created,
             locationPrefix(req, type + 's') + encodeURIComponent(created.id));
  };
}

function replaceHandler(type, Resource) {
  return async function (req, res) {
    const body = scimBody(req);
    const updated = await new Resource(String(req.params.id), queryParams(req))
      .write(body, { req: req });
    sendScim(req, res, { operation: 'replace', resourceType: type }, 200, updated);
  };
}

// PATCH is the one operation this file does not implement at all: scimmy's
// PatchOp reads the resource through egress, applies the operations against the
// schema, and writes the result back through ingress. So the two handlers above
// are what makes PATCH work, and there is no third code path to keep in step.
//
// A PATCH that changes nothing returns 204 with no body, which section 3.5.2
// permits and scimmy signals by resolving to undefined. A client that always
// parses the response body is exactly what that case is for.
function modifyHandler(type, Resource) {
  return async function (req, res) {
    const body = scimBody(req);
    const patched = await new Resource(String(req.params.id), queryParams(req))
      .patch(body, { req: req });
    if (patched === undefined) {
      sendScim(req, res, { operation: 'modify', resourceType: type }, 204, undefined);
      return;
    }
    sendScim(req, res, { operation: 'modify', resourceType: type }, 200, patched);
  };
}

function deleteHandler(type, Resource) {
  return async function (req, res) {
    await new Resource(String(req.params.id)).dispose({ req: req });
    sendScim(req, res, { operation: 'delete', resourceType: type }, 204, undefined);
  };
}

[{ type: 'User', endpoint: '/Users', Resource: SCIMMY.Resources.User },
 { type: 'Group', endpoint: '/Groups', Resource: SCIMMY.Resources.Group }].forEach(function (row) {
  const path = BASE + row.endpoint;
  // `need` is the whole of the access control policy at this layer: reading
  // needs the read scope and everything else needs the write scope, and the two
  // do not imply one another. A POST to `.search` is a READ that happens to use
  // POST because a filter can be longer than a URL (RFC 7644 section 3.4.3) —
  // deciding this on the HTTP method rather than on the operation would have
  // made the one endpoint whose method lies about it need the write scope.
  app.get(path, handle({ operation: 'list', resourceType: row.type, need: 'read' },
                       listHandler(row.type, row.Resource)));
  app.post(path, handle({ operation: 'create', resourceType: row.type, need: 'write' },
                        createHandler(row.type, row.Resource)));
  // Before /:id — see the note above.
  app.post(path + '/.search', handle({ operation: 'search', resourceType: row.type,
                                       need: 'read' },
                                     searchHandler(row.type, row.Resource)));
  app.get(path + '/:id', handle({ operation: 'read', resourceType: row.type, need: 'read' },
                                readHandler(row.type, row.Resource)));
  app.put(path + '/:id', handle({ operation: 'replace', resourceType: row.type,
                                  need: 'write' },
                                replaceHandler(row.type, row.Resource)));
  app.patch(path + '/:id', handle({ operation: 'modify', resourceType: row.type,
                                    need: 'write' },
                                  modifyHandler(row.type, row.Resource)));
  app.delete(path + '/:id', handle({ operation: 'delete', resourceType: row.type,
                                     need: 'write' },
                                   deleteHandler(row.type, row.Resource)));
});

// --- the root search (section 3.4.3) ---------------------------------------

app.post(BASE + '/.search', handle(
  { operation: 'search', resourceType: 'User', need: 'read' },
  async function (req, res) {
    const body = scimBody(req) || {};
    const schemas = Array.isArray(body.schemas) ? body.schemas : [];
    if (schemas.indexOf(SEARCH_REQUEST_URN) < 0) {
      throw new SCIMMY.Types.Error(400, 'invalidSyntax',
        'A .search body must carry schemas: ["' + SEARCH_REQUEST_URN + '"] ' +
        '(RFC 7644 section 3.4.3).');
    }
    // ACROSS BOTH RESOURCE TYPES, which is what the root .search means and is
    // the one thing it does that the per-type one cannot. scimmy's
    // SearchRequest#apply() does the fan-out and the merge.
    //
    // ITS CONSTRUCTOR WANTS A DIFFERENT SHAPE FROM THE RESOURCE CONSTRUCTOR and
    // that asymmetry cost an afternoon. It validates `schemas` itself and
    // REFUSES a request object without one — so the members cannot simply be
    // handed over the way the per-type handlers hand them to a Resource — and it
    // wants `attributes`/`excludedAttributes` as ARRAYS, which is the SearchRequest
    // spelling, where a Resource wants the comma-separated query-string one. So
    // the two are converted back here rather than reusing searchParams()'s
    // output unchanged.
    const request = Object.assign({}, searchParams(body), { schemas: [SEARCH_REQUEST_URN] });
    ['attributes', 'excludedAttributes'].forEach(function (name) {
      if (request[name] !== undefined) {
        request[name] = String(request[name]).split(',')
          .map(function (part) { return part.trim(); })
          .filter(function (part) { return part !== ''; });
      }
    });
    const list = await new SCIMMY.Messages.SearchRequest(request)
      .apply([SCIMMY.Resources.User, SCIMMY.Resources.Group], { req: req });
    sendScim(req, res, { operation: 'search', resourceType: 'User' }, 200, list);
  }));

// --- bulk (section 3.7) -----------------------------------------------------

app.post(BASE + '/Bulk', handle(
  // A BulkRequest carries creates, replaces, patches and deletes and never a
  // read (RFC 7644 section 3.7 defines no GET operation inside one), so it is a
  // write whatever is in it — and a bulk of nothing but deletes must not be
  // reachable with a read-only credential because the envelope looked harmless.
  { operation: 'bulk', resourceType: 'Bulk', need: 'write' },
  async function (req, res) {
    const body = scimBody(req);
    // The payload limit is checked here rather than left to the express body
    // parser, because the parser's limit is a service-wide 5 MB and this one is
    // advertised in the ServiceProviderConfig — a client reads a published limit
    // as a promise, and a request refused at a different size than the document
    // says is the drift this arrangement exists to prevent.
    const size = Buffer.byteLength(typeof req.body === 'string' ? req.body : '', 'utf8');
    if (size > bulkMaxPayloadSize()) {
      throw new SCIMMY.Types.Error(413, null,
        'This BulkRequest is ' + size + ' bytes and the advertised maximum is ' +
        bulkMaxPayloadSize() + ' (scim.bulkMaxPayloadSize, published as ' +
        'bulk.maxPayloadSize in the ServiceProviderConfig).');
    }
    const result = await new SCIMMY.Messages.BulkRequest(body, bulkMaxOperations())
      .apply([SCIMMY.Resources.User, SCIMMY.Resources.Group], { req: req });
    // 200 rather than a status derived from the operations inside: RFC 7644
    // section 3.7 puts each operation's own status in its own `status` member,
    // and a bulk that was accepted and processed succeeded whatever happened
    // inside it. The counters see it as one `bulk` plus whatever the operations
    // inside recorded on their own way through — which is stated on /admin/scim,
    // because a reader adding the column up will otherwise find it does not
    // tally.
    sendScim(req, res, { operation: 'bulk', resourceType: 'Bulk' }, 200, result);
  }));

// ---------------------------------------------------------------------------
// GET /scim — what this is, for a person.
//
// The same shape /ldap and /tls have: a page that says what the protocol surface
// is, what it will and will not do, and where to point a client — plus
// ?format=json so a test can read the same facts. It is NOT a SCIM endpoint and
// says so; a real SCIM server publishes none of this.
// ---------------------------------------------------------------------------
function pageShell(title, inner) {
  return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + xmlEscape(title) + '</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;' +
    'background:#f4f4f7;margin:0;padding:2rem;color:#222;line-height:1.45}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;' +
    'padding:24px 28px;max-width:60rem;margin:0 auto;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}' +
    'h1{font-size:1.3em;margin:0 0 4px;color:#12107c}' +
    'h2{font-size:1em;margin:1.4em 0 .4em}' +
    'p.sub{color:#666;font-size:.85em;margin:0 0 18px}' +
    '.warn{background:#fff8e1;border:1px solid #ffe082;padding:9px 12px;' +
    'border-radius:5px;font-size:.82em;margin:0 0 16px}' +
    'table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;font-size:.85em}' +
    'th,td{border:1px solid #ddd;padding:.35rem .55rem;text-align:left;' +
    'vertical-align:top}th{background:#f0f0f5}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;' +
    'font-size:.85em;background:#f4f4f8;padding:.1rem .25rem;border-radius:3px;' +
    'word-break:break-all}a{color:#12107c}' +
    'ul{margin:.3em 0;padding-left:1.2em}li{margin:.2em 0}' +
    '</style></head><body><div class="card">' + inner + '</div></body></html>\n';
}

// What this surface is, as data. Shared by the page and by ?format=json so the
// two cannot disagree — the same reason /sts-metadata reads the router.
function description(req) {
  log.debug("Entering description().");
  const base = baseUrlOf(req);
  const out = {
    enabled: enabled(),
    baseUrl: base + BASE,
    specifications: ['RFC 7642', 'RFC 7643', 'RFC 7644', 'RFC 6750', 'RFC 7617',
                     'RFC 7616', 'RFC 7486', 'RFC 9449'],
    // Every scheme, whether it is on, what it costs a caller, and the access
    // control policy behind it — from scim_auth.js's table, which is the same
    // table the WWW-Authenticate challenge and the ServiceProviderConfig are
    // built from. So this page cannot describe a scheme a client would not be
    // offered.
    authentication: scimAuth.describe(req),
    store: {
      what: 'The embedded LDAP directory in this process. There is no second ' +
            'store and no cache: a SCIM POST and an ldapadd write the same ' +
            'entry, and a person provisioned here appears on /admin/users, in ' +
            'an ldapsearch, and in the attributes their access token carries.',
      users: directory.USERS_DN,
      groups: directory.GROUPS_DN,
      baseDn: directory.BASE_DN,
      userCount: directory.personCount(),
      groupCount: directory.allGroupEntries().length,
      entryCount: directory.entryCount(),
      maxEntries: directory.maxEntries()
    },
    identifiers: {
      id: "the entry's DN, percent-encoded in a URL path segment",
      why: 'RFC 7643 section 3.1 asks for an opaque, server-assigned, unique ' +
           'identifier, and the DN already is one — it is the key the entry is ' +
           'stored under. Any other choice would be a second definition of one ' +
           'fact. The cost is stated rather than hidden: an LDAP rename gives ' +
           'the same person a new SCIM id, which is a real deviation from ' +
           '"stable for the lifetime of the resource" and is the honest ' +
           'behaviour for a directory-backed server.',
      example: base + BASE + '/Users/' +
               encodeURIComponent('uid=alice,' + directory.USERS_DN)
    },
    endpoints: [
      { method: 'GET', path: BASE + '/ServiceProviderConfig',
        what: 'What this server supports. Read it first.' },
      { method: 'GET', path: BASE + '/ResourceTypes', what: 'User and Group.' },
      { method: 'GET', path: BASE + '/Schemas',
        what: 'The core User and Group schemas, and the enterprise User extension.' },
      { method: 'GET', path: BASE + '/Users',
        what: 'The list, with ?filter, ?sortBy, ?startIndex, ?count, ?attributes.' },
      { method: 'POST', path: BASE + '/Users', what: 'Create.' },
      { method: 'POST', path: BASE + '/Users/.search',
        what: 'The same query as a POST body, for a filter too long for a URL.' },
      { method: 'GET', path: BASE + '/Users/{id}', what: 'One user.' },
      { method: 'PUT', path: BASE + '/Users/{id}', what: 'Replace.' },
      { method: 'PATCH', path: BASE + '/Users/{id}',
        what: 'Modify (section 3.5.2), path grammar and all.' },
      { method: 'DELETE', path: BASE + '/Users/{id}', what: 'Delete.' },
      { method: '(the same seven)', path: BASE + '/Groups',
        what: 'Groups, whose members are resolved from member, uniqueMember ' +
              'and memberUid alike.' },
      { method: 'POST', path: BASE + '/.search',
        what: 'A query across BOTH resource types at once.' },
      { method: 'POST', path: BASE + '/Bulk',
        what: 'Up to ' + bulkMaxOperations() + ' operations in one request.' },
      { method: 'GET / PUT / PATCH / DELETE', path: BASE + '/Me',
        what: 'The subject this request authenticated as (section 3.11), ' +
              'delegated to the same User handlers. 501 when nothing ' +
              'authenticated, and on POST; 404 when the credential names ' +
              'somebody with no entry here.' },
      { method: 'POST', path: '/.well-known/hoba/register',
        what: 'Register a HOBA public key (RFC 7486 section 7). Unauthenticated ' +
              'on purpose — it is how a caller gets a credential. GET ' +
              'describes it.' }
    ],
    // The four sentences that matter most, in the order somebody is likely to be
    // surprised by them.
    doesNotDo: [
      'IT AUTHENTICATES, AND IT CHECKS ALMOST NOTHING. A credential is ' +
      'required' + (scimAuth.authRequired() ? '' : ' — except that ' +
      'scim.authRequired is currently OFF, so it is not') + ', and every ' +
      'scheme behind that requirement is permissive: any caller can get an ' +
      'access token with either scope from this service\'s own token ' +
      'endpoint with any grant, any username with any password but "invalid" ' +
      'passes Basic, any username passes Digest with the one shared password, ' +
      'and anybody can register a HOBA key for any name. It is a turnstile, ' +
      'not a lock. What it buys is that a client\'s 401, 403, ' +
      'challenge-response and scope handling can be exercised at all — none ' +
      'of which an open endpoint can produce. Do not put this port on a ' +
      'public address on the strength of it.',

      'A SCOPE GRANTS AND NOTHING ELSE READS ONE. scim:read and scim:write ' +
      'are the first scope requirement anywhere in this service, and they ' +
      'apply at these endpoints only — no other surface here reads a scope, ' +
      'and holding one confers nothing beyond /scim/v2. Note also that only ' +
      'the OAuth schemes carry scopes at all: Basic, Digest, HOBA, a cookie ' +
      'and a client certificate authenticate a caller who may then do both, ' +
      'so a caller who cannot get a scope can simply use another scheme. Each ' +
      'scheme has a switch of its own for exactly that reason.',

      'active: false DEACTIVATES NOBODY. It is stored on the entry as ' +
      'scimActive and read by nothing here: no bind is refused, no token is ' +
      'withheld and no session ends. Deprovisioning is the commonest thing a ' +
      'SCIM client does, so a mock that pretended to disable an account would ' +
      'let somebody ship a path that has never worked.',

      'NO ETag AND NO changePassword, both advertised as unsupported rather ' +
      'than half-implemented. A version built over a timestamp with ' +
      'one-second resolution would be a concurrency control a client trusts ' +
      'and that is wrong; and no password in this service is checked, so ' +
      'there is none to change.',

      'A MEMBER THAT NAMES NOTHING IS ACCEPTED. This directory does no ' +
      'referential integrity on purpose — deleting a user leaves their DN in ' +
      'every group that listed them — so refusing a dangling member here ' +
      'would make that state impossible to reproduce. /admin/groups reports ' +
      'them.'
    ],
    reachableNegatives: [
      { what: 'A request with no credential',
        answer: '401, with a WWW-Authenticate header per offered scheme — RFC ' +
                '7644 section 2 makes that header a SHALL. The discovery ' +
                'endpoints are exempt unless scim.authDiscovery is on.' },
      { what: 'An access token with the wrong scope for the operation',
        answer: '403 with WWW-Authenticate: Bearer error="insufficient_scope", ' +
                'scope="' + scimAuth.scopeWrite() + '". Reads need "' +
                scimAuth.scopeRead() + '" and writes need "' +
                scimAuth.scopeWrite() + '"; neither implies the other.' },
      { what: 'An access token this service did not issue, or one that was revoked',
        answer: '401. These endpoints verify the signature, unlike the OID4VCI ' +
                'credential endpoints, which accept a foreign token: a scope ' +
                'on a token nobody verified is a permission its holder wrote ' +
                'for themselves.' },
      { what: 'Basic with the password "' + scimAuth.REFUSED_PASSWORD + '"',
        answer: '401 — the same reserved value every other family here refuses.' },
      { what: 'Digest with a wrong password, a stale nonce, or a repeated nc',
        answer: '401 three ways: the password really is checked here, a stale ' +
                'nonce carries stale=true (which a conforming client retries ' +
                'silently), and a replayed nonce count does NOT — it was a ' +
                'valid credential and has been seen before, which is a ' +
                'different sentence.' },
      { what: 'A HOBA signature that does not verify, or a reused ' +
              '(kid, challenge, nonce)',
        answer: '401. The signature is really verified — RSA-SHA256 over RFC ' +
                '7486 section 5\'s length-prefixed blob — and the challenge ' +
                'may be REUSED until its max-age, so what is refused as a ' +
                'replay is the triple and not the challenge.' },
      { what: 'A credential in a scheme this service does not offer',
        answer: '401 naming the ones it does. An access token in the query ' +
                'string is refused separately, by the same check ' +
                '/oauth2/userinfo uses.' },
      { what: 'GET /Me with no credential, or POST /Me',
        answer: '501 — the alias is unavailable rather than the resource ' +
                'missing. A credential naming somebody with no entry gets 404.' },
      { what: 'A userName of "' + REFUSED_USERNAME + '"',
        answer: '400 invalidValue — the same reserved value the password grant, ' +
                'WS-Trust, the WS-Federation sign-in screen and every LDAP bind ' +
                'here refuse.' },
      { what: 'A second user with a userName somebody already has',
        answer: '409 uniqueness.' },
      { what: 'A userName or displayName carrying an RFC 4514 special character ' +
              '(a comma, a quote, a plus, a hash, a semicolon, an equals, an ' +
              'angle bracket or a backslash)',
        answer: '400 invalidValue — the SCIM id here IS the entry\'s DN, so a ' +
                'name carrying one would produce a resource that cannot be read ' +
                'back. It is the SAME refusal the console and the management ' +
                'API give, from the same rule; an ldapadd can still create such ' +
                'an entry with the escaping written out.' },
      { what: 'A userName that is DN-shaped or DID-shaped',
        answer: '400 invalidValue — an entry named by a distinguished name gets ' +
                'here by presenting a client certificate and one named by a ' +
                'decentralized identifier by presenting that, so there is ' +
                'nothing to create one from by hand. Also the console\'s and ' +
                'the management API\'s answer, from the same function.' },
      { what: 'An id that names nothing', answer: '404.' },
      { what: 'A filter this server cannot evaluate',
        answer: '400 invalidFilter — refused rather than answered with an empty ' +
                'list, because "no results" and "I could not read your filter" ' +
                'are different answers.' },
      { what: 'Any method on /Me', answer: '501.' }
    ],
    mapping: {
      what: 'Which LDAP attribute each SCIM member is. The whole table, with ' +
            'the schema document that defines each attribute, is on ' +
            '/admin/scim.',
      user: scimMap.USER_ATTRIBUTES.map(function (row) {
        return { scim: row.scim, ldap: row.ldap, kind: row.kind,
                 readOnly: !!row.readOnly };
      }),
      group: scimMap.GROUP_ATTRIBUTES.map(function (row) {
        return { scim: row.scim, ldap: row.ldap, kind: row.kind,
                 readOnly: !!row.readOnly };
      })
    },
    counters: stats.scimSnapshot(),
    console: base + '/admin/scim',
    managementApi: base + '/admin-api/scim'
  };
  log.debug("Leaving description(). " + out.endpoints.length + " endpoint(s) described.");
  return out;
}

app.get('/scim', function (req, res) {
  log.debug("Entering GET /scim.");
  const info = description(req);
  if (String(req.query.format || '').toLowerCase() === 'json') {
    res.status(200).set('Cache-Control', 'no-store').json(info);
    log.debug("Leaving GET /scim. JSON.");
    return;
  }
  const endpoints = info.endpoints.map(function (row) {
    return '<tr><td><code>' + xmlEscape(row.method) + '</code></td><td><code>' +
      xmlEscape(row.path) + '</code></td><td>' + xmlEscape(row.what) + '</td></tr>';
  }).join('');
  const negatives = info.reachableNegatives.map(function (row) {
    return '<tr><td>' + xmlEscape(row.what) + '</td><td>' + xmlEscape(row.answer) +
      '</td></tr>';
  }).join('');
  const auth = info.authentication;
  const schemeRows = auth.schemes.map(function (row) {
    return '<tr><td>' + xmlEscape(row.name) +
      (row.primary ? ' <em>(primary)</em>' : '') + '</td>' +
      '<td><code>' + xmlEscape(row.type) + '</code>' +
      (row.canonical ? '' : ' <em>(no canonical value in RFC 7643)</em>') + '</td>' +
      '<td>' + (row.enabled ? 'offered' : 'off') +
      ' <span class="sub">(<code>' + xmlEscape(row.setting) + '</code>)</span></td>' +
      '<td>' + (row.scoped ? 'scopes' : 'everything') + '</td>' +
      '<td>' + xmlEscape(row.spec) + '</td></tr>' +
      '<tr><td colspan="5" class="sub">' + xmlEscape(row.description) + '</td></tr>';
  }).join('');
  const policyRows = auth.policy.map(function (text) {
    return '<li>' + xmlEscape(text) + '</li>';
  }).join('');
  const mapping = info.mapping.user.map(function (row) {
    return '<tr><td><code>' + xmlEscape(row.scim) + '</code></td><td><code>' +
      xmlEscape(row.ldap) + '</code></td><td>' + xmlEscape(row.kind) +
      (row.readOnly ? ', read-only' : '') + '</td></tr>';
  }).join('');
  const inner = '<h1>SCIM 2.0 — provisioning into the directory</h1>' +
    '<p class="sub">RFC 7642, 7643 and 7644, at <code>' + xmlEscape(info.baseUrl) +
    '</code>. ' + (info.enabled ? '' : '<strong>Turned off</strong> ' +
      '(<code>scim.enabled</code>) — every endpoint answers 501. ') +
    'This page is not a SCIM endpoint; a real server publishes none of it.</p>' +
    '<div class="warn"><strong>These endpoints require a credential' +
    (auth.required ? '' : ' — except that <code>scim.authRequired</code> is ' +
      'currently OFF, so right now they do not') + ', and almost nothing is ' +
    'checked about it.</strong> They create and DELETE accounts, which is why ' +
    'this is the one surface in this service that asks at all. Every scheme ' +
    'below is permissive: any caller can get an access token with either ' +
    'scope from ' + '<a href="/oauth2/token">the token endpoint</a> with any ' +
    'grant, any username with any password but <code>invalid</code> passes ' +
    'Basic, any username passes Digest with one shared password, and anybody ' +
    'can register a HOBA key for any name. A turnstile, not a lock — what it ' +
    'buys is that a client\'s 401, 403 and challenge-response paths can be ' +
    'run at all. <strong>And <code>active: false</code> deactivates ' +
    'nobody</strong> — it is stored as <code>scimActive</code> and read by ' +
    'nothing: no bind refused, no token withheld, no session ended. ' +
    'Deprovisioning is the commonest thing a SCIM client does, so that one is ' +
    'worth reading twice.</div>' +
    '<h2>What it provisions into</h2>' +
    '<p>' + xmlEscape(info.store.what) + '</p>' +
    '<ul><li>People: <code>' + xmlEscape(info.store.users) + '</code> — ' +
    info.store.userCount + ' entry/entries</li>' +
    '<li>Groups: <code>' + xmlEscape(info.store.groups) + '</code> — ' +
    info.store.groupCount + ' group(s), by placement or by objectClass</li>' +
    '<li>The whole directory holds ' + info.store.entryCount + ' of a maximum ' +
    info.store.maxEntries + ' entries</li></ul>' +
    '<h2>The <code>id</code> is the DN</h2>' +
    '<p>' + xmlEscape(info.identifiers.why) + '</p>' +
    '<p>For example: <code>' + xmlEscape(info.identifiers.example) + '</code></p>' +
    '<h2>Authentication</h2>' +
    '<p>RFC 7644 section 2 defines no credential of its own — it delegates to ' +
    'TLS and to RFC 7235 and NAMES six schemes. All six are here. Its one ' +
    '<em>SHALL</em> is that a provider indicate its schemes in ' +
    '<code>WWW-Authenticate</code>, which every 401 from these endpoints does; ' +
    'its one <em>MUST</em> is that a provider be able to map an authenticated ' +
    'client to an access control policy, which is the list under the table. ' +
    'The realm is <code>' + xmlEscape(auth.realm) + '</code>. Discovery ' +
    '(<code>/ServiceProviderConfig</code>, <code>/ResourceTypes</code>, ' +
    '<code>/Schemas</code>) is ' + (auth.discoveryOpen ? 'OPEN — a client has ' +
      'to be able to read which schemes exist before it can use one' :
      'closed too (<code>scim.authDiscovery</code>)') + '.</p>' +
    '<table><tr><th>Scheme</th><th>type</th><th>State</th><th>May do</th>' +
    '<th>Defined by</th></tr>' + schemeRows + '</table>' +
    '<p>The two OAuth scopes are <code>' + xmlEscape(auth.scopes.read) +
    '</code> and <code>' + xmlEscape(auth.scopes.write) + '</code>, published ' +
    'in <code>scopes_supported</code> in both discovery documents. Digest ' +
    'offers ' + xmlEscape(auth.digestAlgorithms.join(', ')) + '. HOBA keys are ' +
    'registered at <code>' + xmlEscape(auth.hobaRegistration) + '</code>.</p>' +
    '<h3>The access control policy</h3><ul>' + policyRows + '</ul>' +

    '<h2>Endpoints</h2>' +
    '<table><tr><th>Method</th><th>Path</th><th>What</th></tr>' + endpoints + '</table>' +
    '<h2>What it deliberately does not do</h2><ul>' +
    info.doesNotDo.map(function (text) {
      return '<li>' + xmlEscape(text) + '</li>';
    }).join('') + '</ul>' +
    '<h2>Things you can make fail</h2>' +
    '<table><tr><th>Do this</th><th>Get this</th></tr>' + negatives + '</table>' +
    '<h2>The User mapping</h2>' +
    '<table><tr><th>SCIM</th><th>LDAP</th><th>How</th></tr>' + mapping + '</table>' +
    '<p class="sub"><a href="/scim?format=json">This page as JSON</a> &middot; ' +
    '<a href="' + xmlEscape(BASE) + '/ServiceProviderConfig">ServiceProviderConfig</a> ' +
    '&middot; <a href="/admin/scim">the console page</a> &middot; ' +
    '<a href="/ldap">the directory this writes into</a></p>';
  res.status(200).type('html').set('Cache-Control', 'no-store')
     .send(pageShell('SCIM 2.0', inner));
  log.debug("Leaving GET /scim. HTML.");
});

// ---------------------------------------------------------------------------
// THE CONSOLE'S SLOT, FILLED HERE.
//
// /admin/scim renders what description() returns, so the endpoint list, the
// "what it does not do" sentences and the reachable negatives are written ONCE —
// in the module that implements them — and the console page shows the same
// thing GET /scim?format=json does. A page carrying its own copy of "active:
// false deactivates nobody" would be the copy that stops being true.
//
// The direction is inverted for the reason ldap_server.js's two readers are, and
// it passes rule 3e's test on both grounds: a require from admin.js into this
// module would pull every /scim route — and, because this module requires
// ldap_server.js, every /ldap route as well — into the express router ahead of
// the console's own, and /sts-metadata is built by walking that router.
//
// Guarded, exactly as those two are: a copy of admin.js without the slot costs a
// warning rather than a TypeError at require time, which would take the whole
// service down over one page.
if (typeof adminConsole.setScimReader === 'function') {
  adminConsole.setScimReader(description);
} else {
  log.warn('scim: the admin console offers no setScimReader(), so /admin/scim ' +
           'will report the counters and not the surface. SCIM itself is ' +
           'unaffected.');
}

log.info('scim: SCIM 2.0 is registered at ' + BASE + ' and provisions into the ' +
         'embedded directory. A credential is ' +
         (scimAuth.authRequired() ? 'REQUIRED' : 'optional (scim.authRequired is off)') +
         ' and every scheme offered is permissive; active:false still ' +
         'deactivates nobody. GET /scim says what else it will not do.');

module.exports = {
  BASE: BASE,
  REFUSED_USERNAME: REFUSED_USERNAME,
  enabled: enabled,
  description: description
};
