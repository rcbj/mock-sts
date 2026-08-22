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
// And its constructor REQUIRES an authentication scheme and a handler; this
// service authenticates nobody, so what it would have installed is a handler
// that accepts everything, dressed as a check. Registering the routes here costs
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
// **IT AUTHENTICATES NOBODY.** There is no bearer token, no basic credential and
// no client certificate check on any of these endpoints, which is what the rest
// of this service does and is stated in the ServiceProviderConfig itself:
// `authenticationSchemes` is EMPTY, which is the honest answer and not an
// omission. A real SCIM endpoint is the most dangerous URL an identity provider
// exposes — it creates and deletes accounts — so a mock that shipped a token
// check nobody verified would be worse than one that says plainly it has none.
// Do not put this port on a public address.
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
// **`/Me` ANSWERS 501, ON PURPOSE.** RFC 7644 section 3.11 defines it as an
// alias for the authenticated subject, and there is never an authenticated
// subject here. Answering 501 with that sentence in the `detail` is a REACHABLE
// NEGATIVE — the same device as the reserved password `invalid` and /spnego's
// three knobs — and is a better answer than either a 404 (which says the route
// is not there) or a guess at who is asking.
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

const app = require('./app');
const { log, xmlEscape, baseUrlOf } = require('./helpers');
const config = require('./config');
const stats = require('./admin_stats');
const audit = require('./audit');
const directory = require('./ldap_server');
// The console, for its reader slot only — see the bottom of this file. Requiring
// it moves nothing: server.js requires ./admin long before ./scim, so node
// already has it in hand.
const adminConsole = require('./admin');
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
function applyCapabilities() {
  log.debug("Entering applyCapabilities().");
  SCIMMY.Config.set({
    patch: true,
    bulk: { supported: true, maxOperations: bulkMaxOperations(),
            maxPayloadSize: bulkMaxPayloadSize() },
    filter: { supported: true, maxResults: maxResults() },
    changePassword: false,
    sort: true,
    etag: false,
    // EMPTY, and that is the statement rather than the gap. See the header.
    authenticationSchemes: []
  });
  log.debug("Leaving applyCapabilities().");
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
                     status: error.status, ok: false, scimType: error.scimType });
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
                     status: status, ok: true, scimType: '' });
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
    location: locationPrefix(req, 'Users')
  });
}

SCIMMY.Resources.declare(SCIMMY.Resources.User)
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
        note: 'provisioned over SCIM 2.0'
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
    actor: '',
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
  { operation: 'discovery', resourceType: 'ServiceProviderConfig' },
  async function (req, res) {
    // Re-applied so that a runtime change to scim.maxResults or either bulk
    // limit is in the document as well as in the enforcement. See
    // applyCapabilities().
    applyCapabilities();
    const document = await new SCIMMY.Resources.ServiceProviderConfig().read();
    const body = JSON.parse(JSON.stringify(document));
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
  { operation: 'discovery', resourceType: 'ResourceType' },
  async function (req, res) {
    const list = await new SCIMMY.Resources.ResourceType(queryParams(req)).read();
    sendScim(req, res, { operation: 'discovery', resourceType: 'ResourceType' }, 200, list);
  }));

app.get(BASE + '/ResourceTypes/:id', handle(
  { operation: 'discovery', resourceType: 'ResourceType' },
  async function (req, res) {
    const one = await new SCIMMY.Resources.ResourceType(String(req.params.id)).read();
    sendScim(req, res, { operation: 'discovery', resourceType: 'ResourceType' }, 200, one);
  }));

app.get(BASE + '/Schemas', handle(
  { operation: 'discovery', resourceType: 'Schema' },
  async function (req, res) {
    const list = await new SCIMMY.Resources.Schema(queryParams(req)).read();
    sendScim(req, res, { operation: 'discovery', resourceType: 'Schema' }, 200, list);
  }));

app.get(BASE + '/Schemas/:id', handle(
  { operation: 'discovery', resourceType: 'Schema' },
  async function (req, res) {
    const one = await new SCIMMY.Resources.Schema(String(req.params.id)).read();
    sendScim(req, res, { operation: 'discovery', resourceType: 'Schema' }, 200, one);
  }));

// --- /Me (section 3.11), which is a refusal ---------------------------------

['get', 'post', 'put', 'patch', 'delete'].forEach(function (method) {
  app[method](BASE + '/Me', handle(
    { operation: 'read', resourceType: 'Self' },
    function () {
      throw new SCIMMY.Types.Error(501, null,
        '/Me is an alias for the subject the request authenticated as (RFC 7644 ' +
        'section 3.11), and nothing here authenticates. This service checks no ' +
        'password and verifies no token, so there is never a subject to alias — ' +
        'which is why this is a 501 saying so rather than a 404 or a guess. Ask ' +
        'for the user by id, or filter on userName.');
    }));
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
  app.get(path, handle({ operation: 'list', resourceType: row.type },
                       listHandler(row.type, row.Resource)));
  app.post(path, handle({ operation: 'create', resourceType: row.type },
                        createHandler(row.type, row.Resource)));
  // Before /:id — see the note above.
  app.post(path + '/.search', handle({ operation: 'search', resourceType: row.type },
                                     searchHandler(row.type, row.Resource)));
  app.get(path + '/:id', handle({ operation: 'read', resourceType: row.type },
                                readHandler(row.type, row.Resource)));
  app.put(path + '/:id', handle({ operation: 'replace', resourceType: row.type },
                                replaceHandler(row.type, row.Resource)));
  app.patch(path + '/:id', handle({ operation: 'modify', resourceType: row.type },
                                  modifyHandler(row.type, row.Resource)));
  app.delete(path + '/:id', handle({ operation: 'delete', resourceType: row.type },
                                   deleteHandler(row.type, row.Resource)));
});

// --- the root search (section 3.4.3) ---------------------------------------

app.post(BASE + '/.search', handle(
  { operation: 'search', resourceType: 'User' },
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
  { operation: 'bulk', resourceType: 'Bulk' },
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
    specifications: ['RFC 7642', 'RFC 7643', 'RFC 7644'],
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
      { method: '(any)', path: BASE + '/Me',
        what: '501, on purpose: nothing here authenticates, so there is never a ' +
              'subject to alias.' }
    ],
    // The four sentences that matter most, in the order somebody is likely to be
    // surprised by them.
    doesNotDo: [
      'IT AUTHENTICATES NOBODY. There is no bearer token, no basic credential ' +
      'and no client certificate check on any of these endpoints, and the ' +
      'ServiceProviderConfig says so with an EMPTY authenticationSchemes ' +
      'rather than by omission. A real SCIM endpoint is the most dangerous URL ' +
      'an identity provider exposes. Do not put this port on a public address.',

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
    '<div class="warn"><strong>Nothing here checks a credential.</strong> ' +
    'These endpoints create and delete accounts and are not protected, because ' +
    'nothing in this service is. The ServiceProviderConfig says so with an ' +
    'empty <code>authenticationSchemes</code> rather than by leaving it out.</div>' +
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
         'embedded directory. It authenticates nobody and active:false ' +
         'deactivates nobody; GET /scim says what else it will not do.');

module.exports = {
  BASE: BASE,
  REFUSED_USERNAME: REFUSED_USERNAME,
  enabled: enabled,
  description: description
};
