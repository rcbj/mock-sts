'use strict';
//
// File: realms.js
//
// ---------------------------------------------------------------------------
// TRUST REALMS: SEVERAL LOGICAL COPIES OF THIS SERVICE IN ONE PROCESS.
//
// A trust realm is a whole mock identity service — its own configuration, its
// own signing key, its own sessions, tokens, applications, statistics and audit
// log — reached on the SAME sockets as every other, and told apart by a segment
// at the front of the path:
//
//   http://localhost:8081/oauth2/token                the DEFAULT realm
//   http://localhost:8081/realm/acme/oauth2/token     the realm `acme`
//
// THE DEFAULT REALM HAS AN EMPTY PREFIX AND THAT IS THE WHOLE CONTRACT OF THIS
// FILE. A service with no realms configured but the default one behaves exactly
// as it did before this module existed: nothing is stripped, no URL is
// rewritten, no store is partitioned differently, and every path in every
// document this service publishes is the path it always was. Every test, every
// container and every client that predates realms keeps working, and the way to
// keep that true is to check it here rather than in forty modules — see
// `active()`, which is the one predicate that decides whether ANY of this is
// switched on.
//
// ---------------------------------------------------------------------------
// HOW FORTY MODULES BECAME REALM-AWARE WITHOUT BEING EDITED
//
// The obvious implementation is to thread a realm argument through every
// function that reads a setting, mints a token or touches a store. That is
// several hundred call sites in twenty-odd files, every one of them a chance to
// drop the argument silently — a token minted for the wrong realm looks exactly
// like a token minted for the right one.
//
// So the realm is AMBIENT instead, held in an `AsyncLocalStorage` that
// `app.js`'s front middleware enters for the whole life of a request. Three
// consequences, and they are the reason this file is short:
//
//   * `config.value(key)` consults the current realm's overrides first, so
//     every one of the 200-odd reads in this service is realm-aware where it
//     stands. See `overridesOf()` and the slot it fills in config.js.
//   * `helpers.baseUrlOf(req)` appends the realm's prefix, so every issuer
//     identifier, every metadata document, every redirect and every form
//     action this service builds names the realm it was built in. That one
//     function is how eighty call sites came along for nothing.
//   * a store declared with `map()`, `arr()` or `obj()` below is PARTITIONED BY
//     REALM behind an unchanged Map/Array/Object interface, so converting one
//     is a one-line edit at the declaration and no edit at all at its hundred
//     readers.
//
// AsyncLocalStorage is the right primitive and not merely a convenient one: a
// request here is a chain of awaits and callbacks (an LDAP search, an RSA
// signature, a gRPC call), and a module-level `currentRealm` variable would be
// correct only until two requests for two realms overlapped — which is to say,
// correct in every test and wrong in every use. The failure would be a token
// signed with another realm's key under load and nothing else.
//
// ---------------------------------------------------------------------------
// WHAT A REALM DOES **NOT** GET ITS OWN OF, and why saying so matters.
//
// The four sockets that are not HTTP have no path to put a realm segment in:
// Kerberos' UDP/TCP 88, the directory's 389 and 636, the two TLS listeners and
// SPIFFE's four. Those are shared, and each family that can be realm-aware on
// them is realm-aware by a DIFFERENT discriminator — the Kerberos realm name
// inside the request, the base DN a search names, the trust domain in an SVID.
// `kerberos/CLAUDE.md`, `ldap/CLAUDE.md` and `spiffe/CLAUDE.md` carry those;
// the index of which family is realm-aware how is in `realmSupport()` at the
// foot of this file, so that a reader can ask this service rather than guess.
// ---------------------------------------------------------------------------

const { AsyncLocalStorage } = require('async_hooks');
const bunyan = require('bunyan');
// config.js is required in the ORDINARY direction and it is safe: that module
// requires only bunyan and config_file.js, so it cannot reach back here. The
// dependency the other way — config.js needing to know a realm's overrides — is
// an INVERTED HOOK filled at the foot of this file, which is rule 3e's shape
// and passes rule 3e's test: a require in that direction would close a cycle.
const config = require('./config');
// The registry of failure codes, a LEAF. NOT audit.js, which requires this
// file: a failure here is logged with `errorCodes.tag()`, and a refusal handed
// back to the console or the management API carries its code NON-ENUMERABLY
// (`errorCodes.mark()` on the result), so a reply serialised from it is
// byte-for-byte what it was.
const errorCodes = require('./error_codes');

const log = bunyan.createLogger({ name: 'sts-realms' });

// The FIRST condition a list of refusals was built for, kept on the list. A
// later push must not overwrite it: the first sentence is the one a caller
// shows first, and the code should name the same condition.
function firstCode(target, code) {
  log.debug("Entering firstCode().");
  if (code && !errorCodes.codeOf(target)) {
    errorCodes.mark(target, code);
  }
  log.debug("Leaving firstCode().");
  return target;
}
config.registerLogger(log);

// ---------------------------------------------------------------------------
// THE DEFAULT REALM IS NOT A ROW IN THE TABLE BELOW AND THAT IS DELIBERATE.
//
// It cannot be created, renamed, re-prefixed or removed, because everything
// this service published before realms existed is published under it — so an
// operator who could delete it could delete the service. It is a constant here
// and the registry below holds only what somebody defined.
// ---------------------------------------------------------------------------
const DEFAULT_ID = 'default';

const DEFAULT_REALM = {
  id: DEFAULT_ID,
  name: 'Default',
  description: 'The realm every path with no realm segment belongs to. It ' +
               'cannot be removed or re-prefixed: every URL this service ' +
               'published before trust realms existed is a URL in this realm.',
  builtin: true,
  createdAt: null,
  overrides: {}
};

// id -> realm record. Insertion-ordered, which is the order the console lists
// them in; the default realm is prepended by list() rather than held here.
const realms = new Map();

// ---------------------------------------------------------------------------
// The ambient realm. `undefined` outside a request — which is every line of
// module loading, every timer and every socket handler that has not entered a
// realm — and `current()` answers the default realm there, so a module that
// reads a setting at require time gets exactly what it got before.
// ---------------------------------------------------------------------------
const als = new AsyncLocalStorage();

function current() {
  log.debug("Entering current().");
  log.debug("Leaving current().");
  return als.getStore() || DEFAULT_REALM;
}

function currentId() {
  log.debug("Entering currentId().");
  log.debug("Leaving currentId().");
  return current().id;
}

function isDefault(realm) {
  log.debug("Entering isDefault().");
  log.debug("Leaving isDefault().");
  return (realm || current()).id === DEFAULT_ID;
}

// Run `fn` with `realm` as the ambient realm, for `fn` and for everything it
// awaits, schedules or calls back into. The return value is fn's.
function run(realm, fn) {
  log.debug("Entering run().");
  log.debug("Leaving run().");
  return als.run(realm || DEFAULT_REALM, fn);
}

// The same thing as a wrapper, for the callback-shaped surfaces — an LDAP
// handler, a gRPC method, a datagram listener — that are handed a function
// rather than being called inside one.
function bind(realm, fn) {
  log.debug("Entering bind().");
  const captured = realm || DEFAULT_REALM;
  log.debug("Leaving bind().");
  return function () {
    const args = arguments;
    const self = this;
    return als.run(captured, function () {
      return fn.apply(self, args);
    });
  };
}

// ---------------------------------------------------------------------------
// IS ANY OF THIS SWITCHED ON?
//
// False when nobody has defined a realm, and the whole file is then inert: the
// middleware strips nothing, baseUrlOf() appends nothing, the stores below hand
// out one partition, and `helpers.STS` is one key. That is what makes "a
// service with only the default realm behaves exactly as it did" a property of
// one predicate rather than a claim spread over twenty files.
//
// `realms.enabled` can turn it off with realms defined, which is what an
// operator reaches for when a realm is answering something it should not: the
// definitions stay, the paths stop working, and nothing has to be deleted to
// find out whether a realm is the reason for something.
// ---------------------------------------------------------------------------
function active() {
  log.debug("Entering active().");
  log.debug("Leaving active().");
  return realms.size > 0 && config.value('realms.enabled');
}

// ---------------------------------------------------------------------------
// THE PATH PREFIX.
//
// `/realm/<id>` by default. The segment is a setting rather than a constant
// because `realm` is a word an operator may already be using for something in
// front of this service — and because setting it to the empty string gives the
// bare `/<id>/oauth2/token` shape, which is what somebody porting a client from
// a product that spells it that way will want. The empty form is NOT the
// default, and the reason is the collision: with no segment, a realm called
// `admin` or `oauth2` would shadow this service's own routes. `validateId()`
// refuses those names in either form, so the collision cannot be created; the
// segment is still what makes it impossible rather than merely refused.
// ---------------------------------------------------------------------------
function pathSegment() {
  log.debug("Entering pathSegment().");
  log.debug("Leaving pathSegment().");
  return String(config.value('realms.pathSegment') || '').replace(/^\/+|\/+$/g,
                                                                  '');
}

function prefixOf(realm) {
  log.debug("Entering prefixOf().");
  const r = realm || current();
  if (r.id === DEFAULT_ID || !active()) {
    log.debug("Leaving prefixOf().");
    return '';
  }
  const segment = pathSegment();
  log.debug("Leaving prefixOf().");
  return '/' + (segment ? segment + '/' : '') + r.id;
}

// The prefix of whatever realm is ambient. THE function every URL builder
// wants, and the reason `baseUrlOf()` could absorb this for eighty callers.
function currentPrefix() {
  log.debug("Entering currentPrefix().");
  log.debug("Leaving currentPrefix().");
  return prefixOf(current());
}

// A root-relative path, in the current realm. Root-relative and absolute URLs
// alike pass through untouched — an absolute one names a host, and this service
// is not entitled to put its own realm into somebody else's URL.
function href(path) {
  log.debug("Entering href().");
  const prefix = currentPrefix();
  if (!prefix || typeof path !== 'string' || path.charAt(0) !== '/') {
    log.debug("Leaving href().");
    return path;
  }
  // Already prefixed. A caller that built a URL out of baseUrlOf() and then
  // handed it here would otherwise get /realm/acme/realm/acme/oauth2/token,
  // and the symptom is a 404 a long way from the second call.
  if (path === prefix || path.indexOf(prefix + '/') === 0) {
    log.debug("Leaving href().");
    return path;
  }
  log.debug("Leaving href().");
  return prefix + path;
}

// ---------------------------------------------------------------------------
// MATCHING A PATH.
//
// Returns `{ realm, rest }` when the path opens with a defined realm's prefix,
// and null otherwise — including for a path that opens with the SEGMENT and an
// undefined realm. That case deliberately falls through to Express's own 404
// rather than being answered here: `Cannot GET /realm/nope/oauth2/token` is
// what this repository's own tests/vendored/sts_metadata.js uses to tell an
// unrouted path from an endpoint legitimately answering 404, and a prettier
// refusal for unknown realms would break that distinction for every path under
// the segment. `GET /realms` is where somebody finds out what the realms
// actually are.
// ---------------------------------------------------------------------------
function matchPath(pathname) {
  log.debug("Entering matchPath().");
  if (!active()) {
    log.debug("Leaving matchPath().");
    return null;
  }
  const segment = pathSegment();
  let head = String(pathname || '');
  if (segment) {
    if (head.indexOf('/' + segment + '/') !== 0) {
      log.debug("Leaving matchPath().");
      return null;
    }
    head = head.slice(segment.length + 1);
  }
  // head is now "/<id>..." — take one segment of it.
  const slash = head.indexOf('/', 1);
  const id = (slash < 0 ? head.slice(1) : head.slice(1, slash));
  const realm = realms.get(id);
  if (!realm) {
    log.debug("Leaving matchPath().");
    return null;
  }
  const rest = slash < 0 ? '/' : head.slice(slash);
  log.debug("Leaving matchPath().");
  return { realm: realm, rest: rest || '/' };
}

// ---------------------------------------------------------------------------
// COULD THIS PATH NAME A REALM THIS PROCESS HAS NOT HEARD OF YET? (2026-09-14,
// #46)
//
// True when the path opens with the realm prefix and an id that is a valid
// realm id and is not defined here. `common/app.js`'s realm middleware asks it
// before letting such a path fall through to Express's 404, because on an
// active-active node "not defined here" can mean "defined on the other node a
// moment ago": a realm created on node A answered 404 on node B's first
// request two times in six, since the realm middleware runs before the cluster
// barrier that would have applied the realm. The middleware catches up and
// matches again; this only says when that is worth a round trip.
//
// Deliberately NOT `realms.enabled`-and-`active()` gated like matchPath(): a
// node whose FIRST realm is the one being created elsewhere has no realms, so
// `active()` is false there until it catches up — which is exactly the case.
//
// **WITH AN EMPTY `realms.pathSegment` EVERY PATH OPENS "/<id>"**, so the first
// segment of every registered route is excluded (the same list realm creation
// refuses, read from the router once and kept: routes are all registered
// before the first request) — or every mistyped path would be a barrier.
// ---------------------------------------------------------------------------
let routePrefixes = null;

function unknownRealmPath(pathname) {
  log.debug("Entering unknownRealmPath().");
  if (!config.value('realms.enabled')) {
    log.debug("Leaving unknownRealmPath(). Realms are off.");
    return false;
  }
  const segment = pathSegment();
  let head = String(pathname || '');
  if (segment) {
    if (head.indexOf('/' + segment + '/') !== 0) {
      log.debug("Leaving unknownRealmPath(). No realm prefix.");
      return false;
    }
    head = head.slice(segment.length + 1);
  }
  const slash = head.indexOf('/', 1);
  const id = slash < 0 ? head.slice(1) : head.slice(1, slash);
  if (!ID_PATTERN.test(id) || realms.has(id) || id === DEFAULT_ID) {
    log.debug("Leaving unknownRealmPath(). Not an unknown realm id.");
    return false;
  }
  if (!segment) {
    if (!routePrefixes) {
      routePrefixes = new Set(reserved().map(function (one) {
        return String(one).toLowerCase();
      }));
    }
    if (routePrefixes.has(id)) {
      log.debug("Leaving unknownRealmPath(). A route, not a realm.");
      return false;
    }
  }
  log.debug("Leaving unknownRealmPath(). Possibly a realm not yet here.");
  return true;
}

// ---------------------------------------------------------------------------
// READING THE REGISTRY.
// ---------------------------------------------------------------------------
function get(id) {
  log.debug("Entering get().");
  if (!id || id === DEFAULT_ID) {
    log.debug("Leaving get().");
    return DEFAULT_REALM;
  }
  log.debug("Leaving get().");
  return realms.get(String(id)) || null;
}

// Every realm, the default one first. It is prepended rather than stored so
// that it cannot be edited out of the table by anything that iterates.
function list() {
  log.debug("Entering list().");
  log.debug("Leaving list().");
  return [DEFAULT_REALM].concat(Array.from(realms.values()));
}

function count() {
  log.debug("Entering count().");
  log.debug("Leaving count().");
  return realms.size + 1;
}

// ---------------------------------------------------------------------------
// WHAT A REALM MAY BE CALLED.
//
// The id is a PATH SEGMENT, a store key and half of an issuer identifier, so it
// is deliberately narrower than a name: lower-case, digits and hyphens, and it
// must start with a letter or a digit. Everything a person wants to read is in
// `name` and `description`, which are free text.
//
// The reserved list is the one that has already cost something in this
// codebase's shape: with `realms.pathSegment` set to empty, a realm called
// `admin` would shadow the console and a realm called `oauth2` would shadow the
// authorization server — and the shadowing would be silent, because the realm
// middleware runs BEFORE the router. It is refused whatever the segment is set
// to, because the segment is runtime-settable: a realm created under a segment
// and legal there would otherwise become a shadow the moment somebody cleared
// it, and the failure would arrive as "the console stopped existing".
// ---------------------------------------------------------------------------
const ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,30}$/;

// The first segment of every route this service actually has, DERIVED FROM THE
// LIVE ROUTER rather than typed, so that a protocol family added tomorrow
// protects itself without anybody remembering to add it to a list here.
//
// It is a FUNCTION app.js installs rather than an array it hands over, and the
// timing is the whole reason: app.js is loaded before a single protocol module
// registers anything — it has to be, since middleware only applies to routes
// added after it — so an array captured there would be empty. A realm is
// created long after startup, so asking the router at that moment is asking it
// when the answer is complete. It is the same decision /admin/sts-metadata
// makes about the same data, and for the same reason.
let reservedProvider = function () {
  log.debug("Entering reservedProvider().");
  log.debug("Leaving reservedProvider().");
  return [];
};

function reserve(provider) {
  log.debug("Entering reserve().");
  reservedProvider = typeof provider === 'function'
    ? provider
    : function () { return provider || []; };
  log.debug("Leaving reserve().");
}

function reserved() {
  log.debug("Entering reserved().");
  let paths = [];
  try {
    paths = reservedProvider() || [];
  } catch (e) {
    // The router is a private member of express and this is the one place that
    // walks it for a REFUSAL rather than for a report. An express that changed
    // shape must not stop a realm from being created — it must stop the
    // refusal being silent, which is what this line does.
    log.warn(errorCodes.tag('STS-CORE-0017') +
             'realms: could not read the router to reserve realm ids: ' +
             e.message);
  }
  log.debug("Leaving reserved().");
  return paths;
}

function validateId(id) {
  log.debug("Entering validateId().");
  const errors = [];
  const value = String(id == null ? '' : id);
  if (!ID_PATTERN.test(value)) {
    errors.push('A realm id is lower-case letters, digits and hyphens, ' +
                'starts with a letter or a digit and is at most 31 ' +
                'characters. "' + value + '" is not.');
    firstCode(errors, 'STS-CORE-0009');
    log.debug("Leaving validateId().");
    return errors;
  }
  if (value === DEFAULT_ID) {
    errors.push('"' + DEFAULT_ID + '" is the built-in realm and cannot be ' +
                                   'redefined.');
    firstCode(errors, 'STS-CORE-0010');
  }
  if (reserved().indexOf(value) >= 0) {
    errors.push('"' + value + '" is the first segment of a path this service ' +
                'already serves. A realm may not be called that, whatever ' +
                'realms.pathSegment is set to, because clearing that setting ' +
                'would make the realm shadow the endpoint.');
    firstCode(errors, 'STS-CORE-0011');
  }
  if (realms.has(value)) {
    errors.push('A realm called "' + value + '" is already defined.');
    firstCode(errors, 'STS-CORE-0012');
  }
  log.debug("Leaving validateId().");
  return errors;
}

// ---------------------------------------------------------------------------
// WRITING THE REGISTRY.
//
// Every refusal comes back as a LIST OF STRINGS rather than a thrown error,
// which is the shape config.js chose and for the same reason: both callers —
// the console's form handler and the management API — have to turn it into a
// reply rather than a stack trace.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// A NEW REALM IS BORN WITH ITS OWN NAMES FOR THE THINGS THAT ARE NAMES.
//
// Six settings in this service are IDENTIFIERS rather than behaviour: the SAML
// 2.0 identity provider entityID, the SAML 1.1 providerID, the WS-Federation
// entityID, the WS-Trust token issuer, the SAML assertion issuer and the
// OpenID4VP verifier client id. Every one of them defaults to a fixed string,
// and two realms carrying one of those strings is not a configuration choice —
// it is two identity providers claiming one entityID, which is precisely the
// thing a service provider is entitled to refuse.
//
// So a realm is created with each of them suffixed with its id. THE OAUTH
// ISSUER IS DELIBERATELY NOT IN THIS LIST: `oauth2.issuer` defaults to empty,
// which means "name the base URL this request arrived on", and the base URL
// already carries the realm prefix — so it is realm-distinct without help, and
// pinning it here would take away the property that makes the same process
// answer correctly as localhost, as `sts` on a compose network and through a
// published port.
//
// THEY ARE ORDINARY SETTINGS ON THE REALM and are listed as such on
// /admin/realms, which is the whole reason this is done at creation rather than
// inside the six reads. An operator can see exactly what was chosen, change any
// of it, or unset it and go back to sharing the process's name — a realm
// deliberately impersonating another is a case worth being able to build on a
// mock. What a derivation buried in a getter would give instead is six values
// that cannot be seen and cannot be changed.
//
// `krb5.realm` IS NOT HERE, and since 2026-09-15 that is a decision rather than
// a limit. Until then it could not be: the principal database was built from it
// once, when the process started, which is why Kerberos was `none` in
// realmSupport(). A realm now builds a principal database of its own when its
// Kerberos is turned on, so `krb5.realm` is `realmRuntime` — and rcbj chose
// that the operator NAMES a realm's Kerberos realm rather than this inventing
// `ACME.EXAMPLE.COM`. See SEEDED_FOR_REALM below, which turns it off.
// ---------------------------------------------------------------------------
const NAMED_BY_REALM = [
  { key: 'saml2.entityId', join: ':' },
  { key: 'saml11.providerId', join: ':' },
  { key: 'wsfed.entityId', join: ':' },
  { key: 'wstrust.issuer', join: ':' },
  { key: 'saml.issuer', join: ':' },
  { key: 'oid4vp.clientId', join: '-' },
  // ---------------------------------------------------------------------
  // **THE SEVENTH IS THE SPIFFE TRUST DOMAIN (2026-09-12), AND IT IS THE
  // FIRST ONE THAT GOES IN FRONT.**
  //
  // It belongs on this list for the list's own reason and not by analogy: a
  // trust domain is the authority part of every SPIFFE ID an issuing
  // authority mints, so two realms sharing one are two authorities claiming
  // one name — and an SVID from either is then ambiguous in exactly the way
  // two identity providers sharing an entityID are. `spiffe://example.org/w`
  // issued by the default realm and by `acme` would be one identifier over
  // two key sets.
  //
  // `prefix` is what this row adds to the shape. The six above SUFFIX
  // (`urn:…:acme`), because what they name is an entity and a longer name is
  // still a name. A trust domain is a DNS-shaped label whose structure runs
  // the other way — `acme.example.org` is beneath `example.org` and
  // `example.org.acme` is beneath nothing — and rcbj's instruction was a
  // COMMON ROOT with a unique issuer under it, which is that word for word.
  { key: 'spiffe.trustDomain', join: '.', prefix: true }
];

// ---------------------------------------------------------------------------
// AND THE THINGS A REALM MUST NOT INHERIT AT ALL (2026-09-12).
//
// A second list, because it is a different claim. The one above is about
// names that must be DISTINCT; this is about defaults that must be OFF — a
// realm is created without the SPIFFE protocol, at rcbj's instruction and for
// a reason the seeded names do not carry:
//
//   * a realm's SPIFFE is not one more view onto a shared surface. Turning it
//     on BINDS SOCKETS — a Workload API and a SPIRE Server API of that realm's
//     own, on an address of its own — and a realm that bound two listeners
//     merely by existing would make `POST /admin-api/realms/create` an
//     operation that opens ports, which is not what anybody asking for a realm
//     is asking for;
//   * and what comes out of those sockets is a CREDENTIAL another service will
//     believe, issued by an authority that attests nothing. The service-wide
//     posture is that this is deliberate and said out loud on every SPIFFE
//     surface; making it the automatic consequence of creating a realm would
//     be that posture arrived at by nobody.
//
// The default realm is untouched: `spiffe.enabled` defaults to true for the
// process, which is the service this repository has always been.
//
// THE SOCKET PATHS ARE HERE FOR A THIRD REASON, and it is the plainest one in
// this file: two processes cannot bind one Unix socket path, and neither can
// two realms. A realm that inherited `/tmp/spire-agent/public/api.sock` would
// fail to bind, or — worse, on a stale socket — would take it away from the
// realm that had it.
// ---------------------------------------------------------------------------
//
// **AND THE TCP LISTENERS AND THE ADMINISTRATORS ARE HERE FOR A FOURTH
// (2026-09-12).** A realm seeded only its socket paths, so it inherited the
// default realm's `spiffe.workloadPort` (8092), `spiffe.serverPort` (8181) and
// `spiffe.grpcHost` (0.0.0.0) — addresses the default realm is already
// listening on. Turning a realm's SPIFFE on therefore produced two refused
// binds every time, explained by `spiffe_server.js`'s refusal but reached by
// nobody's choice. Two ways out were considered:
//
//   * DISTINCT PORTS per realm. Rejected: `spiffe/CLAUDE.md` argues that a
//     realm is told apart by an ADDRESS with the ports unchanged, so a client
//     configured for :8092 reaches every realm where it expects to — and there
//     is no port this file could pick that is guaranteed free on the host.
//   * THE TCP LISTENERS OFF (port 0) until an operator gives the realm an
//     address. TAKEN. This file cannot know which addresses this machine has,
//     so it cannot choose one; what it can do is not bind the one address it
//     knows is taken. A realm turned on gets its two Unix sockets, which work,
//     and the SPIRE Server API — the network-reachable administrative surface
//     that mints credentials — is opened on TCP only by somebody deciding to:
//     set `spiffe.grpcHost` to an address of the realm's own and the two ports
//     back to 8092 / 8181 on the realm.
//
// `spiffe.adminIds` is seeded EMPTY for the same kind of reason: the process's
// list names SPIFFE IDs in the DEFAULT realm's trust domain, and a realm is a
// different trust domain. None of those ids could verify there — nothing in
// the realm signs them — so inheriting the list granted nothing, but it
// published administrators on `/realm/<id>/spiffe` who are not administrators
// of anything in it. `keepEmpty` is what lets an empty value be seeded at all.
//
// **`krb5.enabled` IS SEEDED OFF FOR THE SPIFFE REASON (2026-09-15).** A
// realm's Kerberos is a KDC of its own on the shared port 88, routed on the
// realm name in each request, and what it issues is a ticket another service
// will believe — so it is not the automatic consequence of creating a realm
// either. Unlike SPIFFE's trust domain the realm NAME is not seeded: rcbj's
// decision was that the operator names it, and turning Kerberos on is refused
// until the realm carries a `krb5.realm` of its own that no other realm has.
// See `kerberosOverrideProblem()` below.
// ---------------------------------------------------------------------------
const SEEDED_FOR_REALM = [
  { key: 'krb5.enabled', value: function () {
    log.debug("Entering value().");
    log.debug("Leaving value().");
    return false;
  } },
  { key: 'spiffe.enabled', value: function () {
    log.debug("Entering value().");
    log.debug("Leaving value().");
    return false;
  } },
  { key: 'spiffe.workloadSocket', value: function (id) {
      log.debug("Entering value().");
      log.debug("Leaving value().");
      return socketPathFor('spiffe.workloadSocket', id);
    } },
  { key: 'spiffe.serverSocket', value: function (id) {
      log.debug("Entering value().");
      log.debug("Leaving value().");
      return socketPathFor('spiffe.serverSocket', id);
    } },
  { key: 'spiffe.workloadPort', value: function () {
    log.debug("Entering value().");
    log.debug("Leaving value().");
    return 0;
  } },
  { key: 'spiffe.serverPort', value: function () {
    log.debug("Entering value().");
    log.debug("Leaving value().");
    return 0;
  } },
  { key: 'spiffe.adminIds', value: function () {
    log.debug("Entering value().");
    log.debug("Leaving value().");
    return '';
  },
    keepEmpty: true }
];

// `/tmp/spire-agent/public/api.sock` for the default realm becomes
// `/tmp/spire-agent/public/acme/api.sock` for `acme` — the realm as a
// DIRECTORY rather than a suffix on the filename, because that is what SPIRE's
// own layout does with a second agent and because a client is pointed at a
// directory far more often than at a file.
function socketPathFor(key, id) {
  log.debug("Entering socketPathFor().");
  const base = run(DEFAULT_REALM, function () {
    return String(config.value(key) || '');
  });
  if (!base) {
    log.debug("Leaving socketPathFor().");
    return '';
  }
  const cut = base.lastIndexOf('/');
  if (cut < 0) {
    log.debug("Leaving socketPathFor().");
    return id + '-' + base;
  }
  log.debug("Leaving socketPathFor().");
  return base.slice(0, cut) + '/' + id + base.slice(cut);
}

function seededNames(id) {
  log.debug("Entering seededNames(). id=" + id);
  const out = {};
  NAMED_BY_REALM.forEach(function (row) {
    // Read OUTSIDE any realm — this runs from a request that arrived in some
    // other realm, and what is wanted is the process's name rather than that
    // realm's, or a realm created from inside `acme` would be called
    // `…:acme:beta`.
    const base = run(DEFAULT_REALM, function () {
      return config.value(row.key);
    });
    if (base) {
      out[row.key] = row.prefix
        ? id + row.join + String(base)
        : String(base) + row.join + id;
    }
  });
  SEEDED_FOR_REALM.forEach(function (row) {
    const value = row.value(id);
    if (value === undefined || value === null) {
      return;
    }
    if (value !== '' || row.keepEmpty) {
      out[row.key] = value;
    }
  });
  log.debug("Leaving seededNames(). " + Object.keys(out).length + " name(s).");
  return out;
}

function create(spec) {
  log.debug("Entering create(). id=" + (spec || {}).id);
  const id = String((spec || {}).id || '').trim().toLowerCase();
  const errors = validateId(id);
  if (errors.length) {
    log.debug("Leaving create(). Refused: " + errors.join(' '));
    return errorCodes.mark({ ok: false, errors: errors },
                           errorCodes.codeOf(errors));
  }
  const overrideErrors = checkOverrides((spec || {}).overrides);
  if (overrideErrors.length) {
    log.debug("Leaving create(). Refused for its overrides.");
    return errorCodes.mark({ ok: false, errors: overrideErrors },
                           errorCodes.codeOf(overrideErrors));
  }
  // Not for a realm the store or another process hands back — see
  // kerberosOverrideProblem() for why a restore is never refused for this.
  if (!(spec && spec.restored)) {
    const kerberos = refusedForKerberos(id, Object.assign(seededNames(id),
      (spec || {}).overrides || {}), {});
    if (kerberos) {
      log.debug("Leaving create(). Refused for its Kerberos settings.");
      return kerberos;
    }
  }
  const realm = {
    id: id,
    name: String((spec || {}).name || id).trim() || id,
    description: String((spec || {}).description || '').trim(),
    builtin: false,
    createdAt: Date.now(),
    // The seeded names first, so that anything the caller asked for wins over
    // them. A management API call that names its own entityID means it.
    overrides: Object.assign(seededNames(id), (spec || {}).overrides || {})
  };
  realms.set(id, realm);
  // A realm removed and defined again takes rows again. See acceptsRows().
  retired.delete(id);
  log.info('realms: "' + id + '" defined; its endpoints are under ' +
           prefixOf(realm) + '/.');
  // AFTER the row is written, because a builder may want to read the realm
  // back through get() — and because a builder that throws must leave a realm
  // that exists rather than half of one. See onCreate() above.
  built(realm);
  // And after the builders, so that a watcher writing the registry down does
  // it once the realm is whole. See onChange() above.
  // `restored` rides along for a watcher that must tell a realm somebody
  // CREATED here from one this process only learnt about — `persistence.js`
  // restores a stored or replicated realm through this same function, and
  // `pki.js` builds a certificate branch for the first and not the second.
  changed(realm.id, 'create', { restored: !!(spec && spec.restored) });
  log.debug("Leaving create().");
  return { ok: true, errors: [], realm: realm };
}

function update(id, changes) {
  log.debug("Entering update(). id=" + id);
  const realm = realms.get(String(id || ''));
  if (!realm) {
    log.debug("Leaving update(). No such realm.");
    return errorCodes.mark({ ok: false,
                             errors: ['No realm called "' + id + '" ' +
        'is defined.'] },
                           'STS-CORE-0013');
  }
  const spec = changes || {};
  if (spec.overrides !== undefined) {
    const overrideErrors = checkOverrides(spec.overrides);
    if (overrideErrors.length) {
      log.debug("Leaving update(). Refused for its overrides.");
      return errorCodes.mark({ ok: false, errors: overrideErrors },
                             errorCodes.codeOf(overrideErrors));
    }
    // A REPLICATED update is not asked, for a restore's reason: the process
    // that made the change already was, and refusing it here would leave two
    // processes holding different overrides for one realm.
    const kerberos = spec.replicated ? null :
      refusedForKerberos(realm.id, spec.overrides, realm.overrides);
    if (kerberos) {
      log.debug("Leaving update(). Refused for its Kerberos settings.");
      return kerberos;
    }
    realm.overrides = Object.assign({}, spec.overrides);
  }
  if (spec.name !== undefined) {
    realm.name = String(spec.name).trim() || realm.id;
  }
  if (spec.description !== undefined) {
    realm.description = String(spec.description).trim();
  }
  log.info('realms: "' + realm.id + '" updated.');
  changed(realm.id, 'update');
  log.debug("Leaving update().");
  return { ok: true, errors: [], realm: realm };
}

// ---------------------------------------------------------------------------
// THE WRITING END OF THE `realms.*` RULE, AND IT WAS MISSING UNTIL 2026-08-25.
//
// `config.js`'s `realmFor()` answers null for any key starting `realms.`, so a
// realm can never CARRY one of those settings: a realm that could switch realms
// off, or move the prefix it was found under, would be doing it half way
// through the request that found it. The comment above that function calls
// itself "the second of two locks on one door" and says the writing end refuses
// as well — **and the writing end did not**. `POST /admin-api/realms/set` with
// `realms.pathSegment` answered `ok: true` and stored it on the realm, where
// nothing would ever read it. The value was inert, so nothing MISBEHAVED; what
// was wrong is worse than inert, because `GET /admin-api/realms` then listed
// that key among the realm's settings — the API asserting that a realm carries
// a prefix setting no reader will ever consult.
//
// So this is that lock, and every writing path into a realm's overrides goes
// through it: `setOverride()` below and `checkOverrides()` — which is what
// `create()` and `update()` validate a whole object with. One predicate rather
// than three copies, for the reason `gateStateFor()` exists: the two that were
// written separately disagreed within the hour.
//
// It matches by PREFIX rather than naming the two settings, so a third
// `realms.*` setting is refused the day it is added rather than the day
// somebody remembers this function.
//
// THE SECOND REFUSAL IS `perProcess`, AND IT IS A DIFFERENT RULE. A setting
// carrying that flag is a property of the OS PROCESS rather than of the
// service's behaviour — `workers.count`, the size of the child-process pool the
// post-quantum signing is handed to, is the first — so one realm's value would
// silently be every realm's. The predicate is config.js's own
// `isPerProcess()` and not a copy of it, for the reason this whole function
// exists: the reading end and the writing end of one rule, written separately,
// disagreed within the hour.
function checkRealmOverride(key, raw) {
  log.debug("Entering checkRealmOverride().");
  if (String(key || '').indexOf('realms.') === 0) {
    log.debug("Leaving checkRealmOverride().");
    return '"' + key + '" cannot be set on one realm: it is what decides ' +
      'whether realms exist and where they are found, so a realm carrying it ' +
      'would be changing how it was reached half way through the request ' +
      'that reached it. Set it on the service as a whole — /admin/oauth2, or ' +
      'POST /admin-api/config/set.';
  }
  if (config.isPerProcess(key)) {
    log.debug("Leaving checkRealmOverride().");
    return '"' + key + '" cannot be set on one realm: it is a property of ' +
      'this OS PROCESS rather than of how a realm behaves, so a realm ' +
      'carrying it would be setting it for every other realm as well. Set it ' +
      'on the service as a whole — /admin/config, or POST ' +
      '/admin-api/config/set.';
  }
  log.debug("Leaving checkRealmOverride().");
  // `true` is the `forRealm` argument, and it is what admits the one setting
  // that is restart-only for the PROCESS and legitimate on a realm:
  // `oauth2.rfc9700`. See the `realmRuntime` paragraph at the top of config.js
  // — a realm binds no socket, so the reason that flag is restart-only (it
  // derives `global.https`, and a listener's scheme is settled when it is
  // bound) is not a reason a realm cannot carry it. Everything else that is
  // restart-only is still refused here, in the same sentence as before.
  return config.checkOverride(key, raw, true);
}

// WHICH CONDITION checkRealmOverride() REFUSED FOR, in its order: the two rules
// that are this file's, then config.js's own three through its twin.
function checkRealmOverrideCode(key, raw) {
  log.debug("Entering checkRealmOverrideCode().");
  if (String(key || '').indexOf('realms.') === 0) {
    log.debug("Leaving checkRealmOverrideCode().");
    return 'STS-CORE-0014';
  }
  if (config.isPerProcess(key)) {
    log.debug("Leaving checkRealmOverrideCode().");
    return 'STS-CORE-0015';
  }
  log.debug("Leaving checkRealmOverrideCode().");
  return config.checkOverrideCode(key, raw, true);
}

// One setting, set or cleared on one realm. Separate from update() because the
// console's configuration page edits a section at a time and the management API
// edits a key at a time, and neither wants to send the whole override object
// back to change one row of it.
function setOverride(id, key, raw) {
  log.debug("Entering setOverride(). id=" + id + ", key=" + key);
  const realm = realms.get(String(id || ''));
  if (!realm) {
    log.debug("Leaving setOverride(). No such realm.");
    return errorCodes.mark({ ok: false,
                             errors: ['No realm called "' + id + '" ' +
        'is defined.'] },
                           'STS-CORE-0013');
  }
  const problem = checkRealmOverride(key, raw);
  if (problem) {
    log.debug("Leaving setOverride(). Refused: " + problem);
    return errorCodes.mark({ ok: false, errors: [problem] },
                           checkRealmOverrideCode(key, raw));
  }
  const after = Object.assign({}, realm.overrides);
  after[key] = raw;
  const kerberos = refusedForKerberos(realm.id, after, realm.overrides);
  if (kerberos) {
    log.debug("Leaving setOverride(). Refused for its Kerberos settings.");
    return kerberos;
  }
  realm.overrides[key] = raw;
  log.info('realms: "' + realm.id + '" sets ' + key + '.');
  changed(realm.id, 'set-override');
  log.debug("Leaving setOverride().");
  return { ok: true, errors: [], key: key };
}

function clearOverride(id, key) {
  log.debug("Entering clearOverride(). id=" + id + ", key=" + key);
  const realm = realms.get(String(id || ''));
  if (!realm) {
    log.debug("Leaving clearOverride(). No such realm.");
    return errorCodes.mark({ ok: false,
                             errors: ['No realm called "' + id + '" ' +
        'is defined.'] },
                           'STS-CORE-0013');
  }
  if (!Object.prototype.hasOwnProperty.call(realm.overrides, key)) {
    log.debug("Leaving clearOverride(). Nothing was set.");
    return errorCodes.mark({ ok: false, errors: ['"' + key + '" is not set ' +
        'on realm "' +
      realm.id + '"; it already comes from what the whole service is ' +
      'configured with.'] }, 'STS-CORE-0016');
  }
  const after = Object.assign({}, realm.overrides);
  delete after[key];
  const kerberos = refusedForKerberos(realm.id, after, realm.overrides);
  if (kerberos) {
    log.debug("Leaving clearOverride(). Refused for its Kerberos settings.");
    return kerberos;
  }
  delete realm.overrides[key];
  log.info('realms: "' + realm.id + '" no longer sets ' + key + '.');
  changed(realm.id, 'clear-override');
  log.debug("Leaving clearOverride().");
  return { ok: true, errors: [], key: key };
}

// Validate a whole override object without applying any of it, which is the
// same all-or-nothing rule config.js's checkOverride() exists for: a realm that
// took three of four settings and refused the fourth would be a realm nobody
// asked for.
function checkOverrides(overrides) {
  log.debug("Entering checkOverrides().");
  const errors = [];
  Object.keys(overrides || {}).forEach(function (key) {
    // checkRealmOverride() and not config.checkOverride(), so that the two
    // `realms.*` settings are refused on a create and an update exactly as they
    // are on a set. This was the door the `create` fix opened: until 2026-08-25
    // `realmsAction()` dropped `overrides` on the floor, so nothing reached
    // here from that direction and the missing refusal could not be provoked.
    const problem = checkRealmOverride(key, overrides[key]);
    if (problem) {
      errors.push(problem);
      firstCode(errors, checkRealmOverrideCode(key, overrides[key]));
    }
  });
  log.debug("Leaving checkOverrides().");
  return errors;
}

// ---------------------------------------------------------------------------
// A REALM'S KERBEROS, AND THE THREE RULES A KEY-AT-A-TIME CHECK CANNOT MAKE
// (2026-09-15).
//
// Port 88 is one socket for every realm, and the KDC chooses the realm a
// request is for by the Kerberos realm NAME inside it. So three things about a
// realm's
// overrides are wrong together that are each fine alone, and
// checkRealmOverride() — which sees one key and no realm — cannot see any of
// them:
//
//   1. **KERBEROS ON WITH NO NAME OF ITS OWN** (STS-KRB-0123). The realm would
//      inherit the process's `krb5.realm`, and two realms answering to one name
//      is a request the KDC cannot route. rcbj's decision was that the operator
//      names it, so nothing is seeded and turning it on without one is refused.
//   2. **A NAME ANOTHER REALM ALREADY ANSWERS TO** (STS-KRB-0124) — another
//      realm's own `krb5.realm`, the default realm's, or `krb5.trustedRealm`,
//      which the default realm answers for in development. Compared without
//      regard to case: Kerberos names are case-sensitive on the wire, and two
//      realms that differ only in case are two realms a person cannot tell
//      apart in a krb5.conf.
//   3. **A RENAME, OR A CLEAR, WHILE IT IS ON** (STS-KRB-0125). Every key in
//      that realm's database is salted with the name, so a rename under a
//      running KDC would leave every person's stored keys naming a realm the
//      KDC no longer answers as. Turn it off, rename, turn it on.
//
// **THEY ARE ASKED IN THE ORDER 3, 1, 2**, which is not the order they are
// written in above: CLEARING the name of a realm whose Kerberos is on satisfies
// rule 1 as well (it is then on with no name), and the sentence somebody needs
// for that change is the one about keys being salted rather than the one about
// turning Kerberos on.
//
// Asked with the overrides a write WOULD leave (`after`) beside the ones it
// found (`before`), by every door that writes a realm's overrides. A realm
// RESTORED from the store is not asked: refusing to restore a realm because the
// process's own `krb5.realm` changed across a restart would lose the realm, and
// the KDC's router reports a collision it finds instead (krb5_principals.js).
// ---------------------------------------------------------------------------
function ownKerberosName(overrides) {
  log.debug("Entering ownKerberosName().");
  const raw = overrides && overrides['krb5.realm'];
  log.debug("Leaving ownKerberosName().");
  return raw === undefined || raw === null ? '' : String(raw).trim();
}

function ownKerberosEnabled(overrides) {
  log.debug("Entering ownKerberosEnabled().");
  if (!overrides ||
      !Object.prototype.hasOwnProperty.call(overrides, 'krb5.enabled')) {
    log.debug("Leaving ownKerberosEnabled(). Not set on the realm.");
    return false;
  }
  const parsed = config.parseAs('krb5.enabled', overrides['krb5.enabled']);
  log.debug("Leaving ownKerberosEnabled().");
  return !!(parsed.ok && parsed.value === true);
}

function kerberosOverrideProblem(id, after, before) {
  log.debug("Entering kerberosOverrideProblem(). id=" + id);
  const name = ownKerberosName(after);
  const enabled = ownKerberosEnabled(after);
  if (ownKerberosEnabled(before) && enabled &&
      name !== ownKerberosName(before)) {
    log.debug("Leaving kerberosOverrideProblem(). Renamed while on.");
    return { code: 'STS-KRB-0125',
             message: 'krb5.realm cannot be changed on realm "' + id + '" ' +
               'while its Kerberos is on: every key in that realm\'s ' +
               'principal database is salted with the name, so the people ' +
               'and services in it would hold keys for a realm the KDC no ' +
               'longer answers as. Turn krb5.enabled off, change the name, ' +
               'and turn it on again.' };
  }
  if (enabled && !name) {
    log.debug("Leaving kerberosOverrideProblem(). On with no name.");
    return { code: 'STS-KRB-0123',
             message: 'Kerberos cannot be turned on for realm "' + id + '" ' +
               'until it has a krb5.realm of its own. Port 88 is shared by ' +
               'every realm and a request is routed by the Kerberos realm ' +
               'name inside it, so a realm that inherited the service\'s ' +
               'name would be a second realm answering to it. Set krb5.realm ' +
               'on ' +
               'this realm first (in the same change is fine).' };
  }
  if (name && name !== ownKerberosName(before)) {
    const wanted = name.toUpperCase();
    const taken = [];
    const processName = String(run(DEFAULT_REALM, function () {
      return config.value('krb5.realm');
    }) || '');
    if (processName.toUpperCase() === wanted) {
      taken.push('the default realm, whose Kerberos realm is ' + processName);
    }
    const trusted = String(run(DEFAULT_REALM, function () {
      return config.value('krb5.trustedRealm');
    }) || '');
    if (trusted.toUpperCase() === wanted) {
      taken.push('krb5.trustedRealm, the second realm the default realm ' +
                 'answers for in development mode');
    }
    realms.forEach(function (other) {
      if (other.id !== id &&
          ownKerberosName(other.overrides).toUpperCase() === wanted) {
        taken.push('realm "' + other.id + '"');
      }
    });
    if (taken.length) {
      log.debug("Leaving kerberosOverrideProblem(). Name taken.");
      return { code: 'STS-KRB-0124',
               message: 'krb5.realm "' + name + '" cannot be given to realm "' +
                 id + '": ' + taken.join(' and ') + ' already answers to ' +
                 'that name (compared without regard to case). The KDC on ' +
                 'port 88 routes a request by that name, so two realms ' +
                 'holding it could not both be reached.' };
    }
  }
  log.debug("Leaving kerberosOverrideProblem().");
  return null;
}

// The same, as the `{ ok:false, errors }` answer every door here returns, or
// null when there is nothing to refuse.
function refusedForKerberos(id, after, before) {
  log.debug("Entering refusedForKerberos().");
  const problem = kerberosOverrideProblem(id, after, before);
  log.debug("Leaving refusedForKerberos().");
  return problem
    ? errorCodes.mark({ ok: false, errors: [problem.message] }, problem.code)
    : null;
}

// ---------------------------------------------------------------------------
// "A REALM ROW CHANGED", ADDED 2026-08-27 FOR PERSISTENCE, AND IT IS AN EVENT
// RATHER THAN A SLOT.
//
// `onCreate()` and `onRemove()` below already cover two of the five doors into
// this registry. The other three — `update()`, `setOverride()` and
// `clearOverride()` — had no hook at all, because until a realm could be
// written down there was nothing that needed to know a name or an override had
// changed. Now there is.
//
// **IT IS NOT ANOTHER INVERTED HOOK AND THE DISTINCTION IS WORTH KEEPING.**
// Rule 3e's slots exist because a require in the obvious direction would close
// a cycle or move a route, and the module on the far end fills a hole this one
// left. This is the opposite shape: `persistence/persistence.js` REQUIRES this
// file, in the ordinary direction, and subscribes. Nothing here knows what
// persistence is or whether any exists, and a process that never loaded that
// module has an empty listener list and behaves exactly as it did.
//
// It fires AFTER the change, for the reason `built()` runs after the registry
// row is written: a listener that reads the registry back must see what the
// caller just did. A listener that throws is logged and does not fail the
// operation — the realm IS renamed, and a persistence layer that could not
// write it down has not made that less true.
// ---------------------------------------------------------------------------
const watchers = [];

function onChange(fn) {
  log.debug("Entering onChange().");
  watchers.push(fn);
  log.debug("Leaving onChange().");
}

function changed(id, what, info) {
  log.debug("Entering changed(). id=" + id + ", what=" + what);
  watchers.forEach(function (watcher) {
    try {
      watcher(id, what, info || {});
    } catch (e) {
      // Swallowed and named: a watcher that cannot do its job must not undo
      // the caller's, and the caller's job here already succeeded.
      log.warn(errorCodes.tag('STS-CORE-0018') +
               'realms: a change watcher threw for "' + id + '" (' + what +
               '): ' + e.message);
    }
  });
  log.debug("Leaving changed(). " + watchers.length + " watcher(s).");
}

// ---------------------------------------------------------------------------
// REMOVING A REALM MUST TAKE ITS STATE WITH IT.
//
// Everything a realm accumulated — its sessions, its tokens, its authorization
// codes, its statistics, its audit log, its signing key — lives in the stores
// below, partitioned by realm id. If removal only dropped the registry row,
// creating a realm with the same id again would inherit the last one's sessions
// and tokens, which is the single most surprising thing a re-created realm
// could do. So every store registers a purge, and this is what calls them.
// ---------------------------------------------------------------------------
const purges = [];

// The ids removed in this process and not defined again. See acceptsRows().
const retired = new Set();

function onRemove(fn) {
  log.debug("Entering onRemove().");
  purges.push(fn);
  log.debug("Leaving onRemove().");
}

// ---------------------------------------------------------------------------
// AND THE OTHER END: A REALM THAT NEEDS SOMETHING BUILT MUST GET IT BUILT.
//
// `keyed()` covers every store that can be built LAZILY — a Map made on first
// touch, a signing key generated the first time something is signed — and that
// is almost all of them, which is why this hook did not exist until the
// embedded directory needed one.
//
// The directory is the case `keyed()` cannot answer, and it is worth being
// precise about why, because it IS a `map()` now. Each realm has a store of its
// own — `map()` would have made one lazily — but it is served by a SOCKET that
// has no realm on it: an `ldapsearch` arrives on 389 asking for a base DN, and
// "first touch" for a directory can be a client asking for a subtree that has
// never been written. A lazily-built store would answer that with an empty
// directory rather than the seeded one every other realm has, and an empty
// directory and LDAP_NO_SUCH_OBJECT are both wrong answers to "show me acme".
// So the realm's directory has to be BUILT from the moment the realm exists,
// which means a hook that fires on CREATE.
//
// A listener that throws does not stop the realm being created — the registry
// row is already written by then, exactly as `onRemove()`'s purges run after
// the row is deleted. The asymmetry is deliberate in both directions: a realm
// that exists with an unbuilt subtree is recoverable (build it), and a create
// that failed half way is not.
// ---------------------------------------------------------------------------
const builders = [];

function onCreate(fn) {
  log.debug("Entering onCreate().");
  builders.push(fn);
  log.debug("Leaving onCreate().");
}

function built(realm) {
  log.debug("Entering built(). id=" + realm.id);
  builders.forEach(function (build) {
    try {
      build(realm.id, realm);
    } catch (e) {
      log.warn(errorCodes.tag('STS-CORE-0019') +
               'realms: a store could not build itself for "' + realm.id +
               '": ' + e.message);
    }
  });
  log.debug("Leaving built(). " + builders.length + " store(s) built.");
}

function remove(id) {
  log.debug("Entering remove(). id=" + id);
  const realm = realms.get(String(id || ''));
  if (!realm) {
    log.debug("Leaving remove(). No such realm.");
    return errorCodes.mark({ ok: false,
                             errors: ['No realm called "' + id + '" ' +
        'is defined.'] },
                           'STS-CORE-0013');
  }
  realms.delete(realm.id);
  // Before the purges, so a replicated row arriving while they run is refused
  // rather than rebuilding a partition they just emptied. See acceptsRows().
  retired.add(realm.id);
  purges.forEach(function (purge) {
    try {
      purge(realm.id);
    } catch (e) {
      // A store that cannot purge itself must not stop the others from
      // purging, and it must not leave the registry row behind either — the
      // row is already gone above. Log it and carry on; the worst outcome is
      // state for an id nobody can reach any more.
      log.warn(errorCodes.tag('STS-CORE-0020') +
               'realms: a store refused to purge "' + realm.id + '": ' +
               e.message);
    }
  });
  log.info('realms: "' + realm.id + '" removed, with everything it held.');
  // AFTER the purges, and that ordering is the whole of what makes a removal
  // persist correctly: a watcher fired before them would walk stores that
  // still held the realm's entries and write them all back down.
  changed(realm.id, 'remove');
  log.debug("Leaving remove(). " + purges.length + " store(s) purged.");
  return { ok: true, errors: [], realm: realm };
}

// ---------------------------------------------------------------------------
// PER-REALM STORES.
//
// `map()`, `arr()` and `obj()` return something that behaves like a `Map`, an
// `Array` and a plain object and holds a SEPARATE one per realm. The point is
// the call sites: converting `const sessions = new Map()` to
// `const sessions = realms.map()` is one line, and the ninety places that do
// `sessions.get(id)` are unchanged and stay correct — they read the realm's
// map, because the realm is ambient.
//
// `keyed(factory)` is the general case for a store that is neither: it calls
// the factory once per realm, lazily, and hands back that realm's value. It is
// what gives each realm its own signing key.
//
// EVERY ONE OF THEM REGISTERS A PURGE, which is why they are here rather than
// three copies of a WeakMap trick in three modules.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// A PERSISTED STORE IS DECLARED PERSISTED, AND NOWHERE ELSE (2026-09-06).
//
// This is the rule two paragraphs up, read a second time. `common/CLAUDE.md`
// says a store becomes PER REALM at its declaration; since product mode
// learned to write down what this process MINTS, a store also becomes
// PERSISTENT at its declaration:
//
//     const sessions = realms.map({ persist: 'authn.sessions' });
//
// and every one of the ninety call sites is unchanged again, for the same
// reason: `set`, `delete` and `clear` on the facade below — and the `set` and
// `deleteProperty` traps on the two Proxies — are already the only ways any of
// these stores can be mutated. Naming the store is therefore enough to name
// every write to it, which is what makes this ~40 one-line edits rather than
// ~200 call-site edits.
//
// **WHY A JOURNAL RATHER THAN THE DIFF `persistence.js` USES.** That module
// compares the whole directory against a shadow, because `touchDirectory()`
// was already the one choke point and does not say which entry moved. These
// stores are the opposite case on both counts: each has two to four mutation
// points, so naming the key is POSSIBLE — and the rows are hot enough that a
// full JSON.stringify sweep per flush is not affordable, because in postgres
// mode the flush delay is 0 and a sweep of the audit ring and the token
// register would then run on every request that touched either. So the store
// reports the KEY, and the flush writes exactly that key.
//
// **THE OBSERVER IS AN INVERTED HOOK (rule 3e) AND IT PASSES THE TEST IN THE
// ONE DIRECTION THAT MATTERS.** `persistence/persistence_minted.js` requires
// this module — through `persistence.js`, which requires `config.js`, which
// this module fills a slot on — so a require from here to there closes a
// cycle, and node answers a cycle with a half-initialised module whose exports
// are `undefined`. The symptom would arrive later as "changed is not a
// function" from inside a session write.
//
// **AN UNFILLED SLOT MEANS "PERSIST NOTHING", WHICH IS EVERY DEVELOPMENT-MODE
// PROCESS, EVERY `npm test` AND EVERY MEMORY-MODE RUN.** That is the whole
// compatibility story here, and it is the same shape as the empty issuance
// decider in `common/issuance_gate.js`: the absent thing has the harmless
// answer, so a process that loaded half this service is a smaller service
// rather than a broken one.
// ---------------------------------------------------------------------------
let persistObserver = null;

function setPersistObserver(fn) {
  log.debug("Entering setPersistObserver().");
  if (typeof fn !== 'function') {
    log.error(errorCodes.tag('STS-CORE-0021') +
              'realms: setPersistObserver() was given a ' + typeof fn +
              ' rather than a function. Nothing minted will be written down.');
    log.debug("Leaving setPersistObserver(). Refused.");
    return false;
  }
  persistObserver = fn;
  log.info('realms: minted stores will now report their writes; ' +
           declaredHandles.length + ' store(s) were declared before this ' +
           'was installed and are all reachable, because the observer is ' +
           'consulted per write rather than captured at declaration.');
  log.debug("Leaving setPersistObserver(). Installed.");
  return true;
}

// EVERY HANDLE DECLARED, in declaration order. `persistence_minted.js` reads it
// to know what a restore may write into, and `tests/realm_isolation.js` reads
// it to check that no two stores claim one handle — two stores sharing a name
// would each overwrite the other's rows, and the first symptom would be one
// restart later.
const declaredHandles = [];

function declareHandle(options, shape, accessors) {
  log.debug("Entering declareHandle().");
  if (!options || !options.persist) {
    log.debug("Leaving declareHandle().");
    return null;
  }
  const handle = String(options.persist);
  const already = declaredHandles.find(function (row) {
    return row.handle === handle;
  });
  if (already) {
    // NOT thrown. A duplicate handle is a programming error, and throwing here
    // would happen at require time and take the whole service down over a
    // store that is at worst not persisted — which is the trade rule 1's
    // "a require that throws takes the service down where a route cannot"
    // already makes for the listeners.
    log.error(errorCodes.tag('STS-CORE-0022') +
              'realms: the handle "' + handle + '" is declared TWICE (' +
              already.shape + ' and ' + shape + '). The second declaration ' +
              'will not be persisted: two stores under one handle would ' +
              'each overwrite the other\'s rows, and the damage would only ' +
              'be visible one restart later.');
    log.debug("Leaving declareHandle().");
    return null;
  }
  declaredHandles.push({
    handle: handle,
    shape: shape,
    scope: options.scope === 'shared' ? 'shared' : 'realm',
    // -----------------------------------------------------------------------
    // HOW TWO PROCESSES' COPIES OF THIS STORE COMBINE, and it is declared here
    // for the same reason everything else about the store is: at the store,
    // once, where somebody changing it will see it.
    //
    //   'replace'  The default and the right answer for almost everything.
    //              The row is whole-valued, so the later write wins and both
    //              processes converge on it — which is EXACTLY the semantics
    //              a single process already has for two concurrent requests.
    //   'own'      This row is MINE. The store is an ACCUMULATOR — a counter
    //              that is incremented, or a ring that is appended to — so a
    //              later write is not a newer version of an earlier one and
    //              replacing would silently lose the other process's work.
    //              Each process writes only its own row, and the fan-in
    //              happens where the value is REPORTED.
    //
    // The test for 'own' is one question: **is a write to this store an
    // ASSIGNMENT or an INCREMENT?** `sessions.set(id, row)` is an assignment
    // and the last one is the truth. `nums.callTotal++` and `events.push(row)`
    // are increments, and there is no "last one".
    // -----------------------------------------------------------------------
    merge: options.merge === 'own' ? 'own' : 'replace',
    // -----------------------------------------------------------------------
    // TWO MORE THINGS A STORE SAYS ABOUT ITS ROWS WHEN SEVERAL NODES WRITE
    // THEM (2026-09-14, #46 section 3), both argued in
    // `persistence/persistence_minted.js`:
    //
    //   `tombstone: true`  A deleted key is ENDED, not merely absent: the
    //              store keeps a tombstone and refuses a later write of the
    //              key, so a node holding an old copy cannot bring back a
    //              session another node signed out. Only for keys that are
    //              random handles and never legitimately written again —
    //              never for a counter or anything keyed by a name.
    //   `mergeRow(mine, theirs)`  The row is edited IN PLACE and two nodes can
    //              each edit it; the flush reads the stored row under a lock
    //              and writes what this returns rather than its own copy.
    //              Must be pure and must converge: merging the answer with
    //              either side again gives the answer.
    // -----------------------------------------------------------------------
    tombstone: options.tombstone === true,
    mergeRow: typeof options.mergeRow === 'function' ? options.mergeRow : null,
    // ---------------------------------------------------------------------
    // `observation: true` (2026-09-15, #46): a write to this store is a TALLY
    // of what a request did — a decision counted — and not a thing the
    // request did. It is journalled and flushed like any other row, but it
    // does not by itself make a request one that WROTE, so the cluster
    // barrier does not hold a read for it (`cluster/CLAUDE.md`, rcbj's
    // decision 6). A request that wrote anything else is held, and the tally
    // rides that commit. `persistence_minted.js`'s `note()` keeps the count.
    // ---------------------------------------------------------------------
    observation: options.observation === true,
    // ---------------------------------------------------------------------
    // THE ACCESSORS LIVE ON THE REGISTRY ROW AND NOT ON THE STORE, and that is
    // the whole reason this is a registry at all. Two of the three shapes are
    // Proxies over a real Array and a real Object, and a `persistRead` member
    // hung on one of those would be a property name that shadows a row: an
    // audit event keyed "persistRead", a counter field of that name. Keeping
    // them here means a persisted store's public surface is EXACTLY the
    // surface it had before it was declared — `Array.isArray()`,
    // `Object.keys()` and a spread all answer what they always did.
    // ---------------------------------------------------------------------
    dump: accessors.dump,
    read: accessors.read,
    restore: accessors.restore,
    remove: accessors.remove
  });
  log.debug('realms: "' + handle + '" declared as a persistable ' + shape +
            '.');
  log.debug("Leaving declareHandle().");
  return handle;
}

// What a store calls when something in it moved. `key` is null for a
// whole-store change, which is what a counter object reports — those are one
// small row and rewriting it is cheaper than working out which field moved.
function noteWrite(handle, key) {
  log.debug("Entering noteWrite().");
  noteWriteIn(handle, currentId(), key);
  log.debug("Leaving noteWrite().");
}

// THE SAME, AGAINST A NAMED REALM RATHER THAN THE AMBIENT ONE. `realmMap(id)`
// hands out a partition BY NAME, and a write through it belongs to that realm
// however the ambient one happens to be set — a sweep walks every realm from
// outside all of them, and journalling those deletes against the default realm
// would leave the rows it removed standing in every other realm's store.
function noteWriteIn(handle, realmId, key) {
  log.debug("Entering noteWriteIn().");
  if (!handle || !persistObserver) {
    log.debug("Leaving noteWriteIn().");
    return;
  }
  try {
    persistObserver(handle, realmId, key === undefined ? null : key);
  } catch (e) {
    // SWALLOWED DELIBERATELY. This runs inside `sessions.set()`, which runs
    // inside a sign-in. A store that cannot journal its write must not fail
    // the request that made it — the same argument persistence.js makes about
    // a failed flush, one layer down.
    log.error(errorCodes.tag('STS-CORE-0023') +
              'realms: "' + handle + '" could not report a write: ' +
              e.message);
  }
  log.debug("Leaving noteWriteIn().");
}

// The handles, for the readers named above. The rows themselves rather than
// copies of them, because they carry the three accessor functions and a copy
// would be a second object claiming to be the same store.
function handles() {
  log.debug("Entering handles().");
  log.debug("Leaving handles().");
  return declaredHandles.slice();
}

// One row by name, or null. What a restore uses to find the store a stored
// handle belongs to — a handle in the store that nothing declares is an older
// build's row, and answering null is what lets the restore say so and move on
// rather than throwing on somebody else's data.
function handleFor(name) {
  log.debug("Entering handleFor().");
  log.debug("Leaving handleFor().");
  return declaredHandles.find(function (row) {
    return row.handle === String(name);
  }) || null;
}

// ---------------------------------------------------------------------------
// MUTATING ARRAY MEMBERS. Wrapped for a DECLARED array so that `push` and
// `shift` are seen — see the long comment in arr()'s `get` trap, which is
// where this list is used and why it exists.
// ---------------------------------------------------------------------------
const MUTATORS = ['push', 'pop', 'shift', 'unshift', 'splice', 'sort',
                  'reverse', 'fill', 'copyWithin'];

// ---------------------------------------------------------------------------
// THE PARTITION A REALM ID NAMES, and it exists because of a bug it already
// caught: `keyed()`'s internal Map is keyed by the id STRING, a write lands
// under `currentId()` — which is `'default'` in the default realm — and an
// empty string is a perfectly ordinary way to spell "the default realm"
// everywhere else in this service (it is what `prefixOf()` answers, and it is
// what a stored row carries for a shared store). Handing `''` to `per.of()`
// therefore built a SECOND, empty partition beside the real one, and the dump
// of a store somebody had just written to came back empty.
//
// **AN ID THIS PROCESS HAS NOT HEARD OF IS ITS OWN PARTITION, NOT THE DEFAULT
// REALM'S (2026-09-14).** This read `(get(realmId) || DEFAULT_REALM).id`, which
// normalised the empty string and ALSO sent every unknown id to the default
// realm. In a dispatched service a replicated row is often applied before the
// realm it belongs to has reached this process — a realm's stream, session or
// token is minted milliseconds after the realm is created, and the change log
// carries both — so `restore()` wrote it into the DEFAULT partition, the next
// in-place edit there journalled it as a default-realm row, and every process
// adopted it. Measured on a dispatch run: forty other realms' own Shared
// Signals receiver streams in the default realm, so every default-realm event
// was pushed forty-two times and forty of the pushes were refused and queued
// for ever. Keyed by the raw id, the rows wait in the partition the realm will
// use when it arrives.
// ---------------------------------------------------------------------------
function partitionId(realmId) {
  log.debug("Entering partitionId().");
  const id = String(realmId || '');
  log.debug("Leaving partitionId().");
  return !id || id === DEFAULT_ID ? DEFAULT_ID : id;
}

// ---------------------------------------------------------------------------
// WHETHER A STORED OR REPLICATED ROW MAY BE WRITTEN INTO A REALM'S PARTITION.
//
// False only for a realm this process REMOVED and has not defined again. A row
// for it arriving after the purge — replication is behind the removal by up to
// a poll interval — would otherwise rebuild the partition the purge emptied,
// and a realm defined again under the same id would inherit it, which is the
// one surprise `remove()`'s purges exist to prevent. An id this process has
// never heard of is accepted: that is the realm that has not arrived yet.
// `retired` itself is declared beside `purges`, above `create()` and
// `remove()`.
// ---------------------------------------------------------------------------
function acceptsRows(realmId) {
  log.debug("Entering acceptsRows().");
  log.debug("Leaving acceptsRows().");
  return !retired.has(partitionId(realmId));
}

function keyed(factory) {
  log.debug("Entering keyed().");
  const per = new Map();
  onRemove(function (id) { per.delete(id); });
  function forCurrent() {
    log.debug("Entering forCurrent().");
    const id = currentId();
    if (!per.has(id)) {
      per.set(id, factory(current()));
    }
    log.debug("Leaving forCurrent().");
    return per.get(id);
  }
  forCurrent.of = function (id) {
    log.debug("Entering of().");
    if (!per.has(id)) {
      per.set(id, factory(get(id) || DEFAULT_REALM));
    }
    log.debug("Leaving of().");
    return per.get(id);
  };
  forCurrent.existing = function () {
    log.debug("Entering existing().");
    log.debug("Leaving existing().");
    return per;
  };
  log.debug("Leaving keyed().");
  return forCurrent;
}

// A Map, per realm. Every member of the Map interface is delegated, including
// the iterator — `for (const [k, v] of store)` is a shape this codebase uses.
function map(options) {
  log.debug("Entering map().");
  const per = keyed(function () { return new Map(); });
  // `reconcile`, for a per-realm store partly built from code — see the
  // contract above sharedMap(). The two accessors below ask it exactly as
  // sharedMap()'s do, through the same two functions, with the realm the row
  // belongs to as a last argument a shared store has no use for.
  const reconcile = (options && options.reconcile) || {};
  const handleName = String((options && options.persist) || '(undeclared)');
  const handle = declareHandle(options, 'map', {
    // Every key in the realm's own partition. `per.of(id)` rather than `per()`
    // so that a flush does not have to be inside the realm to read it — which
    // it is anyway, but a dump that depends on ambient state is a dump that
    // silently returns the default realm's rows when somebody forgets.
    dump: function (realmId) {
      log.debug("Entering dump().");
      const out = [];
      per.of(partitionId(realmId)).forEach(function (v, k) {
        out.push({ key: k, value: v });
      });
      log.debug("Leaving dump().");
      return out;
    },
    read: function (realmId, k) {
      log.debug("Entering read().");
      const m = per.of(partitionId(realmId));
      log.debug("Leaving read().");
      return m.has(k) ? { present: true, value: m.get(k) } : { present: false };
    },
    // NOT `set`, and the difference is the point: this writes without
    // journalling, because what a restore just read out of the store is the
    // one thing that must not be written straight back into it.
    restore: function (realmId, k, v) {
      log.debug("Entering restore().");
      if (!acceptsRows(realmId)) {
        log.debug("Leaving restore(). The realm was removed here.");
        return;
      }
      const target = per.of(partitionId(realmId));
      reconciledRestore(handleName, reconcile, target, k, v,
                        partitionId(realmId));
      log.debug("Leaving restore().");
    },
    // WHAT A REPLICATED DELETE REACHES. It is a fourth accessor rather than a
    // `restore(…, undefined)` because "the value is undefined" and "the key is
    // gone" are different states, and a store that could not tell them apart
    // would answer `has(k) === true` for a key another process deleted.
    remove: function (realmId, k) {
      log.debug("Entering remove().");
      reconciledRemove(handleName, reconcile, per.of(partitionId(realmId)), k,
                       partitionId(realmId));
      log.debug("Leaving remove().");
    }
  });
  // ------------------------------------------------------------------------
  // `realmMap()` HANDS OUT A JOURNALLING VIEW AND NOT THE BARE Map
  // (2026-09-08).
  //
  // It used to return `per()` itself, and a write through it was invisible to
  // the journal — so it never reached the persistence store, never became a
  // change row, and never arrived in any other process. Every OTHER door on
  // this facade calls `noteWrite()`; this one was the hole, and it was not
  // theoretical: `authn.js` creates a RELYING PARTY session through it (the
  // console's and the portal's own sessions, since both surfaces became OpenID
  // Connect clients), expires a presented session through it, and sweeps every
  // realm's expired sessions through it. In the request-worker pool that is a
  // session the worker that minted it can see and no other worker can — the
  // console signed somebody in and `GET /admin-api/sessions`, which fans out,
  // listed no such session. It was equally wrong in one process: the rows were
  // simply never written, so nothing survived a restart and no delete was ever
  // recorded against a row that had been.
  //
  // A PROXY RATHER THAN A HAND-WRITTEN FACADE, because this really must be a
  // Map: callers read `.size`, iterate it with `for…of`, and hand it to code
  // that does either. Proxying the real Map keeps every one of those exact and
  // wraps only the three members that mutate. `set()` answers with the PROXY
  // and not the target, so a chained `set().set()` stays journalled.
  //
  // The realm is captured HERE rather than read at write time, for
  // `noteWriteIn()`'s reason: `realmMap(id)` means that realm's partition, and
  // the caller may well write to it from outside any realm at all.
  // ------------------------------------------------------------------------
  function viewOf(realmId, target) {
    log.debug("Entering viewOf().");
    if (!handle || !persistObserver) {
      log.debug("Leaving viewOf().");
      // Nothing is journalling this store, so there is nothing to wrap and the
      // bare Map is both correct and cheaper. `realms.map()` with no `persist`
      // is the ordinary case — the embedded directory is one — and it must not
      // pay for a Proxy on every entry it holds.
      return target;
    }
    const view = new Proxy(target, {
      get: function (t, prop) {
        log.debug("Entering get().");
        const value = Reflect.get(t, prop, t);
        if (typeof value !== 'function') {
          log.debug("Leaving get().");
          return value;
        }
        if (prop === 'set') {
          log.debug("Leaving get().");
          return function (k, v) {
            t.set(k, v);
            noteWriteIn(handle, realmId, k);
            return view;
          };
        }
        if (prop === 'delete') {
          log.debug("Leaving get().");
          return function (k) {
            const gone = t.delete(k);
            // Reported whether or not the key was there, for `delete()`'s
            // reason on the facade above.
            noteWriteIn(handle, realmId, k);
            return gone;
          };
        }
        if (prop === 'clear') {
          log.debug("Leaving get().");
          return function () {
            t.forEach(function (v, k) { noteWriteIn(handle, realmId, k); });
            return t.clear();
          };
        }
        log.debug("Leaving get().");
        return value.bind(t);
      }
    });
    log.debug("Leaving viewOf().");
    return view;
  }

  const facade = {
    // The realm's own Map, for the callers that genuinely want the whole thing
    // (a purge, a sweep across realms, a console page counting them). It is a
    // JOURNALLING VIEW — see viewOf() above.
    realmMap: function (id) {
      log.debug("Entering realmMap().");
      log.debug("Leaving realmMap().");
      return id === undefined
        ? viewOf(currentId(), per())
        // target as before; journal on the RESOLVED id
        : viewOf(partitionId(id), per.of(id));
    },
    get: function (k) {
      log.debug("Entering get().");
      log.debug("Leaving get().");
      return per().get(k);
    },
    set: function (k, v) {
      log.debug("Entering set().");
      per().set(k, v);
      noteWrite(handle, k);
      log.debug("Leaving set().");
      return facade;
    },
    has: function (k) {
      log.debug("Entering has().");
      log.debug("Leaving has().");
      return per().has(k);
    },
    delete: function (k) {
      log.debug("Entering delete().");
      const gone = per().delete(k);
      // Reported whether or not the key was there. A delete of a key this
      // process never held may still have a ROW — restored from the store and
      // swept before anything read it — and reporting only the hits would
      // leave that row behind for ever.
      noteWrite(handle, k);
      log.debug("Leaving delete().");
      return gone;
    },
    clear: function () {
      log.debug("Entering clear().");
      // EVERY KEY NAMED, before the clear rather than after it: afterwards
      // there is nothing left to name, and a store that reported "cleared"
      // without saying what it held would need the flush to read a shadow this
      // design deliberately does not keep.
      if (handle) {
        per().forEach(function (v, k) { noteWrite(handle, k); });
      }
      log.debug("Leaving clear().");
      return per().clear();
    },
    forEach: function (fn, thisArg) {
      log.debug("Entering forEach().");
      log.debug("Leaving forEach().");
      return per().forEach(fn, thisArg);
    },
    keys: function () {
      log.debug("Entering keys().");
      log.debug("Leaving keys().");
      return per().keys();
    },
    values: function () {
      log.debug("Entering values().");
      log.debug("Leaving values().");
      return per().values();
    },
    entries: function () {
      log.debug("Entering entries().");
      log.debug("Leaving entries().");
      return per().entries();
    },
    get size() {
      log.debug("Entering size().");
      log.debug("Leaving size().");
      return per().size;
    }
  };
  facade[Symbol.iterator] = function () { return per()[Symbol.iterator](); };
  log.debug("Leaving map().");
  return facade;
}

// An Array, per realm. A Proxy rather than a facade because an array is used by
// INDEX and by `length` as much as by method, and no list of delegated methods
// would cover `rows[0]`, `rows.length = 0` or a spread. The proxy target is a
// real array so that `Array.isArray()` — which several callers use — is true.
function arr(options) {
  log.debug("Entering arr().");
  const per = keyed(function () { return []; });
  // A SEGMENTED ARRAY IS A DIFFERENT SET OF ACCESSORS — see segmentedArr().
  const segment = options && options.persist &&
                  Number(options.segment) > 0
    ? Math.floor(Number(options.segment)) : 0;
  if (segment) {
    log.debug("Leaving arr(). Segmented by " + segment + ".");
    return segmentedArr(options, per, segment);
  }
  // ONE ROW FOR THE WHOLE ARRAY, under the empty key. An array's key is its
  // POSITION, and a `splice` renumbers every row after it — so a row per index
  // would need the flush to work out which positions moved, which is the diff
  // this design exists to avoid. The two arrays here are an audit ring and the
  // issued register, and both are read whole by everything that reads them.
  const handle = declareHandle(options, 'arr', {
    dump: function (realmId) {
      log.debug("Entering dump().");
      log.debug("Leaving dump().");
      return [{ key: '', value: per.of(partitionId(realmId)).slice() }];
    },
    read: function (realmId) {
      log.debug("Entering read().");
      log.debug("Leaving read().");
      return { present: true, value: per.of(partitionId(realmId)).slice() };
    },
    restore: function (realmId, key, value) {
      log.debug("Entering restore().");
      if (!acceptsRows(realmId)) {
        log.debug("Leaving restore(). The realm was removed here.");
        return;
      }
      const real = per.of(partitionId(realmId));
      real.length = 0;
      (Array.isArray(value) ? value : []).forEach(function (row) {
        real.push(row);
      });
      log.debug("Leaving restore().");
    },
    // An array's row is the whole array, so removing it is emptying it.
    remove: function (realmId) {
      log.debug("Entering remove().");
      per.of(partitionId(realmId)).length = 0;
      log.debug("Leaving remove().");
    }
  });
  log.debug("Leaving arr().");
  return new Proxy([], {
    get: function (target, prop, receiver) {
      log.debug("Entering get().");
      const real = per();
      const v = Reflect.get(real, prop, real);
      if (typeof v !== 'function') {
        log.debug("Leaving get().");
        return v;
      }
      // ---------------------------------------------------------------
      // **THE ONE PLACE THIS PROXY DOES NOT SEE A WRITE, AND THE REASON
      // THIS BRANCH EXISTS.** A method is handed back BOUND TO THE REAL
      // ARRAY, so `rows.push(x)` mutates it without ever reaching the
      // `set` trap below. That is invisible and harmless while nothing
      // watches an array — and it is exactly how `common/audit.js`'s ring
      // is written, `push` on one end and `shift` on the other. A
      // persisted array that reported index assignments and not `push`
      // would persist nothing at all, and the damage would be visible one
      // restart later.
      //
      // So a DECLARED array wraps the mutating members, and only those:
      // the read-only ones stay the bare bound function they have always
      // been, because wrapping `map` or `slice` would cost every reader a
      // closure for nothing.
      // ---------------------------------------------------------------
      if (!handle || MUTATORS.indexOf(prop) < 0) {
        log.debug("Leaving get().");
        return v.bind(real);
      }
      log.debug("Leaving get().");
      return function () {
        const out = v.apply(real, arguments);
        // WHOLE-STORE, not per index. `splice` and `sort` move rows the
        // caller never names, and an array's KEY is its position — so any
        // mutation potentially renumbers every row after it. The flush
        // rewrites the list, which for the two arrays here (an audit ring
        // and the issued register) is what it would have had to do anyway.
        noteWrite(handle, null);
        return out;
      };
    },
    set: function (target, prop, value) {
      log.debug("Entering set().");
      per()[prop] = value;
      noteWrite(handle, null);
      log.debug("Leaving set().");
      return true;
    },
    has: function (target, prop) {
      log.debug("Entering has().");
      log.debug("Leaving has().");
      return prop in per();
    },
    deleteProperty: function (target, prop) {
      log.debug("Entering deleteProperty().");
      delete per()[prop];
      noteWrite(handle, null);
      log.debug("Leaving deleteProperty().");
      return true;
    },
    ownKeys: function () {
      log.debug("Entering ownKeys().");
      log.debug("Leaving ownKeys().");
      return Reflect.ownKeys(per());
    },
    getOwnPropertyDescriptor: function (target, prop) {
      log.debug("Entering getOwnPropertyDescriptor().");
      const d = Object.getOwnPropertyDescriptor(per(), prop);
      log.debug("Leaving getOwnPropertyDescriptor().");
      // A proxy may not report a property as non-configurable when its target
      // has no such property, and the target here is a permanently empty array.
      // Marking every descriptor configurable is what keeps Object.keys() and
      // the spread operator legal over this.
      return d ? Object.assign({}, d, { configurable: true }) : undefined;
    },
    defineProperty: function (target, prop, desc) {
      log.debug("Entering defineProperty().");
      Object.defineProperty(per(), prop, desc);
      log.debug("Leaving defineProperty().");
      return true;
    }
  });
}

// ---------------------------------------------------------------------------
// A PERSISTED ARRAY IN SEGMENTS: `realms.arr({ persist, segment: N })`
// (2026-09-14, #46).
//
// **ONE ROW FOR THE WHOLE ARRAY WAS THE COST OF A CLUSTER.** The audit ring is
// 5,000 events, about 2.3 MB of JSON, and it moves on every request — so every
// flush sealed and wrote 2.3 MB, and every OTHER node read it back, opened it
// and parsed it to learn about one event. In `postgres` mode that was paid
// once per burst, behind the response. In active-active mode the cluster
// barrier holds a writing response until its commit, so it was paid per
// request, twice: measured on two nodes, a management-API create took 180ms
// against 2ms on one `postgres` node, and the audit ring was 3.3 MB of the
// 3.4 MB of minted rows those creates wrote.
//
// So a store that is APPENDED TO AT ONE END AND TRIMMED AT THE OTHER — which is
// what a ring is, and nothing else should declare this — can be stored as rows
// of N elements, keyed by ABSOLUTE position: the index an element would have
// if nothing had ever been removed from the front. Absolute positions do not
// renumber on a `shift`, which is exactly the property whole-array storage
// was chosen to avoid needing.
//
//   * `push` rewrites the one segment the new element lands in — at most N
//     elements, whatever the length of the array.
//   * `shift` WRITES NOTHING until a whole segment has left, and then deletes
//     that segment's row. Until then the stored head segment still carries the
//     elements already dropped here, so a copy restored or read from the store
//     can hold up to N-1 elements more than this process does. That is the
//     trade, and it is why this is for a CAPPED ring: its reader trims to the
//     cap (audit.js's merged()), and its own trim removes them locally.
//   * `pop` rewrites the last segment; every other mutation (`splice`, `sort`,
//     an index assignment, `length = 0`) renumbers positions, so every segment
//     the array covered before or after is rewritten — correct, and the whole
//     cost the one-row design always paid.
//
// A segment's value is `{ start, rows }` — its first element's absolute
// position and its elements — so the store can be put back in order without
// the key. What another process contributed under a segmented `merge: 'own'`
// handle is read back with `persistence_replication.remoteSegmentedRows()`.
// ---------------------------------------------------------------------------
function segmentedArr(options, per, size) {
  log.debug("Entering segmentedArr().");
  // Partition id -> absolute position of element 0.
  const bases = new Map();
  // Partition id -> key -> { start, rows }, for restore() only.
  const restored = new Map();
  onRemove(function (id) {
    bases.delete(id);
    restored.delete(id);
  });

  function baseOf(id) {
    log.debug("Entering baseOf().");
    log.debug("Leaving baseOf().");
    return bases.get(id) || 0;
  }

  // The keys of the segments absolute positions [from, to) fall in.
  function keysOver(from, to) {
    log.debug("Entering keysOver().");
    const out = [];
    if (to <= from) {
      log.debug("Leaving keysOver(). None.");
      return out;
    }
    for (let k = Math.floor(from / size); k <= Math.floor((to - 1) / size);
         k++) {
      out.push(String(k));
    }
    log.debug("Leaving keysOver().");
    return out;
  }

  function segmentOf(id, key) {
    log.debug("Entering segmentOf().");
    const real = per.of(id);
    const base = baseOf(id);
    const start = Number(key) * size;
    const lo = Math.max(start, base);
    const hi = Math.min(start + size, base + real.length);
    if (!/^\d+$/.test(String(key)) || lo >= hi) {
      log.debug("Leaving segmentOf(). Empty.");
      return null;
    }
    log.debug("Leaving segmentOf().");
    return { start: lo, rows: real.slice(lo - base, hi - base) };
  }

  const handle = declareHandle(options, 'arr', {
    dump: function (realmId) {
      log.debug("Entering dump().");
      const id = partitionId(realmId);
      const base = baseOf(id);
      const out = keysOver(base, base + per.of(id).length)
        .map(function (key) {
          return { key: key, value: segmentOf(id, key) };
        });
      log.debug("Leaving dump().");
      return out;
    },
    read: function (realmId, key) {
      log.debug("Entering read().");
      const value = segmentOf(partitionId(realmId), key);
      log.debug("Leaving read().");
      return value ? { present: true, value: value }
                   : { present: false };
    },
    // Only a row this process wrote in a life with the same origin reaches
    // here for a `merge: 'own'` store; another origin's is contributed. The
    // array is rebuilt from every segment restored so far, in position order.
    restore: function (realmId, key, value) {
      log.debug("Entering restore().");
      const id = partitionId(realmId);
      if (!acceptsRows(realmId)) {
        log.debug("Leaving restore(). The realm was removed here.");
        return;
      }
      if (!restored.has(id)) {
        restored.set(id, new Map());
      }
      const segments = restored.get(id);
      if (Array.isArray(value)) {
        // A whole-array row written before this store was segmented.
        segments.set(String(key), { start: 0, rows: value });
      } else if (value && Array.isArray(value.rows)) {
        segments.set(String(key), { start: Number(value.start) || 0,
                                    rows: value.rows });
      } else {
        segments.delete(String(key));
      }
      rebuild(id, segments);
      log.debug("Leaving restore().");
    },
    remove: function (realmId, key) {
      log.debug("Entering remove().");
      const id = partitionId(realmId);
      const segments = restored.get(id);
      if (segments && key !== undefined && key !== null && key !== '') {
        segments.delete(String(key));
        rebuild(id, segments);
      } else {
        per.of(id).length = 0;
        bases.delete(id);
      }
      log.debug("Leaving remove().");
    }
  });

  function rebuild(id, segments) {
    log.debug("Entering rebuild().");
    const ordered = Array.from(segments.values()).sort(function (a, b) {
      return a.start - b.start;
    });
    const real = per.of(id);
    real.length = 0;
    ordered.forEach(function (one) {
      one.rows.forEach(function (row) {
        real.push(row);
      });
    });
    bases.set(id, ordered.length ? ordered[0].start : 0);
    log.debug("Leaving rebuild().");
  }

  function journal(id, keys) {
    log.debug("Entering journal().");
    keys.forEach(function (key) {
      noteWrite(handle, key);
    });
    log.debug("Leaving journal().");
  }

  // Which segments a mutation moved, per the table in the header.
  function mutated(prop, id, before) {
    log.debug("Entering mutated().");
    const real = per.of(id);
    const base = baseOf(id);
    if (prop === 'push') {
      journal(id, keysOver(base + before, base + real.length));
    } else if (prop === 'shift') {
      if (before > 0) {
        const next = base + 1;
        bases.set(id, next);
        if (next % size === 0) {
          journal(id, [String(next / size - 1)]);
        }
      }
    } else if (prop === 'pop') {
      if (before > 0) {
        journal(id, keysOver(base + before - 1, base + before));
      }
    } else {
      journal(id, keysOver(base, base + Math.max(before, real.length)));
    }
    log.debug("Leaving mutated().");
  }

  log.debug("Leaving segmentedArr().");
  return new Proxy([], {
    get: function (target, prop) {
      log.debug("Entering get().");
      const real = per();
      const v = Reflect.get(real, prop, real);
      if (typeof v !== 'function') {
        log.debug("Leaving get().");
        return v;
      }
      if (!handle || MUTATORS.indexOf(prop) < 0) {
        log.debug("Leaving get().");
        return v.bind(real);
      }
      log.debug("Leaving get().");
      // See arr()'s `get` trap: a bound mutator never reaches `set`.
      return function () {
        const id = currentId();
        const before = per.of(id).length;
        const out = v.apply(per.of(id), arguments);
        mutated(prop, id, before);
        return out;
      };
    },
    set: function (target, prop, value) {
      log.debug("Entering set().");
      const id = currentId();
      const before = per.of(id).length;
      per.of(id)[prop] = value;
      mutated('set', id, before);
      log.debug("Leaving set().");
      return true;
    },
    has: function (target, prop) {
      log.debug("Entering has().");
      log.debug("Leaving has().");
      return prop in per();
    },
    deleteProperty: function (target, prop) {
      log.debug("Entering deleteProperty().");
      const id = currentId();
      const before = per.of(id).length;
      delete per.of(id)[prop];
      mutated('delete', id, before);
      log.debug("Leaving deleteProperty().");
      return true;
    },
    ownKeys: function () {
      log.debug("Entering ownKeys().");
      log.debug("Leaving ownKeys().");
      return Reflect.ownKeys(per());
    },
    getOwnPropertyDescriptor: function (target, prop) {
      log.debug("Entering getOwnPropertyDescriptor().");
      const d = Object.getOwnPropertyDescriptor(per(), prop);
      log.debug("Leaving getOwnPropertyDescriptor().");
      return d ? Object.assign({}, d, { configurable: true }) : undefined;
    },
    defineProperty: function (target, prop, desc) {
      log.debug("Entering defineProperty().");
      Object.defineProperty(per(), prop, desc);
      log.debug("Leaving defineProperty().");
      return true;
    }
  });
}

// A plain object, per realm. Same Proxy for the same reason: these are used as
// dictionaries with computed keys, `delete` and `Object.keys()`. `factory` is
// optional and is what makes this usable for SCALARS as well as dictionaries: a
// module with `let seq = 0` beside a realm-partitioned array has a counter that
// counts every realm's rows and a list holding one realm's, and the two
// disagree on the page that shows them both. Declaring `realms.obj(() => ({
// seq: 0 }))` and spelling the reads `nums.seq` moves the counter into the
// partition with the thing it counts — `nums.seq++` works through the proxy
// exactly as it did through the binding.
function obj(factory, options) {
  log.debug("Entering obj().");
  const per = keyed(factory || function () { return {}; });
  // ONE ROW FOR THE WHOLE OBJECT, under the empty key, for the array's reason
  // read the other way: these are counters and claim sets, one small object
  // per realm, so the row IS the object and a row per field would be a table
  // of scalars nobody wants to read.
  const handle = declareHandle(options, 'obj', {
    dump: function (realmId) {
      log.debug("Entering dump().");
      log.debug("Leaving dump().");
      return [{ key: '',
                value: Object.assign({}, per.of(partitionId(realmId))) }];
    },
    read: function (realmId) {
      log.debug("Entering read().");
      log.debug("Leaving read().");
      return { present: true,
               value: Object.assign({}, per.of(partitionId(realmId))) };
    },
    // MERGED rather than replaced. The factory has already built this realm's
    // object with every field the current build expects; assigning over it
    // keeps a field added since the row was written at its default instead of
    // making it `undefined`, which is what a wholesale replacement would do
    // and what would then arrive as NaN out of `nums.seq++`.
    restore: function (realmId, key, value) {
      log.debug("Entering restore().");
      if (!acceptsRows(realmId)) {
        log.debug("Leaving restore(). The realm was removed here.");
        return;
      }
      Object.assign(per.of(partitionId(realmId)), value || {});
      log.debug("Leaving restore().");
    },
    // BACK TO WHAT THE FACTORY BUILDS rather than to an empty object: these
    // are counter sets and claim sets whose fields are read unconditionally,
    // and `nums.seq++` on a `{}` is NaN for ever after.
    remove: function (realmId) {
      log.debug("Entering remove().");
      const id = partitionId(realmId);
      const real = per.of(id);
      Object.keys(real).forEach(function (k) { delete real[k]; });
      Object.assign(real, (factory ? factory(get(id) || DEFAULT_REALM) : {}));
      log.debug("Leaving remove().");
    }
  });
  log.debug("Leaving obj().");
  return new Proxy({}, {
    get: function (target, prop) {
      log.debug("Entering get().");
      const real = per();
      const v = real[prop];
      log.debug("Leaving get().");
      return typeof v === 'function' ? v.bind(real) : v;
    },
    set: function (target, prop, value) {
      log.debug("Entering set().");
      per()[prop] = value;
      // WHOLE-STORE, like the array above but for a different reason: these
      // are counters and claim sets — one small object per realm — so the row
      // IS the object and naming a field would mean a row per field.
      noteWrite(handle, null);
      log.debug("Leaving set().");
      return true;
    },
    has: function (target, prop) {
      log.debug("Entering has().");
      log.debug("Leaving has().");
      return prop in per();
    },
    deleteProperty: function (target, prop) {
      log.debug("Entering deleteProperty().");
      delete per()[prop];
      noteWrite(handle, null);
      log.debug("Leaving deleteProperty().");
      return true;
    },
    ownKeys: function () {
      log.debug("Entering ownKeys().");
      log.debug("Leaving ownKeys().");
      return Reflect.ownKeys(per());
    },
    getOwnPropertyDescriptor: function (target, prop) {
      log.debug("Entering getOwnPropertyDescriptor().");
      const d = Object.getOwnPropertyDescriptor(per(), prop);
      log.debug("Leaving getOwnPropertyDescriptor().");
      return d ? Object.assign({}, d, { configurable: true }) : undefined;
    },
    defineProperty: function (target, prop, desc) {
      log.debug("Entering defineProperty().");
      Object.defineProperty(per(), prop, desc);
      log.debug("Leaving defineProperty().");
      return true;
    }
  });
}

// ---------------------------------------------------------------------------
// A STORE THAT IS DELIBERATELY NOT PER REALM, DECLARED IN THE FILE ABOUT
// REALMS — which needs its argument made rather than assumed.
//
// The rate limiter's buckets and the LDAP cluster connection mirror are shared
// across every realm, because what they hold is about a SOCKET or an ADDRESS
// rather than about a realm. Kerberos was on this list until 2026-09-15 — its
// three stores are per realm now that each trust realm has a KDC of its own —
// and SPIFFE's sockets left it on 2026-09-12. They are still MINTED state, so
// product mode has to write them down, and they need somewhere to be
// declared.
//
// A shared store is declared HERE, and not in `persistence_minted.js`, for one
// reason:
// `declaredHandles` above is the ONE list of persistable stores, and
// `tests/realm_isolation.js` reads it to check that a store which ought to be
// per realm has not quietly been left process-wide. A second list somewhere
// else would be exactly the thing that test exists to catch, hidden from the
// test that catches it. So a shared store says so, in the same place, in one
// word: `realms.sharedMap({ persist: 'security.rateLimitBuckets',
// scope: 'shared' })`.
//
// It is a plain `Map` with no partitioning at all — every member is the real
// Map's, and only the three mutators are wrapped — so a caller cannot tell it
// from the `new Map()` it replaces.
//
// ---------------------------------------------------------------------------
// `reconcile`: WHAT A STORED ROW MAY CHANGE IN A STORE PARTLY BUILT FROM CODE
// (2026-09-12).
//
// `restore` and `remove` below are the two accessors BOTH doors a stored row
// comes in through reach — `persistence_minted.js`'s startup `restore()` and
// its replication applier `applyLocally()` — so a rule stated here is obeyed by
// a restart and by another process alike, and cannot be forgotten by a third
// door, because there is no third accessor.
//
// Until this date both accessors wrote whatever they were handed. That is right
// for a store whose every row was MINTED (a session, a replay entry), and wrong
// for `krb5.principals`, whose configured rows are BUILT FROM SETTINGS at
// require time and only then written down: a restore put back the password,
// salt, etypes and kvno the row had when it was written, silently overriding a
// changed `krb5.servicePassword` for as long as that row lived in the store —
// and resurrected a fixture account with a published password into a process
// whose settings no longer create it. So a store may pass
//
//     reconcile: { restore(key, incoming, held) -> value | undefined,
//                  remove(key, held) -> boolean }
//
// and the accessor asks it first. `restore` answers the value to HOLD, which
// may be `held` itself with fields copied onto it, or `undefined` meaning
// "hold nothing new" — what was held stays and nothing replaces it. `remove`
// answers false to refuse. Either missing means the old behaviour for that
// half.
//
// **A RECONCILER THAT THROWS APPLIES NOTHING**, which is fail-closed on
// purpose: the rule exists because some incoming rows must not be believed, and
// a rule that could not be evaluated has not said this one may be. The row
// stays in the store and the next write of that key through a process that CAN
// evaluate it replaces it. Logged, with a code, because it is a defect in the
// reconciler rather than anything about the row.
//
// **ONE CALLER TODAY, AND SINCE 2026-09-15 IT IS A PER-REALM STORE.**
// `kerberos/krb5_principals.js` was on `sharedMap()` while the KDC was the
// process's; when each trust realm got a principal database of its own it moved
// to `realms.map()`, which is what this paragraph said would "add the same two
// lines to its accessors". Both shapes now call the two functions below, so the
// rule is written once. A per-realm reconciler is also told WHICH realm's
// partition the row is for — a store built from settings is built from that
// realm's settings — as a fourth argument (`restore`) and a third (`remove`);
// a shared store passes the empty string.
// ---------------------------------------------------------------------------
function reconciledRestore(handleName, reconcile, target, k, v, realmId) {
  log.debug("Entering reconciledRestore().");
  if (typeof reconcile.restore !== 'function') {
    target.set(k, v);
    log.debug("Leaving reconciledRestore(). No reconciler.");
    return;
  }
  let admitted;
  try {
    admitted = reconcile.restore(k, v, target.get(k), realmId, target);
  } catch (e) {
    log.error(errorCodes.tag('STS-CORE-0042') +
              'realms: "' + handleName + '" could not reconcile a stored ' +
              'row under "' + k + '", so it was NOT applied and what ' +
              'this process held is unchanged: ' + e.message);
    log.debug("Leaving reconciledRestore(). The reconciler threw.");
    return;
  }
  if (admitted !== undefined) {
    target.set(k, admitted);
  }
  log.debug("Leaving reconciledRestore().");
}

function reconciledRemove(handleName, reconcile, target, k, realmId) {
  log.debug("Entering reconciledRemove().");
  if (typeof reconcile.remove !== 'function') {
    target.delete(k);
    log.debug("Leaving reconciledRemove(). No reconciler.");
    return;
  }
  let allowed = false;
  try {
    allowed = reconcile.remove(k, target.get(k), realmId) !== false;
  } catch (e) {
    log.error(errorCodes.tag('STS-CORE-0042') +
              'realms: "' + handleName + '" could not reconcile a stored ' +
              'removal of "' + k + '", so it was NOT applied and what ' +
              'this process held is unchanged: ' + e.message);
    log.debug("Leaving reconciledRemove(). The reconciler threw.");
    return;
  }
  if (allowed) {
    target.delete(k);
  }
  log.debug("Leaving reconciledRemove().");
}

function sharedMap(options) {
  log.debug("Entering sharedMap().");
  const real = new Map();
  const declared = Object.assign({}, options || {}, { scope: 'shared' });
  const reconcile = (options && options.reconcile) || {};
  const handleName = String((options && options.persist) || '(undeclared)');
  const handle = declareHandle(declared, 'shared-map', {
    dump: function () {
      log.debug("Entering dump().");
      const out = [];
      real.forEach(function (v, k) { out.push({ key: k, value: v }); });
      log.debug("Leaving dump().");
      return out;
    },
    read: function (realmId, k) {
      log.debug("Entering read().");
      log.debug("Leaving read().");
      return real.has(k) ? { present: true, value: real.get(k) }
                         : { present: false };
    },
    restore: function (realmId, k, v) {
      log.debug("Entering restore().");
      reconciledRestore(handleName, reconcile, real, k, v, '');
      log.debug("Leaving restore().");
    },
    remove: function (realmId, k) {
      log.debug("Entering remove().");
      reconciledRemove(handleName, reconcile, real, k, '');
      log.debug("Leaving remove().");
    }
  });
  // The realm reported is always the empty string, whatever realm the write
  // happened in: a shared store has ONE row set, and journalling a write under
  // the ambient realm would file the same key under whichever realm happened
  // to be current — so a restore would find it under a realm that may not
  // exist by then.
  function note(k) {
    log.debug("Entering note().");
    if (handle && persistObserver) {
      try {
        persistObserver(handle, '', k === undefined ? null : k);
      } catch (e) {
        log.error(errorCodes.tag('STS-CORE-0023') +
                  'realms: "' + handle + '" could not report a write: ' +
                  e.message);
      }
    }
    log.debug("Leaving note().");
  }
  const facade = {
    get: function (k) {
      log.debug("Entering get().");
      log.debug("Leaving get().");
      return real.get(k);
    },
    set: function (k, v) {
      log.debug("Entering set().");
      real.set(k, v);
      note(k);
      log.debug("Leaving set().");
      return facade;
    },
    has: function (k) {
      log.debug("Entering has().");
      log.debug("Leaving has().");
      return real.has(k);
    },
    delete: function (k) {
      log.debug("Entering delete().");
      const gone = real.delete(k);
      note(k);
      log.debug("Leaving delete().");
      return gone;
    },
    clear: function () {
      log.debug("Entering clear().");
      real.forEach(function (v, k) { note(k); });
      log.debug("Leaving clear().");
      return real.clear();
    },
    forEach: function (fn, thisArg) {
      log.debug("Entering forEach().");
      log.debug("Leaving forEach().");
      return real.forEach(fn, thisArg);
    },
    keys: function () {
      log.debug("Entering keys().");
      log.debug("Leaving keys().");
      return real.keys();
    },
    values: function () {
      log.debug("Entering values().");
      log.debug("Leaving values().");
      return real.values();
    },
    entries: function () {
      log.debug("Entering entries().");
      log.debug("Leaving entries().");
      return real.entries();
    },
    get size() {
      log.debug("Entering size().");
      log.debug("Leaving size().");
      return real.size;
    }
  };
  facade[Symbol.iterator] = function () { return real[Symbol.iterator](); };
  log.debug("Leaving sharedMap().");
  return facade;
}

// ---------------------------------------------------------------------------
// WHAT CONFIG.JS ASKS THIS FILE.
//
// The inverted hook promised at the top. `config.value()` needs the current
// realm's overrides and cannot require this module to get them — this one
// requires that one — so it offers a slot and this fills it. It is rule 3e's
// shape and it passes rule 3e's test in the one direction that matters: a
// require here would close a cycle.
//
// It answers the REALM RECORD rather than its overrides, and null when there is
// no realm context, when realms are off or when the ambient realm is the
// default one. The record rather than the object because config.js WRITES
// through this too — `setOverride()` in a realm sets the realm's value, which
// is what makes /admin/config, /admin/token-lifetimes and POST
// /admin-api/config/set realm-aware without one of them being edited — and a
// write wants to name the realm in its log line.
// ---------------------------------------------------------------------------
function realmContext() {
  log.debug("Entering realmContext().");
  const realm = als.getStore();
  if (!realm || realm.id === DEFAULT_ID || !active()) {
    log.debug("Leaving realmContext().");
    return null;
  }
  log.debug("Leaving realmContext().");
  return realm;
}

config.setRealmContext(realmContext);

// ---------------------------------------------------------------------------
// WHICH FAMILIES ARE REALM-AWARE, AND HOW.
//
// An index rather than a claim: `/admin/realms` and `GET /realms` both render
// this, so the answer to "does Kerberos know about realms?" is something this
// service tells you rather than something a reader works out from four
// directory CLAUDE.md files.
//
// `by` is the DISCRIMINATOR — what actually tells one realm's traffic from
// another's on that surface. It is the path for everything that is HTTP, and
// something else for each of the four socket families, because a socket has no
// path to put a segment in.
// ---------------------------------------------------------------------------
function realmSupport() {
  log.debug("Entering realmSupport().");
  log.debug("Leaving realmSupport().");
  return [
    { family: 'OAuth 2.0 / OIDC', state: 'full', by: 'path',
      note: 'Its own issuer, signing key, authorization codes, access and ' +
            'refresh tokens, refresh families, DPoP replay and nonce state, ' +
            'client-assertion replay state and named authorization servers. ' +
            'The CLIENT REGISTRATIONS are per realm as of 2026-08-25, ' +
            'because the directory is: a client registered under one realm ' +
            'lives in that realm\'s ou=applications and is unknown to every ' +
            'other. This line said the opposite until then. RFC 9700 MODE IS ' +
            'PER REALM TOO — `oauth2.rfc9700` is the one setting here that ' +
            'is restart-only for the process and settable on a realm, ' +
            'because a realm binds no socket — so one process can answer ' +
            'permissively at /oauth2/authorize and enforce the BCP at a ' +
            'realm\'s. What a realm cannot bring with it is a SCHEME: the ' +
            'main port is https or it is not, for every realm at once, and ' +
            'GET /oauth2/rfc9700 reports which.' },
    { family: 'Authentication service', state: 'full', by: 'path',
      note: 'Its own sessions and WebAuthn credentials, so signing in to one ' +
            'realm signs you in to that realm only. That is the point of a ' +
            'realm rather than a limitation of one. Who you may sign in AS ' +
            'is shared only in the sense that this service checks no ' +
            'password anywhere — the PERSON is an entry in the realm\'s own ' +
            'directory. The admin console is the ONE reader that crosses ' +
            'this line, and it crosses it in exactly one direction: it ' +
            'accepts the DEFAULT realm\'s session and no other. The row ' +
            'below says why.' },
    { family: 'SAML 2.0 / SAML 1.1', state: 'full', by: 'path',
      note: 'Its own entityID and providerID (seeded distinct when the realm ' +
            'is created), its own signing key, request state, artifacts and ' +
            'per-service-provider metadata — whose URL therefore carries the ' +
            'realm as well as the SP digest. The SERVICE PROVIDER ENTRIES ' +
            'are per realm, for the reason the OAuth clients are: they are ' +
            'applications in the realm\'s own directory.' },
    { family: 'WS-Trust', state: 'full', by: 'path',
      note: 'Its own token issuer and signing key.' },
    { family: 'WS-Federation', state: 'full', by: 'path',
      note: 'Its own entityID and signing key. Single sign-on with OAuth is ' +
            'preserved WITHIN a realm and does not cross realms, because the ' +
            'session it leans on does not.' },
    { family: 'OpenID4VCI / OpenID4VP / DID', state: 'full', by: 'path',
      note: 'Its own credential offers, pre-authorized codes, deferred ' +
            'transactions, issuance nonces and presentation transactions — ' +
            'and its own answer to what a credential asserts and what the ' +
            'verifier asks for. The did:web identifier carries the realm ' +
            'segment, which is what keeps two realms\' DID documents apart.' },
    { family: 'Statistics and the audit log', state: 'full', by: 'path',
      note: 'Each realm counts and records what happened under its own ' +
            'prefix. The audit sequence numbers are per realm too, so one ' +
            'realm\'s rows are contiguous.' },
    { family: 'SCIM 2.0', state: 'full', by: 'path',
      note: 'The endpoints AND the store. A user created through one ' +
            'realm\'s /scim/v2 is an entry in that realm\'s ou=users and ' +
            'exists nowhere else — this row read `partial` and said the ' +
            'opposite until 2026-08-25, when the directory became per realm. ' +
            'SCIM still makes no decision of its own about it: it provisions ' +
            'into the directory, and the directory is the thing that is ' +
            'partitioned.' },
    { family: 'Admin console and management API', state: 'partial', by: 'path',
      note: 'Every page and every operation is per realm — /admin/config ' +
            'READS and WRITES the realm it is reached in, and /admin/users ' +
            'lists the realm\'s own people. The ADMIN ROLES are held TWICE, ' +
            'deliberately, since 2026-09-14 (#32): the DEFAULT realm\'s ' +
            'cn=admin-read and cn=admin-write are the SERVICE roster and ' +
            'administer every realm, and each other realm has the same two ' +
            'groups in its own ou=groups, seeded with an `admin` account, ' +
            'whose members administer THAT realm only — every page and ' +
            'operation about the whole process (the store, the database, ' +
            'the secret store, the listeners, the debugger, the explorer), ' +
            'creating or removing a realm, replacing the service Root, and ' +
            'the per-process settings are refused to them. A realm\'s own ' +
            'roster therefore grants nothing outside the realm, which is ' +
            'what made it safe to add. The console signs a person in through ' +
            'the realm it is reached in, and the plain /admin and /portal ' +
            'ask which realm first when realms are defined. /admin-api takes ' +
            'the default realm\'s token everywhere and a realm\'s own ' +
            'sts-management-api token in that realm only.' },
    { family: 'LDAP (389 / 636)', state: 'full', by: 'dn',
      note: 'A DIRECTORY PER REALM behind one socket — a separate store, not ' +
            'a subtree of a shared one, since 2026-08-25. The DN layout is ' +
            'what a client sees: the default realm is ldap.baseDn itself ' +
            '(dc=example,dc=com) and every other realm is dc=<id> beneath ' +
            'it. So ou=users, ou=groups, ou=applications, ou=federations and ' +
            'the two SPIFFE containers exist once per realm and share ' +
            'nothing — this row read `none` and said every realm saw the ' +
            'same people until 2026-08-25. The realm is in the DN and not in ' +
            'a partitioned store BECAUSE the socket has no path to put a ' +
            'segment in: an ldapsearch arrives with a base DN and nothing ' +
            'else, so `-b dc=acme,dc=example,dc=com` is the only way a ' +
            'client could ever name a realm, and it works. EVERY OPERATION ' +
            'IS ANSWERED FROM THE STORE THE DN NAMES, since 2026-08-25 and ' +
            'at rcbj\'s request — this line said a subtree search from the ' +
            'naming context returns every realm\'s entries, on the argument ' +
            'that a naming context IS the whole tree. It left port 389 as ' +
            'the one door through which a realm could see another realm\'s ' +
            'people, groups and applications, while the console, /scim/v2 ' +
            'and the group claim showed each realm only its own. So `-b ' +
            'dc=example,dc=com` is the default realm\'s directory, `-b ' +
            'dc=acme,dc=example,dc=com` is acme\'s, and the root DSE ' +
            'publishes one namingContexts value per realm so that a client ' +
            'can discover them. An add, modify, delete, compare or ' +
            'base-scope search is answered in the realm its DN names, ' +
            'because spelling the DN out is how a client names a realm on a ' +
            'socket with nowhere else to put one; a modifyDN that would ' +
            'cross a realm is refused with LDAP_AFFECTS_MULTIPLE_DSAS (71), ' +
            'two realms here being two directories.' },
    { family: 'Kerberos v5', state: 'full', by: 'name',
      note: 'A KDC per trust realm on the SHARED port 88, told apart by the ' +
            'Kerberos realm name inside every request — the discriminator ' +
            'the protocol already carries. A realm is created with ' +
            'krb5.enabled OFF; set a krb5.realm of its own (no two realms ' +
            'may answer to one name) and turn it on, and that realm builds a ' +
            'principal database, long-term keys and a krbtgt of its own, ' +
            'from its own settings. Its people are the people in its own ' +
            'directory subtree. Raw UDP/TCP 88 and a bare /KdcProxy route by ' +
            'the name; a realm\'s own /realm/<id>/KdcProxy is pinned to that ' +
            'realm and refuses another realm\'s name with ' +
            'KDC_ERR_WRONG_REALM. What is still the PROCESS\'s: the two ' +
            'sockets, and the development-mode trust with krb5.trustedRealm ' +
            '— trust realms do not trust each other\'s Kerberos. Before ' +
            '2026-09-15 there was one KDC, one principal database and one ' +
            'realm name for the whole process.' },
    { family: 'TLS (8443 / 9443)', state: 'none', by: 'shared',
      note: 'Their whole content is what the server saw of the connection, ' +
            'which is a property of the socket and not of a realm.' },
    { family: 'SPIFFE', state: 'full', by: 'socket',
      note: 'A TRUST DOMAIN, AN AUTHORITY, A REGISTRY AND A PAIR OF gRPC ' +
            'SOCKETS PER REALM since 2026-09-12 — this row read `none` until ' +
            'then and said one trust domain, one signing authority and four ' +
            'shared sockets. **THE DISCRIMINATOR IS THE ENDPOINT ADDRESS AND ' +
            'IT COULD NOT HAVE BEEN ANYTHING ELSE**: gRPC has a path and it ' +
            'is the METHOD — `/SpiffeWorkloadAPI/FetchX509SVID` is fixed by ' +
            'that specification and the SPIRE APIs by theirs — so a realm ' +
            'segment in it would be a method no conforming client calls. A ' +
            'realm is created with `spiffe.trustDomain` of ' +
            '`<realm>.<the process\'s>` (the common root with a unique ' +
            'issuer under it) and with SPIFFE OFF; turning it on builds that ' +
            'realm\'s authorities and binds a Workload API and a SPIRE ' +
            'Server API of its own, on Unix socket paths seeded when the ' +
            'realm was made — and on TCP only once somebody gives it an ' +
            'address (`spiffe.grpcHost`) and ports, which a realm is created ' +
            'without, because the ones it would inherit are the default ' +
            'realm\'s and already bound. ' +
            'Join tokens are per realm too, because a join token is a ' +
            'credential for joining a trust domain. **WHAT IS STILL SHARED ' +
            'IS THE PROCESS\'S OWN FOUR SOCKETS**, which belong to the ' +
            'default realm and stay bound whatever `spiffe.enabled` says — a ' +
            'socket that vanished would read as a service that had stopped' +
            '. The FEDERATED bundles are a realm\'s own since 2026-09-12, ' +
            'and none may be registered under a trust domain any realm of ' +
            'this service serves.' }
  ];
}

module.exports = {
  DEFAULT_ID: DEFAULT_ID,
  DEFAULT_REALM: DEFAULT_REALM,
  active: active,
  current: current,
  currentId: currentId,
  isDefault: isDefault,
  run: run,
  bind: bind,
  get: get,
  list: list,
  count: count,
  create: create,
  update: update,
  remove: remove,
  setOverride: setOverride,
  clearOverride: clearOverride,
  validateId: validateId,
  reserve: reserve,
  reserved: reserved,
  pathSegment: pathSegment,
  prefixOf: prefixOf,
  currentPrefix: currentPrefix,
  href: href,
  matchPath: matchPath,
  onCreate: onCreate,
  onRemove: onRemove,
  onChange: onChange,
  realmContext: realmContext,
  keyed: keyed,
  map: map,
  arr: arr,
  obj: obj,
  sharedMap: sharedMap,
  setPersistObserver: setPersistObserver,
  unknownRealmPath: unknownRealmPath,
  handles: handles,
  handleFor: handleFor,
  realmSupport: realmSupport
};
