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
// `kerberos/CLAUDE.md`, `ldap/CLAUDE.md` and `spiffe/CLAUDE.md` carry those; the
// index of which family is realm-aware how is in `realmSupport()` at the foot
// of this file, so that a reader can ask this service rather than guess.
// ---------------------------------------------------------------------------

const { AsyncLocalStorage } = require('async_hooks');
const bunyan = require('bunyan');
// config.js is required in the ORDINARY direction and it is safe: that module
// requires only bunyan and config_file.js, so it cannot reach back here. The
// dependency the other way — config.js needing to know a realm's overrides — is
// an INVERTED HOOK filled at the foot of this file, which is rule 3e's shape and
// passes rule 3e's test: a require in that direction would close a cycle.
const config = require('./config');

const log = bunyan.createLogger({ name: 'sts-realms' });
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
  return als.getStore() || DEFAULT_REALM;
}

function currentId() {
  return current().id;
}

function isDefault(realm) {
  return (realm || current()).id === DEFAULT_ID;
}

// Run `fn` with `realm` as the ambient realm, for `fn` and for everything it
// awaits, schedules or calls back into. The return value is fn's.
function run(realm, fn) {
  return als.run(realm || DEFAULT_REALM, fn);
}

// The same thing as a wrapper, for the callback-shaped surfaces — an LDAP
// handler, a gRPC method, a datagram listener — that are handed a function
// rather than being called inside one.
function bind(realm, fn) {
  const captured = realm || DEFAULT_REALM;
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
  return String(config.value('realms.pathSegment') || '').replace(/^\/+|\/+$/g, '');
}

function prefixOf(realm) {
  const r = realm || current();
  if (r.id === DEFAULT_ID || !active()) {
    return '';
  }
  const segment = pathSegment();
  return '/' + (segment ? segment + '/' : '') + r.id;
}

// The prefix of whatever realm is ambient. THE function every URL builder
// wants, and the reason `baseUrlOf()` could absorb this for eighty callers.
function currentPrefix() {
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
// what the parent project's tests/sts_metadata.js uses to tell an unrouted path
// from an endpoint legitimately answering 404, and a prettier refusal for
// unknown realms would break that distinction for every path under the segment.
// `GET /realms` is where somebody finds out what the realms actually are.
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
// READING THE REGISTRY.
// ---------------------------------------------------------------------------
function get(id) {
  if (!id || id === DEFAULT_ID) {
    return DEFAULT_REALM;
  }
  return realms.get(String(id)) || null;
}

// Every realm, the default one first. It is prepended rather than stored so
// that it cannot be edited out of the table by anything that iterates.
function list() {
  return [DEFAULT_REALM].concat(Array.from(realms.values()));
}

function count() {
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
let reservedProvider = function () { return []; };

function reserve(provider) {
  reservedProvider = typeof provider === 'function'
    ? provider
    : function () { return provider || []; };
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
    log.warn('realms: could not read the router to reserve realm ids: ' + e.message);
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
    log.debug("Leaving validateId().");
    return errors;
  }
  if (value === DEFAULT_ID) {
    errors.push('"' + DEFAULT_ID + '" is the built-in realm and cannot be redefined.');
  }
  if (reserved().indexOf(value) >= 0) {
    errors.push('"' + value + '" is the first segment of a path this service ' +
                'already serves. A realm may not be called that, whatever ' +
                'realms.pathSegment is set to, because clearing that setting ' +
                'would make the realm shadow the endpoint.');
  }
  if (realms.has(value)) {
    errors.push('A realm called "' + value + '" is already defined.');
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
// `krb5.realm` is NOT here and cannot be: it is not runtime-settable, because
// the principal database is built from it when the process starts. That is the
// reason Kerberos over UDP/TCP 88 is `partial` in realmSupport() rather than
// `full`, and it is the first thing to fix if that changes.
// ---------------------------------------------------------------------------
const NAMED_BY_REALM = [
  { key: 'saml2.entityId', join: ':' },
  { key: 'saml11.providerId', join: ':' },
  { key: 'wsfed.entityId', join: ':' },
  { key: 'wstrust.issuer', join: ':' },
  { key: 'saml.issuer', join: ':' },
  { key: 'oid4vp.clientId', join: '-' }
];

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
      out[row.key] = String(base) + row.join + id;
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
    return { ok: false, errors: errors };
  }
  const overrideErrors = checkOverrides((spec || {}).overrides);
  if (overrideErrors.length) {
    log.debug("Leaving create(). Refused for its overrides.");
    return { ok: false, errors: overrideErrors };
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
  log.info('realms: "' + id + '" defined; its endpoints are under ' +
           prefixOf(realm) + '/.');
  log.debug("Leaving create().");
  return { ok: true, errors: [], realm: realm };
}

function update(id, changes) {
  log.debug("Entering update(). id=" + id);
  const realm = realms.get(String(id || ''));
  if (!realm) {
    log.debug("Leaving update(). No such realm.");
    return { ok: false, errors: ['No realm called "' + id + '" is defined.'] };
  }
  const spec = changes || {};
  if (spec.overrides !== undefined) {
    const overrideErrors = checkOverrides(spec.overrides);
    if (overrideErrors.length) {
      log.debug("Leaving update(). Refused for its overrides.");
      return { ok: false, errors: overrideErrors };
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
  log.debug("Leaving update().");
  return { ok: true, errors: [], realm: realm };
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
    return { ok: false, errors: ['No realm called "' + id + '" is defined.'] };
  }
  const problem = config.checkOverride(key, raw);
  if (problem) {
    log.debug("Leaving setOverride(). Refused: " + problem);
    return { ok: false, errors: [problem] };
  }
  realm.overrides[key] = raw;
  log.info('realms: "' + realm.id + '" sets ' + key + '.');
  log.debug("Leaving setOverride().");
  return { ok: true, errors: [], key: key };
}

function clearOverride(id, key) {
  log.debug("Entering clearOverride(). id=" + id + ", key=" + key);
  const realm = realms.get(String(id || ''));
  if (!realm) {
    log.debug("Leaving clearOverride(). No such realm.");
    return { ok: false, errors: ['No realm called "' + id + '" is defined.'] };
  }
  if (!Object.prototype.hasOwnProperty.call(realm.overrides, key)) {
    log.debug("Leaving clearOverride(). Nothing was set.");
    return { ok: false, errors: ['"' + key + '" is not set on realm "' +
      realm.id + '"; it already comes from what the whole service is ' +
      'configured with.'] };
  }
  delete realm.overrides[key];
  log.info('realms: "' + realm.id + '" no longer sets ' + key + '.');
  log.debug("Leaving clearOverride().");
  return { ok: true, errors: [], key: key };
}

// Validate a whole override object without applying any of it, which is the
// same all-or-nothing rule config.js's checkOverride() exists for: a realm that
// took three of four settings and refused the fourth would be a realm nobody
// asked for.
function checkOverrides(overrides) {
  const errors = [];
  Object.keys(overrides || {}).forEach(function (key) {
    const problem = config.checkOverride(key, overrides[key]);
    if (problem) {
      errors.push(problem);
    }
  });
  return errors;
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

function onRemove(fn) {
  purges.push(fn);
}

function remove(id) {
  log.debug("Entering remove(). id=" + id);
  const realm = realms.get(String(id || ''));
  if (!realm) {
    log.debug("Leaving remove(). No such realm.");
    return { ok: false, errors: ['No realm called "' + id + '" is defined.'] };
  }
  realms.delete(realm.id);
  purges.forEach(function (purge) {
    try {
      purge(realm.id);
    } catch (e) {
      // A store that cannot purge itself must not stop the others from
      // purging, and it must not leave the registry row behind either — the
      // row is already gone above. Log it and carry on; the worst outcome is
      // state for an id nobody can reach any more.
      log.warn('realms: a store refused to purge "' + realm.id + '": ' + e.message);
    }
  });
  log.info('realms: "' + realm.id + '" removed, with everything it held.');
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
function keyed(factory) {
  log.debug("Entering keyed().");
  const per = new Map();
  onRemove(function (id) { per.delete(id); });
  function forCurrent() {
    const id = currentId();
    if (!per.has(id)) {
      per.set(id, factory(current()));
    }
    return per.get(id);
  }
  forCurrent.of = function (id) {
    if (!per.has(id)) {
      per.set(id, factory(get(id) || DEFAULT_REALM));
    }
    return per.get(id);
  };
  forCurrent.existing = function () { return per; };
  log.debug("Leaving keyed().");
  return forCurrent;
}

// A Map, per realm. Every member of the Map interface is delegated, including
// the iterator — `for (const [k, v] of store)` is a shape this codebase uses.
function map() {
  log.debug("Entering map().");
  const per = keyed(function () { return new Map(); });
  const facade = {
    // The realm's own Map, for the two callers that genuinely want the whole
    // thing (a purge, and a console page counting across realms).
    realmMap: function (id) { return id === undefined ? per() : per.of(id); },
    get: function (k) { return per().get(k); },
    set: function (k, v) { per().set(k, v); return facade; },
    has: function (k) { return per().has(k); },
    delete: function (k) { return per().delete(k); },
    clear: function () { return per().clear(); },
    forEach: function (fn, thisArg) { return per().forEach(fn, thisArg); },
    keys: function () { return per().keys(); },
    values: function () { return per().values(); },
    entries: function () { return per().entries(); },
    get size() { return per().size; }
  };
  facade[Symbol.iterator] = function () { return per()[Symbol.iterator](); };
  log.debug("Leaving map().");
  return facade;
}

// An Array, per realm. A Proxy rather than a facade because an array is used by
// INDEX and by `length` as much as by method, and no list of delegated methods
// would cover `rows[0]`, `rows.length = 0` or a spread. The proxy target is a
// real array so that `Array.isArray()` — which several callers use — is true.
function arr() {
  log.debug("Entering arr().");
  const per = keyed(function () { return []; });
  log.debug("Leaving arr().");
  return new Proxy([], {
    get: function (target, prop, receiver) {
      const real = per();
      const v = Reflect.get(real, prop, real);
      return typeof v === 'function' ? v.bind(real) : v;
    },
    set: function (target, prop, value) { per()[prop] = value; return true; },
    has: function (target, prop) { return prop in per(); },
    deleteProperty: function (target, prop) { delete per()[prop]; return true; },
    ownKeys: function () { return Reflect.ownKeys(per()); },
    getOwnPropertyDescriptor: function (target, prop) {
      const d = Object.getOwnPropertyDescriptor(per(), prop);
      // A proxy may not report a property as non-configurable when its target
      // has no such property, and the target here is a permanently empty array.
      // Marking every descriptor configurable is what keeps Object.keys() and
      // the spread operator legal over this.
      return d ? Object.assign({}, d, { configurable: true }) : undefined;
    },
    defineProperty: function (target, prop, desc) {
      Object.defineProperty(per(), prop, desc);
      return true;
    }
  });
}

// A plain object, per realm. Same Proxy for the same reason: these are used as
// dictionaries with computed keys, `delete` and `Object.keys()`.
// `factory` is optional and is what makes this usable for SCALARS as well as
// dictionaries: a module with `let seq = 0` beside a realm-partitioned array has
// a counter that counts every realm's rows and a list holding one realm's, and
// the two disagree on the page that shows them both. Declaring
// `realms.obj(() => ({ seq: 0 }))` and spelling the reads `nums.seq` moves the
// counter into the partition with the thing it counts — `nums.seq++` works
// through the proxy exactly as it did through the binding.
function obj(factory) {
  log.debug("Entering obj().");
  const per = keyed(factory || function () { return {}; });
  log.debug("Leaving obj().");
  return new Proxy({}, {
    get: function (target, prop) {
      const real = per();
      const v = real[prop];
      return typeof v === 'function' ? v.bind(real) : v;
    },
    set: function (target, prop, value) { per()[prop] = value; return true; },
    has: function (target, prop) { return prop in per(); },
    deleteProperty: function (target, prop) { delete per()[prop]; return true; },
    ownKeys: function () { return Reflect.ownKeys(per()); },
    getOwnPropertyDescriptor: function (target, prop) {
      const d = Object.getOwnPropertyDescriptor(per(), prop);
      return d ? Object.assign({}, d, { configurable: true }) : undefined;
    },
    defineProperty: function (target, prop, desc) {
      Object.defineProperty(per(), prop, desc);
      return true;
    }
  });
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
  const realm = als.getStore();
  if (!realm || realm.id === DEFAULT_ID || !active()) {
    return null;
  }
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
  return [
    { family: 'OAuth 2.0 / OIDC', state: 'full', by: 'path',
      note: 'Its own issuer, signing key, authorization codes, access and ' +
            'refresh tokens, refresh families, DPoP replay and nonce state, ' +
            'client-assertion replay state and named authorization servers. ' +
            'The CLIENT REGISTRATIONS are shared, because they are entries in ' +
            'the directory: a client registered once can be used in every ' +
            'realm, and what differs is the key its tokens are signed with.' },
    { family: 'Authentication service', state: 'full', by: 'path',
      note: 'Its own sessions and WebAuthn credentials, so signing in to one ' +
            'realm signs you in to that realm only. That is the point of a ' +
            'realm rather than a limitation of one. Who you may sign in AS is ' +
            'shared, since this service checks no password anywhere. The ' +
            'admin console is the ONE reader that crosses this line, and the ' +
            'row below says why.' },
    { family: 'SAML 2.0 / SAML 1.1', state: 'full', by: 'path',
      note: 'Its own entityID and providerID (seeded distinct when the realm ' +
            'is created), its own signing key, request state, artifacts and ' +
            'per-service-provider metadata — whose URL therefore carries the ' +
            'realm as well as the SP digest. The SERVICE PROVIDER ENTRIES are ' +
            'shared, for the reason the OAuth clients are: they are ' +
            'applications in the directory.' },
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
    { family: 'SCIM 2.0', state: 'partial', by: 'path',
      note: 'The ENDPOINTS are per realm and the STORE is not: SCIM ' +
            'provisions into the shared directory, so a user created through ' +
            'one realm\'s /scim/v2 exists in every realm. That is the ' +
            'directory\'s sharing rather than a decision SCIM makes.' },
    { family: 'Admin console and management API', state: 'partial', by: 'path',
      note: 'Every page and every operation is per realm — /admin/config ' +
            'READS and WRITES the realm it is reached in. The two ADMIN ROLES ' +
            'are not: they are groups in the shared directory, so somebody ' +
            'who holds Admin Write holds it in every realm. There is no ' +
            'per-realm administrator — and the CONSOLE SIGN-ON follows that ' +
            'rather than the sessions: its gate resolves the one session ' +
            'cookie in whichever realm minted it, so the realm switcher ' +
            'switches instead of asking you to sign in again. Nothing else ' +
            'reads a session that way; in the realm you switched to, ' +
            '/oauth2/authorize and the SAML and WS-Federation endpoints still ' +
            'see none.' },
    { family: 'LDAP (389 / 636)', state: 'none', by: 'shared',
      note: 'ONE DIRECTORY FOR THE WHOLE PROCESS, and it is the sharing every ' +
            'other line here refers back to. Every realm sees the same ' +
            'people, groups and applications, because LDAP answers on a ' +
            'socket with no path to put a realm segment in. What differs ' +
            'between realms is what each ISSUES about them.' },
    { family: 'Kerberos v5', state: 'none', by: 'shared',
      note: 'One KDC, one principal database and one Kerberos realm name for ' +
            'the whole process — over raw UDP/TCP 88 AND over MS-KKDCP, ' +
            'whose /KdcProxy is reachable under a realm prefix but reaches ' +
            'the same KDC behind it. Kerberos ALREADY HAS a realm and it is ' +
            'the natural discriminator: give each trust realm a krb5.realm of ' +
            'its own, dispatch a request on the realm name it carries, and ' +
            'the shared port serves both. What stands in the way is that ' +
            'krb5.realm is not runtime-settable — the principal database and ' +
            'its long-term keys are built from it when the process starts — ' +
            'so that database has to become per realm and lazily built first.' },
    { family: 'TLS (8443 / 9443)', state: 'none', by: 'shared',
      note: 'Their whole content is what the server saw of the connection, ' +
            'which is a property of the socket and not of a realm.' },
    { family: 'SPIFFE', state: 'none', by: 'shared',
      note: 'One trust domain, one signing authority and one registry per ' +
            'process. A SPIFFE trust domain is already the thing a trust ' +
            'realm is, so the two would be nested rather than combined — and ' +
            'the registry is in the shared directory in any case.' }
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
  onRemove: onRemove,
  realmContext: realmContext,
  keyed: keyed,
  map: map,
  arr: arr,
  obj: obj,
  realmSupport: realmSupport
};
