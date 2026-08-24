'use strict';
//
// File: authorization_servers.js
//
// ===========================================================================
// MORE THAN ONE AUTHORIZATION SERVER, OUT OF ONE PROCESS.
//
// RFC 9700 section 2.6 says an authorization server SHOULD publish RFC 8414
// metadata and a client SHOULD consume it, and the point behind that is worth
// stating in the form the BCP puts it: **do not make clients hard-code security
// capabilities the server can advertise**. A client that has `S256` compiled
// into it works until it meets a server that only does `plain`; a client that
// reads `code_challenge_methods_supported` works against both, and — the part
// that matters for a mock — can be SHOWN to work against both.
//
// This service published one document describing itself. That is enough to be
// compliant and not enough to be useful, because the interesting question about
// a client is not "does it read the metadata" but "what does it do when the
// metadata says something else". So the document is now a PROFILE, selected by
// the path component the two discovery shapes already carry:
//
//   /.well-known/oauth-authorization-server            the `default` profile
//   /.well-known/oauth-authorization-server/tenant1    the `tenant1` profile
//   /tenant1/.well-known/openid-configuration          the same one
//
// Those two URLs existed already — RFC 8414 section 3.1 INSERTS the path and
// OpenID Connect Discovery section 4 APPENDS it, which is the single commonest
// reason a discovery fetch 404s, and this service has answered both for a long
// time. What is new is that the path now selects a CONFIGURATION rather than
// only an issuer identifier.
//
// ---------------------------------------------------------------------------
// ANY CONFIGURATION IS VALID, AND THAT IS THE FEATURE.
//
// A profile is a set of member overrides applied to the document this service
// would otherwise publish. There is no schema on it and there must not be: a
// member this service has never heard of is stored and published, because half
// the value of a mock is answering with something a client did not expect. The
// catalogue below is help for whoever is filling the form, not a constraint —
// it is what `/admin/authorization-servers` offers as suggestions and what it
// explains, and an override outside it is accepted with a note saying it is not
// one this service recognises.
//
// **THE DEFAULTS ARE WHAT THIS SERVICE ALREADY DID.** A profile with no
// overrides publishes exactly the document `asMetadata()` builds, so an
// unconfigured profile — and the `default` one, and any path nobody has
// configured — behaves as this service always has. That is the same contract
// `oauth2.rfc9700` has and it is kept for the same reason.
//
// ---------------------------------------------------------------------------
// A PROFILE IS THE AUTHORIZATION SERVER, NOT A DOCUMENT ABOUT ONE.
//
// This started as a way to publish a different discovery document per path, and
// that was half a feature: the document said one thing and every endpoint went
// on behaving identically, so a client configured from `tenant1`'s metadata was
// configured from a description of somebody else. **The capabilities in the
// document now DRIVE the endpoints.** A profile advertising
// `code_challenge_methods_supported: ["S256"]` refuses `plain` at its own
// authorization endpoint; one advertising `grant_types_supported` without
// `refresh_token` refuses that grant at its own token endpoint. The document is
// the source of truth for both, so it cannot describe an authorization server
// that is not there.
//
// Which endpoints are "its own" is the path: a named authorization server lives
// under `/{id}/oauth2/…`, which is the shape its own document advertises, and
// the unprefixed endpoints are the `default` one. That is the same path
// component OpenID Connect Discovery already appends the well-known segment to,
// so a client that fetched `/{id}/.well-known/openid-configuration` finds
// endpoints beside it rather than somewhere else.
//
// EVERY AUTHORIZATION SERVER STARTS EQUAL. A profile that has never been
// configured has the defaults `asMetadata()` builds — the same capabilities the
// default one has — so `tenant1` and `tenant2` behave identically until
// somebody makes them differ. And a path nobody has configured is CREATED on
// first sight with those defaults rather than 404'd, so an arbitrary name works
// immediately and can then be changed.
//
// ---------------------------------------------------------------------------
// WHAT DRIFT MEANS NOW, because the word changed meaning with the design.
//
// It used to mean "this document lies about this service". That cannot happen
// any more for the members that drive behaviour — the document IS the behaviour.
// What it means now is narrower and more useful: **a member this service cannot
// honour**. `require_pushed_authorization_requests: true` when there is no PAR
// endpoint; `id_token_signing_alg_values_supported: ["ES256"]` when this service
// signs RS256 and nothing else; a `token_endpoint` pointing at another host.
// Those are still publishable, because producing a misconfigured document on
// purpose is a thing a client author needs, and they are still reported —
// `enforceable` on the catalogue row is what tells the two kinds apart.
//
// ---------------------------------------------------------------------------
// WHERE THE PROFILES LIVE, and why it is not the directory.
//
// `applications.js` keeps its registry in `ou=applications` because an
// application is an OBJECT other systems have opinions about — a relying party
// is a thing in the world, and an LDAP client asking what relying parties exist
// is a reasonable question. An authorization server profile is this service's
// own CONFIGURATION, in the same family as the custom claim sets and the
// verifier's request: in memory, gone on restart, changed through the console
// and the management API. Putting it in the directory would make `ou=` a place
// where this service keeps its settings, which is what `config.js` is for.
//
// It is a LIBRARY (rule 3): it registers no route and requires only
// `helpers.js`, so it cannot join a cycle and its position in the require order
// does not matter.
// ===========================================================================

const { log } = require('../common/helpers');

// The profile a request selects when its URL carries no path component. Named
// rather than empty-stringed because it is a value people type into a form and
// read on a page, and "" is not a thing anybody can type.
const DEFAULT_ID = 'default';

// ---------------------------------------------------------------------------
// THE CATALOGUE — help, not schema.
//
// One row per metadata member this service has something to say about, grouped
// so the page can put the SECURITY capabilities RFC 9700 section 2.6 is about
// where a reader will find them. `what` is why a client cares, which is the
// half a bare member name does not carry.
//
// A member that is NOT here is still settable. That is the difference between a
// catalogue and a schema and it is deliberate: `applications.js` REFUSES an
// attribute outside its table because that table is a published contract about
// what an entry carries, and this one accepts anything because the whole point
// is to be able to publish something a client did not expect.
// ---------------------------------------------------------------------------
const MEMBERS = [
  // --- what RFC 9700 section 2.6 is actually about ------------------------
  { name: 'code_challenge_methods_supported', group: 'Security capabilities',
    kind: 'list', enforces: 'which PKCE challenge methods the authorization endpoint accepts',
    what: 'THE ONE THE BCP NAMES OUTRIGHT. A client discovers PKCE support here and nowhere ' +
          'else — there is no other signal — so a server that supports PKCE and does not ' +
          'advertise it will simply never be asked for it. Publish ["S256"] to say S256 only, ' +
          '["plain"] to make a conforming client downgrade, or remove the member entirely to ' +
          'see what a client does when it cannot tell.' },
  { name: 'dpop_signing_alg_values_supported', group: 'Security capabilities',
    kind: 'list', enforces: 'which algorithms a DPoP proof may be signed with',
    what: 'RFC 9449 section 5.1. Its presence is how a wallet learns DPoP is on offer at all. ' +
          'Narrow it to one algorithm to see whether a client honours the list or signs with ' +
          'whatever it has.' },
  { name: 'token_endpoint_auth_methods_supported', group: 'Security capabilities',
    kind: 'list', enforces: 'which client authentication methods the token endpoint accepts',
    what: 'Which of the six this server will verify. RFC 9700 section 2.5 RECOMMENDS the ' +
          'asymmetric ones, so a profile that advertises only private_key_jwt is how you find ' +
          'out whether a client can do it.' },
  { name: 'tls_client_certificate_bound_access_tokens', group: 'Security capabilities',
    kind: 'boolean',
    what: 'RFC 8705 section 3.3. Whether this deployment will bind an access token to the ' +
          'client certificate the connection was made with.' },
  { name: 'authorization_response_iss_parameter_supported', group: 'Security capabilities',
    kind: 'boolean',
    what: 'RFC 9207. A client may only REQUIRE the iss parameter — and so refuse a mix-up ' +
          'attacker\'s response that lacks it — if the metadata says the server sends it. ' +
          'Setting this false while the responses still carry iss is a way to test the ' +
          'client\'s side of that.' },
  { name: 'require_pushed_authorization_requests', group: 'Security capabilities',
    kind: 'boolean',
    what: 'RFC 9126. NOT IMPLEMENTED HERE — there is no PAR endpoint — so setting it true ' +
          'publishes a requirement this server cannot satisfy, which is exactly the ' +
          'misconfiguration a client\'s error path should survive.' },
  { name: 'response_types_supported', group: 'Security capabilities', kind: 'list',
    enforces: 'which response_type values the authorization endpoint answers',
    what: 'RFC 9700 section 2.1.2 rules out the ones that issue an access token from the ' +
          'authorization endpoint. RFC 9700 mode removes them; a profile can put them back in ' +
          'the document without putting them back in the endpoint.' },
  { name: 'response_modes_supported', group: 'Security capabilities', kind: 'list',
    enforces: 'which response_mode values the authorization endpoint answers',
    what: 'How the authorization response gets back to the client: `query`, `fragment`, or ' +
          '`form_post` — which puts it in a request body so it is in no URL, no browser ' +
          'history entry and no Referer (RFC 9700 section 4.3). NOT here: `web_message`, the ' +
          'postMessage-based mode SPAs use for silent renewal. This service has no browser ' +
          'messaging of any kind, and a mode it advertised and did not perform would leave a ' +
          'client waiting for a message that never arrives — which is what asking for one it ' +
          'does not advertise is now refused for.' },
  { name: 'grant_types_supported', group: 'Security capabilities', kind: 'list',
    enforces: 'which grants the token endpoint performs',
    what: 'Section 2.4 rules out `password`. Advertising a grant this server refuses is a ' +
          'promise broken at the token endpoint, which is a client error path worth running.' },

  // --- endpoints ----------------------------------------------------------
  { name: 'issuer', group: 'Identity', kind: 'string',
    what: 'A conforming client MUST reject a document whose issuer is not the identifier it ' +
          'fetched from. Overriding it here produces that refusal deliberately — the same ' +
          'thing oauth2.issuer does globally, per profile.' },
  { name: 'authorization_endpoint', group: 'Endpoints', kind: 'string',
    what: 'Point it elsewhere to produce a misconfigured document. RFC 9700 section 2.6 asks ' +
          'clients to use metadata to REDUCE endpoint misconfiguration; this is how to check ' +
          'that a client actually follows what it read rather than a path it hard-coded.' },
  { name: 'token_endpoint', group: 'Endpoints', kind: 'string',
    what: 'As above. A client that hard-codes /oauth2/token will not notice this changed.' },
  { name: 'userinfo_endpoint', group: 'Endpoints', kind: 'string',
    what: 'OpenID Connect Discovery. Present in the OIDC document only.' },
  { name: 'introspection_endpoint', group: 'Endpoints', kind: 'string', what: 'RFC 7662.' },
  { name: 'revocation_endpoint', group: 'Endpoints', kind: 'string', what: 'RFC 7009.' },
  { name: 'registration_endpoint', group: 'Endpoints', kind: 'string', what: 'RFC 7591.' },
  { name: 'end_session_endpoint', group: 'Endpoints', kind: 'string',
    what: 'RP-Initiated Logout. OIDC document only.' },

  // --- keys ---------------------------------------------------------------
  { name: 'jwks_uri', group: 'Keys', kind: 'string',
    what: 'KEY ROTATION AND AGILITY is the third thing RFC 9700 section 2.6 wants metadata ' +
          'for: a client that fetches the JWKS every time survives a key change, and one that ' +
          'cached a PEM does not. This service regenerates its signing key on every start, so ' +
          'a client that caches is already going to fail here — pointing this at a second URL ' +
          'is how to test the same thing on purpose.' },
  { name: 'id_token_signing_alg_values_supported', group: 'Keys', kind: 'list',
    what: 'What this server will sign an ID Token with. It signs RS256 whatever this says, so ' +
          'advertising ES256 is a way to find out whether a client checks `alg` against the ' +
          'list or against the token.' },

  // --- documents ----------------------------------------------------------
  { name: 'scopes_supported', group: 'Documents and limits', kind: 'list',
    what: 'RFC 9700 section 2.3 is about least privilege; this is the list a client picks from.' },
  { name: 'service_documentation', group: 'Documents and limits', kind: 'string', what: '' },
  { name: 'op_policy_uri', group: 'Documents and limits', kind: 'string', what: '' },
  { name: 'op_tos_uri', group: 'Documents and limits', kind: 'string', what: '' },
  { name: 'ui_locales_supported', group: 'Documents and limits', kind: 'list', what: '' }
];

const MEMBER_BY_NAME = {};
MEMBERS.forEach(function (row) { MEMBER_BY_NAME[row.name] = row; });

const GROUPS = MEMBERS.reduce(function (out, row) {
  if (out.indexOf(row.group) < 0) out.push(row.group);
  return out;
}, []);

// ---------------------------------------------------------------------------
// The store. In memory, gone on restart, exactly like the custom claim sets and
// the verifier's request — see the header for why this is not in the directory.
// ---------------------------------------------------------------------------
const profiles = new Map();   // id -> { id, label, description, overrides, removed, at }

// An id has to survive being a URL path segment and being typed into a form.
// Refused by NAME rather than sanitised, because a profile silently renamed
// from `tenant 1` to `tenant%201` is one nobody can find again.
const ID_SHAPE = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,63}$/;

function idProblem(id) {
  const text = String(id || '').trim();
  if (!text) {
    return 'An id is required: it is the path component that selects this profile — ' +
           '/.well-known/oauth-authorization-server/<id>.';
  }
  if (!ID_SHAPE.test(text)) {
    return '"' + text + '" cannot be a profile id. It has to be a single URL path segment: ' +
           '1 to 64 characters of letters, digits, dot, dash, underscore or tilde, starting ' +
           'with a letter or a digit. A profile whose id had to be escaped to appear in a URL ' +
           'would be one nobody could find again.';
  }
  return null;
}

function blank(id) {
  return { id: String(id), label: '', description: '',
           overrides: {}, removed: [], at: 0,
           // When this authorization server was first ASKED FOR, and how many
           // times. An auto-created one has been asked for once by definition;
           // the count is what /admin/sts-metadata lists the accessed ones by.
           createdAt: Date.now(), seenAt: 0, seen: 0, autoCreated: false };
}

// ---------------------------------------------------------------------------
// EVERY NAME IS AN AUTHORIZATION SERVER, whether or not anybody configured one.
//
// A path nobody has configured used to publish the ordinary document and behave
// as the default one; now it is CREATED, with the defaults, on first sight. The
// difference is that it can then be configured, appear on a page and be told
// apart from its neighbours — an authorization server somebody is using and
// cannot see is worse than one that exists with nothing special about it.
//
// It is marked `autoCreated` so the console can say which ones a caller
// invented and which somebody chose, and the two are otherwise identical:
// EVERY AUTHORIZATION SERVER STARTS EQUAL, with the capabilities the default
// one has, and differs only where somebody has made it differ.
//
// Bounded, because the id comes off a URL path and any caller can invent one.
// Past the cap a name is still SERVED — with the defaults, which is what it
// would have had anyway — and simply not recorded, so a load generator cannot
// take the feature away from the names that matter.
// ---------------------------------------------------------------------------
const MAX_PROFILES = 200;

function ensure(id, options) {
  const opts = options || {};
  const key = String(id || '').trim();
  log.debug("Entering ensure(). id=" + key);
  if (!key || idProblem(key)) {
    log.debug("Leaving ensure(). Not a usable id.");
    return null;
  }
  let profile = profiles.get(key);
  if (!profile) {
    if (profiles.size >= MAX_PROFILES) {
      // Warned rather than thrown: the request that named it is answered with
      // the defaults, which is what an unconfigured name has always produced.
      log.warn('authorization_servers: not recording "' + key + '"; ' + MAX_PROFILES +
               ' profiles are held (the id comes off a URL path, so any caller can invent ' +
               'one). It is still served, with the defaults.');
      log.debug("Leaving ensure(). The registry is full.");
      return null;
    }
    profile = blank(key);
    profile.autoCreated = !!opts.autoCreated;
    profiles.set(key, profile);
    log.info('authorization_servers: "' + key + '" ' +
             (opts.autoCreated ? 'was asked for and did not exist, so it now does'
                               : 'created') + ', with the default capabilities. ' +
             profiles.size + ' authorization server(s).');
  }
  if (opts.seen) {
    profile.seen++;
    profile.seenAt = Date.now();
  }
  log.debug("Leaving ensure(). seen=" + profile.seen);
  return profile;
}

function get(id) {
  return profiles.get(String(id || '')) || null;
}

function has(id) {
  return profiles.has(String(id || ''));
}

function count() {
  return profiles.size;
}

// ---------------------------------------------------------------------------
// APPLYING a profile to the document this service would otherwise publish.
//
// Three operations and the order matters: REMOVALS happen after overrides, so a
// member can be both set and removed and the removal wins — which is what a
// reader of the form expects, and the alternative (a removal a later override
// silently resurrects) is a control that does nothing.
//
// `null` is not special here. A member overridden to null is PUBLISHED as null,
// because JSON has a null and a client that mishandles one is a client worth
// finding out about; removing a member is what the removals list is for.
// ---------------------------------------------------------------------------
function apply(metadata, id) {
  log.debug("Entering apply(). profile=" + (id || DEFAULT_ID));
  const profile = get(id || DEFAULT_ID);
  if (!profile) {
    // Not an error: an unconfigured path component publishes the document this
    // service always published, with the issuer built from the path. That is
    // what every existing caller sees and it must stay true.
    log.debug("Leaving apply(). No profile by that name; the document is unchanged.");
    return metadata;
  }
  Object.keys(profile.overrides).forEach(function (member) {
    metadata[member] = profile.overrides[member];
  });
  profile.removed.forEach(function (member) {
    delete metadata[member];
  });
  log.debug("Leaving apply(). " + Object.keys(profile.overrides).length + " override(s), " +
            profile.removed.length + " removal(s).");
  return metadata;
}

// ---------------------------------------------------------------------------
// THE CAPABILITIES OF ONE AUTHORIZATION SERVER — one function, read by the
// endpoints AND by the document, which is the whole of how the two are kept in
// step.
//
// `defaults` is the document this service builds for itself; the profile's
// overrides and removals are applied on top; the result is what gets published
// AND what the endpoints enforce. There is no second table of "what tenant1
// does" that could disagree with what tenant1 advertises, because there is no
// second table.
//
// A REMOVED member is `undefined` rather than an empty list, and the callers
// treat that as "this server has nothing to say about it" — which for an
// enforceable member means the check does not run. That is the honest reading:
// a client cannot learn from an absent `code_challenge_methods_supported` that
// PKCE is unavailable, so a server that refused every method on the strength of
// having removed the member would be enforcing something it never said.
// ---------------------------------------------------------------------------
function capabilitiesOf(id, defaults) {
  const merged = Object.assign({}, defaults || {});
  const profile = get(id);
  if (!profile) {
    return merged;
  }
  Object.keys(profile.overrides).forEach(function (member) {
    merged[member] = profile.overrides[member];
  });
  profile.removed.forEach(function (member) {
    delete merged[member];
  });
  return merged;
}

// One capability as a LIST, for the four members that are lists and drive a
// check. `null` means the server said nothing — see above — and every caller
// distinguishes that from an empty list, which means it said "none".
function capabilityList(id, defaults, member) {
  const merged = capabilitiesOf(id, defaults);
  const value = merged[member];
  if (value === undefined) {
    return null;
  }
  return Array.isArray(value) ? value.map(String) : [String(value)];
}

// ---------------------------------------------------------------------------
// WHAT THE PROFILE MAKES THIS DOCUMENT SAY THAT IS NOT TRUE.
//
// Every surface reports this, because a mock that let somebody publish a
// misleading document is useful and one that did it quietly is a trap. It is
// computed by comparing the profile's overrides against the document this
// service would have published — so it needs no list of its own and cannot go
// stale as the real document grows members.
//
// A REMOVAL is drift too, and the subtler kind: a client that cannot find
// `code_challenge_methods_supported` does not know PKCE is unavailable, it
// knows nothing, and section 2.6's whole argument is about that difference.
// ---------------------------------------------------------------------------
function driftOf(id, truth) {
  log.debug("Entering driftOf(). profile=" + id);
  const profile = get(id);
  if (!profile) {
    log.debug("Leaving driftOf(). No such profile.");
    return [];
  }
  const rows = [];
  Object.keys(profile.overrides).forEach(function (member) {
    const published = profile.overrides[member];
    const actual = truth ? truth[member] : undefined;
    if (JSON.stringify(published) === JSON.stringify(actual)) {
      return;
    }
    const spec = MEMBER_BY_NAME[member];
    // AN ENFORCEABLE MEMBER IS NOT DRIFT. It used to be — the document said one
    // thing and every endpoint did another — and now the endpoints read this
    // value, so a difference from the DEFAULT document is this authorization
    // server being configured rather than lying. What is left as drift is the
    // rest: a member this service cannot honour however it is set.
    if (spec && spec.enforces) {
      return;
    }
    rows.push({
      member: member, published: published, actual: actual,
      kind: actual === undefined ? 'invented' : 'not-enforceable',
      what: actual === undefined
        ? 'Not a member this service builds, so nothing here backs it — which is allowed, and ' +
          'is how a document a client did not expect gets published.'
        : 'This service cannot make this true: it does not read this member, and would ' +
          'otherwise publish ' + JSON.stringify(actual) + '. A client configured from it will ' +
          'behave as though it were.'
    });
  });
  profile.removed.forEach(function (member) {
    if (!truth || truth[member] === undefined) {
      return;
    }
    const spec = MEMBER_BY_NAME[member];
    rows.push({
      member: member, published: undefined, actual: truth[member], kind: 'removed',
      what: spec && spec.enforces
        ? 'Removed, so this server says nothing about it — and the check it drives (' +
          spec.enforces + ') does not run. A client cannot learn from an absent member that a ' +
          'capability is unavailable; it learns nothing, which is what section 2.6 is about.'
        : 'Removed from the document. A client cannot then tell that this server supports it — ' +
          'which is not the same as learning that it does not.'
    });
  });
  log.debug("Leaving driftOf(). " + rows.length + " member(s) this service cannot honour.");
  return rows;
}

// ---------------------------------------------------------------------------
// The write operations. Each returns { ok } or { ok: false, errors } in the
// shape every other console action uses, so `admin.js` renders them the same
// way without knowing what a profile is.
// ---------------------------------------------------------------------------
function create(detail) {
  const info = detail || {};
  const id = String(info.id || '').trim();
  log.debug("Entering create(). id=" + id);
  const problem = idProblem(id);
  if (problem) {
    log.debug("Leaving create(). " + problem);
    return { ok: false, errors: [problem] };
  }
  if (has(id)) {
    log.debug("Leaving create(). It exists already.");
    return { ok: false, errors: ['There is already an authorization server profile called "' +
                                 id + '". Change it rather than creating it again.'] };
  }
  const profile = ensure(id, {});
  if (!profile) {
    return { ok: false, errors: ['This service is holding its maximum of ' + MAX_PROFILES +
                                 ' authorization servers. Delete one first.'] };
  }
  profile.label = String(info.label || '');
  profile.description = String(info.description || '');
  profile.at = Date.now();
  log.info('authorization_servers: profile "' + id + '" created. ' + profiles.size +
           ' profile(s). It is served at /.well-known/oauth-authorization-server/' + id +
           ' and /' + id + '/.well-known/openid-configuration.');
  log.debug("Leaving create(). Created.");
  return { ok: true, profile: view(id) };
}

function setMember(id, member, rawValue) {
  log.debug("Entering setMember(). id=" + id + ", member=" + member);
  const profile = get(id);
  if (!profile) {
    return { ok: false, errors: ['There is no authorization server profile called "' + id +
                                 '".'] };
  }
  const name = String(member || '').trim();
  if (!name) {
    return { ok: false, errors: ['Which member? Any RFC 8414 member name is accepted, and so ' +
                                 'is one this service has never heard of — publishing ' +
                                 'something a client did not expect is half the point.'] };
  }
  // JSON FIRST, then the raw string. A form field carrying `["S256"]` means a
  // list and one carrying `S256` means a string, and guessing from the member's
  // catalogue `kind` instead would be wrong for every member not in the
  // catalogue — which is the case this file exists to allow.
  let value = rawValue;
  if (typeof rawValue === 'string') {
    const text = rawValue.trim();
    try {
      value = JSON.parse(text);
    } catch (e) {
      // Not JSON, so it is a plain string. Not an error and not worth a log
      // line: `https://example.com/token` is the ordinary case.
      value = rawValue;
    }
  }
  profile.overrides[name] = value;
  // A member being set is a member not being removed. Without this, setting one
  // that had been removed would leave it removed and the form would appear to
  // have done nothing.
  profile.removed = profile.removed.filter(function (one) { return one !== name; });
  profile.at = Date.now();
  log.info('authorization_servers: profile "' + id + '" now publishes ' + name + '=' +
           JSON.stringify(value) + '.');
  log.debug("Leaving setMember(). Set.");
  return { ok: true, profile: view(id),
           message: name + ' is now ' + JSON.stringify(value) + ' in the "' + id +
                    '" document.' + (MEMBER_BY_NAME[name] ? '' :
                    ' That is not a member this service recognises, which is allowed: any ' +
                    'configuration is valid here.') };
}

function removeMember(id, member) {
  log.debug("Entering removeMember(). id=" + id + ", member=" + member);
  const profile = get(id);
  if (!profile) {
    return { ok: false, errors: ['There is no authorization server profile called "' + id +
                                 '".'] };
  }
  const name = String(member || '').trim();
  if (!name) {
    return { ok: false, errors: ['Which member?'] };
  }
  delete profile.overrides[name];
  if (profile.removed.indexOf(name) < 0) {
    profile.removed.push(name);
  }
  profile.at = Date.now();
  log.info('authorization_servers: profile "' + id + '" no longer publishes ' + name + '.');
  log.debug("Leaving removeMember(). Removed.");
  return { ok: true, profile: view(id),
           message: name + ' is gone from the "' + id + '" document. A client reading it ' +
                    'cannot tell that this server supports it — which is not the same as ' +
                    'learning that it does not.' };
}

// One member back to what this service would publish. Different from removing
// it, and the difference is the whole reason both exist: this UNDOES an
// override, that PUBLISHES an absence.
function resetMember(id, member) {
  log.debug("Entering resetMember(). id=" + id + ", member=" + member);
  const profile = get(id);
  if (!profile) {
    return { ok: false, errors: ['There is no authorization server profile called "' + id +
                                 '".'] };
  }
  const name = String(member || '').trim();
  const had = Object.prototype.hasOwnProperty.call(profile.overrides, name) ||
              profile.removed.indexOf(name) >= 0;
  delete profile.overrides[name];
  profile.removed = profile.removed.filter(function (one) { return one !== name; });
  profile.at = Date.now();
  log.debug("Leaving resetMember(). " + (had ? "Reset." : "It was not overridden."));
  return { ok: true, profile: view(id),
           message: had
             ? name + ' is back to what this service publishes for it.'
             : name + ' was not overridden in "' + id + '", so nothing changed.' };
}

function remove(id) {
  log.debug("Entering remove(). id=" + id);
  if (!has(id)) {
    return { ok: false, errors: ['There is no authorization server profile called "' + id +
                                 '".'] };
  }
  profiles.delete(String(id));
  log.info('authorization_servers: profile "' + id + '" deleted. ' + profiles.size + ' left.');
  log.debug("Leaving remove(). Deleted.");
  return { ok: true,
           message: '"' + id + '" is gone. The two discovery URLs that carried it still answer ' +
                    '— with the document this service builds, and the issuer taken from the ' +
                    'path — because an unconfigured path component has always been served ' +
                    'that way rather than 404\'d.' };
}

function view(id) {
  const profile = get(id);
  if (!profile) {
    return null;
  }
  return {
    id: profile.id,
    label: profile.label,
    description: profile.description,
    overrides: Object.assign({}, profile.overrides),
    removed: profile.removed.slice(0),
    changedAt: profile.at ? new Date(profile.at).toISOString() : '',
    memberCount: Object.keys(profile.overrides).length + profile.removed.length,
    // The two URLs this profile is served at, spelt out rather than left to be
    // assembled: the whole reason both shapes exist is that people get them
    // wrong, and a page that made somebody derive them would be repeating the
    // problem it documents.
    autoCreated: profile.autoCreated,
    seen: profile.seen,
    seenAt: profile.seenAt ? new Date(profile.seenAt).toISOString() : '',
    createdAt: profile.createdAt ? new Date(profile.createdAt).toISOString() : '',
    urls: {
      oauth: '/.well-known/oauth-authorization-server/' + profile.id,
      oidc: '/' + profile.id + '/.well-known/openid-configuration',
      // ITS OWN ENDPOINTS, which is what makes it an authorization server rather
      // than a document about one. They are what its metadata advertises, so a
      // client that read that document is already using them.
      authorize: '/' + profile.id + '/oauth2/authorize',
      token: '/' + profile.id + '/oauth2/token'
    }
  };
}

function list() {
  const rows = [];
  profiles.forEach(function (profile) { rows.push(view(profile.id)); });
  rows.sort(function (a, b) { return a.id.localeCompare(b.id); });
  return rows;
}

module.exports = {
  DEFAULT_ID: DEFAULT_ID,
  MAX_PROFILES: MAX_PROFILES,
  ensure: ensure,
  capabilitiesOf: capabilitiesOf,
  capabilityList: capabilityList,
  MEMBERS: MEMBERS,
  GROUPS: GROUPS,
  apply: apply,
  driftOf: driftOf,
  create: create,
  setMember: setMember,
  removeMember: removeMember,
  resetMember: resetMember,
  remove: remove,
  get: view,
  has: has,
  list: list,
  count: count
};
