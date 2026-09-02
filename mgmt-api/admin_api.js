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
//     function the console's form posts to — admin.tokenAction, claimsAction,
//     vcAction, vpConfigAction — with `action` taken from the URL instead of
//     from a hidden input, and every GET calls the same JSON view the page's
//     `?format=json` answers. So adding an action to the console's switch is
//     most of adding it here: what is left is one row of the table below.
//   * **The OpenAPI document is built from that table** (admin_api_spec.js), so
//     an operation cannot exist and be undocumented, and cannot be documented
//     and not exist. What no code can check is the direction that matters — a
//     new console control with no row here — and that is what the parent
//     project's tests/vendored/admin_api.js asserts, by walking the console's own NAV
//     and the action names each of its four handlers accepts.
//
// ---------------------------------------------------------------------------
// NOT PROTECTED, deliberately — AND THE CONSOLE NOW IS, so this paragraph is no
// longer "exactly as the console is not" and the difference has to be argued
// rather than assumed.
//
// `admin.authRequired` gates every page and form under /admin: a sign-on session
// and one of two roles. It does NOT gate anything here, and that is three
// decisions rather than an omission:
//
//   * **A test drives this API.** The parent project's tests/vendored/admin_api.js walks
//     every operation over HTTP with no browser and no cookie jar. A credential
//     on this surface would be the only one a test had to hold a secret for, in
//     a service whose premise is that it authenticates nobody.
//   * **It is the way back in.** With `admin.openWhenEmpty` off and no role
//     granted, NO browser can reach the console at all — the screen that grants
//     the first role is behind the gate the role opens. `POST
//     /admin-api/rbac/grant` is the only door out of that state, and one that
//     needed a role would not be a door.
//   * **The honest consequence, stated rather than buried:** anybody who can
//     reach this port can grant themselves both roles here and then use the
//     console. The gate is a turnstile for exercising a client's 302/401/403
//     paths, not a lock — this service still checks no password anywhere and
//     /oauth2/token will still mint a token for any username asked of it. Do
//     not put this service on a public address.
//
// If that ever needs to change it is a SEPARATE setting and a separate argument
// (`admin.apiAuthRequired` was considered and not built), not a quiet extension
// of admin.authRequired to this path — a test suite that started failing because
// a console setting reached an API it never named would be the worst possible
// way to find out.
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
const { log, parseBody, baseUrlOf } = require('../common/helpers');
const admin = require('../admin-ui/admin');
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
const spec = require('./admin_api_spec');
const docs = require('./admin_api_docs');
// The trust realm this call arrived in — for the explorer, which is the one
// page in this service that builds its URLs in a script and therefore cannot
// have its markup rewritten. See docs.page().
const realms = require('../common/realms');
const VERSION = require('../package.json').version;

const BASE = '/admin-api';

// Every reply here is JSON, is never cached, and is pretty-printed. The last of
// those is not decoration: the caller of a mock's admin API is usually a person
// at a terminal or a test whose failure message is the body, and a 40 KB single
// line is unreadable in both.
function sendJson(res, status, body) {
  log.debug("Entering sendJson(). status=" + status);
  res.status(status).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(body, null, 2));
  log.debug("Leaving sendJson().");
}

// The action a POST names, from the path rather than the body. It is forced
// over whatever the body carried so that a body copied from the console's form
// — which does carry `action` — cannot mean something other than the URL it was
// sent to.
function withAction(req, body) {
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
// on /users, two on /groups. One `page` would move all of them together, so each
// gets a parameter named after itself and `per` above stays shared.
//
// Every one is clamped the way `page` is, and every one is answered: the reply
// carries a `<name>Paging` object beside the array, with the same member names
// the flat lists put at the top level. A caller walks these exactly as it walks
// /tokens, one list at a time.
// ONE NAME PER LIST: the parameter is the reply array's own name with `Page` on
// the end, and the object answering it is that name with `Paging` on the end. A
// caller that can read the reply can therefore write the request without a table
// mapping one set of names onto the other.
function detailPagingParameters(lists) {
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
// test that the parameterisation was real: `sets`, `noun`, `carrier`, `example`,
// `reserved` and the operationIds were the whole of what varied between the
// first two, and they were the whole of what varied for the third.
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
      description: 'Every ' + family.carrier + ' of that kind issued from now ' +
                   'on carries it; nothing already issued changes.\n\n' +
                   'ADDITIVE ONLY. What the protocol puts in is never ' +
                   'displaced — an ID Token\'s `sub`, a SAML 2.0 assertion\'s ' +
                   '`name`, a WS-Federation assertion\'s whole identity claim ' +
                   'list.' +
                   (family.reserved
                     ? ' A name this service sets itself is REFUSED rather ' +
                       'than allowed to win, because every one of those is ' +
                       'load-bearing — a settable `exp` would produce tokens ' +
                       'that fail to verify with nothing pointing back at the ' +
                       'call that caused it. `GET /admin-api/claims` lists the ' +
                       'refused names.'
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
    description: 'The thirteen `oauth2.*` settings: the issuer identifier, ' +
                 'RFC 9700 mode, the registered redirect URIs and the ' +
                 'loopback port wildcard, Front-Channel Logout, the refresh ' +
                 'token idle timeout, whether a sign-out revokes refresh ' +
                 'tokens, the client assertion clock skew, the four ' +
                 'lifetimes `GET /token-lifetimes` also reports — and ' +
                 '`oauth2.breakIdTokenNonce`, which makes this service return ' +
                 'an ID Token whose `nonce` is WRONG so that a client can be ' +
                 'shown to check it.\n\n`oauth2.rfc9700` is restart-only and ' +
                 'says so in `restartReason`: `global.https` derives from it ' +
                 'and a listener\'s scheme is settled when the socket is ' +
                 'bound. A TRUST REALM can carry it while the process does ' +
                 'not, which is how one process answers permissively at ' +
                 '/oauth2/authorize and enforces the BCP under a realm ' +
                 'prefix.' },
  { path: '/oid4vci-settings', console: '/admin/oid4vci', tag: 'OpenID4VCI',
    operationId: 'getOid4vciSettings',
    summary: 'The credential issuer\'s own settings',
    description: 'The nine `oid4vci.*` settings: the wallet an offer sends a ' +
                 'holder to, the authorization server the credential endpoint ' +
                 'will take a token from, the batch size, the deferred ' +
                 'issuance timings, the offer username, whether a credential ' +
                 'request must be encrypted, and the two that decide whether ' +
                 'the SD-JWT VC and `ldp_vc` issuers name themselves by ' +
                 '`did:web` or by URL.\n\nThose two are restart-only and they ' +
                 'change what a VERIFIER has to resolve — a key fetched from ' +
                 'a DID document rather than from JWKS. What a credential ' +
                 'CONTAINS is `GET /credential-claims`.' },
  { path: '/oid4vp-settings', console: '/admin/oid4vp', tag: 'OpenID4VP',
    operationId: 'getOid4vpSettings',
    summary: 'The mock Verifier\'s own settings',
    description: 'The four `oid4vp.*` settings: the client identifier the ' +
                 'verifier presents as, where it sends a holder to present, ' +
                 'the Key Binding JWT\'s maximum age, and the claims asked ' +
                 'for when nothing else has been chosen.\n\n' +
                 '`oid4vp.walletUrl` is DERIVED: with no value of its own it ' +
                 'is the OID4VCI wallet, since it is the same wallet in every ' +
                 'arrangement this service is used in. Its `source` is ' +
                 '`default` for that reason and for no other. The DCQL query ' +
                 'itself is `GET /verifier-request`.' },
  { path: '/kerberos', console: '/admin/kerberos', tag: 'Kerberos',
    operationId: 'getKerberosSettings',
    summary: 'The KDC\'s own settings',
    description: 'The nineteen `krb5.*` settings: the realm, the two raw ' +
                 'ports, the clock skew and the deliberate clock OFFSET, the ' +
                 'one password every user account shares, the names that stay ' +
                 'unknown, the long-term keys behind krbtgt and the ' +
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
  // whole failure mode this feature has. See admin.js's persistenceStatusBlock().
  { path: '/persistence', console: '/admin/persistence', tag: 'Persistence',
    operationId: 'getPersistenceSettings',
    summary: 'What survives a restart, where it is written, and whether that ' +
             'is working',
    description: 'The six `persistence.*` settings AND — unlike every other ' +
                 'operation in this group — a `status` member saying what the ' +
                 'store is actually doing: which mode is in force, whether it ' +
                 'FELL BACK to memory because it could not be opened, where ' +
                 'it writes, how many entries and realms it holds, when it ' +
                 'last wrote, and the error if the last write failed.\n\n' +
                 'THREE THINGS PERSIST when a store is on: the embedded LDAP ' +
                 'directory (which is also the applications registry, the ' +
                 'federation register and the SPIFFE registry — they are ' +
                 'directory entries and nothing else), the trust realm ' +
                 'registry, and the runtime appconfig overrides that ' +
                 '`POST /admin-api/config/set` writes.\n\n' +
                 'NOTHING THIS SERVICE MINTS EVER PERSISTS, in any mode: ' +
                 'sessions, access tokens, ID Tokens, refresh tokens, ' +
                 'authorization codes, pre-authorized codes, SAML artifacts, ' +
                 'Kerberos tickets, the replay caches, the statistics and the ' +
                 'audit log all go with the process. The signing key is ' +
                 'regenerated on every start, so a token restored from a disk ' +
                 'would verify against nothing.\n\n' +
                 'PERSISTENCE IS NOT COORDINATION. Two processes pointed at ' +
                 'one Postgres database each hold their own copy of the ' +
                 'directory in memory and will not see each other\'s writes ' +
                 'until they restart. `status.coordinates` is `false` and ' +
                 'says so; running several copies against one store is not ' +
                 'yet a way to scale this service.\n\n' +
                 'FIVE OF THE SIX SETTINGS ARE RESTART-ONLY, because the ' +
                 'store is opened and read before the HTTP listener binds. ' +
                 '`persistence.databaseUrl` is never echoed back in `status` ' +
                 '— it carries a password, so the host, port, database and ' +
                 'user are parsed out of it and reported instead.' },
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
                 'response.\n\nThe assertion it carries is a SAML 1.1 one, so ' +
                 'its Issuer is `saml.issuer` (on `GET /saml2` and ' +
                 '`GET /saml11`) and its contents are ' +
                 '`GET /saml-attributes`. `wauth` is recorded and not ' +
                 'honoured and `wreqptr` is never dereferenced; neither is a ' +
                 'setting, and the page says so rather than implying a ' +
                 'missing one.' },
  { path: '/tls', console: '/admin/tls', tag: 'TLS',
    operationId: 'getTlsSettings',
    summary: 'The two TLS listeners\' own settings',
    description: 'The four `tls.*` settings: the two ports, and the hostnames ' +
                 'and IP addresses that go into the self-signed certificate ' +
                 'this service mints on every start.\n\nALL FOUR ARE ' +
                 'RESTART-ONLY: the certificate is minted and the sockets are ' +
                 'bound before anything is listening. One certificate serves ' +
                 '8443, 9443, LDAPS 636 and — when `global.https` is on — the ' +
                 'main port, so a caller trusts this service once rather than ' +
                 'four times.\n\nWhether the MAIN port is HTTPS is ' +
                 '`global.https`, which is on `GET /config` with the rest of ' +
                 'the process\'s own settings: it is a fact about the process ' +
                 'rather than about these listeners, and it defaults to ' +
                 'whatever `oauth2.rfc9700` is.' }
].map(function (row) {
  return { method: 'GET', path: BASE + row.path, tag: row.tag,
           operationId: row.operationId,
           summary: row.summary,
           description: row.description +
             '\n\nTHERE IS NO POST BESIDE THIS ONE and that is not a gap: ' +
             'every form on the console page this mirrors posts `set-many` to ' +
             '/admin/config, so `POST /admin-api/config/set-many` is already ' +
             'the operation for it. One store, one action, two doors.',
           mirrors: 'GET ' + row.console,
           responseDescription: 'What the page says, and the settings it ' +
                                'draws — described rows carrying each ' +
                                'value\'s source and whether it can be ' +
                                'changed while the service runs.',
           responseSchema: { $ref: '#/components/schemas/PageSettings' },
           handler: function (req, res) {
             log.debug("Entering the management API " + row.console + " endpoint.");
             sendJson(res, 200, admin.protocolSettingsJsonFor(row.console));
             log.debug("Leaving the management API " + row.console + " endpoint.");
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
        openapi: base + BASE + '/openapi.json',
        docs: base + BASE + '/docs',
        console: base + '/admin',
        protected: false,
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
      sendJson(res, 200, spec.buildSpec(ROUTES, {
        baseUrl: baseUrlOf(req), version: VERSION
      }));
      log.debug("Leaving the OpenAPI document endpoint.");
    } },

  // ---------------------------------------------------------------------
  // THE CRYPTO REPORT. It calls `admin.cryptoView()` and computes nothing of
  // its own, which is rule 7 read strictly: the page and this operation must
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
                 'and XML Encryption, WS-Security, COSE, X.509, Kerberos.\n\n' +
                 'EVERY ALGORITHM LIST IN THE REPLY IS READ FROM THE MODULE ' +
                 'THAT PERFORMS THE ALGORITHM, the way GET ' +
                 '/admin/sts-metadata reads its endpoint list off the live ' +
                 'express router — so it cannot claim something this service ' +
                 'does not do, and it reports drift against that page\'s own ' +
                 'family list in both directions.\n\nThe `postQuantum` member ' +
                 'is the one to read before quoting this reply: the ' +
                 'signatures are partly post-quantum and the key ' +
                 'establishment is entirely classical, and those are ' +
                 'reported separately because a signature is checked when it ' +
                 'is presented while captured ciphertext can be kept and ' +
                 'opened later.\n\nNOTHING HERE IS A SECRET: key types, key ' +
                 'identifiers, curve names, certificate fingerprints and ' +
                 'validity dates only, all of them already readable from ' +
                 '/oauth2/jwks, /tls/server-certificate and the SPIFFE bundle ' +
                 'endpoint. Nothing changes anything.',
    mirrors: 'GET /admin/crypto-metadata',
    responseDescription: 'The whole report.',
    responseSchema: { $ref: '#/components/schemas/CryptoMetadata' },
    handler: function (req, res) {
      log.debug("Entering the management API crypto metadata endpoint.");
      const report = admin.cryptoView(req);
      if (!report) {
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
  // THE KEY PAIRS. Two operations, because LISTING what this process holds and
  // HANDING A KEY OVER are different acts and only the second is a write.
  // ---------------------------------------------------------------------
  { method: 'GET', path: BASE + '/keys', tag: 'Service',
    operationId: 'getKeys',
    summary: 'Every key pair this process generated at start, and what it is for',
    description: 'A LIST and never key material. The signing keys are per ' +
                 'trust realm and the TLS certificate belongs to the process, ' +
                 'and each row says which. `formats` is what that key can be ' +
                 'exported as, computed rather than listed: a key with no ' +
                 'certificate cannot be a PKCS#12, and a post-quantum key has ' +
                 'no PKCS#8 encoding at all, so the answer differs per key for ' +
                 'two different reasons.\n\nNothing here is key material. ' +
                 'POST /admin-api/keys/export is the operation that hands one ' +
                 'over.',
    mirrors: 'GET /admin/keys',
    responseDescription: 'The key pairs.',
    responseSchema: { $ref: '#/components/schemas/KeyList' },
    handler: function (req, res) {
      log.debug("Entering the management API key list endpoint.");
      const report = admin.keysView(req);
      if (!report) {
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
        sendJson(res, 400, { ok: false, errors: [
          'Unknown action "' + body.action + '". The actions here are: ' +
          'export.'] });
        log.debug("Leaving the management API key export endpoint. " +
                  "Unknown action.");
        return;
      }
      const pending = admin.keysExport(String(body.key || ''),
                                       String(body.format || 'pem'),
                                       String(body.password || ''));
      if (!pending) {
        sendJson(res, 503, { ok: false, errors: [
          'The crypto reporter is not installed in this process.'] });
        log.debug("Leaving the management API key export endpoint. No reporter.");
        return;
      }
      pending.then(function (result) {
        if (!result.ok) {
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
        sendJson(res, 400, { ok: false, errors: ['The export failed: ' +
                                                 e.message] });
        log.debug("Leaving the management API key export endpoint. Threw.");
      });
    },
    actions: [
      { action: 'export', operationId: 'exportKey',
        summary: 'Hand over one key pair, in a chosen keystore format',
        description: 'THIS OPERATION RETURNS PRIVATE KEY MATERIAL. It is the API ' +
                 'half of the one page in this console where reading is ' +
                 'taking.\n\nIt is defensible because of what these keys ' +
                 'are: generated at start, held only in memory, dead when the ' +
                 'process exits, and protecting nothing — this service checks ' +
                 'no password and validates no token it did not mint. **This ' +
                 'API is not gated at all**, so anybody who can reach this ' +
                 'port can call it; that is the same honest consequence every ' +
                 'other operation here has, stated again because this one ' +
                 'returns a key.\n\n`format` is one of `pem`, `der`, `jwk` ' +
                 'or `pkcs12`. A password is REQUIRED for `pkcs12` and ' +
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
                        description: 'REQUIRED for `pkcs12`; optional for the ' +
                                     'other three, where it encrypts the ' +
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

  { method: 'GET', path: BASE + '/docs', tag: 'Service',
    operationId: 'getDocs',
    summary: 'The explorer: every operation, with a form that calls it',
    description: 'A page that reads the document above and renders one form ' +
                 'per operation. It is this repository\'s own rather than ' +
                 'Swagger UI, and the reason is the service it lives in: ' +
                 'swagger-ui-dist is 11.7 MB with an install-time telemetry ' +
                 'dependency, in a service that is deliberately ' +
                 'dependency-light and must build offline. It does the same ' +
                 'job — read the spec, fill a form, see the response.',
    mirrors: 'GET /admin',
    responseDescription: 'The explorer page.',
    responseType: 'text/html',
    responseSchema: { type: 'string' },
    handler: function (req, res) {
      log.debug("Entering the API explorer page.");
      // The one place in this service that relaxes the Content-Security-Policy
      // app.js sets, and it relaxes exactly one clause: this page has a script
      // and every other page here has none. It is served from a file of its
      // own rather than inline precisely so that `'self'` is enough and
      // `'unsafe-inline'` is not needed — see the note in admin_api_docs.js.
      res.setHeader('Content-Security-Policy', docs.CONTENT_SECURITY_POLICY);
      res.status(200).type('text/html').set('Cache-Control', 'no-store')
         .send(docs.page(baseUrlOf(req), BASE, VERSION, realms.currentPrefix()));
      log.debug("Leaving the API explorer page.");
    } },

  { method: 'GET', path: BASE + '/docs/explorer.js', tag: 'Service',
    operationId: 'getDocsScript',
    summary: 'The explorer\'s script',
    description: 'The only script this service serves. It is a separate ' +
                 'resource rather than an inline block so that the page can ' +
                 'be allowed `script-src \'self\'` instead of ' +
                 '`\'unsafe-inline\'`.',
    mirrors: 'GET /admin',
    responseDescription: 'The script.',
    responseType: 'application/javascript',
    responseSchema: { type: 'string' },
    handler: function (req, res) {
      log.debug("Entering the API explorer script endpoint.");
      res.setHeader('Content-Security-Policy', docs.CONTENT_SECURITY_POLICY);
      res.status(200).type('application/javascript')
         .set('Cache-Control', 'no-store').send(docs.SCRIPT);
      log.debug("Leaving the API explorer script endpoint.");
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
      sendJson(res, 200, admin.metricsJson());
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
                 '`?user=alice&session-8Qk3...Page=2` moves that block and no ' +
                 'other, and each session in the reply answers with its own ' +
                 '`tokensPaging`. It is named after the session rather than ' +
                 'numbered so that the link still moves the same session after ' +
                 'the list around it has changed, and it is paged at all ' +
                 'because one browser session can hold most of the tokens this ' +
                 'service remembers. OpenAPI cannot spell a parameter whose ' +
                 'name is built at runtime, and a `session-{id}Page` in the ' +
                 'list would generate a client that sends a literal `{id}` — ' +
                 'so it is here in words instead.',
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
      sendJson(res, 200, admin.usersView(req).json);
      log.debug("Leaving the management API users endpoint.");
    } },

  { method: 'POST', route: BASE + '/users/:action', tag: 'Users',
    mirrors: 'POST /admin/users',
    handler: function (req, res) {
      log.debug("Entering the management API users action endpoint.");
      const body = parseBody(req);
      const result = admin.usersAction(withAction(req, body));
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API users action endpoint.");
    },
    actions: [
      { action: 'create', operationId: 'createUser',
        summary: 'Put a person in the directory before they authenticate',
        description: 'An entry under `ou=users` usually appears because ' +
                     'somebody AUTHENTICATED — at either sign-in screen, on a ' +
                     'password grant, with a `UsernameToken`, in a Kerberos ' +
                     'AS-REQ. This is how to get one in ahead of that, which ' +
                     'is what a client testing claims from the directory ' +
                     'needs: the entry carries the invented person behind that ' +
                     'name, so a credential issued for them and an ' +
                     '`ldapsearch` for the entry say the same thing from the ' +
                     'start.\n\n**One entry per person, and this is one of ' +
                     'three doors onto that rule.** A username already here is ' +
                     'refused with the DN that holds it — whatever protocol ' +
                     'brought them, and whichever attribute their entry is ' +
                     'named by, since a person whose entry was created by a ' +
                     'client certificate is at `cn=<name>,ou=users` rather ' +
                     'than `uid=<name>,ou=users`. An `ldapadd` under ' +
                     '`ou=users` gets the same refusal as ' +
                     'LDAP_ENTRY_ALREADY_EXISTS (68), because all three call ' +
                     'one function.\n\n**No password is set** — none is ever ' +
                     'checked here, in this protocol or any other. Creating ' +
                     'the entry does not put the name in `GET ' +
                     '/admin-api/users`: that lists identities this service ' +
                     'has SEEN authenticate, and this writes what the ' +
                     'directory HOLDS.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            username: { type: 'string',
                        description: 'The name they will authenticate under — ' +
                                     'the same string that appears in a ' +
                                     'token\'s `sub` and on /admin/users. Not ' +
                                     'a DN and not a `did:`, and it may not ' +
                                     'carry a character RFC 4514 reserves in ' +
                                     'a DN: those name entries that get here ' +
                                     'by being presented rather than by being ' +
                                     'created.' },
            note: { type: 'string',
                    description: 'Optional. What the entry\'s `description` ' +
                                 'says about why it exists; the default says ' +
                                 'it was created by hand rather than by ' +
                                 'authenticating.' }
          },
          required: ['username'],
          examples: [{ username: 'rcbj' }],
          additionalProperties: false
        },
        responseDescription: 'The entry as created, in `entry`, with its `dn`.' }
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
                 'nothing consults the issuer when they are presented — and a ' +
                 'reply that omitted them would make a global logout look ' +
                 'complete when it is not.\n\nThe identity is a QUERY ' +
                 'PARAMETER and not a path segment for the reason ' +
                 '/admin-api/users gives: the identities here contain the ' +
                 'characters a path is made of.',
    mirrors: 'GET /admin/logout',
    parameters: [
      { name: 'user', in: 'query', required: false, schema: { type: 'string' },
        description: 'The identity to look at, as typed. It is normalised the ' +
                     'way every other door here normalises one, so `alice`, ' +
                     '`alice@REALM` and a `urn:` subject are one answer.' },
      { name: 'family', in: 'query', required: false, schema: { type: 'string' },
        description: 'Only rows of this family. The `families` member of the ' +
                     'reply says which values there are; it is read off the ' +
                     'same table the endpoint acts on, so a family that ' +
                     'cannot occur is never offered.' }
    ].concat(pagingParameters()),
    responseDescription: 'The family list, or one identity\'s live state.',
    responseSchema: { $ref: '#/components/schemas/LogoutInventory' },
    handler: function (req, res) {
      log.debug("Entering the management API sign-out endpoint.");
      sendJson(res, 200, admin.logoutView(req).json);
      log.debug("Leaving the management API sign-out endpoint.");
    } },

  { method: 'POST', route: BASE + '/logout/:action', tag: 'Sign-out',
    mirrors: 'POST /admin/logout',
    handler: function (req, res) {
      log.debug("Entering the management API sign-out action endpoint.");
      const body = parseBody(req);
      const result = admin.logoutAction(withAction(req, body));
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
                     'come back in `notifications` and `cleanups` so a caller ' +
                     'can load them, and `/logout` is the page where a ' +
                     'browser does it by itself.',
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
                             '`unknown`, and the three fan-outs a browser has ' +
                             'to perform.' },
      { action: 'end', operationId: 'endLiveSessions',
        summary: 'End named items and nothing else',
        description: 'The selective half. `select` carries row ids from the ' +
                     'GET — `session:<id>`, `token:<jti>`, ' +
                     '`wsfed-rp:<session>|<realm>`, and so on.\n\n**An empty ' +
                     '`select` is REFUSED here and is a global logout at ' +
                     '`POST /logout`**, which is the one place the two doors ' +
                     'differ and is deliberate: an empty selection arriving ' +
                     'at this operation is a caller that built a list and got ' +
                     'nothing, where an empty body at /logout is a caller ' +
                     'asking for everything. Same absence, opposite intent.\n' +
                     '\nIds are re-resolved against what is live NOW rather ' +
                     'than trusted, so an id that has since been redeemed or ' +
                     'expired ends nothing and is answered in `unknown` or ' +
                     '`skipped` rather than ending something else.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            user: { type: 'string', description: 'The identity to act on.' },
            select: { type: 'array', items: { type: 'string' },
                      description: 'Row ids from `GET /admin-api/logout?user=`.' }
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
                     'reason is that restarting this service to get back to a ' +
                     'working token turns a two-second test into a ' +
                     'two-minute one.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            user: { type: 'string', description: 'The identity, for the audit row.' },
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
                 'NOTHING: no token, assertion, ticket or PAC this service ' +
                 'issues carries a group from this directory, and no ' +
                 'endpoint reads one.',
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
      sendJson(res, 200, admin.groupsView(req).json);
      log.debug("Leaving the management API groups endpoint.");
    } },

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
  // `admin.directoryPageJson()` and the slot `ldap/ldap_server.js` fills — see
  // the block above `setDirectoryPages()` in `admin-ui/admin.js` for why it
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
                 'nothing, and it is why the operational attributes are here: ' +
                 'a search withholds `createTimestamp` and `modifyTimestamp` ' +
                 'unless they are asked for by name (RFC 4511 §4.5.1.8) and ' +
                 'this is not a search.\n\n`q` matches the DN, any attribute ' +
                 'NAME and any attribute VALUE, case-insensitively — values ' +
                 'because the caller who needs this most often has a ' +
                 'thumbprint or a secret in hand and no idea which entry ' +
                 'carries it.\n\nTHE REPLY IS THIS REALM\'S DIRECTORY AND NO ' +
                 'OTHER. Since 2026-08-25 each trust realm has a subtree of ' +
                 'its own; reach another realm\'s through its own path prefix.',
    mirrors: 'GET /admin/ldap/directory',
    parameters: [
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the DN, of an attribute name, or of an ' +
                     'attribute value. Case-insensitive.' },
      { name: 'origin', in: 'query', required: false, schema: { type: 'string' },
        description: 'Only entries that came from here. The values actually ' +
                     'present are in `origins`.' }
    ].concat(pagingParameters()),
    responseDescription: 'The page of entries, with the filter and the paging.',
    responseSchema: { $ref: '#/components/schemas/DirectoryEntryList' },
    handler: function (req, res) {
      log.debug("Entering the management API directory entries endpoint.");
      sendJson(res, 200, admin.directoryPageJson('directory', req));
      log.debug("Leaving the management API directory entries endpoint.");
    } },

  { method: 'GET', path: BASE + '/ldap/applications', tag: 'LDAP',
    operationId: 'getDirectoryApplications',
    summary: 'The application registry as the directory holds it, and its schema',
    description: 'One entry per identifier under `ou=applications`, every ' +
                 'attribute on it, and the published SCHEMA — the object ' +
                 'classes and every attribute name with what sets ' +
                 'it.\n\nTHE SCHEMA IS WHY THIS IS NOT `GET ' +
                 '/admin-api/applications`. That operation is the registry as ' +
                 'the console works with it: the counters, the drill-down, ' +
                 'the writes. This is the registry as the DIRECTORY holds it, ' +
                 'and the vocabulary is the half a client reading an entry ' +
                 'back over 389 actually needs — this directory is ' +
                 'schemaless, so an entry carrying thirty invented attribute ' +
                 'names is otherwise guesswork.\n\nTHESE ENTRIES ARE THE ' +
                 'REGISTRY rather than a copy of one. Nothing caches them, so ' +
                 'an `ldapmodify` of `oauthRedirectUri` changes which ' +
                 'redirect URI RFC 9700 mode accepts on the next ' +
                 'request.\n\nTwo attributes hold CREDENTIALS in the clear, ' +
                 'for the reason `/krb5/principals` prints the Kerberos ' +
                 'passwords. They are never written to the audit log.',
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
      sendJson(res, 200, admin.directoryPageJson('applications', req));
      log.debug("Leaving the management API directory applications endpoint.");
    } },

  { method: 'GET', path: BASE + '/ldap/federations', tag: 'LDAP',
    operationId: 'getDirectoryFederations',
    summary: 'The federation register as the directory holds it, and its schema',
    description: 'The application registry\'s twin, for `ou=federations` — ' +
                 'and THE ONE CONTAINER IN THIS DIRECTORY WHERE AN LDAPMODIFY ' +
                 'IS A SECURITY CHANGE. Everywhere else an edit changes what ' +
                 'this service HANDS OUT; `fedSigningCertificate` decides ' +
                 'whose assertions it will BELIEVE and `fedEnabled` turns a ' +
                 'partner on.\n\nIt is a container of its own rather than a ' +
                 'corner of `ou=applications` because half its entries are ' +
                 'FOREIGN IDENTITY PROVIDERS, which ask this service for ' +
                 'nothing at all.\n\nThe schema carries a column the ' +
                 'applications one has no need of: which DIRECTION each ' +
                 'attribute is for.\n\n`fedClientSecret` is REDACTED in ' +
                 '`relationships` and present in the entry\'s own attributes, ' +
                 'which is the same split the page makes: what a script reads ' +
                 'is redacted, and a page claiming to say what the directory ' +
                 'holds may not hide a value an `ldapsearch` shows.',
    mirrors: 'GET /admin/ldap/federations',
    parameters: [
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the relationship id, the DN, the protocol ' +
                     'or the direction. Case-insensitive.' }
    ].concat(pagingParameters()),
    responseDescription: 'The page of relationships, the roles, the protocols ' +
                         'and the schema.',
    responseSchema: { $ref: '#/components/schemas/DirectoryFederationList' },
    handler: function (req, res) {
      log.debug("Entering the management API directory federations endpoint.");
      sendJson(res, 200, admin.directoryPageJson('federations', req));
      log.debug("Leaving the management API directory federations endpoint.");
    } },

  { method: 'GET', path: BASE + '/ldap/spiffe', tag: 'LDAP',
    operationId: 'getDirectorySpiffe',
    summary: 'The two SPIFFE containers as the directory holds them, and their schema',
    description: 'THE TWO CONTAINERS HOLD DIFFERENT KINDS OF THING, which is ' +
                 'why they are two. `ou=entries` is CONFIGURATION — which ' +
                 'SPIFFE ID a workload gets, under which parent, matching ' +
                 'which selectors — and `ou=agents` is a RECORD of what has ' +
                 'attested, which is why nothing about an agent is editable ' +
                 'anywhere.\n\nTHE ENTRIES ARE THE REGISTRY: nothing caches ' +
                 'them, so an `ldapmodify` of `spiffeX509SvidTtl` changes the ' +
                 'lifetime of the next SVID the Workload API hands ' +
                 'out.\n\nTHIS IS THE ONE DIRECTORY OPERATION WITH TWO LISTS ' +
                 'IN IT, so it pages the way the console\'s drill-downs do: ' +
                 '`entriesPage` and `agentsPage` move one list each and `per` ' +
                 'is shared, with an `entriesPaging` and an `agentsPaging` ' +
                 'object in the reply. `entries` and `agents` at the top ' +
                 'level are the TOTALS and not the page.',
    mirrors: 'GET /admin/ldap/spiffe',
    parameters: [
      { name: 'entryq', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of a registration entry\'s SPIFFE ID or DN.' },
      { name: 'agentq', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of an attested agent\'s id or DN.' }
    ].concat(pagingParameters()).concat(detailPagingParameters([
      { name: 'entries', description: 'The registration entries.' },
      { name: 'agents', description: 'The attested agents.' }
    ])),
    responseDescription: 'The two pages, the two containers and the schema.',
    responseSchema: { $ref: '#/components/schemas/DirectorySpiffe' },
    handler: function (req, res) {
      log.debug("Entering the management API directory SPIFFE endpoint.");
      sendJson(res, 200, admin.directoryPageJson('spiffe', req));
      log.debug("Leaving the management API directory SPIFFE endpoint.");
    } },

  // LAST OF THE FIVE, and it is the one that answers about the SOCKETS rather
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
                 'it.\n\nNO BIND IS EVER REFUSED here, by any setting, except ' +
                 'the one literal password named in `refusedPassword` — which ' +
                 'exists so a negative test has something to fail on.',
    mirrors: 'GET /admin/ldap/service',
    parameters: [],
    responseDescription: 'The directory as it is right now.',
    responseSchema: { $ref: '#/components/schemas/DirectoryService' },
    handler: function (req, res) {
      log.debug("Entering the management API directory service endpoint.");
      sendJson(res, 200, admin.directoryPageJson('service', req));
      log.debug("Leaving the management API directory service endpoint.");
    } },

  // --- The console's own roles ---------------------------------------------
  //
  // TWO OPERATIONS, AND THIS RESOURCE MATTERS MORE THAN THE OTHERS RATHER THAN
  // LESS. Rule 7 says a console control gets an operation in the same change;
  // here the API half is not merely parity, it is the ONLY door onto the roster
  // that still works when nobody holds a role and `admin.openWhenEmpty` is off.
  // The console cannot let you fix that — you cannot reach it — so this can, and
  // `/admin-api` is deliberately not gated by `admin.authRequired`.
  //
  // Which is worth saying plainly rather than leaving to be discovered: WITH THE
  // CONSOLE PROTECTED AND THIS API OPEN, ANYBODY WHO CAN REACH THIS PORT CAN
  // GRANT THEMSELVES BOTH ROLES. That is not an oversight in the gate, it is the
  // same decision the whole service is built on — this is a mock whose value is
  // exercising clients, the management API is how a test drives it, and a port
  // that mints a token for any username asked of it is not made safe by a
  // password on one of its web pages. The gate exists so a client can be driven
  // through 302 / 401 / 403 and a role model, not to make this service safe to
  // expose. Do not put this port on a public address.
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
                 'group.\n\n**While NEITHER group has a member**, ' +
                 '`openToAnyone` is true and anybody who signs in holds both ' +
                 'roles — there is no password anywhere in this service to ' +
                 'bootstrap an administrator with, so an empty roster opens ' +
                 'rather than closes. `admin.openWhenEmpty` turns that off, ' +
                 'and `closedToEveryone` reports the state it produces: a ' +
                 'console no browser can reach, which is what this resource ' +
                 'is the way out of.\n\nNONE OF IT IS IN FORCE while ' +
                 '`admin.authRequired` is off (`enforced: false`). The ' +
                 'grants are still real and can be made in advance.',
    mirrors: 'GET /admin/rbac',
    parameters: [
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the person\'s name or of the raw ' +
                     'membership value, case-insensitive.' },
      { name: 'role', in: 'query', required: false,
        schema: { type: 'string', enum: rbac.ROLE_IDS },
        description: 'Only grants of this role.' }
    ].concat(pagingParameters()),
    responseDescription: 'The roster, the settings, and who is asking.',
    handler: function (req, res) {
      log.debug("Entering the management API admin roles endpoint.");
      sendJson(res, 200, admin.rbacView(req).json);
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
      const result = admin.rbacAction(withAction(req, body),
                                      { via: 'api', actor: '' });
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
                     'roster**, which re-opens the console to anybody who ' +
                     'signs in (or closes it to everybody, if ' +
                     '`admin.openWhenEmpty` is off). The reply says which.',
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

  { method: 'GET', path: BASE + '/tokens', tag: 'Tokens',
    operationId: 'getIssued',
    summary: 'Everything issued: JWTs, SAML assertions and Kerberos tickets',
    description: 'One list, newest first, filtered and paged. Claims and ' +
                 'facts only — the signed token, the assertion XML and the ' +
                 'ticket are never kept, and the `jti` is all any operation ' +
                 'here needs.\n\nOID4VCI credentials are NOT in this list. ' +
                 'They are counted on /admin-api/metrics and listed nowhere, ' +
                 'which is a gap rather than a principle and is said here so ' +
                 '"everything issued" is read as the three families it says.',
    mirrors: 'GET /admin/tokens',
    parameters: [
      { name: 'family', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'One protocol family. The reply\'s `families` member ' +
                     'lists them with the kinds in each.' },
      { name: 'kind', in: 'query', required: false, schema: { type: 'string' },
        description: 'One kind. ANDed with `family`, so a kind from another ' +
                     'family matches nothing — which is what an empty list ' +
                     'then means.' },
      { name: 'state', in: 'query', required: false,
        schema: { type: 'string',
                  enum: ['valid', 'expired', 'revoked', 'not yet valid',
                         'no expiry stated'] },
        description: 'One state.' }
    ].concat(pagingParameters()),
    responseDescription: 'The matching rows, with the paging that found them.',
    responseSchema: { $ref: '#/components/schemas/IssuedList' },
    handler: function (req, res) {
      log.debug("Entering the management API issued-list endpoint.");
      sendJson(res, 200, admin.tokensView(req.query).json);
      log.debug("Leaving the management API issued-list endpoint.");
    } },

  { method: 'POST', route: BASE + '/tokens/:action', tag: 'Tokens',
    mirrors: 'POST /admin/tokens',
    handler: function (req, res) {
      log.debug("Entering the management API token action endpoint.");
      const body = parseBody(req);
      const result = admin.tokenAction(withAction(req, body));
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
          examples: [{ subject: 'urn:sts-mock:user:alice' }],
          additionalProperties: false
        },
        responseDescription: 'How many were revoked, in `revoked`.' },

      { action: 'revoke-user', operationId: 'revokeTokensByUser',
        summary: 'Revoke everything for one identity, under every spelling',
        description: 'The users list\'s `key`, and every spelling of it — ' +
                     '`alice`, `urn:sts-mock:user:alice` and ' +
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
                 'segment at the front of the path.\n\n' +
                 'The DEFAULT realm has no prefix, cannot be removed and ' +
                 'cannot be renamed: every URL this service published before ' +
                 'realms existed is a URL in it. A process with no realms ' +
                 'defined behaves exactly as it did before this feature ' +
                 'existed, which is a property of one predicate rather than a ' +
                 'claim.\n\n' +
                 'Each row carries the realm\'s `pathPrefix`, its `baseUrl`, ' +
                 'the `kid` of its signing key — two realms showing one kid ' +
                 'would be two names for one authorization server — the ' +
                 'settings it sets, and the four discovery documents a client ' +
                 'asks for first.\n\n' +
                 '`support` is the part answered nowhere else: WHICH ' +
                 'protocol families a realm actually separates, which is not ' +
                 'a tidy answer. A realm separates what this service ISSUES ' +
                 'and everything it holds while issuing it — keys, sessions, ' +
                 'codes, tokens, offers, artifacts, statistics and the audit ' +
                 'log. It does NOT separate the embedded directory: LDAP ' +
                 'answers on a socket with no path to put a segment in, so ' +
                 'there is one set of people, groups and applications for the ' +
                 'whole process — which means OAuth client registrations, ' +
                 'SAML service provider entries, the SPIFFE registry and the ' +
                 'two admin console roles are shared. Kerberos, the two TLS ' +
                 'listeners and SPIFFE\'s four sockets are shared for the ' +
                 'same reason.\n\n' +
                 '`reserved` is the list of ids a realm may not be called, ' +
                 'read off the live router: they are the first segments of ' +
                 'paths this service already serves, and the refusal stands ' +
                 'whatever `realms.pathSegment` is set to precisely so that ' +
                 'clearing that setting cannot turn an existing realm into a ' +
                 'shadow over the console or the authorization server.',
    mirrors: 'GET /admin/realms',
    responseDescription: 'The realms, and the support table.',
    handler: function (req, res) {
      log.debug("Entering the management API trust realms endpoint.");
      sendJson(res, 200, admin.realmsJson(req));
      log.debug("Leaving the management API trust realms endpoint.");
    } },

  { method: 'POST', route: BASE + '/realms/:action', tag: 'Trust realms',
    mirrors: 'POST /admin/realms',
    handler: function (req, res) {
      log.debug("Entering the management API trust realms action endpoint.");
      const body = parseBody(req);
      const result = admin.realmsAction(withAction(req, body));
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
                    description: 'What a person calls it. Free text; defaults ' +
                                 'to the id.' },
            description: { type: 'string' },
            overrides: { type: 'object',
                         description: 'Settings to set on the realm, named by ' +
                                      'the dot paths GET /admin-api/config ' +
                                      'lists. They win over the six seeded ' +
                                      'names. `realms.enabled` and ' +
                                      '`realms.pathSegment` are refused: a ' +
                                      'realm that could switch realms off, or ' +
                                      'move the prefix it was found under, ' +
                                      'would be doing it half way through the ' +
                                      'request that found it.' }
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
                     'whatever the process as a whole is configured with, and ' +
                     'below nothing.\n\n' +
                     'This is the same store `POST /realm/<id>/admin-api/' +
                     'config/set` writes to, and either is fine; the ' +
                     'difference is only which realm you have to be in to ' +
                     'make the call. A setting whose `editable` is false is ' +
                     'refused with the reason, exactly as it is on the ' +
                     'service-wide resource, and `realms.enabled` and ' +
                     '`realms.pathSegment` are refused outright.',
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
                     'a realm re-created with the same id inheriting the last ' +
                     'one\'s sessions and tokens would be the single most ' +
                     'surprising thing a re-created realm could do.\n\n' +
                     'NOTHING IS REMOVED FROM THE DIRECTORY, because nothing ' +
                     'there belongs to a realm: `ou=users`, `ou=groups` and ' +
                     '`ou=applications` are shared by every realm in this ' +
                     'process.\n\n' +
                     'A realm cannot remove ITSELF — a call to ' +
                     '`/realm/acme/admin-api/realms/remove` naming `acme` is ' +
                     'refused. Everything about the removal would work; what ' +
                     'would not is the caller, which would be talking to a ' +
                     'prefix that had stopped existing. Call it from another ' +
                     'realm, or from the default one.\n\n' +
                     'The DEFAULT realm cannot be removed at all.',
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
                 'module.\n\n' +
                 'It also says which settings can be CHANGED while the ' +
                 'service runs. The ones that cannot were consumed at ' +
                 'startup — a bound socket, the TLS certificate\'s names, the ' +
                 'Kerberos principal database and its long-term keys, the ' +
                 'directory\'s base DN — and each carries the reason.',
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
      const result = admin.configAction(withAction(req, body));
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
                     'down and re-applied at the next start through this same ' +
                     'function, which is why it adds no sixth layer. See ' +
                     '`GET /admin-api/persistence`.\n\nNOTHING HERE WRITES ' +
                     'TO THE APPCONFIG FILE in either mode, and that is ' +
                     'deliberate rather than unfinished: a service that ' +
                     'edited a file checked into a repository would leave a ' +
                     'test\'s forgotten change behind permanently. The ' +
                     'durable copy goes to the persistent store, which is not ' +
                     'a place anything is checked in from.\n\nThe change ' +
                     'applies to the next token, assertion, ticket or search. ' +
                     'Nothing already issued changes, because a token is a ' +
                     'signed document.\n\nA setting whose `editable` is false ' +
                     'is REFUSED with the reason rather than accepted, and a ' +
                     'value that does not fit the setting\'s type is refused ' +
                     'by name.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            key: { type: 'string',
                   description: 'The dot path, as GET /admin-api/config ' +
                                'lists it.' },
            value: { description: 'A string is always accepted and is coerced ' +
                                  'to the setting\'s type, so the environment ' +
                                  'spelling works here too; a JSON number, ' +
                                  'boolean or array of strings is accepted ' +
                                  'where the type takes one.' }
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
                     'declared; `applied` says which were taken and `changed` ' +
                     'which actually differed from what was already in force.',
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
  // handler calls `admin.tokenLifetimesAction`, which writes through
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
      sendJson(res, 200, admin.tokenLifetimesJson());
      log.debug("Leaving the management API token lifetimes endpoint.");
    } },

  { method: 'POST', route: BASE + '/token-lifetimes/:action',
    tag: 'Token lifetimes',
    mirrors: 'POST /admin/token-lifetimes',
    handler: function (req, res) {
      log.debug("Entering the management API token lifetimes action.");
      const body = parseBody(req);
      const result = admin.tokenLifetimesAction(withAction(req, body));
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
          properties: narrowDoorProperties(admin.tokenLifetimeKeys()),
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
  // admin.samlAssertionsAction, which writes through config.setOverride()
  // against the same override map POST /config/set writes to, and the same
  // map the two identity provider pages' own forms write to. Four doors, one
  // thing.
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
                 'numbers, and includes `saml2WindowS` and `saml11WindowS` ' +
                 '— the WHOLE width of the stated window, which is the ' +
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
                 '`saml11.assertionLifetimeMin` governs it.\n\n`saml.clockSkewS` ' +
                 'IS NOT `oauth2.clockSkewS`. This one is written INTO a ' +
                 'document this service issues. That one is the tolerance ' +
                 'applied wherever this service READS one back, including an ' +
                 'inbound federation partner\'s assertion, and it is on ' +
                 '`GET /token-lifetimes`.\n\nIt also reports what has ' +
                 'already been issued, per profile, counted against this ' +
                 'service\'s own clock with no allowance applied.\n\nA ' +
                 'WINDOW IS STAMPED INTO AN ASSERTION WHEN IT IS SIGNED, so ' +
                 'changing one reaches the next assertion and nothing ' +
                 'already issued.',
    mirrors: 'GET /admin/saml-assertions',
    responseDescription: 'The three settings, and what has been issued ' +
                         'under them.',
    responseSchema: { $ref: '#/components/schemas/SamlAssertions' },
    handler: function (req, res) {
      log.debug("Entering the management API SAML assertions endpoint.");
      sendJson(res, 200, admin.samlAssertionsJson());
      log.debug("Leaving the management API SAML assertions endpoint.");
    } },

  { method: 'POST', route: BASE + '/saml-assertions/:action',
    tag: 'SAML assertions',
    mirrors: 'POST /admin/saml-assertions',
    handler: function (req, res) {
      log.debug("Entering the management API SAML assertions action.");
      const body = parseBody(req);
      const result = admin.samlAssertionsAction(withAction(req, body));
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
          properties: narrowDoorProperties(admin.samlAssertionKeys()),
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
      sendJson(res, 200, admin.claimsJson(admin.claimsPreviewUser(req.query)));
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
      const result = admin.claimsAction(withAction(req, body), names,
                                        stats.JWT_CLAIM_SET_IDS);
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
                 'signed documents: a claim added to one of those sets reaches ' +
                 'a client at its next sign-in and never reaches what it ' +
                 'already holds. A claim added here reaches the next ' +
                 '`GET /oauth2/userinfo` from a client that signed in an hour ' +
                 'ago and has done nothing since. That is the whole reason it ' +
                 'is configured separately from the ID Token set rather than ' +
                 'being the same list under two names.\n\nThe set has the same ' +
                 'TWO HALVES as every other and they are configured by ' +
                 'different operations. `claims` are TYPED: a name and a value ' +
                 'somebody wrote, the same for everybody except where a ' +
                 '${placeholder} carries the sign-in. `attributes` are LDAP ' +
                 'ATTRIBUTE TYPES chosen from `attributeCatalogue`, whose ' +
                 'value is read off that person\'s entry under ou=users — so ' +
                 'an `ldapmodify` changes the next response, with no new ' +
                 'sign-in at all.\n\n`reservedJwtClaims` IS here, unlike ' +
                 'GET /admin-api/saml-attributes, and the reason is worth ' +
                 'reading before assuming it is a copy-paste: `sub` is ' +
                 'REQUIRED in this response (OIDC Core 5.3.2, and a client ' +
                 'MUST check it against the ID Token\'s), and when a client ' +
                 'has registered a `userinfo_signed_response_alg` the whole ' +
                 'response is a JWT carrying `iss`, `aud` and `exp`.\n\n' +
                 '`claimsRequest` is the half no operation here sets: OIDC ' +
                 'Core section 5.5 lets a CLIENT name individual claims in the ' +
                 '`claims` request parameter, and this service answers them ' +
                 'off the same catalogue. It lists every name a request may ' +
                 'use, the four layers of precedence, what is carried and NOT ' +
                 'enforced (`essential`, `value`, `values`), and the non-spec ' +
                 'way to send one straight to the endpoint.',
    mirrors: 'GET /admin/userinfo-claims',
    parameters: [
      { name: 'user', in: 'query', required: false,
        schema: { type: 'string', default: 'alice' },
        description: 'Whose attribute values to preview. The same parameter, ' +
                     'the same cap and the same default GET /admin-api/claims ' +
                     'takes, deliberately: the three replies preview one ' +
                     'person unless asked otherwise. `preview.entryFound` says ' +
                     'whether the directory holds them or the values were ' +
                     'invented from the username.' },
      { name: 'request', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'A section 5.5 claims request, as the JSON a client would ' +
                     'send — for example ' +
                     '`{"userinfo":{"birthdate":null,"address":null}}`. The ' +
                     'reply\'s `claimsRequest.preview` then says exactly what ' +
                     'that request would return for `user`, computed by the ' +
                     'two functions the UserInfo endpoint itself calls. A ' +
                     'MALFORMED one is reported in `claimsRequest.preview.' +
                     'error` and does NOT fail this call: what it shows is the ' +
                     '`invalid_request` a client would be given, which is the ' +
                     'thing a caller is asking about.' }
    ],
    responseDescription: 'The UserInfo set, the attribute catalogue, the ' +
                         'preview and the section 5.5 vocabulary.',
    responseSchema: { $ref: '#/components/schemas/UserInfoClaimSets' },
    handler: function (req, res) {
      log.debug("Entering the management API UserInfo claims endpoint.");
      sendJson(res, 200,
               admin.userinfoClaimsJson(admin.claimsPreviewUser(req.query),
                                        admin.claimsRequestParameter(req.query)));
      log.debug("Leaving the management API UserInfo claims endpoint.");
    } },

  { method: 'POST', route: BASE + '/userinfo-claims/:action',
    tag: 'UserInfo claims',
    mirrors: 'POST /admin/userinfo-claims',
    handler: function (req, res) {
      log.debug("Entering the management API UserInfo claims action endpoint.");
      const body = parseBody(req);
      const names = namesOf(req, body, 'attribute', 'attributes');
      const result = admin.claimsAction(withAction(req, body), names,
                                        stats.USERINFO_CLAIM_SET_IDS);
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
  { method: 'GET', path: BASE + '/saml-attributes', tag: 'Custom SAML attributes',
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
                 'absence is the answer rather than an omission: that list is ' +
                 'enforced for a JWT set only, because an assertion attribute ' +
                 'called `exp` collides with nothing. `defaultSaml11Namespace` ' +
                 'is the rule that IS this family\'s — the namespace a 1.1 ' +
                 'attribute gets when the call does not name one.\n\nThe two ' +
                 'JWT sets are at GET /admin-api/claims. One store behind ' +
                 'both, and one audit row per change whichever door made it.',
    mirrors: 'GET /admin/saml-attributes',
    parameters: [
      { name: 'user', in: 'query', required: false,
        schema: { type: 'string', default: 'alice' },
        description: 'Whose attribute values to preview. Defaults to a ' +
                     'person the directory holds from startup, so the ' +
                     'preview shows real values on a fresh process. Somebody ' +
                     'with no entry gets generated values — the same ' +
                     'invented person every time, seeded from the name — and ' +
                     '`preview.entryFound` says which of the two happened. It ' +
                     'is the same parameter, the same cap and the same ' +
                     'default GET /admin-api/claims takes, deliberately: the ' +
                     'two replies preview one person unless asked otherwise.' }
    ],
    responseDescription: 'The two SAML sets, the attribute catalogue and the ' +
                         'preview.',
    responseSchema: { $ref: '#/components/schemas/SamlAttributeSets' },
    handler: function (req, res) {
      log.debug("Entering the management API SAML attributes endpoint.");
      sendJson(res, 200,
               admin.samlAttributesJson(admin.claimsPreviewUser(req.query)));
      log.debug("Leaving the management API SAML attributes endpoint.");
    } },

  { method: 'POST', route: BASE + '/saml-attributes/:action',
    tag: 'Custom SAML attributes',
    mirrors: 'POST /admin/saml-attributes',
    handler: function (req, res) {
      log.debug("Entering the management API SAML attributes action endpoint.");
      const body = parseBody(req);
      const names = namesOf(req, body, 'attribute', 'attributes');
      const result = admin.claimsAction(withAction(req, body), names,
                                        stats.SAML_CLAIM_SET_IDS);
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
      sendJson(res, 200, admin.vcJson(admin.vcPreviewUser(req.query)));
      log.debug("Leaving the management API credential-claims endpoint.");
    } },

  { method: 'POST', route: BASE + '/credential-claims/:action',
    tag: 'Credential claims',
    mirrors: 'POST /admin/vc',
    handler: function (req, res) {
      log.debug("Entering the management API credential-claims action.");
      const body = parseBody(req);
      const names = namesOf(req, body, 'attribute', 'attributes');
      const result = admin.vcAction(withAction(req, body), names);
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
          properties: { attribute: { type: 'string' } },
          required: ['attribute'],
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
          properties: { attribute: { type: 'string' } },
          required: ['attribute'],
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
      sendJson(res, 200, admin.vpConfigJson());
      log.debug("Leaving the management API verifier-request endpoint.");
    } },

  { method: 'POST', route: BASE + '/verifier-request/:action',
    tag: 'Verifier request',
    mirrors: 'POST /admin/vc-verifier-config',
    handler: function (req, res) {
      log.debug("Entering the management API verifier-request action.");
      const body = parseBody(req);
      const names = namesOf(req, body, 'claim', 'claims');
      const result = admin.vpConfigAction(withAction(req, body), names);
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
          properties: { claim: { type: 'string' } },
          required: ['claim'],
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
          properties: { claim: { type: 'string' } },
          required: ['claim'],
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
                                   'under `formats`.' }
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
                 'WS-Federation 1.2, OpenID Connect and OAuth 2.0.\n\n' +
                 '**This is the one feature here that has to be configured ' +
                 'before it will do anything.** Everywhere else this service ' +
                 'accepts what it is given — any username, any client_id, any ' +
                 'entityID, any LDAP bind. It cannot do that at an assertion ' +
                 'consumer service: what arrives there is an unauthenticated ' +
                 'HTTP request claiming to be a person, and the session it ' +
                 'produces is the same one `/oauth2/authorize`, `/wsfed`, ' +
                 '`/saml2` and the admin console all read. So a relationship ' +
                 'is created DISABLED, and an assertion is refused unless it ' +
                 'verifies against the certificate configured on it.\n\n' +
                 '**The gate is on the SIGNER, not on the subject.** Once a ' +
                 'relationship is enabled and configured, everything ' +
                 'downstream is as permissive as the rest of this service: ' +
                 'any username in the assertion is accepted, any attribute is ' +
                 'mapped, and a directory entry is created for the person.\n\n' +
                 '`?relationship=<id>` returns one of them, with everything it ' +
                 'holds and the URLs to configure at the partner. It answers ' +
                 '200 with `found: false` for an id that is not registered.\n\n' +
                 'This resource holds nothing: every row is an entry under ' +
                 '`ou=federations`, the same one an `ldapsearch` reads.',
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
        description: 'Only the relationships in which this service takes that ' +
                     'role. `service-provider` is the direction that CONSUMES ' +
                     'somebody else\'s assertions.' }
    ].concat(pagingParameters()),
    responseDescription: 'The relationships with the paging that found them, ' +
                         'or one of them with its endpoints, its fields and ' +
                         'what has crossed it.',
    responseSchema: { $ref: '#/components/schemas/FederationRelationshipList' },
    handler: function (req, res) {
      log.debug("Entering the management API federation endpoint.");
      sendJson(res, 200, admin.federationView(req).json);
      log.debug("Leaving the management API federation endpoint.");
    } },

  { method: 'POST', route: BASE + '/federation/:action',
    tag: 'Federation',
    mirrors: 'POST /admin/federation',
    handler: function (req, res) {
      log.debug("Entering the management API federation action endpoint.");
      const body = parseBody(req);
      const result = admin.federationAction(withAction(req, body));
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API federation action endpoint.");
    },
    actions: [
      { action: 'create', operationId: 'createFederationRelationship',
        summary: 'Register a federation relationship',
        description: 'It is created **DISABLED**, whatever this request says, ' +
                     'and nothing about it does anything until `enable` is ' +
                     'called. That is the one place this operation overrides ' +
                     'its input, and it is deliberate: a partner that ' +
                     'half-exists and silently accepts assertions is the ' +
                     'failure this whole register is arranged to prevent, so ' +
                     'enabling is a second act that says the configuration is ' +
                     'finished.\n\n' +
                     '**ONE RELATIONSHIP IS ONE DIRECTION.** A partner this ' +
                     'service both consumes from and asserts to is two ' +
                     'relationships with two ids, because everything that ' +
                     'configures one differs by direction.\n\n' +
                     'The reply carries `readiness.missing` — the fields this ' +
                     'protocol and role still need — so a caller can go ' +
                     'straight on to `set` for each of them without knowing ' +
                     'the schema in advance.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            id: { type: 'string',
                  description: 'The key, the RDN and a URL segment. It has to ' +
                               'start with a letter or a digit and hold only ' +
                               'letters, digits, dot, dash and underscore, up ' +
                               'to 63 characters.' },
            role: { type: 'string',
                    enum: ['service-provider', 'identity-provider'],
                    description: 'Which end THIS SERVICE is. ' +
                                 '`service-provider` means a foreign identity ' +
                                 'provider authenticates the person and this ' +
                                 'service consumes what it issues.' },
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
                                        'relationship only: the identifier of ' +
                                        'the partner\'s entry in ' +
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
        description: 'The field must be one of this relationship\'s — a field ' +
                     'belonging to the other ROLE is refused by name rather ' +
                     'than written and ignored, and so is one that records ' +
                     'what HAPPENED (the counters, the last error).\n\n' +
                     '`fedId`, `fedRole` and `fedProtocol` are refused too, ' +
                     'and that is a third category rather than an oversight: ' +
                     'they are the relationship\'s identity, and changing one ' +
                     'would leave a SAML relationship carrying a token ' +
                     'endpoint. Delete it and make another — there is no ' +
                     'state to lose but the counters.\n\n' +
                     '`GET /admin-api/federation?relationship=<id>` returns ' +
                     '`editable`, which is exactly the list this operation ' +
                     'accepts, so a caller need not guess.\n\n' +
                     'The reply always carries `readiness`, so setting the ' +
                     'last missing field tells you it was the last one.',
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
                     'service-provider-side relationship, and `fedRelease` on ' +
                     'an identity-provider-side one.\n\n' +
                     '**`fedAttributeMap`** is written `<incoming ' +
                     'name>=<LDAP attribute>` and is split at the FIRST equals ' +
                     'sign — which matters, because an incoming name can be a ' +
                     'URL and a URL can hold one. It is only needed for a ' +
                     'partner\'s own inventions: the ordinary OpenID Connect ' +
                     'claims, the SAML `urn:oid:` names and the AD FS claim ' +
                     'URIs are mapped already.\n\n' +
                     '**`fedRelease`** names an attribute or claim released to ' +
                     'that partner, and it can only REMOVE — from what ' +
                     '/admin/claims, /admin/saml-attributes and the groups ' +
                     'claim would add, and from nothing else. It cannot touch ' +
                     '`sub`, `iss`, `exp` or a NameID. **NO VALUES MEANS NO ' +
                     'POLICY, not release nothing**: adding the first value ' +
                     'here is what starts the filtering.',
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
                     'fields are missing — it never half-works — and the reply ' +
                     'to this operation says so too.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { id: { type: 'string', description: 'The relationship.' } },
          required: ['id'],
          examples: [{ id: 'partner-a' }],
          additionalProperties: false
        },
        responseDescription: 'The relationship, and whether it is now usable.' },

      { action: 'disable', operationId: 'disableFederationRelationship',
        summary: 'Turn a relationship off',
        description: 'A response arriving for a disabled relationship is ' +
                     'refused without being looked at, which is what disabling ' +
                     'is for. Nothing else is lost: the configuration, the ' +
                     'counters and the mappings all stay, and the people it ' +
                     'authenticated keep their directory entries and their ' +
                     'sessions.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { id: { type: 'string', description: 'The relationship.' } },
          required: ['id'],
          additionalProperties: false
        },
        responseDescription: 'The relationship, now disabled.' },

      { action: 'delete', operationId: 'deleteFederationRelationship',
        summary: 'Delete a relationship',
        description: 'The entry goes and takes its recorded sign-ins with ' +
                     'it. **The PEOPLE it authenticated keep their entries ' +
                     'under `ou=users`** — nothing is ever deleted from there ' +
                     '— and any session they hold is unaffected until it ' +
                     'expires or is ended, which is what `POST ' +
                     '/admin-api/logout` is for.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { id: { type: 'string', description: 'The relationship.' } },
          required: ['id'],
          additionalProperties: false
        },
        responseDescription: 'Confirmation, and what was deliberately left ' +
                             'behind.' }
    ] },

  { method: 'GET', path: BASE + '/saml2', tag: 'SAML 2.0',
    operationId: 'getSaml2ServiceProviders',
    summary: 'Every SAML 2.0 service provider, and the endpoints each is configured from',
    description: 'A full SAML 2.0 identity provider: HTTP Redirect and HTTP ' +
                 'POST for the AuthnRequest, and HTTP POST, HTTP Redirect or ' +
                 'HTTP Artifact for the Response, with a SOAP artifact ' +
                 'resolution service behind the third.\n\n**Every service ' +
                 'provider gets its own identity provider metadata** — a ' +
                 'distinct entityID and its own endpoints — and **a document ' +
                 'is minted for any entityID asked for**, so nothing has to be ' +
                 'provisioned before a service provider can be pointed at this ' +
                 'service. That is why `metadataUrl` is on every row rather ' +
                 'than being one constant.\n\nThis resource holds nothing: ' +
                 'every row is an entry in `ou=applications`, the same one ' +
                 '`GET /admin-api/applications` reports.\n\n`?sp=<entityID>` ' +
                 'returns one of them, with what has been recorded about it — ' +
                 'and answers 200 with `found: false` for an entityID that is ' +
                 'not registered, whose metadata is still served and whose ' +
                 'AuthnRequest would still be answered.',
    mirrors: 'GET /admin/saml2',
    parameters: [
      { name: 'sp', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'One service provider, by its entityID.' }
    ].concat(pagingParameters()),
    responseDescription: 'The service providers with the paging that found ' +
                         'them, or one of them with its endpoints and its record.',
    responseSchema: { $ref: '#/components/schemas/Saml2ServiceProviderList' },
    handler: function (req, res) {
      log.debug("Entering the management API SAML 2.0 endpoint.");
      sendJson(res, 200, admin.saml2View(req).json);
      log.debug("Leaving the management API SAML 2.0 endpoint.");
    } },

  { method: 'POST', route: BASE + '/saml2/:action',
    tag: 'SAML 2.0',
    mirrors: 'POST /admin/saml2',
    handler: function (req, res) {
      log.debug("Entering the management API SAML 2.0 action endpoint.");
      const body = parseBody(req);
      const result = admin.saml2Action(withAction(req, body));
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API SAML 2.0 action endpoint.");
    },
    actions: [
      { action: 'register', operationId: 'registerSaml2ServiceProvider',
        summary: 'Register a service provider by entityID',
        description: 'OPTIONAL, and it changes nothing about whether a request ' +
                     'is accepted: this identity provider accepts any ' +
                     'entityID, and the first AuthnRequest or metadata fetch ' +
                     'creates the entry anyway. What registering early buys is ' +
                     'a metadata document to hand somebody before they have ' +
                     'sent anything.\n\nIt is refused for an entityID that is ' +
                     'already in the registry — an identifier names ONE ' +
                     'application here whatever protocol brought it, so the ' +
                     'answer to "it is already there" is to change what it ' +
                     'holds rather than to create it twice.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            sp: { type: 'string', description: 'The service provider\'s entityID.' }
          },
          required: ['sp'],
          examples: [{ sp: 'https://sp.example.com/saml' }],
          additionalProperties: false
        },
        responseDescription: 'The application entry, and where its metadata is served.' },

      { action: 'set-logout-service', operationId: 'addSaml2LogoutService',
        summary: 'Declare where this service provider\'s LogoutResponse goes',
        description: 'A `<samlp:LogoutRequest>` CARRIES NO RETURN ADDRESS — ' +
                     'only SP metadata does, and this service does not consume ' +
                     'SP metadata. With nothing declared the profile falls ' +
                     'back to `saml2.defaultSingleLogoutService` and then to ' +
                     'the assertion consumer service URL that service provider ' +
                     'last used, WHICH IS A GUESS and is logged as one. This ' +
                     'is how to remove the guess.\n\nIt writes ' +
                     '`samlSingleLogoutService` on the application entry, so ' +
                     'an `ldapmodify` of the same attribute does exactly this ' +
                     '— two doors onto one value, not two stores.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            sp: { type: 'string', description: 'The service provider\'s entityID.' },
            value: { type: 'string', description: 'An absolute URL.' }
          },
          required: ['sp', 'value'],
          examples: [{ sp: 'https://sp.example.com/saml',
                       value: 'https://sp.example.com/saml/slo' }],
          additionalProperties: false
        },
        responseDescription: 'The application entry as it now stands.' },

      { action: 'remove-logout-service', operationId: 'removeSaml2LogoutService',
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

      { action: 'set-signing-certificate', operationId: 'setSaml2SigningCertificate',
        summary: 'Record the certificate this service provider signs with',
        description: 'Base64 DER — PEM armour and whitespace are stripped, ' +
                     'because what the attribute holds is what a ' +
                     '`ds:X509Certificate` carries, and a PEM stored there ' +
                     'would be something no reader of it expects with nothing ' +
                     'to say so until the day one tried to use it.\n\n**IT IS ' +
                     'NOT CHECKED AGAINST ANYTHING.** This service records ' +
                     'whether an AuthnRequest was signed and verifies no ' +
                     'signature, which is the same posture it takes to every ' +
                     'credential — see `saml/CLAUDE.md`. This is the material ' +
                     'a verification would read the day one is wanted, and it ' +
                     'is public key material, so unlike a client secret it is ' +
                     'worth nothing to whoever reads this directory. An empty ' +
                     'value clears it.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            sp: { type: 'string' },
            value: { type: 'string', description: 'Base64 DER, or a PEM to be stripped.' }
          },
          required: ['sp'],
          examples: [{ sp: 'https://sp.example.com/saml', value: 'MIIC...' }],
          additionalProperties: false
        },
        responseDescription: 'The application entry as it now stands.' }
    ] },

  { method: 'GET', path: BASE + '/saml11', tag: 'SAML 1.1',
    operationId: 'getSaml11RelyingParties',
    summary: 'Every SAML 1.1 relying party, and the endpoints each is configured from',
    description: 'A full SAML 1.1 identity provider: both browser profiles — ' +
                 'Browser/POST and Browser/Artifact — and the SAML responder ' +
                 'behind the second, which also answers AttributeQuery and ' +
                 'AuthenticationQuery and is therefore this service\'s ' +
                 'attribute authority.\n\n**IT IS NOT AN OLDER SPELLING OF ' +
                 '`GET /admin-api/saml2`.** SAML 1.1 has no request message, ' +
                 'so a relying party cannot identify itself in the protocol: ' +
                 '`identifier` comes from Shibboleth\'s `providerId` ' +
                 'parameter, from a scoped endpoint\'s path segment, or it is ' +
                 'GUESSED from the origin of the TARGET. It has no Single ' +
                 'Logout, so there is no logout service to declare, and no ' +
                 'request signature to record. It has an attribute authority, ' +
                 'which the 2.0 profile does not.\n\n**Every relying party ' +
                 'gets its own metadata document** and one is minted for any ' +
                 'identifier asked for, so nothing has to be provisioned ' +
                 'before a relying party can be pointed at this service.\n\n' +
                 'This resource holds nothing: every row is an entry in ' +
                 '`ou=applications`, the same one `GET /admin-api/applications` ' +
                 'reports — and the KIND is shared with WS-Federation, because ' +
                 'a relying party handed the same assertion through the ' +
                 'passive requestor profile is the same application. ' +
                 '`profiles` says which of the two browser profiles it has ' +
                 'actually used, and an empty list means it has only ever been ' +
                 'handed a 1.1 assertion through another door.\n\n' +
                 '`?rp=<identifier>` returns one of them, with what has been ' +
                 'recorded about it — and answers 200 with `found: false` for ' +
                 'an identifier that is not registered, whose metadata is ' +
                 'still served and whose flow would still be answered.',
    mirrors: 'GET /admin/saml11',
    parameters: [
      { name: 'rp', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'One relying party, by its identifier.' }
    ].concat(pagingParameters()),
    responseDescription: 'The relying parties with the paging that found ' +
                         'them, or one of them with its endpoints and its record.',
    responseSchema: { $ref: '#/components/schemas/Saml11RelyingPartyList' },
    handler: function (req, res) {
      log.debug("Entering the management API SAML 1.1 endpoint.");
      sendJson(res, 200, admin.saml11View(req).json);
      log.debug("Leaving the management API SAML 1.1 endpoint.");
    } },

  { method: 'POST', route: BASE + '/saml11/:action',
    tag: 'SAML 1.1',
    mirrors: 'POST /admin/saml11',
    handler: function (req, res) {
      log.debug("Entering the management API SAML 1.1 action endpoint.");
      const body = parseBody(req);
      const result = admin.saml11Action(withAction(req, body));
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API SAML 1.1 action endpoint.");
    },
    actions: [
      { action: 'register', operationId: 'registerSaml11RelyingParty',
        summary: 'Register a relying party by identifier',
        description: 'OPTIONAL, and it changes nothing about whether a flow is ' +
                     'accepted: this identity provider accepts any identifier, ' +
                     'and the first flow or metadata fetch creates the entry ' +
                     'anyway.\n\nIt buys two things here rather than the one ' +
                     'it buys on the SAML 2.0 side. A metadata document to ' +
                     'hand somebody before they have sent anything — and **a ' +
                     'NAME to put in `providerId`**, which matters more in ' +
                     'this protocol than in any other here: with no name sent, ' +
                     'the audience of the assertion is guessed from the origin ' +
                     'of the TARGET, and a relying party expecting a different ' +
                     'audience refuses the assertion inside a signature check ' +
                     'with nothing saying why.\n\nIt is refused for an ' +
                     'identifier already in the registry — an identifier names ' +
                     'ONE application here whatever protocol brought it, and a ' +
                     'WS-Federation relying party taking 1.1 assertions is ' +
                     'already one of these.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            rp: { type: 'string', description: 'The relying party\'s identifier.' }
          },
          required: ['rp'],
          examples: [{ rp: 'urn:example:app' }],
          additionalProperties: false
        },
        responseDescription: 'The application entry, and where its metadata is served.' }
    ] },

  { method: 'GET', path: BASE + '/authorization-servers', tag: 'Authorization servers',
    operationId: 'getAuthorizationServers',
    summary: 'Every authorization server profile, and what its document says',
    description: 'One process, several authorization servers. The path ' +
                 'component the two discovery shapes already carry — RFC 8414 ' +
                 'section 3.1 INSERTS it after the well-known segment, OpenID ' +
                 'Connect Discovery section 4 APPENDS the well-known segment ' +
                 'to it — now selects a CONFIGURATION as well as an issuer ' +
                 'identifier.\n\n**A path nobody has configured publishes the ' +
                 'document this service always published**, so nothing that ' +
                 'worked before behaves differently.\n\nEvery reply carries ' +
                 '`drift`: the members whose published value disagrees with ' +
                 'what this service would publish, and the removals that hide ' +
                 'something real. A profile that lies is often exactly what is ' +
                 'wanted — it is how you find out whether a client reads the ' +
                 'metadata — but a mock that let somebody publish a misleading ' +
                 'document QUIETLY would be a trap.\n\n`?profile=<id>` returns ' +
                 'one of them with every override, every removal and its ' +
                 'drift.',
    mirrors: 'GET /admin/authorization-servers',
    parameters: [
      { name: 'profile', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'One profile, by the path component that selects it. ' +
                     'Answers 200 with `found: false` for one that is not ' +
                     'configured — whose discovery URLs still answer, with ' +
                     'this service\'s own document.' }
    ].concat(pagingParameters()),
    responseDescription: 'The profiles with the paging that found them, or one ' +
                         'profile with its overrides and drift.',
    responseSchema: { $ref: '#/components/schemas/AuthorizationServerList' },
    handler: function (req, res) {
      log.debug("Entering the management API authorization servers endpoint.");
      sendJson(res, 200, admin.authorizationServersView(req).json);
      log.debug("Leaving the management API authorization servers endpoint.");
    } },

  { method: 'POST', route: BASE + '/authorization-servers/:action',
    tag: 'Authorization servers',
    mirrors: 'POST /admin/authorization-servers',
    handler: function (req, res) {
      log.debug("Entering the management API authorization servers action endpoint.");
      const body = parseBody(req);
      const result = admin.authorizationServersAction(withAction(req, body));
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API authorization servers action endpoint.");
    },
    actions: [
      { action: 'create', operationId: 'createAuthorizationServer',
        summary: 'Add an authorization server profile',
        description: 'The `id` is a single URL path segment, because it has to ' +
                     'appear in a discovery URL without being escaped — one ' +
                     'that had to be escaped would be one nobody could find ' +
                     'again. A new profile has no overrides, so both its ' +
                     'documents say exactly what this service says about ' +
                     'itself, which is the right place to start from.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            id: { type: 'string',
                  description: '1-64 characters of letters, digits, dot, dash, ' +
                               'underscore or tilde, starting with a letter or ' +
                               'a digit.' },
            label: { type: 'string', description: 'Optional display name.' },
            description: { type: 'string', description: 'Optional note.' }
          },
          required: ['id'],
          examples: [{ id: 'tenant1', label: 'Tenant One',
                       description: 'advertises plain PKCE, to see what a client does' }],
          additionalProperties: false
        },
        responseDescription: 'The profile and the two URLs it is published at.' },

      { action: 'set', operationId: 'setAuthorizationServerMember',
        summary: 'Publish a metadata member with a chosen value',
        description: 'The value is read as JSON first and as a plain string if ' +
                     'that fails, so `["S256"]` is a list, `false` is a boolean ' +
                     'and `https://example.com/token` is a string.\n\n**Any ' +
                     'member name is accepted**, including one this service has ' +
                     'never heard of; the catalogue in the GET reply is help ' +
                     'for whoever fills the form rather than a constraint. A ' +
                     'member that is also removed stops being removed, or the ' +
                     'call would appear to do nothing.\n\nWhat this does NOT ' +
                     'change is what the endpoints do. Advertise ' +
                     '`code_challenge_methods_supported: ["plain"]` and the ' +
                     'token endpoint still verifies S256 — which is the point, ' +
                     'and is reported as drift rather than left to be ' +
                     'discovered.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            profile: { type: 'string', description: 'The profile id.' },
            member: { type: 'string', description: 'Any metadata member name.' },
            value: { description: 'JSON if it parses as JSON, otherwise the string.' }
          },
          required: ['profile', 'member'],
          examples: [{ profile: 'tenant1',
                       member: 'code_challenge_methods_supported',
                       value: ['S256'] }],
          additionalProperties: false
        },
        responseDescription: 'The profile as it now stands.' },

      { action: 'remove', operationId: 'removeAuthorizationServerMember',
        summary: 'Stop publishing a member at all',
        description: 'DIFFERENT FROM `reset`, and the difference is the reason ' +
                     'both exist: reset undoes an override and this publishes ' +
                     'an ABSENCE. A client that cannot find ' +
                     '`code_challenge_methods_supported` does not learn that ' +
                     'PKCE is unavailable — it learns nothing, and RFC 9700 ' +
                     'section 2.6 is entirely about that difference.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            profile: { type: 'string' },
            member: { type: 'string' }
          },
          required: ['profile', 'member'],
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
            member: { type: 'string' }
          },
          required: ['profile', 'member'],
          examples: [{ profile: 'tenant1', member: 'token_endpoint' }],
          additionalProperties: false
        },
        responseDescription: 'The profile as it now stands.' },

      { action: 'delete', operationId: 'deleteAuthorizationServer',
        summary: 'Delete a profile',
        description: 'The two discovery URLs go on answering — with this ' +
                     'service\'s own document and the issuer taken from the ' +
                     'path — because an unconfigured path component has always ' +
                     'been served that way rather than 404\'d.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { profile: { type: 'string' } },
          required: ['profile'],
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
  // and an ldapmodify are one act arriving by two routes. That is what keeps the
  // one-store rule intact with three ways in.
  //
  // What may be changed is DECLARED and not DERIVED — configuration, which is
  // what RFC 9700 mode reads, but never the counters or the sightings, which are
  // what happened. The line is drawn by applications.js's EDITABLE table, so
  // this file offers no opinion about it and the console's selects are built
  // from the same rows these actions validate against.
  { method: 'GET', path: BASE + '/applications', tag: 'Applications',
    operationId: 'getApplications',
    summary: 'Every application this service has been asked about, filtered and paged',
    description: 'The other side of /admin-api/users. That resource lists ' +
                 'every identity that has authenticated here; this lists what ' +
                 'they authenticated TO — every OAuth client, OpenID Connect ' +
                 'relying party, SAML 2.0 or 1.1 service provider, ' +
                 'WS-Federation application, WS-Trust relying party, ' +
                 'OpenID4VP verifier and Kerberos service.\n\n**The entries ' +
                 'ARE the registry.** They live under `ou=applications` in the ' +
                 'embedded LDAP directory and nothing caches them, so an ' +
                 '`ldapmodify` is visible here on the next call — and changes ' +
                 'what RFC 9700 mode enforces at the same moment. The RFC 7591 ' +
                 'client registrations are those entries too.\n\n**One entry ' +
                 'per identifier, whatever protocol brought it.** The key is ' +
                 'the identifier exactly as it arrived, so an application ' +
                 'appearing under one name in two protocols is one row with ' +
                 'two `kinds` rather than two rows.\n\n`?application=<id>` ' +
                 'returns ONE of them with every attribute of its directory ' +
                 'entry and what the published schema says each attribute is; ' +
                 'that reply pages its attribute list under `attributesPage` ' +
                 'rather than `page`, which is the convention for a reply ' +
                 'holding a list that is not the top-level one.\n\n**Two ' +
                 'attributes hold credentials in the clear** — ' +
                 '`oauthClientSecret` and `appRegistrationAccessToken` — for ' +
                 'the reason GET /krb5/principals prints the Kerberos ' +
                 'passwords. In RFC 9700 mode that secret is CHECKED, so ' +
                 'anyone who can reach this endpoint can authenticate as that ' +
                 'client.',
    mirrors: 'GET /admin/applications',
    parameters: [
      { name: 'application', in: 'query', required: false,
        schema: { type: 'string' },
        description: 'One application, by its identifier exactly — the ' +
                     'client_id, wtrealm, AppliesTo, entityID or service ' +
                     'principal name. Answers 200 with `found: false` for one ' +
                     'this service has never accepted, which is a different ' +
                     'fact from one it has refused: an entry appears when an ' +
                     'identifier is ACCEPTED, so a client whose every request ' +
                     'was turned away has none.' },
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
      sendJson(res, 200, admin.applicationsView(req).json);
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
    summary: 'The vocabulary a new application may be created with, and where it would land',
    description: 'The eight KINDS and the fourteen PROTOCOL FAMILIES a create ' +
                 'takes, each with what it means, the FIELDS the console\'s form ' +
                 'is drawn from (`declarations` — the per-protocol identifiers ' +
                 'and the redirect URIs, deduped by attribute and each naming ' +
                 'the families it serves), plus the container DN a new ' +
                 'entry would be created under and how many that container will ' +
                 'hold.\n\n**It creates nothing** — the create is `POST ' +
                 '/admin-api/applications/create`. This is the list that call ' +
                 'validates against, published so that a caller learns what it ' +
                 'may send from the service rather than from a copy of the list ' +
                 'in a document.\n\n**The container is THIS REALM\'S.** The ' +
                 'embedded directory is per trust realm, so `/realm/acme/' +
                 'admin-api/applications/new` answers with acme\'s ' +
                 '`ou=applications` and an application created there is ' +
                 'invisible to every other realm — including in an `ldapsearch`, ' +
                 'which reaches it only under that realm\'s base DN.\n\n' +
                 '**Declaring a protocol family grants and refuses nothing.** No ' +
                 'endpoint in this service reads `appAllowedProtocol`: an ' +
                 'application declared for SAML 2.0 alone is still issued an ' +
                 'access token. It is a record of intent on the entry, and it is ' +
                 'deliberately not a permission — a mock that refused a protocol ' +
                 'would remove a test case rather than add one. The ' +
                 'configuration that DOES take effect is in `editable`.',
    mirrors: 'GET /admin/applications/new',
    responseDescription: 'The two vocabularies, the fields a create may carry, ' +
                         'the container and the realm.',
    responseSchema: { $ref: '#/components/schemas/NewApplicationForm' },
    handler: function (req, res) {
      log.debug("Entering the management API new-application endpoint.");
      sendJson(res, 200, admin.newApplicationView(req).json);
      log.debug("Leaving the management API new-application endpoint.");
    } },

  { method: 'POST', route: BASE + '/applications/:action', tag: 'Applications',
    mirrors: 'POST /admin/applications',
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
      const result = admin.applicationsAction(withAction(req, body), protocols);
      // `refresh-metadata` is asynchronous — it dials the service provider's
      // metadata URL — and every other action is not. See that action's comment
      // in admin.js for why one promise is cheaper than forty awaits.
      if (result && typeof result.then === 'function') {
        result.then(function (answer) {
          sendJson(res, answer.ok ? 200 : 400, answer);
          log.debug("Leaving the management API applications action endpoint. Fetched.");
        });
        return;
      }
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API applications action endpoint.");
    },
    actions: [
      { action: 'create', operationId: 'createApplication',
        summary: 'Put an application in the registry before it connects',
        description: 'An entry usually appears because an identifier was ' +
                     'ACCEPTED — a client_id at the token endpoint, a wtrealm ' +
                     'on a sign-in response, an SPN on a TGS-REP. This is how ' +
                     'to get one in ahead of that, which is what RFC 9700 mode ' +
                     'needs if a client is to be judged against its OWN ' +
                     'redirect URIs rather than against the ' +
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
                                 '/admin/applications/new beside the protocol ' +
                                 'families, which is two vocabularies for one ' +
                                 'question — eight kinds against fourteen ' +
                                 'families, five of them with no kind at all — ' +
                                 'and it is DERIVED rather than declared: a ' +
                                 'kind is written when a protocol actually ' +
                                 'recognises the identifier, so a form ' +
                                 'choosing one asserted a sighting that had ' +
                                 'not happened. Prefer `protocols`.' },
            protocols: {
              type: 'array', items: { type: 'string', enum: applications.PROTOCOL_IDS },
              description: 'THE PROTOCOL FAMILIES THIS APPLICATION IS DECLARED ' +
                           'FOR, as ids from the closed vocabulary GET ' +
                           '/admin-api/applications/new publishes. They land on ' +
                           '`appAllowedProtocol`, and one that is not in that ' +
                           'list is REFUSED rather than recorded — a typo that ' +
                           'silently became a new family is how one application ' +
                           'comes to be declared for two spellings of one ' +
                           'thing.\n\n**IT GRANTS AND REFUSES NOTHING.** ' +
                           'Nothing in this service reads the attribute: an ' +
                           'application declared for `saml2` alone is still ' +
                           'issued an access token at /oauth2/token, and one ' +
                           'declared for nothing is treated exactly as it would ' +
                           'have been. It is a record of INTENT, kept apart from ' +
                           '`appProtocol` — which is what has actually happened ' +
                           'and is not editable — so the two lists on an entry ' +
                           'can be read against each other.\n\nA ' +
                           'form-encoded body may repeat `protocol` instead, ' +
                           'which is how the console\'s checkbox column posts ' +
                           'it, and a single string may carry several separated ' +
                           'by spaces or commas.' },
            fields: {
              type: 'object', additionalProperties: true,
              description: 'THE ATTRIBUTES THE ENTRY IS CREATED WITH, keyed by ' +
                           'the schema\'s own attribute name and valued with a ' +
                           'string or an array of strings. This is where the ' +
                           'per-protocol identifiers and the redirect URIs go — ' +
                           '`oauthClientId`, `samlEntityId`, `wsfedRealm`, ' +
                           '`krb5ServicePrincipalName`, `oauthRedirectUri`, ' +
                           '`samlAssertionConsumerService`, `wsfedReplyUrl` and ' +
                           'the rest.\n\nGET /admin-api/applications/new ' +
                           'publishes the list as `declarations`, with the ' +
                           'families each attribute serves and whether it holds ' +
                           'a list; it is the same walk of the protocol table ' +
                           'the console\'s form is drawn from, so this document ' +
                           'and that page cannot offer different fields. GET ' +
                           '/admin/ldap/applications publishes every attribute in the ' +
                           'schema with an `editable` member.\n\n**Only ' +
                           'DECLARED attributes may be given.** A derived one — ' +
                           'a counter, a sighting, `appProtocol`, ' +
                           '`appRedirectUriObserved` — is REFUSED by name rather ' +
                           'than written, because an entry created with one ' +
                           'would be asserting a past it does not have. A ' +
                           'single-valued attribute given several values is ' +
                           'refused as well, rather than truncated to the first: ' +
                           'the only one you are likely to meet is ' +
                           '`oauthTlsClientAuthSubjectDn`, which an RFC 8705 ' +
                           'check compares by exact string equality, and quietly ' +
                           'keeping one of two is exactly the wrong answer ' +
                           'there.\n\n**Nothing given here is CHECKED except ' +
                           'the OAuth redirect URIs, and those only in RFC 9700 ' +
                           'mode.** The rest are recorded, in the way being in ' +
                           'this registry at all is a record.' }
          },
          required: ['identifier'],
          examples: [{ identifier: 'urn:example:crm', name: 'CRM',
                       protocols: ['wsfed', 'saml11'],
                       fields: { wsfedRealm: 'urn:example:crm',
                                 wsfedReplyUrl: ['https://crm.example.com/wsfed'],
                                 samlEntityId: 'urn:example:crm' } }],
          additionalProperties: false
        },
        responseDescription: 'The application as it now stands, in `application`.' },

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
                     }).join(', ') + '. ' +
                     'An empty `value` CLEARS the attribute.\n\n**What may be ' +
                     'changed is DECLARED and not DERIVED.** Configuration — ' +
                     'what this application is allowed to do, which is what ' +
                     'RFC 9700 mode reads — is editable. The counters, the ' +
                     'sightings, the kinds and the protocols are what ' +
                     'HAPPENED, and are refused with a list of what is not: a ' +
                     'call that could rewrite them would make this registry ' +
                     'lie about the service\'s own behaviour, in a way ' +
                     'indistinguishable from the recording being broken. ' +
                     '`ldapmodify` still reaches every attribute, which is a ' +
                     'deliberate difference — refusing them HERE is the ' +
                     'difference between offering an operation and merely not ' +
                     'preventing it.\n\nThis writes the same entry LDAP ' +
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
                                      'attributes. GET /admin/ldap/applications ' +
                                      'publishes the schema with an ' +
                                      '`editable` member on every row.' },
            value: { type: 'string',
                     description: 'The new value; empty clears the attribute.' }
          },
          required: ['application', 'attribute'],
          examples: [{ application: 'my-web-app',
                       attribute: 'oauthTokenEndpointAuthMethod',
                       value: 'none' }],
          additionalProperties: false
        },
        responseDescription: 'The application as it now stands, with `changed` ' +
                             'saying whether anything actually differed.' },

      { action: 'add', operationId: 'addApplicationValue',
        summary: 'Add a value to a multi-valued attribute',
        // Read off the schema, for the reason `set` above gives.
        description: 'For the attributes that hold a LIST — ' +
                     applications.editableAttributes('multi').map(function (row) {
                       return '`' + row.name + '`';
                     }).join(', ') + '.\n\nThis ' +
                     'is the one that matters most: a value added to ' +
                     '`oauthRedirectUri` is a redirect URI RFC 9700 mode ' +
                     'accepts by exact string match on the next authorization ' +
                     'request. Note that it is the REGISTERED list — ' +
                     '`appRedirectUriObserved`, which records what a client ' +
                     'actually used, is not editable, because "registered" and ' +
                     '"used" are different facts and section 2.1 is entirely ' +
                     'about not confusing them.',
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
        description: 'The inverse of `add`. Removing the LAST value takes the ' +
                     'attribute with it, which is what the LDAP modify handler ' +
                     'does for every other entry in this directory and what an ' +
                     'operator reading it with an LDAP client will expect.',
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

      { action: 'revoke-registration', operationId: 'revokeApplicationRegistration',
        summary: 'Withdraw an RFC 7591 registration, keeping the entry',
        description: 'RFC 7592\'s delete reached from here instead of from the ' +
                     'client that holds the registration access token — the ' +
                     'same function, so the outcome is the same one rather ' +
                     'than a second reading of what "unregistered" means.' +
                     '\n\n**The ENTRY stays**, with everything it had ' +
                     'recorded; the `client_secret`, the registration access ' +
                     'token and the registration document go. Losing that an ' +
                     'application was ever here because its registration was ' +
                     'withdrawn would be losing the fact rather than the ' +
                     'configuration.\n\nAfterwards RFC 9700 mode treats it as ' +
                     'an unregistered, PUBLIC client: PKCE is required of it, ' +
                     'its secret is no longer checked, and its redirect_uri is ' +
                     'judged against the `oauth2.redirectUris` setting rather ' +
                     'than against its own list.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { application: { type: 'string' } },
          required: ['application'],
          examples: [{ application: 'sts-mock-client-Ab12Cd34' }],
          additionalProperties: false
        },
        responseDescription: 'The application as it now stands, with ' +
                             '`registered` false.' },

      { action: 'refresh-metadata', operationId: 'refreshApplicationMetadata',
        summary: 'Fetch this service provider\'s SAML metadata and store its ' +
                 'encryption certificate',
        description: 'Dials the `samlSpMetadataUrl` ON THE ENTRY — never a URL ' +
                     'in the request body — parses the document, and writes ' +
                     '`samlSpMetadata` and `samlEncryptionCertificate` back. ' +
                     'That certificate is what an assertion for this service ' +
                     'provider is encrypted to when `saml2.encryptAssertion` ' +
                     '(or `saml2EncryptAssertion` on the entry) is on.\n\n' +
                     'IT IS THE ONLY OPERATION IN THIS API THAT MAKES AN ' +
                     'OUTBOUND REQUEST, and the second surface in this service ' +
                     'that makes one at all — federation is the other. The same ' +
                     'refusals apply: https only unless ' +
                     '`federation.outboundAllowInsecure` is on, a timeout of ' +
                     '`federation.outboundTimeoutMs`, no redirects followed, ' +
                     'and a size cap.\n\nISSUING NEVER FETCHES. This writes ' +
                     'the certificate onto the entry and an assertion reads the ' +
                     'entry, so no sign-in waits on somebody else\'s web ' +
                     'server.\n\nA FAILURE CHANGES NOTHING — not the ' +
                     'document, not the certificate — so an application that ' +
                     'was working does not stop working because a metadata host ' +
                     'was down.\n\nThe `use="encryption"` KeyDescriptor is ' +
                     'taken, falling back to one with no `use` at all; a ' +
                     '`use="signing"` descriptor is deliberately NOT taken. The ' +
                     'endpoints in the document are REPORTED and not applied.',
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
                             'KeyDescriptor the certificate came from, and the ' +
                             'endpoints it describes.' },

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
                 'over it and neither is implemented here yet.\n\nTHE ' +
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
      sendJson(res, 200, admin.ssfView(req));
      log.debug("Leaving the management API Shared Signals endpoint.");
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
      admin.ssfAction(withAction(req, body)).then(function (result) {
        sendJson(res, result.ok ? 200 : 400, result);
        log.debug("Leaving the management API Shared Signals action " +
                  "endpoint.");
      }).catch(function (e) {
        // A rejection here is a bug in ssf/ssf.js rather than anything a
        // request can cause — its action function resolves a refusal rather
        // than throwing one — so it is reported as a refusal instead of
        // becoming an unhandled rejection that ends the process.
        log.error('admin-api: the Shared Signals action threw: ' + e.message);
        sendJson(res, 500, { ok: false,
          errors: ['The action failed: ' + e.message] });
        log.debug("Leaving the management API Shared Signals action " +
                  "endpoint. Threw.");
      });
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
                      description: 'Optional. Why, in words — it rides in the ' +
                                   'stream-updated event\'s `reason` member, ' +
                                   'which nothing parses.' }
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
                       description: 'The event\'s own members. A verification ' +
                                    'event takes an optional `state`; a ' +
                                    'stream-updated event takes a required ' +
                                    '`status` and an optional `reason`. An ' +
                                    'unrecognised member is CARRIED with a ' +
                                    'warning rather than refused: an event ' +
                                    'vocabulary extends, and a receiver is ' +
                                    'expected to ignore what it does not ' +
                                    'know.' },
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

  { method: 'GET', path: BASE + '/scim', tag: 'SCIM',
    operationId: 'getScim',
    summary: 'The SCIM 2.0 provisioning surface, and what it has been asked to do',
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
                 'the authentication settings — ' +
                 'so POST /admin-api/config/set is already the operation for ' +
                 'it. The console page has no form on it either, which is ' +
                 'the parity rule holding rather than being broken.\n\nWHAT ' +
                 'SCIM WROTE is not here: it went into the embedded ' +
                 'directory, so a person provisioned over SCIM is on ' +
                 '/admin-api/users and their groups are on /admin-api/groups. ' +
                 'There is no second store to report.',
    mirrors: 'GET /admin/scim',
    responseDescription: 'The counters and the capabilities.',
    responseSchema: { $ref: '#/components/schemas/Scim' },
    handler: function (req, res) {
      log.debug("Entering the management API SCIM endpoint.");
      sendJson(res, 200, admin.scimJson(req));
      log.debug("Leaving the management API SCIM endpoint.");
    } },

  { method: 'GET', path: BASE + '/audit', tag: 'Audit log',
    operationId: 'getAudit',
    summary: 'What happened here, in order, filtered and paged',
    description: 'Every authentication, session, LDAP directory operation, ' +
                 'console interaction, management API call and protocol ' +
                 'endpoint call, newest first.\n\nThis is HISTORY where the ' +
                 'rest of this API is STATE. /admin-api/metrics can say the ' +
                 'directory holds eleven entries; only this can say a twelfth ' +
                 'was created at 14:02 and deleted at 14:03 by somebody bound ' +
                 'as `uid=carol`, over LDAPS.\n\n**NO CREDENTIAL IS EVER IN ' +
                 'A ROW.** Not a password, not a bearer token, not an ' +
                 'assertion, and no request or response body. A modify names ' +
                 'the attributes it changed and never their values, because a ' +
                 'modify is where a `userPassword` gets set; a compare says ' +
                 'whether it matched and not what was tried; an ' +
                 'authorization code in a query string is replaced with ' +
                 '`(redacted)`.\n\n**One act usually produces several ' +
                 'events.** A sign-in writes three — the HTTP call, the ' +
                 'credential being accepted, and the session that came out of ' +
                 'it. They are three facts at three layers, and a Kerberos ' +
                 'AS-REQ authenticates somebody and starts no session at all.' +
                 '\n\nWALK IT BY `seq`, not by page. That number is ' +
                 'monotonic and never reused, including across a drop, so ' +
                 '"everything after 4102" is exact; a gap between the last ' +
                 'one you saw and `oldestSeq` is precisely how many events ' +
                 'you missed while the cap discarded them.',
    mirrors: 'GET /admin/audit',
    parameters: [
      { name: 'category', in: 'query', required: false,
        schema: { type: 'string',
                  enum: ['authentication', 'session', 'directory', 'admin',
                         'api', 'protocol'] },
        description: 'One of the six categories. The reply\'s `categories` ' +
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
                     'X.509 subject). A substring because the collapse to one ' +
                     'key can only be done where an identity is normalised, ' +
                     'and a directory row\'s actor is a DN.' },
      { name: 'q', in: 'query', required: false, schema: { type: 'string' },
        description: 'Substring of the summary, the target or the action, ' +
                     'case-insensitive.' }
    ].concat(pagingParameters()),
    responseDescription: 'The matching events, with the paging that found ' +
                         'them and the vocabulary the filters take.',
    responseSchema: { $ref: '#/components/schemas/AuditList' },
    handler: function (req, res) {
      log.debug("Entering the management API audit endpoint.");
      sendJson(res, 200, admin.auditView(req.query).json);
      log.debug("Leaving the management API audit endpoint.");
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
                 'configured policy that decides the Kerberos ones.\n\n' +
                 'Eight mechanisms: Kerberos S4U2Self, S4U2Proxy (classic and ' +
                 'resource-based) and a forwarded ticket-granting ticket; ' +
                 'WS-Trust `OnBehalfOf` and `ActAs`; RFC 8693 token exchange ' +
                 'in both its shapes. They are recorded against ONE model ' +
                 'because the question is protocol-independent: which hop ' +
                 'invented which identity.\n\n**The axis worth filtering on is ' +
                 '`mode`.** Under a `delegation` the credential CARRIES the ' +
                 'chain — an `act` claim, a composite `ActAs`, ' +
                 '`S4U_DELEGATION_INFO` in the PAC — so the far end can see ' +
                 'who is really asking. Under an `impersonation` nothing does, ' +
                 'which means this endpoint is the ONLY place that fact is ' +
                 'ever visible: no reading of the token afterwards can recover ' +
                 'it.\n\n**Refusals are here and are most of the value.** A ' +
                 'refused act carries `reason` — the KDC\'s own words, the ' +
                 'same sentence the client was sent — naming the two accounts ' +
                 'and the two attributes and which was missing. A refused ' +
                 'delegation appears in NO other resource here: nothing was ' +
                 'accepted, so /admin-api/audit and /admin-api/users have ' +
                 'nothing to say about it.\n\n**Nothing checks who may ' +
                 'delegate except the KDC.** WS-Trust and token exchange are ' +
                 'unpoliced here, and each act says so in the field that names ' +
                 'an attribute for a Kerberos one.\n\nBesides the paged acts ' +
                 'the reply carries `chains` — the distinct (mechanism, ' +
                 'initial, intermediary, target) tuples among what MATCHED, ' +
                 'one per edge of the picture — `applications`, every ' +
                 'application an act named in WHATEVER ROLE it played (the ' +
                 'console draws one of them in full at ' +
                 '/admin/delegation/application) — and `policy`, which is who ' +
                 'may delegate to whom before anybody has tried.\n\n**THIS IS ' +
                 'THE DELEGATION REGISTER AND NOT EVERYTHING A PERSON WAS ' +
                 'ISSUED.** An ordinary grant is not a delegation act and is ' +
                 'not here: for one identity END TO END — every credential ' +
                 'with the exact grant or flow that produced it, beside the ' +
                 'acts naming them — the console unions this register with the ' +
                 'issued one at /admin/delegation/user?user=…&format=json, and ' +
                 'the tokens alone are in GET /admin-api/users.\n\nWALK IT BY ' +
                 '`seq`: monotonic and never reused, including across a drop.',
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
        description: 'Two rather than the audit log\'s three: a delegation is ' +
                     'DECIDED rather than performed, so there is no third ' +
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
                     'explanation, case-insensitive. One box over six fields, ' +
                     'because the fact a caller has names one of them and not ' +
                     'which column it is in.' }
    ].concat(pagingParameters()),
    responseDescription: 'The matching acts, the distinct chains among them, ' +
                         'the configured Kerberos policy, and the vocabulary ' +
                         'the filters take.',
    responseSchema: { $ref: '#/components/schemas/DelegationList' },
    handler: function (req, res) {
      log.debug("Entering the management API delegation endpoint.");
      sendJson(res, 200, admin.delegationView(req.query).json);
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
                 '(`oauthPermissionBaseUri`; Entra calls it the Application ID ' +
                 'URI and spells it `api://<guid>`, and anything absolute ' +
                 'works here) and permissions on it (`oauthPermission`). A ' +
                 'permission is identified by the two joined — ' +
                 '`https://example.com/` + `write` = ' +
                 '`https://example.com/write` — and a CLIENT application is ' +
                 'granted some of them (`oauthDelegatedPermission`). All three ' +
                 'are ordinary attributes on ordinary entries in ' +
                 '`ou=applications`, so an `ldapmodify` is a configuration ' +
                 'change here exactly as it is for a redirect ' +
                 'URI.\n\n**What the token then says.** A client asks for a ' +
                 'permission as an ordinary OAuth `scope`, and the access ' +
                 'token comes back AUDIENCED to the base URI with the ' +
                 'permission NAME on its scope claim: ' +
                 '`scope=openid https://example.com/write` produces ' +
                 '`aud: https://example.com/` and `scope: openid write`. Each ' +
                 'grant row spells that out, because it is two facts a caller ' +
                 'would otherwise have to compose.\n\n**It refuses nothing ' +
                 'by default.** An ungranted permission is honoured exactly as ' +
                 'a granted one is and marked here; only ' +
                 '`oauth2.delegatedPermissionsEnforced` turns it into ' +
                 '`invalid_scope`, at the authorization endpoint where the ' +
                 'client can still be told.\n\n`grants[].dangling` is a ' +
                 'grant naming a permission no application defines — a deleted ' +
                 'resource, a permission removed from under it, or an ' +
                 '`ldapmodify`, since both console doors refuse to create one. ' +
                 '`grants[].asked` is whether the client has ever requested ' +
                 'that scope, read off its own `oauthScope`: evidence rather ' +
                 'than proof, and the one thing here that comes from what ' +
                 'happened.\n\nThe `graph` member is the same picture ' +
                 '/admin/delegation/allowed draws, in the shape ' +
                 '`GET /admin-api/delegation`\'s `graph` uses.',
    mirrors: 'GET /admin/delegation',
    responseDescription: 'Every application exposing an API, every permission ' +
                         'defined, every grant between two applications, and ' +
                         'the graph of them.',
    responseSchema: { type: 'object',
                      description: 'The configured delegated permission ' +
                                   'register, both directions.' },
    handler: function (req, res) {
      log.debug("Entering the management API permissions endpoint.");
      const view = admin.permissionsView();
      sendJson(res, 200, Object.assign({}, view.register, { graph: view.graph }));
      log.debug("Leaving the management API permissions endpoint.");
    } },

  { method: 'POST', route: BASE + '/permissions/:action', tag: 'Delegation',
    mirrors: 'POST /admin/delegation',
    handler: function (req, res) {
      log.debug("Entering the management API permissions action endpoint.");
      const body = parseBody(req);
      const result = admin.permissionsAction(withAction(req, body));
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API permissions action endpoint.");
    },
    actions: [
      { action: 'set-permission-base', operationId: 'setPermissionBase',
        summary: 'Give an application the base URI its permissions hang off',
        description: 'The first step of exposing an API, and the one that ' +
                     'makes every permission on the entry NAMEABLE: a ' +
                     'permission is identified by this value followed by its ' +
                     'name, so an application with permissions and no base has ' +
                     'permissions no client can ever ask for.\n\nIt must be ' +
                     'ABSOLUTE, because it becomes the `aud` of an access ' +
                     'token and an audience that is not absolute is one ' +
                     'nothing can compare against. A trailing separator is ' +
                     'ADDED where there is none — `https://example.com` ' +
                     'becomes `https://example.com/` — because the identifier ' +
                     'is a plain concatenation and the two would otherwise ' +
                     'join into one word. An `ldapmodify` is not normalised ' +
                     'and means exactly what it says.\n\nSending an empty ' +
                     'value CLEARS it. The permissions stay on the entry with ' +
                     'no identifier, which `GET /admin-api/permissions` ' +
                     'reports, and grants already made become `dangling` on ' +
                     'the clients holding them. Neither is tidied up: that ' +
                     'would be this operation writing to entries the caller ' +
                     'did not name.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            resource: { type: 'string',
                        description: 'The application that EXPOSES the API, by ' +
                                     'its identifier exactly as ' +
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
                     'quote and backslash (RFC 6749 section 3.3), and not `|`, ' +
                     'which separates the name from the description in the ' +
                     'attribute. The DESCRIPTION is optional and is stored ' +
                     'after the first `|` in the same value.\n\n**Defining a ' +
                     'permission grants it to nobody.** That is the ordering ' +
                     'this feature is built on and the reason this operation ' +
                     'and `grant-permission` are two: a permission must exist ' +
                     'before anything can be granted it, and the check is in ' +
                     '`applications.updateApplication()` so that this ' +
                     'operation, the console form and the generic ' +
                     '`POST /admin-api/applications/update` cannot disagree ' +
                     'about it.\n\nA second permission of the SAME NAME is ' +
                     'refused rather than merged — a permission has one ' +
                     'description, and two rows with one name would leave the ' +
                     'second unreachable. Remove it and define it again to ' +
                     'change the wording.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            resource: { type: 'string',
                        description: 'The application that exposes it.' },
            name: { type: 'string',
                    description: 'The permission name — the word a client will ' +
                                 'send inside a `scope`.' },
            description: { type: 'string',
                           description: 'Optional prose, shown wherever the ' +
                                        'permission is.' }
          },
          required: ['resource', 'name'],
          examples: [{ resource: 'api1', name: 'write',
                       description: 'Change widgets on somebody\'s behalf' }],
          additionalProperties: false
        },
        responseDescription: 'The permission\'s identifier, and what a request ' +
                             'naming it would be issued.' },

      { action: 'remove-permission', operationId: 'removePermission',
        summary: 'Stop exposing a permission',
        description: 'Named by its NAME rather than by the raw attribute ' +
                     'value, because that value is `name|description` and a ' +
                     'caller holding a stale description would fail to remove ' +
                     'anything.\n\n**Grants naming it are NOT revoked.** ' +
                     'They stay on the clients\' entries and become ' +
                     '`dangling`, which `GET /admin-api/permissions` reports ' +
                     'and the reply here counts. Revoking them would be this ' +
                     'operation writing to entries the caller did not name; ' +
                     'define the permission again and every one of them ' +
                     'resolves exactly as before.',
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
                     'of `oauthDelegatedPermission`, because the client is the ' +
                     'party that will name the permission in a `scope` — so ' +
                     'the entry that answers *may this request be honoured* is ' +
                     'the entry the request identifies. One client granted ' +
                     'three permissions is three calls and three values; three ' +
                     'clients granted one permission is one value on each of ' +
                     'three entries. That is how one-to-many and many-to-one ' +
                     'both work with no store of their own.\n\n**The ' +
                     'permission must already be DEFINED**, matched EXACTLY ' +
                     'rather than as a prefix of a registered base — so a ' +
                     'client cannot address a token to somebody\'s API by ' +
                     'inventing a word after their base URI. An application ' +
                     'cannot be granted its own permission: the token would be ' +
                     'addressed to itself, which is what an ID Token already ' +
                     'is.\n\n**It changes nothing about what is issued** ' +
                     'unless `oauth2.delegatedPermissionsEnforced` is on. With ' +
                     'it off — the default — the request was already producing ' +
                     'the audience and the scope, and what the grant changes is ' +
                     'that the console stops marking it ungranted.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            client: { type: 'string',
                      description: 'The application that WILL ASK — the one ' +
                                   'whose `client_id` appears on the token ' +
                                   'request. Not the one exposing the API.' },
            permission: { type: 'string',
                          description: 'The whole permission identifier, base ' +
                                       'URI and name together.' }
          },
          required: ['client', 'permission'],
          examples: [{ client: 'webapp1', permission: 'https://example.com/write' }],
          additionalProperties: false
        },
        responseDescription: 'The grant, and what an access token asking for ' +
                             'it will carry.' },

      { action: 'revoke-permission', operationId: 'revokePermission',
        summary: 'Take a permission away from a client application',
        description: 'The opposite of `grant-permission`, and with the setting ' +
                     'off it changes nothing about what is issued either: the ' +
                     'permission still becomes an audience and a scope, and ' +
                     'those requests are simply reported as UNGRANTED — which ' +
                     'is the state `oauth2.delegatedPermissionsEnforced` turns ' +
                     'into a refusal.\n\nIt is also how a DANGLING grant is ' +
                     'cleared: send the identifier exactly as it appears on ' +
                     'the entry, and it goes whether or not anything defines ' +
                     'it.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            client: { type: 'string', description: 'The application holding it.' },
            permission: { type: 'string',
                          description: 'The whole permission identifier.' }
          },
          required: ['client', 'permission'],
          examples: [{ client: 'webapp1', permission: 'https://example.com/write' }],
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
  { method: 'GET', path: BASE + '/consent', tag: 'Delegation',
    operationId: 'getConsent',
    summary: 'What people agreed applications may ask for on their behalf',
    description: 'Both halves of the consent register.\n\n**How it works.** ' +
                 'With `oauth2.consentRequired` on — it is ON by default, and ' +
                 'it is the one policy in this service that is — the ' +
                 'authorization endpoint draws `/oauth2/consent` the first ' +
                 'time a given username signs in to a given `client_id` for a ' +
                 'given scope, and issues nothing until they answer. Allow ' +
                 'writes one `oauthConsent` value per scope onto that ' +
                 'person\'s own entry under `ou=users`; Deny returns ' +
                 '`access_denied` to the client and records nothing.\n\n' +
                 '**`globals` is CONFIGURATION and `users` is a RECORD**, and ' +
                 'the difference decides what removing a row does. A global ' +
                 'consent is `oauthGlobalConsent` on an APPLICATION\'s entry, ' +
                 'one value per scope: everybody who signs in to that ' +
                 'application skips the prompt for it and nothing is written ' +
                 'about anybody — so revoking it asks EVERYBODY again, ' +
                 'including the people who would have said yes. A recorded ' +
                 'consent is one person\'s answer, and revoking it asks that ' +
                 'one person.\n\n**A delegated permission is recorded by its ' +
                 'WHOLE identifier** — `https://example.com/write`, never the ' +
                 'bare `write` — because two resources may both expose a ' +
                 'permission of that name and a consent to one must not cover ' +
                 'the other. `globals[].resource` says which application ' +
                 'exposes it where the scope resolves to one, and ' +
                 '`globals[].granted` whether that client has also been ' +
                 'GRANTED it: the two are independent, and a consented ' +
                 'permission the client does not hold is still refused when ' +
                 '`oauth2.delegatedPermissionsEnforced` is on.\n\n' +
                 '`users[].unreadable` is a value on somebody\'s entry that is ' +
                 'not in the shape this service writes — an `ldapmodify` put ' +
                 'it there. It consents nothing and is reported rather than ' +
                 'dropped.\n\n`storable: false` means no directory is ' +
                 'installed behind the register, so an answer is honoured for ' +
                 'one request and forgotten and the screen is drawn every ' +
                 'time. That is deliberate: an agreement that cannot be ' +
                 'remembered is one nobody gave.',
    mirrors: 'GET /admin/consent',
    responseDescription: 'Every scope consented for everybody on an ' +
                         'application, every answer a person has given, and ' +
                         'whether the screen is being drawn at all.',
    responseSchema: { type: 'object',
                      description: 'The consent register, both halves.' },
    handler: function (req, res) {
      log.debug("Entering the management API consent endpoint.");
      sendJson(res, 200, admin.consentView());
      log.debug("Leaving the management API consent endpoint.");
    } },

  { method: 'POST', route: BASE + '/consent/:action', tag: 'Delegation',
    mirrors: 'POST /admin/consent',
    handler: function (req, res) {
      log.debug("Entering the management API consent action endpoint.");
      const body = parseBody(req);
      const result = admin.consentAction(withAction(req, body));
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API consent action endpoint.");
    },
    actions: [
      { action: 'grant-global-consent', operationId: 'grantGlobalConsent',
        summary: 'Consent a scope for everybody who signs in to an application',
        description: 'Adds one value to `oauthGlobalConsent` on the ' +
                     'application\'s own entry. Nobody is asked about that ' +
                     'scope on that application again, and **nothing is ' +
                     'written about anybody** — this is an OVERRIDE and not a ' +
                     'record.\n\nThat is the whole difference from a person ' +
                     'pressing Allow, and it decides what removing it does: ' +
                     '`revoke-global-consent` asks everybody again, because ' +
                     'there is no record of who would have agreed. Somebody ' +
                     'who consented the same scope personally — before or ' +
                     'after — still has that on their entry and is still not ' +
                     'asked.\n\n**It is keyed on the pair, not on the scope.** ' +
                     'Consenting `read` here consents it for THIS application; ' +
                     'an application registered five minutes later that spells ' +
                     'the same word is still asked. There is no service-wide ' +
                     'list of scopes nobody is ever asked about, deliberately: ' +
                     'it would mean an application nobody has reviewed ' +
                     'inheriting a decision made about a different one.\n\n' +
                     'The scope must be a legal RFC 6749 section 3.3 scope ' +
                     'token, because a value with a space in it is two scopes ' +
                     'and could never match one. It need NOT name a permission ' +
                     'any application defines — most scopes are not ' +
                     'permissions, and refusing an unrecognised one would make ' +
                     'it impossible to consent `openid`.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            client: { type: 'string',
                      description: 'The application people sign in to, by its ' +
                                   'identifier exactly as `ou=applications` ' +
                                   'holds it. This is the CLIENT — the party ' +
                                   'that will name the scope in a request — ' +
                                   'and not the resource that exposes it.' },
            scope: { type: 'string',
                     description: 'The scope, exactly as a client puts it in a ' +
                                  '`scope` parameter. A delegated permission ' +
                                  'is its WHOLE identifier.' }
          },
          required: ['client', 'scope'],
          examples: [{ client: 'webapp1', scope: 'openid' }],
          additionalProperties: false
        },
        responseDescription: 'The application as it now stands, and what ' +
                             'skipping the prompt for that scope now means.' },

      { action: 'revoke-global-consent', operationId: 'revokeGlobalConsent',
        summary: 'Stop consenting a scope for everybody',
        description: 'Removes one value from `oauthGlobalConsent`. **The next ' +
                     'person to sign in asking for that scope is PROMPTED**, ' +
                     'including everybody the override was covering, because ' +
                     'an override records nothing about the people it covers. ' +
                     'Somebody who agreed to it personally is unaffected — ' +
                     'their answer is on their own entry and `revoke-consent` ' +
                     'is what takes that away.\n\nNothing already ISSUED is ' +
                     'touched. An access token minted while the override stood ' +
                     'is still valid, exactly as revoking a delegated ' +
                     'permission does not re-judge a grant already made.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            client: { type: 'string', description: 'The application holding it.' },
            scope: { type: 'string', description: 'The scope to stop consenting.' }
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
                     'nobody else is affected.\n\n**All three are required and ' +
                     'that is not pedantry.** One person may consent the same ' +
                     'scope to several applications, and revoking the wrong ' +
                     'pair is invisible until somebody is asked again — which ' +
                     'is a week later and looks like a bug in the screen.\n\n' +
                     'A scope covered by GLOBAL consent is not on anybody\'s ' +
                     'entry, so there is nothing here to remove and this ' +
                     'refuses rather than pretending: ' +
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
                                     'and `urn:sts-mock:user:alice` are one ' +
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
                     'consents is a chore rather than a control.\n\nIt reaches ' +
                     'nothing under GLOBAL consent, because there is nothing ' +
                     'on their entry to reach — a scope they were never asked ' +
                     'about leaves no record, which is what lets the register ' +
                     'tell the two apart at all. Nothing already issued is ' +
                     'touched.',
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
                 'retired ones that are still published behind it), the bundle ' +
                 'path and its sequence, every federated trust domain, and ' +
                 'whether each of the four gRPC listeners actually bound — ' +
                 'which nothing else can tell you, because neither this API ' +
                 'nor GET /admin/sts-metadata can see a socket.\n\nThe ' +
                 'reply also ' +
                 'carries `authentication`: whether the SPIRE Server API is ' +
                 'enforcing mutual TLS (`spiffe.authRequired`), which ' +
                 'identities are administrators, and the whole per-method ' +
                 'authorization table, which is SPIRE\'s own ' +
                 '`policy_data.json` row for row.\n\n**Nothing here attests ' +
                 'a workload or a node.** A Workload API caller is identified ' +
                 'only by the transport it arrived on, the endpoint it ' +
                 'reached and its peer address — node cannot read a Unix ' +
                 'socket\'s peer credentials — and an agent\'s attestation ' +
                 'payload is taken on trust. With `spiffe.authRequired` off, ' +
                 'the SPIRE Server API authenticates nobody either and any ' +
                 'caller that reaches its port can create a registration ' +
                 'entry granting any identity here. GET /spiffe carries the ' +
                 'full list of what is and is not checked.\n\nNo private key ' +
                 'is in this reply. The authority CERTIFICATE is published, as ' +
                 'GET /tls/server-certificate publishes that one.',
    mirrors: 'GET /admin/spiffe',
    responseDescription: 'The trust domain, its authorities, its federated ' +
                         'bundles and its listeners.',
    responseSchema: { type: 'object',
                      description: 'The SPIFFE trust domain as this service ' +
                                   'holds it.' },
    handler: function (req, res) {
      log.debug("Entering the management API SPIFFE endpoint.");
      sendJson(res, 200, admin.spiffeView(req).json);
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
      admin.spiffeAction(withAction(req, body)).then(function (result) {
        sendJson(res, result.ok ? 200 : 400, result);
        log.debug("Leaving the management API SPIFFE action endpoint.");
      }).catch(function (err) {
        log.error('The SPIFFE management API action threw: ' + err.message);
        sendJson(res, 500, { ok: false, errors: [err.message] });
        log.debug("Leaving the management API SPIFFE action endpoint. It threw.");
      });
    },
    actions: [
      { action: 'rotate', operationId: 'rotateSpiffeAuthority',
        summary: 'Rotate the X.509 authority, the JWT authority, or both',
        description: 'A new authority is PREPENDED — everything is signed with ' +
                     'it from that moment — and the old one stays in the ' +
                     'published bundle, so SVIDs already in the field go on ' +
                     'verifying. That is what a bundle is FOR, and dropping ' +
                     'the old one is the difference between a rotation and an ' +
                     'outage.\n\nThe bundle `spiffe_sequence` changes, which ' +
                     'is how a consumer that polls the bundle endpoint knows ' +
                     'to refetch. At most four authorities are retained; past ' +
                     'that the oldest is dropped and anything it signed stops ' +
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
                     'RefreshBundle says so in terms — because fetching a URL ' +
                     'somebody registered, in order to obtain a key that will ' +
                     'then verify credentials, is a server-side request ' +
                     'forgery with a citation attached. The same refusal this ' +
                     'service gives WS-Federation\'s `wreqptr` and a ' +
                     'client\'s `jwks_uri`.\n\nThe document is CHECKED, ' +
                     'which is unusual for this service: every JWK needs a ' +
                     '`use` of `x509-svid`, `jwt-svid` or `wit-svid`, because ' +
                     'a consumer MUST IGNORE one without it — so a bundle of ' +
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
                                     '`spiffe_refresh_hint`. A JSON string is ' +
                                     'accepted too, which is what the ' +
                                     'console\'s textarea sends.' },
            bundleEndpointUrl: { type: 'string',
                                 description: 'Recorded and never fetched. It ' +
                                              'is reported back so an operator ' +
                                              'can see what the relationship ' +
                                              'says.' },
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
        description: 'Any registration entry that federates with it keeps the ' +
                     'name and simply contributes no bundle to its workloads, ' +
                     'which is the same state as a relationship configured ' +
                     'before its bundle has arrived. The entries are left ' +
                     'alone deliberately; the SPIRE Server API\'s ' +
                     'BatchDeleteFederatedBundle is where the three modes ' +
                     'RESTRICT, DELETE and DISSOCIATE live.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            trustDomain: { type: 'string', description: 'The trust domain name.' }
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
                 'under which parent, matching which selectors. It is the most ' +
                 'important object in a SPIFFE deployment: the Workload API ' +
                 'answers out of it.\n\n**The entries ARE the registry.** ' +
                 'They live under `ou=entries,ou=spiffe` in the embedded LDAP ' +
                 'directory and nothing caches them, so an `ldapmodify` is ' +
                 'visible here on the next call and changes what the next SVID ' +
                 'looks like.\n\n**The selectors restrict nothing here.** ' +
                 'They are recorded, reported, and used by the SPIRE Server ' +
                 'API\'s GetAuthorizedEntries — and the Workload API hands ' +
                 'every caller every identity, because nothing in this service ' +
                 'attests a workload.',
    mirrors: 'GET /admin/spiffe/entries',
    parameters: [
      { name: 'entry', in: 'query', required: false, schema: { type: 'string' },
        description: 'One entry, by its id — the 32 hex characters this ' +
                     'registry minted, which is what the SPIRE Server API ' +
                     'calls `id`. The reply then carries that entry with every ' +
                     'attribute of its directory entry.' },
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
      sendJson(res, 200, admin.spiffeEntriesView(req).json);
      log.debug("Leaving the management API SPIFFE entries endpoint.");
    } },

  { method: 'POST', route: BASE + '/spiffe/entries/:action', tag: 'SPIFFE',
    mirrors: 'POST /admin/spiffe/entries',
    handler: function (req, res) {
      log.debug("Entering the management API SPIFFE entries action endpoint.");
      const body = parseBody(req);
      const result = admin.spiffeEntriesAction(withAction(req, body));
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
                     'for), and a SPIFFE ID under the reserved `/spire` path, ' +
                     'which belongs to this server and the agents it ' +
                     'attests.\n\nA DUPLICATE SPIFFE ID IS ALLOWED. Two ' +
                     'entries granting one identity under different parents is ' +
                     'a real configuration and SPIRE permits it.\n\nThis is ' +
                     'the same function `BatchCreateEntry` on the SPIRE Server ' +
                     'API calls, writing the same directory entry an ' +
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
                                     'entry describing a workload rather than ' +
                                     'a node.' },
            selectors: { type: 'string',
                         description: 'Comma-separated `type:value` pairs, ' +
                                      'split on the FIRST colon only — so ' +
                                      '`docker:label:app:web` is type ' +
                                      '`docker` and value `label:app:web`. An ' +
                                      'entry with NO selectors matches every ' +
                                      'workload, which is how a catch-all is ' +
                                      'written and is also the shape of one ' +
                                      'somebody forgot to finish.' },
            dnsNames: { type: 'string',
                        description: 'Comma-separated DNS subjectAltNames, ' +
                                     'added beside the SPIFFE ID. What makes ' +
                                     'an SVID usable by TLS software that ' +
                                     'checks a hostname and cannot read a ' +
                                     'SPIFFE ID.' },
            federatesWith: { type: 'string',
                             description: 'Comma-separated trust domain names ' +
                                          'whose bundles are handed to a ' +
                                          'holder of this identity. A name ' +
                                          'with no bundle here contributes ' +
                                          'nothing rather than failing.' },
            x509SvidTtl: { type: 'integer',
                           description: 'Seconds. 0 means spiffe.svidTtl.' },
            jwtSvidTtl: { type: 'integer',
                          description: 'Seconds. 0 means spiffe.jwtSvidTtl.' },
            hint: { type: 'string',
                    description: 'Operator guidance when a workload gets more ' +
                                 'than one SVID — `internal`, `external`. ' +
                                 'Passed through verbatim; nothing here reads ' +
                                 'it.' }
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
        description: '**What may be changed is DECLARED and not DERIVED.** The ' +
                     'declared half is what the entry may DO — the SPIFFE ID, ' +
                     'the parent, the selectors, the DNS names, the ' +
                     'lifetimes, the hint, the flags — and it is what the ' +
                     'Workload API reads. The derived half is what HAPPENED: ' +
                     'the revision number, the SVID counter, when it was ' +
                     'created. Those are refused with a list of what is not, ' +
                     'because a call that could rewrite them would make this ' +
                     'registry lie about the service\'s own behaviour in a ' +
                     'way indistinguishable from the recording being ' +
                     'broken.\n\n`ldapmodify` still reaches everything, ' +
                     'which is deliberate: refusing it HERE is the difference ' +
                     'between offering an operation and merely not preventing ' +
                     'it.\n\nThe change applies to the NEXT SVID issued from ' +
                     'this entry. Nothing already issued changes, and there is ' +
                     'nothing to invalidate — SPIFFE has no revocation.',
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
        responseDescription: 'The entry as it now stands, at its new revision.' },

      { action: 'delete', operationId: 'deleteSpiffeEntry',
        summary: 'Remove an entry',
        description: 'Anything holding an SVID minted from it keeps that SVID ' +
                     'until it expires. SPIFFE has no revocation — the answer ' +
                     'is a short lifetime and rotation, which is why the ' +
                     'default X509-SVID lifetime here is an hour and the ' +
                     'JWT-SVID one is five minutes.\n\nIf this was the LAST ' +
                     'entry naming that SPIFFE ID, the identity\'s directory ' +
                     'entry under `ou=users` is marked ' +
                     '`spiffeCredentialStatus: revoked` with the reason on it. ' +
                     'The entry is NOT deleted, and that flag is not a ' +
                     'certificate status: nothing reads it back and no SVID is ' +
                     'refused because of it. Deleting one of several entries ' +
                     'that name the same identity changes nothing there.' +
                     '\n\nA seeded entry stays ' +
                     'deleted until a restart: nothing here is persisted, but ' +
                     'nothing re-creates it either, because an operator who ' +
                     'deleted it meant to.',
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
                 'whatever payload it sends are written down as claimed, which ' +
                 'is why every agent carries a selector valued ' +
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
      sendJson(res, 200, admin.spiffeAgentsView(req).json);
      log.debug("Leaving the management API SPIFFE agents endpoint.");
    } },

  { method: 'POST', route: BASE + '/spiffe/agents/:action', tag: 'SPIFFE',
    mirrors: 'POST /admin/spiffe/agents',
    handler: function (req, res) {
      log.debug("Entering the management API SPIFFE agents action endpoint.");
      const body = parseBody(req);
      const result = admin.spiffeAgentsAction(withAction(req, body));
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
                     'in SPIFFE, so a ban stops the NEXT identity rather than ' +
                     'the current one.\n\nThe agent\'s own entry under ' +
                     '`ou=users` — the one every identity this trust domain ' +
                     'issues a certificate to gets — is marked ' +
                     '`spiffeCredentialStatus: revoked`, and unbanning marks it ' +
                     'active again. It is never deleted, and nothing reads that ' +
                     'flag back.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            agent: { type: 'string', description: 'The agent\'s SPIFFE ID.' }
          },
          required: ['agent'],
          examples: [{ agent: 'spiffe://example.org/spire/agent/k8s_psat/abc' }],
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
          examples: [{ agent: 'spiffe://example.org/spire/agent/k8s_psat/abc' }],
          additionalProperties: false
        },
        responseDescription: 'The agent as it now stands.' },

      { action: 'delete', operationId: 'deleteSpiffeAgent',
        summary: 'Forget an agent',
        description: '**Deleting is forgetting, not revoking.** It reappears ' +
                     'the moment it attests again, because attestation is not ' +
                     'checked here. Ban it if the intention was to stop it.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            agent: { type: 'string', description: 'The agent\'s SPIFFE ID.' }
          },
          required: ['agent'],
          examples: [{ agent: 'spiffe://example.org/spire/agent/k8s_psat/abc' }],
          additionalProperties: false
        },
        responseDescription: 'That it is forgotten.' }
    ] }
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
ROUTES.forEach(function (entry) {
  const path = entry.route || entry.path;
  if (entry.method === 'GET') {
    app.get(path, entry.handler);
    return;
  }
  app.post(path, entry.handler);
});

log.info('The management API is at ' + BASE + ': ' +
         operationSummaries().length + ' operations over the same functions ' +
         'the /admin console calls. Its OpenAPI document is at ' + BASE +
         '/openapi.json and an explorer that calls it is at ' + BASE +
         '/docs. It is NOT protected — and the console now IS ' +
         '(admin.authRequired), so this is the surface to reach for when ' +
         'nobody holds a console role: POST ' + BASE + '/rbac/grant.');

module.exports = {
  BASE: BASE,
  // The table, so that the parent project's tests can assert what this file
  // covers against what the console offers rather than against a list somebody
  // typed into a test.
  ROUTES: ROUTES,
  operationSummaries: operationSummaries
};
