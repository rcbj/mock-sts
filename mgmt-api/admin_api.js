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
//     project's tests/admin_api.js asserts, by walking the console's own NAV
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
//   * **A test drives this API.** The parent project's tests/admin_api.js walks
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
// the router honest (one row in GET /sts-metadata per resource, showing the
// parameter) while the OpenAPI document lists each URL as the separate
// operation it is, which is what makes the explorer's per-action forms
// possible. An unknown action is not a 404: it reaches the console's own
// handler and comes back as its "Unknown action" refusal, naming the ones that
// exist.
// ---------------------------------------------------------------------------

const app = require('../common/app');
const { log, parseBody, baseUrlOf } = require('../common/helpers');
const admin = require('../admin-ui/admin');
// The two console roles, for the `enum` on the role parameter and on both
// request bodies. A library that registers nothing, so requiring it here moves
// no route; taking the ids from it rather than writing them twice is what stops
// the OpenAPI document offering a role this service does not have.
const rbac = require('../admin-ui/admin_rbac');
const spec = require('./admin_api_spec');
const docs = require('./admin_api_docs');
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
// THE TABLE. Express registration and the OpenAPI document are both built from
// it, which is what makes them incapable of disagreeing.
//
// A row is either a plain operation (`path` + `handler`) or an action resource
// (`route` with `:action` in it + `handler` + `actions`), where each action is
// one documented operation at its own concrete URL.
// ---------------------------------------------------------------------------
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
    mirrors: 'GET /sts-metadata',
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
         .send(docs.page(baseUrlOf(req), BASE, VERSION));
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

  { method: 'GET', path: BASE + '/config', tag: 'Configuration',
    operationId: 'getConfig',
    summary: 'Every setting this service has, and where each value came from',
    description: 'The forty-five settings, grouped by protocol, each with its ' +
                 'effective value and the SOURCE of that value: a runtime ' +
                 'override, an environment variable, the appconfig file, or ' +
                 'the built-in default. The source is the part that was not ' +
                 'answerable before this resource existed — the four are ' +
                 'indistinguishable once a value has been read, and the ' +
                 'question "why is the issuer that?" used to be a grep.\n\n' +
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
        description: 'IN MEMORY ONLY, and gone on restart — nothing here ' +
                     'writes to the appconfig file. That is the same ' +
                     'arrangement as the custom claims and the credential ' +
                     'claims, and it is deliberate: a service that edited a ' +
                     'file checked into a repository would leave a test\'s ' +
                     'forgotten change behind permanently.\n\nThe change ' +
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
                     'variable, the appconfig file, or the built-in default. ' +
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
      const result = admin.claimsAction(withAction(req, body), names);
      sendJson(res, result.ok ? 200 : 400, result);
      log.debug("Leaving the management API claims action endpoint.");
    },
    actions: [
      { action: 'add', operationId: 'addClaim',
        summary: 'Add one claim to one set',
        description: 'Every token or assertion of that kind issued from now ' +
                     'on carries it; nothing already issued changes.\n\n' +
                     'ADDITIVE ONLY. A name this service sets itself is ' +
                     'REFUSED rather than allowed to win, because every one ' +
                     'of those is load-bearing — a settable `exp` would ' +
                     'produce tokens that fail to verify with nothing ' +
                     'pointing back at the call that caused it. `GET ' +
                     '/admin-api/claims` lists the refused names.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            set: { type: 'string',
                   enum: ['access_token', 'id_token', 'saml2', 'saml11'] },
            name: { type: 'string' },
            value: { type: 'string',
                     description: 'May carry a ${...} placeholder.' },
            nameFormat: { type: 'string',
                          description: 'The SAML 2.0 set only.' },
            namespace: { type: 'string',
                         description: 'The SAML 1.1 set only.' }
          },
          required: ['set', 'name'],
          examples: [{ set: 'id_token', name: 'dept', value: 'engineering' }],
          additionalProperties: false
        },
        responseDescription: 'The set as it now stands, in `claims`.' },

      { action: 'remove', operationId: 'removeClaim',
        summary: 'Remove one claim from one set',
        description: 'By name. A name the set does not carry is refused ' +
                     'rather than treated as already done, because the two ' +
                     'are different facts and a caller that misspelt a name ' +
                     'would otherwise be told it succeeded.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            set: { type: 'string',
                   enum: ['access_token', 'id_token', 'saml2', 'saml11'] },
            name: { type: 'string' }
          },
          required: ['set', 'name'],
          examples: [{ set: 'id_token', name: 'dept' }],
          additionalProperties: false
        },
        responseDescription: 'The set as it now stands, in `claims`.' },

      { action: 'clear', operationId: 'clearClaims',
        summary: 'Empty one set',
        description: 'Those tokens then carry only what the protocol puts in ' +
                     'them.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            set: { type: 'string',
                   enum: ['access_token', 'id_token', 'saml2', 'saml11'] }
          },
          required: ['set'],
          examples: [{ set: 'id_token' }],
          additionalProperties: false
        },
        responseDescription: 'An empty `claims`.' },

      { action: 'replace', operationId: 'replaceClaims',
        summary: 'Set a whole claim set at once',
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
            set: { type: 'string',
                   enum: ['access_token', 'id_token', 'saml2', 'saml11'] },
            claims: { type: 'array',
                      items: { $ref: '#/components/schemas/ClaimEntry' } }
          },
          required: ['set', 'claims'],
          examples: [{ set: 'id_token', claims: [
            { name: 'dept', value: 'engineering' },
            { name: 'on_behalf_of', value: '${username}' }
          ] }],
          additionalProperties: false
        },
        responseDescription: 'The set as it now stands, in `claims`.' },

      // --- the directory-attribute half of a set --------------------------
      //
      // Three operations rather than one with a mode, mirroring the console's
      // three buttons, and the reason is in admin.js beside them: an empty
      // `attributes` array would otherwise be ambiguous between "clear it" and
      // "my HTTP client dropped an empty array", which is a real behaviour of
      // real clients and the kind of ambiguity that silently empties a set.
      { action: 'attributes', operationId: 'setClaimAttributes',
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
                     'has an entry value for still produces a claim; it is ' +
                     'generated, and `attributeReport` says so per claim.' +
                     '\n\nAn unknown attribute name refuses the WHOLE call ' +
                     'rather than being skipped: the catalogue is fixed, so ' +
                     'an unknown name is either a hand-written request that ' +
                     'deserves an answer or a rename that left a caller ' +
                     'behind. `attributeCatalogue` in GET ' +
                     '/admin-api/claims is the list.\n\nA TYPED claim of ' +
                     'the same name WINS over one of these, and THE ' +
                     'PROTOCOL\'S OWN CLAIM BEATS BOTH — which is worth ' +
                     'knowing before it is discovered on a token. An ID ' +
                     'Token always carries name, given_name, family_name, ' +
                     'preferred_username and email built from the sign-in, ' +
                     'so selecting cn, givenName, sn, uid or mail ON THAT ' +
                     'SET changes nothing the client sees; the same five ' +
                     'reach an access token from the directory, because the ' +
                     'protocol sets none of them there. A SAML 2.0 assertion ' +
                     'sets `name` the same way and a WS-Federation one sets ' +
                     'the whole identity claim list. Both halves are ' +
                     'reported by that same GET.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            set: { type: 'string',
                   enum: ['access_token', 'id_token', 'saml2', 'saml11'] },
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
          examples: [{ set: 'access_token',
                       attributes: ['mail', 'departmentNumber', 'title'] }],
          additionalProperties: false
        },
        responseDescription: 'What the set carries now, in `attributes`, ' +
                             'with `added` and `removed`.' },

      { action: 'attributes-all', operationId: 'selectAllClaimAttributes',
        summary: 'Put every catalogued attribute in one set',
        description: 'Every attribute type in the catalogue, which is a ' +
                     'legitimate thing to test and makes a large token. It ' +
                     'exists as its own operation so that "all of them" does ' +
                     'not mean a caller constructing the whole list of ' +
                     'names that has to be updated whenever the catalogue ' +
                     'is.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            set: { type: 'string',
                   enum: ['access_token', 'id_token', 'saml2', 'saml11'] }
          },
          required: ['set'],
          examples: [{ set: 'id_token' }],
          additionalProperties: false
        },
        responseDescription: 'The whole catalogue, in `attributes`.' },

      { action: 'attributes-clear', operationId: 'clearClaimAttributes',
        summary: 'Take every directory attribute out of one set',
        description: 'The TYPED claims on that set are untouched — this is ' +
                     'the other half. Clearing both takes this and `clear`.' +
                     '\n\nNothing is deleted from the directory: what was ' +
                     'written onto an entry stays there, because an operator ' +
                     'may have set it and nothing here has the standing to ' +
                     'remove it.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            set: { type: 'string',
                   enum: ['access_token', 'id_token', 'saml2', 'saml11'] }
          },
          required: ['set'],
          examples: [{ set: 'id_token' }],
          additionalProperties: false
        },
        responseDescription: 'An empty `attributes`, and what was `removed`.' }
    ] },

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

  { method: 'POST', route: BASE + '/applications/:action', tag: 'Applications',
    mirrors: 'POST /admin/applications',
    handler: function (req, res) {
      log.debug("Entering the management API applications action endpoint.");
      const body = parseBody(req);
      const result = admin.applicationsAction(withAction(req, body));
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
                                 'refused rather than recorded.' }
          },
          required: ['identifier'],
          examples: [{ identifier: 'urn:example:crm', name: 'CRM',
                       kind: 'wsfed-relying-party' }],
          additionalProperties: false
        },
        responseDescription: 'The application as it now stands, in `application`.' },

      { action: 'set', operationId: 'setApplicationAttribute',
        summary: 'Set a single-valued attribute',
        description: 'For the attributes that hold ONE value — `appName`, ' +
                     '`oauthClientSecret`, `oauthTokenEndpointAuthMethod`, ' +
                     '`oauthConfidential`, the SAML and Kerberos identifiers. ' +
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
                                      'attributes. GET /ldap/applications ' +
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
        description: 'For the attributes that hold a LIST — `oauthRedirectUri`, ' +
                     '`oauthPostLogoutRedirectUri`, `oauthGrantType`, ' +
                     '`oauthResponseType`, `oauthScope`, ' +
                     '`samlAssertionConsumerService`, `description`.\n\nThis ' +
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
                 'nor GET /sts-metadata can see a socket.\n\nThe reply also ' +
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
