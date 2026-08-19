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
// NOT PROTECTED, deliberately, exactly as the console is not. This service
// checks no password anywhere; a credential on this API would be the only
// authenticated surface in a service whose premise is that it authenticates
// nobody, and the only one a test would have to hold a secret for. Anyone who
// can reach this port can revoke every token issued here and change what the
// next one contains. Do not put this service on a public address — which was
// already true of /oauth2/token, and is why there is nothing new to weigh here.
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

const app = require('./app');
const { log, parseBody, baseUrlOf } = require('./helpers');
const admin = require('./admin');
const spec = require('./admin_api_spec');
const docs = require('./admin_api_docs');
const VERSION = require('./package.json').version;

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
                   ' and is capped at ' + admin.MAX_ROWS + '.' }
  ];
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
                 'naming nobody.',
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
    ].concat(pagingParameters()),
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
    ].concat(pagingParameters()),
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
                 'value may use.',
    mirrors: 'GET /admin/claims',
    responseDescription: 'The four sets.',
    responseSchema: { $ref: '#/components/schemas/ClaimSets' },
    handler: function (req, res) {
      log.debug("Entering the management API claims endpoint.");
      sendJson(res, 200, admin.claimsJson());
      log.debug("Leaving the management API claims endpoint.");
    } },

  { method: 'POST', route: BASE + '/claims/:action', tag: 'Custom claims',
    mirrors: 'POST /admin/claims',
    handler: function (req, res) {
      log.debug("Entering the management API claims action endpoint.");
      const body = parseBody(req);
      const result = admin.claimsAction(withAction(req, body));
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
        responseDescription: 'The set as it now stands, in `claims`.' }
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
         '/docs. It is NOT protected, exactly as the console is not.');

module.exports = {
  BASE: BASE,
  // The table, so that the parent project's tests can assert what this file
  // covers against what the console offers rather than against a list somebody
  // typed into a test.
  ROUTES: ROUTES,
  operationSummaries: operationSummaries
};
