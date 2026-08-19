'use strict';
//
// File: admin_api_spec.js
//
// ---------------------------------------------------------------------------
// The OpenAPI document for the management API, and the schemas it is written
// in.
//
// It is BUILT FROM THE ROUTE TABLE in admin_api.js rather than kept beside it
// as a hand-written YAML file, and that is the whole point of this module. A
// spec file next to the code it describes is a spec file that is wrong within a
// month: somebody adds an action to the console, adds it to the API, and does
// not touch the document — and the only thing that then reports the drift is a
// person reading both. Here the operation and its description are ONE OBJECT,
// so an operation that exists is documented by construction and one that is
// documented exists.
//
// The counterpart rule is in admin_api.js: an /admin control gets an /admin-api
// operation in the same commit. That one cannot be enforced by construction —
// nothing can see a form appear on a page — so it is asserted by the parent
// project's tests/admin_api.js instead, which walks the console's own NAV and
// action lists and fails on a page or an action with no operation.
//
// OpenAPI 3.1.0 rather than 3.0.3: this document uses JSON Schema `examples`,
// `const` and nullable-by-union, all of which 3.0 spells differently or not at
// all. Every tool this repository would plausibly meet reads 3.1.
//
// This module registers no route and requires nothing of this service's — it is
// a pure function over a table — so its position in the require order does not
// matter, in the sense rule 3 gives for dpop.js.
// ---------------------------------------------------------------------------

// The reply shape shared by every POST here: the console's own action result,
// unchanged. `ok` is the only member that is always present; the rest depends
// on what was asked, which is why this schema is open rather than closed.
const ACTION_RESULT = {
  type: 'object',
  description:
    'What the console\'s own action functions return, unchanged. `ok` is ' +
    'true when the operation was applied and false when it was refused; a ' +
    'refusal carries `errors` and is answered with HTTP 400. Successful ' +
    'replies carry `message` — the sentence the console would have shown — ' +
    'plus whatever the action produced: `claims` for a claim set, `selected` ' +
    'for the credential claim set, `requested` for the verifier request, ' +
    '`revoked` for a count.',
  properties: {
    ok: { type: 'boolean', description: 'Whether the operation was applied.' },
    message: {
      type: 'string',
      description: 'What happened, in the words the console would have used. ' +
                   'Present on success.'
    },
    errors: {
      type: 'array', items: { type: 'string' },
      description: 'Why it was refused. Present when `ok` is false.'
    }
  },
  required: ['ok'],
  additionalProperties: true
};

// One row of the issued list: a JWT, a SAML assertion or a Kerberos ticket. The
// signed artifact is NEVER in it — see the note on the console's tokens page —
// so what a caller gets is the facts about it and the jti to act on.
const ISSUED_RECORD = {
  type: 'object',
  description:
    'One thing this service issued and still remembers. Claims and facts ' +
    'only: the signed token, the assertion XML and the ticket are ' +
    'deliberately not kept, because a list that carried them would be a ' +
    'credential dump.',
  properties: {
    family: {
      type: 'string',
      description: 'Which of the three families this row is — the value the ' +
                   '`family` filter takes. `GET /admin-api/tokens` lists ' +
                   'them all under `families`.'
    },
    kind: {
      type: 'string',
      description: 'access_token, id_token, refresh_token, a SAML assertion ' +
                   'version, or a Kerberos ticket type.'
    },
    state: {
      type: 'string',
      description: 'valid, expired, revoked, "not yet valid" or "no expiry ' +
                   'stated" — the value the `state` filter takes.'
    },
    jti: {
      type: 'string',
      description: 'The identifier every POST here acts on. Only the three ' +
                   'JWT kinds can be revoked; an assertion or a ticket has ' +
                   'one so that it can be named, not so that it can be ' +
                   'invalidated.'
    },
    sub: { type: 'string', description: 'The subject named on it.' },
    username: { type: 'string', description: 'The name that was signed in.' },
    typ: { type: 'string',
           description: 'The artifact type as its own family names it.' },
    issuedAt: { type: 'integer', description: 'Milliseconds since the epoch.' },
    expiresAtMs: {
      type: ['integer', 'null'],
      description: 'Milliseconds since the epoch, or absent where the ' +
                   'artifact states no expiry. `iat`, `nbf` and `exp` are ' +
                   'beside it in SECONDS, as the artifact itself carries them.'
    },
    revocable: {
      type: 'boolean',
      description: 'Whether anything consults this service about it. FALSE ' +
                   'for every SAML assertion and every Kerberos ticket, which ' +
                   'is why those are listed without a way to revoke them ' +
                   'rather than with one that would change a number here and ' +
                   'nothing out there.'
    },
    revoked: { type: 'boolean' },
    revokedAt: { type: ['integer', 'null'] },
    revokedVia: { type: 'string', description: 'What revoked it.' },
    sessionId: {
      type: 'string',
      description: 'The browser sign-on session this was issued ON, where ' +
                   'there was one. Empty for anything issued with no human ' +
                   'behind it, a client-credentials token included.'
    },
    jkt: { type: 'string',
           description: 'The DPoP key thumbprint, where the token is bound.' },
    grant: { type: 'string', description: 'The grant that issued it.' },
    client_id: { type: 'string' },
    scope: { type: 'string' },
    identifier: {
      type: 'string',
      description: 'The same value as `jti`, under the name this row\'s own ' +
                   'family uses for it.'
    },
    length: {
      type: 'integer',
      description: 'How long the artifact was, in characters. The artifact ' +
                   'itself is not kept.'
    },
    key: { type: 'string', description: 'The same value as `jti` again — the ' +
                                        'name the row is filed under.' },
    iat: { type: 'integer', description: 'SECONDS since the epoch, as the ' +
                                         'artifact carries it.' },
    nbf: { type: 'integer', description: 'Seconds since the epoch.' },
    exp: { type: 'integer', description: 'Seconds since the epoch.' }
  },
  additionalProperties: true
};

const CLAIM_ENTRY = {
  type: 'object',
  description:
    'One custom claim. `nameFormat` applies to the SAML 2.0 set and ' +
    '`namespace` to the SAML 1.1 set; both are ignored by the two JWT sets.',
  properties: {
    name: { type: 'string' },
    value: {
      type: 'string',
      description: 'May carry a placeholder such as ${username}; ' +
                   '`GET /admin-api/claims` lists the ones this service ' +
                   'expands.'
    },
    nameFormat: { type: 'string' },
    namespace: { type: 'string' }
  },
  required: ['name'],
  additionalProperties: false
};

// The paging members every list here carries. Written once and mixed into the
// three list schemas, because a caller walking one of them has to be able to
// walk the others the same way.
const PAGING_PROPERTIES = {
  page: {
    type: 'integer',
    description: 'The page these rows are from, CLAMPED — `?page=999` on a ' +
                 'two-page list reports 2, which is the page in the reply.'
  },
  pages: { type: 'integer', description: 'How many pages the match has.' },
  perPage: { type: 'integer',
             description: 'Rows per page, clamped to the cap.' },
  firstRow: {
    type: 'integer',
    description: '1-based and inclusive; 0 when nothing matched.'
  },
  lastRow: { type: 'integer', description: '1-based and inclusive.' }
};

function openObject(description, properties) {
  return { type: 'object', description: description,
           properties: properties, additionalProperties: true };
}


// One row of config.js's table, as this API reports it. Written out rather than
// left open because every property here is one a generator would want a name
// for, and because `source` is the answer to the question the whole resource
// exists for: a value alone does not say whether somebody set it, the container
// set it, the file set it, or nobody did.
const CONFIG_SETTING = openObject(
  'One setting: what it is, what it is set to, and where that came from.',
  {
    key: { type: 'string',
           description: 'The dot path, which is BOTH the name every operation ' +
                        'here takes and the path in the appconfig file. ' +
                        '`oid4vci.batchSize` is `appconfig.oid4vci.batchSize`.' },
    group: { type: 'string',
             description: 'The protocol it belongs to, and the console\'s ' +
                          'section heading.' },
    label: { type: 'string' },
    description: { type: 'string',
                   description: 'What it does and why the default is the ' +
                                'default.' },
    type: { type: 'string',
            enum: ['string', 'int', 'port', 'bool', 'csv', 'enum'],
            description: 'How a value posted for it is coerced and checked.' },
    enumValues: { type: 'array', items: { type: 'string' },
                  description: 'Present on `enum` settings only.' },
    value: { description: 'The effective value, coerced to its type: a number ' +
                          'for int/port, a boolean for bool, an array of ' +
                          'strings for csv.' },
    text: { type: 'string',
            description: 'The same value on one line — what the console shows ' +
                         'in its input and what the environment variable ' +
                         'would carry.' },
    source: {
      type: 'string',
      enum: ['override', 'env', 'env-legacy', 'appconfig', 'default'],
      description: 'Where the effective value came from, highest first: a ' +
                   'runtime override set through this API or the console; the ' +
                   'setting\'s own environment variable; the LEGACY variable ' +
                   'named in `legacyEnv` (STS_ISSUER still feeds the three ' +
                   'issuers carved out of it); the appconfig file; the ' +
                   'built-in default.'
    },
    editable: {
      type: 'boolean',
      description: 'Whether POST /config/set will take it. False means the ' +
                   'value was consumed at startup — a bound socket, the TLS ' +
                   'certificate\'s names, the Kerberos principal database, ' +
                   'the directory\'s base DN — so changing it now would do ' +
                   'nothing. It is refused rather than accepted, because an ' +
                   'accepted change that does nothing reads as having worked.'
    },
    restartReason: { type: 'string',
                     description: 'Why it is not editable. Present exactly ' +
                                  'when `editable` is false.' },
    env: { type: 'string', description: 'Its environment variable.' },
    legacyEnv: { type: 'string',
                 description: 'An older variable that still feeds it. Only ' +
                              'the three issuers have one.' },
    appconfigPath: { type: 'string' },
    default: { description: 'The built-in default, which is what the shipped ' +
                            'appconfig files were seeded with.' },
    overridden: { type: 'boolean',
                  description: 'Whether a runtime override is in force. Equal ' +
                               'to `source === "override"`, and reported ' +
                               'separately so a caller can filter without ' +
                               'matching a string.' }
  });

const SCHEMAS = {
  ActionResult: ACTION_RESULT,
  IssuedRecord: ISSUED_RECORD,
  ClaimEntry: CLAIM_ENTRY,

  ApiIndex: openObject(
    'What this API is, where its document is, and every operation it offers.',
    {
      name: { type: 'string' },
      version: { type: 'string' },
      openapi: { type: 'string', description: 'Where the document is.' },
      docs: { type: 'string', description: 'Where the explorer is.' },
      console: { type: 'string',
                 description: 'Where the console every operation mirrors is.' },
      protected: {
        type: 'boolean',
        description: 'Always false. Nothing here checks a credential; see ' +
                     'the description at the top of this document.'
      },
      operations: {
        type: 'array',
        description: 'Every operation, with the console page it mirrors.',
        items: openObject('One operation.', {
          method: { type: 'string' },
          path: { type: 'string' },
          operationId: { type: 'string' },
          summary: { type: 'string' },
          mirrors: {
            type: 'string',
            description: 'The /admin control this operation is the API form of.'
          }
        })
      }
    }),

  Status: openObject(
    'What this service is and how much it has done since it started. The ' +
    'same object GET /admin?format=json answers.',
    {
      issuer: { type: 'string' },
      startedAt: { type: 'string', format: 'date-time' },
      uptimeMs: { type: 'integer' },
      calls: { type: 'integer', description: 'Endpoint calls served.' },
      tokensHeld: { type: 'integer' },
      tokensRevoked: { type: 'integer' },
      artifactsHeld: {
        type: 'integer',
        description: 'Assertions, tickets and credentials — everything that ' +
                     'is not a JWT.'
      },
      signOnSessions: {
        type: 'integer',
        description: 'Browser sign-on sessions really held, which is a ' +
                     'different count from the sessions implied by what has ' +
                     'been issued. GET /admin-api/metrics reports both.'
      },
      usersKnown: { type: 'integer' },
      usersAuthenticatedHere: { type: 'integer' },
      pages: {
        type: 'array', items: { type: 'string' },
        description: 'The console pages this API mirrors.'
      }
    }),

  Metrics: openObject(
    'Everything counted: endpoint calls by matched route and status class, ' +
    'tokens and artifacts by kind with how many of each are valid, expired, ' +
    'revoked and DPoP-bound, and sessions counted BOTH ways. The snapshot\'s ' +
    'own keys are at the top level rather than under a member of their own, ' +
    'because that is what GET /admin/metrics?format=json has always answered.',
    {
      startedAt: { type: 'integer',
                   description: 'Milliseconds since the epoch.' },
      startedAtIso: { type: 'string', format: 'date-time' },
      now: {
        type: 'integer',
        description: 'When this snapshot was taken, in milliseconds — so that ' +
                     'every age in it can be worked out without trusting the ' +
                     'caller\'s clock.'
      },
      uptimeMs: { type: 'integer' },
      claims: {
        type: 'array',
        description: 'The four custom claim sets and how many claims each ' +
                     'carries, so the thing most likely to explain a ' +
                     'surprising token is counted beside the tokens. ' +
                     '/admin-api/claims is where they are changed.',
        items: openObject('One set.', {})
      },
      calls: openObject('Endpoint calls, in total and per matched route.', {}),
      tokens: openObject('JWTs by typ, with the state of each.', {}),
      artifacts: openObject(
        'Assertions, tickets and credentials the same way.', {}),
      users: openObject('How many identities are known, and how many of them ' +
                        'authenticated here.', {}),
      sessions: openObject(
        'The sessions IMPLIED by what has been issued, per protocol ' +
        'family. Not the same thing as `signOnSessions` beside it, and ' +
        'the two disagree on purpose: a client-credentials token implies ' +
        'a session with no browser behind it, and a browser that has ' +
        'signed in but been issued nothing yet is a sign-on session that ' +
        'implies none.', {}),
      signOnSessions: openObject(
        'The browser sign-on sessions this process really holds — the map ' +
        'the OAuth 2.0 / OIDC login screen and WS-Federation share.', {
          held: { type: 'integer' },
          active: {
            type: 'integer',
            description: 'Held minus the expired ones. An expired session ' +
                         'stays in the map until something reads it, so it ' +
                         'is reported as held and not active rather than ' +
                         'omitted.'
          },
          rows: { type: 'array', items: openObject('One session.', {}) }
        })
    }),

  UserList: openObject(
    'Every identity this service knows, filtered and paged.',
    Object.assign({
      known: { type: 'integer', description: 'How many it knows in total.' },
      matched: { type: 'integer' },
      shown: { type: 'integer' },
      authenticatedHere: { type: 'integer' },
      filter: openObject(
        'What was asked for, with null where nothing was — so a reply can be ' +
        'read on its own without the request beside it.', {}),
      protocols: {
        type: 'array', items: { type: 'string' },
        description: 'Every protocol any known identity authenticated ' +
                     'through, read off the data rather than written down — ' +
                     'which is what the `protocol` filter takes.'
      },
      users: { type: 'array', items: openObject('One identity.', {}) }
    }, PAGING_PROPERTIES)),

  UserDetail: openObject(
    'One identity: the names it has been seen under, how it authenticated ' +
    'each time, every sign-on session it holds with the tokens issued ON ' +
    'each of them, the tokens that belong to no session, the artifacts ' +
    'issued to it, and its LDAP entry.',
    {
      known: {
        type: 'boolean',
        description: 'FALSE is an answer rather than an error, and is why ' +
                     'this is not a 404: the name may never have been seen, ' +
                     'or may have been forgotten to the registry cap. The ' +
                     'rest of the members are then absent.'
      },
      user: {
        description: 'The identity, or the name that was asked for when ' +
                     '`known` is false.'
      },
      sessions: { type: 'array', items: openObject('One session.', {}) },
      tokensOnEndedSessions: { type: 'array', items: ISSUED_RECORD },
      tokensWithNoSession: { type: 'array', items: ISSUED_RECORD },
      artifacts: { type: 'array', items: ISSUED_RECORD },
      ldap: {
        description: 'This person\'s directory entry, or null when no ' +
                     'directory is loaded in this process — which is a ' +
                     'different answer from an entry that is not there, and ' +
                     'that one is an object whose `found` is false.'
      }
    }),

  GroupList: openObject(
    'Every group in the embedded LDAP directory. A group is an entry under ' +
    'ou=groups OR one carrying a group objectClass wherever it sits, because ' +
    'the directory is schemaless and either rule alone would miss what a ' +
    'client can write.',
    Object.assign({
      directory: {
        type: 'boolean',
        description: 'Present and FALSE when no directory is loaded in this ' +
                     'process. The call still answers 200: the page exists ' +
                     'and the directory does not, and those are different ' +
                     'facts.'
      },
      groupCount: { type: 'integer' },
      matched: { type: 'integer' },
      shown: { type: 'integer' },
      membershipValues: { type: 'integer' },
      dangling: {
        type: 'integer',
        description: 'Membership values naming an entry this directory does ' +
                     'not hold. Not a defect: nothing here enforces ' +
                     'referential integrity, so deleting a user leaves its ' +
                     'DN in every group that listed it.'
      },
      filter: openObject('What was asked for; null where nothing was.', {}),
      baseDn: { type: 'string' },
      groupsDn: { type: 'string' },
      usersDn: { type: 'string' },
      port: { type: 'integer' },
      listening: {
        type: 'boolean',
        description: 'Whether the plain listener bound. It and LDAPS are ' +
                     'reported SEPARATELY because they bind independently, ' +
                     'and "389 is up and 636 is not" is the ordinary outcome ' +
                     'of a host run, which is not root.'
      },
      listenError: { type: 'string',
                     description: 'Why it did not bind, where it did not.' },
      ldapsPort: { type: 'integer' },
      ldapsListening: { type: 'boolean' },
      groups: { type: 'array', items: openObject('One group.', {}) }
    }, PAGING_PROPERTIES)),

  GroupDetail: openObject(
    'One group, under `group`, with the same directory facts the list carries ' +
    'around it — which is deliberate rather than untidy: a drill-down that ' +
    'did not say which directory it came from would be unreadable beside a ' +
    'second one.',
    {
      found: {
        type: 'boolean',
        description: 'FALSE is an answer rather than an error, and is why ' +
                     'this is not a 404: a client can delete a group, rename ' +
                     'it out of ou=groups or strip its objectClass between ' +
                     'one call and the next, and that is the interesting case.'
      },
      requested: { type: 'string', description: 'The DN that was asked for.' },
      group: openObject(
        'The entry: `attributes` (operational ones included — this is a dump ' +
        'rather than a search, so they are all here), `members` RESOLVED, ' +
        '`memberCount` and `danglingCount` reported apart, and `claimed` for ' +
        'entries whose own memberOf names this group while it does not list ' +
        'them back. Nesting is shown and NEVER expanded: a member that is ' +
        'itself a group is marked as one and nobody inside it is counted, ' +
        'because nothing in this service walks a group tree.',
        {
          dn: { type: 'string' },
          cn: { type: 'string' },
          rule: {
            type: 'string',
            description: 'WHICH RULE CAUGHT IT — under ou=groups, a group ' +
                         'objectClass wherever it sits, or both. Both rules ' +
                         'apply because the directory is schemaless and ' +
                         'either one alone would miss what a client can ' +
                         'write, so the row says which.'
          },
          origin: {
            type: 'string',
            description: 'WHERE IT CAME FROM — seeded at startup, or written ' +
                         'through the protocol since. A different fact from ' +
                         '`rule` beside it.'
          },
          createdAt: { type: 'string',
                       description: 'LDAP generalized time.' },
          modifiedAt: { type: 'string' },
          operational: {
            type: 'array', items: { type: 'string' },
            description: 'Which of its attributes are operational. A search ' +
                         'returns those only when asked for by name (RFC ' +
                         '4511 4.5.1.8); this is a dump, so they are all in ' +
                         '`attributes`.'
          },
          memberAttributes: {
            type: 'array', items: { type: 'string' },
            description: 'member, uniqueMember and memberUid. The first two ' +
                         'hold a DN and the third a bare name, which is why ' +
                         'they resolve differently — treating them alike is ' +
                         'how every posixGroup member gets reported as ' +
                         'dangling.'
          },
          memberCount: { type: 'integer' },
          presentCount: {
            type: 'integer',
            description: 'How many membership values name an entry this ' +
                         'directory actually holds. Reported apart from ' +
                         '`danglingCount` because a group whose seven ' +
                         'members resolve to five is this directory doing ' +
                         'what it says it does, and one combined number ' +
                         'would report that as seven with nothing wrong.'
          },
          danglingCount: { type: 'integer' },
          members: { type: 'array',
                     items: openObject('One member, resolved.', {}) },
          claimed: { type: 'array',
                     items: openObject('One entry claiming membership.', {}) },
          attributes: openObject('Every attribute value it holds.', {})
        }),
      baseDn: { type: 'string' },
      groupsDn: { type: 'string' },
      usersDn: { type: 'string' },
      groupCount: { type: 'integer' },
      listening: { type: 'boolean' },
      ldapsListening: { type: 'boolean' }
    }),

  IssuedList: openObject(
    'Everything issued and still remembered — every JWT, every SAML ' +
    'assertion and every Kerberos ticket — in one list, newest first. ' +
    'OID4VCI credentials are NOT in it; they are counted on ' +
    '/admin-api/metrics. Walk the whole list with `page` and `pages` rather ' +
    'than guessing where it ends.',
    Object.assign({
      held: { type: 'integer' },
      matched: { type: 'integer' },
      shown: { type: 'integer' },
      heldByFamily: openObject('How much of each family is held.', {}),
      filter: openObject('What was asked for; null where nothing was.', {}),
      families: {
        type: 'array',
        description: 'Every family and the kinds in it — what the `family` ' +
                     'and `kind` filters take.',
        items: openObject('One family.', {})
      },
      revocableKinds: {
        type: 'array', items: { type: 'string' },
        description: 'The only kinds `revoke-kind` accepts, and the only ' +
                     'ones any revocation here affects.'
      },
      revokedCount: { type: 'integer' },
      issued: { type: 'array', items: ISSUED_RECORD }
    }, PAGING_PROPERTIES)),

  Config: openObject(
    'Every setting this service has, grouped by the protocol it belongs to. ' +
    'The same table the /admin/config page renders and the same call it ' +
    'makes, so the console and this API cannot come to describe different ' +
    'sets of settings.',
    {
      configFile: {
        type: 'string',
        description: 'The CONFIG_FILE this process was started with, which is ' +
                     'the file to edit to make a change survive a restart. ' +
                     'Nothing here ever writes to it.'
      },
      settingCount: { type: 'integer' },
      editableCount: {
        type: 'integer',
        description: 'How many of them POST /config/set will take. The rest ' +
                     'are restart-only and say why in `restartReason`.'
      },
      overridden: {
        type: 'array', items: { type: 'string' },
        description: 'The keys with a runtime override in force. Empty on a ' +
                     'freshly started service, and emptied again by ' +
                     'POST /config/reset-all.'
      },
      groups: {
        type: 'array',
        description: 'In the order config.js declares them, which is the ' +
                     'order the console renders its sections.',
        items: openObject('One protocol\'s settings.', {
          group: { type: 'string' },
          settings: { type: 'array', items: CONFIG_SETTING }
        })
      }
    }),

  ClaimSets: openObject(
    'The four custom claim sets and the rules that govern them.',
    {
      reservedJwtClaims: {
        type: 'array', items: { type: 'string' },
        description: 'Claim names this service sets itself. Adding one is ' +
                     'REFUSED rather than allowed to override: every one of ' +
                     'them is load-bearing, and a settable `exp` would ' +
                     'produce tokens that fail to verify with nothing ' +
                     'pointing back at the operation that caused it.'
      },
      placeholders: {
        description: 'The ${...} substitutions a value may use.'
      },
      defaultSaml11Namespace: { type: 'string' },
      sets: {
        type: 'array',
        items: openObject('One set.', {
          id: {
            type: 'string',
            description: 'What the `set` field of every POST here takes.'
          },
          label: { type: 'string' },
          claims: { type: 'array', items: CLAIM_ENTRY }
        })
      }
    }),

  CredentialClaims: openObject(
    'Which claims a Verifiable Credential issued from now on carries, chosen ' +
    'from a catalogue of LDAP ATTRIBUTE TYPES rather than of claim names: ' +
    'the value of a claim is the value on that person\'s entry under ' +
    'ou=users, so an LDAP client and a wallet are shown one person.',
    {
      selected: { type: 'array', items: { type: 'string' } },
      defaults: { type: 'array', items: { type: 'string' } },
      ldpOmitted: {
        description: 'The selected attributes the ldp_vc format cannot ' +
                     'carry. It is signed over canonicalized JSON-LD, so ' +
                     'only terms the vendored context defines can appear; ' +
                     'the two JOSE-secured formats carry all of them.'
      },
      attributes: {
        type: 'array',
        description: 'The whole catalogue, each row saying which claim it ' +
                     'becomes and whether it is selected.',
        items: openObject('One attribute type.', {
          ldap: { type: 'string' },
          claim: { type: 'string' },
          label: { type: 'string' },
          schema: { type: 'string' },
          ldpTerm: { type: 'string' },
          selected: { type: 'boolean' }
        })
      },
      preview: openObject(
        'What one person\'s credential would carry if it were issued now. ' +
        'The values are invented from the username — deterministically, so ' +
        'one username is one invented person across restarts — and none of ' +
        'them is verified by anything.', {})
    }),

  VerifierRequest: openObject(
    'What the mock OID4VP Verifier at /oid4vp/verifier asks a wallet for, ' +
    'and in which credential format. It reaches the wire as the `dcql_query` ' +
    'of the next Authorization Request and is then what the presentation is ' +
    'checked against.',
    {
      requested: { type: 'array', items: { type: 'string' } },
      defaults: { type: 'array', items: { type: 'string' } },
      format: {
        type: 'string',
        description: 'The format a request that names none asks for.'
      },
      formats: {
        type: 'array',
        description: 'The three credential formats and what each implies.',
        items: openObject('One format.', {})
      },
      ldpOmitted: { description: 'Claims ldp_vc cannot carry.' },
      catalogue: {
        type: 'array',
        description: 'Every requestable claim, its DCQL path in the current ' +
                     'format, whether it is requested, and whether the ' +
                     'ISSUER currently mints it. The last two disagreeing is ' +
                     'a state to report rather than one to prevent — asking ' +
                     'for a claim nothing here issues is the only way to ' +
                     'exercise what a wallet does with a request it cannot ' +
                     'satisfy.',
        items: openObject('One claim.', {})
      },
      dcqlQuery: openObject(
        'The query this builds, from the function that builds the real ' +
        'one.', {})
    })
};

// The prose at the top of the document. It is long on purpose: the first thing
// anybody pointing a tool at this needs to know is that it is unprotected and
// that four of its operations change what the PROTOCOL endpoints do.
const DESCRIPTION = [
  'The management API of the mock STS: everything the /admin console ' +
  'shows and everything it can change, over JSON, with no browser.',

  '**Nothing here is protected, and that is a decision rather than an ' +
  'oversight.** This service checks no password anywhere — the username ' +
  'typed at its sign-in screen simply becomes the identity in every token ' +
  'it issues — so a console or an API with a credential on it would be the ' +
  'only authenticated surface in a service whose whole premise is that it ' +
  'authenticates nobody, and the only one a test would have to hold a ' +
  'secret for. What follows is worth stating plainly: anyone who can reach ' +
  'this port can revoke every token this service has issued and change ' +
  'what the next one contains. That is fine on a laptop or a compose ' +
  'network and is not fine on a public address, which was already true of ' +
  '/oauth2/token — it will mint a token for any username asked of it.',

  '**Four groups of operations change what the protocol endpoints do**, ' +
  'rather than only reporting on them. Revoking a token is the same ' +
  'revocation RFC 7009\'s /oauth2/revoke performs, so introspection, ' +
  'UserInfo and the refresh grant all honour it immediately. A custom ' +
  'claim reaches every access token, ID Token and SAML assertion issued ' +
  'from then on. The credential claim set reaches every Verifiable ' +
  'Credential AND sweeps the embedded LDAP directory. And the verifier ' +
  'request reaches the dcql_query of the next OID4VP Authorization ' +
  'Request. Nothing already issued ever changes — a signed document ' +
  'cannot be reached into.',

  '**Every operation here mirrors a control on the /admin console and ' +
  'calls the same function behind it.** They are not two implementations ' +
  'of one idea: admin_api.js holds no opinion about what a revocation ' +
  'means that admin.js does not. The `mirrors` line on each operation ' +
  'says which control it is.',

  'All state is in memory and dies with the process.'
].join('\n\n');

// One operation, as OpenAPI wants it. `entry` is a row of admin_api.js's route
// table and `action` is one of its actions, or null for a plain route.
function operationOf(entry, action) {
  const source = action || entry;
  const mirrors = source.mirrors || entry.mirrors || '';
  const parts = [source.description || ''];
  if (mirrors) {
    parts.push('\n\n**Mirrors** `' + mirrors + '` on the admin console.');
  }
  const operation = {
    operationId: source.operationId,
    summary: source.summary,
    description: parts.join(''),
    tags: [entry.tag],
    responses: {}
  };
  if (entry.parameters && entry.parameters.length) {
    operation.parameters = entry.parameters;
  }
  if (source.requestBody) {
    operation.requestBody = {
      required: !!source.requestBodyRequired,
      content: { 'application/json': { schema: source.requestBody } }
    };
  }
  if (action) {
    operation.responses['200'] = {
      description: source.responseDescription || 'The operation was applied.',
      content: { 'application/json': {
        schema: { $ref: '#/components/schemas/ActionResult' } } }
    };
    operation.responses['400'] = {
      description: 'The operation was refused; `errors` says why and nothing ' +
                   'changed.',
      content: { 'application/json': {
        schema: { $ref: '#/components/schemas/ActionResult' } } }
    };
    return operation;
  }
  operation.responses['200'] = {
    description: source.responseDescription || 'The current state.',
    content: {}
  };
  operation.responses['200'].content[source.responseType ||
                                     'application/json'] = {
    schema: source.responseSchema || { type: 'object' }
  };
  return operation;
}

// The document. `routes` is admin_api.js's table; an entry carrying `actions`
// becomes one operation per action, at the concrete URL each of them has —
// which is a real address even though express serves the six of them from one
// `:action` pattern.
function buildSpec(routes, options) {
  const opts = options || {};
  const paths = {};
  const tags = [];
  routes.forEach(function (entry) {
    if (tags.indexOf(entry.tag) < 0) {
      tags.push(entry.tag);
    }
    const method = entry.method.toLowerCase();
    if (!entry.actions) {
      paths[entry.path] = paths[entry.path] || {};
      paths[entry.path][method] = operationOf(entry, null);
      return;
    }
    entry.actions.forEach(function (action) {
      const path = entry.route.replace(':action', action.action);
      paths[path] = paths[path] || {};
      paths[path][method] = operationOf(entry, action);
    });
  });
  return {
    openapi: '3.1.0',
    info: {
      title: 'mock STS management API',
      version: opts.version || '0.0.0',
      description: DESCRIPTION,
      license: { name: 'MIT' }
    },
    servers: [{ url: opts.baseUrl || '/', description: 'This service.' }],
    tags: tags.map(function (name) {
      return { name: name, description: TAG_DESCRIPTIONS[name] || '' };
    }),
    // Empty rather than absent, and it is a statement rather than an omission:
    // an empty security array is how OpenAPI says "this operation needs no
    // credential", which is exactly true of every operation here.
    security: [],
    paths: paths,
    components: { schemas: SCHEMAS }
  };
}

const TAG_DESCRIPTIONS = {
  Service: 'What this API is, its document, and the explorer that calls it.',
  Metrics: 'What this service has done since it started.',
  Users: 'Who it has authenticated, and what each of them holds.',
  Groups: 'The embedded LDAP directory\'s groups. A group here GRANTS ' +
          'NOTHING: no token, assertion, ticket or PAC carries one and no ' +
          'endpoint reads one.',
  Tokens: 'What has been issued, and the revocation of the three kinds that ' +
          'can be revoked.',
  'Custom claims': 'What to add to every access token, ID Token and SAML ' +
                   'assertion issued from now on.',
  'Credential claims': 'What an issued Verifiable Credential carries.',
  'Verifier request': 'What the mock OID4VP Verifier asks a wallet for.'
};

module.exports = {
  SCHEMAS: SCHEMAS,
  buildSpec: buildSpec
};
