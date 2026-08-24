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

// The same members as an OBJECT, for a reply that carries more than one list and
// therefore cannot put them at the top level. Built from PAGING_PROPERTIES above
// rather than written out again, because two hand-kept copies of five member
// names is one copy that will eventually be missing `lastRow`.
//
// `total` is here and not up there for a reason worth stating: at the top level
// the number is called `matched`, which is the count AFTER a filter. A
// drill-down's lists have no filter, so the honest name for the number is the
// plain one.
function pagingObject(what) {
  return {
    type: 'object',
    description: 'Where `' + what + '` came from in the whole list: the page, ' +
                 'how many there are, and the 1-based row numbers this page ' +
                 'covers. Same member names the flat lists carry at the top ' +
                 'level, one level down.',
    properties: Object.assign({
      total: { type: 'integer',
               description: 'How many there are in all, which is what to page ' +
                            'through rather than the length of this array.' }
    }, PAGING_PROPERTIES),
    additionalProperties: false
  };
}

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
    // Present on an `int` setting whose row narrows it, and absent everywhere
    // else — the same way `enumValues` is present on an enum and nowhere else.
    // They are DOCUMENTED rather than left implicit because a client rendering
    // an input for a setting has no other way to learn what will be refused,
    // and the four token lifetimes are the settings somebody actually types a
    // number into.
    min: { type: 'integer',
           description: 'The lowest value POST /config/set will take, on an ' +
                        'int setting that declares one.' },
    max: { type: 'integer',
           description: 'The highest value it will take.' },
    step: { type: 'integer',
            description: 'The value must be a MULTIPLE of this, counted from ' +
                         '`min`. The four token lifetimes use 30: they exist ' +
                         'to be set short and watched, and below half a ' +
                         'minute a token expires between the response being ' +
                         'written and the client reading it.' },
    value: { description: 'The effective value, coerced to its type: a number ' +
                          'for int/port, a boolean for bool, an array of ' +
                          'strings for csv.' },
    text: { type: 'string',
            description: 'The same value on one line — what the console shows ' +
                         'in its input and what the environment variable ' +
                         'would carry.' },
    source: {
      type: 'string',
      enum: ['override', 'env', 'env-legacy', 'appconfig', 'defaults', 'default'],
      description: 'Where the effective value came from, highest first: a ' +
                   'runtime override set through this API or the console; the ' +
                   'setting\'s own environment variable; the LEGACY variable ' +
                   'named in `legacyEnv` (STS_ISSUER still feeds the three ' +
                   'issuers carved out of it); the appconfig file CONFIG_FILE ' +
                   'names; `env/defaults.js`, the DEFAULT appconfig file that ' +
                   'one is unioned on top of. `default` is the sixth and is ' +
                   'reachable only for the three DERIVED settings ' +
                   '(`global.https`, `oid4vp.walletUrl`, ' +
                   '`krb5.serviceDomains`), whose value is a function of a ' +
                   'neighbouring setting rather than a literal in any file: ' +
                   'for every other setting, no value in either appconfig ' +
                   'file and no environment variable stops this service from ' +
                   'STARTING, so there is nothing left to fall back to.'
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
    default: { description: 'The built-in default — the `dflt` column of ' +
                            'config.js\'s table, which `env/defaults.js` is ' +
                            'GENERATED from and which the three shipped ' +
                            'appconfig files were seeded with. It is what the ' +
                            'value WOULD be with nothing set anywhere, and is ' +
                            'no longer a source in its own right: see ' +
                            '`source`.' },
    overridden: { type: 'boolean',
                  description: 'Whether a runtime override is in force. Equal ' +
                               'to `source === "override"`, and reported ' +
                               'separately so a caller can filter without ' +
                               'matching a string.' }
  });

// ---------------------------------------------------------------------------
// THE PROPERTIES BOTH CLAIM-SET REPLIES CARRY.
//
// GET /admin-api/claims answers for the two JWT sets and GET
// /admin-api/saml-attributes for the two SAML ones — two console pages onto
// one store since 2026-08-24 — and everything except ONE property each is the
// same shape answered twice. So the shape is written once and each schema adds
// what is genuinely its own: `reservedJwtClaims` for the tokens, because that
// list is enforced for `kind === 'jwt'` alone, and `defaultSaml11Namespace`
// for the assertions, because nothing else has one.
//
// Copied instead, this would be the pair of schemas that disagree about
// `attributeCatalogue` within a month — and the parent project's
// tests/admin_api.js checks each documented property against a LIVE reply, so
// the disagreement would surface as a test failure naming a property rather
// than as anything pointing here.
// ---------------------------------------------------------------------------
const CLAIM_SET_PROPS = {
      placeholders: {
        description: 'The ${...} substitutions a value may use.'
      },
      precedence: {
        type: 'string',
        description: 'Stated in the reply and not only in this document, ' +
                     'because it only shows up when both halves of a set ' +
                     'name one claim: the typed one wins.'
      },
      attributeCatalogue: {
        type: 'array',
        description: 'Every LDAP attribute type a set may carry, and which ' +
                     'of the four currently carries it. It is the same ' +
                     'catalogue the credential claims choose from — one list ' +
                     'of spellings, because two would eventually disagree ' +
                     'about what `schacDateOfBirth` is called.',
        items: openObject('One attribute type.', {
          ldap: {
            type: 'string',
            description: 'Spelled the way its schema document spells it, ' +
                         'which is what the `attributes` field of a POST takes.'
          },
          claim: {
            type: 'string',
            description: 'The claim it becomes. A dot means NESTED in a JWT ' +
                         '(`address.locality` is a member of an `address` ' +
                         'object) and is the attribute\'s literal name in an ' +
                         'assertion, where the content model cannot nest.'
          },
          label: { type: 'string' },
          schema: {
            type: 'string',
            description: 'Where the attribute type is defined. Three of them ' +
                         'are not RFC 4519/4524/2798: there is no standard ' +
                         'type for a birthdate or a nationality, so the ' +
                         'SCHAC schema\'s names are borrowed rather than ' +
                         'invented.'
          },
          sets: openObject(
            'Which of the FOUR sets carries it, keyed by set id — all ' +
            'four, not only the two this reply configures: the ' +
            'catalogue is one list and a per-page view of it would ' +
            'answer "which sets carry mail" with half the truth.', {})
        })
      },
      groups: openObject(
        'The groups claim. The one thing on this page that is not chosen per ' +
        'set: with groups.claim on, ALL FOUR carry a claim naming the ' +
        'directory groups the subject is a member of, and somebody in no ' +
        'group gets no claim at all rather than an empty list. There is no ' +
        'operation beside this: its four settings are config.js\'s, so POST ' +
        '/admin-api/config/set is the door and a second one would be a ' +
        'second store for one setting.',
        {
          enabled: { type: 'boolean', description: 'groups.claim.' },
          loaded: {
            type: 'boolean',
            description: 'Whether the embedded directory is loaded in this ' +
                         'process. False means there are no groups to read ' +
                         'and nothing else is affected.'
          },
          claim: {
            type: 'string',
            description: 'What the claim is called (groups.claimName): the ' +
                         'JWT member name and the SAML Attribute name. A ' +
                         'name this service sets itself is refused at ' +
                         'issuance and `problem` says so.'
          },
          valueForm: {
            type: 'string',
            description: '`cn` or `dn` (groups.claimValue) — whether each ' +
                         'value is the group\'s common name or its whole DN. ' +
                         'Both are what somebody\'s real identity provider ' +
                         'does, and a client that has only parsed one has ' +
                         'never run the other path.'
          },
          memberOfCounts: {
            type: 'boolean',
            description: 'groups.claimFromMemberOf — whether a group named ' +
                         'by the PERSON\'s own memberOf counts when the group ' +
                         'entry does not list them back. Nothing here ' +
                         'maintains memberOf, so that disagreement is ' +
                         'reachable in one operation and this is which side ' +
                         'a token believes.'
          },
          sets: {
            type: 'array', items: { type: 'string' },
            description: 'The sets that carry it, which is all four.'
          },
          problem: {
            type: 'string',
            description: 'Why a claim that is switched ON is not arriving. ' +
                         'Empty when there is nothing wrong.'
          },
          grants: { type: 'string' },
          precedence: { type: 'string' },
          settings: { type: 'array', items: { type: 'string' } },
          preview: openObject(
            'What the claim would carry for the previewed person, built by ' +
            'the function the ISSUANCE path calls so it cannot disagree with ' +
            'the token.',
            {
              user: { type: 'string' },
              key: { type: 'string' },
              dn: {
                type: 'string',
                description: 'Where this person\'s entry is, or would be. ' +
                             'Reported either way: a group can list a DN ' +
                             'nothing is stored at, and that is still the ' +
                             'group saying so.'
              },
              entryFound: { type: 'boolean' },
              reason: {
                type: 'string',
                description: 'Why the claim is empty, when it is. Usually ' +
                             'the ordinary answer — this person is in no ' +
                             'group — rather than a fault.'
              },
              values: {
                type: 'array', items: { type: 'string' },
                description: 'Exactly what the claim would carry. Absent ' +
                             'from the token entirely when this is empty.'
              },
              groups: {
                type: 'array',
                description: 'Every group naming this person, and how.',
                items: openObject('One group.', {
                  dn: { type: 'string' },
                  cn: { type: 'string' },
                  rule: {
                    type: 'string',
                    description: 'What made it a group: `placement` (under ' +
                                 'ou=groups), `objectClass`, or `both`.'
                  },
                  via: {
                    type: 'array', items: { type: 'string' },
                    description: 'The group\'s own membership attributes ' +
                                 'that name this person — member, ' +
                                 'uniqueMember, memberUid. Empty when only ' +
                                 'memberOf found it.'
                  },
                  viaMemberOf: {
                    type: 'boolean',
                    description: 'Whether the PERSON\'s own memberOf names ' +
                                 'this group. Counted only when ' +
                                 'memberOfCounts is true.'
                  }
                })
              }
            })
        }),

      preview: openObject(
        'One person\'s value for every attribute in the catalogue, selected ' +
        'or not, so a caller can see what selecting one WOULD produce.',
        {
          user: { type: 'string' },
          entryFound: {
            type: 'boolean',
            description: 'Whether the directory holds this person at all. ' +
                         'False means every value below was generated from ' +
                         'the username — the same invented person every ' +
                         'time — and that is a different answer from "the ' +
                         'entry says so", which the values alone cannot tell ' +
                         'you.'
          },
          byLdap: openObject(
            'Keyed by the LOWER-CASED attribute name, because that is what ' +
            'the store holds. Each value carries the claim, the value and ' +
            'the source it came from.', {})
        }),
      sets: {
        type: 'array',
        items: openObject('One set.', {
          id: {
            type: 'string',
            description: 'What the `set` field of every POST here takes.'
          },
          label: { type: 'string' },
          claims: { type: 'array', items: CLAIM_ENTRY },
          attributes: {
            type: 'array', items: { type: 'string' },
            description: 'The LDAP attribute types this set carries, ' +
                         'canonically spelled and in CATALOGUE order rather ' +
                         'than in the order they were chosen — the order ' +
                         'reaches the token, and a list that reordered ' +
                         'itself would look like a different token to ' +
                         'anything diffing them. Empty on a fresh start, in ' +
                         'all four sets: this changes what every client ' +
                         'receives, so it does nothing until asked.'
          },
          attributeClaims: openObject(
            'What those attributes would put in this set right now for the ' +
            'previewed person, nested as the token would carry it. Built by ' +
            'the function the ISSUANCE path calls, so it cannot disagree ' +
            'with the token.', {}),
          attributeReport: {
            type: 'array',
            description: 'The same, flat, with where each value came from.',
            items: openObject('One claim.', {
              ldap: { type: 'string' },
              claim: { type: 'string' },
              value: { type: 'string' },
              source: {
                type: 'string',
                description: '`directory` when the entry carries it, ' +
                             '`generated` when it was invented from the ' +
                             'username.'
              }
            })
          }
        })
      }
};

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
      // EVERY ARRAY HERE IS ONE PAGE, not the whole list — the same thing
      // `users` is on the list beside it — and every one is answered by the
      // `*Paging` object under it. Five lists on one reply is why they are
      // paged separately: `sessionsPage`, `endedPage`, `sessionlessPage` and
      // `artifactsPage` each move one of them, and `per` is shared.
      sessions: {
        type: 'array',
        description: 'One page of this identity\'s sign-on sessions. Each ' +
                     'carries the tokens issued ON it — itself one page, ' +
                     'moved by `session-{id}Page` and answered by that ' +
                     'session\'s own `tokensPaging`, because there is one ' +
                     'such list per session and no top-level place to put ' +
                     'five of them that would still say which was which.',
        items: openObject('One session, with `tokens` and `tokensPaging`.', {})
      },
      sessionsPaging: pagingObject('sessions'),
      tokensOnEndedSessions: { type: 'array', items: ISSUED_RECORD },
      tokensOnEndedSessionsPaging: pagingObject('tokensOnEndedSessions'),
      tokensWithNoSession: { type: 'array', items: ISSUED_RECORD },
      tokensWithNoSessionPaging: pagingObject('tokensWithNoSession'),
      artifacts: { type: 'array', items: ISSUED_RECORD },
      artifactsPaging: pagingObject('artifacts'),
      ldap: {
        description: 'This person\'s directory entry, or null when no ' +
                     'directory is loaded in this process — which is a ' +
                     'different answer from an entry that is not there, and ' +
                     'that one is an object whose `found` is false.'
      }
    }),

  AuthorizationServerList: openObject(
    'Every authorization server profile this process publishes a discovery ' +
    'document for. The path component the two discovery shapes carry selects ' +
    'one; a path nobody has configured publishes the document this service ' +
    'always published. With ?profile= the reply is ONE of them instead.',
    Object.assign({
      profileCount: { type: 'integer' },
      shown: { type: 'integer', description: 'How many are on this page.' },
      members: {
        type: 'array',
        description: 'The catalogue of metadata members this service has ' +
                     'something to say about, each with why a client cares. ' +
                     'HELP RATHER THAN SCHEMA: a member outside it is accepted ' +
                     'and published just the same, which is the difference ' +
                     'between this resource and the applications registry.',
        items: openObject('One member: `name`, `group`, `kind`, `what`.', {})
      },
      authorizationServers: {
        type: 'array',
        description: 'One page of them, by id.',
        items: openObject(
          'One profile: `id`, `label`, `description`, `overrides` (member to ' +
          'published value), `removed` (members this document omits), ' +
          '`changedAt`, `urls` (the two it is served at) and `drift`.', {})
      },
      found: {
        type: 'boolean',
        description: 'On the ?profile= reply only. FALSE for a profile that is ' +
                     'not configured — whose discovery URLs still answer.'
      },
      drift: {
        type: 'array',
        description: 'THE MEMBERS OF THIS DOCUMENT THAT DO NOT DESCRIBE THIS ' +
                     'SERVICE. Each carries `member`, `published`, `actual`, ' +
                     'and `kind` — `differs` where this service would publish ' +
                     'something else, `invented` where it publishes nothing of ' +
                     'that name, `removed` where the profile hides something ' +
                     'real. A profile that lies is often the point; one that ' +
                     'lied without saying so would be a trap.',
        items: openObject('One disagreement.', {})
      }
    }, PAGING_PROPERTIES)),

  ApplicationList: openObject(
    'Every application this service has been asked about — an OAuth client, an ' +
    'OpenID Connect relying party, a SAML 2.0 or 1.1 service provider, a ' +
    'WS-Federation application, a WS-Trust relying party, the OpenID4VP ' +
    'verifier, a Kerberos service — one per unique identifier. THE ENTRIES ARE ' +
    'THE REGISTRY: they live under ou=applications in the embedded LDAP ' +
    'directory, nothing caches them, and the RFC 7591 client registrations are ' +
    'those same entries. With ?application= the reply is ONE of them instead, ' +
    'shaped as the second block of properties below.',
    Object.assign({
      applicationCount: { type: 'integer',
                          description: 'How many the registry holds in all.' },
      matched: { type: 'integer', description: 'How many the filter matched.' },
      shown: { type: 'integer', description: 'How many are on this page.' },
      registered: {
        type: 'integer',
        description: 'How many went through POST /oauth2/register. The rest ' +
                     'are client_ids and realms that simply turned up, which ' +
                     'RFC 9700 mode treats as PUBLIC and judges against the ' +
                     'oauth2.redirectUris setting rather than against a ' +
                     'registration.'
      },
      filter: openObject('What was asked for; null where nothing was.', {}),
      container: {
        type: 'string',
        description: 'The DN these entries live under, or null when no ' +
                     'directory is loaded in this process — in which case ' +
                     'there is no registry at all, because this module keeps ' +
                     'no store of its own on purpose.'
      },
      max: { type: 'integer',
             description: 'How many entries the container will hold ' +
                          '(applications.max). Past it a new application is ' +
                          'REFUSED and warned about rather than an old one ' +
                          'evicted: a directory that quietly dropped entries ' +
                          'would be the worst possible source of truth.' },
      kinds: {
        type: 'array',
        description: 'The eight kinds an application can be, each with what ' +
                     'it means. NOT disjoint — a record commonly carries two ' +
                     '— so these do not partition the list.',
        items: openObject('One kind: `kind`, `label`, `what`.', {})
      },
      applications: {
        type: 'array',
        description: 'One page of them, newest activity first.',
        items: openObject(
          'One application: `identifier`, `dn` (WHERE THE ENTRY IS — the key it ' +
          'is stored under, and what an ldapsearch or ldapmodify is aimed at; ' +
          'null only where no directory is loaded in this process, in which ' +
          'case there is no registry at all), `dnLabel` (the RDN, which is a ' +
          'digest of the identifier when that is too long to read), `name`, ' +
          '`kinds`, `protocols`, `registered`, `firstSeen`, `lastSeen`, ' +
          '`authentications`, `sessions`, `users`, `descriptions`, `origin`, ' +
          '`createdAt` and `modifiedAt` (the ENTRY\'s own, which an ldapmodify ' +
          'moves and firstSeen/lastSeen do not), `operational` (which of the ' +
          'attributes a SEARCH would have withheld unless asked for by name, ' +
          'RFC 4511 section 4.5.1.8 — this is a dump of the store rather than a ' +
          'search, so it carries them always), `attributes` — EVERY attribute ' +
          'the entry carries, canonically spelled, the operational ones and ' +
          '`entryDN` included — and `fields`, which is the narrower question of ' +
          'what this registry has recorded about it.',
          {})
      },
      found: {
        type: 'boolean',
        description: 'On the ?application= reply only. FALSE means this ' +
                     'service has never ACCEPTED that identifier, which is ' +
                     'not the same as having refused it.'
      },
      attributesShown: {
        type: 'array',
        description: 'On the ?application= reply only: one page of the ' +
                     'entry\'s attributes, each `{name, values, operational}`. ' +
                     'EVERY attribute the entry carries, not the ' +
                     'protocol-specific half — objectClass, cn, appIdentifier, ' +
                     'both timestamps and `entryDN` are among them, and so is ' +
                     'anything an ldapmodify wrote by hand, because this ' +
                     'directory is schemaless.',
        items: openObject('One attribute of the directory entry.', {})
      },
      attributesPaging: pagingObject('attributesShown')
    }, PAGING_PROPERTIES, {
      matched: { type: 'integer', description: 'How many the filter matched.' }
    })),

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
          members: {
            type: 'array',
            description: 'ONE PAGE of them, moved by `membersPage` and ' +
                         'answered by `membersPaging` beside `group`. The ' +
                         'three counts above are of the whole list.',
            items: openObject('One member, resolved.', {})
          },
          claimed: {
            type: 'array',
            description: 'One page, moved by `claimedPage`.',
            items: openObject('One entry claiming membership.', {})
          },
          attributes: openObject('Every attribute value it holds.', {})
        }),
      // Beside `group` rather than inside it, because they describe THIS REPLY
      // and not the directory entry — whose own memberCount, presentCount and
      // danglingCount are untouched next to them and stay counts of the whole
      // list.
      membersPaging: pagingObject('group.members'),
      claimedPaging: pagingObject('group.claimed'),
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
      defaultsFile: {
        type: 'string',
        description: 'The DEFAULT appconfig file, which `configFile` is ' +
                     'unioned on top of key by key with the operator\'s value ' +
                     'winning. It carries a default for every setting, which ' +
                     'is what lets `configFile` be as small as its author ' +
                     'likes while a setting with no value ANYWHERE — in ' +
                     'either file and in no environment variable — stops this ' +
                     'service from starting. A setting whose `source` is ' +
                     '`defaults` came from here.'
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

  TokenLifetimes: openObject(
    'How long an access token, an ID Token and a refresh token issued here ' +
    'are good for, the clock skew applied when one is read back, and what ' +
    'has already been issued under them. Four of the settings GET /config ' +
    'returns, under a name that promises four.',
    {
      lifetimes: openObject(
        'The four effective values in seconds, for a caller that wants the ' +
        'number rather than the provenance.',
        {
          accessTokenTtlS: { type: 'integer' },
          idTokenTtlS: { type: 'integer' },
          refreshTokenTtlS: { type: 'integer' },
          clockSkewS: {
            type: 'integer',
            description: 'The allowance applied to `exp` and `nbf` wherever ' +
                         'this service reads back a token it signed — ' +
                         'introspection, UserInfo, the refresh grant, token ' +
                         'exchange, the DPoP-bound access token check, and ' +
                         'the state reported here and on the console. It ' +
                         'never changes what goes INTO a token, and it is a ' +
                         'different setting from oauth2.clientAssertionSkewS, ' +
                         'which is about a CLIENT\'s clock.'
          }
        }),
      settings: {
        type: 'array',
        description: 'The same four as full configuration rows — bounds, ' +
                     'source, default and prose — in the shape GET /config ' +
                     'uses, so a client renders them with one piece of code.',
        items: CONFIG_SETTING
      },
      tokens: openObject(
        'What has already been issued, counted against the same clock the ' +
        'endpoints use: `clockSkewS` is applied here too, so a token counted ' +
        'expired is one POST /oauth2/introspect will report inactive. ' +
        'CHANGING A LIFETIME DOES NOT MOVE THESE — a lifetime is stamped ' +
        'into a token as its exp claim when it is signed.',
        {
          held: { type: 'integer' },
          forgotten: { type: 'integer' },
          cap: { type: 'integer' },
          revoked: { type: 'integer' },
          byKind: {
            type: 'array',
            description: 'One row per token kind, which is what tells the ' +
                         'three lifetimes apart in the counts.',
            items: openObject('One kind.', {
              kind: { type: 'string' },
              issued: { type: 'integer' },
              valid: { type: 'integer' },
              expired: { type: 'integer' },
              revoked: { type: 'integer' },
              notYetValid: { type: 'integer' },
              noExpiry: { type: 'integer' },
              bound: { type: 'integer' }
            })
          }
        }),
      now: {
        type: 'integer',
        description: 'This service\'s clock, in milliseconds, as the counts ' +
                     'above were taken against it.'
      }
    }),

  ClaimSets: openObject(
    'The two JWT claim sets — the OAuth 2.0 access token and the OIDC ID ' +
    'Token — and the rules that govern them. The two SAML sets are at GET ' +
    '/admin-api/saml-attributes; one store answers both.',
    Object.assign({
      reservedJwtClaims: {
        type: 'array', items: { type: 'string' },
        description: 'Claim names this service sets itself. Adding one is ' +
                     'REFUSED rather than allowed to override: every one of ' +
                     'them is load-bearing, and a settable `exp` would ' +
                     'produce tokens that fail to verify with nothing ' +
                     'pointing back at the operation that caused it.'
      },
    }, CLAIM_SET_PROPS)),

  SamlAttributeSets: openObject(
    'The two SAML attribute sets — SAML 2.0 and SAML 1.1 (WS-Federation) — ' +
    'and the rules that govern them. Everything here is the shape GET ' +
    '/admin-api/claims answers for the two JWT sets, minus the reserved ' +
    'claim names, which are a JWT rule and are not enforced for an ' +
    'assertion attribute, plus the one rule that is this family\'s.',
    Object.assign({
      defaultSaml11Namespace: {
        type: 'string',
        description: 'The AttributeNamespace a SAML 1.1 attribute gets when ' +
                     'the call does not name one — the WS-Federation claim ' +
                     'namespace every relying party already reads, so an ' +
                     'attribute added with a name and a value alone arrives ' +
                     'somewhere useful instead of in a namespace nothing ' +
                     'looks in. SAML 2.0 has no equivalent: NameFormat is ' +
                     'optional there and is left off unless it is given.'
      }
    }, CLAIM_SET_PROPS)),

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
    }),

  Scim: openObject(
    'The SCIM 2.0 provisioning surface: what it has been asked to do, what it ' +
    'will and will not do, and which LDAP attribute each SCIM member is. It ' +
    'writes into the SAME directory /admin-api/users and /admin-api/groups ' +
    'report, with no store of its own — so a POST to /scim/v2/Users and an ' +
    'ldapadd create the same entry.',
    {
      installed: {
        type: 'boolean',
        description: 'Whether the SCIM module is loaded in this process at ' +
                     'all. A DIFFERENT question from `enabled`: a process ' +
                     'that never required scim.js has no /scim routes, where ' +
                     'one with scim.enabled false has routes that answer 501. ' +
                     'Reporting both as "off" would send a caller to the ' +
                     'wrong setting.'
      },
      enabled: {
        type: 'boolean',
        description: 'The `scim.enabled` setting. When false, every endpoint ' +
                     'under /scim/v2 answers 501 — the routes stay registered, ' +
                     'because "turned off" and "wrong URL" are different ' +
                     'answers to a client.'
      },
      baseUrl: {
        type: 'string',
        description: 'Where the endpoints are, as the request reached this ' +
                     'service — so a document fetched through a proxy or a ' +
                     'published port names an address the caller can use.'
      },
      specifications: { type: 'array', items: { type: 'string' } },
      authentication: openObject(
        'WHO MAY CALL THESE ENDPOINTS. The SCIM surface is the one place in ' +
        'this service that refuses a caller who presents nothing, because it ' +
        'creates and deletes accounts. All six schemes RFC 7644 section 2 ' +
        'names are offered and every one of them is permissive — it is a ' +
        'turnstile rather than a lock. Null when the SCIM module is not ' +
        'loaded, which is not the same as every scheme being off.',
        {
          required: {
            type: 'boolean',
            description: 'The `scim.authRequired` setting. When false these ' +
                         'endpoints answer an unauthenticated request, which ' +
                         'is the behaviour they had before authentication ' +
                         'existed and stays reachable on purpose. A ' +
                         'credential that IS presented is checked either way.'
          },
          discoveryOpen: {
            type: 'boolean',
            description: 'Whether /ServiceProviderConfig, /ResourceTypes and ' +
                         '/Schemas answer without a credential. True by ' +
                         'default: a client has to be able to read which ' +
                         'schemes exist before it can use one.'
          },
          realm: { type: 'string',
                   description: 'The protection space in every challenge — ' +
                                'and a value Digest hashes and HOBA signs ' +
                                'OVER, so changing it invalidates every ' +
                                'credential computed against the old one.' },
          scopes: openObject(
            'The two OAuth scopes, which are the first scope requirement ' +
            'anywhere in this service. Neither implies the other.',
            { read: { type: 'string' }, write: { type: 'string' } }),
          digestAlgorithms: {
            type: 'array', items: { type: 'string' },
            description: 'The Digest algorithms this process can compute, ' +
                         'strongest first — checked against the openssl this ' +
                         'build actually has rather than assumed.'
          },
          hobaRegistration: {
            type: 'string',
            description: 'Where a HOBA public key is registered (RFC 7486 ' +
                         'section 7). Unauthenticated, because it is how a ' +
                         'caller GETS a credential.'
          },
          schemes: {
            type: 'array',
            description: 'Every scheme, including the ones turned off — the ' +
                         'same table that builds the WWW-Authenticate ' +
                         'challenge and the ServiceProviderConfig, so this ' +
                         'cannot describe a scheme a client would not be ' +
                         'offered.',
            items: openObject('One scheme.', {
              id: { type: 'string' },
              type: { type: 'string',
                      description: 'The ServiceProviderConfig `type`. Three ' +
                                   'of the seven have no canonical value in ' +
                                   'RFC 7643 section 5 and carry an honest ' +
                                   'one of their own; `canonical` says which.' },
              canonical: { type: 'boolean' },
              name: { type: 'string' },
              enabled: { type: 'boolean' },
              setting: { type: 'string' },
              primary: { type: 'boolean' },
              scoped: { type: 'boolean',
                        description: 'Whether it carries OAuth scopes. Only ' +
                                     'the two token schemes do; every other ' +
                                     'accepted credential may do both.' },
              recorded: { type: 'boolean',
                          description: 'Whether accepting it reaches ' +
                                       'recordAuthentication(). True for the ' +
                                       'three that present a credential per ' +
                                       'request; the others continue an ' +
                                       'authentication recorded elsewhere.' },
              challenged: { type: 'boolean' },
              spec: { type: 'string' },
              specUri: { type: 'string' },
              description: { type: 'string' }
            })
          },
          policy: {
            type: 'array', items: { type: 'string' },
            description: 'The access control policy RFC 7644 section 2 ' +
                         'requires a provider to be able to map an ' +
                         'authenticated client to. It is two lines, which is ' +
                         'the honest length for a mock.'
          }
        }),
      store: openObject(
        'The directory it provisions into, and how full it is. The cap is ' +
        '`ldap.maxEntries`: SCIM has no cap of its own because it has no ' +
        'store of its own.', {}),
      identifiers: openObject(
        'What a SCIM `id` is here — the entry\'s DN — and why. Includes the ' +
        'cost, which is that an LDAP rename gives the same person a new id.',
        {}),
      endpoints: {
        type: 'array',
        description: 'Every SCIM endpoint with what it does.',
        items: openObject('One endpoint.', {})
      },
      doesNotDo: {
        type: 'array',
        items: { type: 'string' },
        description: 'The sentences worth reading before pointing a ' +
                     'provisioning client at this. It authenticates and ' +
                     'checks almost nothing; a scope grants only here and ' +
                     'nothing else reads one; `active: false` deactivates ' +
                     'nobody; there is no ETag and no changePassword; a ' +
                     'member naming nothing is accepted.'
      },
      reachableNegatives: {
        type: 'array',
        description: 'What to do to get each error out of it. A permissive ' +
                     'server is hard to write error handling against, so ' +
                     'these exist on purpose — the same device as the ' +
                     'reserved password `invalid` elsewhere in this service.',
        items: openObject('One way to make it fail.', {})
      },
      mapping: openObject(
        'Which LDAP attribute each SCIM member is, for both resource types. ' +
        'The attribute spellings are the same catalogue the credential and ' +
        'token claim pages read, checked against it at startup rather than ' +
        'copied.',
        {
          user: {
            type: 'array',
            items: openObject('One User member.', {
              scim: { type: 'string' },
              ldap: { type: 'string' },
              kind: { type: 'string' },
              readOnly: { type: 'boolean' },
              required: { type: 'boolean' },
              extension: { type: 'boolean' },
              schema: { type: 'string' },
              note: { type: 'string' }
            })
          },
          group: {
            type: 'array',
            items: openObject('One Group member.', {})
          }
        }),
      counters: openObject(
        'What has been asked of it. Every operation and every resource type ' +
        'is listed INCLUDING the ones at zero, because "does this support ' +
        'PATCH" is answered by omission otherwise. The bulk count ' +
        'deliberately does not tally with the rest: one Bulk carrying five ' +
        'creates is one bulk AND five creates, because each is performed.',
        {
          total: { type: 'integer' },
          ok: { type: 'integer' },
          failed: { type: 'integer' },
          firstAt: { type: 'integer' },
          lastAt: { type: 'integer' },
          operations: {
            type: 'array',
            items: openObject('One operation, with its count.', {
              operation: { type: 'string' },
              label: { type: 'string' },
              method: { type: 'string' },
              what: { type: 'string' },
              count: { type: 'integer' }
            })
          },
          resourceTypes: {
            type: 'array',
            items: openObject('One resource type, with its count.', {
              resourceType: { type: 'string' },
              count: { type: 'integer' }
            })
          },
          byStatus: openObject('HTTP status code to count.', {}),
          byScimType: openObject(
            'RFC 7644 section 3.12 `scimType` to count. `(none)` is a ' +
            'refusal that carried no such code — a 404 has none — counted ' +
            'rather than dropped so that the failure tables agree.', {})
        })
    }),

  AuditEvent: openObject(
    'One thing that happened, with the facts of it and no credential of any ' +
    'kind. Written out rather than left open because a caller filtering or ' +
    'alerting on this list needs a name for every field.',
    {
      seq: {
        type: 'integer',
        description: 'Monotonic and NEVER REUSED, including across a drop. ' +
                     'This is the stable name for an event and the thing to ' +
                     'walk the log by: a row number would silently mean a ' +
                     'different event as soon as the cap discarded anything.'
      },
      at: { type: 'integer',
            description: 'When it happened, in milliseconds since the epoch.' },
      category: { type: 'string',
                  enum: ['authentication', 'session', 'directory', 'admin',
                         'api', 'protocol'],
                  description: 'Derived from `action` and never set ' +
                               'independently, so the two cannot disagree.' },
      action: { type: 'string',
                description: 'What happened, from a fixed vocabulary the ' +
                             'list\'s `actions` member enumerates.' },
      outcome: { type: 'string', enum: ['success', 'refused', 'error'],
                 description: 'A `refused` is this service saying no and ' +
                              'working; an `error` is this service failing.' },
      actor: {
        type: 'string',
        description: 'The NORMALISED local name, so a row here and a row on ' +
                     '/admin-api/users name the same person — `alice`, ' +
                     '`urn:sts-mock:user:alice` and `alice@STS.MOCK` are one ' +
                     'identity. Empty where nothing named an actor, which an ' +
                     'unauthenticated protocol call and an anonymous LDAP ' +
                     'bind both are.'
      },
      actorForm: {
        type: 'string',
        description: 'The identity exactly as it was presented, when that ' +
                     'differs from `actor` — a bind DN, a Kerberos ' +
                     'principal, an X.509 subject. Both are carried because ' +
                     'the collapse from one to the other is something an ' +
                     'auditor has to be able to see rather than infer.'
      },
      target: { type: 'string',
                description: 'What it was done to: a DN, a request path, a ' +
                             'session id.' },
      protocol: { type: 'string',
                  description: 'The family, where one applies. Free text: the ' +
                               'sixteen families here spell themselves ' +
                               'differently in the places this is read from, ' +
                               'and an enum would be a lookup table that ' +
                               'silently drops the seventeenth.' },
      channel: {
        type: 'string',
        enum: ['http', 'ldap', 'ldaps', 'internal'],
        description: 'Which socket it arrived on, or `internal` for something ' +
                     'this service did on its own — the directory entry it ' +
                     'seeds for somebody who authenticated elsewhere. NOT the ' +
                     'client\'s address, which on a mock behind a compose ' +
                     'bridge would be a fact about docker.'
      },
      summary: { type: 'string',
                 description: 'One sentence, the same one the console shows.' },
      detail: openObject(
        'Flat facts about this event, at most twelve keys with each value ' +
        'trimmed. What is in it depends on the action — a modify names the ' +
        'ATTRIBUTES it changed and never their values, a search names how ' +
        'many entries came back, an HTTP row names the route and the ' +
        'elapsed time.', {})
    }),

  AuditList: openObject(
    'What happened here, newest first, filtered and paged. HISTORY where the ' +
    'rest of this API is STATE.\n\nWalk it with `seq` rather than with ' +
    '`page`: events are still being recorded while you page, so page 2 taken ' +
    'a second after page 1 can repeat a row that shifted onto it. The ' +
    'sequence number cannot do that.',
    Object.assign({
      held: { type: 'integer',
              description: 'Events currently in the log.' },
      recorded: {
        type: 'integer',
        description: 'Events recorded since this process started. Greater ' +
                     'than `held` once the cap has bitten — `held` alone ' +
                     'would read as "this is all there ever was".'
      },
      dropped: { type: 'integer',
                 description: 'Events discarded to stay under the cap, oldest ' +
                              'first.' },
      maxEvents: { type: 'integer',
                   description: 'The cap: `audit.maxEvents`, changeable at ' +
                                'runtime through POST /admin-api/config/set.' },
      protocolCalls: {
        type: 'boolean',
        description: 'Whether ordinary protocol endpoint calls are being ' +
                     'recorded — `audit.protocolCalls`. False means the ' +
                     '`protocol` category is deliberately empty rather than ' +
                     'quiet; /admin-api/metrics counts every call either way.'
      },
      matched: { type: 'integer', description: 'How many events the filter ' +
                                               'matched.' },
      shown: { type: 'integer', description: 'How many are in `events`.' },
      oldestSeq: {
        type: 'integer',
        description: 'The lowest sequence number still held. A gap between ' +
                     'the last one a caller saw and this is exactly how many ' +
                     'events it missed.'
      },
      newestSeq: { type: 'integer',
                   description: 'The highest sequence number recorded.' },
      byCategory: openObject('How many held events are in each category.', {}),
      byOutcome: openObject('How many held events had each outcome.', {}),
      byAction: openObject('How many held events had each action. Only ' +
                           'actions that have occurred appear.', {}),
      filter: openObject('What was asked for; null where nothing was.', {}),
      categories: {
        type: 'array',
        description: 'The six categories with what each covers — what the ' +
                     '`category` filter takes.',
        items: openObject('One category.', {
          category: { type: 'string' },
          label: { type: 'string' },
          what: { type: 'string' }
        })
      },
      actions: {
        type: 'array',
        description: 'Every action with the category it belongs to — what ' +
                     'the `action` filter takes. Read off the same table the ' +
                     'log records against, so an action cannot occur and be ' +
                     'unfilterable, nor be offered and never occur.',
        items: openObject('One action.', {
          action: { type: 'string' },
          category: { type: 'string' },
          label: { type: 'string' }
        })
      },
      outcomes: { type: 'array', items: { type: 'string' } },
      events: { type: 'array', items: { $ref: '#/components/schemas/AuditEvent' } }
    }, PAGING_PROPERTIES))
};

// The prose at the top of the document. It is long on purpose: the first thing
// anybody pointing a tool at this needs to know is that it is unprotected and
// that four of its operations change what the PROTOCOL endpoints do.
const DESCRIPTION = [
  'The management API of the mock STS: everything the /admin console ' +
  'shows and everything it can change, over JSON, with no browser.',

  '**Nothing here is protected, and that is a decision rather than an ' +
  'oversight.** This service checks no end-user password anywhere — the ' +
  'username typed at its sign-in screen simply becomes the identity in every ' +
  'token it issues — so a console or an API with a credential on it would be ' +
  'a surface a test would have to hold a secret for, in a service whose ' +
  'premise is that it authenticates nobody. Two surfaces are the exception ' +
  'and neither is this one: the SCIM endpoints, which create and delete ' +
  'accounts, and the SPIRE Server API, whose callers present an X509-SVID ' +
  'over mutual TLS. Both are turnstiles rather than locks — anybody can get ' +
  'the credential — and both exist so that a client\'s refusal paths can be ' +
  'exercised at all. What follows is worth stating plainly: anyone who can reach ' +
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
  SCIM: 'The SCIM 2.0 provisioning endpoints under /scim/v2 — what they have ' +
        'been asked to do, and what they will and will not do. READ-ONLY ' +
        'here, and that is the parity rule holding rather than a gap: the ' +
        'console page has no form on it either, because everything about ' +
        'SCIM that can be changed is a configuration row. What SCIM WROTE is ' +
        'under Users and Groups, since it provisions into the same directory ' +
        'and has no store of its own.',
  'Audit log': 'What happened here, in order — history rather than state, ' +
               'and read-only. It carries no credential of any kind and has ' +
               'no clear operation: an erase control on an unprotected ' +
               'surface would make an audit log unable to answer the one ' +
               'question it exists for.',
  'Custom claims': 'What to add to every access token and ID Token issued ' +
                   'from now on. The assertions are next door, under Custom ' +
                   'SAML attributes.',
  'Custom SAML attributes': 'What to add to every SAML 2.0 and SAML 1.1 ' +
                            'assertion issued from now on — WS-Trust\'s and ' +
                            'WS-Federation\'s alike. The same store the ' +
                            'custom claims are in, and the same two halves: ' +
                            'a typed attribute and a directory one.',
  'Credential claims': 'What an issued Verifiable Credential carries.',
  'Verifier request': 'What the mock OID4VP Verifier asks a wallet for.',
  'Token lifetimes': 'How long an access token, an ID Token and a refresh ' +
                     'token issued here last, and how far out a clock may be ' +
                     'before this service stops believing one of its own. ' +
                     'Four of the settings under Configuration, behind a ' +
                     'name that promises four rather than forty-nine — and a ' +
                     'door that refuses a key it does not recognise instead ' +
                     'of ignoring it.'
};

module.exports = {
  SCHEMAS: SCHEMAS,
  buildSpec: buildSpec
};
