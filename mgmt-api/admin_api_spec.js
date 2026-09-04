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
// This module registers no route and requires nothing of this service's but the
// LOGGER — it is a pure function over a table — so its position in the require
// order does not matter, in the sense rule 3 gives for dpop.js, which reaches
// for helpers.js on exactly the same terms. What it must not grow is a require
// of anything that holds state: a document built from what the service happens
// to be doing is a document that describes one moment.
// ---------------------------------------------------------------------------

// The reply shape shared by every POST here: the console's own action result,
// unchanged. `ok` is the only member that is always present; the rest depends
// on what was asked, which is why this schema is open rather than closed.
const { log } = require('../common/helpers');

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

// THE SETTINGS BLOCK EVERY PAGE THAT OWNS SETTINGS CARRIES, written once for
// the same reason CONFIG_SETTING above is: since 2026-08-27 twenty-one console
// pages draw their own settings, and their `settings` member is this shape on
// every one of them. A caller reads it once.
const SETTINGS_BLOCK = openObject(
  'The settings this page draws, described. The same rows GET /config returns, ' +
  'filtered to the ones this page owns — which is where they are EDITED, not a ' +
  'second copy of them: every form posts to POST /config/set-many.',
  {
    page: { type: 'string' },
    groups: {
      type: 'array',
      description: 'In the order config.js declares them. Usually one; the ' +
                   'SAML pages draw two, because `saml.issuer` is a group of ' +
                   'its own governing both profiles.',
      items: openObject('One group\'s settings.', {
        group: { type: 'string' },
        settings: { type: 'array', items: CONFIG_SETTING }
      })
    },
    settingCount: { type: 'integer' },
    editableCount: {
      type: 'integer',
      description: 'How many of them can be changed while the service runs. ' +
                   'The rest were consumed at startup and say why in ' +
                   '`restartReason`; on the Kerberos and TLS pages that is ' +
                   'most of them.'
    },
    overridden: {
      type: 'array', items: { type: 'string' },
      description: 'The keys on this page with a runtime override in force.'
    },
    setWith: {
      type: 'string',
      description: 'The operation that writes them, named rather than left to ' +
                   'be inferred: one store, one action, however many pages ' +
                   'draw the door.'
    }
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

  // ---------------------------------------------------------------------
  // THE SIGN-OUT INVENTORY.
  //
  // One shape for both answers `GET /admin-api/logout` gives — the family list
  // when no `user` was named, and one identity's live state when one was —
  // because the two differ by which members are present rather than in kind,
  // which is the same arrangement UserList/UserDetail has one screen down.
  //
  // `terminable: false` rows are the members most likely to be mistaken for a
  // defect, so the description says what they are where a generated client's
  // documentation will show it.
  // ---------------------------------------------------------------------
  LogoutRow: openObject(
    'One live thing: a session, a credential, a relying party, a directory ' +
    'connection, or an artifact that cannot be ended at all.',
    {
      id: { type: 'string',
            description: 'What `POST /admin-api/logout/end` takes in ' +
                         '`select`. It is `<family>:<handle>`, and for a row ' +
                         'whose natural key is a CREDENTIAL — an ' +
                         'authorization code, a pre-authorized code — the ' +
                         'handle is a hash of it and never the value: a code ' +
                         'in a reply is a code in a log.' },
      family: { type: 'string', description: 'Which family it belongs to.' },
      kind: { type: 'string',
              description: 'What it is, in that family\'s own vocabulary.' },
      label: { type: 'string', description: 'The thing itself, for a person.' },
      detail: { type: 'string',
                description: 'Who issued it, to whom, and what rides on it.' },
      startedAt: { type: 'integer',
                   description: 'Epoch ms, or 0 where the family cannot say.' },
      expiresAt: { type: 'integer',
                   description: 'Epoch ms, or 0 for "no expiry was stated" — ' +
                                'which is the honest answer for several of ' +
                                'these rather than an expiry of now.' },
      terminable: { type: 'boolean',
                    description: 'FALSE means nothing can end it — not this ' +
                                 'service and not a real one. Nothing ' +
                                 'consults the issuer when a SAML assertion, ' +
                                 'a Kerberos service ticket or an X509-SVID ' +
                                 'is presented, so there is no revocation to ' +
                                 'perform. `why` says so in a sentence.' },
      why: { type: 'string',
             description: 'When `terminable` is false, the reason. Empty ' +
                          'otherwise.' },
      sessionId: { type: 'string',
                   description: 'The browser sign-on session it hangs off, ' +
                                'where there is one. Empty is a fact about ' +
                                'the row — the direct grants have no session ' +
                                '— rather than a gap.' }
    }),

  LogoutFamily: openObject(
    'One family of live things, and the prose saying what a logout does and ' +
    'does not reach in it.',
    {
      id: { type: 'string' },
      label: { type: 'string' },
      protocol: { type: 'string' },
      spec: { type: 'string',
              description: 'The document this family\'s behaviour comes ' +
                           'from, or a sentence saying there is none to ' +
                           'cite — which is the answer for everything that ' +
                           'cannot be recalled.' },
      what: { type: 'string' },
      terminable: { type: 'boolean' },
      held: { type: 'integer', description: 'How many are live.' },
      notListed: { type: 'integer',
                   description: 'How many were held back by `logout.maxRows`. ' +
                                'The cap is on what is LISTED and never on ' +
                                'what a termination reaches: a global logout ' +
                                'still ends every one of them.' },
      failure: { type: 'string',
                 description: 'Set when this family could not be read. The ' +
                              'rest of the reply is unaffected — a family ' +
                              'that cannot answer is reported rather than ' +
                              'taking the whole inventory down.' },
      rows: { type: 'array', items: { $ref: '#/components/schemas/LogoutRow' } }
    }),

  KeyList: openObject(
    'Every key pair this process generated at start, what each is used for, ' +
    'and which keystore formats it can be exported as. A LIST and never key ' +
    'material — POST /admin-api/keys/export is what hands one over.',
    {
      issuer: { type: 'string' },
      realm: { type: 'string',
               description: 'The signing keys belong to this realm; the TLS ' +
                            'certificate belongs to the process. Each row ' +
                            'says which in `scope`.' },
      regeneratedEveryStart: { type: 'boolean' },
      formats: { type: 'array', items: { type: 'string' },
                 description: 'Every format the exporter knows. What a ' +
                              'PARTICULAR key offers is its own `formats`, ' +
                              'which is narrower.' },
      warning: { type: 'string' },
      keys: { type: 'array', items: openObject('One key pair.', {
        id: { type: 'string',
              description: 'What POST /admin-api/keys/export takes as `key`.' },
        label: { type: 'string' },
        alg: { type: 'string' },
        kty: { type: 'string' },
        crv: { type: 'string' },
        kid: { type: 'string',
               description: 'Empty for the TLS key, which has a fingerprint ' +
                            'instead, and for a post-quantum key that has not ' +
                            'been generated yet.' },
        scope: { type: 'string', description: '`realm` or `process`.' },
        hasCertificate: { type: 'boolean',
                          description: 'Whether a PKCS#12 is possible: a .p12 ' +
                                       'wraps a private key in a certificate ' +
                                       'and this service holds one for the ' +
                                       'signing key and the TLS key only.' },
        formats: { type: 'array', items: { type: 'string' },
                   description: 'Empty means not exportable, and the page ' +
                                'says why — a post-quantum key that has not ' +
                                'been made yet, or one with no interoperable ' +
                                'encoding.' },
        usedFor: { type: 'array', items: { type: 'string' } }
      }) }
    }),

  KeyExportRequest: openObject(
    'Which key, in which format, under which password.',
    {
      key: { type: 'string',
             description: 'The `id` from GET /admin-api/keys.' },
      format: { type: 'string', enum: ['pem', 'der', 'jwk', 'pkcs12'] },
      password: { type: 'string',
                  description: 'REQUIRED for `pkcs12`. Optional for the other ' +
                               'three, where it encrypts the private half — ' +
                               'PKCS#8 for PEM and DER, PBES2 as a .jwe for ' +
                               'JWK. Empty means the private key comes out in ' +
                               'the clear, which is usually what is wanted ' +
                               'from a mock and never anywhere else.' }
    }),

  KeyExport: openObject(
    'THE EXPORTED FILES, CARRYING PRIVATE KEY MATERIAL. base64 rather than ' +
    'raw octets because this API answers JSON everywhere else, and a caller ' +
    'that suddenly got a binary body would have to special-case one operation.',
    {
      ok: { type: 'boolean' },
      status: { type: 'string', description: 'One line about what came out.' },
      publicOnly: { type: 'boolean',
                    description: 'True for a post-quantum key: RFC 9964 ' +
                                 'defines the public members and the private ' +
                                 'seed handling is still moving, so there is ' +
                                 'no interoperable private encoding to hand ' +
                                 'over.' },
      files: { type: 'array', items: openObject('One file.', {
        name: { type: 'string' },
        mime: { type: 'string' },
        bytes: { type: 'integer' },
        base64: { type: 'string' }
      }) }
    }),

  CryptoMetadata: openObject(
    'What this service does when it signs, verifies, encrypts or decrypts — ' +
    'for every identity service it advertises, with the algorithms each ' +
    'really uses. Every algorithm list in it is READ FROM THE MODULE THAT ' +
    'PERFORMS THE ALGORITHM rather than written down, so it cannot claim ' +
    'something this service does not do. Mirrors GET /admin/crypto-metadata.',
    {
      issuer: { type: 'string',
                description: 'This service as the request reached it.' },
      realm: { type: 'string',
               description: 'The trust realm the key material below belongs ' +
                            'to. The ALGORITHM tables are process-wide; the ' +
                            'SIGNING KEYS are per realm, and the TLS ' +
                            'certificate and the SPIFFE authorities are ' +
                            'neither — those three socket families have no ' +
                            'path to put a realm segment in.' },
      generatedAt: { type: 'string' },
      oneModule: { type: 'string',
                   description: 'Where all of this happens. One module since ' +
                                '2026-08-27; about twenty places before it.' },
      drift: openObject(
        'The family list here, checked against the one ' +
        '/admin/sts-metadata advertises, in BOTH directions — a family ' +
        'advertised with no crypto profile, and a profile naming a family ' +
        'that is not advertised, which is what a rename produces. `checked` ' +
        'is false when that module never handed its list over, which is said ' +
        'rather than rendered as two empty lists that look like a clean bill ' +
        'of health.', {
          checked: { type: 'boolean' },
          undescribed: { type: 'array', items: { type: 'string' } },
          stale: { type: 'array', items: { type: 'string' } },
          envelopes: { type: 'array', items: { type: 'string' } }
        }),
      keys: openObject(
        'The key material this process holds. TYPES, IDENTIFIERS, CURVE ' +
        'NAMES, FINGERPRINTS AND DATES ONLY — everything here is already ' +
        'readable from /oauth2/jwks, /tls/server-certificate and the SPIFFE ' +
        'bundle endpoint, and no private key or secret is ever in this ' +
        'reply.', {}),
      families: { type: 'array', items: openObject(
        'One identity service, and what it does with cryptography. The four ' +
        'verbs are separate because they are four different exposures: an ' +
        'empty one means this service does not do it in that family, and ' +
        'every one of those is a documented non-goal.', {
          name: { type: 'string' },
          signs: { type: 'string' },
          verifies: { type: 'string' },
          encrypts: { type: 'string' },
          decrypts: { type: 'string' },
          hashes: { type: 'string' },
          whatItDoesNot: { type: 'string' },
          envelopes: { type: 'array', items: { type: 'string' },
                       description: 'Keys into `standards` below.' },
          algorithms: { type: 'array', items: openObject(
            'One labelled list, read live from the module that performs it.',
            { what: { type: 'string' },
              values: { type: 'array', items: { type: 'string' } } }) }
        }) },
      hashing: openObject('Every digest this service computes, and what for.',
                          {}),
      signatures: openObject(
        'JWS, XML SignatureMethod, canonicalization, COSE, and the rest.', {}),
      encryption: openObject(
        'JWE, XML Encryption, the Kerberos encryption types and TLS. The ' +
        'encrypt and decrypt lists differ on purpose in both JOSE and XML.',
        {}),
      postQuantum: openObject(
        'THE SIGNATURES ARE PARTLY POST-QUANTUM AND THE KEY ESTABLISHMENT IS ' +
        'ENTIRELY CLASSICAL, and those two halves are reported separately ' +
        'because they are in very different positions: a signature is ' +
        'checked when it is presented, while captured ciphertext can be kept ' +
        'and opened later. Symmetric cryptography is a third category ' +
        'again.', {}),
      standards: { type: 'array', items: openObject(
        'One higher-level envelope, with an honest coverage note. Every ' +
        '`coverage` starts `full`, `partial` or `mock` and says what is ' +
        'missing.', {
          key: { type: 'string' },
          name: { type: 'string' },
          specs: { type: 'array', items: { type: 'string' } },
          coverage: { type: 'string' },
          what: { type: 'string' }
        }) }
    }),

  SessionList: openObject(
    'Every session this service is holding right now, across the three ' +
    'protocols that have one, filtered and paged.',
    Object.assign({
      installed: { type: 'boolean',
                   description: 'FALSE when `logout/logout.js` is not loaded ' +
                                'in this process, which is the module that ' +
                                'holds the one model of what a live session ' +
                                'is. Nothing else in the reply is then ' +
                                'meaningful.' },
      held: { type: 'integer', description: 'Live sessions in total.' },
      matched: { type: 'integer' },
      shown: { type: 'integer' },
      heldByKind: openObject(
        'How many of each kind are live, keyed by the same `family` value ' +
        'every row carries: `session`, `krb5`, `ldap`.', {}),
      filter: openObject(
        'What was asked for, with null where nothing was — so a reply can be ' +
        'read on its own without the request beside it.', {}),
      at: { type: 'integer',
            description: 'When this answer was computed, epoch ms. It matters ' +
                         'here more than on most resources: every row is a ' +
                         'countdown, and `expiresAt` minus this is the ' +
                         'remaining life at the moment it was read.' },
      expiryRules: openObject(
        'The sentence saying how each kind\'s expiry is worked out, keyed by ' +
        '`family`. It is here once rather than on every row because it is a ' +
        'property of the KIND: a browser session\'s expiry is absolute and ' +
        'is not extended by use, a Kerberos TGT\'s was sealed into the ' +
        'ticket by the KDC and cannot be moved, and an LDAP connection has ' +
        'no expiry at all.', {}),
      sessions: { type: 'array',
                  items: { $ref: '#/components/schemas/SessionRow' } }
    }, PAGING_PROPERTIES)),

  SessionRow: openObject(
    'One live session. The three kinds share this shape and the members that ' +
    'do not apply to a kind are empty rather than absent.',
    {
      id: { type: 'string',
            description: 'What `POST /admin-api/sessions/revoke` takes as ' +
                         '`select`: the family and the handle, as ' +
                         '`session:…`, `ldap:…` or `krb5:…@REALM`. It is the ' +
                         'same identifier `POST /admin-api/logout/selective` ' +
                         'takes, because both go through one termination.' },
      family: { type: 'string', enum: ['session', 'krb5', 'ldap'],
                description: 'Which kind of session this is.' },
      kind: { type: 'string', description: 'That kind, for a person to read.' },
      key: { type: 'string',
             description: 'The normalised identity this is filed under, and ' +
                          'the `key` the revoke operation needs beside `id`.' },
      username: { type: 'string',
                  description: 'Who is signed in, as they are named in this ' +
                               'kind of session: a username, a principal, or ' +
                               'the bind DN.' },
      sub: { type: 'string',
             description: 'The subject a token would carry. Empty on the two ' +
                          'kinds that issue no token.' },
      protocol: { type: 'string',
                  description: 'The protocol the sign-in came THROUGH, which ' +
                               'is not the only one the session serves: every ' +
                               'browser family here reads the same session. ' +
                               '`carries` is what has actually signed in on ' +
                               'it.' },
      handle: { type: 'string',
                description: 'The thing itself — a session id, a connection ' +
                             'id, a principal name.' },
      sessionId: { type: 'string',
                   description: 'The browser sign-on session id, which is ' +
                                'what a token issued under it records — so it ' +
                                'is the join to `GET /admin-api/tokens?' +
                                'session=`. Empty on the other two kinds, ' +
                                'which issue nothing that records one.' },
      startedAt: { type: 'integer',
                   description: 'Epoch ms, or 0 when nothing recorded it.' },
      expiresAt: { type: 'integer',
                   description: '**Epoch ms, or 0 for NO EXPIRY — which is ' +
                                'not an expiry of the epoch.** An LDAP ' +
                                'connection has none: it lasts until the next ' +
                                'Bind, an Unbind, or the socket closing. ' +
                                '`expiryRule` says which arithmetic produced ' +
                                'this number.' },
      expiryRule: { type: 'string',
                    description: 'How this kind\'s expiry is worked out, in a ' +
                                 'sentence. The same string as the matching ' +
                                 'member of `expiryRules`.' },
      amr: { type: 'array', items: { type: 'string' } },
      acr: { type: 'string' },
      carries: { type: 'array', items: { type: 'string' },
                 description: 'What has signed in ON this session — OIDC ' +
                              'relying parties, WS-Federation realms, SAML ' +
                              '2.0 service providers — which is what makes ' +
                              'ending one reach further than it looks.' },
      detail: { type: 'string' },
      terminable: { type: 'boolean',
                    description: 'Whether this service can end it. FALSE ' +
                                 'where a setting says otherwise ' +
                                 '(`logout.kerberosSignOut`, ' +
                                 '`logout.ldapDisconnect`), with `why` ' +
                                 'saying so.' },
      why: { type: 'string',
             description: 'What ending this actually does, or why it cannot ' +
                          'be done. It is present on rows that CAN be ended ' +
                          'too, and on a Kerberos row it is the important ' +
                          'half: ending one stamps an instant on the ' +
                          'PRINCIPAL and refuses every ticket it ' +
                          'authenticated before now, not just this one.' }
    }),

  LogoutInventory: openObject(
    'What this service is still holding for one identity, across every ' +
    'protocol family — or, with no `user`, the list of families a logout ' +
    'reaches.',
    Object.assign({
      user: { type: 'string', description: 'The name that was asked about.' },
      known: { type: 'boolean',
               description: 'FALSE with no `user` means this is the family ' +
                            'list rather than an identity.' },
      key: { type: 'string',
             description: 'The normalised identity key everything is filed ' +
                          'under — what folds `alice`, `alice@REALM` and a ' +
                          '`urn:` subject into one answer.' },
      sessions: { type: 'integer', description: 'Browser sign-on sessions held.' },
      total: { type: 'integer', description: 'Live items in every family.' },
      listed: { type: 'integer' },
      notListed: { type: 'integer' },
      maxRows: { type: 'integer', description: 'The `logout.maxRows` cap.' },
      canWrite: { type: 'boolean',
                  description: 'Whether the caller holds Admin Write. Always ' +
                               'true through this API, which is not gated.' },
      families: { type: 'array',
                  items: { $ref: '#/components/schemas/LogoutFamily' } },
      rows: { type: 'array', items: { $ref: '#/components/schemas/LogoutRow' },
              description: 'The same rows flattened, filtered and paged — ' +
                           'which is what the console table shows.' }
    }, PAGING_PROPERTIES)),

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

  Saml2ServiceProviderList: openObject(
    'The SAML 2.0 identity provider: every service provider this profile has ' +
    'answered for, and the four endpoint URLs each of them is configured ' +
    'from. THE METADATA IS PER SERVICE PROVIDER — a distinct identity ' +
    'provider entityID and its own SSO, SLO and artifact endpoints, the way ' +
    'Okta and Ping do it — which is why a URL here is a per-row fact rather ' +
    'than one constant. With ?sp= the reply is ONE of them instead.\n\n' +
    'It holds nothing: every row is an entry in `ou=applications`, and the ' +
    'writes below are the same `updateApplication()` an `ldapmodify` reaches.',
    Object.assign({
      serviceProviders: {
        type: 'array',
        description: 'One page of them. Each carries `identifier` (the ' +
                     'entityID), `slug` (its URL path segment), ' +
                     '`idpEntityId`, `metadataUrl`, `ssoUrl`, `sloUrl`, ' +
                     '`arsUrl`, the counters, and what has been recorded ' +
                     'about it.',
        items: openObject(
          'One service provider, its endpoints and what has been seen of it.', {})
      },
      unscopedMetadata: {
        type: 'string',
        description: 'The document at /saml2/metadata, which names ONE ' +
                     'identity provider for everybody and works for a service ' +
                     'provider that does not want a document of its own.'
      },
      settings: SETTINGS_BLOCK,
      artifactsAwaitingResolution: {
        type: 'integer',
        description: 'How many artifacts are minted and not yet resolved. An ' +
                     'artifact is ONE-SHOT and expires (saml2.artifactTtlS), ' +
                     'so this rises and falls; a number that only ever rises ' +
                     'is a leak.'
      },
      requestsHeldForSignIn: {
        type: 'integer',
        description: 'AuthnRequests held while a browser is at the sign-in ' +
                     'screen, or held for the one hop that turns a ' +
                     'POST-binding request into a GET so the SameSite=Lax ' +
                     'session cookie is visible. Same reading as above.'
      },
      found: {
        type: 'boolean',
        description: 'On the ?sp= reply only. FALSE for an entityID that is ' +
                     'not in the registry — whose metadata document is still ' +
                     'served, and whose AuthnRequest would still be answered, ' +
                     'because this profile accepts any entityID.'
      }
    }, PAGING_PROPERTIES)),

  FederationRelationshipList: openObject(
    'THE FEDERATION REGISTER: every relationship this service has been ' +
    'configured with, in either direction and in any of five protocols. With ' +
    '?relationship= the reply is ONE of them instead, with everything it holds ' +
    'and the URLs to configure at the partner.\n\n' +
    '**This is the one resource in this API whose contents are a security ' +
    'decision rather than a record.** Everywhere else this service accepts ' +
    'what it is given; it cannot do that at an assertion consumer service, ' +
    'because what arrives there is an unauthenticated request claiming to be a ' +
    'person and the session it produces is the one every protocol in this ' +
    'process reads. So a relationship is created DISABLED and an assertion is ' +
    'refused unless it verifies against the certificate configured on it.\n\n' +
    'It holds nothing of its own: every row is an entry under ' +
    '`ou=federations`, so an `ldapmodify` there is exactly what these ' +
    'operations do.\n\n' +
    '`fedClientSecret` is NEVER returned by this API — it is reported as `(set ' +
    '— not returned)` or empty. That is not a security boundary and is not ' +
    'claimed as one: an `ldapsearch` of this directory shows it, deliberately ' +
    'and loudly, exactly as `GET /krb5/principals` prints every Kerberos ' +
    'password. What it avoids is this API being a SECOND way to read a ' +
    'credential that belongs to somebody else\'s service out of this process.',
    Object.assign({
      relationships: {
        type: 'array',
        description: 'One page of them. Each carries `id`, `role`, ' +
                     '`protocol`, `peer`, `enabled`, `ready`, `missing` (the ' +
                     'fields still to configure), `usable` (enabled AND ' +
                     'ready — the only state in which anything happens), the ' +
                     'counters and `lastError`.',
        items: openObject(
          'One relationship, its state and what has crossed it.', {})
      },
      roles: {
        type: 'array',
        description: 'The two directions, each with what it means. Named for ' +
                     'what THIS SERVICE does rather than for what the partner ' +
                     'does, because every log line and every page here is ' +
                     'written from this service\'s point of view.',
        items: openObject('One role.', {})
      },
      protocols: {
        type: 'array',
        description: 'The five, each with what happens in it, the ' +
                     'specification it cites, and `needs` — the fields a ' +
                     'service-provider-side relationship of that protocol ' +
                     'must carry before it can work. That list is what ' +
                     '`missing` is computed from, so a caller can check its ' +
                     'own configuration against the same rule the endpoint ' +
                     'applies.',
        items: openObject('One protocol.', {})
      },
      paths: openObject(
        'The four federation paths, so a caller builds the URL to configure ' +
        'at the partner from the same strings the router serves rather than ' +
        'from a copy that can drift.', {}),
      ready: {
        type: 'integer',
        description: 'How many are enabled AND fully configured. A count ' +
                     'below `relationshipCount` is the ordinary state, since a ' +
                     'relationship is created disabled.'
      },
      found: {
        type: 'boolean',
        description: 'On the ?relationship= reply only. FALSE for an id that ' +
                     'is not registered — and unlike almost everything else in ' +
                     'this API, one does not appear because somebody used it: ' +
                     'this register is configured, and nothing creates an ' +
                     'entry in it by turning up.'
      }
    }, PAGING_PROPERTIES)),

  Saml11RelyingPartyList: openObject(
    'The SAML 1.1 identity provider: every relying party this profile has ' +
    'answered for, and the three endpoint URLs each of them is configured ' +
    'from. THE METADATA IS PER RELYING PARTY, exactly as the SAML 2.0 ' +
    'profile\'s is, and it is a SAML 2.0 metadata document describing a SAML ' +
    '1.1 identity provider — SAML 1.1 never had a metadata specification, and ' +
    'what every relying party consumes is an EntityDescriptor whose ' +
    'protocolSupportEnumeration is the 1.1 protocol.\n\n**THERE IS NO ' +
    'REQUEST MESSAGE IN SAML 1.1**, which is where this resource differs from ' +
    '`GET /admin-api/saml2` rather than merely being older: a relying party ' +
    'cannot identify itself in the protocol, so `identifier` may be something ' +
    'this service GUESSED from the origin of a TARGET — `identifierLooksGuessed` ' +
    'says so on the ?rp= reply. There is also no logout service to declare ' +
    'and no request signature to record, because the protocol has neither.\n\n' +
    'It holds nothing: every row is an entry in `ou=applications`, and the ' +
    'kind is shared with WS-Federation, so a row here may never have touched ' +
    '/saml11 — `profiles` says which of the two browser profiles it has ' +
    'actually used. With ?rp= the reply is ONE of them instead.',
    Object.assign({
      relyingParties: {
        type: 'array',
        description: 'One page of them. Each carries `identifier`, `slug` ' +
                     '(its URL path segment, THE SAME ONE the SAML 2.0 ' +
                     'profile uses for that application), `idpProviderId`, ' +
                     '`metadataUrl`, `ssoUrl`, `responderUrl`, the counters, ' +
                     'and what has been recorded about it.',
        items: openObject(
          'One relying party, its endpoints and what has been seen of it.', {})
      },
      unscopedMetadata: {
        type: 'string',
        description: 'The document at /saml11/metadata, which names ONE ' +
                     'identity provider for everybody and works for a relying ' +
                     'party that does not want a document of its own.'
      },
      settings: SETTINGS_BLOCK,
      artifactsAwaitingResolution: {
        type: 'integer',
        description: 'How many type 0x0001 artifacts are minted and not yet ' +
                     'resolved. An artifact is ONE-SHOT and expires ' +
                     '(saml11.artifactTtlS), so this rises and falls; a number ' +
                     'that only ever rises is a leak.'
      },
      assertionsHeldByReference: {
        type: 'integer',
        description: 'Assertions kept so that a <samlp:AssertionIDReference> ' +
                     'can ask for one again. Unlike the artifacts above it is ' +
                     'CAPPED rather than swept — a reference is not a ' +
                     'credential, so it is not one-shot — which means this ' +
                     'number sitting at its ceiling is the healthy state and ' +
                     'not a leak.'
      },
      flowsHeldForSignIn: {
        type: 'integer',
        description: 'Flows held while a browser is at the sign-in screen. ' +
                     'There is no second reason here: a SAML 1.1 flow arrives ' +
                     'as a top-level GET, so it needs none of the POST-to-GET ' +
                     'hop the SAML 2.0 profile holds requests for.'
      },
      found: {
        type: 'boolean',
        description: 'On the ?rp= reply only. FALSE for an identifier that is ' +
                     'not in the registry — whose metadata document is still ' +
                     'served, and whose flow would still be answered, because ' +
                     'this profile accepts any identifier.'
      }
    }, PAGING_PROPERTIES)),

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
          '`kinds`, `protocols` (DERIVED — the protocol families it has actually ' +
          'appeared in, as the prose labels /admin/users spells protocols with), ' +
          '`allowedProtocols` (DECLARED — the families somebody said it is FOR, as ' +
          'ids from the closed vocabulary GET /admin-api/applications/new ' +
          'publishes; nothing in this service reads it, so it grants and refuses ' +
          'nothing), `recordedProtocols` (the same vocabulary again, worked out ' +
          'from this entry\'s KINDS — which is what makes the two comparable, since ' +
          'the labels in `protocols` and the ids in `allowedProtocols` are different ' +
          'alphabets and matching on the labels would read every OAuth client as a ' +
          'federation partner. It is NOT "has authenticated": a create takes a kind ' +
          'too, so a hand-made entry can be recorded in a family it has never ' +
          'connected in, and `authentications` is the figure that answers that), ' +
          '`registered`, `firstSeen`, `lastSeen`, ' +
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

  // WHAT A CREATE MAY SAY, answered by the service rather than described in
  // this document. The two vocabularies below are the closed lists
  // createApplication() validates against, so a caller that reads this cannot
  // construct a create the service will refuse — the property
  // editableAttributes() gives the console's two selects, reached over HTTP.
  NewApplicationForm: openObject(
    'The vocabulary a new application entry may be created with, and where it ' +
    'would land. Mirrors GET /admin/applications/new, which is the console page ' +
    'built from exactly these lists. It creates nothing itself: the create is ' +
    'POST /admin-api/applications/create.',
    {
      directory: {
        type: 'boolean',
        description: 'FALSE when no directory is loaded in this process, in ' +
                     'which case there is no ou=applications container and a ' +
                     'create would be refused. The call still answers 200: the ' +
                     'operation exists and the store does not, and those are ' +
                     'different facts.'
      },
      container: { type: 'string',
                   description: 'The DN a new entry would be created under, IN ' +
                                'THE REALM THIS CALL ARRIVED IN. The directory ' +
                                'is per realm, so /realm/acme/admin-api/... ' +
                                'answers with acme\'s container and an entry ' +
                                'created there is invisible to every other realm.' },
      max: { type: 'integer',
             description: 'How many entries that container will hold ' +
                          '(applications.max). Past it a create is REFUSED ' +
                          'rather than an old entry evicted.' },
      applicationCount: { type: 'integer',
                          description: 'How many it holds now.' },
      realm: openObject('The trust realm this call arrived in: `id` and `name`.', {}),
      kinds: {
        type: 'array',
        description: 'The eight kinds, each `{kind, label, what}`. A create ' +
                     'takes AT MOST ONE, and a value that is not one of these ' +
                     'is refused rather than recorded.',
        items: openObject('One kind.', {})
      },
      protocols: {
        type: 'array',
        description: 'THE CLOSED PROTOCOL VOCABULARY: one row per family an ' +
                     'application may be DECLARED for, each `{id, label, kind, ' +
                     'kinds, what}`. `id` is what a create sends and what lands ' +
                     'on `appAllowedProtocol`; `kind` is what the registry would ' +
                     'record the application as when a protocol of that family ' +
                     'finally recognises it; `kinds` is every kind that COUNTS ' +
                     'as a sighting of the family, which is how ' +
                     '`recordedProtocols` on an application is worked out — ' +
                     'usually the same one ' +
                     'value, except OAuth 2.0, which also counts the OpenID ' +
                     'Connect kind because a relying party IS an OAuth client. ' +
                     'BOTH ARE EMPTY for a family in which this service records ' +
                     'no application identifier at all (LDAP, SCIM, SPIFFE, ' +
                     'mutual TLS, OpenID4VCI): nothing will ever record one of ' +
                     'those, which is a different fact from "it has not ' +
                     'happened yet". The match is on kinds and NOT on the protocol ' +
                     'labels in `protocols`, because a federation partner is ' +
                     'recorded under the protocol its relationship speaks and ' +
                     'by label is indistinguishable from an ordinary client. ' +
                     '**DECLARING GRANTS AND REFUSES NOTHING**: no endpoint ' +
                     'reads this attribute, and an application declared for one ' +
                     'family may still use every other, because a mock that ' +
                     'refused a protocol would remove a test case rather than ' +
                     'add one.',
        items: openObject('One protocol family.', {})
      },
      declarations: {
        type: 'array',
        description: 'THE FIELDS THE CREATE FORM IS DRAWN FROM, in the order it ' +
                     'draws them: one row per ATTRIBUTE a protocol family names ' +
                     'as its identifier or as where its responses go back to, ' +
                     'each `{attribute, role, kind, editable, sensitive, what, ' +
                     'families}`. `role` is `identifier` or `redirect`; `kind` ' +
                     'is `multi` where the attribute holds a list; `families` ' +
                     'names every family the attribute serves.\n\n**It is ' +
                     'DEDUPED BY ATTRIBUTE, so it is shorter than `protocols` ' +
                     'above.** Three families name `oauthClientId` — an OpenID ' +
                     'Connect relying party IS an OAuth client and an OpenID4VCI ' +
                     'wallet authenticates as one — and both SAML profiles name ' +
                     '`samlEntityId`, because those specifications genuinely ' +
                     'share the identifier. Two attributes for one fact would be ' +
                     'two spellings that disagree the first time either is ' +
                     'edited.\n\nThese are the names a create sends in ' +
                     '`fields`. Publishing them is what stops this document and ' +
                     'the console offering different fields: both are the same ' +
                     'walk of the same table.',
        items: openObject('One declared attribute, and the families it serves.', {})
      },
      editable: {
        type: 'array',
        description: 'EVERY attribute that may be changed — a superset of ' +
                     '`declarations` above, which is the identifier and ' +
                     'redirect-URI half of it. Each `{name, mode, sensitive}` ' +
                     'where `mode` is `set` for a single-valued attribute and ' +
                     '`multi` for a list. A create takes any of them in `fields`, ' +
                     'and POST /admin-api/applications/set, /add and /remove ' +
                     'change them afterwards. This is where the configuration ' +
                     'RFC 9700 mode actually reads goes — the redirect URIs, the ' +
                     'grant types, the secret.'
                     ,
        items: openObject('One editable attribute.', {})
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

  // -------------------------------------------------------------------------
  // THE FIVE DIRECTORY PAGES, 2026-09-01.
  //
  // `/admin/ldap/directory`, `/admin/ldap/applications`,
  // `/admin/ldap/federations`, `/admin/ldap/spiffe` and
  // `/admin/ldap/service` were HTML pages outside the console until that day
  // and are console pages now; rule 7 gave each of them an operation, and
  // these are what those operations answer with.
  //
  // EVERY ONE OF THEM IS DELIBERATELY SHALLOW, and it is worth saying why
  // rather than leaving it to look like an omission. What these resources
  // return is DIRECTORY ENTRIES, and this directory is SCHEMALESS on purpose
  // — an entry may carry whatever attributes a client sent it. So an
  // `attributes` member written out property by property would be a document
  // making a promise the store does not keep, and the first `ldapadd` of an
  // unknown attribute would make it false. The names ARE published, and in
  // the one place that can keep them right: each of these replies carries the
  // container's own `schema`, read out of the module that owns it. That is
  // the same argument the pages themselves make for printing a schema at all.
  // -------------------------------------------------------------------------
  DirectoryEntryList: openObject(
    'Every entry in THIS REALM\'s directory, paged: the DN, where the entry ' +
    'came from, and every attribute with every value. It is not an LDAP ' +
    'search — a search withholds the operational attributes unless they are ' +
    'asked for by name (RFC 4511 §4.5.1.8) and this is the service showing ' +
    'its own store, so they are here.',
    Object.assign({
      baseDn: { type: 'string' },
      count: { type: 'integer',
               description: 'Every entry in this realm, before the filter. ' +
                            'The name is kept from before this was a console ' +
                            'page, because callers read it.' },
      matched: { type: 'integer', description: 'What the filter left.' },
      shown: { type: 'integer', description: 'Rows on this page.' },
      filter: openObject('What was asked for; null where nothing was.', {}),
      origins: { type: 'array', items: { type: 'string' },
                 description: 'Every value of `origin` present in this ' +
                              'realm, which is what the `origin` parameter ' +
                              'may be set to.' },
      entries: { type: 'array',
                 items: openObject('One entry: `dn`, `origin` and ' +
                                   '`attributes`.', {}) }
    }, PAGING_PROPERTIES)),

  DirectoryApplicationList: openObject(
    'The application registry as the directory holds it: one entry per ' +
    'identifier under ou=applications, with every attribute on it, plus the ' +
    'published vocabulary. THESE ENTRIES ARE THE REGISTRY and nothing caches ' +
    'them.',
    Object.assign({
      baseDn: { type: 'string' },
      container: { type: 'string', description: 'The ou=applications DN.' },
      count: { type: 'integer' },
      matched: { type: 'integer' },
      shown: { type: 'integer' },
      max: { type: 'integer', description: 'The cap, ldap.maxApplications.' },
      filter: openObject('What was asked for; null where nothing was.', {}),
      sourceOfTruth: { type: 'string',
                       description: 'The sentence a caller most needs about ' +
                                    'this container, in the reply rather ' +
                                    'than only on the page.' },
      kinds: { type: 'array',
               items: openObject('One kind an application can be.', {}) },
      schema: openObject('The object classes and the attributes, read out of ' +
                         'common/applications.js.', {}),
      applications: { type: 'array',
                      items: openObject('One entry, whole.', {}) }
    }, PAGING_PROPERTIES)),

  DirectoryFederationList: openObject(
    'The federation register as the directory holds it — the one container ' +
    'here where an ldapmodify is a SECURITY change. `fedClientSecret` is ' +
    'redacted in `relationships` and present in each entry\'s own ' +
    'attributes, which is the split the page makes: what a script reads is ' +
    'redacted, and a document claiming to say what the directory holds may ' +
    'not hide a value an ldapsearch shows.',
    Object.assign({
      baseDn: { type: 'string' },
      container: { type: 'string', description: 'The ou=federations DN.' },
      count: { type: 'integer' },
      matched: { type: 'integer' },
      shown: { type: 'integer' },
      max: { type: 'integer', description: 'The cap, federation.maxRelationships.' },
      filter: openObject('What was asked for; null where nothing was.', {}),
      sourceOfTruth: { type: 'string' },
      roles: { type: 'array', items: openObject('One direction.', {}) },
      protocols: { type: 'array',
                   items: openObject('One protocol a relationship can ' +
                                     'speak, and what it needs.', {}) },
      schema: openObject('The object classes and the attributes, read out of ' +
                         'federation/federation.js. Each attribute names the ' +
                         'DIRECTION it is for.', {}),
      relationships: { type: 'array',
                       items: openObject('One relationship, with `ready` and ' +
                                         '`missing` on it.', {}) }
    }, PAGING_PROPERTIES)),

  DirectorySpiffe: openObject(
    'The two SPIFFE containers as the directory holds them. ou=entries is ' +
    'CONFIGURATION and ou=agents is a RECORD, which is why they are two ' +
    'containers and why nothing about an agent is editable. THE ONE ' +
    'DIRECTORY RESOURCE WITH TWO LISTS IN IT, so it pages the way a console ' +
    'drill-down does: `entries` and `agents` at the top level are the TOTALS ' +
    'and the two `*Paging` objects say which page the arrays are.',
    {
      baseDn: { type: 'string' },
      container: { type: 'string', description: 'The ou=spiffe DN.' },
      entriesContainer: { type: 'string' },
      agentsContainer: { type: 'string' },
      entries: { type: 'integer',
                 description: 'HOW MANY registration entries there are, not ' +
                              'the entries themselves — those are ' +
                              '`registrationEntries`.' },
      agents: { type: 'integer', description: 'How many agents have attested.' },
      maxEntries: { type: 'integer' },
      maxAgents: { type: 'integer' },
      sourceOfTruth: { type: 'string' },
      filter: openObject('What was asked for; null where nothing was.', {}),
      editable: { type: 'array', items: { type: 'string' },
                  description: 'Which attributes the console will change. An ' +
                               'ldapmodify reaches everything either way.' },
      schema: openObject('The object classes and the attributes, read out of ' +
                         'spiffe/spiffe_registry.js.', {}),
      entriesPaging: pagingObject('the registration entries'),
      agentsPaging: pagingObject('the attested agents'),
      registrationEntries: { type: 'array',
                             items: openObject('One registration entry.', {}) },
      attestedAgents: { type: 'array',
                        items: openObject('One attested agent.', {}) }
    }),

  DirectoryService: openObject(
    'What the embedded directory IS right now, as opposed to what it is SET ' +
    'to be — which is GET /admin-api/ldap. The two disagree on a host whose ' +
    'own slapd already holds 389, and that disagreement is the whole reason ' +
    'both exist.',
    {
      url: { type: 'string' },
      port: { type: 'integer' },
      listening: {
        type: 'boolean',
        description: 'Whether the plain listener actually bound. Reported ' +
                     'separately from LDAPS because they bind independently ' +
                     'and "389 is up and 636 is not" is the ordinary outcome ' +
                     'of a host run that is not root.'
      },
      listenError: { type: 'string' },
      tls: openObject('The LDAPS socket, its certificate and what a client ' +
                      'certificate presented to it does — which is nothing.', {}),
      baseDn: { type: 'string' },
      usersDn: { type: 'string' },
      groupsDn: { type: 'string' },
      namingContexts: { type: 'array', items: { type: 'string' },
                        description: 'One per trust realm.' },
      searchScope: { type: 'string',
                     description: 'What a subtree search from each of those ' +
                                  'answers about.' },
      ldapVersion: { type: 'integer' },
      bindPolicy: { type: 'string',
                    description: 'Every bind succeeds. This says so in the ' +
                                 'reply rather than only on the page.' },
      refusedPassword: { type: 'string',
                         description: 'The ONE literal password answered ' +
                                      'LDAP_INVALID_CREDENTIALS (49), so ' +
                                      'that a negative test has something ' +
                                      'to fail on.' },
      schema: { type: 'string',
                description: 'A SENTENCE and not an object: this directory ' +
                             'has no schema, and saying so is the answer.' },
      referentialIntegrity: { type: 'boolean' },
      autoCreateUsers: { type: 'boolean' },
      autoCreateRule: { type: 'string' },
      authenticationFacts: { type: 'string' },
      enforcedRules: { type: 'array', items: { type: 'string' },
                       description: 'What this directory does still refuse, ' +
                                    'schemaless as it is.' },
      persistence: openObject('Whether any of it survives a restart, where ' +
                              'it is written, and whether the last write ' +
                              'worked.', {}),
      limits: openObject('The caps and the counts. `currentEntries` is this ' +
                         'realm\'s and `currentEntriesEverywhere` is the ' +
                         'process\'s, because the cap is on the process.', {}),
      operations: { type: 'array', items: { type: 'string' } },
      specifications: { type: 'array', items: { type: 'string' } },
      implementation: { type: 'string' }
    }),

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
      },
      homes: {
        type: 'array',
        description: 'WHERE EACH GROUP IS EDITED. Since 2026-08-27 every ' +
                     'group is drawn on the console page for the protocol it ' +
                     'configures rather than all of them on /admin/config, ' +
                     'and this says which — so a caller can send a person to ' +
                     'the right page instead of to a table of a hundred and ' +
                     'fifty-four rows. A row may name TWO pages: `saml.issuer` ' +
                     'governs both SAML profiles and WS-Federation, so it is ' +
                     'drawn on both SAML pages. Every one of those forms ' +
                     'posts to the same four actions below, so this changes ' +
                     'nothing about how a setting is written.',
        items: openObject('One group, and the page or pages that draw it.', {
          group: { type: 'string' },
          pages: { type: 'array', items: { type: 'string' } },
          labels: { type: 'array', items: { type: 'string' },
                    description: 'The pages\' console labels, in the same ' +
                                 'order, read off the console\'s own ' +
                                 'navigation rather than repeated here.' }
        })
      },
      homeProblems: {
        type: 'array', items: { type: 'string' },
        description: 'Empty, and reported rather than left implicit. A ' +
                     'sentence here means a setting group exists that no ' +
                     'console page draws — the drift this service checks for ' +
                     'at startup and refuses to be quiet about, since a ' +
                     'setting that is read and appears nowhere is worse than ' +
                     'one that is missing.'
      }
    }),

  // The shape every page that OWNS SETTINGS answers with, and one schema
  // rather than eight: the eight protocol settings pages differ in prose and
  // in which group they draw, and a schema per page would have been eight
  // copies of this. It is also what the `settings` member of the SAML, SCIM,
  // SPIFFE, federation and directory pages carries, so a caller learns one
  // shape and reads it everywhere.
  PageSettings: openObject(
    'One console page, and the settings it draws. The settings are the same ' +
    'described rows GET /config returns — value, text, source, editable, ' +
    'bounds — filtered to the ones that page owns.',
    {
      page: { type: 'string', description: 'The console path this mirrors.' },
      title: { type: 'string' },
      what: { type: 'string',
              description: 'What the page says the family is, as plain text.' },
      notes: { type: 'array', items: { type: 'string' },
               description: 'The caveats the page carries, in order. On these ' +
                            'pages the caveats are most of the content — what ' +
                            'a family does NOT check is the half a client ' +
                            'author cannot read off a protocol trace.' },
      links: { type: 'array',
               items: openObject('One link the page offers.', {
                 href: { type: 'string' },
                 what: { type: 'string' }
               }) },
      settings: SETTINGS_BLOCK
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

  SamlAssertions: openObject(
    'The DEFAULTS every SAML application inherits: how long an assertion is ' +
    'valid for in each profile, whether it and its response are signed, the ' +
    'NameID format, the artifact lifetime, and the clock skew written into ' +
    'both ends of the window. Eleven of the settings GET /config returns, ' +
    'with `perApplication` naming the entry attribute that overrides each.',
    {
      assertions: openObject(
        'The three effective values, plus the two figures no single setting ' +
        'states. THE LIFETIMES ARE MINUTES AND THE SKEW IS SECONDS, which is ' +
        'the unit each setting is declared in.',
        {
          saml2LifetimeMin: { type: 'integer' },
          saml11LifetimeMin: { type: 'integer' },
          clockSkewS: {
            type: 'integer',
            description: 'Added to BOTH ENDS of every assertion this service ' +
                         'issues: `Conditions/NotBefore` is backdated by it ' +
                         'and `NotOnOrAfter` extended by it, in SAML 2.0 and ' +
                         'SAML 1.1 alike and therefore in WS-Trust and ' +
                         'WS-Federation too. `IssueInstant` and the ' +
                         'authentication instant are NOT moved — those state ' +
                         'when something happened. 0, the default, is what ' +
                         'this service always did. It is not ' +
                         'oauth2.clockSkewS, which is the tolerance applied ' +
                         'when this service READS a document back.'
          },
          saml2WindowS: {
            type: 'integer',
            description: 'The whole width of the window a SAML 2.0 assertion ' +
                         'states, in seconds: the lifetime plus TWICE the ' +
                         'skew. This is the figure a relying party ' +
                         'experiences and it is what makes a large skew ' +
                         'visible as the lifetime extension it is.'
          },
          saml11WindowS: {
            type: 'integer',
            description: 'The same for a SAML 1.1 assertion.'
          }
        }),
      perApplication: {
        type: 'array',
        description: 'WHICH OF THESE AN APPLICATION MAY OVERRIDE, and the ' +
                     'attribute that does it. Ten of the eleven: every ' +
                     'setting here except the clock skew, which is a fact ' +
                     'about the estate rather than about one relying ' +
                     'party.\n\nSet the named attribute on an application ' +
                     'entry — `POST /admin-api/applications/set` with ' +
                     '`attribute` and `value`, on the console\'s New ' +
                     'application form, or with an `ldapmodify` — and that ' +
                     'application stops inheriting the row beside it. An ' +
                     'ABSENT attribute means inherit; there is no third ' +
                     'state, and clearing the attribute restores the ' +
                     'default.\n\nA value that will not parse is IGNORED ' +
                     'and logged, not refused: the directory is a vocabulary ' +
                     'rather than a constraint here, and an identity ' +
                     'provider that stopped issuing because somebody typed ' +
                     '"yes" would be a mock that stopped answering.',
        items: openObject('One overridable setting.', {
          setting: { type: 'string',
                     description: 'The appconfig key, as in GET /config.' },
          attribute: { type: 'string',
                       description: 'The application entry attribute that ' +
                                    'overrides it.' },
          profile: { type: 'string',
                     description: '`saml2` or `saml11`. The two are ' +
                                  'independent: an application declared for ' +
                                  'both carries two lifetimes and gets each ' +
                                  'where it applies.' }
        })
      },
      settings: {
        type: 'array',
        description: 'The same eleven as full configuration rows — bounds, ' +
                     'source, default and prose — in the shape GET /config ' +
                     'uses, so a client renders them with one piece of code.',
        items: CONFIG_SETTING
      },
      assertionsIssued: openObject(
        'What has already been issued, per profile, counted against this ' +
        'service\'s own clock with NO allowance applied — the skew is ' +
        'written into an assertion rather than applied when one is read ' +
        'here, so an assertion counted expired is one whose stated ' +
        'NotOnOrAfter has passed. CHANGING A SETTING DOES NOT MOVE THESE — ' +
        'a window is stamped into an assertion when it is signed. The counts ' +
        'are of the artifacts still held, which is a rolling window capped ' +
        'at `cap`.',
        {
          held: {
            type: 'integer',
            description: 'Artifacts of EVERY kind still held, not only ' +
                         'assertions: it is the cap below that these are ' +
                         'counted against, and Kerberos tickets and ' +
                         'credentials share it.'
          },
          forgotten: { type: 'integer' },
          cap: { type: 'integer' },
          byKind: {
            type: 'array',
            description: 'One row per profile — `SAML 2.0` and `SAML 1.1` — ' +
                         'always both, with zeroes where nothing has been ' +
                         'issued, so a client need not handle an absent row.',
            items: openObject('One profile.', {
              kind: { type: 'string' },
              issued: { type: 'integer' },
              valid: { type: 'integer' },
              expired: { type: 'integer' },
              noExpiry: { type: 'integer' }
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
    'Token — and the rules that govern them. The UserInfo set is at GET ' +
    '/admin-api/userinfo-claims and the two SAML sets at GET ' +
    '/admin-api/saml-attributes; one store answers all three.',
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

  UserInfoClaimSets: openObject(
    'The `userinfo` claim set — what every UserInfo response carries — and the ' +
    'OpenID Connect Core section 5.5 vocabulary a CLIENT may add to it. ' +
    'Everything except `claimsRequest` is the shape GET /admin-api/claims ' +
    'answers for the two JWT sets; one store answers all three resources.',
    Object.assign({
      reservedJwtClaims: {
        type: 'array', items: { type: 'string' },
        description: 'Claim names this service sets itself. Adding one is ' +
                     'REFUSED. The list IS enforced here, unlike on the two ' +
                     'SAML sets, and the reason is not a copy-paste: `sub` is ' +
                     'required in this response by OIDC Core 5.3.2 and a ' +
                     'client MUST check it against the ID Token\'s, and the ' +
                     'signed form of the same response — for a client that ' +
                     'registered a userinfo_signed_response_alg — is a JWT ' +
                     'carrying iss, aud and exp.'
      },
      claimsRequest: openObject(
        'THE HALF NO OPERATION HERE SETS. OpenID Connect Core section 5.5 lets ' +
        'a client name individual claims in the `claims` request parameter at ' +
        'the authorization endpoint, and this service parses it, refuses a ' +
        'malformed one by name, carries it on the authorization code and ' +
        'INSIDE the access token, and answers it by reading the named claims ' +
        'off that person\'s entry under ou=users.',
        {
          supported: {
            type: 'boolean',
            description: 'The same fact `claims_parameter_supported` states in ' +
                         'the OpenID Provider metadata, where it said false ' +
                         'until 2026-08-26.'
          },
          members: {
            type: 'array', items: { type: 'string' },
            description: 'The two top-level members section 5.5 defines and ' +
                         'this service acts on. Any OTHER top-level member is ' +
                         'ignored rather than refused — the section says ' +
                         'others MAY be defined — and the ignored names are ' +
                         'reported in `preview.ignoredMembers` so that ' +
                         '"ignored" and "not understood" are distinguishable.'
          },
          maxClaims: {
            type: 'integer',
            description: 'How many claims one request may name. The parsed ' +
                         'request is copied into the access token, and one ' +
                         'large enough to overflow a header would fail at a ' +
                         'client in a way nothing points back here.'
          },
          requestable: {
            type: 'array',
            description: 'Every name a request may use. A nested claim appears ' +
                         'twice: by its flat name (`address.locality`) and by ' +
                         'its top-level name alone (`address`), which returns ' +
                         'the whole Address Claim of OIDC Core 5.1.1 as one ' +
                         'object and is the spelling section 5.5.1\'s own ' +
                         'example uses. A language tag is part of the name ' +
                         '(Core 5.2): `family_name#ja-Kana-JP` is answered ' +
                         'under exactly that name with the one value this ' +
                         'service holds.',
            items: openObject('One requestable claim.', {
              claim: { type: 'string' },
              ldap: { type: 'string' },
              label: { type: 'string' },
              grouped: { type: 'boolean' }
            })
          },
          fromTheSignIn: {
            type: 'array', items: { type: 'string' },
            description: 'The claims this service invents from the username ' +
                         'rather than reading off an entry. They are ' +
                         'answerable too, and they are listed apart because ' +
                         'the difference is the interesting part: an ' +
                         '`ldapmodify` moves everything in `requestable` and ' +
                         'moves none of these.'
          },
          precedence: {
            type: 'array', items: { type: 'string' },
            description: 'The four layers of the response, outermost last. ' +
                         'Layer 3 beating layer 2 is the one choice that is ' +
                         'not obvious: a scope asks for a category and a ' +
                         'claims request names a claim.'
          },
          notEnforced: {
            type: 'array', items: { type: 'string' },
            description: 'What is carried and deliberately not acted on, with ' +
                         'the reason for each. `essential` is a hint (5.5.1 ' +
                         'says a server MUST NOT error for an unavailable ' +
                         'claim); `value` and `values` are checked and ' +
                         'reported rather than echoed back.'
          },
          directParameter: openObject(
            'NON-SPEC. The UserInfo endpoint also accepts a claims request on ' +
            'the request itself, which section 5.3.1 does not define. It is a ' +
            'union with what the access token carries and can never take a ' +
            'claim away from it.', {}),
          preview: openObject(
            'What the `request` query parameter would return for `user`, ' +
            'computed by the two functions the UserInfo endpoint itself calls. ' +
            '`asked` is false when no request was given; `ok` is false, with ' +
            '`error`, when the request is one the authorization endpoint would ' +
            'refuse `invalid_request` — which is shown rather than corrected.',
            {})
        })
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

  Ssf: openObject(
    'The Shared Signals transmitter: the streams it has agreed, who each one ' +
    'is about, what is queued for it, what a receiver refused, and what has ' +
    'been pushed AT this service. SSF is the PIPE and not the vocabulary — ' +
    'it defines two events of its own, both about the pipe, and CAEP and ' +
    'RISC are the vocabularies spoken over it. CAEP is implemented and has ' +
    'a register of its own at GET /admin-api/caep; RISC is not here yet.',
    {
      installed: {
        type: 'boolean',
        description: 'Whether ssf/ssf.js is loaded in this process at all. A ' +
                     'DIFFERENT question from `enabled`, exactly as it is ' +
                     'for SCIM: a process that never required it has no /ssf ' +
                     'routes, where one with ssf.enabled false has routes ' +
                     'that answer 501.'
      },
      enabled: {
        type: 'boolean',
        description: 'The `ssf.enabled` setting. When false every endpoint ' +
                     'answers 501 EXCEPT the transmitter metadata, which ' +
                     'goes on answering so that a receiver can tell "this ' +
                     'service does not speak SSF" from "the path is wrong".'
      },
      issuer: {
        type: 'string',
        description: 'The `iss` of every Security Event Token this ' +
                     'transmitter signs, and of its configuration metadata. ' +
                     'A receiver matches the two, so they are one string.'
      },
      signingAlgorithm: {
        type: 'string',
        description: 'What SETs are signed with (`ssf.signingAlgorithm`). It ' +
                     'reaches the whole JWS table, post-quantum included, ' +
                     'because a SET goes through the same signer every other ' +
                     'JWT here does.'
      },
      metadataUrl: {
        type: 'string',
        description: 'Where the never-gated transmitter configuration ' +
                     'document is.'
      },
      streamDetail: {
        type: 'array',
        description: 'One entry per stream: its configuration, its subjects, ' +
                     'what is queued, its counters and its own log. The ' +
                     'receiver\'s `authorization_header` is NEVER in it — it ' +
                     'is a credential belonging to somebody else\'s ' +
                     'endpoint, and this resource is not the door it goes ' +
                     'back through.',
        items: { type: 'object' }
      },
      receivedDetail: {
        type: 'array',
        description: 'What POST /ssf/receive has taken, newest first, with ' +
                     'whether each signature verified and whether the ' +
                     'application/secevent+jwt media type was used.',
        items: { type: 'object' }
      },
      settings: {
        type: 'object',
        description: 'The `SSF` setting group as /admin/ssf draws it, with ' +
                     'each row\'s source and whether it is editable at ' +
                     'runtime. Change one through POST ' +
                     '/admin-api/config/set-many, which is why there is no ' +
                     'settings operation of this resource\'s own.'
      }
    }),

  CaepApplication: openObject(
    'One receiver, and everything this transmitter has said to it.',
    {
      identifier: { type: 'string',
                    description: 'What it authenticated as when it created ' +
                                 'the stream, which is the `ssfReceiverId` on ' +
                                 'its application entry.' },
      name: { type: 'string' },
      registered: { type: 'boolean',
                    description: 'FALSE only on the collected row for streams ' +
                                 'that belong to no application entry.' },
      declared: { type: 'boolean',
                  description: 'Whether an operator ticked Shared Signals on ' +
                               'the entry, as opposed to the entry appearing ' +
                               'because a stream was created.' },
      dn: { type: 'string' },
      endpoints: { type: 'array', items: { type: 'string' },
                   description: 'The `ssfDeliveryEndpoint` values on the ' +
                                'entry — what an operator wrote down that a ' +
                                'receiver is EXPECTED to be. A stream carries ' +
                                'its own delivery endpoint and this is not ' +
                                'read as one.' },
      streams: { type: 'array', items: { type: 'string' } },
      streamCount: { type: 'integer' },
      enabled: { type: 'integer',
                 description: 'How many of those streams are enabled.' },
      deliveries: { type: 'array', items: { type: 'string' } },
      audiences: { type: 'array', items: { type: 'string' } },
      takes: { type: 'array', items: { type: 'string' },
               description: 'The CAEP types its streams deliver, as short ' +
                            'names. EMPTY is the answer to half the "nothing ' +
                            'arrived" reports there are.' },
      counts: { type: 'object',
                description: 'Event type URI -> how many have been said to ' +
                             'this receiver, across every session.' },
      total: { type: 'integer' },
      sessions: { type: 'integer' },
      queued: { type: 'integer' },
      delivered: { type: 'integer' },
      failed: { type: 'integer' },
      acknowledged: { type: 'integer' },
      receiverErrors: { type: 'integer' },
      lastPushAt: { type: 'string' },
      lastPushError: { type: 'string' }
    }),

  Caep: openObject(
    'The Continuous Access Evaluation Profile: what state each session is in ' +
    'and how many events of which type have been sent about it. CAEP is a ' +
    'VOCABULARY over Shared Signals rather than a family of its own — its ' +
    'events travel on SSF streams, are signed by the SSF signer and are ' +
    'delivered by the two SSF deliveries — so the streams themselves are at ' +
    'GET /admin-api/ssf and only their CAEP-relevant half is repeated here.',
    {
      installed: {
        type: 'boolean',
        description: 'Whether ssf/ssf.js is loaded in this process at all. A ' +
                     'DIFFERENT question from `enabled`, and CAEP cannot be ' +
                     'installed without SSF: it has no transport of its own.'
      },
      enabled: {
        type: 'boolean',
        description: 'The `caep.enabled` setting. When false the eight event ' +
                     'types are dropped from `events_supported`, so a stream ' +
                     'asking for one gets it back MISSING from ' +
                     '`events_delivered` — which is the only notice SSF ' +
                     'gives, and is exactly the case a receiver ought to be ' +
                     'tested against. SSF itself is unaffected.'
      },
      autoEmit: {
        type: 'boolean',
        description: 'The `caep.autoEmit` setting, and the one that changes ' +
                     'what this service IS. With it on, a sign-in, a single ' +
                     'sign-on and a sign-out each send a Security Event ' +
                     'Token with nobody having asked — the only place here ' +
                     'where an endpoint is not what starts the work.'
      },
      autoEmitActs: {
        type: 'array',
        description: 'Which of the three observable acts emit on their own. ' +
                     'The other five event types describe things nothing ' +
                     'here does, so they are only ever emitted by hand.',
        items: { type: 'string' }
      },
      omitEventTimestamp: {
        type: 'boolean',
        description: 'The deliberate defect that is not one. ' +
                     '`event_timestamp` is OPTIONAL in CAEP section 2, so an ' +
                     'event without it is perfectly conforming — and every ' +
                     'receiver that assumes it is there breaks on a ' +
                     'transmitter that omits it.'
      },
      tracked: {
        type: 'integer',
        description: 'How many sessions the register holds, capped by ' +
                     '`caep.maxSessionsTracked` with the oldest going first.'
      },
      totals: {
        type: 'object',
        description: 'How many of each event type have been sent, across ' +
                     'every session.'
      },
      applications: {
        type: 'array',
        description: 'WHAT THIS TRANSMITTER HAS SAID TO EACH RECEIVER, ' +
                     'across every session — one row per application that ' +
                     'supports CAEP, which is the Shared Signals family in ' +
                     'the registry: declared with the `ssf` checkbox, seen ' +
                     'when a stream was created, or holding an ' +
                     '`ssfReceiverId`.\n\n**An application with NO STREAM is ' +
                     'a row rather than an omission** — it is the commonest ' +
                     'state a receiver under test is in, and a list that ' +
                     'showed only receivers with streams would answer "where ' +
                     'is my application" with silence. A row named `(no ' +
                     'application …)` is the collected total for streams ' +
                     'agreed while `ssf.authRequired` was off: there was no ' +
                     'principal to record and the events are real.\n\n`counts` ' +
                     'is per event type and never forgets; it is counted when ' +
                     'the Security Event Token is built and QUEUED, so a poll ' +
                     'stream nobody has polled yet still shows what is ' +
                     'waiting. `delivered` and `failed` are the pipe, and are ' +
                     'a different number from `total` for exactly that ' +
                     'reason. `sessions` is the DISTINCT sessions the ' +
                     'receiver has been told about across all of its streams ' +
                     'together.\n\n`identifier` is what the receiver ' +
                     'authenticated as; `audiences` is what it asked its SETs ' +
                     'to be addressed to. They are different fields — `aud` ' +
                     'is required on a stream and is never defaulted to the ' +
                     'caller — and this is the only place both are reported.',
        items: { $ref: '#/components/schemas/CaepApplication' }
      },
      eventTypes: {
        type: 'array',
        description: 'The eight, with their short names — which is what the ' +
                     '`emit` action and `caep.eventsSupported` both take, ' +
                     'because these URIs are sixty characters long.',
        items: { type: 'object' }
      },
      catalogue: {
        type: 'array',
        description: 'The same eight opened out: every member the ' +
                     'specification gives each event, whether it is ' +
                     'required, its type and its permitted values, and the ' +
                     'four claims CAEP gives them all.',
        items: { type: 'object' }
      },
      sessions: {
        type: 'array',
        description: 'One entry per session this service has held, ' +
                     'INCLUDING ONES IT NO LONGER HOLDS — a row saying ' +
                     '`revoked` is the only remaining evidence that the ' +
                     'session existed and was revoked, and nothing else in ' +
                     'this service records it. Each carries the CAEP state, ' +
                     'the assurance level, the device compliance, the risk ' +
                     'level, the claims that have changed, a count per event ' +
                     'type, and the last few events with their jtis.',
        items: { type: 'object' }
      },
      streams: {
        type: 'array',
        description: 'Which streams would take a CAEP event at all. It is ' +
                     'here rather than only on the Ssf resource because a ' +
                     'session with a count of zero almost always means ' +
                     'nobody asked for that type, and SSF gives a receiver ' +
                     'no other notice of that.',
        items: { type: 'object' }
      },
      settings: {
        type: 'object',
        description: 'The `CAEP` setting group as /admin/caep draws it. ' +
                     'Change one through POST /admin-api/config/set-many.'
      }
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

  // ---------------------------------------------------------------------------
  // DELEGATION. Written out rather than left open for the reason AuditEvent is:
  // a caller filtering, alerting on or DRAWING this list needs a name for every
  // field, and the picture is the point of it.
  // ---------------------------------------------------------------------------
  DelegationParty: openObject(
    'One layer of the architecture. Each of the three roles uses this shape ' +
    'and each can be an identity, an application, or BOTH — which is the fact ' +
    'that makes the model protocol-independent rather than a Kerberos model ' +
    'the other two are squeezed into.',
    {
      key: {
        type: 'string',
        description: 'The NORMALISED local name, so a party here and a row on ' +
                     '/admin-api/users name the same person — `alice`, ' +
                     '`urn:sts-mock:user:alice` and `alice@STS.MOCK` are one ' +
                     'identity. Empty where this layer is an application ' +
                     'rather than a person, or where nothing named it.'
      },
      presented: {
        type: 'string',
        description: 'The identity exactly as it arrived, when that differs ' +
                     'from `key` — a Kerberos principal, a NameID, a `sub`. ' +
                     'Both are carried because the collapse from one to the ' +
                     'other is something a reader has to be able to see.'
      },
      application: {
        type: 'string',
        description: 'The application this layer IS — a client_id, an ' +
                     'AppliesTo, an SPN, an audience. NOT a promise that an ' +
                     'entry exists under ou=applications: that registry holds ' +
                     'what this service has been ASKED ABOUT, and a ' +
                     'delegation naming something nobody has otherwise ' +
                     'mentioned is an ordinary and interesting outcome. Look ' +
                     'it up on /admin-api/applications to find out which.'
      },
      what: { type: 'string',
              description: 'What this party is in THIS act, in the ' +
                           'protocol\'s own words.' }
    }),

  DelegationCredential: openObject(
    'One credential presented or produced. NO CREDENTIAL IS EVER CARRIED — ' +
    'only what kind it was and its identifier, which is the rule the audit ' +
    'log follows and applies here twice over: a delegation is precisely the ' +
    'request that carries two credentials at once.',
    {
      kind: { type: 'string',
              description: '`subject_token`, `actor_token`, `access_token`, ' +
                           '`Kerberos evidence ticket`, `SAML 2.0 assertion`, ' +
                           '`PA-FOR-USER`, and so on.' },
      identifier: {
        type: 'string',
        description: 'A `jti` or an AssertionID. EMPTY for a Kerberos ticket, ' +
                     'which genuinely has none in the protocol, and for the ' +
                     'WS-Trust JWT, which is signed directly rather than ' +
                     'through this service\'s JWT funnel and so carries no ' +
                     '`jti` and is in no register. `note` says which.'
      },
      note: { type: 'string',
              description: 'What is worth knowing about this credential — ' +
                           'whether it verified, whether it was forwardable.' }
    }),

  DelegationAct: openObject(
    'ONE ACT: a single exchange at a single moment in which somebody acted on ' +
    'somebody else\'s behalf. Not a relationship — the same three parties ' +
    'appearing eleven times is eleven acts, and `chainKey` is what collapses ' +
    'them.',
    {
      seq: {
        type: 'integer',
        description: 'Monotonic and NEVER REUSED, including across a drop. ' +
                     'The stable name for an act and the thing to walk this ' +
                     'list by.'
      },
      at: { type: 'integer', description: 'Milliseconds since the epoch.' },
      protocol: { type: 'string',
                  description: 'The family, spelled as /admin-api/users ' +
                               'spells it.' },
      type: { type: 'string',
              description: 'The mechanism, as its specification names it. The ' +
                           'list\'s `types` member describes each one.' },
      typeLabel: { type: 'string', description: 'That mechanism in words.' },
      mode: {
        type: 'string',
        enum: ['impersonation', 'delegation'],
        description: 'THE AXIS WORTH READING FIRST. `delegation` means the ' +
                     'credential carries the chain and the far end can see ' +
                     'who is really asking. `impersonation` means nothing ' +
                     'does — so this record is the only place the fact will ' +
                     'ever exist.'
      },
      spec: { type: 'string',
              description: 'Where the mechanism is defined.' },
      policed: {
        type: 'boolean',
        description: 'Whether THIS SERVICE decided who may perform the act. ' +
                     'True for the three Kerberos S4U mechanisms and false ' +
                     'for everything else, which is a real asymmetry rather ' +
                     'than an omission — see `authorizedBy`.'
      },
      outcome: { type: 'string', enum: ['issued', 'refused'] },
      initial: { $ref: '#/components/schemas/DelegationParty' },
      intermediary: { $ref: '#/components/schemas/DelegationParty' },
      target: { $ref: '#/components/schemas/DelegationParty' },
      chainKey: {
        type: 'string',
        description: 'The identity of the CHAIN rather than of the act: the ' +
                     'mechanism and the three parties, with the time, the ' +
                     'credentials and the OUTCOME left out. Acts sharing one ' +
                     'are one edge of the picture — and the outcome is out of ' +
                     'it deliberately, so a chain refused nine times and then ' +
                     'fixed is one edge that changes rather than two that ' +
                     'never meet.'
      },
      authorizedBy: {
        type: 'string',
        description: 'What PERMITTED it: the attribute AND the account it is ' +
                     'on, in the KDC\'s own words. For the unpoliced ' +
                     'mechanisms it says so and says why — that sentence is ' +
                     'the point rather than a placeholder.'
      },
      reason: {
        type: 'string',
        description: 'Why it was REFUSED — the `e-text` of the error the ' +
                     'client was sent, not a second wording that could come ' +
                     'to disagree with it. Empty on an issued act.'
      },
      consumed: { type: 'array',
                  items: { $ref: '#/components/schemas/DelegationCredential' } },
      produced: { type: 'array',
                  items: { $ref: '#/components/schemas/DelegationCredential' } },
      sessionId: {
        type: 'string',
        description: 'The browser sign-on session, where there was one. ' +
                     'USUALLY EMPTY, and that is a fact about delegation ' +
                     'rather than a gap in the recording: a service asking on ' +
                     'somebody\'s behalf has no browser anywhere in it.'
      },
      note: { type: 'string', description: 'One sentence of context.' }
    }),

  DelegationChain: openObject(
    'One DISTINCT chain among the acts that matched — one edge of the ' +
    'picture. This is the more useful answer to "what talks to what".',
    {
      chainKey: { type: 'string' },
      protocol: { type: 'string' },
      type: { type: 'string' },
      typeLabel: { type: 'string' },
      mode: { type: 'string', enum: ['impersonation', 'delegation'] },
      initial: { $ref: '#/components/schemas/DelegationParty' },
      intermediary: { $ref: '#/components/schemas/DelegationParty' },
      target: { $ref: '#/components/schemas/DelegationParty' },
      acts: { type: 'integer', description: 'How many acts are on this edge.' },
      issued: { type: 'integer' },
      refused: { type: 'integer' },
      firstAt: { type: 'integer' },
      lastAt: { type: 'integer' },
      authorizedBy: { type: 'string',
                      description: 'From the MOST RECENT act on the chain, so ' +
                                   'an edge that was fixed says how it works ' +
                                   'now rather than why it used to fail.' },
      reason: { type: 'string', description: 'Likewise, for a refusal.' }
    }),

  DelegationPolicy: openObject(
    'WHO MAY DELEGATE TO WHOM, before anybody has tried. KERBEROS ONLY, and ' +
    'that is not an omission: Kerberos is the only family here that polices ' +
    'delegation at all. WS-Trust puts no authorization on OnBehalfOf or ' +
    'ActAs, and RFC 8693 leaves the policy to the authorization server, which ' +
    'this one does not have.',
    {
      pairs: {
        type: 'array',
        description: 'One per (front end, target, mechanism). The two ' +
                     'mechanisms are in ONE list because the messages and the ' +
                     'KDC options are identical and the whole difference is ' +
                     'which of the two accounts carries the permission — ' +
                     'which is `setOn`.',
        items: openObject('One configured pair.', {
          mechanism: { type: 'string', enum: ['classic', 'rbcd'] },
          type: { type: 'string',
                  description: 'The same mechanism id an ACT carries, so the ' +
                               'two halves of this resource can be read ' +
                               'against each other without a second lookup ' +
                               'table.' },
          frontEnd: { type: 'string', description: 'Who may act.' },
          target: { type: 'string', description: 'What may be reached.' },
          realm: { type: 'string' },
          attribute: { type: 'string',
                       description: '`msDS-AllowedToDelegateTo` or ' +
                                    '`msDS-AllowedToActOnBehalfOfOtherIdentity`.' },
          setOn: {
            type: 'string',
            description: 'THE ACCOUNT THE PERMISSION LIVES ON, and the field ' +
                         'to read first. Classic puts it on the front end, ' +
                         'where only a domain admin can set it; resource-based ' +
                         'puts it on the back end, where whoever controls that ' +
                         'object can set it themselves. That is the entire ' +
                         'security story of RBCD.'
          },
          setOnRole: { type: 'string', enum: ['front end', 'back end'] },
          requires: { type: 'string',
                      description: 'What ELSE the mechanism needs beyond the ' +
                                   'attribute.' },
          targetKnown: { type: 'boolean',
                         description: 'Whether this KDC has a principal by ' +
                                      'that name. A misspelt SPN fails at TGS ' +
                                      'time with an error about ' +
                                      'authorization rather than spelling.' },
          warning: {
            type: 'string',
            description: 'Why this pair may still fail although the attribute ' +
                         'names it. The expensive one: a front end with no ' +
                         'TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION gets a ' +
                         'non-forwardable ticket out of S4U2Self, so classic ' +
                         'S4U2Proxy then fails complaining about the evidence ' +
                         '— two steps from the attribute that caused it.'
          },
          note: { type: 'string' }
        })
      },
      accounts: {
        type: 'array',
        description: 'Principals carrying a flag that changes what delegation ' +
                     'can do to them or with them. Two of the three STOP ' +
                     'delegation rather than permit it, and one is not a ' +
                     'control at all. Listed whether or not a pair names ' +
                     'them.',
        items: openObject('One account.', {
          principal: { type: 'string' },
          realm: { type: 'string' },
          notDelegated: { type: 'boolean' },
          trustedToAuthenticateForDelegation: { type: 'boolean' },
          okAsDelegate: {
            type: 'boolean',
            description: 'ADVICE TO THE CLIENT and not a control: it tells a ' +
                         'client this service may be trusted with forwarded ' +
                         'credentials, a client is free to ignore it, and ' +
                         'this KDC enforces nothing by it.'
          },
          autoCreated: { type: 'boolean' },
          description: { type: 'string' },
          effects: { type: 'array', items: { type: 'string' },
                     description: 'What each flag actually does.' }
        })
      }
    }),

  DelegationList: openObject(
    'Who acted on whose behalf, newest first, filtered and paged — plus the ' +
    'distinct chains among the match and the configured policy behind the ' +
    'Kerberos ones.\n\nWalk it with `seq` rather than with `page`: acts are ' +
    'still being recorded while you page.',
    Object.assign({
      held: { type: 'integer', description: 'Acts currently held.' },
      recorded: {
        type: 'integer',
        description: 'Acts recorded since this process started. Greater than ' +
                     '`held` once the cap has bitten — `held` alone would ' +
                     'read as "this is all there ever was".'
      },
      dropped: { type: 'integer',
                 description: 'Acts discarded to stay under the cap, oldest ' +
                              'first.' },
      maxRecords: { type: 'integer',
                    description: 'The cap: `delegation.maxRecords`, ' +
                                 'changeable at runtime through ' +
                                 'POST /admin-api/config/set.' },
      matched: { type: 'integer' },
      shown: { type: 'integer' },
      oldestSeq: { type: 'integer' },
      newestSeq: { type: 'integer' },
      byType: openObject('How many held acts used each mechanism. EVERY ' +
                         'mechanism appears, including the ones at zero, ' +
                         'because "does this server do RBCD" is otherwise ' +
                         'answered by omission.', {}),
      byMode: openObject('How many were impersonations and how many carried ' +
                         'the chain.', {}),
      byOutcome: openObject('How many were issued and how many refused.', {}),
      byProtocol: openObject('How many came from each family. Only families ' +
                             'that have delegated appear.', {}),
      filter: openObject('What was asked for; null where nothing was.', {}),
      types: {
        type: 'array',
        description: 'The eight mechanisms with the specification each comes ' +
                     'from, what it is, and whether this service polices it — ' +
                     'what the `type` filter takes. Read off the same table ' +
                     'the store records against, so a mechanism cannot occur ' +
                     'and be unfilterable nor be offered and never occur.',
        items: openObject('One mechanism.', {
          type: { type: 'string' }, protocol: { type: 'string' },
          mode: { type: 'string' }, label: { type: 'string' },
          spec: { type: 'string' }, policed: { type: 'boolean' },
          what: { type: 'string' }
        })
      },
      modes: {
        type: 'array',
        description: 'The two kinds and what each means.',
        items: openObject('One kind.', {
          mode: { type: 'string' }, label: { type: 'string' },
          what: { type: 'string' }
        })
      },
      outcomes: { type: 'array', items: { type: 'string' } },
      roles: {
        type: 'array',
        description: 'The three layers of the architecture, in the order a ' +
                     'request moves through them. The names are this ' +
                     'service\'s own and deliberately not any protocol\'s: ' +
                     'a Kerberos front end, a WS-Trust requester and an OAuth ' +
                     'client doing an exchange are the same position in the ' +
                     'same picture.',
        items: openObject('One layer.', {
          role: { type: 'string' }, label: { type: 'string' },
          what: { type: 'string' }
        })
      },
      acts: { type: 'array',
              items: { $ref: '#/components/schemas/DelegationAct' } },
      chains: {
        type: 'array',
        description: 'The distinct chains among what MATCHED — one per edge ' +
                     'of the picture. Not paged: it cannot be longer than the ' +
                     'list it is derived from.',
        items: { $ref: '#/components/schemas/DelegationChain' }
      },
      applications: {
        type: 'array',
        description: 'Every APPLICATION named by an act among what matched, ' +
                     'in whatever role it played, with what it did. It is a ' +
                     'strictly different question from `chains` and cannot be ' +
                     'derived from one: an application is keyed on its ' +
                     'IDENTIFIER, normalised, while a chain names three ' +
                     'parties — one of which routinely carries an application ' +
                     'identifier that is not its identity (an RFC 8693 ' +
                     'intermediary is an ACTOR who exchanged through a ' +
                     '`client_id`). This is what the chooser on ' +
                     '/admin/delegation is built from, and ' +
                     '/admin/delegation/application is one entry of it drawn ' +
                     'in full.',
        items: openObject('One application, in every role it has played.', {
          key: { type: 'string',
                 description: 'The normalised identifier. Two spellings of ' +
                              'one application are one entry, on the same ' +
                              'normalisation the picture merges boxes with.' },
          identifier: { type: 'string',
                        description: 'The most recent spelling, which is what ' +
                                     'the console shows and links by.' },
          spellings: { type: 'array', items: { type: 'string' },
                       description: 'Every form seen. Carried so that the ' +
                                    'collapse is something a reader can SEE ' +
                                    'rather than take on trust.' },
          identityKey: {
            type: 'string',
            description: 'Set when this application also PRESENTED a ' +
                         'credential — the middle tier that is a person and ' +
                         'an application at once. Empty otherwise.'
          },
          roles: openObject('How many acts it was the initial identity, the ' +
                            'intermediary and the target of. One act can ' +
                            'count twice: an S4U2Self names its requester as ' +
                            'the intermediary AND the target.', {}),
          protocols: { type: 'array', items: { type: 'string' } },
          acts: { type: 'integer',
                  description: 'Acts it took part in, counted ONCE each ' +
                               'however many roles it played in one.' },
          issued: { type: 'integer' }, refused: { type: 'integer' },
          credentials: {
            type: 'integer',
            description: 'Credentials produced by the acts it took part in — ' +
                         'issued THROUGH it where it was the intermediary and ' +
                         'FOR it where it was the target. Both, because ' +
                         '"related to this application" is the question, and ' +
                         'a count that silently meant one of them would be ' +
                         'the wrong answer half the time.'
          },
          chains: { type: 'integer' },
          firstAt: { type: 'integer' }, lastAt: { type: 'integer' }
        })
      },
      policy: { $ref: '#/components/schemas/DelegationPolicy' }
    }, PAGING_PROPERTIES)),

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
  log.debug("Entering operationOf().");
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
    log.debug("Leaving operationOf().");
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
  // EVERY POST DOCUMENTS ITS 400, not only the action resources. A refusal is
  // the reply half a caller has to handle, and it is not a property of being
  // an ACTION — a plain POST that takes a body can refuse it just as an action
  // can refuse its name. This was found by the parity test rather than
  // reasoned about: `POST /admin-api/keys/export` is the first non-action POST
  // this API has had, and it went in documenting a 200 alone.
  if (entry.method === 'POST') {
    operation.responses['400'] = {
      description: 'The operation was refused; `errors` says why and nothing ' +
                   'was handed over.',
      content: { 'application/json': {
        schema: { $ref: '#/components/schemas/ActionResult' } } }
    };
  }
  log.debug("Leaving operationOf().");
  return operation;
}

// The document. `routes` is admin_api.js's table; an entry carrying `actions`
// becomes one operation per action, at the concrete URL each of them has —
// which is a real address even though express serves the six of them from one
// `:action` pattern.
function buildSpec(routes, options) {
  log.debug("Entering buildSpec().");
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
  log.debug("Leaving buildSpec().");
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
