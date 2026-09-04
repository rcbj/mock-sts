'use strict';
//
// File: xacml_store.js
//
// ---------------------------------------------------------------------------
// THE POLICY STORE, AND `ou=policies` IS IT.
//
// There is no store here. A policy is an entry in the embedded directory under
// `ou=policies`, exactly the way `ou=federations` IS the federation register
// and the SPIFFE registry is its two containers — and for the same three
// reasons, none of which is tidiness:
//
//   1. PERSISTENCE COMES FOR FREE, IN ALL THREE MODES. `persistence/` writes
//      the directory, so a policy survives a restart under `postgres` and
//      under `ldif` with nothing added to any driver. A store of this module's
//      own would have needed a fourth thing to persist, three driver changes,
//      and a migration.
//   2. PER-REALM ISOLATION COMES FOR FREE. The directory is `realms.map()`, so
//      `/realm/acme/...` gets its own `ou=policies` and cannot see the default
//      realm's. A `new Map()` here would have been process-wide, and
//      `tests/realm_isolation.js` exists because that mistake has been made in
//      this repository twice already.
//   3. IT IS INSPECTABLE WITH `ldapsearch`, and it appears on
//      `/admin/ldap/directory` beside everything else, rather than being a
//      private table only this module can show anybody.
//
// This module owns the SCHEMA — what a policy entry carries — and the
// directory functions arrive through `setDirectory()`, filled by
// `ldap/ldap_server.js` at require time. That is the same inverted install
// `federation.js`, `spiffe_registry.js` and `scim_map.js` take, and for the
// same reason: this module must not require `ldap_server.js`, because doing so
// would drag every `/ldap` route into the router at whatever point this file
// is first loaded.
//
// ---------------------------------------------------------------------------
// A POLICY IS STORED AS ITS XML, AND THE PARSE IS CACHED BESIDE IT.
//
// The entry holds the DOCUMENT — `xacmlPolicyDocument`, the XACML 3.0 XML as
// written — and not a decomposition of it into attributes. Two reasons, and
// the second is the one that matters:
//
//   * a policy is a document somebody authored, and round-tripping it through
//     a set of LDAP attributes would lose comments, ordering and whitespace
//     that a policy author put there on purpose;
//   * an `ldapmodify` of the document is then a policy change, with no way for
//     the stored XML and a parsed copy to disagree — because there is no
//     stored parsed copy. The cache below is keyed by the document's own
//     digest, so editing the entry through ANY door invalidates it.
//
// The indexed attributes beside it (`xacmlPolicyId`, `xacmlVersion`,
// `xacmlEnabled`, `xacmlCombiningAlgId`) are DERIVED from the document at
// write time. They exist so that the console can list policies without parsing
// every one, and they are never read back as the truth about a policy — if one
// disagrees with the document, the document wins and the attribute is stale.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const { log } = require('../common/helpers');
const model = require('./xacml_model');
const xml = require('./xacml_xml');

// ---------------------------------------------------------------------------
// THE SCHEMA. Published on `/admin/ldap/*` the way every other container's is,
// because this directory is schemaless and a container of entries carrying
// invented attributes needs to say what they mean somewhere.
// ---------------------------------------------------------------------------
const SCHEMA = {
  objectClasses: [
    { name: 'xacmlPolicy',
      what: 'One XACML 3.0 Policy or PolicySet, stored as the document it ' +
            'was authored as. THIS CONTAINER IS THE POLICY REPOSITORY — an ' +
            'ldapmodify of xacmlPolicyDocument here changes what the PDP ' +
            'decides on the next request.' }
  ],
  attributes: [
    { name: 'xacmlPolicyId',
      what: 'The PolicyId or PolicySetId inside the document. DERIVED at ' +
            'write time and used for listing and for resolving a ' +
            'PolicyIdReference; the document is the truth.' },
    { name: 'xacmlPolicyDocument',
      what: 'The XACML 3.0 XML. THIS IS THE POLICY. Everything else on the ' +
            'entry is derived from it.' },
    { name: 'xacmlVersion',
      what: 'The Version attribute of the document. Derived.' },
    { name: 'xacmlKind',
      what: '"Policy" or "PolicySet". Derived.' },
    { name: 'xacmlCombiningAlgId',
      what: 'The rule- or policy-combining algorithm the document names. ' +
            'Derived, and shown on the console because it is the single ' +
            'most consequential line in a policy.' },
    { name: 'xacmlEnabled',
      what: '"TRUE" or "FALSE". A disabled policy stays in the repository ' +
            'and is not evaluated. NOT derived — it is the one thing here ' +
            'that is a fact about the deployment rather than about the ' +
            'document, which is why it is an attribute rather than a ' +
            'comment in the XML.' },
    { name: 'xacmlIsRoot',
      what: '"TRUE" on the policy the PDP starts from. A repository with no ' +
            'root decides nothing and says so; a repository with two is ' +
            'refused at write time rather than picking one.' },
    { name: 'description',
      what: "The document's own <Description>, where it has one." }
  ]
};

// The directory functions, installed by `ldap/ldap_server.js`.
let directory = null;
let warnedAboutNoDirectory = false;

// Parsed policies, keyed by the SHA-256 of the document text. Keyed by content
// rather than by policy id or DN precisely so that a change made through any
// door — the console, `/admin-api`, an `ldapmodify` on 389, an LDIF restore —
// invalidates it without anything having to remember to.
const parsed = new Map();

function setDirectory(fns) {
  log.debug('Entering setDirectory().');
  directory = fns || null;
  log.debug('Leaving setDirectory(). The repository ' +
            (directory ? 'has its container.' : 'has none.'));
}

function haveDirectory() {
  if (directory) {
    return true;
  }
  if (!warnedAboutNoDirectory) {
    warnedAboutNoDirectory = true;
    log.warn('xacml: the embedded directory was never loaded, so there is ' +
             'no ou=policies to hold a policy. The PDP answers ' +
             'NotApplicable to everything and the repository is empty. This ' +
             'is the ordinary state of an in-process test that requires only ' +
             'app.js and one module; it is not a failure, and there is no ' +
             'fallback store, deliberately — a policy repository that ' +
             'quietly lived in memory would decide things nobody could find.');
  }
  return false;
}

// ---------------------------------------------------------------------------
// PARSE, CACHED.
//
// The parse INCLUDES static validation (`xacml_xml.js` calls
// `xacml_validate.js`), so a document that does not typecheck never becomes a
// usable policy — it is reported at write time and, if it got in some other
// way, at read time.
// ---------------------------------------------------------------------------
function parseDocument(document) {
  log.debug('Entering parseDocument().');
  const digest = crypto.createHash('sha256').update(document).digest('hex');
  const cached = parsed.get(digest);
  if (cached) {
    log.debug('Leaving parseDocument(). Cached.');
    return cached;
  }
  const policy = xml.parsePolicy(document);
  parsed.set(digest, policy);
  log.debug('Leaving parseDocument(). Parsed and cached as ' +
            digest.slice(0, 12) + '.');
  return policy;
}

// What the derived attributes should be for a document. One function, called
// at write time, so the entry and the document cannot drift at the moment they
// are written — they can still drift afterwards through an `ldapmodify`, which
// is why the document is the truth and these are only an index.
function describe(document) {
  log.debug('Entering describe().');
  const policy = parseDocument(document);
  log.debug('Leaving describe(). id=' + policy.id);
  return { id: policy.id,
           kind: policy.kind,
           version: policy.version,
           combiningAlgId: policy.combiningAlgId };
}

// ---------------------------------------------------------------------------
// READING.
// ---------------------------------------------------------------------------
function all() {
  log.debug('Entering all().');
  if (!haveDirectory()) {
    log.debug('Leaving all(). No directory.');
    return [];
  }
  const rows = directory.allPolicies().map(function (entry) {
    const at = attributeReader(entry.attributes);
    return {
      name: entry.name,
      dn: entry.dn,
      id: at('xacmlPolicyId'),
      kind: at('xacmlKind') || 'Policy',
      version: at('xacmlVersion') || '1.0',
      combiningAlgId: at('xacmlCombiningAlgId') || '',
      description: at('description') || '',
      enabled: at('xacmlEnabled') !== 'FALSE',
      isRoot: at('xacmlIsRoot') === 'TRUE',
      document: at('xacmlPolicyDocument') || ''
    };
  });
  log.debug('Leaving all(). ' + rows.length + ' policy(ies).');
  return rows;
}

// ---------------------------------------------------------------------------
// READING AN ATTRIBUTE BACK, CASE-INSENSITIVELY, BECAUSE LDAP IS.
//
// RFC 4512: attribute type names are case-insensitive, and this directory
// normalises them to lower case on the way in. So an entry written with
// `xacmlPolicyDocument` reads back as `xacmlpolicydocument`, and a reader that
// asks for the camel-case name it wrote gets `undefined`.
//
// That cost a boot here and it failed in the worst available way: `all()`
// returned rows whose every field was empty, `root()` found no root because
// `xacmlIsRoot` read as undefined, and the PDP answered NotApplicable to
// everything — with a repository that plainly had a policy in it and no error
// anywhere. `federation.js` reads `stored.attributes.fedid` in lower case for
// exactly this reason; this does it through one function so that the fifteen
// call sites cannot each get it right separately.
// ---------------------------------------------------------------------------
function attributeReader(attributes) {
  const lowered = {};
  Object.keys(attributes || {}).forEach(function (key) {
    lowered[key.toLowerCase()] = attributes[key];
  });
  return function (name) {
    return one(lowered[String(name).toLowerCase()]);
  };
}

function one(value) {
  if (Array.isArray(value)) {
    return value.length ? String(value[0]) : null;
  }
  return value === undefined || value === null ? null : String(value);
}

function read(name) {
  log.debug('Entering read(). name=' + name);
  const found = all().filter(function (row) {
    return row.name === name;
  })[0] || null;
  log.debug('Leaving read(). ' + (found ? 'Found.' : 'Not found.'));
  return found;
}

// ---------------------------------------------------------------------------
// THE ROOT, AND THE REPOSITORY BEHIND IT.
//
// A PDP evaluates ONE document and reaches the rest through
// `PolicyIdReference`. So the repository has a root, and this is where "which
// one" is answered — as an explicit `xacmlIsRoot` rather than by a rule like
// "the only PolicySet" or "the first one", both of which change their answer
// when somebody adds a second policy and neither of which anybody can see.
// ---------------------------------------------------------------------------
function root() {
  log.debug('Entering root().');
  const enabled = all().filter(function (row) {
    return row.enabled;
  });
  const roots = enabled.filter(function (row) {
    return row.isRoot;
  });
  if (roots.length === 1) {
    log.debug('Leaving root(). ' + roots[0].id);
    return roots[0];
  }
  if (roots.length > 1) {
    // Refused rather than resolved. Two roots is a repository whose answer
    // depends on iteration order, and a PDP that picked one would decide
    // consistently and arbitrarily.
    log.debug('Leaving root(). More than one.');
    return null;
  }
  if (enabled.length === 1) {
    // The one unambiguous convenience: a repository holding exactly one
    // enabled policy has an obvious root, and demanding the flag there would
    // make the simplest possible setup fail for a reason that reads as a bug.
    log.debug('Leaving root(). The only enabled policy.');
    return enabled[0];
  }
  log.debug('Leaving root(). None.');
  return null;
}

// Every enabled policy keyed by its PolicyId, which is what `xacml_pdp.js`
// resolves a `PolicyIdReference` against. Built per decision rather than held,
// because the directory is the store and a cached map is a second copy of it.
function repository() {
  log.debug('Entering repository().');
  const map = {};
  all().forEach(function (row) {
    if (!row.enabled || !row.id) {
      return;
    }
    try {
      map[row.id] = parseDocument(row.document);
    } catch (error) {
      // A policy that does not parse is left OUT of the repository rather than
      // taking the whole decision down. It is not silent: a reference to it is
      // then unresolvable, which `xacml_pdp.js` reports as Indeterminate
      // naming the reference — and the console shows the parse error on the
      // policy itself.
      log.warn('xacml: policy "' + row.name + '" is in the repository and ' +
               'does not parse, so nothing can reference it: ' +
               error.message);
    }
  });
  log.debug('Leaving repository(). ' + Object.keys(map).length +
            ' entry(ies).');
  return map;
}

// ---------------------------------------------------------------------------
// WRITING.
//
// The document is VALIDATED before it is written. A repository that accepts a
// policy which does not typecheck is a repository whose next decision is
// Indeterminate for a reason nobody will connect to the save that caused it —
// so the refusal happens at the moment somebody can still fix it.
// ---------------------------------------------------------------------------
function write(name, document, options) {
  log.debug('Entering write(). name=' + name);
  const settings = options || {};
  if (!haveDirectory()) {
    log.debug('Leaving write(). No directory.');
    return { ok: false, why: 'There is no embedded directory, so there is ' +
                             'nowhere to put a policy.' };
  }
  if (!name || !/^[A-Za-z0-9._-]{1,128}$/.test(name)) {
    log.debug('Leaving write(). Bad name.');
    return { ok: false, why: 'A policy name is 1 to 128 characters of ' +
                             'letters, digits, dot, dash or underscore. It ' +
                             'names the DIRECTORY ENTRY; the PolicyId inside ' +
                             'the document is a separate thing and may be ' +
                             'any URI.' };
  }
  let described;
  try {
    described = describe(document);
  } catch (error) {
    log.debug('Leaving write(). The document was refused.');
    return { ok: false, why: error.message,
             problems: (error.xacmlDetail && error.xacmlDetail.problems) ||
                       null };
  }
  // TWO ROOTS IS REFUSED AT WRITE TIME rather than reported at decision time,
  // for the reason `root()` gives: a repository with two roots answers
  // arbitrarily, and the moment to say so is while somebody is looking.
  if (settings.isRoot) {
    const clash = all().filter(function (row) {
      return row.isRoot && row.name !== name;
    })[0];
    if (clash) {
      log.debug('Leaving write(). A root already exists.');
      return { ok: false,
               why: 'Policy "' + clash.name + '" is already the root of ' +
                    'this repository. A PDP evaluates one document and ' +
                    'reaches the rest through PolicyIdReference, so there is ' +
                    'exactly one root. Clear the flag there first.' };
    }
  }
  const attributes = {
    objectClass: ['top', 'xacmlPolicy'],
    xacmlPolicyId: described.id,
    xacmlPolicyDocument: document,
    xacmlVersion: described.version,
    xacmlKind: described.kind,
    xacmlCombiningAlgId: described.combiningAlgId,
    xacmlEnabled: settings.enabled === false ? 'FALSE' : 'TRUE',
    xacmlIsRoot: settings.isRoot ? 'TRUE' : 'FALSE'
  };
  if (settings.description) {
    attributes.description = String(settings.description);
  }
  const written = directory.writePolicy(name, attributes);
  log.debug('Leaving write(). ' + (written ? 'Written.' : 'Refused.'));
  return written ? { ok: true, id: described.id, kind: described.kind }
                 : { ok: false, why: 'The directory refused the entry. The ' +
                                     'container may be at its maximum.' };
}

function remove(name) {
  log.debug('Entering remove(). name=' + name);
  if (!haveDirectory()) {
    log.debug('Leaving remove(). No directory.');
    return false;
  }
  const removed = directory.deletePolicy(name);
  log.debug('Leaving remove(). ' + (removed ? 'Removed.' : 'Not there.'));
  return removed;
}


// ---------------------------------------------------------------------------
// THE SEEDED POLICY.
//
// This service seeds a directory — people, groups, containers — so that it
// answers something the moment it starts, and the policy repository follows
// the same rule for the same reason: a PDP with an empty repository answers
// NotApplicable to everything, which is indistinguishable from a PDP that is
// broken. One policy, seeded, makes `GET /xacml/protected?subject=alice`
// mean something before anybody has authored anything.
//
// IT IS A REAL POLICY AND NOT A PLACEHOLDER. Role-based, in the shape the
// OASIS RBAC profile takes: a permission is granted to a role, and the role
// is an attribute of the subject — read here by the PIP off the person's own
// `employeeType` in the embedded directory, which is an attribute this
// service's seeded entries already carry. So the seeded policy and the seeded
// directory agree, and the first decision anybody asks for exercises the
// PDP, the repository AND the PIP rather than just the first of the three.
//
// `deny-unless-permit` deliberately: the combining algorithm that cannot
// return NotApplicable or Indeterminate, so the seeded repository never hands
// the embedded PEP an answer whose meaning depends on the PEP's bias. A
// reader who wants to see the bias matter should disable this policy or write
// one that can be Indeterminate — which is the point of the setting.
// ---------------------------------------------------------------------------
const SEED_NAME = 'seeded-rbac';

const SEED_DOCUMENT = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  '<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"',
  '        PolicyId="urn:sts-mock:xacml:policy:seeded-rbac"',
  '        Version="1.0"',
  '        RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:' +
    'rule-combining-algorithm:deny-unless-permit">',
  '  <Description>',
  '    Seeded by the mock STS so that the PDP answers something before',
  '    anybody has authored a policy. Anyone whose directory entry carries',
  '    employeeType=staff may GET; anyone with employeeType=admin may do',
  '    anything. Everybody else is denied, because deny-unless-permit cannot',
  '    return NotApplicable. Replace it rather than editing it.',
  '  </Description>',
  '  <Target/>',
  '  <Rule RuleId="urn:sts-mock:xacml:rule:admin-anything" Effect="Permit">',
  '    <Description>An admin may do anything.</Description>',
  '    <Target>',
  '      <AnyOf><AllOf>',
  '        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:' +
    'string-equal">',
  '          <AttributeValue',
  '            DataType="http://www.w3.org/2001/XMLSchema#string"' +
    '>admin</AttributeValue>',
  '          <AttributeDesignator',
  '            Category="urn:oasis:names:tc:xacml:1.0:subject-category:' +
    'access-subject"',
  '            AttributeId="employeeType"',
  '            DataType="http://www.w3.org/2001/XMLSchema#string"',
  '            MustBePresent="false"/>',
  '        </Match>',
  '      </AllOf></AnyOf>',
  '    </Target>',
  '  </Rule>',
  '  <Rule RuleId="urn:sts-mock:xacml:rule:staff-read" Effect="Permit">',
  '    <Description>Staff may GET.</Description>',
  '    <Target>',
  '      <AnyOf><AllOf>',
  '        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:' +
    'string-equal">',
  '          <AttributeValue',
  '            DataType="http://www.w3.org/2001/XMLSchema#string"' +
    '>staff</AttributeValue>',
  '          <AttributeDesignator',
  '            Category="urn:oasis:names:tc:xacml:1.0:subject-category:' +
    'access-subject"',
  '            AttributeId="employeeType"',
  '            DataType="http://www.w3.org/2001/XMLSchema#string"',
  '            MustBePresent="false"/>',
  '        </Match>',
  '      </AllOf></AnyOf>',
  '      <AnyOf><AllOf>',
  '        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:' +
    'string-equal">',
  '          <AttributeValue',
  '            DataType="http://www.w3.org/2001/XMLSchema#string"' +
    '>GET</AttributeValue>',
  '          <AttributeDesignator',
  '            Category="urn:oasis:names:tc:xacml:3.0:attribute-category:' +
    'action"',
  '            AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id"',
  '            DataType="http://www.w3.org/2001/XMLSchema#string"',
  '            MustBePresent="false"/>',
  '        </Match>',
  '      </AllOf></AnyOf>',
  '    </Target>',
  '  </Rule>',
  '</Policy>'
].join('\n');

// Called by `ldap/ldap_server.js` immediately after it creates ou=policies,
// which is the only moment "the repository is new" is knowable. It writes
// through the ordinary `write()` path — so the seeded document is parsed and
// STATICALLY VALIDATED like any other, and a seed that stopped typechecking
// would be refused at startup and say so rather than becoming the one policy
// in the repository nobody had checked.
function seed() {
  log.debug('Entering seed().');
  const written = write(SEED_NAME, SEED_DOCUMENT,
                        { isRoot: true, enabled: true,
                          description: 'Seeded role-based policy. Replace ' +
                                       'it rather than editing it.' });
  if (!written.ok) {
    log.warn('xacml: the seeded policy was refused: ' + written.why);
  }
  log.debug('Leaving seed(). ' + (written.ok ? 'Seeded.' : 'Refused.'));
  return written.ok;
}

module.exports = {
  SCHEMA: SCHEMA,
  SEED_NAME: SEED_NAME,
  SEED_DOCUMENT: SEED_DOCUMENT,
  seed: seed,
  setDirectory: setDirectory,
  all: all,
  read: read,
  root: root,
  repository: repository,
  write: write,
  remove: remove,
  describe: describe,
  parseDocument: parseDocument
};
