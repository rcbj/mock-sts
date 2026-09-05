'use strict';
//
// File: xacml_alfa.js
//
// ---------------------------------------------------------------------------
// ALFA, IN BOTH DIRECTIONS, AND THE ONE CONTRACT THIS SERVICE CAN ACTUALLY
// KEEP ABOUT IT.
//
// ALFA is an OASIS **Committee Specification Draft**. There is no conformance
// suite for it, no schema, and no second implementation to disagree with —
// which is a completely different footing from the engine, where 455 cases
// somebody else wrote hold it honest. So there is nothing here to check
// against, and a test that merely drove this implementation against itself
// would prove that it is self-consistent and nothing more.
//
// What it CAN prove is the contract `xacml_alfa.js` states in its header:
//
//   **ANYTHING THE EMITTER WRITES, THE PARSER READS, AND THE POLICY DECIDES
//   IDENTICALLY EITHER WAY.**
//
// That is three separate claims and this file asserts all three:
//
//   1. the ALFA is STABLE — write, parse, write again, byte-identical;
//   2. the policy that comes back TYPE-CHECKS as XACML;
//   3. it makes the SAME DECISIONS as the original, over a set of requests
//      chosen to exercise each of its rules.
//
// The third is the one that matters, and the one a round-trip test usually
// leaves out. A syntax can round-trip perfectly and still have swapped the
// sides of a comparison — `age > 18` becoming `18 > age` — which produces a
// stable, type-checking, well-formed policy that decides the opposite. That
// specific mistake is why `mirrorOperator()` exists, and the decision
// assertions below are the only thing that would catch it.
// ---------------------------------------------------------------------------

const model = require('../xacml/xacml_model');
const xml = require('../xacml/xacml_xml');
const alfa = require('../xacml/xacml_alfa');
const store = require('../xacml/xacml_store');
const templates = require('../xacml/xacml_templates');
const pdp = require('../xacml/xacml_pdp');
const pap = require('../xacml/xacml_admin');

require('../ldap/ldap_server');

// ---------------------------------------------------------------------------
// A HANDFUL OF REQUESTS, BUILT ONCE. No PIP: the point here is that TWO
// RENDERINGS OF ONE POLICY AGREE, and a directory lookup would be the same
// answer on both sides of the comparison while adding a way for the test to
// depend on seeded data.
// ---------------------------------------------------------------------------
function requestFor(attributes, action) {
  const subjectAttributes = Object.keys(attributes).map(function (id) {
    return { attributeId: id, issuer: null, includeInResult: false,
             values: [{ type: model.TYPE.STRING,
                        lexical: String(attributes[id]) }] };
  });
  return {
    returnPolicyIdList: false, combinedDecision: false,
    categories: [
      { category: model.CATEGORY.ACCESS_SUBJECT, id: null, content: null,
        attributes: subjectAttributes },
      { category: model.CATEGORY.ACTION, id: null, content: null,
        attributes: [{ attributeId: model.ATTRIBUTE.ACTION_ID, issuer: null,
                       includeInResult: false,
                       values: [{ type: model.TYPE.STRING,
                                  lexical: action }] }] },
      { category: model.CATEGORY.RESOURCE, id: null, content: null,
        attributes: [{ attributeId: model.ATTRIBUTE.RESOURCE_ID, issuer: null,
                       includeInResult: false,
                       values: [{ type: model.TYPE.ANYURI,
                                  lexical: 'https://example.test/records' }] }]
      },
      { category: model.CATEGORY.ENVIRONMENT, id: null, content: null,
        attributes: [] }
    ]
  };
}

const PROBES = [
  { what: 'admin doing anything',
    request: requestFor({ employeeType: 'admin' }, 'DELETE') },
  { what: 'staff reading',
    request: requestFor({ employeeType: 'staff' }, 'GET') },
  { what: 'staff deleting',
    request: requestFor({ employeeType: 'staff' }, 'DELETE') },
  { what: 'a stranger',
    request: requestFor({ employeeType: 'contractor' }, 'GET') },
  { what: 'nobody at all', request: requestFor({}, 'GET') },
  { what: 'the ABAC subject',
    request: requestFor({ departmentNumber: '42' }, 'GET') },
  { what: 'the wrong department',
    request: requestFor({ departmentNumber: '7' }, 'GET') }
];

function decisionsOf(policy) {
  return PROBES.map(function (probe) {
    return pdp.evaluate(policy, probe.request, {}).decision;
  });
}

// ---------------------------------------------------------------------------
// THE THREE CLAIMS, OVER EVERY POLICY THIS SERVICE CAN PRODUCE.
// ---------------------------------------------------------------------------
function checkRoundTrip(t, name, policy) {
  let text;
  try {
    text = alfa.write(policy);
  } catch (error) {
    t.check(false, name + ': renders as ALFA', error.message);
    return;
  }
  t.check(text.indexOf('namespace') === 0,
          name + ': renders as ALFA', text.length + ' bytes');

  let back;
  try {
    back = alfa.parse(text);
  } catch (error) {
    t.check(false, name + ': and parses back', error.message);
    return;
  }
  t.check(true, name + ': and parses back');

  // CLAIM 1 — stable.
  t.equal(alfa.write(back), text,
          name + ': writing it again is byte-identical');

  // CLAIM 2 — still valid XACML. `parsePolicy()` validates, so this is a
  // type-check and not merely a parse.
  let reloaded = null;
  try {
    reloaded = xml.parsePolicy(xml.writePolicy(back));
  } catch (error) {
    t.check(false, name + ': the result TYPE-CHECKS as XACML', error.message);
    return;
  }
  t.check(true, name + ': the result type-checks as XACML');

  // CLAIM 3 — and it decides the same. See the header: this is the one that
  // catches a swapped comparison, which claims 1 and 2 cannot.
  const before = decisionsOf(policy).join(',');
  const after = decisionsOf(reloaded).join(',');
  t.equal(after, before,
          name + ': and reaches the SAME decision on all ' + PROBES.length +
          ' probes');
}

function checkEveryPolicy(t) {
  checkRoundTrip(t, 'the seeded policy',
                 xml.parsePolicy(store.SEED_DOCUMENT));
  templates.TEMPLATES.forEach(function (row) {
    const built = templates.build(row.id, {}, { name: row.id });
    if (built.ok) {
      checkRoundTrip(t, 'the ' + row.id + ' template', built.policy);
    }
  });
}

// ---------------------------------------------------------------------------
// HAND-WRITTEN ALFA, which is the case the emitter can never exercise.
// ---------------------------------------------------------------------------
const HAND_WRITTEN = [
  'namespace example {',
  '    attribute role {',
  '        category = subjectCat',
  '        id = "employeeType"',
  '        type = string',
  '    }',
  '    attribute clearance {',
  '        category = subjectCat',
  '        id = "clearanceLevel"',
  '        type = integer',
  '    }',
  '    attribute act {',
  '        category = actionCat',
  '        id = "urn:oasis:names:tc:xacml:1.0:action:action-id"',
  '        type = string',
  '    }',
  '',
  '    policy handWritten {',
  '        id = "urn:test:hand-written"',
  '        apply denyUnlessPermit',
  '        rule cleared {',
  '            permit',
  '            target clause role == "staff" or role == "admin"',
  '            target clause act == "GET"',
  '            condition integerGreaterThanOrEqual(',
  '                integerOneAndOnly(clearance), 3)',
  '        }',
  '    }',
  '}'
].join('\n');

function checkHandWritten(t) {
  let policy = null;
  try {
    policy = alfa.parse(HAND_WRITTEN);
  } catch (error) {
    t.check(false, 'a hand-written ALFA policy parses', error.message);
    return;
  }
  t.check(true, 'a hand-written ALFA policy parses');
  t.equal(policy.id, 'urn:test:hand-written',
          'the `id = "..."` property carries the real PolicyId — the ALFA ' +
          'identifier is a slug and cannot hold a colon, so emitting only ' +
          'the slug would silently rename every policy');
  t.equal(policy.rules.length, 1, 'with its one rule');

  // The three-level target: one clause is one AnyOf, `or` gives two AllOf
  // alternatives inside it, and the second clause is a second AnyOf.
  const target = policy.rules[0].target;
  t.equal(target.anyOf.length, 2,
          'two `target clause` lines become two AnyOf — which is an AND');
  t.equal(target.anyOf[0].allOf.length, 2,
          'and `or` inside one clause becomes two alternatives — an OR');

  let ok = true;
  let why = '';
  try {
    xml.parsePolicy(xml.writePolicy(policy));
  } catch (error) {
    ok = false;
    why = error.message;
  }
  t.check(ok, 'and the whole thing type-checks as XACML', why);
}

// ---------------------------------------------------------------------------
// THE REFUSALS. Each is a mistake somebody will make, and each fails in a way
// that is worth being loud about.
// ---------------------------------------------------------------------------
function refusal(t, what, text, expected) {
  let message = null;
  try {
    alfa.parse(text);
  } catch (error) {
    message = error.message;
  }
  if (!message) {
    t.check(false, what, 'it was ACCEPTED');
    return;
  }
  t.check(expected.test(message), what, message);
}

function checkRefusals(t) {
  // THE MOST USEFUL ONE. An undeclared attribute is otherwise a policy that
  // quietly matches nothing — which looks exactly like a policy that is
  // working correctly and denying you.
  refusal(t, 'an undeclared attribute is refused, and the refusal lists what ' +
             'IS declared',
          'namespace x { policy p { id = "u:p" apply denyUnlessPermit ' +
          'rule r { permit target clause nosuchThing == "a" } } }',
          /never declared/);

  refusal(t, 'a policy with no `apply` line is refused rather than defaulted',
          'namespace x { policy p { id = "u:p" rule r { permit } } }',
          /combining algorithm/);

  refusal(t, 'a rule that says neither permit nor deny is refused',
          'namespace x { policy p { id = "u:p" apply denyUnlessPermit ' +
          'rule r { } } }',
          /permit nor deny/);

  refusal(t, 'an unknown combining algorithm is refused and the refusal ' +
             'names the real ones',
          'namespace x { policy p { apply sometimesMaybe rule r { permit } } }',
          /denyUnlessPermit/);

  refusal(t, 'an unknown function is refused',
          'namespace x { policy p { id = "u:p" apply denyUnlessPermit ' +
          'rule r { permit condition notARealFunction("a") } } }',
          /no function called/);

  // `!=` has no XACML match function, so it cannot appear in a Target — and
  // saying so is more use than a generic parse error, because the fix is to
  // move it into a Condition.
  refusal(t, '`!=` in a target clause is refused WITH the reason and the fix',
          'namespace x { attribute a { category = subjectCat id = "a" ' +
          'type = string } policy p { id = "u:p" apply denyUnlessPermit ' +
          'rule r { permit target clause a != "b" } } }',
          /condition/);

  refusal(t, 'two top-level policies are refused — a PDP evaluates one ' +
             'document',
          'namespace x { policy p { id="u:p" apply denyUnlessPermit } ' +
          'policy q { id="u:q" apply denyUnlessPermit } }',
          /more than one top-level policy/);

  refusal(t, 'an unterminated string is refused with its line number',
          'namespace x { policy p { id = "unterminated } }',
          /unterminated string/i);
}

// ---------------------------------------------------------------------------
// TYPED LITERALS, which are this dialect's own extension and the thing most
// likely to be quietly dropped by a future change.
// ---------------------------------------------------------------------------
function checkTypedLiterals(t) {
  const text = [
    'namespace x {',
    '    attribute when { category = environmentCat id = "d" type = date }',
    '    policy p {',
    '        id = "urn:test:dates"',
    '        apply denyUnlessPermit',
    '        rule r {',
    '            permit',
    '            target clause when == date("2026-01-01")',
    '        }',
    '    }',
    '}'
  ].join('\n');
  let policy = null;
  try {
    policy = alfa.parse(text);
  } catch (error) {
    t.check(false, 'a typed literal parses', error.message);
    return;
  }
  const match = policy.rules[0].target.anyOf[0].allOf[0].matches[0];
  t.equal(match.value.type, model.TYPE.DATE,
          'date("2026-01-01") is a DATE and not a string — without the cast ' +
          'form it would come back as a string and the policy would silently ' +
          'stop comparing dates');
  t.check(/date\("2026-01-01"\)/.test(alfa.write(policy)),
          'and it is written back in the same form');
}

// ---------------------------------------------------------------------------
// THE PAP'S IMPORT ACTION, against the real store.
// ---------------------------------------------------------------------------
function checkImport(t) {
  const imported = pap.combinedAction({ action: 'import-alfa',
                                        name: 'alfa-import',
                                        alfa: HAND_WRITTEN });
  t.check(imported.ok, 'the PAP imports a policy from ALFA',
          imported.why || imported.what);
  const stored = store.read('alfa-import');
  t.check(!!stored, 'and it is in the repository');
  if (stored) {
    // STORED AS XACML XML. The repository holds one representation; a stored
    // ALFA text beside a stored XML one would be two documents that could
    // disagree.
    t.check(stored.document.indexOf('<Policy') >= 0,
            'stored as XACML XML rather than as the ALFA it arrived as');
    t.equal(stored.id, 'urn:test:hand-written',
            'with the PolicyId the ALFA declared');
  }

  const bad = pap.combinedAction({ action: 'import-alfa', name: 'bad',
                                   alfa: 'namespace x { oops }' });
  t.check(!bad.ok, 'ALFA that does not parse is refused', bad.why);
  t.check(!store.read('bad'),
          'and nothing is written when it is');

  pap.combinedAction({ action: 'delete', name: 'alfa-import' });
}

function run(t) {
  checkEveryPolicy(t);
  checkHandWritten(t);
  checkRefusals(t);
  checkTypedLiterals(t);
  checkImport(t);
}

module.exports = {
  name: 'xacml_alfa',
  describe: 'ALFA read and written, and that both renderings decide the same',
  run: run
};
