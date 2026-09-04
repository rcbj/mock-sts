'use strict';
//
// File: xacml_service.js
//
// ---------------------------------------------------------------------------
// THE HALF OF XACML THAT IS NOT THE ENGINE: THE STORE, THE PIP, THE JSON
// PROFILE, AND WHAT THE EMBEDDED PEP DOES WITH A DECISION.
//
// `xacml_conformance.js` beside this file holds the engine to 455 cases
// somebody else wrote. Nothing in that suite touches a directory, a JSON
// request or a PEP, because none of those is XACML — they are how THIS
// SERVICE wires XACML up, and a defect in any of them produces a wrong
// authorization decision just as surely as a defect in a combining algorithm.
//
// It needs no port and no container: the store is the embedded directory,
// which loads in process, and the PDP is a pure function. So this runs in
// `npm test` with everything else.
//
// ---------------------------------------------------------------------------
// FOUR OF THESE ASSERTIONS EXIST BECAUSE THE THING THEY CHECK WAS WRONG.
//
// Every one of them failed silently — the service started, answered every
// request, logged nothing unusual, and decided incorrectly:
//
//   1. LDAP ATTRIBUTE NAMES COME BACK LOWER-CASED. `xacmlPolicyDocument` reads
//      as `xacmlpolicydocument`, so a store that asked for what it wrote got
//      `undefined` for every field: the repository listed a policy whose id,
//      document and root flag were all empty, `root()` found nothing, and the
//      PDP answered NotApplicable to everything with a policy plainly sitting
//      in `ou=policies`.
//   2. THE SAME BUG IN THE PIP IS QUIETER AND WORSE. A missing attribute is a
//      legitimate answer, so the PDP simply decided as though the person held
//      no roles. Nothing anywhere reported a problem.
//   3. THE SEED RAN BEFORE THE STORE HAD ITS DIRECTORY. `ldap_server.js`
//      seeds at require time and fills the store's slot further down the same
//      file, so a seed written beside the container is refused.
//   4. JSON HAS ONE NUMBER TYPE. `5` and `5.0` both parse to `5`, so the
//      integer/double distinction survives only in the source text.
// ---------------------------------------------------------------------------

const model = require('../xacml/xacml_model');
const json = require('../xacml/xacml_json');
const store = require('../xacml/xacml_store');
const pip = require('../xacml/xacml_pip');
const pdp = require('../xacml/xacml_pdp');
const xacml = require('../xacml/xacml');

// Requiring the directory is what fills the store's and the PIP's slots and
// seeds the repository. It registers routes, which is harmless here: nothing
// in this file makes a request.
const directory = require('../ldap/ldap_server');

// ---------------------------------------------------------------------------
// THE STORE.
// ---------------------------------------------------------------------------
function checkRepository(t) {
  const rows = store.all();
  t.check(rows.length >= 1, 'the repository holds the seeded policy',
          rows.length + ' policy(ies)');
  const seeded = store.read(store.SEED_NAME);
  if (!t.check(!!seeded, 'the seeded policy is readable by name',
               store.SEED_NAME)) {
    return;
  }
  // DEFECT 1. Each of these read back `undefined` before `attributeReader()`
  // existed, and every one of them looks like an empty repository rather than
  // like a case-folding bug.
  t.check(!!seeded.id, 'its PolicyId survives the round trip through LDAP',
          'id=' + seeded.id);
  t.check(seeded.document.indexOf('<Policy') >= 0,
          'its document survives the round trip',
          seeded.document.length + ' bytes');
  t.equal(seeded.kind, 'Policy', 'its kind is derived from the document');
  t.check(seeded.enabled, 'it is enabled');
  t.check(seeded.isRoot, 'it is the root');

  const root = store.root();
  t.check(root && root.name === store.SEED_NAME,
          'root() finds it', root ? root.name : 'nothing');

  // The repository a PolicyIdReference resolves against is keyed by PolicyId,
  // not by entry name — the two are different identifiers on purpose.
  const repository = store.repository();
  t.check(!!repository[seeded.id],
          'the reference repository is keyed by PolicyId rather than by ' +
          'entry name', Object.keys(repository).join(', '));
}

function checkWriteRefusesRubbish(t) {
  // A document that is not XML at all.
  const bad = store.write('not-a-policy', 'this is not XML', {});
  t.check(!bad.ok, 'a document that is not XML is refused', bad.why);

  // A document that IS well-formed XACML and does not TYPECHECK. This is the
  // case that matters: it parses, it looks right, and every decision it takes
  // part in would be Indeterminate for ever.
  const untyped = [
    '<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"',
    ' PolicyId="urn:test:untyped" Version="1.0"',
    ' RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:' +
      'rule-combining-algorithm:deny-unless-permit">',
    '<Target/><Rule RuleId="r" Effect="Permit"><Condition>',
    '<Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:integer-add">',
    '<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#integer">1',
    '</AttributeValue>',
    '<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">2',
    '</AttributeValue></Apply></Condition></Rule></Policy>'
  ].join('');
  const refused = store.write('untyped', untyped, {});
  t.check(!refused.ok,
          'a well-formed policy that does not typecheck is refused at WRITE ' +
          'time rather than going Indeterminate on every request', refused.why);

  // And a second root is refused rather than resolved arbitrarily.
  const secondRoot = store.write('another-root', store.SEED_DOCUMENT,
                                 { isRoot: true });
  t.check(!secondRoot.ok, 'a second root policy is refused',
          secondRoot.why);
}

// ---------------------------------------------------------------------------
// THE PIP.
// ---------------------------------------------------------------------------
function checkPip(t) {
  t.check(pip.available(),
          'the PIP has the directory (its setDirectory slot was filled)');

  // Which AttributeIds map to a directory attribute, and which deliberately do
  // not. A standard XACML URI must NOT — mapping `subject-id` to a directory
  // lookup would let a policy read a different subject from the one being
  // decided about.
  t.equal(pip.directoryAttributeFor('employeeType'), 'employeeType',
          'a bare name is a directory attribute');
  t.equal(pip.directoryAttributeFor(pip.ATTRIBUTE_PREFIX + 'mail'), 'mail',
          'the explicit URN prefix names one too');
  t.equal(pip.directoryAttributeFor(model.ATTRIBUTE.SUBJECT_ID), null,
          'a standard XACML attribute URI is NOT looked up in the directory');
}

// Build a request the way a PEP would, without going through HTTP.
function requestFor(subject, action, extras) {
  const subjectAttributes = [];
  if (subject) {
    subjectAttributes.push({ attributeId: model.ATTRIBUTE.SUBJECT_ID,
                             issuer: null, includeInResult: false,
                             values: [{ type: model.TYPE.STRING,
                                        lexical: subject }] });
  }
  (extras || []).forEach(function (extra) {
    subjectAttributes.push({ attributeId: extra.id, issuer: null,
                             includeInResult: false,
                             values: [{ type: model.TYPE.STRING,
                                        lexical: extra.value }] });
  });
  return {
    returnPolicyIdList: false,
    combinedDecision: false,
    categories: [
      { category: model.CATEGORY.ACCESS_SUBJECT, id: null, content: null,
        attributes: subjectAttributes },
      { category: model.CATEGORY.ACTION, id: null, content: null,
        attributes: [{ attributeId: model.ATTRIBUTE.ACTION_ID, issuer: null,
                       includeInResult: false,
                       values: [{ type: model.TYPE.STRING,
                                  lexical: action }] }] }
    ]
  };
}

function checkDecisionsThroughThePip(t) {
  // DEFECT 2. Nothing in the request says what alice's role is; the seeded
  // policy grants on `employeeType`, and the only place that lives is her
  // directory entry. If the PIP is not consulted — or reads the attribute
  // with the wrong case — every one of these is Deny and the service looks
  // like it is working.
  t.equal(xacml.decide(requestFor('alice', 'GET')).decision,
          model.DECISION.PERMIT,
          'alice is staff IN THE DIRECTORY and may GET');
  t.equal(xacml.decide(requestFor('alice', 'DELETE')).decision,
          model.DECISION.DENY,
          'staff may not DELETE');
  t.equal(xacml.decide(requestFor('carol', 'DELETE')).decision,
          model.DECISION.PERMIT,
          'carol is admin in the directory and may DELETE');
  t.equal(xacml.decide(requestFor('nobody-at-all', 'GET')).decision,
          model.DECISION.DENY,
          'somebody with no directory entry is denied');

  // THE REQUEST WINS OVER THE DIRECTORY. A PEP asserting an attribute is
  // describing this request; the directory is describing the world.
  t.equal(xacml.decide(requestFor('alice', 'DELETE',
                                  [{ id: 'employeeType', value: 'admin' }]))
            .decision,
          model.DECISION.PERMIT,
          'an attribute asserted in the request overrides the directory');
}

// ---------------------------------------------------------------------------
// THE JSON PROFILE.
// ---------------------------------------------------------------------------
function checkJsonProfile(t) {
  const body = JSON.stringify({
    Request: {
      AccessSubject: { Attribute: [
        { AttributeId: model.ATTRIBUTE.SUBJECT_ID, Value: 'alice' }
      ] },
      Action: { Attribute: [
        { AttributeId: model.ATTRIBUTE.ACTION_ID, Value: 'GET' }
      ] }
    }
  });
  const request = json.parseRequest(body);
  t.equal(request.categories.length, 2,
          'the shorthand category names are expanded');
  t.equal(request.categories[0].category, model.CATEGORY.ACCESS_SUBJECT,
          'AccessSubject means the access-subject category URI');
  t.equal(xacml.decide(request).decision, model.DECISION.PERMIT,
          'a JSON Profile request decides the same as a built one');

  // DEFECT 4. JSON has ONE number type, so `5` and `5.0` both come back from
  // JSON.parse as `5` — the distinction survives only in the source text, and
  // a policy comparing an integer against a double fails the static type
  // check for a reason its author cannot see in their own request.
  const numbers = json.parseRequest(JSON.stringify({
    Request: { Resource: { Attribute: [
      { AttributeId: 'count', Value: 5 },
      { AttributeId: 'ratio', Value: 5.5 }
    ] } }
  }));
  const attributes = numbers.categories[0].attributes;
  t.equal(attributes[0].values[0].type, model.TYPE.INTEGER,
          'a JSON number with no fractional part is an integer');
  t.equal(attributes[1].values[0].type, model.TYPE.DOUBLE,
          'a JSON number with one is a double');

  // An array is a BAG, not a value of an array type.
  const bag = json.parseRequest(JSON.stringify({
    Request: { Resource: { Attribute: [
      { AttributeId: 'roles', Value: ['a', 'b', 'c'] }
    ] } }
  }));
  t.equal(bag.categories[0].attributes[0].values.length, 3,
          'an array Value is a bag of three rather than one array');

  // A short datatype name is legal and means the XML Schema URI.
  const short = json.parseRequest(JSON.stringify({
    Request: { Resource: { Attribute: [
      { AttributeId: 'when', Value: '2026-09-04', DataType: 'date' }
    ] } }
  }));
  t.equal(short.categories[0].attributes[0].values[0].type, model.TYPE.DATE,
          'the short datatype name "date" resolves to the XML Schema URI');

  // A malformed request is REFUSED rather than decided about.
  let refused = false;
  try {
    json.parseRequest('{"NotARequest": {}}');
  } catch (error) {
    refused = true;
  }
  t.check(refused,
          'a body with no Request member is refused rather than treated as ' +
          'an empty request — an empty request DECIDES something, and a ' +
          'malformed one must not');
}

function checkResponseShape(t) {
  const answer = xacml.decide(requestFor('alice', 'GET'));
  const written = json.writeResponse(answer);
  t.check(Array.isArray(written.Response) && written.Response.length === 1,
          'a JSON Profile response holds an array of Results');
  t.equal(written.Response[0].Decision, 'Permit',
          'the decision is one of the four external values');
  t.check(!!written.Response[0].Status.StatusCode.Value,
          'and it carries a status code',
          written.Response[0].Status.StatusCode.Value);
}

// ---------------------------------------------------------------------------
// THE EMBEDDED PEP.
// ---------------------------------------------------------------------------
function checkEnforcement(t) {
  // The two biases agree on Permit and on Deny...
  const permit = { decision: model.DECISION.PERMIT, obligations: [] };
  const deny = { decision: model.DECISION.DENY, obligations: [] };
  t.check(xacml.enforce(permit).allowed, 'a Permit is allowed');
  t.check(!xacml.enforce(deny).allowed, 'a Deny is refused');

  // ...and an obligation the PEP cannot discharge turns a Permit into a
  // refusal. Section 7.2, and the part implementations skip: allowing the
  // access while dropping the obligation enforces half a policy and reports
  // success.
  const withObligation = { decision: model.DECISION.PERMIT,
                           obligations: [{ id: 'urn:test:cannot-do-this',
                                           assignments: [] }] };
  const verdict = xacml.enforce(withObligation);
  t.check(!verdict.allowed,
          'a Permit carrying an obligation the PEP cannot discharge is a ' +
          'REFUSAL', verdict.why);
  t.equal(verdict.undischargeable.length, 1,
          'and the obligation it could not discharge is named');
}

function run(t) {
  checkRepository(t);
  checkWriteRefusesRubbish(t);
  checkPip(t);
  checkDecisionsThroughThePip(t);
  checkJsonProfile(t);
  checkResponseShape(t);
  checkEnforcement(t);
}

module.exports = {
  name: 'xacml_service',
  describe: 'the XACML store, PIP, JSON Profile and embedded PEP in process',
  run: run
};
