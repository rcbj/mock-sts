'use strict';
//
// File: xacml_pap.js
//
// ---------------------------------------------------------------------------
// THE POLICY ADMINISTRATION POINT: THE TEMPLATES, THE EDITOR GRAMMAR, AND THE
// XML WRITER UNDER BOTH.
//
// `xacml_conformance.js` holds the ENGINE to somebody else's 455 cases and
// `xacml_service.js` holds the STORE, the PIP and the PEP. This file is the
// authoring half, and none of it is XACML — it is how a person is helped to
// write XACML, which is a different thing to get wrong and fails differently:
// an editor defect does not produce a wrong decision, it produces a policy
// somebody cannot save or, worse, one they save believing it says something
// else.
//
// It needs no browser. `xacml_editor.js` has no DOM on purpose, exactly so
// that "a Match offers the two-argument boolean predicates and nothing else"
// is a claim that can be asserted in node. A grammar that only existed inside
// a `<select>` could not be checked at all.
//
// ---------------------------------------------------------------------------
// THE ASSERTION THIS FILE IS REALLY FOR.
//
// **Every edit leaves a policy that still type-checks.** The editor is LIVE —
// the draft IS the stored policy, and there is no save button — so an edit
// that produced an invalid document would break the policy the PDP is
// deciding with, at the moment somebody was trying to improve it. The store
// validates on write, so such an edit is refused and the stored document is
// unchanged; the test below drives a sequence of edits and checks the result
// loads every time.
// ---------------------------------------------------------------------------

const model = require('../xacml/xacml_model');
const xml = require('../xacml/xacml_xml');
const store = require('../xacml/xacml_store');
const editor = require('../xacml/xacml_editor');
const templates = require('../xacml/xacml_templates');
const validate = require('../xacml/xacml_validate');
const pap = require('../xacml/xacml_admin');

// Fills the store's directory slot and seeds the repository.
require('../ldap/ldap_server');

const F1 = 'urn:oasis:names:tc:xacml:1.0:function:';

// ---------------------------------------------------------------------------
// THE XML WRITER.
// ---------------------------------------------------------------------------
function checkWriter(t) {
  const first = xml.parsePolicy(store.SEED_DOCUMENT);
  const written = xml.writePolicy(first);
  let second = null;
  try {
    second = xml.parsePolicy(written);
  } catch (error) {
    t.check(false, 'a written policy parses back', error.message);
    return;
  }
  t.check(true, 'a written policy parses back');
  t.equal(xml.writePolicy(second), written,
          'and writing it again is byte-identical — the round trip is a ' +
          'fixed point rather than drifting a little on each pass');
  t.equal(second.rules.length, first.rules.length,
          'every rule survives the round trip');
  t.equal(second.combiningAlgId, first.combiningAlgId,
          'and so does the combining algorithm');
  // The reader dropped <Description> until this was noticed, so a policy
  // through the editor silently lost every explanation its author wrote —
  // the one part of a policy that exists purely for the next reader.
  t.check(second.description.length > 0,
          'the policy <Description> survives', second.description.slice(0, 40));
  t.check(second.rules[0].description.length > 0,
          'and so does a rule\'s');
}

// ---------------------------------------------------------------------------
// THE TEMPLATES.
// ---------------------------------------------------------------------------
function checkTemplates(t) {
  t.equal(templates.catalogue().length, templates.TEMPLATES.length,
          'the catalogue is DERIVED from the table, so adding a template is ' +
          'a row and nothing else');

  templates.TEMPLATES.forEach(function (row) {
    const built = templates.build(row.id, {}, { name: row.id });
    if (!t.check(built.ok, 'the ' + row.id + ' template builds',
                 built.ok ? '' : built.why)) {
      return;
    }
    const document = xml.writePolicy(built.policy);
    let parsed = null;
    try {
      parsed = xml.parsePolicy(document);
    } catch (error) {
      t.check(false, 'the ' + row.id + ' template TYPE-CHECKS', error.message);
      return;
    }
    t.check(true, 'the ' + row.id + ' template type-checks',
            parsed.rules.length + ' rule(s)');
    t.equal(validate.problemsIn(parsed).length, 0,
            'and reports no static problems');
  });

  // A template with no answers at all must still produce something — the
  // first thing anybody does with an API is call it with an empty body.
  const bare = templates.build('rbac', null, {});
  t.check(bare.ok && bare.policy.rules.length > 0,
          'a template called with NO answers falls back to its own defaults ' +
          'rather than producing an empty policy');

  // A value that would break XML if it were substituted into text. The
  // template builds the MODEL and the writer escapes, so this has to survive.
  const awkward = templates.build(
    'rbac', { adminRoles: 'a"b<c&d', readerRoles: '' },
    { name: 'awkward' });
  t.check(awkward.ok,
          'a template accepts a role containing XML metacharacters');
  const awkwardDoc = xml.writePolicy(awkward.policy);
  let awkwardBack = null;
  try {
    awkwardBack = xml.parsePolicy(awkwardDoc);
  } catch (error) {
    t.check(false, 'and the document it produces still parses', error.message);
  }
  if (awkwardBack) {
    t.check(true, 'and the document it produces still parses');
    const literal = awkwardBack.rules[0].target.anyOf[0].allOf[0]
      .matches[0].value.lexical;
    t.equal(literal, 'a"b<c&d',
            'with the value intact — which is why a template builds the ' +
            'model rather than substituting into XML text');
  }

  const nonesuch = templates.build('nonesuch', {}, {});
  t.check(!nonesuch.ok && /rbac/.test(nonesuch.why),
          'an unknown template is refused and the refusal NAMES the ones ' +
          'that exist', nonesuch.why);
}

// ---------------------------------------------------------------------------
// THE EDITOR'S MENUS.
// ---------------------------------------------------------------------------
function checkMatchMenu(t) {
  const menu = editor.matchFunctions();
  const labels = menu.map(function (one) {
    return one.label;
  });
  t.check(menu.length > 20, 'a Match offers a menu of functions',
          menu.length + ' of them');
  t.check(labels.indexOf('string-equal') >= 0,
          'string-equal is offered — it is a two-argument boolean predicate');
  t.check(labels.indexOf('integer-greater-than') >= 0,
          'so is integer-greater-than');
  // The three exclusions are the point of the filter. A Match takes exactly
  // two primitives and returns a boolean; offering anything else would let
  // somebody build a Match the validator then refuses.
  t.check(labels.indexOf('string-bag') < 0,
          'string-bag is NOT offered — it returns a bag, not a boolean');
  t.check(labels.indexOf('and') < 0,
          'and is NOT offered — it is variadic, and a Match takes two');
  t.check(labels.indexOf('string-one-and-only') < 0,
          'string-one-and-only is NOT offered — it takes a bag');
  // Every offered function must actually be usable in a Match, which is the
  // claim the filter is making. Checked against the library rather than
  // against a list, so a new function cannot quietly break it.
  const wrong = menu.filter(function (one) {
    return !one.type;
  });
  t.equal(wrong.length, 0,
          'every offered match function names the datatype both sides must be');
}

function checkContextualOptions(t) {
  const built = templates.build('rbac', {}, { name: 'menus' });
  const policy = built.policy;

  const atRoot = editor.optionsAt(policy, '').additions.map(actionOf);
  t.check(atRoot.indexOf('add-rule') >= 0, 'the policy root offers a Rule');
  t.check(atRoot.indexOf('add-match') < 0,
          'and does NOT offer a Match — a Match may only go inside an ' +
          'alternative');

  const atAllOf = editor.optionsAt(
    policy, 'rules.0.target.anyOf.0.allOf.0').additions.map(actionOf);
  t.equal(atAllOf.join(','), 'add-match',
          'an alternative offers exactly one thing: a Match');

  const atRule = editor.optionsAt(policy, 'rules.0').additions.map(actionOf);
  t.check(atRule.indexOf('add-condition') >= 0,
          'a rule with no Condition offers one');

  // ...and a rule that already has one does not, because the schema allows
  // exactly one. Filtered from the MENU rather than refused after the click:
  // an option that is offered and then refused teaches a person that the menu
  // is not to be trusted.
  const withCondition = templates.build('abac', {}, { name: 'c' }).policy;
  const atAbacRule = editor.optionsAt(withCondition, 'rules.0')
    .additions.map(actionOf);
  t.check(atAbacRule.indexOf('add-condition') < 0,
          'a rule that ALREADY has a Condition is not offered a second one');

  t.check(!editor.optionsAt(policy, '').removable,
          'the policy root cannot be removed');
  t.check(editor.optionsAt(policy, 'rules.0').removable,
          'a rule can be');

  const nowhere = editor.optionsAt(policy, 'rules.99.target');
  t.equal(nowhere.additions.length, 0,
          'a path that does not resolve offers nothing rather than throwing');
}

function actionOf(one) {
  return one.action;
}

// EVERY ACTION THE MENUS CAN OFFER MUST BE ONE THE API DECLARES. A move that
// is in the menu and not in the action list would be offered by the console,
// accepted by the console, and missing from `/admin-api` — which is rule 7
// broken in the direction nobody looks.
function checkMenuAndApiAgree(t) {
  const offered = {};
  Object.keys(editor.ADDITIONS).forEach(function (kind) {
    editor.ADDITIONS[kind].forEach(function (one) {
      offered[one.action] = true;
    });
  });
  offered['add-argument'] = true;
  offered.remove = true;
  const declared = pap.actionNames();
  const missing = Object.keys(offered).filter(function (action) {
    return declared.indexOf(action) < 0;
  });
  t.equal(missing.length, 0,
          'every action the editor can offer is declared to /admin-api',
          missing.join(', ') || 'none missing');
}

// ---------------------------------------------------------------------------
// APPLYING EDITS.
// ---------------------------------------------------------------------------
function checkEdits(t) {
  const policy = templates.build('rbac', {}, { name: 'edits' }).policy;
  const before = policy.rules.length;

  const steps = [
    ['', 'add-rule', { effect: 'Deny' }],
    ['rules.' + before, 'edit-rule',
     { id: 'urn:test:rule:blocked', effect: 'Deny' }],
    ['rules.' + before, 'add-target-anyof',
     { matchId: F1 + 'string-equal', value: 'contractor',
       attributeId: 'employeeType' }],
    ['rules.' + before, 'add-condition', {}],
    ['rules.' + before + '.target.anyOf.0', 'add-allof',
     { value: 'intern', attributeId: 'employeeType' }],
    ['', 'edit-policy', { combiningAlgId: model.RULE_ALG.DENY_OVERRIDES }]
  ];

  let allApplied = true;
  steps.forEach(function (step) {
    const result = editor.applyEdit(policy, step[0], step[1], step[2]);
    if (!result.ok) {
      allApplied = false;
      t.check(false, 'edit ' + step[1] + ' applies', result.why);
    }
  });
  if (allApplied) {
    t.check(true, 'a sequence of six edits applies',
            steps.map(function (s) { return s[1]; }).join(', '));
  }

  t.equal(policy.rules.length, before + 1, 'the rule was added');
  t.equal(policy.combiningAlgId, model.RULE_ALG.DENY_OVERRIDES,
          'the combining algorithm changed');

  // THE ASSERTION THIS FILE IS FOR. See the header.
  const document = xml.writePolicy(policy);
  let reloaded = null;
  try {
    reloaded = xml.parsePolicy(document);
  } catch (error) {
    t.check(false, 'the edited policy still TYPE-CHECKS', error.message);
    return;
  }
  t.check(true, 'the edited policy still type-checks',
          reloaded.rules.length + ' rule(s)');

  // A removal, and then the document must still load.
  const removed = editor.applyEdit(policy, 'rules.' + before, 'remove', {});
  t.check(removed.ok, 'a rule can be removed');
  t.equal(policy.rules.length, before, 'and it is gone');
  let afterRemoval = null;
  try {
    afterRemoval = xml.parsePolicy(xml.writePolicy(policy));
  } catch (error) {
    t.check(false, 'the policy still type-checks after a removal',
            error.message);
  }
  if (afterRemoval) {
    t.check(true, 'the policy still type-checks after a removal');
  }

  // An unknown action is REFUSED and says so, rather than silently doing
  // nothing — which is what a gap between the menu and the code would look
  // like from the outside.
  const bogus = editor.applyEdit(policy, '', 'add-unicorn', {});
  t.check(!bogus.ok && /does not know how to/.test(bogus.why),
          'an action the editor does not implement is refused out loud',
          bogus.why);

  // A stale path is refused with an explanation rather than editing the wrong
  // node. This is the consequence of paths being positional.
  const stale = editor.applyEdit(policy, 'rules.99', 'edit-rule',
                                 { id: 'x' });
  t.check(!stale.ok && /not there any more/.test(stale.why),
          'a path that no longer resolves is refused rather than guessing',
          stale.why);
}

// A Match's datatype must follow its function, or the two sides can be set
// independently into something that does not type-check — and the person
// finds out a screen later.
function checkMatchTypeFollowsFunction(t) {
  const policy = templates.build('rbac', {}, { name: 'types' }).policy;
  const path = 'rules.0.target.anyOf.0.allOf.0.matches.0';
  const result = editor.applyEdit(policy, path, 'edit-match', {
    matchId: F1 + 'integer-greater-than', value: '5'
  });
  t.check(result.ok, 'a Match\'s function can be changed', result.why || '');
  const located = editor.nodeAt(policy, path);
  t.equal(located.node.value.type, model.TYPE.INTEGER,
          'the literal takes the function\'s datatype');
  t.equal(located.node.reference.dataType, model.TYPE.INTEGER,
          'and so does the attribute it is compared with — set independently ' +
          'they could disagree, and the policy would not type-check');
  let ok = true;
  try {
    xml.parsePolicy(xml.writePolicy(policy));
  } catch (error) {
    ok = false;
  }
  t.check(ok, 'so the policy still type-checks after the change');
}

// ---------------------------------------------------------------------------
// THE PAP'S ACTIONS, AGAINST THE REAL STORE.
// ---------------------------------------------------------------------------
function checkPapActions(t) {
  const created = pap.combinedAction({
    action: 'create-from-template', template: 'abac', name: 'pap-test',
    p_subjectAttribute: 'employeeType', p_subjectValue: 'staff'
  });
  t.check(created.ok, 'the PAP creates a policy from a template',
          created.why || created.what);

  const stored = store.read('pap-test');
  t.check(!!stored, 'and it is in the repository');

  const disabled = pap.combinedAction({ action: 'disable',
                                        name: 'pap-test' });
  t.check(disabled.ok, 'it can be disabled');
  t.check(!store.read('pap-test').enabled, 'and it is');

  // An edit through the PAP goes through the store, so it is validated.
  const edited = pap.combinedAction({ action: 'add-rule', policy: 'pap-test',
                                      path: '', effect: 'Deny' });
  t.check(edited.ok, 'a rule can be added through the PAP action',
          edited.why || edited.what);
  const after = store.read('pap-test');
  t.check(!!after, 'and the policy is still readable');
  t.equal(store.parseDocument(after.document).rules.length, 2,
          'with the new rule in it');

  const gone = pap.combinedAction({ action: 'delete', name: 'pap-test' });
  t.check(gone.ok, 'it can be deleted');
  t.check(!store.read('pap-test'), 'and it is gone');

  const unknown = pap.combinedAction({ action: 'not-an-action' });
  t.check(!unknown.ok && /Unknown action/.test(unknown.why),
          'an unknown action is refused, and the refusal lists every action ' +
          'there is');
}


// ---------------------------------------------------------------------------
// A POLICY SET IS NOT A POLICY WITH DIFFERENT CHILDREN.
//
// This is the section that would have caught the defect the whole group of
// them was written for. Until a policy set was editable, `kindAt()` derived
// "policy" from the empty path, the menu offered `add-rule`, `applyEdit()`
// pushed onto `rules`, `xacml_xml.js` serialized `children` and never looked
// at `rules` — and the editor answered "Rule added." about a document that did
// not contain it. Every layer behaved correctly on its own.
// ---------------------------------------------------------------------------
function newPolicySet() {
  return { kind: 'PolicySet', id: 'urn:test:set', description: '',
           version: '1.0', combiningAlgId: model.POLICY_ALG.DENY_OVERRIDES,
           target: null, children: [], obligations: [], advice: [] };
}

function checkPolicySets(t) {
  const set = newPolicySet();

  t.equal(editor.optionsAt(set, '').kind, 'policySet',
          'the root of a PolicySet is a policySet and not a policy — derived ' +
          'from the NODE, because the path is the same empty string for both');

  const offered = editor.optionsAt(set, '').additions.map(actionOf);
  t.check(offered.indexOf('add-policy') >= 0,
          'a policy set offers a Policy');
  t.check(offered.indexOf('add-rule') < 0,
          'and does NOT offer a Rule — a set holds policies, and the menu ' +
          'that offered one wrote it where the serializer does not look');

  const refused = editor.applyEdit(set, '', 'add-rule', {});
  t.check(!refused.ok && /holds policies, not rules/.test(refused.why),
          'and the ACTION refuses it too, because /admin-api is not the menu',
          refused.why);

  t.check(editor.applyEdit(set, '', 'add-policy', {}).ok,
          'a policy can be added to the set');
  t.check(editor.applyEdit(set, '', 'add-policyset', {}).ok,
          'and a nested set');
  t.check(editor.applyEdit(set, '', 'add-policy-reference',
                           { ref: 'urn:test:elsewhere' }).ok,
          'and a PolicyIdReference');
  t.check(editor.applyEdit(set, 'children.0', 'add-rule', {}).ok,
          'a rule goes on the CHILD POLICY, which is where it belongs');

  // THE TWO ALGORITHM VOCABULARIES ARE ONE URI SEGMENT APART, and a policy set
  // carrying the rule-combining spelling names an algorithm no combiner can
  // find. Nothing else in this repository would refuse it.
  const wrong = editor.applyEdit(set, '', 'edit-policy',
                                 { combiningAlgId: model.RULE_ALG.DENY_OVERRIDES });
  t.check(!wrong.ok && /policy-combining/.test(wrong.why),
          'a RULE-combining algorithm is refused on a policy set', wrong.why);
  const right = editor.applyEdit(
    set, '', 'edit-policy',
    { combiningAlgId: model.POLICY_ALG.ONLY_ONE_APPLICABLE });
  t.check(right.ok, 'and the policy-combining one is accepted', right.why);
  t.check(editor.optionsAt(set, 'children.0').kind === 'policy',
          'a child of the set is a policy, and its own menu offers rules');

  const document = xml.writePolicy(set);
  let back = null;
  try {
    back = xml.parsePolicy(document);
  } catch (error) {
    t.check(false, 'the edited policy set still type-checks', error.message);
    return;
  }
  t.check(true, 'the edited policy set type-checks');
  t.equal(back.children.length, 3,
          'and all three children survived the round trip — the assertion ' +
          'that fails when an edit is accepted and then serialized nowhere');
  t.equal(back.children[0].rules.length, 1,
          'including the rule on the child policy');
  t.equal(back.combiningAlgId, model.POLICY_ALG.ONLY_ONE_APPLICABLE,
          'and the policy-combining algorithm is the one that was chosen');

  const rows = editor.tree(set).map(function (row) { return row.kind; });
  t.check(rows.indexOf('reference') >= 0,
          'the tree draws the reference, so it can be seen and removed');
  t.check(rows.filter(function (kind) { return kind === 'policySet'; })
            .length === 2,
          'and recurses into the nested set rather than stopping at the root');
}

// ---------------------------------------------------------------------------
// VARIABLES, AND THE MENU ITEM THAT USED TO BE A TRAP.
//
// `set-expression-variable` has been in the menu since the editor shipped and
// there was no way to DEFINE a variable — so choosing it built `$v1`, the
// validator refused the document, the store declined the write, and the
// editor's one promise (it cannot offer what the validator will refuse) was
// broken by its own menu.
// ---------------------------------------------------------------------------
function checkVariables(t) {
  const policy = templates.build('rbac', {}, { name: 'vars' }).policy;
  editor.applyEdit(policy, 'rules.0', 'add-condition', {});

  const before = editor.optionsAt(policy, 'rules.0.condition')
    .additions.map(actionOf);
  t.check(before.indexOf('set-expression-variable') < 0,
          'with no variable defined, a VariableReference is NOT offered — ' +
          'the menu withdraws what the validator would refuse');

  const added = editor.applyEdit(policy, '', 'add-variable', {});
  t.check(added.ok, 'a variable can be defined', added.why || added.what);
  t.check(editor.optionsAt(policy, 'rules.0.condition').additions
            .map(actionOf).indexOf('set-expression-variable') >= 0,
          'and now the reference IS offered');

  const duplicate = editor.applyEdit(policy, '', 'add-variable',
                                     { variableId: 'v1' });
  t.check(!duplicate.ok && /already defines/.test(duplicate.why),
          'a duplicate VariableId is refused — the reader rejects a document ' +
          'defining one twice, so allowing it would write a policy this ' +
          'service cannot load back', duplicate.why);

  const dotted = editor.applyEdit(policy, '', 'add-variable',
                                  { variableId: 'a.b' });
  t.check(!dotted.ok && /dotted path/.test(dotted.why),
          'and so is a name with a dot in it, because the id becomes a path ' +
          'segment here — refused where it can be explained rather than ' +
          'discovered as a row whose buttons do nothing', dotted.why);

  t.check(editor.applyEdit(policy, 'rules.0.condition.args.1',
                           'set-expression-variable', {}).ok,
          'an argument can be pointed at the variable');
  const unknown = editor.applyEdit(policy, 'rules.0.condition.args.1',
                                   'set-expression-variable',
                                   { variableId: 'nope' });
  t.check(!unknown.ok && /5.24/.test(unknown.why),
          'and naming one this policy does not define is refused, citing the ' +
          'section that says why', unknown.why);

  // THE RENAME IS THE INTERESTING ONE: a rename that left the references
  // behind produces a document that does not load, so the store would refuse
  // the write and nothing would change — a control that silently does nothing.
  const renamed = editor.applyEdit(policy, 'variables.v1', 'edit-variable',
                                   { variableId: 'staffTypes' });
  t.check(renamed.ok && /1 reference/.test(renamed.what),
          'renaming a variable rewrites the references with it, and says how ' +
          'many', renamed.what || renamed.why);
  let back = null;
  try {
    back = xml.parsePolicy(xml.writePolicy(policy));
  } catch (error) {
    t.check(false, 'the renamed policy still type-checks', error.message);
    return;
  }
  t.check(true, 'the renamed policy type-checks — which is the whole point: ' +
          'an unrewritten reference is a document that will not load');
  t.check(!!back.variables.staffTypes,
          'the definition is under the new name');
  t.equal(Object.keys(back.variables).length, 1,
          'and not under both');
}

// ---------------------------------------------------------------------------
// THE THREE EXPRESSION KINDS THE MODEL HAD AND THE EDITOR COULD NOT BUILD.
// ---------------------------------------------------------------------------
function checkSelectorsAndFunctions(t) {
  const policy = templates.build('rbac', {}, { name: 'expr' }).policy;
  editor.applyEdit(policy, 'rules.0', 'add-condition', {});

  // A HIGHER-ORDER FUNCTION TAKES A FUNCTION, and until `newExpression()` knew
  // that, choosing `any-of` built an <AttributeValue> in that position — an
  // expression the validator refuses, offered by the editor's own menu.
  const higher = editor.applyEdit(
    policy, 'rules.0.condition', 'set-expression-apply',
    { functionId: 'urn:oasis:names:tc:xacml:3.0:function:any-of' });
  t.check(higher.ok, 'a higher-order function can be chosen', higher.why || '');
  const condition = editor.nodeAt(policy, 'rules.0.condition').node;
  t.equal(condition.args[0].kind, 'function',
          'and its first argument arrives as a Function REFERENCE rather ' +
          'than a literal — which is the difference between a policy that ' +
          'loads and one the validator refuses');
  t.equal(validate.problemsIn(policy).length, 0,
          'so the policy type-checks with no further edits');

  const changed = editor.applyEdit(
    policy, 'rules.0.condition.args.0', 'edit-function',
    { functionId: 'urn:oasis:names:tc:xacml:1.0:function:string-greater-than' });
  t.check(changed.ok, 'the function reference can be changed', changed.why || '');

  // `map` applies its function to ONE value; the other six take a predicate of
  // two. A default of the wrong shape is legal XACML that fails at evaluation,
  // which is worse than one that fails at load.
  editor.applyEdit(policy, 'rules.0.condition', 'set-expression-apply',
                   { functionId: 'urn:oasis:names:tc:xacml:3.0:function:map' });
  t.equal(editor.nodeAt(policy, 'rules.0.condition').node.args[0].functionId,
          'urn:oasis:names:tc:xacml:1.0:function:string-normalize-to-lower-case',
          'and `map` gets a ONE-argument default rather than a predicate');

  // AN AttributeSelector, AND THE BINDINGS THAT MAKE ITS PATH MEAN ANYTHING.
  //
  // Put back to a boolean condition first: `map` returns a BAG, and a rule
  // whose Condition is a bag does not load. That is the validator doing its
  // job on an expression this test built on purpose, and it is worth leaving
  // in the file rather than starting from a fresh policy — the second half of
  // this check is that the SELECTOR round-trips through a document, and a
  // document that will not parse cannot show it.
  editor.applyEdit(policy, 'rules.0.condition', 'set-expression-apply',
                   { functionId: 'urn:oasis:names:tc:xacml:1.0:function:' +
                                 'string-is-in' });
  const selector = editor.applyEdit(policy, 'rules.0.condition.args.1',
                                    'set-expression-selector', {});
  t.check(selector.ok, 'an AttributeSelector can be built', selector.why || '');
  const bound = editor.applyEdit(
    policy, 'rules.0.condition.args.1', 'edit-selector',
    { path: '//md:record/md:patient', namespacePrefix: 'md',
      namespaceUri: 'http://www.medico.com/schemas/record',
      mustBePresent: 'true' });
  t.check(bound.ok, 'and given a path and a namespace binding',
          bound.why || '');

  // THE ASSERTION THIS PAIR EXISTS FOR. The reader captured namespace
  // bindings from the document and the writer dropped them, so the FIRST edit
  // of any policy holding a selector produced one whose prefixes resolved to
  // nothing — and an unresolvable prefix is an empty bag, which is
  // NotApplicable, which looks exactly like a policy that decided you may not.
  const document = xml.writePolicy(policy);
  t.check(/<AttributeSelector[^>]*xmlns:md="http:\/\/www\.medico\.com/
            .test(document),
          'the binding is WRITTEN ONTO the selector, so the path still ' +
          'resolves in the document that comes back out');
  t.check(/MustBePresent="true"/.test(document),
          'and MustBePresent survives — the difference between an absent ' +
          'attribute being an empty bag and being Indeterminate');

  const back = xml.parsePolicy(document);
  t.equal(xml.writePolicy(back), document,
          'and the round trip is a fixed point rather than drifting a ' +
          'binding on each pass');
  t.equal(editor.xpathVersionGaps(back).length, 1,
          'a document using a selector with no XPathVersion is REPORTED — ' +
          'section 5.14 asks for one, no decision here changes either way, ' +
          'and a schema validator elsewhere would refuse it');
  editor.applyEdit(back, '', 'edit-policy',
                   { xpathVersion: 'http://www.w3.org/TR/1999/REC-xpath-19991116' });
  t.equal(editor.xpathVersionGaps(back).length, 0,
          'and setting it closes the report');
  t.check(/<PolicyDefaults>/.test(xml.writePolicy(back)),
          'which is written as <PolicyDefaults><XPathVersion>');
}

// ---------------------------------------------------------------------------
// THE OPTIONAL ATTRIBUTES, AND THE ASSIGNMENTS THAT COULD BE ADDED AND NOT SEEN.
// ---------------------------------------------------------------------------
function checkOptionalSyntax(t) {
  const policy = templates.build('rbac', {}, { name: 'optional' }).policy;

  editor.applyEdit(policy, 'rules.0', 'add-rule-obligation', {});
  editor.applyEdit(policy, 'rules.0.obligations.0', 'add-assignment', {});
  const rows = editor.tree(policy);
  const assignment = rows.filter(function (row) {
    return row.kind === 'assignment';
  })[0];
  t.check(!!assignment,
          'an attribute assignment is DRAWN — it could be added and not seen ' +
          'since the editor shipped, so the only way to correct a mistyped ' +
          'one was to remove the whole obligation');
  if (assignment) {
    const edited = editor.applyEdit(policy, assignment.path,
                                    'edit-assignment',
                                    { attributeId: 'urn:test:notify',
                                      category: model.CATEGORY.RESOURCE,
                                      issuer: 'sts' });
    t.check(edited.ok, 'and it can be edited', edited.why || '');
    t.check(editor.optionsAt(policy, assignment.path).removable,
            'and removed');
    t.check(editor.optionsAt(policy, assignment.path + '.expression').kind ===
              'expression',
            'and its VALUE is an expression node of its own, with the whole ' +
            'expression menu on it');
  }

  // Optional attributes, each of which used to have no control at all.
  const versioned = editor.applyEdit(policy, '', 'edit-policy',
                                     { version: '2.13.7',
                                       maxDelegationDepth: '4',
                                       description: 'Written by the editor.' });
  t.check(versioned.ok, 'Version, MaxDelegationDepth and Description are ' +
          'settable', versioned.why || '');
  const bad = editor.applyEdit(policy, '', 'edit-policy',
                               { version: 'draft 2' });
  t.check(!bad.ok && /dot-separated/.test(bad.why),
          'and a Version that is not dot-separated numbers is refused here, ' +
          'because nothing else in this service would refuse it and a schema ' +
          'validator elsewhere will', bad.why);

  const matchPath = 'rules.0.target.anyOf.0.allOf.0.matches.0';
  const issued = editor.applyEdit(policy, matchPath, 'edit-match',
                                  { issuer: 'urn:test:issuer',
                                    mustBePresent: 'true' });
  t.check(issued.ok, 'a Match\'s designator takes an Issuer and ' +
          'MustBePresent', issued.why || '');

  // THE TRISTATE. An unchecked checkbox sends nothing, so a form that edits
  // the FUNCTION and does not carry the MustBePresent control must not clear
  // it — which is what `given.mustBePresent === 'true'` did on every save.
  editor.applyEdit(policy, matchPath, 'edit-match', { value: 'contractor' });
  t.check(editor.nodeAt(policy, matchPath).node.reference.mustBePresent,
          'and editing the Match\'s VALUE leaves MustBePresent alone rather ' +
          'than clearing it — a field the form did not mention is not a ' +
          'field set to false');

  // A Match may reference a SELECTOR instead, and it is a switch rather than
  // two fields: the schema allows exactly one of the two.
  const switched = editor.applyEdit(policy, matchPath, 'edit-match',
                                    { referenceKind: 'selector',
                                      path: '//md:patient' });
  t.check(switched.ok, 'a Match can test an XPath selector instead of a ' +
          'named attribute', switched.why || '');
  t.equal(editor.nodeAt(policy, matchPath).node.reference.kind, 'selector',
          'and the reference IS the selector rather than both');

  const document = xml.writePolicy(policy);
  t.check(/MaxDelegationDepth="4"/.test(document),
          'MaxDelegationDepth is written — carried and not honoured, since ' +
          'this PDP implements no delegation, but a round trip that dropped ' +
          'it would delete it from a document that arrived with one');
  t.check(/Version="2.13.7"/.test(document), 'and the Version');
  let back = null;
  try {
    back = xml.parsePolicy(document);
  } catch (error) {
    t.check(false, 'and the result still type-checks', error.message);
    return;
  }
  t.check(true, 'and the result still type-checks');
  t.equal(back.maxDelegationDepth, '4', 'and reads back');
}

// ---------------------------------------------------------------------------
// THE FOUR COMBINER-PARAMETER ELEMENTS: CARRIED, DRAWN, REMOVABLE, NOT ADDABLE.
//
// The one place in this editor where those come apart, and the assertion is
// about all four halves at once — a document that arrives with them keeps
// them, the person can see and delete them, and no menu offers one, because
// section C says no standard combining algorithm reads a parameter.
// ---------------------------------------------------------------------------
const WITH_COMBINER_PARAMETERS =
  '<?xml version="1.0" encoding="UTF-8"?>\n' +
  '<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" ' +
  'PolicyId="urn:test:combiner" Version="1.0" ' +
  'RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:' +
  'first-applicable">\n' +
  '  <Target/>\n' +
  '  <CombinerParameters>\n' +
  '    <CombinerParameter ParameterName="order">\n' +
  '      <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#integer">' +
  '1</AttributeValue>\n' +
  '    </CombinerParameter>\n' +
  '  </CombinerParameters>\n' +
  '  <RuleCombinerParameters RuleIdRef="urn:test:combiner:rule:1">\n' +
  '    <CombinerParameter ParameterName="weight">\n' +
  '      <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#integer">' +
  '7</AttributeValue>\n' +
  '    </CombinerParameter>\n' +
  '  </RuleCombinerParameters>\n' +
  '  <Rule RuleId="urn:test:combiner:rule:1" Effect="Permit"><Target/></Rule>\n' +
  '</Policy>\n';

function checkCombinerParameters(t) {
  let policy = null;
  try {
    policy = xml.parsePolicy(WITH_COMBINER_PARAMETERS);
  } catch (error) {
    t.check(false, 'a policy carrying combiner parameters loads',
            error.message);
    return;
  }
  t.equal(policy.combinerParameters.length, 1,
          'a <CombinerParameters> is READ rather than walked past');
  t.equal(policy.ruleCombinerParameters.length, 1,
          'and so is a <RuleCombinerParameters>');

  // THE ASSERTION THAT MATTERS: the editor rewrites the whole document on
  // every edit, so anything the reader skips is DELETED by the first click.
  editor.applyEdit(policy, '', 'edit-policy', { description: 'touched' });
  const document = xml.writePolicy(policy);
  t.check(/ParameterName="order"/.test(document) &&
          /RuleIdRef="urn:test:combiner:rule:1"/.test(document),
          'and both survive an unrelated edit — an element the reader drops ' +
          'is not merely unread, it is deleted by the next rename');

  const kinds = editor.tree(policy).map(function (row) { return row.kind; });
  t.check(kinds.indexOf('combinerParameter') >= 0 &&
          kinds.indexOf('combinerParameterGroup') >= 0,
          'they are DRAWN, because an element you cannot see is one you ' +
          'cannot delete');
  t.check(editor.optionsAt(policy, 'combinerParameters.0').removable,
          'and removable');

  const offered = [];
  Object.keys(editor.ADDITIONS).forEach(function (kind) {
    editor.ADDITIONS[kind].forEach(function (one) {
      offered.push(one.action);
    });
  });
  t.check(!offered.some(function (action) {
    return /combiner/i.test(action);
  }), 'and NO menu offers to add one — section C says none of the twelve ' +
      'standard combining algorithms takes a parameter, so an Add button ' +
      'here would be the first control on this console that provably ' +
      'changes no decision');

  t.equal(xml.writePolicy(xml.parsePolicy(document)), document,
          'the round trip through them is a fixed point');
}

function run(t) {
  checkWriter(t);
  checkTemplates(t);
  checkMatchMenu(t);
  checkContextualOptions(t);
  checkMenuAndApiAgree(t);
  checkEdits(t);
  checkMatchTypeFollowsFunction(t);
  checkPolicySets(t);
  checkVariables(t);
  checkSelectorsAndFunctions(t);
  checkOptionalSyntax(t);
  checkCombinerParameters(t);
  checkPapActions(t);
}

module.exports = {
  name: 'xacml_pap',
  describe: 'the XACML templates, the guided editor grammar and the XML writer',
  run: run
};
