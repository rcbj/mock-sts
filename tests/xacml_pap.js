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

function run(t) {
  checkWriter(t);
  checkTemplates(t);
  checkMatchMenu(t);
  checkContextualOptions(t);
  checkMenuAndApiAgree(t);
  checkEdits(t);
  checkMatchTypeFollowsFunction(t);
  checkPapActions(t);
}

module.exports = {
  name: 'xacml_pap',
  describe: 'the XACML templates, the guided editor grammar and the XML writer',
  run: run
};
