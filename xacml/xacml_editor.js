'use strict';
//
// File: xacml_editor.js
//
// ---------------------------------------------------------------------------
// THE GUIDED EDITOR'S GRAMMAR: WHAT MAY BE ADDED WHERE, AND HOW ONE EDIT IS
// APPLIED.
//
// This file has NO DOM and emits no HTML. It answers three questions about a
// policy model and `xacml_admin.js` draws the answers:
//
//   tree(policy)              what nodes are there, and where
//   optionsAt(policy, path)   what may legally be added AT this node
//   applyEdit(policy, ...)    do one of those things, and hand back the model
//
// Keeping it DOM-free is the same rule the rest of this directory follows, and
// here it buys something specific: the grammar is testable in node without a
// browser, a page or a form, so `tests/xacml_service.js` can assert that a
// `<Match>` offers exactly the two-argument boolean functions and nothing else.
// A grammar that only existed inside a `<select>` could not be checked at all.
//
// ---------------------------------------------------------------------------
// WHY THE OPTIONS ARE COMPUTED ON THE SERVER, WHICH IS NOT A COMPROMISE.
//
// The admin console is `script-src 'none'`, and `admin-ui/CLAUDE.md` refuses a
// script nine times over — twice for graph pages, and its rule is that the
// argument has to be MADE rather than cited: a script is allowed only when the
// page CANNOT work without one. An editor can. So every dropdown here is a
// plain `<select>` whose `<option>`s were computed by this file, and choosing
// one is a form POST that re-renders the page.
//
// What that costs is a round trip per element, and it is worth saying out loud
// rather than hiding: building a five-rule policy by hand is perhaps forty
// POSTs. What it buys is that the list of legal next elements is computed by
// THE SAME CODE THAT VALIDATES THE POLICY, in the same process, against the
// real function library — so the editor cannot offer something the validator
// will then refuse. A browser-side editor would have needed a second copy of
// the grammar shipped to the page, and two copies of a grammar is the thing
// this whole directory is arranged to avoid.
//
// The templates in `xacml_templates.js` are the answer to the forty POSTs.
//
// ---------------------------------------------------------------------------
// A PATH IS A STRING OF SEGMENTS AND IT IS NOT AN OBJECT REFERENCE.
//
// `rules.0.target.anyOf.1.allOf.0.matches.2` names a node. It survives a form
// POST, which an object reference does not, and it survives being written into
// an `<input type="hidden">`, which is the only state this editor has.
//
// THE CONSEQUENCE, and it is the one thing that will surprise somebody: a path
// is only valid against the document it was computed from. Remove rule 0 and
// every path naming rule 1 now means rule 0. That is why every edit re-renders
// the whole tree rather than patching part of it, and why `nodeAt()` returns
// null for a path that no longer resolves instead of guessing.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const model = require('./xacml_model');
const datatypes = require('./xacml_datatypes');
const functions = require('./xacml_functions');

const F1 = 'urn:oasis:names:tc:xacml:1.0:function:';
const TYPE = model.TYPE;

// ---------------------------------------------------------------------------
// PATHS.
// ---------------------------------------------------------------------------
function segmentsOf(path) {
  return String(path || '').split('.').filter(function (one) {
    return one.length > 0;
  });
}

// Resolve a path to `{ node, parent, key }`, or null. `parent` and `key` are
// what a REMOVE needs — you cannot delete a node from itself.
function nodeAt(policy, path) {
  log.debug('Entering nodeAt(). path=' + path);
  const segments = segmentsOf(path);
  let node = policy;
  let parent = null;
  let key = null;
  for (let i = 0; i < segments.length; i += 1) {
    if (node === null || node === undefined) {
      log.debug('Leaving nodeAt(). The path does not resolve.');
      return null;
    }
    parent = node;
    key = segments[i];
    node = Array.isArray(node) ? node[Number(key)] : node[key];
  }
  if (node === null || node === undefined) {
    log.debug('Leaving nodeAt(). Nothing there.');
    return null;
  }
  log.debug('Leaving nodeAt(). Resolved.');
  return { node: node, parent: parent, key: key, path: path };
}

// ---------------------------------------------------------------------------
// WHAT KIND OF THING SITS AT A PATH.
//
// Derived from the PATH rather than from the object, because the model's nodes
// are plain objects with no type tag — an `AllOf` is `{ matches: [...] }` and
// nothing about it says so. Reading the path is unambiguous and needs no tag
// on every node, which would be a second thing to keep in step with the
// reader, the writer and the ALFA parser.
// ---------------------------------------------------------------------------
function kindAt(path) {
  const segments = segmentsOf(path);
  if (!segments.length) {
    return 'policy';
  }
  const last = segments[segments.length - 1];
  const previous = segments.length > 1 ? segments[segments.length - 2] : '';
  if (last === 'target') {
    return 'target';
  }
  if (last === 'condition') {
    return 'expression';
  }
  if (previous === 'rules') {
    return 'rule';
  }
  if (previous === 'anyOf') {
    return 'anyOf';
  }
  if (previous === 'allOf') {
    return 'allOf';
  }
  if (previous === 'matches') {
    return 'match';
  }
  if (previous === 'args') {
    return 'expression';
  }
  if (previous === 'obligations' || previous === 'advice') {
    return 'obligation';
  }
  return 'unknown';
}

// ---------------------------------------------------------------------------
// THE FUNCTION MENUS.
//
// Computed from the real library rather than written down, which is what stops
// the editor offering something `xacml_validate.js` will refuse. Two menus,
// because a Match and an Apply want different things:
//
//   matchFunctions()  the two-argument predicates a <Match> may use — exactly
//                     the functions taking two primitives and returning a
//                     boolean. `string-equal` is in; `string-bag` is not;
//                     `and` is not, because its parameters are variadic.
//   applyFunctions()  everything, grouped, for the general expression editor.
// ---------------------------------------------------------------------------
function matchFunctions() {
  log.debug('Entering matchFunctions().');
  const out = functions.names().filter(function (uri) {
    const definition = functions.FUNCTIONS[uri];
    if (!definition.returns || definition.variadic) {
      return false;
    }
    if (model.canonicalType(definition.returns.type) !== TYPE.BOOLEAN) {
      return false;
    }
    const args = definition.args || [];
    return args.length === 2 && args[0].kind === 'primitive' &&
           args[1].kind === 'primitive';
  }).map(function (uri) {
    return { uri: uri, label: shortName(uri),
             // The datatype the Match's AttributeValue and its designator both
             // have to be. Offered so that the editor can pre-select the right
             // one instead of letting somebody pick a mismatch the validator
             // then rejects a screen later.
             type: functions.FUNCTIONS[uri].args[0].type };
  });
  log.debug('Leaving matchFunctions(). ' + out.length + ' function(s).');
  return out;
}

function applyFunctions() {
  log.debug('Entering applyFunctions().');
  const out = functions.names().map(function (uri) {
    const definition = functions.FUNCTIONS[uri];
    return { uri: uri, label: shortName(uri),
             arity: definition.variadic ? 'any'
                                        : (definition.args || []).length,
             returns: definition.returns
               ? shortType(definition.returns.type) : '?' };
  });
  log.debug('Leaving applyFunctions(). ' + out.length + ' function(s).');
  return out;
}

function shortName(uri) {
  return String(uri).replace(/^urn:oasis:names:tc:xacml:[0-9.]+:function:/, '');
}

function shortType(uri) {
  const row = uri ? datatypes.typeOf(uri) : null;
  return row ? row.name : (uri || 'any');
}

// The datatypes a dropdown offers, in a stable order with the common ones
// first — because an alphabetical list puts `anyURI` and `base64Binary` above
// `string`, and `string` is what nine values out of ten are.
const COMMON_TYPES = [TYPE.STRING, TYPE.BOOLEAN, TYPE.INTEGER, TYPE.DOUBLE,
                      TYPE.ANYURI, TYPE.DATE, TYPE.DATETIME, TYPE.TIME];

function typeMenu() {
  const rest = Object.keys(datatypes.TYPES).filter(function (uri) {
    return COMMON_TYPES.indexOf(uri) < 0;
  }).sort();
  return COMMON_TYPES.concat(rest).map(function (uri) {
    return { uri: uri, label: shortType(uri) };
  });
}

const CATEGORY_MENU = [
  { uri: model.CATEGORY.ACCESS_SUBJECT, label: 'access-subject' },
  { uri: model.CATEGORY.RESOURCE, label: 'resource' },
  { uri: model.CATEGORY.ACTION, label: 'action' },
  { uri: model.CATEGORY.ENVIRONMENT, label: 'environment' },
  { uri: model.CATEGORY.RECIPIENT_SUBJECT, label: 'recipient-subject' },
  { uri: model.CATEGORY.INTERMEDIARY_SUBJECT, label: 'intermediary-subject' },
  { uri: model.CATEGORY.CODEBASE, label: 'codebase' },
  { uri: model.CATEGORY.REQUESTING_MACHINE, label: 'requesting-machine' }
];

const RULE_ALG_MENU = [
  { uri: model.RULE_ALG.DENY_UNLESS_PERMIT, label: 'deny-unless-permit',
    what: 'Anything not permitted is denied. Cannot return NotApplicable or ' +
          'Indeterminate, so the answer never depends on the PEP\'s bias.' },
  { uri: model.RULE_ALG.PERMIT_UNLESS_DENY, label: 'permit-unless-deny',
    what: 'Anything not denied is permitted. The mirror, and the one to ' +
          'think twice about.' },
  { uri: model.RULE_ALG.DENY_OVERRIDES, label: 'deny-overrides',
    what: 'One Deny outranks any number of Permits. Stops at the first Deny, ' +
          'so a later rule\'s obligations are never collected.' },
  { uri: model.RULE_ALG.PERMIT_OVERRIDES, label: 'permit-overrides',
    what: 'One Permit outranks any number of Denies.' },
  { uri: model.RULE_ALG.FIRST_APPLICABLE, label: 'first-applicable',
    what: 'The first rule that decides anything wins. Order matters.' },
  { uri: model.RULE_ALG.ORDERED_DENY_OVERRIDES,
    label: 'ordered-deny-overrides',
    what: 'deny-overrides with the evaluation order fixed. Identical here, ' +
          'because this PDP always evaluates in document order.' },
  { uri: model.RULE_ALG.ORDERED_PERMIT_OVERRIDES,
    label: 'ordered-permit-overrides',
    what: 'permit-overrides with the evaluation order fixed.' }
];

// ---------------------------------------------------------------------------
// WHAT MAY BE ADDED AT A NODE.
//
// THE TABLE IS THE GRAMMAR. Each entry is one `<option>` in that node's
// `Add ▾`, and `applyEdit()` below is the only thing that acts on them — so a
// legal move that is not in this table cannot be made, and a move in this
// table that `applyEdit()` does not handle is reported rather than silently
// doing nothing.
// ---------------------------------------------------------------------------
const ADDITIONS = {
  policy: [
    { action: 'add-rule', label: 'Rule',
      help: 'A Permit or Deny with its own Target and Condition.' },
    { action: 'add-policy-obligation', label: 'Obligation',
      help: 'Something the PEP must do when this policy decides. It MUST ' +
            'honour it or refuse the request.' },
    { action: 'add-policy-advice', label: 'Advice',
      help: 'Something the PEP may do. It is allowed to ignore this, which ' +
            'is the whole difference from an obligation.' },
    { action: 'add-target-anyof', label: 'Target clause',
      help: 'Narrows what this whole policy applies to. Every clause must ' +
            'match — they are ANDed.' }
  ],
  rule: [
    { action: 'add-target-anyof', label: 'Target clause',
      help: 'Narrows what this rule applies to. Clauses are ANDed.' },
    { action: 'add-condition', label: 'Condition',
      help: 'A boolean expression evaluated after the Target matches. Only ' +
            'one per rule.' },
    { action: 'add-rule-obligation', label: 'Obligation',
      help: 'Fires when this rule\'s Effect is the decision.' },
    { action: 'add-rule-advice', label: 'Advice' }
  ],
  target: [
    { action: 'add-target-anyof', label: 'Target clause',
      help: 'Another clause. All of them must match.' }
  ],
  anyOf: [
    { action: 'add-allof', label: 'Alternative',
      help: 'Another alternative within this clause. ANY of them matching ' +
            'satisfies it — they are ORed.' }
  ],
  allOf: [
    { action: 'add-match', label: 'Match',
      help: 'A test of one attribute against one value. Every Match in an ' +
            'alternative must hold.' }
  ],
  expression: [
    { action: 'set-expression-apply', label: 'Function call',
      help: 'Apply a function to arguments.' },
    { action: 'set-expression-value', label: 'Literal value' },
    { action: 'set-expression-designator', label: 'Attribute',
      help: 'Reads an attribute out of the request, or out of the directory ' +
            'through the PIP. Returns a BAG — most functions need ' +
            'one-and-only around it.' },
    { action: 'set-expression-variable', label: 'Variable reference' }
  ],
  match: [],
  obligation: [
    { action: 'add-assignment', label: 'Attribute assignment',
      help: 'A value handed to the PEP along with the obligation.' }
  ]
};

function optionsAt(policy, path) {
  log.debug('Entering optionsAt(). path=' + path);
  const kind = kindAt(path);
  const located = nodeAt(policy, path);
  if (!located) {
    log.debug('Leaving optionsAt(). The path does not resolve.');
    return { kind: 'unknown', additions: [], removable: false };
  }
  let additions = (ADDITIONS[kind] || []).slice();
  // A rule already carrying a Condition may not have a second one — the schema
  // allows exactly one. Filtered here rather than refused in `applyEdit()`,
  // because an option that is offered and then refused teaches a person that
  // the menu is not to be trusted.
  if (kind === 'rule' && located.node.condition) {
    additions = additions.filter(function (one) {
      return one.action !== 'add-condition';
    });
  }
  // An `Apply` may take more arguments; every other expression is a leaf and
  // may only be REPLACED, which the `set-expression-*` options already do.
  if (kind === 'expression' && located.node.kind === 'apply') {
    additions = additions.concat([
      { action: 'add-argument', label: 'Argument',
        help: 'Another argument to this function.' }
    ]);
  }
  const result = {
    kind: kind,
    additions: additions,
    // THE ROOT IS NOT REMOVABLE. Everything else is, and a Target is removable
    // by removing its last clause rather than as a node of its own — which is
    // why `target` is absent here.
    removable: kind !== 'policy' && kind !== 'target'
  };
  log.debug('Leaving optionsAt(). ' + additions.length + ' addition(s).');
  return result;
}

// ---------------------------------------------------------------------------
// APPLYING ONE EDIT.
//
// Mutates the model in place and returns `{ ok, why }`. In place rather than
// returning a copy, because the caller has just parsed the document and is
// about to serialize it — a deep clone in between would buy immutability
// nothing else here relies on.
//
// EVERY NEW NODE IS COMPLETE AND VALID ON ITS OWN. A rule arrives with a
// Target, an Effect and an id; a Match arrives with a function, a literal and
// a designator. That is deliberate and it is the difference between an editor
// that always holds a loadable policy and one that holds a half-built document
// which cannot be saved until several more edits are made — the second kind
// cannot show you what you have, because it cannot evaluate it.
// ---------------------------------------------------------------------------
function applyEdit(policy, path, action, params) {
  log.debug('Entering applyEdit(). action=' + action + ' path=' + path);
  const given = params || {};
  const located = nodeAt(policy, path);
  if (!located) {
    log.debug('Leaving applyEdit(). The path does not resolve.');
    return { ok: false,
             why: 'That part of the policy is not there any more. The ' +
                  'document changed since the page was drawn — reload and ' +
                  'try again.' };
  }
  const node = located.node;

  if (action === 'remove') {
    if (!located.parent || located.key === null) {
      log.debug('Leaving applyEdit(). Nothing to remove from.');
      return { ok: false, why: 'The policy itself cannot be removed.' };
    }
    if (Array.isArray(located.parent)) {
      located.parent.splice(Number(located.key), 1);
    } else {
      located.parent[located.key] = null;
    }
    log.debug('Leaving applyEdit(). Removed.');
    return { ok: true, what: 'Removed.' };
  }

  if (action === 'add-rule') {
    const index = (node.rules || []).length;
    node.rules = node.rules || [];
    node.rules.push({
      id: (node.id || 'urn:policy') + ':rule:' + (index + 1),
      effect: given.effect === model.EFFECT.DENY ? model.EFFECT.DENY
                                                 : model.EFFECT.PERMIT,
      description: '',
      target: null, condition: null, obligations: [], advice: []
    });
    log.debug('Leaving applyEdit(). Rule added.');
    return { ok: true, what: 'Rule added.' };
  }

  if (action === 'add-target-anyof') {
    // The Target is created if it is not there — an absent Target and an empty
    // one mean the same thing (match everything), so materialising it on the
    // first clause is not a change of meaning.
    node.target = node.target || { anyOf: [] };
    node.target.anyOf.push({ allOf: [{ matches: [newMatch(given)] }] });
    log.debug('Leaving applyEdit(). Target clause added.');
    return { ok: true, what: 'Target clause added.' };
  }

  if (action === 'add-allof') {
    node.allOf = node.allOf || [];
    node.allOf.push({ matches: [newMatch(given)] });
    log.debug('Leaving applyEdit(). Alternative added.');
    return { ok: true, what: 'Alternative added.' };
  }

  if (action === 'add-match') {
    node.matches = node.matches || [];
    node.matches.push(newMatch(given));
    log.debug('Leaving applyEdit(). Match added.');
    return { ok: true, what: 'Match added.' };
  }

  if (action === 'edit-match') {
    const matchId = given.matchId || node.matchId;
    const definition = functions.lookup(matchId);
    if (!definition) {
      log.debug('Leaving applyEdit(). Unknown match function.');
      return { ok: false, why: 'There is no function "' + matchId + '".' };
    }
    const type = definition.args[0].type;
    node.matchId = matchId;
    node.value = { kind: 'value', type: type,
                   lexical: given.value === undefined ? node.value.lexical
                                                      : String(given.value) };
    node.reference = {
      kind: 'designator',
      category: given.category || node.reference.category,
      attributeId: given.attributeId || node.reference.attributeId,
      // THE DATATYPE FOLLOWS THE FUNCTION, always. A Match whose literal is a
      // string and whose designator is an integer does not typecheck, and
      // letting the two be chosen independently is how somebody spends ten
      // minutes on a form to be told at the end that it is wrong.
      dataType: type,
      issuer: node.reference.issuer || null,
      mustBePresent: given.mustBePresent === 'true' ||
                     given.mustBePresent === true
    };
    log.debug('Leaving applyEdit(). Match edited.');
    return { ok: true, what: 'Match updated.' };
  }

  if (action === 'edit-rule') {
    if (given.id) {
      node.id = String(given.id);
    }
    if (given.effect === model.EFFECT.PERMIT ||
        given.effect === model.EFFECT.DENY) {
      node.effect = given.effect;
    }
    if (given.description !== undefined) {
      node.description = String(given.description);
    }
    log.debug('Leaving applyEdit(). Rule edited.');
    return { ok: true, what: 'Rule updated.' };
  }

  if (action === 'edit-policy') {
    if (given.id) {
      node.id = String(given.id);
    }
    if (given.description !== undefined) {
      node.description = String(given.description);
    }
    if (given.combiningAlgId) {
      const known = RULE_ALG_MENU.filter(function (one) {
        return one.uri === given.combiningAlgId;
      })[0];
      if (!known) {
        log.debug('Leaving applyEdit(). Unknown combining algorithm.');
        return { ok: false,
                 why: 'That is not one of the rule-combining algorithms this ' +
                      'editor offers.' };
      }
      node.combiningAlgId = given.combiningAlgId;
    }
    log.debug('Leaving applyEdit(). Policy edited.');
    return { ok: true, what: 'Policy updated.' };
  }

  if (action === 'add-condition') {
    if (node.condition) {
      log.debug('Leaving applyEdit(). It already has one.');
      return { ok: false, why: 'A rule may have only one Condition.' };
    }
    // A NEW CONDITION IS A COMPLETE, TRUE ONE rather than an empty shell:
    // `string-is-in("", <a subject attribute>)`. A rule whose Condition is
    // half-built cannot be saved, and an editor that cannot save is an editor
    // that has lost your work.
    node.condition = {
      kind: 'apply', functionId: F1 + 'string-is-in',
      args: [
        { kind: 'value', type: TYPE.STRING, lexical: '' },
        { kind: 'designator', category: model.CATEGORY.ACCESS_SUBJECT,
          attributeId: 'employeeType', dataType: TYPE.STRING,
          issuer: null, mustBePresent: false }
      ]
    };
    log.debug('Leaving applyEdit(). Condition added.');
    return { ok: true, what: 'Condition added.' };
  }

  if (action === 'set-expression-apply' ||
      action === 'set-expression-value' ||
      action === 'set-expression-designator' ||
      action === 'set-expression-variable') {
    const replacement = newExpression(action, given);
    if (!replacement.ok) {
      log.debug('Leaving applyEdit(). ' + replacement.why);
      return replacement;
    }
    if (Array.isArray(located.parent)) {
      located.parent[Number(located.key)] = replacement.expression;
    } else {
      located.parent[located.key] = replacement.expression;
    }
    log.debug('Leaving applyEdit(). Expression replaced.');
    return { ok: true, what: 'Expression replaced.' };
  }

  if (action === 'add-argument') {
    if (node.kind !== 'apply') {
      log.debug('Leaving applyEdit(). Not a function call.');
      return { ok: false, why: 'Only a function call takes arguments.' };
    }
    node.args = node.args || [];
    node.args.push({ kind: 'value', type: TYPE.STRING, lexical: '' });
    log.debug('Leaving applyEdit(). Argument added.');
    return { ok: true, what: 'Argument added.' };
  }

  if (action === 'edit-apply') {
    if (!functions.lookup(given.functionId)) {
      log.debug('Leaving applyEdit(). Unknown function.');
      return { ok: false, why: 'There is no function "' + given.functionId +
                               '".' };
    }
    node.functionId = given.functionId;
    log.debug('Leaving applyEdit(). Function changed.');
    return { ok: true, what: 'Function changed.' };
  }

  if (action === 'edit-value') {
    node.type = given.type || node.type;
    node.lexical = given.lexical === undefined ? node.lexical
                                               : String(given.lexical);
    log.debug('Leaving applyEdit(). Value edited.');
    return { ok: true, what: 'Value updated.' };
  }

  if (action === 'edit-designator') {
    node.category = given.category || node.category;
    node.attributeId = given.attributeId || node.attributeId;
    node.dataType = given.dataType || node.dataType;
    node.mustBePresent = given.mustBePresent === 'true' ||
                         given.mustBePresent === true;
    log.debug('Leaving applyEdit(). Designator edited.');
    return { ok: true, what: 'Attribute updated.' };
  }

  if (action === 'add-rule-obligation' || action === 'add-policy-obligation' ||
      action === 'add-rule-advice' || action === 'add-policy-advice') {
    const advice = action.indexOf('advice') >= 0;
    const list = advice ? 'advice' : 'obligations';
    node[list] = node[list] || [];
    node[list].push({
      id: 'urn:sts-mock:xacml:' + (advice ? 'advice' : 'obligation') + ':' +
          ((node[list].length) + 1),
      on: given.on === model.EFFECT.DENY ? model.EFFECT.DENY
                                         : model.EFFECT.PERMIT,
      assignments: []
    });
    log.debug('Leaving applyEdit(). ' + (advice ? 'Advice' : 'Obligation') +
              ' added.');
    return { ok: true, what: (advice ? 'Advice' : 'Obligation') + ' added.' };
  }

  if (action === 'edit-obligation') {
    if (given.id) {
      node.id = String(given.id);
    }
    if (given.on === model.EFFECT.PERMIT || given.on === model.EFFECT.DENY) {
      node.on = given.on;
    }
    log.debug('Leaving applyEdit(). Obligation edited.');
    return { ok: true, what: 'Updated.' };
  }

  if (action === 'add-assignment') {
    node.assignments = node.assignments || [];
    node.assignments.push({
      attributeId: 'urn:sts-mock:xacml:assignment:' +
                   (node.assignments.length + 1),
      category: null, issuer: null,
      expression: { kind: 'value', type: TYPE.STRING, lexical: '' }
    });
    log.debug('Leaving applyEdit(). Assignment added.');
    return { ok: true, what: 'Assignment added.' };
  }

  // A move that is in ADDITIONS and not handled here would silently do
  // nothing, which is the failure this branch exists to make impossible.
  log.debug('Leaving applyEdit(). Unknown action.');
  return { ok: false,
           why: 'The editor does not know how to "' + action + '". This is a ' +
                'gap between the menu and the code that acts on it, not ' +
                'something you did.' };
}

function newMatch(given) {
  const matchId = given.matchId || (F1 + 'string-equal');
  const definition = functions.lookup(matchId);
  const type = definition && definition.args && definition.args.length === 2
    ? definition.args[0].type : TYPE.STRING;
  return {
    matchId: matchId,
    value: { kind: 'value', type: type,
             lexical: given.value === undefined ? '' : String(given.value) },
    reference: { kind: 'designator',
                 category: given.category || model.CATEGORY.ACCESS_SUBJECT,
                 attributeId: given.attributeId ||
                              model.ATTRIBUTE.SUBJECT_ID,
                 dataType: type, issuer: null, mustBePresent: false }
  };
}

function newExpression(action, given) {
  if (action === 'set-expression-value') {
    return { ok: true, expression: { kind: 'value',
                                     type: given.type || TYPE.STRING,
                                     lexical: given.lexical || '' } };
  }
  if (action === 'set-expression-designator') {
    return { ok: true, expression: {
      kind: 'designator',
      category: given.category || model.CATEGORY.ACCESS_SUBJECT,
      attributeId: given.attributeId || 'employeeType',
      dataType: given.dataType || TYPE.STRING,
      issuer: null, mustBePresent: false } };
  }
  if (action === 'set-expression-variable') {
    return { ok: true, expression: { kind: 'variableRef',
                                     variableId: given.variableId || 'v1' } };
  }
  const functionId = given.functionId || (F1 + 'string-equal');
  const definition = functions.lookup(functionId);
  if (!definition) {
    return { ok: false, why: 'There is no function "' + functionId + '".' };
  }
  // ARGUMENTS ARE PRE-BUILT TO THE FUNCTION'S DECLARED ARITY AND TYPES, so the
  // expression typechecks the moment it exists. An `Apply` with no arguments
  // is an arity error, and an editor that produced one would refuse to save
  // the document it had just told you it had updated.
  const args = (definition.args || []).map(function (parameter) {
    if (parameter.kind === 'bag') {
      return { kind: 'designator',
               category: model.CATEGORY.ACCESS_SUBJECT,
               attributeId: 'employeeType',
               dataType: parameter.type || TYPE.STRING,
               issuer: null, mustBePresent: false };
    }
    return { kind: 'value', type: parameter.type || TYPE.STRING,
             lexical: '' };
  });
  return { ok: true, expression: { kind: 'apply', functionId: functionId,
                                   args: args } };
}

// ---------------------------------------------------------------------------
// THE TREE THE PAGE DRAWS.
//
// A flat list of `{ path, depth, kind, label, detail }` rather than a nested
// structure, because the page renders it as an indented list and a flat list
// is what that needs — nesting it here would mean the renderer had to walk it
// again to flatten it.
// ---------------------------------------------------------------------------
function tree(policy) {
  log.debug('Entering tree().');
  const rows = [];

  function push(path, depth, kind, label, detail) {
    rows.push({ path: path, depth: depth, kind: kind, label: label,
                detail: detail || '' });
  }

  function walkExpression(expression, path, depth, label) {
    if (!expression) {
      return;
    }
    if (expression.kind === 'apply') {
      push(path, depth, 'expression', label + shortName(expression.functionId),
           (expression.args || []).length + ' argument(s)');
      (expression.args || []).forEach(function (argument, index) {
        walkExpression(argument, path + '.args.' + index, depth + 1, '');
      });
      return;
    }
    if (expression.kind === 'value') {
      push(path, depth, 'expression', label + '"' + expression.lexical + '"',
           shortType(expression.type));
      return;
    }
    if (expression.kind === 'designator') {
      push(path, depth, 'expression', label + expression.attributeId,
           shortType(expression.dataType) + ' from ' +
           categoryLabel(expression.category) +
           (expression.mustBePresent ? ', must be present' : ''));
      return;
    }
    if (expression.kind === 'variableRef') {
      push(path, depth, 'expression', label + '$' + expression.variableId, '');
      return;
    }
    push(path, depth, 'expression', label + expression.kind, '');
  }

  function walkTarget(target, base, depth) {
    if (!target || !target.anyOf || !target.anyOf.length) {
      return;
    }
    push(base + '.target', depth, 'target', 'Target',
         target.anyOf.length + ' clause(s), all must match');
    target.anyOf.forEach(function (anyOf, i) {
      const anyPath = base + '.target.anyOf.' + i;
      push(anyPath, depth + 1, 'anyOf', 'Clause ' + (i + 1),
           anyOf.allOf.length + ' alternative(s), any may match');
      anyOf.allOf.forEach(function (allOf, j) {
        const allPath = anyPath + '.allOf.' + j;
        push(allPath, depth + 2, 'allOf', 'Alternative ' + (j + 1),
             allOf.matches.length + ' match(es), all must hold');
        allOf.matches.forEach(function (match, k) {
          push(allPath + '.matches.' + k, depth + 3, 'match',
               shortName(match.matchId),
               '"' + match.value.lexical + '" against ' +
               (match.reference.attributeId || match.reference.path) + ' in ' +
               categoryLabel(match.reference.category));
        });
      });
    });
  }

  push('', 0, 'policy', policy.id,
       shortName(policy.combiningAlgId).replace(/^.*algorithm:/, '') + ', ' +
       (policy.rules || []).length + ' rule(s)');
  walkTarget(policy.target, '', 1);
  (policy.rules || []).forEach(function (rule, index) {
    const base = 'rules.' + index;
    push(base, 1, 'rule', rule.effect + ' — ' + rule.id, rule.description);
    walkTarget(rule.target, base, 2);
    if (rule.condition) {
      walkExpression(rule.condition, base + '.condition', 2, 'Condition: ');
    }
    (rule.obligations || []).forEach(function (one, i) {
      push(base + '.obligations.' + i, 2, 'obligation',
           'Obligation ' + one.id, 'on ' + one.on);
    });
    (rule.advice || []).forEach(function (one, i) {
      push(base + '.advice.' + i, 2, 'obligation', 'Advice ' + one.id,
           'on ' + one.on);
    });
  });
  (policy.obligations || []).forEach(function (one, i) {
    push('obligations.' + i, 1, 'obligation', 'Obligation ' + one.id,
         'on ' + one.on);
  });
  (policy.advice || []).forEach(function (one, i) {
    push('advice.' + i, 1, 'obligation', 'Advice ' + one.id, 'on ' + one.on);
  });
  log.debug('Leaving tree(). ' + rows.length + ' row(s).');
  return rows;
}

function categoryLabel(uri) {
  const found = CATEGORY_MENU.filter(function (one) {
    return one.uri === uri;
  })[0];
  return found ? found.label : uri;
}

module.exports = {
  nodeAt: nodeAt,
  kindAt: kindAt,
  optionsAt: optionsAt,
  applyEdit: applyEdit,
  tree: tree,
  matchFunctions: matchFunctions,
  applyFunctions: applyFunctions,
  typeMenu: typeMenu,
  shortName: shortName,
  shortType: shortType,
  categoryLabel: categoryLabel,
  CATEGORY_MENU: CATEGORY_MENU,
  RULE_ALG_MENU: RULE_ALG_MENU,
  ADDITIONS: ADDITIONS
};
