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
// THE NODE IS A SECOND ARGUMENT AND IT IS OPTIONAL, which is the one wrinkle
// in "derived from the path". Three kinds cannot be told apart from a path:
// the ROOT of a document is a `Policy` or a `PolicySet` and the two accept
// completely different children, and a `PolicySet`'s child is a Policy, a
// nested PolicySet or a reference — all three at `children.0`. So where the
// caller has the node it is passed and the answer is exact; where it does not,
// the path-derived answer is returned and it is the Policy one, which is what
// every caller of the one-argument form meant before policy sets were
// editable.
function kindAt(path, node) {
  const segments = segmentsOf(path);
  if (node && node.kind === 'PolicySet') {
    return 'policySet';
  }
  if (node && (node.kind === 'PolicyIdReference' ||
               node.kind === 'PolicySetIdReference')) {
    return 'reference';
  }
  if (!segments.length) {
    return 'policy';
  }
  const last = segments[segments.length - 1];
  const previous = segments.length > 1 ? segments[segments.length - 2] : '';
  if (last === 'target') {
    return 'target';
  }
  if (last === 'condition' || last === 'expression') {
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
  if (previous === 'assignments') {
    return 'assignment';
  }
  if (previous === 'variables') {
    return 'variable';
  }
  if (previous === 'children') {
    // A PolicySet's child, and the node above already answered the two cases
    // that are not a Policy. Without the node this is the safe answer: a
    // Policy offers rules, which is what a child of a set usually is.
    return 'policy';
  }
  if (previous === 'combinerParameters' || previous === 'parameters') {
    return 'combinerParameter';
  }
  if (previous === 'ruleCombinerParameters' ||
      previous === 'policyCombinerParameters' ||
      previous === 'policySetCombinerParameters') {
    return 'combinerParameterGroup';
  }
  return 'unknown';
}

// The nearest enclosing Policy or PolicySet, which is the SCOPE a
// VariableReference resolves in. A variable defined on one policy is invisible
// from a sibling policy in the same set — section 5.24 — so an editor that
// offered every variable in the document would offer references the validator
// then refuses, which is the one thing this file exists not to do.
function enclosingPolicy(policy, path) {
  log.debug('Entering enclosingPolicy(). path=' + path);
  const segments = segmentsOf(path);
  let node = policy;
  let holder = policy;
  for (let i = 0; i < segments.length; i += 1) {
    if (node === null || node === undefined) {
      break;
    }
    const key = segments[i];
    node = Array.isArray(node) ? node[Number(key)] : node[key];
    if (node && (node.kind === 'Policy' || node.kind === 'PolicySet')) {
      holder = node;
    }
  }
  log.debug('Leaving enclosingPolicy(). id=' + (holder ? holder.id : 'none'));
  return holder;
}

function isPolicySet(node) {
  return !!(node && node.kind === 'PolicySet');
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

// A one-line reading of an expression, for a menu or a detail line. It never
// throws and never returns '': a node the reader produced that this function
// has no case for is named by its kind, because a blank row in a tree is a
// node somebody cannot select.
function describeExpression(expression) {
  if (!expression) {
    return 'nothing';
  }
  if (expression.kind === 'value') {
    return '"' + expression.lexical + '" (' + shortType(expression.type) + ')';
  }
  if (expression.kind === 'designator') {
    return expression.attributeId + ' from ' +
      categoryLabel(expression.category);
  }
  if (expression.kind === 'selector') {
    return expression.path + ' in ' + categoryLabel(expression.category);
  }
  if (expression.kind === 'variableRef') {
    return '$' + expression.variableId;
  }
  if (expression.kind === 'function') {
    return shortName(expression.functionId) + ' (as a value)';
  }
  if (expression.kind === 'apply') {
    return shortName(expression.functionId) + '(' +
      (expression.args || []).length + ')';
  }
  return String(expression.kind);
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

// THE POLICY-COMBINING ALGORITHMS, WHICH ARE NOT THE RULE-COMBINING ONES AND
// ARE ALMOST SPELT THE SAME.
//
// `...:3.0:rule-combining-algorithm:deny-overrides` against
// `...:3.0:policy-combining-algorithm:deny-overrides` — one segment apart, and
// a PolicySet carrying the rule-combining spelling is a document that names an
// algorithm no combiner can find. That is why this is a second table rather
// than one table used in both places: the editor picks the menu from the kind
// of the node, so the wrong spelling is never on offer.
//
// `only-one-applicable` is the one that exists here and has no rule-combining
// counterpart at all, because it is about POLICIES being applicable — it is
// Indeterminate when two of them are, which is how a deployment says "these
// are meant to be disjoint and I want to hear about it when they are not".
const POLICY_ALG_MENU = [
  { uri: model.POLICY_ALG.DENY_UNLESS_PERMIT, label: 'deny-unless-permit',
    what: 'Anything not permitted is denied. Cannot return NotApplicable or ' +
          'Indeterminate, so the answer never depends on the PEP\'s bias.' },
  { uri: model.POLICY_ALG.PERMIT_UNLESS_DENY, label: 'permit-unless-deny',
    what: 'Anything not denied is permitted. The mirror, and the one to ' +
          'think twice about.' },
  { uri: model.POLICY_ALG.DENY_OVERRIDES, label: 'deny-overrides',
    what: 'One Deny outranks any number of Permits.' },
  { uri: model.POLICY_ALG.PERMIT_OVERRIDES, label: 'permit-overrides',
    what: 'One Permit outranks any number of Denies.' },
  { uri: model.POLICY_ALG.FIRST_APPLICABLE, label: 'first-applicable',
    what: 'The first child that decides anything wins. Order matters.' },
  { uri: model.POLICY_ALG.ONLY_ONE_APPLICABLE, label: 'only-one-applicable',
    what: 'Exactly one child may apply. Two applicable children is ' +
          'Indeterminate rather than a decision — the way to say that a set ' +
          'is meant to be disjoint and to hear about it when it is not. ' +
          'There is no rule-combining algorithm of this name.' },
  { uri: model.POLICY_ALG.ORDERED_DENY_OVERRIDES,
    label: 'ordered-deny-overrides',
    what: 'deny-overrides with the evaluation order fixed. Identical here, ' +
          'because this PDP always evaluates in document order.' },
  { uri: model.POLICY_ALG.ORDERED_PERMIT_OVERRIDES,
    label: 'ordered-permit-overrides',
    what: 'permit-overrides with the evaluation order fixed.' }
];

// Which menu a node's combining algorithm comes from. One function, so that
// the page, the edit and the refusal cannot disagree about it.
function algorithmMenuFor(node) {
  return isPolicySet(node) ? POLICY_ALG_MENU : RULE_ALG_MENU;
}

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
    { action: 'add-variable', label: 'Variable definition',
      help: 'Names an expression so that several rules can share it — and ' +
            'so it is evaluated once per request rather than once per use. ' +
            'Its scope is THIS policy: a sibling policy in the same set ' +
            'cannot see it.' },
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
  // A POLICY SET HOLDS POLICIES AND NOT RULES, which is the whole reason this
  // is a separate row rather than the list above with one thing added. Until
  // it existed the editor offered `Rule` on a policy set, accepted it, said
  // "Rule added." and wrote a document with no rule in it — because the writer
  // serializes a PolicySet's `children` and never looks at `rules`. An edit
  // that is accepted and then silently discarded is the worst failure this
  // editor can have, and it is what a menu keyed only by path produced.
  policySet: [
    { action: 'add-policy', label: 'Policy',
      help: 'A policy of its own, inside this set. It gets its own ' +
            'rule-combining algorithm — the set combines the POLICIES and ' +
            'each policy combines its own rules.' },
    { action: 'add-policyset', label: 'Policy set',
      help: 'A nested set. There is no depth limit.' },
    { action: 'add-policy-reference', label: 'PolicyIdReference',
      help: 'Names a policy stored SEPARATELY in the repository by its ' +
            'PolicyId. This is how a PDP reaches more than one document: ' +
            'the root is evaluated and references are resolved from the ' +
            'repository at decision time.' },
    { action: 'add-policyset-reference', label: 'PolicySetIdReference',
      help: 'The same, naming a policy set.' },
    { action: 'add-target-anyof', label: 'Target clause',
      help: 'Narrows what this whole set applies to. Every clause must ' +
            'match — they are ANDed.' },
    { action: 'add-policy-obligation', label: 'Obligation',
      help: 'Something the PEP must do when this SET decides. It MUST ' +
            'honour it or refuse the request.' },
    { action: 'add-policy-advice', label: 'Advice',
      help: 'Something the PEP may do. It is allowed to ignore this.' }
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
    { action: 'set-expression-selector', label: 'Attribute selector',
      help: 'Reads an XPath over the CONTENT of a request category, rather ' +
            'than a named attribute. Also a bag. The bindings for any ' +
            'prefixes in the path travel with it.' },
    { action: 'set-expression-function', label: 'Function reference',
      help: 'Names a function WITHOUT applying it — the first argument of a ' +
            'higher-order function such as any-of or map. It is a value ' +
            'here, not a call.' },
    { action: 'set-expression-variable', label: 'Variable reference',
      help: 'Uses a VariableDefinition declared on this policy. Offered ' +
            'only where there is one to name.' }
  ],
  match: [],
  obligation: [
    { action: 'add-assignment', label: 'Attribute assignment',
      help: 'A value handed to the PEP along with the obligation.' }
  ],
  // Four kinds with nothing legal underneath them. They are here as EMPTY
  // LISTS rather than absent, because `ADDITIONS[kind] || []` would give the
  // same answer for "nothing may be added here" and "nobody has thought about
  // this kind yet", and those became different answers the moment a policy set
  // was editable.
  assignment: [],
  variable: [],
  reference: [],
  combinerParameter: [],
  combinerParameterGroup: []
};

// The variables a VariableReference at this path may legally name: the ones
// declared on the nearest enclosing Policy, sorted, as `{ id, detail }` so the
// menu can say what each one IS rather than offering five bare names.
function variablesInScope(policy, path) {
  log.debug('Entering variablesInScope(). path=' + path);
  const holder = enclosingPolicy(policy, path);
  const variables = (holder && holder.variables) || {};
  const out = Object.keys(variables).sort().map(function (id) {
    return { id: id, detail: describeExpression(variables[id]) };
  });
  log.debug('Leaving variablesInScope(). ' + out.length + ' variable(s).');
  return out;
}

// A VariableDefinition HOLDS an expression, so what may be "added" at one is
// exactly what may be added at any expression: the definition is replaced.
// Assigned here rather than written twice in the table above, because two
// copies of that list would drift the moment a seventh expression kind
// arrived — which is how the fifth and sixth arrived to find the table saying
// four.
ADDITIONS.variable = ADDITIONS.expression.slice();

function optionsAt(policy, path) {
  log.debug('Entering optionsAt(). path=' + path);
  const located = nodeAt(policy, path);
  if (!located) {
    log.debug('Leaving optionsAt(). The path does not resolve.');
    return { kind: 'unknown', additions: [], removable: false };
  }
  const kind = kindAt(path, located.node);
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
  // A VariableReference may only name a variable THIS POLICY DEFINES (section
  // 5.24), so the option is withdrawn where there is none — an editor that
  // offered it would build `$v1`, the validator would refuse the document, and
  // the store would decline the write with a message about a variable the
  // person never asked for. It was exactly that until variables could be
  // defined here at all.
  if ((kind === 'expression' || kind === 'variable') &&
      !variablesInScope(policy, path).length) {
    additions = additions.filter(function (one) {
      return one.action !== 'set-expression-variable';
    });
  }
  // An `Apply` may take more arguments; every other expression is a leaf and
  // may only be REPLACED, which the `set-expression-*` options already do.
  if ((kind === 'expression' || kind === 'variable') &&
      located.node.kind === 'apply') {
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
    // why `target` is absent here. `path` rather than `kind` decides the root,
    // because a policy set INSIDE a set is a `policySet` that may certainly go.
    removable: path !== '' && kind !== 'target'
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
    if (isPolicySet(node)) {
      // The menu does not offer this here, and the management API is not the
      // menu. Without this the rule lands on `rules`, the writer serializes
      // `children` and never looks at it, and the reply says "Rule added."
      log.debug('Leaving applyEdit(). A policy set holds policies.');
      return { ok: false,
               why: 'A PolicySet holds policies, not rules. Add a Policy to ' +
                    'it and add the rule to that — the set combines the ' +
                    'policies and each policy combines its own rules.' };
    }
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

  if (action === 'add-policy' || action === 'add-policyset') {
    if (!isPolicySet(node)) {
      log.debug('Leaving applyEdit(). Not a policy set.');
      return { ok: false,
               why: 'Only a PolicySet holds policies. This is a Policy — it ' +
                    'holds rules.' };
    }
    const set = action === 'add-policyset';
    node.children = node.children || [];
    const child = {
      kind: set ? 'PolicySet' : 'Policy',
      id: (node.id || 'urn:policyset') + (set ? ':set:' : ':policy:') +
          (node.children.length + 1),
      description: '',
      version: '1.0',
      // COMPLETE AND VALID, and deny-unless-permit rather than something
      // permissive, because this editor is LIVE: a child added to the running
      // root takes effect on the next request, and one that started life
      // permitting whatever its parent's target let through would be a hole
      // opened by clicking Add. An empty deny-unless-permit policy denies,
      // which is the direction a half-built element should fail in.
      combiningAlgId: set ? model.POLICY_ALG.DENY_UNLESS_PERMIT
                          : model.RULE_ALG.DENY_UNLESS_PERMIT,
      target: null, obligations: [], advice: []
    };
    if (set) {
      child.children = [];
    } else {
      child.variables = {};
      child.rules = [];
    }
    node.children.push(child);
    log.debug('Leaving applyEdit(). ' + child.kind + ' added.');
    return { ok: true, what: (set ? 'Policy set' : 'Policy') + ' added.' };
  }

  if (action === 'add-policy-reference' ||
      action === 'add-policyset-reference') {
    if (!isPolicySet(node)) {
      log.debug('Leaving applyEdit(). Not a policy set.');
      return { ok: false,
               why: 'Only a PolicySet may reference another policy.' };
    }
    node.children = node.children || [];
    node.children.push({
      kind: action === 'add-policyset-reference' ? 'PolicySetIdReference'
                                                 : 'PolicyIdReference',
      // A REFERENCE TO SOMETHING THAT IS NOT THERE YET IS LEGAL AND IS NOT AN
      // ERROR HERE. It is resolved from the repository at DECISION time, not
      // at load time, so a policy may reference one that has not been written
      // yet — and `xacml_store.js` reports an unresolved reference on the
      // decision rather than refusing the document. Refusing it here would
      // make the order in which two policies are authored matter.
      ref: given.ref ? String(given.ref) : 'urn:example:policy:referenced',
      version: given.version ? String(given.version) : null
    });
    log.debug('Leaving applyEdit(). Reference added.');
    return { ok: true, what: 'Reference added.' };
  }

  if (action === 'edit-reference') {
    if (node.kind !== 'PolicyIdReference' &&
        node.kind !== 'PolicySetIdReference') {
      log.debug('Leaving applyEdit(). Not a reference.');
      return { ok: false, why: 'That node is not a policy reference.' };
    }
    if (given.ref) {
      node.ref = String(given.ref);
    }
    if (given.version !== undefined) {
      // An empty box means NO version constraint, which is a different
      // document from one naming a version — so '' is written as absent rather
      // than as the string ''.
      node.version = String(given.version) || null;
    }
    log.debug('Leaving applyEdit(). Reference edited.');
    return { ok: true, what: 'Reference updated.' };
  }

  if (action === 'add-variable') {
    if (isPolicySet(node)) {
      log.debug('Leaving applyEdit(). A policy set has no variables.');
      return { ok: false,
               why: 'A VariableDefinition belongs to a Policy. A PolicySet ' +
                    'has no variable scope of its own — section 5.24.' };
    }
    node.variables = node.variables || {};
    let id = String(given.variableId || '').trim();
    const badId = checkVariableId(id);
    if (badId) {
      log.debug('Leaving applyEdit(). ' + badId);
      return { ok: false, why: badId };
    }
    if (!id) {
      let n = Object.keys(node.variables).length + 1;
      while (node.variables['v' + n]) {
        n += 1;
      }
      id = 'v' + n;
    }
    if (node.variables[id]) {
      // The reader refuses a document with two definitions of one id, so
      // producing one here would write a policy this service cannot load back.
      log.debug('Leaving applyEdit(). Duplicate variable id.');
      return { ok: false,
               why: 'This policy already defines $' + id + ', and a ' +
                    'VariableId must be unique within a policy.' };
    }
    // COMPLETE AND VALID: a bag of the subject's employeeType, which is the
    // same starting expression `add-condition` uses and for the same reason —
    // a VariableDefinition with no expression is a document that will not load.
    node.variables[id] = {
      kind: 'designator', category: model.CATEGORY.ACCESS_SUBJECT,
      attributeId: 'employeeType', dataType: TYPE.STRING,
      issuer: null, mustBePresent: false
    };
    log.debug('Leaving applyEdit(). Variable added.');
    return { ok: true, what: 'Variable $' + id + ' added.' };
  }

  if (action === 'edit-variable') {
    const holder = enclosingPolicy(policy, path);
    const wasCalled = segmentsOf(path)[segmentsOf(path).length - 1];
    const renamed = String(given.variableId || '').trim();
    const badRename = checkVariableId(renamed);
    if (badRename) {
      log.debug('Leaving applyEdit(). ' + badRename);
      return { ok: false, why: badRename };
    }
    if (!renamed || renamed === wasCalled) {
      log.debug('Leaving applyEdit(). Nothing to rename.');
      return { ok: true, what: 'Unchanged.' };
    }
    if (holder.variables[renamed]) {
      log.debug('Leaving applyEdit(). Duplicate variable id.');
      return { ok: false,
               why: 'This policy already defines $' + renamed + '.' };
    }
    // EVERY REFERENCE IS REWRITTEN WITH IT. The alternative — refusing to
    // rename a variable that is used — is safe and useless, because a variable
    // nobody references is the only one nobody wants to rename. A rename that
    // left the references behind would produce a document that does not load,
    // and the store would refuse the write with a message about a variable
    // that no longer exists.
    holder.variables[renamed] = holder.variables[wasCalled];
    delete holder.variables[wasCalled];
    const rewritten = renameVariableReferences(holder, wasCalled, renamed);
    log.debug('Leaving applyEdit(). Variable renamed.');
    return { ok: true,
             what: 'Renamed to $' + renamed + ', and ' + rewritten +
                   ' reference(s) with it.' };
  }

  if (action === 'edit-assignment') {
    if (given.attributeId) {
      node.attributeId = String(given.attributeId);
    }
    if (given.category !== undefined) {
      node.category = String(given.category) || null;
    }
    if (given.issuer !== undefined) {
      node.issuer = String(given.issuer) || null;
    }
    log.debug('Leaving applyEdit(). Assignment edited.');
    return { ok: true, what: 'Assignment updated.' };
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
    const was = node.reference || {};
    // WHICH KIND OF REFERENCE. A <Match> may hold an <AttributeDesignator> or
    // an <AttributeSelector> and the schema allows exactly one of the two, so
    // this is a switch rather than two fields — and it keeps whichever it
    // already was when the form does not say, so the half of the form that
    // edits the function cannot silently turn a selector into a designator.
    const wantsSelector = given.referenceKind
      ? given.referenceKind === 'selector'
      : was.kind === 'selector';
    node.matchId = matchId;
    node.value = { kind: 'value', type: type,
                   lexical: given.value === undefined ? node.value.lexical
                                                      : String(given.value) };
    // THE DATATYPE FOLLOWS THE FUNCTION, always. A Match whose literal is a
    // string and whose designator is an integer does not typecheck, and
    // letting the two be chosen independently is how somebody spends ten
    // minutes on a form to be told at the end that it is wrong.
    node.reference = wantsSelector
      ? { kind: 'selector',
          category: given.category || was.category ||
                    model.CATEGORY.ACCESS_SUBJECT,
          path: given.path || was.path || '//*',
          dataType: type,
          contextSelectorId: given.contextSelectorId === undefined
            ? (was.contextSelectorId || null)
            : (String(given.contextSelectorId) || null),
          issuer: null,
          namespaces: was.namespaces || null,
          mustBePresent: flagOf(given.mustBePresent, was.mustBePresent) }
      : { kind: 'designator',
          category: given.category || was.category ||
                    model.CATEGORY.ACCESS_SUBJECT,
          attributeId: given.attributeId || was.attributeId ||
                       model.ATTRIBUTE.SUBJECT_ID,
          dataType: type,
          issuer: given.issuer === undefined
            ? (was.issuer || null) : (String(given.issuer) || null),
          mustBePresent: flagOf(given.mustBePresent, was.mustBePresent) };
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
    if (given.version !== undefined && String(given.version)) {
      // The schema's VersionType: dot-separated numbers. Checked here because
      // a Version of "draft 2" is refused by somebody else's schema validator
      // and by nothing in this service, so it would travel a long way before
      // anybody found out.
      if (!/^\d+(\.\d+)*$/.test(String(given.version))) {
        log.debug('Leaving applyEdit(). Bad version.');
        return { ok: false,
                 why: 'A Version is dot-separated numbers — "1", "1.0", ' +
                      '"2.13.7". "' + given.version + '" is not, and a ' +
                      'schema validator elsewhere would refuse the document.' };
      }
      node.version = String(given.version);
    }
    if (given.maxDelegationDepth !== undefined) {
      const depth = String(given.maxDelegationDepth).trim();
      if (depth && !/^\d+$/.test(depth)) {
        log.debug('Leaving applyEdit(). Bad delegation depth.');
        return { ok: false,
                 why: 'MaxDelegationDepth is a non-negative integer, or ' +
                      'empty for none.' };
      }
      node.maxDelegationDepth = depth || null;
    }
    if (given.xpathVersion !== undefined) {
      node.xpathVersion = String(given.xpathVersion).trim() || null;
    }
    if (given.combiningAlgId) {
      // THE MENU IS CHOSEN BY THE NODE. A PolicySet takes a POLICY-combining
      // algorithm and a Policy takes a RULE-combining one, and the two
      // vocabularies differ by one URI segment — so validating a policy set's
      // choice against the rule table would refuse every legal answer, and
      // accepting either would write a document naming an algorithm no
      // combiner can find.
      const menu = algorithmMenuFor(node);
      const known = menu.filter(function (one) {
        return one.uri === given.combiningAlgId;
      })[0];
      if (!known) {
        log.debug('Leaving applyEdit(). Unknown combining algorithm.');
        return { ok: false,
                 why: 'That is not one of the ' +
                      (isPolicySet(node) ? 'policy' : 'rule') +
                      '-combining algorithms this editor offers.' };
      }
      node.combiningAlgId = given.combiningAlgId;
    }
    log.debug('Leaving applyEdit(). Policy edited.');
    return { ok: true,
             what: (isPolicySet(node) ? 'Policy set' : 'Policy') +
                   ' updated.' };
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
      action === 'set-expression-selector' ||
      action === 'set-expression-function' ||
      action === 'set-expression-variable') {
    const replacement = newExpression(action, given,
                                      variablesInScope(policy, path));
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
    if (given.description !== undefined) {
      node.description = String(given.description);
    }
    log.debug('Leaving applyEdit(). Function changed.');
    return { ok: true, what: 'Function changed.' };
  }

  if (action === 'edit-value') {
    node.type = given.type || node.type;
    node.lexical = given.lexical === undefined ? node.lexical
                                               : String(given.lexical);
    if (given.xpathCategory !== undefined) {
      node.xpathCategory = String(given.xpathCategory) || null;
    }
    // An `xpathExpression` literal is an XPath and needs the category it runs
    // against; a value that is no longer one carries neither, so that a
    // datatype changed back to string does not leave an XPathCategory on it
    // for somebody to puzzle over.
    if (model.canonicalType(node.type) !== TYPE.XPATH_EXPRESSION) {
      node.xpathCategory = null;
    } else if (!node.xpathCategory) {
      node.xpathCategory = model.CATEGORY.RESOURCE;
    }
    log.debug('Leaving applyEdit(). Value edited.');
    return { ok: true, what: 'Value updated.' };
  }

  if (action === 'edit-designator') {
    node.category = given.category || node.category;
    node.attributeId = given.attributeId || node.attributeId;
    node.dataType = given.dataType || node.dataType;
    if (given.issuer !== undefined) {
      // OPTIONAL, AND ABSENT IS NOT THE SAME AS EMPTY. A designator with no
      // Issuer matches an attribute whatever its issuer; one with Issuer=""
      // matches only an attribute issued by the empty string, which is
      // nothing. So a cleared box is written as absent.
      node.issuer = String(given.issuer) || null;
    }
    node.mustBePresent = flagOf(given.mustBePresent, node.mustBePresent);
    log.debug('Leaving applyEdit(). Designator edited.');
    return { ok: true, what: 'Attribute updated.' };
  }

  if (action === 'edit-selector') {
    if (node.kind !== 'selector') {
      log.debug('Leaving applyEdit(). Not a selector.');
      return { ok: false, why: 'That node is not an AttributeSelector.' };
    }
    node.category = given.category || node.category;
    node.dataType = given.dataType || node.dataType;
    if (given.path) {
      node.path = String(given.path);
    }
    if (given.contextSelectorId !== undefined) {
      node.contextSelectorId = String(given.contextSelectorId) || null;
    }
    if (given.namespacePrefix !== undefined || given.namespaceUri !== undefined) {
      // ONE BINDING AT A TIME, because a no-JavaScript console cannot grow a
      // row. A prefix with no URI REMOVES that binding, which is the only way
      // to take one away without a second control.
      const prefix = String(given.namespacePrefix || '').trim();
      const uri = String(given.namespaceUri || '').trim();
      if (prefix) {
        node.namespaces = node.namespaces || {};
        if (uri) {
          node.namespaces[prefix] = uri;
        } else {
          delete node.namespaces[prefix];
        }
      }
    }
    node.mustBePresent = flagOf(given.mustBePresent, node.mustBePresent);
    log.debug('Leaving applyEdit(). Selector edited.');
    return { ok: true, what: 'Selector updated.' };
  }

  if (action === 'edit-function') {
    if (node.kind !== 'function') {
      log.debug('Leaving applyEdit(). Not a function reference.');
      return { ok: false, why: 'That node is not a function reference.' };
    }
    if (!functions.lookup(given.functionId)) {
      log.debug('Leaving applyEdit(). Unknown function.');
      return { ok: false, why: 'There is no function "' + given.functionId +
                               '".' };
    }
    node.functionId = given.functionId;
    log.debug('Leaving applyEdit(). Function reference changed.');
    return { ok: true, what: 'Function reference changed.' };
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

// A TRISTATE READ OF A FORM FIELD: true, false, or "the form did not say".
//
// It exists because of one specific way this console can lose information. An
// unchecked checkbox SENDS NOTHING, so a form that edits a Match's function
// and happens not to carry the MustBePresent box would clear MustBePresent on
// every save — silently turning "an absent attribute makes this Indeterminate"
// into "an absent attribute is an empty bag", which is the difference between
// a policy that fails closed and one that quietly does not apply. So the
// controls for it are <select>s with an explicit false, and a field that is
// genuinely absent keeps what was there.
function flagOf(given, current) {
  if (given === undefined || given === null || given === '') {
    return !!current;
  }
  return given === true || given === 'true' || given === 'on' || given === '1';
}

// Rewrite every <VariableReference> naming `from` to name `to`, within one
// policy, and say how many. Walks the same places `xacml_pdp.js` evaluates
// expressions in — the definitions themselves (a variable may be defined in
// terms of another), every rule's condition, and every attribute assignment on
// an obligation or advice at either level. A Target holds no expressions a
// reference can appear in: a <Match> takes an AttributeValue and a designator
// or selector, and none of those is a VariableReference.
function renameVariableReferences(holder, from, to) {
  log.debug('Entering renameVariableReferences(). from=' + from);
  let count = 0;

  function walk(expression) {
    if (!expression) {
      return;
    }
    if (expression.kind === 'variableRef' && expression.variableId === from) {
      expression.variableId = to;
      count += 1;
      return;
    }
    if (expression.kind === 'apply') {
      (expression.args || []).forEach(walk);
    }
  }

  function walkHolders(list) {
    (list || []).forEach(function (one) {
      (one.assignments || []).forEach(function (assignment) {
        walk(assignment.expression);
      });
    });
  }

  Object.keys(holder.variables || {}).forEach(function (id) {
    walk(holder.variables[id]);
  });
  (holder.rules || []).forEach(function (rule) {
    walk(rule.condition);
    walkHolders(rule.obligations);
    walkHolders(rule.advice);
  });
  walkHolders(holder.obligations);
  walkHolders(holder.advice);
  log.debug('Leaving renameVariableReferences(). ' + count + ' rewritten.');
  return count;
}

// A VariableId IS A PATH SEGMENT HERE, and that is this editor's limitation
// rather than XACML's. A variable is addressed as `variables.<id>`, and
// `segmentsOf()` splits an address on the dot — so a variable called `a.b`
// would produce a row nothing could edit or remove, while the document itself
// stayed perfectly valid. Refused at the point of naming, where it can still
// be explained, rather than discovered later as a row whose buttons do
// nothing.
function checkVariableId(id) {
  if (!id) {
    return null;
  }
  if (id.indexOf('.') >= 0) {
    return 'A variable name may not contain a dot in this editor. XACML ' +
           'allows one; this page addresses a node by a dotted path, so "' +
           id + '" would produce a row that cannot be edited or removed. ' +
           'The document itself would be valid — which is why this is ' +
           'refused here rather than by the validator.';
  }
  return null;
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

function newExpression(action, given, inScope) {
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
  if (action === 'set-expression-selector') {
    return { ok: true, expression: {
      kind: 'selector',
      category: given.category || model.CATEGORY.RESOURCE,
      // A path that selects everything, so the expression is complete and the
      // bag it returns is whatever the request's <Content> holds. An empty
      // Path is not legal and a selector with one would be a document that
      // does not load.
      path: given.path || '//*',
      dataType: given.dataType || TYPE.STRING,
      contextSelectorId: null, namespaces: null,
      mustBePresent: false } };
  }
  if (action === 'set-expression-function') {
    const named = given.functionId || (F1 + 'string-equal');
    if (!functions.lookup(named)) {
      return { ok: false, why: 'There is no function "' + named + '".' };
    }
    // A FUNCTION AS A VALUE, not a call: `<Function FunctionId="..."/>` is
    // what the first argument of `any-of` or `map` is, and applying it there
    // instead is the commonest way to write a higher-order function wrongly.
    return { ok: true, expression: { kind: 'function', functionId: named } };
  }
  if (action === 'set-expression-variable') {
    const available = inScope || [];
    const chosen = given.variableId ||
                   (available.length ? available[0].id : '');
    if (!chosen) {
      // Cannot happen through the console — `optionsAt()` withdraws the option
      // where there is nothing to name — and can happen through /admin-api,
      // which is not the menu.
      return { ok: false,
               why: 'This policy defines no variables, so there is nothing ' +
                    'for a VariableReference to name. Add a variable ' +
                    'definition to the policy first.' };
    }
    const known = available.filter(function (one) {
      return one.id === chosen;
    }).length > 0;
    if (!known) {
      return { ok: false,
               why: 'This policy defines no $' + chosen + '. A ' +
                    'VariableReference may only name a VariableDefinition on ' +
                    'the SAME policy — section 5.24 — and the document would ' +
                    'not load.' };
    }
    return { ok: true, expression: { kind: 'variableRef',
                                     variableId: chosen } };
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
    if (parameter.kind === 'function') {
      // THE SIX HIGHER-ORDER FUNCTIONS AND `map` TAKE A FUNCTION, and until
      // this branch existed they were handed an <AttributeValue> instead —
      // so choosing `any-of` from the menu built an expression the validator
      // refuses, the store declines the write, and the editor's one promise
      // (it cannot offer what the validator will refuse) was broken by seven
      // of the 275 entries in its own function list.
      //
      // `map` is the one that needs a different default: its function is
      // applied to ONE value and returns one, while the other six take a
      // predicate of two. A default of the wrong shape is legal XACML that
      // fails at evaluation, which is worse than one that fails at load.
      return { kind: 'function',
               functionId: /:map$/.test(functionId)
                 ? (F1 + 'string-normalize-to-lower-case')
                 : (F1 + 'string-equal') };
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
           (expression.args || []).length + ' argument(s)' +
           (expression.description ? ' — ' + expression.description : ''));
      (expression.args || []).forEach(function (argument, index) {
        walkExpression(argument, path + '.args.' + index, depth + 1, '');
      });
      return;
    }
    if (expression.kind === 'value') {
      push(path, depth, 'expression', label + '"' + expression.lexical + '"',
           shortType(expression.type) +
           (expression.xpathCategory
              ? ', over ' + categoryLabel(expression.xpathCategory) : ''));
      return;
    }
    if (expression.kind === 'designator') {
      push(path, depth, 'expression', label + expression.attributeId,
           shortType(expression.dataType) + ' from ' +
           categoryLabel(expression.category) +
           (expression.issuer ? ', issued by ' + expression.issuer : '') +
           (expression.mustBePresent ? ', must be present' : ''));
      return;
    }
    // AN AttributeSelector IS DRAWN AS ITS PATH, because that is what it is —
    // an XPath over the <Content> of a request category rather than a named
    // attribute. Until it was drawn at all, a policy holding one showed a row
    // labelled `selector` with no way to see or change the path.
    if (expression.kind === 'selector') {
      const bindings = Object.keys(expression.namespaces || {})
        .filter(function (prefix) {
          return prefix !== '';
        });
      push(path, depth, 'expression', label + expression.path,
           shortType(expression.dataType) + ' selected from ' +
           categoryLabel(expression.category) +
           (expression.contextSelectorId
              ? ', rooted at ' + expression.contextSelectorId : '') +
           (expression.mustBePresent ? ', must be present' : '') +
           (bindings.length
              ? ', ' + bindings.length + ' namespace binding(s)' : ''));
      return;
    }
    if (expression.kind === 'variableRef') {
      push(path, depth, 'expression', label + '$' + expression.variableId, '');
      return;
    }
    if (expression.kind === 'function') {
      push(path, depth, 'expression',
           label + shortName(expression.functionId),
           'a function used as a VALUE — not applied here');
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
          const reference = match.reference || {};
          push(allPath + '.matches.' + k, depth + 3, 'match',
               shortName(match.matchId),
               '"' + match.value.lexical + '" against ' +
               (reference.kind === 'selector'
                  ? 'the path ' + reference.path
                  : reference.attributeId) +
               ' in ' + categoryLabel(reference.category) +
               (reference.mustBePresent ? ', must be present' : ''));
        });
      });
    });
  }

  // An obligation or an advice, and the ATTRIBUTE ASSIGNMENTS under it — which
  // were addable and invisible until this walked them. `add-assignment` has
  // been in the menu since the editor shipped, and what it produced could not
  // be seen, edited or removed: the only way to correct a mistyped one was to
  // remove the whole obligation and build it again.
  function walkHolders(list, base, depth, what) {
    (list || []).forEach(function (one, i) {
      const path = base + '.' + (what === 'Advice' ? 'advice' : 'obligations') +
        '.' + i;
      push(path, depth, 'obligation', what + ' ' + one.id,
           'on ' + one.on + ', ' + (one.assignments || []).length +
           ' assignment(s)');
      (one.assignments || []).forEach(function (assignment, j) {
        const assignmentPath = path + '.assignments.' + j;
        push(assignmentPath, depth + 1, 'assignment', assignment.attributeId,
             (assignment.category
                ? 'in ' + categoryLabel(assignment.category) + ', ' : '') +
             (assignment.issuer ? 'issued by ' + assignment.issuer + ', ' : '') +
             'value: ' + describeExpression(assignment.expression));
        walkExpression(assignment.expression,
                       assignmentPath + '.expression', depth + 2, '');
      });
    });
  }

  // The four combiner-parameter elements, which are SHOWN AND REMOVABLE AND
  // NOT ADDABLE — the one place in this editor where those three come apart,
  // and it is deliberate. Section C of the specification says none of the
  // twelve standard combining algorithms takes a parameter, so an Add button
  // here would be the first control on this console that provably changes no
  // decision. Drawing them is a different question: a document may arrive with
  // them (through ALFA, an import, or an `ldapmodify` straight into
  // `ou=policies`), and an element the editor did not draw would be one the
  // person could neither see nor delete while the writer faithfully kept it.
  function walkCombinerParameters(node, base, depth) {
    (node.combinerParameters || []).forEach(function (one, i) {
      push(base + '.combinerParameters.' + i, depth, 'combinerParameter',
           'CombinerParameter ' + one.name,
           describeExpression(one.value) +
           ' — carried, and read by no standard algorithm');
    });
    [['ruleCombinerParameters', 'RuleCombinerParameters'],
     ['policyCombinerParameters', 'PolicyCombinerParameters'],
     ['policySetCombinerParameters', 'PolicySetCombinerParameters']]
      .forEach(function (pair) {
        (node[pair[0]] || []).forEach(function (group, i) {
          const path = base + '.' + pair[0] + '.' + i;
          push(path, depth, 'combinerParameterGroup',
               pair[1] + ' for ' + group.ref,
               (group.parameters || []).length + ' parameter(s) — carried, ' +
               'and read by no standard algorithm');
          (group.parameters || []).forEach(function (one, j) {
            push(path + '.parameters.' + j, depth + 1, 'combinerParameter',
                 one.name, describeExpression(one.value));
          });
        });
      });
  }

  // ONE WALK FOR A POLICY AND A POLICY SET, recursing through the second's
  // children. It used to walk `policy.rules` and nothing else, so a PolicySet
  // drew as a policy with no rules — an empty tree, an Add menu offering a
  // Rule the writer would discard, and no way to reach a single thing inside
  // the document.
  function walkPolicy(node, base, depth) {
    const set = isPolicySet(node);
    push(base, depth, set ? 'policySet' : 'policy', node.id,
         shortAlgorithm(node.combiningAlgId) + ', ' +
         (set ? (node.children || []).length + ' child(ren)'
              : (node.rules || []).length + ' rule(s)') +
         ', version ' + (node.version || '1.0') +
         (node.maxDelegationDepth
            ? ', delegation depth ' + node.maxDelegationDepth : '') +
         (node.xpathVersion ? ', XPath ' + node.xpathVersion : ''));
    walkTarget(node.target, base, depth + 1);

    if (set) {
      (node.children || []).forEach(function (child, index) {
        const path = base + '.children.' + index;
        if (child.kind === 'PolicyIdReference' ||
            child.kind === 'PolicySetIdReference') {
          push(path, depth + 1, 'reference', child.kind + ' ' + child.ref,
               (child.version ? 'version ' + child.version
                              : 'any version') +
               ' — resolved from the repository when a decision is made, ' +
               'not when the document is loaded');
          return;
        }
        walkPolicy(child, path, depth + 1);
      });
    } else {
      // THE VARIABLES COME BEFORE THE RULES, which is the schema's order and
      // also the reading order: a rule's condition may name one, and a
      // definition drawn after its use reads backwards.
      Object.keys(node.variables || {}).forEach(function (id) {
        const path = base + '.variables.' + id;
        push(path, depth + 1, 'variable', '$' + id,
             describeExpression(node.variables[id]) +
             ' — visible to this policy only');
        const definition = node.variables[id];
        if (definition && definition.kind === 'apply') {
          (definition.args || []).forEach(function (argument, index) {
            walkExpression(argument, path + '.args.' + index, depth + 2, '');
          });
        }
      });
      (node.rules || []).forEach(function (rule, index) {
        const rulePath = base + '.rules.' + index;
        push(rulePath, depth + 1, 'rule', rule.effect + ' — ' + rule.id,
             rule.description);
        walkTarget(rule.target, rulePath, depth + 2);
        if (rule.condition) {
          walkExpression(rule.condition, rulePath + '.condition', depth + 2,
                         'Condition: ');
        }
        walkHolders(rule.obligations, rulePath, depth + 2, 'Obligation');
        walkHolders(rule.advice, rulePath, depth + 2, 'Advice');
      });
    }
    walkCombinerParameters(node, base, depth + 1);
    walkHolders(node.obligations, base, depth + 1, 'Obligation');
    walkHolders(node.advice, base, depth + 1, 'Advice');
  }

  walkPolicy(policy, '', 0);
  log.debug('Leaving tree(). ' + rows.length + ' row(s).');
  return rows;
}

// ---------------------------------------------------------------------------
// THE ONE SCHEMA RULE THIS EDITOR CAN BREAK WITHOUT THE VALIDATOR NOTICING.
//
// Section 5.14: <XPathVersion> MUST be present when the policy contains an
// <AttributeSelector> or an `xpathExpression` value. It is a document rule
// rather than a typing rule, so `xacml_validate.js` says nothing about it and
// never will — that file refuses what is CERTAINLY WRONG for every request,
// and a missing XPathVersion changes no decision this PDP makes, because this
// PDP has exactly one XPath engine and does not switch dialects on a URI.
//
// So it is reported rather than refused, and reported where it can be fixed:
// the editor page draws it beside the field that sets it. Refusing the write
// would be the editor inventing a rule the evaluator does not have; saying
// nothing would let somebody build a document here that this service is
// perfectly happy with and somebody else's schema validator rejects — which is
// the failure mode `writeTarget()` argues about, arriving from the other side.
//
// Returns the policies (by id) that need one and have not got one, so the page
// can name them: in a policy set the requirement is per policy, and "somewhere
// in this document" would send somebody looking through five of them.
// ---------------------------------------------------------------------------
function xpathVersionGaps(policy) {
  log.debug('Entering xpathVersionGaps().');
  const gaps = [];

  function usesXPath(node) {
    let found = false;

    function walkExpression(expression) {
      if (!expression || found) {
        return;
      }
      if (expression.kind === 'selector') {
        found = true;
        return;
      }
      if (expression.kind === 'value' &&
          model.canonicalType(expression.type) === TYPE.XPATH_EXPRESSION) {
        found = true;
        return;
      }
      if (expression.kind === 'apply') {
        (expression.args || []).forEach(walkExpression);
      }
    }

    function walkTarget(target) {
      ((target || {}).anyOf || []).forEach(function (anyOf) {
        (anyOf.allOf || []).forEach(function (allOf) {
          (allOf.matches || []).forEach(function (match) {
            walkExpression(match.value);
            walkExpression(match.reference);
          });
        });
      });
    }

    function walkHolders(list) {
      (list || []).forEach(function (one) {
        (one.assignments || []).forEach(function (assignment) {
          walkExpression(assignment.expression);
        });
      });
    }

    walkTarget(node.target);
    Object.keys(node.variables || {}).forEach(function (id) {
      walkExpression(node.variables[id]);
    });
    (node.rules || []).forEach(function (rule) {
      walkTarget(rule.target);
      walkExpression(rule.condition);
      walkHolders(rule.obligations);
      walkHolders(rule.advice);
    });
    walkHolders(node.obligations);
    walkHolders(node.advice);
    return found;
  }

  function visit(node) {
    if (!node) {
      return;
    }
    if (usesXPath(node) && !node.xpathVersion) {
      gaps.push(node.id);
    }
    if (isPolicySet(node)) {
      (node.children || []).forEach(function (child) {
        if (child.kind === 'Policy' || child.kind === 'PolicySet') {
          visit(child);
        }
      });
    }
  }

  visit(policy);
  log.debug('Leaving xpathVersionGaps(). ' + gaps.length + ' gap(s).');
  return gaps;
}

// The bare name of a combining algorithm. `shortName()` strips a FUNCTION
// prefix and leaves an algorithm URI whole, which is why this is separate
// rather than one regular expression asked to do both — the two families of
// URI differ in more than their last segment.
function shortAlgorithm(uri) {
  return String(uri || '').replace(/^.*combining-algorithm:/, '') || '?';
}

function categoryLabel(uri) {
  const found = CATEGORY_MENU.filter(function (one) {
    return one.uri === uri;
  })[0];
  return found ? found.label : uri;
}

module.exports = {
  nodeAt: nodeAt,
  enclosingPolicy: enclosingPolicy,
  isPolicySet: isPolicySet,
  variablesInScope: variablesInScope,
  describeExpression: describeExpression,
  shortAlgorithm: shortAlgorithm,
  xpathVersionGaps: xpathVersionGaps,
  algorithmMenuFor: algorithmMenuFor,
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
  POLICY_ALG_MENU: POLICY_ALG_MENU,
  ADDITIONS: ADDITIONS
};
