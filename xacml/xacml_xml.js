'use strict';
//
// File: xacml_xml.js
//
// ---------------------------------------------------------------------------
// XACML 3.0 CORE XML, READ INTO THE MODEL AND WRITTEN BACK OUT.
//
// One of three readers — the JSON Profile and ALFA are the others — and all
// three produce the SAME `xacml_model.js` shapes. Nothing downstream of this
// file knows a policy came from XML. See the header of `xacml_model.js` for
// why that is the rule this directory is built on.
//
// This file reads with `@xmldom/xmldom`, which the api and this service
// already depend on for SAML and WS-Federation, and it uses `xpath` only where
// an `AttributeSelector` demands one — the policy grammar itself is walked by
// element name, because an XPath per element would be slower and would hide
// what is actually a very small tree walk.
//
// ---------------------------------------------------------------------------
// THE PARSER IS DELIBERATELY STRICT, AND SIX CONFORMANCE CASES DEPEND ON IT.
//
// Six cases in the vendored suite carry `Request.xml.ignore` and
// `Response.xml.ignore` — upstream renamed them so that no runner would
// evaluate them — because the POLICY in those cases is invalid and the whole
// assertion is that loading it FAILS. A permissive parser that shrugged at an
// unknown element or a missing attribute would load all six, produce a
// decision, and pass every one of them for the wrong reason.
//
// So an unrecognised element inside a construct this file understands is a
// SYNTAX ERROR rather than something skipped. The one deliberate looseness is
// the XML NAMESPACE: elements are matched on local name, because documents in
// the wild carry the 3.0 namespace, the 2.0 namespace and occasionally none,
// and rejecting a policy over its namespace declaration would fail cases about
// namespaces rather than about decisions. `xsi:schemaLocation` is ignored
// entirely — several cases in this suite carry one that points at the XACML
// 2.0 schema, which upstream's README lists as a defect in the original AT&T
// files.
//
// ---------------------------------------------------------------------------
// AN `AttributeValue` IS NOT PARSED HERE.
//
// It is carried as its LEXICAL FORM plus its declared datatype, and turned
// into a value by `xacml_datatypes.js` at evaluation time. That is not
// laziness — it is what keeps a bad lexical form an INDETERMINATE at
// evaluation rather than a load-time failure, which is the difference between
// a policy that refuses one request and a policy that will not load at all.
// The exception is `xpathExpression`, which has to capture the namespace
// bindings in scope AT THE POINT IT WAS WRITTEN, and those are gone once the
// element is out of the document.
// ---------------------------------------------------------------------------

const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');
const { log } = require('../common/helpers');
const model = require('./xacml_model');
const validate = require('./xacml_validate');

// ---------------------------------------------------------------------------
// SMALL DOM HELPERS. All of them match on LOCAL NAME — see the header.
// ---------------------------------------------------------------------------

function localName(node) {
  if (!node) {
    return '';
  }
  if (node.localName) {
    return node.localName;
  }
  const name = node.nodeName || '';
  const colon = name.indexOf(':');
  return colon < 0 ? name : name.slice(colon + 1);
}

function elementChildren(node) {
  const result = [];
  if (!node || !node.childNodes) {
    return result;
  }
  for (let i = 0; i < node.childNodes.length; i += 1) {
    const child = node.childNodes[i];
    if (child.nodeType === 1) {
      result.push(child);
    }
  }
  return result;
}

function childrenNamed(node, name) {
  return elementChildren(node).filter(function (child) {
    return localName(child) === name;
  });
}

function firstNamed(node, name) {
  const found = childrenNamed(node, name);
  return found.length ? found[0] : null;
}

function attribute(node, name) {
  if (!node || !node.getAttribute) {
    return null;
  }
  const value = node.getAttribute(name);
  return value === null || value === '' ? null : value;
}

function requiredAttribute(node, name) {
  const value = attribute(node, name);
  if (value === null) {
    throw model.syntaxError(
      '<' + localName(node) + '> is missing the required "' + name +
      '" attribute.');
  }
  return value;
}

// The text of an element, children and all. `AttributeValue` may hold markup
// for a structured datatype, so this concatenates text nodes rather than
// insisting on a single one.
function textOf(node) {
  let text = '';
  if (!node || !node.childNodes) {
    return text;
  }
  for (let i = 0; i < node.childNodes.length; i += 1) {
    const child = node.childNodes[i];
    if (child.nodeType === 3 || child.nodeType === 4) {
      text += child.nodeValue;
    } else if (child.nodeType === 1) {
      text += textOf(child);
    }
  }
  return text;
}

function booleanAttribute(node, name, fallback) {
  const value = attribute(node, name);
  if (value === null) {
    return fallback;
  }
  return value === 'true' || value === '1';
}

// ---------------------------------------------------------------------------
// THE NAMESPACE BINDINGS IN SCOPE AT AN ELEMENT.
//
// Walked up the tree, because an `xpathExpression` written deep in a policy
// may use a prefix declared on the document element — and once the value is
// out of the document there is nothing left to resolve it against. Collecting
// them at parse time is the only moment this information exists.
// ---------------------------------------------------------------------------
function namespacesInScope(node) {
  log.debug('Entering namespacesInScope().');
  const bindings = {};
  let current = node;
  while (current && current.nodeType === 1) {
    if (current.attributes) {
      for (let i = 0; i < current.attributes.length; i += 1) {
        const attr = current.attributes[i];
        if (attr.name === 'xmlns') {
          // An inner declaration wins, so a binding already collected from a
          // DEEPER element is not overwritten by an outer one.
          if (bindings[''] === undefined) {
            bindings[''] = attr.value;
          }
        } else if (attr.name.indexOf('xmlns:') === 0) {
          const prefix = attr.name.slice(6);
          if (bindings[prefix] === undefined) {
            bindings[prefix] = attr.value;
          }
        }
      }
    }
    current = current.parentNode;
  }
  log.debug('Leaving namespacesInScope(). ' +
            Object.keys(bindings).length + ' binding(s).');
  return bindings;
}

// ---------------------------------------------------------------------------
// EXPRESSIONS.
//
// The six things that can appear where XACML expects an <Expression>. The
// substitution group is closed, so anything else here is a syntax error rather
// than something to skip — see the header.
// ---------------------------------------------------------------------------
function readExpression(node) {
  log.debug('Entering readExpression(). element=' + localName(node));
  const name = localName(node);
  if (name === 'AttributeValue') {
    const type = model.canonicalType(requiredAttribute(node, 'DataType'));
    const expression = { kind: 'value', type: type, lexical: textOf(node) };
    if (type === model.TYPE.XPATH_EXPRESSION) {
      // See the header: the bindings have to be captured now.
      expression.namespaces = namespacesInScope(node);
      expression.xpathCategory = attribute(node, 'XPathCategory');
    }
    log.debug('Leaving readExpression(). AttributeValue.');
    return expression;
  }
  if (name === 'AttributeDesignator') {
    log.debug('Leaving readExpression(). AttributeDesignator.');
    return {
      kind: 'designator',
      category: requiredAttribute(node, 'Category'),
      attributeId: requiredAttribute(node, 'AttributeId'),
      dataType: model.canonicalType(requiredAttribute(node, 'DataType')),
      issuer: attribute(node, 'Issuer'),
      // MustBePresent is REQUIRED by the schema and defaults to nothing. A
      // missing one is treated as false, which is the permissive reading and
      // the one every implementation takes — but it is recorded as a default
      // rather than assumed, because the difference between false and absent
      // is the difference between "not there is fine" and "nobody said".
      mustBePresent: booleanAttribute(node, 'MustBePresent', false)
    };
  }
  if (name === 'AttributeSelector') {
    log.debug('Leaving readExpression(). AttributeSelector.');
    return {
      kind: 'selector',
      category: requiredAttribute(node, 'Category'),
      path: requiredAttribute(node, 'Path'),
      dataType: model.canonicalType(requiredAttribute(node, 'DataType')),
      contextSelectorId: attribute(node, 'ContextSelectorId'),
      mustBePresent: booleanAttribute(node, 'MustBePresent', false),
      namespaces: namespacesInScope(node)
    };
  }
  if (name === 'Apply') {
    const args = elementChildren(node)
      .filter(function (child) {
        // <Description> is allowed inside <Apply> and is not an argument.
        // Treating it as one would shift every argument by a place and produce
        // an arity error naming the wrong function.
        return localName(child) !== 'Description';
      })
      .map(readExpression);
    log.debug('Leaving readExpression(). Apply with ' + args.length +
              ' argument(s).');
    return { kind: 'apply',
             functionId: requiredAttribute(node, 'FunctionId'),
             args: args };
  }
  if (name === 'Function') {
    // A function used as a VALUE — the first argument of a higher-order
    // function. It is not applied here and carries no arguments.
    log.debug('Leaving readExpression(). Function reference.');
    return { kind: 'function',
             functionId: requiredAttribute(node, 'FunctionId') };
  }
  if (name === 'VariableReference') {
    log.debug('Leaving readExpression(). VariableReference.');
    return { kind: 'variableRef',
             variableId: requiredAttribute(node, 'VariableId') };
  }
  log.debug('Leaving readExpression(). Unrecognised.');
  throw model.syntaxError('<' + name + '> is not a XACML expression.');
}

// ---------------------------------------------------------------------------
// TARGETS.
//
// Target -> AnyOf* (all must match)
// AnyOf  -> AllOf* (at least one must match)
// AllOf  -> Match* (all must match)
//
// The nesting reads backwards from the element names and is the thing most
// worth being careful about: `AnyOf` holds `AllOf` children and is satisfied
// when ANY of them is, while the `Target` above it is satisfied only when ALL
// of its `AnyOf` children are. An absent or empty Target matches EVERYTHING,
// which is why `null` is a meaningful value here rather than an omission.
// ---------------------------------------------------------------------------
function readTarget(node) {
  log.debug('Entering readTarget().');
  if (!node) {
    log.debug('Leaving readTarget(). Absent, so it matches everything.');
    return null;
  }
  const anyOf = childrenNamed(node, 'AnyOf').map(function (anyOfNode) {
    const allOf = childrenNamed(anyOfNode, 'AllOf').map(function (allOfNode) {
      const matches = childrenNamed(allOfNode, 'Match').map(readMatch);
      if (matches.length === 0) {
        throw model.syntaxError('<AllOf> must hold at least one <Match>.');
      }
      return { matches: matches };
    });
    if (allOf.length === 0) {
      throw model.syntaxError('<AnyOf> must hold at least one <AllOf>.');
    }
    return { allOf: allOf };
  });
  if (anyOf.length === 0) {
    log.debug('Leaving readTarget(). Empty, so it matches everything.');
    return null;
  }
  log.debug('Leaving readTarget(). ' + anyOf.length + ' AnyOf.');
  return { anyOf: anyOf };
}

function readMatch(node) {
  log.debug('Entering readMatch().');
  const value = firstNamed(node, 'AttributeValue');
  if (!value) {
    throw model.syntaxError('<Match> must hold an <AttributeValue>.');
  }
  const designator = firstNamed(node, 'AttributeDesignator');
  const selector = firstNamed(node, 'AttributeSelector');
  if (!designator && !selector) {
    throw model.syntaxError(
      '<Match> must hold an <AttributeDesignator> or an ' +
      '<AttributeSelector>.');
  }
  log.debug('Leaving readMatch().');
  return { matchId: requiredAttribute(node, 'MatchId'),
           value: readExpression(value),
           reference: readExpression(designator || selector) };
}

// ---------------------------------------------------------------------------
// OBLIGATIONS AND ADVICE.
//
// Structurally identical and semantically not: a PEP MUST honour an obligation
// or refuse the request, and MAY ignore advice. They are read by one function
// and kept in two lists, because collapsing them into one list with a flag is
// how the distinction gets lost at the point it matters.
// ---------------------------------------------------------------------------
function readExpressionHolders(parent, wrapper, item, idAttribute) {
  const container = firstNamed(parent, wrapper);
  if (!container) {
    return [];
  }
  return childrenNamed(container, item).map(function (node) {
    return {
      id: requiredAttribute(node, idAttribute),
      // FulfillOn on an obligation, AppliesTo on advice. Same idea, two
      // spellings, and the specification is the reason rather than this file.
      on: requiredAttribute(node,
                            item === 'ObligationExpression' ? 'FulfillOn'
                                                            : 'AppliesTo'),
      assignments: childrenNamed(node, 'AttributeAssignmentExpression')
        .map(function (assignment) {
          const children = elementChildren(assignment);
          if (children.length !== 1) {
            throw model.syntaxError(
              '<AttributeAssignmentExpression> must hold exactly one ' +
              'expression.');
          }
          return {
            attributeId: requiredAttribute(assignment, 'AttributeId'),
            category: attribute(assignment, 'Category'),
            issuer: attribute(assignment, 'Issuer'),
            expression: readExpression(children[0])
          };
        })
    };
  });
}

function readObligations(parent) {
  return readExpressionHolders(parent, 'ObligationExpressions',
                               'ObligationExpression', 'ObligationId');
}

function readAdvice(parent) {
  return readExpressionHolders(parent, 'AdviceExpressions',
                               'AdviceExpression', 'AdviceId');
}

// ---------------------------------------------------------------------------
// RULES, POLICIES AND POLICY SETS.
// ---------------------------------------------------------------------------
function readRule(node) {
  log.debug('Entering readRule().');
  const condition = firstNamed(node, 'Condition');
  const effect = requiredAttribute(node, 'Effect');
  if (effect !== model.EFFECT.PERMIT && effect !== model.EFFECT.DENY) {
    throw model.syntaxError(
      'A <Rule> Effect must be "Permit" or "Deny"; this one is "' + effect +
      '".');
  }
  let conditionExpression = null;
  if (condition) {
    const children = elementChildren(condition);
    if (children.length !== 1) {
      throw model.syntaxError(
        '<Condition> must hold exactly one expression; this one holds ' +
        children.length + '.');
    }
    conditionExpression = readExpression(children[0]);
  }
  log.debug('Leaving readRule(). id=' + attribute(node, 'RuleId'));
  return { id: requiredAttribute(node, 'RuleId'),
           effect: effect,
           target: readTarget(firstNamed(node, 'Target')),
           condition: conditionExpression,
           obligations: readObligations(node),
           advice: readAdvice(node) };
}

function readVariableDefinitions(node) {
  log.debug('Entering readVariableDefinitions().');
  const variables = {};
  childrenNamed(node, 'VariableDefinition').forEach(function (definition) {
    const id = requiredAttribute(definition, 'VariableId');
    if (variables[id]) {
      // The specification requires VariableId to be unique within a policy,
      // and the vendored suite has a case for it. A duplicate silently
      // overwriting the first would make which definition wins depend on
      // document order, which is not something a policy author can see.
      throw model.syntaxError(
        'VariableId "' + id + '" is defined twice in one <Policy>.');
    }
    const children = elementChildren(definition);
    if (children.length !== 1) {
      throw model.syntaxError(
        '<VariableDefinition> must hold exactly one expression.');
    }
    variables[id] = readExpression(children[0]);
  });
  log.debug('Leaving readVariableDefinitions(). ' +
            Object.keys(variables).length + ' variable(s).');
  return variables;
}

function readPolicy(node) {
  log.debug('Entering readPolicy().');
  const rules = childrenNamed(node, 'Rule').map(readRule);
  const seen = {};
  rules.forEach(function (rule) {
    if (seen[rule.id]) {
      throw model.syntaxError(
        'RuleId "' + rule.id + '" appears twice in one <Policy>.');
    }
    seen[rule.id] = true;
  });
  log.debug('Leaving readPolicy(). ' + rules.length + ' rule(s).');
  return {
    kind: 'Policy',
    id: requiredAttribute(node, 'PolicyId'),
    version: attribute(node, 'Version') || '1.0',
    combiningAlgId: requiredAttribute(node, 'RuleCombiningAlgId'),
    target: readTarget(firstNamed(node, 'Target')),
    variables: readVariableDefinitions(node),
    rules: rules,
    obligations: readObligations(node),
    advice: readAdvice(node),
    maxDelegationDepth: attribute(node, 'MaxDelegationDepth')
  };
}

function readPolicySet(node) {
  log.debug('Entering readPolicySet().');
  const children = [];
  elementChildren(node).forEach(function (child) {
    const name = localName(child);
    if (name === 'Policy') {
      children.push(readPolicy(child));
    } else if (name === 'PolicySet') {
      children.push(readPolicySet(child));
    } else if (name === 'PolicyIdReference') {
      children.push({ kind: 'PolicyIdReference', ref: textOf(child).trim(),
                      version: attribute(child, 'Version') });
    } else if (name === 'PolicySetIdReference') {
      children.push({ kind: 'PolicySetIdReference', ref: textOf(child).trim(),
                      version: attribute(child, 'Version') });
    }
  });
  log.debug('Leaving readPolicySet(). ' + children.length + ' child(ren).');
  return {
    kind: 'PolicySet',
    id: requiredAttribute(node, 'PolicySetId'),
    version: attribute(node, 'Version') || '1.0',
    combiningAlgId: requiredAttribute(node, 'PolicyCombiningAlgId'),
    target: readTarget(firstNamed(node, 'Target')),
    children: children,
    obligations: readObligations(node),
    advice: readAdvice(node)
  };
}

// ---------------------------------------------------------------------------
// THE ENTRY POINTS.
// ---------------------------------------------------------------------------
function parseDocument(xml) {
  log.debug('Entering parseDocument().');
  // `@xmldom/xmldom` reports a malformed document by CALLING A HANDLER rather
  // than throwing, and its default handler writes to the console and carries
  // on — so without this, a truncated policy parses to a partial tree and
  // fails much later as something that is not an element. Six conformance
  // cases assert that a bad document is refused, and every one of them would
  // pass for the wrong reason.
  // `onError` IS THE ONLY SPELLING. The older `errorHandler` object is not
  // merely deprecated in @xmldom/xmldom 0.9 — passing one THROWS a TypeError
  // out of the constructor ("errorHandler object is no longer supported"), so
  // carrying both spellings defensively is not free: it makes every parse fail
  // before a document is read. It cost the first conformance run here, where
  // 449 of 455 cases reported "could not be loaded" and named an option rather
  // than a policy.
  const errors = [];
  const parser = new DOMParser({
    onError: function (level, message) {
      // Warnings are ignored deliberately. Several policies in the vendored
      // suite carry an `xsi:schemaLocation` pointing at the XACML 2.0 schema —
      // upstream's README lists it as a defect in the original AT&T files —
      // and refusing those would fail cases over a schema hint rather than
      // over a decision.
      if (level === 'error' || level === 'fatalError') {
        errors.push(String(message));
      }
    }
  });
  const document = parser.parseFromString(xml, 'text/xml');
  if (errors.length) {
    log.debug('Leaving parseDocument(). Malformed.');
    throw model.syntaxError('The document is not well-formed XML: ' +
                            errors[0], { errors: errors });
  }
  if (!document || !document.documentElement) {
    log.debug('Leaving parseDocument(). No document element.');
    throw model.syntaxError('The document has no root element.');
  }
  log.debug('Leaving parseDocument(). Root is ' +
            localName(document.documentElement) + '.');
  return document;
}

function parsePolicy(xml) {
  log.debug('Entering parsePolicy().');
  const root = parseDocument(xml).documentElement;
  const name = localName(root);
  if (name === 'Policy' || name === 'PolicySet') {
    const parsed = name === 'Policy' ? readPolicy(root)
                                     : readPolicySet(root);
    // STATIC VALIDATION IS PART OF LOADING, not a separate step a caller can
    // forget. XACML is statically typed and a policy that does not typecheck
    // is wrong for every request rather than for some — see
    // `xacml_validate.js`, which the JSON and ALFA readers call at the same
    // point so that all three refuse the same documents.
    validate.validate(parsed);
    log.debug('Leaving parsePolicy(). A valid ' + name + '.');
    return parsed;
  }
  log.debug('Leaving parsePolicy(). Wrong root element.');
  throw model.syntaxError(
    'A policy document\'s root must be <Policy> or <PolicySet>; this one is ' +
    '<' + name + '>.');
}

// ---------------------------------------------------------------------------
// A REQUEST.
//
// The shape is flat on purpose: a list of categories, each holding a list of
// attributes, each holding a bag of values. That is what the specification
// says a request IS, and the temptation to index it by category on the way in
// is worth resisting — a request may carry the SAME category twice (which is
// how the Multiple Decision Profile's scheme 2.3 works), and a map keyed by
// category would silently lose one of them.
// ---------------------------------------------------------------------------
function parseRequest(xml) {
  log.debug('Entering parseRequest().');
  const root = parseDocument(xml).documentElement;
  if (localName(root) !== 'Request') {
    log.debug('Leaving parseRequest(). Wrong root element.');
    throw model.syntaxError(
      'A request document\'s root must be <Request>; this one is <' +
      localName(root) + '>.');
  }
  const categories = childrenNamed(root, 'Attributes').map(function (node) {
    const content = firstNamed(node, 'Content');
    return {
      category: requiredAttribute(node, 'Category'),
      id: attribute(node, 'id'),
      // The <Content> is kept as a DOM node rather than as text, because an
      // AttributeSelector runs an XPath over it and re-parsing at every
      // evaluation would be both slow and a second chance to disagree about
      // namespaces.
      content: content || null,
      attributes: childrenNamed(node, 'Attribute').map(function (each) {
        return {
          attributeId: requiredAttribute(each, 'AttributeId'),
          issuer: attribute(each, 'Issuer'),
          includeInResult: booleanAttribute(each, 'IncludeInResult',
                                            false),
          values: childrenNamed(each, 'AttributeValue')
            .map(function (valueNode) {
              return {
                type: model.canonicalType(
                  requiredAttribute(valueNode, 'DataType')),
                lexical: textOf(valueNode),
                node: valueNode
              };
            })
        };
      })
    };
  });
  log.debug('Leaving parseRequest(). ' + categories.length + ' category(ies).');
  return {
    returnPolicyIdList: booleanAttribute(root, 'ReturnPolicyIdList', false),
    combinedDecision: booleanAttribute(root, 'CombinedDecision', false),
    categories: categories
  };
}

// ---------------------------------------------------------------------------
// A RESPONSE, READ BACK.
//
// Only the conformance runner needs this — a PDP produces responses and does
// not consume them. It is here rather than in the test because the runner
// comparing responses must read them the same way this implementation writes
// them, and two readings would be the very thing this directory refuses.
// ---------------------------------------------------------------------------
function parseResponse(xml) {
  log.debug('Entering parseResponse().');
  const root = parseDocument(xml).documentElement;
  if (localName(root) !== 'Response') {
    throw model.syntaxError('Expected <Response>, found <' +
                            localName(root) + '>.');
  }
  const results = childrenNamed(root, 'Result').map(function (node) {
    const status = firstNamed(node, 'Status');
    const statusCode = status ? firstNamed(status, 'StatusCode') : null;
    return {
      decision: textOf(firstNamed(node, 'Decision')).trim(),
      status: statusCode ? { code: attribute(statusCode, 'Value') } : null,
      obligations: readResponseAssignments(node, 'Obligations', 'Obligation',
                                           'ObligationId'),
      advice: readResponseAssignments(node, 'AssociatedAdvice', 'Advice',
                                      'AdviceId')
    };
  });
  log.debug('Leaving parseResponse(). ' + results.length + ' result(s).');
  return { results: results };
}

function readResponseAssignments(parent, wrapper, item, idAttribute) {
  const container = firstNamed(parent, wrapper);
  if (!container) {
    return [];
  }
  return childrenNamed(container, item).map(function (node) {
    return {
      id: attribute(node, idAttribute),
      assignments: childrenNamed(node, 'AttributeAssignment')
        .map(function (assignment) {
          return {
            attributeId: attribute(assignment, 'AttributeId'),
            category: attribute(assignment, 'Category'),
            type: model.canonicalType(attribute(assignment, 'DataType') ||
                                      model.TYPE.STRING),
            lexical: textOf(assignment)
          };
        })
    };
  });
}

module.exports = {
  parsePolicy: parsePolicy,
  parseRequest: parseRequest,
  parseResponse: parseResponse,
  parseDocument: parseDocument,
  localName: localName,
  elementChildren: elementChildren,
  childrenNamed: childrenNamed,
  firstNamed: firstNamed,
  textOf: textOf,
  namespacesInScope: namespacesInScope,
  readExpression: readExpression,
  readTarget: readTarget
};
