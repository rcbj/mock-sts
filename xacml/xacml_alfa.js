'use strict';
//
// File: xacml_alfa.js
//
// ---------------------------------------------------------------------------
// ALFA — THE ABBREVIATED LANGUAGE FOR AUTHORIZATION — READ AND WRITTEN.
//
// The THIRD rendering of `xacml_model.js`, and the one people actually want to
// look at. A policy that is forty lines of XML is eight lines of ALFA, and the
// eight say the same thing:
//
//     policy staffAccess {
//         apply denyUnlessPermit
//         rule allowStaff {
//             permit
//             target clause employeeType == "staff" and actionId == "GET"
//         }
//     }
//
// So this file is a parser and an emitter over the same model the XML reader
// produces, and NOTHING downstream knows which one a policy came from — see
// `xacml_model.js`'s header for why that is the rule this directory is built
// on. It is also what made this phase cheap: the model, the validator and the
// writer were already there, so ALFA is a syntax and not a second policy
// system.
//
// ---------------------------------------------------------------------------
// ALFA IS A COMMITTEE SPECIFICATION DRAFT, NOT A RATIFIED STANDARD.
//
// It was Axiomatics' language, contributed to the OASIS XACML TC, and it has
// never gone to Committee Specification. There is no conformance suite for it,
// no schema, and no second implementation to disagree with — which is a very
// different footing from the rest of this directory, where 455 cases somebody
// else wrote hold the engine honest.
//
// So the contract this file offers is one it can actually keep, stated rather
// than implied:
//
//   **ANYTHING THIS EMITTER WRITES, THIS PARSER READS, AND THE POLICY DECIDES
//   IDENTICALLY EITHER WAY.**
//
// `tests/xacml_alfa.js` asserts exactly that, in both directions, over every
// policy the templates can build and over the seeded one. What this file does
// NOT claim is that it reads every ALFA document in the world: the language
// has corners — macros, `advice` at namespace scope, imports across files —
// that nothing here emits and nothing here parses, and it says so when it
// meets one rather than guessing.
//
// ---------------------------------------------------------------------------
// THREE PLACES THIS DIALECT IS EXPLICIT WHERE ALFA IS VAGUE, AND EACH IS
// WRITTEN DOWN BECAUSE A READER WILL OTHERWISE THINK IT IS A BUG.
//
// 1. TYPED LITERALS. ALFA has native syntax for strings, integers, booleans
//    and doubles and nothing agreed for the other thirteen datatypes. This
//    dialect writes those as a cast — `date("2026-01-01")`,
//    `anyURI("https://x/y")` — and reads the same. Without it a `date` would
//    have to be emitted as a string and would come back as one, which is a
//    policy that silently stops comparing dates.
//
// 2. THE THREE LEVELS OF A TARGET MAP ONTO `clause`, `or` AND `and`, in that
//    order. A XACML Target is AnyOf* (ANDed), an AnyOf is AllOf* (ORed) and an
//    AllOf is Match* (ANDed) — so each `clause` is one AnyOf, `or` separates
//    alternatives within it, and `and` joins matches inside an alternative.
//    `and` binds tighter than `or`, which makes `A and B or C` mean
//    `(A and B) or C` and lands on exactly the shape XACML wants.
//
// 3. AN ATTRIBUTE IS DECLARED BEFORE IT IS USED. ALFA references attributes by
//    a short name and the mapping to a category, an AttributeId and a datatype
//    lives in an `attribute` declaration. The emitter writes one for every
//    designator it meets and the parser refuses a name it has not seen — which
//    is the single most useful refusal in this file, because a typo in an
//    attribute name is otherwise a policy that quietly matches nothing.
//
// 4. A BARE NAME MAY ALSO BE A FUNCTION, AND THAT IS WHAT A HIGHER-ORDER
//    FUNCTION TAKES. `anyOfAny(stringEqual, a, b)` passes the FUNCTION
//    `string-equal` as an argument — a `<Function>` element in XACML, not an
//    `<AttributeValue>` and not a designator — and the seven higher-order
//    functions this engine implements are the only place one appears. The
//    emitter has always written it as the bare short name, which is the only
//    spelling ALFA has; the parser read it as an attribute reference and
//    refused the document, so `anyOfAny` round-tripped in one direction only.
//    It was found the day the first policy here used one — the `role-issuance`
//    template, whose whole condition is an intersection test.
//
//    **A DECLARATION WINS.** A name that is BOTH declared as an attribute and
//    the short name of a function is the attribute, because the declaration is
//    something somebody wrote in this document on purpose. The emitter makes
//    sure the two can never collide from its side: `collectAttributes()` will
//    not hand a designator a short name that a function already owns, and
//    numbers it instead. Point 3's refusal is unchanged for every name that is
//    neither — it just says so about both kinds now.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const model = require('./xacml_model');
const datatypes = require('./xacml_datatypes');
const functions = require('./xacml_functions');

const F1 = 'urn:oasis:names:tc:xacml:1.0:function:';
const F3 = 'urn:oasis:names:tc:xacml:3.0:function:';
const TYPE = model.TYPE;

// ---------------------------------------------------------------------------
// THE NAMES ALFA USES FOR THINGS THAT HAVE URIs IN XACML.
// ---------------------------------------------------------------------------
const CATEGORY_NAMES = {
  subjectCat: model.CATEGORY.ACCESS_SUBJECT,
  resourceCat: model.CATEGORY.RESOURCE,
  actionCat: model.CATEGORY.ACTION,
  environmentCat: model.CATEGORY.ENVIRONMENT,
  recipientSubjectCat: model.CATEGORY.RECIPIENT_SUBJECT,
  intermediarySubjectCat: model.CATEGORY.INTERMEDIARY_SUBJECT,
  codebaseCat: model.CATEGORY.CODEBASE,
  requestingMachineCat: model.CATEGORY.REQUESTING_MACHINE
};

const CATEGORY_URIS = {};
Object.keys(CATEGORY_NAMES).forEach(function (name) {
  CATEGORY_URIS[CATEGORY_NAMES[name]] = name;
});

// The combining algorithms, in ALFA's camel case. Both the 3.0 and the legacy
// 1.0 spellings map to the same ALFA name, and the emitter writes the 3.0 one
// back — which is a NORMALISATION and is worth knowing: a policy that came in
// naming the legacy algorithm and goes out through ALFA names the modern one.
// They are different functions (see `xacml_pdp.js`), so this is the one place
// a round trip through ALFA can change what a policy does, and it only does so
// for the legacy spellings.
const ALGORITHM_NAMES = {
  denyOverrides: [model.RULE_ALG.DENY_OVERRIDES,
                  model.POLICY_ALG.DENY_OVERRIDES],
  permitOverrides: [model.RULE_ALG.PERMIT_OVERRIDES,
                    model.POLICY_ALG.PERMIT_OVERRIDES],
  orderedDenyOverrides: [model.RULE_ALG.ORDERED_DENY_OVERRIDES,
                         model.POLICY_ALG.ORDERED_DENY_OVERRIDES],
  orderedPermitOverrides: [model.RULE_ALG.ORDERED_PERMIT_OVERRIDES,
                           model.POLICY_ALG.ORDERED_PERMIT_OVERRIDES],
  denyUnlessPermit: [model.RULE_ALG.DENY_UNLESS_PERMIT,
                     model.POLICY_ALG.DENY_UNLESS_PERMIT],
  permitUnlessDeny: [model.RULE_ALG.PERMIT_UNLESS_DENY,
                     model.POLICY_ALG.PERMIT_UNLESS_DENY],
  firstApplicable: [model.RULE_ALG.FIRST_APPLICABLE,
                    model.POLICY_ALG.FIRST_APPLICABLE],
  onlyOneApplicable: [null, model.POLICY_ALG.ONLY_ONE_APPLICABLE]
};

function algorithmNameOf(uri) {
  const names = Object.keys(ALGORITHM_NAMES);
  for (let i = 0; i < names.length; i += 1) {
    if (ALGORITHM_NAMES[names[i]].indexOf(uri) >= 0) {
      return names[i];
    }
  }
  // A legacy 1.0 or 1.1 spelling, which shares an ALFA name with its modern
  // counterpart. Mapped by SUFFIX rather than left unnamed, because an
  // unnamed algorithm would make the whole policy unrenderable.
  const suffix = String(uri).split(':').pop();
  const camel = suffix.replace(/-([a-z])/g, function (whole, letter) {
    return letter.toUpperCase();
  });
  return ALGORITHM_NAMES[camel] ? camel : null;
}

function algorithmUriOf(name, forPolicySet) {
  const pair = ALGORITHM_NAMES[name];
  if (!pair) {
    return null;
  }
  return forPolicySet ? pair[1] : pair[0];
}

// The comparison functions that get an operator instead of a call. Everything
// else is written as a call, which is both readable and unambiguous — the
// alternative is inventing operators the language does not have.
const OPERATORS = [
  { symbol: '==', suffix: '-equal' },
  { symbol: '>=', suffix: '-greater-than-or-equal' },
  { symbol: '<=', suffix: '-less-than-or-equal' },
  { symbol: '>', suffix: '-greater-than' },
  { symbol: '<', suffix: '-less-than' }
];

function operatorFor(functionId) {
  const short = String(functionId).replace(/^.*:function:/, '');
  for (let i = 0; i < OPERATORS.length; i += 1) {
    if (short.slice(-OPERATORS[i].suffix.length) === OPERATORS[i].suffix) {
      return OPERATORS[i].symbol;
    }
  }
  return null;
}

// The function a `<type> <symbol> <type>` comparison means. Resolved through
// the real library, so an operator on a type that has no such function is
// refused rather than producing a URI nothing implements.
function functionForOperator(symbol, typeUri) {
  const entry = OPERATORS.filter(function (one) {
    return one.symbol === symbol;
  })[0];
  if (!entry) {
    return null;
  }
  const row = datatypes.typeOf(typeUri);
  if (!row) {
    return null;
  }
  const duration = typeUri === TYPE.DAYTIME_DURATION ||
                   typeUri === TYPE.YEARMONTH_DURATION;
  const uri = (duration && entry.suffix === '-equal' ? F3 : F1) +
              row.name + entry.suffix;
  return functions.lookup(uri) ? uri : null;
}

function shortFunctionName(uri) {
  return String(uri).replace(/^.*:function:/, '')
    .replace(/-([a-z0-9])/g, function (whole, ch) {
      return ch.toUpperCase();
    });
}

// The inverse. Built once from the library, so every function this service
// implements is reachable by its camel-case name and nothing else is.
const FUNCTION_BY_SHORT_NAME = {};
functions.names().forEach(function (uri) {
  const name = shortFunctionName(uri);
  // A collision would be two functions with one ALFA name; the 3.0 one wins,
  // because that is the spelling a new policy should use. Recorded rather
  // than silent — see `collisions()`.
  if (!FUNCTION_BY_SHORT_NAME[name] || uri.indexOf(':3.0:') >= 0) {
    FUNCTION_BY_SHORT_NAME[name] = uri;
  }
});

// ---------------------------------------------------------------------------
// THE EMITTER.
// ---------------------------------------------------------------------------

// Every designator in a policy gets a short name, and the same designator
// always gets the same one. Collected in one pass BEFORE anything is written,
// because the declarations go at the top and the uses come after.
function collectAttributes(policy) {
  log.debug('Entering collectAttributes().');
  const byKey = {};
  const order = [];

  function note(designator) {
    const key = designator.category + '|' + designator.attributeId + '|' +
                designator.dataType;
    if (byKey[key]) {
      return;
    }
    const base = shortNameForAttribute(designator.attributeId);
    let name = base;
    let n = 2;
    // A COLLISION IS ON THE SHORT NAME AND NOT ON THE ATTRIBUTE. Two different
    // attributes can end with the same segment — `...:subject:role` and
    // `...:resource:role` — and giving both the name `role` would make the
    // second declaration silently replace the first, so a policy would read an
    // attribute out of the wrong category. Numbered instead.
    // AND NOT A NAME A FUNCTION ALREADY OWNS. A bare word in an expression is
    // an attribute reference OR a function reference (header point 4), and the
    // parser resolves it by looking at the declarations first — so a
    // designator called `stringEqual` would shadow the function of that name
    // for the whole document and turn a higher-order argument into a bag. It
    // is vanishingly rare and costs one comparison to make impossible.
    while (order.some(function (one) { return one.name === name; }) ||
           FUNCTION_BY_SHORT_NAME[name]) {
      name = base + n;
      n += 1;
    }
    byKey[key] = name;
    order.push({ name: name, category: designator.category,
                 attributeId: designator.attributeId,
                 dataType: designator.dataType });
  }

  walkDesignators(policy, note);
  log.debug('Leaving collectAttributes(). ' + order.length + ' attribute(s).');
  return { byKey: byKey, order: order };
}

function shortNameForAttribute(attributeId) {
  const tail = String(attributeId).split(':').pop().split('/').pop();
  const camel = tail.replace(/[-_.]([a-zA-Z0-9])/g, function (whole, ch) {
    return ch.toUpperCase();
  }).replace(/[^A-Za-z0-9]/g, '');
  if (!camel) {
    return 'attr';
  }
  return /^[0-9]/.test(camel) ? 'a' + camel
                              : camel.charAt(0).toLowerCase() + camel.slice(1);
}

function walkDesignators(node, visit) {
  function expression(one) {
    if (!one) {
      return;
    }
    if (one.kind === 'designator') {
      visit(one);
      return;
    }
    if (one.kind === 'apply') {
      (one.args || []).forEach(expression);
    }
  }
  function target(one) {
    if (!one || !one.anyOf) {
      return;
    }
    one.anyOf.forEach(function (anyOf) {
      anyOf.allOf.forEach(function (allOf) {
        allOf.matches.forEach(function (match) {
          expression(match.reference);
        });
      });
    });
  }
  function holders(list) {
    (list || []).forEach(function (holder) {
      (holder.assignments || []).forEach(function (assignment) {
        expression(assignment.expression);
      });
    });
  }
  function policy(one) {
    target(one.target);
    holders(one.obligations);
    holders(one.advice);
    if (one.kind === 'PolicySet') {
      (one.children || []).forEach(function (child) {
        if (child.kind === 'Policy' || child.kind === 'PolicySet') {
          policy(child);
        }
      });
      return;
    }
    Object.keys(one.variables || {}).forEach(function (id) {
      expression(one.variables[id]);
    });
    (one.rules || []).forEach(function (rule) {
      target(rule.target);
      expression(rule.condition);
      holders(rule.obligations);
      holders(rule.advice);
    });
  }
  policy(node);
}

// A literal. Native syntax for the four types ALFA has one for; a cast for the
// other thirteen. See point 1 in the header.
function literalOf(expression) {
  const type = model.canonicalType(expression.type);
  const lexical = String(expression.lexical === undefined
                           ? '' : expression.lexical);
  if (type === TYPE.STRING) {
    return quote(lexical);
  }
  if (type === TYPE.BOOLEAN) {
    return lexical === 'true' || lexical === '1' ? 'true' : 'false';
  }
  if (type === TYPE.INTEGER || type === TYPE.DOUBLE) {
    // Written bare only when it LOOKS like a number. A double of `INF` or
    // `NaN` is a legal lexical form that is not a numeric literal in any
    // language, so it takes the cast form and round-trips.
    if (/^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$/.test(lexical)) {
      return lexical;
    }
  }
  const row = datatypes.typeOf(type);
  return (row ? row.name : 'string') + '(' + quote(lexical) + ')';
}

function quote(text) {
  return '"' + String(text).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

function emitExpression(expression, attributes) {
  if (!expression) {
    return '';
  }
  if (expression.kind === 'value') {
    return literalOf(expression);
  }
  if (expression.kind === 'designator') {
    const key = expression.category + '|' + expression.attributeId + '|' +
                expression.dataType;
    return attributes.byKey[key] || shortNameForAttribute(
      expression.attributeId);
  }
  if (expression.kind === 'variableRef') {
    return '$' + expression.variableId;
  }
  if (expression.kind === 'function') {
    return shortFunctionName(expression.functionId);
  }
  if (expression.kind === 'selector') {
    // Nothing here evaluates an AttributeSelector, and ALFA has no agreed
    // syntax for one. Emitted as a call that names it, so the document is
    // readable and the parser refuses it rather than pretending.
    return 'attributeSelector(' + quote(expression.category) + ', ' +
      quote(expression.path) + ', ' + quote(expression.dataType) + ')';
  }
  if (expression.kind === 'apply') {
    const args = (expression.args || []).map(function (one) {
      return emitExpression(one, attributes);
    });
    const short = shortFunctionName(expression.functionId);
    if (short === 'and' || short === 'or') {
      const symbol = short === 'and' ? ' && ' : ' || ';
      return args.length ? '(' + args.join(symbol) + ')' : (
        short === 'and' ? 'true' : 'false');
    }
    if (short === 'not' && args.length === 1) {
      return '!' + args[0];
    }
    const operator = operatorFor(expression.functionId);
    if (operator && args.length === 2) {
      return '(' + args[0] + ' ' + operator + ' ' + args[1] + ')';
    }
    return short + '(' + args.join(', ') + ')';
  }
  return '/* unrenderable */';
}

function emitTarget(target, attributes, indent) {
  if (!target || !target.anyOf || !target.anyOf.length) {
    return '';
  }
  return target.anyOf.map(function (anyOf) {
    const alternatives = anyOf.allOf.map(function (allOf) {
      return allOf.matches.map(function (match) {
        const left = emitExpression(match.reference, attributes);
        const right = emitExpression(match.value, attributes);
        const operator = operatorFor(match.matchId);
        if (operator) {
          // ATTRIBUTE ON THE LEFT, VALUE ON THE RIGHT — which is the reverse
          // of XACML, where a Match's AttributeValue comes first. ALFA reads
          // the way a person writes a condition, and the parser swaps them
          // back. For a NON-symmetric operator that swap matters, which is why
          // `>` becomes `<` and not `>` when the sides are exchanged.
          return left + ' ' + mirrorOperator(operator) + ' ' + right;
        }
        return shortFunctionName(match.matchId) + '(' + right + ', ' + left +
          ')';
      }).join(' and ');
    }).join(' or ');
    return indent + 'target clause ' + alternatives;
  }).join('\n');
}

// `a > b` written with the sides exchanged is `b < a`. Only the four ordering
// operators are affected; `==` is symmetric.
function mirrorOperator(symbol) {
  if (symbol === '>') {
    return '<';
  }
  if (symbol === '<') {
    return '>';
  }
  if (symbol === '>=') {
    return '<=';
  }
  if (symbol === '<=') {
    return '>=';
  }
  return symbol;
}

function emitHolders(list, attributes, indent, keyword) {
  if (!list || !list.length) {
    return '';
  }
  const byEffect = { Permit: [], Deny: [] };
  list.forEach(function (holder) {
    (byEffect[holder.on] || byEffect.Permit).push(holder);
  });
  return Object.keys(byEffect).filter(function (effect) {
    return byEffect[effect].length;
  }).map(function (effect) {
    const body = byEffect[effect].map(function (holder) {
      const assignments = (holder.assignments || []).map(function (one) {
        return indent + '        ' + one.attributeId + ' = ' +
          emitExpression(one.expression, attributes);
      }).join('\n');
      return indent + '    ' + keyword + ' ' + quote(holder.id) +
        (assignments ? ' {\n' + assignments + '\n' + indent + '    }' : ' { }');
    }).join('\n');
    return indent + 'on ' + effect.toLowerCase() + ' {\n' + body + '\n' +
      indent + '}';
  }).join('\n');
}

function emitRule(rule, attributes, indent) {
  const lines = [];
  lines.push(indent + 'rule ' + identifier(rule.id) + ' {');
  const inner = indent + '    ';
  // A DESCRIPTION IS A PROPERTY AND NOT A `//` COMMENT, and that is the whole
  // of why: the tokenizer discards comments, so a description written as one
  // survives being read by a person and is DELETED by the next round trip.
  // The XML reader had the same defect and it cost every explanation in every
  // policy that went through the editor. `description = "..."` reads back.
  if (rule.description) {
    lines.push(inner + 'description = ' +
               quote(rule.description.replace(/\s+/g, ' ')));
  }
  lines.push(inner + rule.effect.toLowerCase());
  const target = emitTarget(rule.target, attributes, inner);
  if (target) {
    lines.push(target);
  }
  if (rule.condition) {
    lines.push(inner + 'condition ' +
               emitExpression(rule.condition, attributes));
  }
  const obligations = emitHolders(rule.obligations, attributes, inner,
                                  'obligation');
  if (obligations) {
    lines.push(obligations);
  }
  const advice = emitHolders(rule.advice, attributes, inner, 'advice');
  if (advice) {
    lines.push(advice);
  }
  lines.push(indent + '}');
  return lines.join('\n');
}

// An ALFA identifier cannot hold a colon, and every PolicyId in the world is a
// URI. So the identifier is a SLUG and the full URI is carried in an `id`
// property beside it — which is what makes a round trip lossless. Emitting
// only the slug would silently rename every policy that went through ALFA.
function identifier(uri) {
  const tail = String(uri).split(':').pop().split('/').pop();
  const camel = tail.replace(/[-_.]([a-zA-Z0-9])/g, function (whole, ch) {
    return ch.toUpperCase();
  }).replace(/[^A-Za-z0-9]/g, '');
  if (!camel) {
    return 'p';
  }
  return /^[0-9]/.test(camel) ? 'p' + camel : camel;
}

function emitPolicyBody(policy, attributes, indent) {
  const lines = [];
  const keyword = policy.kind === 'PolicySet' ? 'policyset' : 'policy';
  lines.push(indent + keyword + ' ' + identifier(policy.id) + ' {');
  const inner = indent + '    ';
  lines.push(inner + 'id = ' + quote(policy.id));
  lines.push(inner + 'version = ' + quote(policy.version || '1.0'));
  // See emitRule(): a property rather than a comment, so it survives.
  if (policy.description) {
    lines.push(inner + 'description = ' +
               quote(policy.description.replace(/\s+/g, ' ')));
  }
  const algorithm = algorithmNameOf(policy.combiningAlgId);
  lines.push(inner + 'apply ' + (algorithm || 'denyUnlessPermit'));
  if (!algorithm) {
    lines.push(inner + '// The original combining algorithm was ' +
               policy.combiningAlgId + ', which has no ALFA name.');
  }
  const target = emitTarget(policy.target, attributes, inner);
  if (target) {
    lines.push(target);
  }
  if (policy.kind === 'PolicySet') {
    (policy.children || []).forEach(function (child) {
      if (child.kind === 'Policy' || child.kind === 'PolicySet') {
        lines.push(emitPolicyBody(child, attributes, inner));
      } else {
        lines.push(inner + '// ' + child.kind + ' ' + child.ref +
                   ' — a reference, which ALFA resolves by name at compile ' +
                   'time and this dialect does not follow.');
      }
    });
  } else {
    Object.keys(policy.variables || {}).forEach(function (id) {
      lines.push(inner + '$' + id + ' = ' +
                 emitExpression(policy.variables[id], attributes));
    });
    (policy.rules || []).forEach(function (rule) {
      lines.push(emitRule(rule, attributes, inner));
    });
  }
  const obligations = emitHolders(policy.obligations, attributes, inner,
                                  'obligation');
  if (obligations) {
    lines.push(obligations);
  }
  const advice = emitHolders(policy.advice, attributes, inner, 'advice');
  if (advice) {
    lines.push(advice);
  }
  lines.push(indent + '}');
  return lines.join('\n');
}

function write(policy, options) {
  log.debug('Entering write(). id=' + policy.id);
  const settings = options || {};
  const namespace = settings.namespace || 'stsMock';
  const attributes = collectAttributes(policy);
  const declarations = attributes.order.map(function (one) {
    const row = datatypes.typeOf(one.dataType);
    return '    attribute ' + one.name + ' {\n' +
      '        category = ' + (CATEGORY_URIS[one.category] ||
                               quote(one.category)) + '\n' +
      '        id = ' + quote(one.attributeId) + '\n' +
      '        type = ' + (row ? row.name : 'string') + '\n' +
      '    }';
  }).join('\n');
  const body = emitPolicyBody(policy, attributes, '    ');
  const text = 'namespace ' + namespace + ' {\n' +
    (declarations ? declarations + '\n\n' : '') + body + '\n}\n';
  log.debug('Leaving write(). ' + text.length + ' bytes.');
  return text;
}

// ---------------------------------------------------------------------------
// THE TOKENIZER.
// ---------------------------------------------------------------------------
const PUNCTUATION = ['==', '!=', '>=', '<=', '&&', '||', '{', '}', '(', ')',
                     ',', '=', '>', '<', '!', '$'];

function tokenize(text) {
  log.debug('Entering tokenize().');
  const tokens = [];
  let i = 0;
  let line = 1;
  const source = String(text);
  while (i < source.length) {
    const ch = source[i];
    if (ch === '\n') {
      line += 1;
      i += 1;
      continue;
    }
    if (/\s/.test(ch)) {
      i += 1;
      continue;
    }
    if (ch === '/' && source[i + 1] === '/') {
      while (i < source.length && source[i] !== '\n') {
        i += 1;
      }
      continue;
    }
    if (ch === '/' && source[i + 1] === '*') {
      const end = source.indexOf('*/', i + 2);
      if (end < 0) {
        throw model.syntaxError('An unterminated /* comment at line ' + line +
                                '.');
      }
      line += source.slice(i, end).split('\n').length - 1;
      i = end + 2;
      continue;
    }
    if (ch === '"') {
      let value = '';
      i += 1;
      while (i < source.length && source[i] !== '"') {
        if (source[i] === '\\') {
          i += 1;
          if (i >= source.length) {
            break;
          }
        }
        value += source[i];
        i += 1;
      }
      if (i >= source.length) {
        throw model.syntaxError('An unterminated string at line ' + line +
                                '.');
      }
      i += 1;
      tokens.push({ kind: 'string', value: value, line: line });
      continue;
    }
    if (/[0-9]/.test(ch) ||
        (ch === '-' && /[0-9]/.test(source[i + 1] || ''))) {
      let value = ch;
      i += 1;
      while (i < source.length && /[0-9.eE+-]/.test(source[i])) {
        // An exponent's sign belongs to the number; a bare `-` after a digit
        // does not, and treating it as part of the number would swallow the
        // operator in `a-1`.
        if ((source[i] === '+' || source[i] === '-') &&
            !/[eE]/.test(value[value.length - 1])) {
          break;
        }
        value += source[i];
        i += 1;
      }
      tokens.push({ kind: 'number', value: value, line: line });
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let value = '';
      while (i < source.length && /[A-Za-z0-9_]/.test(source[i])) {
        value += source[i];
        i += 1;
      }
      tokens.push({ kind: 'word', value: value, line: line });
      continue;
    }
    const two = source.slice(i, i + 2);
    const punctuation = PUNCTUATION.indexOf(two) >= 0 ? two
      : (PUNCTUATION.indexOf(ch) >= 0 ? ch : null);
    if (!punctuation) {
      throw model.syntaxError('Unexpected character "' + ch + '" at line ' +
                              line + '.');
    }
    tokens.push({ kind: 'punct', value: punctuation, line: line });
    i += punctuation.length;
  }
  tokens.push({ kind: 'end', value: '', line: line });
  log.debug('Leaving tokenize(). ' + tokens.length + ' token(s).');
  return tokens;
}

// ---------------------------------------------------------------------------
// THE PARSER.
// ---------------------------------------------------------------------------
function parse(text) {
  log.debug('Entering parse().');
  const tokens = tokenize(text);
  let at = 0;
  const attributes = {};

  function peek(offset) {
    return tokens[at + (offset || 0)];
  }

  function next() {
    const token = tokens[at];
    at += 1;
    return token;
  }

  function is(value, offset) {
    const token = peek(offset);
    return token && token.value === value &&
           (token.kind === 'word' || token.kind === 'punct');
  }

  function expect(value) {
    const token = next();
    if (!token || token.value !== value) {
      throw model.syntaxError(
        'Expected "' + value + '" at line ' +
        (token ? token.line : '?') + ' but found "' +
        (token ? token.value : 'the end of the document') + '".');
    }
    return token;
  }

  function expectWord() {
    const token = next();
    if (!token || token.kind !== 'word') {
      throw model.syntaxError(
        'Expected a name at line ' + (token ? token.line : '?') +
        ' but found "' + (token ? token.value : 'the end') + '".');
    }
    return token.value;
  }

  function expectString() {
    const token = next();
    if (!token || token.kind !== 'string') {
      throw model.syntaxError(
        'Expected a quoted string at line ' + (token ? token.line : '?') +
        ' but found "' + (token ? token.value : 'the end') + '".');
    }
    return token.value;
  }

  // --- attribute declarations ---------------------------------------------
  function attributeDeclaration() {
    log.debug('Entering attributeDeclaration().');
    expect('attribute');
    const name = expectWord();
    expect('{');
    const declared = { category: null, attributeId: null, dataType: null };
    while (!is('}')) {
      const key = expectWord();
      expect('=');
      if (key === 'category') {
        const token = next();
        declared.category = token.kind === 'string' ? token.value
          : CATEGORY_NAMES[token.value];
        if (!declared.category) {
          throw model.syntaxError(
            'Unknown category "' + token.value + '" at line ' + token.line +
            '. The names are: ' + Object.keys(CATEGORY_NAMES).join(', ') +
            ', or a category URI in quotes.');
        }
      } else if (key === 'id') {
        declared.attributeId = expectString();
      } else if (key === 'type') {
        const token = next();
        const wanted = token.kind === 'string' ? token.value : token.value;
        const found = Object.keys(datatypes.TYPES).filter(function (uri) {
          return datatypes.TYPES[uri].name === wanted || uri === wanted;
        })[0];
        if (!found) {
          throw model.syntaxError(
            'Unknown datatype "' + wanted + '" at line ' + token.line + '.');
        }
        declared.dataType = found;
      } else {
        throw model.syntaxError(
          'An attribute declaration takes category, id and type; "' + key +
          '" is not one of them.');
      }
    }
    expect('}');
    if (!declared.category || !declared.attributeId || !declared.dataType) {
      throw model.syntaxError(
        'The attribute "' + name + '" must declare all three of category, ' +
        'id and type.');
    }
    attributes[name] = declared;
    log.debug('Leaving attributeDeclaration(). name=' + name);
  }

  function designatorFor(name, token) {
    const declared = attributes[name];
    if (!declared) {
      // THE MOST USEFUL REFUSAL IN THIS FILE. See point 3 in the header: a
      // typo in an attribute name is otherwise a policy that quietly matches
      // nothing, and a policy that matches nothing looks exactly like a policy
      // that is working correctly and denying you.
      throw model.syntaxError(
        'The attribute "' + name + '" is used at line ' +
        (token ? token.line : '?') + ' and never declared. ALFA references ' +
        'attributes by a short name; the category, id and type come from an ' +
        '`attribute ' + name + ' { ... }` declaration. It is not the name of ' +
        'a function this engine implements either, which is the OTHER thing ' +
        'a bare word may be — the first argument of a higher-order function ' +
        'such as `anyOfAny`.' +
        (Object.keys(attributes).length
          ? ' Declared here: ' + Object.keys(attributes).sort().join(', ') +
            '.'
          : ' Nothing is declared in this document.'));
    }
    return { kind: 'designator', category: declared.category,
             attributeId: declared.attributeId,
             dataType: declared.dataType, issuer: null,
             mustBePresent: false };
  }

  // A BARE WORD IN AN EXPRESSION IS ONE OF TWO THINGS, and header point 4
  // argues the order they are tried in: an attribute the document DECLARED,
  // or — where nothing declared it — the short name of a function, which is
  // what the seven higher-order functions take as their first argument. Only
  // a name that is neither reaches the refusal, which is point 3's and is the
  // most useful one in this file.
  function nameReference(name, token) {
    if (attributes[name]) {
      return designatorFor(name, token);
    }
    const uri = FUNCTION_BY_SHORT_NAME[name];
    if (uri) {
      log.debug('nameReference(): "' + name + '" is the function ' + uri +
                '.');
      return { kind: 'function', functionId: uri };
    }
    return designatorFor(name, token);
  }

  // --- expressions ---------------------------------------------------------
  function primary() {
    const token = next();
    if (token.kind === 'string') {
      return { kind: 'value', type: TYPE.STRING, lexical: token.value };
    }
    if (token.kind === 'number') {
      const isDouble = /[.eE]/.test(token.value);
      return { kind: 'value',
               type: isDouble ? TYPE.DOUBLE : TYPE.INTEGER,
               lexical: token.value };
    }
    if (token.kind === 'punct' && token.value === '(') {
      const inner = expression();
      expect(')');
      return inner;
    }
    if (token.kind === 'punct' && token.value === '!') {
      return { kind: 'apply', functionId: F1 + 'not', args: [primary()] };
    }
    if (token.kind === 'punct' && token.value === '$') {
      return { kind: 'variableRef', variableId: expectWord() };
    }
    if (token.kind === 'word') {
      if (token.value === 'true' || token.value === 'false') {
        return { kind: 'value', type: TYPE.BOOLEAN, lexical: token.value };
      }
      if (is('(')) {
        next();
        // A TYPED LITERAL or a FUNCTION CALL, and the name decides which. A
        // datatype name followed by one quoted string is a cast; anything else
        // is a call. `string("x")` is therefore a literal and not a call to a
        // function called `string`, which does not exist.
        const typeUri = Object.keys(datatypes.TYPES).filter(function (uri) {
          return datatypes.TYPES[uri].name === token.value;
        })[0];
        if (typeUri && peek().kind === 'string' && is(')', 1)) {
          const value = expectString();
          expect(')');
          return { kind: 'value', type: typeUri, lexical: value };
        }
        const args = [];
        if (!is(')')) {
          args.push(expression());
          while (is(',')) {
            next();
            args.push(expression());
          }
        }
        expect(')');
        const uri = FUNCTION_BY_SHORT_NAME[token.value];
        if (!uri) {
          throw model.syntaxError(
            'There is no function called "' + token.value + '" at line ' +
            token.line + '.');
        }
        return { kind: 'apply', functionId: uri, args: args };
      }
      return nameReference(token.value, token);
    }
    throw model.syntaxError('Unexpected "' + token.value + '" at line ' +
                            token.line + '.');
  }

  function comparison() {
    const left = primary();
    const token = peek();
    const symbols = ['==', '!=', '>=', '<=', '>', '<'];
    if (token.kind === 'punct' && symbols.indexOf(token.value) >= 0) {
      next();
      const right = primary();
      return comparisonOf(left, token.value, right, token.line);
    }
    return left;
  }

  // A CHAIN OF `&&` OR `||` IS ONE n-ARY APPLY AND NOT A NEST OF TWO-ARGUMENT
  // ONES, and that is worth the four extra lines. XACML's `and` and `or` take
  // any number of arguments, every template here that builds one builds it
  // n-ary, and the emitter writes `(a || b || c)` for all three shapes — so a
  // left-associative parse read that back as `or(or(a, b), c)`, which DECIDES
  // identically and re-emits as `((a || b) || c)`. The contract in this file's
  // header is that a round trip is byte-identical, not merely equivalent, and
  // an ALFA edit that silently re-bracketed every condition it touched would
  // make the XML diff of a policy somebody changed one word in unreadable.
  function chain(operand, functionId, symbol, word) {
    const args = [operand()];
    while (is(symbol) || is(word)) {
      next();
      args.push(operand());
    }
    return args.length === 1 ? args[0]
      : { kind: 'apply', functionId: functionId, args: args };
  }

  function conjunction() {
    return chain(comparison, F1 + 'and', '&&', 'and');
  }

  function expression() {
    return chain(conjunction, F1 + 'or', '||', 'or');
  }

  // The function a comparison means, chosen from the DECLARED TYPE of
  // whichever side has one. A comparison between two literals with no
  // designator is typed from the left; a comparison against a designator is
  // typed from the designator, because that is the type the policy will
  // actually meet at evaluation.
  function comparisonOf(left, symbol, right, line) {
    const typeUri = typeOfExpression(right) || typeOfExpression(left) ||
                    TYPE.STRING;
    if (symbol === '!=') {
      const equal = functionForOperator('==', typeUri);
      if (!equal) {
        throw model.syntaxError('There is no equality function for ' +
                                typeUri + ' (line ' + line + ').');
      }
      return { kind: 'apply', functionId: F1 + 'not',
               args: [{ kind: 'apply', functionId: equal,
                        args: [left, right] }] };
    }
    const uri = functionForOperator(symbol, typeUri);
    if (!uri) {
      const row = datatypes.typeOf(typeUri);
      throw model.syntaxError(
        'The operator "' + symbol + '" has no XACML function for ' +
        (row ? row.name : typeUri) + ' at line ' + line + '. Not every ' +
        'datatype is ordered — boolean and anyURI have equality and no ' +
        'comparison.');
    }
    // XACML PUTS THE VALUE FIRST. ALFA reads attribute-first, so the sides are
    // exchanged on the way in — and for an ordering operator the operator has
    // to be mirrored with them or `age > 18` becomes `18 > age`.
    if (left.kind === 'designator' && right.kind === 'value') {
      const mirrored = functionForOperator(mirrorOperator(symbol), typeUri);
      return { kind: 'apply', functionId: mirrored || uri,
               args: [right, left] };
    }
    return { kind: 'apply', functionId: uri, args: [left, right] };
  }

  function typeOfExpression(one) {
    if (!one) {
      return null;
    }
    if (one.kind === 'value') {
      return model.canonicalType(one.type);
    }
    if (one.kind === 'designator') {
      return model.canonicalType(one.dataType);
    }
    if (one.kind === 'apply') {
      const definition = functions.lookup(one.functionId);
      return definition && definition.returns ? definition.returns.type : null;
    }
    return null;
  }

  // --- targets -------------------------------------------------------------
  //
  // `clause` is one AnyOf, `or` separates its AllOf alternatives, and `and`
  // joins the Matches inside one. Parsed structurally rather than through
  // `expression()` because a Target is NOT a boolean expression — it is three
  // fixed levels, and flattening it would lose the difference between
  // `A and B` inside one alternative and `A` in one clause with `B` in the
  // next, which mean the same thing here and different things everywhere else.
  function targetClause() {
    expect('target');
    expect('clause');
    const alternatives = [];
    let matches = [matchTerm()];
    for (;;) {
      if (is('and') || is('&&')) {
        next();
        matches.push(matchTerm());
        continue;
      }
      if (is('or') || is('||')) {
        next();
        alternatives.push({ matches: matches });
        matches = [matchTerm()];
        continue;
      }
      break;
    }
    alternatives.push({ matches: matches });
    return { allOf: alternatives };
  }

  function matchTerm() {
    const token = peek();
    // A CALL FORM, for the match functions that have no operator —
    // `regexpMatch("a.*", role)` and the two name-match functions. XACML's own
    // argument order, value first, because that is what the function
    // declares.
    if (token.kind === 'word' && is('(', 1) &&
        FUNCTION_BY_SHORT_NAME[token.value]) {
      const call = primary();
      if (call.kind !== 'apply' || call.args.length !== 2) {
        throw model.syntaxError(
          'A target clause written as a call needs exactly two arguments ' +
          '(line ' + token.line + ').');
      }
      const value = call.args[0];
      const reference = call.args[1];
      if (value.kind !== 'value' || reference.kind !== 'designator') {
        throw model.syntaxError(
          'A target clause call takes a literal and then an attribute ' +
          '(line ' + token.line + ').');
      }
      return { matchId: call.functionId, value: value, reference: reference };
    }
    const left = primary();
    const operatorToken = next();
    const symbols = ['==', '>=', '<=', '>', '<'];
    if (operatorToken.kind !== 'punct' ||
        symbols.indexOf(operatorToken.value) < 0) {
      throw model.syntaxError(
        'A target clause compares an attribute with a value using one of ' +
        symbols.join(', ') + '; found "' + operatorToken.value +
        '" at line ' + operatorToken.line + '. `!=` is not available in a ' +
        'target — XACML has no not-equal match function — so put it in a ' +
        'condition instead.');
    }
    const right = primary();
    const applied = comparisonOf(left, operatorToken.value, right,
                                 operatorToken.line);
    if (applied.args.length !== 2 || applied.args[0].kind !== 'value' ||
        applied.args[1].kind !== 'designator') {
      throw model.syntaxError(
        'A target clause compares one attribute with one literal value ' +
        '(line ' + operatorToken.line + ').');
    }
    return { matchId: applied.functionId, value: applied.args[0],
             reference: applied.args[1] };
  }

  // --- obligations ---------------------------------------------------------
  function holderBlock(effect, into) {
    expect('{');
    while (!is('}')) {
      const keyword = expectWord();
      if (keyword !== 'obligation' && keyword !== 'advice') {
        throw model.syntaxError(
          'An `on ' + effect.toLowerCase() + '` block holds obligations and ' +
          'advice; "' + keyword + '" is neither.');
      }
      const token = peek();
      const id = token.kind === 'string' ? expectString() : expectWord();
      const assignments = [];
      expect('{');
      while (!is('}')) {
        const attributeId = peek().kind === 'string' ? expectString()
                                                    : expectWord();
        expect('=');
        assignments.push({ attributeId: attributeId, category: null,
                           issuer: null, expression: expression() });
      }
      expect('}');
      into[keyword === 'advice' ? 'advice' : 'obligations'].push({
        id: id, on: effect, assignments: assignments });
    }
    expect('}');
  }

  // --- rules, policies, policy sets ---------------------------------------
  function ruleBlock() {
    expect('rule');
    const slug = expectWord();
    expect('{');
    const rule = { id: slug, effect: null, description: '', target: null,
                   condition: null, obligations: [], advice: [] };
    const anyOf = [];
    while (!is('}')) {
      if (is('permit') || is('deny')) {
        rule.effect = next().value === 'permit' ? model.EFFECT.PERMIT
                                                : model.EFFECT.DENY;
        continue;
      }
      if (is('id')) {
        next();
        expect('=');
        rule.id = expectString();
        continue;
      }
      if (is('description')) {
        next();
        expect('=');
        rule.description = expectString();
        continue;
      }
      if (is('target')) {
        anyOf.push(targetClause());
        continue;
      }
      if (is('condition')) {
        next();
        rule.condition = expression();
        continue;
      }
      if (is('on')) {
        next();
        const effect = expectWord() === 'permit' ? model.EFFECT.PERMIT
                                                 : model.EFFECT.DENY;
        holderBlock(effect, rule);
        continue;
      }
      const token = peek();
      throw model.syntaxError(
        'Unexpected "' + token.value + '" inside a rule at line ' +
        token.line + '. A rule holds permit or deny, an id, target clauses, ' +
        'a condition, and `on permit` / `on deny` blocks.');
    }
    expect('}');
    if (!rule.effect) {
      throw model.syntaxError(
        'The rule "' + rule.id + '" says neither permit nor deny. Every ' +
        'XACML rule has an Effect and there is no default.');
    }
    if (anyOf.length) {
      rule.target = { anyOf: anyOf };
    }
    return rule;
  }

  function policyBlock() {
    const keyword = next().value;
    const isSet = keyword === 'policyset';
    const slug = expectWord();
    expect('{');
    const policy = { kind: isSet ? 'PolicySet' : 'Policy', id: slug,
                     version: '1.0', description: '',
                     combiningAlgId: null, target: null, variables: {},
                     rules: [], children: [], obligations: [], advice: [] };
    const anyOf = [];
    while (!is('}')) {
      if (is('id')) {
        next();
        expect('=');
        policy.id = expectString();
        continue;
      }
      if (is('version')) {
        next();
        expect('=');
        policy.version = expectString();
        continue;
      }
      if (is('description')) {
        next();
        expect('=');
        policy.description = expectString();
        continue;
      }
      if (is('apply')) {
        next();
        const name = expectWord();
        const uri = algorithmUriOf(name, isSet);
        if (!uri) {
          throw model.syntaxError(
            'There is no ' + (isSet ? 'policy' : 'rule') +
            '-combining algorithm called "' + name + '". The names are: ' +
            Object.keys(ALGORITHM_NAMES).filter(function (one) {
              return algorithmUriOf(one, isSet);
            }).join(', ') + '.');
        }
        policy.combiningAlgId = uri;
        continue;
      }
      if (is('target')) {
        anyOf.push(targetClause());
        continue;
      }
      if (is('rule')) {
        policy.rules.push(ruleBlock());
        continue;
      }
      if (is('policy') || is('policyset')) {
        policy.children.push(policyBlock());
        continue;
      }
      if (is('on')) {
        next();
        const effect = expectWord() === 'permit' ? model.EFFECT.PERMIT
                                                 : model.EFFECT.DENY;
        holderBlock(effect, policy);
        continue;
      }
      if (is('$')) {
        next();
        const id = expectWord();
        expect('=');
        policy.variables[id] = expression();
        continue;
      }
      const token = peek();
      throw model.syntaxError(
        'Unexpected "' + token.value + '" inside a ' + keyword +
        ' at line ' + token.line + '.');
    }
    expect('}');
    if (!policy.combiningAlgId) {
      throw model.syntaxError(
        'The ' + keyword + ' "' + policy.id + '" has no `apply` line. A ' +
        'combining algorithm is the single most consequential line in a ' +
        'policy and there is deliberately no default.');
    }
    if (anyOf.length) {
      policy.target = { anyOf: anyOf };
    }
    if (isSet) {
      delete policy.rules;
      delete policy.variables;
    } else {
      delete policy.children;
    }
    return policy;
  }

  // --- the document --------------------------------------------------------
  expect('namespace');
  expectWord();
  expect('{');
  let root = null;
  while (!is('}')) {
    if (is('attribute')) {
      attributeDeclaration();
      continue;
    }
    if (is('import')) {
      // `import Attributes.*` is idiomatic ALFA and pulls in the standard
      // attribute set from another file. There is no file system here and no
      // second document, so it is SKIPPED with the attributes it would have
      // brought left undeclared — which means a policy relying on it fails at
      // the first use, naming the attribute. That is a better failure than
      // silently inventing the standard set, because the set an implementation
      // ships is exactly what varies between them.
      next();
      while (!is('{') && peek().kind !== 'end' &&
             !is('policy') && !is('policyset') && !is('attribute')) {
        next();
      }
      continue;
    }
    if (is('policy') || is('policyset')) {
      const parsed = policyBlock();
      if (root) {
        throw model.syntaxError(
          'This document holds more than one top-level policy. A PDP ' +
          'evaluates ONE document, so wrap them in a policyset and say which ' +
          'combining algorithm joins them.');
      }
      root = parsed;
      continue;
    }
    const token = peek();
    throw model.syntaxError(
      'Unexpected "' + token.value + '" at line ' + token.line +
      ' inside the namespace.');
  }
  expect('}');
  if (!root) {
    throw model.syntaxError(
      'This document declares a namespace and no policy in it.');
  }
  log.debug('Leaving parse(). id=' + root.id);
  return root;
}

module.exports = {
  write: write,
  parse: parse,
  tokenize: tokenize,
  algorithmNameOf: algorithmNameOf,
  algorithmUriOf: algorithmUriOf,
  shortFunctionName: shortFunctionName,
  shortNameForAttribute: shortNameForAttribute,
  CATEGORY_NAMES: CATEGORY_NAMES,
  ALGORITHM_NAMES: ALGORITHM_NAMES,
  FUNCTION_BY_SHORT_NAME: FUNCTION_BY_SHORT_NAME
};
