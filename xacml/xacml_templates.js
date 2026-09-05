'use strict';
//
// File: xacml_templates.js
//
// ---------------------------------------------------------------------------
// STARTING POINTS: A POLICY SOMEBODY CAN EDIT, RATHER THAN A BLANK ONE.
//
// The guided editor can build any policy from nothing, one element at a time,
// and nobody wants to. A template is the first twenty clicks already made — a
// working, valid, evaluable policy in a shape people actually write — and the
// editor takes it from there.
//
// ADDING A TEMPLATE IS A ROW IN `TEMPLATES` BELOW AND NOTHING ELSE. That is
// the whole design and it is the promise this file has to keep: the console
// lists what is here, the management API offers what is here, and the
// parameter form is DERIVED from the row's `parameters`. If adding one ever
// needs an edit to `xacml_admin.js` or to `mgmt-api/admin_api.js`, this
// separation has gone wrong and the fix belongs here.
//
// ---------------------------------------------------------------------------
// A TEMPLATE BUILDS THE MODEL, NOT A STRING OF XML.
//
// It would be far easier to keep each template as XML with `{{placeholders}}`
// in it, and it would be wrong in a way that shows up late. A template's
// parameters are user input — a role name, an attribute id, a resource URI —
// and substituting them into XML text means escaping them correctly at every
// one of a dozen sites. Miss one and a role called `a"b` produces a document
// that will not parse, or worse, one that parses into something else.
//
// Building the model and handing it to `xacml_xml.js`'s writer moves that
// problem to the one place that already solves it: every value goes through
// `xmlEscape` on the way out, once, in code that is exercised by every policy
// this service writes. The template never sees a `<`.
//
// It also means a template is checked the same way a hand-authored policy is —
// `store.write()` validates it — so a template that stopped typechecking would
// be refused rather than becoming the broken policy everybody starts from.
//
// ---------------------------------------------------------------------------
// TWO TEMPLATES, AND THEY ARE THE TWO HALVES OF THE ARGUMENT XACML EXISTS FOR.
//
// RBAC asks "what ROLE do you hold", ABAC asks "what is TRUE about you, this
// resource, and right now". The first is what most deployments have and the
// second is what they wanted; having both here side by side, producing
// documents in the same language, is the clearest way to show what the
// difference actually costs in policy.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const model = require('./xacml_model');

const F1 = 'urn:oasis:names:tc:xacml:1.0:function:';
const TYPE = model.TYPE;

// ---------------------------------------------------------------------------
// SMALL MODEL BUILDERS.
//
// Named for what they produce rather than for the element they emit, because
// the point of building the model is that a template author does not have to
// know the element names — that is the writer's problem.
// ---------------------------------------------------------------------------
function value(type, lexical) {
  return { kind: 'value', type: type, lexical: String(lexical) };
}

function designator(category, attributeId, type) {
  return { kind: 'designator', category: category, attributeId: attributeId,
           dataType: type, issuer: null, mustBePresent: false };
}

function match(matchId, literal, reference) {
  return { matchId: matchId, value: literal, reference: reference };
}

// A Target that is satisfied when ALL of the given match-groups are — one
// `AnyOf` per group, since a Target ANDs its AnyOf children. Each group is a
// list of alternatives, ORed, since an AnyOf ORs its AllOf children.
function targetOf(groups) {
  const anyOf = groups.filter(function (group) {
    return group && group.length;
  }).map(function (group) {
    return { allOf: group.map(function (one) {
      return { matches: [one] };
    }) };
  });
  return anyOf.length ? { anyOf: anyOf } : null;
}

function apply(functionId, args) {
  return { kind: 'apply', functionId: functionId, args: args };
}

// A list typed into a form: commas or newlines, blanks dropped. One reader for
// every template parameter of list type, so that "a, b" and "a\nb" cannot mean
// different things on two different templates.
function listOf(raw) {
  return String(raw || '').split(/[,\n]/).map(function (one) {
    return one.trim();
  }).filter(function (one) {
    return one.length > 0;
  });
}

function slug(text) {
  return String(text || '').toLowerCase().replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'x';
}

// ---------------------------------------------------------------------------
// THE TABLE.
//
// `parameters` drives the form, so a parameter's `label` and `help` are what a
// person reads and its `dflt` is what they get if they say nothing. `build`
// receives the answers already coerced and returns a MODEL.
// ---------------------------------------------------------------------------
const TEMPLATES = [
  {
    id: 'rbac',
    label: 'Role-based (RBAC)',
    blurb: 'A permission is granted to a ROLE, and the role is an attribute ' +
           'of the subject. The shape most deployments already have.',
    what: 'Produces one Permit rule per role, each matching a role value ' +
          'against a subject attribute and — where the role is limited to ' +
          'certain actions — those actions too. The combining algorithm is ' +
          'deny-unless-permit, so anything not granted is denied and the ' +
          'answer never depends on the PEP\'s bias.',
    parameters: [
      { name: 'roleAttribute', label: 'The subject attribute holding the role',
        dflt: 'employeeType', type: 'string',
        help: 'A bare directory attribute name is read off the person\'s own ' +
              'entry by the PIP. `employeeType` is what the seeded people ' +
              'here carry.' },
      { name: 'adminRoles', label: 'Roles that may do anything',
        dflt: 'admin', type: 'list',
        help: 'Comma- or newline-separated. Each gets a rule with no action ' +
              'restriction.' },
      { name: 'readerRoles', label: 'Roles limited to certain actions',
        dflt: 'staff', type: 'list',
        help: 'Each gets a rule that also matches the actions below.' },
      { name: 'readerActions', label: 'The actions those roles may perform',
        dflt: 'GET, HEAD', type: 'list',
        help: 'Matched against the standard action-id attribute.' }
    ],
    build: function (answers, options) {
      log.debug('Entering buildRbac().');
      const roleAttribute = answers.roleAttribute || 'employeeType';
      const actions = listOf(answers.readerActions);
      const rules = [];
      listOf(answers.adminRoles).forEach(function (role) {
        rules.push({
          id: options.idBase + ':rule:' + slug(role) + '-anything',
          effect: model.EFFECT.PERMIT,
          description: 'Anyone whose ' + roleAttribute + ' is "' + role +
                       '" may perform any action.',
          target: targetOf([[
            match(F1 + 'string-equal', value(TYPE.STRING, role),
                  designator(model.CATEGORY.ACCESS_SUBJECT, roleAttribute,
                             TYPE.STRING))
          ]]),
          condition: null, obligations: [], advice: []
        });
      });
      listOf(answers.readerRoles).forEach(function (role) {
        rules.push({
          id: options.idBase + ':rule:' + slug(role) + '-limited',
          effect: model.EFFECT.PERMIT,
          description: 'Anyone whose ' + roleAttribute + ' is "' + role +
                       '" may perform ' +
                       (actions.length ? actions.join(', ') : 'any action') +
                       '.',
          // TWO AnyOf GROUPS, WHICH IS AN AND. The role must match AND the
          // action must be one of the listed ones. Putting both matches in one
          // AllOf would also be an AND but would require BOTH to be about the
          // same category, and putting them in one AnyOf would be an OR —
          // which is the mistake that grants every action to anybody holding
          // the role.
          target: targetOf([
            [match(F1 + 'string-equal', value(TYPE.STRING, role),
                   designator(model.CATEGORY.ACCESS_SUBJECT, roleAttribute,
                              TYPE.STRING))],
            actions.map(function (action) {
              return match(F1 + 'string-equal', value(TYPE.STRING, action),
                           designator(model.CATEGORY.ACTION,
                                      model.ATTRIBUTE.ACTION_ID,
                                      TYPE.STRING));
            })
          ]),
          condition: null, obligations: [], advice: []
        });
      });
      log.debug('Leaving buildRbac(). ' + rules.length + ' rule(s).');
      return {
        kind: 'Policy',
        id: options.idBase,
        version: '1.0',
        description: 'Role-based access control on the subject attribute "' +
                     roleAttribute + '". Anything not granted below is ' +
                     'denied, because the combining algorithm is ' +
                     'deny-unless-permit.',
        combiningAlgId: model.RULE_ALG.DENY_UNLESS_PERMIT,
        target: null,
        variables: {},
        rules: rules,
        obligations: [], advice: []
      };
    }
  },
  {
    id: 'abac',
    label: 'Attribute-based (ABAC)',
    blurb: 'A permission is granted on what is TRUE about the subject, the ' +
           'resource and the action — no roles anywhere.',
    what: 'Produces one Permit rule whose Target selects the resource and ' +
          'whose Condition is the conjunction of every attribute test you ' +
          'ask for. This is the shape that shows what XACML is actually ' +
          'for: the condition is an expression rather than a lookup, so a ' +
          'rule can compare two attributes with each other rather than each ' +
          'against a constant.',
    parameters: [
      { name: 'resource', label: 'The resource this applies to',
        dflt: 'https://example.test/records', type: 'string',
        help: 'Matched against the standard resource-id attribute. Leave it ' +
              'empty to apply to every resource.' },
      { name: 'actions', label: 'The actions it permits',
        dflt: 'GET', type: 'list',
        help: 'Comma- or newline-separated. Empty means any action.' },
      { name: 'subjectAttribute', label: 'A subject attribute to test',
        dflt: 'departmentNumber', type: 'string',
        help: 'A bare directory attribute name, read off the person\'s own ' +
              'entry by the PIP.' },
      { name: 'subjectValue', label: 'The value it must equal',
        dflt: '42', type: 'string',
        help: 'Compared as a string.' },
      { name: 'clearanceAttribute',
        label: 'A numeric subject attribute (optional)',
        dflt: '', type: 'string',
        help: 'If set, the rule additionally requires this attribute to be ' +
              'at least the level below. This is the part RBAC cannot ' +
              'express without a role per level.' },
      { name: 'clearanceMinimum', label: 'The minimum it must reach',
        dflt: '3', type: 'string', help: 'An integer.' }
    ],
    build: function (answers, options) {
      log.debug('Entering buildAbac().');
      const actions = listOf(answers.actions);
      const groups = [];
      if (answers.resource) {
        groups.push([match(F1 + 'anyURI-equal',
                           value(TYPE.ANYURI, answers.resource),
                           designator(model.CATEGORY.RESOURCE,
                                      model.ATTRIBUTE.RESOURCE_ID,
                                      TYPE.ANYURI))]);
      }
      if (actions.length) {
        groups.push(actions.map(function (action) {
          return match(F1 + 'string-equal', value(TYPE.STRING, action),
                       designator(model.CATEGORY.ACTION,
                                  model.ATTRIBUTE.ACTION_ID, TYPE.STRING));
        }));
      }
      const tests = [];
      if (answers.subjectAttribute) {
        // `string-is-in(value, bag)` rather than
        // `string-equal(value, one-and-only(bag))`, and the difference is the
        // whole reason to prefer it: a person with TWO values for the
        // attribute makes `one-and-only` Indeterminate, and makes `is-in`
        // true if either matches. A multi-valued directory attribute is the
        // normal case, not the exception.
        tests.push(apply(F1 + 'string-is-in', [
          value(TYPE.STRING, answers.subjectValue || ''),
          designator(model.CATEGORY.ACCESS_SUBJECT, answers.subjectAttribute,
                     TYPE.STRING)
        ]));
      }
      if (answers.clearanceAttribute) {
        tests.push(apply(F1 + 'integer-greater-than-or-equal', [
          apply(F1 + 'integer-one-and-only', [
            designator(model.CATEGORY.ACCESS_SUBJECT,
                       answers.clearanceAttribute, TYPE.INTEGER)
          ]),
          value(TYPE.INTEGER, answers.clearanceMinimum || '0')
        ]));
      }
      // A Condition must be exactly one boolean. One test is that test; two or
      // more are an `and`; none at all means the Target alone decides, and the
      // rule carries no Condition rather than one that is trivially true —
      // `and()` with no arguments IS true, and writing it would be a puzzle
      // for the next reader.
      let condition = null;
      if (tests.length === 1) {
        condition = tests[0];
      } else if (tests.length > 1) {
        condition = apply(F1 + 'and', tests);
      }
      log.debug('Leaving buildAbac(). ' + tests.length + ' test(s).');
      return {
        kind: 'Policy',
        id: options.idBase,
        version: '1.0',
        description: 'Attribute-based access control. The Target selects the ' +
                     'resource and action; the Condition is what must be ' +
                     'true about the subject. Anything not permitted is ' +
                     'denied.',
        combiningAlgId: model.RULE_ALG.DENY_UNLESS_PERMIT,
        target: null,
        variables: {},
        rules: [{
          id: options.idBase + ':rule:permit',
          effect: model.EFFECT.PERMIT,
          description: 'Permit when every attribute test holds.',
          target: targetOf(groups),
          condition: condition,
          obligations: [], advice: []
        }],
        obligations: [], advice: []
      };
    }
  }
];

function lookup(id) {
  return TEMPLATES.filter(function (one) {
    return one.id === id;
  })[0] || null;
}

// ---------------------------------------------------------------------------
// BUILD ONE.
//
// `answers` is whatever the form or the management API sent; missing
// parameters fall back to the row's `dflt`, so a caller may send none at all
// and get the documented example. That is deliberate: the management API's
// "create from template" with an empty body should produce something, because
// the first thing anybody does with an API is call it with nothing.
// ---------------------------------------------------------------------------
function build(id, answers, options) {
  log.debug('Entering build(). template=' + id);
  const template = lookup(id);
  if (!template) {
    log.debug('Leaving build(). No such template.');
    return { ok: false,
             why: 'There is no template "' + id + '". The ones here are: ' +
                  TEMPLATES.map(function (one) {
                    return one.id;
                  }).join(', ') + '.' };
  }
  const settings = options || {};
  const filled = {};
  template.parameters.forEach(function (parameter) {
    const given = answers ? answers[parameter.name] : undefined;
    filled[parameter.name] = (given === undefined || given === null ||
                              String(given).trim() === '')
      ? parameter.dflt : String(given).trim();
  });
  const name = settings.name || template.id;
  const policy = template.build(filled, {
    idBase: settings.idBase || 'urn:sts-mock:xacml:policy:' + slug(name)
  });
  log.debug('Leaving build(). ' + policy.rules.length + ' rule(s).');
  return { ok: true, policy: policy, answers: filled, template: template };
}

// What the console and the management API list. Derived, so a template added
// to the table above appears in both with no second edit.
function catalogue() {
  return TEMPLATES.map(function (one) {
    return { id: one.id, label: one.label, blurb: one.blurb, what: one.what,
             parameters: one.parameters.map(function (parameter) {
               return { name: parameter.name, label: parameter.label,
                        help: parameter.help, type: parameter.type,
                        dflt: parameter.dflt };
             }) };
  });
}

module.exports = {
  TEMPLATES: TEMPLATES,
  lookup: lookup,
  build: build,
  catalogue: catalogue,
  listOf: listOf,
  slug: slug
};
