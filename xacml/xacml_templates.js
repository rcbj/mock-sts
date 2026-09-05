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
const F3 = 'urn:oasis:names:tc:xacml:3.0:function:';
const TYPE = model.TYPE;

// ---------------------------------------------------------------------------
// THE ATTRIBUTE VOCABULARY OF AN ISSUANCE DECISION.
//
// These four identifiers are the contract between the embedded PEP that
// ASSERTS them (`xacml/xacml_role_pep.js`) and the policy that READS them —
// which is the one below, and any policy anybody writes afterwards. They are
// exported so there is ONE spelling of each: a template that built a policy
// reading `urn:sts-mock:xacml:roles` while the PEP asserted
// `urn:sts-mock:xacml:role` would produce an empty bag, an empty bag is no
// intersection, and no intersection is a Deny — a policy that refuses
// everybody for a reason invisible in both files.
//
// **THEY ARE URI-SHAPED ON PURPOSE.** `xacml_pip.js` treats a BARE name as a
// directory attribute to look up on the subject's own entry, so an attribute
// called `roles` would send the PIP looking for a `roles` attribute in LDAP
// and quietly answer with whatever it found there instead of with what the PEP
// asserted. A colon in the name is what keeps these out of that path.
// ---------------------------------------------------------------------------
const ISSUANCE_ATTRIBUTE = {
  // On the SUBJECT: the roles the party being authenticated holds, from the
  // register and from the six built-in ones.
  ROLE: 'urn:sts-mock:xacml:role',
  // On the SUBJECT: the roles found in a token the caller PRESENTED, read out
  // of the claim `roles.claimName` names. Separate from the above rather than
  // unioned into it, and that separation is the whole reason it is visible in
  // the policy: these two are not equally trustworthy. The register is this
  // service's own record; a claim is whatever was in a token, and this service
  // does not verify access tokens it did not issue.
  TOKEN_ROLE: 'urn:sts-mock:xacml:role-from-token',
  // On the RESOURCE: the roles the application demands. `appRequiredRole` on
  // its entry, or EVERYBODY where it names none.
  REQUIRED_ROLE: 'urn:sts-mock:xacml:required-role'
};

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

// A yes/no answer from a template parameter, which is a text field like every
// other one. Anything that is not plainly a no is a yes, because these two
// parameters both default to yes and the cost of misreading a typo as a yes is
// a policy that permits slightly more than intended — while misreading one as
// a no builds the issuance policy without an arm and refuses people.
function yes(answer, dflt) {
  const text = String(answer === undefined || answer === null ? '' : answer)
    .trim().toLowerCase();
  if (!text) {
    return dflt !== false;
  }
  return !(text === 'no' || text === 'false' || text === 'off' ||
           text === '0' || text === 'n');
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
    // -----------------------------------------------------------------------
    // THE ONE TEMPLATE THIS SERVICE EVALUATES ABOUT ITSELF.
    //
    // Every other template here builds a policy about somebody ELSE's
    // boundary, which is what a PDP is for. This one builds the policy the
    // EMBEDDED PEP asks before this service issues anything — a token, a
    // ticket, an assertion, a session — and `xacml.issuancePolicy` names the
    // repository entry it lives in.
    //
    // IT IS SEEDED, AND IT IS NOT THE REPOSITORY ROOT. Two questions, two
    // documents: the root answers what a caller asks at /xacml/pdp and what
    // every remote PEP pulls, and this answers who may be issued something
    // here. Making them one document would mean editing the demo policy
    // changed who could sign in, and narrowing one application's roles changed
    // what /xacml/pdp told a remote PEP.
    //
    // WHY IT IS ONE POLICY FOR EVERY APPLICATION RATHER THAN ONE PER
    // APPLICATION. The alternative — a rule per application naming its roles —
    // was rejected because the requirement then lives in TWO places that can
    // disagree: `appRequiredRole` on the entry, which the console edits, and a
    // rule in a policy, which the editor edits. This way the policy states the
    // RULE ("you must hold one of the roles this application requires") and
    // the entry states the FACT, the PEP puts both in the request, and there
    // is nothing to keep in step.
    // -----------------------------------------------------------------------
    id: 'role-issuance',
    label: 'Role-based issuance (this service\'s own)',
    blurb: 'The policy the embedded PEP asks before this service issues ' +
           'anything: the party being authenticated must hold one of the ' +
           'roles the application requires.',
    what: 'Produces ONE Permit rule whose condition is an intersection test ' +
          'between the roles the subject holds and the roles the resource ' +
          'requires — plus the same test against the roles found in a ' +
          'PRESENTED TOKEN\'s claim, and a permit for an application that ' +
          'requires nothing at all. The combining algorithm is ' +
          'deny-unless-permit, so anything the rule does not permit is ' +
          'refused rather than left to the PEP\'s bias. Because the ' +
          'requirement travels in the REQUEST rather than being written into ' +
          'the policy, this one document decides for every application, and ' +
          'narrowing an application is editing its entry rather than editing ' +
          'a policy.',
    parameters: [
      { name: 'allowTokenRoles',
        label: 'Also accept roles found in a presented token',
        dflt: 'yes', type: 'string',
        help: 'yes or no. When yes, a role named in the roles claim of a ' +
              'token the caller presented counts as held. THAT IS WEAKER ' +
              'THAN THE REGISTER and the policy says so in its own ' +
              'description: this service does not verify access tokens it ' +
              'did not issue, so a claim is evidence about a token rather ' +
              'than about a person. It is on by default because reading the ' +
              'claim back is the thing most people come here to watch.' },
      { name: 'permitWhenNothingRequired',
        label: 'Permit when the application requires no role at all',
        dflt: 'yes', type: 'string',
        help: 'yes or no. An application that names no required role is ' +
              'given EVERYBODY by the registry, so this arm is a belt-and- ' +
              'braces answer for a request that carries no requirement at ' +
              'all — a PEP written by somebody else, or this one after a ' +
              'future change. Saying no makes such a request a Deny.' }
    ],
    build: function (answers, options) {
      log.debug('Entering buildRoleIssuance().');
      const given = answers || {};
      const useTokenRoles = yes(given.allowTokenRoles, true);
      const permitEmpty = yes(given.permitWhenNothingRequired, true);

      // THE INTERSECTION TEST, and it is a HIGHER-ORDER function because that
      // is the only way XACML expresses "do these two bags share a member".
      // `any-of-any(string-equal, A, B)` is true when string-equal holds for
      // ANY pair — which is exactly the question, and which no ordinary
      // two-argument predicate can ask.
      function intersects(subjectAttribute) {
        return apply(F3 + 'any-of-any', [
          { kind: 'function', functionId: F1 + 'string-equal' },
          designator(model.CATEGORY.ACCESS_SUBJECT, subjectAttribute,
                     TYPE.STRING),
          designator(model.CATEGORY.RESOURCE,
                     ISSUANCE_ATTRIBUTE.REQUIRED_ROLE, TYPE.STRING)
        ]);
      }

      const arms = [intersects(ISSUANCE_ATTRIBUTE.ROLE)];
      if (useTokenRoles) {
        arms.push(intersects(ISSUANCE_ATTRIBUTE.TOKEN_ROLE));
      }
      if (permitEmpty) {
        // "The resource requires nothing." Written as a bag-size test because
        // XACML has no way to ask whether a designator matched — an absent
        // attribute and an attribute with no values are the same empty bag,
        // which is the right answer here: both mean nobody said.
        arms.push(apply(F1 + 'integer-equal', [
          apply(F1 + 'string-bag-size', [
            designator(model.CATEGORY.RESOURCE,
                       ISSUANCE_ATTRIBUTE.REQUIRED_ROLE, TYPE.STRING)
          ]),
          value(TYPE.INTEGER, '0')
        ]));
      }

      const condition = arms.length === 1 ? arms[0]
        : apply(F1 + 'or', arms);

      log.debug('Leaving buildRoleIssuance(). ' + arms.length + ' arm(s).');
      return {
        kind: 'Policy',
        id: options.idBase,
        version: '1.0',
        description: 'THE ISSUANCE POLICY. The embedded PEP asks this before ' +
                     'this service issues a token, a ticket, an assertion or ' +
                     'a session. It permits when the party being ' +
                     'authenticated holds one of the roles the application ' +
                     'requires' +
                     (useTokenRoles
                        ? ', or when a role in a PRESENTED TOKEN\'s claim is ' +
                          'one of them — which is weaker, because this ' +
                          'service does not verify tokens it did not issue'
                        : '') +
                     (permitEmpty
                        ? ', or when the application requires nothing at all'
                        : '') +
                     '. Everything else is denied, because the combining ' +
                     'algorithm is deny-unless-permit and an issuance ' +
                     'decision must not depend on a PEP\'s bias.',
        combiningAlgId: model.RULE_ALG.DENY_UNLESS_PERMIT,
        // NO TARGET, and that is deliberate rather than an omission: this
        // document is evaluated by ONE caller that only ever asks about an
        // issuance, so a target restating that could only ever refuse a
        // request the PEP would not have made — and would do it as
        // NotApplicable, which under deny-unless-permit is a Deny nobody can
        // explain.
        target: null,
        variables: {},
        rules: [{
          id: options.idBase + ':rule:holds-a-required-role',
          effect: model.EFFECT.PERMIT,
          description: 'Permit when the roles the subject holds and the ' +
                       'roles the resource requires share a member.',
          target: null,
          condition: condition,
          obligations: [], advice: []
        }],
        obligations: [], advice: []
      };
    }
  },
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
  ISSUANCE_ATTRIBUTE: ISSUANCE_ATTRIBUTE,
  TEMPLATES: TEMPLATES,
  lookup: lookup,
  build: build,
  catalogue: catalogue,
  listOf: listOf,
  slug: slug
};
