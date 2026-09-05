'use strict';
//
// File: xacml_role_pep.js
//
// ---------------------------------------------------------------------------
// THE EMBEDDED POLICY ENFORCEMENT POINT FOR THIS SERVICE'S OWN ISSUANCE.
//
// Every other thing in this directory answers a question about somebody
// else's boundary — that is what a PDP is, and it is why `xacml/CLAUDE.md`
// calls this the only family here that is handed a subject authenticated
// elsewhere and asked whether they may. This file is the exception and it is
// deliberately the only one: it turns THIS service's own issuances into XACML
// requests and refuses the ones the PDP will not permit.
//
// It is what `common/issuance_gate.js` calls. Nine issuance sites ask that
// file, that file asks this one, and this one asks the engine. **There is no
// second implementation of the rule** — no `if (roles.includes(...))` in
// oauth2.js, no membership test in the SAML builder — which is the whole point
// of routing an internal decision through a policy engine that is already
// here: the reason a person was refused is a document an administrator can
// read, edit, test on `/admin/xacml/decide` and see in the audit log.
//
// ---------------------------------------------------------------------------
// THE REQUEST IT BUILDS, WHICH IS THE CONTRACT.
//
//   access-subject   subject-id                    who is being authenticated
//                    urn:sts-mock:xacml:role       the roles they hold
//                    urn:sts-mock:xacml:role-from-token
//                                                  roles read out of a token
//                                                  they PRESENTED
//   resource         resource-id                   the application
//                    urn:sts-mock:xacml:required-role
//                                                  what it demands
//   action           action-id                     issue-access-token,
//                                                  start-session, and the rest
//                                                  of issuance_gate's ISSUANCE
//
// **THE SUBJECT IS THE PARTY BEING AUTHENTICATED AND NOT ALWAYS A PERSON.** In
// a browser flow it is whoever signed in; in a `client_credentials` grant
// there is no person at all and it is the CLIENT. That is the case the role
// register exists to be able to answer — an application is a first-class
// member of a role precisely so that this decision has a subject when nobody
// is there.
//
// **THE APPLICATION IS THE RESOURCE AND ALSO, OFTEN, THE SUBJECT'S EMPLOYER.**
// A client asking for a token for itself appears in both categories, and that
// is not a confusion: as a resource it is the thing being reached, and as a
// subject it is the party whose roles are being read. A policy may name either.
//
// ---------------------------------------------------------------------------
// THE TWO WAYS THIS CAN FAIL, AND THEY GET OPPOSITE ANSWERS.
//
// This is the part to read before changing anything here.
//
// **A MISSING OR BROKEN ISSUANCE POLICY FAILS OPEN FOR AN APPLICATION THAT
// REQUIRES ONLY `EVERYBODY`, AND CLOSED FOR ONE THAT REQUIRES ANYTHING ELSE.**
//
// An application that names no required role is the default state of every
// application in this service. It requires EVERYBODY, everybody holds
// EVERYBODY, and the only answer the policy could ever give is Permit — so a
// missing policy costs that application nothing, and refusing it would mean a
// service whose issuance policy was deleted stops issuing ANYTHING to ANYBODY,
// including the session an administrator needs to put the policy back. That is
// not a security posture, it is a locked room with the key inside.
//
// An application whose entry names `staff` is a different sentence entirely:
// somebody deliberately asked for a restriction. Answering Permit because the
// document implementing that restriction is missing would be the one failure
// this feature must not have — a configured refusal silently not happening.
// So that one is refused, and the refusal NAMES the policy and the template
// that rebuilds it.
//
// **AN ERROR IS NOT A DECISION.** A throw out of the engine is a defect, and
// `issuance_gate.js` answers a throw by allowing, for the locked-room reason
// above. A Deny, a NotApplicable and an Indeterminate are not throws — they
// are answers, and every one of them refuses here, because the policy is
// `deny-unless-permit` and an issuance decision must not rest on a PEP's bias.
// `xacml.pepBias` is the EMBEDDED DEMO PEP's setting at `/xacml/protected` and
// it is deliberately not read here: that one exists to show what bias does,
// and this one is enforcing.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const config = require('../common/config');
const audit = require('../common/audit');
const applications = require('../common/applications');
const roles = require('../common/roles');
const gate = require('../common/issuance_gate');
const model = require('./xacml_model');
const store = require('./xacml_store');
const pdp = require('./xacml_pdp');
const pip = require('./xacml_pip');
const templates = require('./xacml_templates');

const ATTRIBUTE = templates.ISSUANCE_ATTRIBUTE;

// Said once per process rather than once per issuance. A service running
// without its issuance policy would otherwise write a line per token, which
// buries the one thing anybody needs to read.
let warnedAboutMissingPolicy = false;

function issuancePolicyName() {
  return String(config.value('xacml.issuancePolicy') || 'role-issuance');
}

// ---------------------------------------------------------------------------
// THE POLICY, OR WHY THERE IS NOT ONE.
//
// Answers `{ policy }` or `{ why }`. Kept apart from the decision below so
// that "there is no policy" is a state with its own sentence rather than an
// Indeterminate somebody has to interpret.
// ---------------------------------------------------------------------------
function issuancePolicy() {
  log.debug('Entering issuancePolicy().');
  const name = issuancePolicyName();
  const row = store.read(name);
  if (!row) {
    log.debug('Leaving issuancePolicy(). There is no such policy.');
    return { why: 'there is no policy called "' + name + '" in the ' +
                  'repository (xacml.issuancePolicy names it)' };
  }
  if (!row.enabled) {
    // A DISABLED POLICY IS A DELIBERATE ACT and reads differently from a
    // missing one, so it says so: somebody took it out of the decision, which
    // is exactly what the console's Disable button is for while editing.
    log.debug('Leaving issuancePolicy(). It is disabled.');
    return { why: 'the policy "' + name + '" is DISABLED, so it is not ' +
                  'evaluated' };
  }
  try {
    const policy = store.parseDocument(row.document);
    log.debug('Leaving issuancePolicy(). Loaded.');
    return { policy: policy, name: name };
  } catch (error) {
    log.debug('Leaving issuancePolicy(). It will not load.');
    return { why: 'the policy "' + name + '" does not load: ' +
                  error.message };
  }
}

// ---------------------------------------------------------------------------
// ONE ATTRIBUTE, MULTI-VALUED.
//
// A bag rather than a value everywhere, because every one of these genuinely
// is one: a party holds several roles and an application requires several. A
// single-valued spelling would have made the policy's intersection test
// impossible to write and would have been discovered at the first application
// that needed two.
// ---------------------------------------------------------------------------
function attribute(attributeId, values, type) {
  return {
    attributeId: attributeId,
    issuer: null,
    includeInResult: true,
    values: (values || []).map(function (one) {
      return { type: type || model.TYPE.STRING, lexical: String(one) };
    })
  };
}

function buildRequest(asked, held, fromToken, required) {
  log.debug('Entering buildRequest().');
  const subjectAttributes = [
    attribute(model.ATTRIBUTE.SUBJECT_ID, [asked.subject.name || '']),
    attribute(ATTRIBUTE.ROLE, held),
    attribute(ATTRIBUTE.TOKEN_ROLE, fromToken)
  ];
  const request = {
    returnPolicyIdList: true,
    combinedDecision: false,
    categories: [
      { category: model.CATEGORY.ACCESS_SUBJECT, id: null, content: null,
        attributes: subjectAttributes },
      { category: model.CATEGORY.RESOURCE, id: null, content: null,
        attributes: [
          // THE APPLICATION IS THE RESOURCE-ID and it is a STRING rather than
          // an anyURI, unlike `/admin/xacml/decide`'s. An application handle
          // here is a client_id, a wtrealm or a SAML entityID slug, and only
          // some of those are URIs — typing them all as anyURI would make the
          // ones that are not fail to parse and take the decision
          // Indeterminate, which under deny-unless-permit refuses everybody
          // with a message about a datatype.
          attribute(model.ATTRIBUTE.RESOURCE_ID, [asked.application]),
          attribute(ATTRIBUTE.REQUIRED_ROLE, required)
        ] },
      { category: model.CATEGORY.ACTION, id: null, content: null,
        attributes: [attribute(model.ATTRIBUTE.ACTION_ID, [asked.kind])] },
      { category: model.CATEGORY.ENVIRONMENT, id: null, content: null,
        attributes: [] }
    ]
  };
  log.debug('Leaving buildRequest().');
  return request;
}

// ---------------------------------------------------------------------------
// THE DECISION.
// ---------------------------------------------------------------------------
function decide(asked) {
  log.debug('Entering decide(). application=' + asked.application +
            ' kind=' + asked.kind);

  if (config.value('xacml.enabled') === false) {
    log.debug('Leaving decide(). The XACML family is switched off.');
    return allowed('xacml.enabled is off, so no policy is evaluated at all.',
                   [], []);
  }

  const subject = asked.subject || {};
  const required = applications.requiredRolesOf(asked.application);
  const held = roles.rolesOf(subject);
  const fromToken = roles.rolesInClaims(asked.claims);
  const narrowed = applications.requiresNarrowedRoles(asked.application);

  const loaded = issuancePolicy();
  if (!loaded.policy) {
    // The split the header argues. Both halves log; only one refuses.
    if (!narrowed) {
      if (!warnedAboutMissingPolicy) {
        warnedAboutMissingPolicy = true;
        log.warn('xacml: ' + loaded.why + '. Issuance is NOT being gated: ' +
                 'every application that has not been narrowed requires ' +
                 'EVERYBODY, which everybody holds, so nothing is refused ' +
                 'that would have been permitted. An application whose entry ' +
                 'names a role WILL be refused until the policy is back — ' +
                 'create it from the `role-issuance` template on ' +
                 '/admin/xacml/policies.');
      }
      log.debug('Leaving decide(). No policy, and nothing narrowed.');
      return allowed('No issuance policy is loaded, and "' +
                     asked.application + '" requires only ' +
                     roles.DEFAULT_REQUIRED_ROLE + ', which everybody holds.',
                     held, required);
    }
    log.debug('Leaving decide(). No policy, and this application is narrowed.');
    return refused(
      'This application requires ' + required.join(' or ') + ', and ' +
      loaded.why + ' — so the restriction cannot be evaluated. It is refused ' +
      'rather than permitted BECAUSE somebody asked for it: an application ' +
      'that requires only ' + roles.DEFAULT_REQUIRED_ROLE + ' would have ' +
      'been let through. Create the policy from the `role-issuance` template ' +
      'on /admin/xacml/policies, or clear appRequiredRole on the application.',
      'NotApplicable', held, required, null);
  }

  const request = buildRequest(asked, held, fromToken, required);
  const answer = pdp.evaluate(loaded.policy, request, {
    repository: store.repository(),
    // THE SAME PIP THE PUBLIC ENDPOINT USES. A decision made here against a
    // different attribute source from the one `/xacml/pdp` and
    // `/admin/xacml/decide` use would be a decision nobody could reproduce on
    // the page built to reproduce it — which is the drift `xacml.js`'s
    // `decide()` exists to prevent, and this is the second caller that has to
    // honour it.
    resolver: pip.resolverFor(request)
  });

  if (answer.decision === model.DECISION.PERMIT) {
    log.debug('Leaving decide(). Permit.');
    return allowed('The issuance policy permitted it.', held, required,
                   answer);
  }

  // EVERYTHING ELSE REFUSES, and the sentence says which of the three it was,
  // because they mean quite different things to whoever has to fix it: a Deny
  // is the policy working, a NotApplicable is a policy that did not cover the
  // question, and an Indeterminate is a policy that could not be evaluated.
  const why = reasonFor(answer, held, required, asked);
  audit.audit({
    action: 'xacml.issuance.refused',
    actor: subject.name || '',
    protocol: 'XACML',
    detail: answer.decision + ' for ' + (asked.kind || 'an issuance') +
            ' to "' + asked.application + '": ' + why
  });
  log.info('xacml: REFUSED ' + (asked.kind || 'an issuance') + ' for "' +
           asked.application + '" to "' + (subject.name || 'nobody') +
           '" — ' + answer.decision + '. ' + why);
  log.debug('Leaving decide(). ' + answer.decision + '.');
  return refused(why, answer.decision, held, required, answer);
}

function reasonFor(answer, held, required, asked) {
  const who = asked.subject && asked.subject.name
    ? '"' + asked.subject.name + '"' : 'the caller';
  if (answer.decision === model.DECISION.DENY ||
      answer.decision === model.DECISION.NOT_APPLICABLE) {
    return '"' + asked.application + '" requires ' +
      (required.length ? required.join(' or ') : 'a role nothing named') +
      ' and ' + who + ' holds ' +
      (held.length ? held.join(', ') : 'no role at all') + '.';
  }
  const status = (answer.status && answer.status.message) || '';
  return 'the issuance policy could not be evaluated' +
    (status ? ': ' + status : '') + '. Nothing is issued on an ' +
    'Indeterminate, because the alternative is issuing on an error.';
}

function allowed(why, held, required, answer) {
  return { allowed: true,
           decision: answer ? answer.decision : model.DECISION.NOT_APPLICABLE,
           why: why, roles: held || [], required: required || [],
           policy: issuancePolicyName() };
}

function refused(why, decision, held, required, answer) {
  return { allowed: false, decision: decision, why: why,
           roles: held || [], required: required || [],
           policy: issuancePolicyName(),
           status: answer ? answer.status : null };
}

// ---------------------------------------------------------------------------
// A DRY RUN, FOR THE CONSOLE.
//
// The same decision, asked without anything being issued, so that
// `/admin/roles` can answer "would alice get a token for this application"
// without somebody having to try it. It goes through `decide()` rather than
// reimplementing it — a preview that agreed with the enforcement only by
// coincidence is worse than no preview.
// ---------------------------------------------------------------------------
function preview(question) {
  log.debug('Entering preview().');
  const asked = question || {};
  const answer = decide({
    application: String(asked.application || ''),
    kind: asked.kind || gate.ISSUANCE.ACCESS_TOKEN,
    subject: asked.subject || { kind: 'user', name: '', authenticated: false },
    claims: asked.claims || null
  });
  log.debug('Leaving preview(). ' + (answer.allowed ? 'Permit.' : 'Refused.'));
  return answer;
}

// ---------------------------------------------------------------------------
// FILL THE SLOT.
//
// At require time, which is what `xacml/xacml.js` requiring this file at 23c
// buys: from that moment every issuance site's call to
// `issuance_gate.check()` reaches the engine. Before it — and in any process
// that never loads the XACML family — the gate answers "allowed" and this
// service is what it always was.
// ---------------------------------------------------------------------------
if (typeof gate.setDecider === 'function') {
  gate.setDecider(decide);
} else {
  log.warn('xacml: common/issuance_gate.js offers no setDecider(), so ' +
           'issuance is not gated by policy. Every other part of the XACML ' +
           'family is unaffected.');
}

module.exports = {
  decide: decide,
  preview: preview,
  issuancePolicy: issuancePolicy,
  issuancePolicyName: issuancePolicyName,
  buildRequest: buildRequest,
  ATTRIBUTE: ATTRIBUTE
};
