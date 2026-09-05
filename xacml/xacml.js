'use strict';
//
// File: xacml.js
//
// ---------------------------------------------------------------------------
// THE XACML SURFACE: A DECISION ENDPOINT, THE REPOSITORY, AND AN EMBEDDED PEP.
//
// Everything else in this directory is a library with no DOM, no HTTP and no
// store. This file is the only one that registers a route, and it is
// deliberately thin — it reads a request, hands it to `xacml_pdp.js`, and
// writes what comes back. No decision logic lives here, and none should: the
// whole point of the conformance suite driving the engine in process is that
// the thing that decides is reachable without a port.
//
//   GET  /xacml            what this surface is, and what it decides against
//   POST /xacml/pdp        a decision. JSON Profile in, JSON Profile out.
//   GET  /xacml/policies   the repository, as the PDP sees it
//   GET  /xacml/protected  THE EMBEDDED PEP — a resource this service guards
//                          with its own PDP
//
// ---------------------------------------------------------------------------
// THE EMBEDDED PEP IS THE POINT OF THE LAST ONE, AND IT IS NOT A DEMO PAGE.
//
// A PDP endpoint answers questions in the abstract; a PEP is where a decision
// stops being an opinion. `/xacml/protected` builds a request out of the
// caller — who they are, what they asked for, how they asked for it — asks the
// PDP, and then ENFORCES the answer, including the part everybody skips: an
// obligation it cannot discharge turns a Permit into a refusal (section 7.2).
//
// It is also where `xacml.pepBias` lives, and that setting is the reason this
// exists as a real component rather than a canned response. XACML lets a PEP
// be deny-biased or permit-biased, the two agree on every Permit and every
// Deny, and they differ on exactly the answer nobody tests: Indeterminate and
// NotApplicable. Being able to flip it and watch the same policy produce two
// different outcomes is the thing a debugger is for.
//
// ---------------------------------------------------------------------------
// THIS ENDPOINT AUTHENTICATES NOBODY, AND FOR ONCE THAT IS NOT THE HOUSE RULE.
//
// Everything in this service is permissive by design. Here there is a second,
// narrower reason worth stating: a PDP is not an authorization boundary — it
// is a function that answers a question about somebody ELSE'S boundary. The
// caller of `POST /xacml/pdp` is a PEP asking on behalf of a subject it names
// in the request, so the interesting identity is IN the request rather than on
// the connection. Phase five adds mutual TLS on this surface, and what that
// will authenticate is WHICH PEP is asking — not who the decision is about.
// Those are two different questions and conflating them is how a PDP ends up
// deciding about whoever holds the client certificate.
// ---------------------------------------------------------------------------

const app = require('../common/app');
const { log, xmlEscape, baseUrlOf } = require('../common/helpers');
const config = require('../common/config');
const audit = require('../common/audit');
const model = require('./xacml_model');
const json = require('./xacml_json');
const pdp = require('./xacml_pdp');
const store = require('./xacml_store');
const pip = require('./xacml_pip');
const validate = require('./xacml_validate');
// THE CONSOLE PAGES. Required from here rather than from `server.js` so that
// the require order has ONE line for this family: this module is 23c and the
// pages are part of it. `xacml_admin.js` requires `admin-ui/admin` (18) for
// the shell, which is already loaded by the time anything here runs — and it
// requires THIS module lazily, inside the one function that needs it, because
// a require at its top would close a cycle and node answers a cycle with a
// half-initialised module rather than with an error.
require('./xacml_admin');

function enabled() {
  return config.value('xacml.enabled') !== false;
}

// The same shape `ssf.js`'s `offCheck()` has, and the same argument: the
// routes stay REGISTERED and answer 501, because the feature being off and the
// URL being wrong are different sentences to a client.
function offCheck(res) {
  log.debug('Entering offCheck().');
  if (enabled()) {
    log.debug('Leaving offCheck(). On.');
    return false;
  }
  res.status(501).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify({
       error: 'not_implemented',
       error_description:
         'XACML is turned off on this service (xacml.enabled). The routes ' +
         'stay registered and answer 501 rather than 404, because the ' +
         'feature being off and the URL being wrong are different sentences ' +
         'to a client. The policy repository in ou=policies is untouched.'
     }, null, 2));
  log.debug('Leaving offCheck(). Off.');
  return true;
}

function fail(res, status, code, description) {
  res.status(status).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify({ error: code, error_description: description },
                          null, 2));
}

// ---------------------------------------------------------------------------
// A DECISION, FROM A PARSED REQUEST.
//
// The one place the engine, the store and the PIP are put together, so that
// the endpoint and the embedded PEP cannot decide against different policies
// or with different attribute sources — which is exactly the drift that makes
// a PEP and a PDP disagree in a real deployment and is the hardest kind to
// find.
// ---------------------------------------------------------------------------
function decide(request) {
  log.debug('Entering decide().');
  const root = store.root();
  if (!root) {
    // NOT an error, and not a Permit. A repository with no root has nothing to
    // say about this request, which is precisely `NotApplicable` — and what
    // the PEP then does with it is the PEP's bias, which is where that
    // decision belongs.
    log.debug('Leaving decide(). No root policy.');
    return { decision: model.DECISION.NOT_APPLICABLE,
             status: { code: model.STATUS.OK },
             obligations: [], advice: [], policyIdentifiers: [],
             note: 'This repository has no root policy, so there is nothing ' +
                   'to evaluate. Mark one policy as the root.' };
  }
  let policy;
  try {
    policy = store.parseDocument(root.document);
  } catch (error) {
    log.debug('Leaving decide(). The root policy will not load.');
    return { decision: model.DECISION.INDETERMINATE,
             status: { code: error.xacmlStatus || model.STATUS.SYNTAX_ERROR,
                       message: 'The root policy "' + root.name + '" does ' +
                                'not load: ' + error.message },
             obligations: [], advice: [], policyIdentifiers: [] };
  }
  if (config.value('xacml.returnPolicyIdList') === true) {
    request.returnPolicyIdList = true;
  }
  const answer = pdp.evaluate(policy, request, {
    repository: store.repository(),
    resolver: pip.resolverFor(request)
  });
  log.debug('Leaving decide(). ' + answer.decision);
  return answer;
}

// ---------------------------------------------------------------------------
// POST /xacml/pdp — the decision endpoint.
// ---------------------------------------------------------------------------
app.post('/xacml/pdp', function (req, res) {
  log.debug('Entering POST /xacml/pdp.');
  if (offCheck(res)) {
    log.debug('Leaving POST /xacml/pdp. Off.');
    return;
  }
  // `app.js` parses every body as TEXT, which is what this endpoint wants
  // rather than a parsed object: the JSON Profile's integer/double inference
  // reads the raw source (see `xacml_json.js`, trap 1), and an already-parsed
  // body has thrown that away.
  const raw = typeof req.body === 'string' ? req.body
    : (Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '');
  let request;
  try {
    request = json.parseRequest(raw);
  } catch (error) {
    // A MALFORMED REQUEST IS A 400, NOT AN INDETERMINATE, and the distinction
    // is the one a PEP most needs: an Indeterminate is an answer ABOUT the
    // request and a 400 says there was no request to answer about. Collapsing
    // them would have a PEP enforce its bias over somebody's typo.
    log.debug('Leaving POST /xacml/pdp. The request would not parse.');
    fail(res, 400, 'invalid_request', error.message);
    return;
  }
  const answer = decide(request);
  audit.audit({
    action: 'xacml.decision',
    actor: pip.subjectOf(request) || '',
    protocol: 'XACML',
    detail: 'POST /xacml/pdp decided ' + answer.decision + '.'
  });
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(json.writeResponse(answer), null, 2));
  log.debug('Leaving POST /xacml/pdp. ' + answer.decision);
});

// ---------------------------------------------------------------------------
// GET /xacml/policies — the repository as the PDP sees it.
//
// The DOCUMENT is included, because this is a debugger and the policy is the
// thing somebody is trying to understand. That is a deliberate departure from
// how `/admin/ldap/*` treats the directory — those pages hide
// `oauthClientSecret` — and the argument for it is that a policy is not a
// credential: it is a rule, and a rule nobody can read is a rule nobody can
// check. Anything secret that ends up inside a policy document is in the wrong
// place, and hiding the document would conceal that rather than fix it.
// ---------------------------------------------------------------------------
app.get('/xacml/policies', function (req, res) {
  log.debug('Entering GET /xacml/policies.');
  if (offCheck(res)) {
    log.debug('Leaving GET /xacml/policies. Off.');
    return;
  }
  const root = store.root();
  const rows = store.all().map(function (row) {
    const view = { name: row.name, policyId: row.id, kind: row.kind,
                   version: row.version,
                   combiningAlgId: row.combiningAlgId,
                   enabled: row.enabled,
                   isRoot: !!(root && root.name === row.name),
                   description: row.description,
                   document: row.document };
    // A policy that does not load is reported HERE rather than only when a
    // decision meets it, because the moment somebody is looking at the list is
    // the moment they can fix it.
    try {
      const parsed = store.parseDocument(row.document);
      view.problems = validate.problemsIn(parsed);
    } catch (error) {
      view.problems = [error.message];
    }
    return view;
  });
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify({
       root: root ? root.name : null,
       rootNote: root ? undefined
         : 'No policy is marked as the root, so every decision is ' +
           'NotApplicable. A PDP evaluates one document and reaches the rest ' +
           'through PolicyIdReference.',
       policies: rows
     }, null, 2));
  log.debug('Leaving GET /xacml/policies. ' + rows.length + ' policy(ies).');
});

// ---------------------------------------------------------------------------
// GET /xacml/protected — THE EMBEDDED PEP.
//
// Builds a request out of the caller, asks the PDP, and enforces the answer.
// The three query parameters are what a PEP would ordinarily get from its own
// context; here they are supplied so that one endpoint can exercise a whole
// policy without a client having to be written.
// ---------------------------------------------------------------------------
app.get('/xacml/protected', function (req, res) {
  log.debug('Entering GET /xacml/protected.');
  if (offCheck(res)) {
    log.debug('Leaving GET /xacml/protected. Off.');
    return;
  }
  const subject = String(req.query.subject || '');
  const resource = String(req.query.resource ||
                          baseUrlOf(req) + '/xacml/protected');
  const action = String(req.query.action || 'GET');
  const request = {
    returnPolicyIdList: true,
    combinedDecision: false,
    categories: [
      { category: model.CATEGORY.ACCESS_SUBJECT, id: null, content: null,
        attributes: subject ? [{ attributeId: model.ATTRIBUTE.SUBJECT_ID,
                                 issuer: null, includeInResult: true,
                                 values: [{ type: model.TYPE.STRING,
                                            lexical: subject }] }] : [] },
      { category: model.CATEGORY.RESOURCE, id: null, content: null,
        attributes: [{ attributeId: model.ATTRIBUTE.RESOURCE_ID,
                       issuer: null, includeInResult: true,
                       values: [{ type: model.TYPE.ANYURI,
                                  lexical: resource }] }] },
      { category: model.CATEGORY.ACTION, id: null, content: null,
        attributes: [{ attributeId: model.ATTRIBUTE.ACTION_ID,
                       issuer: null, includeInResult: true,
                       values: [{ type: model.TYPE.STRING,
                                  lexical: action }] }] },
      { category: model.CATEGORY.ENVIRONMENT, id: null, content: null,
        attributes: [] }
    ]
  };
  const answer = decide(request);
  const enforcement = enforce(answer);
  audit.audit({
    action: 'xacml.enforcement',
    actor: subject,
    protocol: 'XACML',
    detail: 'The embedded PEP got ' + answer.decision + ' and ' +
            (enforcement.allowed ? 'allowed' : 'refused') + ' access to ' +
            resource + ' (' + enforcement.bias + ').'
  });
  const body = {
    decision: answer.decision,
    allowed: enforcement.allowed,
    bias: enforcement.bias,
    why: enforcement.why,
    status: answer.status,
    obligations: (answer.obligations || []).map(function (one) {
      return { id: one.id, discharged: enforcement.discharged
        .indexOf(one.id) >= 0 };
    }),
    advice: (answer.advice || []).map(function (one) {
      return one.id;
    }),
    request: { subject: subject || null, resource: resource, action: action },
    applicablePolicies: answer.policyIdentifiers || []
  };
  if (answer.note) {
    body.note = answer.note;
  }
  res.status(enforcement.allowed ? 200 : 403)
     .type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(body, null, 2));
  log.debug('Leaving GET /xacml/protected. ' +
            (enforcement.allowed ? 'Allowed.' : 'Refused.'));
});

// ---------------------------------------------------------------------------
// WHAT A PEP DOES WITH A DECISION. Section 7.2, and the obligation rule.
//
// TWO THINGS, and the second is the one implementations skip:
//
//   1. The BIAS decides what a non-Permit means. Deny-biased: only Permit
//      allows. Permit-biased: only Deny refuses. They agree on Permit and on
//      Deny and differ on Indeterminate and NotApplicable — which is to say
//      they differ on exactly the cases nobody writes a test for.
//   2. AN OBLIGATION THAT CANNOT BE DISCHARGED TURNS A PERMIT INTO A REFUSAL.
//      That is not a nicety: an obligation is the half of a decision that says
//      "yes, AND you must also do this", and a PEP that allows the access
//      while dropping the obligation has enforced half a policy and reported
//      success. This PEP can discharge exactly one obligation — the one it
//      knows about, below — and refuses on any other, loudly.
// ---------------------------------------------------------------------------
const DISCHARGEABLE = ['urn:sts-mock:xacml:obligation:log'];

function enforce(answer) {
  log.debug('Entering enforce(). decision=' + answer.decision);
  const bias = config.value('xacml.pepBias') === 'permit-biased'
    ? 'permit-biased' : 'deny-biased';
  const discharged = [];
  const undischargeable = [];
  (answer.obligations || []).forEach(function (obligation) {
    if (DISCHARGEABLE.indexOf(obligation.id) >= 0) {
      log.info('xacml: discharging obligation ' + obligation.id + ' with ' +
               (obligation.assignments || []).length + ' assignment(s).');
      discharged.push(obligation.id);
      return;
    }
    undischargeable.push(obligation.id);
  });
  const permitted = answer.decision === model.DECISION.PERMIT;
  const denied = answer.decision === model.DECISION.DENY;
  let allowed = bias === 'deny-biased' ? permitted : !denied;
  let why;
  if (bias === 'deny-biased') {
    why = permitted ? 'The PDP said Permit.'
      : 'The PDP said ' + answer.decision + ', and this PEP is deny-biased, ' +
        'so anything that is not Permit is a refusal.';
  } else {
    why = denied ? 'The PDP said Deny.'
      : 'The PDP said ' + answer.decision + ', and this PEP is ' +
        'permit-biased, so anything that is not Deny is allowed.';
  }
  if (allowed && undischargeable.length) {
    allowed = false;
    why = 'The PDP said ' + answer.decision + ', but the decision carries ' +
          (undischargeable.length === 1 ? 'an obligation' : 'obligations') +
          ' this PEP cannot discharge (' + undischargeable.join(', ') +
          '). Section 7.2: a PEP that cannot fulfil an obligation MUST NOT ' +
          'grant the access. Allowing it and dropping the obligation would ' +
          'enforce half a policy and report success.';
  }
  log.debug('Leaving enforce(). ' + (allowed ? 'Allowed.' : 'Refused.'));
  return { allowed: allowed, bias: bias, why: why, discharged: discharged,
           undischargeable: undischargeable };
}

// ---------------------------------------------------------------------------
// GET /xacml — what this surface is.
// ---------------------------------------------------------------------------
function description(req) {
  const root = store.root();
  const policies = store.all();
  return {
    enabled: enabled(),
    specification: 'OASIS XACML 3.0 (core), JSON Profile 1.1',
    pdpEndpoint: baseUrlOf(req) + '/xacml/pdp',
    repository: {
      container: 'ou=policies in the embedded directory',
      policies: policies.length,
      enabledPolicies: policies.filter(function (one) {
        return one.enabled;
      }).length,
      root: root ? root.name : null
    },
    pep: { embeddedAt: baseUrlOf(req) + '/xacml/protected',
           bias: config.value('xacml.pepBias') },
    pip: { source: 'the embedded directory, access-subject category only',
           attributePrefix: pip.ATTRIBUTE_PREFIX,
           available: pip.available() },
    conformance: '454 of the 455 mandatory OASIS conformance cases; see ' +
                 'xacml/conformance/ and xacml/CLAUDE.md.',
    endpoints: [
      { method: 'GET', path: '/xacml', what: 'this document' },
      { method: 'POST', path: '/xacml/pdp',
        what: 'a decision — JSON Profile request in, response out' },
      { method: 'GET', path: '/xacml/policies',
        what: 'the repository as the PDP sees it, documents included' },
      { method: 'GET', path: '/xacml/protected',
        what: 'the embedded PEP: a resource guarded by this PDP' }
    ],
    notYetHere: [
      'the PAP console pages and /admin-api operations (phase three)',
      'ALFA (phase four)',
      'the remote PEP, its registration and policy push (phase five)',
      'AttributeSelector and the XPath functions — a policy using one is ' +
        'Indeterminate rather than silently empty'
    ]
  };
}

app.get('/xacml', function (req, res) {
  log.debug('Entering GET /xacml.');
  const info = description(req);
  if (String(req.query.format || '').toLowerCase() === 'json') {
    res.status(200).set('Cache-Control', 'no-store').json(info);
    log.debug('Leaving GET /xacml. JSON.');
    return;
  }
  const rows = info.endpoints.map(function (row) {
    return '<tr><td><code>' + xmlEscape(row.method) + '</code></td><td><code>' +
      xmlEscape(row.path) + '</code></td><td>' + xmlEscape(row.what) +
      '</td></tr>';
  }).join('');
  const later = info.notYetHere.map(function (one) {
    return '<li>' + xmlEscape(one) + '</li>';
  }).join('');
  res.status(200).type('text/html').set('Cache-Control', 'no-store').send(
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
    '<title>XACML 3.0</title><style>body{font-family:system-ui,sans-serif;' +
    'margin:2rem;max-width:52rem;line-height:1.5}table{border-collapse:' +
    'collapse;margin:1rem 0}td,th{border:1px solid #ccc;padding:.35rem .6rem;' +
    'text-align:left}code{font-size:.9em}</style></head><body>' +
    '<h1>XACML 3.0</h1>' +
    '<p>This service is a Policy Decision Point. Policies live in ' +
    '<code>ou=policies</code> in the embedded directory — that container ' +
    '<strong>is</strong> the repository rather than a copy of one — and the ' +
    'Policy Information Point reads attributes off the subject&rsquo;s own ' +
    'directory entry.</p>' +
    '<p>' + (info.enabled ? 'XACML is <strong>on</strong>.'
                          : 'XACML is <strong>off</strong> ' +
                            '(<code>xacml.enabled</code>); these endpoints ' +
                            'answer 501.') + '</p>' +
    '<p>The repository holds ' + info.repository.policies + ' policy(ies), ' +
    info.repository.enabledPolicies + ' enabled, and the root is ' +
    (info.repository.root
      ? '<code>' + xmlEscape(info.repository.root) + '</code>.'
      : '<strong>not set</strong>, so every decision is NotApplicable.') +
    '</p>' +
    '<table><tr><th>Method</th><th>Path</th><th>What</th></tr>' + rows +
    '</table>' +
    '<h2>The embedded PEP</h2>' +
    '<p><code>GET /xacml/protected?subject=&hellip;&amp;resource=&hellip;' +
    '&amp;action=&hellip;</code> asks this PDP and then <em>enforces</em> ' +
    'the answer. It is <code>' + xmlEscape(info.pep.bias) + '</code>: the ' +
    'two biases agree on every Permit and every Deny and differ on ' +
    'Indeterminate and NotApplicable, which is the case worth looking at. ' +
    'An obligation it cannot discharge turns a Permit into a refusal, which ' +
    'is section 7.2 and is the part implementations skip.</p>' +
    '<h2>Not here yet</h2><ul>' + later + '</ul>' +
    '<p><a href="?format=json">This document as JSON</a></p>' +
    '</body></html>');
  log.debug('Leaving GET /xacml. HTML.');
});

module.exports = { decide: decide, enforce: enforce, description: description,
                   enabled: enabled };
