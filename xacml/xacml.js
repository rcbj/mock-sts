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
const { log, xmlEscape, baseUrlOf, parseBody } = require('../common/helpers');
const config = require('../common/config');
const audit = require('../common/audit');
const model = require('./xacml_model');
const json = require('./xacml_json');
const pdp = require('./xacml_pdp');
const store = require('./xacml_store');
const pip = require('./xacml_pip');
const validate = require('./xacml_validate');
const mtls = require('../oauth-oidc/mtls');
const peps = require('./xacml_pep_registry');
const pepHttp = require('./xacml_pep_http');
// THE CONSOLE PAGES. Required from here rather than from `server.js` so that
// the require order has ONE line for this family: this module is 23c and the
// pages are part of it. `xacml_admin.js` requires `admin-ui/admin` (18) for
// the shell, which is already loaded by the time anything here runs — and it
// requires THIS module lazily, inside the one function that needs it, because
// a require at its top would close a cycle and node answers a cycle with a
// half-initialised module rather than with an error.
require('./xacml_admin');

// THE EMBEDDED PEP FOR THIS SERVICE'S OWN ISSUANCE, required from here for the
// same reason and with one extra consequence: requiring it is what FILLS
// `common/issuance_gate.js`'s decider slot, so from this line onward every
// issuance site's `gate.check()` reaches the engine. Before it — and in any
// process that never loads this family, which is `npm test`, the parent
// project's in-process Kerberos jobs and the remote PEP container — the gate
// answers "allowed" and this service is exactly what it was.
//
// It registers NO ROUTE and is therefore a library (rule 3): it is here rather
// than in `server.js` so that the require order keeps its one line for this
// family, and its position within that line does not matter. It must come
// after `xacml_admin.js` for no technical reason at all, and does, because the
// pages are what an administrator fixes a refusal with.
require('./xacml_role_pep');

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

// ===========================================================================
// PHASE FIVE: THE REMOTE PEP. THREE ENDPOINTS, AND THE PULL IS THE CONTRACT.
//
//   POST /xacml/pep/register    a PEP says it exists, over mutual TLS
//   GET  /xacml/pep/policies    the repository, for a PEP to LOAD and evaluate
//   POST /xacml/pep/heartbeat   what it has enforced, and what it holds
//
// ---------------------------------------------------------------------------
// WHY THE PEP PULLS AND THIS SERVICE DOES NOT PUSH.
//
// A remote PEP holds its own copy of the engine and evaluates locally — which
// is the whole point of having one, because a PEP that asked this service per
// request would be `POST /xacml/pdp` with extra steps and would put a network
// hop in front of every access decision. So something has to move POLICY from
// here to there, and it could have moved either way.
//
// It moves by PULL, for three reasons and the first is this repository's own:
//
//   1. **A PUSH WOULD BE AN OUTBOUND REQUEST CARRYING CONTENT.** Outbound
//      requests are deliberately rare here — federation's and SSF's headers
//      each argue their own — and a push would make policy DISTRIBUTION depend
//      on this service being able to dial every PEP. The nudge below is an
//      outbound request too, and it is affordable precisely because it carries
//      nothing.
//   2. **A PEP KNOWS WHEN IT IS BEHIND AND THIS SERVICE DOES NOT.** Under
//      push, a PEP that was down for a minute has a stale copy and no way to
//      discover it; under pull, being current is the PEP's own responsibility
//      and it is checked on every poll. That inverts the failure: a network
//      partition leaves a pulling PEP knowingly stale rather than unknowingly
//      wrong.
//   3. **IT WORKS WHERE A PEP CANNOT BE DIALLED.** Behind NAT, in another
//      cluster, on a laptop. A PDP that could only serve PEPs it could reach
//      would be a PDP for one deployment topology.
//
// **AND THE NUDGE DOES NOT CHANGE ANY OF THAT.** When the repository changes,
// this service POSTs a few bytes to each registered PEP that gave a URL,
// saying "pull now". It is an optimisation over the polling interval and never
// the mechanism — `xacml_pep_http.js` makes that argument at length, because it
// is what makes a third outbound requester affordable in this repository.
//
// ---------------------------------------------------------------------------
// WHAT IS AUTHENTICATED HERE, AND WHAT DELIBERATELY IS NOT.
//
// `POST /xacml/pdp` authenticates nobody and the header of this file says why:
// a PDP is not an authorization boundary, and the identity that matters is IN
// the request rather than on the connection. **THAT IS UNCHANGED, AND SO IS
// `GET /xacml/pep/policies`** — pulling the repository needs no credential,
// exactly as `GET /xacml/policies` needs none, because a policy is a RULE and
// a rule nobody can read is a rule nobody can check.
//
// **REGISTERING IS THE ONE THAT ASKS**, and it asks a different question:
// not who the decision is about, but WHICH PEP IS THIS. That question has an
// answer worth having, because a registration writes a directory entry, puts a
// row on the console, and supplies an address this service will later dial. So
// `xacml.pepRequireCertificate` is on by default and a registration with no
// client certificate is refused.
//
// It is a TURNSTILE like every other gate here. The certificate need not chain
// to anything — RFC 8705 section 3's argument applies unchanged, that what is
// proved is that the same key completed the handshake — and the main listener
// already asks for one (`server.js`: `requestCert: true,
// rejectUnauthorized: false`), so phase five needed no new socket and no new
// TLS configuration at all.
//
// **AND THE REGISTRATION IS NOT A PERMISSION.** An unregistered PEP can pull
// and enforce perfectly. What registration buys is visibility and a nudge, and
// `xacml_pep_registry.js` says so where the register is defined, because the
// shape looks like an access-control list and is not one.
// ===========================================================================

function remotePepsEnabled() {
  return config.value('xacml.remotePeps') !== false;
}

// The same shape `offCheck()` has one screen up, and a second function rather
// than a parameter because the two answer different sentences: one says XACML
// is off here, the other says XACML is on and remote enforcement points are
// not. A caller told the first when the second was true would go looking in
// the wrong place.
function remotePepOffCheck(res) {
  log.debug('Entering remotePepOffCheck().');
  if (offCheck(res)) {
    log.debug('Leaving remotePepOffCheck(). XACML is off.');
    return true;
  }
  if (remotePepsEnabled()) {
    log.debug('Leaving remotePepOffCheck(). On.');
    return false;
  }
  res.status(501).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify({
       error: 'not_implemented',
       error_description:
         'XACML is on, but remote Policy Enforcement Points are turned off ' +
         'on this service (xacml.remotePeps). The register in ou=peps is ' +
         'untouched, so a PEP that was registered is still listed and comes ' +
         'back the moment this is turned on again.'
     }, null, 2));
  log.debug('Leaving remotePepOffCheck(). Off.');
  return true;
}

// ---------------------------------------------------------------------------
// WHAT A PEP IS TOLD ITS IDENTITY IS.
//
// One function, so that the registration and the refusal cannot disagree about
// what the connection carried. It returns what was presented rather than a
// verdict — the caller decides what to do about `authenticated: false`,
// because that is `xacml.pepRequireCertificate`'s decision and not this
// function's.
// ---------------------------------------------------------------------------
function callerIdentity(req) {
  log.debug('Entering callerIdentity().');
  const certificate = mtls.peerCertificate(req);
  if (!certificate) {
    log.debug('Leaving callerIdentity(). No client certificate.');
    return { authenticated: false, subject: '', thumbprint: '',
             dn: '', commonName: '' };
  }
  // The DN and the common name come from `certificatePlan()`, across the
  // register's slot — this service already has exactly one answer to "what
  // identity is this certificate" and a second one written here would be how
  // a PEP ends up filed under two names on two pages.
  const named = peps.certificateIdentity(certificate);
  const identity = {
    authenticated: true,
    subject: named.subject,
    // RFC 8705 x5t#S256, through the same function the token endpoint binds a
    // certificate-bound token with, so the two spellings cannot drift.
    thumbprint: mtls.presentedThumbprint(req),
    dn: named.dn,
    commonName: named.commonName
  };
  log.debug('Leaving callerIdentity(). dn=' + identity.dn);
  return identity;
}

// ---------------------------------------------------------------------------
// POST /xacml/pep/register
// ---------------------------------------------------------------------------
app.post('/xacml/pep/register', function (req, res) {
  log.debug('Entering POST /xacml/pep/register.');
  if (remotePepOffCheck(res)) {
    log.debug('Leaving POST /xacml/pep/register. Off.');
    return;
  }
  const body = parseBody(req);
  const identity = callerIdentity(req);
  const required = config.value('xacml.pepRequireCertificate') !== false;
  if (required && !identity.authenticated) {
    // THE REFUSAL NAMES THE CAUSE AND THE WAY OUT, and it distinguishes the
    // two ways to arrive here — because they need opposite fixes and a single
    // sentence covering both would send half the readers the wrong way. A
    // plain-HTTP listener cannot carry a certificate at all, however good the
    // client's; an https one can, and a client that sent none simply did not.
    const plain = !(req.socket &&
                    typeof req.socket.getPeerCertificate === 'function');
    log.debug('Leaving POST /xacml/pep/register. No client certificate.');
    fail(res, 401, 'invalid_client', plain
      ? 'This registration arrived on a PLAIN HTTP connection, which cannot ' +
        'carry a client certificate at all — so there is nothing a better ' +
        'client could have sent. Either turn on global.https (STS_HTTPS) so ' +
        'the main listener asks for one, or turn off ' +
        'xacml.pepRequireCertificate, in which case the registration is ' +
        'accepted and marked UNAUTHENTICATED on its own row rather than ' +
        'being quietly indistinguishable from one that proved something. ' +
        'Note that neither is needed to ENFORCE: GET /xacml/pep/policies ' +
        'requires no credential and a PEP that never registers still pulls ' +
        'and decides.'
      : 'A remote Policy Enforcement Point registers over mutual TLS and ' +
        'this connection carried no client certificate ' +
        '(xacml.pepRequireCertificate). The certificate does not have to ' +
        'chain to anything — what is proved is that the same key completed ' +
        'the handshake, which is RFC 8705 section 3\'s argument and it holds ' +
        'here unchanged. Note that registering is not what lets a PEP ' +
        'enforce: GET /xacml/pep/policies requires no credential, and what ' +
        'a registration buys is a row on /admin/xacml/peps and an address ' +
        'for the change nudge.');
    return;
  }
  // THE NAME COMES FROM THE CERTIFICATE WHEN THERE IS ONE, and from the body
  // only when there is not. A PEP that could name itself while holding a
  // certificate could register as somebody else's PEP and take over their row
  // — which is the one thing in this whole family that would be a security
  // bug rather than a fidelity one.
  const name = identity.authenticated
    ? (identity.commonName || identity.dn)
    : String(body.name || '');
  const result = peps.register({
    name: name,
    identity: identity.dn,
    certificateSubject: identity.subject,
    thumbprint: identity.thumbprint,
    authenticated: identity.authenticated,
    notifyUrl: String(body.notifyUrl || body.notify_url || ''),
    bias: String(body.bias || ''),
    resource: String(body.resource || ''),
    version: String(body.version || ''),
    description: String(body.description || '')
  });
  if (!result.ok) {
    log.debug('Leaving POST /xacml/pep/register. Refused.');
    fail(res, 400, 'invalid_request', result.why);
    return;
  }
  audit.audit({
    action: 'xacml.pep.register',
    actor: identity.dn || result.name,
    protocol: 'XACML',
    detail: 'Remote PEP "' + result.name + '" ' +
            (result.created ? 'registered' : 're-registered') +
            (identity.authenticated ? ' over mutual TLS.'
                                    : ' with no client certificate.')
  });
  const notifyProblem = pepHttp.urlProblem(String(body.notifyUrl ||
                                                  body.notify_url || ''));
  res.status(result.created ? 201 : 200).type('application/json')
     .set('Cache-Control', 'no-store')
     .send(JSON.stringify({
       registered: true,
       name: result.name,
       created: result.created,
       authenticated: identity.authenticated,
       identity: identity.dn,
       syncToken: peps.syncToken(),
       policiesUrl: baseUrlOf(req) + '/xacml/pep/policies',
       heartbeatUrl: baseUrlOf(req) + '/xacml/pep/heartbeat',
       // SAID BACK IMMEDIATELY, rather than being discovered the first time a
       // nudge is not delivered. A PEP whose notify URL this service will
       // never dial should find that out while somebody is still looking at
       // the deployment, and it costs nothing to answer because the check is
       // a string test rather than a request.
       notify: { url: String(body.notifyUrl || body.notify_url || '') || null,
                 usable: !notifyProblem,
                 why: notifyProblem || 'This URL will be nudged when the ' +
                                       'repository changes.' },
       note: 'THE PULL IS THE CONTRACT. Poll ' + baseUrlOf(req) +
             '/xacml/pep/policies on your own interval and pass the ' +
             'syncToken you hold as ?since= — an unchanged repository ' +
             'answers 304. The nudge is an optimisation over that interval ' +
             'and never a replacement for it, so a PEP that is never ' +
             'nudged still converges.'
     }, null, 2));
  log.debug('Leaving POST /xacml/pep/register. ' + result.name);
});

// ---------------------------------------------------------------------------
// GET /xacml/pep/policies — WHAT A REMOTE PEP LOADS.
//
// The ENABLED policies and which one is the root, plus the sync token over
// exactly those bytes. Three differences from `GET /xacml/policies`, and each
// is because this answer is for a MACHINE that is about to evaluate it rather
// than for a person reading:
//
//   * DISABLED POLICIES ARE NOT HERE. That page shows them because somebody
//     wants to see what is in the repository; a PEP that loaded one would
//     enforce a policy this service does not.
//   * THE STATIC PROBLEMS ARE NOT HERE either — a document that does not
//     typecheck cannot be written through the store in the first place, and a
//     PEP has its own validator and will refuse it again.
//   * IT CARRIES A SYNC TOKEN AND HONOURS `?since=`, which is what makes
//     polling cheap enough to be the contract.
//
// **NO CREDENTIAL IS REQUIRED**, which is the same decision `GET
// /xacml/policies` makes and rests on the same sentence: a policy is a rule,
// and a rule nobody can read is a rule nobody can check. Anything secret that
// ends up inside a policy document is in the wrong place, and refusing to
// serve the document would conceal that rather than fix it.
// ---------------------------------------------------------------------------
app.get('/xacml/pep/policies', function (req, res) {
  log.debug('Entering GET /xacml/pep/policies.');
  if (remotePepOffCheck(res)) {
    log.debug('Leaving GET /xacml/pep/policies. Off.');
    return;
  }
  const token = peps.syncToken();
  const since = String(req.query.since || '');
  // A PEP that reports the name it registered under gets its `lastSeen`
  // moved by a PULL as well as by a heartbeat, because a PEP that is polling
  // is plainly alive and a register that called it stale would be reporting
  // on its own heartbeat interval rather than on the PEP.
  const asName = peps.nameFrom(String(req.query.pep || ''));
  if (asName && peps.read(asName)) {
    peps.heartbeat(asName, {});
  }
  if (since && since === token) {
    // 304 AND NOT 200 WITH A FLAG, because a PEP polling every few seconds is
    // the ordinary case and this is the answer it gets almost every time. The
    // token goes in an ETag as well so that an ordinary HTTP cache — or a
    // client library that already speaks conditional requests — behaves
    // correctly without knowing anything about XACML.
    res.status(304).set('Cache-Control', 'no-store').set('ETag', '"' + token + '"')
       .end();
    log.debug('Leaving GET /xacml/pep/policies. Unchanged.');
    return;
  }
  const root = store.root();
  const rows = store.all().filter(function (row) {
    return row.enabled;
  }).map(function (row) {
    return { name: row.name, policyId: row.id, kind: row.kind,
             version: row.version, combiningAlgId: row.combiningAlgId,
             isRoot: !!(root && root.name === row.name),
             description: row.description, document: row.document };
  });
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .set('ETag', '"' + token + '"')
     .send(JSON.stringify({
       syncToken: token,
       root: root ? root.name : null,
       rootNote: root ? undefined
         : 'No policy is marked as the root, so a PEP loading this decides ' +
           'NotApplicable to everything — which its bias then turns into a ' +
           'refusal or an allowance. That is a real state and not an error, ' +
           'and it is reported rather than hidden.',
       policies: rows,
       note: 'Every ENABLED policy. A disabled one is left out rather than ' +
             'sent with a flag, because a PEP that loaded one would enforce ' +
             'a policy this service does not.'
     }, null, 2));
  log.debug('Leaving GET /xacml/pep/policies. ' + rows.length + ' policy(ies).');
});

// ---------------------------------------------------------------------------
// POST /xacml/pep/heartbeat — WHAT A REMOTE PEP REPORTS.
//
// Its counters, and the sync token it is holding. The second is what makes
// "current" a comparison this service can perform rather than a claim the PEP
// makes about itself, and the first is the only way the enforcement a remote
// PEP does is visible here at all — those decisions happened in another
// process and this service did not see one of them, which is the entire point
// of a remote PEP.
//
// IT DOES NOT CREATE A ROW. A heartbeat from something that never registered
// is refused naming the registration endpoint, because a row created here
// would carry no certificate, no notify URL and no registration date.
// ---------------------------------------------------------------------------
app.post('/xacml/pep/heartbeat', function (req, res) {
  log.debug('Entering POST /xacml/pep/heartbeat.');
  if (remotePepOffCheck(res)) {
    log.debug('Leaving POST /xacml/pep/heartbeat. Off.');
    return;
  }
  const body = parseBody(req);
  const identity = callerIdentity(req);
  // A CERTIFICATE, WHERE THERE IS ONE, OVERRIDES THE NAME IN THE BODY —
  // the same rule the registration follows and for the same reason: a PEP
  // holding a certificate must not be able to file its counters against
  // somebody else's row.
  const name = peps.nameFrom(identity.authenticated
    ? (identity.commonName || identity.dn)
    : String(body.name || ''));
  if (!name) {
    log.debug('Leaving POST /xacml/pep/heartbeat. Nameless.');
    fail(res, 400, 'invalid_request',
         'A heartbeat says which PEP it is from — by the client certificate ' +
         'it arrives with, or by `name` when it carries none.');
    return;
  }
  const result = peps.heartbeat(name, {
    syncToken: body.syncToken === undefined ? undefined : body.syncToken,
    policyCount: body.policyCount,
    decisions: body.decisions,
    allowed: body.allowed,
    refused: body.refused,
    undischargeable: body.undischargeable,
    bias: body.bias,
    resource: body.resource,
    version: body.version,
    notifyUrl: body.notifyUrl === undefined ? body.notify_url : body.notifyUrl
  });
  if (!result.ok) {
    log.debug('Leaving POST /xacml/pep/heartbeat. Refused.');
    fail(res, 404, 'invalid_request', result.why);
    return;
  }
  const row = peps.read(name);
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify({
       acknowledged: true,
       name: name,
       syncToken: result.current,
       // TOLD RATHER THAN LEFT TO BE COMPARED. A PEP that has to diff two
       // strings to find out it is behind is a PEP that will get it wrong
       // once; this service has both values in front of it here.
       current: !!row && row.current,
       action: row && row.current ? 'nothing — your copy is the current one'
         : 'pull GET /xacml/pep/policies; your copy is not the current one'
     }, null, 2));
  log.debug('Leaving POST /xacml/pep/heartbeat. ' + name);
});

// ---------------------------------------------------------------------------
// THE NUDGE, FIRED WHEN THE REPOSITORY CHANGES.
//
// Installed as `xacml_store.js`'s change observer, which is an inverted hook
// for a mechanical reason that file states: the register requires the store
// for the sync token, so a require in the obvious direction closes a cycle.
//
// **NOTHING WAITS ON THIS.** The promise is deliberately not returned and not
// awaited: the console form that saved a policy has finished its work whether
// or not four PEPs answered, and a save that blocked on somebody else's web
// server would be exactly the mistake `saml/CLAUDE.md` records about not
// dialling a service provider's metadata URL while issuing. What each PEP
// answered is recorded on its own row and read on /admin/xacml/peps.
// ---------------------------------------------------------------------------
function nudgeRegisteredPeps(what) {
  log.debug('Entering nudgeRegisteredPeps(). what=' + what);
  if (!pepHttp.notifyAllowed() || !remotePepsEnabled()) {
    log.debug('Leaving nudgeRegisteredPeps(). Turned off.');
    return;
  }
  const rows = peps.notifiable();
  if (!rows.length) {
    log.debug('Leaving nudgeRegisteredPeps(). Nobody to nudge.');
    return;
  }
  log.info('xacml: ' + what + '; nudging ' + rows.length +
           ' registered PEP(s) to pull. The nudge is an optimisation — every ' +
           'one of them would converge on its next poll without it.');
  pepHttp.nudgeAll(rows, '', peps.recordNotify).then(function (results) {
    const failed = results.filter(function (one) {
      return !one.ok;
    });
    if (failed.length) {
      log.warn('xacml: ' + failed.length + ' of ' + results.length +
               ' nudge(s) were not delivered. Each is recorded on that PEP\'s ' +
               'row at /admin/xacml/peps. No policy change is lost by this: ' +
               'those PEPs converge on their next poll.');
    }
  }).catch(function (error) {
    // `nudgeAll()` resolves rather than rejects for every ordinary failure, so
    // reaching here means a defect in this file rather than an unreachable
    // PEP. Logged and swallowed regardless: a policy that was written stays
    // written.
    log.warn('xacml: the nudge dispatcher threw, which is a bug here rather ' +
             'than a PEP being unreachable: ' + error.message);
  });
  log.debug('Leaving nudgeRegisteredPeps(). Dispatched.');
}

store.setChangeObserver(nudgeRegisteredPeps);

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
    // THE EMBEDDED PEP'S BIAS IS NOT REPORTED HERE FOR THE REMOTE ONES, and
    // the omission is deliberate: `xacml.pepBias` governs the endpoint above
    // and nothing else. A remote PEP is a separate process with its own
    // configuration and reports the bias it is actually running with on every
    // heartbeat, which is what /admin/xacml/peps shows.
    remotePeps: {
      enabled: remotePepsEnabled(),
      registerAt: baseUrlOf(req) + '/xacml/pep/register',
      policiesAt: baseUrlOf(req) + '/xacml/pep/policies',
      heartbeatAt: baseUrlOf(req) + '/xacml/pep/heartbeat',
      requiresCertificate:
        config.value('xacml.pepRequireCertificate') !== false,
      syncToken: peps.syncToken(),
      registered: peps.all().length,
      notify: pepHttp.notifyAllowed(),
      contract: 'THE PULL IS THE CONTRACT. A PEP polls the policies ' +
                'endpoint on its own interval with ?since=<syncToken>; an ' +
                'unchanged repository answers 304. The nudge this service ' +
                'sends on a change is an optimisation over that interval ' +
                'and never a replacement for it.'
    },
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
        what: 'the embedded PEP: a resource guarded by this PDP' },
      { method: 'POST', path: '/xacml/pep/register',
        what: 'a remote PEP registers, over mutual TLS' },
      { method: 'GET', path: '/xacml/pep/policies',
        what: 'the enabled policies for a remote PEP to LOAD and evaluate; ' +
              '?since=<syncToken> answers 304 when nothing changed' },
      { method: 'POST', path: '/xacml/pep/heartbeat',
        what: 'what a remote PEP has enforced, and which repository it holds' }
    ],
    notYetHere: [
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
    '<h2>Remote enforcement points</h2>' +
    '<p>' + (info.remotePeps.enabled
      ? 'A Policy Enforcement Point in another process registers at ' +
        '<code>/xacml/pep/register</code>, <strong>pulls</strong> the ' +
        'enabled policies from <code>/xacml/pep/policies</code> and ' +
        'evaluates them itself with its own copy of this engine. ' +
        info.remotePeps.registered + ' registered. The repository&rsquo;s ' +
        'sync token is <code>' + xmlEscape(info.remotePeps.syncToken) +
        '</code>; pass it as <code>?since=</code> and an unchanged ' +
        'repository answers 304.'
      : 'Remote Policy Enforcement Points are <strong>off</strong> ' +
        '(<code>xacml.remotePeps</code>); those three endpoints answer 501.') +
    '</p>' +
    '<p>The pull <em>is</em> the contract. When the repository changes this ' +
    'service also POSTs a few bytes to each registered PEP that gave a ' +
    'notify URL, saying only that something changed &mdash; an optimisation ' +
    'over the polling interval and never a replacement for it, so a PEP ' +
    'that is never nudged still converges.</p>' +
    '<h2>Not here yet</h2><ul>' + later + '</ul>' +
    '<p><a href="?format=json">This document as JSON</a></p>' +
    '</body></html>');
  log.debug('Leaving GET /xacml. HTML.');
});

module.exports = { decide: decide, enforce: enforce, description: description,
                   enabled: enabled };
