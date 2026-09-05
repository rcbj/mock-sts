'use strict';
//
// File: xacml-pep/pep.js
//
// ===========================================================================
// A REMOTE POLICY ENFORCEMENT POINT. PHASE FIVE.
//
// This is a whole separate process. It holds its own copy of the XACML engine
// (`engine.js`), PULLS the policy repository from the mock's PDP (`sync.js`)
// and ENFORCES it here — which is the point of the exercise, because a PEP
// that asked the PDP per request would be `POST /xacml/pdp` with a network hop
// in front of every access decision, and pushing POLICIES to something that
// could not evaluate them would make no sense at all.
//
// Four endpoints:
//
//   GET  /              what this PEP is, what it holds, what it has enforced
//   GET  /protected     THE RESOURCE. 200 or 403, decided here
//   POST /notify        the PDP's nudge: pull now
//   GET  /healthcheck   liveness, for the container
//
// ---------------------------------------------------------------------------
// WHAT MAKES THIS DIFFERENT FROM THE MOCK'S EMBEDDED PEP AT /xacml/protected.
//
// The embedded one shares a process with the PDP, so it can never disagree
// with it and can never be stale — which makes it a fine demonstration of
// section 7.2 and a useless demonstration of everything a distributed
// deployment is actually hard about. This one can be stale, can hold a policy
// the PDP no longer has, can refuse a document the PDP accepted, and can be
// unreachable while still enforcing. Every one of those is a real state that
// this container makes reachable and reports rather than hides:
//
//   * `GET /` says whether the copy is stale and how long since a successful
//     pull;
//   * the PDP's `/admin/xacml/peps` says the same thing from the other side,
//     which is the interesting half — those two answers can DISAGREE, and a
//     deployment where they do is one nobody could have debugged from either
//     end alone.
//
// ---------------------------------------------------------------------------
// THE ENFORCEMENT RULE IS THE MOCK'S, RESTATED RATHER THAN IMPORTED.
//
// `xacml.js`'s `enforce()` is fifty lines and it is not in `engine.js`'s copy
// list, deliberately. It is the PEP's own decision — the bias and the
// obligation rule — and a PEP that imported the PDP's enforcement would be
// demonstrating that two processes agree because they are one program, which
// is the thing `tests/sts_dpop.js` refuses to do when it writes its own DPoP
// client. Written out here, this PEP can be configured with a DIFFERENT bias
// from the mock's embedded one, and the two then disagree about exactly the
// answers the two biases disagree about — which is the demonstration worth
// having.
//
// The rule, both halves:
//
//   1. THE BIAS decides what a non-Permit means. Deny-biased: only Permit
//      allows. Permit-biased: only Deny refuses. They agree on Permit and Deny
//      and differ on Indeterminate and NotApplicable — the two nobody tests.
//   2. AN OBLIGATION THAT CANNOT BE DISCHARGED TURNS A PERMIT INTO A REFUSAL
//      (section 7.2). This PEP can discharge exactly one obligation and
//      refuses on any other, loudly. Allowing the access and dropping the
//      obligation would enforce half a policy and report success.
// ===========================================================================

const http = require('http');
const fs = require('fs');
const { URL } = require('url');
const engine = require('./engine');
const sync = require('./sync');

const log = engine.log;
const model = engine.model;

const VERSION = 'mock-sts xacml-pep, phase five';

// ---------------------------------------------------------------------------
// CONFIGURATION, ALL OF IT FROM THE ENVIRONMENT.
//
// No appconfig file and no settings table, and that is not a shortcut: this
// container is one component with a dozen knobs, and the mock's five-layer
// configuration exists to serve a console that can change a setting while the
// service runs. A PEP has no console.
// ---------------------------------------------------------------------------
function intFromEnv(name, dflt) {
  const raw = process.env[name];
  const n = raw === undefined ? NaN : parseInt(raw, 10);
  return isNaN(n) ? dflt : n;
}

function fileFromEnv(name) {
  const path = process.env[name];
  if (!path) {
    return null;
  }
  try {
    return fs.readFileSync(path);
  } catch (error) {
    // NAMED AND FATAL-ADJACENT rather than swallowed: a PEP configured with a
    // certificate path it cannot read would otherwise start, register
    // unauthenticated, and leave somebody looking at the PDP's console
    // wondering why the row says it proved nothing.
    log.error('xacml-pep: ' + name + ' names ' + path + ' and it could not ' +
              'be read (' + error.message + '). Carrying on WITHOUT it, ' +
              'which means this PEP registers unauthenticated if the PDP ' +
              'allows that and is refused if it does not.');
    return null;
  }
}

const options = {
  pdpUrl: process.env.PEP_PDP_URL || 'https://localhost:8081',
  name: process.env.PEP_NAME || 'pep-1',
  notifyUrl: process.env.PEP_NOTIFY_URL || '',
  resource: process.env.PEP_RESOURCE || '',
  version: VERSION,
  description: process.env.PEP_DESCRIPTION ||
    'A remote XACML Policy Enforcement Point holding its own copy of the ' +
    'engine and pulling this repository.',
  bias: process.env.PEP_BIAS === 'permit-biased' ? 'permit-biased'
                                                 : 'deny-biased',
  port: intFromEnv('PEP_PORT', 9090),
  pollIntervalMs: intFromEnv('PEP_POLL_INTERVAL_MS', 15000),
  heartbeatIntervalMs: intFromEnv('PEP_HEARTBEAT_INTERVAL_MS', 60000),
  timeoutMs: intFromEnv('PEP_TIMEOUT_MS', 5000),
  maxBodyBytes: intFromEnv('PEP_MAX_BODY_BYTES', 4 * 1024 * 1024),
  clientCertificate: fileFromEnv('PEP_TLS_CERT'),
  clientKey: fileFromEnv('PEP_TLS_KEY'),
  pdpCa: fileFromEnv('PEP_TLS_CA'),
  insecure: process.env.PEP_TLS_INSECURE === 'true'
};

function send(res, status, body) {
  const text = JSON.stringify(body, null, 2);
  res.writeHead(status, { 'Content-Type': 'application/json',
                          'Cache-Control': 'no-store',
                          'Content-Length': Buffer.byteLength(text) });
  res.end(text);
}

// ---------------------------------------------------------------------------
// WHAT THIS PEP DOES WITH A DECISION. See the header — the mock's rule,
// restated rather than imported.
// ---------------------------------------------------------------------------
const DISCHARGEABLE = ['urn:sts-mock:xacml:obligation:log'];

function enforce(answer) {
  log.debug('Entering enforce(). decision=' + answer.decision);
  const discharged = [];
  const undischargeable = [];
  (answer.obligations || []).forEach(function (obligation) {
    if (DISCHARGEABLE.indexOf(obligation.id) >= 0) {
      log.info('xacml-pep: discharging obligation ' + obligation.id +
               ' with ' + (obligation.assignments || []).length +
               ' assignment(s).');
      discharged.push(obligation.id);
      return;
    }
    undischargeable.push(obligation.id);
  });
  const permitted = answer.decision === model.DECISION.PERMIT;
  const denied = answer.decision === model.DECISION.DENY;
  let allowed = options.bias === 'deny-biased' ? permitted : !denied;
  let why;
  if (options.bias === 'deny-biased') {
    why = permitted ? 'The PDP policy said Permit.'
      : 'The policy said ' + answer.decision + ', and this PEP is ' +
        'deny-biased, so anything that is not Permit is a refusal.';
  } else {
    why = denied ? 'The policy said Deny.'
      : 'The policy said ' + answer.decision + ', and this PEP is ' +
        'permit-biased, so anything that is not Deny is allowed.';
  }
  if (allowed && undischargeable.length) {
    allowed = false;
    why = 'The policy said ' + answer.decision + ', but the decision carries ' +
          (undischargeable.length === 1 ? 'an obligation' : 'obligations') +
          ' this PEP cannot discharge (' + undischargeable.join(', ') +
          '). Section 7.2: a PEP that cannot fulfil an obligation MUST NOT ' +
          'grant the access. Allowing it and dropping the obligation would ' +
          'enforce half a policy and report success.';
  }
  log.debug('Leaving enforce(). ' + (allowed ? 'Allowed.' : 'Refused.'));
  return { allowed: allowed, bias: options.bias, why: why,
           discharged: discharged, undischargeable: undischargeable };
}

// ---------------------------------------------------------------------------
// A DECISION, HERE, WITH WHAT WAS PULLED.
//
// THERE IS NO PIP. Every attribute a policy asks about has to be in the
// request, and one that is not produces an empty bag — which is a perfectly
// ordinary XACML result rather than an error. That is not a gap in this
// container: a real PEP knows who the caller is and generally nothing else
// about them, and the mock's PIP reads a person's entry in an embedded
// directory this process cannot see and should not have.
//
// So a policy that decides on `employeeType` decides here only if the caller
// asserts one. `GET /protected?employeeType=staff` is how this container lets
// somebody see that, and it is honest about what it means: an attribute the
// SUBJECT asserted about itself, which no real deployment would believe and
// which is exactly the sort of thing a mock exists to let you try.
// ---------------------------------------------------------------------------
function decide(query) {
  log.debug('Entering decide().');
  const holding = sync.current();
  if (!holding.loaded) {
    log.debug('Leaving decide(). Nothing is held.');
    return { decision: model.DECISION.NOT_APPLICABLE,
             status: { code: model.STATUS.OK },
             obligations: [], advice: [], policyIdentifiers: [],
             note: 'This PEP holds no root policy — it has never pulled one ' +
                   'successfully, or what it pulled had no root. There is ' +
                   'nothing to evaluate, so the decision is NotApplicable ' +
                   'and the bias below is what actually decided.' };
  }
  const subject = String(query.subject || '');
  const resource = String(query.resource || options.resource ||
                          'urn:xacml-pep:protected');
  const action = String(query.action || 'GET');
  const subjectAttributes = subject
    ? [{ attributeId: model.ATTRIBUTE.SUBJECT_ID, issuer: null,
         includeInResult: true,
         values: [{ type: model.TYPE.STRING, lexical: subject }] }]
    : [];
  // EVERY OTHER QUERY PARAMETER BECOMES A SUBJECT ATTRIBUTE, ASSERTED UNDER
  // BOTH SPELLINGS — the bare name and the mock's own
  // `urn:sts-mock:xacml:attribute:` form.
  //
  // **THAT IS NOT BELT AND BRACES; IT IS WHAT MAKES THE CONTRACT TRUE.** The
  // mock's `xacml_pip.js` answers BOTH spellings from ONE directory attribute
  // — a designator for `employeeType` and one for
  // `urn:sts-mock:xacml:attribute:employeeType` both read the same entry — so
  // a policy author over there may legitimately write either and the PDP
  // decides identically. A remote PEP that asserted only one of them would
  // decide differently from the PDP for every policy that happened to use the
  // other, which is precisely the disagreement this whole phase exists to
  // make impossible. It cost a run to find: the seeded RBAC policy names
  // `employeeType` bare, this container asserted only the prefixed form, and
  // every request was denied by a policy that was working perfectly.
  //
  // The prefix is a literal here rather than imported from `xacml_pip.js`,
  // because that module is not in `engine.js`'s copy list and pulling it in
  // for one string would bring the mock's directory reader into a process
  // that has no directory.
  const PIP_PREFIX = 'urn:sts-mock:xacml:attribute:';
  Object.keys(query).forEach(function (key) {
    if (key === 'subject' || key === 'resource' || key === 'action') {
      return;
    }
    const values = [{ type: model.TYPE.STRING, lexical: String(query[key]) }];
    subjectAttributes.push({ attributeId: key, issuer: null,
                             includeInResult: true, values: values });
    subjectAttributes.push({ attributeId: PIP_PREFIX + key, issuer: null,
                             includeInResult: true, values: values });
  });
  const request = {
    returnPolicyIdList: true,
    combinedDecision: false,
    categories: [
      { category: model.CATEGORY.ACCESS_SUBJECT, id: null, content: null,
        attributes: subjectAttributes },
      { category: model.CATEGORY.RESOURCE, id: null, content: null,
        attributes: [{ attributeId: model.ATTRIBUTE.RESOURCE_ID, issuer: null,
                       includeInResult: true,
                       values: [{ type: model.TYPE.ANYURI,
                                  lexical: resource }] }] },
      { category: model.CATEGORY.ACTION, id: null, content: null,
        attributes: [{ attributeId: model.ATTRIBUTE.ACTION_ID, issuer: null,
                       includeInResult: true,
                       values: [{ type: model.TYPE.STRING,
                                  lexical: action }] }] },
      { category: model.CATEGORY.ENVIRONMENT, id: null, content: null,
        attributes: [] }
    ]
  };
  const answer = engine.pdp.evaluate(holding.root, request, {
    repository: holding.repository
    // NO `resolver`. There is no PIP here — see the block comment above.
  });
  log.debug('Leaving decide(). ' + answer.decision);
  return answer;
}

// ---------------------------------------------------------------------------
// THE ROUTES. Node's own http and no framework: this container's whole surface
// is four endpoints and none of them takes a form, so express would be a
// dependency to describe four `if`s.
// ---------------------------------------------------------------------------
function overview() {
  const s = sync.state();
  const staleAfterMs = options.pollIntervalMs * 3;
  const lastPull = s.held.lastPullAt ? Date.parse(s.held.lastPullAt) : NaN;
  const stale = !(lastPull > 0) || (Date.now() - lastPull) > staleAfterMs;
  return {
    what: 'A REMOTE XACML Policy Enforcement Point. It holds its own copy of ' +
          'the engine, PULLS the policy repository from the PDP below, and ' +
          'decides here. The PDP saw none of the decisions counted on this ' +
          'page, which is what a remote PEP is.',
    version: VERSION,
    pdp: options.pdpUrl,
    bias: options.bias,
    protectedAt: '/protected',
    holding: s.held,
    // COMPUTED HERE AND SEPARATELY FROM THE PDP'S OWN VERDICT, on purpose.
    // The PDP calls this PEP stale after `xacml.pepStaleAfterS` without a
    // heartbeat; this PEP calls itself stale after three missed polls. The two
    // measure different things and CAN DISAGREE — a PEP that is pulling
    // happily while its heartbeats are being dropped looks fine here and
    // stale there, which is a real and confusing deployment state that is far
    // easier to recognise when both numbers are visible.
    stale: stale,
    staleAfterMs: staleAfterMs,
    registration: s.registration,
    enforced: s.counters,
    notify: options.notifyUrl || null,
    poll: { intervalMs: options.pollIntervalMs,
            heartbeatMs: options.heartbeatIntervalMs },
    contract: 'THE PULL IS THE CONTRACT. This PEP polls the PDP on its own ' +
              'interval and converges whether or not a nudge ever arrives. ' +
              'A PDP that is unreachable leaves this PEP enforcing what it ' +
              'last pulled rather than denying everything — which is a ' +
              'deliberate trade, and it means a policy change made during an ' +
              'outage is not enforced here until the next successful pull.',
    noPip: 'There is no Policy Information Point here. Every attribute a ' +
           'policy asks about must be IN the request, and one that is not ' +
           'produces an empty bag. Pass extra query parameters to ' +
           '/protected and each becomes a subject attribute under ' +
           'urn:sts-mock:xacml:attribute: — asserted by the caller about ' +
           'itself, which no real deployment would believe and which is ' +
           'exactly what a mock is for.'
  };
}

function protectedResource(query) {
  const answer = decide(query);
  const outcome = enforce(answer);
  sync.countDecision(outcome);
  const body = {
    decision: answer.decision,
    allowed: outcome.allowed,
    bias: outcome.bias,
    why: outcome.why,
    status: answer.status,
    obligations: (answer.obligations || []).map(function (one) {
      return { id: one.id, discharged: outcome.discharged.indexOf(one.id) >= 0 };
    }),
    advice: (answer.advice || []).map(function (one) {
      return one.id;
    }),
    applicablePolicies: answer.policyIdentifiers || [],
    decidedBy: { pep: options.name,
                 syncToken: sync.state().held.syncToken,
                 note: 'Decided IN THIS PROCESS, against the policy this PEP ' +
                       'last pulled. The PDP did not see this request.' }
  };
  if (answer.note) {
    body.note = answer.note;
  }
  return { status: outcome.allowed ? 200 : 403, body: body };
}

const server = http.createServer(function (req, res) {
  let parsed;
  try {
    parsed = new URL(req.url, 'http://localhost');
  } catch (error) {
    // A URL node itself will not parse cannot name any of four fixed paths,
    // so there is nothing to route it to.
    send(res, 400, { error: 'that is not a request URL' });
    return;
  }
  const path = parsed.pathname;
  const query = {};
  parsed.searchParams.forEach(function (value, key) {
    query[key] = value;
  });

  if (req.method === 'GET' && path === '/healthcheck') {
    // LIVENESS ONLY, AND IT DOES NOT ASK WHETHER THE POLICY IS CURRENT. A PEP
    // holding a stale copy is working — it is enforcing, and it is saying so
    // on `GET /`. A healthcheck that failed on staleness would make a
    // container restart loop out of a PDP outage, which would turn a
    // recoverable problem into an outage of its own.
    send(res, 200, { message: 'Success' });
    return;
  }
  if (req.method === 'GET' && (path === '/' || path === '')) {
    send(res, 200, overview());
    return;
  }
  if (req.method === 'GET' && path === '/protected') {
    const answer = protectedResource(query);
    send(res, answer.status, answer.body);
    return;
  }
  if (req.method === 'POST' && path === '/notify') {
    // THE NUDGE. Answered 204 IMMEDIATELY and the pull happens after, which
    // matters: the PDP times this request out in two seconds by default and
    // holding it open for the length of a pull would make a slow pull look
    // like an unreachable PEP on somebody's console.
    //
    // THE BODY IS NOT READ AND NOTHING IN IT IS TRUSTED. A nudge says only
    // that something changed; what actually changed is discovered by pulling
    // from the PDP over this PEP's own configured URL. A nudge that could tell
    // this PEP what the policy now is, or where to fetch it, would be an
    // unauthenticated caller supplying policy — and the whole reason a nudge
    // is affordable is that it carries nothing.
    req.resume();
    send(res, 204, {});
    log.info('xacml-pep: nudged by the PDP; pulling now rather than waiting ' +
             'up to ' + options.pollIntervalMs + 'ms for the next poll. ' +
             'Nothing in the nudge was read — what changed is discovered by ' +
             'pulling.');
    sync.pull(options).catch(function (error) {
      log.warn('xacml-pep: the nudged pull failed: ' + error.message +
               '. The scheduled poll will try again.');
    });
    return;
  }
  send(res, 404, {
    error: 'not_found',
    error_description: 'This PEP answers GET /, GET /protected, ' +
                       'POST /notify and GET /healthcheck.'
  });
});

async function start() {
  log.info('xacml-pep: starting. PDP=' + options.pdpUrl + ' name=' +
           options.name + ' bias=' + options.bias);
  if (options.insecure) {
    // ON EVERY START rather than once somewhere, for `federation_http.js`'s
    // reason about insecure requests: a certificate check turned off months
    // ago and forgotten is the worst kind of leftover.
    log.warn('xacml-pep: PEP_TLS_INSECURE is on, so this PEP does NOT verify ' +
             'the PDP\'s certificate. That is the ordinary setting against ' +
             'the mock — it regenerates its key on every start and signs it ' +
             'itself, so there is no anchor to verify against — and it is ' +
             'the wrong setting against anything else.');
  }
  if (!options.clientCertificate) {
    log.warn('xacml-pep: no PEP_TLS_CERT, so this PEP registers with no ' +
             'client certificate. The PDP refuses that unless ' +
             'xacml.pepRequireCertificate is off. IT DOES NOT AFFECT ' +
             'ENFORCEMENT: pulling policy needs no credential and this PEP ' +
             'decides either way.');
  }
  // REGISTER FIRST, PULL REGARDLESS. `await`ed rather than fired and
  // forgotten so that the first `GET /` after start reports a settled
  // registration rather than "not attempted yet" — but its result is not
  // checked, because a refused registration must not stop anything.
  await sync.register(options);
  await sync.pull(options);

  setInterval(function () {
    sync.pull(options).catch(function (error) {
      log.warn('xacml-pep: the scheduled pull threw: ' + error.message);
    });
  }, options.pollIntervalMs).unref();

  setInterval(function () {
    sync.heartbeat(options).then(function (result) {
      // A PDP THAT SAYS THIS COPY IS BEHIND GETS A PULL IMMEDIATELY. It is the
      // second path to convergence after the nudge and the poll, and it costs
      // one comparison on a beat that was happening anyway.
      if (result.ok && result.current === false) {
        return sync.pull(options);
      }
      return null;
    }).catch(function (error) {
      log.warn('xacml-pep: the heartbeat threw: ' + error.message);
    });
  }, options.heartbeatIntervalMs).unref();

  server.listen(options.port, function () {
    log.info('xacml-pep: listening on ' + options.port +
             '. The protected resource is GET /protected.');
  });
}

// Guarded so that `tests/xacml_pep.js` can require this file for `enforce()`
// and `decide()` without starting a listener or a timer — the same guard
// `common/worker.js` carries, for the same reason.
if (require.main === module) {
  start().catch(function (error) {
    log.error('xacml-pep: could not start: ' +
              (error && error.stack ? error.stack : error));
    process.exit(1);
  });
}

module.exports = { enforce: enforce, decide: decide, overview: overview,
                   protectedResource: protectedResource, options: options,
                   server: server, start: start };
