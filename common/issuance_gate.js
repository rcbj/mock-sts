'use strict';
//
// File: issuance_gate.js
//
// ---------------------------------------------------------------------------
// THE ONE PLACE THIS SERVICE ASKS "MAY I ISSUE THIS?", AND THE REASON IT IS AN
// EMPTY SHELL.
//
// Every protocol family here ends in an issuance: an access token, an ID
// Token, a SAML assertion, a WS-Federation response, a WS-Trust token, a
// browser session. Since 2026-09-05 each of those asks this file first, and
// this file asks whoever filled the slot below — which is
// `xacml/xacml_role_pep.js`, an EMBEDDED POLICY ENFORCEMENT POINT that turns
// the question into a XACML request and puts it to the PDP.
//
// So the answer to "may this application be issued anything for this person"
// is a POLICY DECISION in this service, made by the same engine that answers
// `/xacml/pdp` for anybody else, against a policy an administrator can read,
// edit and test on the console. There is no second implementation of the rule
// and there is no `if` in an issuance site.
//
// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS AT ALL, RATHER THAN oauth2.js CALLING THE PEP.
//
// Rule 3e's test, and it fails both ways round, which is exactly when a slot
// is the answer:
//
//   * A require from an issuance site to `xacml/` would MOVE ROUTES. Nine
//     modules issue something and every one of them is required BEFORE
//     `xacml/xacml.js` at 23c — `authn` at 8, `oauth2` at 9, the two SAML
//     profiles at 10a and 10b. Requiring the XACML family from any of them
//     registers seven `/xacml` routes and five `/admin/xacml` pages at that
//     position instead, ahead of the management API's own, which is the
//     failure CLAUDE.md's require-order table exists to prevent.
//   * And it would CLOSE A CYCLE. `xacml_admin.js` requires
//     `admin-ui/admin.js`, which requires `oauth2.js`.
//
// A require in the other direction — the PEP reaching into `oauth2.js` — is
// not a candidate at all: the PEP would then have to know about nine callers.
//
// **SO THIS FILE REQUIRES ALMOST NOTHING AND MUST STAY THAT WAY.** `helpers`
// and `config`, both of which every module here already has. It is a LEAF, and
// a leaf can be required from position 7 without dragging anything with it.
//
// ---------------------------------------------------------------------------
// AN EMPTY SLOT MEANS ISSUE, AND THAT IS THE MOST IMPORTANT LINE HERE.
//
// A process that never loaded the XACML family — the parent project's
// in-process Kerberos jobs, `npm test`, any of the module tests that require
// two files and an app — has no decider installed, and every call answers
// `allowed`. The service is then exactly what it was before this existed: a
// smaller service, not a broken one, which is the same rule every other slot
// in this repository follows.
//
// It is the right default for a second reason that is about failure rather
// than about tests. This service exists to be exercised, and an authorization
// subsystem that could brick every protocol family by being half-loaded would
// be the worst possible thing to put in front of a mock. **Where enforcement
// must fail CLOSED it does so in the PEP, which knows whether somebody
// actually asked for a restriction** — see `xacml/xacml_role_pep.js`, which
// argues the one case that refuses on a missing policy and the one that does
// not. This file's job is to be absent-safe; it is not the file that decides
// what a restriction means.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');
const config = require('./config');

// The kinds of issuance a caller may ask about. They become the XACML
// `action-id` of the request, so this list is a VOCABULARY that policies are
// written against — adding one is adding a word a policy author can match on,
// and renaming one silently stops every policy that named the old word from
// matching, which is a policy that permits nothing rather than an error.
const ISSUANCE = {
  SESSION: 'start-session',
  ACCESS_TOKEN: 'issue-access-token',
  ID_TOKEN: 'issue-id-token',
  REFRESH_TOKEN: 'issue-refresh-token',
  AUTHORIZATION_CODE: 'issue-authorization-code',
  SAML_ASSERTION: 'issue-saml-assertion',
  WSFED_TOKEN: 'issue-wsfed-token',
  WSTRUST_TOKEN: 'issue-wstrust-token',
  KERBEROS_TICKET: 'issue-kerberos-ticket'
};

const KINDS = Object.keys(ISSUANCE).map(function (key) {
  return ISSUANCE[key];
});

let decider = null;

function setDecider(fn) {
  log.debug('Entering setDecider().');
  decider = typeof fn === 'function' ? fn : null;
  log.debug('Leaving setDecider(). Issuance is now ' +
            (decider ? 'decided by the embedded PEP.' : 'ungated.'));
}

// What is installed, for a test that stubs it — `xacml_store.js` argues why
// this is not pedantry, and it is the same one-process, one-reference
// situation here.
function deciderInstalled() {
  return decider;
}

// ---------------------------------------------------------------------------
// THE QUESTION.
//
// `request` is:
//   { application   the handle of the application something is being issued
//                   FOR — a client_id, a SAML entityID's slug, a wtrealm.
//                   ABSENT MEANS THERE IS NOTHING TO DECIDE ABOUT: this
//                   service issues nothing to nobody, so a call with no
//                   application is a caller that does not know who it is
//                   serving, and the honest answer is to allow rather than to
//                   invent a subject.
//     kind          one of ISSUANCE above.
//     subject       { kind, name, authenticated, groups } — the party being
//                   authenticated, which is a PERSON in a browser flow and the
//                   CLIENT ITSELF in a client_credentials grant. That is the
//                   whole of the "user or application" the requirement is
//                   about.
//     claims        the claims of a token the caller presented, if any, so
//                   that a roles claim in it can be read back.
//     realm         for the log line only; the decision runs in the ambient
//                   realm like everything else. }
//
// The answer is `{ allowed, decision, why, roles, required, policy }` — the
// XACML decision and the reason, kept apart on purpose: `allowed` is what an
// issuance site branches on and everything else is what it puts in a log, an
// error description or an audit record.
//
// IT NEVER THROWS AND NEVER RETURNS A PROMISE. Nine issuance sites call it,
// several of them inside code paths this service has always run
// synchronously, and an authorization check that could make a token endpoint
// asynchronous would be a change to nine protocol implementations rather than
// to one file.
// ---------------------------------------------------------------------------
function check(request) {
  log.debug('Entering check(). kind=' + (request || {}).kind);
  const asked = request || {};
  if (!decider) {
    log.debug('Leaving check(). No decider is installed, so nothing is gated.');
    return allow('The XACML role subsystem is not loaded in this process, ' +
                 'so issuance is not gated.');
  }
  if (config.value('roles.enforceIssuance') === false) {
    log.debug('Leaving check(). Enforcement is switched off.');
    return allow('roles.enforceIssuance is off, so the decision was not ' +
                 'asked for.');
  }
  if (!asked.application) {
    log.debug('Leaving check(). No application to decide about.');
    return allow('Nothing named an application, so there is no requirement ' +
                 'to check.');
  }
  let answer;
  try {
    answer = decider(asked);
  } catch (error) {
    // THE ONE PLACE THIS FAILS OPEN ON AN ERROR, and it is deliberate and
    // narrow. A THROW here is a defect in the PEP or the engine — not a Deny,
    // not an Indeterminate, both of which the PEP returns as ordinary answers.
    // A mock whose every protocol family stopped issuing because a policy
    // module threw would be unusable and, worse, unfixable: the console that
    // would let somebody correct the policy is reached through a session this
    // service would then refuse to mint.
    log.error('issuance_gate: the decider threw and issuance was ALLOWED; ' +
              'this is a defect in the embedded PEP rather than a decision. ' +
              error.message);
    return allow('The embedded PEP threw, which is a defect rather than a ' +
                 'decision: ' + error.message);
  }
  const result = answer || allow('The embedded PEP answered nothing.');
  log.debug('Leaving check(). ' + (result.allowed ? 'Allowed.' : 'REFUSED: ' +
            result.why));
  return result;
}

function allow(why) {
  return { allowed: true, decision: 'NotApplicable', why: why,
           roles: [], required: [], policy: null };
}

module.exports = {
  ISSUANCE: ISSUANCE,
  KINDS: KINDS,
  setDecider: setDecider,
  deciderInstalled: deciderInstalled,
  check: check
};
