'use strict';
//
// File: caep_initiating_entity.js
//
// ===========================================================================
// WHO ENDED THIS SESSION, AS THE EVENT REPORTS IT — AND THE BRANCH THAT WAS
// UNREACHABLE UNTIL 2026-09-04.
//
// CAEP section 2's `initiating_entity` exists to let a receiver tell "an
// ADMINISTRATOR revoked this" from "the person signed out" from "a policy
// decided" — three facts that call for three different responses and are
// indistinguishable without it.
//
// This service had the branch and could not reach it. `dropSession()` decides
// the value by testing the `via` it is given for `admin` or `console`, and
// EVERY door went through `logout.js`'s session family, which passed one
// hard-coded string: `the protocol-independent logout`. So a support desk
// ending somebody's session from /admin/logout, the Revoke button on
// /admin/sessions and the management API all emitted an event saying the
// PERSON had signed themselves out — wrong in the one direction that matters,
// with no symptom anywhere: the event is conforming, the value is a legal one,
// and only a receiver acting on it would ever notice.
//
// The second half is the SESSION EXPIRY, which until the same day emitted
// nothing at all and now emits `policy`. `system` would have been the easy
// wrong answer — that word is for a maintenance activity, and this is a
// lifetime this service configured running out, which is what a policy
// evaluation IS.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Seeing this over HTTP means agreeing a stream, driving a sign-out through
// each of four doors and reading the SET off the far end — which is a protocol
// test and belongs in the parent project's suite. What is asserted here is the
// CONTRACT BETWEEN THREE MODULES that the value rests on: `logout.js` carries
// the caller's own words, `authn.js` turns them into an entity, and `caep.js`
// honours an entity the notice states outright. Every one of those is a
// function call with no port, and the defect above lived precisely in the
// seam between them — each module was correct on its own.
//
// The EXPIRY half additionally cannot be driven over HTTP at all: the session
// lifetime is an hour, and nothing anywhere can shorten it from outside.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: nothing
// here should depend on a developer's exported appconfig.
delete process.env.CONFIG_FILE;

const authn = require('../authn/authn');
const caep = require('../ssf/caep');
const logout = require('../logout/logout');

// What the observer was told, without a transmitter behind it. The notice is
// what `caep.observe()` reads, so capturing it is capturing the whole input to
// the decision — and it keeps this file off streams, signing and delivery,
// none of which is what is being asserted.
function capture() {
  const seen = [];
  authn.setSessionObserver(function (notice) {
    seen.push(notice);
    return null;
  });
  return seen;
}

// A sign-in, without a response object: startSession() only ever calls
// `res.set()` and reads `res.req`.
function signIn(username, via) {
  return authn.startSession({ set: function () {}, req: null },
                            username, ['pwd'], '1', via || 'OAuth 2.0 / OIDC');
}

// The entity `caep.js` would put on the event for one notice. Asked of THAT
// module rather than recomputed here, because the mapping is the thing under
// test: a copy of the rule in this file would pass while the service was
// wrong.
function entityOf(notice) {
  const due = caep.observe(notice);
  if (!due) {
    return '(nothing was due)';
  }
  return String(due.payload.initiating_entity || '(absent)');
}

function run(t) {
  caep.clear();

  // -----------------------------------------------------------------------
  t.log.info('A. the door that ended it decides what the event says');
  // -----------------------------------------------------------------------
  const doors = [
    { by: 'the /logout endpoint', want: 'user',
      what: 'a person signing themselves out at /logout' },
    { by: 'the admin console at /admin/logout', want: 'admin',
      what: 'an operator ending somebody else\'s session' },
    { by: 'the /admin/sessions page', want: 'admin',
      what: 'the Revoke button on /admin/sessions' },
    { by: 'the management API at /admin-api/sessions', want: 'admin',
      what: 'POST /admin-api/sessions/revoke' }
  ];
  doors.forEach(function (door, n) {
    const seen = capture();
    const session = signIn('entity-' + n);
    // The sign-in's own notice is not what this is about.
    seen.length = 0;
    const result = logout.terminate('entity-' + n, ['session:' + session.id],
                                    { by: door.by });
    t.equal(result.terminated.length, 1,
            door.what + ' really ended the session');
    t.equal(seen.length, 1,
            'and told the observer exactly once');
    t.equal(entityOf(seen[0]), door.want,
            'initiating_entity is "' + door.want + '" for ' + door.what);
  });

  // -----------------------------------------------------------------------
  t.log.info('B. and the phrase that decides it is the same phrase the ' +
             'reason carries, so the two cannot disagree');
  // -----------------------------------------------------------------------
  const seenReason = capture();
  const reasonSession = signIn('entity-reason');
  seenReason.length = 0;
  logout.terminate('entity-reason', ['session:' + reasonSession.id],
                   { by: 'the admin console at /admin/logout' });
  const due = caep.observe(seenReason[0]);
  t.check(!!due && !!due.payload.reason_admin,
          'the event carries reason_admin');
  t.check(!!due && String((due.payload.reason_admin || {}).en || '')
            .indexOf('the admin console at /admin/logout') >= 0,
          'and it names the door in the SAME words the entity was read from',
          JSON.stringify((due.payload || {}).reason_admin));

  // -----------------------------------------------------------------------
  t.log.info('C. an expiry is neither a person nor an administrator');
  // -----------------------------------------------------------------------
  const seenExpiry = capture();
  const expiring = signIn('entity-expiry');
  seenExpiry.length = 0;
  // Make it run out and then look it up, which is one of the two lazy paths.
  // The sweep is the other and reaches the same function; a test that waited
  // thirty seconds for it would be a test nobody runs.
  expiring.expires = Date.now() - 1000;
  const found = authn.sessionOf({
    headers: { cookie: 'sts_mock_session=' + expiring.id } });
  t.equal(found, null, 'an expired session is not returned');
  t.equal(seenExpiry.length, 1,
          'and ending it told the observer, which it did not do at all ' +
          'before 2026-09-04');
  t.equal(entityOf(seenExpiry[0] || {}), 'policy',
          'initiating_entity is "policy" — not "user", which would say the ' +
          'person signed out, and not "system", which CAEP keeps for a ' +
          'maintenance activity');
  t.check((seenExpiry[0] || {}).expired === true,
          'the notice says it EXPIRED, which is what changes reason_user ' +
          'from "You have been signed out" to "Your session expired"');
  const expiryDue = caep.observe(seenExpiry[0] || {});
  t.check(!!expiryDue && String((expiryDue.payload.reason_user || {}).en || '')
            .indexOf('expired') >= 0,
          'and the sentence a receiver may show the person says so',
          JSON.stringify(((expiryDue || {}).payload || {}).reason_user));

  // -----------------------------------------------------------------------
  t.log.info('D. a notice that states no entity still gets the old rule, so ' +
             'a caller that has never heard of this behaves as it did');
  // -----------------------------------------------------------------------
  const plain = { kind: 'revoked', via: 'a sign-out endpoint',
    issuer: 'https://sts.example.com',
    session: { id: 'entity-plain', user: { sub: 'u-plain', username: 'plain' },
      acr: '1', amr: ['pwd'] } };
  t.equal(entityOf(plain), 'user',
          'no byAdmin and no initiatingEntity is still "user"');
  t.equal(entityOf(Object.assign({}, plain,
            { session: Object.assign({}, plain.session, { id: 'entity-p2' }),
              byAdmin: true })), 'admin',
          'and byAdmin alone is still "admin"');

  authn.setSessionObserver(function () { return null; });
}

module.exports = {
  name: 'caep_initiating_entity',
  describe: 'who ended a session, as the event reports it: the admin branch ' +
            'that was unreachable, and the expiry that is a policy',
  run: run
};
