'use strict';
//
// File: caep_presented_every_protocol.js
//
// ===========================================================================
// SINGLE SIGN-ON IS AN ACT OF THE SESSION AND NOT OF THE PROTOCOL, AND FOR
// THREE OF THE FOUR BROWSER SSO PROFILES HERE IT USED TO BE SILENT.
//
// CAEP is a vocabulary about SESSIONS. Nothing in `session-presented` names
// OAuth 2.0 or OpenID Connect — the event says an existing session was
// presented and honoured without a new authentication, which is exactly what
// happens when a browser that already holds `sts_mock_session` arrives at the
// SAML 2.0 SSO endpoint, the SAML 1.1 inter-site transfer service or the
// WS-Federation passive requestor endpoint.
//
// `session-established` and `session-revoked` were protocol-independent from
// the day CAEP landed, because both go through the ONE funnel:
// `authn.startSession()` and `authn.dropSession()`. `session-presented` did
// not, because there is no funnel for it — a presentation is a thing each
// protocol endpoint decides it is doing, and only `oauth-oidc/oauth2.js`
// called `notePresented()`. So a receiver watching a stream saw a SAML session
// start and end with every single sign-on between the two missing, and the
// evidence of the gap was a count of zero, which in this protocol is also what
// "nobody asked for that type" looks like.
//
// **WHY THIS TEST IS IN PROCESS AND NOT OVER HTTP.** The presentation itself
// is one line in three route handlers, and driving it needs a browser session,
// a stream and three protocol round trips — which is the parent project's
// `tests/caep_protocol.js` and belongs there. What can be settled here, in
// milliseconds and with no port, is the pair of contracts that line rests on:
// that `notePresented()` is protocol-independent (section A), and that every
// module which answers a request out of an existing session actually calls it
// (section B). B is a SOURCE check and it is the one that would catch the
// regression, because the fifth browser SSO profile somebody adds will have
// the same hole and nothing else in either suite is looking for it.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const authn = require('../authn/authn');

// The four browser SSO profiles: a module, and the identifier it passes as
// `via` so the event says which door the session came back through. A profile
// added here without a `notePresented()` fails section B by name.
const PROFILES = [
  { file: '../oauth-oidc/oauth2.js', via: 'OAuth 2.0 / OIDC' },
  { file: '../saml/saml2_sso.js', via: 'SAML 2.0' },
  { file: '../saml/saml11_sso.js', via: 'SAML 1.1' },
  { file: '../ws-federation/wsfed.js', via: 'WS-Federation' }
];

// A session in the shape `startSession()` leaves one, INCLUDING the flag that
// makes the sign-in's own return trip free. Spelling it out rather than
// calling startSession() keeps this test off `res` and the cookie.
function sessionAfterSignIn(id) {
  return { id: id, user: { sub: 'urn:sts-mock:user:tester',
    username: 'tester' }, acr: '1', amr: ['pwd'],
    firstPresentationIsTheSignIn: true };
}

function run(t) {
  // -----------------------------------------------------------------------
  t.log.info('A. notePresented() is about the SESSION, so it behaves the ' +
             'same whichever protocol presents one');
  // -----------------------------------------------------------------------
  const seen = [];
  authn.setSessionObserver(function (notice) {
    seen.push(notice);
  });

  // The sign-in's own return trip, once per protocol. Every one of these is a
  // browser coming back to the endpoint it was sent away from, and reporting
  // it would mean `session-established` and `session-presented` arriving
  // milliseconds apart on every flow — after which the event that is supposed
  // to mean SINGLE SIGN-ON HAPPENED would mean nothing.
  PROFILES.forEach(function (profile) {
    const session = sessionAfterSignIn('sess-' + profile.via);
    const reported = authn.notePresented(session, profile.via, null);
    t.equal(reported, false,
            'a brand-new session presented at ' + profile.via + ' is the ' +
            "sign-in's own return trip and is NOT reported");
  });
  t.equal(seen.length, 0,
          'so nothing at all went to the observer — the flag is spent by ' +
          'the protocol that set it, whichever one that was');

  // The same sessions, presented a second time. THIS is single sign-on.
  const carried = PROFILES.map(function (profile) {
    const session = sessionAfterSignIn('sso-' + profile.via);
    authn.notePresented(session, profile.via, null);
    seen.length = 0;
    const reported = authn.notePresented(session, profile.via, null);
    t.equal(reported, true,
            'presenting that session AGAIN at ' + profile.via + ' is single ' +
            'sign-on and IS reported');
    return seen[0] || {};
  });
  carried.forEach(function (notice, i) {
    t.equal(notice.kind, 'presented',
            'the observer is told "presented" for ' + PROFILES[i].via);
    t.equal(notice.via, PROFILES[i].via,
            'and carries the protocol, which is what puts "' +
            PROFILES[i].via + '" in reason_admin and in the register\'s row');
  });

  // A session signed in at one door and presented at ANOTHER is single sign-on
  // in the plainest sense, and it is the case a per-protocol flag would get
  // wrong. The flag lives on the session, so the sign-in spends it once and
  // every later door reports.
  const shared = sessionAfterSignIn('sess-crossed');
  authn.notePresented(shared, 'OAuth 2.0 / OIDC', null);
  seen.length = 0;
  t.equal(authn.notePresented(shared, 'SAML 2.0', null), true,
          'a session signed in over OIDC and presented at the SAML 2.0 ' +
          'endpoint reports — one session, two protocols, and the second ' +
          'arrival is the single sign-on this event exists to name');
  t.equal((seen[0] || {}).via, 'SAML 2.0',
          'named by the door it came back through and not by the one it was ' +
          'made at');

  authn.setSessionObserver(function () {
    return null;
  });

  // -----------------------------------------------------------------------
  t.log.info('B. every browser SSO profile CALLS it, which is the half that ' +
             'was missing and the half a module test cannot infer');
  // -----------------------------------------------------------------------
  PROFILES.forEach(function (profile) {
    const file = path.join(__dirname, profile.file);
    const src = fs.readFileSync(file, 'utf8');
    const name = path.basename(file);
    // IN SCOPE, in either of the two shapes this tree uses: the three SAML
    // and WS-Federation modules destructure the name out of the require, and
    // `oauth2.js` keeps the namespace and calls `authn.notePresented()`.
    // Accepting only one of them would fail a module that is correct.
    t.check(/notePresented\s*[,}]/.test(src) ||
            /\.\s*notePresented\s*\(/.test(src),
            name + ' has notePresented in scope — destructured from ' +
            'authn.js, or called through the namespace');
    t.check(/notePresented\(\s*session/.test(src),
            name + ' CALLS notePresented(session, …) — without it every ' +
            'single sign-on over this protocol is silent, and the only ' +
            'evidence is a count of zero, which is also what "no stream ' +
            'asked for that type" looks like');
    // The `via` it passes is the string the rest of this service already uses
    // for that protocol. A second spelling would split one protocol into two
    // rows on /admin/caep-sessions and two sentences in reason_admin.
    t.check(src.indexOf("notePresented(session, '" + profile.via + "'") >= 0,
            name + " names the protocol as '" + profile.via + "', the same " +
            'spelling it hands startSession() and recordServiceProvider()');
  });
}

module.exports = {
  name: 'caep_presented_every_protocol',
  describe: 'single sign-on is an act of the session, so every browser SSO ' +
            'profile reports session-presented and not just the OIDC one',
  run: run
};
