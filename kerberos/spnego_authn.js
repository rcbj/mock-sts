'use strict';
//
// File: spnego_authn.js
//
// ---------------------------------------------------------------------------
// SPNEGO AS A WAY OF SIGNING IN — Kerberos, over HTTP, producing the SESSION
// that every protocol family in this service reads.
//
// `/spnego/protected` next door has authenticated people since the day it was
// written, and then thrown the identity away: it prints a table saying who the
// ticket named and stops. This module is the same handshake with the last step
// added. Past it, a person who holds a Kerberos ticket has a browser session
// here, and `/oauth2/authorize`, `/wsfed`, `/saml2/sso`, `/saml11/sso`,
// `/federation` and `/admin` all see it — because they all read the one session
// `authn.js` owns and none of them is told how it was established.
//
// **IT IS AVAILABLE TO EVERY APPLICATION AND NOTHING HAS TO BE CONFIGURED FOR
// IT.** There are three ways in and they are three different amounts of
// configuration, which is the same ladder federation already has:
//
//   1. A BUTTON ON THE SIGN-IN SCREEN, offered to every application that ever
//      reaches it (`krb5.spnegoLoginButton`). Nothing is registered, nothing
//      is named: whatever flow is in progress carries on afterwards, because
//      the button hands this door the pending record the screen was drawn
//      from.
//   2. `appAuthnMechanism: spnego` ON THE APPLICATION ENTRY, which is home
//      realm discovery by configuration — that application's people never see
//      the screen at all.
//   3. `fedAuthnMechanism: spnego` ON AN IDENTITY-PROVIDER-SIDE FEDERATION
//      RELATIONSHIP, which answers a different question: when THAT partner
//      asks this service to authenticate somebody, integrated Kerberos is
//      what happens. A SAML 2.0 partner satisfied by a Kerberos ticket, with
//      the partner never learning it.
//
// All three land here, and all three arrive the same way: with an `?authn=`
// naming a pending record `authn.js` minted. See the endpoint below.
//
// ---------------------------------------------------------------------------
// WHY THIS IS A DOOR OF ITS OWN AND NOT A BRANCH INSIDE `authn.js`.
//
// Because of the require order, and it is a dependency rather than a
// preference. `authn.js` is #8 — before `oauth2.js`, which reads the session it
// owns — and every Kerberos module is at #15 and below, because the KDC's
// listeners and the acceptor's socket must not be dragged to the front of the
// router by something the authorization endpoint depends on. A require from
// `authn.js` to this file would do exactly that, and would close a cycle
// besides, since this file requires `authn.js` for `startSession()`.
//
// **AND IT NEEDED NO INVERTED HOOK EITHER**, which is worth saying because rule
// 3e's list is six slots long and a seventh is the obvious move. It is not
// needed here: the only two things `authn.js` has to know are the PATH and
// whether the door is open. The path is `/authn/spnego` — a path in the space
// that module already owns, so it declares the constant and this file imports
// it — and whether the door is open is `krb5.spnegoAuthentication`, a setting
// both files read from `config.js`. A slot costs a reader an indirection every
// time, and rule 3e's own test is whether a require would close a cycle or move
// a route. Here nothing has to point anywhere: two files read one constant and
// one setting.
//
// ---------------------------------------------------------------------------
// WHAT IS CHECKED, AND WHY THAT IS NOT THE INTERESTING SENTENCE.
//
// Everything `krb5_service.js` checks, which is nine things and includes the
// replay cache — so a captured AP-REQ cannot be replayed into a second session.
// Not one line of that is here, and not one line of RFC 4178 is here either:
// `spnego_exchange.js` performs the negotiation and this module renders and
// signs in. That split exists precisely so that the sign-in and the page
// documenting it cannot come to disagree about what was checked.
//
// **THE INTERESTING SENTENCE IS THE OTHER ONE.** This service checks no
// password anywhere — the username typed at `/authn/login` IS the identity —
// and Kerberos is the one family where that is impossible, because the password
// there IS the key. So a session minted here is the ONLY kind in this service
// that rests on a credential the service genuinely verified. `krb5_principals.js`
// makes the KDC as permissive as the protocol allows (one password shared by
// every user account, an account created for any name on first sight), which
// keeps the mock a mock — but the verification is real, and the difference
// between "any name is accepted" and "any name is accepted once it has been to
// the KDC" is the whole of what this door adds.
//
// ---------------------------------------------------------------------------
// TRUST REALMS: THIS DOOR IS PER REALM AND THE KDC BEHIND IT IS NOT.
//
// `/realm/acme/authn/spnego` mints a session in `acme` — the ambient-realm
// middleware strips the prefix before the router sees the URL, and
// `startSession()` writes into whichever realm's partition is ambient, so this
// module needed no realm code at all and has none. A session minted in `acme`
// does not satisfy the default realm's `/oauth2/authorize`, exactly as every
// other sign-in here behaves.
//
// **What is NOT per realm is the KDC**, which is one of the three socket
// families `realmSupport()` reports as shared: a raw TCP socket on 88 has no
// path to put a realm segment in and no name inside the protocol to put one in
// either. So every realm here trusts the SAME principal database and the same
// long-term keys, and a ticket good for one realm's door is good for all of
// them. That is stated rather than left to be discovered — it is not a hole,
// because a Kerberos realm and a trust realm are two different words for two
// different things and this service has never claimed to give each of the
// second one a KDC of its own.
//
// ---------------------------------------------------------------------------
// THE FALLBACK IS PART OF THE DESIGN AND NOT AN AFTERTHOUGHT.
//
// A 401 carrying `WWW-Authenticate: Negotiate` and nothing else is a dead end
// for most browsers: Chrome and Firefox use Negotiate only for hosts on an
// explicit allow-list, and the machine needs a credential cache in the realm
// besides. A person who meets that on the way into an application is stuck with
// no way back. So every refusal here draws a PAGE with a link to
// `/authn/login?authn=<the same record>` on it — the sign-in they were already
// having, resumed — which is what real intranet sites do and is the reason
// `?authn=` is carried through rather than being spent on arrival.
// ---------------------------------------------------------------------------

const app = require('../common/app');
const { log, xmlEscape } = require('../common/helpers');
const config = require('../common/config');
// THE SESSION. This is the dependency that decides where this file sits in the
// require order — see the header. `authn.js` requires nothing in this directory
// and must not, so the arrow points one way only.
const authn = require('../authn/authn');
const principals = require('./krb5_principals.js');
const spnego = require('./krb5_spnego.js');
const exchange = require('./spnego_exchange.js');
// The shell and the check table. See that module's export list for why the
// sign-in door wears the debugger page's look rather than the sign-in screen's.
const spnegoPage = require('./spnego.js');

const page = spnegoPage.page;
const checksTable = spnegoPage.checksTable;

// The path, from the module that owns `/authn/*`. Imported rather than spelled
// again here: `authn.js` builds a redirect to it and draws a button pointing at
// it, and a string spelled in two files is a string that drifts.
const SPNEGO_PATH = authn.SPNEGO_PATH;

// What the console and the audit log call a sign-in that came through here. It
// names the PROTOCOL rather than the flow that was interrupted, exactly as
// federation's `via` does: what a reader of /admin/users wants to know is how
// this person proved who they are, and the flow they were signing in TO is on
// the record's own `protocol`, which the note below carries.
const VIA = 'Kerberos v5 (SPNEGO)';

// ---------------------------------------------------------------------------
// THE NAME THE SESSION IS FOR, out of the principal the ticket named.
//
// `krb5_service.js` hands back `alice@EXAMPLE.COM` — the client name joined
// with '/' and the ticket's realm after an '@' — and what goes in the session
// is `alice`, when and only when that realm is THIS KDC's own.
//
// **THE STRIPPING IS THE POINT AND IT IS NOT COSMETIC.** The session's username
// becomes `sub: urn:sts-mock:user:<username>` in every token, assertion and
// credential that follows. Leaving the realm on would mean that somebody who
// types `alice` at the sign-in screen and the same person arriving with a
// ticket are TWO SUBJECTS as far as every relying party is concerned — which is
// the exact failure `mock-sts`'s one-entry-per-person rule exists to prevent,
// and the exact shape of the defect the first federated sign-in shipped with
// (a foreign subject reaching `startSession()` unnormalised).
//
// **A FOREIGN REALM KEEPS ITS REALM**, and that asymmetry is deliberate.
// `bob@PARTNER.EXAMPLE.COM` arriving over a cross-realm ticket is not this
// service's `bob`, and issuing a token that says he is would be an assertion
// nothing here has any basis for. What happens instead is worth knowing rather
// than discovering: `admin_stats.js`'s `identityOf()` splits at the last '@'
// for filing purposes, so the DIRECTORY still folds the two onto one entry and
// the Realms column says which realms were folded. The directory answers "which
// human is this" and the token answers "who am I asserting" — they are allowed
// to differ, and this is one of the few places where they do.
//
// A multi-component name (`a/b@REALM`) is kept whole before the '@', because a
// service principal signing in is unusual but not wrong and the components ARE
// the name.
// ---------------------------------------------------------------------------
function usernameFor(clientPrincipal) {
  log.debug('Entering usernameFor(). principal=' + clientPrincipal);
  const text = String(clientPrincipal || '');
  const at = text.lastIndexOf('@');
  if (at <= 0) {
    log.debug('Leaving usernameFor(). No realm on it.');
    return text;
  }
  const realm = text.slice(at + 1);
  // Case-sensitively. Kerberos realms are case-sensitive by specification and
  // `EXAMPLE.COM` and `example.com` are two realms — folding them here would be
  // this module deciding a question the KDC did not.
  if (realm !== principals.REALM) {
    log.debug('Leaving usernameFor(). A foreign realm, kept whole.');
    return text;
  }
  log.debug('Leaving usernameFor(). ' + text.slice(0, at));
  return text.slice(0, at);
}

// ---------------------------------------------------------------------------
// WHAT THE SESSION CLAIMS, READ OFF THE TICKET'S OWN FLAGS.
//
// This is the one place in this service where `amr` and `acr` are DERIVED from
// something a credential actually says, rather than from what somebody ticked
// on a screen — so it is worth being exact about what the two flags mean, since
// both are easy to over-read.
//
//   pre-authent   RFC 4120 section 2.1: the KDC verified pre-authentication
//                 before issuing the initial ticket. On this KDC that is
//                 PA-ENC-TIMESTAMP, a timestamp encrypted under the client's
//                 long-term key — which is derived from a password. So `pwd`,
//                 RFC 8176's "password-based authentication", is the honest
//                 value: a password WAS proven, to the KDC, at some point in
//                 this credential's lineage.
//   hw-authent    section 2.1 again: "the protocol employed for initial
//                 authentication required the use of hardware expected to be
//                 possessed solely by the named client". That is `hwk` —
//                 proof-of-possession of a hardware key — and nothing else in
//                 RFC 8176 fits it.
//
// NEITHER FLAG IS NOT A FAILURE. A ticket carrying neither is one this KDC
// issued without pre-authentication, which is a configuration a real KDC can
// have and which this one can be made to produce; the honest answer is then an
// EMPTY `amr` and an `acr` of "0", which is RFC 6711's way of saying no level
// of assurance is being claimed. Filling in `pwd` there would be this service
// telling a relying party that a password was checked when nothing anywhere
// knows whether one was.
//
// **THE FLAGS ARE ON THE TICKET AND THE TICKET MAY BE SECOND-HAND.** A service
// ticket obtained from a TGT inherits `pre-authent` from the AS exchange that
// produced the TGT, which may have been hours ago — that is Kerberos's model
// and not a weakness here, and it is exactly what `authTime` on the session
// then means. What a ticket does NOT carry is the `initial` flag once it has
// been through the TGS, so `initial` is reported on the page and used for
// nothing: it says the credential was minted at the AS exchange, which is
// interesting to a person and is not an authentication method.
// ---------------------------------------------------------------------------
function factorsFor(ticketFlags) {
  log.debug('Entering factorsFor(). flags=' + (ticketFlags || []).join(','));
  const flags = ticketFlags || [];
  const password = flags.indexOf('pre-authent') !== -1;
  const hardware = flags.indexOf('hw-authent') !== -1;
  const amr = [];
  if (password) {
    amr.push('pwd');
  }
  if (hardware) {
    amr.push('hwk');
  }
  // "mfa" only where BOTH are claimed, and for the reason authn.js gives about
  // the passwordless WebAuthn path: one factor does not become two by being
  // phishing-resistant, and a relying party that asked for two must not be told
  // it got them.
  const acr = (password && hardware) ? 'mfa' : (amr.length ? '1' : '0');
  const method = 'Kerberos ticket over SPNEGO' +
    (password && hardware
       ? ' (the KDC required pre-authentication AND hardware)'
       : password
         ? ' (the KDC required pre-authentication, so a long-term key derived ' +
           'from a password was proven to it)'
         : hardware
           ? ' (the KDC required hardware for the initial authentication)'
           : ' (the ticket claims no pre-authentication at all, so nothing ' +
             'here knows what the KDC checked)');
  log.debug('Leaving factorsFor(). amr=' + amr.join(',') + ', acr=' + acr);
  return { amr: amr, acr: acr, method: method, password: password,
           hardware: hardware };
}

// Is this door open at all? A function rather than a constant, because the
// setting is settable at runtime and a value read at require time would be the
// one the process started with.
function enabled() {
  return !!config.value('krb5.spnegoAuthentication');
}

// The link back to the password screen, which every page here carries. It is
// the whole of the fallback story — see the header — and it is empty when there
// is no pending record, because there is then nothing to fall back INTO: a
// person who came to this URL directly was not in the middle of anything.
function fallbackHtml(record) {
  log.debug('Entering fallbackHtml().');
  if (!record) {
    log.debug('Leaving fallbackHtml(). Nothing was interrupted.');
    return '<p class="sub">Nothing sent you here, so there is nothing to go ' +
      'back to. This door can be used on its own — a client that holds a ' +
      'ticket gets a session and no application had to ask.</p>';
  }
  const html = '<p><a href="' + xmlEscape(authn.LOGIN_PATH) + '?authn=' +
    encodeURIComponent(record.id) + '"><strong>Sign in with a username ' +
    'instead</strong></a> &mdash; the request that sent you here is still ' +
    'waiting, and it will carry on either way.</p>' +
    '<p class="sub">Signing in for: <code>' +
    xmlEscape(record.protocol || '') + '</code>' +
    (record.application
       ? ' &middot; <code>' + xmlEscape(record.application) + '</code>'
       : '') + '</p>';
  log.debug('Leaving fallbackHtml(). Offered the screen.');
  return html;
}

// What a browser that cannot do Negotiate is looking at, said once. It is on
// the first challenge only: the later pages are refusals of a token that WAS
// sent, so the client evidently can.
const BROWSER_NOTE =
  '<h2>If nothing happened</h2>' +
  '<p>Most browsers send <code>Negotiate</code> only to hosts on an explicit ' +
  'allow-list, and the machine needs a Kerberos credential cache in this ' +
  'realm besides. In Chrome that is <code>--auth-server-allowlist</code>; in ' +
  'Firefox it is <code>network.negotiate-auth.trusted-uris</code>. Without ' +
  'both, what you see is this page and no ticket is ever requested &mdash; ' +
  'which is not a failure of anything here, and is why the link above ' +
  'exists.</p>' +
  '<p class="sub">A program does not have this problem: get a ticket for the ' +
  'service principal named below and send it as ' +
  '<code>Authorization: Negotiate &lt;base64&gt;</code>. That is all this ' +
  'endpoint is.</p>';

function spnFacts() {
  log.debug('Entering spnFacts().');
  const html = '<table>' +
    '<tr><th>What</th><th>Value</th></tr>' +
    '<tr><td>Service principal name</td><td><code>' +
      xmlEscape(exchange.SPN + '@' + principals.REALM) + '</code></td></tr>' +
    '<tr><td>Realm</td><td><code>' + xmlEscape(principals.REALM) +
      '</code></td></tr>' +
    '<tr><td>Also answers for hosts</td><td><code>' +
      xmlEscape(principals.SERVICE_DOMAINS.join(', ')) + '</code></td></tr>' +
    '</table>';
  log.debug('Leaving spnFacts().');
  return html;
}

// ---------------------------------------------------------------------------
// The endpoint.
//
// A GET, because that is what a redirect from a protocol endpoint produces and
// what a browser repeats when it answers a 401 — the whole exchange is one URL
// fetched twice, which is what makes `?authn=` the right place to carry the
// interrupted request. It is never in the URL as a return ADDRESS: the record
// is server-side and holds `returnTo`, so there is no open-redirect surface
// here at all. (`/federation/login/{id}` does take a `returnTo`, and has to —
// the browser leaves this origin there and comes back to a different endpoint.
// This one never leaves.)
// ---------------------------------------------------------------------------
async function handleSignIn(req, res) {
  log.debug('Entering handleSignIn().');
  const record = authn.pendingFor((req.query || {}).authn);

  if (!enabled()) {
    // A REFUSAL WITH A REASON, not a 404. The route exists — it is in the
    // router, it is on /admin/sts-metadata — and answering "no such page"
    // would send somebody to look for a deployment problem when what they have
    // is a setting. Every other switchable refusal in this service says which
    // setting it was, for the same reason.
    log.info('krb5-spnego-authn: refused a sign-in because ' +
      'krb5.spnegoAuthentication is off.');
    res.status(403).type('html').set('Cache-Control', 'no-store').send(
      page('Integrated authentication is off',
        '<h1>403 &mdash; integrated authentication is off</h1>' +
        '<div class="err">This service can sign people in with a Kerberos ' +
        'ticket, and <code>krb5.spnegoAuthentication</code> is set to ' +
        'false.</div>' +
        '<p>Turn it on at <a href="/admin/kerberos">/admin/kerberos</a>, or with ' +
        '<code>POST /admin-api/config/set</code>. Nothing else changes when ' +
        'it is off: <a href="/spnego/protected">/spnego/protected</a> still ' +
        'performs the whole handshake and shows you both halves of it &mdash; ' +
        'what it will not do is give you a session.</p>' +
        fallbackHtml(record)));
    log.debug('Leaving handleSignIn(). The door is closed.');
    return;
  }

  const verdict = await exchange.negotiate(req, {
    door: SPNEGO_PATH,
    // WHAT krb5_service.js CALLS THIS on /admin/users, and it is deliberately
    // not the protected page's phrasing: "SPNEGO over HTTP" is a transport,
    // and this is a sign-on.
    via: 'SPNEGO sign-in over HTTP (RFC 4559)',
    // AND IT MUST NOT RECORD IT ITSELF. See krb5_service.js, where this
    // parameter is argued: the act here is a ticket accepted AND a session
    // minted, `startSession()` is the funnel that records exactly that with
    // the session id on it, and two records would make /admin/users count one
    // sign-in twice — which is the defect federation shipped with and fixed
    // the same way.
    record: false
  });

  exchange.applyVerdict(res, verdict);

  if (!verdict.ok) {
    const first = verdict.code === 'no-authorization';
    // A CONTINUATION IS NOT A FAILURE, and saying so is the one thing this
    // page has to get right that the protected page does not: three of the
    // fifteen outcomes are the acceptor asking for another round trip, and a
    // person told "you could not be signed in" over one of them would go and
    // fix something that is working.
    const waiting = !exchange.OUTCOMES[verdict.code] ||
                    !exchange.OUTCOMES[verdict.code].terminal;
    res.type('html').send(page(
      first ? 'Sign in with Kerberos'
            : waiting ? 'Kerberos: one more round trip'
                      : 'Kerberos sign-in refused',
      '<h1>' + (first
        ? 'Sign in with a Kerberos ticket'
        : waiting
          ? '401 &mdash; the negotiation is not finished'
          : '401 &mdash; that ticket did not sign you in') + '</h1>' +
      (first
        ? '<p>This service asked your client for a Kerberos ticket ' +
          '(<code>WWW-Authenticate: Negotiate</code>, RFC 4559). If it has ' +
          'one, or can get one, it will repeat this request with it and you ' +
          'will be signed in without typing anything.</p>'
        : '<div class="' + (waiting ? 'ok' : 'err') + '">' +
          xmlEscape(verdict.reason) + '</div>') +
      (waiting && !first
        ? '<p>Your client should answer this reply with another token. If you ' +
          'are reading this page, it did not &mdash; the exchange is ' +
          'unfinished rather than refused.</p>'
        : '') +
      (verdict.checks ? '<h2>What this service checked</h2>' +
        checksTable(verdict.checks) : '') +
      fallbackHtml(record) +
      (first ? BROWSER_NOTE + spnFacts() : '')));
    log.debug('Leaving handleSignIn(). ' + verdict.code + '.');
    return;
  }

  // ---------------------------------------------------------------------
  // ACCEPTED. Everything below this line is the sign-in, and the order is the
  // one federation_sp.js uses for the same reason: the thing with an effect
  // outside this process goes LAST, and everything above it is a record of
  // why.
  // ---------------------------------------------------------------------
  const username = usernameFor(verdict.client);
  const factors = factorsFor(verdict.ticketFlags);
  const detail = {
    // The PRINCIPAL as presented, not the username the session carries. They
    // differ by the realm and `admin_stats.js`'s identityOf() folds them onto
    // one person anyway — so recording the stripped form here would lose the
    // only place the full principal is ever written down.
    presented: verdict.client,
    protocol: 'Kerberos v5',
    method: factors.method,
    note: 'A Kerberos service ticket for ' + exchange.SPN + '@' +
          principals.REALM + ' was accepted over SPNEGO and a browser session ' +
          'was started for the principal inside it. This is the one sign-in ' +
          'in this service that rests on a credential it genuinely verified — ' +
          'every other one takes the name it is given. Ticket flags: ' +
          ((verdict.ticketFlags || []).join(', ') || 'none') + '.' +
          (record ? ' The request it completes is a ' +
                    (record.protocol || 'unnamed') + ' one' +
                    (record.application ? ' for "' + record.application + '"'
                                        : '') + '.'
                  : ' Nothing was interrupted; this door was used directly.'),
    summary: username + ' was signed in with a Kerberos ticket over SPNEGO'
  };
  const session = authn.startSession(res, username, factors.amr, factors.acr,
                                     VIA, detail);
  log.info('krb5-spnego-authn: ' + username + ' signed in as ' + verdict.client +
    ' over ' + spnego.mechName(verdict.selected) +
    (verdict.micVerified ? ', mechListMIC verified' : '') +
    (verdict.rawKerberos ? ' (a bare Kerberos token, no negotiation)' : '') +
    '. amr [' + factors.amr.join(',') + '], acr "' + factors.acr +
    '". Session ' + session.id + '.');

  if (record) {
    // Back to whatever was interrupted, which now runs a second time, sees the
    // session cookie and completes. `completeAuthentication()` is authn.js's,
    // and going through it rather than redirecting from here is what keeps the
    // pending record from being spendable twice and the 303 in one place —
    // RFC 9700 section 4.12, argued at length over there.
    authn.completeAuthentication(res, record);
    log.debug('Leaving handleSignIn(). Signed in and returned to ' +
      record.returnTo + '.');
    return;
  }

  // Nothing was interrupted, so this is the whole of it: a page saying who you
  // now are. The same shape federation's own entry point draws when it is
  // reached without a `returnTo`.
  res.type('html').send(page('Signed in',
    '<h1>200 &mdash; you are signed in</h1>' +
    '<div class="ok">Signed in as <strong>' + xmlEscape(username) +
    '</strong>, from the Kerberos principal <code>' +
    xmlEscape(verdict.client) + '</code>.</div>' +
    '<p>The session cookie is set. Every protocol this service speaks reads ' +
    'the same session, so an <code>/oauth2/authorize</code>, a ' +
    '<code>wsignin1.0</code>, a SAML AuthnRequest or the admin console will ' +
    'now complete without asking you for anything.</p>' +
    '<table>' +
    '<tr><th>What</th><th>Value</th></tr>' +
    '<tr><td>Session</td><td><code>' + xmlEscape(session.id) +
      '</code></td></tr>' +
    '<tr><td>Subject</td><td><code>' + xmlEscape(session.user.sub) +
      '</code></td></tr>' +
    '<tr><td>Ticket flags</td><td><code>' +
      xmlEscape((verdict.ticketFlags || []).join(', ') || 'none') +
      '</code></td></tr>' +
    '<tr><td>amr</td><td><code>' +
      xmlEscape(factors.amr.join(', ') || '(none claimed)') + '</code>' +
      (factors.amr.length ? '' : ' &mdash; the ticket claims no ' +
        'pre-authentication, so this service claims no authentication method') +
      '</td></tr>' +
    '<tr><td>acr</td><td><code>' + xmlEscape(factors.acr) + '</code></td></tr>' +
    '<tr><td>Mechanism</td><td><code>' +
      xmlEscape(spnego.mechName(verdict.selected)) + '</code>' +
      (verdict.rawKerberos ? ' &mdash; a bare Kerberos token, no negotiation'
                           : '') + '</td></tr>' +
    '<tr><td>mechListMIC</td><td>' + (verdict.micVerified
      ? '<span class="pass">verified</span>'
      : '<span class="fail">not sent</span>') + '</td></tr>' +
    '</table>' +
    (verdict.checks ? '<h2>What this service checked</h2>' +
      checksTable(verdict.checks) : '') +
    '<p class="sub"><a href="/admin/users">/admin/users</a> now has a row for ' +
    'this person, and the embedded directory has an entry. ' +
    '<a href="/logout">/logout</a> ends it.</p>'));
  log.debug('Leaving handleSignIn(). Signed in with nothing to return to.');
}

app.get(SPNEGO_PATH, function (req, res) {
  log.debug('Entering GET ' + SPNEGO_PATH + '.');
  handleSignIn(req, res).catch(function (e) {
    // Every path in that function writes a response; an exception that escaped
    // would leave the browser holding an open request in the middle of a
    // sign-in, which reads as an unreachable service rather than as a fault
    // here.
    log.error('krb5-spnego-authn: unhandled failure: ' + (e.stack || e.message));
    if (!res.headersSent) {
      res.status(500).type('html').send(page('Failed',
        '<h1>500</h1><div class="err">' + xmlEscape(e.message) + '</div>'));
    }
  });
  log.debug('Leaving GET ' + SPNEGO_PATH + '.');
});

module.exports = {
  SPNEGO_PATH: SPNEGO_PATH,
  enabled: enabled,
  usernameFor: usernameFor,
  factorsFor: factorsFor
};
