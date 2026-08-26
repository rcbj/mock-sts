// File: authn.js
//
// THE AUTHENTICATION SERVICE — the screen where a person proves who they are,
// and nothing else.
//
// It used to be part of oauth2.js: `GET /oauth2/authorize` with no session
// answered 200 with the login form in the body, at the authorization endpoint's
// own URL. That worked, and it made authentication look like a feature of one
// protocol. It is not: WS-Federation signs people in too, the session is shared
// between them, and everything this service will grow next — a second factor
// somebody else's protocol can ask for, a screen that can say WHY it is asking,
// remembered devices — belongs to the act of authenticating rather than to the
// grant that happened to trigger it. So the screen is its own endpoint, and a
// protocol that needs a user authenticated SENDS them here and gets them back.
//
// The contract, in full:
//
//   1. A protocol module calls beginAuthentication({ returnTo, ... }) and
//      redirects the browser to the path it returns.
//   2. This service shows the screen, takes what the person types, and — on
//      every successful sign-in, which is all of them, since no password is
//      checked — establishes the session cookie.
//   3. It redirects the browser to `returnTo`, which the caller built out of
//      its ORIGINAL request, unchanged.
//   4. The caller's endpoint runs again, sees the session cookie this time, and
//      completes its protocol per spec.
//
// Three properties of that are deliberate:
//
// * **`returnTo` is a path on this service and is checked to be one.** It is
//   built by the caller and never read off the query string, but it is checked
//   anyway — an authentication service that will redirect a browser to an
//   arbitrary absolute URL after signing somebody in is an open redirector with
//   a login screen in front of it, which is the exact shape of a credential
//   phishing tool.
//
// * **The service knows nothing about OAuth.** It does not read client_id, it
//   does not know what a redirect_uri is, and it cannot build a protocol error.
//   What the screen SHOWS about the request it interrupted — the client, the
//   scope, the Credential Offer it came from — arrives as `details`, rows the
//   caller wrote, because only the caller knows what those values mean.
//
// * **Cancelling comes back here too.** The person is returned to `returnTo`
//   with `authn_error=access_denied` on it, and the CALLER turns that into
//   whatever its own specification says a refusal looks like. This service must
//   not: OAuth's answer is a redirect to the client's redirect_uri, and in
//   response_mode=form_post it is not a redirect at all but a self-submitting
//   form. Protocol knowledge stays in the protocol module.
//
// It owns the session store because it is the only thing that creates one:
// oauth2.js's note used to say the session lived there "because this module
// owns the login flow the session comes out of", which is exactly the sentence
// that moves it here now that the login flow has.
//
// Nothing in here requires oauth2.js, which is what keeps this a one-way
// dependency and free of the import cycles this service's module split exists
// to avoid: oauth2.js, wsfed.js and admin.js require THIS.
const crypto = require('crypto');
// TRUST REALMS: the stores below are partitioned by realm. It requires
// config.js and nothing else here, so it cannot join a cycle and it registers
// no route, so its position is not a position at all.
const realms = require('../common/realms');
const app = require('../common/app');
const { log, logArtifact, baseUrlOf, nowSec, randomId, xmlEscape, parseBody,
        oauthError, userFor } = require('../common/helpers');
const stats = require('../common/admin_stats');
// The federation register, for the buttons at the foot of the sign-in screen.
// A plain require in the ordinary direction and it passes rule 3e's test both
// ways round: that module registers no route, so nothing about requiring it
// from here can move one, and it requires only config.js, helpers.js and
// audit.js — none of which requires this file — so there is no cycle to close.
//
// It is THIS module that requires the register rather than the other way about,
// and that is the arrangement rather than an accident: `federation_sp.js`
// requires THIS file (it has no sign-in screen of its own and calls
// startSession() directly, which is the same dependency saml2_sso.js has), so a
// require back from here to that module would be a cycle. The register in the
// middle is what both halves can safely reach.
const federation = require('./../federation/federation');
// The application registry, for the one attribute on an entry that decides
// where that application's people are sent to sign in —
// `appFederationRelationship`. Same shape of dependency as the register above
// and it passes the same test: `common/applications.js` requires config.js,
// helpers.js and audit.js and nothing else here, so there is no cycle to close,
// and it registers no route, so requiring it moves nothing in the require
// order.
const applications = require('../common/applications');
// For one thing only: whether the main port is an HTTPS listener, which decides
// the Secure attribute on the session cookie below.
const config = require('../common/config');
// For one decision: whether ending a session should revoke the refresh tokens
// issued on it (RFC 9700 section 2.2.2). The policy is that module's, with the
// rest of the mode; the session and the token registry are here, which is why
// the act is here. A library that registers no route, so requiring it cannot
// move anything in the require order.
const bcp = require('../oauth-oidc/oauth2_bcp');
// The audit log. Two things happen here that no other module can see: a session
// is created, and a session is ended. Neither is an authentication —
// admin_stats.js records that, at the funnel every protocol family shares — and
// neither is an HTTP call, which app.js records. A sign-in therefore writes
// three audit rows, which is three facts at three layers rather than one fact
// three times; /admin/audit says so where a reader counting rows will see it.
//
// This module also FILLS audit.js's actor slot at the bottom of this file, which
// is what puts a name on every console and management API row.
const audit = require('../common/audit');

// The path a caller sends the browser to. Exported, because the two callers
// build a URL out of it and a string spelled twice is a string that drifts.
const LOGIN_PATH = '/authn/login';

const SESSION_COOKIE = 'sts_mock_session';

const SESSION_TTL_MS = 60 * 60 * 1000;

// How long an interrupted request waits at the screen before it has to be
// started again.
const AUTHN_TTL_MS = 10 * 60 * 1000;

// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const sessions = realms.map();         // session id -> the signed-in user

// The requests waiting at the login screen: what to do with the person once
// they have signed in, and what to tell them they are signing in FOR.
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const pending = realms.map();          // authn id -> { returnTo, details, ... }

// WebAuthn, IN EITHER OF ITS TWO ROLES. The verifier is ./webauthn — written
// from the specification and sharing no code with the debugger's own decoder,
// which is what makes tests/webauthn_cross_impl.js over there a real check
// rather than an implementation agreeing with itself.
//
// It lives HERE, with the password step it follows or replaces: the two are one
// act of authentication, they share the pending record, and a second factor is
// the first thing a centralized authentication service is asked for.
//
// **The two roles are one ceremony and three consequences, and they are worth
// keeping straight because everything downstream reads them off the session.**
//
//   * SECOND FACTOR (`use_webauthn`): a password step has already happened, so
//     the session records amr ["pwd","hwk"] and acr "mfa". The person is not a
//     new identity — they are the one the password step named — so the
//     directory entry that the funnel seeds is theirs either way, and what the
//     key adds to it is a FLAG saying multi-factor happened. See
//     ldap_server.js's applyAuthenticationFactors().
//   * PRIMARY (`webauthn_only`): no password was presented at all, so the
//     session records amr ["hwk"] and acr "1" — ONE factor, and a
//     phishing-resistant one is still one. This is an authentication in its own
//     right, so it goes through stats.recordAuthentication() like every other
//     accepted credential and the directory grows an entry for the person the
//     same way a password sign-in makes one.
//
// The distinction is refused rather than fudged in one place: a caller that
// demanded a second factor (`forceMfa`) does not get the passwordless path,
// because answering "two factors" with one would be exactly the lie wauth and
// acr_values exist to prevent.
const webauthnVerifier = require('./webauthn');
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const webauthnCredentials = realms.map();  // username -> { credentialId, publicKeyJwk, signCount }
// mfa id -> { authn, username, challenge, passwordless, expires }
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const pendingMfa = realms.map();
const MFA_TTL_MS = 5 * 60 * 1000;

// --- the browser session -----------------------------------------------------
// The cookie, and the three things done with it. This is the store every
// protocol module reads to answer "is this person already signed in?", and the
// only place in the service that writes it.
function cookiesOf(req) {
  log.debug("Entering cookiesOf().");
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(function (part) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  log.debug("Leaving cookiesOf(). " + Object.keys(out).length + " cookie(s).");
  return out;
}

function sessionOf(req) {
  log.debug("Entering sessionOf().");
  const id = cookiesOf(req)[SESSION_COOKIE];
  if (!id) {
    log.debug("Leaving sessionOf(). No session cookie.");
    return null;
  }
  const session = sessions.get(id);
  if (!session) {
    log.debug("Leaving sessionOf(). The cookie names no session this server knows.");
    return null;
  }
  if (session.expires < Date.now()) {
    sessions.delete(id);
    log.debug("Leaving sessionOf(). The session had expired and was discarded.");
    return null;
  }
  log.debug("Leaving sessionOf(). Signed in as " + session.user.username + ".");
  return session;
}

// ---------------------------------------------------------------------------
// THE CONSOLE'S SESSION, AND IT IS ALWAYS THE DEFAULT REALM'S. FOR THE ADMIN
// CONSOLE, AND FOR NOTHING ELSE IN THIS SERVICE.
//
// `sessions` is per realm and `sessionOf()` reads the ambient realm's
// partition, which is right for every protocol here: signing in to `acme` must
// not satisfy the default realm's `/oauth2/authorize`, and realmSupport() says
// so out loud. The console is the one caller that needs a different answer, and
// what it needs is not "any realm" — it is "the default realm, whichever realm
// is being read".
//
// **THIS FUNCTION USED TO ANSWER "ANY REALM" AND THAT BECAME WRONG ON
// 2026-08-25**, when the embedded directory became per realm. The old argument
// was explicit about its own premise: *who may use the console is already
// shared, because the two roles are groups in the ONE directory this process
// has, so a session refused for being minted next door would have been refused
// on a boundary the authorization decision behind it does not have.* That
// premise is now false. Each realm has its own `ou=groups`, and if a session
// minted in `acme` still opened the console then anybody who could create a
// realm could grant themselves both roles inside it and walk back out into the
// default realm — the realm feature would have become a privilege escalation.
// `ldap_server.js` pins `admin_rbac.js`'s whole directory to the default realm
// for that reason, and this is the other half of the same decision. The two
// have to agree: a gate that accepted an `acme` session while the roster could
// only name default-realm people would let somebody in and then insist they
// were nobody.
//
// **THERE IS STILL ONE COOKIE, AND THAT IS WHY THIS IS NOT `sessionOf()`.**
// `startSession()` writes `sts_mock_session` at `Path=/`, deliberately and for
// a reason that has nothing to do with realms — every protocol here shares one
// session, so the name, path and SameSite have to agree exactly. A browser
// therefore holds exactly ONE session id for this whole origin. Reading the
// AMBIENT realm's partition would make the console's realm switcher a loop: the
// gate finds nothing in `acme`, sends the reader to `/realm/acme/authn/login`,
// and that sign-in OVERWRITES the one cookie there is — so switching back finds
// nothing either, forever, one sign-in per click. Nothing expires and nothing
// is misconfigured; the two realms take turns holding the only cookie slot the
// browser has. Pinning to the default realm ends that in the same stroke: there
// is one realm the console ever signs anybody in to, so there is nothing to
// take turns over.
//
// Two properties this keeps from the version it replaced:
//
//   * IT GRANTS NOTHING ELSE. This is called from `gateStateFor()` in admin.js
//     and from nowhere else, and the thing it answers is "may this browser read
//     this console". No token is issued on the session it finds, no assertion
//     names it, and `/oauth2/authorize` still calls `sessionOf()` and still
//     sees only its own realm's.
//   * ENDING IT STILL ENDS IT. The session is the one object in the default
//     realm's map — so /logout, /admin/logout and an expiry sweep all shut the
//     console too, because there is nothing here to end separately.
//
// It sweeps an expired session out of the default realm's map exactly as
// `sessionOf()` does, rather than leaving one for a later reader to clear.
//
// The realm is returned alongside the session so that `gateStateFor()` can keep
// reporting one, and `foreign` says whether the realm being READ is a different
// one — which is now the ordinary case for every page under a realm prefix, and
// is what the console's banner says out loud.
// ---------------------------------------------------------------------------
function consoleSession(req) {
  log.debug("Entering consoleSession().");
  // In the default realm this is the ordinary reader, sweep and all, so the
  // common case — a service with no realms defined — is byte-for-byte what it
  // always was.
  if (!realms.active() || realms.currentId() === realms.DEFAULT_ID) {
    const here = sessionOf(req);
    log.debug("Leaving consoleSession(). The default realm is the one being read.");
    return here
      ? { session: here, realm: realms.DEFAULT_REALM, foreign: false }
      : null;
  }
  const id = cookiesOf(req)[SESSION_COOKIE];
  if (!id) {
    log.debug("Leaving consoleSession(). No session cookie.");
    return null;
  }
  // The default realm's own Map. `realmMap(id)` is the facade's door for
  // exactly this — a caller that wants a NAMED partition rather than the
  // ambient one.
  const store = sessions.realmMap(realms.DEFAULT_ID);
  const session = store.get(id);
  if (!session) {
    log.debug("Leaving consoleSession(). The default realm holds no such session.");
    return null;
  }
  if (session.expires < Date.now()) {
    store.delete(id);
    log.debug("Leaving consoleSession(). The session had expired and was discarded.");
    return null;
  }
  log.debug("Leaving consoleSession(). Signed in as " + session.user.username +
            " on the default realm's session.");
  return { session: session, realm: realms.DEFAULT_REALM, foreign: true };
}

// --- starting and ending a session -----------------------------------------
// Both are functions rather than four lines repeated at each call site, and the
// reason is WS-Federation. `wsfed.js` signs a user in at its own login screen and
// must land them in THE SAME session this service owns, because the two protocols
// share the browser and single sign-on between them is the interesting behaviour:
// sign in at this screen with a security key, arrive at `wsignin1.0`, and the
// assertion says a hardware key was used because the session recorded it.
//
// The cookie's attributes are the part that must not be written twice. Sharing a
// session across protocols means the cookie NAME, PATH and SameSite have to agree
// exactly; a second copy that set Path=/oauth2 or omitted SameSite would produce
// two sessions that each looked fine on its own and never saw each other, which is
// a debugging session with no error message anywhere in it.
//
// **SameSite=Lax is deliberate and it has one consequence worth knowing.** It is
// sent on a top-level GET navigation, which is how a relying party sends a browser
// here in both protocols — but NOT on a cross-site POST, and WS-Federation section
// 13.2.1 permits the sign-in request to arrive as a form POST. Such a request
// therefore sees no session and is shown the login screen even though one exists.
// The alternative is SameSite=None, which requires Secure, which this service
// cannot be over http://localhost — so the quirk stays, and wsfed.js says so on
// the screen rather than leaving it to look like a broken session.
//
// `via` names the screen the person actually used, and it is a parameter rather than
// something derived here because this function cannot tell: WS-Federation's sign-in
// screen calls it too, and a session started there is indistinguishable afterwards
// from one started here — which is the point of sharing the store, and is exactly
// why the admin console would otherwise report every WS-Federation sign-in as an
// OIDC one. beginAuthentication() carries it from the caller as `protocol`; it
// still defaults to OIDC, so a call site that omits it says what it always meant.
// What the console and the audit log call this sign-in. A function because
// there are THREE of them now and the two-way conditional this replaced could
// not say the third: it asked whether `hwk` was present, so a passwordless
// ceremony — amr ["hwk"] and no password anywhere — was reported as a password
// sign-in with a security key beside it, which is the one thing the two roles
// must not be confused about.
function methodPhraseFor(amr) {
  const factors = amr || [];
  const key = factors.indexOf('hwk') >= 0;
  const password = factors.indexOf('pwd') >= 0;
  if (key && password) {
    return 'sign-in screen (password and a security key)';
  }
  if (key) {
    return 'sign-in screen (a security key alone, passwordless)';
  }
  return 'sign-in screen (password)';
}

// ---------------------------------------------------------------------------
// `detail` — THE SIXTH ARGUMENT, AND WHY IT EXISTS RATHER THAN A SECOND
// recordAuthentication() CALL AT THE CALLER.
//
// This function is the single funnel for "somebody now holds a session here",
// and it has always recorded the authentication ITSELF — the comment two lines
// into the body says so, and it is what makes a WS-Federation sign-in appear on
// /admin/users without that module knowing the console exists.
//
// FEDERATION BROKE THAT ASSUMPTION IN TWO PLACES AT ONCE and the fix had to be
// here rather than there. A federated sign-in has facts this function cannot
// derive:
//
//   * `methodPhraseFor()` reads `amr` and answers "sign-in screen (password)"
//     for anything it does not recognise, which is exactly wrong for somebody
//     who never saw this screen at all;
//   * the mapped attributes a foreign identity provider asserted have to ride
//     the funnel to the directory, and there is no other way in.
//
// The obvious alternative — the caller calling `stats.recordAuthentication()`
// and then this — was written first and is what this parameter replaced: it
// produced TWO authentication records for one sign-in, so /admin/users counted
// every federated arrival twice and the audit log carried a duplicate of every
// one of them. A caller passing nothing behaves exactly as every existing
// caller did.
// ---------------------------------------------------------------------------
function startSession(res, username, amr, acr, via, detail) {
  log.debug("Entering startSession(). username=" + username + ", acr=" + acr);
  const extra = detail || {};
  const sessionId = randomId(24);
  const session = {
    // The id is on the session as well as being the map key, because everything that
    // is handed a session gets the object and not the key — the authorization
    // endpoint, WS-Federation, the console — and without it the tokens issued on a
    // session could not name the session they were issued on.
    id: sessionId,
    user: userFor(username), authTime: nowSec(), expires: Date.now() + SESSION_TTL_MS,
    // Stated rather than omitted: a relying party that asked for a second factor
    // needs to be able to see that it did not get one.
    amr: amr, acr: acr
  };
  sessions.set(sessionId, session);
  // `Secure` when — and only when — this port is TLS (global.https, which RFC
  // 9700 mode brings with it). It has to be conditional rather than always on:
  // a browser silently DROPS a Secure cookie that arrives over plain http, so
  // setting it unconditionally would leave the default deployment with a
  // sign-in that appears to succeed and a session that is never there again —
  // which is the same symptom as a session that expired and points nowhere near
  // the cookie. `SameSite=Lax` stays as it is: WS-Federation section 13.2.1
  // sends its sign-in request as a cross-site form POST, and None would be the
  // change that needs its own argument.
  res.set('Set-Cookie', SESSION_COOKIE + '=' + sessionId + '; Path=/; HttpOnly; SameSite=Lax' +
                        (config.value('global.https') ? '; Secure' : ''));
  // One of the two places a person is authenticated by typing a name at a screen —
  // this one covers both, since WS-Federation signs in through here.
  stats.recordAuthentication(Object.assign({
    presented: username, protocol: via || 'OAuth 2.0 / OIDC',
    method: methodPhraseFor(amr),
    sub: session.user.sub, amr: amr, acr: acr, sessionId: sessionId,
    note: 'No password was checked; the name typed is the identity.'
  }, extra, { sessionId: sessionId }));
  // The session itself, as its own audit event. It is deliberately separate
  // from the authentication recorded on the line above: the two are one act at
  // this screen and are NOT one act everywhere — a Kerberos AS-REQ and a
  // WS-Trust UsernameToken authenticate somebody and start no session at all,
  // and a session that outlives the sign-in is the thing single sign-on then
  // runs on. An audit log that could not tell those apart could not answer
  // "when did this browser get its session", which is the question a sign-out
  // row is only interesting beside.
  //
  // The session id is recorded WHOLE. It is a credential-shaped thing and this
  // is the one exception to "no credential is ever recorded" — it is not one:
  // the cookie is HttpOnly and the console already prints session ids on
  // /admin/users and /admin/metrics, where the whole point is to line a token
  // up with the session it was issued on. Truncating it here would break that
  // and protect nothing.
  audit.audit({
    action: 'session.start',
    actor: username,
    protocol: via || 'OAuth 2.0 / OIDC',
    channel: 'http',
    target: sessionId,
    // "at the … screen" is wrong for a caller that had no screen, so the
    // phrasing follows the caller where it says so. Federation is the one such
    // caller today: the person signed in somewhere else entirely.
    summary: extra.summary ||
             (username + ' was signed in at the ' + (via || 'OAuth 2.0 / OIDC') +
              ' screen; session ' + sessionId + ' was created'),
    detail: {
      sessionId: sessionId,
      sub: session.user.sub,
      amr: (amr || []).join(', '),
      acr: acr || '',
      authTime: session.authTime,
      expiresAt: new Date(session.expires).toISOString(),
      // The caller's own sentence where it has one. A federated sign-in's
      // "No password was checked" is true and useless — nothing was typed
      // here at all — and the row is the only place that distinction will
      // ever be recorded.
      note: extra.note || 'No password was checked; the name typed is the identity.'
    }
  });
  log.debug("Leaving startSession(). " + username + " is signed in (amr " + (amr || []).join(',') + ").");
  return session;
}

// ---------------------------------------------------------------------------
// ENDING A SESSION, IN THE TWO SHAPES CALLERS NEED, AND ONE BODY UNDER BOTH.
//
// `endSession(req, res)` is the browser's: it reads the cookie, drops what it
// names, and clears the cookie. `endSessionById(id, via)` is the one the
// PROTOCOL-INDEPENDENT logout needs — /logout ends sessions that are not the
// caller's own, and /admin/logout ends somebody else's entirely, neither of
// which has a cookie to read.
//
// They share `dropSession()` and MUST keep sharing it. What that function does
// besides the delete is the whole reason: the RFC 9700 section 2.2.2 refresh
// revocation and the `session.end` audit row. A second copy of either would be
// a sign-out that revoked nothing on one path, or two audit rows that came to
// disagree about what a sign-out is — which is exactly the argument that put
// this code here rather than in /oauth2/logout and wsignout1.0 separately.
// ---------------------------------------------------------------------------

// The one place a session actually stops existing. `via` names the door, and it
// goes on the audit row: "the sign-out endpoint", "a global logout", "the admin
// console". Returns the session as it was — the caller needs what it WAS, not
// merely that it is gone, because the lists of relying parties and service
// providers a federated sign-out has to fan out to live on the object being
// discarded.
function dropSession(id, via, cookiePresented) {
  log.debug("Entering dropSession(). id=" + (id || '(none)'));
  const session = id ? sessions.get(id) : null;
  if (id) sessions.delete(id);
  // RFC 9700 section 2.2.2: an authorization server MAY revoke refresh tokens
  // after a security event, and the section names LOGOUT as one. In RFC 9700
  // mode it does — every refresh token issued ON this session, through the same
  // revocation set /oauth2/revoke and the console write to, so introspection
  // reports them inactive immediately.
  //
  // HERE and not at any sign-out endpoint, because this function is the single
  // place all of them end a session: /oauth2/logout, WS-Federation's
  // wsignout1.0, SAML 2.0 Single Logout and /logout are four words for one act,
  // and a revocation at each would be four that could come to disagree.
  //
  // Only the REFRESH tokens. An access token issued on this session expires in
  // an hour and revoking it would take away the evidence of what the session
  // did; the refresh token is the thirty-day credential a sign-out is supposed
  // to be about, and leaving it live is what made signing out mean nothing to
  // the back channel. A GLOBAL logout revokes the access tokens too — but it
  // does that itself, as a separate stated act, rather than by widening this
  // one: the two are different promises and only one of them is the BCP's.
  if (id && bcp.revokeRefreshOnLogout()) {
    const revoked = stats.revokeWhere(function (record) {
      return record.sessionId === id && String(record.typ || '') === 'Refresh';
    }, 'RFC 9700 section 2.2.2: the sign-on session it was issued on ended');
    if (revoked) {
      log.info('RFC 9700 section 2.2.2: signing out of session ' + id + ' revoked ' + revoked +
               ' refresh token(s) issued on it. Without that, a sign-out drops a cookie and ' +
               'leaves a thirty-day credential in the client\'s hands.');
    }
  }
  // The sign-out, recorded here because this is the one place every door
  // reaches: they are four protocols' words for ending the one session this
  // service holds, and a row per caller would be four rows that could come to
  // disagree about what a sign-out is.
  //
  // A logout with NOTHING TO END is recorded too, as `refused`. That is not
  // pedantry: a relying party looping on wsignout1.0 against a session that
  // expired an hour ago looks identical, from every other page in this console,
  // to one that is working — and the row that says "there was no session to
  // drop" is the only place that shows up.
  audit.audit({
    action: 'session.end',
    outcome: session ? 'success' : 'refused',
    actor: session ? session.user.username : '',
    channel: 'http',
    target: session ? session.id : (id || ''),
    summary: session
      ? 'the sign-on session for ' + session.user.username + ' was ended'
      : 'a sign-out was asked for and there was no session to end',
    detail: {
      sessionId: session ? session.id : '',
      // How the session was named. A cookie is the browser's own sign-out; an
      // id is /logout or the console ending a session that is not the caller's,
      // and telling the two apart is the difference between "they signed out"
      // and "somebody signed them out".
      cookiePresented: cookiePresented ? 'yes' : 'no',
      namedBy: cookiePresented ? 'the session cookie' : 'its identifier',
      via: via || 'a sign-out endpoint',
      // Whether the name reached a session this service still had. A `yes` on
      // cookiePresented with no session means it had already expired or already
      // been signed out, which are the two ordinary ways this row is a refusal.
      sessionFound: session ? 'yes' : 'no',
      amr: session ? (session.amr || []).join(', ') : '',
      acr: session ? (session.acr || '') : ''
    }
  });
  log.debug("Leaving dropSession(). " + (session ? 'Dropped the session for ' + session.user.username + '.'
                                                 : 'There was no session to drop.'));
  return session || null;
}

// Every session this service holds for one person, newest first. The comparison
// is on the USERNAME as typed, because that is what the session records and what
// /logout was asked about; admin_stats.js's identityKeyOf() normalisation is
// applied by the CALLER where it wants `alice` and `alice@REALM` to be one
// person, so that this function cannot quietly fold two names together for a
// caller that meant one.
function sessionsOf(username) {
  log.debug("Entering sessionsOf(). username=" + username);
  const wanted = String(username || '');
  const out = [];
  sessions.forEach(function (session) {
    if (((session.user && session.user.username) || '') === wanted) out.push(session);
  });
  out.sort(function (a, b) { return (b.authTime || 0) - (a.authTime || 0); });
  log.debug("Leaving sessionsOf(). " + out.length + " session(s).");
  return out;
}

// One session by its id, without the cookie and without expiring it. Used by
// /logout to draw a row for a session that is not the caller's; `sessionOf()`
// stays the function that reads the cookie and sweeps what it finds expired.
function sessionById(id) {
  return sessions.get(String(id || '')) || null;
}

// End one session named by its id. The protocol-independent logout's door, and
// the console's. It does NOT touch the caller's cookie: the session being ended
// is usually not the one the caller is holding, and clearing the cookie of a
// browser that is signed in as somebody else would sign the operator out
// instead of the person they asked about.
function endSessionById(id, via) {
  log.debug("Entering endSessionById(). id=" + id);
  const session = dropSession(String(id || ''), via, false);
  log.debug("Leaving endSessionById(). " + (session ? 'Ended.' : 'There was no such session.'));
  return session;
}

// Clear the session cookie on this response, whatever the session it named. It
// is the second half of a browser sign-out and it is EXPORTED because /logout
// can end the caller's own session by id — through the list, like any other row
// — and would otherwise leave the browser holding a cookie naming a session
// this service no longer has. Same attributes it was SET with, Secure included:
// a browser matches an expiry against the cookie it holds, and one that
// disagrees about Secure can leave the original in place — a sign-out that
// reports success and ends nothing.
function clearSessionCookie(res) {
  res.set('Set-Cookie', SESSION_COOKIE + '=; Path=/; Max-Age=0' +
                        (config.value('global.https') ? '; Secure' : ''));
}

// Ends the session the request carries, and returns it — the caller needs what it
// was, not merely that it is gone: WS-Federation's sign-out has to send a cleanup
// request to each relying party the session signed into, and that list lives on
// the session object it is about to discard.
function endSession(req, res) {
  log.debug("Entering endSession().");
  const id = cookiesOf(req)[SESSION_COOKIE];
  const session = dropSession(id, 'the sign-out endpoint for this browser', !!id);
  clearSessionCookie(res);
  log.debug("Leaving endSession(). " + (session ? 'Dropped the session for ' + session.user.username + '.'
                                                : 'There was no session to drop.'));
  return session || null;
}

// ---------------------------------------------------------------------------
// WHERE THIS APPLICATION'S PEOPLE SIGN IN, if its entry says.
//
// An application entry may name a federation relationship
// (`appFederationRelationship`), which is the registry answering a question it
// could not answer before: a relationship under `ou=federations` says how to
// talk to a foreign identity provider and nothing about WHO should be sent
// there, and until this attribute existed the only answer was a person
// choosing a button at the foot of the screen below — home realm discovery
// performed by the user, once per sign-in.
//
// FOUR CHECKS, AND EACH OF THEM IS MADE HERE RATHER THAN AT THE WRITE.
// The attribute is a string on a directory entry: `ldapmodify` reaches it, so
// does the management API, and the relationship it names can be disabled or
// deleted afterwards by somebody who never looked at this application. A check
// made when it was written would therefore be a check about the past. The
// relationship must exist IN THIS REALM (the register is per realm, so an id
// from another realm names nothing here), must be service-provider-side (the
// other direction is this service asserting TO that partner — there is nothing
// to sign in to), must be enabled, and must be fully configured.
//
// A failure of any of them is REPORTED rather than swallowed, in `problem`,
// and the caller shows it on the sign-in screen. The alternative — falling
// silently back to the password box — is a federated application quietly
// authenticating people locally, which looks exactly like it working.
//
// Returns null when there is nothing to say: no application named, no entry,
// or no relationship on the entry. That is the ordinary case and it is the
// first thing checked, because every sign-in in this service passes through
// here.
// ---------------------------------------------------------------------------
function federationFor(applicationId) {
  log.debug("Entering federationFor(). application=" +
            (applicationId || '(none)'));
  const wanted = String(applicationId || '').trim();
  if (!wanted) {
    log.debug("Leaving federationFor(). The caller named no application.");
    return null;
  }
  let entry = null;
  try {
    entry = applications.get(wanted);
  } catch (e) {
    // Swallowed with a reason, and it is the same reason
    // federatedOptionsHtml() below swallows the register's: this runs on the
    // way to the sign-in screen, so a registry that throws must cost the
    // shortcut and never the screen.
    log.error('authn: the application registry threw while looking "' + wanted +
              '" up on the way to the sign-in screen and was ignored; the ' +
              'screen itself is unaffected: ' + e.message);
    log.debug("Leaving federationFor(). The registry threw.");
    return null;
  }
  const named = String(((entry || {}).fields ||
                        {}).appFederationRelationship || '').trim();
  if (!named) {
    log.debug("Leaving federationFor(). That application names no partner.");
    return null;
  }
  const auto = federation.boolOf(((entry || {}).fields ||
                                  {}).appFederationAutoRedirect, true);
  // THE FOUR CHECKS ARE federation.js's, not this function's, since
  // fedAuthnRelationship gave them a second caller — see
  // usableServiceProvider() there. They were written out here first and
  // copying them was never going to hold: a relationship id on an application
  // entry and one on another relationship are the same string, checkable the
  // same four ways, and two implementations of "would this actually work"
  // would answer differently the first time one of them learned a fifth.
  const usable = federation.usableServiceProvider(
    named, 'This application');
  if (usable.problem) {
    log.debug("Leaving federationFor(). " + usable.problem);
    return { id: named, relationship: null, auto: auto,
             problem: usable.problem };
  }
  log.debug("Leaving federationFor(). " + named + ", auto=" + auto + ".");
  return { id: named, relationship: usable.relationship, auto: auto,
           problem: '' };
}

// ---------------------------------------------------------------------------
// WHAT THIS SIGN-IN IS ACTUALLY GOING TO DO, from the two places that can say.
//
// This is the ONE order in which the two sources are read, and writing it in
// one function is the price of having two. They answer different questions and
// that is why both exist:
//
//   * an IDENTITY-PROVIDER-SIDE RELATIONSHIP answers "when this partner asks
//     me to authenticate somebody, what do I do?" — a fact about the
//     relationship, and the one that makes this service an identity BRIDGE:
//     `fedAuthnMechanism: federation` sends the person to a relationship in
//     the other direction, so a SAML 2.0 partner is satisfied by a
//     WS-Federation identity provider that this service consumes from. That
//     partner never learns it happened, which is the same property the
//     application at the top of the chain has, one layer down.
//
//   * an APPLICATION ENTRY answers "where do this application's people sign
//     in?" — `appFederationRelationship`, home realm discovery by
//     configuration, and what this service has done since 2026-08-26.
//
// THE RELATIONSHIP WINS, when one has anything to say. It is the more specific
// statement: an application entry may be a federation partner AND an ordinary
// OAuth client, registered by two different people, and only one of those two
// facts is about the exchange actually in progress.
//
// AN EMPTY MECHANISM IS NOT AN ANSWER. A relationship that declares none —
// which is every relationship created before the attribute existed — falls
// through to the application entry and then to the screen, so this function
// returns exactly what federationFor() alone used to return for every
// configuration that predates it. That is the whole compatibility argument and
// it is why authenticationFor() returns null rather than 'password'.
//
// A PROBLEM IS CARRIED RATHER THAN THROWN. Both sources report a relationship
// that is missing, disabled, half-configured or pointing the wrong way as a
// `problem` string, and the screen prints it. Falling silently back to the
// password box is the failure worth being loud about: a federated application
// authenticating people locally looks exactly like a federated application
// working, and a BROKER that has quietly stopped brokering looks exactly like
// one that is.
// ---------------------------------------------------------------------------
function mechanismFor(applicationId) {
  log.debug("Entering mechanismFor(). application=" +
            (applicationId || '(none)'));
  const wanted = String(applicationId || '').trim();
  if (!wanted) {
    log.debug("Leaving mechanismFor(). The caller named no application.");
    return { mechanism: 'password', source: 'default', federation: null,
             via: '', problem: '' };
  }
  let broker = null;
  try {
    broker = federation.authenticationFor(
      federation.identityProviderFor(wanted));
  } catch (e) {
    // Swallowed for federationFor()'s reason and no other: this runs on the
    // way to the sign-in screen, so a register that throws must cost the
    // shortcut and never the screen. It is logged at error because a throw
    // here is a bug in this service rather than a configuration.
    log.error('authn: the federation register threw while looking for an ' +
              'identity-provider-side relationship naming "' + wanted +
              '" and was ignored; the sign-in screen itself is unaffected: ' +
              e.message);
    broker = null;
  }
  if (broker) {
    const home = broker.relationship
      ? { id: broker.onward, relationship: broker.relationship, auto: true,
          problem: '' }
      : null;
    log.info('authn: the federation relationship "' + broker.via + '" says ' +
             'this sign-in is "' + (broker.mechanism || 'unrecognised') +
             '"' + (broker.onward ? ', through "' + broker.onward + '"' : '') +
             (broker.problem ? ' — and it cannot be done: ' + broker.problem
                             : '') + '.');
    log.debug("Leaving mechanismFor(). The relationship decided it.");
    return { mechanism: broker.mechanism || 'password',
             source: 'relationship', federation: home, via: broker.via,
             problem: broker.problem };
  }
  const home = federationFor(wanted);
  if (home) {
    log.debug("Leaving mechanismFor(). The application entry decided it.");
    return { mechanism: 'federation', source: 'application', federation: home,
             via: '', problem: home.problem };
  }
  log.debug("Leaving mechanismFor(). Nothing configured; the screen it is.");
  return { mechanism: 'password', source: 'default', federation: null,
           via: '', problem: '' };
}

// ---------------------------------------------------------------------------
// THE ENTRY POINT A PROTOCOL MODULE CALLS.
//
//   returnTo   where to send the browser once they are signed in — a path on
//              this service, carrying the caller's original request whole, so
//              that running it again is the same request over again.
//   details    rows for the screen's footer: [{ label, value, note }]. The
//              caller writes them because only the caller knows what its own
//              parameters mean.
//   hint       what to pre-fill the username with (OIDC's login_hint, and
//              whatever the next protocol calls its equivalent).
//   forceMfa   the caller has been told a second factor is required, so the
//              opt-out is taken away rather than offered.
//   protocol   what to record the sign-in AS, for the admin console — this
//              service cannot tell, and "every sign-in is an OIDC one" is
//              exactly the wrong answer once more than one protocol uses it.
//   application the identifier the caller's own protocol presented — a
//              client_id, an entityID, a relying party id. OPTIONAL, and every
//              caller that has one passes it, because it is what decides
//              whether this sign-in is federated: see federationFor() above.
//              Nothing else is done with it, and an identifier this registry
//              has never heard of is not an error.
//
// Returns the path to redirect to. A path rather than a full URL: the browser
// is already on this origin, and building an absolute URL here would mean
// guessing the base the caller was reached on. IT IS NOT ALWAYS THIS MODULE'S
// SCREEN — an application whose entry names a usable federation relationship,
// with the auto-redirect left on, is answered with the federated flow's own
// entry point instead. The caller cannot tell the two apart and must not: what
// it asked for is "get this person authenticated and bring them back to
// returnTo", and which identity provider does the authenticating is not its
// business. That is the same property the buttons at the foot of the screen
// have had all along; what is new is that nobody has to press one.
// ---------------------------------------------------------------------------
function beginAuthentication(opts) {
  log.debug("Entering beginAuthentication(). protocol=" + (opts.protocol || '(unnamed)'));
  const returnTo = String(opts.returnTo || '');
  // Same-origin, and a path: see the header. A caller that gets this wrong is a
  // bug in this service rather than a hostile request, so it throws rather than
  // quietly signing somebody in and sending them somewhere else.
  if (returnTo.charAt(0) !== '/' || returnTo.charAt(1) === '/') {
    throw new Error('beginAuthentication() needs a path on this service to return to, not "' +
                    returnTo + '".');
  }
  // ---------------------------------------------------------------------
  // HOME REALM DISCOVERY BY CONFIGURATION, and it happens BEFORE a pending
  // record is written because there is nothing pending: the browser is going
  // to a foreign identity provider and comes back to `/federation/acs/{id}`,
  // which finishes the sign-in through startSession() without this screen ever
  // being drawn. A record minted here would be one nothing could ever spend.
  //
  // `returnTo` has already been checked to be a path on this service, and
  // `federation_sp.js` checks it AGAIN on the way in — see decision 4 there.
  // Two checks on one value is deliberate: this one catches a caller's bug and
  // that one catches somebody handing the federated entry point a returnTo of
  // their own.
  // ---------------------------------------------------------------------
  const chosen = mechanismFor(opts.application);
  const home = chosen.federation;
  if (home && home.relationship && home.auto) {
    const target = federation.PATHS.login + '/' +
      encodeURIComponent(home.relationship.fedId) +
      '?returnTo=' + encodeURIComponent(returnTo);
    log.info('authn: "' + String(opts.application) + '" authenticates through ' +
             'the federation relationship "' + home.relationship.fedId +
             '"' + (chosen.source === 'relationship'
                      ? ', because the identity-provider-side relationship "' +
                        chosen.via + '" brokers it there'
                      : '') +
             ', so this sign-in goes straight there rather than to the sign-in ' +
             'screen.');
    log.debug("Leaving beginAuthentication(). Federated to " +
              home.relationship.fedId + ".");
    return target;
  }
  // ---------------------------------------------------------------------
  // THE THREE MECHANISMS THAT STILL DRAW THIS SCREEN, folded into the record
  // the screen is drawn from rather than handled beside it — so that a
  // relationship configuring `password-mfa` and a RequestedAuthnContext
  // demanding two factors produce ONE screen and not two code paths that
  // could come to differ.
  //
  // forceMfa WINS OVER forcePasswordless and says so in the log. They are
  // mutually exclusive by construction — one enum value, one mechanism — but
  // `opts.forceMfa` does not come from the register at all: it comes from the
  // request a protocol module is answering, and a caller that has been told
  // two factors are required does not get a one-factor answer because a
  // relationship preferred one. `webauthn` here is PASSWORDLESS, which is amr
  // ["hwk"] and a single factor, however phishing-resistant it is.
  // ---------------------------------------------------------------------
  const forceMfa = !!opts.forceMfa || chosen.mechanism === 'password-mfa';
  let forcePasswordless = chosen.mechanism === 'webauthn';
  if (forcePasswordless && forceMfa) {
    log.info('authn: the configured mechanism for "' +
             String(opts.application || '(none)') + '" is a passwordless ' +
             'security key, and this request demands two factors, so the ' +
             'demand wins: the screen asks for a password and a key. One ' +
             'factor does not answer a request for two, however ' +
             'phishing-resistant that factor is.');
    forcePasswordless = false;
  }
  const record = {
    id: randomId(18),
    returnTo: returnTo,
    details: Array.isArray(opts.details) ? opts.details : [],
    hint: String(opts.hint || ''),
    forceMfa: forceMfa,
    // Set only by a relationship configuring `webauthn`. Nothing a protocol
    // module passes can turn it on: a caller asking for a passwordless
    // sign-in is a caller choosing somebody else's authenticator for them,
    // which is a deployment decision and not a request parameter.
    forcePasswordless: forcePasswordless,
    mechanism: chosen.mechanism,
    mechanismSource: chosen.source,
    mechanismVia: chosen.via,
    // The problem is on the RECORD and not only inside `federation`, because
    // the two sources fail differently: an application entry naming an
    // unusable relationship still produces a `federation` object to hang it
    // on, and a BROKERING relationship whose onward partner is disabled
    // produces no such object at all — there is nothing usable to describe.
    // Reading it from one place is what stops the second case being the
    // silent fallback the first case was made loud to prevent.
    mechanismProblem: chosen.problem || '',
    protocol: opts.protocol || 'OAuth 2.0 / OIDC',
    // Carried so the screen can offer the RIGHT partner rather than every
    // usable one, and so that a relationship this application names and cannot
    // use is reported instead of being replaced by a password box.
    application: String(opts.application || ''),
    federation: home,
    expires: Date.now() + AUTHN_TTL_MS
  };
  pending.set(record.id, record);
  pending.forEach(function (v, k) {
    if (v.expires < Date.now()) pending.delete(k);
  });
  log.debug("Leaving beginAuthentication(). " + record.id + " will return to " + returnTo + ".");
  return LOGIN_PATH + '?authn=' + encodeURIComponent(record.id);
}

// Back where they came from, with the outcome on the query string. An error is
// named in `authn_error` and the CALLER decides what its protocol does about
// it; a success carries nothing at all, because the session cookie is the
// answer and a parameter saying so would be a second, weaker way to ask.
function returnToCaller(res, record, error, description) {
  log.debug("Entering returnToCaller(). error=" + (error || '(none)'));
  let target = record.returnTo;
  if (error) {
    target += (target.indexOf('?') === -1 ? '?' : '&') +
      'authn_error=' + encodeURIComponent(error) +
      '&authn_error_description=' + encodeURIComponent(description || '');
  }
  // ---------------------------------------------------------------------
  // 303, NOT 302, AND NEVER 307 — RFC 9700 section 4.12.
  //
  // This is the redirect that follows the POST carrying somebody's username and
  // password, and it is the one place in this service where the choice of
  // status code is a security question rather than a formality. A 307 PRESERVES
  // the method and the body, so the browser would repeat the POST — credentials
  // and all — to wherever this points, which is a URL the CALLING PROTOCOL
  // composed. That is the section's whole point: the authorization server hands
  // the user's password to the client without either of them doing anything
  // wrong.
  //
  // This service has never used 307. What it used was 302, whose behaviour after
  // a POST is historically ambiguous — every browser turns it into a GET, and
  // the specification does not say they must. 303 says it: change the method to
  // GET. The section asks for 303 by name and there is no reason not to give it.
  //
  // It is NOT gated on RFC 9700 mode, unlike the refusals that mode adds. No
  // client can tell the difference — a browser does the same thing with both —
  // so gating it would leave the default deployment with the ambiguous one and
  // buy nobody an exercise.
  //
  // `returnToCaller()` is the single funnel: the password step and the WebAuthn
  // step both leave through here, so there is one place where this is decided
  // rather than two that could come to differ.
  // ---------------------------------------------------------------------
  res.redirect(303, target);
  log.debug("Leaving returnToCaller(). Sent the browser to " + target + " with a 303.");
}

// The record a request names, or null — expired ones are dropped on the way
// past, which is the only cleanup this store needs beyond the sweep above.
function pendingFor(id) {
  log.debug("Entering pendingFor(). id=" + (id || '(none)'));
  const record = pending.get(String(id || ''));
  if (!record) {
    log.debug("Leaving pendingFor(). No such authentication is pending.");
    return null;
  }
  if (record.expires < Date.now()) {
    pending.delete(record.id);
    log.debug("Leaving pendingFor(). It had expired.");
    return null;
  }
  log.debug("Leaving pendingFor(). Found it.");
  return record;
}

// The screen itself. Unchanged from the one that used to be rendered inside the
// authorization endpoint, in everything a person or a test can see: the same
// element ids (`username`, `password`, `kc-login`, `kc-cancel`), the same
// Keycloak-shaped vocabulary, the same statement that no password is checked.
// What changed is where it lives, what it posts to, and that its footer rows
// are supplied rather than read off an authorization request.
// The partner buttons, or nothing at all. Nothing at all is the ordinary state
// — a service with no federation configured must have a sign-in screen byte for
// byte the one it always had, which is why this returns an empty string rather
// than an empty section with a heading.
function federatedOptionsHtml(record) {
  log.debug("Entering federatedOptionsHtml().");
  // ---------------------------------------------------------------------
  // THE APPLICATION'S OWN PARTNER FIRST, AND ON ITS OWN.
  //
  // An entry naming a relationship has answered the question this list is
  // asking, so offering the other partners beside it would be putting the
  // discovery step back one line below the configuration that removed it.
  //
  // IT IGNORES `federation.loginButtons`, which the generic list below
  // respects, and the asymmetry is the point rather than an oversight: that
  // setting exists so that a service with no federation configured has a
  // sign-in screen byte for byte the one it always had, and an application
  // whose entry names a partner IS federation configured. The auto-redirect
  // above cannot consult a screen setting either — it never draws a screen —
  // so honouring it here would make the same configuration behave two ways
  // depending on one unrelated boolean.
  // ---------------------------------------------------------------------
  const home = record.federation;
  if (home && home.relationship) {
    const html = federatedButtons(record, [{
      id: home.relationship.fedId,
      label: home.relationship.fedName || home.relationship.fedId,
      protocolLabel: (federation.protocolRow(home.relationship.fedProtocol) ||
                      {}).label || home.relationship.fedProtocol,
      peer: home.relationship.fedPeer
    }], 'This application signs its users in at a federated identity ' +
        'provider. No password is typed here and none is checked there ' +
        'either as far as this service can tell — what it checks is the ' +
        'partner\'s signature.');
    log.debug("Leaving federatedOptionsHtml(). The application's own partner.");
    return html;
  }
  if (!config.value('federation.loginButtons')) {
    log.debug("Leaving federatedOptionsHtml(). federation.loginButtons is off.");
    return '';
  }
  let options = [];
  try {
    options = federation.signInOptions();
  } catch (e) {
    // Swallowed with a reason: the sign-in screen is the last thing in this
    // service that may fail to draw. A federation register that throws costs
    // the buttons, never the password field underneath them.
    log.error('authn: the federation register threw while building the sign-in ' +
              'screen and was ignored; the screen itself is unaffected: ' + e.message);
    log.debug("Leaving federatedOptionsHtml(). It threw.");
    return '';
  }
  if (!options.length) {
    log.debug("Leaving federatedOptionsHtml(). No usable partner is configured.");
    return '';
  }
  const html = federatedButtons(record, options,
    'Or sign in with a federated identity provider. No password is typed here ' +
    'and none is checked there either as far as this service can tell — what ' +
    'it checks is the partner\'s signature.');
  log.debug("Leaving federatedOptionsHtml(). " + options.length + " partner(s) offered.");
  return html;
}

// The markup, once, for both of the lists above. One function because the two
// differ only in WHICH partners and what the sentence over them says, and two
// copies of an anchor carrying a returnTo is two chances to drop the returnTo
// from one of them — which produces a federated sign-in that succeeds and lands
// the person on a page nobody asked for.
function federatedButtons(record, options, blurb) {
  log.debug("Entering federatedButtons(). " + options.length + " option(s).");
  // The whole original request rides along, so that whatever brought the person
  // here resumes once the partner has answered. It is `record.returnTo`, which
  // beginAuthentication() has already checked is a path on this service.
  const back = encodeURIComponent(record.returnTo);
  const html = '<div class="fed"><p>' + blurb + '</p>' +
    options.map(function (one) {
      return '<a class="fedbtn" href="/federation/login/' + encodeURIComponent(one.id) +
        '?returnTo=' + back + '">' + xmlEscape(one.label) +
        '<span>' + xmlEscape(one.protocolLabel) +
        (one.peer ? ' · ' + xmlEscape(one.peer) : '') + '</span></a>';
    }).join('') + '</div>';
  log.debug("Leaving federatedButtons().");
  return html;
}

function loginPage(base, record, error) {
  log.debug("Entering loginPage(). protocol=" + record.protocol +
            (error ? ", showing an error" : ""));
  const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<title>Sign in — mock authentication service</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:28px 32px;width:380px;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.25em;margin:0 0 4px}' +
    'p.sub{color:#666;font-size:.85em;margin:0 0 18px}label{display:block;font-size:.85em;font-weight:600;' +
    'margin:12px 0 4px}input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:8px 10px;' +
    'border:1px solid #bbb;border-radius:5px;font-size:1em}.row{display:flex;gap:10px;margin-top:20px}' +
    'button{flex:1;padding:9px 12px;border-radius:5px;border:1px solid #12107c;background:#12107c;color:#fff;' +
    'font-size:.95em;cursor:pointer}button.secondary{background:#fff;color:#12107c}' +
    '.err{background:#fdecea;border:1px solid #f5c6c2;color:#b00020;padding:8px 10px;border-radius:5px;' +
    'font-size:.85em;margin-bottom:12px}.meta{margin-top:20px;padding-top:14px;border-top:1px solid #eee;' +
    'font-size:.75em;color:#777;word-break:break-all}.meta div{margin:2px 0}code{font-family:ui-monospace,' +
    'SFMono-Regular,Menlo,monospace}.fed{margin-top:18px;padding-top:14px;border-top:1px solid #eee}.fed p{font-size:.78em;color:#666;margin:0 0 8px}a.fedbtn{display:block;text-align:center;padding:9px 12px;margin:6px 0;border-radius:5px;border:1px solid #12107c;color:#12107c;background:#fff;text-decoration:none;font-size:.9em}a.fedbtn span{display:block;font-size:.75em;color:#777}'
    + '</style></head><body><div class="card">' +
    '<h1>Sign in</h1>' +
    '<p class="sub">Mock authentication service at <code>' + xmlEscape(base) + '</code></p>' +
    (error ? '<div class="err">' + xmlEscape(error) + '</div>' : '') +
    '<form method="post" action="' + LOGIN_PATH + '">' +
    '<input type="hidden" name="authn_id" value="' + xmlEscape(record.id) + '">' +
    '<label for="username">Username</label>' +
    '<input type="text" id="username" name="username" autocomplete="username" autofocus' +
    ' value="' + xmlEscape(record.hint) + '">' +
    '<label for="password">Password</label>' +
    '<input type="password" id="password" name="password" autocomplete="current-password">' +
    // Two checkboxes rather than one, because a security key is two different
    // things here and the difference is what the tokens end up claiming: ticked
    // with a password it is a SECOND factor (amr ["pwd","hwk"], acr "mfa"), and
    // on its own it is the PRIMARY one (amr ["hwk"], acr "1"). They cannot be
    // made exclusive in the browser — this screen runs no script, by design, and
    // an inline one would not run under script-src 'none' — so the POST handler
    // decides between them and `webauthn_only` wins. Under forceMfa the
    // passwordless box is disabled: one factor does not answer a request for
    // two, however phishing-resistant that factor is.
    // forcePasswordless is the mirror image and arrives from the OTHER
    // direction: forceMfa is a demand the CALLING PROTOCOL made, and this is a
    // mechanism an operator CONFIGURED on the federation relationship the
    // partner is registered under (fedAuthnMechanism: webauthn). Both end here
    // because both decide what this one screen offers, and they cannot both be
    // on — beginAuthentication() resolves that, loudly, before the record is
    // written.
    //
    // THE HIDDEN INPUT IS NOT THE ENFORCEMENT. A disabled checkbox posts
    // nothing and a hidden one can be deleted by anybody with the developer
    // tools open, so handleLogin() reads the RECORD as well: see the note
    // there. The markup is what a person sees; the record is what decides.
    '<label class="chk"><input type="checkbox" id="use_webauthn" name="use_webauthn" value="1"' +
    (record.forceMfa ? ' checked disabled' : '') +
    (record.forcePasswordless ? ' disabled' : '') +
    '> Use a security key (WebAuthn) as a second factor' +
    (record.forcePasswordless
       ? ' — not available: this partner is configured for a passwordless key'
       : '') + '</label>' +
    (record.forceMfa ? '<input type="hidden" name="use_webauthn" value="1">' : '') +
    '<label class="chk"><input type="checkbox" id="webauthn_only" name="webauthn_only" value="1"' +
    (record.forceMfa ? ' disabled' : '') +
    (record.forcePasswordless ? ' checked disabled' : '') +
    '> Sign in with the security key alone (passwordless — ' +
    'no password step, and the tokens will say one factor)' +
    (record.forceMfa ? ' — not available: this request demands two factors' : '') +
    (record.forcePasswordless
       ? ' — required: the federation relationship "' +
         xmlEscape(record.mechanismVia || '') + '" configures this'
       : '') + '</label>' +
    (record.forcePasswordless
       ? '<input type="hidden" name="webauthn_only" value="1">' : '') +
    '<div class="row"><button type="submit" id="kc-login" name="action" value="login">Sign In</button>' +
    '<button type="submit" id="kc-cancel" name="action" value="cancel" class="secondary">Cancel</button></div>' +
    '</form>' +
    // ---------------------------------------------------------------------
    // AND THE FEDERATION PARTNERS, if any are configured and usable.
    //
    // THIS IS WHY THE BUTTONS ARE HERE RATHER THAN ONLY ON /federation: a
    // person arriving at this screen is in the middle of SOMETHING — an OAuth
    // 2.0 authorization request, a WS-Federation sign-in, a SAML AuthnRequest,
    // the admin console — and `record.returnTo` is that something, whole. Handing
    // it to the federated flow is what lets a foreign identity provider satisfy
    // any protocol this service speaks, without a single one of them being told
    // that federation exists.
    //
    // ONLY USABLE ONES ARE OFFERED. `signInOptions()` filters to relationships
    // that are enabled AND fully configured, because a button leading to a
    // refusal is worse than no button — the person has already left this screen
    // by the time they find out.
    //
    // They are LINKS rather than buttons in the form, and that is not
    // cosmetic: a form control would post to this screen's own handler, which
    // signs somebody in on a typed name. These have to leave for somewhere
    // else entirely, and a GET is what leaving looks like.
    // ---------------------------------------------------------------------
    federatedOptionsHtml(record) +
    '<div class="meta">' +
    '<div>No password is checked. The username you enter is the identity the issued tokens describe.</div>' +
    '<div>Passwordless: the password field is not read at all, and the security key becomes the ' +
    'only factor — a key is enrolled for this username on first use, so the first person to claim ' +
    'a name here gets it. This service authenticates nobody; that is the same statement as the ' +
    'line above and not a weaker one.</div>' +
    '<div>Signing in for: <code>' + xmlEscape(record.protocol) + '</code></div>' +
    record.details.map(function (d) {
      return '<div>' + xmlEscape(d.label) + ': <code>' + xmlEscape(d.value == null ? '' : d.value) +
             '</code>' + (d.note ? ' (' + xmlEscape(d.note) + ')' : '') + '</div>';
    }).join('') +
    '</div></div></body></html>\n';
  log.debug("Leaving loginPage().");
  return page;
}

function sendLoginPage(res, html) {
  res.status(200).type('text/html').set('Cache-Control', 'no-store').send(html);
}

// The screen. A GET, because that is what a redirect from a protocol endpoint
// produces — and it is why this is a service rather than a page: it can be
// linked, reloaded and bookmarked while the request it interrupted waits.
app.get(LOGIN_PATH, function (req, res) {
  log.debug("Entering the authentication screen.");
  const record = pendingFor((req.query || {}).authn);
  if (!record) {
    log.debug("Leaving the authentication screen. Nothing is pending under that id.");
    return oauthError(res, 400, 'invalid_request',
      'There is no sign-in waiting under that id, or it has expired. Start the request again ' +
      'from the application that sent you here.');
  }
  // A relationship this application NAMES and cannot use is shown here rather
  // than being replaced silently by the password box below it. That fallback is
  // the failure worth being loud about: a federated application authenticating
  // people locally looks exactly like a federated application working.
  const problem = record.mechanismProblem ||
                  ((record.federation || {}).problem) || '';
  sendLoginPage(res, loginPage(baseUrlOf(req), record, problem));
  log.debug("Leaving the authentication screen. Showed the form for " + record.id +
            (problem ? ", with a federation problem." : "."));
});

// The form target. Everything that can go wrong here re-renders the screen with
// a message rather than redirecting: the person is mid-authentication and the
// request they interrupted is still waiting.
app.post(LOGIN_PATH, function (req, res) {
  log.debug("Entering the authentication endpoint.");
  const base = baseUrlOf(req);
  const body = parseBody(req);
  const record = pendingFor(body.authn_id);
  if (!record) {
    log.debug("Leaving the authentication endpoint. The form had expired.");
    return oauthError(res, 400, 'invalid_request',
      'This sign-in form has expired. Start the request again from the application that sent ' +
      'you here.');
  }

  if (String(body.action || '') === 'cancel') {
    pending.delete(record.id);
    log.debug("Leaving the authentication endpoint. The user cancelled.");
    return returnToCaller(res, record, 'access_denied',
      'The user cancelled at the sign-in screen.');
  }

  const username = String(body.username || '').trim();
  // The only two ways to fail: no username to put in the tokens, and the
  // reserved password the rest of this mock also refuses.
  if (!username) {
    log.debug("Leaving the authentication endpoint. No username was entered, so the form is shown again.");
    return sendLoginPage(res, loginPage(base, record,
      'Enter a username. It does not have to exist — it is the identity the issued tokens will ' +
      'describe.'));
  }
  // Which role the security key is in, if it is in one at all. The two boxes
  // cannot be made exclusive on a screen that runs no script, so a POST can
  // carry both — and `webauthn_only` wins, because the two mean different
  // things and answering "both" with the second-factor path would put somebody
  // through a password step they explicitly asked not to have.
  // READ OFF THE RECORD AND NOT ONLY OFF THE BODY. The screen posts a hidden
  // `webauthn_only` when the mechanism demands one, and a hidden input is a
  // suggestion: it is deleted by anybody with the developer tools open, and
  // the request that arrives then looks exactly like an ordinary password
  // sign-in. A configured mechanism that a client can opt out of is not a
  // mechanism, so the record decides and the markup only shows.
  const passwordless = !!record.forcePasswordless ||
                       String(body.webauthn_only || '') === '1';
  const secondFactor = !passwordless && String(body.use_webauthn || '') === '1';

  // A caller that demanded a second factor does not get the passwordless path.
  // The checkbox is rendered disabled for this reason and THIS is the check that
  // matters: `disabled` is a property of a browser, not of an HTTP request, and
  // the whole value of acr_values and wauth is that the answer cannot be chosen
  // by whoever is answering.
  if (passwordless && record.forceMfa) {
    log.debug("Leaving the authentication endpoint. Passwordless was asked for where the caller " +
              "demands a second factor, so the form is shown again.");
    return sendLoginPage(res, loginPage(base, record,
      'This request asked for a second factor, so a security key on its own cannot answer it — ' +
      'one factor is one factor. Sign in with a password and the key together.'));
  }

  // The reserved password the rest of this mock also refuses. It is not read at
  // all on the passwordless path: no password was presented there, so there is
  // nothing to refuse, and failing a field the screen says it will ignore would
  // make the screen wrong about what it does.
  if (!passwordless && String(body.password || '') === 'invalid') {
    log.debug("Leaving the authentication endpoint. The reserved password was used, so the form is shown again.");
    return sendLoginPage(res, loginPage(base, record, 'Authentication failed for ' + username + '.'));
  }

  // The security key, in whichever role. On the second-factor path the password
  // step has succeeded and the session is NOT created yet, because a session
  // created here and upgraded later would be a valid single-factor session in
  // the window between — and a request arriving in that window would be answered
  // with tokens that claim one factor's worth of assurance and carry none of the
  // second's. On the passwordless path there is nothing to upgrade FROM, and the
  // rule holds for the same reason: nothing has been authenticated until the
  // ceremony verifies.
  if (passwordless || secondFactor) {
    pending.delete(record.id);
    const mfaId = randomId(24);
    pendingMfa.set(mfaId, {
      authn: record, username: username,
      challenge: crypto.randomBytes(32).toString('base64url'),
      // Which role, carried on the pending record rather than re-read from the
      // POST at the other end: that POST is the browser's ceremony result and
      // nothing in it says what the person chose a screen ago. Everything the
      // session then claims — amr, acr, and whether the directory entry is
      // flagged as multi-factor — is decided from this one boolean.
      passwordless: passwordless,
      expires: Date.now() + MFA_TTL_MS
    });
    pendingMfa.forEach(function (v, k) {
      if (v.expires < Date.now()) pendingMfa.delete(k);
    });
    log.debug("Leaving the authentication endpoint. " + username +
              (passwordless ? " asked for a passwordless sign-in; asking for the security key."
                            : " passed the password step; asking for the security key."));
    return sendWebauthnPage(res, webauthnPage(base, mfaId, username, ''));
  }

  pending.delete(record.id);
  // One factor, and the tokens will say so.
  startSession(res, username, ['pwd'], '1', record.protocol);

  // Back to whatever sent them here, with its own original request — which now
  // runs a second time, sees the session cookie, and completes.
  returnToCaller(res, record, null, null);
  log.debug("Leaving the authentication endpoint. " + username + " is signed in; back to " +
            record.returnTo + ".");
});

// The security-key screen, and it is ONE screen for both roles. It performs the
// ceremony in the browser against THIS origin — the RP ID is the STS's own host,
// because WebAuthn binds a ceremony to the calling origin and no amount of
// configuration changes that.
//
// Registration on first use, assertion afterwards: a mock authorization server
// that demanded an already-enrolled key would be untestable without a manual
// enrolment step, and the interesting artifacts are the same either way.
//
// What differs between the roles is what the page SAYS, not what it does — the
// ceremony a second factor performs and the one a passwordless sign-in performs
// are the same bytes. It says it anyway, because the difference is what the
// session ends up claiming and a person reading the tokens afterwards has to be
// able to tell which one they did.
function webauthnPage(base, mfaId, username, error) {
  log.debug("Entering webauthnPage(). username=" + username);
  const known = webauthnCredentials.get(username);
  const mode = known ? 'get' : 'create';
  const step = pendingMfa.get(mfaId);
  // Absent where the step has already gone — an expired id reaches this
  // function through one of the error paths — and false is the safe reading:
  // the page then describes the more cautious of the two roles.
  const passwordless = !!(step && step.passwordless);
  const html = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<title>Security key — mock authentication service</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:28px 32px;width:420px;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.25em;margin:0 0 4px}' +
    'p.sub{color:#666;font-size:.85em;margin:0 0 18px}button{padding:9px 12px;border-radius:5px;' +
    'border:1px solid #12107c;background:#12107c;color:#fff;font-size:.95em;cursor:pointer;width:100%}' +
    '.err{background:#fdecea;border:1px solid #f5c6c2;color:#b00020;padding:8px 10px;border-radius:5px;' +
    'font-size:.85em;margin-bottom:12px}.meta{margin-top:20px;padding-top:14px;border-top:1px solid #eee;' +
    'font-size:.75em;color:#777;word-break:break-all}.meta div{margin:2px 0}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}</style></head><body>' +
    '<div class="card"><h1>' + (mode === 'create' ? 'Enrol a security key' : 'Use your security key') + '</h1>' +
    '<p class="sub">' + (passwordless
      ? 'Passwordless sign-in as <code>' + xmlEscape(username) + '</code> — the key is the only factor'
      : 'Second factor for <code>' + xmlEscape(username) + '</code>') + '</p>' +
    (error ? '<div class="err">' + xmlEscape(error) + '</div>' : '') +
    '<button id="wa-go" type="button">' +
    (mode === 'create' ? 'Enrol security key' : 'Authenticate with security key') + '</button>' +
    '<form method="post" action="/authn/webauthn" id="wa-form">' +
    '<input type="hidden" name="mfa_id" value="' + xmlEscape(mfaId) + '">' +
    '<input type="hidden" name="mode" value="' + mode + '">' +
    '<input type="hidden" name="credential" id="wa-credential">' +
    '</form>' +
    // The ceremony's parameters travel as data attributes and the script is a
    // separate resource, so this page needs no inline script. That is not
    // fastidiousness: this service sets `script-src 'none'` on everything by
    // design (see app.js), and an inline script here would simply not run —
    // silently, with the button doing nothing. One page relaxes it to 'self',
    // which is the smallest exception that works.
    '<div id="wa-data"' +
    ' data-challenge="' + xmlEscape(step ? step.challenge : '') + '"' +
    ' data-rpid="' + xmlEscape(rpIdOf(base)) + '"' +
    ' data-user="' + xmlEscape(username) + '"' +
    ' data-allow="' + xmlEscape(known ? known.credentialId : '') + '"' +
    ' data-mode="' + mode + '"></div>' +
    '<div class="meta">' +
    '<div>RP ID: <code>' + xmlEscape(rpIdOf(base)) + '</code> — the ceremony is bound to this origin.</div>' +
    '<div>challenge: <code>' + xmlEscape(step ? step.challenge : '') + '</code></div>' +
    '<div>' + (mode === 'create'
      ? 'No key is enrolled for this user yet, so this step registers one.'
      : 'A key is already enrolled for this user, so this step is an assertion.') + '</div>' +
    '<div>' + (passwordless
      ? 'No password was presented. On success the session records amr ["hwk"] and acr "1" — ' +
        'ONE factor — and this counts as an authentication in its own right, so it appears on ' +
        '/admin/users and the directory grows an entry for ' + xmlEscape(username) + '.'
      : 'A password step has already succeeded. On success the session records amr ["pwd","hwk"] ' +
        'and acr "mfa", and the directory entry for ' + xmlEscape(username) + ' is flagged as ' +
        'having authenticated with more than one factor.') + '</div>' +
    '</div></div>' +
    '<script src="/authn/webauthn.js"></script></body></html>\n';
  log.debug("Leaving webauthnPage(). mode=" + mode);
  return html;
}

// The ceremony script, as its own resource. Written with split/join rather than
// regular expressions on purpose: this string passes through a JavaScript string
// literal on the way out, where `\+` collapses to `+` and `\/` to `/`, which
// silently produced `/+/g` and `///g` in the delivered script the first time
// this was written inline. split/join has nothing to escape.
const WEBAUTHN_SCRIPT = [
  '(function () {',
  '  var d = document.getElementById("wa-data");',
  '  var b64u = function (b) {',
  '    var s = btoa(String.fromCharCode.apply(null, new Uint8Array(b)));',
  '    return s.split("+").join("-").split("/").join("_").split("=").join("");',
  '  };',
  '  var bytes = function (s) {',
  '    var t = s.split("-").join("+").split("_").join("/");',
  '    while (t.length % 4) { t += "="; }',
  '    var bin = atob(t), out = new Uint8Array(bin.length);',
  '    for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }',
  '    return out;',
  '  };',
  '  var send = function (payload) {',
  '    document.getElementById("wa-credential").value = JSON.stringify(payload);',
  '    document.getElementById("wa-form").submit();',
  '  };',
  '  document.getElementById("wa-go").addEventListener("click", function () {',
  '    var challenge = bytes(d.getAttribute("data-challenge"));',
  '    var rpId = d.getAttribute("data-rpid");',
  '    var user = d.getAttribute("data-user");',
  '    var allow = d.getAttribute("data-allow");',
  '    var p;',
  '    if (d.getAttribute("data-mode") === "create") {',
  '      p = navigator.credentials.create({ publicKey: {',
  '        rp: { name: "Mock authorization server", id: rpId },',
  '        user: { id: new TextEncoder().encode(user), name: user, displayName: user },',
  '        challenge: challenge,',
  '        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],',
  '        authenticatorSelection: { userVerification: "preferred" },',
  '        attestation: "direct", timeout: 60000 } })',
  '        .then(function (c) { return { id: c.id, rawId: b64u(c.rawId), type: c.type, response: {',
  '          clientDataJSON: b64u(c.response.clientDataJSON),',
  '          attestationObject: b64u(c.response.attestationObject) } }; });',
  '    } else {',
  '      p = navigator.credentials.get({ publicKey: {',
  '        challenge: challenge, rpId: rpId,',
  '        allowCredentials: allow ? [{ type: "public-key", id: bytes(allow) }] : undefined,',
  '        userVerification: "preferred", timeout: 60000 } })',
  '        .then(function (a) { return { id: a.id, rawId: b64u(a.rawId), type: a.type, response: {',
  '          clientDataJSON: b64u(a.response.clientDataJSON),',
  '          authenticatorData: b64u(a.response.authenticatorData),',
  '          signature: b64u(a.response.signature),',
  '          userHandle: a.response.userHandle ? b64u(a.response.userHandle) : null } }; });',
  '    }',
  '    p.then(send).catch(function (e) { send({ error: e.name, message: e.message }); });',
  '  });',
  '})();',
  ''
].join('\n');

// The one page in this service that runs a script, and the one response that
// relaxes the policy for it — to 'self', not 'unsafe-inline', so the exception
// is a named resource rather than a hole. app.js sets script-src 'none' on
// everything by default and that default is worth keeping.
function sendWebauthnPage(res, html) {
  // Through the builder, so the framing clauses cannot be lost by editing this
  // line — see the note above contentSecurityPolicy() in app.js. What is being
  // relaxed is script-src and nothing else.
  res.set('Content-Security-Policy', app.contentSecurityPolicy({ 'script-src': "'self'" }));
  res.status(200).type('text/html').set('Cache-Control', 'no-store').send(html);
}

app.get('/authn/webauthn.js', function (req, res) {
  log.debug("Serving the WebAuthn ceremony script.");
  // A script resource cannot be clicked through, so framing it is not the
  // clickjacking vector the page it belongs to is — but it goes through the
  // builder anyway, because "this one does not need it" is the reasoning that
  // ends with a PAGE that does not have it.
  res.set('Content-Security-Policy', app.contentSecurityPolicy({ 'style-src': null,
                                                                 'img-src': null }));
  res.type('application/javascript').set('Cache-Control', 'no-store').send(WEBAUTHN_SCRIPT);
});

// The RP ID is the origin's HOST, never anything configurable. A mock that let
// you set it to something else would be teaching the one lesson WebAuthn exists
// to prevent.
function rpIdOf(base) {
  try {
    return new URL(base).hostname;
  } catch (e) {
    // A base that will not parse is a misconfiguration of this service rather
    // than of the ceremony; fall back to the literal so the page still says
    // something true about what it will send.
    return String(base).replace(/^https?:\/\//, '').split(':')[0];
  }
}

app.post('/authn/webauthn', function (req, res) {
  log.debug("Entering the WebAuthn second-factor endpoint.");
  const base = baseUrlOf(req);
  const body = parseBody(req);
  const step = pendingMfa.get(String(body.mfa_id || ''));
  if (!step || step.expires < Date.now()) {
    pendingMfa.delete(String(body.mfa_id || ''));
    log.debug("Leaving the WebAuthn endpoint. The step had expired.");
    return oauthError(res, 400, 'invalid_request',
      'This security-key step has expired. Start the request again from the application that ' +
      'sent you here.');
  }

  let credential;
  try {
    credential = JSON.parse(String(body.credential || '{}'));
  } catch (e) {
    log.debug("Leaving the WebAuthn endpoint. The posted credential was not JSON.");
    return sendWebauthnPage(res, webauthnPage(base, step.authn && String(body.mfa_id), step.username,
                         'The browser returned something this server could not read.'));
  }
  if (credential.error) {
    // The browser refused the ceremony. Its error is deliberately ambiguous —
    // no credential, declined, and timed out are one error — so report it as
    // given rather than guessing which happened.
    log.debug("Leaving the WebAuthn endpoint. The browser refused: " + credential.error);
    return sendWebauthnPage(res, webauthnPage(base, String(body.mfa_id), step.username,
        credential.error + ': ' + (credential.message || '') +
        '  (WebAuthn reports one error for several situations, so this does not say which.)'));
  }

  const expectedOrigin = base;
  const expectedRpId = rpIdOf(base);
  let verdict;
  try {
    if (String(body.mode || '') === 'create') {
      verdict = webauthnVerifier.verifyRegistration({
        attestationObject: credential.response.attestationObject,
        clientDataJSON: credential.response.clientDataJSON,
        expectedChallenge: step.challenge,
        expectedOrigin: expectedOrigin,
        expectedRpId: expectedRpId,
        requireUserVerification: false
      });
      if (verdict.ok) {
        webauthnCredentials.set(step.username, {
          credentialId: verdict.credentialId,
          publicKeyJwk: verdict.publicKeyJwk,
          signCount: verdict.signCount
        });
      }
    } else {
      const known = webauthnCredentials.get(step.username);
      if (!known) {
        throw new Error('no key is enrolled for ' + step.username);
      }
      verdict = webauthnVerifier.verifyAssertion({
        authenticatorData: credential.response.authenticatorData,
        clientDataJSON: credential.response.clientDataJSON,
        signature: credential.response.signature,
        publicKeyJwk: known.publicKeyJwk,
        expectedChallenge: step.challenge,
        expectedOrigin: expectedOrigin,
        expectedRpId: expectedRpId,
        requireUserVerification: false,
        previousSignCount: known.signCount
      });
      if (verdict.ok) {
        known.signCount = verdict.signCount;
        webauthnCredentials.set(step.username, known);
      }
    }
  } catch (e) {
    log.debug("Leaving the WebAuthn endpoint. Verification threw: " + e.message);
    return sendWebauthnPage(res, webauthnPage(base, String(body.mfa_id), step.username,
                         'The second factor could not be checked: ' + e.message));
  }

  logArtifact('WebAuthn ' + (String(body.mode) === 'create' ? 'registration' : 'assertion'),
              'as verified by this server', { ok: verdict.ok, checks: verdict.checks });

  if (!verdict.ok) {
    // Name the check that failed. "Authentication failed" would be true and
    // useless, and this is a debugging service.
    log.debug("Leaving the WebAuthn endpoint. Refused: " + verdict.failed.join('; '));
    return sendWebauthnPage(res, webauthnPage(base, String(body.mfa_id), step.username,
                         'The second factor did not verify — ' + verdict.failed.join('; ') + '.'));
  }

  pendingMfa.delete(String(body.mfa_id));
  // What the session claims, which is the whole difference between the two roles
  // and the only place it is decided. `hwk` is the RFC 8176 value for proof of
  // possession of a hardware key, which is what a WebAuthn assertion is; `pwd`
  // is on the list only where a password step actually happened.
  //
  // acr "1" for the passwordless sign-in is deliberate and it is the
  // conservative reading: this ceremony is performed with userVerification
  // "preferred" rather than "required" (see the script above), so the key proves
  // possession and nothing about the person holding it. Calling that "mfa"
  // because it is phishing-resistant would be the fake this profile refuses
  // everywhere else — a relying party that asked for two factors would be told
  // it got them.
  const amr = step.passwordless ? ['hwk'] : ['pwd', 'hwk'];
  const acr = step.passwordless ? '1' : 'mfa';
  // The single funnel, reached through startSession() as every sign-in at these
  // screens is. It is what puts the person on /admin/users and what seeds their
  // entry in the embedded directory — so a PRIMARY WebAuthn sign-in creates that
  // entry exactly as a password one does, and a SECOND FACTOR adds no second
  // identity, because the person it authenticates is the one the password step
  // already named. What the second factor adds to the entry is a flag; see
  // ldap_server.js's applyAuthenticationFactors(), which reads the amr below.
  startSession(res, step.username, amr, acr, step.authn.protocol);
  // Back to the caller, exactly as the password-only path returns: the
  // session now records what happened, and the request that was interrupted
  // runs again and sees it.
  returnToCaller(res, step.authn, null, null);
  log.debug("Leaving the WebAuthn endpoint. " + step.username +
            (step.passwordless ? " signed in with a security key alone."
                               : " completed the second factor."));
});
// ---------------------------------------------------------------------------
// WHO POSTED THAT FORM: the audit log's actor, filled from here.
//
// Every row on /admin/audit that came in over HTTP wants a name against it, and
// this module is the only one that can supply it — it owns the cookie and the
// session store. It cannot be REQUIRED from audit.js, though: that module is
// required by app.js, this module requires app.js, and a require the other way
// would close the loop and hand back a half-initialised module whose exports
// are undefined. So the direction is inverted the same way helpers.js's
// setJwtRecorder and admin_stats.js's setUserObserver are — audit.js offers a
// slot and this file fills it at require time, which is before any route can be
// called because every protocol module requires app.js.
//
// It is deliberately NOT sessionOf(). Three differences, and each of them is the
// reason:
//
//   * It has NO SIDE EFFECTS. sessionOf() deletes an expired session as it
//     finds it, which is right for a protocol endpoint deciding whether to show
//     the login screen and wrong for an observer: an audit log that quietly
//     ended sessions while reporting on them would be changing the thing it
//     describes.
//   * It says WHO the cookie names even when the session has expired, marked as
//     such by the caller's own vocabulary rather than reported as nobody.
//     "alice, whose session had expired" is the answer to what happened; "" is
//     not.
//   * It adds no log lines of its own. sessionOf()'s four say what a protocol
//     endpoint decided; this runs once per answered request, beside the two the
//     call log already writes, and repeating them would be most of the log.
//     (cookiesOf() writes its own pair, which is one parser rather than two.)
// ---------------------------------------------------------------------------
function auditActorOf(req) {
  const id = cookiesOf(req)[SESSION_COOKIE];
  if (!id) return '';
  const session = sessions.get(id);
  if (!session) return '';
  return session.user.username;
}

audit.setActorResolver(auditActorOf);

// ---------------------------------------------------------------------------
// What the rest of this service uses.
//
// `sessions` is handed out rather than copied because the admin console reports
// on the live store; `startSession` / `endSession` are functions rather than
// four lines repeated per call site for the reason written above them.
// ---------------------------------------------------------------------------
module.exports = {
  LOGIN_PATH: LOGIN_PATH,
  SESSION_COOKIE: SESSION_COOKIE,
  sessions: sessions,
  cookiesOf: cookiesOf,
  sessionOf: sessionOf,
  // The console's reader, and the ONE caller it has. It answers the same
  // question across every realm's partition because there is only ever one
  // session cookie in the browser; the header above it argues why that is the
  // boundary already drawn rather than a hole in this one. Every protocol
  // module keeps calling sessionOf() and keeps seeing its own realm only.
  consoleSession: consoleSession,
  startSession: startSession,
  endSession: endSession,
  // The three the protocol-independent logout needs, and the reason each is
  // here rather than reimplemented over there: /logout ends sessions it was not
  // handed a cookie for, so it names them by id — and every one of them still
  // has to go through dropSession(), which is where the RFC 9700 refresh
  // revocation and the one `session.end` audit row live. A second delete
  // somewhere else would be a sign-out that revoked nothing and logged nothing,
  // and it would look exactly like this one from the outside.
  sessionsOf: sessionsOf,
  sessionById: sessionById,
  endSessionById: endSessionById,
  clearSessionCookie: clearSessionCookie,
  beginAuthentication: beginAuthentication
};
