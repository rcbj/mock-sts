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
const app = require('./app');
const { log, logArtifact, baseUrlOf, nowSec, randomId, xmlEscape, parseBody,
        oauthError, userFor } = require('./helpers');
const stats = require('./admin_stats');
// The audit log. Two things happen here that no other module can see: a session
// is created, and a session is ended. Neither is an authentication —
// admin_stats.js records that, at the funnel every protocol family shares — and
// neither is an HTTP call, which app.js records. A sign-in therefore writes
// three audit rows, which is three facts at three layers rather than one fact
// three times; /admin/audit says so where a reader counting rows will see it.
//
// This module also FILLS audit.js's actor slot at the bottom of this file, which
// is what puts a name on every console and management API row.
const audit = require('./audit');

// The path a caller sends the browser to. Exported, because the two callers
// build a URL out of it and a string spelled twice is a string that drifts.
const LOGIN_PATH = '/authn/login';

const SESSION_COOKIE = 'sts_mock_session';

const SESSION_TTL_MS = 60 * 60 * 1000;

// How long an interrupted request waits at the screen before it has to be
// started again.
const AUTHN_TTL_MS = 10 * 60 * 1000;

const sessions = new Map();         // session id -> the signed-in user

// The requests waiting at the login screen: what to do with the person once
// they have signed in, and what to tell them they are signing in FOR.
const pending = new Map();          // authn id -> { returnTo, details, ... }

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
const webauthnCredentials = new Map();  // username -> { credentialId, publicKeyJwk, signCount }
// mfa id -> { authn, username, challenge, passwordless, expires }
const pendingMfa = new Map();
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

function startSession(res, username, amr, acr, via) {
  log.debug("Entering startSession(). username=" + username + ", acr=" + acr);
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
  res.set('Set-Cookie', SESSION_COOKIE + '=' + sessionId + '; Path=/; HttpOnly; SameSite=Lax');
  // One of the two places a person is authenticated by typing a name at a screen —
  // this one covers both, since WS-Federation signs in through here.
  stats.recordAuthentication({
    presented: username, protocol: via || 'OAuth 2.0 / OIDC',
    method: methodPhraseFor(amr),
    sub: session.user.sub, amr: amr, acr: acr, sessionId: sessionId,
    note: 'No password was checked; the name typed is the identity.'
  });
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
    summary: username + ' was signed in at the ' + (via || 'OAuth 2.0 / OIDC') +
             ' screen; session ' + sessionId + ' was created',
    detail: {
      sessionId: sessionId,
      sub: session.user.sub,
      amr: (amr || []).join(', '),
      acr: acr || '',
      authTime: session.authTime,
      expiresAt: new Date(session.expires).toISOString(),
      note: 'No password was checked; the name typed is the identity.'
    }
  });
  log.debug("Leaving startSession(). " + username + " is signed in (amr " + (amr || []).join(',') + ").");
  return session;
}

// Ends the session the request carries, and returns it — the caller needs what it
// was, not merely that it is gone: WS-Federation's sign-out has to send a cleanup
// request to each relying party the session signed into, and that list lives on
// the session object it is about to discard.
function endSession(req, res) {
  log.debug("Entering endSession().");
  const id = cookiesOf(req)[SESSION_COOKIE];
  const session = id ? sessions.get(id) : null;
  if (id) sessions.delete(id);
  res.set('Set-Cookie', SESSION_COOKIE + '=; Path=/; Max-Age=0');
  // The sign-out, recorded here because this is the one place both of them
  // reach: /oauth2/logout and WS-Federation's wsignout1.0 are two protocols'
  // words for ending the one session this service holds, and a row per caller
  // would be two rows that could come to disagree about what a sign-out is.
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
      cookiePresented: id ? 'yes' : 'no',
      // Whether the cookie named a session this service still had. A `yes`
      // here with no session means it had already expired or already been
      // signed out, which are the two ordinary ways this row is a refusal.
      sessionFound: session ? 'yes' : 'no',
      amr: session ? (session.amr || []).join(', ') : '',
      acr: session ? (session.acr || '') : ''
    }
  });
  log.debug("Leaving endSession(). " + (session ? 'Dropped the session for ' + session.user.username + '.'
                                               : 'There was no session to drop.'));
  return session || null;
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
//
// Returns the path to redirect to. A path rather than a full URL: the browser
// is already on this origin, and building an absolute URL here would mean
// guessing the base the caller was reached on.
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
  const record = {
    id: randomId(18),
    returnTo: returnTo,
    details: Array.isArray(opts.details) ? opts.details : [],
    hint: String(opts.hint || ''),
    forceMfa: !!opts.forceMfa,
    protocol: opts.protocol || 'OAuth 2.0 / OIDC',
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
  res.redirect(302, target);
  log.debug("Leaving returnToCaller(). Sent the browser to " + target + ".");
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
    'SFMono-Regular,Menlo,monospace}</style></head><body><div class="card">' +
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
    '<label class="chk"><input type="checkbox" id="use_webauthn" name="use_webauthn" value="1"' +
    (record.forceMfa ? ' checked disabled' : '') + '> Use a security key (WebAuthn) as a second factor</label>' +
    (record.forceMfa ? '<input type="hidden" name="use_webauthn" value="1">' : '') +
    '<label class="chk"><input type="checkbox" id="webauthn_only" name="webauthn_only" value="1"' +
    (record.forceMfa ? ' disabled' : '') + '> Sign in with the security key alone (passwordless — ' +
    'no password step, and the tokens will say one factor)' +
    (record.forceMfa ? ' — not available: this request demands two factors' : '') + '</label>' +
    '<div class="row"><button type="submit" id="kc-login" name="action" value="login">Sign In</button>' +
    '<button type="submit" id="kc-cancel" name="action" value="cancel" class="secondary">Cancel</button></div>' +
    '</form><div class="meta">' +
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
  sendLoginPage(res, loginPage(baseUrlOf(req), record, ''));
  log.debug("Leaving the authentication screen. Showed the form for " + record.id + ".");
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
  const passwordless = String(body.webauthn_only || '') === '1';
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
  res.set('Content-Security-Policy',
          "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; " +
          "base-uri 'none'; frame-ancestors 'none'");
  res.status(200).type('text/html').set('Cache-Control', 'no-store').send(html);
}

app.get('/authn/webauthn.js', function (req, res) {
  log.debug("Serving the WebAuthn ceremony script.");
  res.set('Content-Security-Policy', "default-src 'none'");
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
  startSession: startSession,
  endSession: endSession,
  beginAuthentication: beginAuthentication
};
