'use strict';
//
// File: frontchannel_logout.js
//
// ---------------------------------------------------------------------------
// OPENID CONNECT FRONT-CHANNEL LOGOUT 1.0 — TELLING THE RELYING PARTIES.
//
// The other half of a sign-out. Ending the session here drops a cookie and
// revokes what this service issued; every relying party the person signed into
// still believes they are signed in, and will go on believing it until its own
// session expires. Front-Channel Logout is how an OpenID Provider says
// otherwise: each RP registers a `frontchannel_logout_uri`, and the sign-out
// page loads all of them in hidden iframes so that each RP's own logout runs in
// the browser that is doing the signing out.
//
// It is a LIBRARY (rule 3): it registers no route, so its position in the
// require order does not matter and it cannot be the reason a route is missing.
// It requires `helpers.js`, `config.js` and `applications.js` — none of which
// requires it back — and deliberately NOT `oauth2.js`, because that module
// requires THIS one. That is the whole reason this file exists rather than the
// code living in `oauth2.js`: `/oauth2/logout`, WS-Federation's `wsignout1.0`
// and the protocol-independent `/logout` all have to render the same fan-out,
// and `logout/logout.js` reaching into `oauth2.js` for it would be a require
// this file makes unnecessary.
//
// ---------------------------------------------------------------------------
// FIVE THINGS ARE WORTH KNOWING BEFORE READING FURTHER.
//
// **THE LIST OF RELYING PARTIES LIVES ON THE SESSION.** `noteClient()` writes
// `session.oidcClients` at the moment an authorization response goes out, which
// is the one point where both the client and the session are in scope. It is on
// the session object rather than in a map of its own because that is exactly
// the lifetime it should have: when the session goes, so does the list, and
// nothing has to be swept. The same decision `wsfed.js` makes about
// `session.wsfedRealms` and `saml2_sso.js` makes about
// `session.saml2ServiceProviders` — three protocols, one shape, deliberately.
//
// **`sid` IS THE SESSION ID AND IT REVERSED A DOCUMENTED DECISION.**
// `admin_stats.js` used to say, in as many words, that no token this service
// issues carries a session identifier and that inventing one to make a console
// page easier would be changing what every client receives. That was right at
// the time and the reasoning is worth keeping: a claim is added because a
// SPECIFICATION needs it, not because something here would find it convenient.
// Front-Channel Logout is that specification — section 3 requires the OP to
// send `sid` to any RP that registered `frontchannel_logout_session_required`,
// and an RP holding two sessions in one browser cannot tell which one ended
// without it. So the ID Token carries `sid` when it was issued ON a session,
// and `oauth2.frontchannelLogout` turns the whole feature — the claim, the
// advertisement and the fan-out — off in one place for anybody who wants the
// tokens this service used to issue.
//
// **THE IFRAMES ARE A CSP RELAXATION AND IT IS THE NARROW ONE.** `app.js` sets
// `default-src 'none'`, from which `frame-src` falls back — so an iframe to
// another origin is blocked, which is the correct default for every other page
// here. The sign-out page relaxes `frame-src` to THE ORIGINS IT IS ACTUALLY
// LOADING, enumerated from the URIs themselves, rather than to `*`. It goes
// through `app.contentSecurityPolicy()` like every other relaxation in this
// service, so `frame-ancestors` and `base-uri` cannot be dropped by it — see
// the repository CLAUDE.md's two CSP rules, which this is the sixth caller of.
//
// **THE URLS ARE LISTED VISIBLY BESIDE THE IFRAMES.** A hidden iframe that
// failed — a dead RP, a certificate a browser will not accept, a URI somebody
// mistyped into the directory — is indistinguishable from one that worked,
// because a front-channel notification has no answer the OP can read. Section 5
// of the specification says as much: the OP cannot know whether the logout
// succeeded. So the page shows each URL as a link, which is the only thing that
// turns "nothing happened" into something a person can click and see. It is the
// same decision `wsfed.js` made about its cleanup pings, for the same reason.
//
// **IT SENDS `iss` AND `sid` ONLY WHERE THE CLIENT ASKED FOR THEM.** Section 2
// says the two are sent when `frontchannel_logout_session_required` is true and
// that they are otherwise omitted, and an RP that did not ask may well be
// validating the query string it gets. RFC 7591 section 2 makes an omitted
// boolean FALSE rather than unknown, which is what `clientConfigOf()` applies.
// ---------------------------------------------------------------------------

const { log, xmlEscape } = require('../common/helpers');
const app = require('../common/app');
const config = require('../common/config');
const applications = require('../common/applications');

// Is the feature on at all? Read per call rather than captured at require time,
// which is what `runtime: true` on the setting claims — a `const` here is the
// one thing /admin/config could not change.
function enabled() {
  return !!config.value('oauth2.frontchannelLogout');
}

// ---------------------------------------------------------------------------
// WHICH CLIENTS A SESSION HAS SIGNED INTO.
//
// Called from `issueAuthorizationResponse()` — the point at which this service
// issues something to a client ON a session, which is exactly the event that
// makes the client an RP of that session. Not from the token endpoint: a code
// redeemed there is the same transaction continuing, and counting it again
// would say nothing new. Not from the direct grants either, which have no
// session to sign out of.
//
// It cannot throw. It is called in the middle of building an authorization
// response, and a bookkeeping failure must never be the reason a client does
// not get its code — the same rule `audit()`, `signJwt()`'s recorder and the
// directory's user observer follow.
// ---------------------------------------------------------------------------
function noteClient(session, clientId) {
  try {
    if (!session || !clientId) return;
    session.oidcClients = session.oidcClients || {};
    const known = session.oidcClients[clientId];
    session.oidcClients[clientId] = {
      first: (known && known.first) || Date.now(),
      last: Date.now(),
      count: ((known && known.count) || 0) + 1
    };
  } catch (e) {
    log.warn('front-channel logout: could not record the client on the session: ' + e.message);
  }
}

// Every client this session signed into, in the order they were first seen.
// Read straight off the session, so a caller holding a session it is about to
// discard still gets the list — which is the whole reason `endSession()` and
// `endSessionById()` RETURN the session rather than a boolean.
function clientsOf(session) {
  const held = (session && session.oidcClients) || {};
  return Object.keys(held).sort(function (a, b) {
    return (held[a].first || 0) - (held[b].first || 0);
  });
}

// ---------------------------------------------------------------------------
// THE NOTIFICATIONS THIS SIGN-OUT SHOULD SEND.
//
// One row per client the session signed into, whether or not it can be
// notified — a client with no `frontchannel_logout_uri` is REPORTED with
// `uri: ''` rather than filtered out, because "this RP still thinks you are
// signed in and there is nowhere to tell it" is the single most useful sentence
// this page can produce, and a filtered list would say nothing at all.
//
// `issuer` is this authorization server's own issuer identifier, which the
// caller supplies: this service runs SEVERAL named authorization servers in one
// process and the `iss` an RP is expecting is the one that issued its tokens.
// ---------------------------------------------------------------------------
function notificationsFor(session, issuer) {
  log.debug("Entering notificationsFor(). issuer=" + issuer);
  const sid = (session && session.id) || '';
  const rows = clientsOf(session).map(function (clientId) {
    const client = applications.clientConfigOf(clientId);
    const uri = String((client && client.frontchannel_logout_uri) || '');
    const wantsSession = !!(client && client.frontchannel_logout_session_required);
    let url = '';
    if (uri) {
      // Section 2: iss and sid are added when the client required them, and
      // omitted otherwise. Appended rather than rebuilt through URL(), because
      // a registered URI may carry a query string of its own and this service
      // must hand back what was registered plus what the specification adds —
      // reserialising somebody's URI is how a logout endpoint stops matching
      // whatever the RP is comparing against.
      url = uri;
      if (wantsSession) {
        url += (url.indexOf('?') >= 0 ? '&' : '?') +
               'iss=' + encodeURIComponent(issuer || '') +
               '&sid=' + encodeURIComponent(sid);
      }
    }
    return {
      clientId: clientId,
      uri: uri,
      url: url,
      sessionRequired: wantsSession,
      // Why this client will not be notified, in words, or '' when it will be.
      // Stated here rather than worked out again by each renderer.
      why: uri ? ''
                : (client && client.known
                    ? 'this client has registered no frontchannel_logout_uri, so there is ' +
                      'nowhere to tell it. Register one, or set ' +
                      'oauthFrontchannelLogoutUri on its entry under ou=applications.'
                    : 'this service has never been told anything about this client beyond ' +
                      'its identifier, so it has no logout URI to be notified at.')
    };
  });
  log.debug("Leaving notificationsFor(). " + rows.length + " client(s), " +
            rows.filter(function (r) { return !!r.url; }).length + " notifiable.");
  return rows;
}

// The distinct origins of the notifications that will actually load — what
// `frame-src` has to allow. A URI this service cannot parse is DROPPED from the
// policy rather than widening it: the iframe then does not load, which is the
// safe direction, and the row beside it still shows the URL so the failure is
// visible rather than silent.
function frameOriginsOf(notifications) {
  log.debug("Entering frameOriginsOf().");
  const origins = {};
  notifications.forEach(function (row) {
    if (!row.url) return;
    try {
      origins[new URL(row.url).origin] = true;
    } catch (e) {
      // Not a URL this runtime will parse. Logged rather than swallowed: it is
      // almost always a value typed into the directory by hand, and it is worth
      // saying so once rather than leaving an iframe that never loads.
      log.warn('front-channel logout: ' + row.clientId + '\'s frontchannel_logout_uri (' +
               row.uri + ') is not a URL this runtime can parse, so it is left out of the ' +
               'Content-Security-Policy and its iframe will not load: ' + e.message);
    }
  });
  const list = Object.keys(origins);
  log.debug("Leaving frameOriginsOf(). " + list.length + " origin(s).");
  return list;
}

// The Content-Security-Policy for a page carrying these iframes. Through
// `app.contentSecurityPolicy()`, which re-adds `frame-ancestors` and `base-uri`
// whatever this asks for — a caller cannot drop them, and this one must not
// want to.
function contentSecurityPolicyFor(notifications) {
  const origins = frameOriginsOf(notifications);
  if (!origins.length) return app.contentSecurityPolicy({});
  return app.contentSecurityPolicy({ 'frame-src': origins.join(' ') });
}

// ---------------------------------------------------------------------------
// THE BLOCK OF HTML: the iframes, and the same URLs as visible links.
//
// Returned as a string for the caller to place in its own page, because the
// three callers draw three different pages around it — `/oauth2/logout` is an
// OIDC sign-out, `/logout` is a protocol-independent one, and the console's is
// an operator's report. What must not differ is the fan-out itself.
//
// The iframes are 0x0 and `aria-hidden`: they are a side effect and not
// content, and a screen reader announcing eight empty frames would be reading
// out the plumbing. The LINKS are the accessible half and carry the same URLs.
// ---------------------------------------------------------------------------
function render(notifications) {
  log.debug("Entering render(). " + notifications.length + " notification(s).");
  if (!notifications.length) {
    log.debug("Leaving render(). Nothing to notify.");
    return '<p>No OpenID Connect relying party was signed into on this session, so there is ' +
           'nothing to notify.</p>';
  }
  const notifiable = notifications.filter(function (row) { return !!row.url; });
  const rows = notifications.map(function (row) {
    return '<tr><td><code>' + xmlEscape(row.clientId) + '</code></td>' +
      '<td>' + (row.url
        ? '<a href="' + xmlEscape(row.url) + '" target="_blank" rel="noopener noreferrer">' +
          xmlEscape(row.url) + '</a>' +
          (row.sessionRequired
            ? '<br><span class="sub">iss and sid are on it: this client registered ' +
              'frontchannel_logout_session_required.</span>'
            : '<br><span class="sub">No iss or sid: this client did not register ' +
              'frontchannel_logout_session_required, and section 2 says they are then ' +
              'omitted.</span>')
        : '<span class="sub">' + xmlEscape(row.why) + '</span>') + '</td></tr>';
  }).join('');
  const frames = notifiable.map(function (row) {
    return '<iframe src="' + xmlEscape(row.url) + '" width="0" height="0" ' +
           'style="display:none" aria-hidden="true" title=""></iframe>';
  }).join('');
  const inner =
    '<h2>' + notifiable.length + ' of ' + notifications.length + ' relying part' +
      (notifications.length === 1 ? 'y' : 'ies') + ' notified</h2>' +
    '<p class="sub">OpenID Connect Front-Channel Logout 1.0. Each URL below was loaded in a ' +
    'hidden iframe as this page rendered, so each relying party\'s own logout ran in this ' +
    'browser.</p>' +
    '<table><thead><tr><th>Client</th><th>frontchannel_logout_uri</th></tr></thead>' +
    '<tbody>' + rows + '</tbody></table>' +
    '<p class="sub">The URLs are shown as links deliberately. A front-channel notification ' +
    'has no answer this service can read — section 5 says the provider cannot know whether ' +
    'the logout succeeded — so a dead relying party, a certificate this browser will not ' +
    'accept and a URI somebody mistyped all look exactly like success. Clicking one is the ' +
    'only way to see which happened.</p>' +
    frames;
  log.debug("Leaving render(). " + notifiable.length + " iframe(s).");
  return inner;
}

module.exports = {
  enabled: enabled,
  noteClient: noteClient,
  clientsOf: clientsOf,
  notificationsFor: notificationsFor,
  frameOriginsOf: frameOriginsOf,
  contentSecurityPolicyFor: contentSecurityPolicyFor,
  render: render
};
