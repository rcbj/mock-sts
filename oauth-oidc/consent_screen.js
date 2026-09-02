'use strict';
//
// File: consent_screen.js
//
// ---------------------------------------------------------------------------
// THE SCREEN A PERSON SEES BEFORE ANYTHING IS ISSUED FOR A SCOPE THEY HAVE NOT
// AGREED TO.
//
// `common/consent.js` is the REGISTER — what has been agreed, what is
// configured, and which of a request's scopes are outstanding. This file is the
// SCREEN: it holds the pending records, draws the page, and spends a record on
// Allow or Deny. The split is exactly `common/app_permissions.js` /
// `admin-ui/admin.js`'s and `common/delegation.js` / `delegation_map.js`'s —
// what something MEANS in one file, what it LOOKS like in another.
//
// ---------------------------------------------------------------------------
// IT IS `authn.js`'s SHAPE, DELIBERATELY, AND THAT IS THE WHOLE DESIGN.
//
// `beginConsent()` takes a `returnTo` on this service, mints a pending record,
// and answers with a path. The browser goes there, presses a button, and is
// sent BACK to `returnTo` — which is the authorization request, whole, exactly
// as it was. So the authorization endpoint keeps no state across the hop, for
// the reason it keeps none across the sign-in hop: the second pass is the same
// request over again, and everything it reads (PKCE, nonce, `claims`,
// `authorization_details`) is read from the query string both times.
//
// **THE RECORD IS SERVER-SIDE AND `returnTo` IS NEVER IN THE URL.** Same rule
// `federation_sp.js`'s decision 3 states: a page carrying a return address
// anybody could rewrite is an open redirect with a heading on it. The only
// thing on the query string is an unguessable id.
//
// **`returnTo` IS CHECKED TO BE A PATH ON THIS SERVICE**, in `beginConsent()`,
// with the same two-character test `beginAuthentication()` uses — a leading `/`
// that is not `//`. A caller that gets it wrong is a bug in this service rather
// than a hostile request, so it throws rather than quietly sending somebody
// somewhere else.
//
// ---------------------------------------------------------------------------
// THREE THINGS ARE CHECKED WHEN THE SCREEN IS DRAWN, AND ONLY ONE OF THEM IS
// OBVIOUS.
//
//   * THE RECORD EXISTS AND HAS NOT EXPIRED. Ten minutes, the same window
//     `authn.js` gives a pending sign-in, because they are two halves of one
//     flow and a person who is slow at one is slow at the other.
//   * THE PERSON LOOKING AT IT IS THE PERSON IT WAS MINTED FOR. The record
//     names a username; the request carries a session cookie. If the session
//     ended, or somebody else's browser opened the link, the answer would be
//     recorded against the wrong entry — which is the one failure here that
//     writes a lie into the directory rather than merely refusing something.
//   * THE ANSWER IS POSTED, NEVER GOT. A GET that recorded consent would be a
//     consent anything that prefetches a link could give — a browser, a chat
//     client unfurling a URL, a security scanner. The screen is a GET and the
//     decision is a POST, which is what a form is for.
//
// ---------------------------------------------------------------------------
// NO SCRIPT, AND THEREFORE NO CSP RELAXATION AT ALL.
//
// `app.js` sets `script-src 'none'` for the whole service and CLAUDE.md's rule
// is that a page wanting a script has to argue that it CANNOT work without one.
// This one plainly can: it is two buttons in a form. So the policy is untouched
// — no `contentSecurityPolicy()` override anywhere in this file — and this is
// not a candidate for the list of scripted pages.
//
// The stylesheet is `authn.js`'s CARD_CSS, imported rather than copied. A
// person meets the sign-in screen and this screen in one flow, seconds apart,
// and two hand-maintained stylesheets would drift into looking like two
// different services.
// ---------------------------------------------------------------------------

const { log, xmlEscape, parseBody, randomId, oauthError, baseUrlOf } = require('../common/helpers');
const app = require('../common/app');
const realms = require('../common/realms');
const consent = require('../common/consent');
const applications = require('../common/applications');
const audit = require('../common/audit');
// The session, and the stylesheet the sign-in screen is drawn with. This module
// is required AFTER authn.js in server.js, so this moves no route; and that
// module does not require this one, so there is no cycle.
const authn = require('../authn/authn');

const CONSENT_PATH = '/oauth2/consent';

// Ten minutes, `authn.js`'s AUTHN_TTL_MS by intention rather than by accident:
// the two records are two halves of one interrupted request, and a consent that
// expired while the sign-in beside it had not would strand somebody halfway
// with no way to tell which half had gone.
const CONSENT_TTL_MS = 10 * 60 * 1000;

// ---------------------------------------------------------------------------
// PER REALM, BECAUSE EVERYTHING THIS RECORD POINTS AT IS.
//
// `returnTo` is a path inside one realm, the username is a person in that
// realm's directory, and the client_id names an entry in that realm's
// ou=applications. A process-wide Map would let a record minted in `acme` be
// spent in the default realm and write somebody's consent into the wrong
// directory — which is the exact failure `common/CLAUDE.md` describes for the
// stores that were left shared, and the reason `realms.map()` exists.
// ---------------------------------------------------------------------------
const pending = realms.map();

// ---------------------------------------------------------------------------
// BEGIN. Called by the authorization endpoint and by nothing else.
//
// It returns a PATH rather than performing the redirect, exactly as
// `beginAuthentication()` does, so that the caller decides what its protocol
// does with it — and so that this module never has to know that a `form_post`
// response is not a redirect.
// ---------------------------------------------------------------------------
function beginConsent(opts) {
  log.debug("Entering beginConsent().");
  const info = opts || {};
  const returnTo = String(info.returnTo || '');
  if (returnTo.charAt(0) !== '/' || returnTo.charAt(1) === '/') {
    throw new Error('beginConsent() needs a path on this service to return to, not "' +
                    returnTo + '".');
  }
  const record = {
    id: randomId(18),
    returnTo: returnTo,
    // WHO IS ANSWERING. Checked again when the screen is drawn and again when
    // the button is pressed — see the header. It is the normalised local name,
    // because that is what `consent.record()` will file the answer under and a
    // record naming one spelling while the write used another would be a
    // consent nobody could revoke.
    username: String(info.username || ''),
    clientId: String(info.clientId || ''),
    clientName: String(info.clientName || info.clientId || ''),
    // The rows `consent.outstanding()` produced: the scope, whether it resolves
    // to a defined delegated permission, and what somebody typed as that
    // permission's description. Carried whole rather than re-derived at render
    // time, so that what the person is shown is what was decided — the same
    // rule `authn.js`'s record follows for `forcePasswordless`.
    scopes: Array.isArray(info.scopes) ? info.scopes : [],
    // What the whole request asked for, including the scopes already agreed.
    // Shown under a fold, because "you already agreed to these three" is the
    // answer to the question somebody asks when a screen they have seen before
    // comes back with one line on it.
    already: Array.isArray(info.already) ? info.already : [],
    details: Array.isArray(info.details) ? info.details : [],
    protocol: String(info.protocol || 'OAuth 2.0 / OIDC'),
    expires: Date.now() + CONSENT_TTL_MS
  };
  pending.set(record.id, record);
  pending.forEach(function (v, k) {
    if (v.expires < Date.now()) {
      pending.delete(k);
    }
  });
  log.info('consent: "' + record.username + '" is being asked whether "' +
           record.clientId + '" may have ' +
           record.scopes.map(function (one) { return one.scope; }).join(', ') +
           ' on their behalf. Nothing is issued until they answer; ' + returnTo +
           ' is where they come back to.');
  log.debug("Leaving beginConsent(). " + record.id + " will return to " + returnTo + ".");
  return CONSENT_PATH + '?consent=' + encodeURIComponent(record.id);
}

// The record a request names, or null. Expired ones are dropped on the way
// past, which is the only cleanup this store needs beyond the sweep above —
// `authn.js`'s `pendingFor()` exactly.
function pendingFor(id) {
  log.debug("Entering pendingFor(). id=" + (id || '(none)'));
  const record = pending.get(String(id || ''));
  if (!record) {
    log.debug("Leaving pendingFor(). No such consent is pending.");
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

// ---------------------------------------------------------------------------
// WHO IS ACTUALLY HERE, AND IS IT THE PERSON THIS RECORD IS ABOUT?
//
// The session is read through `authn.js` rather than from a cookie here,
// because that module owns what a session is. The comparison is on the
// NORMALISED name, which is what `beginConsent()` was given and what
// `consent.record()` files under — comparing the raw values would make
// `alice` and `alice@EXAMPLE.COM` two people at this one door and one person
// everywhere else.
// ---------------------------------------------------------------------------
function answeredBy(req, record) {
  log.debug("Entering answeredBy().");
  const session = authn.sessionOf(req);
  if (!session) {
    log.debug("Leaving answeredBy(). Nobody is signed in.");
    return { ok: false, why: 'nosession' };
  }
  // `session.user` is the CLAIMS OBJECT `helpers.userFor()` built, not a
  // string — this read was `session.user` for one afternoon and put
  // `[object Object]` on the screen where a name belongs. The typed name is
  // `username` on it, and it is normalised below exactly as the record's was.
  const here = consentIdentity((session.user || {}).username);
  if (here !== consentIdentity(record.username)) {
    log.debug("Leaving answeredBy(). The session is somebody else's.");
    return { ok: false, why: 'mismatch', who: here };
  }
  log.debug("Leaving answeredBy(). It is them.");
  return { ok: true, session: session, who: here };
}

// One normalisation, through the register, so that this file has no opinion of
// its own about who somebody is.
function consentIdentity(value) {
  return consent.identityOf(value);
}

// ---------------------------------------------------------------------------
// THE PAGE.
//
// What it shows, and why each part is on it:
//
//   * WHICH APPLICATION, by the name on its entry with the raw client_id under
//     it. Both, because the name is what somebody recognises and the client_id
//     is what the request actually carried — and a mock exists to show the
//     difference between what a screen says and what a protocol sent.
//   * ONE ROW PER SCOPE, with the permission's description where the scope
//     resolves to one somebody defined. A screen that lists five opaque words
//     is a screen that teaches a person to press Allow.
//   * WHAT WAS ALREADY AGREED, under a `<details>`, so that a second visit
//     explains itself.
//   * THE REQUEST'S OWN PARAMETERS at the foot, in the sign-in screen's `meta`
//     block, because this is a debugging tool and the redirect_uri is the thing
//     somebody is usually here to check.
// ---------------------------------------------------------------------------
function consentPage(base, record) {
  log.debug("Entering consentPage(). " + record.scopes.length + " scope(s).");
  const rows = record.scopes.map(function (one) {
    const permission = one.permission;
    return '<li><code>' + xmlEscape(one.scope) + '</code>' +
      (permission
        ? '<span>' + xmlEscape(permission.description ||
            ('the permission "' + permission.name + '"')) +
          ' — exposed by <code>' + xmlEscape(permission.identifier) + '</code>, and the ' +
          'access token will be addressed to <code>' + xmlEscape(permission.baseUri) +
          '</code></span>'
        : '<span>an ordinary scope: this service attaches no meaning to it and will ' +
          'put it on the token\'s scope claim as it stands</span>') +
      '</li>';
  }).join('');
  const already = record.already.length
    ? '<details><summary>' + record.already.length + ' scope(s) you have already agreed ' +
      'to for this application</summary><ul class="scopes">' +
      record.already.map(function (one) {
        return '<li><code>' + xmlEscape(one.scope) + '</code><span>' +
          (one.global
            ? 'consented for everybody on this application\'s entry ' +
              '(<code>oauthGlobalConsent</code>) — you were never asked'
            : 'agreed by you' + (one.at ? ' at ' + xmlEscape(one.at) : '')) +
          '</span></li>';
      }).join('') + '</ul></details>'
    : '';
  const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<title>Allow access? — mock authorization server</title><style>' +
    authn.CARD_CSS + CONSENT_CSS + '</style></head><body><div class="card">' +
    '<h1>Allow access?</h1>' +
    '<p class="sub">Signed in as <code>' + xmlEscape(record.username) + '</code> at <code>' +
    xmlEscape(base) + '</code></p>' +
    '<p class="app"><strong>' + xmlEscape(record.clientName) + '</strong> is asking for ' +
    'access on your behalf.' +
    (record.clientName === record.clientId ? ''
      : '<br><code>' + xmlEscape(record.clientId) + '</code>') + '</p>' +
    '<ul class="scopes">' + rows + '</ul>' +
    already +
    '<form method="post" action="' + CONSENT_PATH + '">' +
    '<input type="hidden" name="consent_id" value="' + xmlEscape(record.id) + '">' +
    '<div class="row">' +
    '<button type="submit" id="consent-allow" name="action" value="allow">Allow</button>' +
    '<button type="submit" id="consent-deny" name="action" value="deny" ' +
    'class="secondary">Deny</button></div></form>' +
    '<div class="meta">' +
    '<div>Allow writes one <code>' + xmlEscape(consent.USER_ATTRIBUTE) + '</code> value per ' +
    'scope onto your entry under <code>ou=users</code>, so you are not asked again for ' +
    'these. Deny returns <code>access_denied</code> to the application and records ' +
    'nothing.</div>' +
    '<div>Nothing has been issued yet. This screen is <code>oauth2.consentRequired</code>, ' +
    'which is on by default; /admin/consent is where every answer given here can be ' +
    'read and taken back.</div>' +
    '<div>Consenting for: <code>' + xmlEscape(record.protocol) + '</code></div>' +
    record.details.map(function (d) {
      return '<div>' + xmlEscape(d.label) + ': <code>' +
        xmlEscape(d.value == null ? '' : d.value) + '</code>' +
        (d.note ? ' (' + xmlEscape(d.note) + ')' : '') + '</div>';
    }).join('') +
    '</div></div></body></html>\n';
  log.debug("Leaving consentPage().");
  return page;
}

// The few rules the sign-in screen's stylesheet has no use for. Appended rather
// than merged into CARD_CSS, so that a change here cannot alter the sign-in
// screen — which four tests and a person's muscle memory depend on.
const CONSENT_CSS =
  '.card{width:460px}p.app{font-size:.9em;margin:0 0 14px}' +
  'ul.scopes{list-style:none;padding:0;margin:0 0 8px}' +
  'ul.scopes li{padding:8px 10px;margin:6px 0;border:1px solid #e3e3ea;border-radius:6px;' +
  'background:#fafafd;font-size:.85em}' +
  'ul.scopes li span{display:block;color:#666;font-size:.9em;margin-top:3px}' +
  'details{margin:10px 0 0;font-size:.8em;color:#555}' +
  'details summary{cursor:pointer}';

function sendConsentPage(res, html) {
  res.status(200).type('text/html').set('Cache-Control', 'no-store').send(html);
}

// ---------------------------------------------------------------------------
// GET — the screen.
// ---------------------------------------------------------------------------
app.get(CONSENT_PATH, function (req, res) {
  log.debug("Entering the consent screen.");
  const record = pendingFor((req.query || {}).consent);
  if (!record) {
    log.debug("Leaving the consent screen. Nothing is pending under that id.");
    return oauthError(res, 400, 'invalid_request',
      'There is no consent waiting under that id, or it has expired. Start the request ' +
      'again from the application that sent you here — nothing was issued and nothing ' +
      'was recorded.');
  }
  const who = answeredBy(req, record);
  if (!who.ok) {
    log.debug("Leaving the consent screen. " + who.why + ".");
    return oauthError(res, 400, 'invalid_request',
      who.why === 'nosession'
        ? 'Nobody is signed in here any more, so there is nobody to record an answer ' +
          'for. Start the request again from the application that sent you here.'
        : 'This consent was asked of "' + record.username + '" and the session in this ' +
          'browser belongs to "' + who.who + '". It is refused rather than recorded ' +
          'against whoever happens to be signed in, which is the one failure at this ' +
          'door that would write something untrue into the directory.');
  }
  sendConsentPage(res, consentPage(baseUrlOf(req), record));
  log.debug("Leaving the consent screen. Showed " + record.scopes.length +
            " scope(s) for " + record.id + ".");
});

// ---------------------------------------------------------------------------
// POST — the answer.
//
// THE RECORD IS SPENT EITHER WAY, before anything is written or anybody is
// redirected. A consent id that survived being answered would be one a back
// button could answer a second time, and on Allow that is a second write of
// something already agreed; on Deny it is an `access_denied` delivered twice to
// a client that has already given up.
// ---------------------------------------------------------------------------
app.post(CONSENT_PATH, function (req, res) {
  log.debug("Entering the consent endpoint.");
  const body = parseBody(req);
  const record = pendingFor(body.consent_id);
  if (!record) {
    log.debug("Leaving the consent endpoint. The form had expired.");
    return oauthError(res, 400, 'invalid_request',
      'This consent form has expired, or it has already been answered. Start the request ' +
      'again from the application that sent you here.');
  }
  const who = answeredBy(req, record);
  if (!who.ok) {
    log.debug("Leaving the consent endpoint. " + who.why + ".");
    return oauthError(res, 400, 'invalid_request',
      who.why === 'nosession'
        ? 'Nobody is signed in here any more, so this answer belongs to nobody. Nothing ' +
          'was recorded.'
        : 'This consent was asked of "' + record.username + '" and this browser is signed ' +
          'in as "' + who.who + '". Nothing was recorded.');
  }
  pending.delete(record.id);

  const names = record.scopes.map(function (one) { return one.scope; });
  if (String(body.action || '') !== 'allow') {
    audit.record({
      action: 'consent.deny', actor: record.username, target: record.clientId,
      protocol: 'OAuth 2.0 / OIDC', channel: 'http', outcome: 'refused',
      detail: 'refused ' + names.join(', ')
    });
    log.info('consent: "' + record.username + '" refused "' + record.clientId +
             '" the scope(s) ' + names.join(', ') + '. Nothing was recorded and ' +
             'nothing was issued; the client is told access_denied.');
    log.debug("Leaving the consent endpoint. Denied.");
    return backToCaller(res, record, 'access_denied',
      'The user did not consent to ' + names.join(' ') + '.');
  }

  const written = consent.record(record.username, record.clientId, names);
  audit.record({
    action: 'consent.grant', actor: record.username, target: record.clientId,
    protocol: 'OAuth 2.0 / OIDC', channel: 'http',
    outcome: written.stored ? 'success' : 'warning',
    detail: 'consented ' + names.join(', ') +
            (written.stored ? '' : ' (not written down: ' + (written.reason || 'no entry') +
                                   ', so they will be asked again)')
  });
  log.debug("Leaving the consent endpoint. Allowed.");
  return backToCaller(res, record, null, null);
});

// ---------------------------------------------------------------------------
// BACK TO THE AUTHORIZATION REQUEST.
//
// 303 AND NOT 302, for `returnToCaller()`'s reason in `authn.js` — this is the
// redirect that follows a POST, and 303 is the only status that SAYS the next
// request is a GET. It is one funnel for both answers so that the status code
// is decided once.
//
// A REFUSAL RIDES BACK ON `consent_error`, which the authorization endpoint
// reads exactly as it reads `authn_error`: this module names the outcome and
// THAT module decides what OAuth does about it, because `redirectBack()` knows
// about `response_mode` and in `form_post` the answer is not a redirect at all.
// Putting the error in the client's redirect_uri from here would be this file
// making a protocol decision it has no way to make correctly.
// ---------------------------------------------------------------------------
function backToCaller(res, record, error, description) {
  log.debug("Entering backToCaller(). error=" + (error || '(none)'));
  let target = record.returnTo;
  if (error) {
    target += (target.indexOf('?') === -1 ? '?' : '&') +
      'consent_error=' + encodeURIComponent(error) +
      '&consent_error_description=' + encodeURIComponent(description || '');
  }
  res.redirect(303, target);
  log.debug("Leaving backToCaller(). Sent the browser to " + target + " with a 303.");
}

log.info('The consent screen is registered at ' + CONSENT_PATH + '. The ' +
         'authorization endpoint sends a person here before it issues anything ' +
         'for a scope they have not agreed to for that application, and they ' +
         'come back to the request they interrupted.');

module.exports = {
  CONSENT_PATH: CONSENT_PATH,
  beginConsent: beginConsent,
  pendingFor: pendingFor
};
