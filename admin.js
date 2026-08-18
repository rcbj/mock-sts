'use strict';
//
// File: admin.js
//
// ---------------------------------------------------------------------------
// The admin console: five pages over the state admin_stats.js holds, and one more —
// /admin/groups — over the embedded LDAP directory next door.
//
//   GET  /admin           what the console is, and what it can do to this service
//   GET  /admin/metrics   every call, every artifact, and both kinds of session
//   GET  /admin/users     everyone this service has authenticated; with ?user= it is
//                         one of them, their sessions, and what was issued on each
//   GET  /admin/groups    every group in the embedded LDAP directory; with ?group= it
//                         is one of them, every attribute it has, and everybody in it
//   GET  /admin/tokens    what was issued — every JWT, every SAML assertion and every
//                         Kerberos ticket, filtered and paged — and the buttons that
//                         invalidate the ones that can be
//   POST /admin/tokens    revoke / restore, one token or a whole class of them
//   GET  /admin/claims    the custom claims every new token will carry
//   POST /admin/claims    add, remove, clear, or replace a whole set
//
// Every GET also answers `?format=json`, and every POST answers JSON when it was
// sent JSON. That is not decoration: the four tests this repository still owes the
// parent project are plain node scripts driven over HTTP with no browser, and a
// console reachable only by clicking is a console no test can assert against.
//
// **This module renders; it decides nothing.** All the state, all the caps and all
// the rules about what a claim may be called live in admin_stats.js, so a test can
// exercise them without going near an HTML page, and so this file stays the one
// place the markup is. The only thing it reaches for elsewhere is the browser
// sign-on session store, which oauth2.js owns.
//
// **It must therefore come AFTER oauth2.js in server.js**, and that is a dependency
// rather than a preference, the same one wsfed.js has: it reads the `sessions` map
// oauth2.js exports so the metrics page can report real sign-on sessions beside the
// ones derived from what was issued. The dependency is one way — oauth2.js knows
// nothing about this module — so it is not a cycle.
//
// ---------------------------------------------------------------------------
// THIS CONSOLE IS NOT PROTECTED, and that is a decision rather than an oversight.
//
// Every page here says so. This service checks no password anywhere — the username
// typed at the login screen simply becomes the identity in every token — and a
// console with a credential on it would be the only authenticated surface in a
// service whose whole premise is that it authenticates nobody. It would also be the
// only one a test had to hold a secret for.
//
// What follows from that is worth stating plainly rather than leaving implied:
// anyone who can reach this port can revoke every token this service has issued and
// add a claim to every token it issues next. That is fine for a mock on a laptop or
// on a compose network and is not fine on a public address, which is the same thing
// that was already true of /oauth2/token — it will mint a token for any username
// asked of it. Do not put this service on a public address.
// ---------------------------------------------------------------------------

const app = require('./app');
const { log, xmlEscape, baseUrlOf, ISSUER, parseBody, b64uDecode } = require('./helpers');
const stats = require('./admin_stats');
// The browser sign-on sessions, shared between the OAuth 2.0 / OIDC login screen
// and WS-Federation. Read-only here: the console reports them and never ends one,
// because /oauth2/logout and wsignout1.0 already do that and doing it from a third
// place would mean three ways of getting the cleanup wrong.
const { sessions } = require('./oauth2');
// The credential claim set: which LDAP attributes an issued Verifiable Credential
// carries, and the invented values behind them. A library like admin_stats.js —
// it registers no route — so requiring it here neither adds to the express router
// nor makes a cycle, and /admin/vc below is the page that sets it. The DIRECTORY
// half of it (populating entries, reading values back) is ldap_server.js's, wired
// into that module through a slot for the route-order reason rule 6 gives.
const vcClaims = require('./vc_claims');
// The other end of that: which of those claims the mock OID4VP Verifier — the
// "bar door" at /oid4vp/verifier — ASKS a wallet for, and in which credential
// format. A library like vc_claims.js and admin_stats.js, registering no route,
// so requiring it here neither moves a route nor makes a cycle; vc_verifier.js
// reads the same module from the other side of the require order.
const vpConfig = require('./vc_verifier_config');

// How many rows of a list a page will draw. A cap is needed — 5,000 token rows is
// a page no browser enjoys — and what it hid is always stated underneath, because a
// truncated table that does not say it was truncated reads as the whole truth.
//
// On the tokens page this is now the ceiling on ONE PAGE rather than on the whole
// list: everything held is reachable by paging, so nothing is hidden any more. The
// cap stays because the reason for it never went away — `?per=` is a number a caller
// types, and without a ceiling `?per=5000` is the page the cap existed to prevent.
const MAX_ROWS = 300;

// Rows per page when nobody said. Small enough that the table is the first thing on
// screen rather than the last, and the paging controls above and below it say what
// the rest of the list is.
const DEFAULT_PER_PAGE = 50;

// How many subjects the metrics page names in one "Who" cell before it says how
// many more there are. A separate cap from MAX_ROWS because it bounds a cell rather
// than a list: the ceiling that matters here is the width of one row, and the full
// list is on /admin/users and in `?format=json` either way.
const MAX_WHO = 12;

// ---------------------------------------------------------------------------
// The page shell.
//
// One for all five pages, with the nav in it, so a page cannot be added without a
// way back. The CSS is inline because app.js sets `default-src 'none'` with
// `style-src 'unsafe-inline'`: a stylesheet as its own resource would need its own
// exception and would buy nothing.
//
// There is NO SCRIPT anywhere here, and that constrains the design rather than
// merely describing it — `script-src 'none'` is what makes the whole family of
// reflected-content problems moot for this service, so the console does not get an
// exception. Every control on these pages is therefore a plain form POST, and
// every list is sorted server-side.
// ---------------------------------------------------------------------------
const NAV = [
  { path: '/admin', label: 'Console' },
  { path: '/admin/metrics', label: 'Metrics' },
  { path: '/admin/users', label: 'Users' },
  { path: '/admin/groups', label: 'Groups' },
  { path: '/admin/tokens', label: 'Tokens' },
  { path: '/admin/claims', label: 'Custom claims' },
  { path: '/admin/vc', label: 'Credential claims' },
  { path: '/admin/vc-verifier-config', label: 'Verifier request' },
  { path: '/sts-metadata', label: 'Service metadata' }
];

function esc(v) { return xmlEscape(v == null ? '' : String(v)); }

// A list of names, each in its own <code>. Written as a function because the
// obvious one-liner — join with the markup and escape the result — escapes the
// markup too, and the page then shows the tags it was supposed to render. It did.
function codeList(names) {
  return names.map(function (name) { return '<code>' + esc(name) + '</code>'; }).join(', ');
}

function navBar(active) {
  return '<nav>' + NAV.map(function (item) {
    if (item.path === active) return '<span class="here">' + esc(item.label) + '</span>';
    return '<a href="' + esc(item.path) + '">' + esc(item.label) + '</a>';
  }).join('') + '</nav>';
}

// The banner every page carries. It is repeated on all of them rather than shown
// once on the index, because the pages are linkable and the one somebody arrives at
// directly is exactly the one that needs to say this.
const OPEN_BANNER =
  '<div class="warn"><strong>This console is not protected.</strong> Nothing here checks a ' +
  'credential, because nothing in this service does — the username typed at the sign-in screen ' +
  'is the identity in every token it issues. Anyone who can reach this port can revoke every ' +
  'token and change what the next one contains. That is fine on a laptop or a compose network ' +
  'and is not fine on a public address.</div>';

function page(title, active, inner) {
  log.debug("Entering page(). title=" + title);
  const html = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + esc(title) + ' — mock STS admin</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'padding:2rem 1rem;color:#222;line-height:1.45}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:24px 28px;' +
    'max-width:76rem;margin:0 auto;box-shadow:0 6px 24px rgba(0,0,0,.08)}' +
    'h1{font-size:1.35em;margin:0 0 4px;color:#12107c}' +
    'h2{font-size:1.05em;margin:1.8em 0 .5em;color:#12107c;border-bottom:1px solid #eee;padding-bottom:.2em}' +
    'h3{font-size:.92em;margin:1.2em 0 .4em}' +
    'p.sub{color:#666;font-size:.85em;margin:0 0 14px}' +
    'nav{margin:0 0 16px;padding-bottom:10px;border-bottom:1px solid #eee;font-size:.85em}' +
    'nav a,nav .here{display:inline-block;margin-right:.9em;text-decoration:none}' +
    'nav a{color:#12107c}nav .here{font-weight:700;color:#222}' +
    '.warn{background:#fff8e1;border:1px solid #ffe082;padding:9px 12px;border-radius:5px;' +
    'font-size:.82em;margin:0 0 16px}' +
    '.ok{background:#e8f5e9;border:1px solid #a5d6a7;padding:8px 11px;border-radius:5px;' +
    'font-size:.85em;margin:0 0 14px}' +
    '.err{background:#fdecea;border:1px solid #f5c6c2;color:#b00020;padding:8px 11px;border-radius:5px;' +
    'font-size:.85em;margin:0 0 14px}' +
    '.tiles{display:flex;flex-wrap:wrap;gap:10px;margin:.6em 0 1em}' +
    '.tile{border:1px solid #e2e2ea;border-radius:8px;padding:10px 14px;min-width:9rem;background:#fbfbfd}' +
    '.tile .n{font-size:1.5em;font-weight:700;color:#12107c;line-height:1.1}' +
    '.tile .l{font-size:.74em;color:#666;text-transform:uppercase;letter-spacing:.03em}' +
    'table{border-collapse:collapse;width:100%;margin:.4rem 0 .9rem;font-size:.8em}' +
    'th,td{border:1px solid #e2e2ea;padding:.3rem .5rem;text-align:left;vertical-align:top}' +
    'th{background:#f0f0f5;font-weight:600}tr:nth-child(even) td{background:#fafafc}' +
    'td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}' +
    // A cell holding a list of opaque identifiers. `overflow-wrap:anywhere` is the
    // one that also shrinks the cell's MINIMUM width, which is the property that
    // matters: break-all alone wraps the text and still lets one unbreakable
    // did:jwk widen the whole table past the card it sits in.
    'td.who{overflow-wrap:anywhere;line-height:1.9}' +
    'td.who code{white-space:normal}' +
    '.state-valid{color:#0b6b4f;font-weight:600}.state-expired{color:#8a6d00}' +
    '.state-revoked{color:#b00020;font-weight:600}.state-none{color:#666}' +
    'form.inline{display:inline;margin:0}' +
    'button{padding:5px 10px;border-radius:5px;border:1px solid #12107c;background:#12107c;color:#fff;' +
    'font-size:.8em;cursor:pointer}button.secondary{background:#fff;color:#12107c}' +
    'button.danger{background:#b00020;border-color:#b00020}' +
    'input[type=text],textarea,select{box-sizing:border-box;padding:6px 8px;border:1px solid #bbb;' +
    'border-radius:5px;font-size:.85em;font-family:inherit}' +
    'textarea{width:100%;min-height:7rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}' +
    '.formrow{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:.5em 0}' +
    '.formrow label{font-size:.78em;font-weight:600;color:#555}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em;background:#f4f4f8;' +
    'padding:.1rem .25rem;border-radius:3px;word-break:break-all}a{color:#12107c}' +
    '.note{font-size:.78em;color:#666;margin:.3em 0 1em}' +
    '.meta{margin-top:22px;padding-top:12px;border-top:1px solid #eee;font-size:.76em;color:#666}' +
    '.meta div{margin:3px 0}ul{margin:.3em 0;padding-left:1.2em}li{margin:.25em 0;font-size:.85em}' +
    '.pagenav{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:.5em 0;font-size:.8em}' +
    '.pagenav a,.pagenav .here,.pagenav .off{display:inline-block;padding:3px 8px;border-radius:5px;' +
    'border:1px solid #d5d5dd;background:#fff;text-decoration:none;min-width:1.6em;text-align:center}' +
    '.pagenav .here{background:#12107c;border-color:#12107c;color:#fff;font-weight:700}' +
    '.pagenav .off{color:#aaa;background:#f7f7fa}' +
    '.pagenav .where{border:0;background:none;color:#666;padding-left:.4em}' +
    '</style></head><body><div class="card">' +
    '<h1>' + esc(title) + '</h1>' +
    '<p class="sub">Mock STS admin console — issuer <code>' + esc(ISSUER) + '</code></p>' +
    navBar(active) + OPEN_BANNER + inner +
    '<div class="meta">' +
    '<div>Everything on these pages is held in memory and dies with the process, like the signing ' +
    'key this service regenerates on every start. There is nothing to persist and a statistics file ' +
    'that outlived the key that signed the tokens it described would be worse than none.</div>' +
    '<div>Every page here also answers <code>?format=json</code>, and every form also accepts a ' +
    'JSON body, so a test can drive this console without a browser.</div>' +
    // Two closing divs, not one: the .meta block and then the .card the whole page
    // is inside. Getting this wrong leaves a document that renders and does not
    // parse, which is the kind of thing only a parser notices.
    '</div></div></body></html>\n';
  log.debug("Leaving page(). " + html.length + " bytes.");
  return html;
}

// Both response shapes for a page, chosen by ?format=json. `no-store` on all of
// them: they describe live state, and a cached metrics page is a wrong one.
function respond(req, res, json, title, active, html) {
  log.debug("Entering respond(). title=" + title);
  res.set('Cache-Control', 'no-store');
  if (String(req.query.format || '') === 'json') {
    res.status(200).type('application/json').send(JSON.stringify(json, null, 2));
    log.debug("Leaving respond(). Answered JSON.");
    return;
  }
  res.status(200).type('text/html').send(page(title, active, html));
  log.debug("Leaving respond(). Answered HTML.");
}

// A POST answers the way it was asked: JSON in, JSON out; a form, and the browser
// is sent back to the page it came from with a message. The redirect is a 303 so
// that the reload after it is a GET — a 302 here leaves the browser able to repeat
// the POST on refresh, which for "revoke everything" is a surprise.
function respondToAction(req, res, target, result) {
  log.debug("Entering respondToAction(). ok=" + result.ok);
  const type = String(req.headers['content-type'] || '');
  if (/json/i.test(type)) {
    res.status(result.ok ? 200 : 400).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(result, null, 2));
    log.debug("Leaving respondToAction(). Answered JSON.");
    return;
  }
  const key = result.ok ? 'notice' : 'error';
  const message = result.ok ? result.message : (result.errors || []).join(' ');
  // `&` when the target already carries a query string, `?` when it does not. The
  // tokens page sends the reader back to the page and filter the button was on, so
  // this is no longer always a bare path — and a second `?` does not start a second
  // query string, it becomes part of the previous parameter's value, which loses the
  // message and corrupts the parameter it landed on in one go.
  const joiner = target.indexOf('?') < 0 ? '?' : '&';
  res.set('Cache-Control', 'no-store')
     .redirect(303, target + joiner + key + '=' + encodeURIComponent(String(message).slice(0, 500)));
  log.debug("Leaving respondToAction(). Redirected to " + target + ".");
}

// The message a redirect brought back, if any. Escaped where it is rendered; capped
// where it is read, so a hand-written URL cannot make the page arbitrarily long.
function messagesOf(req) {
  const notice = String(req.query.notice || '').slice(0, 500);
  const error = String(req.query.error || '').slice(0, 500);
  return (notice ? '<div class="ok">' + esc(notice) + '</div>' : '') +
         (error ? '<div class="err">' + esc(error) + '</div>' : '');
}

function tile(n, label) {
  return '<div class="tile"><div class="n">' + esc(n) + '</div><div class="l">' + esc(label) + '</div></div>';
}

// The three formatters below are deliberately without entering/leaving logs: they
// are called once per table cell and would drown everything else in the log.
function whenText(ms) {
  if (!ms) return '—';
  return new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}

function durationText(ms) {
  const s = Math.floor((ms || 0) / 1000);
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  const parts = [];
  if (days) parts.push(days + 'd');
  if (days || hours) parts.push(hours + 'h');
  parts.push(minutes + 'm');
  parts.push((s % 60) + 's');
  return parts.join(' ');
}

function stateClass(state) {
  if (state === 'valid') return 'state-valid';
  if (state === 'expired' || state === 'not yet valid') return 'state-expired';
  if (state === 'revoked') return 'state-revoked';
  return 'state-none';
}

// A long opaque value, shortened for the table but recoverable: the full string is
// the title attribute, so it can be hovered and read. Truncating with no way back
// would make the jti column decorative, and the jti is the thing every button on
// the tokens page acts on.
function shortened(value, keep) {
  const text = String(value || '');
  if (text.length <= (keep || 18)) return '<code title="' + esc(text) + '">' + esc(text || '—') + '</code>';
  return '<code title="' + esc(text) + '">' + esc(text.slice(0, keep || 18)) + '&hellip;</code>';
}

// ---------------------------------------------------------------------------
// One table, three families.
//
// The tokens page lists JWTs, SAML assertions and Kerberos tickets together and
// newest first, because that is the order they happened in: a WS-Federation
// sign-in that produced an ID Token and a SAML 1.1 assertion is one event, and a
// page that showed the two halves of it in two places would be a page somebody has
// to correlate by timestamp by hand.
//
// What that costs is that most columns mean something slightly different depending
// on which family the row belongs to, and the way a table like that goes wrong is a
// column that quietly means two things. So the mapping is written down twice over:
// once here as ONE FUNCTION PER COLUMN answering for all three families — which is
// what makes a header like "Client, audience or service" checkable against the
// three answers underneath it — and once on the page itself as a legend, for the
// reader, who cannot see this comment.
//
// Which families exist and what is in them is decided in admin_stats.js. Nothing
// here chooses what the list contains; these functions only say how a row is drawn.
// ---------------------------------------------------------------------------

// A JWT has two names for one person — the `username` that was typed at the login
// screen and the `sub` derived from it — and seeing both is how you tell those two
// apart. A SAML NameID and a Kerberos client principal are ONE name each, so they
// fill the Subject column and leave this one empty rather than being printed twice
// to avoid an empty cell.
function userCell(record) {
  if (record.family === 'token') return esc(record.username || '—');
  return '<span class="state-none" title="' +
    esc('A SAML assertion names a Subject and a Kerberos ticket names a client principal. ' +
        'Neither carries a second, human-readable name beside it the way a JWT carries ' +
        'username beside sub, so the one name it has is in the Subject column.') +
    '">—</span>';
}

function subjectCell(record) {
  if (record.family === 'token') return shortened(record.sub, 30);
  return shortened(record.subject, 30);
}

// Who it was issued FOR: the party meant to accept it.
function partyCell(record) {
  if (record.family === 'assertion') {
    if (record.audience) return shortened(record.audience, 30);
    return '<span class="state-none" title="' +
      esc('This assertion carries no AudienceRestriction — WS-Trust was asked to Issue with no ' +
          'AppliesTo. Any relying party may accept it, which is the thing an audience restriction ' +
          'exists to prevent, so it is named here rather than shown as a dash.') +
      '">unrestricted</span>';
  }
  if (record.family === 'ticket') {
    // The realm recorded with a ticket is the realm that ANSWERED, which under a
    // cross-realm referral is not the service's own realm. So it is stated as the
    // issuer in the tooltip rather than appended to the service name as though it
    // were part of the principal — which is what it would look like, since a
    // Kerberos principal is written service/host@REALM.
    return '<code title="' + esc(String(record.service || '') +
      (record.realm ? ' — issued by the ' + record.realm + ' KDC' : '')) + '">' +
      esc(record.service || '—') + '</code>';
  }
  return esc(record.client_id || '—');
}

// The one extra fact each family has that no other column has room for. It is
// headed Detail rather than Scope, because the three are not answers to the same
// question — a scope says what an access token authorises, an enc-type says which
// cipher sealed a ticket — and a header naming one of them would make the other two
// rows look like answers to it.
function detailCell(record) {
  if (record.family === 'assertion') {
    if (record.signed === false) {
      return '<span class="state-revoked" title="' +
        esc('Signing threw and the assertion went out unsigned rather than not at all, so that a ' +
            'relying party can reject it for the right reason. The log line says what failed.') +
        '">unsigned</span>';
    }
    return '<span title="' +
      esc('An enveloped XML signature over the assertion, its reference naming the ID (SAML 2.0) ' +
          'or the AssertionID (SAML 1.1).') + '">signed</span>';
  }
  if (record.family === 'ticket') {
    return '<code title="' + esc('The enc-type the ticket and its session key were sealed with.') +
      '">' + esc(record.etype || '—') + '</code>';
  }
  return esc(record.scope || '—');
}

// How the holder gets to use it, which is the question the DPoP column was already
// asking and which the other two families have their own answers to.
function presentedCell(record) {
  if (record.family === 'assertion') {
    return '<span title="' +
      esc('Both builders write a bearer SubjectConfirmation: whoever holds the assertion may ' +
          'present it. There is no holder-of-key confirmation here, so there is nothing for this ' +
          'column to distinguish between.') + '">bearer</span>';
  }
  if (record.family === 'ticket') {
    if (record.kind === 'Kerberos TGT') {
      return '<span title="' +
        esc('A TGT goes back to the KDC in a TGS-REQ to get a service ticket. It is never ' +
            'presented to a service, which is why it is the Kerberos session rather than one use ' +
            'of one.') + '">TGS-REQ</span>';
    }
    return '<span title="' +
      esc('A service ticket is presented to the service it names, in an AP-REQ — over raw ' +
          'Kerberos, or wrapped in SPNEGO over HTTP.') + '">AP-REQ</span>';
  }
  if (record.jkt) {
    return '<span title="' +
      esc('Bound to a key: cnf.jkt is in the token and a DPoP proof over that key has to ' +
          'accompany it.') + '">DPoP</span>';
  }
  return 'Bearer';
}

// The handle the row can be quoted by — and for one family there is none, which is
// worth saying rather than leaving as a bare dash beside two columns full of them.
function identifierCell(record) {
  if (record.family === 'ticket') {
    return '<span class="state-none" title="' +
      esc('A Kerberos ticket carries no identifier anybody can quote: no jti, no ID. It is named ' +
          'by its client, its service and when it was issued — the columns to the left — and the ' +
          'KDC keeps no handle on it either, because the KDC is stateless and the ticket is the ' +
          'state.') + '">—</span>';
  }
  return shortened(record.identifier, 12);
}

// The button, or why there is not one. Two different reasons, and they are not
// interchangeable: a signed UserInfo response has no jti to act on, and a SAML
// assertion has an identifier and still cannot be revoked because nothing out there
// would ask this service about it.
function actionCell(record, backRow) {
  if (record.family !== 'token') {
    return '<span class="state-none" title="' +
      esc('Nothing consults this service about a SAML assertion or a Kerberos ticket. An ' +
          'assertion is valid because its signature verifies and its Conditions hold; a ticket is ' +
          'valid because the service it names can decrypt it with a key it already has. A button ' +
          'here would change a number on this page and nothing at all out there.') + '">—</span>';
  }
  if (!record.revocable) {
    return '<span class="state-none" title="' +
      esc('Only access tokens, ID Tokens and refresh tokens can be revoked — the others are ' +
          'replies rather than credentials, or carry no jti to act on.') + '">—</span>';
  }
  return '<form method="post" action="/admin/tokens" class="inline">' +
    '<input type="hidden" name="action" value="' + (record.revoked ? 'restore' : 'revoke') + '">' +
    '<input type="hidden" name="target" value="' + esc(record.jti) + '">' +
    '<input type="hidden" name="back" value="' + esc(backRow) + '">' +
    '<button class="' + (record.revoked ? 'secondary' : 'danger') + '">' +
    (record.revoked ? 'Restore' : 'Revoke') + '</button></form>';
}

function issuedRow(record, backRow) {
  return '<tr><td>' + esc(record.kind) + '</td>' +
    '<td class="' + stateClass(record.state) + '">' + esc(record.state) + '</td>' +
    '<td>' + userCell(record) + '</td>' +
    '<td>' + subjectCell(record) + '</td>' +
    '<td>' + partyCell(record) + '</td>' +
    '<td>' + detailCell(record) + '</td>' +
    '<td>' + presentedCell(record) + '</td>' +
    '<td>' + esc(whenText(record.issuedAt)) + '</td>' +
    '<td>' + esc(record.expiresAtMs ? whenText(record.expiresAtMs) : '—') + '</td>' +
    '<td>' + identifierCell(record) + '</td>' +
    '<td>' + actionCell(record, backRow) + '</td></tr>';
}

// The legend for the above, on the page, because a reader cannot see the comment
// this file opens the section with and a table whose columns shift meaning between
// rows has to say so where the rows are.
const COLUMN_LEGEND =
  '<table><tr><th>Column</th><th>A JWT</th><th>A SAML assertion</th><th>A Kerberos ticket</th></tr>' +
  '<tr><td>User</td><td><code>username</code>, as typed at the sign-in screen</td>' +
    '<td colspan="2">nothing: each of these has one name, and it is in Subject</td></tr>' +
  '<tr><td>Subject</td><td><code>sub</code></td><td>the <code>NameID</code></td>' +
    '<td>the client principal, <code>name@REALM</code></td></tr>' +
  '<tr><td>Client, audience or service</td><td><code>client_id</code> (or <code>azp</code>, or the ' +
    '<code>aud</code>)</td><td>the <code>AudienceRestriction</code>, or <em>unrestricted</em> when ' +
    'WS-Trust was given no <code>AppliesTo</code></td><td>the service the ticket is for; hover for ' +
    'the realm that issued it</td></tr>' +
  '<tr><td>Detail</td><td><code>scope</code></td><td>whether the signature was written — an ' +
    'assertion that failed to sign still went out</td><td>the enc-type it was sealed with</td></tr>' +
  '<tr><td>Presented as</td><td>Bearer, or DPoP when <code>cnf.jkt</code> binds it to a key</td>' +
    '<td>bearer <code>SubjectConfirmation</code>; there is no holder-of-key form here</td>' +
    '<td>in a TGS-REQ (a TGT) or an AP-REQ (a service ticket)</td></tr>' +
  '<tr><td>jti or ID</td><td>the <code>jti</code>, which is what every button acts on</td>' +
    '<td>the <code>ID</code> / <code>AssertionID</code></td>' +
    '<td>none exists — a ticket has no identifier to quote, and the KDC keeps no handle on ' +
    'one</td></tr></table>';

// ---------------------------------------------------------------------------
// Paging.
//
// There is no script on these pages — `script-src 'none'`, see the shell above — so
// paging is links and a query parameter and nothing else. That is also why every
// number is settled server-side before the markup is built: a page that renders
// "page 4 of 2" and leaves the browser to sort it out has nothing to sort it out
// with.
//
// Both parameters are read defensively. `?page=abc`, `?page=-3` and `?page=999` all
// have to land somewhere sensible, because they arrive from hand-edited URLs and
// from a stale bookmark taken when the list was longer — a revocation sweep can
// shorten it between two clicks, and an out-of-range page must be the last page
// rather than an empty table that reads as "nothing matched".
// ---------------------------------------------------------------------------
function pagingOf(query, total) {
  log.debug("Entering pagingOf(). total=" + total);
  const askedPer = parseInt(String(query.per || ''), 10);
  const perPage = (isFinite(askedPer) && askedPer > 0) ? Math.min(askedPer, MAX_ROWS) : DEFAULT_PER_PAGE;
  // At least one page even when nothing matched, so "page 1 of 1" is what an empty
  // list says rather than "page 1 of 0".
  const pages = Math.max(1, Math.ceil(total / perPage));
  const askedPage = parseInt(String(query.page || ''), 10);
  const page = Math.min(Math.max(isFinite(askedPage) ? askedPage : 1, 1), pages);
  const offset = (page - 1) * perPage;
  log.debug("Leaving pagingOf(). page=" + page + " of " + pages + ", perPage=" + perPage + ".");
  return {
    page: page, perPage: perPage, pages: pages, offset: offset, total: total,
    // 1-based and inclusive, for the "rows 51–100 of 312" line. Zero and zero when
    // nothing matched, which is what the line then has to say.
    firstRow: total ? offset + 1 : 0,
    lastRow: Math.min(offset + perPage, total)
  };
}

// A query string built from what the caller is already looking at plus an override.
// Every paging link goes through this, because a "next" that dropped `?kind=` would
// be page 2 of a different list — the bug this exists to make impossible rather than
// merely avoidable. Empty values are omitted so the URL of the unfiltered first page
// is the bare path.
function queryWith(params, overrides) {
  const merged = Object.assign({}, params, overrides);
  const parts = [];
  Object.keys(merged).forEach(function (key) {
    const value = merged[key];
    if (value === '' || value === null || value === undefined) {
      return;
    }
    parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(String(value)));
  });
  return parts.length ? '?' + parts.join('&') : '';
}

// The paging control. Drawn above and below the table both, because the reason to
// want the next page is usually that you have just read to the bottom of this one.
//
// The numbered links are a WINDOW around the current page rather than one per page:
// 5,000 tokens at 50 a page is 100 links, which is a worse navigation aid than none.
// First and last are always offered so the ends stay one click away.
function pageNav(path, params, pg) {
  log.debug("Entering pageNav(). pages=" + pg.pages);
  if (pg.pages <= 1) {
    log.debug("Leaving pageNav(). One page; no control drawn.");
    return '';
  }
  function link(page, label, title) {
    return '<a href="' + esc(path + queryWith(params, { page: page })) + '"' +
           (title ? ' title="' + esc(title) + '"' : '') + '>' + label + '</a>';
  }
  const out = [];
  if (pg.page > 1) {
    out.push(link(1, '&laquo; first', 'The newest rows'));
    out.push(link(pg.page - 1, '&lsaquo; prev'));
  } else {
    out.push('<span class="off">&laquo; first</span><span class="off">&lsaquo; prev</span>');
  }
  const from = Math.max(1, Math.min(pg.page - 3, pg.pages - 6));
  const to = Math.min(pg.pages, Math.max(pg.page + 3, 7));
  for (let n = from; n <= to; n++) {
    out.push(n === pg.page ? '<span class="here">' + n + '</span>' : link(n, String(n)));
  }
  if (pg.page < pg.pages) {
    out.push(link(pg.page + 1, 'next &rsaquo;'));
    out.push(link(pg.pages, 'last &raquo;', 'The oldest rows still held'));
  } else {
    out.push('<span class="off">next &rsaquo;</span><span class="off">last &raquo;</span>');
  }
  out.push('<span class="where">page ' + pg.page + ' of ' + pg.pages + ' — rows ' +
           pg.firstRow + '&ndash;' + pg.lastRow + ' of ' + pg.total + '</span>');
  log.debug("Leaving pageNav(). Drew " + out.length + " element(s).");
  return '<div class="pagenav">' + out.join('') + '</div>';
}

// ---------------------------------------------------------------------------
// GET /admin — the index.
// ---------------------------------------------------------------------------
app.get('/admin', function (req, res) {
  log.debug("Entering the admin console index.");
  const snap = stats.snapshot();
  const base = baseUrlOf(req);
  const inner = messagesOf(req) +
    '<div class="tiles">' +
      tile(snap.calls.total, 'endpoint calls') +
      tile(snap.tokens.held, 'tokens issued') +
      tile(snap.tokens.revoked, 'tokens revoked') +
      tile(snap.artifacts.held, 'other artifacts') +
      tile(snap.users.known, 'users known') +
      tile(sessions.size, 'sign-on sessions') +
      tile(durationText(snap.uptimeMs), 'uptime') +
    '</div>' +
    '<h2>What this console is</h2>' +
    '<p class="note">This service exists to exercise clients, and the pages here exist to ' +
    'exercise the parts of a client that only show themselves when something changes underneath it: ' +
    'what happens when a token it holds stops being valid, and what happens when a token it reads ' +
    'grows a claim it was not expecting.</p>' +
    '<ul>' +
    '<li><a href="/admin/metrics">Metrics</a> — every endpoint call by route and status, every ' +
    'token and artifact this service has issued with how many are still valid, and sessions ' +
    'counted both ways: the browser sign-on sessions this service really holds, and the sessions ' +
    'implied by what it has issued.</li>' +
    '<li><a href="/admin/users">Users</a> — every userid this service has been given as part of an ' +
    'interaction that succeeded, across all twelve protocol families, with what each one holds. ' +
    'Click a name for the sessions they are signed in on, the tokens issued on each of those ' +
    'sessions, and the assertions, tickets and credentials issued to them. It also lists the ' +
    'subjects that were never here at all — an exchanged token names one, so does a WS-Trust ' +
    '<code>OnBehalfOf</code> and a Kerberos S4U request — and says so on the row.</li>' +
    '<li><a href="/admin/groups">Groups</a> — every group in the embedded LDAP directory, with ' +
    'how many of its members name an entry that is actually there. Click one for every attribute ' +
    'it holds and everybody in it, each member linked back to their row on the users page. It is ' +
    'the one page here that reports the directory rather than what this service has issued, and ' +
    'the one thing to know about it is that <strong>a group here grants nothing</strong>: no ' +
    'token, assertion or ticket this service issues carries a group, and no endpoint reads one.' +
    '</li>' +
    '<li><a href="/admin/tokens">Tokens</a> — everything issued, in one table: every JWT, every ' +
    'SAML assertion (WS-Trust\'s and WS-Federation\'s alike) and every Kerberos ticket, newest ' +
    'first. And the buttons that invalidate the ones that can be — one access token, one ID Token, ' +
    'one refresh token, everything for one subject, or everything of one kind. Revocation here is ' +
    'the SAME revocation RFC 7009\'s <code>/oauth2/revoke</code> performs, so introspection, ' +
    'UserInfo and the refresh grant all honour it.</li>' +
    '<li><a href="/admin/claims">Custom claims</a> — what to add to every OAuth 2.0 access token, ' +
    'every OIDC ID Token, and every SAML 2.0 and SAML 1.1 assertion this service issues from now ' +
    'on. Additive only: a custom claim is never allowed to displace one the protocol defines.</li>' +
    '<li><a href="/admin/vc">Credential claims</a> — which claims a Verifiable Credential issued ' +
    'from now on carries, chosen from a catalogue of LDAP attribute types rather than of claim ' +
    'names: the value of a claim is the value on that person\'s directory entry. Saving a ' +
    'selection also populates the directory, so an LDAP client and a wallet describe one ' +
    'person.</li>' +
    '</ul>' +
    '<h2>What it deliberately does not do</h2>' +
    '<ul>' +
    '<li><strong>It does not invalidate a SAML assertion, a Kerberos ticket or a credential.</strong> ' +
    'It counts them, it lists the first two on the tokens page beside the JWTs, and it says when ' +
    'each expires — but none of those has a revocation mechanism a relying party consults. A SAML ' +
    'assertion is valid because its signature verifies and its Conditions hold, and a Kerberos ' +
    'ticket because the service it names can decrypt it; nothing about this service is asked in ' +
    'either case. A button claiming to revoke one would change a number here and nothing at all ' +
    'out there, which is why those rows carry a dash and the reason for it.</li>' +
    '<li><strong>It does not end a sign-on session.</strong> <code>/oauth2/logout</code> and ' +
    'WS-Federation\'s <code>wsignout1.0</code> already do, and the second of those has to fan a ' +
    'cleanup request out to every relying party the session signed into. A third way to end one ' +
    'would be a third place to get that wrong.</li>' +
    '<li><strong>It does not keep the tokens themselves</strong>, only their claims. A page listing ' +
    'a thousand live bearer credentials in a form a browser will render is a page that leaks them, ' +
    'and the <code>jti</code> is all any button here needs.</li>' +
    '</ul>' +
    '<h2>Reading it from a test</h2>' +
    '<p class="note">Every page answers <code>?format=json</code>:</p>' +
    '<ul>' +
    '<li><code>GET ' + esc(base) + '/admin/metrics?format=json</code></li>' +
    '<li><code>GET ' + esc(base) + '/admin/groups?format=json</code>, and ' +
    '<code>GET ' + esc(base) + '/admin/groups?group=cn=developers,ou=groups,...&amp;format=json' +
    '</code> — the second carries every attribute of that group and every member resolved.</li>' +
    '<li><code>GET ' + esc(base) + '/admin/users?format=json</code>, and ' +
    '<code>GET ' + esc(base) + '/admin/users?user=alice&amp;format=json</code> — the second carries ' +
    '<code>sessions</code>, each with the tokens issued on it, plus the tokens that belong to no ' +
    'session and the artifacts</li>' +
    '<li><code>GET ' + esc(base) + '/admin/tokens?format=json&amp;page=1&amp;per=100</code> — the ' +
    'reply carries <code>page</code>, <code>pages</code> and <code>matched</code>, so walking the ' +
    'whole list needs no guess about where it ends</li>' +
    '<li><code>POST ' + esc(base) + '/admin/tokens</code> with ' +
    '<code>{"action":"revoke","target":"&lt;jti or token&gt;"}</code></li>' +
    '<li><code>POST ' + esc(base) + '/admin/claims</code> with ' +
    '<code>{"action":"replace","set":"id_token","claims":[{"name":"dept","value":"engineering"}]}</code></li>' +
    '</ul>';
  respond(req, res, {
    issuer: ISSUER, startedAt: new Date(snap.startedAt).toISOString(), uptimeMs: snap.uptimeMs,
    calls: snap.calls.total, tokensHeld: snap.tokens.held, tokensRevoked: snap.tokens.revoked,
    artifactsHeld: snap.artifacts.held, signOnSessions: sessions.size,
    usersKnown: snap.users.known, usersAuthenticatedHere: snap.users.authenticatedHere,
    pages: NAV.map(function (n) { return n.path; })
  }, 'Admin console', '/admin', inner);
  log.debug("Leaving the admin console index.");
});

// ---------------------------------------------------------------------------
// GET /admin/metrics
// ---------------------------------------------------------------------------

// The browser sign-on sessions, as rows. Expired ones are still in the map until
// something reads them (sessionOf() drops one when it finds it stale), so the state
// is computed here rather than assumed — otherwise the console would report a
// session that no request would honour.
function signOnSessionRows() {
  log.debug("Entering signOnSessionRows().");
  const nowMs = Date.now();
  const rows = [];
  sessions.forEach(function (session, id) {
    rows.push({
      id: id,
      username: (session.user && session.user.username) || '',
      sub: (session.user && session.user.sub) || '',
      amr: (session.amr || []).join(', '),
      acr: session.acr || '',
      authTime: (session.authTime || 0) * 1000,
      expires: session.expires || 0,
      expired: !!session.expires && session.expires <= nowMs,
      // Which WS-Federation relying parties this session signed into. It is the
      // list wsignout1.0 has to fan out to, and seeing it is the only way to know
      // in advance what a sign-out is about to do.
      wsfedRealms: Object.keys(session.wsfedRealms || {})
    });
  });
  rows.sort(function (a, b) { return b.authTime - a.authTime; });
  log.debug("Leaving signOnSessionRows(). " + rows.length + " session(s).");
  return rows;
}

function callTable(snap) {
  log.debug("Entering callTable().");
  const rows = snap.calls.rows.slice(0, MAX_ROWS);
  const body = rows.map(function (row) {
    return '<tr><td><code>' + esc(row.method) + '</code></td>' +
      '<td><code>' + esc(row.path) + '</code>' +
      (row.matched ? '' : ' <span class="state-expired">no route</span>') + '</td>' +
      '<td class="num">' + row.count + '</td>' +
      '<td class="num">' + (row.statuses['2xx'] || 0) + '</td>' +
      '<td class="num">' + (row.statuses['3xx'] || 0) + '</td>' +
      '<td class="num">' + (row.statuses['4xx'] || 0) + '</td>' +
      '<td class="num">' + (row.statuses['5xx'] || 0) + '</td>' +
      '<td class="num">' + Math.round(row.totalMs / Math.max(row.count, 1)) + '</td>' +
      '<td class="num">' + row.maxMs + '</td>' +
      '<td>' + esc(whenText(row.lastAt)) + '</td></tr>';
  }).join('');
  const hidden = snap.calls.rows.length - rows.length;
  log.debug("Leaving callTable(). " + rows.length + " row(s).");
  return '<table><tr><th>Method</th><th>Route</th><th class="num">Calls</th>' +
    '<th class="num">2xx</th><th class="num">3xx</th><th class="num">4xx</th><th class="num">5xx</th>' +
    '<th class="num">Avg ms</th><th class="num">Max ms</th><th>Last</th></tr>' +
    (body || '<tr><td colspan="10">No call has been recorded yet.</td></tr>') + '</table>' +
    (hidden > 0 ? '<p class="note">' + hidden + ' further route(s) are not shown; the table draws the ' +
                  MAX_ROWS + ' busiest.</p>' : '') +
    (snap.calls.pathsCollapsed > 0
      ? '<p class="note">' + snap.calls.pathsCollapsed + ' request(s) to paths that matched no route ' +
        'were counted in the single <code>' + esc('(other unmatched paths)') + '</code> row: the table ' +
        'is capped so that a scanner inventing URLs cannot grow it without limit.</p>'
      : '');
}

function tokenKindTable(snap) {
  log.debug("Entering tokenKindTable(). " + snap.tokens.byKind.length + " kind(s).");
  const body = snap.tokens.byKind.map(function (row) {
    return '<tr><td>' + esc(row.kind) + '</td>' +
      '<td class="num">' + row.issued + '</td>' +
      '<td class="num state-valid">' + row.valid + '</td>' +
      '<td class="num state-expired">' + row.expired + '</td>' +
      '<td class="num state-revoked">' + row.revoked + '</td>' +
      '<td class="num">' + row.notYetValid + '</td>' +
      '<td class="num">' + row.noExpiry + '</td>' +
      '<td class="num">' + row.bound + '</td></tr>';
  }).join('');
  log.debug("Leaving tokenKindTable().");
  return '<table><tr><th>Token</th><th class="num">Issued</th><th class="num">Valid</th>' +
    '<th class="num">Expired</th><th class="num">Revoked</th><th class="num">Not yet valid</th>' +
    '<th class="num">No expiry</th><th class="num">DPoP-bound</th></tr>' +
    (body || '<tr><td colspan="8">No token has been issued yet.</td></tr>') + '</table>';
}

function artifactKindTable(snap) {
  log.debug("Entering artifactKindTable(). " + snap.artifacts.byKind.length + " kind(s).");
  const body = snap.artifacts.byKind.map(function (row) {
    return '<tr><td>' + esc(row.kind) + '</td>' +
      '<td class="num">' + row.issued + '</td>' +
      '<td class="num state-valid">' + row.valid + '</td>' +
      '<td class="num state-expired">' + row.expired + '</td>' +
      '<td class="num">' + row.noExpiry + '</td></tr>';
  }).join('');
  log.debug("Leaving artifactKindTable().");
  return '<table><tr><th>Artifact</th><th class="num">Issued</th><th class="num">Valid</th>' +
    '<th class="num">Expired</th><th class="num">No expiry</th></tr>' +
    (body || '<tr><td colspan="5">No assertion, ticket or credential has been issued yet.</td></tr>') +
    '</table>';
}

app.get('/admin/metrics', function (req, res) {
  log.debug("Entering the admin metrics page.");
  const snap = stats.snapshot();
  const signOn = signOnSessionRows();
  const liveSignOn = signOn.filter(function (s) { return !s.expired; });

  // The Who column holds SUBJECTS, and one family's are not names in any readable
  // sense: an OID4VCI credential's subject is a `did:jwk:` — a couple of hundred
  // characters of base64url with not one place in it a browser will break a line.
  // Emitted as plain text that made the cell's minimum width wider than the card,
  // so the table overflowed and took the OAuth 2.0 / OIDC row's column with it,
  // even though `urn:sts-mock:user:alice` is short and never the problem. So each
  // subject is drawn the way the tokens page draws a jti — shortened, with the
  // whole string in the title so it is still recoverable by hovering — and inside
  // <code>, which the stylesheet already lets break mid-string.
  const sessionFamilyRows = snap.sessions.families.map(function (row) {
    const shown = row.who.slice(0, MAX_WHO).map(function (subject) {
      return shortened(subject, 28);
    }).join(' ');
    return '<tr><td>' + esc(row.family) + '</td><td class="num">' + row.subjects + '</td>' +
      '<td class="who">' + shown +
      (row.who.length > MAX_WHO ? ' &hellip; and ' + (row.who.length - MAX_WHO) + ' more' : '') +
      '</td></tr>';
  }).join('');

  const signOnRows = signOn.slice(0, MAX_ROWS).map(function (s) {
    return '<tr><td>' + esc(s.username) + '</td>' +
      '<td class="' + (s.expired ? 'state-expired' : 'state-valid') + '">' +
        (s.expired ? 'expired, not yet swept' : 'active') + '</td>' +
      '<td>' + esc(s.amr || '—') + '</td><td>' + esc(s.acr || '—') + '</td>' +
      '<td>' + esc(whenText(s.authTime)) + '</td>' +
      '<td>' + esc(whenText(s.expires)) + '</td>' +
      '<td>' + (s.wsfedRealms.length ? esc(s.wsfedRealms.join(', ')) : '—') + '</td></tr>';
  }).join('');

  const inner = messagesOf(req) +
    '<div class="tiles">' +
      tile(snap.calls.total, 'endpoint calls') +
      tile(snap.calls.paths, 'routes called') +
      tile(snap.tokens.held, 'tokens issued') +
      tile(snap.tokens.revoked, 'tokens revoked') +
      tile(snap.artifacts.held, 'assertions, tickets, credentials') +
      tile(liveSignOn.length, 'sign-on sessions') +
      tile(snap.sessions.distinctSubjects, 'subjects with a live artifact') +
      tile(durationText(snap.uptimeMs), 'uptime') +
    '</div>' +
    '<p class="note">Since <code>' + esc(whenText(snap.startedAt)) + '</code>. Every figure on this ' +
    'page is computed when the page is drawn rather than kept up to date as things happen, because ' +
    '&ldquo;valid&rdquo; and &ldquo;expired&rdquo; are functions of the clock: a counter incremented ' +
    'at issuance would be wrong a second later.</p>' +

    '<h2>Endpoint calls</h2>' +
    '<p class="note">Keyed on the route Express matched, not on the URL requested, so ' +
    '<code>/oauth2/register/:client_id</code> is one row rather than one row per client. These are ' +
    'the same route patterns <a href="/sts-metadata">/sts-metadata</a> lists.</p>' +
    callTable(snap) +

    '<h2>Tokens</h2>' +
    '<p class="note">Every JWT this service signs, by <code>typ</code> — which is the only thing ' +
    'that tells them apart, since all of them are RS256 and signed with the same key. ' +
    '<a href="/admin/tokens">The tokens page</a> lists them one by one — beside the SAML ' +
    'assertions and Kerberos tickets, which it also lists — and can invalidate these.</p>' +
    tokenKindTable(snap) +
    (snap.tokens.forgotten > 0
      ? '<p class="note">' + snap.tokens.forgotten + ' older token(s) have been forgotten: the ' +
        'registry holds the most recent ' + snap.tokens.cap + '. Their revocations are NOT ' +
        'forgotten — the set of revoked <code>jti</code>s is kept separately and is not capped, so ' +
        'a token revoked long ago stays revoked.</p>'
      : '') +

    '<h2>Assertions, tickets and credentials</h2>' +
    '<p class="note">The artifacts that are not JWTs. None of them can be revoked and the console ' +
    'does not pretend otherwise — see the index for why — so the only distinction here is whether ' +
    'the validity window has closed. The assertions and the tickets are listed one by one on ' +
    '<a href="/admin/tokens">the tokens page</a>, beside the JWTs and in the order they were all ' +
    'issued; the credentials are counted here and nowhere else.</p>' +
    artifactKindTable(snap) +
    (snap.artifacts.forgotten > 0
      ? '<p class="note">' + snap.artifacts.forgotten + ' older artifact(s) have been forgotten; the ' +
        'registry holds the most recent ' + snap.artifacts.cap + '.</p>'
      : '') +

    '<h2>Sessions, counted both ways</h2>' +
    '<p class="note">The two numbers mean different things and disagree on purpose. A ' +
    '<strong>sign-on session</strong> is a real one: a browser holding the ' +
    '<code>sts_mock_session</code> cookie, shared between the OAuth 2.0 / OIDC login screen and ' +
    'WS-Federation, which is what makes single sign-on across the two work. An ' +
    '<strong>artifact-derived session</strong> is an inference: a subject that holds at least one ' +
    'artifact from that protocol family which is still valid. A <code>client_credentials</code> ' +
    'token is the second and not the first (there is no human and no browser behind it); a browser ' +
    'that has signed in but been issued nothing yet is the first and not the second; a Kerberos ' +
    'client is never the first at all. Both are counted here per family; ' +
    '<a href="/admin/users">the users page</a> is where one person\'s sessions and the tokens ' +
    'issued on each of them are.</p>' +
    '<h3>Sign-on sessions (' + liveSignOn.length + ' active of ' + signOn.length + ' held)</h3>' +
    '<table><tr><th>User</th><th>State</th><th>amr</th><th>acr</th><th>Signed in</th>' +
    '<th>Expires</th><th>WS-Fed relying parties signed into</th></tr>' +
    (signOnRows || '<tr><td colspan="7">Nobody is signed in.</td></tr>') + '</table>' +
    '<p class="note">An expired session stays in the map until something reads it — ' +
    '<code>sessionOf()</code> drops one when it finds it stale — so it is listed as held but not ' +
    'active rather than quietly omitted.</p>' +
    '<h3>Artifact-derived sessions (' + snap.sessions.distinctSubjects + ' distinct subject(s))</h3>' +
    '<table><tr><th>Protocol family</th><th class="num">Subjects</th><th>Who</th></tr>' +
    (sessionFamilyRows || '<tr><td colspan="3">Nothing valid has been issued yet.</td></tr>') +
    '</table>' +
    '<p class="note">A Kerberos TGT is counted as a session and a service ticket is not, because ' +
    'that is what they are: the TGT is the credential the session consists of, and a service ticket ' +
    'is one use of it. Counting both would report the same session twice.</p>';

  respond(req, res, Object.assign({}, snap, {
    startedAtIso: new Date(snap.startedAt).toISOString(),
    signOnSessions: { held: signOn.length, active: liveSignOn.length, rows: signOn }
  }), 'Metrics', '/admin/metrics', inner);
  log.debug("Leaving the admin metrics page.");
});

// ---------------------------------------------------------------------------
// GET /admin/tokens, POST /admin/tokens
// ---------------------------------------------------------------------------

// The jti a caller named, from whichever of the two forms they used. A jti is
// accepted directly, and so is a whole token — because the thing somebody has in
// their hand when they want to invalidate it is the token, not its jti.
//
// The token's SIGNATURE IS NOT VERIFIED here, and that is safe rather than sloppy:
// the only thing read out of it is the jti, which is then looked up in this
// service's own registry. A forged token yields a jti this service never issued, and
// revoking a jti that was never issued invalidates nothing. RFC 7009's endpoint does
// verify, because there the token is the credential being presented; here it is
// merely a way of typing a jti that is 22 characters long.
function jtiFrom(target) {
  log.debug("Entering jtiFrom().");
  const text = String(target || '').trim();
  if (!text) {
    log.debug("Leaving jtiFrom(). Nothing was given.");
    return { jti: '', how: 'nothing was given' };
  }
  const parts = text.split('.');
  if (parts.length !== 3) {
    log.debug("Leaving jtiFrom(). Treating it as a jti.");
    return { jti: text, how: 'read as a jti' };
  }
  try {
    const claims = JSON.parse(b64uDecode(parts[1]).toString('utf8'));
    log.debug("Leaving jtiFrom(). Read the jti out of a JWT.");
    return { jti: String(claims.jti || ''), how: 'read out of the JWT payload without verifying it',
             claims: claims };
  } catch (e) {
    // Three dot-separated parts that are not a JWT. Fall back to treating the whole
    // string as a jti rather than refusing: it costs nothing and a jti containing
    // two dots is not forbidden anywhere.
    log.debug("Leaving jtiFrom(). It has three parts but is not a JWT: " + e.message);
    return { jti: text, how: 'read as a jti (it looked like a JWT but did not decode)' };
  }
}

function tokenAction(body) {
  log.debug("Entering tokenAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');

  if (action === 'revoke' || action === 'restore') {
    const found = jtiFrom(body.target || body.jti || body.token);
    if (!found.jti) {
      log.debug("Leaving tokenAction(). No jti was given.");
      return { ok: false, errors: ['Give a jti, or paste the whole token and the jti will be read ' +
                                   'out of it.'] };
    }
    if (action === 'restore') {
      const was = stats.restore(found.jti);
      log.debug("Leaving tokenAction(). Restored.");
      return { ok: true, jti: found.jti,
               message: was ? 'The token with jti ' + found.jti + ' is no longer revoked (NON-SPEC — ' +
                              'a real authorization server cannot undo a revocation).'
                            : 'The token with jti ' + found.jti + ' was not revoked, so nothing changed.' };
    }
    const first = stats.revoke(found.jti, 'the admin console');
    log.debug("Leaving tokenAction(). Revoked.");
    return { ok: true, jti: found.jti,
             message: (first ? 'Revoked ' : 'Already revoked: ') + found.jti + ' (' + found.how +
                      '). Introspection now reports it inactive, UserInfo refuses it, and it will ' +
                      'not refresh.' };
  }

  if (action === 'revoke-kind') {
    const kind = String(body.kind || '');
    if (stats.REVOCABLE_KINDS.indexOf(kind) < 0) {
      log.debug("Leaving tokenAction(). Not a revocable kind.");
      return { ok: false, errors: ['"' + kind + '" is not a kind that can be revoked. The three are: ' +
                                   stats.REVOCABLE_KINDS.join(', ') + '.'] };
    }
    const count = stats.revokeWhere(function (record) { return record.kind === kind; },
                                    'the admin console (every ' + kind + ')');
    log.debug("Leaving tokenAction(). Revoked " + count + " by kind.");
    return { ok: true, revoked: count, message: 'Revoked ' + count + ' ' + kind + '(s).' };
  }

  if (action === 'revoke-subject') {
    const subject = String(body.subject || '').trim();
    if (!subject) {
      log.debug("Leaving tokenAction(). No subject was given.");
      return { ok: false, errors: ['Give a subject or a username.'] };
    }
    const count = stats.revokeWhere(function (record) {
      return record.sub === subject || record.username === subject;
    }, 'the admin console (everything for ' + subject + ')');
    log.debug("Leaving tokenAction(). Revoked " + count + " for a subject.");
    return { ok: true, revoked: count,
             message: 'Revoked ' + count + ' token(s) for ' + subject + '.' };
  }

  // The users page's button. It is not the same thing as revoke-subject above, and
  // the difference is the reason it exists: that one matches a `sub` or a `username`
  // EXACTLY, which is what somebody typing into the box on the tokens page means,
  // while a user on the users page is an identity that has been seen under several
  // spellings — `alice`, `urn:sts-mock:user:alice`, `alice@STS.MOCK`. Revoking "for
  // alice" from that page has to mean all of them, or the page would offer a button
  // that visibly missed half of its own table.
  if (action === 'revoke-user') {
    const key = String(body.user || '').trim();
    if (!key) {
      log.debug("Leaving tokenAction(). No user was given.");
      return { ok: false, errors: ['Give a user, as the users page names them.'] };
    }
    const count = stats.revokeWhere(function (record) {
      return stats.identityKeyOf(record.username || record.sub) === key;
    }, 'the admin console (everything for the user ' + key + ')');
    log.debug("Leaving tokenAction(). Revoked " + count + " for a user.");
    return { ok: true, revoked: count, user: key,
             message: 'Revoked ' + count + ' token(s) for ' + key + ' — every spelling of that ' +
                      'identity, not just the one the row showed.' };
  }

  if (action === 'revoke-all') {
    const count = stats.revokeWhere(function () { return true; }, 'the admin console (everything)');
    log.debug("Leaving tokenAction(). Revoked everything: " + count + ".");
    return { ok: true, revoked: count,
             message: 'Revoked ' + count + ' token(s) — every access token, ID Token and refresh ' +
                      'token this service has issued and still remembers.' };
  }

  log.debug("Leaving tokenAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The six are: revoke, restore, ' +
                               'revoke-kind, revoke-subject, revoke-user, revoke-all.'] };
}

// Where a form POST sends the browser back to. Revoking the token on page 4 and
// landing on page 1 of an unfiltered list is the paging bug everybody has met, so
// the row forms carry the view they were rendered in as a `back` field.
//
// It is REBUILT rather than echoed, and that is the whole point of doing it here: a
// redirect target taken from a request body is an open redirect, and one carrying a
// newline is a header injection. Only the parameters this page understands survive,
// each of them re-encoded, so the worst a hand-written `back` can produce is a
// different page of this same table.
//
// The list below has to be kept in step with the filter form. A parameter the form
// offers and this function drops is a filter that silently resets itself the moment
// somebody revokes a token — which looks like the console losing your place rather
// than like a missing line here.
//
// The users page posts to this same endpoint, so `from` says which of the two pages
// a button was on. It is read as an ENUM and never as a path: the two paths below
// are written here, and a `from` naming anything else falls through to the tokens
// page. That is what keeps the open-redirect property while letting a second page
// share the handler — a `back` field carrying `//evil.example` would otherwise become
// a redirect off this service the moment a path came from the body.
function backTo(body) {
  log.debug("Entering backTo().");
  let params = null;
  try {
    params = new URLSearchParams(String(body.back || '').replace(/^\?/, ''));
  } catch (e) {
    // Unparseable; the bare page is the right answer and is what the forms that
    // carry no `back` at all get anyway.
    log.debug("Leaving backTo(). Unparseable back field: " + e.message);
    return '/admin/tokens';
  }
  if (String(body.from || '') === 'users') {
    const usersTarget = '/admin/users' + queryWith({
      user: params.get('user') || '',
      q: params.get('q') || '',
      protocol: params.get('protocol') || '',
      per: params.get('per') || '',
      page: params.get('page') || ''
    }, {});
    log.debug("Leaving backTo(). " + usersTarget);
    return usersTarget;
  }
  const target = '/admin/tokens' + queryWith({
    family: params.get('family') || '',
    kind: params.get('kind') || '',
    state: params.get('state') || '',
    per: params.get('per') || '',
    page: params.get('page') || ''
  }, {});
  log.debug("Leaving backTo(). " + target);
  return target;
}

app.post('/admin/tokens', function (req, res) {
  log.debug("Entering the admin token action endpoint.");
  const body = parseBody(req);
  const result = tokenAction(body);
  respondToAction(req, res, backTo(body), result);
  log.debug("Leaving the admin token action endpoint.");
});

app.get('/admin/tokens', function (req, res) {
  log.debug("Entering the admin tokens page.");
  const wantedFamily = String(req.query.family || '');
  const wantedKind = String(req.query.kind || '');
  const wantedState = String(req.query.state || '');
  // Not tokenList(): this page lists every JWT, every SAML assertion (whether
  // WS-Trust or WS-Federation issued it) and every Kerberos ticket, in one table in
  // the order they were issued.
  const all = stats.issuedList();
  const filtered = all.filter(function (record) {
    if (wantedFamily && record.family !== wantedFamily) return false;
    if (wantedKind && record.kind !== wantedKind) return false;
    if (wantedState && record.state !== wantedState) return false;
    return true;
  });
  // Filter first, then page: paging a list and then filtering it would give a page 2
  // whose length depends on what page 1 happened to contain.
  const paging = pagingOf(req.query, filtered.length);
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  // How much of each family is held, for the line under the table. Counted from this
  // list rather than taken from the snapshot, because the snapshot's artifact count
  // includes the OID4VCI credentials this page does not list — two totals on one
  // page differing by a number of credentials is a page nobody can check.
  const heldByFamily = {};
  all.forEach(function (record) {
    heldByFamily[record.family] = (heldByFamily[record.family] || 0) + 1;
  });
  // What every paging link has to carry with it. The page number is not in here —
  // pageNav() supplies that per link — and neither is `format`, because JSON has no
  // links in it and a caller asking for JSON passes its own parameters anyway.
  const filterParams = { family: wantedFamily, kind: wantedKind, state: wantedState,
                         per: req.query.per ? paging.perPage : '' };
  const nav = pageNav('/admin/tokens', filterParams, paging);
  // What the POST handler sends the browser back to. A row button returns to THIS
  // page of THIS filter; the bulk buttons below keep the filter but not the page,
  // because after "revoke everything" the list they were looking at is a different
  // list and page 7 of it means nothing.
  const backRow = queryWith(filterParams, { page: paging.page });
  const backFilter = queryWith(filterParams, {});

  const rows = shown.map(function (record) {
    return issuedRow(record, backRow);
  }).join('');

  const familyOptions = ['<option value=""' + (wantedFamily ? '' : ' selected') + '>any family</option>']
    .concat(stats.ISSUED_FAMILIES.map(function (entry) {
      return '<option value="' + esc(entry.family) + '"' +
             (entry.family === wantedFamily ? ' selected' : '') + '>' + esc(entry.label) + '</option>';
    })).join('');

  // Grouped by family rather than flat, because "SAML 2.0" and "id_token" in one
  // list of nine reads as nine unrelated things. Both this and the family select are
  // built from the same structure in admin_stats.js, so the two cannot come to
  // disagree about which kind belongs to which family — which they would, being two
  // hand-written lists of the same nine strings.
  const kindOptions = '<option value=""' + (wantedKind ? '' : ' selected') + '>any kind</option>' +
    stats.ISSUED_FAMILIES.map(function (entry) {
      return '<optgroup label="' + esc(entry.label) + '">' + entry.kinds.map(function (k) {
        return '<option value="' + esc(k) + '"' + (k === wantedKind ? ' selected' : '') + '>' +
               esc(k) + '</option>';
      }).join('') + '</optgroup>';
    }).join('');
  const stateOptions = ['', 'valid', 'expired', 'revoked', 'not yet valid', 'no expiry stated']
    .map(function (s) {
      return '<option value="' + esc(s) + '"' + (s === wantedState ? ' selected' : '') + '>' +
             esc(s || 'any state') + '</option>';
    }).join('');
  // MAX_ROWS is offered as the largest choice so the old behaviour — everything on
  // one page, up to the cap — is still one click away for anyone who wants to search
  // the table with the browser's own find.
  //
  // A hand-typed `?per=7` is added to the list rather than ignored, or the select
  // would show a size that is not the one being used and would silently change it on
  // the next Filter.
  const perChoices = [25, DEFAULT_PER_PAGE, 100, MAX_ROWS];
  if (perChoices.indexOf(paging.perPage) < 0) {
    perChoices.push(paging.perPage);
    perChoices.sort(function (a, b) { return a - b; });
  }
  const perOptions = perChoices.map(function (n) {
    return '<option value="' + n + '"' + (n === paging.perPage ? ' selected' : '') + '>' +
           n + ' rows</option>';
  }).join('');

  const inner = messagesOf(req) +
    '<p class="note">Everything this service has issued and still remembers: every JWT, every SAML ' +
    'assertion — whether WS-Trust issued it or a WS-Federation sign-in did — and every Kerberos ' +
    'ticket the KDC minted, in one table, newest first. One table rather than three because a ' +
    'WS-Federation sign-in that produced an ID Token and a SAML 1.1 assertion is <em>one event</em>, ' +
    'and three tables would leave it to be reassembled by comparing timestamps.</p>' +
    '<p class="note">Only the JWTs can be invalidated. Revoking one here is the SAME operation ' +
    'RFC 7009\'s <code>/oauth2/revoke</code> performs — there is one set of revoked ' +
    '<code>jti</code>s in this service, not one per page. So a token revoked here immediately ' +
    'introspects as inactive at <code>/oauth2/introspect</code>, is refused by ' +
    '<code>/oauth2/userinfo</code> with <code>invalid_token</code>, and fails the refresh grant ' +
    'with <code>invalid_grant</code>. Two sets would each look correct on their own and never see ' +
    'each other, which is a debugging session with no error message anywhere in it.</p>' +
    '<p class="note">An assertion and a ticket have no button and are listed anyway, which is the ' +
    'point of listing them: <strong>nothing consults this service about either</strong>. An ' +
    'assertion is valid because its signature verifies and its <code>Conditions</code> hold, and a ' +
    'ticket because the service it names can decrypt it with a key it already has. So the only ' +
    'thing that ends one is its own expiry, and the only way to see when that is — or to see that ' +
    'a sign-in produced one at all — is a page that shows it.</p>' +

    '<h2>Invalidate</h2>' +
    '<form method="post" action="/admin/tokens">' +
      '<input type="hidden" name="action" value="revoke">' +
      '<input type="hidden" name="back" value="' + esc(backFilter) + '">' +
      '<div class="formrow"><label for="target">A jti, or paste the whole token</label>' +
      '<input type="text" id="target" name="target" size="60" placeholder="jti, or eyJhbGciOi...">' +
      '<button class="danger">Revoke</button></div></form>' +
    '<p class="note">Pasting a token is read for its <code>jti</code> and the signature is not ' +
    'checked, which is safe: a forged token yields a jti this service never issued, and revoking ' +
    'one of those invalidates nothing. To undo a revocation, use the Restore button in the table — ' +
    'a NON-SPEC operation no real authorization server can offer, kept because otherwise getting ' +
    'back to a working token means restarting this service.</p>' +
    '<div class="formrow">' +
      ['access_token', 'id_token', 'refresh_token'].map(function (kind) {
        return '<form method="post" action="/admin/tokens" class="inline">' +
          '<input type="hidden" name="action" value="revoke-kind">' +
          '<input type="hidden" name="kind" value="' + esc(kind) + '">' +
          '<input type="hidden" name="back" value="' + esc(backFilter) + '">' +
          '<button class="danger">Revoke every ' + esc(kind) + '</button></form>';
      }).join(' ') +
      '<form method="post" action="/admin/tokens" class="inline">' +
      '<input type="hidden" name="action" value="revoke-all">' +
      '<input type="hidden" name="back" value="' + esc(backFilter) + '">' +
      '<button class="danger">Revoke everything</button></form>' +
    '</div>' +
    '<form method="post" action="/admin/tokens">' +
      '<input type="hidden" name="action" value="revoke-subject">' +
      '<input type="hidden" name="back" value="' + esc(backFilter) + '">' +
      '<div class="formrow"><label for="subject">Everything for one subject or username</label>' +
      '<input type="text" id="subject" name="subject" size="40" placeholder="alice, or urn:sts-mock:user:alice">' +
      '<button class="danger">Revoke</button></div></form>' +

    '<h2>What has been issued</h2>' +
    // No `page` input in this form, and that is the point: changing the filter or the
    // page size sends the reader back to page 1. Carrying the old page number over
    // would land somebody on page 6 of a two-page result, and the clamp in pagingOf()
    // would then quietly move them again.
    '<form method="get" action="/admin/tokens"><div class="formrow">' +
      '<label for="family">Family</label><select id="family" name="family">' + familyOptions +
      '</select>' +
      '<label for="kind">Kind</label><select id="kind" name="kind">' + kindOptions + '</select>' +
      '<label for="state">State</label><select id="state" name="state">' + stateOptions + '</select>' +
      '<label for="per">Per page</label><select id="per" name="per">' + perOptions + '</select>' +
      '<button class="secondary">Filter</button>' +
      (wantedFamily || wantedKind || wantedState ? ' <a href="/admin/tokens">clear</a>' : '') +
    '</div></form>' +
    // Family and Kind are ANDed, like any two filters, so a contradictory pair
    // (Kerberos tickets, id_token) matches nothing. Said here rather than prevented,
    // because the alternative is a page that silently ignores one of the two
    // selects the reader can see it obeying.
    '<p class="note">Family and Kind narrow together: choosing a family and a kind from a ' +
    'different one matches nothing, which is what an empty table below then means.</p>' +
    nav +
    '<table><tr><th>Kind</th><th>State</th><th>User</th><th>Subject</th>' +
    '<th>Client, audience or service</th><th>Detail</th>' +
    '<th>Presented as</th><th>Issued</th><th>Expires</th><th>jti or ID</th><th></th></tr>' +
    (rows || '<tr><td colspan="11">Nothing matches.</td></tr>') + '</table>' +
    nav +
    '<p class="note">' + filtered.length + ' row(s) match' +
    (paging.pages > 1 ? ', of which rows ' + paging.firstRow + '&ndash;' + paging.lastRow +
                        ' are on this page (' + paging.page + ' of ' + paging.pages + ')' : '') +
    '; ' + all.length + ' held in total — ' +
    stats.ISSUED_FAMILIES.map(function (entry) {
      return (heldByFamily[entry.family] || 0) + ' ' + esc(entry.label);
    }).join(', ') +
    '. Newest first, so page 1 is what somebody is most likely to be debugging. Only the claims ' +
    'and the facts below are kept, never the signed token, the assertion XML or the ticket: a page ' +
    'rendering a thousand live credentials in a form a browser will display is a page that leaks ' +
    'them, and the <code>jti</code> is all any button here needs.</p>' +

    '<h3>What each column means</h3>' +
    '<p class="note">Three families in one table, so most columns answer a slightly different ' +
    'question depending on the row. Rather than leave that to be inferred:</p>' +
    COLUMN_LEGEND +
    '<p class="note">OID4VCI credentials are <strong>not</strong> in this table. They are recorded ' +
    'and counted on <a href="/admin/metrics">the metrics page</a> and listed nowhere. That is a ' +
    'gap rather than a principle — a credential is as much an issued artifact as an assertion is — ' +
    'and it is named here so that "everything this service has issued" above is read as the three ' +
    'families it says and not as four.</p>' +

    '<p class="note">Paging is <code>?page=</code> and <code>?per=</code> (at most ' + MAX_ROWS +
    ' rows a page), and both work with <code>?format=json</code> — where the reply carries ' +
    '<code>page</code>, <code>pages</code> and <code>matched</code>, so a test can walk the whole ' +
    'list without guessing when it has reached the end. The rows are in <code>issued</code> there, ' +
    'each carrying its <code>family</code>; it was <code>tokens</code> when this page listed only ' +
    'JWTs. Every button on this page acts on a <code>jti</code> and never on a row number, so a ' +
    'revocation between two clicks cannot make the wrong token the target — the most it can do is ' +
    'shift a row onto another page.</p>';

  respond(req, res, {
    held: all.length, matched: filtered.length, shown: shown.length,
    heldByFamily: stats.ISSUED_FAMILIES.reduce(function (out, entry) {
      out[entry.family] = heldByFamily[entry.family] || 0;
      return out;
    }, {}),
    filter: { family: wantedFamily || null, kind: wantedKind || null, state: wantedState || null },
    // The clamped values, not what was asked for: `?page=999` on a two-page list
    // reports page 2, which is the page whose rows are in the reply.
    page: paging.page, pages: paging.pages, perPage: paging.perPage,
    firstRow: paging.firstRow, lastRow: paging.lastRow,
    families: stats.ISSUED_FAMILIES,
    revocableKinds: stats.REVOCABLE_KINDS,
    revokedCount: stats.revokedCount(),
    // `issued` rather than `tokens`, because the array is no longer only tokens and
    // a key that says otherwise is the kind of thing a test asserts against once and
    // then trusts. Nothing outside this repository read the old name.
    issued: shown
  }, 'Tokens', '/admin/tokens', inner);
  log.debug("Leaving the admin tokens page.");
});

// ---------------------------------------------------------------------------
// GET /admin/users — who this service has authenticated, and one of them in full.
//
// One route and two pages: without `?user=` it is the list, with it the drill-down.
// That is deliberate rather than lazy. A path parameter would have been the obvious
// shape and cannot be used here, because the identities this service holds contain
// the characters a path is made of — a Kerberos service principal is `HTTP/host` and
// a subject is a `urn:` — so `/admin/users/HTTP/web.example.com` is a two-segment
// path naming nobody. A query parameter carries any of them unaltered and keeps the
// console to one row in the metrics table for the whole feature.
//
// **What "a user" means here, and the two ways it can surprise you.** The list is
// built in admin_stats.js from the authentications this service recorded, PLUS every
// subject that appears on something it issued — so a subject that never authenticated
// here (an exchanged foreign token, a WS-Trust OnBehalfOf, a Kerberos S4U2Self) is
// listed and marked as such, rather than being absent from a page whose whole job is
// to answer "who has this service seen". And the identity is keyed on the local name,
// so one row covers `alice`, `urn:sts-mock:user:alice` and `alice@STS.MOCK`, which is
// right on a mock where the name you type is who you are everywhere — and would be
// wrong on a real system with two realms. The Realms column exists so that collapse
// is visible.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE EMBEDDED DIRECTORY'S VIEW OF ONE USER, AND WHY IT ARRIVES THROUGH A SLOT.
//
// ldap_server.js grows an entry under `ou=users` for everybody who authenticates
// anywhere in this service, so by the time a person has a page here they usually
// have a directory object too — and showing it beside their tokens is the point:
// the two are the same authentication seen from two sides.
//
// This module does NOT require ldap_server.js to get at it, and the reason is the
// route order rather than a cycle. server.js requires ./admin before
// ./ldap_server (that module needs admin_stats' identity normalisation, and the
// console reads oauth2's sessions), so a require from here would pull the
// directory's routes into the router AHEAD of the console's — and /sts-metadata is
// built by walking that router. So the direction is inverted the same way
// admin_stats.js's user observer is: this file offers a slot, and ldap_server.js
// fills it at its own require time.
//
// It stays null when that module was never required. That is a real state — the
// directory is the newest thing here and a build without it must still render this
// page — so the section says "no directory is loaded" rather than being absent,
// which would read as "this user has no entry".
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// The two things every LDAP section of this console draws, in one place each
// because there are now three such sections — a user's entry, the groups list
// and one group in full.
// ---------------------------------------------------------------------------

// What a section is showing, in the four grammatical forms the listener warning
// needs. A warning about sockets has to name the thing the reader came for —
// the whole point of it is the gap between "this service holds it" and "an LDAP
// client can fetch it" — and that sentence needs a noun that agrees with itself.
const ENTRY_SUBJECT = { upper: 'The entry below', lower: 'the entry below',
                        verb: 'is', pronoun: 'it' };
const GROUPS_SUBJECT = { upper: 'The groups below', lower: 'the groups below',
                         verb: 'are', pronoun: 'they' };
const GROUP_SUBJECT = { upper: 'The group below', lower: 'the group below',
                        verb: 'is', pronoun: 'it' };

// The state of the directory's two sockets as a banner, or '' when both are up.
//
// Three cases rather than two, because plain 389 and LDAPS 636 are independent
// sockets and either can be up while the other is not — which is the commonest
// outcome of a host run, where 636 is privileged and 389 has usually lost the
// port to the host's own slapd. A page that said "no client can connect" while
// LDAPS was answering would be wrong in the direction that costs somebody an
// afternoon looking for a directory that was there all along.
function directoryListenerWarning(info, subject) {
  if (!info.listening && !info.ldapsListening) {
    return '<div class="warn"><strong>The directory\'s listeners are not up</strong> — ' +
      esc(info.listenError || 'it never bound') + '. ' + subject.upper + ' ' + subject.verb +
      ' in this process\'s store and ' + subject.verb + ' what an LDAP client WOULD read; ' +
      'right now no client can connect, most likely because TCP ' + esc(info.port) +
      ' was already taken. This page is HTTP and answers either way.</div>';
  }
  if (!info.listening) {
    return '<div class="warn"><strong>The directory\'s plain listener is not up</strong> — ' +
      esc(info.listenError || 'it never bound') + ' — but <strong>LDAPS on ' +
      esc(info.ldapsPort) + ' is</strong>, so ' + subject.lower + ' ' + subject.verb +
      ' reachable over TLS. TCP ' + esc(info.port) + ' was most likely already taken.</div>';
  }
  if (info.ldapsPort && !info.ldapsListening) {
    return '<div class="warn">The plain listener on ' + esc(info.port) + ' is up; ' +
      '<strong>LDAPS is not</strong>. That affects how ' + subject.lower + ' can be ' +
      'reached, not whether ' + subject.pronoun + ' ' + subject.verb + ' there.</div>';
  }
  return '';
}

// Every attribute of one entry, operational ones included, as the table both the
// user page and the group page draw. `entry` is what the directory's readers
// return: canonically spelled names, values already arrays, and `operational`
// naming which of them a search would have withheld.
function attributeTable(entry) {
  const rows = Object.keys(entry.attributes).map(function (name) {
    const values = entry.attributes[name];
    const operational = entry.operational.indexOf(name) >= 0;
    return '<tr><td><code>' + esc(name) + '</code>' +
      (operational
        ? ' <span class="state-none" title="An operational attribute. A search returns it only ' +
          'when it is asked for by name (RFC 4511 section 4.5.1.8) — this dump shows it always.' +
          '">(operational)</span>'
        : '') + '</td>' +
      '<td class="num">' + values.length + '</td>' +
      '<td>' + (values.map(function (value) {
        return '<code>' + esc(value) + '</code>';
      }).join('<br>') || '—') + '</td></tr>';
  }).join('');
  return '<table><tr><th>Attribute</th><th class="num">Values</th><th>Value(s)</th></tr>' +
    rows + '</table>';
}

let directoryReader = null;

function setDirectoryReader(fn) {
  directoryReader = fn;
  log.debug("A directory reader was installed; a user's page will now show that " +
            "user's LDAP entry.");
}

// The groups pages read through their own slot, installed the same way and by the
// same module, for the reason above: this file must not require ldap_server.js.
//
// Two slots rather than one object with two functions, because they were added at
// different times and a single slot would mean an ldap_server.js that filled it
// with only one of them silently disabling the other. A missing slot is already
// handled — each page says "no directory is loaded" — and two of those are cheaper
// than one half-filled reader nothing reports.
let groupReader = null;

function setGroupReader(fn) {
  groupReader = fn;
  log.debug("A group reader was installed; /admin/groups will now show the " +
            "directory's groups.");
}

// The whole section, as HTML and as the object that goes into ?format=json. Both
// come out of one call so that the page and the JSON cannot disagree about what
// the directory holds, which is the same rule /ldap follows for its own two views.
//
// `row` is the user record: it is what tells a missing entry apart from an entry
// that was never going to exist. Four of the five reasons for an absence are facts
// about the USER rather than about the directory — a client is not a person, an
// LDAP bind presents a DN and not a user name, an identity that only ever appeared
// as the subject of something never authenticated at all — and a section that said
// only "not found" would send a reader to look for a bug in the directory.
function ldapObjectSection(row, key) {
  log.debug("Entering ldapObjectSection(). key=" + key);
  const heading = '<h2>This user in the LDAP directory</h2>';
  if (!directoryReader) {
    log.debug("Leaving ldapObjectSection(). No directory is loaded.");
    return {
      html: heading +
        '<p class="note">No LDAP directory is loaded in this process, so there is no entry to ' +
        'show. That is a build of this service without <code>ldap_server.js</code> and not a ' +
        'failure — every other section of this page is unaffected.</p>',
      json: null
    };
  }
  const info = directoryReader(key);
  const link = '<p class="note"><a href="/ldap">What this directory is</a> &middot; ' +
    '<a href="/ldap/directory">every entry in it</a> &middot; ' +
    '<a href="/ldap/directory?format=json">the same as JSON</a>.</p>';
  // Said on every branch, including the ones with an entry: the entry can be there
  // and the socket down, and a reader who trusts this page to mean "an LDAP client
  // can fetch this" needs to know which.
  const listener = directoryListenerWarning(info, ENTRY_SUBJECT);
  const alsoNamed = info.alsoNamed.length
    ? '<p class="note">' + info.alsoNamed.length + ' other entr' +
      (info.alsoNamed.length === 1 ? 'y names' : 'ies name') + ' this uid: ' +
      codeList(info.alsoNamed) + '. Those were written through the protocol rather than seeded ' +
      'by an authentication — this directory has no schema and does not require a uid to be ' +
      'unique, so they are shown rather than merged.</p>'
    : '';

  if (!info.found) {
    // Why not, in the order that makes the first true one the real answer. The DN
    // is quoted with it, EXCEPT where the identity is an LDAP bind DN — there the
    // name this console files the person under is itself a DN, so the place an
    // entry would have gone is `uid=<a whole DN>,ou=users,...`, and leading with
    // that reads as a malformed directory rather than as the explanation that
    // follows it.
    let because;
    let intro = 'There is no entry at <code>' + esc(info.dn) + '</code>.';
    if (!info.autoCreateUsers) {
      because = 'An entry per authenticated user is switched OFF in this process ' +
        '(<code>LDAP_AUTOCREATE_USERS</code>), so nothing here seeds one.';
    } else if (row.isClient) {
      because = 'This identity is a <strong>client</strong>, not a person. ' +
        '<code>client_credentials</code> produces tokens with a subject and nobody behind them, ' +
        'and a directory of people is the wrong place for it, so the directory declines to ' +
        'invent one.';
    } else if (!row.authenticated) {
      because = 'This identity has <strong>never authenticated here</strong>. The entry is ' +
        'seeded at the moment a credential is ACCEPTED, and this one is known only as the ' +
        'subject of something that was issued — so there was no such moment.';
    } else if (row.protocols.length === 1 && row.protocols[0].protocol === 'ldap') {
      intro = 'Nothing was seeded for this identity.';
      because = 'Everything this identity has done here is an <strong>LDAP bind</strong>, which ' +
        'presents a DN rather than a user name. Seeding <code>uid=&lt;a whole DN&gt;</code> under ' +
        '<code>' + esc(info.usersDn) + '</code> would put a second, malformed object beside the ' +
        'one the DN already names.';
    } else if (info.full) {
      because = 'The directory holds its maximum of ' + esc(info.maxEntries) + ' entries, so it ' +
        'stopped creating them. The authentication itself was unaffected — a full directory ' +
        'must never fail one.';
    } else {
      because = 'It was there and is not now: an entry can be <code>delete</code>d or ' +
        '<code>modifyDN</code>&rsquo;d through the protocol like any other, and nothing puts it ' +
        'back until this name authenticates again.';
    }
    log.debug("Leaving ldapObjectSection(). There is no entry at " + info.dn + ".");
    return {
      html: heading + listener +
        '<p class="note">' + intro + ' ' + because + '</p>' + alsoNamed + link,
      json: info
    };
  }

  const entry = info.entry;

  const html = heading + listener +
    '<p class="note">The entry the embedded directory holds for this person &mdash; the object ' +
    'itself and not a copy of it, so an LDAP client bound to <code>ldap://&lt;host&gt;:' +
    esc(info.port) + '</code> reading <code>' + esc(entry.dn) + '</code> sees exactly this. It ' +
    'appeared the first time they authenticated through any protocol here, and it carries no ' +
    'password: <strong>every bind to this directory succeeds anyway</strong>, whatever DN and ' +
    'whatever password, so nothing in this object is a credential.</p>' +
    '<table><tr><th>DN</th><th>Came from</th><th>Created</th><th>Last modified</th></tr>' +
    '<tr><td><code>' + esc(entry.dn) + '</code></td>' +
    '<td>' + esc(entry.origin) + '</td>' +
    '<td><code>' + esc(entry.createdAt) + '</code></td>' +
    '<td><code>' + esc(entry.modifiedAt) + '</code></td></tr></table>' +
    '<p class="note">The two timestamps are <em>generalized time</em> ' +
    '(<code>YYYYMMDDHHMMSSZ</code>), which is what a directory shows &mdash; not the ISO 8601 ' +
    'strings the rest of this console uses. The difference is only punctuation and it is kept ' +
    'because a debugger that showed one where the protocol carries the other would be showing ' +
    'the wrong thing.</p>' +
    attributeTable(entry) +
    '<p class="note">Every attribute the entry has, operational ones included. This directory is ' +
    '<strong>schemaless</strong>: no <code>objectClass</code> is enforced and no value is checked ' +
    'against a syntax, so an attribute a real directory would refuse is here because something ' +
    'wrote it. The <code>description</code> values are this service\'s own note of which ' +
    'protocols this person has authenticated through &mdash; one line per protocol, added the ' +
    'first time each is seen.</p>' +
    alsoNamed + link;

  log.debug("Leaving ldapObjectSection(). " + Object.keys(entry.attributes).length +
            " attribute(s) dumped.");
  return { html: html, json: info };
}

// The live sign-on sessions belonging to one user. Sessions are keyed by an opaque
// id and hold a user object, so the match is on the identity rather than the string:
// the session says `alice` and the tokens say `urn:sts-mock:user:alice`, and these
// have to end up on the same page.
function sessionRowsFor(key) {
  log.debug("Entering sessionRowsFor(). key=" + key);
  const rows = signOnSessionRows().filter(function (session) {
    return stats.identityKeyOf(session.username || session.sub) === key;
  });
  log.debug("Leaving sessionRowsFor(). " + rows.length + " session(s).");
  return rows;
}

// The tokens of one user, split by the session they were issued on.
//
// Three buckets, and the third is the one worth explaining. A token whose record
// names a session that is no longer held is not an error: sessions expire and are
// swept, and the token outlives the sign-on it came from — that is exactly the state
// an OIDC client is in when its ID Token still verifies and the browser would be
// asked to sign in again. Showing those under "no session" would say something false
// about how they were issued.
function tokensBySession(tokens, sessionRows) {
  log.debug("Entering tokensBySession(). " + tokens.length + " token(s).");
  const held = {};
  sessionRows.forEach(function (session) { held[session.id] = []; });
  const ended = [];
  const sessionless = [];
  tokens.forEach(function (record) {
    if (!record.sessionId) {
      sessionless.push(record);
      return;
    }
    if (held[record.sessionId]) {
      held[record.sessionId].push(record);
      return;
    }
    ended.push(record);
  });
  log.debug("Leaving tokensBySession(). " + Object.keys(held).length + " session(s), " +
            ended.length + " on an ended session, " + sessionless.length + " with none.");
  return { held: held, ended: ended, sessionless: sessionless };
}

// One user's tokens as a table. The columns are the ones that differ WITHIN a user:
// their name and subject are the same on every row by construction and are stated
// once above the table instead of repeated down it.
function userTokenTable(records, back, empty) {
  log.debug("Entering userTokenTable(). " + records.length + " row(s).");
  const rows = records.map(function (record) {
    const button = record.revocable
      ? '<form method="post" action="/admin/tokens" class="inline">' +
        '<input type="hidden" name="action" value="' + (record.revoked ? 'restore' : 'revoke') + '">' +
        '<input type="hidden" name="target" value="' + esc(record.jti) + '">' +
        '<input type="hidden" name="from" value="users">' +
        '<input type="hidden" name="back" value="' + esc(back) + '">' +
        '<button class="' + (record.revoked ? 'secondary' : 'danger') + '">' +
        (record.revoked ? 'Restore' : 'Revoke') + '</button></form>'
      : '<span class="state-none" title="Only access tokens, ID Tokens and refresh tokens can be ' +
        'revoked — the others are replies rather than credentials, or carry no jti to act on.">—</span>';
    return '<tr><td>' + esc(record.kind) + '</td>' +
      '<td class="' + stateClass(record.state) + '">' + esc(record.state) + '</td>' +
      '<td>' + esc(record.grant || '—') + '</td>' +
      '<td>' + esc(record.client_id || '—') + '</td>' +
      '<td>' + esc(record.scope || '—') + '</td>' +
      '<td>' + (record.jkt ? 'DPoP' : 'Bearer') + '</td>' +
      '<td>' + esc(whenText(record.issuedAt)) + '</td>' +
      '<td>' + esc(record.exp ? whenText(record.exp * 1000) : '—') + '</td>' +
      '<td>' + shortened(record.jti, 12) + '</td>' +
      '<td>' + button + '</td></tr>';
  }).join('');
  log.debug("Leaving userTokenTable().");
  return '<table><tr><th>Token</th><th>State</th><th>Grant</th><th>Client</th><th>Scope</th>' +
    '<th>Presented as</th><th>Issued</th><th>Expires</th><th>jti</th><th></th></tr>' +
    (rows || '<tr><td colspan="10">' + esc(empty) + '</td></tr>') + '</table>';
}

// The artifacts that are not JWTs. One table for all three kinds, with a single
// Detail column, because an assertion's audience, a ticket's service and enc-type
// and a credential's configuration id are each the one thing worth reading about
// that row and giving each its own column would leave two thirds of the table empty.
function userArtifactTable(records) {
  log.debug("Entering userArtifactTable(). " + records.length + " row(s).");
  const rows = records.map(function (record) {
    const detail = record.service
      ? 'service ' + record.service + (record.etype ? ', ' + record.etype : '') +
        (record.realm ? ', realm ' + record.realm : '')
      : (record.audience ? 'audience ' + record.audience
                         : (record.configId ? 'configuration ' + record.configId : ''));
    return '<tr><td>' + esc(record.kind) + '</td>' +
      '<td class="' + stateClass(record.state) + '">' + esc(record.state) + '</td>' +
      '<td>' + esc(detail || '—') + '</td>' +
      '<td>' + (record.id ? shortened(record.id, 20) : '<span class="state-none" ' +
        'title="A Kerberos ticket has no identifier to quote: it is named by the client and ' +
        'service it is for.">—</span>') + '</td>' +
      '<td>' + esc(whenText(record.issuedAt)) + '</td>' +
      '<td>' + esc(record.expiresAt ? whenText(record.expiresAt) : '—') + '</td></tr>';
  }).join('');
  log.debug("Leaving userArtifactTable().");
  return '<table><tr><th>Artifact</th><th>State</th><th>Detail</th><th>Identifier</th>' +
    '<th>Issued</th><th>Expires</th></tr>' +
    (rows || '<tr><td colspan="6">Nothing that is not a JWT has been issued to this user.</td></tr>') +
    '</table>';
}

// How they authenticated, most recent first. The whole point of the table is the
// Method column: "sign-in screen (password)" and "AS-REQ with PA-ENC-TIMESTAMP" are
// both authentications and only one of them checked anything.
function authenticationTable(row) {
  log.debug("Entering authenticationTable(). " + row.events.length + " event(s).");
  const rows = row.events.slice().reverse().map(function (event) {
    return '<tr><td>' + esc(whenText(event.at)) + '</td>' +
      '<td>' + esc(event.protocol) + '</td>' +
      '<td>' + esc(event.method) + '</td>' +
      '<td>' + esc(event.presented) + '</td>' +
      '<td>' + esc(event.amr || '—') + '</td>' +
      '<td>' + esc(event.acr || '—') + '</td>' +
      '<td>' + esc(event.client_id || '—') + '</td>' +
      '<td>' + (event.sessionId ? shortened(event.sessionId, 10) : '—') + '</td>' +
      '<td>' + esc(event.note || '') + '</td></tr>';
  }).join('');
  log.debug("Leaving authenticationTable().");
  return '<table><tr><th>When</th><th>Protocol</th><th>Method</th><th>Presented as</th>' +
    '<th>amr</th><th>acr</th><th>Client</th><th>Session</th><th>Note</th></tr>' +
    (rows || '<tr><td colspan="9">No authentication was recorded for this identity. See above: ' +
             'they are known here only as the subject of something that was issued.</td></tr>') +
    '</table>' +
    (row.eventsForgotten > 0
      ? '<p class="note">The most recent ' + stats.MAX_EVENTS_PER_USER + ' of ' +
        (row.eventsForgotten + row.events.length) + ' authentication(s); the rest have been ' +
        'forgotten. The counts above them are of all of them and are not capped.</p>'
      : '');
}

// One session and everything issued on it. This is the answer to the question the
// page exists for — "what does this person hold right now, and where did it come
// from" — so the session's own facts and its tokens are drawn as one block rather
// than as two tables somebody has to join by eye.
function sessionBlock(session, tokens, back) {
  log.debug("Entering sessionBlock(). id=" + session.id);
  const html = '<h3>Session ' + shortened(session.id, 12) + ' &mdash; ' +
    '<span class="' + (session.expired ? 'state-expired' : 'state-valid') + '">' +
    (session.expired ? 'expired, not yet swept' : 'active') + '</span></h3>' +
    '<table><tr><th>Signed in</th><th>Expires</th><th>amr</th><th>acr</th>' +
    '<th>WS-Fed relying parties signed into</th></tr>' +
    '<tr><td>' + esc(whenText(session.authTime)) + '</td>' +
    '<td>' + esc(whenText(session.expires)) + '</td>' +
    '<td>' + esc(session.amr || '—') + '</td>' +
    '<td>' + esc(session.acr || '—') + '</td>' +
    '<td>' + (session.wsfedRealms.length ? esc(session.wsfedRealms.join(', ')) : '—') + '</td></tr></table>' +
    userTokenTable(tokens, back,
      'Nothing has been issued on this session yet. A browser can hold a sign-on session and have ' +
      'been given no token at all — it is what the authorization endpoint reads before it issues ' +
      'anything.');
  log.debug("Leaving sessionBlock().");
  return html;
}

// The drill-down. Returns null when the identity is not one this service knows,
// which the route below turns into an honest empty page rather than a 404: a user
// can genuinely be forgotten to the cap between the click and the page.
function userDetailPage(req, key) {
  log.debug("Entering userDetailPage(). key=" + key);
  const detail = stats.userDetail(key);
  if (!detail) {
    log.debug("Leaving userDetailPage(). No such user.");
    return null;
  }
  const row = detail.user;
  const sessionRows = sessionRowsFor(key);
  const live = sessionRows.filter(function (s) { return !s.expired; });
  const split = tokensBySession(detail.tokens, sessionRows);
  // Where a revoke button on this page returns to: this user's page, which is the
  // only sensible answer — the reader is looking at one person and wants to see the
  // effect on that person.
  const back = queryWith({ user: key }, {});
  const valid = detail.tokens.filter(function (t) { return t.state === 'valid'; }).length;
  // Read before the markup is assembled rather than inside it, because it is also
  // one of the keys of the JSON view below and reading it twice could show a page
  // and a JSON body that disagree about a directory another request just changed.
  const directory = ldapObjectSection(row, key);

  const sessionBlocks = sessionRows.map(function (session) {
    return sessionBlock(session, split.held[session.id] || [], back);
  }).join('');

  const inner = messagesOf(req) +
    '<div class="tiles">' +
      tile(row.authentications, 'authentications') +
      tile(row.protocols.length, 'protocols') +
      tile(live.length, 'active sessions') +
      tile(detail.tokens.length, 'tokens issued') +
      tile(valid, 'tokens still valid') +
      tile(detail.artifacts.length, 'assertions, tickets, credentials') +
    '</div>' +
    '<p class="note">Everything below is about the identity <code>' + esc(row.name) + '</code>, ' +
    'which is <a href="/admin/users">one row of the users list</a>. ' +
    (row.authenticated
      ? 'They have presented a credential to this service ' + row.authentications + ' time(s).'
      : '<strong>They have never authenticated here.</strong> This identity is known only because ' +
        'something was issued naming them as its subject — an exchanged token from another issuer, ' +
        'a WS-Trust <code>OnBehalfOf</code>, or a Kerberos S4U request made by a service. Nothing ' +
        'about this row says the person was ever present.') +
    (row.isClient
      ? ' <strong>This is a client, not a person</strong>: it appears here because ' +
        '<code>client_credentials</code> produces tokens with a subject and no human behind them.'
      : '') + '</p>' +

    '<h2>Names this identity has been seen under</h2>' +
    '<p class="note">One person reaches this service under several spellings and they are the same ' +
    'row here — see the note at the top of the users list for what that costs.</p>' +
    '<table><tr><th>As presented</th><th class="num">Times</th></tr>' +
    (row.forms.map(function (form) {
      return '<tr><td><code>' + esc(form.form) + '</code></td><td class="num">' + form.count + '</td></tr>';
    }).join('') || '<tr><td colspan="2">—</td></tr>') + '</table>' +
    (row.realms.length
      ? '<p class="note">Kerberos realm(s): ' +
        codeList(row.realms.map(function (r) { return r.realm; })) + '.</p>'
      : '') +

    '<h2>How they authenticated</h2>' +
    '<table><tr><th>Protocol</th><th class="num">Times</th><th>Methods</th><th>Last</th></tr>' +
    (row.protocols.map(function (family) {
      return '<tr><td>' + esc(family.protocol) + '</td>' +
        '<td class="num">' + family.count + '</td>' +
        '<td>' + esc(family.methods.map(function (m) {
          return m.method + ' ×' + m.count;
        }).join('; ')) + '</td>' +
        '<td>' + esc(whenText(family.lastAt)) + '</td></tr>';
    }).join('') || '<tr><td colspan="4">Never, here.</td></tr>') + '</table>' +
    authenticationTable(row) +

    '<h2>Sessions, and what was issued on each</h2>' +
    '<p class="note">A <strong>sign-on session</strong> is a browser holding the ' +
    '<code>sts_mock_session</code> cookie, shared between the OAuth 2.0 / OIDC login screen and ' +
    'WS-Federation. A token is placed under a session because the issuance said so — no token ' +
    'this service issues carries a session identifier, and OIDC\'s <code>sid</code> claim is for ' +
    'front-channel logout, so inventing one to make this page easier would change what every ' +
    'client receives. The link is recorded out of band at issuance instead, and it survives a ' +
    'refresh: a refreshed token is looked up by the refresh token\'s <code>jti</code> and lands ' +
    'under the same session.</p>' +
    (sessionBlocks || '<p class="note">This user holds no sign-on session. That is the normal state ' +
      'for every identity that never used a browser here — a password grant, a Kerberos client, a ' +
      'WS-Trust requester — and for anyone whose session has expired and been swept.</p>') +

    (split.ended.length
      ? '<h3>Issued on a session that has since ended</h3>' +
        '<p class="note">These name a session this service no longer holds. It is not an error and ' +
        'it is the ordinary end state: the session expired or was signed out, and the tokens it ' +
        'produced outlived it — which is exactly the position a client is in when its access token ' +
        'still verifies and the browser would be asked to sign in again.</p>' +
        userTokenTable(split.ended, back, '')
      : '') +

    (split.sessionless.length
      ? '<h3>Issued with no browser session at all</h3>' +
        '<p class="note">The grants that never involve a browser: <code>password</code>, ' +
        '<code>client_credentials</code>, OID4VCI\'s pre-authorized code, and token exchange. The ' +
        'Grant column says which. An empty Grant means the token was minted somewhere that states ' +
        'nothing about how — WS-Trust\'s JWT and the credential issuer both sign directly.</p>' +
        userTokenTable(split.sessionless, back, '')
      : '') +

    '<h2>Assertions, tickets and credentials</h2>' +
    '<p class="note">None of these can be revoked here and the console does not pretend otherwise: ' +
    'nothing consults this service about a SAML assertion, a Kerberos ticket or a credential, so a ' +
    'button would change a number on this page and nothing at all out there. The only distinction ' +
    'is whether the validity window has closed.</p>' +
    userArtifactTable(detail.artifacts) +

    directory.html +

    '<h2>Invalidate everything for this user</h2>' +
    '<p class="note">Every access token, ID Token and refresh token held for this identity under ' +
    'any of its spellings, revoked through the same set <code>/oauth2/revoke</code> writes to. ' +
    'Assertions and tickets are untouched, for the reason above.</p>' +
    '<form method="post" action="/admin/tokens">' +
      '<input type="hidden" name="action" value="revoke-user">' +
      '<input type="hidden" name="user" value="' + esc(key) + '">' +
      '<input type="hidden" name="from" value="users">' +
      '<input type="hidden" name="back" value="' + esc(back) + '">' +
      '<div class="formrow"><button class="danger">Revoke everything for ' + esc(row.name) +
      '</button></div></form>';

  log.debug("Leaving userDetailPage(). " + detail.tokens.length + " token(s) shown.");
  return {
    inner: inner,
    json: {
      user: row,
      sessions: sessionRows.map(function (session) {
        return Object.assign({}, session, { tokens: split.held[session.id] || [] });
      }),
      tokensOnEndedSessions: split.ended,
      tokensWithNoSession: split.sessionless,
      artifacts: detail.artifacts,
      // null when no directory is loaded in this process, which is a different
      // answer from an entry that is not there — that one is an object whose
      // `found` is false and which says where it would have been.
      ldap: directory.json
    }
  };
}

// The list. Filtered by a name fragment and by protocol, and paged with the same
// controls the tokens page uses.
function usersListPage(req) {
  log.debug("Entering usersListPage().");
  const wantedText = String(req.query.q || '').trim();
  const wantedProtocol = String(req.query.protocol || '');
  const all = stats.userRows();
  // Every protocol any known user authenticated through, for the filter. Read off the
  // data rather than written down, so a protocol that starts recording authentications
  // appears in the dropdown by itself and one that never has cannot offer a filter
  // that matches nothing.
  const protocolsSeen = {};
  all.forEach(function (row) {
    row.protocols.forEach(function (family) { protocolsSeen[family.protocol] = true; });
  });
  const filtered = all.filter(function (row) {
    if (wantedText && row.key.toLowerCase().indexOf(wantedText.toLowerCase()) < 0) return false;
    if (wantedProtocol && !row.protocols.some(function (f) { return f.protocol === wantedProtocol; })) {
      return false;
    }
    return true;
  });
  const paging = pagingOf(req.query, filtered.length);
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  const filterParams = { q: wantedText, protocol: wantedProtocol,
                         per: req.query.per ? paging.perPage : '' };
  const nav = pageNav('/admin/users', filterParams, paging);

  // Sessions are counted per user here rather than fetched per row inside the loop:
  // one pass over the session map instead of one per user, and more importantly one
  // definition of "active" for the list and the drill-down both.
  const liveByUser = {};
  signOnSessionRows().forEach(function (session) {
    if (session.expired) return;
    const key = stats.identityKeyOf(session.username || session.sub);
    liveByUser[key] = (liveByUser[key] || 0) + 1;
  });

  const rows = shown.map(function (row) {
    const href = '/admin/users' + queryWith({ user: row.key }, {});
    return '<tr><td><a href="' + esc(href) + '"><code>' + esc(row.name) + '</code></a></td>' +
      '<td>' + (row.isClient ? 'client' : 'user') + '</td>' +
      '<td class="' + (row.authenticated ? 'state-valid' : 'state-none') + '">' +
        (row.authenticated ? row.authentications + '&times;' : 'never') + '</td>' +
      '<td>' + esc(row.protocols.map(function (f) { return f.protocol; }).join(', ') || '—') + '</td>' +
      '<td>' + esc(row.realms.map(function (r) { return r.realm; }).join(', ') || '—') + '</td>' +
      '<td class="num">' + (liveByUser[row.key] || 0) + '</td>' +
      '<td class="num">' + row.tokens.issued + '</td>' +
      '<td class="num state-valid">' + row.tokens.valid + '</td>' +
      '<td class="num state-revoked">' + row.tokens.revoked + '</td>' +
      '<td class="num">' + row.artifacts + '</td>' +
      '<td>' + esc(row.firstAt ? whenText(row.firstAt) : '—') + '</td>' +
      '<td>' + esc(whenText(row.lastActivityAt)) + '</td>' +
      '<td><a href="' + esc(href) + '">sessions and tokens &rsaquo;</a></td></tr>';
  }).join('');

  const protocolOptions = [''].concat(Object.keys(protocolsSeen).sort()).map(function (p) {
    return '<option value="' + esc(p) + '"' + (p === wantedProtocol ? ' selected' : '') + '>' +
           esc(p || 'any protocol') + '</option>';
  }).join('');
  const perChoices = [25, DEFAULT_PER_PAGE, 100, MAX_ROWS];
  if (perChoices.indexOf(paging.perPage) < 0) {
    perChoices.push(paging.perPage);
    perChoices.sort(function (a, b) { return a - b; });
  }
  const perOptions = perChoices.map(function (n) {
    return '<option value="' + n + '"' + (n === paging.perPage ? ' selected' : '') + '>' +
           n + ' rows</option>';
  }).join('');

  const authenticatedHere = all.filter(function (row) { return row.authenticated; }).length;
  const inner = messagesOf(req) +
    '<div class="tiles">' +
      tile(all.length, 'identities known') +
      tile(authenticatedHere, 'authenticated here') +
      tile(all.length - authenticatedHere, 'seen only as a subject') +
      tile(all.filter(function (row) { return row.isClient; }).length, 'clients, not people') +
      tile(Object.keys(liveByUser).length, 'with an active session') +
    '</div>' +
    '<p class="note">Every userid this service has been given as part of an interaction that ' +
    'succeeded — the name typed at either sign-in screen, the one on a password grant, the subject ' +
    'of a WS-Security <code>UsernameToken</code>, the client principal in a Kerberos AS-REQ or an ' +
    'accepted AP-REQ, and the subject of an exchanged token. A request that was REFUSED records ' +
    'nothing, so this is a list of identities that got somewhere rather than of names that were ' +
    'tried. Click a name for its sessions and everything issued to it.</p>' +
    '<div class="warn"><strong>One row is one local name, across every protocol.</strong> The same ' +
    'person arrives here as <code>alice</code> at the login screen, ' +
    '<code>urn:sts-mock:user:alice</code> in every token and <code>alice@STS.MOCK</code> as a ' +
    'Kerberos principal, and showing three rows for that would be a worse answer than one — the ' +
    'premise of this service is that the name you type is who you are in every protocol at once. ' +
    'What it costs: two different people called <code>alice</code> in two Kerberos realms are one ' +
    'row here. The Realms column is what makes that visible. Case is never collapsed, because ' +
    'nothing in this service treats <code>Alice</code> and <code>alice</code> as one.</div>' +

    '<form method="get" action="/admin/users"><div class="formrow">' +
      '<label for="q">Name contains</label>' +
      '<input type="text" id="q" name="q" size="20" value="' + esc(wantedText) + '">' +
      '<label for="protocol">Authenticated through</label>' +
      '<select id="protocol" name="protocol">' + protocolOptions + '</select>' +
      '<label for="per">Per page</label><select id="per" name="per">' + perOptions + '</select>' +
      '<button class="secondary">Filter</button>' +
      (wantedText || wantedProtocol ? ' <a href="/admin/users">clear</a>' : '') +
    '</div></form>' +
    nav +
    '<table><tr><th>User</th><th>Kind</th><th>Authenticated</th><th>Protocols</th><th>Realms</th>' +
    '<th class="num">Sessions</th><th class="num">Tokens</th><th class="num">Valid</th>' +
    '<th class="num">Revoked</th><th class="num">Artifacts</th><th>First seen</th>' +
    '<th>Last activity</th><th></th></tr>' +
    (rows || '<tr><td colspan="13">Nobody matches. Nothing has authenticated here yet unless a ' +
             'filter above is hiding it.</td></tr>') + '</table>' +
    nav +
    '<p class="note">' + filtered.length + ' identit' + (filtered.length === 1 ? 'y' : 'ies') +
    ' match; ' + all.length + ' known in total, most recently active first. An identity marked ' +
    '<em>never</em> under Authenticated has been issued something without ever presenting a ' +
    'credential here: an exchanged token from another issuer, a WS-Trust <code>OnBehalfOf</code>, ' +
    'or a Kerberos S4U request that a service made in their name. Listing them is the point — a ' +
    'users page that showed only the sign-ins would deny the existence of subjects the tokens ' +
    'page is showing at the same moment.</p>' +
    '<p class="note">All of it is in memory and dies with the process, and the registry holds the ' +
    'most recent ' + stats.MAX_USERS + ' identities.' +
    '</p>';

  log.debug("Leaving usersListPage(). " + shown.length + " row(s) drawn.");
  return {
    inner: inner,
    json: {
      known: all.length, matched: filtered.length, shown: shown.length,
      authenticatedHere: authenticatedHere,
      filter: { q: wantedText || null, protocol: wantedProtocol || null },
      protocols: Object.keys(protocolsSeen).sort(),
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      users: shown
    }
  };
}

app.get('/admin/users', function (req, res) {
  log.debug("Entering the admin users page.");
  const wantedUser = String(req.query.user || '').trim();
  if (wantedUser) {
    const detail = userDetailPage(req, wantedUser);
    if (!detail) {
      // Not a 404: this service has simply never seen the name, or has forgotten it
      // to the cap since the link was drawn. Both are answers rather than errors, and
      // a 404 here would send a test looking for a routing problem.
      const inner = messagesOf(req) +
        '<p class="note">Nothing here has authenticated as <code>' + esc(wantedUser) + '</code>, ' +
        'and nothing has been issued naming them. Either the name is not one this service has ' +
        'seen, or it has been forgotten — the registry holds the most recent ' + stats.MAX_USERS +
        ' identities, and everything in it dies with the process.</p>' +
        '<p class="note"><a href="/admin/users">Back to the list</a>.</p>';
      respond(req, res, { user: wantedUser, known: false }, 'User', '/admin/users', inner);
      log.debug("Leaving the admin users page. No such user.");
      return;
    }
    respond(req, res, Object.assign({ known: true }, detail.json),
            'User ' + wantedUser, '/admin/users', detail.inner);
    log.debug("Leaving the admin users page. Drew the drill-down.");
    return;
  }
  const list = usersListPage(req);
  respond(req, res, list.json, 'Users', '/admin/users', list.inner);
  log.debug("Leaving the admin users page. Drew the list.");
});

// ---------------------------------------------------------------------------
// GET /admin/groups — every group in the embedded directory, and one of them in
// full.
//
// The one page in this console whose whole content comes from another module.
// Everything else here reads admin_stats.js; this reads the directory through
// the slot ldap_server.js fills, and it renders exactly what that returns
// without deciding anything — including what counts as a group, which is that
// module's rule and is stated on the page rather than reimplemented here.
//
// A GROUP IS NOT AN AUTHORISATION HERE, and the page says so where a reader will
// see it. Nothing in this service reads these groups: no token carries them, no
// SAML assertion has them as an attribute, no endpoint checks one. They are a
// directory's objects for a directory client to read, and a console that listed
// them beside the tokens page without saying that would let somebody conclude
// that adding a user to `cn=directory-admins` changed what their token could do.
// ---------------------------------------------------------------------------

// The heading a group's link carries, and the fallback when it has no cn — an
// entry can be a group by placement alone, and `(no cn)` is a truer label than an
// empty cell that reads as a rendering fault.
function groupLabel(group) {
  return group.cn || '(no cn)';
}

// Why this entry counted as a group, in words. The rule is ldap_server.js's; this
// is only its three values spelled out, and it is on the page because "developers
// is a group" is uninteresting next to "this entry is a group because somebody put
// it under ou=groups and it carries no group objectClass at all".
const GROUP_RULES = {
  both: { label: 'placement + objectClass',
          title: 'It is under ou=groups AND carries a group objectClass. This is what a group ' +
                 'written the conventional way looks like.' },
  placement: { label: 'placement only',
               title: 'It is under ou=groups but carries no group objectClass. This directory ' +
                      'is schemaless, so nothing refused the add — it is listed here because ' +
                      'of where it sits.' },
  objectClass: { label: 'objectClass only',
                 title: 'It carries a group objectClass but sits outside ou=groups. Nothing ' +
                        'here requires a group to live under the groups container.' }
};

function groupRuleCell(rule) {
  const rendered = GROUP_RULES[rule];
  if (!rendered) {
    return '<span class="state-none">' + esc(rule || 'unstated') + '</span>';
  }
  return '<span title="' + esc(rendered.title) + '">' + esc(rendered.label) + '</span>';
}

// THE TWO LISTS ARE DIFFERENT QUESTIONS, and this is where that shows.
//
// The directory holds an entry for anybody somebody wrote one for — the three it
// seeds at startup, and whatever a client has added since. The users page holds
// everybody who has actually presented a credential to this service. `alice` is
// in the directory from the moment the process starts and is on the users page
// only once somebody signs in as her, so a member row that always linked there
// would usually land on "nothing here has authenticated as alice", which reads
// as a broken link rather than as the fact it is.
//
// So the console's own user registry is consulted, and a member it does not know
// is named without a link and with the reason. Reading it once per page rather
// than once per row is deliberate: userRows() walks the whole registry.
function knownUserKeys() {
  const known = {};
  stats.userRows().forEach(function (row) {
    known[row.key] = true;
  });
  return known;
}

// A member's link. To the group page when the member is itself a group, so
// nesting can be walked; to the users page when this console has actually seen
// that person authenticate. Neither, and the DN stands on its own — which is the
// commonest case in a directory nobody has signed in to yet.
function memberLink(member, known) {
  const label = '<code>' + esc(member.dn) + '</code>';
  if (member.kind === 'group') {
    return '<a href="' + esc('/admin/groups' + queryWith({ group: member.dn }, {})) +
      '">' + label + '</a>';
  }
  if (member.userKey && known[member.userKey]) {
    return '<a href="' + esc('/admin/users' + queryWith({ user: member.userKey }, {})) +
      '">' + label + '</a>';
  }
  return label;
}

// The "On the users page" cell, for a member and for a memberOf claimant alike.
// Three states and they are all worth telling apart: a name this console has seen
// authenticate, a name it could file somebody under but never has, and an entry
// named in a way that yields no user name at all.
function usersPageCell(userKey, known) {
  if (!userKey) {
    return '<span class="state-none" title="This entry is not named uid=&lt;name&gt; and carries ' +
      'no uid, so there is no name to look it up by. The console files people under the local ' +
      'name userFor() derives; an entry named some other way — a cn=, or the one a TLS client ' +
      'certificate seeds — has none.">—</span>';
  }
  if (!known[userKey]) {
    return '<span class="state-none" title="The directory holds an entry for them and nothing ' +
      'has authenticated as this name in this process, so the users page has no row to link to. ' +
      'The two lists answer different questions: the directory is what somebody wrote into it, ' +
      'the users page is who has actually presented a credential here.">' + esc(userKey) +
      ' <em>(never here)</em></span>';
  }
  return '<a href="' + esc('/admin/users' + queryWith({ user: userKey }, {})) + '">' +
    esc(userKey) + '</a>';
}

// What this directory's groups are and are not, said on both pages. Repeated
// rather than shown once on the list, for the reason the open-console banner is
// repeated: the page somebody arrives at directly is exactly the one that needs it.
const GROUPS_CAVEAT =
  '<p class="note"><strong>A group here grants nothing.</strong> Nothing in this service reads ' +
  'them: no access token, ID Token, SAML assertion, WS-Federation token or Kerberos PAC carries ' +
  'a group from this directory, and no endpoint checks one. They exist for an LDAP client to ' +
  'read, write and search. Adding somebody to <code>cn=directory-admins</code> changes what a ' +
  'directory client sees and changes nothing at all about what their token can do &mdash; on a ' +
  'service that authenticates nobody, it could hardly be otherwise.</p>';

function noGroupDirectorySection() {
  return '<p class="note">No LDAP directory is loaded in this process, so there are no groups to ' +
    'show. That is a build of this service without <code>ldap_server.js</code> and not a failure ' +
    '&mdash; every other page of this console is unaffected.</p>';
}

const GROUPS_LINKS =
  '<p class="note"><a href="/ldap">What this directory is</a> &middot; ' +
  '<a href="/ldap/directory">every entry in it</a> &middot; ' +
  '<a href="/ldap/directory?format=json">the same as JSON</a> &middot; ' +
  '<a href="/admin/users">the people who have authenticated here</a>.</p>';

// The list.
function groupsListPage(req) {
  log.debug("Entering groupsListPage().");
  const info = groupReader('');
  const wantedText = String(req.query.q || '').trim();
  const needle = wantedText.toLowerCase();
  const filtered = info.groups.filter(function (group) {
    if (!needle) {
      return true;
    }
    // The DN and the cn both, because a person looking for a group has one or the
    // other in mind and which one depends on whether they came from an LDAP client
    // or from this console.
    return group.dn.toLowerCase().indexOf(needle) >= 0 ||
           String(group.cn).toLowerCase().indexOf(needle) >= 0;
  });
  const paging = pagingOf(req.query, filtered.length);
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  const filterParams = { q: wantedText || '', per: req.query.per || '' };
  const nav = pageNav('/admin/groups', filterParams, paging);

  const rows = shown.map(function (group) {
    const href = '/admin/groups' + queryWith({ group: group.dn }, {});
    return '<tr><td><a href="' + esc(href) + '">' + esc(groupLabel(group)) + '</a></td>' +
      '<td class="who"><code>' + esc(group.dn) + '</code></td>' +
      '<td>' + groupRuleCell(group.rule) + '</td>' +
      '<td class="num">' + group.memberCount + '</td>' +
      '<td class="num">' + (group.presentCount
        ? '<span class="state-valid">' + group.presentCount + '</span>'
        : '<span class="state-none">0</span>') + '</td>' +
      '<td class="num">' + (group.danglingCount
        ? '<span class="state-revoked" title="Membership values naming an entry this directory ' +
          'does not hold. Deleting a user does not remove it from the groups that list it — ' +
          'referential integrity is a directory feature and not a protocol rule, and this ' +
          'directory deliberately does not have it.">' + group.danglingCount + '</span>'
        : '<span class="state-none">0</span>') + '</td>' +
      '<td class="num">' + (group.claimedCount
        ? '<span class="state-expired" title="Entries whose own memberOf names this group and ' +
          'which this group does not list back. Nothing here maintains memberOf, so a client ' +
          'that writes it creates exactly this disagreement.">' + group.claimedCount + '</span>'
        : '<span class="state-none">0</span>') + '</td>' +
      '<td class="num">' + group.attributeCount + '</td>' +
      '<td>' + esc(group.origin) + '</td>' +
      '<td><code>' + esc(group.modifiedAt) + '</code></td></tr>';
  }).join('');

  const totalMembers = info.groups.reduce(function (n, g) { return n + g.memberCount; }, 0);
  const totalDangling = info.groups.reduce(function (n, g) { return n + g.danglingCount; }, 0);

  const inner = messagesOf(req) +
    directoryListenerWarning(info, GROUPS_SUBJECT) +
    '<div class="tiles">' +
    tile(info.groupCount, 'Groups') +
    tile(totalMembers, 'Membership values') +
    tile(totalDangling, 'Dangling') +
    tile(info.entryCount, 'Entries in the directory') +
    '</div>' +
    '<form method="get" action="/admin/groups"><div class="formrow">' +
    '<label for="q">Group</label>' +
    '<input type="text" id="q" name="q" value="' + esc(wantedText) + '" size="28" ' +
    'placeholder="part of a cn or a DN">' +
    '<button type="submit">Filter</button>' +
    (wantedText ? ' <a href="/admin/groups">clear</a>' : '') +
    '</div></form>' +
    nav +
    '<table><tr><th>Group</th><th>DN</th><th>Counted because</th><th class="num">Members</th>' +
    '<th class="num">Resolve</th><th class="num">Dangling</th><th class="num">Claimed</th>' +
    '<th class="num">Attributes</th><th>Came from</th><th>Last modified</th></tr>' +
    (rows || '<tr><td colspan="10">No group matches. ' +
             (wantedText ? 'The filter above may be hiding some.' : 'This directory holds none — ' +
              'the two it seeds can be deleted through the protocol like any other entry.') +
             '</td></tr>') + '</table>' +
    nav +
    '<p class="note">A group is an entry that sits under <code>' + esc(info.groupsDn) + '</code>, ' +
    'or that carries one of the group object classes (<code>groupOfNames</code>, ' +
    '<code>groupOfUniqueNames</code>, <code>posixGroup</code>, <code>groupOfURLs</code>) wherever ' +
    'it sits &mdash; either rule is enough, and the column above says which one caught each. Both ' +
    'are applied because this directory is <strong>schemaless</strong>: nothing stops a client ' +
    'adding a <code>groupOfNames</code> under <code>' + esc(info.usersDn) + '</code>, or an entry ' +
    'with no <code>objectClass</code> at all under the groups container, and a page that applied ' +
    'only one rule would answer for one of those and quietly lose the other.</p>' +
    '<p class="note"><strong>Members</strong> counts the values of <code>member</code>, ' +
    '<code>uniqueMember</code> and <code>memberUid</code> together; <strong>Resolve</strong> is ' +
    'how many of them name an entry this directory actually holds and <strong>Dangling</strong> ' +
    'is the rest. The two are shown apart because a group whose seven members resolve to five is ' +
    'this directory doing exactly what it says it does &mdash; deleting a user leaves its DN in ' +
    'every group that listed it &mdash; and one combined number would report that as seven ' +
    'members with nothing wrong. <strong>Claimed</strong> is the disagreement in the other ' +
    'direction: entries whose own <code>memberOf</code> names the group while the group does not ' +
    'list them back.</p>' +
    GROUPS_CAVEAT + GROUPS_LINKS;

  log.debug("Leaving groupsListPage(). " + shown.length + " row(s) drawn of " +
            info.groupCount + " group(s).");
  return {
    inner: inner,
    json: {
      groupCount: info.groupCount, matched: filtered.length, shown: shown.length,
      membershipValues: totalMembers, dangling: totalDangling,
      filter: { q: wantedText || null },
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      baseDn: info.baseDn, groupsDn: info.groupsDn, usersDn: info.usersDn,
      port: info.port, listening: info.listening, listenError: info.listenError,
      ldapsPort: info.ldapsPort, ldapsListening: info.ldapsListening,
      groups: shown
    }
  };
}

// One group: every attribute it has, and everybody in it.
function groupDetailPage(req, wantedDn) {
  log.debug("Entering groupDetailPage(). dn=" + wantedDn);
  const info = groupReader(wantedDn);
  const back = '<p class="note"><a href="/admin/groups">Back to the groups</a>.</p>';

  if (!info.found) {
    // Three ways to be here and they are different answers, so they get different
    // words. A 404 is none of them: the console linked here from a list it drew
    // from this same store, and the interesting case is precisely that the store
    // has changed since — a client can delete a group, rename it out of
    // ou=groups, or strip its objectClass through the protocol between one click
    // and the next.
    const because = info.notAGroup
      ? 'There <strong>is</strong> an entry at <code>' + esc(info.entryDn) + '</code>, and it is ' +
        'not a group: it sits outside <code>' + esc(info.groupsDn) + '</code> and carries no ' +
        'group <code>objectClass</code>. A <code>modifyDN</code> out of the groups container or ' +
        'a <code>modify</code> that deleted the <code>objectClass</code> does exactly this, and ' +
        'neither is refused &mdash; this directory has no schema. ' +
        '<a href="/ldap/directory">The full dump</a> still shows it.'
      : 'Nothing is at <code>' + esc(wantedDn) + '</code>. Either it was <code>delete</code>d or ' +
        '<code>modifyDN</code>&rsquo;d through the protocol since the link was drawn, or the DN ' +
        'was typed. DNs are compared case-folded and with the space after each comma ignored, so ' +
        'the spelling is not what is wrong.';
    log.debug("Leaving groupDetailPage(). Not a group.");
    return {
      inner: messagesOf(req) + directoryListenerWarning(info, GROUP_SUBJECT) +
        '<p class="note">' + because + '</p>' + back,
      json: Object.assign({ found: false }, info)
    };
  }

  const group = info.group;
  const known = knownUserKeys();

  const memberRows = group.members.map(function (member) {
    const state = member.present
      ? '<span class="state-valid">in the directory</span>'
      : '<span class="state-revoked" title="The value names an entry this directory does not ' +
        'hold. It is shown rather than dropped: nothing here enforces referential integrity, ' +
        'so this is the state the protocol leaves behind when a member is deleted.">dangling' +
        '</span>';
    return '<tr><td class="who">' + memberLink(member, known) + '</td>' +
      '<td><code>' + esc(member.attribute) + '</code></td>' +
      '<td>' + state + '</td>' +
      '<td>' + esc(member.kind === 'group' ? 'a group' :
                   member.kind === 'entry' ? 'an entry' : '—') + '</td>' +
      '<td>' + (member.cn ? esc(member.cn) : '<span class="state-none">—</span>') + '</td>' +
      '<td>' + (member.mail ? '<code>' + esc(member.mail) + '</code>'
                            : '<span class="state-none">—</span>') + '</td>' +
      '<td>' + usersPageCell(member.userKey, known) + '</td>' +
      // The raw value, last, because for `member` and `uniqueMember` it is the DN
      // in the first column all over again — and for `memberUid` it is not, which
      // is the whole reason the column is here.
      '<td class="who"><code>' + esc(member.value) + '</code></td></tr>';
  }).join('');

  const claimedRows = group.claimed.map(function (entry) {
    return '<tr><td class="who"><code>' + esc(entry.dn) + '</code></td>' +
      '<td>' + (entry.cn ? esc(entry.cn) : '<span class="state-none">—</span>') + '</td>' +
      '<td>' + (entry.mail ? '<code>' + esc(entry.mail) + '</code>'
                           : '<span class="state-none">—</span>') + '</td>' +
      '<td>' + usersPageCell(entry.userKey, known) + '</td></tr>';
  }).join('');

  const claimedSection = group.claimed.length
    ? '<h2>Entries that claim this group, and that it does not list</h2>' +
      '<table><tr><th>DN</th><th>cn</th><th>mail</th><th>On the users page</th></tr>' +
      claimedRows + '</table>' +
      '<p class="note">Each of these carries a <code>memberOf</code> naming this group while this ' +
      'group&rsquo;s own <code>member</code> does not name them back. <strong>Nothing here ' +
      'maintains <code>memberOf</code></strong> &mdash; it is not a standard attribute at all ' +
      '(Microsoft&rsquo;s directory and OpenLDAP&rsquo;s <code>memberof</code> overlay both write ' +
      'it, the server keeping it in step with <code>member</code> itself), and a schemaless mock ' +
      'that neither writes nor checks it lets a client create exactly this disagreement in one ' +
      '<code>modify</code>. They are listed apart from the members above rather than merged into ' +
      'them, because which side of the disagreement a name came from is the only interesting ' +
      'thing about it.</p>'
    : '';

  const inner = messagesOf(req) +
    directoryListenerWarning(info, GROUP_SUBJECT) +
    '<h2>' + esc(groupLabel(group)) + '</h2>' +
    '<table><tr><th>DN</th><th>Counted as a group because</th><th>Came from</th>' +
    '<th>Created</th><th>Last modified</th></tr>' +
    '<tr><td class="who"><code>' + esc(group.dn) + '</code></td>' +
    '<td>' + groupRuleCell(group.rule) + '</td>' +
    '<td>' + esc(group.origin) + '</td>' +
    '<td><code>' + esc(group.createdAt) + '</code></td>' +
    '<td><code>' + esc(group.modifiedAt) + '</code></td></tr></table>' +
    '<p class="note">The two timestamps are <em>generalized time</em> ' +
    '(<code>YYYYMMDDHHMMSSZ</code>), which is what a directory shows &mdash; not the ISO 8601 ' +
    'strings the rest of this console uses. An LDAP client bound to <code>ldap://&lt;host&gt;:' +
    esc(info.port) + '</code> reading <code>' + esc(group.dn) + '</code> sees exactly the object ' +
    'below, because it <em>is</em> that object and not a copy of it.</p>' +

    '<h2>Members</h2>' +
    '<div class="tiles">' +
    tile(group.memberCount, 'Membership values') +
    tile(group.presentCount, 'Resolve to an entry') +
    tile(group.danglingCount, 'Dangling') +
    tile(group.claimed.length, 'Claim it back') +
    '</div>' +
    (group.memberCount
      ? '<table><tr><th>Member</th><th>From</th><th>State</th><th>What it is</th><th>cn</th>' +
        '<th>mail</th><th>On the users page</th><th>The value as stored</th></tr>' +
        memberRows + '</table>'
      : '<p class="note">This group lists nobody. An empty <code>groupOfNames</code> is something ' +
        'a real directory refuses &mdash; RFC 4519 makes <code>member</code> MUST &mdash; and ' +
        'this one has no schema, so it is here because something wrote it.</p>') +
    '<p class="note">Membership is read from <code>' + esc(group.memberAttributes.join('</code>, ' +
    '<code>')) + '</code>. The first two hold a <strong>DN</strong>; <code>memberUid</code> holds ' +
    'a bare user name, which is looked up under <code>' + esc(info.usersDn) + '</code> &mdash; ' +
    'treating the three alike is how a page ends up reporting every <code>posixGroup</code> ' +
    'member as dangling. <strong>Nesting is shown and not expanded</strong>: a member that is ' +
    'itself a group links to its own page, and nobody inside it is counted here, because nothing ' +
    'in this service walks a group tree and a flattened list would be claiming a feature that is ' +
    'not here.</p>' +
    '<p class="note">The last column links to the users page only for somebody this service has ' +
    'actually seen <strong>authenticate</strong>. The other members are marked <em>never ' +
    'here</em>, and that is not a fault: the directory holds whatever somebody wrote into it — ' +
    'the three people it seeds at startup, and anything a client has added since — while the ' +
    'users page holds whoever has presented a credential to this process. <code>alice</code> is ' +
    'in this directory from the moment it starts and appears on the users page only once ' +
    'somebody signs in as her. A link that was always drawn would usually land on &ldquo;nothing ' +
    'here has authenticated as alice&rdquo;, which reads as a broken link rather than as the ' +
    'answer it is.</p>' +
    claimedSection +

    '<h2>Every attribute this group has</h2>' +
    attributeTable(group) +
    '<p class="note">The whole object, operational attributes included &mdash; a search returns ' +
    'those only when they are asked for by name (RFC 4511 &sect;4.5.1.8), and this is a dump ' +
    'rather than a search. The membership attributes are in here too, as the raw values the ' +
    'store holds; the table above is the same values resolved. This directory is ' +
    '<strong>schemaless</strong>: no <code>objectClass</code> is enforced and no value is checked ' +
    'against a syntax, so an attribute a real directory would refuse is here because something ' +
    'wrote it.</p>' +
    GROUPS_CAVEAT + back + GROUPS_LINKS;

  log.debug("Leaving groupDetailPage(). " + group.memberCount + " member value(s), " +
            Object.keys(group.attributes).length + " attribute(s).");
  return { inner: inner, json: Object.assign({ found: true }, info) };
}

app.get('/admin/groups', function (req, res) {
  log.debug("Entering the admin groups page.");
  if (!groupReader) {
    // A build without ldap_server.js. Answered rather than 404'd, and with the
    // nav intact, for the same reason the user page's directory section says it
    // in words: the page exists, the directory does not, and those are different
    // facts about this process.
    respond(req, res, { directory: false, groups: [] }, 'Groups', '/admin/groups',
            messagesOf(req) + noGroupDirectorySection());
    log.debug("Leaving the admin groups page. No directory is loaded.");
    return;
  }
  const wantedDn = String(req.query.group || '').trim();
  if (wantedDn) {
    const detail = groupDetailPage(req, wantedDn);
    respond(req, res, detail.json, 'Group ' + wantedDn, '/admin/groups', detail.inner);
    log.debug("Leaving the admin groups page. Drew the drill-down.");
    return;
  }
  const list = groupsListPage(req);
  respond(req, res, list.json, 'Groups', '/admin/groups', list.inner);
  log.debug("Leaving the admin groups page. Drew the list.");
});

// ---------------------------------------------------------------------------
// GET /admin/claims, POST /admin/claims
// ---------------------------------------------------------------------------
function claimsAction(body) {
  log.debug("Entering claimsAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const setId = String(body.set || '');
  if (stats.CLAIM_SET_IDS.indexOf(setId) < 0) {
    log.debug("Leaving claimsAction(). No such set.");
    return { ok: false, errors: ['There is no claim set called "' + setId + '". The four are: ' +
                                 stats.CLAIM_SET_IDS.join(', ') + '.'] };
  }
  const label = stats.CLAIM_SETS[setId].label;

  if (action === 'add') {
    const entry = { name: String(body.name || '').trim(), value: String(body.value == null ? '' : body.value) };
    if (body.nameFormat) entry.nameFormat = String(body.nameFormat).trim();
    if (body.namespace) entry.namespace = String(body.namespace).trim();
    const result = stats.setClaimSet(setId, stats.claimSet(setId).concat([entry]));
    log.debug("Leaving claimsAction(). add -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, claims: result.claims,
          message: 'Added "' + entry.name + '" to the ' + label + ' claim set. Every one of those ' +
                   'issued from now on carries it; nothing already issued changes.' }
      : result;
  }

  if (action === 'remove') {
    const name = String(body.name || '').trim();
    const remaining = stats.claimSet(setId).filter(function (c) { return c.name !== name; });
    if (remaining.length === stats.claimSet(setId).length) {
      log.debug("Leaving claimsAction(). Nothing named that.");
      return { ok: false, errors: ['The ' + label + ' claim set has no claim called "' + name + '".'] };
    }
    const result = stats.setClaimSet(setId, remaining);
    log.debug("Leaving claimsAction(). remove -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, claims: result.claims,
          message: 'Removed "' + name + '" from the ' + label + ' claim set.' }
      : result;
  }

  if (action === 'clear') {
    stats.setClaimSet(setId, []);
    log.debug("Leaving claimsAction(). Cleared.");
    return { ok: true, set: setId, claims: [],
             message: 'The ' + label + ' claim set is empty again.' };
  }

  if (action === 'replace') {
    let entries = body.claims;
    if (typeof entries === 'string') {
      try {
        entries = JSON.parse(entries || '[]');
      } catch (e) {
        log.debug("Leaving claimsAction(). The JSON did not parse.");
        return { ok: false, errors: ['That is not valid JSON: ' + e.message] };
      }
    }
    if (!Array.isArray(entries)) {
      log.debug("Leaving claimsAction(). Not an array.");
      return { ok: false, errors: ['Give a JSON ARRAY of {"name": ..., "value": ...} objects. An ' +
                                   'empty array clears the set.'] };
    }
    const result = stats.setClaimSet(setId, entries);
    log.debug("Leaving claimsAction(). replace -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, claims: result.claims,
          message: 'The ' + label + ' claim set now has ' + result.claims.length + ' custom claim(s).' }
      : result;
  }

  log.debug("Leaving claimsAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The four are: add, remove, clear, ' +
                               'replace.'] };
}

app.post('/admin/claims', function (req, res) {
  log.debug("Entering the admin claims action endpoint.");
  const body = parseBody(req);
  const result = claimsAction(body);
  respondToAction(req, res, '/admin/claims', result);
  log.debug("Leaving the admin claims action endpoint.");
});

// One set, rendered: what is in it, a way to remove each, and a way to add another.
// The three sets differ in the extra field each needs, which is why the form is
// built from the set's kind rather than being one form four times.
function claimSetSection(setId) {
  log.debug("Entering claimSetSection(). setId=" + setId);
  const set = stats.CLAIM_SETS[setId];
  const claims = stats.claimSet(setId);
  const isSaml2 = setId === 'saml2';
  const isSaml11 = setId === 'saml11';
  const extraHeader = isSaml2 ? '<th>NameFormat</th>' : (isSaml11 ? '<th>AttributeNamespace</th>' : '');

  const rows = claims.map(function (claim) {
    const extraCell = isSaml2 ? '<td>' + esc(claim.nameFormat || '—') + '</td>'
                    : (isSaml11 ? '<td>' + shortened(claim.namespace, 44) + '</td>' : '');
    return '<tr><td><code>' + esc(claim.name) + '</code></td>' + extraCell +
      '<td><code>' + esc(claim.value) + '</code></td>' +
      '<td><form method="post" action="/admin/claims" class="inline">' +
      '<input type="hidden" name="action" value="remove">' +
      '<input type="hidden" name="set" value="' + esc(setId) + '">' +
      '<input type="hidden" name="name" value="' + esc(claim.name) + '">' +
      '<button class="secondary">Remove</button></form></td></tr>';
  }).join('');

  const extraInput = isSaml2
    ? '<label for="nf-' + setId + '">NameFormat</label>' +
      '<input type="text" id="nf-' + setId + '" name="nameFormat" size="28" placeholder="(optional)">'
    : (isSaml11
      ? '<label for="ns-' + setId + '">Namespace</label>' +
        '<input type="text" id="ns-' + setId + '" name="namespace" size="34" placeholder="' +
        esc(stats.DEFAULT_SAML11_NAMESPACE) + '">'
      : '');

  log.debug("Leaving claimSetSection(). " + claims.length + " claim(s).");
  return '<h3>' + esc(set.label) + ' <code>' + esc(setId) + '</code></h3>' +
    '<table><tr><th>Name</th>' + extraHeader + '<th>Value</th><th></th></tr>' +
    (rows || '<tr><td colspan="' + (extraHeader ? 4 : 3) + '">No custom claim is configured; ' +
             'these tokens carry only what the protocol puts in them.</td></tr>') + '</table>' +
    '<form method="post" action="/admin/claims"><div class="formrow">' +
      '<input type="hidden" name="action" value="add">' +
      '<input type="hidden" name="set" value="' + esc(setId) + '">' +
      '<label for="n-' + setId + '">Name</label>' +
      '<input type="text" id="n-' + setId + '" name="name" size="20">' +
      extraInput +
      '<label for="v-' + setId + '">Value</label>' +
      '<input type="text" id="v-' + setId + '" name="value" size="28">' +
      '<button>Add</button>' +
      '</div></form>' +
    (claims.length
      ? '<form method="post" action="/admin/claims" class="inline">' +
        '<input type="hidden" name="action" value="clear">' +
        '<input type="hidden" name="set" value="' + esc(setId) + '">' +
        '<button class="secondary">Clear this set</button></form>'
      : '');
}

app.get('/admin/claims', function (req, res) {
  log.debug("Entering the admin claims page.");
  const setSelect = stats.CLAIM_SET_IDS.map(function (id) {
    return '<option value="' + esc(id) + '">' + esc(stats.CLAIM_SETS[id].label) + '</option>';
  }).join('');

  const inner = messagesOf(req) +
    '<p class="note">What to add to every token and assertion this service issues <em>from now ' +
    'on</em>. Nothing already issued changes — a token is a signed document and this page cannot ' +
    'reach inside one. Four sets, because the four are different vocabularies: an OAuth access ' +
    'token and an OIDC ID Token go to different readers (a resource server and a client), and SAML ' +
    '2.0 and SAML 1.1 spell an attribute differently enough that one list could not serve both.</p>' +

    '<div class="warn"><strong>Custom claims are additive.</strong> A configured claim is added to ' +
    'what the protocol already puts in the token and never replaces one. The names this service ' +
    'sets itself are refused rather than silently ignored: ' +
    codeList(stats.RESERVED_JWT_CLAIMS) + '. Every one of them is ' +
    'load-bearing somewhere here — an <code>exp</code> settable from a web form would produce ' +
    'tokens that fail to verify with nothing pointing back at this page.</div>' +

    '<h2>The four sets</h2>' +
    stats.CLAIM_SET_IDS.map(claimSetSection).join('') +

    '<h2>Values</h2>' +
    '<p class="note">A value may contain <code>${placeholders}</code>, because a claim that can only ' +
    'be a constant cannot exercise the thing worth testing — that a claim carrying the signed-in ' +
    'user\'s identity reaches the relying party. The ones understood are ' +
    codeList(stats.PLACEHOLDERS) + '. An unknown one is left as it was ' +
    'written rather than replaced with nothing: <code>${dept}</code> that silently became an empty ' +
    'string is a bug that looks like a configuration mistake, and one that still says ' +
    '<code>${dept}</code> names itself.</p>' +
    '<p class="note">A JWT claim value is typed: text that unambiguously looks like JSON — an ' +
    'object, an array, a bare <code>true</code>/<code>false</code>/<code>null</code>, or a number — ' +
    'is used as that JSON, and anything else is a string. One consequence, stated rather than left ' +
    'to be discovered: a claim whose value is genuinely the four characters <code>true</code> cannot ' +
    'be configured, because a text field cannot tell the two apart. Write <code>"true"</code>, which ' +
    'parses as the JSON string. SAML attribute values are never typed — the XML content model is ' +
    'text.</p>' +

    '<h2>Replace a whole set</h2>' +
    '<p class="note">The form a test wants. POST the same thing as JSON to get JSON back.</p>' +
    '<form method="post" action="/admin/claims">' +
      '<input type="hidden" name="action" value="replace">' +
      '<div class="formrow"><label for="set">Set</label>' +
      '<select id="set" name="set">' + setSelect + '</select></div>' +
      '<textarea name="claims" spellcheck="false">[{"name": "dept", "value": "engineering"}, ' +
      '{"name": "on_behalf_of", "value": "${username}"}]</textarea>' +
      '<div class="formrow"><button>Replace</button></div>' +
    '</form>';

  respond(req, res, {
    reservedJwtClaims: stats.RESERVED_JWT_CLAIMS,
    placeholders: stats.PLACEHOLDERS,
    defaultSaml11Namespace: stats.DEFAULT_SAML11_NAMESPACE,
    sets: stats.CLAIM_SET_IDS.map(function (id) {
      return { id: id, label: stats.CLAIM_SETS[id].label, claims: stats.claimSet(id) };
    })
  }, 'Custom claims', '/admin/claims', inner);
  log.debug("Leaving the admin claims page.");
});

// ---------------------------------------------------------------------------
// GET /admin/vc, POST /admin/vc
//
// WHICH CLAIMS AN ISSUED CREDENTIAL CARRIES. The page is a list of LDAP attribute
// types rather than of claim names, and vc_claims.js says at length why; the short
// version is that this service has a directory, so a claim can have a value that
// something other than the credential can see.
//
// It is the second page here that CHANGES what the protocol endpoints do, and the
// first that writes to the directory: saving a selection sweeps every person under
// ou=users and fills in what they are missing. That sweep is the whole point of
// the page rather than a side effect — without it, ticking `title` would change
// every future credential and change nothing an LDAP client could see, and the two
// halves of this service would quietly stop describing the same people.
// ---------------------------------------------------------------------------

// The values of a field that may appear MORE THAN ONCE in the body — which is what
// a list of checkboxes is, and what nothing else on this console needed until now.
//
// helpers.parseBody() cannot answer it: it builds a plain object, so a repeated
// field keeps only its LAST value and a form with ten boxes ticked would arrive as
// a selection of one. That is not a bug there — every other form on this console
// has scalar fields, and changing the shape of that function would change what
// eight other handlers see — so the repetition is read here, from the raw body,
// beside the parsed one.
function listField(req, body, name) {
  log.debug("Entering listField(). name=" + name);
  const type = String(req.headers['content-type'] || '');
  if (/json/i.test(type)) {
    const value = body[name];
    const out = Array.isArray(value) ? value.map(String)
              : (value == null || value === '' ? [] : [String(value)]);
    log.debug("Leaving listField(). " + out.length + " value(s) from a JSON body.");
    return out;
  }
  const raw = typeof req.body === 'string' ? req.body : '';
  const out = new URLSearchParams(raw).getAll(name);
  log.debug("Leaving listField(). " + out.length + " value(s) from a form body.");
  return out;
}

// The sweep's outcome as a sentence, appended to whatever message the action
// itself produced. It is stated on EVERY selection change, including the ones that
// changed nothing in the directory, because "0 entries gained anything" and "there
// is no directory here" are different facts and the page must not read the same
// for both.
function sweepText(sweep) {
  if (!sweep.loaded) {
    return ' The embedded directory is not loaded, so no entry was populated; ' +
           'credentials still carry these claims, generated per user.';
  }
  if (!sweep.ok) {
    return ' The directory could not be populated: ' + (sweep.errors || []).join(' ');
  }
  return ' Swept ' + sweep.examined + ' directory entry/entries; ' + sweep.changed +
         ' of them gained ' + sweep.values + ' value(s).';
}

function vcAction(body, names) {
  log.debug("Entering vcAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const current = vcClaims.selectedNames();

  if (action === 'select' || action === 'replace') {
    // `replace` is the same operation under the name a test would look for, and
    // the same name /admin/claims uses for "here is the whole set at once".
    const result = vcClaims.setSelection(names);
    if (!result.ok) {
      log.debug("Leaving vcAction(). The selection was refused.");
      return result;
    }
    const sweep = vcClaims.populateDirectory();
    log.debug("Leaving vcAction(). Selected " + result.selected.length + " attribute(s).");
    return { ok: true, selected: result.selected, added: result.added, removed: result.removed,
             sweep: sweep,
             message: 'A credential issued from now on carries ' + result.selected.length +
                      ' claim(s). Added: ' + (result.added.join(', ') || 'nothing') +
                      '. Removed: ' + (result.removed.join(', ') || 'nothing') + '.' +
                      sweepText(sweep) };
  }

  if (action === 'add' || action === 'remove') {
    const name = String(body.attribute || body.name || '').trim();
    if (!name) {
      log.debug("Leaving vcAction(). No attribute was named.");
      return { ok: false, errors: ['Name the attribute to ' + action + '.'] };
    }
    const lower = name.toLowerCase();
    const already = current.some(function (n) { return n.toLowerCase() === lower; });
    if (action === 'add' && already) {
      log.debug("Leaving vcAction(). Already selected.");
      return { ok: false, errors: ['"' + name + '" is already in the claim set.'] };
    }
    if (action === 'remove' && !already) {
      log.debug("Leaving vcAction(). Not selected.");
      return { ok: false, errors: ['"' + name + '" is not in the claim set.'] };
    }
    const wanted = action === 'add' ? current.concat([name])
                                    : current.filter(function (n) { return n.toLowerCase() !== lower; });
    const result = vcClaims.setSelection(wanted);
    if (!result.ok) {
      log.debug("Leaving vcAction(). The attribute was refused.");
      return result;
    }
    const sweep = vcClaims.populateDirectory();
    log.debug("Leaving vcAction(). " + action + " -> " + result.selected.length + " selected.");
    return { ok: true, selected: result.selected, sweep: sweep,
             message: (action === 'add' ? 'Added ' : 'Removed ') + name +
                      '. A credential issued from now on carries ' + result.selected.length +
                      ' claim(s).' + sweepText(sweep) };
  }

  if (action === 'defaults') {
    const result = vcClaims.resetSelection();
    const sweep = vcClaims.populateDirectory();
    log.debug("Leaving vcAction(). Restored the defaults.");
    return { ok: true, selected: result.selected, sweep: sweep,
             message: 'The claim set is the default ' + result.selected.length +
                      ' attribute(s) again — the six claims this issuer carried before this ' +
                      'page existed.' + sweepText(sweep) };
  }

  if (action === 'populate') {
    const sweep = vcClaims.populateDirectory();
    log.debug("Leaving vcAction(). Populated only.");
    return { ok: sweep.ok, errors: sweep.errors, selected: current, sweep: sweep,
             message: 'Populated the directory for the current claim set.' + sweepText(sweep) };
  }

  log.debug("Leaving vcAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The five are: select, add, ' +
                               'remove, defaults, populate.'] };
}

app.post('/admin/vc', function (req, res) {
  log.debug("Entering the admin credential-claims action endpoint.");
  const body = parseBody(req);
  // Two names for the list, because the two callers spell it differently and
  // neither spelling is wrong: a checkbox is one `attribute` repeated, and a JSON
  // body carries one `attributes` array.
  const names = listField(req, body, 'attribute').concat(listField(req, body, 'attributes'));
  const result = vcAction(body, names);
  respondToAction(req, res, '/admin/vc', result);
  log.debug("Leaving the admin credential-claims action endpoint.");
});

// The one preview row: what this attribute would put in a credential for the
// person the page is previewing, and where that value came from.
function vcExampleCell(row, persona, byLdap) {
  const found = byLdap[row.ldap.toLowerCase()];
  if (found) {
    return '<td><code>' + esc(found.value) + '</code></td><td>' + esc(found.source) + '</td>';
  }
  if (!row.from) {
    // The only row with no generator: `description`, which this service already
    // writes on every entry to record the protocols that person has used. Saying
    // so is the point — it is the one attribute whose value is a real fact.
    return '<td>—</td><td>the entry\'s own</td>';
  }
  // Shown in the form the CLAIM would take rather than the form the attribute
  // holds, because that is what the column above it is showing for the selected
  // rows and a table with two conventions in one column is a table nobody can
  // read. The two differ for exactly two attributes — a date and a postal
  // address — and both differences are punctuation.
  const raw = persona[row.from] == null ? '' : String(persona[row.from]);
  return '<td><code>' + esc(row.toClaim ? row.toClaim(raw) : raw) +
         '</code></td><td>would be generated</td>';
}

function vcAttributeTable(previewUser) {
  log.debug("Entering vcAttributeTable(). previewUser=" + previewUser);
  const persona = vcClaims.personaFor(previewUser);
  const built = vcClaims.subjectClaimsFor(previewUser, {});
  const byLdap = {};
  built.report.forEach(function (item) { byLdap[item.ldap.toLowerCase()] = item; });

  const rows = vcClaims.VC_ATTRIBUTES.map(function (row) {
    const on = vcClaims.isSelected(row.ldap);
    return '<tr><td><input type="checkbox" name="attribute" value="' + esc(row.ldap) + '"' +
      (on ? ' checked' : '') + '></td>' +
      '<td><code>' + esc(row.ldap) + '</code></td>' +
      '<td>' + esc(row.schema) + '</td>' +
      '<td><code>' + esc(row.claim.join('.')) + '</code></td>' +
      '<td>' + (row.ldpTerm ? '<code>' + esc(row.ldpTerm) + '</code>' : '<span class="state-none">—</span>') +
      '</td>' + vcExampleCell(row, persona, byLdap) + '</tr>';
  }).join('');

  log.debug("Leaving vcAttributeTable(). " + vcClaims.VC_ATTRIBUTES.length + " row(s).");
  return '<form method="post" action="/admin/vc">' +
    '<input type="hidden" name="action" value="select">' +
    '<table><tr><th>In</th><th>LDAP attribute</th><th>Defined by</th><th>Claim</th>' +
    '<th>ldp_vc term</th><th>In a credential for ' + esc(previewUser) + '</th><th>Source</th></tr>' +
    rows + '</table>' +
    '<div class="formrow"><button>Save this selection</button>' +
    '<span class="note">Saving also populates the directory: every person under ' +
    '<code>ou=users</code> gains the attributes they are missing.</span></div></form>' +
    '<div class="formrow">' +
    '<form method="post" action="/admin/vc" class="inline">' +
    '<input type="hidden" name="action" value="defaults">' +
    '<button class="secondary">Restore the six default claims</button></form> ' +
    '<form method="post" action="/admin/vc" class="inline">' +
    '<input type="hidden" name="action" value="populate">' +
    '<button class="secondary">Populate the directory now</button></form></div>';
}

// What a credential for this person would actually assert, claim by claim. It is
// built by the same function the issuer calls, not by a second walk of the
// catalogue — a preview that agreed with the page and disagreed with the
// credential would be worse than no preview.
function vcPreviewSection(previewUser) {
  log.debug("Entering vcPreviewSection(). previewUser=" + previewUser);
  const built = vcClaims.subjectClaimsFor(previewUser, {});
  const rows = built.report.map(function (item) {
    return '<tr><td><code>' + esc(item.claim) + '</code></td>' +
      '<td><code>' + esc(item.value) + '</code></td>' +
      '<td>' + esc(item.source) + '</td>' +
      '<td>' + (item.ldpTerm ? 'yes' : '<span class="state-none">no</span>') + '</td></tr>';
  }).join('');
  const omitted = vcClaims.ldpOmitted();

  log.debug("Leaving vcPreviewSection(). " + built.report.length + " claim(s).");
  return '<form method="get" action="/admin/vc"><div class="formrow">' +
    '<label for="user">Preview the credential for</label>' +
    '<input type="text" id="user" name="user" size="20" value="' + esc(previewUser) + '">' +
    '<button class="secondary">Show</button></div></form>' +
    '<p class="note">' + (built.entryFound
      ? 'This person has an entry in the directory, so the values below marked ' +
        '<em>directory</em> are what an LDAP client reads from it.'
      : 'This person has no entry in the directory — nobody has authenticated as them and ' +
        'nothing was added by hand — so every value below is generated. It will be the same ' +
        'one next time: the invented person is seeded from the username.') + '</p>' +
    '<table><tr><th>Claim</th><th>Value</th><th>From</th><th>In ldp_vc</th></tr>' +
    (rows || '<tr><td colspan="4">No attribute is selected, so a credential carries nothing ' +
             'but its subject identifier. That is a legitimate thing to test and is not a ' +
             'mistake this page will correct.</td></tr>') + '</table>' +
    (omitted.length
      ? '<p class="note"><strong>' + codeList(omitted) + '</strong> ' +
        (omitted.length === 1 ? 'is selected and does' : 'are selected and do') +
        ' not appear in an <code>ldp_vc</code> credential. That format is signed over ' +
        'canonicalized JSON-LD, so it can only carry terms the vendored context defines, and ' +
        'the context is vendored precisely because editing it would invalidate every ' +
        'credential already issued against it. The two JOSE-secured formats carry all of ' +
        'them.</p>'
      : '');
}

app.get('/admin/vc', function (req, res) {
  log.debug("Entering the admin credential-claims page.");
  // Somebody the directory actually holds, so the page shows real values on a
  // fresh start rather than an invented person nobody can look up. The parameter
  // wins where it is given; the cap is there because this string is echoed.
  const previewUser = String(req.query.user || 'alice').trim().slice(0, 64) || 'alice';

  const inner = messagesOf(req) +
    '<p class="note">Which claims a Verifiable Credential issued by this service carries, ' +
    '<em>from now on</em>. Nothing already issued changes — a credential is a signed document ' +
    'and this page cannot reach inside one. It applies to all five OID4VCI configurations: the ' +
    'SD-JWT VC, the <code>jwt_vc_json</code> W3C credential, the <code>ldp_vc</code> one with a ' +
    'BBS proof, and the two whose only difference is that the issuer names itself by DID.</p>' +

    '<p class="note">The list is of <strong>LDAP attribute types</strong> and not of claim ' +
    'names, because this service has a directory and a claim with a value nothing else can see ' +
    'is half a demonstration. A selected attribute becomes the claim named beside it, and the ' +
    'value is the one on that person\'s entry under <code>ou=users</code> — so an LDAP client ' +
    'and an OID4VCI wallet pointed at this service are shown the same person. Three rows are ' +
    'not RFC 4519/4524/2798: there is no standard attribute type for a birthdate or a ' +
    'nationality, so the SCHAC schema\'s names are borrowed rather than invented.</p>' +

    '<div class="warn"><strong>None of this is verified, and the values are garbage on ' +
    'purpose.</strong> This service authenticates nobody — the username typed at the sign-in ' +
    'screen is the identity in every token and credential it issues — so there is no source of ' +
    'a real birthdate here and there had better not be. What a person is missing is invented ' +
    'from their username: the same invented person every time, across restarts, so that two ' +
    'credentials issued a minute apart describe one human being rather than two. A verifier ' +
    'that believed any of it would be believing this page.</div>' +

    '<h2>The attributes</h2>' +
    vcAttributeTable(previewUser) +

    '<h2>What a credential would carry</h2>' +
    vcPreviewSection(previewUser) +

    '<h2>Where a value comes from</h2>' +
    '<p class="note">Three sources, in this order. <strong>The access token</strong>, where it ' +
    'carries a claim of that name — that is a statement this service already made about the ' +
    'person, from the sign-in or from the <a href="/admin/claims">custom claims</a> page, and a ' +
    'credential contradicting the token that authorised it would be indefensible. Then <strong>' +
    'the directory entry</strong>, which is where the generated values live once an entry ' +
    'exists and also where an <code>ldapmodify</code> lands: change <code>mail</code> on ' +
    '<code>uid=alice,ou=users</code> and the next credential says so. Then <strong>the ' +
    'generated persona</strong>, for a person with no entry, or an entry without that ' +
    'attribute, or a directory that is not running.</p>' +
    '<p class="note">Populating never overwrites. An attribute an entry already carries is left ' +
    'exactly as it is — which is why the three seeded people keep their names and only gain what ' +
    'they had nothing for, and why a sweep run twice does nothing the second time.</p>' +

    '<h2>What these claims do not do</h2>' +
    '<p class="note">Nothing reads them back. No access token, ID Token, SAML assertion or ' +
    'Kerberos PAC carries a claim from this page, and no endpoint makes a decision on one — it ' +
    'reaches a credential and stops there. The <a href="/admin/users">users</a> page shows the ' +
    'directory entry each of these values was written onto.</p>';

  respond(req, res, {
    selected: vcClaims.selectedNames(),
    defaults: vcClaims.DEFAULT_SELECTION,
    ldpOmitted: vcClaims.ldpOmitted(),
    attributes: vcClaims.VC_ATTRIBUTES.map(function (row) {
      return { ldap: row.ldap, claim: row.claim.join('.'), label: row.label,
               schema: row.schema, ldpTerm: row.ldpTerm || '',
               selected: vcClaims.isSelected(row.ldap) };
    }),
    preview: { user: previewUser, claims: vcClaims.subjectClaimsFor(previewUser, {}) }
  }, 'Credential claims', '/admin/vc', inner);
  log.debug("Leaving the admin credential-claims page.");
});


// ---------------------------------------------------------------------------
// GET /admin/vc-verifier-config, POST /admin/vc-verifier-config
//
// WHAT THE BAR DOOR ASKS FOR — the other end of the page above. /admin/vc decides
// what an issued credential CARRIES; this decides what the Verifier at
// /oid4vp/verifier ASKS FOR, and the two are deliberately separate settings
// because the interesting states are the ones where they disagree. A Verifier
// asking for a claim the issuer is not minting is the negative that exercises a
// wallet's "I cannot satisfy this request" path, and there is no way to reach it
// if one page sets both.
//
// The catalogue is vc_claims.js's, grouped into CLAIMS rather than listed as
// attribute types, and vc_verifier_config.js says at length why: a credential
// carries one Disclosure per top-level claim, so `address` is one unit of
// disclosure however many attribute types feed it. Offering six address
// checkboxes would offer a choice that does not exist on the wire.
//
// It is the third page here that changes what a protocol endpoint does, and the
// only one whose effect is visible in a document this service SENDS rather than
// in one it issues — the dcql_query in the next Authorization Request.
// ---------------------------------------------------------------------------
function vpConfigAction(body, names) {
  log.debug("Entering vpConfigAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');

  if (action === 'select' || action === 'replace') {
    // An empty list is a legitimate save and not an empty form: DCQL with no
    // `claims` member asks for the WHOLE credential, so unticking everything is
    // how somebody tests that. It is stated in the message rather than left to be
    // discovered from a presentation that disclosed everything.
    const result = vpConfig.setRequested(names);
    if (!result.ok) {
      log.debug("Leaving vpConfigAction(). The selection was refused.");
      return result;
    }
    log.debug("Leaving vpConfigAction(). " + result.requested.length + " claim(s) requested.");
    return { ok: true, requested: result.requested, added: result.added, removed: result.removed,
             message: result.requested.length
               ? 'The next Authorization Request asks for ' + result.requested.length +
                 ' claim(s): ' + result.requested.join(', ') + '. Added: ' +
                 (result.added.join(', ') || 'nothing') + '. Removed: ' +
                 (result.removed.join(', ') || 'nothing') + '.'
               : 'The next Authorization Request names no claims at all, which in DCQL asks for ' +
                 'the WHOLE credential — the query carries no claims member. Removed: ' +
                 (result.removed.join(', ') || 'nothing') + '.' };
  }

  if (action === 'add') {
    const name = String(body.claim || body.name || '').trim();
    const result = vpConfig.addRequested(name);
    if (!result.ok) {
      log.debug("Leaving vpConfigAction(). The claim was refused.");
      return result;
    }
    const known = vpConfig.rowFor(name);
    log.debug("Leaving vpConfigAction(). Added " + name + ".");
    return { ok: true, requested: result.requested,
             message: 'Now asking for ' + name + '.' + (known ? '' :
               ' It is not in the catalogue, so no credential this service issues carries it — ' +
               'which is what makes it a test of what your wallet does with a request it cannot ' +
               'satisfy. This Verifier will refuse the presentation on the "Requested claims" ' +
               'check and name it.') };
  }

  if (action === 'remove') {
    const name = String(body.claim || body.name || '').trim();
    const result = vpConfig.removeRequested(name);
    if (!result.ok) {
      log.debug("Leaving vpConfigAction(). Nothing named that.");
      return result;
    }
    log.debug("Leaving vpConfigAction(). Removed " + name + ".");
    return { ok: true, requested: result.requested,
             message: 'No longer asking for ' + name + '.' };
  }

  if (action === 'defaults') {
    const result = vpConfig.resetRequested();
    log.debug("Leaving vpConfigAction(). Restored the startup request.");
    return { ok: true, requested: result.requested,
             message: 'Back to what this process started with: ' +
                      (result.requested.join(', ') || '(no claims)') + '. That is OID4VP_CLAIMS ' +
                      'where it was set and given_name, family_name where it was not.' };
  }

  if (action === 'format') {
    const result = vpConfig.setDefaultFormat(String(body.format || ''));
    if (!result.ok) {
      log.debug("Leaving vpConfigAction(). No such format.");
      return result;
    }
    log.debug("Leaving vpConfigAction(). Default format is " + result.format + ".");
    return { ok: true, format: result.format,
             message: 'A request that does not name a format now asks for a ' + result.format +
                      ' credential. The three format links on the bar door name one explicitly ' +
                      'and are unaffected.' };
  }

  log.debug("Leaving vpConfigAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The five are: select, add, ' +
                               'remove, defaults, format.'] };
}

app.post('/admin/vc-verifier-config', function (req, res) {
  log.debug("Entering the admin verifier-request action endpoint.");
  const body = parseBody(req);
  // Two names for the list, for the reason /admin/vc has two: a checkbox is one
  // `claim` repeated, and a JSON body carries one `claims` array.
  const names = listField(req, body, 'claim').concat(listField(req, body, 'claims'));
  const result = vpConfigAction(body, names);
  respondToAction(req, res, '/admin/vc-verifier-config', result);
  log.debug("Leaving the admin verifier-request action endpoint.");
});

// Whether the ISSUER currently mints the claim this Verifier is asking for. The
// two pages are separate settings on purpose (see the header), so the disagreement
// is a state to report rather than one to prevent — and reporting it is what stops
// "the wallet disclosed nothing" being investigated as a wallet bug.
function vpIssuedCell(claimName) {
  const carried = vpConfig.carriedNow(claimName);
  if (!carried.known) {
    return '<td><span class="state-none">not a claim this service issues</span></td>';
  }
  if (!carried.carried.length) {
    return '<td><span class="state-expired">no — not selected on ' +
           '<a href="/admin/vc">/admin/vc</a></span></td>';
  }
  if (carried.missing.length) {
    return '<td><span class="state-expired">partly — ' + codeList(carried.missing) +
           ' not selected</span></td>';
  }
  return '<td><span class="state-valid">yes</span></td>';
}

// One catalogue row. The DCQL path column is shown for the format the next
// unqualified request will use, because a path is not a property of the claim: the
// same claim is ["given_name"], ["credentialSubject","given_name"] or
// ["credentialSubject","birthDate"] depending on what is being asked for, and a
// column that picked one silently would be wrong two-thirds of the time.
function vpClaimRow(row, format) {
  const on = vpConfig.isRequested(row.claim);
  const paths = vpConfig.dcqlPathsFor(format, row.claim);
  const attributes = row.members.map(function (member) {
    return '<code>' + esc(member.ldap) + '</code> <span class="state-none">(' +
           esc(member.schema) + ')</span>';
  }).join('<br>');
  return '<tr><td><input type="checkbox" name="claim" value="' + esc(row.claim) + '"' +
    (on ? ' checked' : '') + '></td>' +
    '<td><code>' + esc(row.claim) + '</code>' +
    (row.nested ? '<br><span class="state-none">one object, ' + row.members.length +
                  ' attributes</span>' : '') + '</td>' +
    '<td>' + esc(row.label) + '</td>' +
    '<td>' + attributes + '</td>' +
    '<td>' + (paths.length
      ? paths.map(function (path) { return '<code>' + esc(JSON.stringify(path)) + '</code>'; }).join('<br>')
      : '<span class="state-expired">cannot be asked for in this format</span>') + '</td>' +
    '<td>' + (row.ldpTerms.length ? codeList(row.ldpTerms)
                                  : '<span class="state-none">—</span>') + '</td>' +
    vpIssuedCell(row.claim) + '</tr>';
}

// The claims being asked for that are NOT in the catalogue. Rendered as ticked
// checkboxes in the same form rather than as a separate list with its own Save,
// because a form that dropped them the moment somebody saved the table above would
// silently undo a deliberate configuration.
function vpExtraRows(format) {
  const extras = vpConfig.requestedRows().filter(function (row) { return !row.inCatalogue; });
  if (!extras.length) {
    return '';
  }
  return '<h3>Asked for, and not in the catalogue</h3>' +
    '<p class="note">Nothing this service issues carries these, which is what makes them worth ' +
    'asking for: it is the only way to see what a wallet does with a request it cannot satisfy, ' +
    'and what this Verifier says when it checks. They are ticked below so that saving the table ' +
    'above keeps them — untick one to stop asking for it.</p>' +
    '<table><tr><th>In</th><th>Claim</th><th>DCQL path (' + esc(format) + ')</th></tr>' +
    extras.map(function (row) {
      const paths = vpConfig.dcqlPathsFor(format, row.claim);
      return '<tr><td><input type="checkbox" name="claim" value="' + esc(row.claim) + '" checked></td>' +
        '<td><code>' + esc(row.claim) + '</code></td>' +
        '<td>' + paths.map(function (path) {
          return '<code>' + esc(JSON.stringify(path)) + '</code>';
        }).join('<br>') + '</td></tr>';
    }).join('') + '</table>';
}

function vpClaimsSection(format) {
  log.debug("Entering vpClaimsSection(). format=" + format);
  const rows = vpConfig.REQUESTABLE.map(function (row) { return vpClaimRow(row, format); }).join('');
  const omitted = format === 'ldp_vc' ? vpConfig.ldpOmitted() : [];
  log.debug("Leaving vpClaimsSection(). " + vpConfig.REQUESTABLE.length + " row(s).");
  return '<form method="post" action="/admin/vc-verifier-config">' +
    '<input type="hidden" name="action" value="select">' +
    '<table><tr><th>Ask</th><th>Claim</th><th>Label</th><th>LDAP attribute (defined by)</th>' +
    '<th>DCQL path (' + esc(format) + ')</th><th>ldp_vc term</th>' +
    '<th>Issued now</th></tr>' + rows + '</table>' +
    vpExtraRows(format) +
    '<div class="formrow"><button>Save this request</button>' +
    '<span class="note">It applies to the next Authorization Request. One already in flight ' +
    'keeps the claims it was built with — a Verifier that judged a presentation against a list ' +
    'changed after it asked would refuse a wallet for answering the question it was really ' +
    'asked.</span></div></form>' +
    (omitted.length
      ? '<p class="note"><strong>' + codeList(omitted) + '</strong> ' +
        (omitted.length === 1 ? 'is asked for and is' : 'are asked for and are') +
        ' dropped from an <code>ldp_vc</code> query. That format is signed over canonicalized ' +
        'JSON-LD, so only terms the vendored context defines can be named at all, and asking ' +
        'under a name it does not define would fail canonicalization rather than return less. ' +
        'The two JOSE-secured formats ask for all of them.</p>'
      : '') +
    '<div class="formrow">' +
    '<form method="post" action="/admin/vc-verifier-config" class="inline">' +
    '<input type="hidden" name="action" value="add">' +
    '<label for="claim">Also ask for a claim that is not in the catalogue</label>' +
    '<input type="text" id="claim" name="claim" size="24" placeholder="drivers_licence_number">' +
    '<button class="secondary">Add</button></form> ' +
    '<form method="post" action="/admin/vc-verifier-config" class="inline">' +
    '<input type="hidden" name="action" value="defaults">' +
    '<button class="secondary">Back to what this process started with</button></form></div>';
}

// The credential types a wallet may submit, and which one an unqualified request
// asks for. One request is for ONE of them: a presentation cannot convert between
// formats, so a wallet holding a jwt_vc_json credential has nothing to answer a
// dc+sd-jwt query with — and the honest outcome is that it says so rather than
// that this page pretends the choice does not matter.
function vpFormatsSection(format) {
  log.debug("Entering vpFormatsSection(). format=" + format);
  const rows = vpConfig.FORMATS.map(function (item) {
    const configs = item.configs.map(function (id) {
      return '<code>' + esc(id) + '</code>';
    }).join('<br>');
    return '<tr><td><input type="radio" name="format" value="' + esc(item.id) + '"' +
      (item.id === format ? ' checked' : '') + '></td>' +
      '<td><code>' + esc(item.id) + '</code><br>' + esc(item.label) + '</td>' +
      '<td><code>' + esc(item.identifiedBy) + '</code><br><code>' +
      esc(item.identifierText) + '</code></td>' +
      '<td>' + esc(item.selectiveDisclosure) + '</td>' +
      '<td>' + esc(item.holderBinding) + '</td>' +
      '<td>' + configs + '</td>' +
      '<td><a href="' + esc('/oid4vp/verifier?format=' + encodeURIComponent(item.id)) +
      '">Present one</a></td></tr>';
  }).join('');
  log.debug("Leaving vpFormatsSection(). " + vpConfig.FORMATS.length + " row(s).");
  return '<form method="post" action="/admin/vc-verifier-config">' +
    '<input type="hidden" name="action" value="format">' +
    '<table><tr><th>Default</th><th>Format</th><th>Identified in DCQL by</th>' +
    '<th>Selective disclosure</th><th>Holder binding</th><th>Issued here as</th><th></th></tr>' +
    rows + '</table>' +
    '<div class="formrow"><button>Ask for this one by default</button>' +
    '<span class="note">The default is what <code>/oid4vp/start</code> asks for when the link ' +
    'that reached it names no format. The bar door\'s three format buttons name one explicitly, ' +
    'so they are unaffected — a button saying "present an SD-JWT VC" that asked for something ' +
    'else would be lying in the one place a reader is most likely to trust it.</span></div>' +
    '</form>' +
    '<p class="note">' + vpConfig.FORMATS.map(function (item) {
      return '<strong>' + esc(item.id) + '</strong> — ' + esc(item.what);
    }).join('<br><br>') + '</p>' +
    '<p class="note">The identifying values are not settable here. They are what this service\'s ' +
    'own issuer mints (<code>vc_configs.js</code>), and a Verifier asking for a <code>vct</code> ' +
    'nobody here issues would be a request no wallet in this stack could ever satisfy — a ' +
    'negative worth having, but one that belongs to the issuer\'s configuration rather than to a ' +
    'text box on this page.</p>';
}

app.get('/admin/vc-verifier-config', function (req, res) {
  log.debug("Entering the admin verifier-request page.");
  const format = vpConfig.defaultFormatId();
  const requested = vpConfig.requestedClaims();
  const query = vpConfig.dcqlQuery(format);

  const inner = messagesOf(req) +
    '<p class="note">What the mock Verifier at <a href="/oid4vp/verifier">/oid4vp/verifier</a> — ' +
    'the pages call it <em>The Bar Door</em> — asks a wallet for, and in which credential format. ' +
    'It reaches the wire as the <code>dcql_query</code> of the next OID4VP Authorization Request, ' +
    'and it is what the Verifier then checks the presentation against: a claim asked for and not ' +
    'presented fails the <em>Requested claims</em> check by name.</p>' +

    '<p class="note">The claims are the same catalogue <a href="/admin/vc">/admin/vc</a> fills a ' +
    'credential from, grouped into <strong>claims</strong> rather than listed as attribute types. ' +
    'A credential carries one Disclosure per top-level claim, so <code>address</code> is one unit ' +
    'of disclosure however many LDAP attributes feed it — asking for it gets the street, the ' +
    'locality, the region, the postal code and the country together, and a page offering six ' +
    'address checkboxes would be offering a choice that does not exist on the wire.</p>' +

    '<div class="warn"><strong>This asks; it does not admit anybody.</strong> A presentation that ' +
    'verifies here starts no session, issues no token and grants no access — the door says yes and ' +
    'that is the whole of it. Nothing else in this service reads what was presented. The two ' +
    'settings are also deliberately separate: this page decides what is ASKED FOR and ' +
    '<a href="/admin/vc">/admin/vc</a> decides what is ISSUED, so that asking for a claim the ' +
    'issuer does not mint stays reachable. That is the negative worth testing, and one page ' +
    'setting both would make it impossible to reach.</div>' +

    '<h2>The claims</h2>' +
    (requested.length
      ? '<p class="note">Asking for ' + requested.length + ': ' + codeList(requested) + '.</p>'
      : '<div class="warn"><strong>No claim is selected, and that is a real request rather than ' +
        'an empty form.</strong> DCQL reads an absent <code>claims</code> member as the WHOLE ' +
        'credential, so the query below carries none and the wallet is being asked for ' +
        'everything — the opposite of what selective disclosure is for, which is exactly why it ' +
        'is worth being able to ask for it.</div>') +
    vpClaimsSection(format) +

    '<h2>The credential types that can be submitted</h2>' +
    vpFormatsSection(format) +

    '<h2>The query this builds</h2>' +
    '<p class="note">Built by the function that builds the real one, not by a second walk of the ' +
    'table above — a preview that agreed with this page and disagreed with the request would be ' +
    'worse than no preview. It is the <code>dcql_query</code> parameter of the next ' +
    'Authorization Request, by value or inside the signed Request Object.</p>' +
    '<textarea readonly spellcheck="false">' + esc(JSON.stringify(query, null, 2)) + '</textarea>' +

    '<h2>What this page does not change</h2>' +
    '<p class="note">Not what the issuer mints — that is <a href="/admin/vc">/admin/vc</a>, and ' +
    'the <em>Issued now</em> column above is this page reporting on that one. Not a request ' +
    'already in flight, which keeps the claims it was built with. Not the <code>vct</code> or the ' +
    'type array a credential is identified by. And not what a verified presentation is worth: ' +
    'nothing here turns one into a credential of any kind.</p>';

  respond(req, res, {
    requested: requested,
    defaults: vpConfig.DEFAULT_REQUESTED,
    format: format,
    formats: vpConfig.FORMATS.map(function (item) {
      return { id: item.id, label: item.label, identifiedBy: item.identifiedBy,
               identifier: item.identifier, selectiveDisclosure: item.selectiveDisclosure,
               holderBinding: item.holderBinding, configurations: item.configs };
    }),
    ldpOmitted: vpConfig.ldpOmitted(),
    catalogue: vpConfig.REQUESTABLE.map(function (row) {
      return { claim: row.claim, label: row.label, nested: row.nested,
               attributes: row.members.map(function (member) {
                 return { ldap: member.ldap, schema: member.schema };
               }),
               ldpTerms: row.ldpTerms,
               paths: vpConfig.dcqlPathsFor(format, row.claim),
               requested: vpConfig.isRequested(row.claim),
               issued: vpConfig.carriedNow(row.claim) };
    }),
    dcqlQuery: query
  }, 'Verifier request', '/admin/vc-verifier-config', inner);
  log.debug("Leaving the admin verifier-request page.");
});

module.exports = {
  // Filled by ldap_server.js at its require time; see the note above it.
  setDirectoryReader: setDirectoryReader,
  setGroupReader: setGroupReader,
  jtiFrom: jtiFrom,
  tokenAction: tokenAction,
  claimsAction: claimsAction,
  vcAction: vcAction,
  vpConfigAction: vpConfigAction
};
