'use strict';
//
// File: admin.js
//
// ---------------------------------------------------------------------------
// The admin console: four pages over the state admin_stats.js holds.
//
//   GET  /admin           what the console is, and what it can do to this service
//   GET  /admin/metrics   every call, every artifact, and both kinds of session
//   GET  /admin/users     everyone this service has authenticated; with ?user= it is
//                         one of them, their sessions, and what was issued on each
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
  { path: '/admin/tokens', label: 'Tokens' },
  { path: '/admin/claims', label: 'Custom claims' },
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
    '<li><a href="/admin/tokens">Tokens</a> — everything issued, in one table: every JWT, every ' +
    'SAML assertion (WS-Trust\'s and WS-Federation\'s alike) and every Kerberos ticket, newest ' +
    'first. And the buttons that invalidate the ones that can be — one access token, one ID Token, ' +
    'one refresh token, everything for one subject, or everything of one kind. Revocation here is ' +
    'the SAME revocation RFC 7009\'s <code>/oauth2/revoke</code> performs, so introspection, ' +
    'UserInfo and the refresh grant all honour it.</li>' +
    '<li><a href="/admin/claims">Custom claims</a> — what to add to every OAuth 2.0 access token, ' +
    'every OIDC ID Token, and every SAML 2.0 and SAML 1.1 assertion this service issues from now ' +
    'on. Additive only: a custom claim is never allowed to displace one the protocol defines.</li>' +
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
      artifacts: detail.artifacts
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

module.exports = {
  jtiFrom: jtiFrom,
  tokenAction: tokenAction,
  claimsAction: claimsAction
};
