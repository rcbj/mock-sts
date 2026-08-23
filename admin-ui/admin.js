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
//   GET  /admin/audit     what happened here, in order — every authentication,
//                         session, directory operation, console interaction,
//                         management API call and protocol endpoint call, as
//                         rows rather than as counters, filtered and paged
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

const app = require('../common/app');
const { log, xmlEscape, baseUrlOf, parseBody, b64uDecode } = require('../common/helpers');
const config = require('../common/config');
const stats = require('../common/admin_stats');
// The browser sign-on sessions, from the authentication service that creates
// them — shared between the OAuth 2.0 / OIDC flow and WS-Federation. Read-only
// here: the console reports them and never ends one, because /oauth2/logout and
// wsignout1.0 already do that and doing it from a third place would mean three
// ways of getting the cleanup wrong.
const { sessions } = require('../authn/authn');
// The credential claim set: which LDAP attributes an issued Verifiable Credential
// carries, and the invented values behind them. A library like admin_stats.js —
// it registers no route — so requiring it here neither adds to the express router
// nor makes a cycle, and /admin/vc below is the page that sets it. The DIRECTORY
// half of it (populating entries, reading values back) is ldap_server.js's, wired
// into that module through a slot for the route-order reason rule 6 gives.
const vcClaims = require('../oid4vc/vc_claims');
// The other end of that: which of those claims the mock OID4VP Verifier — the
// "bar door" at /oid4vp/verifier — ASKS a wallet for, and in which credential
// format. A library like vc_claims.js and admin_stats.js, registering no route,
// so requiring it here neither moves a route nor makes a cycle; vc_verifier.js
// reads the same module from the other side of the require order.
const vpConfig = require('../oid4vc/vc_verifier_config');
// The THIRD reader of that same catalogue: which LDAP attributes a token or an
// assertion carries, per claim set. A library like the two above, registering no
// route, so requiring it here neither moves a route nor makes a cycle — it
// requires admin_stats.js and vc_claims.js, and neither requires it back. It is
// what turns /admin/claims from a page of typed constants into one that can put
// what the directory says into an access token. See its header for why the
// selection is per-set and why nothing is selected on a fresh start.
const claimAttributes = require('../common/claim_attributes');
// The FOURTH library over that catalogue's territory: which LDAP attribute each
// SCIM member is, in both directions. Read here for the mapping tables on
// /admin/scim, and by scim.js for the conversions themselves. It registers no
// route and requires only helpers.js and vc_claims.js, so requiring it here
// neither moves a route nor makes a cycle — which is exactly why the conversions
// live in a library rather than in scim.js, where a require from this file would
// have dragged every /scim and /ldap route ahead of the console's own.
const scimMap = require('../scim/scim_map');
// The groups claim: which directory groups reach a token, whether it is on, and
// what it would say about one person. A LIBRARY like the line above — it
// registers no route, so requiring it here cannot reorder the router
// /sts-metadata is built by walking, and it requires helpers.js, config.js and
// admin_stats.js, none of which requires this file. It is required for the same
// reason claim_attributes.js is: the page and the management API both report
// this feature, and neither should be reading its four settings itself.
const groupClaims = require('../common/group_claims');
// The audit log: what happened here, in order, as rows rather than as counters.
// A library like the three above — it registers no route — so requiring it here
// neither moves a route nor makes a cycle. It holds the events and this file
// renders them at /admin/audit, which is the same split admin_stats.js has and
// for the same reason: a test can walk the log over JSON without going near an
// HTML page.
const auditLog = require('../common/audit');
// The application registry, whose store is the ou=applications container in the
// embedded directory. A library that registers no route, so requiring it from
// the console cannot move anything in the route order — unlike ldap_server.js,
// which is why the user and group readers below are hooks rather than requires.
// Nothing is cached on either side: every read here is a directory read, which
// is what lets this page show an ldapmodify that happened a second ago.
const applications = require('../common/applications');
// The authorization server profiles — what each discovery document publishes.
// A library that registers no route, so requiring it here moves nothing.
const authorizationServers = require('../oauth-oidc/authorization_servers');
// The two SPIFFE LIBRARIES, and only those two. `spiffe_ca.js` holds the trust
// domain's authorities and `spiffe_registry.js` the registration entries and
// agents; both register nothing, so requiring them here moves no route and
// cannot close a cycle. `spiffe_id.js` comes with them for the server ID.
//
// **`spiffe_server.js` is deliberately NOT required here.** That module
// registers the bundle endpoint and /spiffe, and server.js requires this file
// FIRST — so a require from here would pull those routes into the express
// router ahead of the console's own, and GET /sts-metadata is built by walking
// that router. What this page needs from it is two facts about sockets, and
// they arrive through a reader slot instead: the same inversion
// setDirectoryReader(), setGroupReader() and setScimReader() already use, and
// justified by rule 3e's test in exactly the same way.
const spiffeCa = require('../spiffe/spiffe_ca');
const spiffeRegistry = require('../spiffe/spiffe_registry');
// WHO MAY CALL THE SPIRE SERVER API. A library like the two above it — it
// registers nothing and starts nothing — so neither thing that forces a slot
// applies, and it is required directly rather than read through
// `setSpiffeReader()`. What DOES need the slot is which of the four sockets
// bound, which is a fact about a socket and only `spiffe_server.js` knows it.
const spiffeAuth = require('../spiffe/spiffe_auth');
const spiffeIdLib = require('../spiffe/spiffe_id');
// For the DRIFT report: the document this service would publish, to compare a
// profile's overrides against. oauth2.js is required before admin.js in
// server.js (rule 5), so this is a plain require in the ordinary direction.
const oauth2 = require('../oauth-oidc/oauth2');

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

// Rows per page for a list whose ROW IS A TABLE. There is one of those — the session
// blocks on the users drill-down, where each row of the list is a session heading, a
// facts table and a token table under it — and giving it DEFAULT_PER_PAGE would put
// fifty tables on one page, each of which is itself paged at fifty rows. The list
// pages get away with one number because a row there is a row.
//
// `?per=` still overrides it, for the same reason it overrides everything else: a
// number somebody typed is a number they meant.
const DEFAULT_BLOCKS_PER_PAGE = 5;

// How many subjects the metrics page names in one "Who" cell before it says how
// many more there are. A separate cap from MAX_ROWS because it bounds a cell rather
// than a list: the ceiling that matters here is the width of one row, and the full
// list is on /admin/users and in `?format=json` either way.
const MAX_WHO = 12;

// ---------------------------------------------------------------------------
// The page shell.
//
// One for all five pages, with the nav in it, so a page cannot be added without a
// way back — which held for the SECTIONS and did not hold for the pages under them
// until `up` existed, because the nav's answer on a drill-down was the section's
// own tab, drawn as text. See navBar(). The CSS is inline because app.js sets `default-src 'none'` with
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
  { path: '/admin/scim', label: 'SCIM' },
  { path: '/admin/applications', label: 'Applications' },
  { path: '/admin/authorization-servers', label: 'Authorization servers' },
  { path: '/admin/spiffe', label: 'SPIFFE' },
  { path: '/admin/spiffe/entries', label: 'Registration entries' },
  { path: '/admin/spiffe/agents', label: 'Agents' },
  { path: '/admin/tokens', label: 'Tokens' },
  { path: '/admin/audit', label: 'Audit log' },
  { path: '/admin/claims', label: 'Custom claims' },
  { path: '/admin/vc', label: 'Credential claims' },
  { path: '/admin/vc-verifier-config', label: 'Verifier request' },
  { path: '/admin/config', label: 'Configuration' },
  { path: '/sts-metadata', label: 'Service metadata' }
];

function esc(v) { return xmlEscape(v == null ? '' : String(v)); }

// A list of names, each in its own <code>. Written as a function because the
// obvious one-liner — join with the markup and escape the result — escapes the
// markup too, and the page then shows the tags it was supposed to render. It did.
function codeList(names) {
  return names.map(function (name) { return '<code>' + esc(name) + '</code>'; }).join(', ');
}

// WHICH QUERY PARAMETERS BELONG TO A SECTION'S LIST rather than to the page under
// it — the filter the reader typed and the page they had reached.
//
// It is a WHITELIST per section rather than "everything that is not ours", for the
// same reason the tokens page rebuilds its `back` field from a list of names
// instead of echoing it: what comes out of here is put into a URL this service
// hands to a browser, so the set of names has to be one this file wrote. It is
// also why a section that cannot be drilled into has no row — carrying a filter
// through a page nothing hangs under would be state nobody can get back to.
const LIST_PARAMS = {
  '/admin/users': ['q', 'protocol', 'per', 'page'],
  '/admin/groups': ['q', 'per', 'page'],
  '/admin/applications': ['q', 'kind', 'per', 'page'],
  '/admin/authorization-servers': ['per', 'page'],
  '/admin/spiffe/entries': ['q', 'origin', 'per', 'page'],
  '/admin/spiffe/agents': ['q', 'per', 'page']
};

// The list AS THE READER LEFT IT, picked out of a query by that table.
//
// This is what makes the trail a way back to where somebody was rather than to the
// top of an unfiltered list. A drill-down link carries it, every control on the
// drill-down carries it onward (pageParamsOf() takes the whole query through), and
// the trail's section crumb spends it. Nothing on the drill-down reads these keys
// for anything else: their names belong to the list's filter form, and a page
// showing one application has no `q`.
function listViewOf(section, query) {
  log.debug("Entering listViewOf(). section=" + section);
  const out = {};
  (LIST_PARAMS[section] || []).forEach(function (key) {
    const raw = (query || {})[key];
    // Express hands back an array when a parameter is repeated, and String() on one
    // is "a,b" — a filter nothing matches, reached by a link somebody clicked twice.
    // The same first-wins rule pageParamsOf() uses.
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (value !== undefined && value !== null && String(value) !== '') {
      out[key] = String(value);
    }
  });
  log.debug("Leaving listViewOf(). " + Object.keys(out).length + " parameter(s) carried.");
  return out;
}

// The same thing out of a form's `back` field, which is a query string a browser
// sent us rather than one we are looking at.
//
// It is REBUILT and never echoed: the names come from LIST_PARAMS, the values are
// re-encoded by queryWith(), and anything else in the field is dropped. That is
// the guarantee backTo() gives the tokens page and it is needed here for the same
// reason — a redirect target taken out of a request body is an open redirect, and
// one carrying a newline is a header injection. The worst a hand-written `back`
// can now reach is another page of the same list.
function listViewFromBack(section, raw) {
  log.debug("Entering listViewFromBack(). section=" + section);
  let params = null;
  try {
    params = new URLSearchParams(String(raw || '').replace(/^\?/, ''));
  } catch (e) {
    // Unparseable; the bare list is the right answer and is what a form carrying no
    // `back` at all gets anyway.
    log.debug("Leaving listViewFromBack(). Unparseable: " + e.message);
    return {};
  }
  const query = {};
  params.forEach(function (value, key) {
    // First wins, for the reason listViewOf() takes the first of a repeated
    // parameter: a field sent twice is one value, not "a,b".
    if (!Object.prototype.hasOwnProperty.call(query, key)) {
      query[key] = value;
    }
  });
  log.debug("Leaving listViewFromBack().");
  return listViewOf(section, query);
}

// The section a DRILL-DOWN hangs under: where "back" goes, what that section is
// called, and what the reader has drilled INTO.
//
// The label comes out of NAV rather than the call site, so a renamed tab cannot
// leave a way back that names the old one. A path with no NAV row falls back to
// the path itself, which is visible rather than silent — a drill-down under a
// section that is not in the nav is worth noticing.
//
// `listView` is listViewOf()'s answer, and it is what the href carries: the reader
// goes back to page 3 of the filter they were looking at rather than to the top of
// everything. `leaf` is the thing drilled into, for the last crumb.
function upTo(path, leaf, listView) {
  log.debug("Entering upTo(). path=" + path);
  const item = NAV.filter(function (row) { return row.path === path; })[0];
  const view = listView || {};
  log.debug("Leaving upTo(). " + (item ? "labelled " + item.label : "no nav row") +
            ", " + Object.keys(view).length + " list parameter(s).");
  return { href: path + queryWith(view, {}), label: item ? item.label : path,
           leaf: leaf, filtered: Object.keys(view).length > 0 };
}

// `up` is set on a drill-down — a page reached from a link on one of the sections
// below rather than one of the sections itself — and what it changes is the ACTIVE
// TAB.
//
// That tab was drawn as plain text on every page whose `active` matched, and
// `active` is the section's path on the list page and on every page underneath it
// alike. So on a drill-down the one control that pointed at the list was the one
// control this shell had turned off, and the only way back from
// /admin/applications?application=x was the browser's own Back button or a link at
// the foot of a long page. On a drill-down the tab is a LINK: still bold, because
// the reader is inside that section, and underlined so that "the section you are
// in" cannot be read as "not clickable".
function navBar(active, up) {
  return '<nav>' + NAV.map(function (item) {
    if (item.path === active) {
      if (up) {
        return '<a class="here" href="' + esc(up.href) + '" title="Back to ' +
               esc(up.label) + '">' + esc(item.label) + '</a>';
      }
      return '<span class="here">' + esc(item.label) + '</span>';
    }
    return '<a href="' + esc(item.path) + '">' + esc(item.label) + '</a>';
  }).join('') + '</nav>';
}

// How long a leaf crumb may be before it is cut. A group's leaf is a DN and a
// user's can be a did:jwk — a few hundred characters of base64url with nowhere a
// browser will break a line — and a trail that wraps to four lines is not a trail.
// The full name is in the <h1> immediately below it and in the `title` here, so
// nothing is lost by cutting: what the crumb is for is the LINKS to its left.
const MAX_CRUMB = 44;

function shortCrumb(text) {
  const value = String(text == null ? '' : text);
  return value.length > MAX_CRUMB ? value.slice(0, MAX_CRUMB - 1) + '…' : value;
}

// THE BREADCRUMB TRAIL, AND IT IS ON EVERY PAGE RATHER THAN ONLY ON A DRILL-DOWN.
//
// One line under the nav saying where the reader is and offering every level above
// them: `Admin console › Applications › rfc9700-debugger`. The nav answers "what
// else is there"; the trail answers "where am I and how do I get back", which are
// different questions — the tab for the section you are standing in is exactly the
// tab that tells you nothing about the page you are standing on.
//
// Three things about it are deliberate.
//
// The section crumb on a drill-down is `up.href`, which carries THE FILTER AND THE
// PAGE the reader clicked in from (see listViewOf()), so the trail goes back to
// where they were rather than to the top of an unfiltered list. That is the whole
// difference between a breadcrumb and a link to the section.
//
// The last crumb is NOT a link. It is the page being drawn, and a crumb that
// reloads the page you are on is a control that does nothing — which teaches a
// reader not to trust the ones beside it.
//
// The root crumb is `Admin console` on every page including `/admin` itself, where
// it is the only crumb and is not a link. A trail that appeared on some pages and
// not others would be a trail nobody looks for.
function trailBar(active, up, title) {
  log.debug("Entering trailBar(). active=" + active);
  const crumbs = [{ label: 'Admin console', href: active === '/admin' ? null : '/admin' }];
  if (active !== '/admin') {
    const item = NAV.filter(function (row) { return row.path === active; })[0];
    const label = item ? item.label : active;
    if (up) {
      crumbs.push({ label: label, href: up.href,
                    // Said in the tooltip rather than in the crumb, because "as you
                    // left it" is reassurance for somebody who wonders and noise for
                    // everybody else — and a crumb whose text changes with the
                    // filter is a crumb that moves under the pointer.
                    title: up.filtered
                      ? 'Back to ' + label + ' — the filter and page you came from'
                      : 'Back to ' + label });
      crumbs.push({ label: shortCrumb(up.leaf || title), title: String(up.leaf || title) });
    } else {
      crumbs.push({ label: label });
    }
  }
  const html = '<p class="crumb">' + crumbs.map(function (crumb, index) {
    const sep = index ? '<span class="sep">&rsaquo;</span>' : '';
    if (!crumb.href) {
      return sep + '<span class="leaf"' +
        (crumb.title ? ' title="' + esc(crumb.title) + '"' : '') + '>' +
        esc(crumb.label) + '</span>';
    }
    return sep + '<a href="' + esc(crumb.href) + '"' +
      (crumb.title ? ' title="' + esc(crumb.title) + '"' : '') + '>' +
      esc(crumb.label) + '</a>';
  }).join('') + '</p>';
  log.debug("Leaving trailBar(). " + crumbs.length + " crumb(s).");
  return html;
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

function page(title, active, inner, up) {
  log.debug("Entering page(). title=" + title + ", up=" + (up ? up.href : "none"));
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
    // The active tab on a DRILL-DOWN. It keeps the weight `.here` gives it, because
    // the reader is still inside that section, and takes back the link colour and an
    // underline, because it is a link again and a bold black tab reads as text
    // nobody can click — which is exactly what it was.
    'nav a.here{color:#12107c;text-decoration:underline}' +
    '.crumb{font-size:.82em;margin:0 0 14px;color:#666}' +
    '.crumb a{text-decoration:none;font-weight:600}' +
    '.crumb a:hover{text-decoration:underline}' +
    '.crumb .sep{margin:0 .45em;color:#aaa}' +
    // The last crumb is the page being drawn. It is not a link and must not look
    // like one, or the one crumb that does nothing is the one a reader clicks.
    '.crumb .leaf{color:#222;font-weight:600}' +
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
    '<p class="sub">Mock STS admin console — issuer <code>' +
      esc(config.value('wstrust.issuer')) + '</code></p>' +
    navBar(active, up) + trailBar(active, up, title) + OPEN_BANNER + inner +
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
// `up`, when given, is what upTo() returned for the section this page hangs
// under. Only a drill-down passes it; a section's own list page does not, and the
// JSON answer ignores it either way — a way back up is a property of a page a
// person is reading, and a caller of ?format=json has the URL it asked for.
function respond(req, res, json, title, active, html, up) {
  log.debug("Entering respond(). title=" + title);
  res.set('Cache-Control', 'no-store');
  if (String(req.query.format || '') === 'json') {
    res.status(200).type('application/json').send(JSON.stringify(json, null, 2));
    log.debug("Leaving respond(). Answered JSON.");
    return;
  }
  res.status(200).type('text/html').send(page(title, active, html, up));
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
//
// ONE PAGE CAN HOLD SEVERAL LISTS, and that is what `options.name` is for. The three
// list views have one list each and read the bare `page`, which is what they have
// always done and what every bookmark and every caller of the management API already
// says. The two DRILL-DOWNS have five and two: a users page holds its sessions, the
// tokens under each of them, the tokens on ended sessions, the tokens on no session
// and the artifacts, and a group page holds its members and the entries claiming it.
// A single `page` cannot serve those — clicking "next" under the artifacts would
// silently advance the sessions above it — so each list gets a page parameter named
// after itself and `per` stays shared, because "rows per table" is one choice a
// reader makes for the whole page rather than seven.
//
// `per` is shared for a second reason worth stating: it is the parameter with the
// cap on it, and one capped parameter is one place the cap can be got right.
// ---------------------------------------------------------------------------
function pagingOf(query, total, options) {
  const opts = options || {};
  const param = opts.name ? opts.name + 'Page' : 'page';
  log.debug("Entering pagingOf(). total=" + total + ", param=" + param);
  const askedPer = parseInt(String(query.per || ''), 10);
  const perPage = (isFinite(askedPer) && askedPer > 0)
    ? Math.min(askedPer, MAX_ROWS)
    : (opts.defaultPer || DEFAULT_PER_PAGE);
  // At least one page even when nothing matched, so "page 1 of 1" is what an empty
  // list says rather than "page 1 of 0".
  const pages = Math.max(1, Math.ceil(total / perPage));
  const askedPage = parseInt(String(query[param] || ''), 10);
  const page = Math.min(Math.max(isFinite(askedPage) ? askedPage : 1, 1), pages);
  const offset = (page - 1) * perPage;
  log.debug("Leaving pagingOf(). page=" + page + " of " + pages + ", perPage=" + perPage + ".");
  return {
    page: page, perPage: perPage, pages: pages, offset: offset, total: total,
    // 1-based and inclusive, for the "rows 51–100 of 312" line. Zero and zero when
    // nothing matched, which is what the line then has to say.
    firstRow: total ? offset + 1 : 0,
    lastRow: Math.min(offset + perPage, total),
    // Which query parameter this list moves on, carried on the result rather than
    // passed to pageNav() a second time: the one place that decides the name is the
    // one place that builds the links, so a control cannot come to page a list other
    // than the one it is drawn under.
    param: param,
    // What a row of this list IS, for the summary line. Seven controls on one page
    // all saying "rows" would leave the reader counting tables to work out which
    // number belongs to which.
    noun: opts.noun || 'rows'
  };
}

// The paging members of a reply, for a page that carries more than one list and
// therefore cannot put them at the top level the way the three list views do.
// Same names one level down, deliberately: a caller that has learned to walk
// `page`/`pages` on /admin-api/tokens reads `sessionsPaging.page` without being
// told anything new. `total` is here and not up there because up there it is
// `matched`, which is the count AFTER a filter — there is no filter on a
// drill-down's lists, so the honest name for the number is the plain one.
function pagingJson(pg) {
  return {
    page: pg.page, pages: pg.pages, perPage: pg.perPage,
    firstRow: pg.firstRow, lastRow: pg.lastRow, total: pg.total
  };
}

// The slice, with the paging that produced it. Written once because seven lists
// across the two drill-downs do exactly this and a hand-written eighth would be the
// one that forgets to slice.
function pagedRows(query, rows, options) {
  const pg = pagingOf(query, rows.length, options);
  return { paging: pg, shown: rows.slice(pg.offset, pg.offset + pg.perPage) };
}

// The parameters every control on a drill-down has to carry.
//
// The list views name theirs one by one, and they can: their parameter set is the
// filter form beside them and it is written down two lines above the call. A
// drill-down's is not written down anywhere — one of its lists has a page parameter
// PER SESSION BLOCK, so the set depends on what the reader has been clicking — and
// listing the ones that exist today is how paging the artifacts comes to reset the
// members six months from now. So the current query is carried through whole and
// each control overrides its own key.
//
// Three things are dropped and each for its own reason. `format`, for the reason the
// tokens page gives about its own links: JSON has no page to click, so a nav link
// carrying it would answer a click with a download. And `notice` and `error`, which
// are the message a revoke's redirect brought back — they belong to the act that has
// just happened and not to the view, so carrying them would leave "Revoked …" at the
// top of every page the reader clicked to afterwards, and would put a stale one in
// the `back` field of the next revoke, which answers with two.
const NOT_A_VIEW = ['format', 'notice', 'error'];

function pageParamsOf(query) {
  log.debug("Entering pageParamsOf().");
  const out = {};
  Object.keys(query || {}).forEach(function (key) {
    if (NOT_A_VIEW.indexOf(key) >= 0) {
      return;
    }
    // Express hands back an array when a parameter is repeated. The first is taken
    // rather than String()'d, because String(['2','5']) is "2,5" — a page number
    // nothing can parse, silently reached by a link somebody clicked twice.
    const value = Array.isArray(query[key]) ? query[key][0] : query[key];
    out[key] = value == null ? '' : String(value);
  });
  log.debug("Leaving pageParamsOf(). " + Object.keys(out).length + " parameter(s).");
  return out;
}

// The per-page select, written once because five surfaces offer it and a sixth
// written by hand is the one that forgets to add a hand-typed size to the list.
//
// MAX_ROWS is offered as the largest choice so the old behaviour — everything on one
// page, up to the cap — is still one click away for anyone who wants to search the
// table with the browser's own find.
//
// A hand-typed `?per=7` is ADDED to the list rather than ignored, or the select would
// show a size that is not the one being used and would silently change it on the next
// Filter — which is a control that lies about the page it is on.
function perPageOptions(perPage) {
  const choices = [25, DEFAULT_PER_PAGE, 100, MAX_ROWS];
  if (choices.indexOf(perPage) < 0) {
    choices.push(perPage);
    choices.sort(function (a, b) { return a - b; });
  }
  return choices.map(function (n) {
    return '<option value="' + n + '"' + (n === perPage ? ' selected' : '') + '>' +
           n + ' rows</option>';
  }).join('');
}

// The same control as a form of its own, for the two DRILL-DOWNS — which have no
// filter form to hang it on, and which need it more than the lists do because they
// carry several tables at once.
//
// Submitting it drops every page parameter, which is deliberate rather than an
// oversight of the hidden inputs: a GET form posts its own fields and nothing else,
// and page 4 of fifty-row pages is not page 4 of anything after the size changes.
// Going back to the top of each list is the only answer that is true of all of them.
//
// `carry` is the list's FILTER, and it has to be spelt out as hidden inputs for the
// reason above: a GET form posts its own fields and nothing else, so without them
// this control quietly empties the breadcrumb's way back to the list the reader
// came from. Its PAGE is deliberately not carried — `per` is the thing this form
// changes, and page 4 of fifty-row pages is not page 4 of anything afterwards,
// which is the same sentence as the paragraph above about the tables below.
function perPageForm(path, key, value, perPage, extraNote, carry) {
  log.debug("Entering perPageForm(). path=" + path);
  const carried = Object.keys(carry || {}).map(function (name) {
    return '<input type="hidden" name="' + esc(name) + '" value="' + esc(carry[name]) + '">';
  }).join('');
  const html = '<form method="get" action="' + esc(path) + '"><div class="formrow">' +
    '<input type="hidden" name="' + esc(key) + '" value="' + esc(value) + '">' + carried +
    '<label for="per">Rows per table</label>' +
    '<select id="per" name="per">' + perPageOptions(perPage) + '</select>' +
    '<button class="secondary">Apply</button>' +
    '<span class="note">Every table below is paged separately and they share this ' +
    'size. Changing it starts each of them at its first page.' +
    (extraNote ? ' ' + extraNote : '') + '</span>' +
    '</div></form>';
  log.debug("Leaving perPageForm().");
  return html;
}

// The FILTER half of a carried list view — everything except the two parameters
// that describe how the list was being paged. Written once because both of the
// controls that need it need the same half: a form that changes the page size, and
// anything else that lands the reader at the top of a list rather than where they
// were in it.
function filterOnly(view) {
  const out = {};
  Object.keys(view || {}).forEach(function (key) {
    if (key !== 'page' && key !== 'per') {
      out[key] = view[key];
    }
  });
  return out;
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
  log.debug("Entering pageNav(). pages=" + pg.pages + ", param=" + pg.param);
  if (pg.pages <= 1) {
    log.debug("Leaving pageNav(). One page; no control drawn.");
    return '';
  }
  function link(page, label, title) {
    const move = {};
    // The list's OWN parameter, off pg, so that a drill-down's five controls move
    // five different lists. Everything else in `params` rides along untouched,
    // which is what keeps the other four where the reader left them.
    move[pg.param] = page;
    return '<a href="' + esc(path + queryWith(params, move)) + '"' +
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
  out.push('<span class="where">page ' + pg.page + ' of ' + pg.pages + ' — ' + pg.noun + ' ' +
           pg.firstRow + '&ndash;' + pg.lastRow + ' of ' + pg.total + '</span>');
  log.debug("Leaving pageNav(). Drew " + out.length + " element(s).");
  return '<div class="pagenav">' + out.join('') + '</div>';
}

// ---------------------------------------------------------------------------
// GET /admin — the index.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE JSON VIEWS, AND WHY EVERY ONE OF THEM IS NOW A FUNCTION.
//
// Each page here answers `?format=json`, and until admin_api.js existed each of
// those objects was built inline in the route handler that also built the
// markup. That was fine while there was one caller. There are two now — this
// console and the management API at /admin-api — and two hand-built copies of
// the same object is precisely the drift the console's own text keeps warning
// about elsewhere: two views that each look correct alone and never see each
// other.
//
// So the JSON is a function per page, and where the markup needs the same
// intermediate work (the filtered, paged token list; a user drill-down that is
// one of three answers) the WHOLE VIEW is the function and the route is what
// chooses between HTML and JSON. admin_api.js calls these and nothing else — it
// holds no second opinion about what a metrics reply contains.
//
// One cost is worth stating rather than discovering: usersView() and
// groupsView() build the HTML as well, and the API throws it away. That is what
// `/admin/users?format=json` has always done, it is a string concatenation on a
// mock, and the alternative — a second set of builders for the same data — is
// the thing this whole arrangement exists to prevent.
// ---------------------------------------------------------------------------
function consoleJson() {
  log.debug("Entering consoleJson().");
  const snap = stats.snapshot();
  const json = {
    issuer: config.value('wstrust.issuer'),
    startedAt: new Date(snap.startedAt).toISOString(),
    uptimeMs: snap.uptimeMs,
    calls: snap.calls.total, tokensHeld: snap.tokens.held,
    tokensRevoked: snap.tokens.revoked,
    artifactsHeld: snap.artifacts.held, signOnSessions: sessions.size,
    usersKnown: snap.users.known,
    usersAuthenticatedHere: snap.users.authenticatedHere,
    pages: NAV.map(function (n) { return n.path; })
  };
  log.debug("Leaving consoleJson().");
  return json;
}

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
    'endpoint reads one and nothing decides anything on one. A token can CARRY one &mdash; see ' +
    '<code>groups.claim</code> &mdash; which is a different sentence.' +
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
  respond(req, res, consoleJson(), 'Admin console', '/admin', inner);
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

// The metrics reply: the whole snapshot, with the sign-on sessions beside it.
// The snapshot's own keys are at the TOP LEVEL of it rather than under a
// `snapshot` member, which is what /admin/metrics?format=json has always
// answered and what the parent project's tests read — so the route below uses
// this object for the markup too rather than taking a second snapshot a few
// microseconds later.
function metricsJson() {
  log.debug("Entering metricsJson().");
  const snap = stats.snapshot();
  const signOn = signOnSessionRows();
  const live = signOn.filter(function (s) { return !s.expired; });
  const json = Object.assign({}, snap, {
    startedAtIso: new Date(snap.startedAt).toISOString(),
    signOnSessions: { held: signOn.length, active: live.length, rows: signOn }
  });
  log.debug("Leaving metricsJson(). " + signOn.length + " sign-on session(s).");
  return json;
}

app.get('/admin/metrics', function (req, res) {
  log.debug("Entering the admin metrics page.");
  const json = metricsJson();
  // The snapshot's keys are the top level of that object; see the note on it.
  const snap = json;
  const signOn = json.signOnSessions.rows;
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

  respond(req, res, json, 'Metrics', '/admin/metrics', inner);
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
// The drill-down's page parameters, out of a `back` field, for the redirect that
// follows a revoke.
//
// The named parameters above are a WHITELIST, which is the right shape for a
// redirect target built out of a form field somebody posted — but a whitelist cannot
// cover this set, because one of the users page's lists has a page parameter per
// session block and the names therefore depend on which sessions exist. So the rule
// is a shape rather than a list: a key ending in `Page`, made of the characters a
// name and a base64url session id are made of, whose value is a positive integer.
// The value is REBUILT from parseInt rather than passed through, so what lands in
// the URL is a number this function produced.
//
// What it buys is the thing a reader notices immediately: revoking a token from page
// three of a session's table used to answer with page one of everything, so the row
// you had just acted on was no longer on screen and neither was its neighbour.
function drillDownPages(params) {
  log.debug("Entering drillDownPages().");
  const out = {};
  params.forEach(function (value, key) {
    if (!/^[A-Za-z0-9_-]+Page$/.test(key)) {
      return;
    }
    const n = parseInt(String(value), 10);
    if (isFinite(n) && n > 0) {
      out[key] = String(n);
    }
  });
  log.debug("Leaving drillDownPages(). " + Object.keys(out).length + " page parameter(s).");
  return out;
}

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
    const usersTarget = '/admin/users' + queryWith(Object.assign({
      user: params.get('user') || '',
      q: params.get('q') || '',
      protocol: params.get('protocol') || '',
      per: params.get('per') || '',
      page: params.get('page') || ''
    }, drillDownPages(params)), {});
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

// The filtered, paged token list and the reply built from it. The WHOLE view
// rather than only its JSON, because the markup below needs every intermediate
// step of it — and a second walk of the same list a few lines later is how a
// table and the JSON beside it come to disagree about a revocation that
// happened in between.
function tokensView(query) {
  log.debug("Entering tokensView().");
  const wantedFamily = String(query.family || '');
  const wantedKind = String(query.kind || '');
  const wantedState = String(query.state || '');
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
  const paging = pagingOf(query, filtered.length);
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  // How much of each family is held, for the line under the table. Counted from this
  // list rather than taken from the snapshot, because the snapshot's artifact count
  // includes the OID4VCI credentials this page does not list — two totals on one
  // page differing by a number of credentials is a page nobody can check.
  const heldByFamily = {};
  all.forEach(function (record) {
    heldByFamily[record.family] = (heldByFamily[record.family] || 0) + 1;
  });
  log.debug("Leaving tokensView(). " + shown.length + " row(s) of " +
            filtered.length + ".");
  return {
    wantedFamily: wantedFamily, wantedKind: wantedKind,
    wantedState: wantedState,
    all: all, filtered: filtered, paging: paging, shown: shown,
    heldByFamily: heldByFamily,
    json: {
      held: all.length, matched: filtered.length, shown: shown.length,
      heldByFamily: stats.ISSUED_FAMILIES.reduce(function (out, entry) {
        out[entry.family] = heldByFamily[entry.family] || 0;
        return out;
      }, {}),
      filter: { family: wantedFamily || null, kind: wantedKind || null,
                state: wantedState || null },
      // The clamped values, not what was asked for: `?page=999` on a two-page
      // list reports page 2, which is the page whose rows are in the reply.
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      families: stats.ISSUED_FAMILIES,
      revocableKinds: stats.REVOCABLE_KINDS,
      revokedCount: stats.revokedCount(),
      // `issued` rather than `tokens`, because the array is no longer only
      // tokens and a key that says otherwise is the kind of thing a test
      // asserts against once and then trusts. Nothing outside this repository
      // read the old name.
      issued: shown
    }
  };
}

app.get('/admin/tokens', function (req, res) {
  log.debug("Entering the admin tokens page.");
  const view = tokensView(req.query);
  const wantedFamily = view.wantedFamily;
  const wantedKind = view.wantedKind;
  const wantedState = view.wantedState;
  const all = view.all;
  const filtered = view.filtered;
  const paging = view.paging;
  const shown = view.shown;
  const heldByFamily = view.heldByFamily;
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
  const perOptions = perPageOptions(paging.perPage);

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

  respond(req, res, view.json, 'Tokens', '/admin/tokens', inner);
  log.debug("Leaving the admin tokens page.");
});

// ---------------------------------------------------------------------------
// GET /admin/audit — what happened here, in order.
//
// The other pages on this console are STATE: how many calls, which tokens are
// still valid, who is in cn=developers. This one is HISTORY, and the difference
// is the reason it exists. The metrics page can tell you the directory holds
// eleven entries; only this one can tell you that a twelfth was created at
// 14:02 and deleted at 14:03, by somebody bound as uid=carol, over LDAPS.
//
// Six categories, and every event in the service arrives through one of five
// funnels rather than from a recording site per feature:
//
//   authentication   admin_stats.recordAuthentication(), the single point all
//                    sixteen protocol families already pass through when a
//                    credential is ACCEPTED — SCIM being the fifteenth, for
//                    the three of its schemes that present a credential per
//                    request, and SPIFFE the sixteenth, for an X509-SVID
//                    presented over mutual TLS, an agent attesting and a
//                    JWT-SVID validated
//   session          authn.js's startSession / endSession, which is where both
//                    OAuth 2.0 / OIDC and WS-Federation sign in and out
//   directory        the seven LDAP handlers in ldap_server.js, plus the
//                    entries this service creates for people who authenticated
//                    somewhere else
//   admin / api      app.js's call log, classified by path
//   protocol         the same call log, everything else
//
// **ONE ACT USUALLY PRODUCES SEVERAL ROWS.** A sign-in at /authn/login writes
// three: the HTTP call, the credential being accepted, and the session that came
// out of it. They are three facts at three layers rather than one fact three
// times — and which of them you want depends on the question, which is exactly
// why the log does not choose. The page says so under the table.
//
// **IT OBSERVES ITSELF.** Drawing this page is console access, so it records an
// `admin.view` row, so the list is one longer than when you asked for it.
// Suppressing that would put a blind spot exactly where the person reading the
// audit log stands. It is stated instead, and `?category=` reads past it.
// ---------------------------------------------------------------------------

// Everything the page and the API both need out of one query string. Written as
// a view function for the reason the comment above consoleJson() gives: this
// console and /admin-api are two callers, and two hand-built copies of the same
// filtering would be two answers that each look right alone.
function auditView(query) {
  log.debug("Entering auditView().");
  const wantedCategory = String(query.category || '');
  const wantedAction = String(query.action || '');
  const wantedOutcome = String(query.outcome || '');
  const wantedActor = String(query.actor || '');
  const wantedText = String(query.q || '');
  const all = auditLog.list();
  const needle = wantedText.toLowerCase();
  const actorNeedle = wantedActor.toLowerCase();
  const filtered = all.filter(function (row) {
    if (wantedCategory && row.category !== wantedCategory) return false;
    if (wantedAction && row.action !== wantedAction) return false;
    if (wantedOutcome && row.outcome !== wantedOutcome) return false;
    // Substring rather than equality, and case-insensitively, because the actor
    // on a directory row may be the console key (`alice`) while the one on a
    // Kerberos row arrived as `alice@STS.MOCK` — the collapse to one key is done
    // where an identity is normalised and cannot be done for a row whose actor
    // is a bind DN. A substring finds the person either way.
    if (actorNeedle && (row.actor + ' ' + row.actorForm).toLowerCase()
                         .indexOf(actorNeedle) < 0) return false;
    // One free-text box over the three columns somebody would look in. The
    // summary alone would miss a DN that only appears in `target`, and a box
    // that silently searched one column while the reader assumed three is worse
    // than no box.
    if (needle && (row.summary + ' ' + row.target + ' ' + row.action)
                    .toLowerCase().indexOf(needle) < 0) return false;
    return true;
  });
  // Filter first, then page — the same order the tokens page uses and for the
  // same reason: paging a list and then filtering it gives a page 2 whose length
  // depends on what page 1 happened to hold.
  const paging = pagingOf(query, filtered.length);
  const shown = filtered.slice(paging.offset, paging.offset + paging.perPage);
  const summary = auditLog.summary();
  log.debug("Leaving auditView(). " + shown.length + " row(s) of " +
            filtered.length + ".");
  return {
    wantedCategory: wantedCategory, wantedAction: wantedAction,
    wantedOutcome: wantedOutcome, wantedActor: wantedActor,
    wantedText: wantedText,
    all: all, filtered: filtered, paging: paging, shown: shown,
    summary: summary,
    json: {
      held: summary.held,
      // Everything ever recorded and everything dropped, both, because `held`
      // alone reads as "this is all there was" the moment the cap has bitten.
      recorded: summary.recorded, dropped: summary.dropped,
      maxEvents: summary.maxEvents, protocolCalls: summary.protocolCalls,
      matched: filtered.length, shown: shown.length,
      // The lowest and highest sequence numbers still held. A caller polling
      // this endpoint uses them rather than a timestamp: `seq` is monotonic and
      // never reused, so "everything after 4,102" is exact, and a gap between
      // the last seq you saw and `oldestSeq` is precisely how many events you
      // missed.
      oldestSeq: summary.oldestSeq, newestSeq: summary.newestSeq,
      byCategory: summary.byCategory, byOutcome: summary.byOutcome,
      byAction: summary.byAction,
      filter: { category: wantedCategory || null, action: wantedAction || null,
                outcome: wantedOutcome || null, actor: wantedActor || null,
                q: wantedText || null },
      // The clamped values, not what was asked for: `?page=999` on a two-page
      // list reports page 2, which is the page whose rows are in the reply.
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      // The vocabulary, off the data rather than out of a list in a test: what
      // the `category`, `action` and `outcome` filters take.
      categories: auditLog.CATEGORIES, actions: auditLog.ACTIONS,
      outcomes: auditLog.OUTCOMES,
      events: shown
    }
  };
}

// The outcome, in the same three colours the token states use — so that a page
// somebody has learned to skim once reads the same way here. `refused` is amber
// rather than red on purpose: it is this service working correctly and saying
// no, which is most of what a debugger of a protocol client wants to see, and
// painting it as a failure would bury the 5xx rows that are one.
function outcomeCell(outcome) {
  const cls = outcome === 'success' ? 'state-valid'
            : (outcome === 'refused' ? 'state-expired' : 'state-revoked');
  return '<span class="' + cls + '">' + esc(outcome) + '</span>';
}

// The detail object as one cell. Rendered as `key=value` pairs rather than as
// JSON because the column is narrow and a reader is scanning for one fact, not
// parsing a document; `?format=json` has the object itself for anything that is
// not a person.
function auditDetailCell(detail) {
  const keys = Object.keys(detail || {});
  if (!keys.length) return '<span class="state-none">—</span>';
  return keys.map(function (key) {
    return '<code>' + esc(key) + '=' + esc(detail[key]) + '</code>';
  }).join(' ');
}

// Who did it. The console key links to their page where this service has seen
// them authenticate, following the same three-state rule the groups page uses —
// a name it knows, a name it could file somebody under but never has, and no
// name at all. The PRESENTED form is shown underneath when it differs, because
// the collapse from `uid=alice,ou=users,dc=example,dc=com` to `alice` is a thing
// an auditor has to be able to see rather than take on trust.
function auditActorCell(row, known) {
  if (!row.actor && !row.actorForm) {
    return '<span class="state-none" title="Nothing here names an actor. An ' +
      'unauthenticated protocol call and an anonymous LDAP bind both look like ' +
      'this, and both are ordinary on a service that authenticates nobody.">—</span>';
  }
  const parts = [];
  if (row.actor) {
    parts.push(known[row.actor]
      ? '<a href="' + esc('/admin/users' + queryWith({ user: row.actor }, {})) +
        '">' + esc(row.actor) + '</a>'
      : '<span class="state-none" title="The console has no row for this name: ' +
        'nothing has authenticated as them in this process. A directory bind DN ' +
        'yields a name without there being anybody behind it.">' +
        esc(row.actor) + ' <em>(never here)</em></span>');
  }
  if (row.actorForm && row.actorForm !== row.actor) {
    parts.push('<code>' + esc(row.actorForm) + '</code>');
  }
  return parts.join('<br>');
}

function auditRow(row, known) {
  return '<tr>' +
    '<td class="num">' + esc(row.seq) + '</td>' +
    '<td>' + esc(whenText(row.at)) + '</td>' +
    '<td>' + esc(row.category) + '</td>' +
    '<td><code>' + esc(row.action) + '</code></td>' +
    '<td>' + outcomeCell(row.outcome) + '</td>' +
    '<td class="who">' + auditActorCell(row, known) + '</td>' +
    '<td class="who">' + (row.target ? '<code>' + esc(row.target) + '</code>'
                                     : '<span class="state-none">—</span>') +
      (row.channel ? '<br><span class="state-none">' + esc(row.channel) +
                     (row.protocol ? ' — ' + esc(row.protocol) : '') + '</span>' : '') +
    '</td>' +
    '<td>' + esc(row.summary) + '</td>' +
    '<td class="who">' + auditDetailCell(row.detail) + '</td>' +
    '</tr>';
}

app.get('/admin/audit', function (req, res) {
  log.debug("Entering the admin audit page.");
  const view = auditView(req.query);
  const paging = view.paging;
  const summary = view.summary;
  const known = knownUserKeys();
  // What every paging link carries with it. The page number is not in here —
  // pageNav() supplies that per link — for the reason the tokens page gives: a
  // "next" that dropped the filter would be page 2 of a different list.
  const filterParams = { category: view.wantedCategory, action: view.wantedAction,
                         outcome: view.wantedOutcome, actor: view.wantedActor,
                         q: view.wantedText,
                         per: req.query.per ? paging.perPage : '' };
  const nav = pageNav('/admin/audit', filterParams, paging);

  const rows = view.shown.map(function (row) {
    return auditRow(row, known);
  }).join('');

  const categoryOptions = ['<option value=""' + (view.wantedCategory ? '' : ' selected') +
                           '>any category</option>']
    .concat(auditLog.CATEGORIES.map(function (entry) {
      return '<option value="' + esc(entry.category) + '"' +
             (entry.category === view.wantedCategory ? ' selected' : '') + '>' +
             esc(entry.label) + ' (' + (summary.byCategory[entry.category] || 0) + ')</option>';
    })).join('');

  // Grouped by category, and built from the SAME table the category select is,
  // so the two cannot come to disagree about which action belongs where — which
  // they would, being two hand-written lists of the same twenty-four strings.
  const actionOptions = '<option value=""' + (view.wantedAction ? '' : ' selected') +
    '>any action</option>' +
    auditLog.CATEGORIES.map(function (entry) {
      const inGroup = auditLog.ACTIONS.filter(function (a) {
        return a.category === entry.category;
      });
      return '<optgroup label="' + esc(entry.label) + '">' + inGroup.map(function (a) {
        return '<option value="' + esc(a.action) + '"' +
               (a.action === view.wantedAction ? ' selected' : '') + '>' +
               esc(a.action) + ' (' + (summary.byAction[a.action] || 0) + ')</option>';
      }).join('') + '</optgroup>';
    }).join('');

  const outcomeOptions = ['<option value=""' + (view.wantedOutcome ? '' : ' selected') +
                          '>any outcome</option>']
    .concat(auditLog.OUTCOMES.map(function (name) {
      return '<option value="' + esc(name) + '"' +
             (name === view.wantedOutcome ? ' selected' : '') + '>' + esc(name) +
             ' (' + (summary.byOutcome[name] || 0) + ')</option>';
    })).join('');

  const perOptions = perPageOptions(paging.perPage);

  const filtering = view.wantedCategory || view.wantedAction || view.wantedOutcome ||
                    view.wantedActor || view.wantedText;

  const inner = messagesOf(req) +
    '<div class="tiles">' +
      tile(summary.held, 'events held') +
      tile(summary.recorded, 'events recorded') +
      tile(summary.dropped, 'dropped (oldest first)') +
      tile(summary.byCategory.directory || 0, 'directory') +
      tile(summary.byCategory.authentication || 0, 'authentications') +
      tile(summary.byCategory.session || 0, 'session events') +
    '</div>' +

    '<p class="note">What this service has been asked to do, in the order it was ' +
    'asked, newest first. The other pages here are <em>state</em> — how many calls, ' +
    'which tokens are still valid, who is in <code>cn=developers</code>. This one is ' +
    '<em>history</em>: the metrics page can say the directory holds eleven entries, and ' +
    'only this page can say that a twelfth was created at 14:02 and deleted at 14:03 by ' +
    'somebody bound as <code>uid=carol</code>, over LDAPS.</p>' +

    '<p class="note"><strong>No credential is ever recorded here.</strong> Not a ' +
    'password, not a bearer token, not an assertion, and no request or response body. ' +
    'An event carries the facts of what happened — who, what, where, the outcome — and ' +
    'the identifiers that are already safe to show. A modify names the attributes it ' +
    'changed and never their values, because a modify is where a <code>userPassword</code> ' +
    'gets set; a compare says whether it matched and not what was tried; an ' +
    '<code>authorization code</code> in a query string is replaced with ' +
    '<code>(redacted)</code>. The debug log is where somebody who wants the bodies looks, ' +
    'and it is a log rather than a web page.</p>' +

    '<p class="note"><strong>One act usually produces several rows, and they are not ' +
    'duplicates.</strong> Signing in at <code>/authn/login</code> writes three: the HTTP ' +
    'call (<code>protocol.call</code>), the credential being accepted ' +
    '(<code>authentication</code>) and the session that came out of it ' +
    '(<code>session.start</code>). Those are three facts at three layers, and which one ' +
    'answers your question depends on the question — a Kerberos AS-REQ authenticates ' +
    'somebody and starts no session at all, and an LDAP bind does both without an HTTP ' +
    'request anywhere in it. Collapsing them would mean choosing, once and for everybody, ' +
    'which of the three this page can answer.</p>' +

    '<p class="note"><strong>This log observes itself.</strong> Drawing this page is ' +
    'console access, so fetching it records an <code>admin.view</code> event and the list ' +
    'is one row longer than it was when you asked. That is not a defect being left ' +
    'unfixed: suppressing it would put a blind spot exactly where the person reading the ' +
    'audit log stands. Filter by category to read past it.</p>' +

    '<h2>What happened</h2>' +
    // No `page` input in this form, deliberately: changing a filter or the page
    // size returns to page 1. Carrying the old page number over would land
    // somebody on page 6 of a two-page result and the clamp in pagingOf() would
    // then move them again, which reads as the form ignoring them.
    '<form method="get" action="/admin/audit"><div class="formrow">' +
      '<label for="category">Category</label><select id="category" name="category">' +
        categoryOptions + '</select>' +
      '<label for="action">Action</label><select id="action" name="action">' +
        actionOptions + '</select>' +
      '<label for="outcome">Outcome</label><select id="outcome" name="outcome">' +
        outcomeOptions + '</select>' +
      '<label for="per">Per page</label><select id="per" name="per">' + perOptions +
        '</select>' +
    '</div><div class="formrow">' +
      '<label for="actor">Actor</label>' +
      '<input type="text" id="actor" name="actor" size="20" value="' +
        esc(view.wantedActor) + '" placeholder="alice">' +
      '<label for="q">Text</label>' +
      '<input type="text" id="q" name="q" size="30" value="' + esc(view.wantedText) +
        '" placeholder="a DN, a path, anything in the summary">' +
      '<button class="secondary">Filter</button>' +
      (filtering ? ' <a href="/admin/audit">clear</a>' : '') +
    '</div></form>' +
    '<p class="note">Category and Action narrow together, like any two filters, so an ' +
    'action from another category matches nothing — which is what an empty table below ' +
    'then means. Actor matches a substring of either spelling of the name, because the ' +
    'actor on a directory row is a bind DN and the one on a Kerberos row is ' +
    '<code>alice@REALM</code>; the collapse to a single key can only be done where an ' +
    'identity is normalised.</p>' +
    nav +
    '<table><tr><th class="num">#</th><th>When</th><th>Category</th><th>Action</th>' +
    '<th>Outcome</th><th>Actor</th><th>Target</th><th>What happened</th><th>Detail</th></tr>' +
    (rows || '<tr><td colspan="9">Nothing matches.</td></tr>') + '</table>' +
    nav +

    '<p class="note">' + view.filtered.length + ' row(s) match' +
    (paging.pages > 1 ? ', of which rows ' + paging.firstRow + '&ndash;' + paging.lastRow +
                        ' are on this page (' + paging.page + ' of ' + paging.pages + ')' : '') +
    '; ' + summary.held + ' held of ' + summary.recorded + ' recorded since this process ' +
    'started' +
    (summary.dropped
      ? ', and <strong>' + summary.dropped + ' dropped</strong> — the log holds at most ' +
        summary.maxEvents + ' events and discards the oldest first. Raise ' +
        '<code>audit.maxEvents</code> on <a href="/admin/config">the configuration page</a> ' +
        'if that is losing something you need.'
      : '. The cap is ' + summary.maxEvents + ' events and nothing has been dropped yet.') +
    '</p>' +

    '<p class="note">The <strong>#</strong> column is a sequence number, and it is ' +
    'monotonic and never reused — including across a drop. That is what makes it a stable ' +
    'name for an event: a caller can say &ldquo;I have read up to ' +
    (summary.newestSeq || 0) + '&rdquo; and mean it, where a row number would silently ' +
    'name a different event as soon as anything was discarded. <code>?format=json</code> ' +
    'carries <code>oldestSeq</code> and <code>newestSeq</code> for exactly that: a gap ' +
    'between the last one you saw and <code>oldestSeq</code> is how many events you ' +
    'missed.</p>' +

    '<h3>Where the rows come from</h3>' +
    '<p class="note">Six categories and five recording points, rather than a recording ' +
    'site per feature. Each of these is a funnel this service already had:</p>' +
    '<ul>' + auditLog.CATEGORIES.map(function (entry) {
      return '<li><strong>' + esc(entry.label) + '</strong> (<code>' + esc(entry.category) +
             '</code>, ' + (summary.byCategory[entry.category] || 0) + ') — ' +
             esc(entry.what) + '</li>';
    }).join('') + '</ul>' +

    '<p class="note"><strong>What is deliberately not on a row: the client\'s address.</strong> ' +
    'On a mock this service is reached over a compose bridge, through a published port, or ' +
    'from the same machine, so what it would record is the bridge — a fact about docker ' +
    'rather than about whoever made the call. A column that was right on a laptop and ' +
    'quietly wrong everywhere else is worse than no column. What a row does say is the ' +
    'CHANNEL it arrived on — <code>http</code>, <code>ldap</code>, <code>ldaps</code>, or ' +
    '<code>internal</code> for the things this service did on its own — which is the part ' +
    'that is actually knowable and is what somebody turning on LDAPS wants to check.</p>' +

    '<p class="note"><strong>It is in memory and dies with the process</strong>, like the ' +
    'counters, the sessions and the signing key. There is no compliance story here to ' +
    'serve: this service checks no password anywhere, so an audit log of it is a debugging ' +
    'aid and not a record of anything. It also has no clear button, and that is a decision ' +
    'rather than an omission — an erase control on an unprotected console would make the ' +
    'page unable to answer the one question an audit log exists for. Restarting the ' +
    'service is how you get an empty one.</p>' +

    '<p class="note">Two settings on <a href="/admin/config">the configuration page</a> ' +
    'change this page and both take effect immediately: <code>audit.maxEvents</code> (now ' +
    summary.maxEvents + ') is the cap, and <code>audit.protocolCalls</code> (now ' +
    (summary.protocolCalls ? 'on' : '<strong>off</strong>') + ') is whether ordinary ' +
    'protocol endpoint calls get a row at all. That last one is the noisy category — every ' +
    'JWKS poll and metadata fetch is an event — so turning it off is how somebody watching ' +
    'the directory or the console gets a readable page. It never affects the other five ' +
    'categories, and <a href="/admin/metrics">the metrics page</a> counts every call either ' +
    'way.</p>' +

    '<p class="note">Paging is <code>?page=</code> and <code>?per=</code> (at most ' +
    MAX_ROWS + ' rows a page) and both work with <code>?format=json</code>, whose reply ' +
    'carries <code>page</code>, <code>pages</code> and <code>matched</code> so a test can ' +
    'walk the whole list without guessing where it ends. The same list is at ' +
    '<code>GET /admin-api/audit</code> with the same parameters.</p>';

  respond(req, res, view.json, 'Audit log', '/admin/audit', inner);
  log.debug("Leaving the admin audit page.");
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

// The FOURTH slot, and the third of the ones that READ. Same direction and same
// reason as the two above, and it passes rule 3e's test for the same two
// grounds: requiring scim.js from here would pull every /scim route — and, since
// that module requires ldap_server.js, every /ldap route too — into the express
// router ahead of the console's own, and /sts-metadata is built by walking that
// router.
//
// What it holds is scim.js's description(), which is the same object GET
// /scim?format=json answers with. So /admin/scim shows what that page shows
// rather than a second account of the same feature: the endpoint list, what SCIM
// deliberately does not do, and the reachable negatives are written ONCE, in the
// module that implements them, and this page renders them. A console page
// carrying its own copy of "active: false deactivates nobody" would be the copy
// that stops being true.
// The SPIFFE listeners, through a slot for the reason given beside the requires
// above: this file must not require spiffe_server.js. What it holds is that
// module's `bindings()` and its bundle path — two facts about SOCKETS, which
// neither this page nor /sts-metadata can see any other way, so a page without
// this reports "nothing bound" and cannot tell that from a listener whose port
// was taken.
let spiffeReader = null;

function setSpiffeReader(fn) {
  spiffeReader = fn;
  log.debug("A SPIFFE reader was installed; /admin/spiffe will now report " +
            "which gRPC listeners bound.");
}

// Answered with empty listeners rather than null when the slot is unfilled, so
// every caller renders the same "nothing bound" table instead of each having to
// guard. The bundle path falls back to the configured value, which is what that
// module reads too — one setting, two readers, no third opinion.
function spiffeListeners() {
  const read = spiffeReader ? spiffeReader() : null;
  return read || { workload: [], api: [],
                   bundlePath: config.value('spiffe.bundlePath') };
}

let scimReader = null;

function setScimReader(fn) {
  scimReader = fn;
  log.debug("A SCIM reader was installed; /admin/scim will now describe the " +
            "SCIM 2.0 endpoints.");
}

// And the one that WRITES, which is the third of these and the only one of the
// three that changes anything. Same direction and same reason as the two above —
// this file must not require ldap_server.js — and a third slot rather than a
// member on one of theirs, for the reason stated there: a module that filled a
// combined slot with only the readers would silently disable creation with
// nothing reporting it.
//
// It holds createUser() and NOT a way to write an arbitrary entry. The console
// is not a second definition of what a user is: what a name may be, and the
// refusal of one that is already here, live in that function so that this form,
// the management API and an `ldapadd` cannot come to disagree about the same
// name.
let directoryWriter = null;

function setDirectoryWriter(fn) {
  directoryWriter = fn;
  log.debug("A directory writer was installed; /admin/users can now create a " +
            "person in the directory.");
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
//
// Its token table is PAGED, and paged separately from every other block on the page.
// One browser session can hold most of the five thousand tokens this service
// remembers — a refresh grant in a loop is all it takes — so the block that answers
// "what does this person hold right now" is the one table here that can genuinely
// run away, and a single `page` shared with the block above it would move both.
// Hence a page parameter named after the session id: it names the block it moves, so
// a bookmark still moves the same session after the list around it has changed,
// which an index into the session list would not.
function sessionBlock(session, tokenPage, back, params) {
  log.debug("Entering sessionBlock(). id=" + session.id);
  const nav = pageNav('/admin/users', params, tokenPage.paging);
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
    nav +
    userTokenTable(tokenPage.shown, back,
      'Nothing has been issued on this session yet. A browser can hold a sign-on session and have ' +
      'been given no token at all — it is what the authorization endpoint reads before it issues ' +
      'anything.') +
    nav;
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
  // effect on that person. It carries the whole query and not just the name, so the
  // answer is the page of the table the button was on rather than the first page of
  // all five; backTo() picks the page parameters back out by shape.
  //
  // `params` is the whole current query carried through, and every control on this
  // page rides on it, so moving one of the five lists leaves the other four where
  // they are. See pageParamsOf() for why it is carried rather than listed.
  const params = pageParamsOf(req.query);
  const back = queryWith(params, {});
  const valid = detail.tokens.filter(function (t) { return t.state === 'valid'; }).length;
  // Read before the markup is assembled rather than inside it, because it is also
  // one of the keys of the JSON view below and reading it twice could show a page
  // and a JSON body that disagree about a directory another request just changed.
  const directory = ldapObjectSection(row, key);

  // Five lists on one page, each with its own page parameter and all of them sharing
  // `per` — see pagingOf() for why it is that way round.
  //
  // What is deliberately NOT paged here: the names this identity has been seen under,
  // the protocols it authenticated through, and the authentication events. The first
  // two are bounded by how many spellings and protocols exist, and the third is
  // capped at stats.MAX_EVENTS_PER_USER — fifty — by the registry itself, which is
  // the note authenticationTable() already prints. Paging a list that cannot exceed
  // fifty would buy a control nobody will see, and it would cost something real: all
  // three live on `row`, which goes out whole as this reply's `user`, so slicing them
  // for the table would either corrupt that object or duplicate it, and leaving the
  // JSON whole while the table paged is the console-and-API disagreement this file
  // keeps warning about.
  const sessionPage = pagedRows(req.query, sessionRows,
    { name: 'sessions', noun: 'sessions', defaultPer: DEFAULT_BLOCKS_PER_PAGE });
  const sessionsNav = pageNav('/admin/users', params, sessionPage.paging);
  // The token paging of each session that is on this page of sessions, kept beside
  // the block rather than recomputed for the JSON below: two calls with the same
  // arguments would be two chances for the page and the reply to disagree about
  // which tokens a reader is looking at.
  const sessionTokenPages = sessionPage.shown.map(function (session) {
    return pagedRows(req.query, split.held[session.id] || [],
                     { name: 'session-' + session.id, noun: 'tokens' });
  });
  const sessionBlocks = sessionPage.shown.map(function (session, index) {
    return sessionBlock(session, sessionTokenPages[index], back, params);
  }).join('');

  // ONE NAME PER LIST, and it is the name the reply's array carries: the parameter is
  // `<array>Page` and the paging object beside it is `<array>Paging`. Shortening
  // these two to `endedPage` and `sessionlessPage` read better and was wrong — a
  // caller reading `tokensWithNoSession` in the reply had to be told separately that
  // the parameter moving it was called something else, which is the sort of thing a
  // document gets right and a client author never finds.
  const endedPage = pagedRows(req.query, split.ended,
                              { name: 'tokensOnEndedSessions', noun: 'tokens' });
  const endedNav = pageNav('/admin/users', params, endedPage.paging);
  const sessionlessPage = pagedRows(req.query, split.sessionless,
                                    { name: 'tokensWithNoSession', noun: 'tokens' });
  const sessionlessNav = pageNav('/admin/users', params, sessionlessPage.paging);
  const artifactPage = pagedRows(req.query, detail.artifacts,
                                 { name: 'artifacts', noun: 'artifacts' });
  const artifactNav = pageNav('/admin/users', params, artifactPage.paging);

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

    perPageForm('/admin/users', 'user', key, artifactPage.paging.perPage,
                'The session BLOCKS below start at ' + DEFAULT_BLOCKS_PER_PAGE +
                ' rather than ' + DEFAULT_PER_PAGE + ', because each of them is ' +
                'itself a table; setting a size here applies to those too.',
                filterOnly(listViewOf('/admin/users', req.query))) +

    '<h2>Sessions, and what was issued on each</h2>' +
    '<p class="note">A <strong>sign-on session</strong> is a browser holding the ' +
    '<code>sts_mock_session</code> cookie, shared between the OAuth 2.0 / OIDC login screen and ' +
    'WS-Federation. A token is placed under a session because the issuance said so — no token ' +
    'this service issues carries a session identifier, and OIDC\'s <code>sid</code> claim is for ' +
    'front-channel logout, so inventing one to make this page easier would change what every ' +
    'client receives. The link is recorded out of band at issuance instead, and it survives a ' +
    'refresh: a refreshed token is looked up by the refresh token\'s <code>jti</code> and lands ' +
    'under the same session.</p>' +
    sessionsNav +
    (sessionBlocks || '<p class="note">This user holds no sign-on session. That is the normal state ' +
      'for every identity that never used a browser here — a password grant, a Kerberos client, a ' +
      'WS-Trust requester — and for anyone whose session has expired and been swept.</p>') +
    sessionsNav +

    (split.ended.length
      ? '<h3>Issued on a session that has since ended</h3>' +
        '<p class="note">These name a session this service no longer holds. It is not an error and ' +
        'it is the ordinary end state: the session expired or was signed out, and the tokens it ' +
        'produced outlived it — which is exactly the position a client is in when its access token ' +
        'still verifies and the browser would be asked to sign in again.</p>' +
        endedNav + userTokenTable(endedPage.shown, back, '') + endedNav
      : '') +

    (split.sessionless.length
      ? '<h3>Issued with no browser session at all</h3>' +
        '<p class="note">The grants that never involve a browser: <code>password</code>, ' +
        '<code>client_credentials</code>, OID4VCI\'s pre-authorized code, and token exchange. The ' +
        'Grant column says which. An empty Grant means the token was minted somewhere that states ' +
        'nothing about how — WS-Trust\'s JWT and the credential issuer both sign directly.</p>' +
        sessionlessNav + userTokenTable(sessionlessPage.shown, back, '') + sessionlessNav
      : '') +

    '<h2>Assertions, tickets and credentials</h2>' +
    '<p class="note">None of these can be revoked here and the console does not pretend otherwise: ' +
    'nothing consults this service about a SAML assertion, a Kerberos ticket or a credential, so a ' +
    'button would change a number on this page and nothing at all out there. The only distinction ' +
    'is whether the validity window has closed.</p>' +
    artifactNav + userArtifactTable(artifactPage.shown) + artifactNav +

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

  log.debug("Leaving userDetailPage(). " + sessionPage.shown.length + " session(s), " +
            artifactPage.shown.length + " artifact(s) shown of " + detail.tokens.length +
            " token(s) held.");
  return {
    inner: inner,
    json: {
      user: row,
      // Every array here is THE PAGE, not the whole list, exactly as `users` is on
      // the list view — and every one of them is answered by a `*Paging` object
      // carrying the same member names one level down, so a caller walks a
      // drill-down's five lists the way it already walks the three flat ones. A
      // session's own tokens are paged too and its paging travels with it, because
      // there is one such list per session and no top-level place to put five of
      // them that would still say which was which.
      sessions: sessionPage.shown.map(function (session, index) {
        return Object.assign({}, session, {
          tokens: sessionTokenPages[index].shown,
          tokensPaging: pagingJson(sessionTokenPages[index].paging)
        });
      }),
      sessionsPaging: pagingJson(sessionPage.paging),
      tokensOnEndedSessions: endedPage.shown,
      tokensOnEndedSessionsPaging: pagingJson(endedPage.paging),
      tokensWithNoSession: sessionlessPage.shown,
      tokensWithNoSessionPaging: pagingJson(sessionlessPage.paging),
      artifacts: artifactPage.shown,
      artifactsPaging: pagingJson(artifactPage.paging),
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

  const listView = listViewOf('/admin/users', req.query);
  const rows = shown.map(function (row) {
    // The link carries the list AS IT IS BEING VIEWED, which is what lets the
    // trail on the other side come back to this page of this filter rather than to
    // the top of everything. See listViewOf().
    const href = '/admin/users' + queryWith(listView, { user: row.key });
    // Shortened for the same reason the metrics page's Who column is, and the
    // Decentralized Identity endpoints are what made it reach this table too: a
    // did:jwk is a couple of hundred characters of base64url with not one place
    // in it a browser will break a line, so drawn in full it sets this cell's
    // minimum width and pushes every column after it off the card — including
    // the rows of people whose names are three letters long. 40 keeps
    // `urn:sts-mock:user:alice` and an ordinary DID whole; shortened() puts the
    // rest in the title attribute, so nothing is lost, only hidden.
    return '<tr><td><a href="' + esc(href) + '">' + shortened(row.name, 40) + '</a></td>' +
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
  const perOptions = perPageOptions(paging.perPage);

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

    // The one control on this page. It writes to the DIRECTORY and not to the
    // table below it, which the note says outright — see usersAction() for why
    // that sentence is not optional. The `back` field carries the filter and
    // page so that creating somebody does not throw the reader back to the top
    // of an unfiltered list; the handler rebuilds it through the whitelist
    // rather than echoing it.
    '<form method="post" action="/admin/users">' +
      '<input type="hidden" name="action" value="create">' +
      '<input type="hidden" name="back" value="' + esc(queryWith(listView, {})) + '">' +
      '<div class="formrow">' +
        '<label for="new-username">Create a user</label>' +
        '<input type="text" id="new-username" name="username" size="20" ' +
               'placeholder="username" required>' +
        '<button>Create</button>' +
      '</div>' +
      '<p class="note">Puts an entry in the embedded LDAP directory at ' +
      '<code>uid=&lt;name&gt;,' + esc('ou=users,' + config.value('ldap.baseDn')) + '</code>, with the invented person ' +
      'behind that name written onto it, so an issued credential and an ' +
      '<code>ldapsearch</code> agree from the start. <strong>One entry per person:</strong> a ' +
      'name that is already here is refused, whichever protocol brought them and whatever ' +
      'attribute their entry is named by — the same refusal an <code>ldapadd</code> and ' +
      '<code>POST /admin-api/users/create</code> get, because all three call one function. ' +
      'The new user will not appear in the table below until they authenticate somewhere: that ' +
      'is who this service has SEEN, and this is what the directory HOLDS. No password is set, ' +
      'because none is ever checked.</p>' +
    '</form>' +
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

// ---------------------------------------------------------------------------
// THE ONE THING THIS PAGE CAN CHANGE.
//
// Everything else on /admin/users is a report: who has authenticated, what they
// were issued, what the directory holds about them. This creates a person in the
// directory, and it is here rather than on /admin/groups or /ldap because this is
// the page a reader is on when they discover that somebody is missing.
//
// IT DECIDES NOTHING. Every rule about what a username may be, and the refusal
// of one that already exists, is in ldap_server.js's createUser() — reached
// through the slot above. This function reads the form and phrases the answer,
// which is the same split /admin/applications keeps with applications.js and the
// reason POST /admin-api/users/create can call straight into this without a
// second reading of any of it.
//
// WHAT IT DOES NOT DO is make the person appear in the list on this page. That
// list is identities this service has SEEN authenticate; the entry is in the
// DIRECTORY. The two are different questions — it is the same distinction
// /admin/groups draws when it marks a member "never here" — and the message says
// so outright, because an operator who created a user and could not find them in
// the table above would reasonably conclude the button was broken.
// ---------------------------------------------------------------------------
function usersAction(body) {
  log.debug("Entering usersAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');

  if (action === 'create') {
    if (!directoryWriter) {
      log.debug("Leaving usersAction(). No directory is loaded.");
      return { ok: false, errors: ['No LDAP directory is loaded in this process, so there is ' +
                                   'nowhere to put a person. The rest of this page is ' +
                                   'unaffected — it reports what this service has seen, which ' +
                                   'does not come from the directory.'] };
    }
    const username = String(body.username || body.user || '').trim();
    const result = directoryWriter(username, {
      origin: 'console',
      note: String(body.note || '').trim() ||
            'created by hand on the admin console rather than by authenticating',
      channel: 'console'
    });
    if (!result.ok) {
      log.debug("Leaving usersAction(). create refused.");
      return result;
    }
    log.debug("Leaving usersAction(). Created " + result.dn + ".");
    return { ok: true, dn: result.dn, username: result.username, entry: result.entry,
             message: result.dn + ' now exists in the directory, with the invented person ' +
                      'behind that name written onto it — so a credential issued for ' +
                      result.username + ' and an ldapsearch for that entry say the same ' +
                      'thing. They will NOT appear in the table on this page until they ' +
                      'authenticate somewhere: this list is who this service has seen, and ' +
                      'the entry is what the directory holds. Nothing here checks a ' +
                      'password, so there is none to set.' };
  }

  log.debug("Leaving usersAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". There is one: create.'] };
}

// One route, three answers, and the choice between them is here rather than in
// the route so that /admin-api/users makes the same one. `known: false` is the
// third and it is not a 404 — see the comment inside it.
function usersView(req) {
  log.debug("Entering usersView().");
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
        // The same href the trail's section crumb carries, so the two ways back off
        // this page cannot land in different places.
        '<p class="note"><a href="' +
        esc('/admin/users' + queryWith(listViewOf('/admin/users', req.query), {})) +
        '">Back to the list</a>.</p>';
      log.debug("Leaving usersView(). No such user.");
      return { json: { user: wantedUser, known: false }, inner: inner,
               title: 'User',
               up: upTo('/admin/users', wantedUser, listViewOf('/admin/users', req.query)) };
    }
    log.debug("Leaving usersView(). The drill-down.");
    return { json: Object.assign({ known: true }, detail.json),
             inner: detail.inner, title: 'User ' + wantedUser,
             up: upTo('/admin/users', wantedUser,
                      listViewOf('/admin/users', req.query)) };
  }
  const list = usersListPage(req);
  log.debug("Leaving usersView(). The list.");
  return { json: list.json, inner: list.inner, title: 'Users' };
}

app.get('/admin/users', function (req, res) {
  log.debug("Entering the admin users page.");
  const view = usersView(req);
  respond(req, res, view.json, view.title, '/admin/users', view.inner, view.up);
  log.debug("Leaving the admin users page. " + view.title + ".");
});

app.post('/admin/users', function (req, res) {
  log.debug("Entering the admin users action endpoint.");
  const body = parseBody(req);
  const result = usersAction(body);
  // Back to the list carrying whatever filter and page the form came from, so
  // that creating somebody does not cost the reader their place — the rule every
  // form on this console follows.
  const back = '/admin/users' + queryWith(listViewFromBack('/admin/users', body.back), {});
  respondToAction(req, res, back, result);
  log.debug("Leaving the admin users action endpoint.");
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
// It used to say the two halves as one sentence — nothing reads a group AND no
// token carries one — and the second half stopped being true when the groups
// claim was added. They are split now, in that order, because the one a reader
// most needs is still the first: CARRYING a fact and ACTING on it are different
// claims, and this is the same line this service already draws between an
// identity being recorded and an identity being authenticated.
const GROUPS_CAVEAT =
  '<p class="note"><strong>A group here grants nothing.</strong> No endpoint in this service ' +
  'checks one, and nothing decides anything on one. Adding somebody to ' +
  '<code>cn=directory-admins</code> changes what a directory client sees, and what a token ' +
  '<em>says</em>, and changes nothing at all about what that token can DO &mdash; on a service ' +
  'that authenticates nobody, it could hardly be otherwise.</p>' +
  '<p class="note"><strong>A token can now carry one.</strong> With ' +
  '<code>groups.claim</code> on &mdash; it is on by default &mdash; every OAuth 2.0 access ' +
  'token, OIDC ID Token, SAML 2.0 assertion and SAML 1.1 assertion this service issues carries ' +
  'a claim naming the groups its subject is in, read from these entries at the moment it is ' +
  'minted. Somebody in no group gets no claim at all rather than an empty list. What it is ' +
  'called, whether each value is a <code>cn</code> or a whole DN, and whether a person\'s own ' +
  '<code>memberOf</code> counts are on <a href="/admin/config">the configuration page</a>; ' +
  '<a href="/admin/claims">the claims page</a> shows what it would say about one person. No ' +
  'Kerberos PAC and no WS-Federation-specific token carries a group either way.</p>';

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
  const filterParams = { q: wantedText || '',
                         per: req.query.per ? paging.perPage : '' };
  const nav = pageNav('/admin/groups', filterParams, paging);

  const listView = listViewOf('/admin/groups', req.query);
  const rows = shown.map(function (group) {
    // The link carries the list AS IT IS BEING VIEWED, which is what lets the
    // trail on the other side come back to this page of this filter rather than to
    // the top of everything. See listViewOf().
    const href = '/admin/groups' + queryWith(listView, { group: group.dn });
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
    '<label for="per">Per page</label>' +
    '<select id="per" name="per">' + perPageOptions(paging.perPage) + '</select>' +
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
  // The same href the trail's section crumb carries — see listViewOf(). Two ways
  // back off one page that land in different places is worse than one.
  const back = '<p class="note"><a href="' +
    esc('/admin/groups' + queryWith(listViewOf('/admin/groups', req.query), {})) +
    '">Back to the groups</a>.</p>';

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

  // Two lists on this page and a page parameter each, sharing `per` — the same
  // arrangement the users drill-down has, and for the same reason: one `page` would
  // move both, and the two disagreements this page exists to show are read against
  // each other, so advancing the members while the claimants jumped with them would
  // be the one navigation that makes the page harder to read than no navigation.
  //
  // The counts above the tables — memberCount, presentCount, danglingCount — stay
  // counts of the WHOLE list and are read off the directory rather than off the
  // slice, because "seven members, five resolve" is the fact the page is for and
  // "five members on this page" is not an answer to it.
  const params = pageParamsOf(req.query);
  const memberPage = pagedRows(req.query, group.members, { name: 'members', noun: 'members' });
  const membersNav = pageNav('/admin/groups', params, memberPage.paging);
  const claimedPage = pagedRows(req.query, group.claimed, { name: 'claimed', noun: 'entries' });
  const claimedNav = pageNav('/admin/groups', params, claimedPage.paging);

  const memberRows = memberPage.shown.map(function (member) {
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

  const claimedRows = claimedPage.shown.map(function (entry) {
    return '<tr><td class="who"><code>' + esc(entry.dn) + '</code></td>' +
      '<td>' + (entry.cn ? esc(entry.cn) : '<span class="state-none">—</span>') + '</td>' +
      '<td>' + (entry.mail ? '<code>' + esc(entry.mail) + '</code>'
                           : '<span class="state-none">—</span>') + '</td>' +
      '<td>' + usersPageCell(entry.userKey, known) + '</td></tr>';
  }).join('');

  const claimedSection = group.claimed.length
    ? '<h2>Entries that claim this group, and that it does not list</h2>' +
      claimedNav +
      '<table><tr><th>DN</th><th>cn</th><th>mail</th><th>On the users page</th></tr>' +
      claimedRows + '</table>' +
      claimedNav +
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

    perPageForm('/admin/groups', 'group', group.dn, memberPage.paging.perPage, '',
                filterOnly(listViewOf('/admin/groups', req.query))) +

    '<h2>Members</h2>' +
    '<div class="tiles">' +
    tile(group.memberCount, 'Membership values') +
    tile(group.presentCount, 'Resolve to an entry') +
    tile(group.danglingCount, 'Dangling') +
    tile(group.claimed.length, 'Claim it back') +
    '</div>' +
    (group.memberCount
      ? membersNav +
        '<table><tr><th>Member</th><th>From</th><th>State</th><th>What it is</th><th>cn</th>' +
        '<th>mail</th><th>On the users page</th><th>The value as stored</th></tr>' +
        memberRows + '</table>' + membersNav
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

  log.debug("Leaving groupDetailPage(). " + memberPage.shown.length + " of " +
            group.memberCount + " member value(s) shown, " +
            Object.keys(group.attributes).length + " attribute(s).");
  // The entry is copied rather than sliced in place. groupsFor() builds a fresh
  // object per call today, so mutating it would work — but that is a fact about
  // another module, and a reader of this one cannot see it. `members` and `claimed`
  // go out as THE PAGE, like every other list here; the paging objects sit beside
  // `group` rather than inside it because they describe this reply and not the
  // directory entry, whose own counts are untouched next to them.
  const pagedGroup = Object.assign({}, group, {
    members: memberPage.shown, claimed: claimedPage.shown
  });
  return {
    inner: inner,
    json: Object.assign({ found: true }, info, {
      group: pagedGroup,
      membersPaging: pagingJson(memberPage.paging),
      claimedPaging: pagingJson(claimedPage.paging)
    })
  };
}

// Three answers again, and the first of them — no directory in this process —
// is the one an API caller is most likely to meet and least likely to expect,
// because it answers 200 with `directory: false` rather than failing.
function groupsView(req) {
  log.debug("Entering groupsView().");
  if (!groupReader) {
    // A build without ldap_server.js. Answered rather than 404'd, and with the
    // nav intact, for the same reason the user page's directory section says it
    // in words: the page exists, the directory does not, and those are different
    // facts about this process.
    log.debug("Leaving groupsView(). No directory is loaded.");
    return { json: { directory: false, groups: [] }, title: 'Groups',
             inner: messagesOf(req) + noGroupDirectorySection() };
  }
  const wantedDn = String(req.query.group || '').trim();
  if (wantedDn) {
    const detail = groupDetailPage(req, wantedDn);
    log.debug("Leaving groupsView(). The drill-down.");
    return { json: detail.json, inner: detail.inner,
             title: 'Group ' + wantedDn,
             // The whole DN is the leaf and shortCrumb() cuts it if it has to,
             // rather than being cut to its first RDN here: a leaf trimmed at the
             // shell keeps its full text in the tooltip, and a DN cut here would
             // lose the container it is in with nowhere left to say so. What the
             // cut drops is the tail, which is the part every entry shares.
             up: upTo('/admin/groups', wantedDn,
                      listViewOf('/admin/groups', req.query)) };
  }
  const list = groupsListPage(req);
  log.debug("Leaving groupsView(). The list.");
  return { json: list.json, inner: list.inner, title: 'Groups' };
}

// ---------------------------------------------------------------------------
// GET /admin/applications
//
// The other side of /admin/users. That page lists every identity that has
// authenticated here; this one lists what they authenticated TO — every OAuth
// client, OpenID Connect relying party, SAML 2.0 or 1.1 service provider,
// WS-Federation application, WS-Trust relying party, OpenID4VP verifier and
// Kerberos service this instance has been asked about.
//
// **It reads the directory and holds nothing.** The registry IS the
// ou=applications container (see applications.js), so this page cannot come to
// disagree with what an LDAP client sees — there is no second copy for it to
// disagree with. An `ldapmodify` made a second ago shows up on the next refresh.
//
// **There is no form on it, and that is a decision rather than an omission.**
// The write paths into this registry are the protocol endpoints and LDAP
// itself, and both are the point: a client is recorded because it turned up, and
// an operator changes one with `ldapmodify` — which is what makes the directory
// the source of truth rather than a display of one. A console form would be a
// third door onto the same store, and the one a reader would then expect to be
// authoritative. It is the same shape /admin/audit has and for a related
// reason, so it needs no POST on /admin-api either (see rule 7 in CLAUDE.md:
// the parity is about CONTROLS, and there are none here).
// ---------------------------------------------------------------------------
const APPLICATIONS_CAVEAT =
  '<p class="note"><strong>An entry here grants nothing.</strong> Being in this ' +
  'registry does not let an application do anything it could not do before &mdash; ' +
  'this service issues a token to any client_id that asks. The one place it is READ ' +
  'is RFC 9700 mode (<code>oauth2.rfc9700</code>), which matches a redirect_uri ' +
  'against <code>oauthRedirectUri</code> by exact string comparison, decides ' +
  'public-versus-confidential from <code>oauthTokenEndpointAuthMethod</code>, and ' +
  'checks <code>oauthClientSecret</code> at the token endpoint. With that mode off, ' +
  'these entries are a record and nothing more.</p>' +
  '<p class="note"><strong>Two attributes hold credentials in the clear</strong> ' +
  '&mdash; <code>oauthClientSecret</code> and <code>appRegistrationAccessToken</code> ' +
  '&mdash; in a directory where every bind succeeds. That is the same decision ' +
  '<code>/krb5/principals</code> makes about the Kerberos passwords and it costs more ' +
  'here than it does there: in RFC 9700 mode that secret is checked, so anyone who can ' +
  'read this directory can authenticate as that client. They are never written to the ' +
  'audit log.</p>';

const APPLICATIONS_LINKS =
  '<p class="sub"><a href="/ldap/applications">the same registry as the directory ' +
  'sees it, with the schema</a> &middot; <a href="/admin/users">the identities on the ' +
  'other side of these</a> &middot; <a href="/ldap/directory">every entry in the ' +
  'directory</a></p>';

// One application's kinds as cells, since a record commonly carries two — an
// OAuth client that asked for the openid scope is also a relying party, and a
// wtrealm handed a SAML 2.0 assertion in one request and the 1.1 default in the
// next is both of those. The registry accumulates rather than choosing, so the
// cell has to.
function kindCells(kinds) {
  if (!kinds.length) {
    return '<span class="state-none">unstated</span>';
  }
  return kinds.map(function (kind) {
    return '<code>' + esc(kind) + '</code>';
  }).join('<br>');
}

// ---------------------------------------------------------------------------
// POST /admin/applications — the six actions.
//
// **The console is not a second door onto this registry**, and that is the whole
// design of these: every one calls a function in `applications.js` which does
// the same read-modify-write `seen()` does, through the same two conversions,
// against the same `ou=applications` entries. The store stays one store; what is
// added here is a set of controls in front of it. An `ldapmodify` and a form
// post are the same act arriving by two routes, and both are visible to the
// other immediately because nothing caches.
//
// **What may be changed is DECLARED and not DERIVED**, and that line is drawn in
// `applications.js`'s EDITABLE table rather than here: redirect URIs, grant
// types, scopes, the secret, whether the client is confidential — configuration,
// which is what RFC 9700 mode reads — but never the counters, the sightings, the
// kinds or the protocols, which are what happened. LDAP can still reach those;
// the difference between offering an operation and merely not preventing it is
// the point. This handler renders and decides nothing: it validates that an
// action exists and hands the rest over, exactly as the console does for groups.
// ---------------------------------------------------------------------------
function applicationsAction(body) {
  log.debug("Entering applicationsAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const identifier = String(body.application || '').trim();
  const needsOne = ['set', 'add', 'remove', 'revoke-registration', 'forget'];
  if (needsOne.indexOf(action) >= 0 && !identifier) {
    log.debug("Leaving applicationsAction(). No application named.");
    return { ok: false, errors: ['Which application? Send `application` with the identifier ' +
                                 'exactly as this registry holds it — the client_id, wtrealm, ' +
                                 'AppliesTo, entityID or service principal name.'] };
  }

  if (action === 'create') {
    const result = applications.createApplication({
      identifier: String(body.identifier || body.application || ''),
      name: String(body.name || ''),
      kind: String(body.kind || '')
    });
    log.debug("Leaving applicationsAction(). create " + (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) return result;
    return { ok: true, application: result.application,
             message: '"' + result.application.identifier + '" is in the registry. It has ' +
                      'authenticated nothing yet — the counters are zero and the entry says ' +
                      'it was created by hand, so it cannot be mistaken for one that turned ' +
                      'up once. Give it the redirect URIs and grant types it is allowed, and ' +
                      'RFC 9700 mode will judge it against them.' };
  }

  if (action === 'set' || action === 'add' || action === 'remove') {
    const result = applications.updateApplication(identifier, {
      mode: action,
      attribute: String(body.attribute || ''),
      value: body.value === undefined ? '' : String(body.value)
    });
    log.debug("Leaving applicationsAction(). " + action + " " + (result.ok ? 'ok' : 'refused') + ".");
    return result;
  }

  if (action === 'revoke-registration') {
    // Not a delete: the entry stays and its history with it. This is RFC 7592's
    // delete reached from the console instead of from the client that holds the
    // registration access token — the same function, so the outcome is the same
    // one and not a second reading of what "unregistered" means.
    const before = applications.get(identifier);
    if (!before) {
      return { ok: false, errors: ['There is no application called "' + identifier + '" here.'] };
    }
    if (!before.registered) {
      return { ok: false, errors: ['"' + identifier + '" has no registration to revoke. It is ' +
                                   'a client_id this service has seen rather than one that ' +
                                   'went through POST /oauth2/register, which RFC 9700 mode ' +
                                   'already treats as public.'] };
    }
    applications.forgetRegistration(identifier);
    log.debug("Leaving applicationsAction(). The registration was revoked.");
    return { ok: true, application: applications.get(identifier),
             message: 'The RFC 7591 registration for "' + identifier + '" is gone, along with ' +
                      'its client_secret and its registration access token. The ENTRY stays, ' +
                      'with everything it had recorded — losing that this application was ever ' +
                      'here because its registration was withdrawn would be losing the fact ' +
                      'rather than the configuration. RFC 9700 mode now treats it as an ' +
                      'unregistered, public client and judges its redirect_uri against the ' +
                      'oauth2.redirectUris setting.' };
  }

  if (action === 'forget') {
    const result = applications.deleteApplication(identifier);
    log.debug("Leaving applicationsAction(). forget " + (result.ok ? 'ok' : 'refused') + ".");
    return result;
  }

  log.debug("Leaving applicationsAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The six are: create, set, ' +
                               'add, remove, revoke-registration, forget.'] };
}

app.post('/admin/applications', function (req, res) {
  log.debug("Entering the admin applications action endpoint.");
  const body = parseBody(req);
  const result = applicationsAction(body);
  // Back to the drill-down the form was posted from, when there was one, so a
  // reader who has just added a redirect URI is looking at the entry that now
  // carries it rather than at the top of the list — and carrying the list state
  // that came in on the form's `back` field either way, so the breadcrumb on the
  // page they land on still offers the filter and page they came from. Without
  // that, editing an application silently costs the reader their place in the
  // list, which is exactly what the trail exists to keep.
  const listView = listViewFromBack('/admin/applications', body.back);
  const back = String(body.application || '').trim() && result.ok !== false
    ? '/admin/applications' + queryWith(listView, { application: String(body.application).trim() })
    : '/admin/applications' + queryWith(listView, {});
  respondToAction(req, res, back, result);
  log.debug("Leaving the admin applications action endpoint.");
});

// The two selects the edit forms offer, built from applications.js's EDITABLE
// table so that a form cannot offer a field the action would refuse — the same
// reason the audit page's filters are built from the audit vocabulary.
function editableOptions(mode, selected) {
  return applications.editableAttributes(mode).map(function (row) {
    return '<option value="' + esc(row.name) + '"' +
      (row.name === selected ? ' selected' : '') + '>' + esc(row.name) +
      (row.sensitive ? ' (credential)' : '') + '</option>';
  }).join('');
}

// What one attribute of an application entry IS, as the drill-down's third
// column. Split out of that page because the entry carries FOUR kinds of
// attribute and the table only ever described one of them — so everything else
// came out as "not in the published schema", which is true of `objectClass` and
// `createTimestamp` in the narrowest sense and useless as an explanation.
//
// The order is the order of certainty: the registry's own table first, since it
// is the same table the entry was written from; then the operational ones, which
// the DIRECTORY sets and no schema of this module's would ever mention; then the
// object classes, published one heading further down `/ldap/applications`; and
// only then the honest "somebody wrote this by hand", which is a real state —
// this directory is schemaless and an ldapmodify can put anything on an entry.
//
// No description is invented for an attribute nothing here knows. Saying
// something confident about a name written by hand is how a page starts lying.
function applicationAttributeNote(name, operational) {
  const lower = String(name).toLowerCase();
  const spec = applications.SCHEMA.attributes.filter(function (one) {
    return one.name.toLowerCase() === lower;
  })[0];
  if (spec) {
    return { text: spec.what, sensitive: !!spec.sensitive };
  }
  if (lower === 'entrydn') {
    return { text: 'WHERE THE ENTRY IS. RFC 5020, and the directory synthesises it ' +
                   'rather than storing it: the DN is the key the entry is held under, ' +
                   'so a stored copy would be a second definition of the same fact and ' +
                   'the one that goes stale the moment the entry is renamed. It is the ' +
                   'name an ldapsearch filter matches this by, which is why the dump ' +
                   'calls it the same thing.' };
  }
  if (lower === 'createtimestamp' || lower === 'modifytimestamp') {
    return { text: 'The directory\'s own, not the registry\'s: when this ENTRY was ' +
                   (lower === 'createtimestamp' ? 'created' : 'last written') + '. ' +
                   'Different from appFirstSeen and appLastSeen one row up, which are ' +
                   'when the APPLICATION was seen — an ldapmodify moves this one and ' +
                   'not those.' };
  }
  if (lower === 'objectclass') {
    return { text: 'The classes this entry claims, from the registry\'s vocabulary: ' +
                   applications.SCHEMA.objectClasses.map(function (one) {
                     return one.name;
                   }).join(', ') + '. A VOCABULARY and not a constraint — node-ldapjs ' +
                   'has no schema subsystem and this directory is schemaless on ' +
                   'purpose, so nothing rejects an entry for disobeying it.' };
  }
  if (operational) {
    // An operational attribute this function has no sentence for, which means
    // ldap_server.js's OPERATIONAL list grew and this one did not. Saying so is
    // better than the "written by hand" answer below, which would be flatly
    // wrong about an attribute the directory sets itself.
    return { text: 'An operational attribute the directory sets. A search returns it only ' +
                   'when it is asked for by name (RFC 4511 section 4.5.1.8); this dump is ' +
                   'not a search, so it is here. This page has nothing more specific to ' +
                   'say about it.' };
  }
  return { text: 'Not in the published schema and not one the directory sets — written ' +
                 'by hand into this entry, which nothing here prevents and which is what ' +
                 'a schemaless directory means. The registry\'s own writes REPLACE the ' +
                 'entry, so a value here survives only until the next time this ' +
                 'application is seen.' };
}

function applicationsListPage(req) {
  log.debug("Entering applicationsListPage().");
  const all = applications.list();
  const wantedText = String(req.query.q || '').trim();
  const wantedKind = String(req.query.kind || '').trim();
  const needle = wantedText.toLowerCase();
  const filtered = all.filter(function (row) {
    if (wantedKind && row.kinds.indexOf(wantedKind) < 0) {
      return false;
    }
    if (!needle) {
      return true;
    }
    // The identifier and the name both, because somebody looking for an
    // application has one or the other in mind and which one depends on whether
    // they came from a client's configuration or from this console.
    return row.identifier.toLowerCase().indexOf(needle) >= 0 ||
           String(row.name).toLowerCase().indexOf(needle) >= 0;
  });
  const paged = pagedRows(req.query, filtered, { noun: 'applications' });
  const paging = paged.paging;
  const filterParams = { q: wantedText || '', kind: wantedKind || '',
                         per: req.query.per ? paging.perPage : '' };
  const nav = pageNav('/admin/applications', filterParams, paging);

  const listView = listViewOf('/admin/applications', req.query);
  const rows = paged.shown.map(function (row) {
    // The link carries the list AS IT IS BEING VIEWED, which is what lets the
    // trail on the other side come back to this page of this filter rather than to
    // the top of everything. See listViewOf().
    const href = '/admin/applications' + queryWith(listView, { application: row.identifier });
    return '<tr><td><a href="' + esc(href) + '"><code>' + esc(row.identifier) + '</code></a>' +
      // The DN on every row rather than only where the RDN is a digest. These
      // entries ARE the registry, so the DN is what an ldapsearch or ldapmodify
      // is aimed at; showing it only in the odd case made it look like a note
      // about a special entry instead of the address of every one of them.
      (row.dn ? '<div class="sub"><code>' + esc(row.dn) + '</code>' +
        (row.identifier === row.dnLabel ? '' :
          ' &mdash; the identifier is too long for a readable RDN, so the ' +
          '<code>cn</code> is a digest of it') + '</div>' : '') +
      '</td><td>' + esc(row.name) + '</td>' +
      '<td>' + kindCells(row.kinds) + '</td>' +
      '<td>' + esc(row.protocols.join(', ')) + '</td>' +
      '<td>' + (row.registered
        ? '<span class="state-valid">yes</span>'
        : '<span class="state-none">no</span>') + '</td>' +
      '<td class="num">' + row.authentications + '</td>' +
      '<td class="num">' + row.sessions + '</td>' +
      '<td class="num">' + row.users + '</td>' +
      '<td><code>' + esc(row.lastSeen) + '</code></td></tr>';
  }).join('');

  const kindOptions = ['<option value=""' + (wantedKind ? '' : ' selected') +
                       '>any kind</option>']
    .concat(applications.KINDS.map(function (one) {
      // Counted over EVERYTHING rather than over the filtered set, so the
      // numbers do not change as the reader narrows the list — a select whose
      // options renumber themselves on every Filter is one nobody can use to
      // find out where the rows went.
      const n = all.filter(function (row) { return row.kinds.indexOf(one.kind) >= 0; }).length;
      return '<option value="' + esc(one.kind) + '"' +
             (one.kind === wantedKind ? ' selected' : '') + '>' +
             esc(one.label) + ' (' + n + ')</option>';
    })).join('');

  const registeredCount = all.filter(function (row) { return row.registered; }).length;

  const inner = messagesOf(req) +
    '<div class="tiles">' +
    tile(all.length, 'Applications') +
    tile(registeredCount, 'Registered (RFC 7591)') +
    tile(all.reduce(function (n, r) { return n + r.authentications; }, 0), 'Authentications') +
    tile(applications.maxApplications ? applications.maxApplications() : '', 'Maximum held') +
    '</div>' +
    '<form method="get" action="/admin/applications"><div class="formrow">' +
    '<label for="q">Application</label>' +
    '<input type="text" id="q" name="q" value="' + esc(wantedText) + '" size="28" ' +
    'placeholder="client_id, wtrealm, entityID, SPN or name">' +
    '<label for="kind">Kind</label>' +
    '<select id="kind" name="kind">' + kindOptions + '</select>' +
    '<label for="per">Show</label>' +
    '<select id="per" name="per">' + perPageOptions(paging.perPage) + '</select>' +
    '<button type="submit">Filter</button>' +
    ((wantedText || wantedKind)
      ? ' <a href="/admin/applications">clear</a>' : '') +
    '</div></form>' +
    nav +
    '<table><tr><th>Identifier</th><th>Name</th><th>Kind</th><th>Protocols</th>' +
    '<th>Registered</th><th class="num">Auth</th><th class="num">Sessions</th>' +
    '<th class="num">Users</th><th>Last seen</th></tr>' +
    (rows || '<tr><td colspan="9">No application matches. ' +
             ((wantedText || wantedKind)
               ? 'The filter above may be hiding some.'
               : 'One appears the first time a client_id, wtrealm, AppliesTo, entityID ' +
                 'or service principal name is accepted here.') + '</td></tr>') +
    '</table>' +
    nav +
    '<h2>Add an application</h2>' +
    '<p class="note">For a relying party that has not connected yet. An entry usually appears ' +
    'because an identifier was ACCEPTED — a client_id at the token endpoint, a wtrealm on a ' +
    'sign-in response — and this is how to get one in ahead of that, which is what RFC 9700 ' +
    'mode needs if it is to judge a client against its own redirect URIs rather than against ' +
    'the <code>oauth2.redirectUris</code> setting. It records that it was created by hand, so ' +
    'it cannot be mistaken for one that turned up once and never came back.</p>' +
    '<form method="post" action="/admin/applications"><div class="formrow">' +
    '<input type="hidden" name="action" value="create">' +
    '<label for="identifier">Identifier</label>' +
    '<input type="text" id="identifier" name="identifier" size="30" required ' +
    'placeholder="client_id, wtrealm, entityID or SPN">' +
    '<label for="newname">Name</label>' +
    '<input type="text" id="newname" name="name" size="18" placeholder="optional">' +
    '<label for="newkind">Kind</label>' +
    '<select id="newkind" name="kind">' +
    '<option value="">unstated</option>' +
    applications.KINDS.map(function (one) {
      return '<option value="' + esc(one.kind) + '">' + esc(one.label) + '</option>';
    }).join('') +
    '</select>' +
    '<button type="submit">Add</button>' +
    '</div></form>' +
    '<p class="note"><strong>One entry per identifier, whatever protocol brought it.</strong> ' +
    'The key is the identifier exactly as it arrived &mdash; not lower-cased and not ' +
    'namespaced by protocol &mdash; so an application appearing under one name in two ' +
    'protocols is one row with two kinds rather than two rows. That is the same rule that ' +
    'makes <code>alice</code>, <code>urn:sts-mock:user:alice</code> and ' +
    '<code>alice@REALM</code> one person on the users page.</p>' +
    '<p class="note"><strong>Sessions and Users are counts of CHANGES, not of distinct ' +
    'sets.</strong> The ids themselves are deliberately not kept on the entry &mdash; an ' +
    'application used by two thousand people would otherwise carry two thousand values ' +
    '&mdash; so the count moves when the id differs from the last one recorded. Right for ' +
    'the ordinary case, and it undercounts somebody alternating between two applications.</p>' +
    APPLICATIONS_CAVEAT + APPLICATIONS_LINKS;

  log.debug("Leaving applicationsListPage(). " + paged.shown.length + " row(s) of " +
            filtered.length + " matched.");
  return {
    inner: inner,
    json: {
      applicationCount: all.length, matched: filtered.length, shown: paged.shown.length,
      registered: registeredCount,
      filter: { q: wantedText || null, kind: wantedKind || null },
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      container: applications.containerDn ? applications.containerDn() : null,
      max: applications.maxApplications ? applications.maxApplications() : null,
      kinds: applications.KINDS,
      applications: paged.shown
    }
  };
}

// The drill-down. Its one list is the ATTRIBUTE table, which is paged under a
// name of its own (`attributesPage`) rather than the bare `page` — the
// convention pagingOf()'s header describes for a view that holds more than the
// list views do, and the shape to grow into when this page gains a second list.
function applicationDetailPage(req, identifier) {
  log.debug("Entering applicationDetailPage(). identifier=" + identifier);
  // THE LIST THE READER CAME FROM, carried on every form on this page as one
  // opaque field. A form POST answers with a redirect, and a redirect built from
  // the identifier alone lands back here with the list state gone — so the
  // breadcrumb above would then offer the top of an unfiltered list to somebody
  // who arrived from page 3 of a filter. It is one field rather than four because
  // an action reads its own body by name, and `q` or `kind` loose in there is a
  // field an action added later could pick up by accident. The handler REBUILDS a
  // query from it through listViewOf()'s whitelist rather than echoing it, which
  // is what backTo() does with the tokens page's and for the same reason: a
  // redirect target taken out of a request body is an open redirect, and one
  // carrying a newline is a header injection.
  const carryBack = '<input type="hidden" name="back" value="' +
    esc(queryWith(listViewOf('/admin/applications', req.query), {})) + '">';
  const row = applications.get(identifier);
  if (!row) {
    log.debug("Leaving applicationDetailPage(). No such application.");
    return {
      inner: messagesOf(req) +
        '<p class="warn">No application called <code>' + esc(identifier) + '</code> is ' +
        'recorded here. That is not the same as one this service has refused: an entry ' +
        'appears the first time an identifier is ACCEPTED, so a client whose every request ' +
        'was turned away has none.</p>' + APPLICATIONS_LINKS,
      json: { found: false, identifier: identifier }
    };
  }
  // EVERY attribute the entry carries, operational ones and entryDN included.
  // This used to be the schema half minus the twelve names applications.js reads
  // into named members, under a heading that said "every attribute the entry
  // carries" — so objectClass, cn, appIdentifier, both timestamps and the DN
  // itself were all missing from the one table on this service whose whole job
  // is to be complete.
  const attributeRows = Object.keys(row.attributes).sort().map(function (name) {
    const value = row.attributes[name];
    return { name: name, values: Array.isArray(value) ? value : [String(value)],
             operational: (row.operational || []).indexOf(name) >= 0 };
  });
  const paged = pagedRows(req.query, attributeRows,
                          { name: 'attributes', noun: 'attributes' });
  const paging = paged.paging;
  const nav = pageNav('/admin/applications', pageParamsOf(req.query), paging);

  const attrHtml = paged.shown.map(function (attr) {
    // What each attribute MEANS rather than only what it holds. The registry's
    // own table is the first answer and is the same table the entry was written
    // from — a second description here would be the one that went stale — and
    // applicationAttributeNote() carries the other three cases.
    const note = applicationAttributeNote(attr.name, attr.operational);
    return '<tr><td><code>' + esc(attr.name) + '</code>' +
      (note.sensitive ? ' <span class="state-revoked">credential</span>' : '') +
      (attr.operational
        ? ' <span class="state-none" title="An operational attribute. A search returns it ' +
          'only when it is asked for by name (RFC 4511 section 4.5.1.8) — this dump shows ' +
          'it always.">(operational)</span>'
        : '') +
      '</td><td>' + attr.values.map(function (v) {
        return '<code>' + esc(v) + '</code>';
      }).join('<br>') + '</td><td class="sub">' + esc(note.text) + '</td></tr>';
  }).join('');

  const inner = messagesOf(req) +
    '<h2><code>' + esc(row.identifier) + '</code></h2>' +
    '<div class="tiles">' +
    tile(row.authentications, 'Authentications') +
    tile(row.sessions, 'Sessions') +
    tile(row.users, 'Users') +
    tile(row.registered ? 'yes' : 'no', 'Registered') +
    '</div>' +
    '<table><tr><th>Thing</th><th>Value</th></tr>' +
    // FIRST, because it is the thing this page could not previously answer:
    // where in the tree this application lives. The registry is the directory,
    // so the DN is what an ldapsearch or an ldapmodify is aimed at, and a
    // console that showed only the cn made an operator reconstruct it.
    '<tr><td>Distinguished name</td><td>' + (row.dn
      ? '<code>' + esc(row.dn) + '</code>' +
        (row.identifier === row.dnLabel ? '' :
          '<div class="sub">The RDN is a digest &mdash; <code>' + esc(row.identifier) +
          '</code> is longer than 64 characters, which is not a readable RDN. ' +
          '<code>appIdentifier</code> is the identity, not the <code>cn</code>.</div>')
      : '<span class="state-none">no directory is loaded in this process, so there is ' +
        'no entry and no registry</span>') + '</td></tr>' +
    '<tr><td>Name</td><td>' + esc(row.name) + '</td></tr>' +
    '<tr><td>Kind</td><td>' + kindCells(row.kinds) + '</td></tr>' +
    '<tr><td>Protocols</td><td>' + esc(row.protocols.join(', ')) + '</td></tr>' +
    '<tr><td>First seen</td><td><code>' + esc(row.firstSeen) + '</code></td></tr>' +
    '<tr><td>Last seen</td><td><code>' + esc(row.lastSeen) + '</code></td></tr>' +
    '<tr><td>How it got here</td><td>' + (row.descriptions.length
      ? row.descriptions.map(function (d) { return esc(d); }).join('<br>')
      : '<span class="state-none">nothing recorded</span>') + '</td></tr>' +
    '</table>' +
    '<h2>Its directory entry</h2>' +
    '<p class="sub">Every attribute the entry carries &mdash; the operational ones and ' +
    '<code>entryDN</code> included, which a SEARCH would return only when asked for by ' +
    'name (RFC 4511 section 4.5.1.8) &mdash; with what each one is. This IS the entry ' +
    '&mdash; the registry is the <code>ou=applications</code> container and nothing ' +
    'caches it &mdash; so an <code>ldapmodify</code> shows here on the next refresh, and ' +
    'changes what RFC 9700 mode enforces at the same moment.</p>' +
    (row.dn
      ? '<p class="sub"><code>' + esc(row.dn) + '</code>' +
        (row.createdAt ? ' &middot; created <code>' + esc(row.createdAt) + '</code>' : '') +
        (row.modifiedAt ? ' &middot; last written <code>' + esc(row.modifiedAt) +
                          '</code>' : '') +
        (row.origin ? ' &middot; written by <code>' + esc(row.origin) + '</code>' : '') +
        '</p>'
      : '') +
    nav +
    '<table><tr><th>Attribute</th><th>Value</th><th>What it is</th></tr>' +
    // Reachable only where no directory is loaded in this process. Every real
    // entry carries objectClass, cn, appIdentifier and its two timestamps at the
    // least, so "no attributes" is now a statement about the STORE rather than
    // about this application — which is what it says.
    (attrHtml || '<tr><td colspan="3">No directory is loaded in this process, so there ' +
     'is no <code>ou=applications</code> container and no entry to show. This module ' +
     'keeps no store of its own on purpose.</td></tr>') +
    '</table>' +
    nav +

    '<h2>Change what it is allowed to do</h2>' +
    '<p class="note">These write the same entry an <code>ldapmodify</code> writes, through the ' +
    'same functions &mdash; the console is a set of controls in front of this registry and not ' +
    'a second copy of it. A change here is what RFC 9700 mode enforces on the very next ' +
    'request: add to <code>oauthRedirectUri</code> and that URI is accepted by exact match, set ' +
    '<code>oauthTokenEndpointAuthMethod</code> to <code>none</code> and the client becomes ' +
    'public, so PKCE is required of it and its secret stops being checked.</p>' +
    '<form method="post" action="/admin/applications">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="set">' +
    '<input type="hidden" name="application" value="' + esc(row.identifier) + '">' +
    '<label for="setattr">Set</label>' +
    '<select id="setattr" name="attribute">' + editableOptions('set', '') + '</select>' +
    '<label for="setval">to</label>' +
    '<input type="text" id="setval" name="value" size="34" placeholder="empty clears it">' +
    '<button type="submit">Set</button>' +
    '</div></form>' +
    '<form method="post" action="/admin/applications">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="add">' +
    '<input type="hidden" name="application" value="' + esc(row.identifier) + '">' +
    '<label for="addattr">Add to</label>' +
    '<select id="addattr" name="attribute">' + editableOptions('multi', 'oauthRedirectUri') +
    '</select>' +
    '<label for="addval">the value</label>' +
    '<input type="text" id="addval" name="value" size="34" required>' +
    '<button type="submit">Add</button>' +
    '</div></form>' +
    '<form method="post" action="/admin/applications">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="remove">' +
    '<input type="hidden" name="application" value="' + esc(row.identifier) + '">' +
    '<label for="remattr">Remove from</label>' +
    '<select id="remattr" name="attribute">' + editableOptions('multi', 'oauthRedirectUri') +
    '</select>' +
    '<label for="remval">the value</label>' +
    '<input type="text" id="remval" name="value" size="34" required>' +
    '<button type="submit">Remove</button>' +
    '</div></form>' +
    '<p class="note"><strong>What these will not change, and why.</strong> The counters, the ' +
    'first and last sighting, the kinds and the protocols are DERIVED &mdash; they are what ' +
    'happened rather than what this application may do &mdash; and a form that could rewrite ' +
    'them would make this page lie about the service\'s own behaviour, in a way ' +
    'indistinguishable from the recording being broken. <code>ldapmodify</code> still reaches ' +
    'every one of them: an operator with an LDAP client is doing something deliberate, and ' +
    'refusing them HERE is the difference between offering an operation and merely not ' +
    'preventing it. <code>appRegistrationJson</code> is not offered either &mdash; edit the ' +
    'attributes beside it instead, which is what the registration is rebuilt from.</p>' +

    '<h2>Take it out of the registry</h2>' +
    (row.registered
      ? '<form method="post" action="/admin/applications">' + carryBack + '<div class="formrow">' +
        '<input type="hidden" name="action" value="revoke-registration">' +
        '<input type="hidden" name="application" value="' + esc(row.identifier) + '">' +
        '<button type="submit">Revoke the RFC 7591 registration</button>' +
        '<span class="sub">The entry and its history stay; the client_secret, the registration ' +
        'access token and the registration itself go. Afterwards RFC 9700 mode treats it as an ' +
        'unregistered, public client.</span>' +
        '</div></form>'
      : '<p class="note">It has no RFC 7591 registration to revoke &mdash; it is an identifier ' +
        'this service has seen rather than a client that registered, which RFC 9700 mode ' +
        'already treats as public.</p>') +
    '<form method="post" action="/admin/applications">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="forget">' +
    '<input type="hidden" name="application" value="' + esc(row.identifier) + '">' +
    '<button type="submit" class="danger">Delete this entry</button>' +
    '<span class="sub">The only control here that LOSES a fact: the entry goes and takes its ' +
    row.authentications + ' recorded authentication(s) with it. It will reappear, empty, the ' +
    'next time this identifier is accepted by a protocol.</span>' +
    '</div></form>' +
    APPLICATIONS_CAVEAT +
    '<p class="sub"><a href="' +
    esc('/admin/applications' + queryWith(listViewOf('/admin/applications', req.query), {})) +
    '">back to the list</a> &middot; ' +
    '<a href="/ldap/applications">the registry as the directory sees it</a></p>';

  log.debug("Leaving applicationDetailPage(). " + paged.shown.length + " attribute row(s).");
  return {
    inner: inner,
    json: Object.assign({ found: true }, row, {
      attributesShown: paged.shown,
      attributesPaging: pagingJson(paging)
    })
  };
}

function applicationsView(req) {
  log.debug("Entering applicationsView().");
  const wanted = String(req.query.application || '').trim();
  if (wanted) {
    const detail = applicationDetailPage(req, wanted);
    log.debug("Leaving applicationsView(). The drill-down.");
    return { json: detail.json, inner: detail.inner, title: 'Application ' + wanted,
             up: upTo('/admin/applications', wanted,
                      listViewOf('/admin/applications', req.query)) };
  }
  const list = applicationsListPage(req);
  log.debug("Leaving applicationsView(). The list.");
  return { json: list.json, inner: list.inner, title: 'Applications' };
}

app.get('/admin/applications', function (req, res) {
  log.debug("Entering the admin applications page.");
  const view = applicationsView(req);
  respond(req, res, view.json, view.title, '/admin/applications', view.inner, view.up);
  log.debug("Leaving the admin applications page. " + view.title + ".");
});

// ---------------------------------------------------------------------------
// GET /admin/authorization-servers, POST /admin/authorization-servers
//
// RFC 9700 section 2.6 asks an authorization server to PUBLISH its metadata so
// that clients stop hard-coding security capabilities. This page is the other
// side of that: it decides what the published document SAYS, per authorization
// server, so that a client which reads the metadata can be shown reading it —
// and a client which does not can be shown not to.
//
// **A profile changes the document and not the endpoints**, and the page says so
// three times because it is the one thing here that could mislead badly.
// Everywhere else in this service a document disagreeing with the code is a
// defect — /sts-metadata exists to report exactly that — and here it is the
// feature. So every view computes the DRIFT: which overridden members disagree
// with what this service would actually publish, and which removals hide
// something real.
// ---------------------------------------------------------------------------
const AS_CAVEAT =
  '<p class="note"><strong>What a document says is what that authorization server DOES.</strong> ' +
  'Advertise <code>code_challenge_methods_supported: ["S256"]</code> here and this server\'s own ' +
  'authorization endpoint refuses <code>plain</code> — at <code>/{id}/oauth2/authorize</code>, ' +
  'and nowhere else. The members marked <em>enforced</em> below drive behaviour; the rest are ' +
  'published and cannot be made true by this service, which is still useful (a document a ' +
  'client did not expect is a client error path worth running) and is listed as <em>drift</em> ' +
  'so that nobody discovers it the hard way.</p>' +
  '<p class="note"><strong>Every authorization server starts equal.</strong> A new one — or one ' +
  'created by somebody simply asking for it — has exactly the capabilities the default server ' +
  'has, and differs only where it has been made to. <strong>Every client may use every one of ' +
  'them</strong>: nothing here restricts a client to a server, and ' +
  '<a href="/admin/applications">the applications page</a> records which ones each client has ' +
  'actually used. What does NOT cross between them is a credential — an authorization code ' +
  'issued by one is refused at another\'s token endpoint.</p>';

const AS_LINKS =
  '<p class="sub"><a href="/.well-known/oauth-authorization-server">the default RFC 8414 ' +
  'document</a> &middot; <a href="/.well-known/openid-configuration">the default OpenID ' +
  'Provider Configuration</a> &middot; <a href="/admin/applications">the clients that read ' +
  'them</a></p>';

function asDriftRows(id) {
  // The document this service would publish for THIS profile if the profile
  // said nothing — built from the same function the endpoints serve, so the
  // comparison cannot go stale as that document grows members. `truthFor()`
  // gives it a request-shaped object because asMetadata() derives every URL in
  // it from the one the request arrived on.
  return authorizationServers.driftOf(id, oauth2.asMetadata(asTruthRequest()));
}

// A request-shaped stand-in, so the document can be built outside a request.
// The host is this service's own default, which is what /admin/config and
// /sts-metadata already assume when they name a URL: the console is being read
// by somebody who reached this process, and the comparison is about MEMBERS
// rather than about hostnames.
function asTruthRequest() {
  return {
    protocol: config.value('global.https') ? 'https' : 'http',
    get: function (name) {
      return String(name).toLowerCase() === 'host'
        ? 'localhost:' + config.value('global.port') : '';
    },
    query: {}
  };
}

function asAction(body) {
  log.debug("Entering asAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const id = String(body.profile || body.id || '').trim();

  if (action === 'create') {
    const result = authorizationServers.create({
      id: id, label: String(body.label || ''), description: String(body.description || '')
    });
    log.debug("Leaving asAction(). create " + (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) return result;
    return { ok: true, profile: result.profile,
             message: 'The "' + result.profile.id + '" authorization server is published at ' +
                      result.profile.urls.oauth + ' and ' + result.profile.urls.oidc + '. It ' +
                      'has no overrides yet, so both documents say exactly what this service ' +
                      'says about itself — which is the right place to start from.' };
  }
  if (action === 'set') {
    const result = authorizationServers.setMember(id, body.member, body.value);
    log.debug("Leaving asAction(). set " + (result.ok ? 'ok' : 'refused') + ".");
    return result;
  }
  if (action === 'remove') {
    const result = authorizationServers.removeMember(id, body.member);
    log.debug("Leaving asAction(). remove " + (result.ok ? 'ok' : 'refused') + ".");
    return result;
  }
  if (action === 'reset') {
    const result = authorizationServers.resetMember(id, body.member);
    log.debug("Leaving asAction(). reset " + (result.ok ? 'ok' : 'refused') + ".");
    return result;
  }
  if (action === 'delete') {
    const result = authorizationServers.remove(id);
    log.debug("Leaving asAction(). delete " + (result.ok ? 'ok' : 'refused') + ".");
    return result;
  }
  log.debug("Leaving asAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The five are: create, set, ' +
                               'remove, reset, delete.'] };
}

function asMemberOptions(selected) {
  return authorizationServers.GROUPS.map(function (group) {
    const inGroup = authorizationServers.MEMBERS.filter(function (row) {
      return row.group === group;
    });
    return '<optgroup label="' + esc(group) + '">' + inGroup.map(function (row) {
      return '<option value="' + esc(row.name) + '"' +
        (row.name === selected ? ' selected' : '') + '>' + esc(row.name) + '</option>';
    }).join('') + '</optgroup>';
  }).join('');
}

function asListPage(req) {
  log.debug("Entering asListPage().");
  const all = authorizationServers.list();
  const paged = pagedRows(req.query, all, { noun: 'authorization servers' });
  const paging = paged.paging;
  const nav = pageNav('/admin/authorization-servers',
                      { per: req.query.per ? paging.perPage : '' }, paging);

  const listView = listViewOf('/admin/authorization-servers', req.query);
  const rows = paged.shown.map(function (row) {
    const drift = asDriftRows(row.id);
    // The link carries the list AS IT IS BEING VIEWED, which is what lets the
    // trail on the other side come back to this page of this filter rather than to
    // the top of everything. See listViewOf().
    const href = '/admin/authorization-servers' + queryWith(listView, { profile: row.id });
    return '<tr><td><a href="' + esc(href) + '"><code>' + esc(row.id) + '</code></a></td>' +
      '<td>' + esc(row.label || '') + '</td>' +
      '<td class="num">' + Object.keys(row.overrides).length + '</td>' +
      '<td class="num">' + row.removed.length + '</td>' +
      '<td class="num">' + (drift.length
        ? '<span class="state-expired" title="Members whose published value disagrees with ' +
          'what this service would publish.">' + drift.length + '</span>'
        : '<span class="state-none">0</span>') + '</td>' +
      '<td><code>' + esc(row.urls.authorize) + '</code><br><code>' + esc(row.urls.token) +
      '</code><div class="sub">metadata at <code>' + esc(row.urls.oidc) + '</code></div>' +
      '</td>' +
      '<td>' + (row.autoCreated
        ? '<span class="sub">asked for</span>' : '<span class="sub">configured</span>') +
      '</td><td class="num">' + esc(row.seen) + '</td></tr>';
  }).join('');

  const inner = messagesOf(req) +
    '<div class="tiles">' +
    tile(all.length, 'Profiles') +
    tile(all.reduce(function (n, r) { return n + Object.keys(r.overrides).length; }, 0), 'Overrides') +
    tile(all.reduce(function (n, r) { return n + asDriftRows(r.id).length; }, 0), 'Drifting members') +
    '</div>' +
    '<p class="note"><strong>One process, several authorization servers.</strong> The path ' +
    'component the two discovery shapes already carry now selects a CONFIGURATION as well as ' +
    'an issuer identifier &mdash; RFC 8414 section 3.1 <em>inserts</em> it after the well-known ' +
    'segment and OpenID Connect Discovery section 4 <em>appends</em> the well-known segment to ' +
    'it, which is the commonest reason a discovery fetch 404s, and this service has answered ' +
    'both for a long time. <strong>A path nobody has configured publishes the document this ' +
    'service always published</strong>, so nothing that worked before this page existed ' +
    'behaves differently.</p>' +
    nav +
    '<table><tr><th>Authorization server</th><th>Label</th><th class="num">Overrides</th>' +
    '<th class="num">Removed</th><th class="num">Drift</th><th>Its endpoints</th>' +
    '<th>Came from</th><th class="num">Asked for</th></tr>' +
    (rows || '<tr><td colspan="8">No authorization server has been named. Every discovery URL answers with ' +
             'the document this service builds for itself, which is what RFC 9700 section 2.6 ' +
             'asks for &mdash; these are for when you need it to say something else.</td></tr>') +
    '</table>' +
    nav +
    '<h2>Add an authorization server</h2>' +
    '<form method="post" action="/admin/authorization-servers"><div class="formrow">' +
    '<input type="hidden" name="action" value="create">' +
    '<label for="asid">Id</label>' +
    '<input type="text" id="asid" name="id" size="18" required placeholder="tenant1">' +
    '<label for="aslabel">Label</label>' +
    '<input type="text" id="aslabel" name="label" size="20" placeholder="optional">' +
    '<label for="asdesc">Note</label>' +
    '<input type="text" id="asdesc" name="description" size="28" placeholder="what it is for">' +
    '<button type="submit">Add</button>' +
    '</div></form>' +
    '<p class="note">The id is a single URL path segment &mdash; letters, digits, dot, dash, ' +
    'underscore or tilde &mdash; because it has to appear in a URL without being escaped. One ' +
    'that had to be escaped would be one nobody could find again.</p>' +
    AS_CAVEAT + AS_LINKS;

  log.debug("Leaving asListPage(). " + paged.shown.length + " row(s).");
  return {
    inner: inner,
    json: {
      profileCount: all.length, shown: paged.shown.length,
      page: paging.page, pages: paging.pages, perPage: paging.perPage,
      firstRow: paging.firstRow, lastRow: paging.lastRow,
      members: authorizationServers.MEMBERS,
      authorizationServers: paged.shown.map(function (row) {
        return Object.assign({}, row, { drift: asDriftRows(row.id) });
      })
    }
  };
}

function asDetailPage(req, id) {
  log.debug("Entering asDetailPage(). id=" + id);
  // THE LIST THE READER CAME FROM, carried on every form on this page as one
  // opaque field. A form POST answers with a redirect, and a redirect built from
  // the identifier alone lands back here with the list state gone — so the
  // breadcrumb above would then offer the top of an unfiltered list to somebody
  // who arrived from page 3 of a filter. It is one field rather than four because
  // an action reads its own body by name, and `q` or `kind` loose in there is a
  // field an action added later could pick up by accident. The handler REBUILDS a
  // query from it through listViewOf()'s whitelist rather than echoing it, which
  // is what backTo() does with the tokens page's and for the same reason: a
  // redirect target taken out of a request body is an open redirect, and one
  // carrying a newline is a header injection.
  const carryBack = '<input type="hidden" name="back" value="' +
    esc(queryWith(listViewOf('/admin/authorization-servers', req.query), {})) + '">';
  const profile = authorizationServers.get(id);
  if (!profile) {
    log.debug("Leaving asDetailPage(). No such profile.");
    return {
      inner: messagesOf(req) +
        '<p class="warn">There is no authorization server profile called <code>' + esc(id) +
        '</code>. Its discovery URLs still answer &mdash; with the document this service ' +
        'builds and the issuer taken from the path &mdash; because an unconfigured path ' +
        'component has always been served that way rather than 404\'d.</p>' + AS_LINKS,
      json: { found: false, id: id }
    };
  }
  const drift = asDriftRows(id);
  // The document this authorization server publishes, which is the same object
  // its endpoints read their capabilities out of.
  const capabilities = authorizationServers.capabilitiesOf(id, oauth2.asMetadata(asTruthRequest(), true));
  const memberRows = Object.keys(profile.overrides).sort().map(function (member) {
    const spec = authorizationServers.MEMBERS.filter(function (row) {
      return row.name === member;
    })[0];
    const bad = drift.filter(function (d) { return d.member === member; })[0];
    return '<tr><td><code>' + esc(member) + '</code></td>' +
      '<td><code>' + esc(JSON.stringify(profile.overrides[member])) + '</code></td>' +
      '<td>' + (bad
        ? '<span class="state-expired">' + esc(bad.kind) + '</span><div class="sub">' +
          esc(bad.what) + '</div>'
        : '<span class="state-valid">agrees</span>') + '</td>' +
      '<td class="sub">' + esc(spec ? spec.what : 'Not a member this service recognises — ' +
        'which is allowed, and is half the point: publishing something a client did not ' +
        'expect is what this page is for.') + '</td>' +
      '<td><form method="post" action="/admin/authorization-servers">' + carryBack +
      '<input type="hidden" name="action" value="reset">' +
      '<input type="hidden" name="profile" value="' + esc(id) + '">' +
      '<input type="hidden" name="member" value="' + esc(member) + '">' +
      '<button type="submit">Reset</button></form></td></tr>';
  }).join('');

  const removedRows = profile.removed.map(function (member) {
    return '<tr><td><code>' + esc(member) + '</code></td><td class="sub">Not published at all. ' +
      'A client reading this document cannot tell that this server supports it &mdash; which ' +
      'is not the same as learning that it does not, and is the difference RFC 9700 section ' +
      '2.6 is arguing about.</td>' +
      '<td><form method="post" action="/admin/authorization-servers">' + carryBack +
      '<input type="hidden" name="action" value="reset">' +
      '<input type="hidden" name="profile" value="' + esc(id) + '">' +
      '<input type="hidden" name="member" value="' + esc(member) + '">' +
      '<button type="submit">Put it back</button></form></td></tr>';
  }).join('');

  const inner = messagesOf(req) +
    '<h2><code>' + esc(profile.id) + '</code>' +
    (profile.label ? ' &mdash; ' + esc(profile.label) : '') + '</h2>' +
    (profile.description ? '<p class="note">' + esc(profile.description) + '</p>' : '') +
    '<table><tr><th>Thing</th><th>Value</th></tr>' +
    '<tr><td>RFC 8414 document</td><td><a href="' + esc(profile.urls.oauth) + '"><code>' +
    esc(profile.urls.oauth) + '</code></a></td></tr>' +
    '<tr><td>OpenID Provider Configuration</td><td><a href="' + esc(profile.urls.oidc) +
    '"><code>' + esc(profile.urls.oidc) + '</code></a></td></tr>' +
    '<tr><td>Last changed</td><td><code>' + esc(profile.changedAt) + '</code></td></tr>' +
    '</table>' +
    (drift.length
      ? '<div class="warn"><strong>' + drift.length + ' member(s) of this document do not ' +
        'describe this service.</strong> That is allowed and is often the point &mdash; but ' +
        'a client configured from this document will behave as though these were true.</div>'
      : '<div class="ok">Every member of this document agrees with what this service would ' +
        'publish. A client configured from it is configured correctly.</div>') +
    '<h2>What this authorization server does</h2>' +
    '<p class="sub">Its effective capabilities — the defaults every authorization server here ' +
    'starts with, plus whatever this one has been given. This IS the document it publishes and ' +
    'it IS what its endpoints enforce; there is no second table that could disagree with it.</p>' +
    '<table><tr><th>Capability</th><th>This server</th><th>Enforced</th></tr>' +
    authorizationServers.MEMBERS.filter(function (row) { return row.enforces; })
      .map(function (row) {
        const value = capabilities[row.name];
        return '<tr><td><code>' + esc(row.name) + '</code></td>' +
          '<td>' + (value === undefined
            ? '<span class="state-none">not published — the check does not run</span>'
            : '<code>' + esc(JSON.stringify(value)) + '</code>') + '</td>' +
          '<td class="sub">' + esc(row.enforces) + '</td></tr>';
      }).join('') +
    '</table>' +
    '<h2>Overridden members</h2>' +
    '<table><tr><th>Member</th><th>Published as</th><th>Agreement</th><th>What it is</th>' +
    '<th></th></tr>' +
    (memberRows || '<tr><td colspan="5">Nothing is overridden, so this document says exactly ' +
                   'what this service says about itself.</td></tr>') + '</table>' +
    (removedRows
      ? '<h2>Removed members</h2><table><tr><th>Member</th><th>What that means</th><th></th></tr>' +
        removedRows + '</table>'
      : '') +
    '<h2>Publish a member</h2>' +
    '<p class="note">The value is read as JSON first and as a plain string if that fails, so ' +
    '<code>["S256"]</code> is a list, <code>false</code> is a boolean and ' +
    '<code>https://example.com/token</code> is a string. <strong>Any member name is accepted</strong> ' +
    '&mdash; the list below is help rather than a schema, and one this service has never heard ' +
    'of is published just the same.</p>' +
    '<form method="post" action="/admin/authorization-servers">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="set">' +
    '<input type="hidden" name="profile" value="' + esc(id) + '">' +
    '<label for="asmember">Member</label>' +
    '<select id="asmember" name="member">' + asMemberOptions('') + '</select>' +
    '<label for="asvalue">as</label>' +
    '<input type="text" id="asvalue" name="value" size="36" placeholder=\'["S256"]\'>' +
    '<button type="submit">Publish</button>' +
    '</div></form>' +
    '<form method="post" action="/admin/authorization-servers">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="set">' +
    '<input type="hidden" name="profile" value="' + esc(id) + '">' +
    '<label for="asother">Or any member</label>' +
    '<input type="text" id="asother" name="member" size="30" required ' +
    'placeholder="a name this service has never heard of">' +
    '<label for="asothervalue">as</label>' +
    '<input type="text" id="asothervalue" name="value" size="26">' +
    '<button type="submit">Publish</button>' +
    '</div></form>' +
    '<h2>Stop publishing a member</h2>' +
    '<form method="post" action="/admin/authorization-servers">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="remove">' +
    '<input type="hidden" name="profile" value="' + esc(id) + '">' +
    '<label for="asrem">Remove</label>' +
    '<select id="asrem" name="member">' + asMemberOptions('code_challenge_methods_supported') +
    '</select>' +
    '<button type="submit">Remove it from the document</button>' +
    '<span class="sub">Different from resetting it: reset undoes an override, this publishes ' +
    'an ABSENCE.</span>' +
    '</div></form>' +
    '<h2>Delete this authorization server</h2>' +
    '<form method="post" action="/admin/authorization-servers">' + carryBack + '<div class="formrow">' +
    '<input type="hidden" name="action" value="delete">' +
    '<input type="hidden" name="profile" value="' + esc(id) + '">' +
    '<button type="submit" class="danger">Delete</button>' +
    '<span class="sub">The two URLs go on answering &mdash; with this service\'s own document ' +
    '&mdash; because an unconfigured path has always been served that way.</span>' +
    '</div></form>' +
    AS_CAVEAT + AS_LINKS;

  log.debug("Leaving asDetailPage(). " + drift.length + " drifting member(s).");
  return { inner: inner, json: Object.assign({ found: true }, profile, { drift: drift }) };
}

function authorizationServersView(req) {
  log.debug("Entering authorizationServersView().");
  const wanted = String(req.query.profile || '').trim();
  if (wanted) {
    const detail = asDetailPage(req, wanted);
    log.debug("Leaving authorizationServersView(). The drill-down.");
    return { json: detail.json, inner: detail.inner,
             title: 'Authorization server ' + wanted,
             up: upTo('/admin/authorization-servers', wanted,
                      listViewOf('/admin/authorization-servers', req.query)) };
  }
  const list = asListPage(req);
  log.debug("Leaving authorizationServersView(). The list.");
  return { json: list.json, inner: list.inner, title: 'Authorization servers' };
}

app.get('/admin/authorization-servers', function (req, res) {
  log.debug("Entering the admin authorization servers page.");
  const view = authorizationServersView(req);
  respond(req, res, view.json, view.title, '/admin/authorization-servers', view.inner,
          view.up);
  log.debug("Leaving the admin authorization servers page.");
});

app.post('/admin/authorization-servers', function (req, res) {
  log.debug("Entering the admin authorization servers action endpoint.");
  const body = parseBody(req);
  const result = asAction(body);
  const id = String(body.profile || body.id || '').trim();
  // The list state the form carried, for the reason the applications action gives.
  const listView = listViewFromBack('/admin/authorization-servers', body.back);
  const back = id && result.ok !== false
    ? '/admin/authorization-servers' + queryWith(listView, { profile: id })
    : '/admin/authorization-servers' + queryWith(listView, {});
  respondToAction(req, res, back, result);
  log.debug("Leaving the admin authorization servers action endpoint.");
});

app.get('/admin/groups', function (req, res) {
  log.debug("Entering the admin groups page.");
  const view = groupsView(req);
  respond(req, res, view.json, view.title, '/admin/groups', view.inner, view.up);
  log.debug("Leaving the admin groups page. " + view.title + ".");
});

// ---------------------------------------------------------------------------
// GET /admin/claims, POST /admin/claims
// ---------------------------------------------------------------------------
// `names` is the second argument for the same reason vcAction() has one: a list
// that may appear more than once in a form body is not something
// helpers.parseBody() can answer, so the caller reads it with listField() and
// hands it in. It is only read by the `attributes` action; the other six ignore
// it.
function claimsAction(body, names) {
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

  // ------------------------------------------------------------------------
  // The three that act on the DIRECTORY ATTRIBUTE half of a set rather than on
  // the typed claims above.
  //
  // They are three actions and not one with a mode, because each is a different
  // thing to authorise and a different row in the audit log: `attributes`
  // carries a list somebody chose, and the other two carry nothing and mean the
  // extremes. A single action taking a list would make "select all" a caller's
  // job to construct — the whole catalogue in a POST body to say "all of them" —
  // which is a list that has to be updated every time the catalogue is.
  //
  // What the split does NOT do is make an empty `attributes` unambiguous, and it
  // is worth being plain about that rather than implying otherwise. An empty
  // list and an absent one both mean "the selection is nothing", so a caller
  // that misspells the field clears the set. Three things make that recoverable
  // rather than silent, and they are the reason it is not refused instead: the
  // reply names every attribute it `removed`, the audit log keeps a row saying
  // the same, and unticking every box and pressing Update is a legitimate way to
  // clear a set that a refusal would have to break. `attributes-clear` exists so
  // that a caller which MEANS it can say so, and so that the console's button
  // does not depend on submitting an empty form.
  //
  // The console's buttons are form posts for the same reason every other control
  // here is: app.js sets `script-src 'none'` for the whole service, so a
  // browser-side "tick every box" is not available and would not be taken if it
  // were — a server-side select-all leaves an audit row, and a scripted one
  // would leave the boxes ticked and the set unchanged until somebody pressed
  // Update.
  // ------------------------------------------------------------------------
  if (action === 'attributes') {
    const result = claimAttributes.setSelection(setId, names || [], 'select');
    log.debug("Leaving claimsAction(). attributes -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, attributes: result.attributes,
          added: result.added, removed: result.removed,
          message: 'The ' + label + ' set now carries ' + result.attributes.length +
                   ' directory attribute(s): ' + (result.attributes.join(', ') || '(none)') +
                   '. Every one of those issued from now on carries them, with the value on ' +
                   'that person\'s entry; nothing already issued changes.' }
      : result;
  }

  if (action === 'attributes-all') {
    const result = claimAttributes.selectAll(setId);
    log.debug("Leaving claimsAction(). attributes-all -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, attributes: result.attributes,
          added: result.added, removed: result.removed,
          message: 'The ' + label + ' set now carries every attribute in the catalogue — ' +
                   result.attributes.length + ' of them. That is a legitimate thing to test ' +
                   'and it makes a large token; it is not a mistake this page will correct.' }
      : result;
  }

  if (action === 'attributes-clear') {
    const result = claimAttributes.clearSelection(setId);
    log.debug("Leaving claimsAction(). attributes-clear -> ok=" + result.ok);
    return result.ok
      ? { ok: true, set: setId, attributes: [], added: [], removed: result.removed,
          message: 'The ' + label + ' set carries no directory attribute again. Removed: ' +
                   (result.removed.join(', ') || 'nothing — it was already empty') + '. The ' +
                   'typed claims on this set, if any, are untouched.' }
      : result;
  }

  log.debug("Leaving claimsAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The seven are: add, remove, ' +
                               'clear, replace, attributes, attributes-all, attributes-clear.'] };
}

app.post('/admin/claims', function (req, res) {
  log.debug("Entering the admin claims action endpoint.");
  const body = parseBody(req);
  // Two names for the list, exactly as /admin/vc takes them and for the same
  // reason: a checkbox column is one `attribute` repeated, and a JSON body
  // carries one `attributes` array. Neither spelling is wrong and refusing
  // either would make the console's own form and the API's document disagree.
  const names = listField(req, body, 'attribute').concat(listField(req, body, 'attributes'));
  const result = claimsAction(body, names);
  // Back to the page the reader was on, preview user and all: the four tables
  // show that person's values, and a redirect that dropped the parameter would
  // answer "what did that do" with somebody else's row.
  respondToAction(req, res, claimsPageUrl(req.query), result);
  log.debug("Leaving the admin claims action endpoint.");
});

// Which person the four tables show values for, and where the page sends itself
// back to. Capped because the string is echoed, and defaulted to somebody the
// directory actually holds from startup so a fresh process shows real values
// rather than an invented person nobody can look up — the same rule and the same
// default /admin/vc uses, deliberately, so the two pages preview the same person
// unless somebody says otherwise.
function claimsPreviewUser(query) {
  const asked = String((query && query.user) || 'alice').trim();
  return asked.slice(0, 64) || 'alice';
}

// The page's own URL with the preview user on it. Every form on this page posts
// to THIS rather than to the bare path, so that the 303 after an action lands
// back on the person the reader was looking at. A form that dropped the
// parameter would answer "what did that do?" with somebody else's values, which
// reads as the action having done something it did not.
function claimsPageUrl(query) {
  return '/admin/claims?user=' + encodeURIComponent(claimsPreviewUser(query));
}

// ---------------------------------------------------------------------------
// THE DIRECTORY ATTRIBUTE HALF OF ONE SET.
//
// A checkbox per attribute type in the catalogue, a column saying what it would
// put in a token for the person being previewed, and three buttons. It is
// repeated for each of the four sets rather than being one table with four
// checkbox columns, because the four sets are chosen for different reasons — an
// access token goes to a resource server and an ID Token goes to a client, and
// the interesting configuration is usually the one where they DIFFER. A single
// grid would make four independent decisions look like one, and would have to
// post all four sets at once, so changing the ID Token would rewrite the access
// token's selection as a side effect.
//
// THE THREE BUTTONS ARE THREE FORMS, and unticking a box in one of the other
// three sets' tables does nothing to this one: only the form that is submitted
// sends anything, so each Update button carries exactly its own set's boxes.
// That is worth stating because a page with four checkbox tables and one Update
// button would be the obvious design and would be wrong in the direction nobody
// notices — it would clear the three sets whose tables were rendered before the
// reader ticked anything.
// ---------------------------------------------------------------------------
function claimAttributeSection(setId, previewUser, values, pageUrl) {
  log.debug("Entering claimAttributeSection(). setId=" + setId);
  const selected = claimAttributes.selectedNames(setId);

  const rows = claimAttributes.CATALOGUE.map(function (row) {
    const on = claimAttributes.isSelected(setId, row.ldap);
    const found = values.byLdap[row.ldap.toLowerCase()];
    // `description` is the one row with no generator: this service writes it on
    // every entry itself, to record the protocols that person has used. So it is
    // the one attribute whose value is a real fact, and it is absent rather than
    // invented for somebody with no entry.
    const valueCell = found
      ? '<td><code>' + esc(found.value) + '</code></td><td>' + esc(found.source) + '</td>'
      : '<td><span class="state-none">—</span></td><td>' +
        (row.from ? 'would be generated' : 'the entry\'s own') + '</td>';
    return '<tr><td><input type="checkbox" name="attribute" value="' + esc(row.ldap) + '"' +
      (on ? ' checked' : '') + '></td>' +
      '<td><code>' + esc(row.ldap) + '</code></td>' +
      '<td>' + esc(row.schema) + '</td>' +
      '<td><code>' + esc(row.claim.join('.')) + '</code></td>' +
      valueCell + '</tr>';
  }).join('');

  log.debug("Leaving claimAttributeSection(). " + selected.length + " of " +
            claimAttributes.CATALOGUE.length + " selected.");
  return '<p class="note">' + (selected.length
      ? 'Carries ' + selected.length + ' directory attribute(s): ' + codeList(selected) + '.'
      : 'Carries no directory attribute. Tick some and press Update.') + '</p>' +
    '<form method="post" action="' + esc(pageUrl) + '">' +
    '<input type="hidden" name="action" value="attributes">' +
    '<input type="hidden" name="set" value="' + esc(setId) + '">' +
    '<table><tr><th>In</th><th>LDAP attribute</th><th>Defined by</th>' +
    '<th>' + (setId === 'saml2' || setId === 'saml11' ? 'Attribute name' : 'Claim') + '</th>' +
    '<th>For ' + esc(previewUser) + '</th><th>Source</th></tr>' +
    rows + '</table>' +
    '<div class="formrow"><button>Update</button>' +
    '<span class="note">The ticked boxes become the whole selection for this set: unticking is ' +
    'how an attribute is removed.</span></div></form>' +
    '<div class="formrow">' +
    '<form method="post" action="' + esc(pageUrl) + '" class="inline">' +
    '<input type="hidden" name="action" value="attributes-all">' +
    '<input type="hidden" name="set" value="' + esc(setId) + '">' +
    '<button class="secondary">Select all</button></form> ' +
    '<form method="post" action="' + esc(pageUrl) + '" class="inline">' +
    '<input type="hidden" name="action" value="attributes-clear">' +
    '<input type="hidden" name="set" value="' + esc(setId) + '">' +
    '<button class="secondary">Delete all</button></form>' +
    '<span class="note">Both act immediately — there is no script on this page, so these are ' +
    'form posts and not a way of ticking the boxes above.</span></div>';
}

// One set, rendered: what is in it, a way to remove each, and a way to add another.
// The three sets differ in the extra field each needs, which is why the form is
// built from the set's kind rather than being one form four times.
function claimSetSection(setId, previewUser, values, pageUrl) {
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
      '<td><form method="post" action="' + esc(pageUrl) + '" class="inline">' +
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
    // The two halves in this order because the second is the one that changes
    // per person, and a reader who has just pressed Update wants to see the
    // table they pressed it under rather than scroll past a form they did not
    // touch. The headings say which half is which: they are configured
    // separately, audited separately, and only one of them can be wrong in a way
    // the directory explains.
    '<p class="sub">Typed claims &mdash; a name and a value, the same for everybody.</p>' +
    '<table><tr><th>Name</th>' + extraHeader + '<th>Value</th><th></th></tr>' +
    (rows || '<tr><td colspan="' + (extraHeader ? 4 : 3) + '">No custom claim is configured; ' +
             'these tokens carry only what the protocol puts in them.</td></tr>') + '</table>' +
    '<form method="post" action="' + esc(pageUrl) + '"><div class="formrow">' +
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
      ? '<form method="post" action="' + esc(pageUrl) + '" class="inline">' +
        '<input type="hidden" name="action" value="clear">' +
        '<input type="hidden" name="set" value="' + esc(setId) + '">' +
        '<button class="secondary">Clear this set</button></form>'
      : '') +
    '<p class="sub">Directory attributes &mdash; a value read off each person\'s own entry.</p>' +
    claimAttributeSection(setId, previewUser, values, pageUrl);
}

// ---------------------------------------------------------------------------
// THE GROUPS CLAIM, on the page that already answers "what will the next token
// carry".
//
// READ-ONLY here, and that is a decision rather than an omission. Its four
// settings live in config.js's table, which means /admin/config and POST
// /admin-api/config/set already change them — a second form here would be a
// second door to one setting, which is exactly the two-stores mistake this
// service keeps out of everything else. So this section reports and links; the
// parity rule (a control gets an API operation in the same commit) is satisfied
// by there being no new control.
//
// What it does add is the thing no configuration page can: what the claim WOULD
// say about the person being previewed, built by groupsOf() — the same function
// the issuance path calls — so a preview that agreed with the page and
// disagreed with the token is not possible.
// ---------------------------------------------------------------------------
function groupClaimSection(previewUser) {
  log.debug("Entering groupClaimSection(). user=" + previewUser);
  const state = groupClaims.state();
  const answer = groupClaims.groupsOf(previewUser);
  const rows = answer.groups.map(function (group) {
    // WHY this group is in the list, which is the whole of the memberOf
    // disagreement in one cell: `member` and its two siblings are the GROUP
    // saying so, memberOf is the PERSON saying so, and this directory maintains
    // neither from the other.
    const how = group.via.length
      ? group.via.map(function (name) { return '<code>' + esc(name) + '</code>'; }).join(', ')
      : '';
    const counted = group.via.length || state.memberOfCounts;
    return '<tr><td><code>' + esc(group.dn) + '</code></td>' +
      '<td>' + esc(group.cn) + '</td>' +
      '<td>' + (how || '&mdash;') +
      (group.viaMemberOf
        ? (how ? ', ' : '') + 'the person\'s own <code>memberOf</code>' +
          (state.memberOfCounts ? '' : ' <em>(not counted)</em>')
        : '') + '</td>' +
      '<td>' + (counted ? 'yes' : 'no') + '</td></tr>';
  }).join('');

  const values = answer.values.length
    ? '<p class="note">The claim <code>' + esc(state.claim) + '</code> would carry ' +
      codeList(answer.values) + '.</p>'
    : '<p class="note">No claim at all for this person &mdash; not an empty list, absent. ' +
      esc(answer.reason) + '</p>';

  log.debug("Leaving groupClaimSection(). " + answer.values.length + " value(s).");
  return '<h2>The groups claim</h2>' +
    '<p class="note">The one thing on this page that is <strong>not</strong> chosen per set: ' +
    'with <code>groups.claim</code> on, all four carry it, for anybody who is a member of a ' +
    'group in <a href="/admin/groups">the embedded directory</a>. The membership is read at the ' +
    'moment a token is minted, so an <code>ldapmodify</code> changes the next one, and somebody ' +
    'in no group gets no claim rather than an empty list &mdash; which is why this can be on by ' +
    'default without changing what an existing client receives.</p>' +

    '<div class="' + (state.enabled && !state.problem ? 'note' : 'warn') + '">' +
    (state.enabled
      ? (state.problem
          ? '<strong>On, and not arriving.</strong> ' + esc(state.problem)
          : '<strong>On.</strong> Every access token, ID Token and both SAML assertions carry ' +
            '<code>' + esc(state.claim) + '</code>, each value being ' +
            (state.valueForm === 'dn' ? 'the group\'s whole DN' : 'the group\'s <code>cn</code>') +
            '. A person\'s own <code>memberOf</code> ' +
            (state.memberOfCounts ? 'counts' : 'does NOT count') + ' as membership.')
      : '<strong>Off.</strong> No token or assertion carries a groups claim. ' +
        'Turn it on with <code>groups.claim</code>.') +
    ' Change any of it on <a href="/admin/config">the configuration page</a>: ' +
    codeList(state.settings) + '.' +
    (state.loaded ? '' : ' <strong>The embedded directory is not loaded in this process</strong>, ' +
                         'so there are no groups to read.') +
    '</div>' +

    '<div class="warn"><strong>Carrying a group is not granting one.</strong> No endpoint here ' +
    'reads this claim and nothing decides anything on it &mdash; the same sentence ' +
    '<a href="/admin/groups">the groups page</a> has always carried, and the half of it that ' +
    'changed is that a token now says so out loud.</div>' +

    '<p class="note">A typed claim above, and a ticked directory attribute above, both win over ' +
    'this one where the names collide: those were named on this page about this service, and ' +
    'this comes from a setting and a directory.</p>' +

    '<h3>What ' + esc(previewUser) + ' would get</h3>' +
    values +
    (answer.groups.length
      ? '<table><tr><th>Group</th><th>cn</th><th>Named by</th><th>Counted</th></tr>' +
        rows + '</table>'
      : '<p class="note">' + esc(previewUser) + ' is named by no group here' +
        (answer.entryFound ? '' : ', and has no entry in the directory either') + '. ' +
        'The entry would be at <code>' + esc(answer.dn) + '</code>.</p>');
}

// The four sets and the rules that govern them. The rules are in the reply and
// not only on the page because the first thing a caller of POST .../claims/add
// needs is the list of names it will refuse.
function claimsJson(previewUser) {
  log.debug("Entering claimsJson(). previewUser=" + previewUser);
  const user = previewUser || 'alice';
  const json = {
    reservedJwtClaims: stats.RESERVED_JWT_CLAIMS,
    placeholders: stats.PLACEHOLDERS,
    defaultSaml11Namespace: stats.DEFAULT_SAML11_NAMESPACE,
    // The catalogue every set chooses from, so a caller can discover the legal
    // values of `attributes` without reading this service's source or guessing
    // at LDAP spellings. `sets` says which of the four carries each, which is
    // the same fact the console's four tables draw and is answered here once
    // rather than repeated inside every set below.
    attributeCatalogue: claimAttributes.catalogueRows(),
    // Stated rather than left to be discovered, because the two halves of a set
    // are one screen apart and the precedence only shows up when both name one
    // claim.
    precedence: 'A typed claim wins over a directory attribute of the same name.',
    sets: stats.CLAIM_SET_IDS.map(function (id) {
      const preview = claimAttributes.previewFor(id, user);
      return { id: id, label: stats.CLAIM_SETS[id].label,
               claims: stats.claimSet(id),
               attributes: claimAttributes.selectedNames(id),
               // What those attributes would actually put in this set right now,
               // built by the function the ISSUANCE path calls. A caller with no
               // browser has no other way to ask "what would this issue", and a
               // preview built by a second walk of the catalogue would be a
               // preview that can disagree with the token.
               attributeClaims: preview.claims,
               attributeReport: preview.report };
    }),
    // Whether the directory holds this person at all, and what every attribute
    // in the catalogue would say about them — selected or not, so a caller can
    // see what ticking a box would do before ticking it. Read through
    // catalogueValuesFor() rather than off one of the previews above, because a
    // set with nothing selected reports no entry: that is the right answer to
    // "what does this set carry" and the wrong answer to "is this person in the
    // directory".
    preview: Object.assign({ user: user }, claimAttributes.catalogueValuesFor(user)),
    // The groups claim, which is the one thing here that is not chosen per set:
    // all four carry it or none does. Its settings are config.js's, so this is
    // a report and there is no operation beside it — POST
    // /admin-api/config/set is the door, and a second one would be a second
    // store for one setting.
    //
    // `preview` is built by the function the ISSUANCE path calls, for the
    // reason every other preview here is: a caller with no browser has no other
    // way to ask "what would this token carry", and a second walk of the
    // directory would be a preview that can disagree with the token.
    groups: Object.assign(groupClaims.state(),
                          { preview: groupClaims.groupsOf(user) })
  };
  log.debug("Leaving claimsJson(). " + json.sets.length + " set(s).");
  return json;
}

app.get('/admin/claims', function (req, res) {
  log.debug("Entering the admin claims page.");
  const setSelect = stats.CLAIM_SET_IDS.map(function (id) {
    return '<option value="' + esc(id) + '">' + esc(stats.CLAIM_SETS[id].label) + '</option>';
  }).join('');
  const previewUser = claimsPreviewUser(req.query);
  const pageUrl = claimsPageUrl(req.query);
  // ONE read of the directory and one invented persona for the whole page, not
  // one per set: the four tables show the same catalogue of values for the same
  // person, and four reads of one entry per render would be three that exist
  // only because the sections were written separately.
  const values = claimAttributes.catalogueValuesFor(previewUser);

  const inner = messagesOf(req) +
    '<p class="note">What to add to every token and assertion this service issues <em>from now ' +
    'on</em>. Nothing already issued changes — a token is a signed document and this page cannot ' +
    'reach inside one. Four sets, because the four are different vocabularies: an OAuth access ' +
    'token and an OIDC ID Token go to different readers (a resource server and a client), and SAML ' +
    '2.0 and SAML 1.1 spell an attribute differently enough that one list could not serve both.</p>' +

    '<p class="note">Each set has <strong>two halves</strong>. A <em>typed claim</em> is a name and ' +
    'a value somebody wrote here, the same for everybody except where it carries a ' +
    '<code>${placeholder}</code>. A <em>directory attribute</em> is ticked from the catalogue below ' +
    'and its value is whatever that person\'s entry under <code>ou=users</code> says — so an ' +
    '<code>ldapmodify</code> changes the next token, and an LDAP client and an OIDC client pointed ' +
    'at this service are shown the same person. That is the half worth exercising, and until now ' +
    'only a Verifiable Credential could do it.</p>' +

    '<form method="get" action="/admin/claims"><div class="formrow">' +
    '<label for="user">Show the values for</label>' +
    '<input type="text" id="user" name="user" size="20" value="' + esc(previewUser) + '">' +
    '<button class="secondary">Show</button>' +
    '<span class="note">' + (values.entryFound
      ? 'This person has an entry in the directory, so the values marked <em>directory</em> are ' +
        'what an LDAP client reads from it.'
      : 'This person has no entry in the directory — nobody has authenticated as them and nothing ' +
        'was added by hand — so every value below is generated. It will be the same one next ' +
        'time: the invented person is seeded from the username.') + '</span></div></form>' +

    '<div class="warn"><strong>Custom claims are additive.</strong> A configured claim is added to ' +
    'what the protocol already puts in the token and never replaces one. The names this service ' +
    'sets itself are refused rather than silently ignored: ' +
    codeList(stats.RESERVED_JWT_CLAIMS) + '. Every one of them is ' +
    'load-bearing somewhere here — an <code>exp</code> settable from a web form would produce ' +
    'tokens that fail to verify with nothing pointing back at this page.</div>' +

    '<h2>The four sets</h2>' +
    stats.CLAIM_SET_IDS.map(function (id) {
      return claimSetSection(id, previewUser, values, pageUrl);
    }).join('') +

    groupClaimSection(previewUser) +

    '<h2>Where a directory attribute comes from, and what it does not do</h2>' +
    '<p class="note">The catalogue is of <strong>LDAP attribute types</strong> and not of claim ' +
    'names, and it is the same catalogue <a href="/admin/vc">the credential claims page</a> ' +
    'chooses from — one list of spellings, because two would eventually disagree about what ' +
    '<code>schacDateOfBirth</code> is called while both looked right. The value is the one on that ' +
    'person\'s entry under <code>ou=users</code>; where the entry has nothing, it is invented from ' +
    'the username — the same invented person every time, across restarts, in obviously fictional ' +
    'ranges. Three rows are not RFC 4519/4524/2798: there is no standard attribute type for a ' +
    'birthdate or a nationality, so the SCHAC schema\'s names are borrowed rather than invented.</p>' +
    '<p class="note">The four selections are <strong>independent</strong>, which is the point of ' +
    'having four: an access token carrying <code>employee_number</code> and an ID Token carrying ' +
    '<code>email</code> is a normal arrangement and a single list could not express it. They are ' +
    'also independent of what a <a href="/admin/vc">credential</a> carries and of what the ' +
    '<a href="/admin/vc-verifier-config">Verifier asks for</a>, deliberately — that is what keeps ' +
    '"issue a credential carrying a claim the access token does not" reachable.</p>' +
    '<p class="note">A <strong>nested</strong> claim stays nested in a JWT: <code>address.locality' +
    '</code> is a <code>locality</code> member of an <code>address</code> object, which is what ' +
    'OIDC Core 5.1.1 defines. A SAML Attribute has no way to spell that — the content model is a ' +
    'name and text values — so the assertion carries the dotted path as the attribute\'s name. ' +
    'Both families then call one claim by one name, which is the property somebody comparing an ID ' +
    'Token with an assertion needs.</p>' +
    '<p class="note"><strong>A typed claim of the same name wins.</strong> Somebody who wrote ' +
    '<code>email</code> by hand on the set that also has <code>mail</code> ticked has said ' +
    'something specific, and the specific thing beats the general one. In an assertion that has to ' +
    'be a filter rather than an overwrite: two <code>&lt;Attribute&gt;</code> elements with one ' +
    'name would leave a relying party reading whichever the builder emitted first.</p>' +
    '<p class="note"><strong>And the protocol\'s own claim beats both</strong>, which is worth ' +
    'knowing before it is discovered on a token. An ID Token always carries <code>name</code>, ' +
    '<code>given_name</code>, <code>family_name</code>, <code>preferred_username</code> and ' +
    '<code>email</code> built from the sign-in, so ticking <code>cn</code>, <code>givenName</code>, ' +
    '<code>sn</code>, <code>uid</code> or <code>mail</code> <em>on that set</em> changes nothing ' +
    'the client sees — the same five reach an access token, where the protocol sets none of them, ' +
    'and reach it from the directory. A SAML 2.0 assertion sets <code>name</code> the same way, and ' +
    'a WS-Federation one sets the whole identity claim list. The rule is not new and is not this ' +
    'page\'s: a configured claim is added to a token and never substituted into one, because a ' +
    'claim a relying party keys off that a web form could displace would break a sign-in somewhere ' +
    'that looks nothing like this page.</p>' +
    '<p class="note"><strong>None of it is verified and none of it grants anything.</strong> This ' +
    'service authenticates nobody — the username typed at the sign-in screen is the identity in ' +
    'every token it issues — so a birthdate from here is a birthdate from a web form. No endpoint ' +
    'here reads one of these claims back or decides anything on one. That is true of the groups ' +
    'claim below as well: a token carries it, and a group on that person\'s entry still grants ' +
    'them nothing &mdash; see <a href="/admin/groups">the groups page</a>.</p>' +

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
    '<p class="note">The form a test wants. POST the same thing as JSON to get JSON back. This ' +
    'replaces the <em>typed</em> claims only; the directory attributes ticked above are a separate ' +
    'action (<code>attributes</code>) and are left alone by it.</p>' +
    '<form method="post" action="' + esc(pageUrl) + '">' +
      '<input type="hidden" name="action" value="replace">' +
      '<div class="formrow"><label for="set">Set</label>' +
      '<select id="set" name="set">' + setSelect + '</select></div>' +
      '<textarea name="claims" spellcheck="false">[{"name": "dept", "value": "engineering"}, ' +
      '{"name": "on_behalf_of", "value": "${username}"}]</textarea>' +
      '<div class="formrow"><button>Replace</button></div>' +
    '</form>';

  respond(req, res, claimsJson(previewUser), 'Custom claims', '/admin/claims', inner);
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

// Somebody the directory actually holds, so the page shows real values on a
// fresh start rather than an invented person nobody can look up. The parameter
// wins where it is given; the cap is there because this string is echoed.
function vcPreviewUser(query) {
  const asked = String((query && query.user) || 'alice').trim();
  return asked.slice(0, 64) || 'alice';
}

// The catalogue, the selection, and one person's claims as they would be minted
// right now. The preview is in the JSON as well as on the page because "what
// would this issue" is the question the selection exists to answer, and a
// caller with no browser has no other way to ask it.
function vcJson(previewUser) {
  log.debug("Entering vcJson(). previewUser=" + previewUser);
  const json = {
    selected: vcClaims.selectedNames(),
    defaults: vcClaims.DEFAULT_SELECTION,
    ldpOmitted: vcClaims.ldpOmitted(),
    attributes: vcClaims.VC_ATTRIBUTES.map(function (row) {
      return { ldap: row.ldap, claim: row.claim.join('.'), label: row.label,
               schema: row.schema, ldpTerm: row.ldpTerm || '',
               selected: vcClaims.isSelected(row.ldap) };
    }),
    preview: { user: previewUser,
               claims: vcClaims.subjectClaimsFor(previewUser, {}) }
  };
  log.debug("Leaving vcJson().");
  return json;
}

app.get('/admin/vc', function (req, res) {
  log.debug("Entering the admin credential-claims page.");
  const previewUser = vcPreviewUser(req.query);

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

  respond(req, res, vcJson(previewUser), 'Credential claims', '/admin/vc',
          inner);
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

// What the bar door asks for, and the dcql_query that carries it. The query is
// built by the function that builds the REAL one — see the note in
// vc_verifier_config.js — so a caller reading this reply is reading the next
// Authorization Request rather than a description of one.
function vpConfigJson() {
  log.debug("Entering vpConfigJson().");
  const format = vpConfig.defaultFormatId();
  const json = {
    requested: vpConfig.requestedClaims(),
    defaults: vpConfig.defaultRequested(),
    format: format,
    formats: vpConfig.FORMATS.map(function (item) {
      return { id: item.id, label: item.label, identifiedBy: item.identifiedBy,
               identifier: item.identifier,
               selectiveDisclosure: item.selectiveDisclosure,
               holderBinding: item.holderBinding,
               configurations: item.configs };
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
    dcqlQuery: vpConfig.dcqlQuery(format)
  };
  log.debug("Leaving vpConfigJson(). Asking for " + json.requested.length +
            " claim(s).");
  return json;
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

  respond(req, res, vpConfigJson(), 'Verifier request',
          '/admin/vc-verifier-config', inner);
  log.debug("Leaving the admin verifier-request page.");
});


// ---------------------------------------------------------------------------
// /admin/config — every setting this service has, in one page.
//
// The sections are the PROTOCOLS, in the order config.js's table declares them,
// because that is where a reader looks: somebody who wants the Kerberos realm
// looks under Kerberos, not under an alphabetical list of forty-five keys. The
// grouping is not decided here — `config.groups()` is the same call the
// management API makes, so the page and the API cannot come to describe
// different sets of settings.
//
// EVERY ROW SAYS WHERE ITS VALUE CAME FROM. That is the question this page
// exists to answer and it is the one that used to require a grep: a value can
// arrive from a runtime override, from an environment variable (its own or the
// legacy STS_ISSUER), from the appconfig file, or from the built-in default,
// and the four are indistinguishable once they have been read.
//
// A restart-only row is SHOWN and its input is DISABLED, with the reason beside
// it. Both halves matter. Hiding it would answer "what is this service
// configured with?" with three quarters of the answer; letting it be typed into
// would accept a change that does nothing, which reads as having worked.
//
// No script here, like every other page in this console: each section is a
// plain form that posts the whole section at once (`set-many`), and each row
// has a Reset button of its own. See the shell's note above — `script-src
// 'none'` is what makes reflected content moot for this service, and the
// explorer at /admin-api/docs is the single exception.
// ---------------------------------------------------------------------------

// The four sources, as a phrase a reader can act on. `env-legacy` is its own
// case rather than being folded into `env`, because the variable it names is
// not the one the rest of the row talks about — being told the value comes from
// "the environment" while STS_SAML_ISSUER is unset is the kind of true answer
// that costs twenty minutes.
function sourceNote(setting) {
  if (setting.source === 'override') {
    return 'set here, in memory only';
  }
  if (setting.source === 'env') {
    return 'from ' + setting.env;
  }
  if (setting.source === 'env-legacy') {
    return 'from ' + setting.legacyEnv + ' (the legacy variable)';
  }
  if (setting.source === 'appconfig') {
    return 'from ' + (process.env.CONFIG_FILE || 'the appconfig file');
  }
  return 'built-in default';
}

function configRow(setting) {
  const id = 'cfg-' + setting.key.replace(/\./g, '-');
  const input = setting.type === 'enum'
    ? '<select name="' + esc(setting.key) + '" id="' + esc(id) + '"' +
      (setting.editable ? '' : ' disabled') + '>' +
      setting.enumValues.map(function (option) {
        return '<option value="' + esc(option) + '"' +
          (option === setting.text ? ' selected' : '') + '>' + esc(option) + '</option>';
      }).join('') + '</select>'
    : (setting.type === 'bool'
      ? '<select name="' + esc(setting.key) + '" id="' + esc(id) + '"' +
        (setting.editable ? '' : ' disabled') + '>' +
        ['true', 'false'].map(function (option) {
          return '<option value="' + option + '"' +
            (option === setting.text ? ' selected' : '') + '>' + option + '</option>';
        }).join('') + '</select>'
      : '<input type="text" name="' + esc(setting.key) + '" id="' + esc(id) + '"' +
        ' size="34" value="' + esc(setting.text) + '"' +
        (setting.editable ? '' : ' disabled') + '>');

  // The Reset button is its own form. It has to be: it is a different action
  // from the section's Save, and a second submit button inside one form would
  // post every field in the section with it.
  const reset = setting.overridden
    ? '<form method="post" action="/admin/config" class="inline">' +
      '<input type="hidden" name="action" value="reset">' +
      '<input type="hidden" name="key" value="' + esc(setting.key) + '">' +
      '<button class="secondary">Reset</button></form>'
    : '';

  const provenance = setting.overridden
    ? '<strong>' + esc(sourceNote(setting)) + '</strong>'
    : esc(sourceNote(setting));

  const note = setting.editable
    ? ''
    : '<div class="note"><strong>Restart to apply:</strong> ' +
      esc(setting.restartReason) + '.</div>';

  return '<tr>' +
    '<td><label for="' + esc(id) + '"><code>' + esc(setting.key) + '</code></label>' +
    '<div class="note">' + esc(setting.label) + '. ' + esc(setting.description) + '</div>' +
    note + '</td>' +
    '<td>' + input + '</td>' +
    '<td>' + provenance + '</td>' +
    '<td>' + reset + '</td></tr>';
}

function configSection(group) {
  log.debug("Entering configSection(). group=" + group.group);
  const rows = group.settings.map(configRow).join('');
  const anyEditable = group.settings.some(function (setting) { return setting.editable; });
  const save = anyEditable
    ? '<p><button>Save ' + esc(group.group) + '</button> ' +
      '<span class="note">Applies to the next token, assertion, ticket or ' +
      'search — nothing already issued changes.</span></p>'
    : '<p class="note">Every setting in this section is read at startup, so ' +
      'there is nothing here to save. Change them in ' +
      esc(process.env.CONFIG_FILE || 'the appconfig file') + ' or in the ' +
      'environment and restart.</p>';
  log.debug("Leaving configSection(). " + group.settings.length + " setting(s).");
  return '<h3>' + esc(group.group) + '</h3>' +
    '<form method="post" action="/admin/config">' +
    '<input type="hidden" name="action" value="set-many">' +
    '<table><tr><th>Setting</th><th>Value</th><th>Source</th><th></th></tr>' +
    rows + '</table>' + save + '</form>';
}

// The action switch. `set` and `reset` name one setting; `set-many` is what a
// section's Save posts, and it is not a convenience — a section is how a person
// changes configuration, and turning that into one call per field would make a
// partly-applied section the ordinary outcome of a mistake in any one of them.
// So set-many is ALL-OR-NOTHING: every field is checked before any is written.
function configAction(body) {
  log.debug("Entering configAction(). action=" + (body && body.action));
  const action = String((body && body.action) || '').trim();

  if (action === 'set') {
    const key = String(body.key || '').trim();
    const result = config.setOverride(key, body.value);
    if (!result.ok) {
      log.debug("Leaving configAction(). set refused.");
      return result;
    }
    log.debug("Leaving configAction(). set ok.");
    return { ok: true, key: key, setting: config.describe(configSettingFor(key)),
             message: key + ' is now "' + config.text(key) + '". It applies to ' +
                      'the next token, assertion, ticket or search, and is gone ' +
                      'on restart.' };
  }

  if (action === 'set-many') {
    // Only the keys this service knows and that were actually posted. A form
    // posts its disabled inputs not at all, so a section holding restart-only
    // rows submits the editable ones and nothing else — which is why an absent
    // key is silently skipped rather than treated as an attempt to clear it.
    const wanted = Object.keys(body).filter(function (name) {
      return name !== 'action' && configKnows(name);
    });
    if (!wanted.length) {
      log.debug("Leaving configAction(). set-many named nothing.");
      return { ok: false, errors: ['No settings were posted. Every name must be ' +
        'one of the keys GET /admin/config?format=json lists.'] };
    }
    // Checked first, every one of them, and only then written. A section that
    // applied its first three fields and refused the fourth would leave the
    // service in a state nobody asked for and the page showing it.
    const errors = [];
    wanted.forEach(function (key) {
      const problem = config.checkOverride(key, body[key]);
      if (problem) errors.push(problem);
    });
    if (errors.length) {
      log.debug("Leaving configAction(). set-many refused: " + errors.length + " problem(s).");
      return { ok: false, errors: errors };
    }
    const changed = [];
    wanted.forEach(function (key) {
      const before = config.text(key);
      config.setOverride(key, body[key]);
      if (config.text(key) !== before) changed.push(key);
    });
    log.debug("Leaving configAction(). set-many ok, " + changed.length + " changed.");
    return { ok: true, applied: wanted, changed: changed,
             settings: wanted.map(function (key) {
               return config.describe(configSettingFor(key));
             }),
             message: changed.length
               ? changed.length + ' setting(s) changed: ' + changed.join(', ') +
                 '. Gone on restart.'
               : 'Nothing changed — every value posted was the one already in force.' };
  }

  if (action === 'reset') {
    const key = String(body.key || '').trim();
    const result = config.clearOverride(key);
    if (!result.ok) {
      log.debug("Leaving configAction(). reset refused.");
      return result;
    }
    log.debug("Leaving configAction(). reset ok.");
    return { ok: true, key: key, setting: config.describe(configSettingFor(key)),
             message: key + ' is back to its ' + config.sourceOf(key) + ' value, "' +
                      config.text(key) + '".' };
  }

  if (action === 'reset-all') {
    const result = config.clearAllOverrides();
    log.debug("Leaving configAction(). reset-all ok.");
    return { ok: true, cleared: result.cleared,
             message: result.cleared.length
               ? result.cleared.length + ' runtime override(s) cleared: ' +
                 result.cleared.join(', ') + '.'
               : 'There were no runtime overrides to clear.' };
  }

  log.debug("Leaving configAction(). Unknown action.");
  return { ok: false, errors: ['Unknown action "' + action + '". The four are: ' +
    'set, set-many, reset, reset-all.'] };
}

// Whether this service has a setting of that name. Asked before `describe()`,
// which throws on an unknown key by design — the throw is right for a caller
// that has a key it believes in, and wrong for a form body whose field names
// arrived from outside.
function configKnows(key) {
  return config.SETTINGS.some(function (setting) { return setting.key === key; });
}

function configSettingFor(key) {
  return config.SETTINGS.filter(function (setting) {
    return setting.key === key;
  })[0];
}

function configJson() {
  log.debug("Entering configJson().");
  const json = config.snapshot();
  log.debug("Leaving configJson(). " + json.settingCount + " setting(s).");
  return json;
}

app.post('/admin/config', function (req, res) {
  log.debug("Entering the admin configuration action endpoint.");
  const body = parseBody(req);
  const result = configAction(body);
  respondToAction(req, res, '/admin/config', result);
  log.debug("Leaving the admin configuration action endpoint.");
});

// ---------------------------------------------------------------------------
// /admin/scim — WHAT THE PROVISIONING SURFACE HAS DONE.
//
// The one page here that reports a protocol family rather than an artifact this
// service issued, and it reports two different kinds of thing on purpose:
//
//   * the COUNTERS, from admin_stats.js. Which SCIM operation was performed how
//     many times, on which resource type, and what was refused with which
//     `scimType`. Every row of both vocabularies is drawn INCLUDING the zeroes,
//     because "does this server do PATCH" is the question somebody comes here
//     with and a table that only listed what had happened would answer it by
//     omission.
//   * the SURFACE, from scim.js through the reader slot — the endpoints, what it
//     deliberately does not do, and the things you can make fail. Written once,
//     in the module that implements them, and rendered here. See setScimReader().
//
// **IT HAS NO CONTROLS, AND THAT IS WHY IT NEEDS ONLY A GET ON /admin-api.**
// Everything about SCIM that can be changed is a `config.js` row —
// `scim.enabled`, the three limits, and the thirteen authentication settings
// (which scheme is offered, the two scope names, the realm, the shared Digest
// password, the two lifetimes) — so /admin/config already has the form
// and POST /admin-api/config/set already has the operation. A second form here
// would be a second door to one setting, which is the mistake rule 5 exists for
// and the same argument group_claims.js makes about `groups.claim`.
//
// **THE BULK COUNT DOES NOT TALLY WITH THE REST, ON PURPOSE.** One
// POST /scim/v2/Bulk carrying five creates is one `bulk` row AND five `create`
// rows, because each operation inside really is performed. Said on the page,
// because a reader adding the column up will otherwise conclude the counting is
// broken.
// ---------------------------------------------------------------------------
function scimJson(req) {
  log.debug("Entering scimJson().");
  const counters = stats.scimSnapshot();
  const surface = scimReader ? scimReader(req) : null;
  const out = {
    // Distinguished from `enabled` deliberately: a process whose scim.js never
    // loaded is a different thing from one where scim.enabled is false, and a
    // page that reported both as "off" would send somebody to the wrong setting.
    installed: !!surface,
    enabled: surface ? surface.enabled : false,
    baseUrl: surface ? surface.baseUrl : null,
    specifications: surface ? surface.specifications : ['RFC 7642', 'RFC 7643', 'RFC 7644'],
    store: surface ? surface.store : null,
    identifiers: surface ? surface.identifiers : null,
    // The six schemes, whether each is on, and the access control policy —
    // from scim_auth.js's table by way of scim.js's description(). Null when
    // SCIM is not loaded, which is a different thing from every scheme being
    // off and is why it is not defaulted to an empty list.
    authentication: surface ? surface.authentication : null,
    endpoints: surface ? surface.endpoints : [],
    doesNotDo: surface ? surface.doesNotDo : [],
    reachableNegatives: surface ? surface.reachableNegatives : [],
    mapping: { user: scimMap.USER_ATTRIBUTES.map(scimMappingRow),
               group: scimMap.GROUP_ATTRIBUTES.map(scimMappingRow) },
    counters: counters
  };
  log.debug("Leaving scimJson(). " + counters.total + " request(s) counted.");
  return out;
}

// ---------------------------------------------------------------------------
// THE AUTHENTICATION SECTION OF /admin/scim.
//
// Two tables and a list, and the division between them is the one this page
// already draws everywhere else: the SCHEMES come from scim.js's description()
// — which is scim_auth.js's table, the same one that builds the
// WWW-Authenticate challenge and the ServiceProviderConfig — while the COUNTS
// come from admin_stats.js. So a scheme that is offered cannot be missing from
// this page and a count cannot be attributed to a scheme that does not exist.
//
// Every scheme is drawn INCLUDING the ones at zero and the ones turned off,
// for the reason the operations table below draws its zeroes: "can I use Digest
// against this server" is the question somebody arrives with, and a table that
// listed only what had been used would answer it by omission.
//
// There are no CONTROLS here, which is what keeps rule 7 satisfied with only a
// GET on /admin-api/scim: every one of these is a config.js row, so
// /admin/config already has the form and POST /admin-api/config/set already has
// the operation. A second form here would be a second door to one setting.
// ---------------------------------------------------------------------------
function authenticationSection(auth, counters) {
  log.debug("Entering authenticationSection().");
  const counts = (counters && counters.byAuthScheme) || {};
  const rows = auth.schemes.map(function (row) {
    return '<tr><td>' + esc(row.name) +
      (row.primary ? ' <span class="sub">(primary)</span>' : '') +
      '<div class="sub">' + esc(row.description) + '</div></td>' +
      '<td><code>' + esc(row.type) + '</code>' +
      (row.canonical ? '' : '<div class="sub">no canonical value in RFC 7643 ' +
        'section 5 — published beside the four that have one</div>') + '</td>' +
      '<td>' + (row.enabled
        ? '<span class="state-valid">offered</span>'
        : '<span class="state-none">off</span>') +
      '<div class="sub"><code>' + esc(row.setting) + '</code></div></td>' +
      '<td>' + (row.scoped ? 'what its scopes say' : 'everything') + '</td>' +
      '<td class="num">' + (counts[row.id] || 0) + '</td></tr>';
  }).join('');
  const extra = ['anonymous', 'refused'].map(function (name) {
    return '<tr><td>' + esc(name === 'anonymous'
      ? 'Nothing (an open discovery call, or authentication turned off)'
      : 'Refused before any handler ran') + '</td><td></td><td></td><td></td>' +
      '<td class="num">' + (counts[name] || 0) + '</td></tr>';
  }).join('');
  const policy = auth.policy.map(function (text) {
    return '<li>' + esc(text) + '</li>';
  }).join('');
  const out = '<h2>Authentication</h2>' +
    '<p class="note">RFC 7644 section 2 defines no credential of its own — it ' +
    'delegates to TLS and RFC 7235 and NAMES six schemes, and all six are ' +
    'here. Its one SHALL is that the schemes be indicated in ' +
    '<code>WWW-Authenticate</code>, which every 401 from these endpoints ' +
    'carries; its one MUST is that an authenticated client be mappable to an ' +
    'access control policy, which is the list below. Realm <code>' +
    esc(auth.realm) + '</code>. Discovery is ' +
    (auth.discoveryOpen
      ? 'OPEN, because a client has to be able to read which schemes exist ' +
        'before it can use one'
      : 'closed as well (<code>scim.authDiscovery</code>)') + '. Every switch ' +
    'here is on <a href="/admin/config">Configuration</a>.</p>' +
    '<table><tr><th>Scheme</th><th>type</th><th>State</th><th>May do</th>' +
    '<th class="num">Requests</th></tr>' + rows + extra + '</table>' +
    '<p class="note">The two OAuth scopes are <code>' + esc(auth.scopes.read) +
    '</code> and <code>' + esc(auth.scopes.write) + '</code> — the first scope ' +
    'requirement anywhere in this service — and they are published in ' +
    '<code>scopes_supported</code> in both discovery documents. Digest offers ' +
    esc(auth.digestAlgorithms.join(', ')) + '; HOBA keys are registered at ' +
    '<code>' + esc(auth.hobaRegistration) + '</code> and land on the person\'s ' +
    'own directory entry, so <a href="/admin/users">Users</a> shows them.</p>' +
    '<h3>The access control policy</h3><ul class="note">' + policy + '</ul>';
  log.debug("Leaving authenticationSection(). " + auth.schemes.length + " scheme(s).");
  return out;
}

// One row of the mapping, as the page and the API both want it. The `note` is
// carried through because several of them are the whole reason the row is not
// obvious — `groups` being read-only, `active` deactivating nobody, `manager`
// being passed through rather than resolved.
function scimMappingRow(row) {
  return { scim: row.scim, ldap: row.ldap, kind: row.kind,
           readOnly: !!row.readOnly, required: !!row.required,
           extension: !!row.extension, schema: row.schema || '',
           note: row.note || '' };
}

app.get('/admin/scim', function (req, res) {
  log.debug("Entering the admin SCIM page.");
  const json = scimJson(req);
  const counters = json.counters;

  const tiles = tile(counters.total, 'SCIM requests') +
    tile(counters.ok, 'answered') +
    tile(counters.failed, 'refused') +
    tile(json.store ? json.store.userCount : '—', 'people in the directory') +
    tile(json.store ? json.store.groupCount : '—', 'groups') +
    tile(json.store ? json.store.entryCount + ' / ' + json.store.maxEntries : '—', 'entries / max');

  const operationRows = counters.operations.map(function (row) {
    return '<tr><td><code>' + esc(row.method) + '</code> ' + esc(row.label) + '</td>' +
      '<td class="num">' + row.count + '</td>' +
      '<td class="sub">' + esc(row.what) + '</td></tr>';
  }).join('');

  const typeRows = counters.resourceTypes.map(function (row) {
    return '<tr><td><code>' + esc(row.resourceType) + '</code></td>' +
      '<td class="num">' + row.count + '</td></tr>';
  }).join('');

  const statusRows = Object.keys(counters.byStatus).sort().map(function (code) {
    return '<tr><td><code>' + esc(code) + '</code></td><td class="num">' +
      counters.byStatus[code] + '</td></tr>';
  }).join('') || '<tr><td colspan="2">Nothing has been answered yet.</td></tr>';

  const scimTypeRows = Object.keys(counters.byScimType).sort().map(function (name) {
    return '<tr><td><code>' + esc(name) + '</code></td><td class="num">' +
      counters.byScimType[name] + '</td></tr>';
  }).join('') || '<tr><td colspan="2">Nothing has been refused yet, which on a ' +
                 'server this permissive usually means nothing has tried the ' +
                 'error paths.</td></tr>';

  const endpointRows = json.endpoints.map(function (row) {
    return '<tr><td><code>' + esc(row.method) + '</code></td><td><code>' +
      esc(row.path) + '</code></td><td class="sub">' + esc(row.what) + '</td></tr>';
  }).join('');

  const negativeRows = json.reachableNegatives.map(function (row) {
    return '<tr><td>' + esc(row.what) + '</td><td>' + esc(row.answer) + '</td></tr>';
  }).join('');

  function mappingTable(rows) {
    return '<table><tr><th>SCIM</th><th>LDAP attribute</th><th>How</th>' +
      '<th>Defined by</th></tr>' +
      rows.map(function (row) {
        return '<tr><td><code>' + esc(row.scim) + '</code>' +
          (row.required ? ' <span class="state-valid">required</span>' : '') +
          (row.extension ? ' <span class="sub">(enterprise extension)</span>' : '') +
          '</td>' +
          '<td><code>' + esc(row.ldap) + '</code></td>' +
          '<td>' + esc(row.kind) + (row.readOnly ? ', read-only' : '') +
          (row.note ? '<div class="sub">' + esc(row.note) + '</div>' : '') + '</td>' +
          '<td class="sub">' + esc(row.schema) + '</td></tr>';
      }).join('') + '</table>';
  }

  const inner = messagesOf(req) +
    (!json.installed
      ? '<div class="err"><strong>SCIM is not loaded in this process.</strong> ' +
        'The module registers no routes here, so there is nothing to report. ' +
        'Everything else on this console is unaffected.</div>'
      : '') +
    (json.installed && !json.enabled
      ? '<div class="warn"><strong>SCIM is turned off</strong> ' +
        '(<code>scim.enabled</code>). The routes are still registered and answer ' +
        '<code>501</code> rather than <code>404</code>, because the feature ' +
        'being off and the URL being wrong are different sentences to a client. ' +
        'Turn it back on at <a href="/admin/config">Configuration</a>.</div>'
      : '') +

    '<p class="note">SCIM 2.0 — RFC 7642, 7643 and 7644 — at <code>' +
    esc(json.baseUrl || '/scim/v2') + '</code>. It is the only protocol family ' +
    'here whose purpose is to WRITE, and what it writes is the embedded LDAP ' +
    'directory: there is no second store and no cache. A ' +
    '<code>POST /scim/v2/Users</code> and an <code>ldapadd</code> create the ' +
    'same entry, so somebody provisioned over SCIM appears on ' +
    '<a href="/admin/users">Users</a>, gains whatever attributes ' +
    '<a href="/admin/vc">Credential claims</a> selects, and lands in whatever ' +
    'group a client puts them in on <a href="/admin/groups">Groups</a>.</p>' +

    '<div class="warn"><strong>These endpoints create and delete accounts, and ' +
    'they are the one surface in this service that requires a credential' +
    (json.authentication && !json.authentication.required
      ? ' — except that <code>scim.authRequired</code> is currently OFF, so ' +
        'right now they do not'
      : '') + '.</strong> Almost nothing is checked about it: every scheme ' +
    'below is permissive, so this is a turnstile rather than a lock. What it ' +
    'buys is that a client\'s 401, 403 and challenge-response paths can be ' +
    'exercised at all. <strong>And <code>active: false</code> deactivates ' +
    'nobody</strong> — it is stored on the entry as <code>scimActive</code> ' +
    'and read by nothing here: no bind is refused, no token withheld, no ' +
    'session ended. Deprovisioning is the commonest thing a SCIM client does, ' +
    'so that one is worth reading twice.</div>' +

    tiles +

    (json.authentication ? authenticationSection(json.authentication, counters) : '') +

    '<h2>Operations</h2>' +
    '<p class="note">Every operation this server implements, including the ones ' +
    'nothing has used yet — a table listing only what has happened would answer ' +
    '&ldquo;does this support PATCH?&rdquo; by omission. <strong>The column does ' +
    'not tally</strong>, on purpose: one <code>Bulk</code> carrying five creates ' +
    'is one bulk AND five creates, because each of the five really is performed.</p>' +
    '<table><tr><th>Operation</th><th class="num">Count</th><th>What it is</th></tr>' +
    operationRows + '</table>' +

    '<h2>By resource type</h2>' +
    '<table><tr><th>Resource type</th><th class="num">Count</th></tr>' + typeRows +
    '</table>' +

    '<h2>What went back</h2>' +
    '<p class="note">The HTTP status of every answer, and the <code>scimType</code> ' +
    'of every refusal (RFC 7644 section 3.12). <code>(none)</code> is a refusal ' +
    'that carried no such code — a 404 has none — and is counted rather than ' +
    'dropped, so the two failure tables agree with each other.</p>' +
    '<div class="tiles" style="align-items:flex-start">' +
    '<div><table><tr><th>Status</th><th class="num">Count</th></tr>' + statusRows +
    '</table></div>' +
    '<div><table><tr><th>scimType</th><th class="num">Count</th></tr>' +
    scimTypeRows + '</table></div></div>' +

    (json.identifiers
      ? '<h2>The <code>id</code> is the DN</h2>' +
        '<p class="note">' + esc(json.identifiers.why) + '</p>' +
        '<p class="note">For example: <code>' + esc(json.identifiers.example) +
        '</code></p>'
      : '') +

    (endpointRows
      ? '<h2>Endpoints</h2><table><tr><th>Method</th><th>Path</th><th>What</th>' +
        '</tr>' + endpointRows + '</table>'
      : '') +

    (json.doesNotDo.length
      ? '<h2>What it deliberately does not do</h2><ul>' +
        json.doesNotDo.map(function (text) {
          return '<li>' + esc(text) + '</li>';
        }).join('') + '</ul>'
      : '') +

    (negativeRows
      ? '<h2>Things you can make fail</h2>' +
        '<p class="note">A permissive server is hard to write error handling ' +
        'against, so these are here on purpose — the same device as the reserved ' +
        'password <code>invalid</code> everywhere else in this service.</p>' +
        '<table><tr><th>Do this</th><th>Get this</th></tr>' + negativeRows +
        '</table>'
      : '') +

    '<h2>The User mapping</h2>' +
    '<p class="note">Which LDAP attribute each SCIM member is. The attribute ' +
    'spellings are the same catalogue <a href="/admin/vc">Credential claims</a> ' +
    'and <a href="/admin/claims">Custom claims</a> read, checked against it at ' +
    'startup rather than copied — four independently maintained lists of ' +
    'spellings is how one of them comes to be quietly wrong.</p>' +
    mappingTable(json.mapping.user) +

    '<h2>The Group mapping</h2>' +
    mappingTable(json.mapping.group) +

    '<p class="note">Nothing on this page is a control, because everything about ' +
    'SCIM that can be changed is a configuration row: <code>scim.enabled</code> ' +
    'and the three limits, on <a href="/admin/config">Configuration</a>. A form ' +
    'here would be a second door to one setting.</p>' +

    '<p class="note"><a href="/scim">What this is, for a person</a> &middot; ' +
    '<a href="/admin/scim?format=json">this page as JSON</a> &middot; ' +
    '<a href="/admin-api/scim">the same over the management API</a> &middot; ' +
    '<a href="/ldap">the directory it writes into</a></p>';

  respond(req, res, json, 'SCIM 2.0', '/admin/scim', inner);
  log.debug("Leaving the admin SCIM page.");
});

app.get('/admin/config', function (req, res) {
  log.debug("Entering the admin configuration page.");
  const snapshot = config.snapshot();
  const overridden = snapshot.overridden.length;

  const inner = messagesOf(req) +
    '<p class="note">Every setting this service has, grouped by the protocol it ' +
    'belongs to. A value can arrive from four places and the <em>Source</em> ' +
    'column says which: a runtime override set on this page, an environment ' +
    'variable, the appconfig file this process was started with (<code>' +
    esc(snapshot.configFile || '(none)') + '</code>), or the built-in default. ' +
    'Higher beats lower, so an environment variable set on the container still ' +
    'wins over the file — which is what keeps every existing deployment working ' +
    'unchanged.</p>' +

    '<div class="warn"><strong>Changes here are in memory and are gone on ' +
    'restart.</strong> Nothing writes to the appconfig file. That is the same ' +
    'arrangement as the custom claims and the credential claims next door, and ' +
    'it is deliberate: a service that edited a file checked into a repository ' +
    'would leave a test\'s forgotten change behind permanently. To make ' +
    'something stick, put it in <code>' + esc(snapshot.configFile || 'env/local.js') +
    '</code>.</div>' +

    '<div class="warn"><strong>' + esc(String(snapshot.settingCount - snapshot.editableCount)) +
    ' of these ' + esc(String(snapshot.settingCount)) + ' cannot be changed while ' +
    'this service runs</strong>, and they are shown with their inputs disabled ' +
    'and the reason beside them rather than hidden. They are the ones already ' +
    'consumed by the time the service was listening: a bound socket, the TLS ' +
    'certificate\'s names, the Kerberos principal database and its long-term ' +
    'keys, and the directory\'s base DN. Accepting a change to one of those ' +
    'would do nothing and read as having worked.</div>' +

    '<h2>' + esc(String(snapshot.settingCount)) + ' settings, ' +
    esc(String(snapshot.editableCount)) + ' of them changeable here</h2>' +

    (overridden
      ? '<div class="ok">' + esc(String(overridden)) + ' runtime override(s) in ' +
        'force: ' + codeList(snapshot.overridden) + '. ' +
        '<form method="post" action="/admin/config" class="inline">' +
        '<input type="hidden" name="action" value="reset-all">' +
        '<button class="secondary">Reset all</button></form></div>'
      : '<p class="note">No runtime overrides are in force: every value below ' +
        'is coming from the environment, the appconfig file or a built-in ' +
        'default.</p>') +

    snapshot.groups.map(configSection).join('') +

    '<p class="note">The same table over JSON is at <code>/admin/config?format=json</code> ' +
    'and <code>GET /admin-api/config</code>; the four actions on this page are ' +
    '<code>POST /admin-api/config/set</code>, <code>/set-many</code>, ' +
    '<code>/reset</code> and <code>/reset-all</code>.</p>';

  respond(req, res, configJson(), 'Configuration', '/admin/config', inner);
  log.debug("Leaving the admin configuration page.");
});

// ---------------------------------------------------------------------------
// /admin/spiffe, /admin/spiffe/entries, /admin/spiffe/agents — THE SPIFFE
// SECTION.
//
// Three pages rather than one, and the split is by what the reader is doing
// rather than by what the data is:
//
//   /admin/spiffe           the TRUST DOMAIN — its authorities, the bundle,
//                           the four gRPC listeners, the federated bundles.
//                           The forms here rotate an authority and set or
//                           remove a federated bundle.
//   /admin/spiffe/entries   the REGISTRATION ENTRIES: a list with a filter and
//                           paging, a drill-down per entry, and the forms that
//                           create, change and delete one.
//   /admin/spiffe/agents    the ATTESTED AGENTS: the same shape, and the forms
//                           ban, unban and delete.
//
// **The second and third are separate sections rather than drill-downs**, which
// is why each has its own NAV row and its own LIST_PARAMS whitelist. A
// drill-down's section crumb points at the list it came from, and an entries
// list hanging under /admin/spiffe would make the crumb point at a page that
// does not hold that list — the exact defect rule 7a describes.
//
// **THIS PAGE DECIDES NOTHING.** Every form posts to an action function that
// calls into `spiffe_registry.js` or `spiffe_ca.js` — the same functions the
// SPIRE Server API's `BatchCreateEntry`, `BanAgent` and
// `BatchSetFederatedBundle` call, and the same store an `ldapmodify` under
// `ou=spiffe` writes to. Three doors, one store, which is the one-store rule
// this service already applies to revocation, to the applications registry and
// to SCIM.
//
// **AND IT SAYS, ON EVERY PAGE, THAT NOTHING IS ATTESTED.** A console that
// listed registration entries beside the tokens page without saying so would
// let somebody conclude that a selector on an entry restricts who can get that
// identity. Nothing here restricts anything: any caller that reaches the
// Workload API socket is handed every identity in the trust domain.
// ---------------------------------------------------------------------------

// The warning that goes at the top of all three, written once. It is the SPIFFE
// analogue of the "a group here grants nothing" line on /admin/groups, and it
// matters more, because what comes out of these pages is a credential another
// service will believe.
// The banner every SPIFFE page carries. It is a FUNCTION rather than a constant
// now, because half of what it says depends on a setting that can be off: a
// fixed string would go on describing mutual TLS on a port that had been bound
// plain, which is the silent disagreement this repository keeps warning about.
//
// TWO PARAGRAPHS, and the split is the point — the two surfaces are
// authenticated differently because their specifications say opposite things,
// and a single sentence covering both was what made the old note wrong in one
// direction as soon as one of them changed.
function spiffePostureNote() {
  const enforced = spiffeAuth.authRequired();
  return '<div class="warn"><strong>Nothing here is attested.</strong> A real ' +
    'SPIFFE agent reads the peer credentials of its socket — pid, uid, gid, ' +
    'and from those the executable, the container, the pod — and hands a ' +
    'workload only the identities those selectors match. Node cannot read ' +
    'them at all, so this service identifies a Workload API caller by the ' +
    'transport it arrived on, the endpoint it reached and its peer address, ' +
    'and nothing else. Those DO now decide which entries answer ' +
    '(<code>spiffe.attestWorkloads</code>), and they prove nothing about who ' +
    'is calling: anybody who can reach the socket can still get an identity. ' +
    'Node attestation is taken on trust too, which is why every agent below ' +
    'carries an <code>unverified:true</code> selector.</div>' +
    '<div class="' + (enforced ? 'note' : 'warn') + '">' +
    (enforced
      ? '<strong>The SPIRE Server API is the exception.</strong> Its TCP port ' +
        'is mutual TLS: a caller presents an X509-SVID from this trust ' +
        'domain, and every method is authorized against SPIRE\'s own table — ' +
        'so an entry marked <code>admin</code> or <code>downstream</code> ' +
        'below now decides what its holder may do. Its Unix socket is the ' +
        '<code>local</code> entity and needs no credential. The Workload API ' +
        'is deliberately untouched: its specification says a client MUST NOT ' +
        'be required to authenticate.'
      : '<strong>And nobody is authenticated on the SPIRE Server API either, ' +
        'because <code>spiffe.authRequired</code> is off.</strong> That port ' +
        'is plain gRPC, any caller can create a registration entry granting ' +
        'any identity here and then collect an SVID for it, and the ' +
        '<code>admin</code> and <code>downstream</code> flags below are ' +
        'recorded and read by nothing. It is restart-only, because it decides ' +
        'how the socket is bound.') +
    ' <a href="/spiffe">GET /spiffe</a> has the whole table and the full list ' +
    'of what is and is not checked.</div>';
}

function spiffeSelectorText(selector) {
  return spiffeRegistry.selectorText(selector);
}

// ---------------------------------------------------------------------------
// THE TRUST DOMAIN PAGE.
// ---------------------------------------------------------------------------
function spiffeJson(req) {
  log.debug("Entering spiffeJson().");
  const state = spiffeCa.state();
  const bindings = spiffeListeners();
  const json = {
    enabled: state.enabled,
    ready: state.ready,
    error: state.error,
    trustDomain: state.trustDomain,
    trustDomainId: state.trustDomainId,
    serverId: state.serverId,
    bundle: {
      path: bindings.bundlePath,
      sequence: state.sequence,
      refreshHint: state.refreshHint
    },
    authorities: { x509: state.x509Authorities, jwt: state.jwtAuthorities,
                   maxRetained: spiffeCa.MAX_RETAINED_AUTHORITIES },
    listeners: { workloadApi: bindings.workload, serverApi: bindings.api },
    federated: state.federated,
    counts: { entries: spiffeRegistry.entryCount(),
              agents: spiffeRegistry.agentCount(),
              maxEntries: spiffeRegistry.maxEntries(),
              maxAgents: spiffeRegistry.maxAgents(),
              maxFederatedBundles: config.value('spiffe.maxFederatedBundles') },
    keyTypes: state.keyTypes,
    // WHO MAY CALL, from the one table `GET /spiffe` and the management API
    // read too. Built there rather than here for the reason the two discovery
    // documents are built from one object: three surfaces describing what is
    // enforced three ways is two of them eventually wrong.
    authentication: spiffeAuth.state(),
    // Which settings shape this, so that a reader who wants to change something
    // knows where to go rather than hunting /admin/config. The same courtesy
    // /admin/scim pays.
    settings: ['spiffe.enabled', 'spiffe.trustDomain', 'spiffe.x509KeyType',
               'spiffe.jwtKeyType', 'spiffe.caTtl', 'spiffe.svidTtl',
               'spiffe.jwtSvidTtl', 'spiffe.refreshHint', 'spiffe.svidSubject',
               'spiffe.autoCreateEntries', 'spiffe.requireSecurityHeader',
               'spiffe.authRequired', 'spiffe.trustLocalSocket',
               'spiffe.adminIds', 'spiffe.clockSkew',
               'spiffe.attestWorkloads', 'spiffe.acceptAssertedSelectors',
               'spiffe.maxEntries', 'spiffe.maxAgents',
               'spiffe.maxFederatedBundles', 'spiffe.bundlePath',
               'spiffe.workloadSocketEnabled', 'spiffe.workloadSocket',
               'spiffe.workloadPort', 'spiffe.serverPort',
               'spiffe.serverSocketEnabled', 'spiffe.serverSocket',
               'spiffe.grpcHost'].map(function (key) {
      return { key: key, value: config.text(key) };
    })
  };
  log.debug("Leaving spiffeJson(). ready=" + json.ready);
  return json;
}

// A listener row, and the fourth column is WHAT A CALLER HAS TO PRESENT ON IT.
// Not decoration: the four sockets have three different postures — plain,
// plain-and-trusted-as-local, and mutual TLS — and a reader who cannot see
// which is which meets the difference as a handshake failure with no message.
// The same courtesy /tls says about which port needs verification turned off.
function spiffeListenerRows(bindings, what) {
  if (!bindings.length) {
    return '<tr><td colspan="4">Nothing bound for ' + esc(what) + '. Either ' +
      'both transports are off in configuration, or the process has not ' +
      'finished starting.</td></tr>';
  }
  return bindings.map(function (binding) {
    return '<tr><td>' + esc(what) + '</td><td><code>' + esc(binding.address) +
      '</code>' + (binding.tls ? ' <span class="note">(mutual TLS)</span>' : '') +
      '</td><td>' + (binding.listening ? 'listening'
        : '<strong>did not bind</strong> &mdash; ' + esc(binding.error)) +
      '</td><td>' + esc(binding.authentication || '') + '</td></tr>';
  }).join('');
}

function spiffePage(req) {
  log.debug("Entering spiffePage().");
  const json = spiffeJson(req);
  const state = spiffeCa.state();
  const x509Rows = state.x509Authorities.map(function (authority) {
    return '<tr><td><code>' + esc(authority.id) + '</code></td><td>' +
      (authority.active ? '<strong>active</strong>' : 'retired, still published') +
      '</td><td>' + esc(authority.keyType) + '</td><td>' +
      esc(authority.notAfter) + '</td><td><code>' + esc(authority.subject) +
      '</code></td></tr>';
  }).join('');
  const jwtRows = state.jwtAuthorities.map(function (authority) {
    return '<tr><td><code>' + esc(authority.id) + '</code></td><td>' +
      (authority.active ? '<strong>active</strong>' : 'retired, still published') +
      '</td><td>' + esc(authority.keyType) + ' / ' + esc(authority.alg) +
      '</td><td>' + esc(new Date(authority.createdAt).toISOString()) +
      '</td><td>&mdash;</td></tr>';
  }).join('');
  const federatedRows = state.federated.map(function (entry) {
    return '<tr><td><code>' + esc(entry.trustDomainId) + '</code></td><td>' +
      entry.x509Keys + ' x509, ' + entry.jwtKeys + ' jwt</td><td>' +
      esc(entry.bundleEndpointProfile) + '<br><span class="note">' +
      esc(entry.bundleEndpointUrl || '(no endpoint URL recorded)') +
      '</span></td><td>' + esc(entry.sequence) + '</td><td>' +
      '<form method="post" action="/admin/spiffe" class="inline">' +
      '<input type="hidden" name="action" value="federation-remove">' +
      '<input type="hidden" name="trustDomain" value="' + esc(entry.trustDomain) + '">' +
      '<button class="danger">Remove</button></form> ' +
      '<a href="/spiffe/federated/' + encodeURIComponent(entry.trustDomain) +
      '">document</a></td></tr>';
  }).join('') || '<tr><td colspan="5">None. This trust domain federates with ' +
    'nobody.</td></tr>';

  const inner = messagesOf(req) + spiffePostureNote() +
    (json.enabled ? '' : '<div class="warn">SPIFFE is turned OFF ' +
      '(<code>spiffe.enabled</code>): the bundle endpoint answers 404 and every ' +
      'gRPC call is refused with <code>Unavailable</code>. Turn it back on from ' +
      '<a href="/admin/config">Configuration</a>; it needs no restart.</div>') +
    (json.ready ? '' : '<div class="warn">' + (json.error
      ? 'The issuing authority could not be built, so nothing here will issue ' +
        'an SVID: ' + esc(json.error)
      : 'The issuing authority is still being generated &mdash; an RSA-4096 key ' +
        'takes a few seconds. Reload.') + '</div>') +

    '<h2>The trust domain</h2>' +
    '<p>This service is the issuing authority for <code>' +
    esc(json.trustDomainId) + '</code>. Its own identity as a SPIFFE server is ' +
    '<code>' + esc(json.serverId || '(not yet)') + '</code>, and every ' +
    'registration entry hangs beneath that by default. The trust domain is ' +
    'restart-only (<code>spiffe.trustDomain</code>): every authority ' +
    'certificate names it.</p>' +
    '<p>The bundle is published at <a href="' + esc(json.bundle.path) +
    '"><code>' + esc(json.bundle.path) + '</code></a> &mdash; sequence <code>' +
    esc(json.bundle.sequence) + '</code>, refresh hint ' +
    esc(json.bundle.refreshHint) + ' seconds. The sequence changes whenever the ' +
    'bundle does and never otherwise, which is what lets a consumer tell ' +
    '&ldquo;I have the current bundle&rdquo; from &ldquo;I have a ' +
    'bundle&rdquo;.</p>' +

    '<h2>Authorities</h2>' +
    '<p>Generated per start and held in memory, exactly like the STS signing ' +
    'key and the TLS certificate &mdash; so a workload holding a bundle from ' +
    'before a restart will fail to verify every SVID minted after it. ' +
    'Rotating PREPENDS a new authority and keeps the old one published: an SVID ' +
    'minted a minute ago has to go on verifying, which is what a bundle is for. ' +
    'At most ' + esc(json.authorities.maxRetained) + ' are retained, and past ' +
    'that the oldest is dropped &mdash; anything it signed stops verifying at ' +
    'that moment.</p>' +
    '<table><tr><th>Id</th><th>State</th><th>Key</th><th>Until</th>' +
    '<th>Subject</th></tr>' + x509Rows + jwtRows + '</table>' +
    '<form method="post" action="/admin/spiffe"><div class="formrow">' +
    '<input type="hidden" name="action" value="rotate">' +
    '<label for="which">Rotate</label>' +
    '<select id="which" name="which">' +
    '<option value="x509">the X.509 authority</option>' +
    '<option value="jwt">the JWT authority</option>' +
    '<option value="both">both</option></select>' +
    '<button>Rotate</button>' +
    '<span class="note">New SVIDs are signed with the new authority ' +
    'immediately; existing ones keep verifying until they expire.</span>' +
    '</div></form>' +

    '<h2>The gRPC listeners</h2>' +
    '<p>Neither <code>/sts-metadata</code> nor this page can see a socket, so ' +
    'this table is the only place that reports whether each one actually ' +
    'bound. All four are restart-only.</p>' +
    '<table><tr><th>Surface</th><th>Address</th><th>State</th>' +
    '<th>What a caller presents</th></tr>' +
    spiffeListenerRows(json.listeners.workloadApi, 'Workload API') +
    spiffeListenerRows(json.listeners.serverApi, 'SPIRE Server API') +
    '</table>' +

    '<h2>Who may call the SPIRE Server API</h2>' +
    '<p>' + esc(json.authentication.what || '') + '</p>' +
    '<p>A caller may be several of these at once and the check asks whether it ' +
    'is <em>any</em> of the ones a method allows, which is what SPIRE\'s own ' +
    'policy does: the <code>spire-server</code> CLI on this host is ' +
    '<code>local</code>, and an agent that also holds an entry marked ' +
    '<code>admin</code> is both.</p>' +
    '<table><tr><th>Entity</th><th>What it means</th></tr>' +
    json.authentication.entities.map(function (entity) {
      return '<tr><td><code>' + esc(entity.id) + '</code></td><td>' +
        esc(entity.what) + '</td></tr>';
    }).join('') + '</table>' +
    '<p>Administrators by configuration ' +
    '(<a href="/admin/config"><code>spiffe.adminIds</code></a>): ' +
    (json.authentication.adminIds.length
      ? json.authentication.adminIds.map(function (id) {
          return '<code>' + esc(id) + '</code>';
        }).join(', ') + '. '
      : 'none. ') +
    'The other way to make one is to mark a registration entry ' +
    '<code>admin</code> on <a href="/admin/spiffe/entries">the entries ' +
    'page</a>; SPIRE has both, and neither is cached, so either takes effect ' +
    'on the next call.</p>' +
    '<p class="note">Workload API selectors: a caller there is identified as ' +
    '<code>transport:</code>, <code>endpoint:</code> and <code>peer:</code>, ' +
    'and ' + (json.authentication.attestWorkloads
      ? 'those decide which entries answer it ' +
        '(<code>spiffe.attestWorkloads</code>).'
      : 'that decides nothing at the moment &mdash; ' +
        '<code>spiffe.attestWorkloads</code> is off, so every caller is ' +
        'answered with every entry.') +
    ' Asserted selectors (<code>' +
    esc(json.authentication.assertedSelectorHeader) + '</code>) are ' +
    (json.authentication.acceptAssertedSelectors
      ? '<strong>believed</strong>, and nothing verifies them.'
      : 'ignored (<code>spiffe.acceptAssertedSelectors</code> is off).') +
    '</p>' +
    '<h3>The per-method table</h3>' +
    '<p>Copied from SPIRE\'s own <code>policy_data.json</code> rather than ' +
    'reasoned out: a table derived from what each method &ldquo;obviously&rdquo; ' +
    'needs disagrees with SPIRE in two or three places, and the client author ' +
    'who meets the disagreement cannot tell which end is wrong. ' +
    '<code>any</code> means the method is open here and in a real server too ' +
    '&mdash; <code>AttestAgent</code> because an agent has no SVID until that ' +
    'call gives it one, <code>GetBundle</code> because a trust bundle is ' +
    'public.</p>' +
    '<table><tr><th>Method</th><th>Allowed to</th></tr>' +
    json.authentication.policy.map(function (row) {
      return '<tr><td><code>' + esc(row.method) + '</code></td><td>' +
        esc(row.allow.join(', ')) + '</td></tr>';
    }).join('') + '</table>' +

    '<h2>Federated trust domains</h2>' +
    '<p><strong>A foreign bundle is given to this service and never fetched by ' +
    'it.</strong> The federation specification has a bundle endpoint URL in the ' +
    'relationship and a real implementation polls it; this one records the URL ' +
    'and refuses to follow it, because fetching a URL somebody registered in ' +
    'order to obtain a credential-verification key is a server-side request ' +
    'forgery with a citation attached &mdash; the same refusal this service ' +
    'gives WS-Federation\'s <code>wreqptr</code> and a client\'s ' +
    '<code>jwks_uri</code>. Paste the bundle in below, or push it with ' +
    '<code>BatchSetFederatedBundle</code>.</p>' +
    '<table><tr><th>Trust domain</th><th>Keys</th><th>Profile / endpoint</th>' +
    '<th>Sequence</th><th></th></tr>' + federatedRows + '</table>' +
    '<form method="post" action="/admin/spiffe">' +
    '<div class="formrow">' +
    '<input type="hidden" name="action" value="federation-set">' +
    '<label for="fed-td">Trust domain</label>' +
    '<input id="fed-td" name="trustDomain" placeholder="other.example" size="24">' +
    '<label for="fed-url">Bundle endpoint URL</label>' +
    '<input id="fed-url" name="bundleEndpointUrl" placeholder="https://other.example/bundle" size="34">' +
    '<label for="fed-profile">Profile</label>' +
    '<select id="fed-profile" name="bundleEndpointProfile">' +
    '<option value="https_web">https_web</option>' +
    '<option value="https_spiffe">https_spiffe</option></select>' +
    '</div><div class="formrow">' +
    '<label for="fed-doc">Bundle document</label>' +
    '<textarea id="fed-doc" name="document" rows="6" cols="80" ' +
    'placeholder=\'{"keys":[{"kty":"EC","use":"x509-svid","x5c":["..."]}],"spiffe_sequence":1,"spiffe_refresh_hint":300}\'></textarea>' +
    '<button>Set</button>' +
    '<span class="note">A JWK Set. Every key needs <code>use</code> of ' +
    '<code>x509-svid</code>, <code>jwt-svid</code> or <code>wit-svid</code>: a ' +
    'consumer MUST IGNORE one without it, so a bundle of keys missing that ' +
    'member verifies nothing and reports no error, which is why it is refused ' +
    'here rather than stored.</span></div></form>' +

    '<h2>Elsewhere</h2><ul>' +
    '<li><a href="/admin/spiffe/entries">Registration entries</a> &mdash; ' +
    esc(json.counts.entries) + ' of at most ' + esc(json.counts.maxEntries) +
    '</li>' +
    '<li><a href="/admin/spiffe/agents">Attested agents</a> &mdash; ' +
    esc(json.counts.agents) + ' of at most ' + esc(json.counts.maxAgents) +
    '</li>' +
    '<li><a href="/spiffe">What this is, and what it does not check</a></li>' +
    '<li><a href="/ldap/spiffe">The containers and their schema</a></li>' +
    '<li><a href="/admin-api/spiffe">The same, over JSON</a></li>' +
    '</ul>';
  log.debug("Leaving spiffePage().");
  return { json: json, inner: inner, title: 'SPIFFE' };
}

// ---------------------------------------------------------------------------
// THE REGISTRATION ENTRIES.
// ---------------------------------------------------------------------------
function spiffeEntriesJson(req) {
  log.debug("Entering spiffeEntriesJson().");
  const q = String(req.query.q || '').trim().toLowerCase();
  const origin = String(req.query.origin || '').trim();
  const all = spiffeRegistry.allEntries();
  const rows = all.filter(function (entry) {
    if (origin && entry.origin !== origin) return false;
    if (!q) return true;
    return (entry.spiffeId + ' ' + entry.parentId + ' ' + entry.id + ' ' +
            entry.hint + ' ' +
            entry.selectors.map(spiffeSelectorText).join(' ')).toLowerCase()
      .indexOf(q) >= 0;
  });
  const pg = pagingOf(req.query, rows.length, { unit: 'entry' });
  const json = {
    total: all.length,
    matched: rows.length,
    filter: { q: q, origin: origin },
    origins: all.map(function (entry) { return entry.origin; })
      .filter(function (value, index, list) { return list.indexOf(value) === index; })
      .sort(),
    paging: { page: pg.page, pages: pg.pages, perPage: pg.perPage,
              total: pg.total },
    max: spiffeRegistry.maxEntries(),
    container: 'ou=entries,ou=spiffe',
    entries: rows.slice(pg.offset, pg.offset + pg.perPage)
  };
  log.debug("Leaving spiffeEntriesJson(). " + rows.length + " matched.");
  return { json: json, paging: pg };
}

function spiffeEntriesListPage(req) {
  log.debug("Entering spiffeEntriesListPage().");
  const view = spiffeEntriesJson(req);
  const json = view.json;
  const listView = listViewOf('/admin/spiffe/entries', req.query);
  const rows = json.entries.map(function (entry) {
    return '<tr><td><a href="/admin/spiffe/entries' +
      queryWith(listView, { entry: entry.id }) + '"><code>' +
      esc(entry.spiffeId) + '</code></a>' +
      (entry.expired ? ' <strong>(expired)</strong>' : '') +
      '<br><span class="note"><code>' + esc(entry.id) + '</code></span></td>' +
      '<td>' + esc(entry.selectors.map(spiffeSelectorText).join(', ') ||
                   '(none — matches every workload)') + '</td>' +
      '<td>' + esc(entry.origin) + '</td>' +
      '<td>' + esc(entry.hint || '—') + '</td>' +
      '<td>' + entry.svidsIssued + '</td>' +
      '<td>rev ' + entry.revisionNumber + '</td></tr>';
  }).join('') || '<tr><td colspan="6">No registration entry matches.</td></tr>';
  const originOptions = ['<option value="">every origin</option>'].concat(
    json.origins.map(function (name) {
      return '<option value="' + esc(name) + '"' +
        (json.filter.origin === name ? ' selected' : '') + '>' + esc(name) +
        '</option>';
    })).join('');
  const inner = messagesOf(req) + spiffePostureNote() +
    '<p>' + esc(json.total) + ' registration entry/entries, of at most ' +
    esc(json.max) + ' (<code>spiffe.maxEntries</code>). The store is the ' +
    'embedded directory under <code>' + esc(json.container) + '</code>: ' +
    'an <code>ldapmodify</code> there, a form here and the SPIRE Server API\'s ' +
    '<code>BatchUpdateEntry</code> are three doors onto one entry, and nothing ' +
    'caches it &mdash; so a change takes effect on the next SVID.</p>' +
    '<form method="get" action="/admin/spiffe/entries"><div class="formrow">' +
    '<label for="q">Search</label>' +
    '<input id="q" name="q" value="' + esc(json.filter.q) + '" size="28" ' +
    'placeholder="a SPIFFE ID, a selector, an entry id">' +
    '<label for="origin">Origin</label>' +
    '<select id="origin" name="origin">' + originOptions + '</select>' +
    '<label for="per">Rows</label>' +
    '<select id="per" name="per">' + perPageOptions(view.paging.perPage) +
    '</select><button class="secondary">Filter</button>' +
    '<span class="note">Origin is how the entry got here: <code>seed</code> ' +
    'at startup, <code>console</code>, <code>api</code>, <code>grpc</code>, ' +
    '<code>auto</code> (invented for a workload that matched nothing) or ' +
    '<code>ldap</code>.</span></div></form>' +
    '<table><tr><th>SPIFFE ID / entry id</th><th>Selectors</th><th>Origin</th>' +
    '<th>Hint</th><th>SVIDs</th><th>Revision</th></tr>' + rows + '</table>' +
    pageNav('/admin/spiffe/entries', filterOnly(listView), view.paging) +
    spiffeCreateEntryForm() ;
  log.debug("Leaving spiffeEntriesListPage().");
  return { json: json, inner: inner };
}

function spiffeCreateEntryForm() {
  return '<h2>Create a registration entry</h2>' +
    '<p>The SPIFFE ID must be in this trust domain and outside the reserved ' +
    '<code>/spire</code> path &mdash; those two refusals are the whole of what ' +
    'is checked. The parent defaults to this server\'s own identity, which is ' +
    'what SPIRE uses for an entry describing a workload rather than a node.</p>' +
    '<form method="post" action="/admin/spiffe/entries"><div class="formrow">' +
    '<input type="hidden" name="action" value="create">' +
    '<label for="e-id">SPIFFE ID</label>' +
    '<input id="e-id" name="spiffeId" size="40" placeholder="spiffe://' +
    esc(spiffeCa.trustDomain()) + '/ns/default/sa/web">' +
    '<label for="e-parent">Parent</label>' +
    '<input id="e-parent" name="parentId" size="34" placeholder="(this server)">' +
    '</div><div class="formrow">' +
    '<label for="e-sel">Selectors</label>' +
    '<input id="e-sel" name="selectors" size="40" ' +
    'placeholder="unix:uid:1000, k8s:ns:default">' +
    '<label for="e-dns">DNS names</label>' +
    '<input id="e-dns" name="dnsNames" size="26" placeholder="web.default.svc">' +
    '</div><div class="formrow">' +
    '<label for="e-x509ttl">X509-SVID TTL</label>' +
    '<input id="e-x509ttl" name="x509SvidTtl" size="6" placeholder="3600">' +
    '<label for="e-jwtttl">JWT-SVID TTL</label>' +
    '<input id="e-jwtttl" name="jwtSvidTtl" size="6" placeholder="300">' +
    '<label for="e-hint">Hint</label>' +
    '<input id="e-hint" name="hint" size="12" placeholder="internal">' +
    '<label for="e-fed">Federates with</label>' +
    '<input id="e-fed" name="federatesWith" size="20" placeholder="other.example">' +
    '<button>Create</button>' +
    '<span class="note">Selectors, DNS names and trust domains are ' +
    'comma-separated. A selector is <code>type:value</code>, split on the ' +
    'FIRST colon only &mdash; so <code>docker:label:app:web</code> is type ' +
    '<code>docker</code>.</span></div></form>';
}

function spiffeEntryDetailPage(req, id) {
  log.debug("Entering spiffeEntryDetailPage(). id=" + id);
  const entry = spiffeRegistry.entryById(id);
  const listView = listViewOf('/admin/spiffe/entries', req.query);
  const back = queryWith(listView, {});
  if (!entry) {
    log.debug("Leaving spiffeEntryDetailPage(). Not here.");
    return { json: { error: 'No registration entry has the id ' + id },
             inner: messagesOf(req) +
               '<p>No registration entry has the id <code>' + esc(id) +
               '</code>. It may have been deleted &mdash; from this page, ' +
               'with <code>BatchDeleteEntry</code>, or with an ' +
               '<code>ldapdelete</code> under <code>ou=entries,ou=spiffe</code>, ' +
               'which are three doors onto one store.</p>' +
               '<p><a href="/admin/spiffe/entries' + esc(back) +
               '">Back to the entries</a>.</p>' };
  }
  const attributeRows = Object.keys(entry.attributes || {}).sort()
    .map(function (name) {
      const value = entry.attributes[name];
      return '<tr><td><code>' + esc(name) + '</code></td><td>' +
        esc(Array.isArray(value) ? value.join(' | ') : String(value)) +
        '</td></tr>';
    }).join('');
  const json = { entry: entry, editable: spiffeRegistry.EDITABLE };
  const carried = '<input type="hidden" name="back" value="' + esc(back) + '">' +
                  '<input type="hidden" name="entry" value="' + esc(entry.id) + '">';
  const inner = messagesOf(req) + spiffePostureNote() +
    '<h2><code>' + esc(entry.spiffeId) + '</code></h2>' +
    '<p>Entry <code>' + esc(entry.id) + '</code>, revision ' +
    esc(entry.revisionNumber) + ', created by <code>' + esc(entry.origin) +
    '</code>. It lives at <code>' + esc(entry.dn) + '</code>' +
    (entry.expired ? ' and <strong>has expired</strong> &mdash; it is kept and ' +
      'reported rather than deleted, because an entry that vanished is ' +
      'indistinguishable from one nobody created' : '') + '.</p>' +
    '<table><tr><th>Field</th><th>Value</th></tr>' +
    '<tr><td>Parent</td><td><code>' + esc(entry.parentId) + '</code></td></tr>' +
    '<tr><td>Selectors</td><td>' +
    esc(entry.selectors.map(spiffeSelectorText).join(', ') ||
        '(none — this entry matches every workload)') + '</td></tr>' +
    '<tr><td>DNS names</td><td>' + esc(entry.dnsNames.join(', ') || '—') +
    '</td></tr>' +
    '<tr><td>Federates with</td><td>' +
    esc(entry.federatesWith.join(', ') || '—') + '</td></tr>' +
    '<tr><td>X509-SVID TTL</td><td>' +
    (entry.x509SvidTtl || ('default (' + esc(config.text('spiffe.svidTtl')) + ')')) +
    '</td></tr>' +
    '<tr><td>JWT-SVID TTL</td><td>' +
    (entry.jwtSvidTtl || ('default (' + esc(config.text('spiffe.jwtSvidTtl')) + ')')) +
    '</td></tr>' +
    '<tr><td>Hint</td><td>' + esc(entry.hint || '—') + '</td></tr>' +
    '<tr><td>admin / downstream / storeSvid</td><td>' +
    (entry.admin ? 'admin' : '') + (entry.downstream ? ' downstream' : '') +
    (entry.storeSvid ? ' storeSvid' : '') +
    ((entry.admin || entry.downstream || entry.storeSvid) ? '' : '—') +
    ' <span class="note">recorded and never read &mdash; nothing here decides ' +
    'anything on one</span></td></tr>' +
    '<tr><td>SVIDs issued</td><td>' + entry.svidsIssued +
    (entry.lastSvidAt ? ', most recently ' + esc(entry.lastSvidAt) : '') +
    '</td></tr></table>' +

    '<h3>Change it</h3>' +
    '<p>Only the DECLARED half is editable here &mdash; what the entry may DO. ' +
    'The derived half (the revision number, the SVID counter, when it was ' +
    'created) is what HAPPENED, and a form that could rewrite it would make ' +
    'this page lie about the service\'s own behaviour. <code>ldapmodify</code> ' +
    'reaches everything: refusing it here is the difference between offering ' +
    'an operation and merely not preventing it.</p>' +
    '<form method="post" action="/admin/spiffe/entries"><div class="formrow">' +
    '<input type="hidden" name="action" value="update">' + carried +
    '<label for="u-field">Field</label>' +
    '<select id="u-field" name="field">' +
    ['spiffeId', 'parentId', 'selectors', 'dnsNames', 'federatesWith',
     'x509SvidTtl', 'jwtSvidTtl', 'hint', 'expiresAt', 'admin', 'downstream',
     'storeSvid'].map(function (name) {
      return '<option value="' + esc(name) + '">' + esc(name) + '</option>';
    }).join('') + '</select>' +
    '<label for="u-value">Value</label>' +
    '<input id="u-value" name="value" size="40">' +
    '<button>Set</button>' +
    '<span class="note">A list field takes comma-separated values and an ' +
    'empty value clears it. A boolean takes true or false.</span>' +
    '</div></form>' +
    '<form method="post" action="/admin/spiffe/entries"><div class="formrow">' +
    '<input type="hidden" name="action" value="delete">' + carried +
    '<button class="danger">Delete this entry</button>' +
    '<span class="note">Whatever holds an SVID minted from it keeps that SVID ' +
    'until it expires. SPIFFE has no revocation &mdash; the answer is a short ' +
    'lifetime, which is why the default is an hour.</span></div></form>' +

    '<h3>The directory entry</h3>' +
    '<p>Every attribute, operational ones included. This is the store rather ' +
    'than a description of it.</p>' +
    '<table><tr><th>Attribute</th><th>Value</th></tr>' + attributeRows +
    '</table>';
  log.debug("Leaving spiffeEntryDetailPage().");
  return { json: json, inner: inner };
}

function spiffeEntriesView(req) {
  log.debug("Entering spiffeEntriesView().");
  const wanted = String(req.query.entry || '').trim();
  if (wanted) {
    const detail = spiffeEntryDetailPage(req, wanted);
    log.debug("Leaving spiffeEntriesView(). The drill-down.");
    return { json: detail.json, inner: detail.inner,
             title: 'Registration entry ' + wanted,
             up: upTo('/admin/spiffe/entries', wanted,
                      listViewOf('/admin/spiffe/entries', req.query)) };
  }
  const list = spiffeEntriesListPage(req);
  log.debug("Leaving spiffeEntriesView(). The list.");
  return { json: list.json, inner: list.inner, title: 'Registration entries' };
}

// ---------------------------------------------------------------------------
// THE AGENTS.
// ---------------------------------------------------------------------------
function spiffeAgentsJson(req) {
  log.debug("Entering spiffeAgentsJson().");
  const q = String(req.query.q || '').trim().toLowerCase();
  const all = spiffeRegistry.allAgents();
  const rows = all.filter(function (agent) {
    if (!q) return true;
    return (agent.id + ' ' + agent.attestationType + ' ' +
            agent.selectors.map(spiffeSelectorText).join(' ')).toLowerCase()
      .indexOf(q) >= 0;
  });
  const pg = pagingOf(req.query, rows.length, { unit: 'agent' });
  const json = {
    total: all.length,
    matched: rows.length,
    filter: { q: q },
    max: spiffeRegistry.maxAgents(),
    container: 'ou=agents,ou=spiffe',
    paging: { page: pg.page, pages: pg.pages, perPage: pg.perPage,
              total: pg.total },
    agents: rows.slice(pg.offset, pg.offset + pg.perPage)
  };
  log.debug("Leaving spiffeAgentsJson(). " + rows.length + " matched.");
  return { json: json, paging: pg };
}

function spiffeAgentsListPage(req) {
  log.debug("Entering spiffeAgentsListPage().");
  const view = spiffeAgentsJson(req);
  const json = view.json;
  const listView = listViewOf('/admin/spiffe/agents', req.query);
  const rows = json.agents.map(function (agent) {
    return '<tr><td><a href="/admin/spiffe/agents' +
      queryWith(listView, { agent: agent.id }) + '"><code>' +
      esc(agent.id) + '</code></a></td>' +
      '<td>' + esc(agent.attestationType) + '</td>' +
      '<td>' + (agent.banned ? '<strong>banned</strong>' : 'active') + '</td>' +
      '<td>' + agent.attestations + '</td>' +
      '<td>' + esc(agent.lastSeen || '—') + '</td></tr>';
  }).join('') || '<tr><td colspan="5">No agent has attested here. An agent ' +
    'appears when it calls <code>AttestAgent</code> on the SPIRE Server ' +
    'API.</td></tr>';
  const inner = messagesOf(req) + spiffePostureNote() +
    '<p>' + esc(json.total) + ' agent(s), of at most ' + esc(json.max) +
    ' (<code>spiffe.maxAgents</code>). These entries are a RECORD rather than ' +
    'configuration &mdash; everything on them was written by this service when ' +
    'an agent attested &mdash; which is why nothing about an agent is editable ' +
    'and only the ban is.</p>' +
    '<div class="warn"><strong>Node attestation is never verified.</strong> ' +
    'Whatever attestor an agent names and whatever payload it sends are ' +
    'written down as claimed. That is why every agent carries a selector ' +
    'valued <code>unverified:true</code>: an agent\'s selectors here are ' +
    'claims, not attested facts.</div>' +
    '<form method="get" action="/admin/spiffe/agents"><div class="formrow">' +
    '<label for="q">Search</label>' +
    '<input id="q" name="q" value="' + esc(json.filter.q) + '" size="30" ' +
    'placeholder="an agent id, an attestor, a selector">' +
    '<label for="per">Rows</label>' +
    '<select id="per" name="per">' + perPageOptions(view.paging.perPage) +
    '</select><button class="secondary">Filter</button></div></form>' +
    '<table><tr><th>Agent</th><th>Attestor</th><th>State</th>' +
    '<th>Attestations</th><th>Last seen</th></tr>' + rows + '</table>' +
    pageNav('/admin/spiffe/agents', filterOnly(listView), view.paging);
  log.debug("Leaving spiffeAgentsListPage().");
  return { json: json, inner: inner };
}

function spiffeAgentDetailPage(req, id) {
  log.debug("Entering spiffeAgentDetailPage(). id=" + id);
  const agent = spiffeRegistry.agentById(id);
  const listView = listViewOf('/admin/spiffe/agents', req.query);
  const back = queryWith(listView, {});
  if (!agent) {
    log.debug("Leaving spiffeAgentDetailPage(). Not here.");
    return { json: { error: 'No agent has attested here as ' + id },
             inner: messagesOf(req) +
               '<p>No agent has attested here as <code>' + esc(id) +
               '</code>.</p><p><a href="/admin/spiffe/agents' + esc(back) +
               '">Back to the agents</a>.</p>' };
  }
  const attributeRows = Object.keys(agent.attributes || {}).sort()
    .map(function (name) {
      const value = agent.attributes[name];
      return '<tr><td><code>' + esc(name) + '</code></td><td>' +
        esc(Array.isArray(value) ? value.join(' | ') : String(value)) +
        '</td></tr>';
    }).join('');
  const carried = '<input type="hidden" name="back" value="' + esc(back) + '">' +
                  '<input type="hidden" name="agent" value="' + esc(agent.id) + '">';
  const inner = messagesOf(req) + spiffePostureNote() +
    '<h2><code>' + esc(agent.id) + '</code></h2>' +
    '<p>Attested with <code>' + esc(agent.attestationType) + '</code>, ' +
    esc(agent.attestations) + ' time(s), first at ' + esc(agent.firstSeen) +
    ' and most recently at ' + esc(agent.lastSeen) + '. It lives at <code>' +
    esc(agent.dn) + '</code> &mdash; the RDN is a digest of the SPIFFE ID, ' +
    'because a SPIFFE ID is too long for a readable one, so <strong>the cn is ' +
    'not the identity here</strong>: <code>spiffeAgentId</code> is.</p>' +
    '<table><tr><th>Field</th><th>Value</th></tr>' +
    '<tr><td>State</td><td>' + (agent.banned
      ? '<strong>banned</strong> — AttestAgent refuses it, which is one of ' +
        'the few refusals in this service and is what keeps the button below ' +
        'from being a lie'
      : 'active') + '</td></tr>' +
    '<tr><td>Can reattest</td><td>' + (agent.canReattest ? 'yes' : 'no') +
    '</td></tr>' +
    '<tr><td>Selectors</td><td>' +
    esc(agent.selectors.map(spiffeSelectorText).join(', ') || '—') +
    ' <span class="note">claimed, never verified</span></td></tr>' +
    '<tr><td>SVID</td><td>' + esc(agent.svidHash || '—') +
    (agent.expiresAt ? ', expires ' +
      esc(new Date(agent.expiresAt * 1000).toISOString()) : '') +
    '</td></tr></table>' +
    '<form method="post" action="/admin/spiffe/agents"><div class="formrow">' +
    '<input type="hidden" name="action" value="' +
    (agent.banned ? 'unban' : 'ban') + '">' + carried +
    '<button class="' + (agent.banned ? 'secondary' : 'danger') + '">' +
    (agent.banned ? 'Unban' : 'Ban') + ' this agent</button>' +
    '<span class="note">A banned agent is refused at <code>AttestAgent</code> ' +
    'with <code>PermissionDenied</code>. Whatever SVID it already holds keeps ' +
    'working until it expires &mdash; there is no revocation in SPIFFE.</span>' +
    '</div></form>' +
    '<form method="post" action="/admin/spiffe/agents"><div class="formrow">' +
    '<input type="hidden" name="action" value="delete">' + carried +
    '<button class="danger">Delete this agent</button>' +
    '<span class="note">It reappears the next time it attests, because ' +
    'attestation is not checked &mdash; deleting is forgetting, not ' +
    'revoking.</span></div></form>' +
    '<h3>The directory entry</h3>' +
    '<table><tr><th>Attribute</th><th>Value</th></tr>' + attributeRows +
    '</table>';
  log.debug("Leaving spiffeAgentDetailPage().");
  return { json: { agent: agent }, inner: inner };
}

function spiffeAgentsView(req) {
  log.debug("Entering spiffeAgentsView().");
  const wanted = String(req.query.agent || '').trim();
  if (wanted) {
    const detail = spiffeAgentDetailPage(req, wanted);
    log.debug("Leaving spiffeAgentsView(). The drill-down.");
    return { json: detail.json, inner: detail.inner, title: 'Agent ' + wanted,
             up: upTo('/admin/spiffe/agents', wanted,
                      listViewOf('/admin/spiffe/agents', req.query)) };
  }
  const list = spiffeAgentsListPage(req);
  log.debug("Leaving spiffeAgentsView(). The list.");
  return { json: list.json, inner: list.inner, title: 'Attested agents' };
}

// ---------------------------------------------------------------------------
// THE ACTIONS.
//
// Three handlers, one per page, and each is what BOTH the console form and the
// management API call — with `action` taken from the URL there instead of from
// a hidden input here. That is rule 7's arrangement, and it is what makes an
// API operation most of the cost of a console control rather than a second
// implementation of it.
//
// Each returns `{ ok, errors, message }` and DECIDES NOTHING ITSELF: the work
// is in `spiffe_registry.js` and `spiffe_ca.js`, which the SPIRE Server API
// also calls.
// ---------------------------------------------------------------------------
function spiffeCommaList(value) {
  return String(value == null ? '' : value).split(',')
    .map(function (part) { return part.trim(); })
    .filter(Boolean);
}

// The known actions, as a list, so that an unknown one can be answered by
// NAMING the ones that exist. The parent project's tests/admin_api.js reads
// exactly that reply to assert console/API parity — it asks each handler for an
// action that does not exist and compares what comes back with the API's
// operations — so this list is not decoration.
const SPIFFE_ACTIONS = ['rotate', 'federation-set', 'federation-remove'];
const SPIFFE_ENTRY_ACTIONS = ['create', 'update', 'delete'];
const SPIFFE_AGENT_ACTIONS = ['ban', 'unban', 'delete'];

function spiffeUnknownAction(action, known) {
  return { ok: false, errors: ['Unknown action "' + String(action) + '". ' +
    'The actions here are: ' + known.join(', ') + '.'] };
}

async function spiffeAction(body) {
  log.debug("Entering spiffeAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  if (action === 'rotate') {
    const which = String(body.which || 'x509');
    const done = [];
    try {
      if (which === 'x509' || which === 'both') {
        const authority = await spiffeCa.rotateX509Authority();
        done.push('a new X.509 authority (' + authority.id + ')');
      }
      if (which === 'jwt' || which === 'both') {
        const authority = await spiffeCa.rotateJwtAuthority();
        done.push('a new JWT authority (kid ' + authority.id + ')');
      }
    } catch (e) {
      log.debug("Leaving spiffeAction(). Rotation failed.");
      return { ok: false, errors: ['The authority could not be rotated: ' +
                                   e.message] };
    }
    if (!done.length) {
      log.debug("Leaving spiffeAction(). Nothing named.");
      return { ok: false, errors: ['Rotate what? `which` is x509, jwt or both.'] };
    }
    auditLog.audit({ action: 'spiffe.bundle.change', actor: '', protocol: 'SPIFFE',
                  channel: 'internal', target: spiffeCa.trustDomainId(),
                  summary: 'An authority was rotated from the console',
                  detail: { which: which, sequence: spiffeCa.sequence() } });
    log.debug("Leaving spiffeAction(). Rotated.");
    return { ok: true, message: 'Rotated: ' + done.join(' and ') + '. The ' +
      'previous authority is still published in the bundle, so SVIDs already ' +
      'issued go on verifying; the bundle sequence is now ' +
      spiffeCa.sequence() + '.' };
  }

  if (action === 'federation-set') {
    const name = String(body.trustDomain || '').trim().toLowerCase();
    if (!name) {
      log.debug("Leaving spiffeAction(). No trust domain.");
      return { ok: false, errors: ['Which trust domain? Send `trustDomain` ' +
                                   'with its name — other.example, not ' +
                                   'spiffe://other.example.'] };
    }
    const result = spiffeCa.setFederatedBundle(name, body.document, {
      bundleEndpointUrl: String(body.bundleEndpointUrl || ''),
      bundleEndpointProfile: String(body.bundleEndpointProfile || 'https_web'),
      endpointSpiffeId: String(body.endpointSpiffeId || '')
    });
    if (!result.ok) {
      log.debug("Leaving spiffeAction(). Refused.");
      return { ok: false, errors: [result.reason] };
    }
    auditLog.audit({ action: 'spiffe.bundle.change', actor: '', protocol: 'SPIFFE',
                  channel: 'internal', target: name,
                  summary: 'A federated bundle for ' + name + ' was set from ' +
                           'the console',
                  detail: { created: result.created } });
    log.debug("Leaving spiffeAction(). Federated bundle set.");
    return { ok: true, message: 'The bundle for ' + name + ' was ' +
      (result.created ? 'added' : 'replaced') + '. Any registration entry that ' +
      'federates with it will now hand it to its workloads. The endpoint URL ' +
      'is recorded and will not be fetched — see the note on this page.' };
  }

  if (action === 'federation-remove') {
    const name = String(body.trustDomain || '').trim().toLowerCase();
    const removed = spiffeCa.deleteFederatedBundle(name);
    if (!removed) {
      log.debug("Leaving spiffeAction(). Not held.");
      return { ok: false, errors: ['This service holds no bundle for the ' +
                                   'trust domain ' + name + '.'] };
    }
    auditLog.audit({ action: 'spiffe.bundle.change', actor: '', protocol: 'SPIFFE',
                  channel: 'internal', target: name,
                  summary: 'A federated bundle for ' + name + ' was removed ' +
                           'from the console', detail: {} });
    log.debug("Leaving spiffeAction(). Removed.");
    return { ok: true, message: 'The bundle for ' + name + ' is gone. Any ' +
      'entry that federates with it keeps the name and simply contributes no ' +
      'bundle, which is the same state as a relationship configured before its ' +
      'bundle arrives.' };
  }

  log.debug("Leaving spiffeAction(). Unknown action.");
  return spiffeUnknownAction(action, SPIFFE_ACTIONS);
}

function spiffeEntriesAction(body) {
  log.debug("Entering spiffeEntriesAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const trustDomain = spiffeCa.trustDomain();

  if (action === 'create') {
    const result = spiffeRegistry.createEntry({
      spiffeId: String(body.spiffeId || '').trim(),
      parentId: String(body.parentId || '').trim() ||
                spiffeIdLib.serverId(trustDomain),
      selectors: spiffeCommaList(body.selectors)
        .map(spiffeRegistry.parseSelector).filter(Boolean),
      dnsNames: spiffeCommaList(body.dnsNames),
      federatesWith: spiffeCommaList(body.federatesWith),
      x509SvidTtl: parseInt(String(body.x509SvidTtl || '0'), 10) || 0,
      jwtSvidTtl: parseInt(String(body.jwtSvidTtl || '0'), 10) || 0,
      hint: String(body.hint || '').trim()
    }, 'console', trustDomain, '');
    log.debug("Leaving spiffeEntriesAction(). create " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) return result;
    return { ok: true, id: result.id, entry: result.entry,
             message: 'The entry is in the registry as ' + result.id +
                      '. The next FetchX509SVID will include an SVID ' +
                      'for ' + result.entry.spiffeId + ' — this service hands ' +
                      'every caller every identity, so the selectors do not ' +
                      'narrow that.' };
  }

  if (action === 'update') {
    const id = String(body.entry || '').trim();
    if (!id) {
      log.debug("Leaving spiffeEntriesAction(). No entry named.");
      return { ok: false, errors: ['Which entry? Send `entry` with its id.'] };
    }
    const field = String(body.field || '').trim();
    if (spiffeRegistry.EDITABLE.indexOf(fieldToAttribute(field)) < 0) {
      log.debug("Leaving spiffeEntriesAction(). Not editable.");
      return { ok: false, errors: ['"' + field + '" is not a field this page ' +
        'may change. The editable ones are what the entry may DO: ' +
        'spiffeId, parentId, selectors, dnsNames, federatesWith, ' +
        'x509SvidTtl, jwtSvidTtl, hint, expiresAt, admin, downstream, ' +
        'storeSvid. The rest is what HAPPENED, and only ldapmodify reaches it.'] };
    }
    const raw = body.value === undefined ? '' : String(body.value);
    const changes = {};
    if (field === 'selectors') {
      changes.selectors = spiffeCommaList(raw)
        .map(spiffeRegistry.parseSelector).filter(Boolean);
    } else if (field === 'dnsNames' || field === 'federatesWith') {
      changes[field] = spiffeCommaList(raw);
    } else if (field === 'x509SvidTtl' || field === 'jwtSvidTtl' ||
               field === 'expiresAt') {
      changes[field] = parseInt(raw, 10) || 0;
    } else if (field === 'admin' || field === 'downstream' ||
               field === 'storeSvid') {
      changes[field] = /^(1|true|yes|on)$/i.test(raw.trim());
    } else {
      changes[field] = raw.trim();
    }
    const result = spiffeRegistry.updateEntry(id, changes, trustDomain, '');
    log.debug("Leaving spiffeEntriesAction(). update " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) return result;
    return { ok: true, id: id, entry: result.entry,
             message: field + ' is set. The entry is now at revision ' +
                      result.entry.revisionNumber + ', and the change applies ' +
                      'to the NEXT SVID issued from it — nothing caches this ' +
                      'and nothing already issued changes.' };
  }

  if (action === 'delete') {
    const id = String(body.entry || '').trim();
    if (!id) {
      log.debug("Leaving spiffeEntriesAction(). No entry named.");
      return { ok: false, errors: ['Which entry? Send `entry` with its id.'] };
    }
    const result = spiffeRegistry.deleteEntry(id, '');
    log.debug("Leaving spiffeEntriesAction(). delete " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) return result;
    return { ok: true, id: id,
             message: 'The entry is gone. Anything holding an SVID minted from ' +
                      'it keeps that SVID until it expires — SPIFFE has no ' +
                      'revocation.' };
  }

  log.debug("Leaving spiffeEntriesAction(). Unknown action.");
  return spiffeUnknownAction(action, SPIFFE_ENTRY_ACTIONS);
}

// The console names a field the way the record does and the EDITABLE table
// names it the way the DIRECTORY does. One map, here, rather than two
// vocabularies that drift: a form offering `dnsNames` while the table says
// `spiffeDnsName` would refuse every edit the form offers.
const SPIFFE_FIELD_ATTRIBUTES = {
  spiffeId: 'spiffeId', parentId: 'spiffeParentId', selectors: 'spiffeSelector',
  dnsNames: 'spiffeDnsName', federatesWith: 'spiffeFederatesWith',
  x509SvidTtl: 'spiffeX509SvidTtl', jwtSvidTtl: 'spiffeJwtSvidTtl',
  hint: 'spiffeHint', expiresAt: 'spiffeEntryExpiresAt', admin: 'spiffeAdmin',
  downstream: 'spiffeDownstream', storeSvid: 'spiffeStoreSvid'
};

function fieldToAttribute(field) {
  return SPIFFE_FIELD_ATTRIBUTES[String(field)] || '';
}

function spiffeAgentsAction(body) {
  log.debug("Entering spiffeAgentsAction(). action=" + (body.action || '(none)'));
  const action = String(body.action || '');
  const id = String(body.agent || '').trim();
  if (SPIFFE_AGENT_ACTIONS.indexOf(action) >= 0 && !id) {
    log.debug("Leaving spiffeAgentsAction(). No agent named.");
    return { ok: false, errors: ['Which agent? Send `agent` with its SPIFFE ' +
                                 'ID, which is under /spire/agent/.'] };
  }
  if (action === 'ban' || action === 'unban') {
    const result = spiffeRegistry.setAgentBanned(id, action === 'ban', '');
    log.debug("Leaving spiffeAgentsAction(). " + action + " " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) return result;
    return { ok: true, id: id, agent: result.agent,
             message: action === 'ban'
               ? 'That agent is banned: AttestAgent now refuses it with ' +
                 'PermissionDenied. Whatever SVID it already holds keeps ' +
                 'working until it expires.'
               : 'That agent may attest again.' };
  }
  if (action === 'delete') {
    const result = spiffeRegistry.deleteAgent(id, '');
    log.debug("Leaving spiffeAgentsAction(). delete " +
              (result.ok ? 'ok' : 'refused') + ".");
    if (!result.ok) return result;
    return { ok: true, id: id,
             message: 'That agent is forgotten. It reappears the moment it ' +
                      'attests again, because attestation is not checked — ' +
                      'deleting is forgetting, not revoking. Ban it instead if ' +
                      'that is what you meant.' };
  }
  log.debug("Leaving spiffeAgentsAction(). Unknown action.");
  return spiffeUnknownAction(action, SPIFFE_AGENT_ACTIONS);
}

// ---------------------------------------------------------------------------
// THE ROUTES.
// ---------------------------------------------------------------------------
app.get('/admin/spiffe', function (req, res) {
  log.debug("Entering the admin SPIFFE page.");
  const view = spiffePage(req);
  respond(req, res, view.json, view.title, '/admin/spiffe', view.inner);
  log.debug("Leaving the admin SPIFFE page.");
});

// The one action handler here that is ASYNCHRONOUS, because rotating an
// authority generates a key and key generation is async. `respondToAction`
// takes the resolved result, so the await is here rather than inside it — every
// other action in this console is synchronous and making that function async
// would change the shape of all of them for one caller.
app.post('/admin/spiffe', function (req, res) {
  log.debug("Entering the admin SPIFFE action endpoint.");
  const body = parseBody(req);
  spiffeAction(body).then(function (result) {
    respondToAction(req, res, '/admin/spiffe', result);
    log.debug("Leaving the admin SPIFFE action endpoint.");
  }).catch(function (err) {
    // A throw out of the action itself. Answered rather than left to express's
    // handler, which would replace the Content-Security-Policy header — see the
    // frame-ancestors note in CLAUDE.md.
    log.error('The SPIFFE console action threw: ' + err.message);
    respondToAction(req, res, '/admin/spiffe',
                    { ok: false, errors: [err.message] });
    log.debug("Leaving the admin SPIFFE action endpoint. It threw.");
  });
});

app.get('/admin/spiffe/entries', function (req, res) {
  log.debug("Entering the admin SPIFFE entries page.");
  const view = spiffeEntriesView(req);
  respond(req, res, view.json, view.title, '/admin/spiffe/entries', view.inner,
          view.up);
  log.debug("Leaving the admin SPIFFE entries page. " + view.title + ".");
});

app.post('/admin/spiffe/entries', function (req, res) {
  log.debug("Entering the admin SPIFFE entries action endpoint.");
  const body = parseBody(req);
  const result = spiffeEntriesAction(body);
  // Back to the drill-down the form was posted from where there was one, and
  // carrying the list state off the form's `back` field either way — so an edit
  // does not silently cost the reader their place in the list. Rule 7a: a new
  // form on this page needs `carryBack` in it, and nothing can check that it
  // has one.
  const listView = listViewFromBack('/admin/spiffe/entries', body.back);
  const target = String(body.entry || '').trim() && result.ok !== false
    ? '/admin/spiffe/entries' + queryWith(listView,
        { entry: String(body.entry).trim() })
    : '/admin/spiffe/entries' + queryWith(listView, {});
  respondToAction(req, res, target, result);
  log.debug("Leaving the admin SPIFFE entries action endpoint.");
});

app.get('/admin/spiffe/agents', function (req, res) {
  log.debug("Entering the admin SPIFFE agents page.");
  const view = spiffeAgentsView(req);
  respond(req, res, view.json, view.title, '/admin/spiffe/agents', view.inner,
          view.up);
  log.debug("Leaving the admin SPIFFE agents page. " + view.title + ".");
});

app.post('/admin/spiffe/agents', function (req, res) {
  log.debug("Entering the admin SPIFFE agents action endpoint.");
  const body = parseBody(req);
  const result = spiffeAgentsAction(body);
  const listView = listViewFromBack('/admin/spiffe/agents', body.back);
  const target = String(body.agent || '').trim() && result.ok !== false &&
                 String(body.action || '') !== 'delete'
    ? '/admin/spiffe/agents' + queryWith(listView,
        { agent: String(body.agent).trim() })
    : '/admin/spiffe/agents' + queryWith(listView, {});
  respondToAction(req, res, target, result);
  log.debug("Leaving the admin SPIFFE agents action endpoint.");
});


module.exports = {
  // Filled by ldap_server.js at its require time; see the note above it.
  setDirectoryReader: setDirectoryReader,
  // Filled by spiffe_server.js at its require time, for the reason beside the
  // requires at the top: this file must not require that module.
  setSpiffeReader: setSpiffeReader,
  setScimReader: setScimReader,
  setGroupReader: setGroupReader,
  setDirectoryWriter: setDirectoryWriter,
  usersAction: usersAction,
  jtiFrom: jtiFrom,
  // The four action functions. admin_api.js calls exactly these — it decides
  // nothing about a revocation or a claim that this console does not — which is
  // what makes "every /admin control has an /admin-api operation" a property of
  // the code rather than a promise in a comment.
  tokenAction: tokenAction,
  claimsAction: claimsAction,
  vcAction: vcAction,
  vpConfigAction: vpConfigAction,
  configAction: configAction,
  // The JSON views, one per page, for the same reason. See the block comment
  // above consoleJson().
  consoleJson: consoleJson,
  metricsJson: metricsJson,
  tokensView: tokensView,
  // The audit log's view is the whole function rather than a JSON builder, for
  // the reason the block above consoleJson() gives: the filtering and the paging
  // are work both the page and the API need, and two copies of it would be two
  // answers that each looked right alone.
  auditView: auditView,
  usersView: usersView,
  groupsView: groupsView,
  applicationsView: applicationsView,
  applicationsAction: applicationsAction,
  // The three SPIFFE views and their three action handlers. admin_api.js calls
  // exactly these — rule 7 again: the API decides nothing the console does not,
  // and an action added to one of these switches is most of adding it there.
  spiffeView: spiffePage,
  spiffeAction: spiffeAction,
  spiffeEntriesView: spiffeEntriesView,
  spiffeEntriesAction: spiffeEntriesAction,
  spiffeAgentsView: spiffeAgentsView,
  spiffeAgentsAction: spiffeAgentsAction,
  authorizationServersView: authorizationServersView,
  authorizationServersAction: asAction,
  claimsJson: claimsJson,
  // Which person the claims page shows attribute values for. Exported for the
  // same reason vcPreviewUser is: GET /admin-api/claims takes the same `user`
  // parameter, and a second reader of that query string would be a second cap
  // and a second default.
  claimsPreviewUser: claimsPreviewUser,
  vcJson: vcJson,
  vcPreviewUser: vcPreviewUser,
  vpConfigJson: vpConfigJson,
  scimJson: scimJson,
  configJson: configJson,
  // A body field that may appear more than once. Exported because the
  // management API takes the same two spellings of a list (`attribute` and
  // `attributes`), and reading a repeated form field is not something
  // helpers.parseBody() can answer.
  listField: listField,
  // The console's own paging rules, so that /admin-api reports and clamps `per`
  // and `page` the way every page here does rather than inventing a second
  // ceiling.
  MAX_ROWS: MAX_ROWS,
  DEFAULT_PER_PAGE: DEFAULT_PER_PAGE,
  // The drill-downs' session blocks start smaller, and the API documents that
  // number rather than repeating it: a document saying 50 beside a service doing
  // 5 is worse than a document that says nothing.
  DEFAULT_BLOCKS_PER_PAGE: DEFAULT_BLOCKS_PER_PAGE
};
