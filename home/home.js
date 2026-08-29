'use strict';
//
// File: home.js
//
// ---------------------------------------------------------------------------
// GET / — the front door.
//
// Until 2026-08-24 the root of this service was an unrouted path, so the first
// thing anybody who typed the host and port into a browser saw was Express's
// `Cannot GET /`. That is a true statement about the router and a useless one
// about the service: this port answers well over a hundred endpoints across
// sixteen protocol families, and none of them is discoverable from the one URL
// a person types first.
//
// So this page exists, and it is deliberately SHORT. It carries the logo of the
// project this service was extracted from, says what this service is called,
// and offers four links — the repository, its issues, the documentation site,
// and the admin console on THIS instance. It is a signpost, not a second
// documentation site.
//
// **IT DOES NOT LIST ENDPOINTS, AND THAT IS THE ONE RULE TO KEEP.**
// `GET /admin/sts-metadata` builds that list by walking the running Express
// router, so it cannot go stale by omission, and the parent project's
// `tests/vendored/sts_metadata.js` fails on drift in either direction. A hand-written
// list of highlights here would be a second, unchecked copy of it — wrong
// within a month, on the page most likely to be read first and least likely to
// be re-read. The documentation site makes the same argument in
// `docs/endpoints.md` and this page holds to it: LINK to the thing that
// generates the list.
//
// ---------------------------------------------------------------------------
// TWO ROUTES, AND THE SECOND ONE IS A PNG.
//
// `/logo.png` serves `assets/debugger-logo.png` from this directory. It is a
// route rather than `express.static()` because one file does not need a static
// middleware, and a middleware mounted at the root would sit in front of every
// protocol module's routes for the rest of the process's life — see rule 1 in
// the repository's CLAUDE.md: requiring a module registers its endpoints, and
// middleware applies to everything registered after it.
//
// The file is read ONCE, here, at require time. A per-request read would be a
// disk hit for a decoration; the file cannot change while the process runs.
//
// **A failure to read it is recorded, not thrown.** A `require` that throws
// takes the whole service down — the same reason the KDC, the directory, the
// TLS endpoint and the SPIFFE listeners start their sockets from `listen()`
// rather than at require time — and a missing image is the least important
// thing that could go wrong here. With no image the page is drawn without one
// and `/logo.png` answers 404 with a sentence saying why, which is also what
// keeps that route honest for the link check in `tests/vendored/sts_metadata.js`: it
// fails on Express's own `Cannot GET`, so an endpoint answering for itself is
// the distinction it is looking for.
//
// ---------------------------------------------------------------------------
// THE IMAGE IS ON A BLACK BAND AND THAT IS NOT A STYLE CHOICE.
//
// The logo is the parent project's transparent one: white lettering with a dark
// outline, a green wordmark and a pale-blue mark, drawn to sit on a dark
// ground. On this file's own card background the "IYA CYBER SECURITY" half all
// but disappears. The band behind it is black for the same reason the parent
// project ships a black-backed copy of the same artwork on its error pages —
// it is what the artwork was drawn for.
//
// The asset is a DERIVATIVE rather than a byte-identical copy, which is why it
// is here and not in `common/vendored/` (that directory's rule is that its
// files match the parent's byte for byte, and two of the parent's tests hold
// them to it). It was produced from
// `client/public/images/oauth2oidcdebugger+iyasec-logo-transparent.png` — 2172
// x724 and 745 kB — with:
//
//     convert <source> -resize 720x -strip PNG32:debugger-logo.png
//     convert debugger-logo.png -colors 256 PNG8:debugger-logo.png
//     optipng -o5 debugger-logo.png
//
// 720px is twice the width it is drawn at, so it stays sharp on a 2x display,
// and 256 colours takes it to 31 kB. Re-run those three lines if the parent's
// artwork changes.
//
// ---------------------------------------------------------------------------
// NO SCRIPT, NO EXTERNAL RESOURCE.
//
// `app.js` sets `script-src 'none'` service-wide and this page needs no
// exception: it has no behaviour. Its one `<style>` block is covered by the
// `style-src 'unsafe-inline'` six other pages here already rely on, and the
// image is same-origin, which is what `img-src 'self' data:` already allows.
// A page that reached out to a CDN for a font would need the policy widened
// for a decoration, so it does not.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const app = require('../common/app');
const { log, xmlEscape, baseUrlOf } = require('../common/helpers');
// The trust realm registry, for GET /realms below.
const realms = require('../common/realms');
// For ONE sentence: whether the console asks the reader to sign in. It is a
// runtime setting (`/admin/config` and the management API can turn it off
// while the process runs), so it is read per request rather than captured
// here — a front page that said "it will ask you to sign in" over a console
// that does not is exactly the kind of small lie that costs somebody ten
// minutes.
const config = require('../common/config');
// For the version line only. `admin_api.js` reads it the same way, which is the
// precedent for requiring the manifest rather than threading a constant.
const VERSION = require('../package.json').version;

// ---------------------------------------------------------------------------
// THE FOUR LINKS.
//
// Three of them name the repository this service lives in, and they are
// written out rather than derived from `package.json` — that manifest carries
// no `repository` member, and adding one so that this page could compute three
// URLs from it would be the kind of indirection that makes a reader open two
// files to answer "where does this link go".
//
// The documentation URL is GitHub Pages' own arrangement of the same
// repository: `docs/` is built and deployed by `.github/workflows/pages.yml`,
// and `docs/_config.yml` sets `baseurl: /mock-sts`, so the site is served under
// the repository name. Change the repository and all three of these change
// together — and so does that baseurl.
// ---------------------------------------------------------------------------
const REPO_URL = 'https://github.com/rcbj/mock-sts';
const ISSUES_URL = REPO_URL + '/issues';
const DOCS_URL = 'https://rcbj.github.io/mock-sts/';
// Relative on purpose. This service is reached as localhost, as `sts` on a
// compose network and through a published port, and `baseUrlOf()` exists
// because documents that carry absolute URLs have to follow the request. A
// same-origin link does not have to know any of that.
const CONSOLE_PATH = '/admin';

const LOGO_PATH = path.join(__dirname, 'assets', 'debugger-logo.png');
const LOGO_ROUTE = '/logo.png';

// Read once, at require time. See the header for why a failure here is recorded
// rather than thrown.
let logoBytes = null;
try {
  logoBytes = fs.readFileSync(LOGO_PATH);
  log.debug('home: the logo is ' + logoBytes.length + ' bytes.');
} catch (e) {
  // Swallowed deliberately, and this is the whole reason: the front page is a
  // signpost and the image on it is decoration. Losing it must not stop a
  // service that speaks sixteen protocols from starting, so it is reported at
  // error level — where it is visible — and the page is drawn without it.
  logoBytes = null;
  log.error('home: the logo could not be read from ' + LOGO_PATH + ': ' +
            e.message + '. The front page will be drawn without it and ' +
            LOGO_ROUTE + ' will answer 404.');
}

// ---------------------------------------------------------------------------
// Rendering. One card, in the same material as `/tls` and the console, so that
// a reader who follows a link from here does not arrive somewhere that looks
// like a different service.
// ---------------------------------------------------------------------------

function linkRow(href, label, external, note) {
  return '<li><a href="' + xmlEscape(href) + '"' +
    (external ? ' target="_blank" rel="noopener noreferrer"' : '') + '>' +
    xmlEscape(label) + '</a><span class="note">' + xmlEscape(note) +
    '</span></li>';
}

function homePage() {
  log.debug('Entering homePage().');
  const logo = logoBytes
    ? '<div class="hero"><img src="' + LOGO_ROUTE + '" width="720" ' +
      'height="240" alt="OAuth2 / OIDC / SAML2 Debugger — Iya Cyber ' +
      'Security"></div>'
    : '';
  const html = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>mock-sts</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;' +
    'background:#f4f4f7;margin:0;padding:2rem 1rem;color:#222;line-height:1.45}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;' +
    'padding:0 0 26px;max-width:44rem;margin:0 auto;overflow:hidden;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}' +
    // The band the artwork was drawn for. See the header.
    '.hero{background:#000;padding:22px 24px;text-align:center}' +
    '.hero img{width:100%;max-width:360px;height:auto;display:inline-block}' +
    '.body{padding:22px 28px 0}' +
    'h1{font-size:1.5em;margin:0 0 2px;color:#12107c;letter-spacing:.01em}' +
    'p.sub{color:#666;font-size:.88em;margin:0 0 4px}' +
    'p.ver{color:#8a8a99;font-size:.76em;margin:0 0 16px}' +
    '.warn{background:#fff8e1;border:1px solid #ffe082;padding:9px 12px;' +
    'border-radius:5px;font-size:.82em;margin:0 0 18px}' +
    'ul{list-style:none;margin:0;padding:0}' +
    'li{border-top:1px solid #eee;padding:11px 2px}' +
    'li:first-child{border-top:0}' +
    'a{color:#12107c;font-weight:600;text-decoration:none}' +
    'a:hover{text-decoration:underline}' +
    '.note{display:block;color:#666;font-size:.8em;font-weight:400;' +
    'margin-top:2px}' +
    '</style></head><body><div class="card">' + logo + '<div class="body">' +
    '<h1>mock-sts</h1>' +
    '<p class="sub">A permissive mock identity service that speaks sixteen ' +
    'protocol families. It exists to exercise CLIENTS.</p>' +
    '<p class="ver">version ' + xmlEscape(VERSION) + '</p>' +
    '<div class="warn">It checks no password, validates no access token and ' +
    'attests no workload. Do not put this port on a public address.</div>' +
    '<ul>' +
    linkRow(REPO_URL, 'The project on GitHub', true,
            'The source, the README, and the sixteen families in full.') +
    linkRow(ISSUES_URL, 'Issues', true,
            'What is known to be wrong, and where to say what is not.') +
    linkRow(DOCS_URL, 'Documentation', true,
            'The GitHub Pages site: getting started, configuration, and ' +
            'what is deliberately not checked.') +
    linkRow(CONSOLE_PATH, 'The admin console on this instance', false,
            'Everything this process has done, and the settings that change ' +
            'what its protocol endpoints do. ' +
            (config.value('admin.authRequired')
              ? 'It asks you to sign in, and nothing else here does — any ' +
                'username, no password checked.'
              : 'It is open: admin.authRequired is off on this instance.') +
            ' Every endpoint this service registered is listed inside it, ' +
            'at /admin/sts-metadata.') +
    '</ul></div></div></body></html>\n';
  log.debug('Leaving homePage().');
  return html;
}

app.get('/', function (req, res) {
  log.debug('Entering the front page endpoint.');
  res.type('html').send(homePage());
  log.debug('Leaving the front page endpoint.');
});

// ---------------------------------------------------------------------------
// GET /realms — THE TRUST REALM DIRECTORY, AND IT IS DELIBERATELY UNGATED.
//
// A trust realm is a whole logical copy of this service reached under a path
// prefix (see common/realms.js), and a client that has been told to use one has
// no way to find out what the prefix is — the prefix segment is configurable
// and the realm ids are whatever an operator defined. So this answers it, in
// JSON, to anybody who can reach this port.
//
// It is on the FRONT DOOR module rather than in the console because of who
// needs it: the console already knows, and the thing that does not is the
// client being pointed at a realm. Gating it would make the one document that
// says where the endpoints are the one document a client cannot fetch, which is
// the shape of every RFC 8414 discovery document here and for the same reason.
//
// WHAT IT DOES NOT CARRY: a realm's overrides. Those are the realm's
// configuration — what it is set up to do differently — and that is the console
// and the management API's business rather than a discovery document's. What is
// here is the id, the name, the description an operator wrote and the base URL,
// which is everything needed to construct a URL in that realm and nothing else.
// ---------------------------------------------------------------------------
app.get('/realms', function (req, res) {
  log.debug('Entering the realm directory endpoint.');
  // The base URL WITHOUT the current realm's prefix, so that a request that
  // arrived inside realm `acme` still lists every realm from the root rather
  // than listing them all as though they hung under `acme`. baseUrlOf() adds
  // the ambient prefix by design — this is the one caller that does not want
  // it, and it says so here rather than working around it elsewhere.
  const root = baseUrlOf(req).slice(0, baseUrlOf(req).length -
                                       realms.currentPrefix().length);
  const body = {
    // What the segment in front of a realm id currently is, because a client
    // that wants to build a URL for a realm it has NOT been told about — a new
    // one, in a test — needs the rule and not just the answers.
    pathSegment: realms.pathSegment(),
    // TWO FLAGS RATHER THAN ONE, because they answer different questions and a
    // single `enabled` was ambiguous in exactly the case that matters. `enabled`
    // is the `realms.enabled` SETTING — whether an operator has switched the
    // feature off. `active` is whether any prefix actually answers, which is
    // false when the setting is on and nobody has defined a realm. A client
    // told "enabled: false" when the truth was "nobody has defined one yet"
    // would look for the wrong problem.
    enabled: config.value('realms.enabled'),
    active: realms.active(),
    current: realms.currentId(),
    realms: realms.list().map(function (realm) {
      return {
        id: realm.id,
        name: realm.name,
        description: realm.description,
        builtin: !!realm.builtin,
        pathPrefix: realms.prefixOf(realm),
        baseUrl: root + realms.prefixOf(realm)
      };
    }),
    // Which protocol families are realm-aware and by what discriminator. It is
    // here rather than only on the console page because the honest answer for
    // four of the sixteen families is "not by path", and a client driving
    // Kerberos or LDAP against a realm needs to be told that by the service
    // rather than by a README it did not read.
    support: realms.realmSupport()
  };
  res.set('Cache-Control', 'no-store').type('application/json')
     .send(JSON.stringify(body, null, 2));
  log.debug('Leaving the realm directory endpoint. ' + body.realms.length + ' realm(s).');
});

app.get(LOGO_ROUTE, function (req, res) {
  log.debug('Entering the logo endpoint.');
  if (!logoBytes) {
    // 404 in this service's own words rather than Express's. The difference is
    // load-bearing for the link check in the parent project's
    // tests/vendored/sts_metadata.js, which fails on `Cannot GET` and passes on an
    // endpoint answering for itself — and it is the more useful answer anyway.
    res.status(404).type('text/plain')
      .send('The logo could not be read from disk at startup. The service ' +
            'log says why; nothing else about this service is affected.\n');
    log.debug('Leaving the logo endpoint. There is no logo.');
    return;
  }
  // An hour. The bytes cannot change while this process runs, and this is a
  // mock whose whole traffic is one browser: a longer max-age would only make
  // a rebuilt image's new logo linger.
  res.set('Cache-Control', 'public, max-age=3600');
  res.type('png').send(logoBytes);
  log.debug('Leaving the logo endpoint.');
});

// Nothing is exported. This module is required for its side effect — two
// routes — the way every other route module here is, and the three URLs above
// are this page's business alone. See rule 1 in the repository's CLAUDE.md.
