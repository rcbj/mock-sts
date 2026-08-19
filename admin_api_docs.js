'use strict';
//
// File: admin_api_docs.js
//
// ---------------------------------------------------------------------------
// The API explorer: one page that reads /admin-api/openapi.json and renders a
// form per operation that calls it. Swagger UI's job, done by this repository.
//
// WHY NOT SWAGGER UI. It was weighed rather than skipped. swagger-ui-dist is
// 11.7 MB unpacked with an install-time telemetry dependency of its own, in a
// service whose package.json is deliberately short and whose image is built in
// CI and in containers that may have no network beyond the registry. Against
// that, what Swagger UI would have bought here is a familiar look for an API of
// thirty-odd operations with no authentication, no oauth flows, no polymorphic
// bodies and no code generation. The page below is ~250 lines, has no
// dependency, and does the same three things: read the document, fill a form,
// show the response. It also shows the equivalent curl line, which is what an
// operator of a mock actually copies.
//
// THE ONE THING THIS PAGE COSTS. app.js sets `script-src 'none'` for the whole
// service, and this page has a script — so it is the single place that relaxes
// that header, and it relaxes exactly one clause on exactly two routes. The
// script is a SEPARATE RESOURCE rather than an inline block precisely so that
// `'self'` suffices: `'unsafe-inline'` would be the clause that mattered, and
// this page never needs it. Everything else in the policy stays as it is,
// `default-src 'none'` included, and `connect-src 'self'` is what lets the
// page call the API it documents and nothing else.
//
// This module registers no route — admin_api.js does — so it is a library in
// the sense rule 3 gives, and its position in the require order is free.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const { log, xmlEscape } = require('./helpers');

// The relaxed policy, which differs from app.js's in exactly two clauses:
// script-src is 'self' rather than 'none', and connect-src is added so the page
// may fetch the document and call the operations. Written out in full rather
// than patched from the other one, because a policy assembled by string surgery
// is a policy nobody can read.
const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'unsafe-inline'",
  "connect-src 'self'",
  "img-src 'self' data:",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  // Not on app.js's policy, and safe here where it is not there: this page has
  // no form at all, so there is no submission and therefore no redirect chain
  // for a browser to enforce it against. See the long note in app.js for why
  // the service-wide policy must not carry it.
  "form-action 'none'"
].join('; ');

// The browser script, read once at require time. A file rather than a string
// constant in this module, so that it is readable, diffable and syntax-checked
// like any other source here; see its own header.
const SCRIPT = fs.readFileSync(
  path.join(__dirname, 'admin_api_explorer.js'), 'utf8');

const STYLE = [
  'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;',
  'background:#f4f4f7;margin:0;padding:2rem 1rem;color:#222;line-height:1.45}',
  '#app{max-width:76rem;margin:0 auto}',
  '.head{background:#fff;border:1px solid #d5d5dd;border-radius:10px;',
  'padding:22px 26px;margin:0 0 18px;box-shadow:0 6px 24px rgba(0,0,0,.08)}',
  'h1{font-size:1.35em;margin:0 0 6px;color:#12107c}',
  'h2{font-size:1.05em;margin:0 0 4px;color:#12107c}',
  '.meta{margin:0 0 10px;font-size:.82em;color:#666}',
  '.meta span,.meta a{margin-right:1em}',
  '.meta a{color:#12107c}',
  '.lede{font-size:.86em;color:#444;margin:.5em 0}',
  '.filter{margin:0 0 14px}',
  '.filter label{font-size:.78em;font-weight:600;color:#555;margin-right:.5em}',
  '.filter input{width:22rem;max-width:100%}',
  '.tag{background:#fff;border:1px solid #d5d5dd;border-radius:10px;',
  'padding:16px 20px;margin:0 0 14px;box-shadow:0 6px 24px rgba(0,0,0,.06)}',
  '.tagnote{font-size:.8em;color:#666;margin:0 0 10px}',
  '.op{border-top:1px solid #eee}',
  '.ophead{display:flex;gap:.7em;align-items:baseline;width:100%;',
  'text-align:left;background:none;border:0;padding:9px 2px;cursor:pointer;',
  'font:inherit}',
  '.ophead:hover{background:#fafafc}',
  '.method{font-size:.72em;font-weight:700;letter-spacing:.04em;',
  'border-radius:4px;padding:2px 7px;color:#fff;flex:none;min-width:3.4rem;',
  'text-align:center}',
  '.m-get{background:#0b6b4f}.m-post{background:#b06000}',
  '.path{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;',
  'font-size:.84em;flex:none}',
  '.summary{font-size:.8em;color:#666}',
  '.opbody{padding:4px 2px 18px 4.4rem}',
  '.prose{font-size:.82em;color:#444;margin:.4em 0}',
  '.hint{font-size:.76em;color:#777;margin:.2em 0 0;flex-basis:100%}',
  '.form{margin:.8em 0 .4em}',
  '.field{display:flex;flex-wrap:wrap;gap:.6em;align-items:center;',
  'margin:.5em 0}',
  '.field label{font-size:.78em;font-weight:600;color:#555;min-width:9rem}',
  '.field.wide{display:block}',
  'input[type=text],textarea{box-sizing:border-box;padding:6px 8px;',
  'border:1px solid #bbb;border-radius:5px;font-size:.85em;',
  'font-family:inherit}',
  'input[type=text]{min-width:16rem}',
  'textarea{width:100%;font-size:.8em;',
  'font-family:ui-monospace,SFMono-Regular,Menlo,monospace}',
  '.controls{margin:.6em 0}',
  'button.run{padding:6px 14px;border-radius:5px;border:1px solid #12107c;',
  'background:#12107c;color:#fff;font-size:.82em;cursor:pointer}',
  '.curl,.body{background:#f4f4f8;border:1px solid #e2e2ea;border-radius:5px;',
  'padding:8px 10px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;',
  'font-size:.76em;white-space:pre-wrap;word-break:break-word;margin:.5em 0}',
  '.curl{color:#555}',
  '.resulthead{display:flex;gap:.8em;align-items:baseline;margin:.6em 0 0}',
  '.status{font-weight:700;font-size:.82em}',
  '.status.ok{color:#0b6b4f}.status.bad{color:#b00020}',
  '.status.err{color:#b00020}',
  '.ms{font-size:.76em;color:#777}',
  '.pending{font-size:.8em;color:#777;margin:.6em 0}',
  '.warn{background:#fff8e1;border:1px solid #ffe082;padding:9px 12px;',
  'border-radius:5px;font-size:.82em;margin:0 0 16px}',
  'code{font-size:.9em;',
  'font-family:ui-monospace,SFMono-Regular,Menlo,monospace;',
  'background:#f4f4f8;padding:.1rem .25rem;border-radius:3px}'
].join('');

// The banner. It is in the HTML rather than drawn from the document, so that it
// is on the page even when the fetch of that document fails — the one moment
// somebody is most likely to be poking at this service from somewhere it should
// not be reachable from.
const BANNER =
  '<div class="warn"><strong>Nothing here is protected.</strong> This ' +
  'service checks no credential anywhere, so neither does its management ' +
  'API. Anyone who can reach this port can revoke every token it has issued ' +
  'and change what the next one contains. Fine on a laptop or a compose ' +
  'network; not fine on a public address.</div>';

function page(baseUrl, base, version) {
  log.debug("Entering page(). base=" + base);
  const specUrl = xmlEscape(base + '/openapi.json');
  const html = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>mock STS management API</title><style>' + STYLE + '</style>' +
    '</head><body>' +
    // The banner is BEFORE the app rather than after it, and the position is
    // the point: it is the first thing on the page whether or not the document
    // loads, and a warning at the bottom of thirty-two operations is a warning
    // nobody has read yet when they press Try it.
    BANNER +
    '<div id="app" data-spec="' + specUrl + '" data-version="' +
    xmlEscape(version) + '">' +
    '<h1>mock STS management API</h1>' +
    '<p class="lede">Reading <code>' + specUrl + '</code>&hellip;</p>' +
    '</div>' +
    '<script src="' + xmlEscape(base) + '/docs/explorer.js" defer></script>' +
    '</body></html>';
  log.debug("Leaving page(). " + html.length + " bytes.");
  return html;
}

module.exports = {
  CONTENT_SECURITY_POLICY: CONTENT_SECURITY_POLICY,
  SCRIPT: SCRIPT,
  page: page
};
