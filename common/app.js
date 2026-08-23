'use strict';
//
// File: app.js
//
// ---------------------------------------------------------------------------
// The express application and everything that must be in place BEFORE a single
// route is registered: the security headers, the Private Network Access answer,
// CORS, the body parser and the call log.
//
// It is a module of its own, and the reason is the registration order. Each
// protocol module registers its endpoints as a side effect of being required
// (`const app = require('./app')` then `app.get(...)` at its top level), which
// keeps every handler exactly where it was written instead of wrapped in a
// register() function and re-indented. Express applies middleware in the order it
// was added and only to routes added AFTER it, so the middleware has to be
// installed by the time any protocol module is loaded — i.e. here, in the module
// they all require, rather than in server.js, which requires them.
//
// The consequence to remember when adding a module: server.js requires the
// protocol modules in a deliberate order, and that order is the route order.
// Nothing here has overlapping paths, so it does not currently matter — but a new
// module that registers a wildcard would matter a great deal.
// ---------------------------------------------------------------------------

const express = require('express');
const cors = require('cors');
// For one decision only: whether CORS is withheld from the authorization
// endpoint (RFC 9700 section 2.6). It registers no route and requires only
// helpers.js and config.js, so requiring it from the module every protocol
// module requires cannot create a cycle or reorder anything.
const bcp = require('../oauth-oidc/oauth2_bcp');
const bodyParser = require('body-parser');
const { log, headersOf, bodyOf } = require('./helpers');
// The service's own record of what it has done. Required HERE, and the position is
// load-bearing twice over: the call log below is where the per-endpoint statistics
// are collected, so this is a real dependency — and because every protocol module
// requires this file, requiring it here means admin_stats.js has installed its JWT
// recorder into helpers.js before any route exists and therefore before any token
// can be minted. See the comment on setJwtRecorder in helpers.js for why that
// installation is a hook rather than a require in the other direction.
const stats = require('./admin_stats');
// The service's account of WHAT HAPPENED, as against how much of it. Required
// here for the same reason admin_stats.js is and with the same consequence: the
// call log below is the single place every answered request passes through, so
// one call there covers three of the six audit categories — the admin console,
// the management API and every protocol endpoint — instead of a recording site
// in each of forty route handlers, thirty-seven of which would never be added.
// It is a library like admin_stats.js (it registers no route) and it requires
// only helpers.js and config.js, which is what keeps it out of the cycles rule 2
// exists to avoid.
const audit = require('./audit');
// --- express app -----------------------------------------------------------
const app = express();

// Chrome Private Network Access: when a PUBLIC page calls a LOCAL (loopback)
// server — which is exactly the live-site test setup, an HTTPS page on
// idptools.com calling this mock at http://localhost:8081 — Chrome may send a
// CORS preflight carrying Access-Control-Request-Private-Network and require
// this header on the response. Answer it so the call isn't blocked. Registered
// BEFORE cors() so the header is set before the preflight response is sent;
// a no-op for the containerized suite (both sides on the same bridge network).
app.use(function (req, res, next) {
  if (req.headers['access-control-request-private-network']) {
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
  }
  next();
});

// The response hardening that actually applies to this service.
//
// Almost everything here answers `application/json`, and the values in those
// responses are echoed from what a caller sent — an error_description quoting a
// bad grant_type, a client name from a registration request. Escaping that
// content is NOT the control: JSON.stringify already encodes it unambiguously,
// and running an HTML sanitizer over it would corrupt legitimate values while
// protecting nothing (a JSON string is not markup). The way such a body turns
// into script is a browser deciding to treat it as HTML anyway, so the control
// is to forbid that decision:
//
//   X-Content-Type-Options: nosniff   honour the declared Content-Type, never
//                                     sniff a JSON body as text/html
//   Content-Security-Policy           no script runs even if some response were
//                                     rendered as a document after all
//   X-Frame-Options: DENY             no framing of the login screen the
//                                     authorization endpoint serves
//
// The HTML this service does emit (the login screen, the credential-offer and
// verifier pages) builds its markup from server-side values, and where a
// caller-supplied value appears in it, it is escaped at that point with
// xmlEscape().
//
// The policy is as tight as these pages allow, and it is worth saying what each
// clause is for, because a stricter-looking one would break them:
//   script-src 'none'   they contain no <script> at all, inline or external —
//                       so this is the clause that makes the whole family of
//                       js/reflected-xss reports moot rather than merely
//                       unlikely: a JSON body rendered as a document still runs
//                       nothing.
//   style-src           six pages carry an inline <style> block, so
//                       'unsafe-inline' is required; extracting them to files
//                       would buy nothing here since no untrusted value reaches
//                       a style.
//   img-src data:       the two QR pages embed the code as a data: URI produced
//                       by the qrcode library server-side.
//
// NOT present, and it must not be added back: **form-action**. It looks obviously
// right here — the only form posts to /authn/login, which is same-origin — but
// Chrome enforces form-action against the whole REDIRECT CHAIN that follows a
// submission, not just its immediate target. This is an authorization server:
// signing in POSTs the login form and the response is a 302 to the client's
// redirect_uri, which is by definition another origin. `form-action 'self'`
// therefore blocks the browser from ever reaching the client, and the symptom is
// remote from the cause — the sign-in appears to succeed and the wallet simply
// never comes back. It cost a full SD-JWT VC issuance run to find, and
// tests/sd_jwt_vc_issuance.js is what catches it (H.1 signs in here).
// Enumerating allowed redirect origins is not a fix either: this mock accepts
// arbitrary redirect_uris on purpose.
const CSP_DIRECTIVES = {
  'default-src': "'none'",
  'script-src': "'none'",
  'style-src': "'unsafe-inline'",
  'img-src': "'self' data:",
  'base-uri': "'none'",
  'frame-ancestors': "'none'"
};

// ---------------------------------------------------------------------------
// THE CLAUSES NO PAGE MAY DROP — RFC 9700 section 4.14, clickjacking.
//
// A page framed invisibly over another one collects a click the person meant
// for something else, and on a sign-in screen or an authorization page that
// click IS the decision. `frame-ancestors 'none'` is what prevents it —
// X-Frame-Options is set beside it for the browsers that still read it, but
// that header is obsolete and the CSP directive is the one that governs.
//
// **`frame-ancestors` HAS NO FALLBACK.** `default-src` covers most fetch
// directives and not this one, so a page that sets `Content-Security-Policy:
// default-src 'none'` and nothing else is framable as far as CSP is concerned.
// That is the trap this list exists to close: five routes here relax the policy
// so they can load a named script, each by SETTING THE WHOLE HEADER, and any of
// them could have left this clause out without anything failing — the page
// works, the script runs, and the protection is quietly gone.
//
// So a relaxation goes through `contentSecurityPolicy()` below, which starts
// from the base and re-adds the framing clauses whatever the caller asked for.
// A caller CANNOT turn them off, which is deliberate: there is no page in an
// authorization server that should be framable, and a mock that let one be
// would be teaching the opposite of what section 4.14 is for.
// ---------------------------------------------------------------------------
const UNDROPPABLE = ['frame-ancestors', 'base-uri'];

function contentSecurityPolicy(overrides) {
  const merged = Object.assign({}, CSP_DIRECTIVES, overrides || {});
  UNDROPPABLE.forEach(function (name) {
    merged[name] = CSP_DIRECTIVES[name];
  });
  return Object.keys(merged).filter(function (name) {
    return merged[name] !== null && merged[name] !== undefined;
  }).map(function (name) {
    return name + ' ' + merged[name];
  }).join('; ');
}

const CONTENT_SECURITY_POLICY = contentSecurityPolicy({});

app.use(function (req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', CONTENT_SECURITY_POLICY);
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  // ---------------------------------------------------------------------
  // NO RESPONSE LEAVES THIS SERVICE WITHOUT `frame-ancestors`, INCLUDING THE
  // ONES THIS SERVICE DID NOT WRITE.
  //
  // Setting the header above is not enough, and the gap is one nothing in this
  // repository could have shown: **Express's own 404 handler replaces the
  // Content-Security-Policy with `default-src 'none'`** on its way out.
  // `frame-ancestors` has no fallback from `default-src`, so every unrouted
  // path — every typo, every probe, and every error page a framework generates
  // — came back framable as far as CSP was concerned, protected only by the
  // obsolete X-Frame-Options. RFC 9700 section 4.14 names error pages
  // specifically, and this is why.
  //
  // So the header is re-checked at the moment it is flushed. The test is
  // deliberately "does it still carry the clause" rather than "is it still the
  // value I set": five routes here legitimately relax the policy to load a
  // named script, and every one of them goes through contentSecurityPolicy(),
  // which cannot drop the framing clauses — so a policy without them was set by
  // something that is not us, and the base policy is put back.
  //
  // Wrapping writeHead rather than adding a final 404 handler is deliberate
  // too. A handler would have to reproduce Express's body byte for byte:
  // `Cannot GET /path` is how the parent project's tests/sts_metadata.js tells
  // an unrouted path from an endpoint legitimately answering 404, and a
  // prettier 404 here would silently break that distinction.
  // ---------------------------------------------------------------------
  const writeHead = res.writeHead;
  res.writeHead = function () {
    const current = String(res.getHeader('Content-Security-Policy') || '');
    if (current.indexOf('frame-ancestors') < 0) {
      res.setHeader('Content-Security-Policy', CONTENT_SECURITY_POLICY);
      res.setHeader('X-Frame-Options', 'DENY');
    }
    return writeHead.apply(res, arguments);
  };
  next();
});

// ---------------------------------------------------------------------------
// CORS, with one endpoint carved out of it in RFC 9700 mode.
//
// `origin: '*'` everywhere is right for a mock whose token, userinfo, metadata
// and JWKS endpoints are fetched with XHR by in-browser clients — that is most
// of what this service is for. RFC 9700 section 2.6 says CORS MUST NOT be
// supported at the AUTHORIZATION endpoint, which is a different kind of
// endpoint: a browser NAVIGATES to it, so nothing legitimate ever read those
// headers there, and offering them only widens what a script on another origin
// can do with it.
//
// The decision is `oauth2_bcp.js`'s rather than this file's, and that is not
// ceremony: this module installs middleware and has no business knowing which
// of this service's paths is an authorization endpoint. It asks. The require is
// safe from here — that module registers no route and requires only helpers.js
// and config.js, so it cannot join a cycle and cannot move anything in the route
// order.
//
// `origin: false` makes the cors package send no headers at all, which is what
// "not supported" means. The same options function serves the preflight, or a
// browser would be told by OPTIONS that a request is allowed and then find the
// answer unreadable.
const corsOptions = function (req, callback) {
  if (bcp.corsForbidden(req)) {
    callback(null, { origin: false });
    return;
  }
  callback(null, { origin: '*' });
};

app.use(cors(corsOptions));

app.options('*', cors(corsOptions));

// Accept any content-type as raw text (SOAP arrives as text/xml or
// application/soap+xml).
app.use(bodyParser.text({ type: function () { return true; }, limit: '5mb' }));

// ---------------------------------------------------------------------------
// Record every call into every endpoint: the path, the request (headers and
// body), the response (headers, body and status), and how long it took.
//
// Registered AFTER the body parser on purpose: before that runs req.body is
// undefined, and every request would be recorded as empty.
//
// res.send / res.json / res.end are wrapped rather than hooked on 'finish',
// because by the time the response has been flushed the body is gone. Two
// entries are written per call — one when the request arrives, one when the
// answer goes out — so a request that never gets answered is still visible.
// ---------------------------------------------------------------------------
app.use(function (req, res, next) {
  const started = Date.now();
  const request = {
    path: req.originalUrl,
    method: req.method,
    query: req.query,
    headers: headersOf(req.headers),
    body: bodyOf(req.body)
  };
  log.debug({ request: request }, 'Request: ' + req.method + ' ' + req.originalUrl);

  let responseBody = '';
  const send = res.send;
  const json = res.json;
  const end = res.end;
  res.send = function (body) {
    responseBody = bodyOf(body);
    return send.apply(res, arguments);
  };
  res.json = function (body) {
    responseBody = bodyOf(body);
    return json.apply(res, arguments);
  };
  res.end = function (chunk) {
    if (!responseBody && chunk) responseBody = bodyOf(Buffer.isBuffer(chunk) ? chunk.toString('utf8') : chunk);
    return end.apply(res, arguments);
  };

  res.on('finish', function () {
    // Counted here rather than at the top of the middleware because the two things
    // worth counting — the status code and how long it took — do not exist until
    // the response has gone out. `req.route` is set by Express when it dispatches
    // into a route, so by now it holds the PATTERN that matched
    // ("/oauth2/register/:client_id") rather than the URL that was requested; the
    // metrics table is keyed on it so that one row means one endpoint instead of
    // one row per client id. A request that matched nothing has no pattern, which
    // is what `matched` records: those are 404s, and they are the ones the table's
    // cap collapses when a scanner starts inventing paths.
    const matchedPath = (req.route && req.route.path) || '';
    stats.recordCall({
      method: req.method,
      path: matchedPath || String(req.originalUrl || '/').split('?')[0],
      matched: !!matchedPath,
      status: res.statusCode,
      durationMs: Date.now() - started
    });
    // The same event, as one ROW rather than as a number that went up. It is
    // recorded here and not at the top of the middleware for the same reason
    // the counting is: the status and the elapsed time do not exist until the
    // response has gone out. `req` is still live — the body has been flushed,
    // the request object has not gone anywhere — which is what lets audit.js
    // resolve the signed-in user without that having to be threaded through
    // every handler.
    //
    // Nothing out of the request or response BODY is recorded, deliberately:
    // those carry passwords, bearer tokens and assertions on this service, and
    // the debug log above is where a person who wants them looks. The one field
    // read out of an admin body is `action`, by name — see audit.js.
    audit.recordHttp(req, res, {
      route: matchedPath,
      matched: !!matchedPath,
      durationMs: Date.now() - started
    });
    log.debug({ response: { path: req.originalUrl,
                            method: req.method,
                            status: res.statusCode,
                            durationMs: Date.now() - started,
                            headers: headersOf(res.getHeaders()),
                            body: responseBody } },
              'Response: ' + res.statusCode + ' ' + req.method + ' ' + req.originalUrl +
              ' in ' + (Date.now() - started) + 'ms');
  });
  next();
});

app.get('/healthcheck', function (req, res) {
  log.debug("Entering the healthcheck endpoint.");
  res.status(200).json({ message: 'Success' });
  log.debug("Leaving the healthcheck endpoint.");
});

module.exports = app;
// The policy builder, for the five routes that relax it. Exported off the app
// object rather than as a second module because every one of them already
// requires this file — and because a relaxation belongs beside the policy it
// relaxes, where the next reader will find both.
module.exports.contentSecurityPolicy = contentSecurityPolicy;
module.exports.CONTENT_SECURITY_POLICY = CONTENT_SECURITY_POLICY;
