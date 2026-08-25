'use strict';
//
// File: server.js  —  the mock web application
//
// ===========================================================================
// A HELLO-WORLD PAGE BEHIND AN OPENID CONNECT SIGN-IN, AND NOTHING ELSE.
//
// This is NOT part of the mock STS. It is a separate application in a separate
// container that has never heard of federation, and that is the whole point of
// it being here: the identity service it talks to is federating on its behalf,
// and this application cannot tell. It sends an ordinary authorization request
// to an ordinary OpenID Provider and gets an ordinary ID Token back. Everything
// interesting happens two hops away and is invisible from here.
//
// If this file ever needs to know that federation exists, something upstream is
// wrong.
//
// ---------------------------------------------------------------------------
// IT HAS NO DEPENDENCIES, DELIBERATELY.
//
// No express, no openid-client, no jsonwebtoken. Node's own `http`, `crypto`
// and `fetch` are enough for a relying party, and the ID Token verification
// below is thirty lines. Two reasons, and the second is the one that matters:
//
//   * the container is `FROM node:22-alpine` and a COPY. No npm install, no
//     lockfile, no network at build time.
//   * **a relying party built out of a library proves less.** The point of
//     pointing this at a mock is to see the protocol happen; a library that
//     silently fixes a malformed response, or silently accepts one it should
//     refuse, is exactly what a mock exists to expose. Every check here is
//     visible in this file.
//
// ---------------------------------------------------------------------------
// THE FRONT-CHANNEL / BACK-CHANNEL URL SPLIT, WHICH IS THE WHOLE DIFFICULTY OF
// RUNNING OIDC IN CONTAINERS AND IS NOT A MOCK PROBLEM.
//
// This application reaches its provider by its DOCKER SERVICE NAME
// (`http://sts-sp:8081`). The BROWSER cannot resolve that — it is on the host,
// and reaches the same provider through a published port
// (`http://localhost:8081`). So there are two base URLs for one provider, and
// which one is correct depends entirely on WHO IS DOING THE FETCHING:
//
//   discovery, the token endpoint, JWKS   →  back channel, service name
//   the authorization endpoint            →  front channel, published port
//
// Discovery is fetched over the BACK channel, so every URL in the document
// comes back with the back-channel host in it — including
// `authorization_endpoint`, which is the one URL a browser has to be able to
// reach. Sending the browser there produces `DNS_PROBE_FINISHED_NXDOMAIN`, and
// the flow dies before the provider has logged anything at all.
//
// `OIDC_BROWSER_BASE` is the fix, and it is the same fix every real product has
// (Keycloak calls it `frontendUrl`): fetch discovery back-channel, then rewrite
// the endpoints a BROWSER visits onto the front-channel base. Nothing else is
// rewritten — a token endpoint rewritten to `localhost` would be this container
// dialling itself.
//
// ---------------------------------------------------------------------------
// WHAT IT CHECKS ON THE WAY BACK, which is more than most demonstration
// clients:
//
//   * `state` — against a value it minted and SPENDS, so a replayed callback
//     fails the second time;
//   * the ID Token's SIGNATURE, against the provider's JWKS, with the algorithm
//     family taken from the KEY rather than from the token's own header (a
//     token nominating HS256 against an RSA key is the classic forgery);
//   * `iss` against the discovery document's issuer;
//   * `aud` against this client's own id;
//   * `exp` / `nbf` with a small tolerance;
//   * `nonce` against the value it sent.
//
// It sends PKCE always. This is a confidential client with a secret and does
// not strictly need it; RFC 9700 section 2.1.1 recommends it of every client,
// and a demonstration client that skips the recommended thing teaches the
// wrong lesson.
// ===========================================================================

const bunyan = require('bunyan');
const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = parseInt(process.env.PORT || '3000', 10);
const APP_NAME = process.env.APP_NAME || 'Hello World';
// Where this application reaches its provider: a docker service name, or
// whatever a host run uses. Discovery, token and JWKS go here.
const ISSUER = process.env.OIDC_ISSUER || 'http://localhost:8081';
// Where the BROWSER reaches the same provider. See the header.
const BROWSER_BASE = process.env.OIDC_BROWSER_BASE || ISSUER;
const CLIENT_ID = process.env.OIDC_CLIENT_ID || 'hello-world-app';
const CLIENT_SECRET = process.env.OIDC_CLIENT_SECRET || '';
const REDIRECT_URI = process.env.OIDC_REDIRECT_URI ||
  ('http://localhost:' + PORT + '/callback');
const SCOPE = process.env.OIDC_SCOPE || 'openid profile email';

const SESSION_COOKIE = 'webapp_session';
const SESSION_TTL_MS = 30 * 60 * 1000;
const PENDING_TTL_MS = 10 * 60 * 1000;
const CLOCK_TOLERANCE_S = 60;

const sessions = new Map();
const pending = new Map();

// bunyan rather than console, the same as the two driver scripts and as every
// test in the parent project's suite. The `name` field is what the '[webapp]'
// prefix used to be, and it is a field rather than a string a reader has to
// pick apart.
const log = bunyan.createLogger({ name: 'webapp',
                                  level: process.env.LOG_LEVEL || 'info' });

// ---------------------------------------------------------------------------
// DISCOVERY, fetched once and then held.
//
// It is fetched LAZILY rather than at startup, and that is about container
// ordering rather than about laziness: compose starts this alongside the
// identity service, and a provider that is not listening yet would otherwise
// kill this process before the stack finished coming up. A failure here is
// reported on the page instead, which is also what somebody debugging the
// stack needs to see.
// ---------------------------------------------------------------------------
let discovery = null;

async function discover() {
  log.debug('Entering discover().');
  if (discovery) {
    log.debug('Leaving discover().');
    return discovery;
  }
  const url = ISSUER.replace(/\/+$/, '') + '/.well-known/openid-configuration';
  log.info('fetching discovery from ' + url + ' (back channel)');
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error('discovery at ' + url + ' answered ' + response.status);
  }
  const document = await response.json();
  // THE REWRITE. See the header — only the endpoints a BROWSER visits.
  const rewrite = function (endpoint) {
    if (!endpoint) return endpoint;
    if (BROWSER_BASE === ISSUER) return endpoint;
    const moved = endpoint.replace(ISSUER.replace(/\/+$/, ''),
                                   BROWSER_BASE.replace(/\/+$/, ''));
    if (moved !== endpoint) log.info('front-channel rewrite: ' + endpoint + ' -> ' + moved);
    return moved;
  };
  discovery = {
    issuer: document.issuer,
    authorization_endpoint: rewrite(document.authorization_endpoint),
    token_endpoint: document.token_endpoint,
    jwks_uri: document.jwks_uri,
    end_session_endpoint: rewrite(document.end_session_endpoint)
  };
  log.info('provider issuer is ' + discovery.issuer);
  log.debug('Leaving discover().');
  return discovery;
}

// ---------------------------------------------------------------------------
// The ID Token, verified by hand. See the header for why there is no library.
// ---------------------------------------------------------------------------
function b64uJson(segment) {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

async function jwks(uri) {
  const response = await fetch(uri);
  if (!response.ok) throw new Error('JWKS at ' + uri + ' answered ' + response.status);
  const document = await response.json();
  return Array.isArray(document.keys) ? document.keys : [];
}

async function verifyIdToken(token, expected) {
  log.debug('Entering verifyIdToken().');
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new Error('the ID Token is not three segments');
  const header = b64uJson(parts[0]);
  const payload = b64uJson(parts[1]);

  // Refused BY NAME rather than by failing to find a key, because `alg: none`
  // is an attack with a name and whoever sees this should know which one.
  if (String(header.alg || '').toLowerCase() === 'none') {
    throw new Error('the ID Token says alg=none, which is an unsigned token dressed as a signed one');
  }

  const keys = await jwks(expected.jwksUri);
  const candidates = keys.filter(function (key) {
    return header.kid && key.kid ? key.kid === header.kid : true;
  });
  if (!candidates.length) {
    throw new Error('no key in the provider\'s JWKS matches kid "' + (header.kid || '(none)') + '"');
  }

  const signed = parts[0] + '.' + parts[1];
  const signature = Buffer.from(parts[2], 'base64url');
  let verified = false;
  for (const jwk of candidates) {
    let key = null;
    try {
      key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    } catch (e) {
      continue;
    }
    // THE ALGORITHM FAMILY COMES FROM THE KEY, NOT FROM THE TOKEN. Without
    // this, a token nominating HS256 would be verified using the provider's
    // PUBLIC key as an HMAC secret — which anybody who has read the JWKS can
    // produce. It is the best-known JWT forgery there is.
    if (key.asymmetricKeyType === 'rsa' && !/^(RS|PS)\d{3}$/.test(header.alg)) {
      throw new Error('the ID Token nominates ' + header.alg + ' against an RSA key');
    }
    if (key.asymmetricKeyType === 'ec' && !/^ES\d{3}$/.test(header.alg)) {
      throw new Error('the ID Token nominates ' + header.alg + ' against an EC key');
    }
    const scheme = header.alg.startsWith('PS')
      ? { key: key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }
      : key;
    const digest = 'sha' + header.alg.slice(2);
    const dsaEncoding = key.asymmetricKeyType === 'ec' ? 'ieee-p1363' : undefined;
    if (crypto.verify(digest, Buffer.from(signed),
                      dsaEncoding ? { key: scheme, dsaEncoding: dsaEncoding } : scheme,
                      signature)) {
      verified = true;
      break;
    }
  }
  if (!verified) throw new Error('the ID Token signature did not verify against the provider\'s JWKS');

  if (payload.iss !== expected.issuer) {
    throw new Error('iss is "' + payload.iss + '", expected "' + expected.issuer + '"');
  }
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (audiences.indexOf(expected.clientId) === -1) {
    throw new Error('aud is "' + audiences.join(', ') + '", expected "' + expected.clientId + '"');
  }
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp + CLOCK_TOLERANCE_S <= now) {
    throw new Error('the ID Token expired at ' + new Date(payload.exp * 1000).toISOString());
  }
  if (payload.nbf && payload.nbf - CLOCK_TOLERANCE_S > now) {
    throw new Error('the ID Token is not valid until ' + new Date(payload.nbf * 1000).toISOString());
  }
  if (expected.nonce && payload.nonce !== expected.nonce) {
    throw new Error('nonce is "' + payload.nonce + '", expected "' + expected.nonce +
                    '" — a replayed ID Token looks exactly like this');
  }
  log.debug('Leaving verifyIdToken().');
  return payload;
}

// ---------------------------------------------------------------------------
// Plumbing.
// ---------------------------------------------------------------------------
function cookiesOf(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(function (part) {
    const at = part.indexOf('=');
    if (at < 1) return;
    out[part.slice(0, at).trim()] = part.slice(at + 1).trim();
  });
  return out;
}

function sessionOf(req) {
  const id = cookiesOf(req)[SESSION_COOKIE];
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;
  if (session.expires < Date.now()) {
    sessions.delete(id);
    return null;
  }
  return session;
}

function esc(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const STYLE = 'body{font-family:system-ui,Segoe UI,Helvetica,Arial,sans-serif;margin:3rem auto;' +
  'max-width:46rem;line-height:1.55;color:#111}h1{font-size:1.7rem;margin-bottom:.2rem}' +
  'p.sub{color:#666;margin-top:0}code{background:#f4f4f5;padding:.1rem .3rem;border-radius:3px;' +
  'word-break:break-all;font-size:.9em}table{border-collapse:collapse;width:100%;margin:1rem 0}' +
  'th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;font-size:.9rem;' +
  'vertical-align:top}th{background:#fafafa;width:12rem}a.btn{display:inline-block;padding:.6rem 1.2rem;' +
  'background:#12107c;color:#fff;text-decoration:none;border-radius:5px;font-size:1rem}' +
  '.err{background:#fdecea;border:1px solid #f5c6c2;color:#b00020;padding:.8rem 1rem;' +
  'border-radius:5px}.note{color:#555;font-size:.88rem}';

function page(res, status, title, body) {
  const html = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>' + esc(title) + '</title><style>' + STYLE + '</style></head><body>' +
    body + '</body></html>\n';
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8',
                          'Cache-Control': 'no-store' });
  res.end(html);
}

function redirect(res, location, cookie) {
  const headers = { Location: location };
  if (cookie) headers['Set-Cookie'] = cookie;
  res.writeHead(302, headers);
  res.end();
}

// ---------------------------------------------------------------------------
// The pages.
// ---------------------------------------------------------------------------
function homePage(res, session) {
  log.debug('Entering homePage().');
  if (!session) {
    log.debug('Leaving homePage().');
    return page(res, 200, APP_NAME,
      '<h1>' + esc(APP_NAME) + '</h1>' +
      '<p class="sub">A web application that knows nothing about federation.</p>' +
      '<p>You are not signed in. This application is an ordinary OpenID Connect ' +
      'relying party: it will send you to <code>' + esc(BROWSER_BASE) + '</code> and ' +
      'expect an ID Token back.</p>' +
      '<p class="note">Whether that provider authenticates you itself or federates the ' +
      'question out to somebody else is invisible from here, and that is the point of ' +
      'this page existing.</p>' +
      '<p><a class="btn" href="/login">Sign in</a></p>');
  }
  const claims = session.claims;
  const rows = Object.keys(claims).sort().map(function (name) {
    const value = claims[name];
    return '<tr><th><code>' + esc(name) + '</code></th><td><code>' +
      esc(typeof value === 'object' ? JSON.stringify(value) : value) + '</code></td></tr>';
  }).join('');
  log.debug('Leaving homePage().');
  return page(res, 200, APP_NAME,
    '<h1>Hello, ' + esc(claims.name || claims.preferred_username || claims.sub) + '.</h1>' +
    '<p class="sub">Signed in through <code>' + esc(session.issuer) + '</code>.</p>' +
    '<p>Everything below came out of the ID Token this application verified. It asked ' +
    'one provider one question and got one answer; how many identity services were ' +
    'involved in producing it is not something this application can see.</p>' +
    '<h2>The claims</h2><table>' + rows + '</table>' +
    '<p class="note">Signed in at ' + esc(new Date(session.at).toISOString()) + '. ' +
    'The access token is held server-side and is not shown.</p>' +
    '<p><a class="btn" href="/logout">Sign out</a></p>');
}

async function login(req, res) {
  log.debug('Entering login().');
  const meta = await discover();
  const verifier = crypto.randomBytes(32).toString('base64url');
  const state = crypto.randomBytes(16).toString('base64url');
  const nonce = crypto.randomBytes(16).toString('base64url');
  pending.set(state, { verifier: verifier, nonce: nonce, expires: Date.now() + PENDING_TTL_MS });
  pending.forEach(function (value, key) {
    if (value.expires < Date.now()) pending.delete(key);
  });
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: SCOPE,
    state: state,
    nonce: nonce,
    code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256'
  });
  const joiner = meta.authorization_endpoint.indexOf('?') === -1 ? '?' : '&';
  const url = meta.authorization_endpoint + joiner + params.toString();
  log.info('sending the browser to ' + url.slice(0, 120) + '…');
  redirect(res, url);
  log.debug('Leaving login().');
}

async function callback(req, res, url) {
  log.debug('Entering callback().');
  const meta = await discover();
  const error = url.searchParams.get('error');
  if (error) {
    log.debug('Leaving callback().');
    return page(res, 400, 'Sign-in failed',
      '<h1>The provider refused</h1><div class="err"><code>' + esc(error) + '</code>' +
      (url.searchParams.get('error_description')
        ? ' — ' + esc(url.searchParams.get('error_description')) : '') +
      '</div><p><a href="/">Back</a></p>');
  }
  const state = url.searchParams.get('state') || '';
  // READ AND SPEND. A replayed callback fails the second time, which is what a
  // one-shot state is for.
  const context = pending.get(state);
  pending.delete(state);
  if (!context || context.expires < Date.now()) {
    log.debug('Leaving callback().');
    return page(res, 400, 'Sign-in failed',
      '<h1>That was not a sign-in this application started</h1>' +
      '<div class="err">The <code>state</code> is not one this application minted, or the ' +
      'sign-in it belonged to expired. A cross-site request forgery on this callback looks ' +
      'exactly like this.</div><p><a href="/">Back</a></p>');
  }
  const code = url.searchParams.get('code');
  if (!code) {
    log.debug('Leaving callback().');
    return page(res, 400, 'Sign-in failed',
      '<h1>No authorization code arrived</h1><div class="err">The provider redirected here ' +
      'with neither a code nor an error.</div><p><a href="/">Back</a></p>');
  }

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: REDIRECT_URI,
    code_verifier: context.verifier
  });
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (CLIENT_SECRET) {
    headers['Authorization'] = 'Basic ' +
      Buffer.from(CLIENT_ID + ':' + CLIENT_SECRET).toString('base64');
  } else {
    body.set('client_id', CLIENT_ID);
  }
  log.info('redeeming the code at ' + meta.token_endpoint + ' (back channel)');
  const response = await fetch(meta.token_endpoint,
                               { method: 'POST', headers: headers, body: body.toString() });
  const text = await response.text();
  let tokens = null;
  try {
    tokens = JSON.parse(text);
  } catch (e) {
    // Not JSON. The TEXT is the diagnosis — a proxy in front of the provider
    // answers with HTML, and "unexpected token <" would hide that.
    tokens = null;
  }
  if (!response.ok || !tokens) {
    log.debug('Leaving callback().');
    return page(res, 502, 'Sign-in failed',
      '<h1>The code could not be redeemed</h1><div class="err">The token endpoint answered ' +
      response.status + ': <code>' + esc(text.slice(0, 400)) + '</code></div>' +
      '<p><a href="/">Back</a></p>');
  }
  if (!tokens.id_token) {
    log.debug('Leaving callback().');
    return page(res, 502, 'Sign-in failed',
      '<h1>No ID Token</h1><div class="err">The token response carried <code>' +
      esc(Object.keys(tokens).join(', ')) + '</code> and no <code>id_token</code>. That is an ' +
      'OAuth 2.0 response rather than an OpenID Connect one — an access token says a client ' +
      'was authorized, not that a person signed in.</div><p><a href="/">Back</a></p>');
  }

  let claims = null;
  try {
    claims = await verifyIdToken(tokens.id_token, {
      issuer: meta.issuer, clientId: CLIENT_ID, jwksUri: meta.jwks_uri, nonce: context.nonce
    });
  } catch (e) {
    log.info('the ID Token was REFUSED: ' + e.message);
    log.debug('Leaving callback().');
    return page(res, 401, 'Sign-in failed',
      '<h1>The ID Token did not verify</h1><div class="err">' + esc(e.message) + '</div>' +
      '<p class="note">This application checked the signature against the provider\'s JWKS, ' +
      'and then <code>iss</code>, <code>aud</code>, <code>exp</code> and <code>nonce</code>. ' +
      'It refuses rather than trusting a token it could not check.</p>' +
      '<p><a href="/">Back</a></p>');
  }

  const id = crypto.randomBytes(24).toString('base64url');
  sessions.set(id, {
    claims: claims, issuer: meta.issuer, at: Date.now(),
    accessToken: tokens.access_token || '', expires: Date.now() + SESSION_TTL_MS
  });
  log.info('signed in as ' + (claims.preferred_username || claims.sub) +
      ' (' + Object.keys(claims).length + ' claims)');
  redirect(res, '/', SESSION_COOKIE + '=' + id + '; Path=/; HttpOnly; SameSite=Lax');
  log.debug('Leaving callback().');
}

const server = http.createServer(function (req, res) {
  const url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
  const path = url.pathname;
  log.info(req.method + ' ' + path);
  Promise.resolve().then(function () {
    if (path === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, app: APP_NAME, issuer: ISSUER }));
    }
    if (path === '/login') return login(req, res);
    if (path === '/callback') return callback(req, res, url);
    if (path === '/logout') {
      const id = cookiesOf(req)[SESSION_COOKIE];
      if (id) sessions.delete(id);
      // This ends the session HERE and nowhere else. RP-initiated logout at the
      // provider is a different act and this demonstration does not perform it,
      // which is stated rather than left to be discovered: signing out here and
      // clicking Sign in again goes straight back through, because the
      // provider's own session is untouched.
      return redirect(res, '/', SESSION_COOKIE + '=; Path=/; Max-Age=0');
    }
    if (path === '/') return homePage(res, sessionOf(req));
    return page(res, 404, 'Not found', '<h1>Not found</h1><p><a href="/">Back</a></p>');
  }).catch(function (e) {
    log.info('ERROR ' + (e && e.stack ? e.stack : e));
    page(res, 500, 'Error',
      '<h1>This application failed</h1><div class="err">' + esc(e.message) + '</div>' +
      '<p class="note">If this is a discovery failure, the identity service at <code>' +
      esc(ISSUER) + '</code> is not answering yet.</p><p><a href="/">Back</a></p>');
  });
});

server.listen(PORT, '0.0.0.0', function () {
  log.info(APP_NAME + ' listening on ' + PORT);
  log.info('  provider (back channel) : ' + ISSUER);
  log.info('  provider (browser)      : ' + BROWSER_BASE);
  log.info('  client_id               : ' + CLIENT_ID);
  log.info('  redirect_uri            : ' + REDIRECT_URI);
});
