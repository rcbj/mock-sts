'use strict';
//
// File: http_client.js
//
// ===========================================================================
// A BROWSER, ROUGHLY, IN ABOUT A HUNDRED LINES.
//
// `configure.js` and `drive.js` both need to speak HTTP to three services, and
// `drive.js` needs to do it the way a browser would. There is no puppeteer here
// and there should not be: every page in this stack is server-rendered and
// runs no script at all — the mock STS sets `script-src 'none'` service-wide —
// so a browser engine would add a hundred megabytes and answer no question that
// this file cannot.
//
// ---------------------------------------------------------------------------
// THE ONE THING IT HAS TO GET RIGHT IS THE COOKIE JAR, AND IT IS **PER
// ORIGIN**.
//
// This flow crosses three origins, and TWO OF THEM SET A SESSION COOKIE UNDER
// THE SAME NAME. The mock STS calls its cookie `sts_session` — both instances
// do, because they are the same image — so a single flat jar would send the
// service provider's session to the identity provider and back again, and each
// would read a session id the other minted.
//
// What that produces is the worst kind of green: the flow completes, somebody
// appears to be signed in, and the reason has nothing to do with federation.
// The jar is keyed by `scheme://host:port`, which is what a browser does, and
// `jarFor()` is the only way in.
// ===========================================================================

const http = require('http');
const https = require('https');
const { URL } = require('url');

const jars = new Map();

function originOf(url) {
  const parsed = new URL(url);
  return parsed.protocol + '//' + parsed.host;
}

function jarFor(url) {
  const origin = originOf(url);
  if (!jars.has(origin)) jars.set(origin, new Map());
  return jars.get(origin);
}

function cookieHeaderFor(url) {
  const jar = jarFor(url);
  if (!jar.size) return '';
  return Array.from(jar.entries())
    .map(function (pair) { return pair[0] + '=' + pair[1]; })
    .join('; ');
}

function absorbCookies(url, setCookie) {
  const jar = jarFor(url);
  (setCookie || []).forEach(function (line) {
    const first = String(line).split(';')[0];
    const at = first.indexOf('=');
    if (at < 1) return;
    const name = first.slice(0, at).trim();
    const value = first.slice(at + 1).trim();
    // A cleared cookie is a DELETE rather than an empty value, because the
    // mock STS clears its session with `sts_session=; Max-Age=0` and a jar
    // that kept the empty string would go on sending a header naming a
    // session that does not exist.
    if (value === '' || /max-age=0/i.test(line)) jar.delete(name);
    else jar.set(name, value);
  });
}

// One request, no redirect following. `body` may be a string or an object,
// which is form-encoded — every form in this stack is
// application/x-www-form-urlencoded, and the two management APIs take JSON,
// which is what `json` is for.
function request(method, url, options) {
  const opts = options || {};
  return new Promise(function (resolve, reject) {
    const parsed = new URL(url);
    const headers = Object.assign({ 'Accept': 'text/html,application/json' },
                                  opts.headers || {});
    const cookies = cookieHeaderFor(url);
    if (cookies) headers['Cookie'] = cookies;
    let payload = null;
    if (opts.json !== undefined) {
      payload = JSON.stringify(opts.json);
      headers['Content-Type'] = 'application/json';
    } else if (opts.form !== undefined) {
      payload = typeof opts.form === 'string'
        ? opts.form : new URLSearchParams(opts.form).toString();
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
    }
    if (payload !== null) headers['Content-Length'] = Buffer.byteLength(payload);
    const driver = parsed.protocol === 'https:' ? https : http;
    const req = driver.request({
      protocol: parsed.protocol, hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search, method: method, headers: headers,
      rejectUnauthorized: false
    }, function (res) {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', function (chunk) { text += chunk; });
      res.on('end', function () {
        absorbCookies(url, res.headers['set-cookie']);
        resolve({ status: res.statusCode, headers: res.headers, text: text, url: url,
                  location: res.headers.location
                    ? new URL(res.headers.location, url).toString() : '' });
      });
    });
    req.on('error', reject);
    if (payload !== null) req.write(payload);
    req.end();
  });
}

// Follow redirects the way a browser does, and RECORD EVERY HOP. The trail is
// most of what this test asserts on: which service answered, in what order, is
// the whole shape of a federated sign-in, and a driver that silently followed
// twelve redirects and reported the last page would pass just as happily if
// four of them had gone somewhere else.
//
// A 303 turns the method into GET by definition; a 302 after a POST does so in
// every browser ever shipped. Both are followed as GET, which is what the
// services here are written against.
async function follow(method, url, options, trail, max) {
  let response = await request(method, url, options);
  let hops = 0;
  const limit = max || 12;
  while (response.status >= 300 && response.status < 400 && response.location) {
    if (trail) trail.push({ status: response.status, from: url, to: response.location });
    if (++hops > limit) throw new Error('more than ' + limit + ' redirects from ' + url);
    url = response.location;
    response = await request('GET', url, {});
  }
  if (trail) trail.push({ status: response.status, from: url, to: '' });
  return response;
}

// The value of one named input in an HTML form. Every page in this stack is
// server-rendered markup with no script, so this is genuinely how a browser
// would find it — there is nothing dynamic to miss.
function inputValue(html, name) {
  const patterns = [
    new RegExp('name="' + name + '"[^>]*\\svalue="([^"]*)"'),
    new RegExp('value="([^"]*)"[^>]*\\sname="' + name + '"')
  ];
  for (const pattern of patterns) {
    const match = String(html).match(pattern);
    if (match) return unescapeHtml(match[1]);
  }
  return '';
}

// Every `href` on the page whose text or attributes match a pattern.
function links(html, pattern) {
  const out = [];
  const re = /<a\b[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/g;
  let match;
  while ((match = re.exec(String(html))) !== null) {
    const href = unescapeHtml(match[1]);
    const text = match[2].replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
    if (!pattern || pattern.test(href) || pattern.test(text)) out.push({ href: href, text: text });
  }
  return out;
}

function unescapeHtml(value) {
  return String(value)
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'");
}

function resetJars() {
  jars.clear();
}

// Poll until a service answers, or give up saying which one did not. Compose
// healthchecks already gate `depends_on`, so this is for the HOST run and for
// the gap between "the container is healthy" and "the published port is
// forwarding".
async function waitFor(url, seconds) {
  const deadline = Date.now() + (seconds || 60) * 1000;
  let last = '';
  while (Date.now() < deadline) {
    try {
      const response = await request('GET', url, {});
      if (response.status >= 200 && response.status < 500) return true;
      last = 'answered ' + response.status;
    } catch (e) {
      last = e.code || e.message;
    }
    await new Promise(function (r) { setTimeout(r, 500); });
  }
  throw new Error('gave up waiting for ' + url + ' after ' + (seconds || 60) + 's (' + last + ')');
}

module.exports = {
  request: request, follow: follow, inputValue: inputValue, links: links,
  unescapeHtml: unescapeHtml, jarFor: jarFor, resetJars: resetJars,
  waitFor: waitFor, originOf: originOf
};
