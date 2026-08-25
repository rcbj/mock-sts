'use strict';
//
// File: federation_http.js
//
// ===========================================================================
// THE ONLY OUTBOUND REQUEST IN THIS REPOSITORY.
//
// Nothing else here has ever dialled anything. This service is reached; it does
// not reach. That is not an accident of what got built — it is a position taken
// in two places and argued in both:
//
//   * `oauthJwksUri` on an application entry is RECORDED AND NEVER FETCHED.
//     `applications.js`'s schema row says why: following it would mean this
//     service making an outbound request to a URL somebody registered in order
//     to verify a credential, "which is a server-side request forgery with a
//     specification citation attached".
//   * WS-Federation's `wreqptr` gets the same refusal in `wsfed.js`, and
//     `client_auth.js` says holding that position in one file and not the other
//     would be no position at all.
//
// BOTH OF THOSE STAND, UNCHANGED, AND THIS FILE DOES NOT CONTRADICT THEM. The
// distinction is not "this feature needs it" — that is the argument every
// SSRF ever shipped was made with. It is:
//
//   **THOSE URLS ARE SUPPLIED BY THE CALLER. THESE ARE SUPPLIED BY THE
//   ADMINISTRATOR.**
//
// `POST /oauth2/register` is unauthenticated and takes any `jwks_uri` anybody
// types; a `wreqptr` rides on a query string from a browser. Following either
// turns this service into a request-forwarder for whoever can reach the port,
// and the URL that gets dialled is chosen by the attacker on the spot. A
// federation relationship is created through the admin console — which is
// gated — or through `/admin-api`, and its `fedTokenUrl` was written down
// deliberately by somebody configuring a partner. Anybody who can set it can
// already do worse things than make this process issue a GET.
//
// So the rule this file enforces, and the reason it exists at all rather than
// being three lines inside `federation_sp.js`:
//
//   **EVERY URL DIALLED COMES OFF A FEDERATION RELATIONSHIP ENTRY, BY
//   ATTRIBUTE NAME, AND THE ATTRIBUTE NAME IS PASSED IN.** `fetchJson()` will
//   not take a bare URL. It takes the relationship and the name of the
//   attribute holding the URL, looks it up itself, and refuses a name that is
//   not one of the three it is allowed to read. A caller that has a URL from
//   somewhere else cannot use this module, which is the whole point — there is
//   no back door here for the next feature that "just needs to fetch one
//   thing".
//
// If that ever needs to change, it is a SEPARATE argument in a SEPARATE
// function, never a fourth name quietly added to `DIALLABLE`.
//
// ---------------------------------------------------------------------------
// FIVE MORE THINGS ARE ENFORCED HERE, AND EACH IS A DIFFERENT FAILURE.
//
// 1. **`federation.outbound` TURNS IT ALL OFF.** A deployment with no egress
//    sets it and nothing here dials anything. The refusal names the setting, so
//    somebody watching a federated sign-in fail in an air-gapped test knows
//    within one line why.
//
// 2. **https ONLY, unless `federation.outboundAllowInsecure` says otherwise.**
//    What travels on these requests is a client secret and an authorization
//    code, at somebody ELSE'S service — this is the one place in this
//    repository where a credential leaves the process, and it is the one place
//    this service is stricter than a mock would ordinarily be. `allowInsecure`
//    exists because federating against another mock on localhost is the
//    ordinary development case, and every request made under it is LOGGED as
//    insecure rather than only the setting being logged once: a certificate
//    check disabled six months ago and forgotten is the worst kind of leftover.
//
// 3. **NO REDIRECTS ARE FOLLOWED.** A 302 from a token endpoint is not a
//    protocol this service speaks, and following one would hand the credential
//    in the Authorization header to whatever the Location said — which is the
//    SSRF this whole file is arranged to avoid, arriving through the front
//    door instead of the back. A redirect is a failure and says so.
//
// 4. **THE BODY IS CAPPED AND THE REQUEST IS TIMED OUT.** A partner that
//    answers slowly is a browser hanging on a blank tab, and a partner that
//    answers forever is this process's memory. Both are bounded, and the
//    error names which bound was hit.
//
// 5. **NOTHING THAT ARRIVES IS TRUSTED.** This module returns parsed JSON and
//    a status code and makes no judgement at all. Whether the token is any
//    good, whether the issuer is the configured one, whether the signature
//    verifies — all of that is `federation_sp.js`'s, where the relationship's
//    keys are. A fetcher that also validated would be the place both halves of
//    a check ended up half-written.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). It registers nothing and requires `helpers.js` and
// `config.js` — plus node's own `https`, `http` and `url` — so it cannot join a
// cycle. `federation.js` is NOT required from here, deliberately: this module
// is handed a relationship record and reads two attributes off it, which keeps
// the dependency pointing one way and lets a test drive this file with a plain
// object.
// ===========================================================================

const https = require('https');
const http = require('http');
const { URL } = require('url');
const config = require('./../common/config');
const { log } = require('./../common/helpers');

// THE THREE ATTRIBUTES THAT MAY HOLD A URL THIS SERVICE WILL DIAL. See the
// header — this list is the mechanism, not a convenience. A fourth name here is
// a new argument, not a new line.
const DIALLABLE = ['fedTokenUrl', 'fedUserinfoUrl', 'fedJwksUri'];

// A partner that answers with more than this is not answering a protocol. A
// token response is a few hundred bytes and a JWKS a few kilobytes; 256 KiB is
// two orders of magnitude of headroom and still a bound.
const MAX_BODY_BYTES = 256 * 1024;

function outboundAllowed() {
  return !!config.value('federation.outbound');
}

function allowInsecure() {
  return !!config.value('federation.outboundAllowInsecure');
}

function timeoutMs() {
  return config.value('federation.outboundTimeoutMs');
}

// ---------------------------------------------------------------------------
// WHETHER THIS URL MAY BE DIALLED AT ALL, as a sentence rather than a boolean.
//
// Every refusal here ends up on the relationship's `fedLastError` and on
// `/admin/federation`, so each one has to name what is wrong and what to do
// about it — "refused" would send somebody to read this file.
// ---------------------------------------------------------------------------
function urlProblem(raw) {
  log.debug('Entering urlProblem().');
  const text = String(raw || '').trim();
  if (!text) {
    log.debug('Leaving urlProblem(). Empty.');
    return 'there is no URL configured for it';
  }
  let parsed = null;
  try {
    parsed = new URL(text);
  } catch (e) {
    log.debug('Leaving urlProblem(). It will not parse.');
    return '"' + text + '" is not a URL (' + e.message + ')';
  }
  if (parsed.protocol === 'https:') {
    log.debug('Leaving urlProblem(). https, fine.');
    return '';
  }
  if (parsed.protocol === 'http:') {
    if (allowInsecure()) {
      log.debug('Leaving urlProblem(). http, allowed by setting.');
      return '';
    }
    log.debug('Leaving urlProblem(). http, refused.');
    return 'it is an http:// URL and federation.outboundAllowInsecure is off. ' +
           'A client secret and an authorization code travel on this request, ' +
           'so plain http is refused unless that setting says otherwise';
  }
  log.debug('Leaving urlProblem(). Wrong scheme.');
  return 'its scheme is "' + parsed.protocol.replace(':', '') + '", and only https ' +
         '(or http, with federation.outboundAllowInsecure on) is dialled';
}

// ---------------------------------------------------------------------------
// THE REQUEST.
//
//   record     the federation relationship, as `federation.js` hands it back
//   attribute  WHICH attribute holds the URL. One of DIALLABLE, checked.
//   options    { method, form, bearer, basic, headers }
//
// Returns a promise of { ok, status, json, text, url, why } and NEVER rejects.
// A rejected promise here would have to be caught at four call sites in the
// middle of a browser redirect, and the fourth one added later would not be —
// which is the same reasoning `audit.audit()` and the user observer are written
// under. `ok` is false and `why` is a sentence.
// ---------------------------------------------------------------------------
function fetchJson(record, attribute, options) {
  log.debug('Entering fetchJson().');
  const opts = options || {};
  const id = (record && record.fedId) || '?';
  log.debug('Entering fetchJson(). id=' + id + ', attribute=' + attribute);

  if (DIALLABLE.indexOf(String(attribute)) === -1) {
    // A programming error rather than a configuration one, so it is loud. See
    // the header: this is the mechanism that keeps the SSRF position honest,
    // and it must never be possible to slip past it by passing a string.
    log.error('federation: something asked to dial "' + attribute + '" on ' + id +
              ', which is not one of the three attributes this service will ' +
              'follow (' + DIALLABLE.join(', ') + '). Refused. This is a bug in ' +
              'the caller, not a misconfiguration — see the header of ' +
              'federation_http.js.');
    log.debug('Leaving fetchJson(). Not a diallable attribute.');
    log.debug('Leaving fetchJson().');
    return Promise.resolve({ ok: false, status: 0, json: null, text: '', url: '',
                             why: 'this service will not follow a URL from "' + attribute + '"' });
  }
  if (!outboundAllowed()) {
    log.debug('Leaving fetchJson(). Outbound is off.');
    log.debug('Leaving fetchJson().');
    return Promise.resolve({ ok: false, status: 0, json: null, text: '', url: '',
                             why: 'federation.outbound is off, so this service makes no ' +
                                  'back-channel request at all. SAML, SAML 1.1 and ' +
                                  'WS-Federation need none; an OIDC partner can be used ' +
                                  'with fedResponseType=id_token and its keys in fedJwks' });
  }
  const raw = String((record && record[attribute]) || '');
  const problem = urlProblem(raw);
  if (problem) {
    log.debug('Leaving fetchJson(). ' + problem);
    log.debug('Leaving fetchJson().');
    return Promise.resolve({ ok: false, status: 0, json: null, text: '', url: raw,
                             why: attribute + ' cannot be dialled: ' + problem });
  }

  const target = new URL(raw);
  const secure = target.protocol === 'https:';
  if (!secure) {
    // Every insecure request, not just the setting. See the header.
    log.warn('federation: dialling ' + target.origin + ' over plain http for ' + id +
             ' because federation.outboundAllowInsecure is ON. A client secret ' +
             'and an authorization code travel on this request.');
  }
  const method = String(opts.method || 'GET').toUpperCase();
  const headers = Object.assign({ 'Accept': 'application/json',
                                  'User-Agent': 'mock-sts federation' },
                                opts.headers || {});
  let body = '';
  if (opts.form) {
    body = new URLSearchParams(opts.form).toString();
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    headers['Content-Length'] = Buffer.byteLength(body);
  }
  if (opts.bearer) headers['Authorization'] = 'Bearer ' + opts.bearer;
  if (opts.basic) {
    headers['Authorization'] = 'Basic ' +
      Buffer.from(String(opts.basic.user) + ':' + String(opts.basic.pass)).toString('base64');
  }

  log.debug('Leaving fetchJson().');
  return new Promise(function (resolve) {
    const done = function (result) {
      log.debug('Leaving fetchJson(). ok=' + result.ok + ', status=' + result.status);
      resolve(Object.assign({ url: raw }, result));
    };
    let request = null;
    try {
      request = (secure ? https : http).request({
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (secure ? 443 : 80),
        path: target.pathname + target.search,
        method: method,
        headers: headers,
        // The certificate check, and it is the ordinary one — this is the one
        // place in this service where a real TLS verification happens against
        // somebody else's certificate, and the mock's usual "verify nothing"
        // posture is exactly wrong for it: what is being protected is the
        // secret in the Authorization header. `allowInsecure` turns it off for
        // localhost work and is warned about above.
        rejectUnauthorized: secure && !allowInsecure()
      }, function (response) {
        const status = response.statusCode || 0;
        const location = response.headers.location;
        if (status >= 300 && status < 400 && location) {
          // See the header, point 3. The socket is destroyed rather than read:
          // there is nothing here worth having.
          response.destroy();
          return done({ ok: false, status: status, json: null, text: '',
                        why: 'it answered ' + status + ' redirecting to "' + location +
                             '", and this service does not follow a redirect on a ' +
                             'back-channel request — the credential in the ' +
                             'Authorization header would go wherever that pointed' });
        }
        let text = '';
        let bytes = 0;
        let overflowed = false;
        response.setEncoding('utf8');
        response.on('data', function (chunk) {
          if (overflowed) return;
          bytes += Buffer.byteLength(chunk);
          if (bytes > MAX_BODY_BYTES) {
            overflowed = true;
            response.destroy();
            return;
          }
          text += chunk;
        });
        response.on('end', function () {
          if (overflowed) {
            return done({ ok: false, status: status, json: null, text: '',
                          why: 'it answered with more than ' + MAX_BODY_BYTES +
                               ' bytes, which is not a token response, a UserInfo ' +
                               'document or a JWKS' });
          }
          let json = null;
          try {
            json = JSON.parse(text);
          } catch (e) {
            // Not JSON. Kept rather than failed here, because an OAuth error is
            // often served as HTML by a proxy in front of the partner and the
            // TEXT is the diagnosis — the caller decides whether it needed JSON.
            json = null;
          }
          done({ ok: status >= 200 && status < 300, status: status, json: json, text: text,
                 why: status >= 200 && status < 300 ? ''
                   : 'it answered ' + status + (json && json.error ? ' ' + json.error : '') });
        });
        response.on('error', function (e) {
          done({ ok: false, status: status, json: null, text: text,
                 why: 'the response failed: ' + e.message });
        });
      });
    } catch (e) {
      // A malformed option rather than a network failure — new URL() has
      // already succeeded by here, so this is a bug in the caller and is
      // reported as a refusal rather than thrown into a redirect.
      return done({ ok: false, status: 0, json: null, text: '',
                    why: 'the request could not be built: ' + e.message });
    }
    request.setTimeout(timeoutMs(), function () {
      request.destroy();
      done({ ok: false, status: 0, json: null, text: '',
             why: 'it did not answer within ' + timeoutMs() + 'ms ' +
                  '(federation.outboundTimeoutMs). A browser is waiting on this ' +
                  'request, which is why the wait is short' });
    });
    request.on('error', function (e) {
      // The one that actually happens: DNS, connection refused, a certificate
      // nothing trusts. `e.code` is the useful half and is named, because
      // "self-signed certificate" and "connection refused" send somebody to two
      // completely different places.
      done({ ok: false, status: 0, json: null, text: '',
             why: 'the request failed: ' + (e.code ? e.code + ' — ' : '') + e.message +
                  (e.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
                   e.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
                   e.code === 'SELF_SIGNED_CERT_IN_CHAIN'
                     ? '. Set federation.outboundAllowInsecure to dial a partner whose ' +
                       'certificate nothing here trusts'
                     : '') });
    });
    if (body) request.write(body);
    request.end();
  });
}

module.exports = {
  DIALLABLE: DIALLABLE,
  MAX_BODY_BYTES: MAX_BODY_BYTES,
  urlProblem: urlProblem,
  fetchJson: fetchJson,
  outboundAllowed: outboundAllowed,
  allowInsecure: allowInsecure
};
