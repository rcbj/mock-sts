'use strict';
//
// File: ssf_http.js
//
// ===========================================================================
// THE SECOND OUTBOUND REQUEST IN THIS REPOSITORY, AND IT IS A WEAKER CASE THAN
// THE FIRST ONE. SAY SO RATHER THAN CITING IT.
//
// `federation/federation_http.js` is the first, and its header makes an
// argument this file CANNOT make. Its rule is:
//
//     THOSE URLS ARE SUPPLIED BY THE CALLER. THESE ARE SUPPLIED BY THE
//     ADMINISTRATOR.
//
// — and it enforces it by refusing to take a URL at all: `fetchJson()` takes a
// relationship record and the NAME of an attribute on it, and there are three
// legal names. A push delivery endpoint is not like that and pretending
// otherwise would be the dangerous version of this feature.
//
// **RFC 8935 PUSH DELIVERY IS, BY CONSTRUCTION, THE RECEIVER TELLING THE
// TRANSMITTER WHERE TO POST.** That is not an implementation choice here; it
// is what the delivery method IS. A receiver creates a stream at the
// management API and names `delivery.endpoint_url`, and the transmitter posts
// SETs there. Any transmitter that speaks push takes a caller-supplied URL,
// including every commercial one.
//
// So the honest statement is: this file makes an outbound request to an
// address a caller chose, and these are the four things that bound it.
//
// 1. **`ssf.pushDelivery` TURNS IT OFF ENTIRELY**, and a deployment that is
//    reachable by anybody it does not trust should set it. With it off, this
//    service still speaks the whole of SSF over POLL delivery — where nothing
//    is dialled at all, because the receiver comes here — and
//    `ssf.deliveryMethods` then advertises only `urn:ietf:rfc:8936`, so a
//    receiver finds out at stream creation rather than by never receiving
//    anything.
//
// 2. **`ssf.pushAllowedHosts` IS AN ALLOWLIST AND IT IS EMPTY BY DEFAULT,
//    MEANING ANY.** That default is the one deliberate looseness here and it
//    is what makes this service usable as a mock; a deployment sets the list
//    and every other host is refused by name. It is a HOST list rather than a
//    URL list on purpose: a receiver legitimately moves its endpoint path
//    around and does not legitimately move to another host.
//
// 3. **https ONLY UNLESS `ssf.pushAllowInsecure` SAYS OTHERWISE**, exactly as
//    federation does, and for a reason that is different in kind: what travels
//    on this request is not a credential, it is an EVENT — that somebody's
//    session was revoked, that an account was disabled. That is somebody's
//    security posture in transit, and it is also carrying the receiver's own
//    `authorization_header`, which IS a credential. Both halves want TLS.
//
// 4. **NO REDIRECTS, A CAPPED BODY AND A TIMEOUT**, for federation's reasons.
//    A 302 from a push endpoint is not a protocol this service speaks and
//    following one would post the event, and the receiver's authorization
//    header, wherever the Location said.
//
// **AND ONE THING THAT IS NOT A BOUND AND IS WORTH NOT MISTAKING FOR ONE.**
// The management API is not gated by default (`ssf.authRequired` gates it and
// ships ON, but every credential this service accepts is a turnstile — see
// `ssf/CLAUDE.md`). So "a receiver created the stream" is not evidence of
// anything much. The bounds above are the bounds; the gate is not one of them.
//
// ---------------------------------------------------------------------------
// WHAT IT DOES NOT DO, AND THE ONE THAT SURPRISES PEOPLE.
//
// **IT DOES NOT RETRY.** RFC 8935 section 2.4 lets a transmitter retry a
// failed push and this service does not, because a mock that retried would
// make a receiver's ONE-SHOT failure invisible: a client under test that
// answers 500 to the first push and 202 to the second looks, from its own
// logs, like a client that works. The failure is recorded on the stream, the
// event stays on the queue, and `POST /admin-api/ssf/redeliver` sends it
// again when somebody asks. Deliberate rather than unfinished, and
// `ssf/CLAUDE.md` lists it under what this family does not do.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). It registers no route and requires `helpers.js`,
// `config.js` and node's own `http`/`https`/`url` — nothing else here — so it
// cannot join a cycle and a test can drive it against a throwaway listener.
// ===========================================================================

const https = require('https');
const http = require('http');
const { URL } = require('url');
const config = require('../common/config');
const { log } = require('../common/helpers');

// A receiver that answers a push with more than this is not answering RFC
// 8935. A success is 202 with an EMPTY body and a failure is a small JSON
// object; 64 KiB is three orders of magnitude of headroom and still a bound.
const MAX_BODY_BYTES = 64 * 1024;

// The media type of a SET on the wire (RFC 8417 section 2.3). It is not
// `application/jwt` and a receiver that dispatches on the type — several do —
// drops one sent as a plain JWT with no error anybody sees.
const SET_MEDIA_TYPE = 'application/secevent+jwt';

function pushAllowed() {
  log.debug('Entering pushAllowed().');
  const on = !!config.value('ssf.pushDelivery');
  log.debug('Leaving pushAllowed(). ' + on);
  return on;
}

function allowInsecure() {
  log.debug('Entering allowInsecure().');
  const on = !!config.value('ssf.pushAllowInsecure');
  log.debug('Leaving allowInsecure(). ' + on);
  return on;
}

function timeoutMs() {
  log.debug('Entering timeoutMs().');
  const value = config.value('ssf.pushTimeoutMs');
  log.debug('Leaving timeoutMs(). ' + value);
  return value;
}

// The allowlist, as a list of lower-case host names. Empty means ANY, which is
// the default and the one deliberate looseness in this file — see point 2 of
// the header.
function allowedHosts() {
  log.debug('Entering allowedHosts().');
  const asked = config.value('ssf.pushAllowedHosts');
  const list = Array.isArray(asked) ? asked : String(asked || '').split(',');
  const out = list.map(function (one) {
    return String(one).trim().toLowerCase();
  }).filter(Boolean);
  log.debug('Leaving allowedHosts(). ' + out.length + ' entry/entries.');
  return out;
}

// ---------------------------------------------------------------------------
// WHETHER THIS URL MAY BE DIALLED, as a sentence rather than a boolean.
//
// Every refusal ends up on the stream's own log and on `/admin/ssf`, so each
// one names what is wrong and which setting decides it — "refused" would send
// somebody to read this file.
//
// It is exported and is called at STREAM CREATION as well as at push time,
// which is the half that matters to a receiver: a stream whose endpoint can
// never be dialled is refused when it is created rather than accepted and then
// silently delivering nothing.
// ---------------------------------------------------------------------------
function urlProblem(raw) {
  log.debug('Entering urlProblem().');
  const text = String(raw || '').trim();
  if (!text) {
    log.debug('Leaving urlProblem(). Empty.');
    return 'there is no delivery.endpoint_url on the stream';
  }
  let parsed = null;
  try {
    parsed = new URL(text);
  } catch (e) {
    log.debug('Leaving urlProblem(). It will not parse.');
    return '"' + text + '" is not a URL (' + e.message + ')';
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    log.debug('Leaving urlProblem(). Wrong scheme.');
    return 'its scheme is "' + parsed.protocol.replace(':', '') + '", and a ' +
           'push endpoint is https (or http, with ssf.pushAllowInsecure on)';
  }
  if (parsed.protocol === 'http:' && !allowInsecure()) {
    log.debug('Leaving urlProblem(). http, refused.');
    return 'it is an http:// URL and ssf.pushAllowInsecure is off. A ' +
           'Security Event Token is somebody\'s security posture in ' +
           'transit, and the receiver\'s own authorization_header travels ' +
           'beside it, so plain http is refused unless that setting says ' +
           'otherwise';
  }
  const hosts = allowedHosts();
  if (hosts.length && hosts.indexOf(parsed.hostname.toLowerCase()) < 0) {
    log.debug('Leaving urlProblem(). Not on the allowlist.');
    return 'its host "' + parsed.hostname + '" is not in ' +
           'ssf.pushAllowedHosts (' + hosts.join(', ') + '). That list is ' +
           'empty by default, meaning any host; this deployment has set it';
  }
  log.debug('Leaving urlProblem(). Fine.');
  return '';
}

// ---------------------------------------------------------------------------
// PUSH ONE SET.
//
//   url      the stream's delivery.endpoint_url
//   token    the signed SET, as a compact JWS
//   options  { authorizationHeader }
//
// Returns a promise of `{ ok, status, err, description, why }` and NEVER
// rejects, for the reason `federation_http.js` gives about its own: a rejected
// promise here would have to be caught at every call site, and the one added
// later would not be.
//
// **THE THREE OUTCOMES ARE NOT TWO.** RFC 8935 section 2.3 makes a 202 the
// success and section 2.4 makes a 400 with `err`/`description` a REFUSAL BY
// THE RECEIVER — which is a completely different thing from a network failure,
// and the most interesting thing a receiver ever says. `ok` is false for both,
// and `err` is set only for the second, so the stream's log can tell "nothing
// answered" from "the receiver said invalid_audience".
// ---------------------------------------------------------------------------
function pushSet(url, token, options) {
  log.debug('Entering pushSet().');
  const opts = options || {};
  if (!pushAllowed()) {
    log.debug('Leaving pushSet(). ssf.pushDelivery is off.');
    return Promise.resolve({ ok: false, status: 0, err: '', description: '',
      why: 'ssf.pushDelivery is off, so this service makes no outbound ' +
           'request at all. Poll delivery (urn:ietf:rfc:8936) needs none — ' +
           'the receiver comes here.' });
  }
  const problem = urlProblem(url);
  if (problem) {
    log.debug('Leaving pushSet(). ' + problem);
    return Promise.resolve({ ok: false, status: 0, err: '', description: '',
      why: 'the delivery endpoint cannot be dialled: ' + problem });
  }
  const target = new URL(String(url).trim());
  const secure = target.protocol === 'https:';
  if (!secure) {
    // Every insecure request, not just the setting. See federation_http.js's
    // header, point 2 — a check disabled six months ago and forgotten is the
    // worst kind of leftover.
    log.warn('ssf: pushing a Security Event Token to ' + target.origin +
             ' over plain http because ssf.pushAllowInsecure is ON. The ' +
             'event and the receiver\'s authorization_header both travel in ' +
             'clear.');
  }
  const body = Buffer.from(String(token), 'utf8');
  const headers = {
    'Content-Type': SET_MEDIA_TYPE,
    'Content-Length': body.length,
    'Accept': 'application/json',
    'User-Agent': 'mock-sts ssf-transmitter'
  };
  if (opts.authorizationHeader) {
    headers.Authorization = String(opts.authorizationHeader);
  }

  log.debug('Leaving pushSet(). Dialling ' + target.origin + '.');
  return new Promise(function (resolve) {
    const done = function (result) {
      log.debug('pushSet() finished. ok=' + result.ok + ', status=' +
                result.status);
      resolve(Object.assign({ url: String(url) }, result));
    };
    let request = null;
    try {
      request = (secure ? https : http).request({
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (secure ? 443 : 80),
        path: target.pathname + target.search,
        method: 'POST',
        headers: headers,
        // The ordinary certificate check, and it is deliberately NOT this
        // service's usual "verify nothing" posture: what is being protected
        // is the receiver's authorization_header and the fact that somebody's
        // session was revoked. `ssf.pushAllowInsecure` turns it off for
        // localhost work and is warned about above.
        rejectUnauthorized: secure && !allowInsecure()
      }, function (response) {
        const status = response.statusCode || 0;
        const location = response.headers.location;
        if (status >= 300 && status < 400 && location) {
          response.destroy();
          return done({ ok: false, status: status, err: '', description: '',
            why: 'it answered ' + status + ' redirecting to "' + location +
                 '", and this service does not follow a redirect on a push. ' +
                 'The event and the receiver\'s authorization_header would ' +
                 'go wherever that pointed.' });
        }
        let text = '';
        let bytes = 0;
        let overflowed = false;
        response.setEncoding('utf8');
        response.on('data', function (chunk) {
          if (overflowed) {
            return;
          }
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
            return done({ ok: false, status: status, err: '',
              description: '',
              why: 'it answered with more than ' + MAX_BODY_BYTES +
                   ' bytes. RFC 8935 makes a success an EMPTY 202 and a ' +
                   'failure a small JSON object, so this is not a push ' +
                   'endpoint answering.' });
          }
          if (status === 202 || status === 200 || status === 204) {
            // 202 is what RFC 8935 section 2.3 specifies. 200 and 204 are
            // accepted as well and NOT silently: a receiver answering one of
            // those is very slightly wrong, the event did arrive, and a mock
            // that refused would be testing the transmitter's pedantry rather
            // than the receiver's behaviour. The note says which it was.
            return done({ ok: true, status: status, err: '',
              description: '',
              why: status === 202 ? '' : 'it answered ' + status +
                   ' rather than the 202 RFC 8935 section 2.3 specifies. ' +
                   'The event was accepted; a stricter transmitter might ' +
                   'not have treated it as delivered.' });
          }
          let json = null;
          try {
            json = JSON.parse(text);
          } catch (e) {
            // Not JSON. A proxy in front of the receiver serving an HTML
            // error page is the ordinary case, and the TEXT is then the
            // diagnosis — so it is carried rather than discarded.
            json = null;
          }
          if (status === 400 && json && json.err) {
            return done({ ok: false, status: status, err: String(json.err),
              description: String(json.description || ''),
              why: 'the receiver REFUSED the event: ' + String(json.err) +
                   ' — ' + String(json.description || '(no description)') });
          }
          return done({ ok: false, status: status, err: '', description: '',
            why: 'it answered ' + status + (text
              ? ': ' + text.slice(0, 200) : ' with no body') });
        });
        response.on('error', function (e) {
          done({ ok: false, status: status, err: '', description: '',
            why: 'the response failed: ' + e.message });
        });
      });
    } catch (e) {
      // A malformed option rather than a network failure — new URL() has
      // already succeeded by here, so this is a bug in the caller.
      return done({ ok: false, status: 0, err: '', description: '',
        why: 'the request could not be built: ' + e.message });
    }
    request.setTimeout(timeoutMs(), function () {
      request.destroy();
      done({ ok: false, status: 0, err: '', description: '',
        why: 'it did not answer within ' + timeoutMs() +
             'ms (ssf.pushTimeoutMs)' });
    });
    request.on('error', function (e) {
      // The one that actually happens: DNS, connection refused, a certificate
      // nothing trusts. `e.code` is the useful half and is named, because
      // "self-signed certificate" and "connection refused" send somebody to
      // two completely different places.
      const selfSigned = e.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
        e.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
        e.code === 'SELF_SIGNED_CERT_IN_CHAIN';
      done({ ok: false, status: 0, err: '', description: '',
        why: 'the request failed: ' + (e.code ? e.code + ' — ' : '') +
             e.message + (selfSigned
          ? '. Set ssf.pushAllowInsecure to push to a receiver whose ' +
            'certificate nothing here trusts.' : '') });
    });
    request.write(body);
    request.end();
  });
}

module.exports = {
  MAX_BODY_BYTES: MAX_BODY_BYTES,
  SET_MEDIA_TYPE: SET_MEDIA_TYPE,
  pushAllowed: pushAllowed,
  allowInsecure: allowInsecure,
  allowedHosts: allowedHosts,
  urlProblem: urlProblem,
  pushSet: pushSet
};
