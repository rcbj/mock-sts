'use strict';
//
// File: xacml_pep_http.js
//
// ===========================================================================
// THE THIRD OUTBOUND REQUEST IN THIS REPOSITORY, AND IT IS THE WEAKEST CASE OF
// THE THREE. MAKE THE ARGUMENT; DO NOT CITE THE OTHER TWO.
//
// `federation/federation_http.js` is the first and `ssf/ssf_http.js` is the
// second, and the second one's header opens by refusing to lean on the first.
// That is the rule this file inherits — the ARGUMENT is what is inherited, not
// the permission — so here it is from the beginning.
//
// Federation's rule is:
//
//     THOSE URLS ARE SUPPLIED BY THE CALLER. THESE ARE SUPPLIED BY THE
//     ADMINISTRATOR.
//
// and it enforces it by refusing to take a URL at all: `fetchJson()` takes a
// relationship record and the NAME of an attribute on it. SSF cannot make that
// argument, because RFC 8935 push IS the receiver telling the transmitter
// where to post, so it says so plainly and lists four bounds instead.
//
// **THIS FILE CANNOT MAKE EITHER ARGUMENT.** A notify URL is supplied by the
// PEP that registers, which is a caller; and no specification requires it,
// because there is no specification here at all — XACML 3.0 says nothing about
// how a policy reaches a PEP. So the honest statement is the shortest of the
// three: this service makes an outbound request to an address a caller chose,
// for a feature nobody asked it to have.
//
// ---------------------------------------------------------------------------
// WHAT MAKES IT AFFORDABLE ANYWAY IS THE ONE THING THE OTHER TWO CANNOT SAY.
//
// **THE NUDGE IS NEVER THE MECHANISM.** A remote PEP PULLS
// `GET /xacml/pep/policies` on its own interval, and that is the contract —
// the whole of it. This request says one sentence, "the repository changed,
// pull now", and carries nothing else: no policy, no decision, no event, no
// credential, not even the new sync token. Every PEP converges without it.
//
// That is a different KIND of bound from federation's and SSF's, and it is
// stronger than either. Federation's request carries a client secret to
// somebody else's token endpoint, so a failure there is a sign-in that does
// not happen. SSF's carries a Security Event Token, so a failure is an event
// the receiver never learns about — which is why that file records failures on
// the stream and offers a redeliver. Here a failure costs ONE POLLING INTERVAL
// OF LATENCY and is not otherwise observable, which means:
//
//   * `xacml.pepNotify` can be turned off in a deployment with no egress and
//     nothing breaks — not the feature, not a test, not a PEP;
//   * there is no retry and there is nothing to redeliver, because there is
//     nothing to lose;
//   * a refusal here is worth RECORDING (a nudge that never succeeds means a
//     PEP this service cannot reach, which is worth seeing on the console) and
//     is never worth escalating.
//
// If a future change ever puts something in this body that a PEP cannot get
// any other way, that removes the whole of the argument above and the feature
// needs a new one. The body is built in `nudge()` and is three members; keep
// it that way, or move the argument.
//
// ---------------------------------------------------------------------------
// AND FOUR BOUNDS, WHICH ARE SSF'S FOUR BECAUSE TWO FAMILIES MAKING ONE
// OUTBOUND REQUEST EACH SHOULD BE CONFIGURED THE SAME WAY.
//
// 1. **`xacml.pepNotify` TURNS IT OFF ENTIRELY**, and see above for why that
//    costs nothing but latency.
//
// 2. **`xacml.pepNotifyAllowedHosts` IS AN ALLOWLIST, EMPTY BY DEFAULT,
//    MEANING ANY.** SSF's default and SSF's reason: it is what makes this
//    usable as a mock, and a deployment reachable by anybody it does not trust
//    sets the list. Hosts rather than URLs, because a component legitimately
//    moves its path and does not legitimately move to another host.
//
// 3. **https ONLY UNLESS `xacml.pepNotifyAllowInsecure` SAYS OTHERWISE.** What
//    travels here is weaker than what travels on either of the other two — no
//    credential and no event — and it is still off by default, because a
//    request this service makes in the clear is a request somebody else can
//    answer for, and a PEP that acted on a forged nudge would pull from
//    wherever it was told to pull from. What protects it is that the PEP holds
//    the PDP's address itself and a nudge cannot change it; what the setting
//    protects is the rest.
//
// 4. **NO REDIRECTS, A CAPPED BODY AND A TIMEOUT**, for federation's reasons.
//    A 302 from a notify endpoint is not a protocol this service speaks.
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

// A PEP that answers a nudge with more than this is not answering a nudge. The
// expected reply is 204 with nothing in it; 16 KiB is generous for the error
// object a broken one might send and is still a bound.
const MAX_BODY_BYTES = 16 * 1024;

function notifyAllowed() {
  log.debug('Entering notifyAllowed().');
  const on = !!config.value('xacml.pepNotify');
  log.debug('Leaving notifyAllowed(). ' + on);
  return on;
}

function allowInsecure() {
  log.debug('Entering allowInsecure().');
  const on = !!config.value('xacml.pepNotifyAllowInsecure');
  log.debug('Leaving allowInsecure(). ' + on);
  return on;
}

function timeoutMs() {
  log.debug('Entering timeoutMs().');
  const value = config.value('xacml.pepNotifyTimeoutMs');
  log.debug('Leaving timeoutMs(). ' + value);
  return value;
}

// The allowlist as lower-case host names. Empty means ANY, which is the
// default and the one deliberate looseness here — see bound 2.
function allowedHosts() {
  log.debug('Entering allowedHosts().');
  const raw = config.value('xacml.pepNotifyAllowedHosts');
  const list = String(raw || '').split(',').map(function (one) {
    return one.trim().toLowerCase();
  }).filter(function (one) {
    return !!one;
  });
  log.debug('Leaving allowedHosts(). ' + list.length + ' host(s).');
  return list;
}

// ---------------------------------------------------------------------------
// WHY A URL IS REFUSED, or null when it is fine. Separate from the request so
// that the console and `/admin-api` can show the refusal a PEP's notify URL
// WOULD get without anything being dialled to find out.
// ---------------------------------------------------------------------------
function urlProblem(raw) {
  log.debug('Entering urlProblem(). raw=' + raw);
  if (!raw) {
    log.debug('Leaving urlProblem(). Empty.');
    return 'There is no notify URL on this PEP, so it is never nudged. That ' +
           'is not a fault: the nudge is an optimisation and the PEP still ' +
           'pulls on its own interval.';
  }
  let parsed;
  try {
    parsed = new URL(String(raw));
  } catch (error) {
    // Not JSON and not a URL; the raw text is what gets shown, so the parse
    // failure itself carries no information worth keeping.
    log.debug('Leaving urlProblem(). Unparseable.');
    return 'That is not a URL.';
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    log.debug('Leaving urlProblem(). Wrong scheme.');
    return 'A notify URL is http or https; this one is "' +
           parsed.protocol.replace(/:$/, '') + '".';
  }
  if (parsed.protocol === 'http:' && !allowInsecure()) {
    log.debug('Leaving urlProblem(). Insecure.');
    return 'This notify URL is plain http and ' +
           'xacml.pepNotifyAllowInsecure is off. A nudge carries no ' +
           'credential and no event, so this is the mildest of this ' +
           'service\'s three outbound refusals — but a request made in the ' +
           'clear is a request somebody else can answer for.';
  }
  const list = allowedHosts();
  if (list.length && list.indexOf(parsed.hostname.toLowerCase()) < 0) {
    log.debug('Leaving urlProblem(). Not on the allowlist.');
    return 'The host "' + parsed.hostname + '" is not in ' +
           'xacml.pepNotifyAllowedHosts (' + list.join(', ') + ').';
  }
  log.debug('Leaving urlProblem(). None.');
  return null;
}

// ---------------------------------------------------------------------------
// THE NUDGE ITSELF.
//
// Resolves — never rejects — with `{ ok, status, why }`, because every caller
// of this wants to RECORD what happened rather than to handle it. A nudge that
// failed is a sentence on a console row; there is no recovery to attempt and
// nothing upstream that should stop because of one.
//
// THE BODY IS THREE MEMBERS AND THE HEADER ABOVE DEPENDS ON THAT. It says that
// something changed, when, and which PDP is saying so — and nothing a PEP
// could not get by pulling. Adding a fourth that carries content removes the
// argument for this file existing.
// ---------------------------------------------------------------------------
function nudge(url, issuer, options) {
  log.debug('Entering nudge(). url=' + url);
  const settings = options || {};
  return new Promise(function (resolve) {
    if (!notifyAllowed()) {
      log.debug('Leaving nudge(). Notification is off.');
      resolve({ ok: false, status: 0,
                why: 'xacml.pepNotify is off, so nothing was dialled. The ' +
                     'PEP converges on its next poll.' });
      return;
    }
    const problem = urlProblem(url);
    if (problem) {
      log.debug('Leaving nudge(). Refused before dialling.');
      resolve({ ok: false, status: 0, why: problem });
      return;
    }
    const parsed = new URL(String(url));
    const insecure = parsed.protocol === 'http:';
    const body = JSON.stringify({
      event: 'policy-repository-changed',
      at: new Date().toISOString(),
      pdp: String(issuer || '')
    });
    if (insecure) {
      // Logged per REQUEST rather than once when the setting was read, for
      // federation's reason: a check disabled six months ago and forgotten is
      // the worst kind of leftover.
      log.warn('xacml: nudging ' + parsed.origin + ' over plain http ' +
               '(xacml.pepNotifyAllowInsecure is on).');
    }
    const transport = insecure ? http : https;
    const request = transport.request({
      method: 'POST',
      hostname: parsed.hostname,
      port: parsed.port || (insecure ? 80 : 443),
      path: parsed.pathname + parsed.search,
      headers: { 'Content-Type': 'application/json',
                 'Content-Length': Buffer.byteLength(body) },
      timeout: timeoutMs(),
      // A PEP's certificate is its own and this service is not the authority
      // for it. `allowInsecure` covers both halves of "insecure" on purpose —
      // it is one decision, and two settings would let somebody turn off the
      // half they did not mean to.
      rejectUnauthorized: !allowInsecure()
    }, function (response) {
      let received = 0;
      const chunks = [];
      response.on('data', function (chunk) {
        received += chunk.length;
        if (received <= MAX_BODY_BYTES) {
          chunks.push(chunk);
          return;
        }
        // A body over the cap is not read further and the request is ended.
        // What a PEP says back is not used for anything, so there is nothing
        // to lose by truncating it.
        response.destroy();
      });
      response.on('end', function () {
        const status = response.statusCode || 0;
        if (status >= 300 && status < 400) {
          log.debug('Leaving nudge(). A redirect.');
          resolve({ ok: false, status: status,
                    why: 'The notify endpoint answered ' + status +
                         '. Redirects are not followed: a nudge posted ' +
                         'wherever a Location said would be this service ' +
                         'dialling an address nobody configured.' });
          return;
        }
        if (status >= 200 && status < 300) {
          log.debug('Leaving nudge(). ' + status);
          resolve({ ok: true, status: status,
                    why: 'The PEP answered ' + status + '.' });
          return;
        }
        const text = Buffer.concat(chunks).toString('utf8').trim();
        log.debug('Leaving nudge(). Refused with ' + status);
        resolve({ ok: false, status: status,
                  why: 'The PEP answered ' + status +
                       (text ? ': ' + text.slice(0, 300) : '.') });
      });
    });
    request.on('timeout', function () {
      request.destroy(new Error('the notify endpoint did not answer within ' +
                                timeoutMs() + 'ms'));
    });
    request.on('error', function (error) {
      log.debug('Leaving nudge(). Failed.');
      resolve({ ok: false, status: 0,
                why: 'The nudge could not be delivered: ' +
                     (error && error.message ? error.message :
                      String(error)) +
                     '. The PEP converges on its next poll.' });
    });
    request.end(body);
  });
}

// ---------------------------------------------------------------------------
// NUDGE EVERY REGISTERED PEP THAT HAS A URL. Awaited by nobody who is holding
// a browser: `xacml.js` calls this and does not wait, because a console form
// that saved a policy has finished its work whether or not four PEPs answered.
// The result of each is recorded on that PEP's row.
// ---------------------------------------------------------------------------
function nudgeAll(rows, issuer, record) {
  log.debug('Entering nudgeAll(). ' + (rows || []).length + ' PEP(s).');
  const work = (rows || []).map(function (row) {
    return nudge(row.notifyUrl, issuer).then(function (result) {
      if (typeof record === 'function') {
        record(row.name, result.why);
      }
      return { name: row.name, ok: result.ok, status: result.status,
               why: result.why };
    });
  });
  log.debug('Leaving nudgeAll(). Dispatched.');
  return Promise.all(work);
}

module.exports = {
  MAX_BODY_BYTES: MAX_BODY_BYTES,
  notifyAllowed: notifyAllowed,
  allowInsecure: allowInsecure,
  allowedHosts: allowedHosts,
  timeoutMs: timeoutMs,
  urlProblem: urlProblem,
  nudge: nudge,
  nudgeAll: nudgeAll
};
