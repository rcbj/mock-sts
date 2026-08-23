'use strict';
//
// File: spnego.js
//
// NOTE ON THE NAME. The RFC 4178 codec beside this file is krb5_spnego.js and
// is VENDORED — a byte-identical copy of common/krb5/krb5_spnego.js in the
// parent project, kept honest by tests/krb5_codec_sync.js. This file is the
// mock's own, so it is named for the protocol like wsfed.js and wstrust.js
// rather than for the codec. Do not merge the two: one is somebody else's file.
//
// ---------------------------------------------------------------------------
// A SPNEGO-protected web page: Kerberos over HTTP, RFC 4559 and RFC 4178.
//
// krb5_service.js said this would come — "an HTTP service wrapping the same
// token in a `Negotiate` header is SPNEGO, which is the next phase; the
// acceptor logic here is written as its own function so that phase adds a
// transport and no protocol code". This is that phase, and the promise held:
// every Kerberos check still happens in krb5_service.js's accept(), and what is
// here is the negotiation around it and the HTTP that carries it.
//
// ---------------------------------------------------------------------------
// THE EXCHANGE, which is two round trips and looks like one.
//
//   GET /spnego/protected                          (no Authorization)
//   401 WWW-Authenticate: Negotiate                (the bare challenge)
//
//   GET /spnego/protected
//   Authorization: Negotiate <NegTokenInit>        mechTypes + an AP-REQ
//   200 WWW-Authenticate: Negotiate <NegTokenResp> accept-completed + AP-REP
//
// The first 401 carries NO token. That is RFC 4559 section 4: the server says
// only that it will negotiate, and the client — which already knows the SPN
// from the URL — goes to the KDC by itself. Nothing about which KDC, which
// realm or which SPN is in this exchange at all, which is why a SPNEGO failure
// so often turns out to be a DNS or SPN problem with no evidence on the wire.
//
// ---------------------------------------------------------------------------
// WHAT THIS ACCEPTOR IS DELIBERATELY STRICT ABOUT, AND WHAT IT IS NOT.
//
// Strict: the mechanism list must contain Kerberos, the mechListMIC is verified
// when one is sent, and a MIC that does not verify is a REJECT rather than a
// warning. That last one is the whole point of RFC 4178 section 5 — the MIC is
// what makes a mechanism list unforgeable, so an acceptor that logs a bad MIC
// and continues has implemented the syntax and none of the protection.
//
// Not strict: it accepts a BARE Kerberos InitialContextToken (no negotiation at
// all), because real clients send one and a debugger that refused it would be
// teaching something false. It says so in the response body rather than hiding
// the difference.
//
// ---------------------------------------------------------------------------
// THE KEY THE mechListMIC IS COMPUTED WITH, which is the one thing here nobody
// can guess and every implementation has to agree on.
//
// The two MICs use DIFFERENT keys, and the asymmetry is forced by when each one
// is computed rather than chosen:
//
//  * The INITIATOR's mechListMIC travels in the NegTokenInit, which is built
//    before any answer exists. The only context key that exists at that moment
//    is the subkey in its own Authenticator (or, if it sent none, the ticket's
//    session key). So that is the key, with the initiator's key usage, 25.
//  * The ACCEPTOR's mechListMIC travels beside the AP-REP, by which point the
//    acceptor has offered a subkey of its own — and RFC 4121 makes THAT the
//    context key once it is offered. So the acceptor's MIC uses the acceptor
//    subkey, with the acceptor's key usage, 23.
//
// Both are over the DER of the MechTypeList — the SEQUENCE, not the `[0]`
// wrapper it sits behind inside NegTokenInit (RFC 4178 section 5). Both use
// sequence number 0. Getting any of that wrong produces a MIC that verifies
// against nothing, and an error naming a checksum.
// ---------------------------------------------------------------------------

const app = require('../common/app');
const { log, xmlEscape } = require('../common/helpers');
const prim = require('./krb5_primitives.js');
const msgs = require('./krb5_messages.js');
const kcrypto = require('./krb5_crypto.js');
const gss = require('./krb5_gss.js');
const spnego = require('./krb5_spnego.js');
const principals = require('./krb5_principals.js');
const krb5Service = require('./krb5_service.js');

// What this acceptor supports, in ITS order of preference. Kerberos first
// because it is the only thing here that works — NTLM is listed by every real
// Windows server and is not implemented, so offering it would be a lie a client
// could act on.
const SUPPORTED_MECHS = [spnego.KRB5_MECH_OID, spnego.MS_KRB5_MECH_OID];

// A half-finished negotiation, held between the two requests of a request-mic
// exchange. A real acceptor keeps this on the CONNECTION — that is what RFC
// 4559 section 5 means by the authentication being connection-based, and it is
// why HTTP/2 and connection-pooling proxies break SPNEGO in ways nothing
// reports. Node's Express gives no stable connection identity here, so this
// stands in with the remote address plus the mechanism list, held briefly.
// Being a stand-in is stated rather than hidden: it is the one place this mock
// is structurally unlike a real server.
const PENDING_TTL_MS = 120000;
const MAX_PENDING = 64;
const pending = new Map();

function pendingKey(req, mechListDer) {
  log.debug('Entering pendingKey().');
  const who = (req.ip || req.connection.remoteAddress || 'unknown');
  log.debug('Leaving pendingKey().');
  return who + '|' + prim.toHex(mechListDer);
}

function prunePending(nowMs) {
  log.debug('Entering prunePending().');
  for (const [key, entry] of pending) {
    if (nowMs - entry.at > PENDING_TTL_MS) {
      pending.delete(key);
    }
  }
  while (pending.size > MAX_PENDING) {
    pending.delete(pending.keys().next().value);
  }
  log.debug('Leaving prunePending().');
}

// ---------------------------------------------------------------------------
// The HTML the two pages share. A local copy of wsfed.js's page() rather than a
// require of it: server.js's require order IS the route order and the modules
// deliberately do not reach sideways into each other (see CLAUDE.md rule 2), so
// a shared page helper would belong in helpers.js and moving it there means
// touching five protocols for one new page.
// ---------------------------------------------------------------------------
function page(title, inner) {
  log.debug('Entering page().');
  log.debug('Leaving page().');
  return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + xmlEscape(title) + '</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'padding:2rem;color:#222;line-height:1.45}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:24px 28px;' +
    'max-width:52rem;margin:0 auto;box-shadow:0 6px 24px rgba(0,0,0,.08)}' +
    'h1{font-size:1.3em;margin:0 0 4px;color:#12107c}h2{font-size:1em;margin:1.4em 0 .4em}' +
    'p.sub{color:#666;font-size:.85em;margin:0 0 18px}' +
    'table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;font-size:.85em}' +
    'th,td{border:1px solid #ddd;padding:.35rem .55rem;text-align:left;vertical-align:top}' +
    'th{background:#f0f0f5}.pass{color:#0b6b4f;font-weight:600;white-space:nowrap}' +
    '.fail{color:#b00020;font-weight:600;white-space:nowrap}' +
    '.err{background:#fdecea;border:1px solid #f5c6c2;color:#b00020;padding:8px 10px;border-radius:5px;' +
    'font-size:.9em;margin-bottom:12px}' +
    '.ok{background:#e8f5e9;border:1px solid #a5d6a7;padding:8px 10px;border-radius:5px;' +
    'font-size:.9em;margin-bottom:12px}' +
    'pre{background:#f4f4f8;border:1px solid #e2e2ea;border-radius:5px;padding:.6rem;font-size:.75rem;' +
    'overflow-x:auto;white-space:pre-wrap;word-break:break-all}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em;background:#f4f4f8;' +
    'padding:.1rem .25rem;border-radius:3px;word-break:break-all}a{color:#12107c}' +
    'ul{margin:.3em 0;padding-left:1.2em}li{margin:.2em 0}' +
    '</style></head><body><div class="card">' + inner + '</div></body></html>\n';
}

function checksTable(checks) {
  log.debug('Entering checksTable().');
  const rows = (checks || []).map(function (c) {
    return '<tr><td>' + xmlEscape(c.name) + '</td><td class="' +
      (c.ok ? 'pass">passed' : 'fail">FAILED') + '</td><td>' +
      xmlEscape(c.detail == null ? '' : String(c.detail)) + '</td></tr>';
  }).join('');
  log.debug('Leaving checksTable().');
  return '<table><tr><th>Check</th><th>Result</th><th>Detail</th></tr>' +
    rows + '</table>';
}

// ---------------------------------------------------------------------------
// The advertisement. A page that says a protected resource exists, what SPN it
// is behind, and what a client has to do — which is the part a real intranet
// site never tells you and the part that is always wrong.
// ---------------------------------------------------------------------------
const SPN = krb5Service.SERVICE_PRINCIPAL.join('/');

app.get('/spnego', function (req, res) {
  log.debug('Entering GET /spnego.');
  const principal = SPN + '@' + principals.REALM;
  if (String(req.query.format || '').toLowerCase() === 'json') {
    log.debug('Leaving GET /spnego. JSON.');
    return res.status(200).json({
      protectedResource: '/spnego/protected',
      servicePrincipalName: principal,
      // The SPN a client DERIVES from this URL's host is usually not the
      // canonical one above — RFC 4559 clients guess `HTTP/<url host>`, so
      // reaching this mock at localhost or by its compose name produces
      // HTTP/localhost or HTTP/sts. This service holds a key for any SPN whose
      // host matches one of these, and the KDC registers it on first sight, so a
      // client's own guess works. NOTHING IN SPNEGO CARRIES THIS: it is an
      // affordance of the mock, published so a debugger can show what a real
      // deployment would make you look up in DNS and in the account's keytab.
      acceptsAnySpnForHosts: principals.SERVICE_DOMAINS,
      spnHostRule: 'a host matches when it IS one of acceptsAnySpnForHosts or ' +
        'ends with a dot and one of them',
      mechanisms: SUPPORTED_MECHS.map(function (oid) {
        return { oid: oid, name: spnego.mechName(oid) };
      }),
      scheme: 'Negotiate',
      specifications: ['RFC 4178 (SPNEGO)', 'RFC 4559 (Negotiate over HTTP)',
                       'RFC 4121 (the Kerberos v5 GSS-API mechanism)'],
      knobs: {
        'mic=require': 'answer the first token with request-mic, forcing the ' +
          'mechListMIC exchange and a second round trip',
        'mech=none': 'support no mechanism the client offers, so the ' +
          'negotiation is rejected',
        'mutual=off': 'accept the ticket but send no AP-REP back'
      },
      lastExchange: lastExchange
    });
  }
  const inner = '<h1>A SPNEGO-protected page lives here</h1>' +
    '<p class="sub">Kerberos over HTTP: RFC 4559 carries RFC 4178, which ' +
    'carries RFC 4121, which carries the AP-REQ.</p>' +
    '<p><a href="/spnego/protected"><strong>/spnego/protected</strong></a> ' +
    'answers <code>401</code> with <code>WWW-Authenticate: Negotiate</code> ' +
    'to anyone who asks for it without a ticket. Your browser will most ' +
    'likely fail that: Chrome and Firefox use Negotiate only for hosts on an ' +
    'explicit allow-list, so what you will see is the 401 itself. That is ' +
    'the point of the debugger &mdash; it performs the handshake by hand and ' +
    'shows you both halves.</p>' +
    '<h2>What a client needs before it can get in</h2>' +
    '<table>' +
    '<tr><th>Thing</th><th>Value</th></tr>' +
    '<tr><td>Service principal name</td><td><code>' +
      xmlEscape(principal) + '</code></td></tr>' +
    '<tr><td>Realm</td><td><code>' + xmlEscape(principals.REALM) +
      '</code></td></tr>' +
    '<tr><td>Authentication scheme</td><td><code>Negotiate</code></td></tr>' +
    '<tr><td>Mechanisms accepted</td><td>' +
      SUPPORTED_MECHS.map(function (oid) {
        return '<code>' + xmlEscape(oid) + '</code> (' +
          xmlEscape(spnego.mechName(oid)) + ')';
      }).join('<br>') + '</td></tr>' +
    '</table>' +
    '<p>Note what is <em>not</em> in the exchange: the realm, the KDC, and ' +
    'the SPN. The client derives the SPN from the URL&rsquo;s host name and ' +
    'finds the KDC from its own configuration, so a SPNEGO failure is ' +
    'usually a DNS or SPN problem that leaves no evidence on the wire at ' +
    'all. The SPN this service holds a key for is above; a ticket for any ' +
    'other name is refused with <code>KRB_AP_ERR_NOT_US</code>.</p>' +
    '<h2>Deliberate misconfigurations</h2>' +
    '<p>Add these to <code>/spnego/protected</code> to make the negotiation ' +
    'go wrong in one specific way &mdash; which is what this mock is for:</p>' +
    '<ul>' +
    '<li><code>?mic=require</code> &mdash; answer with ' +
      '<code>request-mic</code>, so the mechListMIC exchange becomes ' +
      'mandatory and the handshake takes a second round trip.</li>' +
    '<li><code>?mech=none</code> &mdash; support nothing the client offers, ' +
      'so the negotiation ends in <code>reject</code> with no explanation, ' +
      'exactly as the protocol requires.</li>' +
    '<li><code>?mutual=off</code> &mdash; accept the ticket and send no ' +
      'AP-REP, so the client is authenticated and has proved nothing about ' +
      'the server.</li>' +
    '</ul>' +
    '<p class="sub"><a href="/spnego?format=json">This page as JSON</a> ' +
    '&middot; <a href="/krb5/principals">the KDC&rsquo;s principals</a> ' +
    '&middot; <a href="/sts-metadata">everything this service speaks</a></p>';
  res.status(200).type('html').send(page('SPNEGO-protected page', inner));
  log.debug('Leaving GET /spnego.');
});

// ---------------------------------------------------------------------------
// The protected resource.
// ---------------------------------------------------------------------------
let lastExchange = null;

function record(outcome) {
  log.debug('Entering record().');
  lastExchange = Object.assign({ at: new Date().toISOString() }, outcome);
  log.debug('Leaving record().');
}

// ---------------------------------------------------------------------------
// WHAT THIS MOCK VOLUNTEERS THAT NO REAL SERVER DOES, and why it is two headers.
//
// RFC 4559's challenge is `WWW-Authenticate: Negotiate` and nothing else. It does
// not say the realm, the KDC or the SPN — so a client guesses `HTTP/<url host>`,
// and when that guess is wrong the whole exchange fails at the KDC with an error
// that names nothing about HTTP. That silence is the protocol's, it is the single
// commonest cause of a SPNEGO failure in the field, and this mock cannot fix it
// for the world. What it CAN do is stop being another instance of it.
//
// So the challenge carries two extra headers, on every 401 this resource sends:
//
//   X-Krb5-Service-Principal   the SPN this service holds a key for, canonically
//   X-Krb5-Accepts-Spn-Hosts   every host it will answer for, comma-separated
//
// They are inert to every real client (an unknown header is ignored), they cost
// nothing, and they are what lets the debugger say "your derived SPN will work
// here" or "this service says it is X" BEFORE sending somebody to the KDC for a
// ticket that cannot be issued. `X-` because they are nobody's standard: they are
// this mock talking to this debugger, and the page labels them as such rather than
// presenting them as something it learned from the protocol.
// ---------------------------------------------------------------------------
function volunteerTheSpn(res) {
  log.debug('Entering volunteerTheSpn().');
  res.set('X-Krb5-Service-Principal', SPN + '@' + principals.REALM);
  res.set('X-Krb5-Accepts-Spn-Hosts', principals.SERVICE_DOMAINS.join(','));
  log.debug('Leaving volunteerTheSpn().');
}

// The bare challenge. No token: RFC 4559 section 4 — the server says only that
// it will negotiate, and everything else is the client's problem.
function challenge(res, body, status) {
  log.debug('Entering challenge().');
  res.set('WWW-Authenticate', 'Negotiate');
  volunteerTheSpn(res);
  res.status(status || 401).type('html').send(body);
  log.debug('Leaving challenge().');
}

// A challenge that carries a token back — a continuation or a refusal.
function challengeWith(res, token, body, status) {
  log.debug('Entering challengeWith().');
  res.set('WWW-Authenticate', 'Negotiate ' +
    Buffer.from(token).toString('base64'));
  volunteerTheSpn(res);
  res.status(status || 401).type('html').send(body);
  log.debug('Leaving challengeWith().');
}

function refusal(res, reason, detail, checks) {
  log.debug('Entering refusal().');
  record({ ok: false, reason: reason, checks: checks || null });
  const token = spnego.encodeNegTokenResp({
    negState: spnego.NEG_STATE.REJECT
  });
  const inner = '<h1>401 &mdash; the negotiation was rejected</h1>' +
    '<div class="err">' + xmlEscape(reason) + '</div>' +
    (detail ? '<p>' + detail + '</p>' : '') +
    (checks ? '<h2>What this service checked</h2>' + checksTable(checks) : '') +
    '<p class="sub">SPNEGO&rsquo;s <code>reject</code> carries no reason of ' +
    'its own &mdash; the structure has no field for one. Everything above ' +
    'this line is out of band, and a real server tells you none of it.</p>';
  challengeWith(res, token, page('Rejected', inner));
  log.debug('Leaving refusal().');
}

// Which of the client's mechanisms this acceptor will use, respecting the
// CLIENT's order of preference — RFC 4178 section 4.1 makes the mechTypes list
// ordered, and an acceptor that imposes its own order is what makes the
// mechListMIC exchange mandatory rather than optional.
function selectMech(offered, supported) {
  log.debug('Entering selectMech().');
  for (let i = 0; i < offered.length; i++) {
    if (supported.indexOf(offered[i]) !== -1) {
      log.debug('Leaving selectMech(). ' + offered[i]);
      return offered[i];
    }
  }
  log.debug('Leaving selectMech(). None.');
  return null;
}

// The key each side signs the mechanism list with. See the header: the
// asymmetry is forced by WHEN each MIC is computed, not chosen.
function initiatorMicKey(result) {
  log.debug('Entering initiatorMicKey().');
  const key = result.initiatorSubkey || {
    etype: result.sessionKeyEtype,
    key: result.sessionKey
  };
  log.debug('Leaving initiatorMicKey().');
  return key;
}

async function handleProtected(req, res) {
  log.debug('Entering handleProtected().');
  const supported = String(req.query.mech || '') === 'none' ? [] :
    SUPPORTED_MECHS;
  const wantMic = String(req.query.mic || '') === 'require';
  const mutualOff = String(req.query.mutual || '') === 'off';
  const header = req.get('authorization') || '';

  if (!header) {
    record({ ok: false, reason: 'no Authorization header; challenged' });
    log.info('krb5-spnego: no Authorization header — answering 401 with a ' +
      'bare Negotiate challenge');
    const inner = '<h1>401 &mdash; authentication required</h1>' +
      '<p>This resource is protected with <code>Negotiate</code>. The ' +
      'challenge above carries <strong>no token</strong>, which is RFC 4559 ' +
      'section 4: the server says only that it will negotiate, and the ' +
      'client is expected to know the rest already.</p>' +
      '<p>What the client has to work out for itself, with no help from this ' +
      'exchange: that the service principal name is <code>' +
      xmlEscape(SPN) + '</code>, which realm that is in, and where that ' +
      'realm&rsquo;s KDC is.</p>';
    challenge(res, page('Authentication required', inner));
    log.debug('Leaving handleProtected(). Challenged.');
    return;
  }

  const match = /^Negotiate\s+([A-Za-z0-9+/=]*)\s*$/i.exec(header.trim());
  if (!match) {
    // A scheme this resource does not speak. Named, because "401" on its own
    // sends people to look at their ticket when they sent Basic.
    const scheme = header.split(/\s/)[0] || '(none)';
    record({ ok: false, reason: 'Authorization scheme ' + scheme });
    log.info('krb5-spnego: refusing Authorization scheme ' + scheme);
    const inner = '<h1>401 &mdash; wrong authentication scheme</h1>' +
      '<div class="err">This resource speaks <code>Negotiate</code>. The ' +
      'request offered <code>' + xmlEscape(scheme) + '</code>.</div>';
    challenge(res, page('Wrong scheme', inner));
    log.debug('Leaving handleProtected(). Wrong scheme.');
    return;
  }
  if (!match[1]) {
    record({ ok: false, reason: 'an empty Negotiate token' });
    const inner = '<h1>401 &mdash; an empty Negotiate token</h1>' +
      '<div class="err">The <code>Authorization</code> header named ' +
      '<code>Negotiate</code> and carried nothing after it.</div>';
    challenge(res, page('Empty token', inner));
    log.debug('Leaving handleProtected(). Empty token.');
    return;
  }

  const tokenBytes = new Uint8Array(Buffer.from(match[1], 'base64'));
  let parsed;
  try {
    parsed = spnego.decodeNegotiationToken(tokenBytes);
  } catch (e) {
    refusal(res, 'the Negotiate token does not decode: ' + e.message,
      '<p>The bytes after <code>Negotiate </code> must be a SPNEGO ' +
      'negotiation token (RFC 4178) or a bare Kerberos GSS token (RFC 4121).' +
      '</p>');
    log.debug('Leaving handleProtected(). Undecodable.');
    return;
  }

  // A continuation: the client answering our request-mic with the MIC alone.
  if (parsed.kind === 'NegTokenResp') {
    await handleContinuation(req, res, parsed);
    log.debug('Leaving handleProtected(). Continuation.');
    return;
  }

  let mechToken = null;
  let selected = null;
  let mechListDer = null;
  let rawKerberos = false;

  if (parsed.kind === 'RawKerberos') {
    // No negotiation at all. Accepted, because real clients do this and a
    // debugger that refused would be teaching something false — but the
    // difference is stated rather than smoothed over, since none of SPNEGO's
    // protection applies to it.
    rawKerberos = true;
    mechToken = tokenBytes;
    selected = spnego.KRB5_MECH_OID;
  } else {
    mechListDer = parsed.mechListDer;
    selected = selectMech(parsed.mechTypes, supported);
    if (!selected) {
      refusal(res, 'no mechanism in common',
        '<p>The client offered ' + parsed.mechTypes.length + ' mechanism(s): ' +
        parsed.mechTypes.map(function (oid, i) {
          return '<code>' + xmlEscape(oid) + '</code> (' +
            xmlEscape(parsed.mechTypeNames[i]) + ')';
        }).join(', ') + '. This service supports ' +
        (supported.length
          ? supported.map(function (oid) {
              return '<code>' + xmlEscape(oid) + '</code>';
            }).join(', ')
          : '<strong>nothing</strong> &mdash; <code>?mech=none</code> is set') +
        '.</p>');
      log.debug('Leaving handleProtected(). No common mechanism.');
      return;
    }
    if (!parsed.mechToken) {
      // A pessimistic NegTokenInit: the client named its mechanisms and sent
      // no token. Legal, and it costs the round trip the optimistic token
      // exists to avoid.
      record({ ok: false, reason: 'no optimistic mechToken; asked for one' });
      const token = spnego.encodeNegTokenResp({
        negState: spnego.NEG_STATE.ACCEPT_INCOMPLETE,
        supportedMech: selected
      });
      const inner = '<h1>401 &mdash; send the mechanism&rsquo;s token</h1>' +
        '<p>The <code>NegTokenInit</code> carried a mechanism list and no ' +
        '<code>mechToken</code>, so this reply selects <code>' +
        xmlEscape(spnego.mechName(selected)) + '</code> and asks for one: ' +
        '<code>accept-incomplete</code>. That is the round trip the ' +
        '&ldquo;optimistic&rdquo; token exists to avoid.</p>';
      challengeWith(res, token, page('Send a token', inner));
      log.debug('Leaving handleProtected(). Asked for a mechToken.');
      return;
    }
    mechToken = parsed.mechToken;
    if (!spnego.isKerberosMech(selected)) {
      refusal(res, 'the selected mechanism is not one this service performs',
        '<p>Selected <code>' + xmlEscape(selected) + '</code>.</p>');
      log.debug('Leaving handleProtected(). Non-Kerberos mechanism.');
      return;
    }
  }

  // The Kerberos half, unchanged: krb5_service.js's acceptor does every check
  // it does over a raw socket. This module adds no protocol code to it, which
  // was the design promise the split was made for.
  let result;
  try {
    // `via` only names the transport for the console: every Kerberos check is that
    // module's, and this one adds none. Without it a SPNEGO sign-in would be filed
    // as a raw-socket one, which is the difference between "a browser did this" and
    // "something on port 8888 did".
    result = await krb5Service.accept(mechToken, { via: 'SPNEGO over HTTP (RFC 4559)' });
  } catch (e) {
    log.error('krb5-spnego: the acceptor threw: ' + (e.stack || e.message));
    refusal(res, 'the Kerberos acceptor failed: ' + e.message, null);
    log.debug('Leaving handleProtected(). Acceptor threw.');
    return;
  }

  if (!result.ok) {
    // The mechanism's own error token goes back INSIDE the responseToken. This
    // is the only way a SPNEGO rejection can say why: negState has no reason
    // field, so the KRB-ERROR is the entire diagnosis.
    record({ ok: false, reason: 'the Kerberos AP-REQ was refused',
             checks: result.checks });
    const token = spnego.encodeNegTokenResp({
      negState: spnego.NEG_STATE.REJECT,
      supportedMech: selected,
      responseToken: result.reply
        ? gss.encodeInitialContextToken(gss.TOK_ID.KRB_ERROR, result.reply)
        : null
    });
    const inner = '<h1>401 &mdash; the ticket was refused</h1>' +
      '<div class="err">The negotiation selected Kerberos and the AP-REQ ' +
      'did not pass.</div>' +
      '<p>The reason is in the <code>responseToken</code> of the ' +
      '<code>WWW-Authenticate</code> header, as a <code>KRB-ERROR</code>. ' +
      'SPNEGO itself carries no error detail at all, so a client that reads ' +
      'only <code>negState</code> learns nothing but &ldquo;no&rdquo;.</p>' +
      '<h2>What this service checked</h2>' + checksTable(result.checks);
    challengeWith(res, token, page('Ticket refused', inner));
    log.debug('Leaving handleProtected(). Ticket refused.');
    return;
  }

  // The mechanism list is now integrity-protected, or it is not, and RFC 4178
  // section 5 decides which of those is acceptable.
  const requirement = rawKerberos
    ? { required: false, reason: 'There is no mechanism list to protect: ' +
        'this was a bare Kerberos token with no negotiation around it.' }
    : spnego.micRequirement(parsed.mechTypes, selected);
  const initiatorKey = initiatorMicKey(result);

  if (parsed && parsed.mechListMic) {
    let verdict;
    try {
      verdict = await spnego.verifyMechListMic({
        key: initiatorKey.key,
        etype: initiatorKey.etype,
        mic: parsed.mechListMic,
        mechListDer: mechListDer
      });
    } catch (e) {
      verdict = { ok: false, error: e.message };
    }
    if (!verdict.ok) {
      // A REJECT, not a warning. An acceptor that logs a bad MIC and carries
      // on has implemented RFC 4178 section 5's syntax and none of its
      // protection — the MIC is the only thing standing between this
      // negotiation and an attacker who edited the mechanism list on the wire.
      refusal(res, 'the mechListMIC does not verify' +
        (verdict.error ? ': ' + verdict.error : ''),
        '<p>The client&rsquo;s ticket was perfectly good. What failed is the ' +
        'integrity check over the <em>mechanism list</em> &mdash; so either ' +
        'the list was altered in transit, or the client computed the MIC ' +
        'over the wrong bytes. The commonest cause of the second is signing ' +
        '<code>[0] MechTypeList</code> rather than <code>MechTypeList</code>: ' +
        'two bytes, and RFC 4178 section 5 spells the distinction out because ' +
        'implementations kept getting it wrong.</p>', result.checks);
      log.debug('Leaving handleProtected(). Bad mechListMIC.');
      return;
    }
    log.info('krb5-spnego: the mechListMIC verifies (' + verdict.senderRole +
      ', sequence ' + verdict.sequenceNumber + ')');
  } else if (requirement.required && !rawKerberos) {
    refusal(res, 'a mechListMIC was required and none was sent',
      '<p>' + xmlEscape(requirement.reason) + '</p>', result.checks);
    log.debug('Leaving handleProtected(). Missing required mechListMIC.');
    return;
  } else if (wantMic && !rawKerberos) {
    // The knob: force the exchange even though section 5 would let it be
    // skipped. Real acceptors do this — Windows sets request-mic whenever it
    // wants the list protected regardless of preference order.
    prunePending(Date.now());
    pending.set(pendingKey(req, mechListDer), {
      at: Date.now(),
      mechListDer: mechListDer,
      selected: selected,
      initiatorKey: initiatorKey,
      acceptorSubkey: result.acceptorSubkey || null,
      client: result.client
    });
    const micToken = spnego.encodeNegTokenResp({
      negState: spnego.NEG_STATE.REQUEST_MIC,
      supportedMech: selected,
      responseToken: result.reply || null
    });
    record({ ok: false, reason: 'request-mic sent; awaiting the client MIC',
             client: result.client });
    const inner = '<h1>401 &mdash; send the mechListMIC</h1>' +
      '<p>The ticket was accepted, and this reply is ' +
      '<code>request-mic</code>: the mechanism list must be integrity ' +
      'protected before the context is usable. Legal only in the ' +
      'acceptor&rsquo;s first reply (RFC 4178 section 4.2.2).</p>' +
      '<p>Answer with a bare <code>NegTokenResp</code> carrying only the ' +
      '<code>mechListMIC</code>, computed over the DER of the ' +
      '<code>MechTypeList</code> with the subkey from your Authenticator.</p>';
    challengeWith(res, micToken, page('Send the MIC', inner));
    log.debug('Leaving handleProtected(). request-mic.');
    return;
  }

  await succeed(res, {
    result: result,
    selected: selected,
    mechListDer: mechListDer,
    requirement: requirement,
    rawKerberos: rawKerberos,
    micVerified: !!(parsed && parsed.mechListMic),
    mutualOff: mutualOff
  });
  log.debug('Leaving handleProtected(). Accepted.');
}

// The client's answer to request-mic: a bare NegTokenResp carrying the MIC and
// nothing else. The context it belongs to is the pending one.
async function handleContinuation(req, res, parsed) {
  log.debug('Entering handleContinuation().');
  prunePending(Date.now());
  let entry = null;
  let entryKey = null;
  for (const [key, value] of pending) {
    if (key.indexOf((req.ip || req.connection.remoteAddress || 'unknown') +
        '|') === 0) {
      entry = value;
      entryKey = key;
    }
  }
  if (!entry) {
    refusal(res, 'there is no negotiation in progress to continue',
      '<p>A bare <code>NegTokenResp</code> arrived, but nothing here is ' +
      'waiting for one. A real acceptor keeps this state on the ' +
      '<em>connection</em>, which is why SPNEGO breaks behind ' +
      'connection-pooling proxies and on HTTP/2 in ways nothing reports.</p>');
    log.debug('Leaving handleContinuation(). Nothing pending.');
    return;
  }
  pending.delete(entryKey);
  if (!parsed.mechListMic) {
    refusal(res, 'the continuation carried no mechListMIC',
      '<p>The previous reply was <code>request-mic</code>, so the only ' +
      'thing this token needed was the MIC.</p>');
    log.debug('Leaving handleContinuation(). No MIC.');
    return;
  }
  let verdict;
  try {
    verdict = await spnego.verifyMechListMic({
      key: entry.initiatorKey.key,
      etype: entry.initiatorKey.etype,
      mic: parsed.mechListMic,
      mechListDer: entry.mechListDer
    });
  } catch (e) {
    verdict = { ok: false, error: e.message };
  }
  if (!verdict.ok) {
    refusal(res, 'the mechListMIC does not verify' +
      (verdict.error ? ': ' + verdict.error : ''),
      '<p>Computed over the DER of the <code>MechTypeList</code> &mdash; the ' +
      'SEQUENCE, not the <code>[0]</code> wrapper (RFC 4178 section 5).</p>');
    log.debug('Leaving handleContinuation(). Bad MIC.');
    return;
  }
  await succeed(res, {
    result: {
      ok: true,
      client: entry.client,
      acceptorSubkey: entry.acceptorSubkey,
      checks: [{ name: 'mechListMIC verifies', ok: true,
                 detail: 'sent by the ' + verdict.senderRole +
                   ', sequence ' + verdict.sequenceNumber }]
    },
    selected: entry.selected,
    mechListDer: entry.mechListDer,
    requirement: { required: true,
                   reason: 'This acceptor asked for it with request-mic.' },
    rawKerberos: false,
    micVerified: true,
    mutualOff: false,
    continuation: true
  });
  log.debug('Leaving handleContinuation(). Accepted.');
}

// 200, and the token that proves who answered.
async function succeed(res, ctx) {
  log.debug('Entering succeed().');
  const result = ctx.result;
  let mic = null;
  let micNote = null;
  if (ctx.mechListDer && result.acceptorSubkey) {
    // The ACCEPTOR's MIC, and it is keyed differently from the client's — see
    // the header. The acceptor subkey is the context key once it has been
    // offered, and the key usage is the acceptor's, 23.
    try {
      mic = await spnego.computeMechListMic({
        key: result.acceptorSubkey.key,
        etype: result.acceptorSubkey.etype,
        role: 'acceptor',
        acceptorSubkey: true,
        mechListDer: ctx.mechListDer,
        sequenceNumber: 0
      });
    } catch (e) {
      // Not fatal: the context is established and the client has already
      // authenticated. Reported rather than swallowed, because a missing MIC
      // where one was expected is exactly what a client will complain about.
      micNote = 'this service could not compute its own mechListMIC: ' +
        e.message;
      log.warn('krb5-spnego: ' + micNote);
    }
  }
  const responseToken = (!ctx.continuation && !ctx.mutualOff && result.reply)
    ? result.reply : null;
  const token = spnego.encodeNegTokenResp({
    negState: spnego.NEG_STATE.ACCEPT_COMPLETED,
    // Legal only in the acceptor's FIRST reply. On the continuation of a
    // request-mic exchange this is the second, so it is omitted — an acceptor
    // that repeats it is telling the initiator to renegotiate.
    supportedMech: ctx.continuation ? null : ctx.selected,
    responseToken: responseToken,
    mechListMic: mic
  });
  record({ ok: true, client: result.client || null,
           mechanism: ctx.selected, micVerified: ctx.micVerified,
           checks: result.checks || null });
  log.info('krb5-spnego: ACCEPTED ' + (result.client || '?') + ' for ' + SPN +
    ' over ' + spnego.mechName(ctx.selected) +
    (ctx.micVerified ? ', mechListMIC verified' : '') +
    (ctx.rawKerberos ? ' (a bare Kerberos token, no negotiation)' : ''));

  const inner = '<h1>200 &mdash; you are in</h1>' +
    '<div class="ok">Authenticated as <strong>' +
    xmlEscape(result.client || 'unknown') + '</strong> to <code>' +
    xmlEscape(SPN) + '</code>.</div>' +
    '<p>This is the protected content. Getting here took a Kerberos AP-REQ ' +
    'inside an RFC 4121 GSS token inside an RFC 4178 negotiation inside an ' +
    'RFC 4559 HTTP header &mdash; four layers, of which HTTP shows you one.' +
    '</p>' +
    '<table>' +
    '<tr><th>What</th><th>Value</th></tr>' +
    '<tr><td>Client</td><td><code>' +
      xmlEscape(result.client || 'unknown') + '</code></td></tr>' +
    '<tr><td>Mechanism selected</td><td><code>' +
      xmlEscape(ctx.selected) + '</code> (' +
      xmlEscape(spnego.mechName(ctx.selected)) + ')</td></tr>' +
    '<tr><td>Negotiation</td><td>' + (ctx.rawKerberos
      ? 'none &mdash; a bare Kerberos token. Accepted, but understand what ' +
        'it means: with no mechanism list there is nothing for a mechListMIC ' +
        'to protect, so none of SPNEGO&rsquo;s downgrade defence applies.'
      : 'SPNEGO, RFC 4178') + '</td></tr>' +
    '<tr><td>mechListMIC</td><td>' + (ctx.micVerified
      ? '<span class="pass">verified</span>'
      : '<span class="fail">not sent</span> &mdash; ' +
        xmlEscape(ctx.requirement.reason)) + '</td></tr>' +
    '<tr><td>Mutual authentication</td><td>' + (responseToken
      ? 'an AP-REP is in the <code>WWW-Authenticate</code> header; check its ' +
        'echoed <code>ctime</code> and you have proved who answered'
      : ctx.mutualOff
        ? '<span class="fail">none</span> &mdash; <code>?mutual=off</code> is ' +
          'set, so nothing has proved this server is who it claims to be'
        : 'none in this reply') + '</td></tr>' +
    (micNote ? '<tr><td>Note</td><td>' + xmlEscape(micNote) +
      '</td></tr>' : '') +
    '</table>' +
    (result.checks ? '<h2>What this service checked</h2>' +
      checksTable(result.checks) : '');
  res.set('WWW-Authenticate', 'Negotiate ' +
    Buffer.from(token).toString('base64'));
  res.status(200).type('html').send(page('Authenticated', inner));
  log.debug('Leaving succeed().');
}

app.get('/spnego/protected', function (req, res) {
  log.debug('Entering GET /spnego/protected.');
  handleProtected(req, res).catch(function (e) {
    // The no-response branch must answer. This handler is async and every
    // path in it writes a response; an exception that escaped would otherwise
    // leave the client holding an open request, which reads as an unreachable
    // service rather than as a fault here.
    log.error('krb5-spnego: unhandled failure: ' + (e.stack || e.message));
    if (!res.headersSent) {
      res.status(500).type('html').send(page('Failed',
        '<h1>500</h1><div class="err">' + xmlEscape(e.message) + '</div>'));
    }
  });
  log.debug('Leaving GET /spnego/protected.');
});

module.exports = {
  SPN: SPN,
  SUPPORTED_MECHS: SUPPORTED_MECHS,
  lastExchange: function () { return lastExchange; }
};
