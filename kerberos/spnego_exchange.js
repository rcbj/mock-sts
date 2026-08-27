'use strict';
//
// File: spnego_exchange.js
//
// ---------------------------------------------------------------------------
// THE SPNEGO EXCHANGE, WITH NO PAGE ON IT — a LIBRARY, in the sense rule 3
// gives that word: it registers no route, so its position in the require order
// is not a position at all.
//
// It was `handleProtected()` inside `spnego.js` until 2026-08-26, and it was
// moved for one reason: THERE ARE TWO DOORS NOW. `/spnego/protected` is the
// debugger's protected page, which shows a person both halves of the handshake
// and then stops. `/authn/spnego` is a SIGN-IN, which takes the same handshake
// and turns it into a session this service's sixteen protocol families all
// read. The Kerberos and the RFC 4178 halves of those two are not similar —
// they have to be IDENTICAL, because the second one is an authentication and
// the first one is the documentation of it. A second copy of this negotiation
// would be a page that describes a check the sign-in does not make, or the
// reverse, and neither would show up as a failure anywhere.
//
// So the split is the same one `krb5_service.js` already made one layer down
// and for the same reason, which that module's header states as a promise:
// *"the acceptor logic here is written as its own function so that phase adds a
// transport and no protocol code"*. This is that promise kept a second time.
// The layering is now three deep and each layer adds exactly one thing:
//
//   krb5_service.js   the AP-REQ. Every Kerberos check, over any transport.
//   THIS FILE         the RFC 4178 negotiation and the RFC 4559 header around
//                     it. No Kerberos code, no HTML, no session.
//   spnego.js         a page that explains what happened.
//   spnego_authn.js   a session, and the identity that goes in it.
//
// ---------------------------------------------------------------------------
// WHAT IT RETURNS: A VERDICT, AND NEVER A RESPONSE.
//
// `negotiate()` writes nothing to `res` — it does not take one. It returns an
// object carrying:
//
//   code              which of the fifteen outcomes this is, as a stable
//                     string. The callers switch on it to choose their prose.
//   ok                true only for `accepted`.
//   status            the HTTP status to answer with.
//   wwwAuthenticate   the complete `WWW-Authenticate` header value, or null.
//                     Composed HERE rather than at the two callers, because it
//                     is the part of the answer the PROTOCOL specifies: the
//                     base64 of a NegTokenResp with the right negState in it.
//                     Two spellings of that is two acceptors.
//   reason            one sentence, for the log and for a heading.
//   checks            krb5_service.js's own check list, where the exchange got
//                     far enough to have one.
//
// plus whatever facts that particular outcome has — the mechanisms offered, the
// selected OID, the client principal, the ticket flags. Every branch is
// enumerated in OUTCOMES below so that a caller can be checked against the
// whole list rather than against the branches somebody remembered.
//
// The alternative — returning rendered HTML — was written first and thrown
// away. It made this file own the wording of a debugger page AND of a sign-in
// screen, which are two audiences: one is being taught what a mechListMIC is,
// and the other is being told their sign-in failed and offered a password box.
// ---------------------------------------------------------------------------

const { log } = require('../common/helpers');
const prim = require('./krb5_primitives.js');
const gss = require('./krb5_gss.js');
const spnego = require('./krb5_spnego.js');
const principals = require('./krb5_principals.js');
const krb5Service = require('./krb5_service.js');

// What this acceptor supports, in ITS order of preference. Kerberos first
// because it is the only thing here that works — NTLM is listed by every real
// Windows server and is not implemented, so offering it would be a lie a client
// could act on.
const SUPPORTED_MECHS = [spnego.KRB5_MECH_OID, spnego.MS_KRB5_MECH_OID];

// The canonical SPN both doors are behind. One name, because a client derives
// its SPN from the URL's host and both doors are on the same host — see
// principals.SERVICE_DOMAINS, which is the list of hosts this service holds a
// key for.
const SPN = krb5Service.SERVICE_PRINCIPAL.join('/');

// ---------------------------------------------------------------------------
// THE FIFTEEN OUTCOMES. Named here rather than left implicit in the branches
// below, because the second door was added by reading this list and answering
// each row — and a sixteenth branch added without a row here is one a caller
// will fall through silently.
//
// `terminal` says whether the exchange is over. A false means the client is
// expected to come back with another token, which matters to the sign-in door:
// it must not draw "you could not be signed in" over a reply that is asking
// for the next round trip.
// ---------------------------------------------------------------------------
const OUTCOMES = {
  'no-authorization':        { terminal: false, what: 'no Authorization header; the bare RFC 4559 challenge' },
  'wrong-scheme':            { terminal: true,  what: 'an Authorization header naming some other scheme' },
  'empty-token':             { terminal: true,  what: 'Negotiate with nothing after it' },
  'undecodable':             { terminal: true,  what: 'the token is neither a NegToken nor a bare Kerberos one' },
  'no-common-mechanism':     { terminal: true,  what: 'nothing the client offered is performed here' },
  'no-mech-token':           { terminal: false, what: 'a pessimistic NegTokenInit; the mechanism token was asked for' },
  'non-kerberos-mechanism':  { terminal: true,  what: 'the selected mechanism is not one this service performs' },
  'acceptor-threw':          { terminal: true,  what: 'the Kerberos acceptor raised' },
  'ticket-refused':          { terminal: true,  what: 'the AP-REQ did not pass one of krb5_service.js\'s checks' },
  'bad-mech-list-mic':       { terminal: true,  what: 'the mechListMIC does not verify (RFC 4178 section 5)' },
  'mic-required':            { terminal: true,  what: 'section 5 required a mechListMIC and none was sent' },
  'request-mic':             { terminal: false, what: 'request-mic sent; awaiting the client MIC' },
  'no-pending-continuation': { terminal: true,  what: 'a bare NegTokenResp with no negotiation in progress' },
  'continuation-no-mic':     { terminal: true,  what: 'the continuation carried no mechListMIC' },
  'accepted':               { terminal: true,  what: 'the context is established' }
};

// ---------------------------------------------------------------------------
// WHAT THIS SERVICE VOLUNTEERS THAT NO REAL SERVER DOES, and why it is two
// headers.
//
// RFC 4559's challenge is `WWW-Authenticate: Negotiate` and nothing else. It
// does not say the realm, the KDC or the SPN — so a client guesses
// `HTTP/<url host>`, and when that guess is wrong the whole exchange fails at
// the KDC with an error that names nothing about HTTP. That silence is the
// protocol's, it is the single commonest cause of a SPNEGO failure in the
// field, and this mock cannot fix it for the world. What it CAN do is stop
// being another instance of it.
//
// So the challenge carries two extra headers, on every 401 either door sends:
//
//   X-Krb5-Service-Principal   the SPN this service holds a key for, canonically
//   X-Krb5-Accepts-Spn-Hosts   every host it will answer for, comma-separated
//
// They are inert to every real client (an unknown header is ignored), they cost
// nothing, and they are what lets the debugger say "your derived SPN will work
// here" or "this service says it is X" BEFORE sending somebody to the KDC for a
// ticket that cannot be issued. `X-` because they are nobody's standard: they
// are this mock talking to this debugger, and the page labels them as such
// rather than presenting them as something it learned from the protocol.
//
// It is HERE rather than in either door because both send them and they are the
// same two headers: a sign-in door that volunteered a different SPN from the
// page documenting it would be worse than one that volunteered nothing.
// ---------------------------------------------------------------------------
function volunteerTheSpn(res) {
  log.debug('Entering volunteerTheSpn().');
  res.set('X-Krb5-Service-Principal', SPN + '@' + principals.REALM);
  res.set('X-Krb5-Accepts-Spn-Hosts', principals.SERVICE_DOMAINS.join(','));
  log.debug('Leaving volunteerTheSpn().');
}

// Put a verdict on a response: the status, the two volunteered headers and the
// `WWW-Authenticate` the protocol asked for. The BODY is the caller's, which is
// the whole point of the split — this function is everything about the answer
// that is not prose.
function applyVerdict(res, verdict) {
  log.debug('Entering applyVerdict(). code=' + verdict.code);
  if (verdict.wwwAuthenticate) {
    res.set('WWW-Authenticate', verdict.wwwAuthenticate);
  }
  volunteerTheSpn(res);
  // A sign-in and a protected page are both answers about a credential, and
  // neither may sit in a cache: the next person through the same proxy would be
  // served somebody else's session or somebody else's refusal.
  res.set('Cache-Control', 'no-store');
  res.status(verdict.status);
  log.debug('Leaving applyVerdict().');
}

// ---------------------------------------------------------------------------
// A half-finished negotiation, held between the two requests of a request-mic
// exchange. A real acceptor keeps this on the CONNECTION — that is what RFC
// 4559 section 5 means by the authentication being connection-based, and it is
// why HTTP/2 and connection-pooling proxies break SPNEGO in ways nothing
// reports. Node's Express gives no stable connection identity here, so this
// stands in with the remote address plus the mechanism list, held briefly.
// Being a stand-in is stated rather than hidden: it is the one place this mock
// is structurally unlike a real server.
//
// **THE DOOR IS PART OF THE KEY SINCE 2026-08-26, and that is not tidiness.**
// The stand-in was only ever a diagnostic while one door used it; with a
// SIGN-IN door on the same map, a continuation arriving at `/authn/spnego`
// could otherwise be matched against a half-finished exchange begun at
// `/spnego/protected` by anybody sharing the remote address — a NAT, a proxy,
// a container network — and the accepted client on that entry is what the
// session would be minted for. Keying the door in does not make the stand-in a
// connection; it stops one door from spending the other's state.
// ---------------------------------------------------------------------------
const PENDING_TTL_MS = 120000;
const MAX_PENDING = 64;
const pending = new Map();

function whoIs(req) {
  return (req.ip || req.connection.remoteAddress || 'unknown');
}

function pendingKey(req, door, mechListDer) {
  log.debug('Entering pendingKey().');
  log.debug('Leaving pendingKey().');
  return String(door || '') + '|' + whoIs(req) + '|' + prim.toHex(mechListDer);
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
// THE LAST EXCHANGE, for `GET /spnego`'s diagnostic view.
//
// It lives here rather than in `spnego.js` now that there are two doors, and
// it carries the DOOR — so a person reading that page can tell an exchange
// that was a sign-in from one that was the protected page. One record for both
// is deliberate: the question the page answers is "what did the last SPNEGO
// client to reach this service do", and two records would answer it twice with
// no way to tell which was later.
// ---------------------------------------------------------------------------
let lastExchange = null;

function record(door, outcome) {
  log.debug('Entering record().');
  lastExchange = Object.assign({ at: new Date().toISOString(), door: door },
                               outcome);
  log.debug('Leaving record().');
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

// The key each side signs the mechanism list with. See spnego.js's header: the
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

function negotiateHeader(token) {
  return 'Negotiate ' + Buffer.from(token).toString('base64');
}

// A verdict that carries a token back — a continuation, a rejection or an
// acceptance. `status` defaults to 401 because all but one of them are.
function tokenVerdict(door, code, token, facts) {
  log.debug('Entering tokenVerdict(). code=' + code);
  const verdict = Object.assign({
    code: code,
    ok: code === 'accepted',
    status: 401,
    wwwAuthenticate: token ? negotiateHeader(token) : null
  }, facts || {});
  record(door, { ok: verdict.ok, code: code, reason: verdict.reason || null,
                 client: verdict.client || null,
                 checks: verdict.checks || null });
  log.debug('Leaving tokenVerdict().');
  return verdict;
}

// The bare challenge. No token: RFC 4559 section 4 — the server says only that
// it will negotiate, and everything else is the client's problem.
function bareVerdict(door, code, facts) {
  log.debug('Entering bareVerdict(). code=' + code);
  const verdict = Object.assign({
    code: code,
    ok: false,
    status: 401,
    wwwAuthenticate: 'Negotiate'
  }, facts || {});
  record(door, { ok: false, code: code, reason: verdict.reason || null,
                 checks: verdict.checks || null });
  log.debug('Leaving bareVerdict().');
  return verdict;
}

// The REJECT token. SPNEGO's `reject` carries no reason of its own — the
// structure has no field for one — so everything a caller prints about WHY is
// out of band and a real server tells a client none of it.
function rejection(door, code, facts) {
  return tokenVerdict(door, code,
    spnego.encodeNegTokenResp({ negState: spnego.NEG_STATE.REJECT }), facts);
}

// ---------------------------------------------------------------------------
// negotiate(req, opts) — the whole exchange, from the Authorization header to
// a verdict.
//
//   door      which endpoint this is, for the pending map's key and for the
//             diagnostic record. A string, and the two callers pass their own
//             path.
//   supported the mechanism OIDs this acceptor will use. Defaults to
//             SUPPORTED_MECHS; `/spnego/protected` passes an empty list when
//             `?mech=none` is set, which is a knob and is why this is a
//             parameter rather than a constant read here.
//   wantMic   force the request-mic round trip even where section 5 would let
//             it be skipped. Also a knob.
//   mutualOff withhold the AP-REP from an otherwise successful exchange.
//   via       what to call this transport when krb5_service.js records the
//             authentication. See `record` below.
//   record    FALSE stops krb5_service.js recording the authentication itself,
//             because the CALLER is going to record the whole act — see
//             spnego_authn.js, where a sign-in must be ONE row on /admin/users
//             and not a ticket acceptance beside a session start.
// ---------------------------------------------------------------------------
async function negotiate(req, opts) {
  log.debug('Entering negotiate().');
  const options = opts || {};
  const door = String(options.door || 'spnego');
  const supported = options.supported || SUPPORTED_MECHS;
  const wantMic = !!options.wantMic;
  const mutualOff = !!options.mutualOff;
  const header = req.get('authorization') || '';

  if (!header) {
    log.info('krb5-spnego: no Authorization header at ' + door +
      ' — answering 401 with a bare Negotiate challenge');
    log.debug('Leaving negotiate(). Challenged.');
    return bareVerdict(door, 'no-authorization',
      { reason: 'no Authorization header; challenged' });
  }

  const match = /^Negotiate\s+([A-Za-z0-9+/=]*)\s*$/i.exec(header.trim());
  if (!match) {
    // A scheme this resource does not speak. Named, because "401" on its own
    // sends people to look at their ticket when they sent Basic.
    const scheme = header.split(/\s/)[0] || '(none)';
    log.info('krb5-spnego: refusing Authorization scheme ' + scheme + ' at ' + door);
    log.debug('Leaving negotiate(). Wrong scheme.');
    return bareVerdict(door, 'wrong-scheme',
      { reason: 'Authorization scheme ' + scheme, scheme: scheme });
  }
  if (!match[1]) {
    log.debug('Leaving negotiate(). Empty token.');
    return bareVerdict(door, 'empty-token',
      { reason: 'an empty Negotiate token' });
  }

  const tokenBytes = new Uint8Array(Buffer.from(match[1], 'base64'));
  let parsed;
  try {
    parsed = spnego.decodeNegotiationToken(tokenBytes);
  } catch (e) {
    log.debug('Leaving negotiate(). Undecodable.');
    return rejection(door, 'undecodable',
      { reason: 'the Negotiate token does not decode: ' + e.message,
        error: e.message });
  }

  // A continuation: the client answering our request-mic with the MIC alone.
  if (parsed.kind === 'NegTokenResp') {
    const verdict = await continuation(req, door, parsed);
    log.debug('Leaving negotiate(). Continuation.');
    return verdict;
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
      log.debug('Leaving negotiate(). No common mechanism.');
      return rejection(door, 'no-common-mechanism',
        { reason: 'no mechanism in common',
          offered: parsed.mechTypes,
          offeredNames: parsed.mechTypeNames,
          supported: supported });
    }
    if (!parsed.mechToken) {
      // A pessimistic NegTokenInit: the client named its mechanisms and sent
      // no token. Legal, and it costs the round trip the optimistic token
      // exists to avoid.
      log.debug('Leaving negotiate(). Asked for a mechToken.');
      return tokenVerdict(door, 'no-mech-token',
        spnego.encodeNegTokenResp({
          negState: spnego.NEG_STATE.ACCEPT_INCOMPLETE,
          supportedMech: selected
        }),
        { reason: 'no optimistic mechToken; asked for one', selected: selected });
    }
    mechToken = parsed.mechToken;
    if (!spnego.isKerberosMech(selected)) {
      log.debug('Leaving negotiate(). Non-Kerberos mechanism.');
      return rejection(door, 'non-kerberos-mechanism',
        { reason: 'the selected mechanism is not one this service performs',
          selected: selected });
    }
  }

  // The Kerberos half, unchanged: krb5_service.js's acceptor does every check
  // it does over a raw socket. This module adds no protocol code to it, which
  // was the design promise the split was made for.
  let result;
  try {
    // `via` only names the transport for the console: every Kerberos check is
    // that module's, and this one adds none. Without it a SPNEGO sign-in would
    // be filed as a raw-socket one, which is the difference between "a browser
    // did this" and "something on port 8888 did".
    result = await krb5Service.accept(mechToken, {
      via: options.via || 'SPNEGO over HTTP (RFC 4559)',
      record: options.record !== false
    });
  } catch (e) {
    log.error('krb5-spnego: the acceptor threw: ' + (e.stack || e.message));
    log.debug('Leaving negotiate(). Acceptor threw.');
    return rejection(door, 'acceptor-threw',
      { reason: 'the Kerberos acceptor failed: ' + e.message,
        error: e.message });
  }

  if (!result.ok) {
    // The mechanism's own error token goes back INSIDE the responseToken. This
    // is the only way a SPNEGO rejection can say why: negState has no reason
    // field, so the KRB-ERROR is the entire diagnosis.
    log.debug('Leaving negotiate(). Ticket refused.');
    return tokenVerdict(door, 'ticket-refused',
      spnego.encodeNegTokenResp({
        negState: spnego.NEG_STATE.REJECT,
        supportedMech: selected,
        responseToken: result.reply
          ? gss.encodeInitialContextToken(gss.TOK_ID.KRB_ERROR, result.reply)
          : null
      }),
      { reason: 'the Kerberos AP-REQ was refused', checks: result.checks,
        selected: selected });
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
      log.debug('Leaving negotiate(). Bad mechListMIC.');
      return rejection(door, 'bad-mech-list-mic',
        { reason: 'the mechListMIC does not verify' +
                  (verdict.error ? ': ' + verdict.error : ''),
          error: verdict.error || '', checks: result.checks });
    }
    log.info('krb5-spnego: the mechListMIC verifies (' + verdict.senderRole +
      ', sequence ' + verdict.sequenceNumber + ')');
  } else if (requirement.required && !rawKerberos) {
    log.debug('Leaving negotiate(). Missing required mechListMIC.');
    return rejection(door, 'mic-required',
      { reason: 'a mechListMIC was required and none was sent',
        requirement: requirement, checks: result.checks });
  } else if (wantMic && !rawKerberos) {
    // The knob: force the exchange even though section 5 would let it be
    // skipped. Real acceptors do this — Windows sets request-mic whenever it
    // wants the list protected regardless of preference order.
    prunePending(Date.now());
    pending.set(pendingKey(req, door, mechListDer), {
      at: Date.now(),
      mechListDer: mechListDer,
      selected: selected,
      initiatorKey: initiatorKey,
      acceptorSubkey: result.acceptorSubkey || null,
      client: result.client,
      ticketFlags: result.ticketFlags || null
    });
    log.debug('Leaving negotiate(). request-mic.');
    return tokenVerdict(door, 'request-mic',
      spnego.encodeNegTokenResp({
        negState: spnego.NEG_STATE.REQUEST_MIC,
        supportedMech: selected,
        responseToken: result.reply || null
      }),
      { reason: 'request-mic sent; awaiting the client MIC',
        client: result.client, selected: selected });
  }

  const accepted = await accept(door, {
    result: result,
    selected: selected,
    mechListDer: mechListDer,
    requirement: requirement,
    rawKerberos: rawKerberos,
    micVerified: !!(parsed && parsed.mechListMic),
    mutualOff: mutualOff
  });
  log.debug('Leaving negotiate(). Accepted.');
  return accepted;
}

// The client's answer to request-mic: a bare NegTokenResp carrying the MIC and
// nothing else. The context it belongs to is the pending one.
async function continuation(req, door, parsed) {
  log.debug('Entering continuation().');
  prunePending(Date.now());
  let entry = null;
  let entryKey = null;
  const prefix = String(door) + '|' + whoIs(req) + '|';
  for (const [key, value] of pending) {
    if (key.indexOf(prefix) === 0) {
      entry = value;
      entryKey = key;
    }
  }
  if (!entry) {
    log.debug('Leaving continuation(). Nothing pending.');
    return rejection(door, 'no-pending-continuation',
      { reason: 'there is no negotiation in progress to continue' });
  }
  pending.delete(entryKey);
  if (!parsed.mechListMic) {
    log.debug('Leaving continuation(). No MIC.');
    return rejection(door, 'continuation-no-mic',
      { reason: 'the continuation carried no mechListMIC' });
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
    log.debug('Leaving continuation(). Bad MIC.');
    // `continuation` is on the verdict because the two ways this code is
    // reached want different prose and a caller cannot tell them apart
    // otherwise: on the FIRST token a bad MIC means a perfectly good ticket
    // with a MIC computed over the wrong bytes, and on the SECOND it means a
    // client that was asked for one thing and sent it wrong.
    return rejection(door, 'bad-mech-list-mic',
      { reason: 'the mechListMIC does not verify' +
                (verdict.error ? ': ' + verdict.error : ''),
        error: verdict.error || '', continuation: true });
  }
  const accepted = await accept(door, {
    result: {
      ok: true,
      client: entry.client,
      ticketFlags: entry.ticketFlags,
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
  log.debug('Leaving continuation(). Accepted.');
  return accepted;
}

// 200, and the token that proves who answered.
async function accept(door, ctx) {
  log.debug('Entering accept().');
  const result = ctx.result;
  let mic = null;
  let micNote = null;
  if (ctx.mechListDer && result.acceptorSubkey) {
    // The ACCEPTOR's MIC, and it is keyed differently from the client's — see
    // spnego.js's header. The acceptor subkey is the context key once it has
    // been offered, and the key usage is the acceptor's, 23.
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
  log.info('krb5-spnego: ACCEPTED ' + (result.client || '?') + ' for ' + SPN +
    ' at ' + door + ' over ' + spnego.mechName(ctx.selected) +
    (ctx.micVerified ? ', mechListMIC verified' : '') +
    (ctx.rawKerberos ? ' (a bare Kerberos token, no negotiation)' : ''));
  const verdict = tokenVerdict(door, 'accepted', token, {
    status: 200,
    reason: 'the context is established',
    client: result.client || null,
    ticketFlags: result.ticketFlags || [],
    selected: ctx.selected,
    micVerified: ctx.micVerified,
    rawKerberos: ctx.rawKerberos,
    requirement: ctx.requirement,
    mutualOff: ctx.mutualOff,
    continuation: !!ctx.continuation,
    // Whether an AP-REP went back, which is what mutual authentication IS. The
    // callers say so on their pages; it is computed here because the three
    // things that can suppress it are all decided here.
    mutual: !!responseToken,
    micNote: micNote,
    checks: result.checks || null
  });
  log.debug('Leaving accept().');
  return verdict;
}

module.exports = {
  SPN: SPN,
  SUPPORTED_MECHS: SUPPORTED_MECHS,
  OUTCOMES: OUTCOMES,
  negotiate: negotiate,
  applyVerdict: applyVerdict,
  volunteerTheSpn: volunteerTheSpn,
  lastExchange: function () { return lastExchange; }
};
