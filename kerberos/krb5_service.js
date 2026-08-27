'use strict';
//
// File: krb5_service.js
//
// ---------------------------------------------------------------------------
// A service that will not talk to you without a ticket.
//
// This is what the whole Kerberos workflow is FOR. A KDC issuing tickets proves
// half the protocol; the other half is a service that decrypts one, checks it, and
// proves its own identity back. Until something does that, "the ticket looks right"
// is the strongest claim available.
//
// It is a **raw TCP acceptor**, deliberately, because that is the shape of the
// Windows services people actually debug — CIFS, LDAP, SQL Server. An HTTP service
// wrapping the same token in a `Negotiate` header is SPNEGO, which is the next
// phase; the acceptor logic here is written as its own function so that phase adds a
// transport and no protocol code.
//
// ---------------------------------------------------------------------------
// WHAT A SERVICE ACTUALLY CHECKS, in order, and why each one matters.
//
//   1. **The GSS wrapper.** A service is handed an InitialContextToken, not a bare
//      AP-REQ. Rejecting a bare one is not pedantry: it is what a real service does,
//      and a client that sends one gets a refusal naming nothing.
//   2. **The ticket decrypts with MY key** — key usage 2, the service's own
//      long-term key, at the kvno the ticket names. A stale keytab fails here, and
//      KRB_AP_ERR_BADKEYVER says exactly that.
//   3. **The ticket is for ME.** A ticket for another service that happens to
//      decrypt (because two accounts share a password) must still be refused.
//   4. **The Authenticator decrypts with the ticket's SESSION key** — key usage 11.
//   5. **The Authenticator's cname matches the ticket's.** Otherwise one client's
//      ticket authenticates a request naming another.
//   6. **The clock.** Five minutes, and the error carries this service's own time so
//      the client can measure the difference rather than guess it.
//   7. **The replay cache.** An Authenticator seen before is a replay, and refusing
//      it is the only thing standing between a captured AP-REQ and a free
//      impersonation. This is the check a mock is most tempted to skip.
//   8. **The 0x8003 checksum**, which is not a checksum — it carries the GSS flags,
//      and MUTUAL is what decides whether this service must prove itself back.
//
// Only then does it answer, and if mutual authentication was asked for the AP-REP
// echoes the Authenticator's ctime encrypted under the session key. That echo IS the
// proof: only something holding this service's long-term key could have learned the
// session key to produce it.
// ---------------------------------------------------------------------------

const net = require('net');
const app = require('../common/app');
const { log } = require('../common/helpers');
const config = require('../common/config');
const msgs = require('./krb5_messages.js');
const kcrypto = require('./krb5_crypto.js');
const prim = require('./krb5_primitives.js');
const gss = require('./krb5_gss.js');
const principals = require('./krb5_principals.js');
const stats = require('../common/admin_stats');
// The application registry. A plain require in the ordinary direction and safe
// in the way rule 3g describes: applications.js registers no route and requires
// only helpers.js, config.js and audit.js, so nothing about requiring it here
// closes a cycle or moves an endpoint in the router.
const applications = require('../common/applications');

const SERVICE_PORT = config.value('krb5.servicePort');
const SERVICE_PRINCIPAL = config.value('krb5.servicePrincipal').split('/');
// A function, because krb5.clockSkew is settable at runtime: the tolerance a
// request is judged against has to be the one in force when it arrives.
function clockSkewSeconds() {
  return config.value('krb5.clockSkew');
}
const MAX_TOKEN_BYTES = 64 * 1024;

// The replay cache. Keyed by the Authenticator's client, ctime and cusec — the
// triple RFC 4120 section 3.2.3 names — and bounded, because an unbounded cache in a
// long-running service is a memory leak an attacker controls.
function replayWindowSeconds() {
  return clockSkewSeconds() * 2;
}
const MAX_REPLAY_ENTRIES = 10000;
const replayCache = new Map();

function replayKey(authenticator) {
  return authenticator.crealm + '/' + authenticator.cname.name.join('/') + '/' +
         authenticator.ctime.getTime() + '/' + authenticator.cusec;
}

function pruneReplayCache(nowMs) {
  for (const [key, seenAt] of replayCache) {
    if (nowMs - seenAt > replayWindowSeconds() * 1000) replayCache.delete(key);
  }
  // If it is still oversized, the oldest go first. Refusing to grow without bound
  // matters more than remembering everything: entries older than the skew window
  // cannot be replayed anyway, because the clock check rejects them first.
  while (replayCache.size > MAX_REPLAY_ENTRIES) {
    replayCache.delete(replayCache.keys().next().value);
  }
}

function errorReply(code, eText) {
  const stime = new Date();
  log.info('krb5-service: refusing with ' + msgs.describeError(code).name + ' — ' + eText);
  return msgs.encKrbError({
    stime: stime,
    susec: (stime.getMilliseconds() * 1000) % 1000000,
    errorCode: code,
    realm: principals.REALM,
    sname: { type: 3, name: SERVICE_PRINCIPAL },
    eText: eText
  });
}

// The acceptor. Takes the bytes a client sent and returns the bytes to send back,
// plus a per-check verdict a test (or a human) can read.
//
// `opts.via` names the transport the AP-REQ arrived over, and it exists because this
// function is the ONE place a ticket is accepted: the raw socket below and SPNEGO
// over HTTP both come through here, which was the point of the split. The
// authentication is recorded here for the same reason — recording it in the two
// callers instead would be two call sites and, before long, a third that forgot.
async function accept(tokenBytes, opts) {
  log.debug('Entering accept(). bytes=' + tokenBytes.length);
  const via = (opts && opts.via) || 'AP-REQ over raw TCP';
  const checks = [];
  function check(name, ok, detail) {
    checks.push({ name: name, ok: !!ok, detail: detail });
    return ok;
  }

  if (tokenBytes.length > MAX_TOKEN_BYTES) {
    return { reply: errorReply(60, 'the token is ' + tokenBytes.length + ' bytes, over this ' +
      'service\'s limit'), checks: checks, ok: false };
  }

  // 1. The GSS wrapper.
  let token;
  try {
    token = gss.decodeInitialContextToken(tokenBytes);
    check('GSS InitialContextToken', true, 'mechanism ' + token.mechOid + ', token id ' +
      (token.tokIdName || prim.toHex(new Uint8Array(token.tokId))));
  } catch (e) {
    check('GSS InitialContextToken', false, e.message);
    return { reply: errorReply(60, e.message), checks: checks, ok: false };
  }
  if (token.tokIdName !== 'AP_REQ') {
    check('token is an AP-REQ', false, 'it is ' + (token.tokIdName || 'unrecognised'));
    return { reply: errorReply(40, 'this service accepts an AP-REQ; it was sent ' +
      (token.tokIdName || 'something else')), checks: checks, ok: false };
  }
  check('token is an AP-REQ', true, null);

  let apReq;
  try {
    apReq = msgs.readApReq(token.inner);
  } catch (e) {
    check('AP-REQ decodes', false, e.message);
    return { reply: errorReply(60, 'the AP-REQ does not decode: ' + e.message), checks: checks, ok: false };
  }
  check('AP-REQ decodes', true, 'ap-options: ' +
    (msgs.apOptionNames(apReq.apOptions).join(', ') || '(none)'));

  // 3. The ticket is for me. Checked BEFORE decrypting, because the answer is more
  // specific: a ticket for another service is a client mistake, not a key problem.
  //
  // "Me" is more than one name, and the line between the names that are mine and
  // the names that are not is the whole of this check.
  //
  // A real service account carries several SPNs — the short name, the FQDN, an
  // alias, a load balancer's name — and one keytab holds a key for each, so what
  // makes a ticket acceptable is that this service HOLDS THE KEY the ticket names
  // rather than that the name equals one configured string. This acceptor
  // therefore answers for two kinds of name:
  //
  //   * its CANONICAL SPN, KRB5_SERVICE_PRINCIPAL; and
  //   * any SPN the KDC registered ON DEMAND for a host it is willing to be —
  //     HTTP/localhost, HTTP/sts, HTTP/127.0.0.1, HTTP/anything.example.com. Those
  //     are names no other account has claimed, created because a client derives
  //     `HTTP/<url host>` and cannot know this table.
  //
  // And it answers for nothing else — in particular NOT for another CONFIGURED
  // account's SPN. `HTTP/frontend.example.com` and `HTTP/backend.example.com` exist
  // to be separate identities with separate keys and separate delegation
  // attributes; accepting a ticket for one of them here would make this service
  // every service in the realm, which would quietly destroy the meaning of
  // KRB_AP_ERR_NOT_US, of the delegation tests, and of "a ticket for one service
  // proves nothing to another" — the sentence the whole workflow rests on. Two
  // tests caught exactly that when this check was first widened, which is why the
  // distinction is spelled out here rather than left to the code.
  const wanted = SERVICE_PRINCIPAL.join('/');
  const presented = apReq.ticket.sname.name.join('/');
  const found = principals.findOrCreateService(apReq.ticket.sname.name,
      apReq.ticket.realm);
  const mine = !!found && (presented === wanted || found.autoCreated);
  const me = mine ? found : null;
  if (!me) {
    const why = found
      ? 'that is another account\'s SPN, configured in this realm with its own key'
      : 'this service answers only on ' +
        (principals.SERVICE_DOMAINS.join(', ') || '(nothing configured)');
    check('the ticket is for this service', false, 'it is for ' + presented +
      ', not ' + wanted + ' — ' + why);
    return { reply: errorReply(35, 'this ticket is for ' + presented +
      '; this service is ' + wanted + ' — ' + why), checks: checks, ok: false };
  }
  check('the ticket is for this service', true, presented +
    (presented === wanted ? '' : ' (registered on demand for a host this ' +
      'service answers on; its canonical name is ' + wanted + ')'));

  // 2. The ticket decrypts with my key.
  if (apReq.ticket.encPart.kvno !== null && apReq.ticket.encPart.kvno !== me.kvno) {
    // A stale keytab, and named as such — this is the error whose meaning is least
    // guessable from its name.
    check('key version matches', false, 'the ticket names kvno ' + apReq.ticket.encPart.kvno +
      ' and this service holds kvno ' + me.kvno);
    return { reply: errorReply(44, 'the ticket was encrypted with key version ' +
      apReq.ticket.encPart.kvno + ' and this service holds version ' + me.kvno +
      ' — the keytab is out of date with the account\'s password'), checks: checks, ok: false };
  }
  check('key version matches', true, 'kvno ' + me.kvno);

  const ticketProfile = kcrypto.etypeById(apReq.ticket.encPart.etype);
  let ticketPart;
  try {
    ticketPart = msgs.readEncTicketPart(await ticketProfile.decrypt(
      await principals.longTermKey(me, apReq.ticket.encPart.etype),
      kcrypto.KEY_USAGE.KDC_REP_TICKET, apReq.ticket.encPart.cipher));
    check('ticket decrypts with this service\'s key', true, ticketProfile.name + ', key usage 2');
  } catch (e) {
    check('ticket decrypts with this service\'s key', false, e.message);
    return { reply: errorReply(31, 'the ticket does not decrypt with this service\'s key: ' + e.message),
             checks: checks, ok: false };
  }

  // 4. The Authenticator, under the ticket's session key at key usage 11.
  const sessionKey = ticketPart.key.key;
  const authProfile = kcrypto.etypeById(apReq.authenticator.etype);
  let authenticator;
  try {
    authenticator = msgs.readAuthenticator(await authProfile.decrypt(
      sessionKey, kcrypto.KEY_USAGE.AP_REQ_AUTH, apReq.authenticator.cipher));
    check('Authenticator decrypts with the session key', true, 'key usage 11');
  } catch (e) {
    check('Authenticator decrypts with the session key', false, e.message);
    return { reply: errorReply(31, 'the Authenticator does not decrypt with the ticket\'s session ' +
      'key at key usage 11: ' + e.message), checks: checks, ok: false };
  }

  // 5. Same client in both.
  if (authenticator.cname.name.join('/') !== ticketPart.cname.name.join('/') ||
      authenticator.crealm !== ticketPart.crealm) {
    check('Authenticator and ticket name the same client', false,
      'the Authenticator says ' + authenticator.cname.name.join('/') + ', the ticket says ' +
      ticketPart.cname.name.join('/'));
    return { reply: errorReply(36, 'the Authenticator and the ticket name different clients'),
             checks: checks, ok: false };
  }
  check('Authenticator and ticket name the same client', true,
    ticketPart.cname.name.join('/') + '@' + ticketPart.crealm);

  // 6. The clock, and the ticket's window.
  const nowDate = new Date();
  const skew = Math.abs(nowDate.getTime() - authenticator.ctime.getTime()) / 1000;
  if (skew > clockSkewSeconds()) {
    check('clock skew within tolerance', false, Math.round(skew) + 's against a ' +
      clockSkewSeconds() + 's tolerance');
    return { reply: errorReply(37, 'the Authenticator\'s clock is ' + Math.round(skew) +
      ' seconds from this service\'s (tolerance ' + clockSkewSeconds() + 's)'),
             checks: checks, ok: false };
  }
  check('clock skew within tolerance', true, Math.round(skew) + 's');

  if (ticketPart.endtime <= nowDate) {
    check('ticket is inside its validity window', false, 'it expired at ' +
      ticketPart.endtime.toISOString());
    return { reply: errorReply(32, 'the ticket expired at ' + ticketPart.endtime.toISOString()),
             checks: checks, ok: false };
  }
  check('ticket is inside its validity window', true, 'until ' + ticketPart.endtime.toISOString());

  // 7. The replay cache. The check a mock is most tempted to skip, and the only
  // thing between a captured AP-REQ and a free impersonation.
  pruneReplayCache(nowDate.getTime());
  const key = replayKey(authenticator);
  if (replayCache.has(key)) {
    check('not a replay', false, 'this Authenticator (client, ctime, cusec) has been seen before');
    return { reply: errorReply(34, 'this Authenticator has been seen before — a replay. The ' +
      'triple (client, ctime, cusec) is what identifies one, per RFC 4120 section 3.2.3.'),
             checks: checks, ok: false };
  }
  replayCache.set(key, nowDate.getTime());
  check('not a replay', true, 'the cache holds ' + replayCache.size + ' recent Authenticator(s)');

  // 8. The 0x8003 checksum: the GSS flags, and whether mutual authentication was
  // asked for.
  let gssInfo = null;
  if (authenticator.cksum && authenticator.cksum.type === gss.CHECKSUM_TYPE_GSS) {
    try {
      gssInfo = gss.parseGssChecksum(authenticator.cksum.checksum);
      check('0x8003 checksum parses', true, 'flags: ' + (gssInfo.flagNames.join('|') || '(none)') +
        (gssInfo.hasChannelBindings ? ', with channel bindings' : ', no channel bindings'));
    } catch (e) {
      check('0x8003 checksum parses', false, e.message);
      return { reply: errorReply(50, 'the Authenticator\'s 0x8003 checksum is malformed: ' + e.message),
               checks: checks, ok: false };
    }
  } else if (authenticator.cksum) {
    check('0x8003 checksum parses', false, 'the checksum is type ' + authenticator.cksum.type +
      ', not 0x8003 (32771) — a GSS caller must send the channel-bindings-and-flags structure');
    return { reply: errorReply(50, 'checksum type ' + authenticator.cksum.type + ' is not ' +
      'appropriate here; a GSS AP-REQ carries type 32771 (0x8003)'), checks: checks, ok: false };
  } else {
    check('0x8003 checksum parses', false, 'the Authenticator carries no checksum at all');
  }

  // Mutual authentication, from ap-options AND from the GSS flags. Either asking is
  // enough; a client that sets one and not the other is common.
  const mutualWanted = apReq.apOptions.indexOf(msgs.AP_OPTION.MUTUAL_REQUIRED) !== -1 ||
    !!(gssInfo && (gssInfo.flags & gss.GSS_FLAG.MUTUAL));

  const clientName = ticketPart.cname.name.join('/') + '@' + ticketPart.crealm;
  // Every check above has passed, which is what makes this the moment the client is
  // authenticated: the ticket decrypted under this service's key, the Authenticator
  // decrypted under the ticket's session key, both name the same client, the clock
  // holds and it is not a replay. Nine checks, and the console records what they
  // amount to rather than that a request arrived.
  //
  // ---------------------------------------------------------------------
  // UNLESS THE CALLER IS GOING TO RECORD THE WHOLE ACT ITSELF, which is
  // `opts.record === false` and has exactly one caller: the SPNEGO SIGN-IN
  // door at /authn/spnego.
  //
  // The rule this bends is written three paragraphs down and still holds
  // everywhere else — *one acceptor is one recording site, and a second call
  // over there would count one ticket twice*. What that rule assumed is that
  // accepting a ticket is the whole act. At the sign-in door it is not: the
  // act is a ticket accepted AND a browser session minted for the principal
  // inside it, and `authn.startSession()` is the funnel every other sign-in
  // in this service goes through — the one place an authentication is
  // recorded with its `sessionId` on it, and the only route the identity
  // funnel takes to the directory.
  //
  // So the choice was between two rows on /admin/users for one sign-in — one
  // naming a ticket with no session and one naming a session — or one row
  // that says both. Federation faced the identical question and answered it
  // the same way; `startSession()`'s sixth argument exists because the
  // two-call version was written first and made the console count every
  // federated arrival twice. See authn.js, where that is argued at length.
  //
  // A caller that passes nothing gets what every caller has always got. The
  // raw socket, /spnego/protected and the parent project's real-DC jobs are
  // all still recorded here.
  // ---------------------------------------------------------------------
  if (!opts || opts.record !== false) {
    stats.recordAuthentication({
      presented: clientName, protocol: 'Kerberos v5', method: via,
      note: 'The ticket was for ' + wanted + ' and decrypted under this service\'s own key ' +
            '(' + ticketProfile.name + ').' +
            (mutualWanted ? '' : ' Mutual authentication was not requested, so the client has no ' +
                                 'proof it reached the real service.')
    });
  } else {
    log.debug('krb5-service: the caller records this authentication itself, so ' +
      'the acceptor does not — ' + clientName + ' for ' + wanted + '.');
  }
  // THE SERVICE, which is the application half of this exchange and was missing
  // until now. The KDC records an SPN when it ISSUES a service ticket
  // (krb5_kdc.js's TGS handler), and that covered the ordinary case so
  // completely that the gap was invisible: every ticket presented here had been
  // minted here a moment earlier, so the entry already existed. It stops being
  // true the moment a ticket comes from somewhere else — a real Active
  // Directory KDC, which the parent project's real-DC and relay jobs use — and
  // then a service that decrypted a ticket under its own key appeared in no
  // registry at all while the CLIENT was recorded one line above.
  //
  // Recorded HERE rather than in spnego.js as well, because that module calls
  // this function for every check it makes and adds none of its own: one
  // acceptor is one recording site, and a second call over there would count one
  // ticket twice. `via` says which transport it arrived on.
  //
  // The identifier is the SPN AS PRESENTED with the ticket's realm, which is the
  // same string the KDC files it under, so a ticket from this KDC lands on the
  // entry that already exists rather than beside it. Where the name was
  // registered on demand it is not this service's canonical SPN, and the note
  // says so rather than quietly recording `wanted`.
  applications.seen({
    identifier: presented + '@' + apReq.ticket.realm,
    kind: 'kerberos-service',
    protocol: 'Kerberos v5',
    user: clientName,
    note: 'a service ticket was accepted for this principal (' + via + ')',
    fields: { krb5ServicePrincipalName: presented + '@' + apReq.ticket.realm }
  });
  log.info('krb5-service: ACCEPTED ' + clientName + ' for ' + wanted + ' (' + ticketProfile.name +
    ', flags [' + msgs.ticketFlagNames(ticketPart.flags).join(', ') + ']' +
    (mutualWanted ? ', mutual authentication requested' : '') + ')');

  if (!mutualWanted) {
    // Nothing to send back. Worth noting rather than silently returning nothing:
    // without mutual authentication the CLIENT has no idea whether it just talked to
    // the real service.
    return {
      reply: null,
      checks: checks,
      ok: true,
      client: clientName,
      ticketFlags: msgs.ticketFlagNames(ticketPart.flags),
      gss: gssInfo,
      // The INITIATOR's subkey, and the etype of the session key it falls back
      // to. Neither is used over the raw socket, and both are needed by
      // spnego.js: SPNEGO's mechListMIC is signed by the client with the key
      // established by its own Authenticator, which is this subkey when it
      // sent one and the ticket's session key when it did not. Returned rather
      // than re-derived there, because there is only one right answer and it
      // is known here.
      initiatorSubkey: authenticator.subkey || null,
      sessionKey: sessionKey,
      sessionKeyEtype: ticketPart.key.etype,
      mutual: false,
      note: 'mutual authentication was not requested, so this service sends nothing back and the ' +
            'client has no proof it reached the real service'
    };
  }

  // The AP-REP. Echoing ctime and cusec under the session key IS the proof of
  // identity: only something holding this service's long-term key could have
  // decrypted the ticket to learn that session key.
  const acceptorSubkey = { etype: ticketPart.key.etype,
                           key: kcrypto.randomBytes(ticketProfile.keyBytes) };
  const encApRepPart = msgs.encEncApRepPart({
    ctime: authenticator.ctime,
    cusec: authenticator.cusec,
    subkey: acceptorSubkey,
    seqNumber: ((kcrypto.randomBytes(4)[0] & 0x7f) << 24) | 0x010203
  });
  const apRep = msgs.encApRep({
    encPart: {
      etype: ticketPart.key.etype,
      cipher: await ticketProfile.encrypt(sessionKey, kcrypto.KEY_USAGE.AP_REP_ENCPART, encApRepPart)
    }
  });
  return {
    reply: gss.encodeInitialContextToken(gss.TOK_ID.AP_REP, apRep),
    checks: checks,
    ok: true,
    client: clientName,
    ticketFlags: msgs.ticketFlagNames(ticketPart.flags),
    gss: gssInfo,
    mutual: true,
    acceptorSubkey: acceptorSubkey,
    // See the note on the no-mutual return above: spnego.js verifies the
    // client's mechListMIC with the initiator subkey and signs its own with
    // the acceptor subkey, and the asymmetry is forced by when each MIC is
    // computed rather than chosen.
    initiatorSubkey: authenticator.subkey || null,
    sessionKey: sessionKey,
    sessionKeyEtype: ticketPart.key.etype
  };
}

// ---------------------------------------------------------------------------
// The transport: the same length-prefixed framing the KDC uses, so a client that
// can talk to one can talk to the other.
// ---------------------------------------------------------------------------
function startTcp(port) {
  log.debug('Entering startTcp().');
  const server = net.createServer(function (socket) {
    let buffer = Buffer.alloc(0);
    socket.on('error', function (err) {
      log.debug('krb5-service: socket error: ' + err.message);
    });
    socket.on('data', function (chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > MAX_TOKEN_BYTES) {
        log.warn('krb5-service: a client sent more than ' + MAX_TOKEN_BYTES + ' bytes; closing');
        socket.destroy();
        return;
      }
      if (buffer.length < 4) return;
      const declared = buffer.readUInt32BE(0);
      if (declared & 0x80000000) {
        log.warn('krb5-service: a length prefix with the reserved top bit set; closing');
        socket.destroy();
        return;
      }
      if (buffer.length < 4 + declared) return;
      const message = buffer.subarray(4, 4 + declared);
      buffer = buffer.subarray(4 + declared);
      module.exports.accept(message).then(function (result) {
        // A refusal is an ERROR TOKEN, not a closed socket: a client that gets
        // silence learns nothing, and the whole point of this service is to say why.
        const reply = result.reply;
        if (!reply) {
          // Accepted with no mutual authentication requested. Nothing to send, so
          // close cleanly rather than leaving the client waiting for a reply the
          // protocol does not require.
          socket.end();
          return;
        }
        const framed = Buffer.alloc(4 + reply.length);
        framed.writeUInt32BE(reply.length, 0);
        Buffer.from(reply).copy(framed, 4);
        socket.write(framed);
      }).catch(function (e) {
        log.error('krb5-service: failed to build a reply: ' + (e.stack || e.message));
        socket.destroy();
      });
    });
  });
  server.on('error', function (err) {
    log.error('krb5-service: the listener on port ' + port + ' failed: ' + err.message);
  });
  server.listen(port, '0.0.0.0', function () {
    log.info('krb5-service: ' + SERVICE_PRINCIPAL.join('/') + ' listening on TCP ' +
      server.address().port + ' — present a GSS-wrapped AP-REQ');
  });
  log.debug('Leaving startTcp().');
  return server;
}

// A non-spec HTTP view of the last exchange, so a test and a human can read the
// per-check verdict without a packet capture. It publishes no keys.
//
// The listener above calls module.exports.accept rather than the local accept()
// on purpose: the recording wrapper is defined further down, so a direct call
// would bind the bare acceptor and this view would never fill — the kind of
// silent no-op that makes a diagnostic page lie about what happened.
let lastExchange = null;

app.get('/krb5/service', function (req, res) {
  log.debug('Entering GET /krb5/service.');
  res.status(200).json({
    principal: SERVICE_PRINCIPAL.join('/') + '@' + principals.REALM,
    // Every SPN this service will answer for, not just the canonical one: a real
    // service account carries several and one keytab holds a key for each. See the
    // identity check in accept().
    acceptsAnySpnForHosts: principals.SERVICE_DOMAINS,
    port: SERVICE_PORT,
    clockSkewSeconds: clockSkewSeconds(),
    replayCacheEntries: replayCache.size,
    checksThisServicePerforms: [
      'the GSS InitialContextToken wrapper and its mechanism OID',
      'the ticket decrypts with this service\'s own key at key usage 2',
      'the ticket names a principal this service holds a key for (its own ' +
        'name, or any SPN whose host matches acceptsAnySpnForHosts)',
      'the key version the ticket names matches the one held',
      'the Authenticator decrypts with the ticket session key at key usage 11',
      'the Authenticator and the ticket name the same client',
      'the clock, against a ' + clockSkewSeconds() + '-second tolerance',
      'the replay cache (client, ctime, cusec)',
      'the 0x8003 checksum and the GSS flags in it'
    ],
    lastExchange: lastExchange
  });
  log.debug('Leaving GET /krb5/service.');
});

function listen(port) {
  const p = port === undefined || port === null ? SERVICE_PORT : port;
  return startTcp(p);
}

// Record the last exchange for the HTTP view. Wrapped rather than inlined so the
// acceptor itself stays free of presentation concerns.
const acceptAndRecord = async function (bytes, opts) {
  log.debug('Entering acceptAndRecord().');
  const result = await accept(bytes, opts);
  lastExchange = {
    at: new Date().toISOString(),
    ok: result.ok,
    client: result.client || null,
    mutual: !!result.mutual,
    ticketFlags: result.ticketFlags || null,
    gssFlags: result.gss ? result.gss.flagNames : null,
    checks: result.checks
  };
  log.debug('Leaving acceptAndRecord().');
  return result;
};

module.exports = {
  listen: listen,
  accept: acceptAndRecord,
  acceptRaw: accept,
  SERVICE_PORT: SERVICE_PORT,
  SERVICE_PRINCIPAL: SERVICE_PRINCIPAL,
  replayCache: replayCache
};
