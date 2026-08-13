'use strict';
//
// File: krb5_kdc.js
//
// ---------------------------------------------------------------------------
// The mock Key Distribution Center: the AS exchange.
//
// This is the first thing in this service that is NOT an HTTP endpoint. Kerberos
// speaks DER over TCP and UDP port 88, so the listeners here are raw sockets, and
// three consequences follow that are worth stating because none of them is
// obvious from the code:
//
//  * **Requiring this module does not start the listeners.** Every other module
//    here registers its routes at require time (see server.js's note on why), and
//    for a route that is harmless. Binding a privileged port is not: it can fail,
//    and a require that throws takes the whole service down. So the KKDCP route
//    IS registered at require time, for consistency, and the sockets are started
//    by an exported `listen()` that server.js calls and whose failure it reports.
//  * **`GET /sts-metadata` cannot see a raw socket.** That page's whole design is
//    that it reads the live Express router and so cannot go stale — and a protocol
//    family it cannot see is the one way it can. The port-88 listener therefore
//    needs an explicit entry there; the drift test in tests/sts_metadata.js has to
//    tolerate an entry with no route behind it.
//  * **Port 88 is privileged.** In the container this process is root and binds it
//    directly. A host run is not root, so `KRB5_KDC_PORT` exists — and if it is
//    changed, the api's `krb5AllowedPorts` has to allow the new one or the relay
//    will refuse to reach it. That coupling is the price of the port allowlist and
//    is worth paying.
//
// ---------------------------------------------------------------------------
// The exchange, and why the two-message dance is the interesting part.
//
// A client's first AS-REQ usually carries no pre-authentication. A real KDC does
// not treat that as an error to be logged and forgotten: it answers
// KDC_ERR_PREAUTH_REQUIRED **carrying PA-ETYPE-INFO2**, which is where the client
// learns the SALT and the iteration count it needs to turn a password into a key.
// The salt is not guessable — see krb5_principals.js — so a client that treats
// this error as a failure cannot authenticate to Active Directory at all.
//
// This KDC therefore implements both halves, and has a principal (`noreauth`)
// configured the other way so the one-message case can be seen too.
//
// It checks what a KDC checks, and refuses in the KDC's own vocabulary: an unknown
// principal, a locked account, an expired password, no common encryption type, a
// bad password, and a clock outside the tolerance. Those refusals are the product
// here. It does NOT check request signatures, does not implement FAST, and issues
// no PAC yet — phase 4 adds the PAC, and this file says so rather than leaving a
// reader to wonder why a Windows service rejects its tickets.
// ---------------------------------------------------------------------------

const net = require('net');
const dgram = require('dgram');
const app = require('./app');
const { log } = require('./helpers');
const asn1 = require('./krb5_asn1.js');
const msgs = require('./krb5_messages.js');
const kcrypto = require('./krb5_crypto.js');
const prim = require('./krb5_primitives.js');
const principals = require('./krb5_principals.js');

const KDC_PORT = parseInt(process.env.KRB5_KDC_PORT || '88', 10);
const REALM = principals.REALM;

// Active Directory's default tolerance, and the reason KRB_AP_ERR_SKEW is one of
// the most common Kerberos failures in the field.
const CLOCK_SKEW_SECONDS = parseInt(process.env.KRB5_CLOCK_SKEW || '300', 10);
const TICKET_LIFETIME_SECONDS = 10 * 3600;
const RENEW_LIFETIME_SECONDS = 7 * 24 * 3600;

// A test can ask this KDC to lie about its clock, so the client's skew handling
// can be exercised without changing anybody's system time.
const CLOCK_OFFSET_SECONDS = parseInt(process.env.KRB5_CLOCK_OFFSET || '0', 10);

// Replies larger than this are a bug in this service rather than a legitimate
// message; the cap exists so a mistake surfaces here rather than as a truncated
// datagram at the far end.
const MAX_REPLY_BYTES = 128 * 1024;

function now() {
  return new Date(Date.now() + CLOCK_OFFSET_SECONDS * 1000);
}

function kdcTime(offsetSeconds) {
  return new Date(now().getTime() + (offsetSeconds || 0) * 1000);
}

// Every refusal goes through here, so every one of them carries the KDC's own
// clock (which is how a client measures skew) and names the principals involved.
function errorReply(code, options) {
  const opts = options || {};
  const stime = now();
  log.info('krb5: refusing with ' + msgs.describeError(code).name + ' (' + code + ')' +
    (opts.eText ? ' — ' + opts.eText : ''));
  return msgs.encKrbError({
    ctime: opts.ctime || null,
    cusec: opts.ctime ? 0 : null,
    stime: stime,
    susec: (stime.getMilliseconds() * 1000) % 1000000,
    errorCode: code,
    crealm: opts.crealm || null,
    cname: opts.cname || null,
    realm: opts.realm || REALM,
    sname: opts.sname || { type: 2, name: ['krbtgt', REALM] },
    eText: opts.eText || null,
    eData: opts.eData || null
  });
}

// KDC_ERR_PREAUTH_REQUIRED, with the ETYPE-INFO2 that makes it useful rather than
// merely negative.
function preAuthRequiredReply(client, request) {
  const entries = principals.etypeInfo2For(client);
  log.info('krb5: ' + client.name.join('/') + ' needs pre-authentication; sending ETYPE-INFO2 with ' +
    entries.length + ' entr' + (entries.length === 1 ? 'y' : 'ies') + ', salt ' +
    JSON.stringify(client.salt));
  return errorReply(25, {
    crealm: request.reqBody.realm,
    cname: request.reqBody.cname,
    sname: request.reqBody.sname,
    eText: 'NEEDED_PREAUTH',
    // Both PA-ETYPE-INFO2 and PA-PW-SALT, which is what AD sends. The older
    // PA-PW-SALT is there for clients that predate ETYPE-INFO2; a client should
    // prefer the newer one, and being able to see both is the point.
    eData: asn1.encSequenceOf([
      msgs.encPaData({ type: msgs.PA_TYPE.ETYPE_INFO2, value: msgs.encEtypeInfo2(entries) }),
      msgs.encPaData({ type: msgs.PA_TYPE.PW_SALT, value: prim.utf8(client.salt) })
    ])
  });
}

// Verify PA-ENC-TIMESTAMP. Returns null on success or an error code to answer with.
//
// Key usage 1, and only key usage 1: a KDC that used any other number would see an
// integrity failure and report it as a wrong password, which is the single most
// misleading thing a Kerberos implementation can do.
async function checkEncTimestamp(client, etype, padata) {
  const profile = kcrypto.etypeById(etype);
  const key = await principals.longTermKey(client, etype);
  let encrypted;
  try {
    encrypted = msgs.readEncryptedData(asn1.readTlv(padata.value, 0));
  } catch (e) {
    log.warn('krb5: PA-ENC-TIMESTAMP does not decode as EncryptedData: ' + e.message);
    return { code: 24, eText: 'PA-ENC-TIMESTAMP is not well formed' };
  }
  if (encrypted.etype !== etype) {
    // The client encrypted with a key of a different type from the one it asked
    // the KDC to use. Worth its own message: it means the client's own
    // negotiation is inconsistent.
    log.warn('krb5: PA-ENC-TIMESTAMP is ' + encrypted.etypeName + ' but the request negotiated ' +
             profile.name);
    return { code: 24, eText: 'PA-ENC-TIMESTAMP was encrypted with a different etype' };
  }
  let plaintext;
  try {
    plaintext = await profile.decrypt(key, kcrypto.KEY_USAGE.AS_REQ_PA_ENC_TIMESTAMP, encrypted.cipher);
  } catch (e) {
    // This is what a wrong password looks like — and also what a wrong SALT looks
    // like, and a wrong key usage number. The KDC cannot tell them apart, which is
    // exactly why the debugger showing the salt matters.
    log.info('krb5: pre-authentication failed for ' + client.name.join('/') + ': ' + e.message);
    return { code: 24, eText: 'PREAUTH_FAILED' };
  }
  let stamp;
  try {
    stamp = msgs.readPaEncTsEnc(plaintext);
  } catch (e) {
    return { code: 24, eText: 'the decrypted PA-ENC-TS-ENC is not well formed' };
  }
  const skew = Math.abs(now().getTime() - stamp.patimestamp.getTime()) / 1000;
  if (skew > CLOCK_SKEW_SECONDS) {
    log.info('krb5: clock skew ' + Math.round(skew) + 's exceeds the ' + CLOCK_SKEW_SECONDS +
             's tolerance for ' + client.name.join('/'));
    return { code: 37, eText: 'clock skew is ' + Math.round(skew) + ' seconds' };
  }
  log.info('krb5: pre-authentication succeeded for ' + client.name.join('/') +
           ' (' + profile.name + ', skew ' + Math.round(skew) + 's)');
  return null;
}

async function handleAsReq(request) {
  log.debug('Entering handleAsReq().');
  const body = request.reqBody;

  if (body.realm !== REALM) {
    log.info('krb5: wrong realm ' + JSON.stringify(body.realm) + '; this KDC serves ' + REALM);
    return errorReply(68, {
      realm: REALM, sname: body.sname,
      eText: 'this KDC serves ' + REALM + ', not ' + body.realm
    });
  }
  if (!body.cname) {
    return errorReply(6, { realm: REALM, sname: body.sname, eText: 'no client name in the request' });
  }

  const client = principals.find(body.cname.name);
  if (!client) {
    return errorReply(6, {
      crealm: body.realm, cname: body.cname, sname: body.sname,
      eText: 'no such principal: ' + body.cname.name.join('/')
    });
  }
  const service = principals.find((body.sname || {}).name || []);
  if (!service) {
    return errorReply(7, {
      crealm: body.realm, cname: body.cname, sname: body.sname,
      eText: 'no such service principal: ' + ((body.sname || {}).name || []).join('/')
    });
  }
  if (client.revoked) {
    return errorReply(18, { crealm: body.realm, cname: body.cname, sname: body.sname,
      eText: 'the account is disabled or locked out' });
  }
  if (client.passwordExpired) {
    return errorReply(23, { crealm: body.realm, cname: body.cname, sname: body.sname,
      eText: 'the password has expired and must be changed' });
  }

  // Negotiate. The client's order is its preference; a KDC honours it.
  const etype = principals.chooseEtype(client, body.etypes);
  if (etype === null) {
    log.info('krb5: no common etype for ' + client.name.join('/') + '. It offers [' +
      principals.supportedEtypes(client).map(kcrypto.etypeName).join(', ') + '], the client asked for [' +
      (body.etypes || []).map(kcrypto.etypeName).join(', ') + ']');
    return errorReply(14, {
      crealm: body.realm, cname: body.cname, sname: body.sname,
      eText: 'no common encryption type: this principal supports ' +
             principals.supportedEtypes(client).map(kcrypto.etypeName).join(', ')
    });
  }
  const profile = kcrypto.etypeById(etype);

  // Pre-authentication.
  const encTimestamp = (request.padata || []).filter(function (pa) {
    return pa.type === msgs.PA_TYPE.ENC_TIMESTAMP;
  })[0];
  if (client.requiresPreAuth && !encTimestamp) {
    return preAuthRequiredReply(client, request);
  }
  if (encTimestamp) {
    const failure = await checkEncTimestamp(client, etype, encTimestamp);
    if (failure) {
      return errorReply(failure.code, {
        crealm: body.realm, cname: body.cname, sname: body.sname, eText: failure.eText,
        // A KDC re-sends ETYPE-INFO2 with PREAUTH_FAILED as well, because the
        // client may have used the wrong salt and this is how it finds out.
        eData: failure.code === 24
          ? asn1.encSequenceOf([msgs.encPaData({
              type: msgs.PA_TYPE.ETYPE_INFO2,
              value: msgs.encEtypeInfo2(principals.etypeInfo2For(client)) })])
          : null
      });
    }
  }

  // Issue. The session key is fresh per ticket; both copies of it — the one in the
  // ticket for the service and the one in the enc-part for the client — must be the
  // same bytes, which is the whole mechanism.
  const sessionKey = kcrypto.randomBytes(profile.keyBytes);
  const authtime = now();
  const requestedTill = body.till && body.till > authtime ? body.till : kdcTime(TICKET_LIFETIME_SECONDS);
  const endtime = new Date(Math.min(requestedTill.getTime(),
    kdcTime(TICKET_LIFETIME_SECONDS).getTime()));

  const wantsForwardable = (body.kdcOptions || []).indexOf(msgs.KDC_OPTION.FORWARDABLE) !== -1;
  const wantsRenewable = (body.kdcOptions || []).indexOf(msgs.KDC_OPTION.RENEWABLE) !== -1;
  const flags = [msgs.TICKET_FLAG.INITIAL];
  if (wantsForwardable) flags.push(msgs.TICKET_FLAG.FORWARDABLE);
  if (wantsRenewable) flags.push(msgs.TICKET_FLAG.RENEWABLE);
  // pre-authent is set only if pre-authentication actually happened. A service can
  // read this flag and insist on it, so setting it unconditionally would be a lie
  // with security consequences.
  if (encTimestamp) flags.push(msgs.TICKET_FLAG.PRE_AUTHENT);
  if (service.okAsDelegate) flags.push(msgs.TICKET_FLAG.OK_AS_DELEGATE);
  const renewTill = wantsRenewable ? kdcTime(RENEW_LIFETIME_SECONDS) : null;

  const serviceKey = await principals.longTermKey(service, etype);
  const encTicketPart = msgs.encEncTicketPart({
    flags: flags,
    key: { etype: etype, key: sessionKey },
    crealm: REALM,
    cname: body.cname,
    authtime: authtime,
    starttime: authtime,
    endtime: endtime,
    renewTill: renewTill
  });
  const ticket = {
    realm: REALM,
    sname: body.sname,
    encPart: {
      etype: etype,
      kvno: service.kvno,
      cipher: await profile.encrypt(serviceKey, kcrypto.KEY_USAGE.KDC_REP_TICKET, encTicketPart)
    }
  };

  const clientKey = await principals.longTermKey(client, etype);
  const encRepPart = msgs.encEncKdcRepPart({
    key: { etype: etype, key: sessionKey },
    lastReq: [{ type: 0, value: authtime }],
    // The nonce must come back UNCHANGED. It is the client's only defence against
    // a replayed reply, and a KDC that regenerates it breaks every correct client.
    nonce: body.nonce,
    flags: flags,
    authtime: authtime,
    starttime: authtime,
    endtime: endtime,
    renewTill: renewTill,
    srealm: REALM,
    sname: body.sname
  }, msgs.APPLICATION.ENC_AS_REP_PART);

  log.info('krb5: issued a TGT for ' + body.cname.name.join('/') + '@' + REALM + ' to ' +
    body.sname.name.join('/') + ' using ' + profile.name + ', flags [' +
    msgs.ticketFlagNames(flags).join(', ') + '], expiring ' + endtime.toISOString());

  return msgs.encKdcRep({
    msgType: msgs.MSG_TYPE.AS_REP,
    crealm: REALM,
    cname: body.cname,
    ticket: ticket,
    encPart: {
      etype: etype,
      cipher: await profile.encrypt(clientKey, kcrypto.KEY_USAGE.AS_REP_ENCPART, encRepPart)
    }
  });
}

// The dispatcher. Anything that is not a request this KDC serves gets an error
// rather than silence: a client waiting for a reply that never comes learns
// nothing, and "I do not do that yet" is information.
async function handleMessage(bytes) {
  log.debug('Entering handleMessage(). bytes=' + bytes.length);
  let identified = null;
  try {
    identified = msgs.identify(bytes);
    if (!identified) throw new Error('no [APPLICATION n] tag');
    if (identified.applicationNumber === msgs.APPLICATION.AS_REQ) {
      const request = msgs.readKdcReq(bytes);
      return await handleAsReq(request);
    }
    if (identified.applicationNumber === msgs.APPLICATION.TGS_REQ) {
      // Phase 3. Answered honestly rather than dropped.
      log.info('krb5: a TGS-REQ arrived; this mock does not serve the TGS exchange yet');
      return errorReply(60, { eText: 'this mock KDC does not implement the TGS exchange yet' });
    }
    log.info('krb5: received ' + identified.name + ', which is not a request a KDC answers');
    return errorReply(40, { eText: identified.name + ' is not a request this KDC answers' });
  } catch (e) {
    log.warn('krb5: could not handle the message: ' + (e.stack || e.message));
    // KRB_ERR_GENERIC with the reason in e-text, which is where a KDC says what it
    // actually objected to.
    return errorReply(60, { eText: 'could not decode the request: ' + e.message });
  }
}

// ---------------------------------------------------------------------------
// The listeners.
// ---------------------------------------------------------------------------
function startTcp(port) {
  const server = net.createServer(function (socket) {
    let buffer = Buffer.alloc(0);
    socket.on('error', function (err) {
      // A client that disappears mid-exchange is ordinary, not exceptional. An
      // unhandled 'error' on a socket takes the whole process down.
      log.debug('krb5: TCP socket error: ' + err.message);
    });
    socket.on('data', function (chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > MAX_REPLY_BYTES) {
        log.warn('krb5: a TCP client sent more than ' + MAX_REPLY_BYTES + ' bytes; closing');
        socket.destroy();
        return;
      }
      if (buffer.length < 4) return;
      const declared = buffer.readUInt32BE(0);
      if (declared & 0x80000000) {
        log.warn('krb5: a TCP client sent a length prefix with the reserved top bit set; closing');
        socket.destroy();
        return;
      }
      if (buffer.length < 4 + declared) return;
      const message = buffer.subarray(4, 4 + declared);
      buffer = buffer.subarray(4 + declared);
      handleMessage(message).then(function (reply) {
        const framed = Buffer.alloc(4 + reply.length);
        framed.writeUInt32BE(reply.length, 0);
        Buffer.from(reply).copy(framed, 4);
        socket.write(framed);
      }).catch(function (e) {
        // handleMessage catches its own errors; this is the last resort, and it
        // must still answer rather than leave the client waiting.
        log.error('krb5: failed to build a reply: ' + (e.stack || e.message));
        socket.destroy();
      });
    });
  });
  server.on('error', function (err) {
    log.error('krb5: the TCP listener on port ' + port + ' failed: ' + err.message +
      (err.code === 'EACCES'
        ? ' — port 88 is privileged. Set KRB5_KDC_PORT to something above 1024 for a host run, ' +
          'and add that port to the api\'s krb5AllowedPorts or the relay will refuse to reach it.'
        : ''));
  });
  server.listen(port, '0.0.0.0', function () {
    // The BOUND port, not the requested one: asked for 0 the OS picks, and logging
    // the request would print "listening on TCP 0".
    log.info('krb5: KDC listening on TCP ' + server.address().port + ' for realm ' + REALM);
  });
  return server;
}

function startUdp(port) {
  const socket = dgram.createSocket('udp4');
  socket.on('error', function (err) {
    log.error('krb5: the UDP listener on port ' + port + ' failed: ' + err.message);
  });
  socket.on('message', function (message, rinfo) {
    handleMessage(message).then(function (reply) {
      // A real KDC answers KRB_ERR_RESPONSE_TOO_BIG when its reply will not fit in
      // a datagram, and a client then retries over TCP. Reproducing that is worth
      // more than sending an oversized datagram, because the retry is the
      // behaviour a client has to get right.
      if (reply.length > 1465) {
        log.info('krb5: the reply is ' + reply.length + ' bytes, too big for UDP; answering ' +
                 'KRB_ERR_RESPONSE_TOO_BIG so the client retries over TCP');
        const tooBig = errorReply(52, { eText: 'the reply is ' + reply.length + ' bytes; retry over TCP' });
        return socket.send(Buffer.from(tooBig), rinfo.port, rinfo.address);
      }
      socket.send(Buffer.from(reply), rinfo.port, rinfo.address);
    }).catch(function (e) {
      log.error('krb5: failed to build a UDP reply: ' + (e.stack || e.message));
    });
  });
  socket.bind(port, '0.0.0.0', function () {
    log.info('krb5: KDC listening on UDP ' + socket.address().port + ' for realm ' + REALM);
  });
  return socket;
}

// ---------------------------------------------------------------------------
// MS-KKDCP, the KDC Proxy: the same messages over HTTPS.
//
// Registered at require time like every other route here. It is how a domain
// controller behind a firewall gets reached in practice, and it costs almost
// nothing once the framing exists — the body is the TCP-framed message wrapped in
// a small DER envelope.
// ---------------------------------------------------------------------------
app.post('/KdcProxy', function (req, res) {
  log.debug('Entering POST /KdcProxy.');
  const body = req.body;
  if (!body || !body.length) {
    log.debug('Leaving POST /KdcProxy. Empty body.');
    return res.status(400).type('text/plain').send('a KDC-PROXY-MESSAGE is required');
  }
  let framed;
  try {
    // KDC-PROXY-MESSAGE ::= SEQUENCE { kerb-message [0] OCTET STRING, ... }
    const outer = asn1.readTlv(prim.toBytes(body), 0);
    const fields = asn1.readTaggedSequence(outer.value);
    framed = asn1.decOctetString(fields[0]);
  } catch (e) {
    log.warn('krb5: KdcProxy body does not decode: ' + e.message);
    log.debug('Leaving POST /KdcProxy. Undecodable.');
    return res.status(400).type('text/plain').send('the KDC-PROXY-MESSAGE does not decode: ' + e.message);
  }
  if (framed.length < 4) {
    log.debug('Leaving POST /KdcProxy. Too short.');
    return res.status(400).type('text/plain').send('the kerb-message is too short to be framed');
  }
  const declared = (framed[0] << 24 | framed[1] << 16 | framed[2] << 8 | framed[3]) >>> 0;
  const message = framed.subarray(4, 4 + declared);
  handleMessage(message).then(function (reply) {
    const replyFramed = new Uint8Array(4 + reply.length);
    replyFramed[0] = (reply.length >>> 24) & 255;
    replyFramed[1] = (reply.length >>> 16) & 255;
    replyFramed[2] = (reply.length >>> 8) & 255;
    replyFramed[3] = reply.length & 255;
    replyFramed.set(reply, 4);
    const envelope = asn1.encSequence([asn1.encContext(0, asn1.encOctetString(replyFramed))]);
    log.debug('Leaving POST /KdcProxy. reply=' + reply.length + ' bytes');
    res.status(200).type('application/kerberos').send(Buffer.from(envelope));
  }).catch(function (e) {
    log.error('krb5: KdcProxy failed: ' + (e.stack || e.message));
    log.debug('Leaving POST /KdcProxy. Failed.');
    res.status(500).type('text/plain').send('the KDC could not answer: ' + e.message);
  });
});

// A non-spec convenience so a test (and a curious human) can see what this KDC
// knows without decrypting anything. It publishes NO keys and no passwords —
// only the principals, their supported etypes and their salts, which is exactly
// what a client can already learn from PA-ETYPE-INFO2.
app.get('/krb5/principals', function (req, res) {
  log.debug('Entering GET /krb5/principals.');
  const list = principals.all().map(function (p) {
    return {
      principal: p.name.join('/') + '@' + p.realm,
      nameType: p.type,
      salt: p.salt,
      etypes: principals.supportedEtypes(p).map(function (id) {
        return { etype: id, name: kcrypto.etypeName(id) };
      }),
      requiresPreAuth: p.requiresPreAuth,
      revoked: p.revoked,
      passwordExpired: p.passwordExpired,
      okAsDelegate: p.okAsDelegate,
      kvno: p.kvno,
      description: p.description
    };
  });
  log.debug('Leaving GET /krb5/principals. ' + list.length + ' principals.');
  res.status(200).json({
    realm: REALM,
    kdcPort: KDC_PORT,
    clockSkewSeconds: CLOCK_SKEW_SECONDS,
    clockOffsetSeconds: CLOCK_OFFSET_SECONDS,
    ticketLifetimeSeconds: TICKET_LIFETIME_SECONDS,
    implemented: ['AS exchange'],
    notImplementedYet: ['TGS exchange', 'AP exchange', 'PAC', 'FAST', 'PKINIT', 'cross-realm referrals'],
    principals: list
  });
});

// Start both listeners on ONE port.
//
// The subtlety is port 0. A real KDC is reached at a single port number over both
// transports — a client that fails over from UDP to TCP after
// KRB_ERR_RESPONSE_TOO_BIG sends the retry to the same place. Binding TCP and UDP
// independently with port 0 gives two DIFFERENT ephemeral ports, so the UDP
// listener silently becomes unreachable at the address anything else was told
// about. (Found by tests/krb5_as_exchange.js, whose UDP case timed out against a
// KDC that was listening perfectly well on a port nobody knew.)
//
// So TCP binds first and UDP follows it onto whatever port it actually got.
// `whenReady` resolves once both are up, for a caller that needs to know.
function listen(port) {
  const requested = (port === undefined || port === null) ? KDC_PORT : port;
  const tcp = startTcp(requested);
  const result = { tcp: tcp, udp: null, port: requested };
  result.whenReady = new Promise(function (resolve, reject) {
    function bindUdp() {
      const bound = tcp.address() ? tcp.address().port : requested;
      result.port = bound;
      result.udp = startUdp(bound);
      result.udp.once('listening', function () { resolve(result); });
      result.udp.once('error', reject);
    }
    if (tcp.listening) return bindUdp();
    tcp.once('listening', bindUdp);
    tcp.once('error', reject);
  });
  return result;
}

module.exports = {
  listen: listen,
  handleMessage: handleMessage,
  KDC_PORT: KDC_PORT,
  REALM: REALM,
  CLOCK_SKEW_SECONDS: CLOCK_SKEW_SECONDS
};
