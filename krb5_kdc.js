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
// here.
//
// Every ticket it issues now carries a **PAC** ([MS-PAC]) — the account's SID, its
// groups and its UserAccountControl flags, signed. That is what a Windows service
// actually authorizes on, and each principal in krb5_principals.js carries the identity
// to fill one, including the deliberately misconfigured accounts: `locked`'s PAC says
// ACCOUNT_DISABLED, `noreauth`'s says DONT_REQUIRE_PREAUTH, and the computer account's
// says WORKSTATION_TRUST_ACCOUNT with Domain Computers as its primary group. See
// buildPacFor() below for the two things about it that are silent when wrong.
//
// ---------------------------------------------------------------------------
// TWO REALMS, and one shared key between them.
//
// This KDC answers for EXAMPLE.COM **and** PARTNER.COM, which a real one never does —
// the simplification hides finding the other realm's KDC (DNS and SRV records) and none
// of the protocol. What it buys is that the whole cross-realm referral can be walked
// without a second container.
//
// A trust is not a setting: it is one principal, krbtgt/PARTNER.COM@EXAMPLE.COM, whose
// key both KDCs hold. Ask this KDC for a service in the other realm and it does not
// refuse — it issues a ticket-granting ticket for that realm, sealed with the trust key,
// and expects the client to notice and go and ask there. The reply is an ordinary,
// successful TGS-REP; the only signal is that its `sname` is not what was asked for. See
// issueReferral().
//
// Three consequences run through the code below, and each is silent when wrong:
//
//  * **Every principal lookup carries a REALM.** krbtgt/PARTNER.COM exists in BOTH
//    databases — the trust in one, that realm's own ticket-granting service in the other,
//    with different keys. A lookup that defaults to the local realm finds the wrong one
//    and the failure is an integrity check, which names the crypto.
//  * **The realm being answered AS comes from the request**, not from a constant, and
//    every field of the reply follows it.
//  * **A PAC arriving across a trust is RE-SIGNED, not rebuilt.** The target realm has no
//    copy of the client's account. It carries the buffers across and signs them with its
//    own keys. **SID filtering is not implemented** — that is the control which stops the
//    other realm asserting membership of groups in this one, and its absence is stated
//    rather than left as a silence.
//
// It does NOT check request signatures, does not implement FAST, and does not do S4U —
// phase 5 adds delegation. The AS and TGS exchanges are both served; the AP exchange
// belongs to a SERVICE rather than to a KDC and lives in krb5_service.js.
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
const kpac = require('./krb5_pac.js');

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

// Is the ticket being asked for a ticket-granting ticket? It decides which of the
// four PAC signatures belong in it ([MS-PAC] sections 2.8.2 and 2.8.3), so it is a
// question about the SNAME rather than about which exchange we are in — a TGS-REQ for
// krbtgt is a renewal or a referral and still yields a TGT.
function isTgtRequest(sname) {
  const parts = (sname || {}).name || [];
  return parts.length > 0 && parts[0] === 'krbtgt';
}

// ---------------------------------------------------------------------------
// The PAC.
//
// A Kerberos ticket proves who the client is. A Windows service decides what the
// client may DO from the PAC inside it — the account's SID, its groups, its account
// flags — so a KDC that issues tickets without one is not exercising the half of the
// protocol most questions are actually about. See krb5_pac.js for the wire format and
// for why the four signatures are not interchangeable.
//
// TWO THINGS HERE ARE EASY TO GET WRONG AND SILENT WHEN WRONG.
//
// **Which key signs the server signature.** It is the key the TICKET is encrypted
// with, not the krbtgt key — that is what lets the service verify it alone. For a TGT
// those are the same key, which is exactly why testing only with a TGT would not
// reveal a mix-up.
//
// **Which signatures belong in which ticket.** [MS-PAC] sections 2.8.2 and 2.8.3 say
// the ticket signature and the extended KDC signature SHOULD be present in tickets
// NOT encrypted to the krbtgt account. So a service ticket carries all four and a TGT
// carries two, and this KDC reproduces that rather than always emitting four — a
// client that only ever saw four would happily require them and then fail against a
// real domain the moment it looked at a TGT.
// ---------------------------------------------------------------------------
async function buildPacFor(client, opts) {
  log.debug('Entering buildPacFor(). client=' + client.name.join('/'));
  const options = opts || {};
  const identity = client.pac;
  const clientRealm = options.clientRealm || client.realm || REALM;
  const serverKey = options.serverKey;
  const kdcKey = options.kdcKey;

  const spec = {
    serverKey: serverKey,
    kdcKey: kdcKey,
    includeExtendedKdcSignature: !options.isTgt,
    includeTicketSignature: false,
    logonInfo: {
      logonTime: options.authtime,
      passwordLastSet: new Date(options.authtime.getTime() - 30 * 24 * 3600 * 1000),
      passwordMustChange: identity.passwordMustChange || undefined,
      effectiveName: client.name[0],
      fullName: identity.fullName,
      logonServer: 'DC01',
      // The CLIENT's domain, not the KDC's. They differ for a client of the other realm,
      // and the domain SID is what a service authorizes on — a PAC that named the
      // resource domain would describe an account that does not exist.
      logonDomainName: clientRealm.split('.')[0],
      logonDomainId: principals.domainSidFor(clientRealm),
      userId: identity.rid,
      primaryGroupId: identity.primaryGroupRid,
      groups: identity.groups.map(function (rid) { return { relativeId: rid }; }),
      extraSids: identity.extraSids.map(function (sid) { return { sid: sid }; }),
      userAccountControl: identity.userAccountControl,
      logonCount: 1
    },
    clientInfo: {
      // The INITIAL authentication time, which is the same in every service ticket
      // derived from one TGT. A service compares it with the ticket's own authtime.
      name: client.name[0],
      clientId: options.authtime
    },
    upnDns: {
      upn: client.name[0] + '@' + clientRealm.toLowerCase(),
      dnsDomainName: clientRealm,
      samName: client.name[0],
      sid: principals.domainSidFor(clientRealm) + '-' + identity.rid
    },
    // PAC_WAS_REQUESTED when the client asked via PA-PAC-REQUEST, and
    // PAC_WAS_GIVEN_IMPLICITLY when it neither asked nor declined. Reproducing that
    // distinction is the only way the workflow can show what the flag means.
    attributes: options.pacRequested ? 0x00000001 : 0x00000002,
    requestorSid: principals.domainSidFor(clientRealm) + '-' + identity.rid
  };

  if (options.isTgt) {
    log.debug('Leaving buildPacFor(). a TGT, so no ticket or extended KDC signature.');
    return kpac.buildPac(spec);
  }

  // A service ticket needs the ticket signature, and that is a two-pass build: the
  // signature covers the EncTicketPart's DER with THIS PAC's ad-data replaced by a
  // single zero byte. The PAC's own length therefore does not enter into it, which is
  // what makes the two passes possible at all — build the ticket around a one-byte
  // placeholder, checksum that, then build the real PAC and put it in the real ticket.
  const placeholderTicket = options.encodeTicketPart(
    kpac.wrapPacAsAuthorizationData(new Uint8Array([0])));
  spec.includeTicketSignature = true;
  spec.ticketBytes = placeholderTicket;
  const pacBytes = await kpac.buildPac(spec);
  log.debug('Leaving buildPacFor(). a service ticket, all four signatures, ' +
    pacBytes.length + ' bytes.');
  return pacBytes;
}

// ---------------------------------------------------------------------------
// The referral.
//
// A client asks for HTTP/app.partner.com. Its own KDC has no such principal — and the
// interesting part is what it does NOT do: it does not refuse. It issues a
// ticket-granting ticket for **krbtgt/PARTNER.COM**, sealed with the trust key, and the
// client is expected to notice and go ask that realm's KDC instead.
//
// THE TRAP IS ON THE CLIENT SIDE, and it is why this is worth being able to produce.
// The reply is a perfectly ordinary TGS-REP. Its `sname` is krbtgt/PARTNER.COM rather
// than the HTTP service that was asked for, and that difference is the ONLY signal that
// a referral happened. A client that assumes a successful TGS-REP contains the ticket it
// asked for will hand a ticket-granting ticket to a web server, and the web server will
// report that the ticket does not decrypt — a message about a ticket, for a problem
// about a realm. See readTgsRep() in krb5_client.js, which reports it explicitly.
//
// Three details that are real and easy to miss:
//
//  * **The etype is negotiated against the TRUST, not the service.** The ticket is
//    sealed with the trust key, so the trust's supported etypes decide. A trust with
//    only an RC4 key is why referrals fail on a hardened domain while tickets inside
//    each realm keep working.
//  * **`transited` stays empty for a direct trust.** RFC 4120 section 3.3.3.2 records
//    the realms traversed EXCLUDING the client's and the server's own, so a single hop
//    across a direct trust transits nothing. It is only a multi-hop path that fills the
//    field — and it is the field a service is supposed to apply policy to.
//  * **The PAC is not re-signed here and is not stripped either.** The referral ticket
//    carries the client's PAC from the issuing realm; the TARGET realm's KDC is what
//    re-signs it with its own keys. That is also where Windows applies SID filtering,
//    which this mock does NOT implement — a note rather than a silence, because SID
//    filtering is the control that stops the other realm asserting membership of groups
//    in this one.
// ---------------------------------------------------------------------------
async function issueReferral(ctx) {
  log.debug('Entering issueReferral(). target=' + ctx.targetRealm);
  const body = ctx.body;
  const trust = ctx.trust;

  const etype = principals.chooseEtype(trust, body.etypes);
  if (etype === null) {
    // Distinguished from an ordinary etype failure on purpose: the account that could
    // not agree is the TRUST, which is not the principal the client named.
    log.info('krb5: no common etype with the trust ' + trust.name.join('/') + ' — it offers [' +
      principals.supportedEtypes(trust).join(', ') + '] and the client offered [' +
      (body.etypes || []).join(', ') + ']');
    return errorReply(14, {
      crealm: ctx.ticketPart.crealm, cname: ctx.ticketPart.cname,
      realm: ctx.answeringRealm, sname: body.sname,
      eText: 'a referral to ' + ctx.targetRealm + ' would be sealed with the trust key, and the ' +
             'trust account offers [' + principals.supportedEtypes(trust).join(', ') + '] while ' +
             'the client offered [' + (body.etypes || []).join(', ') + ']. The trust, not the ' +
             'service, is what has to agree here.'
    });
  }
  const profile = kcrypto.etypeById(etype);
  const trustKey = await principals.longTermKey(trust, etype);
  const referralSname = { type: msgs.NAME_TYPE.SRV_INST, name: ['krbtgt', ctx.targetRealm] };

  // The referral ticket inherits the presented TGT's flags and lifetime, minus `initial`
  // — it was not obtained with a password — and carries the client's authorization data
  // forward unchanged.
  const flags = ticketFlagsForReferral(ctx.ticketPart.flags);
  const sessionKey = kcrypto.randomBytes(profile.keyBytes);
  const endtime = new Date(Math.min(
    (body.till && body.till > ctx.at ? body.till : kdcTime(TICKET_LIFETIME_SECONDS)).getTime(),
    ctx.ticketPart.endtime.getTime()));

  const encTicketPart = msgs.encEncTicketPart({
    flags: flags,
    key: { etype: etype, key: sessionKey },
    crealm: ctx.ticketPart.crealm,
    cname: ctx.ticketPart.cname,
    // Empty: a direct trust transits no intermediate realm. See above.
    transited: { type: 1, contents: new Uint8Array(0) },
    authtime: ctx.ticketPart.authtime,
    starttime: ctx.at,
    endtime: endtime,
    renewTill: ctx.ticketPart.renewTill,
    authorizationData: ctx.ticketPart.authorizationData
  });

  const useSubkey = !!ctx.authenticator.subkey;
  const replyKey = useSubkey ? ctx.authenticator.subkey.key : ctx.sessionKey;
  const replyEtype = useSubkey ? ctx.authenticator.subkey.etype : ctx.apReq.ticket.encPart.etype;
  const replyProfile = kcrypto.etypeById(replyEtype);
  const replyUsage = useSubkey
    ? kcrypto.KEY_USAGE.TGS_REP_ENCPART_SUBKEY
    : kcrypto.KEY_USAGE.TGS_REP_ENCPART_SESSKEY;

  const encRepPart = msgs.encEncKdcRepPart({
    key: { etype: etype, key: sessionKey },
    lastReq: [{ type: 0, value: ctx.ticketPart.authtime }],
    nonce: body.nonce,
    flags: flags,
    authtime: ctx.ticketPart.authtime,
    starttime: ctx.at,
    endtime: endtime,
    renewTill: ctx.ticketPart.renewTill,
    srealm: ctx.answeringRealm,
    // The reply's sname is the REFERRAL, not what was asked for. A client compares this
    // with its own request to discover that it was referred.
    sname: referralSname
  }, msgs.APPLICATION.ENC_TGS_REP_PART);

  log.info('krb5: ' + ctx.answeringRealm + ' has no ' + body.sname.name.join('/') +
    ' and REFERRED ' + ctx.ticketPart.cname.name.join('/') + '@' + ctx.ticketPart.crealm +
    ' to ' + ctx.targetRealm + ' — a TGT for ' + referralSname.name.join('/') + ' sealed with ' +
    'the trust key using ' + profile.name);
  log.debug('Leaving issueReferral().');
  return msgs.encKdcRep({
    msgType: msgs.MSG_TYPE.TGS_REP,
    crealm: ctx.ticketPart.crealm,
    cname: ctx.ticketPart.cname,
    ticket: {
      realm: ctx.answeringRealm,
      sname: referralSname,
      encPart: {
        etype: etype,
        kvno: trust.kvno,
        cipher: await profile.encrypt(trustKey, kcrypto.KEY_USAGE.KDC_REP_TICKET, encTicketPart)
      }
    },
    encPart: {
      etype: replyEtype,
      cipher: await replyProfile.encrypt(replyKey, replyUsage, encRepPart)
    }
  });
}

// `initial` never survives: it means the ticket came from an AS exchange with a
// password, and a referral did not.
function ticketFlagsForReferral(presented) {
  return (presented || []).filter(function (f) { return f !== msgs.TICKET_FLAG.INITIAL; });
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

  // Either realm this process answers for. KDC_ERR_WRONG_REALM for anything else, which
  // is a distinct and useful refusal: it means the client asked the wrong KDC rather
  // than that the account does not exist.
  if (principals.realmsServed().indexOf(body.realm) === -1) {
    log.info('krb5: wrong realm ' + JSON.stringify(body.realm) + '; this KDC serves ' +
      principals.realmsServed().join(' and '));
    return errorReply(68, {
      // This KDC's OWN realm, not the one asked for: `asRealm` does not exist yet, and
      // could not — the request named a realm we do not serve, so there is no answering
      // realm to speak of. A KRB-ERROR's `realm` is the sender's identity.
      realm: REALM, sname: body.sname,
      eText: 'this KDC serves ' + principals.realmsServed().join(' and ') + ', not ' + body.realm
    });
  }
  const asRealm = body.realm;
  if (!body.cname) {
    return errorReply(6, { realm: REALM, sname: body.sname, eText: 'no client name in the request' });
  }

  const client = principals.find(body.cname.name, asRealm);
  if (!client) {
    return errorReply(6, {
      crealm: body.realm, cname: body.cname, sname: body.sname,
      eText: 'no such principal: ' + body.cname.name.join('/')
    });
  }
  const service = principals.find((body.sname || {}).name || [], asRealm);
  if (!service) {
    return errorReply(7, {
      crealm: body.realm, cname: body.cname, sname: body.sname,
      eText: 'no such service principal: ' + ((body.sname || {}).name || []).join('/') +
             ' in ' + asRealm
    });
  }
  // The krbtgt key signs three of the PAC's four signatures whatever service the
  // ticket is for, so it is needed even when the ticket is not a TGT.
  const krbtgt = principals.find(['krbtgt', asRealm], asRealm);
  if (!krbtgt) {
    // Not reachable with the shipped principal table, and worth saying rather than
    // failing later inside the PAC builder with something about a missing key.
    log.error('krb5: there is no krbtgt principal, so no ticket can be signed');
    return errorReply(7, { crealm: body.realm, cname: body.cname, sname: body.sname,
      eText: 'this KDC has no krbtgt principal' });
  }
  // MS-KILE's PA-PAC-REQUEST: the client may ask for a PAC or ask for none. Which of
  // those happened goes into PAC_ATTRIBUTES_INFO, and a client that declines is
  // honoured — a service reading groups out of a PAC that is not there is a case worth
  // being able to produce on purpose.
  let pacRequested = false;
  let pacDeclined = false;
  (request.padata || []).forEach(function (pa) {
    if (pa.type !== msgs.PA_TYPE.PAC_REQUEST) return;
    try {
      // readPaPacRequest returns an OBJECT, not a boolean — `{ includePac: … }`. A
      // strict comparison against true/false is therefore always false and BOTH states
      // stay unset, which reads as "the client said nothing" and quietly grants a PAC
      // to a client that explicitly declined one.
      const asked = msgs.readPaPacRequest(pa.value).includePac;
      pacRequested = asked === true;
      pacDeclined = asked === false;
    } catch (e) {
      // A malformed PA-PAC-REQUEST is not worth refusing the whole request over: AD
      // ignores padata it cannot read, and so does this. Logged so it is not silent.
      log.info('krb5: could not read PA-PAC-REQUEST, ignoring it: ' + e.message);
    }
  });
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

  // The PAC. `encodeTicketPart` is passed as a function because the ticket signature
  // has to be computed over the ticket the PAC is going INTO, which does not exist
  // until the PAC does — see buildPacFor().
  const encodeTicketPart = function (authorizationData) {
    return msgs.encEncTicketPart({
      flags: flags,
      key: { etype: etype, key: sessionKey },
      crealm: asRealm,
      cname: body.cname,
      authtime: authtime,
      starttime: authtime,
      endtime: endtime,
      renewTill: renewTill,
      authorizationData: authorizationData
    });
  };
  // A client that DECLINED a PAC gets none. That is not a curiosity: it is the only
  // way to see what a Windows service does when the groups it authorizes on are not
  // there, and the request page offers it as a checkbox — so honouring it is what makes
  // that checkbox mean something rather than being a control that quietly does nothing.
  let encTicketPart;
  if (pacDeclined) {
    log.info('krb5: the client asked for NO PAC (PA-PAC-REQUEST include=false), so this ticket ' +
      'carries none. A Windows service reading group memberships from it will find nothing.');
    encTicketPart = encodeTicketPart(null);
  } else {
    const pacBytes = await buildPacFor(client, {
      authtime: authtime,
      clientRealm: asRealm,
      serverKey: { etype: etype, key: serviceKey },
      kdcKey: { etype: etype, key: await principals.longTermKey(krbtgt, etype) },
      // Whether the ticket is a TGT decides which two of the four signatures go in.
      isTgt: isTgtRequest(body.sname),
      pacRequested: pacRequested,
      encodeTicketPart: encodeTicketPart
    });
    encTicketPart = encodeTicketPart(kpac.wrapPacAsAuthorizationData(pacBytes));
  }
  const ticket = {
    realm: asRealm,
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
    srealm: asRealm,
    sname: body.sname
  }, msgs.APPLICATION.ENC_AS_REP_PART);

  log.info('krb5: issued a TGT for ' + body.cname.name.join('/') + '@' + asRealm + ' to ' +
    body.sname.name.join('/') + ' using ' + profile.name + ', flags [' +
    msgs.ticketFlagNames(flags).join(', ') + '], expiring ' + endtime.toISOString());

  return msgs.encKdcRep({
    msgType: msgs.MSG_TYPE.AS_REP,
    crealm: asRealm,
    cname: body.cname,
    ticket: ticket,
    encPart: {
      etype: etype,
      cipher: await profile.encrypt(clientKey, kcrypto.KEY_USAGE.AS_REP_ENCPART, encRepPart)
    }
  });
}

// ---------------------------------------------------------------------------
// The TGS exchange: trade a TGT for a service ticket.
//
// The structure is what surprises people. A TGS-REQ carries the TGT as
// PRE-AUTHENTICATION — a PA-TGS-REQ whose value is an entire AP-REQ — and that
// AP-REQ's Authenticator carries a checksum over the encoded KDC-REQ-BODY. So the
// KDC does, in order:
//
//   1. decrypt the ticket inside the AP-REQ with the krbtgt key (key usage 2), to
//      learn the session key and who the client is;
//   2. decrypt the Authenticator with that SESSION key (key usage 7);
//   3. verify the Authenticator's checksum over the request body (key usage 6) —
//      against the body's ORIGINAL bytes, not a re-encoding of them;
//   4. and only then look at what was actually asked for.
//
// Three checks in there are the ones a mock is tempted to skip and a debugger needs
// most: that the checksum covers the body actually sent (otherwise the body could be
// swapped after signing), that the Authenticator's cname matches the ticket's
// (otherwise one client's TGT authenticates another), and that the ticket is inside
// its validity window.
// ---------------------------------------------------------------------------
async function handleTgsReq(request) {
  log.debug('Entering handleTgsReq().');
  const body = request.reqBody;

  const paTgs = (request.padata || []).filter(function (pa) {
    return pa.type === msgs.PA_TYPE.TGS_REQ;
  })[0];
  if (!paTgs) {
    // Without the TGT there is nothing to verify. This is not a policy refusal but a
    // structural one, and saying which is useful.
    return errorReply(25, {
      realm: REALM, sname: body.sname,
      eText: 'a TGS-REQ must carry the TGT in a PA-TGS-REQ; this request carries none'
    });
  }

  let apReq;
  try {
    apReq = msgs.readApReq(paTgs.value);
  } catch (e) {
    return errorReply(60, { realm: REALM, sname: body.sname,
      eText: 'the PA-TGS-REQ does not contain a readable AP-REQ: ' + e.message });
  }

  // 1. The ticket, under the krbtgt key. A ticket for anything else presented here
  // is a different error, and worth distinguishing: it means the client asked the
  // wrong server.
  // Looked up in the TICKET'S OWN REALM, not in ours. A cross-realm ticket-granting
  // ticket is named krbtgt/OUR-REALM but was ISSUED BY the other realm, so its `realm`
  // field says EXAMPLE.COM while we are answering as PARTNER.COM — and the key that
  // opens it is the trust key held under that realm's entry. Looking it up in the local
  // realm finds this realm's own krbtgt instead, whose key is a different secret, and
  // the failure is "the ticket does not decrypt": a message about the ticket, for a
  // problem about which of two identically-named principals was consulted.
  const ticketService = principals.find(apReq.ticket.sname.name, apReq.ticket.realm);
  if (!ticketService) {
    return errorReply(7, { realm: REALM, sname: apReq.ticket.sname,
      eText: 'the ticket presented is for ' + apReq.ticket.sname.name.join('/') +
             ', which this KDC does not know' });
  }
  const ticketProfile = kcrypto.etypeById(apReq.ticket.encPart.etype);
  let ticketPart;
  try {
    ticketPart = msgs.readEncTicketPart(await ticketProfile.decrypt(
      await principals.longTermKey(ticketService, apReq.ticket.encPart.etype),
      kcrypto.KEY_USAGE.KDC_REP_TICKET, apReq.ticket.encPart.cipher));
  } catch (e) {
    log.info('krb5: the presented ticket will not decrypt: ' + e.message);
    return errorReply(31, { realm: REALM, sname: body.sname,
      eText: 'the ticket does not decrypt with this KDC\'s key for ' +
             apReq.ticket.sname.name.join('/') });
  }

  // 2. The Authenticator, under the ticket's SESSION key at key usage 7.
  const sessionKey = ticketPart.key.key;
  const authProfile = kcrypto.etypeById(apReq.authenticator.etype);
  let authenticator;
  try {
    authenticator = msgs.readAuthenticator(await authProfile.decrypt(
      sessionKey, kcrypto.KEY_USAGE.TGS_REQ_AUTH, apReq.authenticator.cipher));
  } catch (e) {
    log.info('krb5: the TGS-REQ Authenticator will not decrypt: ' + e.message);
    return errorReply(31, { realm: REALM, sname: body.sname,
      eText: 'the Authenticator does not decrypt with the ticket\'s session key at key usage 7' });
  }

  // The Authenticator's cname must match the ticket's, or one client's TGT would
  // authenticate a request naming another.
  if (authenticator.cname.name.join('/') !== ticketPart.cname.name.join('/') ||
      authenticator.crealm !== ticketPart.crealm) {
    log.warn('krb5: the Authenticator names ' + authenticator.cname.name.join('/') +
             ' but the ticket names ' + ticketPart.cname.name.join('/'));
    return errorReply(36, { realm: REALM, sname: body.sname,
      eText: 'the Authenticator and the ticket name different clients' });
  }

  // The ticket's own validity window, and the Authenticator's freshness.
  const at = now();
  if (ticketPart.endtime <= at) {
    return errorReply(32, { crealm: ticketPart.crealm, cname: ticketPart.cname,
      realm: REALM, sname: body.sname,
      eText: 'the ticket expired at ' + ticketPart.endtime.toISOString() });
  }
  if (ticketPart.starttime && ticketPart.starttime > new Date(at.getTime() + CLOCK_SKEW_SECONDS * 1000)) {
    return errorReply(33, { realm: REALM, sname: body.sname, eText: 'the ticket is not yet valid' });
  }
  const authSkew = Math.abs(at.getTime() - authenticator.ctime.getTime()) / 1000;
  if (authSkew > CLOCK_SKEW_SECONDS) {
    return errorReply(37, { crealm: ticketPart.crealm, cname: ticketPart.cname,
      realm: REALM, sname: body.sname,
      eText: 'the Authenticator\'s clock is ' + Math.round(authSkew) + ' seconds out' });
  }

  // 3. The checksum, over the body's ORIGINAL bytes. body.raw is kept by the reader
  // for exactly this: a re-encoding could differ and the checksum would then cover
  // something else, which is indistinguishable from tampering.
  if (!authenticator.cksum) {
    return errorReply(50, { realm: REALM, sname: body.sname,
      eText: 'the TGS-REQ Authenticator carries no checksum over the request body' });
  }
  let checksumOk = false;
  try {
    checksumOk = await authProfile.verifyChecksum(sessionKey, kcrypto.KEY_USAGE.TGS_REQ_AUTH_CKSUM,
      body.raw, authenticator.cksum.checksum);
  } catch (e) {
    log.warn('krb5: could not verify the request-body checksum: ' + e.message);
  }
  if (!checksumOk) {
    log.info('krb5: the Authenticator\'s checksum does not cover this request body');
    return errorReply(50, { crealm: ticketPart.crealm, cname: ticketPart.cname,
      realm: REALM, sname: body.sname,
      eText: 'the Authenticator\'s checksum does not match the request body (checksum type ' +
             authenticator.cksum.type + ', key usage 6)' });
  }

  // Which realm this request is being answered AS. It comes from the request body, not
  // from a constant, because this process serves both realms: a TGS-REQ whose realm is
  // PARTNER.COM is one the trusted realm's KDC is being asked to answer, and every
  // principal lookup and every field of the reply below has to follow that.
  const answeringRealm = principals.realmsServed().indexOf(body.realm) !== -1
    ? body.realm : REALM;

  // Now the request itself.
  const service = principals.find((body.sname || {}).name || [], answeringRealm);
  if (!service) {
    // Before refusing: is this a service in a realm we have a TRUST with? If so the
    // answer is not an error at all but a REFERRAL — a ticket-granting ticket for the
    // other realm, which the client presents to that realm's KDC. See issueReferral().
    const targetRealm = principals.realmForService((body.sname || {}).name || []);
    if (targetRealm && targetRealm !== answeringRealm) {
      const trust = principals.find(['krbtgt', targetRealm], answeringRealm);
      if (trust) {
        return issueReferral({
          request: request, body: body, ticketPart: ticketPart, trust: trust,
          targetRealm: targetRealm, answeringRealm: answeringRealm, at: at,
          sessionKey: sessionKey, apReq: apReq, authenticator: authenticator
        });
      }
      log.info('krb5: ' + ((body.sname || {}).name || []).join('/') + ' looks like it belongs to ' +
        targetRealm + ', but there is no trust with that realm from ' + answeringRealm);
    }
    return errorReply(7, { crealm: ticketPart.crealm, cname: ticketPart.cname,
      realm: answeringRealm, sname: body.sname,
      eText: 'no such service principal: ' + ((body.sname || {}).name || []).join('/') +
             '. On Active Directory this is an SPN that is not registered, or registered on a ' +
             'different account' +
             (targetRealm ? ', or a trust with ' + targetRealm + ' that does not exist' : '') +
             '.' });
  }
  // Looked up by name rather than reused from the presented ticket's sname: three of
  // the PAC's four signatures are made with the KRBTGT key specifically, and while the
  // ticket presented here is normally a TGT, saying so explicitly is what keeps this
  // correct once cross-realm referrals arrive and the presented ticket is somebody
  // else's krbtgt.
  const krbtgt = principals.find(['krbtgt', answeringRealm], answeringRealm);
  if (!krbtgt) {
    log.error('krb5: there is no krbtgt principal for ' + answeringRealm + ', so no ticket can ' +
      'be signed');
    return errorReply(7, { crealm: ticketPart.crealm, cname: ticketPart.cname,
      realm: answeringRealm, sname: body.sname,
      eText: 'this KDC has no krbtgt principal for ' + answeringRealm });
  }
  const etype = principals.chooseEtype(service, body.etypes);
  if (etype === null) {
    return errorReply(14, { crealm: ticketPart.crealm, cname: ticketPart.cname,
      realm: answeringRealm, sname: body.sname,
      eText: 'no common encryption type for ' + service.name.join('/') + ': it supports ' +
             principals.supportedEtypes(service).map(kcrypto.etypeName).join(', ') });
  }
  const profile = kcrypto.etypeById(etype);

  // Issue. The new ticket inherits the TGT's flags minus `initial` — only the AS
  // exchange issues an initial ticket, and a service may rely on that distinction.
  const inherited = ticketPart.flags.filter(function (f) {
    return f !== msgs.TICKET_FLAG.INITIAL;
  });
  const flags = inherited.slice();
  if (service.okAsDelegate && flags.indexOf(msgs.TICKET_FLAG.OK_AS_DELEGATE) === -1) {
    flags.push(msgs.TICKET_FLAG.OK_AS_DELEGATE);
  }

  const newSessionKey = kcrypto.randomBytes(profile.keyBytes);
  const authtime = ticketPart.authtime;
  const requestedTill = body.till && body.till > at ? body.till : kdcTime(TICKET_LIFETIME_SECONDS);
  // A service ticket cannot outlive the TGT that bought it.
  const endtime = new Date(Math.min(requestedTill.getTime(), ticketPart.endtime.getTime()));

  const serviceKey = await principals.longTermKey(service, etype);

  // The PAC again, and here the two keys are genuinely DIFFERENT: the server signature
  // is made with this service's key so the service can check it alone, and the other
  // three with the krbtgt key. On a TGT they coincide, which is why a mix-up between
  // them only shows up on a service ticket.
  //
  // A real KDC copies the client's groups out of the TGT's PAC rather than looking the
  // account up again. This one re-reads the principal table, which is a simplification
  // worth naming: it means a change to a principal takes effect on the next service
  // ticket rather than on the next TGT, where AD would keep serving the groups the TGT
  // was minted with until it expired.
  const encodeTicketPart = function (authorizationData) {
    return msgs.encEncTicketPart({
      flags: flags,
      key: { etype: etype, key: newSessionKey },
      crealm: ticketPart.crealm,
      cname: ticketPart.cname,
      authtime: authtime,
      starttime: at,
      endtime: endtime,
      renewTill: ticketPart.renewTill,
      authorizationData: authorizationData
    });
  };
  // The client's account lives in the realm the TICKET came from, not necessarily in the
  // one being answered — after a referral those differ, and that is the whole point.
  const ticketClient = principals.find(ticketPart.cname.name, ticketPart.crealm);
  const crossRealm = ticketPart.crealm !== answeringRealm;
  // Whether the TGT itself carries a PAC. A real KDC propagates the client's
  // authorization data from the TGT into the service ticket, so a client that declined
  // a PAC at the AS exchange does not acquire one by asking for a service ticket — and
  // a workflow where unticking the box only affected the TGT would be misleading in a
  // way that is hard to notice, since the TGT is the ticket nobody looks inside.
  const tgtHadPac = kpac.findPacs(ticketPart.authorizationData || []).length > 0;
  let encTicketPart;
  if (!tgtHadPac) {
    log.info('krb5: the presented TGT carries no PAC, so neither does the service ticket issued ' +
      'from it');
    encTicketPart = encodeTicketPart(null);
  } else if (crossRealm) {
    // A referral has arrived. This realm has no copy of the client's account — it lives
    // in ticketPart.crealm — so the PAC is carried across and RE-SIGNED with this realm's
    // keys rather than rebuilt. The signatures it came with were made with the other
    // realm's krbtgt key and the trust key, neither of which the service being issued to
    // holds.
    const carried = kpac.findPacs(ticketPart.authorizationData || []);
    const placeholder = encodeTicketPart(kpac.wrapPacAsAuthorizationData(new Uint8Array([0])));
    const resigned = await kpac.resignPac(carried[0].bytes, {
      serverKey: { etype: etype, key: serviceKey },
      kdcKey: { etype: etype, key: await principals.longTermKey(krbtgt, etype) },
      includeTicketSignature: !isTgtRequest(body.sname),
      includeExtendedKdcSignature: !isTgtRequest(body.sname),
      ticketBytes: placeholder
    });
    log.info('krb5: ' + answeringRealm + ' re-signed the PAC that ' + ticketPart.crealm +
      ' issued for ' + ticketPart.cname.name.join('/') + ' — its contents are carried across ' +
      'unchanged (SID filtering is NOT implemented here) and all of its signatures are new');
    encTicketPart = encodeTicketPart(kpac.wrapPacAsAuthorizationData(resigned));
  } else if (!ticketClient) {
    // The TGT names a principal this KDC no longer has. The ticket is still issuable —
    // the TGT's signature is what authorized it — so it is issued without a PAC rather
    // than refused, and said out loud, because a service ticket with no PAC is a
    // situation worth being able to reach on purpose.
    log.info('krb5: the TGT names ' + ticketPart.cname.name.join('/') + ', which is not in the ' +
      'principal table; issuing a service ticket with NO PAC');
    encTicketPart = encodeTicketPart(null);
  } else {
    const pacBytes = await buildPacFor(ticketClient, {
      authtime: authtime,
      clientRealm: ticketPart.crealm,
      serverKey: { etype: etype, key: serviceKey },
      kdcKey: { etype: etype, key: await principals.longTermKey(krbtgt, etype) },
      isTgt: isTgtRequest(body.sname),
      // In a TGS exchange the client asked for its PAC back when it got the TGT, so
      // the attribute records that it was requested rather than given implicitly.
      pacRequested: true,
      encodeTicketPart: encodeTicketPart
    });
    encTicketPart = encodeTicketPart(kpac.wrapPacAsAuthorizationData(pacBytes));
  }

  // The reply's enc-part: key usage 9 under the Authenticator's subkey when one was
  // sent, 8 under the TGT's session key otherwise. A client that always tries one
  // fails whenever the other applies, so which was used is logged.
  const useSubkey = !!authenticator.subkey;
  const replyKey = useSubkey ? authenticator.subkey.key : sessionKey;
  const replyEtype = useSubkey ? authenticator.subkey.etype : apReq.ticket.encPart.etype;
  const replyProfile = kcrypto.etypeById(replyEtype);
  const replyUsage = useSubkey
    ? kcrypto.KEY_USAGE.TGS_REP_ENCPART_SUBKEY
    : kcrypto.KEY_USAGE.TGS_REP_ENCPART_SESSKEY;

  const encRepPart = msgs.encEncKdcRepPart({
    key: { etype: etype, key: newSessionKey },
    lastReq: [{ type: 0, value: authtime }],
    nonce: body.nonce,
    flags: flags,
    authtime: authtime,
    starttime: at,
    endtime: endtime,
    renewTill: ticketPart.renewTill,
    srealm: answeringRealm,
    sname: body.sname
  }, msgs.APPLICATION.ENC_TGS_REP_PART);

  log.info('krb5: ' + answeringRealm + ' issued a service ticket for ' +
    ticketPart.cname.name.join('/') + '@' + ticketPart.crealm + ' to ' +
    body.sname.name.join('/') + ' using ' + profile.name +
    ', flags [' + msgs.ticketFlagNames(flags).join(', ') + '], enc-part at key usage ' + replyUsage +
    (useSubkey ? ' (the Authenticator carried a subkey)' : ' (no subkey was sent)'));

  log.debug('Leaving handleTgsReq().');
  return msgs.encKdcRep({
    msgType: msgs.MSG_TYPE.TGS_REP,
    crealm: ticketPart.crealm,
    cname: ticketPart.cname,
    ticket: {
      realm: answeringRealm,
      sname: body.sname,
      encPart: {
        etype: etype,
        kvno: service.kvno,
        cipher: await profile.encrypt(serviceKey, kcrypto.KEY_USAGE.KDC_REP_TICKET, encTicketPart)
      }
    },
    encPart: {
      etype: replyEtype,
      cipher: await replyProfile.encrypt(replyKey, replyUsage, encRepPart)
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
      const request = msgs.readKdcReq(bytes);
      return await handleTgsReq(request);
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
    implemented: ['AS exchange', 'TGS exchange'],
    notImplementedYet: ['PAC', 'FAST', 'PKINIT', 'cross-realm referrals', 'S4U2Self', 'S4U2Proxy'],
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
