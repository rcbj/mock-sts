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
// ---------------------------------------------------------------------------
// DELEGATION is served too, all four ways, and the mock draws the distinctions on purpose:
// S4U2Self (PA-FOR-USER), S4U2Proxy authorized by EITHER msDS-AllowedToDelegateTo on the
// front end or msDS-AllowedToActOnBehalfOfOtherIdentity on the back end, FORWARDED tickets
// for unconstrained delegation, and RENEWALS. See resolveS4u() for the asymmetries between
// the two S4U2Proxy routes, which are the whole security story of resource-based
// delegation, and the FORWARDED block in handleTgsReq() for the one control that limits
// unconstrained delegation at all.
//
// It does NOT check request signatures, does not implement FAST, does not implement kpasswd,
// and does not apply SID filtering across a trust. The AS and TGS exchanges are both served;
// the AP exchange belongs to a SERVICE rather than to a KDC and lives in krb5_service.js.
// ---------------------------------------------------------------------------

const net = require('net');
const dgram = require('dgram');
const app = require('../common/app');
const { log } = require('../common/helpers');
const config = require('../common/config');
// The register the admin console counts tickets in. Kerberos is the one protocol
// family here whose artifacts do not pass through signJwt() or an assertion
// builder, so the two places a ticket is minted say so explicitly — and there are
// exactly two, the end of handleAsReq() and the end of handleTgsReq().
const stats = require('../common/admin_stats');
// The application registry (ou=applications in the embedded directory). A
// Kerberos service principal is an application like an OAuth client is, and
// this is where a ticket for one is issued.
const applications = require('../common/applications');
const asn1 = require('./krb5_asn1.js');
const msgs = require('./krb5_messages.js');
const kcrypto = require('./krb5_crypto.js');
const prim = require('./krb5_primitives.js');
const principals = require('./krb5_principals.js');
const kpac = require('./krb5_pac.js');

const KDC_PORT = config.value('krb5.kdcPort');
const REALM = principals.REALM;

// Active Directory's default tolerance, and the reason KRB_AP_ERR_SKEW is one of
// the most common Kerberos failures in the field.
// Functions rather than constants: both are settable at runtime, and moving
// the clock deliberately is the whole point of the offset — a value captured
// at require time could only ever be moved by a restart.
function clockSkewSeconds() {
  return config.value('krb5.clockSkew');
}
const TICKET_LIFETIME_SECONDS = 10 * 3600;
const RENEW_LIFETIME_SECONDS = 7 * 24 * 3600;

// A test can ask this KDC to lie about its clock, so the client's skew handling
// can be exercised without changing anybody's system time.
function clockOffsetSeconds() {
  return config.value('krb5.clockOffset');
}

// Replies larger than this are a bug in this service rather than a legitimate
// message; the cap exists so a mistake surfaces here rather than as a truncated
// datagram at the far end.
const MAX_REPLY_BYTES = 128 * 1024;

function now() {
  return new Date(Date.now() + clockOffsetSeconds() * 1000);
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

// ---------------------------------------------------------------------------
// S4U — the two halves of "on behalf of somebody else" ([MS-SFU]).
//
// Ordinarily a TGS-REQ produces a ticket for whoever presented the TGT. These two
// extensions change that, and the whole of delegation is the KDC's decision about
// whether to allow it:
//
//   **S4U2Self** (padata PA-FOR-USER). A service asks for a ticket to ITSELF naming a
//   user who is not involved at all — no password, no ticket, no consent. It is how a
//   service that authenticated somebody by other means gets a Kerberos identity for
//   them. Anyone with a service account can do this; it is not a privilege, because the
//   ticket is to yourself.
//
//   **S4U2Proxy** (option cname-in-addl-tkt, evidence in additional-tickets). The service
//   then asks for a ticket to ANOTHER service as that user. THIS is the privilege, and
//   what authorizes it is one of two attributes on two different accounts:
//
//     * CLASSIC constrained delegation — `msDS-AllowedToDelegateTo` on the FRONT-END
//       account, listing the services it may reach. Only a domain admin can set it.
//     * RESOURCE-BASED (RBCD) — `msDS-AllowedToActOnBehalfOfOtherIdentity` on the
//       BACK-END account, listing who may act on its behalf. Whoever controls that
//       object can set it, which is why RBCD turns "I can write to this computer
//       account" into "I can reach this service as anybody".
//
// Two more asymmetries that matter and are easy to miss:
//
//   * **Classic requires the evidence ticket to be FORWARDABLE; RBCD does not.** And a
//     forwardable ticket out of S4U2Self is granted only to an account with
//     TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION. So classic delegation needs that flag and
//     RBCD does not need it either — one of the reasons RBCD is the easier path.
//   * **RBCD additionally requires PA-PAC-OPTIONS with the RBCD bit**, and [MS-SFU] says
//     a KDC MUST answer KDC_ERR_BADOPTION without it. That error mentions nothing about
//     padata, so it is refused here with an explanation.
//
// Returns { mode, clientName, clientRealm, evidencePart, transited, error }.
// ---------------------------------------------------------------------------
async function resolveS4u(ctx) {
  log.debug('Entering resolveS4u().');
  const body = ctx.body;
  const ticketPart = ctx.ticketPart;
  const plain = {
    mode: 'none',
    clientName: ticketPart.cname,
    clientRealm: ticketPart.crealm,
    evidencePart: null,
    transited: []
  };

  const forUserPa = (ctx.request.padata || []).filter(function (pa) {
    return pa.type === msgs.PA_TYPE.FOR_USER;
  })[0];
  const wantsProxy = (body.kdcOptions || []).indexOf(msgs.KDC_OPTION.CNAME_IN_ADDL_TKT) !== -1;

  if (!forUserPa && !wantsProxy) {
    log.debug('Leaving resolveS4u(). an ordinary TGS request.');
    return plain;
  }

  // The account that is ASKING. For S4U it is a service acting for somebody else, and
  // its own attributes are what decide whether it may.
  const requester = principals.find(ticketPart.cname.name, ticketPart.crealm);
  const requesterName = ticketPart.cname.name.join('/');

  // ----- S4U2Self -----
  if (forUserPa) {
    if (wantsProxy) {
      return { error: errorReply(13, {
        crealm: ticketPart.crealm, cname: ticketPart.cname, realm: ctx.answeringRealm,
        sname: body.sname,
        eText: 'PA-FOR-USER and cname-in-addl-tkt were BOTH sent. Those are the two halves of ' +
               'S4U and they are separate requests: S4U2Self obtains the evidence ticket, and ' +
               'S4U2Proxy then presents it.'
      }) };
    }
    let forUser;
    try {
      forUser = msgs.readPaForUser(forUserPa.value);
    } catch (e) {
      return { error: errorReply(13, {
        crealm: ticketPart.crealm, cname: ticketPart.cname, realm: ctx.answeringRealm,
        sname: body.sname, eText: 'PA-FOR-USER does not decode: ' + e.message
      }) };
    }

    // The checksum is what stops a service naming a user it did not authenticate... and
    // note exactly what it proves: only that whoever built this padata holds the TGT's
    // session key. It is integrity, not authorization. [MS-SFU] section 2.2.1 fixes the
    // algorithm as HMAC-MD5 at key usage 17 whatever the session key's etype.
    const arcfour = kcrypto.etypeById(23);
    const expected = await arcfour.checksum(ctx.sessionKey, kcrypto.KEY_USAGE.PA_FOR_USER_CKSUM,
      s4uByteArray(forUser.userName, forUser.userRealm, forUser.authPackage));
    if (!prim.equalConstantTime(expected, forUser.cksum.checksum)) {
      log.info('krb5: the PA-FOR-USER checksum does not verify for ' + requesterName);
      return { error: errorReply(13, {
        crealm: ticketPart.crealm, cname: ticketPart.cname, realm: ctx.answeringRealm,
        sname: body.sname,
        eText: 'the PA-FOR-USER checksum does not verify. It is HMAC-MD5 (not the session key\'s ' +
               'own checksum type) at key usage 17, over the name type as four little-endian ' +
               'bytes then the name components, the realm and the auth-package concatenated.'
      }) };
    }
    if (forUser.cksum.type !== arcfour.checksumType) {
      log.info('krb5: PA-FOR-USER carries cksumtype ' + forUser.cksum.type + ' rather than -138');
    }

    // Created on demand, exactly as at the AS exchange: a front-end may name any user,
    // and the whole point of S4U2Self is that the named account is not involved and
    // never proves anything. A reserved name still fails, which is the only way to see
    // what a service gets back when it impersonates somebody who does not exist.
    const user = principals.findOrCreateUser(forUser.userName.name, forUser.userRealm);
    if (!user) {
      return { error: errorReply(6, {
        crealm: ticketPart.crealm, cname: ticketPart.cname, realm: ctx.answeringRealm,
        sname: body.sname,
        eText: 'S4U2Self named ' + forUser.userName.name.join('/') + '@' + forUser.userRealm +
               ', which this KDC does not know and will not create. The name is either ' +
               'reserved (' + principals.reservedUnknown().join(', ') + '), service-shaped, ' +
               'or in a realm this KDC does not serve'
      }) };
    }
    // A service may only ask for a ticket to ITSELF this way.
    if (body.sname.name.join('/') !== requesterName) {
      return { error: errorReply(13, {
        crealm: ticketPart.crealm, cname: ticketPart.cname, realm: ctx.answeringRealm,
        sname: body.sname,
        eText: 'S4U2Self is a request for a ticket to YOURSELF: ' + requesterName + ' asked for ' +
               body.sname.name.join('/') + '. Reaching another service on a user\'s behalf is ' +
               'S4U2Proxy, which needs the evidence ticket and an authorization to match.'
      }) };
    }
    log.info('krb5: S4U2Self — ' + requesterName + ' is asking for a ticket to itself on behalf ' +
      'of ' + forUser.userName.name.join('/') + '@' + forUser.userRealm + ' (no involvement from ' +
      'that account at all)');
    log.debug('Leaving resolveS4u(). mode=self');
    return {
      mode: 'self',
      clientName: { type: user.type, name: user.name },
      clientRealm: forUser.userRealm,
      impersonated: user,
      requester: requester,
      evidencePart: null,
      transited: []
    };
  }

  // ----- S4U2Proxy -----
  const additional = body.additionalTickets || [];
  if (!additional.length) {
    return { error: errorReply(13, {
      crealm: ticketPart.crealm, cname: ticketPart.cname, realm: ctx.answeringRealm,
      sname: body.sname,
      eText: 'cname-in-addl-tkt was set but additional-tickets is empty. That option means "read ' +
             'the client\'s identity out of the ticket I am also sending", and there is none.'
    }) };
  }

  // The evidence ticket is a service ticket FOR THE REQUESTER, so the requester's own key
  // opens it. That is the check: a service can only present evidence addressed to itself.
  const evidence = additional[0];
  const evidenceService = principals.find(evidence.sname.name, evidence.realm);
  if (!evidenceService || evidence.sname.name.join('/') !== requesterName) {
    return { error: errorReply(13, {
      crealm: ticketPart.crealm, cname: ticketPart.cname, realm: ctx.answeringRealm,
      sname: body.sname,
      eText: 'the evidence ticket is for ' + evidence.sname.name.join('/') + ' but the request ' +
             'comes from ' + requesterName + '. A service may only present evidence addressed to ' +
             'itself — otherwise anyone holding any service ticket could delegate with it.'
    }) };
  }
  let evidencePart;
  try {
    const evidenceProfile = kcrypto.etypeById(evidence.encPart.etype);
    evidencePart = msgs.readEncTicketPart(await evidenceProfile.decrypt(
      await principals.longTermKey(evidenceService, evidence.encPart.etype),
      kcrypto.KEY_USAGE.KDC_REP_TICKET, evidence.encPart.cipher));
  } catch (e) {
    return { error: errorReply(13, {
      crealm: ticketPart.crealm, cname: ticketPart.cname, realm: ctx.answeringRealm,
      sname: body.sname,
      eText: 'the evidence ticket does not decrypt with ' + requesterName + '\'s key: ' + e.message
    }) };
  }

  const target = principals.find(body.sname.name, ctx.answeringRealm);
  const targetName = (body.sname.name || []).join('/');
  const resourceBased = (ctx.request.padata || []).some(function (pa) {
    if (pa.type !== msgs.PA_TYPE.PAC_OPTIONS) return false;
    try {
      return msgs.readPaPacOptions(pa.value).flags
        .indexOf(msgs.PAC_OPTION.RESOURCE_BASED_CONSTRAINED_DELEGATION) !== -1;
    } catch (e) {
      // Unreadable padata is ignored rather than fatal, as AD ignores padata it cannot
      // read — but logged, because silently treating it as absent changes the answer.
      log.info('krb5: could not read PA-PAC-OPTIONS, treating RBCD as not requested: ' + e.message);
      return false;
    }
  });

  const classicAllowed = !!requester &&
    requester.allowedToDelegateTo.indexOf(targetName) !== -1;
  const rbcdAllowed = !!target &&
    target.allowedToActOnBehalfOf.indexOf(requesterName) !== -1;

  if (!classicAllowed && !rbcdAllowed) {
    log.info('krb5: REFUSING S4U2Proxy — ' + requesterName + ' may not delegate to ' + targetName +
      '. Neither its own msDS-AllowedToDelegateTo nor that target\'s ' +
      'msDS-AllowedToActOnBehalfOfOtherIdentity permits it.');
    return { error: errorReply(13, {
      crealm: ticketPart.crealm, cname: ticketPart.cname, realm: ctx.answeringRealm,
      sname: body.sname,
      eText: requesterName + ' is not authorized to reach ' + targetName + ' on anybody\'s ' +
             'behalf. Two attributes could permit it and neither does: ' +
             'msDS-AllowedToDelegateTo on ' + requesterName + ' (classic constrained delegation, ' +
             'currently [' + (requester ? requester.allowedToDelegateTo.join(', ') : '') + ']), ' +
             'or msDS-AllowedToActOnBehalfOfOtherIdentity on ' + targetName + ' (resource-based, ' +
             'currently [' + (target ? target.allowedToActOnBehalfOf.join(', ') : '') + ']).'
    }) };
  }

  // RBCD is the only thing permitting it, so the padata is mandatory ([MS-SFU]).
  if (!classicAllowed && rbcdAllowed && !resourceBased) {
    log.info('krb5: REFUSING S4U2Proxy — only RBCD permits this and PA-PAC-OPTIONS is missing');
    return { error: errorReply(13, {
      crealm: ticketPart.crealm, cname: ticketPart.cname, realm: ctx.answeringRealm,
      sname: body.sname,
      eText: 'this delegation is permitted only by resource-based constrained delegation, and ' +
             '[MS-SFU] requires PA-PAC-OPTIONS carrying the resource-based bit for that. ' +
             'Without it the answer is KDC_ERR_BADOPTION — which says nothing about padata, ' +
             'so: send PA-PAC-OPTIONS (padata type 167) with bit 3 set.'
    }) };
  }

  // Classic needs FORWARDABLE evidence; RBCD does not, and that asymmetry is real.
  const evidenceForwardable =
    (evidencePart.flags || []).indexOf(msgs.TICKET_FLAG.FORWARDABLE) !== -1;
  if (classicAllowed && !rbcdAllowed && !evidenceForwardable) {
    log.info('krb5: REFUSING S4U2Proxy — the evidence ticket is not forwardable');
    return { error: errorReply(13, {
      crealm: ticketPart.crealm, cname: ticketPart.cname, realm: ctx.answeringRealm,
      sname: body.sname,
      eText: 'the evidence ticket is not forwardable, which classic constrained delegation ' +
             'requires. A ticket from S4U2Self is forwardable only when the requesting account ' +
             'has TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION set, so this usually means that flag is ' +
             'missing on ' + requesterName + ' — note that resource-based delegation would not ' +
             'have needed either.'
    }) };
  }

  log.info('krb5: S4U2Proxy — ' + requesterName + ' is reaching ' + targetName + ' as ' +
    evidencePart.cname.name.join('/') + '@' + evidencePart.crealm + ', authorized by ' +
    (classicAllowed ? 'msDS-AllowedToDelegateTo on ' + requesterName + ' (classic)'
                    : 'msDS-AllowedToActOnBehalfOfOtherIdentity on ' + targetName + ' (RBCD)'));
  log.debug('Leaving resolveS4u(). mode=proxy');
  return {
    mode: 'proxy',
    clientName: evidencePart.cname,
    clientRealm: evidencePart.crealm,
    evidencePart: evidencePart,
    requester: requester,
    resourceBased: resourceBased,
    classic: classicAllowed,
    // The audit trail that goes into the PAC: this service is now one of the services the
    // client has been delegated through.
    transited: [requesterName]
  };
}

// [MS-SFU] section 2.2.1's S4UByteArray. Duplicated deliberately from the client's copy —
// the two ends have to agree, and tests/krb5_codec_sync.js compares them.
function s4uByteArray(userName, userRealm, authPackage) {
  const parts = [Uint8Array.from([
    userName.type & 0xff, (userName.type >>> 8) & 0xff,
    (userName.type >>> 16) & 0xff, (userName.type >>> 24) & 0xff
  ])];
  (userName.name || []).forEach(function (c) { parts.push(prim.utf8(c)); });
  parts.push(prim.utf8(userRealm));
  parts.push(prim.utf8(authPackage || 'Kerberos'));
  return prim.concat(parts);
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
    JSON.stringify(client.salt) + ', s2kparams ' +
    (principals.s2kparamsMode() === 'send'
      ? 'SENT (explicit 4096, the pre-2026-08 behaviour of this mock)'
      : 'OMITTED (as Active Directory does; the client must apply the RFC ' +
        '3962 default). Set KRB5_S2KPARAMS=send to advertise it explicitly.'));
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
  if (skew > clockSkewSeconds()) {
    log.info('krb5: clock skew ' + Math.round(skew) + 's exceeds the ' + clockSkewSeconds() +
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

  // Any username authenticates here, so a name that is not in the table gets an account
  // rather than KDC_ERR_C_PRINCIPAL_UNKNOWN — see findOrCreateUser() in
  // krb5_principals.js. It still returns null for the two cases that must keep failing:
  // a reserved name (so this error stays reachable on purpose) and a service-shaped
  // multi-component name, which is not a user and is nobody's to invent.
  const client = principals.findOrCreateUser(body.cname.name, asRealm);
  if (!client) {
    return errorReply(6, {
      crealm: body.realm, cname: body.cname, sname: body.sname,
      // No em dash and no other non-ASCII in an eText: KerberosString is a GeneralString,
      // and a client that decodes it as Latin-1 renders the UTF-8 bytes as mojibake in the
      // one field whose whole job is to be read by a person.
      eText: 'no such principal: ' + body.cname.name.join('/') + '. Every other username ' +
             'would have been created on the spot; this one is either reserved (' +
             principals.reservedUnknown().join(', ') + ') or has more than one component, ' +
             'which makes it a service name rather than a user'
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
  // "Account is sensitive and cannot be delegated". The refusal is not an error — the
  // ticket is issued, simply WITHOUT the forwardable flag — and that is the design: it
  // works no matter which service the user visits, because a ticket that was never
  // forwardable cannot be forwarded by anybody. An error here would break the user's
  // logon instead of protecting it.
  if (wantsForwardable && client.notDelegated) {
    log.info('krb5: ' + client.name.join('/') + ' is flagged NOT_DELEGATED (account is sensitive ' +
      'and cannot be delegated), so its TGT is NOT forwardable however it was asked for');
  } else if (wantsForwardable) {
    flags.push(msgs.TICKET_FLAG.FORWARDABLE);
  }
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

  // A TGT is what the console counts as a Kerberos session, because that is what
  // it is: the credential the session consists of. Service tickets are counted
  // separately below for the same reason — they are uses of a session, not
  // sessions, and adding the two would report the wrong number twice.
  stats.recordTicket('TGT', {
    client: body.cname.name.join('/') + '@' + asRealm,
    realm: asRealm,
    service: body.sname.name.join('/'),
    etype: profile.name,
    expiresAt: endtime.getTime()
  });

  // An AS-REP is the one authentication in this whole service that a wrong password
  // really does fail: the pre-authentication timestamp had to decrypt under the
  // client's long-term key to get this far, and the reply is sealed with it. So this
  // is recorded as the strongest thing here, and the method says which of the two
  // shapes it was — a KDC that accepts an AS-REQ with no padata is the interesting
  // misconfiguration, not the ordinary case.
  stats.recordAuthentication({
    presented: body.cname.name.join('/') + '@' + asRealm,
    protocol: 'Kerberos v5',
    method: encTimestamp ? 'AS-REQ with PA-ENC-TIMESTAMP' : 'AS-REQ without pre-authentication',
    note: 'Encryption type ' + profile.name + '. The client proved possession of its long-term key, ' +
          'which is the only credential this service genuinely checks.'
  });

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
  if (ticketPart.starttime && ticketPart.starttime > new Date(at.getTime() + clockSkewSeconds() * 1000)) {
    return errorReply(33, { realm: REALM, sname: body.sname, eText: 'the ticket is not yet valid' });
  }
  const authSkew = Math.abs(at.getTime() - authenticator.ctime.getTime()) / 1000;
  if (authSkew > clockSkewSeconds()) {
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
  // `let`, not `const`: findOrCreateService() below may fill it in for a host this
  // mock is willing to be, which is the whole of the on-demand registration.
  let service = principals.find((body.sname || {}).name || [], answeringRealm);
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
    // AFTER the referral, and only for a host this mock is willing to be a service
    // for: an SPN in one of KRB5_SERVICE_DOMAINS is registered on first sight. The
    // order matters — a name in the trusted realm's domain has already been
    // answered with a referral above, and creating it locally instead would answer
    // a cross-realm question with a local ticket that the other realm's service
    // could not open. See findOrCreateService() for why creating a service is safe
    // HERE and is not in general.
    const created = principals.findOrCreateService((body.sname || {}).name || [],
        answeringRealm);
    if (!created) {
      return errorReply(7, { crealm: ticketPart.crealm, cname: ticketPart.cname,
        realm: answeringRealm, sname: body.sname,
        eText: 'no such service principal: ' + ((body.sname || {}).name || []).join('/') +
               '. On Active Directory this is an SPN that is not registered, or registered on a ' +
               'different account' +
               (targetRealm ? ', or a trust with ' + targetRealm + ' that does not exist' : '') +
               '. This mock registers a service on first sight when its host matches ' +
               (principals.SERVICE_DOMAINS.join(', ') || '(nothing configured)') +
               ', and this one does not — GET /krb5/principals lists what it knows.' });
    }
    service = created;
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

  // ---------------------------------------------------------------------------
  // A RENEWAL. The RENEW option means "give me the same ticket again, later" rather than
  // "issue me a new one", and three rules make it that rather than a fresh authentication:
  //
  //   * the presented ticket must be flagged RENEWABLE and carry a renew-till;
  //   * the new endtime is capped at renew-till, which does NOT move — that cap is the
  //     whole point of a renewable ticket, since otherwise it would be immortal;
  //   * **authtime is preserved.** A renewed ticket must not look freshly authenticated: a
  //     service reading authtime to decide how recently the user proved themselves would
  //     otherwise be told a lie that grows more wrong with every renewal.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // FORWARDED — UNCONSTRAINED delegation, and the one the KDC cannot police afterwards.
  //
  // The client is asking for another ticket-granting ticket, flagged `forwarded`, to hand
  // to a service inside a KRB-CRED. Once it has it, that service can obtain tickets to
  // ANYTHING as this client until the ticket expires, and the KDC is never asked about it
  // again — there is no list of permitted targets, because there is no constraint. So the
  // only place a limit can be applied is HERE, at issue time, and it rests on two things:
  //
  //   * the presented ticket must itself be FORWARDABLE — which the AS exchange refuses to
  //     an account flagged NOT_DELEGATED, so a sensitive account can never reach this point;
  //   * the account is re-checked anyway, because a forwardable ticket issued before the
  //     flag was set would otherwise still work.
  // ---------------------------------------------------------------------------
  const wantsForwarded = (body.kdcOptions || []).indexOf(msgs.KDC_OPTION.FORWARDED) !== -1;
  if (wantsForwarded) {
    if ((ticketPart.flags || []).indexOf(msgs.TICKET_FLAG.FORWARDABLE) === -1) {
      log.info('krb5: REFUSING to forward — the presented ticket is not forwardable');
      return errorReply(13, { crealm: ticketPart.crealm, cname: ticketPart.cname,
        realm: answeringRealm, sname: body.sname,
        eText: 'the FORWARDED option needs a FORWARDABLE ticket to forward, and this one is not. ' +
               'An account flagged NOT_DELEGATED ("sensitive and cannot be delegated") is never ' +
               'issued one, which is how that flag protects it from every service at once.' });
    }
    const forwardingClient = principals.find(ticketPart.cname.name, ticketPart.crealm);
    if (forwardingClient && forwardingClient.notDelegated) {
      log.info('krb5: REFUSING to forward — ' + ticketPart.cname.name.join('/') + ' is sensitive');
      return errorReply(13, { crealm: ticketPart.crealm, cname: ticketPart.cname,
        realm: answeringRealm, sname: body.sname,
        eText: ticketPart.cname.name.join('/') + ' is flagged NOT_DELEGATED, so its credentials ' +
               'may not be forwarded. Re-checked here as well as at the AS exchange, because a ' +
               'forwardable ticket issued before the flag was set would otherwise still work.' });
    }
    log.info('krb5: forwarding ' + ticketPart.cname.name.join('/') + '@' + ticketPart.crealm +
      "'s credentials — the ticket issued is flagged `forwarded` and whoever receives it can act " +
      'as that client anywhere, with no further reference to this KDC');
  }

  const wantsRenew = (body.kdcOptions || []).indexOf(msgs.KDC_OPTION.RENEW) !== -1;
  if (wantsRenew) {
    if ((ticketPart.flags || []).indexOf(msgs.TICKET_FLAG.RENEWABLE) === -1) {
      return errorReply(13, { crealm: ticketPart.crealm, cname: ticketPart.cname,
        realm: answeringRealm, sname: body.sname,
        eText: 'the RENEW option was set but this ticket is not renewable. Renewability is asked ' +
               'for when the ticket is FIRST obtained (the RENEWABLE option on the AS-REQ) and ' +
               'cannot be added afterwards.' });
    }
    if (!ticketPart.renewTill) {
      return errorReply(13, { crealm: ticketPart.crealm, cname: ticketPart.cname,
        realm: answeringRealm, sname: body.sname,
        eText: 'the ticket is flagged renewable but carries no renew-till, so there is no limit ' +
               'to renew it up to' });
    }
    if (ticketPart.renewTill <= at) {
      return errorReply(32, { crealm: ticketPart.crealm, cname: ticketPart.cname,
        realm: answeringRealm, sname: body.sname,
        eText: 'renew-till passed at ' + ticketPart.renewTill.toISOString() + '. A renewable ' +
               'ticket can be renewed repeatedly but only up to that instant, which does not ' +
               'move — otherwise it would never expire.' });
    }
    if (body.sname.name.join('/') !== apReq.ticket.sname.name.join('/')) {
      return errorReply(13, { crealm: ticketPart.crealm, cname: ticketPart.cname,
        realm: answeringRealm, sname: body.sname,
        eText: 'a renewal must name the SAME service as the ticket being renewed (' +
               apReq.ticket.sname.name.join('/') + '), not ' + body.sname.name.join('/') });
    }
    log.info('krb5: renewing ' + ticketPart.cname.name.join('/') + '@' + ticketPart.crealm +
      "'s ticket for " + body.sname.name.join('/') + ' — authtime stays at ' +
      ticketPart.authtime.toISOString() + ', capped at renew-till ' +
      ticketPart.renewTill.toISOString());
  }

  // WHO is this ticket for? Ordinarily whoever presented the TGT — but S4U changes it,
  // and the KDC's decision about whether to allow that is the whole of delegation.
  const s4u = await resolveS4u({
    request: request, body: body, ticketPart: ticketPart, service: service,
    answeringRealm: answeringRealm, sessionKey: sessionKey, apReq: apReq
  });
  if (s4u.error) return s4u.error;
  const clientName = s4u.clientName;
  const clientRealm = s4u.clientRealm;

  // Issue. The new ticket inherits the TGT's flags minus `initial` — only the AS
  // exchange issues an initial ticket, and a service may rely on that distinction.
  const inherited = ticketPart.flags.filter(function (f) {
    return f !== msgs.TICKET_FLAG.INITIAL;
  });
  let flags = inherited.slice();
  if (service.okAsDelegate && flags.indexOf(msgs.TICKET_FLAG.OK_AS_DELEGATE) === -1) {
    flags.push(msgs.TICKET_FLAG.OK_AS_DELEGATE);
  }

  if (s4u.mode === 'self') {
    // The flags come from the SERVICE's own configuration, not from the TGT: a ticket out
    // of S4U2Self is forwardable only if the requesting account has
    // TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION. Without it S4U2Self still succeeds and
    // returns a ticket that cannot be used as evidence for classic S4U2Proxy — which
    // then fails several steps later for a reason that looks nothing like this flag.
    flags = flags.filter(function (f) { return f !== msgs.TICKET_FLAG.FORWARDABLE; });
    if (s4u.requester && s4u.requester.trustedToAuthenticateForDelegation) {
      flags.push(msgs.TICKET_FLAG.FORWARDABLE);
    } else {
      log.info('krb5: ' + ticketPart.cname.name.join('/') + ' does not have ' +
        'TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION, so its S4U2Self ticket is NOT forwardable and ' +
        'cannot be used as evidence for classic constrained delegation');
    }
  } else if (s4u.mode === 'proxy' && flags.indexOf(msgs.TICKET_FLAG.FORWARDABLE) === -1) {
    flags.push(msgs.TICKET_FLAG.FORWARDABLE);
  }
  if (wantsForwarded && flags.indexOf(msgs.TICKET_FLAG.FORWARDED) === -1) {
    // The flag is the RECORD that this happened: a service receiving a ticket can see the
    // credentials were forwarded rather than presented by their owner, and can refuse.
    flags.push(msgs.TICKET_FLAG.FORWARDED);
  }

  const newSessionKey = kcrypto.randomBytes(profile.keyBytes);
  const authtime = ticketPart.authtime;
  const requestedTill = body.till && body.till > at ? body.till : kdcTime(TICKET_LIFETIME_SECONDS);
  // A service ticket cannot outlive the TGT that bought it — EXCEPT on a renewal, where
  // the presented ticket's own endtime is the thing being extended and capping against it
  // would make every renewal a no-op. There the cap is renew-till.
  const endtime = wantsRenew
    ? new Date(Math.min(requestedTill.getTime(), ticketPart.renewTill.getTime()))
    : new Date(Math.min(requestedTill.getTime(), ticketPart.endtime.getTime()));

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
      // The IMPERSONATED client under S4U, and the presenter otherwise. This one field
      // is what makes a delegated ticket a delegated ticket: the service that asked is
      // nowhere in it, and the only record that delegation happened at all is the PAC's
      // S4U_DELEGATION_INFO.
      crealm: clientRealm,
      cname: clientName,
      authtime: authtime,
      starttime: at,
      endtime: endtime,
      renewTill: ticketPart.renewTill,
      authorizationData: authorizationData
    });
  };
  // The client's account lives in the realm the TICKET came from, not necessarily in the
  // one being answered — after a referral those differ, and that is the whole point.
  // Under S4U it is the IMPERSONATED user's account, which is the point there.
  const ticketClient = principals.find(clientName.name, clientRealm);
  const crossRealm = clientRealm !== answeringRealm;

  // The delegation audit trail, if this hop is one. It names the target and every service
  // the client has already been delegated through — appended to rather than replaced, so
  // a chain of hops is visible.
  const delegationInfo = s4u.mode === 'proxy' ? {
    s4u2proxyTarget: (body.sname.name || []).join('/'),
    transitedServices: (function () {
      const already = kpac.findPacs(s4u.evidencePart.authorizationData || []);
      let previous = [];
      if (already.length) {
        try {
          const entry = kpac.bufferOfType(kpac.parsePac(already[0].bytes),
            kpac.TYPE.DELEGATION_INFO);
          if (entry && entry.parsed) previous = entry.parsed.transitedServices || [];
        } catch (e) {
          // A malformed delegation buffer must not stop the ticket being issued: the
          // audit trail is evidence, not a gate. Logged so it is not lost.
          log.info('krb5: could not read the evidence ticket\'s delegation info: ' + e.message);
        }
      }
      return previous.concat(s4u.transited);
    })()
  } : null;
  // Whether the TGT itself carries a PAC. A real KDC propagates the client's
  // authorization data from the TGT into the service ticket, so a client that declined
  // a PAC at the AS exchange does not acquire one by asking for a service ticket — and
  // a workflow where unticking the box only affected the TGT would be misleading in a
  // way that is hard to notice, since the TGT is the ticket nobody looks inside.
  const tgtHadPac = kpac.findPacs(ticketPart.authorizationData || []).length > 0;
  let encTicketPart;
  if (s4u.mode === 'proxy') {
    // The user's PAC comes from the EVIDENCE ticket — the requester never had the user's
    // credentials, and this KDC must not invent authorization data for an account on the
    // strength of a service asking nicely. It is re-signed for the target service and the
    // delegation trail is added.
    const carried = kpac.findPacs(s4u.evidencePart.authorizationData || []);
    if (!carried.length) {
      log.info('krb5: the evidence ticket carries no PAC, so the delegated ticket has none either');
      encTicketPart = encodeTicketPart(null);
    } else {
      const placeholder = encodeTicketPart(kpac.wrapPacAsAuthorizationData(new Uint8Array([0])));
      const resigned = await kpac.resignPac(carried[0].bytes, {
        serverKey: { etype: etype, key: serviceKey },
        kdcKey: { etype: etype, key: await principals.longTermKey(krbtgt, etype) },
        includeTicketSignature: !isTgtRequest(body.sname),
        includeExtendedKdcSignature: !isTgtRequest(body.sname),
        ticketBytes: placeholder,
        delegationInfo: delegationInfo
      });
      encTicketPart = encodeTicketPart(kpac.wrapPacAsAuthorizationData(resigned));
    }
  } else if (!tgtHadPac) {
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
      clientRealm: clientRealm,
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

  const s4uNote = s4u.mode === 'none' ? ''
    : ' [S4U2' + s4u.mode + ', requested by ' + ticketPart.cname.name.join('/') +
      (s4u.mode === 'proxy' ? ', via ' + (s4u.classic ? 'classic' : 'resource-based') +
        ' constrained delegation' : '') + ']';
  log.info('krb5: ' + answeringRealm + ' issued a service ticket for ' +
    clientName.name.join('/') + '@' + clientRealm + s4uNote + ' to ' +
    body.sname.name.join('/') + ' using ' + profile.name +
    ', flags [' + msgs.ticketFlagNames(flags).join(', ') + '], enc-part at key usage ' + replyUsage +
    (useSubkey ? ' (the Authenticator carried a subkey)' : ' (no subkey was sent)'));

  // The ticket is named by the client it is FOR, which under S4U is the
  // impersonated user rather than the service that asked — the same distinction
  // the reply itself makes just below, and getting it the other way round here
  // would make the console's session count describe the wrong people.
  stats.recordTicket(isTgtRequest(body.sname) ? 'TGT' : 'service ticket', {
    client: clientName.name.join('/') + '@' + clientRealm,
    realm: answeringRealm,
    service: body.sname.name.join('/'),
    etype: profile.name,
    expiresAt: endtime.getTime()
  });

  // A TGS-REQ presents a TGT rather than a password, so it is an authentication of a
  // different kind and the method says so. **Under S4U it is not an authentication of
  // the named client at all** — the impersonated user presented nothing, a service
  // asked on their behalf — and recording that as if they had signed in would be the
  // one place this console could libel somebody. So the requester is named in the
  // note and the method says which of the three this was.
  // THE SERVICE. A TGS-REP is a ticket FOR a named service principal, which is
  // Kerberos's application identity — the only one in this service that this
  // process may have created on demand (KRB5_SERVICE_DOMAINS). It is recorded
  // here rather than at the AS exchange because an AS-REQ names no service but
  // the krbtgt: a TGT is a ticket for the KDC itself, and filing that as an
  // application would put this service in its own registry.
  applications.seen({
    identifier: body.sname.name.join('/') + '@' + answeringRealm,
    kind: 'kerberos-service',
    protocol: 'Kerberos v5',
    user: clientName.name.join('/') + '@' + clientRealm,
    note: 'a service ticket was issued for this principal',
    fields: { krb5ServicePrincipalName: body.sname.name.join('/') + '@' + answeringRealm }
  });
  stats.recordAuthentication({
    presented: clientName.name.join('/') + '@' + clientRealm,
    protocol: 'Kerberos v5',
    method: s4u.mode === 'none' ? 'TGS-REQ with a TGT (PA-TGS-REQ)'
                                : 'S4U2' + s4u.mode + ' (impersonated; presented nothing)',
    note: s4u.mode === 'none'
      ? 'Asked ' + answeringRealm + ' for ' + body.sname.name.join('/') + '.'
      : 'Requested by ' + ticketPart.cname.name.join('/') + ', which asked for a ticket in this ' +
        'user\'s name. The user was not here.'
  });

  log.debug('Leaving handleTgsReq().');
  return msgs.encKdcRep({
    msgType: msgs.MSG_TYPE.TGS_REP,
    // The reply names the client the TICKET is for, which under S4U is the impersonated
    // user rather than the service that asked. Leaving the requester here would make the
    // reply disagree with the ticket inside it — and a client reads its own identity off
    // the reply, so it would believe it had a ticket for itself.
    crealm: clientRealm,
    cname: clientName,
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
// knows without decrypting anything. It publishes NO keys and no SERVICE
// passwords — only the principals, their supported etypes and their salts, which
// is exactly what a client can already learn from PA-ETYPE-INFO2.
//
// The one exception is `accountPolicy` below: the password every USER account
// shares. That one is not a secret to keep — it is the same for everybody, the
// README states it, and it is the only fact about this KDC a client cannot learn
// from the protocol.
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
      // An account that was not configured but turned up: somebody authenticated as a
      // name nobody registered. Flagged so a reader is not left wondering why the table
      // has entries the documentation does not describe.
      autoCreated: p.autoCreated,
      description: p.description
    };
  });
  log.debug('Leaving GET /krb5/principals. ' + list.length + ' principals.');
  res.status(200).json({
    realm: REALM,
    kdcPort: KDC_PORT,
    clockSkewSeconds: clockSkewSeconds(),
    clockOffsetSeconds: clockOffsetSeconds(),
    ticketLifetimeSeconds: TICKET_LIFETIME_SECONDS,
    // The one thing about this KDC a client cannot discover from the protocol, and the
    // one that stops somebody guessing at passwords: any username authenticates, and
    // they all share one. Publishing it is not the leak it would be elsewhere on this
    // page — a password every account holds and the README states is a POLICY of the
    // mock, not a secret, and a debugger whose accounts are unusable without reading the
    // source is worse than one that says so here.
    accountPolicy: {
      anyUsernameAuthenticates: true,
      userPassword: principals.USER_PASSWORD,
      // The names that are refused instead, so KDC_ERR_C_PRINCIPAL_UNKNOWN stays
      // reachable, plus the shape rule that keeps a missing SPN an error.
      neverCreated: principals.reservedUnknown(),
      // SERVICES are created on first sight too, but only for the hosts this mock
      // is willing to be — a client derives `HTTP/<url host>` and cannot be
      // expected to know this table. Their password is shared and published for
      // the same reason the user one is: it is what lets a debugger open a service
      // ticket's own EncTicketPart and read the PAC inside it, which is the one
      // structure a client can otherwise never see. Configured service accounts
      // keep their own separate passwords.
      serviceHosts: principals.SERVICE_DOMAINS,
      serviceHostRule: 'an SPN\'s host matches when it IS one of serviceHosts ' +
        'or ends with a dot and one of them; anything else stays ' +
        'KDC_ERR_S_PRINCIPAL_UNKNOWN',
      autoServicePassword: principals.AUTO_SERVICE_PASSWORD,
      note: 'A username not in this table is created on first sight as an ordinary user, ' +
            'with the salt Active Directory would use (realm + name) and this password. ' +
            'A multi-component name is a SERVICE, and one is created on first sight too ' +
            'when its host matches serviceHosts above — with autoServicePassword, so a ' +
            'reader can open the ticket. An SPN outside those hosts is still ' +
            'KDC_ERR_S_PRINCIPAL_UNKNOWN, which is how that error stays reachable on ' +
            'purpose (try HTTP/app.elsewhere.invalid). The CONFIGURED service, computer ' +
            'and krbtgt accounts keep their own passwords, which are not published here.'
    },
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
  clockSkewSeconds: clockSkewSeconds
};
