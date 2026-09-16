// ===========================================================================
// A REAL AS EXCHANGE AGAINST THE MOCK KDC, OVER MS-KKDCP.
//
// **THIS IS NOT A TEST. It is the one thing a test cannot get any other way:**
// a Kerberos TGT for a named principal, obtained by doing the exchange rather
// than by asking the console to pretend one happened. `sts_global_logout.js`
// needs it because a TGT is what a Kerberos SESSION IS — the thing a global
// sign-out has to be able to end — and there is no HTTP endpoint that hands one
// out.
//
// ---------------------------------------------------------------------------
// WHY OVER HTTP AND NOT OVER PORT 88.
//
// The KDC answers on raw TCP and UDP 88 and over MS-KKDCP at `POST /KdcProxy`,
// and this uses the third. Two reasons, and the second is the one that decides
// it: the proxy is on the SAME port and the same base URL the rest of the suite
// already talks to, so a job driving it needs no second address, no second
// firewall hole and no knowledge of whether 88 bound at all.
//
// **AND A REALM'S OWN `/realm/<id>/KdcProxy` IS PINNED TO THAT REALM
// (2026-09-15).** This paragraph said *88 is SHARED ACROSS TRUST REALMS while
// the proxy is not*, which was true of the URL and not of the KDC behind it —
// every door reached one principal database. Each trust realm whose
// `krb5.enabled` is on now has a Kerberos realm and a database of its own, so
// port 88 and a bare `/KdcProxy` route by the realm NAME in the request, and
// this address refuses a name the realm does not serve. Driving a throwaway
// realm's KDC therefore means giving that realm a `krb5.realm` of its own,
// turning `krb5.enabled` on, and asking for THAT name.
//
// ---------------------------------------------------------------------------
// THE EXCHANGE, AND THE ONE THING ABOUT IT THAT SURPRISES EVERYBODY.
//
// A KDC does not tell you how to pre-authenticate until you have failed to.
// So it is two round trips and the first one is MEANT to fail:
//
//   1. a bare AS-REQ with no padata -> KRB-ERROR, KDC_ERR_PREAUTH_REQUIRED,
//      carrying an ETYPE-INFO2 in `eDataPaData` that names the salt and the
//      string-to-key parameters;
//   2. the same AS-REQ with a PA-ENC-TIMESTAMP encrypted under the key that
//      salt and those parameters produce -> AS-REP.
//
// Reading the first as a failure is the mistake to avoid: it is the KDC
// telling the client what it needs, and a driver that gave up there would
// report "Kerberos is broken" about a KDC behaving exactly to specification.
//
// THE MODULES ARE THIS SERVICE'S OWN, loaded in process. That is deliberate and
// is the same decision `tests/CLAUDE.md` records for the other in-process jobs:
// what is under test here is the KDC's behaviour over the wire, and
// hand-rolling a second ASN.1 encoder to check the first one would be testing
// the copy.
// ===========================================================================

"use strict";

const paths = require("./module_paths.js");

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'krb5_drive',
  level: process.env.LOG_LEVEL || 'info' });
paths.addTestsModulesToResolutionPath();

const msgs = require(paths.mockStsModule("krb5_messages.js"));
const crypto = require(paths.mockStsModule("krb5_crypto.js"));
const prim = require(paths.mockStsModule("krb5_primitives.js"));
const asn1 = require(paths.mockStsModule("krb5_asn1.js"));

// The KDC's own default, and the one every seeded principal here has a key
// for. Named rather than taken from a preference list, because a driver that
// negotiated would hide the case where the KDC offers something this cannot do.
const ETYPE_NAME = "aes256-cts-hmac-sha1-96";

// **`encKerberosTime()` TAKES A DATE, NOT A STRING**, and this function exists
// to say so once rather than at three call sites. The wire format is
// `YYYYMMDDHHMMSSZ` — UTC, no punctuation, no `T`, no milliseconds — and
// `formatKerberosTime()` inside the encoder produces it. Handing it the
// formatted string instead is refused with `krb5: not a date`, which reads like
// a clock problem and is in fact the wrong TYPE.
function kerberosTime(atMs) {
  log.debug("Entering kerberosTime().");
  log.debug("Leaving kerberosTime().");
  return new Date(atMs);
}

// One MS-KKDCP round trip. RFC 4120's framing over TCP is a four-byte
// big-endian length in front of the message, and MS-KKDCP wraps that same
// framed message in a small ASN.1 envelope — which `krb5_kdc.js` unwraps at
// the other end, so this has to write it.
async function proxy(baseUrl, realm, request) {
  log.debug("Entering proxy().");
  const framed = Buffer.concat([
    Buffer.from([(request.length >>> 24) & 0xff, (request.length >>> 16) & 0xff,
                 (request.length >>> 8) & 0xff, request.length & 0xff]),
    request
  ]);
  // KDC-PROXY-MESSAGE ::= SEQUENCE { kerb-message [0] OCTET STRING, ... }.
  // Built here from the ASN.1 primitives rather than through a helper, because
  // `krb5_messages.js` has none — the KDC's own handler decodes it inline for
  // the same reason, and a helper for one caller on each side would be two
  // places to get one envelope wrong.
  const body = Buffer.from(
    asn1.encSequence([asn1.encContext(0, asn1.encOctetString(framed))]));
  const r = await fetch(baseUrl + "/KdcProxy", {
    method: "POST",
    headers: { "Content-Type": "application/kerberos" },
    body: body
  });
  const raw = Buffer.from(await r.arrayBuffer());
  if (r.status !== 200) {
    throw new Error("the KDC proxy answered " + r.status + ": " +
                    raw.toString("utf8").slice(0, 300));
  }
  const outer = asn1.readTlv(prim.toBytes(raw), 0);
  const fields = asn1.readTaggedSequence(outer.value);
  const unwrapped = asn1.decOctetString(fields[0]);
  log.debug("Leaving proxy().");
  // Strip the four-byte length the TCP framing put in front on the way back.
  return Buffer.from(unwrapped.subarray(4));
}

function asReq(realm, username, padata) {
  log.debug("Entering asReq().");
  const now = Date.now();
  log.debug("Leaving asReq().");
  return msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.AS_REQ,
    padata: padata || [],
    reqBody: {
      // A LIST OF BIT NUMBERS and not an object of flags — `encFlags()` takes
      // the numbers, and an object here fails as `(bitNumbers || []).forEach
      // is not a function`, which names neither the field nor the shape.
      kdcOptions: [msgs.KDC_OPTION.FORWARDABLE, msgs.KDC_OPTION.PROXIABLE,
                   msgs.KDC_OPTION.RENEWABLE],
      cname: { type: msgs.NAME_TYPE.PRINCIPAL, name: [username] },
      realm: realm,
      sname: { type: msgs.NAME_TYPE.SRV_INST, name: ["krbtgt", realm] },
      till: kerberosTime(now + 8 * 3600 * 1000),
      rtime: kerberosTime(now + 24 * 3600 * 1000),
      // The nonce is the client's own and is echoed back; it is not a
      // challenge and nothing here checks it.
      nonce: Math.floor(Math.random() * 0x7fffffff),
      // `etypes`, plural. The singular is silently ignored by the encoder and
      // produces a request offering no encryption type at all, which the KDC
      // answers with KDC_ERR_ETYPE_NOSUPP — an error about the KDC for a
      // mistake in the client.
      etypes: [crypto.etypeByName(ETYPE_NAME).id]
    }
  });
}

// ---------------------------------------------------------------------------
// A TGT for `username`, by doing the exchange. Returns what the caller needs to
// say something about it afterwards — the AS-REP, and the fact that it worked —
// rather than a decoded ticket, because nothing that uses this needs to present
// the ticket anywhere: what it needs is for the KDC to have ISSUED one, so that
// the console has a Kerberos session to end.
// ---------------------------------------------------------------------------
async function getTgt(baseUrl, realm, username, password) {
  log.debug("Entering getTgt().");
  const etype = crypto.etypeByName(ETYPE_NAME);

  // 1. The bare request, which is MEANT to be refused. `readKdcResponse()`
  //    answers a DISCRIMINATED UNION — `{kind, error}` or `{kind, rep}` — and
  //    not a message with a `msgType` on it, which is the shape to expect here
  //    and the one most likely to be guessed wrong.
  const bare = await proxy(baseUrl, realm, asReq(realm, username, []));
  const first = msgs.readKdcResponse(bare);
  if (first.kind !== "KRB-ERROR") {
    log.debug("Leaving getTgt().");
    // A KDC configured to require no pre-authentication. Not an error — the
    // seeded `noreauth` principal is exactly this — so it is answered rather
    // than treated as a surprise.
    return { ok: true, preauthRequired: false, asRep: first.rep };
  }

  // 2. What it wants: the salt and the string-to-key parameters for our etype.
  //    `eDataPaData` is a LIST OF PA-DATA and not the ETYPE-INFO2 itself — the
  //    KDC may name several pre-authentication mechanisms and this picks the
  //    one it can do. Handing the list straight to readEtypeInfo2() decodes the
  //    first entry's envelope as though it were the payload and finds nothing,
  //    which is a silent wrong answer rather than a throw.
  const err = first.error || {};
  const entry = (err.eDataPaData || []).filter(function (pa) {
    return pa.type === msgs.PA_TYPE.ETYPE_INFO2;
  })[0];
  if (!entry) {
    throw new Error("the KDC required pre-authentication and named no " +
                    "ETYPE-INFO2, so there is nothing to derive a key from. " +
                    "Error " + ((err.error || {}).code) + " " +
                    ((err.error || {}).name || "") +
                    (err.eDataNote ? " — " + err.eDataNote : "") +
                    ". It offered: " +
                    (err.eDataPaData || []).map(function (pa) {
                      return pa.type;
                    }).join(", "));
  }
  const info = msgs.readEtypeInfo2(entry.value);
  const chosen = (info || []).filter(function (one) {
    return one.etype === etype.id;
  })[0] || (info || [])[0];
  if (!chosen) {
    throw new Error("the ETYPE-INFO2 named no encryption type this driver " +
                    "can do. It offered: " + (info || []).map(function (one) {
                      return one.etypeName;
                    }).join(", "));
  }
  // **BOTH CRYPTO CALLS ARE ASYNCHRONOUS AND NEITHER LOOKS IT.**
  // `krb5_crypto.js` is built on WebCrypto, so `stringToKey()` and `encrypt()`
  // return promises — and a caller that forgets returns a Promise where bytes
  // are expected, failing much later as `krb5: expected bytes, got object` from
  // inside `importAesKey()`, which names neither call.
  const key = await etype.stringToKey(
      password, prim.utf8(chosen.salt || (realm + username)), chosen.s2kparams);

  // 3. The same request, with the timestamp encrypted under that key. Key
  //    usage 1 is RFC 4120's for PA-ENC-TIMESTAMP and is not negotiable.
  // POSITIONAL, not an object: `encPaEncTsEnc(when, usec)`. An object argument
  // is accepted silently and encodes a timestamp of `undefined`.
  const stamp = msgs.encPaEncTsEnc(kerberosTime(Date.now()), 0);
  // Key usage 1 below is RFC 4120's for PA-ENC-TIMESTAMP and is not negotiable.
  const sealed = await etype.encrypt(key, 1, stamp);
  const padata = [{ type: msgs.PA_TYPE.ENC_TIMESTAMP,
                    value: msgs.encEncryptedData({ etype: etype.id,
                                                   cipher: sealed }) }];
  const second = await proxy(baseUrl, realm, asReq(realm, username, padata));
  const reply = msgs.readKdcResponse(second);
  if (reply.kind === "KRB-ERROR") {
    const e = reply.error || {};
    throw new Error("the pre-authenticated AS-REQ was refused: " +
                    ((e.error || {}).code) + " " +
                    ((e.error || {}).name || "") +
                    " " + (e.eText || ""));
  }
  log.debug("Leaving getTgt().");
  return { ok: true, preauthRequired: true, asRep: reply.rep };
}

module.exports = { getTgt: getTgt, kerberosTime: kerberosTime,
                   ETYPE_NAME: ETYPE_NAME };
