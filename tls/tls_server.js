'use strict';
//
// File: tls_server.js
//
// ---------------------------------------------------------------------------
// TWO HTTPS LISTENERS WHOSE ONLY CONTENT IS WHAT THE SERVER SAW.
//
// Everything else in this service is HTTP behind the one plain listener in
// server.js. This is not: it is TLS, so it is its own socket — a third one
// beside the KDC's port 88 and the directory's 389 — and it has the same
// consequences those two have. `GET /sts-metadata` is built by walking the
// Express router, so it cannot see a socket; the two rows it carries for this
// module are the plain-HTTP views below, and the listeners themselves are
// described in their text.
//
// ---------------------------------------------------------------------------
// WHY IT EXISTS, GIVEN THAT THE DEBUGGER ALREADY REPORTS THE HANDSHAKE.
//
// The parent project's PKI page builds a certificate authority in the browser —
// a Root, an Intermediate, an Issuing CA — issues a client certificate from it,
// and then has to find out whether anything on earth accepts the thing. Its api
// opens the socket and reports the handshake, because a browser cannot choose a
// client certificate, cannot be given a truststore and cannot read the
// negotiated version, cipher or chain.
//
// But that report is ONE SIDE of the exchange, and it is the side that already
// knows what it sent. What it cannot say is what the SERVER made of the
// certificate: which chain the server built out of what arrived, which anchor it
// verified against, what it read out of the leaf, and whether it considers the
// caller authenticated at all. A client that completed a handshake has proved
// that the bytes were acceptable to OpenSSL on this machine, and no more. Under
// TLS 1.3 it has not even proved that — the client is finished before the server
// has said anything about the certificate.
//
// So this is the other side, and the whole of its content is that answer: a
// message, and three sections saying what arrived over HTTPS, what was
// negotiated at the TLS layer, and what the client certificate is. Fetch
// `/tls/whoami` over one of these listeners and the reply describes the very
// connection it is travelling on.
//
// ---------------------------------------------------------------------------
// TWO LISTENERS, BECAUSE "DOES THIS SERVER REQUIRE A CERTIFICATE" HAS TWO
// ANSWERS AND BOTH ARE WORTH BEING ABLE TO REACH.
//
//   * STS_TLS_PORT (8443) always ASKS for a client certificate and accepts
//     whatever arrives, including nothing: `requestCert: true,
//     rejectUnauthorized: false`. Every connection is answered and the answer
//     says whether the certificate verified. This is the listener to point a
//     debugger at, because a refusal at the TLS layer tells you almost nothing —
//     node's own TLS server refuses a client certificate by closing the socket
//     with no alert at all — while this one can tell you which check failed.
//
//   * STS_MTLS_PORT (9443) REQUIRES one: `rejectUnauthorized: true`, so node
//     refuses the connection itself and no handler here ever runs. That is not
//     redundancy — it is what makes the debugger's five mutual-authentication
//     verdicts reachable against a real server rather than against a fixture.
//     With the issuing CA trusted here the verdict is `required`; before it is
//     trusted the verdict is `required-and-rejected`, which is the case an
//     operator hits most and the one a single connection cannot tell from the
//     first.
//
// Reaching the second listener at all is therefore the proof: if this page came
// back from 9443, the certificate verified.
//
// ---------------------------------------------------------------------------
// THE TRUSTSTORE IS EMPTY AT STARTUP AND IS FILLED AT RUNTIME.
//
// It has to be. The certificate authority whose clients this is meant to verify
// is generated in somebody's BROWSER, thirty seconds before the connection, and
// exists nowhere else — so there is no configuration file that could hold it and
// no image that could bake it in. `POST /tls/trust` takes the anchors and
// `tls.Server.setSecureContext()` applies them; existing connections are not
// disturbed, and the next handshake is judged against the new list.
//
// Two details about that are load-bearing and both were measured rather than
// assumed:
//
//   * `ca: []` means NO ANCHORS. It is not the same as omitting `ca`, which
//     selects node's bundled root store — the opposite of what is wanted here,
//     since a public root has no business verifying a client certificate issued
//     by a private CA. So the empty case is passed explicitly, and with it every
//     client certificate is unverified: on 8443 that is reported, and on 9443 it
//     means nothing can connect. That is the correct starting state and the
//     `/tls` page says so.
//   * the anchors go in over the MAIN port, not over 8443 or 9443. That port is
//     normally plain HTTP, which is the one reachable before anything is
//     trusted, and this is a mock: an endpoint that could only be called by
//     somebody who had already been trusted would be a chicken-and-egg with a
//     specification citation.
//
//     `global.https` — which RFC 9700 mode turns on — takes that property away,
//     and it is worth knowing rather than discovering: with it on there is no
//     plain listener in this process at all, so the FIRST fetch of
//     /tls/server-certificate and the first POST to /tls/trust have to be made
//     without verifying the certificate (`curl -k`). That is the ordinary
//     bootstrap for a certificate regenerated on every start — it is the same
//     act as trusting the PEM this endpoint hands back, done a step earlier —
//     and `mainPortPhrase()` below is what keeps every page in this module from
//     claiming a plain port that is not there.
//
// ---------------------------------------------------------------------------
// AND IT AUTHENTICATES NOBODY, like the rest of this service.
//
// A verified client certificate here means one thing exactly: a chain was built
// from what the client sent to an anchor somebody POSTed to this process. It is
// not a login, no session is started, no token is issued, and nothing else in
// this service consults it. Saying so is the point — a mock that quietly turned
// a certificate into an identity would teach a client something false about
// every server it will meet afterwards.
// ---------------------------------------------------------------------------

const https = require('https');
const tls = require('tls');
const crypto = require('crypto');
const forge = require('node-forge');
const app = require('../common/app');
const helpers = require('../common/helpers');
const { log, xmlEscape, parseBody, baseUrlOf } = helpers;
// The single funnel every authentication in this service passes through at the
// moment a credential is ACCEPTED. A verified client certificate is one, and
// going through here rather than writing to the console and the directory
// directly is what keeps it one call site and not three — see the note above
// recordClientCertificate().
const stats = require('../common/admin_stats');
const config = require('../common/config');

// The permissive listener: always asks, never refuses, always explains.
const TLS_PORT = config.value('tls.port');
// The strict one: node refuses an unverified client certificate during the
// handshake, so nothing below ever runs for one.
const MTLS_PORT = config.value('tls.mutualPort');

// The names the server certificate is issued for. A caller reaches this stack
// as `localhost` from a host run, as `sts` from the compose network and as
// `127.0.0.1` from whatever is easiest, and a certificate that named only one of
// them would produce a hostname-verification failure that is about this file
// rather than about anything the reader is debugging.
const TLS_HOSTNAMES = config.value('tls.hostnames');
const TLS_IPS = config.value('tls.ips');

// A truststore is a list of anchors, not a certificate store dump. The cap is
// generous for any private PKI and stops a caller handing over a body that costs
// more to parse than the handshakes it will be used for.
const MAX_ANCHORS = 32;

// State the two listeners share.
let anchors = [];
let boundTlsPort = null;
let boundMtlsPort = null;
let tlsListening = false;
let mtlsListening = false;
let listenError = null;

// ---------------------------------------------------------------------------
// The server certificate.
//
// Self-signed and generated per start, exactly like the signing key in
// helpers.js, and for the same reason: nothing about a mock is worth persisting,
// and a certificate committed to a repository is a private key committed to a
// repository. The consequence for a caller is that the anchor changes on every
// restart, which is why `GET /tls/server-certificate` exists — a debugger
// fetches it and puts it in its own truststore, rather than being told to
// disable verification, which is the habit this whole workflow is trying to
// break.
// ---------------------------------------------------------------------------
function makeServerCertificate() {
  log.debug('Entering makeServerCertificate().');
  const kp = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = kp.publicKey;
  cert.serialNumber = '03';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(
      cert.validity.notBefore.getFullYear() + 2);
  const attrs = [{ name: 'commonName', value: TLS_HOSTNAMES[0] || 'localhost' },
                 { name: 'organizationName', value: 'mock-sts' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  // altNames type 2 is dNSName and type 7 is iPAddress. The CN is ignored by
  // every current client — RFC 6125 has said so since 2011 and browsers stopped
  // reading it years ago — so the subjectAltName is not decoration here, it is
  // the only place the names are.
  const altNames = TLS_HOSTNAMES.map(function (name) {
    return { type: 2, value: name };
  }).concat(TLS_IPS.map(function (address) {
    return { type: 7, ip: address };
  }));
  cert.setExtensions([
    { name: 'basicConstraints', cA: false, critical: true },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true,
      critical: true },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectAltName', altNames: altNames }
  ]);
  cert.sign(kp.privateKey, forge.md.sha256.create());
  const pem = forge.pki.certificateToPem(cert);
  log.debug('Leaving makeServerCertificate(). names=' +
            TLS_HOSTNAMES.concat(TLS_IPS).join(', '));
  return {
    privateKeyPem: forge.pki.privateKeyToPem(kp.privateKey),
    certPem: pem,
    subject: 'CN=' + (TLS_HOSTNAMES[0] || 'localhost') + ', O=mock-sts',
    names: TLS_HOSTNAMES.concat(TLS_IPS),
    fingerprint256: fingerprintOf(pem),
    notAfter: cert.validity.notAfter.toISOString()
  };
}

// SHA-256 over the DER, rendered the way every tool renders it, so that what
// this page prints can be compared with `openssl x509 -fingerprint -sha256`
// without anybody having to reformat it.
// What to CALL the port these views answer on. It is the plain HTTP port unless
// `global.https` has made it TLS as well, and seven sentences in this module
// used to say "the plain HTTP port" outright — each of them correct until the
// day somebody turned that setting on, and then quietly wrong in the one place
// a reader goes when a handshake is failing. Read per call rather than captured:
// the setting is restart-only, but a captured const here would be a second
// thing to remember if that ever changed.
function mainPortPhrase() {
  return config.value('global.https')
    ? 'the main HTTPS port' : 'the plain HTTP port';
}

// The extra sentence a bootstrap instruction needs when there is no plain port
// left to bootstrap from. Empty in the ordinary case, so it can be appended
// unconditionally.
function bootstrapNote() {
  return config.value('global.https')
    ? ' That port is HTTPS too (global.https), so the first fetch has to be ' +
      'made without verifying the certificate — curl -k, or its equivalent — ' +
      'since this is where the certificate to verify with comes from.'
    : '';
}

function fingerprintOf(pem) {
  const der = Buffer.from(String(pem)
      .replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
  const hex = crypto.createHash('sha256').update(der).digest('hex')
      .toUpperCase();
  return (hex.match(/.{2}/g) || []).join(':');
}

const SERVER_CERTIFICATE = makeServerCertificate();

// ---------------------------------------------------------------------------
// ONE CERTIFICATE FOR EVERY TLS SOCKET IN THIS PROCESS.
//
// ldap_server.js's LDAPS listener on 636 serves this same certificate and key,
// read through serverCertificate() below rather than generating a second pair.
// That is a decision about what a CALLER has to do rather than a saving of one
// keypair: this certificate is self-signed and regenerated on every start, so
// anybody who wants to verify this service has to fetch it and trust it — and
// one anchor covering 8443, 9443 and 636 is one fetch. Two keypairs would mean
// an `ldapsearch` that verifies perfectly well against a truststore built for
// the HTTPS ports failing with `unable to get local issuer certificate`, which
// names nothing and reads as a broken directory.
//
// The names are the other half of why one certificate works for both: they are
// in the subjectAltName (see above — the CN is ignored by every current client)
// and they are the names this stack is reached at, not names about HTTPS.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// The client truststore.
// ---------------------------------------------------------------------------

// A truststore is nearly always pasted as a bundle, and node's `ca` option takes
// an array — handing it the bundle as one string works on some node versions and
// silently uses only the first certificate on others, which reads as "the root I
// added is not trusted".
function splitPemCertificates(text) {
  const matches = String(text || '').match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  return matches || [];
}

function describePem(pem) {
  log.debug('Entering describePem().');
  let subject = '(unreadable)';
  try {
    const cert = forge.pki.certificateFromPem(pem);
    subject = cert.subject.attributes.map(function (attribute) {
      return (attribute.shortName || attribute.name) + '=' + attribute.value;
    }).join(', ');
  } catch (e) {
    // Not a certificate this parser can read. It is still handed to OpenSSL as
    // an anchor — forge and OpenSSL do not accept exactly the same set, and
    // refusing here on forge's opinion would reject anchors that work. The
    // subject is a label on a page, not a check.
    log.warn('tls: an anchor could not be parsed for display: ' + e.message);
  }
  log.debug('Leaving describePem(). subject=' + subject);
  return { pem: pem, subject: subject, fingerprint256: fingerprintOf(pem) };
}

// The `ca` half of the secure context. See the header: the empty case is passed
// EXPLICITLY as an empty array, because omitting `ca` selects node's bundled
// root store — which would mean a client certificate chaining to a public CA
// verified here, a chain nobody asked about.
function secureContextOptions() {
  log.debug('Entering secureContextOptions(). anchors=' + anchors.length);
  log.debug('Leaving secureContextOptions().');
  return {
    key: SERVER_CERTIFICATE.privateKeyPem,
    cert: SERVER_CERTIFICATE.certPem,
    ca: anchors.map(function (anchor) { return anchor.pem; })
  };
}

// Apply the current anchors to both listeners. Existing connections keep the
// context they were made under — node says so and it is the behaviour worth
// having, since a connection judged under one truststore should not silently
// change its mind halfway through.
function applyAnchors() {
  log.debug('Entering applyAnchors(). anchors=' + anchors.length);
  [permissiveServer, strictServer].forEach(function (server) {
    try {
      server.setSecureContext(secureContextOptions());
    } catch (e) {
      // Reported rather than thrown: the caller is a route, and a truststore
      // that could not be applied must not take the service down with it. The
      // anchors are already recorded, so the page and ?format=json will show
      // them while the listener has not got them — which is exactly the state
      // this message is here to make visible.
      log.error('tls: the truststore could not be applied to a listener: ' +
                e.message);
    }
  });
  log.debug('Leaving applyAnchors().');
}

function addAnchors(text) {
  log.debug('Entering addAnchors().');
  const found = splitPemCertificates(text);
  if (!found.length) {
    log.debug('Leaving addAnchors(). Nothing that looks like a certificate.');
    return { added: 0, total: anchors.length, error:
      'No PEM certificate was found in the body. Send one or more ' +
      '-----BEGIN CERTIFICATE----- blocks, as raw text or as the ' +
      '`certificates` field of a form or JSON body.' };
  }
  let added = 0;
  let duplicates = 0;
  for (const pem of found) {
    if (anchors.length >= MAX_ANCHORS) {
      log.debug('Leaving addAnchors(). The truststore is full.');
      return { added: added, total: anchors.length, error:
        'This truststore holds at most ' + MAX_ANCHORS + ' anchors; ' + added +
        ' were added before it filled up. POST /tls/trust/clear to empty it.' };
    }
    const described = describePem(pem);
    const already = anchors.some(function (anchor) {
      return anchor.fingerprint256 === described.fingerprint256;
    });
    if (already) {
      duplicates += 1;
      continue;
    }
    anchors.push(described);
    added += 1;
    log.info('tls: trusting client certificates issued by ' +
             described.subject + ' (' + described.fingerprint256 + ')');
  }
  if (added) applyAnchors();
  log.debug('Leaving addAnchors(). added=' + added + ' duplicates=' +
            duplicates);
  return { added: added, duplicates: duplicates, total: anchors.length };
}

function clearAnchors() {
  log.debug('Entering clearAnchors(). anchors=' + anchors.length);
  const removed = anchors.length;
  anchors = [];
  applyAnchors();
  log.info('tls: the client truststore was emptied; ' + removed +
           ' anchor(s) removed. Every client certificate is unverified again, ' +
           'and nothing can connect to the listener on ' + MTLS_PORT + '.');
  log.debug('Leaving clearAnchors().');
  return { removed: removed, total: 0 };
}

// ---------------------------------------------------------------------------
// Describing one connection.
// ---------------------------------------------------------------------------

// node hands a certificate's subject back as an object of arrays. Render it as
// the one-line DN everybody recognises, because that is the form a reader will
// compare with what their own tool printed.
function dnToString(dn) {
  if (!dn || typeof dn !== 'object') return String(dn || '');
  return Object.keys(dn).map(function (key) {
    const value = dn[key];
    return key + '=' + (Array.isArray(value) ? value.join('+') : value);
  }).join(', ');
}

// The SAME subject in RFC 4514 form, which is a different string and has to be.
//
// dnToString() above renders what a reader's own tool prints: node hands the
// subject back most-significant-first (`C=US, O=Example, CN=alice`) and openssl
// x509 -subject shows it that way too. A DN as LDAP writes it is the REVERSE,
// leaf first and with no spaces after the commas, and that is the form this
// service files the identity under and the directory builds an entry from.
//
// **THE FUNCTION ITSELF NOW LIVES IN `common/helpers.js`** and is re-exported
// from here unchanged, because the string has FOUR producers rather than two
// and two spellings of one DN is two people on /admin/users. `scim_auth.js`
// and `spiffe_auth.js` require this module for it and still may; `spiffe_ca.js`
// cannot — `admin.js` requires that module and is required BEFORE this one, so
// the require would move every `/tls*` route ahead of the console's — and it
// needs the same spelling for a certificate it has just MINTED. The header in
// `helpers.js` carries the whole argument, including the second shape of DN it
// learnt in order to serve that caller.
const dnRfc4514 = helpers.dnRfc4514;

// The address in a certificate, if it carries one: the emailAddress RDN, or the
// first rfc822Name in the subjectAltName. Read rather than invented, because the
// directory entry this ends up on is derived from the certificate and an address
// the certificate does not carry would be this service making one up.
function emailOf(cert) {
  if (!cert) return '';
  const subject = cert.subject || {};
  const fromDn = subject.emailAddress || subject.E || '';
  if (fromDn) {
    return String(Array.isArray(fromDn) ? fromDn[0] : fromDn);
  }
  const san = String(cert.subjectaltname || '');
  const match = san.match(/email:([^,]+)/i);
  return match ? match[1].trim() : '';
}

function describeCertificate(cert, depth) {
  log.debug('Entering describeCertificate(). depth=' + depth);
  if (!cert || !Object.keys(cert).length) {
    log.debug('Leaving describeCertificate(). Nothing was presented.');
    return null;
  }
  const out = {
    depth: depth,
    subject: dnToString(cert.subject),
    issuer: dnToString(cert.issuer),
    serialNumber: cert.serialNumber || null,
    validFrom: cert.valid_from || null,
    validTo: cert.valid_to || null,
    subjectAltName: cert.subjectaltname || null,
    extendedKeyUsage: cert.ext_key_usage || null,
    keySize: cert.bits || null,
    curve: cert.nistCurve || cert.asn1Curve || null,
    fingerprint256: cert.fingerprint256 || null,
    pem: cert.raw
      ? '-----BEGIN CERTIFICATE-----\n' +
        (cert.raw.toString('base64').match(/.{1,64}/g) || []).join('\n') +
        '\n-----END CERTIFICATE-----\n'
      : null
  };
  log.debug('Leaving describeCertificate(). subject=' + out.subject);
  return out;
}

// Walk the chain as OpenSSL assembled it, leaf first. `issuerCertificate` is a
// self-reference at the end of the walk, which is what stops it; the loop is
// additionally bounded, because the shape of that structure is decided by
// somebody else's bytes.
//
// Note precisely whose certificates these are, because the obvious reading is
// wrong in a way that matters here: this is the path that was BUILT, not the
// bytes that arrived. When verification succeeds the last entry is the anchor
// this service holds — which the client did not send and, for a root, must not
// have. So a chain of three from a client that sent two is the normal, correct
// case, and the report says so rather than letting a reader count the rows as
// "what I sent".
function chainOf(socket) {
  log.debug('Entering chainOf().');
  const out = [];
  const seen = new Set();
  let cert = socket.getPeerCertificate(true);
  let depth = 0;
  while (cert && Object.keys(cert).length && depth < 10) {
    const fingerprint = cert.fingerprint256 || String(depth);
    if (seen.has(fingerprint)) break;
    seen.add(fingerprint);
    out.push(describeCertificate(cert, depth));
    if (!cert.issuerCertificate || cert.issuerCertificate === cert) break;
    cert = cert.issuerCertificate;
    depth += 1;
  }
  log.debug('Leaving chainOf(). ' + out.length + ' certificate(s).');
  return out;
}

// The sentence that says what this connection actually proved. It is the one
// piece of prose here that draws a conclusion rather than reporting a fact, so
// it states what it is concluding from.
function verdictFor(mode, presented, authorized, authorizationError) {
  log.debug('Entering verdictFor(). mode=' + mode);
  let verdict;
  if (mode === 'required') {
    verdict = 'You are reading this from the listener that REQUIRES a client ' +
      'certificate, so the handshake could not have completed unless the ' +
      'certificate verified against an anchor this service holds. Reaching ' +
      'this page at all is the proof; the chain below is what was built. The ' +
      'subject DN was recorded as an authentication when that handshake ' +
      'completed — see below for what that does and does not mean.';
  } else if (!presented) {
    verdict = 'This listener asked for a client certificate and none was ' +
      'presented. It answered anyway — never refusing is what makes it useful ' +
      'for debugging — so this exchange proves the server certificate and the ' +
      'transport, and says nothing whatever about client authentication. ' +
      'Present one, or use port ' + MTLS_PORT + ', which will not answer ' +
      'without it.';
  } else if (authorized) {
    verdict = 'A client certificate was presented and it VERIFIED against ' +
      anchors.length + ' anchor(s) this service was given at runtime. That is ' +
      'the whole of what it PROVED: a chain was built from what you sent to ' +
      'something somebody POSTed to /tls/trust. No session was started and no ' +
      'token was issued. It was, however, written down — the subject DN is now ' +
      'an identity in the admin console and an entry in this service\'s LDAP ' +
      'directory, which is a record of what happened and not a credential.';
  } else {
    verdict = 'A client certificate was presented and it did NOT verify: ' +
      (authorizationError || 'no reason was given') + '. The connection ' +
      'completed regardless, because this listener never refuses one — which ' +
      'is exactly why it can tell you why. On port ' + MTLS_PORT + ' the same ' +
      'certificate is refused during the handshake, and node refuses it by ' +
      'closing the socket with no alert at all, so the far end learns nothing. ' +
      (anchors.length
        ? 'This truststore holds ' + anchors.length + ' anchor(s); the issuing ' +
          'CA is evidently not one of them.'
        : 'This truststore is EMPTY — nothing has been POSTed to /tls/trust — ' +
          'so no client certificate can verify here yet.');
  }
  log.debug('Leaving verdictFor().');
  return verdict;
}

function describeConnection(req, mode) {
  log.debug('Entering describeConnection(). mode=' + mode);
  const socket = req.socket;
  const cipher = socket.getCipher ? (socket.getCipher() || {}) : {};
  const chain = chainOf(socket);
  const leaf = chain.length ? chain[0] : null;
  const presented = !!leaf;
  const authorized = socket.authorized === true;
  // The leaf's subject as a DN, computed ONCE. It is the string this service
  // filed the identity under when the handshake completed, so it appears in two
  // places below and in a link; reading the peer certificate again for each of
  // them would be three chances to disagree with the chain the report is
  // otherwise built from.
  const subjectDn = presented ? dnRfc4514(socket.getPeerCertificate().subject)
                              : null;
  const authorizationError = socket.authorizationError
    ? String(socket.authorizationError) : null;
  let ephemeral = null;
  try {
    ephemeral = socket.getEphemeralKeyInfo ? socket.getEphemeralKeyInfo()
      : null;
  } catch (e) {
    // Not available on every negotiation, and it is a detail rather than the
    // point of the page. Recorded so its absence is not read as an omission.
    log.debug('describeConnection(): no ephemeral key info: ' + e.message);
  }
  const report = {
    service: 'mock-sts',
    message: 'This is what the server saw. Everything below describes the ' +
      'very connection this response is travelling on — the HTTPS request as ' +
      'it arrived, what TLS negotiated underneath it, and the client ' +
      'certificate, if any, exactly as it was presented.',
    receivedAt: new Date().toISOString(),
    https: {
      method: req.method,
      url: req.url,
      httpVersion: req.httpVersion,
      host: req.headers.host || null,
      userAgent: req.headers['user-agent'] || null,
      // Every header, with nothing removed. This mock issues test credentials
      // only and the point of it is to show exactly what was exchanged.
      headers: Object.assign({}, req.headers),
      remoteAddress: socket.remoteAddress || null,
      remotePort: socket.remotePort || null,
      localPort: socket.localPort || null,
      secure: true
    },
    tls: {
      listener: mode,
      listenerPort: mode === 'required' ? boundMtlsPort : boundTlsPort,
      clientCertificatePolicy: mode === 'required'
        ? 'requestCert: true, rejectUnauthorized: true — a certificate that ' +
          'does not verify is refused during the handshake and no request is ' +
          'ever read'
        : 'requestCert: true, rejectUnauthorized: false — a certificate is ' +
          'always asked for, whatever arrives is accepted, and the verdict is ' +
          'reported rather than enforced',
      protocol: socket.getProtocol ? socket.getProtocol() : null,
      cipher: { name: cipher.name || null,
                standardName: cipher.standardName || null,
                version: cipher.version || null },
      // The name in the ClientHello, which is what a virtual host would route
      // on and what hostname verification is done against. Null means the
      // client sent none — every client dialling by IP address does.
      sniServername: socket.servername || null,
      alpnProtocol: socket.alpnProtocol || null,
      sessionReused: typeof socket.isSessionReused === 'function'
        ? socket.isSessionReused() : null,
      ephemeralKey: ephemeral || null,
      serverCertificate: {
        subject: SERVER_CERTIFICATE.subject,
        names: SERVER_CERTIFICATE.names,
        fingerprint256: SERVER_CERTIFICATE.fingerprint256,
        notAfter: SERVER_CERTIFICATE.notAfter,
        selfSigned: true,
        note: 'Self-signed and regenerated on every start, so it is an anchor ' +
          'nobody can have baked in. GET /tls/server-certificate over ' +
          mainPortPhrase() + ' for the PEM, and put it in your truststore ' +
          'rather than switching verification off.' + bootstrapNote()
      }
    },
    clientCertificate: {
      presented: presented,
      authorized: authorized,
      authorizationError: authorizationError,
      // The chain OpenSSL BUILT, leaf first — not a count of what arrived. Its
      // last entry is the anchor this service holds whenever verification
      // succeeded, and that certificate came from here rather than from the
      // client. What the difference is for: a leaf presented without its
      // intermediates is the commonest mutual-TLS mistake there is and is
      // invisible from the client, and it shows here as a chain of one that
      // did not verify.
      chainLength: chain.length,
      chainNote: 'the path as it was assembled, leaf first. When verification ' +
        'succeeded the last entry is an anchor this service holds — the client ' +
        'did not send it, and for a root it must not: a server that does not ' +
        'already hold a root will not trust it because somebody offered it.',
      chain: chain,
      subject: leaf ? leaf.subject : null,
      // The same subject as a DIRECTORY writes it: leaf first, no spaces after
      // the commas, values escaped. It is here because it is the exact string
      // this service filed the identity under — /admin/users?user=<this> is the
      // page for it — and because the difference between the two forms is worth
      // seeing side by side rather than discovering. See dnRfc4514().
      subjectRfc4514: subjectDn,
      issuer: leaf ? leaf.issuer : null,
      serialNumber: leaf ? leaf.serialNumber : null,
      validFrom: leaf ? leaf.validFrom : null,
      validTo: leaf ? leaf.validTo : null,
      subjectAltName: leaf ? leaf.subjectAltName : null,
      extendedKeyUsage: leaf ? leaf.extendedKeyUsage : null,
      fingerprint256: leaf ? leaf.fingerprint256 : null
    },
    truststore: {
      anchors: anchors.length,
      subjects: anchors.map(function (anchor) { return anchor.subject; }),
      note: 'The anchors this service verifies CLIENT certificates against. ' +
        'They are POSTed to /tls/trust at runtime over ' + mainPortPhrase() +
        ', because the CA in question is usually generated in a browser ' +
        'minutes before the connection and exists nowhere else.' +
        bootstrapNote()
    },
    authentication: {
      // Still false, and it is the most important false in this report: a
      // verified certificate is not a login here and no endpoint of this
      // service will let its holder do anything an anonymous caller cannot.
      authenticated: false,
      // What DID happen, when the certificate verified: the subject DN was
      // filed as an authentication. Recorded and not authenticated — the
      // distinction the rest of this page exists to keep.
      recorded: presented && authorized,
      identity: presented && authorized ? subjectDn : null,
      consoleUrl: presented && authorized
        ? '/admin/users?user=' + encodeURIComponent(subjectDn) : null,
      directoryUrl: presented && authorized ? '/ldap/directory' : null,
      note: 'Nothing here is a login. A verified client certificate means a ' +
        'chain was built to an anchor somebody supplied, and no more: no ' +
        'session is started, no token is issued, no revocation is checked, and ' +
        'no endpoint of this service will let you do anything an anonymous ' +
        'caller cannot. What a verified certificate DOES do is get written ' +
        'down. The subject DN is filed as an authentication on /admin/users, ' +
        'and the embedded LDAP directory seeds an entry for it — a certificate ' +
        'subject is already a DN, so it is the one identity here that does not ' +
        'have to be turned into one. Both of those are records of what ' +
        'happened. Neither is a credential, and nothing in this service ' +
        'consults them to decide anything. The two links above are on the ' +
        'PLAIN HTTP port, not this one.'
    }
  };
  report.verdict = verdictFor(mode, presented, authorized, authorizationError);
  log.debug('Leaving describeConnection(). presented=' + presented +
            ' authorized=' + authorized);
  return report;
}

// ---------------------------------------------------------------------------
// Rendering.
// ---------------------------------------------------------------------------

function pageShell(title, inner) {
  return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + xmlEscape(title) + '</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;' +
    'background:#f4f4f7;margin:0;padding:2rem;color:#222;line-height:1.45}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;' +
    'padding:24px 28px;max-width:60rem;margin:0 auto;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}' +
    'h1{font-size:1.3em;margin:0 0 4px;color:#12107c}' +
    'h2{font-size:1em;margin:1.4em 0 .4em}' +
    'p.sub{color:#666;font-size:.85em;margin:0 0 18px}' +
    'p.verdict{background:#f0f0f8;border-left:4px solid #12107c;' +
    'padding:.6rem .8rem;margin:.6rem 0}' +
    'table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;' +
    'font-size:.85em}' +
    'th,td{border:1px solid #ddd;padding:.35rem .55rem;text-align:left;' +
    'vertical-align:top}th{background:#f0f0f5}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;' +
    'font-size:.85em;background:#f4f4f8;padding:.1rem .25rem;border-radius:3px;' +
    'word-break:break-all}a{color:#12107c}' +
    'textarea{width:100%;font-family:ui-monospace,monospace;font-size:.8em}' +
    'ul{margin:.3em 0;padding-left:1.2em}li{margin:.2em 0}' +
    '</style></head><body><div class="card">' + inner + '</div></body></html>\n';
}

function rowsFrom(pairs) {
  return pairs.map(function (pair) {
    return '<tr><td>' + xmlEscape(pair[0]) + '</td><td><code>' +
      xmlEscape(pair[1] === null || pair[1] === undefined
        ? '(none)' : String(pair[1])) + '</code></td></tr>';
  }).join('');
}

function reportPage(report) {
  log.debug('Entering reportPage().');
  const httpsRows = rowsFrom([
    ['Request', report.https.method + ' ' + report.https.url +
      ' HTTP/' + report.https.httpVersion],
    ['Host header', report.https.host],
    ['User-Agent', report.https.userAgent],
    ['From', report.https.remoteAddress + ':' + report.https.remotePort],
    ['Arrived on', 'port ' + report.https.localPort]
  ]);
  const tlsRows = rowsFrom([
    ['Listener', report.tls.listener + ' (port ' + report.tls.listenerPort +
      ')'],
    ['Client certificate policy', report.tls.clientCertificatePolicy],
    ['Protocol', report.tls.protocol],
    ['Cipher', (report.tls.cipher.standardName || report.tls.cipher.name) +
      ' (' + report.tls.cipher.version + ')'],
    ['SNI server name', report.tls.sniServername],
    ['ALPN', report.tls.alpnProtocol],
    ['Session reused', String(report.tls.sessionReused)],
    ['Server certificate', report.tls.serverCertificate.subject],
    ['Its names', report.tls.serverCertificate.names.join(', ')],
    ['Its SHA-256', report.tls.serverCertificate.fingerprint256]
  ]);
  const certRows = report.clientCertificate.presented
    ? rowsFrom([
        ['Verified', report.clientCertificate.authorized ? 'yes' :
          'no — ' + (report.clientCertificate.authorizationError || '')],
        ['Subject', report.clientCertificate.subject],
        ['Subject as a DN (RFC 4514)',
          report.clientCertificate.subjectRfc4514],
        ['Issuer', report.clientCertificate.issuer],
        ['Serial', report.clientCertificate.serialNumber],
        ['Valid from', report.clientCertificate.validFrom],
        ['Valid to', report.clientCertificate.validTo],
        ['subjectAltName', report.clientCertificate.subjectAltName],
        ['extendedKeyUsage',
          (report.clientCertificate.extendedKeyUsage || []).join(', ')],
        ['SHA-256', report.clientCertificate.fingerprint256],
        ['Certificates in the path built',
          String(report.clientCertificate.chainLength) + ' (leaf first)']
      ])
    : '<tr><td colspan="2">Nothing was presented.</td></tr>';
  const chainRows = (report.clientCertificate.chain || []).map(function (c) {
    return '<tr><td>' + c.depth + '</td><td><code>' + xmlEscape(c.subject) +
      '</code></td><td><code>' + xmlEscape(c.issuer) + '</code></td><td>' +
      xmlEscape(c.validTo || '') + '</td></tr>';
  }).join('');
  const inner = '<h1>This is what the server saw</h1>' +
    '<p class="sub">' + xmlEscape(report.message) + '</p>' +
    '<p class="verdict">' + xmlEscape(report.verdict) + '</p>' +
    '<h2>The HTTPS request</h2><table>' +
    '<tr><th>Thing</th><th>Value</th></tr>' + httpsRows + '</table>' +
    '<h2>The TLS connection underneath it</h2><table>' +
    '<tr><th>Thing</th><th>Value</th></tr>' + tlsRows + '</table>' +
    '<h2>The client certificate</h2><table>' +
    '<tr><th>Thing</th><th>Value</th></tr>' + certRows + '</table>' +
    (chainRows
      ? '<h2>The chain that was built, leaf first</h2>' +
        '<p class="sub">The path as it was assembled &mdash; not a list of ' +
        'what arrived. When verification succeeded the last entry is an ' +
        'anchor this service holds, which the client did not send. What this ' +
        'does show is the commonest mutual-TLS mistake there is and one that ' +
        'is invisible from the client: a leaf presented without its ' +
        'intermediates, which appears here as a chain of one that did not ' +
        'verify.</p>' +
        '<table><tr><th>Depth</th><th>Subject</th><th>Issuer</th>' +
        '<th>Not after</th></tr>' + chainRows + '</table>'
      : '') +
    '<h2>What this proves about who you are</h2>' +
    '<p>' + xmlEscape(report.authentication.note) + '</p>' +
    (report.authentication.recorded
      ? '<table><tr><th>Thing</th><th>Value</th></tr>' + rowsFrom([
          ['Recorded as', report.authentication.identity],
          ['In the console', report.authentication.consoleUrl +
            ' (on ' + mainPortPhrase() + ')'],
          // Not "under ou=users": a subject that already lies inside this
          // directory's own tree keeps its place there, so naming the branch
          // here would be right most of the time and wrong exactly when a
          // reader was testing that case.
          ['In the directory', 'an entry derived from this subject — ' +
            report.authentication.directoryUrl + ' lists every one, and ' +
            '/ldap says how the DN is chosen']
        ]) + '</table>'
      : '') +
    '<p class="sub"><a href="/tls/whoami">This page as JSON</a></p>';
  log.debug('Leaving reportPage().');
  return pageShell('What the server saw', inner);
}

// One handler, given to both listeners with the mode they were created in.
// Which listener answered is part of the report, so the two cannot be confused
// by a reader looking at a saved response.
function makeHandler(mode) {
  log.debug('Entering makeHandler(). mode=' + mode);
  log.debug('Leaving makeHandler().');
  return function (req, res) {
    log.debug('Entering the TLS listener handler. mode=' + mode + ' url=' +
              req.url);
    const report = describeConnection(req, mode);
    // Logged in full, like every other exchange this service records: this is
    // the one place the server's own view of a handshake is written down, and
    // when a mutual-TLS test fails it is the first thing worth reading.
    log.debug({ tlsConnection: report },
              'TLS connection on the ' + mode + ' listener: ' +
              (report.clientCertificate.presented
                ? (report.clientCertificate.authorized
                    ? 'a verified client certificate'
                    : 'an unverified client certificate')
                : 'no client certificate'));
    const path = String(req.url || '/').split('?')[0];
    const query = String(req.url || '').split('?')[1] || '';
    const wantsJson = /(^|&)format=json(&|$)/.test(query) ||
        path === '/tls/whoami' ||
        /application\/json/i.test(String(req.headers.accept || ''));
    res.setHeader('Cache-Control', 'no-store');
    if (wantsJson) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(report, null, 2));
      log.debug('Leaving the TLS listener handler. JSON.');
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(reportPage(report));
    log.debug('Leaving the TLS listener handler. HTML.');
  };
}

// ---------------------------------------------------------------------------
// A VERIFIED CLIENT CERTIFICATE IS RECORDED, AND RECORDING IT IS NOT ACCEPTING
// IT AS A LOGIN.
//
// The two are worth holding apart, because this listener's whole value is that
// it does not confuse them. What a verified certificate means here has not
// changed and is stated everywhere this module speaks: OpenSSL built a chain
// from what the client sent to an anchor somebody POSTed to /tls/trust. No
// session starts, no token is issued, no revocation is checked, and no endpoint
// of this service will let the holder do anything it would not let an anonymous
// caller do.
//
// What it now also does is get WRITTEN DOWN. `/admin/users` answers "who has
// this service seen, in an interaction that succeeded", and a mutual-TLS client
// that verified is exactly that — leaving it out made the console's answer
// wrong by omission, and it is the one family whose identity the embedded
// directory can seed an entry for verbatim, because a certificate subject is
// already a DN. So this calls `stats.recordAuthentication()`, the same funnel
// the other thirteen families pass through, and the LDAP entry follows from the
// observer that is already on it rather than from a second call here.
//
// Three decisions in the implementation, each of which can be got wrong quietly:
//
//   * IT HAPPENS AT THE HANDSHAKE, not in the request handler. The credential
//     was accepted when the handshake completed, which is the rule every other
//     call site in this service follows; recording in the handler would count
//     REQUESTS instead, so one connection carrying six of them would read as six
//     authentications. The consequence to expect is the other way round and is
//     honest: a client that opens six CONNECTIONS did present its certificate
//     six times, and the console says six.
//   * ONLY WHEN `authorized` IS TRUE. On the optional listener a certificate
//     that did not verify, or none at all, records nothing — the console lists
//     identities that got somewhere, not names that were tried.
//   * A RESUMED SESSION may carry no peer certificate: the client does not send
//     it again, and node hands back an empty object. Nothing is recorded then,
//     rather than an authentication with no identity on it.
// ---------------------------------------------------------------------------
function recordClientCertificate(socket, mode) {
  log.debug('Entering recordClientCertificate(). mode=' + mode);
  if (!socket || socket.authorized !== true) {
    log.debug('Leaving recordClientCertificate(). Nothing verified here.');
    return null;
  }
  let cert = null;
  try {
    cert = socket.getPeerCertificate ? socket.getPeerCertificate() : null;
  } catch (e) {
    // A socket that went away between the handshake and this line. Logged
    // rather than thrown: this is an event handler on a listener, so a throw
    // out of it is an uncaught exception and takes the service down.
    log.debug('recordClientCertificate(): the peer certificate could not be ' +
              'read: ' + e.message);
    log.debug('Leaving recordClientCertificate(). No certificate.');
    return null;
  }
  if (!cert || !Object.keys(cert).length) {
    log.debug('Leaving recordClientCertificate(). The connection verified but ' +
              'carries no peer certificate, which is what a resumed session ' +
              'looks like.');
    return null;
  }
  const subject = dnRfc4514(cert.subject);
  if (!subject) {
    log.debug('Leaving recordClientCertificate(). The subject is empty.');
    return null;
  }
  const common = cert.subject && cert.subject.CN
    ? String(Array.isArray(cert.subject.CN) ? cert.subject.CN[0] : cert.subject.CN)
    : '';
  try {
    stats.recordAuthentication({
      presented: subject,
      protocol: 'TLS',
      method: 'client certificate on the ' + mode + '-client-certificate ' +
        'listener (port ' + (mode === 'required'
          ? (boundMtlsPort || MTLS_PORT) : (boundTlsPort || TLS_PORT)) + ')',
      note: 'the chain verified against one of the ' + anchors.length +
        ' anchor(s) POSTed to /tls/trust. That is the whole of what it proved: ' +
        'no session was started and no token was issued.',
      // Both DNs in RFC 4514 form, which is not the form the report on this
      // connection shows — see dnRfc4514(). These two go into a DIRECTORY, and
      // that is the only form a directory takes.
      certificate: {
        subject: subject,
        commonName: common,
        issuer: dnRfc4514(cert.issuer),
        serialNumber: cert.serialNumber || '',
        validFrom: cert.valid_from || '',
        validTo: cert.valid_to || '',
        fingerprint256: cert.fingerprint256 || '',
        email: emailOf(cert)
      }
    });
  } catch (e) {
    // Same reason as the read above, and one more: the console and the
    // directory are bookkeeping, and bookkeeping must never be able to break a
    // connection that has already been accepted.
    log.error('tls: recording the client certificate failed and was ignored; ' +
              'the connection is unaffected: ' + e.message);
    log.debug('Leaving recordClientCertificate(). The recording threw.');
    return null;
  }
  log.info('tls: ' + subject + ' presented a client certificate that verified ' +
           'on the ' + mode + ' listener. It is recorded in the admin console ' +
           'and the directory has an entry for it; it is still not a login.');
  log.debug('Leaving recordClientCertificate(). Recorded.');
  return subject;
}

// ---------------------------------------------------------------------------
// The two listeners.
//
// Created at require time — creating a server binds nothing — and started from
// listen() in server.js, for the same reason the KDC's and the directory's
// sockets are: a bind can fail, and a require that throws takes the whole
// service down where a route cannot.
// ---------------------------------------------------------------------------
const permissiveServer = https.createServer(
    Object.assign({ requestCert: true, rejectUnauthorized: false },
                  secureContextOptions()),
    makeHandler('optional'));

const strictServer = https.createServer(
    Object.assign({ requestCert: true, rejectUnauthorized: true },
                  secureContextOptions()),
    makeHandler('required'));

// The moment the credential is accepted, on both listeners. `secureConnection`
// fires once per completed handshake — on the strict listener it cannot fire at
// all unless the certificate verified, and on the permissive one the check
// inside decides. See recordClientCertificate() for why it is here and not in
// the request handler.
permissiveServer.on('secureConnection', function (socket) {
  recordClientCertificate(socket, 'optional');
});

strictServer.on('secureConnection', function (socket) {
  recordClientCertificate(socket, 'required');
});

// A refused client certificate reaches the STRICT listener as a socket error
// and never as a request, so without this it is invisible: the far end sees a
// closed connection with no alert and this log says nothing at all. It is the
// single most confusing failure in mutual TLS, so it is logged with the reason
// OpenSSL gave.
strictServer.on('tlsClientError', function (error, socket) {
  log.warn('tls: the listener on ' + (boundMtlsPort || MTLS_PORT) +
           ' refused a connection from ' +
           ((socket && socket.remoteAddress) || 'an unknown address') + ': ' +
           error.message + '. That listener requires a client certificate ' +
           'that verifies against one of the ' + anchors.length + ' anchor(s) ' +
           'it holds. POST the issuing CA to /tls/trust on ' +
           mainPortPhrase() + ', or use port ' + (boundTlsPort || TLS_PORT) +
           ', which answers whatever arrives and says what it made of it.');
});

permissiveServer.on('tlsClientError', function (error, socket) {
  // This listener refuses nothing about the CLIENT certificate, so an error
  // here is about the handshake itself — a version or cipher mismatch, or a
  // caller that spoke something other than TLS at it.
  log.warn('tls: a handshake failed on ' + (boundTlsPort || TLS_PORT) +
           ' from ' + ((socket && socket.remoteAddress) || 'an unknown ' +
           'address') + ': ' + error.message + '. This listener accepts any ' +
           'client certificate or none, so this is not about one.');
});

// ---------------------------------------------------------------------------
// The plain-HTTP views.
//
// These are the only surfaces of this module that /sts-metadata can see, since
// that page is built by walking the Express router and the two listeners above
// are sockets. They are also the only way to configure the truststore, and
// they are on the MAIN port on purpose — see the header, including what
// global.https changes about that.
// ---------------------------------------------------------------------------

function description(req) {
  log.debug('Entering description().');
  const host = String(req.get('host') || 'localhost').split(':')[0];
  const out = {
    listeners: [
      { mode: 'optional',
        url: 'https://' + host + ':' + (boundTlsPort || TLS_PORT) + '/',
        port: boundTlsPort || TLS_PORT,
        listening: tlsListening,
        requestsClientCertificate: true,
        requiresClientCertificate: false,
        what: 'Always asks for a client certificate, accepts whatever ' +
          'arrives including nothing, and reports the verdict instead of ' +
          'enforcing it. Point a debugger here.' },
      { mode: 'required',
        url: 'https://' + host + ':' + (boundMtlsPort || MTLS_PORT) + '/',
        port: boundMtlsPort || MTLS_PORT,
        listening: mtlsListening,
        requestsClientCertificate: true,
        requiresClientCertificate: true,
        what: 'Refuses a client certificate that does not verify, during the ' +
          'handshake, the way a real server does — which is to say by closing ' +
          'the socket with no alert. Reaching it is the proof that the ' +
          'certificate verified.' }
    ],
    // Published because these pages are HTTP and the listeners are not: /tls
    // answers 200 whether or not either socket bound, so a reader has no other
    // way to tell a running listener from one whose port was already taken.
    listenError: listenError,
    paths: {
      report: '/tls/whoami',
      page: '/'
    },
    serverCertificate: {
      subject: SERVER_CERTIFICATE.subject,
      names: SERVER_CERTIFICATE.names,
      fingerprint256: SERVER_CERTIFICATE.fingerprint256,
      notAfter: SERVER_CERTIFICATE.notAfter,
      selfSigned: true,
      pemUrl: '/tls/server-certificate'
    },
    truststore: {
      anchors: anchors.length,
      maxAnchors: MAX_ANCHORS,
      subjects: anchors.map(function (anchor) { return anchor.subject; }),
      fingerprints: anchors.map(function (anchor) {
        return anchor.fingerprint256;
      }),
      addUrl: '/tls/trust',
      clearUrl: '/tls/trust/clear'
    },
    authenticatesNobody: true,
    // Not a contradiction of the line above, and the two are next to each other
    // so that neither can be read alone: nothing here is a login, and a
    // certificate that VERIFIED is still written down.
    recordsVerifiedCertificates: {
      recorded: true,
      what: 'when a handshake completes with a client certificate that ' +
        'verified, the subject DN is filed as an authentication (protocol ' +
        '"TLS") and the embedded LDAP directory seeds an entry for it',
      when: 'once per handshake, not once per request',
      consoleUrl: '/admin/users?protocol=TLS',
      directoryUrl: '/ldap/directory',
      note: 'a record of what happened, not a credential. No session, no ' +
        'token, no revocation check, and nothing in this service consults it.'
    }
  };
  log.debug('Leaving description().');
  return out;
}

app.get('/tls', function (req, res) {
  log.debug('Entering GET /tls.');
  const info = description(req);
  if (String(req.query.format || '').toLowerCase() === 'json') {
    log.debug('Leaving GET /tls. JSON.');
    return res.status(200).set('Cache-Control', 'no-store').json(info);
  }
  const listenerRows = info.listeners.map(function (listener) {
    return '<tr><td><code>' + xmlEscape(listener.url) + '</code></td><td>' +
      (listener.requiresClientCertificate ? 'required' : 'optional') +
      '</td><td>' + (listener.listening ? 'up' : 'DOWN') + '</td><td>' +
      xmlEscape(listener.what) + '</td></tr>';
  }).join('');
  const anchorRows = anchors.length
    ? anchors.map(function (anchor) {
        return '<tr><td><code>' + xmlEscape(anchor.subject) +
          '</code></td><td><code>' + xmlEscape(anchor.fingerprint256) +
          '</code></td></tr>';
      }).join('')
    : '<tr><td colspan="2">Empty. No client certificate can verify here ' +
      'yet, and nothing can connect to the listener that requires one.</td>' +
      '</tr>';
  const inner = '<h1>A TLS endpoint lives here</h1>' +
    '<p class="sub">Two HTTPS listeners whose only content is what the server ' +
    'saw: the request as it arrived, what TLS negotiated underneath it, and ' +
    'the client certificate exactly as it was presented. This page is on ' +
    xmlEscape(mainPortPhrase()) +
    (config.value('global.https')
      ? ', so there is no plain listener in this process: fetch the server ' +
        'certificate below without verifying it the first time, then trust it.'
      : ', which is the one that is reachable before anything is trusted.') +
    '</p>' +
    '<table><tr><th>URL</th><th>Client certificate</th><th>Listener</th>' +
    '<th>What it is for</th></tr>' + listenerRows + '</table>' +
    (info.listenError
      ? '<p class="verdict">A listener did not bind: ' +
        xmlEscape(info.listenError) + '. This page is HTTP and answers ' +
        'either way; the listener does not.</p>'
      : '') +
    '<h2>The server certificate</h2>' +
    '<p>Self-signed, and <strong>regenerated on every start</strong> — so it ' +
    'is an anchor nobody can have baked in. Fetch it and put it in your own ' +
    'truststore rather than switching verification off, which is the habit ' +
    'this whole workflow exists to break.</p>' +
    '<table>' + rowsFrom([
      ['Subject', info.serverCertificate.subject],
      ['Names', info.serverCertificate.names.join(', ')],
      ['SHA-256', info.serverCertificate.fingerprint256],
      ['Not after', info.serverCertificate.notAfter],
      ['PEM', 'GET /tls/server-certificate']
    ]) + '</table>' +
    '<h2>What client certificates are verified against</h2>' +
    '<p>Empty at startup, and it has to be: the certificate authority whose ' +
    'clients this verifies is generated in a <em>browser</em>, minutes before ' +
    'the connection, and exists nowhere else. Paste its certificate here — ' +
    'the root, or the whole chain above the leaf.</p>' +
    '<table><tr><th>Anchor</th><th>SHA-256</th></tr>' + anchorRows +
    '</table>' +
    '<form method="post" action="/tls/trust">' +
    '<textarea name="certificates" rows="6" ' +
    'placeholder="-----BEGIN CERTIFICATE-----"></textarea>' +
    '<p><button type="submit">Trust these</button></p></form>' +
    '<form method="post" action="/tls/trust/clear">' +
    '<button type="submit">Empty the truststore</button></form>' +
    '<h2>It authenticates nobody</h2>' +
    '<p>A verified client certificate here means one thing: a chain was built ' +
    'from what the client sent to an anchor somebody supplied. No session is ' +
    'started, no token is issued, no revocation is checked, and no endpoint of ' +
    'this service will let the holder do anything an anonymous caller cannot.</p>' +
    '<p>It is <em>recorded</em>, which is a different claim. When the ' +
    'handshake completes with a certificate that verified, the subject DN is ' +
    'filed as an authentication on <a href="/admin/users">/admin/users</a> and ' +
    'the embedded LDAP directory seeds an entry for it — a certificate subject ' +
    'is already a DN, so it is the one identity here that does not have to be ' +
    'turned into one, and the subject, issuer, serial and validity go on the ' +
    'entry beside it. <a href="/ldap">GET /ldap</a> says where. Both are a ' +
    'record of what happened; neither is a credential.</p>' +
    '<p class="sub"><a href="/tls?format=json">This page as JSON</a> ' +
    '&middot; <a href="/sts-metadata">everything this service speaks</a></p>';
  res.status(200).type('html').set('Cache-Control', 'no-store')
     .send(pageShell('TLS endpoint', inner));
  log.debug('Leaving GET /tls.');
});

app.get('/tls/server-certificate', function (req, res) {
  log.debug('Entering GET /tls/server-certificate.');
  // no-store for the same reason every document describing the signing key
  // carries it: this certificate is regenerated on every start, so a cached
  // copy outlives the key it describes and the failure it produces is a
  // handshake that does not verify — which reads as a broken server rather
  // than a stale anchor.
  res.status(200).type('text/plain').set('Cache-Control', 'no-store')
     .send(SERVER_CERTIFICATE.certPem);
  log.debug('Leaving GET /tls/server-certificate.');
});

// The body may be raw PEM (what a script sends), or the `certificates` member
// of a form or JSON body (what the page above sends). They are told apart by
// looking for the PEM header rather than by the content type, because a raw PEM
// posted as text/plain would otherwise be run through URLSearchParams and come
// out as a set of nonsense keys — a silent mangling rather than a refusal.
app.post('/tls/trust', function (req, res) {
  log.debug('Entering POST /tls/trust.');
  const raw = typeof req.body === 'string' ? req.body : '';
  const looksLikePem = /-----BEGIN CERTIFICATE-----/.test(raw) &&
      !/^certificates=/.test(raw.trim());
  const text = looksLikePem ? raw
    : String((parseBody(req) || {}).certificates || '');
  const result = addAnchors(text);
  const wantsHtml = /html/i.test(String(req.headers.accept || '')) &&
      !/json/i.test(String(req.headers['content-type'] || ''));
  if (result.error && !result.added) {
    log.debug('Leaving POST /tls/trust. Refused: ' + result.error);
    if (wantsHtml) {
      return res.status(400).type('html').send(pageShell('Truststore',
        '<h1>Nothing was added</h1><p>' + xmlEscape(result.error) + '</p>' +
        '<p class="sub"><a href="/tls">back to the TLS endpoint</a></p>'));
    }
    return res.status(400).json({ error: result.error, anchors: anchors.length });
  }
  if (wantsHtml) {
    log.debug('Leaving POST /tls/trust. HTML, added=' + result.added);
    return res.status(200).type('html').send(pageShell('Truststore',
      '<h1>' + result.added + ' anchor(s) added</h1>' +
      '<p>This service now verifies client certificates against ' +
      anchors.length + ' anchor(s). Existing connections keep the truststore ' +
      'they were made under; the next handshake is judged against this one.</p>' +
      '<p class="sub"><a href="/tls">back to the TLS endpoint</a></p>'));
  }
  res.status(200).json({
    added: result.added,
    duplicates: result.duplicates || 0,
    anchors: anchors.length,
    subjects: anchors.map(function (anchor) { return anchor.subject; }),
    note: 'Applied with tls.Server.setSecureContext(). Existing connections ' +
      'keep the truststore they were made under; the next handshake is judged ' +
      'against this one.'
  });
  log.debug('Leaving POST /tls/trust. added=' + result.added);
});

app.post('/tls/trust/clear', function (req, res) {
  log.debug('Entering POST /tls/trust/clear.');
  const result = clearAnchors();
  if (/html/i.test(String(req.headers.accept || ''))) {
    log.debug('Leaving POST /tls/trust/clear. HTML.');
    return res.status(200).type('html').send(pageShell('Truststore',
      '<h1>The truststore is empty</h1>' +
      '<p>' + result.removed + ' anchor(s) removed. No client certificate ' +
      'verifies here now, and nothing can connect to the listener that ' +
      'requires one — which is the state this service starts in.</p>' +
      '<p class="sub"><a href="/tls">back to the TLS endpoint</a></p>'));
  }
  res.status(200).json({ removed: result.removed, anchors: 0 });
  log.debug('Leaving POST /tls/trust/clear.');
});

// ---------------------------------------------------------------------------
// Starting the listeners.
//
// Called from server.js rather than at require time, for the reason the KDC and
// the directory record: a bind can fail — 8443 and 9443 are ordinary ports, but
// a second instance of this service is not an unusual thing to have running —
// and a require that throws takes the whole service down where a route cannot.
// Callers await `whenReady` rather than reading a port that is not bound yet.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// GET /tls/forwarded — what a reverse proxy told this service, and what was
// believed of it.
//
// RFC 9700 section 2.6 has a paragraph about reverse proxies with two halves.
// The proxy's half is that it MUST sanitize inbound security-sensitive headers
// before forwarding — a client must not be able to reach past the proxy by
// setting a header the proxy is supposed to set. The application's half, which
// is the one this service can do something about, is that it must not BELIEVE
// those headers unless it knows a proxy set them.
//
// So this page reports the request as it arrived: every forwarding header, every
// security-sensitive header a proxy might inject, whether this service believed
// any of it, and what the effective base URL — the thing every issuer and every
// endpoint in both discovery documents is built from — came out as.
//
// It lives in this module for the same reason /tls/whoami does: this file's
// whole content is what the SERVER saw of a connection, and a forwarding header
// is what the server was TOLD about a connection it did not see. The difference
// between those two sentences is the page.
//
// **The client certificate headers are the important row.** A proxy that
// terminates mTLS forwards the certificate in a header — X-Client-Cert,
// X-Forwarded-Client-Cert, X-SSL-Client-Cert, and a dozen vendor spellings — and
// an application that believed one would be accepting a certificate anybody can
// forge, since a header costs nothing to write. THIS SERVICE READS NONE OF THEM,
// in either mode, and the page says so with the ones it saw listed: a mock that
// silently ignored a header somebody was relying on would be as bad as one that
// silently trusted it.
// ---------------------------------------------------------------------------
const FORWARDING_HEADERS = [
  { name: 'x-forwarded-proto', what: 'The scheme the CLIENT used. Believed when ' +
      'global.trustProxy is on, and then it decides whether every URL this service ' +
      'publishes says http or https.' },
  { name: 'x-forwarded-host', what: 'The host the CLIENT used. Believed when ' +
      'global.trustProxy is on, and then it is the authority in every published URL and in ' +
      'the issuer of every token.' },
  { name: 'x-forwarded-port', what: 'READ BY NOTHING HERE. The port is taken from ' +
      'x-forwarded-host, which carries one where it matters — two sources for one value is ' +
      'two values that will eventually disagree.' },
  { name: 'x-forwarded-for', what: 'The client\'s address. READ BY NOTHING HERE, and the ' +
      'audit log deliberately records the CHANNEL rather than an address: on a mock reached ' +
      'over a compose bridge an address is a fact about docker, and a column right on a laptop ' +
      'and quietly wrong everywhere else is worse than none.' },
  { name: 'forwarded', what: 'RFC 7239\'s single-header form. NOT PARSED — this service ' +
      'reads the X- forms only, which is what every proxy in front of it emits as well.' }
];

const SENSITIVE_HEADERS = [
  { name: 'x-client-cert', what: 'A client certificate forwarded by a proxy that terminated ' +
      'mTLS.' },
  { name: 'x-forwarded-client-cert', what: 'The same thing, as Envoy and Istio spell it.' },
  { name: 'x-ssl-client-cert', what: 'The same thing, as nginx spells it.' },
  { name: 'x-ssl-client-verify', what: 'A proxy\'s verdict on the certificate it verified.' },
  { name: 'x-ssl-client-s-dn', what: 'The subject DN of a certificate a proxy verified.' },
  { name: 'x-amzn-mtls-clientcert', what: 'The same thing, as an AWS load balancer spells it.' }
];

app.get('/tls/forwarded', function (req, res) {
  log.debug('Entering GET /tls/forwarded.');
  const trusted = !!config.value('global.trustProxy');
  const seen = function (rows) {
    return rows.map(function (row) {
      const value = req.headers[row.name];
      return { header: row.name, present: value !== undefined,
               value: value === undefined ? null : String(value), what: row.what };
    });
  };
  const forwarding = seen(FORWARDING_HEADERS);
  const sensitive = seen(SENSITIVE_HEADERS);
  const presentSensitive = sensitive.filter(function (row) { return row.present; });
  const payload = {
    trustProxy: trusted,
    socket: { scheme: req.protocol, host: req.get('host') || '', encrypted: !!req.secure },
    effectiveBaseUrl: baseUrlOf(req),
    what_it_means: trusted
      ? 'global.trustProxy is ON, so X-Forwarded-Proto and X-Forwarded-Host decide what this ' +
        'service thinks its own URLs are. That is correct behind a reverse proxy and unsafe ' +
        'without one, because those are headers any client can set.'
      : 'global.trustProxy is OFF, so the forwarding headers below are IGNORED and this ' +
        'service describes the connection it can see. If a proxy is terminating TLS in front ' +
        'of it, the metadata is publishing the wrong URLs and every DPoP proof is being ' +
        'refused for naming the real endpoint — turn the setting on.',
    forwarding: forwarding,
    clientCertificateHeaders: {
      readByThisService: false,
      seen: presentSensitive.map(function (row) { return row.header; }),
      note: 'THIS SERVICE READS NONE OF THESE, in either mode. A certificate in a header is a ' +
            'certificate anybody can write, so believing one would let any client claim any ' +
            'identity — and RFC 8705 binding here reads the certificate off the TLS handshake ' +
            'itself (see /tls/whoami and mtls.js). A proxy that terminates mTLS in front of ' +
            'this service therefore cannot pass the certificate through, which is a real ' +
            'limitation rather than an oversight: the alternative is trusting a header.' +
            (presentSensitive.length
              ? ' This request carried ' + presentSensitive.length + ' of them and they were ' +
                'ignored.'
              : ''),
      headers: sensitive
    },
    proxyMustSanitize: 'RFC 9700 section 2.6: a reverse proxy MUST strip these headers from ' +
      'what a CLIENT sent before setting its own, or a client can reach past it by setting ' +
      'them itself. That is the proxy\'s job and this service cannot do it — what it can do ' +
      'is not believe them unless told to, which is what the setting above is.'
  };
  if (String(req.query.format || '').toLowerCase() === 'json') {
    log.debug('Leaving GET /tls/forwarded. JSON.');
    return res.status(200).json(payload);
  }
  const rowsOf = function (rows) {
    return rows.map(function (row) {
      return '<tr><td><code>' + xmlEscape(row.header) + '</code></td>' +
        '<td>' + (row.present
          ? '<code>' + xmlEscape(row.value) + '</code>'
          : '<span class="none">not sent</span>') + '</td>' +
        '<td>' + xmlEscape(row.what) + '</td></tr>';
    }).join('');
  };
  const inner = '<h1>What a proxy told this service</h1>' +
    '<p class="sub">The request as it arrived, and what was believed of it. Every issuer and ' +
    'every endpoint in both discovery documents is built from the effective base URL below, ' +
    'so if that is wrong, everything a client reads is wrong with it.</p>' +
    '<table><tr><th>Thing</th><th>Value</th></tr>' +
    '<tr><td>global.trustProxy</td><td>' + (trusted
      ? '<strong>on</strong> — the forwarding headers are believed'
      : '<strong>off</strong> — the forwarding headers are ignored') + '</td></tr>' +
    '<tr><td>The socket saw</td><td><code>' + xmlEscape(req.protocol) + '://' +
    xmlEscape(req.get('host') || '') + '</code>' +
    (req.secure ? ' (encrypted)' : ' (not encrypted)') + '</td></tr>' +
    '<tr><td>Effective base URL</td><td><code>' + xmlEscape(baseUrlOf(req)) +
    '</code></td></tr>' +
    '</table>' +
    '<p class="' + (trusted ? 'sub' : 'verdict') + '">' + xmlEscape(payload.what_it_means) +
    '</p>' +
    '<h2>Forwarding headers</h2>' +
    '<table><tr><th>Header</th><th>This request</th><th>What it does here</th></tr>' +
    rowsOf(forwarding) + '</table>' +
    '<h2>Client certificate headers</h2>' +
    '<p class="verdict">' + xmlEscape(payload.clientCertificateHeaders.note) + '</p>' +
    '<table><tr><th>Header</th><th>This request</th><th>What it is</th></tr>' +
    rowsOf(sensitive) + '</table>' +
    '<h2>What the proxy has to do</h2>' +
    '<p>' + xmlEscape(payload.proxyMustSanitize) + '</p>' +
    '<p class="sub"><a href="/tls/forwarded?format=json">This page as JSON</a> &middot; ' +
    '<a href="/tls">what the TLS endpoint is</a> &middot; ' +
    '<a href="/.well-known/oauth-authorization-server">the document built from that base ' +
    'URL</a></p>';
  res.status(200).type('html').send(pageShell('Forwarded headers', inner));
  log.debug('Leaving GET /tls/forwarded. trustProxy=' + trusted);
});

function listen() {
  log.debug('Entering listen().');
  function start(server, port, label) {
    return new Promise(function (resolve, reject) {
      function onError(error) {
        server.removeListener('error', onError);
        listenError = label + ' on ' + port + ': ' + error.message;
        log.error('tls: the ' + label + ' listener could not bind ' + port +
                  ': ' + error.message);
        reject(error);
      }
      server.once('error', onError);
      server.listen(port, '0.0.0.0', function () {
        server.removeListener('error', onError);
        const address = server.address();
        resolve(address ? address.port : port);
      });
    });
  }
  const whenReady = Promise.all([
    start(permissiveServer, TLS_PORT, 'optional-client-certificate'),
    start(strictServer, MTLS_PORT, 'required-client-certificate')
  ]).then(function (ports) {
    boundTlsPort = ports[0];
    boundMtlsPort = ports[1];
    tlsListening = true;
    mtlsListening = true;
    log.debug('Leaving listen(). Both listeners are up.');
    return { tlsPort: boundTlsPort, mtlsPort: boundMtlsPort };
  });
  log.debug('Leaving listen(). Binding.');
  return { whenReady: whenReady };
}

function close() {
  log.debug('Entering close().');
  try {
    permissiveServer.close();
    strictServer.close();
  } catch (e) {
    // Closing a listener that never bound throws, and there is nothing useful
    // to do about it: this exists for tests and for an orderly shutdown.
    log.debug('close(): ' + e.message);
  }
  tlsListening = false;
  mtlsListening = false;
  log.debug('Leaving close().');
}

module.exports = {
  listen: listen,
  close: close,
  // Exported for tests, which check these without opening a socket.
  splitPemCertificates: splitPemCertificates,
  // The RFC 4514 form of a subject. It now LIVES in common/helpers.js and is
  // re-exported here so that scim_auth.js and spiffe_auth.js — which require
  // this module for it and have done since before it moved — go on getting the
  // same string this module records and the directory files a certificate
  // under. Two spellings of one DN is two people on /admin/users, and the
  // difference between them is a comma and a space.
  dnRfc4514: dnRfc4514,
  addAnchors: addAnchors,
  clearAnchors: clearAnchors,
  serverCertificatePem: function () { return SERVER_CERTIFICATE.certPem; },
  // The whole of it, private key included, because ldap_server.js serves it on
  // 636 — see the note above SERVER_CERTIFICATE. Handing a private key to
  // another module in this process is not the same act as publishing one: this
  // key is generated per start, exists only in memory and dies with the
  // process, exactly like the signing key in helpers.js. Nothing here writes it
  // to a response; GET /tls/server-certificate publishes the CERTIFICATE alone.
  serverCertificate: function () {
    return {
      certPem: SERVER_CERTIFICATE.certPem,
      privateKeyPem: SERVER_CERTIFICATE.privateKeyPem,
      subject: SERVER_CERTIFICATE.subject,
      names: SERVER_CERTIFICATE.names.slice(0),
      fingerprint256: SERVER_CERTIFICATE.fingerprint256,
      notAfter: SERVER_CERTIFICATE.notAfter
    };
  },
  anchorCount: function () { return anchors.length; },
  ports: function () {
    return { tls: boundTlsPort || TLS_PORT,
             mtls: boundMtlsPort || MTLS_PORT };
  }
};
