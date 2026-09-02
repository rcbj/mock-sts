'use strict';
//
// File: pq_certificates.js
//
// ===========================================================================
// THE ML-DSA SERVER CERTIFICATE, AND THE TLS HANDSHAKE THAT DEPENDS ON IT.
//
// `common/crypto.js`'s selfSignedMlDsaCertificate() is the second certificate
// builder in this service, and it exists because node-forge — which builds the
// other one — cannot represent an ML-DSA key at all. Everything it produces is
// DER written by hand against RFC 9881 and RFC 5280 over a key and a signature
// that come from node's OpenSSL 3.5.
//
// **WHY IT IS HERE AND NOT IN THE PARENT SUITE**, which is the question
// tests/CLAUDE.md says to answer first: every assertion below compares this
// service's encoder against OPENSSL, in process, with no port. The `openssl`
// BINARY is no use for it — its version belongs to the base image and to
// whoever is running this, and 3.0 (Ubuntu 22.04's, and ubuntu:latest's until
// recently) has no post-quantum algorithms at all — while node's OpenSSL moves
// with the node version, which this service pins. So the second implementation
// is the one node is linked against, reached through crypto.X509Certificate
// and tls.connect. There is nothing to observe over HTTP.
//
// The two things it is worth being sure of, in order:
//
//   1. OPENSSL READS WHAT THIS SERVICE WROTE. A certificate whose OID is in
//      the wrong place, whose AlgorithmIdentifier carries the NULL an RSA one
//      needs, or whose subjectAltName is EXPLICIT rather than IMPLICIT, parses
//      in some readers and is refused by others. `new X509Certificate()` is
//      OpenSSL's own parser saying yes.
//   2. A REAL HANDSHAKE COMPLETES WITH IT. That is the thing the certificate
//      exists for, and it fails for reasons no parse can catch: a missing
//      subjectAltName, a keyUsage without digitalSignature, a v1 certificate
//      whose extensions were ignored in silence.
//
// It also records the SHAPE OF THE MIGRATION this service can now demonstrate:
// with `tls.certificateAlgorithms` naming both, one port answers an ordinary
// client with RSA and a post-quantum one with ML-DSA, and which one arrives is
// OpenSSL's answer to the signature algorithms the CLIENT offered. That is not
// a property of this code and it is the whole point of configuring both, so it
// is asserted rather than described.
// ===========================================================================

const crypto = require('../common/crypto');
const nodeCrypto = require('crypto');
const tls = require('tls');

// A throwaway TLS server carrying the certificates given, on a loopback port.
// Returns a promise for {port, close} — the tests below all connect to it.
function listen(pairs) {
  return new Promise(function (resolve) {
    const server = tls.createServer({
      key: pairs.map(function (one) { return one.privateKeyPem; }),
      cert: pairs.map(function (one) { return one.certPem; }),
      minVersion: 'TLSv1.3'
    }, function (socket) {
      socket.end('ok\n');
    });
    server.on('tlsClientError', function () {
      // Expected in the case that asserts a refusal; the connect side reports.
    });
    server.listen(0, '127.0.0.1', function () {
      resolve({ port: server.address().port,
               close: function () { server.close(); } });
    });
  });
}

// One handshake, resolved with what the client saw rather than rejected: a
// FAILED handshake is a result here as often as a successful one is.
function handshake(port, options) {
  return new Promise(function (resolve) {
    const socket = tls.connect(Object.assign({
      host: '127.0.0.1', port: port, servername: 'localhost',
      rejectUnauthorized: false
    }, options || {}), function () {
      let keyType = null;
      try {
        keyType = new nodeCrypto.X509Certificate(
            socket.getPeerCertificate().raw).publicKey.asymmetricKeyType;
      } catch (e) {
        keyType = null;
      }
      socket.end();
      resolve({ ok: true, keyType: keyType, protocol: socket.getProtocol() });
    });
    socket.on('error', function (error) {
      resolve({ ok: false, error: error.message });
    });
  });
}

module.exports = {
  name: 'pq_certificates',
  describe: 'common/crypto.js: the ML-DSA server certificate, read by ' +
            'OpenSSL and used in a real TLS 1.3 handshake',

  run: async function (t) {
    // -----------------------------------------------------------------------
    // THE RUNTIME COMES FIRST, AND IT IS THE ONE THING IN THIS DIRECTORY THAT
    // CAN STOP A FILE FROM RUNNING AT ALL.
    //
    // Everything below needs node's OpenSSL 3.5 — the KEY and the SIGNATURE
    // are OpenSSL's, deliberately, because a test where both sides came from
    // one implementation proves nothing. That is node 24, which this
    // repository's Dockerfile pins (24.16.0) and which the containerized run
    // therefore always has; a developer on node 22 has an interpreter with no
    // ML-DSA in it, and until 2026-09-01 this file died there with
    // `ERR_INVALID_ARG_VALUE: The argument 'type' must be a supported key
    // type` — a stack naming neither this service nor the requirement nor the
    // way out.
    //
    // **IT DOES NOT SILENTLY PASS.** This harness has no skip and a file that
    // asserts nothing counts as green, which is the failure mode this whole
    // directory is about — so the warning is loud, it names the version that
    // is running and the version that is needed, and the two assertions that
    // ARE runnable here are made: that the probe and the builder AGREE, which
    // is the only branch of this code a node 22 can reach and is exactly the
    // branch that stopped `tls_server.js` from throwing out of a require.
    // -----------------------------------------------------------------------
    if (!crypto.mlDsaAvailable()) {
      t.check(true,
              'this runtime has no ML-DSA, so the certificate assertions ' +
              'below did not run — node ' + process.versions.node +
              ' is linked against OpenSSL ' + process.versions.openssl +
              ' and ML-DSA needs 3.5, which is node 24 (the Dockerfile pins ' +
              '24.16.0, so the containerized run does check all of it)');
      t.log.warn('NOT CHECKED HERE: every ML-DSA certificate assertion in ' +
                 'pq_certificates.js. Run ./docker-run-tests.sh, or use ' +
                 'node 24, to check them. The post-quantum JOSE algorithms ' +
                 'are unaffected and worker_pool.js still covers them — they ' +
                 'come from @noble/post-quantum and need nothing of OpenSSL.');
      let named = null;
      try {
        crypto.selfSignedMlDsaCertificate({ algorithm: 'ml-dsa-65',
                                            commonName: 'localhost' });
      } catch (e) {
        named = e.message;
      }
      t.check(named && /OpenSSL 3\.5/.test(named) && /node 24/.test(named),
              'and the builder refuses in this service\'s own words rather ' +
              'than node\'s — a caller that did not ask first must still be ' +
              'told which runtime it needs, because the raw refusal names an ' +
              'argument called `type` and nothing else',
              String(named));
      return;
    }

    // -----------------------------------------------------------------------
    t.log.info('A. OpenSSL reads what this service wrote');
    // -----------------------------------------------------------------------
    const built = crypto.selfSignedMlDsaCertificate({
      algorithm: 'ml-dsa-65',
      commonName: 'localhost',
      organizationName: 'mock-sts',
      serialNumber: '04',
      dnsNames: ['localhost', 'sts'],
      ipAddresses: ['127.0.0.1']
    });
    const parsed = new nodeCrypto.X509Certificate(built.certPem);
    t.check(parsed.publicKey.asymmetricKeyType === 'ml-dsa-65',
            'OpenSSL reads the subject public key as ML-DSA-65',
            'it read ' + parsed.publicKey.asymmetricKeyType);
    t.check(parsed.verify(parsed.publicKey),
            'and it verifies the self-signature — the signature is over the ' +
            'bytes this encoder said it was over');
    t.check(/CN=localhost/.test(parsed.subject),
            'the subject is an RDNSequence OpenSSL can read', parsed.subject);
    t.check(/DNS:localhost/.test(parsed.subjectAltName || '') &&
            /DNS:sts/.test(parsed.subjectAltName || '') &&
            /IP Address:127\.0\.0\.1/.test(parsed.subjectAltName || ''),
            'the subjectAltName carries both names and the address — the CN ' +
            'is ignored by every current client, so this is where the names ' +
            'are', String(parsed.subjectAltName));
    t.check(parsed.ca === false,
            'and it is not a CA: basicConstraints is present and says so');
    // The private key has to be loadable on its own, because that is what a
    // TLS listener is handed.
    let keyType = null;
    try {
      keyType = nodeCrypto.createPrivateKey(built.privateKeyPem)
          .asymmetricKeyType;
    } catch (e) {
      keyType = 'refused: ' + e.message;
    }
    t.check(keyType === 'ml-dsa-65',
            'the PKCS#8 private key is one OpenSSL can load', String(keyType));

    // -----------------------------------------------------------------------
    t.log.info('B. a real TLS 1.3 handshake completes with it');
    // -----------------------------------------------------------------------
    const single = await listen([built]);
    try {
      const report = await handshake(single.port);
      t.check(report.ok, 'the handshake completed', report.error || '');
      t.check(report.keyType === 'ml-dsa-65',
              'and the certificate the client received is the ML-DSA one',
              String(report.keyType));
      t.check(report.protocol === 'TLSv1.3',
              'over TLS 1.3, which is the only version that has these ' +
              'signature algorithms', String(report.protocol));

      // A client that refuses post-quantum signatures cannot talk to a server
      // whose only certificate is ML-DSA. Without this, the check above would
      // pass just as well against a server that had quietly fallen back to
      // something else.
      const classicalOnly = await handshake(single.port, {
        sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256'
      });
      t.check(!classicalOnly.ok,
              'and a client offering only classical signature algorithms is ' +
              'refused — so it really is the ML-DSA signature doing the ' +
              'authenticating', classicalOnly.error || 'it connected');
    } finally {
      single.close();
    }

    // -----------------------------------------------------------------------
    t.log.info('C. two certificates on one port: the CLIENT decides which');
    // -----------------------------------------------------------------------
    const rsa = crypto.selfSignedRsaCertificate({
      commonName: 'localhost', organizationName: 'mock-sts',
      serialNumber: '03',
      extensions: [
        { name: 'basicConstraints', cA: false, critical: true },
        { name: 'keyUsage', digitalSignature: true, keyEncipherment: true,
          critical: true },
        { name: 'extKeyUsage', serverAuth: true },
        { name: 'subjectAltName',
          altNames: [{ type: 2, value: 'localhost' },
                     { type: 7, ip: '127.0.0.1' }] }
      ]
    });
    const both = await listen([rsa, built]);
    try {
      const classical = await handshake(both.port, {
        sigalgs: 'rsa_pss_rsae_sha256:rsa_pkcs1_sha256'
      });
      t.check(classical.ok && classical.keyType === 'rsa',
              'a client offering only RSA signature algorithms gets the RSA ' +
              'certificate', classical.error || String(classical.keyType));
      const postQuantum = await handshake(both.port, {
        sigalgs: 'mldsa44:mldsa65:mldsa87'
      });
      t.check(postQuantum.ok && postQuantum.keyType === 'ml-dsa-65',
              'and a client offering only ML-DSA gets the ML-DSA one, from ' +
              'the same port and the same listener — which is what makes ' +
              'this a migration rather than a cut-over',
              postQuantum.error || String(postQuantum.keyType));
    } finally {
      both.close();
    }

    // -----------------------------------------------------------------------
    t.log.info('D. the parameter sets, and the refusal for anything else');
    // -----------------------------------------------------------------------
    ['ml-dsa-44', 'ml-dsa-87'].forEach(function (algorithm) {
      const one = crypto.selfSignedMlDsaCertificate({
        algorithm: algorithm, commonName: 'localhost',
        dnsNames: ['localhost']
      });
      const read = new nodeCrypto.X509Certificate(one.certPem);
      t.check(read.publicKey.asymmetricKeyType === algorithm,
              algorithm + ' produces a certificate OpenSSL reads as ' +
              algorithm, read.publicKey.asymmetricKeyType);
    });
    let refused = null;
    try {
      crypto.selfSignedMlDsaCertificate({ algorithm: 'ml-dsa-99' });
    } catch (e) {
      refused = e.message;
    }
    t.check(refused && /ML-DSA/.test(refused),
            'an unknown parameter set is refused by name rather than ' +
            'producing a certificate with an invented OID', String(refused));
  }
};
