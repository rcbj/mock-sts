'use strict';
//
// File: mtls.js
//
// ===========================================================================
// RFC 8705 — CERTIFICATE-BOUND ACCESS TOKENS, the other half of RFC 9700's
// sender-constraining recommendation.
//
// Section 2.2 of the BCP names two mechanisms and this service had one of them.
// `dpop.js` binds a token to a KEY the client proves possession of per request;
// this binds it to the CLIENT CERTIFICATE the TLS connection was made with. The
// shapes are deliberately parallel and the reason to have both is that they fail
// differently: DPoP needs no PKI and works for a client that cannot hold a
// certificate, and mTLS needs no per-request signature and survives a client
// that cannot do JOSE.
//
// What a client sees:
//
//   token endpoint over mTLS       ->  cnf: { "x5t#S256": <thumbprint> }
//   resource endpoint over mTLS    ->  the presented certificate is thumbprinted
//                                      again and compared
//
// This is RFC 8705 section 3 (the confirmation method) and section 3.1 (the
// check). What is NOT here is section 2 — mutual-TLS CLIENT AUTHENTICATION, where
// the certificate replaces the client_secret. That is a different feature with a
// different registry of `tls_client_auth_subject_dn` metadata behind it, and
// leaving it out is stated rather than implied: this service authenticates a
// client with a secret (see `oauth2_bcp.js`'s section 2.5 note) or not at all.
//
// ---------------------------------------------------------------------------
// IT ONLY WORKS WHERE THERE IS A CLIENT CERTIFICATE TO SEE, AND THAT IS A
// DEPLOYMENT FACT RATHER THAN A CHECK.
//
// The token endpoint has to be reached over a TLS connection that ASKED for a
// certificate. On this service that means `global.https` — which RFC 9700 mode
// turns on — because the main listener is where `/oauth2/token` lives, and
// `server.js` sets `requestCert: true, rejectUnauthorized: false` on it: asked
// for, never required, exactly the posture port 8443 has. A client that presents
// none gets an ordinary Bearer or DPoP-bound token and nothing about its
// behaviour changes, which is what keeps this invisible to every caller that
// does not use it.
//
// `rejectUnauthorized: false` is worth being precise about, because it looks
// like a hole and is not: a certificate that did not build a chain to a trusted
// anchor is still THUMBPRINTED and still binds the token. RFC 8705 section 3
// says the binding is to the certificate itself and explicitly permits a
// self-signed one — the proof is that the same key completed the handshake, not
// that a CA vouched for it. Refusing an unverified certificate here would break
// exactly the case the truststore at `/tls/trust` exists to make reachable.
//
// ---------------------------------------------------------------------------
// THE THUMBPRINT IS OF THE DER, AND THAT IS THE WHOLE OF THE INTEROPERABILITY.
//
// RFC 8705 section 3.1: `x5t#S256` is the base64url-encoded SHA-256 of the DER
// encoding of the X.509 certificate. Not of the PEM, not of the public key, not
// hex, and not base64 with padding. Every one of those produces a value that
// looks right in a log and matches nothing, so `thumbprintOf()` is the only
// place it is computed and both ends of the comparison go through it.
//
// ---------------------------------------------------------------------------
// It is a LIBRARY like `dpop.js` (rule 3): it registers no route and requires
// only `helpers.js` and `config.js`, so it cannot join a cycle and its position
// in the require order does not matter. `dpop.js` requires it, because
// `presentedAccessToken()` there is the single check the four protected
// endpoints share and a second one beside it would be a fourth caller nobody
// updated.
// ===========================================================================

const crypto = require('crypto');
// One thumbprint computation for the whole service since 2026-08-27.
const stsCrypto = require('../common/crypto');
const { log, b64u } = require('../common/helpers');
const config = require('../common/config');

// RFC 8705 section 3.1's confirmation member. Spelt out as a constant because
// the `#` in it is legal in a JSON member name and looks like a mistake every
// time somebody reads it.
const CONFIRMATION_MEMBER = 'x5t#S256';

// ---------------------------------------------------------------------------
// The certificate the TLS connection was made with, or null.
//
// node hands back an EMPTY OBJECT rather than null when no certificate was
// presented — `{}` — so the test is for the raw DER rather than for the object,
// which is the trap this function exists to hold in one place.
// ---------------------------------------------------------------------------
function peerCertificate(req) {
  log.debug("Entering peerCertificate().");
  const socket = req && req.socket;
  if (!socket || typeof socket.getPeerCertificate !== 'function') {
    // A plain HTTP connection. Not an error and not worth a log line per
    // request: it is the ordinary case for this service's default listener.
    log.debug("Leaving peerCertificate().");
    return null;
  }
  const cert = socket.getPeerCertificate();
  if (!cert || !cert.raw || !cert.raw.length) {
    log.debug("Leaving peerCertificate().");
    return null;
  }
  log.debug("Leaving peerCertificate().");
  return cert;
}

// RFC 8705 `x5t#S256`: SHA-256 over the DER, base64url. The same digest
// `tls/tls_server.js` prints as colon-hex and `spiffe/spiffe_ca.js` truncates
// as an authority id — three spellings of one computation, which is why the
// shared function takes a format and the three that each computed it are one.
function thumbprintOf(cert) {
  if (!cert || !cert.raw) {
    return '';
  }
  return stsCrypto.certificateThumbprint(cert);
}

// The thumbprint of whatever certificate this request arrived with, or ''. The
// one function anything outside this file should need.
function presentedThumbprint(req) {
  return thumbprintOf(peerCertificate(req));
}

// RFC 8705 section 3: the confirmation claim to put on an issued token, or
// undefined when there is nothing to bind to. Returned as the whole `cnf` value
// so the caller does not have to know the member's name — and MERGED with a
// DPoP `jkt` rather than replacing it, because a client that both presented a
// certificate and sent a proof has demonstrated both and a token that recorded
// one of them would be throwing away a check somebody performed.
function confirmationFor(req, existing) {
  log.debug("Entering confirmationFor().");
  const thumbprint = presentedThumbprint(req);
  if (!thumbprint) {
    log.debug("Leaving confirmationFor(). No client certificate on this connection.");
    return existing;
  }
  const cnf = Object.assign({}, existing || {});
  cnf[CONFIRMATION_MEMBER] = thumbprint;
  log.info('RFC 8705: this token is bound to the client certificate the connection was made ' +
           'with. ' + CONFIRMATION_MEMBER + '=' + thumbprint +
           (existing && existing.jkt ? ', and to the DPoP key ' + existing.jkt + ' as well' : ''));
  log.debug("Leaving confirmationFor(). Bound.");
  return cnf;
}

// What a token says about its own certificate binding, or ''.
function boundThumbprintOf(claims) {
  const cnf = claims && claims.cnf;
  if (!cnf || typeof cnf !== 'object') {
    return '';
  }
  const value = cnf[CONFIRMATION_MEMBER];
  return value ? String(value) : '';
}

// ---------------------------------------------------------------------------
// RFC 8705 section 3.1, the RESOURCE server's half: a certificate-bound token
// is only usable on a connection made with that certificate.
//
// Returns null when there is nothing to say and a refusal object otherwise. The
// two failures are told apart because they send a client to different places: no
// certificate at all is usually a client that did not configure one or a proxy
// that terminated TLS, and a DIFFERENT certificate is the case the binding
// exists to catch.
//
// A token this service did not issue is NOT checked, and that is the same
// judgement `presentedAccessToken()` makes about `cnf.jkt`: for a foreign token
// the confirmation claim is something anybody could have written, so enforcing
// it would be theatre performed on an unverified string.
// ---------------------------------------------------------------------------
function checkBinding(claims, req, verified, noun) {
  log.debug("Entering checkBinding().");
  // What to CALL the thing in the refusal. The refresh grant checks a refresh
  // token with this same function, and a message about "this access token" when
  // the client is holding a refresh token sends somebody looking at the wrong
  // credential.
  const what = noun || 'access token';
  const bound = boundThumbprintOf(claims);
  if (!bound) {
    log.debug("Leaving checkBinding(). This token is not certificate-bound.");
    return null;
  }
  if (!verified) {
    log.warn('RFC 8705: this access token carries a ' + CONFIRMATION_MEMBER + ' confirmation ' +
             'and was NOT issued by this service, so the binding is a claim anybody could have ' +
             'written and is not enforced. The same is true of cnf.jkt on a foreign token.');
    log.debug("Leaving checkBinding(). A foreign token's binding is not enforced.");
    return null;
  }
  const presented = presentedThumbprint(req);
  if (!presented) {
    log.debug("Leaving checkBinding(). Bound, and no certificate on this connection.");
    return {
      error: 'invalid_token',
      description: 'RFC 8705 section 3.1: this ' + what + ' is bound to a client certificate ' +
                   '(cnf["' + CONFIRMATION_MEMBER + '"]), so it may only be used on a TLS ' +
                   'connection made with that certificate. This request arrived with no client ' +
                   'certificate at all — either none was configured, or something terminated ' +
                   'TLS in front of this service.'
    };
  }
  if (presented !== bound) {
    log.debug("Leaving checkBinding(). Bound to a different certificate.");
    return {
      error: 'invalid_token',
      description: 'RFC 8705 section 3.1: this ' + what + ' is bound to the client certificate ' +
                   'whose SHA-256 thumbprint is ' + bound + ', and this connection was made ' +
                   'with the one whose thumbprint is ' + presented + '. A certificate-bound ' +
                   'token is usable only by the holder of that certificate\'s private key, ' +
                   'which is the whole of what sender-constraining buys.'
    };
  }
  log.debug("Leaving checkBinding(). The certificate matches. thumbprint=" + presented);
  return null;
}

// Whether this deployment can bind a token at all, for the pages that report it.
// It is a property of the listener rather than of a request: `global.https` is
// what makes `server.js` ask for a client certificate, and without TLS there is
// no certificate to ask for.
function available() {
  return !!config.value('global.https');
}

module.exports = {
  CONFIRMATION_MEMBER: CONFIRMATION_MEMBER,
  peerCertificate: peerCertificate,
  thumbprintOf: thumbprintOf,
  presentedThumbprint: presentedThumbprint,
  confirmationFor: confirmationFor,
  boundThumbprintOf: boundThumbprintOf,
  checkBinding: checkBinding,
  available: available
};
