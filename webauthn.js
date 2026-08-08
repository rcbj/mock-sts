// File: webauthn.js
//
// ---------------------------------------------------------------------------
// The relying party's half of WebAuthn, server side: verifying a registration
// and an assertion (W3C Web Authentication, sections 7.1 and 7.2).
//
// **Written independently of the debugger's own implementation, on purpose.**
// The wallet-side decoder lives in the debugger's client/src/{cbor,cose,webauthn}.js
// and this file shares no code with it — not the CBOR reader, not the COSE
// mapping, not the signature check. That is the same arrangement bbs2023.js is
// in, and for the same reason: two independent readings of one specification
// that agree is a real result, whereas one implementation agreeing with itself
// is none. tests/webauthn_cross_impl.js in the debugger repository runs both
// over the same real ceremonies and requires the same verdict on each.
//
// The independence is not cosmetic. This side verifies ECDSA through node's
// `crypto.verify`, which takes the signature in its native **DER** form; the
// browser side has to convert DER to raw `r‖s` because Web Crypto will not.
// Those are genuinely different code paths, so a mistake in one is not mirrored
// in the other — which is the whole value of the exercise.
//
// Scope: `packed`, `none` and `fido-u2f` attestation are recognised; the
// statement's own signature is NOT verified and no metadata service is
// consulted. This is a mock issuer whose purpose is to exercise a wallet, and
// pretending to attest an authenticator's provenance would be a lie told
// convincingly. What IS verified is everything a relying party must check about
// the ceremony itself: challenge, origin, RP ID hash, flags, and the signature
// over authenticatorData ‖ SHA-256(clientDataJSON).
// ---------------------------------------------------------------------------

'use strict';

const crypto = require('crypto');
const { log } = require('./helpers');

// --- CBOR, enough of it, decode only -----------------------------------------
//
// A recursive-descent reader over a Buffer, returning [value, nextOffset].
// Definite lengths only: CTAP2's canonical CBOR forbids the indefinite forms, so
// meeting one means the input is not what it claims and saying so is better than
// coping. Maps come back as a Map because COSE keys are integers, several of
// them negative.

const MAX_DEPTH = 24;

function cborRead(buf, offset, depth) {
  if (depth > MAX_DEPTH) {
    throw new Error('CBOR nested deeper than ' + MAX_DEPTH + ' levels');
  }
  if (offset >= buf.length) {
    throw new Error('CBOR ran off the end of the buffer at ' + offset);
  }
  const initial = buf[offset];
  const major = initial >> 5;
  const info = initial & 0x1f;
  let value;
  let cursor = offset + 1;

  if (info < 24) {
    value = info;
  } else if (info === 24) {
    value = buf.readUInt8(cursor); cursor += 1;
  } else if (info === 25) {
    value = buf.readUInt16BE(cursor); cursor += 2;
  } else if (info === 26) {
    value = buf.readUInt32BE(cursor); cursor += 4;
  } else if (info === 27) {
    const hi = buf.readUInt32BE(cursor), lo = buf.readUInt32BE(cursor + 4);
    value = hi * 4294967296 + lo; cursor += 8;
    if (!Number.isSafeInteger(value)) {
      throw new Error('CBOR argument exceeds the exactly-representable range');
    }
  } else {
    throw new Error('CBOR additional information ' + info + ' is reserved or indefinite; ' +
                    'CTAP2 canonical CBOR uses neither');
  }

  switch (major) {
    case 0:
      return [value, cursor];
    case 1:
      return [-1 - value, cursor];
    case 2: {
      if (cursor + value > buf.length) {
        throw new Error('a CBOR byte string claims ' + value + ' bytes, past the end of the input');
      }
      return [buf.subarray(cursor, cursor + value), cursor + value];
    }
    case 3: {
      if (cursor + value > buf.length) {
        throw new Error('a CBOR text string claims ' + value + ' bytes, past the end of the input');
      }
      return [buf.toString('utf8', cursor, cursor + value), cursor + value];
    }
    case 4: {
      const arr = [];
      for (let i = 0; i < value; i++) {
        const [item, next] = cborRead(buf, cursor, depth + 1);
        arr.push(item); cursor = next;
      }
      return [arr, cursor];
    }
    case 5: {
      const map = new Map();
      for (let i = 0; i < value; i++) {
        const [k, afterKey] = cborRead(buf, cursor, depth + 1);
        const [v, afterValue] = cborRead(buf, afterKey, depth + 1);
        if (map.has(k)) {
          throw new Error('a CBOR map repeats the key ' + JSON.stringify(k));
        }
        map.set(k, v); cursor = afterValue;
      }
      return [map, cursor];
    }
    case 7:
      if (info === 20) return [false, cursor];
      if (info === 21) return [true, cursor];
      if (info === 22) return [null, cursor];
      throw new Error('CBOR simple value ' + info + ' is not decoded here');
    default:
      throw new Error('CBOR major type ' + major + ' is not decoded here');
  }
}

function cborDecodeFirst(buf, offset) {
  return cborRead(buf, offset || 0, 0);
}

// --- COSE_Key -> JWK ----------------------------------------------------------

const COSE_CURVES = { 1: 'P-256', 2: 'P-384', 3: 'P-521', 6: 'Ed25519' };
const COSE_ALGS = {
  '-7': 'ES256', '-35': 'ES384', '-36': 'ES512', '-8': 'EdDSA',
  '-257': 'RS256', '-258': 'RS384', '-259': 'RS512',
};

function b64u(buf) {
  return Buffer.from(buf).toString('base64url');
}

function coseKeyToJwk(coseKey) {
  log.debug('Entering coseKeyToJwk().');
  if (!(coseKey instanceof Map)) {
    throw new Error('the credential public key is not a COSE_Key map');
  }
  const kty = coseKey.get(1);
  const alg = coseKey.get(3);
  let jwk;
  if (kty === 2) {
    const crv = COSE_CURVES[coseKey.get(-1)];
    if (!crv) {
      throw new Error('unsupported COSE curve ' + coseKey.get(-1));
    }
    jwk = { kty: 'EC', crv: crv, x: b64u(coseKey.get(-2)), y: b64u(coseKey.get(-3)) };
  } else if (kty === 3) {
    jwk = { kty: 'RSA', n: b64u(coseKey.get(-1)), e: b64u(coseKey.get(-2)) };
  } else if (kty === 1) {
    const crv = COSE_CURVES[coseKey.get(-1)];
    if (!crv) {
      throw new Error('unsupported COSE OKP curve ' + coseKey.get(-1));
    }
    jwk = { kty: 'OKP', crv: crv, x: b64u(coseKey.get(-2)) };
  } else {
    throw new Error('unsupported COSE key type ' + kty);
  }
  log.debug('Leaving coseKeyToJwk(). kty=' + jwk.kty + ' alg=' + COSE_ALGS[String(alg)]);
  return { jwk: jwk, alg: COSE_ALGS[String(alg)] || null, coseAlg: alg };
}

// --- authenticator data --------------------------------------------------------

function parseAuthenticatorData(buf) {
  log.debug('Entering parseAuthenticatorData(). bytes=' + buf.length);
  if (buf.length < 37) {
    throw new Error('authenticator data is ' + buf.length + ' bytes; the fixed part alone is 37');
  }
  const flags = buf[32];
  const out = {
    rpIdHash: buf.subarray(0, 32),
    flags: {
      up: !!(flags & 0x01), uv: !!(flags & 0x04), be: !!(flags & 0x08),
      bs: !!(flags & 0x10), at: !!(flags & 0x40), ed: !!(flags & 0x80),
    },
    signCount: buf.readUInt32BE(33),
    aaguid: null, credentialId: null, credentialPublicKey: null,
  };
  let cursor = 37;
  if (out.flags.at) {
    if (buf.length < cursor + 18) {
      throw new Error('the AT flag is set but the attested credential data does not fit');
    }
    out.aaguid = buf.subarray(cursor, cursor + 16); cursor += 16;
    const idLength = buf.readUInt16BE(cursor); cursor += 2;
    if (buf.length < cursor + idLength) {
      throw new Error('the credential ID claims ' + idLength + ' bytes, past the end');
    }
    out.credentialId = buf.subarray(cursor, cursor + idLength); cursor += idLength;
    const [key, next] = cborDecodeFirst(buf, cursor);
    out.credentialPublicKey = key;
    cursor = next;
  }
  if (out.flags.ed) {
    const [ext, next] = cborDecodeFirst(buf, cursor);
    out.extensions = ext;
    cursor = next;
  }
  log.debug('Leaving parseAuthenticatorData(). at=' + out.flags.at + ' signCount=' + out.signCount);
  return out;
}

// --- the two ceremonies ----------------------------------------------------------

function parseClientData(buf, expectedType) {
  const text = buf.toString('utf8');
  let json;
  try {
    json = JSON.parse(text);
  } catch (e) {
    throw new Error('clientDataJSON is not JSON: ' + e.message);
  }
  return { json: json, text: text, typeMatches: json.type === expectedType };
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

// Every check by name, in order, so a caller can report WHICH one failed. A
// single boolean is what makes people blame the authenticator.
function collect() {
  const checks = [];
  return {
    checks: checks,
    add: function (name, ok, detail) {
      checks.push({ name: name, ok: !!ok, detail: detail || '' });
      return !!ok;
    },
    ok: function () {
      return checks.every(function (c) { return c.ok; });
    },
    failed: function () {
      return checks.filter(function (c) { return !c.ok; }).map(function (c) { return c.name; });
    },
  };
}

function verifyRegistration(input) {
  log.debug('Entering verifyRegistration().');
  const c = collect();
  const attestationObject = Buffer.from(input.attestationObject, 'base64url');
  const clientDataJSON = Buffer.from(input.clientDataJSON, 'base64url');

  const [decoded] = cborDecodeFirst(attestationObject, 0);
  if (!(decoded instanceof Map)) {
    throw new Error('the attestation object is not a CBOR map');
  }
  const fmt = decoded.get('fmt');
  const authDataBuf = decoded.get('authData');
  const authData = parseAuthenticatorData(authDataBuf);
  const cd = parseClientData(clientDataJSON, 'webauthn.create');

  c.add('clientData.type is webauthn.create', cd.typeMatches, 'type=' + cd.json.type);
  c.add('challenge matches', cd.json.challenge === input.expectedChallenge,
        'got ' + cd.json.challenge);
  c.add('origin matches', cd.json.origin === input.expectedOrigin,
        'got ' + cd.json.origin + ', expected ' + input.expectedOrigin);
  c.add('rpIdHash is SHA-256 of the RP ID',
        authData.rpIdHash.equals(sha256(Buffer.from(input.expectedRpId, 'utf8'))),
        'rpId=' + input.expectedRpId);
  c.add('user presence', authData.flags.up, 'UP=' + authData.flags.up);
  if (input.requireUserVerification) {
    c.add('user verification', authData.flags.uv, 'UV=' + authData.flags.uv);
  }
  c.add('attested credential data present', authData.flags.at, 'AT=' + authData.flags.at);

  let key = null;
  if (authData.flags.at) {
    key = coseKeyToJwk(authData.credentialPublicKey);
  }

  const result = {
    ok: c.ok(),
    checks: c.checks,
    failed: c.failed(),
    fmt: fmt,
    aaguid: authData.aaguid ? authData.aaguid.toString('hex') : null,
    credentialId: authData.credentialId ? b64u(authData.credentialId) : null,
    publicKeyJwk: key ? key.jwk : null,
    algorithm: key ? key.alg : null,
    signCount: authData.signCount,
  };
  log.debug('Leaving verifyRegistration(). ok=' + result.ok);
  return result;
}

function verifyAssertion(input) {
  log.debug('Entering verifyAssertion().');
  const c = collect();
  const authDataBuf = Buffer.from(input.authenticatorData, 'base64url');
  const clientDataJSON = Buffer.from(input.clientDataJSON, 'base64url');
  const signature = Buffer.from(input.signature, 'base64url');
  const authData = parseAuthenticatorData(authDataBuf);
  const cd = parseClientData(clientDataJSON, 'webauthn.get');

  c.add('clientData.type is webauthn.get', cd.typeMatches, 'type=' + cd.json.type);
  c.add('challenge matches', cd.json.challenge === input.expectedChallenge,
        'got ' + cd.json.challenge);
  c.add('origin matches', cd.json.origin === input.expectedOrigin,
        'got ' + cd.json.origin + ', expected ' + input.expectedOrigin);
  c.add('rpIdHash is SHA-256 of the RP ID',
        authData.rpIdHash.equals(sha256(Buffer.from(input.expectedRpId, 'utf8'))),
        'rpId=' + input.expectedRpId);
  c.add('user presence', authData.flags.up, 'UP=' + authData.flags.up);
  if (input.requireUserVerification) {
    // Its own check, never folded into the signature: a UV-clear assertion is
    // correctly signed, and calling it a bad signature sends the operator after
    // the wrong thing entirely.
    c.add('user verification', authData.flags.uv, 'UV=' + authData.flags.uv);
  }
  if (typeof input.previousSignCount === 'number') {
    const advanced = authData.signCount === 0 && input.previousSignCount === 0
      ? true : authData.signCount > input.previousSignCount;
    c.add('signature counter advanced', advanced,
          'now ' + authData.signCount + ', was ' + input.previousSignCount);
  }

  // The signed message: raw authenticator data, then the HASH of the client data.
  const signedData = Buffer.concat([authDataBuf, sha256(clientDataJSON)]);
  let signatureValid = false;
  try {
    const keyObject = crypto.createPublicKey({ key: input.publicKeyJwk, format: 'jwk' });
    if (input.publicKeyJwk.kty === 'OKP') {
      signatureValid = crypto.verify(null, signedData, keyObject, signature);
    } else {
      // node takes an ECDSA signature in its native DER form, which is how it
      // arrives from the authenticator — no conversion, unlike Web Crypto.
      signatureValid = crypto.verify('sha256', signedData, keyObject, signature);
    }
  } catch (e) {
    // A key node cannot import, or a signature it cannot parse. Both are
    // verification failures rather than crashes, and the reason belongs in the
    // check's detail where the operator will see it.
    signatureValid = false;
    c.add('signature verifies', false, 'the key or signature could not be read: ' + e.message);
  }
  if (!c.checks.some(function (x) { return x.name === 'signature verifies'; })) {
    c.add('signature verifies', signatureValid,
          (input.publicKeyJwk.alg || input.publicKeyJwk.kty) + ' over ' + signedData.length + ' bytes');
  }

  const result = {
    ok: c.ok(),
    checks: c.checks,
    failed: c.failed(),
    signatureValid: signatureValid,
    signCount: authData.signCount,
    flags: authData.flags,
  };
  log.debug('Leaving verifyAssertion(). ok=' + result.ok);
  return result;
}

module.exports = {
  verifyRegistration,
  verifyAssertion,
  parseAuthenticatorData,
  coseKeyToJwk,
  cborDecodeFirst,
};
