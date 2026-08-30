'use strict';
//
// File: pq_jose.js
//
// ---------------------------------------------------------------------------
// POST-QUANTUM AND COMPOSITE JWS FOR THIS SERVICE — ML-DSA (FIPS 204, RFC
// 9964), SLH-DSA (FIPS 205) and the six composite ML-DSA + traditional
// algorithms of draft-ietf-jose-pq-composite-sigs.
//
// WHY THIS IS WRITTEN OUT HERE RATHER THAN VENDORED FROM THE DEBUGGER.
//
// This service exists to be the far end of the debugger's own JOSE code, and
// the value of that arrangement is INDEPENDENCE: the mock signs, the debugger
// reads, and a misunderstanding that both share is one neither can see. Every
// other cross-check in this project has that property — the mock's RSA and
// ECDSA go through node's OpenSSL while the debugger's go through Web Crypto
// and @noble, so a disagreement surfaces as a failure rather than as agreement.
//
// Copying `client/src/pqc.js` in here would have thrown that away. The two
// sides would then share one reading of the composite construction, agree with
// each other perfectly, and interoperate with nothing — which is precisely the
// class of defect this whole area keeps producing (a CEK split the wrong way
// round, an AL in bytes, a DER signature where R||S was meant).
//
// So the split is deliberate:
//
//   * THE PRIMITIVE is @noble/post-quantum. There is no second implementation
//     of ML-DSA or SLH-DSA to be had — node has none — so this is shared, and
//     the cross-check cannot say anything about the lattice itself.
//   * EVERYTHING AROUND IT is written here from the specifications: the AKP
//     JWK, the composite message, the key and signature layouts, and the
//     traditional half of every composite — which runs on **node's OpenSSL**
//     and not on the curve library the debugger uses.
//
// That is where the value is. The framing is what has been wrong every time.
//
// THE TRADITIONAL HALF NEEDS NO CURVE LIBRARY, and that is worth knowing
// because it looks impossible at first: a composite private key holds the raw
// EC SCALAR, and node will not build a key from a scalar alone — a JWK needs
// `x` and `y` as well. It will, however, read an RFC 5915 ECPrivateKey whose
// public key is OMITTED, and derive the point itself. `ecPrivateFromScalar()`
// below builds exactly that, which is how this file signs P-256 and P-384
// without importing anything.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const { ml_dsa44, ml_dsa65, ml_dsa87 } =
  require('@noble/post-quantum/ml-dsa.js');
const { slh_dsa_sha2_128s, slh_dsa_shake_128s } =
  require('@noble/post-quantum/slh-dsa.js');
const bunyan = require('bunyan');
const config = require('./config');

// The module's own logger, made the way common/crypto.js makes its own — NOT
// taken from helpers.js, which requires crypto.js, which requires this file.
const log = bunyan.createLogger({
  name: 'pq_jose',
  level: (function () {
    try {
      return config.value('global.logLevel') || 'info';
    } catch (e) {
      return 'info';
    }
  })()
});

// ---------------------------------------------------------------------------
// The traditional halves. `pubLen` is the length of the public key AS THE
// COMPOSITE CARRIES IT, which for the two EC curves is `x || y` — the
// uncompressed point with its 0x04 prefix removed. Carrying the prefix would
// be a public key every implementation reads and none agrees on the length of.
// ---------------------------------------------------------------------------
const TRAD = {
  ES256: { kind: 'ec', curve: 'prime256v1', hash: 'sha256',
           oid: [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
           pubLen: 64, privLen: 32, sigLen: 64 },
  ES384: { kind: 'ec', curve: 'secp384r1', hash: 'sha384',
           oid: [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
           pubLen: 96, privLen: 48, sigLen: 96 },
  Ed25519: { kind: 'eddsa', curve: 'ed25519',
             pkcs8Prefix: '302e020100300506032b657004220420',
             spkiPrefix: '302a300506032b6570032100',
             pubLen: 32, privLen: 32, sigLen: 64 },
  Ed448: { kind: 'eddsa', curve: 'ed448',
           pkcs8Prefix: '3047020100300506032b6571043b0439',
           spkiPrefix: '3043300506032b6571033a00',
           pubLen: 57, privLen: 57, sigLen: 114 }
};

// draft-ietf-jose-pq-composite-sigs. The label is the domain separator that
// goes into the composite message AND into the ML-DSA context string, which is
// what stops a signature made for one composite being replayed as another.
const COMPOSITES = {
  'ML-DSA-44-ES256': { ml: 'ML-DSA-44', trad: 'ES256', ph: 'sha256',
                       label: 'COMPSIG-MLDSA44-ECDSA-P256-SHA256' },
  'ML-DSA-65-ES256': { ml: 'ML-DSA-65', trad: 'ES256', ph: 'sha512',
                       label: 'COMPSIG-MLDSA65-ECDSA-P256-SHA512' },
  'ML-DSA-87-ES384': { ml: 'ML-DSA-87', trad: 'ES384', ph: 'sha512',
                       label: 'COMPSIG-MLDSA87-ECDSA-P384-SHA512' },
  'ML-DSA-44-Ed25519': { ml: 'ML-DSA-44', trad: 'Ed25519', ph: 'sha512',
                         label: 'COMPSIG-MLDSA44-Ed25519-SHA512' },
  'ML-DSA-65-Ed25519': { ml: 'ML-DSA-65', trad: 'Ed25519', ph: 'sha512',
                         label: 'COMPSIG-MLDSA65-Ed25519-SHA512' },
  'ML-DSA-87-Ed448': { ml: 'ML-DSA-87', trad: 'Ed448', ph: 'shake256-64',
                       label: 'COMPSIG-MLDSA87-Ed448-SHAKE256' }
};

const COMPOSITE_PREFIX = Buffer.from('CompositeAlgorithmSignatures2025',
                                     'utf8');

const ML = { 'ML-DSA-44': ml_dsa44, 'ML-DSA-65': ml_dsa65,
             'ML-DSA-87': ml_dsa87 };
const ML_SIZES = { 'ML-DSA-44': { pub: 1312, sig: 2420 },
                   'ML-DSA-65': { pub: 1952, sig: 3309 },
                   'ML-DSA-87': { pub: 2592, sig: 4627 } };
const SLH = { 'SLH-DSA-SHA2-128s': slh_dsa_sha2_128s,
              'SLH-DSA-SHAKE-128s': slh_dsa_shake_128s };

// Every algorithm this file speaks, in the order they are offered.
const PQ_ALGS = Object.keys(ML)
  .concat(Object.keys(SLH))
  .concat(Object.keys(COMPOSITES));

function isPqAlg(alg) {
  log.debug('Entering isPqAlg(). alg=' + alg);
  log.debug('Leaving isPqAlg().');
  return PQ_ALGS.indexOf(alg) !== -1;
}

// ---------------------------------------------------------------------------
// The prehash a composite applies to the message before either half signs it.
// SHAKE256 with a 64-byte output for the Ed448 composite, a plain digest
// otherwise. Node has SHAKE256 as a hash whose length is given in options.
// ---------------------------------------------------------------------------
function prehash(name, message) {
  log.debug('Entering prehash(). ' + name);
  if (name === 'shake256-64') {
    log.debug('Leaving prehash(). SHAKE256/64.');
    return nodeCrypto.createHash('shake256', { outputLength: 64 })
      .update(message).digest();
  }
  log.debug('Leaving prehash().');
  return nodeCrypto.createHash(name).update(message).digest();
}

// M' = "CompositeAlgorithmSignatures2025" || label || 0x00 || PH(message)
function compositeMessage(cfg, message) {
  log.debug('Entering compositeMessage().');
  const out = Buffer.concat([COMPOSITE_PREFIX,
                             Buffer.from(cfg.label, 'utf8'),
                             Buffer.from([0x00]),
                             prehash(cfg.ph, message)]);
  log.debug('Leaving compositeMessage(). ' + out.length + ' bytes.');
  return out;
}

// ---------------------------------------------------------------------------
// An EC private key from the raw scalar alone, with no curve library.
//
// RFC 5915's ECPrivateKey makes the public key OPTIONAL, and OpenSSL will
// derive it. So this hand-builds:
//
//   PKCS#8 ::= SEQUENCE { version 0, AlgorithmIdentifier, privateKey OCTET
//                         STRING containing ECPrivateKey }
//   ECPrivateKey ::= SEQUENCE { version 1, privateKey OCTET STRING }
//
// Every length here is short-form, which is correct because none of these
// structures reaches 128 bytes for P-256 or P-384.
// ---------------------------------------------------------------------------
function der(tag, contents) {
  log.debug('Entering der().');
  if (contents.length > 127) {
    log.debug('Leaving der(). Long form needed.');
    throw new Error('pq_jose: a DER element of ' + contents.length +
      ' bytes needs the long length form, which this builder does not write ' +
      '— it is only ever used for EC key structures, which are shorter.');
  }
  log.debug('Leaving der().');
  return Buffer.concat([Buffer.from([tag, contents.length]), contents]);
}

function ecPrivateFromScalar(spec, scalar) {
  log.debug('Entering ecPrivateFromScalar().');
  const ecPrivateKey = der(0x30, Buffer.concat([
    der(0x02, Buffer.from([0x01])),
    der(0x04, Buffer.from(scalar))
  ]));
  const algId = der(0x30, Buffer.concat([
    Buffer.from([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
    Buffer.from(spec.oid)
  ]));
  const pkcs8 = der(0x30, Buffer.concat([
    der(0x02, Buffer.from([0x00])), algId, der(0x04, ecPrivateKey)
  ]));
  log.debug('Leaving ecPrivateFromScalar().');
  return nodeCrypto.createPrivateKey({ key: pkcs8, format: 'der',
                                       type: 'pkcs8' });
}

function ecPublicFromXY(spec, xy) {
  log.debug('Entering ecPublicFromXY().');
  const half = spec.pubLen / 2;
  const jwk = { kty: 'EC',
                crv: spec.curve === 'prime256v1' ? 'P-256' : 'P-384',
                x: Buffer.from(xy.subarray(0, half)).toString('base64url'),
                y: Buffer.from(xy.subarray(half)).toString('base64url') };
  log.debug('Leaving ecPublicFromXY().');
  return nodeCrypto.createPublicKey({ key: jwk, format: 'jwk' });
}

function edPrivateFromSeed(spec, seed) {
  log.debug('Entering edPrivateFromSeed().');
  const key = nodeCrypto.createPrivateKey({
    key: Buffer.concat([Buffer.from(spec.pkcs8Prefix, 'hex'),
                        Buffer.from(seed)]),
    format: 'der', type: 'pkcs8' });
  log.debug('Leaving edPrivateFromSeed().');
  return key;
}

function edPublicFromRaw(spec, raw) {
  log.debug('Entering edPublicFromRaw().');
  const key = nodeCrypto.createPublicKey({
    key: Buffer.concat([Buffer.from(spec.spkiPrefix, 'hex'),
                        Buffer.from(raw)]),
    format: 'der', type: 'spki' });
  log.debug('Leaving edPublicFromRaw().');
  return key;
}

// The traditional half's public key AS THE COMPOSITE CARRIES IT.
function tradPublicKey(spec, priv) {
  log.debug('Entering tradPublicKey(). ' + spec.kind);
  if (spec.kind === 'ec') {
    const jwk = nodeCrypto.createPublicKey(ecPrivateFromScalar(spec, priv))
      .export({ format: 'jwk' });
    log.debug('Leaving tradPublicKey(). EC x||y.');
    return Buffer.concat([Buffer.from(jwk.x, 'base64url'),
                          Buffer.from(jwk.y, 'base64url')]);
  }
  const raw = nodeCrypto.createPublicKey(edPrivateFromSeed(spec, priv))
    .export({ format: 'jwk' });
  log.debug('Leaving tradPublicKey(). EdDSA.');
  return Buffer.from(raw.x, 'base64url');
}

function tradSign(spec, priv, mPrime) {
  log.debug('Entering tradSign(). ' + spec.kind);
  if (spec.kind === 'ec') {
    // R||S and not DER — RFC 7518 section 3.4's form, which is what the
    // composite concatenates.
    log.debug('Leaving tradSign(). ECDSA.');
    return nodeCrypto.sign(spec.hash, mPrime,
      { key: ecPrivateFromScalar(spec, priv), dsaEncoding: 'ieee-p1363' });
  }
  log.debug('Leaving tradSign(). EdDSA.');
  return nodeCrypto.sign(null, mPrime, edPrivateFromSeed(spec, priv));
}

function tradVerify(spec, pub, mPrime, signature) {
  log.debug('Entering tradVerify(). ' + spec.kind);
  if (spec.kind === 'ec') {
    log.debug('Leaving tradVerify(). ECDSA.');
    return nodeCrypto.verify(spec.hash, mPrime,
      { key: ecPublicFromXY(spec, pub), dsaEncoding: 'ieee-p1363' },
      signature);
  }
  log.debug('Leaving tradVerify(). EdDSA.');
  return nodeCrypto.verify(null, mPrime, edPublicFromRaw(spec, pub),
                           signature);
}

// ---------------------------------------------------------------------------
// Key generation, signing and verification, by JOSE `alg`.
//
// AN ML-DSA PRIVATE KEY IS THE 32-BYTE SEED and not the expanded secret key —
// RFC 9964 section 3.2 says so, and it is why `priv` on one of these JWKs is
// so much smaller than a reader expects. The expanded key is derived from it
// every time, which costs nothing and keeps the JWK to the size the RFC
// defines. SLH-DSA's `priv` is its own secret key, which has no seed form.
// ---------------------------------------------------------------------------
function generate(alg) {
  log.debug('Entering generate(). alg=' + alg);
  if (ML[alg]) {
    const seed = nodeCrypto.randomBytes(32);
    const kp = ML[alg].keygen(seed);
    log.debug('Leaving generate(). ML-DSA.');
    return { pub: Buffer.from(kp.publicKey), priv: seed };
  }
  if (SLH[alg]) {
    const kp = SLH[alg].keygen();
    log.debug('Leaving generate(). SLH-DSA.');
    return { pub: Buffer.from(kp.publicKey),
             priv: Buffer.from(kp.secretKey) };
  }
  const cfg = COMPOSITES[alg];
  if (!cfg) {
    log.debug('Leaving generate(). Unknown algorithm.');
    throw new Error('pq_jose: ' + alg + ' is not one of ' +
      PQ_ALGS.join(', ') + '.');
  }
  const spec = TRAD[cfg.trad];
  const seed = nodeCrypto.randomBytes(32);
  const mlKp = ML[cfg.ml].keygen(seed);
  // The traditional scalar. For EC it must be a valid one, and generating it
  // through node rather than from random bytes is what guarantees that — a
  // scalar at or above the group order is rejected by OpenSSL, rarely and
  // unreproducibly.
  const tradPriv = spec.kind === 'ec'
    ? Buffer.from(nodeCrypto.generateKeyPairSync('ec',
        { namedCurve: spec.curve }).privateKey.export({ format: 'jwk' }).d,
        'base64url')
    : Buffer.from(nodeCrypto.generateKeyPairSync(spec.curve)
        .privateKey.export({ format: 'jwk' }).d, 'base64url');
  log.debug('Leaving generate(). Composite ' + alg + '.');
  return {
    // pub = mldsaPK || tradPK, priv = 32-byte seed || tradSK.
    pub: Buffer.concat([Buffer.from(mlKp.publicKey),
                        tradPublicKey(spec, tradPriv)]),
    priv: Buffer.concat([seed, tradPriv])
  };
}

function sign(alg, priv, message) {
  log.debug('Entering sign(). alg=' + alg);
  const msg = Buffer.from(message);
  if (ML[alg]) {
    if (priv.length !== 32) {
      log.debug('Leaving sign(). Wrong seed length.');
      throw new Error('an ML-DSA "priv" is the 32-byte seed of RFC 9964 ' +
        'section 3.2; this one is ' + priv.length + ' bytes.');
    }
    const kp = ML[alg].keygen(Buffer.from(priv));
    log.debug('Leaving sign(). ML-DSA.');
    return Buffer.from(ML[alg].sign(kp.secretKey, msg));
  }
  if (SLH[alg]) {
    log.debug('Leaving sign(). SLH-DSA.');
    return Buffer.from(SLH[alg].sign(Buffer.from(priv), msg));
  }
  const cfg = COMPOSITES[alg];
  if (!cfg) {
    throw new Error('pq_jose: cannot sign with ' + alg + '.');
  }
  const spec = TRAD[cfg.trad];
  if (priv.length !== 32 + spec.privLen) {
    log.debug('Leaving sign(). Wrong composite key length.');
    throw new Error('a ' + alg + ' private key is ' + (32 + spec.privLen) +
      ' bytes — a 32-byte ML-DSA seed followed by a ' + spec.privLen +
      '-byte ' + cfg.trad + ' key; this one is ' + priv.length + '.');
  }
  const seed = Buffer.from(priv.subarray(0, 32));
  const tradPriv = Buffer.from(priv.subarray(32));
  const mPrime = compositeMessage(cfg, msg);
  const mlKp = ML[cfg.ml].keygen(seed);
  // The ML-DSA half signs M' WITH THE LABEL AS ITS CONTEXT STRING. Omitting
  // the context produces a signature that verifies against an implementation
  // that also omits it and against nothing else.
  const mlSig = ML[cfg.ml].sign(mlKp.secretKey, mPrime,
                                Buffer.from(cfg.label, 'utf8'));
  log.debug('Leaving sign(). Composite ' + alg + '.');
  return Buffer.concat([Buffer.from(mlSig), tradSign(spec, tradPriv, mPrime)]);
}

function verify(alg, pub, message, signature) {
  log.debug('Entering verify(). alg=' + alg);
  const msg = Buffer.from(message);
  const sig = Buffer.from(signature);
  if (ML[alg]) {
    log.debug('Leaving verify(). ML-DSA.');
    return ML[alg].verify(Buffer.from(pub), msg, sig);
  }
  if (SLH[alg]) {
    log.debug('Leaving verify(). SLH-DSA.');
    return SLH[alg].verify(Buffer.from(pub), msg, sig);
  }
  const cfg = COMPOSITES[alg];
  if (!cfg) {
    throw new Error('pq_jose: cannot verify ' + alg + '.');
  }
  const spec = TRAD[cfg.trad];
  const sizes = ML_SIZES[cfg.ml];
  if (sig.length !== sizes.sig + spec.sigLen ||
      pub.length !== sizes.pub + spec.pubLen) {
    log.debug('Leaving verify(). Wrong length.');
    return false;
  }
  const mPrime = compositeMessage(cfg, msg);
  // BOTH HALVES MUST VERIFY. A composite where either alone were enough would
  // be weaker than its weaker half, which is the opposite of the point.
  const mlOk = ML[cfg.ml].verify(Buffer.from(pub.subarray(0, sizes.pub)),
    mPrime, Buffer.from(sig.subarray(0, sizes.sig)),
    Buffer.from(cfg.label, 'utf8'));
  const tradOk = tradVerify(spec, Buffer.from(pub.subarray(sizes.pub)),
    mPrime, Buffer.from(sig.subarray(sizes.sig)));
  log.debug('Leaving verify(). ml=' + mlOk + ', trad=' + tradOk);
  return mlOk && tradOk;
}

// ---------------------------------------------------------------------------
// THE SAME THREE OPERATIONS, OFF THIS PROCESS'S THREAD.
//
// Everything above is synchronous and stays that way — it is a specification
// written out, and where it RUNS is not a property of the specification. What
// is below is the other question: this service is one node process owning six
// listener families on one thread, and an SLH-DSA signature takes SECONDS
// during which it answers nobody at all, the KDC on port 88 included. See
// common/worker.js, which is where the measurements are.
//
// So a pool of child processes computes them, and these three are how a caller
// asks for that. They resolve with exactly what their synchronous namesakes
// return, because the pool runs THE SAME FUNCTIONS — `common/worker.js`'s job
// table calls sign(), verify() and generate() above, in a child, and hands the
// bytes back. There is no second implementation to disagree with this one.
//
// ---------------------------------------------------------------------------
// THE POOL IS HANDED TO THIS FILE RATHER THAN REQUIRED BY IT, AND THAT IS NOT
// STYLE.
//
// `worker_pool.js` requires `worker.js`, which requires THIS FILE — so a
// require in the obvious direction closes a cycle, and a cycle in node does not
// fail loudly: it hands back a half-initialised module whose exports are
// undefined, and the symptom arrives later as something that is not a function.
// That is rule 2 in the root CLAUDE.md, and rule 3e's test for when an inverted
// slot is the right answer is exactly this case.
//
// It buys a second thing that matters more than the cycle. **A WORKER PROCESS
// NEVER FILLS THIS SLOT** — a child requires this file and nothing else of the
// service — so `signAsync()` inside a worker computes in the worker, which is
// what a worker is for. A lazy require would have let a child fork a pool of
// its own, recursively, and the first symptom would have been a machine out of
// processes.
//
// `common/crypto.js` fills it, because that is the module that routes an `alg`
// to this file in the first place.
// ---------------------------------------------------------------------------
let workerPool = null;

function setWorkerPool(pool) {
  log.debug('Entering setWorkerPool(). pool=' + (pool ? 'given' : 'null'));
  workerPool = pool;
  log.debug('Leaving setWorkerPool().');
}

// With no pool — a worker process, a test that required this file on its own,
// or `workers.count` at 0 — the work is done HERE and the promise is already
// resolved when it is returned. That is the same answer, arrived at by
// blocking, and it is why every caller can be written one way.
function withoutPool(compute) {
  log.debug('Entering withoutPool().');
  try {
    const value = compute();
    log.debug('Leaving withoutPool(). Computed in this process.');
    return Promise.resolve(value);
  } catch (e) {
    log.debug('Leaving withoutPool(). It threw.');
    return Promise.reject(e);
  }
}

// `opts.session` names an authenticated session, so that one session's
// signatures go to one worker. It is a routing preference and never a
// correctness requirement — a worker remembers nothing — so a caller with no
// session to name simply omits it.
function signAsync(alg, priv, message, opts) {
  log.debug('Entering signAsync(). alg=' + alg);
  if (!workerPool) {
    log.debug('Leaving signAsync(). No pool.');
    return withoutPool(function () { return sign(alg, priv, message); });
  }
  log.debug('Leaving signAsync(). Handed to the pool.');
  return workerPool.run('pq.sign',
    { alg: alg, priv: Buffer.from(priv), message: Buffer.from(message) },
    opts).then(function (result) {
      return result.signature;
    });
}

function verifyAsync(alg, pub, message, signature, opts) {
  log.debug('Entering verifyAsync(). alg=' + alg);
  if (!workerPool) {
    log.debug('Leaving verifyAsync(). No pool.');
    return withoutPool(function () {
      return verify(alg, pub, message, signature);
    });
  }
  log.debug('Leaving verifyAsync(). Handed to the pool.');
  return workerPool.run('pq.verify',
    { alg: alg, pub: Buffer.from(pub), message: Buffer.from(message),
      signature: Buffer.from(signature) },
    opts).then(function (result) {
      return result.ok;
    });
}

function generateAsync(alg, opts) {
  log.debug('Entering generateAsync(). alg=' + alg);
  if (!workerPool) {
    log.debug('Leaving generateAsync(). No pool.');
    return withoutPool(function () { return generate(alg); });
  }
  log.debug('Leaving generateAsync(). Handed to the pool.');
  return workerPool.run('pq.generate', { alg: alg }, opts);
}

// RFC 9964 section 3: the key type is AKP, the parameters are `pub` and
// `priv`, and `alg` is REQUIRED — an AKP JWK without it names no algorithm
// and there is no way to guess one from the key material.
function akpPublicJwk(alg, pub, kid) {
  log.debug('Entering akpPublicJwk(). alg=' + alg);
  const jwk = { kty: 'AKP', alg: alg, use: 'sig',
                pub: Buffer.from(pub).toString('base64url') };
  if (kid) {
    jwk.kid = kid;
  }
  log.debug('Leaving akpPublicJwk().');
  return jwk;
}

module.exports = {
  PQ_ALGS: PQ_ALGS,
  COMPOSITES: COMPOSITES,
  TRAD: TRAD,
  isPqAlg: isPqAlg,
  generate: generate,
  sign: sign,
  verify: verify,
  akpPublicJwk: akpPublicJwk,
  compositeMessage: compositeMessage,
  setWorkerPool: setWorkerPool,
  signAsync: signAsync,
  verifyAsync: verifyAsync,
  generateAsync: generateAsync
};
