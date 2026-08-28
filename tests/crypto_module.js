'use strict';
//
// File: crypto_module.js
//
// ===========================================================================
// THE ONE CRYPTO MODULE'S CONTRACTS.
//
// `common/crypto.js` replaced six XML signers, four XML signature verifiers,
// two hand-rolled JWE halves, three RFC 7638 thumbprints, two self-signed
// certificate builders and two constant-time comparisons on 2026-08-27. This
// file is what stops that becoming one shared way of being wrong.
//
// **WHY IT IS HERE AND NOT IN THE PARENT SUITE**, which is the question
// `tests/CLAUDE.md` says to answer first. The central assertion is that a
// document this service signs is accepted by an INDEPENDENT implementation —
// `xml-crypto`, which is what all six signers used until this change — and
// there is no way to ask that of a running service over HTTP. You would have to
// import xml-crypto into the test and hand it the document, which is exactly
// this file, in process, with no port. The same is true of the reverse
// direction, of the algorithm tables, and of the three thumbprints agreeing:
// each compares one implementation against another rather than observing a
// response.
//
// The PROTOCOL half — that /saml2/metadata is signed, that a Browser/POST
// response carries two verifiable signatures — is a different test and belongs
// over there. It is not written yet; the root CLAUDE.md's "Tests" section says
// so rather than implying it is covered.
//
// **`xml-crypto` IS KEPT AS A DEPENDENCY FOR THIS FILE AND FOR NOTHING ELSE.**
// No module in the service requires it any more. Removing it would save a
// package and cost the only independent reading of XMLDSIG in this repository,
// which is the reading that makes the interop assertions mean anything — if
// both ends of the comparison came from one implementation, a shared
// misunderstanding would pass and interoperate with nobody. That is the rule
// `tests/sts_dpop.js` states over in the parent suite, applied here.
// ===========================================================================

const crypto = require('../common/crypto');
const { SignedXml } = require('xml-crypto');
const { DOMParser } = require('@xmldom/xmldom');
const forge = require('node-forge');
const nodeCrypto = require('crypto');

// ---------------------------------------------------------------------------
// THE SEVEN DOCUMENTS THIS SERVICE SIGNS, one per call site that used to have a
// signer of its own, with the placement each requires. The placement is not
// decoration: a signature in the wrong position produces a document that
// verifies and that a strict parser rejects, which is the worst of both.
// ---------------------------------------------------------------------------
const NS_SAMLP2 = 'urn:oasis:names:tc:SAML:2.0:protocol';
const NS_SAML2 = 'urn:oasis:names:tc:SAML:2.0:assertion';
const NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata';

const DOCUMENTS = [
  { name: 'SAML 2.0 Assertion (was saml2.js)',
    root: 'Assertion', idAttr: 'ID', id: '_a2',
    placement: crypto.PLACEMENT.AFTER_ISSUER,
    xml: '<saml:Assertion xmlns:saml="' + NS_SAML2 + '" ID="_a2" Version="2.0">' +
         '<saml:Issuer>sts</saml:Issuer><saml:Subject/></saml:Assertion>' },
  { name: 'SAML 2.0 Response (was saml2_sso.js)',
    root: 'Response', idAttr: 'ID', id: '_r2',
    placement: crypto.PLACEMENT.AFTER_ISSUER,
    xml: '<samlp:Response xmlns:samlp="' + NS_SAMLP2 + '" xmlns:saml="' + NS_SAML2 + '" ID="_r2">' +
         '<saml:Issuer>sts</saml:Issuer><samlp:Status/></samlp:Response>' },
  { name: 'SAML 2.0 metadata (was saml2_sso.js)',
    root: 'EntityDescriptor', idAttr: 'ID', id: '_m2',
    placement: crypto.PLACEMENT.FIRST,
    xml: '<md:EntityDescriptor xmlns:md="' + NS_MD + '" ID="_m2" entityID="urn:sts">' +
         '<md:IDPSSODescriptor/></md:EntityDescriptor>' },
  { name: 'SAML 1.1 Assertion (was saml11.js)',
    root: 'Assertion', idAttr: 'AssertionID', id: '_a1',
    placement: crypto.PLACEMENT.LAST,
    xml: '<Assertion xmlns="urn:oasis:names:tc:SAML:1.0:assertion" AssertionID="_a1" ' +
         'Issuer="sts" MajorVersion="1" MinorVersion="1"><Conditions/></Assertion>' },
  { name: 'SAML 1.1 Response (was saml11_sso.js)',
    root: 'Response', idAttr: 'ResponseID', id: '_r1',
    placement: crypto.PLACEMENT.FIRST,
    xml: '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" ResponseID="_r1">' +
         '<samlp:Status/></samlp:Response>' },
  { name: 'WS-Federation metadata (was wsfed.js)',
    root: 'EntityDescriptor', idAttr: 'ID', id: '_wf',
    placement: crypto.PLACEMENT.FIRST,
    xml: '<EntityDescriptor xmlns="' + NS_MD + '" ID="_wf" entityID="urn:sts">' +
         '<RoleDescriptor/></EntityDescriptor>' },
  { name: 'SAML 2.0 AuthnRequest (was federation_sp.js)',
    root: 'AuthnRequest', idAttr: 'ID', id: '_q1',
    placement: crypto.PLACEMENT.AFTER_ISSUER,
    xml: '<samlp:AuthnRequest xmlns:samlp="' + NS_SAMLP2 + '" xmlns:saml="' + NS_SAML2 + '" ID="_q1">' +
         '<saml:Issuer>sts</saml:Issuer><samlp:NameIDPolicy AllowCreate="true"/></samlp:AuthnRequest>' }
];

// xml-crypto's own signer, as each of the six call sites drove it before this
// change. Kept so the BACKWARD direction can be asserted: a document signed the
// old way must still verify, or an upgrade would reject artifacts already in
// flight.
function signTheOldWay(doc, keys) {
  const options = { privateKey: keys.privateKeyPem, publicCert: keys.certPem };
  // The `idAttribute` dance the old call sites had to get right, reproduced
  // exactly: named for SAML 1.1, and NEVER for SAML 2.0's `ID`, which is
  // already on xml-crypto's default list.
  if (doc.idAttr !== 'ID') {
    options.idAttribute = doc.idAttr;
  }
  const sig = new SignedXml(options);
  sig.signatureAlgorithm = crypto.SIG_RSA_SHA256;
  sig.canonicalizationAlgorithm = crypto.C14N_EXCLUSIVE;
  sig.addReference({
    xpath: "/*[local-name(.)='" + doc.root + "']",
    transforms: [crypto.TRANSFORM_ENVELOPED, crypto.C14N_EXCLUSIVE],
    digestAlgorithm: crypto.DIGEST_SHA256,
    uri: '#' + doc.id
  });
  const where = doc.placement === crypto.PLACEMENT.FIRST
    ? { reference: "/*[local-name(.)='" + doc.root + "']", action: 'prepend' }
    : (doc.placement === crypto.PLACEMENT.LAST
      ? { reference: "/*[local-name(.)='" + doc.root + "']", action: 'append' }
      : { reference: "/*[local-name(.)='" + doc.root + "']/*[local-name(.)='Issuer']",
          action: 'after' });
  sig.computeSignature(doc.xml, { location: where });
  return sig.getSignedXml();
}

// xml-crypto verifying what this service produced. This is the assertion the
// whole file exists for.
function verifiesUnderXmlCrypto(signed, doc, keys) {
  const parsed = new DOMParser().parseFromString(signed, 'text/xml');
  const sigEl = parsed.getElementsByTagNameNS(crypto.DS_NS, 'Signature')[0];
  if (!sigEl) {
    return { ok: false, why: 'there is no ds:Signature in the output at all' };
  }
  const options = { publicCert: keys.certPem };
  if (doc.idAttr !== 'ID') {
    options.idAttribute = doc.idAttr;
  }
  const check = new SignedXml(options);
  check.loadSignature(sigEl);
  try {
    return { ok: !!check.checkSignature(signed), why: 'the signature did not verify' };
  } catch (e) {
    return { ok: false, why: e.message };
  }
}

module.exports = {
  name: 'crypto_module',
  describe: 'common/crypto.js: one signer, one verifier, one cipher — checked ' +
            'against xml-crypto in both directions',

  run: function (t) {
    // ONE key pair for the whole file. RSA-2048 keygen in forge is about a
    // tenth of a second and this suite is meant to stay under a second.
    const keys = crypto.selfSignedRsaCertificate({ commonName: 'sts-test', serialNumber: '02' });
    const other = crypto.selfSignedRsaCertificate({ commonName: 'somebody-else' });

    // -----------------------------------------------------------------------
    t.log.info('A. every document this service signs is accepted by xml-crypto');
    // -----------------------------------------------------------------------
    DOCUMENTS.forEach(function (doc) {
      const signed = crypto.signXml(doc.xml, {
        privateKeyPem: keys.privateKeyPem,
        certPem: keys.certPem,
        placement: doc.placement,
        what: doc.name
      });
      const verdict = verifiesUnderXmlCrypto(signed, doc, keys);
      t.check(verdict.ok, doc.name + ' verifies under an independent implementation',
              verdict.ok ? '' : verdict.why);

      // **THE `Id="_0"` DEFECT, WHICH IS THE REASON THIS MODULE EXISTS.**
      // xml-crypto could not find `AssertionID` or `ResponseID`, so it invented
      // an `Id="_0"` attribute the schema does not have and referenced THAT.
      // It verified anyway, which is why it survived for months. The shared
      // signer resolves every SAML id spelling, so there is nothing to invent.
      t.check(!/Id="_0"/.test(signed),
              '  and carries no invented Id="_0" — the attribute the schema does not have');

      // The reference names the element's REAL id, whatever it is called.
      const uri = /URI="([^"]*)"/.exec(signed);
      t.equal(uri && uri[1], '#' + doc.id,
              '  and its reference names the real ' + doc.idAttr);

      // The placement, which is schema-mandated per document.
      const body = signed.replace(/^<\?xml[^>]*\?>/, '');
      if (doc.placement === crypto.PLACEMENT.FIRST) {
        t.check(/^<[^>]*>\s*<(ds:)?Signature/.test(body),
                '  and the signature is FIRST, as metadata requires');
      } else if (doc.placement === crypto.PLACEMENT.AFTER_ISSUER) {
        t.check(/<\/(saml:)?Issuer>\s*<(ds:)?Signature/.test(body),
                '  and the signature follows <Issuer>, as the schema requires');
      } else {
        t.check(/<\/(ds:)?Signature>\s*<\/[^>]+>\s*$/.test(body.trim()),
                '  and the signature is LAST, as SAML 1.1 requires');
      }
    });

    // -----------------------------------------------------------------------
    t.log.info('B. and a document signed the OLD way still verifies here');
    // -----------------------------------------------------------------------
    DOCUMENTS.forEach(function (doc) {
      const signed = signTheOldWay(doc, keys);
      const result = crypto.verifyXmlSignature(signed, { element: doc.root, certPem: keys.certPem });
      t.check(result.ok, doc.name + ' signed by xml-crypto is accepted', result.why);
    });

    // -----------------------------------------------------------------------
    t.log.info('C. the refusals — a verifier that only ever says yes guards nothing');
    // -----------------------------------------------------------------------
    const doc2 = DOCUMENTS[0];
    const signed2 = crypto.signXml(doc2.xml, {
      privateKeyPem: keys.privateKeyPem, certPem: keys.certPem, placement: doc2.placement });

    const wrongKey = crypto.verifyXmlSignature(signed2, { element: 'Assertion', certPem: other.certPem });
    t.check(!wrongKey.ok, 'a signature made by a different key is refused', wrongKey.why);
    t.check(wrongKey.present, '  and is reported as PRESENT rather than missing — a different fact');

    const tampered = crypto.verifyXmlSignature(
      signed2.replace('<saml:Subject/>', '<saml:Subject><saml:NameID>mallory</saml:NameID></saml:Subject>'),
      { element: 'Assertion', certPem: keys.certPem });
    t.check(!tampered.ok, 'an altered document is refused', tampered.why);
    t.check(tampered.signatureValid && !tampered.referencesValid,
            '  and the reason distinguishes a good signature over changed content from a bad signature');

    const unsigned = crypto.verifyXmlSignature(doc2.xml, { element: 'Assertion', certPem: keys.certPem });
    t.check(!unsigned.ok && !unsigned.present, 'an unsigned element is refused as NOT PRESENT');

    const absent = crypto.verifyXmlSignature(signed2, { element: 'LogoutRequest', certPem: keys.certPem });
    t.check(!absent.ok && !absent.present, 'an element that is not in the document is refused');
    t.check(/no <LogoutRequest> at all/.test(absent.why || ''),
            '  and says the element is absent rather than that it is unsigned', absent.why);

    // -----------------------------------------------------------------------
    t.log.info('D. TWO SIGNATURES IN ONE DOCUMENT — the case that was wrong before');
    // -----------------------------------------------------------------------
    // A SAML 1.1 Browser/POST response is two signed documents in one. Three of
    // the four verifiers this replaced took the FIRST <ds:Signature> in the
    // document, so asking "is the Response signed by us" could be answered
    // about the ASSERTION — a confident yes about a different element, which is
    // one step from accepting a response whose assertion was swapped.
    const innerAssertion = crypto.signXml(
      '<Assertion xmlns="urn:oasis:names:tc:SAML:1.0:assertion" AssertionID="_inner" Issuer="sts">' +
      '<Conditions/></Assertion>',
      { privateKeyPem: keys.privateKeyPem, certPem: keys.certPem, placement: crypto.PLACEMENT.LAST })
      .replace(/^<\?xml[^>]*\?>/, '');
    const bothSigned = crypto.signXml(
      '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" ResponseID="_outer">' +
      '<samlp:Status/>' + innerAssertion + '</samlp:Response>',
      { privateKeyPem: keys.privateKeyPem, certPem: keys.certPem,
        placement: crypto.PLACEMENT.LAST, refUri: '#_outer' });

    t.equal((bothSigned.match(/<ds:Signature[ >]/g) || []).length, 2,
            'the document really does carry two signatures');

    const outer = crypto.verifyXmlSignature(bothSigned, { element: 'Response', certPem: keys.certPem });
    const inner = crypto.verifyXmlSignature(bothSigned, { element: 'Assertion', certPem: keys.certPem });
    t.check(outer.ok, 'the RESPONSE signature verifies', outer.why);
    t.equal(outer.referenceUri, '#_outer', '  and it is the one referencing the ResponseID');
    t.check(inner.ok, 'the ASSERTION signature verifies', inner.why);
    t.equal(inner.referenceUri, '#_inner', '  and it is the one referencing the AssertionID');
    t.check(outer.referenceUri !== inner.referenceUri,
            'THE TWO ANSWERS ARE ABOUT DIFFERENT ELEMENTS — the whole point of naming one');

    // What a first-signature verifier concludes about this same document: ONE
    // answer, whichever element was asked about. Asserted rather than described,
    // so that a future "simplification" back to that shape goes red here.
    const naive = crypto.xmldsig.verifyXml(bothSigned, { certPem: keys.certPem });
    // The Response is signed LAST here, so the first signature in document
    // order is the ASSERTION'S. A first-signature verifier therefore reports a
    // confident `valid: true` about the assertion no matter which element was
    // asked about — so asking it "is the RESPONSE signed by us" is answered
    // about a different element entirely.
    t.check(naive.valid, 'a first-signature verifier reports valid=true on this document');
    t.equal(naive.references[0].uri, inner.referenceUri,
            '  and its one answer is always about the assertion, whatever was asked');
    t.check(naive.references[0].uri !== outer.referenceUri,
            'SO ASKING IT ABOUT THE RESPONSE GETS AN ANSWER ABOUT THE ASSERTION — ' +
            'the defect naming the element removes',
            'the Response references ' + outer.referenceUri + '; it answered about ' +
            naive.references[0].uri);

    // Signature wrapping: a signature whose reference names a DIFFERENT element
    // must be refused even though it verifies perfectly on its own terms. None
    // of the four implementations this replaced checked this at all.
    const wrapped = bothSigned.replace('URI="#_outer"', 'URI="#_inner"');
    const wrapVerdict = crypto.verifyXmlSignature(wrapped, { element: 'Response', certPem: keys.certPem });
    t.check(!wrapVerdict.ok,
            'A SIGNATURE REFERENCING A DIFFERENT ELEMENT IS REFUSED (signature wrapping)',
            wrapVerdict.why);
    t.check(/references "#_inner"/.test(wrapVerdict.why || ''),
            '  and the refusal names what it referenced instead', wrapVerdict.why);

    // -----------------------------------------------------------------------
    t.log.info('E. XML encryption round-trips over every algorithm offered');
    // -----------------------------------------------------------------------
    const plain = '<saml:Assertion xmlns:saml="' + NS_SAML2 + '" ID="_e1"><saml:Subject/></saml:Assertion>';
    Object.keys(crypto.BLOCK_CIPHERS).forEach(function (algorithm) {
      Object.keys(crypto.KEY_TRANSPORTS).forEach(function (keyTransport) {
        const sealed = crypto.encryptElement(plain, keys.certPem,
          { algorithm: algorithm, keyTransport: keyTransport });
        const opened = crypto.decryptElement(sealed, keys.privateKeyPem);
        t.check(opened.ok && opened.xml === plain,
                algorithm + ' + ' + keyTransport + ' round-trips', opened.why);
      });
    });

    const wrongCert = crypto.decryptElement(
      crypto.encryptElement(plain, other.certPem, {}), keys.privateKeyPem);
    t.check(!wrongCert.ok, 'an element encrypted to a DIFFERENT certificate is refused',
            (wrongCert.why || '').slice(0, 90));

    // -----------------------------------------------------------------------
    t.log.info('F. JWE, both halves, over one table');
    // -----------------------------------------------------------------------
    const pair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = Object.assign(pair.publicKey.export({ format: 'jwk' }), { kid: 'k1' });
    ['A128GCM', 'A256GCM'].forEach(function (enc) {
      const compact = crypto.encryptJweCompact('{"probe":true}', { jwk: jwk, enc: enc });
      t.equal(compact.split('.').length, 5, enc + ' produces a five-part compact JWE');
      const back = crypto.decryptJweCompact(compact,
        { privateKey: pair.privateKey, allowedEnc: ['A128GCM', 'A256GCM'], expectedKid: 'k1' });
      t.equal(back.plaintext, '{"probe":true}', '  and it round-trips');
    });

    const compact = crypto.encryptJweCompact('{"probe":true}', { jwk: jwk, enc: 'A256GCM' });
    const refusals = [
      ['a stale kid', { privateKey: pair.privateKey, expectedKid: 'rotated' }],
      ['an enc this endpoint never offered', { privateKey: pair.privateKey, allowedEnc: ['A128GCM'] }],
      ['a compressed request', { privateKey: pair.privateKey }]
    ];
    refusals.forEach(function (row, i) {
      let threw = '';
      try {
        // The third case needs a `zip` header rather than different options.
        const text = i === 2
          ? (function () {
              const parts = compact.split('.');
              const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
              header.zip = 'DEF';
              parts[0] = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
              return parts.join('.');
            })()
          : compact;
        crypto.decryptJweCompact(text, row[1]);
      } catch (e) {
        threw = e.message;
      }
      t.check(!!threw, 'a JWE with ' + row[0] + ' is refused', threw.slice(0, 80));
    });

    let tagThrew = '';
    try {
      const parts = compact.split('.');
      const tag = Buffer.from(parts[4], 'base64url');
      tag[0] = tag[0] ^ 0xff;
      parts[4] = tag.toString('base64url');
      crypto.decryptJweCompact(parts.join('.'), { privateKey: pair.privateKey });
    } catch (e) {
      tagThrew = e.message;
    }
    t.check(!!tagThrew, 'a JWE whose authentication tag was altered is refused',
            tagThrew.slice(0, 80));

    // -----------------------------------------------------------------------
    t.log.info('G. the thumbprints agree with the three implementations they replaced');
    // -----------------------------------------------------------------------
    // What `spiffe_ca.js` and `vc_issuer.js` each computed: JSON.stringify over
    // an object literal whose keys happened to be in lexicographic order. The
    // shared one builds the canonical JSON from an ORDERED LIST, so the ordering
    // is a property of the code rather than of how somebody typed an object.
    const legacyRsa = nodeCrypto.createHash('sha256')
      .update(JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n })).digest('base64url');
    t.equal(crypto.jwkThumbprint(jwk), legacyRsa,
            'the RFC 7638 thumbprint matches what the two JSON.stringify copies produced');
    t.equal(crypto.jwkThumbprint(jwk, { truncate: 16 }), legacyRsa.slice(0, 16),
            '  and truncating it is the same prefix those two used as a kid');

    // **ONLY THE REQUIRED MEMBERS ARE HASHED.** A key carrying `kid`, `alg`,
    // `use` or Web Crypto's `key_ops` must hash to the same value, because a
    // DPoP client sends its key in every proof and a stray member would break
    // the binding silently.
    t.equal(crypto.jwkThumbprint(Object.assign({}, jwk,
              { alg: 'RS256', use: 'sig', key_ops: ['verify'], ext: true })),
            crypto.jwkThumbprint(jwk),
            'a key carrying kid/alg/use/key_ops hashes the same — the DPoP binding depends on it');

    const ec = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
      .publicKey.export({ format: 'jwk' });
    t.equal(crypto.jwkThumbprint(ec), nodeCrypto.createHash('sha256')
              .update(JSON.stringify({ crv: ec.crv, kty: ec.kty, x: ec.x, y: ec.y }))
              .digest('base64url'),
            'and an EC key uses its own member list, in RFC 7638 order');

    // The certificate thumbprint: three spellings of ONE digest.
    const der = Buffer.from(keys.certB64, 'base64');
    const hex = nodeCrypto.createHash('sha256').update(der).digest('hex');
    t.equal(crypto.certificateThumbprint(keys.certPem),
            nodeCrypto.createHash('sha256').update(der).digest('base64url'),
            "RFC 8705's x5t#S256 spelling is base64url over the DER");
    t.equal(crypto.certificateThumbprint(keys.certPem, { format: 'hex', truncate: 16 }),
            hex.slice(0, 16), "SPIRE's authority id is the same digest, hex, truncated");
    t.equal(crypto.certificateThumbprint(keys.certPem, { format: 'colon-hex' }),
            (hex.toUpperCase().match(/.{2}/g) || []).join(':'),
            "and openssl's spelling is the same digest again");
    t.equal(crypto.certificateThumbprint(der), crypto.certificateThumbprint(keys.certPem),
            'a DER buffer and a PEM give the same answer');

    // -----------------------------------------------------------------------
    t.log.info('H. the clock allowance is applied by DEFAULT — the drift this closed');
    // -----------------------------------------------------------------------
    // `oauth2.js` has always said every read-back of one of our own tokens takes
    // `oauth2.clockSkewS`, and scoped it to that file. Four sites in oid4vc/ did
    // not, so a token could be refused there seconds before it should be. The
    // fix is that the shared verifier applies it unless a caller opts out — so
    // the assertion is about the DEFAULT, not about any one call site.
    const skew = crypto.tokenClockSkew();
    t.check(skew > 0, 'there is a configured clock allowance to apply', 'oauth2.clockSkewS=' + skew);

    const justExpired = Math.floor(Date.now() / 1000) - Math.floor(skew / 2);
    const token = crypto.signJws({ sub: 'probe', exp: justExpired }, keys.privateKeyPem);

    let acceptedByDefault = false;
    try {
      crypto.verifyJws(token, keys.certPem);
      acceptedByDefault = true;
    } catch (e) {
      acceptedByDefault = false;
    }
    t.check(acceptedByDefault,
            'A TOKEN INSIDE THE ALLOWANCE IS ACCEPTED WITHOUT THE CALLER ASKING — ' +
            'this is what the four oid4vc/ sites got wrong',
            'exp was ' + Math.floor(skew / 2) + 's ago, allowance is ' + skew + 's');

    let refusedWhenOptedOut = false;
    try {
      crypto.verifyJws(token, keys.certPem, { clockTolerance: 0 });
    } catch (e) {
      refusedWhenOptedOut = true;
    }
    t.check(refusedWhenOptedOut,
            'and a caller that deliberately opts out still gets the strict reading',
            'which is what spiffe/spiffe_ca.js does for a JWT-SVID');

    // The algorithm list is never left to the token's own header.
    let algNoneRefused = false;
    try {
      crypto.verifyJws(
        Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url') + '.' +
        Buffer.from(JSON.stringify({ sub: 'mallory' })).toString('base64url') + '.',
        keys.certPem);
    } catch (e) {
      algNoneRefused = true;
    }
    t.check(algNoneRefused, 'an `alg: none` token is refused by the default algorithm list');

    // -----------------------------------------------------------------------
    t.log.info('I. constant-time comparison, including the length case that throws');
    // -----------------------------------------------------------------------
    t.check(crypto.constantTimeEquals('s3cret', 's3cret'), 'equal secrets match');
    t.check(!crypto.constantTimeEquals('s3cret', 's3cres'), 'unequal secrets of one length do not');
    // `crypto.timingSafeEqual()` THROWS on different lengths, which is the trap
    // both previous copies had to write a guard around — and the reason there
    // were two copies at all.
    t.check(!crypto.constantTimeEquals('short', 'a much longer secret'),
            'and different lengths ANSWER FALSE rather than throwing');
    t.check(!crypto.constantTimeEquals(undefined, 'x'), 'a missing secret answers false');
  }
};
