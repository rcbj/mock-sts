'use strict';
//
// File: saml2.js
//
// ---------------------------------------------------------------------------
// SAML 2.0 assertions: building one, signing it, and encrypting it.
//
// Separate from wstrust.js because a SAML assertion is not a WS-Trust concept —
// WS-Trust merely carries one. These three functions are what a SAML 2.0
// implementation owes anyone who asks for a token in that format, and the
// debugger's SAML pages verify their output against an independent reading of the
// specification.
//
// The signature is an enveloped XML Signature over the Assertion with an
// exclusive canonicalization, and the encryption is XML Encryption with an
// AES-256-CBC content key wrapped with RSA-OAEP. Both are what Keycloak and
// ADFS produce, which is the point: the debugger's response pages have to cope
// with what real identity providers send.
// ---------------------------------------------------------------------------

const forge = require('node-forge');
const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');
const { SignedXml } = require('xml-crypto');
const { log, logArtifact, STS, xmlEscape, genId, iso } = require('./helpers');
// saml.issuer, read per assertion rather than captured at require time so
// that /admin/config can change what the next one says it came from.
const config = require('./config');
// The custom attributes an admin configured, and the register every assertion is
// counted in. A library like dpop.js: it registers no route and requires only
// helpers.js, so it cannot join a cycle with this file.
const stats = require('./admin_stats');
// Sign a SAML assertion enveloped (signature after Issuer), like api/server.js.
function signAssertion(xml) {
  log.debug("Entering signAssertion().");
  logArtifact('SAML assertion', 'before signing', xml);
  const m = xml.match(/\bID="([^"]+)"/);
  const id = m ? m[1] : '';
  const sig = new SignedXml({ privateKey: STS.privateKeyPem, publicCert: STS.certPem });
  sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
  sig.addReference({
    xpath: "/*[local-name(.)='Assertion']",
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#'
    ],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    uri: id ? ('#' + id) : ''
  });
  sig.computeSignature(xml, {
    location: { reference: "/*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: 'after' }
  });
  const signed = sig.getSignedXml();
  logArtifact('SAML assertion', 'after signing', signed);
  log.debug("Leaving signAssertion().");
  return signed;
}

// The optional fourth argument is what WS-Federation needs and WS-Trust does not,
// and it is an argument rather than a second builder on purpose: one assertion
// writer means one place where the element order, the namespace and the signature
// location are decided, and those are what a relying party's parser is strict
// about. Omit it and this produces exactly what it always did.
//
//   authnContextClassRef  how the End-User authenticated. WS-Federation's `wauth`
//                         asks for a method and the session records which one was
//                         actually performed, so the assertion has to be able to
//                         say something other than the default.
//   attributes            [{ name, nameFormat, value }] replacing the default two.
//                         A WS-Federation relying party keys off the claim URIs
//                         from the Microsoft claim namespaces, not off `name`.
function buildSamlAssertion(subject, audience, lifetimeMin, opts) {
  log.debug("Entering buildSamlAssertion().");
  opts = opts || {};
  const id = genId();
  const now = iso(0);
  const exp = iso(lifetimeMin > 0 ? lifetimeMin : 60);
  const audienceEl = audience
    ? '<saml:AudienceRestriction><saml:Audience>' + xmlEscape(audience) + '</saml:Audience></saml:AudienceRestriction>'
    : '';
  const authnContextClassRef = opts.authnContextClassRef ||
    'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';
  const attributes = (opts.attributes && opts.attributes.length) ? opts.attributes : [
    { name: 'name', value: subject },
    { name: 'issuedBy', value: config.value('saml.issuer') }
  ];
  // Whatever the admin console was told to add, APPENDED to the above rather than
  // replacing it — and appended in both branches, so a WS-Federation sign-in
  // (which passes its own claim list) and a WS-Trust Issue (which does not) both
  // carry them. A configured attribute that displaced the claim a relying party
  // keys off would break the sign-in and look like a bug in the relying party.
  const custom = stats.samlAttributes('saml2', { subject: subject, audience: audience });
  const attributeEls = attributes.concat(custom).map(function (a) {
    return '<saml:Attribute Name="' + xmlEscape(a.name) + '"' +
      (a.nameFormat ? ' NameFormat="' + xmlEscape(a.nameFormat) + '"' : '') + '>' +
      '<saml:AttributeValue>' + xmlEscape(a.value) + '</saml:AttributeValue></saml:Attribute>';
  }).join('');
  const xml =
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
      ' ID="' + id + '" Version="2.0" IssueInstant="' + now + '">' +
      '<saml:Issuer>' + xmlEscape(config.value('saml.issuer')) + '</saml:Issuer>' +
      '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">' +
        xmlEscape(subject) + '</saml:NameID>' +
      '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/></saml:Subject>' +
      '<saml:Conditions NotBefore="' + now + '" NotOnOrAfter="' + exp + '">' + audienceEl + '</saml:Conditions>' +
      '<saml:AuthnStatement AuthnInstant="' + now + '" SessionIndex="' + id + '">' +
      '<saml:AuthnContext><saml:AuthnContextClassRef>' +
        xmlEscape(authnContextClassRef) +
      '</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>' +
      '<saml:AttributeStatement>' + attributeEls + '</saml:AttributeStatement>' +
    '</saml:Assertion>';
  // Counted here rather than at the call sites: WS-Trust and WS-Federation both
  // come through this function, so this counts every SAML 2.0 assertion instead of
  // every one somebody remembered to count. `exp` is the Conditions/NotOnOrAfter
  // already computed above, which is what makes the console able to say how many
  // are still valid without re-parsing anything.
  const record = stats.recordAssertion('2.0', { id: id, subject: subject, audience: audience,
                                                expiresAt: Date.parse(exp) || 0 });
  try {
    log.debug("Leaving buildSamlAssertion().");
    return signAssertion(xml);
  } catch (e) {
    // The record is corrected rather than left as it was, because the console now
    // SHOWS whether an assertion was signed and an unsigned one is the single most
    // useful thing that column can say. Counting it as signed because it was
    // counted before the attempt would be a page that agrees with itself and not
    // with what went out.
    record.signed = false;
    log.error('sign failed, returning unsigned: ' + e.message);
    return xml;
  }
}

// Encrypt an assertion to a recipient certificate (AES-256-GCM data key wrapped
// with RSA-OAEP-MGF1P/SHA-1), wrapped in <saml:EncryptedAssertion> — the shape
// the debugger's decryptXml consumes. Used when a request asks for encryption
// (?encrypt=1) and carries the recipient cert in its WS-Security signature.
function encryptAssertion(assertionXml, certPem) {
  log.debug("Entering encryptAssertion().");
  logArtifact('SAML assertion', 'before encryption', assertionXml);
  var XENC = 'http://www.w3.org/2001/04/xmlenc#';
  var X11 = 'http://www.w3.org/2009/xmlenc11#';
  var DS = 'http://www.w3.org/2000/09/xmldsig#';
  var cert = forge.pki.certificateFromPem(certPem);
  var pub = cert.publicKey;
  var key = forge.random.getBytesSync(32);
  var iv = forge.random.getBytesSync(12);
  var cipher = forge.cipher.createCipher('AES-GCM', key);
  cipher.start({ iv: iv, tagLength: 128 });
  cipher.update(forge.util.createBuffer(forge.util.encodeUtf8(assertionXml)));
  if (!cipher.finish()) throw new Error('assertion encryption failed');
  var cipherB64 = forge.util.encode64(iv + cipher.output.getBytes() + cipher.mode.tag.getBytes());
  var wrapped = pub.encrypt(key, 'RSA-OAEP', { md: forge.md.sha1.create(), mgf1: { md: forge.md.sha1.create() } });
  var wrappedB64 = forge.util.encode64(wrapped);
  var certB64 = certPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  var encrypted = '<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' +
    '<xenc:EncryptedData xmlns:xenc="' + XENC + '" Type="' + XENC + 'Element">' +
      '<xenc:EncryptionMethod Algorithm="' + X11 + 'aes256-gcm"/>' +
      '<ds:KeyInfo xmlns:ds="' + DS + '">' +
        '<xenc:EncryptedKey>' +
          '<xenc:EncryptionMethod Algorithm="' + XENC + 'rsa-oaep-mgf1p">' +
            '<ds:DigestMethod xmlns:ds="' + DS + '" Algorithm="' + DS + 'sha1"/></xenc:EncryptionMethod>' +
          '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>' + certB64 + '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' +
          '<xenc:CipherData><xenc:CipherValue>' + wrappedB64 + '</xenc:CipherValue></xenc:CipherData>' +
        '</xenc:EncryptedKey>' +
      '</ds:KeyInfo>' +
      '<xenc:CipherData><xenc:CipherValue>' + cipherB64 + '</xenc:CipherValue></xenc:CipherData>' +
    '</xenc:EncryptedData></saml:EncryptedAssertion>';
  logArtifact('SAML assertion', 'after encryption (AES-256-GCM, key wrapped with RSA-OAEP-MGF1P)', encrypted);
  log.debug("Leaving encryptAssertion().");
  return encrypted;
}

module.exports = {
  signAssertion: signAssertion,
  buildSamlAssertion: buildSamlAssertion,
  encryptAssertion: encryptAssertion
};
