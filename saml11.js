'use strict';
//
// File: saml11.js
//
// ---------------------------------------------------------------------------
// SAML 1.1 assertions: building one and signing it.
//
// It is here because WS-Federation asked for it, and it is a module of its own for
// the same reason saml2.js is one: an assertion is not a WS-Federation concept, the
// passive requestor profile merely carries one. What made a second file necessary
// rather than a flag on saml2.js is that **SAML 1.1 is a different specification
// and not a dialect of SAML 2.0** — the element vocabulary, the attribute names and
// the document order all differ, and a builder that tried to be both would be a
// series of conditionals around every line.
//
// Why 1.1 at all, when this service already issues SAML 2.0: AD FS issues a SAML
// 1.1 assertion to a WS-Federation relying party by default, and the RP libraries
// written against it (WIF, `Microsoft.Owin.Security.WsFederation`) read 1.1 first.
// A WS-Federation mock that only spoke 2.0 would be exercising the half of those
// clients that is rarely the half in production. Both are offered — see
// `wsfed.js`, and `fed:TokenTypesOffered` in the federation metadata, which
// advertises exactly these two.
//
// The six differences from SAML 2.0 that actually break a parser, all of them
// visible below and every one of them worth stating because each is a plausible
// thing to get wrong by writing 2.0 out of habit:
//
//   * the id attribute is **AssertionID**, not `ID`. This also matters on the way
//     back IN: a verifier resolving the signature's `#id` reference looks for
//     attributes named Id/ID/id, so xml-crypto has to be told about this one
//     explicitly (see verifyAssertionSignature in wsfed.js) or the reference
//     resolves to nothing and a perfectly good signature reports as broken.
//   * the version is **two attributes**, MajorVersion="1" MinorVersion="1".
//   * the **Issuer is an attribute** of Assertion, not a child element.
//   * the **Subject sits inside each statement**, and is repeated in every one of
//     them, rather than once on the assertion.
//   * **ds:Signature is the LAST child** (SAML 2.0 puts it directly after Issuer),
//     which is why computeSignature() is called here with no location option — its
//     default of appending to the root element is, for once, exactly right.
//   * an attribute is **AttributeName + AttributeNamespace**, two halves of the
//     claim URI, where SAML 2.0 has one `Name`. The convention every WS-Federation
//     relying party follows is that the claim URI is the namespace, a slash, and
//     the name; both halves are written here rather than the joined URI, because a
//     relying party that re-joins them is the common case.
//
// And one that does not break a parser but does break a signature: the condition
// element is **AudienceRestrictionCondition**, not `AudienceRestriction`.
// ---------------------------------------------------------------------------

const { SignedXml } = require('xml-crypto');
const { log, logArtifact, ISSUER, STS, xmlEscape, genId, iso } = require('./helpers');
// As in saml2.js: the custom attributes an admin configured, and the register every
// assertion is counted in.
const stats = require('./admin_stats');

const SAML11_NS = 'urn:oasis:names:tc:SAML:1.0:assertion';

// The one every relying party here can read, and the only one this service could
// honestly claim: nothing about the NameIdentifier it writes is a persistent
// identifier or an email address, because the username is whatever was typed.
const NAMEID_FORMAT_UNSPECIFIED = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';

const CONFIRMATION_BEARER = 'urn:oasis:names:tc:SAML:1.0:cm:bearer';

// Sign the assertion enveloped, with the signature as the last child of Assertion
// — which is where the SAML 1.1 schema requires it and, unusually, also where
// xml-crypto puts it with no location option at all.
//
// The reference URI is "#" + the AssertionID. The digest is computed over the node
// the xpath selects rather than over whatever that URI resolves to, so SIGNING
// does not care that the id attribute has an unusual name; only verification does.
function signSaml11Assertion(xml) {
  log.debug("Entering signSaml11Assertion().");
  logArtifact('SAML 1.1 assertion', 'before signing', xml);
  const m = xml.match(/\bAssertionID="([^"]+)"/);
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
  // Exclusive canonicalization, not inclusive, and this is the load-bearing
  // choice: the assertion is signed here as a standalone document and then
  // embedded inside an RSTR that declares prefixes of its own (wst, wsp, wsa).
  // Inclusive c14n would pull those ancestor declarations into the digest at
  // verification time and the signature would fail for every relying party while
  // verifying perfectly here, which is the worst shape of bug to chase.
  sig.computeSignature(xml);
  const signed = sig.getSignedXml();
  logArtifact('SAML 1.1 assertion', 'after signing', signed);
  log.debug("Leaving signSaml11Assertion().");
  return signed;
}

// opts:
//   subject       the NameIdentifier, and the subject of every statement
//   audience      goes in AudienceRestrictionCondition; omitted when empty
//   lifetimeMin   minutes, default 60
//   authnMethod   the AuthenticationMethod URI actually performed
//   authnInstant  when, as an ISO instant; defaults to now
//   attributes    [{ name, namespace, value }]
function buildSaml11Assertion(opts) {
  log.debug("Entering buildSaml11Assertion(). subject=" + (opts.subject || '(none)'));
  const id = genId();
  const now = iso(0);
  const lifetimeMin = opts.lifetimeMin > 0 ? opts.lifetimeMin : 60;
  const exp = iso(lifetimeMin);
  const authnInstant = opts.authnInstant || now;
  const authnMethod = opts.authnMethod || 'urn:oasis:names:tc:SAML:1.0:am:password';
  // Repeated in both statements, which is not redundancy in SAML 1.1 but the
  // schema: a statement is about a subject, and the assertion itself is not.
  const subjectEl =
    '<saml:Subject>' +
      '<saml:NameIdentifier Format="' + NAMEID_FORMAT_UNSPECIFIED + '">' +
        xmlEscape(opts.subject) + '</saml:NameIdentifier>' +
      '<saml:SubjectConfirmation><saml:ConfirmationMethod>' + CONFIRMATION_BEARER +
      '</saml:ConfirmationMethod></saml:SubjectConfirmation>' +
    '</saml:Subject>';
  const audienceEl = opts.audience
    ? '<saml:AudienceRestrictionCondition><saml:Audience>' + xmlEscape(opts.audience) +
      '</saml:Audience></saml:AudienceRestrictionCondition>'
    : '';
  // Appended to what the caller asked for, never substituted for it — the same
  // rule as SAML 2.0, and it matters more here: a WS-Federation relying party keys
  // off the claim URIs in claimsFor(), and displacing one of those would break the
  // sign-in somewhere that looks nothing like this page. An attribute configured
  // with no namespace gets the identity claims namespace, which is where a relying
  // party is already looking.
  const custom = stats.samlAttributes('saml11', { subject: opts.subject, audience: opts.audience });
  const attributeEls = (opts.attributes || []).concat(custom).map(function (a) {
    return '<saml:Attribute AttributeName="' + xmlEscape(a.name) + '"' +
      ' AttributeNamespace="' + xmlEscape(a.namespace) + '">' +
      '<saml:AttributeValue>' + xmlEscape(a.value) + '</saml:AttributeValue></saml:Attribute>';
  }).join('');
  // Conditions, then the statements, then (added by the signer) ds:Signature. The
  // order is the schema's sequence and not a preference.
  const xml =
    '<saml:Assertion xmlns:saml="' + SAML11_NS + '"' +
      ' MajorVersion="1" MinorVersion="1"' +
      ' AssertionID="' + id + '"' +
      ' Issuer="' + xmlEscape(ISSUER) + '"' +
      ' IssueInstant="' + now + '">' +
      '<saml:Conditions NotBefore="' + now + '" NotOnOrAfter="' + exp + '">' + audienceEl +
      '</saml:Conditions>' +
      '<saml:AuthenticationStatement AuthenticationMethod="' + xmlEscape(authnMethod) + '"' +
        ' AuthenticationInstant="' + authnInstant + '">' + subjectEl +
      '</saml:AuthenticationStatement>' +
      (attributeEls
        ? '<saml:AttributeStatement>' + subjectEl + attributeEls + '</saml:AttributeStatement>'
        : '') +
    '</saml:Assertion>';
  // Counted before the signing attempt, not after: an assertion that failed to sign
  // was still built and still went out (unsigned — see the catch), so counting it
  // only on success would leave the console reporting fewer than actually left.
  const record = stats.recordAssertion('1.1', { id: id, subject: opts.subject, audience: opts.audience,
                                                expiresAt: Date.parse(exp) || 0 });
  try {
    const signed = signSaml11Assertion(xml);
    log.debug("Leaving buildSaml11Assertion(). AssertionID " + id + ".");
    return signed;
  } catch (e) {
    // Returned unsigned rather than not at all, exactly as saml2.js does: an
    // unsigned assertion in the response is something a relying party can look at
    // and reject for the right reason, where a 500 here would say nothing about
    // what failed. The log line is the record of which it was — and so, now, is the
    // console's Signed column, which is why the record is corrected here.
    record.signed = false;
    log.error('SAML 1.1 signing failed, returning the assertion unsigned: ' + e.message);
    log.debug("Leaving buildSaml11Assertion(). Unsigned.");
    return xml;
  }
}

module.exports = {
  SAML11_NS: SAML11_NS,
  buildSaml11Assertion: buildSaml11Assertion,
  signSaml11Assertion: signSaml11Assertion
};
