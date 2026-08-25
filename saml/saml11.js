'use strict';
//
// File: saml11.js
//
// ---------------------------------------------------------------------------
// SAML 1.1 assertions: building one and signing it.
//
// It is here because WS-Federation asked for it — and since 2026-08-24 it has a
// SECOND CALLER, `saml11_sso.js`, which puts the same assertion in front of a
// browser through SAML 1.1's own two profiles. That is the reason this file is a
// module of its own stated twice over: an assertion is not a WS-Federation
// concept, the passive requestor profile merely carries one, and now so do
// Browser/POST and Browser/Artifact. What made a second file necessary
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
const { log, logArtifact, STS, xmlEscape, genId, iso } = require('../common/helpers');
// saml.issuer — the same setting the 2.0 assertions carry, because it names
// the same signer.
const config = require('../common/config');
// As in saml2.js: the custom attributes an admin configured, and the register every
// assertion is counted in.
const stats = require('../common/admin_stats');

const SAML11_NS = 'urn:oasis:names:tc:SAML:1.0:assertion';

// The one every relying party here can read, and the only one this service could
// honestly claim: nothing about the NameIdentifier it writes is a persistent
// identifier or an email address, because the username is whatever was typed.
const NAMEID_FORMAT_UNSPECIFIED = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';

const CONFIRMATION_BEARER = 'urn:oasis:names:tc:SAML:1.0:cm:bearer';

// The Browser/Artifact profile's, and NOT interchangeable with the one above —
// see the `confirmationMethod` option. It says the assertion was pulled back
// through a SOAP channel rather than carried by the browser, which is the whole
// difference between the two profiles.
const CONFIRMATION_ARTIFACT = 'urn:oasis:names:tc:SAML:1.0:cm:artifact';

// Sign the assertion enveloped, with the signature as the last child of Assertion
// — which is where the SAML 1.1 schema requires it and, unusually, also where
// xml-crypto puts it with no location option at all.
//
// **`idAttribute: 'AssertionID'` IS LOAD-BEARING ON THE WAY OUT AS WELL AS THE
// WAY BACK IN, and this file said the opposite until 2026-08-24.** It used to
// read "SIGNING does not care that the id attribute has an unusual name; only
// verification does", which is true of the DIGEST and false of the document.
// xml-crypto's ensureHasId() looks for the first of `Id`, `ID`, `id` on the node
// being signed, and when it finds none it INVENTS ONE — `Id="_0"` — and
// overrides the reference URI passed below with `#_0`. So every SAML 1.1
// assertion this service issued carried a bogus `Id` attribute the schema does
// not have, and a reference naming it instead of the AssertionID.
//
// It verified anyway, which is why it went unnoticed for so long: a verifier
// resolving `#_0` finds the injected attribute. Two things broke it. A relying
// party that resolves the reference through `AssertionID` — which is what a
// SAML-aware verifier does, and what wsfed.js's own verifyAssertionSignature()
// is told to do — looks for an element with that AssertionID and finds the
// reference pointing somewhere else. And, the failure that actually surfaced it,
// **a document carrying TWO signatures gets `Id="_0"` on both**: the
// saml11_sso.js browser profiles sign the assertion and the Response around it,
// and xml-crypto then refuses to verify either, reporting "multiple elements
// with the same value for the ID / Id / Id attributes" — its signature-wrapping
// guard, firing on a document nothing malicious ever touched.
//
// Naming the attribute here makes ensureHasId() find the real one, so nothing is
// injected and the reference is `#` + the AssertionID, which is what every real
// identity provider emits. It is safe to name because `AssertionID` is NOT
// already on that default list — see saml2_sso.js, which records the opposite
// case: naming `ID` for SAML 2.0 unshifts a DUPLICATE and trips the same guard.
function signSaml11Assertion(xml) {
  log.debug("Entering signSaml11Assertion().");
  logArtifact('SAML 1.1 assertion', 'before signing', xml);
  const m = xml.match(/\bAssertionID="([^"]+)"/);
  const id = m ? m[1] : '';
  const sig = new SignedXml({ privateKey: STS.privateKeyPem, publicCert: STS.certPem,
                              idAttribute: 'AssertionID' });
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

// ---------------------------------------------------------------------------
// One <Attribute>'s values.
//
// A SAML Attribute is MULTI-VALUED — several <AttributeValue> children under
// one <Attribute> — and until the groups claim there was nothing here that
// needed to be. `value` stays the single-value spelling every existing caller
// uses and is untouched; `values` is the array spelling, and a caller that
// passes both (group_claims.js does, so that anything reading `.value` still
// sees a group rather than undefined) gets the array.
//
// The alternative was one <Attribute> element per group carrying the same
// name, which is precisely the defect admin_stats.samlAttributes()'s dedup
// filter exists to prevent: that is not a multi-valued attribute, it is a
// relying party reading the first element and silently seeing one group where
// the person is in four.
// ---------------------------------------------------------------------------
function attributeValuesOf(a) {
  const values = Array.isArray(a.values) ? a.values : [a.value];
  return values.map(function (value) {
    return '<saml:AttributeValue>' + xmlEscape(String(value == null ? '' : value)) +
           '</saml:AttributeValue>';
  }).join('');
}

// opts:
//   subject       the NameIdentifier, and the subject of every statement
//   audience      goes in AudienceRestrictionCondition; omitted when empty
//   lifetimeMin   minutes, default 60
//   authnMethod   the AuthenticationMethod URI actually performed
//   authnInstant  when, as an ISO instant; defaults to now
//   attributes    [{ name, namespace, value }]
//
// SEVEN MORE ARRIVED WITH THE BROWSER PROFILES (saml11_sso.js), and this is the
// same growth saml2.js took for the Web Browser SSO profile — options on the one
// builder rather than a second builder, for the reason this directory has always
// given: one assertion writer means ONE place where the element order, the
// attribute spelling and the signature location are decided, and those are
// exactly what a relying party's parser is strict about. It also means the
// custom SAML 1.1 attributes configured on /admin/saml-attributes reach an
// assertion issued by the browser profiles with no wiring at all.
//
// Every default below reproduces what WS-Trust and WS-Federation were already
// getting, BYTE FOR BYTE. That is a requirement rather than a courtesy: those
// two have relying parties in the parent project's test suite that verify a
// signature over this document, and a single added attribute changes the digest.
//
//   issuer              the Issuer attribute, when it is not `saml.issuer`. The
//                       browser profiles MUST override it: they publish a
//                       providerID per relying party, and a relying party checks
//                       the assertion's Issuer against the one in the metadata it
//                       was configured from. An assertion issued under a name
//                       that is not in that document is refused, and the refusal
//                       reads as a trust-store problem.
//   nameIdFormat        the NameIdentifier's Format. The two older callers want
//                       `unspecified` — nothing consumes it — and a relying party
//                       configured for an email address is entitled to see one.
//   nameIdValue         the NameIdentifier's text, when it is not the subject.
//   nameQualifier       the NameIdentifier's NameQualifier, which SAML 1.1 has
//                       and SAML 2.0 spells the same way. A Shibboleth service
//                       provider keys its attribute resolution off it, so the
//                       browser profiles set it to the identity provider's own
//                       providerID; omitted entirely when nothing asks, because
//                       an empty NameQualifier is not the same as no attribute.
//   confirmationMethod  **THE ONE THE PROFILES ACTUALLY DISAGREE ABOUT.**
//                       saml-profile-1.1 section 4.1.1.4 requires
//                       `urn:oasis:names:tc:SAML:1.0:cm:artifact` for the
//                       Browser/Artifact profile and section 4.2.1.4 requires
//                       `...:cm:bearer` for Browser/POST. They are not
//                       interchangeable and a strict relying party checks: an
//                       artifact-profile assertion confirmed as `bearer` says the
//                       assertion travelled through the browser when it did not.
//   subjectLocality     { ipAddress, dnsAddress } becoming a <SubjectLocality>
//                       inside the AuthenticationStatement. Section 4.2 asks the
//                       identity provider to record where the browser was, and it
//                       is the one element here written from the HTTP request
//                       rather than from the session.
//   doNotCache          adds <DoNotCacheCondition/>. The Browser/POST profile's
//                       single-use policy: the assertion travels through the
//                       browser, so a relying party is told not to keep it. It is
//                       off for the two older callers, whose assertions do not
//                       pass through a browser at all.
//   sign                false returns the assertion UNSIGNED. It is a test case
//                       rather than a mistake — a relying party that accepts an
//                       unsigned assertion has a hole in it and this is how
//                       somebody finds that out — and it is why signing is a
//                       setting in the browser profiles.

function buildSaml11Assertion(opts) {
  log.debug("Entering buildSaml11Assertion(). subject=" + (opts.subject || '(none)'));
  const id = genId();
  const now = iso(0);
  const lifetimeMin = opts.lifetimeMin > 0 ? opts.lifetimeMin : 60;
  const exp = iso(lifetimeMin);
  const authnInstant = opts.authnInstant || now;
  const authnMethod = opts.authnMethod || 'urn:oasis:names:tc:SAML:1.0:am:password';
  // The NameIdentifier, and the one thing to know about the defaults: they are
  // what this service has said for years and nothing consumed, so they stay the
  // defaults rather than becoming what a browser-profile relying party asked
  // for. A caller that was asked for a format passes it.
  const nameIdFormat = opts.nameIdFormat || NAMEID_FORMAT_UNSPECIFIED;
  const nameIdValue = opts.nameIdValue == null ? opts.subject : opts.nameIdValue;
  // OMITTED rather than written empty when nothing asks: `NameQualifier=""` is a
  // qualifier whose value is the empty string, which is not the same document as
  // one with no qualifier, and the difference is inside the signature.
  const qualifier = opts.nameQualifier
    ? ' NameQualifier="' + xmlEscape(opts.nameQualifier) + '"'
    : '';
  const confirmation = opts.confirmationMethod || CONFIRMATION_BEARER;
  // Repeated in both statements, which is not redundancy in SAML 1.1 but the
  // schema: a statement is about a subject, and the assertion itself is not.
  const subjectEl =
    '<saml:Subject>' +
      '<saml:NameIdentifier' + qualifier + ' Format="' + xmlEscape(nameIdFormat) + '">' +
        xmlEscape(nameIdValue) + '</saml:NameIdentifier>' +
      '<saml:SubjectConfirmation><saml:ConfirmationMethod>' + xmlEscape(confirmation) +
      '</saml:ConfirmationMethod></saml:SubjectConfirmation>' +
    '</saml:Subject>';
  const audienceEl = opts.audience
    ? '<saml:AudienceRestrictionCondition><saml:Audience>' + xmlEscape(opts.audience) +
      '</saml:Audience></saml:AudienceRestrictionCondition>'
    : '';
  // <DoNotCacheCondition/> AFTER the audience restriction, which is the schema's
  // sequence: Conditions holds a choice of AudienceRestrictionCondition and
  // DoNotCacheCondition, and a document that reverses them is one a generated
  // parser rejects while a hand-written one accepts. Off unless asked for.
  const doNotCacheEl = opts.doNotCache ? '<saml:DoNotCacheCondition/>' : '';
  // <SubjectLocality> is the FIRST child of AuthenticationStatement after the
  // Subject and before any AuthorityBinding — again the schema's sequence rather
  // than a preference. Both attributes are optional and each is omitted when the
  // caller has nothing to say, for the reason NameQualifier is.
  const locality = opts.subjectLocality || null;
  const localityEl = locality && (locality.ipAddress || locality.dnsAddress)
    ? '<saml:SubjectLocality' +
        (locality.ipAddress ? ' IPAddress="' + xmlEscape(locality.ipAddress) + '"' : '') +
        (locality.dnsAddress ? ' DNSAddress="' + xmlEscape(locality.dnsAddress) + '"' : '') +
      '/>'
    : '';
  // Appended to what the caller asked for, never substituted for it — the same
  // rule as SAML 2.0, and it matters more here: a WS-Federation relying party keys
  // off the claim URIs in claimsFor(), and displacing one of those would break the
  // sign-in somewhere that looks nothing like this page. An attribute configured
  // with no namespace gets the identity claims namespace, which is where a relying
  // party is already looking.
  const custom = stats.samlAttributes('saml11', { subject: opts.subject, audience: opts.audience });
  // FILTERED against the caller's own claims by name, for the reason saml2.js
  // states beside the same line: an assertion is a list of elements, so a
  // duplicate name is not an overwrite but two <Attribute> elements with one
  // name, and the relying party reads whichever came first. It matters more here
  // than there — a WS-Federation relying party keys off these claim URIs — and it
  // became easy to hit when /admin/claims grew a table of directory attributes to
  // tick.
  //
  // Keyed on the NAMESPACE AND THE NAME together, which is the only correct key
  // here: SAML 1.1 splits a claim URI into the two, so `name` in the identity
  // claims namespace and `name` in somebody else's are different claims, and a
  // filter on the local name alone would drop a configured attribute that
  // collided with nothing. The one collision it does catch is real — the
  // WS-Federation claim list carries `name` in that namespace, and so does a
  // ticked `cn`.
  const asked = opts.attributes || [];
  const keyOf = function (a) { return String(a.namespace || '') + ' ' + String(a.name || ''); };
  const names = new Set(asked.map(keyOf));
  const configured = custom.filter(function (a) { return !names.has(keyOf(a)); });
  const attributeEls = asked.concat(configured).map(function (a) {
    return '<saml:Attribute AttributeName="' + xmlEscape(a.name) + '"' +
      ' AttributeNamespace="' + xmlEscape(a.namespace) + '">' +
      attributeValuesOf(a) + '</saml:Attribute>';
  }).join('');
  // Conditions, then the statements, then (added by the signer) ds:Signature. The
  // order is the schema's sequence and not a preference.
  const xml =
    '<saml:Assertion xmlns:saml="' + SAML11_NS + '"' +
      ' MajorVersion="1" MinorVersion="1"' +
      ' AssertionID="' + id + '"' +
      ' Issuer="' + xmlEscape(opts.issuer || config.value('saml.issuer')) + '"' +
      ' IssueInstant="' + now + '">' +
      '<saml:Conditions NotBefore="' + now + '" NotOnOrAfter="' + exp + '">' + audienceEl +
      doNotCacheEl + '</saml:Conditions>' +
      '<saml:AuthenticationStatement AuthenticationMethod="' + xmlEscape(authnMethod) + '"' +
        ' AuthenticationInstant="' + authnInstant + '">' + subjectEl + localityEl +
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
  // `sign: false` is a DELIBERATE unsigned assertion and is recorded as one, so
  // that the console's Signed column tells it apart from a signing FAILURE
  // below. The two look identical on the wire and mean opposite things: one is
  // somebody exercising a relying party's checking, the other is this service
  // being broken.
  if (opts.sign === false) {
    record.signed = false;
    log.debug("Leaving buildSaml11Assertion(). Unsigned because the caller asked for that.");
    return xml;
  }
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
  // The two the browser profiles need by name: an artifact-profile assertion
  // MUST be confirmed as `artifact` and a POST-profile one as `bearer`, and
  // exporting them means saml11_sso.js cannot spell either differently.
  CONFIRMATION_BEARER: CONFIRMATION_BEARER,
  CONFIRMATION_ARTIFACT: CONFIRMATION_ARTIFACT,
  NAMEID_FORMAT_UNSPECIFIED: NAMEID_FORMAT_UNSPECIFIED,
  buildSaml11Assertion: buildSaml11Assertion,
  signSaml11Assertion: signSaml11Assertion
};
