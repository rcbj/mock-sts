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

const { log, logArtifact, STS, xmlEscape, genId, iso } = require('../common/helpers');
// ---------------------------------------------------------------------------
// EVERY SIGNATURE AND EVERY CIPHER IN THIS SERVICE IS IN ONE MODULE SINCE
// 2026-08-27, and this file is where two of the four families used to live.
//
// The SIGNING moved out and is now the parent project's own signer, vendored
// and shared, so both ends of a SAML exchange canonicalize with the same code —
// see `common/crypto.js` for why that is worth having. The ENCRYPTION moved
// with it unchanged, code and comments both: it was already one implementation
// with two callers, and what it has that a shared one did not is the diagnosis
// a mock exists to give. It is re-exported at the bottom of this file, so
// `ws-trust/wstrust.js` and everything else that took `encryptAssertion` from
// here still does.
// ---------------------------------------------------------------------------
const stsCrypto = require('../common/crypto');
// saml.issuer, read per assertion rather than captured at require time so
// that /admin/config can change what the next one says it came from.
const config = require('../common/config');
// The custom attributes an admin configured, and the register every assertion is
// counted in. A library like dpop.js: it registers no route and requires only
// helpers.js, so it cannot join a cycle with this file.
const stats = require('../common/admin_stats');
// Sign a SAML assertion enveloped (signature after Issuer), like api/server.js.
function signAssertion(xml) {
  log.debug("Entering signAssertion().");
  logArtifact('SAML assertion', 'before signing', xml);
  // AFTER the <Issuer>, which is where the SAML 2.0 schema puts a signature on
  // an assertion. The reference is worked out from the root's own `ID` by the
  // signer; passing one here would only be a second place for it to be wrong.
  const signed = stsCrypto.signXml(xml, {
    privateKeyPem: STS.privateKeyPem,
    certPem: STS.certPem,
    placement: stsCrypto.PLACEMENT.AFTER_ISSUER,
    what: 'SAML 2.0 assertion'
  });
  logArtifact('SAML assertion', 'after signing', signed);
  log.debug("Leaving signAssertion().");
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
//
// FIVE MORE ARRIVED WITH THE WEB BROWSER SSO PROFILE (saml2_sso.js), and every
// one of them is a MUST in saml-profiles-2.0-os section 4.1.4.2 that WS-Trust
// and WS-Federation genuinely do not need. That is why they are options here
// rather than a second builder: the element order, the namespace and the
// signature location are what a service provider's parser is strict about, and
// there is one place they are decided.
//
//   nameIdFormat          the NameID's Format. The two older callers want
//                         `unspecified` — nothing consumes it — and a service
//                         provider that asked for a format in NameIDPolicy is
//                         entitled to see the one it asked for.
//   nameIdValue           the NameID's text, when it is not the subject. A
//                         transient or persistent format needs an opaque value,
//                         and the subject is still what the attributes say.
//   subjectConfirmation   { recipient, inResponseTo, notOnOrAfter } becoming a
//                         <SubjectConfirmationData>. THE PROFILE REQUIRES IT:
//                         section 4.1.4.2 says the bearer assertion MUST carry a
//                         Recipient matching the assertion consumer service URL
//                         and an InResponseTo matching the request. A service
//                         provider that checks either — most do — refuses an
//                         assertion without them, and the refusal reads as a
//                         signature problem to anybody who has not met it before.
//   sessionIndex          the AuthnStatement's SessionIndex. It defaults to the
//                         assertion's own ID, which is what the two older callers
//                         got and is fine while nothing logs out; Single Logout
//                         is the feature that makes it matter, because the
//                         LogoutRequest names the session by this value.
//   authnInstant          when the person actually authenticated, which is the
//                         SESSION's authTime and not now. Defaulted to now, as
//                         it always was.
//
// AND TWO MORE, which are about the DOCUMENT rather than about its contents:
//
//   issuer                who signed it. It defaults to `saml.issuer`, which is
//                         what the two older callers get and is the shared
//                         value WS-Trust and WS-Federation both want. The Web
//                         SSO profile has to override it because that profile
//                         publishes an entityID PER SERVICE PROVIDER, and a
//                         service provider checks the assertion's Issuer
//                         against the entityID in the metadata it was
//                         configured from — an assertion issued by a name that
//                         is not in that document is refused, and the refusal
//                         reads as a trust-store problem.
//   sign                  false to return the assertion unsigned. Default true,
//                         which is what every existing caller gets. It is a
//                         supported state and not a failure: a service provider
//                         that accepts an unsigned assertion has a hole in it,
//                         and this is how somebody finds that out. The RECORD
//                         says `signed: false` either way, so the console
//                         reports what actually went out rather than what was
//                         intended.
function buildSamlAssertion(subject, audience, lifetimeMin, opts) {
  log.debug("Entering buildSamlAssertion().");
  opts = opts || {};
  const id = genId();
  const now = iso(0);
  // The validity window, WIDENED AT BOTH ENDS by saml.clockSkewS. `now` is
  // untouched and is what IssueInstant and the default AuthnInstant carry: those
  // two state when this service actually did something, and backdating them
  // would be a lie about an event rather than an allowance about a clock. Only
  // the Conditions move. With the setting at its default 0 this is byte-for-byte
  // what this function emitted before the setting existed, which is the property
  // that keeps every existing caller and every recorded assertion unchanged.
  const skewS = Math.max(0, Number(config.value('saml.clockSkewS')) || 0);
  const notBefore = iso(-skewS / 60);
  const exp = iso((lifetimeMin > 0 ? lifetimeMin : 60) + skewS / 60);
  const audienceEl = audience
    ? '<saml:AudienceRestriction><saml:Audience>' + xmlEscape(audience) + '</saml:Audience></saml:AudienceRestriction>'
    : '';
  const authnContextClassRef = opts.authnContextClassRef ||
    'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';
  // Who signed it. Read once, because it appears in the Issuer element and in
  // the default `issuedBy` attribute, and two reads of a runtime-changeable
  // setting inside one document can disagree with each other.
  const issuer = opts.issuer || config.value('saml.issuer');
  const attributes = (opts.attributes && opts.attributes.length) ? opts.attributes : [
    { name: 'name', value: subject },
    { name: 'issuedBy', value: issuer }
  ];
  // Whatever the admin console was told to add, APPENDED to the above rather than
  // replacing it — and appended in both branches, so a WS-Federation sign-in
  // (which passes its own claim list) and a WS-Trust Issue (which does not) both
  // carry them. A configured attribute that displaced the claim a relying party
  // keys off would break the sign-in and look like a bug in the relying party.
  const custom = stats.samlAttributes('saml2', { subject: subject, audience: audience });
  // Appended, and FILTERED against what is already there by name. The rule is the
  // one the JWT builders follow — the protocol's own claims win — but it has to be
  // written as a filter rather than as an assignment order, because an assertion
  // is a list of elements and not an object: a duplicate name does not overwrite
  // anything, it produces two <Attribute> elements with one name, and a relying
  // party reading the first sees whichever this function happened to emit first.
  // It became reachable by ticking a box rather than by typing a name when
  // /admin/claims grew its directory attributes: `cn` becomes the claim `name`,
  // and `name` is one of the two attributes above.
  const names = new Set(attributes.map(function (a) { return a.name; }));
  const configured = custom.filter(function (a) { return !names.has(a.name); });
  const attributeEls = attributes.concat(configured).map(function (a) {
    return '<saml:Attribute Name="' + xmlEscape(a.name) + '"' +
      (a.nameFormat ? ' NameFormat="' + xmlEscape(a.nameFormat) + '"' : '') + '>' +
      attributeValuesOf(a) + '</saml:Attribute>';
  }).join('');
  // The NameID, and the one thing to know about the default: `unspecified` is
  // what this service said for years and nothing consumed it, so it stays the
  // default rather than becoming what a Web SSO service provider asked for.
  // A caller that was asked for a format passes it.
  const nameIdFormat = opts.nameIdFormat ||
    'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
  const nameIdValue = opts.nameIdValue == null ? subject : opts.nameIdValue;
  // <SubjectConfirmationData>, which the Web Browser SSO profile requires and
  // the other two callers have no request to answer. Built as an EMPTY-ELEMENT
  // SubjectConfirmation when there is nothing to say, exactly as before, because
  // that is what every existing caller's output has been and a self-closing
  // element is not the same document as one with an empty child.
  const scd = opts.subjectConfirmation;
  const confirmation = scd
    ? '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
        '<saml:SubjectConfirmationData' +
        (scd.notOnOrAfter ? ' NotOnOrAfter="' + xmlEscape(scd.notOnOrAfter) + '"' : '') +
        (scd.recipient ? ' Recipient="' + xmlEscape(scd.recipient) + '"' : '') +
        (scd.inResponseTo ? ' InResponseTo="' + xmlEscape(scd.inResponseTo) + '"' : '') +
        '/></saml:SubjectConfirmation>'
    : '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/>';
  const sessionIndex = opts.sessionIndex || id;
  const authnInstant = opts.authnInstant || now;
  const xml =
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
      ' ID="' + id + '" Version="2.0" IssueInstant="' + now + '">' +
      '<saml:Issuer>' + xmlEscape(issuer) + '</saml:Issuer>' +
      '<saml:Subject><saml:NameID Format="' + xmlEscape(nameIdFormat) + '">' +
        xmlEscape(nameIdValue) + '</saml:NameID>' +
      confirmation + '</saml:Subject>' +
      '<saml:Conditions NotBefore="' + notBefore + '" NotOnOrAfter="' + exp + '">' + audienceEl + '</saml:Conditions>' +
      '<saml:AuthnStatement AuthnInstant="' + xmlEscape(authnInstant) + '" SessionIndex="' +
        xmlEscape(sessionIndex) + '">' +
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
  // `sign: false` is a state, not a failure — see the option's note above — so
  // the record is corrected here for the same reason it is corrected in the
  // catch below: the console shows whether an assertion was signed, and an
  // unsigned one is the single most useful thing that column can say.
  if (opts.sign === false) {
    record.signed = false;
    log.debug("Leaving buildSamlAssertion(). Unsigned, because the caller asked for that.");
    return xml;
  }
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

// ---------------------------------------------------------------------------
// XML ENCRYPTION MOVED TO `common/crypto.js` ON 2026-08-27, CODE AND COMMENTS
// UNCHANGED, AND IS RE-EXPORTED FROM HERE.
//
// It did not move because it was duplicated — it never was: one implementation
// with two callers, this file's SSO profile and WS-Trust's `?encrypt=1`. It
// moved because the four crypto families are now in one module, and leaving the
// only cipher in the service inside a SAML file would have meant "all of it
// except that one" — which is the shape of exception that stops being true.
//
// **IT WAS NOT REPLACED BY THE VENDORED `encryptXml()`/`decryptXml()`, and that
// is argued at the top of Section 2 over there rather than here** — briefly,
// the two produce byte-compatible documents so there was no interop gap to
// close, and this one answers rather than throwing, checks the unwrapped key's
// LENGTH, parses the plaintext before calling CBC a success, and tells a
// NamespaceError apart from a wrong certificate. Those messages are the product.
//
// The re-exports below are not a compatibility shim to be removed later: an
// assertion is what gets encrypted, so `saml2.encryptAssertion()` is the name
// this belongs under from a caller's point of view, whatever file the cipher
// lives in.
// ---------------------------------------------------------------------------
// The artifact log is INJECTED HERE rather than asked of every caller, and
// that is what makes this a move with no behaviour change: at the default
// `debug` level the before-and-after of an encryption is printed exactly as it
// was, and none of the three call sites had to learn about a new parameter.
// `common/crypto.js` cannot reach `logArtifact()` itself — helpers.js requires
// that file, so requiring it back would close a cycle.
function encryptElement(xml, certPem, opts) {
  return stsCrypto.encryptElement(xml, certPem,
    Object.assign({}, opts, { logArtifact: logArtifact }));
}

function encryptAssertion(assertionXml, certPem, opts) {
  return stsCrypto.encryptAssertion(assertionXml, certPem,
    Object.assign({}, opts, { logArtifact: logArtifact }));
}

function decryptElement(xml, privateKeyPem, opts) {
  return stsCrypto.decryptElement(xml, privateKeyPem,
    Object.assign({}, opts, { logArtifact: logArtifact }));
}

const BLOCK_CIPHERS = stsCrypto.BLOCK_CIPHERS;
const KEY_TRANSPORTS = stsCrypto.KEY_TRANSPORTS;

module.exports = {
  signAssertion: signAssertion,
  buildSamlAssertion: buildSamlAssertion,
  encryptAssertion: encryptAssertion,
  encryptElement: encryptElement,
  decryptElement: decryptElement,
  BLOCK_CIPHERS: BLOCK_CIPHERS,
  KEY_TRANSPORTS: KEY_TRANSPORTS
};
