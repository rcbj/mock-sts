// File: common/crypto.js
//
// ---------------------------------------------------------------------------
// THE ONE PLACE THIS SERVICE SIGNS, VERIFIES, ENCRYPTS AND DECRYPTS.
//
// Before 2026-08-27 it did all four in about twenty places. There were SIX
// independent XML signers and FOUR independent XML signature verifiers, each
// with the same four algorithm URIs typed out again; ten `jwt.verify()` calls
// against this service's own certificate, four of which had quietly stopped
// applying the configured clock skew; two RFC 7638 JWK thumbprints; two forge
// self-signed certificate builders; and two `timingSafeEqual` wrappers. None of
// that was carelessness — each one was written where it was needed, and the
// copies agreed on the day they were made.
//
// **THE COST WAS NOT ABSTRACT AND IT IS WORTH NAMING, BECAUSE IT IS THE WHOLE
// ARGUMENT FOR THIS FILE.** `saml/CLAUDE.md` records the `Id="_0"` defect: every
// SAML 1.1 assertion this service ever issued carried an attribute the schema
// does not have, because xml-crypto invents one when it cannot find an id it
// recognises. It verified anyway, so it survived for months, and the fix had to
// be applied to EACH SIGNER SEPARATELY. A single signer would have been one
// edit and one place to be wrong. The four verifiers had drifted the same way:
// three of them took the FIRST <ds:Signature> in the document, which on a
// SAML 1.1 Response carrying a signed assertion is the ASSERTION'S — so a caller
// asking "is this Response signed by us" was answered about a different element
// and told yes.
//
// ---------------------------------------------------------------------------
// WHERE THE XML CODE CAME FROM, AND WHY IT IS NOT WRITTEN HERE.
//
// `common/vendored/xmldsig.js` is the parent project's own XML security module,
// copied here byte-identical under the rule that directory already has. It is
// not a library somebody found: it is the OTHER END of most of these exchanges.
// The debugger signs, verifies, encrypts and decrypts with it on its WS-Trust,
// SAML and Digital Signature pages, and `tests/xmlsec_interop.js` over there
// already drives it against xml-crypto AND xml-encryption — two independent
// implementations — across all three SAML versions and their three different
// signature placements.
//
// So using it here buys three things a local implementation could not. Both
// ends of an exchange now canonicalize with the same code, which matters
// because a disagreement about c14n is invisible until it is a signature that
// verifies on one side and not the other. It resolves `AssertionID`,
// `ResponseID` and `RequestID` natively, so the `Id="_0"` class of bug cannot
// recur — there is no attribute to invent. And its algorithm coverage is wider
// than what replaced it: RSA, RSASSA-PSS, ECDSA and HMAC, every c14n mode,
// InclusiveNamespaces, the XPath transforms.
//
// **THIS FILE IS THE POLICY AND THAT FILE IS THE MECHANISM**, and the split is
// deliberate rather than tidy. What is here is what is true of THIS service:
// which placements its six documents use, that a verifier must be told WHICH
// element's signature to check, that a decryption ANSWERS rather than throws,
// that a token verified against our own certificate gets the configured clock
// skew. None of that belongs in a file that has to stay byte-identical to
// somebody else's copy.
//
// ---------------------------------------------------------------------------
// THIS MODULE IS A LEAF AND MUST STAY ONE.
//
// It requires npm packages, `./vendored/xmldsig.js`, and `./config` — and
// `config.js` requires nothing in this repository, so there is no cycle to
// close and no route order to disturb. It registers no endpoint, exactly like
// `oauth-oidc/dpop.js` (rule 3), and it is BELOW `helpers.js` rather than
// beside it: helpers requires this file for its key generation and its token
// minting, so this file may never require helpers back. Concretely, that means
// **nothing here reads `STS`, the ambient realm, or a session** — every
// function takes the key it is to use as a parameter. Realm-awareness is
// helpers.js's job and stays there.
//
// It also means `logArtifact()` is not reachable from here. That is on purpose:
// the callers keep their own `logArtifact('SAML assertion', 'before signing', …)`
// lines exactly where they were, so the debug log of a mock — which is the
// point of a mock — is unchanged by this refactor. A hook back into helpers
// would have been a sixth inverted slot, and the root CLAUDE.md's rule 3e is
// explicit that a slot is for a require that would close a cycle or move a
// route, not for convenience.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const forge = require('node-forge');
// The DER writer for the post-quantum certificate below. node-forge cannot
// represent an ML-DSA key at all, so that one certificate is built by hand.
const asn1js = require('asn1js');
const jwt = require('jsonwebtoken');
const bunyan = require('bunyan');
const config = require('./config');
const pqJose = require('./pq_jose');

// ---------------------------------------------------------------------------
// REQUIRED FOR ITS EFFECT, and the effect is the point: loading the pool is
// what hands pq_jose.js the pool to use, so this line is why signJwsAsync()
// below computes in a child process rather than in this one. See the foot of
// common/worker_pool.js, which explains why the reference goes that way round
// and why a worker process is never armed by it.
//
// This module is where the line belongs because this module is what routes an
// `alg` to pq_jose.js in the first place — every path that can reach a
// post-quantum signature comes through here.
// ---------------------------------------------------------------------------
require('./worker_pool');
const xmldom = require('@xmldom/xmldom');

const log = bunyan.createLogger({
  name: 'crypto',
  level: config.value('global.logLevel')
});

// ---------------------------------------------------------------------------
// THE TWO DOM CONSTRUCTORS, INSTALLED AS GLOBALS BEFORE xmldsig.js IS REQUIRED.
//
// The vendored module is the parent project's BROWSER code, where `DOMParser`
// and `XMLSerializer` are ambient. Node has neither. `@xmldom/xmldom` supplies
// both and is already a dependency of this service, and this is exactly what
// the parent's own `api/server.js` does at its line 987 for the same file — so
// this is the established way to run it server-side rather than something
// invented here.
//
// THE ORDER OF THE NEXT FIVE LINES IS LOAD-BEARING. `xmldsig.js` captures
// nothing at require time, but every function in it reaches for the bare
// globals, so a `require` that happened before this ran would load fine and
// then fail on the first signature with "DOMParser is not defined" — a message
// that names neither this file nor the real problem.
//
// They are set only when absent. Something else in the process may have
// installed a real DOM (a test harness, a future jsdom), and quietly replacing
// it would be the kind of action at a distance that is impossible to find.
// ---------------------------------------------------------------------------
if (!global.DOMParser) {
  global.DOMParser = xmldom.DOMParser;
}
if (!global.XMLSerializer) {
  global.XMLSerializer = xmldom.XMLSerializer;
}
const xmldsig = require('./vendored/xmldsig.js');

// The namespace URIs this file names. They are also exported by xmldsig.js and
// are repeated here ONLY as local constants for readability — a caller that
// needs one should take it from the re-export at the bottom, so that there
// stays exactly one spelling of each in the process.
const DS_NS = 'http://www.w3.org/2000/09/xmldsig#';
const XENC_NS = 'http://www.w3.org/2001/04/xmlenc#';
const XENC11_NS = 'http://www.w3.org/2009/xmlenc11#';
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';

// ===========================================================================
// SECTION 1 — XML DIGITAL SIGNATURE
// ===========================================================================

// ---------------------------------------------------------------------------
// WHERE THE <ds:Signature> GOES, and all three are schema-mandated rather than
// a matter of taste. Getting one wrong produces a document that VERIFIES and
// that a strict parser rejects, which is the worst of both worlds and is why
// they are named here rather than passed as raw strings from six call sites.
//
//   AFTER_ISSUER  a SAML 2.0 protocol message or assertion, and a signed
//                 AuthnRequest. The schema puts ds:Signature immediately after
//                 <Issuer>; xml-crypto with no location appended it to the
//                 document element instead, which several identity providers
//                 refuse without saying why.
//   FIRST         a metadata <EntityDescriptor>, and a SAML 1.1 Response whose
//                 signature precedes the assertion.
//   LAST          a SAML 1.1 assertion, which has no <Issuer> ELEMENT at all —
//                 in 1.1 the issuer is an ATTRIBUTE, so "after the issuer" is
//                 not a position that exists.
// ---------------------------------------------------------------------------
const PLACEMENT = {
  AFTER_ISSUER: 'after-issuer',
  FIRST: 'first',
  LAST: 'last'
};

// The id attributes an XML signature reference may name, in the order the
// vendored findById() searches. SAML 1.1 gives every message type its own
// spelling instead of one shared attribute, which is the whole reason the old
// xml-crypto call sites had to be told the name and this one does not.
const ID_ATTRIBUTES = ['ID', 'AssertionID', 'ResponseID', 'RequestID', 'Id', 'id'];

// The id an element carries, whatever it is called. Returns '' when there is
// none, which is a legal signature reference (URI="" means the whole document)
// rather than an error.
function idOf(element) {
  for (let i = 0; i < ID_ATTRIBUTES.length; i++) {
    const value = element.getAttribute(ID_ATTRIBUTES[i]);
    if (value) {
      return value;
    }
  }
  return '';
}

// A direct child by local name, namespace-insensitively. `getElementsByTagName`
// would reach into descendants, and on a Response carrying a signed assertion
// that is the difference between this element's signature and somebody else's.
function directChildByLocal(parent, localName, namespaceUri) {
  for (let child = parent.firstChild; child; child = child.nextSibling) {
    if (child.nodeType !== 1 || child.localName !== localName) {
      continue;
    }
    if (namespaceUri && child.namespaceURI !== namespaceUri) {
      continue;
    }
    return child;
  }
  return null;
}

// ---------------------------------------------------------------------------
// SIGN ONE DOCUMENT, ENVELOPED.
//
// This replaces six near-identical functions. `opts`:
//
//   privateKeyPem  required. The PEM, not a KeyObject — forge parses PEM, and
//                  this is why helpers.js still keeps `STS.privateKeyPem`
//                  alongside the pre-parsed `STS.privateKey` that jsonwebtoken
//                  wants.
//   certPem        embedded as <ds:KeyInfo><ds:X509Data>. Omit to sign with no
//                  KeyInfo, which nothing here does but the profile allows.
//   placement      one of PLACEMENT above. Defaults to AFTER_ISSUER because
//                  five of the six callers want it.
//   refUri         normally omitted: the vendored signer reads the root
//                  element's own id, trying ID, AssertionID and Id in turn, and
//                  references THAT. Pass it only to reference something the
//                  root does not carry.
//   what           a label for the debug line. Not part of the signature.
//
// **THE ARGUMENT THAT USED TO LIVE AT EVERY CALL SITE — that exclusive
// canonicalization is load-bearing — is now made once, here.** A SAML assertion
// is signed as a standalone document and then embedded inside an RSTR, a
// Response or a wresult that declares prefixes of its own (wst, wsp, wsa,
// samlp). INCLUSIVE c14n would pull those ancestor declarations into the digest
// at verification time, so the signature would fail for every relying party
// while verifying perfectly here — the worst shape of bug to chase. Exclusive
// renders only visibly-utilized prefixes and is therefore stable under
// embedding. It is the default below and no caller overrides it.
// ---------------------------------------------------------------------------
function signXml(xml, opts) {
  const options = opts || {};
  const what = options.what || 'XML document';
  log.debug('Entering signXml(). what=' + what + ', placement=' +
            (options.placement || PLACEMENT.AFTER_ISSUER));
  if (!options.privateKeyPem) {
    log.debug('Leaving signXml(). No private key.');
    throw new Error('signXml: privateKeyPem is required to sign ' + what + '.');
  }
  // ---------------------------------------------------------------------
  // THE REFERENCE IS RESOLVED HERE RATHER THAN LEFT TO THE SIGNER, AND A TEST
  // IS WHY. The vendored signer works the id out from the root element when it
  // is given none — but it looks for `ID`, `AssertionID` and `Id` only. SAML
  // 1.1 spells a RESPONSE'S id `ResponseID`, which is on neither that list nor
  // xml-crypto's, so a SAML 1.1 Response signed without an explicit reference
  // came out with `URI=""`.
  //
  // That is not a broken signature — an empty URI means the whole document and
  // it verifies — but it is not the document a SAML 1.1 relying party is
  // looking at, and it is the SAME SHAPE OF DEFECT as the `Id="_0"` bug this
  // module exists to have made impossible: a signature that verifies
  // everywhere and references the wrong thing, which is exactly what survives
  // for months. `saml11_sso.js` passes its id explicitly and was never
  // affected; this is about what happens when the next caller does not.
  //
  // `idOf()` knows all six spellings, so the safe behaviour is now the default
  // one and a caller has to work to get anything else. An explicit `refUri` is
  // still honoured — including a deliberate empty string.
  // ---------------------------------------------------------------------
  let refUri = options.refUri;
  if (refUri === undefined || refUri === null) {
    const root = new xmldom.DOMParser()
      .parseFromString(String(xml), 'text/xml').documentElement;
    const id = root ? idOf(root) : '';
    refUri = id ? ('#' + id) : '';
  }
  const signed = xmldsig.signEnveloped(xml, {
    privateKeyPem: options.privateKeyPem,
    certPem: options.certPem,
    placement: options.placement || PLACEMENT.AFTER_ISSUER,
    refUri: refUri,
    sigAlg: options.sigAlg,
    c14nAlg: options.c14nAlg,
    includeKeyInfo: options.includeKeyInfo
  });
  log.debug('Leaving signXml(). ' + signed.length + ' characters.');
  return signed;
}

// ---------------------------------------------------------------------------
// VERIFY THE SIGNATURE ON ONE NAMED ELEMENT, AND ON NO OTHER.
//
// **`element` IS THE WHOLE REASON THIS FUNCTION IS NOT ONE LINE OVER THE
// VENDORED verifyXml(), AND THE BUG IT PREVENTS IS A REAL ONE THAT WAS
// MEASURED.** A SAML Response carrying a signed assertion has TWO signatures.
// Every general-purpose verifier — the vendored one, and three of the four
// implementations this replaced — takes the FIRST <ds:Signature> in document
// order. On a SAML 1.1 Browser/POST response, where this service signs the
// Response LAST, the first one is the ASSERTION'S. So a caller asking "is this
// Response signed by us" was handed a confident `true` about a different
// element. That is one small step from accepting a Response whose assertion was
// swapped for another validly-signed one, which is the signature-wrapping
// attack the guards in every XML library exist to stop.
//
// So the target is chosen HERE, by policy: the first element with the wanted
// local name that carries a ds:Signature as a DIRECT CHILD. The vendored engine
// is then handed exactly two things — that one signature, serialized on its own,
// and the target element with that signature removed as `referencedXml`. It has
// no opportunity to choose differently, and it still brings its full algorithm
// coverage: RSA, PSS, ECDSA, HMAC, every canonicalization, the transforms.
//
// Removing the signature before handing over is not a trick; it is what the
// enveloped-signature transform is DEFINED to do (XMLDSIG section 6.6.4 — the
// signature element is omitted from the digest). The transform then finds
// nothing left to remove and is a no-op, which is the correct outcome and not a
// skipped check.
//
// It ANSWERS RATHER THAN THROWS, and `present` is separate from `ok` because
// "there is no signature here" and "the signature is wrong" are different facts
// that every caller reports differently.
//
// ONE LIMIT, STATED RATHER THAN DISCOVERED: a NESTED element is verified from
// its serialized subtree, so namespace prefixes declared by an ANCESTOR and
// merely inherited are not in those octets. Under exclusive c14n — which is
// what this service signs with, what SAML mandates, and what every partner seen
// here uses — that is exactly right, because exclusive c14n renders only
// visibly-utilized prefixes and deliberately ignores inherited ones. Under
// INCLUSIVE c14n it would not be, so that case is detected and reported below
// rather than being quietly wrong.
// ---------------------------------------------------------------------------
function verifyXmlSignature(xml, opts) {
  const options = opts || {};
  const wanted = options.element;
  log.debug('Entering verifyXmlSignature(). element=' + wanted);
  if (!wanted) {
    log.debug('Leaving verifyXmlSignature(). No element named.');
    throw new Error('verifyXmlSignature: `element` is required — a verifier ' +
                    'that guesses which signature it is checking is the bug ' +
                    'this function exists to prevent.');
  }

  let doc;
  try {
    doc = new xmldom.DOMParser().parseFromString(String(xml), 'text/xml');
  } catch (e) {
    // Not XML at all. The parser's own message is more use than one of ours,
    // and this is somebody else's document being wrong rather than a fault here.
    log.debug('Leaving verifyXmlSignature(). It did not parse: ' + e.message);
    return { ok: false, present: false,
             why: 'the document is not well-formed XML: ' + e.message };
  }

  // The target: the first element of that name carrying its OWN signature.
  let target = null;
  let sigEl = null;
  const candidates = doc.getElementsByTagName('*');
  for (let i = 0; i < candidates.length && !target; i++) {
    if (candidates[i].localName !== wanted) {
      continue;
    }
    const own = directChildByLocal(candidates[i], 'Signature', DS_NS);
    if (own) {
      target = candidates[i];
      sigEl = own;
    }
  }

  if (!target) {
    // Two different facts, and telling them apart is most of the diagnosis: a
    // document with no such element is a routing or profile mistake, and one
    // whose element is simply unsigned is a configuration mistake at the far
    // end. Reporting "no signature" for both sends people to the wrong place.
    let exists = false;
    for (let i = 0; i < candidates.length && !exists; i++) {
      exists = candidates[i].localName === wanted;
    }
    log.debug('Leaving verifyXmlSignature(). No signed <' + wanted + '>.');
    return { ok: false, present: false,
             why: exists
               ? 'the <' + wanted + '> carries no ds:Signature of its own'
               : 'the document contains no <' + wanted + '> at all' };
  }

  // The reference must name THIS element. A signature whose reference points
  // somewhere else may verify perfectly and say nothing whatever about the
  // element the caller asked about — which is signature wrapping, exactly.
  const signedInfo = directChildByLocal(sigEl, 'SignedInfo', DS_NS);
  const reference = signedInfo
    ? signedInfo.getElementsByTagNameNS('*', 'Reference')[0] : null;
  const referenceUri = reference ? (reference.getAttribute('URI') || '') : '';
  const targetId = idOf(target);
  if (referenceUri !== '' && referenceUri.replace(/^#/, '') !== targetId) {
    log.debug('Leaving verifyXmlSignature(). The reference names something else.');
    return { ok: false, present: true,
             why: 'the signature on this <' + wanted + '> references "' + referenceUri +
                  '" rather than the element it is attached to (' +
                  (targetId ? '#' + targetId : 'which carries no id') +
                  '), so it says nothing about this element' };
  }

  // Inclusive canonicalization on a NESTED element: see the note above. Said
  // out loud rather than attempted, because a wrong answer here reads as a
  // broken signature and would send somebody looking at the signer.
  const c14nEl = signedInfo
    ? signedInfo.getElementsByTagNameNS('*', 'CanonicalizationMethod')[0] : null;
  const c14nAlg = c14nEl ? (c14nEl.getAttribute('Algorithm') || '') : '';
  const isNested = target !== doc.documentElement;
  if (isNested && c14nAlg && c14nAlg.indexOf('xml-exc-c14n') === -1) {
    log.debug('Leaving verifyXmlSignature(). Inclusive c14n on a nested element.');
    return { ok: false, present: true,
             why: 'this nested <' + wanted + '> is signed with ' + c14nAlg +
                  ', an INCLUSIVE canonicalization whose digest depends on ' +
                  'namespace declarations inherited from its ancestors. This ' +
                  'service verifies a nested element from its own subtree and ' +
                  'cannot reproduce those octets, so it refuses rather than ' +
                  'reporting a failure it did not really test' };
  }

  const serializer = new xmldom.XMLSerializer();
  const signatureXml = serializer.serializeToString(sigEl);
  sigEl.parentNode.removeChild(sigEl);
  const referencedXml = serializer.serializeToString(target);

  let result;
  try {
    result = xmldsig.verifyXml(signatureXml, {
      certPem: options.certPem,
      publicKeyPem: options.publicKeyPem,
      referencedXml: referencedXml
    });
  } catch (e) {
    // The engine throws rather than answering for a malformed signature
    // element or an algorithm it cannot name, and the message says WHICH — an
    // unresolvable reference reads quite differently from a digest mismatch,
    // and that distinction is the whole diagnosis. This comment used to exist,
    // word for word, in four separate files.
    log.debug('Leaving verifyXmlSignature(). It threw: ' + e.message);
    return { ok: false, present: true, why: e.message };
  }

  const firstRef = (result.references || [])[0] || {};
  let why = '';
  if (!result.valid) {
    if (result.signatureValid === false) {
      why = 'the signature value does not verify against the expected ' +
            'certificate' + (result.signatureError ? ': ' + result.signatureError : '');
    } else if (firstRef.ok === false) {
      why = 'the signature value is genuine but the digest does not match, so ' +
            'the <' + wanted + '> was altered after it was signed' +
            (firstRef.reason ? ' (' + firstRef.reason + ')' : '');
    } else {
      why = result.error || 'the signature did not verify';
    }
  }
  log.debug('Leaving verifyXmlSignature(). ok=' + result.valid);
  return {
    ok: !!result.valid,
    present: true,
    why: why,
    // Passed through for the pages that show a check-by-check verdict — the
    // WS-Federation mock relying party, the SAML mock service provider and the
    // OID4VP verifier all draw one, and one boolean would tell a person nothing
    // they could act on.
    signatureValid: !!result.signatureValid,
    referencesValid: !!result.referencesValid,
    signatureMethod: result.signatureMethod || '',
    canonicalization: result.canonicalization || '',
    signerSubject: result.signerSubject || '',
    signerCertB64: result.signerCertB64 || '',
    referenceUri: firstRef.uri === undefined ? referenceUri : firstRef.uri
  };
}

// ---------------------------------------------------------------------------
// THE SAML HTTP REDIRECT BINDING'S DETACHED SIGNATURE (saml-bindings-2.0-os
// section 3.4.4.1). It is a signature over the QUERY STRING and not over any
// document, so it shares nothing with signXml() above except the key.
//
// The ORDER of the parameters in the signed octet string is part of the
// specification — SAMLRequest or SAMLResponse, then RelayState if there is one,
// then SigAlg — and building that string is the CALLER'S job, because only the
// caller knows which of the two message parameters it has. A verifier rebuilds
// it from the parameters as they arrived, so a signer that used a different
// order produces a signature that verifies nowhere and whose only symptom at
// the far end is "invalid signature".
// ---------------------------------------------------------------------------
function signQueryString(queryString, privateKeyPem, sigAlg) {
  log.debug('Entering signQueryString().');
  if (!privateKeyPem) {
    log.debug('Leaving signQueryString(). No private key.');
    throw new Error('signQueryString: privateKeyPem is required.');
  }
  const signature = xmldsig.signQueryString(queryString, {
    privateKeyPem: privateKeyPem,
    sigAlg: sigAlg
  });
  log.debug('Leaving signQueryString(). ' + signature.length + ' characters.');
  return signature;
}

// ===========================================================================
// SECTION 2 — XML ENCRYPTION
// ===========================================================================
//
// ---------------------------------------------------------------------------
// THIS SECTION IS MOVED FROM `saml/saml2.js` RATHER THAN REPLACED BY THE
// VENDORED encryptXml()/decryptXml(), AND THAT IS A DELIBERATE EXCEPTION TO
// EVERYTHING SAID AT THE TOP OF THIS FILE. It is worth the paragraph, because
// the obvious reading of this refactor is that the vendored module always wins.
//
// It does not win here, for two reasons and neither is inertia. The OUTPUT of
// the two is already byte-compatible — same EncryptedData shape, same
// EncryptedKey nesting, same echoed recipient certificate, verified element by
// element — so there was no interop gap to close, which was the whole argument
// for the signature half. And what this implementation has that the vendored
// one does not is the DIAGNOSIS: it answers rather than throwing, it names an
// unknown cipher and an unknown key transport separately, it checks the
// unwrapped key's LENGTH (because RSA-1_5 unwraps a wrong key to plausible
// garbage instead of failing), it parses the plaintext before calling CBC a
// success, and it tells a NamespaceError in a perfectly good NameID apart from
// a wrong certificate. Every one of those messages exists because somebody once
// chased the wrong thing, and a mock whose whole value is explaining what went
// wrong does not trade them for a shared line count.
//
// So this is centralization by MOVE. It was already one implementation with two
// callers; it is now one implementation in the module where the other three
// crypto families live, and `saml/saml2.js` re-exports it so WS-Trust's
// `?encrypt=1` path is untouched.
// ---------------------------------------------------------------------------

// Every block cipher this service will encrypt with or decrypt, by its
// algorithm URI. `keyBytes` is the AES key length; `mode` is what forge calls
// it; `ivBytes` and `tagBytes` are the layout above. A URI that is not here is
// refused BY NAME on the way in and cannot be chosen on the way out, because
// the setting is an enum over exactly these keys.
const BLOCK_CIPHERS = {
  'aes256-gcm': { uri: XENC11_NS + 'aes256-gcm', keyBytes: 32, mode: 'AES-GCM',
                  ivBytes: 12, tagBytes: 16 },
  'aes128-gcm': { uri: XENC11_NS + 'aes128-gcm', keyBytes: 16, mode: 'AES-GCM',
                  ivBytes: 12, tagBytes: 16 },
  'aes256-cbc': { uri: XENC_NS + 'aes256-cbc', keyBytes: 32, mode: 'AES-CBC',
                  ivBytes: 16, tagBytes: 0 },
  'aes128-cbc': { uri: XENC_NS + 'aes128-cbc', keyBytes: 16, mode: 'AES-CBC',
                  ivBytes: 16, tagBytes: 0 }
};

// The two key transports. `rsa-1_5` is RSAES-PKCS1-v1_5 and is offered because
// old service providers require it, not because it is safe.
const KEY_TRANSPORTS = {
  'rsa-oaep-mgf1p': { uri: XENC_NS + 'rsa-oaep-mgf1p', scheme: 'RSA-OAEP' },
  'rsa-1_5': { uri: XENC_NS + 'rsa-1_5', scheme: 'RSAES-PKCS1-V1_5' }
};

function cipherByUri(uri) {
  const name = Object.keys(BLOCK_CIPHERS).filter(function (key) {
    return BLOCK_CIPHERS[key].uri === uri;
  })[0];
  return name ? Object.assign({ name: name }, BLOCK_CIPHERS[name]) : null;
}

function transportByUri(uri) {
  const name = Object.keys(KEY_TRANSPORTS).filter(function (key) {
    return KEY_TRANSPORTS[key].uri === uri;
  })[0];
  return name ? Object.assign({ name: name }, KEY_TRANSPORTS[name]) : null;
}

// The forge options for a key transport. RSA-OAEP here is SHA-1/MGF1-SHA1,
// which is what `rsa-oaep-mgf1p` MEANS — the newer `rsa-oaep` URI carries its
// digest in a child element and is deliberately not offered, because a service
// provider that can do that can do GCM too and this list exists for the ones
// that cannot.
function transportOptions(transport) {
  if (transport.scheme === 'RSA-OAEP') {
    return { md: forge.md.sha1.create(), mgf1: { md: forge.md.sha1.create() } };
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// ENCRYPT ONE ELEMENT, wrapped in whatever the caller says.
//
// `wrapper` is the SAML element that holds the result — `EncryptedAssertion`
// for a Response, `EncryptedID` for a NameID in a LogoutRequest — and it is a
// parameter because those two are the same document with a different name
// around it. A third caller passes a third name and needs no new function.
//
// The RECIPIENT'S CERTIFICATE is echoed into ds:KeyInfo. That is not required
// and it is deliberate: a service provider with more than one key has to be
// told which one this was encrypted to, and the alternative — a KeyName, or
// nothing — leaves it guessing. It is the recipient's OWN public certificate,
// so publishing it back to them discloses nothing.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE ARTIFACT LOG, PASSED IN RATHER THAN REACHED FOR.
//
// `helpers.logArtifact()` writes the before-and-after of everything this
// service mints, and at the default `debug` level that IS the product: a mock
// exists so somebody can see what a protocol looks like. This file cannot
// require helpers.js — helpers requires THIS file, and a cycle in node hands
// back a half-initialised module whose exports are `undefined`, with the
// failure arriving later as something that is not a function.
//
// So it is an ordinary optional parameter. Not a sixth inverted slot (root
// CLAUDE.md rule 3e): a slot costs every reader an indirection and is for a
// require that would close a cycle or move a route, and a caller that already
// has the function can simply hand it over. `saml/saml2.js` and
// `ws-trust/wstrust.js` pass `helpers.logArtifact` and their log output is
// byte-for-byte what it was before this move.
// ---------------------------------------------------------------------------
function artifact(opts, what, stage, value) {
  const sink = opts && opts.logArtifact;
  if (typeof sink !== 'function') {
    return;
  }
  try {
    sink(what, stage, value);
  } catch (e) {
    // A logger that throws must not fail the encryption it was describing —
    // the tail wagging the dog, which is the rule signJwt()'s recorder follows.
    log.error('the artifact logger threw and was ignored: ' + e.message);
  }
}

function encryptElement(xml, certPem, opts) {
  log.debug("Entering encryptElement().");
  opts = opts || {};
  const wrapper = opts.wrapper || 'saml:EncryptedAssertion';
  const cipher = BLOCK_CIPHERS[opts.algorithm] || BLOCK_CIPHERS['aes256-gcm'];
  const transport = KEY_TRANSPORTS[opts.keyTransport] || KEY_TRANSPORTS['rsa-oaep-mgf1p'];
  artifact(opts, 'SAML 2.0 ' + wrapper, 'before encryption', xml);

  const cert = forge.pki.certificateFromPem(certPem);
  const key = forge.random.getBytesSync(cipher.keyBytes);
  const iv = forge.random.getBytesSync(cipher.ivBytes);
  const c = forge.cipher.createCipher(cipher.mode, key);
  // The tag length matters only to GCM; forge ignores it for CBC, and passing
  // it unconditionally keeps this one call rather than two.
  c.start({ iv: iv, tagLength: cipher.tagBytes * 8 });
  c.update(forge.util.createBuffer(forge.util.encodeUtf8(xml)));
  if (!c.finish()) {
    log.debug("Leaving encryptElement(). The cipher refused.");
    throw new Error('SAML encryption failed in ' + cipher.mode);
  }
  const body = cipher.tagBytes
    ? iv + c.output.getBytes() + c.mode.tag.getBytes()
    : iv + c.output.getBytes();
  const wrapped = cert.publicKey.encrypt(key, transport.scheme, transportOptions(transport));
  const certB64 = certPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');

  const encrypted =
    '<' + wrapper + ' xmlns:saml="' + NS_SAML + '">' +
    '<xenc:EncryptedData xmlns:xenc="' + XENC_NS + '" Type="' + XENC_NS + 'Element">' +
      '<xenc:EncryptionMethod Algorithm="' + cipher.uri + '"/>' +
      '<ds:KeyInfo xmlns:ds="' + DS_NS + '">' +
        '<xenc:EncryptedKey>' +
          '<xenc:EncryptionMethod Algorithm="' + transport.uri + '">' +
            // The digest child belongs to OAEP and is meaningless under
            // RSA-1_5, so it is emitted only where it means something. A
            // service provider parsing strictly refuses the stray element.
            (transport.scheme === 'RSA-OAEP'
              ? '<ds:DigestMethod xmlns:ds="' + DS_NS + '" Algorithm="' + DS_NS + 'sha1"/>'
              : '') +
          '</xenc:EncryptionMethod>' +
          '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>' + certB64 +
          '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' +
          '<xenc:CipherData><xenc:CipherValue>' + forge.util.encode64(wrapped) +
          '</xenc:CipherValue></xenc:CipherData>' +
        '</xenc:EncryptedKey>' +
      '</ds:KeyInfo>' +
      '<xenc:CipherData><xenc:CipherValue>' + forge.util.encode64(body) +
      '</xenc:CipherValue></xenc:CipherData>' +
    '</xenc:EncryptedData></' + wrapper + '>';

  artifact(opts, 'SAML 2.0 ' + wrapper,
           'after encryption (' + cipher.name + ', key wrapped with ' + transport.name + ')',
           encrypted);
  log.debug("Leaving encryptElement(). " + cipher.name + " / " + transport.name + ".");
  return encrypted;
}

// The original name, kept because WS-Trust calls it and its signature is part
// of that module's contract. It is now one line over encryptElement().
function encryptAssertion(assertionXml, certPem, opts) {
  return encryptElement(assertionXml, certPem,
    Object.assign({}, opts, { wrapper: 'saml:EncryptedAssertion' }));
}

// ---------------------------------------------------------------------------
// DECRYPT, and it ANSWERS RATHER THAN THROWS.
//
// `{ ok, xml, why, algorithm, keyTransport }`. Every failure here is somebody
// else's document being wrong — encrypted to a key this service does not hold,
// in an algorithm it does not have, or simply corrupt — and a mock that threw
// would turn a bad LogoutRequest into a stack trace instead of into a refusal
// with a sentence. The caller decides what a failure means, which differs: a
// LogoutRequest with an undecryptable EncryptedID is refused, and a future
// caller might carry on without the value.
//
// IT TAKES THE ELEMENT'S XML, NOT A PARSED NODE, so a caller can hand it a
// serialised subtree and this function owns the parsing. That also keeps the
// namespace handling in one place: `getElementsByTagNameNS('*', ...)` matches
// on LOCAL NAME so a document using `xe:` or no prefix at all is read the same,
// which is the same rule helpers.firstByLocal() follows and for the same
// reason.
// ---------------------------------------------------------------------------
// DOES THIS PLAINTEXT PARSE, allowing for a fragment that relies on its parent
// for a namespace prefix?
//
// This is the second bug this check found and it was in the check itself. A
// decrypted <saml:EncryptedID> often contains `<saml:NameID Format="...">` with
// NO xmlns:saml on it, because in the document it came from the prefix was
// declared on the LogoutRequest three levels up. Parsed on its own that is a
// NamespaceError, and the first version of this function reported a perfectly
// good NameID as corrupt.
//
// So it is tried twice: as it stands, and then inside a container that declares
// the prefixes a SAML fragment can legitimately expect to inherit. Only if BOTH
// fail is it rubbish. What this service ITSELF emits is self-contained — see
// subjectFor() in saml2_sso.js — but somebody else's document is not this
// service's to dictate.
function parsesAsFragment(xml) {
  const ok = function (doc) {
    return !!(doc && doc.documentElement &&
              !doc.getElementsByTagName('parsererror').length);
  };
  try {
    if (ok(new DOMParser().parseFromString(xml, 'text/xml'))) return true;
  } catch (e) {
    // Not a failure yet: the wrapped attempt below is the one that matters for
    // a fragment, and a genuine syntax error fails that too.
  }
  const wrapped = '<x xmlns:saml="' + NS_SAML +
    '" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
    ' xmlns:ds="' + DS_NS + '" xmlns:xenc="' + XENC_NS + '">' + xml + '</x>';
  try {
    return ok(new DOMParser().parseFromString(wrapped, 'text/xml'));
  } catch (e) {
    return false;
  }
}

function decryptElement(xml, privateKeyPem, opts) {
  log.debug("Entering decryptElement().");
  let doc;
  try {
    doc = new DOMParser().parseFromString(String(xml), 'text/xml');
  } catch (e) {
    // Not XML at all. The message is the parser's and is more use than ours.
    log.debug("Leaving decryptElement(). It did not parse.");
    return { ok: false, why: 'the encrypted element is not well-formed XML: ' + e.message };
  }
  const data = doc.getElementsByTagNameNS('*', 'EncryptedData')[0];
  if (!data) {
    log.debug("Leaving decryptElement(). No EncryptedData.");
    return { ok: false, why: 'there is no <xenc:EncryptedData> inside it' };
  }
  const dataMethod = data.getElementsByTagNameNS('*', 'EncryptionMethod')[0];
  const cipher = cipherByUri(dataMethod ? dataMethod.getAttribute('Algorithm') : '');
  if (!cipher) {
    log.debug("Leaving decryptElement(). Unknown block cipher.");
    return { ok: false, why: 'the data is encrypted with ' +
             ((dataMethod && dataMethod.getAttribute('Algorithm')) || '(no algorithm stated)') +
             ', and this service reads only ' + Object.keys(BLOCK_CIPHERS).join(', ') };
  }
  const keyEl = data.getElementsByTagNameNS('*', 'EncryptedKey')[0];
  if (!keyEl) {
    // A <RetrievalMethod> pointing at an EncryptedKey elsewhere in the document
    // is legal and is not implemented: nothing this service issues produces one,
    // and saying so is more useful than a null dereference three lines down.
    log.debug("Leaving decryptElement(). No EncryptedKey.");
    return { ok: false, why: 'there is no <xenc:EncryptedKey> inside the KeyInfo. A key ' +
             'carried elsewhere and pointed at with <ds:RetrievalMethod> is legal and is ' +
             'not implemented here' };
  }
  const keyMethod = keyEl.getElementsByTagNameNS('*', 'EncryptionMethod')[0];
  const transport = transportByUri(keyMethod ? keyMethod.getAttribute('Algorithm') : '');
  if (!transport) {
    log.debug("Leaving decryptElement(). Unknown key transport.");
    return { ok: false, why: 'the key is wrapped with ' +
             ((keyMethod && keyMethod.getAttribute('Algorithm')) || '(no algorithm stated)') +
             ', and this service unwraps only ' + Object.keys(KEY_TRANSPORTS).join(', ') };
  }
  // Two CipherValues: the wrapped key inside EncryptedKey, and the data. Read
  // the key's from the EncryptedKey subtree rather than from the document, or a
  // document whose EncryptedKey comes second yields the wrong one.
  const keyCipher = keyEl.getElementsByTagNameNS('*', 'CipherValue')[0];
  const dataCipherEls = data.getElementsByTagNameNS('*', 'CipherValue');
  let dataCipher = null;
  for (let n = 0; n < dataCipherEls.length; n++) {
    if (!keyEl.contains || !keyEl.contains(dataCipherEls[n])) {
      dataCipher = dataCipherEls[n];
    }
  }
  if (!keyCipher || !dataCipher) {
    log.debug("Leaving decryptElement(). A CipherValue is missing.");
    return { ok: false, why: 'the element is missing one of its two <xenc:CipherValue>s — ' +
             'the wrapped key, or the data' };
  }

  try {
    const priv = forge.pki.privateKeyFromPem(privateKeyPem);
    const key = priv.decrypt(forge.util.decode64((keyCipher.textContent || '').trim()),
                             transport.scheme, transportOptions(transport));
    if (!key || key.length !== cipher.keyBytes) {
      // A WRONG KEY IS THE ORDINARY FAILURE and it is worth naming: this
      // service regenerates its key on every start, so a service provider that
      // cached the certificate from a previous run encrypts to a key that no
      // longer exists. Under RSA-1_5 that unwraps to plausible-looking garbage
      // of the wrong length rather than failing, which is the whole reason the
      // length is checked here.
      log.debug("Leaving decryptElement(). The unwrapped key is the wrong size.");
      return { ok: false, why: 'the wrapped key did not unwrap to a ' + cipher.keyBytes +
               '-byte key, so it was encrypted to a different certificate. This service ' +
               'regenerates its key on every start, so a stale copy of its metadata is the ' +
               'usual cause — fetch /saml2/metadata again' };
    }
    const raw = forge.util.decode64((dataCipher.textContent || '').trim());
    const iv = raw.slice(0, cipher.ivBytes);
    const decipher = forge.cipher.createDecipher(cipher.mode, key);
    if (cipher.tagBytes) {
      const tag = raw.slice(raw.length - cipher.tagBytes);
      decipher.start({ iv: iv, tag: forge.util.createBuffer(tag), tagLength: cipher.tagBytes * 8 });
      decipher.update(forge.util.createBuffer(
        raw.slice(cipher.ivBytes, raw.length - cipher.tagBytes)));
    } else {
      decipher.start({ iv: iv });
      decipher.update(forge.util.createBuffer(raw.slice(cipher.ivBytes)));
    }
    if (!decipher.finish()) {
      // For GCM this is the authentication tag failing, which means the
      // ciphertext was altered; for CBC it is the padding. They are different
      // facts and the message says which, because "decryption failed" sends
      // somebody looking at their key when the document was edited in transit.
      log.debug("Leaving decryptElement(). The cipher refused.");
      return { ok: false, why: cipher.tagBytes
        ? 'the AES-GCM authentication tag did not verify, so the ciphertext was altered ' +
          'after it was encrypted'
        : 'the AES-CBC padding is not valid, so the key or the ciphertext is wrong' };
    }
    const plain = forge.util.decodeUtf8(decipher.output.getBytes());
    // ---------------------------------------------------------------------
    // DOES IT PARSE? A cipher that finished is not a document that survived,
    // and the gap between those two is CBC's whole problem.
    //
    // AES-GCM is authenticated: an altered ciphertext fails the tag above and
    // never reaches here. AES-CBC IS NOT. Altering a byte of CBC ciphertext
    // corrupts one block, flips bits in the next, and quite often still leaves
    // valid PKCS#7 padding — so `finish()` returns true and hands back
    // plausible-looking rubbish. Measured, not assumed: flipping one character
    // of a CBC cipher value here returns the element TRUNCATED mid-tag, with no
    // error anywhere.
    //
    // So the plaintext is parsed before it is called a success. That is not
    // integrity — nothing can retrofit integrity onto unauthenticated CBC, and
    // this service offers CBC precisely because real service providers require
    // it — but it turns "here is your NameID" plus a crash two frames later
    // into one refusal that says what happened. A caller that wanted the bytes
    // whatever they are is not a caller this function has.
    if (!parsesAsFragment(plain)) {
      log.debug("Leaving decryptElement(). The plaintext is not XML.");
      return { ok: false, why: 'the decryption produced something that is not well-formed ' +
               'XML' + (cipher.tagBytes ? '' : ', and ' + cipher.name + ' is UNAUTHENTICATED — ' +
               'an altered ciphertext can decrypt to rubbish with valid padding and no error, ' +
               'which is what a GCM algorithm would have caught') };
    }
    artifact(opts, 'SAML 2.0 encrypted element',
             'after decryption (' + cipher.name + ', key unwrapped with ' +
             transport.name + ')', plain);
    log.debug("Leaving decryptElement(). " + plain.length + " characters.");
    return { ok: true, xml: plain, algorithm: cipher.name, keyTransport: transport.name };
  } catch (e) {
    // forge throws on a key that will not unwrap at all, which is the RSA-OAEP
    // equivalent of the length check above. Swallowed into an answer for the
    // reason this whole function answers rather than throws.
    //
    // THE MESSAGE IS NOT ASSUMED TO BE ABOUT THE KEY, and that is a correction
    // rather than caution: this catch covers the decryption AND the parse, and
    // while it said "the wrapped key could not be unwrapped" unconditionally, a
    // NamespaceError from a perfectly good NameID was reported as a wrong
    // certificate — which sends somebody to re-fetch metadata over a bug in the
    // parser three lines away.
    const aboutTheKey = /oaep|padding|rsa|decrypt|key/i.test(e.message || '');
    log.debug("Leaving decryptElement(). " + e.message);
    return { ok: false, why: aboutTheKey
      ? 'the wrapped key could not be unwrapped with this service\'s private key (' +
        e.message + '). It was encrypted to a different certificate — and this service ' +
        'regenerates its key on every start, so a stale copy of its metadata is the usual ' +
        'cause'
      : 'the encrypted element could not be read: ' + e.message };
  }
}

// ===========================================================================
// SECTION 3 — JWS / JWT
// ===========================================================================

// ---------------------------------------------------------------------------
// SIGN A JWS. Every RS256 signature this service puts on a JWT goes through
// here — but NOT every token is COUNTED here, and the difference matters.
//
// `helpers.signJwt()` sits directly on top of this and is the funnel that
// records a token in the admin console's register. It stays where it is because
// it needs two things this file must never reach: the ambient realm's key, and
// the recorder that `admin_stats.js` fills. What moved down here is the
// signature itself, so that the eight call sites that sign OUTSIDE that funnel
// — WS-Trust's SAML-shaped JWT, the three OID4VCI credential formats, the
// SD-JWT holder key, the RFC 8414 signed metadata, SPIFFE's JWT-SVID — are
// making the same call with the same defaults rather than each reaching for
// jsonwebtoken on its own.
//
// Those eight are still not counted, which is a documented property rather
// than an oversight (see `oid4vc/vc_issuer.js` and `ws-trust/wstrust.js`),
// and centralizing the signature does not change it.
// ---------------------------------------------------------------------------
// The `jsonwebtoken` sign options this service uses, passed through by name.
// A WHITELIST rather than a spread, and that is the point: a caller that hands
// over an object of its own cannot accidentally set `algorithm: 'none'` or
// swap the key, and a reader can see from here exactly what a signature in this
// service is allowed to vary by.
const SIGN_OPTIONS = ['keyid', 'header', 'expiresIn', 'notBefore', 'noTimestamp',
                      'issuer', 'audience', 'subject', 'jwtid'];

// ---------------------------------------------------------------------------
// THE ONE JWS ALGORITHM TABLE FOR THIS SERVICE.
//
// Every algorithm this service signs with or verifies is a row here, and every
// module that touches a JWS reads this rather than keeping a table of its own.
// `oauth-oidc/dpop.js` had the second one — nine rows, node-crypto parameters,
// its own verifier — which is how DPoP came to accept a different set of
// algorithms from everything else in the service for no reason anybody chose.
//
// TWO ROWS EXIST BECAUSE A LIBRARY CANNOT DO THEM. `jsonwebtoken`'s `algorithm`
// is a string enum with no EdDSA and no ES256K, so those two are signed and
// verified directly on node's OpenSSL below. That is a limit of the library and
// never of this service: a client may legitimately register either.
//
// THE ECDSA SIGNATURE FORMAT IS NODE'S JOB AND NOT OURS. RFC 7518 section 3.4
// wants the R||S concatenation, while a general-purpose API returns the DER
// SEQUENCE of two INTEGERs — and `dsaEncoding: 'ieee-p1363'` is node asking
// OpenSSL for the former. This file briefly carried a hand-written DER
// converter for ES256K; it worked, and it was a second implementation of
// something the runtime already does, so it is gone. Anything that needs the
// raw form passes that option.
// ---------------------------------------------------------------------------
const JWS_ALGS = {
  HS256: { family: 'hmac', hash: 'sha256' },
  HS384: { family: 'hmac', hash: 'sha384' },
  HS512: { family: 'hmac', hash: 'sha512' },
  RS256: { family: 'rsa', hash: 'sha256', kty: 'RSA' },
  RS384: { family: 'rsa', hash: 'sha384', kty: 'RSA' },
  RS512: { family: 'rsa', hash: 'sha512', kty: 'RSA' },
  PS256: { family: 'rsa', hash: 'sha256', kty: 'RSA',
           padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
           saltLength: 32 },
  PS384: { family: 'rsa', hash: 'sha384', kty: 'RSA',
           padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
           saltLength: 48 },
  PS512: { family: 'rsa', hash: 'sha512', kty: 'RSA',
           padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
           saltLength: 64 },
  ES256: { family: 'ec', hash: 'sha256', kty: 'EC', crv: 'P-256',
           namedCurve: 'prime256v1', sigBytes: 64 },
  ES384: { family: 'ec', hash: 'sha384', kty: 'EC', crv: 'P-384',
           namedCurve: 'secp384r1', sigBytes: 96 },
  ES512: { family: 'ec', hash: 'sha512', kty: 'EC', crv: 'P-521',
           namedCurve: 'secp521r1', sigBytes: 132 },
  // RFC 8812. `jsonwebtoken` has no ES256K, so this one is signed here.
  ES256K: { family: 'ec', hash: 'sha256', kty: 'EC', crv: 'secp256k1',
            namedCurve: 'secp256k1', sigBytes: 64, ownSigner: true },
  // RFC 8037. `jsonwebtoken` has no EdDSA either. Ed25519 hashes internally,
  // so there is no digest to name — which is what `crypto.sign(null, ...)`
  // means.
  EdDSA: { family: 'okp', hash: null, kty: 'OKP', crv: 'Ed25519',
           sigBytes: 64, ownSigner: true }
};

// The post-quantum and composite algorithms join the same table rather than
// living in one of their own — `common/pq_jose.js` performs them, and this is
// what makes them ordinary here: `signJws()` routes to it, `verifyCompactJws()`
// routes to it, and every metadata list that reads JWS_SIGNING_ALGS gained
// eleven entries without being touched.
//
// `kty: 'AKP'` is RFC 9964's key type for all of them, which is also why they
// are absent from DPoP: RFC 7638 defines a JWK Thumbprint for RSA, EC, OKP and
// oct and not for AKP, so a DPoP proof signed with one could not be bound to
// anything. See oauth-oidc/dpop.js.
pqJose.PQ_ALGS.forEach(function (alg) {
  JWS_ALGS[alg] = { family: 'pq', hash: null, kty: 'AKP', alg: alg,
                    ownSigner: true };
});

// Every signing algorithm, and the asymmetric ones — the split matters because
// several specifications say "an asymmetric algorithm, never a MAC and never
// none": DPoP proofs (RFC 9449 section 4.2), OID4VCI proofs of possession, and
// request objects are all in that class.
const JWS_SIGNING_ALGS = Object.keys(JWS_ALGS);
const JWS_ASYMMETRIC_ALGS = JWS_SIGNING_ALGS.filter(function (alg) {
  return JWS_ALGS[alg].family !== 'hmac';
});

function jwsSpec(alg) {
  log.debug('Entering jwsSpec(). alg=' + alg);
  const spec = JWS_ALGS[alg];
  if (!spec) {
    log.debug('Leaving jwsSpec(). Unknown.');
    throw new Error('unsupported JWS algorithm "' + alg + '"; this service ' +
      'implements ' + JWS_SIGNING_ALGS.join(', ') + '.');
  }
  log.debug('Leaving jwsSpec().');
  return spec;
}

// The node parameters for one verification or signature. One place, so the PSS
// salt length and the ECDSA encoding cannot disagree between two call sites.
function nodeParamsFor(spec, key) {
  log.debug('Entering nodeParamsFor().');
  const params = { key: key };
  if (spec.padding !== undefined) {
    params.padding = spec.padding;
    params.saltLength = spec.saltLength;
  }
  if (spec.family === 'ec') {
    // RFC 7518 section 3.4 wants R||S; this is node asking OpenSSL for it
    // rather than for the DER SEQUENCE it returns by default.
    params.dsaEncoding = 'ieee-p1363';
  }
  log.debug('Leaving nodeParamsFor().');
  return params;
}

// ---------------------------------------------------------------------------
// THE PROTECTED HEADER THE TWO HAND-ROLLED SIGNERS BUILD.
//
// `jsonwebtoken` merges `options.header` into the header it makes, so the
// library path has always honoured a caller's `typ`. THE OTHER TWO DID NOT:
// the `ownSigner` branch (EdDSA and ES256K, the two the library refuses) and
// the post-quantum branch each hard-coded `typ: 'JWT'` and ignored
// `options.header` entirely — so the SAME call produced a different header
// depending on which algorithm was chosen, and no caller could have seen that
// coming.
//
// **IT COST A REAL DEFECT AND THAT IS WHY THIS FUNCTION EXISTS.** A Security
// Event Token (RFC 8417 section 2.2) carries `typ: "secevent+jwt"`, and a
// receiver that dispatches on the media type — and several do — drops one
// without it with no error anybody sees. `ssf/ssf_events.js` asks for that
// header; on RS256 it got it and on EdDSA, ES256K and every post-quantum
// algorithm it silently did not, which is precisely the shape of failure this
// module was consolidated to end.
//
// `alg` and `kid` are this function's to set and a caller may not override
// them: the algorithm is what was actually used, and the kid names the key
// that was actually used. Everything else in `options.header` is merged.
// ---------------------------------------------------------------------------
function protectedHeaderFor(algorithm, options) {
  log.debug('Entering protectedHeaderFor(). alg=' + algorithm);
  const asked = (options && options.header && typeof options.header ===
    'object') ? options.header : {};
  const header = Object.assign({ typ: 'JWT' }, asked,
      { alg: algorithm });
  if (options && options.keyid) {
    header.kid = options.keyid;
  }
  log.debug('Leaving protectedHeaderFor(). typ=' + header.typ);
  return header;
}

// ---------------------------------------------------------------------------
// The JWS framing a post-quantum signature goes over: header, payload,
// base64url. The same shape as the `ownSigner` branch of signJws() below —
// written out here rather than shared with the debugger's copy ON PURPOSE, see
// the header of common/pq_jose.js — and factored out of it because the
// SYNCHRONOUS and the ASYNCHRONOUS signer must produce the same bytes, and two
// copies of a framing is one copy that will drift.
// ---------------------------------------------------------------------------
function pqSigningInput(payload, algorithm, options) {
  log.debug('Entering pqSigningInput(). alg=' + algorithm);
  const header = protectedHeaderFor(algorithm, options);
  const body = Object.assign({}, payload);
  if (body.iat === undefined) {
    body.iat = Math.floor(Date.now() / 1000);
  }
  const input = b64u(Buffer.from(JSON.stringify(header), 'utf8')) + '.' +
                b64u(Buffer.from(JSON.stringify(body), 'utf8'));
  log.debug('Leaving pqSigningInput(). ' + input.length + ' characters.');
  return input;
}

function signJws(payload, key, opts) {
  const options = opts || {};
  log.debug('Entering signJws(). alg=' + (options.algorithm || 'RS256') +
            ', typ=' + (payload && payload.typ ? payload.typ : '(none)'));
  // b64u() is defined further down this file with the JWE helpers; it is used
  // here too rather than written twice.
  if (!key) {
    log.debug('Leaving signJws(). No key.');
    throw new Error('signJws: a signing key is required.');
  }
  const algorithm = options.algorithm || 'RS256';
  const spec = jwsSpec(algorithm);
  if (spec.family === 'pq') {
    const pqInput = pqSigningInput(payload, algorithm, options);
    const pqSig = pqJose.sign(algorithm, key, Buffer.from(pqInput, 'ascii'));
    const pqOut = pqInput + '.' + b64u(pqSig);
    log.debug('Leaving signJws(). ' + algorithm + ', ' + pqOut.length +
              ' characters.');
    return pqOut;
  }
  if (spec.ownSigner) {
    // EdDSA and ES256K — the two `jsonwebtoken` refuses. Assembled here, on
    // node's OpenSSL, with the same claim conveniences the library gives the
    // others so that a token does not gain or lose `iat` depending on which
    // algorithm signed it.
    const header = protectedHeaderFor(algorithm, options);
    const body = Object.assign({}, payload);
    if (body.iat === undefined) {
      body.iat = Math.floor(Date.now() / 1000);
    }
    const input = b64u(Buffer.from(JSON.stringify(header), 'utf8')) + '.' +
                  b64u(Buffer.from(JSON.stringify(body), 'utf8'));
    const signature = nodeCrypto.sign(spec.hash, Buffer.from(input, 'ascii'),
        nodeParamsFor(spec, key));
    const out = input + '.' + b64u(signature);
    log.debug('Leaving signJws(). ' + algorithm + ', ' + out.length +
              ' characters.');
    return out;
  }
  const signOptions = { algorithm: algorithm };
  for (let i = 0; i < SIGN_OPTIONS.length; i++) {
    const name = SIGN_OPTIONS[i];
    if (options[name] !== undefined) {
      signOptions[name] = options[name];
    }
  }
  const signed = jwt.sign(payload, key, signOptions);
  log.debug('Leaving signJws(). ' + signed.length + ' characters.');
  return signed;
}

// ---------------------------------------------------------------------------
// THE SAME SIGNATURE, WITHOUT HOLDING THE EVENT LOOP.
//
// Post-quantum signing is the one thing this service does that takes SECONDS —
// 14.6 and 15.4 of them were measured for a single SLH-DSA-SHAKE-128s token on
// 2026-08-29 — and node runs this service's six listener families on one
// thread, so for those seconds it answers nobody: not another HTTP caller, not
// the KDC on port 88. See common/worker.js.
//
// So the four call paths that can reach a post-quantum `alg` — the ID Token,
// the signed UserInfo response, a client assertion and an OID4VCI proof — call
// this instead, and it hands the computation to the pool. **EVERY OTHER
// ALGORITHM IS UNCHANGED AND IS NOT DEFERRED**: an RS256 signature is
// microseconds, so sending it to a child process would cost an IPC round trip
// to save nothing. Those resolve with the value signJws() computed, which is
// what lets a caller be written one way and not two.
//
// `opts.session` is passed through as the routing hint — see worker_pool.js.
// It is a preference and never a correctness requirement, so a caller with no
// session to name simply omits it.
// ---------------------------------------------------------------------------
function signJwsAsync(payload, key, opts) {
  const options = opts || {};
  const algorithm = options.algorithm || 'RS256';
  log.debug('Entering signJwsAsync(). alg=' + algorithm);
  let spec;
  try {
    if (!key) {
      throw new Error('signJwsAsync: a signing key is required.');
    }
    spec = jwsSpec(algorithm);
  } catch (e) {
    log.debug('Leaving signJwsAsync(). Refused.');
    return Promise.reject(e);
  }
  if (spec.family !== 'pq') {
    // Not deferred, and the throw is turned into a rejection so that a caller
    // never has to know which algorithms go to the pool.
    try {
      const signed = signJws(payload, key, opts);
      log.debug('Leaving signJwsAsync(). ' + algorithm + ', in process.');
      return Promise.resolve(signed);
    } catch (e) {
      log.debug('Leaving signJwsAsync(). It threw.');
      return Promise.reject(e);
    }
  }
  const input = pqSigningInput(payload, algorithm, options);
  log.debug('Leaving signJwsAsync(). ' + algorithm + ', handed to the pool.');
  return pqJose.signAsync(algorithm, key, Buffer.from(input, 'ascii'),
                          { session: options.session })
    .then(function (signature) {
      return input + '.' + b64u(signature);
    });
}

// ---------------------------------------------------------------------------
// THE CLOCK ALLOWANCE THIS SERVICE APPLIES WHEN IT READS BACK A TOKEN IT
// SIGNED, AND THE DRIFT THAT MADE IT WORTH A FUNCTION.
//
// `oauth2.js` has said for a long time, in capitals, that EVERY `jwt.verify()`
// of one of our own tokens takes it — and then scoped the promise to "IN THIS
// FILE", which is the only part of it that was true. Outside that file four
// verifications of this service's own tokens omitted it entirely:
// `vc_issuer.js` twice and `vc_verifier.js` twice. Each was a second, stricter
// opinion about what "expired" means, reachable only through whichever endpoint
// had forgotten — and the symptom is a token that introspects active and is
// refused at a credential endpoint thirty seconds before it should be, which
// reads as a client bug from every side.
//
// It is read per call rather than captured, because it is runtime-settable from
// the console and a constant taken at require time would be the one value
// nothing could change.
// ---------------------------------------------------------------------------
function tokenClockSkew() {
  return config.value('oauth2.clockSkewS');
}

// ---------------------------------------------------------------------------
// VERIFY A JWS. `key` is whatever jsonwebtoken will verify with: this service's
// own certificate PEM, a client's registered public key, a shared secret.
//
// **THE CLOCK TOLERANCE IS APPLIED UNLESS A CALLER DELIBERATELY OPTS OUT**, and
// that default is the entire point of the function. A caller that wants the
// strict reading passes `clockTolerance: 0` and has said so out loud; a caller
// that says nothing gets the service's configured answer instead of an
// accidental second policy.
//
// It THROWS, exactly as `jwt.verify()` does, because every one of the twelve
// call sites already catches — several of them distinguishing
// `TokenExpiredError` from `JsonWebTokenError`, which is a distinction an
// answer-shaped return would have flattened.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// VERIFY A COMPACT JWS SOMEBODY ELSE SIGNED — the one implementation.
//
// This is for a JWS this service did NOT produce: a DPoP proof, an OID4VCI
// proof of possession, a Key Binding JWT, a client assertion, a request object.
// Its counterpart `verifyJws()` below is for the service's OWN tokens and does
// the claim checking (`exp`, `nbf`, `aud`, clock skew) that `jsonwebtoken`
// gives; this one checks a SIGNATURE and leaves the claims to the caller,
// because each of those five profiles checks different claims for different
// reasons and a shared "verify everything" would be right for none of them.
//
// THE CALLER NAMES THE ACCEPTABLE ALGORITHMS AND THE TOKEN DOES NOT — RFC 8725
// section 3.1. Reading `alg` out of the header and doing as it says is the
// algorithm-confusion defect, and it is the reason `algorithms` has no default
// here: a verifier that let the token choose would accept `none`, or an HS256
// signature made with the RSA public key everybody has.
//
// `key` may be a node KeyObject, a JWK, or a PEM. All three occur — a JWK from
// a proof's own header, a PEM from a registration, a KeyObject already parsed.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// SPLIT IN THREE, AND THE SPLIT IS WHAT LETS THE POST-QUANTUM BRANCH GO TO A
// CHILD PROCESS.
//
// Reading the token, choosing the algorithm and refusing an unacceptable one
// are the same in both directions; only the one line that actually checks the
// bytes differs, and for a composite ML-DSA verification that line took 17.8
// and 23.3 seconds on 2026-08-29 (see common/worker.js). So:
//
//   prepareVerification()  everything up to the check — and every refusal that
//                          is about the TOKEN rather than about the signature
//   verifyBytes()          the check itself, for everything but post-quantum
//   finishVerification()   the refusal for a signature that did not hold up,
//                          and the payload
//
// `verifyCompactJws()` below runs the three in a row exactly as it always did.
// `verifyCompactJwsAsync()` runs the same three with the post-quantum check
// handed to the pool. THE ORDER OF THE REFUSALS IS PART OF THE CONTRACT: a
// token whose `alg` is not in the caller's list is refused for that and never
// for its signature, whichever entry point was used.
// ---------------------------------------------------------------------------
function prepareVerification(token, key, options) {
  log.debug('Entering prepareVerification().');
  const parts = String(token || '').split('.');
  if (parts.length !== 3) {
    log.debug('Leaving prepareVerification(). Not three parts.');
    throw new Error('a compact JWS has three dot-separated parts; this has ' +
      parts.length + '.');
  }
  let header;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  } catch (e) {
    log.debug('Leaving prepareVerification(). The header is not JSON.');
    throw new Error('the JWS protected header is not readable base64url ' +
      'JSON: ' + e.message);
  }
  const allowed = options.algorithms;
  if (!Array.isArray(allowed) || !allowed.length) {
    log.debug('Leaving prepareVerification(). No algorithm list.');
    throw new Error('verifyCompactJws: the caller must name the acceptable ' +
      'algorithms. A verifier that takes them from the token is the ' +
      'algorithm-confusion defect (RFC 8725 section 3.1).');
  }
  if (allowed.indexOf(header.alg) === -1) {
    log.debug('Leaving prepareVerification(). Algorithm not accepted.');
    throw new Error('this JWS is signed with "' + header.alg + '" and only ' +
      allowed.join(', ') + ' ' + (allowed.length === 1 ? 'is' : 'are') +
      ' accepted here.');
  }
  const spec = jwsSpec(header.alg);
  const prepared = {
    header: header,
    spec: spec,
    payload: parts[1],
    signingInput: Buffer.from(parts[0] + '.' + parts[1], 'ascii'),
    signature: Buffer.from(parts[2], 'base64url')
  };
  if (spec.family === 'pq') {
    // `key` is the AKP `pub` value — bytes, or the base64url of them off a
    // JWK, which is what a verifier is handed in practice. Read HERE rather
    // than at the check, so that a key that cannot be read is refused in the
    // same place whichever entry point was used.
    prepared.pub = (key && key.pub) ? Buffer.from(key.pub, 'base64url')
      : (typeof key === 'string' ? Buffer.from(key, 'base64url')
                                 : Buffer.from(key));
  }
  log.debug('Leaving prepareVerification(). alg=' + header.alg);
  return prepared;
}

// Everything but post-quantum, which is every algorithm whose check is
// microseconds and belongs in the process that is holding the request open.
function verifyBytes(prepared, key) {
  log.debug('Entering verifyBytes(). alg=' + prepared.header.alg);
  const spec = prepared.spec;
  const signingInput = prepared.signingInput;
  const signature = prepared.signature;
  if (spec.family === 'hmac') {
    const expected = nodeCrypto.createHmac(spec.hash, key)
      .update(signingInput).digest();
    log.debug('Leaving verifyBytes(). HMAC.');
    return expected.length === signature.length &&
           nodeCrypto.timingSafeEqual(expected, signature);
  }
  // A raw ECDSA signature is a fixed length; a wrong one reaches OpenSSL as
  // a buffer it will refuse in a way that names nothing, so it is checked
  // here where the reason can be given.
  if (spec.sigBytes && spec.family === 'ec' &&
      signature.length !== spec.sigBytes) {
    log.debug('Leaving verifyBytes(). Wrong signature length.');
    throw new Error('an ' + prepared.header.alg + ' signature is ' +
      spec.sigBytes + ' bytes — the R||S concatenation of RFC 7518 section ' +
      '3.4 — and this one is ' + signature.length + '. A ~70-byte one is the ' +
      'DER SEQUENCE a general-purpose crypto API returns, sent without ' +
      'converting it.');
  }
  let publicKey;
  try {
    publicKey = (key && key.type === 'public') ? key
      : nodeCrypto.createPublicKey(
          (key && key.kty) ? { key: key, format: 'jwk' } : key);
  } catch (e) {
    log.debug('Leaving verifyBytes(). The key would not load.');
    throw new Error('the verification key could not be read: ' + e.message);
  }
  log.debug('Leaving verifyBytes(). ' + spec.family + '.');
  return nodeCrypto.verify(spec.hash, signingInput,
      nodeParamsFor(spec, publicKey), signature);
}

function finishVerification(prepared, ok) {
  log.debug('Entering finishVerification(). ok=' + ok);
  if (!ok) {
    log.debug('Leaving finishVerification(). It does not verify.');
    throw new Error('the ' + prepared.header.alg +
      ' signature does not verify.');
  }
  let claims;
  try {
    claims = JSON.parse(Buffer.from(prepared.payload, 'base64url')
      .toString('utf8'));
  } catch (e) {
    log.debug('Leaving finishVerification(). The payload is not JSON.');
    throw new Error('the JWS payload is not readable base64url JSON: ' +
      e.message);
  }
  log.debug('Leaving finishVerification(). ' + prepared.header.alg +
            ' verified.');
  return { header: prepared.header, claims: claims };
}

function verifyCompactJws(token, key, opts) {
  const options = opts || {};
  log.debug('Entering verifyCompactJws().');
  const prepared = prepareVerification(token, key, options);
  const ok = prepared.spec.family === 'pq'
    ? pqJose.verify(prepared.header.alg, prepared.pub, prepared.signingInput,
                    prepared.signature)
    : verifyBytes(prepared, key);
  const out = finishVerification(prepared, ok);
  log.debug('Leaving verifyCompactJws(). ' + prepared.header.alg +
            ' verified.');
  return out;
}

// The same verification with the post-quantum check handed to the pool. Every
// other algorithm resolves with what verifyCompactJws() computed, for the
// reason signJwsAsync() gives: an RS256 check is microseconds, and an IPC round
// trip to save that would be a cost with no saving.
function verifyCompactJwsAsync(token, key, opts) {
  const options = opts || {};
  log.debug('Entering verifyCompactJwsAsync().');
  let prepared;
  try {
    prepared = prepareVerification(token, key, options);
  } catch (e) {
    log.debug('Leaving verifyCompactJwsAsync(). Refused.');
    return Promise.reject(e);
  }
  if (prepared.spec.family !== 'pq') {
    try {
      const out = finishVerification(prepared, verifyBytes(prepared, key));
      log.debug('Leaving verifyCompactJwsAsync(). In process.');
      return Promise.resolve(out);
    } catch (e) {
      log.debug('Leaving verifyCompactJwsAsync(). It did not verify.');
      return Promise.reject(e);
    }
  }
  log.debug('Leaving verifyCompactJwsAsync(). Handed to the pool.');
  return pqJose.verifyAsync(prepared.header.alg, prepared.pub,
                            prepared.signingInput, prepared.signature,
                            { session: options.session })
    .then(function (ok) {
      return finishVerification(prepared, ok);
    });
}

// The claim checks `jsonwebtoken` performs, for the two algorithms it cannot
// verify. Written once, here, so that an EdDSA or ES256K token is held to
// exactly the same rules as an RS256 one — a token that skipped `exp` because
// of the curve it was signed on would be the worst kind of inconsistency.
function checkJwtClaims(claims, options) {
  log.debug('Entering checkJwtClaims().');
  const now = Math.floor(Date.now() / 1000);
  const skew = options.clockTolerance === undefined ? tokenClockSkew()
                                                    : options.clockTolerance;
  if (claims.exp !== undefined && now > Number(claims.exp) + skew) {
    const e = new Error('jwt expired');
    e.name = 'TokenExpiredError';
    e.expiredAt = new Date(Number(claims.exp) * 1000);
    log.debug('Leaving checkJwtClaims(). Expired.');
    throw e;
  }
  if (claims.nbf !== undefined && now + skew < Number(claims.nbf)) {
    const e = new Error('jwt not active');
    e.name = 'NotBeforeError';
    log.debug('Leaving checkJwtClaims(). Not yet valid.');
    throw e;
  }
  if (options.issuer !== undefined && claims.iss !== options.issuer) {
    log.debug('Leaving checkJwtClaims(). Wrong issuer.');
    throw new Error('jwt issuer invalid. expected: ' + options.issuer);
  }
  if (options.audience !== undefined) {
    // `aud` may be a string or an array, and the expectation may be either
    // too; a match on ANY member is a match, which is the rule RFC 7519
    // section 4.1.3 states and the one jsonwebtoken applies.
    const wanted = Array.isArray(options.audience) ? options.audience
                                                   : [options.audience];
    const held = Array.isArray(claims.aud) ? claims.aud
                                           : [claims.aud];
    const hit = wanted.some(function (one) { return held.indexOf(one) !== -1; });
    if (wanted.length && !hit) {
      log.debug('Leaving checkJwtClaims(). Wrong audience.');
      throw new Error('jwt audience invalid. expected: ' + wanted.join(' or '));
    }
  }
  log.debug('Leaving checkJwtClaims().');
  return claims;
}

function verifyJws(token, key, opts) {
  const options = opts || {};
  log.debug('Entering verifyJws().');
  // THE TWO ALGORITHMS `jsonwebtoken` CANNOT VERIFY GO THE OTHER WAY, and they
  // are held to the same claim rules — see checkJwtClaims(). This keeps ONE
  // entry point for "verify a JWS and check its claims": every caller in this
  // service gained EdDSA and ES256K the day this branch was added, without
  // any of them changing, which is the whole point of there being one.
  let peeked = null;
  try {
    peeked = JSON.parse(Buffer.from(String(token || '').split('.')[0],
      'base64url').toString('utf8'));
  } catch (e) {
    peeked = null;
  }
  if (peeked && JWS_ALGS[peeked.alg] && JWS_ALGS[peeked.alg].ownSigner) {
    const allowed = options.algorithms || [peeked.alg];
    const verified = verifyCompactJws(token, key, { algorithms: allowed });
    log.debug('Leaving verifyJws(). ' + peeked.alg + ' via the shared ' +
              'verifier.');
    return checkJwtClaims(verified.claims, options);
  }
  const verifyOptions = Object.assign({}, options);
  if (verifyOptions.algorithms === undefined) {
    // Naming the algorithms is not decoration: jsonwebtoken will otherwise
    // accept whatever the token's own header asks for, which is how `alg: none`
    // and an HS256 token verified against an RSA PUBLIC key — a value the
    // attacker also has — became the two best-known JWT vulnerabilities.
    verifyOptions.algorithms = ['RS256'];
  }
  if (verifyOptions.clockTolerance === undefined) {
    verifyOptions.clockTolerance = tokenClockSkew();
  }
  const claims = jwt.verify(token, key, verifyOptions);
  log.debug('Leaving verifyJws(). sub=' + (claims.sub || '(none)'));
  return claims;
}

// ---------------------------------------------------------------------------
// The same entry point, with a post-quantum signature checked in a child
// process. It is a SEPARATE FUNCTION rather than verifyJws() made async,
// because every one of that function's callers is synchronous and turning the
// return value of all of them into a promise would be a change to code that
// verifies RS256 in microseconds and has nothing to gain from it.
//
// The two share `checkJwtClaims()` and the peek that chooses between the
// library and the shared verifier, so an AKP assertion is held to exactly the
// same `exp`, `nbf`, `aud` and clock-skew rules as an RS256 one. A token that
// skipped a claim check because of the algorithm it was signed with would be
// the worst kind of inconsistency, and it is the reason this is a wrapper of
// the same three steps rather than a second reading of them.
// ---------------------------------------------------------------------------
function verifyJwsAsync(token, key, opts) {
  const options = opts || {};
  log.debug('Entering verifyJwsAsync().');
  let peeked = null;
  try {
    peeked = JSON.parse(Buffer.from(String(token || '').split('.')[0],
      'base64url').toString('utf8'));
  } catch (e) {
    peeked = null;
  }
  if (peeked && JWS_ALGS[peeked.alg] && JWS_ALGS[peeked.alg].family === 'pq') {
    const allowed = options.algorithms || [peeked.alg];
    log.debug('Leaving verifyJwsAsync(). Handed to the pool.');
    return verifyCompactJwsAsync(token, key,
        { algorithms: allowed, session: options.session })
      .then(function (verified) {
        return checkJwtClaims(verified.claims, options);
      });
  }
  // Everything else — including EdDSA and ES256K, which go through the shared
  // verifier but are microseconds — is what verifyJws() already does.
  try {
    const claims = verifyJws(token, key, opts);
    log.debug('Leaving verifyJwsAsync(). In process.');
    return Promise.resolve(claims);
  } catch (e) {
    log.debug('Leaving verifyJwsAsync(). It did not verify.');
    return Promise.reject(e);
  }
}

// ===========================================================================
// SECTION 4 — JWE (RFC 7516 compact serialization)
// ===========================================================================
//
// ---------------------------------------------------------------------------
// WRITTEN OUT BY HAND, AND THAT IS KEPT ON PURPOSE. `oid4vc/vc_issuer.js` made
// the argument where this code used to live and it still holds: OID4VCI
// section 10 is a Credential Issuer and a Wallet encrypting to each other, and
// having the steps visible — the content key, the wrap, the AAD, the tag — is
// what a mock is FOR. A call into a JOSE library would show a reader nothing.
//
// What was wrong was not the hand-rolling, it was that the encrypt half and the
// decrypt half sat two hundred lines apart in a protocol module with no shared
// notion of what an `enc` value means. They are together here, over one table,
// so a third algorithm is one row rather than two edits that have to agree.
//
// `common/vendored/jose_jwe.js` is the obvious alternative and is deliberately
// not used: its own header says it exists so that OID4VCI's two ends do not
// each implement the Concat KDF — and this service uses neither ECDH-ES nor the
// KDF, only RSA-OAEP-256 with AES-GCM, which is the part of JWE with no room
// for two readings to disagree. That file stays vendored for `key_material.js`
// and `x509.js`, which SPIFFE reaches through.
// ---------------------------------------------------------------------------

// The content encryption algorithms this service speaks, in both families RFC
// 7518 section 5 defines. `bits` is the AES key size; `cekBytes` is the size of
// the CONTENT ENCRYPTION KEY, which for the CBC-HMAC family is twice the AES
// key because the CEK carries a MAC key in front of it.
//
// The CBC-HMAC three are here because A128CBC-HS256 is what an OpenID Connect
// client gets by DEFAULT: register `userinfo_encrypted_response_alg` and say
// nothing about `enc` and section 2 of the registration spec has chosen
// A128CBC-HS256 for you. A service that spoke only AES-GCM would refuse the
// commonest encrypted response there is, and would look to the client like it
// had refused the request.
const JWE_ENCS = {
  A128GCM: { bits: 128, cipher: 'aes-128-gcm', cekBytes: 16, mode: 'gcm' },
  A192GCM: { bits: 192, cipher: 'aes-192-gcm', cekBytes: 24, mode: 'gcm' },
  A256GCM: { bits: 256, cipher: 'aes-256-gcm', cekBytes: 32, mode: 'gcm' },
  'A128CBC-HS256': { bits: 128, cipher: 'aes-128-cbc', cekBytes: 32,
                     mode: 'cbc-hmac', hash: 'sha256', halfBytes: 16 },
  'A192CBC-HS384': { bits: 192, cipher: 'aes-192-cbc', cekBytes: 48,
                     mode: 'cbc-hmac', hash: 'sha384', halfBytes: 24 },
  'A256CBC-HS512': { bits: 256, cipher: 'aes-256-cbc', cekBytes: 64,
                     mode: 'cbc-hmac', hash: 'sha512', halfBytes: 32 }
};

// The key management algorithms this service can ENCRYPT with. RSA-OAEP-256 is
// RSA-OAEP with SHA-256, which is what node calls RSA_PKCS1_OAEP_PADDING plus
// an explicit oaepHash — the default is SHA-1 and would interoperate with
// nothing that reads the `alg` header.
//
// RSA-OAEP (SHA-1) is offered beside it because it is what a recipient whose
// stack predates the -256 variant registers, and this is a service for testing
// other people's clients. ECDH-ES and its three key-wrapping variants are here
// because a recipient with an EC key has no RSA one to offer.
const JWE_ALG = 'RSA-OAEP-256';
const JWE_ALGS = ['RSA-OAEP-256', 'RSA-OAEP', 'ECDH-ES', 'ECDH-ES+A128KW',
                  'ECDH-ES+A192KW', 'ECDH-ES+A256KW'];
// The one this service can DECRYPT with, which is a shorter list on purpose:
// what it receives is encrypted to the RSA key it publishes, and it holds no EC
// private key to agree with.
const JWE_DECRYPT_ALGS = ['RSA-OAEP-256'];
const ECDH_KW_BYTES = { 'ECDH-ES+A128KW': 16, 'ECDH-ES+A192KW': 24,
                        'ECDH-ES+A256KW': 32 };
// JWK curve name -> the name node's OpenSSL knows it by.
const EC_CURVES = { 'P-256': 'prime256v1', 'P-384': 'secp384r1',
                    'P-521': 'secp521r1' };

function b64u(buf) {
  return Buffer.from(buf).toString('base64url');
}

// ---------------------------------------------------------------------------
// ENCRYPT TO A COMPACT JWE. `opts`:
//
//   jwk    the recipient's public key as a JWK, straight out of their metadata.
//   enc    one of JWE_ENCS. Required — there is no sensible default when the
//          recipient has told you what they can read.
//   typ    the protected header's `typ`, if the profile wants one.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE CONTENT ENCRYPTION HALF, FOR BOTH FAMILIES.
//
// AES-GCM is one primitive and node does the whole of it. AES-CBC-HMAC is the
// composite of RFC 7518 section 5.2 and has to be assembled: the CEK splits
// MAC-KEY FIRST then ENC-KEY, the MAC covers AAD || IV || CIPHERTEXT || AL
// where AL is the AAD length IN BITS as a 64-bit big-endian integer, and the
// tag is the FIRST HALF of the HMAC output. Each of those four is a place a
// wrong reading round-trips against itself perfectly and interoperates with
// nothing.
// ---------------------------------------------------------------------------
function cbcHmacKeys(spec, cek) {
  return { macKey: cek.subarray(0, spec.halfBytes),
           encKey: cek.subarray(spec.halfBytes) };
}

function cbcHmacTag(spec, cek, iv, aad, ciphertext) {
  const keys = cbcHmacKeys(spec, cek);
  const al = Buffer.alloc(8);
  al.writeBigUInt64BE(BigInt(aad.length * 8));
  return nodeCrypto.createHmac(spec.hash, keys.macKey)
    .update(Buffer.concat([aad, iv, ciphertext, al]))
    .digest().subarray(0, spec.halfBytes);
}

function sealContent(spec, cek, iv, aad, plaintext) {
  log.debug('Entering sealContent(). mode=' + spec.mode);
  if (spec.mode === 'cbc-hmac') {
    const keys = cbcHmacKeys(spec, cek);
    const cipher = nodeCrypto.createCipheriv(spec.cipher, keys.encKey, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    log.debug('Leaving sealContent(). CBC-HMAC.');
    return { ciphertext: ciphertext,
             tag: cbcHmacTag(spec, cek, iv, aad, ciphertext) };
  }
  const cipher = nodeCrypto.createCipheriv(spec.cipher, cek, iv);
  // The protected header is the additional authenticated data, per RFC 7516
  // section 5.1 step 14 — as its ASCII base64url text, not as the JSON. Getting
  // that wrong produces a tag the far end cannot verify and no other symptom.
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  log.debug('Leaving sealContent(). GCM.');
  return { ciphertext: ciphertext, tag: cipher.getAuthTag() };
}

function openContent(spec, cek, iv, aad, ciphertext, tag) {
  log.debug('Entering openContent(). mode=' + spec.mode);
  if (spec.mode === 'cbc-hmac') {
    const expected = cbcHmacTag(spec, cek, iv, aad, ciphertext);
    // timingSafeEqual throws on a length mismatch, so the length is checked
    // first — and a wrong length is a wrong tag either way.
    if (expected.length !== tag.length ||
        !nodeCrypto.timingSafeEqual(expected, tag)) {
      log.debug('Leaving openContent(). The tag did not verify.');
      throw new Error('the authentication tag does not verify');
    }
    const keys = cbcHmacKeys(spec, cek);
    const decipher = nodeCrypto.createDecipheriv(spec.cipher, keys.encKey, iv);
    const out = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    log.debug('Leaving openContent(). CBC-HMAC.');
    return out;
  }
  const decipher = nodeCrypto.createDecipheriv(spec.cipher, cek, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const out = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  log.debug('Leaving openContent(). GCM.');
  return out;
}

// ---------------------------------------------------------------------------
// THE KEY MANAGEMENT HALF. Returns the encrypted_key segment's bytes and, for
// the ECDH-ES variants, writes the ephemeral public key into the header — the
// recipient cannot agree the secret without it.
//
// The Concat KDF here REPEATS: NIST SP 800-56A produces 32 bytes per SHA-256
// round, and A192CBC-HS384 and A256CBC-HS512 need 48 and 64. A single round
// truncated to length would agree with a matching bug at the far end and with
// nothing else.
// ---------------------------------------------------------------------------
function concatKdf(z, keyBytes, algId) {
  log.debug('Entering concatKdf(). algId=' + algId);
  const u32 = function (n) {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n >>> 0);
    return b;
  };
  const alg = Buffer.from(algId, 'utf8');
  const otherInfo = Buffer.concat([u32(alg.length), alg, u32(0), u32(0),
                                   u32(keyBytes * 8)]);
  const rounds = Math.ceil(keyBytes / 32);
  const blocks = [];
  for (let i = 1; i <= rounds; i++) {
    blocks.push(nodeCrypto.createHash('sha256')
      .update(Buffer.concat([u32(i), z, otherInfo])).digest());
  }
  log.debug('Leaving concatKdf(). ' + rounds + ' round(s).');
  return Buffer.concat(blocks).subarray(0, keyBytes);
}

const AES_KW_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');

function aesKeyWrap(kek, plaintextKey) {
  log.debug('Entering aesKeyWrap().');
  const cipher = nodeCrypto.createCipheriv('id-aes' + (kek.length * 8) +
      '-wrap', kek, AES_KW_IV);
  const out = Buffer.concat([cipher.update(plaintextKey), cipher.final()]);
  log.debug('Leaving aesKeyWrap().');
  return out;
}

function wrapCek(alg, recipientJwk, cek, header) {
  log.debug('Entering wrapCek(). alg=' + alg);
  if (JWE_ALGS.indexOf(alg) === -1) {
    log.debug('Leaving wrapCek(). Unknown alg.');
    throw new Error('encryptJweCompact: unsupported alg "' + alg +
      '"; this service encrypts with ' + JWE_ALGS.join(', ') + '.');
  }
  const publicKey = nodeCrypto.createPublicKey({ key: recipientJwk, format: 'jwk' });

  if (alg === 'RSA-OAEP' || alg === 'RSA-OAEP-256') {
    const wrapped = nodeCrypto.publicEncrypt({
      key: publicKey,
      padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: alg === 'RSA-OAEP' ? 'sha1' : 'sha256'
    }, cek);
    log.debug('Leaving wrapCek(). RSA.');
    return { cek: cek, encryptedKey: wrapped };
  }

  // ECDH-ES, direct or with AES key wrapping.
  const curve = EC_CURVES[recipientJwk.crv];
  if (!curve) {
    log.debug('Leaving wrapCek(). Unknown curve.');
    throw new Error('encryptJweCompact: the recipient key names curve "' +
      recipientJwk.crv + '", and this service agrees over ' +
      Object.keys(EC_CURVES).join(', ') + '.');
  }
  const ephemeral = nodeCrypto.generateKeyPairSync('ec', { namedCurve: curve });
  const z = nodeCrypto.diffieHellman({ privateKey: ephemeral.privateKey,
                                       publicKey: publicKey });
  const epk = ephemeral.publicKey.export({ format: 'jwk' });
  header.epk = { kty: epk.kty, crv: epk.crv, x: epk.x, y: epk.y };
  if (alg === 'ECDH-ES') {
    // Direct agreement: the derived key IS the CEK and encrypted_key is empty.
    // The AlgorithmID is the content encryption `enc`, and the key data length
    // is the WHOLE CEK — both halves, for a CBC-HMAC enc.
    log.debug('Leaving wrapCek(). ECDH-ES direct.');
    return { cek: concatKdf(z, cek.length, header.enc),
             encryptedKey: Buffer.alloc(0) };
  }
  const kek = concatKdf(z, ECDH_KW_BYTES[alg], alg);
  log.debug('Leaving wrapCek(). ' + alg + '.');
  return { cek: cek, encryptedKey: aesKeyWrap(kek, cek) };
}

function encryptJweCompact(plaintext, opts) {
  const options = opts || {};
  log.debug('Entering encryptJweCompact(). alg=' + (options.alg || JWE_ALG) +
            ', enc=' + options.enc);
  const spec = JWE_ENCS[options.enc];
  if (!spec) {
    log.debug('Leaving encryptJweCompact(). Unknown enc.');
    throw new Error('encryptJweCompact: unsupported enc "' + options.enc +
                    '"; this service encrypts with ' +
                    Object.keys(JWE_ENCS).join(', ') + '.');
  }
  const alg = options.alg || JWE_ALG;
  const random = nodeCrypto.randomBytes(spec.cekBytes);
  // Sixteen octets — one AES block — for CBC, twelve for GCM. A CBC-HMAC JWE
  // carrying a 12-byte IV is refused by every other implementation.
  const iv = nodeCrypto.randomBytes(spec.mode === 'cbc-hmac' ? 16 : 12);
  const header = { alg: alg, enc: options.enc, typ: options.typ || 'JWT' };
  if (options.cty) {
    header.cty = options.cty;
  }
  if (options.jwk && options.jwk.kid) {
    header.kid = options.jwk.kid;
  }
  // wrapCek() may WRITE to the header (the ECDH-ES variants add `epk`), so the
  // header is serialised after it and not before — the AAD has to be the bytes
  // that actually go out, and an epk added after the AAD was taken would make
  // every tag fail at the far end.
  const wrapped = wrapCek(alg, options.jwk, random, header);
  const headerB64 = b64u(Buffer.from(JSON.stringify(header), 'utf8'));

  const sealed = sealContent(spec, wrapped.cek, iv,
      Buffer.from(headerB64, 'ascii'), Buffer.from(plaintext, 'utf8'));

  const compact = [headerB64, b64u(wrapped.encryptedKey), b64u(iv),
                   b64u(sealed.ciphertext), b64u(sealed.tag)].join('.');
  log.debug('Leaving encryptJweCompact(). ' + compact.length + ' characters.');
  return compact;
}

// ---------------------------------------------------------------------------
// DECRYPT A COMPACT JWE. `opts`:
//
//   privateKey    a node KeyObject.
//   allowedEnc    the `enc` values this endpoint accepts. Required.
//   expectedKid   when set, the header's kid must equal it. Checking it is
//                 what makes key rotation DETECTABLE: this service regenerates
//                 its keys on every start, so a wallet holding a stale one is
//                 told exactly that instead of getting an opaque decryption
//                 failure it will blame on its own code.
//
// It THROWS with a sentence a caller can hand to a client, because every
// failure here is the far end's document being wrong and the OID4VCI error
// responses quote the message directly.
// ---------------------------------------------------------------------------
function decryptJweCompact(compact, opts) {
  const options = opts || {};
  log.debug('Entering decryptJweCompact().');
  const parts = String(compact || '').trim().split('.');
  if (parts.length !== 5) {
    log.debug('Leaving decryptJweCompact(). Not five parts.');
    throw new Error('an encrypted request must be a JWE in compact serialization ' +
      '(five dot-separated parts); this has ' + parts.length + '.');
  }
  let header;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  } catch (e) {
    log.debug('Leaving decryptJweCompact(). The header is not JSON.');
    throw new Error('the JWE protected header is not valid base64url JSON: ' + e.message);
  }
  if (JWE_DECRYPT_ALGS.indexOf(header.alg) === -1) {
    // Shorter than the list this service ENCRYPTS with, and deliberately so:
    // what arrives here is encrypted to the RSA key this service publishes, and
    // there is no EC private key here to agree an ECDH-ES secret with.
    log.debug('Leaving decryptJweCompact(). Wrong alg.');
    throw new Error('this service decrypts with alg ' + JWE_DECRYPT_ALGS.join(' or ') +
      '; the request used "' + header.alg + '".');
  }
  const allowed = options.allowedEnc || Object.keys(JWE_ENCS);
  if (allowed.indexOf(header.enc) === -1) {
    log.debug('Leaving decryptJweCompact(). Unsupported enc.');
    throw new Error('this service supports enc ' + allowed.join(' or ') +
      '; the request used "' + header.enc + '".');
  }
  if (header.zip) {
    // Refused rather than ignored: a compressed payload that is silently read
    // as though it were not compressed is a parse error three frames away.
    log.debug('Leaving decryptJweCompact(). Compressed.');
    throw new Error('this service advertises no zip_values_supported, so a compressed ' +
      'request cannot be read.');
  }
  if (options.expectedKid && header.kid !== options.expectedKid) {
    log.debug('Leaving decryptJweCompact(). Wrong kid.');
    throw new Error('the JWE kid "' + (header.kid || '(absent)') + '" is not this service\'s ' +
      'current encryption key "' + options.expectedKid + '". Re-read the metadata: this key ' +
      'is regenerated when the service restarts.');
  }

  let cek;
  try {
    cek = nodeCrypto.privateDecrypt({
      key: options.privateKey,
      padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    }, Buffer.from(parts[1], 'base64url'));
  } catch (e) {
    log.debug('Leaving decryptJweCompact(). The key would not unwrap.');
    throw new Error('the content encryption key could not be unwrapped with this service\'s ' +
      'private key: ' + e.message);
  }
  const spec = JWE_ENCS[header.enc];
  if (cek.length !== spec.cekBytes) {
    // The wrong-key case, and it is checked rather than left to the cipher for
    // the reason the XML decryption above checks the same thing: an unwrap that
    // succeeds with the wrong length is a wrong key, and saying so beats a
    // cipher error about a buffer size. Note a CBC-HMAC CEK is TWICE the AES
    // key size, which is why this reads cekBytes and not bits/8.
    log.debug('Leaving decryptJweCompact(). The key is the wrong size.');
    throw new Error('the unwrapped content encryption key is ' + cek.length + ' bytes; ' +
      header.enc + ' needs ' + spec.cekBytes + '.');
  }

  let plaintext;
  try {
    plaintext = openContent(spec, cek, Buffer.from(parts[2], 'base64url'),
      Buffer.from(parts[0], 'ascii'), Buffer.from(parts[3], 'base64url'),
      Buffer.from(parts[4], 'base64url')).toString('utf8');
  } catch (e) {
    // An authentication tag failure lands here, and it is the interesting case:
    // the ciphertext or the header was altered in flight.
    log.debug('Leaving decryptJweCompact(). The tag did not verify.');
    throw new Error('the ciphertext did not decrypt or its authentication tag did not ' +
      'verify: ' + e.message);
  }
  log.debug('Leaving decryptJweCompact(). ' + plaintext.length + ' characters.');
  return { header: header, plaintext: plaintext };
}

// ===========================================================================
// SECTION 5 — KEYS, CERTIFICATES, THUMBPRINTS
// ===========================================================================

// ---------------------------------------------------------------------------
// AN RSA KEY AND A SELF-SIGNED CERTIFICATE OVER IT.
//
// Two copies of this existed — `helpers.makeStsKeys()` for the signing key and
// `tls/tls_server.js`'s `makeServerCertificate()` for the listeners' — and they
// were not gratuitous copies: one is a signing certificate with no extensions
// at all and the other is a TLS server certificate that lives or dies by its
// subjectAltName. What they shared was the whole RSA keygen-and-self-sign
// skeleton, which is the part worth having once.
//
// So the differences are PARAMETERS and the skeleton is here. `extensions` is
// passed through to forge untouched rather than being modelled, because the
// two callers want disjoint sets and a third will want a third — modelling it
// would be inventing a certificate profile language for two users.
//
// A THIRD generator is deliberately NOT folded in: `spiffe/spiffe_ca.js` issues
// through `common/vendored/x509.js` because **node-forge cannot sign with an EC
// key at all** and SPIFFE issues P-256. That is a capability gap, not a
// duplication, and `common/vendored/CLAUDE.md` records it.
// ---------------------------------------------------------------------------
function selfSignedRsaCertificate(opts) {
  const options = opts || {};
  log.debug('Entering selfSignedRsaCertificate(). cn=' + (options.commonName || '(none)'));
  const pair = forge.pki.rsa.generateKeyPair({ bits: options.bits || 2048, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = pair.publicKey;
  // The serial is the caller's because it is how a person tells two of this
  // service's certificates apart in a packet capture, and they are otherwise
  // identical self-signed RSA certificates minted seconds apart.
  cert.serialNumber = options.serialNumber || '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(
    cert.validity.notBefore.getFullYear() + (options.years || 5));
  const attrs = [{ name: 'commonName', value: options.commonName || 'mock-sts' }];
  if (options.organizationName) {
    attrs.push({ name: 'organizationName', value: options.organizationName });
  }
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  if (options.extensions && options.extensions.length) {
    cert.setExtensions(options.extensions);
  }
  cert.sign(pair.privateKey, forge.md.sha256.create());
  const certPem = forge.pki.certificateToPem(cert);
  log.debug('Leaving selfSignedRsaCertificate().');
  return {
    privateKeyPem: forge.pki.privateKeyToPem(pair.privateKey),
    publicKeyPem: forge.pki.publicKeyToPem(pair.publicKey),
    certPem: certPem,
    certB64: stripPem(certPem),
    // The validity window, because a caller that PUBLISHES a certificate has to
    // be able to say when it stops working — `GET /tls` prints `notAfter` so
    // somebody who put this in a truststore knows how long it is good for.
    // Returned rather than re-parsed out of the PEM by the caller, which would
    // be a second reading of a value this function just decided.
    notBefore: cert.validity.notBefore,
    notAfter: cert.validity.notAfter
  };
}

// ---------------------------------------------------------------------------
// AN ML-DSA KEY AND A SELF-SIGNED CERTIFICATE OVER IT (FIPS 204, RFC 9881).
//
// WHY THIS IS WRITTEN OUT HERE AND NOT VENDORED FROM THE DEBUGGER, which is
// the same argument pq_jose.js makes at length and which applies with more
// force to a certificate: this service exists to be the FAR END of the
// debugger's own PKI code. The debugger builds a post-quantum certificate with
// pkijs and signs it with @noble/post-quantum; if this service did the same,
// the two would share one reading of RFC 9881 — of where the OID goes, of
// whether the AlgorithmIdentifier carries a NULL, of what the BIT STRING holds
// — agree with each other perfectly, and interoperate with nothing.
//
// So the two halves here are deliberately the ones the debugger does NOT use:
//
//   * the KEY and the SIGNATURE come from node's OpenSSL 3.5, which has
//     ML-DSA natively. `crypto.generateKeyPairSync('ml-dsa-65')` and
//     `crypto.sign(null, tbs, key)` are C code from a different project.
//   * the ENCODING is written below against RFC 9881 section 3 and RFC 5280
//     section 4.1, with asn1js as the DER writer.
//
// The result is that a debugger which verifies this certificate has verified
// something OpenSSL produced, and a debugger whose certificate this service
// accepts has been read by OpenSSL. That is the only kind of check that means
// anything here.
//
// NODE-FORGE CANNOT DO ANY OF THIS. It has no ML-DSA, cannot parse a
// certificate whose signature algorithm it does not know, and cannot sign with
// a key it cannot represent — which is the same capability gap
// `spiffe/spiffe_ca.js` records for EC keys, one algorithm generation later.
// ---------------------------------------------------------------------------
const ML_DSA_OIDS = {
  'ml-dsa-44': '2.16.840.1.101.3.4.3.17',
  'ml-dsa-65': '2.16.840.1.101.3.4.3.18',
  'ml-dsa-87': '2.16.840.1.101.3.4.3.19'
};

function mlDsaOid(algorithm) {
  log.debug('Entering mlDsaOid(). algorithm=' + algorithm);
  const oid = ML_DSA_OIDS[String(algorithm || '').toLowerCase()];
  if (!oid) {
    log.debug('Leaving mlDsaOid(). Unknown.');
    throw new Error('Not an ML-DSA parameter set this service knows: ' +
                    algorithm + '. RFC 9881 defines ML-DSA-44, -65 and -87.');
  }
  log.debug('Leaving mlDsaOid().');
  return oid;
}

// The three DN attribute OIDs this builder writes, and the string type each
// one takes. `C` MUST be a PrintableString and everything else here is a
// UTF8String: a country encoded as UTF8String parses perfectly and is refused
// by several validators, which reads as a signature problem.
const DN_TYPES = {
  commonName: { oid: '2.5.4.3', printable: false },
  organizationName: { oid: '2.5.4.10', printable: false },
  countryName: { oid: '2.5.4.6', printable: true }
};

function selfSignedMlDsaCertificate(opts) {
  const options = opts || {};
  const algorithm = String(options.algorithm || 'ml-dsa-65').toLowerCase();
  log.debug('Entering selfSignedMlDsaCertificate(). algorithm=' + algorithm +
            ' cn=' + (options.commonName || '(none)'));
  const oid = mlDsaOid(algorithm);
  const pair = nodeCrypto.generateKeyPairSync(algorithm);
  const spkiDer = pair.publicKey.export({ type: 'spki', format: 'der' });

  function bufferOf(bytes) {
    const view = Uint8Array.from(bytes);
    return view.buffer.slice(view.byteOffset, view.byteOffset +
        view.byteLength);
  }

  function algorithmIdentifier() {
    // PARAMETERS ABSENT — RFC 9881 section 3 says MUST, and an explicit NULL
    // here (which is what an RSA identifier carries, so it is what a copied
    // line produces) makes a certificate OpenSSL refuses to load at all.
    return new asn1js.Sequence({
      value: [new asn1js.ObjectIdentifier({ value: oid })]
    });
  }

  function name(attributes) {
    // An RDNSequence — a SEQUENCE OF one-element SETs — and not one SET
    // holding every attribute. The second is a multi-valued RDN, which is a
    // DIFFERENT NAME: it parses, it prints with + between the attributes, and
    // nothing chains to it.
    return new asn1js.Sequence({
      value: attributes.map(function (attribute) {
        const type = DN_TYPES[attribute.name];
        const value = type.printable
          ? new asn1js.PrintableString({ value: attribute.value })
          : new asn1js.Utf8String({ value: attribute.value });
        return new asn1js.Set({
          value: [new asn1js.Sequence({
            value: [new asn1js.ObjectIdentifier({ value: type.oid }), value]
          })]
        });
      })
    });
  }

  function utcTime(date) {
    return new asn1js.UTCTime({ valueDate: date });
  }

  function extension(extnOid, critical, valueAsn1) {
    const der = new Uint8Array(valueAsn1.toBER(false));
    const value = [new asn1js.ObjectIdentifier({ value: extnOid })];
    if (critical) value.push(new asn1js.Boolean({ value: true }));
    value.push(new asn1js.OctetString({ valueHex: bufferOf(der) }));
    return new asn1js.Sequence({ value: value });
  }

  const attributes = [
    { name: 'commonName', value: options.commonName || 'mock-sts' }
  ];
  if (options.organizationName) {
    attributes.push({ name: 'organizationName',
                     value: options.organizationName });
  }
  const subject = name(attributes);
  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime());
  notAfter.setFullYear(notBefore.getFullYear() + (options.years || 2));

  // subjectAltName: dNSName is [2] and iPAddress is [7], both IMPLICIT and
  // both primitive. The CN is ignored by every current client, so these are
  // not decoration — they are the only place the names are.
  const generalNames = [];
  (options.dnsNames || []).forEach(function (dns) {
    generalNames.push(new asn1js.Primitive({
      idBlock: { tagClass: 3, tagNumber: 2 },
      valueHex: bufferOf(Buffer.from(String(dns), 'utf8'))
    }));
  });
  (options.ipAddresses || []).forEach(function (address) {
    const octets = String(address).split('.').map(function (part) {
      return parseInt(part, 10) & 0xff;
    });
    if (octets.length !== 4) return;
    generalNames.push(new asn1js.Primitive({
      idBlock: { tagClass: 3, tagNumber: 7 },
      valueHex: bufferOf(octets)
    }));
  });

  const extensions = [
    extension('2.5.29.19', true, new asn1js.Sequence({ value: [] })),
    // digitalSignature only: an ML-DSA key cannot encipher anything, so
    // keyEncipherment — which the RSA certificate beside this one sets — would
    // be a lie about the algorithm. RFC 9881 section 4 says the same.
    extension('2.5.29.15', true, new asn1js.BitString({
      valueHex: bufferOf([0x80]), unusedBits: 7 })),
    extension('2.5.29.37', false, new asn1js.Sequence({
      value: [new asn1js.ObjectIdentifier({ value: '1.3.6.1.5.5.7.3.1' })] }))
  ];
  if (generalNames.length) {
    extensions.push(extension('2.5.29.17', false,
        new asn1js.Sequence({ value: generalNames })));
  }

  const serialHex = String(options.serialNumber || '04');
  const serialBytes = Buffer.from(serialHex.length % 2
    ? '0' + serialHex : serialHex, 'hex');

  const tbs = new asn1js.Sequence({
    value: [
      // [0] EXPLICIT version, v3 (2). A v1 certificate cannot carry
      // extensions at all, and a subjectAltName in one is ignored in silence.
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [new asn1js.Integer({ value: 2 })]
      }),
      new asn1js.Integer({ valueHex: bufferOf(serialBytes) }),
      algorithmIdentifier(),
      subject,
      new asn1js.Sequence({ value: [utcTime(notBefore), utcTime(notAfter)] }),
      subject,
      // The SubjectPublicKeyInfo is OpenSSL's own export, parsed in as the DER
      // it already is rather than rebuilt — the one field where a second
      // encoding of the same key would be a second chance to be wrong.
      asn1js.fromBER(bufferOf(spkiDer)).result,
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 3 },
        value: [new asn1js.Sequence({ value: extensions })]
      })
    ]
  });

  const tbsDer = Buffer.from(tbs.toBER(false));
  // `null` as the algorithm is how node asks for the key's own built-in
  // hashing, which is what ML-DSA does: FIPS 204 takes the message, not a
  // digest of it.
  const signature = nodeCrypto.sign(null, tbsDer, pair.privateKey);

  const certificate = new asn1js.Sequence({
    value: [
      tbs,
      algorithmIdentifier(),
      new asn1js.BitString({ valueHex: bufferOf(signature) })
    ]
  });
  const certDer = Buffer.from(certificate.toBER(false));
  const certPem = '-----BEGIN CERTIFICATE-----\n' +
      (certDer.toString('base64').match(/.{1,64}/g) || []).join('\n') +
      '\n-----END CERTIFICATE-----\n';
  // Read back through OpenSSL before it leaves this function. A certificate
  // this service cannot itself load is one the listener would fail to start
  // with, at a point where the error names the socket rather than the encoder.
  new nodeCrypto.X509Certificate(certDer);
  log.debug('Leaving selfSignedMlDsaCertificate(). ' + certDer.length +
            ' bytes.');
  return {
    algorithm: algorithm,
    privateKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }),
    certPem: certPem,
    certB64: stripPem(certPem),
    notBefore: notBefore,
    notAfter: notAfter
  };
}

// PEM armour off, whitespace out. What goes inside a <ds:X509Certificate>, and
// what a DER digest is taken over.
function stripPem(pem) {
  return String(pem || '').replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}

// ---------------------------------------------------------------------------
// RFC 7638 JWK THUMBPRINT.
//
// THERE WERE THREE OF THESE, which is one more than the audit that started this
// work had found: `oauth-oidc/dpop.js` (hand-built canonical JSON, full member
// table), `spiffe/spiffe_ca.js` (JSON.stringify over an object literal whose
// keys happen to be in lexicographic order) and `oid4vc/vc_issuer.js` (the same
// trick, RSA only, inline in a key-generation IIFE).
//
// All three were correct. That is precisely the problem: RFC 7638 is a
// specification whose whole purpose is that two implementations agree, and the
// two that relied on JSON.stringify agreed only because somebody typed the
// members in the right order — a member added out of order later would produce
// a different thumbprint for the same key, and nothing would fail until a
// client's DPoP-bound token stopped matching its own proof.
//
// **ONLY THE LISTED MEMBERS ARE HASHED**, which is the part people get wrong: a
// key carrying `kid`, `alg`, `use` or Web Crypto's `key_ops`/`ext` must hash to
// the same value as the same key without them, because the wallet sends its key
// in every proof header and a stray member would silently break the binding.
// ---------------------------------------------------------------------------
const THUMBPRINT_MEMBERS = {
  EC: ['crv', 'kty', 'x', 'y'],
  RSA: ['e', 'kty', 'n'],
  OKP: ['crv', 'kty', 'x'],
  oct: ['k', 'kty']
};

// The canonical JSON RFC 7638 hashes: the required members, lexicographically
// ordered, no whitespace. Built by hand rather than with JSON.stringify over an
// object, so the order is a property of this list and not of how somebody
// happened to type an object literal.
function canonicalJwk(jwk) {
  log.debug('Entering canonicalJwk().');
  if (!jwk || !jwk.kty) {
    throw new Error('a JWK Thumbprint needs a key with a kty.');
  }
  const members = THUMBPRINT_MEMBERS[jwk.kty];
  if (!members) {
    throw new Error('no RFC 7638 member list for kty ' + jwk.kty + '.');
  }
  const missing = members.filter(function (m) {
    return jwk[m] === undefined || jwk[m] === null || jwk[m] === '';
  });
  if (missing.length) {
    throw new Error('this ' + jwk.kty + ' key is missing ' + missing.join(', ') + '.');
  }
  log.debug('Leaving canonicalJwk().');
  return '{' + members.map(function (m) {
    return JSON.stringify(m) + ':' + JSON.stringify(jwk[m]);
  }).join(',') + '}';
}

// The thumbprint itself. `opts.truncate` shortens it for the two callers that
// use one as a `kid` rather than as a binding — a kid only has to be unique
// within a JWKS, and a shorter one is readable in a log. DPoP's `jkt` must
// never be truncated: it is compared byte for byte against a value the client
// computed, so it takes the default.
function jwkThumbprint(jwk, opts) {
  const options = opts || {};
  const digest = nodeCrypto.createHash('sha256')
    .update(canonicalJwk(jwk), 'utf8').digest('base64url');
  return options.truncate ? digest.slice(0, options.truncate) : digest;
}

// ---------------------------------------------------------------------------
// A CERTIFICATE'S SHA-256 THUMBPRINT, over the DER, in whichever spelling the
// specification that asked for it uses.
//
// There were three of these too, and unlike the JWK thumbprints they are NOT
// interchangeable — which is why this takes a format rather than picking one:
//
//   base64url   RFC 8705 `x5t#S256`, the mTLS certificate binding. Compared
//               byte for byte against a client's confirmation claim.
//   hex         SPIRE's `local authority id`, truncated to 16.
//   colon-hex   what `openssl x509 -fingerprint -sha256` prints, which is what
//               a person is holding when they compare one by eye.
//
// Three formats of one digest was never the duplication. Three functions each
// computing that digest was.
// ---------------------------------------------------------------------------
function certificateThumbprint(certificate, opts) {
  const options = opts || {};
  let der;
  if (Buffer.isBuffer(certificate)) {
    der = certificate;
  } else if (certificate && certificate.raw) {
    // A node `X509Certificate`, which is what a TLS socket hands over.
    der = certificate.raw;
  } else {
    der = Buffer.from(stripPem(certificate), 'base64');
  }
  const format = options.format || 'base64url';
  let out;
  if (format === 'hex') {
    out = nodeCrypto.createHash('sha256').update(der).digest('hex');
  } else if (format === 'colon-hex') {
    const hex = nodeCrypto.createHash('sha256').update(der).digest('hex').toUpperCase();
    out = (hex.match(/.{2}/g) || []).join(':');
  } else {
    out = nodeCrypto.createHash('sha256').update(der).digest('base64url');
  }
  return options.truncate ? out.slice(0, options.truncate) : out;
}

// ---------------------------------------------------------------------------
// COMPARE TWO SECRETS WITHOUT LEAKING THEIR LENGTH OR THEIR PREFIX.
//
// `crypto.timingSafeEqual()` THROWS when the two buffers differ in length,
// which is the trap both previous copies had to work around and one of them
// worked around by testing the length first — so the length is compared in
// variable time before the contents are compared in constant time. That is the
// correct shape and it is worth saying why it is not a hole: the length of a
// client secret is not the secret, and there is no constant-time comparison of
// two strings of different lengths to be had.
// ---------------------------------------------------------------------------
function constantTimeEquals(a, b) {
  const left = Buffer.from(String(a == null ? '' : a), 'utf8');
  const right = Buffer.from(String(b == null ? '' : b), 'utf8');
  if (left.length !== right.length) {
    return false;
  }
  return nodeCrypto.timingSafeEqual(left, right);
}

module.exports = {
  // --- XML digital signature ---
  PLACEMENT: PLACEMENT,
  signXml: signXml,
  verifyXmlSignature: verifyXmlSignature,
  signQueryString: signQueryString,
  idOf: idOf,
  // --- XML encryption ---
  encryptElement: encryptElement,
  encryptAssertion: encryptAssertion,
  decryptElement: decryptElement,
  BLOCK_CIPHERS: BLOCK_CIPHERS,
  KEY_TRANSPORTS: KEY_TRANSPORTS,
  cipherByUri: cipherByUri,
  transportByUri: transportByUri,
  // --- JWS / JWT ---
  signJws: signJws,
  verifyJws: verifyJws,
  // The three that hand a post-quantum computation to the worker pool and
  // resolve with exactly what their synchronous namesakes return. See
  // signJwsAsync() for which callers use them and why the others do not.
  signJwsAsync: signJwsAsync,
  verifyJwsAsync: verifyJwsAsync,
  verifyCompactJwsAsync: verifyCompactJwsAsync,
  tokenClockSkew: tokenClockSkew,
  // --- JWE ---
  // The one JWS algorithm table and the operations built on it.
  b64u: b64u,
  JWS_ALGS: JWS_ALGS,
  JWS_SIGNING_ALGS: JWS_SIGNING_ALGS,
  JWS_ASYMMETRIC_ALGS: JWS_ASYMMETRIC_ALGS,
  jwsSpec: jwsSpec,
  protectedHeaderFor: protectedHeaderFor,
  verifyCompactJws: verifyCompactJws,
  checkJwtClaims: checkJwtClaims,
  JWE_ALG: JWE_ALG,
  JWE_ALGS: JWE_ALGS,
  JWE_DECRYPT_ALGS: JWE_DECRYPT_ALGS,
  JWE_ENCS: JWE_ENCS,
  encryptJweCompact: encryptJweCompact,
  decryptJweCompact: decryptJweCompact,
  // --- keys, certificates, thumbprints ---
  selfSignedRsaCertificate: selfSignedRsaCertificate,
  selfSignedMlDsaCertificate: selfSignedMlDsaCertificate,
  ML_DSA_OIDS: ML_DSA_OIDS,
  stripPem: stripPem,
  canonicalJwk: canonicalJwk,
  jwkThumbprint: jwkThumbprint,
  certificateThumbprint: certificateThumbprint,
  constantTimeEquals: constantTimeEquals,
  // --- the algorithm URIs, so that there is one spelling of each in the
  //     process. Taken from the vendored module rather than re-declared.
  DS_NS: xmldsig.DS_NS,
  XENC_NS: xmldsig.XENC_NS,
  XENC11_NS: xmldsig.XENC11_NS,
  C14N_EXCLUSIVE: xmldsig.C14N_EXCLUSIVE,
  TRANSFORM_ENVELOPED: xmldsig.TRANSFORM_ENVELOPED,
  SIG_RSA_SHA256: xmldsig.SIG_ALG_RSA_SHA256,
  DIGEST_SHA256: xmldsig.XENC_NS + 'sha256',
  // The vendored engine itself, for the two pages that expose a general XML
  // signature tool and need its algorithm tables. Everything else here should
  // use the six functions above.
  xmldsig: xmldsig
};
