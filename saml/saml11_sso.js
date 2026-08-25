'use strict';
//
// File: saml11_sso.js
//
// ===========================================================================
// SAML 1.1 — the two browser profiles, and the SAML responder behind one of them.
//
// **THIS FILE FINISHES A REVERSAL `saml2_sso.js` STARTED ON THE SAME DAY.** That
// module's header says it reverses a documented non-goal: "there is no SAML 2.0
// Web SSO profile" was asserted in eight places and every one of them had to be
// qualified. This one is not a reversal of anything — nothing ever claimed there
// was no SAML 1.1 browser profile, because until 2026-08-24 there was no browser
// SAML at all and the 2.0 sentence covered the ground. What it does mean is that
// **`saml11.js` is no longer a module only WS-Federation calls**, and the two
// places that said so (`../ws-federation/wsfed.js`'s header, and this
// directory's `CLAUDE.md`) now have a second caller to name.
//
//   GET|POST /saml11/sso[/{rp}]        the INTER-SITE TRANSFER SERVICE. This is
//                                      SAML 1.1's name for what 2.0 calls the
//                                      Single Sign-On service, and the
//                                      difference is not only vocabulary — see
//                                      decision 1.
//   POST     /saml11/responder[/{rp}]  the SAML RESPONDER, over the SOAP binding
//                                      (saml-bindings-1.1 section 3.1). It
//                                      answers a <samlp:Request> carrying an
//                                      AssertionArtifact, an
//                                      AssertionIDReference, an AttributeQuery
//                                      or an AuthenticationQuery.
//   GET      /saml11/metadata[/{rp}]   the SIGNED identity provider metadata,
//                                      per relying party. SAML 1.1 has no
//                                      metadata specification of its own; see
//                                      decision 5.
//   GET      /saml11/autopost.js       the one script the Browser/POST profile
//                                      runs. The SIXTH scripted page in this
//                                      service, and the argument is made again
//                                      below rather than by analogy.
//   GET|POST /saml11/rp                a mock RELYING PARTY. NON-SPEC, the
//                                      default assertion consumer, and where a
//                                      response can be verified check by check
//                                      without standing up a second service.
//   GET      /saml11                   what all of that is, for somebody who
//                                      clicked the link.
//
// ---------------------------------------------------------------------------
// SEVEN DECISIONS HERE ARE NOT OBVIOUS FROM THE SPECIFICATIONS, AND THE FIRST
// THREE ARE WHERE SAML 1.1 IS GENUINELY A DIFFERENT PROTOCOL RATHER THAN AN
// OLDER SPELLING OF THE SAME ONE. Reading `saml2_sso.js`'s six decisions and
// assuming these are the same six is the specific mistake this list exists to
// prevent.
//
// 1. **THERE IS NO REQUEST MESSAGE, SO THERE IS NOTHING TO PARSE AND NOTHING TO
//    ANSWER.** SAML 1.1 has no `<AuthnRequest>`: the browser profiles are
//    IDENTITY-PROVIDER-INITIATED, and a flow starts when a browser arrives at
//    the inter-site transfer service carrying a `TARGET` — the URL at the
//    relying party it wants to end up at. Four consequences follow and every one
//    of them is a place where a reader who knows 2.0 will expect the opposite:
//
//      * **The relying party does not identify itself.** There is no `Issuer`.
//        Who the assertion is FOR comes from the `{rp}` path segment, from
//        Shibboleth's `providerId` parameter, or — failing both — is INFERRED
//        FROM THE ORIGIN of the assertion consumer URL, which is a guess and is
//        made out loud. See relyingPartyFor().
//      * **Nothing asks for a NameIdentifier format, a binding or an
//        authentication context**, so `saml11.nameIdFormat` and
//        `saml11.defaultProfile` are answers rather than defaults a request
//        overrides. The non-spec `format` and `profile` parameters exist so that
//        both can be exercised by hand; that is the same device `/sts?encrypt=1`
//        is, and it is marked as non-spec everywhere it appears.
//      * **`ForceAuthn`, `IsPassive` and `RequestedAuthnContext` have no
//        spelling at all.** The 2.0 module implements all three. Here they are
//        absent from the protocol rather than unimplemented, which is why this
//        file has no `NoPassive` path — there is no way to ask for one.
//      * **A failure cannot be reported to the relying party.** With no request
//        there is no `InResponseTo`, and — the part that actually decides it —
//        an unsolicited `<samlp:Response>` carrying a failure status is not
//        something the Browser/POST profile defines. So an error here is a PAGE,
//        exactly as WS-Federation's is and unlike SAML 2.0's. samlError() says
//        so on the page rather than leaving it to be inferred.
//
//    Shibboleth 1.x bolted a request onto this and it is the one every real
//    SAML 1.1 service provider sends: a redirect to the identity provider with
//    `shire`, `target`, `providerId` and `time`, identified by the profile URI
//    `urn:mace:shibboleth:1.0:profiles:AuthnRequest`. **It is supported, it is
//    not a standard, and it is advertised in the metadata** — a SAML 1.1 relying
//    party that could not tell this service where to send the assertion would be
//    a mock nobody could point at anything.
//
// 2. **THE CONFIRMATION METHOD IS THE PROFILE, AND GETTING IT WRONG IS
//    INVISIBLE.** saml-profile-1.1 section 4.1.1.4 requires
//    `urn:oasis:names:tc:SAML:1.0:cm:artifact` for Browser/Artifact and section
//    4.2.1.4 requires `...:cm:bearer` for Browser/POST. They are not
//    interchangeable and they are not decoration: the confirmation method is the
//    assertion's own statement of HOW it reached the relying party, so an
//    artifact-profile assertion confirmed as `bearer` claims to have travelled
//    through the browser when it did not. A relying party that checks refuses
//    it; one that does not check works perfectly with either, which is why this
//    is worth a decision rather than a line of code. `saml11.js` exports both
//    constants so this file cannot spell either differently.
//
// 3. **AN ARTIFACT STANDS FOR AN ASSERTION HERE, WHERE A SAML 2.0 ARTIFACT
//    STANDS FOR A MESSAGE.** In 2.0 the artifact is resolved into an
//    `<ArtifactResponse>` wrapping the whole `<Response>` that would otherwise
//    have been POSTed. In 1.1 the artifact references the ASSERTION, and the
//    `<samlp:Response>` around it is built AT RESOLUTION TIME — which is what
//    lets it carry `InResponseTo` naming the SOAP request's `RequestID`, and
//    `Recipient` naming whoever asked. Storing a pre-built Response and handing
//    it back, which is what porting the 2.0 code would do, produces a Response
//    whose InResponseTo is empty and whose Recipient names the browser's
//    destination rather than the SOAP caller. Both are things a strict relying
//    party checks, and neither shows up in a happy path.
//
//    The one-shot rule is the same as 2.0's and for the same reason
//    (saml-bindings-1.1 section 3.2.3): resolving an artifact DESTROYS it, and
//    a second attempt is refused with a status naming the reason rather than
//    answered with the assertion again.
//
// 4. **THE RESPONDER ANSWERS FOUR REQUEST TYPES, NOT ONE, AND THAT IS A REAL
//    DIFFERENCE FROM THE 2.0 MODULE RATHER THAN SCOPE CREEP.** `saml2_sso.js`
//    has a SOAP endpoint that resolves artifacts and refuses everything else,
//    and its `CLAUDE.md` lists the Assertion Query and Request profile as not
//    implemented. Here the SOAP responder has to exist for the artifact profile
//    to work at all, and once it exists an `<AttributeQuery>` is the same
//    assertion builder behind the same envelope. So all four of SAML 1.1's
//    request types are answered: AssertionArtifact, AssertionIDReference,
//    AttributeQuery and AuthenticationQuery. **The attribute authority is the
//    half of SAML 1.1 that Shibboleth deployments actually leaned on**, and a
//    mock that spoke the browser profile without it would be missing the part a
//    Shibboleth service provider exercises on every sign-in.
//
// 5. **THE METADATA IS A SAML 2.0 DOCUMENT DESCRIBING A SAML 1.1 IDENTITY
//    PROVIDER, AND THAT IS CORRECT RATHER THAN A COMPROMISE.** SAML 1.1 has no
//    metadata specification — there was a `.well-known` file convention and
//    Shibboleth's own `sites.xml`, and neither is what anything reads now. What
//    every SAML 1.1 relying party consumes today is a
//    `saml-metadata-2.0-os` `<EntityDescriptor>` whose `IDPSSODescriptor`
//    carries `protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol"`
//    and whose endpoints name the 1.1 profile URIs as their bindings. That is
//    what is published here. It is per relying party and minted for anything
//    asked for, exactly as the 2.0 document is — see that module's decision 1,
//    which is the same argument and is not repeated.
//
// 6. **NOTHING IS VERIFIED, AND IN THIS PROFILE THERE IS ALSO NOTHING TO
//    VERIFY.** The 2.0 module records an AuthnRequest's signature and its
//    certificate without checking either. Here there is no request to sign, so
//    the posture is not a decision this file makes — it is a property of the
//    protocol. What IS recorded is the relying party's identity, its assertion
//    consumer URL and which profile it used, on the application entry under
//    `ou=applications`, so `/admin/saml11` can show what was actually asked for.
//
// 7. **THE ASSERTION IS BUILT BY `saml11.js` AND NOT BY THIS FILE**, which is
//    the same decision `saml2_sso.js` made about `saml2.js` and is worth
//    restating because the pull to write a second builder was stronger here: the
//    browser profiles want a NameQualifier, a SubjectLocality, a
//    DoNotCacheCondition and a confirmation method that WS-Federation has no use
//    for. They became options on the one builder, and the property that buys is
//    the one a second builder would silently have lost: **the custom SAML 1.1
//    attributes configured on `/admin/saml-attributes` reach an assertion issued
//    here with no wiring at all**, because the same `stats.samlAttributes('saml11',
//    …)` line that puts them in a WS-Federation assertion puts them in this one.
// ===========================================================================

const crypto = require('crypto');
// TRUST REALMS: the stores below are partitioned by realm. It requires
// config.js and nothing else here, so it cannot join a cycle and it registers
// no route, so its position is not a position at all.
const realms = require('../common/realms');
const { DOMParser } = require('@xmldom/xmldom');
const { SignedXml } = require('xml-crypto');
const app = require('../common/app');
const { log, logArtifact, STS, xmlEscape, genId, iso, baseUrlOf, randomId,
        parseBody, firstByLocal, textByLocal, userFor } = require('../common/helpers');
// Read per request rather than captured at require time, so that /admin/config
// and /admin-api can change what the next response says and how it is signed.
const config = require('../common/config');
// The one assertion writer for this version. See decision 7.
const { buildSaml11Assertion, CONFIRMATION_BEARER, CONFIRMATION_ARTIFACT,
        NAMEID_FORMAT_UNSPECIFIED } = require('./saml11');
// The SLUG, and ONLY the slug. This is a require from the 1.1 profile to the 2.0
// one and it is deliberate rather than convenient: the slug is a HANDLE FOR AN
// APPLICATION, and `/saml2/metadata/app-1a2b3c` and `/saml11/metadata/app-9f8e7d`
// naming one entry in one directory would be the same defect two spellings of a
// DN is — one thing that reads as two. It is also a require in the ordinary
// direction (server.js takes 2.0 at 10a and this file at 10b), so it closes no
// cycle and moves no route. Nothing else is taken from that module; the two
// profiles share a registry and a session and know nothing else about each
// other.
const { slugOf } = require('./saml2_sso');
// The session, from the service that owns it. This profile starts none of its
// own and has no sign-in screen: `beginAuthentication()` sends the browser to
// authn.js's screen and back, exactly as the 2.0 profile does. See the note
// above interSiteTransfer() for why that works here without the POST-to-GET
// dance that module needs.
const { sessionOf, beginAuthentication } = require('../authn/authn');
// The application registry, which lives under ou=applications in the embedded
// directory. A library that registers no route, so requiring it here changes
// nothing about the route order this module's position in server.js fixes.
const applications = require('../common/applications');

// --- the vocabulary --------------------------------------------------------
// SAML 1.1's namespaces carry `1.0` and that is not a typo anywhere in this
// file: the assertion and protocol schemas were never renamed between 1.0 and
// 1.1, and the version travels in MajorVersion/MinorVersion attributes instead.
// Writing `urn:oasis:names:tc:SAML:1.1:assertion` produces a document that looks
// right in a diff and that nothing will parse.
const NS_SAML = 'urn:oasis:names:tc:SAML:1.0:assertion';

const NS_SAMLP = 'urn:oasis:names:tc:SAML:1.0:protocol';

const NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata';

const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

const NS_SOAP = 'http://schemas.xmlsoap.org/soap/envelope/';

// The two browser profiles, by the URIs metadata names them with. Both carry
// `1.0` for the reason the namespaces do, and `artifact-01` is the real spelling
// rather than a truncation of something.
const PROFILE_POST = 'urn:oasis:names:tc:SAML:1.0:profiles:browser-post';

const PROFILE_ARTIFACT = 'urn:oasis:names:tc:SAML:1.0:profiles:artifact-01';

// The SOAP binding the responder speaks.
const BINDING_SOAP = 'urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding';

// Shibboleth's request profile — decision 1. Advertised so that a service
// provider building its endpoint list from the metadata offers it.
const PROFILE_SHIB_AUTHN_REQUEST = 'urn:mace:shibboleth:1.0:profiles:AuthnRequest';

// What `protocolSupportEnumeration` says. THIS one is spelled 1.1, because it
// names the PROTOCOL version rather than a schema namespace — the one place in
// this file where the digit changes, and the reason the constant exists rather
// than the literal being written inline next to the others.
const PROTOCOL_SAML11 = 'urn:oasis:names:tc:SAML:1.1:protocol';

// **SAML 1.1 STATUS CODES ARE QNames, NOT URIs**, and this is the single easiest
// thing in the file to get wrong by writing 2.0 out of habit. The value of
// `<samlp:StatusCode Value="...">` is a qualified name resolved against the
// document's namespace declarations — so `samlp:Success` is only correct while
// the `samlp` prefix is bound on an ancestor, and a relying party that resolves
// the QName properly reads a status of `{urn:oasis:names:tc:SAML:1.0:protocol}Success`.
// Writing the 2.0 URI here produces a document that looks plausible and whose
// status resolves to nothing at all.
const STATUS_SUCCESS = 'samlp:Success';

const STATUS_REQUESTER = 'samlp:Requester';

const STATUS_RESPONDER = 'samlp:Responder';

const SIG_RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

const DIGEST_SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

const C14N_EXCLUSIVE = 'http://www.w3.org/2001/10/xml-exc-c14n#';

const TRANSFORM_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

// The NameIdentifier formats this identity provider ADVERTISES. Shorter than the
// 2.0 list and deliberately so: the three 2.0-only formats (persistent,
// transient, entity) have no meaning in a 1.1 assertion, and advertising them
// would tell a relying party it could ask for something the protocol has no way
// to ask for. What is here is what SAML 1.1 defines plus the X.509 one every
// deployment used. As in 2.0, the list is what goes in the metadata and is NOT a
// list of what will be accepted: the non-spec `format` parameter is answered with
// whatever it says.
const NAMEID_FORMATS = [
  NAMEID_FORMAT_UNSPECIFIED,
  'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName'
];

// How the End-User authenticated, in SAML 1.1's vocabulary — `am:` URIs, where
// 2.0 has `ac:classes:`. THREE outcomes, because /authn/login can use a security
// key in either of two roles: after a password (two factors) or instead of one
// (one factor, and a key).
//
// **This is deliberately NOT shared with `../ws-federation/wsfed.js`'s
// authnMethodsFor(), which computes the same three values**, and the reasoning
// is that module's own: a require from here to `ws-federation/` would make a
// browser SSO profile depend on the passive requestor profile for a lookup
// table, and half of that function is the SAML 2.0 vocabulary, which has no
// meaning in this file. `saml2_sso.js` states the same thing about the same
// function and made the same choice. If one of the three outcomes changes, all
// three files change — and the multi-factor test is the one that has already
// moved once: it is `hwk` AND `pwd`, not `hwk` alone, because a passwordless
// sign-in would otherwise claim `multipleauthn`.
const AM_PASSWORD = 'urn:oasis:names:tc:SAML:1.0:am:password';

const AM_HARDWARE_TOKEN = 'urn:oasis:names:tc:SAML:1.0:am:HardwareToken';

// Microsoft's, and used here for the reason wsfed.js records: SAML 1.1's own
// authentication methods have no member that describes a WebAuthn hardware key
// used as a second factor without overstating what happened.
const AM_MULTIFACTOR = 'http://schemas.microsoft.com/claims/multipleauthn';

const BASE_PATH = '/saml11';

const SSO_PATH = BASE_PATH + '/sso';

const RESPONDER_PATH = BASE_PATH + '/responder';

const METADATA_PATH = BASE_PATH + '/metadata';

const RP_PATH = BASE_PATH + '/rp';

// A flow interrupted by the sign-in screen. Smaller than the 2.0 module's
// equivalent in what it holds, because there is no request document to hold —
// just the handful of parameters the browser arrived with.
const REQUEST_TTL_MS = 10 * 60 * 1000;

// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const pendingFlows = realms.map();

// Artifact -> the ASSERTION it stands for (decision 3), and the context needed
// to build a Response around it later. Resolving one deletes it, so this map is
// also the record of what has NOT been resolved yet.
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const artifacts = realms.map();

// AssertionID -> the assertion, for <samlp:AssertionIDReference>. It is a
// SEPARATE map from the artifacts above and outlives them on purpose: an
// artifact is one-shot and an AssertionIDReference is not, because the reference
// is not a credential — anybody holding the assertion already has the assertion,
// and the reference is how a relying party asks for it AGAIN after it dropped
// its copy. Bounded rather than swept on a timer, for the reason every store in
// this service is: nothing here persists, and a mock that ran out of memory
// overnight would be a worse mock than one that forgot the oldest assertion.
const ASSERTION_CACHE_MAX = 500;

// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const assertionsById = realms.map();

// ---------------------------------------------------------------------------
// WHICH RELYING PARTY A REQUEST NAMES, which is decision 1's hardest
// consequence.
//
// SAML 2.0 reads the `<saml:Issuer>` off the AuthnRequest and is done. There is
// no request here, so the answer is looked for in four places in order, and the
// LAST of them is a guess this service makes out loud:
//
//   1. `providerId`, Shibboleth's parameter. A real SAML 1.1 service provider
//      sends it, and it is the only thing in this protocol that is the relying
//      party SAYING WHO IT IS.
//   2. the `{rp}` path segment, which is what /admin/saml11 links to and what
//      the per-relying-party metadata document tells a service provider to use.
//   3. `TARGET`'s origin, or the assertion consumer's — because a relying party
//      that sent neither of the above has still told this service where it
//      lives, and `https://app.example.com` is a better audience than nothing.
//   4. nothing, and then the request is refused with a page saying which of the
//      three to supply.
//
// The THIRD is the one to be careful about: it is a guess, it is logged as one,
// and it is the reason the assertion's audience can differ from what a relying
// party expected to see. That is stated on the page rather than left to be
// discovered inside a signature.
// ---------------------------------------------------------------------------
function originOf(url) {
  const m = /^(https?:\/\/[^/?#]+)/i.exec(String(url || ''));
  return m ? m[1] : '';
}

// The relying party a path segment names, and whether this service had heard of
// it. It NEVER answers "no such relying party", for the reason `saml2_sso.js`'s
// decision 1 gives: the ask is what registers it, so a service provider can be
// pointed here before anything at all has been provisioned.
function relyingPartyFromSegment(segment) {
  log.debug("Entering relyingPartyFromSegment(). segment=" + (segment || '(none)'));
  const text = String(segment == null ? '' : segment).trim();
  if (!text) {
    log.debug("Leaving relyingPartyFromSegment(). The unscoped endpoint.");
    return { id: '', known: false, unscoped: true };
  }
  // Express has already percent-decoded the parameter, so an identifier that was
  // encoded into the path arrives whole here.
  const direct = applications.get(text);
  if (direct) {
    log.debug("Leaving relyingPartyFromSegment(). It is a known identifier.");
    return { id: text, known: true, unscoped: false };
  }
  // A slug, then — which cannot be reversed, so it has to be looked for. A scan
  // of a mock's in-memory directory.
  const match = applications.list().filter(function (row) {
    return slugOf(row.identifier) === text;
  })[0];
  if (match) {
    log.debug("Leaving relyingPartyFromSegment(). A slug for " + match.identifier + ".");
    return { id: match.identifier, known: true, unscoped: false };
  }
  log.debug("Leaving relyingPartyFromSegment(). Nothing knows it; it IS the identifier.");
  return { id: text, known: false, unscoped: false };
}

// The four-step search above. Returns the identifier AND how it was arrived at,
// because the page and the log both say which — a guessed audience that nobody
// was told about is the failure this function exists to make impossible.
function relyingPartyFor(params, scoped, acsUrl) {
  log.debug("Entering relyingPartyFor().");
  if (params.providerId) {
    log.debug("Leaving relyingPartyFor(). From the providerId parameter.");
    return { id: String(params.providerId), from: 'the providerId parameter', guessed: false };
  }
  if (scoped.id) {
    log.debug("Leaving relyingPartyFor(). From the path segment.");
    return { id: scoped.id, from: 'the path segment', guessed: false };
  }
  const origin = originOf(params.TARGET) || originOf(acsUrl);
  if (origin) {
    log.warn('saml11: this flow names no relying party — SAML 1.1 has no request message for one ' +
             'to identify itself in, and neither providerId nor a path segment was supplied. The ' +
             'audience of the assertion is being GUESSED as "' + origin + '", from the origin of ' +
             'the TARGET. Send providerId, or use /saml11/sso/{rp}, to make it exact.');
    log.debug("Leaving relyingPartyFor(). Guessed from an origin.");
    return { id: origin, from: 'the origin of the TARGET, which is a guess', guessed: true };
  }
  log.debug("Leaving relyingPartyFor(). Nothing names one.");
  return { id: '', from: '', guessed: false };
}

// This identity provider's own providerID, for a given relying party. The same
// device `saml2_sso.js` uses and a SEPARATE setting, because a relying party
// that trusts this service for 1.1 and not for 2.0 is the ordinary case — see
// `saml11.providerId`.
function providerIdFor(rpId) {
  const base = String(config.value('saml11.providerId') || 'urn:sts-mock:idp:saml11');
  if (!rpId || !config.value('saml11.perApplicationProviderId')) {
    return base;
  }
  return base + ':' + slugOf(rpId);
}

// Where this relying party's endpoints live. One function so that the metadata
// document and the handlers cannot disagree about a URL — the failure that
// produces is a service provider configured from a document, posting to a path
// nothing serves, and a 404 that looks like the identity provider is down.
function endpointsFor(base, rpId) {
  const suffix = rpId ? '/' + encodeURIComponent(slugOf(rpId)) : '';
  return {
    sso: base + SSO_PATH + suffix,
    responder: base + RESPONDER_PATH + suffix,
    metadata: base + METADATA_PATH + suffix
  };
}

// ---------------------------------------------------------------------------
// THE REGISTRY.
//
// Every relying party this profile answers for gets an application entry, and
// this is the one place that happens. `counts` is the argument that matters, and
// it is `saml2_sso.js`'s: `applications.seen()` counts an AUTHENTICATION unless
// told otherwise, and a browser ARRIVING is not one — the person may never sign
// in. So the arrival records the sighting with `counts: false` and the RESPONSE
// records the authentication.
//
// The kind is `saml11-relying-party`, which the registry already had before this
// file existed — it is what a WS-Federation relying party handed a 1.1 assertion
// is recorded as. That is not a collision to be tidied up: a relying party that
// takes a SAML 1.1 assertion through WS-Federation and one that takes it through
// the Browser/POST profile are the same relying party with the same audience,
// and giving the browser profiles a kind of their own would split one
// application into two entries. `note` says which door it came through.
// ---------------------------------------------------------------------------
const RP_KIND = 'saml11-relying-party';

function recordRelyingParty(detail) {
  log.debug("Entering recordRelyingParty(). identifier=" + (detail.identifier || '(none)'));
  if (!config.value('saml11.autocreateApplications')) {
    log.debug("Leaving recordRelyingParty(). saml11.autocreateApplications is off.");
    return null;
  }
  const record = applications.seen(detail);
  log.debug("Leaving recordRelyingParty().");
  return record;
}

// What the registry already knows about this relying party, as plain fields.
// Absent everywhere the directory is (see applications.js's header — without
// ldap_server.js there is no registry at all), so every caller has to cope with
// an empty object rather than with null.
function fieldsOf(rpId) {
  const row = rpId ? applications.get(rpId) : null;
  return (row && row.fields) || {};
}

// The parameters of a request, from a GET query or a form POST. The body wins on
// a collision for the reason `wsfed.js`'s paramsOf() gives: a POST that also
// carried query parameters said the same thing twice and the body is the half it
// meant.
function paramsOf(req) {
  log.debug("Entering paramsOf(). method=" + req.method);
  const out = {};
  Object.keys(req.query || {}).forEach(function (k) { out[k] = req.query[k]; });
  if (req.method === 'POST') {
    const body = parseBody(req);
    Object.keys(body).forEach(function (k) { out[k] = body[k]; });
  }
  log.debug("Leaving paramsOf(). " + Object.keys(out).length + " parameter(s).");
  return out;
}

// --- the pages -------------------------------------------------------------
// One shell, and it is `wsfed.js`'s and `saml2_sso.js`'s: the CSS is inline
// because app.js sets `default-src 'none'` with `style-src 'unsafe-inline'`, so
// a stylesheet as a separate resource would need its own exception to buy
// nothing.
function page(title, inner) {
  return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + xmlEscape(title) + '</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'padding:2rem;color:#222;line-height:1.45}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:24px 28px;' +
    'max-width:56rem;margin:0 auto;box-shadow:0 6px 24px rgba(0,0,0,.08)}' +
    'h1{font-size:1.3em;margin:0 0 4px;color:#12107c}h2{font-size:1em;margin:1.4em 0 .4em}' +
    'p.sub{color:#666;font-size:.85em;margin:0 0 18px}' +
    '.row{display:flex;gap:10px;margin-top:20px;flex-wrap:wrap}' +
    'button{font:inherit;padding:.5rem 1rem;border-radius:6px;border:1px solid #12107c;' +
    'background:#12107c;color:#fff;cursor:pointer}' +
    'button.alt{background:#fff;color:#12107c}' +
    '.err{background:#fdf0f0;border:1px solid #e7c3c3;border-radius:6px;padding:.7rem .9rem;' +
    'color:#8a1f1f;margin:.6em 0}' +
    '.ok{color:#1a6b2a;font-weight:600}.bad{color:#8a1f1f;font-weight:600}' +
    'table{border-collapse:collapse;width:100%;margin:.5em 0;font-size:.85em}' +
    'th,td{border:1px solid #e2e2ea;padding:.35rem .5rem;text-align:left;vertical-align:top}' +
    'th{background:#f7f7fb}' +
    '.meta{margin-top:18px;padding-top:12px;border-top:1px solid #eee;font-size:.78em;color:#666;' +
    'word-break:break-all}.meta div{margin:3px 0}' +
    'pre{background:#f4f4f8;border:1px solid #e2e2ea;border-radius:5px;padding:.6rem;font-size:.75rem;' +
    'overflow-x:auto;white-space:pre-wrap;word-break:break-all}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em;background:#f4f4f8;' +
    'padding:.1rem .25rem;border-radius:3px;word-break:break-all}a{color:#12107c}' +
    'ul{margin:.3em 0;padding-left:1.2em}li{margin:.2em 0}' +
    '</style></head><body><div class="card">' + inner + '</div></body></html>\n';
}

function sendPage(res, status, title, inner) {
  res.status(status).type('text/html').set('Cache-Control', 'no-store').send(page(title, inner));
}

// A sentence naming what was wrong, and a 400.
//
// **THE ERROR IS A PAGE AND NOT A `<samlp:Response>`, WHICH IS THE OPPOSITE OF
// WHAT THE 2.0 MODULE DOES** — and it is decision 1 rather than a shortcut. That
// profile can report a failure to the service provider because its response
// answers a request: there is an `InResponseTo` to fill in and an assertion
// consumer expecting something. Here the browser arrived unsolicited, so a
// failure `<samlp:Response>` POSTed to a relying party would be a document it
// never asked for, carrying a status about a request it never sent. WS-Federation
// reaches the same conclusion from the same starting point, and says so in
// wsfedError().
function samlError(res, status, title, detail, extra) {
  log.debug("Entering samlError(). status=" + status + ", title=" + title);
  const inner = '<h1>' + xmlEscape(title) + '</h1>' +
    '<p class="sub">SAML 1.1 inter-site transfer service at <code>' + SSO_PATH + '</code></p>' +
    '<div class="err">' + xmlEscape(detail) + '</div>' + (extra || '') +
    '<div class="meta"><div>This is a page rather than a <code>&lt;samlp:Response&gt;</code>, and ' +
    'unlike the SAML 2.0 profile that is not because the destination is unknown — it is because ' +
    'SAML 1.1\'s browser profiles have NO REQUEST MESSAGE. The browser arrived here unsolicited, ' +
    'so there is nothing to answer and no <code>InResponseTo</code> to name. A failure delivered ' +
    'to the relying party would be a document it never asked for.</div>' +
    '<div>The request is logged in full at debug level.</div></div>';
  res.status(status).type('text/html').set('Cache-Control', 'no-store').send(page(title, inner));
  log.debug("Leaving samlError().");
}

// --- signing ---------------------------------------------------------------
// **A SAML 1.1 `<samlp:Response>` PUTS ds:Signature FIRST, and that is a THIRD
// position for the same element in this one service.** The 1.1 schema's
// ResponseAbstractType opens its sequence with `ds:Signature?`, so the signature
// precedes `<samlp:Status>`. Counting what this repository now contains: a SAML
// 1.1 ASSERTION signs last (saml11.js, and xml-crypto's default is right for
// once), a SAML 1.1 RESPONSE signs first, a SAML 2.0 protocol message signs
// after `<saml:Issuer>`, and a metadata EntityDescriptor signs first. Getting one
// wrong produces a document that verifies here and that a strict parser rejects,
// which is the worst of both outcomes.
//
// The other half is the ID ATTRIBUTE. SAML 1.1 spells it `ResponseID` on a
// Response and `AssertionID` on an assertion, and xml-crypto's reference
// resolution knows about `Id`, `ID` and `id` only. SIGNING does not care — the
// digest is computed over the node an xpath selected — but VERIFICATION does, and
// a verifier that is not told resolves `#_abc` to nothing and reports a perfectly
// good signature as broken. That cost `wsfed.js` a debugging session, it is why
// verifyAssertionSignature() there takes an idAttribute, and it is why the mock
// relying party below passes one for both documents.
function signDocument(xml, rootLocalName, id, placement, idAttribute) {
  log.debug("Entering signDocument(). root=" + rootLocalName + ", placement=" + placement +
            ", idAttribute=" + (idAttribute || '(the defaults)'));
  // **NAMING THE ID ATTRIBUTE HERE IS WHAT KEEPS THIS DOCUMENT VERIFIABLE AT
  // ALL**, and the failure it prevents is worth the paragraph because it looks
  // like an attack report. xml-crypto's ensureHasId() searches the node for the
  // first of `Id`, `ID`, `id`; finding none it INVENTS `Id="_0"` and rewrites the
  // reference URI to match. A SAML 1.1 Response has `ResponseID` and the
  // assertion inside it has `AssertionID`, so with nothing named BOTH get
  // `Id="_0"` — and xml-crypto then refuses to verify either one, reporting
  // "multiple elements with the same value for the ID / Id / Id attributes",
  // which is its signature-wrapping guard firing on a document this service
  // built itself.
  //
  // Passing the real name makes it find the real attribute, inject nothing, and
  // reference `#` + that id — which is also the document a SAML 1.1 relying
  // party expects. It is only safe because neither name is already on that
  // default list: `saml2_sso.js` records the opposite case, where naming `ID`
  // for SAML 2.0 unshifts a duplicate and trips the very same guard. The
  // metadata's `EntityDescriptor` therefore passes NOTHING — its id attribute is
  // spelled `ID`, which is already there.
  const options = { privateKey: STS.privateKeyPem, publicCert: STS.certPem };
  if (idAttribute) {
    options.idAttribute = idAttribute;
  }
  const sig = new SignedXml(options);
  sig.signatureAlgorithm = SIG_RSA_SHA256;
  sig.canonicalizationAlgorithm = C14N_EXCLUSIVE;
  sig.addReference({
    xpath: "/*[local-name(.)='" + rootLocalName + "']",
    transforms: [TRANSFORM_ENVELOPED, C14N_EXCLUSIVE],
    digestAlgorithm: DIGEST_SHA256,
    uri: id ? ('#' + id) : ''
  });
  const location = placement === 'append'
    ? { reference: "/*[local-name(.)='" + rootLocalName + "']", action: 'append' }
    : { reference: "/*[local-name(.)='" + rootLocalName + "']", action: 'prepend' };
  sig.computeSignature(xml, { location: location });
  const signed = sig.getSignedXml();
  log.debug("Leaving signDocument(). " + signed.length + " characters.");
  return signed;
}

// --- what a session says ---------------------------------------------------
// See the note above AM_PASSWORD for why this is not shared with wsfed.js.
function authnMethodFor(session) {
  log.debug("Entering authnMethodFor().");
  const amr = (session && session.amr) || [];
  const hardwareKey = amr.indexOf('hwk') >= 0;
  const password = amr.indexOf('pwd') >= 0;
  if ((hardwareKey && password) || (session && session.acr === 'mfa')) {
    log.debug("Leaving authnMethodFor(). Multi-factor.");
    return { method: AM_MULTIFACTOR, multiFactor: true, hardwareKey: hardwareKey };
  }
  if (hardwareKey) {
    log.debug("Leaving authnMethodFor(). A security key, and one factor.");
    return { method: AM_HARDWARE_TOKEN, multiFactor: false, hardwareKey: true };
  }
  log.debug("Leaving authnMethodFor(). A password.");
  return { method: AM_PASSWORD, multiFactor: false, hardwareKey: false };
}

// --- what goes in the assertion --------------------------------------------
// A SAML 1.1 attribute is `AttributeName` + `AttributeNamespace` — the two halves
// of a claim URI — where SAML 2.0 has one `Name`. So these are written as pairs,
// which is the shape `saml11.js` takes and the shape `wsfed.js`'s claimsFor()
// produces for the same builder.
//
// **The custom SAML 1.1 attributes from /admin/saml-attributes are NOT added
// here**, and that is decision 7's whole point: `buildSaml11Assertion()` appends
// them to whatever this returns, filtered on namespace AND name so that a
// configured attribute cannot displace one of these. Adding them here as well
// would put every one of them in twice.
const CLAIM_NS = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims';

const MS_CLAIM_NS = 'http://schemas.microsoft.com/ws/2008/06/identity/claims';

// Shibboleth's OID-style names, which are the other half of the SAML 1.1
// ecosystem: a service provider configured against a Shibboleth identity
// provider keys off `urn:mace:dir:attribute-def:*` (and later off the OID
// URNs), and one configured against AD FS keys off the claim URIs above.
// Sending both is what makes this mock usable against either without a mapper
// being written first — the same argument `saml2_sso.js` makes for sending the
// unqualified `uid`/`mail` spellings beside the URIs.
const MACE_NS = 'urn:mace:dir:attribute-def';

function attributesFor(user, authnMethod, authnInstant) {
  log.debug("Entering attributesFor(). user=" + user.username);
  const attributes = [
    { namespace: CLAIM_NS, name: 'name', value: user.username },
    { namespace: CLAIM_NS, name: 'givenname', value: user.given_name },
    { namespace: CLAIM_NS, name: 'surname', value: user.family_name },
    { namespace: CLAIM_NS, name: 'emailaddress', value: user.email },
    { namespace: CLAIM_NS, name: 'nameidentifier', value: user.sub },
    // The UPN and the mail address are the same string here because userFor()
    // mints one address, and inventing a second identifier that differed would
    // be a distinction with nothing behind it. The same note wsfed.js's
    // claimsFor() carries, for the same reason.
    { namespace: CLAIM_NS, name: 'upn', value: user.email },
    { namespace: MS_CLAIM_NS, name: 'authenticationmethod', value: authnMethod },
    { namespace: MS_CLAIM_NS, name: 'authenticationinstant', value: authnInstant },
    { namespace: MACE_NS, name: 'uid', value: user.username },
    { namespace: MACE_NS, name: 'mail', value: user.email },
    { namespace: MACE_NS, name: 'givenName', value: user.given_name },
    { namespace: MACE_NS, name: 'sn', value: user.family_name },
    { namespace: MACE_NS, name: 'displayName', value: user.name }
  ];
  log.debug("Leaving attributesFor(). " + attributes.length + " attribute(s).");
  return attributes;
}

// The NameIdentifier VALUE. Shorter than the 2.0 module's equivalent because two
// of the three cases it handles cannot arise here: SAML 1.1 has no `transient`
// or `persistent` format to answer, so there is no opaque identifier to derive
// and no lie to avoid telling.
function nameIdValueFor(format, session) {
  log.debug("Entering nameIdValueFor(). format=" + format);
  const username = (session.user && session.user.username) || '';
  if (format === 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress') {
    log.debug("Leaving nameIdValueFor(). The mail address.");
    return (session.user && session.user.email) || username;
  }
  if (format === 'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName') {
    // `domain\user`, which is what the format means and what a relying party
    // asking for it is going to try to split on a backslash.
    log.debug("Leaving nameIdValueFor(). A Windows domain qualified name.");
    return 'MOCKSTS\\' + username;
  }
  if (format === 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName') {
    log.debug("Leaving nameIdValueFor(). An X.509 subject name.");
    return 'CN=' + username;
  }
  log.debug("Leaving nameIdValueFor(). The username.");
  return username;
}

// --- building the response --------------------------------------------------
// A `<samlp:Response>`, with or without an assertion in it. One builder for the
// success and the failure alike, because the two differ by exactly one child
// element and a status code — and because an error response that took a
// different code path is an error response nobody ever looks at.
//
// THREE attributes here are 1.1-only and each is worth naming, because a reader
// who knows 2.0 will look for the wrong spelling of all three:
//
//   ResponseID     what 2.0 calls `ID`, and what the signature's reference has
//                  to resolve through.
//   Recipient      the assertion consumer this is being delivered TO. Section
//                  4.2.1.4 requires it for Browser/POST and it is what stops a
//                  response being replayed at a different relying party. SAML
//                  2.0 spells the same idea `Destination` on the Response and
//                  `Recipient` inside SubjectConfirmationData.
//   InResponseTo   present ONLY when answering a SOAP request. It MUST be absent
//                  in Browser/POST, because there was no request — writing one
//                  there names a RequestID nobody minted.
function buildResponse(opts) {
  log.debug("Entering buildResponse(). status=" + opts.status);
  const id = genId();
  const xml =
    '<samlp:Response xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' + NS_SAML + '"' +
      ' ResponseID="' + id + '" MajorVersion="1" MinorVersion="1"' +
      ' IssueInstant="' + iso(0) + '"' +
      (opts.recipient ? ' Recipient="' + xmlEscape(opts.recipient) + '"' : '') +
      (opts.inResponseTo ? ' InResponseTo="' + xmlEscape(opts.inResponseTo) + '"' : '') + '>' +
      '<samlp:Status><samlp:StatusCode Value="' + xmlEscape(opts.status) + '"/>' +
        (opts.statusMessage
          ? '<samlp:StatusMessage>' + xmlEscape(opts.statusMessage) + '</samlp:StatusMessage>'
          : '') +
      '</samlp:Status>' +
      (opts.assertion || '') +
    '</samlp:Response>';
  logArtifact('SAML 1.1 Response', 'before signing', xml);
  if (!config.value('saml11.signResponse')) {
    log.debug("Leaving buildResponse(). Unsigned: saml11.signResponse is off.");
    return { xml: xml, id: id, signed: false };
  }
  try {
    // 'prepend' — ds:Signature is the FIRST child of a 1.1 Response. See
    // signDocument()'s header, where all four positions in this service are
    // counted.
    const signed = signDocument(xml, 'Response', id, 'prepend', 'ResponseID');
    logArtifact('SAML 1.1 Response', 'after signing', signed);
    log.debug("Leaving buildResponse(). Signed.");
    return { xml: signed, id: id, signed: true };
  } catch (e) {
    // Reported and returned unsigned rather than thrown, exactly as
    // buildSaml11Assertion() does: an unsigned response that a relying party
    // rejects is a diagnosable failure, and an exception here is a 500 that says
    // nothing about SAML at all.
    log.error('the SAML 1.1 Response could not be signed, sending it unsigned: ' + e.message);
    log.debug("Leaving buildResponse(). Unsigned after a signing failure.");
    return { xml: xml, id: id, signed: false };
  }
}

// The assertion, from the one builder. Everything the browser profiles require
// of it and nothing this file decided for itself — see decision 7.
function buildAssertionFor(ctx) {
  log.debug("Entering buildAssertionFor(). rp=" + ctx.rpId + ", profile=" + ctx.profile);
  const session = ctx.session;
  const user = session.user;
  const how = authnMethodFor(session);
  const lifetimeMin = Number(config.value('saml11.assertionLifetimeMin')) || 60;
  const format = ctx.nameIdFormat ||
    String(config.value('saml11.nameIdFormat') || NAMEID_FORMAT_UNSPECIFIED);
  const authnInstant = new Date((session.authTime || 0) * 1000).toISOString();
  const assertion = buildSaml11Assertion({
    subject: user.username,
    audience: ctx.rpId,
    lifetimeMin: lifetimeMin,
    authnMethod: how.method,
    authnInstant: authnInstant,
    issuer: ctx.providerId,
    nameIdFormat: format,
    nameIdValue: nameIdValueFor(format, session),
    // The NameQualifier is this identity provider's own providerID, which is
    // what a Shibboleth service provider keys its attribute resolution off.
    nameQualifier: ctx.providerId,
    // DECISION 2. The profile IS the confirmation method, and the two are not
    // interchangeable.
    confirmationMethod: ctx.profile === 'artifact' ? CONFIRMATION_ARTIFACT : CONFIRMATION_BEARER,
    // Section 4.2 asks the identity provider to record where the browser was.
    // It is the one element in the assertion written from the HTTP request
    // rather than from the session, and it is omitted entirely when there is
    // nothing to say rather than written empty.
    subjectLocality: ctx.locality,
    // The Browser/POST single-use policy: the assertion travels through the
    // browser, so the relying party is told not to keep it. Not set for the
    // artifact profile, where the assertion never passes through the browser
    // and caching it is the relying party's business.
    doNotCache: ctx.profile === 'post',
    attributes: attributesFor(user, how.method, authnInstant),
    sign: config.value('saml11.signAssertion')
  });
  log.debug("Leaving buildAssertionFor(). " + assertion.length + " characters.");
  return assertion;
}

// Remember an assertion by its AssertionID, for <samlp:AssertionIDReference>.
// Oldest out first when the cache is full — a Map iterates in insertion order,
// which makes this three lines rather than a data structure.
function rememberAssertion(xml) {
  const m = /\bAssertionID="([^"]+)"/.exec(xml);
  if (!m) {
    // Nothing to key on. It cannot happen with an assertion this service built,
    // and if it ever does the reference lookup simply misses rather than this
    // throwing inside a sign-in.
    log.debug("rememberAssertion(): no AssertionID, so it is not cached.");
    return '';
  }
  assertionsById.set(m[1], xml);
  while (assertionsById.size > ASSERTION_CACHE_MAX) {
    assertionsById.delete(assertionsById.keys().next().value);
  }
  return m[1];
}

// --- delivering it ----------------------------------------------------------
// Written with no regular expressions and nothing to escape, for the reason
// oauth2.js's ceremony script records: a backslash in a script that passes
// through a JavaScript string literal on its way out does not survive the trip.
const AUTOPOST_SCRIPT = [
  '(function () {',
  '  var f = document.getElementById("saml11-form");',
  '  if (f) { f.submit(); }',
  '})();',
  ''
].join('\n');

// **THIS IS THE SIXTH SCRIPTED PAGE IN THIS SERVICE AND THE ARGUMENT IS MADE
// AGAIN RATHER THAN BY ANALOGY**, which is what the root CLAUDE.md asks for —
// and it asks precisely because the fifth was `/saml2/autopost.js`, which makes
// "the same as the one next door" the most tempting and least useful thing to
// say here.
//
// The argument stands on its own: `app.js` sets `script-src 'none'` on every
// response because that makes the family of reflected-content problems moot
// rather than merely unlikely. The Browser/POST profile (saml-bindings-1.1
// section 4.1.2) **is** a self-submitting form — the specification's own
// description of the profile is that the identity provider returns a document
// containing a form whose action is the assertion consumer and which submits
// itself — so there is no version of this profile without a script. It is not
// the same requirement as SAML 2.0's HTTP POST binding, it is an older and
// separate specification that arrived at the same shape, and it would still be
// here if the 2.0 profile had never been written.
//
// The exception is the same shape as the other five and no wider: `script-src
// 'self'` naming ONE resource, never `'unsafe-inline'`. And the submit button is
// not a fallback nobody sees — with scripting off the button IS the mechanism,
// so it is labelled for a person rather than hidden.
//
// `form-action` is deliberately absent from the policy, here as everywhere: the
// form posts to the relying party's assertion consumer, which is by definition
// another origin, and `form-action 'self'` would block the response from ever
// arriving. The symptom is a sign-in that appears to succeed while the relying
// party never hears anything.
app.get(BASE_PATH + '/autopost.js', function (req, res) {
  log.debug("Serving the SAML 1.1 Browser/POST profile auto-post script.");
  res.set('Content-Security-Policy', app.contentSecurityPolicy({ 'style-src': null,
                                                                 'img-src': null }));
  res.type('application/javascript').set('Cache-Control', 'no-store').send(AUTOPOST_SCRIPT);
});

// The Browser/POST form. `TARGET` travels beside `SAMLResponse` and is the
// relying party's own state — SAML 1.1's equivalent of `RelayState`, and the
// same rule applies to it: echoed byte for byte and never interpreted. An
// identity provider that decoded and re-encoded it produces the same symptom as
// a lost session.
function postProfilePage(destination, message, target, note) {
  log.debug("Entering postProfilePage(). destination=" + destination);
  const inner = '<h1>' + xmlEscape(note.title) + '</h1>' +
    '<p class="sub">' + note.sub + '</p>' +
    '<form method="post" action="' + xmlEscape(destination) + '" id="saml11-form">' +
      '<input type="hidden" name="SAMLResponse" value="' + xmlEscape(message) + '">' +
      (target ? '<input type="hidden" name="TARGET" value="' + xmlEscape(target) + '">' : '') +
      '<div class="row"><button type="submit">Continue to ' + xmlEscape(note.who) +
      '</button></div>' +
    '</form>' +
    '<div class="meta">' +
    '<div>posting to: <code>' + xmlEscape(destination) + '</code></div>' +
    '<div>field: <code>SAMLResponse</code>, ' + message.length + ' base64 characters</div>' +
    '<div>TARGET: ' + (target ? '<code>' + xmlEscape(target) + '</code>, echoed byte for byte'
                              : 'none was supplied, so none is returned') + '</div>' +
    '<div>The form submits itself from <code>' + BASE_PATH + '/autopost.js</code>. It is a ' +
    'separate resource because this service sets <code>script-src \'none\'</code> on every ' +
    'response and this page relaxes it to <code>\'self\'</code> — an inline script would not run, ' +
    'and the button would be the only thing that worked. With scripting off, the button IS the ' +
    'mechanism.</div>' +
    '</div>' +
    '<script src="' + BASE_PATH + '/autopost.js"></script>';
  log.debug("Leaving postProfilePage().");
  return inner;
}

function sendPostProfile(res, title, inner) {
  res.set('Content-Security-Policy', app.contentSecurityPolicy({ 'script-src': "'self'" }));
  res.status(200).type('text/html').set('Cache-Control', 'no-store').send(page(title, inner));
}

// ---------------------------------------------------------------------------
// THE ARTIFACT (saml-bindings-1.1 section 3.2.2).
//
// **TYPE 0x0001, NOT 0x0004**, and the two are not the same layout with a
// different number on the front:
//
//   TypeCode        0x0001, the only artifact type SAML 1.1 defines
//   SourceID        SHA-1 of the ISSUER's providerID. Not a hash for security —
//                   an INDEX, so a relying party talking to several identity
//                   providers can tell whose artifact it is holding without
//                   asking anybody
//   AssertionHandle twenty random bytes, and the only part that is a secret
//
// FORTY-TWO BYTES, where a SAML 2.0 artifact is forty-four: 2.0 added a
// two-byte EndpointIndex after the type code so that an identity provider could
// publish several resolution services. SAML 1.1 has no such field, so there is
// exactly one responder and its address has to come from the metadata or from
// configuration. A relying party that assumes the 2.0 layout reads this
// artifact's SourceID two bytes late and matches no identity provider it knows.
// ---------------------------------------------------------------------------
function mintArtifact(providerId) {
  log.debug("Entering mintArtifact(). providerId=" + providerId);
  const header = Buffer.alloc(2);
  header.writeUInt16BE(0x0001, 0);
  const sourceId = crypto.createHash('sha1').update(String(providerId), 'utf8').digest();
  const handle = crypto.randomBytes(20);
  const artifact = Buffer.concat([header, sourceId, handle]).toString('base64');
  log.debug("Leaving mintArtifact(). " + artifact.length + " base64 characters.");
  return artifact;
}

function stashArtifact(artifact, detail) {
  const ttlS = Number(config.value('saml11.artifactTtlS')) || 300;
  artifacts.set(artifact, Object.assign({ expires: Date.now() + ttlS * 1000 }, detail));
  artifacts.forEach(function (v, k) {
    if (v.expires < Date.now()) {
      artifacts.delete(k);
    }
  });
}

// Deliver a built assertion to a relying party, on whichever profile was chosen.
// The two profiles differ in WHAT travels through the browser — the assertion
// itself, or a reference to it — which is the whole distinction between them.
function deliver(res, opts) {
  log.debug("Entering deliver(). profile=" + opts.profile);
  if (opts.profile === 'artifact') {
    const artifact = mintArtifact(opts.providerId);
    // The ASSERTION is stashed, not a Response — decision 3. The Response is
    // built at resolution time so it can carry InResponseTo and a Recipient
    // naming the SOAP caller.
    stashArtifact(artifact, {
      assertion: opts.assertion, rpId: opts.rpId, providerId: opts.providerId,
      subject: opts.subject, createdAt: Date.now()
    });
    let url = opts.destination + (opts.destination.indexOf('?') >= 0 ? '&' : '?') +
      'SAMLart=' + encodeURIComponent(artifact);
    if (opts.target) {
      url += '&TARGET=' + encodeURIComponent(opts.target);
    }
    log.info('saml11: artifact ' + artifact.slice(0, 12) + '… stands for an assertion for ' +
             (opts.rpId || '(unnamed)') + '; it is resolvable once, at ' + RESPONDER_PATH + '.');
    // 303, not 302: this may follow a POST, and a 307 would repeat that body at
    // the relying party. The same reasoning authn.js's returnToCaller() writes
    // down at length.
    res.set('Cache-Control', 'no-store').redirect(303, url);
    log.debug("Leaving deliver(). By artifact.");
    return;
  }
  const response = buildResponse({
    status: STATUS_SUCCESS,
    // Recipient, and NO InResponseTo: there was no request. See buildResponse().
    recipient: opts.destination,
    assertion: opts.assertion
  });
  sendPostProfile(res, opts.note.title,
                  postProfilePage(opts.destination,
                                  Buffer.from(response.xml, 'utf8').toString('base64'),
                                  opts.target, opts.note));
  log.debug("Leaving deliver(). By form POST.");
}

// ---------------------------------------------------------------------------
// THE INTER-SITE TRANSFER SERVICE.
//
// SAML 1.1's name for the endpoint a browser is sent to in order to be signed
// in. The whole of the profile's front half is here and it runs in four steps
// rather than the 2.0 module's five, because the step that module spends most of
// its length on — reading a request message and deciding what it asked for —
// does not exist in this protocol:
//
//   1. read the parameters, and work out who this is for
//   2. work out where the answer goes
//   3. get a session, which may mean going to the sign-in screen and back
//   4. build the assertion and deliver it on the chosen profile
//
// **THIS ENDPOINT NEEDS NO POST-TO-GET DANCE, and that is worth stating because
// the 2.0 module's decision 2 is one of the most load-bearing paragraphs in the
// directory.** That profile has to hold an AuthnRequest and 303 to a GET,
// because the HTTP POST binding delivers the request as a CROSS-SITE FORM POST,
// which `SameSite=Lax` keeps the session cookie off. A SAML 1.1 flow arrives as
// a top-level GET navigation — a link, a redirect from the relying party, a
// bookmark — which Lax does carry. So the session is visible on the first
// request and there is nothing to stash. The POST route below exists only
// because somebody's relying party will post a form at it anyway, and answering
// that with a 405 would be a worse mock than reading it.
// ---------------------------------------------------------------------------
function localityOf(req) {
  // `req.ip` carries the proxy's address when one is in front and
  // `global.trustProxy` is off, which is the ordinary state here. It is written
  // into the assertion as what THIS SERVICE SAW, which is the only honest thing
  // it could be, and the log says so rather than the assertion pretending
  // otherwise.
  const address = String(req.ip || (req.connection && req.connection.remoteAddress) || '');
  if (!address) {
    return null;
  }
  // ::ffff:127.0.0.1 is how node reports an IPv4 client on a dual-stack socket.
  // Written as the IPv4 address a person would recognise, because a
  // SubjectLocality nobody can match against their own logs is decoration.
  return { ipAddress: address.replace(/^::ffff:/, '') };
}

// Which profile to use. The request may say — `profile=post|artifact`, non-spec
// and marked as such — and otherwise `saml11.defaultProfile` answers. There is
// no way for a SAML 1.1 relying party to ask in the protocol itself, which is
// decision 1 again: in 2.0 this comes off the AuthnRequest's ProtocolBinding.
function profileFor(params) {
  log.debug("Entering profileFor(). asked=" + (params.profile || '(none)'));
  const asked = String(params.profile || '').toLowerCase();
  if (asked === 'post' || asked === 'artifact') {
    log.debug("Leaving profileFor(). " + asked + ", from the non-spec profile parameter.");
    return { profile: asked, stated: true };
  }
  if (asked) {
    log.debug("Leaving profileFor(). An unknown profile was named.");
    return { error: asked };
  }
  const dflt = String(config.value('saml11.defaultProfile') || 'post');
  log.debug("Leaving profileFor(). " + dflt + ", the configured default.");
  return { profile: dflt === 'artifact' ? 'artifact' : 'post', stated: false };
}

function interSiteTransfer(req, res) {
  log.debug("Entering interSiteTransfer(). method=" + req.method);
  const base = baseUrlOf(req);
  const params = paramsOf(req);
  const scoped = relyingPartyFromSegment(req.params.rp);

  // A flow being resumed after the sign-in screen. There is no request document
  // to restore — just the parameters the browser first arrived with.
  const held = params.fid ? pendingFlows.get(String(params.fid)) : null;
  if (params.fid && !held) {
    log.debug("Leaving interSiteTransfer(). The held flow had expired.");
    return samlError(res, 400, 'This sign-in has expired',
      'A flow is held for ten minutes while the browser is at the sign-in screen. Start again ' +
      'from the relying party.');
  }
  const carried = held ? held.params : params;

  // --- step 1: is there a flow here at all ---------------------------------
  // TARGET is what makes this a browser profile request. `shire` alone counts
  // too: a Shibboleth service provider sends both, and one without the other is
  // a request that named where to send the assertion but not where to send the
  // person, which is worth answering rather than refusing.
  if (!carried.TARGET && !carried.shire && !carried.providerId) {
    log.debug("Leaving interSiteTransfer(). Nothing was asked for, so it describes itself.");
    return sendPage(res, 200, 'SAML 1.1 inter-site transfer service',
                    describeSsoPage(base, scoped));
  }

  const wanted = profileFor(carried);
  if (wanted.error) {
    log.debug("Leaving interSiteTransfer(). An unknown profile was named.");
    return samlError(res, 400, 'That is not one of the two browser profiles',
      'This request asked for profile="' + wanted.error + '". SAML 1.1 has exactly two browser ' +
      'profiles: "post" (Browser/POST, section 4.2) and "artifact" (Browser/Artifact, section ' +
      '4.1). The parameter is non-spec — nothing in SAML 1.1 lets a relying party choose — and ' +
      'it exists so both can be exercised by hand.');
  }

  // --- step 2: where does the answer go ------------------------------------
  // `shire` is Shibboleth's name for the assertion consumer service, and it is
  // the only thing in this protocol that carries one. Failing that: what the
  // registry recorded for this relying party, and failing THAT this service's
  // own mock relying party — so that a request naming no destination has
  // somewhere real to go instead of nowhere.
  const knownFirst = fieldsOf(scoped.id);
  const recorded = Array.isArray(knownFirst.samlAssertionConsumerService)
    ? knownFirst.samlAssertionConsumerService[knownFirst.samlAssertionConsumerService.length - 1]
    : knownFirst.samlAssertionConsumerService || '';
  const acsUrl = String(carried.shire || recorded || (base + RP_PATH));
  if (!/^https?:\/\//i.test(acsUrl)) {
    log.debug("Leaving interSiteTransfer(). The assertion consumer URL is not absolute.");
    return samlError(res, 400, 'The assertion consumer URL must be absolute',
      'It is "' + acsUrl + '". The response is delivered there by form POST or as an artifact on ' +
      'a redirect, and a relative value addresses this service instead — which looks exactly like ' +
      'a relying party that ignored the response.');
  }

  const who = relyingPartyFor(carried, scoped, acsUrl);
  if (!who.id) {
    log.debug("Leaving interSiteTransfer(). Nothing names a relying party.");
    return samlError(res, 400, 'Nothing here names a relying party',
      'SAML 1.1 has no request message, so there is no <saml:Issuer> for a relying party to ' +
      'identify itself in. This service takes the audience from the providerId parameter, from ' +
      'the {rp} path segment, or — failing both — from the origin of the TARGET. This request ' +
      'carried none of the three, and an assertion with no audience restriction is one any ' +
      'relying party would be entitled to accept.',
      '<p>There is a mock relying party here that sends a complete request: ' +
      '<a href="' + RP_PATH + '">' + RP_PATH + '</a>.</p>');
  }
  const rpId = who.id;
  const providerId = providerIdFor(rpId);

  // THE RELYING PARTY, recorded now that the request has been understood and
  // before anything can go wrong at the sign-in screen. `counts: false` because
  // a browser arriving is not an authentication — the person may never sign in
  // — and counting one here would double every successful flow.
  recordRelyingParty({
    identifier: rpId,
    kind: RP_KIND,
    protocol: 'SAML 1.1',
    note: 'arrived at the SAML 1.1 inter-site transfer service' +
          (who.guessed ? ', and its identity was guessed from the TARGET' : ''),
    counts: false,
    fields: {
      samlEntityId: rpId,
      samlAssertionConsumerService: acsUrl,
      samlNameIdFormat: String(carried.format || ''),
      samlResponseBinding: wanted.profile === 'artifact' ? PROFILE_ARTIFACT : PROFILE_POST
    }
  });

  // --- step 3: a session ----------------------------------------------------
  const session = sessionOf(req);
  if (!session) {
    // Hold the parameters and go to authn.js's screen. The return address is a
    // GET on this endpoint carrying the held id, so coming back runs this
    // function again from the top with a session in place.
    //
    // There is no ForceAuthn to honour and no RequestedAuthnContext to satisfy:
    // neither exists in this protocol (decision 1), so an existing session is
    // always good enough and this branch is reached only when there is none.
    const record = held || { id: randomId(18), params: carried };
    record.expires = Date.now() + REQUEST_TTL_MS;
    pendingFlows.set(record.id, record);
    pendingFlows.forEach(function (v, k) {
      if (v.expires < Date.now()) {
        pendingFlows.delete(k);
      }
    });
    const returnTo = req.path + '?fid=' + encodeURIComponent(record.id);
    const where = beginAuthentication({
      returnTo: returnTo,
      protocol: 'SAML 1.1',
      details: [
        { label: 'Relying party', value: rpId,
          note: who.guessed
            ? 'GUESSED from the origin of the TARGET — SAML 1.1 has no request message for a ' +
              'relying party to name itself in. It becomes the assertion\'s audience.'
            : 'from ' + who.from + '. It becomes the assertion\'s audience restriction.' },
        { label: 'Assertion consumer', value: acsUrl,
          note: 'where the assertion is delivered. Not checked against any registration.' },
        { label: 'Browser profile', value: wanted.profile === 'artifact'
            ? 'Browser/Artifact (section 4.1)' : 'Browser/POST (section 4.2)',
          note: wanted.stated ? 'asked for by the non-spec profile parameter.'
                              : 'the saml11.defaultProfile setting; nothing in SAML 1.1 lets a ' +
                                'relying party ask.' },
        { label: 'TARGET', value: String(carried.TARGET || '(none)'),
          note: 'the relying party\'s own state, echoed back untouched. SAML 1.1\'s RelayState.' }
      ]
    });
    log.debug("Leaving interSiteTransfer(). To the sign-in screen, returning to " + returnTo + ".");
    return res.set('Cache-Control', 'no-store').redirect(303, where);
  }

  // The person cancelled at the screen, or it failed. authn.js reports back on
  // the query string and leaves it to the CALLER to decide what its protocol
  // does — and what this one does is show a page, because decision 1 says there
  // is nowhere to report it to. That is the difference from the 2.0 profile,
  // which sends an AuthnFailed Response, and it is a property of SAML 1.1 rather
  // than a gap here.
  if (params.authn_error) {
    log.debug("The sign-in did not complete: " + params.authn_error);
    pendingFlows.delete(String(params.fid || ''));
    log.debug("Leaving interSiteTransfer(). The sign-in was not completed.");
    return samlError(res, 400, 'The sign-in did not complete',
      String(params.authn_error_description || params.authn_error),
      '<p>The SAML 2.0 profile answers this with a <code>&lt;samlp:Response&gt;</code> carrying ' +
      '<code>AuthnFailed</code>, delivered to the service provider. This one cannot: there is no ' +
      'request to answer and no <code>InResponseTo</code> to name, so the report is this page.</p>');
  }

  // --- step 4: the answer ---------------------------------------------------
  pendingFlows.delete(String(params.fid || ''));
  issueSignIn(res, req, {
    session: session, rpId: rpId, providerId: providerId, acsUrl: acsUrl,
    profile: wanted.profile, target: String(carried.TARGET || ''),
    nameIdFormat: String(carried.format || ''), how: who
  });
  log.debug("Leaving interSiteTransfer(). An assertion went to " + rpId + ".");
}

function issueSignIn(res, req, ctx) {
  log.debug("Entering issueSignIn(). rp=" + ctx.rpId + ", profile=" + ctx.profile);
  const session = ctx.session;
  const assertion = buildAssertionFor({
    session: session, rpId: ctx.rpId, providerId: ctx.providerId, profile: ctx.profile,
    nameIdFormat: ctx.nameIdFormat, locality: localityOf(req)
  });
  rememberAssertion(assertion);

  // THE AUTHENTICATION, recorded here rather than when the browser arrived: this
  // is the moment this service has decided to tell that relying party who
  // somebody is. The sighting was recorded at step 2 with `counts: false` for
  // exactly this reason.
  recordRelyingParty({
    identifier: ctx.rpId,
    kind: RP_KIND,
    protocol: 'SAML 1.1',
    sessionId: session.id || '',
    user: (session.user && session.user.username) || '',
    note: 'was issued a ' + (ctx.profile === 'artifact' ? 'Browser/Artifact' : 'Browser/POST') +
          ' assertion',
    fields: {
      samlEntityId: ctx.rpId,
      samlAssertionConsumerService: ctx.acsUrl,
      samlResponseBinding: ctx.profile === 'artifact' ? PROFILE_ARTIFACT : PROFILE_POST
    }
  });

  // Which relying parties this session has signed into. It lives ON the session
  // rather than in a map of its own because that is exactly the lifetime it
  // should have: when the session goes, so does the list, and nothing has to be
  // swept. The same decision `wsfed.js` makes about `session.wsfedRealms` and
  // `saml2_sso.js` about `session.saml2ServiceProviders`.
  //
  // **NOTHING READS IT YET, and that is deliberate rather than an oversight:
  // SAML 1.1 HAS NO SINGLE LOGOUT.** There is no LogoutRequest, no
  // LogoutResponse and no SingleLogoutService in the protocol — Single Logout
  // arrived with SAML 2.0. It is recorded because /admin/saml11 shows it and
  // because a person signing out of the console is entitled to see which relying
  // parties still hold an assertion nothing here can recall.
  session.saml11RelyingParties = session.saml11RelyingParties || {};
  session.saml11RelyingParties[ctx.rpId] = {
    acs: ctx.acsUrl, providerId: ctx.providerId, profile: ctx.profile, at: Date.now()
  };

  deliver(res, {
    profile: ctx.profile, destination: ctx.acsUrl, assertion: assertion, target: ctx.target,
    providerId: ctx.providerId, rpId: ctx.rpId,
    subject: (session.user && session.user.username) || '',
    note: { title: 'Signing in — SAML 1.1', who: 'the relying party',
            sub: 'saml-profile-1.1 section 4.2, the Browser/POST profile — the assertion travels ' +
                 'in the body of a form POST, so it is not length-limited and never appears in a ' +
                 'URL, a log or a Referer header.' }
  });
  log.debug("Leaving issueSignIn(). " +
            ((session.user && session.user.username) || '?') + " signed in to " + ctx.rpId + ".");
}

// ---------------------------------------------------------------------------
// THE SAML RESPONDER (saml-bindings-1.1 section 3.1, the SOAP binding).
//
// The back channel, and the one endpoint here a BROWSER never touches: the
// relying party calls it directly, server to server. For the artifact profile
// that is the whole point — the assertion never passes through the browser at
// all — and for the three query types it is SAML 1.1's attribute authority,
// which is the half of this protocol Shibboleth deployments leaned on hardest.
// See decision 4 for why all four request types are answered where the 2.0
// module answers one.
//
// It is not authenticated, and on a service that authenticates nobody that is
// the ordinary state of affairs rather than a decision about this endpoint. What
// stands in for authentication on the artifact path is the AssertionHandle,
// which is twenty random bytes, and the one-shot rule.
//
// **A QUERY, THOUGH, HAS NO SUCH THING**, and that is worth saying out loud
// rather than leaving inside the sentence above: anybody who can reach this port
// can ask this responder for an assertion about anybody, by name, with no
// credential. A real attribute authority authenticates the caller with mutual
// TLS and consults a policy. This one is the same turnstile-free mock the rest of
// the service is, and the log says so on every query.
// ---------------------------------------------------------------------------
function soapEnvelope(inner) {
  return '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="' + NS_SOAP + '"><soap:Body>' + inner +
    '</soap:Body></soap:Envelope>';
}

// A subject's username out of a query's <saml:Subject>. Both spellings are read
// — a NameIdentifier is what the schema says and is what everything sends — and
// the text is trimmed because a pretty-printed query puts a newline inside the
// element.
function subjectOf(el) {
  const nameId = el ? firstByLocal(el, 'NameIdentifier') : null;
  return nameId ? (nameId.textContent || '').trim() : '';
}

function respond(req, res) {
  log.debug("Entering respond().");
  const base = baseUrlOf(req);
  const scoped = relyingPartyFromSegment(req.params.rp);
  const raw = typeof req.body === 'string' ? req.body : '';
  logArtifact('SAML 1.1 Request', 'as received over SOAP', raw);

  const answer = function (status, message, assertion, inResponseTo, recipient) {
    const response = buildResponse({
      status: status, statusMessage: message, assertion: assertion || '',
      inResponseTo: inResponseTo, recipient: recipient
    });
    const envelope = soapEnvelope(response.xml);
    logArtifact('SAML 1.1 Response', 'as returned over SOAP', envelope);
    // 200 whatever the status: a SOAP fault is an HTTP-layer failure and this is
    // a SAML-layer refusal, and collapsing the two makes a relying party's
    // client throw a transport error where it should be reading a status code.
    res.status(200).type('text/xml; charset=utf-8').set('Cache-Control', 'no-store')
       .send(envelope);
  };

  let doc = null;
  try {
    doc = new DOMParser().parseFromString(raw, 'text/xml');
  } catch (e) {
    // Kept as a SAML status rather than thrown, for the reason above.
    log.error('saml11: the request body is not XML: ' + e.message);
    log.debug("Leaving respond(). Unparseable.");
    return answer(STATUS_REQUESTER, 'the request body is not XML: ' + e.message, '', '', '');
  }
  const request = firstByLocal(doc, 'Request');
  if (!request) {
    log.debug("Leaving respond(). No samlp:Request.");
    return answer(STATUS_REQUESTER, 'there is no <samlp:Request> in the SOAP body. This endpoint ' +
                  'speaks the SAML 1.1 SOAP binding (saml-bindings-1.1 section 3.1) and nothing ' +
                  'else. A SAML 2.0 <samlp:ArtifactResolve> goes to /saml2/ars.', '', '', '');
  }
  const requestId = request.getAttribute('RequestID') || '';

  // --- an artifact ---------------------------------------------------------
  const artifactEl = firstByLocal(request, 'AssertionArtifact');
  if (artifactEl) {
    const artifact = (artifactEl.textContent || '').trim();
    const held = artifacts.get(artifact);
    if (!held) {
      // The one refusal here worth making loudly, because it is the same answer
      // for three different mistakes and a relying party cannot tell them apart
      // from the status code alone: an artifact that was never minted here, one
      // that has expired, and — the interesting one — one that has ALREADY BEEN
      // RESOLVED.
      log.warn('saml11: artifact ' + String(artifact).slice(0, 12) + '… does not resolve. It was ' +
               'never minted here, or it has expired (saml11.artifactTtlS), or it has already ' +
               'been resolved once — which destroys it, because saml-bindings-1.1 section 3.2.3 ' +
               'says an artifact is resolvable exactly once.');
      log.debug("Leaving respond(). Unknown artifact.");
      return answer(STATUS_REQUESTER,
                    'that artifact does not resolve: it was never issued here, it has expired, or ' +
                    'it has already been resolved — an artifact is one-shot (section 3.2.3).',
                    '', requestId, '');
    }
    // ONE-SHOT. Deleted BEFORE the answer is built rather than after it is sent,
    // so that two requests arriving together cannot both find it.
    artifacts.delete(artifact);
    log.debug("Leaving respond(). An artifact was resolved and destroyed.");
    // Decision 3: the Response is built HERE, so it carries InResponseTo naming
    // this SOAP request and a Recipient naming whoever asked.
    return answer(STATUS_SUCCESS, '', held.assertion, requestId, scoped.id || held.rpId);
  }

  // --- an assertion by id --------------------------------------------------
  const referenceEl = firstByLocal(request, 'AssertionIDReference');
  if (referenceEl) {
    const wanted = (referenceEl.textContent || '').trim();
    const assertion = assertionsById.get(wanted);
    if (!assertion) {
      log.debug("Leaving respond(). No such AssertionID.");
      return answer(STATUS_REQUESTER, 'no assertion with AssertionID "' + wanted + '" is held ' +
                    'here. This service keeps the last ' + ASSERTION_CACHE_MAX + ' it issued, in ' +
                    'memory, and everything is gone on restart.', '', requestId, '');
    }
    // NOT one-shot, unlike an artifact — see the note on assertionsById. A
    // reference is not a credential; whoever holds it holds the assertion
    // already.
    log.debug("Leaving respond(). An assertion was returned by reference.");
    return answer(STATUS_SUCCESS, '', assertion, requestId, scoped.id);
  }

  // --- a query -------------------------------------------------------------
  const attributeQuery = firstByLocal(request, 'AttributeQuery');
  const authnQuery = firstByLocal(request, 'AuthenticationQuery');
  const query = attributeQuery || authnQuery;
  if (query) {
    const username = subjectOf(query);
    if (!username) {
      log.debug("Leaving respond(). The query names no subject.");
      return answer(STATUS_REQUESTER, 'the query carries no <saml:Subject> with a ' +
                    '<saml:NameIdentifier> in it, so there is nobody to answer about.',
                    '', requestId, '');
    }
    // The `Resource` attribute is the relying party the query is on behalf of,
    // and it is the only thing in a SAML 1.1 query that names one. Falling back
    // to the path segment keeps a scoped responder's audience right.
    const resource = attributeQuery ? (attributeQuery.getAttribute('Resource') || '') : '';
    const rpId = resource || scoped.id || '';
    const providerId = providerIdFor(rpId);
    const user = userFor(username);
    // **NO CREDENTIAL WAS CHECKED TO GET HERE**, and this is the line that says
    // so. A real attribute authority authenticates the caller over mutual TLS
    // and applies an attribute release policy; this one answers anybody about
    // anybody, which is what makes it useful for exercising a relying party and
    // is why it must never be pointed at anything real.
    log.info('saml11: answering an ' + (attributeQuery ? 'AttributeQuery' : 'AuthenticationQuery') +
             ' about "' + username + '" for "' + (rpId || '(nobody named)') + '" with no ' +
             'credential presented and no attribute release policy applied. That is what this ' +
             'mock is for; it is not what an attribute authority does.');
    const now = iso(0);
    const how = { method: AM_PASSWORD };
    // An AuthenticationQuery asks about an authentication that HAPPENED, and
    // this service has no record of one for somebody who never signed in here.
    // It answers with what it can say honestly — the method it would have used,
    // at the instant of the query — and the log above has already said the
    // subject was not verified. A relying party that treats an
    // AuthenticationQuery answer as proof of a sign-on is exercising exactly the
    // assumption a mock should break.
    const assertion = buildSaml11Assertion({
      subject: username,
      audience: rpId,
      lifetimeMin: Number(config.value('saml11.assertionLifetimeMin')) || 60,
      authnMethod: how.method,
      authnInstant: now,
      issuer: providerId,
      nameQualifier: providerId,
      // A query's answer is confirmed by neither browser profile: it did not
      // travel through a browser and it is not an artifact. The bearer method is
      // the honest one — whoever holds it, holds it.
      confirmationMethod: CONFIRMATION_BEARER,
      // An AuthenticationQuery asks for the AuthenticationStatement alone, and
      // the builder always writes one; an AttributeQuery asks for attributes,
      // which is what the second statement carries. Passing none for the
      // authentication query is what leaves the attribute statement out.
      attributes: attributeQuery ? attributesFor(user, how.method, now) : [],
      sign: config.value('saml11.signAssertion')
    });
    rememberAssertion(assertion);
    log.debug("Leaving respond(). A query was answered about " + username + ".");
    return answer(STATUS_SUCCESS, '', assertion, requestId, rpId);
  }

  log.debug("Leaving respond(). The request asked for nothing this responder has.");
  return answer(STATUS_REQUESTER,
                'this <samlp:Request> carries none of the four things this responder answers: ' +
                '<samlp:AssertionArtifact>, <samlp:AssertionIDReference>, ' +
                '<samlp:AttributeQuery> or <samlp:AuthenticationQuery>. An AuthorizationDecision' +
                'Query is the fifth SAML 1.1 request type and this service does not make ' +
                'authorization decisions.', '', requestId, '');
}

// Resolve an artifact IN PROCESS, for the mock relying party below. It is a
// function call rather than an HTTP request to this service's own responder, and
// that is deliberate: a server calling itself over TCP works until somebody puts
// this behind a proxy that terminates TLS, and then the mock relying party fails
// in a way that has nothing to do with SAML. The one-shot rule is applied here
// exactly as it is on the wire, because the mock relying party is meant to
// exercise the same behaviour a real one would meet.
function resolveForMockRp(artifact) {
  log.debug("Entering resolveForMockRp().");
  const held = artifacts.get(artifact);
  if (!held) {
    log.debug("Leaving resolveForMockRp(). Nothing to resolve.");
    return null;
  }
  artifacts.delete(artifact);
  log.debug("Leaving resolveForMockRp(). Resolved and destroyed.");
  return held;
}

// ---------------------------------------------------------------------------
// THE METADATA — decision 5. A SAML 2.0 metadata document describing a SAML 1.1
// identity provider, which is what every SAML 1.1 relying party actually
// consumes.
//
// SIGNED, with ds:Signature FIRST inside EntityDescriptor, which the metadata
// schema requires — and which is NOT where this profile's own Response puts it
// even though both are 'prepend'. They agree by coincidence rather than by rule,
// and the rule is in each schema separately.
// ---------------------------------------------------------------------------
function metadataFor(base, rpId) {
  log.debug("Entering metadataFor(). rp=" + (rpId || '(unscoped)'));
  const id = genId();
  const providerId = providerIdFor(rpId);
  const where = endpointsFor(base, rpId);
  const keyDescriptor = function (use) {
    return '<md:KeyDescriptor use="' + use + '"><ds:KeyInfo xmlns:ds="' + NS_DS + '">' +
      '<ds:X509Data><ds:X509Certificate>' + STS.certB64 +
      '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>';
  };
  const service = function (element, binding, location, extra) {
    return '<md:' + element + ' Binding="' + binding + '" Location="' + xmlEscape(location) + '"' +
      (extra || '') + '/>';
  };
  const xml =
    '<?xml version="1.0" encoding="UTF-8"?>' +
    '<md:EntityDescriptor xmlns:md="' + NS_MD + '" ID="' + id + '"' +
      ' entityID="' + xmlEscape(providerId) + '">' +
      // TWO descriptors, and this is the shape of the document that matters. An
      // IDPSSODescriptor describes the browser profiles; an
      // AttributeAuthorityDescriptor describes the responder's query half
      // (decision 4). A Shibboleth service provider reads the second one to find
      // its attribute authority and will not look for it inside the first —
      // which is why the responder's address appears twice, once as an
      // ArtifactResolutionService and once as an AttributeService.
      '<md:IDPSSODescriptor' +
        ' WantAuthnRequestsSigned="false"' +
        ' protocolSupportEnumeration="' + PROTOCOL_SAML11 + '">' +
        keyDescriptor('signing') +
        // The metadata schema's sequence: ArtifactResolutionService, then
        // SingleLogoutService, then NameIDFormat, then SingleSignOnService. There
        // is no SingleLogoutService here at all — SAML 1.1 has no Single Logout,
        // which is stated in issueSignIn() rather than implied by this absence.
        service('ArtifactResolutionService', BINDING_SOAP, where.responder,
                ' index="0" isDefault="true"') +
        NAMEID_FORMATS.map(function (format) {
          return '<md:NameIDFormat>' + format + '</md:NameIDFormat>';
        }).join('') +
        // The two browser profiles, named by their PROFILE URIs. In a SAML 1.1
        // descriptor the Binding attribute carries a profile identifier rather
        // than a binding one, which reads wrong and is what Shibboleth's own
        // metadata does — the 1.1 profiles bundle their binding into the profile.
        service('SingleSignOnService', PROFILE_POST, where.sso) +
        service('SingleSignOnService', PROFILE_ARTIFACT, where.sso) +
        // Shibboleth's request profile — decision 1. Advertised so a service
        // provider that builds its endpoint list from this document can send the
        // one request SAML 1.1 deployments actually use.
        service('SingleSignOnService', PROFILE_SHIB_AUTHN_REQUEST, where.sso) +
      '</md:IDPSSODescriptor>' +
      '<md:AttributeAuthorityDescriptor' +
        ' protocolSupportEnumeration="' + PROTOCOL_SAML11 + '">' +
        keyDescriptor('signing') +
        service('AttributeService', BINDING_SOAP, where.responder) +
        NAMEID_FORMATS.map(function (format) {
          return '<md:NameIDFormat>' + format + '</md:NameIDFormat>';
        }).join('') +
      '</md:AttributeAuthorityDescriptor>' +
      '<md:Organization>' +
        '<md:OrganizationName xml:lang="en">mock-sts</md:OrganizationName>' +
        '<md:OrganizationDisplayName xml:lang="en">Mock security token service' +
        '</md:OrganizationDisplayName>' +
        '<md:OrganizationURL xml:lang="en">' + xmlEscape(base) + '/</md:OrganizationURL>' +
      '</md:Organization>' +
    '</md:EntityDescriptor>';
  logArtifact('SAML 1.1 IdP metadata', 'before signing', xml);
  try {
    const signed = signDocument(xml, 'EntityDescriptor', id, 'prepend');
    logArtifact('SAML 1.1 IdP metadata', 'after signing', signed);
    log.debug("Leaving metadataFor(). Signed.");
    return signed;
  } catch (e) {
    log.error('the SAML 1.1 metadata could not be signed, serving it unsigned: ' + e.message);
    log.debug("Leaving metadataFor(). Unsigned.");
    return xml;
  }
}

function serveMetadata(req, res) {
  log.debug("Entering the SAML 1.1 metadata endpoint.");
  const base = baseUrlOf(req);
  const scoped = relyingPartyFromSegment(req.params.rp);
  if (scoped.id) {
    // THE ASK IS WHAT REGISTERS IT. `counts: false` because fetching a metadata
    // document is not an authentication and is not even a request from that
    // relying party — it is somebody configuring one.
    recordRelyingParty({
      identifier: scoped.id,
      kind: RP_KIND,
      protocol: 'SAML 1.1',
      counts: false,
      note: scoped.known
        ? 'its SAML 1.1 identity provider metadata was fetched'
        : 'first seen when its SAML 1.1 identity provider metadata was asked for',
      fields: { samlEntityId: scoped.id }
    });
  }
  // no-store like every other document here that carries the signing key: the
  // key is regenerated on every start, so a cached copy describes a key that is
  // gone and the failure looks like a broken signature rather than a stale
  // document.
  res.status(200).type('application/samlmetadata+xml').set('Cache-Control', 'no-store')
     .send(metadataFor(base, scoped.id));
  log.debug("Leaving the SAML 1.1 metadata endpoint. rp=" + (scoped.id || '(unscoped)'));
}

// ---------------------------------------------------------------------------
// THE PAGES A PERSON REACHES BY CLICKING.
// ---------------------------------------------------------------------------
function describeSsoPage(base, scoped) {
  log.debug("Entering describeSsoPage().");
  const where = endpointsFor(base, scoped.id);
  return '<h1>SAML 1.1 — inter-site transfer service</h1>' +
    '<p class="sub">Identity provider <code>' + xmlEscape(providerIdFor(scoped.id)) +
    '</code> at <code>' + xmlEscape(where.sso) + '</code></p>' +
    '<p><strong>SAML 1.1 has no request message.</strong> There is no ' +
    '<code>&lt;AuthnRequest&gt;</code> in this version of the protocol: a flow starts when a ' +
    'browser arrives here carrying a <code>TARGET</code>, and this service answers with a ' +
    '<code>&lt;samlp:Response&gt;</code> the relying party never asked for. That single fact is ' +
    'what most of the differences from <a href="/saml2">the SAML 2.0 profile</a> come out of, ' +
    'including why an error here is this page rather than a Response.</p>' +
    '<h2>Try it</h2><ul>' +
    '<li><a href="' + RP_PATH + '">' + RP_PATH + '</a> — a mock relying party here that starts ' +
    'both browser profiles and then verifies what comes back check by check.</li>' +
    '<li><a href="' + xmlEscape(where.metadata) + '">' + xmlEscape(where.metadata) + '</a> — the ' +
    'signed identity provider metadata, which is what a relying party should be configured ' +
    'from.</li></ul>' +
    '<h2>What it reads</h2><table><thead><tr><th>Parameter</th><th>What this service does with it</th>' +
    '</tr></thead><tbody>' +
    [['TARGET', 'The resource at the relying party the person wants to reach. It is echoed back ' +
                'beside the response byte for byte and never interpreted — SAML 1.1\'s ' +
                'RelayState. With no providerId and no path segment, its ORIGIN is also what ' +
                'the audience of the assertion is guessed from.'],
     ['shire', 'Where the assertion is delivered. Shibboleth\'s name for the assertion consumer ' +
               'service, and the only thing in this protocol that carries one. Not validated ' +
               'against any registration, like every other return URL here. With none, the ' +
               'response goes to this service\'s own mock relying party at ' + RP_PATH + '.'],
     ['providerId', 'Who the assertion is FOR — the audience restriction. Shibboleth\'s ' +
                    'parameter, and the only way a SAML 1.1 relying party can name itself.'],
     ['time', 'Read and logged. Shibboleth sends it; nothing here enforces it, because there is ' +
              'no clock skew setting for this profile to reject a request under.'],
     ['profile', '<strong>Non-spec.</strong> <code>post</code> or <code>artifact</code>, ' +
                 'choosing between the two browser profiles. Nothing in SAML 1.1 lets a relying ' +
                 'party choose, so without it the saml11.defaultProfile setting decides.'],
     ['format', '<strong>Non-spec.</strong> The NameIdentifier Format to answer with. SAML 1.1 ' +
                'has no NameIDPolicy to ask in, so without it saml11.nameIdFormat decides.']
    ].map(function (r) {
      return '<tr><td><code>' + r[0] + '</code></td><td>' + r[1] + '</td></tr>';
    }).join('') + '</tbody></table>' +
    '<h2>The two profiles</h2>' +
    '<p><strong>Browser/POST</strong> (section 4.2) puts the whole signed assertion in a ' +
    'self-submitting form. <strong>Browser/Artifact</strong> (section 4.1) sends a 42-byte ' +
    'reference on a redirect and the relying party fetches the assertion from the SAML responder ' +
    'at <code>' + xmlEscape(where.responder) + '</code> over SOAP — so the assertion never passes ' +
    'through the browser. The assertion says which of the two happened, in its ' +
    '<code>&lt;ConfirmationMethod&gt;</code>, and the two values are not interchangeable.</p>' +
    '<div class="meta"><div>Not implemented, and stated rather than left to be discovered: ' +
    'SAML 1.1 has NO SINGLE LOGOUT — that arrived with SAML 2.0 — so there is no ' +
    'SingleLogoutService here and no way to recall an assertion. No assertion is encrypted. ' +
    'The fifth SAML 1.1 request type, AuthorizationDecisionQuery, is refused by name: this ' +
    'service makes no authorization decisions.</div></div>';
}

function describeProfilePage(base) {
  log.debug("Entering describeProfilePage().");
  const where = endpointsFor(base, '');
  return '<h1>SAML 1.1</h1>' +
    '<p class="sub">The two browser profiles, and the SAML responder behind one of them</p>' +
    '<p>This service issues SAML 1.1 assertions through three doors, and this is the newest of ' +
    'them: the <strong>browser profiles</strong>, where a person signs in and an assertion ' +
    'reaches a relying party. The other two are <a href="/wsfed">WS-Federation</a>, which wraps ' +
    'the same assertion in a <code>wresult</code>, and <a href="/sts">WS-Trust</a>, which returns ' +
    'one in an <code>RSTR</code>. All three call one builder, so an attribute configured on ' +
    '<code>/admin/saml-attributes</code> appears in all three.</p>' +
    '<h2>The endpoints</h2><table><thead><tr><th>Endpoint</th><th>What it is</th></tr></thead>' +
    '<tbody>' +
    '<tr><td><a href="' + SSO_PATH + '">' + SSO_PATH + '</a></td><td>the inter-site transfer ' +
    'service — SAML 1.1\'s name for what SAML 2.0 calls the Single Sign-On service</td></tr>' +
    '<tr><td><code>' + RESPONDER_PATH + '</code></td><td>the SAML responder, over SOAP. Resolves ' +
    'artifacts, returns assertions by AssertionID, and answers AttributeQuery and ' +
    'AuthenticationQuery — the attribute authority half of SAML 1.1</td></tr>' +
    '<tr><td><a href="' + METADATA_PATH + '">' + METADATA_PATH + '</a></td><td>signed metadata. ' +
    'A SAML 2.0 metadata document describing a SAML 1.1 identity provider, which is what every ' +
    'relying party actually consumes</td></tr>' +
    '<tr><td><a href="' + RP_PATH + '">' + RP_PATH + '</a></td><td>a mock relying party, to ' +
    'exercise both profiles and see the checks</td></tr>' +
    '</tbody></table>' +
    '<h2>What makes it different from SAML 2.0</h2><ul>' +
    '<li><strong>No request message.</strong> No AuthnRequest, so the relying party never ' +
    'identifies itself, never asks for a binding, a NameID format or an authentication context, ' +
    'and never receives an error — there is nothing to answer.</li>' +
    '<li><strong>No Single Logout.</strong> It arrived with SAML 2.0.</li>' +
    '<li><strong>Different spellings throughout.</strong> <code>AssertionID</code> not ' +
    '<code>ID</code>, an <code>Issuer</code> attribute not an element, a status code that is a ' +
    'QName not a URI, <code>AudienceRestrictionCondition</code> not ' +
    '<code>AudienceRestriction</code>, and a signature that goes LAST in an assertion and FIRST ' +
    'in a response.</li>' +
    '<li><strong>A 42-byte artifact</strong>, type 0x0001, where SAML 2.0\'s is 44 bytes and ' +
    'type 0x0004.</li></ul>' +
    '<div class="row"><a href="' + RP_PATH + '"><button>Try it at the mock relying party</button></a> ' +
    '<a href="' + xmlEscape(where.metadata) + '"><button class="alt">The metadata</button></a></div>';
}

// ===========================================================================
// THE MOCK RELYING PARTY. NON-SPEC, and it earns its place for the two reasons
// /saml2/sp and /wsfed/rp do:
//
//   * it is the default assertion consumer, so a flow that names no destination
//     has somewhere real to go instead of nowhere;
//   * it makes the profile testable from one service. A Response POSTed into the
//     void could not be checked at all without standing up a second service, and
//     the checks below are the ones that catch the mistakes THIS profile makes —
//     a signature reference that will not resolve because AssertionID was not
//     named, a confirmation method that does not match the profile the assertion
//     arrived on, a status QName written as a URI, an audience naming a guessed
//     origin rather than the relying party.
// ===========================================================================
function verifySignature(xml, rootLocalName, idAttribute) {
  log.debug("Entering verifySignature(). root=" + rootLocalName + ", id=" + idAttribute);
  try {
    const doc = new DOMParser().parseFromString(xml, 'text/xml');
    const root = rootLocalName === 'Response'
      ? doc.documentElement
      : firstByLocal(doc.documentElement, 'Assertion');
    if (!root) {
      log.debug("Leaving verifySignature(). There is no " + rootLocalName + ".");
      return { ok: false, present: false, why: 'there is no <' + rootLocalName + '> to check' };
    }
    // A DIRECT child only. `firstByLocal` would find whichever Signature came
    // first in the document, which is not the same question — and getting it
    // wrong reports the assertion's signature twice and the response's never.
    let sigEl = null;
    for (let i = 0; i < root.childNodes.length; i++) {
      const child = root.childNodes[i];
      if (child.nodeType === 1 && child.localName === 'Signature') {
        sigEl = child;
        break;
      }
    }
    if (!sigEl) {
      log.debug("Leaving verifySignature(). It is not signed.");
      return { ok: false, present: false,
               why: 'the ' + rootLocalName + ' carries no ds:Signature' };
    }
    // **THE idAttribute IS THE WHOLE POINT OF THIS FUNCTION.** SAML 1.1 spells
    // its ids `AssertionID` and `ResponseID`, and xml-crypto resolves `#_abc`
    // against `Id`, `ID` and `id` only — so without this the reference resolves
    // to nothing and a perfectly good signature reports as broken. It is safe to
    // name them here for the reason `saml2_sso.js` records about NOT naming
    // `ID`: neither is already on xml-crypto's default list, so nothing is
    // duplicated onto it and the signature-wrapping guard is not tripped.
    const sig = new SignedXml({ publicCert: STS.certPem, idAttribute: idAttribute });
    sig.loadSignature(sigEl);
    const ok = sig.checkSignature(xml);
    log.debug("Leaving verifySignature(). ok=" + ok);
    return { ok: !!ok, present: true, why: ok ? '' : 'the signature did not verify' };
  } catch (e) {
    // xml-crypto throws rather than returning false for most failures, and the
    // message names which of them it was — an unresolvable reference reads quite
    // differently from a digest mismatch, and that distinction is the diagnosis.
    log.debug("Leaving verifySignature(). It threw: " + e.message);
    return { ok: false, present: true, why: e.message };
  }
}

// Every check, in the order a relying party would apply them, each with its own
// verdict. One boolean for the whole response would say "it failed" and nothing
// anybody could act on — the same argument /wsfed/rp, /saml2/sp and the OID4VP
// verifier all make.
function verifyResponse(xml, rpId, acsUrl, profile) {
  log.debug("Entering verifyResponse(). profile=" + profile);
  const checks = [];
  const add = function (name, ok, detail) { checks.push({ name: name, ok: !!ok, detail: detail }); };
  const result = { checks: checks, subject: '', attributes: [], status: '', assertionId: '' };

  let doc = null;
  try {
    doc = new DOMParser().parseFromString(xml, 'text/xml');
  } catch (e) {
    add('the response parses as XML', false, e.message);
    log.debug("Leaving verifyResponse(). Not XML.");
    return result;
  }
  const root = doc.documentElement;
  add('it is a samlp:Response', !!root && root.localName === 'Response',
      root ? '<' + root.localName + '> in ' + (root.namespaceURI || '(no namespace)')
           : 'nothing parsed');
  if (!root || root.localName !== 'Response') {
    log.debug("Leaving verifyResponse(). Not a Response.");
    return result;
  }

  add('it is MajorVersion 1, MinorVersion 1',
      root.getAttribute('MajorVersion') === '1' && root.getAttribute('MinorVersion') === '1',
      'MajorVersion=' + (root.getAttribute('MajorVersion') || '(none)') +
      ', MinorVersion=' + (root.getAttribute('MinorVersion') || '(none)') +
      ' — SAML 1.1 carries its version in two attributes, where 2.0 has Version="2.0"');

  const statusEl = firstByLocal(root, 'StatusCode');
  const status = statusEl ? (statusEl.getAttribute('Value') || '') : '';
  result.status = status;
  const statusMessage = textByLocal(root, 'StatusMessage');
  // The QName check, which is the one a 2.0-shaped implementation fails: the
  // status is `samlp:Success`, a qualified name, and NOT the URI
  // `urn:oasis:names:tc:SAML:2.0:status:Success`.
  add('the status is samlp:Success', status === STATUS_SUCCESS,
      (status || '(no StatusCode)') + (statusMessage ? ' — ' + statusMessage : '') +
      (status && status.indexOf('urn:') === 0
        ? ' — that is a URI, and a SAML 1.1 status code is a QName' : ''));

  // Recipient, which section 4.2.1.4 requires of a Browser/POST response and
  // which is what stops it being replayed at another relying party. The artifact
  // profile's Response is built at the responder and names the SOAP caller
  // instead, so the expectation differs by profile.
  const recipient = root.getAttribute('Recipient') || '';
  if (profile === 'post') {
    add('Recipient names this assertion consumer', recipient === acsUrl,
        recipient || '(none)');
    // InResponseTo MUST be absent: there was no request. A Response that carries
    // one names a RequestID nobody minted, and it is the single most common
    // thing to get wrong by porting SAML 2.0 code.
    add('InResponseTo is absent', !root.getAttribute('InResponseTo'),
        root.getAttribute('InResponseTo')
          ? 'it is "' + root.getAttribute('InResponseTo') + '", and there was no request to be ' +
            'in response to — SAML 1.1 browser profiles are unsolicited'
          : 'correct — the browser profiles have no request message');
  } else {
    add('InResponseTo names the SOAP request', !!root.getAttribute('InResponseTo'),
        root.getAttribute('InResponseTo') ||
        '(none) — the artifact was resolved by a <samlp:Request>, so the Response should name it');
  }

  const responseSig = verifySignature(xml, 'Response', 'ResponseID');
  add('the Response signature verifies', responseSig.ok,
      responseSig.present
        ? (responseSig.ok ? 'RSA-SHA256, and the reference resolved through ResponseID'
                          : responseSig.why)
        : 'unsigned — saml11.signResponse is off, which is a supported state and not a failure ' +
          'of the relying party');

  const assertion = firstByLocal(root, 'Assertion');
  add('it contains an assertion', !!assertion,
      assertion ? 'in ' + assertion.namespaceURI : 'no saml:Assertion — see the status above');
  if (!assertion) {
    log.debug("Leaving verifyResponse(). No assertion.");
    return result;
  }
  result.assertionId = assertion.getAttribute('AssertionID') || '';

  add('the assertion is identified by AssertionID', !!result.assertionId,
      result.assertionId ||
      '(none) — SAML 1.1 spells it AssertionID, not ID, and a signature reference cannot resolve ' +
      'without it');

  const assertionSig = verifySignature(xml, 'Assertion', 'AssertionID');
  add('the assertion signature verifies', assertionSig.ok,
      assertionSig.present
        ? (assertionSig.ok ? 'resolved through the AssertionID attribute — xml-crypto has to be ' +
                             'told that name, or a good signature reports as broken'
                           : assertionSig.why)
        : 'unsigned — saml11.signAssertion is off');

  // The Issuer is an ATTRIBUTE in SAML 1.1, not a child element. Reading it with
  // textByLocal(), which is what a 2.0-shaped verifier would do, finds nothing.
  const issuer = assertion.getAttribute('Issuer') || '';
  add('the issuer is this identity provider', issuer === providerIdFor(rpId),
      (issuer || '(none)') +
      (issuer === providerIdFor(rpId) ? ' — read from the Issuer ATTRIBUTE, which is where SAML ' +
                                        '1.1 puts it'
                                      : ', expected ' + providerIdFor(rpId)));

  const conditions = firstByLocal(assertion, 'Conditions');
  const audience = conditions ? textByLocal(conditions, 'Audience') : '';
  add('the audience is this relying party', audience === rpId,
      'audience ' + (audience || '(none)') + ', expected ' + rpId +
      (audience && audience !== rpId
        ? ' — if this names an origin rather than an identifier, the relying party was GUESSED ' +
          'from the TARGET because nothing sent providerId'
        : ''));

  const notBefore = conditions ? conditions.getAttribute('NotBefore') : '';
  const notOnOrAfter = conditions ? conditions.getAttribute('NotOnOrAfter') : '';
  const now = Date.now();
  add('it is inside its validity window',
      !!notBefore && !!notOnOrAfter && Date.parse(notBefore) <= now && now < Date.parse(notOnOrAfter),
      (notBefore || '(no NotBefore)') + ' to ' + (notOnOrAfter || '(no NotOnOrAfter)'));

  // DECISION 2, checked. This is the assertion's own statement of how it reached
  // here, and the two profiles require different values.
  const method = textByLocal(assertion, 'ConfirmationMethod');
  const expected = profile === 'artifact' ? CONFIRMATION_ARTIFACT : CONFIRMATION_BEARER;
  add('the confirmation method matches the profile', method === expected,
      (method || '(none)') + ', expected ' + expected +
      ' — section ' + (profile === 'artifact' ? '4.1.1.4' : '4.2.1.4') + ' requires it, and the ' +
      'two are not interchangeable: an artifact-profile assertion confirmed as bearer claims to ' +
      'have travelled through the browser when it did not');

  // The single-use policy, which Browser/POST carries and the artifact profile
  // does not: the assertion passed through the browser, so the relying party is
  // told not to keep it.
  const doNotCache = !!firstByLocal(assertion, 'DoNotCacheCondition');
  add('the single-use policy matches the profile', doNotCache === (profile === 'post'),
      doNotCache
        ? 'a <DoNotCacheCondition> is present'
        : 'no <DoNotCacheCondition> — correct for the artifact profile, where the assertion never ' +
          'passed through the browser');

  const statement = firstByLocal(assertion, 'AuthenticationStatement');
  add('there is an authentication statement', !!statement,
      statement
        ? 'AuthenticationMethod=' + (statement.getAttribute('AuthenticationMethod') || '(none)') +
          ', AuthenticationInstant=' + (statement.getAttribute('AuthenticationInstant') || '(none)')
        : 'none — the assertion says nothing about anybody having authenticated');

  const nameId = firstByLocal(assertion, 'NameIdentifier');
  result.subject = nameId ? (nameId.textContent || '').trim() : '';
  add('it names a subject', !!result.subject,
      result.subject
        ? result.subject + ' (Format=' + (nameId.getAttribute('Format') || '(none)') +
          ', NameQualifier=' + (nameId.getAttribute('NameQualifier') || '(none)') + ')'
        : 'no <saml:NameIdentifier>');

  const attributeEls = assertion.getElementsByTagNameNS('*', 'Attribute');
  for (let i = 0; i < attributeEls.length; i++) {
    const a = attributeEls[i];
    const values = a.getElementsByTagNameNS('*', 'AttributeValue');
    const list = [];
    for (let j = 0; j < values.length; j++) {
      list.push((values[j].textContent || '').trim());
    }
    result.attributes.push({
      // BOTH halves, because that is what a SAML 1.1 attribute is: a relying
      // party re-joins them into a claim URI, and showing only the name would
      // hide the half that distinguishes two attributes called `name`.
      namespace: a.getAttribute('AttributeNamespace') || '',
      name: a.getAttribute('AttributeName') || '',
      values: list
    });
  }
  add('it carries attributes', result.attributes.length > 0,
      result.attributes.length + ' <saml:Attribute> element(s), each an AttributeName and an ' +
      'AttributeNamespace — the two halves SAML 2.0 joins into one Name');

  result.ok = checks.every(function (c) { return c.ok; });
  log.debug("Leaving verifyResponse(). " + checks.filter(function (c) { return c.ok; }).length +
            "/" + checks.length + " checks passed.");
  return result;
}

function verificationTable(result) {
  return '<table><thead><tr><th>Check</th><th></th><th>What was seen</th></tr></thead><tbody>' +
    result.checks.map(function (c) {
      return '<tr><td>' + xmlEscape(c.name) + '</td>' +
        '<td class="' + (c.ok ? 'ok' : 'bad') + '">' + (c.ok ? 'yes' : 'no') + '</td>' +
        '<td>' + c.detail + '</td></tr>';
    }).join('') + '</tbody></table>';
}

function attributeTable(attributes) {
  if (!attributes.length) {
    return '';
  }
  return '<h2>Attributes</h2><table><thead><tr><th>AttributeNamespace</th><th>AttributeName</th>' +
    '<th>Value(s)</th></tr></thead><tbody>' +
    attributes.map(function (a) {
      return '<tr><td><code>' + xmlEscape(a.namespace) + '</code></td>' +
        '<td><code>' + xmlEscape(a.name) + '</code></td>' +
        '<td>' + a.values.map(function (v) { return xmlEscape(v); }).join('<br>') + '</td></tr>';
    }).join('') + '</tbody></table>';
}

function mockRpStartPage(base) {
  log.debug("Entering mockRpStartPage().");
  const rpId = base + RP_PATH;
  const start = function (profile) {
    return SSO_PATH + '?providerId=' + encodeURIComponent(rpId) +
      '&shire=' + encodeURIComponent(base + RP_PATH) +
      '&TARGET=' + encodeURIComponent(base + RP_PATH + '?done=1') +
      '&profile=' + profile;
  };
  return '<h1>SAML 1.1 — mock relying party</h1>' +
    '<p class="sub">A service provider that lives here, so the profile can be exercised without ' +
    'standing up a second one</p>' +
    '<p>This page starts a real flow at the inter-site transfer service and then verifies what ' +
    'comes back, check by check. It identifies itself as <code>' + xmlEscape(rpId) + '</code> ' +
    'with Shibboleth\'s <code>providerId</code> parameter, which is the only way a SAML 1.1 ' +
    'relying party can name itself — see <a href="' + SSO_PATH + '">the endpoint\'s own ' +
    'page</a>.</p>' +
    '<div class="row">' +
    '<a href="' + start('post') + '"><button>Browser/POST</button></a>' +
    '<a href="' + start('artifact') + '"><button class="alt">Browser/Artifact</button></a>' +
    '</div>' +
    '<div class="meta">' +
    '<div><strong>Browser/POST</strong> (section 4.2): the whole signed assertion arrives here in ' +
    'a self-submitting form. Watch the intermediate page — it carries a real button, because ' +
    'this service sets <code>script-src \'none\'</code> everywhere and the auto-submit is one ' +
    'named script.</div>' +
    '<div><strong>Browser/Artifact</strong> (section 4.1): a 42-byte reference arrives on a ' +
    'redirect and this page fetches the assertion from the SAML responder over SOAP. The ' +
    'assertion never passes through the browser, and the artifact is destroyed by being ' +
    'resolved — reload the result page and the second attempt is refused.</div>' +
    '</div>';
}

// The mock relying party's assertion consumer. THREE things can arrive here and
// they are told apart by what they carry: a form POST with `SAMLResponse` is the
// Browser/POST profile, a GET with `SAMLart` is the Browser/Artifact profile, and
// anything else is somebody who clicked the link.
function mockRelyingParty(req, res) {
  log.debug("Entering mockRelyingParty(). method=" + req.method);
  const base = baseUrlOf(req);
  const params = paramsOf(req);
  const rpId = base + RP_PATH;
  const acsUrl = base + RP_PATH;

  if (params.SAMLResponse) {
    const xml = Buffer.from(String(params.SAMLResponse), 'base64').toString('utf8');
    logArtifact('SAML 1.1 Response', 'as received on the Browser/POST profile', xml);
    const result = verifyResponse(xml, rpId, acsUrl, 'post');
    const inner = '<h1>SAML 1.1 — Browser/POST</h1>' +
      '<p class="sub">' + result.checks.filter(function (c) { return c.ok; }).length + ' of ' +
      result.checks.length + ' checks passed</p>' +
      (result.subject
        ? '<p>Signed in as <strong>' + xmlEscape(result.subject) + '</strong>.</p>'
        : '<p class="bad">No subject was found in the response.</p>') +
      '<p>TARGET came back as <code>' + xmlEscape(String(params.TARGET || '(none)')) +
      '</code> — the relying party\'s own state, echoed byte for byte.</p>' +
      verificationTable(result) +
      attributeTable(result.attributes) +
      '<h2>The response</h2><pre>' + xmlEscape(xml) + '</pre>' +
      '<div class="row"><a href="' + RP_PATH + '"><button class="alt">Again</button></a></div>';
    sendPage(res, 200, 'SAML 1.1 — Browser/POST', inner);
    log.debug("Leaving mockRelyingParty(). A POST-profile response was verified.");
    return;
  }

  if (params.SAMLart) {
    const artifact = String(params.SAMLart);
    // Resolved in process — see resolveForMockRp(). The one-shot rule applies
    // here exactly as it does on the wire, which is what makes reloading this
    // page a demonstration rather than a bug.
    const held = resolveForMockRp(artifact);
    if (!held) {
      const inner = '<h1>SAML 1.1 — Browser/Artifact</h1>' +
        '<div class="err">That artifact did not resolve: it was never issued here, it has ' +
        'expired, or — most likely if you just reloaded this page — it has ALREADY BEEN ' +
        'RESOLVED. An artifact is one-shot (saml-bindings-1.1 section 3.2.3), and resolving it ' +
        'destroys it.</div>' +
        '<p>That is the behaviour worth seeing: a relying party that retries a resolution, or ' +
        'that resolves the same artifact on two workers, gets exactly this and nothing in the ' +
        'happy path would have shown it.</p>' +
        '<div class="row"><a href="' + RP_PATH + '"><button>Start again</button></a></div>';
      sendPage(res, 400, 'SAML 1.1 — the artifact was spent', inner);
      log.debug("Leaving mockRelyingParty(). The artifact did not resolve.");
      return;
    }
    // Decision 3: the Response is built HERE, around the assertion, the way the
    // responder builds it for a SOAP caller — carrying InResponseTo naming the
    // request this mock would have sent.
    const requestId = genId();
    const response = buildResponse({
      status: STATUS_SUCCESS, assertion: held.assertion,
      inResponseTo: requestId, recipient: rpId
    });
    logArtifact('SAML 1.1 Response', 'as resolved from an artifact over SOAP', response.xml);
    const result = verifyResponse(response.xml, rpId, acsUrl, 'artifact');
    const inner = '<h1>SAML 1.1 — Browser/Artifact</h1>' +
      '<p class="sub">' + result.checks.filter(function (c) { return c.ok; }).length + ' of ' +
      result.checks.length + ' checks passed</p>' +
      (result.subject
        ? '<p>Signed in as <strong>' + xmlEscape(result.subject) + '</strong>.</p>'
        : '<p class="bad">No subject was found in the assertion.</p>') +
      '<p>The artifact was <code>' + xmlEscape(artifact) + '</code> — 42 bytes, type 0x0001: a ' +
      'two-byte type code, a twenty-byte SourceID that is the SHA-1 of the identity provider\'s ' +
      'providerID, and a twenty-byte handle. <strong>The assertion never passed through this ' +
      'browser</strong>; it was fetched from the SAML responder.</p>' +
      '<p>TARGET came back as <code>' + xmlEscape(String(params.TARGET || '(none)')) + '</code>.</p>' +
      verificationTable(result) +
      attributeTable(result.attributes) +
      '<h2>The response the responder built</h2><pre>' + xmlEscape(response.xml) + '</pre>' +
      '<div class="row"><a href="' + RP_PATH + '"><button class="alt">Again</button></a>' +
      '<a href="' + req.originalUrl + '"><button class="alt">Reload — the artifact is ' +
      'spent</button></a></div>';
    sendPage(res, 200, 'SAML 1.1 — Browser/Artifact', inner);
    log.debug("Leaving mockRelyingParty(). An artifact-profile assertion was verified.");
    return;
  }

  sendPage(res, 200, 'SAML 1.1 — mock relying party', mockRpStartPage(base));
  log.debug("Leaving mockRelyingParty(). The start page.");
}

// ---------------------------------------------------------------------------
// THE ROUTES.
//
// Registered at require time, which is rule 1: this module's position in
// server.js IS its position in the route order and on /admin/sts-metadata. Every
// path has a scoped and an unscoped spelling, for the reason `saml2_sso.js`
// gives — the scoped one is what the per-relying-party metadata document tells a
// service provider to use.
// ---------------------------------------------------------------------------
app.get(BASE_PATH, function (req, res) {
  log.debug("Entering the SAML 1.1 landing page.");
  sendPage(res, 200, 'SAML 1.1', describeProfilePage(baseUrlOf(req)));
  log.debug("Leaving the SAML 1.1 landing page.");
});

app.get(METADATA_PATH, serveMetadata);
app.get(METADATA_PATH + '/:rp', serveMetadata);

app.get(SSO_PATH, interSiteTransfer);
app.get(SSO_PATH + '/:rp', interSiteTransfer);
// The POST spelling exists because somebody's relying party will post a form at
// this endpoint whatever the specification says, and answering that with a 405
// would be a worse mock than reading it. It needs no POST-to-GET dance — see the
// note above interSiteTransfer().
app.post(SSO_PATH, interSiteTransfer);
app.post(SSO_PATH + '/:rp', interSiteTransfer);

app.post(RESPONDER_PATH, respond);
app.post(RESPONDER_PATH + '/:rp', respond);

// A GET on the responder describes it rather than 405ing, because the address is
// in the metadata and somebody will paste it into a browser.
app.get(RESPONDER_PATH, function (req, res) {
  log.debug("Entering the SAML 1.1 responder description.");
  const where = endpointsFor(baseUrlOf(req), '');
  sendPage(res, 200, 'SAML 1.1 SAML responder',
    '<h1>SAML 1.1 — the SAML responder</h1>' +
    '<p class="sub">SOAP over HTTP POST at <code>' + xmlEscape(where.responder) + '</code></p>' +
    '<p>This is the back channel, and a browser never touches it: a relying party calls it ' +
    'directly, server to server. It answers a <code>&lt;samlp:Request&gt;</code> inside a SOAP ' +
    'envelope, and there are four it understands.</p>' +
    '<table><thead><tr><th>Request</th><th>What comes back</th></tr></thead><tbody>' +
    '<tr><td><code>&lt;samlp:AssertionArtifact&gt;</code></td><td>the assertion that artifact ' +
    'stands for. <strong>One-shot</strong> — resolving destroys it (section 3.2.3).</td></tr>' +
    '<tr><td><code>&lt;samlp:AssertionIDReference&gt;</code></td><td>an assertion this service ' +
    'issued, by its AssertionID. Not one-shot: a reference is not a credential.</td></tr>' +
    '<tr><td><code>&lt;samlp:AttributeQuery&gt;</code></td><td>an assertion carrying the ' +
    'attribute statement for the subject named. This is SAML 1.1\'s attribute authority, and it ' +
    'is the half Shibboleth deployments leaned on.</td></tr>' +
    '<tr><td><code>&lt;samlp:AuthenticationQuery&gt;</code></td><td>an assertion carrying the ' +
    'authentication statement alone.</td></tr>' +
    '</tbody></table>' +
    '<div class="meta"><div><strong>Nothing authenticates a caller here.</strong> Anybody who can ' +
    'reach this port can ask this responder for an assertion about anybody, by name, with no ' +
    'credential and no attribute release policy. A real attribute authority uses mutual TLS and a ' +
    'policy. Every query is logged saying so.</div>' +
    '<div>The fifth SAML 1.1 request type, <code>AuthorizationDecisionQuery</code>, is refused by ' +
    'name: this service makes no authorization decisions.</div></div>');
  log.debug("Leaving the SAML 1.1 responder description.");
});

app.get(RP_PATH, mockRelyingParty);
app.post(RP_PATH, mockRelyingParty);

// Exported for `../admin-ui/admin.js`, which draws /admin/saml11 and needs to
// name the same endpoints and the same slug this file does — a console that
// derived a URL of its own would be a console that tells somebody to configure a
// path nothing serves.
module.exports = {
  PROFILE_POST: PROFILE_POST,
  PROFILE_ARTIFACT: PROFILE_ARTIFACT,
  BINDING_SOAP: BINDING_SOAP,
  PROFILE_SHIB_AUTHN_REQUEST: PROFILE_SHIB_AUTHN_REQUEST,
  NAMEID_FORMATS: NAMEID_FORMATS,
  RP_KIND: RP_KIND,
  slugOf: slugOf,
  providerIdFor: providerIdFor,
  endpointsFor: endpointsFor,
  metadataFor: metadataFor,
  artifactCount: function () { return artifacts.size; },
  cachedAssertionCount: function () { return assertionsById.size; },
  pendingFlowCount: function () { return pendingFlows.size; },
  verifyResponse: verifyResponse
};
