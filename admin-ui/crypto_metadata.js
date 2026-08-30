'use strict';
//
// File: admin-ui/crypto_metadata.js
//
// ---------------------------------------------------------------------------
// GET /admin/crypto-metadata — WHAT THIS SERVICE DOES WITH CRYPTOGRAPHY, for
// every identity service it advertises, and with which algorithms.
//
// `/admin/sts-metadata` answers "what can I call, and what specification is it
// pretending to implement". This page answers the question that sits underneath
// it and that nothing here could answer before: **when this service signs,
// verifies, encrypts or decrypts something, what does it actually use** — which
// digest, which signature algorithm, which cipher, which key, and which of the
// several higher-level envelopes (JWS, JWE, XMLDSIG, XML Encryption, WS-Security,
// COSE, X.509) that primitive is wrapped in.
//
// It was worth a page of its own for a reason this repository has met before:
// the answer was spread over eleven modules and four vendored ones, and every
// prose statement of it was a copy that could drift. `common/crypto.js`
// centralised the CODE in 2026-08-27 and did not centralise the DESCRIPTION —
// so "which algorithms does this thing speak" was still answered by reading
// six tables in four files, and the console, which exists precisely so that
// nobody has to, said nothing about any of them.
//
// ---------------------------------------------------------------------------
// EVERY TABLE ON THIS PAGE IS READ FROM THE MODULE THAT PERFORMS THE
// ALGORITHM. THAT IS THE WHOLE DESIGN, AND IT IS `sts_metadata.js`'S
// ARGUMENT ONE LEVEL DOWN.
//
// That page walks the live express router rather than keeping a list of routes,
// because a hand-kept list next to the routes goes stale the first time
// somebody adds one and the failure is silent in the worst direction — the page
// still looks complete. An algorithm table is the same shape of thing. So:
//
//   JWS signature algorithms   `stsCrypto.JWS_ALGS`, which is THE table for
//                              this service — dpop.js had a second one once and
//                              that is how DPoP came to accept a different set
//                              from everything else for no reason anybody chose.
//   post-quantum and composite `pqJose.PQ_ALGS` / `pqJose.COMPOSITES`
//   JWE                        `stsCrypto.JWE_ALGS`, `JWE_DECRYPT_ALGS`,
//                              `JWE_ENCS`
//   XML signature / digest /   `xmldsig.SIG_METHODS`, `DIGEST_METHODS`,
//   canonicalization           `C14N_METHODS` — the VENDORED module, which is
//                              the other end of most of these exchanges
//   XML encryption             `stsCrypto.BLOCK_CIPHERS`, `KEY_TRANSPORTS`
//   Kerberos encryption types  `krb5crypto.ETYPES`, and the decode-only names
//                              read back through `etypeName()` rather than
//                              copied — see `kerberosEtypes()`
//   SPIFFE authority keys      `spiffeCa.KEY_TYPES`
//   WebAuthn                   `webauthn.COSE_ALGS` / `COSE_CURVES`
//   DPoP                       `dpop.SIGNING_ALGS`, which is a FILTER over the
//                              shared table and must stay visible as one
//   client authentication      `clientAuth.SYMMETRIC_METHODS` / `ASYMMETRIC_METHODS`
//   ID Token / UserInfo        `oauth2.ID_TOKEN_SIGNING_ALGS` /
//                              `USERINFO_SIGNING_ALGS`
//   the TLS certificate        `tlsServer.serverCertificate()`
//   the signing keys           `helpers.stsKeysFor()`, for the AMBIENT REALM
//
// Only two things here are written by hand, and both are things no table can
// hold: the per-family prose in `FAMILIES` (what each identity service signs
// and why) and `STANDARDS` (which document an envelope comes from and how much
// of it is really implemented). Both follow `sts_metadata.js`'s rule for the
// same reason — written CONSERVATIVELY, saying where this service does LESS
// than the specification, because a list that overstates is worse than no list
// at all in a tool people use to learn these specifications.
//
// ---------------------------------------------------------------------------
// THE FAMILY LIST IS CHECKED AGAINST `sts_metadata.js` RATHER THAN AGREED WITH
// IT, AND THAT IS WHY THERE IS A SLOT.
//
// The page reports on the identity services this mock ADVERTISES, so the list
// of them must be the same list `/admin/sts-metadata` draws its cards from. Two
// tables naming fourteen protocol families is two tables that will disagree the
// first time a fifteenth arrives — and the disagreement would be invisible,
// because each page would look complete on its own.
//
// So `sts_metadata.js` hands its `PROTOCOLS` over at its own require time
// (`setProtocolFamilies()`), and this page reports BOTH directions of drift the
// way that page reports both directions of endpoint drift: a family this mock
// advertises with no crypto profile here, and a profile here naming a family
// that is not advertised. A slot rather than a require because rule 3e's test
// answers yes — a `require('../sts_metadata')` from this file would load that
// module HERE, and its one constraint is that it is required LAST, so the
// require would take the last module in server.js and make it not last.
//
// The slot is optional in the only direction that matters: with nothing in it
// the page draws its own table and says the check did not run, rather than
// failing. A process that loaded this module and not that one is not a process
// whose crypto report should be a 500.
//
// ---------------------------------------------------------------------------
// WHERE IT SITS IN THE REQUIRE ORDER, AND WHY EVERY REQUIRE BELOW IS A CACHE
// HIT.
//
// server.js requires this module at 20a — after `tls/tls_server` (20) and
// before `ldap/ldap_server` (21). That position is a DEPENDENCY and not a
// preference: this file reads a table out of eleven other modules, and requiring
// one of them that server.js has not yet loaded would REGISTER ITS ROUTES HERE
// (rule 1). At 20a every one of them is already loaded, so every require below
// is a cache hit that registers nothing and moves nothing:
//
//   common/crypto, common/pq_jose, the vendored xmldsig and bbs2023   leaves
//   kerberos/krb5_crypto                loaded at 15 by krb5_kdc
//   authn/webauthn                      loaded at 8 by authn.js
//   oauth-oidc/{oauth2,dpop,client_auth,mtls}   loaded at 9
//   spiffe/spiffe_ca                    loaded at 18 by admin.js
//   admin-ui/admin                      loaded at 18 — the SHELL, and the gate
//   tls/tls_server                      loaded at 20, for its certificate
//
// The gate is admin.js's one `app.use('/admin', ...)`, registered at 18 and
// therefore above this route: express applies middleware only to routes added
// after it, so this page is behind the console's sign-on and its two roles by
// construction, exactly like `/admin/sts-metadata`. Nothing here repeats that
// check — a second opinion about who may read this page is a second thing to
// get wrong.
//
// **THIS PAGE PUBLISHES NO PRIVATE KEY AND NO SECRET.** It names key TYPES,
// key identifiers, curve names, certificate fingerprints and validity dates —
// everything a caller can already read off `/oauth2/jwks`,
// `/tls/server-certificate` and the SPIFFE bundle endpoint — and nothing that
// is not already published somewhere. That is a rule for anything added here
// later, not an observation about what is here now: this is a console page
// about cryptography, which makes it exactly the page somebody would think to
// put a private key on.
// ---------------------------------------------------------------------------

const app = require('../common/app');
const { log, xmlEscape, baseUrlOf, stsKeysFor } = require('../common/helpers');
const config = require('../common/config');
const realms = require('../common/realms');
// The console's SHELL and its prose helpers, exactly as `../sts_metadata.js`
// takes them: `respond()` answers ?format=json itself and wraps the body in the
// two columns, and `note()`/`warn()`/`bullet()`/`tip()` are what make prose on
// a console page fold instead of being a wall of text. Nothing about what this
// page SAYS comes from that module.
const admin = require('./admin');
// THE ONE PLACE THIS SERVICE SIGNS, VERIFIES, ENCRYPTS AND DECRYPTS, and
// therefore the source of most of this page. `stsCrypto.xmldsig` is the
// vendored module re-exported, which is taken from here rather than required
// again so that there stays exactly one spelling of it in the process.
const stsCrypto = require('../common/crypto');
const pqJose = require('../common/pq_jose');
const bbs2023 = require('../common/vendored/bbs2023.js');
const krb5crypto = require('../kerberos/krb5_crypto');
const spiffeCa = require('../spiffe/spiffe_ca');
const webauthn = require('../authn/webauthn');
const dpop = require('../oauth-oidc/dpop');
const clientAuth = require('../oauth-oidc/client_auth');
const mtls = require('../oauth-oidc/mtls');
const oauth2 = require('../oauth-oidc/oauth2');
const tlsServer = require('../tls/tls_server');

const esc = xmlEscape;
const xmldsig = stsCrypto.xmldsig;
const scimAuth = require('../scim/scim_auth');

// ---------------------------------------------------------------------------
// THE IDENTITY SERVICES THIS MOCK ADVERTISES, AND WHAT EACH ONE DOES WITH
// CRYPTOGRAPHY.
//
// One row per protocol family on `/admin/sts-metadata`'s cards, and the `name`
// of each is that page's name for it CHARACTER FOR CHARACTER — that is what
// `driftReport()` below joins on, so a row renamed here and not there is
// reported rather than silently unmatched.
//
// The four verbs are separated on purpose and are not four ways of saying
// "uses crypto". A family that SIGNS is minting something a relying party will
// believe; one that VERIFIES is making a decision it could get wrong; one that
// ENCRYPTS is protecting somebody else's data with somebody else's key; one
// that DECRYPTS is holding a private key that a caller can aim ciphertext at.
// They are different exposures and this service does a different amount of each
// — federation VERIFIES and barely signs, SAML 2.0 does all four — so a table
// that collapsed them would hide the one distinction a reader came for.
//
// `algorithms` is a FUNCTION and never a list, because everything it names is
// read from the module that performs it at the moment the page is drawn. A
// family whose algorithms are settable at runtime (SAML 2.0's two encryption
// settings) therefore shows what this realm is configured with right now rather
// than what the defaults are.
//
// An empty string for a verb means this service does not do it in that family,
// and every one of those is a documented non-goal rather than an oversight —
// `saml/CLAUDE.md` on verifying an AuthnRequest signature,
// `federation/CLAUDE.md` on decrypting a partner's assertion. The page prints
// them as "—" and the `whatItDoesNot` line beside them says which.
// ---------------------------------------------------------------------------
const FAMILIES = [
  { name: 'OAuth2 / OIDC',
    signs: 'Every access token and refresh token, and the ID Token, with the ' +
           'realm\'s RSA key as RS256. A client that registers ' +
           '`id_token_signed_response_alg` gets that algorithm instead, out of ' +
           'the shared JWS table — every curve, both Edwards curves, and the ' +
           'post-quantum and composite ones. A signed UserInfo response the ' +
           'same way, plus the HMAC family (signed with that client\'s own ' +
           '`client_secret`, which is why it needs no published key) and ' +
           '`none`.',
    verifies: 'DPoP proofs (RFC 9449), `private_key_jwt` and ' +
              '`client_secret_jwt` client assertions, and every access token ' +
              'it is handed at a protected endpoint — against its own JWKS, ' +
              'with `oauth2.clockSkewS` applied.',
    encrypts: 'A UserInfo response for a client that registered ' +
              '`userinfo_encrypted_response_alg`: JWE compact, RSA-OAEP or ' +
              'ECDH-ES to the client\'s own key.',
    decrypts: 'A JWE encrypted to this service\'s RSA key, RSA-OAEP-256 only ' +
              '— a shorter list than it encrypts with on purpose, because it ' +
              'holds no EC private key to agree with.',
    hashes: '`at_hash` and `c_hash` are the left half of the SHA-256 of the ' +
            'token; PKCE `S256` is SHA-256 over the verifier; `cnf.jkt` is an ' +
            'RFC 7638 JWK Thumbprint (SHA-256) and `cnf["x5t#S256"]` is the ' +
            'SHA-256 of the client certificate\'s DER.',
    whatItDoesNot: 'It verifies no access token it did not issue, except at ' +
                   'UserInfo, and it follows no `jwks_uri` — an inline `jwks` ' +
                   'on the registration is the only key it will read.',
    envelopes: ['jws', 'jwe', 'jwk', 'jwt', 'thumbprint', 'dpop', 'mtls', 'pkce'],
    algorithms: function () {
      return [
        ['Tokens this service mints by default', ['RS256']],
        ['ID Token, when a client registers one', oauth2.ID_TOKEN_SIGNING_ALGS],
        ['UserInfo response', oauth2.USERINFO_SIGNING_ALGS],
        ['DPoP proof', dpop.SIGNING_ALGS],
        ['Client assertion', clientAuth.SYMMETRIC_METHODS
          .concat(clientAuth.ASYMMETRIC_METHODS)],
        ['JWE key management (out)', stsCrypto.JWE_ALGS],
        ['JWE key management (in)', stsCrypto.JWE_DECRYPT_ALGS],
        ['JWE content encryption', Object.keys(stsCrypto.JWE_ENCS)]
      ];
    } },

  { name: 'Federation',
    signs: 'The SAML 2.0 `<AuthnRequest>` it sends a foreign identity ' +
           'provider, enveloped, RSA-SHA256 over exclusive c14n — the same ' +
           'signer every other document here goes through.',
    verifies: 'THE WHOLE POINT OF THE FEATURE. A partner\'s SAML Response ' +
              'and the Assertion inside it, each checked SEPARATELY and each ' +
              'against the certificate configured on the relationship — never ' +
              'against a certificate the document carries in its own ' +
              '`ds:KeyInfo`, which is the check a naive implementation ' +
              'skips. A partner\'s ID Token as an ordinary JWS against the ' +
              'partner\'s published keys.',
    encrypts: '',
    decrypts: '',
    hashes: 'Whatever the partner\'s `DigestMethod` names, out of the ' +
            'vendored table below.',
    whatItDoesNot: 'It does not decrypt an assertion a partner encrypted, and ' +
                   'it does not consume a federated sign-out. THE GATE IS ON ' +
                   'THE SIGNER AND NOT ON THE SUBJECT: past a verified ' +
                   'signature any username is accepted. This is the one ' +
                   'surface here where a missing check is an authentication ' +
                   'bypass for every protocol in the process — see ' +
                   'federation/CLAUDE.md.',
    envelopes: ['xmldsig', 'c14n', 'jws'],
    algorithms: function () {
      return [
        ['Outbound request signature',
         ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256']],
        ['Inbound signature, any of', Object.keys(xmldsig.SIG_METHODS)],
        ['Inbound ID Token', stsCrypto.JWS_ASYMMETRIC_ALGS]
      ];
    } },

  { name: 'SAML 2.0',
    signs: 'Assertions, Responses, LogoutRequests and the per-service-provider ' +
           'metadata — enveloped, RSA-SHA256, EXCLUSIVE canonicalization, with ' +
           'the `<ds:Signature>` immediately after `<Issuer>` where the schema ' +
           'puts it. The HTTP Redirect binding is signed differently and that ' +
           'is the specification\'s doing rather than this service\'s: it is a ' +
           'DETACHED signature over the octets of the query string, with ' +
           '`SigAlg` naming the algorithm as a parameter.',
    verifies: 'Its own artifacts, and a service provider\'s ' +
              '`<EncryptedID>` is decrypted rather than verified.',
    encrypts: 'The assertion in a Response, as `<EncryptedAssertion>`, and the ' +
              'NameID in a LogoutRequest as `<EncryptedID>` — per application, ' +
              'to the certificate held on its entry. SIGNED FIRST AND THEN ' +
              'ENCRYPTED, which is the order every service provider expects: ' +
              'the signature is inside the ciphertext and is what survives ' +
              'decryption.',
    decrypts: 'An `<EncryptedID>` a service provider sends in a LogoutRequest, ' +
              'to the realm\'s RSA key.',
    hashes: 'SHA-256 for the Reference digest; SHA-1 inside RSA-OAEP-MGF1P, ' +
            'because that is what the URI MEANS rather than a choice this ' +
            'service made.',
    whatItDoesNot: 'It does not verify an AuthnRequest\'s signature and it ' +
                   'does not consume service provider metadata — both are ' +
                   'recorded, neither is checked. A service provider it holds ' +
                   'no certificate for gets the assertion IN CLEAR, loudly, ' +
                   'rather than being refused.',
    envelopes: ['xmldsig', 'xmlenc', 'c14n'],
    algorithms: function () {
      return [
        ['Signature', ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256']],
        ['Block cipher (saml2.encryptionAlgorithm)',
         [String(config.value('saml2.encryptionAlgorithm'))]],
        ['Key transport (saml2.keyTransportAlgorithm)',
         [String(config.value('saml2.keyTransportAlgorithm'))]],
        ['Block ciphers offered', Object.keys(stsCrypto.BLOCK_CIPHERS)],
        ['Key transports offered', Object.keys(stsCrypto.KEY_TRANSPORTS)]
      ];
    } },

  { name: 'SAML 1.1',
    signs: 'Assertions and Browser/POST Responses, RSA-SHA256 over exclusive ' +
           'c14n, through the same signer. The PLACEMENT differs and the ' +
           'reason is the grammar rather than the crypto: a 1.1 assertion has ' +
           'no `<Issuer>` ELEMENT — in 1.1 the issuer is an ATTRIBUTE — so ' +
           '"after the issuer" is not a position that exists and the signature ' +
           'goes LAST. A Response signs FIRST, ahead of the assertion it ' +
           'carries.',
    verifies: 'Its own artifacts, for the mock relying party.',
    encrypts: '',
    decrypts: '',
    hashes: 'SHA-256 for the Reference digest.',
    whatItDoesNot: 'SAML 1.1 has no encryption at all — `<EncryptedAssertion>` ' +
                   'arrived with 2.0 — and no request message to verify a ' +
                   'signature on. The reference URI names `AssertionID` or ' +
                   '`ResponseID`, which is the whole reason the shared signer ' +
                   'resolves an id by SEARCHING for one rather than being told ' +
                   'its name.',
    envelopes: ['xmldsig', 'c14n'],
    algorithms: function () {
      return [
        ['Signature', ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256']]
      ];
    } },

  { name: 'WS-Federation',
    signs: 'The SAML assertion inside the `wresult`, in whichever version the ' +
           'relying party asked for, through the shared signer.',
    verifies: 'The mock relying party at `/wsfed/rp` verifies that assertion ' +
              'check by check, and is told WHICH element to verify rather ' +
              'than taking the first `<ds:Signature>` in the document — the ' +
              'defect four separate verifiers here used to have.',
    encrypts: '',
    decrypts: '',
    hashes: 'SHA-256 for the Reference digest.',
    whatItDoesNot: 'It fakes no `wauth` and dereferences no `wreqptr` — ' +
                   'fetching a URL somebody registered is a server-side ' +
                   'request forgery with a citation attached.',
    envelopes: ['xmldsig', 'c14n', 'wss'],
    algorithms: function () {
      return [
        ['Signature', ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256']]
      ];
    } },

  { name: 'WS-Trust',
    signs: 'The SAML assertion in the RequestSecurityTokenResponse, 1.1 or ' +
           '2.0, through the shared signer.',
    verifies: 'It READS a requester\'s `<wsse:Security>` credential and the ' +
              '`<ds:X509Certificate>` in a signed request — the latter to ' +
              'find out who to ENCRYPT to. It checks no password behind it.',
    encrypts: 'With `?encrypt=1`, the issued 2.0 assertion, to the ' +
              'certificate found in the request signature. Same two tables as ' +
              'SAML 2.0, because it is the same code — `saml/saml2.js` ' +
              're-exports it.',
    decrypts: '',
    hashes: 'SHA-256 for the Reference digest.',
    whatItDoesNot: 'It polices no delegation: an RST asking for a token for ' +
                   'somebody else is answered. And it produces no signed SOAP ' +
                   'envelope of its own — see WS-Security below, which is the ' +
                   'row that says what this service does and does not do with ' +
                   'that specification.',
    envelopes: ['xmldsig', 'xmlenc', 'c14n', 'wss'],
    algorithms: function () {
      return [
        ['Signature', ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256']],
        ['Block ciphers offered', Object.keys(stsCrypto.BLOCK_CIPHERS)],
        ['Key transports offered', Object.keys(stsCrypto.KEY_TRANSPORTS)]
      ];
    } },

  { name: 'Kerberos',
    signs: 'Nothing, in the public-key sense — THIS IS THE ONE FAMILY HERE ' +
           'WITH NO ASYMMETRIC CRYPTOGRAPHY IN IT AT ALL. Integrity comes from ' +
           'a keyed checksum (HMAC-SHA1-96, HMAC-SHA-256-128, HMAC-SHA-384-192 ' +
           'or HMAC-MD5) under a key derived from the long-term key for that ' +
           'message\'s key usage number.',
    verifies: 'Pre-authentication, every AP-REQ authenticator, and the ' +
              'checksums above. THIS IS THE ONE DOOR IN THIS SERVICE THAT ' +
              'REALLY VERIFIES A CREDENTIAL, and it is not a policy choice: ' +
              'in Kerberos the password IS the key, so a KDC that accepted ' +
              'anything would still have to pick a key the client could not ' +
              'guess. The permissiveness moved into the ACCOUNT POLICY ' +
              'instead — one shared password, an account created for any name.',
    encrypts: 'Every encrypted part of every message: the AS-REP enc-part, ' +
              'the ticket, the authenticator, the TGS-REP. AES in CTS mode ' +
              'with a confounder, or RC4-HMAC.',
    decrypts: 'The same, in the other direction, including a real service ' +
              'ticket presented at `/authn/spnego`.',
    hashes: 'PBKDF2-HMAC-SHA1 (RFC 3962) or PBKDF2-HMAC-SHA-256/384 (RFC ' +
            '8009) for string-to-key; MD4 (the NT hash) for RC4-HMAC, which ' +
            'is unsalted and is why salt discovery matters only for AES.',
    whatItDoesNot: 'No PKINIT, so no certificate ever enters a Kerberos ' +
                   'exchange here. DES and 3DES are DECODE-ONLY — named so a ' +
                   'capture renders honestly, never performed.',
    envelopes: ['krb5', 'gssapi'],
    algorithms: function () {
      return [['Encryption types performed', kerberosEtypes().performed
        .map(function (row) { return row.id + ' ' + row.name; })]];
    } },

  { name: 'SPNEGO',
    signs: 'Nothing of its own. The MIC in a `negTokenResp` is a Kerberos ' +
           'checksum over the negotiation, computed with the mechanism\'s key.',
    verifies: 'The AP-REQ inside the GSS token, through the Kerberos acceptor ' +
              '— including the replay cache, which is the one check at this ' +
              'door whose absence would be a security bug rather than a ' +
              'fidelity one.',
    encrypts: '',
    decrypts: 'The AP-REQ authenticator, under the service\'s long-term key.',
    hashes: 'Whatever the negotiated encryption type\'s checksum uses.',
    whatItDoesNot: 'It adds no check of its own on top of the acceptor\'s, and ' +
                   'it negotiates no mechanism but Kerberos v5.',
    envelopes: ['krb5', 'gssapi'],
    algorithms: function () {
      return [['Negotiated mechanism', ['Kerberos v5 (1.2.840.113554.1.2.2)']]];
    } },

  { name: 'SPIFFE',
    signs: 'X509-SVIDs, from a self-signed authority generated at start, and ' +
           'JWT-SVIDs as ordinary JWS. The authority\'s key type is a setting ' +
           'and each type fixes both the certificate signature algorithm and ' +
           'the JWS `alg` — a certificate whose declared algorithm and actual ' +
           'signature disagree parses perfectly and is refused with a message ' +
           'about a signature, naming neither hash.',
    verifies: 'An X509-SVID over mutual TLS on the SPIRE Server API\'s TCP ' +
              'port, and a JWT-SVID at `ValidateJWTSVID`.',
    encrypts: '',
    decrypts: '',
    hashes: 'SHA-256 over the SVID DER wherever one is recorded, and the ' +
            'certificate signature\'s own digest, which follows the key type.',
    whatItDoesNot: 'It attests no workload and no node — what the Workload ' +
                   'API lacks is ATTESTATION, not authentication, and its ' +
                   'specification says it MUST NOT authenticate. It revokes ' +
                   'no credential either; the directory records who may still ' +
                   'be ISSUED one, which is a different claim. Ed25519 is ' +
                   'available for the X.509 authority and NOT for the JWT ' +
                   'one, which is a limit of `jsonwebtoken` and not of the ' +
                   'specification.',
    envelopes: ['x509', 'jws', 'jwk', 'mtls'],
    algorithms: function () {
      return [
        ['Authority key types', spiffeCa.KEY_TYPES.map(function (t) {
          return t.id + ' (' + t.sigAlg + (t.jwtAlg ? ', ' + t.jwtAlg
                                                    : ', no JWT) ') + ')';
        })],
        ['X.509 authority in this process',
         [String(config.value('spiffe.x509KeyType'))]],
        ['JWT authority in this process',
         [String(config.value('spiffe.jwtKeyType'))]]
      ];
    } },

  { name: 'SCIM',
    signs: 'Nothing. It MINTS no credential — it is the one family here that ' +
           'only ever checks them.',
    verifies: 'A credential in any of the six schemes RFC 7644 section 2 ' +
              'names, and TWO OF THE SIX ARE REALLY VERIFIED: HTTP Digest ' +
              'computes the response over the configured password, and a HOBA ' +
              'signature is checked against the public key the client ' +
              'registered. The other four are turnstiles — any password but ' +
              'one passes Basic, and the OAuth ones need only a token this ' +
              'service issued carrying `scim:read` or `scim:write`.',
    encrypts: '',
    decrypts: '',
    hashes: 'RFC 7616 Digest: SHA-256, SHA-512-256 and MD5, each with its ' +
            '`-sess` variant, offered strongest first because section 3.7 ' +
            'says so and because a client takes the first it understands. ' +
            'Each is checked against the openssl this process actually has, ' +
            'so a challenge never names an algorithm the server cannot ' +
            'compute.',
    whatItDoesNot: 'It deactivates nobody on `active: false`, and it stores ' +
                   'no password of its own — the Digest password is a ' +
                   'setting.',
    envelopes: ['digest', 'hoba', 'jws', 'dpop', 'mtls'],
    algorithms: function () {
      return [
        ['Authentication schemes', scimAuth.SCHEMES.map(function (s) {
          return s.name;
        })],
        ['Digest', (scimAuth.DIGEST_ALGORITHMS || []).map(function (row) {
          return row.token;
        })],
        ['HOBA', ['RSA-SHA256 (algorithm ' +
                  String(scimAuth.HOBA_ALG_RSA_SHA256) + ')']]
      ];
    } },

  { name: 'LDAP',
    signs: 'Nothing.',
    verifies: 'Nothing. Every bind succeeds — any DN, any password, ' +
              'anonymous, on 389 and on 636 alike — except the one password ' +
              'spelled `invalid`, which exists so a client\'s failure path ' +
              'can be exercised.',
    encrypts: 'The LDAPS listener on 636 is TLS, on the certificate ' +
              '`tls/tls_server.js` generates and three other sockets share. ' +
              'One set of handlers and one store sit behind both ports.',
    decrypts: 'The same connection, in the other direction.',
    hashes: 'None. No password is ever hashed here because none is ever ' +
            'checked, and no `userPassword` is stored.',
    whatItDoesNot: 'It answers NO SASL MECHANISM — the root DSE omits ' +
                   '`supportedSASLMechanisms` rather than publishing it ' +
                   'empty, because an LDAP attribute always has at least one ' +
                   'value and an empty one is not a weaker claim, it is a ' +
                   'malformed one. So no GSSAPI bind, no EXTERNAL bind, and ' +
                   'no StartTLS: 636 is TLS from the first byte.',
    envelopes: ['tls'],
    algorithms: function () {
      return [['LDAPS transport', ['TLS, on the shared server certificate']]];
    } },

  { name: 'PKI / X.509',
    signs: 'Three self-signed certificates, all RSA 2048 with SHA-256, all ' +
           'generated at start and none of them persisted: the SIGNING ' +
           'certificate (serial 02, five years, no extensions at all) and the ' +
           'TLS SERVER certificate (serial 03, two years, with the ' +
           'subjectAltName that is the only place the names are, because RFC ' +
           '6125 has said the CN is ignored since 2011). SPIFFE\'s authority ' +
           'is the third and is configured separately.',
    verifies: 'A client certificate presented on 9443 or on the main port, ' +
              'against whatever anchors have been added — and then turns it ' +
              'into a THUMBPRINT rather than into a login.',
    encrypts: 'Every byte on 8443, 9443, LDAPS 636 and, since 2026-08-30, the ' +
              'main port too. The cipher suite and the key exchange are ' +
              'node\'s OpenSSL defaults; nothing here narrows them.',
    decrypts: 'The same.',
    hashes: 'SHA-256 over the DER, everywhere a certificate is named: RFC ' +
            '8705\'s `x5t#S256` confirmation, `/tls`\'s fingerprint, and the ' +
            'SPKI pin the test suite carries.',
    whatItDoesNot: 'It turns a verified client certificate into a LOGIN ' +
                   'nowhere. The first fetch of the server certificate ' +
                   'cannot be verified and that is a consequence of the key ' +
                   'being regenerated per start rather than a gap — there is ' +
                   'no plain listener left to fetch it from.',
    envelopes: ['x509', 'tls', 'mtls'],
    algorithms: function () {
      const cert = tlsServer.serverCertificate();
      return [
        ['Server certificate', ['RSA 2048, SHA-256, self-signed, valid to ' +
                                String(cert.notAfter)]],
        ['Certificate binding', [mtls.CONFIRMATION_MEMBER +
                                 ' — SHA-256 over the DER, base64url']]
      ];
    } },

  { name: 'WebAuthn / CTAP',
    signs: 'Nothing. The AUTHENTICATOR signs; this service is the relying ' +
           'party, which is the half that only ever checks.',
    verifies: 'The registration attestation and every assertion: the ' +
              'signature over `authenticatorData || SHA-256(clientDataJSON)`, ' +
              'against the COSE public key the credential registered.',
    encrypts: '',
    decrypts: '',
    hashes: 'SHA-256 twice over — the client data hash the signature covers, ' +
            'and the RP ID hash inside the authenticator data that is ' +
            'compared byte for byte against SHA-256 of the origin\'s domain.',
    whatItDoesNot: 'It validates no attestation STATEMENT — the certificate ' +
                   'chain a packed or TPM attestation carries is parsed and ' +
                   'not chased. The sign-in screen offers two algorithms and ' +
                   'accepts more, which is deliberate: what a platform ' +
                   'authenticator actually produces is what a person came ' +
                   'here to see.',
    envelopes: ['cose', 'webauthn'],
    algorithms: function () {
      return [
        ['Offered at registration', ['ES256 (-7)', 'RS256 (-257)']],
        ['Accepted at verification',
         Object.keys(webauthn.COSE_ALGS).map(function (k) {
           return webauthn.COSE_ALGS[k] + ' (' + k + ')';
         })],
        ['Curves', Object.keys(webauthn.COSE_CURVES).map(function (k) {
          return webauthn.COSE_CURVES[k];
        })]
      ];
    } },

  { name: 'Verifiable Credentials (OID4VCI / OID4VP)',
    signs: 'An SD-JWT VC as an RS256 JWS with `_sd_alg: sha-256`, and a W3C ' +
           '`ldp_vc` with a `bbs-2023` Data Integrity proof — BLS12-381-SHA-256, ' +
           'which is a pairing-based signature and the only one in this ' +
           'service. Its key is not a JWK and is published as ' +
           '`publicKeyMultibase` rather than being forced into one it does ' +
           'not fit.',
    verifies: 'A wallet\'s proof of possession at the credential endpoint, ' +
              'which must be an ASYMMETRIC JWS — never a MAC and never ' +
              '`none` — and a presentation at the verifier, including a ' +
              'DERIVED bbs-2023 proof, which is what selective disclosure ' +
              'looks like when it is not an SD-JWT.',
    encrypts: '',
    decrypts: '',
    hashes: 'SHA-256 for every SD-JWT disclosure digest, and inside the BBS ' +
            'ciphersuite for the message mapping.',
    whatItDoesNot: 'It verifies nothing in a credential\'s VALUES, which are ' +
                   'invented, and it turns a verified presentation into a ' +
                   'sign-on nowhere.',
    envelopes: ['jws', 'sdjwt', 'dataintegrity', 'did'],
    algorithms: function () {
      return [
        ['Credential signing', ['RS256', bbs2023.CRYPTOSUITE]],
        ['Wallet proof of possession', stsCrypto.JWS_ASYMMETRIC_ALGS],
        ['Disclosure digest', ['sha-256']]
      ];
    } }
];

// ---------------------------------------------------------------------------
// THE HIGHER-LEVEL STANDARDS — the envelopes the primitives above travel in.
//
// A reader who knows that this service signs with RSA-SHA256 still does not
// know whether that signature is a JWS, an enveloped XMLDSIG, a detached
// signature over a query string or a `<wsse:Security>` header, and those are
// four different documents with four different failure modes. This table is
// that layer, and every row is keyed by the short name `FAMILIES` above cites
// in its `envelopes` — so a family naming an envelope that is not here is
// reported by `driftReport()` rather than rendering as a dead link.
//
// `coverage` MUST START `full`, `partial` OR `mock`, which is the rule
// `sts_metadata.js` states for its own specification list and which is worth
// more here than there: this is a page about cryptography, and a page about
// cryptography that overstates what it implements is actively dangerous to
// somebody using it to learn.
//
// **WS-SECURITY IS THE ROW TO READ BEFORE ARGUING WITH THIS TABLE**, and it is
// the one people ask about by two names that are not specifications. There is
// no OASIS document called "WS-Integrity" and none called "WS-Encryption": WSS
// (Web Services Security: SOAP Message Security) is one specification, and the
// integrity half is XML Signature applied to the SOAP Body and Timestamp
// through a `<wsse:Security>` header, while the confidentiality half is XML
// Encryption applied the same way. This service does NEITHER of those, and
// saying so plainly is the point of the row: what it does is put a SIGNED SAML
// ASSERTION inside a SOAP body, which is the SAML Token Profile and not
// message-level security. The vendored `xmldsig.js` can produce a real
// `<wsse:Security>` signature — `signSoapMessage()` is in it, and the debugger
// uses it — and nothing here calls it.
// ---------------------------------------------------------------------------
const STANDARDS = [
  { key: 'jws', name: 'JWS — JSON Web Signature',
    specs: ['RFC 7515', 'RFC 7518 (JWA)', 'RFC 8037 (EdDSA)',
            'RFC 8812 (ES256K)', 'RFC 9964 (AKP / ML-DSA)'],
    coverage: 'full for the algorithms listed below, in compact serialization ' +
              'only. JSON and flattened serializations are not produced or ' +
              'read; nothing in any of these protocols asks for one.',
    what: 'The envelope for every token this service mints and every ' +
          'assertion it is handed. ONE TABLE FOR THE WHOLE SERVICE — ' +
          '`common/crypto.js`\'s `JWS_ALGS` — because there were two once, ' +
          'and that is how DPoP came to accept a different set of algorithms ' +
          'from everything else for no reason anybody chose.' },
  { key: 'jwe', name: 'JWE — JSON Web Encryption',
    specs: ['RFC 7516', 'RFC 7518'],
    coverage: 'partial: compact serialization, and it ENCRYPTS with a longer ' +
              'list than it DECRYPTS with. That asymmetry is deliberate — ' +
              'what it receives is encrypted to the RSA key it publishes, and ' +
              'it holds no EC private key to agree with.',
    what: 'An encrypted UserInfo response, and anything a client sends ' +
          'encrypted to this service\'s key. The CBC-HMAC family is here ' +
          'because `A128CBC-HS256` is what an OpenID Connect client gets by ' +
          'DEFAULT: register `userinfo_encrypted_response_alg` and say ' +
          'nothing about `enc`, and section 2 of the registration ' +
          'specification has chosen it for you.' },
  { key: 'jwk', name: 'JWK — JSON Web Key and JWK Set',
    specs: ['RFC 7517', 'RFC 7638 (thumbprint)'],
    coverage: 'full for publication. The published JWKS carries NO `alg` ' +
              'member, and its absence is deliberate: RFC 7517 section 4.4 ' +
              'makes it optional and says it names the INTENDED algorithm, ' +
              'and one RSA key here signs six of them. It said `RS256` until ' +
              '2026-08-28 and that was a promise the service had stopped ' +
              'keeping — Web Crypto refuses to import a JWK whose `alg` ' +
              'disagrees with the operation asked of it.',
    what: 'How every public key here is published, and how a client\'s own ' +
          'key is read. The RFC 7638 thumbprint is what DPoP binds to.' },
  { key: 'jwt', name: 'JWT — JSON Web Token',
    specs: ['RFC 7519', 'RFC 9068 (JWT access tokens)'],
    coverage: 'full for what it mints; `partial` for what it reads, because ' +
              'it verifies no access token it did not issue except at ' +
              'UserInfo.',
    what: 'The claim set inside the JWS. `oauth2.clockSkewS` is applied ' +
          'wherever this service reads back a token it signed, in ONE place ' +
          'since 2026-08-27 — four of the ten call sites that used to do it ' +
          'had quietly stopped.' },
  { key: 'thumbprint', name: 'JWK Thumbprint',
    specs: ['RFC 7638'],
    coverage: 'full for RSA, EC, OKP and oct, which is every key type the ' +
              'RFC defines members for. THERE IS NO THUMBPRINT FOR `AKP`, ' +
              'the post-quantum key type, and that is why the PQ algorithms ' +
              'are excluded from DPoP.',
    what: 'One canonicalization, one SHA-256, one place — there were two ' +
          'implementations of it here before 2026-08-27.' },
  { key: 'dpop', name: 'DPoP — Demonstrating Proof of Possession',
    specs: ['RFC 9449'],
    coverage: 'full: all twelve of section 4.3\'s checks, the `cnf.jkt` ' +
              'binding on access AND refresh tokens, `dpop_jkt`, `jti` ' +
              'replay detection and the nonce handshake in both shapes. NOT ' +
              'required — nonce mode makes proofs fresher, not mandatory.',
    what: 'The sender constraint that makes a stolen access token worthless ' +
          'without the key. Its algorithm list is a FILTER over the shared ' +
          'JWS table — asymmetric, and not post-quantum — rather than a ' +
          'table of its own.' },
  { key: 'mtls', name: 'Mutual TLS client authentication and certificate binding',
    specs: ['RFC 8705'],
    coverage: 'partial: both client authentication methods and the ' +
              'certificate-bound access token. It turns a verified ' +
              'certificate into a THUMBPRINT and never into a login.',
    what: '`x5t#S256` is the base64url SHA-256 of the certificate\'s DER — ' +
          'the DER, not the PEM, which is the mistake that looks right in a ' +
          'log and matches nothing.' },
  { key: 'pkce', name: 'PKCE — Proof Key for Code Exchange',
    specs: ['RFC 7636'],
    coverage: 'full for `S256` and `plain`. In RFC 9700 mode `plain` is ' +
              'withdrawn and the advertised list becomes `S256` alone.',
    what: 'SHA-256 over the code verifier. The one place in this service ' +
          'where a hash is the whole of a security property.' },
  { key: 'xmldsig', name: 'XML Signature',
    specs: ['XMLDSIG-CORE (W3C)', 'RFC 4051 / RFC 6931 (xmldsig-more)',
            'RFC 9231 (RSASSA-PSS)'],
    coverage: 'partial: this service SIGNS with RSA-SHA256 alone, and ' +
              'VERIFIES anything in the table below — RSA, RSASSA-PSS, ECDSA ' +
              'and HMAC across four digests. Enveloped signatures only; it ' +
              'produces no detached or enveloping signature except the ' +
              'Redirect binding\'s, which is a different mechanism.',
    what: 'The envelope for every XML document this service mints. Since ' +
          '2026-08-27 it is the parent project\'s own `xmldsig.js`, vendored ' +
          'byte-identical, which is THE OTHER END of most of these exchanges ' +
          '— so both sides canonicalize with the same code, and a ' +
          'disagreement about c14n cannot be invisible until it is a ' +
          'signature that verifies on one side and not the other.' },
  { key: 'xmlenc', name: 'XML Encryption',
    specs: ['XMLENC-CORE1 (W3C)', 'xmlenc11 (AES-GCM)'],
    coverage: 'partial: four block ciphers and two key transports, wrapping ' +
              'one element at a time. It is not the vendored ' +
              'implementation and that is a deliberate exception — the ' +
              'output of the two is already byte-compatible, and what this ' +
              'one has that the other does not is the DIAGNOSIS.',
    what: 'Every message this deliberately says out loud: the two CBC ' +
          'ciphers are NOT authenticated and `rsa-1_5` is broken by ' +
          'Bleichenbacher. Both are offered because real service providers ' +
          'require them and a mock that offered only the safe choice could ' +
          'not be used to show what the unsafe one does.' },
  { key: 'c14n', name: 'Canonical XML',
    specs: ['Canonical XML 1.0', 'Exclusive XML Canonicalization 1.0'],
    coverage: 'partial: both algorithms and both `#WithComments` twins. C14N ' +
              '1.1 is NOT offered — its whole difference is how `xml:base`, ' +
              '`xml:lang` and `xml:space` inherit into a detached subtree, ' +
              'the engine does not implement that inheritance, and an option ' +
              'naming a method it does not perform is worse than an absent ' +
              'one.',
    what: 'EXCLUSIVE IS LOAD-BEARING AND IS THE DEFAULT EVERYWHERE HERE. An ' +
          'assertion is signed standalone and then embedded inside an RSTR, a ' +
          'Response or a `wresult` that declares prefixes of its own, so ' +
          'INCLUSIVE c14n would pull those ancestor declarations into the ' +
          'digest at verification time — the signature then fails for every ' +
          'relying party while verifying perfectly here, which is the worst ' +
          'shape of bug to chase.' },
  { key: 'wss', name: 'WS-Security (SOAP Message Security)',
    specs: ['WS-Security 1.1 (OASIS)', 'WSS SAML Token Profile 1.1'],
    coverage: 'mock, and this row is the one to read before asking for ' +
              '"WS-Integrity" or "WS-Encryption" — neither is a document ' +
              'that exists. WSS is one specification whose integrity half is ' +
              'XML Signature over the SOAP Body and Timestamp inside a ' +
              '`<wsse:Security>` header and whose confidentiality half is XML ' +
              'Encryption applied the same way. THIS SERVICE DOES NEITHER. ' +
              'It signs no SOAP envelope, encrypts no SOAP body, produces no ' +
              'Timestamp and verifies no message-level signature on a request.',
    what: 'What it DOES is the SAML Token Profile: a signed SAML assertion ' +
          'carried inside a SOAP body, with a ' +
          '`<wsse:SecurityTokenReference>` naming it by `KeyIdentifier`, and ' +
          'a `<wsse:BinarySecurityToken>` where an X.509 token was asked ' +
          'for. It READS a requester\'s `<wsse:Security>` header for a ' +
          'credential and for the certificate to encrypt to. The vendored ' +
          '`xmldsig.js` CAN produce a real `<wsse:Security>` signature — ' +
          '`signSoapMessage()` is in it and the debugger uses it — and ' +
          'nothing here calls it.' },
  { key: 'krb5', name: 'Kerberos v5 cryptography',
    specs: ['RFC 3961 (framework)', 'RFC 3962 (AES-SHA1)',
            'RFC 8009 (AES-SHA2)', 'RFC 4757 (RC4-HMAC)'],
    coverage: 'partial: four AES profiles and RC4-HMAC performed, DES and ' +
              '3DES decode-only. Simplified profile, key derivation by key ' +
              'usage, confounder and CTS all real — the vector tests reach ' +
              'each layer individually, because a passing end-to-end ' +
              'encryption can hide two compensating errors.',
    what: 'THE ONLY FAMILY HERE WITH NO PUBLIC-KEY CRYPTOGRAPHY IN IT. ' +
          'Confidentiality and integrity both come from one long-term ' +
          'symmetric key, which is exactly why this is the one door in this ' +
          'service that really verifies a credential.' },
  { key: 'gssapi', name: 'GSS-API / SPNEGO',
    specs: ['RFC 4121 (Kerberos GSS mechanism)', 'RFC 4178 (SPNEGO)',
            'RFC 4559 (HTTP Negotiate)'],
    coverage: 'partial: the Kerberos mechanism only, with the MIC exchange. ' +
              'No NTLM, no mechanism negotiation worth the name — there is ' +
              'one mechanism to negotiate.',
    what: 'The wrapper that carries an AP-REQ over HTTP. It adds no ' +
          'cryptography of its own: the MIC is a Kerberos checksum computed ' +
          'with the mechanism\'s key.' },
  { key: 'x509', name: 'X.509 / PKIX',
    specs: ['RFC 5280'],
    coverage: 'mock: every certificate here is self-signed, generated at ' +
              'start and valid for years, with no CRL, no OCSP and no path ' +
              'longer than one. SPIFFE\'s authority signs SVIDs, which is ' +
              'the only two-level chain in the process.',
    what: 'RSA 2048 with SHA-256 for the signing and TLS certificates; the ' +
          'SPIFFE authority is whatever `spiffe.x509KeyType` says. THE ' +
          'SUBJECTALTNAME IS THE ONLY PLACE THE NAMES ARE on the TLS ' +
          'certificate — RFC 6125 has said the CN is ignored since 2011.' },
  { key: 'tls', name: 'TLS',
    specs: ['RFC 8446 (1.3)', 'RFC 5246 (1.2)'],
    coverage: 'mock: node\'s OpenSSL defaults, unnarrowed. This service ' +
              'chooses no cipher suite, no protocol floor and no curve — ' +
              'what it configures is which sockets are TLS and which ' +
              'certificate they serve.',
    what: 'Four listeners plus the main port share one certificate. `STS_HTTPS' +
          '=false` is the supported way back to plain HTTP, not an escape ' +
          'hatch.' },
  { key: 'cose', name: 'COSE — CBOR Object Signing and Encryption',
    specs: ['RFC 9052', 'RFC 9053'],
    coverage: 'partial: COSE_Key parsing and signature verification for the ' +
              'algorithms below. It writes no COSE structure and reads no ' +
              'COSE_Encrypt.',
    what: 'How a WebAuthn credential\'s public key arrives. The CBOR reader ' +
          'and the COSE mapping are this repository\'s own and share no code ' +
          'with the debugger\'s, which is what makes the two an independent ' +
          'check on each other.' },
  { key: 'webauthn', name: 'WebAuthn Level 3',
    specs: ['W3C WebAuthn Level 3', 'FIDO CTAP2'],
    coverage: 'partial: the relying party\'s half. Registration and ' +
              'assertion signatures are really verified; attestation ' +
              'STATEMENTS are parsed and not chased.',
    what: 'The signature covers `authenticatorData || SHA-256(clientDataJSON)` ' +
          'and the RP ID hash inside that authenticator data is compared ' +
          'byte for byte against SHA-256 of the origin\'s domain.' },
  { key: 'digest', name: 'HTTP Digest Access Authentication',
    specs: ['RFC 7616'],
    coverage: 'partial: `qop=auth` with SHA-256, SHA-512-256 and MD5 and ' +
              'their `-sess` variants, with nonce counts, stale nonces and ' +
              '`Authentication-Info`. No `qop=auth-int`.',
    what: 'ONE OF THE TWO PLACES IN THIS SERVICE WHERE A PASSWORD IS REALLY ' +
          'CHECKED, and it has to be: the password is an input to the hash, ' +
          'so a server that accepted anything could not compute the response ' +
          'the client is expecting.' },
  { key: 'hoba', name: 'HOBA — HTTP Origin-Bound Authentication',
    specs: ['RFC 7486'],
    coverage: 'partial: algorithm 0 (RSA-SHA256) only, with the signature ' +
              'really verified against the registered key.',
    what: 'A password replacement: the client holds a key pair scoped to one ' +
          'origin, registers the public half, and signs a blob of nonce, ' +
          'algorithm, origin, realm, key id and the server\'s challenge. ' +
          'ANYBODY MAY REGISTER A KEY — that is the turnstile — but a ' +
          'signature that does not verify against the key registered under ' +
          'that `kid` is refused.' },
  { key: 'sdjwt', name: 'SD-JWT and SD-JWT VC',
    specs: ['draft-ietf-oauth-selective-disclosure-jwt',
            'draft-ietf-oauth-sd-jwt-vc'],
    coverage: 'partial: `_sd` digests with `_sd_alg: sha-256`, disclosures, ' +
              'and the `dc+sd-jwt` type. Key binding is by the wallet\'s ' +
              'proof of possession at issuance.',
    what: 'Selective disclosure by hashing: the credential carries the ' +
          'DIGEST of each claim and the holder hands over the ones it ' +
          'chooses to reveal.' },
  { key: 'dataintegrity', name: 'Data Integrity / BBS',
    specs: ['W3C VC Data Integrity', 'bbs-2023 cryptosuite',
            'draft-irtf-cfrg-bbs-signatures'],
    coverage: 'partial: issue, verify a base proof, and verify a DERIVED ' +
              'proof. BLS12381-SHA-256 ciphersuite.',
    what: 'THE ONLY PAIRING-BASED SIGNATURE IN THIS SERVICE, and the only ' +
          'selective disclosure here that is not hashing. What must be ' +
          'shared with the far end is the CANONICAL FORM — bbs-2023 signs ' +
          'canonicalized RDF statements — which is why the JSON-LD contexts ' +
          'are vendored rather than fetched.' },
  { key: 'did', name: 'DID Core and DIF domain linkage',
    specs: ['W3C DID Core', 'did:web', 'DIF Well Known DID Configuration'],
    coverage: 'partial: `did:web` resolution, a document publishing this ' +
              'service\'s keys, and the domain linkage credential.',
    what: 'How a wallet finds the key that verifies a credential whose ' +
          '`iss` is a DID. The BBS key is published as ' +
          '`publicKeyMultibase` because it has no JWK representation to be ' +
          'forced into.' }
];

// ---------------------------------------------------------------------------
// THE SLOT `sts_metadata.js` FILLS. See the header for why it is a slot: a
// require in the obvious direction would load the module whose one constraint
// is that it is required LAST.
//
// It is validated when it is installed rather than when it is read, which is
// the rule `admin.js`'s `setLogoutReader()` follows and for the same reason —
// a half-usable list installed quietly would produce a drift report that is
// wrong rather than absent, and a wrong drift report is worse than none.
// ---------------------------------------------------------------------------
let advertisedFamilies = null;

function setProtocolFamilies(protocols) {
  log.debug("Entering setProtocolFamilies().");
  if (!Array.isArray(protocols)) {
    log.error('crypto metadata: setProtocolFamilies() was given ' +
              typeof protocols + ' rather than an array, and was ignored. ' +
              'The crypto page will say the drift check did not run.');
    log.debug("Leaving setProtocolFamilies(). Refused.");
    return;
  }
  const named = protocols.filter(function (row) {
    return row && typeof row.name === 'string' && row.name;
  });
  if (named.length !== protocols.length) {
    log.error('crypto metadata: setProtocolFamilies() was given ' +
              (protocols.length - named.length) + ' row(s) with no name, and ' +
              'was ignored whole. A partial list would produce a drift ' +
              'report that is wrong rather than absent.');
    log.debug("Leaving setProtocolFamilies(). Refused.");
    return;
  }
  advertisedFamilies = named.map(function (row) { return row.name; });
  log.debug("Leaving setProtocolFamilies(). " + advertisedFamilies.length +
            " advertised family/families.");
}

// Both directions of drift, the way `/admin/sts-metadata` reports both
// directions of endpoint drift. `checked: false` means the slot was never
// filled — which the page says out loud rather than rendering two empty lists
// that look like a clean bill of health.
function driftReport() {
  log.debug("Entering driftReport().");
  if (!advertisedFamilies) {
    log.debug("Leaving driftReport(). The slot was never filled.");
    return { checked: false, undescribed: [], stale: [], envelopes: [] };
  }
  const described = FAMILIES.map(function (row) { return row.name; });
  const known = STANDARDS.map(function (row) { return row.key; });
  const report = {
    checked: true,
    // A family this mock advertises with no crypto profile here.
    undescribed: advertisedFamilies.filter(function (name) {
      return described.indexOf(name) < 0;
    }),
    // A profile here naming a family that is not advertised — what a rename
    // produces, and the direction that is otherwise invisible.
    stale: described.filter(function (name) {
      return advertisedFamilies.indexOf(name) < 0;
    }),
    // A family citing an envelope with no row in STANDARDS, which would
    // otherwise render as a dead cross-reference.
    envelopes: []
  };
  FAMILIES.forEach(function (row) {
    (row.envelopes || []).forEach(function (key) {
      if (known.indexOf(key) < 0 && report.envelopes.indexOf(key) < 0) {
        report.envelopes.push(row.name + ' → ' + key);
      }
    });
  });
  log.debug("Leaving driftReport(). " + report.undescribed.length +
            " undescribed, " + report.stale.length + " stale, " +
            report.envelopes.length + " unknown envelope(s).");
  return report;
}

// ---------------------------------------------------------------------------
// THE KEY MATERIAL THIS PROCESS HOLDS, FOR THE AMBIENT REALM.
//
// A realm has its own signing key (`realms.keyed()` in helpers.js), so this
// reads whichever realm the console is being viewed in — the same rule every
// settings form on this console follows. The two TLS certificates and the
// SPIFFE authorities are NOT per realm and the table says so, because those
// three socket families have no path to put a realm segment in.
//
// **IT DOES NOT CALL `allSigningKeys()`, AND THAT IS THE ONE THING TO KNOW
// BEFORE CHANGING THIS FUNCTION.** The post-quantum keys are made on FIRST USE
// — one SLH-DSA keygen is most of two seconds — so a metadata page that reached
// for them would spend that on every view, in a realm where nobody had asked
// for a post-quantum signature. It reads `keys.pqKeys` instead, which is
// present only once something has brought them into being, and reports honestly
// which of the two states this realm is in.
// ---------------------------------------------------------------------------
function keyMaterial() {
  log.debug("Entering keyMaterial().");
  const keys = stsKeysFor();
  const cert = tlsServer.serverCertificate();
  const spiffe = spiffeCa.state();
  const out = {
    realm: realms.currentId(),
    regeneratedEveryStart: true,
    signing: {
      kty: 'RSA', bits: 2048, alg: 'RS256', kid: String(keys.kid || ''),
      certificate: 'self-signed, SHA-256, serial 02, five years',
      what: 'The realm\'s one RSA key. It signs every access token, every ' +
            'refresh token, the default ID Token, and every XML document ' +
            'this service mints.'
    },
    curveKeys: (keys.extraKeys || []).map(function (one) {
      return { alg: one.alg, kty: one.publicJwk.kty,
               crv: one.publicJwk.crv || '', kid: one.publicJwk.kid };
    }),
    postQuantum: {
      algorithms: pqJose.PQ_ALGS.slice(0),
      generated: Array.isArray(keys.pqKeys),
      keys: (keys.pqKeys || []).map(function (one) {
        return { alg: one.alg, kty: 'AKP', kid: one.publicJwk.kid };
      }),
      what: 'Made on FIRST USE rather than at start — one SLH-DSA keygen is ' +
            'most of two seconds, which would be paid by every realm whether ' +
            'or not anybody asked for a post-quantum signature. The first ' +
            'JWKS fetch on a realm is what brings them into being.'
    },
    bbs: {
      cryptosuite: bbs2023.CRYPTOSUITE,
      curve: 'BLS12-381 G2, SHA-256 ciphersuite',
      what: 'Made on first use, like the post-quantum keys. It is published ' +
            'as `publicKeyMultibase` on the DID document rather than as a ' +
            'JWK, because a BLS key has no JWK representation to be forced ' +
            'into.'
    },
    tls: {
      subject: cert.subject,
      names: cert.names,
      fingerprint256: cert.fingerprint256,
      notAfter: cert.notAfter,
      perRealm: false,
      what: 'RSA 2048, SHA-256, self-signed, serial 03, two years. Shared by ' +
            '8443, 9443, LDAPS 636 and — when `global.https` is on — the main ' +
            'port. Two years rather than five because this one is put in ' +
            'somebody\'s truststore by hand.'
    },
    spiffe: {
      enabled: spiffe.enabled,
      ready: spiffe.ready,
      perRealm: false,
      trustDomain: spiffe.trustDomain,
      x509KeyType: String(config.value('spiffe.x509KeyType')),
      jwtKeyType: String(config.value('spiffe.jwtKeyType')),
      x509Authorities: (spiffe.x509Authorities || []).length,
      jwtAuthorities: (spiffe.jwtAuthorities || []).length
    }
  };
  log.debug("Leaving keyMaterial(). realm=" + out.realm + ", " +
            out.curveKeys.length + " curve key(s), post-quantum keys " +
            (out.postQuantum.generated ? "generated" : "not yet made") + ".");
  return out;
}

// ---------------------------------------------------------------------------
// THE KERBEROS ENCRYPTION TYPES, READ BACK OUT OF THE CODEC RATHER THAN COPIED.
//
// `kerberos/` is VENDORED — those eight modules are not editable here — so the
// decode-only names cannot be exported and must not be transcribed. They ARE
// reachable: `etypeName()` answers for anything either table knows and returns
// `etype-N` for anything neither does, and `isSupportedEtype()` says which of
// the two tables answered. So walking the assigned range and keeping what is
// named is the codec's own list, obtained without editing it and without a
// second copy to drift.
//
// The range is 1..26 because that is where every etype this codec has heard of
// lives; a number outside it simply produces no row, which is the honest answer
// for an etype nothing here can name.
// ---------------------------------------------------------------------------
function kerberosEtypes() {
  log.debug("Entering kerberosEtypes().");
  const performed = [];
  const decodeOnly = [];
  for (let id = 1; id <= 26; id++) {
    const name = krb5crypto.etypeName(id);
    if (name === 'etype-' + id) {
      continue;
    }
    (krb5crypto.isSupportedEtype(id) ? performed : decodeOnly)
      .push({ id: id, name: name });
  }
  log.debug("Leaving kerberosEtypes(). " + performed.length + " performed, " +
            decodeOnly.length + " decode-only.");
  return {
    performed: performed,
    decodeOnly: decodeOnly,
    preference: (krb5crypto.DEFAULT_ETYPE_PREFERENCE || []).slice(0)
  };
}

// ---------------------------------------------------------------------------
// HASHING. Every digest this service computes, and what for.
//
// Three of the four lists below are DERIVED, and the fourth — `fixed` — is the
// one that cannot be: "SHA-256, because RFC 7638 says the thumbprint is
// SHA-256" is a fact about a specification rather than a row in a table, and
// there is nowhere to read it from. Each of those rows therefore names the
// mechanism it belongs to, so a reader can check it against the standard rather
// than against this page.
//
// `weak` is separate and is not a scolding. SHA-1, MD5 and MD4 are all here on
// purpose: SHA-1 because XMLDSIG's original 2000 recommendation is what a great
// many deployed relying parties still send, MD5 and MD4 because RC4-HMAC is
// what most of the installed base of Kerberos clients falls back to. A mock
// that offered only the safe choice could not be used to show what the unsafe
// one does — which is this service's whole argument, made once here rather than
// four times below.
// ---------------------------------------------------------------------------
function hashing() {
  log.debug("Entering hashing().");
  const jws = [];
  stsCrypto.JWS_SIGNING_ALGS.forEach(function (alg) {
    const spec = stsCrypto.JWS_ALGS[alg];
    if (spec.hash && jws.indexOf(spec.hash) < 0) {
      jws.push(spec.hash);
    }
  });
  const out = {
    // The digests a JWS in this service is built on. `null` for EdDSA (Ed25519
    // hashes internally, which is what `crypto.sign(null, ...)` means) and for
    // the post-quantum ones, which is why the list is shorter than the
    // algorithm list.
    jws: jws,
    xmlDigestMethods: Object.keys(xmldsig.DIGEST_METHODS).map(function (uri) {
      return { uri: uri, label: xmldsig.DIGEST_METHODS[uri].label };
    }),
    scimDigest: (scimAuth.DIGEST_ALGORITHMS || []).map(function (row) {
      return { token: row.token, hash: row.hash };
    }),
    fixed: [
      { where: 'RFC 7638 JWK Thumbprint', hash: 'SHA-256',
        what: 'The canonical JWK, hashed. It is what `cnf.jkt` binds a ' +
              'DPoP-bound token to, and it is why the post-quantum ' +
              'algorithms cannot be used for DPoP — RFC 7638 defines the ' +
              'required members for RSA, EC, OKP and oct, and `AKP` is on ' +
              'none of those lists.' },
      { where: 'RFC 8705 `x5t#S256`', hash: 'SHA-256',
        what: 'Over the certificate\'s DER, base64url. The DER and not the ' +
              'PEM, which is the mistake that looks right in a log and ' +
              'matches nothing.' },
      { where: 'PKCE `S256`', hash: 'SHA-256',
        what: 'Over the code verifier. In RFC 9700 mode `plain` is withdrawn ' +
              'and this becomes the only method advertised.' },
      { where: 'OIDC `at_hash` / `c_hash`', hash: 'SHA-256, left half',
        what: 'Section 3.1.3.6: the left-most half of the digest of the ' +
              'ASCII token, base64url. The half is the part people leave ' +
              'out.' },
      { where: 'SD-JWT `_sd_alg`', hash: 'sha-256',
        what: 'Every disclosure digest in an SD-JWT VC.' },
      { where: 'WebAuthn client data hash', hash: 'SHA-256',
        what: 'The signature covers `authenticatorData || ' +
              'SHA-256(clientDataJSON)`, and the RP ID hash inside that ' +
              'authenticator data is SHA-256 of the origin\'s domain, ' +
              'compared byte for byte.' },
      { where: 'SPIFFE SVID identity', hash: 'SHA-256',
        what: 'Over the SVID\'s DER, wherever an issuance is recorded ' +
              'against a directory entry.' },
      { where: 'Key identifiers (`kid`)', hash: 'SHA-256, truncated',
        what: 'A `kid` names a KEY and is therefore DERIVED from the key\'s ' +
              'own public material. It was a constant once, so two instances ' +
              'of this mock published one name over two different keys — a ' +
              'verifier matches the kid exactly, tries that key, and reports ' +
              'a bad signature.' },
      { where: 'Kerberos string-to-key', hash: 'PBKDF2-HMAC-SHA1 / SHA-256 / SHA-384',
        what: 'RFC 3962 for the AES-SHA1 profiles and RFC 8009 for the ' +
              'AES-SHA2 ones. The iteration count and the salt come off the ' +
              'KDC\'s ETYPE-INFO2.' }
    ],
    weak: [
      { hash: 'SHA-1', where: 'XMLDSIG `#sha1` and `rsa-sha1`; ' +
              'RSA-OAEP-MGF1P; Kerberos etypes 17 and 18\'s HMAC-SHA1-96',
        why: 'The XMLDSIG spellings are the original 2000 recommendation and ' +
             'are what a great many deployed relying parties still send. ' +
             '`rsa-oaep-mgf1p` IS SHA-1 by definition — the URI means it — ' +
             'and the newer `rsa-oaep` carries its digest in a child element ' +
             'and is deliberately not offered, because a service provider ' +
             'that can do that can do GCM too. HMAC-SHA1-96 in RFC 3962 is a ' +
             'MAC rather than a collision-resistance claim and is what ' +
             'Active Directory uses to this day.' },
      { hash: 'MD5', where: 'Kerberos RC4-HMAC (etype 23); HTTP Digest',
        why: 'RC4-HMAC is what most of the installed base of Kerberos ' +
             'clients falls back to, and MD5 Digest is what most of the ' +
             'installed base of Digest clients speaks. Both are offered ' +
             'LAST and neither is a recommendation.' },
      { hash: 'MD4', where: 'The NT hash, inside RC4-HMAC\'s string-to-key',
        why: 'It is what the etype is. It is unsalted, which is why salt ' +
             'discovery matters only for AES.' }
    ]
  };
  log.debug("Leaving hashing(). " + out.jws.length + " JWS digest(s), " +
            out.fixed.length + " fixed use(s).");
  return out;
}

// ---------------------------------------------------------------------------
// SIGNATURES AND MACS. Four tables, all read from the module that performs the
// algorithm.
//
// The JWS rows carry `asymmetric` and `postQuantum` because several
// specifications say "an asymmetric algorithm, never a MAC and never none" —
// DPoP proofs (RFC 9449 section 4.2), OID4VCI proofs of possession and request
// objects are all in that class — and because the post-quantum split is what
// the section further down is built on. Both are computed from the shared
// table rather than listed, so neither can fall behind it.
// ---------------------------------------------------------------------------
function signatures() {
  log.debug("Entering signatures().");
  const composites = Object.keys(pqJose.COMPOSITES || {});
  const out = {
    jws: stsCrypto.JWS_SIGNING_ALGS.map(function (alg) {
      const spec = stsCrypto.JWS_ALGS[alg];
      return {
        alg: alg,
        family: spec.family,
        kty: spec.kty || 'oct',
        crv: spec.crv || '',
        hash: spec.hash || '',
        asymmetric: stsCrypto.JWS_ASYMMETRIC_ALGS.indexOf(alg) >= 0,
        postQuantum: spec.family === 'pq',
        composite: composites.indexOf(alg) >= 0,
        dpop: dpop.SIGNING_ALGS.indexOf(alg) >= 0
      };
    }),
    xml: Object.keys(xmldsig.SIG_METHODS).map(function (uri) {
      const spec = xmldsig.SIG_METHODS[uri];
      return { uri: uri, label: spec.label, family: spec.family,
               hash: spec.hash, keyKind: spec.keyKind,
               // What this service will SIGN with, as opposed to verify. One
               // row, and it is worth saying which: six signers used to type
               // this URI out separately.
               signsWith: uri ===
                 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' };
    }),
    canonicalization: Object.keys(xmldsig.C14N_METHODS).map(function (uri) {
      const spec = xmldsig.C14N_METHODS[uri];
      return { uri: uri, label: spec.label, exclusive: spec.exclusive,
               comments: spec.comments,
               // Exclusive without comments is the default at every call site
               // here and no caller overrides it — see the c14n row in
               // STANDARDS for why that is load-bearing rather than a taste.
               usedHere: spec.exclusive && !spec.comments };
    }),
    cose: Object.keys(webauthn.COSE_ALGS).map(function (id) {
      return { coseAlg: Number(id), jose: webauthn.COSE_ALGS[id] };
    }),
    other: [
      { name: bbs2023.CRYPTOSUITE,
        what: 'BLS12-381 G2 with the SHA-256 ciphersuite, as a W3C Data ' +
              'Integrity proof. The only pairing-based signature here, and ' +
              'the only selective disclosure that is not hashing.' },
      { name: 'HOBA algorithm ' + String(scimAuth.HOBA_ALG_RSA_SHA256) +
              ' (RSA-SHA256)',
        what: 'RFC 7486. Over a blob of nonce, algorithm, origin, realm, key ' +
              'id and the server\'s challenge, against a public key the ' +
              'client registered.' },
      { name: 'Kerberos keyed checksums',
        what: 'HMAC-SHA1-96 (etypes 17, 18), HMAC-SHA-256-128 (19), ' +
              'HMAC-SHA-384-192 (20) and HMAC-MD5 (23), each under a key ' +
              'derived from the long-term key for that message\'s KEY USAGE ' +
              'NUMBER. The usage numbers are the thing that goes wrong: the ' +
              'wrong one produces a checksum mismatch and no other symptom.' },
      { name: 'X.509 certificate signatures',
        what: 'SHA-256 with RSA for the signing and TLS certificates; ' +
              'whatever `spiffe.x509KeyType` implies for an SVID.' }
    ]
  };
  log.debug("Leaving signatures(). " + out.jws.length + " JWS, " +
            out.xml.length + " XML, " + out.cose.length + " COSE.");
  return out;
}

// ---------------------------------------------------------------------------
// ENCRYPTION AND KEY TRANSPORT.
//
// The XML half shows the CONFIGURED choice beside the offered list, because
// both are runtime settings on `/admin/saml2` and a page that showed only what
// is possible would not answer "what will the next assertion actually use".
// ---------------------------------------------------------------------------
function encryption() {
  log.debug("Entering encryption().");
  const out = {
    jwe: {
      keyManagementOut: stsCrypto.JWE_ALGS.slice(0),
      keyManagementIn: stsCrypto.JWE_DECRYPT_ALGS.slice(0),
      contentEncryption: Object.keys(stsCrypto.JWE_ENCS).map(function (enc) {
        const spec = stsCrypto.JWE_ENCS[enc];
        return { enc: enc, bits: spec.bits, mode: spec.mode,
                 cekBytes: spec.cekBytes,
                 authenticated: true,
                 // Both modes authenticate; they differ in HOW, and the
                 // difference is where the bug was. A CBC-HMAC CEK carries a
                 // MAC key in FRONT of the AES key, which is why `cekBytes` is
                 // twice `bits/8` — splitting it the wrong way round is a
                 // ciphertext that decrypts to garbage with a valid tag.
                 note: spec.mode === 'gcm'
                   ? 'AEAD: one key, one tag.'
                   : 'The CEK is a MAC key followed by the AES key, and the ' +
                     'tag is HMAC-' + String(spec.hash).toUpperCase() +
                     ' truncated to half its length.' };
      })
    },
    xml: {
      blockCiphers: Object.keys(stsCrypto.BLOCK_CIPHERS).map(function (name) {
        const spec = stsCrypto.BLOCK_CIPHERS[name];
        return { name: name, uri: spec.uri, keyBits: spec.keyBytes * 8,
                 mode: spec.mode, ivBytes: spec.ivBytes,
                 authenticated: spec.tagBytes > 0 };
      }),
      keyTransports: Object.keys(stsCrypto.KEY_TRANSPORTS).map(function (name) {
        const spec = stsCrypto.KEY_TRANSPORTS[name];
        return { name: name, uri: spec.uri, scheme: spec.scheme,
                 safe: spec.scheme === 'RSA-OAEP' };
      }),
      configured: {
        blockCipher: String(config.value('saml2.encryptionAlgorithm')),
        keyTransport: String(config.value('saml2.keyTransportAlgorithm')),
        encryptAssertion: !!config.value('saml2.encryptAssertion'),
        encryptLogoutNameId: !!config.value('saml2.encryptLogoutNameId')
      }
    },
    kerberos: kerberosEtypes(),
    tls: {
      what: 'Node\'s OpenSSL defaults, unnarrowed. This service chooses no ' +
            'cipher suite, no protocol floor and no curve — what it ' +
            'configures is which sockets are TLS and which certificate they ' +
            'serve.',
      sockets: ['main port (when global.https is on)', '8443 (TLS)',
                '9443 (mutual TLS)', 'LDAPS 636']
    }
  };
  log.debug("Leaving encryption(). " + out.xml.blockCiphers.length +
            " XML cipher(s), " + out.kerberos.performed.length +
            " Kerberos etype(s).");
  return out;
}

// ---------------------------------------------------------------------------
// POST-QUANTUM READINESS, SURFACE BY SURFACE.
//
// THE HEADLINE IS ONE SENTENCE AND IT IS NOT THE FLATTERING ONE: this service's
// SIGNATURES are partly post-quantum and its KEY ESTABLISHMENT is entirely
// classical. Those two halves are in very different positions and a page that
// reported "we support ML-DSA" without separating them would be the kind of
// claim this repository exists not to make.
//
// The reason they differ is the threat and not the effort. A signature is
// verified at the moment it is presented, so a signature algorithm that falls
// to a quantum computer in 2035 is a problem in 2035. A KEY AGREEMENT is not:
// ciphertext captured today can be kept and opened when the machine arrives,
// which is what "harvest now, decrypt later" names. So the surface that most
// needs a post-quantum answer here is the one that has none — there is no
// ML-KEM anywhere in this process, in JWE, in XML Encryption or in TLS.
//
// THE THIRD CATEGORY IS THE ONE PEOPLE GET WRONG. Symmetric ciphers and hashes
// are not broken by Shor's algorithm; Grover's costs a square root, which is
// answered by doubling the key. AES-256 and SHA-384 are therefore in a
// perfectly good position, AES-128 and SHA-256 are at a reduced margin that
// NIST still considers adequate, and RC4, MD5 and MD4 are broken for reasons
// that have nothing to do with quantum computers at all. So Kerberos here — the
// one family with no public-key cryptography in it — is the family least
// affected, which is exactly the opposite of what its reputation suggests.
//
// `state` is one of:
//   `pq`         a post-quantum algorithm can be selected on this surface today
//   `classical`  it cannot, and the algorithm is one Shor's algorithm breaks
//   `symmetric`  no public-key cryptography is involved; Grover applies and the
//                margin is what the key length says
// ---------------------------------------------------------------------------
function postQuantum() {
  log.debug("Entering postQuantum().");
  const composites = Object.keys(pqJose.COMPOSITES || {});
  const pure = pqJose.PQ_ALGS.filter(function (alg) {
    return composites.indexOf(alg) < 0;
  });
  const out = {
    algorithms: {
      mlDsa: pure.filter(function (a) { return a.indexOf('ML-DSA') === 0; }),
      slhDsa: pure.filter(function (a) { return a.indexOf('SLH-DSA') === 0; }),
      composite: composites.map(function (alg) {
        const spec = pqJose.COMPOSITES[alg];
        return { alg: alg, mlDsa: spec.ml, traditional: spec.trad,
                 prehash: spec.ph, domainSeparator: spec.label };
      }),
      keyType: 'AKP (RFC 9964)',
      what: 'ML-DSA is FIPS 204 and SLH-DSA is FIPS 205 — a lattice ' +
            'signature and a hash-based one, which are different bets and ' +
            'are both here for that reason. The six COMPOSITES are ' +
            'draft-ietf-jose-pq-composite-sigs: one ML-DSA signature and one ' +
            'traditional signature over the same message, both of which must ' +
            'verify, so the pair is no weaker than its stronger half. Each ' +
            'carries a DOMAIN SEPARATOR into both the composite message and ' +
            'the ML-DSA context string, which is what stops a signature made ' +
            'for one composite being replayed as another.',
      independence: 'The lattice PRIMITIVE is @noble/post-quantum, shared ' +
                    'with the debugger because there is no second ' +
                    'implementation of ML-DSA to be had — node has none. ' +
                    'EVERYTHING AROUND IT is written here from the ' +
                    'specifications, and the traditional half of every ' +
                    'composite runs on node\'s OpenSSL rather than on the ' +
                    'curve library the far end uses. That is where the ' +
                    'cross-check has any value: a shared misunderstanding ' +
                    'about the framing would agree with itself perfectly and ' +
                    'interoperate with nothing.'
    },
    signatures: [
      { surface: 'ID Token', state: 'pq',
        how: 'A client registers `id_token_signed_response_alg`, and the ' +
             'advertised list IS the shared JWS table — so every ML-DSA, ' +
             'SLH-DSA and composite algorithm is selectable.' },
      { surface: 'Signed UserInfo response', state: 'pq',
        how: 'The post-quantum entries are taken from the shared table by a ' +
             'filter rather than listed, so this list cannot fall behind it.' },
      { surface: 'JWKS publication', state: 'pq',
        how: 'Every post-quantum key is published as an `AKP` JWK with a ' +
             '`kid` of its own, so a client can actually VERIFY one rather ' +
             'than merely be offered it. They are made on FIRST USE, which ' +
             'is what makes the first JWKS fetch on a realm slow.' },
      { surface: 'Access tokens and refresh tokens', state: 'classical',
        how: 'RS256, always. `signJwt()` is the one path that records a ' +
             'token in the console\'s counters and it signs with the ' +
             'realm\'s RSA key.' },
      { surface: 'DPoP proofs', state: 'classical',
        how: 'DELIBERATELY, and it is the most interesting exclusion here. ' +
             'A DPoP proof is bound through `cnf.jkt`, the RFC 7638 JWK ' +
             'Thumbprint — and RFC 7638 defines the required members for ' +
             'RSA, EC, OKP and oct only. An ML-DSA key is `kty: "AKP"`, for ' +
             'which no thumbprint is registered, so a proof signed with one ' +
             'would verify perfectly and bind to NOTHING. The gap is in the ' +
             'binding, not in the signature.' },
      { surface: 'Every XML signature — SAML 2.0, SAML 1.1, WS-Federation, ' +
                 'WS-Trust, federation', state: 'classical',
        how: 'RSA-SHA256. XMLDSIG has no registered post-quantum ' +
             'SignatureMethod, so there is nothing to select: this is a gap ' +
             'in the specification stack rather than in this service.' },
      { surface: 'X.509 certificates and SPIFFE SVIDs', state: 'classical',
        how: 'RSA 2048 or an elliptic curve. The SPIFFE authority key types ' +
             'are EC P-256/384/521, RSA 2048/4096 and Ed25519 — all broken ' +
             'by Shor.' },
      { surface: 'Verifiable credentials', state: 'classical',
        how: 'RS256 for an SD-JWT VC, and `bbs-2023` for an `ldp_vc` — a ' +
             'pairing-based signature, which is if anything MORE exposed ' +
             'than plain ECDSA.' },
      { surface: 'WebAuthn assertions', state: 'classical',
        how: 'ES256, RS256 or EdDSA, and it is not this service\'s choice: ' +
             'the AUTHENTICATOR signs, and COSE registers no post-quantum ' +
             'algorithm that a platform authenticator produces.' }
    ],
    keyEstablishment: {
      state: 'classical',
      mechanisms: stsCrypto.JWE_ALGS
        .concat(Object.keys(stsCrypto.KEY_TRANSPORTS).map(function (name) {
          return stsCrypto.KEY_TRANSPORTS[name].scheme + ' (XML ' + name + ')';
        }))
        .concat(['TLS key exchange — node\'s OpenSSL defaults']),
      what: 'EVERY ONE OF THEM IS BROKEN BY SHOR\'S ALGORITHM, and there is ' +
            'no ML-KEM anywhere in this process — not in JWE, not in XML ' +
            'Encryption, not on any of the five TLS sockets. THIS IS THE ' +
            'HALF THAT MATTERS SOONEST: a signature is checked when it is ' +
            'presented, so a signature algorithm that falls in 2035 is a ' +
            'problem in 2035, while ciphertext captured today can be kept ' +
            'and opened when the machine arrives. Nothing this service ' +
            'encrypts is a real secret, which is why this is a fidelity gap ' +
            'here and would be a serious one anywhere else.',
      whatWouldClose: 'draft-ietf-jose-pq-kem would add `ML-KEM` as a JWE ' +
                      '`alg`, and a hybrid TLS group (X25519MLKEM768) needs ' +
                      'only an OpenSSL that offers it. Neither is here, and ' +
                      'this row says so rather than leaving the ' +
                      'post-quantum signatures above to imply otherwise.'
    },
    symmetric: {
      state: 'symmetric',
      what: 'Grover\'s algorithm costs a square root rather than breaking ' +
            'these outright, so the answer is key length. AES-256 and ' +
            'SHA-384 are unaffected in any practical sense; AES-128 and ' +
            'SHA-256 keep a reduced margin that is still considered ' +
            'adequate. KERBEROS IS THEREFORE THE FAMILY HERE LEAST AFFECTED ' +
            'BY ANY OF THIS — it is the only one with no public-key ' +
            'cryptography in it at all — which is the opposite of what its ' +
            'reputation suggests. What is wrong with RC4-HMAC, MD5 and MD4 ' +
            'has nothing to do with quantum computers.',
      strongest: 'aes256-cts-hmac-sha384-192 (etype 20), AES-256-GCM for ' +
                 'XML Encryption, A256GCM for JWE.'
    }
  };
  log.debug("Leaving postQuantum(). " + out.algorithms.mlDsa.length +
            " ML-DSA, " + out.algorithms.slhDsa.length + " SLH-DSA, " +
            out.algorithms.composite.length + " composite.");
  return out;
}

// ---------------------------------------------------------------------------
// THE WHOLE REPORT, ONCE. Both the page and `GET /admin-api/crypto` are built
// from this — the API mirrors the console rather than computing its own answer,
// which is rule 7 and is why the parity check is a property of the code rather
// than a promise in a comment.
// ---------------------------------------------------------------------------
function cryptoJson(base) {
  log.debug("Entering cryptoJson().");
  const report = {
    issuer: base,
    realm: realms.currentId(),
    generatedAt: new Date().toISOString(),
    oneModule: 'common/crypto.js is the one place this service signs, ' +
               'verifies, encrypts and decrypts. Before 2026-08-27 it did all ' +
               'four in about twenty places, including six XML signers and ' +
               'four XML signature verifiers.',
    drift: driftReport(),
    keys: keyMaterial(),
    families: FAMILIES.map(function (row) {
      return {
        name: row.name,
        signs: row.signs, verifies: row.verifies,
        encrypts: row.encrypts, decrypts: row.decrypts,
        hashes: row.hashes,
        whatItDoesNot: row.whatItDoesNot,
        envelopes: row.envelopes.slice(0),
        algorithms: row.algorithms().map(function (pair) {
          return { what: pair[0], values: pair[1] };
        })
      };
    }),
    hashing: hashing(),
    signatures: signatures(),
    encryption: encryption(),
    postQuantum: postQuantum(),
    standards: STANDARDS.map(function (row) {
      return { key: row.key, name: row.name, specs: row.specs.slice(0),
               coverage: row.coverage, what: row.what };
    })
  };
  log.debug("Leaving cryptoJson(). " + report.families.length +
            " family/families, " + report.standards.length + " standard(s).");
  return report;
}

// --- rendering --------------------------------------------------------------

// ---------------------------------------------------------------------------
// PROSE FOR THE PAGE. The tables above are written with `backticks` around
// identifiers, because the SAME strings are served as JSON at `?format=json`
// and on `/admin-api/crypto`, where the convention every description in this
// service follows is markdown — `mgmt-api/admin_api.js`'s operation
// descriptions are full of them.
//
// So the conversion belongs HERE, in the renderer, and nowhere else: the JSON
// keeps its backticks and the page gets `<code>`. ESCAPING HAPPENS FIRST and
// the substitution second, which is the order that matters — the content
// between a pair of backticks has already been through `esc()` by the time
// this looks at it, so nothing inside one can close the element it is about to
// be put in.
// ---------------------------------------------------------------------------
function prose(text) {
  return esc(String(text == null ? '' : text))
    .replace(/`([^`]+)`/g, '<code>$1</code>');
}

// A list of algorithm names as code chips. Empty renders as an em dash rather
// than as nothing, because an empty cell and a cell this function has not
// reached look identical and only one of them is a fact.
function chips(values) {
  if (!values || !values.length) {
    return '<span class="why">—</span>';
  }
  return values.map(function (one) {
    return '<code>' + esc(String(one)) + '</code>';
  }).join(' ');
}

// One verb's cell in the family table. An empty string means this service does
// not do it in that family, which is a claim and is drawn as one.
function verbCell(text) {
  if (!text) {
    return '<span class="why">does not</span>';
  }
  return prose(text);
}

function anchorFor(name) {
  return 'fam-' + String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

function renderFamilies(report) {
  log.debug("Entering renderFamilies().");
  let html = '<h2 id="families">The identity services this mock advertises</h2>' +
    '<p class="lead">One row per protocol family on ' +
    '<a href="/admin/sts-metadata">Service metadata</a>, with what each does ' +
    'with cryptography. The four verbs are kept apart on purpose: signing is ' +
    'minting something a relying party will believe, verifying is a decision ' +
    'that can be got wrong, encrypting uses somebody else\'s key, and ' +
    'decrypting means holding a private key a caller can aim ciphertext at. ' +
    'Those are four different exposures and this service does a different ' +
    'amount of each.</p>';

  const drift = report.drift;
  if (!drift.checked) {
    html += admin.warn('<strong>The family list was not checked against the ' +
      'service metadata.</strong> This page names the identity services it ' +
      'reports on, and <code>/admin/sts-metadata</code> names the ones this ' +
      'process advertises; normally that module hands its list over at ' +
      'require time and both directions of drift are reported here. It did ' +
      'not, so the table below is this file\'s own word for what the service ' +
      'offers.');
  } else if (drift.undescribed.length || drift.stale.length ||
             drift.envelopes.length) {
    html += admin.warn('<strong>This page and the service metadata disagree.' +
      '</strong> ' +
      (drift.undescribed.length
        ? 'Advertised with no crypto profile here: ' +
          chips(drift.undescribed) + '. '
        : '') +
      (drift.stale.length
        ? 'Profiled here and not advertised — which is what a rename ' +
          'produces: ' + chips(drift.stale) + '. '
        : '') +
      (drift.envelopes.length
        ? 'Citing an envelope with no row in the standards table: ' +
          chips(drift.envelopes) + '. '
        : '') +
      'Both directions are reported rather than reconciled, for the reason ' +
      '<code>/admin/sts-metadata</code> reports both directions of endpoint ' +
      'drift: the one that is silent is the one that costs an afternoon.');
  } else {
    html += '<p class="why">Checked against the service metadata: all ' +
      esc(report.families.length) + ' advertised families have a profile ' +
      'here, none is profiled that is not advertised, and every envelope ' +
      'cited has a row below.</p>';
  }

  html += '<table><thead><tr><th class="n">Identity service</th>' +
    '<th>Signs</th><th>Verifies</th><th>Encrypts</th><th>Decrypts</th>' +
    '</tr></thead><tbody>' +
    report.families.map(function (row) {
      return '<tr><td class="n"><a href="#' + esc(anchorFor(row.name)) +
        '">' + esc(row.name) + '</a></td>' +
        '<td>' + verbCell(row.signs) + '</td>' +
        '<td>' + verbCell(row.verifies) + '</td>' +
        '<td>' + verbCell(row.encrypts) + '</td>' +
        '<td>' + verbCell(row.decrypts) + '</td></tr>';
    }).join('') + '</tbody></table>';

  report.families.forEach(function (row) {
    html += '<h3 id="' + esc(anchorFor(row.name)) + '">' + esc(row.name) +
      '</h3>' +
      '<table><tbody>' +
      '<tr><th class="n">Hashing</th><td>' + prose(row.hashes) + '</td></tr>' +
      row.algorithms.map(function (group) {
        return '<tr><th class="n">' + esc(group.what) + '</th><td>' +
          chips(group.values) + '</td></tr>';
      }).join('') +
      '<tr><th class="n">Envelopes</th><td>' +
      row.envelopes.map(function (key) {
        const std = STANDARDS.filter(function (s) { return s.key === key; })[0];
        return std ? '<a href="#std-' + esc(key) + '">' + esc(std.name) +
                     '</a>' : '<code>' + esc(key) + '</code>';
      }).join(', ') + '</td></tr>' +
      '</tbody></table>' +
      admin.note('<strong>What it deliberately does not do.</strong> ' +
                 prose(row.whatItDoesNot));
  });
  log.debug("Leaving renderFamilies().");
  return html;
}

function renderKeys(report) {
  log.debug("Entering renderKeys().");
  const keys = report.keys;
  let html = '<h2 id="keys">The key material this process holds</h2>' +
    '<p class="lead">Every key here is generated at start and none of them is ' +
    'persisted, in any persistence mode. That is deliberate and two things ' +
    'depend on it: the <code>kid</code> is derived from the key material, so ' +
    'two instances of this mock cannot publish one name over two different ' +
    'keys, and every document that carries or describes a key is served ' +
    '<code>Cache-Control: no-store</code>. <strong>The signing keys are per ' +
    'trust realm; the TLS certificate and the SPIFFE authorities are ' +
    'not.</strong> This shows realm <code>' + esc(keys.realm) + '</code>.</p>';

  html += '<table><thead><tr><th class="n">Key</th><th>Type</th>' +
    '<th>Identifier</th><th>Scope</th></tr></thead><tbody>' +
    '<tr><td class="n">Signing key</td><td><code>RSA 2048</code> ' +
    '<code>RS256</code></td><td><code>' + esc(keys.signing.kid) +
    '</code></td><td>this realm</td></tr>' +
    keys.curveKeys.map(function (one) {
      return '<tr><td class="n">Curve key</td><td><code>' + esc(one.alg) +
        '</code> <code>' + esc(one.kty) +
        (one.crv ? '</code> <code>' + esc(one.crv) : '') +
        '</code></td><td><code>' + esc(one.kid) +
        '</code></td><td>this realm</td></tr>';
    }).join('') +
    (keys.postQuantum.generated
      ? keys.postQuantum.keys.map(function (one) {
          return '<tr><td class="n">Post-quantum key</td><td><code>' +
            esc(one.alg) + '</code> <code>AKP</code></td><td><code>' +
            esc(one.kid) + '</code></td><td>this realm</td></tr>';
        }).join('')
      : '<tr><td class="n">Post-quantum keys</td><td><code>AKP</code>, ' +
        esc(keys.postQuantum.algorithms.length) +
        ' algorithms</td><td><span class="why">not made yet in this realm' +
        '</span></td><td>this realm</td></tr>') +
    '<tr><td class="n">BBS key</td><td><code>' +
    esc(keys.bbs.cryptosuite) + '</code> ' + esc(keys.bbs.curve) +
    '</td><td><span class="why">published as publicKeyMultibase</span></td>' +
    '<td>this realm</td></tr>' +
    '<tr><td class="n">TLS certificate</td><td><code>RSA 2048</code> ' +
    '<code>SHA-256</code></td><td><code>' + esc(keys.tls.fingerprint256) +
    '</code></td><td>the process</td></tr>' +
    '<tr><td class="n">SPIFFE X.509 authority</td><td><code>' +
    esc(keys.spiffe.x509KeyType) + '</code></td><td>' +
    (keys.spiffe.ready ? esc(keys.spiffe.x509Authorities) + ' authority/ies'
                       : '<span class="why">not started</span>') +
    '</td><td>the process</td></tr>' +
    '<tr><td class="n">SPIFFE JWT authority</td><td><code>' +
    esc(keys.spiffe.jwtKeyType) + '</code></td><td>' +
    (keys.spiffe.ready ? esc(keys.spiffe.jwtAuthorities) + ' authority/ies'
                       : '<span class="why">not started</span>') +
    '</td><td>the process</td></tr>' +
    '</tbody></table>';

  html += admin.note('<strong>The post-quantum and BBS keys are made on ' +
    'first use, not at start.</strong> ' + prose(keys.postQuantum.what) +
    ' The consequence a reader meets is that the first JWKS fetch on a realm ' +
    'is slow — about two seconds, nearly all of it one SLH-DSA keygen — and ' +
    'every one after it is not.');
  html += admin.note('<strong>Nothing on this page is a secret.</strong> Key ' +
    'types, key identifiers, curve names, certificate fingerprints and ' +
    'validity dates are all readable already from <code>/oauth2/jwks</code>, ' +
    '<code>/tls/server-certificate</code> and the SPIFFE bundle endpoint. ' +
    'That is a rule for anything added here later rather than an observation ' +
    'about what is here now: a page about cryptography is exactly the page ' +
    'somebody would think to put a private key on.');
  log.debug("Leaving renderKeys().");
  return html;
}

function renderHashing(report) {
  log.debug("Entering renderHashing().");
  const h = report.hashing;
  let html = '<h2 id="hashing">Hashing</h2>' +
    '<p class="lead">Every digest this service computes. The first three ' +
    'tables are read from the modules that compute them; the fourth cannot ' +
    'be, because "SHA-256, because RFC 7638 says so" is a fact about a ' +
    'specification and not a row in a table — so each of those names the ' +
    'mechanism it belongs to.</p>';

  html += '<table><tbody>' +
    '<tr><th class="n">Digests behind the JWS algorithms</th><td>' +
    chips(h.jws) + ' <span class="why">EdDSA and the post-quantum ' +
    'algorithms name none — Ed25519 hashes internally and ML-DSA takes the ' +
    'message</span></td></tr>' +
    '<tr><th class="n">HTTP Digest (SCIM)</th><td>' +
    chips(h.scimDigest.map(function (r) { return r.token; })) +
    ' <span class="why">strongest first, and each checked against the ' +
    'openssl this process actually has</span></td></tr>' +
    '</tbody></table>';

  html += '<h3>XML DigestMethod</h3><table><thead><tr><th class="n">URI</th>' +
    '<th>Label</th></tr></thead><tbody>' +
    h.xmlDigestMethods.map(function (row) {
      return '<tr><td class="n"><code>' + esc(row.uri) + '</code></td><td>' +
        esc(row.label) + '</td></tr>';
    }).join('') + '</tbody></table>';

  html += '<h3>Fixed uses</h3><table><thead><tr><th class="n">Where</th>' +
    '<th>Digest</th><th>What</th></tr></thead><tbody>' +
    h.fixed.map(function (row) {
      return '<tr><td class="n">' + prose(row.where) + '</td><td><code>' +
        esc(row.hash) + '</code></td><td>' + prose(row.what) + '</td></tr>';
    }).join('') + '</tbody></table>';

  html += '<h3>The weak ones, and why they are here</h3>' +
    admin.note('<strong>None of these is an oversight and none is a ' +
      'recommendation.</strong> This service exists to exercise other ' +
      'people\'s clients, and a mock that offered only the safe choice could ' +
      'not be used to show what the unsafe one does. Each row says which ' +
      'installed base asks for it.') +
    '<table><thead><tr><th class="n">Digest</th><th>Where</th><th>Why</th>' +
    '</tr></thead><tbody>' +
    h.weak.map(function (row) {
      return '<tr><td class="n"><code>' + esc(row.hash) + '</code></td><td>' +
        prose(row.where) + '</td><td>' + prose(row.why) + '</td></tr>';
    }).join('') + '</tbody></table>';
  log.debug("Leaving renderHashing().");
  return html;
}

function renderSignatures(report) {
  log.debug("Entering renderSignatures().");
  const s = report.signatures;
  let html = '<h2 id="signatures">Signatures and MACs</h2>' +
    '<p class="lead">Read from the module that performs each one. The JWS ' +
    'table is <em>the</em> table for this service — there were two once, ' +
    'which is how DPoP came to accept a different set of algorithms from ' +
    'everything else for no reason anybody chose.</p>';

  html += '<h3>JWS</h3><table><thead><tr><th class="n">alg</th><th>Family</th>' +
    '<th>Key</th><th>Digest</th><th>Asymmetric</th><th>DPoP</th>' +
    '</tr></thead><tbody>' +
    s.jws.map(function (row) {
      return '<tr><td class="n"><code>' + esc(row.alg) + '</code></td>' +
        '<td>' + esc(row.family) +
        (row.composite ? ' <span class="why">composite</span>' : '') + '</td>' +
        '<td><code>' + esc(row.kty) + '</code>' +
        (row.crv ? ' <code>' + esc(row.crv) + '</code>' : '') + '</td>' +
        '<td>' + (row.hash ? '<code>' + esc(row.hash) + '</code>'
                           : '<span class="why">none</span>') + '</td>' +
        '<td>' + (row.asymmetric ? 'yes' : 'no — a MAC') + '</td>' +
        '<td>' + (row.dpop ? 'yes' : 'no') + '</td></tr>';
    }).join('') + '</tbody></table>' +
    admin.note('<strong>The DPoP column is a filter over this table and not ' +
      'a table of its own.</strong> It excludes the HMAC family because RFC ' +
      '9449 section 4.2 requires an asymmetric algorithm, and it excludes ' +
      'every post-quantum one because a DPoP proof is bound through the RFC ' +
      '7638 thumbprint — which is defined for RSA, EC, OKP and oct and not ' +
      'for <code>AKP</code>. A proof signed with ML-DSA would verify ' +
      'perfectly and bind to nothing, which is worse than a refusal.');

  html += '<h3>XML SignatureMethod</h3>' +
    '<p class="lead">This service <strong>signs</strong> with one of these ' +
    'and <strong>verifies</strong> any of them — the asymmetry is the point ' +
    'of the vendored implementation, which is the other end of most of these ' +
    'exchanges.</p>' +
    '<table><thead><tr><th class="n">URI</th><th>Label</th><th>Key</th>' +
    '<th>Signs with</th></tr></thead><tbody>' +
    s.xml.map(function (row) {
      return '<tr><td class="n"><code>' + esc(row.uri) + '</code></td><td>' +
        esc(row.label) + '</td><td><code>' + esc(row.keyKind) +
        '</code></td><td>' + (row.signsWith ? 'yes' : '<span class="why">' +
        'verify only</span>') + '</td></tr>';
    }).join('') + '</tbody></table>';

  html += '<h3>Canonicalization</h3>' +
    '<table><thead><tr><th class="n">URI</th><th>Label</th>' +
    '<th>Used here</th></tr></thead><tbody>' +
    s.canonicalization.map(function (row) {
      return '<tr><td class="n"><code>' + esc(row.uri) + '</code></td><td>' +
        esc(row.label) + '</td><td>' + (row.usedHere
          ? 'yes — the default at every call site'
          : '<span class="why">read only</span>') + '</td></tr>';
    }).join('') + '</tbody></table>' +
    admin.note('<strong>Exclusive canonicalization is load-bearing here and ' +
      'not a matter of taste.</strong> An assertion is signed as a standalone ' +
      'document and then embedded inside an RSTR, a Response or a ' +
      '<code>wresult</code> that declares prefixes of its own. Inclusive ' +
      'c14n would pull those ancestor declarations into the digest at ' +
      'verification time, so the signature would fail for every relying ' +
      'party while verifying perfectly here — the worst shape of bug to ' +
      'chase. C14N 1.1 is not offered at all: its whole difference is how ' +
      '<code>xml:base</code>, <code>xml:lang</code> and <code>xml:space</code> ' +
      'inherit into a detached subtree, this engine does not implement that ' +
      'inheritance, and an option naming a method it does not perform is ' +
      'worse than an absent one.');

  html += '<h3>COSE (WebAuthn)</h3><table><thead><tr>' +
    '<th class="n">COSE alg</th><th>JOSE name</th></tr></thead><tbody>' +
    s.cose.map(function (row) {
      return '<tr><td class="n"><code>' + esc(row.coseAlg) +
        '</code></td><td><code>' + esc(row.jose) + '</code></td></tr>';
    }).join('') + '</tbody></table>';

  html += '<h3>Everything else</h3><table><thead><tr><th class="n">What</th>' +
    '<th>Detail</th></tr></thead><tbody>' +
    s.other.map(function (row) {
      return '<tr><td class="n">' + esc(row.name) + '</td><td>' +
        prose(row.what) + '</td></tr>';
    }).join('') + '</tbody></table>';
  log.debug("Leaving renderSignatures().");
  return html;
}

function renderEncryption(report) {
  log.debug("Entering renderEncryption().");
  const e = report.encryption;
  let html = '<h2 id="encryption">Encryption and key transport</h2>' +
    '<p class="lead">What this service encrypts with, and — separately — what ' +
    'it will decrypt. The two lists are different on purpose in both JOSE and ' +
    'XML, and the reason is the same each time: it holds one private key of ' +
    'each kind and can encrypt to anybody\'s.</p>';

  html += '<h3>JWE</h3><table><tbody>' +
    '<tr><th class="n">Key management, encrypting</th><td>' +
    chips(e.jwe.keyManagementOut) + '</td></tr>' +
    '<tr><th class="n">Key management, decrypting</th><td>' +
    chips(e.jwe.keyManagementIn) + ' <span class="why">shorter on purpose: ' +
    'what it receives is encrypted to the RSA key it publishes, and it holds ' +
    'no EC private key to agree with</span></td></tr>' +
    '</tbody></table>' +
    '<table><thead><tr><th class="n">enc</th><th>Bits</th><th>Mode</th>' +
    '<th>CEK</th><th>Note</th></tr></thead><tbody>' +
    e.jwe.contentEncryption.map(function (row) {
      return '<tr><td class="n"><code>' + esc(row.enc) + '</code></td><td>' +
        esc(row.bits) + '</td><td><code>' + esc(row.mode) +
        '</code></td><td>' + esc(row.cekBytes) + ' bytes</td><td>' +
        esc(row.note) + '</td></tr>';
    }).join('') + '</tbody></table>' +
    admin.note('<strong>The CBC-HMAC family is here because it is what an ' +
      'OpenID Connect client gets by default.</strong> Register ' +
      '<code>userinfo_encrypted_response_alg</code> and say nothing about ' +
      '<code>enc</code>, and section 2 of the registration specification has ' +
      'chosen <code>A128CBC-HS256</code> for you. A service that spoke only ' +
      'AES-GCM would refuse the commonest encrypted response there is, and ' +
      'would look to the client like it had refused the request.');

  html += '<h3>XML Encryption</h3>' +
    '<p class="lead">The configured choice is what the next encrypted ' +
    'assertion will actually use; both settings are editable on ' +
    '<a href="/admin/saml2">SAML 2.0</a>. Right now: block cipher <code>' +
    esc(e.xml.configured.blockCipher) + '</code>, key transport <code>' +
    esc(e.xml.configured.keyTransport) + '</code>, assertions ' +
    (e.xml.configured.encryptAssertion ? 'encrypted' : 'not encrypted') +
    ', logout NameID ' +
    (e.xml.configured.encryptLogoutNameId ? 'encrypted' : 'not encrypted') +
    '.</p>' +
    '<table><thead><tr><th class="n">Block cipher</th><th>URI</th>' +
    '<th>Key</th><th>Authenticated</th></tr></thead><tbody>' +
    e.xml.blockCiphers.map(function (row) {
      return '<tr><td class="n"><code>' + esc(row.name) +
        '</code></td><td><code>' + esc(row.uri) + '</code></td><td>' +
        esc(row.keyBits) + '-bit ' + esc(row.mode) + '</td><td>' +
        (row.authenticated ? 'yes' : '<strong>no</strong>') + '</td></tr>';
    }).join('') + '</tbody></table>' +
    '<table><thead><tr><th class="n">Key transport</th><th>URI</th>' +
    '<th>Scheme</th></tr></thead><tbody>' +
    e.xml.keyTransports.map(function (row) {
      return '<tr><td class="n"><code>' + esc(row.name) +
        '</code></td><td><code>' + esc(row.uri) + '</code></td><td>' +
        esc(row.scheme) + (row.safe ? '' : ' — <strong>broken</strong>') +
        '</td></tr>';
    }).join('') + '</tbody></table>' +
    admin.warn('<strong>Two of these are unsafe and are offered anyway.</strong> ' +
      'The CBC ciphers are not authenticated — that is the property CBC has, ' +
      'not a defect in this service — and what this service does about it ' +
      'when READING is parse the result and refuse anything that is not ' +
      'well-formed XML, which catches ordinary corruption and is not ' +
      'integrity. <code>rsa-1_5</code> is RSAES-PKCS1-v1_5, which ' +
      'Bleichenbacher\'s adaptive chosen-ciphertext attack is against ' +
      'exactly. Both are here because a great many deployed service ' +
      'providers accept nothing else, which is a fact about the world that a ' +
      'client library is entitled to be tested against. Nothing this service ' +
      'encrypts is a real secret. <code>rsa-oaep-mgf1p</code> is SHA-1 by ' +
      'definition — the URI means it — and the newer <code>rsa-oaep</code> ' +
      'carries its digest in a child element and is deliberately not ' +
      'offered, because a service provider that can read that one can do GCM ' +
      'too and this list exists for the ones that cannot.');

  html += '<h3>Kerberos encryption types</h3>' +
    '<table><thead><tr><th class="n">etype</th><th>Name</th>' +
    '<th>Performed</th></tr></thead><tbody>' +
    e.kerberos.performed.map(function (row) {
      return '<tr><td class="n"><code>' + esc(row.id) +
        '</code></td><td><code>' + esc(row.name) +
        '</code></td><td>yes</td></tr>';
    }).join('') +
    e.kerberos.decodeOnly.map(function (row) {
      return '<tr><td class="n"><code>' + esc(row.id) +
        '</code></td><td><code>' + esc(row.name) +
        '</code></td><td><span class="why">decode only</span></td></tr>';
    }).join('') + '</tbody></table>' +
    admin.note('<strong>The decode-only rows are named rather than left as ' +
      'bare numbers, and that is the whole reason they are in the codec.</strong> ' +
      'A packet capture or a KDC\'s advertised list containing one of them ' +
      'renders honestly instead of showing an integer nobody can look up. ' +
      'DES was removed from Windows Server 2025 and is not performed here ' +
      'either. This table is read back out of the codec through its own ' +
      '<code>etypeName()</code>, not copied — those modules are vendored and ' +
      'cannot be edited to export a list.');

  html += '<h3>TLS</h3>' + admin.note('<strong>' + prose(e.tls.what) +
    '</strong> The sockets: ' + chips(e.tls.sockets) + '.');
  log.debug("Leaving renderEncryption().");
  return html;
}

function renderPostQuantum(report) {
  log.debug("Entering renderPostQuantum().");
  const pq = report.postQuantum;
  let html = '<h2 id="post-quantum">Post-quantum readiness</h2>' +
    '<p class="lead"><strong>The headline is one sentence and it is not the ' +
    'flattering one: this service\'s signatures are partly post-quantum and ' +
    'its key establishment is entirely classical.</strong> Those two halves ' +
    'are in very different positions, and a page that said "supports ML-DSA" ' +
    'without separating them would be making the kind of claim this ' +
    'repository exists not to make.</p>' +
    admin.note('<strong>The two halves differ because of the threat, not the ' +
      'effort.</strong> A signature is verified at the moment it is ' +
      'presented, so a signature algorithm that falls to a quantum computer ' +
      'in 2035 is a problem in 2035. A key agreement is not: ciphertext ' +
      'captured today can be kept and opened when the machine arrives, which ' +
      'is what "harvest now, decrypt later" names. So the surface here that ' +
      'most needs a post-quantum answer is the one that has none.') +
    admin.note('<strong>Symmetric cryptography is a third category and is ' +
      'the one people get wrong.</strong> ' + prose(pq.symmetric.what) +
      ' The strongest this service performs: ' + prose(pq.symmetric.strongest));

  html += '<h3>The post-quantum algorithms this service holds</h3>' +
    '<table><tbody>' +
    '<tr><th class="n">ML-DSA (FIPS 204)</th><td>' + chips(pq.algorithms.mlDsa) +
    '</td></tr>' +
    '<tr><th class="n">SLH-DSA (FIPS 205)</th><td>' + chips(pq.algorithms.slhDsa) +
    '</td></tr>' +
    '<tr><th class="n">Key type</th><td><code>' + esc(pq.algorithms.keyType) +
    '</code></td></tr>' +
    '</tbody></table>' +
    '<table><thead><tr><th class="n">Composite</th><th>ML-DSA half</th>' +
    '<th>Traditional half</th><th>Domain separator</th></tr></thead><tbody>' +
    pq.algorithms.composite.map(function (row) {
      return '<tr><td class="n"><code>' + esc(row.alg) +
        '</code></td><td><code>' + esc(row.mlDsa) +
        '</code></td><td><code>' + esc(row.traditional) +
        '</code></td><td><code>' + esc(row.domainSeparator) +
        '</code></td></tr>';
    }).join('') + '</tbody></table>' +
    admin.note('<strong>What the composites buy, and what the domain ' +
      'separator is for.</strong> ' + prose(pq.algorithms.what)) +
    admin.note('<strong>Where the independence is, and where it is not.</strong> ' +
      prose(pq.algorithms.independence));

  html += '<h3>Signatures, surface by surface</h3>' +
    '<table><thead><tr><th class="n">Surface</th><th>State</th><th>How</th>' +
    '</tr></thead><tbody>' +
    pq.signatures.map(function (row) {
      return '<tr><td class="n">' + esc(row.surface) + '</td><td>' +
        (row.state === 'pq'
          ? '<strong>post-quantum available</strong>'
          : '<span class="why">classical only</span>') +
        '</td><td>' + prose(row.how) + '</td></tr>';
    }).join('') + '</tbody></table>';

  html += '<h3>Key establishment</h3>' +
    admin.warn('<strong>Every key establishment mechanism in this process is ' +
      'classical.</strong> ' + prose(pq.keyEstablishment.what)) +
    '<table><tbody><tr><th class="n">Mechanisms</th><td>' +
    chips(pq.keyEstablishment.mechanisms) + '</td></tr>' +
    '<tr><th class="n">What would close it</th><td>' +
    prose(pq.keyEstablishment.whatWouldClose) + '</td></tr></tbody></table>';
  log.debug("Leaving renderPostQuantum().");
  return html;
}

function renderStandards(report) {
  log.debug("Entering renderStandards().");
  let html = '<h2 id="standards">The higher-level standards</h2>' +
    '<p class="lead">Knowing that this service signs with RSA-SHA256 does not ' +
    'say whether that signature is a JWS, an enveloped XMLDSIG, a detached ' +
    'signature over a query string or a <code>&lt;wsse:Security&gt;</code> ' +
    'header — four different documents with four different failure modes. ' +
    'This is that layer. <strong>Every coverage note starts ' +
    '<code>full</code>, <code>partial</code> or <code>mock</code></strong> ' +
    'and says what is missing, which is the rule ' +
    '<a href="/admin/sts-metadata">Service metadata</a> follows and which is ' +
    'worth more here: a page about cryptography that overstates what it ' +
    'implements is actively dangerous to somebody using it to learn.</p>';

  html += report.standards.map(function (row) {
    return '<h3 id="std-' + esc(row.key) + '">' + esc(row.name) + '</h3>' +
      '<table><tbody>' +
      '<tr><th class="n">Specifications</th><td>' + chips(row.specs) +
      '</td></tr>' +
      '<tr><th class="n">Coverage</th><td>' + prose(row.coverage) + '</td></tr>' +
      '<tr><th class="n">What it is here</th><td>' + prose(row.what) +
      '</td></tr>' +
      '</tbody></table>';
  }).join('');
  log.debug("Leaving renderStandards().");
  return html;
}

function renderInner(report) {
  log.debug("Entering renderInner().");
  let html = '<p class="lead">What this service does when it signs, verifies, ' +
    'encrypts or decrypts something — for every identity service it ' +
    'advertises, with the algorithms each one really uses and the ' +
    'higher-level envelope each is wrapped in. <strong>Every algorithm table ' +
    'below is read from the module that performs the algorithm</strong>, the ' +
    'way <a href="/admin/sts-metadata">Service metadata</a> reads its ' +
    'endpoint list off the live router, so none of it can claim something ' +
    'this service does not do.</p>';

  html += '<p><a class="btn" href="/admin/crypto-metadata?format=json" ' +
    'download="crypto-metadata.json" title="The whole of this page as JSON: ' +
    'every identity service, every algorithm table, the post-quantum ' +
    'posture and the standards list">Download all of this as JSON</a> ' +
    '<span class="why">' + esc(report.families.length) +
    ' identity services, ' + esc(report.signatures.jws.length) +
    ' JWS algorithms, ' + esc(report.standards.length) +
    ' standards</span></p>';

  html += admin.note('<strong>There is one place in this service that signs, ' +
    'verifies, encrypts and decrypts, and this page is its report.</strong> ' +
    'Before 2026-08-27 all four happened in about twenty places: six ' +
    'independent XML signers, four independent XML signature verifiers, ten ' +
    '<code>jwt.verify()</code> calls of which four had quietly stopped ' +
    'applying the configured clock skew, two RFC 7638 thumbprints and two ' +
    'self-signed certificate builders. None of that was carelessness — each ' +
    'was written where it was needed and the copies agreed on the day they ' +
    'were made. What it cost is on the record: every SAML 1.1 assertion this ' +
    'service ever issued carried an <code>Id="_0"</code> attribute the ' +
    'schema does not have, and three of the four verifiers took the FIRST ' +
    '<code>&lt;ds:Signature&gt;</code> in the document — which on a Response ' +
    'carrying a signed assertion is the assertion\'s, so a caller asking "is ' +
    'this Response signed by us" was answered about a different element and ' +
    'told yes.');

  html += '<p class="lead">On this page: ' +
    '<a href="#families">the identity services</a> &middot; ' +
    '<a href="#keys">key material</a> &middot; ' +
    '<a href="#hashing">hashing</a> &middot; ' +
    '<a href="#signatures">signatures and MACs</a> &middot; ' +
    '<a href="#encryption">encryption</a> &middot; ' +
    '<a href="#post-quantum">post-quantum readiness</a> &middot; ' +
    '<a href="#standards">the standards</a></p>';

  html += renderFamilies(report);
  html += renderKeys(report);
  html += renderHashing(report);
  html += renderSignatures(report);
  html += renderEncryption(report);
  html += renderPostQuantum(report);
  html += renderStandards(report);
  log.debug("Leaving renderInner().");
  return html;
}

// ---------------------------------------------------------------------------
// THE ROUTE. Behind the console's gate by construction — admin.js registers its
// one `app.use('/admin', ...)` at require 18 and express applies middleware
// only to routes added after it, and this module is required at 20a. Nothing
// here repeats that check.
//
// `admin.respond()` answers `?format=json` itself, which keeps the
// machine-readable form byte-for-byte the shape every other console page's is:
// 200, `Cache-Control: no-store`, and the JSON this file builds.
// ---------------------------------------------------------------------------
app.get('/admin/crypto-metadata', function (req, res) {
  log.debug("Entering the crypto metadata endpoint.");
  const report = cryptoJson(baseUrlOf(req));
  admin.respond(req, res, report, 'Cryptography', '/admin/crypto-metadata',
                renderInner(report));
  log.debug("Leaving the crypto metadata endpoint. " + report.families.length +
            " identity service(s), " + report.standards.length +
            " standard(s).");
});

// ---------------------------------------------------------------------------
// THE SLOT THIS MODULE FILLS, so that `/admin-api/crypto` can mirror this page
// without `mgmt-api/admin_api.js` requiring this file. Rule 3e's test answers
// yes in both directions and that is why it is a slot rather than a require:
//
//   * a require from `admin_api.js` (19) to this module (20a) would MOVE
//     ROUTES — this page's own, and `tls/tls_server.js`'s three, which this
//     file requires for the server certificate — ahead of the management API's
//     own routes and of ldap, scim and spiffe.
//   * a require from `admin.js` (18) to this module would CLOSE A CYCLE: this
//     file requires that one for the shell.
//
// It carries one function and is validated when it is installed, for the same
// reason `setLogoutReader()` is: a page that could be drawn and an API that
// could not would be the parity rule failing silently, which is the one thing
// that rule exists to make impossible.
// ---------------------------------------------------------------------------
if (typeof admin.setCryptoReporter === 'function') {
  admin.setCryptoReporter(cryptoJson);
} else {
  // An older copy of admin.js, which is a real possibility while this
  // repository is vendored into another one. The PAGE still works — it is
  // registered above and does not go through the slot — and only the API
  // mirror is missing, which is what this line says rather than leaving a
  // 404 to be explained.
  log.error('crypto metadata: this build of admin-ui/admin.js offers no ' +
            'setCryptoReporter(), so /admin/crypto-metadata is drawn and ' +
            'GET /admin-api/crypto will not answer.');
}

module.exports = {
  FAMILIES: FAMILIES,
  STANDARDS: STANDARDS,
  // Filled by ../sts_metadata.js at ITS require time — see the header for why
  // this direction and not the other.
  setProtocolFamilies: setProtocolFamilies,
  // For the tests, which assert these against what the modules that perform
  // the algorithms actually offer rather than against a list in a test.
  driftReport: driftReport,
  keyMaterial: keyMaterial,
  kerberosEtypes: kerberosEtypes,
  hashing: hashing,
  signatures: signatures,
  encryption: encryption,
  postQuantum: postQuantum,
  cryptoJson: cryptoJson
};
